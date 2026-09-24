//! Proving and verifying PX transactions (docs/px.md §4.3, §7).
//!
//! A PX proof is one BVM-1 batch proof of several executions:
//! - execution 0: the fixed kernel program ([`KERNEL_ELF`], built from
//!   `zkvm/guests/kernel`), halting with exit code 0 and writing exactly the
//!   transaction's public statement;
//! - executions 1..: the contract functions it calls, each halting with exit
//!   code 0 and writing `io_hash ‖ contract` (the values the kernel reports
//!   for it) followed by its public outputs.
//!
//! All executions are bound to the transaction hash `h_tx`. The verifier never
//! runs anything: it rebuilds the statement from public data and checks the
//! proof. It must also check that each function's program is registered to
//! the contract it claims ([`verify`] takes the registry as an argument):
//! otherwise anyone could write a "function" that approves spending another
//! contract's records.

use crate::perm::HostPerm;
use blacksilk_px_core::call::function_prefix;
use blacksilk_px_core::kernel::{self, Public, SliceSource, Witness};
use blacksilk_px_core::Digest;
use blacksilk_zk::{Proof, ZkError};
use blacksilk_zkvm::air::trace::{Budget, Part, Statement};
use blacksilk_zkvm::prove::ProveError;
use blacksilk_zkvm::Program;
use rand_core::{CryptoRng, RngCore};
use std::sync::{Arc, OnceLock};

/// The kernel guest (RISC-V ELF), rebuilt by `zkvm/guests/build.sh`.
pub const KERNEL_ELF: &[u8] = include_bytes!("../kernel.elf");

/// The kernel's program id (hex), pinned in `px/kernel.id`. A test checks
/// that it matches [`KERNEL_ELF`], so an unintended rebuild cannot change it
/// silently.
pub const KERNEL_PROGRAM_ID: &str = include_str!("../kernel.id");

pub fn kernel_program() -> Arc<Program> {
    static P: OnceLock<Arc<Program>> = OnceLock::new();
    P.get_or_init(|| Arc::new(Program::from_elf(KERNEL_ELF).expect("the kernel ELF loads")))
        .clone()
}

/// The kernel's fixed row budget for a transaction calling `n_fn` functions
/// (zkvm.md §8): every kernel execution with the same `n_fn` has exactly the
/// same table heights, whatever its witness.
///
/// Values are the measured use plus ~6%, rounded up
/// (`budgets_leave_headroom` checks that every tested witness stays at or
/// below 95% of each). Changing the kernel changes its program id and
/// requires re-measuring.
///
/// # Panics
/// If `n_fn > MAX_FN`.
pub fn kernel_budget(n_fn: usize) -> Budget {
    let [cycles, keys, add, bit, lt, shift, mul, poseidon] = match n_fn {
        0 => [26_500, 4_450, 18_300, 1_500, 15_300, 1_450, 1_450, 126],
        1 => [31_200, 4_500, 21_800, 1_700, 17_900, 1_550, 1_550, 138],
        2 => [35_600, 4_550, 25_200, 1_900, 20_400, 1_650, 1_650, 151],
        _ => panic!("at most MAX_FN functions"),
    };
    Budget {
        cycles,
        keys,
        add,
        bit,
        lt,
        shift,
        mul,
        poseidon,
    }
}

/// A called function, as the verifier sees it: its program and the public
/// outputs it writes after `io_hash ‖ contract`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionCall {
    pub program: Arc<Program>,
    pub outputs: Vec<u32>,
}

#[derive(Debug)]
pub enum TransferError {
    /// The kernel rejected the witness (no valid proof exists).
    Rejected(kernel::Error),
    /// The kernel or a function panicked, trapped or halted with an error.
    Execution(String),
    /// Function `k` did not report the `(io_hash, contract)` the kernel
    /// computed: its transcript differs from the kernel's.
    FunctionMismatch(usize),
    /// A function run is missing or superfluous.
    Shape,
    /// An execution needs more rows than its budget in table `.0`.
    BudgetExceeded(usize),
    Proof(ZkError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The number of function calls differs from the statement's.
    Shape,
    /// Function `k`'s program is not registered to its contract.
    Unregistered(usize),
    Proof(ZkError),
}

pub fn public_words(p: &Public) -> Vec<u32> {
    let mut v = Vec::new();
    p.write(|x| v.push(x));
    v
}

pub fn witness_words(w: &Witness) -> Vec<u32> {
    let mut v = Vec::new();
    w.write(|x| v.push(x));
    v
}

fn statement(
    public: &Public,
    calls: &[FunctionCall],
    budgets: &[Budget],
    h_tx: [u8; 32],
) -> Option<Statement> {
    if calls.len() != public.n_fn || budgets.len() != calls.len() {
        return None;
    }
    let mut st = Statement::single(kernel_program(), 0, public_words(public), h_tx);
    st.budget = Some(kernel_budget(public.n_fn));
    for ((call, (contract, io_hash)), budget) in calls.iter().zip(&public.functions).zip(budgets) {
        let mut output = function_prefix(io_hash, contract).to_vec();
        output.extend(&call.outputs);
        st.others.push(Part {
            program: call.program.clone(),
            exit_code: 0,
            output,
            budget: Some(*budget),
        });
    }
    Some(st)
}

fn prove_error(e: ProveError) -> TransferError {
    match e {
        ProveError::Execution(t) => TransferError::Execution(format!("{t:?}")),
        ProveError::BudgetExceeded(t) => TransferError::BudgetExceeded(t),
        ProveError::Proof(e) => TransferError::Proof(e),
    }
}

/// Checks the witness natively, then proves the kernel's execution together
/// with the function runs `functions[k] = (program, private input, budget)`,
/// each budget as registered for the program. The proof has the fixed shape
/// of these budgets.
pub fn prove<R: RngCore + CryptoRng>(
    w: &Witness,
    functions: &[(Arc<Program>, Vec<u32>, Budget)],
    h_tx: [u8; 32],
    rng: &mut R,
) -> Result<(Public, Vec<FunctionCall>, Proof), TransferError> {
    let words = witness_words(w);
    // The native run is the same code as the guest: reject early, with the
    // precise reason, instead of proving a failing execution.
    let public = kernel::transfer(&mut HostPerm::new(), &mut SliceSource::new(&words))
        .map_err(TransferError::Rejected)?;
    if functions.len() != public.n_fn {
        return Err(TransferError::Shape);
    }
    // Run every function first (cheap) and check it reports the kernel's
    // `(io_hash, contract)`, so a mismatched call is refused before any
    // proving work.
    for (k, (program, input, _)) in functions.iter().enumerate() {
        let exec = blacksilk_zkvm::run(program, input, blacksilk_zkvm::MAX_CYCLES)
            .map_err(|t| TransferError::Execution(format!("function {k}: {t:?}")))?;
        if exec.exit_code != 0 {
            return Err(TransferError::Execution(format!(
                "function {k} halted with {}",
                exec.exit_code
            )));
        }
        let (contract, io_hash) = &public.functions[k];
        if exec.output.len() < 16 || exec.output[..16] != function_prefix(io_hash, contract) {
            return Err(TransferError::FunctionMismatch(k));
        }
    }
    let mut runs: Vec<(Arc<Program>, &[u32])> = vec![(kernel_program(), &words)];
    runs.extend(functions.iter().map(|(p, i, _)| (p.clone(), i.as_slice())));
    let mut budgets = vec![kernel_budget(public.n_fn)];
    budgets.extend(functions.iter().map(|(_, _, b)| *b));
    let (st, proof) = blacksilk_zkvm::prove::prove_shaped(&runs, Some(&budgets), h_tx, rng)
        .map_err(prove_error)?;
    // Guest and host agree (they are the same source; checked on every proof).
    if st.exit_code != 0 || st.output != public_words(&public) {
        return Err(TransferError::Execution(format!(
            "kernel guest diverged from the native kernel: exit {}",
            st.exit_code
        )));
    }
    let mut calls = Vec::new();
    for (k, part) in st.others.iter().enumerate() {
        if part.exit_code != 0 {
            return Err(TransferError::Execution(format!(
                "function {k} halted with {}",
                part.exit_code
            )));
        }
        let (contract, io_hash) = &public.functions[k];
        if part.output.len() < 16 || part.output[..16] != function_prefix(io_hash, contract) {
            return Err(TransferError::FunctionMismatch(k));
        }
        calls.push(FunctionCall {
            program: part.program.clone(),
            outputs: part.output[16..].to_vec(),
        });
    }
    Ok((public, calls, proof))
}

/// Verifies a PX proof. `registered(contract, program_id)` must return the
/// program's registered budget if it is a function of the contract, and
/// `None` otherwise (consensus state). The proof must have exactly the fixed
/// shape of the kernel's and the functions' budgets.
pub fn verify(
    public: &Public,
    calls: &[FunctionCall],
    h_tx: [u8; 32],
    proof: &Proof,
    registered: impl Fn(&Digest, &[u8; 32]) -> Option<Budget>,
) -> Result<(), VerifyError> {
    if calls.len() != public.n_fn {
        return Err(VerifyError::Shape);
    }
    let mut budgets = Vec::with_capacity(calls.len());
    for (k, call) in calls.iter().enumerate() {
        match registered(&public.functions[k].0, &call.program.id()) {
            Some(b) => budgets.push(b),
            None => return Err(VerifyError::Unregistered(k)),
        }
    }
    let st = statement(public, calls, &budgets, h_tx).ok_or(VerifyError::Shape)?;
    blacksilk_zkvm::prove::verify(&st, proof).map_err(VerifyError::Proof)
}

/// Proves a plain transfer (no functions).
pub fn prove_transfer<R: RngCore + CryptoRng>(
    w: &Witness,
    h_tx: [u8; 32],
    rng: &mut R,
) -> Result<(Public, Proof), TransferError> {
    prove(w, &[], h_tx, rng).map(|(p, _, proof)| (p, proof))
}

/// Verifies a plain transfer proof (a statement with functions is rejected).
pub fn verify_transfer(public: &Public, h_tx: [u8; 32], proof: &Proof) -> Result<(), VerifyError> {
    verify(public, &[], h_tx, proof, |_, _| None)
}
