//! Proving and verifying PX transactions (docs/px.md §4.3, §7).
//!
//! A PX proof is one BVM-1 batch proof of several executions:
//! - execution 0: the fixed kernel program ([`KERNEL_ELF`], built from
//!   `zkvm/guests/kernel`), halting with exit code 0 and writing exactly the
//!   transaction's public statement;
//! - executions 1..: the contract functions it calls, each halting with exit
//!   code 0 and writing the function prefix `abi ‖ io_hash ‖ contract ‖
//!   window` (`blacksilk_px_core::call::function_prefix`: its registered call
//!   ABI, the values the kernel reports for it and the transaction's validity
//!   window) followed by its public outputs.
//!
//! All executions are bound to the transaction hash `h_tx`. The verifier never
//! runs anything: it rebuilds the statement from public data and checks the
//! proof. It must also check that each function's program is registered to
//! the contract it claims ([`verify`] takes the registry as an argument):
//! otherwise anyone could write a "function" that approves spending another
//! contract's records.

use crate::perm::HostPerm;
use blacksilk_px_core::call::{function_prefix, Window, ABI_VERSION, MAX_FN, PREFIX_WORDS};
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
/// Every honest shape must fit: the kernel's few data-dependent comparisons
/// (a specified contract output, an approval) cost rows, and a kernel
/// execution over its budget would be provable only while the padded shared
/// tables happen to have room, so provability would depend on the other
/// functions' budgets (RTW1C-1). Values are the maximum over every shape the
/// kernel accepts plus ~6%, rounded up to 50 (`px/tests/kernel_budget.rs`
/// enumerates the shapes and checks that each table stays at or below 95%).
/// The budgets are prover and verifier parameters (the statement's table
/// heights), not part of the kernel ELF; they are consensus values, listed
/// in the fingerprint (`px.kernel.BUDGET`). Changing the kernel changes its
/// program id and requires re-measuring.
///
/// # Panics
/// If `n_fn > MAX_FN`.
pub fn kernel_budget(n_fn: usize) -> Budget {
    let [cycles, keys, add, bit, lt, shift, mul, poseidon] = match n_fn {
        0 => [26_500, 4_550, 18_300, 1_500, 15_300, 1_450, 1_450, 126],
        1 => [31_200, 4_600, 21_800, 1_850, 18_050, 1_550, 1_550, 138],
        2 => [35_600, 4_650, 25_200, 2_000, 20_550, 1_650, 1_650, 151],
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

/// The proof decoder's limits for PX statements (RT-FUZZ-1,
/// `blacksilk_zk::bounds`): the envelope's, with the table count of the
/// widest PX statement, the kernel and `MAX_FN` functions
/// (`zkvm::air::trace::tables`: 12 base tables, 5 per further execution and
/// the Blind table, 23). [`verify`] and [`check_shape`] accept only a proof
/// with exactly its statement's tables, so a proof with more cannot verify
/// for any PX statement. `px/tests/proof_limits.rs` checks every PX table
/// against the quotient-chunk and width limits.
pub const PROOF_LIMITS: blacksilk_zk::DecodeLimits = blacksilk_zk::DecodeLimits {
    max_instances: blacksilk_zkvm::air::trace::BASE_TABLES
        + blacksilk_zkvm::air::trace::TABLES_PER_EXTRA * MAX_FN
        + 1,
    ..blacksilk_zk::DecodeLimits::ENVELOPE
};

/// A called function, as the verifier sees it: its program and call ABI (both
/// from the registry) and the public outputs it writes after its prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionCall {
    pub program: Arc<Program>,
    /// The call ABI the program is registered with: the first prefix word.
    pub abi: u32,
    pub outputs: Vec<u32>,
}

#[derive(Debug)]
pub enum TransferError {
    /// The kernel rejected the witness (no valid proof exists).
    Rejected(kernel::Error),
    /// The kernel or a function panicked, trapped or halted with an error.
    Execution(String),
    /// Function `k` did not write the prefix the statement requires: its
    /// transcript differs from the kernel's (`io_hash`), or it echoes another
    /// ABI or validity window.
    FunctionMismatch(usize),
    /// A function run is missing or superfluous.
    Shape,
    /// An execution needs more rows than its budget in table `.0`.
    BudgetExceeded(usize),
    /// Execution `execution` (0 is the kernel, `k + 1` function `k`) uses
    /// `used` rows of `table`, more than its budget `budget`. Checked for each
    /// execution before proving: the shared tables are padded to a power of
    /// two of the budgets' sum, so an over-budget execution could otherwise
    /// be proven or not depending on the other executions' budgets.
    OverBudget {
        execution: usize,
        table: &'static str,
        used: usize,
        budget: usize,
    },
    Proof(ZkError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The number of function calls differs from the statement's, or exceeds
    /// `MAX_FN`.
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
    window: &Window,
    h_tx: [u8; 32],
) -> Option<Statement> {
    // `n_fn > MAX_FN` never decodes from a transaction; a hand-built
    // statement gets `Shape` instead of a panic (F-20-5).
    if public.n_fn > MAX_FN || calls.len() != public.n_fn || budgets.len() != calls.len() {
        return None;
    }
    let mut st = Statement::single(kernel_program(), 0, public_words(public), h_tx);
    st.budget = Some(kernel_budget(public.n_fn));
    for ((call, (contract, io_hash)), budget) in calls.iter().zip(&public.functions).zip(budgets) {
        let mut output = function_prefix(call.abi, io_hash, contract, window).to_vec();
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

/// The first table in which `used` exceeds `budget`, as
/// `(table, used, budget)`.
pub fn over_budget(used: &Budget, budget: &Budget) -> Option<(&'static str, usize, usize)> {
    [
        ("cycles", used.cycles, budget.cycles),
        ("keys", used.keys, budget.keys),
        ("add", used.add, budget.add),
        ("bit", used.bit, budget.bit),
        ("lt", used.lt, budget.lt),
        ("shift", used.shift, budget.shift),
        ("mul", used.mul, budget.mul),
        ("poseidon", used.poseidon, budget.poseidon),
    ]
    .into_iter()
    .find(|&(_, u, b)| u > b)
}

/// Checks that execution `execution` (a run of `program`) fits `budget` in
/// every table ([`TransferError::OverBudget`]).
fn check_budget(
    execution: usize,
    program: &Program,
    exec: &blacksilk_zkvm::Execution,
    budget: &Budget,
) -> Result<(), TransferError> {
    let used = blacksilk_zkvm::air::trace::usage(program, exec);
    match over_budget(&used, budget) {
        Some((table, used, budget)) => Err(TransferError::OverBudget {
            execution,
            table,
            used,
            budget,
        }),
        None => Ok(()),
    }
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
/// each budget as registered for the program (with ABI [`ABI_VERSION`], the
/// only one a deploy may register). `window` is the transaction's validity
/// window, which every function echoes in its prefix. The proof has the
/// fixed shape of these budgets.
pub fn prove<R: RngCore + CryptoRng>(
    w: &Witness,
    functions: &[(Arc<Program>, Vec<u32>, Budget)],
    window: &Window,
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
    // Run the kernel guest and every function first (cheap next to proving):
    // each execution must fit its own budget in every table (RTW1C-1), and
    // each function must write the prefix of the kernel's `(io_hash,
    // contract)`, the ABI and the window, so a mismatched or over-budget call
    // is refused before any proving work.
    let kernel_exec = blacksilk_zkvm::run(&kernel_program(), &words, blacksilk_zkvm::MAX_CYCLES)
        .map_err(|t| TransferError::Execution(format!("kernel: {t:?}")))?;
    if kernel_exec.exit_code != 0 {
        return Err(TransferError::Execution(format!(
            "kernel guest diverged from the native kernel: exit {}",
            kernel_exec.exit_code
        )));
    }
    check_budget(
        0,
        &kernel_program(),
        &kernel_exec,
        &kernel_budget(public.n_fn),
    )?;
    drop(kernel_exec);
    for (k, (program, input, budget)) in functions.iter().enumerate() {
        let exec = blacksilk_zkvm::run(program, input, blacksilk_zkvm::MAX_CYCLES)
            .map_err(|t| TransferError::Execution(format!("function {k}: {t:?}")))?;
        if exec.exit_code != 0 {
            return Err(TransferError::Execution(format!(
                "function {k} halted with {}",
                exec.exit_code
            )));
        }
        let (contract, io_hash) = &public.functions[k];
        let prefix = function_prefix(ABI_VERSION, io_hash, contract, window);
        if exec.output.len() < PREFIX_WORDS || exec.output[..PREFIX_WORDS] != prefix {
            return Err(TransferError::FunctionMismatch(k));
        }
        check_budget(k + 1, program, &exec, budget)?;
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
        let prefix = function_prefix(ABI_VERSION, io_hash, contract, window);
        if part.output.len() < PREFIX_WORDS || part.output[..PREFIX_WORDS] != prefix {
            return Err(TransferError::FunctionMismatch(k));
        }
        calls.push(FunctionCall {
            program: part.program.clone(),
            abi: ABI_VERSION,
            outputs: part.output[PREFIX_WORDS..].to_vec(),
        });
    }
    Ok((public, calls, proof))
}

/// Verifies a PX proof. `registered(contract, program_id)` must return the
/// program's registered budget if it is a function of the contract, and
/// `None` otherwise (consensus state); each call's `abi` must be the
/// program's registered one. `window` is the transaction's validity window.
/// The proof must have exactly the fixed shape of the kernel's and the
/// functions' budgets.
pub fn verify(
    public: &Public,
    calls: &[FunctionCall],
    window: &Window,
    h_tx: [u8; 32],
    proof: &Proof,
    registered: impl Fn(&Digest, &[u8; 32]) -> Option<Budget>,
) -> Result<(), VerifyError> {
    if public.n_fn > MAX_FN || calls.len() != public.n_fn {
        return Err(VerifyError::Shape);
    }
    let mut budgets = Vec::with_capacity(calls.len());
    for (k, call) in calls.iter().enumerate() {
        match registered(&public.functions[k].0, &call.program.id()) {
            Some(b) => budgets.push(b),
            None => return Err(VerifyError::Unregistered(k)),
        }
    }
    let st = statement(public, calls, &budgets, window, h_tx).ok_or(VerifyError::Shape)?;
    blacksilk_zkvm::prove::verify(&st, proof).map_err(VerifyError::Proof)
}

/// The cheap part of [`verify`], no cryptography: the statement exists
/// (function count, registrations) and `proof` has exactly its table shape
/// (the degree bits of every table). A proof failing this fails [`verify`]
/// with the same kind of error, so running it first changes only when a bad
/// proof is found (block validation runs it before any ring signature,
/// dossier 10 F10-2).
pub fn check_shape(
    public: &Public,
    calls: &[FunctionCall],
    window: &Window,
    h_tx: [u8; 32],
    proof: &Proof,
    registered: impl Fn(&Digest, &[u8; 32]) -> Option<Budget>,
) -> Result<(), VerifyError> {
    check_shape_bits(public, calls, window, h_tx, &proof.degree_bits, registered)
}

/// [`check_shape`] on a proof's degree bits alone (`Proof::degree_bits`),
/// the only part of the proof it reads: a caller can drop the decoded proof
/// and keep these (P2P admission, RT-PXDOS F1). Same verdicts.
pub fn check_shape_bits(
    public: &Public,
    calls: &[FunctionCall],
    window: &Window,
    h_tx: [u8; 32],
    degree_bits: &[usize],
    registered: impl Fn(&Digest, &[u8; 32]) -> Option<Budget>,
) -> Result<(), VerifyError> {
    if public.n_fn > MAX_FN || calls.len() != public.n_fn {
        return Err(VerifyError::Shape);
    }
    let mut budgets = Vec::with_capacity(calls.len());
    for (k, call) in calls.iter().enumerate() {
        match registered(&public.functions[k].0, &call.program.id()) {
            Some(b) => budgets.push(b),
            None => return Err(VerifyError::Unregistered(k)),
        }
    }
    let st = statement(public, calls, &budgets, window, h_tx).ok_or(VerifyError::Shape)?;
    // Every execution has a budget here, so the statement has a fixed shape.
    let shape = st.shape().ok_or(VerifyError::Shape)?;
    // `degree_bits` is log2(height) + 1 under zero knowledge (as in
    // `blacksilk_zkvm::prove::verify`).
    let ok = degree_bits.len() == shape.len()
        && shape
            .iter()
            .zip(degree_bits)
            .all(|(&h, &db)| db == h.trailing_zeros() as usize + 1);
    if ok {
        Ok(())
    } else {
        Err(VerifyError::Proof(ZkError::Shape(
            "proof shape differs from the statement's".into(),
        )))
    }
}

/// Proves a plain transfer (no functions). No function reads the validity
/// window, which `h_tx` still binds.
pub fn prove_transfer<R: RngCore + CryptoRng>(
    w: &Witness,
    h_tx: [u8; 32],
    rng: &mut R,
) -> Result<(Public, Proof), TransferError> {
    prove(w, &[], &Window::UNBOUNDED, h_tx, rng).map(|(p, _, proof)| (p, proof))
}

/// Verifies a plain transfer proof (a statement with functions is rejected).
pub fn verify_transfer(public: &Public, h_tx: [u8; 32], proof: &Proof) -> Result<(), VerifyError> {
    verify(public, &[], &Window::UNBOUNDED, h_tx, proof, |_, _| None)
}
