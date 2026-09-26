//! Proving and verifying BVM-1 executions (docs/zkvm.md §7, §10).
//!
//! The verifier needs only the public statement: the program, the exit code,
//! the output words and the transaction binding. It rebuilds every table
//! (including the preprocessed program, image and output tables) from them.

use crate::air::trace::{self, Budget, Part, Statement, MAX_EXECUTIONS};
use crate::air::Table;
use crate::exec::{run, Trap};
use crate::program::Program;
use crate::MAX_CYCLES;
use blacksilk_zk::config::{ProverConfig, VerifierConfig};
use blacksilk_zk::{params, Proof, ZkError};
use p3_matrix::Matrix;
use rand_core::{CryptoRng, RngCore};
use std::sync::Arc;

#[derive(Debug)]
pub enum ProveError {
    /// The program trapped or did not halt: no valid execution exists.
    Execution(Trap),
    /// An execution needs more rows than its budget allows in table `.0`
    /// (index in `trace::tables` order): it cannot be proven in its shape.
    BudgetExceeded(usize),
    Proof(ZkError),
}

/// Per-table height limits (log2): the byte table is fixed at 2^16; CPU
/// tables hold at most `MAX_CYCLES` rows, so the circuit accepts exactly the
/// executions the interpreter allows (finding ZK-F9); every other table is
/// bounded by the parameter set's maximum.
pub fn limits(airs: &[Table]) -> Vec<usize> {
    airs.iter()
        .map(|t| match t {
            Table::Byte => 16,
            Table::Cpu(_) => MAX_CYCLES.trailing_zeros() as usize,
            // The Blind table holds at most one row per other table (at most
            // 32): it never needs more than the minimum height.
            Table::Blind => params::MIN_LOG_HEIGHT,
            _ => params::MAX_LOG_HEIGHT,
        })
        .collect()
}

const _: () = assert!(MAX_CYCLES.is_power_of_two());

/// The digest of every public column of every table of a statement: the
/// programs, images, claimed outputs and the byte table, exactly as the
/// verifier supplies them to the AIRs (periodic columns). It is absorbed into
/// the Fiat–Shamir transcript before any challenge (`blacksilk_zk::config`),
/// so none of this data can be chosen after the challenges.
pub fn statement_digest(airs: &[Table]) -> [u8; 32] {
    use p3_air::BaseAir;
    use p3_field::PrimeField32;
    let mut h = blacksilk_crypto::hash::Hasher64::new(blacksilk_crypto::hash::tags::ZKVM_STATEMENT);
    h.update(&(airs.len() as u64).to_le_bytes());
    for (t, air) in airs.iter().enumerate() {
        let cols = air.periodic_columns();
        h.update(&(t as u64).to_le_bytes());
        h.update(&(cols.len() as u64).to_le_bytes());
        for col in cols.iter() {
            h.update(&(col.len() as u64).to_le_bytes());
            let mut bytes = Vec::with_capacity(4 * col.len());
            for v in col {
                bytes.extend_from_slice(&v.as_canonical_u32().to_le_bytes());
            }
            h.update(&bytes);
        }
    }
    let wide = h.finalize();
    let mut d = [0u8; 32];
    d.copy_from_slice(&wide[..32]);
    d
}

/// Executes `program` on the private `input` and proves the execution.
pub fn prove<R: RngCore + CryptoRng>(
    program: Arc<Program>,
    input: &[u32],
    binding: [u8; 32],
    rng: &mut R,
) -> Result<(Statement, Proof), ProveError> {
    prove_multi(&[(program, input)], binding, rng)
}

/// Executes each `(program, input)` and proves all executions in one batch
/// proof (zkvm.md §6.5). Execution `e` gets id `e`; the first is the main
/// execution of the returned statement. No budgets: table heights follow the
/// execution (use [`prove_shaped`] for a fixed shape).
///
/// # Panics
/// If `runs` is empty or longer than [`MAX_EXECUTIONS`].
pub fn prove_multi<R: RngCore + CryptoRng>(
    runs: &[(Arc<Program>, &[u32])],
    binding: [u8; 32],
    rng: &mut R,
) -> Result<(Statement, Proof), ProveError> {
    prove_shaped(runs, None, binding, rng)
}

/// As [`prove_multi`], with one budget per execution: the proof has the fixed
/// shape [`Statement::shape`], and an execution that exceeds its budget is
/// refused with [`ProveError::BudgetExceeded`].
///
/// # Panics
/// If `runs` is empty or longer than [`MAX_EXECUTIONS`], or `budgets` has
/// another length.
pub fn prove_shaped<R: RngCore + CryptoRng>(
    runs: &[(Arc<Program>, &[u32])],
    budgets: Option<&[Budget]>,
    binding: [u8; 32],
    rng: &mut R,
) -> Result<(Statement, Proof), ProveError> {
    assert!(!runs.is_empty() && runs.len() <= MAX_EXECUTIONS);
    if let Some(b) = budgets {
        assert_eq!(b.len(), runs.len(), "one budget per execution");
    }
    let budget = |e: usize| budgets.map(|b| b[e]);
    let mut execs = Vec::with_capacity(runs.len());
    for (program, input) in runs {
        execs.push(run(program, input, MAX_CYCLES).map_err(ProveError::Execution)?);
    }
    let mut st = Statement::single(
        runs[0].0.clone(),
        execs[0].exit_code,
        execs[0].output.clone(),
        binding,
    );
    st.budget = budget(0);
    for (e, ((program, _), exec)) in runs.iter().zip(&execs).enumerate().skip(1) {
        st.others.push(Part {
            program: program.clone(),
            exit_code: exec.exit_code,
            output: exec.output.clone(),
            budget: budget(e),
        });
    }
    let airs = trace::tables(&st);
    let refs: Vec<&crate::exec::Execution> = execs.iter().collect();
    let traces = trace::build_multi(&st, &refs);
    if let Some(shape) = st.shape() {
        for (t, (tr, &h)) in traces.iter().zip(&shape).enumerate() {
            if tr.height() != h {
                return Err(ProveError::BudgetExceeded(t));
            }
        }
    }
    let public = trace::public_values(&st);
    // The witness digest hedges the proof randomness (zk ProverConfig).
    let mut witness =
        blacksilk_crypto::hash::Hasher64::new(blacksilk_crypto::hash::tags::ZK_PROVER_SEED);
    for (_, input) in runs {
        witness.update(&(input.len() as u64).to_le_bytes());
        for w in *input {
            witness.update(&w.to_le_bytes());
        }
    }
    witness.update(&binding);
    let wide = witness.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&wide[..32]);
    // Terminal blinding (ZK-F29): fresh random values, from the OS RNG hedged
    // with the witness digest as for the proof's other randomness.
    let mut traces = traces;
    {
        use rand_chacha::rand_core::SeedableRng;
        let mut fresh = [0u8; 32];
        rng.fill_bytes(&mut fresh);
        let mut h =
            blacksilk_crypto::hash::Hasher64::new(blacksilk_crypto::hash::tags::ZK_BLIND_SEED);
        h.update(&digest);
        h.update(&fresh);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&h.finalize()[..32]);
        let mut blind_rng = rand_chacha::ChaCha20Rng::from_seed(seed);
        trace::randomize_blinding(&mut traces, &mut blind_rng);
        use zeroize::Zeroize;
        seed.zeroize();
        fresh.zeroize();
    }
    let cfg = ProverConfig::for_statement(&statement_digest(&airs), &digest, rng);
    let proof = blacksilk_zk::prove(&cfg, &airs, &traces, &public, &limits(&airs))
        .map_err(ProveError::Proof)?;
    Ok((st, proof))
}

/// Verifies that `proof` shows an execution of `st.program` halting with
/// `st.exit_code` and output `st.output`, bound to `st.binding`.
///
/// A statement with a fixed shape ([`Statement::shape`]) is accepted only if
/// every table of the proof has exactly its shape's height.
pub fn verify(st: &Statement, proof: &Proof) -> Result<(), ZkError> {
    let airs = trace::tables(st);
    if let Some(shape) = st.shape() {
        // `degree_bits` is log2(height) + 1 under zero knowledge.
        let ok = proof.degree_bits.len() == shape.len()
            && shape
                .iter()
                .zip(&proof.degree_bits)
                .all(|(&h, &db)| db == h.trailing_zeros() as usize + 1);
        if !ok {
            return Err(ZkError::Shape(
                "proof shape differs from the statement's".into(),
            ));
        }
    }
    let public = trace::public_values(st);
    blacksilk_zk::verify(
        &VerifierConfig::for_statement(&statement_digest(&airs)),
        &airs,
        proof,
        &public,
        &limits(&airs),
    )
}
