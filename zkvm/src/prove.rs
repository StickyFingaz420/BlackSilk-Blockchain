//! Proving and verifying BVM-1 executions (docs/zkvm.md §7, §10).
//!
//! The verifier needs only the public statement: the program, the exit code,
//! the output words and the transaction binding. It rebuilds every table
//! (including the preprocessed program, image and output tables) from them.

use crate::air::trace::{self, Part, Statement, MAX_EXECUTIONS};
use crate::air::Table;
use crate::exec::{run, Trap};
use crate::program::Program;
use crate::MAX_CYCLES;
use blacksilk_zk::config::{ProverConfig, VerifierConfig};
use blacksilk_zk::{params, Proof, ZkError};
use rand_core::{CryptoRng, RngCore};
use std::sync::Arc;

#[derive(Debug)]
pub enum ProveError {
    /// The program trapped or did not halt: no valid execution exists.
    Execution(Trap),
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
            _ => params::MAX_LOG_HEIGHT,
        })
        .collect()
}

const _: () = assert!(MAX_CYCLES.is_power_of_two());

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
/// execution of the returned statement.
///
/// # Panics
/// If `runs` is empty or longer than [`MAX_EXECUTIONS`].
pub fn prove_multi<R: RngCore + CryptoRng>(
    runs: &[(Arc<Program>, &[u32])],
    binding: [u8; 32],
    rng: &mut R,
) -> Result<(Statement, Proof), ProveError> {
    assert!(!runs.is_empty() && runs.len() <= MAX_EXECUTIONS);
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
    for ((program, _), exec) in runs.iter().zip(&execs).skip(1) {
        st.others.push(Part {
            program: program.clone(),
            exit_code: exec.exit_code,
            output: exec.output.clone(),
        });
    }
    let airs = trace::tables(&st);
    let refs: Vec<&crate::exec::Execution> = execs.iter().collect();
    let traces = trace::build_multi(&st, &refs);
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
    let cfg = ProverConfig::new(&digest, rng);
    let proof = blacksilk_zk::prove(&cfg, &airs, &traces, &public, &limits(&airs))
        .map_err(ProveError::Proof)?;
    Ok((st, proof))
}

/// Verifies that `proof` shows an execution of `st.program` halting with
/// `st.exit_code` and output `st.output`, bound to `st.binding`.
pub fn verify(st: &Statement, proof: &Proof) -> Result<(), ZkError> {
    let airs = trace::tables(st);
    let public = trace::public_values(st);
    blacksilk_zk::verify(
        &VerifierConfig::new(),
        &airs,
        proof,
        &public,
        &limits(&airs),
    )
}
