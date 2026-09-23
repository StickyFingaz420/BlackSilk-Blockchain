//! Proving and verifying BVM-1 executions (docs/zkvm.md §7, §10).
//!
//! The verifier needs only the public statement: the program, the exit code,
//! the output words and the transaction binding. It rebuilds every table
//! (including the preprocessed program, image and output tables) from them.

use crate::air::trace::{self, Statement};
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

/// Per-table height limits (log2): the byte table is fixed at 2^16, every
/// other table at the parameter set's maximum.
fn limits(n: usize) -> Vec<usize> {
    let mut v = vec![params::MAX_LOG_HEIGHT; n];
    v[0] = 16;
    v
}

/// Executes `program` on the private `input` and proves the execution.
pub fn prove<R: RngCore + CryptoRng>(
    program: Arc<Program>,
    input: &[u32],
    binding: [u8; 32],
    rng: &mut R,
) -> Result<(Statement, Proof), ProveError> {
    let exec = run(&program, input, MAX_CYCLES).map_err(ProveError::Execution)?;
    let st = Statement {
        program,
        exit_code: exec.exit_code,
        output: exec.output.clone(),
        binding,
    };
    let airs = trace::tables(&st);
    let traces = trace::build(&st, &exec);
    let public = trace::public_values(&st);
    // The witness digest hedges the proof randomness (zk ProverConfig).
    let mut witness =
        blacksilk_crypto::hash::Hasher64::new(blacksilk_crypto::hash::tags::ZK_PROVER_SEED);
    for w in input {
        witness.update(&w.to_le_bytes());
    }
    witness.update(&binding);
    let wide = witness.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&wide[..32]);
    let cfg = ProverConfig::new(&digest, rng);
    let proof = blacksilk_zk::prove(&cfg, &airs, &traces, &public, &limits(airs.len()))
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
        &limits(airs.len()),
    )
}
