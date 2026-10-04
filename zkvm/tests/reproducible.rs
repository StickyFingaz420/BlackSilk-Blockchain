//! Proof bytes are a function of (program, input, binding, RNG seed) alone:
//! the prover's thread scheduling must not change them (finding PXDET-1).
//!
//! Before the fix, `p3-batch-stark` computed every table's quotient LDE inside
//! a rayon parallel loop, and each call drew its hiding randomness from the
//! one shared PCS RNG; the order in which tables took the RNG lock, hence
//! which table got which random values, followed the scheduler. The quotient
//! commitment, every later Fiat–Shamir challenge, the query positions and so
//! the pruned Merkle paths (the proof length) then varied run to run.

use blacksilk_zkvm::asm::{reg::*, Asm};
use blacksilk_zkvm::isa::Op;
use blacksilk_zkvm::program::Program;
use blacksilk_zkvm::prove;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::Arc;

const BASE: u32 = 0x1_0000;

/// A small program that touches the CPU, ALU (add, lt) and output tables.
fn program() -> Arc<Program> {
    let mut p = Asm::new(BASE);
    p.ecall(1) // A0 = input
        .li(T0, 0)
        .li(T1, 3)
        .branch(Op::Beq, A0, ZERO, "loop")
        .li(T1, 7)
        .label("loop")
        .imm(Op::Addi, T0, T0, 1)
        .branch(Op::Blt, T0, T1, "loop")
        .li(A1, 42)
        .write_reg(A1)
        .halt(0);
    Arc::new(p.finish().unwrap())
}

fn proof_bytes(seed: u64) -> Vec<u8> {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let (st, proof) = prove::prove(program(), &[1], [9; 32], &mut rng).unwrap();
    assert!(prove::verify(&st, &proof).is_ok());
    blacksilk_zk::encode_proof(&proof)
}

#[test]
fn the_same_seed_gives_the_same_proof_bytes() {
    let first = proof_bytes(5);
    for run in 1..3 {
        let again = proof_bytes(5);
        let diff = first.iter().zip(&again).position(|(a, b)| a != b);
        assert!(
            first == again,
            "run {run}: {} vs {} bytes, first difference at {diff:?}",
            first.len(),
            again.len()
        );
    }
    // Another seed gives another proof (the randomness is used).
    assert_ne!(first, proof_bytes(6));
}
