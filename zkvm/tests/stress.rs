//! Liveness under concurrency (AUDIT.md ZK-F11, ZK-F21): many proofs running at
//! once in one process must all finish. Plonky3 0.7.0 held `spin` locks across
//! rayon work, which could hang concurrent proofs forever (patched in
//! `third_party/`).
//!
//! Ignored by default (slow). Run it under an external timeout, since a
//! regression shows up as a hang, not a failure:
//! `cargo test --release -p blacksilk-zkvm --test stress -- --ignored --nocapture`
//! (`BLACKSILK_STRESS_ROUNDS` sets the proofs per thread).

use blacksilk_zkvm::asm::{reg::*, Asm};
use blacksilk_zkvm::isa::Op;
use blacksilk_zkvm::prove;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::Arc;
use std::time::Instant;

#[test]
#[ignore]
fn concurrent_proofs_all_finish() {
    const THREADS: u64 = 8;
    let rounds: u64 = std::env::var("BLACKSILK_STRESS_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);
    let mut p = Asm::new(0x1_0000);
    p.li(T0, 7).li(T1, 5);
    p.r(Op::Mul, T2, T0, T1);
    p.write_reg(T2);
    p.halt(0);
    let program = Arc::new(p.finish().unwrap());
    let t = Instant::now();
    std::thread::scope(|s| {
        for k in 0..THREADS {
            let program = program.clone();
            s.spawn(move || {
                for i in 0..rounds {
                    // Each proof builds a fresh configuration, so every one
                    // misses the DFT twiddle caches and draws hiding
                    // randomness: the code paths that used to hang.
                    let mut rng = ChaCha20Rng::seed_from_u64(k * 1_000 + i);
                    let (st, proof) =
                        prove::prove(program.clone(), &[], [0; 32], &mut rng).expect("proves");
                    assert_eq!(prove::verify(&st, &proof), Ok(()));
                }
            });
        }
    });
    println!(
        "{} concurrent proofs ({THREADS} threads) finished in {:.1?}",
        THREADS * rounds,
        t.elapsed()
    );
}
