//! Size and time of the small toy proofs (the two-table statement of
//! `proofs.rs`), for comparing parameter sets. Not a benchmark of PX proofs:
//! those are measured with `px/examples/proof_bench.rs`.
//!
//! Ignored by default (timing only, no assertion beyond validity):
//! `cargo test --release -p blacksilk-zk --test toy_measure -- --ignored --nocapture --test-threads=1`

use blacksilk_zk::config::{ProverConfig, Val, VerifierConfig};
use blacksilk_zk::params::{NUM_RANDOM_CODEWORDS, PARAMS_ID};
use blacksilk_zk::{encode_proof, prove, verify};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::{InteractionBuilder, LookupBus};
use p3_matrix::dense::RowMajorMatrix;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::time::Instant;

const RANGE: LookupBus<'static> = LookupBus::new("test/range");

#[derive(Clone, Copy, Debug)]
enum Toy {
    Counter,
    Range,
}

impl<F> BaseAir<F> for Toy {
    fn width(&self) -> usize {
        2
    }
    fn num_public_values(&self) -> usize {
        match self {
            Toy::Counter => 2,
            Toy::Range => 0,
        }
    }
}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for Toy {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let local: Vec<AB::Expr> = main.current_slice().iter().map(|v| (*v).into()).collect();
        let next: Vec<AB::Expr> = main.next_slice().iter().map(|v| (*v).into()).collect();
        match self {
            Toy::Counter => {
                let pis: Vec<AB::Expr> = b.public_values().iter().map(|v| (*v).into()).collect();
                let (x, sq) = (local[0].clone(), local[1].clone());
                b.assert_zero(sq.clone() - x.clone() * x.clone());
                b.when_first_row().assert_zero(x.clone() - pis[0].clone());
                b.when_transition()
                    .assert_zero(next[0].clone() - x.clone() - AB::Expr::ONE);
                b.when_last_row().assert_zero(sq - pis[1].clone());
                RANGE.lookup_key(b, [x], 1);
            }
            Toy::Range => {
                let (v, mult) = (local[0].clone(), local[1].clone());
                b.when_first_row().assert_zero(v.clone());
                b.when_transition()
                    .assert_zero(next[0].clone() - v.clone() - AB::Expr::ONE);
                RANGE.table_entry(b, [v], mult);
            }
        }
    }
}

const AIRS: [Toy; 2] = [Toy::Counter, Toy::Range];
const LIMITS: [usize; 2] = [16, 16];

fn witness(n: usize) -> (Vec<RowMajorMatrix<Val>>, Vec<Vec<Val>>) {
    let mut counter = Vec::with_capacity(2 * n);
    let mut table = Vec::with_capacity(2 * n);
    for i in 0..n as u32 {
        counter.push(Val::from_u32(i));
        counter.push(Val::from_u32(i) * Val::from_u32(i));
        table.push(Val::from_u32(i));
        table.push(Val::ONE);
    }
    let last = Val::from_u32(n as u32 - 1);
    (
        vec![
            RowMajorMatrix::new(counter, 2),
            RowMajorMatrix::new(table, 2),
        ],
        vec![vec![Val::ZERO, last * last], vec![]],
    )
}

#[test]
#[ignore = "timing only; run explicitly with --ignored --nocapture"]
fn toy_proof_size_and_time() {
    const ROUNDS: u64 = 5;
    println!(
        "parameter set {}, {NUM_RANDOM_CODEWORDS} random codewords",
        String::from_utf8_lossy(PARAMS_ID)
    );
    let v = VerifierConfig::new();
    for log_n in [8usize, 12] {
        let (traces, pv) = witness(1 << log_n);
        let (mut sizes, mut proving, mut verifying) = (vec![], vec![], vec![]);
        for seed in 0..ROUNDS {
            let cfg = ProverConfig::new(&[seed as u8; 32], &mut ChaCha20Rng::seed_from_u64(seed));
            let t = Instant::now();
            let proof = prove(&cfg, &AIRS, &traces, &pv, &LIMITS).expect("honest proof");
            proving.push(t.elapsed().as_secs_f64() * 1e3);
            sizes.push(encode_proof(&proof).len());
            let t = Instant::now();
            verify(&v, &AIRS, &proof, &pv, &LIMITS).expect("verifies");
            verifying.push(t.elapsed().as_secs_f64() * 1e3);
        }
        let range = |v: &[f64]| {
            let min = v.iter().cloned().fold(f64::INFINITY, f64::min);
            let max = v.iter().cloned().fold(0.0, f64::max);
            format!("{min:.1}-{max:.1} ms")
        };
        println!(
            "2 tables x 2^{log_n} rows, {ROUNDS} proofs: size {}-{} B, prove {}, verify {}",
            sizes.iter().min().unwrap(),
            sizes.iter().max().unwrap(),
            range(&proving),
            range(&verifying)
        );
    }
}
