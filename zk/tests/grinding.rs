//! Query proof-of-work grinding and the prover's thread count (27 W6, F27-3).
//!
//! The FRI prover publishes its query-grinding witness in every proof. Plonky3
//! 0.7.0's `DuplexChallenger::grind` searches the candidates with rayon's
//! `find_map_any`, which returns whichever thread finds a valid nonce first:
//! the witness then sits near the start of some thread's range, so it reveals
//! a coarse class of the prover's thread count and links proofs made on one
//! device (the query positions, and so the proof length, depend on it too).
//!
//! These tests run the same computation in child processes of this test
//! binary under `RAYON_NUM_THREADS` = 1, 2, 8 and 16 (rayon's global pool reads
//! it at start-up), and compare what the children print.

use blacksilk_zk::config::{
    permutation, smallest_pow_witness, Challenger, ProverChallenger, ProverConfig, Val,
    VerifierConfig,
};
use blacksilk_zk::{decode_proof, encode_proof, prove, verify};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_challenger::{CanObserve, CanSample, GrindingChallenger};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_lookup::{InteractionBuilder, LookupBus};
use p3_matrix::dense::RowMajorMatrix;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::BTreeMap;
use std::process::Command;

const THREADS: [usize; 4] = [1, 2, 8, 16];
const HELPER: &str = "grinding_witnesses_helper";

// ------------------------------------------------ a toy statement (as proofs.rs)

const RANGE: LookupBus<'static> = LookupBus::new("test/range");

#[derive(Clone, Copy, Debug)]
enum Toy {
    Counter,
    Range,
    /// The counter alone, without the lookup: a one-table statement.
    Square,
}

impl<F> BaseAir<F> for Toy {
    fn width(&self) -> usize {
        2
    }
    fn num_public_values(&self) -> usize {
        match self {
            Toy::Counter | Toy::Square => 2,
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
            Toy::Counter | Toy::Square => {
                let pis: Vec<AB::Expr> = b.public_values().iter().map(|v| (*v).into()).collect();
                let (x, sq) = (local[0].clone(), local[1].clone());
                b.assert_zero(sq.clone() - x.clone() * x.clone());
                b.when_first_row().assert_zero(x.clone() - pis[0].clone());
                b.when_transition()
                    .assert_zero(next[0].clone() - x.clone() - AB::Expr::ONE);
                b.when_last_row().assert_zero(sq - pis[1].clone());
                if matches!(self, Toy::Counter) {
                    RANGE.lookup_key(b, [x], 1);
                }
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

fn witness() -> (Vec<RowMajorMatrix<Val>>, Vec<Vec<Val>>) {
    let n = 256u32;
    let mut counter = Vec::new();
    let mut table = Vec::new();
    for i in 0..n {
        counter.extend([Val::from_u32(i), Val::from_u32(i) * Val::from_u32(i)]);
        table.extend([Val::from_u32(i), Val::ONE]);
    }
    let last = Val::from_u32(n - 1);
    (
        vec![
            RowMajorMatrix::new(counter, 2),
            RowMajorMatrix::new(table, 2),
        ],
        vec![vec![Val::ZERO, last * last], vec![]],
    )
}

/// FNV-1a, to print a short fingerprint of a proof's bytes.
fn fnv(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// A challenger in one of several transcript states (different contents and
/// different numbers of buffered inputs).
fn transcript(state: u32) -> Challenger {
    let mut c = Challenger::new(permutation());
    for i in 0..(3 + state) {
        c.observe(Val::from_u32(state * 1_000 + i));
    }
    c
}

const STATES: u32 = 8;

/// Not a test on its own: prints what the parent tests compare, one fact per
/// line. Run by them in child processes with a given `RAYON_NUM_THREADS`.
#[test]
#[ignore = "helper: run by the tests below in child processes"]
fn grinding_witnesses_helper() {
    for s in 0..STATES {
        let w = transcript(s).grind(16);
        println!("UPSTREAM {s} {}", w.as_canonical_u64());
        let w = ProverChallenger::new(transcript(s)).grind(16);
        println!("PROVER {s} {}", w.as_canonical_u64());
    }
    let (traces, pv) = witness();
    let one_table = [Toy::Square];
    for seed in 0..3u64 {
        let cfg = || ProverConfig::new(&[seed as u8; 32], &mut ChaCha20Rng::seed_from_u64(seed));
        let line = |proof: &blacksilk_zk::Proof| {
            let bytes = encode_proof(proof);
            format!(
                "witness {} length {} fnv {:016x}",
                proof.opening_proof.1.query_pow_witness.as_canonical_u64(),
                bytes.len(),
                fnv(&bytes)
            )
        };
        let proof = prove(&cfg(), &one_table, &traces[..1], &pv[..1], &LIMITS[..1]).unwrap();
        println!("PROOF {seed} {}", line(&proof));
        let proof = prove(&cfg(), &AIRS, &traces, &pv, &LIMITS).unwrap();
        println!("PROOF2 {seed} {}", line(&proof));
    }
}

/// Runs the helper under `threads` rayon threads; returns its lines by key
/// (`"UPSTREAM <state>"`, `"PROOF <seed>"`).
fn run_helper(threads: usize) -> BTreeMap<String, String> {
    let out = Command::new(std::env::current_exe().unwrap())
        .args([
            HELPER,
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("RAYON_NUM_THREADS", threads.to_string())
        .output()
        .expect("run the helper");
    assert!(out.status.success(), "helper failed: {out:?}");
    // The harness prints "test <name> ... " before the first line of output.
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .filter_map(|l| {
            ["UPSTREAM ", "PROVER ", "PROOF ", "PROOF2 "]
                .iter()
                .find_map(|tag| l.find(tag))
                .map(|i| &l[i..])
        })
        .map(|l| {
            let mut parts = l.splitn(3, ' ');
            let key = format!("{} {}", parts.next().unwrap(), parts.next().unwrap());
            (key, parts.next().unwrap().to_string())
        })
        .collect()
}

/// The smallest valid nonce, by brute force with the verifier's own check.
fn smallest_by_brute_force(c: &Challenger, bits: usize) -> u64 {
    (0..Val::ORDER_U64)
        .find(|&w| c.clone().check_witness(bits, Val::from_u64(w)))
        .unwrap()
}

/// The leak, in upstream code: Plonky3 0.7.0's `grind` on one thread returns
/// the smallest valid nonce, and on 16 threads (almost surely, for at least
/// one of the eight transcript states) another one. This is why the prover
/// does not use it (see the next test).
#[test]
fn upstream_grinding_witness_depends_on_the_thread_count() {
    let runs: BTreeMap<usize, _> = THREADS.iter().map(|&t| (t, run_helper(t))).collect();
    for s in 0..STATES {
        let key = format!("UPSTREAM {s}");
        let min = smallest_by_brute_force(&transcript(s), 16);
        assert_eq!(runs[&1][&key], min.to_string(), "one thread scans in order");
        let by_threads: Vec<&str> = THREADS.iter().map(|t| runs[t][&key].as_str()).collect();
        println!("state {s}: smallest {min}; by 1/2/8/16 threads: {by_threads:?}");
    }
    let differs = (0..STATES).any(|s| {
        let key = format!("UPSTREAM {s}");
        runs[&1][&key] != runs[&16][&key]
    });
    assert!(
        differs,
        "upstream grinding gave the same witnesses on 1 and 16 threads for every state"
    );
}

/// 27 W6: the query-grinding witness does not depend on the prover's thread
/// count. The prover challenger's witness is the smallest valid nonce under
/// every thread count, and one-table proofs made with the same (seeded)
/// hiding randomness under 1, 2, 8 and 16 threads are byte-identical.
///
/// Two-table proofs are printed but not compared: Plonky3 0.7.0 draws each
/// table's quotient randomizers from the shared hiding RNG inside a rayon
/// loop over the tables (`p3-batch-stark` prover, `get_quotient_ldes`), so
/// which table gets which block of the random stream follows the scheduling.
/// Every table's randomizer is still fresh and uniform (the stream is not
/// reused), so this does not show in the proof's distribution, but it makes
/// multi-table proofs irreproducible from the seed; see the v3 record.
#[test]
fn proofs_do_not_depend_on_the_thread_count() {
    let runs: BTreeMap<usize, _> = THREADS.iter().map(|&t| (t, run_helper(t))).collect();
    for s in 0..STATES {
        let key = format!("PROVER {s}");
        let min = smallest_by_brute_force(&transcript(s), 16).to_string();
        for t in THREADS {
            assert_eq!(runs[&t][&key], min, "state {s}, {t} threads");
        }
    }
    for seed in 0..3 {
        let key = format!("PROOF {seed}");
        let lines: Vec<&str> = THREADS.iter().map(|t| runs[t][&key].as_str()).collect();
        println!("seed {seed}: {lines:?}");
        assert!(
            lines.iter().all(|l| *l == lines[0]),
            "seed {seed}: the proof depends on the thread count: {lines:?}"
        );
        let key = format!("PROOF2 {seed}");
        let lines: Vec<&str> = THREADS.iter().map(|t| runs[t][&key].as_str()).collect();
        println!("seed {seed}, two tables (not compared): {lines:?}");
    }
}

/// Challengers in many transcript states: every number of buffered inputs
/// (0 to 7, including right after a full absorb), and after a squeeze.
fn states() -> Vec<Challenger> {
    let mut out = Vec::new();
    for len in 0..=17u32 {
        let mut c = Challenger::new(permutation());
        for i in 0..len {
            c.observe(Val::from_u32(7 * len + i));
        }
        out.push(c.clone());
        let _: Val = c.sample();
        out.push(c);
    }
    out
}

/// The prover challenger's witness is exactly the smallest nonce the
/// verifier's `check_witness` accepts, and grinding leaves the transcript in
/// the state the verifier reaches by checking it.
#[test]
fn the_prover_grinds_the_smallest_valid_nonce() {
    let mut checked = 0;
    for (i, c) in states().into_iter().enumerate() {
        let bit_counts: &[usize] = if i % 6 == 0 {
            &[1, 4, 8, 12, 16]
        } else {
            &[1, 4, 8, 12]
        };
        for &bits in bit_counts {
            let min = smallest_by_brute_force(&c, bits);
            assert_eq!(
                smallest_pow_witness(&c, bits).as_canonical_u64(),
                min,
                "state {i}, {bits} bits"
            );
            let mut prover = ProverChallenger::new(c.clone());
            let w = prover.grind(bits);
            assert_eq!(w.as_canonical_u64(), min, "state {i}, {bits} bits");
            let mut verifier = c.clone();
            assert!(verifier.check_witness(bits, w));
            let (a, b): (Val, Val) = (prover.sample(), verifier.sample());
            assert_eq!(a, b, "state {i}, {bits} bits: transcripts diverge");
            checked += 1;
        }
        // Zero bits: no work, nothing absorbed (as upstream).
        let mut prover = ProverChallenger::new(c.clone());
        assert_eq!(prover.grind(0), Val::ZERO);
        let mut untouched = c.clone();
        let (a, b): (Val, Val) = (prover.sample(), untouched.sample());
        assert_eq!(a, b);
    }
    println!("{checked} (state, bits) cases: smallest nonce, same transcript");
}

/// The verifier is unchanged: proofs whose witness was found by Plonky3's own
/// thread-dependent search (the prover before 27 W6) still decode and verify,
/// and so do proofs of the current prover.
#[test]
fn proofs_from_the_upstream_grinding_prover_still_verify() {
    let (traces, pv) = witness();
    let v = VerifierConfig::new();
    for seed in 0..2u64 {
        let old = ProverConfig::with_upstream_grinding(
            &[0; 32],
            &[seed as u8; 32],
            &mut ChaCha20Rng::seed_from_u64(seed),
        );
        let proof = prove(&old, &AIRS, &traces, &pv, &LIMITS).unwrap();
        let decoded = decode_proof(&encode_proof(&proof)).expect("decodes");
        assert_eq!(verify(&v, &AIRS, &decoded, &pv, &LIMITS), Ok(()));
        let new = ProverConfig::new(&[seed as u8; 32], &mut ChaCha20Rng::seed_from_u64(seed));
        let proof = prove(&new, &AIRS, &traces, &pv, &LIMITS).unwrap();
        assert_eq!(verify(&v, &AIRS, &proof, &pv, &LIMITS), Ok(()));
    }
}

/// Grinding time at the parameter set's `QUERY_POW_BITS` (BS-ZK-4: 20 bits),
/// for the record of decision "BS-ZK-4" (docs/zk.md §11.3): the deterministic
/// smallest-nonce search over 64 transcript states, with the minimum, median,
/// mean and maximum time, and a brute-force cross-check of the result on the
/// first four states. Release only (timing):
/// `cargo test --release -p blacksilk-zk --test grinding -- --ignored --nocapture grinding_time`
#[test]
#[ignore = "timing; run in release"]
fn grinding_time_at_the_parameter_sets_bits() {
    use blacksilk_zk::params::QUERY_POW_BITS;
    use std::time::Instant;
    let bits = QUERY_POW_BITS;
    let mut times = Vec::new();
    let mut nonces = Vec::new();
    for s in 0..64u32 {
        let c = transcript(s);
        let t = Instant::now();
        let w = smallest_pow_witness(&c, bits);
        times.push(t.elapsed().as_secs_f64());
        assert!(c.clone().check_witness(bits, w));
        if s < 4 {
            assert_eq!(
                w.as_canonical_u64(),
                smallest_by_brute_force(&c, bits),
                "state {s}"
            );
        }
        nonces.push(w.as_canonical_u64());
    }
    let mut sorted = times.clone();
    sorted.sort_by(f64::total_cmp);
    let mean = times.iter().sum::<f64>() / times.len() as f64;
    let mean_nonce = nonces.iter().sum::<u64>() as f64 / nonces.len() as f64;
    println!(
        "{bits} bits, 64 states: min {:.1} ms, median {:.1} ms, mean {:.1} ms, max {:.1} ms; mean nonce {mean_nonce:.0} (2^{bits} = {})",
        sorted[0] * 1e3,
        sorted[32] * 1e3,
        mean * 1e3,
        sorted[63] * 1e3,
        1u64 << bits
    );
}
