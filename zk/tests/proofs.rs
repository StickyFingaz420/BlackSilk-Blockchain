//! ZK-1 tests (docs/zkvm.md §9 items 5–7) on a two-table system with a lookup:
//!
//! - `Counter` (width 2: `x`, `sq`): `x` counts up from a public start, `sq = x²`,
//!   and every `x` is looked up in the range table;
//! - `Range` (width 2: `v`, `mult`): `v = 0, 1, 2, …` provides each value
//!   `mult` times.
//!
//! Public values of `Counter`: `[start, last_sq, binding…]`.

use blacksilk_zk::config::{ProverConfig, Val, VerifierConfig};
use blacksilk_zk::params::{self, ProofShape};
use blacksilk_zk::{decode_proof, encode_proof, prove, verify, Proof, ZkError, PROOF_VERSION};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_lookup::{InteractionBuilder, LookupBus};
use p3_matrix::dense::RowMajorMatrix;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::panic::{catch_unwind, AssertUnwindSafe};

const RANGE: LookupBus<'static> = LookupBus::new("test/range");
const BINDING: usize = 4;

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
            Toy::Counter => 2 + BINDING,
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

/// Traces and public values of one statement.
type Witness = (Vec<RowMajorMatrix<Val>>, Vec<Vec<Val>>);
const LIMITS: [usize; 2] = [16, 16];

fn binding(tag: u32) -> Vec<Val> {
    (0..BINDING as u32)
        .map(|i| Val::from_u32(tag * 16 + i))
        .collect()
}

/// Counter over `start .. start + n`, range table over `0 .. range`.
fn witness(start: u32, n: usize, range: usize) -> Witness {
    let mut counter = Vec::with_capacity(2 * n);
    let mut mult = vec![0u32; range];
    for i in 0..n as u32 {
        let x = start + i;
        counter.push(Val::from_u32(x));
        counter.push(Val::from_u32(x) * Val::from_u32(x));
        if (x as usize) < range {
            mult[x as usize] += 1;
        }
    }
    let mut table = Vec::with_capacity(2 * range);
    for (v, m) in mult.iter().enumerate() {
        table.push(Val::from_u32(v as u32));
        table.push(Val::from_u32(*m));
    }
    let last = start + n as u32 - 1;
    let mut pv = vec![
        Val::from_u32(start),
        Val::from_u32(last) * Val::from_u32(last),
    ];
    pv.extend(binding(1));
    (
        vec![
            RowMajorMatrix::new(counter, 2),
            RowMajorMatrix::new(table, 2),
        ],
        vec![pv, vec![]],
    )
}

fn prover(seed: u64) -> ProverConfig {
    ProverConfig::new(&[seed as u8; 32], &mut ChaCha20Rng::seed_from_u64(seed))
}

fn honest_proof(seed: u64) -> (Proof, Vec<Vec<Val>>) {
    let (traces, pv) = witness(3, 64, 256);
    let proof = prove(&prover(seed), &AIRS, &traces, &pv, &LIMITS).expect("honest proof");
    (proof, pv)
}

#[test]
fn honest_proofs_verify_and_round_trip() {
    let (proof, pv) = honest_proof(1);
    let v = VerifierConfig::new();
    assert_eq!(verify(&v, &AIRS, &proof, &pv, &LIMITS), Ok(()));
    let bytes = encode_proof(&proof);
    println!("toy proof: {} bytes", bytes.len());
    assert!(bytes.len() < params::MAX_PROOF_BYTES);
    let decoded = decode_proof(&bytes).expect("decodes");
    assert_eq!(verify(&v, &AIRS, &decoded, &pv, &LIMITS), Ok(()));
    // The smallest allowed height works too.
    let (traces, pv) = witness(0, 1 << params::MIN_LOG_HEIGHT, 1 << params::MIN_LOG_HEIGHT);
    let p = prove(&prover(2), &AIRS, &traces, &pv, &LIMITS).unwrap();
    assert_eq!(verify(&v, &AIRS, &p, &pv, &LIMITS), Ok(()));
}

#[test]
fn wrong_public_values_and_binding_are_rejected() {
    let (proof, pv) = honest_proof(3);
    let v = VerifierConfig::new();
    let mut bad = pv.clone();
    bad[0][0] += Val::ONE;
    assert!(matches!(
        verify(&v, &AIRS, &proof, &bad, &LIMITS),
        Err(ZkError::Invalid(_))
    ));
    let mut bad = pv.clone();
    bad[0][1] += Val::ONE;
    assert!(matches!(
        verify(&v, &AIRS, &proof, &bad, &LIMITS),
        Err(ZkError::Invalid(_))
    ));
    // The binding values are unconstrained by the AIR but part of the
    // transcript: a proof for one transaction does not verify for another.
    let mut other_tx = pv.clone();
    other_tx[0].truncate(2);
    other_tx[0].extend(binding(2));
    assert!(matches!(
        verify(&v, &AIRS, &proof, &other_tx, &LIMITS),
        Err(ZkError::Invalid(_))
    ));
    // Missing public values, or values for the wrong table.
    let mut short = pv.clone();
    short[0].pop();
    assert!(verify(&v, &AIRS, &proof, &short, &LIMITS).is_err());
    let swapped = vec![pv[1].clone(), pv[0].clone()];
    assert!(verify(&v, &AIRS, &proof, &swapped, &LIMITS).is_err());
}

#[test]
fn false_statements_cannot_be_proven() {
    // (a) A counter value outside the range table: the lookup cannot balance.
    // (b) A wrong square. Either the prover's debug checker refuses (panic) or
    // the produced proof must not verify.
    let v = VerifierConfig::new();
    let cases: Vec<Witness> = vec![
        witness(200, 64, 256), // 200..263 runs past the 256-entry table
        {
            let (mut t, pv) = witness(3, 64, 256);
            t[0].values[1] += Val::ONE; // sq of row 0
            (t, pv)
        },
    ];
    for (i, (traces, pv)) in cases.into_iter().enumerate() {
        let result = catch_unwind(AssertUnwindSafe(|| {
            prove(&prover(10 + i as u64), &AIRS, &traces, &pv, &LIMITS)
        }));
        if let Ok(Ok(proof)) = result {
            assert!(
                verify(&v, &AIRS, &proof, &pv, &LIMITS).is_err(),
                "false statement {i} verified"
            );
        }
    }
}

#[test]
fn claimed_heights_and_table_counts_are_checked_first() {
    let (proof, pv) = honest_proof(4);
    let v = VerifierConfig::new();
    for bad_bits in [0usize, 1, params::MIN_LOG_HEIGHT, 40, usize::MAX] {
        let mut p = decode_proof(&encode_proof(&proof)).unwrap();
        p.degree_bits[0] = bad_bits;
        assert!(
            matches!(
                verify(&v, &AIRS, &p, &pv, &LIMITS),
                Err(ZkError::Height { .. })
            ),
            "degree bits {bad_bits}"
        );
    }
    // A per-table limit lower than the proof's height.
    assert!(matches!(
        verify(&v, &AIRS, &proof, &pv, &[5, 16]),
        Err(ZkError::Height { .. })
    ));
    // One table too few or too many.
    assert!(matches!(
        verify(&v, &AIRS[..1], &proof, &pv[..1], &LIMITS[..1]),
        Err(ZkError::Shape(_))
    ));
    let three = [Toy::Counter, Toy::Range, Toy::Range];
    let pv3 = vec![pv[0].clone(), vec![], vec![]];
    assert!(matches!(
        verify(&v, &three, &proof, &pv3, &[16, 16, 16]),
        Err(ZkError::Shape(_))
    ));
    // Tables in the wrong order.
    let swapped = [Toy::Range, Toy::Counter];
    assert!(verify(
        &v,
        &swapped,
        &proof,
        &[pv[1].clone(), pv[0].clone()],
        &LIMITS
    )
    .is_err());
}

#[test]
fn byte_mutations_never_verify_and_never_panic_the_caller() {
    let (proof, pv) = honest_proof(5);
    let v = VerifierConfig::new();
    let bytes = encode_proof(&proof);
    let mut outcomes = [0usize; 4]; // decode error, invalid, height/shape, panicked
                                    // Flip one byte at ~400 positions spread over the whole proof.
    let step = (bytes.len() / 400).max(1);
    for pos in (0..bytes.len()).step_by(step) {
        let mut b = bytes.clone();
        b[pos] ^= 0x5a;
        match decode_proof(&b) {
            Err(_) => outcomes[0] += 1,
            Ok(p) => match verify(&v, &AIRS, &p, &pv, &LIMITS) {
                Ok(()) => panic!("mutated proof at byte {pos} verified"),
                Err(ZkError::Invalid(_)) => outcomes[1] += 1,
                Err(ZkError::Height { .. }) | Err(ZkError::Shape(_)) => outcomes[2] += 1,
                Err(ZkError::VerifierPanicked) => outcomes[3] += 1,
                Err(e) => panic!("unexpected {e:?}"),
            },
        }
    }
    println!(
        "mutations: {} decode errors, {} invalid, {} shape/height, {} verifier panics caught",
        outcomes[0], outcomes[1], outcomes[2], outcomes[3]
    );
}

#[test]
fn encoding_is_strict() {
    let (proof, _) = honest_proof(6);
    let bytes = encode_proof(&proof);
    assert!(matches!(decode_proof(&[]), Err(ZkError::Encoding(_))));
    // Unknown versions are refused.
    for version in [0, PROOF_VERSION + 1] {
        let mut other = bytes.clone();
        other[0] = version;
        assert!(matches!(decode_proof(&other), Err(ZkError::Encoding(_))));
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(matches!(decode_proof(&trailing), Err(ZkError::Encoding(_))));
    assert!(matches!(
        decode_proof(&bytes[..bytes.len() / 2]),
        Err(ZkError::Encoding(_))
    ));
    let huge = vec![1u8; params::MAX_PROOF_BYTES + 1];
    assert!(matches!(decode_proof(&huge), Err(ZkError::Encoding(_))));
    // Garbage of every small length decodes to an error, never a panic.
    for len in 0..64 {
        let _ = decode_proof(&vec![1u8; len]);
    }
}

#[test]
fn proofs_are_randomized() {
    // Same statement, fresh hiding randomness: different proofs, both valid.
    let (a, pv) = honest_proof(7);
    let (b, _) = honest_proof(8);
    assert_ne!(encode_proof(&a), encode_proof(&b));
    // Field elements are fixed-width, so values never change the length.
    // What varies is the number of distinct Merkle nodes in the pruned query
    // paths, a function of the public query positions (privacy review P-5).
    println!(
        "two proofs of one statement: {} and {} bytes",
        encode_proof(&a).len(),
        encode_proof(&b).len()
    );
    let v = VerifierConfig::new();
    assert!(verify(&v, &AIRS, &a, &pv, &LIMITS).is_ok());
    assert!(verify(&v, &AIRS, &b, &pv, &LIMITS).is_ok());
    // The witness digest alone (a broken OS RNG) still changes the proof.
    let (traces, pv) = witness(3, 64, 256);
    struct Zero;
    impl rand_core::RngCore for Zero {
        fn next_u32(&mut self) -> u32 {
            0
        }
        fn next_u64(&mut self) -> u64 {
            0
        }
        fn fill_bytes(&mut self, d: &mut [u8]) {
            d.fill(0)
        }
        fn try_fill_bytes(&mut self, d: &mut [u8]) -> Result<(), rand_core::Error> {
            d.fill(0);
            Ok(())
        }
    }
    impl rand_core::CryptoRng for Zero {}
    let p1 = prove(
        &ProverConfig::new(&[1; 32], &mut Zero),
        &AIRS,
        &traces,
        &pv,
        &LIMITS,
    )
    .unwrap();
    let p2 = prove(
        &ProverConfig::new(&[2; 32], &mut Zero),
        &AIRS,
        &traces,
        &pv,
        &LIMITS,
    )
    .unwrap();
    assert_ne!(encode_proof(&p1), encode_proof(&p2));
}

#[test]
fn toy_shape_meets_the_security_floor() {
    let s = params::security(&ProofShape {
        constraints: 8,
        max_degree: 2,
        committed_columns: 16,
        log_height: 8,
    });
    assert!(s.johnson_bits >= params::MIN_PROVEN_BITS, "{s:?}");
    // Keep the value visible in test logs.
    let _ = Val::ORDER_U32;
}

/// Regression (found while building the zkVM): preprocessed tables must be
/// committed identically by prover and verifier. A counter whose values are
/// looked up in a *preprocessed* range table must prove and verify.
mod preprocessed {
    use super::*;
    use p3_matrix::dense::RowMajorMatrix;

    #[derive(Clone, Copy, Debug)]
    enum P {
        Counter,
        Table,
    }

    const N: usize = 64;

    impl<F: p3_field::Field> BaseAir<F> for P {
        fn width(&self) -> usize {
            match self {
                P::Counter => 1,
                P::Table => 1,
            }
        }
        fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
            match self {
                P::Counter => None,
                P::Table => Some(RowMajorMatrix::new(
                    (0..N as u32).map(F::from_u32).collect(),
                    1,
                )),
            }
        }
        fn preprocessed_width(&self) -> usize {
            match self {
                P::Counter => 0,
                P::Table => 1,
            }
        }
    }

    impl<AB: AirBuilder<F = Val> + InteractionBuilder> Air<AB> for P {
        fn eval(&self, b: &mut AB) {
            use p3_air::WindowAccess;
            let main: Vec<AB::Expr> = b
                .main()
                .current_slice()
                .iter()
                .map(|v| (*v).into())
                .collect();
            match self {
                P::Counter => RANGE.lookup_key(b, [main[0].clone()], 1),
                P::Table => {
                    let v: AB::Expr = b.preprocessed().current_slice()[0].into();
                    RANGE.table_entry(b, [v], main[0].clone());
                }
            }
        }
    }

    #[test]
    fn statements_with_preprocessed_tables_verify() {
        let airs = [P::Counter, P::Table];
        let counter = RowMajorMatrix::new((0..N as u32).map(|i| Val::from_u32(i / 2)).collect(), 1);
        let mut mult = vec![Val::ZERO; N];
        for i in 0..N {
            mult[i / 2] += Val::ONE;
        }
        let traces = vec![counter, RowMajorMatrix::new(mult, 1)];
        let pv = vec![vec![], vec![]];
        let proof = prove(&prover(20), &airs, &traces, &pv, &LIMITS).unwrap();
        assert_eq!(
            verify(&VerifierConfig::new(), &airs, &proof, &pv, &LIMITS),
            Ok(())
        );
    }
}
