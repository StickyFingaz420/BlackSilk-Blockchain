//! The query proof-of-work witness is checked, not only absorbed (red-team
//! follow-up to the PX tamper sweep, mutant M6).
//!
//! A single-byte tamper sweep cannot catch a verifier that accepts any query
//! grinding witness: the witness is still observed, so a changed one moves
//! the query positions and the proof fails anyway. This test builds the
//! proof such a verifier would accept: a prover whose challenger, at the
//! query grinding step, publishes a witness that **fails** the grinding check
//! and absorbs it exactly as the verifier's `check_witness` does (observe,
//! then sample the grinding bits), so every later challenge and every query
//! opening is consistent with that witness. The real verifier must refuse it
//! with `FriError::InvalidPowWitness` (as `ZkError::Invalid`).
//!
//! The proof is built with Plonky3's `prove_batch` and a test-side copy of
//! BS-ZK-4's configuration (the same parameters, permutation, transcript
//! prefix and statement digest as `VerifierConfig::new`; only the hiding
//! seeds and the challenger's grinding differ), so no production code is
//! involved beyond what the verifier runs. A control proof from the same
//! harness with the honest (smallest valid) witness verifies, which shows the
//! harness reproduces the real prover's transcript.

use blacksilk_zk::config::{
    permutation, smallest_pow_witness, Challenge, ChallengeMmcs, Challenger, Compress, Dft, Hash,
    Pcs, Val, ValMmcs, VerifierConfig,
};
use blacksilk_zk::params::{self, NUM_RANDOM_CODEWORDS};
use blacksilk_zk::{decode_proof, encode_proof, verify, Proof, ZkError};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_batch_stark::{prove_batch, ProverData, StarkInstance};
use p3_challenger::{CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger};
use p3_field::{Algebra, BasedVectorSpace, PrimeCharacteristicRing};
use p3_fri::FriParameters;
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::StarkConfig;
use rand::rngs::StdRng;
use rand::SeedableRng;

// ------------------------------------------------ a one-table toy statement

/// `x` counts from the first public value; `sq = x²`; the last `sq` is the
/// second public value (as grinding.rs's `Toy::Square`).
#[derive(Clone, Copy, Debug)]
struct Square;

impl<F> BaseAir<F> for Square {
    fn width(&self) -> usize {
        2
    }
    fn num_public_values(&self) -> usize {
        2
    }
}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for Square {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let local: Vec<AB::Expr> = main.current_slice().iter().map(|v| (*v).into()).collect();
        let next: Vec<AB::Expr> = main.next_slice().iter().map(|v| (*v).into()).collect();
        let pis: Vec<AB::Expr> = b.public_values().iter().map(|v| (*v).into()).collect();
        let (x, sq) = (local[0].clone(), local[1].clone());
        b.assert_zero(sq.clone() - x.clone() * x.clone());
        b.when_first_row().assert_zero(x.clone() - pis[0].clone());
        b.when_transition()
            .assert_zero(next[0].clone() - x.clone() - AB::Expr::ONE);
        b.when_last_row().assert_zero(sq - pis[1].clone());
    }
}

const LIMITS: [usize; 1] = [16];

fn witness() -> (RowMajorMatrix<Val>, Vec<Val>) {
    let n = 256u32;
    let mut rows = Vec::new();
    for i in 0..n {
        rows.extend([Val::from_u32(i), Val::from_u32(i) * Val::from_u32(i)]);
    }
    let last = Val::from_u32(n - 1);
    (RowMajorMatrix::new(rows, 2), vec![Val::ZERO, last * last])
}

// ------------------------------------------------ the test prover's challenger

/// BS-ZK-4's challenger, whose query grinding publishes either the honest
/// witness (the smallest valid nonce, as the production prover) or one that
/// fails the check. Either way the witness is absorbed with the verifier's
/// own `check_witness`, so the transcript afterwards is the verifier's.
#[derive(Clone, Debug)]
struct TestChallenger {
    inner: Challenger,
    bad_query_pow: bool,
}

impl<T> CanObserve<T> for TestChallenger
where
    Challenger: CanObserve<T>,
{
    fn observe(&mut self, value: T) {
        self.inner.observe(value);
    }
    fn observe_slice(&mut self, values: &[T])
    where
        T: Clone,
    {
        self.inner.observe_slice(values);
    }
}

impl<T> CanSample<T> for TestChallenger
where
    Challenger: CanSample<T>,
{
    fn sample(&mut self) -> T {
        self.inner.sample()
    }
    fn sample_array<const N: usize>(&mut self) -> [T; N] {
        self.inner.sample_array()
    }
    fn sample_vec(&mut self, n: usize) -> Vec<T> {
        self.inner.sample_vec(n)
    }
}

impl CanSampleBits<usize> for TestChallenger {
    fn sample_bits(&mut self, bits: usize) -> usize {
        self.inner.sample_bits(bits)
    }
}

impl FieldChallenger<Val> for TestChallenger {
    fn observe_algebra_element<A: BasedVectorSpace<Val>>(&mut self, alg_elem: A) {
        self.inner.observe_algebra_element(alg_elem);
    }
    fn observe_algebra_slice<A: BasedVectorSpace<Val> + Clone>(&mut self, alg_elems: &[A]) {
        self.inner.observe_algebra_slice(alg_elems);
    }
    fn sample_algebra_element<A: BasedVectorSpace<Val>>(&mut self) -> A {
        self.inner.sample_algebra_element()
    }
    fn observe_base_as_algebra_element<EF>(&mut self, val: Val)
    where
        EF: Algebra<Val> + BasedVectorSpace<Val>,
    {
        self.inner.observe_base_as_algebra_element::<EF>(val);
    }
}

impl GrindingChallenger for TestChallenger {
    type Witness = Val;

    fn grind(&mut self, bits: usize) -> Val {
        // Zero bits (the commit phase under BS-ZK-4): no work, nothing
        // absorbed, as the production prover.
        if bits == 0 {
            return Val::ZERO;
        }
        let witness = if self.bad_query_pow {
            // The first nonce that fails the verifier's check (almost surely
            // 0; a nonce passes with probability 2^-bits).
            (0u64..)
                .map(Val::from_u64)
                .find(|&w| !self.inner.clone().check_witness(bits, w))
                .expect("a failing nonce")
        } else {
            smallest_pow_witness(&self.inner, bits)
        };
        // Absorb it exactly as the verifier will: observe, sample the bits.
        let passes = self.inner.check_witness(bits, witness);
        assert_eq!(passes, !self.bad_query_pow);
        witness
    }

    fn check_witness(&mut self, bits: usize, witness: Val) -> bool {
        self.inner.check_witness(bits, witness)
    }
}

type TestConfig = StarkConfig<Pcs, Challenge, TestChallenger>;

/// BS-ZK-4's configuration (zk/src/config.rs `build_prover` and `pcs`) with
/// the test challenger, for the statement digest `[0; 32]` of
/// `VerifierConfig::new`.
fn test_config(bad_query_pow: bool) -> TestConfig {
    let perm = permutation();
    let val_mmcs = ValMmcs::new(
        Hash::new(perm.clone()),
        Compress::new(perm.clone()),
        0,
        StdRng::from_seed([7; 32]),
    );
    let fri = FriParameters {
        log_blowup: params::LOG_BLOWUP,
        log_final_poly_len: params::LOG_FINAL_POLY_LEN,
        max_log_arity: params::MAX_LOG_ARITY,
        num_queries: params::NUM_QUERIES,
        commit_proof_of_work_bits: params::COMMIT_POW_BITS,
        query_proof_of_work_bits: params::QUERY_POW_BITS,
        mmcs: ChallengeMmcs::new(val_mmcs.clone()),
    };
    let pcs = Pcs::new(
        Dft::default(),
        val_mmcs,
        fri,
        NUM_RANDOM_CODEWORDS,
        StdRng::from_seed([9; 32]),
    );
    // The transcript prefix: the parameter-set identifier, then the
    // statement digest (zk/src/config.rs `challenger`).
    let mut c = Challenger::new(perm);
    c.observe(Val::from_u32(params::PARAMS_ID.len() as u32));
    for b in params::PARAMS_ID {
        c.observe(Val::from_u8(*b));
    }
    for b in [0u8; 32] {
        c.observe(Val::from_u8(b));
    }
    StarkConfig::new(
        pcs,
        TestChallenger {
            inner: c,
            bad_query_pow,
        },
    )
}

/// Proves the toy statement with the test configuration (as
/// `blacksilk_zk::prove`, which has no preprocessed table here).
fn prove_with(bad_query_pow: bool) -> Proof {
    let cfg = test_config(bad_query_pow);
    let (trace, public) = witness();
    let airs = [Square];
    let traces = [&trace];
    let publics = [public];
    let instances = StarkInstance::new_multiple(&airs, &traces, &publics);
    let data = ProverData::from_instances(&cfg, &instances);
    let p = prove_batch(&cfg, &instances, &data);
    // The proof types coincide field by field (as in `blacksilk_zk::prove`).
    Proof {
        commitments: p.commitments,
        opened_values: p.opened_values,
        opening_proof: p.opening_proof,
        lookup_terminals: p.lookup_terminals,
        degree_bits: p.degree_bits,
    }
}

fn check(proof: &Proof) -> Result<(), ZkError> {
    // The encoding is canonical: the proof is refused by verification, not by
    // decoding.
    let decoded = decode_proof(&encode_proof(proof)).expect("the proof decodes");
    let (_, public) = witness();
    verify(
        &VerifierConfig::new(),
        &[Square],
        &decoded,
        &[public],
        &LIMITS,
    )
}

/// The control: the harness with the honest witness gives a valid proof.
#[test]
fn the_harness_with_the_honest_witness_verifies() {
    let proof = prove_with(false);
    assert_eq!(check(&proof), Ok(()));
}

/// A proof consistent with a query grinding witness that fails the check is
/// refused, with the grinding error.
#[test]
fn a_query_pow_witness_that_fails_the_check_is_refused() {
    let honest = prove_with(false);
    let proof = prove_with(true);
    let w = proof.opening_proof.1.query_pow_witness;
    assert_ne!(w, honest.opening_proof.1.query_pow_witness);
    // That the witness fails the check for its transcript is asserted where
    // the test challenger absorbs it (`grind`).
    match check(&proof) {
        Err(ZkError::Invalid(msg)) => assert!(
            msg.contains("InvalidPowWitness"),
            "refused for another reason: {msg}"
        ),
        other => panic!("expected the grinding refusal, got {other:?}"),
    }
}
