//! STARK configuration for BS-ZK-3 (docs/zk.md §9.2–9.3, docs/proof-system.md).
//!
//! | Part | Choice |
//! |---|---|
//! | Base field | BabyBear, p = 2^31 − 2^27 + 1 |
//! | Challenge field | degree-8 binomial extension (247 bits) |
//! | Hash | Poseidon2, width 16, standard BabyBear constants |
//! | Merkle tree | salted leaves (`MerkleTreeHidingMmcs`), 8-element digests |
//! | PCS | `HidingFriPcs` (zero-knowledge FRI) |
//! | Fiat–Shamir | duplex sponge on the same Poseidon2, pre-seeded with [`params::PARAMS_ID`] |
//!
//! **Hiding randomness.** The salted Merkle tree and the hiding PCS each own an
//! RNG. Zero knowledge holds only if these are unpredictable and fresh for every
//! proof, so [`ProverConfig::new`] seeds them from a hedged derivation: the OS
//! CSPRNG mixed with a digest of the witness (transactions.md §10). A broken OS
//! RNG then still yields per-statement unpredictable seeds.
//!
//! [`VerifierConfig`] uses fixed seeds, and the type cannot produce proofs, so a
//! verifier configuration can never be used to prove with predictable
//! randomness. Committing preprocessed tables does draw Merkle salts; both
//! `prove` and `verify` do it with a fresh deterministic setup configuration
//! ([`VerifierConfig::setup`] and its prover-side twin), so a caller's
//! configuration is never consumed and can be reused (ZK-F3).
//!
//! **Prover and verifier challengers.** The verifier uses Plonky3's
//! [`DuplexChallenger`] ([`Challenger`], [`ZkConfig`]) unchanged. The prover
//! uses [`ProverChallenger`] ([`ProverZkConfig`]): the same challenger, whose
//! only difference is how it *finds* the query proof-of-work witness
//! (deterministically, the smallest valid nonce; 27 W6). Both produce the same
//! transcript and the same proof type, so this is prover policy, not a rule.

use crate::params::{self, NUM_RANDOM_CODEWORDS};
use blacksilk_crypto::hash::{tags, Hasher64};
use p3_baby_bear::{default_babybear_poseidon2_16, BabyBear, Poseidon2BabyBear};
use p3_challenger::{
    CanObserve, CanSample, CanSampleBits, DuplexChallenger, FieldChallenger, GrindingChallenger,
};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{
    Algebra, BasedVectorSpace, Field, PackedValue, PrimeCharacteristicRing, PrimeField64,
};
use p3_fri::{FriParameters, HidingFriPcs};
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{PaddingFreeSponge, Permutation, TruncatedPermutation};
use p3_uni_stark::StarkConfig;
use rand::rngs::StdRng;
use rand::SeedableRng;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

pub type Val = BabyBear;
pub type Challenge = BinomialExtensionField<Val, { params::EXTENSION_DEGREE }>;
pub type Perm = Poseidon2BabyBear<16>;
pub type Hash = PaddingFreeSponge<Perm, 16, 8, 8>;
pub type Compress = TruncatedPermutation<Perm, 2, 8, 16>;
pub type ValMmcs = MerkleTreeHidingMmcs<
    <Val as Field>::Packing,
    <Val as Field>::Packing,
    Hash,
    Compress,
    StdRng,
    2,
    8,
    { params::MERKLE_SALT_ELEMS },
>;
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
pub type Dft = Radix2DitParallel<Val>;
pub type Pcs = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs, StdRng>;
/// Sponge width and rate of [`Challenger`].
const WIDTH: usize = 16;
const RATE: usize = 8;
pub type Challenger = DuplexChallenger<Val, Perm, WIDTH, RATE>;
/// The Plonky3 configuration type of every BlackSilk proof, and the verifier's.
pub type ZkConfig = StarkConfig<Pcs, Challenge, Challenger>;
/// The prover's configuration type: [`ZkConfig`] with the [`ProverChallenger`].
/// Its proofs have the same type and bytes as [`ZkConfig`] proofs.
pub type ProverZkConfig = StarkConfig<Pcs, Challenge, ProverChallenger>;

/// The prover's Fiat–Shamir challenger: [`Challenger`] (Plonky3's
/// `DuplexChallenger`) with **deterministic proof-of-work grinding**
/// (27 W6, finding F27-3).
///
/// Every operation delegates to the inner challenger, so the transcript is
/// identical, except [`GrindingChallenger::grind`]. Plonky3 0.7.0 searches the
/// nonce with rayon's `find_map_any`, which returns whichever thread finds a
/// valid nonce first: the published `query_pow_witness` then sits near the
/// start of some thread's slice of the field and reveals a class of the
/// prover's thread count, linking proofs made on one device (and the query
/// positions, hence the proof length, follow the witness). This challenger
/// returns the **smallest** valid nonce, a function of the transcript alone.
///
/// The verifier is untouched: `check_witness` accepts any valid nonce, so
/// proofs from upstream-grinding provers still verify. The search is
/// sequential, SIMD-packed as upstream's: about 2^16 permutations on average at
/// 16 bits, a few milliseconds. (Raising the grinding bits would call for a
/// chunk-parallel scan that still returns the smallest nonce, F27-7.)
#[derive(Clone, Debug)]
pub struct ProverChallenger {
    inner: Challenger,
    /// Test only: grind with Plonky3's own search (the pre-W6 prover).
    upstream_grinding: bool,
}

impl ProverChallenger {
    /// The prover challenger around `inner`.
    pub fn new(inner: Challenger) -> Self {
        Self {
            inner,
            upstream_grinding: false,
        }
    }
}

impl<T> CanObserve<T> for ProverChallenger
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

impl<T> CanSample<T> for ProverChallenger
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

impl CanSampleBits<usize> for ProverChallenger {
    fn sample_bits(&mut self, bits: usize) -> usize {
        self.inner.sample_bits(bits)
    }
}

impl FieldChallenger<Val> for ProverChallenger {
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

impl GrindingChallenger for ProverChallenger {
    type Witness = Val;

    fn grind(&mut self, bits: usize) -> Val {
        if self.upstream_grinding {
            return self.inner.grind(bits);
        }
        // As upstream: zero bits need no work and absorb nothing.
        if bits == 0 {
            return Val::ZERO;
        }
        let witness = smallest_pow_witness(&self.inner, bits);
        // The verifier's check, which also absorbs the witness exactly as
        // upstream's `grind` does.
        assert!(
            self.inner.check_witness(bits, witness),
            "the proof-of-work search disagrees with the verifier's check"
        );
        witness
    }

    fn check_witness(&mut self, bits: usize, witness: Val) -> bool {
        self.inner.check_witness(bits, witness)
    }
}

/// The smallest `w` (as a canonical integer) such that `challenger`, after
/// observing `w`, samples `bits` zero low bits: the proof-of-work witness the
/// verifier's `check_witness` accepts, found by a scan in increasing order.
///
/// Mirrors Plonky3 0.7.0's `DuplexChallenger::grind`, which absorbs a
/// candidate by overwriting the next free rate slot, zeroing the rest of the
/// rate and adding the absorbed length to the first capacity element, then
/// reads the sample from the last rate element after one permutation; `lanes`
/// candidates share each packed permutation. Unlike upstream, it scans the
/// candidates in order on one thread, so the result depends on the transcript
/// only. Callers confirm the result with `check_witness` (the verifier's
/// code), so a mismatch here could never yield an invalid proof.
///
/// # Panics
/// If `bits ≥ 31`, or (probability far below 2^-1000) no field element works.
pub fn smallest_pow_witness(challenger: &Challenger, bits: usize) -> Val {
    type Packed = <Val as Field>::Packing;
    assert!(
        (1u64 << bits) < Val::ORDER_U64,
        "too many proof-of-work bits"
    );
    let slot = challenger.input_buffer.len();
    assert!(slot < RATE, "a full input buffer is absorbed immediately");
    let tagged_capacity = challenger.sponge_state[RATE] + Val::from_u8((slot + 1) as u8);
    let base: [Packed; WIDTH] = core::array::from_fn(|i| {
        if i < slot {
            Packed::from(challenger.input_buffer[i])
        } else if i < RATE {
            Packed::ZERO
        } else if i == RATE {
            Packed::from(tagged_capacity)
        } else {
            Packed::from(challenger.sponge_state[i])
        }
    });
    let mask = (1u64 << bits) - 1;
    let order = Val::ORDER_U64;
    let lanes = Packed::WIDTH as u64;
    let mut start = 0u64;
    while start < order {
        let mut state = base;
        // Candidates past the field order repeat the last one; they are
        // skipped below.
        state[slot] = Packed::from_fn(|l| Val::from_u64((start + l as u64).min(order - 1)));
        challenger.permutation.permute_mut(&mut state);
        for (l, sample) in state[RATE - 1].as_slice().iter().enumerate() {
            let candidate = start + l as u64;
            if candidate < order && sample.as_canonical_u64() & mask == 0 {
                return Val::from_u64(candidate);
            }
        }
        start += lanes;
    }
    panic!("no proof-of-work witness in the field");
}

/// The standard Poseidon2 permutation (BabyBear, width 16).
pub fn permutation() -> Perm {
    default_babybear_poseidon2_16()
}

/// The Fiat–Shamir challenger, having absorbed the parameter-set identifier
/// (so transcripts of different parameter sets, or of other Plonky3 users,
/// never coincide) and the statement digest.
///
/// **Statement digest.** Public data the verifier supplies to the AIRs
/// itself (periodic columns: programs, images, claimed outputs) is not
/// committed by Plonky3 and not observed by it. It must enter the transcript
/// before the first challenge, or a prover could choose it after seeing the
/// challenges (a "Frozen Heart" weak Fiat–Shamir). Callers pass a digest of
/// all such data; public values are observed by Plonky3 itself.
fn challenger(perm: &Perm, statement: &[u8; 32]) -> Challenger {
    let mut c = Challenger::new(perm.clone());
    c.observe(Val::from_u32(params::PARAMS_ID.len() as u32));
    for b in params::PARAMS_ID {
        c.observe(Val::from_u8(*b));
    }
    for b in statement {
        c.observe(Val::from_u8(*b));
    }
    c
}

/// A transcript sample for the consensus fingerprint (RTFP3-11): the
/// verifier's challenger for `statement` ([`challenger`]: the parameter-set
/// identifier, then the statement digest), after observing `observed`,
/// samples one extension-field challenge (its basis coefficients), one base
/// element and 20 bits, as canonical integers. Every proof's challenges come
/// from this transcript, so a changed challenger construction, permutation or
/// absorption order changes the sample.
pub fn transcript_sample(statement: &[u8; 32], observed: &[u32]) -> Vec<u64> {
    let mut c = challenger(&permutation(), statement);
    for &w in observed {
        c.observe(Val::from_u32(w));
    }
    let ext: Challenge = c.sample_algebra_element();
    let mut out: Vec<u64> = BasedVectorSpace::<Val>::as_basis_coefficients_slice(&ext)
        .iter()
        .map(|v| v.as_canonical_u64())
        .collect();
    let base: Val = c.sample();
    out.push(base.as_canonical_u64());
    out.push(c.sample_bits(20) as u64);
    out
}

fn build(mmcs_seed: [u8; 32], pcs_seed: [u8; 32], statement: &[u8; 32]) -> ZkConfig {
    StarkConfig::new(
        pcs(mmcs_seed, pcs_seed),
        challenger(&permutation(), statement),
    )
}

fn build_prover(
    mmcs_seed: [u8; 32],
    pcs_seed: [u8; 32],
    statement: &[u8; 32],
    upstream_grinding: bool,
) -> ProverZkConfig {
    let challenger = ProverChallenger {
        inner: challenger(&permutation(), statement),
        upstream_grinding,
    };
    StarkConfig::new(pcs(mmcs_seed, pcs_seed), challenger)
}

fn pcs(mmcs_seed: [u8; 32], pcs_seed: [u8; 32]) -> Pcs {
    let perm = permutation();
    let val_mmcs = ValMmcs::new(
        Hash::new(perm.clone()),
        Compress::new(perm.clone()),
        0,
        StdRng::from_seed(mmcs_seed),
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
    Pcs::new(
        Dft::default(),
        val_mmcs,
        fri,
        NUM_RANDOM_CODEWORDS,
        StdRng::from_seed(pcs_seed),
    )
}

/// The prover-side twin of [`VerifierConfig::setup`]: the same deterministic
/// seeds, so preprocessed (public) tables are committed exactly as the
/// verifier recomputes them. Only for `ProverData`; never used to prove.
pub(crate) fn prover_setup() -> ProverZkConfig {
    build_prover([0; 32], [0; 32], &[0; 32], false)
}

/// Configuration for proving. Build a fresh one for every proof.
pub struct ProverConfig(ProverZkConfig);

impl ProverConfig {
    /// `witness_digest` should commit to the secret inputs of this proof; it
    /// is mixed into the seeds so that a failing OS RNG still gives
    /// unpredictable, statement-specific hiding randomness.
    pub fn new<R: RngCore + CryptoRng>(witness_digest: &[u8; 32], rng: &mut R) -> Self {
        Self::for_statement(&[0; 32], witness_digest, rng)
    }

    /// As [`new`](Self::new), bound to `statement` (see the statement digest
    /// on the challenger). The verifier must use the same digest.
    pub fn for_statement<R: RngCore + CryptoRng>(
        statement: &[u8; 32],
        witness_digest: &[u8; 32],
        rng: &mut R,
    ) -> Self {
        Self::build(statement, witness_digest, rng, false)
    }

    /// **Tests only.** As [`for_statement`](Self::for_statement), but grinding
    /// with Plonky3's own thread-dependent search: the prover before 27 W6. It
    /// exists to show that such proofs still verify.
    #[doc(hidden)]
    pub fn with_upstream_grinding<R: RngCore + CryptoRng>(
        statement: &[u8; 32],
        witness_digest: &[u8; 32],
        rng: &mut R,
    ) -> Self {
        Self::build(statement, witness_digest, rng, true)
    }

    fn build<R: RngCore + CryptoRng>(
        statement: &[u8; 32],
        witness_digest: &[u8; 32],
        rng: &mut R,
        upstream_grinding: bool,
    ) -> Self {
        let mut fresh = [0u8; 32];
        rng.fill_bytes(&mut fresh);
        let mut wide = Hasher64::new(tags::ZK_PROVER_SEED)
            .chain(witness_digest)
            .chain(&fresh)
            .finalize();
        fresh.zeroize();
        let mut mmcs_seed = [0u8; 32];
        let mut pcs_seed = [0u8; 32];
        mmcs_seed.copy_from_slice(&wide[..32]);
        pcs_seed.copy_from_slice(&wide[32..]);
        wide.zeroize();
        let cfg = build_prover(mmcs_seed, pcs_seed, statement, upstream_grinding);
        mmcs_seed.zeroize();
        pcs_seed.zeroize();
        Self(cfg)
    }

    pub(crate) fn inner(&self) -> &ProverZkConfig {
        &self.0
    }
}

/// Configuration for verifying. Cheap to build; reusable.
pub struct VerifierConfig(ZkConfig);

impl Default for VerifierConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl VerifierConfig {
    pub fn new() -> Self {
        Self::for_statement(&[0; 32])
    }

    /// A verifier bound to `statement` (as [`ProverConfig::for_statement`]).
    pub fn for_statement(statement: &[u8; 32]) -> Self {
        Self(build([0; 32], [0; 32], statement))
    }

    /// The deterministic configuration used to commit preprocessed (public)
    /// tables, identical on the prover and verifier sides.
    pub fn setup() -> Self {
        Self::new()
    }

    pub(crate) fn inner(&self) -> &ZkConfig {
        &self.0
    }
}
