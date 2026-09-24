//! STARK configuration for BS-ZK-2 (docs/zk.md §9.2–9.3).
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
//! [`VerifierConfig`] uses fixed seeds. Verification never draws from those RNGs,
//! and the type cannot produce proofs, so a verifier configuration can never be
//! used to prove with predictable randomness.

use crate::params::{self, NUM_RANDOM_CODEWORDS};
use blacksilk_crypto::hash::{tags, Hasher64};
use p3_baby_bear::{default_babybear_poseidon2_16, BabyBear, Poseidon2BabyBear};
use p3_challenger::{CanObserve, DuplexChallenger};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::{FriParameters, HidingFriPcs};
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
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
pub type Challenger = DuplexChallenger<Val, Perm, 16, 8>;
/// The Plonky3 configuration type used by every BlackSilk proof.
pub type ZkConfig = StarkConfig<Pcs, Challenge, Challenger>;

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

fn build(mmcs_seed: [u8; 32], pcs_seed: [u8; 32], statement: &[u8; 32]) -> ZkConfig {
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
    let pcs = Pcs::new(
        Dft::default(),
        val_mmcs,
        fri,
        NUM_RANDOM_CODEWORDS,
        StdRng::from_seed(pcs_seed),
    );
    StarkConfig::new(pcs, challenger(&perm, statement))
}

/// Configuration for proving. Build a fresh one for every proof.
pub struct ProverConfig(ZkConfig);

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
        let cfg = build(mmcs_seed, pcs_seed, statement);
        mmcs_seed.zeroize();
        pcs_seed.zeroize();
        Self(cfg)
    }

    pub(crate) fn inner(&self) -> &ZkConfig {
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
