//! BlackSilk zero-knowledge proof layer (docs/zk.md §9, docs/zkvm.md §7, §10).
//!
//! Everything a BlackSilk zero-knowledge proof depends on lives here:
//! - [`params`]: parameter set BS-ZK-2 and its proven security;
//! - [`config`]: the Plonky3 configuration (hiding FRI STARK over BabyBear^5);
//! - [`prove`] / [`verify`]: batch proving and hardened verification;
//! - [`encode_proof`] / [`decode_proof`]: the strict wire format.
//!
//! **Hardening** (zkvm.md §10). [`verify`] never trusts the proof's own shape:
//! - it checks table counts and claimed heights against the caller's limits
//!   before any expensive work;
//! - it runs the Plonky3 verifier behind `catch_unwind`, because Plonky3
//!   documents that malformed proofs may panic it. Nodes must be built with
//!   `panic = "unwind"` for this to take effect (workspace release profile).

#![forbid(unsafe_code)]

pub mod config;
pub mod params;

use config::{ProverConfig, Val, VerifierConfig, ZkConfig};
use p3_air::Air;
use p3_batch_stark::{prove_batch, verify_batch, ProverData, StarkInstance};
use p3_lookup::folder::{ProverConstraintFolderWithLookups, VerifierConstraintFolderWithLookups};
use p3_lookup::InteractionSymbolicBuilder;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use std::panic::{catch_unwind, AssertUnwindSafe};

pub use p3_batch_stark::BatchProof;

/// A BlackSilk proof.
pub type Proof = BatchProof<ZkConfig>;

/// Version byte of the proof encoding.
pub const PROOF_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZkError {
    /// Tables, traces and public values do not line up.
    Shape(String),
    /// A table height is not a power of two, or outside the allowed range.
    Height { table: usize, log_height: usize },
    /// The proof bytes are oversized, of an unknown version, or not canonical.
    Encoding(String),
    /// The proof does not verify.
    Invalid(String),
    /// The Plonky3 verifier panicked on this proof. Treated as invalid; logged
    /// for an upstream report.
    VerifierPanicked,
}

/// Bounds every AIR type must satisfy to be proven (Plonky3 batch prover).
pub trait ProvableAir:
    Air<InteractionSymbolicBuilder<Val, config::Challenge>>
    + for<'a> Air<ProverConstraintFolderWithLookups<'a, ZkConfig>>
    + for<'a> Air<VerifierConstraintFolderWithLookups<'a, ZkConfig>>
    + for<'a> Air<p3_air::DebugConstraintBuilder<'a, Val, config::Challenge>>
    + Clone
{
}

impl<A> ProvableAir for A where
    A: Air<InteractionSymbolicBuilder<Val, config::Challenge>>
        + for<'a> Air<ProverConstraintFolderWithLookups<'a, ZkConfig>>
        + for<'a> Air<VerifierConstraintFolderWithLookups<'a, ZkConfig>>
        + for<'a> Air<p3_air::DebugConstraintBuilder<'a, Val, config::Challenge>>
        + Clone
{
}

fn log2_exact(n: usize) -> Option<usize> {
    n.is_power_of_two().then(|| n.trailing_zeros() as usize)
}

/// Proves that `traces` satisfy `airs` with `public` values, as one batch.
///
/// Each trace height must be a power of two within `[2^MIN_LOG_HEIGHT,
/// 2^max_log_heights[i]]`. The caller must build a fresh [`ProverConfig`] for
/// every proof (hiding randomness).
pub fn prove<A: ProvableAir>(
    cfg: &ProverConfig,
    airs: &[A],
    traces: &[RowMajorMatrix<Val>],
    public: &[Vec<Val>],
    max_log_heights: &[usize],
) -> Result<Proof, ZkError> {
    if airs.is_empty()
        || airs.len() != traces.len()
        || airs.len() != public.len()
        || airs.len() != max_log_heights.len()
    {
        return Err(ZkError::Shape(
            "tables, traces and public values differ in number".into(),
        ));
    }
    for (i, t) in traces.iter().enumerate() {
        let log = log2_exact(t.height()).ok_or(ZkError::Height {
            table: i,
            log_height: usize::MAX,
        })?;
        if log < params::MIN_LOG_HEIGHT || log > max_log_heights[i].min(params::MAX_LOG_HEIGHT) {
            return Err(ZkError::Height {
                table: i,
                log_height: log,
            });
        }
    }
    let refs: Vec<&RowMajorMatrix<Val>> = traces.iter().collect();
    let instances = StarkInstance::new_multiple(airs, &refs, public);
    // Preprocessed tables (programs, the byte table) are public. They are
    // committed with the deterministic setup configuration, exactly as the
    // verifier recomputes them; committing them with the prover's hiding
    // configuration would salt the commitment and desynchronize the transcript.
    let data = ProverData::from_instances(VerifierConfig::setup().inner(), &instances);
    Ok(prove_batch(cfg.inner(), &instances, &data))
}

/// Verifies `proof` against `airs` and `public`. `max_log_heights[i]` bounds the
/// height the proof may claim for table `i` (in addition to the global limit).
pub fn verify<A: ProvableAir>(
    cfg: &VerifierConfig,
    airs: &[A],
    proof: &Proof,
    public: &[Vec<Val>],
    max_log_heights: &[usize],
) -> Result<(), ZkError> {
    let n = airs.len();
    if n == 0 || public.len() != n || max_log_heights.len() != n {
        return Err(ZkError::Shape(
            "tables and public values differ in number".into(),
        ));
    }
    if proof.degree_bits.len() != n
        || proof.opened_values.instances.len() != n
        || proof.lookup_terminals.len() != n
    {
        return Err(ZkError::Shape(
            "proof covers a different number of tables".into(),
        ));
    }
    // `degree_bits` is `log2(height) + 1` under zero knowledge.
    for (i, &db) in proof.degree_bits.iter().enumerate() {
        let max = max_log_heights[i].min(params::MAX_LOG_HEIGHT) + 1;
        if db < params::MIN_LOG_HEIGHT + 1 || db > max {
            return Err(ZkError::Height {
                table: i,
                log_height: db.saturating_sub(1),
            });
        }
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        // Same deterministic setup as the prover (see `prove`).
        let data = ProverData::from_airs_and_degrees(cfg.inner(), airs, &proof.degree_bits);
        verify_batch(cfg.inner(), airs, proof, public, &data.common)
    }));
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(ZkError::Invalid(format!("{e:?}"))),
        Err(_) => Err(ZkError::VerifierPanicked),
    }
}

/// Encodes a proof: `PROOF_VERSION ‖ postcard(proof)`.
///
/// Field elements are always 4 bytes (Plonky3 writes them as fixed-width
/// arrays in binary formats), so values never change the length. A proof's
/// length varies only with the number of distinct Merkle nodes in its pruned
/// query paths, a function of the public query positions (docs/px.md §4.4,
/// privacy review §3a).
pub fn encode_proof(proof: &Proof) -> Vec<u8> {
    let mut out = vec![PROOF_VERSION];
    out.extend(postcard::to_allocvec(proof).expect("proof serialization cannot fail"));
    out
}

/// Strictly decodes a proof. Oversized input, unknown versions, trailing bytes
/// and any non-canonical encoding (bytes that do not re-encode identically)
/// are rejected, so one proof has exactly one valid encoding.
pub fn decode_proof(bytes: &[u8]) -> Result<Proof, ZkError> {
    if bytes.len() > params::MAX_PROOF_BYTES {
        return Err(ZkError::Encoding("proof too large".into()));
    }
    let (&version, body) = bytes
        .split_first()
        .ok_or_else(|| ZkError::Encoding("empty proof".into()))?;
    if version != PROOF_VERSION {
        return Err(ZkError::Encoding(format!(
            "unknown proof version {version}"
        )));
    }
    let decoded = catch_unwind(AssertUnwindSafe(|| {
        postcard::take_from_bytes::<Proof>(body)
    }));
    let (proof, rest) = match decoded {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return Err(ZkError::Encoding(e.to_string())),
        Err(_) => return Err(ZkError::Encoding("decoder panicked".into())),
    };
    if !rest.is_empty() {
        return Err(ZkError::Encoding("trailing bytes".into()));
    }
    if encode_proof(&proof) != bytes {
        return Err(ZkError::Encoding("non-canonical encoding".into()));
    }
    Ok(proof)
}

/// **Analysis only** (not used by proving or verification): what an outside
/// observer can compute about a proof's lookup terminals (finding ZK-F29).
///
/// [`Observer::new`] replays the verifier's Fiat–Shamir transcript up to the
/// lookup challenges, from public data only. [`Observer::terminal`] computes
/// the LogUp terminal a given trace of table `i` would produce under those
/// challenges, exactly as the prover computes the value it publishes. A test
/// can then check whether a published terminal is explained by a hypothesis.
#[doc(hidden)]
pub mod analysis {
    use super::config::{Challenge, Val, VerifierConfig, ZkConfig};
    use super::{Proof, ProvableAir};
    use p3_batch_stark::{BatchTranscript, ProverData};
    use p3_lookup::{LogUpGadget, LookupProtocol, Lookups};
    use p3_matrix::dense::RowMajorMatrix;
    use p3_uni_stark::StarkGenericConfig;

    pub struct Observer {
        lookups: Vec<Lookups<Val>>,
        /// Per table: one `(bus offset, combiner)` pair per lookup, in the
        /// table's lookup order.
        pub challenges: Vec<Vec<Challenge>>,
    }

    impl Observer {
        pub fn new<A: ProvableAir>(
            cfg: &VerifierConfig,
            airs: &[A],
            proof: &Proof,
            public: &[Vec<Val>],
        ) -> Self {
            let inner = cfg.inner();
            let data = ProverData::from_airs_and_degrees(inner, airs, &proof.degree_bits);
            let common = data.common;
            let mut t = BatchTranscript::<ZkConfig>::new(inner.initialise_challenger());
            t.observe_instance_count(airs.len());
            for (i, air) in airs.iter().enumerate() {
                let db = proof.degree_bits[i];
                let chunks = proof.opened_values.instances[i]
                    .base_opened_values
                    .quotient_chunks
                    .len();
                t.observe_instance_binding(db, db - 1, p3_air::BaseAir::<Val>::width(air), chunks);
            }
            t.observe_main(&proof.commitments.main, public);
            let widths: Vec<usize> = (0..airs.len())
                .map(|i| {
                    common
                        .preprocessed
                        .as_ref()
                        .and_then(|g| g.instances[i].as_ref().map(|m| m.width))
                        .unwrap_or(0)
                })
                .collect();
            t.observe_preprocessed(&widths, common.preprocessed.as_ref());
            let challenges = t.sample_perm_challenges(&common.lookups, &LogUpGadget::new());
            Self {
                lookups: common.lookups,
                challenges,
            }
        }

        /// The terminal of table `i` for `trace` (its full main trace).
        pub fn terminal<A: ProvableAir>(
            &self,
            i: usize,
            air: &A,
            trace: &RowMajorMatrix<Val>,
            public: &[Val],
        ) -> Option<Challenge> {
            let pre = p3_air::BaseAir::<Val>::preprocessed_trace(air);
            let (_, t) = LogUpGadget::new().generate_permutation::<ZkConfig>(
                trace,
                &pre,
                public,
                self.lookups[i].as_ref(),
                &self.challenges[i],
            );
            t.map(|t| t.0)
        }
    }

    const _: fn() = || {
        fn is_config<C: StarkGenericConfig>() {}
        is_config::<ZkConfig>();
    };
}
