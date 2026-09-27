//! BlackSilk zero-knowledge proof layer (docs/zk.md §9, docs/zkvm.md §7, §10).
//!
//! Everything a BlackSilk zero-knowledge proof depends on lives here:
//! - [`params`]: parameter set BS-ZK-3 and its proven security;
//! - [`config`]: the Plonky3 configuration (hiding FRI STARK over BabyBear, degree-8 extension);
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

// The verifier contains panics from malformed proofs with `catch_unwind`. Built with
// `panic = "abort"`, one malformed proof would crash every such node instead.
#[cfg(not(panic = "unwind"))]
compile_error!("blacksilk-zk must be built with panic = \"unwind\"");

pub mod config;
pub mod params;

use config::{ProverConfig, ProverZkConfig, Val, VerifierConfig, ZkConfig};
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
    + for<'a> Air<ProverConstraintFolderWithLookups<'a, ProverZkConfig>>
    + for<'a> Air<VerifierConstraintFolderWithLookups<'a, ZkConfig>>
    + for<'a> Air<p3_air::DebugConstraintBuilder<'a, Val, config::Challenge>>
    + Clone
{
}

impl<A> ProvableAir for A where
    A: Air<InteractionSymbolicBuilder<Val, config::Challenge>>
        + for<'a> Air<ProverConstraintFolderWithLookups<'a, ProverZkConfig>>
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
    // verifier recomputes them (`VerifierConfig::setup`, same seeds);
    // committing them with the prover's hiding configuration would salt the
    // commitment and desynchronize the transcript.
    let data = ProverData::from_instances(&config::prover_setup(), &instances);
    let p = prove_batch(cfg.inner(), &instances, &data);
    // The prover's configuration differs from `ZkConfig` only in how its
    // challenger grinds (config::ProverChallenger); the proof types coincide
    // field by field.
    Ok(Proof {
        commitments: p.commitments,
        opened_values: p.opened_values,
        opening_proof: p.opening_proof,
        lookup_terminals: p.lookup_terminals,
        degree_bits: p.degree_bits,
    })
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
    check_fri_schedule(proof)?;
    let result = catch_unwind(AssertUnwindSafe(|| {
        // Same deterministic setup as the prover (see `prove`): a fresh setup
        // configuration, so the preprocessed commitment never depends on the
        // state of `cfg`'s RNGs and a `VerifierConfig` can be reused (ZK-F3).
        let data = ProverData::from_airs_and_degrees(
            VerifierConfig::setup().inner(),
            airs,
            &proof.degree_bits,
        );
        verify_batch(cfg.inner(), airs, proof, public, &data.common)
    }));
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(ZkError::Invalid(format!("{e:?}"))),
        Err(_) => Err(ZkError::VerifierPanicked),
    }
}

/// The FRI folding schedule (log2 of each commit-phase round's arity) that
/// the honest prover uses for a proof whose tables have `degree_bits`.
///
/// Every FRI input of a table with degree bits `db` (its main trace, the
/// hiding PCS's random columns, its randomized quotient chunks, its
/// preprocessed columns and its lookup columns) lies on a domain of size
/// `2^db` (p3-batch-stark 0.7.0 `commitments_with_opening_points`), so the
/// distinct input log-heights are `{db_i + LOG_BLOWUP}`. From the largest,
/// each round folds by `p3_fri::compute_log_arity_for_round` (the function
/// the p3-fri prover's commit phase calls, `third_party/p3-fri/src/config.rs`)
/// until the final height `LOG_BLOWUP + LOG_FINAL_POLY_LEN`, stopping at every
/// input height on the way.
pub fn honest_fri_schedule(degree_bits: &[usize]) -> Vec<usize> {
    let mut heights: Vec<usize> = degree_bits
        .iter()
        .map(|db| db + params::LOG_BLOWUP)
        .collect();
    heights.sort_unstable_by(|a, b| b.cmp(a));
    heights.dedup();
    let log_final = params::LOG_BLOWUP + params::LOG_FINAL_POLY_LEN;
    let mut schedule = Vec::new();
    let Some(&start) = heights.first() else {
        return schedule;
    };
    let mut current = start;
    while current > log_final {
        // The prover peeks the next input not yet rolled in: the largest
        // height below the current one.
        let next = heights.iter().copied().find(|&h| h < current);
        let arity =
            p3_fri::compute_log_arity_for_round(current, next, log_final, params::MAX_LOG_ARITY);
        schedule.push(arity);
        current -= arity;
    }
    schedule
}

/// R4-02 (canonical folding schedule). The Plonky3 0.7.0 FRI verifier takes
/// the per-round folding arities from the proof. It checks that they are in
/// `1..=MAX_LOG_ARITY`, that they sum to the right total, and that every input
/// height is reached, but a prover holding the witness may still split the
/// arity differently between input heights and get another valid proof of the
/// same statement. This is not third-party malleability (only a witness holder
/// can re-prove; the SX1 cross-review corrected the earlier rationale), but it
/// is a second valid encoding that nothing needs. The rule: the schedule must
/// be exactly [`honest_fri_schedule`] of the proof's degree bits.
///
/// **Consensus (testnet v3 rule set):** a proof with any other schedule is
/// invalid. Honest proofs are unaffected: the p3-fri prover derives its
/// schedule with the same function from the same heights (tests cover every
/// consensus shape).
fn check_fri_schedule(proof: &Proof) -> Result<(), ZkError> {
    let expected = honest_fri_schedule(&proof.degree_bits);
    let fri = &proof.opening_proof.1;
    let ok = fri.commit_phase_openings.len() == expected.len()
        && fri
            .commit_phase_openings
            .iter()
            .zip(&expected)
            .all(|(o, &a)| o.log_arity as usize == a);
    if ok {
        Ok(())
    } else {
        let got: Vec<u8> = fri
            .commit_phase_openings
            .iter()
            .map(|o| o.log_arity)
            .collect();
        Err(ZkError::Invalid(format!(
            "FRI folding schedule {got:?} is not the canonical {expected:?}"
        )))
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
    check_canonical_form(&proof)?;
    Ok(proof)
}

/// Rejects proofs that verify but carry fields Plonky3 0.7.0's verifier does
/// not bind, so that one statement has exactly one valid proof encoding and a
/// relayer cannot change a transaction id by rewriting its proof (the proof
/// bytes are part of the id; internal review round 5, dependency review M1/M2).
///
/// - **Commit-phase grinding witnesses.** With `COMMIT_POW_BITS = 0`, the
///   0.7.0 verifier accepts any witness value without absorbing it into the
///   transcript (p3-challenger `check_witness` returns early at 0 bits). The
///   honest prover writes zero; any other value is rejected here. Fixed
///   upstream after 0.7.0 (Plonky3 #2106).
/// - **Present-but-empty optional openings.** The 0.7.0 verifier compares
///   only the lengths of optional openings, so `Some(vec![])` passes where
///   `None` is expected (Plonky3 #2256 for `preprocessed_next`). An honest
///   proof never opens an empty column set: `Some(empty)` is rejected.
///
/// - **Hidden random-codeword openings** (22 W2 = 26 ZP-7 = 24 I2). The
///   hiding PCS carries, per opening round, matrix and point, the openings of
///   the matrix's random codewords beside the proof. The 0.7.0 verifier checks
///   only how they nest (rounds, matrices, points) and appends whatever is
///   there, so a prover could choose any number of hidden columns: a proof
///   length channel and padding up to `MAX_PROOF_BYTES`, or a wallet that
///   silently drops its own hiding (Plonky3 0.8 pins the count). The rule:
///   the hidden rounds are exactly the proof's opening rounds (the mask `R`,
///   main, quotient, the preprocessed round if the proof opens preprocessed
///   columns, the permutation round if it has one), and every point of every
///   matrix carries exactly `NUM_RANDOM_CODEWORDS` values, except in the
///   preprocessed round. Preprocessed (public) tables are committed with zero
///   columns instead of random codewords (`HidingFriPcs::commit_preprocessing`),
///   so that round carries none. Whether it exists is read from the proof (an
///   instance opens `preprocessed_local`), and where it sits is Plonky3's
///   `Pcs::PREPROCESSED_TRACE_IDX`; the verifier then checks both against the
///   AIRs.
/// - **Merkle caps** (F24-2; Plonky3 #2277). `MerkleCap` deserializes any
///   number of roots, and the 0.7.0 MMCS verifier compares only the root the
///   cap height selects (with cap height 0, root 0), while the challenger
///   observes all of them: a prover could append roots. Every commitment (the
///   four batch commitments and every FRI commit-phase commitment) must have
///   exactly one root.
///
/// **Consensus:** this narrows the set of valid PX proof encodings. Every
/// honestly generated proof is unaffected (tests); a proof rewritten by a
/// third party is refused. Part of the testnet v3 rule set.
fn check_canonical_form(proof: &Proof) -> Result<(), ZkError> {
    use p3_field::PrimeCharacteristicRing;
    // Merkle caps: exactly one root each (cap height 0).
    let c = &proof.commitments;
    let caps = [
        Some(&c.main),
        c.permutation.as_ref(),
        Some(&c.quotient_chunks),
        c.random.as_ref(),
    ]
    .into_iter()
    .flatten()
    .chain(&proof.opening_proof.1.commit_phase_commits);
    for (i, cap) in caps.enumerate() {
        if cap.num_roots() != 1 {
            return Err(ZkError::Encoding(format!(
                "commitment {i} has {} Merkle cap roots, not 1",
                cap.num_roots()
            )));
        }
    }
    if params::COMMIT_POW_BITS == 0
        && proof
            .opening_proof
            .1
            .commit_pow_witnesses
            .iter()
            .any(|w| *w != Val::ZERO)
    {
        return Err(ZkError::Encoding(
            "non-zero commit-phase grinding witness".into(),
        ));
    }
    for (i, inst) in proof.opened_values.instances.iter().enumerate() {
        let o = &inst.base_opened_values;
        let empty = |v: &Option<Vec<_>>| v.as_ref().is_some_and(|v| v.is_empty());
        if empty(&o.trace_next)
            || empty(&o.preprocessed_local)
            || empty(&o.preprocessed_next)
            || empty(&o.random)
        {
            return Err(ZkError::Encoding(format!(
                "instance {i}: present but empty optional opening"
            )));
        }
    }
    check_hidden_openings(proof)
}

/// The hidden random-codeword openings rule of [`check_canonical_form`].
fn check_hidden_openings(proof: &Proof) -> Result<(), ZkError> {
    let preprocessed = proof
        .opened_values
        .instances
        .iter()
        .any(|i| i.base_opened_values.preprocessed_local.is_some());
    let c = &proof.commitments;
    // The opening rounds of a batch proof (p3-batch-stark 0.7.0 prover): the
    // mask `R`, main, quotient, preprocessed (if any), permutation (if any).
    let rounds = usize::from(c.random.is_some())
        + 2
        + usize::from(preprocessed)
        + usize::from(c.permutation.is_some());
    let hidden = &proof.opening_proof.0;
    if hidden.len() != rounds {
        return Err(ZkError::Encoding(format!(
            "{} hidden opening rounds, the proof has {rounds}",
            hidden.len()
        )));
    }
    let preprocessed_round = <config::Pcs as p3_commit::Pcs<
        config::Challenge,
        config::Challenger,
    >>::PREPROCESSED_TRACE_IDX;
    for (r, round) in hidden.iter().enumerate() {
        let expected = if preprocessed && r == preprocessed_round {
            0
        } else {
            params::NUM_RANDOM_CODEWORDS
        };
        for (m, matrix) in round.iter().enumerate() {
            for (p, point) in matrix.iter().enumerate() {
                if point.len() != expected {
                    return Err(ZkError::Encoding(format!(
                        "round {r}, matrix {m}, point {p}: {} hidden values, not {expected}",
                        point.len()
                    )));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod schedule_tests {
    use super::*;

    /// The schedule is well formed for every set of degree bits a proof may
    /// have (1 to 32 tables, each `MIN_LOG_HEIGHT + 1 ..= MAX_LOG_HEIGHT + 1`):
    /// arities in `1..=MAX_LOG_ARITY`, summing to the fold from the largest
    /// input height to the final height, and stopping at every input height.
    #[test]
    fn honest_schedules_are_well_formed() {
        let lo = params::MIN_LOG_HEIGHT + 1;
        let hi = params::MAX_LOG_HEIGHT + 1;
        let log_final = params::LOG_BLOWUP + params::LOG_FINAL_POLY_LEN;
        // Every subset of the allowed degree bits (15 values: 2^15 sets).
        let range: Vec<usize> = (lo..=hi).collect();
        for mask in 1u32..(1 << range.len()) {
            let dbs: Vec<usize> = range
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .map(|(_, &d)| d)
                .collect();
            let s = honest_fri_schedule(&dbs);
            let top = dbs.iter().max().unwrap() + params::LOG_BLOWUP;
            assert_eq!(s.iter().sum::<usize>(), top - log_final, "{dbs:?}");
            assert!(s.iter().all(|&a| (1..=params::MAX_LOG_ARITY).contains(&a)));
            let mut visited = vec![top];
            for a in &s {
                visited.push(visited.last().unwrap() - a);
            }
            for db in &dbs {
                assert!(
                    visited.contains(&(db + params::LOG_BLOWUP)),
                    "{dbs:?} {s:?}"
                );
            }
            // The order of the tables does not matter.
            let mut rev = dbs.clone();
            rev.reverse();
            assert_eq!(honest_fri_schedule(&rev), s);
        }
    }

    #[test]
    fn known_schedules() {
        // One table of 2^8 rows: input height 12, final 9.
        assert_eq!(honest_fri_schedule(&[9]), vec![3]);
        // 2^12 rows: 16 -> 12 -> 9.
        assert_eq!(honest_fri_schedule(&[13]), vec![4, 3]);
        assert_eq!(honest_fri_schedule(&[13, 13, 9]), vec![4, 3]);
        // Heights 17 and 12: 17 -> 13 -> 12 -> 9.
        assert_eq!(honest_fri_schedule(&[14, 9]), vec![4, 1, 3]);
        assert_eq!(honest_fri_schedule(&[]), Vec::<usize>::new());
    }
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
