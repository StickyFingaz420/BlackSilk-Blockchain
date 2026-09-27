//! Parameter set **BS-ZK-3** (docs/zk.md §9.3, docs/proof-system.md) and its
//! proven security.
//!
//! Every shape inside the envelope reaches
//! - at least [`TARGET_JOHNSON_BITS`] in the Johnson-bound (list-decoding)
//!   regime of `p3-security` — the regime approved for BlackSilk (decision B);
//! - **and** at least [`MIN_PROVEN_BITS`] in the unique-decoding regime, which
//!   relies on no list-decoding theorem at all.
//!
//! So soundness does not depend on the 2020/2025 proximity-gap results; they
//! only add margin. BS-ZK-1 (degree-5 extension, blow-up 32, 50 queries) had
//! exactly 100 Johnson bits and 63 unique-decoding bits at the largest shape
//! and was replaced (AUDIT.md R8, finding ZK-F4). BS-ZK-2 was BS-ZK-3 with 4
//! random codewords per committed matrix; BS-ZK-3 uses 8, the extension
//! degree (decision F24-1, testnet v3 reset; docs/reviews/v3-consensus-changes.md).
//!
//! Changing any constant here changes the proof format, its soundness or its
//! zero knowledge: it is a new parameter set (a new verifier-registry entry),
//! never an in-place edit. The verifier does **not** enforce every constant:
//! it pins none of the hiding randomness (`NUM_RANDOM_CODEWORDS`, the random
//! rows, the hidden columns of `R`, the quotient randomizers), and the number
//! of hidden columns is bounded only by `MAX_PROOF_BYTES`. A prover that
//! skimps weakens only its own proof's hiding. A prover that **pads** adds
//! FRI-batched columns, which enter the soundness bound; each costs at least
//! 4 bytes per query, so `MAX_PROOF_BYTES` caps a proof at
//! `MAX_ADVERSARIAL_COLUMNS`, and the security targets are tested up to that
//! cap (internal review rounds 3 and 4).

use p3_security::fri::FriRegime;
use p3_uni_stark::{ProvenSecurity, StarkSecurityParams};

/// Identifier of this parameter set; absorbed into every transcript.
///
/// BS-ZK-3 (testnet v3): BS-ZK-2 with [`NUM_RANDOM_CODEWORDS`] raised from 4
/// to 8. (An earlier local 8-codeword build had also been called BS-ZK-3; it
/// was reverted before any commit and never produced a published proof.)
pub const PARAMS_ID: &[u8] = b"BlackSilk/zk/BS-ZK-3";

/// log2 of the FRI blow-up factor (rate ρ = 2^-3).
pub const LOG_BLOWUP: usize = 3;
/// Number of FRI queries.
pub const NUM_QUERIES: usize = 108;
/// log2 of the maximum FRI folding arity.
pub const MAX_LOG_ARITY: usize = 4;
/// log2 of the final polynomial length at which FRI stops folding.
pub const LOG_FINAL_POLY_LEN: usize = 6;
/// Proof-of-work bits before query sampling (counted in the security computation).
pub const QUERY_POW_BITS: usize = 16;
/// Proof-of-work bits before each commit-phase challenge.
pub const COMMIT_POW_BITS: usize = 0;

/// Random codewords added by the hiding FRI commitment per committed matrix
/// (Plonky3 `HidingFriPcs`), and salt elements per Merkle leaf
/// (`MerkleTreeHidingMmcs`).
///
/// The paper's FRI mask `R` (ePrint 2024/1037, Protocol 2) is **not** these
/// codewords. Plonky3 commits a separate randomization polynomial per table
/// (`get_opt_randomization_poly_commitment`) with `NUM_RANDOM_CODEWORDS +
/// EXTENSION_DEGREE` base-field columns, which spans the extension field
/// whatever this value is.
///
/// **8 = [`EXTENSION_DEGREE`] (BS-ZK-3, decision F24-1).** Plonky3 0.8
/// (PR #2100) rejects, in prover and verifier, any hiding PCS with fewer
/// random codewords per committed matrix than the extension degree, "to mask
/// extension-field batching". Internal review round 3 had argued that `R`
/// alone suffices and kept 4 (BS-ZK-2); no written proof of either position
/// exists, so the conservative upstream rule is adopted: privacy before proof
/// size (about +10 % bytes and time; the measurement is in
/// docs/reviews/v3-consensus-changes.md). The verifier pins the hidden opening
/// count to this value (canonical form, `crate::decode_proof`).
pub const NUM_RANDOM_CODEWORDS: usize = 8;
pub const MERKLE_SALT_ELEMS: usize = 4;

/// Degree of the challenge extension field over BabyBear.
pub const EXTENSION_DEGREE: usize = 8;
/// `floor(log2(p^8))` for p = 2^31 − 2^27 + 1 (log2 p ≈ 30.91).
pub const CHALLENGE_FIELD_BITS: usize = 247;
/// Collision resistance of an 8-element Poseidon2 digest: 8 · log2(p) / 2 ≈ 123.6.
pub const COLLISION_BITS: usize = 123;

/// Minimum proven security in the unique-decoding regime (and the absolute
/// floor in any regime).
pub const MIN_PROVEN_BITS: usize = 100;
/// Target security in the approved Johnson-bound regime.
pub const TARGET_JOHNSON_BITS: usize = 120;

/// Largest table height (log2) any proof may claim; bounds verifier work.
pub const MAX_LOG_HEIGHT: usize = 22;
/// Largest number of committed base-field columns (main, lookup, quotient
/// chunks, the randomization polynomial `R` and the hidden random codewords,
/// summed over all tables) an honest proof shape may have. The security
/// guarantees are computed (and tested) up to this bound and beyond, up to
/// [`MAX_ADVERSARIAL_COLUMNS`]; honest shapes are checked against it.
///
/// Raised from 4,000 on 2026-09-26: the widest PX statement (kernel plus two
/// functions, 23 tables) is measured on a real proof with the hidden codewords
/// and `R` included
/// (`zkvm/tests/multi.rs::the_widest_multi_execution_shape_stays_in_the_envelope`;
/// internal review round 4, M3). BS-ZK-3's 8 codewords add 4 columns per
/// committed matrix and leave a thin margin below this bound (the measured
/// count is in docs/reviews/v3-consensus-changes.md, "BS-ZK-3"). The security
/// figures do not change up to at least 65,536 columns (tested). The envelope
/// was checked only for single executions before (internal review round 2, S2).
pub const MAX_COMMITTED_COLUMNS: usize = 6_000;
/// Smallest table height (log2). FRI must fold every committed polynomial at
/// least once before the final polynomial: `MIN_LOG_HEIGHT + 1 (zero-knowledge
/// padding) > LOG_FINAL_POLY_LEN` (Plonky3 `p3-fri` prover assertion). The
/// verifier rejects smaller claimed heights before Plonky3 sees them.
pub const MIN_LOG_HEIGHT: usize = 8;

/// Largest encoded proof accepted from the network. A BVM-1 transfer proof
/// is ~2 MB (AUDIT.md R8); the widest shape of the envelope stays below this.
pub const MAX_PROOF_BYTES: usize = 4 << 20;

/// Upper bound on the FRI-batched columns of any proof the verifier accepts,
/// honest or not: the verifier does not pin the hidden columns, but every
/// committed base-field column is opened at every query as a 4-byte element,
/// so padding beyond the envelope is limited by [`MAX_PROOF_BYTES`].
pub const MAX_ADVERSARIAL_COLUMNS: usize =
    MAX_COMMITTED_COLUMNS + MAX_PROOF_BYTES / (4 * NUM_QUERIES);

pub const fn fri_regime() -> FriRegime {
    FriRegime {
        log_blowup: LOG_BLOWUP,
        num_queries: NUM_QUERIES,
        log_final_poly_len: LOG_FINAL_POLY_LEN,
        max_log_arity: MAX_LOG_ARITY,
        commit_pow_bits: COMMIT_POW_BITS,
        query_pow_bits: QUERY_POW_BITS,
    }
}

/// The shape of a whole batch proof, summed over its tables. Summing is the
/// conservative way to apply single-instance bounds to a batch: every
/// constraint and committed column is counted once in the combined instance.
#[derive(Clone, Copy, Debug)]
pub struct ProofShape {
    /// Total number of constraints over all tables (base and extension).
    pub constraints: usize,
    /// Maximum constraint degree of any table.
    pub max_degree: usize,
    /// Total committed base-field columns: main, permutation (lookup), quotient
    /// chunks, `R` and the hidden random codewords.
    pub committed_columns: usize,
    /// log2 of the tallest table.
    pub log_height: usize,
}

/// Security of this parameter set for a proof shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Security {
    /// Johnson-bound regime (the approved regime).
    pub johnson_bits: usize,
    /// Unique-decoding regime (reported for margin).
    pub unique_decoding_bits: usize,
}

pub fn security(shape: &ProofShape) -> Security {
    let mut p = StarkSecurityParams::new(
        fri_regime(),
        CHALLENGE_FIELD_BITS,
        COLLISION_BITS,
        shape.constraints.max(1),
        shape.max_degree.max(1),
        // Tables use `local` and `next` rows.
        2,
    );
    p.num_batched_functions = shape.committed_columns.max(1);
    let s = ProvenSecurity::compute(&p, 1 << shape.log_height);
    Security {
        johnson_bits: s.list_decoding_bits,
        unique_decoding_bits: s.unique_decoding_bits,
    }
}

/// Maximum constraint degree the prover can commit under zero knowledge
/// (quotient must fit the LDE: `degree ≤ 2^LOG_BLOWUP`).
pub const MAX_CONSTRAINT_DEGREE: usize = 1 << LOG_BLOWUP;

/// Out-of-domain opening points per committed polynomial: ζ and its
/// translate g·ζ (tables read the `next` row).
pub const OPENING_POINTS: usize = 2;

// Witness randomization (docs/reviews/zk-coverage.md), checked in every build:
// every table has enough randomizer degrees of freedom for the bound of
// ePrint 2024/1037 §4.2, eq. (17): 2·(e·n_F + n_D) ≤ h ≤ |H|, with e the
// extension degree, n_D the number of FRI queries and h = |H| (Plonky3 adds
// one random row per trace row). n_F counts **both** opening points, as the
// Plonky3 0.8 hiding budget does (PR #2100; the paper's n_F = 1 with the
// translate folded into the factor 2 gave the weaker 2·(8 + 108) = 232):
// 2·(108 + 8·2) = 248 ≤ 2^MIN_LOG_HEIGHT = 256. At this height the query
// ceiling is 112.
const _: () = assert!(2 * (NUM_QUERIES + EXTENSION_DEGREE * OPENING_POINTS) <= 1 << MIN_LOG_HEIGHT);
// Quotient randomization, eq. (16): n_F + n_D ≤ h_p, where h_p (the height
// of a quotient chunk's randomizer) is at least the trace height |H| ≥
// 2^MIN_LOG_HEIGHT (Plonky3 `get_quotient_ldes` follows the Lagrange
// decomposition of §4.2, the premise of this equation). 2 + 108 ≤ 256.
const _: () = assert!(OPENING_POINTS + NUM_QUERIES <= 1 << MIN_LOG_HEIGHT);
// F24-1: at least one random codeword per extension coordinate.
const _: () = assert!(NUM_RANDOM_CODEWORDS >= EXTENSION_DEGREE);

#[cfg(test)]
mod tests {
    use super::*;

    /// Every shape up to the limits used by BlackSilk reaches the minimum. The
    /// envelope is generous on purpose (the zkVM stays well inside it); the
    /// zkVM crate re-checks its exact shape against this function.
    #[test]
    fn every_shape_within_limits_meets_both_security_targets() {
        let mut worst = Security {
            johnson_bits: usize::MAX,
            unique_decoding_bits: usize::MAX,
        };
        for log_height in MIN_LOG_HEIGHT..=MAX_LOG_HEIGHT {
            for constraints in [1usize, 100, 1_000, 5_000] {
                for max_degree in [1usize, 3, 5, MAX_CONSTRAINT_DEGREE] {
                    for committed_columns in [
                        1usize,
                        100,
                        1_000,
                        MAX_COMMITTED_COLUMNS,
                        MAX_ADVERSARIAL_COLUMNS,
                        65_536,
                    ] {
                        let s = security(&ProofShape {
                            constraints,
                            max_degree,
                            committed_columns,
                            log_height,
                        });
                        assert!(
                            s.johnson_bits >= TARGET_JOHNSON_BITS
                                && s.unique_decoding_bits >= MIN_PROVEN_BITS,
                            "{s:?} at 2^{log_height}, {constraints} constraints, degree {max_degree}, {committed_columns} columns"
                        );
                        if s.johnson_bits < worst.johnson_bits {
                            worst = s;
                        }
                    }
                }
            }
        }
        // Record the margin in the test output (cargo test -- --nocapture).
        println!("BS-ZK-3 worst case over the envelope: {worst:?}");
    }

    // Compile-time checks of the parameter relations.
    const _: () = assert!(MAX_CONSTRAINT_DEGREE >= 5);
    const _: () = assert!(MIN_LOG_HEIGHT + 1 > LOG_FINAL_POLY_LEN);
    const _: () = assert!(MIN_LOG_HEIGHT <= MAX_LOG_HEIGHT);
}
