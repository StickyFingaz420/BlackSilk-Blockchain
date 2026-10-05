//! Parameter set **BS-ZK-4** (docs/zk.md §9.3, docs/proof-system.md) and its
//! computed security.
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
//! and was replaced (AUDIT.md R8, finding ZK-F4). BS-ZK-2 had 4 random
//! codewords per committed matrix; BS-ZK-3 used 8, the extension degree
//! (decision F24-1, testnet v3 reset); BS-ZK-4 is BS-ZK-3 with 20 query
//! grinding bits instead of 16 (decision "BS-ZK-4";
//! docs/reviews/v3-consensus-changes.md).
//!
//! Changing any constant here changes the proof format, its soundness or its
//! zero knowledge: it is a new parameter set (a new verifier-registry entry),
//! never an in-place edit. The verifier cannot check the hiding randomness
//! itself (the random codewords, the random rows, the hidden columns of `R`,
//! the quotient randomizers): a prover that uses bad randomness weakens only
//! its own proof's hiding. Since the v3 rule set it does pin the **number** of
//! hidden values, `NUM_RANDOM_CODEWORDS` per opened point (canonical form,
//! `crate::decode_proof`), so a proof can no longer be padded with extra
//! hidden columns. Before that rule, padding was bounded only by
//! `MAX_PROOF_BYTES`: each FRI-batched column costs at least 4 bytes per
//! query, hence `MAX_ADVERSARIAL_COLUMNS`, up to which the security targets
//! are still tested as a margin (internal review rounds 3 and 4).

use p3_security::fri::FriRegime;
use p3_uni_stark::{ProvenSecurity, StarkSecurityParams};

/// Identifier of this parameter set; absorbed into every transcript.
///
/// BS-ZK-4 (testnet v3): BS-ZK-3 with [`QUERY_POW_BITS`] raised from 16 to 20
/// (decision "BS-ZK-4", 2026-10-04): the unique-decoding margin over the
/// 100-bit floor, with the mixed-height union term, goes from about 0.5 to
/// about 4.5 bits at no proof-size cost.
///
/// BS-ZK-3: BS-ZK-2 with [`NUM_RANDOM_CODEWORDS`] raised from 4 to 8. (An
/// earlier local 8-codeword build had also been called BS-ZK-3; it was
/// reverted before any commit and never produced a published proof.)
pub const PARAMS_ID: &[u8] = b"BlackSilk/zk/BS-ZK-4";

/// log2 of the FRI blow-up factor (rate ρ = 2^-3).
pub const LOG_BLOWUP: usize = 3;
/// Number of FRI queries.
pub const NUM_QUERIES: usize = 108;
/// log2 of the maximum FRI folding arity.
pub const MAX_LOG_ARITY: usize = 4;
/// log2 of the final polynomial length at which FRI stops folding.
pub const LOG_FINAL_POLY_LEN: usize = 6;
/// Proof-of-work bits before query sampling (counted in the security
/// computation). 20 since BS-ZK-4; docs/zk.md §9.3 caps grinding at 20 bits.
pub const QUERY_POW_BITS: usize = 20;
const _: () = assert!(
    QUERY_POW_BITS <= 20,
    "grinding is capped at 20 bits (docs/zk.md §9.3)"
);
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
/// The commitment term of the soundness calculation: the security of the
/// Merkle commitments, which caps every regime (a broken commitment forges
/// any proof).
///
/// **122, from ePrint 2026/089** (Coratger, Khovratovich, Mennink, Wagner,
/// "The Billion Dollar Merkle Tree", ACM CCS 2026), **Theorem 3**: for a
/// Plonky3 Merkle tree whose leaves are hashed with an overwrite sponge on the
/// same permutation as the `TruncatedPermutation` node compression (this
/// configuration), an adversary making q permutation queries breaks
/// extractability with probability at most (4q² + 2q)/(|H| − 1), |H| = p^8
/// (log2 |H| ≈ 247.3). Setting that to 1 gives q ≈ 2^122.6: **our evaluation**,
/// not a figure of the paper, floored to 122. Applying the theorem to this
/// tree (salted leaves, fixed topology and matrix dimensions from the proof
/// shape) is **argued, not proven**, and the property is extractability, not
/// collision resistance or binding. The earlier 123 was the generic birthday
/// bound 8·log2(p)/2 ≈ 123.6 of an 8-element digest, which the paper shows
/// does not apply to the node compression on its own (it is not
/// collision-resistant).
pub const COLLISION_BITS: usize = 122;

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
/// honest or not, without relying on the v3 hidden-count rule: every
/// committed base-field column is opened at every query as a 4-byte element,
/// so padding beyond the envelope is limited by [`MAX_PROOF_BYTES`]. With the
/// rule, the committed width is a function of the shape; this bound is kept
/// as a margin for the security figures.
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
    /// log2 of the tallest table's **trace** height (before zero knowledge).
    /// Under zero knowledge the committed polynomials have twice that size
    /// (`degree_bits = log_height + 1`); [`security`] accounts for it.
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

fn stark_params(shape: &ProofShape) -> StarkSecurityParams {
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
    p
}

/// Proven security of `shape` (p3-security 0.7.0 through
/// `ProvenSecurity::compute_from_proof`), computed on the **committed**
/// domain: `degree_bits = shape.log_height + 1` under zero knowledge (25 W1,
/// R4-01). Before v3 the pre-ZK height was passed; the figures did not change
/// (unique decoding is query-bound and domain-independent, Johnson is capped
/// at [`COLLISION_BITS`]), but the input was wrong.
pub fn security(shape: &ProofShape) -> Security {
    let s = ProvenSecurity::compute_from_proof(shape.log_height + 1, &stark_params(shape));
    Security {
        johnson_bits: s.list_decoding_bits,
        unique_decoding_bits: s.unique_decoding_bits,
    }
}

/// The labelled breakdown behind [`security`] (the same p3-security 0.7.0
/// computation, called directly): which term binds in each regime.
pub fn security_report(shape: &ProofShape) -> p3_security::SecurityReport {
    let p = stark_params(shape);
    p3_security::stark::proven_security_report(
        &fri_regime(),
        &p3_security::StarkAirParams {
            num_constraints: p.num_constraints,
            max_constraint_degree: p.air_max_constraint_degree,
            max_combo: p.max_combo,
        },
        &p3_security::InstanceShape {
            log_trace_length: shape.log_height + 1,
            modulus_bits: p.num_modulus_bits,
            collision_resistance: p.collision_resistance,
            num_batched_functions: p.num_batched_functions,
        },
        &[],
        &p3_security::GrindingSites::NONE,
    )
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
// Uniform query positions (25 ZS-6): FRI samples each query index as the low
// bits of a canonical BabyBear element (p3-challenger 0.7.0
// `DuplexChallenger::sample_bits`). Since p − 1 = 15·2^27, the low b bits are
// uniform up to a 1/p bias only for b ≤ 27, so the largest evaluation domain,
// 2^(MAX_LOG_HEIGHT + 1 + LOG_BLOWUP) (zero knowledge doubles the trace), must
// stay at or below 2^27. Beyond it the calculator would over-report.
const _: () = assert!(MAX_LOG_HEIGHT + 1 + LOG_BLOWUP <= 27);
// The Johnson target is reachable at all only below the commitment term; a
// higher target needs a wider digest, not more queries.
const _: () = assert!(TARGET_JOHNSON_BITS <= COLLISION_BITS);

#[cfg(test)]
mod tests {
    use super::*;

    /// Every shape up to the limits used by BlackSilk reaches the minimum. The
    /// envelope is generous on purpose (the zkVM stays well inside it); the
    /// zkVM crate re-checks its exact shape against this function. Trace
    /// heights 2^8..2^22, i.e. committed degree bits 9..=23.
    ///
    /// It also pins **which term binds**: in the unique-decoding regime the
    /// low-degree test (its query phase: 108 queries at rate 1/8 plus 20
    /// grinding bits, about 109.6), in the Johnson regime the commitment term
    /// [`COLLISION_BITS`]; so the reported Johnson figure is exactly
    /// `COLLISION_BITS` everywhere. The independent recomputation is
    /// `zk/tests/soundness_calc.rs`.
    #[test]
    fn every_shape_within_limits_meets_both_security_targets() {
        use p3_security::report::{COLLISION_LABEL, LDT_LABEL};
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
                        let shape = ProofShape {
                            constraints,
                            max_degree,
                            committed_columns,
                            log_height,
                        };
                        let s = security(&shape);
                        let at = format!(
                            "{s:?} at 2^{log_height}, {constraints} constraints, degree {max_degree}, {committed_columns} columns"
                        );
                        assert!(
                            s.johnson_bits >= TARGET_JOHNSON_BITS
                                && s.unique_decoding_bits >= MIN_PROVEN_BITS,
                            "{at}"
                        );
                        // The report is the same computation, term by term.
                        let r = security_report(&shape);
                        let ldr = r.ldr.as_ref().expect("a Johnson regime exists");
                        assert_eq!(r.udr.security_bits() as usize, s.unique_decoding_bits);
                        assert_eq!(ldr.security_bits() as usize, s.johnson_bits);
                        assert_eq!(r.udr.binding().label, LDT_LABEL, "{at}");
                        assert_eq!(ldr.binding().label, COLLISION_LABEL, "{at}");
                        assert_eq!(s.johnson_bits, COLLISION_BITS, "{at}");
                        if s.unique_decoding_bits < worst.unique_decoding_bits {
                            worst = s;
                        }
                    }
                }
            }
        }
        // Record the margin in the test output (cargo test -- --nocapture).
        println!("BS-ZK-4 worst case over the envelope: {worst:?}");
    }

    // Compile-time checks of the parameter relations.
    const _: () = assert!(MAX_CONSTRAINT_DEGREE >= 5);
    const _: () = assert!(MIN_LOG_HEIGHT + 1 > LOG_FINAL_POLY_LEN);
    const _: () = assert!(MIN_LOG_HEIGHT <= MAX_LOG_HEIGHT);
}
