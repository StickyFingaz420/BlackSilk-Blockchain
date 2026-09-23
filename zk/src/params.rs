//! Parameter set **BS-ZK-1** (docs/zk.md §9.3) and its proven security.
//!
//! The FRI parameters are chosen so that every registered table shape reaches
//! at least [`MIN_PROVEN_BITS`] in the Johnson-bound (list-decoding) regime of
//! `p3-security` — the regime approved for BlackSilk (decision B, zk.md §9.2).
//! The unique-decoding bits are computed and reported too, so the margin to the
//! most conservative analysis is always visible.
//!
//! Changing any constant here changes the proof format and soundness: it is a
//! new parameter set (a new verifier-registry entry), never an in-place edit.

use p3_security::fri::FriRegime;
use p3_uni_stark::{ProvenSecurity, StarkSecurityParams};

/// Identifier of this parameter set; absorbed into every transcript.
pub const PARAMS_ID: &[u8] = b"BlackSilk/zk/BS-ZK-1";

/// log2 of the FRI blow-up factor (rate ρ = 2^-5).
pub const LOG_BLOWUP: usize = 5;
/// Number of FRI queries.
pub const NUM_QUERIES: usize = 50;
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
/// (`MerkleTreeHidingMmcs`). Values from Plonky3's zero-knowledge tests; their
/// sufficiency is an external-review item (R8).
pub const NUM_RANDOM_CODEWORDS: usize = 4;
pub const MERKLE_SALT_ELEMS: usize = 4;

/// Degree of the challenge extension field over BabyBear.
pub const EXTENSION_DEGREE: usize = 5;
/// `floor(log2(p^5))` for p = 2^31 − 2^27 + 1 (log2 p ≈ 30.91).
pub const CHALLENGE_FIELD_BITS: usize = 154;
/// Collision resistance of an 8-element Poseidon2 digest: 8 · log2(p) / 2 ≈ 123.6.
pub const COLLISION_BITS: usize = 123;

/// Minimum proven security (Johnson-bound regime) for any accepted table shape.
pub const MIN_PROVEN_BITS: usize = 100;

/// Largest table height (log2) any proof may claim; bounds verifier work.
pub const MAX_LOG_HEIGHT: usize = 22;
/// Largest number of committed columns (main + lookup + quotient chunks, summed
/// over all tables) a proof shape may have. At 2^22 rows the binding security
/// term is the batching proximity gap, which grows with this count and is not
/// reduced by queries or grinding; 2 000 keeps it ≥ 100 bits.
pub const MAX_COMMITTED_COLUMNS: usize = 2_000;
/// Smallest table height (log2). FRI must fold every committed polynomial at
/// least once before the final polynomial: `MIN_LOG_HEIGHT + 1 (zero-knowledge
/// padding) > LOG_FINAL_POLY_LEN` (Plonky3 `p3-fri` prover assertion). The
/// verifier rejects smaller claimed heights before Plonky3 sees them.
pub const MIN_LOG_HEIGHT: usize = 6;

/// Largest encoded proof accepted from the network.
pub const MAX_PROOF_BYTES: usize = 1 << 20;

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
    /// Total committed columns: main, permutation (lookup) and quotient chunks.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Every shape up to the limits used by BlackSilk reaches the minimum. The
    /// envelope is generous on purpose (the zkVM stays well inside it); the
    /// zkVM crate re-checks its exact shape against this function.
    #[test]
    fn every_shape_within_limits_reaches_100_proven_bits() {
        let mut worst = Security {
            johnson_bits: usize::MAX,
            unique_decoding_bits: usize::MAX,
        };
        for log_height in MIN_LOG_HEIGHT..=MAX_LOG_HEIGHT {
            for constraints in [1usize, 100, 1_000, 5_000] {
                for max_degree in [1usize, 3, 5, 8] {
                    for committed_columns in [1usize, 100, 1_000, MAX_COMMITTED_COLUMNS] {
                        let s = security(&ProofShape {
                            constraints,
                            max_degree,
                            committed_columns,
                            log_height,
                        });
                        assert!(
                            s.johnson_bits >= MIN_PROVEN_BITS,
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
        println!("BS-ZK-1 worst case over the envelope: {worst:?}");
    }

    /// The column limit is tight: well beyond it the batching term drops below
    /// the floor, so shapes must be checked, not assumed.
    #[test]
    fn column_limit_is_binding_at_the_largest_height() {
        let over = security(&ProofShape {
            constraints: 1,
            max_degree: 1,
            committed_columns: 3 * MAX_COMMITTED_COLUMNS / 2,
            log_height: MAX_LOG_HEIGHT,
        });
        assert!(over.johnson_bits < MIN_PROVEN_BITS, "{over:?}");
    }

    // Compile-time checks of the parameter relations.
    const _: () = assert!(MAX_CONSTRAINT_DEGREE >= 8);
    const _: () = assert!(MIN_LOG_HEIGHT + 1 > LOG_FINAL_POLY_LEN);
    const _: () = assert!(MIN_LOG_HEIGHT <= MAX_LOG_HEIGHT);
}
