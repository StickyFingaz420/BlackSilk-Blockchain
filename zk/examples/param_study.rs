//! Parameter study (evidence for docs/zk.md §9.3): for each blow-up and
//! query proof-of-work, the fewest FRI queries that reach a security target
//! over the whole BS-ZK shape envelope, in both regimes.
//!
//! `cargo run --release -p blacksilk-zk --example param_study`

use blacksilk_zk::params::*;
use p3_security::fri::FriRegime;
use p3_uni_stark::{ProvenSecurity, StarkSecurityParams};

/// Worst (Johnson, unique-decoding) bits over the envelope.
fn worst(log_blowup: usize, queries: usize, pow: usize) -> (usize, usize) {
    let regime = FriRegime {
        log_blowup,
        num_queries: queries,
        log_final_poly_len: LOG_FINAL_POLY_LEN,
        max_log_arity: MAX_LOG_ARITY,
        commit_pow_bits: COMMIT_POW_BITS,
        query_pow_bits: pow,
    };
    let (mut j, mut u) = (usize::MAX, usize::MAX);
    for log_height in MIN_LOG_HEIGHT..=MAX_LOG_HEIGHT {
        for constraints in [1usize, 5_000] {
            for max_degree in [3usize, 1 << log_blowup] {
                for cols in [1usize, MAX_COMMITTED_COLUMNS] {
                    let mut p = StarkSecurityParams::new(
                        regime,
                        CHALLENGE_FIELD_BITS,
                        COLLISION_BITS,
                        constraints,
                        max_degree,
                        2,
                    );
                    p.num_batched_functions = cols;
                    let s = ProvenSecurity::compute(&p, 1 << log_height);
                    j = j.min(s.list_decoding_bits);
                    u = u.min(s.unique_decoding_bits);
                }
            }
        }
    }
    (j, u)
}

fn min_queries(
    log_blowup: usize,
    pow: usize,
    ok: impl Fn(usize, usize) -> bool,
) -> Option<(usize, usize, usize)> {
    (1..=200).find_map(|q| {
        let (j, u) = worst(log_blowup, q, pow);
        ok(j, u).then_some((q, j, u))
    })
}

fn main() {
    println!("blowup  pow | J>=120: queries (J, UD) | J>=120 & UD>=100: queries (J, UD)");
    for log_blowup in [3usize, 4, 5] {
        for pow in [16usize, 20, 24] {
            let a = min_queries(log_blowup, pow, |j, _| j >= 120);
            let b = min_queries(log_blowup, pow, |j, u| j >= 120 && u >= 100);
            println!("  2^{log_blowup}   {pow:2} | {a:?} | {b:?}");
        }
    }
}
