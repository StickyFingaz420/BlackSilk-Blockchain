//! An independent soundness calculator for the parameter set (25 W2).
//!
//! `zk::params::security` uses Plonky3's `p3-security` 0.7.0. This file
//! recomputes the proven figures from closed-form bounds written out here,
//! sharing no code with it (only the parameter constants and the FRI folding
//! schedule of `zk::honest_fri_schedule`), and checks that the two agree. It
//! also covers terms `p3-security` does not model for a batch STARK (LogUp,
//! the DEEP union over tables), a conservative union-bound term for
//! mixed-height FRI inputs (no published theorem covers them; see
//! `MIXED_HEIGHTS`), and a Johnson column that uses only the peer-reviewed
//! BCIKS20 proximity bound.
//!
//! Evidence class: computed, by formulas stated below. The formulas follow
//! the error terms of ethSTARK (ePrint 2021/582), Haböck's FRI summary
//! (ePrint 2022/1216), the proximity-gap theorems of BCIKS20 (ePrint 2020/654)
//! and BCHKS25 (ePrint 2025/2055, Thm 1.5 form as used by `ethereum/soundcalc`),
//! and LogUp (ePrint 2022/1530). Every bound is written in its conservative
//! direction (error over-estimated). This is internal engineering, not a
//! proof: its value is that a second, independent computation of the headline
//! figures exists and is tested.
//!
//! Notation: F the challenge field (log2 |F| = 8·log2 p), k = 2^(log_height+1)
//! the committed degree bound (zero knowledge doubles the trace), n = k·2^b
//! the evaluation domain, ρ⁺ = (k + 2)/n (the DEEP quotients over the two
//! opening points each add one degree), q queries, g grinding bits, N batched
//! functions, C constraints, D maximum degree, T tables.

use blacksilk_zk::honest_fri_schedule;
use blacksilk_zk::params::{self, ProofShape};

/// log2 of the BabyBear modulus 2^31 − 2^27 + 1.
fn log2_p() -> f64 {
    (2_013_265_921f64).log2()
}

/// log2 |F| for the challenge field.
fn log2_field() -> f64 {
    params::EXTENSION_DEGREE as f64 * log2_p()
}

/// Bits of an error probability given as log2(error): −log2(ε).
fn bits(log2_error: f64) -> f64 {
    -log2_error
}

/// Conservative protocol constants for the terms p3-security does not model.
/// The table count of the widest statement any BlackSilk verifier accepts:
/// BVM-1 with `MAX_EXECUTIONS` = 5 has 12 + 5·4 + 1 = 33 tables
/// (`DecodeLimits::ENVELOPE.max_instances`); a PX statement has at most 23
/// (`PROOF_LIMITS` in `px/src/prove.rs`).
const TABLES: f64 = 33.0;
const LOGUP_INTERACTIONS_LOG2: f64 = params::MAX_LOG_HEIGHT as f64 + 10.0; // 2^22 rows × 1,024
const LOGUP_TUPLE_WIDTH: f64 = 64.0;

/// The mixed-height union-bound term (RES-FREEZE, res-freeze.md §5.4 (b) and
/// §8.6 item 5 (b); decisions "RES-FREEZE dossier, first pass" item 5).
///
/// One PX proof batches 13 to 23 tables (a BVM-1 proof up to 33) of different
/// heights, and Plonky3's FRI rolls each height in at its own folding round.
/// No published theorem bounds the soundness of that roll-in (the upstream
/// advisory GHSA-f69f-5fx9-w9r9 was an unsound roll-in, fixed in Plonky3
/// 0.7.0). The conservative stand-in used here: treat each distinct input
/// height as its own FRI instance and take a union bound over them, so every
/// FRI error term (the batching, every commit-phase round and the query
/// phase) is multiplied by the number H of distinct heights, a loss of
/// log2(H) bits.
///
/// H is at most the table count (`TABLES`, 33) and at most the number of
/// committed heights in the envelope (degree bits 9 to 23, 15 values). The
/// calculator charges the table count, log2 33 = 5.04 bits, against 3.9 for
/// H = 15 (or 4.5 for a PX proof's 23 tables). This is a heuristic bound,
/// not a proof that roll-in is sound.
const MIXED_HEIGHTS: f64 = TABLES;

#[derive(Clone, Copy, Debug)]
struct Terms {
    ali: f64,
    deep: f64,
    batch: f64,
    commit: f64,
    query: f64,
    logup: f64,
}

impl Terms {
    /// The algebraic minimum (every term but the commitment cap).
    fn algebraic(&self) -> f64 {
        [
            self.ali,
            self.deep,
            self.batch,
            self.commit,
            self.query,
            self.logup,
        ]
        .into_iter()
        .fold(f64::INFINITY, f64::min)
    }

    /// The reported figure: capped by the commitment term.
    fn reported(&self) -> f64 {
        self.algebraic().min(params::COLLISION_BITS as f64)
    }

    /// Every term except the query phase.
    fn non_query_min(&self) -> f64 {
        [self.ali, self.deep, self.batch, self.commit, self.logup]
            .into_iter()
            .fold(f64::INFINITY, f64::min)
    }

    /// The same terms with the mixed-height union bound (`MIXED_HEIGHTS`)
    /// applied to the FRI terms: the batching, the commit phase and the query
    /// phase each lose log2(H) bits. The ALI, DEEP and LogUp terms already
    /// take their own union over tables.
    fn with_mixed_height_union(self) -> Terms {
        let loss = MIXED_HEIGHTS.log2();
        Terms {
            batch: self.batch - loss,
            commit: self.commit - loss,
            query: self.query - loss,
            ..self
        }
    }
}

struct Instance {
    log_k: usize,
    log_n: usize,
    rho_plus: f64,
    shape: ProofShape,
}

impl Instance {
    fn new(shape: ProofShape) -> Self {
        let log_k = shape.log_height + 1;
        let log_n = log_k + params::LOG_BLOWUP;
        let k = (1u64 << log_k) as f64;
        let n = (1u64 << log_n) as f64;
        Self {
            log_k,
            log_n,
            rho_plus: (k + 2.0) / n,
            shape,
        }
    }

    fn log2_constraints(&self) -> f64 {
        (self.shape.constraints.max(1) as f64).log2()
    }

    /// log2 of the DEEP-ALI identity-test error numerator, union over tables
    /// and both opening points: 2·T·(D + 1)·k.
    fn log2_deep(&self) -> f64 {
        (2.0 * TABLES * (self.shape.max_degree.max(1) as f64 + 1.0)).log2() + self.log_k as f64
    }

    /// Per FRI commit-phase round of the honest schedule for this height:
    /// (log2 of the domain size before folding, arity).
    fn rounds(&self) -> Vec<(f64, usize)> {
        let mut log_domain = self.log_n;
        honest_fri_schedule(&[self.log_k])
            .into_iter()
            .map(|a| {
                let r = (log_domain as f64, a);
                log_domain -= a;
                r
            })
            .collect()
    }

    fn logup(&self, list_size_log2: f64) -> f64 {
        log2_field() - (LOGUP_INTERACTIONS_LOG2 + (LOGUP_TUPLE_WIDTH + 2.0).log2() + list_size_log2)
    }

    /// Unique-decoding regime (list size 1), δ = (1 − ρ⁺)/2.
    fn udr(&self) -> Terms {
        let f = log2_field();
        let n_fns = self.shape.committed_columns.max(1) as f64;
        // BCIKS20 Thm 1.4 in the unique-decoding radius, batching by powers
        // of one challenge: ε ≤ (N − 1)·n/|F|.
        let batch = if n_fns >= 2.0 {
            f - ((n_fns - 1.0).log2() + self.log_n as f64)
        } else {
            f64::INFINITY
        };
        // Each folding round of arity 2^a is a batch of 2^a functions on its
        // domain: ε_i ≤ (2^a − 1)·n_i/|F|; union over rounds.
        let commit_err: f64 = self
            .rounds()
            .iter()
            .map(|&(log_ni, a)| ((1u64 << a) - 1) as f64 * 2f64.powf(log_ni - f))
            .sum();
        let delta = (1.0 - self.rho_plus) / 2.0;
        let query =
            params::NUM_QUERIES as f64 * bits((1.0 - delta).log2()) + params::QUERY_POW_BITS as f64;
        Terms {
            ali: f - self.log2_constraints(),
            deep: f - self.log2_deep(),
            batch,
            commit: bits(commit_err.log2()),
            query,
            logup: self.logup(0.0),
        }
    }

    /// Johnson regime at proximity parameter m: δ = 1 − √ρ⁺·(1 + 1/(2m)),
    /// list size L = (m + ½)/√ρ⁺. `bciks20_only` replaces the BCHKS25 batching
    /// bound (linear in n) by the peer-reviewed BCIKS20 one (quadratic in n).
    fn johnson(&self, m: usize, bciks20_only: bool) -> Terms {
        let f = log2_field();
        let m = m as f64;
        let sqrt_rho = self.rho_plus.sqrt();
        let log_list = ((m + 0.5) / sqrt_rho).log2();
        // log2 of the per-function batching factor at domain size 2^log_n.
        let factor = |log_n: f64| -> f64 {
            if bciks20_only {
                // (m + ½)^7 · n² / (3 ρ^{3/2})
                7.0 * (m + 0.5).log2() + 2.0 * log_n - 3f64.log2() - 1.5 * self.rho_plus.log2()
            } else {
                // 2 (m + ½)^5 · n / (3 ρ^{3/2})
                1.0 + 5.0 * (m + 0.5).log2() + log_n - 3f64.log2() - 1.5 * self.rho_plus.log2()
            }
        };
        let n_fns = self.shape.committed_columns.max(1) as f64;
        let batch = if n_fns >= 2.0 {
            f - (factor(self.log_n as f64) + (n_fns - 1.0).log2())
        } else {
            f64::INFINITY
        };
        let commit_err: f64 = self
            .rounds()
            .iter()
            .map(|&(log_ni, a)| ((1u64 << a) - 1) as f64 * 2f64.powf(factor(log_ni) - f))
            .sum();
        let query = params::NUM_QUERIES as f64 * bits((sqrt_rho * (1.0 + 0.5 / m)).log2())
            + params::QUERY_POW_BITS as f64;
        Terms {
            ali: f - (self.log2_constraints() + log_list),
            deep: f - (self.log2_deep() + log_list),
            batch,
            commit: bits(commit_err.log2()),
            query,
            logup: self.logup(log_list),
        }
    }

    /// The best m in [3, 200] (by the algebraic minimum).
    fn best_johnson(&self, bciks20_only: bool) -> (usize, Terms) {
        (3..=200)
            .map(|m| (m, self.johnson(m, bciks20_only)))
            .max_by(|a, b| a.1.algebraic().total_cmp(&b.1.algebraic()))
            .unwrap()
    }
}

fn grid() -> impl Iterator<Item = ProofShape> {
    let columns = [
        1usize,
        100,
        1_000,
        params::MAX_COMMITTED_COLUMNS,
        params::MAX_ADVERSARIAL_COLUMNS,
        65_536,
    ];
    (params::MIN_LOG_HEIGHT..=params::MAX_LOG_HEIGHT).flat_map(move |log_height| {
        [1usize, 100, 1_000, 5_000]
            .into_iter()
            .flat_map(move |constraints| {
                [1usize, 3, 5, params::MAX_CONSTRAINT_DEGREE]
                    .into_iter()
                    .flat_map(move |max_degree| {
                        columns
                            .into_iter()
                            .map(move |committed_columns| ProofShape {
                                constraints,
                                max_degree,
                                committed_columns,
                                log_height,
                            })
                    })
            })
    })
}

/// Over the whole envelope (committed degree bits 9..=23): the independent
/// figures agree with p3-security within one bit in the unique-decoding
/// regime and exactly (both capped) in the Johnson regime; both calculators
/// meet both floors; the query phase binds unique decoding, and every other
/// term, including those p3-security does not model, is at least 200 bits;
/// the Johnson regime's algebraic bound is at least 150 bits under BCHKS25
/// and under BCIKS20 alone, so the commitment term binds with a wide margin.
/// With the mixed-height union term (`MIXED_HEIGHTS`), the unique-decoding
/// figure still meets `MIN_PROVEN_BITS` at every point and the Johnson figure
/// is still `COLLISION_BITS`.
#[test]
fn the_independent_calculator_agrees_with_p3_security() {
    let mut points = 0;
    let (mut worst_udr, mut worst_non_query, mut worst_jb, mut worst_jb20) =
        (f64::INFINITY, f64::INFINITY, f64::INFINITY, f64::INFINITY);
    let mut worst_udr_mixed = f64::INFINITY;
    for shape in grid() {
        let p3 = params::security(&shape);
        let inst = Instance::new(shape);
        let udr = inst.udr();
        let (_, jb) = inst.best_johnson(false);
        let (_, jb20) = inst.best_johnson(true);
        let at = format!("{shape:?}: p3 {p3:?}, independent UDR {udr:?}");

        // (a) Agreement.
        assert!(
            (udr.reported() - p3.unique_decoding_bits as f64).abs() <= 1.0,
            "{at}"
        );
        assert_eq!(jb.reported().floor() as usize, p3.johnson_bits, "{at}");
        // (b) Which term binds, and the margins of the others.
        assert!(udr.query <= udr.non_query_min(), "{at}");
        assert!(udr.non_query_min() >= 200.0, "{at}");
        assert!(jb.algebraic() >= 150.0, "{at}: {jb:?}");
        assert!(jb20.algebraic() >= 150.0, "{at}: {jb20:?}");
        assert_eq!(jb20.reported(), params::COLLISION_BITS as f64, "{at}");
        // (c) Both floors, in both calculators.
        assert!(udr.reported() >= params::MIN_PROVEN_BITS as f64, "{at}");
        assert!(jb.reported() >= params::TARGET_JOHNSON_BITS as f64, "{at}");
        assert!(p3.unique_decoding_bits >= params::MIN_PROVEN_BITS, "{at}");
        assert!(p3.johnson_bits >= params::TARGET_JOHNSON_BITS, "{at}");
        // (d) The mixed-height union term: both floors still hold, every
        // non-query term stays >= 200 bits, the query phase still binds unique
        // decoding, and the Johnson figure is still the commitment term.
        let udr_mixed = udr.with_mixed_height_union();
        let jb_mixed = jb.with_mixed_height_union();
        let jb20_mixed = jb20.with_mixed_height_union();
        assert!(
            udr_mixed.reported() >= params::MIN_PROVEN_BITS as f64,
            "{at}: mixed {udr_mixed:?}"
        );
        assert!(udr_mixed.query <= udr_mixed.non_query_min(), "{at}");
        assert!(
            udr_mixed.non_query_min() >= 200.0,
            "{at}: mixed {udr_mixed:?}"
        );
        assert_eq!(jb_mixed.reported(), params::COLLISION_BITS as f64, "{at}");
        assert_eq!(jb20_mixed.reported(), params::COLLISION_BITS as f64, "{at}");

        worst_udr = worst_udr.min(udr.reported());
        worst_udr_mixed = worst_udr_mixed.min(udr_mixed.reported());
        worst_non_query = worst_non_query.min(udr.non_query_min());
        worst_jb = worst_jb.min(jb.algebraic());
        worst_jb20 = worst_jb20.min(jb20.algebraic());
        points += 1;
    }
    // The envelope's minimum with the mixed-height term: 105.58 − 5.04 at the
    // smallest height, where ρ⁺ is largest.
    assert!(
        (100.5..100.7).contains(&worst_udr_mixed),
        "{worst_udr_mixed}"
    );
    println!(
        "{points} shapes: UDR >= {worst_udr:.2} bits (query-bound; other terms >= {worst_non_query:.1}); \
         UDR with the mixed-height union over {MIXED_HEIGHTS} heights >= {worst_udr_mixed:.2}; \
         Johnson algebraic >= {worst_jb:.1} (BCHKS25), >= {worst_jb20:.1} (BCIKS20 only); \
         reported Johnson = COLLISION_BITS = {}",
        params::COLLISION_BITS
    );
}

/// Golden values at the largest shape (2^22 rows, i.e. degree bits 23; 5,000
/// constraints of degree 8; 65,536 batched functions), from the formulas
/// above: unique decoding ≈ 105.6 bits, of which 16 are grinding and ≈ 89.6
/// statistical (query phase alone); Johnson reported = `COLLISION_BITS`.
/// With the mixed-height union term (log2 33 = 5.04 bits, `MIXED_HEIGHTS`):
/// unique decoding ≈ 100.6 bits, just above the 100-bit floor; Johnson unchanged.
#[test]
fn headline_figures_at_the_largest_shape() {
    let shape = ProofShape {
        constraints: 5_000,
        max_degree: params::MAX_CONSTRAINT_DEGREE,
        committed_columns: 65_536,
        log_height: params::MAX_LOG_HEIGHT,
    };
    let inst = Instance::new(shape);
    let udr = inst.udr();
    let statistical = udr.query - params::QUERY_POW_BITS as f64;
    assert!((89.5..89.8).contains(&statistical), "{statistical}");
    assert!((105.5..105.8).contains(&udr.reported()), "{udr:?}");
    let mixed = udr.with_mixed_height_union();
    assert!((5.0..5.1).contains(&MIXED_HEIGHTS.log2()));
    assert!((100.5..100.8).contains(&mixed.reported()), "{mixed:?}");
    assert!(
        mixed.reported() >= params::MIN_PROVEN_BITS as f64,
        "{mixed:?}"
    );
    let p3 = params::security(&shape);
    assert_eq!(p3.unique_decoding_bits, 105);
    assert_eq!(p3.johnson_bits, params::COLLISION_BITS);
    assert_eq!(params::COLLISION_BITS, 122);
    let (m, jb) = inst.best_johnson(false);
    let (m20, jb20) = inst.best_johnson(true);
    println!(
        "largest shape: UDR {:.2} ({statistical:.2} statistical + {} grinding); \
         UDR with the mixed-height union {:.2}; \
         Johnson algebraic {:.1} at m = {m} (BCHKS25), {:.1} at m = {m20} (BCIKS20 only); \
         reported min(., {}) = {}",
        udr.reported(),
        params::QUERY_POW_BITS,
        mixed.reported(),
        jb.algebraic(),
        jb20.algebraic(),
        params::COLLISION_BITS,
        jb.reported()
    );
}

/// The commitment term is ePrint 2026/089 Theorem 3 evaluated for |H| = p^8:
/// (4q² + 2q)/(|H| − 1) reaches 1 at q ≈ 2^122.6, and `COLLISION_BITS` is its
/// floor. (The generic 8-element birthday figure, 123.6, is not used.)
#[test]
fn collision_bits_is_the_floor_of_the_merkle_extractability_bound() {
    let log_h = log2_field();
    // 4q² ≈ |H|  ⇒  log2 q = (log2 |H| − 2)/2 (the 2q term is negligible).
    let log_q = (log_h - 2.0) / 2.0;
    assert!((122.5..122.7).contains(&log_q), "{log_q}");
    assert_eq!(params::COLLISION_BITS, log_q.floor() as usize);
}
