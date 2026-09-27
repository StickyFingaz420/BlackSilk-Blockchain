//! `max_weight(n_in, n_out)`, which defines the exact v1 fee (T8), the v1
//! part of the exact deploy fee and the block weight of the v1 part of PX and
//! deploy transactions (docs/transactions.md §8.4;
//! docs/reviews/v3-consensus-changes.md#exact-v1-fee).
//!
//! - Golden values for every shape, from the independent
//!   `tools/vectors/max_weight.py` (`tx/tests/data/max_weight.txt`).
//! - A property: `max_weight` bounds the weight of every transfer of the
//!   shape, whatever its varints, so the exact fee always covers
//!   `min_fee(weight)`.

use blacksilk_consensus::ChainParams;
use blacksilk_crypto::bulletproofs_plus::{self as bpp, BppProof};
use blacksilk_crypto::clsag::{Clsag, RING_SIZE};
use blacksilk_crypto::{Point, RistrettoPoint, Scalar};
use blacksilk_tx::params::{
    max_weight, TxRules, FEE_PER_WEIGHT, MAX_INPUTS, MAX_OUTPUTS, MIN_OUTPUTS,
};
use blacksilk_tx::types::{Input, Output, Transfer};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

const TABLE: &str = include_str!("data/max_weight.txt");

fn rules() -> TxRules {
    TxRules::for_chain(&ChainParams::regtest())
}

#[test]
fn max_weight_and_the_exact_fee_match_the_independent_table() {
    let rules = rules();
    assert_eq!(rules.fee_per_weight, FEE_PER_WEIGHT);
    assert_eq!(FEE_PER_WEIGHT, 20);
    let mut rows = 0;
    for line in TABLE.lines().filter(|l| !l.starts_with('#')) {
        let v: Vec<u64> = line
            .split_whitespace()
            .map(|x| x.parse().unwrap())
            .collect();
        let (n, k, w, fee) = (v[0] as usize, v[1] as usize, v[2], v[3]);
        assert_eq!(max_weight(n, k), w, "max_weight({n}, {k})");
        assert_eq!(
            rules.standard_fee(n, k),
            Some(fee),
            "standard_fee({n}, {k})"
        );
        rows += 1;
    }
    // Every input count and every output count 0..=16 (0 and 1: PX v1 parts).
    assert_eq!(rows, MAX_INPUTS * (MAX_OUTPUTS + 1));
    // Hand-checked anchors (docs/transactions.md §8.4): 1-in/2-out, the
    // largest shape, and a PX v1 part without hidden outputs.
    assert_eq!(max_weight(1, 2), 1_723);
    assert_eq!(rules.standard_fee(1, 2), Some(34_460));
    assert_eq!(max_weight(64, 16), 57_439);
    assert_eq!(max_weight(1, 0), 841);
}

fn pt(n: u64) -> Point {
    Point::from_point(RistrettoPoint::mul_base(&Scalar::from(n + 1)))
}

/// A transfer of shape `(n, k)` whose ring entries and fee are drawn from
/// `rng` over the whole `u64` range (so varints of every length occur);
/// `extreme` makes every ring delta and the fee need 10-byte varints.
/// Only the encoding matters to the weight, so points and scalars are
/// placeholders.
fn shaped(n: usize, k: usize, rng: &mut ChaCha20Rng, extreme: bool) -> Transfer {
    let inputs = (0..n)
        .map(|i| {
            let mut ring = [0u64; RING_SIZE];
            if extreme {
                // Alternating 0 / 2^63 + j: every delta (wrapping) is ≥ 2^63.
                for (j, r) in ring.iter_mut().enumerate() {
                    *r = if j % 2 == 0 {
                        j as u64
                    } else {
                        (1 << 63) + j as u64
                    };
                }
            } else {
                for r in ring.iter_mut() {
                    *r = rng.next_u64() >> (rng.next_u64() % 64);
                }
                ring.sort_unstable();
            }
            Input {
                key_image: pt(i as u64),
                ring,
            }
        })
        .collect();
    let outputs = (0..k)
        .map(|j| Output {
            one_time_key: pt(100 + j as u64),
            ephemeral: pt(200),
            view_tag: 0,
            commitment: pt(300),
            enc_amount: [0; 8],
            enc_anchor: [0; 16],
        })
        .collect();
    let rounds = bpp::rounds(k).unwrap();
    Transfer {
        inputs,
        outputs,
        fee: if extreme { u64::MAX } else { rng.next_u64() },
        pseudo_outs: (0..n).map(|_| pt(400)).collect(),
        range_proof: BppProof {
            a: pt(1),
            a1: pt(2),
            b: pt(3),
            r1: Scalar::ZERO,
            s1: Scalar::ZERO,
            d1: Scalar::ZERO,
            l: vec![pt(4); rounds],
            r: vec![pt(5); rounds],
        },
        signatures: (0..n)
            .map(|_| Clsag {
                c0: Scalar::ZERO,
                s: [Scalar::ZERO; RING_SIZE],
                d: pt(6),
            })
            .collect(),
    }
}

/// For every valid transfer shape, random and extreme encodings weigh at
/// most `max_weight`: the exact fee `FEE_PER_WEIGHT × max_weight` always
/// pays at least `min_fee(weight)` (the former T8 minimum is implied).
#[test]
fn max_weight_bounds_the_weight_of_every_valid_shape() {
    let rules = rules();
    let mut rng = ChaCha20Rng::seed_from_u64(0x3e1a);
    let mut checked = 0;
    for n in 1..=MAX_INPUTS {
        for k in MIN_OUTPUTS..=MAX_OUTPUTS {
            let bound = max_weight(n, k);
            for case in 0..4 {
                let t = shaped(n, k, &mut rng, case == 0);
                let w = t.weight();
                assert!(w <= bound, "({n}, {k}) case {case}: weight {w} > {bound}");
                assert!(
                    rules.standard_fee(n, k).unwrap() >= rules.min_fee(w).unwrap(),
                    "({n}, {k})"
                );
                checked += 1;
            }
        }
    }
    assert_eq!(checked, MAX_INPUTS * (MAX_OUTPUTS - MIN_OUTPUTS + 1) * 4);
}
