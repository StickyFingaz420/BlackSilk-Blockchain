//! RT-W1b: an independent re-derivation of `max_weight(n, k)` through the
//! real transfer encoder (`Transfer::weight`, which runs the real encoding
//! and the real clawback), not through the spec formula that both
//! `params::max_weight` (a `const fn` since RTW1B-9) and
//! tools/vectors/max_weight.py transcribe.
//!
//! A transfer whose every varint takes 1 byte (version 1, counts below 128,
//! ring [0, 1, ..., 15] so every ring varint is 1 byte, fee 0) is encoded;
//! each of its 4 + 16n varints can grow by at most 9 bytes (a u64 LEB128 is
//! at most 10 bytes, spec §4.1), so max_weight = weight_min + 9 (4 + 16n).
//! For k = 0 (a PX v1 part) the spec has no range proof: the 192 bytes of
//! the empty proof's fixed part are removed.

use blacksilk_crypto::bulletproofs_plus::{self as bpp, BppProof};
use blacksilk_crypto::clsag::{Clsag, RING_SIZE};
use blacksilk_crypto::{Point, RistrettoPoint, Scalar};
use blacksilk_tx::params::{max_weight, MAX_INPUTS, MAX_OUTPUTS};
use blacksilk_tx::types::{Input, Output};
use blacksilk_tx::Transfer;

fn pt(n: u64) -> Point {
    Point::from_point(RistrettoPoint::mul_base(&Scalar::from(n + 1)))
}

fn weight_min(n: usize, k: usize) -> u64 {
    let rounds = if k == 0 { 0 } else { bpp::rounds(k).unwrap() };
    let t = Transfer {
        inputs: (0..n)
            .map(|i| Input {
                key_image: pt(i as u64),
                ring: std::array::from_fn(|j| j as u64),
            })
            .collect(),
        outputs: (0..k)
            .map(|j| Output {
                one_time_key: pt(100 + j as u64),
                ephemeral: pt(200),
                view_tag: 0,
                commitment: pt(201),
                enc_amount: [0; 8],
                enc_anchor: [0; 16],
            })
            .collect(),
        fee: 0,
        pseudo_outs: vec![pt(9); n],
        range_proof: BppProof {
            a: pt(1),
            a1: pt(1),
            b: pt(1),
            r1: Scalar::ZERO,
            s1: Scalar::ZERO,
            d1: Scalar::ZERO,
            l: vec![pt(2); rounds],
            r: vec![pt(3); rounds],
        },
        signatures: vec![
            Clsag {
                c0: Scalar::ZERO,
                s: [Scalar::ZERO; RING_SIZE],
                d: pt(8),
            };
            n
        ],
    };
    let w = t.weight();
    if k == 0 {
        w - 192
    } else {
        w
    }
}

#[test]
fn max_weight_through_the_real_encoder() {
    let file = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/max_weight.txt"),
    )
    .unwrap();
    let mut rows = 0;
    for line in file
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let v: Vec<u64> = line
            .split_whitespace()
            .map(|x| x.parse().unwrap())
            .collect();
        let (n, k, mw, fee) = (v[0] as usize, v[1] as usize, v[2], v[3]);
        let derived = weight_min(n, k) + 9 * (4 + 16 * n as u64);
        assert_eq!(derived, mw, "file row ({n}, {k})");
        assert_eq!(max_weight(n, k), derived, "Rust ({n}, {k})");
        assert_eq!(fee, 20 * derived, "fee ({n}, {k})");
        rows += 1;
    }
    assert_eq!(rows, MAX_INPUTS * (MAX_OUTPUTS + 1));
}
