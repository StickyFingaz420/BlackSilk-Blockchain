//! Non-malleability of CLSAG signatures and Bulletproofs+ range proofs (T-1 b, c).
//!
//! For a valid signature or proof, altering any single scalar or point must make
//! verification fail: adding one, negating, zeroing, replacing a point with the
//! identity or with another group element. Non-canonical encodings are covered
//! at the only place they can appear, decoding: `decode_scalar` must reject
//! `s + ℓ` for every scalar of a valid signature/proof (the reduced value would
//! verify, which is exactly why reduction must never happen).
//!
//! Batch verification of range proofs must agree with individual verification
//! on every subset of a mixed batch, including a pair of invalid proofs whose
//! errors cancel in an unweighted sum.

use blacksilk_crypto::bulletproofs_plus::{self as bpp, BppProof};
use blacksilk_crypto::clsag::{self, Clsag, RingMember, RING_SIZE};
use blacksilk_crypto::commitment::commit;
use blacksilk_crypto::point::decode_scalar;
use blacksilk_crypto::{Point, RistrettoPoint, Scalar};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

fn rng(seed: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

fn random_scalar(rng: &mut impl RngCore) -> Scalar {
    let mut wide = [0u8; 64];
    rng.fill_bytes(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn g() -> RistrettoPoint {
    RistrettoPoint::mul_base(&Scalar::ONE)
}

fn identity() -> Point {
    Point::decode(&[0; 32]).expect("identity encodes as zero")
}

/// ℓ, little-endian.
const L_BYTES: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// The 256-bit integer `s + ℓ` (no reduction). `s < ℓ < 2^253`, so it fits.
fn plus_l(s: &Scalar) -> [u8; 32] {
    let a = s.to_bytes();
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in 0..32 {
        let v = a[i] as u16 + L_BYTES[i] as u16 + carry;
        out[i] = v as u8;
        carry = v >> 8;
    }
    assert_eq!(carry, 0);
    out
}

/// `s + ℓ` is rejected by the canonical decoder, and it reduces to `s`.
fn assert_non_canonical_rejected(s: &Scalar, what: &str) {
    let bytes = plus_l(s);
    assert!(decode_scalar(&bytes).is_none(), "{what}: s + ℓ decoded");
    assert_eq!(Scalar::from_bytes_mod_order(bytes), *s, "{what}");
    assert_eq!(decode_scalar(&s.to_bytes()), Some(*s), "{what}: canonical");
}

/// Scalar alterations: +1, negation, zero, ×2.
fn scalar_variants(s: &Scalar) -> Vec<(&'static str, Scalar)> {
    vec![
        ("+1", s + Scalar::ONE),
        ("neg", -s),
        ("zero", Scalar::ZERO),
        ("x2", s + s),
    ]
    .into_iter()
    .filter(|(_, v)| v != s)
    .collect()
}

/// Point alterations: +G, negation, identity, doubling.
fn point_variants(p: &Point) -> Vec<(&'static str, Point)> {
    vec![
        ("+G", Point::from_point(p.point() + g())),
        ("neg", Point::from_point(-p.point())),
        ("identity", identity()),
        ("x2", Point::from_point(p.point() + p.point())),
    ]
    .into_iter()
    .filter(|(_, v)| v != p)
    .collect()
}

// ---------------------------------------------------------------- CLSAG

struct Signed {
    message: [u8; 32],
    ring: [RingMember; RING_SIZE],
    pseudo_out: Point,
    key_image: Point,
    sig: Clsag,
}

impl Signed {
    fn verifies(&self) -> bool {
        clsag::verify(
            &self.message,
            &self.ring,
            &self.pseudo_out,
            &self.key_image,
            &self.sig,
        )
    }
}

fn signed(seed: u64, real: usize) -> Signed {
    let mut rng = rng(seed);
    let p = random_scalar(&mut rng);
    let mask = random_scalar(&mut rng);
    let pseudo_mask = random_scalar(&mut rng);
    let amount = 5_000u64;
    let mut ring = [RingMember {
        one_time_key: Point::from_point(g()),
        commitment: Point::from_point(g()),
    }; RING_SIZE];
    for (i, m) in ring.iter_mut().enumerate() {
        if i == real {
            m.one_time_key = Point::from_point(RistrettoPoint::mul_base(&p));
            m.commitment = Point::from_point(commit(amount, &mask));
        } else {
            m.one_time_key = Point::from_point(RistrettoPoint::mul_base(&random_scalar(&mut rng)));
            m.commitment = Point::from_point(commit(rng.next_u64(), &random_scalar(&mut rng)));
        }
    }
    let pseudo_out = Point::from_point(commit(amount, &pseudo_mask));
    let mut message = [0u8; 32];
    rng.fill_bytes(&mut message);
    let (sig, key_image) = clsag::sign(
        &message,
        &ring,
        &pseudo_out,
        real,
        &p,
        &(mask - pseudo_mask),
        &mut rng,
    )
    .unwrap();
    let s = Signed {
        message,
        ring,
        pseudo_out,
        key_image,
        sig,
    };
    assert!(s.verifies());
    s
}

#[test]
fn clsag_every_scalar_alteration_fails() {
    for (seed, real) in [(1u64, 0usize), (2, 7), (3, 15)] {
        let base = signed(seed, real);
        let mut tried = 0;
        for (how, v) in scalar_variants(&base.sig.c0) {
            let mut s = Signed {
                sig: base.sig.clone(),
                ..base
            };
            s.sig.c0 = v;
            assert!(!s.verifies(), "c0 {how}");
            tried += 1;
        }
        for i in 0..RING_SIZE {
            for (how, v) in scalar_variants(&base.sig.s[i]) {
                let mut s = Signed {
                    sig: base.sig.clone(),
                    ..base
                };
                s.sig.s[i] = v;
                assert!(!s.verifies(), "s[{i}] {how} (real {real})");
                tried += 1;
            }
        }
        // Swapping two responses.
        let mut s = Signed {
            sig: base.sig.clone(),
            ..base
        };
        s.sig.s.swap(real, (real + 1) % RING_SIZE);
        assert!(!s.verifies(), "swapped responses");
        assert!(tried >= 4 * 17 - 1, "{tried}");
    }
}

#[test]
fn clsag_every_point_alteration_fails() {
    let base = signed(4, 5);
    for (how, v) in point_variants(&base.sig.d) {
        let mut s = Signed {
            sig: base.sig.clone(),
            ..base
        };
        s.sig.d = v;
        assert!(!s.verifies(), "D {how}");
    }
    // The key image: the double-spend tag must not have a second valid form.
    for (how, v) in point_variants(&base.key_image) {
        let s = Signed {
            key_image: v,
            sig: base.sig.clone(),
            ..base
        };
        assert!(!s.verifies(), "key image {how}");
    }
    for (how, v) in point_variants(&base.pseudo_out) {
        let s = Signed {
            pseudo_out: v,
            sig: base.sig.clone(),
            ..base
        };
        assert!(!s.verifies(), "pseudo-out {how}");
    }
    for i in 0..RING_SIZE {
        for (how, v) in point_variants(&base.ring[i].one_time_key) {
            let mut s = Signed {
                sig: base.sig.clone(),
                ..base
            };
            s.ring[i].one_time_key = v;
            assert!(!s.verifies(), "ring[{i}].P {how}");
        }
        for (how, v) in point_variants(&base.ring[i].commitment) {
            let mut s = Signed {
                sig: base.sig.clone(),
                ..base
            };
            s.ring[i].commitment = v;
            assert!(!s.verifies(), "ring[{i}].C {how}");
        }
    }
    // Ring order and message.
    let mut s = Signed {
        sig: base.sig.clone(),
        ..base
    };
    s.ring.rotate_left(1);
    assert!(!s.verifies(), "rotated ring");
    for bit in [0usize, 7, 128, 255] {
        let mut s = Signed {
            sig: base.sig.clone(),
            ..base
        };
        s.message[bit / 8] ^= 1 << (bit % 8);
        assert!(!s.verifies(), "message bit {bit}");
    }
}

#[test]
fn clsag_non_canonical_scalars_are_rejected_by_decoding() {
    let base = signed(5, 3);
    assert_non_canonical_rejected(&base.sig.c0, "c0");
    for (i, s) in base.sig.s.iter().enumerate() {
        assert_non_canonical_rejected(s, &format!("s[{i}]"));
    }
}

#[test]
fn clsag_identity_key_image_and_d() {
    let base = signed(6, 9);
    let s = Signed {
        key_image: identity(),
        sig: base.sig.clone(),
        ..base
    };
    assert!(!s.verifies());
    let mut s = Signed {
        sig: base.sig.clone(),
        ..base
    };
    s.sig.d = identity();
    assert!(!s.verifies());
}

// ---------------------------------------------------------- Bulletproofs+

fn proof(seed: u64, amounts: &[u64]) -> (BppProof, Vec<Point>) {
    let mut rng = rng(seed);
    let masks: Vec<Scalar> = amounts.iter().map(|_| random_scalar(&mut rng)).collect();
    let (p, c) = bpp::prove(amounts, &masks, &mut rng).unwrap();
    assert!(bpp::verify(&p, &c));
    (p, c)
}

/// Every single-field alteration of `p` (for `c`); returns how many were tried.
fn assert_all_alterations_fail(p: &BppProof, c: &[Point]) -> usize {
    let mut tried = 0;
    let mut check = |q: BppProof, what: String| {
        assert!(!bpp::verify(&q, c), "{what}");
        tried += 1;
    };
    for (name, get) in [
        (
            "A",
            (|q: &mut BppProof| &mut q.a) as fn(&mut BppProof) -> &mut Point,
        ),
        ("A1", |q| &mut q.a1),
        ("B", |q| &mut q.b),
    ] {
        let cur = *get(&mut p.clone());
        for (how, v) in point_variants(&cur) {
            let mut q = p.clone();
            *get(&mut q) = v;
            check(q, format!("{name} {how}"));
        }
    }
    for (name, get) in [
        (
            "r1",
            (|q: &mut BppProof| &mut q.r1) as fn(&mut BppProof) -> &mut Scalar,
        ),
        ("s1", |q| &mut q.s1),
        ("d1", |q| &mut q.d1),
    ] {
        let cur = *get(&mut p.clone());
        for (how, v) in scalar_variants(&cur) {
            let mut q = p.clone();
            *get(&mut q) = v;
            check(q, format!("{name} {how}"));
        }
    }
    for t in 0..p.l.len() {
        for (how, v) in point_variants(&p.l[t]) {
            let mut q = p.clone();
            q.l[t] = v;
            check(q, format!("L[{t}] {how}"));
        }
        for (how, v) in point_variants(&p.r[t]) {
            let mut q = p.clone();
            q.r[t] = v;
            check(q, format!("R[{t}] {how}"));
        }
    }
    // Structural rewrites: L and R exchanged, rounds reordered, a round dropped.
    let mut q = p.clone();
    std::mem::swap(&mut q.l, &mut q.r);
    check(q, "L <-> R".into());
    let mut q = p.clone();
    q.l.reverse();
    q.r.reverse();
    check(q, "rounds reversed".into());
    let mut q = p.clone();
    q.l.pop();
    q.r.pop();
    check(q, "one round short".into());
    let mut q = p.clone();
    q.l.push(q.l[0]);
    q.r.push(q.r[0]);
    check(q, "one round extra".into());
    tried
}

#[test]
fn bpp_every_field_alteration_fails() {
    for (seed, amounts) in [
        (10u64, vec![0u64]),
        (11, vec![u64::MAX, 1]),
        (12, vec![7, 1 << 40, 123_456_789]), // padded to 4
    ] {
        let (p, c) = proof(seed, &amounts);
        let tried = assert_all_alterations_fail(&p, &c);
        let rounds = bpp::rounds(amounts.len()).unwrap();
        assert!(tried >= 3 * 4 + 3 * 3 + 2 * rounds * 4, "{tried}");
    }
}

#[test]
fn bpp_commitment_alterations_fail() {
    let (p, c) = proof(13, &[5, 6, 7]);
    for j in 0..c.len() {
        for (how, v) in point_variants(&c[j]) {
            let mut d = c.clone();
            d[j] = v;
            assert!(!bpp::verify(&p, &d), "V[{j}] {how}");
        }
    }
    let mut d = c.clone();
    d.swap(0, 2);
    assert!(!bpp::verify(&p, &d), "commitments reordered");
    assert!(!bpp::verify(&p, &c[..2]), "one commitment fewer");
    let mut d = c.clone();
    d.push(c[0]);
    assert!(
        !bpp::verify(&p, &d),
        "one commitment more (same padded size)"
    );
    assert!(!bpp::verify(&p, &[]), "no commitments");
}

#[test]
fn bpp_non_canonical_scalars_are_rejected_by_decoding() {
    let (p, _) = proof(14, &[1, 2]);
    assert_non_canonical_rejected(&p.r1, "r1");
    assert_non_canonical_rejected(&p.s1, "s1");
    assert_non_canonical_rejected(&p.d1, "d1");
}

// ------------------------------------------------------ batch verification

#[test]
fn batch_verify_agrees_with_individual_verification() {
    let (p1, c1) = proof(20, &[1]);
    let (p2, c2) = proof(21, &[2, 3]);
    let (p3, c3) = proof(22, &[4, 5, 6]);
    let mut bad_r1 = p2.clone();
    bad_r1.r1 += Scalar::ONE;
    let mut bad_l = p3.clone();
    bad_l.l[1] = Point::from_point(bad_l.l[1].point() + g());
    let wrong_c: Vec<Point> = vec![Point::from_point(c1[0].point() + g())];

    let items: Vec<(&BppProof, &[Point])> = vec![
        (&p1, &c1[..]),
        (&p2, &c2[..]),
        (&p3, &c3[..]),
        (&bad_r1, &c2[..]),
        (&bad_l, &c3[..]),
        (&p1, &wrong_c[..]),
        (&p2, &c3[..]), // shape mismatch: 2-output proof for 3 commitments
    ];
    let individual: Vec<bool> = items.iter().map(|(p, c)| bpp::verify(p, c)).collect();
    assert_eq!(individual, [true, true, true, false, false, false, false]);

    let mut r = rng(99);
    let mut batches = 0;
    for mask in 0u32..(1 << items.len()) {
        let batch: Vec<(&BppProof, &[Point])> = (0..items.len())
            .filter(|i| mask & (1 << i) != 0)
            .map(|i| items[i])
            .collect();
        let expected = (0..items.len())
            .filter(|i| mask & (1 << i) != 0)
            .all(|i| individual[i]);
        assert_eq!(
            bpp::batch_verify(&batch, &mut r),
            expected,
            "subset {mask:#b}"
        );
        batches += 1;
    }
    assert_eq!(batches, 128);
    // Duplicates of a valid proof are fine.
    assert!(bpp::batch_verify(&[(&p1, &c1[..]), (&p1, &c1[..])], &mut r));
}

#[test]
fn batch_weights_prevent_cancelling_errors() {
    // Two invalid proofs whose errors cancel in an unweighted sum: the blinding
    // response d1 enters the equation linearly, so d1 + δ in one proof and
    // d1 − δ in a copy of the same statement cancel when both weights are 1.
    let (p, c) = proof(30, &[42, 43]);
    let delta = Scalar::from(1234u64);
    let mut plus = p.clone();
    plus.d1 += delta;
    let mut minus = p.clone();
    minus.d1 -= delta;
    assert!(!bpp::verify(&plus, &c));
    assert!(!bpp::verify(&minus, &c));
    let mut r = rng(31);
    for _ in 0..8 {
        assert!(!bpp::batch_verify(
            &[(&plus, &c[..]), (&minus, &c[..])],
            &mut r
        ));
    }
}
