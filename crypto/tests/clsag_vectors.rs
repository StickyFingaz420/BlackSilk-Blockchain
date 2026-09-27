//! Pinned CLSAG vectors (spec §6.1; dossier 15, item W3).
//!
//! **Independent derivation.** The accept vectors are produced by a reference
//! signer written in this file from `docs/transactions.md` §6.1 only: its own
//! Blake2b calls (`common::spec`), its own ring encoding and loop, and explicit
//! nonces (`α` and the simulated responses `s[i]` are fixed inputs, so the
//! vectors do not depend on `HedgedRng`). The implementation's `clsag::verify`
//! must accept them, and a reference verifier, also written from §6.1, must
//! agree with it on every accept and reject vector. Every input, intermediate
//! value (`Hp_i`, `I`, `D`, `μP`, `μC`, `W`, all `c[i]`) and the encoded
//! signature is pinned in `tests/vectors/clsag.txt`.
//!
//! The explicit nonces are test inputs only. Real signers must use the hedged
//! stream (spec §10); reusing `α` across statements leaks the secret key.
//!
//! **Regression pin.** One vector pins the implementation's own `clsag::sign`
//! with a constant RNG (wallet-side behaviour, not consensus): it is labelled
//! `regression.` in the file.
//!
//! Encoding of the pinned signature: `c0 ‖ s[0] ‖ … ‖ s[15] ‖ D` (spec §4.2,
//! 576 bytes). Scalars are 32-byte little-endian, points compressed Ristretto.

mod common;

use blacksilk_crypto::clsag::{self, Clsag, RingMember, CLSAG_BYTES, RING_SIZE};
use blacksilk_crypto::point::decode_scalar;
use blacksilk_crypto::Point;
use common::spec::{self, cat, enc};
use common::{wide, Pins, ZeroRng};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;

const FILE: &str = "tests/vectors/clsag.txt";
const VECTORS: &str = include_str!("vectors/clsag.txt");

/// The pseudo-output of a vector.
#[derive(Clone, Copy)]
enum Pseudo {
    /// `C' = Com(real amount, mask)`.
    Mask(u8),
    /// `C'` equals the commitment of decoy `j` (the real amount is chosen to match).
    Decoy(usize),
    /// `C' = Cr[π]`, so `z = 0` and `D = identity`.
    Real,
}

/// Inputs of one vector. Ring member `i ≠ π` has key `wide(0x40 + i)·G` and
/// commitment `Com(1000 + i, wide(0x60 + i))`; the real member has key
/// `wide(0x11)·G` and commitment `Com(amount, wide(0x22))`.
struct Def {
    name: &'static str,
    pi: usize,
    pseudo: Pseudo,
    /// Message `[msg; 32]`, `α = wide(alpha)`.
    msg: u8,
    alpha: u8,
}

const REAL_KEY: u8 = 0x11;
const REAL_MASK: u8 = 0x22;

/// `s[i] = wide(0xc0 + i)` for `i ≠ π`.
fn simulated_response(i: usize) -> Scalar {
    wide(0xc0 + i as u8)
}

const ACCEPT: [Def; 4] = [
    Def {
        name: "pi0",
        pi: 0,
        pseudo: Pseudo::Mask(0x33),
        msg: 0x50,
        alpha: 0xa0,
    },
    Def {
        name: "pi6",
        pi: 6,
        pseudo: Pseudo::Mask(0x33),
        msg: 0x5a,
        alpha: 0xa1,
    },
    Def {
        name: "pi15",
        pi: 15,
        pseudo: Pseudo::Mask(0x34),
        msg: 0x51,
        alpha: 0xa2,
    },
    // `C'` equals decoy 4's commitment: `Cr[4] − C'` is the identity.
    Def {
        name: "cprime_equals_decoy",
        pi: 9,
        pseudo: Pseudo::Decoy(4),
        msg: 0x52,
        alpha: 0xa3,
    },
];

/// `z = 0`: `C' = Cr[π]` and `D = identity` (finding C1 / CB-B1).
const D_IDENTITY: Def = Def {
    name: "d_identity",
    pi: 3,
    pseudo: Pseudo::Real,
    msg: 0x53,
    alpha: 0xa4,
};

/// A statement and its reference signature, with every intermediate value.
#[derive(Clone)]
struct Vector {
    pi: usize,
    keys: [RistrettoPoint; RING_SIZE],
    commitments: [RistrettoPoint; RING_SIZE],
    pseudo_out: RistrettoPoint,
    message: [u8; 32],
    p: Scalar,
    z: Scalar,
    alpha: Scalar,
    hp: [RistrettoPoint; RING_SIZE],
    key_image: RistrettoPoint,
    d: RistrettoPoint,
    mu_p: Scalar,
    mu_c: Scalar,
    w: RistrettoPoint,
    c: [Scalar; RING_SIZE],
    s: [Scalar; RING_SIZE],
}

/// `ring_bytes = P[0] ‖ … ‖ P[15] ‖ Cr[0] ‖ … ‖ Cr[15]`.
fn ring_bytes(keys: &[RistrettoPoint], commitments: &[RistrettoPoint]) -> Vec<u8> {
    keys.iter().chain(commitments).flat_map(enc).collect()
}

fn hp_key_image(key: &RistrettoPoint) -> RistrettoPoint {
    spec::hp("key-image", &enc(key))
}

/// `μP`, `μC` (spec §6.1).
fn aggregation(
    ring: &[u8],
    key_image: &RistrettoPoint,
    d: &RistrettoPoint,
    pseudo_out: &RistrettoPoint,
) -> (Scalar, Scalar) {
    let data = cat(&[ring, &enc(key_image), &enc(d), &enc(pseudo_out)]);
    (
        spec::hs("clsag/agg-P", &data),
        spec::hs("clsag/agg-C", &data),
    )
}

/// `Hs("clsag/round", ring_bytes ‖ C' ‖ m ‖ L ‖ R)`.
fn round(
    ring: &[u8],
    pseudo_out: &RistrettoPoint,
    m: &[u8; 32],
    l: &RistrettoPoint,
    r: &RistrettoPoint,
) -> Scalar {
    spec::hs(
        "clsag/round",
        &cat(&[ring, &enc(pseudo_out), m, &enc(l), &enc(r)]),
    )
}

/// The reference signer (spec §6.1) with explicit nonces.
fn reference_sign(def: &Def) -> Vector {
    let pi = def.pi;
    let p = wide(REAL_KEY);
    let real_amount = match def.pseudo {
        Pseudo::Decoy(j) => 1_000 + j as u64,
        _ => 1_000,
    };
    let mut keys = [RistrettoPoint::default(); RING_SIZE];
    let mut commitments = [RistrettoPoint::default(); RING_SIZE];
    for i in 0..RING_SIZE {
        if i == pi {
            keys[i] = p * spec::g();
            commitments[i] = spec::com(real_amount, &wide(REAL_MASK));
        } else {
            keys[i] = wide(0x40 + i as u8) * spec::g();
            commitments[i] = spec::com(1_000 + i as u64, &wide(0x60 + i as u8));
        }
    }
    let (pseudo_out, z) = match def.pseudo {
        Pseudo::Mask(b) => (spec::com(real_amount, &wide(b)), wide(REAL_MASK) - wide(b)),
        Pseudo::Decoy(j) => (commitments[j], wide(REAL_MASK) - wide(0x60 + j as u8)),
        Pseudo::Real => (commitments[pi], Scalar::ZERO),
    };
    assert_eq!(
        z * spec::g(),
        commitments[pi] - pseudo_out,
        "z·G = Cr[π] − C'"
    );
    let message = [def.msg; 32];
    let alpha = wide(def.alpha);

    let ring = ring_bytes(&keys, &commitments);
    let hp: [RistrettoPoint; RING_SIZE] = std::array::from_fn(|i| hp_key_image(&keys[i]));
    let key_image = p * hp[pi];
    let d = z * hp[pi];
    let (mu_p, mu_c) = aggregation(&ring, &key_image, &d, &pseudo_out);
    let w = mu_p * key_image + mu_c * d;

    let mut c = [Scalar::ZERO; RING_SIZE];
    let mut s = [Scalar::ZERO; RING_SIZE];
    let first = (pi + 1) % RING_SIZE;
    c[first] = round(
        &ring,
        &pseudo_out,
        &message,
        &(alpha * spec::g()),
        &(alpha * hp[pi]),
    );
    let mut i = first;
    while i != pi {
        s[i] = simulated_response(i);
        let l = s[i] * spec::g() + c[i] * (mu_p * keys[i] + mu_c * (commitments[i] - pseudo_out));
        let r = s[i] * hp[i] + c[i] * w;
        let next = (i + 1) % RING_SIZE;
        c[next] = round(&ring, &pseudo_out, &message, &l, &r);
        i = next;
    }
    s[pi] = alpha - c[pi] * (mu_p * p + mu_c * z);

    Vector {
        pi,
        keys,
        commitments,
        pseudo_out,
        message,
        p,
        z,
        alpha,
        hp,
        key_image,
        d,
        mu_p,
        mu_c,
        w,
        c,
        s,
    }
}

/// A single change of a statement (reject vectors).
type Change<'a> = dyn Fn(&mut Statement) + 'a;

/// What a signature is verified against: message, ring, `C'` and `I`.
#[derive(Clone, Copy)]
struct Statement {
    message: [u8; 32],
    keys: [RistrettoPoint; RING_SIZE],
    commitments: [RistrettoPoint; RING_SIZE],
    pseudo_out: RistrettoPoint,
    key_image: RistrettoPoint,
}

/// The reference verifier, literally spec §6.1 as written today: reject
/// `I = identity`, recompute `μP`, `μC`, `W`, run the loop from `c0`.
fn reference_verify(st: &Statement, sig: &Clsag) -> bool {
    if st.key_image.is_identity() {
        return false;
    }
    let ring = ring_bytes(&st.keys, &st.commitments);
    let d = *sig.d.point();
    let (mu_p, mu_c) = aggregation(&ring, &st.key_image, &d, &st.pseudo_out);
    let w = mu_p * st.key_image + mu_c * d;
    let mut c = sig.c0;
    for i in 0..RING_SIZE {
        let offset = st.commitments[i] - st.pseudo_out;
        let l = sig.s[i] * spec::g() + c * (mu_p * st.keys[i] + mu_c * offset);
        let r = sig.s[i] * hp_key_image(&st.keys[i]) + c * w;
        c = round(&ring, &st.pseudo_out, &st.message, &l, &r);
    }
    c == sig.c0
}

/// Both verifiers on a (possibly modified) statement; they must agree.
fn verdict(st: &Statement, sig: &Clsag, what: &str) -> bool {
    let ring: [RingMember; RING_SIZE] = std::array::from_fn(|i| RingMember {
        one_time_key: Point::from_point(st.keys[i]),
        commitment: Point::from_point(st.commitments[i]),
    });
    let implementation = clsag::verify(
        &st.message,
        &ring,
        &Point::from_point(st.pseudo_out),
        &Point::from_point(st.key_image),
        sig,
    );
    let reference = reference_verify(st, sig);
    assert_eq!(implementation, reference, "{what}: verifiers disagree");
    implementation
}

/// The encoded signature (`c0 ‖ s ‖ D`), decoded through the canonical decoders.
fn decode_sig(bytes: &[u8]) -> Clsag {
    assert_eq!(bytes.len(), CLSAG_BYTES);
    let field = |i: usize| -> [u8; 32] { bytes[32 * i..32 * (i + 1)].try_into().unwrap() };
    Clsag {
        c0: decode_scalar(&field(0)).expect("canonical c0"),
        s: std::array::from_fn(|i| decode_scalar(&field(1 + i)).expect("canonical s")),
        d: Point::decode(&field(RING_SIZE + 1)).expect("canonical D"),
    }
}

fn encode_sig(sig: &Clsag) -> Vec<u8> {
    let mut out = Vec::with_capacity(CLSAG_BYTES);
    out.extend_from_slice(&sig.c0.to_bytes());
    for s in &sig.s {
        out.extend_from_slice(&s.to_bytes());
    }
    out.extend_from_slice(sig.d.bytes());
    out
}

impl Vector {
    fn sig(&self) -> Clsag {
        Clsag {
            c0: self.c[0],
            s: self.s,
            d: Point::from_point(self.d),
        }
    }

    fn ring(&self) -> [RingMember; RING_SIZE] {
        std::array::from_fn(|i| RingMember {
            one_time_key: Point::from_point(self.keys[i]),
            commitment: Point::from_point(self.commitments[i]),
        })
    }

    fn statement(&self) -> Statement {
        Statement {
            message: self.message,
            keys: self.keys,
            commitments: self.commitments,
            pseudo_out: self.pseudo_out,
            key_image: self.key_image,
        }
    }

    fn verdict_on(&self, sig: &Clsag, what: &str) -> bool {
        verdict(&self.statement(), sig, what)
    }

    fn pin(&self, pins: &mut Pins) {
        let cat_points = |v: &[RistrettoPoint]| -> Vec<u8> { v.iter().flat_map(enc).collect() };
        let cat_scalars =
            |v: &[Scalar]| -> Vec<u8> { v.iter().flat_map(|s| s.to_bytes()).collect() };
        // Inputs.
        pins.check_str("pi", &self.pi.to_string());
        pins.check("m", self.message);
        pins.check("p", self.p.to_bytes());
        pins.check("z", self.z.to_bytes());
        pins.check("alpha", self.alpha.to_bytes());
        let simulated: Vec<Scalar> = (0..RING_SIZE)
            .map(|i| {
                if i == self.pi {
                    Scalar::ZERO
                } else {
                    self.s[i]
                }
            })
            .collect();
        pins.check("simulated_s", cat_scalars(&simulated));
        pins.check("ring_P", cat_points(&self.keys));
        pins.check("ring_C", cat_points(&self.commitments));
        pins.check("pseudo_out", enc(&self.pseudo_out));
        // Intermediate values.
        pins.check("Hp", cat_points(&self.hp));
        pins.check("I", enc(&self.key_image));
        pins.check("D", enc(&self.d));
        pins.check("mu_P", self.mu_p.to_bytes());
        pins.check("mu_C", self.mu_c.to_bytes());
        pins.check("W", enc(&self.w));
        pins.check("c", cat_scalars(&self.c));
        // Output.
        pins.check("sig", encode_sig(&self.sig()));
    }
}

/// Accept vectors: the reference signature is accepted by both verifiers, the
/// implementation's key-image helpers agree with the reference, and every
/// value matches its pin.
#[test]
fn accept_vectors() {
    for def in &ACCEPT {
        let v = reference_sign(def);
        let ring = v.ring();
        let real = &ring[v.pi].one_time_key;
        assert_eq!(clsag::key_image_base(real), v.hp[v.pi], "{}", def.name);
        assert_eq!(
            clsag::key_image(&v.p, real),
            Point::from_point(v.key_image),
            "{}",
            def.name
        );
        assert!(!v.d.is_identity(), "{}", def.name);
        assert!(v.verdict_on(&v.sig(), def.name), "{} must verify", def.name);

        let mut pins = Pins::new(FILE, VECTORS, &format!("accept.{}.", def.name));
        v.pin(&mut pins);
        pins.finish();
    }
}

/// The pinned signature bytes (not recomputed) decode canonically and verify
/// against the pinned statement, so the file alone is a usable vector set.
#[test]
fn pinned_bytes_verify() {
    for def in &ACCEPT {
        let pins = Pins::new(FILE, VECTORS, &format!("accept.{}.", def.name));
        let points = |name: &str| -> [Point; RING_SIZE] {
            let b = pins.bytes(name);
            std::array::from_fn(|i| {
                Point::decode(b[32 * i..32 * (i + 1)].try_into().unwrap()).unwrap()
            })
        };
        let point =
            |name: &str| Point::decode(pins.bytes(name).as_slice().try_into().unwrap()).unwrap();
        let (keys, commitments) = (points("ring_P"), points("ring_C"));
        let ring: [RingMember; RING_SIZE] = std::array::from_fn(|i| RingMember {
            one_time_key: keys[i],
            commitment: commitments[i],
        });
        let m: [u8; 32] = pins.bytes("m").try_into().unwrap();
        let sig = decode_sig(&pins.bytes("sig"));
        assert!(
            clsag::verify(&m, &ring, &point("pseudo_out"), &point("I"), &sig),
            "{}",
            def.name
        );
    }
}

/// Reject vectors: single changes of a valid signature or statement (the
/// `pi6` vector). Both verifiers must refuse each one.
#[test]
fn reject_vectors() {
    let v = reference_sign(&ACCEPT[1]);
    let sig = v.sig();
    let pi = v.pi;
    let other_key = wide(0x12);
    let other_point = wide(0x77) * spec::g();
    let mut rejected = 0;
    let mut reject = |ok: bool, what: &str| {
        assert!(!ok, "reject vector accepted: {what}");
        rejected += 1;
    };

    // Tampered responses s.
    for (what, i) in [("s[π] + 1", pi), ("s[π+1] + 1", pi + 1), ("s[0] + 1", 0)] {
        let mut bad = sig.clone();
        bad.s[i] += Scalar::ONE;
        reject(v.verdict_on(&bad, what), what);
    }
    let mut bad = sig.clone();
    bad.s.swap(0, 1);
    reject(v.verdict_on(&bad, "s[0] ↔ s[1]"), "s[0] ↔ s[1]");
    let mut bad = sig.clone();
    bad.s[pi] = -bad.s[pi];
    reject(v.verdict_on(&bad, "−s[π]"), "−s[π]");

    // Tampered challenge: c0 + 1, c0 = 0, and the intermediate c1 placed as c0.
    let mut bad = sig.clone();
    bad.c0 += Scalar::ONE;
    reject(v.verdict_on(&bad, "c0 + 1"), "c0 + 1");
    let mut bad = sig.clone();
    bad.c0 = Scalar::ZERO;
    reject(v.verdict_on(&bad, "c0 = 0"), "c0 = 0");
    let mut bad = sig.clone();
    bad.c0 = v.c[1];
    reject(v.verdict_on(&bad, "c0 := c1"), "c0 := c1");
    // The same with the responses rotated to match (a rotated signature).
    let mut bad = sig.clone();
    bad.c0 = v.c[1];
    bad.s.rotate_left(1);
    reject(v.verdict_on(&bad, "rotated signature"), "rotated signature");

    // Tampered auxiliary image D.
    for (what, d) in [
        ("D = identity", RistrettoPoint::default()),
        ("D + G", v.d + spec::g()),
        ("D = other point", other_point),
        ("D = I", v.key_image),
    ] {
        let mut bad = sig.clone();
        bad.d = Point::from_point(d);
        reject(v.verdict_on(&bad, what), what);
    }

    // Statement changes: key image I, message, ring members, order, pseudo-out.
    let base = v.statement();
    let cases: [(&str, &Change); 12] = [
        ("I = identity", &|st| {
            st.key_image = RistrettoPoint::default()
        }),
        ("I + G", &|st| st.key_image += spec::g()),
        ("I of another key", &|st| {
            st.key_image = other_key * v.hp[pi]
        }),
        ("−I", &|st| st.key_image = -st.key_image),
        ("message", &|st| st.message[31] ^= 0x80),
        ("P[π] replaced", &|st| st.keys[pi] = other_point),
        ("P[decoy] replaced", &|st| st.keys[2] = other_point),
        ("Cr[π] replaced", &|st| st.commitments[pi] = other_point),
        ("Cr[decoy] replaced", &|st| st.commitments[11] = other_point),
        ("members 0 ↔ 1", &|st| {
            st.keys.swap(0, 1);
            st.commitments.swap(0, 1);
        }),
        ("ring rotated", &|st| {
            st.keys.rotate_left(1);
            st.commitments.rotate_left(1);
        }),
        ("C' + G", &|st| st.pseudo_out += spec::g()),
    ];
    for (what, change) in cases {
        let mut st = base;
        change(&mut st);
        reject(verdict(&st, &sig, what), what);
    }

    assert_eq!(rejected, 25);
}

/// The `z = 0` vector: `C' = Cr[π]`, so `D = identity`. The reference values are
/// pinned, and the spec-literal verifier (§6.1 has no `D` rule) accepts it.
#[test]
fn d_identity_vector_values() {
    let v = reference_sign(&D_IDENTITY);
    assert!(v.d.is_identity());
    assert_eq!(v.pseudo_out, v.commitments[v.pi]);
    assert!(reference_verify(&v.statement(), &v.sig()));
    let mut pins = Pins::new(FILE, VECTORS, "reject_pending_cb_b1.d_identity.");
    v.pin(&mut pins);
    pins.finish();
}

/// Finding C1 (dossier 15) / CB-B1: `clsag::verify` rejects `I = identity` but
/// not `D = identity`. This honest-looking signature with `z = 0` reveals the
/// real input (`C' = Cr[π]`), and Monero and monero-oxide refuse it ("Bad
/// auxiliary key image", `ClsagError::InvalidD`). On the base commit it is
/// ACCEPTED, so this test fails; it is ignored until the W1 rule lands, and
/// must then be un-ignored (and the reference verifier above gains the rule).
#[test]
#[ignore = "pending CB-B1: D != identity"]
fn d_identity_is_rejected() {
    let v = reference_sign(&D_IDENTITY);
    let ok = clsag::verify(
        &v.message,
        &v.ring(),
        &Point::from_point(v.pseudo_out),
        &Point::from_point(v.key_image),
        &v.sig(),
    );
    assert!(!ok, "a CLSAG with D = identity must be rejected");
}

/// Regression pin (wallet-side, not consensus): the implementation's own signer
/// on the `pi6` statement with a constant RNG. The hedged nonce stream then
/// depends only on the statement and secrets, so the output is deterministic.
/// A legitimate change of the nonce derivation (spec §10) updates only this pin.
#[test]
fn regression_sign_with_constant_rng() {
    let v = reference_sign(&ACCEPT[1]);
    let ring = v.ring();
    let pseudo_out = Point::from_point(v.pseudo_out);
    let (sig, ki) = clsag::sign(
        &v.message,
        &ring,
        &pseudo_out,
        v.pi,
        &v.p,
        &v.z,
        &mut ZeroRng,
    )
    .expect("valid secrets");
    assert_eq!(ki, Point::from_point(v.key_image));
    assert_eq!(sig.d, Point::from_point(v.d), "D does not depend on nonces");
    assert!(v.verdict_on(&sig, "implementation signature"));
    let again = clsag::sign(
        &v.message,
        &ring,
        &pseudo_out,
        v.pi,
        &v.p,
        &v.z,
        &mut ZeroRng,
    )
    .expect("valid secrets");
    assert_eq!(again.0, sig);

    let mut pins = Pins::new(FILE, VECTORS, "regression.sign_zero_rng.pi6.");
    pins.check("sig", encode_sig(&sig));
    pins.finish();
}
