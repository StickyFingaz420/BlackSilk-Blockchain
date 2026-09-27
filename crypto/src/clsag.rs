//! CLSAG linkable ring signatures and key images (spec §3.4, §6.1).
//!
//! Goodell, Noether, Blue: "Concise Linkable Ring Signatures and Forgery Against
//! Adversarial Keys", IACR ePrint 2019/654. This is the construction Monero has
//! deployed since 2020. Ristretto255 is prime order, so the cofactor handling
//! Monero needs (`D/8`, torsion checks on key images) does not arise.
//!
//! ```text
//! ring        (P[i], Cr[i]), i < 16         one-time keys and commitments
//! C'          pseudo-output commitment
//! Hp_i        = Hp("key-image", P[i])
//! I = p·Hp_π  D = z·Hp_π                     p·G = P[π], z·G = Cr[π] − C'
//! μP, μC      = Hs("clsag/agg-P" | "clsag/agg-C", ring ‖ I ‖ D ‖ C')
//! c[i+1]      = Hs("clsag/round", ring ‖ C' ‖ m ‖ L_i ‖ R_i)
//! L_i         = s_i·G    + c_i·(μP·P[i] + μC·(Cr[i] − C'))
//! R_i         = s_i·Hp_i + c_i·(μP·I    + μC·D)
//! ```

use crate::hash::{hash_to_point, tags, Hasher64};
use crate::nonce::HedgedRng;
use crate::point::Point;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Ring size, fixed by consensus (spec §4.2).
pub const RING_SIZE: usize = 16;

/// Encoded size: `c0`, 16 × `s`, `D`.
pub const CLSAG_BYTES: usize = 32 * (RING_SIZE + 2);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Clsag {
    pub c0: Scalar,
    pub s: [Scalar; RING_SIZE],
    pub d: Point,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingMember {
    pub one_time_key: Point,
    pub commitment: Point,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClsagError {
    RealIndexOutOfRange,
    /// `p·G ≠ P[π]`: the signer does not own the real member.
    WrongSpendSecret,
    /// `z·G ≠ Cr[π] − C'`: the pseudo-output does not match the real input.
    WrongCommitmentSecret,
    /// `z = 0`: the pseudo-output equals the real member's commitment, so
    /// `D` would be the identity (rejected by `verify`) and `C' = Cr[π]`
    /// would reveal the real input (dossier 15 W1). The builder draws
    /// pseudo-output masks at random, so this is a wallet bug.
    ZeroCommitmentSecret,
}

/// `Hp("key-image", P)`.
pub fn key_image_base(one_time_key: &Point) -> RistrettoPoint {
    hash_to_point(tags::KEY_IMAGE, &[one_time_key.bytes()])
}

/// `I = p·Hp("key-image", P)`, the unique key image of the output `P = p·G`.
pub fn key_image(spend_secret: &Scalar, one_time_key: &Point) -> Point {
    Point::from_point(spend_secret * key_image_base(one_time_key))
}

/// Hashing context shared by signing and verification.
struct Transcript {
    round: Hasher64,
    mu_p: Scalar,
    mu_c: Scalar,
}

impl Transcript {
    fn new(
        ring: &[RingMember; RING_SIZE],
        pseudo_out: &Point,
        key_image: &Point,
        d: &Point,
        message: &[u8; 32],
    ) -> Self {
        let ring_hash = |tag: &str| {
            let mut h = Hasher64::new(tag);
            for m in ring {
                h.update(m.one_time_key.bytes());
            }
            for m in ring {
                h.update(m.commitment.bytes());
            }
            h
        };
        let agg = |tag: &str| {
            ring_hash(tag)
                .chain(key_image.bytes())
                .chain(d.bytes())
                .chain(pseudo_out.bytes())
                .to_scalar()
        };
        let mu_p = agg(tags::CLSAG_AGG_P);
        let mu_c = agg(tags::CLSAG_AGG_C);
        let round = ring_hash(tags::CLSAG_ROUND)
            .chain(pseudo_out.bytes())
            .chain(message);
        Self { round, mu_p, mu_c }
    }

    fn challenge(&self, l: &RistrettoPoint, r: &RistrettoPoint) -> Scalar {
        self.round
            .clone()
            .chain(l.compress().as_bytes())
            .chain(r.compress().as_bytes())
            .to_scalar()
    }
}

/// Purpose label of the CLSAG nonce stream (spec §10). Wallet-side only: it
/// is never hashed by the verifier, so changing it does not affect validity.
const NONCE_LABEL: &[u8] = b"clsag/nonce/v2";

/// The hedged stream that yields `α` and the simulated responses `s[i]`
/// (spec §10, internal review round 5 finding F2).
///
/// Secrets: `p`, `z`. Public context: the label, `m`, `C'`, `I`, `D`,
/// `LE64(π)`, `P[0] ‖ … ‖ P[15]` and `Cr[0] ‖ … ‖ Cr[15]`. Every input of the
/// signing transcript is bound, so any change of the statement being signed
/// (in particular the same message over a different ring, e.g. after a reorg
/// re-resolves the same global indices) changes every nonce even when the
/// CSPRNG is constant. The previous derivation bound only `m`, `C'` and `P[π]`.
fn nonce_stream<R: RngCore + CryptoRng>(
    message: &[u8; 32],
    ring: &[RingMember; RING_SIZE],
    pseudo_out: &Point,
    (key_image, d): (&Point, &Point),
    real_index: usize,
    (spend_secret, commitment_secret): (&Scalar, &Scalar),
    rng: &mut R,
) -> HedgedRng {
    let mut ring_p = [0u8; 32 * RING_SIZE];
    let mut ring_c = [0u8; 32 * RING_SIZE];
    for (i, m) in ring.iter().enumerate() {
        ring_p[32 * i..32 * (i + 1)].copy_from_slice(m.one_time_key.bytes());
        ring_c[32 * i..32 * (i + 1)].copy_from_slice(m.commitment.bytes());
    }
    // The real index is secret too; it goes into the (hashed, never published)
    // context only. The context list order is fixed and every item is
    // length-prefixed by `HedgedRng`, so the encoding is unambiguous.
    let mut index = (real_index as u64).to_le_bytes();
    let mut p_bytes = spend_secret.to_bytes();
    let mut z_bytes = commitment_secret.to_bytes();
    let stream = HedgedRng::new(
        &[&p_bytes, &z_bytes],
        &[
            NONCE_LABEL,
            message,
            pseudo_out.bytes(),
            key_image.bytes(),
            d.bytes(),
            &index,
            &ring_p,
            &ring_c,
        ],
        rng,
    );
    p_bytes.zeroize();
    z_bytes.zeroize();
    index.zeroize();
    stream
}

/// Signs `message` with the ring member at `real_index` (spec §6.1).
///
/// `spend_secret` is `p` with `p·G = P[π]`; `commitment_secret` is `z` with
/// `z·G = Cr[π] − C'`. Returns the signature and the key image. The secrets are
/// checked first, so a wallet bug cannot produce a signature that leaks them.
pub fn sign<R: RngCore + CryptoRng>(
    message: &[u8; 32],
    ring: &[RingMember; RING_SIZE],
    pseudo_out: &Point,
    real_index: usize,
    spend_secret: &Scalar,
    commitment_secret: &Scalar,
    rng: &mut R,
) -> Result<(Clsag, Point), ClsagError> {
    sign_with(
        message,
        ring,
        pseudo_out,
        real_index,
        spend_secret,
        commitment_secret,
        |key_image, d| {
            nonce_stream(
                message,
                ring,
                pseudo_out,
                (key_image, d),
                real_index,
                (spend_secret, commitment_secret),
                rng,
            )
        },
    )
}

/// The signing algorithm with the nonce stream supplied by `nonces(I, D)`.
/// Kept separate so tests can reproduce the pre-F2 derivation.
fn sign_with(
    message: &[u8; 32],
    ring: &[RingMember; RING_SIZE],
    pseudo_out: &Point,
    real_index: usize,
    spend_secret: &Scalar,
    commitment_secret: &Scalar,
    nonces: impl FnOnce(&Point, &Point) -> HedgedRng,
) -> Result<(Clsag, Point), ClsagError> {
    if real_index >= RING_SIZE {
        return Err(ClsagError::RealIndexOutOfRange);
    }
    let real = &ring[real_index];
    let expected_p = Point::from_point(RistrettoPoint::mul_base(spend_secret));
    if !bool::from(expected_p.bytes().ct_eq(real.one_time_key.bytes())) {
        return Err(ClsagError::WrongSpendSecret);
    }
    let offset = real.commitment.point() - pseudo_out.point();
    if RistrettoPoint::mul_base(commitment_secret) != offset {
        return Err(ClsagError::WrongCommitmentSecret);
    }
    if bool::from(commitment_secret.ct_eq(&Scalar::ZERO)) {
        return Err(ClsagError::ZeroCommitmentSecret);
    }

    let hp_real = key_image_base(&real.one_time_key);
    let key_image = Point::from_point(spend_secret * hp_real);
    let d = Point::from_point(commitment_secret * hp_real);
    let t = Transcript::new(ring, pseudo_out, &key_image, &d, message);
    let w = t.mu_p * key_image.point() + t.mu_c * d.point();

    let mut nonces = nonces(&key_image, &d);

    let mut alpha = nonces.scalar();
    let mut c = [Scalar::ZERO; RING_SIZE];
    let mut s = [Scalar::ZERO; RING_SIZE];
    let mut i = (real_index + 1) % RING_SIZE;
    c[i] = t.challenge(&RistrettoPoint::mul_base(&alpha), &(alpha * hp_real));
    while i != real_index {
        s[i] = nonces.scalar();
        let member = &ring[i];
        let l = RistrettoPoint::mul_base(&s[i])
            + c[i]
                * (t.mu_p * member.one_time_key.point()
                    + t.mu_c * (member.commitment.point() - pseudo_out.point()));
        let r = s[i] * key_image_base(&member.one_time_key) + c[i] * w;
        let next = (i + 1) % RING_SIZE;
        c[next] = t.challenge(&l, &r);
        i = next;
    }
    s[real_index] = alpha - c[real_index] * (t.mu_p * spend_secret + t.mu_c * commitment_secret);
    alpha.zeroize();

    Ok((Clsag { c0: c[0], s, d }, key_image))
}

/// Verifies a CLSAG over `ring`, `pseudo_out`, `key_image` and `message`.
pub fn verify(
    message: &[u8; 32],
    ring: &[RingMember; RING_SIZE],
    pseudo_out: &Point,
    key_image: &Point,
    sig: &Clsag,
) -> bool {
    // `I ≠ identity` (the linking tag) and `D ≠ identity` (the auxiliary
    // image, as Monero's "bad auxiliary key image" check and monero-oxide's
    // `InvalidD`; dossier 15 W1). An honest `D` is `z·Hp(P[π])` with `z ≠ 0`.
    if key_image.is_identity() || sig.d.is_identity() {
        return false;
    }
    let t = Transcript::new(ring, pseudo_out, key_image, &sig.d, message);
    let w = t.mu_p * key_image.point() + t.mu_c * sig.d.point();
    let mut c = sig.c0;
    for (member, s) in ring.iter().zip(&sig.s) {
        let offset = member.commitment.point() - pseudo_out.point();
        let l = RistrettoPoint::vartime_multiscalar_mul(
            [*s, c * t.mu_p, c * t.mu_c],
            [G, *member.one_time_key.point(), offset],
        );
        let r = RistrettoPoint::vartime_multiscalar_mul(
            [*s, c],
            [key_image_base(&member.one_time_key), w],
        );
        c = t.challenge(&l, &r);
    }
    bool::from(c.ct_eq(&sig.c0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::commit;
    use crate::nonce::test_rng::{seeded, ChaCha20Rng, ZeroRng};

    fn random_scalar(rng: &mut impl RngCore) -> Scalar {
        let mut wide = [0u8; 64];
        rng.fill_bytes(&mut wide);
        Scalar::from_bytes_mod_order_wide(&wide)
    }

    struct Fixture {
        ring: [RingMember; RING_SIZE],
        pseudo_out: Point,
        real: usize,
        p: Scalar,
        z: Scalar,
        message: [u8; 32],
    }

    fn fixture(rng: &mut ChaCha20Rng, real: usize) -> Fixture {
        let p = random_scalar(rng);
        let mask = random_scalar(rng);
        fixture_with(rng, real, p, mask)
    }

    /// A ring whose real member is the output `(p·G, commit(1000, mask))`.
    fn fixture_with(rng: &mut ChaCha20Rng, real: usize, p: Scalar, mask: Scalar) -> Fixture {
        let amount = 1_000u64;
        let pseudo_mask = random_scalar(rng);
        let mut ring = [RingMember {
            one_time_key: Point::from_point(G),
            commitment: Point::from_point(G),
        }; RING_SIZE];
        for (i, m) in ring.iter_mut().enumerate() {
            if i == real {
                m.one_time_key = Point::from_point(RistrettoPoint::mul_base(&p));
                m.commitment = Point::from_point(commit(amount, &mask));
            } else {
                m.one_time_key = Point::from_point(RistrettoPoint::mul_base(&random_scalar(rng)));
                m.commitment = Point::from_point(commit(rng.next_u64(), &random_scalar(rng)));
            }
        }
        let mut message = [0u8; 32];
        rng.fill_bytes(&mut message);
        Fixture {
            ring,
            pseudo_out: Point::from_point(commit(amount, &pseudo_mask)),
            real,
            p,
            z: mask - pseudo_mask,
            message,
        }
    }

    fn sign_fixture(f: &Fixture, rng: &mut ChaCha20Rng) -> (Clsag, Point) {
        sign(&f.message, &f.ring, &f.pseudo_out, f.real, &f.p, &f.z, rng).unwrap()
    }

    #[test]
    fn signs_and_verifies_at_every_index() {
        let mut rng = seeded(200);
        for real in 0..RING_SIZE {
            let f = fixture(&mut rng, real);
            let (sig, ki) = sign_fixture(&f, &mut rng);
            assert!(
                verify(&f.message, &f.ring, &f.pseudo_out, &ki, &sig),
                "index {real}"
            );
            assert_eq!(ki, key_image(&f.p, &f.ring[real].one_time_key));
        }
    }

    #[test]
    fn any_modification_invalidates() {
        let mut rng = seeded(201);
        let f = fixture(&mut rng, 5);
        let (sig, ki) = sign_fixture(&f, &mut rng);
        let other = Point::from_point(RistrettoPoint::mul_base(&random_scalar(&mut rng)));

        let mut m = f.message;
        m[0] ^= 1;
        assert!(!verify(&m, &f.ring, &f.pseudo_out, &ki, &sig), "message");
        for i in 0..RING_SIZE {
            let mut ring = f.ring;
            ring[i].one_time_key = other;
            assert!(
                !verify(&f.message, &ring, &f.pseudo_out, &ki, &sig),
                "key {i}"
            );
            let mut ring = f.ring;
            ring[i].commitment = other;
            assert!(
                !verify(&f.message, &ring, &f.pseudo_out, &ki, &sig),
                "commitment {i}"
            );
            let mut bad = sig.clone();
            bad.s[i] += Scalar::ONE;
            assert!(
                !verify(&f.message, &f.ring, &f.pseudo_out, &ki, &bad),
                "s {i}"
            );
        }
        // Ring order is part of the statement.
        let mut ring = f.ring;
        ring.swap(0, 1);
        assert!(
            !verify(&f.message, &ring, &f.pseudo_out, &ki, &sig),
            "order"
        );
        assert!(
            !verify(&f.message, &f.ring, &other, &ki, &sig),
            "pseudo-out"
        );
        assert!(
            !verify(&f.message, &f.ring, &f.pseudo_out, &other, &sig),
            "key image"
        );
        let mut bad = sig.clone();
        bad.c0 += Scalar::ONE;
        assert!(!verify(&f.message, &f.ring, &f.pseudo_out, &ki, &bad), "c0");
        let mut bad = sig.clone();
        bad.d = other;
        assert!(!verify(&f.message, &f.ring, &f.pseudo_out, &ki, &bad), "D");
    }

    #[test]
    fn identity_key_image_is_rejected() {
        let mut rng = seeded(202);
        let f = fixture(&mut rng, 0);
        let (sig, _) = sign_fixture(&f, &mut rng);
        let id = Point::decode(&[0; 32]).unwrap();
        assert!(!verify(&f.message, &f.ring, &f.pseudo_out, &id, &sig));
    }

    #[test]
    fn key_images_link_spends_of_the_same_output() {
        let mut rng = seeded(203);
        // One output (p, mask), spent in two unrelated rings at different positions
        // with different pseudo-outputs and messages.
        let p = random_scalar(&mut rng);
        let mask = random_scalar(&mut rng);
        let f1 = fixture_with(&mut rng, 3, p, mask);
        let f2 = fixture_with(&mut rng, 9, p, mask);
        assert_ne!(f1.pseudo_out, f2.pseudo_out);
        let (s1, ki1) = sign_fixture(&f1, &mut rng);
        let (s2, ki2) = sign_fixture(&f2, &mut rng);
        assert!(verify(&f1.message, &f1.ring, &f1.pseudo_out, &ki1, &s1));
        assert!(verify(&f2.message, &f2.ring, &f2.pseudo_out, &ki2, &s2));
        assert_eq!(ki1, ki2, "same output -> same key image");
        // A different output of the same owner has a different key image.
        let p3 = random_scalar(&mut rng);
        let f3 = fixture_with(&mut rng, 3, p3, mask);
        assert_ne!(sign_fixture(&f3, &mut rng).1, ki1);
    }

    #[test]
    fn wrong_secrets_are_refused_by_the_signer() {
        let mut rng = seeded(204);
        let f = fixture(&mut rng, 2);
        let wrong = random_scalar(&mut rng);
        assert_eq!(
            sign(
                &f.message,
                &f.ring,
                &f.pseudo_out,
                2,
                &wrong,
                &f.z,
                &mut rng
            )
            .unwrap_err(),
            ClsagError::WrongSpendSecret
        );
        assert_eq!(
            sign(
                &f.message,
                &f.ring,
                &f.pseudo_out,
                2,
                &f.p,
                &wrong,
                &mut rng
            )
            .unwrap_err(),
            ClsagError::WrongCommitmentSecret
        );
        assert_eq!(
            sign(&f.message, &f.ring, &f.pseudo_out, 3, &f.p, &f.z, &mut rng).unwrap_err(),
            ClsagError::WrongSpendSecret
        );
        assert_eq!(
            sign(&f.message, &f.ring, &f.pseudo_out, 16, &f.p, &f.z, &mut rng).unwrap_err(),
            ClsagError::RealIndexOutOfRange
        );
    }

    /// A pseudo-output that commits to a different amount than the real input
    /// cannot be signed for, even by the owner (this is what enforces balance).
    #[test]
    fn amount_mismatch_cannot_be_signed() {
        let mut rng = seeded(205);
        let f = fixture(&mut rng, 7);
        let inflated = Point::from_point(f.pseudo_out.point() + commit(1, &Scalar::ZERO));
        // With the original z, the commitment check fails...
        assert!(sign(&f.message, &f.ring, &inflated, 7, &f.p, &f.z, &mut rng).is_err());
        // ...and a forged signature (made for the honest pseudo-out) does not verify.
        let (sig, ki) = sign_fixture(&f, &mut rng);
        assert!(!verify(&f.message, &f.ring, &inflated, &ki, &sig));
    }

    /// Finding C1 (dossier 15 W1): `z = 0` (the pseudo-output equals the real
    /// member's commitment) would give `D = identity` and reveal the real
    /// input; `sign` refuses it, and `verify` rejects `D = identity`.
    #[test]
    fn a_zero_commitment_secret_is_refused() {
        let mut rng = seeded(207);
        let f = fixture(&mut rng, 5);
        let real_commitment = f.ring[5].commitment;
        let r = sign(
            &f.message,
            &f.ring,
            &real_commitment,
            5,
            &f.p,
            &Scalar::ZERO,
            &mut rng,
        );
        assert_eq!(r.map(|_| ()), Err(ClsagError::ZeroCommitmentSecret));
        // Honest signatures are unaffected; an identity `D` never verifies.
        let (mut sig, ki) = sign_fixture(&f, &mut rng);
        assert!(verify(&f.message, &f.ring, &f.pseudo_out, &ki, &sig));
        sig.d = Point::from_point(RistrettoPoint::default());
        assert!(!verify(&f.message, &f.ring, &f.pseudo_out, &ki, &sig));
    }

    /// Forgery attempt without any secret: random responses never verify.
    #[test]
    fn keyless_forgery_fails() {
        let mut rng = seeded(206);
        let f = fixture(&mut rng, 0);
        for _ in 0..8 {
            let sig = Clsag {
                c0: random_scalar(&mut rng),
                s: std::array::from_fn(|_| random_scalar(&mut rng)),
                d: Point::from_point(RistrettoPoint::mul_base(&random_scalar(&mut rng))),
            };
            let ki = Point::from_point(RistrettoPoint::mul_base(&random_scalar(&mut rng)));
            assert!(!verify(&f.message, &f.ring, &f.pseudo_out, &ki, &sig));
        }
    }

    /// Anonymity sanity check: the signature does not reveal the index through
    /// any obvious structural difference (all responses are non-zero and distinct).
    #[test]
    fn responses_look_uniform() {
        let mut rng = seeded(207);
        let f = fixture(&mut rng, 11);
        let (sig, _) = sign_fixture(&f, &mut rng);
        for (i, s) in sig.s.iter().enumerate() {
            assert_ne!(*s, Scalar::ZERO, "s[{i}]");
            for t in &sig.s[i + 1..] {
                assert_ne!(s, t);
            }
        }
    }

    /// With a completely broken RNG, signing two different messages with the same
    /// key still uses different nonces (hedging), so the key is not leaked.
    #[test]
    fn broken_rng_does_not_reuse_nonces() {
        let mut rng = seeded(208);
        let f = fixture(&mut rng, 4);
        let (s1, _) = sign(
            &f.message,
            &f.ring,
            &f.pseudo_out,
            4,
            &f.p,
            &f.z,
            &mut ZeroRng,
        )
        .unwrap();
        let (s2, _) = sign(
            &[0xAB; 32],
            &f.ring,
            &f.pseudo_out,
            4,
            &f.p,
            &f.z,
            &mut ZeroRng,
        )
        .unwrap();
        assert!(verify(
            &f.message,
            &f.ring,
            &f.pseudo_out,
            &key_image(&f.p, &f.ring[4].one_time_key),
            &s1
        ));
        // Different messages: every simulated response differs.
        for i in 0..RING_SIZE {
            if i != 4 {
                assert_ne!(s1.s[i], s2.s[i]);
            }
        }
    }

    /// Property test over random rings, positions and messages.
    #[test]
    fn property_random_rings() {
        let mut rng = seeded(209);
        for _ in 0..24 {
            let real = (rng.next_u32() % RING_SIZE as u32) as usize;
            let f = fixture(&mut rng, real);
            let (sig, ki) = sign_fixture(&f, &mut rng);
            assert!(verify(&f.message, &f.ring, &f.pseudo_out, &ki, &sig));
            let mut m = f.message;
            m[(rng.next_u32() % 32) as usize] ^= 1 << (rng.next_u32() % 8);
            assert!(!verify(&m, &f.ring, &f.pseudo_out, &ki, &sig));
        }
    }

    // ---- F2 (internal review round 5): nonce binding ------------------------

    fn fixture_clone(f: &Fixture) -> Fixture {
        Fixture {
            ring: f.ring,
            pseudo_out: f.pseudo_out,
            real: f.real,
            p: f.p,
            z: f.z,
            message: f.message,
        }
    }

    /// First `n` values of the CLSAG nonce stream for `f` under `rng`.
    fn stream_of(
        f: &Fixture,
        key_image: &Point,
        d: &Point,
        rng: &mut (impl RngCore + CryptoRng),
        n: usize,
    ) -> Vec<Scalar> {
        let mut h = nonce_stream(
            &f.message,
            &f.ring,
            &f.pseudo_out,
            (key_image, d),
            f.real,
            (&f.p, &f.z),
            rng,
        );
        (0..n).map(|_| h.scalar()).collect()
    }

    fn images(f: &Fixture) -> (Point, Point) {
        let hp = key_image_base(&f.ring[f.real].one_time_key);
        (Point::from_point(f.p * hp), Point::from_point(f.z * hp))
    }

    /// The pre-F2 derivation, reproduced for regression tests only.
    fn old_stream(f: &Fixture, rng: &mut (impl RngCore + CryptoRng)) -> HedgedRng {
        HedgedRng::new(
            &[&f.p.to_bytes(), &f.z.to_bytes()],
            &[
                b"clsag",
                &f.message,
                f.pseudo_out.bytes(),
                f.ring[f.real].one_time_key.bytes(),
            ],
            rng,
        )
    }

    /// `(c[π], μP, μC)` recomputed from public data only (what an observer can do).
    fn public_challenge(
        message: &[u8; 32],
        ring: &[RingMember; RING_SIZE],
        pseudo_out: &Point,
        key_image: &Point,
        sig: &Clsag,
        index: usize,
    ) -> (Scalar, Scalar, Scalar) {
        let t = Transcript::new(ring, pseudo_out, key_image, &sig.d, message);
        let w = t.mu_p * key_image.point() + t.mu_c * sig.d.point();
        let mut c = sig.c0;
        for (member, s) in ring.iter().zip(&sig.s).take(index) {
            let l = RistrettoPoint::mul_base(s)
                + c * (t.mu_p * member.one_time_key.point()
                    + t.mu_c * (member.commitment.point() - pseudo_out.point()));
            let r = s * key_image_base(&member.one_time_key) + c * w;
            c = t.challenge(&l, &r);
        }
        (c, t.mu_p, t.mu_c)
    }

    /// `α = s[π] + c[π]·(μP·p + μC·z)`, recovered with the secrets.
    fn recover_alpha(f: &Fixture, key_image: &Point, sig: &Clsag) -> Scalar {
        let (c, mu_p, mu_c) =
            public_challenge(&f.message, &f.ring, &f.pseudo_out, key_image, sig, f.real);
        sig.s[f.real] + c * (mu_p * f.p + mu_c * f.z)
    }

    fn random_point(rng: &mut ChaCha20Rng) -> Point {
        Point::from_point(RistrettoPoint::mul_base(&random_scalar(rng)))
    }

    fn sign_zero(g: &Fixture) -> (Clsag, Point) {
        sign(
            &g.message,
            &g.ring,
            &g.pseudo_out,
            g.real,
            &g.p,
            &g.z,
            &mut ZeroRng,
        )
        .unwrap()
    }

    /// Every public and secret input of the signing transcript is bound: changing
    /// any single one of them changes every value of the stream, even when the
    /// CSPRNG is constant.
    #[test]
    fn nonce_stream_binds_every_transcript_input() {
        const N: usize = RING_SIZE;
        let mut rng = seeded(210);
        let f = fixture(&mut rng, 4);
        let (ki, d) = images(&f);
        let base = stream_of(&f, &ki, &d, &mut ZeroRng, N);
        // Deterministic when everything is equal.
        assert_eq!(base, stream_of(&f, &ki, &d, &mut ZeroRng, N));

        let other = random_point(&mut rng);
        let mut variants: Vec<(String, Vec<Scalar>)> = Vec::new();
        for i in 0..RING_SIZE {
            let mut g = fixture_clone(&f);
            g.ring[i].one_time_key = other;
            variants.push((format!("P[{i}]"), stream_of(&g, &ki, &d, &mut ZeroRng, N)));
            let mut g = fixture_clone(&f);
            g.ring[i].commitment = other;
            variants.push((format!("C[{i}]"), stream_of(&g, &ki, &d, &mut ZeroRng, N)));
        }
        let mut g = fixture_clone(&f);
        g.ring.swap(0, 1);
        variants.push(("ring order".into(), stream_of(&g, &ki, &d, &mut ZeroRng, N)));
        let mut g = fixture_clone(&f);
        g.message[31] ^= 1;
        variants.push(("message".into(), stream_of(&g, &ki, &d, &mut ZeroRng, N)));
        let mut g = fixture_clone(&f);
        g.pseudo_out = other;
        variants.push(("C'".into(), stream_of(&g, &ki, &d, &mut ZeroRng, N)));
        variants.push(("I".into(), stream_of(&f, &other, &d, &mut ZeroRng, N)));
        variants.push(("D".into(), stream_of(&f, &ki, &other, &mut ZeroRng, N)));
        let mut g = fixture_clone(&f);
        g.real = 5;
        variants.push(("index".into(), stream_of(&g, &ki, &d, &mut ZeroRng, N)));
        let mut g = fixture_clone(&f);
        g.p += Scalar::ONE;
        variants.push(("p".into(), stream_of(&g, &ki, &d, &mut ZeroRng, N)));
        let mut g = fixture_clone(&f);
        g.z += Scalar::ONE;
        variants.push(("z".into(), stream_of(&g, &ki, &d, &mut ZeroRng, N)));
        assert_eq!(variants.len(), 2 * RING_SIZE + 8);

        let mut seen = std::collections::HashSet::new();
        seen.insert(base[0].to_bytes());
        for (name, stream) in &variants {
            for k in 0..N {
                assert_ne!(stream[k], base[k], "{name}: value {k} unchanged");
            }
            assert!(seen.insert(stream[0].to_bytes()), "{name}: alpha collides");
        }
    }

    /// The F2 scenario: the same message, key and pseudo-output signed over rings
    /// that differ only in one decoy (a reorg re-resolving the same global
    /// indices). With a constant RNG the nonces must still differ, both
    /// signatures verify with the unchanged verifier, and neither can be
    /// replayed on the other ring.
    #[test]
    fn broken_rng_ring_change_alone_changes_nonces() {
        let mut rng = seeded(211);
        let f = fixture(&mut rng, 4);
        let (s1, ki) = sign_zero(&f);
        assert_eq!(ki, key_image(&f.p, &f.ring[4].one_time_key));
        assert!(verify(&f.message, &f.ring, &f.pseudo_out, &ki, &s1));
        let a1 = recover_alpha(&f, &ki, &s1);

        let other = random_point(&mut rng);
        for (decoy, field) in [(0, 'P'), (9, 'C'), (15, 'P'), (5, 'C')] {
            let mut g = fixture_clone(&f);
            match field {
                'P' => g.ring[decoy].one_time_key = other,
                _ => g.ring[decoy].commitment = other,
            }
            let (s2, k2) = sign_zero(&g);
            assert_eq!(k2, ki, "same output, same key image");
            assert_eq!(s2.d, s1.d, "same z and P[π], same D");
            assert!(verify(&g.message, &g.ring, &g.pseudo_out, &ki, &s2));
            let a2 = recover_alpha(&g, &ki, &s2);
            assert_ne!(a2, a1, "{field}[{decoy}]: alpha reused");
            for i in 0..RING_SIZE {
                assert_ne!(s1.s[i], s2.s[i], "{field}[{decoy}]: s[{i}]");
            }
            // Replay across rings fails.
            assert!(!verify(&f.message, &f.ring, &f.pseudo_out, &ki, &s2));
            assert!(!verify(&g.message, &g.ring, &g.pseudo_out, &ki, &s1));
        }
    }

    /// Changing only the message, only the spent output (so a different I), or
    /// only z (so a different D) changes α under a constant RNG; signatures
    /// moved to another statement fail.
    #[test]
    fn broken_rng_message_key_image_and_d_change_nonces() {
        let mut rng = seeded(212);
        let mask = random_scalar(&mut rng);
        let p = random_scalar(&mut rng);
        let f = fixture_with(&mut rng, 7, p, mask);
        let (s1, k1) = sign_zero(&f);
        let a1 = recover_alpha(&f, &k1, &s1);

        // Message only.
        let mut g = fixture_clone(&f);
        g.message[0] ^= 0x80;
        let (s2, k2) = sign_zero(&g);
        assert_eq!(k2, k1);
        assert!(verify(&g.message, &g.ring, &g.pseudo_out, &k2, &s2));
        assert_ne!(recover_alpha(&g, &k2, &s2), a1, "message");
        assert!(!verify(&f.message, &f.ring, &f.pseudo_out, &k1, &s2));

        // Key image: another output of the owner at the same position.
        let mut g = fixture_clone(&f);
        g.p = random_scalar(&mut rng);
        g.ring[7].one_time_key = Point::from_point(RistrettoPoint::mul_base(&g.p));
        let (s3, k3) = sign_zero(&g);
        assert_ne!(k3, k1);
        assert!(verify(&g.message, &g.ring, &g.pseudo_out, &k3, &s3));
        assert_ne!(recover_alpha(&g, &k3, &s3), a1, "key image");
        assert!(!verify(&g.message, &g.ring, &g.pseudo_out, &k1, &s3));

        // D: same C', different real commitment mask, so a different z.
        let mut g = fixture_clone(&f);
        g.ring[7].commitment = Point::from_point(commit(1_000, &(mask + Scalar::ONE)));
        g.z = f.z + Scalar::ONE;
        let (s4, k4) = sign_zero(&g);
        assert_eq!(k4, k1);
        assert_ne!(s4.d, s1.d);
        assert!(verify(&g.message, &g.ring, &g.pseudo_out, &k4, &s4));
        assert_ne!(recover_alpha(&g, &k4, &s4), a1, "D");
    }

    /// Regression demonstration of F2. With the pre-F2 derivation and a constant
    /// RNG, three signatures of one message over three rings that share the real
    /// member reuse α. The differences `s_1[π] − s_j[π]` are linear in `(p, z)`,
    /// so public data alone recovers the spend key. The corrected derivation
    /// defeats the same attack.
    #[test]
    fn pre_f2_derivation_leaks_the_spend_key_and_fix_prevents_it() {
        let mut rng = seeded(213);
        let base = fixture(&mut rng, 3);
        let mut rings = vec![fixture_clone(&base)];
        for _ in 0..2 {
            let mut g = fixture_clone(&base);
            for i in (0..RING_SIZE).filter(|&i| i != 3) {
                g.ring[i].one_time_key = random_point(&mut rng);
                g.ring[i].commitment = random_point(&mut rng);
            }
            rings.push(g);
        }

        // Attacker: public data only (message, rings, C', I, signatures, π).
        let attack = |sigs: &[(Clsag, Point)]| -> Scalar {
            let eq: Vec<(Scalar, Scalar, Scalar)> = sigs
                .iter()
                .zip(&rings)
                .map(|((sig, ki), g)| {
                    let (c, mp, mc) =
                        public_challenge(&g.message, &g.ring, &g.pseudo_out, ki, sig, 3);
                    (c * mp, c * mc, sig.s[3])
                })
                .collect();
            // s_1 − s_j = a_j·p + b_j·z, a_j = c_jμP_j − c_1μP_1, b_j likewise.
            let (a2, b2, e2) = (eq[1].0 - eq[0].0, eq[1].1 - eq[0].1, eq[0].2 - eq[1].2);
            let (a3, b3, e3) = (eq[2].0 - eq[0].0, eq[2].1 - eq[0].1, eq[0].2 - eq[2].2);
            (e2 * b3 - e3 * b2) * (a2 * b3 - a3 * b2).invert()
        };

        let old: Vec<(Clsag, Point)> = rings
            .iter()
            .map(|g| {
                sign_with(&g.message, &g.ring, &g.pseudo_out, 3, &g.p, &g.z, |_, _| {
                    old_stream(g, &mut ZeroRng)
                })
                .unwrap()
            })
            .collect();
        for ((sig, ki), g) in old.iter().zip(&rings) {
            assert!(verify(&g.message, &g.ring, &g.pseudo_out, ki, sig));
        }
        assert_eq!(attack(&old), base.p, "pre-F2 nonce reuse leaks p");

        let new: Vec<(Clsag, Point)> = rings.iter().map(sign_zero).collect();
        for ((sig, ki), g) in new.iter().zip(&rings) {
            assert!(verify(&g.message, &g.ring, &g.pseudo_out, ki, sig));
        }
        assert_ne!(attack(&new), base.p, "corrected derivation must not leak p");
    }

    /// The purpose label separates the CLSAG stream from any other hedged stream
    /// over the same secrets and data, including the pre-F2 label.
    #[test]
    fn nonce_label_domain_separation() {
        let mut rng = seeded(214);
        let f = fixture(&mut rng, 2);
        let (ki, d) = images(&f);
        let alpha = stream_of(&f, &ki, &d, &mut ZeroRng, 1)[0];
        let mut ring_p = Vec::new();
        let mut ring_c = Vec::new();
        for m in &f.ring {
            ring_p.extend_from_slice(m.one_time_key.bytes());
            ring_c.extend_from_slice(m.commitment.bytes());
        }
        let index = (f.real as u64).to_le_bytes();
        let with_label = |label: &[u8]| {
            HedgedRng::new(
                &[&f.p.to_bytes(), &f.z.to_bytes()],
                &[
                    label,
                    &f.message,
                    f.pseudo_out.bytes(),
                    ki.bytes(),
                    d.bytes(),
                    &index,
                    &ring_p,
                    &ring_c,
                ],
                &mut ZeroRng,
            )
            .scalar()
        };
        assert_eq!(with_label(NONCE_LABEL), alpha, "layout as documented");
        for label in [
            &b"clsag"[..],
            b"clsag/nonce/v1",
            b"transfer",
            b"coinbase",
            b"",
        ] {
            assert_ne!(
                with_label(label),
                alpha,
                "{}",
                String::from_utf8_lossy(label)
            );
        }
        assert_ne!(old_stream(&f, &mut ZeroRng).scalar(), alpha);
    }

    /// Fixed secrets, ring and message; constant RNG. Pins the derivation of the
    /// first nonce and the full signature, so any change to either is detected.
    #[test]
    fn nonce_and_signature_test_vector() {
        let wide = |b: u8| Scalar::from_bytes_mod_order_wide(&[b; 64]);
        let real = 6;
        let p = wide(0x11);
        let mask = wide(0x22);
        let pseudo_mask = wide(0x33);
        let ring: [RingMember; RING_SIZE] = std::array::from_fn(|i| {
            let (key, commitment) = if i == real {
                (p, commit(1_000, &mask))
            } else {
                (
                    wide(0x40 + i as u8),
                    commit(1_000 + i as u64, &wide(0x60 + i as u8)),
                )
            };
            RingMember {
                one_time_key: Point::from_point(RistrettoPoint::mul_base(&key)),
                commitment: Point::from_point(commitment),
            }
        });
        let f = Fixture {
            ring,
            pseudo_out: Point::from_point(commit(1_000, &pseudo_mask)),
            real,
            p,
            z: mask - pseudo_mask,
            message: [0x5a; 32],
        };
        let (ki, d) = images(&f);
        let alpha = stream_of(&f, &ki, &d, &mut ZeroRng, 1)[0];
        let (sig, k) = sign_zero(&f);
        assert_eq!(k, ki);
        assert!(verify(&f.message, &f.ring, &f.pseudo_out, &ki, &sig));
        assert_eq!(recover_alpha(&f, &ki, &sig), alpha);

        let mut encoded = Vec::with_capacity(CLSAG_BYTES);
        encoded.extend_from_slice(&sig.c0.to_bytes());
        for s in &sig.s {
            encoded.extend_from_slice(&s.to_bytes());
        }
        encoded.extend_from_slice(sig.d.bytes());
        assert_eq!(encoded.len(), CLSAG_BYTES);
        let fields: Vec<String> = encoded.chunks(32).map(hex::encode).collect();
        assert_eq!(hex::encode(alpha.to_bytes()), ALPHA_VECTOR);
        assert_eq!(hex::encode(ki.bytes()), KEY_IMAGE_VECTOR);
        assert_eq!(fields, SIGNATURE_VECTOR);
    }

    /// First value of the CLSAG nonce stream (`α`), little-endian scalar.
    const ALPHA_VECTOR: &str = "fc145307dc85d999fd654d1a17905eb7b7c1355ab43a78133efbe6a458757c00";
    const KEY_IMAGE_VECTOR: &str =
        "4a7907fa84aec07dd8913337794b3f91868393fca8e4397831e9affe1837d357";
    /// `c0`, `s[0..16)`, `D`: one 32-byte field per line.
    const SIGNATURE_VECTOR: [&str; RING_SIZE + 2] = [
        "6e96ce66ec6b513492ea6757b51027ecde268478677536c78de58dd81f53950b",
        "0e33ebb057ce5cdc6da3a0101ce973d3504a4e063e5a2c3296a11702a74c7101",
        "600ecd6b410d1f64c4b75e211620436ead6e516d415ddb0bb0cbe4025fe29b04",
        "12abaeda794e6a391528f67658d8d9bb2dc39fed5c6121211dd351beff3b4b02",
        "75e8640e53fa04cdd217d9dc2f4a5cf958596188569ff0b571c4be554b155c08",
        "0e3a98c936674f1b275ef47eff4212c0e3935073b6191b9913ae32bad8b8c00e",
        "cc39ea862ded362cc7df925b6d40d9789f525818b5a759605336c576e1e49701",
        "6ee03b2545866d31cb9eae7d507b56d882502107e9f36396c57498a80f0dbe00",
        "8aa6ab4cf83971ad992294c95ee84227b2056b96ee6236a3d39cb9f16389c503",
        "5cf343998a59b0e2233a5063519714c9fba46fa6302de0d3da9e0b1a4cd02c01",
        "b001975f2a2029b61c2554f4d41b6850140e58068bd9b0330949f5549eeeab01",
        "33c195a4df8091781f0899ebf132ce417daca51a1f0267d7ef4a222eb0d84201",
        "c543f251b67222cb2e5585e4b4f6e9491055cff7adfc50e100687a8a6a85860b",
        "0d57fa5be6cde61f6f9f9fde812f9715c7ea1cba18d6068e01396ac77d461e0a",
        "b1ca35c05cedaeb80b3840db4120226c7530294ab5bc252446a37d3b00a60e05",
        "982b4a0cf7e8e9100b4950c29dc6fe06f124638afbe9007d50d8bab90ad2d30c",
        "30d1d5e6e014274ea9f90b69c41faa3bb3fd1eed7edb13d6b5da17f35e75ef0a",
        "5a41709da57013ece0c0ef6f85d488515487c5f2848ccd1c4454141c8b226473",
    ];
}
