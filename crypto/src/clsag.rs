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

    let hp_real = key_image_base(&real.one_time_key);
    let key_image = Point::from_point(spend_secret * hp_real);
    let d = Point::from_point(commitment_secret * hp_real);
    let t = Transcript::new(ring, pseudo_out, &key_image, &d, message);
    let w = t.mu_p * key_image.point() + t.mu_c * d.point();

    let mut p_bytes = spend_secret.to_bytes();
    let mut z_bytes = commitment_secret.to_bytes();
    let mut nonces = HedgedRng::new(
        &[&p_bytes, &z_bytes],
        &[
            b"clsag",
            message,
            pseudo_out.bytes(),
            real.one_time_key.bytes(),
        ],
        rng,
    );
    p_bytes.zeroize();
    z_bytes.zeroize();

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
    if key_image.is_identity() {
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
}
