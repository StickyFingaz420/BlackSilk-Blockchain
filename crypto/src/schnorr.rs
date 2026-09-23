//! Domain-tagged Schnorr signatures over Ristretto255 (contracts spec §6.2, §7.1, §8).
//!
//! One construction serves four purposes, separated by the challenge tag:
//!
//! | Tag | Key | Proves |
//! |---|---|---|
//! | `contract/kernel` | the balance excess `E` | the transaction balances and its builder knows `e` |
//! | `contract/auth` | an auth key `K` | the holder of `K` authorized this transaction |
//! | `contract/claim-eq` | `C_a − C_b` | two commitments hold the same amount |
//! | `contract/claim-val` | `C − v·H` | a commitment holds exactly `v` |
//!
//! ```text
//! sign:    t ← hedged nonce;  R = t·G;  c = Hs(tag, K ‖ R ‖ m);  s = t + c·k
//! verify:  K ≠ identity;  s·G − c·K = R
//! ```
//!
//! The public key is hashed into the challenge (key prefixing), so a signature
//! is bound to one key. The identity key is rejected, because for `K = 0` any
//! `(R, s)` with `R = s·G` verifies. Signatures are 64 bytes: `R ‖ s`.

use crate::hash::Hasher64;
use crate::nonce::HedgedRng;
use crate::point::{decode_scalar, Point};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Encoded size: `R ‖ s`.
pub const SIGNATURE_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature {
    pub r: Point,
    pub s: Scalar,
}

impl Signature {
    pub fn to_bytes(&self) -> [u8; SIGNATURE_BYTES] {
        let mut out = [0u8; SIGNATURE_BYTES];
        out[..32].copy_from_slice(self.r.bytes());
        out[32..].copy_from_slice(self.s.as_bytes());
        out
    }

    /// Strict decoding: canonical point and canonical scalar.
    pub fn from_bytes(bytes: &[u8; SIGNATURE_BYTES]) -> Option<Self> {
        let r = Point::decode(bytes[..32].try_into().ok()?)?;
        let s = decode_scalar(bytes[32..].try_into().ok()?)?;
        Some(Self { r, s })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchnorrError {
    /// `secret·G` is not the given public key.
    WrongSecret,
    /// The public key is the identity, which anyone can sign for.
    IdentityKey,
}

fn challenge(tag: &str, key: &Point, r: &Point, message: &[u8; 32]) -> Scalar {
    Hasher64::new(tag)
        .chain(key.bytes())
        .chain(r.bytes())
        .chain(message)
        .to_scalar()
}

/// Signs `message` under `tag` with `secret`, whose public key must be `key`.
/// The secret is checked first, so a caller bug cannot produce a signature
/// under a key the signer does not hold.
pub fn sign<R: RngCore + CryptoRng>(
    tag: &str,
    secret: &Scalar,
    key: &Point,
    message: &[u8; 32],
    rng: &mut R,
) -> Result<Signature, SchnorrError> {
    if key.is_identity() {
        return Err(SchnorrError::IdentityKey);
    }
    let expected = Point::from_point(RistrettoPoint::mul_base(secret));
    if !bool::from(expected.bytes().ct_eq(key.bytes())) {
        return Err(SchnorrError::WrongSecret);
    }
    let mut secret_bytes = secret.to_bytes();
    let mut nonces = HedgedRng::new(
        &[&secret_bytes],
        &[b"schnorr", tag.as_bytes(), key.bytes(), message],
        rng,
    );
    secret_bytes.zeroize();
    let mut t = nonces.scalar();
    let r = Point::from_point(RistrettoPoint::mul_base(&t));
    let c = challenge(tag, key, &r, message);
    let s = t + c * secret;
    t.zeroize();
    Ok(Signature { r, s })
}

/// Verifies a signature. Public data only, so variable time is fine.
pub fn verify(tag: &str, key: &Point, message: &[u8; 32], sig: &Signature) -> bool {
    if key.is_identity() {
        return false;
    }
    let c = challenge(tag, key, &sig.r, message);
    let r = RistrettoPoint::vartime_multiscalar_mul([sig.s, -c], [G, *key.point()]);
    r == *sig.r.point()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::tags;
    use crate::nonce::test_rng::{seeded, ZeroRng};

    fn random_scalar(rng: &mut impl RngCore) -> Scalar {
        let mut wide = [0u8; 64];
        rng.fill_bytes(&mut wide);
        Scalar::from_bytes_mod_order_wide(&wide)
    }

    fn keypair(rng: &mut impl RngCore) -> (Scalar, Point) {
        let k = random_scalar(rng);
        (k, Point::from_point(RistrettoPoint::mul_base(&k)))
    }

    const TAG: &str = tags::CONTRACT_AUTH;

    #[test]
    fn signs_and_verifies() {
        let mut rng = seeded(900);
        for _ in 0..32 {
            let (k, key) = keypair(&mut rng);
            let mut m = [0u8; 32];
            rng.fill_bytes(&mut m);
            let sig = sign(TAG, &k, &key, &m, &mut rng).unwrap();
            assert!(verify(TAG, &key, &m, &sig));
            let decoded = Signature::from_bytes(&sig.to_bytes()).unwrap();
            assert_eq!(decoded, sig);
        }
    }

    #[test]
    fn any_modification_invalidates() {
        let mut rng = seeded(901);
        let (k, key) = keypair(&mut rng);
        let (_, other_key) = keypair(&mut rng);
        let m = [7u8; 32];
        let sig = sign(TAG, &k, &key, &m, &mut rng).unwrap();

        let mut m2 = m;
        m2[31] ^= 1;
        assert!(!verify(TAG, &key, &m2, &sig), "message");
        assert!(!verify(TAG, &other_key, &m, &sig), "key");
        assert!(!verify(tags::CONTRACT_KERNEL, &key, &m, &sig), "tag");
        let bad_s = Signature {
            s: sig.s + Scalar::ONE,
            ..sig
        };
        assert!(!verify(TAG, &key, &m, &bad_s), "s");
        let bad_r = Signature {
            r: Point::from_point(sig.r.point() + G),
            ..sig
        };
        assert!(!verify(TAG, &key, &m, &bad_r), "R");
        // Every single bit of the encoding matters.
        let bytes = sig.to_bytes();
        for bit in 0..SIGNATURE_BYTES * 8 {
            let mut b = bytes;
            b[bit / 8] ^= 1 << (bit % 8);
            if let Some(s) = Signature::from_bytes(&b) {
                assert!(!verify(TAG, &key, &m, &s), "bit {bit}");
            }
        }
    }

    #[test]
    fn identity_key_is_rejected() {
        let mut rng = seeded(902);
        let identity = Point::from_point(RistrettoPoint::default());
        // Without the check, (R = s·G, s) would verify for any message.
        let s = random_scalar(&mut rng);
        let forged = Signature {
            r: Point::from_point(RistrettoPoint::mul_base(&s)),
            s,
        };
        assert!(!verify(TAG, &identity, &[0; 32], &forged));
        assert_eq!(
            sign(TAG, &Scalar::ZERO, &identity, &[0; 32], &mut rng),
            Err(SchnorrError::IdentityKey)
        );
    }

    #[test]
    fn wrong_secret_is_refused() {
        let mut rng = seeded(903);
        let (_, key) = keypair(&mut rng);
        let (other, _) = keypair(&mut rng);
        assert_eq!(
            sign(TAG, &other, &key, &[1; 32], &mut rng),
            Err(SchnorrError::WrongSecret)
        );
    }

    #[test]
    fn keyless_forgery_attempts_fail() {
        let mut rng = seeded(904);
        let (_, key) = keypair(&mut rng);
        let m = [3u8; 32];
        for _ in 0..64 {
            // Pick s and c first, then try to solve for R: needs c = Hs(K‖R‖m).
            let s = random_scalar(&mut rng);
            let c = random_scalar(&mut rng);
            let r = Point::from_point(RistrettoPoint::mul_base(&s) - c * key.point());
            assert!(!verify(TAG, &key, &m, &Signature { r, s }));
        }
    }

    #[test]
    fn broken_rng_does_not_reuse_nonces() {
        // With a constant RNG, two messages must still get different R values:
        // equal R for different challenges would reveal the secret key.
        let mut rng = seeded(905);
        let (k, key) = keypair(&mut rng);
        let a = sign(TAG, &k, &key, &[1; 32], &mut ZeroRng).unwrap();
        let b = sign(TAG, &k, &key, &[2; 32], &mut ZeroRng).unwrap();
        assert_ne!(a.r, b.r);
        // The same key under another tag is another context as well.
        let c = sign(tags::CONTRACT_KERNEL, &k, &key, &[1; 32], &mut ZeroRng).unwrap();
        assert_ne!(a.r, c.r);
        assert!(verify(TAG, &key, &[1; 32], &a));
        assert!(verify(TAG, &key, &[2; 32], &b));
    }

    #[test]
    fn non_canonical_scalar_is_rejected_in_decoding() {
        let mut rng = seeded(906);
        let (k, key) = keypair(&mut rng);
        let sig = sign(TAG, &k, &key, &[0; 32], &mut rng).unwrap();
        let mut bytes = sig.to_bytes();
        bytes[32..].copy_from_slice(&[0xff; 32]);
        assert!(Signature::from_bytes(&bytes).is_none());
    }
}
