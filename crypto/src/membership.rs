//! Scoped membership proofs (contracts spec §7.2).
//!
//! A linkable ring signature whose tag base is fixed per *scope* instead of per
//! key: the event-oriented linkable ring signature of Tsang & Wei (2004) and
//! Liu & Wong (2005), in the compact bLSAG form.
//!
//! ```text
//! B        = Hp("contract/scope", owner ‖ LE32(set_id) ‖ u8(len) ‖ scope)
//! I        = x·B                                   tag: one per member per scope
//! c[i+1]   = Hs("contract/member-round", u8(r) ‖ P[0..r) ‖ B ‖ I ‖ m ‖ L_i ‖ R_i)
//! L_i      = s_i·G + c_i·P[i]
//! R_i      = s_i·B + c_i·I
//! signature = (c0, s[0..r)),  1 ≤ r ≤ 16
//! ```
//!
//! Properties (under DL and DDH in Ristretto255, random-oracle model):
//! - **Linkability:** the same secret signing in the same scope always yields the
//!   same `I`, whatever the ring and message. A contract detects a second action
//!   (e.g. a second vote) by storing the tags it has seen.
//! - **Anonymity:** `I` and the signature reveal nothing about which ring member
//!   signed, and tags of one key in different scopes are unlinkable (DDH).
//! - **Unforgeability / non-frameability:** producing a valid signature needs the
//!   secret of a ring member, and the tag it carries is that member's tag.
//!
//! Differences from [`crate::clsag`]: the tag base `B` is shared by all members
//! (it depends on the scope, not on `P[i]`), and there is no commitment part.

use crate::hash::{tags, Hasher64};
use crate::nonce::HedgedRng;
use crate::point::Point;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Largest ring (spec §7.2).
pub const MAX_RING: usize = 16;
/// Longest scope in bytes.
pub const MAX_SCOPE: usize = 32;

/// The tag base of one scope: `B = Hp("contract/scope", …)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scope {
    base: Point,
}

impl Scope {
    /// Returns `None` if `scope` is longer than [`MAX_SCOPE`].
    pub fn new(owner: &[u8; 32], set_id: u32, scope: &[u8]) -> Option<Self> {
        if scope.len() > MAX_SCOPE {
            return None;
        }
        let base = Hasher64::new(tags::CONTRACT_SCOPE)
            .chain(owner)
            .chain(&set_id.to_le_bytes())
            .chain(&[scope.len() as u8])
            .chain(scope)
            .to_point();
        Some(Self {
            base: Point::from_point(base),
        })
    }

    pub fn base(&self) -> &Point {
        &self.base
    }

    /// The tag `x·B` of the member with secret `x`.
    pub fn tag(&self, secret: &Scalar) -> Point {
        Point::from_point(secret * self.base.point())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberSig {
    pub c0: Scalar,
    pub s: Vec<Scalar>,
}

impl MemberSig {
    pub fn encoded_len(&self) -> usize {
        32 * (1 + self.s.len())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberError {
    /// The ring is empty or larger than [`MAX_RING`].
    RingSize,
    RealIndexOutOfRange,
    /// `x·G ≠ P[π]`.
    WrongSecret,
}

struct Transcript(Hasher64);

impl Transcript {
    fn new(ring: &[Point], scope: &Scope, tag: &Point, message: &[u8; 32]) -> Self {
        let mut h = Hasher64::new(tags::CONTRACT_MEMBER_ROUND);
        h.update(&[ring.len() as u8]);
        for p in ring {
            h.update(p.bytes());
        }
        h.update(scope.base.bytes())
            .update(tag.bytes())
            .update(message);
        Self(h)
    }

    fn challenge(&self, l: &RistrettoPoint, r: &RistrettoPoint) -> Scalar {
        self.0
            .clone()
            .chain(l.compress().as_bytes())
            .chain(r.compress().as_bytes())
            .to_scalar()
    }
}

fn ring_size_ok(n: usize) -> bool {
    (1..=MAX_RING).contains(&n)
}

/// Signs `message` as ring member `real_index`. Returns the signature and the
/// member's tag for this scope.
pub fn sign<R: RngCore + CryptoRng>(
    message: &[u8; 32],
    ring: &[Point],
    scope: &Scope,
    real_index: usize,
    secret: &Scalar,
    rng: &mut R,
) -> Result<(MemberSig, Point), MemberError> {
    if !ring_size_ok(ring.len()) {
        return Err(MemberError::RingSize);
    }
    if real_index >= ring.len() {
        return Err(MemberError::RealIndexOutOfRange);
    }
    let expected = Point::from_point(RistrettoPoint::mul_base(secret));
    if !bool::from(expected.bytes().ct_eq(ring[real_index].bytes())) {
        return Err(MemberError::WrongSecret);
    }
    let tag = scope.tag(secret);
    let sig = sign_with_tag(message, ring, scope, &tag, real_index, secret, rng);
    Ok((sig, tag))
}

/// The ring loop, for a given tag. `sign` always passes the honest tag; the
/// tests also call this with a wrong one to model a framing attempt.
fn sign_with_tag<R: RngCore + CryptoRng>(
    message: &[u8; 32],
    ring: &[Point],
    scope: &Scope,
    tag: &Point,
    real_index: usize,
    secret: &Scalar,
    rng: &mut R,
) -> MemberSig {
    let n = ring.len();
    let t = Transcript::new(ring, scope, tag, message);
    let mut secret_bytes = secret.to_bytes();
    let mut nonces = HedgedRng::new(
        &[&secret_bytes],
        &[
            b"membership",
            message,
            scope.base.bytes(),
            ring[real_index].bytes(),
        ],
        rng,
    );
    secret_bytes.zeroize();

    let b = scope.base.point();
    let mut alpha = nonces.scalar();
    let mut c = vec![Scalar::ZERO; n];
    let mut s = vec![Scalar::ZERO; n];
    let mut i = (real_index + 1) % n;
    c[i] = t.challenge(&RistrettoPoint::mul_base(&alpha), &(alpha * b));
    while i != real_index {
        s[i] = nonces.scalar();
        let l = RistrettoPoint::mul_base(&s[i]) + c[i] * ring[i].point();
        let r = s[i] * b + c[i] * tag.point();
        let next = (i + 1) % n;
        c[next] = t.challenge(&l, &r);
        i = next;
    }
    s[real_index] = alpha - c[real_index] * secret;
    alpha.zeroize();
    MemberSig { c0: c[0], s }
}

/// Verifies a membership signature with tag `tag` over `ring` in `scope`.
pub fn verify(
    message: &[u8; 32],
    ring: &[Point],
    scope: &Scope,
    tag: &Point,
    sig: &MemberSig,
) -> bool {
    if !ring_size_ok(ring.len()) || sig.s.len() != ring.len() {
        return false;
    }
    // The identity tag would belong to x = 0; identity members are not keys.
    if tag.is_identity() || ring.iter().any(Point::is_identity) {
        return false;
    }
    let t = Transcript::new(ring, scope, tag, message);
    let mut c = sig.c0;
    for (p, s) in ring.iter().zip(&sig.s) {
        let l = RistrettoPoint::vartime_multiscalar_mul([*s, c], [G, *p.point()]);
        let r =
            RistrettoPoint::vartime_multiscalar_mul([*s, c], [*scope.base.point(), *tag.point()]);
        c = t.challenge(&l, &r);
    }
    bool::from(c.ct_eq(&sig.c0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clsag::key_image;
    use crate::nonce::test_rng::{seeded, ChaCha20Rng, ZeroRng};

    fn random_scalar(rng: &mut impl RngCore) -> Scalar {
        let mut wide = [0u8; 64];
        rng.fill_bytes(&mut wide);
        Scalar::from_bytes_mod_order_wide(&wide)
    }

    fn members(rng: &mut ChaCha20Rng, n: usize) -> (Vec<Scalar>, Vec<Point>) {
        let secrets: Vec<Scalar> = (0..n).map(|_| random_scalar(rng)).collect();
        let ring = secrets
            .iter()
            .map(|x| Point::from_point(RistrettoPoint::mul_base(x)))
            .collect();
        (secrets, ring)
    }

    fn scope(name: &[u8]) -> Scope {
        Scope::new(&[0xc0; 32], 1, name).unwrap()
    }

    #[test]
    fn signs_and_verifies_for_every_size_and_index() {
        let mut rng = seeded(910);
        let sc = scope(b"proposal-1");
        for n in 1..=MAX_RING {
            let (secrets, ring) = members(&mut rng, n);
            for (real, secret) in secrets.iter().enumerate() {
                let m = [n as u8; 32];
                let (sig, tag) = sign(&m, &ring, &sc, real, secret, &mut rng).unwrap();
                assert_eq!(tag, sc.tag(secret));
                assert!(verify(&m, &ring, &sc, &tag, &sig), "n={n} real={real}");
            }
        }
    }

    #[test]
    fn any_modification_invalidates() {
        let mut rng = seeded(911);
        let sc = scope(b"vote");
        let (secrets, ring) = members(&mut rng, 16);
        let m = [9u8; 32];
        let (sig, tag) = sign(&m, &ring, &sc, 11, &secrets[11], &mut rng).unwrap();
        assert!(verify(&m, &ring, &sc, &tag, &sig));

        let mut m2 = m;
        m2[0] ^= 1;
        assert!(!verify(&m2, &ring, &sc, &tag, &sig), "message");
        for i in 0..ring.len() {
            let mut r = ring.clone();
            r[i] = Point::from_point(r[i].point() + G);
            assert!(!verify(&m, &r, &sc, &tag, &sig), "member {i}");
        }
        let mut swapped = ring.clone();
        swapped.swap(0, 1);
        assert!(!verify(&m, &swapped, &sc, &tag, &sig), "ring order");
        assert!(!verify(&m, &ring[..15], &sc, &tag, &sig), "shorter ring");
        assert!(!verify(&m, &ring, &scope(b"vote2"), &tag, &sig), "scope");
        assert!(
            !verify(
                &m,
                &ring,
                &Scope::new(&[0xc1; 32], 1, b"vote").unwrap(),
                &tag,
                &sig
            ),
            "owner"
        );
        assert!(
            !verify(
                &m,
                &ring,
                &Scope::new(&[0xc0; 32], 2, b"vote").unwrap(),
                &tag,
                &sig
            ),
            "set"
        );
        let other_tag = Point::from_point(tag.point() + G);
        assert!(!verify(&m, &ring, &sc, &other_tag, &sig), "tag");
        let mut bad = sig.clone();
        bad.c0 += Scalar::ONE;
        assert!(!verify(&m, &ring, &sc, &tag, &bad), "c0");
        for i in 0..ring.len() {
            let mut bad = sig.clone();
            bad.s[i] += Scalar::ONE;
            assert!(!verify(&m, &ring, &sc, &tag, &bad), "s[{i}]");
        }
    }

    #[test]
    fn tags_link_within_a_scope_only() {
        let mut rng = seeded(912);
        let (secrets, ring_a) = members(&mut rng, 16);
        let (_, mut ring_b) = members(&mut rng, 16);
        // The same member appears in a different ring (other decoys, other position).
        ring_b[3] = ring_a[7];
        let sc = scope(b"proposal-17");
        let (_, t1) = sign(&[1; 32], &ring_a, &sc, 7, &secrets[7], &mut rng).unwrap();
        let (_, t2) = sign(&[2; 32], &ring_b, &sc, 3, &secrets[7], &mut rng).unwrap();
        assert_eq!(t1, t2, "a second action in the same scope is detectable");

        let (_, t3) = sign(
            &[1; 32],
            &ring_a,
            &scope(b"proposal-18"),
            7,
            &secrets[7],
            &mut rng,
        )
        .unwrap();
        assert_ne!(t1, t3, "other scopes give other tags");
        // Different members never share a tag in one scope.
        let (_, t4) = sign(&[1; 32], &ring_a, &sc, 8, &secrets[8], &mut rng).unwrap();
        assert_ne!(t1, t4);
        // The tag is not the member's CLSAG key image either.
        assert_ne!(t1, key_image(&secrets[7], &ring_a[7]));
    }

    #[test]
    fn framing_with_another_members_tag_fails() {
        // Member 2 signs honestly with its own secret but claims member 5's tag
        // (e.g. to cast a vote in the victim's name, or to burn it).
        let mut rng = seeded(913);
        let sc = scope(b"vote");
        let (secrets, ring) = members(&mut rng, 16);
        let victim_tag = sc.tag(&secrets[5]);
        let m = [4u8; 32];
        let sig = sign_with_tag(&m, &ring, &sc, &victim_tag, 2, &secrets[2], &mut rng);
        assert!(!verify(&m, &ring, &sc, &victim_tag, &sig));
        // Also for a random tag: evading linkability with a fresh tag fails.
        let fresh = Point::from_point(RistrettoPoint::mul_base(&random_scalar(&mut rng)));
        let sig = sign_with_tag(&m, &ring, &sc, &fresh, 2, &secrets[2], &mut rng);
        assert!(!verify(&m, &ring, &sc, &fresh, &sig));
    }

    #[test]
    fn outsiders_cannot_sign() {
        let mut rng = seeded(914);
        let sc = scope(b"vote");
        let (_, ring) = members(&mut rng, 16);
        let outsider = random_scalar(&mut rng);
        // The signer refuses a secret that is not in the ring.
        assert_eq!(
            sign(&[0; 32], &ring, &sc, 0, &outsider, &mut rng),
            Err(MemberError::WrongSecret)
        );
        // Running the loop anyway yields an invalid signature.
        let tag = sc.tag(&outsider);
        let sig = sign_with_tag(&[0; 32], &ring, &sc, &tag, 0, &outsider, &mut rng);
        assert!(!verify(&[0; 32], &ring, &sc, &tag, &sig));
    }

    #[test]
    fn identity_tag_and_members_are_rejected() {
        let mut rng = seeded(915);
        let sc = scope(b"s");
        let (secrets, mut ring) = members(&mut rng, 4);
        let (sig, tag) = sign(&[0; 32], &ring, &sc, 0, &secrets[0], &mut rng).unwrap();
        let identity = Point::from_point(RistrettoPoint::default());
        assert!(!verify(&[0; 32], &ring, &sc, &identity, &sig));
        ring[3] = identity;
        assert!(!verify(&[0; 32], &ring, &sc, &tag, &sig));
    }

    #[test]
    fn sizes_and_lengths_are_enforced() {
        let mut rng = seeded(916);
        let sc = scope(b"s");
        let (secrets, ring) = members(&mut rng, 17);
        assert_eq!(
            sign(&[0; 32], &ring, &sc, 0, &secrets[0], &mut rng),
            Err(MemberError::RingSize)
        );
        assert_eq!(
            sign(&[0; 32], &[], &sc, 0, &secrets[0], &mut rng),
            Err(MemberError::RingSize)
        );
        assert_eq!(
            sign(&[0; 32], &ring[..4], &sc, 4, &secrets[0], &mut rng),
            Err(MemberError::RealIndexOutOfRange)
        );
        let (sig, tag) = sign(&[0; 32], &ring[..4], &sc, 1, &secrets[1], &mut rng).unwrap();
        let mut short = sig.clone();
        short.s.pop();
        assert!(!verify(&[0; 32], &ring[..4], &sc, &tag, &short));
        assert!(Scope::new(&[0; 32], 0, &[0; MAX_SCOPE + 1]).is_none());
        assert!(Scope::new(&[0; 32], 0, &[0; MAX_SCOPE]).is_some());
    }

    #[test]
    fn scope_encoding_is_unambiguous() {
        // (set 1, "ab") and (set 1, "a" + "b"…) cannot collide thanks to the length
        // byte; different owner/set/scope give different bases.
        let a = Scope::new(&[0; 32], 1, b"ab").unwrap();
        let b = Scope::new(&[0; 32], 1, b"a").unwrap();
        let c = Scope::new(&[0; 32], 0x6201, b"").unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    #[test]
    fn broken_rng_does_not_reuse_nonces() {
        let mut rng = seeded(917);
        let sc = scope(b"s");
        let (secrets, ring) = members(&mut rng, 16);
        let (a, _) = sign(&[1; 32], &ring, &sc, 4, &secrets[4], &mut ZeroRng).unwrap();
        let (b, _) = sign(&[2; 32], &ring, &sc, 4, &secrets[4], &mut ZeroRng).unwrap();
        assert_ne!(a.s[4], b.s[4]);
        assert_ne!(a.s[5], b.s[5], "decoy responses differ too");
    }

    #[test]
    fn responses_look_uniform() {
        // The real index's response is not distinguishable by, e.g., being small.
        let mut rng = seeded(918);
        let sc = scope(b"s");
        let (secrets, ring) = members(&mut rng, 16);
        let mut high_bits = [0u32; 16];
        for _ in 0..64 {
            let (sig, _) = sign(&[0; 32], &ring, &sc, 9, &secrets[9], &mut rng).unwrap();
            for (i, s) in sig.s.iter().enumerate() {
                high_bits[i] += u32::from(s.as_bytes()[31] >> 3 != 0);
            }
        }
        // Scalars < ℓ ≈ 2^252: byte 31 is at most 0x10; roughly half have bit 4 set.
        for (i, h) in high_bits.iter().enumerate() {
            assert!((12..=52).contains(h), "index {i}: {h}");
        }
    }
}
