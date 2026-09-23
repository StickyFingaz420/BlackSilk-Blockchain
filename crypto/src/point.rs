//! Canonical encodings (spec §1.1).
//!
//! A [`Point`] can only be created from a valid canonical Ristretto encoding or
//! from a group element, so holding one proves the bytes are valid. It keeps both
//! forms: the bytes for hashing and serialization, the element for arithmetic.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

#[derive(Clone, Copy)]
pub struct Point {
    bytes: [u8; 32],
    point: RistrettoPoint,
}

impl Point {
    /// Decodes a canonical Ristretto255 encoding. Non-canonical encodings are
    /// rejected by dalek's decompression (RFC 9496 §4.3.1), never normalized.
    pub fn decode(bytes: &[u8; 32]) -> Option<Self> {
        let point = CompressedRistretto(*bytes).decompress()?;
        Some(Self {
            bytes: *bytes,
            point,
        })
    }

    pub fn from_point(point: RistrettoPoint) -> Self {
        Self {
            bytes: point.compress().to_bytes(),
            point,
        }
    }

    pub fn bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    pub fn point(&self) -> &RistrettoPoint {
        &self.point
    }

    pub fn is_identity(&self) -> bool {
        self.point.is_identity()
    }
}

// Equality and ordering are on the canonical encoding, which is unique per element.
impl PartialEq for Point {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}
impl Eq for Point {}

impl Hash for Point {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

impl PartialOrd for Point {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Point {
    fn cmp(&self, other: &Self) -> Ordering {
        self.bytes.cmp(&other.bytes)
    }
}

impl std::fmt::Debug for Point {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Point(")?;
        for b in &self.bytes[..8] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "…)")
    }
}

/// Decodes a canonical scalar (`< ℓ`). Non-canonical values are rejected, never reduced.
pub fn decode_scalar(bytes: &[u8; 32]) -> Option<Scalar> {
    Option::from(Scalar::from_canonical_bytes(*bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

    /// ℓ = 2^252 + 27742317777372353535851937790883648493, little-endian.
    const L_BYTES: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];

    #[test]
    fn round_trip() {
        let p = Point::from_point(RISTRETTO_BASEPOINT_POINT * Scalar::from(7u64));
        let q = Point::decode(p.bytes()).unwrap();
        assert_eq!(p, q);
        assert_eq!(p.point(), q.point());
    }

    #[test]
    fn identity_encodes_as_zero() {
        let id = Point::decode(&[0; 32]).unwrap();
        assert!(id.is_identity());
    }

    #[test]
    fn non_canonical_points_rejected() {
        // s = p = 2^255 - 19 (a non-canonical encoding of 0).
        let mut p_bytes = [0xffu8; 32];
        p_bytes[0] = 0xed;
        p_bytes[31] = 0x7f;
        assert!(Point::decode(&p_bytes).is_none());
        // High bit set.
        let mut high = [0u8; 32];
        high[31] = 0x80;
        assert!(Point::decode(&high).is_none());
        // "Negative" field element (odd s) is not a valid encoding.
        let mut odd = [0u8; 32];
        odd[0] = 1;
        assert!(Point::decode(&odd).is_none());
        assert!(Point::decode(&[0xff; 32]).is_none());
    }

    #[test]
    fn non_canonical_scalars_rejected() {
        let l = L_BYTES;
        // Sanity: ℓ ≡ 0, so reducing it gives zero.
        assert_eq!(Scalar::from_bytes_mod_order(l), Scalar::ZERO);
        assert!(decode_scalar(&l).is_none(), "ℓ itself");
        assert!(decode_scalar(&[0xff; 32]).is_none());
        let mut l_minus_1 = l;
        l_minus_1[0] -= 1;
        assert!(decode_scalar(&l_minus_1).is_some());
        assert_eq!(decode_scalar(&[0; 32]), Some(Scalar::ZERO));
    }

    #[test]
    fn about_half_of_random_bytes_are_invalid_points() {
        // Sanity: decoding really validates (a no-op check would accept everything).
        let mut invalid = 0;
        for i in 0..256u32 {
            let bytes = crate::hash::h32(crate::hash::tags::MASK, &[&i.to_le_bytes()]);
            if Point::decode(&bytes).is_none() {
                invalid += 1;
            }
        }
        assert!(invalid > 128, "{invalid}");
    }
}
