//! Strict binary encoding primitives (spec §4.1).
//!
//! Every value has exactly one valid encoding. Varints must be minimal, points and
//! scalars must be canonical, and trailing bytes are an error. This guarantees
//! `encode(decode(b)) == b`, so hashes computed from a re-encoded transaction
//! always match the bytes that were received.

use blacksilk_crypto::point::decode_scalar;
use blacksilk_crypto::{Point, Scalar};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    UnexpectedEnd,
    NonMinimalVarint,
    VarintOverflow,
    InvalidPoint,
    InvalidScalar,
    TrailingBytes,
    TooLarge,
    UnsupportedVersion(u64),
    UnknownKind(u8),
    /// A count outside its consensus bounds (checked before allocating).
    CountOutOfRange {
        what: &'static str,
        count: u64,
    },
    /// A ring offset delta of 0 (duplicate member) or an index past `u64::MAX`.
    InvalidRingOffsets,
    /// A field element (PX digests, function outputs) that is not canonical.
    NonCanonicalField,
    /// A deploy program binary that does not load.
    InvalidProgram,
}

#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    /// Unsigned LEB128, minimal.
    pub fn varint(&mut self, mut v: u64) {
        while v >= 0x80 {
            self.buf.push((v as u8 & 0x7f) | 0x80);
            v >>= 7;
        }
        self.buf.push(v as u8);
    }

    pub fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    pub fn point(&mut self, p: &Point) {
        self.bytes(p.bytes());
    }

    pub fn scalar(&mut self, s: &Scalar) {
        self.bytes(s.as_bytes());
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// The bytes `start..end` of the input.
    pub fn slice(&self, start: usize, end: usize) -> &'a [u8] {
        &self.data[start..end]
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        let b = *self.data.get(self.pos).ok_or(DecodeError::UnexpectedEnd)?;
        self.pos += 1;
        Ok(b)
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let end = self.pos.checked_add(N).ok_or(DecodeError::UnexpectedEnd)?;
        let slice = self
            .data
            .get(self.pos..end)
            .ok_or(DecodeError::UnexpectedEnd)?;
        self.pos = end;
        Ok(slice.try_into().expect("slice has length N"))
    }

    /// Unsigned LEB128: at most 10 bytes, value ≤ `u64::MAX`, minimal encoding.
    pub fn varint(&mut self) -> Result<u64, DecodeError> {
        let mut value: u64 = 0;
        for i in 0..10 {
            let b = self.u8()?;
            let low = (b & 0x7f) as u64;
            if i == 9 && (b & 0x80 != 0 || low > 1) {
                return Err(DecodeError::VarintOverflow);
            }
            value |= low << (7 * i);
            if b & 0x80 == 0 {
                if i > 0 && b == 0 {
                    return Err(DecodeError::NonMinimalVarint);
                }
                return Ok(value);
            }
        }
        unreachable!("the 10th byte either ends the varint or is rejected")
    }

    /// Advances past `n` bytes (used when an embedded object was decoded separately).
    pub fn skip(&mut self, n: usize) -> Result<(), DecodeError> {
        let end = self.pos.checked_add(n).ok_or(DecodeError::UnexpectedEnd)?;
        if end > self.data.len() {
            return Err(DecodeError::UnexpectedEnd);
        }
        self.pos = end;
        Ok(())
    }

    pub fn point(&mut self) -> Result<Point, DecodeError> {
        Point::decode(&self.array::<32>()?).ok_or(DecodeError::InvalidPoint)
    }

    pub fn scalar(&mut self) -> Result<Scalar, DecodeError> {
        decode_scalar(&self.array::<32>()?).ok_or(DecodeError::InvalidScalar)
    }

    /// A count in `min..=max`, rejected before anything is allocated for it.
    pub fn count(&mut self, what: &'static str, min: u64, max: u64) -> Result<usize, DecodeError> {
        let count = self.varint()?;
        if count < min || count > max {
            return Err(DecodeError::CountOutOfRange { what, count });
        }
        Ok(count as usize)
    }

    pub fn finish(self) -> Result<(), DecodeError> {
        if self.pos == self.data.len() {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(v: u64) -> Vec<u8> {
        let mut w = Writer::new();
        w.varint(v);
        w.into_bytes()
    }

    fn dec(b: &[u8]) -> Result<u64, DecodeError> {
        let mut r = Reader::new(b);
        let v = r.varint()?;
        r.finish()?;
        Ok(v)
    }

    #[test]
    fn varint_round_trip() {
        for v in [
            0,
            1,
            127,
            128,
            255,
            300,
            16_383,
            16_384,
            u32::MAX as u64,
            u64::MAX - 1,
            u64::MAX,
        ] {
            assert_eq!(dec(&enc(v)), Ok(v), "{v}");
        }
        assert_eq!(enc(0), [0]);
        assert_eq!(enc(127), [0x7f]);
        assert_eq!(enc(128), [0x80, 0x01]);
        assert_eq!(enc(u64::MAX).len(), 10);
    }

    #[test]
    fn varint_rejects_non_minimal_and_overflow() {
        assert_eq!(dec(&[0x80, 0x00]), Err(DecodeError::NonMinimalVarint));
        assert_eq!(dec(&[0xff, 0x00]), Err(DecodeError::NonMinimalVarint));
        let mut too_big = vec![0xff; 9];
        too_big.push(0x02); // bit 64
        assert_eq!(dec(&too_big), Err(DecodeError::VarintOverflow));
        assert_eq!(dec(&[0xff; 11]), Err(DecodeError::VarintOverflow));
        assert_eq!(dec(&[0x80]), Err(DecodeError::UnexpectedEnd));
        assert_eq!(dec(&[]), Err(DecodeError::UnexpectedEnd));
        assert_eq!(dec(&[1, 2]), Err(DecodeError::TrailingBytes));
    }

    #[test]
    fn varint_exhaustive_small_values_are_unique() {
        // Every encoding of length ≤ 2 decodes to at most one value and re-encodes
        // to itself (uniqueness of encodings).
        for a in 0..=255u8 {
            if let Ok(v) = dec(&[a]) {
                assert_eq!(enc(v), [a]);
            }
            for b in 0..=255u8 {
                if let Ok(v) = dec(&[a, b]) {
                    assert_eq!(enc(v), [a, b]);
                }
            }
        }
    }

    #[test]
    fn counts_are_bounded() {
        let mut r = Reader::new(&[5]);
        assert_eq!(
            r.count("x", 1, 4),
            Err(DecodeError::CountOutOfRange {
                what: "x",
                count: 5
            })
        );
        let mut r = Reader::new(&[0]);
        assert!(r.count("x", 1, 4).is_err());
    }
}
