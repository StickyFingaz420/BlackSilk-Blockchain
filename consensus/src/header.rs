//! Block header and its canonical encoding (spec §2).

use crate::hash::{Hash, H};

/// Length of a serialized header in bytes.
pub const HEADER_SIZE: usize = 100;

/// The only header version currently valid.
pub const HEADER_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BlockHeader {
    pub version: u32,
    pub height: u64,
    pub prev_id: Hash,
    pub timestamp: u64,
    pub difficulty: u64,
    pub tx_root: Hash,
    pub nonce: u64,
}

/// Offset of the nonce within the serialized header; miners patch it in place.
pub const NONCE_OFFSET: usize = 92;

impl BlockHeader {
    /// Canonical 100-byte encoding. This is also the RandomX input.
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut b = [0u8; HEADER_SIZE];
        b[0..4].copy_from_slice(&self.version.to_le_bytes());
        b[4..12].copy_from_slice(&self.height.to_le_bytes());
        b[12..44].copy_from_slice(&self.prev_id);
        b[44..52].copy_from_slice(&self.timestamp.to_le_bytes());
        b[52..60].copy_from_slice(&self.difficulty.to_le_bytes());
        b[60..92].copy_from_slice(&self.tx_root);
        b[NONCE_OFFSET..100].copy_from_slice(&self.nonce.to_le_bytes());
        b
    }

    /// Strict decoding: exactly [`HEADER_SIZE`] bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let b: &[u8; HEADER_SIZE] = bytes.try_into().ok()?;
        let u64_at = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        Some(Self {
            version: u32::from_le_bytes(b[0..4].try_into().unwrap()),
            height: u64_at(4),
            prev_id: b[12..44].try_into().unwrap(),
            timestamp: u64_at(44),
            difficulty: u64_at(52),
            tx_root: b[60..92].try_into().unwrap(),
            nonce: u64_at(NONCE_OFFSET),
        })
    }

    /// Block id on the network identified by `network_id`.
    pub fn id(&self, network_id: u32) -> Hash {
        H::new()
            .chain(b"BlackSilk/block-id")
            .chain(&network_id.to_le_bytes())
            .chain(&self.to_bytes())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> BlockHeader {
        BlockHeader {
            version: 1,
            height: 42,
            prev_id: [7; 32],
            timestamp: 1_800_000_000,
            difficulty: 12345,
            tx_root: [9; 32],
            nonce: 0xDEAD_BEEF,
        }
    }

    #[test]
    fn roundtrip_and_layout() {
        let h = sample();
        let bytes = h.to_bytes();
        assert_eq!(bytes.len(), HEADER_SIZE);
        assert_eq!(BlockHeader::from_bytes(&bytes), Some(h));
        assert_eq!(&bytes[NONCE_OFFSET..], &0xDEAD_BEEFu64.to_le_bytes());
    }

    #[test]
    fn strict_length() {
        let bytes = sample().to_bytes();
        assert_eq!(BlockHeader::from_bytes(&bytes[..99]), None);
        let mut long = bytes.to_vec();
        long.push(0);
        assert_eq!(BlockHeader::from_bytes(&long), None);
    }

    #[test]
    fn id_commits_to_every_field_and_network() {
        let h = sample();
        let id = h.id(1);
        assert_ne!(id, h.id(2), "network separation");
        let mut m = h;
        m.nonce += 1;
        assert_ne!(id, m.id(1));
        let mut m = h;
        m.tx_root[31] ^= 1;
        assert_ne!(id, m.id(1));
        let mut m = h;
        m.difficulty += 1;
        assert_ne!(id, m.id(1));
    }
}
