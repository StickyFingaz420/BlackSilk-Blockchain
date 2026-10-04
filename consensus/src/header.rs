//! Block header and its canonical encoding (spec §2).

use crate::hash::{Hash, H};

/// Length of a serialized header in bytes.
pub const HEADER_SIZE: usize = 172;

/// The header version of the first epoch of every built-in schedule
/// ([`crate::schedule::V3`]), and so of every genesis header. The version a
/// header must carry is that of the epoch at its height
/// ([`crate::ChainParams::epoch_at`]).
pub const HEADER_VERSION: u32 = 1;

/// A block header (docs/consensus.md §2).
///
/// `Default` is the all-zero header (not a valid header of any network):
/// tests write `..Default::default()` for the fields they do not care about.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct BlockHeader {
    pub version: u32,
    pub height: u64,
    pub prev_id: Hash,
    pub timestamp: u64,
    pub difficulty: u64,
    pub tx_root: Hash,
    /// The number of v1 outputs of the chain through this block, coinbase
    /// outputs included (genesis: 0). Rule B-OMR (docs/blocks.md §5).
    pub output_count: u64,
    /// The root of the output Merkle mountain range over those outputs in
    /// global-index order (docs/consensus.md §7.1; all zero for none). Rule
    /// B-OMR.
    pub output_root: Hash,
    /// The PX commitment tree's root after this block (docs/px.md §5; the
    /// encoding of `blacksilk_tx::px::digest_bytes`). Rule B-PXR.
    pub px_root: Hash,
    pub nonce: u64,
}

/// Offset of the nonce within the serialized header (its last field).
pub const NONCE_OFFSET: usize = 164;

/// Length of the proof-of-work input, the mining blob (docs/consensus.md §3).
pub const POW_BLOB_SIZE: usize = 47;
/// The constant first bytes of the mining blob.
pub const POW_BLOB_TAG: &[u8; 7] = b"BSilk/1";
/// Offset of the nonce (u64, little-endian) within the mining blob: byte 39,
/// where stock xmrig writes its 4-byte RandomX nonce (it iterates bytes
/// 39..43; a pool server owns bytes 43..47 as extranonce).
pub const POW_NONCE_OFFSET: usize = 39;
/// The tag name of the mining hash (under `"BlackSilk/v1/"`; in
/// `blacksilk_crypto::hash::tags::CONSENSUS` as `MINING_HASH`).
pub const MINING_HASH_TAG: &str = "mining-hash";

impl BlockHeader {
    /// Canonical 172-byte encoding. This is also the RandomX input.
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut b = [0u8; HEADER_SIZE];
        b[0..4].copy_from_slice(&self.version.to_le_bytes());
        b[4..12].copy_from_slice(&self.height.to_le_bytes());
        b[12..44].copy_from_slice(&self.prev_id);
        b[44..52].copy_from_slice(&self.timestamp.to_le_bytes());
        b[52..60].copy_from_slice(&self.difficulty.to_le_bytes());
        b[60..92].copy_from_slice(&self.tx_root);
        b[92..100].copy_from_slice(&self.output_count.to_le_bytes());
        b[100..132].copy_from_slice(&self.output_root);
        b[132..164].copy_from_slice(&self.px_root);
        b[NONCE_OFFSET..HEADER_SIZE].copy_from_slice(&self.nonce.to_le_bytes());
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
            output_count: u64_at(92),
            output_root: b[100..132].try_into().unwrap(),
            px_root: b[132..164].try_into().unwrap(),
            nonce: u64_at(NONCE_OFFSET),
        })
    }

    /// `mining_hash = H32("mining-hash", LE32(network_id) ‖ header[0..NONCE_OFFSET])`:
    /// every header field but the nonce, and the network.
    pub fn mining_hash(&self, network_id: u32) -> Hash {
        H::tagged(MINING_HASH_TAG)
            .chain(&network_id.to_le_bytes())
            .chain(&self.to_bytes()[..NONCE_OFFSET])
            .finish()
    }

    /// The proof-of-work input (docs/consensus.md §3): `"BSilk/1" ‖
    /// mining_hash ‖ LE64(nonce)`, 47 bytes. Derived by every node from the
    /// header, never transmitted.
    pub fn pow_blob(&self, network_id: u32) -> [u8; POW_BLOB_SIZE] {
        let mut b = [0u8; POW_BLOB_SIZE];
        b[..POW_NONCE_OFFSET - 32].copy_from_slice(POW_BLOB_TAG);
        b[POW_NONCE_OFFSET - 32..POW_NONCE_OFFSET].copy_from_slice(&self.mining_hash(network_id));
        b[POW_NONCE_OFFSET..].copy_from_slice(&self.nonce.to_le_bytes());
        b
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
            output_count: 77,
            output_root: [10; 32],
            px_root: [11; 32],
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
        assert_eq!(BlockHeader::from_bytes(&bytes[..HEADER_SIZE - 1]), None);
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
        let mut m = h;
        m.output_count += 1;
        assert_ne!(id, m.id(1));
        let mut m = h;
        m.output_root[0] ^= 1;
        assert_ne!(id, m.id(1));
        let mut m = h;
        m.px_root[31] ^= 1;
        assert_ne!(id, m.id(1));
    }

    /// The mining blob: tag, mining hash, nonce; the hash commits to every
    /// field but the nonce and to the network, the nonce is only in the
    /// blob's last 8 bytes.
    #[test]
    fn the_mining_blob_commits_to_every_field_and_the_network() {
        let h = sample();
        let b = h.pow_blob(1);
        assert_eq!(&b[..7], b"BSilk/1");
        assert_eq!(b[7..39], h.mining_hash(1));
        assert_eq!(b[POW_NONCE_OFFSET..], 0xDEAD_BEEFu64.to_le_bytes());
        assert_ne!(h.mining_hash(1), h.mining_hash(2), "network separation");
        let mut n = h;
        n.nonce += 1;
        assert_eq!(n.mining_hash(1), h.mining_hash(1));
        assert_eq!(n.pow_blob(1)[..POW_NONCE_OFFSET], b[..POW_NONCE_OFFSET]);
        type Set = fn(&mut BlockHeader);
        let fields: [Set; 9] = [
            |h| h.version ^= 1,
            |h| h.height ^= 1,
            |h| h.prev_id[3] ^= 1,
            |h| h.timestamp ^= 1,
            |h| h.difficulty ^= 1,
            |h| h.tx_root[3] ^= 1,
            |h| h.output_count ^= 1,
            |h| h.output_root[3] ^= 1,
            |h| h.px_root[3] ^= 1,
        ];
        for (i, set) in fields.into_iter().enumerate() {
            let mut m = h;
            set(&mut m);
            assert_ne!(m.mining_hash(1), h.mining_hash(1), "field {i}");
        }
        // The definition, written out.
        let mut pre = vec![(13 + 11) as u8];
        pre.extend_from_slice(b"BlackSilk/v1/mining-hash");
        pre.extend_from_slice(&1u32.to_le_bytes());
        pre.extend_from_slice(&h.to_bytes()[..164]);
        assert_eq!(h.mining_hash(1), H::new().chain(&pre).finish());
    }

    /// Every field has its own bytes: setting one field changes exactly its
    /// range of the encoding (docs/consensus.md §2).
    #[test]
    fn field_offsets() {
        let z = BlockHeader::default().to_bytes();
        type Set = fn(&mut BlockHeader);
        let ranges: [(Set, std::ops::Range<usize>); 10] = [
            (|h| h.version = u32::MAX, 0..4),
            (|h| h.height = u64::MAX, 4..12),
            (|h| h.prev_id = [0xff; 32], 12..44),
            (|h| h.timestamp = u64::MAX, 44..52),
            (|h| h.difficulty = u64::MAX, 52..60),
            (|h| h.tx_root = [0xff; 32], 60..92),
            (|h| h.output_count = u64::MAX, 92..100),
            (|h| h.output_root = [0xff; 32], 100..132),
            (|h| h.px_root = [0xff; 32], 132..164),
            (|h| h.nonce = u64::MAX, NONCE_OFFSET..HEADER_SIZE),
        ];
        for (set, r) in ranges {
            let mut h = BlockHeader::default();
            set(&mut h);
            let b = h.to_bytes();
            for i in 0..HEADER_SIZE {
                assert_eq!(b[i] != z[i], r.contains(&i), "byte {i} of {r:?}");
            }
        }
    }
}
