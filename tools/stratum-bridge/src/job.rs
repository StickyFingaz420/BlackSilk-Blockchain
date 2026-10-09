//! Jobs: the node's block with a per-job extranonce, as xmrig sees it.
//!
//! The header nonce is a little-endian u64 at blob bytes 39..47
//! (`POW_NONCE_OFFSET`, docs/consensus.md §3). xmrig writes only a
//! little-endian u32 at 39..43, the low half. The bridge owns 43..47: a fresh
//! random extranonce `X` per job, the high half. A share's header nonce is
//! `(X << 32) | u32::from_le_bytes(<the 4 submitted bytes>)`.
//!
//! The blob is always the node's own `BlockHeader::pow_blob`; nothing here
//! re-implements it.

use blacksilk_chain::block::Block;
use blacksilk_consensus::{BlockHeader, Hash, PowBlob, POW_NONCE_OFFSET};

/// Bytes xmrig writes: `blob[39..43]`.
pub const XMRIG_NONCE_BYTES: usize = 4;

/// One job: what a session was sent, and everything a share of it is checked
/// against. Nothing of it comes from the client.
#[derive(Clone, Debug)]
pub struct Job {
    /// The `job_id` (a process-wide counter, sent as a decimal string).
    pub id: u64,
    /// The session the job was sent to.
    pub session: String,
    /// The block, its header nonce `X << 32`.
    pub block: Block,
    /// The extranonce: blob bytes 43..47.
    pub extranonce: u32,
    /// The RandomX key: the template's `seed_id`.
    pub seed: Hash,
    /// The block's difficulty (the header's, from the template).
    pub block_diff: u64,
    /// `max(block_diff, the session's floor)`: only shapes xmrig's local
    /// filter (the target); acceptance is decided by `block_diff`. In the
    /// floor regime (`share_diff > block_diff`) a hash that xmrig filters
    /// out locally can still meet `block_diff`: that valid block is never
    /// submitted, lost by design. Acceptable for the regtest gate (critique
    /// M1): the floor only keeps the light-mode verification from being
    /// flooded.
    pub share_diff: u64,
    /// The template's `prev_id`: the job is stale once the node's best tip
    /// (as the bridge last saw it in a template) differs.
    pub tip_id: Hash,
    /// The algorithm name the job is labelled with.
    pub algo: &'static str,
    /// The network id the blob commits to.
    pub network_id: u32,
}

impl Job {
    pub fn height(&self) -> u64 {
        self.block.header.height
    }

    /// The blob served: `pow_blob` of the header with nonce `X << 32`, so bytes
    /// 39..43 are zero (no nicehash mode in xmrig) and 43..47 are `X`.
    pub fn blob(&self) -> PowBlob {
        self.block.header.pow_blob(self.network_id)
    }

    /// The header of a share with xmrig's 4 nonce bytes.
    pub fn header_for(&self, nonce32: u32) -> BlockHeader {
        let mut h = self.block.header;
        h.nonce = full_nonce(self.extranonce, nonce32);
        h
    }

    /// The block of a share with xmrig's 4 nonce bytes.
    pub fn block_for(&self, nonce32: u32) -> Block {
        let mut b = self.block.clone();
        b.header = self.header_for(nonce32);
        b
    }
}

/// `(X << 32) | n`.
pub fn full_nonce(extranonce: u32, nonce32: u32) -> u64 {
    (u64::from(extranonce) << 32) | u64::from(nonce32)
}

/// The header for a job: the built block's header with nonce `X << 32`.
pub fn with_extranonce(mut block: Block, extranonce: u32) -> Block {
    block.header.nonce = full_nonce(extranonce, 0);
    block
}

/// Decodes a submit's `nonce`: exactly 8 hex characters, decoded to 4 bytes,
/// read as a little-endian u32 (the bytes xmrig wrote at blob 39..43). Never
/// parsed as a number.
pub fn decode_nonce(s: &str) -> Option<u32> {
    if s.len() != 2 * XMRIG_NONCE_BYTES {
        return None;
    }
    let bytes: [u8; XMRIG_NONCE_BYTES] = hex::decode(s).ok()?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

/// Decodes a submit's `result`: exactly 64 hex characters.
pub fn decode_result(s: &str) -> Option<Hash> {
    if s.len() != 64 {
        return None;
    }
    hex::decode(s).ok()?.try_into().ok()
}

/// The served blob with xmrig's raw nonce bytes written at 39..43: what xmrig
/// hashes. Must equal `job.header_for(n).pow_blob(..)`; the verifier checks
/// that for every share.
pub fn blob_with_xmrig_nonce(blob: &PowBlob, nonce_bytes: [u8; XMRIG_NONCE_BYTES]) -> PowBlob {
    let mut b = *blob;
    b[POW_NONCE_OFFSET..POW_NONCE_OFFSET + XMRIG_NONCE_BYTES].copy_from_slice(&nonce_bytes);
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use blacksilk_consensus::header::POW_BLOB_TAG;
    use blacksilk_consensus::{ChainParams, POW_BLOB_SIZE};

    fn job(extranonce: u32) -> Job {
        let header = BlockHeader {
            version: 1,
            height: 12,
            prev_id: [7; 32],
            timestamp: 1_700_000_123,
            difficulty: 5,
            tx_root: [1; 32],
            output_count: 3,
            output_root: [2; 32],
            px_root: [4; 32],
            nonce: 0,
        };
        Job {
            id: 1,
            session: "s".into(),
            block: with_extranonce(
                Block {
                    header,
                    txs: vec![],
                },
                extranonce,
            ),
            extranonce,
            seed: [9; 32],
            block_diff: 5,
            share_diff: 5,
            tip_id: [7; 32],
            algo: "rx/blacksilk",
            network_id: ChainParams::regtest().network_id,
        }
    }

    /// `01000000` is nonce 1 (little-endian bytes), whatever the
    /// extranonce; the high half is the extranonce.
    #[test]
    fn nonce_byte_order() {
        assert_eq!(decode_nonce("01000000"), Some(1));
        assert_eq!(decode_nonce("00000001"), Some(1 << 24));
        assert_eq!(decode_nonce("a1020000"), Some(0x02a1));
        assert_eq!(decode_nonce("DEADBEEF"), Some(0xefbe_adde));
        let j = job(0x1122_3344);
        let h = j.header_for(decode_nonce("01000000").unwrap());
        assert_eq!(h.nonce & 0xffff_ffff, 1);
        assert_eq!(h.nonce >> 32, 0x1122_3344);
        let blob = h.pow_blob(j.network_id);
        assert_eq!(&blob[39..43], &[1, 0, 0, 0]);
        assert_eq!(&blob[43..47], &0x1122_3344u32.to_le_bytes());
    }

    #[test]
    fn malformed_nonces_and_results() {
        for bad in [
            "",
            "0100000",
            "010000000",
            "zz000000",
            "0x010000",
            "01 00000",
            "é1000000",
        ] {
            assert_eq!(decode_nonce(bad), None, "{bad:?}");
        }
        assert!(decode_result(&"ab".repeat(32)).is_some());
        assert!(decode_result(&"ab".repeat(31)).is_none());
        assert!(decode_result(&format!("{}g", "a".repeat(63))).is_none());
    }

    /// The served blob: 47 bytes starting with "BSilk/1", bytes 39..43 zero,
    /// 43..47 the extranonce; with xmrig's 4 bytes written at 39 it equals
    /// the node's `pow_blob` of the rebuilt header.
    #[test]
    fn job_blob_and_reconstruction() {
        for x in [0u32, 1, 0xdead_beef, u32::MAX] {
            let j = job(x);
            let blob = j.blob();
            assert_eq!(blob.len(), POW_BLOB_SIZE);
            assert_eq!(&blob[..7], POW_BLOB_TAG);
            assert_eq!(&blob[39..43], &[0, 0, 0, 0]);
            assert_eq!(&blob[43..47], &x.to_le_bytes());
            assert_eq!(&blob[7..39], &j.block.header.mining_hash(j.network_id));
            for raw in [[0u8, 0, 0, 0], [1, 0, 0, 0], [0xff, 0xee, 0xdd, 0xcc]] {
                let n = u32::from_le_bytes(raw);
                assert_eq!(
                    blob_with_xmrig_nonce(&blob, raw),
                    j.header_for(n).pow_blob(j.network_id)
                );
                assert_eq!(j.block_for(n).header, j.header_for(n));
            }
        }
    }
}
