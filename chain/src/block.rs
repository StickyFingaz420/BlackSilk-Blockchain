//! Block format (docs/blocks.md §4).

use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{BlockHeader, Hash, HEADER_SIZE};
use blacksilk_tx::codec::{DecodeError as TxDecodeError, Reader, Writer};
use blacksilk_tx::types::Transaction;

/// Maximum encoded block size.
pub const MAX_BLOCK_BYTES: usize = 1_000_000;
/// Maximum number of transactions in a block (bounded before allocating).
pub const MAX_BLOCK_TXS: u64 = 10_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    pub txs: Vec<Transaction>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockDecodeError {
    TooLarge,
    Header,
    Tx { index: usize, error: TxDecodeError },
    Framing(TxDecodeError),
}

impl Block {
    pub fn id(&self, network_id: u32) -> Hash {
        self.header.id(network_id)
    }

    /// Merkle root of the transaction hashes, which must equal `header.tx_root`.
    pub fn compute_tx_root(&self) -> Hash {
        let ids: Vec<Hash> = self.txs.iter().map(Transaction::hash).collect();
        tx_root(&ids)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&self.header.to_bytes());
        w.varint(self.txs.len() as u64);
        for tx in &self.txs {
            let bytes = tx.encode();
            w.varint(bytes.len() as u64);
            w.bytes(&bytes);
        }
        w.into_bytes()
    }

    /// Strict decoding: size limit, exact header, bounded counts, every transaction
    /// strictly decoded from exactly its length prefix, no trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, BlockDecodeError> {
        if bytes.len() > MAX_BLOCK_BYTES {
            return Err(BlockDecodeError::TooLarge);
        }
        let mut r = Reader::new(bytes);
        let header_bytes: [u8; HEADER_SIZE] = r.array().map_err(BlockDecodeError::Framing)?;
        let header = BlockHeader::from_bytes(&header_bytes).ok_or(BlockDecodeError::Header)?;
        let n = r
            .count("block transactions", 1, MAX_BLOCK_TXS)
            .map_err(BlockDecodeError::Framing)?;
        let mut txs = Vec::with_capacity(n.min(1024));
        for index in 0..n {
            let len = r.varint().map_err(BlockDecodeError::Framing)? as usize;
            let start = r.position();
            let end = start
                .checked_add(len)
                .filter(|&e| e <= bytes.len())
                .ok_or(BlockDecodeError::Framing(TxDecodeError::UnexpectedEnd))?;
            let tx = Transaction::decode(&bytes[start..end])
                .map_err(|error| BlockDecodeError::Tx { index, error })?;
            r.skip(len).map_err(BlockDecodeError::Framing)?;
            txs.push(tx);
        }
        r.finish().map_err(BlockDecodeError::Framing)?;
        Ok(Self { header, txs })
    }

    /// Sum of the transaction weights.
    pub fn weight(&self) -> u128 {
        self.txs.iter().map(|t| t.weight() as u128).sum()
    }
}
