//! In-memory transaction state: the global output set, spent key images and
//! used one-time keys, with per-block undo for reorganizations.
//!
//! This is the reference implementation of [`ChainView`]. The node's persistent
//! store must behave identically. It is also what the tests use.

use crate::types::{Hash, Transaction};
use crate::validate::{ChainView, OutputRecord};
use blacksilk_crypto::Point;
use std::collections::HashSet;

#[derive(Default)]
pub struct MemoryChain {
    outputs: Vec<OutputRecord>,
    key_images: HashSet<[u8; 32]>,
    one_time_keys: HashSet<[u8; 32]>,
    blocks: Vec<BlockUndo>,
}

struct BlockUndo {
    first_output: usize,
    key_images: Vec<[u8; 32]>,
    tx_hashes: Vec<Hash>,
}

impl MemoryChain {
    pub fn new() -> Self {
        Self::default()
    }

    /// Height of the next block to apply (= number of applied blocks).
    pub fn next_height(&self) -> u64 {
        self.blocks.len() as u64
    }

    pub fn output_count(&self) -> u64 {
        self.outputs.len() as u64
    }

    /// Global index of the first output created at `height`.
    pub fn first_output_at(&self, height: u64) -> Option<u64> {
        self.blocks
            .get(height as usize)
            .map(|b| b.first_output as u64)
    }

    /// Cumulative output counts per block: `[outputs in blocks ≤ 0, ≤ 1, …]`.
    pub fn cumulative_outputs(&self) -> Vec<u64> {
        let mut out: Vec<u64> = self
            .blocks
            .iter()
            .skip(1)
            .map(|b| b.first_output as u64)
            .collect();
        out.push(self.outputs.len() as u64);
        out
    }

    /// Hashes of the transactions of the block at `height`.
    pub fn block_tx_hashes(&self, height: u64) -> Option<&[Hash]> {
        self.blocks
            .get(height as usize)
            .map(|b| b.tx_hashes.as_slice())
    }

    /// Applies an already validated block at [`Self::next_height`]. Returns the
    /// global index of its first output.
    pub fn apply_block(&mut self, txs: &[Transaction]) -> u64 {
        let height = self.next_height();
        let first_output = self.outputs.len();
        let mut key_images = Vec::new();
        for tx in txs {
            if let Transaction::Transfer(t) = tx {
                for input in &t.inputs {
                    self.key_images.insert(*input.key_image.bytes());
                    key_images.push(*input.key_image.bytes());
                }
            }
            for key in tx.output_keys() {
                self.one_time_keys.insert(*key.one_time_key.bytes());
                self.outputs.push(OutputRecord {
                    key,
                    height,
                    coinbase: tx.is_coinbase(),
                });
            }
        }
        self.blocks.push(BlockUndo {
            first_output,
            key_images,
            tx_hashes: txs.iter().map(Transaction::hash).collect(),
        });
        first_output as u64
    }

    /// Disconnects the tip block. Returns `false` if there is none.
    pub fn undo_block(&mut self) -> bool {
        let Some(undo) = self.blocks.pop() else {
            return false;
        };
        for rec in self.outputs.drain(undo.first_output..) {
            self.one_time_keys.remove(rec.key.one_time_key.bytes());
        }
        for ki in &undo.key_images {
            self.key_images.remove(ki);
        }
        true
    }
}

impl ChainView for MemoryChain {
    fn output(&self, global_index: u64) -> Option<OutputRecord> {
        self.outputs
            .get(usize::try_from(global_index).ok()?)
            .copied()
    }

    fn is_key_image_spent(&self, key_image: &Point) -> bool {
        self.key_images.contains(key_image.bytes())
    }

    fn has_one_time_key(&self, key: &Point) -> bool {
        self.one_time_keys.contains(key.bytes())
    }
}
