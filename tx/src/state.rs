//! In-memory transaction state: the global output set, spent key images and
//! used one-time keys, the PX state (tree, root window, nullifiers, pool), the
//! private-contract registry and the PX record log, with per-block undo for
//! reorganizations.
//!
//! This is the reference implementation of [`ChainView`]. The node's persistent
//! store must behave identically. It is also what the tests use.

use crate::types::{Hash, Transaction};
use crate::validate::{ChainView, OutputRecord};
use blacksilk_crypto::Point;
use blacksilk_px::state::{State as PxState, Undo as PxUndo};
use blacksilk_px_core::Digest;
use blacksilk_zkvm::air::trace::Budget;
use blacksilk_zkvm::Program;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// One PX output commitment, as wallets scan it (docs/px.md §11.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PxRecordEntry {
    pub height: u64,
    /// Position in the commitment tree.
    pub position: u64,
    pub commitment: Digest,
    pub ciphertext: Vec<u8>,
    /// The transaction's first nullifier and the output's slot: the
    /// recipient derives `rho` from them.
    pub nf0: Digest,
    pub slot: u32,
}

/// A registered function program.
#[derive(Clone)]
pub struct RegisteredFunction {
    pub program_id: [u8; 32],
    pub program: Arc<Program>,
    pub budget: Budget,
}

#[derive(Default)]
pub struct MemoryChain {
    outputs: Vec<OutputRecord>,
    key_images: HashSet<[u8; 32]>,
    one_time_keys: HashSet<[u8; 32]>,
    blocks: Vec<BlockUndo>,
    px: PxState,
    registry: HashMap<Digest, Vec<RegisteredFunction>>,
    px_records: Vec<PxRecordEntry>,
    /// `(height, nullifier)` in block order.
    px_nullifiers: Vec<(u64, Digest)>,
}

struct BlockUndo {
    first_output: usize,
    key_images: Vec<[u8; 32]>,
    tx_hashes: Vec<Hash>,
    px: Option<PxUndo>,
    contracts: Vec<Digest>,
    px_records: usize,
    px_nullifiers: usize,
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

    // ---- PX ----

    pub fn px(&self) -> &PxState {
        &self.px
    }

    /// PX output records created at heights `from..=to` (for wallets).
    pub fn px_records(&self, from: u64, to: u64) -> Vec<PxRecordEntry> {
        self.px_records
            .iter()
            .filter(|r| r.height >= from && r.height <= to)
            .cloned()
            .collect()
    }

    /// Nullifiers published at heights `from..=to` (for wallets).
    pub fn px_nullifiers(&self, from: u64, to: u64) -> Vec<(u64, Digest)> {
        self.px_nullifiers
            .iter()
            .filter(|(h, _)| *h >= from && *h <= to)
            .copied()
            .collect()
    }

    /// The registered functions of a contract.
    pub fn px_contract(&self, contract: &Digest) -> Option<&[RegisteredFunction]> {
        self.registry.get(contract).map(|v| v.as_slice())
    }

    /// Applies an already validated block at [`Self::next_height`]. Returns the
    /// global index of its first output.
    ///
    /// # Panics
    /// If the block's PX transactions violate the PX state rules, which block
    /// validation excludes.
    pub fn apply_block(&mut self, txs: &[Transaction]) -> u64 {
        let height = self.next_height();
        let first_output = self.outputs.len();
        let mut key_images = Vec::new();
        let (px_records, px_nullifiers) = (self.px_records.len(), self.px_nullifiers.len());
        let mut publics = Vec::new();
        let mut contracts = Vec::new();
        for tx in txs {
            for ki in tx.key_images() {
                self.key_images.insert(*ki.bytes());
                key_images.push(*ki.bytes());
            }
            match tx {
                Transaction::Px(t) => {
                    let position = self.px.size() + 2 * publics.len() as u64;
                    for (j, (cm, ct)) in t.commitments.iter().zip(&t.ciphertexts).enumerate() {
                        self.px_records.push(PxRecordEntry {
                            height,
                            position: position + j as u64,
                            commitment: *cm,
                            ciphertext: ct.clone(),
                            nf0: t.nullifiers[0],
                            slot: j as u32,
                        });
                    }
                    for nf in &t.nullifiers {
                        self.px_nullifiers.push((height, *nf));
                    }
                    publics.push(t.public());
                }
                Transaction::PxDeploy(t) => {
                    let id = t.contract_id();
                    let functions = t
                        .load_programs()
                        .expect("validated deploys load")
                        .into_iter()
                        .map(|(program, budget)| RegisteredFunction {
                            program_id: program.id(),
                            program,
                            budget,
                        })
                        .collect();
                    self.registry.insert(id, functions);
                    contracts.push(id);
                }
                _ => {}
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
        // Every block records a root (the root window counts blocks).
        let px = self
            .px
            .apply_block(&publics)
            .expect("block validation enforces the PX state rules");
        self.blocks.push(BlockUndo {
            first_output,
            key_images,
            tx_hashes: txs.iter().map(Transaction::hash).collect(),
            px: Some(px),
            contracts,
            px_records,
            px_nullifiers,
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
        if let Some(px) = undo.px {
            self.px.undo(px);
        }
        for c in &undo.contracts {
            self.registry.remove(c);
        }
        self.px_records.truncate(undo.px_records);
        self.px_nullifiers.truncate(undo.px_nullifiers);
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

    fn px_is_recent_root(&self, anchor: &Digest) -> bool {
        self.px.is_recent_root(anchor)
    }

    fn px_nullifier_spent(&self, nf: &Digest) -> bool {
        self.px.is_spent(nf)
    }

    fn px_pool(&self) -> u128 {
        self.px.pool()
    }

    fn px_function(
        &self,
        contract: &Digest,
        program_id: &[u8; 32],
    ) -> Option<(Arc<Program>, Budget)> {
        self.registry
            .get(contract)?
            .iter()
            .find(|f| &f.program_id == program_id)
            .map(|f| (f.program.clone(), f.budget))
    }

    fn px_contract_exists(&self, contract: &Digest) -> bool {
        self.registry.contains_key(contract)
    }
}
