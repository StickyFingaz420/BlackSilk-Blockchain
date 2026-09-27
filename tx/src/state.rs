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
    blocks: Vec<BlockUndo>,
    px: PxState,
    registry: HashMap<Digest, Vec<RegisteredFunction>>,
    /// `(height, contract id)` of every registration, in block order.
    px_contract_log: Vec<(u64, Digest)>,
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

    /// Number of PX output records (= commitments appended to the tree).
    pub fn px_record_count(&self) -> u64 {
        self.px_records.len() as u64
    }

    /// At most `limit` PX output records starting at record index (= tree
    /// position) `from`, borrowed: nothing is copied. Empty when `from` is at
    /// or past the end. This is what the RPC pages over; its cost is
    /// proportional to the slice, not to the chain.
    pub fn px_record_slice(&self, from: u64, limit: usize) -> &[PxRecordEntry] {
        let len = self.px_records.len();
        let start = usize::try_from(from).map_or(len, |f| f.min(len));
        let end = start.saturating_add(limit).min(len);
        &self.px_records[start..end]
    }

    /// PX output records created at heights `from..=to` (for wallets and
    /// tests). Records are in block order, so the range is found by binary
    /// search; only the matching records are cloned.
    pub fn px_records(&self, from: u64, to: u64) -> Vec<PxRecordEntry> {
        let (start, end) = height_range(&self.px_records, |r| r.height, from, to);
        self.px_records[start..end].to_vec()
    }

    /// Nullifiers published at heights `from..=to` (for wallets).
    pub fn px_nullifiers(&self, from: u64, to: u64) -> Vec<(u64, Digest)> {
        let (start, end) = height_range(&self.px_nullifiers, |(h, _)| *h, from, to);
        self.px_nullifiers[start..end].to_vec()
    }

    /// The registered functions of a contract.
    pub fn px_contract(&self, contract: &Digest) -> Option<&[RegisteredFunction]> {
        self.registry.get(contract).map(|v| v.as_slice())
    }

    /// Every registration `(height, contract id)`, in block order (for
    /// wallets, which download the whole list).
    pub fn px_contract_log(&self) -> &[(u64, Digest)] {
        &self.px_contract_log
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
                    self.px_contract_log.push((height, id));
                    contracts.push(id);
                }
                _ => {}
            }
            for key in tx.output_keys() {
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
        // Outputs are records by global index; one-time keys may repeat
        // across them (D8 option B), and no key set is kept.
        self.outputs.truncate(undo.first_output);
        for ki in &undo.key_images {
            self.key_images.remove(ki);
        }
        if let Some(px) = undo.px {
            self.px.undo(px);
        }
        for c in &undo.contracts {
            self.registry.remove(c);
        }
        let kept = self.px_contract_log.len() - undo.contracts.len();
        self.px_contract_log.truncate(kept);
        self.px_records.truncate(undo.px_records);
        self.px_nullifiers.truncate(undo.px_nullifiers);
        true
    }
}

/// The index range of the entries of `log` (sorted by height, as every log in
/// [`MemoryChain`] is: entries are appended in block order and removed from the
/// end) with a height in `from..=to`.
fn height_range<T>(log: &[T], height: impl Fn(&T) -> u64, from: u64, to: u64) -> (usize, usize) {
    let start = log.partition_point(|e| height(e) < from);
    let end = log.partition_point(|e| height(e) <= to).max(start);
    (start, end)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::px::PxTx;

    /// A PX transaction that the state accepts (`apply_block` trusts that the
    /// block was validated, so no proof is needed): two fresh nullifiers,
    /// anchored at the current root, two commitments.
    fn synthetic_px(chain: &MemoryChain, tag: u32) -> Transaction {
        Transaction::Px(Box::new(PxTx {
            inputs: vec![],
            outputs: vec![],
            payouts: vec![],
            fee: 0,
            bridge_in: 0,
            bridge_out: 0,
            anchor: chain.px().root(),
            nullifiers: [[tag, 1, 0, 0, 0, 0, 0, 0], [tag, 2, 0, 0, 0, 0, 0, 0]],
            commitments: [[tag, 3, 0, 0, 0, 0, 0, 0], [tag, 4, 0, 0, 0, 0, 0, 0]],
            ciphertexts: [vec![tag as u8; 3], vec![tag as u8; 4]],
            functions: vec![],
            pseudo_outs: vec![],
            range_proof: None,
            signatures: vec![],
            proof: vec![],
        }))
    }

    /// Blocks 0..=4 with 0, 1, 2, 0, 1 PX transactions: 8 records, two at
    /// height 1, four at height 2, two at height 4.
    fn chain() -> MemoryChain {
        let mut c = MemoryChain::new();
        let mut tag = 1;
        for n in [0, 1, 2, 0, 1] {
            let mut txs = Vec::new();
            for _ in 0..n {
                txs.push(synthetic_px(&c, tag));
                tag += 1;
            }
            c.apply_block(&txs);
        }
        c
    }

    #[test]
    fn record_slice_pages_the_record_log() {
        let c = chain();
        let all = c.px_records(0, u64::MAX);
        assert_eq!(c.px_record_count(), 8);
        assert_eq!(all.len(), 8);
        for (i, r) in all.iter().enumerate() {
            assert_eq!(r.position, i as u64, "records are in tree order");
        }
        // Paging with every limit reassembles the full list.
        for limit in 1..=9 {
            let mut paged = Vec::new();
            let mut from = 0;
            loop {
                let page = c.px_record_slice(from, limit);
                if page.is_empty() {
                    break;
                }
                assert!(page.len() <= limit);
                paged.extend_from_slice(page);
                from += page.len() as u64;
            }
            assert_eq!(paged, all, "limit {limit}");
        }
        // Bounds.
        assert_eq!(c.px_record_slice(3, 2), &all[3..5]);
        assert_eq!(c.px_record_slice(7, 100), &all[7..]);
        assert!(c.px_record_slice(8, 10).is_empty());
        assert!(c.px_record_slice(u64::MAX, usize::MAX).is_empty());
        assert!(c.px_record_slice(2, 0).is_empty());
        assert_eq!(c.px_record_slice(0, usize::MAX), &all[..]);
    }

    #[test]
    fn height_ranges_match_a_linear_filter() {
        let c = chain();
        let all = c.px_records(0, u64::MAX);
        let nfs = c.px_nullifiers(0, u64::MAX);
        assert_eq!(nfs.len(), 8);
        for from in 0..7 {
            for to in 0..7 {
                let want: Vec<_> = all
                    .iter()
                    .filter(|r| r.height >= from && r.height <= to)
                    .cloned()
                    .collect();
                assert_eq!(c.px_records(from, to), want, "{from}..={to}");
                let want: Vec<_> = nfs
                    .iter()
                    .filter(|(h, _)| *h >= from && *h <= to)
                    .copied()
                    .collect();
                assert_eq!(c.px_nullifiers(from, to), want, "{from}..={to}");
            }
        }
        assert_eq!(c.px_records(2, 2).len(), 4);
        assert!(c.px_records(5, 1).is_empty());
    }

    #[test]
    fn undo_shrinks_the_record_log() {
        let mut c = chain();
        let kept = c.px_records(0, 2);
        assert_eq!(kept.len(), 6);
        assert!(c.undo_block()); // height 4: two records
        assert_eq!(c.px_record_count(), 6);
        assert!(c.px_record_slice(6, 10).is_empty());
        assert!(c.undo_block()); // height 3: none
        assert_eq!(c.px_record_slice(0, 10), &kept[..]);
        assert!(c.undo_block()); // height 2: four
        assert_eq!(c.px_record_count(), 2);
    }
}
