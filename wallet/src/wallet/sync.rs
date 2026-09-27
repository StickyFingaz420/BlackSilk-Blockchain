//! Synchronization with a node: network checks, rewinds, block scanning and
//! balances.

use super::{
    network_name, Balance, HeldOutput, HeldRecord, Holdings, StoredOutput, Wallet, WalletError,
    KEPT_BLOCK_IDS,
};
use crate::node::NodeApi;
use blacksilk_chain::block::Block;
use blacksilk_crypto::stealth::ReceivedOutput;
use blacksilk_tx::params::{COINBASE_MATURITY, SPENDABLE_AGE};
use blacksilk_tx::scan::scan_block;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};

impl Wallet {
    // ---- sync ----
    pub(super) fn check_network(
        &self,
        node: &dyn NodeApi,
    ) -> Result<blacksilk_rpc::Info, WalletError> {
        let info = node.info().map_err(WalletError::Node)?;
        if info.network != network_name(self.network) {
            return Err(WalletError::WrongNetwork {
                wallet: network_name(self.network).into(),
                node: info.network,
            });
        }
        // The same network name is not enough: a release candidate, a
        // rehearsal or a retired identity uses it too (R15-3).
        let ours = hex::encode(self.genesis_id);
        match &info.genesis_id {
            Some(g) if g.eq_ignore_ascii_case(&ours) => {}
            other => {
                return Err(WalletError::WrongGenesis {
                    wallet: ours,
                    node: other.clone().unwrap_or_default(),
                })
            }
        }
        Ok(info)
    }

    /// Removes everything learned from blocks above `height`. A record
    /// credited for its key image that goes with them hands the credit back
    /// to a duplicate below the fork (RTW1-4).
    fn rewind(&mut self, height: u64) {
        self.outputs.retain(|o| o.height <= height);
        for o in &mut self.outputs {
            if o.spent_height.is_some_and(|h| h > height) {
                o.spent_height = None;
            }
        }
        self.elect_credited();
        self.block_ids.retain(|h, _| *h <= height);
        self.index.rewind(height);
        self.px.rewind(height);
        self.synced_height = height;
    }

    /// Scans new blocks. Detects reorganizations by comparing stored block ids with
    /// the node's, and rewinds to the fork point. Returns the new synced height.
    pub fn sync(&mut self, node: &dyn NodeApi) -> Result<u64, WalletError> {
        let info = self.check_network(node)?;
        if info.header_height > info.height {
            return Err(WalletError::Node(format!(
                "the node is still synchronizing ({} of {} blocks); try again later",
                info.height, info.header_height
            )));
        }
        // Reorg detection: walk back from our tip until our block id matches the node's.
        let fresh = self.block_ids.is_empty();
        while self.synced_height >= self.restore_height && self.synced_height > 0 {
            let Some(ours) = self.block_ids.get(&self.synced_height).copied() else {
                if fresh {
                    break;
                }
                // Fork deeper than the kept window: rescan from the restore height.
                let h = self.restore_height.saturating_sub(1);
                self.rewind(h);
                break;
            };
            let theirs = if self.synced_height <= info.height {
                node.blocks(self.synced_height, 1)
                    .map_err(WalletError::Node)?
                    .blocks
                    .first()
                    .and_then(|b| blacksilk_rpc::parse_hash(&b.id))
            } else {
                None
            };
            if theirs == Some(ours) {
                break;
            }
            let h = self.synced_height - 1;
            self.rewind(h);
        }

        let mut from = self.synced_height + 1;
        while from <= info.height {
            let batch = node
                .blocks(from, blacksilk_rpc::MAX_BLOCKS_PER_REQUEST)
                .map_err(WalletError::Node)?;
            if batch.blocks.is_empty() {
                break;
            }
            for entry in batch.blocks {
                if entry.height != from {
                    return Err(WalletError::BadNodeData(format!(
                        "expected block {from}, got {}",
                        entry.height
                    )));
                }
                let bytes = hex::decode(&entry.hex)
                    .map_err(|_| WalletError::BadNodeData("block hex".into()))?;
                let block = Block::decode(&bytes)
                    .map_err(|e| WalletError::BadNodeData(format!("{e:?}")))?;
                let id = block.id(info.network_id);
                if hex::encode(id) != entry.id || block.compute_tx_root() != block.header.tx_root {
                    return Err(WalletError::BadNodeData(format!(
                        "block {from} does not match its id"
                    )));
                }
                // Each block must extend the one before it (review F6). Proof of
                // work is not checked here: a wallet must trust its node for that.
                if let Some(prev) = self.block_ids.get(&(entry.height - 1)) {
                    if block.header.prev_id != *prev {
                        return Err(WalletError::BadNodeData(format!(
                            "block {from} does not extend the previous block"
                        )));
                    }
                }
                self.apply_block(&block, entry.height, entry.first_output);
                self.block_ids.insert(entry.height, id);
                self.synced_height = entry.height;
                from += 1;
            }
            while self.block_ids.len() > KEPT_BLOCK_IDS {
                let first = *self.block_ids.keys().next().expect("non-empty");
                self.block_ids.remove(&first);
            }
        }
        let synced = self.synced_height;
        self.refresh_pending(node);
        self.px.sync_commitments(node, synced)?;
        self.px.sync_contracts(node, synced)?;
        Ok(self.synced_height)
    }

    fn apply_block(&mut self, block: &Block, height: u64, first_output: u64) {
        // Every output, in the chain's global order (as `scan_block` counts).
        self.index.push_block(
            height,
            first_output,
            block.txs.iter().flat_map(|tx| {
                let coinbase = tx.is_coinbase();
                tx.output_keys()
                    .into_iter()
                    .map(move |k| (*k.one_time_key.bytes(), *k.commitment.bytes(), coinbase))
            }),
        );
        self.px
            .apply_block(&mut self.px_keys, &self.px_account, &block.txs, height);
        // Gap-limit scan (review M-2): an output found near the edge of the
        // window moves the window, and the block is scanned again with it, so
        // later outputs of the same block (and later blocks) are found too.
        loop {
            let report = scan_block(
                self.keys.view_keys(),
                &self.table,
                &block.txs,
                height,
                first_output,
            );
            let mut grew = false;
            for o in report.owned {
                if self
                    .outputs
                    .iter()
                    .any(|s| s.global_index == o.global_index)
                {
                    continue;
                }
                let ki = o.key_image(&self.keys);
                let ReceivedOutput {
                    subaddress,
                    amount,
                    mask,
                    output_key_offset,
                } = o.received;
                let key_image = hex::encode(ki.bytes());
                // One credited output per key image (docs/transactions.md
                // §12.5, D8 option B): two outputs with the same one-time
                // key share the key image, and only one of them can ever be
                // spent. The Janus check makes this unreachable on a valid
                // chain except for a hash collision (a copy in another
                // transaction has another input context), so this is defence
                // in depth, e.g. against a dishonest node. Every such output
                // is kept, unchanged, and one is credited: the LARGEST
                // amount, then the lowest global index (Monero's rule; a
                // small early copy never displaces a large genuine output;
                // `elect_credited`). Records are never rewritten in place,
                // so a rewind of the credited one's block credits the one
                // below the fork again (RTW1-4). The key image's spent and
                // reserved state is shared by all of them.
                let sibling = self.outputs.iter().find(|s| s.key_image == key_image);
                let (spent_height, pending, pending_height) = sibling
                    .map_or((None, false, 0), |s| {
                        (s.spent_height, s.pending, s.pending_height)
                    });
                let duplicate = sibling.map(|s| s.global_index);
                if let Some(held) = duplicate {
                    self.warnings.push(format!(
                        "outputs {held} and {} share a key image: only one of them is \
                         credited (docs/transactions.md §12.5)",
                        o.global_index,
                    ));
                }
                self.outputs.push(StoredOutput {
                    global_index: o.global_index,
                    height,
                    coinbase: o.coinbase,
                    account: subaddress.account,
                    index: subaddress.index,
                    amount,
                    one_time_key: hex::encode(o.key.one_time_key.bytes()),
                    commitment: hex::encode(o.key.commitment.bytes()),
                    mask: hex::encode(mask.as_bytes()),
                    offset: hex::encode(output_key_offset.as_bytes()),
                    key_image,
                    spent_height,
                    pending,
                    pending_height,
                    tx: Some(hex::encode(o.tx_hash)),
                    credited: duplicate.is_none(),
                });
                grew |= self.note_used(subaddress.account, subaddress.index);
            }
            if !grew {
                break;
            }
        }
        self.elect_credited();
        // Rejected outputs (Janus probes, bogus amounts) are deliberately ignored:
        // they must not be shown or spent (docs/transactions.md §12.5).
        // Every kind spends v1 outputs through key images: transfers, PX
        // transactions (bridge-in, fees) and deploys.
        let spent: HashSet<String> = block
            .txs
            .iter()
            .flat_map(|t| t.key_images())
            .map(|ki| hex::encode(ki.bytes()))
            .collect();
        for o in &mut self.outputs {
            if spent.contains(&o.key_image) {
                o.spent_height = Some(height);
                o.pending = false;
            }
        }
    }

    /// Elects, for every key image held more than once, the record that is
    /// credited: the largest amount, then the lowest global index (RTW1-4).
    /// The stored ring of such a key image (W-5) loses every member carrying
    /// its one-time key: the credited record may be one of them now, and a
    /// reused ring must never carry the same one-time key at two positions.
    pub(super) fn elect_credited(&mut self) {
        // key image -> (amount, global index) of the best record so far.
        let mut best: HashMap<&str, (u64, u64)> = HashMap::new();
        // key image -> one-time key, for key images held more than once.
        let mut duplicated: HashMap<&str, &str> = HashMap::new();
        for o in &self.outputs {
            let (amount, index) = (o.amount, o.global_index);
            match best.entry(&o.key_image) {
                Entry::Vacant(e) => {
                    e.insert((amount, index));
                }
                Entry::Occupied(mut e) => {
                    duplicated.insert(&o.key_image, &o.one_time_key);
                    let (held_amount, held_index) = *e.get();
                    if amount > held_amount || (amount == held_amount && index < held_index) {
                        e.insert((amount, index));
                    }
                }
            }
        }
        let credited: HashSet<(&str, u64)> =
            best.iter().map(|(k, &(_, index))| (*k, index)).collect();
        let credited: Vec<bool> = self
            .outputs
            .iter()
            .map(|o| credited.contains(&(o.key_image.as_str(), o.global_index)))
            .collect();
        let duplicated: Vec<(String, String)> = duplicated
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        for (o, c) in self.outputs.iter_mut().zip(credited) {
            o.credited = c;
        }
        for (key_image, one_time_key) in duplicated {
            if let Some(ring) = self.rings.get_mut(&key_image) {
                ring.retain(|m| m.one_time_key != one_time_key);
            }
        }
    }

    pub(super) fn spendable_at(o: &StoredOutput, next_height: u64) -> bool {
        let age = if o.coinbase {
            COINBASE_MATURITY
        } else {
            SPENDABLE_AGE
        };
        o.credited && o.spent_height.is_none() && !o.pending && next_height >= o.height + age
    }

    pub fn balance(&self) -> Balance {
        let next = self.synced_height + 1;
        let mut b = Balance::default();
        for o in self
            .outputs
            .iter()
            .filter(|o| o.credited && o.spent_height.is_none() && !o.pending)
        {
            b.total += o.amount;
            if Self::spendable_at(o, next) {
                b.unlocked += o.amount;
            }
        }
        b
    }

    /// Everything this wallet holds, as of its synced height, for the supply
    /// audit (tools/supply-audit). Read-only: no secret material (masks,
    /// seeds, record openings) is included, only amounts and public ids.
    ///
    /// - v1: every owned output, spent or not, with its confirmation state;
    ///   of outputs sharing a key image, only the credited one.
    /// - PX: every plain record, and every contract record that is on chain
    ///   (`height` known). Contract records created or imported but never
    ///   confirmed are left out: they hold no value on chain.
    pub fn holdings(&self) -> Holdings {
        let outputs = self
            .outputs
            .iter()
            .filter(|o| o.credited)
            .map(|o| HeldOutput {
                global_index: o.global_index,
                height: o.height,
                amount: o.amount,
                coinbase: o.coinbase,
                spent_height: o.spent_height,
                pending: o.pending,
            })
            .collect();
        let mut px_records: Vec<HeldRecord> = self
            .px
            .records
            .iter()
            .map(|r| HeldRecord {
                commitment: r.commitment.clone(),
                height: r.height,
                value: r.value,
                spent_height: r.spent_height,
                pending: r.pending,
                contract: None,
            })
            .collect();
        px_records.extend(self.px.contract_records.iter().filter_map(|r| {
            Some(HeldRecord {
                commitment: r.commitment.clone(),
                height: r.height?,
                value: r.value,
                spent_height: r.spent_height,
                pending: r.pending,
                contract: Some(r.contract.clone()),
            })
        }));
        Holdings {
            height: self.synced_height,
            tip: self.block_ids.get(&self.synced_height).copied(),
            pending_txs: self.pending_txs.len(),
            outputs,
            px_records,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blacksilk_consensus::{BlockHeader, Network, HEADER_VERSION};
    use blacksilk_crypto::keys::SubaddressIndex;
    use blacksilk_crypto::Point;
    use blacksilk_tx::builder::{build_coinbase, Payment};
    use blacksilk_tx::types::{Coinbase, CoinbaseOutput, Input, Transaction, Transfer};
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn wallet() -> Wallet {
        Wallet::from_seed(Network::Regtest, [7; 32], 1)
    }

    fn block(height: u64, txs: Vec<Transaction>) -> Block {
        Block {
            header: BlockHeader {
                version: HEADER_VERSION,
                height,
                prev_id: [0; 32],
                timestamp: 0,
                difficulty: 1,
                tx_root: [0; 32],
                nonce: 0,
            },
            txs,
        }
    }

    /// An honest coinbase at `height` paying `amount` to the wallet.
    fn pay_wallet(w: &Wallet, height: u64, amount: u64, rng: &mut ChaCha20Rng) -> Coinbase {
        build_coinbase(
            height,
            &[Payment {
                address: w.keys.address(SubaddressIndex::PRIMARY),
                amount,
            }],
            &[9; 32],
            rng,
        )
        .unwrap()
    }

    /// A transaction spending `key_image` (only its key images and outputs
    /// matter to `apply_block`).
    fn spend(key_image: Point) -> Transaction {
        Transaction::from(Transfer {
            inputs: vec![Input {
                key_image,
                ring: [0; blacksilk_tx::params::RING_SIZE],
            }],
            outputs: vec![],
            fee: 0,
            pseudo_outs: vec![],
            range_proof: blacksilk_crypto::bulletproofs_plus::BppProof {
                a: key_image,
                a1: key_image,
                b: key_image,
                r1: blacksilk_crypto::Scalar::ZERO,
                s1: blacksilk_crypto::Scalar::ZERO,
                d1: blacksilk_crypto::Scalar::ZERO,
                l: vec![],
                r: vec![],
            },
            signatures: vec![],
        })
    }

    fn stored_key_image(o: &StoredOutput) -> Point {
        let b: [u8; 32] = hex::decode(&o.key_image).unwrap().try_into().unwrap();
        Point::decode(&b).unwrap()
    }

    /// D8 option B (dossier 50 §5.1 test 3): a copy of the wallet's output,
    /// mined BEFORE the genuine output, with the same one-time key and a
    /// larger amount. The copy's input context differs, so the Janus check
    /// refuses it; the genuine output is credited, once, whatever the order
    /// and the amounts. The copy stays in the output index (it is a chain
    /// output, and may be a decoy: never filtered, F13-7).
    #[test]
    fn a_copy_mined_before_the_genuine_output_is_not_credited() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let mut w = wallet();
        let genuine = pay_wallet(&w, 2, 1_000, &mut rng);
        let copy = Coinbase {
            height: 1,
            outputs: vec![CoinbaseOutput {
                amount: 1_000_000,
                ..genuine.outputs[0].clone()
            }],
        };
        w.apply_block(&block(1, vec![Transaction::Coinbase(copy)]), 1, 0);
        assert!(w.outputs.is_empty(), "the copy is not credited");
        w.apply_block(&block(2, vec![Transaction::Coinbase(genuine)]), 2, 1);
        assert_eq!(w.outputs.len(), 1);
        assert_eq!(w.outputs[0].global_index, 1);
        assert_eq!(w.outputs[0].amount, 1_000);
        assert_eq!(w.balance().total, 1_000);
        // Both chain outputs are indexed (decoy candidates).
        assert!(w.index.get(0).is_some() && w.index.get(1).is_some());
        assert_eq!(
            w.index.get(0).unwrap().one_time_key,
            w.index.get(1).unwrap().one_time_key
        );
    }

    /// The records credited for their key image.
    fn credited(w: &Wallet) -> Vec<(u64, u64)> {
        w.outputs
            .iter()
            .filter(|o| o.credited)
            .map(|o| (o.global_index, o.amount))
            .collect()
    }

    /// Defence in depth (F13-6, F17-2, RT-10): outputs that pass the scan but
    /// share a key image (here two outputs of one transaction with the same
    /// one-time key and different amounts, which consensus rejects but a
    /// dishonest node can serve) are credited once: the LARGEST amount, then
    /// the lowest global index. Both are kept (RTW1-4). A spend of that key
    /// image spends it.
    #[test]
    fn one_output_is_credited_per_key_image_the_largest_then_the_lowest_index() {
        for (amounts, kept) in [
            ([500u64, 7_000u64], 1u64), // the larger comes second
            ([7_000, 500], 0),          // the larger comes first
            ([900, 900], 0),            // equal: the lowest index
        ] {
            let mut rng = ChaCha20Rng::seed_from_u64(2);
            let mut w = wallet();
            let honest = pay_wallet(&w, 5, 1, &mut rng);
            let bad = Coinbase {
                height: 5,
                outputs: amounts
                    .iter()
                    .map(|&amount| CoinbaseOutput {
                        amount,
                        ..honest.outputs[0].clone()
                    })
                    .collect(),
            };
            w.apply_block(&block(5, vec![Transaction::Coinbase(bad)]), 5, 0);
            assert_eq!(w.outputs.len(), 2, "{amounts:?}: both kept");
            assert_eq!(
                credited(&w),
                vec![(kept, amounts[kept as usize])],
                "{amounts:?}: credited once"
            );
            assert_eq!(w.balance().total, amounts[kept as usize]);
            assert_eq!(w.holdings().outputs.len(), 1, "audited once");
            assert_eq!(w.take_warnings().len(), 1, "a local diagnostic");
            // The key image is spent: nothing is left.
            let ki = stored_key_image(&w.outputs[0]);
            w.apply_block(&block(6, vec![spend(ki)]), 6, 2);
            assert!(w.outputs.iter().all(|o| o.spent_height == Some(6)));
            assert_eq!(w.balance().total, 0);
        }
    }

    /// The same across two scans of the chain (a copy that somehow passes
    /// the scan in a later block, e.g. after a hash collision): a larger
    /// later output is credited instead, a smaller one is not; the spent and
    /// reserved state of the key image is shared by every record.
    #[test]
    fn a_later_duplicate_is_credited_only_if_larger() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let mut w = wallet();
        let honest = pay_wallet(&w, 5, 300, &mut rng);
        let with = |amount: u64| Coinbase {
            height: 5,
            outputs: vec![CoinbaseOutput {
                amount,
                ..honest.outputs[0].clone()
            }],
        };
        // The same block served twice at two positions (a dishonest node).
        w.apply_block(&block(5, vec![Transaction::Coinbase(with(300))]), 5, 10);
        w.apply_block(&block(5, vec![Transaction::Coinbase(with(100))]), 5, 20);
        assert_eq!(credited(&w), vec![(10, 300)]);
        // Reserved by a submitted spend: a larger duplicate stays reserved.
        w.outputs[0].pending = true;
        w.outputs[0].pending_height = 5;
        w.outputs[1].pending = true;
        w.outputs[1].pending_height = 5;
        w.apply_block(&block(5, vec![Transaction::Coinbase(with(800))]), 5, 30);
        assert_eq!(credited(&w), vec![(30, 800)]);
        assert!(w.outputs.iter().all(|o| o.pending && o.pending_height == 5));
        assert_eq!(w.balance().total, 0, "reserved");
        for o in &mut w.outputs {
            o.pending = false;
        }
        assert_eq!(w.balance().total, 800);
        // Only the credited record can be chosen to spend.
        let spendable: Vec<u64> = w
            .outputs
            .iter()
            .filter(|o| Wallet::spendable_at(o, 1_000))
            .map(|o| o.global_index)
            .collect();
        assert_eq!(spendable, vec![30]);
        // Every record and the credit survive a save and load; files written
        // before the flag (one record per key image) load as credited.
        let loaded = Wallet::from_json(&w.to_json()).unwrap();
        assert_eq!(loaded.outputs.len(), 3);
        assert_eq!(credited(&loaded), vec![(30, 800)]);
        let mut json: serde_json::Value = serde_json::from_slice(&w.to_json()).unwrap();
        let outputs = json["outputs"].as_array_mut().unwrap();
        outputs.retain(|o| o["global_index"] == 30);
        outputs[0].as_object_mut().unwrap().remove("credited");
        let old = Wallet::from_json(&serde_json::to_vec(&json).unwrap()).unwrap();
        assert_eq!(credited(&old), vec![(30, 800)]);
        let _ = w.take_warnings();
        // Spent, then a larger duplicate: still spent.
        let ki = stored_key_image(&w.outputs[0]);
        w.apply_block(&block(6, vec![spend(ki)]), 6, 40);
        w.apply_block(&block(5, vec![Transaction::Coinbase(with(900))]), 5, 50);
        assert_eq!(credited(&w), vec![(50, 900)]);
        assert!(w.outputs.iter().all(|o| o.spent_height == Some(6)));
        assert_eq!(w.balance().total, 0);
    }

    /// RTW1-4 (red team RT-W1): a larger duplicate in a later block is
    /// credited instead of the earlier output, and a rewind below the later
    /// block brings the earlier output back. Before the fix the duplicate
    /// replaced the held record in place (height and global index), so the
    /// rewind dropped the only record and the genuine output, still on chain
    /// below the fork, stayed invisible until a restore from the seed.
    #[test]
    fn a_rewind_below_a_replacing_duplicate_keeps_the_displaced_output() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let mut w = wallet();
        let honest = pay_wallet(&w, 5, 300, &mut rng);
        let with = |amount: u64| Coinbase {
            height: 5,
            outputs: vec![CoinbaseOutput {
                amount,
                ..honest.outputs[0].clone()
            }],
        };
        w.apply_block(&block(5, vec![Transaction::Coinbase(with(300))]), 5, 10);
        w.synced_height = 5;
        w.apply_block(&block(7, vec![Transaction::Coinbase(with(800))]), 7, 30);
        w.synced_height = 7;
        assert_eq!(w.balance().total, 800, "the larger duplicate is credited");
        w.rewind(6);
        assert_eq!(
            w.balance().total,
            300,
            "output 10 at height 5 is still on chain"
        );
        assert_eq!(credited(&w), vec![(10, 300)]);
    }

    /// RTW1-4: once a key image is held twice, its stored ring (W-5, reused
    /// by the next spend of that key image) loses every member carrying the
    /// shared one-time key, so the real input's key never appears at a
    /// second position of the reused ring. Other members are kept.
    #[test]
    fn a_reused_ring_never_carries_the_credited_key_twice() {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let mut w = wallet();
        let honest = pay_wallet(&w, 5, 300, &mut rng);
        let with = |amount: u64| Coinbase {
            height: 5,
            outputs: vec![CoinbaseOutput {
                amount,
                ..honest.outputs[0].clone()
            }],
        };
        w.apply_block(&block(5, vec![Transaction::Coinbase(with(300))]), 5, 10);
        let key = w.outputs[0].one_time_key.clone();
        let other = hex::encode([0x11; 32]);
        let member = |index: u64, k: &str| super::super::RingMember {
            index,
            one_time_key: k.to_owned(),
            commitment: other.clone(),
        };
        // A ring submitted for output 10 whose decoys include output 30,
        // which later turns out to carry the same one-time key.
        w.rings.insert(
            w.outputs[0].key_image.clone(),
            vec![member(3, &other), member(30, &key)],
        );
        w.apply_block(&block(7, vec![Transaction::Coinbase(with(800))]), 7, 30);
        assert_eq!(credited(&w), vec![(30, 800)]);
        let ring = &w.rings[&w.outputs[0].key_image];
        assert_eq!(ring.iter().map(|m| m.index).collect::<Vec<_>>(), vec![3]);
    }
}
