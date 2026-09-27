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
use std::collections::HashSet;

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

    /// Removes everything learned from blocks above `height`.
    fn rewind(&mut self, height: u64) {
        self.outputs.retain(|o| o.height <= height);
        for o in &mut self.outputs {
            if o.spent_height.is_some_and(|h| h > height) {
                o.spent_height = None;
            }
        }
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
                    key_image: hex::encode(ki.bytes()),
                    spent_height: None,
                    pending: false,
                    pending_height: 0,
                    tx: Some(hex::encode(o.tx_hash)),
                });
                grew |= self.note_used(subaddress.account, subaddress.index);
            }
            if !grew {
                break;
            }
        }
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

    pub(super) fn spendable_at(o: &StoredOutput, next_height: u64) -> bool {
        let age = if o.coinbase {
            COINBASE_MATURITY
        } else {
            SPENDABLE_AGE
        };
        o.spent_height.is_none() && !o.pending && next_height >= o.height + age
    }

    pub fn balance(&self) -> Balance {
        let next = self.synced_height + 1;
        let mut b = Balance::default();
        for o in self
            .outputs
            .iter()
            .filter(|o| o.spent_height.is_none() && !o.pending)
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
    /// - v1: every owned output, spent or not, with its confirmation state.
    /// - PX: every plain record, and every contract record that is on chain
    ///   (`height` known). Contract records created or imported but never
    ///   confirmed are left out: they hold no value on chain.
    pub fn holdings(&self) -> Holdings {
        let outputs = self
            .outputs
            .iter()
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
