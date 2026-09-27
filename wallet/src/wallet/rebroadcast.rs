//! Pending transactions: submission, input bookkeeping, expiry and rebroadcast.

use super::{
    PendingTx, StaleTx, Wallet, WalletError, PENDING_EXPIRY_BLOCKS, RING_RETENTION_BLOCKS,
};
use crate::node::NodeApi;
use blacksilk_consensus::Hash;
use blacksilk_tx::params::TxRules;
use blacksilk_tx::types::Transaction;
use std::collections::HashSet;

impl Wallet {
    /// Whether a submitted transaction is still unconfirmed.
    pub fn has_pending(&self) -> bool {
        self.outputs.iter().any(|o| o.pending)
    }

    /// Forgets unconfirmed spends and the stored transactions, v1 and PX alike.
    ///
    /// Meant for a transaction that certainly never left this wallet. The rings
    /// of submitted transactions are kept (`rings`), so a new spend of the same
    /// inputs reuses them; but the new transaction still shares the key images,
    /// so observers can link the two spends.
    pub fn clear_pending(&mut self) {
        for o in &mut self.outputs {
            o.pending = false;
        }
        self.px.clear_pending();
        self.pending_txs.clear();
        self.stale_txs.clear();
    }

    /// Calls `f(spent_height, pending, pending_height)` for every input of
    /// `tx` this wallet owns: v1 outputs by key image, PX and contract records
    /// by nullifier.
    fn for_each_input(
        &mut self,
        tx: &Transaction,
        mut f: impl FnMut(Option<u64>, &mut bool, &mut u64),
    ) {
        let kis: HashSet<String> = tx
            .key_images()
            .iter()
            .map(|k| hex::encode(k.bytes()))
            .collect();
        for o in &mut self.outputs {
            if kis.contains(&o.key_image) {
                f(o.spent_height, &mut o.pending, &mut o.pending_height);
            }
        }
        if let Transaction::Px(t) = tx {
            let nfs: HashSet<String> = t.nullifiers.iter().map(crate::px::digest_hex).collect();
            for r in &mut self.px.records {
                if nfs.contains(&r.nullifier) {
                    f(r.spent_height, &mut r.pending, &mut r.pending_height);
                }
            }
            for r in &mut self.px.contract_records {
                if nfs.contains(&r.nullifier) {
                    f(r.spent_height, &mut r.pending, &mut r.pending_height);
                }
            }
        }
    }

    /// Submits `tx`. Its inputs are reserved and the transaction stored
    /// *before* the request, so a transport failure leaves them reserved
    /// (`WalletError::Uncertain`). Only a definite refusal releases them.
    ///
    /// `rules` are those `tx` was built with. If the node's next block is
    /// already in another epoch (an upgrade activated while the transaction
    /// was built or proven), nothing is sent or reserved
    /// (`WalletError::EpochChanged`).
    pub(super) fn submit(
        &mut self,
        node: &dyn NodeApi,
        tx: Transaction,
        rules: &TxRules,
    ) -> Result<Hash, WalletError> {
        let id = tx.hash();
        let bytes = tx.encode();
        let at = self.synced_height;
        // The node's tip, not the wallet's: proving takes about a minute. An
        // unreachable node is left to the submission itself (Uncertain).
        let tip = node.info().map(|i| i.height).unwrap_or(at).max(at);
        let needed = self.params.epoch_at(tip + 1).branch_id;
        if needed != rules.branch_id {
            self.staged_rings.clear();
            return Err(WalletError::EpochChanged {
                built_for: rules.branch_id,
                needed,
                height: tip + 1,
            });
        }
        // Record everything before the transaction can leave: its reservation,
        // the stored copy, and its rings. Rings are kept even if the node then
        // refuses: reusing a ring that never became public costs nothing, and
        // the node's answer cannot be verified (review F5).
        self.for_each_input(&tx, |_, pending, h| {
            *pending = true;
            *h = at;
        });
        self.pending_txs.push(PendingTx {
            tx: hex::encode(&bytes),
            relayed_height: at,
            branch_id: Some(rules.branch_id),
        });
        let kis: HashSet<String> = tx
            .key_images()
            .iter()
            .map(|k| hex::encode(k.bytes()))
            .collect();
        for (ki, ring) in std::mem::take(&mut self.staged_rings) {
            if kis.contains(&ki) {
                self.rings.insert(ki, ring);
            }
        }
        if let Err(e) = self.persist() {
            // Not sent: undo the reservation.
            self.forget(&tx);
            return Err(e);
        }
        let result = match node.submit_tx(&bytes) {
            Err(e) => Err(WalletError::Uncertain(e)),
            Ok(r)
                if r.accepted
                    || r.error
                        .as_deref()
                        .is_some_and(|e| e.starts_with("AlreadyKnown")) =>
            {
                Ok(id)
            }
            // Refused by the only node that saw it (as far as we can tell).
            Ok(r) => {
                self.forget(&tx);
                Err(WalletError::Rejected(r.error.unwrap_or_default()))
            }
        };
        // Best effort: the state that matters was saved before sending.
        let _ = self.persist();
        result
    }

    /// Drops the stored copy of `tx` and releases its unspent inputs.
    fn forget(&mut self, tx: &Transaction) {
        let hex_tx = hex::encode(tx.encode());
        self.pending_txs.retain(|p| p.tx != hex_tx);
        self.for_each_input(tx, |spent, pending, _| {
            if spent.is_none() {
                *pending = false;
            }
        });
    }

    /// Maintains the stored transactions after a sync (`PENDING_EXPIRY_BLOCKS`).
    /// Transport errors are ignored here; the next sync retries.
    ///
    /// An unconfirmed transaction built for another epoch than the next
    /// block's (an upgrade activated, or a reorganization went back across
    /// one) can never be mined as it is: it is not rebroadcast, its unspent
    /// inputs are released, and it is listed in `stale_transactions` with a
    /// warning. A new spend of those inputs reuses their stored rings (W-5)
    /// but shares their key images, so observers who saw the old transaction
    /// can link the two.
    pub(super) fn refresh_pending(&mut self, node: &dyn NodeApi) {
        let synced = self.synced_height;
        let next_branch = self.params.epoch_at(synced + 1).branch_id;
        let mut unconfirmed = false;
        let mut kept = Vec::new();
        let mut covered_kis = HashSet::new();
        let mut covered_nfs = HashSet::new();
        for mut p in std::mem::take(&mut self.pending_txs) {
            let Some(tx) = hex::decode(&p.tx)
                .ok()
                .and_then(|b| Transaction::decode(&b).ok())
            else {
                continue; // unreadable entry: nothing to rebroadcast
            };
            // Kept until every input is known spent and buried. Inputs the
            // wallet does not currently see (a node behind the wallet, a
            // rewind) do not count as buried (review F3).
            let (mut found, mut unspent, mut buried) = (false, false, true);
            self.for_each_input(&tx, |spent, _, _| {
                found = true;
                match spent {
                    None => {
                        unspent = true;
                        buried = false;
                    }
                    Some(h) => buried &= synced >= h + RING_RETENTION_BLOCKS,
                }
            });
            if found && buried {
                continue;
            }
            if unspent {
                let built_for = p.branch_id.unwrap_or_else(|| {
                    self.params
                        .epoch_at(p.relayed_height.saturating_add(1))
                        .branch_id
                });
                if built_for != next_branch {
                    self.for_each_input(&tx, |spent, pending, _| {
                        if spent.is_none() {
                            *pending = false;
                        }
                    });
                    let id = hex::encode(tx.hash());
                    self.warnings.push(format!(
                        "transaction {id} was built for consensus branch {built_for:#010x}, but                          block {} needs branch {next_branch:#010x} (an upgrade): it can never be                          mined as it is. It was not rebroadcast and its funds are released;                          send the payment again",
                        synced + 1
                    ));
                    self.stale_txs.retain(|s| s.id != id);
                    self.stale_txs.push(StaleTx {
                        id,
                        built_for,
                        needed: next_branch,
                        height: synced,
                    });
                    continue;
                }
                unconfirmed = true;
                // Re-reserve inputs whose confirmation a reorganization undid.
                let at = p.relayed_height;
                self.for_each_input(&tx, |spent, pending, h| {
                    if spent.is_none() && !*pending {
                        *pending = true;
                        *h = at;
                    }
                });
                if synced >= p.relayed_height + PENDING_EXPIRY_BLOCKS {
                    match node.submit_tx(&tx.encode()) {
                        Ok(r) if r.accepted || r.already_pooled() => p.relayed_height = synced,
                        // It can never be mined on this chain: release the inputs.
                        Ok(r) if r.error.as_deref().is_some_and(|e| e.starts_with("Invalid")) => {
                            self.for_each_input(&tx, |spent, pending, _| {
                                if spent.is_none() {
                                    *pending = false;
                                }
                            });
                            continue;
                        }
                        // A full pool or a transport error: retry on a later sync.
                        _ => {}
                    }
                }
            }
            covered_kis.extend(tx.key_images().iter().map(|k| hex::encode(k.bytes())));
            if let Transaction::Px(t) = &tx {
                covered_nfs.extend(t.nullifiers.iter().map(crate::px::digest_hex));
            }
            kept.push(p);
        }
        self.pending_txs = kept;
        if unconfirmed {
            self.warn_near_activation(synced + 1, "an unconfirmed transaction of this wallet");
        }
        // Notices of dropped transactions expire with the rings' window.
        self.stale_txs
            .retain(|s| synced < s.height.saturating_add(RING_RETENTION_BLOCKS));
        // A ring is needed while its output may still be spent again: until the
        // spend is buried, or while a stored transaction still spends it.
        // Only rings of outputs known to be spent and buried beyond the
        // wallet's reorganization window are dropped (review F3, F9).
        let outputs = &self.outputs;
        self.rings.retain(|ki, _| {
            covered_kis.contains(ki)
                || !outputs.iter().any(|o| {
                    o.key_image == *ki
                        && o.spent_height
                            .is_some_and(|h| synced >= h + RING_RETENTION_BLOCKS)
                })
        });
        // Reservations without a stored transaction come from wallet files
        // written before transactions were stored: they keep the old expiry.
        for o in &mut self.outputs {
            if o.pending
                && !covered_kis.contains(&o.key_image)
                && synced >= o.pending_height + PENDING_EXPIRY_BLOCKS
            {
                o.pending = false;
            }
        }
        for r in &mut self.px.records {
            if r.pending
                && !covered_nfs.contains(&r.nullifier)
                && synced >= r.pending_height + PENDING_EXPIRY_BLOCKS
            {
                r.pending = false;
            }
        }
    }
}
