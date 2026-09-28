//! Pending transactions: submission, input bookkeeping, expiry and rebroadcast.
//!
//! **Rebroadcast** (docs/px.md §12; dossier 38 W4). The wallet never re-posts
//! a transaction to learn whether its node still has it: it asks
//! `/tx/status`. A transaction the node lacks is not sent again before
//! `relayed_height + NETWORK_EXPIRY_BLOCKS`, while other nodes may still pool
//! it (a re-send then would mark the wallet's node as its origin to any peer
//! that still pools it), and after that at most once. A PX transaction whose
//! validity window (PX6) ends within the expiring-soon margin is not sent,
//! and one whose window has passed is dropped with its inputs released: no
//! block can include it any more.

use super::{
    PendingTx, StaleTx, Wallet, WalletError, PENDING_EXPIRY_BLOCKS, RING_RETENTION_BLOCKS,
};
use crate::node::NodeApi;
use blacksilk_chain::mempool::{MEMPOOL_EXPIRY_BLOCKS, RECENTLY_EXPIRED_BLOCKS};
use blacksilk_consensus::Hash;
use blacksilk_rpc as rpc;
use blacksilk_tx::params::TxRules;
use blacksilk_tx::types::Transaction;
use blacksilk_tx::validate::px_expires_soon;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// A stored, unconfirmed transaction is checked on with `/tx/status` every
/// this many blocks. A submission that may not have reached the node
/// ([`RebroadcastState::Uncertain`]) is checked at every sync.
pub const REBROADCAST_PROBE_BLOCKS: u64 = 20;

/// Blocks after its relay height during which other nodes may still pool a
/// transaction, or refuse it as recently expired: the pool expiry plus the
/// recently-expired guard. A transaction the node lacks is not sent again
/// before this. Derived from the pool's constants, as the node's originated
/// set is (`blacksilk_p2p::originated::NETWORK_EXPIRY_BLOCKS`), never copied.
pub const NETWORK_EXPIRY_BLOCKS: u64 = MEMPOOL_EXPIRY_BLOCKS + RECENTLY_EXPIRED_BLOCKS;

/// What the wallet knows, and did, about a stored transaction that is not
/// mined (docs/px.md §12). Listed by [`Wallet::pending_transactions`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebroadcastState {
    /// Sent; the node accepted it, or last reported it pooled or mined.
    #[default]
    Sent,
    /// The submission failed in transport: the node may never have received
    /// it. Checked at the next sync, and sent again if the node lacks it.
    Uncertain,
    /// The node no longer holds it, and it is not mined. Not sent again
    /// before `relayed_height + NETWORK_EXPIRY_BLOCKS`: other nodes may still
    /// pool it until then.
    Waiting,
    /// Sent again once, at this wallet height, after the network dropped it.
    /// Never sent again automatically.
    Resent { height: u64 },
    /// The one re-send failed in transport. Checked at the next sync, and
    /// sent again if the node lacks it (still the one re-send).
    ResendUncertain,
}

/// A stored transaction, as [`Wallet::pending_transactions`] lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingInfo {
    /// Transaction id (hex).
    pub id: String,
    /// Wallet height it was relayed at.
    pub relayed_height: u64,
    pub state: RebroadcastState,
    /// The first wallet height at which it may be sent again if the node
    /// lacks it (`relayed_height + NETWORK_EXPIRY_BLOCKS`).
    pub resend_from: u64,
}

/// Whether the node refused a submission as `what` (it reports mempool
/// errors by their `Debug` names).
fn refused_as(r: &rpc::SubmitResult, what: &str) -> bool {
    !r.accepted && r.error.as_deref().is_some_and(|e| e.starts_with(what))
}

impl Wallet {
    /// Whether a submitted transaction is still unconfirmed.
    pub fn has_pending(&self) -> bool {
        self.outputs.iter().any(|o| o.pending)
    }

    /// The stored transactions (unconfirmed, or confirmed but not yet
    /// buried), with what the wallet did about each.
    pub fn pending_transactions(&self) -> Vec<PendingInfo> {
        self.pending_txs
            .iter()
            .map(|p| PendingInfo {
                id: hex::decode(&p.tx)
                    .ok()
                    .and_then(|b| Transaction::decode(&b).ok())
                    .map(|t| hex::encode(t.hash()))
                    .unwrap_or_default(),
                relayed_height: p.relayed_height,
                state: p.state,
                resend_from: p.relayed_height.saturating_add(NETWORK_EXPIRY_BLOCKS),
            })
            .collect()
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
        let tx_hex = hex::encode(&bytes);
        self.pending_txs.push(PendingTx {
            tx: tx_hex.clone(),
            relayed_height: at,
            branch_id: Some(rules.branch_id),
            state: RebroadcastState::Sent,
            checked_height: at,
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
            Err(e) => {
                // Checked, and sent again if the node lacks it, at the next
                // sync (the node's originated set makes a repeat harmless if
                // it did arrive, docs/p2p.md §8.1).
                if let Some(p) = self.pending_txs.iter_mut().find(|p| p.tx == tx_hex) {
                    p.state = RebroadcastState::Uncertain;
                }
                Err(WalletError::Uncertain(e))
            }
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

    /// Checks on the unconfirmed stored transaction `tx` (`p`) at wallet
    /// height `synced` (dossier 38 W4, docs/px.md §12):
    /// - it is due every [`REBROADCAST_PROBE_BLOCKS`], at the first sync at or
    ///   after `relayed_height + NETWORK_EXPIRY_BLOCKS`, and at every sync
    ///   while a submission is uncertain;
    /// - the node is asked `/tx/status`, never sent the transaction to find
    ///   out: `pooled` or `confirmed` means nothing is sent;
    /// - if the node lacks it, it is sent again only after
    ///   `relayed_height + NETWORK_EXPIRY_BLOCKS`, once; an uncertain
    ///   submission is sent again at once (it may never have arrived; if it
    ///   did, the node's originated set keeps the repeat from being
    ///   originated, docs/p2p.md §8.1).
    ///
    /// Returns `false` if the node found it invalid: it can never be mined,
    /// and its inputs were released.
    fn check_pending(
        &mut self,
        node: &dyn NodeApi,
        tx: &Transaction,
        p: &mut PendingTx,
        synced: u64,
    ) -> bool {
        let horizon = p.relayed_height.saturating_add(NETWORK_EXPIRY_BLOCKS);
        let uncertain = matches!(
            p.state,
            RebroadcastState::Uncertain | RebroadcastState::ResendUncertain
        );
        let due = uncertain
            || synced >= p.checked_height.saturating_add(REBROADCAST_PROBE_BLOCKS)
            || (synced >= horizon && p.checked_height < horizon);
        if !due {
            return true;
        }
        p.checked_height = synced;
        let lacks = match node.tx_status(&tx.hash()) {
            Ok(rpc::TxStatus::Pooled) | Ok(rpc::TxStatus::Confirmed { .. }) => {
                p.state = match p.state {
                    RebroadcastState::ResendUncertain => {
                        RebroadcastState::Resent { height: synced }
                    }
                    RebroadcastState::Resent { height } => RebroadcastState::Resent { height },
                    _ => RebroadcastState::Sent,
                };
                false
            }
            Ok(rpc::TxStatus::Unknown) => true,
            // No answer (a transport error, or a node without /tx/status):
            // before the window nothing is sent, as the node may well hold
            // it; an uncertain submission, or one past the window, is sent
            // (a node that holds it answers `AlreadyKnown` and relays
            // nothing).
            Err(_) => uncertain || synced >= horizon,
        };
        if !lacks {
            return true;
        }
        // Pools refuse a PX transaction whose window ends within the
        // expiring-soon margin (RTW1C-4): nothing is sent; it is dropped once
        // its window has passed (`refresh_pending`).
        if let Transaction::Px(t) = tx {
            if px_expires_soon(t, synced + 1) {
                return true;
            }
        }
        match p.state {
            RebroadcastState::Uncertain | RebroadcastState::ResendUncertain => {
                self.resend(node, tx, p, synced)
            }
            // At most once, ever.
            RebroadcastState::Resent { .. } => true,
            RebroadcastState::Sent | RebroadcastState::Waiting if synced < horizon => {
                if p.state != RebroadcastState::Waiting {
                    p.state = RebroadcastState::Waiting;
                    self.warnings.push(format!(
                        "transaction {} is no longer in the node's pool and is not mined. \
                         Other nodes may still hold it, so it is not sent again before \
                         height {horizon} (sending it earlier would show which node it came \
                         from); its funds stay reserved",
                        hex::encode(tx.hash())
                    ));
                }
                true
            }
            RebroadcastState::Sent | RebroadcastState::Waiting => self.resend(node, tx, p, synced),
        }
    }

    /// Sends the stored transaction `tx` (`p`) again: an uncertain submission
    /// once more, or the one re-send after the network dropped it. Every node
    /// answer is handled explicitly; returns `false` if the node found it
    /// invalid (its inputs are released).
    fn resend(
        &mut self,
        node: &dyn NodeApi,
        tx: &Transaction,
        p: &mut PendingTx,
        synced: u64,
    ) -> bool {
        let id = hex::encode(tx.hash());
        // The first submission's outcome is unknown: this is that submission
        // again, not a re-send.
        let first = p.state == RebroadcastState::Uncertain;
        match node.submit_tx(&tx.encode()) {
            Ok(r) if r.accepted || r.already_pooled() => {
                if first {
                    // Relayed now at the latest: the window counts from here.
                    p.state = RebroadcastState::Sent;
                    p.relayed_height = synced;
                } else {
                    p.state = RebroadcastState::Resent { height: synced };
                    self.warnings.push(format!(
                        "transaction {id} was dropped by the network without being mined and \
                         was sent again, once, at height {synced}. It is not sent again \
                         automatically; its funds stay reserved"
                    ));
                }
                true
            }
            // The node expired it within its recently-expired window, so it
            // does not originate it again yet, and nothing was sent. Tried
            // again at a later sync; not the one re-send.
            Ok(r) if refused_as(&r, "Expired") => {
                p.state = match p.state {
                    RebroadcastState::ResendUncertain => {
                        RebroadcastState::Resent { height: synced }
                    }
                    _ => RebroadcastState::Waiting,
                };
                self.warnings.push(format!(
                    "the node refused to send transaction {id} again yet (it dropped it \
                     recently); the wallet tries again at a later sync"
                ));
                true
            }
            // It can never be mined on this chain: release the inputs.
            Ok(r) if refused_as(&r, "Invalid") => {
                self.for_each_input(tx, |spent, pending, _| {
                    if spent.is_none() {
                        *pending = false;
                    }
                });
                false
            }
            // A full pool: nothing was sent; tried again at a later sync.
            Ok(r) if refused_as(&r, "FeeTooLowForFullPool") => true,
            // Any other refusal: nothing was sent; kept reserved and tried
            // again at a later sync.
            Ok(r) => {
                self.warnings.push(format!(
                    "the node refused transaction {id} ({}); its funds stay reserved and the \
                     wallet tries again at a later sync",
                    r.error.unwrap_or_default()
                ));
                true
            }
            // It may or may not have arrived: checked at the next sync.
            Err(_) => {
                p.state = if first {
                    RebroadcastState::Uncertain
                } else {
                    RebroadcastState::ResendUncertain
                };
                true
            }
        }
    }

    /// Maintains the stored transactions after a sync. An unconfirmed one is
    /// checked on ([`Self::check_pending`]); transport errors are ignored
    /// here, and a later sync retries.
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
                        "transaction {id} was built for consensus branch {built_for:#010x}, but \
                         block {} needs branch {next_branch:#010x} (an upgrade): it can never be \
                         mined as it is. It was not rebroadcast and its funds are released; \
                         send the payment again",
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
                // A PX transaction whose validity window (PX6) ends below the
                // next block can never be mined (CB-B2): it is dropped and
                // its unspent inputs are released, like one of another epoch.
                if let Transaction::Px(t) = &tx {
                    let not_after = t.window.not_after;
                    if not_after != 0 && synced + 1 > not_after {
                        self.for_each_input(&tx, |spent, pending, _| {
                            if spent.is_none() {
                                *pending = false;
                            }
                        });
                        self.warnings.push(format!(
                            "transaction {} could be mined only up to block {not_after} (its \
                             validity window) and was not: it was dropped and its funds are \
                             released",
                            hex::encode(tx.hash())
                        ));
                        continue;
                    }
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
                if !self.check_pending(node, &tx, &mut p, synced) {
                    // It can never be mined on this chain: its inputs were
                    // released.
                    continue;
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
