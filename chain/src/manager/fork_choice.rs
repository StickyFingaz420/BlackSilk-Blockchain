//! Fork choice: work, ancestry, body completeness, the connection target,
//! invalidation and syncing the transaction state to the target.

use super::{
    hex, ChainManager, SyncOutcome, DEEP_REORG_WARN_DEPTH, LOW_WORK_MARGIN_BLOCKS, OPERATOR_REASON,
};
use crate::emission::block_reward;
use crate::mempool::{ChainChange, Returned};
use crate::store::{InvalidMarker, InvalidOrigin, Marker};
use blacksilk_consensus::Hash;
use blacksilk_tx::validate::{validate_block_transactions_cached, BlockContext, BlockError};
use std::cmp::Reverse;
use std::io;

impl ChainManager {
    /// Whether the manager halted because a block that passed validation
    /// failed to apply ([`Self::halted`] names it). Unlike a failed block
    /// store, this is deterministic: a restart replays the store into the
    /// same failure, so the node exits with its own status and a supervisor
    /// must not restart it in a loop (RTW1B-4; docs/testnet.md).
    pub fn apply_halted(&self) -> bool {
        self.apply_failed.is_some()
    }

    /// Tests only: makes the next block application fail after validation
    /// (`MemoryChain::fail_next_apply_for_tests`), so that the manager halts.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn fail_next_apply_for_tests(&mut self) {
        self.state.fail_next_apply_for_tests();
    }

    /// Tests only: every bounded validation call with blocks to connect (a
    /// drain step: `submit_block_bounded`, `sync_step`) first sleeps
    /// `delay`, holding the manager: a heavy step on demand, for the
    /// liveness tests and benchmarks of the chain actor.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn set_step_delay_for_tests(&mut self, delay: Option<std::time::Duration>) {
        self.step_delay = delay;
    }

    pub(super) fn work(&self, id: &Hash) -> u128 {
        self.headers.work(id).expect("known header")
    }

    /// The ancestor of `id` (inclusive) at `height`, walking back.
    fn ancestor_at(&self, mut id: Hash, height: u64) -> Option<Hash> {
        loop {
            let h = self.headers.header(&id)?;
            if h.height == height {
                return Some(id);
            }
            if h.height < height {
                return None;
            }
            id = h.prev_id;
        }
    }

    /// Low-work policy ([`LOW_WORK_MARGIN_BLOCKS`]): whether the body of the
    /// (known, valid) block `id` is kept.
    pub(super) fn keeps_body(&self, id: &Hash) -> bool {
        let tip_work = self.work(&self.tip_id());
        let margin = LOW_WORK_MARGIN_BLOCKS * self.tip_header().difficulty as u128;
        if self.work(id) >= tip_work.saturating_sub(margin) {
            return true;
        }
        // On the path to a heavier header tip: its bodies are downloaded.
        if self.headers.best_work() > tip_work && self.headers.is_on_main(id) {
            return true;
        }
        let height = self.headers.header(id).expect("known").height;
        let main_tip = self.headers.tip_id();
        self.leaves
            .range((tip_work + 1, [0u8; 32])..)
            .filter(|(_, leaf)| *leaf != main_tip)
            .any(|(_, leaf)| self.ancestor_at(*leaf, height) == Some(*id))
    }

    /// Marks the valid block `id` (body kept, parent complete) complete. A
    /// block with strictly more work than the current target becomes the
    /// target, so among equal-work blocks the one completed first stays.
    ///
    /// A block the operator invalidated (`--invalidate-block`) is marked
    /// invalid with its descendants instead: this is where the verdict
    /// applies to a block that arrives (or is replayed) after it was given,
    /// before its body is ever validated or connected.
    pub(super) fn mark_complete(&mut self, id: Hash) {
        if self.operator_invalid.contains(&id) {
            log::warn!(
                "block {} at height {} is invalid by operator request \
                 (--invalidate-block); it and its descendants are not connected",
                hex(&id),
                self.headers.header(&id).map_or(0, |h| h.height)
            );
            for x in self.drop_invalid(id) {
                self.bodies.remove(&x);
                self.body_seq.remove(&x);
            }
            return;
        }
        let seq = self.next_complete_seq;
        self.next_complete_seq += 1;
        let w = self.work(&id);
        self.complete.insert(id, seq);
        self.complete_order.insert((w, Reverse(seq), id));
        if w > self.work(&self.best_complete) {
            self.best_complete = id;
        }
    }

    /// Recomputes the target after blocks left the complete set: the most
    /// work; among equal work the connected tip if it is one of them and
    /// still complete (no flapping), else the one completed first. (The
    /// connected tip leaves the complete set only when the operator
    /// invalidates it or an ancestor, [`Self::invalidate_block`].)
    fn recompute_target(&mut self) {
        let &(w, _, id) = self
            .complete_order
            .last()
            .expect("genesis is always complete");
        let tip = self.tip_id();
        self.best_complete = if self.work(&tip) == w && self.complete.contains_key(&tip) {
            tip
        } else {
            id
        };
    }

    /// A body failed validation: marks the block and its descendants invalid,
    /// drops them from the complete set, the leaves and memory, and
    /// recomputes the target.
    fn invalidate(&mut self, id: Hash, e: BlockError) {
        log::warn!(
            "block {} at height {} is invalid: {e:?}",
            hex(&id),
            self.headers.header(&id).map_or(0, |h| h.height)
        );
        self.invalid.insert(id, e);
        for x in self.drop_invalid(id) {
            self.bodies.remove(&x);
            self.body_seq.remove(&x);
        }
    }

    /// Marks the known block `id` and its descendants invalid in the header
    /// chain, drops them from the complete set and the leaves, and
    /// recomputes the target. Returns the ids of the block and its
    /// descendants, whose bodies the caller drops from memory (after
    /// disconnecting them, if they are connected).
    pub(super) fn drop_invalid(&mut self, id: Hash) -> Vec<Hash> {
        self.headers.mark_invalid(&id);
        self.refresh_hot_seeds();
        let mut dropped = Vec::new();
        let mut stack = vec![id];
        while let Some(x) = stack.pop() {
            let w = self.work(&x);
            if let Some(seq) = self.complete.remove(&x) {
                self.complete_order.remove(&(w, Reverse(seq), x));
            }
            self.leaves.remove(&(w, x));
            dropped.push(x);
            if let Some(kids) = self.children.get(&x) {
                stack.extend_from_slice(kids);
            }
        }
        // The parent becomes a leaf if none of its children is valid any more.
        let prev = self.headers.header(&id).expect("known").prev_id;
        let has_valid_child = self
            .children
            .get(&prev)
            .is_some_and(|k| k.iter().any(|c| self.headers.is_valid(c) == Some(true)));
        if !has_valid_child {
            self.leaves.insert((self.work(&prev), prev));
        }
        self.recompute_target();
        dropped
    }

    /// The operator invalidates block `id` on a running manager
    /// (docs/blocks.md §8; the node's `--invalidate-block` does the same
    /// before the manager opens, [`Self::mark_stored_block`]). The verdict
    /// is first appended to the block store as an operator
    /// [`Marker::Invalid`] record, so it holds after a restart. Then the
    /// block and its descendants are marked invalid and never connected: if
    /// the block is on the connected chain, the chain reorganizes at once to
    /// the best remaining body-complete branch (at least the block's
    /// parent), and the transactions of the disconnected blocks return to
    /// the pool as in any reorganization. A block whose header is not known
    /// yet is refused when it arrives.
    ///
    /// Refused (`InvalidInput`, nothing written): genesis. Refused (`Other`):
    /// a halted manager (restart the node with the flag instead) or a failed
    /// store write. A block the operator already invalidated is left as it
    /// is.
    ///
    /// Not a consensus rule: only this node refuses the block, and a chain
    /// built on it is not followed however much work it has (Bitcoin Core's
    /// `invalidateblock`). The chain actor does not expose it; the node uses
    /// the flag.
    pub fn invalidate_block(&mut self, id: Hash) -> io::Result<()> {
        if id == self.params.genesis_id() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the genesis block cannot be invalidated",
            ));
        }
        if let Some(why) = self.halted() {
            return Err(io::Error::other(format!(
                "the manager halted ({why}); restart the node with --invalidate-block"
            )));
        }
        if self.operator_invalid.contains(&id) {
            return Ok(());
        }
        // Finish a bounded drain first, so the verdict applies to a settled
        // chain.
        while !self.sync_step(usize::MAX) {}
        self.store.append_marker(&Marker::Invalid(InvalidMarker {
            id,
            origin: InvalidOrigin::Operator,
            reason: OPERATOR_REASON.into(),
        }))?;
        self.operator_invalid.insert(id);
        if self.headers.is_valid(&id) != Some(true) {
            // Unknown (refused on arrival, `mark_complete`) or already invalid.
            log::warn!("block {} marked invalid by operator request", hex(&id));
            return Ok(());
        }
        log::warn!(
            "block {} at height {} marked invalid by operator request; it and its \
             descendants are not connected",
            hex(&id),
            self.headers.header(&id).map_or(0, |h| h.height)
        );
        let dropped = self.drop_invalid(id);
        let (mut outcome, mut budget) = (SyncOutcome::default(), usize::MAX);
        self.sync_state(&mut outcome, &mut budget);
        self.finish_sync(outcome);
        for x in dropped {
            self.bodies.remove(&x);
            self.body_seq.remove(&x);
        }
        self.publish_summary();
        Ok(())
    }

    /// Height of the last block shared by the connected chain and the best header
    /// chain.
    pub(super) fn fork_height(&self) -> usize {
        let mut fork = self.connected.len() - 1;
        while self.headers.main_id_at(fork as u64) != Some(self.connected[fork]) {
            fork -= 1; // genesis always matches
        }
        fork
    }

    /// Restores the invariant (module docs): moves the connected chain to the
    /// target. The target always has more work than the connected tip when
    /// they differ (`mark_complete`, `recompute_target`), so the chain is only
    /// ever left for a heavier one. From the fork point (the target's last
    /// ancestor on the connected chain) it disconnects the old blocks, then
    /// connects the target's branch block by block, validating each body. A
    /// body that fails is marked invalid with its descendants, the target is
    /// recomputed, and the loop repeats (possibly reconnecting the old chain).
    ///
    /// **Budget.** Each block validation takes one unit of `budget`. With the
    /// budget spent, the method returns false before the next validation, but
    /// only at a tip with at least the work the connected tip had when this
    /// call began: a reorganization is never left with a lighter tip than
    /// before. Calling it again continues from the current connected chain
    /// (now a prefix of the target's branch), exactly where the loop stopped.
    /// Returns true once the connected tip is the target.
    ///
    /// **Apply failure.** A body that passed validation but fails to apply
    /// (`MemoryChain::apply_block`; validation is a superset of every apply
    /// failure, so this is a bug) halts the manager: the block is not marked
    /// invalid and not connected, nothing is connected any more, and the
    /// method returns true (`ChainManager::halted`; the node stops).
    pub(super) fn sync_state(&mut self, outcome: &mut SyncOutcome, budget: &mut usize) -> bool {
        if self.apply_failed.is_some() {
            return true;
        }
        let floor = self.work(&self.tip_id());
        loop {
            let target = self.best_complete;
            if target == self.tip_id() {
                return true;
            }
            // Only an operator invalidation of the connected chain moves it
            // to a lighter target (`invalidate_block`).
            debug_assert!(
                self.work(&target) > self.work(&self.tip_id())
                    || !self.complete.contains_key(&self.tip_id())
            );
            // The target's branch back to the connected chain.
            let mut path = Vec::new();
            let mut cur = target;
            let fork = loop {
                let h = self
                    .headers
                    .header(&cur)
                    .expect("complete blocks have headers");
                if self.connected.get(h.height as usize) == Some(&cur) {
                    break h.height as usize;
                }
                path.push(cur);
                cur = h.prev_id;
            };
            path.reverse();
            let depth = self.connected.len() - 1 - fork;
            self.deepest_reorg = self.deepest_reorg.max(depth);
            if depth >= DEEP_REORG_WARN_DEPTH {
                log::warn!(
                    "reorganization: disconnecting {depth} block(s) above height {fork}. \
                     A reorganization this deep suggests a network partition or a \
                     hash-power attack; no depth limit applies"
                );
            } else if depth > 0 {
                log::info!("reorganization: disconnecting {depth} block(s) above height {fork}");
            }
            while self.connected.len() - 1 > fork {
                outcome.reorganized = true;
                let h = (self.connected.len() - 1) as u64;
                let id = self.connected.pop().expect("above genesis");
                self.generated.pop();
                // Captured while the block is still applied: its rings then
                // resolve as when it was validated (outputs are only
                // appended), so the pool readmits it without verifying it.
                // Tip first, within the per-class readmission budget
                // (RTW2A-6); each captured transaction's conflict keys are
                // reserved until the drain ends (RTW2A-2).
                if let Some(body) = self.bodies.get(&id) {
                    let rules = self.rules_at(h);
                    for tx in body.iter().skip(1) {
                        match Returned::capture_within(
                            tx,
                            &self.state,
                            &rules,
                            &mut outcome.captured_bytes,
                        ) {
                            Some(r) => {
                                self.mempool.reserve(&r);
                                outcome.returned.push(r);
                            }
                            None => outcome.uncaptured += 1,
                        }
                    }
                }
                assert!(self.state.undo_block());
            }
            for id in path {
                if *budget == 0 && self.work(&self.tip_id()) >= floor {
                    return false;
                }
                *budget = budget.saturating_sub(1);
                let body = self.bodies.get(&id).expect("complete blocks have bodies");
                let header = self.headers.header(&id).expect("known header");
                let h = header.height;
                let generated = self.generated();
                let reward = block_reward(h, generated);
                let ctx = BlockContext {
                    height: h,
                    reward,
                    tx_root: header.tx_root,
                };
                // The rules of the block's own height (its epoch's branch id).
                let rules = self.rules_at(h);
                // PX proofs already verified on mempool admission are not
                // verified again (validate_block_transactions_cached), but only
                // when the pool's transactions were verified under this
                // block's rules: across an activation a pooled proof is bound
                // to the previous branch id and vouches for nothing here.
                let mempool = &self.mempool;
                let same_rules = mempool.validated_under() == Some(rules.domain());
                match validate_block_transactions_cached(
                    body,
                    &ctx,
                    &self.state,
                    &rules,
                    &mut self.rng,
                    &|id| same_rules && mempool.contains(id),
                ) {
                    Ok(()) => match self.state.apply_block(body) {
                        Ok(_) => {
                            self.connected.push(id);
                            self.generated.push(generated + reward);
                            self.mempool.remove_block(body);
                        }
                        Err(e) => {
                            // Never `invalidate` here: the block is valid by
                            // the rules; the node is at fault (F48-5).
                            log::error!(
                                "block {} at height {h} passed validation but failed to \
                                 apply ({e:?}); halting without marking it invalid",
                                hex(&id)
                            );
                            self.apply_failed = Some((id, h, format!("{e:?}")));
                            return true;
                        }
                    },
                    Err(e) => {
                        self.invalidate(id, e);
                        break;
                    }
                }
            }
        }
    }

    /// Mempool: expires transactions pooled for `MEMPOOL_EXPIRY_BLOCKS`,
    /// returns transactions from disconnected blocks, then drops anything no
    /// longer valid at the new tip.
    ///
    /// When the next block's rules differ from those the pool was validated
    /// under (the tip crossed an activation, in either direction), the pool is
    /// flushed first (`Mempool::enter_rules`): every pooled signature and PX
    /// proof commits to the old branch id and would fail (docs/consensus.md
    /// §11; docs/reviews/v3-upgrade-mechanism.md §2.5). Returned transactions
    /// are then admitted under the new rules, which refuses those of the old
    /// branch.
    pub(super) fn finish_sync(&mut self, outcome: SyncOutcome) {
        let next = self.height() + 1;
        let rules = self.rules_at(next);
        let uncaptured = outcome.uncaptured;
        // Rules, expiry (before the returned transactions come back: those
        // are pooled with a fresh admission height, even if this node expired
        // them recently), revalidation (the ring-digest path after a
        // reorganization), then readmission without verification
        // (`Mempool::update_after_chain_change`, docs/blocks.md §7).
        let update = self.mempool.update_after_chain_change(
            ChainChange {
                returned: outcome.returned,
                reorganized: outcome.reorganized,
            },
            &self.state,
            next,
            &rules,
        );
        let flushed = update.flushed;
        if flushed > 0 {
            log::info!(
                "rule set {} active from height {next}: {flushed} pooled transaction(s) \
                 signed or proven for the previous rule set dropped",
                self.params.epoch_at(next).name
            );
        }
        let expired = update.expired;
        if expired > 0 {
            log::info!("mempool: {expired} transaction(s) expired at height {next}");
        }
        if outcome.reorganized {
            log::info!(
                "mempool after the reorganization: {:?}; returned transactions: {:?}; \
                 {} beyond the readmission budget, not captured",
                update.revalidation,
                update.readmission,
                uncaptured
            );
        }
    }
}
