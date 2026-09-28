//! Block submission: whole and bounded (step-wise) submission, verdicts, the
//! ready-body queue and header bookkeeping.

use super::{hex, ChainManager, SubmitError, Submitted, STORE_FAILURE_LIMIT};
use crate::block::Block;
use blacksilk_consensus::{Hash, HeaderError, PowFunction};
use std::cmp::Reverse;
use std::io;

impl ChainManager {
    /// Accepts a block from the local miner or (later) the network.
    pub fn submit_block(&mut self, block: Block, now: u64) -> Result<Submitted, SubmitError> {
        let r = self.submit_inner(block, now, true, usize::MAX);
        self.publish_summary();
        r
    }

    /// [`Self::submit_block`] that validates and connects at most `budget`
    /// blocks in this call (the block itself and descendants it releases, or
    /// blocks queued by earlier bounded calls, which go first). If work is
    /// left ([`Self::sync_pending`]), the caller continues with
    /// [`Self::sync_step`], releasing the lock in between, and reads the
    /// final verdict with [`Self::verdict`]; [`submit_block_in_steps`] does
    /// all of this. Until then the returned `on_best_chain` may be stale and
    /// a body failure is not reported yet.
    ///
    /// The result is the same as with [`Self::submit_block`]: blocks complete
    /// in the same order (lowest body arrival first, a block queued while a
    /// drain is in progress waits for everything that arrived before it), and
    /// the connected chain is interrupted only at a tip with at least the
    /// work it had when that sync began (never midway through a
    /// reorganization, before the new branch outweighs the old tip).
    pub fn submit_block_bounded(
        &mut self,
        block: Block,
        now: u64,
        budget: usize,
    ) -> Result<Submitted, SubmitError> {
        let r = self.submit_inner(block, now, true, budget);
        self.publish_summary();
        r
    }

    /// Continues the drain started by [`Self::submit_block_bounded`]: at most
    /// `budget` block validations. Returns true when nothing is left (the
    /// mempool then received the drain's effects).
    pub fn sync_step(&mut self, budget: usize) -> bool {
        let done = self.drain_ready(budget);
        self.publish_summary();
        done
    }

    /// Whether completed blocks still wait to be connected (a bounded drain
    /// is in progress).
    pub fn sync_pending(&self) -> bool {
        self.syncing.is_some() || !self.ready.is_empty()
    }

    /// The verdict on a block submitted earlier (`id` at `height`), once no
    /// drain is pending: as [`Self::submit_block`] reports it.
    pub fn verdict(&self, id: Hash, height: u64) -> Result<Submitted, SubmitError> {
        if let Some(e) = self.invalid.get(&id) {
            return Err(SubmitError::Body(*e));
        }
        Ok(Submitted {
            id,
            height,
            on_best_chain: self.connected.get(height as usize) == Some(&id),
            body_kept: true,
        })
    }

    pub(super) fn submit_inner(
        &mut self,
        block: Block,
        now: u64,
        persist: bool,
        budget: usize,
    ) -> Result<Submitted, SubmitError> {
        if persist && self.store_failed {
            return Err(SubmitError::Store(io::Error::other(
                "the block store failed; no block is accepted until the node restarts",
            )));
        }
        if self.apply_failed.is_some() {
            return Err(SubmitError::Halted);
        }
        let id = block.id(self.params.network_id);
        if self.headers.header(&id).is_some() {
            if self.bodies.contains_key(&id) || id == self.params.genesis_id() {
                return Err(SubmitError::Duplicate);
            }
            if self.headers.is_valid(&id) == Some(false) {
                return Err(SubmitError::Header(HeaderError::InvalidParent));
            }
        } else {
            // Check the body against the header before the header can enter the tree,
            // so a valid header with a garbage body is not stored.
            if block.compute_tx_root() != block.header.tx_root {
                return Err(SubmitError::BodyMismatch);
            }
            self.headers
                .accept(block.header, now)
                .map_err(SubmitError::Header)?;
            self.header_added(id, block.header.prev_id);
        }
        if block.compute_tx_root() != block.header.tx_root {
            return Err(SubmitError::BodyMismatch);
        }
        let height = block.header.height;
        // Replay keeps every stored body: the policy was applied on arrival.
        if persist && !self.keeps_body(&id) {
            log::debug!(
                "low-work side-branch body {} at height {height} not kept",
                hex(&id)
            );
            return Ok(Submitted {
                id,
                height,
                on_best_chain: false,
                body_kept: false,
            });
        }
        if persist {
            // The header is in the tree, so its seed is defined; the hash is
            // cached from header validation (computed again only if not).
            let header_bytes = block.header.to_bytes();
            let seed = self
                .headers
                .seed_id_for(block.header.prev_id, block.header.height);
            let pow_hash = self.pow.pow_hash(&seed, &header_bytes);
            if let Err(e) = self.store.append(&pow_hash, &block.encode()) {
                self.store_failures += 1;
                if self.store.failed() || self.store_failures >= STORE_FAILURE_LIMIT {
                    if !self.store_failed {
                        log::error!(
                            "block store failed ({} write failure(s) in a row, last: {e}); \
                             no further blocks are accepted",
                            self.store_failures
                        );
                    }
                    self.store_failed = true;
                }
                return Err(SubmitError::Store(e));
            }
            self.store_failures = 0;
        }
        let seq = self.next_body_seq;
        self.next_body_seq += 1;
        self.bodies.insert(id, block.txs);
        self.body_seq.insert(id, seq);

        // Completion: this block if its parent is complete, then every
        // descendant whose body is already here, lowest arrival index first
        // (the order `replay` releases them in). The state is synced after
        // each single completion, as in replay. A block whose parent is still
        // queued (a bounded drain in progress) is released with the parent's
        // other children when the parent completes, as if the drain had
        // finished before it arrived.
        if self.complete.contains_key(&block.header.prev_id) {
            self.ready.push(Reverse((seq, id)));
        }
        self.drain_ready(budget);
        self.verdict(id, height)
    }

    /// Completes queued blocks (`ready`), lowest body arrival first, syncing
    /// the state after each completion, with at most `budget` block
    /// validations. Returns true when the queue is empty; the mempool then
    /// receives the effects of the whole drain (`finish_sync`), once.
    fn drain_ready(&mut self, mut budget: usize) -> bool {
        #[cfg(feature = "test-hooks")]
        if let (Some(d), true) = (self.step_delay, budget != usize::MAX) {
            if self.syncing.is_some() || !self.ready.is_empty() {
                std::thread::sleep(d);
            }
        }
        let mut outcome = std::mem::take(&mut self.sync_outcome);
        let before = self.tip_id();
        loop {
            if let Some(x) = self.syncing {
                if !self.sync_state(&mut outcome, &mut budget) {
                    self.sync_outcome = outcome;
                    return false;
                }
                self.syncing = None;
                if !self.complete.contains_key(&x) {
                    continue; // found invalid (or a descendant of an invalid block)
                }
                for c in self.children.get(&x).into_iter().flatten() {
                    if let Some(&s) = self.body_seq.get(c) {
                        self.ready.push(Reverse((s, *c)));
                    }
                }
                continue;
            }
            let Some(Reverse((_, x))) = self.ready.pop() else {
                break;
            };
            if self.headers.is_valid(&x) != Some(true) {
                continue; // an ancestor was found invalid meanwhile
            }
            self.mark_complete(x);
            self.syncing = Some(x);
        }
        if self.tip_id() != before {
            log::debug!("tip {} at height {}", hex(&self.tip_id()), self.height());
        }
        self.finish_sync(outcome);
        true
    }

    /// Records a header just accepted by the header chain.
    pub(super) fn header_added(&mut self, id: Hash, prev: Hash) {
        self.children.entry(prev).or_default().push(id);
        if let Some(w) = self.headers.work(&prev) {
            self.leaves.remove(&(w, prev));
        }
        let w = self.work(&id);
        self.leaves.insert((w, id));
        self.refresh_hot_seeds();
    }

    /// Passes the hot RandomX keys of the best header chain to the PoW layer
    /// when they changed: it pins them and builds the next key's cache on a
    /// background thread, so no block pays a cache build under the chain lock
    /// at a key switch (dossier 07 W1; `sync_policy::hot_seeds`).
    pub(super) fn refresh_hot_seeds(&mut self) {
        let hot = crate::sync_policy::hot_seeds(&self.headers);
        if hot != self.hot_seeds {
            self.pow.set_hot_seeds(&hot);
            self.hot_seeds = hot;
        }
    }
}

#[cfg(test)]
mod tests {
    //! The bounded submission API (`submit_block_bounded`, `sync_step`):
    //! same final chain as `submit_block`, bounded work per call, never a
    //! lighter tip mid-reorganization.
    use super::*;
    use crate::store::MemoryStore;
    use blacksilk_consensus::merkle::tx_root;
    use blacksilk_consensus::HEADER_VERSION;
    use blacksilk_consensus::{BlockHeader, ChainParams};
    use blacksilk_crypto::keys::{SubaddressIndex, WalletKeys};
    use blacksilk_tx::builder::{build_coinbase, Payment};
    use blacksilk_tx::params::TxRules;
    use blacksilk_tx::types::Transaction;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::sync::Arc;

    struct ZeroPow;
    impl PowFunction for ZeroPow {
        fn pow_hash(&self, _: &Hash, _: &[u8]) -> Hash {
            [0; 32]
        }
    }

    fn open() -> ChainManager {
        let p = ChainParams::regtest();
        ChainManager::open(
            p.clone(),
            TxRules::for_chain(&p),
            Arc::new(ZeroPow),
            Box::<MemoryStore>::default(),
            [3; 32],
        )
        .unwrap()
    }

    /// `n` blocks on `parent`, submitted to `m`; `nonce` tells branches apart.
    fn branch(m: &mut ChainManager, parent: Hash, n: usize, nonce: u64) -> Vec<Block> {
        let mut rng = ChaCha20Rng::seed_from_u64(nonce);
        let (keys, _) = WalletKeys::generate(&mut rng);
        let genesis_time = m.params().genesis.timestamp;
        let mut prev = parent;
        let mut out = Vec::new();
        for _ in 0..n {
            let t = m.template_on(&prev).unwrap();
            let cb = build_coinbase(
                t.height,
                &[Payment {
                    address: keys.address(SubaddressIndex::PRIMARY),
                    amount: t.reward,
                }],
                &keys.hedge_secret(),
                &mut rng,
            )
            .unwrap();
            let txs = vec![Transaction::Coinbase(cb)];
            let ids: Vec<Hash> = txs.iter().map(Transaction::hash).collect();
            let header = BlockHeader {
                version: HEADER_VERSION,
                height: t.height,
                prev_id: prev,
                timestamp: t.min_timestamp.max(genesis_time + 120 * t.height),
                difficulty: t.difficulty,
                tx_root: tx_root(&ids),
                nonce,
            };
            let b = Block { header, txs };
            m.submit_block(b.clone(), b.header.timestamp).unwrap();
            prev = b.id(m.params().network_id);
            out.push(b);
        }
        out
    }

    const NOW: u64 = u64::MAX / 2;

    fn same_chain(a: &ChainManager, b: &ChainManager) {
        assert_eq!(a.tip_id(), b.tip_id());
        assert_eq!(a.height(), b.height());
        assert_eq!(a.generated(), b.generated());
        assert_eq!(a.state().output_count(), b.state().output_count());
        assert_eq!(a.connected, b.connected);
        assert_eq!(a.best_complete, b.best_complete);
        assert_eq!(a.deepest_reorg(), b.deepest_reorg());
        assert!(!b.sync_pending());
    }

    /// The gap-filling body of a header-first download releases 39 waiting
    /// descendants. Bounded, each call validates at most `budget` blocks; a
    /// body arriving mid-drain waits for the drain, as if it had arrived
    /// after it; the final chain equals the unbounded one.
    #[test]
    fn bounded_submission_reaches_the_unbounded_result_in_bounded_steps() {
        let mut src = open();
        let genesis = src.tip_id();
        let blocks = branch(&mut src, genesis, 41, 1);
        let headers: Vec<BlockHeader> = blocks[..40].iter().map(|b| b.header).collect();
        let (mut full, mut bounded) = (open(), open());
        for m in [&mut full, &mut bounded] {
            m.accept_headers(&headers, NOW).unwrap();
            for b in blocks[1..40].iter().rev() {
                let s = m.submit_block(b.clone(), NOW).unwrap();
                assert!(!s.on_best_chain, "waits for its parent");
            }
        }
        full.submit_block(blocks[0].clone(), NOW).unwrap();
        full.submit_block(blocks[40].clone(), NOW).unwrap();
        assert_eq!(full.height(), 41);

        let budget = 3;
        assert!(bounded.summary_is_current(), "published after the headers");
        let first = bounded
            .submit_block_bounded(blocks[0].clone(), NOW, budget)
            .unwrap();
        assert_eq!(bounded.height(), 3, "exactly `budget` blocks connected");
        assert!(
            bounded.summary_is_current(),
            "published after a bounded call"
        );
        assert!(bounded.summary().sync_pending);
        assert!(bounded.sync_pending());
        // Block 41 (header unknown so far) arrives mid-drain.
        let late = bounded
            .submit_block_bounded(blocks[40].clone(), NOW, budget)
            .unwrap();
        assert_eq!(bounded.height(), 3 + budget as u64);
        let mut steps = 0;
        loop {
            let before = bounded.height();
            let seq = bounded.summary().seq;
            let done = bounded.sync_step(budget);
            assert!(bounded.height() - before <= budget as u64);
            // A reader without the lock sees exactly the fields of the last
            // step, published once if the step changed any.
            assert!(bounded.summary_is_current(), "published after a step");
            let moved = bounded.height() != before;
            assert!(!moved || bounded.summary().seq == seq + 1);
            steps += 1;
            if done {
                break;
            }
        }
        assert!(steps >= 10, "{steps} steps");
        same_chain(&full, &bounded);
        assert_eq!(*full.summary(), {
            let mut s = (*bounded.summary()).clone();
            s.seq = full.summary().seq;
            s
        });
        assert!(!bounded.summary().sync_pending);
        assert!(
            bounded
                .verdict(first.id, first.height)
                .unwrap()
                .on_best_chain
        );
        assert!(bounded.verdict(late.id, late.height).unwrap().on_best_chain);
    }

    /// A heavier branch (14 blocks) replaces a connected one (10 blocks),
    /// released by its gap-filling first body. With a budget of one block per
    /// call, the drain stops only at tips at least as heavy as the old tip,
    /// and ends on the same chain as the unbounded reorganization.
    #[test]
    fn a_bounded_reorganization_never_stops_on_a_lighter_tip() {
        let mut src = open();
        let genesis = src.tip_id();
        let a = branch(&mut src, genesis, 10, 1);
        let b = branch(&mut src, genesis, 14, 2);
        let (mut full, mut bounded) = (open(), open());
        for m in [&mut full, &mut bounded] {
            for blk in &a {
                m.submit_block(blk.clone(), NOW).unwrap();
            }
            assert_eq!(m.height(), 10);
            let hs: Vec<BlockHeader> = b.iter().map(|x| x.header).collect();
            m.accept_headers(&hs, NOW).unwrap();
            for blk in b[1..].iter().rev() {
                m.submit_block(blk.clone(), NOW).unwrap();
            }
            assert_eq!(m.height(), 10);
        }
        full.submit_block(b[0].clone(), NOW).unwrap();
        assert_eq!(full.height(), 14);

        let old_work = bounded.work(&bounded.tip_id());
        bounded.submit_block_bounded(b[0].clone(), NOW, 1).unwrap();
        let mut done = !bounded.sync_pending();
        let mut stops = 0;
        while !done {
            stops += 1;
            assert!(bounded.work(&bounded.tip_id()) >= old_work, "lighter tip");
            done = bounded.sync_step(1);
        }
        assert!(stops >= 2, "the drain was interrupted ({stops})");
        same_chain(&full, &bounded);
        assert_eq!(bounded.deepest_reorg(), 10);
    }

    /// A block that passes validation but fails to apply (injected fault:
    /// validation rejects every block that would really fail) halts the
    /// manager. It is not marked invalid and not connected; every further
    /// block is refused with `Halted`; `halted()` names it. After a restart
    /// the stored block is replayed and connects.
    #[test]
    fn an_apply_failure_after_validation_halts_without_invalidating() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        let open_file = || {
            let p = ChainParams::regtest();
            ChainManager::open(
                p.clone(),
                TxRules::for_chain(&p),
                Arc::new(ZeroPow),
                Box::new(crate::store::FileStore::open(&path).unwrap()),
                [3; 32],
            )
        };
        let mut src = open();
        let genesis = src.tip_id();
        let blocks = branch(&mut src, genesis, 3, 1);
        let ids: Vec<Hash> = blocks
            .iter()
            .map(|b| b.id(src.params().network_id))
            .collect();

        let mut m = open_file().unwrap();
        m.submit_block(blocks[0].clone(), NOW).unwrap();
        assert!(m.halted().is_none());
        m.state.fail_next_apply_for_tests();
        let s = m.submit_block(blocks[1].clone(), NOW).unwrap();
        assert!(!s.on_best_chain, "not connected");
        assert_eq!(m.height(), 1);
        assert!(m.invalid.is_empty(), "never marked invalid");
        assert_eq!(m.headers.is_valid(&ids[1]), Some(true));
        let reason = m.halted().expect("halted");
        assert!(reason.contains(&hex(&ids[1])), "{reason}");
        assert!(m.apply_halted() && !m.store_failed(), "an apply halt");
        assert!(matches!(
            m.submit_block(blocks[2].clone(), NOW),
            Err(SubmitError::Halted)
        ));
        assert_eq!(m.height(), 1);
        drop(m);

        // Restart: the store holds blocks 1 and 2 (block 3 was refused);
        // replay applies block 2 this time.
        let mut m = open_file().unwrap();
        assert!(m.halted().is_none() && !m.apply_halted());
        assert_eq!(m.height(), 2);
        assert_eq!(m.tip_id(), ids[1]);
        m.submit_block(blocks[2].clone(), NOW).unwrap();
        assert_eq!(m.height(), 3);
    }
}
