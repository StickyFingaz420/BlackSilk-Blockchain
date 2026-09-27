//! Opening a chain manager and replaying the block store.

use super::pow_cache::CachedPow;
use super::{ChainManager, Replayed, SubmitError, SyncOutcome};
use crate::block::Block;
use crate::mempool::Mempool;
use crate::store::{BlockStore, InvalidOrigin, Marker, Record, StoreIdentity, StoredBlock};
use blacksilk_consensus::{ChainParams, Hash, HeaderChain, HeaderError, PowFunction};
use blacksilk_tx::params::TxRules;
use blacksilk_tx::state::MemoryChain;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::cmp::Reverse;
use std::collections::{BTreeSet, BinaryHeap, HashMap, HashSet};
use std::io;
use std::sync::Arc;

impl ChainManager {
    /// Opens the chain: replays every stored block, then returns the manager.
    /// `rng_seed` seeds the CSPRNG used for batch-verification weights; the node
    /// passes 32 bytes from the OS RNG.
    pub fn open(
        params: ChainParams,
        rules: TxRules,
        pow: Arc<dyn PowFunction>,
        mut store: Box<dyn BlockStore>,
        rng_seed: [u8; 32],
    ) -> io::Result<Self> {
        let pow = Arc::new(CachedPow::new(pow));
        let headers = HeaderChain::new(params.clone(), pow.clone());
        let genesis_id = params.genesis_id();
        let genesis_work = headers.work(&genesis_id).expect("genesis");
        let mut state = MemoryChain::new();
        // Genesis: an empty body (docs/blocks.md §3), which always applies.
        state
            .apply_block(&[])
            .map_err(|e| io::Error::other(format!("genesis state: {e:?}")))?;
        // A store written for another network or genesis, or in a format this
        // build does not read, is refused before any record is read
        // (docs/blocks.md §8).
        store.bind(&StoreIdentity::of(&params))?;
        let stored = blocks_of(store.load()?)?;
        let mut manager = Self {
            params,
            rules,
            headers,
            pow,
            state,
            connected: vec![genesis_id],
            generated: vec![0],
            bodies: HashMap::new(),
            body_seq: HashMap::new(),
            next_body_seq: 0,
            children: HashMap::new(),
            leaves: BTreeSet::from([(genesis_work, genesis_id)]),
            complete: HashMap::from([(genesis_id, 0)]),
            complete_order: BTreeSet::from([(genesis_work, Reverse(0), genesis_id)]),
            next_complete_seq: 1,
            best_complete: genesis_id,
            invalid: HashMap::new(),
            mempool: Mempool::new(),
            store,
            rng: ChaCha20Rng::from_seed(rng_seed),
            deepest_reorg: 0,
            store_failures: 0,
            store_failed: false,
            apply_failed: None,
            ready: BinaryHeap::new(),
            syncing: None,
            sync_outcome: SyncOutcome::default(),
        };
        let total = stored.len() as u64;
        manager.replay(stored)?;
        // A stored block that validates but does not apply stops the node at
        // start-up, as it would live (`halted`); it is not marked invalid.
        if manager.apply_failed.is_some() {
            if let Some(reason) = manager.halted() {
                return Err(io::Error::other(reason));
            }
        }
        // Bodies kept from now on are numbered by their index among the
        // store's block records.
        manager.next_body_seq = total;
        Ok(manager)
    }

    /// Replays the stored blocks.
    ///
    /// Blocks are stored in body arrival order, and bodies arrive in any order
    /// during header-first sync. A block is replayed once its parent is known;
    /// one stored before its parent waits for it. Blocks released together
    /// (the waiting children of a block just replayed) are replayed in storage
    /// order (lowest stored index first).
    ///
    /// **Same result as live processing.** A replayed block's parent was
    /// replayed before it, so each block becomes body-complete as it is
    /// replayed, and the manager syncs after each one. Live processing
    /// completes blocks in the same order: a body completes on arrival if its
    /// parent is complete, and otherwise when its parent completes, siblings
    /// released together going lowest arrival index first (`submit_inner`).
    /// Headers that arrived without bodies are not replayed, and they never
    /// influence the connected chain (module docs), so the replayed tip, state
    /// and tie-breaks equal the live ones (docs/blocks.md §8).
    ///
    /// One exception: a stored block whose parent was never stored in the same
    /// session (a failed parent write, or a parent body refused by the
    /// low-work policy) is dropped from memory after a restart and completes
    /// live only when downloaded again, but a later replay releases the older
    /// copy as soon as the parent is replayed. This can only change which of
    /// two equal-work tips is kept.
    fn replay(&mut self, stored: Vec<StoredBlock>) -> io::Result<()> {
        let total = stored.len();
        // Blocks waiting for their parent, by parent id: stored indices.
        let mut waiting: HashMap<Hash, Vec<usize>> = HashMap::new();
        // Decoded blocks not yet replayed, by stored index.
        let mut pending: HashMap<usize, (Hash, Block)> = HashMap::new();
        // Blocks refused as descendants of an invalid block. Their headers are
        // not in the header chain, so their own descendants are refused too
        // (without this, a child would fail with `UnknownParent` and stop the
        // node from starting, or be counted as an orphan to download again).
        let mut invalid_desc: HashSet<Hash> = HashSet::new();
        for (i, (pow_hash, bytes)) in stored.into_iter().enumerate() {
            let block = Block::decode(&bytes).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("stored block {i} does not decode: {e:?}"),
                )
            })?;
            let prev = block.header.prev_id;
            pending.insert(i, (pow_hash, block));
            if self.headers.header(&prev).is_none() && !invalid_desc.contains(&prev) {
                waiting.entry(prev).or_default().push(i);
                continue;
            }
            let mut ready = BinaryHeap::from([Reverse(i)]);
            while let Some(Reverse(j)) = ready.pop() {
                let (pow_hash, block) = pending.remove(&j).expect("pending block");
                let id = block.id(self.params.network_id);
                if invalid_desc.contains(&block.header.prev_id)
                    || self.replay_one(j, total, pow_hash, block)? == Replayed::InvalidParent
                {
                    invalid_desc.insert(id);
                }
                if let Some(children) = waiting.remove(&id) {
                    ready.extend(children.into_iter().map(Reverse));
                }
            }
        }
        if !invalid_desc.is_empty() {
            log::info!(
                "{} stored block(s) descend from blocks found invalid and were not replayed",
                invalid_desc.len()
            );
        }
        // Blocks whose parent was never stored (for example, the parent's write
        // failed): nothing can be built on them yet. They are dropped from
        // memory, not from the file, and the node downloads them again.
        let orphans: usize = waiting.values().map(Vec::len).sum();
        if orphans > 0 {
            log::warn!(
                "{orphans} stored block(s) without a stored parent were not replayed; \
                 they will be downloaded again"
            );
        }
        Ok(())
    }

    /// Replays one stored block whose parent is known.
    fn replay_one(
        &mut self,
        i: usize,
        total: usize,
        pow_hash: Hash,
        block: Block,
    ) -> io::Result<Replayed> {
        // The stored PoW hash is trusted under the seed derived from the stored
        // parent, exactly as header validation derives it. A header whose height
        // does not follow its parent's is rejected before PoW (no preload needed,
        // and `seed_id_for` needs a consistent height).
        let header = &block.header;
        if let Some(parent) = self.headers.header(&header.prev_id) {
            if header.height == parent.height + 1 {
                let seed = self.headers.seed_id_for(header.prev_id, header.height);
                self.pow.preload(&seed, &header.to_bytes(), pow_hash);
            }
        }
        let now = block.header.timestamp; // the future-time rule was checked on arrival
        match self.submit_inner(block, now, false, usize::MAX) {
            // Deterministic outcomes of the original processing: a body found
            // invalid, and descendants of blocks found invalid.
            Ok(_) | Err(SubmitError::Body(_)) | Err(SubmitError::Duplicate) => Ok(Replayed::Done),
            Err(SubmitError::Header(HeaderError::InvalidParent)) => Ok(Replayed::InvalidParent),
            Err(SubmitError::Halted) => Err(io::Error::other(
                self.halted().unwrap_or_else(|| "halted".into()),
            )),
            Err(e) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("stored block {i} of {total} rejected on replay: {e:?}"),
            )),
        }
    }

    /// Whether the block store failed persistently: a write failed and could
    /// not be undone, or [`STORE_FAILURE_LIMIT`] writes in a row failed. No
    /// block is accepted any more ([`SubmitError::Store`]), and the state does
    /// not change. The node must stop; a restart truncates any torn tail and
    /// resumes from the last stored block (docs/blocks.md §8).
    pub fn store_failed(&self) -> bool {
        self.store_failed
    }

    /// Why the node must stop, if it must: the block store failed
    /// ([`Self::store_failed`]), or applying a block that passed validation
    /// failed. The latter is a bug (validation rejects every block that
    /// would fail to apply, docs/blocks.md §6): the block stays valid and
    /// unconnected, nothing is accepted any more, and the node stops naming
    /// it. A restart replays the store and tries the block again; it is
    /// never marked invalid automatically.
    pub fn halted(&self) -> Option<String> {
        if let Some((id, height, e)) = &self.apply_failed {
            return Some(format!(
                "applying block {} at height {height}, which passed validation, failed: {e}; \
                 the node stops (the block is not marked invalid; report this, it is a bug)",
                super::hex(id)
            ));
        }
        self.store_failed
            .then(|| "the block store failed (see the earlier errors)".to_string())
    }
}

/// The stored blocks, in storage order, from the records of the store
/// (docs/blocks.md §8). Markers do not change the chain a replay reaches in
/// this build:
/// - a checkpoint (own-store validation evidence, for a later build) is not
///   trusted: every stored block is validated in full;
/// - an invalid marker holding the node's own verdict is redundant: the block
///   is validated again and gets the same deterministic verdict;
/// - an invalid marker set by the operator must be honoured, and this build
///   cannot apply one, so the store is refused rather than risk connecting a
///   block the operator ruled out.
fn blocks_of(records: Vec<Record>) -> io::Result<Vec<StoredBlock>> {
    let mut blocks = Vec::with_capacity(records.len());
    let (mut checkpoints, mut verdicts) = (0usize, 0usize);
    for record in records {
        match record {
            Record::Block(b) => blocks.push(b),
            Record::Marker(Marker::Checkpoint(_)) => checkpoints += 1,
            Record::Marker(Marker::Invalid(m)) => match m.origin {
                InvalidOrigin::Verdict => verdicts += 1,
                InvalidOrigin::Operator => {
                    return Err(io::Error::other(format!(
                        "the block store marks block {} invalid by operator request, and \
                         this build cannot apply such a marker; run a build that supports \
                         it, or move the store aside and resync",
                        super::hex(&m.id)
                    )))
                }
            },
        }
    }
    if checkpoints + verdicts > 0 {
        log::info!(
            "block store: {checkpoints} checkpoint(s) not trusted and {verdicts} invalid \
             marker(s) re-checked: every stored block is validated in full"
        );
    }
    Ok(blocks)
}
