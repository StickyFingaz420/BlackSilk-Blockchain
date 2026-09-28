//! Opening a chain manager and replaying the block store.

use super::pow_cache::CachedPow;
use super::{ChainManager, Replayed, SubmitError, SyncOutcome, OPERATOR_REASON};
use crate::block::Block;
use crate::mempool::Mempool;
use crate::store::{
    BlockStore, InvalidMarker, InvalidOrigin, Marker, Record, StoreIdentity, StoredBlock,
};
use blacksilk_consensus::{ChainParams, Hash, HeaderChain, HeaderError, PowFunction};
use blacksilk_tx::params::TxRules;
use blacksilk_tx::state::MemoryChain;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::cmp::Reverse;
use std::collections::{BTreeSet, BinaryHeap, HashMap, HashSet};
use std::io;
use std::sync::Arc;

/// An operator verdict for [`ChainManager::mark_stored_block`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperatorMark {
    /// `--invalidate-block`: the block and its descendants are never
    /// connected.
    Invalidate,
    /// `--reconsider-block`: cancels an earlier operator invalidation of the
    /// block.
    Reconsider,
}

/// What [`ChainManager::mark_stored_block`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperatorMarked {
    /// The marker was appended. `height` is the block's height if the store
    /// holds the block, `None` if it does not (yet): an invalidation then
    /// applies when the block arrives.
    Appended { height: Option<u64> },
    /// Nothing was appended: the block is already invalidated by the
    /// operator (`Invalidate`), or it is not (`Reconsider`).
    Unchanged,
}

impl ChainManager {
    /// Appends an operator verdict on block `id` to a store that is not
    /// open (the node's `--invalidate-block` and `--reconsider-block`,
    /// handled before [`Self::open`]; docs/blocks.md §8). The store is bound
    /// to `params`' network and loaded first, exactly as `open` does (a torn
    /// tail is truncated), so a store `open` would refuse is refused here
    /// too, unchanged. The marker takes effect when the store is opened; the
    /// last verdict for an id wins.
    ///
    /// Refused (`InvalidInput`, nothing written): invalidating genesis. A
    /// legacy headerless (regtest) store keeps no markers (`Unsupported`).
    pub fn mark_stored_block(
        params: &ChainParams,
        store: &mut dyn BlockStore,
        id: Hash,
        mark: OperatorMark,
    ) -> io::Result<OperatorMarked> {
        if mark == OperatorMark::Invalidate && id == params.genesis_id() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the genesis block cannot be invalidated",
            ));
        }
        store.bind(&StoreIdentity::of(params))?;
        let records = store.load()?;
        let height = records.iter().find_map(|r| match r {
            Record::Block((_, bytes)) => Block::decode(bytes)
                .ok()
                .filter(|b| b.id(params.network_id) == id)
                .map(|b| b.header.height),
            Record::Marker(_) => None,
        });
        let invalid_now = scan(records).operator.contains(&id);
        let marker = match (mark, invalid_now) {
            (OperatorMark::Invalidate, false) => Marker::Invalid(InvalidMarker {
                id,
                origin: InvalidOrigin::Operator,
                reason: OPERATOR_REASON.into(),
            }),
            (OperatorMark::Reconsider, true) => Marker::Reconsider(id),
            _ => return Ok(OperatorMarked::Unchanged),
        };
        store.append_marker(&marker)?;
        Ok(OperatorMarked::Appended { height })
    }

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
        let genesis_header = *headers.header(&genesis_id).expect("genesis");
        let (network, network_id) = (params.network, params.network_id);
        let mut state = MemoryChain::new();
        // Genesis: an empty body (docs/blocks.md §3), which always applies.
        state
            .apply_block(&[])
            .map_err(|e| io::Error::other(format!("genesis state: {e:?}")))?;
        // A store written for another network or genesis, or in a format this
        // build does not read, is refused before any record is read
        // (docs/blocks.md §8).
        store.bind(&StoreIdentity::of(&params))?;
        let Scanned {
            blocks: stored,
            operator,
            checkpoints,
            verdicts,
        } = scan(store.load()?);
        if checkpoints + verdicts > 0 {
            log::info!(
                "block store: {checkpoints} checkpoint(s) not trusted and {verdicts} invalid \
                 marker(s) re-checked: every stored block is validated in full"
            );
        }
        if !operator.is_empty() {
            log::warn!(
                "block store: {} block(s) invalidated by the operator (--invalidate-block); \
                 they and their descendants are not connected",
                operator.len()
            );
        }
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
            operator_invalid: operator,
            template_latched: false,
            mempool: Mempool::new(),
            store,
            rng: ChaCha20Rng::from_seed(rng_seed),
            deepest_reorg: 0,
            store_failures: 0,
            store_failed: false,
            apply_failed: None,
            hot_seeds: Vec::new(),
            ready: BinaryHeap::new(),
            syncing: None,
            sync_outcome: SyncOutcome::default(),
            summary: Arc::new(super::SummaryCell::placeholder(
                genesis_header,
                network,
                network_id,
            )),
            #[cfg(feature = "test-hooks")]
            step_delay: None,
        };
        let total = stored.len() as u64;
        manager.replay(stored)?;
        // A stored block that validates but does not apply stops the node at
        // start-up, as it would live (`halted`); it is not marked invalid.
        if manager.apply_failed.is_some() {
            if let Some(reason) = manager.halted() {
                return Err(io::Error::other(super::ApplyHalt(reason)));
            }
        }
        // Bodies kept from now on are numbered by their index among the
        // store's block records.
        manager.next_body_seq = total;
        // The pool is not persisted and starts empty (docs/blocks.md §7). A
        // replay that reorganizes pools the transactions of the blocks it
        // disconnects, as it would live; a restart drops them like the rest
        // of the pool (finding W2-02-F1). Peers' re-announcement brings back
        // what is still pending.
        manager.mempool = Mempool::new();
        manager.log_operator_verdicts();
        manager.refresh_hot_seeds();
        manager.publish_first_summary();
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

    /// Logs every operator verdict in force once the store is replayed
    /// (RTW3-11): the full block id and the block's height, or that the
    /// block has not arrived yet; then whether a heavier chain is refused
    /// only because of them ([`Self::operator_fork`]).
    fn log_operator_verdicts(&self) {
        for id in self.operator_verdicts() {
            match self.headers.header(&id) {
                Some(h) => log::warn!(
                    "operator verdict in force: block {} at height {} is invalid by operator \
                     request (--reconsider-block {} cancels it)",
                    full_hex(&id),
                    h.height,
                    full_hex(&id)
                ),
                None => log::warn!(
                    "operator verdict in force: block {} (not received yet) is invalid by \
                     operator request (--reconsider-block {} cancels it)",
                    full_hex(&id),
                    full_hex(&id)
                ),
            }
        }
        if let Some(f) = self.operator_fork() {
            log::warn!(
                "a heavier chain (known up to height {}) is refused only because the operator \
                 invalidated block {} at height {}: this node is off that chain",
                f.branch_height,
                full_hex(&f.block),
                f.height
            );
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
            let full = full_hex(id);
            return Some(format!(
                "applying block {} at height {height} failed: {e}. The block passed \
                 validation, so it is consensus-valid by this build's rules: this is a bug in \
                 this build, not a bad block. The node stops; the block is not marked invalid. \
                 Report the incident (block id, log, data directory) and keep the data \
                 directory. Invalidating the block forks this node off the network's chain: \
                 it then follows no chain containing the block, however much work it has, \
                 until --reconsider-block {full} undoes the verdict after an upgrade to a \
                 fixed build. Only if you accept that, restart once with \
                 --invalidate-block {full}",
                super::hex(id),
            ));
        }
        self.store_failed
            .then(|| "the block store failed (see the earlier errors)".to_string())
    }
}

/// All 64 hex digits of a block id (what `--invalidate-block` takes).
fn full_hex(id: &Hash) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

/// The records of a store, sorted for replay.
struct Scanned {
    /// The stored blocks, in storage order.
    blocks: Vec<StoredBlock>,
    /// The blocks the operator invalidated and did not reconsider since.
    operator: HashSet<Hash>,
    checkpoints: usize,
    verdicts: usize,
}

/// Sorts the records of the store (docs/blocks.md §8):
/// - a checkpoint (own-store validation evidence, for a later build) is not
///   trusted: every stored block is validated in full;
/// - an invalid marker holding the node's own verdict is redundant: the block
///   is validated again and gets the same deterministic verdict;
/// - an invalid marker set by the operator is honoured: the block is never
///   connected (`ChainManager::mark_complete`), whatever its body, and its
///   descendants are refused. A later reconsider marker for the same id
///   cancels it (and a later invalid marker restores it): the last operator
///   record for an id wins, wherever it is in the log.
fn scan(records: Vec<Record>) -> Scanned {
    let mut out = Scanned {
        blocks: Vec::with_capacity(records.len()),
        operator: HashSet::new(),
        checkpoints: 0,
        verdicts: 0,
    };
    for record in records {
        match record {
            Record::Block(b) => out.blocks.push(b),
            Record::Marker(Marker::Checkpoint(_)) => out.checkpoints += 1,
            Record::Marker(Marker::Invalid(m)) => match m.origin {
                InvalidOrigin::Verdict => out.verdicts += 1,
                InvalidOrigin::Operator => {
                    out.operator.insert(m.id);
                }
            },
            Record::Marker(Marker::Reconsider(id)) => {
                out.operator.remove(&id);
            }
        }
    }
    out
}
