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
use rand_chacha::rand_core::{RngCore, SeedableRng};
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

/// What [`ChainManager::open_checked`] does with the proof-of-work hashes
/// stored with the blocks (docs/blocks.md §8; decisions "Agent 01", TM2-5).
///
/// A replay trusts the stored hash of a block instead of recomputing
/// RandomX, so whoever can write the data directory (a copied data
/// directory, a backup from an untrusted source) could plant blocks with
/// fake proof of work. The check recomputes stored hashes after the replay
/// and refuses the store ([`StorePowMismatch`]) if one differs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorePowCheck {
    /// Trust every stored hash ([`ChainManager::open`]: tests and embedders
    /// that wrote the store themselves).
    Trust,
    /// Recompute the stored hashes of the `tip` highest blocks of the
    /// connected chain (the tip region) and of `sampled` blocks drawn
    /// uniformly among its other heights. Both are chosen by height on the
    /// replayed chain, never by position in the file, which whoever wrote
    /// the store controls (RT-NODEOPS). The draw comes from the open's
    /// `rng_seed` (the node draws it from the OS RNG at every start), so
    /// whoever wrote the store cannot know it.
    Sample { sampled: usize, tip: usize },
    /// Recompute every stored hash (the node's `--verify-store-pow`).
    All,
}

impl StorePowCheck {
    /// The node's default (decisions "Agent 01": 48 samples), plus the 16
    /// highest connected blocks.
    pub const NODE_DEFAULT: Self = Self::Sample {
        sampled: 48,
        tip: 16,
    };
}

/// The connected heights a [`StorePowCheck::Sample`] checks on a chain of
/// height `top`: the `tip` highest (down to 1), and `sampled` distinct
/// heights drawn uniformly among `1..=top - tip` with `rng` (Floyd's
/// algorithm; the modulo bias of a 64-bit draw over a height is
/// negligible). Sorted, without genesis.
fn sample_heights(sampled: usize, tip: usize, top: u64, rng: &mut ChaCha20Rng) -> Vec<u64> {
    let rest = top.saturating_sub(tip as u64);
    let mut picked: BTreeSet<u64> = (rest + 1..=top).collect();
    for j in rest.saturating_sub(sampled as u64)..rest {
        // A draw in 1..=j + 1.
        let t = rng.next_u64() % (j + 1) + 1;
        if !picked.insert(t) {
            picked.insert(j + 1);
        }
    }
    picked.into_iter().collect()
}

/// A stored proof-of-work hash that the block's header does not produce
/// ([`StorePowCheck`]): the error inside the `io::Error` of
/// [`ChainManager::open_checked`]. The block store was not written by this
/// node's own verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorePowMismatch {
    /// The block's index among the store's block records, when known
    /// (`--verify-store-pow`), and their number.
    pub index: Option<usize>,
    pub total: usize,
    pub height: u64,
    pub id: Hash,
    /// Stored blocks checked, and how many of them differed.
    pub checked: usize,
    pub mismatches: usize,
}

impl std::fmt::Display for StorePowMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "stored block {}of {} (height {}, id {}) carries a proof-of-work hash that its \
             header does not produce ({} of {} checked blocks differ): this block store was \
             not written by this node's verification (copied from another device, restored \
             from an untrusted backup, or altered)",
            self.index.map_or_else(String::new, |i| format!("{i} ")),
            self.total,
            self.height,
            full_hex(&self.id),
            self.mismatches,
            self.checked
        )
    }
}

impl std::error::Error for StorePowMismatch {}

/// One stored hash to recompute: the block's stored index, height and id,
/// its RandomX key and header, and the stored hash.
struct PowCheck {
    index: Option<usize>,
    height: u64,
    id: Hash,
    seed: Hash,
    header: [u8; blacksilk_consensus::POW_BLOB_SIZE],
    stored: Hash,
}

/// Most threads the stored-hash check uses (the verification-thread
/// default, decisions "Agent 10": `min(4, cores)`).
const POW_CHECK_THREADS: usize = 4;

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
    /// passes 32 bytes from the OS RNG. Every stored proof-of-work hash is
    /// trusted ([`StorePowCheck::Trust`]); the node opens its store with
    /// [`Self::open_checked`].
    pub fn open(
        params: ChainParams,
        rules: TxRules,
        pow: Arc<dyn PowFunction>,
        store: Box<dyn BlockStore>,
        rng_seed: [u8; 32],
    ) -> io::Result<Self> {
        Self::open_checked(params, rules, pow, store, rng_seed, StorePowCheck::Trust)
    }

    /// [`Self::open`], recomputing the stored proof-of-work hashes `check`
    /// selects once the store is replayed, and refusing the store if one
    /// differs (an `io::Error` holding a [`StorePowMismatch`]). The sample
    /// is drawn from `rng_seed` (on its own stream). The hashes are
    /// recomputed on up to [`POW_CHECK_THREADS`] threads.
    pub fn open_checked(
        params: ChainParams,
        rules: TxRules,
        pow: Arc<dyn PowFunction>,
        mut store: Box<dyn BlockStore>,
        rng_seed: [u8; 32],
        check: StorePowCheck,
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
        let mut checks = Vec::new();
        manager.replay(stored, check, &mut checks)?;
        if let StorePowCheck::Sample { sampled, tip } = check {
            let mut rng = ChaCha20Rng::from_seed(rng_seed);
            // Not the batch-weight stream of `manager.rng`.
            rng.set_stream(1);
            let heights = sample_heights(sampled, tip, manager.height(), &mut rng);
            checks = manager.connected_checks(&heights);
        }
        manager.check_stored_pow(check, total as usize, checks)?;
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
    ///
    /// With [`StorePowCheck::All`] the stored proof-of-work hash of every
    /// replayed block is collected in `checks`, for
    /// [`Self::check_stored_pow`]. Unless `check` is
    /// [`StorePowCheck::Trust`], two records of one block with different
    /// stored hashes refuse the store.
    fn replay(
        &mut self,
        stored: Vec<StoredBlock>,
        check: StorePowCheck,
        checks: &mut Vec<PowCheck>,
    ) -> io::Result<()> {
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
                    || self.replay_one(j, total, pow_hash, block, check, checks)?
                        == Replayed::InvalidParent
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

    /// Replays one stored block whose parent is known; with
    /// [`StorePowCheck::All`], its stored PoW hash goes to `checks`.
    fn replay_one(
        &mut self,
        i: usize,
        total: usize,
        pow_hash: Hash,
        block: Block,
        check: StorePowCheck,
        checks: &mut Vec<PowCheck>,
    ) -> io::Result<Replayed> {
        // The stored PoW hash is trusted under the seed derived from the stored
        // parent, exactly as header validation derives it. A header whose height
        // does not follow its parent's is rejected before PoW (no preload needed,
        // and `seed_id_for` needs a consistent height). The first record of a
        // block is the one validation uses (a later copy is a duplicate), so
        // its hash stays in the cache for `check_stored_pow`; a later copy
        // with another hash is itself a forgery (RT-NODEOPS).
        let header = &block.header;
        if let Some(parent) = self.headers.header(&header.prev_id) {
            if header.height == parent.height + 1 {
                let seed = self.headers.seed_id_for(header.prev_id, header.height);
                let bytes = header.pow_blob(self.params.network_id);
                match self.pow.lookup(&seed, &bytes) {
                    None => self.pow.preload(&seed, &bytes, pow_hash),
                    Some(first) if first != pow_hash && check != StorePowCheck::Trust => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            StorePowMismatch {
                                index: Some(i),
                                total,
                                height: header.height,
                                id: block.id(self.params.network_id),
                                checked: 0,
                                mismatches: 1,
                            },
                        ));
                    }
                    Some(_) => {}
                }
                if check == StorePowCheck::All {
                    checks.push(PowCheck {
                        index: Some(i),
                        height: header.height,
                        id: block.id(self.params.network_id),
                        seed,
                        header: bytes,
                        stored: pow_hash,
                    });
                }
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

    /// The checks of the connected blocks at `heights`: each block's RandomX
    /// key and header, and the hash its header validation used (the first
    /// stored record's, from the PoW cache). Heights above the tip, and
    /// blocks without a cached hash, are skipped.
    fn connected_checks(&self, heights: &[u64]) -> Vec<PowCheck> {
        heights
            .iter()
            .filter_map(|&h| {
                let id = *self.connected.get(usize::try_from(h).ok()?)?;
                let header = self.headers.header(&id)?;
                let seed = self.headers.seed_id_for(header.prev_id, h);
                let bytes = header.pow_blob(self.params.network_id);
                let stored = self.pow.lookup(&seed, &bytes)?;
                Some(PowCheck {
                    index: None,
                    height: h,
                    id,
                    seed,
                    header: bytes,
                    stored,
                })
            })
            .collect()
    }

    /// Recomputes the stored PoW hashes in `checks` (selected by `check`
    /// among the store's `total` blocks) on up to [`POW_CHECK_THREADS`]
    /// threads, and fails with a [`StorePowMismatch`] naming the first
    /// block (by height, then stored index) whose hash differs. Nothing to
    /// do for [`StorePowCheck::Trust`] or an empty store.
    fn check_stored_pow(
        &self,
        check: StorePowCheck,
        total: usize,
        mut checks: Vec<PowCheck>,
    ) -> io::Result<()> {
        if checks.is_empty() {
            return Ok(());
        }
        let started = std::time::Instant::now();
        checks.sort_unstable_by_key(|c| (c.height, c.index));
        let threads = std::thread::available_parallelism()
            .map_or(1, |n| n.get())
            .clamp(1, POW_CHECK_THREADS)
            .min(checks.len());
        let pow = &self.pow;
        // Interleaved, so the threads hash under the same keys in turn.
        let differ: Vec<bool> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..threads)
                .map(|t| {
                    let checks = &checks;
                    s.spawn(move || {
                        checks
                            .iter()
                            .enumerate()
                            .skip(t)
                            .step_by(threads)
                            .map(|(k, c)| (k, pow.recompute(&c.seed, &c.header) != c.stored))
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            let mut differ = vec![false; checks.len()];
            for h in handles {
                for (k, d) in h.join().unwrap_or_else(|p| std::panic::resume_unwind(p)) {
                    differ[k] = d;
                }
            }
            differ
        });
        let mismatches = differ.iter().filter(|d| **d).count();
        if let Some(k) = differ.iter().position(|d| *d) {
            let c = &checks[k];
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                StorePowMismatch {
                    index: c.index,
                    total,
                    height: c.height,
                    id: c.id,
                    checked: checks.len(),
                    mismatches,
                },
            ));
        }
        let what = match check {
            StorePowCheck::All => "all".to_string(),
            StorePowCheck::Sample { sampled, tip } => {
                format!("the {tip} highest connected blocks and up to {sampled} sampled heights")
            }
            StorePowCheck::Trust => "none".to_string(),
        };
        log::info!(
            "block store: {} of {total} stored proof-of-work hashes re-verified ({what}) in \
             {:.1?} on {threads} thread(s)",
            checks.len(),
            started.elapsed()
        );
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The tip region is the `tip` highest heights, the samples are
    /// distinct heights below it, genesis is never checked, and a short
    /// chain is checked in full.
    #[test]
    fn sample_heights_cover_the_tip_and_draw_below_it() {
        let mut rng = ChaCha20Rng::from_seed([3; 32]);
        let h = sample_heights(48, 16, 1000, &mut rng);
        assert_eq!(h.len(), 64);
        assert!((985..=1000).all(|x| h.contains(&x)));
        assert!(h.iter().all(|&x| (1..=1000).contains(&x)));
        assert!(h.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(
            sample_heights(48, 16, 20, &mut rng),
            (1..=20).collect::<Vec<_>>()
        );
        assert!(sample_heights(48, 16, 0, &mut rng).is_empty());
        assert_eq!(
            sample_heights(0, 16, 5, &mut rng),
            (1..=5).collect::<Vec<_>>()
        );
        // Every height below the tip region is reachable.
        let mut seen = BTreeSet::new();
        for s in 0..200u8 {
            let mut rng = ChaCha20Rng::from_seed([s; 32]);
            seen.extend(sample_heights(48, 16, 100, &mut rng));
        }
        assert_eq!(seen.len(), 100);
    }
}
