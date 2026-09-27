//! The chain manager (docs/blocks.md §5–§8): header chain, transaction state,
//! emission, reorganizations, mempool and storage behind one API.
//!
//! **Invariant.** The transaction state equals the result of applying the bodies of
//! `connected[1..]` in order, and the connected tip is the *connection target*
//! (docs/blocks.md §6): the most-work valid header whose own body and every
//! ancestor's body are available ("body-complete"). Between equal-work
//! candidates the connected tip stays; otherwise the candidate that became
//! complete first wins.
//!
//! The header chain's best chain (`HeaderChain::main_id_at`) is only a download
//! and locator guide: a heavier header branch whose bodies are withheld never
//! holds the connected chain back (before 2026-09-27 it did: the state only
//! followed the header-best chain, so a bodiless header tying the tip stalled
//! block production for good).
//!
//! **Determinism.** The target depends only on the sequence of *kept* bodies
//! (which is the storage order), never on the order in which headers arrived:
//! a block becomes complete when its body is kept and its parent is complete,
//! and blocks completed together (descendants waiting for a parent) complete in
//! body-arrival order. [`ChainManager::sync_state`] runs after each single
//! completion. Replay (`replay`) releases stored blocks in exactly this order
//! and also syncs after each one, so live processing and every restart pass
//! through the same sequence of states.

use crate::block::Block;
use crate::emission::block_reward;
use crate::mempool::{Mempool, MempoolError, COINBASE_RESERVE};
use crate::store::BlockStore;
use blacksilk_consensus::hash::H;
use blacksilk_consensus::{
    seed_height, BlockHeader, ChainParams, Hash, HeaderChain, HeaderError, PowFunction,
};
use blacksilk_tx::params::TxRules;
use blacksilk_tx::state::MemoryChain;
use blacksilk_tx::types::Transaction;
use blacksilk_tx::validate::{validate_block_transactions_cached, BlockContext, BlockError};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::cmp::Reverse;
use std::collections::{BTreeSet, BinaryHeap, HashMap, HashSet};
use std::io;
use std::sync::{Arc, Mutex};

/// PoW wrapper that remembers every computed hash, keyed by the RandomX key
/// (seed block id) **and** the header bytes. It lets the node store PoW hashes
/// with blocks and skip recomputing RandomX when replaying its own store.
///
/// The seed is part of the key so that a hash computed under one seed (for
/// example by [`ChainManager::pow_jobs`] from a peer's batch) is never reused
/// where header validation derives a different seed: that lookup misses and
/// the hash is computed again under the right key.
pub struct CachedPow {
    inner: Arc<dyn PowFunction>,
    known: Mutex<HashMap<Hash, Hash>>,
}

impl CachedPow {
    pub fn new(inner: Arc<dyn PowFunction>) -> Self {
        Self {
            inner,
            known: Mutex::new(HashMap::new()),
        }
    }

    fn key(seed: &Hash, header_bytes: &[u8]) -> Hash {
        H::new()
            .chain(b"BlackSilk/pow-cache/v2")
            .chain(seed)
            .chain(header_bytes)
            .finish()
    }

    /// The cached PoW hash of `header_bytes` under the RandomX key `seed`.
    pub fn lookup(&self, seed: &Hash, header_bytes: &[u8]) -> Option<Hash> {
        let known = self.known.lock().unwrap_or_else(|e| e.into_inner());
        known.get(&Self::key(seed, header_bytes)).copied()
    }

    /// Trusts `pow_hash` for `header_bytes` under `seed` (only for blocks from
    /// the node's own store, with the seed derived from the stored parent).
    pub fn preload(&self, seed: &Hash, header_bytes: &[u8], pow_hash: Hash) {
        let mut known = self.known.lock().unwrap_or_else(|e| e.into_inner());
        known.insert(Self::key(seed, header_bytes), pow_hash);
    }
}

/// One PoW computation: RandomX key (seed block id) and header bytes.
pub type PowJob = (Hash, [u8; blacksilk_consensus::HEADER_SIZE]);

impl CachedPow {
    /// Computes and caches the PoW hashes of `jobs` on `threads` threads.
    pub fn compute_parallel(&self, jobs: &[PowJob], threads: usize) {
        let todo: Vec<&PowJob> = jobs
            .iter()
            .filter(|(seed, b)| self.lookup(seed, b).is_none())
            .collect();
        if todo.is_empty() {
            return;
        }
        let threads = threads.clamp(1, todo.len());
        let next = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|s| {
            for _ in 0..threads {
                s.spawn(|| loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some((seed, bytes)) = todo.get(i) else {
                        break;
                    };
                    let _ = self.pow_hash(seed, bytes);
                });
            }
        });
    }
}

impl PowFunction for CachedPow {
    fn pow_hash(&self, seed: &Hash, header_bytes: &[u8]) -> Hash {
        if let Some(h) = self.lookup(seed, header_bytes) {
            return h;
        }
        let h = self.inner.pow_hash(seed, header_bytes);
        self.preload(seed, header_bytes, h);
        h
    }
}

#[derive(Debug)]
pub enum SubmitError {
    /// The block (id) is already known.
    Duplicate,
    /// The body does not match the header's `tx_root`; the header was not touched.
    BodyMismatch,
    Header(HeaderError),
    /// The header was valid, but the body failed validation when connecting; the
    /// block is now marked invalid.
    Body(BlockError),
    Store(io::Error),
}

/// Outcome of replaying one stored block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Replayed {
    Done,
    /// Refused as a descendant of an invalid block (its header is not kept).
    InvalidParent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Submitted {
    pub id: Hash,
    pub height: u64,
    /// Whether the block is now part of the connected best chain.
    pub on_best_chain: bool,
    /// Whether the body was stored and kept. `false` only for a low-work
    /// side-branch body refused by node policy ([`LOW_WORK_MARGIN_BLOCKS`]);
    /// its header was accepted (not a consensus rejection).
    pub body_kept: bool,
}

/// Everything a miner needs to build the next block (docs/blocks.md §9 `/template`).
#[derive(Clone, Debug)]
pub struct Template {
    pub height: u64,
    pub prev_id: Hash,
    pub difficulty: u64,
    pub seed_id: Hash,
    pub min_timestamp: u64,
    /// `reward(height)`; the coinbase must pay exactly `reward + fees`.
    pub reward: u64,
    pub fees: u64,
    /// Transactions to include after the coinbase, in order.
    pub txs: Vec<Transaction>,
}

/// Reorganizations at least this deep are logged as warnings. There is no depth
/// limit: the chain with the most work always wins (docs/consensus.md §8,
/// docs/reviews/assumptions.md K4).
pub const DEEP_REORG_WARN_DEPTH: usize = 10;

/// Node policy (not consensus), docs/blocks.md §8: a body is stored and kept
/// only if its block's cumulative work is at least the connected tip's work
/// minus this many blocks at the tip's difficulty, or if the block lies on the
/// path to a header tip with more work than the connected tip (a candidate the
/// node downloads bodies for, [`ChainManager::missing_bodies`]). Anything else
/// is a cheap low-work side branch (for example a child of an early,
/// low-difficulty block) whose body would otherwise be stored forever. The
/// margin covers locally mined side branches up to this depth; reorganizations
/// arriving from the network come header-first and are candidates, so no
/// honest reorganization of any depth is refused.
pub const LOW_WORK_MARGIN_BLOCKS: u128 = 100;

/// Transactions and flags collected while the connected chain moves, applied to
/// the mempool once at the end ([`ChainManager::finish_sync`]).
#[derive(Default)]
struct SyncOutcome {
    /// Transactions of disconnected blocks.
    returned: Vec<Transaction>,
    /// Whether any block was disconnected (the mempool then re-checks every
    /// rule; a reorganization of coinbase-only blocks returns nothing).
    reorganized: bool,
}

pub struct ChainManager {
    params: ChainParams,
    rules: TxRules,
    headers: HeaderChain,
    pow: Arc<CachedPow>,
    state: MemoryChain,
    /// Connected block ids by height; `connected[0]` is genesis.
    connected: Vec<Hash>,
    /// `generated[h]` = coins created by blocks `1..=h` of the connected chain.
    generated: Vec<u64>,
    bodies: HashMap<Hash, Vec<Transaction>>,
    /// Body arrival order of every kept body (equal to its index in the store
    /// for bodies kept in this session; see `replay`).
    body_seq: HashMap<Hash, u64>,
    next_body_seq: u64,
    /// Header tree children (every header enters through this manager).
    children: HashMap<Hash, Vec<Hash>>,
    /// Valid headers without a valid child, by cumulative work.
    leaves: BTreeSet<(u128, Hash)>,
    /// Body-complete valid blocks: id -> completion order. Contains genesis
    /// and every connected block.
    complete: HashMap<Hash, u64>,
    /// The same blocks ordered by (work, earliest completion).
    complete_order: BTreeSet<(u128, Reverse<u64>, Hash)>,
    next_complete_seq: u64,
    /// The connection target (module docs).
    best_complete: Hash,
    invalid: HashMap<Hash, BlockError>,
    mempool: Mempool,
    store: Box<dyn BlockStore>,
    rng: ChaCha20Rng,
    /// The deepest reorganization since the manager was opened.
    deepest_reorg: usize,
    /// Consecutive failed appends (reset by a successful one).
    store_failures: u32,
    /// The block store failed persistently: no block is accepted any more.
    store_failed: bool,
    /// Blocks ready to complete (body kept, parent complete), lowest body
    /// arrival first. Drained by [`ChainManager::sync_step`] (and at once by
    /// [`ChainManager::submit_block`]).
    ready: BinaryHeap<Reverse<(u64, Hash)>>,
    /// The completed block whose `sync_state` stopped at the connect budget
    /// (its children are released when it finishes).
    syncing: Option<Hash>,
    /// Mempool effects of a drain in progress, applied when it ends.
    sync_outcome: SyncOutcome,
}

/// Blocks validated and connected per lock hold by the bounded API
/// ([`ChainManager::submit_block_bounded`], [`ChainManager::sync_step`]):
/// the P2P layer releases the chain lock between steps (docs/p2p.md §6).
pub const SYNC_STEP_BLOCKS: usize = 8;

/// Submits `block` through the bounded API, taking the chain lock with `lock`
/// once per step (at most `budget` block validations each) and releasing it
/// in between, so readers and other writers get the lock while a long batch
/// of downloaded blocks connects. The final verdict is the one
/// [`ChainManager::submit_block`] would return: the chain reaches the same
/// state, only the lock is released between steps.
pub fn submit_block_in_steps<'a>(
    lock: impl Fn() -> std::sync::MutexGuard<'a, ChainManager>,
    block: Block,
    now: u64,
    budget: usize,
) -> Result<Submitted, SubmitError> {
    let first = lock().submit_block_bounded(block, now, budget)?;
    if !first.body_kept {
        return Ok(first);
    }
    loop {
        // The standard mutex is not fair: a yield alone lets this loop take the
        // lock again before a waiting reader (RPC, P2P) is scheduled, which was
        // observed on Windows. A short sleep hands the lock to waiters; a batch
        // of 256 blocks is at most 32 steps, so the cost is negligible next to
        // validating the blocks.
        std::thread::sleep(std::time::Duration::from_millis(1));
        let mut c = lock();
        if c.sync_step(budget) {
            return c.verdict(first.id, first.height);
        }
    }
}

/// Consecutive failed block writes after which the store counts as failed
/// ([`ChainManager::store_failed`]). A single failure is undone by the store
/// and the block is downloaded again; repeated ones mean a full or failing
/// disk, where continuing would only re-download bodies forever.
pub const STORE_FAILURE_LIMIT: u32 = 3;

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
        state.apply_block(&[]); // genesis: empty body (docs/blocks.md §3)
                                // A store written for another network or genesis is refused before
                                // any record is read (docs/blocks.md §8).
        store.bind(params.network_id, &genesis_id)?;
        let stored = store.load()?;
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
            ready: BinaryHeap::new(),
            syncing: None,
            sync_outcome: SyncOutcome::default(),
        };
        let total = stored.len() as u64;
        manager.replay(stored)?;
        // Bodies kept from now on are numbered by their index in the store.
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
    fn replay(&mut self, stored: Vec<crate::store::StoredBlock>) -> io::Result<()> {
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

    /// The PoW cache shared with the header chain (tests and diagnostics).
    pub fn pow_cache(&self) -> &Arc<CachedPow> {
        &self.pow
    }

    pub fn params(&self) -> &ChainParams {
        &self.params
    }

    pub fn rules(&self) -> &TxRules {
        &self.rules
    }

    /// Height of the connected tip.
    pub fn height(&self) -> u64 {
        (self.connected.len() - 1) as u64
    }

    pub fn tip_id(&self) -> Hash {
        *self.connected.last().expect("genesis is always connected")
    }

    pub fn tip_header(&self) -> &BlockHeader {
        self.headers
            .header(&self.tip_id())
            .expect("connected blocks have headers")
    }

    /// Coins generated so far on the connected chain (fees excluded).
    pub fn generated(&self) -> u64 {
        *self.generated.last().expect("non-empty")
    }

    pub fn state(&self) -> &MemoryChain {
        &self.state
    }

    /// The deepest reorganization (blocks disconnected) since opening.
    pub fn deepest_reorg(&self) -> usize {
        self.deepest_reorg
    }

    pub fn mempool(&self) -> &Mempool {
        &self.mempool
    }

    pub fn headers(&self) -> &HeaderChain {
        &self.headers
    }

    /// The connected block at `height`.
    pub fn block_at(&self, height: u64) -> Option<Block> {
        let id = self.connected.get(height as usize)?;
        let header = *self.headers.header(id)?;
        let txs = if height == 0 {
            Vec::new()
        } else {
            self.bodies.get(id)?.clone()
        };
        Some(Block { header, txs })
    }

    /// Why a block was rejected when connecting, if it was.
    pub fn invalid_reason(&self, id: &Hash) -> Option<&BlockError> {
        self.invalid.get(id)
    }

    /// Accepts a block from the local miner or (later) the network.
    pub fn submit_block(&mut self, block: Block, now: u64) -> Result<Submitted, SubmitError> {
        self.submit_inner(block, now, true, usize::MAX)
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
        self.submit_inner(block, now, true, budget)
    }

    /// Continues the drain started by [`Self::submit_block_bounded`]: at most
    /// `budget` block validations. Returns true when nothing is left (the
    /// mempool then received the drain's effects).
    pub fn sync_step(&mut self, budget: usize) -> bool {
        self.drain_ready(budget)
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

    fn submit_inner(
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
        let mut outcome = std::mem::take(&mut self.sync_outcome);
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
        self.finish_sync(outcome);
        true
    }

    /// Records a header just accepted by the header chain.
    fn header_added(&mut self, id: Hash, prev: Hash) {
        self.children.entry(prev).or_default().push(id);
        if let Some(w) = self.headers.work(&prev) {
            self.leaves.remove(&(w, prev));
        }
        let w = self.work(&id);
        self.leaves.insert((w, id));
    }

    fn work(&self, id: &Hash) -> u128 {
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
    fn keeps_body(&self, id: &Hash) -> bool {
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
    fn mark_complete(&mut self, id: Hash) {
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
    /// work; among equal work the connected tip if it is one of them (no
    /// flapping), else the one completed first.
    fn recompute_target(&mut self) {
        let &(w, _, id) = self
            .complete_order
            .last()
            .expect("genesis is always complete");
        let tip = self.tip_id();
        self.best_complete = if self.work(&tip) == w { tip } else { id };
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
        self.headers.mark_invalid(&id);
        let mut stack = vec![id];
        while let Some(x) = stack.pop() {
            let w = self.work(&x);
            if let Some(seq) = self.complete.remove(&x) {
                self.complete_order.remove(&(w, Reverse(seq), x));
            }
            self.leaves.remove(&(w, x));
            self.bodies.remove(&x);
            self.body_seq.remove(&x);
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
    }

    /// Height of the last block shared by the connected chain and the best header
    /// chain.
    fn fork_height(&self) -> usize {
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
    fn sync_state(&mut self, outcome: &mut SyncOutcome, budget: &mut usize) -> bool {
        let floor = self.work(&self.tip_id());
        loop {
            let target = self.best_complete;
            if target == self.tip_id() {
                return true;
            }
            debug_assert!(self.work(&target) > self.work(&self.tip_id()));
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
                let id = self.connected.pop().expect("above genesis");
                self.generated.pop();
                assert!(self.state.undo_block());
                if let Some(body) = self.bodies.get(&id) {
                    outcome.returned.extend(body.iter().skip(1).cloned());
                }
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
                // PX proofs already verified on mempool admission are not
                // verified again (validate_block_transactions_cached).
                let mempool = &self.mempool;
                match validate_block_transactions_cached(
                    body,
                    &ctx,
                    &self.state,
                    &self.rules,
                    &mut self.rng,
                    &|id| mempool.contains(id),
                ) {
                    Ok(()) => {
                        self.state.apply_block(body);
                        self.connected.push(id);
                        self.generated.push(generated + reward);
                        self.mempool.remove_block(body);
                    }
                    Err(e) => {
                        self.invalidate(id, e);
                        break;
                    }
                }
            }
        }
    }

    /// Mempool: returns transactions from disconnected blocks, then drops
    /// anything no longer valid at the new tip.
    fn finish_sync(&mut self, outcome: SyncOutcome) {
        let next = self.height() + 1;
        for tx in outcome.returned {
            let _ = self.mempool.add(tx, &self.state, next, &self.rules);
        }
        self.mempool
            .revalidate(&self.state, next, &self.rules, outcome.reorganized);
    }

    // ---- header-first sync (docs/p2p.md §6) ----

    /// Height of the best valid header chain (may exceed [`Self::height`] while
    /// bodies are downloading).
    pub fn header_height(&self) -> u64 {
        self.headers.height()
    }

    pub fn best_header_id(&self) -> Hash {
        self.headers.tip_id()
    }

    pub fn header(&self, id: &Hash) -> Option<&BlockHeader> {
        self.headers.header(id)
    }

    /// Whether the header is known and not invalid.
    pub fn knows_valid_header(&self, id: &Hash) -> bool {
        self.headers.is_valid(id) == Some(true)
    }

    pub fn has_body(&self, id: &Hash) -> bool {
        *id == self.params.genesis_id() || self.bodies.contains_key(id)
    }

    /// Any stored block (main chain or side branch) with its body.
    pub fn block(&self, id: &Hash) -> Option<Block> {
        let header = *self.headers.header(id)?;
        if *id == self.params.genesis_id() {
            return Some(Block {
                header,
                txs: Vec::new(),
            });
        }
        let txs = self.bodies.get(id)?.clone();
        Some(Block { header, txs })
    }

    /// Block locator over the best header chain: the tip, 10 predecessors one by
    /// one, then exponentially sparser back to genesis (at most 64 ids).
    pub fn locator(&self) -> Vec<Hash> {
        let mut out = Vec::new();
        let mut h = self.headers.height();
        let mut step = 1u64;
        loop {
            out.push(self.headers.main_id_at(h).expect("height on best chain"));
            if h == 0 || out.len() >= 63 {
                break;
            }
            if out.len() >= 10 {
                step *= 2;
            }
            h = h.saturating_sub(step);
        }
        if *out.last().expect("non-empty") != self.params.genesis_id() {
            out.push(self.params.genesis_id());
        }
        out
    }

    /// Headers of the best chain following the first locator id found on it, up to
    /// `max`, ending early at `stop`.
    pub fn headers_after(&self, locator: &[Hash], stop: &Hash, max: usize) -> Vec<BlockHeader> {
        let start = locator
            .iter()
            .find(|id| self.headers.is_on_main(id))
            .and_then(|id| self.headers.header(id))
            .map_or(1, |h| h.height + 1);
        let mut out = Vec::new();
        let mut h = start;
        while out.len() < max {
            let Some(id) = self.headers.main_id_at(h) else {
                break;
            };
            out.push(*self.headers.header(&id).expect("main header"));
            if id == *stop {
                break;
            }
            h += 1;
        }
        out
    }

    /// Blocks whose body is missing on the way to every valid header tip with
    /// more work than the connected tip, lowest height first (for download).
    /// The header-best chain is scanned forward from its fork with the
    /// connected chain; any other heavier tip (a competing branch, for example
    /// while the header-best one's bodies are withheld) is walked back to its
    /// last body-complete ancestor. Equal-work tips are not listed: they could
    /// not replace the connected tip (ties keep it).
    pub fn missing_bodies(&self, max: usize) -> Vec<(u64, Hash)> {
        let tip_work = self.work(&self.tip_id());
        let mut out = Vec::new();
        if self.headers.best_work() > tip_work {
            let mut h = self.fork_height() as u64 + 1;
            while out.len() < max {
                let Some(id) = self.headers.main_id_at(h) else {
                    break;
                };
                if !self.bodies.contains_key(&id) {
                    out.push((h, id));
                }
                h += 1;
            }
        }
        let main_tip = self.headers.tip_id();
        let mut seen: HashSet<Hash> = out.iter().map(|&(_, id)| id).collect();
        for &(_, leaf) in self.leaves.range((tip_work + 1, [0u8; 32])..) {
            if leaf == main_tip {
                continue;
            }
            let mut cur = leaf;
            while !self.complete.contains_key(&cur) {
                let header = self.headers.header(&cur).expect("valid header");
                if !self.bodies.contains_key(&cur) && seen.insert(cur) {
                    out.push((header.height, cur));
                }
                cur = header.prev_id;
            }
        }
        out.sort_by_key(|&(h, _)| h);
        out.truncate(max);
        out
    }

    /// Work to precompute the PoW of a batch of headers (docs/p2p.md §6): the seed
    /// and bytes of each header, taking seeds from the batch itself where needed.
    /// `None` if the batch does not extend a known header or is not a chain. Run
    /// the result with [`CachedPow::compute_parallel`] *without* holding a lock on
    /// the manager, then accept the headers cheaply.
    pub fn pow_jobs(&self, headers: &[BlockHeader]) -> Option<(Arc<CachedPow>, Vec<PowJob>)> {
        let first = headers.first()?;
        let parent = self.headers.header(&first.prev_id)?;
        // Seeds below the batch are looked up on the parent's branch, which is
        // only defined for heights up to the parent's (a height gap would walk
        // past genesis and panic).
        if first.height != parent.height + 1 {
            return None;
        }
        let nid = self.params.network_id;
        let ids: Vec<Hash> = headers.iter().map(|h| h.id(nid)).collect();
        for i in 1..headers.len() {
            if headers[i].prev_id != ids[i - 1] || headers[i].height != headers[i - 1].height + 1 {
                return None;
            }
        }
        let base = first.height;
        let jobs = headers
            .iter()
            .map(|h| {
                let sh = seed_height(h.height, self.params.seed_epoch, self.params.seed_lag);
                let seed = if sh >= base {
                    ids[(sh - base) as usize]
                } else {
                    self.headers.seed_id_for(first.prev_id, h.height)
                };
                (seed, h.to_bytes())
            })
            .collect();
        Some((self.pow.clone(), jobs))
    }

    /// Checks a linked batch of headers with every rule except proof of work,
    /// without storing anything (`HeaderChain::precheck_batch`). Run before
    /// any RandomX work on a peer's batch.
    pub fn precheck_headers(
        &self,
        headers: &[BlockHeader],
        now: u64,
    ) -> Result<(), (usize, HeaderError)> {
        self.headers.precheck_batch(headers, now)
    }

    /// Accepts a batch of headers in order. Known headers are skipped. Returns the
    /// number of new headers, or the index and error of the first rejected one.
    /// Headers before a rejected one stay accepted.
    pub fn accept_headers(
        &mut self,
        headers: &[BlockHeader],
        now: u64,
    ) -> Result<usize, (usize, HeaderError)> {
        let mut new = 0;
        let mut result = Ok(());
        for (i, h) in headers.iter().enumerate() {
            let id = h.id(self.params.network_id);
            if self.headers.header(&id).is_some() {
                if self.headers.is_valid(&id) == Some(false) {
                    result = Err((i, HeaderError::InvalidParent));
                    break;
                }
                continue;
            }
            if let Err(e) = self.headers.accept(*h, now) {
                result = Err((i, e));
                break;
            }
            self.header_added(id, h.prev_id);
            new += 1;
        }
        // Headers never change the connected chain: its target depends only on
        // bodies (module docs). New headers only add bodies to download.
        result.map(|()| new)
    }

    /// Validates a transaction for the next block without adding it (Dandelion
    /// stem phase, docs/p2p.md §8).
    pub fn check_tx(&self, tx: &Transaction) -> Result<Hash, MempoolError> {
        let next = self.height() + 1;
        self.mempool.check(tx, &self.state, next, &self.rules)
    }

    /// Adds a transaction to the mempool (valid for the next block).
    pub fn submit_tx(&mut self, tx: Transaction) -> Result<Hash, MempoolError> {
        let next = self.height() + 1;
        self.mempool.add(tx, &self.state, next, &self.rules)
    }

    /// `G(h)`: coins generated by blocks `1..h`. Rewards depend only on height, so
    /// this is the same on every branch; heights above the tip are extrapolated.
    fn generated_before(&self, height: u64) -> u64 {
        if let Some(g) = self.generated.get(height.saturating_sub(1) as usize) {
            return if height == 0 { 0 } else { *g };
        }
        let mut g = self.generated();
        for h in self.height() + 1..height {
            g += block_reward(h, g);
        }
        g
    }

    /// Template for a coinbase-only child of any valid known block (e.g. to extend
    /// a side branch). Mempool transactions are only offered on the tip.
    pub fn template_on(&self, parent: &Hash) -> Option<Template> {
        let t = self.headers.template_on(*parent)?;
        Some(Template {
            height: t.height,
            prev_id: t.prev_id,
            difficulty: t.difficulty,
            seed_id: t.seed_id,
            min_timestamp: t.min_timestamp,
            reward: block_reward(t.height, self.generated_before(t.height)),
            fees: 0,
            txs: Vec::new(),
        })
    }

    /// Template for the next block on the connected tip.
    pub fn template(&self) -> Template {
        let t = self
            .headers
            .template_on(self.tip_id())
            .expect("connected tip is a valid header");
        let reward = block_reward(t.height, self.generated());
        let txs = self.mempool.select(
            self.rules.max_block_weight.saturating_sub(COINBASE_RESERVE),
            blacksilk_tx::validate::ChainView::px_pool(&self.state),
        );
        let fees = txs.iter().map(Transaction::fee).sum();
        Template {
            height: t.height,
            prev_id: t.prev_id,
            difficulty: t.difficulty,
            seed_id: t.seed_id,
            min_timestamp: t.min_timestamp,
            reward,
            fees,
            txs,
        }
    }
}

fn hex(id: &Hash) -> String {
    id.iter().take(8).map(|b| format!("{b:02x}")).collect()
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
    use blacksilk_crypto::keys::{SubaddressIndex, WalletKeys};
    use blacksilk_tx::builder::{build_coinbase, Payment};

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
        let first = bounded
            .submit_block_bounded(blocks[0].clone(), NOW, budget)
            .unwrap();
        assert_eq!(bounded.height(), 3, "exactly `budget` blocks connected");
        assert!(bounded.sync_pending());
        // Block 41 (header unknown so far) arrives mid-drain.
        let late = bounded
            .submit_block_bounded(blocks[40].clone(), NOW, budget)
            .unwrap();
        assert_eq!(bounded.height(), 3 + budget as u64);
        let mut steps = 0;
        loop {
            let before = bounded.height();
            let done = bounded.sync_step(budget);
            assert!(bounded.height() - before <= budget as u64);
            steps += 1;
            if done {
                break;
            }
        }
        assert!(steps >= 10, "{steps} steps");
        same_chain(&full, &bounded);
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
}
