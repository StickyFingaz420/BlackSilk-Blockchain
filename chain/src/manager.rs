//! The chain manager (docs/blocks.md §5–§8): header chain, transaction state,
//! emission, reorganizations, mempool and storage behind one API.
//!
//! **Invariant.** The transaction state equals the result of applying the bodies of
//! `connected[1..]` in order. `connected` is the most-work chain whose bodies are all
//! available: normally a prefix of the header chain's best chain, but it stays on
//! the current branch while a heavier branch's bodies are still downloading.
//! After every change, [`ChainManager::sync_state`] restores this: it disconnects
//! back to the fork point only when the new branch, as far as bodies are available,
//! has more work, and then connects forward block by block, validating each body.
//! A body that fails marks its block invalid in the header chain, which re-selects
//! the best chain, and the loop repeats.

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
use std::collections::HashMap;
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
        let mut state = MemoryChain::new();
        state.apply_block(&[]); // genesis: empty body (docs/blocks.md §3)
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
            invalid: HashMap::new(),
            mempool: Mempool::new(),
            store,
            rng: ChaCha20Rng::from_seed(rng_seed),
            deepest_reorg: 0,
            store_failures: 0,
            store_failed: false,
        };
        manager.replay(stored)?;
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
    /// **Tie-breaking after a restart.** Between branches of equal work the
    /// header chain keeps the one it saw first. After a restart "first" means
    /// replay order, which follows storage (body arrival) order, not the order
    /// in which headers originally arrived. So a node may come back on a
    /// different one of two equal-work tips than it had before the restart; the
    /// next block on either branch resolves it as usual (docs/blocks.md §8).
    fn replay(&mut self, stored: Vec<crate::store::StoredBlock>) -> io::Result<()> {
        use std::cmp::Reverse;
        use std::collections::{BinaryHeap, HashSet};
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
        match self.submit_inner(block, now, false) {
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
        self.submit_inner(block, now, true)
    }

    fn submit_inner(
        &mut self,
        block: Block,
        now: u64,
        persist: bool,
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
        }
        if block.compute_tx_root() != block.header.tx_root {
            return Err(SubmitError::BodyMismatch);
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
        let height = block.header.height;
        self.bodies.insert(id, block.txs);
        self.sync_state();
        if let Some(e) = self.invalid.get(&id) {
            return Err(SubmitError::Body(*e));
        }
        Ok(Submitted {
            id,
            height,
            on_best_chain: self.connected.get(height as usize) == Some(&id),
        })
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

    /// Restores the invariant (module docs) after the header chain changed.
    fn sync_state(&mut self) {
        let mut returned: Vec<Transaction> = Vec::new();
        // Whether any block was disconnected (the mempool then re-checks every
        // rule; a reorganization of coinbase-only blocks returns nothing).
        let mut reorganized = false;
        loop {
            let fork = self.fork_height();
            // How far the best header chain can be connected with the bodies at hand.
            let mut reachable = fork as u64;
            while let Some(id) = self.headers.main_id_at(reachable + 1) {
                if !self.bodies.contains_key(&id) {
                    break;
                }
                reachable += 1;
            }
            // Only leave the current chain for one with strictly more work whose bodies
            // are all available; otherwise keep it (header-first sync may deliver the
            // other branch's headers long before its bodies).
            if fork + 1 < self.connected.len() {
                let reachable_id = self.headers.main_id_at(reachable).expect("best chain");
                let target_work = self.headers.work(&reachable_id).unwrap_or(0);
                let current_work = self.headers.work(&self.tip_id()).unwrap_or(0);
                if target_work <= current_work {
                    break;
                }
            }
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
                reorganized = true;
                let id = self.connected.pop().expect("above genesis");
                self.generated.pop();
                assert!(self.state.undo_block());
                if let Some(body) = self.bodies.get(&id) {
                    returned.extend(body.iter().skip(1).cloned());
                }
            }
            // Connect forward as far as bodies are available.
            let mut failed = false;
            for h in fork as u64 + 1..=reachable {
                let id = self
                    .headers
                    .main_id_at(h)
                    .expect("height within best chain");
                let body = self.bodies.get(&id).expect("checked above");
                let header = self.headers.header(&id).expect("main chain header");
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
                        log::warn!("block {} at height {h} is invalid: {e:?}", hex(&id));
                        self.invalid.insert(id, e);
                        self.bodies.remove(&id);
                        self.headers.mark_invalid(&id);
                        failed = true;
                        break;
                    }
                }
            }
            if !failed {
                break;
            }
        }
        // Mempool: return transactions from disconnected blocks, then drop anything
        // no longer valid at the new tip.
        let next = self.height() + 1;
        for tx in returned {
            let _ = self.mempool.add(tx, &self.state, next, &self.rules);
        }
        self.mempool
            .revalidate(&self.state, next, &self.rules, reorganized);
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

    /// Best-chain blocks whose body is missing, lowest first (for download).
    pub fn missing_bodies(&self, max: usize) -> Vec<(u64, Hash)> {
        let mut out = Vec::new();
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
    /// Headers before a rejected one stay accepted, and the state is brought up
    /// to date with them either way.
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
            new += 1;
        }
        // New headers can make a stored side branch the best available chain.
        if new > 0 {
            self.sync_state();
        }
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
