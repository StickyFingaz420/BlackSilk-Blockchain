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
use blacksilk_tx::types::{Transaction, Transfer};
use blacksilk_tx::validate::{validate_block_transactions, BlockContext, BlockError};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};

/// PoW wrapper that remembers every computed hash, keyed by the header bytes (which
/// determine the RandomX key through `prev_id`). It lets the node store PoW hashes
/// with blocks and skip recomputing RandomX when replaying its own store.
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

    fn key(header_bytes: &[u8]) -> Hash {
        H::new()
            .chain(b"BlackSilk/pow-cache")
            .chain(header_bytes)
            .finish()
    }

    pub fn lookup(&self, header_bytes: &[u8]) -> Option<Hash> {
        let known = self.known.lock().unwrap_or_else(|e| e.into_inner());
        known.get(&Self::key(header_bytes)).copied()
    }

    /// Trusts `pow_hash` for `header_bytes` (only for blocks from the node's own store).
    pub fn preload(&self, header_bytes: &[u8], pow_hash: Hash) {
        let mut known = self.known.lock().unwrap_or_else(|e| e.into_inner());
        known.insert(Self::key(header_bytes), pow_hash);
    }
}

/// One PoW computation: RandomX key (seed block id) and header bytes.
pub type PowJob = (Hash, [u8; blacksilk_consensus::HEADER_SIZE]);

impl CachedPow {
    /// Computes and caches the PoW hashes of `jobs` on `threads` threads.
    pub fn compute_parallel(&self, jobs: &[PowJob], threads: usize) {
        let todo: Vec<&PowJob> = jobs
            .iter()
            .filter(|(_, b)| self.lookup(b).is_none())
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
        if let Some(h) = self.lookup(header_bytes) {
            return h;
        }
        let h = self.inner.pow_hash(seed, header_bytes);
        self.preload(header_bytes, h);
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
    pub txs: Vec<Transfer>,
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
    invalid: HashMap<Hash, BlockError>,
    mempool: Mempool,
    store: Box<dyn BlockStore>,
    rng: ChaCha20Rng,
}

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
        };
        let total = stored.len();
        for (i, (pow_hash, bytes)) in stored.into_iter().enumerate() {
            let block = Block::decode(&bytes).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("stored block {i} does not decode: {e:?}"),
                )
            })?;
            manager.pow.preload(&block.header.to_bytes(), pow_hash);
            let now = block.header.timestamp; // the future-time rule was checked on arrival
            match manager.submit_inner(block, now, false) {
                // Deterministic outcomes of the original processing: a body found
                // invalid, and descendants of blocks found invalid.
                Ok(_)
                | Err(SubmitError::Body(_))
                | Err(SubmitError::Duplicate)
                | Err(SubmitError::Header(HeaderError::InvalidParent)) => {}
                Err(e) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("stored block {i} of {total} rejected on replay: {e:?}"),
                    ))
                }
            }
        }
        Ok(manager)
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
            let pow_hash = self
                .pow
                .lookup(&block.header.to_bytes())
                .expect("accepted headers have a cached PoW hash");
            self.store
                .append(&pow_hash, &block.encode())
                .map_err(SubmitError::Store)?;
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
            if depth > 0 {
                log::info!("reorganization: disconnecting {depth} block(s) above height {fork}");
            }
            while self.connected.len() - 1 > fork {
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
                match validate_block_transactions(
                    body,
                    &ctx,
                    &self.state,
                    &self.rules,
                    &mut self.rng,
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
        self.mempool.revalidate(&self.state, next, &self.rules);
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
        self.headers.header(&first.prev_id)?;
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

    /// Accepts a batch of headers in order. Known headers are skipped. Returns the
    /// number of new headers, or the index and error of the first rejected one.
    pub fn accept_headers(
        &mut self,
        headers: &[BlockHeader],
        now: u64,
    ) -> Result<usize, (usize, HeaderError)> {
        let mut new = 0;
        for (i, h) in headers.iter().enumerate() {
            let id = h.id(self.params.network_id);
            if self.headers.header(&id).is_some() {
                if self.headers.is_valid(&id) == Some(false) {
                    return Err((i, HeaderError::InvalidParent));
                }
                continue;
            }
            self.headers.accept(*h, now).map_err(|e| (i, e))?;
            new += 1;
        }
        // New headers can make a stored side branch the best available chain.
        if new > 0 {
            self.sync_state();
        }
        Ok(new)
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
        let txs = self
            .mempool
            .select(self.rules.max_block_weight.saturating_sub(COINBASE_RESERVE));
        let fees = txs.iter().map(|t| t.fee).sum();
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
