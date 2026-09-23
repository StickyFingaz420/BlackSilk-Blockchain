//! The chain manager (docs/blocks.md §5–§8): header chain, transaction state,
//! emission, reorganizations, mempool and storage behind one API.
//!
//! **Invariant.** The transaction state equals the result of applying the bodies of
//! `connected[1..]` in order, and `connected` is a prefix of the header chain's best
//! chain. After every change, [`ChainManager::sync_state`] restores this: it
//! disconnects back to the fork point and connects forward block by block,
//! validating each body. A body that fails marks its block invalid in the header
//! chain, which re-selects the best chain, and the loop repeats.

use crate::block::Block;
use crate::emission::block_reward;
use crate::mempool::{Mempool, MempoolError, COINBASE_RESERVE};
use crate::store::BlockStore;
use blacksilk_consensus::hash::H;
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, HeaderChain, HeaderError, PowFunction};
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

    /// Restores the invariant (module docs) after the header chain changed.
    fn sync_state(&mut self) {
        let mut returned: Vec<Transaction> = Vec::new();
        loop {
            // Fork point between the connected chain and the header best chain.
            let mut fork = self.connected.len() - 1;
            while self.headers.main_id_at(fork as u64) != Some(self.connected[fork]) {
                fork -= 1; // genesis always matches
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
            for h in fork as u64 + 1..=self.headers.height() {
                let id = self
                    .headers
                    .main_id_at(h)
                    .expect("height within best chain");
                let Some(body) = self.bodies.get(&id) else {
                    break; // body not yet available (header-first sync)
                };
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
