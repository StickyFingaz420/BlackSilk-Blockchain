//! Long chain-lock holds on demand, for liveness tests (research dossier 34,
//! Stage 0). Test support only: nothing here is reachable from production code.
//!
//! [`SlowStore`] is a [`MemoryStore`] whose next `append` can be armed to
//! stall. `ChainManager` appends a kept body while the caller holds the chain
//! lock (fsync before apply), so a stalled append is a long lock hold on the
//! real submission path, exactly where a slow disk or a heavy block step
//! would hold it. [`StallControl`] arms, observes and ends the stall, and
//! records every append (the store bytes, for equivalence checks).
//!
//! [`Holder`] submits one block with the store armed, on its own thread, and
//! returns once the append has started: [`Holder::start_actor`] through the
//! chain actor's Blocks lane (the Stage 2 path of the P2P block worker and
//! RPC `/block`: the actor is busy with the stalled command), and
//! [`Holder::start`] through `submit_block_in_steps` under the mutex (the
//! pre-Stage 2 path, kept as the baseline), so the chain lock is held.
//!
//! Shared by `chain`, `p2p` and `node` tests through `#[path]`; each test
//! crate uses a different subset of it.
#![allow(dead_code)]

use blacksilk_chain::actor::{ChainHandle, Lane};
use blacksilk_chain::block::Block;
use blacksilk_chain::manager::{submit_block_in_steps, ChainManager, SYNC_STEP_BLOCKS};
use blacksilk_chain::store::{BlockStore, Marker, MemoryStore, Record, StoreIdentity, StoredBlock};
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{BlockHeader, Hash, HEADER_VERSION};
use blacksilk_crypto::keys::{SubaddressIndex, WalletKeys};
use blacksilk_tx::builder::{build_coinbase, Payment};
use blacksilk_tx::types::Transaction;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::io;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

#[derive(Default)]
struct Gate {
    /// The next append stalls for at most this long.
    armed: Option<Duration>,
    /// An append is stalling now.
    stalling: bool,
    /// Ends the current stall early.
    released: bool,
    /// Stalls started so far.
    stalls: u64,
}

/// Arms, observes and ends the stalls of a [`SlowStore`]; also keeps a copy of
/// every appended record, in append order.
#[derive(Default)]
pub struct StallControl {
    gate: Mutex<Gate>,
    changed: Condvar,
    appended: Mutex<Vec<StoredBlock>>,
}

impl StallControl {
    /// The next append stalls for `max` (or until [`Self::release`]).
    pub fn stall_next_append(&self, max: Duration) {
        let mut g = self.gate.lock().unwrap();
        g.armed = Some(max);
        g.released = false;
    }

    /// Ends the current stall now (and disarms a stall not yet started).
    pub fn release(&self) {
        let mut g = self.gate.lock().unwrap();
        g.armed = None;
        g.released = true;
        self.changed.notify_all();
    }

    /// Whether an append is stalling now.
    pub fn is_stalling(&self) -> bool {
        self.gate.lock().unwrap().stalling
    }

    /// Stalls started so far.
    pub fn stalls(&self) -> u64 {
        self.gate.lock().unwrap().stalls
    }

    /// Blocks until an append is stalling; false after `timeout`.
    pub fn wait_stalling(&self, timeout: Duration) -> bool {
        let g = self.gate.lock().unwrap();
        let (g, _) = self
            .changed
            .wait_timeout_while(g, timeout, |g| !g.stalling)
            .unwrap();
        g.stalling
    }

    /// Every record appended so far, in order.
    pub fn appended(&self) -> Vec<StoredBlock> {
        self.appended.lock().unwrap().clone()
    }

    fn stall_if_armed(&self) {
        let mut g = self.gate.lock().unwrap();
        let Some(max) = g.armed.take() else {
            return;
        };
        g.stalling = true;
        g.stalls += 1;
        self.changed.notify_all();
        let deadline = Instant::now() + max;
        while !g.released {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            g = self.changed.wait_timeout(g, left).unwrap().0;
        }
        g.stalling = false;
        g.released = false;
        self.changed.notify_all();
    }
}

/// A [`MemoryStore`] whose appends can be made to stall ([`StallControl`]).
pub struct SlowStore {
    inner: MemoryStore,
    ctl: Arc<StallControl>,
}

impl SlowStore {
    pub fn new() -> (Self, Arc<StallControl>) {
        let ctl = Arc::new(StallControl::default());
        let store = Self {
            inner: MemoryStore::default(),
            ctl: ctl.clone(),
        };
        (store, ctl)
    }
}

impl BlockStore for SlowStore {
    fn append(&mut self, pow_hash: &Hash, block: &[u8]) -> io::Result<()> {
        self.ctl.stall_if_armed();
        self.inner.append(pow_hash, block)?;
        self.ctl
            .appended
            .lock()
            .unwrap()
            .push((*pow_hash, block.to_vec()));
        Ok(())
    }

    fn append_marker(&mut self, marker: &Marker) -> io::Result<()> {
        self.inner.append_marker(marker)
    }

    fn load(&mut self) -> io::Result<Vec<Record>> {
        self.inner.load()
    }

    fn bind(&mut self, identity: &StoreIdentity) -> io::Result<()> {
        self.inner.bind(identity)
    }
}

/// A coinbase-only block on `m`'s tip (valid under a PoW function that accepts
/// everything); `seed` picks the miner and the coinbase randomness.
pub fn next_block(m: &ChainManager, seed: u64, nonce: u64) -> Block {
    let t = m.template();
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let (miner, _) = WalletKeys::generate(&mut rng);
    let fees: u64 = t.txs.iter().map(Transaction::fee).sum();
    let cb = build_coinbase(
        t.height,
        &[Payment {
            address: miner.address(SubaddressIndex::PRIMARY),
            amount: t.reward + fees,
        }],
        &miner.hedge_secret(),
        &mut rng,
    )
    .unwrap();
    let mut txs = vec![Transaction::Coinbase(cb)];
    txs.extend(t.txs.iter().cloned());
    let ids: Vec<Hash> = txs.iter().map(Transaction::hash).collect();
    let header = BlockHeader {
        version: HEADER_VERSION,
        height: t.height,
        prev_id: t.prev_id,
        timestamp: t
            .min_timestamp
            .max(m.params().genesis.timestamp + 120 * t.height),
        difficulty: t.difficulty,
        tx_root: tx_root(&ids),
        nonce,
    };
    Block { header, txs }
}

/// A thread holding the chain lock inside a stalled block append.
pub struct Holder {
    thread: std::thread::JoinHandle<bool>,
    ctl: Arc<StallControl>,
    /// Height of the block being connected.
    pub height: u64,
    pub started: Instant,
}

impl Holder {
    /// Builds the next block on `chain`'s tip, arms `ctl` for `max`, and
    /// submits the block in bounded steps on a new thread. Returns once the
    /// append is stalling (the chain lock is held). Blocks the calling thread
    /// briefly: call it from a plain or blocking thread.
    pub fn start(chain: Arc<Mutex<ChainManager>>, ctl: Arc<StallControl>, max: Duration) -> Self {
        let block = next_block(&chain.lock().unwrap(), 0x5107, 0);
        let height = block.header.height;
        let now = block.header.timestamp;
        ctl.stall_next_append(max);
        let started = Instant::now();
        let thread = std::thread::spawn(move || {
            submit_block_in_steps(|| chain.lock().unwrap(), block, now, SYNC_STEP_BLOCKS).is_ok()
        });
        assert!(
            ctl.wait_stalling(Duration::from_secs(30)),
            "the block append never started"
        );
        Self {
            thread,
            ctl,
            height,
            started,
        }
    }

    /// [`Self::start`] through the chain actor: the block is submitted on the
    /// Blocks lane, so the actor itself stalls in the append (it also holds
    /// the manager's lock, if a caller keeps one).
    pub fn start_actor(chain: ChainHandle, ctl: Arc<StallControl>, max: Duration) -> Self {
        let block = chain
            .call_blocking(Lane::Query, |m| next_block(m, 0x5107, 0))
            .unwrap();
        let height = block.header.height;
        let now = block.header.timestamp;
        ctl.stall_next_append(max);
        let started = Instant::now();
        let thread = std::thread::spawn(move || {
            matches!(chain.submit_block_blocking(block, now), Ok(Ok(_)))
        });
        assert!(
            ctl.wait_stalling(Duration::from_secs(30)),
            "the block append never started"
        );
        Self {
            thread,
            ctl,
            height,
            started,
        }
    }

    /// Whether the hold is still on.
    pub fn holding(&self) -> bool {
        !self.thread.is_finished() && self.ctl.is_stalling()
    }

    /// Ends the stall early and waits for the block to connect.
    pub fn release(self) -> bool {
        self.ctl.release();
        self.join()
    }

    /// Waits for the stall to run out and the block to connect.
    pub fn join(self) -> bool {
        self.thread.join().expect("the holder thread")
    }
}
