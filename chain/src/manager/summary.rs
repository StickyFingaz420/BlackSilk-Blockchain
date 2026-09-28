//! The published chain summary (research dossier 34, Stage 1 item 1b): a
//! small, read-mostly copy of the manager's headline fields that readers take
//! WITHOUT the chain lock.
//!
//! The manager republishes it just before a writer releases the lock: at the
//! end of every submission and bounded step, header batch and replay, and
//! after every closure the P2P and RPC layers run under the lock
//! ([`ChainManager::publish_summary`]). A reader holding a summary acts like
//! a reader that took the chain lock at the last publication: the values are
//! at most one lock hold old, and always mutually consistent (one publication
//! is one linearization point). Nothing consensus-relevant reads it; it serves
//! the P2P handshake, locators, tip announcements and RPC `/info`, so that a
//! long hold (a heavy block step, a reorganization, a slow disk) never stalls
//! them.
//!
//! The cell is a `std::sync::RwLock<Arc<ChainSummary>>` (no new dependency;
//! `arc-swap` was rejected, decisions "Agent 34"). A read clones the `Arc`
//! under the read lock and drops the guard at once; a publication swaps the
//! `Arc` under the write lock. Both critical sections are a pointer copy, so
//! neither side ever waits for chain work. Never hold a read guard while
//! taking another lock (std leaves reader/writer priority to the OS).

use super::ChainManager;
use blacksilk_consensus::{BlockHeader, Hash, Network};
use std::sync::{Arc, PoisonError, RwLock};

/// The manager's headline fields at one publication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainSummary {
    /// Publication number: 1 for the first one, +1 for each that changed a
    /// field.
    pub seq: u64,
    pub network: Network,
    pub network_id: u32,
    pub genesis_id: Hash,
    /// The connected tip.
    pub tip_id: Hash,
    pub tip_header: BlockHeader,
    pub height: u64,
    /// Coins generated on the connected chain (`ChainManager::generated`).
    pub generated: u64,
    /// Outputs in the state (`MemoryChain::output_count`).
    pub outputs: u64,
    /// The best valid header chain (download and locator guide).
    pub header_height: u64,
    pub best_header_id: Hash,
    /// `ChainManager::locator` of the best header chain.
    pub locator: Vec<Hash>,
    pub mempool_txs: usize,
    pub mempool_bytes: usize,
    pub deepest_reorg: usize,
    /// A bounded drain is in progress (`ChainManager::sync_pending`).
    pub sync_pending: bool,
    /// `ChainManager::store_failed`.
    pub store_failed: bool,
    /// `ChainManager::apply_halted`.
    pub apply_halted: bool,
}

impl ChainSummary {
    /// Whether the manager has halted (`ChainManager::halted().is_some()`).
    pub fn halted(&self) -> bool {
        self.store_failed || self.apply_halted
    }

    /// The fields of `m` now; `seq` is the caller's.
    fn of(m: &ChainManager, seq: u64) -> Self {
        let p = m.params();
        Self {
            seq,
            network: p.network,
            network_id: p.network_id,
            genesis_id: p.genesis_id(),
            tip_id: m.tip_id(),
            tip_header: *m.tip_header(),
            height: m.height(),
            generated: m.generated(),
            outputs: m.state().output_count(),
            header_height: m.header_height(),
            best_header_id: m.best_header_id(),
            locator: m.locator(),
            mempool_txs: m.mempool().len(),
            mempool_bytes: m.mempool().bytes(),
            deepest_reorg: m.deepest_reorg(),
            sync_pending: m.sync_pending(),
            store_failed: m.store_failed(),
            apply_halted: m.apply_halted(),
        }
    }

    /// Whether `self` still describes `m`. The locator, the tip's derived
    /// fields (header, height, generated, outputs) and the static fields are
    /// functions of the compared ids, so only the ids and the counters that
    /// change on their own are compared: a cheap test run at every
    /// publication point.
    fn describes(&self, m: &ChainManager) -> bool {
        self.tip_id == m.tip_id()
            && self.best_header_id == m.best_header_id()
            && self.mempool_txs == m.mempool().len()
            && self.mempool_bytes == m.mempool().bytes()
            && self.deepest_reorg == m.deepest_reorg()
            && self.sync_pending == m.sync_pending()
            && self.store_failed == m.store_failed()
            && self.apply_halted == m.apply_halted()
    }
}

/// Where the manager publishes its [`ChainSummary`]; shared (`Arc`) with every
/// reader, which takes it once, at start-up ([`ChainManager::summary_cell`]).
#[derive(Debug)]
pub struct SummaryCell {
    current: RwLock<Arc<ChainSummary>>,
}

impl SummaryCell {
    /// A cell holding a placeholder, replaced by `ChainManager::open` before
    /// the manager is returned (no reader can see it).
    pub(super) fn placeholder(genesis: BlockHeader, network: Network, network_id: u32) -> Self {
        let id = genesis.id(network_id);
        let s = ChainSummary {
            seq: 0,
            network,
            network_id,
            genesis_id: id,
            tip_id: id,
            tip_header: genesis,
            height: 0,
            generated: 0,
            outputs: 0,
            header_height: 0,
            best_header_id: id,
            locator: vec![id],
            mempool_txs: 0,
            mempool_bytes: 0,
            deepest_reorg: 0,
            sync_pending: false,
            store_failed: false,
            apply_halted: false,
        };
        Self {
            current: RwLock::new(Arc::new(s)),
        }
    }

    /// The latest summary. Never waits for chain work.
    pub fn load(&self) -> Arc<ChainSummary> {
        // A panic can not happen inside either critical section (an `Arc`
        // clone or swap), and the value is replaced whole, so a poisoned
        // lock still holds a consistent summary.
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn store(&self, s: ChainSummary) {
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(s);
    }
}

impl ChainManager {
    /// The cell this manager publishes its summary to. Take it once (before
    /// sharing the manager behind the chain lock, or with one short lock at
    /// start-up) and read it with [`SummaryCell::load`] from then on.
    pub fn summary_cell(&self) -> Arc<SummaryCell> {
        self.summary.clone()
    }

    /// The published summary (as a reader without the lock sees it).
    pub fn summary(&self) -> Arc<ChainSummary> {
        self.summary.load()
    }

    /// Publishes the current fields if any changed since the last
    /// publication. Cheap when nothing changed (a few comparisons); otherwise
    /// it builds the locator (at most 64 ids). The manager calls it at the
    /// end of each of its own mutations; the P2P and RPC layers call it after
    /// every closure they run under the chain lock, so a mempool change made
    /// through any method is published before the lock is released.
    pub fn publish_summary(&self) {
        let cur = self.summary.load();
        if cur.describes(self) {
            return;
        }
        self.summary.store(ChainSummary::of(self, cur.seq + 1));
    }

    /// Publishes the full summary unconditionally as publication 1: the end
    /// of `ChainManager::open`, once the store is replayed.
    pub(super) fn publish_first_summary(&self) {
        self.summary.store(ChainSummary::of(self, 1));
    }

    /// Whether the published summary equals the fields recomputed now (tests
    /// of the publication points).
    #[cfg(test)]
    pub(super) fn summary_is_current(&self) -> bool {
        let cur = self.summary.load();
        *cur == ChainSummary::of(self, cur.seq)
    }
}
