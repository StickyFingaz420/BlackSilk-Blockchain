//! The published chain summary (research dossier 34, Stage 1 item 1b,
//! extended into the Stage 2 snapshot): a small, read-mostly copy of the
//! manager's headline fields that readers take WITHOUT reaching the manager.
//!
//! The manager republishes it at the end of every submission and bounded
//! step, header batch and replay; the chain actor (`crate::actor`) publishes
//! it after every command it runs, before it replies and before it takes the
//! next command ([`ChainManager::publish_summary`]). A reader holding a
//! summary acts like a reader that ran a command right after the last
//! publication: the values are at most one command (or one drain step) old,
//! and always mutually consistent (one publication is one linearization
//! point). Nothing consensus-relevant reads it; it serves the P2P handshake,
//! locators, tip announcements, download scheduling and RPC `/info`, so that
//! a long command (a heavy block step, a reorganization, a slow disk) never
//! stalls them.
//!
//! A publication that changes the connected tip also calls the cell's tip
//! listeners ([`SummaryCell::on_tip_change`]): the P2P layer announces a new
//! tip when it is published, not at its next maintenance tick (RT-LAB F2).
//!
//! The cell is a `std::sync::RwLock<Arc<ChainSummary>>` (no new dependency;
//! `arc-swap` was rejected, decisions "Agent 34"). A read clones the `Arc`
//! under the read lock and drops the guard at once; a publication swaps the
//! `Arc` under the write lock. Both critical sections are a pointer copy, so
//! neither side ever waits for chain work. Never hold a read guard while
//! taking another lock (std leaves reader/writer priority to the OS).

use super::ChainManager;
use crate::sync_policy;
use blacksilk_consensus::{BlockHeader, Hash, Network};
use blacksilk_tx::params::SigDomain;
use std::sync::{Arc, Mutex, PoisonError, RwLock};

/// Missing bodies listed in a summary (`ChainManager::missing_bodies`): the
/// most the P2P download scheduler asks for at once.
pub const SUMMARY_MISSING_BODIES: usize = 256;

/// The header fields of the next block on the connected tip, as
/// `ChainManager::template` gives them (without transactions): what a miner
/// or a monitor needs to know about the next block without a command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NextBlock {
    pub height: u64,
    pub prev_id: Hash,
    pub difficulty: u64,
    pub seed_id: Hash,
    pub min_timestamp: u64,
    pub version: u32,
    /// `reward(height)`, fees excluded.
    pub reward: u64,
}

/// A heavier chain this node refuses only because of the operator's
/// verdicts (`--invalidate-block`; RTW3-8): the heaviest known valid-by-rule
/// branch through an operator-invalidated block has more work than the
/// connected tip ([`ChainManager::operator_fork`]). The node then mines, if
/// at all, on a chain the rest of the network does not follow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperatorFork {
    /// The operator-invalidated block the refused branch contains.
    pub block: Hash,
    /// Its height.
    pub height: u64,
    /// The refused branch's heaviest known header: its id and height. Its
    /// headers passed every header rule, proof of work included, before the
    /// verdict applied; headers built on it later are refused unverified,
    /// so the network's chain may be longer than this.
    pub branch_tip: Hash,
    pub branch_height: u64,
    /// The branch's cumulative work minus the connected tip's (positive).
    pub excess_work: u128,
}

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
    /// The connected tip's cumulative work (`HeaderChain::work`, genesis
    /// included), and whether the connected tip is on the best header chain
    /// (false while a heavier branch's bodies are missing on another fork):
    /// the P2P layer does not announce a tip to a peer known to have a
    /// header on the same chain with at least this much work (docs/p2p.md
    /// §6).
    pub tip_work: u128,
    pub tip_on_best_chain: bool,
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
    /// The template gate's catch-up latch
    /// (`ChainManager::template_latched`, RTW3-1).
    pub template_latched: bool,
    /// `sync_policy::max_tip_age` of the network (static).
    pub max_tip_age: Option<u64>,
    /// `ChainManager::operator_fork` (RTW3-8).
    pub operator_fork: Option<OperatorFork>,
    /// `ChainManager::store_failed`.
    pub store_failed: bool,
    /// `ChainManager::apply_halted`.
    pub apply_halted: bool,
    /// `ChainManager::halted`: why the manager halted, if it did.
    pub halt_reason: Option<String>,
    /// `ChainManager::missing_bodies(SUMMARY_MISSING_BODIES)`: the bodies to
    /// download, lowest height first.
    pub missing_bodies: Vec<(u64, Hash)>,
    /// The next block on the connected tip.
    pub next_block: NextBlock,
    /// The signature domain transactions are admitted under now (that of
    /// the next block's rules, `ChainManager::next_rules`).
    pub next_domain: SigDomain,
    /// The name of the next block's rule-set epoch.
    pub next_epoch: &'static str,
    /// PX records in the state (`MemoryChain::px_record_count`).
    pub px_records: u64,
    /// The PX record tree root.
    pub px_root: [u32; 8],
}

impl ChainSummary {
    /// Whether the manager has halted (`ChainManager::halted().is_some()`).
    pub fn halted(&self) -> bool {
        self.store_failed || self.apply_halted
    }

    /// `ChainManager::caught_up` at the local time `now`, as of this
    /// publication.
    pub fn caught_up(&self, now: u64) -> bool {
        sync_policy::caught_up(
            self.sync_pending,
            self.height,
            self.header_height,
            self.tip_header.timestamp,
            now,
            self.max_tip_age,
        )
    }

    /// `ChainManager::template_ready` at the local time `now`, as of this
    /// publication.
    pub fn template_ready(&self, now: u64) -> bool {
        sync_policy::template_ready(
            self.sync_pending,
            self.template_latched,
            self.caught_up(now),
        )
    }

    /// The fields of `m` now; `seq` is the caller's. The fields derived
    /// from the connected tip (the next block, the rule domain, the PX
    /// counters) and the locator (derived from the best header) are copied
    /// from `prev` when those ids did not change.
    fn of(m: &ChainManager, seq: u64, prev: Option<&ChainSummary>) -> Self {
        let p = m.params();
        let tip_id = m.tip_id();
        let best_header_id = m.best_header_id();
        let same_tip = prev.filter(|s| s.seq > 0 && s.tip_id == tip_id);
        let same_best = prev.filter(|s| s.seq > 0 && s.best_header_id == best_header_id);
        let (next_block, next_domain, next_epoch, px_records, px_root) = match same_tip {
            Some(s) => (
                s.next_block,
                s.next_domain,
                s.next_epoch,
                s.px_records,
                s.px_root,
            ),
            None => {
                let t = m
                    .template_on(&tip_id)
                    .expect("the connected tip is a valid header");
                let next = NextBlock {
                    height: t.height,
                    prev_id: t.prev_id,
                    difficulty: t.difficulty,
                    seed_id: t.seed_id,
                    min_timestamp: t.min_timestamp,
                    version: t.version,
                    reward: t.reward,
                };
                let state = m.state();
                (
                    next,
                    m.next_rules().domain(),
                    p.epoch_at(t.height).name,
                    state.px_record_count(),
                    state.px().root(),
                )
            }
        };
        Self {
            seq,
            network: p.network,
            network_id: p.network_id,
            genesis_id: p.genesis_id(),
            tip_id,
            tip_header: *m.tip_header(),
            height: m.height(),
            tip_work: m.headers().work(&tip_id).unwrap_or(0),
            tip_on_best_chain: m.headers().is_on_main(&tip_id),
            generated: m.generated(),
            outputs: m.state().output_count(),
            header_height: m.header_height(),
            best_header_id,
            locator: match same_best {
                Some(s) => s.locator.clone(),
                None => m.locator(),
            },
            mempool_txs: m.mempool().len(),
            mempool_bytes: m.mempool().bytes(),
            deepest_reorg: m.deepest_reorg(),
            sync_pending: m.sync_pending(),
            template_latched: m.template_latched(),
            max_tip_age: sync_policy::max_tip_age(p),
            operator_fork: m.operator_fork(),
            store_failed: m.store_failed(),
            apply_halted: m.apply_halted(),
            halt_reason: m.halted(),
            missing_bodies: m.missing_bodies(SUMMARY_MISSING_BODIES),
            next_block,
            next_domain,
            next_epoch,
            px_records,
            px_root,
        }
    }

    /// Whether `self` still describes `m`. The locator, the tip's derived
    /// fields (header, height, generated, outputs, the next block, the PX
    /// counters) and the static fields are functions of the compared ids,
    /// and the halt reason is a function of the halt flags, so only the ids,
    /// the counters that change on their own, the latch, the missing bodies
    /// (which change with any header or body) and the operator fork (a
    /// verdict can apply without changing any id above) are compared: a
    /// test run at every publication point, bounded by
    /// `SUMMARY_MISSING_BODIES` (and free while no verdict is in force).
    fn describes(&self, m: &ChainManager) -> bool {
        self.tip_id == m.tip_id()
            && self.best_header_id == m.best_header_id()
            && self.mempool_txs == m.mempool().len()
            && self.mempool_bytes == m.mempool().bytes()
            && self.deepest_reorg == m.deepest_reorg()
            && self.sync_pending == m.sync_pending()
            && self.template_latched == m.template_latched()
            && self.store_failed == m.store_failed()
            && self.apply_halted == m.apply_halted()
            && self.missing_bodies == m.missing_bodies(SUMMARY_MISSING_BODIES)
            && self.operator_fork == m.operator_fork()
    }
}

/// A tip listener ([`SummaryCell::on_tip_change`]).
type TipListener = Box<dyn Fn() + Send + Sync>;

/// Where the manager publishes its [`ChainSummary`]; shared (`Arc`) with every
/// reader, which takes it once, at start-up ([`ChainManager::summary_cell`]).
pub struct SummaryCell {
    current: RwLock<Arc<ChainSummary>>,
    /// Called after each publication that changed the connected tip.
    tip_listeners: Mutex<Vec<TipListener>>,
}

impl std::fmt::Debug for SummaryCell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let listeners = self
            .tip_listeners
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len();
        f.debug_struct("SummaryCell")
            .field("current", &self.load())
            .field("tip_listeners", &listeners)
            .finish()
    }
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
            tip_work: genesis.difficulty as u128,
            tip_on_best_chain: true,
            generated: 0,
            outputs: 0,
            header_height: 0,
            best_header_id: id,
            locator: vec![id],
            mempool_txs: 0,
            mempool_bytes: 0,
            deepest_reorg: 0,
            sync_pending: false,
            template_latched: false,
            max_tip_age: None,
            operator_fork: None,
            store_failed: false,
            apply_halted: false,
            halt_reason: None,
            missing_bodies: Vec::new(),
            next_block: NextBlock {
                height: 1,
                prev_id: id,
                difficulty: 0,
                seed_id: id,
                min_timestamp: 0,
                version: genesis.version,
                reward: 0,
            },
            next_domain: SigDomain {
                network_id,
                branch_id: 0,
                genesis_id: id,
            },
            next_epoch: "",
            px_records: 0,
            px_root: [0; 8],
        };
        Self {
            current: RwLock::new(Arc::new(s)),
            tip_listeners: Mutex::new(Vec::new()),
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

    /// Calls `f` after every later publication whose connected tip differs
    /// from the previous publication's. `f` runs on the publishing thread
    /// (the chain actor, under the manager's lock), after the new summary is
    /// readable: it must return at once, without taking a lock the actor's
    /// commands take or waiting for chain work (a wake-up, e.g.
    /// `tokio::sync::Notify::notify_one`). Listeners are never removed.
    pub fn on_tip_change(&self, f: impl Fn() + Send + Sync + 'static) {
        self.tip_listeners
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Box::new(f));
    }

    fn store(&self, s: ChainSummary) {
        let tip = s.tip_id;
        let previous = std::mem::replace(
            &mut *self.current.write().unwrap_or_else(PoisonError::into_inner),
            Arc::new(s),
        );
        // Outside the write lock: a listener may read the new summary.
        if previous.tip_id != tip {
            for f in self
                .tip_listeners
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
            {
                f();
            }
        }
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
        self.summary
            .store(ChainSummary::of(self, cur.seq + 1, Some(&cur)));
    }

    /// Publishes the full summary unconditionally as publication 1: the end
    /// of `ChainManager::open`, once the store is replayed.
    pub(super) fn publish_first_summary(&self) {
        self.summary.store(ChainSummary::of(self, 1, None));
    }

    /// Whether the published summary equals the fields recomputed now (tests
    /// of the publication points).
    #[cfg(test)]
    pub(super) fn summary_is_current(&self) -> bool {
        let cur = self.summary.load();
        *cur == self.summary_now(cur.seq)
    }

    /// The summary of the fields now, computed from scratch (nothing copied
    /// from an earlier publication) and numbered `seq`: what the published
    /// one must equal (tests of the publication points, the actor's E3).
    pub fn summary_now(&self, seq: u64) -> ChainSummary {
        ChainSummary::of(self, seq, None)
    }
}
