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

mod accessors;
mod fork_choice;
mod header_sync;
mod pow_cache;
mod replay;
mod submission;
mod summary;
mod template;

use crate::block::Block;
use crate::mempool::{Mempool, Returned};
use crate::store::BlockStore;
use blacksilk_consensus::{ChainParams, Hash, HeaderChain, HeaderError};
use blacksilk_tx::mmr::OutputFrontier;
use blacksilk_tx::params::TxRules;
use blacksilk_tx::state::MemoryChain;
use blacksilk_tx::types::Transaction;
use blacksilk_tx::validate::BlockError;
pub use pow_cache::{CachedPow, PowJob};
use rand_chacha::ChaCha20Rng;
pub use replay::{OperatorMark, OperatorMarked, StorePowCheck, StorePowMismatch};
use std::cmp::Reverse;
use std::collections::{BTreeSet, BinaryHeap, HashMap, HashSet};
use std::io;
use std::sync::Arc;
pub use summary::{ChainSummary, NextBlock, OperatorFork, SummaryCell, SUMMARY_MISSING_BODIES};

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
    /// The node halted: applying a block that passed validation failed
    /// ([`ChainManager::halted`]). No block is accepted until a restart; the
    /// block is not marked invalid.
    Halted,
}

/// The error inside the `io::Error` that [`ChainManager::open`] returns when
/// a stored block that passes validation fails to apply during replay: the
/// same deterministic halt as [`SubmitError::Halted`], found at start-up.
/// Callers find it with `io::Error::get_ref` and a downcast, so that the node
/// exits with its halt status instead of a generic failure (RTW1B-4).
#[derive(Debug)]
pub struct ApplyHalt(pub String);

impl std::fmt::Display for ApplyHalt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ApplyHalt {}

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
    /// The header version the block must carry: that of the epoch at
    /// `height` (docs/consensus.md §11).
    pub version: u32,
    /// `reward(height)`; the coinbase must pay exactly `reward + fees`.
    pub reward: u64,
    pub fees: u64,
    /// Transactions to include after the coinbase, in order.
    pub txs: Vec<Transaction>,
    /// The output range after the parent (count and peaks): the block's
    /// `output_count` and `output_root` extend it with the block's outputs,
    /// coinbase first (rule B-OMR; [`Template::outputs_after`]).
    pub outputs: OutputFrontier,
    /// The block's `px_root` when it holds exactly the coinbase and `txs`
    /// (rule B-PXR): the coinbase appends no PX commitment.
    pub px_root: Hash,
}

impl Template {
    /// The `output_count` and `output_root` of a block of this template
    /// whose transactions are `txs` (all of them, coinbase first).
    pub fn outputs_after(&self, txs: &[Transaction]) -> (u64, Hash) {
        let mut f = self.outputs.clone();
        f.append_block(self.height, txs);
        (f.count(), f.root())
    }
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
    /// Transactions of disconnected blocks, captured with their ring
    /// digests and block rules before each block was undone
    /// (`Returned::capture`), tip first.
    returned: Vec<Returned>,
    /// Encoded bytes captured into `returned` per class (v1, PX), bounded by
    /// `READMIT_MAX_BYTES` (`Returned::capture_within`, RTW2A-6)...
    captured_bytes: [usize; 2],
    /// ...and the transactions of disconnected blocks not captured beyond
    /// it (dropped; their wallets rebroadcast them).
    uncaptured: usize,
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
    /// Blocks the operator invalidated (`--invalidate-block`, operator
    /// markers in the store; docs/blocks.md §8): never connected, whatever
    /// their bodies. Kept for ids whose header is not known yet, so the
    /// verdict applies when the block arrives.
    operator_invalid: HashSet<Hash>,
    /// The template gate's catch-up latch (RTW3-1,
    /// `sync_policy::template_ready`): set the first time the node is caught
    /// up at a clock reading it was given, or by the operator; never cleared
    /// while the manager lives. Not stored: every start catches up again.
    template_latched: bool,
    mempool: Mempool,
    store: Box<dyn BlockStore>,
    rng: ChaCha20Rng,
    /// The deepest reorganization since the manager was opened.
    deepest_reorg: usize,
    /// Consecutive failed appends (reset by a successful one).
    store_failures: u32,
    /// The block store failed persistently: no block is accepted any more.
    store_failed: bool,
    /// Applying a validated block failed (a bug: validation is a superset of
    /// every apply failure): the block's id and height and the error. The
    /// node stops; the block is not marked invalid ([`ChainManager::halted`]).
    apply_failed: Option<(Hash, u64, String)>,
    /// The RandomX keys last passed to [`PowFunction::set_hot_seeds`]
    /// (`sync_policy::hot_seeds` of the best header chain); refreshed when the
    /// best header chain changes, so the next key is built before it is needed.
    hot_seeds: Vec<Hash>,
    /// Blocks ready to complete (body kept, parent complete), lowest body
    /// arrival first. Drained by [`ChainManager::sync_step`] (and at once by
    /// [`ChainManager::submit_block`]).
    ready: BinaryHeap<Reverse<(u64, Hash)>>,
    /// The completed block whose `sync_state` stopped at the connect budget
    /// (its children are released when it finishes).
    syncing: Option<Hash>,
    /// Mempool effects of a drain in progress, applied when it ends.
    sync_outcome: SyncOutcome,
    /// The published summary, read without the chain lock (`summary`).
    summary: Arc<SummaryCell>,
    /// Test-only: each bounded validation call (a drain step) first sleeps
    /// this long (`set_step_delay_for_tests`).
    #[cfg(feature = "test-hooks")]
    step_delay: Option<std::time::Duration>,
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

/// The reason text of the operator's invalid markers.
const OPERATOR_REASON: &str = "invalidated by the operator (--invalidate-block)";

fn hex(id: &Hash) -> String {
    id.iter().take(8).map(|b| format!("{b:02x}")).collect()
}
