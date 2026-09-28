//! The chain actor (research dossier 34, Stage 2; docs/reviews/
//! chain-actor-stage2.md): one dedicated OS thread runs every operation on
//! the [`ChainManager`], one at a time, taken from bounded priority lanes.
//!
//! Before Stage 2 every chain access was a closure run under one unfair
//! `std::sync::Mutex`: a heavy block step, a reorganization or a slow disk
//! made every other access (header sync, transaction relay, RPC reads) wait
//! in whatever order the OS woke them. Now:
//!
//! - **One writer.** Only the actor thread runs chain operations. A command
//!   is exactly one former lock closure (the same `ChainManager` calls with
//!   the same arguments), so every execution of the actor is one the mutex
//!   already allowed: consensus results are unchanged (the equivalence
//!   argument, docs/reviews/chain-actor-stage2.md §4; tests E1-E4).
//! - **Priority lanes** ([`Lane`]): Headers, Blocks, Query, Tx, served in
//!   that order, with a starvation bound ([`STARVATION_LIMIT`]). Producers
//!   never block on a full lane: [`ChainHandle::call`] and
//!   [`ChainHandle::submit_block`] return [`SendError::Full`] at once.
//! - **Drains in steps.** A submitted body that releases waiting descendants
//!   is connected in steps of at most `step_budget` validations
//!   (`ChainManager::sync_step`); the actor serves one waiting command
//!   between two steps (Headers, Blocks or Query; a Tx command only once
//!   starved), so each command of a header batch or a query waits for at
//!   most one step. This replaces `submit_block_in_steps` and its 1 ms
//!   fairness sleep; the drain's rules (never a lighter tip) are the
//!   manager's, unchanged.
//! - **Snapshots.** After every command and step the actor publishes the
//!   chain summary (`ChainManager::publish_summary`) *before* it replies and
//!   before it takes the next command, so a reply's receiver reads a
//!   snapshot at least as new as its command ([`ChainHandle::summary`]).
//! - **Fail-stop.** A panic in a command leaves the manager in an unknown
//!   state: the process exits with [`POISONED_EXIT_CODE`], as a poisoned
//!   chain lock did, and a restart replays the store (fsync before apply).
//!
//! The manager sits in an `Arc<Mutex<_>>` that only the actor locks, once per
//! command: [`spawn`] creates it and never shares it, so in the node no one
//! else can wait on it. [`spawn_shared`] takes one the caller keeps: a
//! compatibility shim for tests and embedders that read the manager
//! directly, with the old lock semantics (a caller holding that lock stalls
//! the actor, exactly as it stalled the old writers).
//!
//! Ordering guarantees (docs/reviews/chain-actor-stage2.md §3, each tested
//! in `chain/tests/actor_equivalence.rs` and `chain/tests/actor_order.rs`):
//! 1. one writer, total order: the execution order is the linearization;
//! 2. per-producer FIFO within a lane;
//! 3. no order across lanes beyond priority (a higher lane may overtake);
//! 4. drain continuation: between two steps the actor serves at most one
//!    command (a Tx command only once starved); a body submitted mid-drain
//!    waits for the drain;
//! 5. snapshot monotonicity: `seq` never decreases, one publication per
//!    command or step, before its reply;
//! 6. compound operations are single commands (a closure runs whole);
//! 7. stop is served between steps (a pending drain is left to replay).
//!
//! Std-only (decisions "Agent 34": no `arc-swap`, no persistent
//! collections); replies go through callbacks, so this crate needs no async
//! runtime (the P2P layer wraps a `tokio::sync::oneshot` in them).

use crate::block::Block;
use crate::manager::{
    ChainManager, ChainSummary, SubmitError, Submitted, SummaryCell, SYNC_STEP_BLOCKS,
};
use blacksilk_consensus::Hash;
use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;

/// Exit status of a node whose chain actor panicked (or whose manager lock
/// was poisoned by a panic): the manager may be half-updated, so the process
/// stops for a supervisor to restart it; the append-only store replays
/// deterministically. Equal to `blacksilk_p2p::POISONED_EXIT_CODE` and
/// `blacksilk_node::POISONED_EXIT_CODE`.
pub const POISONED_EXIT_CODE: i32 = 70;

/// A lower lane's waiting command is served after at most this many
/// commands from higher lanes (it is never starved by a steady stream).
pub const STARVATION_LIMIT: u32 = 16;

/// The Blocks lane's default capacity ([`ActorConfig::default`]).
pub const DEFAULT_BLOCKS_CAPACITY: usize = 256;

/// The command lanes, highest priority first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Lane {
    /// Header batches from sync: pre-checks and PoW jobs (reads) and
    /// acceptance.
    Headers,
    /// Block bodies: the P2P block worker and RPC `/block` (local mining).
    Blocks,
    /// Reads that need more than the snapshot: `GetHeaders`, `GetBlocks`,
    /// mempool lookups, `/template`, RPC state pages, transaction
    /// pre-checks.
    Query,
    /// Transaction admission (relay, stem checks, fluff, local
    /// submission). Relay is best effort: a full Tx lane drops relayed
    /// transactions without penalty.
    Tx,
}

impl Lane {
    /// Every lane, highest priority first.
    pub const ALL: [Lane; 4] = [Lane::Headers, Lane::Blocks, Lane::Query, Lane::Tx];

    fn index(self) -> usize {
        self as usize
    }
}

/// Actor settings.
#[derive(Clone, Debug)]
pub struct ActorConfig {
    /// Block validations per drain step (`ChainManager::sync_step`).
    pub step_budget: usize,
    /// Commands each lane holds, indexed as [`Lane::ALL`]. A capacity of 0
    /// refuses every command on that lane (tests only: a waiting caller
    /// would wait forever).
    pub capacity: [usize; 4],
}

impl ActorConfig {
    /// The capacity of `lane`.
    pub fn capacity(&self, lane: Lane) -> usize {
        self.capacity[lane.index()]
    }
}

impl Default for ActorConfig {
    /// - Headers: one header worker (one command outstanding) and RPC:
    ///   64 is ample.
    /// - Blocks: at least the sum of the P2P per-peer request windows plus
    ///   the unrequested queue ((64 + 8) × 3 + 8 = 224), so a requested
    ///   block is never refused; the block worker also submits one at a time.
    /// - Query: every peer's slow lane (one command outstanding each), the
    ///   chain maintenance task and the RPC admission slots.
    /// - Tx: one command per peer slow lane at most; beyond this, relayed
    ///   transactions are dropped (best effort, never penalized), which
    ///   frees the peers' slow lanes during a long command.
    fn default() -> Self {
        Self {
            step_budget: SYNC_STEP_BLOCKS,
            capacity: [64, DEFAULT_BLOCKS_CAPACITY, 1024, 64],
        }
    }
}

/// Why a command was not queued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendError {
    /// The lane is full; nothing was queued.
    Full(Lane),
    /// The actor stopped (or was told to stop).
    Stopped,
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendError::Full(lane) => write!(f, "the chain actor's {lane:?} lane is full"),
            SendError::Stopped => f.write_str("the chain actor stopped"),
        }
    }
}

impl std::error::Error for SendError {}

/// A command that was not queued, with what the caller passed, so that it
/// can offer it again (after a full lane) without copying it.
pub struct Rejected<T> {
    pub error: SendError,
    pub returned: Box<T>,
}

impl<T> std::fmt::Debug for Rejected<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Rejected({:?})", self.error)
    }
}

/// A block submission's result: `None` when the submission asked for a
/// known header and the header was unknown (nothing was done).
pub type BlockReply = Option<Result<Submitted, SubmitError>>;

/// Delivers a command's result, after the snapshot is published.
type Deliver = Box<dyn FnOnce() + Send>;
type Job = Box<dyn FnOnce(&mut ChainManager) -> Deliver + Send>;
type SubmitReply = Box<dyn FnOnce(BlockReply) + Send>;

enum Command {
    Run {
        job: Job,
        #[cfg(feature = "test-hooks")]
        label: String,
    },
    Submit {
        block: Block,
        now: u64,
        only_if_header_known: bool,
        reply: SubmitReply,
        #[cfg(feature = "test-hooks")]
        label: String,
    },
    /// Test-only fault injection (F1): the actor panics.
    #[cfg(feature = "test-hooks")]
    Panic,
}

/// The lanes and the handle count, under one short-hold mutex (never held
/// while a command runs).
struct Lanes {
    queues: [VecDeque<Command>; 4],
    capacity: [usize; 4],
    /// Picks since each non-empty lane was last served.
    skipped: [u32; 4],
    /// Live [`ChainHandle`]s. At zero the actor finishes its drain and exits.
    handles: usize,
    /// [`ChainHandle::stop`] was called.
    stop: bool,
    /// The actor thread ended (commands are refused).
    ended: bool,
}

impl Lanes {
    /// The next command: the highest-priority non-empty lane, unless a
    /// lower one was passed over [`STARVATION_LIMIT`] times. During a drain
    /// (`draining`) the Tx lane is served only once starved: blocks,
    /// headers and queries go first (F34-5).
    fn pop(&mut self, draining: bool) -> Option<Command> {
        let tx = Lane::Tx.index();
        let eligible = |l: &Lanes, i: usize| {
            !l.queues[i].is_empty() && (!draining || i != tx || l.skipped[i] >= STARVATION_LIMIT)
        };
        let pick = (0..4)
            .find(|&i| eligible(self, i) && self.skipped[i] >= STARVATION_LIMIT)
            .or_else(|| (0..4).find(|&i| eligible(self, i)))?;
        for i in 0..4 {
            if i == pick {
                self.skipped[i] = 0;
            } else if !self.queues[i].is_empty() {
                self.skipped[i] += 1;
            }
        }
        self.queues[pick].pop_front()
    }

    /// A drain step passed over every waiting command.
    fn pass_over(&mut self) {
        for i in 0..4 {
            if !self.queues[i].is_empty() {
                self.skipped[i] = self.skipped[i].saturating_add(1);
            }
        }
    }
}

struct Queue {
    lanes: Mutex<Lanes>,
    /// Signalled when a command arrives, a handle goes or stop is asked.
    work: Condvar,
    /// Signalled when a command leaves a lane (room for a waiting producer).
    room: Condvar,
}

impl Queue {
    fn lanes(&self) -> MutexGuard<'_, Lanes> {
        // A panic cannot happen inside the lane critical sections (queue
        // pushes and pops); a poisoned lock still holds consistent queues.
        self.lanes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Queues `make(value)` on `lane` if it has room; otherwise hands
    /// `value` back.
    fn offer<T>(
        &self,
        lane: Lane,
        value: T,
        make: impl FnOnce(T) -> Command,
    ) -> Result<(), Rejected<T>> {
        let mut l = self.lanes();
        let error = if l.stop || l.ended {
            SendError::Stopped
        } else if l.queues[lane.index()].len() >= l.capacity[lane.index()] {
            SendError::Full(lane)
        } else {
            l.queues[lane.index()].push_back(make(value));
            drop(l);
            self.work.notify_one();
            return Ok(());
        };
        Err(Rejected {
            error,
            returned: Box::new(value),
        })
    }

    #[cfg(feature = "test-hooks")]
    fn push(&self, lane: Lane, cmd: Command) -> Result<(), SendError> {
        self.offer(lane, cmd, |c| c).map_err(|r| r.error)
    }

    /// [`Self::offer`], waiting for room (plain threads only).
    fn push_waiting(&self, lane: Lane, cmd: Command) -> Result<(), SendError> {
        let mut l = self.lanes();
        let i = lane.index();
        loop {
            if l.stop || l.ended {
                return Err(SendError::Stopped);
            }
            if l.queues[i].len() < l.capacity[i] {
                l.queues[i].push_back(cmd);
                drop(l);
                self.work.notify_one();
                return Ok(());
            }
            l = self
                .room
                .wait(l)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}

/// A cloneable handle to the chain actor: send commands, read snapshots.
/// When the last handle is dropped, the actor finishes a pending drain and
/// exits.
pub struct ChainHandle {
    queue: Arc<Queue>,
    summary: Arc<SummaryCell>,
    #[cfg(feature = "test-hooks")]
    log: Arc<Mutex<Vec<LogEntry>>>,
}

impl Clone for ChainHandle {
    fn clone(&self) -> Self {
        self.queue.lanes().handles += 1;
        Self {
            queue: self.queue.clone(),
            summary: self.summary.clone(),
            #[cfg(feature = "test-hooks")]
            log: self.log.clone(),
        }
    }
}

impl Drop for ChainHandle {
    fn drop(&mut self) {
        let mut l = self.queue.lanes();
        l.handles -= 1;
        if l.handles == 0 {
            drop(l);
            self.queue.work.notify_all();
        }
    }
}

impl ChainHandle {
    /// The latest published snapshot. Never waits for chain work.
    pub fn summary(&self) -> Arc<ChainSummary> {
        self.summary.load()
    }

    /// The cell the actor publishes to (for readers that keep only it).
    pub fn summary_cell(&self) -> Arc<SummaryCell> {
        self.summary.clone()
    }

    /// Queues `f` on `lane`; the actor runs it with the manager and passes
    /// its result to `reply` (on the actor thread: keep `reply` short and
    /// non-blocking, e.g. a channel send). Never waits: a full lane is
    /// [`SendError::Full`], and `f` and `reply` come back unused.
    pub fn call<R, F, P>(&self, lane: Lane, f: F, reply: P) -> Result<(), Rejected<(F, P)>>
    where
        R: Send + 'static,
        F: FnOnce(&mut ChainManager) -> R + Send + 'static,
        P: FnOnce(R) + Send + 'static,
    {
        self.queue.offer(lane, (f, reply), |(f, reply)| {
            run_command(f, reply, String::new())
        })
    }

    /// [`Self::call`] from a plain (non-async) thread: waits for room in the
    /// lane and for the result. `Err(Stopped)` if the actor stops first.
    pub fn call_blocking<R: Send + 'static>(
        &self,
        lane: Lane,
        f: impl FnOnce(&mut ChainManager) -> R + Send + 'static,
    ) -> Result<R, SendError> {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let cmd = run_command(
            f,
            move |r| {
                let _ = tx.send(r);
            },
            String::new(),
        );
        self.queue.push_waiting(lane, cmd)?;
        rx.recv().map_err(|_| SendError::Stopped)
    }

    /// Submits a block on the Blocks lane; `reply` receives the final
    /// verdict, as `ChainManager::submit_block` reports it, once the drain
    /// it started (or joined) has finished. With `only_if_header_known`, a
    /// block whose header the manager does not know is skipped (`None`)
    /// before it is hashed or stored (the P2P rule for unrequested bodies).
    /// Never waits: a full lane is [`SendError::Full`], and the block and
    /// `reply` come back unused.
    pub fn submit_block<P>(
        &self,
        block: Block,
        now: u64,
        only_if_header_known: bool,
        reply: P,
    ) -> Result<(), Rejected<(Block, P)>>
    where
        P: FnOnce(BlockReply) + Send + 'static,
    {
        self.queue
            .offer(Lane::Blocks, (block, reply), |(block, reply)| {
                Command::Submit {
                    block,
                    now,
                    only_if_header_known,
                    reply: Box::new(reply),
                    #[cfg(feature = "test-hooks")]
                    label: String::new(),
                }
            })
    }

    /// [`Self::submit_block`] from a plain thread, waiting for the verdict.
    pub fn submit_block_blocking(
        &self,
        block: Block,
        now: u64,
    ) -> Result<Result<Submitted, SubmitError>, SendError> {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        self.queue.push_waiting(
            Lane::Blocks,
            Command::Submit {
                block,
                now,
                only_if_header_known: false,
                reply: Box::new(move |r| {
                    let _ = tx.send(r);
                }),
                #[cfg(feature = "test-hooks")]
                label: String::new(),
            },
        )?;
        match rx.recv() {
            Ok(Some(r)) => Ok(r),
            Ok(None) => unreachable!("only_if_header_known is false"),
            Err(_) => Err(SendError::Stopped),
        }
    }

    /// Asks the actor to stop after its current command or step. Queued
    /// commands are dropped unanswered; a pending drain is left for the
    /// store replay at the next start (every kept body is on disk).
    pub fn stop(&self) {
        self.queue.lanes().stop = true;
        self.queue.work.notify_all();
        self.queue.room.notify_all();
    }

    /// Commands queued on `lane` now (diagnostics and tests).
    pub fn queued(&self, lane: Lane) -> usize {
        self.queue.lanes().queues[lane.index()].len()
    }
}

fn run_command<R: Send + 'static>(
    f: impl FnOnce(&mut ChainManager) -> R + Send + 'static,
    reply: impl FnOnce(R) + Send + 'static,
    label: String,
) -> Command {
    #[cfg(not(feature = "test-hooks"))]
    let _ = label;
    Command::Run {
        job: Box::new(move |m| {
            let r = f(m);
            Box::new(move || reply(r))
        }),
        #[cfg(feature = "test-hooks")]
        label,
    }
}

/// The actor thread, owned by whoever spawned it.
pub struct ActorThread {
    thread: Option<JoinHandle<()>>,
    chain: Arc<Mutex<ChainManager>>,
    queue: Arc<Queue>,
}

impl ActorThread {
    /// Stops the actor between steps ([`ChainHandle::stop`]) and waits for
    /// its thread. Returns the manager if no one else holds it (the
    /// [`spawn`] case once every handle and snapshot user let go of it).
    pub fn stop_and_join(mut self) -> Option<ChainManager> {
        self.queue.lanes().stop = true;
        self.queue.work.notify_all();
        self.queue.room.notify_all();
        self.join_thread();
        let chain = self.chain.clone();
        drop(self);
        Arc::try_unwrap(chain)
            .ok()
            .map(|m| m.into_inner().unwrap_or_else(|e| e.into_inner()))
    }

    /// Waits for the actor to end on its own: once every handle is dropped
    /// and the drain in progress (if any) is finished.
    pub fn join(mut self) -> Option<ChainManager> {
        self.join_thread();
        let chain = self.chain.clone();
        drop(self);
        Arc::try_unwrap(chain)
            .ok()
            .map(|m| m.into_inner().unwrap_or_else(|e| e.into_inner()))
    }

    fn join_thread(&mut self) {
        if let Some(t) = self.thread.take() {
            // The actor exits the process on a panic; a join error cannot
            // be observed here.
            let _ = t.join();
        }
    }
}

/// Starts the actor on `manager`, which only the actor can reach from now
/// on.
pub fn spawn(manager: ChainManager, config: ActorConfig) -> (ChainHandle, ActorThread) {
    spawn_shared(Arc::new(Mutex::new(manager)), config)
}

/// Starts the actor on a manager the caller keeps a lock on (compatibility
/// shim for tests and embedders, module docs). The caller must not run
/// chain operations through its lock while the actor runs if it wants the
/// single-writer guarantees; reads through it behave as reads under the old
/// chain lock.
pub fn spawn_shared(
    chain: Arc<Mutex<ChainManager>>,
    config: ActorConfig,
) -> (ChainHandle, ActorThread) {
    let summary = lock_manager(&chain).summary_cell();
    let queue = Arc::new(Queue {
        lanes: Mutex::new(Lanes {
            queues: Default::default(),
            capacity: config.capacity,
            skipped: [0; 4],
            handles: 1,
            stop: false,
            ended: false,
        }),
        work: Condvar::new(),
        room: Condvar::new(),
    });
    #[cfg(feature = "test-hooks")]
    let log = Arc::new(Mutex::new(Vec::new()));
    let actor = Actor {
        chain: chain.clone(),
        queue: queue.clone(),
        budget: config.step_budget.max(1),
        waiters: Vec::new(),
        manager_pending: false,
        stepped_since_command: true,
        #[cfg(feature = "test-hooks")]
        log: log.clone(),
    };
    let thread = std::thread::Builder::new()
        .name("chain-actor".into())
        .spawn(move || actor.run())
        .expect("spawning the chain actor thread");
    let handle = ChainHandle {
        queue: queue.clone(),
        summary,
        #[cfg(feature = "test-hooks")]
        log,
    };
    (
        handle,
        ActorThread {
            thread: Some(thread),
            chain,
            queue,
        },
    )
}

/// Locks the manager, or stops the process if a panic poisoned the lock
/// (the manager may be half-updated; see [`POISONED_EXIT_CODE`]).
fn lock_manager(chain: &Mutex<ChainManager>) -> MutexGuard<'_, ChainManager> {
    match chain.lock() {
        Ok(g) => g,
        Err(_) => fatal("chain lock poisoned by a panic"),
    }
}

/// Logs `why` and exits with [`POISONED_EXIT_CODE`].
fn fatal(why: &str) -> ! {
    log::error!("{why}; stopping (restart to recover: the block store is replayed)");
    // Also without a logger (tests, embedders): the exit must not be silent.
    eprintln!("blacksilk-chain: {why}; exiting with status {POISONED_EXIT_CODE}");
    std::process::exit(POISONED_EXIT_CODE)
}

/// Exits the process if the actor thread unwinds (fail-stop).
struct FailStop;

impl Drop for FailStop {
    fn drop(&mut self) {
        if std::thread::panicking() {
            fatal("the chain actor panicked");
        }
    }
}

/// A block submission waiting for its drain to finish.
struct Waiter {
    id: Hash,
    height: u64,
    reply: SubmitReply,
    #[cfg(feature = "test-hooks")]
    label: String,
}

enum Pick {
    Command(Command),
    Step,
    Exit,
}

struct Actor {
    chain: Arc<Mutex<ChainManager>>,
    queue: Arc<Queue>,
    budget: usize,
    /// Submissions whose verdict waits for the drain.
    waiters: Vec<Waiter>,
    /// `ChainManager::sync_pending` after the last command or step.
    manager_pending: bool,
    /// A step ran since the last command (guarantee 4: at most one command
    /// between two steps).
    stepped_since_command: bool,
    #[cfg(feature = "test-hooks")]
    log: Arc<Mutex<Vec<LogEntry>>>,
}

impl Actor {
    fn run(mut self) {
        let _fail_stop = FailStop;
        loop {
            match self.next() {
                Pick::Exit => break,
                Pick::Command(cmd) => {
                    self.stepped_since_command = false;
                    self.execute(cmd);
                }
                Pick::Step => {
                    self.stepped_since_command = true;
                    self.step();
                }
            }
        }
        let mut l = self.queue.lanes();
        l.ended = true;
        // Queued commands are dropped unanswered (their callers see the
        // actor stopped).
        for q in &mut l.queues {
            q.clear();
        }
        drop(l);
        self.queue.room.notify_all();
    }

    /// A drain is in progress or a submission waits for its verdict (which
    /// needs at least one step, as `submit_block_in_steps` took one).
    fn drain_pending(&self) -> bool {
        self.manager_pending || !self.waiters.is_empty()
    }

    fn next(&mut self) -> Pick {
        let mut l = self.queue.lanes();
        loop {
            if l.stop {
                return Pick::Exit;
            }
            let draining = self.drain_pending();
            if draining && !self.stepped_since_command {
                l.pass_over();
                return Pick::Step;
            }
            if let Some(cmd) = l.pop(draining) {
                drop(l);
                self.queue.room.notify_all();
                return Pick::Command(cmd);
            }
            if draining {
                l.pass_over();
                return Pick::Step;
            }
            if l.handles == 0 {
                return Pick::Exit;
            }
            l = self
                .queue
                .work
                .wait(l)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    fn execute(&mut self, cmd: Command) {
        match cmd {
            Command::Run {
                job,
                #[cfg(feature = "test-hooks")]
                label,
            } => {
                let deliver = {
                    let mut m = lock_manager(&self.chain);
                    let deliver = job(&mut m);
                    m.publish_summary();
                    self.manager_pending = m.sync_pending();
                    #[cfg(feature = "test-hooks")]
                    self.record(LogEntry::Run {
                        label,
                        snapshot: m.summary(),
                    });
                    deliver
                };
                deliver();
            }
            Command::Submit {
                block,
                now,
                only_if_header_known,
                reply,
                #[cfg(feature = "test-hooks")]
                label,
            } => {
                let immediate = {
                    let mut m = lock_manager(&self.chain);
                    let id = block.id(m.params().network_id);
                    let r = if only_if_header_known && m.header(&id).is_none() {
                        None
                    } else {
                        Some(m.submit_block_bounded(block, now, self.budget))
                    };
                    m.publish_summary();
                    self.manager_pending = m.sync_pending();
                    #[cfg(feature = "test-hooks")]
                    let logged = format!("{r:?}");
                    let immediate = match r {
                        Some(Ok(s)) if s.body_kept => {
                            self.waiters.push(Waiter {
                                id: s.id,
                                height: s.height,
                                reply,
                                #[cfg(feature = "test-hooks")]
                                label: label.clone(),
                            });
                            None
                        }
                        r => Some((reply, r)),
                    };
                    #[cfg(feature = "test-hooks")]
                    self.record(LogEntry::Submit {
                        label,
                        first: logged,
                        answered: immediate.is_some(),
                        snapshot: m.summary(),
                    });
                    immediate
                };
                if let Some((reply, r)) = immediate {
                    reply(r);
                }
            }
            #[cfg(feature = "test-hooks")]
            Command::Panic => {
                let _held = lock_manager(&self.chain);
                panic!("injected chain actor panic (test-hooks)");
            }
        }
    }

    fn step(&mut self) {
        let answers = {
            let mut m = lock_manager(&self.chain);
            let done = m.sync_step(self.budget);
            m.publish_summary();
            self.manager_pending = m.sync_pending();
            let answers: Vec<_> = if done {
                std::mem::take(&mut self.waiters)
                    .into_iter()
                    .map(|w| {
                        let v = m.verdict(w.id, w.height);
                        (w, v)
                    })
                    .collect()
            } else {
                Vec::new()
            };
            #[cfg(feature = "test-hooks")]
            self.record(LogEntry::Step {
                done,
                verdicts: answers
                    .iter()
                    .map(|(w, v)| (w.label.clone(), format!("{:?}", Some(v))))
                    .collect(),
                snapshot: m.summary(),
            });
            answers
        };
        for (w, v) in answers {
            (w.reply)(Some(v));
        }
    }

    #[cfg(feature = "test-hooks")]
    fn record(&self, e: LogEntry) {
        self.log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(e);
    }
}

/// One applied action of the actor, in execution order (test-only
/// linearization log, `test-hooks` feature; E2/E3).
#[cfg(feature = "test-hooks")]
#[derive(Clone, Debug)]
pub enum LogEntry {
    /// A [`ChainHandle::call`] closure ran.
    Run {
        label: String,
        snapshot: Arc<ChainSummary>,
    },
    /// A block submission's first bounded call; `first` is its result
    /// (`Debug` of [`BlockReply`]); `answered` if that was the reply.
    Submit {
        label: String,
        first: String,
        answered: bool,
        snapshot: Arc<ChainSummary>,
    },
    /// A drain step; when `done`, the verdicts it delivered.
    Step {
        done: bool,
        verdicts: Vec<(String, String)>,
        snapshot: Arc<ChainSummary>,
    },
}

/// Test-only commands and observation (`test-hooks` feature, never enabled
/// in a release build: only dev-dependencies turn it on).
#[cfg(feature = "test-hooks")]
impl ChainHandle {
    /// [`Self::call`] with a label recorded in the linearization log.
    pub fn call_labeled<R: Send + 'static>(
        &self,
        lane: Lane,
        label: String,
        f: impl FnOnce(&mut ChainManager) -> R + Send + 'static,
        reply: impl FnOnce(R) + Send + 'static,
    ) -> Result<(), SendError> {
        self.queue.push(lane, run_command(f, reply, label))
    }

    /// [`Self::submit_block`] with a label recorded in the log.
    pub fn submit_block_labeled(
        &self,
        label: String,
        block: Block,
        now: u64,
        reply: impl FnOnce(BlockReply) + Send + 'static,
    ) -> Result<(), SendError> {
        self.queue.push(
            Lane::Blocks,
            Command::Submit {
                block,
                now,
                only_if_header_known: false,
                reply: Box::new(reply),
                label,
            },
        )
    }

    /// The actions applied so far, in order.
    pub fn log_for_tests(&self) -> Vec<LogEntry> {
        self.log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Makes the actor panic (F1: the process must exit with
    /// [`POISONED_EXIT_CODE`]).
    pub fn inject_panic_for_tests(&self) -> Result<(), SendError> {
        self.queue.push(Lane::Headers, Command::Panic)
    }
}
