//! The PoW hash cache (`CachedPow`) and its parallel precomputation.

use blacksilk_consensus::hash::H;
use blacksilk_consensus::{Hash, PowFunction};
use std::any::Any;
use std::collections::{HashMap, VecDeque};
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;

/// PoW wrapper that remembers every computed hash, keyed by the RandomX key
/// (seed block id) **and** the mining blob. It lets the node store PoW hashes
/// with blocks and skip recomputing RandomX when replaying its own store.
///
/// The seed is part of the key so that a hash computed under one seed (for
/// example by [`ChainManager::pow_jobs`] from a peer's batch) is never reused
/// where header validation derives a different seed: that lookup misses and
/// the hash is computed again under the right key.
///
/// It also owns the node's PoW hashing pool ([`Self::compute_parallel`]).
pub struct CachedPow {
    /// Declared first, so dropped first: the helpers are joined before the
    /// cache drops its own reference to the PoW function.
    pool: HashPool,
    hashes: Arc<Hashes>,
}

/// The PoW function and the hashes it computed: everything a pool thread
/// needs (it never holds the [`CachedPow`] itself, so dropping the cache
/// stops the pool).
struct Hashes {
    inner: Arc<dyn PowFunction>,
    known: Mutex<HashMap<Hash, Hash>>,
}

impl Hashes {
    fn key(seed: &Hash, blob: &blacksilk_consensus::PowBlob) -> Hash {
        H::new()
            .chain(b"BlackSilk/pow-cache/v3")
            .chain(seed)
            .chain(blob)
            .finish()
    }

    fn lookup(&self, seed: &Hash, blob: &blacksilk_consensus::PowBlob) -> Option<Hash> {
        lock(&self.known).get(&Self::key(seed, blob)).copied()
    }

    fn preload(&self, seed: &Hash, blob: &blacksilk_consensus::PowBlob, pow_hash: Hash) {
        lock(&self.known).insert(Self::key(seed, blob), pow_hash);
    }

    fn pow_hash(&self, seed: &Hash, blob: &blacksilk_consensus::PowBlob) -> Hash {
        if let Some(h) = self.lookup(seed, blob) {
            return h;
        }
        let h = self.inner.pow_hash(seed, blob);
        self.preload(seed, blob, h);
        h
    }
}

/// Locks `m`, recovering a poisoned lock: every value guarded here (a hash
/// map of pure function results, counters, a queue) stays consistent if a
/// holder panics, and no hash is computed under one of these locks.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl CachedPow {
    pub fn new(inner: Arc<dyn PowFunction>) -> Self {
        Self {
            pool: HashPool::new(),
            hashes: Arc::new(Hashes {
                inner,
                known: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// The cached PoW hash of `blob` under the RandomX key `seed`.
    pub fn lookup(&self, seed: &Hash, blob: &blacksilk_consensus::PowBlob) -> Option<Hash> {
        self.hashes.lookup(seed, blob)
    }

    /// Trusts `pow_hash` for `blob` under `seed` (only for blocks from
    /// the node's own store, with the seed derived from the stored parent).
    pub fn preload(&self, seed: &Hash, blob: &blacksilk_consensus::PowBlob, pow_hash: Hash) {
        self.hashes.preload(seed, blob, pow_hash)
    }

    /// The PoW function's own hash of `blob` under `seed`, computed
    /// now: never the cached value, and not cached (the start-up check of
    /// the stored hashes compares the two, `ChainManager::open_checked`).
    pub fn recompute(&self, seed: &Hash, blob: &blacksilk_consensus::PowBlob) -> Hash {
        self.hashes.inner.pow_hash(seed, blob)
    }
}

/// One PoW computation: RandomX key (seed block id) and mining blob.
pub type PowJob = (Hash, [u8; blacksilk_consensus::POW_BLOB_SIZE]);

/// Most helper threads a pool starts. The p2p header worker, the only caller
/// with more than one thread, hashes chunks of at most `seed_lag` (64)
/// headers (`sync_policy::pow_chunk`): the caller plus 63 helpers. A larger
/// `threads` only shares the jobs among fewer threads; no result changes.
const MAX_POW_HELPERS: usize = 63;

impl CachedPow {
    /// Computes and caches the PoW hashes of `jobs` on `threads` threads, the
    /// calling thread included, and returns once every one is cached.
    ///
    /// - **One thread** (or one job to hash): the jobs are hashed in order on
    ///   the calling thread; no thread is started or woken.
    /// - **More:** the caller hashes alongside up to `threads - 1` helper
    ///   threads of a persistent pool, started once (the first time they are
    ///   needed) and kept until the cache is dropped, instead of new threads
    ///   per call (W4-POWPOOL: under CPU contention each spawn waited
    ///   13-130 ms for the scheduler, once per PoW chunk). The threads take
    ///   jobs in order from a shared counter. The caller never waits for a
    ///   helper to become free: with every helper busy it hashes the whole
    ///   batch itself, and it waits only for jobs a helper has already taken.
    ///   Concurrent callers share the helpers first come, first served.
    ///
    /// Which thread hashes a job changes nothing: each hash is the PoW
    /// function's, stored under its own key, and jobs already cached are
    /// skipped. Every thread computes one hash at a time and holds no RandomX
    /// cache between hashes (the cache store's caller rule,
    /// `consensus::pow::SeedCache`). A hash that panics is re-raised on the
    /// caller (as a panicking scoped thread was): with helpers, after the
    /// other jobs are done, and the helper that ran it stays in the pool;
    /// inline, at once (the remaining jobs are not hashed).
    pub fn compute_parallel(&self, jobs: &[PowJob], threads: usize) {
        let todo: Vec<PowJob> = jobs
            .iter()
            .filter(|(seed, b)| self.lookup(seed, b).is_none())
            .copied()
            .collect();
        if todo.is_empty() {
            return;
        }
        let wanted = threads.clamp(1, todo.len()) - 1;
        let helpers = if wanted == 0 {
            0
        } else {
            self.pool.start(wanted)
        };
        if helpers == 0 {
            for (seed, bytes) in &todo {
                let _ = self.hashes.pow_hash(seed, bytes);
            }
            return;
        }
        let batch = Arc::new(Batch {
            hashes: self.hashes.clone(),
            jobs: todo,
            next: AtomicUsize::new(0),
            progress: Mutex::new(Progress {
                done: 0,
                panic: None,
            }),
            finished: Condvar::new(),
        });
        self.pool.submit(&batch, helpers);
        batch.work();
        batch.wait();
    }

    /// Helper threads this cache's hashing pool has started: 0 until
    /// [`Self::compute_parallel`] first runs with more than one thread, then
    /// at most `MAX_POW_HELPERS`, whatever the number of calls.
    pub fn pool_threads(&self) -> usize {
        lock(&self.pool.workers).len()
    }
}

/// The jobs of one [`CachedPow::compute_parallel`] call with helpers.
struct Batch {
    hashes: Arc<Hashes>,
    jobs: Vec<PowJob>,
    /// The next job to take.
    next: AtomicUsize,
    progress: Mutex<Progress>,
    /// Signalled when the last job is done.
    finished: Condvar,
}

struct Progress {
    /// Jobs done (hashed, or panicked).
    done: usize,
    /// The first panic of a job.
    panic: Option<Box<dyn Any + Send>>,
}

impl Batch {
    /// Takes jobs until none is left. Never panics: a job's first panic is
    /// kept for the caller ([`Self::wait`]). The completion is signalled
    /// before anything else can unwind, and a later payload is dropped
    /// outside the lock under `catch_unwind` (its own `Drop` may panic,
    /// RT-POWPOOL F1): a waiting caller is always woken.
    fn work(&self) {
        loop {
            let i = self.next.fetch_add(1, Ordering::Relaxed);
            let Some((seed, bytes)) = self.jobs.get(i) else {
                return;
            };
            let hashed = catch_unwind(AssertUnwindSafe(|| {
                let _ = self.hashes.pow_hash(seed, bytes);
            }));
            let mut p = lock(&self.progress);
            p.done += 1;
            let extra = match hashed {
                Err(e) if p.panic.is_none() => {
                    p.panic = Some(e);
                    None
                }
                Err(e) => Some(e),
                Ok(()) => None,
            };
            if p.done == self.jobs.len() {
                self.finished.notify_all();
            }
            drop(p);
            let _ = catch_unwind(AssertUnwindSafe(|| drop(extra)));
        }
    }

    /// Waits until every job is done, then re-raises the first panic.
    fn wait(&self) {
        let mut p = lock(&self.progress);
        while p.done < self.jobs.len() {
            p = self.finished.wait(p).unwrap_or_else(|e| e.into_inner());
        }
        if let Some(e) = p.panic.take() {
            drop(p);
            resume_unwind(e);
        }
    }
}

/// Persistent helper threads for [`CachedPow::compute_parallel`]. A call
/// queues one ticket (its batch) per helper it wants; a helper takes the
/// oldest ticket and works on that batch until no job is left in it. A ticket
/// taken after its batch ran out costs nothing. The queue holds at most
/// `threads - 1` tickets per waiting caller.
struct HashPool {
    queue: Arc<Queue>,
    workers: Mutex<Vec<JoinHandle<()>>>,
}

struct Queue {
    state: Mutex<QueueState>,
    ready: Condvar,
}

struct QueueState {
    tickets: VecDeque<Arc<Batch>>,
    /// Set when the pool is dropped: helpers exit.
    closed: bool,
}

impl HashPool {
    fn new() -> Self {
        Self {
            queue: Arc::new(Queue {
                state: Mutex::new(QueueState {
                    tickets: VecDeque::new(),
                    closed: false,
                }),
                ready: Condvar::new(),
            }),
            workers: Mutex::new(Vec::new()),
        }
    }

    /// Starts helpers until there are `wanted` (at most
    /// `MAX_POW_HELPERS`); returns how many of them a call may use. A
    /// thread that cannot be started leaves its share to the others (the
    /// caller hashes everything if none can).
    ///
    /// A helper never ends while the pool is open (`Queue::serve` contains
    /// every panic of a batch); if one did, it is logged and replaced here.
    fn start(&self, wanted: usize) -> usize {
        let wanted = wanted.min(MAX_POW_HELPERS);
        let mut workers = lock(&self.workers);
        let before = workers.len();
        workers.retain(|h| !h.is_finished());
        if workers.len() < before {
            log::error!(
                "{} PoW helper thread(s) ended unexpectedly; replacing them",
                before - workers.len()
            );
        }
        while workers.len() < wanted {
            let queue = self.queue.clone();
            match std::thread::Builder::new()
                .name("pow-helper".into())
                .spawn(move || queue.serve())
            {
                Ok(handle) => workers.push(handle),
                Err(e) => {
                    log::warn!("could not start a PoW helper thread: {e}");
                    break;
                }
            }
        }
        wanted.min(workers.len())
    }

    fn submit(&self, batch: &Arc<Batch>, helpers: usize) {
        let mut st = lock(&self.queue.state);
        for _ in 0..helpers {
            st.tickets.push_back(batch.clone());
        }
        drop(st);
        for _ in 0..helpers {
            self.queue.ready.notify_one();
        }
    }
}

impl Queue {
    /// A helper's loop: the oldest ticket's batch, until the pool closes.
    fn serve(&self) {
        loop {
            let batch = {
                let mut st = lock(&self.state);
                loop {
                    if st.closed {
                        return;
                    }
                    if let Some(b) = st.tickets.pop_front() {
                        break b;
                    }
                    st = self.ready.wait(st).unwrap_or_else(|e| e.into_inner());
                }
            };
            // `work` never panics; the guard also covers dropping the
            // ticket, which may drop the last reference to the PoW function
            // (whose `Drop` is not ours), so no helper ends while the pool is
            // open.
            let _ = catch_unwind(AssertUnwindSafe(move || {
                batch.work();
                drop(batch);
            }));
        }
    }
}

impl Drop for HashPool {
    /// Stops the helpers and waits for them. No caller is inside
    /// `compute_parallel` (it borrows the cache), so no job is in flight: a
    /// helper is idle or finishing a ticket whose batch is done.
    fn drop(&mut self) {
        lock(&self.queue.state).closed = true;
        self.queue.ready.notify_all();
        for handle in lock(&self.workers).drain(..) {
            let _ = handle.join();
        }
    }
}

impl PowFunction for CachedPow {
    fn pow_hash(&self, seed: &Hash, blob: &blacksilk_consensus::PowBlob) -> Hash {
        self.hashes.pow_hash(seed, blob)
    }

    /// Forwards the hot keys to the RandomX layer, which pins and prebuilds
    /// them off the chain lock (`sync_policy::hot_seeds`, dossier 07 W1).
    fn set_hot_seeds(&self, seeds: &[Hash]) {
        self.hashes.inner.set_hot_seeds(seeds)
    }
}
