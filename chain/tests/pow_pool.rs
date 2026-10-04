//! `CachedPow::compute_parallel` and its persistent hashing pool
//! (W4-POWPOOL): results equal hashing the jobs one by one, one thread hashes
//! inline, helpers are started once and not per call, a panicking hash is
//! contained, the pool shuts down with the cache, and the RandomX cache
//! store's caller rule holds on every thread under concurrent batches.

use blacksilk_chain::manager::{CachedPow, PowJob};
use blacksilk_consensus::hash::H;
use blacksilk_consensus::{Hash, PowFunction, RandomXPow, POW_BLOB_SIZE};
use std::collections::HashSet;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::ThreadId;
use std::time::{Duration, Instant};

/// A cheap deterministic proof of work that records who computed what.
#[derive(Default)]
struct Recorder {
    calls: AtomicUsize,
    threads: Mutex<Vec<ThreadId>>,
}

fn cheap(seed: &Hash, blob: &[u8]) -> Hash {
    H::new()
        .chain(b"pow-pool-test")
        .chain(seed)
        .chain(blob)
        .finish()
}

impl PowFunction for Recorder {
    fn pow_hash(&self, seed: &Hash, blob: &[u8]) -> Hash {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.threads
            .lock()
            .unwrap()
            .push(std::thread::current().id());
        cheap(seed, blob)
    }
}

/// `n` distinct jobs over three keys.
fn jobs(n: usize) -> Vec<PowJob> {
    (0..n as u64)
        .map(|i| {
            let mut b = [0x11; POW_BLOB_SIZE];
            b[..8].copy_from_slice(&i.to_le_bytes());
            ([(i % 3) as u8 + 1; 32], b)
        })
        .collect()
}

/// The old path's result: every job hashed one by one, in order.
fn sequential(jobs: &[PowJob]) -> Vec<Hash> {
    jobs.iter().map(|(s, b)| cheap(s, b)).collect()
}

/// Same jobs, same hashes, whatever the thread count and chunking, and each
/// job not already cached is computed exactly once.
#[test]
fn results_equal_the_one_by_one_path() {
    let all = jobs(97);
    let want = sequential(&all);
    for threads in [1, 2, 3, 4, 8, 64, 200] {
        for chunk in [1, 2, 7, 64, 97] {
            let rec = Arc::new(Recorder::default());
            let pow = CachedPow::new(rec.clone());
            // A few jobs cached beforehand are skipped.
            for (s, b) in all.iter().step_by(10) {
                pow.pow_hash(s, b);
            }
            let before = rec.calls.load(Ordering::SeqCst);
            for part in all.chunks(chunk) {
                pow.compute_parallel(part, threads);
            }
            let got: Vec<Hash> = all.iter().map(|(s, b)| pow.lookup(s, b).unwrap()).collect();
            assert_eq!(got, want, "threads {threads}, chunk {chunk}");
            assert_eq!(
                rec.calls.load(Ordering::SeqCst) - before,
                all.len() - before,
                "each uncached job once (threads {threads}, chunk {chunk})"
            );
            // A second pass hashes nothing.
            pow.compute_parallel(&all, threads);
            assert_eq!(rec.calls.load(Ordering::SeqCst), all.len());
        }
    }
}

/// One thread hashes on the calling thread: no helper is started, however
/// many chunks (INV-PEN: a spawn per chunk cost 13-130 ms under load). More
/// threads start the helpers once, not per call.
#[test]
fn helpers_are_started_once_and_never_for_one_thread() {
    let rec = Arc::new(Recorder::default());
    let pow = CachedPow::new(rec.clone());
    let all = jobs(600);
    for part in all[..300].chunks(1) {
        pow.compute_parallel(part, 1);
    }
    assert_eq!(pow.pool_threads(), 0, "one thread starts no helper");
    let me = std::thread::current().id();
    assert!(
        rec.threads.lock().unwrap().iter().all(|t| *t == me),
        "one thread hashes inline"
    );
    // A single job to hash also runs inline, whatever `threads`.
    pow.compute_parallel(&all[300..301], 8);
    assert_eq!(pow.pool_threads(), 0, "one job starts no helper");

    for part in all[301..].chunks(4) {
        pow.compute_parallel(part, 4);
    }
    assert_eq!(pow.pool_threads(), 3, "three helpers, started once");
    let distinct: HashSet<ThreadId> = rec.threads.lock().unwrap().iter().copied().collect();
    assert!(
        distinct.len() <= 4,
        "the caller plus three helpers over 75 calls, got {}",
        distinct.len()
    );
}

/// A proof of work whose calls wait (bounded) until `n` threads are inside
/// at once: a batch of `n` jobs then provably runs on `n` threads. It panics
/// on helper threads while `panic_on_helpers` is set.
struct Rendezvous {
    n: AtomicUsize,
    inside: Mutex<(usize, u64)>,
    all_in: Condvar,
    panic_on_helpers: std::sync::atomic::AtomicBool,
    threads: Mutex<HashSet<ThreadId>>,
}

impl Rendezvous {
    fn new(n: usize) -> Self {
        Self {
            n: n.into(),
            inside: Mutex::new((0, 0)),
            all_in: Condvar::new(),
            panic_on_helpers: false.into(),
            threads: Mutex::new(HashSet::new()),
        }
    }
}

impl PowFunction for Rendezvous {
    fn pow_hash(&self, seed: &Hash, blob: &[u8]) -> Hash {
        self.threads
            .lock()
            .unwrap()
            .insert(std::thread::current().id());
        {
            let mut g = self.inside.lock().unwrap();
            let round = g.1;
            g.0 += 1;
            if g.0 >= self.n.load(Ordering::SeqCst) {
                g.0 = 0;
                g.1 += 1;
                self.all_in.notify_all();
            } else {
                let deadline = Instant::now() + Duration::from_secs(30);
                while g.1 == round {
                    let left = deadline.saturating_duration_since(Instant::now());
                    assert!(!left.is_zero(), "the pool's threads never met");
                    g = self.all_in.wait_timeout(g, left).unwrap().0;
                }
            }
        }
        let helper = std::thread::current().name() == Some("pow-helper");
        if helper && self.panic_on_helpers.load(Ordering::SeqCst) {
            panic!("injected PoW panic");
        }
        cheap(seed, blob)
    }
}

/// Counts pool threads that have exited: a thread-local guard each helper
/// creates on its first hash drops when the thread ends.
static EXITED: AtomicUsize = AtomicUsize::new(0);
struct ExitGuard;
impl Drop for ExitGuard {
    fn drop(&mut self) {
        EXITED.fetch_add(1, Ordering::SeqCst);
    }
}
thread_local! {
    static GUARD: std::cell::OnceCell<ExitGuard> = const { std::cell::OnceCell::new() };
}

struct Exiting(Rendezvous);
impl PowFunction for Exiting {
    fn pow_hash(&self, seed: &Hash, blob: &[u8]) -> Hash {
        if std::thread::current().name() == Some("pow-helper") {
            GUARD.with(|g| {
                g.get_or_init(|| ExitGuard);
            });
        }
        self.0.pow_hash(seed, blob)
    }
}

/// A hash that panics on a helper reaches the caller (as a panicking scoped
/// thread did), after the other jobs are done; the helpers survive and serve
/// the next batch; dropping the cache stops and joins every helper.
#[test]
fn a_worker_panic_is_contained_and_shutdown_is_clean() {
    let inner = Arc::new(Exiting(Rendezvous::new(4)));
    let pow = CachedPow::new(inner.clone());
    let all = jobs(12);

    // Warm-up: all four threads take part.
    pow.compute_parallel(&all[0..4], 4);
    assert_eq!(pow.pool_threads(), 3);
    assert_eq!(inner.0.threads.lock().unwrap().len(), 4);

    inner.0.panic_on_helpers.store(true, Ordering::SeqCst);
    let started = Instant::now();
    let r = catch_unwind(AssertUnwindSafe(|| pow.compute_parallel(&all[4..8], 4)));
    let msg = r.expect_err("the helpers' panic reaches the caller");
    assert_eq!(msg.downcast_ref::<&str>(), Some(&"injected PoW panic"));
    assert!(started.elapsed() < Duration::from_secs(30), "no hang");
    // The caller's own job is cached; the panicked ones are not.
    let cached = all[4..8]
        .iter()
        .filter(|(s, b)| pow.lookup(s, b).is_some())
        .count();
    assert_eq!(cached, 1, "only the caller's job");

    // The same three helpers serve the next batch (the rendezvous needs all
    // four threads, so a dead helper would fail it).
    inner.0.panic_on_helpers.store(false, Ordering::SeqCst);
    pow.compute_parallel(&all[8..12], 4);
    assert_eq!(pow.pool_threads(), 3, "no helper replaced");
    assert_eq!(inner.0.threads.lock().unwrap().len(), 4, "the same threads");
    // The three panicked jobs, without the rendezvous.
    inner.0.n.store(1, Ordering::SeqCst);
    pow.compute_parallel(&all[4..8], 4);
    for (s, b) in &all {
        assert_eq!(pow.lookup(s, b), Some(cheap(s, b)));
    }

    // Shutdown: dropping the cache joins every helper, and nothing keeps the
    // PoW function alive.
    let exited = EXITED.load(Ordering::SeqCst);
    let started = Instant::now();
    drop(pow);
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "prompt shutdown"
    );
    assert_eq!(
        EXITED.load(Ordering::SeqCst) - exited,
        3,
        "three helpers ended"
    );
    assert_eq!(
        Arc::strong_count(&inner),
        1,
        "no thread holds the PoW function"
    );
}

/// Real light-mode RandomX: concurrent batches from several callers on one
/// cache, across three keys (cache builds and switches while other threads
/// hash). Every hash equals a fresh light-mode computation, and the cache
/// store's caller rule (never hold a cache while asking for another; a debug
/// assertion in `consensus::pow`, on in this test build) never fires: a
/// violation would panic and be re-raised here.
#[test]
fn real_randomx_concurrent_batches_match_fresh_hashes() {
    use blacksilk_randomx::{Cache, Vm};
    let keys: Vec<Hash> = (0..3u8).map(|i| [0xC0 ^ i; 32]).collect();
    let rx = Arc::new(RandomXPow::new());
    let pow = Arc::new(CachedPow::new(rx));
    let batches: Vec<Vec<PowJob>> = (0..3)
        .map(|c| {
            (0..4u64)
                .map(|i| {
                    let mut b = [0x77; POW_BLOB_SIZE];
                    b[..8].copy_from_slice(&(c * 100 + i).to_le_bytes());
                    (keys[((c + i) % 3) as usize], b)
                })
                .collect()
        })
        .collect();
    std::thread::scope(|s| {
        for (c, batch) in batches.iter().enumerate() {
            let pow = pow.clone();
            s.spawn(move || {
                for part in batch.chunks(2) {
                    pow.compute_parallel(part, 2 + c);
                }
            });
        }
    });
    // One reference cache at a time (256 MiB each).
    for key in &keys {
        let cache = Cache::new(key);
        for (seed, b) in batches.iter().flatten().filter(|(s, _)| s == key) {
            assert_eq!(pow.lookup(seed, b), Some(Vm::light(&cache).hash(b)));
        }
    }
    assert!(pow.pool_threads() <= 3);
}
