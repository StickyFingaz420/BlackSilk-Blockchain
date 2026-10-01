//! RT-POWPOOL red-team stress tests for `CachedPow::compute_parallel`:
//! concurrent callers with panics, the last reference dropped on a caller
//! thread, a panic payload whose own drop panics (finding F1, fixed), and
//! real RandomX under hot-set churn (ignored, see its comment).

use blacksilk_chain::manager::{CachedPow, PowJob};
use blacksilk_consensus::hash::H;
use blacksilk_consensus::{Hash, PowFunction, RandomXPow, HEADER_SIZE};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

fn cheap(seed: &Hash, blob: &[u8]) -> Hash {
    H::new().chain(b"rt").chain(seed).chain(blob).finish()
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Byte 8 of a blob: 0xEE panics, 0xDD sleeps 1 ms.
fn job(i: u64, kind: u8) -> PowJob {
    let mut b = [0x33; HEADER_SIZE];
    b[..8].copy_from_slice(&i.to_le_bytes());
    b[8] = kind;
    ([(i % 5) as u8; 32], b)
}

static CREATED: AtomicUsize = AtomicUsize::new(0);
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
fn note_helper() {
    if std::thread::current().name() == Some("pow-helper") {
        GUARD.with(|g| {
            g.get_or_init(|| {
                CREATED.fetch_add(1, Ordering::SeqCst);
                ExitGuard
            });
        });
    }
}

struct Chaos;
impl PowFunction for Chaos {
    fn pow_hash(&self, seed: &Hash, blob: &[u8]) -> Hash {
        note_helper();
        match blob[8] {
            0xEE => panic!("chaos panic"),
            0xDD => std::thread::sleep(Duration::from_millis(1)),
            _ => {}
        }
        cheap(seed, blob)
    }
}

/// Concurrent callers on one cache, random thread counts (1..=70), random
/// batches overlapping across callers (cached-job path concurrent with the
/// pool), injected panics and sleeps. Every call returns (watchdog), panics
/// iff its batch holds a panicking job, and caches every other job with
/// its exact hash.
#[test]
fn stress_concurrent_callers_with_panics() {
    let rounds: usize = std::env::var("RT_ROUNDS").map_or(300, |s| s.parse().unwrap());
    let pow = Arc::new(CachedPow::new(Arc::new(Chaos)));
    let universe: Vec<PowJob> = (0..4000u64)
        .map(|i| {
            let kind = match i % 97 {
                0 => 0xEE,
                1..=9 => 0xDD,
                _ => 0,
            };
            job(i, kind)
        })
        .collect();
    let universe = Arc::new(universe);
    let (tx, rx) = mpsc::channel::<usize>();
    let callers = 6;
    for c in 0..callers {
        let (pow, universe, tx) = (pow.clone(), universe.clone(), tx.clone());
        std::thread::spawn(move || {
            let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ (c as u64 + 1) * 0x1234_5678);
            for _ in 0..rounds {
                let threads = 1 + rng.below(70) as usize;
                let len = 1 + rng.below(80) as usize;
                let start = rng.below((universe.len() - len) as u64) as usize;
                let batch = &universe[start..start + len];
                let r = catch_unwind(AssertUnwindSafe(|| pow.compute_parallel(batch, threads)));
                let has_panic = batch.iter().any(|(_, b)| b[8] == 0xEE);
                match &r {
                    Err(e) => {
                        assert!(has_panic, "unexpected panic");
                        assert_eq!(e.downcast_ref::<&str>(), Some(&"chaos panic"));
                    }
                    Ok(()) => assert!(!has_panic, "a panicking job did not panic"),
                }
                for (s, b) in batch {
                    let want = if b[8] == 0xEE {
                        None
                    } else {
                        Some(cheap(s, b))
                    };
                    let got = pow.lookup(s, b);
                    if r.is_ok() {
                        assert_eq!(got, want, "lost or wrong result");
                    } else {
                        // Inline (one thread) stops at the panic, as the
                        // old one-thread scoped worker did.
                        assert!(got.is_none() || got == want, "wrong result");
                    }
                }
                assert!(pow.pool_threads() <= 63);
                tx.send(c).unwrap();
            }
        });
    }
    drop(tx);
    let mut done = 0;
    loop {
        match rx.recv_timeout(Duration::from_secs(60)) {
            Ok(_) => done += 1,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => panic!("stall: {done} calls done"),
        }
    }
    assert_eq!(done, callers * rounds, "a caller thread died");
    assert!(pow.pool_threads() <= 63);
}

/// The last `Arc<CachedPow>` dropped on a caller thread right after a
/// parallel call (a header worker outliving its manager), repeatedly, with
/// a second caller on the same cache: every helper ends, promptly.
#[test]
fn drop_on_a_caller_thread_joins_every_helper() {
    let before_c = CREATED.load(Ordering::SeqCst);
    let before_e = EXITED.load(Ordering::SeqCst);
    let mut created_here = 0;
    for r in 0..100u64 {
        let pow = Arc::new(CachedPow::new(Arc::new(Chaos)));
        let jobs: Vec<PowJob> = (0..16).map(|i| job(r * 1000 + i, 0xDD)).collect();
        let (p1, p2) = (pow.clone(), pow.clone());
        drop(pow);
        let (j1, j2) = (jobs.clone(), jobs);
        let a = std::thread::spawn(move || {
            p1.compute_parallel(&j1[..8], 8);
            drop(p1);
        });
        let b = std::thread::spawn(move || {
            p2.compute_parallel(&j2[4..], 8);
            drop(p2);
        });
        a.join().unwrap();
        b.join().unwrap();
        created_here += 7;
    }
    // Helpers that never hashed register no guard; at most 7 per round.
    let created = CREATED.load(Ordering::SeqCst) - before_c;
    let exited = EXITED.load(Ordering::SeqCst) - before_e;
    // Other tests in this binary may run concurrently; compare our deltas
    // only when this is the sole test (`--exact`).
    if std::env::var("RT_EXACT").is_ok() {
        assert!(created <= created_here);
        assert_eq!(created, exited, "a helper outlived its cache");
    }
}

/// A panic payload whose own drop panics (RT-POWPOOL F1): the second
/// payload of a batch was dropped under the progress lock before the
/// completion notification, killing the helper and leaving the caller
/// blocked forever (fails on 283300e). Now the caller returns, and the pool
/// still has its helper.
#[test]
fn second_panic_payload_with_panicking_drop_hangs_the_caller() {
    struct Bomb;
    impl Drop for Bomb {
        fn drop(&mut self) {
            if !std::thread::panicking() {
                panic!("payload drop panics");
            }
        }
    }
    struct Late(AtomicUsize);
    impl PowFunction for Late {
        fn pow_hash(&self, _: &Hash, _: &[u8]) -> Hash {
            // Both threads take one job each, then the helper panics last.
            self.0.fetch_add(1, Ordering::SeqCst);
            let t = std::time::Instant::now();
            while self.0.load(Ordering::SeqCst) < 2 && t.elapsed() < Duration::from_secs(10) {
                std::thread::yield_now();
            }
            if std::thread::current().name() == Some("pow-helper") {
                std::thread::sleep(Duration::from_millis(300));
            }
            std::panic::panic_any(Bomb)
        }
    }
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let pow = CachedPow::new(Arc::new(Late(AtomicUsize::new(0))));
        let jobs = [job(1, 0), job(2, 0)];
        let r = catch_unwind(AssertUnwindSafe(|| pow.compute_parallel(&jobs, 2)));
        // Forget the payload (a Bomb) rather than drop it.
        let panicked = r.is_err();
        if let Err(e) = r {
            std::mem::forget(e);
        }
        let helpers = pow.pool_threads();
        std::mem::forget(pow);
        tx.send((panicked, helpers)).unwrap();
    });
    let (panicked, helpers) = rx
        .recv_timeout(Duration::from_secs(20))
        .expect("compute_parallel never returned");
    assert!(panicked, "the first payload reaches the caller");
    assert_eq!(helpers, 1, "the helper survived");
}

/// Real light-mode RandomX in a debug build (the caller-rule assertion on):
/// two caches (two managers) over one `RandomXPow`, four concurrent callers
/// with 2-16 threads over 7 keys (above MAX_CACHES), and a thread churning
/// the hot set. Every hash equals a fresh computation; no assertion fires.
///
/// Ignored (80-115 s in a debug build, about 1.5 GB). Run it by hand:
/// `cargo test -p blacksilk-chain --test rt_pow_pool_stress -- --ignored stress_real_randomx_two_managers_churn`
/// (`RT_RX_JOBS` sets the jobs per caller, default 24).
#[test]
#[ignore = "real RandomX, 80-115 s debug, about 1.5 GB; run by hand (see the doc comment)"]
fn stress_real_randomx_two_managers_churn() {
    use blacksilk_randomx::{Cache, Vm};
    let n_keys = 7u8;
    let per_caller: u64 = std::env::var("RT_RX_JOBS").map_or(24, |s| s.parse().unwrap());
    let keys: Vec<Hash> = (0..n_keys).map(|i| [0xA0 ^ i; 32]).collect();
    let rx = Arc::new(RandomXPow::new());
    let pows = [
        Arc::new(CachedPow::new(rx.clone())),
        Arc::new(CachedPow::new(rx.clone())),
    ];
    let stop = Arc::new(AtomicBool::new(false));
    let churn = {
        let (rx, keys, stop) = (rx.clone(), keys.clone(), stop.clone());
        std::thread::spawn(move || {
            let mut rng = Rng(77);
            let mut peak = 0;
            while !stop.load(Ordering::SeqCst) {
                let a = keys[rng.below(keys.len() as u64) as usize];
                let b = keys[rng.below(keys.len() as u64) as usize];
                rx.set_hot_seeds(&[a, b]);
                peak = peak.max(rx.alive());
                std::thread::sleep(Duration::from_millis(40));
            }
            peak
        })
    };
    let all: Vec<Vec<PowJob>> = (0..4u64)
        .map(|c| {
            let mut rng = Rng(1000 + c);
            (0..per_caller)
                .map(|i| {
                    let mut b = [0x42; HEADER_SIZE];
                    b[..8].copy_from_slice(&(c * 10_000 + i).to_le_bytes());
                    (keys[rng.below(n_keys as u64) as usize], b)
                })
                .collect()
        })
        .collect();
    std::thread::scope(|s| {
        for (c, batch) in all.iter().enumerate() {
            let pow = pows[c % 2].clone();
            s.spawn(move || {
                let threads = [2, 4, 8, 16][c];
                for part in batch.chunks(threads) {
                    pow.compute_parallel(part, threads);
                }
            });
        }
    });
    stop.store(true, Ordering::SeqCst);
    let peak = churn.join().unwrap();
    assert!(peak <= blacksilk_consensus::pow::MAX_CACHES, "peak {peak}");
    for key in &keys {
        let cache = Cache::new(key);
        let mine: Vec<(usize, &PowJob)> = all
            .iter()
            .enumerate()
            .flat_map(|(c, b)| b.iter().map(move |j| (c, j)))
            .filter(|(_, (s, _))| s == key)
            .collect();
        std::thread::scope(|s| {
            for part in mine.chunks(mine.len().div_ceil(4).max(1)) {
                let (cache, pows) = (&cache, &pows);
                s.spawn(move || {
                    for (c, (seed, b)) in part {
                        assert_eq!(
                            pows[c % 2].lookup(seed, b),
                            Some(Vm::light(cache).hash(b)),
                            "hash differs"
                        );
                    }
                });
            }
        });
    }
}
