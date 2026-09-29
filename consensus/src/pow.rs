//! Proof of work (spec §3): target check, RandomX key schedule, hashing.

use crate::hash::Hash;
use blacksilk_randomx::{Cache, Vm};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::time::Duration;

/// True iff `hash` (256-bit little-endian integer) times `difficulty` is below 2^256.
/// Difficulty 0 is never satisfied.
pub fn check_hash(hash: &Hash, difficulty: u64) -> bool {
    if difficulty == 0 {
        return false;
    }
    // Multiply limb by limb (least significant first); any carry out of the top
    // limb means the product reached 2^256.
    let mut carry: u128 = 0;
    for limb in hash.as_chunks::<8>().0 {
        let v = u64::from_le_bytes(*limb) as u128;
        carry = (v * difficulty as u128 + carry) >> 64;
    }
    carry == 0
}

/// Height of the block whose id is the RandomX key for a block at `height`.
pub fn seed_height(height: u64, epoch: u64, lag: u64) -> u64 {
    debug_assert!(epoch.is_power_of_two());
    if height <= epoch + lag {
        0
    } else {
        (height - lag - 1) & !(epoch - 1)
    }
}

/// The PoW hash function. Production code uses [`RandomXPow`]; the trait exists so
/// that chain-logic tests can run thousands of blocks quickly.
pub trait PowFunction: Send + Sync {
    fn pow_hash(&self, seed: &Hash, header_bytes: &[u8]) -> Hash;

    /// The RandomX keys the chain needs now and next (at most [`HOT_SEEDS`];
    /// `blacksilk_chain::sync_policy::hot_seeds`): their caches are kept built
    /// and never evicted for another key, and a missing one is built in the
    /// background. A hint only: it never changes a hash. The default does
    /// nothing (test doubles keep no caches); a wrapper forwards it.
    fn set_hot_seeds(&self, _seeds: &[Hash]) {}
}

/// Most keys [`PowFunction::set_hot_seeds`] keeps built. The pin window of
/// `blacksilk_chain::sync_policy::hot_seeds` spans fewer blocks than one key
/// epoch, so it holds at most one key switch: at most two keys (dossier 07
/// §3.3).
pub const HOT_SEEDS: usize = 2;

/// Built caches kept for keys outside the hot set: one while a hot set is
/// known (Monero's single secondary cache), two before (the capacity-2 LRU
/// this layer replaced, so a node that never sets a hot set keeps what it
/// had).
const SIDE_CAP_PINNED: usize = 1;
const SIDE_CAP_UNPINNED: usize = 2;

/// How long a build outside the hot set waits between checks of the evicted
/// caches still borrowed (they are released without a notification).
const EVICTED_POLL: Duration = Duration::from_millis(10);

/// Per-key cache store for RandomX (`C` = [`Cache`] in production; tests use
/// cheap stand-ins). A cache is a pure function of its key, so nothing here
/// can change a hash: it decides only what stays built and who waits.
///
/// - A build runs **outside** the store's lock: a caller of another, already
///   built key never waits for it (the seed-switch convoy, F07-1). Callers of
///   the key being built wait for that build, so a key is never built twice
///   at once.
/// - Hot keys ([`SeedCache::set_hot`]) are never evicted, and a build for a
///   hot key waits for nothing but itself.
/// - Keys outside the hot set share one kept slot (two while no hot set is
///   known). At most one of them is built at a time, and none starts while
///   more than one evicted cache is still borrowed by a hashing thread, so
///   the caches alive at once stay bounded however many distinct keys callers
///   ask for.
/// - A build that panics leaves no waiter stuck: its key is released and the
///   next caller builds it again.
pub struct SeedCache<C> {
    build: Box<dyn Fn(&Hash) -> C + Send + Sync>,
    state: Mutex<SeedState<C>>,
    changed: Condvar,
}

struct SeedState<C> {
    /// Built caches, least recently used first.
    resident: Vec<(Hash, Arc<C>)>,
    /// Keys being built.
    building: Vec<Hash>,
    /// How many of `building` started outside the hot set.
    side_building: usize,
    hot: Vec<Hash>,
    /// Evicted caches, alive while a hashing thread still holds them.
    evicted: Vec<Weak<C>>,
    builds: u64,
}

impl<C> SeedState<C> {
    fn side_cap(&self) -> usize {
        if self.hot.is_empty() {
            SIDE_CAP_UNPINNED
        } else {
            SIDE_CAP_PINNED
        }
    }

    fn evicted_alive(&mut self) -> usize {
        self.evicted.retain(|w| w.strong_count() > 0);
        self.evicted.len()
    }

    /// Evicts the least recently used caches outside the hot set beyond the
    /// side capacity. A hot key's cache is never evicted.
    fn trim(&mut self) {
        loop {
            let side: Vec<usize> = (0..self.resident.len())
                .filter(|&i| !self.hot.contains(&self.resident[i].0))
                .collect();
            if side.len() <= self.side_cap() {
                return;
            }
            let (_, cache) = self.resident.remove(side[0]);
            if Arc::strong_count(&cache) > 1 {
                self.evicted.push(Arc::downgrade(&cache));
            }
        }
    }
}

/// Releases a key whose build did not finish (it panicked), so that waiters
/// retry instead of waiting forever.
struct BuildGuard<'a, C> {
    cache: &'a SeedCache<C>,
    seed: Hash,
    side: bool,
    done: bool,
}

impl<C> Drop for BuildGuard<'_, C> {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        let mut st = self.cache.lock();
        st.building.retain(|s| *s != self.seed);
        st.side_building -= usize::from(self.side);
        drop(st);
        self.cache.changed.notify_all();
    }
}

impl<C> SeedCache<C> {
    pub fn new(build: impl Fn(&Hash) -> C + Send + Sync + 'static) -> Self {
        Self {
            build: Box::new(build),
            state: Mutex::new(SeedState {
                resident: Vec::new(),
                building: Vec::new(),
                side_building: 0,
                hot: Vec::new(),
                evicted: Vec::new(),
                builds: 0,
            }),
            changed: Condvar::new(),
        }
    }

    // A build never runs under this lock and never panics while holding it,
    // so a poisoned state is still consistent.
    fn lock(&self) -> MutexGuard<'_, SeedState<C>> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The cache for `seed`, built (outside the lock) if needed.
    pub fn get(&self, seed: &Hash) -> Arc<C> {
        let mut st = self.lock();
        let side = loop {
            if let Some(pos) = st.resident.iter().position(|(s, _)| s == seed) {
                let entry = st.resident.remove(pos);
                let cache = entry.1.clone();
                st.resident.push(entry); // most recently used last
                return cache;
            }
            let side = !st.hot.contains(seed);
            if st.building.contains(seed) || (side && st.side_building > 0) {
                st = self.changed.wait(st).unwrap_or_else(|e| e.into_inner());
                continue;
            }
            if side && st.evicted_alive() > 1 {
                st = self
                    .changed
                    .wait_timeout(st, EVICTED_POLL)
                    .unwrap_or_else(|e| e.into_inner())
                    .0;
                continue;
            }
            break side;
        };
        st.building.push(*seed);
        st.side_building += usize::from(side);
        drop(st);

        let mut guard = BuildGuard {
            cache: self,
            seed: *seed,
            side,
            done: false,
        };
        let cache = Arc::new((self.build)(seed));

        let mut st = self.lock();
        st.building.retain(|s| s != seed);
        st.side_building -= usize::from(side);
        st.builds += 1;
        st.resident.push((*seed, cache.clone()));
        st.trim();
        guard.done = true;
        drop(st);
        self.changed.notify_all();
        cache
    }

    /// Replaces the hot set by `seeds` (the first [`HOT_SEEDS`] distinct
    /// ones). Caches of keys that left it become ordinary, evictable ones.
    /// Returns the hot keys that are neither built nor being built.
    pub fn set_hot(&self, seeds: &[Hash]) -> Vec<Hash> {
        let mut st = self.lock();
        let mut hot = Vec::with_capacity(HOT_SEEDS);
        for s in seeds {
            if hot.len() < HOT_SEEDS && !hot.contains(s) {
                hot.push(*s);
            }
        }
        st.hot = hot;
        st.trim();
        let missing = st
            .hot
            .iter()
            .filter(|s| !st.building.contains(s) && !st.resident.iter().any(|(r, _)| r == *s))
            .copied()
            .collect();
        drop(st);
        // A build outside the hot set may have become a hot one.
        self.changed.notify_all();
        missing
    }

    /// Caches built so far (diagnostics and tests).
    pub fn builds(&self) -> u64 {
        self.lock().builds
    }

    /// Keys whose cache is built and kept, least recently used first.
    pub fn resident(&self) -> Vec<Hash> {
        self.lock().resident.iter().map(|(s, _)| *s).collect()
    }

    /// Whether `seed`'s cache is built and kept.
    pub fn is_resident(&self, seed: &Hash) -> bool {
        self.lock().resident.iter().any(|(s, _)| s == seed)
    }
}

/// RandomX (light mode) keyed by the seed block id, over a [`SeedCache`]:
/// caches are built outside any lock other callers need, the chain's hot keys
/// ([`PowFunction::set_hot_seeds`]) stay built and are prebuilt in the
/// background, and other keys share a bounded side slot.
///
/// The hash is `Vm::light(&Cache::new(seed)).hash(header_bytes)` whatever the
/// cache state (`consensus/tests/seed_cache.rs` compares it with fresh caches
/// across key switches).
pub struct RandomXPow {
    caches: Arc<SeedCache<Cache>>,
}

impl RandomXPow {
    pub fn new() -> Self {
        Self {
            caches: Arc::new(SeedCache::new(|seed: &Hash| Cache::new(seed))),
        }
    }

    /// The cache for `seed`, building it (about 1-3 s, 256 MiB) if needed.
    pub fn cache(&self, seed: &Hash) -> Arc<Cache> {
        self.caches.get(seed)
    }

    /// Builds `seed`'s cache on a background thread, unless it is built or
    /// being built, so that no caller waits for it later. Where no thread can
    /// be started, the cache is built on first use instead.
    pub fn prebuild(&self, seed: &Hash) {
        let (caches, seed) = (self.caches.clone(), *seed);
        let spawned = std::thread::Builder::new()
            .name("randomx-prebuild".into())
            .spawn(move || drop(caches.get(&seed)));
        // Detached: the thread ends with its build.
        drop(spawned);
    }

    /// Caches built so far.
    pub fn builds(&self) -> u64 {
        self.caches.builds()
    }

    /// Keys whose cache is built and kept, least recently used first.
    pub fn resident(&self) -> Vec<Hash> {
        self.caches.resident()
    }

    /// Whether `seed`'s cache is built and kept.
    pub fn is_resident(&self, seed: &Hash) -> bool {
        self.caches.is_resident(seed)
    }
}

impl Default for RandomXPow {
    fn default() -> Self {
        Self::new()
    }
}

impl PowFunction for RandomXPow {
    fn pow_hash(&self, seed: &Hash, header_bytes: &[u8]) -> Hash {
        let cache = self.cache(seed);
        Vm::light(&cache).hash(header_bytes)
    }

    fn set_hot_seeds(&self, seeds: &[Hash]) {
        for seed in self.caches.set_hot(seeds) {
            self.prebuild(&seed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_from_u256_le(limbs: [u64; 4]) -> Hash {
        let mut h = [0u8; 32];
        for (i, l) in limbs.iter().enumerate() {
            h[8 * i..8 * i + 8].copy_from_slice(&l.to_le_bytes());
        }
        h
    }

    #[test]
    fn check_hash_boundaries() {
        let max = [0xFF; 32];
        assert!(check_hash(&max, 1), "difficulty 1 accepts everything");
        assert!(!check_hash(&max, 2));
        assert!(!check_hash(&[0; 32], 0), "difficulty 0 is invalid");
        assert!(check_hash(&[0; 32], u64::MAX));

        // h = 2^255 - 1: h*2 = 2^256 - 2 < 2^256 -> valid; h = 2^255: h*2 = 2^256 -> invalid.
        let below = hash_from_u256_le([u64::MAX, u64::MAX, u64::MAX, u64::MAX >> 1]);
        let at = hash_from_u256_le([0, 0, 0, 1 << 63]);
        assert!(check_hash(&below, 2));
        assert!(!check_hash(&at, 2));

        // Little-endian: a large low byte is harmless, a large top byte is not.
        let mut low = [0u8; 32];
        low[0] = 0xFF;
        assert!(check_hash(&low, 1 << 40));
        let mut high = [0u8; 32];
        high[31] = 0x01;
        assert!(check_hash(&high, 255) && !check_hash(&high, 256));
    }

    // ------------------------------------------------ SeedCache (07 W1, T1-T4)

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;

    /// How long a test waits for a call that must return. The stand-in
    /// caches build instantly, so this is only ever reached by a bug (or a
    /// mutant that loses a wake-up), which then fails the test instead of
    /// hanging it (RT-MUT).
    const BOUND: Duration = Duration::from_secs(10);

    /// A stand-in cache that counts the instances alive.
    struct Fake {
        live: Arc<AtomicUsize>,
    }

    impl Drop for Fake {
        fn drop(&mut self) {
            self.live.fetch_sub(1, Ordering::SeqCst);
        }
    }

    fn fake_cache() -> (Arc<SeedCache<Fake>>, Arc<AtomicUsize>) {
        let live = Arc::new(AtomicUsize::new(0));
        let l = live.clone();
        let cache = SeedCache::new(move |_: &Hash| {
            l.fetch_add(1, Ordering::SeqCst);
            Fake { live: l.clone() }
        });
        (Arc::new(cache), live)
    }

    fn key(i: u64) -> Hash {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&i.to_le_bytes());
        h
    }

    /// `cache.get(seed)` on a helper thread, as a receiver of its result.
    fn ask<C: Send + Sync + 'static>(
        cache: &Arc<SeedCache<C>>,
        seed: &Hash,
    ) -> mpsc::Receiver<Arc<C>> {
        let (done, done_rx) = mpsc::channel();
        let (cache, seed) = (cache.clone(), *seed);
        std::thread::spawn(move || {
            let _ = done.send(cache.get(&seed));
        });
        done_rx
    }

    /// `cache.get(seed)`, failing the test unless it returns within [`BOUND`].
    fn get<C: Send + Sync + 'static>(cache: &Arc<SeedCache<C>>, seed: &Hash) -> Arc<C> {
        ask(cache, seed)
            .recv_timeout(BOUND)
            .unwrap_or_else(|e| panic!("get did not return within {BOUND:?}: {e}"))
    }

    /// T1: a hot key is built once and never evicted, however many other
    /// keys are asked for; other keys share one slot.
    #[test]
    fn a_hot_key_is_never_evicted_for_other_keys() {
        let (cache, live) = fake_cache();
        let (a, b) = (key(1), key(2));
        assert_eq!(cache.set_hot(&[a, b, key(3)]), vec![a, b], "two hot keys");
        let _ = get(&cache, &a);
        let _ = get(&cache, &b);
        // Built hot keys are not reported missing (W4-MUT: `&&` to `||`).
        assert_eq!(cache.set_hot(&[a, b]), Vec::<Hash>::new(), "both built");
        for i in 100..200 {
            let _ = get(&cache, &key(i));
            assert!(cache.is_resident(&a) && cache.is_resident(&b));
            assert!(cache.resident().len() <= HOT_SEEDS + SIDE_CAP_PINNED);
        }
        let _ = get(&cache, &a);
        assert_eq!(cache.builds(), 2 + 100, "the hot keys were built once");
        assert_eq!(live.load(Ordering::SeqCst), 3);
        // A key that leaves the hot set becomes evictable.
        cache.set_hot(&[b]);
        let _ = get(&cache, &key(500));
        assert!(!cache.is_resident(&a) && cache.is_resident(&b));
        assert_eq!(live.load(Ordering::SeqCst), 2);
    }

    /// Without a hot set, the store keeps the two most recently used keys
    /// (what `RandomXPow` kept before the hot set existed).
    #[test]
    fn without_a_hot_set_the_two_most_recent_keys_stay() {
        let (cache, live) = fake_cache();
        for i in 0..5 {
            let _ = get(&cache, &key(i));
        }
        let _ = get(&cache, &key(3));
        assert_eq!(cache.resident(), vec![key(4), key(3)]);
        assert_eq!(cache.builds(), 5);
        assert_eq!(live.load(Ordering::SeqCst), 2);
        // Nothing was borrowed when evicted, so nothing is tracked, and no
        // key is left marked as being built (W4-MUT: `trim`'s `> 1` to
        // `>= 1`, and `get`'s `retain` with `!=` to `==`).
        {
            let st = cache.lock();
            assert!(st.evicted.is_empty(), "no evicted cache was borrowed");
            assert!(st.building.is_empty(), "no build in progress");
            assert_eq!(st.side_building, 0);
        }
        // An evicted key is built again when asked for.
        let _ = get(&cache, &key(0));
        assert_eq!(cache.builds(), 6);
        assert_eq!(cache.resident(), vec![key(3), key(0)]);
    }

    /// A hashing thread that still holds one evicted cache can build
    /// another key; two borrowed evicted caches hold every build back until
    /// one is released (the bound of T3, here without a race). W4-MUT:
    /// `get`'s `evicted_alive() > 1` mutated to `>= 1` or `== 1` survived.
    /// Every wait is bounded, so that a mutant fails instead of hanging; the
    /// one negative wait can only let a mutant through, never fail the rule.
    #[test]
    fn one_borrowed_evicted_cache_does_not_block_a_build_but_two_do() {
        let (cache, live) = fake_cache();
        let held1 = get(&cache, &key(1));
        let held2 = get(&cache, &key(2));
        let _ = get(&cache, &key(3)); // evicts key 1, still borrowed
        assert_eq!(cache.lock().evicted_alive(), 1);
        ask(&cache, &key(4))
            .recv_timeout(BOUND)
            .expect("one borrowed evicted cache does not block a build");
        // Key 4 evicted key 2, still borrowed: two are alive now.
        assert_eq!(cache.lock().evicted_alive(), 2);
        let builds = cache.builds();
        let waiting = ask(&cache, &key(5));
        assert!(
            waiting.recv_timeout(Duration::from_millis(300)).is_err(),
            "a build started while two evicted caches were borrowed"
        );
        assert_eq!(cache.builds(), builds);
        drop(held1);
        waiting
            .recv_timeout(BOUND)
            .expect("the build proceeds once one is released");
        drop(held2);
        assert_eq!(cache.builds(), builds + 1);
        assert_eq!(live.load(Ordering::SeqCst), 2);
    }

    /// T2: a caller of a built key, or of a hot key, does not wait for the
    /// build of another key (the build is held open on a channel: no timing).
    #[test]
    fn a_build_blocks_only_callers_of_its_own_key() {
        let (release, gate) = mpsc::channel::<()>();
        let gate = Mutex::new(gate);
        let slow = key(9);
        let cache = Arc::new(SeedCache::new(move |s: &Hash| {
            if *s == slow {
                let _ = gate.lock().unwrap().recv_timeout(BOUND);
            }
            *s
        }));
        let built = key(1);
        let _ = get(&cache, &built);
        let hot = key(2);
        cache.set_hot(&[hot]);
        let slow_caller = ask(&cache, &slow);
        let deadline = std::time::Instant::now() + BOUND;
        while !cache.lock().building.contains(&slow) {
            assert!(
                std::time::Instant::now() < deadline,
                "the slow build never started"
            );
            std::thread::yield_now();
        }
        assert_eq!(*get(&cache, &built), built, "built key: no wait");
        assert_eq!(*get(&cache, &hot), hot, "hot key: built without waiting");
        release.send(()).unwrap();
        let got = slow_caller
            .recv_timeout(BOUND)
            .expect("the slow build finishes");
        assert_eq!(*got, slow);
    }

    /// T3: 32 threads asking for 200 distinct keys each never hold more than
    /// four caches alive at once, and two once idle. A side build starts only
    /// while at most one evicted cache is still borrowed and no other side
    /// build runs, with at most two kept: 2 kept + 1 evicted and borrowed +
    /// 1 being built. (A build that then evicts a borrowed cache moves one
    /// from kept to evicted, and the count stays 4.)
    #[test]
    fn the_caches_alive_stay_bounded_under_many_keys() {
        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        // A cache whose last `Arc` is released is already gone for the store
        // (its weak count reads zero) while its destructor, which decrements
        // `live`, has not run yet. Unguarded, a build that starts in that
        // window counts it, and a preempted destructor made this test flaky
        // under load (peak 6 in 12 of 200 runs, W4-MUT). So hashing threads
        // release under the read side of `gate`, and a build counts itself
        // under the write side: the peak counts exactly the caches the store
        // keeps or lends out, plus the one being built.
        let gate = Arc::new(std::sync::RwLock::new(()));
        let (l, p, g) = (live.clone(), peak.clone(), gate.clone());
        let cache = Arc::new(SeedCache::new(move |_: &Hash| {
            let _counting = g.write().unwrap_or_else(|e| e.into_inner());
            let now = l.fetch_add(1, Ordering::SeqCst) + 1;
            p.fetch_max(now, Ordering::SeqCst);
            Fake { live: l.clone() }
        }));
        // Detached threads and one deadline for all of them, so that a lost
        // wake-up fails the test instead of hanging it.
        let (done, done_rx) = mpsc::channel();
        for t in 0..32u64 {
            let (cache, gate, done) = (cache.clone(), gate.clone(), done.clone());
            std::thread::spawn(move || {
                for i in 0..200u64 {
                    // Hold the cache for a moment, as a hash does.
                    let c = cache.get(&key(t * 1000 + i % 50));
                    std::thread::yield_now();
                    let _releasing = gate.read().unwrap_or_else(|e| e.into_inner());
                    drop(c);
                }
                let _ = done.send(());
            });
        }
        let deadline = std::time::Instant::now() + 6 * BOUND;
        for n in 0..32 {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            done_rx
                .recv_timeout(left)
                .unwrap_or_else(|_| panic!("only {n} of 32 threads finished in time"));
        }
        let peak = peak.load(Ordering::SeqCst);
        assert!(peak <= 4, "peak {peak} caches alive");
        assert_eq!(live.load(Ordering::SeqCst), 2, "idle: the side slots");
    }

    /// T4: a build that panics releases its key: the waiters and the next
    /// caller build it again.
    #[test]
    fn a_panicking_build_leaves_no_waiter_stuck() {
        let fail = Arc::new(AtomicUsize::new(1));
        let f = fail.clone();
        let cache = Arc::new(SeedCache::new(move |s: &Hash| {
            if f.fetch_sub(1, Ordering::SeqCst) == 1 {
                panic!("injected build failure");
            }
            *s
        }));
        let k = key(4);
        assert!(
            matches!(
                ask(&cache, &k).recv_timeout(BOUND),
                Err(mpsc::RecvTimeoutError::Disconnected)
            ),
            "the first build panicked (and did not hang)"
        );
        assert_eq!(*get(&cache, &k), k, "retried");
        let _ = get(&cache, &key(5));
        assert_eq!(cache.builds(), 2);
    }

    #[test]
    fn seed_schedule_matches_monero() {
        let s = |h| seed_height(h, 2048, 64);
        assert_eq!(s(0), 0);
        assert_eq!(s(2112), 0); // E + L
        assert_eq!(s(2113), 2048);
        assert_eq!(s(4160), 2048);
        assert_eq!(s(4161), 4096);
        assert_eq!(s(1_000_000), (1_000_000 - 65) & !2047);
        // The key is always at least L+1 blocks old and changes once per epoch.
        for h in 2113..20_000u64 {
            assert!(h - s(h) > 64);
            assert_eq!(s(h) % 2048, 0);
        }
    }

    /// Every key schedule `ChainParams::check` accepts (epoch a power of two,
    /// `1 ≤ lag < epoch`), small enough to enumerate, against the spec formula
    /// in wide arithmetic: 0 up to `E + L`, then `(h − L − 1)` rounded down to
    /// a multiple of `E`. Lags above `E/2` reach the first branch's edge:
    /// W4-MUT's surviving `E + L → E − L` only differs there.
    #[test]
    fn seed_schedule_matches_the_spec_for_every_valid_small_schedule() {
        for epoch in [2u64, 4, 8, 16] {
            for lag in 1..epoch {
                for h in 0..8 * epoch {
                    let (hh, e, l) = (h as u128, epoch as u128, lag as u128);
                    let want = if hh <= e + l { 0 } else { (hh - l - 1) / e * e };
                    assert_eq!(
                        seed_height(h, epoch, lag) as u128,
                        want,
                        "E {epoch} L {lag} h {h}"
                    );
                }
            }
        }
    }
}
