//! Proof of work (spec §3): target check, RandomX key schedule, hashing.

use crate::hash::Hash;
use blacksilk_randomx::{Cache, Vm};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
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

/// The most cache instances a [`SeedCache`] ever has in memory at once:
/// kept, being built, evicted but still borrowed by a hashing thread, or
/// being freed. With RandomX that is 5 × 256 MiB = 1.25 GiB (RT-MUT).
///
/// The value is what the steady state with a hot set needs without waiting:
/// the two hot keys ([`HOT_SEEDS`]), the one kept side key
/// ([`SIDE_CAP_PINNED`]), one side build, and one evicted cache still being
/// hashed with. Without a hot set the side rules alone stay within 4 (two kept,
/// one build, one evicted and borrowed).
///
/// Every build, hot or not, is admitted only below the bound, so it holds
/// whatever the callers do: hot builds, hot-set churn that turns borrowed hot
/// caches into evicted ones, and any number of hashing threads.
pub const MAX_CACHES: usize = HOT_SEEDS + SIDE_CAP_PINNED + 2;

/// How long a build waiting for room checks again: caches are released by
/// hashing threads without a notification.
const ROOM_POLL: Duration = Duration::from_millis(10);

/// Counts one cache instance from the moment its build is admitted until its
/// memory has been freed.
struct Ticket(Arc<AtomicUsize>);

impl Ticket {
    fn take(alive: &Arc<AtomicUsize>) -> Self {
        alive.fetch_add(1, Ordering::SeqCst);
        Ticket(alive.clone())
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A cache built by a [`SeedCache`]. It dereferences to the cache. Its
/// fields drop in order, so the instance count falls only once the cache's
/// own memory is freed: the bound [`MAX_CACHES`] counts memory, not handles.
pub struct Cached<C> {
    cache: C,
    _ticket: Ticket,
}

impl<C> std::ops::Deref for Cached<C> {
    type Target = C;
    fn deref(&self) -> &C {
        &self.cache
    }
}

/// Per-key cache store for RandomX (`C` = [`Cache`] in production; tests use
/// cheap stand-ins). A cache is a pure function of its key, so nothing here
/// can change a hash: it decides only what stays built and who waits.
///
/// - A build runs **outside** the store's lock: a caller of another, already
///   built key never waits for it (the seed-switch convoy, F07-1). Callers of
///   the key being built wait for that build, so a key is never built twice
///   at once.
/// - Hot keys ([`SeedCache::set_hot`]) are never evicted, and a build for a
///   hot key waits for nothing but room under the bound.
/// - Keys outside the hot set share one kept slot (two while no hot set is
///   known). At most one of them is built at a time, none starts while more
///   than one evicted cache is still in memory, and none takes the room a
///   missing hot key needs.
/// - **The bound** ([`MAX_CACHES`]): no build starts while `MAX_CACHES`
///   instances are in memory. A build that waits for room first evicts idle
///   side caches (no hashing thread holds them), least recently used first;
///   otherwise it waits for a hashing thread to release one. Liveness: at
///   most [`HOT_SEEDS`] instances belong to hot keys (each is kept or being
///   built), a build always finishes, and a hashing thread releases its cache
///   when its hash is done, so a waiting build always gets room. This needs
///   one rule of every caller: **never hold a cache while asking for
///   another** (`pow_hash` and the prebuild threads hold one at a time).
/// - A build that panics leaves no waiter stuck: its key and its room are
///   released and the next caller builds it again.
/// - Caches leave the store's lock before they are freed: a free (256 MiB)
///   never runs while other callers wait for the lock.
pub struct SeedCache<C> {
    build: Box<dyn Fn(&Hash) -> C + Send + Sync>,
    state: Mutex<SeedState<C>>,
    changed: Condvar,
    /// Instances in memory ([`Ticket`]); decremented without the lock.
    alive: Arc<AtomicUsize>,
}

struct SeedState<C> {
    /// Built caches, least recently used first.
    resident: Vec<(Hash, Arc<Cached<C>>)>,
    /// Keys being built.
    building: Vec<Hash>,
    /// How many of `building` started outside the hot set.
    side_building: usize,
    hot: Vec<Hash>,
    /// Hot keys with a prebuild thread that has not finished yet.
    prebuilding: Vec<Hash>,
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

    /// Instances neither kept nor being built: evicted caches still borrowed
    /// or being freed. `alive` only falls outside the lock, so under the
    /// lock this never undercounts.
    fn evicted(&self, alive: usize) -> usize {
        alive.saturating_sub(self.resident.len() + self.building.len())
    }

    /// Hot keys neither kept nor being built, other than `except`.
    fn missing_hot(&self, except: &Hash) -> usize {
        self.hot
            .iter()
            .filter(|h| {
                *h != except
                    && !self.building.contains(h)
                    && !self.resident.iter().any(|(r, _)| r == *h)
            })
            .count()
    }

    /// Takes out the least recently used caches outside the hot set beyond
    /// the side capacity, for the caller to drop after the lock. A hot key's
    /// cache is never evicted.
    fn trim(&mut self) -> Vec<Arc<Cached<C>>> {
        let mut out = Vec::new();
        loop {
            let side: Vec<usize> = (0..self.resident.len())
                .filter(|&i| !self.hot.contains(&self.resident[i].0))
                .collect();
            if side.len() <= self.side_cap() {
                return out;
            }
            out.push(self.resident.remove(side[0]).1);
        }
    }

    /// Takes out the least recently used side cache that no hashing thread
    /// holds, if any: evicting it frees room at once.
    fn take_idle_side(&mut self) -> Option<Arc<Cached<C>>> {
        let i = (0..self.resident.len()).find(|&i| {
            !self.hot.contains(&self.resident[i].0) && Arc::strong_count(&self.resident[i].1) == 1
        })?;
        Some(self.resident.remove(i).1)
    }
}

/// Releases a key whose build did not finish (it panicked), so that waiters
/// retry instead of waiting forever. Its room is released by its [`Ticket`].
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
                prebuilding: Vec::new(),
                builds: 0,
            }),
            changed: Condvar::new(),
            alive: Arc::new(AtomicUsize::new(0)),
        }
    }

    // A build never runs under this lock and never panics while holding it,
    // so a poisoned state is still consistent.
    fn lock(&self) -> MutexGuard<'_, SeedState<C>> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The cache for `seed`, built (outside the lock) if needed.
    pub fn get(&self, seed: &Hash) -> Arc<Cached<C>> {
        self.fetch(seed, false)
            .expect("an unconditional get always returns a cache")
    }

    /// As [`Self::get`]; with `only_hot`, gives up (`None`) as soon as `seed`
    /// is not a hot key (a prebuild whose key left the hot set).
    fn fetch(&self, seed: &Hash, only_hot: bool) -> Option<Arc<Cached<C>>> {
        let mut st = self.lock();
        let side = loop {
            if let Some(pos) = st.resident.iter().position(|(s, _)| s == seed) {
                let entry = st.resident.remove(pos);
                let cache = entry.1.clone();
                st.resident.push(entry); // most recently used last
                return Some(cache);
            }
            let side = !st.hot.contains(seed);
            if only_hot && side {
                return None;
            }
            if st.building.contains(seed) || (side && st.side_building > 0) {
                st = self.changed.wait(st).unwrap_or_else(|e| e.into_inner());
                continue;
            }
            let alive = self.alive.load(Ordering::SeqCst);
            // A side build leaves room for every missing hot key.
            let reserve = if side { st.missing_hot(seed) } else { 0 };
            let under_bound = alive + 1 + reserve <= MAX_CACHES;
            let few_evicted = !side || st.evicted(alive) <= 1;
            if under_bound && few_evicted {
                break side;
            }
            if !under_bound {
                if let Some(idle) = st.take_idle_side() {
                    drop(st);
                    drop(idle); // freed outside the lock
                    st = self.lock();
                    continue;
                }
            }
            st = self
                .changed
                .wait_timeout(st, ROOM_POLL)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        };
        st.building.push(*seed);
        st.side_building += usize::from(side);
        let ticket = Ticket::take(&self.alive);
        drop(st);

        let mut guard = BuildGuard {
            cache: self,
            seed: *seed,
            side,
            done: false,
        };
        let cache = Arc::new(Cached {
            cache: (self.build)(seed),
            _ticket: ticket,
        });

        let mut st = self.lock();
        st.building.retain(|s| s != seed);
        st.side_building -= usize::from(side);
        st.builds += 1;
        st.resident.push((*seed, cache.clone()));
        let trimmed = st.trim();
        guard.done = true;
        drop(st);
        drop(trimmed); // freed outside the lock
        self.changed.notify_all();
        Some(cache)
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
        let trimmed = st.trim();
        let missing = st
            .hot
            .iter()
            .filter(|s| !st.building.contains(s) && !st.resident.iter().any(|(r, _)| r == *s))
            .copied()
            .collect();
        drop(st);
        // Freed outside the lock.
        drop(trimmed);
        // A build outside the hot set may have become a hot one, and a
        // prebuild whose key left the set gives up.
        self.changed.notify_all();
        missing
    }

    /// Caches built so far (diagnostics and tests).
    pub fn builds(&self) -> u64 {
        self.lock().builds
    }

    /// Cache instances in memory now: kept, being built, evicted but still
    /// borrowed, or being freed. Never above [`MAX_CACHES`].
    pub fn alive(&self) -> usize {
        self.alive.load(Ordering::SeqCst)
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

impl<C: Send + Sync + 'static> SeedCache<C> {
    /// Builds hot key `seed`'s cache on a background thread, unless it is
    /// built, being built, or already has a prebuild thread: at most one
    /// thread per hot key. The thread gives up if the key leaves the hot set
    /// before its build starts. Where no thread can be started, the cache is
    /// built on first use instead.
    pub fn prebuild(self: &Arc<Self>, seed: &Hash) {
        {
            let mut st = self.lock();
            if !st.hot.contains(seed)
                || st.prebuilding.contains(seed)
                || st.building.contains(seed)
                || st.resident.iter().any(|(r, _)| r == seed)
            {
                return;
            }
            st.prebuilding.push(*seed);
        }
        /// Clears the key's prebuild mark when the thread ends, even if its
        /// build panicked.
        struct Pending<C>(Arc<SeedCache<C>>, Hash);
        impl<C> Drop for Pending<C> {
            fn drop(&mut self) {
                self.0.lock().prebuilding.retain(|s| *s != self.1);
            }
        }
        let pending = Pending(self.clone(), *seed);
        let spawned = std::thread::Builder::new()
            .name("randomx-prebuild".into())
            .spawn(move || drop(pending.0.fetch(&pending.1, true)));
        // Detached: the thread ends with its build, or when its key leaves
        // the hot set. If no thread could be started, the closure and its
        // `Pending` are dropped, which clears the mark: the cache is built
        // on first use instead.
        drop(spawned);
    }
}

/// RandomX (light mode) keyed by the seed block id, over a [`SeedCache`]:
/// caches are built outside any lock other callers need, the chain's hot keys
/// ([`PowFunction::set_hot_seeds`]) stay built and are prebuilt in the
/// background, other keys share a bounded side slot, and at most
/// [`MAX_CACHES`] caches are ever in memory.
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
    /// Do not hold it while asking for another ([`SeedCache`]'s bound).
    pub fn cache(&self, seed: &Hash) -> Arc<Cached<Cache>> {
        self.caches.get(seed)
    }

    /// Builds hot key `seed`'s cache on a background thread
    /// ([`SeedCache::prebuild`]).
    pub fn prebuild(&self, seed: &Hash) {
        self.caches.prebuild(seed);
    }

    /// Caches built so far.
    pub fn builds(&self) -> u64 {
        self.caches.builds()
    }

    /// Cache instances in memory now (at most [`MAX_CACHES`]).
    pub fn alive(&self) -> usize {
        self.caches.alive()
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
    ) -> mpsc::Receiver<Arc<Cached<C>>> {
        let (done, done_rx) = mpsc::channel();
        let (cache, seed) = (cache.clone(), *seed);
        std::thread::spawn(move || {
            let _ = done.send(cache.get(&seed));
        });
        done_rx
    }

    /// `cache.get(seed)`, failing the test unless it returns within [`BOUND`].
    fn get<C: Send + Sync + 'static>(cache: &Arc<SeedCache<C>>, seed: &Hash) -> Arc<Cached<C>> {
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
            assert_eq!(cache.alive(), 2, "only the two kept caches are in memory");
            assert_eq!(
                st.evicted(cache.alive()),
                0,
                "no evicted cache was borrowed"
            );
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
        assert_eq!(cache.lock().evicted(cache.alive()), 1);
        ask(&cache, &key(4))
            .recv_timeout(BOUND)
            .expect("one borrowed evicted cache does not block a build");
        // Key 4 evicted key 2, still borrowed: two are alive now.
        assert_eq!(cache.lock().evicted(cache.alive()), 2);
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
        assert_eq!(**get(&cache, &built), built, "built key: no wait");
        assert_eq!(**get(&cache, &hot), hot, "hot key: built without waiting");
        release.send(()).unwrap();
        let got = slow_caller
            .recv_timeout(BOUND)
            .expect("the slow build finishes");
        assert_eq!(**got, slow);
    }

    /// T3: 32 threads asking for 200 distinct keys each never hold more than
    /// four caches alive at once, and two once idle. A side build starts only
    /// while at most one evicted cache is still in memory and no other side
    /// build runs, with at most two kept: 2 kept + 1 evicted and borrowed +
    /// 1 being built. (A build that then evicts a borrowed cache moves one
    /// from kept to evicted, and the count stays 4.)
    ///
    /// The store counts an instance until its memory is freed ([`Cached`]'s
    /// ticket drops after the cache), and `Fake` decrements `live` in its own
    /// destructor, before that. So `live` never exceeds the store's count and
    /// needs no gate: before the ticket, a cache whose last `Arc` was dropped
    /// but whose destructor had not run yet was invisible to the store, and
    /// this test failed under load (peak 6 in 12 of 200 runs, W4-MUT).
    #[test]
    fn the_caches_alive_stay_bounded_under_many_keys() {
        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let (l, p) = (live.clone(), peak.clone());
        let cache = Arc::new(SeedCache::new(move |_: &Hash| {
            let now = l.fetch_add(1, Ordering::SeqCst) + 1;
            p.fetch_max(now, Ordering::SeqCst);
            Fake { live: l.clone() }
        }));
        // Detached threads and one deadline for all of them, so that a lost
        // wake-up fails the test instead of hanging it.
        let (done, done_rx) = mpsc::channel();
        for t in 0..32u64 {
            let (cache, done) = (cache.clone(), done.clone());
            std::thread::spawn(move || {
                for i in 0..200u64 {
                    // Hold the cache for a moment, as a hash does.
                    let c = cache.get(&key(t * 1000 + i % 50));
                    std::thread::yield_now();
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
        assert_eq!(cache.alive(), 2, "the store counts the same two");
    }

    /// A stand-in store that also records the most instances ever alive
    /// (counted in the build, as `live` + 1).
    fn peak_cache() -> (Arc<SeedCache<Fake>>, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let (l, p) = (live.clone(), peak.clone());
        let cache = SeedCache::new(move |_: &Hash| {
            let now = l.fetch_add(1, Ordering::SeqCst) + 1;
            p.fetch_max(now, Ordering::SeqCst);
            Fake { live: l.clone() }
        });
        (Arc::new(cache), live, peak)
    }

    /// RT-MUT: hot-set churn with borrowed caches. Two changes of the hot set
    /// while every old hot cache is still borrowed leave three evicted caches
    /// in memory (the pre-bound store then kept building: every hot build
    /// skipped the evicted wait). The bound holds throughout:
    /// - a hot build at the bound evicts an idle side cache instead of
    ///   waiting;
    /// - with no idle cache left, a side build waits until hashing threads
    ///   release enough, then proceeds;
    /// - no wait is unbounded.
    #[test]
    fn hot_set_churn_with_borrowed_caches_stays_within_the_bound() {
        let (cache, live, peak) = peak_cache();
        let k = |i: u64| key(1000 + i);
        cache.set_hot(&[k(1), k(2)]);
        let (e1, e2) = (get(&cache, &k(1)), get(&cache, &k(2)));
        cache.set_hot(&[k(3), k(4)]); // k1 evicted (borrowed), k2 kept as side
        let (e3, e4) = (get(&cache, &k(3)), get(&cache, &k(4)));
        assert_eq!(cache.alive(), 4);
        cache.set_hot(&[k(5), k(6)]); // k2, k3 evicted (borrowed), k4 kept
        assert_eq!(cache.resident(), vec![k(4)]);
        assert_eq!(
            cache.lock().evicted(cache.alive()),
            3,
            "three borrowed evicted"
        );
        drop(e4); // the kept side cache is idle now
        let h5 = get(&cache, &k(5));
        assert_eq!(cache.alive(), MAX_CACHES, "at the bound");
        // A hot build at the bound: the idle side cache k4 makes room.
        let _h6 = get(&cache, &k(6));
        assert!(!cache.is_resident(&k(4)), "the idle side cache was evicted");
        assert_eq!(cache.alive(), MAX_CACHES);
        // A side build at the bound, with no idle cache to evict, waits for
        // the hashing threads (here: this test) to release.
        // Hot key k5 is idle now, but a hot cache is never evicted to make
        // room (W4-MUT: `take_idle_side`'s `&&` mutated to `||` survived).
        drop(h5);
        let builds = cache.builds();
        let waiting = ask(&cache, &k(7));
        assert!(
            waiting.recv_timeout(Duration::from_millis(300)).is_err(),
            "a build started at the bound"
        );
        assert_eq!(cache.builds(), builds);
        assert!(cache.is_resident(&k(5)), "an idle hot cache was evicted");
        drop(e1);
        drop(e2); // one evicted cache left in memory: a side build may start
        let _s7 = waiting
            .recv_timeout(BOUND)
            .expect("the side build proceeds");
        assert_eq!(cache.builds(), builds + 1);
        drop(e3);
        let peak = peak.load(Ordering::SeqCst);
        assert!(peak <= MAX_CACHES, "peak {peak}");
        assert!(cache.alive() <= MAX_CACHES);
        assert_eq!(cache.alive(), live.load(Ordering::SeqCst));
    }

    /// RT-MUT: no caller deadlocks when the bound is reached. 16 hashing
    /// threads ask for keys from a small set (each cache held for a moment,
    /// as a hash does, one at a time) while another thread changes the hot
    /// set 200 times and prebuilds it. Every thread finishes within the
    /// deadline, and the instances in memory never exceed [`MAX_CACHES`].
    #[test]
    fn no_caller_deadlocks_at_the_bound_under_hot_set_churn() {
        let (cache, live, peak) = peak_cache();
        let (done, done_rx) = mpsc::channel();
        for t in 0..16u64 {
            let (cache, done) = (cache.clone(), done.clone());
            std::thread::spawn(move || {
                let mut x = t.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
                for _ in 0..300 {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    let c = cache.get(&key(x % 12));
                    std::thread::yield_now();
                    drop(c);
                }
                let _ = done.send(());
            });
        }
        {
            let (cache, done) = (cache.clone(), done.clone());
            std::thread::spawn(move || {
                for i in 0..200u64 {
                    let hot = [key(i % 12), key((i * 5 + 1) % 12)];
                    for s in cache.set_hot(&hot) {
                        cache.prebuild(&s);
                    }
                    std::thread::yield_now();
                }
                let _ = done.send(());
            });
        }
        let deadline = std::time::Instant::now() + 6 * BOUND;
        for n in 0..17 {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            done_rx
                .recv_timeout(left)
                .unwrap_or_else(|_| panic!("only {n} of 17 threads finished in time"));
        }
        // Prebuild threads may still be finishing: they end with their build
        // or when their key leaves the hot set.
        let settle = std::time::Instant::now() + BOUND;
        while !cache.lock().prebuilding.is_empty() {
            assert!(
                std::time::Instant::now() < settle,
                "a prebuild thread is stuck"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        let peak = peak.load(Ordering::SeqCst);
        assert!(peak <= MAX_CACHES, "peak {peak} caches alive");
        assert!(cache.alive() <= MAX_CACHES);
        assert_eq!(cache.alive(), live.load(Ordering::SeqCst));
    }

    /// Prebuilds: one thread per hot key however often asked, none for a key
    /// outside the hot set, and a prebuild whose key leaves the hot set while
    /// it waits for room gives up without building it.
    #[test]
    fn prebuilds_are_deduplicated_and_give_up_off_the_hot_set() {
        let (cache, _live, _peak) = peak_cache();
        let k = |i: u64| key(2000 + i);
        cache.prebuild(&k(1)); // not hot: nothing happens
        assert!(cache.lock().prebuilding.is_empty());
        cache.set_hot(&[k(1)]);
        for _ in 0..8 {
            cache.prebuild(&k(1));
        }
        let deadline = std::time::Instant::now() + BOUND;
        while !cache.is_resident(&k(1)) || !cache.lock().prebuilding.is_empty() {
            assert!(
                std::time::Instant::now() < deadline,
                "the prebuild did not finish"
            );
            std::thread::yield_now();
        }
        assert_eq!(cache.builds(), 1, "one build for eight prebuild requests");

        // Fill the bound with borrowed caches (hot-set churn evicts them
        // while borrowed), then prebuild a hot key: its thread waits for
        // room. Moving the hot set away makes it give up.
        cache.set_hot(&[k(10), k(11)]);
        let held1 = [get(&cache, &k(10)), get(&cache, &k(11))];
        cache.set_hot(&[k(12), k(13)]);
        let held2 = [get(&cache, &k(12)), get(&cache, &k(13))];
        cache.set_hot(&[k(14), k(20)]);
        let held3 = get(&cache, &k(14));
        assert_eq!(cache.alive(), MAX_CACHES);
        let builds = cache.builds();
        cache.prebuild(&k(20));
        assert_eq!(cache.lock().prebuilding, vec![k(20)]);
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(cache.builds(), builds, "no room: the prebuild waits");
        // Asked again while its thread waits (prebuilding, not building):
        // still one thread (W4-MUT: either `||` of the guard mutated to `&&`
        // survived).
        cache.prebuild(&k(20));
        assert_eq!(cache.lock().prebuilding, vec![k(20)], "one thread per key");
        cache.set_hot(&[k(14)]);
        let deadline = std::time::Instant::now() + BOUND;
        while !cache.lock().prebuilding.is_empty() {
            assert!(
                std::time::Instant::now() < deadline,
                "the prebuild did not give up"
            );
            std::thread::yield_now();
        }
        drop((held1, held2, held3));
        assert_eq!(cache.builds(), builds, "the abandoned key was not built");
        assert!(!cache.is_resident(&k(20)));
    }

    /// A side build leaves room for every missing hot key. The reserve
    /// binds only while builds of keys that have left the hot set are still
    /// in flight (the side rules keep everything else within the bound), so
    /// this test holds two such builds open on a gate. W4-MUT on the bounded
    /// store: every mutant of `missing_hot`, and `alive + 1 - reserve`,
    /// survived without it.
    #[test]
    fn a_side_build_leaves_room_for_the_missing_hot_keys() {
        let k = |i: u64| key(3000 + i);
        let (a, b) = (k(1), k(2));
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let g = gate.clone();
        let cache = Arc::new(SeedCache::new(move |s: &Hash| {
            if *s == a || *s == b {
                let (open, cv) = &*g;
                let open = open.lock().unwrap();
                let _ = cv.wait_timeout_while(open, BOUND, |o| !*o);
            }
            *s
        }));
        // Two hot builds held open, then the hot set moves on: they are
        // builds of keys that are no longer hot.
        cache.set_hot(&[a, b]);
        let (built_a, built_b) = (ask(&cache, &a), ask(&cache, &b));
        let deadline = std::time::Instant::now() + BOUND;
        while cache.lock().building.len() < 2 {
            assert!(
                std::time::Instant::now() < deadline,
                "the hot builds did not start"
            );
            std::thread::yield_now();
        }
        let (c, d) = (k(3), k(4));
        cache.set_hot(&[c, d]);
        // One side cache, borrowed: 3 in memory, 2 hot keys missing.
        let s1 = get(&cache, &k(5));
        assert_eq!(cache.alive(), 3);
        assert_eq!(cache.lock().missing_hot(&k(6)), 2);
        let side = ask(&cache, &k(6));
        assert!(
            side.recv_timeout(Duration::from_millis(300)).is_err(),
            "a side build took the room of the missing hot keys (3 + 1 + 2 > 5)"
        );
        // A hot key's build needs no reserve.
        let _hc = get(&cache, &c);
        assert_eq!(cache.alive(), 4);
        assert_eq!(cache.lock().missing_hot(&k(6)), 1);
        assert!(side.recv_timeout(Duration::from_millis(300)).is_err());
        // The old builds finish and are trimmed; the side build then fits.
        {
            let (open, cv) = &*gate;
            *open.lock().unwrap() = true;
            cv.notify_all();
        }
        drop(built_a.recv_timeout(BOUND).expect("a's build finishes"));
        drop(built_b.recv_timeout(BOUND).expect("b's build finishes"));
        drop(s1);
        let got = side.recv_timeout(BOUND).expect("the side build proceeds");
        assert_eq!(**got, k(6));
        assert!(cache.alive() <= MAX_CACHES);
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
        assert_eq!(**get(&cache, &k), k, "retried");
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
