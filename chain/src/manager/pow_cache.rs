//! The PoW hash cache (`CachedPow`) and its parallel precomputation.

use blacksilk_consensus::hash::H;
use blacksilk_consensus::{Hash, PowFunction};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// PoW wrapper that remembers every computed hash, keyed by the RandomX key
/// (seed block id) **and** the header bytes. It lets the node store PoW hashes
/// with blocks and skip recomputing RandomX when replaying its own store.
///
/// The seed is part of the key so that a hash computed under one seed (for
/// example by [`ChainManager::pow_jobs`] from a peer's batch) is never reused
/// where header validation derives a different seed: that lookup misses and
/// the hash is computed again under the right key.
pub struct CachedPow {
    inner: Arc<dyn PowFunction>,
    known: Mutex<HashMap<Hash, Hash>>,
}

impl CachedPow {
    pub fn new(inner: Arc<dyn PowFunction>) -> Self {
        Self {
            inner,
            known: Mutex::new(HashMap::new()),
        }
    }

    fn key(seed: &Hash, header_bytes: &[u8]) -> Hash {
        H::new()
            .chain(b"BlackSilk/pow-cache/v2")
            .chain(seed)
            .chain(header_bytes)
            .finish()
    }

    /// The cached PoW hash of `header_bytes` under the RandomX key `seed`.
    pub fn lookup(&self, seed: &Hash, header_bytes: &[u8]) -> Option<Hash> {
        let known = self.known.lock().unwrap_or_else(|e| e.into_inner());
        known.get(&Self::key(seed, header_bytes)).copied()
    }

    /// Trusts `pow_hash` for `header_bytes` under `seed` (only for blocks from
    /// the node's own store, with the seed derived from the stored parent).
    pub fn preload(&self, seed: &Hash, header_bytes: &[u8], pow_hash: Hash) {
        let mut known = self.known.lock().unwrap_or_else(|e| e.into_inner());
        known.insert(Self::key(seed, header_bytes), pow_hash);
    }
}

/// One PoW computation: RandomX key (seed block id) and header bytes.
pub type PowJob = (Hash, [u8; blacksilk_consensus::HEADER_SIZE]);

impl CachedPow {
    /// Computes and caches the PoW hashes of `jobs` on `threads` threads.
    pub fn compute_parallel(&self, jobs: &[PowJob], threads: usize) {
        let todo: Vec<&PowJob> = jobs
            .iter()
            .filter(|(seed, b)| self.lookup(seed, b).is_none())
            .collect();
        if todo.is_empty() {
            return;
        }
        let threads = threads.clamp(1, todo.len());
        let next = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|s| {
            for _ in 0..threads {
                s.spawn(|| loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some((seed, bytes)) = todo.get(i) else {
                        break;
                    };
                    let _ = self.pow_hash(seed, bytes);
                });
            }
        });
    }
}

impl PowFunction for CachedPow {
    fn pow_hash(&self, seed: &Hash, header_bytes: &[u8]) -> Hash {
        if let Some(h) = self.lookup(seed, header_bytes) {
            return h;
        }
        let h = self.inner.pow_hash(seed, header_bytes);
        self.preload(seed, header_bytes, h);
        h
    }
}
