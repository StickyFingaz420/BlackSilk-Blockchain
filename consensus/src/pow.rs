//! Proof of work (spec §3): target check, RandomX key schedule, hashing.

use crate::hash::Hash;
use blacksilk_randomx::{Cache, Vm};
use std::sync::{Arc, Mutex};

/// True iff `hash` (256-bit little-endian integer) times `difficulty` is below 2^256.
/// Difficulty 0 is never satisfied.
pub fn check_hash(hash: &Hash, difficulty: u64) -> bool {
    if difficulty == 0 {
        return false;
    }
    let mut carry: u128 = 0;
    for limb in hash.chunks_exact(8) {
        let v = u64::from_le_bytes(limb.try_into().unwrap()) as u128;
        carry = v * difficulty as u128 + carry;
        carry >>= 64;
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
}

/// RandomX (light mode) keyed by the seed block id. Keeps the most recently used
/// caches, because at most two keys are live around an epoch switch.
pub struct RandomXPow {
    caches: Mutex<Vec<(Hash, Arc<Cache>)>>,
    capacity: usize,
}

impl RandomXPow {
    pub fn new() -> Self {
        Self { caches: Mutex::new(Vec::new()), capacity: 2 }
    }

    /// The cache for `seed`, building it (about 0.6 s, 256 MiB) if needed.
    pub fn cache(&self, seed: &Hash) -> Arc<Cache> {
        let mut caches = self.caches.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(pos) = caches.iter().position(|(s, _)| s == seed) {
            let entry = caches.remove(pos);
            let cache = entry.1.clone();
            caches.push(entry); // most recently used last
            return cache;
        }
        // Built while holding the lock so concurrent callers don't build it twice.
        let cache = Arc::new(Cache::new(seed));
        if caches.len() >= self.capacity {
            caches.remove(0);
        }
        caches.push((*seed, cache.clone()));
        cache
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
}
