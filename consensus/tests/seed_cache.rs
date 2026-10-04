//! Differential test of the RandomX cache layer (07 W1, T6): whatever the
//! cache state (hot set changes, prebuilds, evictions, rebuilds across key
//! switches), `RandomXPow::pow_hash` equals light-mode RandomX computed with a
//! freshly built cache for the same key. Cache management must never change a
//! hash (never-change list item 3).
//!
//! Real RandomX, light mode: 4 reference caches plus the layer's own builds.

use blacksilk_consensus::pow::MAX_CACHES;
use blacksilk_consensus::{PowFunction, RandomXPow};
use blacksilk_randomx::{Cache, Vm};
use std::collections::HashMap;
use std::time::{Duration, Instant};

fn key(i: u8) -> [u8; 32] {
    [0xA0 ^ i; 32]
}

/// Header-shaped input with a varying nonce field.
fn blob(n: u64) -> [u8; blacksilk_consensus::HEADER_SIZE] {
    let mut b = [0x3C; blacksilk_consensus::HEADER_SIZE];
    b[blacksilk_consensus::NONCE_OFFSET..].copy_from_slice(&n.to_le_bytes());
    b
}

/// Waits (bounded) until the background prebuild of `seed` has finished.
fn wait_resident(pow: &RandomXPow, seed: &[u8; 32]) {
    let deadline = Instant::now() + Duration::from_secs(120);
    while !pow.is_resident(seed) {
        assert!(Instant::now() < deadline, "prebuild did not finish");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn cached_hashes_equal_fresh_computation_across_key_switches() {
    let keys: Vec<[u8; 32]> = (0..4).map(key).collect();
    let fresh: HashMap<[u8; 32], Cache> = keys.iter().map(|k| (*k, Cache::new(k))).collect();
    let reference = |k: &[u8; 32], n: u64| Vm::light(&fresh[k]).hash(&blob(n));

    let pow = RandomXPow::new();
    // Nothing is built yet; after the first hash exactly its key is (W4-MUT:
    // `resident` and `is_resident` survived mutation).
    assert!(pow.resident().is_empty());
    assert!(!pow.is_resident(&keys[0]));
    assert_eq!(pow.alive(), 0, "no cache in memory yet");
    assert_eq!(pow.pow_hash(&keys[0], &blob(0)), reference(&keys[0], 0));
    assert_eq!(pow.resident(), vec![keys[0]]);
    assert_eq!(pow.alive(), 1, "exactly the one built cache");
    assert!(pow.is_resident(&keys[0]) && !pow.is_resident(&keys[1]));
    // A scripted walk over two key switches (k0 -> k1 -> k2), with a side key
    // (k3) asked for in between, the hot set moved as a chain would move it,
    // and a reorg back to the previous key after the switch.
    #[derive(Clone, Copy)]
    enum Step {
        Hot(&'static [usize]),
        Hash(usize, u64),
    }
    use Step::*;
    let script = [
        Hash(0, 1),
        Hot(&[0]),
        Hash(3, 2),   // side key
        Hot(&[0, 1]), // the next key's block exists: prebuilt
        Hash(0, 3),
        Hash(1, 4), // the switch
        Hash(3, 5), // side key again: must not evict k0 or k1
        Hash(0, 6), // a branch still under the old key
        Hot(&[1]),
        Hash(1, 7),
        Hot(&[1, 2]), // the next switch
        Hash(2, 8),
        Hash(0, 9), // an old key again: rebuilt in the side slot
        Hot(&[]),   // no hot set: plain LRU
        Hash(3, 10),
        Hash(2, 11),
    ];
    let mut checked = 0;
    for step in script {
        match step {
            Hot(ks) => {
                let seeds: Vec<[u8; 32]> = ks.iter().map(|&i| keys[i]).collect();
                pow.set_hot_seeds(&seeds);
                for s in &seeds {
                    wait_resident(&pow, s);
                }
            }
            Hash(k, n) => {
                assert_eq!(
                    pow.pow_hash(&keys[k], &blob(n)),
                    reference(&keys[k], n),
                    "key {k}, input {n}: cached path differs from a fresh cache"
                );
                checked += 1;
            }
        }
        assert!(pow.resident().len() <= 3, "at most 2 hot + 1 side kept");
        assert!(pow.alive() <= MAX_CACHES, "the store's memory bound");
    }
    assert_eq!(checked, 11);
    // Pinning worked: k0, k1 and k2 were each built once while hot, whatever
    // the side key did; the only rebuilds are k3 and k2 after the hot set
    // was cleared (k0 k3 k1 k2, then k3 k2).
    println!("caches built by the layer: {}", pow.builds());
    assert_eq!(pow.builds(), 6);
}
