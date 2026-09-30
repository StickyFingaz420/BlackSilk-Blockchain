//! Liveness of the RandomX key switch (07 W1, F07-1): building the cache of a
//! new key (about 1-3 s, 256 MiB) must not stall PoW callers that use a key
//! whose cache is already built. Before the out-of-lock build, `RandomXPow`
//! built caches while holding its one mutex, so every PoW caller, including
//! one that holds the chain lock, waited for the whole build: the chain-lock
//! convoy at every seed switch.
//!
//! Real RandomX, light mode. The numbers are printed (`--nocapture`) as the
//! before/after evidence.

use blacksilk_consensus::{PowFunction, RandomXPow};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

/// Getting a built key's cache while another key's cache is being built.
/// The wait is the lock wait alone (a light hash itself takes about as long
/// as a build on a loaded machine, so hash times would hide it): it is
/// measured with `is_resident`, which takes the same store lock as a cache
/// lookup and hashes nothing (the cache accessor is private, RT-POW L1).
#[test]
fn a_cache_build_does_not_stall_callers_of_a_built_key() {
    let pow = Arc::new(RandomXPow::new());
    let (old, new) = ([0x51; 32], [0x52; 32]);
    let blob = [7u8; 100];

    let started = Instant::now();
    let reference = pow.pow_hash(&old, &blob);
    let first = started.elapsed();
    let started = Instant::now();
    assert!(pow.is_resident(&old));
    let built = started.elapsed();

    let barrier = Arc::new(Barrier::new(2));
    let switcher = {
        let (pow, barrier) = (pow.clone(), barrier.clone());
        std::thread::spawn(move || {
            barrier.wait();
            let started = Instant::now();
            let _ = pow.pow_hash(&new, &blob); // the build, plus one hash
            started.elapsed()
        })
    };
    barrier.wait();
    // Let the switcher take whatever lock the build takes.
    std::thread::sleep(Duration::from_millis(300));
    let started = Instant::now();
    assert!(pow.is_resident(&old));
    let wait = started.elapsed();
    let started = Instant::now();
    assert_eq!(pow.pow_hash(&old, &blob), reference, "same hash");
    let hash = started.elapsed();
    let build = switcher.join().unwrap();

    println!(
        "first hash incl. build {first:.1?}; built-key cache lookup {built:.1?}; \
         new-key build {build:.1?}; built-key cache lookup during that build {wait:.1?}; \
         one light hash {hash:.1?}"
    );
    // A real build (a 256 MiB Argon2d fill) cannot be near-instant, but its
    // length depends on the machine: fast CI runners build in well under the
    // 400 ms this once assumed (run 101). The claim is relative: the built
    // key's lookup waited a small fraction of the build.
    assert!(
        build > Duration::from_millis(100),
        "the build is a real one: {build:.1?}"
    );
    let bound = Duration::from_millis(50).min(build / 4);
    assert!(
        wait <= bound,
        "a caller of a built key waited for another key's cache build: {wait:.1?} > {bound:.1?} \
         (build {build:.1?})"
    );
}
