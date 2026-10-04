//! Single-thread light-mode benchmark: cache initialization, dataset items
//! computed from the cache, and light-mode hashes. Checks the reference
//! vector 1a first, so a fast but wrong build never reports a number.
//!
//! `cargo run --release -p blacksilk-randomx --example bench -- [hashes] [rounds]`
//! (defaults: 20 hashes, 3 rounds; the best round is reported, as the least
//! disturbed by other load).

use blacksilk_randomx::{Cache, Vm, FINGERPRINT_KAT};
use std::time::Instant;

fn main() {
    let mut args = std::env::args().skip(1);
    let n: u32 = args.next().map_or(20, |a| a.parse().expect("hashes"));
    let rounds: u32 = args.next().map_or(3, |a| a.parse().expect("rounds"));

    let t = Instant::now();
    let cache = Cache::new(FINGERPRINT_KAT.key);
    println!("cache init:       {:>8.2?}", t.elapsed());

    let mut vm = Vm::light(&cache);
    let got = vm.hash(FINGERPRINT_KAT.input);
    let hex: String = got.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, FINGERPRINT_KAT.hash, "vector 1a");

    let mut best = f64::MAX;
    let mut digest = 0u64;
    for round in 0..rounds {
        let t = Instant::now();
        for i in 0..n {
            let h = vm.hash(&i.to_le_bytes());
            digest ^= u64::from_le_bytes(h[..8].try_into().unwrap());
        }
        let per = t.elapsed().as_secs_f64() / n as f64;
        println!(
            "round {round}: light-mode hash {:>7.1} ms  ({:.2} H/s, 1 thread)",
            per * 1e3,
            1.0 / per
        );
        best = best.min(per);
    }
    println!(
        "best: {:.1} ms/hash, {:.2} H/s (1 thread, {n} hashes x {rounds} rounds; digest {digest:016x})",
        best * 1e3,
        1.0 / best
    );
}
