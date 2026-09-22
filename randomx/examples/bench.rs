//! Rough timing of cache initialization and light-mode hashing.
//! `cargo run --release -p blacksilk-randomx --example bench`

use blacksilk_randomx::{Cache, Vm};
use std::time::Instant;

fn main() {
    let t = Instant::now();
    let cache = Cache::new(b"bench key");
    println!("cache init:       {:>8.2?}", t.elapsed());

    let mut vm = Vm::light(&cache);
    let n = 20u32;
    let t = Instant::now();
    for i in 0..n {
        std::hint::black_box(vm.hash(&i.to_le_bytes()));
    }
    let per = t.elapsed() / n;
    println!(
        "light-mode hash:  {per:>8.2?}  ({:.1} H/s per thread)",
        1.0 / per.as_secs_f64()
    );
}
