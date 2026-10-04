//! Timing of header proof-of-work verification as the p2p header worker runs
//! it (W4-POWPOOL, docs/evidence/pow-pool-2026-10-01): a batch hashed in
//! chunks of `pow_threads` headers, one `CachedPow::compute_parallel` call
//! per chunk (`p2p/src/net/headers.rs`, `sync_policy::pow_chunk`).
//!
//! Ignored: run by hand in release mode, idle and under load, e.g.
//! `cargo test --release -p blacksilk-chain --test pow_pool_bench -- --ignored --nocapture --test-threads=1`.
//! `POWPOOL_HEADERS` sets the real-RandomX batch size (default 200),
//! `POWPOOL_THREADS` the comma-separated `pow_threads` values (default 1,2,4).
//!
//! Each run prints a digest of every hash it stored, so runs of different
//! builds can be compared for identical results.

use blacksilk_chain::manager::{CachedPow, PowJob};
use blacksilk_consensus::hash::H;
use blacksilk_consensus::{Hash, PowFunction, RandomXPow, POW_BLOB_SIZE};
use std::sync::Arc;
use std::time::Instant;

/// A cheap stand-in proof of work (one Blake2b), as the p2p tests use.
struct CheapPow;
impl PowFunction for CheapPow {
    fn pow_hash(&self, seed: &Hash, blob: &blacksilk_consensus::PowBlob) -> Hash {
        H::new().chain(seed).chain(blob).finish()
    }
}

/// `n` distinct header-sized blobs under one key.
fn jobs(seed: Hash, n: usize) -> Vec<PowJob> {
    (0..n as u64)
        .map(|i| {
            let mut b = [0x5A; POW_BLOB_SIZE];
            b[POW_BLOB_SIZE - 8..].copy_from_slice(&i.to_le_bytes());
            b[..8].copy_from_slice(&(i * 7919).to_le_bytes());
            (seed, b)
        })
        .collect()
}

/// Hashes `jobs` as the header worker does: chunks of `threads` headers,
/// one `compute_parallel` per chunk. Returns the elapsed milliseconds and a
/// digest of the stored hashes, in job order.
fn run(pow: &CachedPow, jobs: &[PowJob], threads: usize) -> (u128, String) {
    let started = Instant::now();
    for chunk in jobs.chunks(threads) {
        pow.compute_parallel(chunk, threads);
    }
    let ms = started.elapsed().as_millis();
    let mut d = H::new();
    for (seed, b) in jobs {
        d = d.chain(&pow.lookup(seed, b).expect("every job was hashed"));
    }
    (ms, hex(&d.finish()[..8]))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn thread_counts() -> Vec<usize> {
    std::env::var("POWPOOL_THREADS")
        .unwrap_or_else(|_| "1,2,4".into())
        .split(',')
        .map(|s| s.trim().parse().expect("POWPOOL_THREADS"))
        .collect()
}

/// INV-PEN's cheap-header measurement: 300 one-thread chunks, and a
/// 31-header batch in chunks of 2.
#[test]
#[ignore = "timing; run by hand (module docs)"]
fn bench_cheap_chunks() {
    let inner: Arc<dyn PowFunction> = Arc::new(CheapPow);
    let all = jobs([1; 32], 300);
    let (ms, d) = run(&CachedPow::new(inner.clone()), &all, 1);
    println!("cheap 300 x 1-thread chunks: {ms} ms digest {d}");
    let (ms, d) = run(&CachedPow::new(inner), &all[..31], 2);
    println!("cheap 31 headers, 2-thread chunks: {ms} ms digest {d}");
}

/// Real light-mode RandomX: a batch of `POWPOOL_HEADERS` headers under one
/// key whose cache is built before timing (a node keeps its hot keys built).
#[test]
#[ignore = "timing; run by hand (module docs)"]
fn bench_randomx_batch() {
    let n: usize = std::env::var("POWPOOL_HEADERS").map_or(200, |s| s.parse().unwrap());
    let seed = [0xB5; 32];
    let rx = Arc::new(RandomXPow::new());
    let started = Instant::now();
    let _ = rx.pow_hash(&seed, &[0; POW_BLOB_SIZE]);
    println!("cache build + 1 hash: {} ms", started.elapsed().as_millis());
    let inner: Arc<dyn PowFunction> = rx;
    let all = jobs(seed, n);
    for threads in thread_counts() {
        let (ms, d) = run(&CachedPow::new(inner.clone()), &all, threads);
        println!(
            "randomx {n} headers, pow_threads {threads}: {ms} ms ({:.1} ms/header) digest {d}",
            ms as f64 / n as f64
        );
    }
}
