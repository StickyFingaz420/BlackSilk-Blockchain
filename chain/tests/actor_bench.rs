//! Chain actor benchmarks (docs/reviews/chain-actor-stage2.md §5 "Bench"),
//! before (the chain mutex with `submit_block_in_steps`, the pre-Stage 2
//! path) and after (the actor), on the same machine in the same run.
//! Ignored by default; run with
//! `cargo test --release -p blacksilk-chain --test actor_bench -- --ignored --nocapture --test-threads=1`.
//!
//! - **B1 throughput**: a 2,000-block regtest chain of coinbase-only blocks,
//!   (a) submitted in order, one block at a time, and (b) released at once
//!   as one drain (IBD shape: headers first, every body but the first
//!   waiting). The addendum's bar: within ±5 %.
//! - **B2 publication cost**: the snapshot recomputed from scratch, and the
//!   no-change check run after every command.
//! - **B3 read latency**: a reader asking for the height every millisecond
//!   during the B1 drain: through the mutex (before), through the Query lane
//!   and through the published snapshot (after).
//! - **Steps**: the number of drain steps and the mean step duration.
//!
//! The figures depend on the machine and its load; they are printed, not
//! asserted (except that every run reaches the same chain).

#[path = "support/stall.rs"]
mod stall;

use blacksilk_chain::actor::{self, ActorConfig, Lane, LogEntry};
use blacksilk_chain::block::Block;
use blacksilk_chain::manager::{submit_block_in_steps, ChainManager, SYNC_STEP_BLOCKS};
use blacksilk_chain::store::MemoryStore;
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, PowFunction};
use blacksilk_tx::params::TxRules;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct ZeroPow;
impl PowFunction for ZeroPow {
    fn pow_hash(&self, _: &Hash, _: &[u8]) -> Hash {
        [0; 32]
    }
}

const N: u64 = 2000;
const NOW: u64 = u64::MAX / 2;

fn open() -> ChainManager {
    let p = ChainParams::regtest();
    ChainManager::open(
        p.clone(),
        TxRules::for_chain(&p),
        Arc::new(ZeroPow),
        Box::<MemoryStore>::default(),
        [5; 32],
    )
    .unwrap()
}

fn chain() -> Vec<Block> {
    let mut src = open();
    (0..N)
        .map(|i| {
            let b = stall::next_block(&src, 0xBE00 + i, i);
            src.submit_block(b.clone(), NOW).unwrap();
            b
        })
        .collect()
}

/// Headers of every block and every body but the first.
fn waiting(blocks: &[Block]) -> ChainManager {
    let mut m = open();
    let hs: Vec<BlockHeader> = blocks.iter().map(|b| b.header).collect();
    m.accept_headers(&hs, NOW).unwrap();
    for b in &blocks[1..] {
        m.submit_block(b.clone(), NOW).unwrap();
    }
    m
}

/// Latency percentiles of `v` (sorted in place): p50, p99, max.
fn pct(v: &mut [Duration]) -> String {
    if v.is_empty() {
        return "no samples".into();
    }
    v.sort_unstable();
    let at = |q: f64| v[((v.len() - 1) as f64 * q) as usize];
    format!(
        "n={} p50={:?} p99={:?} max={:?}",
        v.len(),
        at(0.5),
        at(0.99),
        v[v.len() - 1]
    )
}

/// Samples `read` every millisecond until `done`.
fn sample(
    done: Arc<AtomicBool>,
    read: impl Fn() + Send + 'static,
) -> std::thread::JoinHandle<Vec<Duration>> {
    std::thread::spawn(move || {
        let mut out = Vec::new();
        while !done.load(Ordering::SeqCst) {
            let t = Instant::now();
            read();
            out.push(t.elapsed());
            std::thread::sleep(Duration::from_millis(1));
        }
        out
    })
}

#[test]
#[ignore = "benchmark: run explicitly with --ignored --nocapture"]
fn bench_actor_against_the_mutex() {
    let blocks = chain();
    let tip = blocks.last().unwrap().id(ChainParams::regtest().network_id);

    // B1 (a): in order, one at a time.
    let in_order_mutex = {
        let m = Mutex::new(open());
        let t = Instant::now();
        for b in &blocks {
            submit_block_in_steps(|| m.lock().unwrap(), b.clone(), NOW, SYNC_STEP_BLOCKS).unwrap();
        }
        let took = t.elapsed();
        assert_eq!(m.lock().unwrap().tip_id(), tip);
        took
    };
    let in_order_actor = {
        let (h, th) = actor::spawn(open(), ActorConfig::default());
        let t = Instant::now();
        for b in &blocks {
            h.submit_block_blocking(b.clone(), NOW).unwrap().unwrap();
        }
        let took = t.elapsed();
        drop(h);
        assert_eq!(th.join().unwrap().tip_id(), tip);
        took
    };

    // B1 (b) and B3: one drain of N blocks, with a reader.
    let (drain_mutex, reads_mutex) = {
        let m = Arc::new(Mutex::new(waiting(&blocks)));
        let done = Arc::new(AtomicBool::new(false));
        let r = m.clone();
        let reader = sample(done.clone(), move || {
            let _ = r.lock().unwrap().height();
        });
        let t = Instant::now();
        let c = m.clone();
        submit_block_in_steps(
            || c.lock().unwrap(),
            blocks[0].clone(),
            NOW,
            SYNC_STEP_BLOCKS,
        )
        .unwrap();
        let took = t.elapsed();
        done.store(true, Ordering::SeqCst);
        let mut reads = reader.join().unwrap();
        assert_eq!(m.lock().unwrap().tip_id(), tip);
        (took, pct(&mut reads))
    };
    let (drain_actor, reads_query, reads_snapshot, steps) = {
        let (h, th) = actor::spawn(waiting(&blocks), ActorConfig::default());
        let done = Arc::new(AtomicBool::new(false));
        let q = h.clone();
        let query = sample(done.clone(), move || {
            let _ = q.call_blocking(Lane::Query, |m| m.height()).unwrap();
        });
        let s = h.clone();
        let snapshot = sample(done.clone(), move || {
            let _ = s.summary().height;
        });
        let t = Instant::now();
        h.submit_block_blocking(blocks[0].clone(), NOW)
            .unwrap()
            .unwrap();
        let took = t.elapsed();
        done.store(true, Ordering::SeqCst);
        let (mut q, mut s) = (query.join().unwrap(), snapshot.join().unwrap());
        let steps = h
            .log_for_tests()
            .iter()
            .filter(|e| matches!(e, LogEntry::Step { .. }))
            .count();
        drop(h);
        assert_eq!(th.join().unwrap().tip_id(), tip);
        (took, pct(&mut q), pct(&mut s), steps)
    };

    // B2: publication cost on the final chain.
    let (full, check) = {
        let (h, th) = actor::spawn(open(), ActorConfig::default());
        for b in &blocks {
            h.submit_block_blocking(b.clone(), NOW).unwrap().unwrap();
        }
        drop(h);
        let m = th.join().unwrap();
        let t = Instant::now();
        for _ in 0..1000 {
            std::hint::black_box(m.summary_now(1));
        }
        let full = t.elapsed() / 1000;
        let t = Instant::now();
        for _ in 0..10_000 {
            m.publish_summary();
        }
        (full, t.elapsed() / 10_000)
    };

    let rate = |d: Duration| N as f64 / d.as_secs_f64();
    println!("B1 in order, {N} blocks: mutex {in_order_mutex:?} ({:.0} blocks/s), actor {in_order_actor:?} ({:.0} blocks/s), actor/mutex {:.3}",
        rate(in_order_mutex), rate(in_order_actor), in_order_actor.as_secs_f64() / in_order_mutex.as_secs_f64());
    println!("B1 one drain, {N} blocks: mutex {drain_mutex:?} ({:.0} blocks/s), actor {drain_actor:?} ({:.0} blocks/s), actor/mutex {:.3}",
        rate(drain_mutex), rate(drain_actor), drain_actor.as_secs_f64() / drain_mutex.as_secs_f64());
    println!(
        "steps: {steps} (budget {SYNC_STEP_BLOCKS}), mean step {:?}",
        drain_actor / steps.max(1) as u32
    );
    println!("B2 snapshot from scratch: {full:?}; no-change check: {check:?}");
    println!("B3 read during the drain: mutex {reads_mutex}");
    println!("B3 read during the drain: actor Query lane {reads_query}");
    println!("B3 read during the drain: actor snapshot {reads_snapshot}");
}
