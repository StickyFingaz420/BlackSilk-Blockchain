//! The chain actor's ordering guarantees (docs/reviews/chain-actor-stage2.md
//! §3; `blacksilk_chain::actor`), the chain-level halves of the liveness
//! tests L7 and L8, and the fail-stop test F1.
//!
//! Guarantees 1, 2 and 5 are also checked on random schedules by E2/E3
//! (`actor_equivalence.rs`); here each guarantee has a deterministic test:
//!
//! | Test | Guarantee |
//! |---|---|
//! | `g1_...` | 1: one writer, total order |
//! | `g2_...` | 2: per-producer FIFO within a lane |
//! | `g3_...` | 3: priority across lanes, with the starvation bound |
//! | `g4_...` | 4: drain continuation (one command between two steps) |
//! | `g5_...` | 5: snapshot monotonicity, published before the reply |
//! | `g6_...` | 6: a command runs whole (no interleaving inside it) |
//! | `g7_...` | 7: stop between steps; the store replays the rest |
//!
//! Heavy steps come from `ChainManager::set_step_delay_for_tests` (each
//! bounded call sleeps first, holding the manager), a gate from a command
//! that waits on a channel; both are `test-hooks` only.

#[path = "support/stall.rs"]
mod stall;

use blacksilk_chain::actor::{
    self, ActorConfig, ChainHandle, Lane, LogEntry, SendError, DEFAULT_BLOCKS_CAPACITY,
    POISONED_EXIT_CODE, STARVATION_LIMIT,
};
use blacksilk_chain::block::Block;
use blacksilk_chain::manager::{submit_block_in_steps, ChainManager};
use blacksilk_chain::store::{BlockStore, FileStore, MemoryStore};
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, PowFunction};
use blacksilk_tx::params::TxRules;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct ZeroPow;
impl PowFunction for ZeroPow {
    fn pow_hash(&self, _: &Hash, _: &[u8]) -> Hash {
        [0; 32]
    }
}

fn params() -> ChainParams {
    ChainParams::regtest()
}

fn open_with(store: Box<dyn BlockStore>) -> ChainManager {
    let p = params();
    ChainManager::open(
        p.clone(),
        TxRules::for_chain(&p),
        Arc::new(ZeroPow),
        store,
        [7; 32],
    )
    .unwrap()
}

fn open() -> ChainManager {
    open_with(Box::<MemoryStore>::default())
}

/// `n` coinbase-only blocks on genesis.
fn chain_of(n: u64) -> Vec<Block> {
    let mut src = open();
    (0..n)
        .map(|i| {
            let b = stall::next_block(&src, 0xB000 + i, i);
            let now = b.header.timestamp;
            src.submit_block(b.clone(), now).unwrap();
            b
        })
        .collect()
}

const NOW: u64 = u64::MAX / 2;

/// A manager that knows the headers of `blocks` and every body but the
/// first: submitting the first releases a drain of all of them.
fn waiting_for_the_first(blocks: &[Block]) -> ChainManager {
    let mut m = open();
    let hs: Vec<BlockHeader> = blocks.iter().map(|b| b.header).collect();
    m.accept_headers(&hs, NOW).unwrap();
    for b in &blocks[1..] {
        let s = m.submit_block(b.clone(), NOW).unwrap();
        assert!(!s.on_best_chain);
    }
    m
}

fn config(budget: usize) -> ActorConfig {
    ActorConfig {
        step_budget: budget,
        ..ActorConfig::default()
    }
}

/// Parks the actor in a command until the returned sender is dropped or
/// sent to; returns once the actor is inside it.
fn gate(h: &ChainHandle) -> mpsc::Sender<()> {
    let (open_tx, open_rx) = mpsc::channel::<()>();
    let (inside_tx, inside_rx) = mpsc::channel();
    h.call(
        Lane::Headers,
        move |_| {
            inside_tx.send(()).unwrap();
            let _ = open_rx.recv();
        },
        |()| {},
    )
    .unwrap();
    inside_rx.recv().unwrap();
    open_tx
}

fn labels(log: &[LogEntry]) -> Vec<String> {
    log.iter()
        .filter_map(|e| match e {
            LogEntry::Run { label, .. } | LogEntry::Submit { label, .. } => {
                (!label.is_empty()).then(|| label.clone())
            }
            LogEntry::Step { .. } => None,
        })
        .collect()
}

fn noop(h: &ChainHandle, lane: Lane, label: &str) -> Result<(), SendError> {
    h.call_labeled(lane, label.to_string(), |_| (), |()| {})
}

/// Waits until every command queued so far has run (a Tx-lane command runs
/// after every higher lane's).
fn settle(h: &ChainHandle) {
    for lane in Lane::ALL {
        h.call_blocking(lane, |_| ()).unwrap();
    }
}

/// Guarantee 1: commands run one at a time, in one total order that every
/// producer observes. Two producers increment a counter they keep in a
/// command's closure; every increment sees exactly the previous ones.
#[test]
fn g1_commands_run_one_at_a_time_in_one_total_order() {
    let (h, t) = actor::spawn(open(), ActorConfig::default());
    let counter = Arc::new(Mutex::new(0u64));
    let producers: Vec<_> = (0..4)
        .map(|p| {
            let (h, counter) = (h.clone(), counter.clone());
            std::thread::spawn(move || {
                let lane = Lane::ALL[p % 4];
                (0..200)
                    .map(|_| {
                        let c = counter.clone();
                        h.call_blocking(lane, move |_| {
                            // No other command can run in between: a
                            // non-atomic read-modify-write stays exact.
                            let v = *c.lock().unwrap();
                            std::thread::yield_now();
                            *c.lock().unwrap() = v + 1;
                            v
                        })
                        .unwrap()
                    })
                    .collect::<Vec<u64>>()
            })
        })
        .collect();
    let mut all: Vec<u64> = producers
        .into_iter()
        .flat_map(|p| p.join().unwrap())
        .collect();
    all.sort_unstable();
    assert_eq!(all, (0..800).collect::<Vec<_>>());
    drop(h);
    t.join();
}

/// Guarantee 2: one producer's commands on one lane run in the order sent,
/// however the actor is loaded.
#[test]
fn g2_a_producers_commands_on_one_lane_run_in_order() {
    let (h, t) = actor::spawn(open(), ActorConfig::default());
    let g = gate(&h);
    for k in 0..50 {
        noop(&h, Lane::Query, &format!("q{k}")).unwrap();
        noop(&h, Lane::Tx, &format!("t{k}")).unwrap();
    }
    drop(g);
    settle(&h);
    let got = labels(&h.log_for_tests());
    for prefix in ["q", "t"] {
        let order: Vec<usize> = got
            .iter()
            .filter(|l| l.starts_with(prefix))
            .map(|l| l[1..].parse().unwrap())
            .collect();
        assert_eq!(order, (0..50).collect::<Vec<_>>(), "{prefix}");
    }
    drop(h);
    t.join();
}

/// Guarantee 3: waiting commands run by lane priority (Headers, Blocks,
/// Query, Tx), whatever their arrival order; and a lower lane's command is
/// served after at most `STARVATION_LIMIT` higher ones.
#[test]
fn g3_lanes_run_by_priority_and_no_lane_starves() {
    let (h, t) = actor::spawn(open(), ActorConfig::default());
    let g = gate(&h);
    for (lane, label) in [
        (Lane::Tx, "t1"),
        (Lane::Query, "q1"),
        (Lane::Blocks, "b1"),
        (Lane::Tx, "t2"),
        (Lane::Headers, "h1"),
        (Lane::Query, "q2"),
        (Lane::Headers, "h2"),
    ] {
        noop(&h, lane, label).unwrap();
    }
    drop(g);
    settle(&h);
    assert_eq!(
        labels(&h.log_for_tests()),
        ["h1", "h2", "b1", "q1", "q2", "t1", "t2"]
    );

    // Starvation bound: one Tx command behind a stream of queries (and
    // nothing else: every reply is awaited, no settling command runs).
    let g = gate(&h);
    let (tx, rx) = mpsc::channel();
    let send = |lane, label: String| {
        let tx = tx.clone();
        h.call_labeled(lane, label, |_| (), move |()| tx.send(()).unwrap())
            .unwrap()
    };
    send(Lane::Tx, "tx".into());
    for k in 0..40 {
        send(Lane::Query, format!("s{k}"));
    }
    drop(tx);
    drop(g);
    assert_eq!(rx.iter().count(), 41);
    let got = labels(&h.log_for_tests());
    let after: Vec<&String> = got.iter().skip(7).collect();
    let at = after.iter().position(|l| *l == "tx").unwrap();
    assert_eq!(at, STARVATION_LIMIT as usize, "{after:?}");
    drop(h);
    t.join();
}

/// Guarantee 4: during a drain the actor alternates steps with waiting
/// commands, one command between two steps; a query is answered while the
/// drain is still pending; a body submitted mid-drain is answered after the
/// drain, connected ("as if it had arrived after it").
#[test]
fn g4_a_drain_serves_one_command_between_two_steps() {
    let blocks = chain_of(25);
    let mut m = waiting_for_the_first(&blocks[..24]);
    m.set_step_delay_for_tests(Some(Duration::from_millis(20)));
    let (h, t) = actor::spawn(m, config(1));
    let (tx, rx) = mpsc::channel();
    let tx2 = tx.clone();
    h.submit_block_labeled("first".into(), blocks[0].clone(), NOW, move |r| {
        tx2.send(("first", format!("{r:?}"))).unwrap()
    })
    .unwrap();
    // Queries mid-drain: answered while the drain is pending.
    let mut answered_mid_drain = 0;
    for _ in 0..5 {
        let pending = h.call_blocking(Lane::Query, |m| m.sync_pending()).unwrap();
        answered_mid_drain += usize::from(pending);
    }
    assert!(answered_mid_drain >= 4, "{answered_mid_drain}");
    // The next block, submitted mid-drain.
    let tx3 = tx.clone();
    h.submit_block_labeled("late".into(), blocks[24].clone(), NOW, move |r| {
        tx3.send(("late", format!("{r:?}"))).unwrap()
    })
    .unwrap();
    drop(tx);
    let replies: Vec<_> = rx.iter().collect();
    assert_eq!(replies.len(), 2);
    for (who, r) in &replies {
        assert!(r.contains("on_best_chain: true"), "{who}: {r}");
    }
    let log = h.log_for_tests();
    // Between two steps of the drain, at most one command.
    let mut since_step = 0;
    let mut steps = 0;
    for e in &log {
        match e {
            LogEntry::Step { done, .. } => {
                since_step = 0;
                steps += 1;
                if *done {
                    break;
                }
            }
            _ if steps > 0 => {
                since_step += 1;
                assert!(since_step <= 1, "two commands between steps: {log:?}");
            }
            _ => {}
        }
    }
    assert!(steps >= 10, "{steps} steps");
    let m = {
        drop(h);
        t.join().unwrap()
    };
    assert_eq!(m.height(), 25);
}

/// Guarantee 5: `seq` never decreases; the snapshot a reply's receiver reads
/// is at least as new as the one published after its command.
#[test]
fn g5_snapshots_are_monotonic_and_published_before_the_reply() {
    let blocks = chain_of(30);
    let (h, t) = actor::spawn(open(), config(2));
    let reader = {
        let h = h.clone();
        std::thread::spawn(move || {
            let mut last = 0;
            let start = Instant::now();
            while start.elapsed() < Duration::from_millis(500) {
                let s = h.summary();
                assert!(s.seq >= last, "seq went back");
                last = s.seq;
            }
            last
        })
    };
    for b in &blocks {
        let (tx, rx) = mpsc::channel();
        let hh = h.clone();
        h.submit_block(b.clone(), NOW, false, move |r| {
            // Read on the actor thread at the reply: already published.
            tx.send((r, hh.summary())).unwrap();
        })
        .unwrap();
        let (r, seen) = rx.recv().unwrap();
        let s = r.unwrap().unwrap();
        assert_eq!(seen.tip_id, s.id, "the reply's snapshot has the block");
        assert_eq!(seen.height, s.height);
    }
    assert!(reader.join().unwrap() >= 1);
    drop(h);
    t.join();
}

/// Guarantee 6: a command's closure runs whole: another producer's
/// submissions never land inside it.
#[test]
fn g6_a_command_is_atomic() {
    let blocks = chain_of(20);
    let (h, t) = actor::spawn(open(), config(1));
    let submitter = {
        let h = h.clone();
        std::thread::spawn(move || {
            for b in blocks {
                h.submit_block_blocking(b, NOW).unwrap().unwrap();
            }
        })
    };
    for _ in 0..50 {
        let (a, b) = h
            .call_blocking(Lane::Tx, |m| {
                let a = (m.tip_id(), m.height());
                std::thread::sleep(Duration::from_millis(1));
                (a, (m.tip_id(), m.height()))
            })
            .unwrap();
        assert_eq!(a, b);
    }
    submitter.join().unwrap();
    drop(h);
    assert_eq!(t.join().unwrap().height(), 20);
}

/// Guarantee 7: `stop` is served between two steps of a drain; the kept
/// bodies are on disk, so a restart replays the rest and reaches the chain
/// the drain was heading for.
#[test]
fn g7_stop_mid_drain_is_safe_and_the_store_replays() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    let file = || Box::new(FileStore::open(&path).unwrap());
    let blocks = chain_of(30);
    let mut m = open_with(file());
    let hs: Vec<BlockHeader> = blocks.iter().map(|b| b.header).collect();
    m.accept_headers(&hs, NOW).unwrap();
    for b in &blocks[1..] {
        m.submit_block(b.clone(), NOW).unwrap();
    }
    m.set_step_delay_for_tests(Some(Duration::from_millis(30)));
    let (h, t) = actor::spawn(m, config(1));
    h.submit_block(blocks[0].clone(), NOW, false, |_| {})
        .unwrap();
    let start = Instant::now();
    while h.summary().height < 5 {
        assert!(start.elapsed() < Duration::from_secs(30));
        std::thread::sleep(Duration::from_millis(5));
    }
    h.stop();
    let stopped = t.stop_and_join();
    assert!(
        matches!(
            h.call_blocking(Lane::Query, |m| m.height()),
            Err(SendError::Stopped)
        ),
        "a stopped actor refuses commands"
    );
    drop(h);
    let m = stopped.expect("the manager");
    assert!(m.sync_pending(), "stopped mid-drain");
    assert!(m.height() < 30);
    drop(m);
    let m = open_with(file());
    assert_eq!(m.height(), 30, "the replay connects the rest");
    assert_eq!(m.tip_id(), blocks[29].id(params().network_id));
}

// ---------------------------------------------------------------- L7

/// The time a header's RandomX hash takes outside the chain (light-mode
/// order of magnitude): the gap between the PoW jobs and the acceptance.
const POW_GAP: Duration = Duration::from_millis(20);
/// Transaction verifications competing for the chain during L7 (the relay
/// load of F34-5), each holding it this long.
const VERIFIERS: usize = 8;
const VERIFY: Duration = Duration::from_millis(20);

/// The pre-Stage 2 header worker's lock pattern for one announced header
/// (`p2p` `verify_headers` before Stage 2): pre-check, PoW jobs, hashing
/// outside the lock, acceptance, and the best-chain check, each a separate
/// hold of the chain mutex.
fn announce_under_the_mutex(chain: &Mutex<ChainManager>, h: BlockHeader) {
    let one = [h];
    assert!(chain.lock().unwrap().precheck_headers(&one, NOW).is_ok());
    let (pow, jobs) = chain.lock().unwrap().pow_jobs(&one).unwrap();
    pow.compute_parallel(&jobs, 1);
    std::thread::sleep(POW_GAP);
    assert_eq!(chain.lock().unwrap().accept_headers(&one, NOW), Ok(1));
    let _ = chain
        .lock()
        .unwrap()
        .headers()
        .is_on_main(&h.id(params().network_id));
}

/// The Stage 2 header worker's commands for one announced header: the
/// pre-check with the PoW jobs, hashing outside the actor, then the
/// acceptance with the best-chain check (two Headers-lane commands).
fn announce_to_the_actor(chain: &ChainHandle, h: BlockHeader) {
    let (pow, jobs) = chain
        .call_blocking(Lane::Headers, move |m| {
            assert!(m.precheck_headers(&[h], NOW).is_ok());
            m.pow_jobs(&[h]).unwrap()
        })
        .unwrap();
    pow.compute_parallel(&jobs, 1);
    std::thread::sleep(POW_GAP);
    let n = chain
        .call_blocking(Lane::Headers, move |m| {
            let n = m.accept_headers(&[h], NOW);
            let _ = m.headers().is_on_main(&h.id(params().network_id));
            n
        })
        .unwrap();
    assert_eq!(n, Ok(1));
}

/// L7 (F34-7), chain level, before and after: a header announcement during
/// a body drain of heavy steps (`STEP` each, 2 blocks per step), while
/// [`VERIFIERS`] transaction verifications keep competing for the chain.
/// Before Stage 2 each of the header worker's four holds of the unfair
/// mutex waits behind whatever holds it (a step or a verification); the
/// actor serves each of its two Headers-lane commands before the next step
/// and before any queued transaction command. Both latencies are printed;
/// the actor's must stay within one step (and one starved Tx command) per
/// command, plus slack for a loaded machine.
#[test]
fn l7_a_header_announcement_is_accepted_within_a_step_per_command_during_a_drain() {
    const STEP: Duration = Duration::from_millis(150);
    let blocks = chain_of(42);
    let announced = blocks[41].header;
    let prepare = || {
        let mut m = waiting_for_the_first(&blocks[..41]);
        m.set_step_delay_for_tests(Some(STEP));
        m
    };
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let running =
        |stop: &Arc<std::sync::atomic::AtomicBool>| !stop.load(std::sync::atomic::Ordering::SeqCst);

    // Before: the mutex, `submit_block_in_steps`, verifiers holding it.
    let before = {
        let chain = Arc::new(Mutex::new(prepare()));
        let c = chain.clone();
        let first = blocks[0].clone();
        let drain = std::thread::spawn(move || {
            submit_block_in_steps(|| c.lock().unwrap(), first, NOW, 2).unwrap()
        });
        let verifiers: Vec<_> = (0..VERIFIERS)
            .map(|_| {
                let (c, stop) = (chain.clone(), stop.clone());
                std::thread::spawn(move || {
                    while running(&stop) {
                        let g = c.lock().unwrap();
                        std::thread::sleep(VERIFY);
                        drop(g);
                    }
                })
            })
            .collect();
        std::thread::sleep(STEP / 2);
        let start = Instant::now();
        announce_under_the_mutex(&chain, announced);
        let took = start.elapsed();
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        for v in verifiers {
            v.join().unwrap();
        }
        let pending = drain.join().unwrap().height;
        (took, pending)
    };

    // After: the actor, verifications on its Tx lane.
    stop.store(false, std::sync::atomic::Ordering::SeqCst);
    let after = {
        let (h, t) = actor::spawn(prepare(), config(2));
        h.submit_block(blocks[0].clone(), NOW, false, |_| {})
            .unwrap();
        let verifiers: Vec<_> = (0..VERIFIERS)
            .map(|_| {
                let (h, stop) = (h.clone(), stop.clone());
                std::thread::spawn(move || {
                    while running(&stop) {
                        h.call_blocking(Lane::Tx, |_| std::thread::sleep(VERIFY))
                            .unwrap();
                    }
                })
            })
            .collect();
        std::thread::sleep(STEP / 2);
        let start = Instant::now();
        announce_to_the_actor(&h, announced);
        let took = start.elapsed();
        let pending = h.summary().sync_pending;
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        for v in verifiers {
            v.join().unwrap();
        }
        drop(h);
        assert_eq!(t.join().unwrap().header_height(), 42);
        (took, pending)
    };
    println!(
        "L7: header accepted during a drain of {STEP:?} steps with {VERIFIERS} verifiers \
         of {VERIFY:?}: mutex {:?}, actor {:?} (drain still pending: {})",
        before.0, after.0, after.1
    );
    assert!(after.1, "the header was accepted during the drain");
    assert!(
        after.0 < 2 * (STEP + VERIFY) + POW_GAP + Duration::from_millis(300),
        "actor: {:?} for two commands",
        after.0
    );
}

/// F34-5, before and after: relayed-transaction verification competing
/// with a body drain. [`VERIFIERS`] verifications of [`VERIFY`] each run in
/// a loop while a drain of 40 blocks (20 steps of `STEP`) connects. Before
/// Stage 2 they hold the same unfair mutex as the drain's steps, which then
/// wait behind them; in the actor they are Tx-lane commands, served during
/// a drain only once starved. Printed: the drain's time alone and under
/// load, for both; asserted: the actor's drain under load stays within
/// twice its time alone (plus slack).
#[test]
fn f34_5_transaction_verification_does_not_starve_a_drain() {
    const STEP: Duration = Duration::from_millis(20);
    let blocks = chain_of(40);
    let prepare = || {
        let mut m = waiting_for_the_first(&blocks);
        m.set_step_delay_for_tests(Some(STEP));
        m
    };
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let running =
        |stop: &Arc<std::sync::atomic::AtomicBool>| !stop.load(std::sync::atomic::Ordering::SeqCst);
    let mutex_drain = |load: bool| {
        stop.store(false, std::sync::atomic::Ordering::SeqCst);
        let chain = Arc::new(Mutex::new(prepare()));
        let verifiers: Vec<_> = (0..if load { VERIFIERS } else { 0 })
            .map(|_| {
                let (c, stop) = (chain.clone(), stop.clone());
                std::thread::spawn(move || {
                    while running(&stop) {
                        let g = c.lock().unwrap();
                        std::thread::sleep(VERIFY);
                        drop(g);
                    }
                })
            })
            .collect();
        std::thread::sleep(Duration::from_millis(50));
        let start = Instant::now();
        let s = submit_block_in_steps(|| chain.lock().unwrap(), blocks[0].clone(), NOW, 2);
        let took = start.elapsed();
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        for v in verifiers {
            v.join().unwrap();
        }
        assert!(s.unwrap().on_best_chain);
        assert_eq!(chain.lock().unwrap().height(), 40);
        took
    };
    let actor_drain = |load: bool| {
        stop.store(false, std::sync::atomic::Ordering::SeqCst);
        let (h, t) = actor::spawn(prepare(), config(2));
        let verifiers: Vec<_> = (0..if load { VERIFIERS } else { 0 })
            .map(|_| {
                let (h, stop) = (h.clone(), stop.clone());
                std::thread::spawn(move || {
                    while running(&stop) {
                        h.call_blocking(Lane::Tx, |_| std::thread::sleep(VERIFY))
                            .unwrap();
                    }
                })
            })
            .collect();
        std::thread::sleep(Duration::from_millis(50));
        let start = Instant::now();
        let s = h.submit_block_blocking(blocks[0].clone(), NOW).unwrap();
        let took = start.elapsed();
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        for v in verifiers {
            v.join().unwrap();
        }
        assert!(s.unwrap().on_best_chain);
        drop(h);
        assert_eq!(t.join().unwrap().height(), 40);
        took
    };
    let (m0, m1) = (mutex_drain(false), mutex_drain(true));
    let (a0, a1) = (actor_drain(false), actor_drain(true));
    println!(
        "F34-5: a 40-block drain ({STEP:?} steps of 2 blocks), alone / with {VERIFIERS} \
         verifiers of {VERIFY:?}: mutex {m0:?} / {m1:?}, actor {a0:?} / {a1:?}"
    );
    assert!(
        a1 < 2 * a0 + Duration::from_millis(300),
        "actor under load {a1:?}, alone {a0:?}"
    );
}

// ---------------------------------------------------------------- L8

/// L8, chain level: a full Tx lane refuses at once (`Full`, nothing
/// queued, the caller is never blocked), while the Blocks lane takes the
/// most blocks the P2P layer can have in flight during the same stall; every
/// queued command is answered once the stall ends. (The P2P half, no
/// penalty for the dropped relay, is `p2p/tests/network.rs`
/// `l8_...`.)
#[test]
fn l8_a_full_tx_lane_refuses_while_the_blocks_lane_takes_every_block() {
    let cfg = ActorConfig {
        capacity: [64, DEFAULT_BLOCKS_CAPACITY, 1024, 2],
        ..ActorConfig::default()
    };
    let blocks = chain_of(1);
    let (h, t) = actor::spawn(open(), cfg);
    let g = gate(&h);
    let (tx, rx) = mpsc::channel();
    let mut refused = 0;
    for _ in 0..5 {
        let tx = tx.clone();
        let start = Instant::now();
        match h.call(Lane::Tx, |_| (), move |()| tx.send("tx").unwrap()) {
            Ok(()) => {}
            Err(r) => {
                assert_eq!(r.error, SendError::Full(Lane::Tx));
                refused += 1;
            }
        }
        assert!(start.elapsed() < Duration::from_millis(100), "never waits");
    }
    assert_eq!(refused, 3);
    // (64 + 8) peers × 3 blocks in their windows + 8 unrequested.
    let in_flight = (64 + 8) * 3 + 8;
    for _ in 0..in_flight {
        let tx = tx.clone();
        h.submit_block(blocks[0].clone(), NOW, false, move |_| {
            tx.send("block").unwrap()
        })
        .expect("the Blocks lane never refuses a block in flight");
    }
    drop(tx);
    drop(g);
    let got: Vec<&str> = rx.iter().collect();
    assert_eq!(got.iter().filter(|x| **x == "tx").count(), 2);
    assert_eq!(got.iter().filter(|x| **x == "block").count(), in_flight);
    drop(h);
    assert_eq!(t.join().unwrap().height(), 1);
}

// ---------------------------------------------------------------- F1

const F1_CHILD: &str = "BLACKSILK_ACTOR_F1_CHILD";

/// The child half of F1: connects three blocks through the actor, then
/// injects a panic into it. The process must exit with
/// `POISONED_EXIT_CODE` from the actor thread.
fn f1_child(dir: &str) -> ! {
    let path = std::path::Path::new(dir).join("blocks.dat");
    let (h, _t) = actor::spawn(
        open_with(Box::new(FileStore::open(&path).unwrap())),
        ActorConfig::default(),
    );
    for i in 0..3 {
        let b = h
            .call_blocking(Lane::Query, move |m| stall::next_block(m, 0xF1 + i, i))
            .unwrap();
        h.submit_block_blocking(b, NOW).unwrap().unwrap();
    }
    h.inject_panic_for_tests().unwrap();
    std::thread::sleep(Duration::from_secs(60));
    panic!("the actor's panic did not stop the process");
}

/// F1 (fail-stop): a panic in the chain actor stops the process with
/// `POISONED_EXIT_CODE` (70), as a poisoned chain lock did; a restart
/// replays the store to the same chain. Runs itself as a child process.
#[test]
fn f1_a_panic_in_the_actor_exits_with_70_and_the_store_replays() {
    if let Ok(dir) = std::env::var(F1_CHILD) {
        f1_child(&dir);
    }
    let dir = tempfile::tempdir().unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "f1_a_panic_in_the_actor_exits_with_70_and_the_store_replays",
            "--test-threads=1",
            "--nocapture",
        ])
        .env(F1_CHILD, dir.path())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(POISONED_EXIT_CODE), "{status:?}");
    let m = open_with(Box::new(
        FileStore::open(dir.path().join("blocks.dat")).unwrap(),
    ));
    assert_eq!(m.height(), 3, "the store replays every connected block");
}
