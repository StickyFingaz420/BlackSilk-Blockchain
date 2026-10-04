//! The equivalence harness of the chain-actor work (research dossier 34;
//! docs/reviews/chain-actor-stage2.md §5): whatever schedules the chain's
//! writes, the consensus outcome is the one of plain sequential submission.
//!
//! **E1.** A seeded random delivery script (bodies in random order,
//! duplicates, header batches along random branch prefixes) runs on four
//! drivers:
//! - **unbounded**: `ChainManager::submit_block` per body (the oracle);
//! - **stepped**: `submit_block_in_steps` through a mutex, with a random
//!   step budget (what the P2P block worker and RPC `/block` did before
//!   Stage 2);
//! - **interleaved**: `submit_block_bounded`, with `sync_step` calls at random
//!   points between deliveries, so bodies and headers arrive mid-drain;
//! - **actor**: the chain actor (`blacksilk_chain::actor`, Stage 2) with one
//!   producer, the same random step budget, headers on the Headers lane and
//!   bodies on the Blocks lane.
//!
//! The block universe has a reorganization (a heavier branch forking below
//! the tip), a lighter side branch, and a body that fails validation on a
//! branch that is heavier than the main chain until it is found invalid.
//! Stepped and actor must match the oracle per call (every verdict) and in
//! final state; interleaved must match it in final state and in every final
//! verdict. The final state compared is the connected chain, the header tree
//! tip, the output set, the PX root, invalid marks, kept bodies, the mempool
//! and the exact store bytes in append order. Every driver's published chain
//! snapshot must equal the one recomputed from its final state.
//!
//! **E2 (linearization replay).** Four producer threads send random bursts
//! of commands on three lanes (header batches, bodies, reads) to one actor.
//! Replaying the actor's applied-command log (test-only `test-hooks`
//! feature) on a bare manager gives every producer's reply and the final
//! state; each producer's commands on one lane ran in the order sent.
//!
//! **E3 (snapshot consistency).** Every snapshot the actor published equals
//! the replayed manager's, recomputed from scratch, at the same `seq`.
//!
//! **E4 (replay equals live).** Restarting from the store the actor wrote
//! gives the oracle's state.

#[path = "support/stall.rs"]
mod stall;

use blacksilk_chain::actor::{self, ActorConfig, Lane, LogEntry};
use blacksilk_chain::block::Block;
use blacksilk_chain::manager::{submit_block_in_steps, ChainManager, Template};
use blacksilk_chain::store::{FileStore, StoredBlock};
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, PowFunction};
use blacksilk_crypto::keys::{SubaddressIndex, WalletKeys};
use blacksilk_tx::builder::{build_coinbase, Payment};
use blacksilk_tx::params::TxRules;
use blacksilk_tx::types::Transaction;
use blacksilk_tx::validate::{ChainView, OutputRecord};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use stall::{SlowStore, StallControl};
use std::collections::{HashMap, HashSet};
use std::sync::{mpsc, Arc, Mutex};

struct ZeroPow;
impl PowFunction for ZeroPow {
    fn pow_hash(&self, _: &Hash, _: &blacksilk_consensus::PowBlob) -> Hash {
        [0; 32]
    }
}

const NOW: u64 = u64::MAX / 2;

fn params() -> ChainParams {
    ChainParams::regtest()
}

fn open() -> (ChainManager, Arc<StallControl>) {
    let p = params();
    let (store, ctl) = SlowStore::new();
    let m = ChainManager::open(
        p.clone(),
        TxRules::for_chain(&p),
        Arc::new(ZeroPow),
        Box::new(store),
        [9; 32],
    )
    .unwrap();
    (m, ctl)
}

fn id(b: &Block) -> Hash {
    b.id(params().network_id)
}

/// A coinbase-only block from `t`, claiming `extra` more than it may.
fn build(t: &Template, miner: &WalletKeys, rng: &mut ChaCha20Rng, extra: u64) -> Block {
    let cb = build_coinbase(
        t.height,
        &[Payment {
            address: miner.address(SubaddressIndex::PRIMARY),
            amount: t.reward + extra,
        }],
        &miner.hedge_secret(),
        rng,
    )
    .unwrap();
    let txs = vec![Transaction::Coinbase(cb)];
    let ids: Vec<Hash> = txs.iter().map(Transaction::hash).collect();
    let (output_count, output_root) = t.outputs_after(&txs);
    let header = BlockHeader {
        version: t.version,
        height: t.height,
        prev_id: t.prev_id,
        timestamp: t
            .min_timestamp
            .max(params().genesis.timestamp + 120 * t.height),
        difficulty: t.difficulty,
        tx_root: tx_root(&ids),
        nonce: 0,
        output_count,
        output_root,
        px_root: t.px_root,
    };
    Block { header, txs }
}

/// The block universe and, per block, its path of headers from genesis.
struct Universe {
    blocks: Vec<Block>,
    paths: Vec<Vec<BlockHeader>>,
}

/// - A: 12 blocks on genesis (the first main chain);
/// - B: 14 blocks on A[2] (heavier: a reorganization 9 blocks deep);
/// - C: 3 blocks on A[7] (a lighter side branch);
/// - X: an over-claiming block on B[9], valid header, invalid body; with it,
///   B[..10] + X outweighs A, so X is connected (and fails) whenever it
///   completes before B's tip.
fn universe() -> Universe {
    let (mut src, _) = open();
    let mut rng = ChaCha20Rng::seed_from_u64(0xE1);
    let (miner, _) = WalletKeys::generate(&mut rng);
    let mut blocks: Vec<Block> = Vec::new();
    let mut paths: Vec<Vec<BlockHeader>> = Vec::new();
    let mut extend = |src: &mut ChainManager,
                      blocks: &mut Vec<Block>,
                      paths: &mut Vec<Vec<BlockHeader>>,
                      parent: Option<usize>,
                      n: usize|
     -> Vec<usize> {
        let mut out = Vec::new();
        let mut prev = parent;
        for _ in 0..n {
            let parent_id = prev.map_or(params().genesis_id(), |i| id(&blocks[i]));
            let t = src.template_on(&parent_id).unwrap();
            let b = build(&t, &miner, &mut rng, 0);
            src.submit_block(b.clone(), NOW).unwrap();
            let mut path = prev.map_or_else(Vec::new, |i| paths[i].clone());
            path.push(b.header);
            blocks.push(b);
            paths.push(path);
            prev = Some(blocks.len() - 1);
            out.push(blocks.len() - 1);
        }
        out
    };
    let a = extend(&mut src, &mut blocks, &mut paths, None, 12);
    let b = extend(&mut src, &mut blocks, &mut paths, Some(a[2]), 14);
    let _c = extend(&mut src, &mut blocks, &mut paths, Some(a[7]), 3);
    assert_eq!(src.height(), 17, "B is the heavier branch");
    let t = src.template_on(&id(&blocks[b[9]])).unwrap();
    let x = build(&t, &miner, &mut rng, 1);
    let mut path = paths[b[9]].clone();
    path.push(x.header);
    blocks.push(x);
    paths.push(path);
    Universe { blocks, paths }
}

#[derive(Clone, Debug)]
enum Op {
    Body(usize),
    /// The headers of block `.0`'s path up to its `.1`-th header.
    Headers(usize, usize),
}

/// Header-first delivery, as the node syncs: every body once, in random
/// order, each after a batch carrying its headers from genesis (unless an
/// earlier batch covered it). Plus random partial header batches, random
/// duplicate bodies, and bodies sent before their headers (refused as
/// orphans unless the parent is known, identically for every driver).
fn script(u: &Universe, rng: &mut ChaCha20Rng) -> Vec<Op> {
    let mut order: Vec<usize> = (0..u.blocks.len()).collect();
    for i in (1..order.len()).rev() {
        order.swap(i, rng.next_u32() as usize % (i + 1));
    }
    let mut covered: HashSet<Hash> = HashSet::new();
    let mut ops = Vec::new();
    let batch = |ops: &mut Vec<Op>, covered: &mut HashSet<Hash>, j: usize, len: usize| {
        covered.extend(u.paths[j][..len].iter().map(|h| h.id(params().network_id)));
        ops.push(Op::Headers(j, len));
    };
    for (k, &i) in order.iter().enumerate() {
        if rng.next_u32().is_multiple_of(4) {
            let j = rng.next_u32() as usize % u.blocks.len();
            let len = 1 + rng.next_u32() as usize % u.paths[j].len();
            batch(&mut ops, &mut covered, j, len);
        }
        if rng.next_u32().is_multiple_of(8) {
            ops.push(Op::Body(i));
        }
        if !covered.contains(&id(&u.blocks[i])) {
            batch(&mut ops, &mut covered, i, u.paths[i].len());
        }
        ops.push(Op::Body(i));
        if k > 0 && rng.next_u32().is_multiple_of(6) {
            ops.push(Op::Body(order[rng.next_u32() as usize % k]));
        }
    }
    ops
}

/// Everything consensus-relevant a driver ends with.
#[derive(Debug, PartialEq)]
struct Outcome {
    tip: Hash,
    height: u64,
    generated: u64,
    header_height: u64,
    best_header: Hash,
    deepest_reorg: usize,
    connected: Vec<Hash>,
    outputs: Vec<OutputRecord>,
    px_root: [u32; 8],
    invalid: Vec<Option<String>>,
    bodies: Vec<bool>,
    verdicts: Vec<String>,
    mempool: usize,
    store: Vec<StoredBlock>,
}

fn outcome(m: &ChainManager, ctl: &StallControl, u: &Universe) -> Outcome {
    assert!(!m.sync_pending(), "the drain is finished");
    // What a reader without the chain lock sees (Stage 1 summary) is the
    // final state, whatever driver published it.
    let s = m.summary();
    assert_eq!(
        (s.tip_id, s.height, s.header_height, s.best_header_id),
        (
            m.tip_id(),
            m.height(),
            m.header_height(),
            m.best_header_id()
        )
    );
    assert_eq!(s.locator, m.locator());
    assert_eq!((s.mempool_txs, s.sync_pending), (m.mempool().len(), false));
    // The whole Stage 2 snapshot, recomputed from scratch.
    assert_eq!(*s, m.summary_now(s.seq));
    let state = m.state();
    Outcome {
        tip: m.tip_id(),
        height: m.height(),
        generated: m.generated(),
        header_height: m.header_height(),
        best_header: m.best_header_id(),
        deepest_reorg: m.deepest_reorg(),
        connected: (1..=m.height())
            .map(|h| id(&m.block_at(h).unwrap()))
            .collect(),
        outputs: (0..state.output_count())
            .map(|i| state.output(i).unwrap())
            .collect(),
        px_root: state.px().root(),
        invalid: u
            .blocks
            .iter()
            .map(|b| m.invalid_reason(&id(b)).map(|e| format!("{e:?}")))
            .collect(),
        bodies: u.blocks.iter().map(|b| m.has_body(&id(b))).collect(),
        verdicts: u
            .blocks
            .iter()
            .map(|b| format!("{:?}", m.verdict(id(b), b.header.height)))
            .collect(),
        mempool: m.mempool().len(),
        store: ctl.appended(),
    }
}

fn headers(u: &Universe, j: usize, len: usize) -> &[BlockHeader] {
    &u.paths[j][..len]
}

/// The oracle: plain sequential submission. Returns every call's result.
fn unbounded(u: &Universe, ops: &[Op]) -> (Outcome, Vec<String>) {
    let (mut m, ctl) = open();
    let results = ops
        .iter()
        .map(|op| match *op {
            Op::Body(i) => format!("{:?}", m.submit_block(u.blocks[i].clone(), NOW)),
            Op::Headers(j, len) => format!("{:?}", m.accept_headers(headers(u, j, len), NOW)),
        })
        .collect();
    (outcome(&m, &ctl, u), results)
}

/// `submit_block_in_steps` through a mutex, as the node does today.
fn stepped(u: &Universe, ops: &[Op], budget: usize) -> (Outcome, Vec<String>) {
    let (m, ctl) = open();
    let shared = Mutex::new(m);
    let results = ops
        .iter()
        .map(|op| match *op {
            Op::Body(i) => format!(
                "{:?}",
                submit_block_in_steps(|| shared.lock().unwrap(), u.blocks[i].clone(), NOW, budget)
            ),
            Op::Headers(j, len) => format!(
                "{:?}",
                shared
                    .lock()
                    .unwrap()
                    .accept_headers(headers(u, j, len), NOW)
            ),
        })
        .collect();
    let m = shared.into_inner().unwrap();
    (outcome(&m, &ctl, u), results)
}

/// Bounded submissions with drain steps at random points between them.
fn interleaved(u: &Universe, ops: &[Op], budget: usize, rng: &mut ChaCha20Rng) -> Outcome {
    let (mut m, ctl) = open();
    for op in ops {
        while m.sync_pending() && rng.next_u32().is_multiple_of(2) {
            m.sync_step(budget);
        }
        match *op {
            Op::Body(i) => {
                let _ = m.submit_block_bounded(u.blocks[i].clone(), NOW, budget);
            }
            Op::Headers(j, len) => {
                let _ = m.accept_headers(headers(u, j, len), NOW);
            }
        }
    }
    while !m.sync_step(budget) {}
    outcome(&m, &ctl, u)
}

fn config(budget: usize) -> ActorConfig {
    ActorConfig {
        step_budget: budget,
        ..ActorConfig::default()
    }
}

/// The chain actor with one producer, every command awaited: headers on the
/// Headers lane, bodies on the Blocks lane (Stage 2).
fn actor_driver(u: &Universe, ops: &[Op], budget: usize) -> (Outcome, Vec<String>) {
    let (m, ctl) = open();
    let (h, thread) = actor::spawn(m, config(budget));
    let results = ops
        .iter()
        .map(|op| match *op {
            Op::Body(i) => format!(
                "{:?}",
                h.submit_block_blocking(u.blocks[i].clone(), NOW).unwrap()
            ),
            Op::Headers(j, len) => {
                let hs = headers(u, j, len).to_vec();
                format!(
                    "{:?}",
                    h.call_blocking(Lane::Headers, move |m| m.accept_headers(&hs, NOW))
                        .unwrap()
                )
            }
        })
        .collect();
    let seen = h.summary();
    drop(h);
    let m = thread.join().expect("the actor hands the manager back");
    assert_eq!(seen, m.summary(), "the last publication is the final one");
    (outcome(&m, &ctl, u), results)
}

#[test]
fn e1_bounded_interleaved_and_actor_submission_equal_sequential_submission() {
    let u = universe();
    let mut reorgs = 0;
    let mut invalid_seen = 0;
    for seed in 0..48u64 {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let ops = script(&u, &mut rng);
        let budget = 1 + rng.next_u32() as usize % 4;
        let (oracle, oracle_results) = unbounded(&u, &ops);
        assert_eq!(oracle.height, 17, "seed {seed}: B wins");
        reorgs += usize::from(oracle.deepest_reorg > 0);
        invalid_seen += usize::from(oracle.invalid.iter().any(Option::is_some));

        let (s, s_results) = stepped(&u, &ops, budget);
        for (k, (a, b)) in oracle_results.iter().zip(&s_results).enumerate() {
            assert_eq!(
                a, b,
                "seed {seed}, budget {budget}: call {k} ({:?})",
                ops[k]
            );
        }
        assert_eq!(
            s, oracle,
            "seed {seed}, budget {budget}: stepped final state"
        );

        let i = interleaved(&u, &ops, budget, &mut rng);
        assert_eq!(
            i, oracle,
            "seed {seed}, budget {budget}: interleaved final state"
        );

        let (a, a_results) = actor_driver(&u, &ops, budget);
        for (k, (x, y)) in oracle_results.iter().zip(&a_results).enumerate() {
            assert_eq!(
                x, y,
                "seed {seed}, budget {budget}: actor call {k} ({:?})",
                ops[k]
            );
        }
        assert_eq!(a, oracle, "seed {seed}, budget {budget}: actor final state");
    }
    // The script exercises what it is meant to.
    assert!(reorgs > 0, "no seed reorganized");
    assert!(invalid_seen > 0, "no seed connected the invalid body");
}

// ---------------------------------------------------------------- E2, E3

/// One producer command of E2.
#[derive(Clone, Debug)]
enum Cmd {
    Op(Op),
    /// A read on the Query lane: the header tip, the missing bodies and the
    /// headers after genesis (their count).
    Read,
}

fn run_read(m: &ChainManager) -> String {
    let hs = m.headers_after(&[params().genesis_id()], &[0; 32], 2000);
    format!(
        "{:?} {:?} {}",
        m.best_header_id(),
        m.missing_bodies(16),
        hs.len()
    )
}

/// Replays `log` on a fresh manager: every reply (by label) and every
/// published snapshot must come out the same (E2, E3). Returns the
/// replayed manager and the replies it computed.
fn replay(
    u: &Universe,
    cmds: &HashMap<String, Cmd>,
    log: &[LogEntry],
    budget: usize,
) -> (
    ChainManager,
    Arc<stall::StallControl>,
    HashMap<String, String>,
) {
    let (mut m, ctl) = open();
    let mut replies = HashMap::new();
    let mut pending: HashMap<String, (Hash, u64)> = HashMap::new();
    let check = |m: &ChainManager, snapshot: &Arc<blacksilk_chain::manager::ChainSummary>| {
        m.publish_summary();
        assert_eq!(m.summary(), *snapshot, "E3: the published snapshot");
        assert_eq!(
            m.summary_now(snapshot.seq),
            **snapshot,
            "E3: recomputed at seq {}",
            snapshot.seq
        );
    };
    for e in log {
        match e {
            LogEntry::Run { label, snapshot } => {
                let r = match &cmds[label] {
                    Cmd::Op(Op::Headers(j, len)) => {
                        format!("{:?}", m.accept_headers(headers(u, *j, *len), NOW))
                    }
                    Cmd::Read => run_read(&m),
                    Cmd::Op(Op::Body(_)) => unreachable!("bodies are submissions"),
                };
                check(&m, snapshot);
                replies.insert(label.clone(), r);
            }
            LogEntry::Submit {
                label,
                first,
                answered,
                snapshot,
            } => {
                let Cmd::Op(Op::Body(i)) = cmds[label] else {
                    unreachable!("a submission is a body")
                };
                let r = m.submit_block_bounded(u.blocks[i].clone(), NOW, budget);
                if let Ok(s) = &r {
                    if s.body_kept {
                        pending.insert(label.clone(), (s.id, s.height));
                    }
                }
                let r = format!("{:?}", Some(r));
                assert_eq!(&r, first, "E2: first call of {label}");
                check(&m, snapshot);
                if *answered {
                    replies.insert(label.clone(), r);
                }
            }
            LogEntry::Step {
                done,
                verdicts,
                snapshot,
            } => {
                assert_eq!(m.sync_step(budget), *done, "E2: step");
                check(&m, snapshot);
                for (label, v) in verdicts {
                    let (id, height) = pending.remove(label).expect("a waiting submission");
                    let r = format!("{:?}", Some(m.verdict(id, height)));
                    assert_eq!(&r, v, "E2: verdict of {label}");
                    replies.insert(label.clone(), r);
                }
            }
        }
    }
    assert!(pending.is_empty(), "every submission was answered");
    (m, ctl, replies)
}

/// E2 and E3: four producers, random bursts on three lanes, one actor.
#[test]
fn e2_e3_concurrent_producers_linearize_and_every_snapshot_is_consistent() {
    let u = universe();
    let mut reorgs = 0;
    for seed in 0..12u64 {
        let mut rng = ChaCha20Rng::seed_from_u64(0xE2_00 + seed);
        let ops = script(&u, &mut rng);
        let budget = 1 + rng.next_u32() as usize % 3;
        // Deal the script out to four producers, with reads mixed in.
        let mut per: Vec<Vec<(String, Cmd)>> = vec![Vec::new(); 4];
        for (k, op) in ops.iter().enumerate() {
            let p = rng.next_u32() as usize % 4;
            per[p].push((format!("p{p}-{k}"), Cmd::Op(op.clone())));
            if rng.next_u32().is_multiple_of(5) {
                let q = rng.next_u32() as usize % 4;
                per[q].push((format!("p{q}-r{k}"), Cmd::Read));
            }
        }
        let cmds: HashMap<String, Cmd> = per.iter().flatten().cloned().collect();
        let bursts: Vec<u64> = (0..4).map(|_| rng.next_u64()).collect();

        let (m, ctl) = open();
        let (h, thread) = actor::spawn(m, config(budget));
        let producers: Vec<_> = per
            .into_iter()
            .zip(bursts)
            .map(|(mine, burst_seed)| {
                let (h, blocks, paths) = (h.clone(), u.blocks.clone(), u.paths.clone());
                std::thread::spawn(move || {
                    let mut rng = ChaCha20Rng::seed_from_u64(burst_seed);
                    let mut got = Vec::new();
                    let mut sent = Vec::new();
                    let mut rest = mine.as_slice();
                    while !rest.is_empty() {
                        // A burst of up to four commands, sent without
                        // waiting, then every reply of the burst.
                        let n = (1 + rng.next_u32() as usize % 4).min(rest.len());
                        let (burst, tail) = rest.split_at(n);
                        rest = tail;
                        let (tx, rx) = mpsc::channel();
                        for (label, cmd) in burst {
                            let (tx, l) = (tx.clone(), label.clone());
                            let lane = match cmd {
                                Cmd::Op(Op::Headers(j, len)) => {
                                    let hs = paths[*j][..*len].to_vec();
                                    h.call_labeled(
                                        Lane::Headers,
                                        label.clone(),
                                        move |m| format!("{:?}", m.accept_headers(&hs, NOW)),
                                        move |r| tx.send((l, r)).unwrap(),
                                    )
                                    .unwrap();
                                    Lane::Headers
                                }
                                Cmd::Op(Op::Body(i)) => {
                                    h.submit_block_labeled(
                                        label.clone(),
                                        blocks[*i].clone(),
                                        NOW,
                                        move |r| tx.send((l, format!("{r:?}"))).unwrap(),
                                    )
                                    .unwrap();
                                    Lane::Blocks
                                }
                                Cmd::Read => {
                                    h.call_labeled(
                                        Lane::Query,
                                        label.clone(),
                                        |m| run_read(m),
                                        move |r| tx.send((l, r)).unwrap(),
                                    )
                                    .unwrap();
                                    Lane::Query
                                }
                            };
                            sent.push((label.clone(), lane));
                        }
                        drop(tx);
                        got.extend(rx.iter());
                        assert_eq!(got.len(), sent.len());
                    }
                    (sent, got)
                })
            })
            .collect();
        let mut sent = Vec::new();
        let mut replies = HashMap::new();
        for p in producers {
            let (s, g) = p.join().unwrap();
            sent.push(s);
            replies.extend(g);
        }
        let log = h.log_for_tests();
        drop(h);
        let live = thread.join().expect("the manager");

        // Guarantee 2: per producer and lane, the commands ran in the order
        // they were sent.
        let position: HashMap<&str, usize> = log
            .iter()
            .enumerate()
            .filter_map(|(k, e)| match e {
                LogEntry::Run { label, .. } | LogEntry::Submit { label, .. } => {
                    Some((label.as_str(), k))
                }
                LogEntry::Step { .. } => None,
            })
            .collect();
        assert_eq!(position.len(), cmds.len(), "every command ran once");
        for s in &sent {
            for lane in Lane::ALL {
                let order: Vec<usize> = s
                    .iter()
                    .filter(|(_, l)| *l == lane)
                    .map(|(label, _)| position[label.as_str()])
                    .collect();
                assert!(
                    order.windows(2).all(|w| w[0] < w[1]),
                    "seed {seed}: FIFO on {lane:?}"
                );
            }
        }
        // Guarantee 5: publications never go back.
        let seqs: Vec<u64> = log
            .iter()
            .map(|e| match e {
                LogEntry::Run { snapshot, .. }
                | LogEntry::Submit { snapshot, .. }
                | LogEntry::Step { snapshot, .. } => snapshot.seq,
            })
            .collect();
        assert!(seqs.windows(2).all(|w| w[0] <= w[1]), "seed {seed}: seq");

        let (replayed, rctl, replayed_replies) = replay(&u, &cmds, &log, budget);
        assert_eq!(replayed_replies, replies, "seed {seed}: E2 replies");
        let (lo, ro) = (outcome(&live, &ctl, &u), outcome(&replayed, &rctl, &u));
        assert_eq!(lo, ro, "seed {seed}: E2 final state");
        reorgs += usize::from(lo.deepest_reorg > 0);
    }
    assert!(reorgs > 0, "no seed reorganized");
}

// ---------------------------------------------------------------- E4

/// E4: the actor's store, replayed at a restart, gives the oracle's state
/// (replay equals live under the actor; the store bytes are compared by E1).
#[test]
fn e4_a_restart_from_the_actors_store_gives_the_oracle_state() {
    let u = universe();
    for seed in 0..6u64 {
        let mut rng = ChaCha20Rng::seed_from_u64(0xE4_00 + seed);
        let ops = script(&u, &mut rng);
        let budget = 1 + rng.next_u32() as usize % 4;
        let (oracle, _) = unbounded(&u, &ops);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        let open_file = || {
            let p = params();
            ChainManager::open(
                p.clone(),
                TxRules::for_chain(&p),
                Arc::new(ZeroPow),
                Box::new(FileStore::open(&path).unwrap()),
                [9; 32],
            )
            .unwrap()
        };
        let (h, thread) = actor::spawn(open_file(), config(budget));
        for op in &ops {
            match *op {
                Op::Body(i) => {
                    let _ = h.submit_block_blocking(u.blocks[i].clone(), NOW).unwrap();
                }
                Op::Headers(j, len) => {
                    let hs = headers(&u, j, len).to_vec();
                    let _ = h.call_blocking(Lane::Headers, move |m| m.accept_headers(&hs, NOW));
                }
            }
        }
        drop(h);
        drop(thread.join().expect("the manager"));
        let restarted = open_file();
        let (_, ctl) = open();
        let mut r = outcome(&restarted, &ctl, &u);
        let mut o = Outcome { ..oracle };
        // The restarted manager knows only what the store holds: kept
        // bodies and their headers (header-only branches are downloaded
        // again), and its store handle is a file, not the recording one.
        r.store = Vec::new();
        o.store = Vec::new();
        assert_eq!(
            (
                r.tip,
                r.height,
                r.generated,
                &r.connected,
                &r.outputs,
                r.px_root
            ),
            (
                o.tip,
                o.height,
                o.generated,
                &o.connected,
                &o.outputs,
                o.px_root
            ),
            "seed {seed}: the restarted chain"
        );
        assert_eq!(r.invalid, o.invalid, "seed {seed}: invalid marks");
        assert_eq!(r.bodies, o.bodies, "seed {seed}: kept bodies");
    }
}
