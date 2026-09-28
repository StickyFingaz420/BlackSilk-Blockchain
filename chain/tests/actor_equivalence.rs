//! E1, the equivalence harness of the chain-actor work (research dossier 34,
//! Stage 0): whatever schedules the chain's writes, the consensus outcome is
//! the one of plain sequential submission.
//!
//! A seeded random delivery script (bodies in random order, duplicates,
//! header batches along random branch prefixes) runs on three drivers:
//! - **unbounded**: `ChainManager::submit_block` per body (the oracle);
//! - **stepped**: `submit_block_in_steps` through a mutex, with a random
//!   step budget (what the P2P block worker and RPC `/block` do today);
//! - **interleaved**: `submit_block_bounded`, with `sync_step` calls at random
//!   points between deliveries, so bodies and headers arrive mid-drain (the
//!   schedule a single-writer actor produces).
//!
//! The block universe has a reorganization (a heavier branch forking below
//! the tip), a lighter side branch, and a body that fails validation on a
//! branch that is heavier than the main chain until it is found invalid.
//! Stepped must match the oracle per call (every verdict) and in final state;
//! interleaved must match it in final state and in every final verdict. The
//! final state compared is the connected chain, the header tree tip, the
//! output set, the PX root, invalid marks, kept bodies, the mempool and the
//! exact store bytes in append order.
//!
//! Every driver's published chain summary (Stage 1) must describe its final
//! state. This starts as a manager-only oracle; Stage 2 adds the actor as a
//! fourth driver (docs/reviews/chain-actor-stage2.md).

#[path = "support/stall.rs"]
mod stall;

use blacksilk_chain::block::Block;
use blacksilk_chain::manager::{submit_block_in_steps, ChainManager, Template};
use blacksilk_chain::store::StoredBlock;
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
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

struct ZeroPow;
impl PowFunction for ZeroPow {
    fn pow_hash(&self, _: &Hash, _: &[u8]) -> Hash {
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

#[test]
fn e1_bounded_and_interleaved_submission_equal_sequential_submission() {
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
    }
    // The script exercises what it is meant to.
    assert!(reorgs > 0, "no seed reorganized");
    assert!(invalid_seen > 0, "no seed connected the invalid body");
}
