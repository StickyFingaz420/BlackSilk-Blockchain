//! RT-W3 regressions (red-team demonstrations turned around; decisions
//! "RT-W3"). Each was written to fail on the base commit cbd50c6.
//!
//! - **RTW3-1:** three bodiless headers on a synced node's tip closed the
//!   W2-09b template gate. With the catch-up latch they never do, and a
//!   node still catching up keeps refusing templates.
//! - **RTW3-7:** `FileStore::repair` (`--repair-store`) moved the operator's
//!   verdicts written after the damage aside with the damaged region, so
//!   the node connected the block the operator had invalidated.
//! - **RTW3-8:** a heavier chain refused only because of an operator verdict
//!   is reported (`ChainManager::operator_fork`, the published snapshot),
//!   live and after a restart, and the report ends when the node's own
//!   chain outweighs it.

use blacksilk_chain::block::Block;
use blacksilk_chain::manager::{ChainManager, OperatorMark, OperatorMarked, Template};
use blacksilk_chain::store::{BlockStore, FileStore, MemoryStore};
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, PowFunction};
use blacksilk_crypto::keys::{SubaddressIndex, WalletKeys};
use blacksilk_tx::builder::{build_coinbase, Payment};
use blacksilk_tx::params::TxRules;
use blacksilk_tx::types::Transaction;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::io;
use std::path::Path;
use std::sync::Arc;

struct ZeroPow;
impl PowFunction for ZeroPow {
    fn pow_hash(&self, _: &Hash, _: &blacksilk_consensus::PowBlob) -> Hash {
        [0; 32]
    }
}

fn regtest() -> ChainParams {
    ChainParams::regtest()
}

fn open_with(p: &ChainParams, store: Box<dyn BlockStore>) -> io::Result<ChainManager> {
    ChainManager::open(
        p.clone(),
        TxRules::for_chain(p),
        Arc::new(ZeroPow),
        store,
        [7; 32],
    )
}

fn open_path(path: &Path) -> io::Result<ChainManager> {
    open_with(&regtest(), Box::new(FileStore::open(path).unwrap()))
}

fn volatile(p: &ChainParams) -> ChainManager {
    open_with(p, Box::<MemoryStore>::default()).unwrap()
}

struct Miner {
    keys: WalletKeys,
    rng: ChaCha20Rng,
}

impl Miner {
    fn new(seed: u64) -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let (keys, _) = WalletKeys::generate(&mut rng);
        Self { keys, rng }
    }

    fn build(&mut self, p: &ChainParams, t: &Template, nonce: u64) -> Block {
        let cb = build_coinbase(
            t.height,
            &[Payment {
                address: self.keys.address(SubaddressIndex::PRIMARY),
                amount: t.reward,
            }],
            &self.keys.hedge_secret(),
            &mut self.rng,
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
                .max(p.genesis.timestamp + p.target_block_time * t.height),
            difficulty: t.difficulty,
            tx_root: tx_root(&ids),
            nonce,
            output_count,
            output_root,
            px_root: t.px_root,
        };
        Block { header, txs }
    }

    /// `n` blocks on `m`'s tip, each submitted at its own timestamp (a node
    /// at the network's tip).
    fn mine(&mut self, m: &mut ChainManager, n: usize, nonce: u64) -> Vec<Block> {
        let p = m.params().clone();
        (0..n)
            .map(|_| {
                let b = self.build(&p, &m.template(), nonce);
                m.submit_block(b.clone(), b.header.timestamp).unwrap();
                b
            })
            .collect()
    }
}

fn id(p: &ChainParams, b: &Block) -> Hash {
    b.id(p.network_id)
}

/// RTW3-1, the RT-W3 demonstration turned around: a minority attacker mines
/// 3 blocks on the victim's tip privately and announces only their headers.
/// The victim, synced, keeps serving templates (on regtest and on testnet
/// parameters, where the clock rule applies too), and so does it after a
/// much longer bodiless lead.
#[test]
fn three_bodiless_headers_do_not_close_the_gate_on_a_synced_node() {
    for p in [regtest(), ChainParams::testnet()] {
        let mut honest = Miner::new(1);
        let mut victim = volatile(&p);
        let main = honest.mine(&mut victim, 5, 0);
        let now = main[4].header.timestamp;
        assert!(victim.template_latched(), "{:?}: synced", p.network);
        assert!(victim.template_ready(now));

        let mut attacker_node = volatile(&p);
        for b in &main {
            attacker_node
                .submit_block(b.clone(), b.header.timestamp)
                .unwrap();
        }
        let mut attacker = Miner::new(2);
        let branch = attacker.mine(&mut attacker_node, 12, 9);
        let headers: Vec<BlockHeader> = branch.iter().map(|b| b.header).collect();
        victim.accept_headers(&headers[..3], now).unwrap();
        assert_eq!((victim.height(), victim.header_height()), (5, 8));
        assert!(
            victim.template_ready(now),
            "{:?}: a 3-header lead",
            p.network
        );
        assert!(victim.summary().template_ready(now));
        let later = headers[11].timestamp;
        victim.accept_headers(&headers[3..], later).unwrap();
        assert_eq!(victim.header_height(), 17);
        assert!(
            victim.template_ready(later),
            "{:?}: a 12-header lead",
            p.network
        );
        // The victim's own miner keeps extending its tip.
        let mine = honest.mine(&mut victim, 1, 0);
        assert_eq!(victim.height(), 6);
        assert!(victim.template_ready(mine[0].header.timestamp));
    }
}

/// RTW3-1: a node still in its initial catch-up refuses templates. Testnet
/// parameters: the headers of a 30-block chain arrive with a recent clock,
/// then the bodies, one by one; templates are refused while more than 2
/// bodies are missing, and the latch sets only once the node catches up.
#[test]
fn a_node_in_its_initial_catch_up_refuses_templates() {
    let p = ChainParams::testnet();
    let mut src = volatile(&p);
    let chain = Miner::new(3).mine(&mut src, 30, 0);
    let now = chain[29].header.timestamp + 60;
    let mut m = volatile(&p);
    assert!(!m.template_ready(now), "genesis is old at this clock");
    let headers: Vec<BlockHeader> = chain.iter().map(|b| b.header).collect();
    m.accept_headers(&headers, now).unwrap();
    for (i, b) in chain.iter().enumerate() {
        // `i` bodies connected: a header gap of `30 - i`. The submission of
        // body 28 finds the node caught up (gap 2) and latches it.
        assert_eq!(m.template_latched(), i >= 29, "{i} bodies");
        assert_eq!(m.template_ready(now), i >= 28, "{i} bodies");
        m.submit_block(b.clone(), now).unwrap();
    }
    assert!(m.template_latched());
    assert!(m.template_ready(now));
}

/// RTW3-7, the demonstration turned around: an operator verdict written
/// after a damaged record survives `FileStore::repair`, and the node keeps
/// refusing the block it names when the dropped blocks are downloaded again.
#[test]
fn repair_keeps_operator_verdicts_written_after_the_damage() {
    let p = regtest();
    let mut miner = Miner::new(0x35b);
    let mut src = volatile(&p);
    let main = miner.mine(&mut src, 5, 0);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    {
        let mut m = open_path(&path).unwrap();
        for b in &main {
            m.submit_block(b.clone(), b.header.timestamp).unwrap();
        }
    }
    let bad = id(&p, &main[3]);
    let other = id(&p, &main[4]);
    {
        let mut s = FileStore::open(&path).unwrap();
        assert_eq!(
            ChainManager::mark_stored_block(&p, &mut s, bad, OperatorMark::Invalidate).unwrap(),
            OperatorMarked::Appended { height: Some(4) }
        );
        // A verdict given and cancelled: the cancellation must survive too.
        for mark in [OperatorMark::Invalidate, OperatorMark::Reconsider] {
            ChainManager::mark_stored_block(&p, &mut s, other, mark).unwrap();
        }
    }
    assert!(open_path(&path).unwrap().operator_invalidated(&bad));
    // Damage one byte inside block 2's record (before the markers).
    let mut data = std::fs::read(&path).unwrap();
    let body = main[1].encode();
    let at = data
        .windows(body.len())
        .position(|w| w == &body[..])
        .expect("block 2 in the file");
    data[at + body.len() / 2] ^= 0x55;
    std::fs::write(&path, &data).unwrap();
    assert!(open_path(&path).is_err(), "damage followed by valid data");
    let moved = FileStore::repair(&path, 1).unwrap();
    assert!(moved > 0);
    let aside = std::fs::read(path.with_extension("dat.damaged-1")).unwrap();
    assert_eq!(
        aside.len() as u64,
        moved,
        "the damaged region is kept aside"
    );
    let mut m = open_path(&path).unwrap();
    assert_eq!(m.height(), 1, "the blocks after the damage are dropped");
    assert!(m.operator_invalidated(&bad), "the verdict survives repair");
    assert!(
        !m.operator_invalidated(&other),
        "and so does the reconsider"
    );
    assert_eq!(m.operator_verdicts(), vec![bad]);
    // The dropped blocks are downloaded again: the invalidated one is not
    // connected, nor its descendant.
    for b in &main[1..] {
        let _ = m.submit_block(b.clone(), b.header.timestamp);
    }
    assert_eq!(m.height(), 3);
    // A second repair finds nothing to do.
    drop(m);
    assert_eq!(FileStore::repair(&path, 2).unwrap(), 0);
    assert!(open_path(&path).unwrap().operator_invalidated(&bad));
}

/// RTW3-8: the operator invalidates a block of the connected chain; the
/// chain built on it is heavier than the node's, so the node reports an
/// operator fork (live, in the snapshot, and after a restart) until its own
/// chain outweighs the refused one.
#[test]
fn an_operator_fork_is_reported_until_the_own_chain_outweighs_it() {
    let p = regtest();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    let mut miner = Miner::new(0x38);
    let main = {
        let mut m = open_path(&path).unwrap();
        let main = miner.mine(&mut m, 6, 0);
        assert_eq!(m.operator_fork(), None);
        let bad = id(&p, &main[3]);
        m.invalidate_block(bad).unwrap();
        assert_eq!(m.height(), 3);
        let f = m.operator_fork().expect("a heavier chain is refused");
        assert_eq!((f.block, f.height), (bad, 4));
        assert_eq!(f.branch_tip, id(&p, &main[5]));
        assert_eq!(f.branch_height, 6);
        assert!(f.excess_work > 0);
        assert_eq!(m.summary().operator_fork, Some(f), "published");
        main
    };
    // After a restart: the verdict is replayed and the fork found again.
    // Only the invalidated block itself is known now: its stored
    // descendants are refused on replay (their headers are not kept), so the
    // refused chain's known work is a lower bound (docs/blocks.md §8).
    let mut m = open_path(&path).unwrap();
    let f = m.operator_fork().expect("after a restart");
    assert_eq!((f.block, f.branch_height), (id(&p, &main[3]), 4));
    assert_eq!(m.summary().operator_fork, Some(f));
    // The node's own chain reaches, then passes, the refused one's work.
    let mut own = Miner::new(0x39);
    own.mine(&mut m, 1, 7);
    assert_eq!(m.height(), 4);
    assert_eq!(
        m.operator_fork(),
        None,
        "equal work: nothing heavier refused"
    );
    own.mine(&mut m, 1, 7);
    assert_eq!(m.operator_fork(), None);
    assert_eq!(m.summary().operator_fork, None);
}

/// RTW3-8: a verdict on a block the node would refuse anyway (its body
/// breaks a rule, or it is on a lighter branch) is no operator fork.
#[test]
fn a_verdict_on_a_lighter_branch_is_no_operator_fork() {
    let p = regtest();
    let mut m = volatile(&p);
    let mut miner = Miner::new(0x40);
    let main = miner.mine(&mut m, 5, 0);
    // A 1-block side branch at height 4.
    let side_parent = id(&p, &main[2]);
    let t = m.template_on(&side_parent).unwrap();
    let side = Miner::new(0x41).build(&p, &t, 3);
    m.submit_block(side.clone(), side.header.timestamp).unwrap();
    assert_eq!(m.height(), 5);
    m.invalidate_block(id(&p, &side)).unwrap();
    assert!(m.operator_invalidated(&id(&p, &side)));
    assert_eq!(m.operator_fork(), None, "the refused branch is lighter");
    // A verdict on a block not received yet.
    m.invalidate_block([0x5a; 32]).unwrap();
    assert_eq!(m.operator_fork(), None);
}
