//! Fork choice by body-complete work (docs/blocks.md §6): a withheld body can
//! no longer stall the connected chain, ties keep the connected tip, invalid
//! bodies fall back to the best remaining candidate, live processing and replay
//! agree, and the low-work body policy (§8) never refuses an honest candidate.

use blacksilk_chain::block::Block;
use blacksilk_chain::manager::{ChainManager, SubmitError, Template, LOW_WORK_MARGIN_BLOCKS};
use blacksilk_chain::store::{BlockStore, FileStore, MemoryStore};
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, PowFunction, HEADER_VERSION};
use blacksilk_crypto::keys::{SubaddressIndex, SubaddressTable, WalletKeys};
use blacksilk_tx::builder::{
    build_coinbase, build_transfer, standard_fee, Decoy, InputPlan, Payment, SpendableOutput,
};
use blacksilk_tx::decoy::select_ring;
use blacksilk_tx::params::{TxRules, COINBASE_MATURITY, SPENDABLE_AGE};
use blacksilk_tx::scan::{scan_block, OwnedOutput};
use blacksilk_tx::types::Transaction;
use blacksilk_tx::validate::{BlockError, ChainView};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::path::Path;
use std::sync::Arc;
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

fn open(store: Box<dyn BlockStore>) -> ChainManager {
    let p = params();
    let rules = TxRules::for_chain(&p);
    ChainManager::open(p, rules, Arc::new(ZeroPow), store, [7; 32]).unwrap()
}

fn open_mem() -> ChainManager {
    open(Box::<MemoryStore>::default())
}

fn open_file(path: &Path) -> ChainManager {
    open(Box::new(FileStore::open(path).unwrap()))
}

fn id(b: &Block) -> Hash {
    b.id(params().network_id)
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

    /// A block from a template; `claim` overrides the coinbase amount.
    fn build(
        &mut self,
        t: &Template,
        txs: Vec<Transaction>,
        claim: Option<u64>,
        nonce: u64,
    ) -> Block {
        let fees: u64 = txs.iter().map(Transaction::fee).sum();
        let cb = build_coinbase(
            t.height,
            &[Payment {
                address: self.keys.address(SubaddressIndex::PRIMARY),
                amount: claim.unwrap_or(t.reward + fees),
            }],
            &self.keys.hedge_secret(),
            &mut self.rng,
        )
        .unwrap();
        let mut all = vec![Transaction::Coinbase(cb)];
        all.extend(txs);
        let ids: Vec<Hash> = all.iter().map(Transaction::hash).collect();
        let header = BlockHeader {
            version: HEADER_VERSION,
            height: t.height,
            prev_id: t.prev_id,
            timestamp: t
                .min_timestamp
                .max(params().genesis.timestamp + 120 * t.height),
            difficulty: t.difficulty,
            tx_root: tx_root(&ids),
            nonce,
        };
        Block { header, txs: all }
    }

    /// Mines the next block on the connected tip (with mempool transactions).
    fn mine_tip(&mut self, m: &mut ChainManager) -> Block {
        let t = m.template();
        let txs = t.txs.clone();
        let b = self.build(&t, txs, None, 0);
        let s = m.submit_block(b.clone(), b.header.timestamp).unwrap();
        assert!(s.on_best_chain && s.body_kept);
        b
    }

    /// A coinbase-only child of `parent` (any valid known header).
    fn child(&mut self, m: &ChainManager, parent: &Hash, claim_delta: u64, nonce: u64) -> Block {
        let t = m.template_on(parent).unwrap();
        let claim = (claim_delta > 0).then(|| t.reward + claim_delta);
        self.build(&t, vec![], claim, nonce)
    }

    /// `n` coinbase-only blocks on `parent` whose **headers only** reach `m`
    /// (the bodies are returned, not submitted).
    fn headers_only(
        &mut self,
        m: &mut ChainManager,
        parent: Hash,
        n: usize,
        nonce: u64,
    ) -> Vec<Block> {
        let mut out = Vec::new();
        let mut p = parent;
        for _ in 0..n {
            let b = self.child(m, &p, 0, nonce);
            m.accept_headers(&[b.header], b.header.timestamp).unwrap();
            p = id(&b);
            out.push(b);
        }
        out
    }
}

fn submit(m: &mut ChainManager, b: &Block) -> Result<blacksilk_chain::Submitted, SubmitError> {
    m.submit_block(b.clone(), b.header.timestamp)
}

fn scan_all(m: &ChainManager, keys: &WalletKeys) -> Vec<OwnedOutput> {
    let table = SubaddressTable::new(keys.view_keys(), 1, 5);
    let mut out = Vec::new();
    for h in 1..=m.height() {
        let b = m.block_at(h).unwrap();
        let first = m.state().first_output_at(h).unwrap();
        out.extend(scan_block(keys.view_keys(), &table, &b.txs, h, first).owned);
    }
    out
}

/// The `nth` mature, unspent output of `from`, with a ring.
fn plan_nth(m: &ChainManager, from: &WalletKeys, nth: usize, rng: &mut ChaCha20Rng) -> InputPlan {
    let height = m.height() + 1;
    let mature = |created: u64, coinbase: bool| {
        let age = if coinbase {
            COINBASE_MATURITY
        } else {
            SPENDABLE_AGE
        };
        height >= created + age
    };
    let owned = scan_all(m, from)
        .into_iter()
        .filter(|o| {
            mature(o.height, o.coinbase) && !m.state().is_key_image_spent(&o.key_image(from))
        })
        .nth(nth)
        .expect("a spendable output");
    let state = m.state();
    let ring = select_ring(
        rng,
        &state.cumulative_outputs(),
        height,
        120,
        owned.global_index,
        |i| {
            state
                .output(i)
                .is_some_and(|r| mature(r.height, r.coinbase))
        },
    )
    .unwrap();
    InputPlan {
        real: SpendableOutput::from(&owned),
        decoys: ring
            .iter()
            .filter(|&&i| i != owned.global_index)
            .map(|&i| Decoy {
                global_index: i,
                key: state.output(i).unwrap().key,
            })
            .collect(),
    }
}

/// A 1-input transfer of the `nth` spendable output of `from` to `to`.
fn transfer(
    m: &ChainManager,
    from: &WalletKeys,
    to: &WalletKeys,
    nth: usize,
    rng: &mut ChaCha20Rng,
) -> Transaction {
    let plan = plan_nth(m, from, nth, rng);
    Transaction::from(
        build_transfer(
            from,
            vec![plan],
            &[Payment {
                address: to.address(SubaddressIndex::PRIMARY),
                amount: 1_000,
            }],
            &from.address(SubaddressIndex::PRIMARY),
            standard_fee(1, 2, m.rules()),
            m.rules(),
            rng,
        )
        .unwrap(),
    )
}

/// Everything the connected chain determines.
#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    tip: Hash,
    height: u64,
    generated: u64,
    outputs: u64,
    px_root: [u32; 8],
    nullifiers: usize,
    spent: Vec<bool>,
}

fn snapshot(m: &ChainManager, key_images: &[blacksilk_crypto::Point]) -> Snapshot {
    let s = m.state();
    Snapshot {
        tip: m.tip_id(),
        height: m.height(),
        generated: m.generated(),
        outputs: s.output_count(),
        px_root: s.px().root(),
        nullifiers: s.px_nullifiers(0, u64::MAX).len(),
        spent: key_images.iter().map(|k| s.is_key_image_spent(k)).collect(),
    }
}

// ---------------------------------------------------------------- (1)

/// A10-H1: an attacker announces B1 on the tip F and never serves its body.
/// B1 ties the local miner's A1, and before 2026-09-27 the node never
/// connected A1 (the state only followed the header-best chain, which kept
/// the first-seen B1): templates stayed on F forever. Now A1 and A2 connect,
/// and when B1's body arrives late the chain follows work.
#[test]
fn a_withheld_body_cannot_stall_block_production() {
    let mut m = open_mem();
    let mut miner = Miner::new(1);
    let mut attacker = Miner::new(2);
    for _ in 0..5 {
        miner.mine_tip(&mut m);
    }
    let f = m.tip_id();
    let b = attacker.headers_only(&mut m, f, 1, 1);
    let b1 = id(&b[0]);
    assert_eq!(m.best_header_id(), b1, "B1 is the header-best tip");
    assert_eq!(m.missing_bodies(10), vec![(6, b1)], "heavier: downloaded");

    let t = m.template();
    assert_eq!((t.height, t.prev_id), (6, f));
    let a1 = miner.mine_tip(&mut m);
    assert_eq!(m.height(), 6);
    assert_eq!(m.tip_id(), id(&a1));
    assert_eq!(
        m.best_header_id(),
        b1,
        "equal work: the header chain keeps B1"
    );
    assert!(
        m.missing_bodies(10).is_empty(),
        "an equal-work tip is not fetched"
    );
    assert_eq!(m.template().prev_id, id(&a1), "templates move on");

    let a2 = miner.mine_tip(&mut m);
    assert_eq!(m.height(), 7);
    assert_eq!(
        m.best_header_id(),
        id(&a2),
        "the header-best chain switches to A"
    );

    // Recovery: B1's body arrives after all; A has more work, nothing moves.
    let s = submit(&mut m, &b[0]).unwrap();
    assert!(s.body_kept && !s.on_best_chain);
    assert_eq!(m.tip_id(), id(&a2));
    assert_eq!(m.deepest_reorg(), 0);
    // B catches up and overtakes A (bodies served now): the chain follows work.
    let more = attacker.headers_only(&mut m, b1, 2, 1);
    assert_eq!(m.tip_id(), id(&a2), "headers alone move nothing");
    submit(&mut m, &more[0]).unwrap();
    assert_eq!(m.tip_id(), id(&a2), "B2 only ties A2");
    assert!(submit(&mut m, &more[1]).unwrap().on_best_chain);
    assert_eq!((m.height(), m.tip_id()), (8, id(&more[1])));
    assert_eq!(m.deepest_reorg(), 2);
}

// ---------------------------------------------------------------- (2)

/// Heavier bodiless branch B1..B3, valid A1, A2 with an invalid body: A1
/// connects and stays, A2 is marked invalid, a valid A2' tying B2 connects.
/// B's bodies arrive: a heavier B wins; with an invalid body in B the node
/// falls back to A.
#[test]
fn candidates_by_complete_work_with_invalid_bodies_on_both_sides() {
    for b_invalid in [false, true] {
        let mut m = open_mem();
        let mut miner = Miner::new(3);
        let mut attacker = Miner::new(4);
        for _ in 0..5 {
            miner.mine_tip(&mut m);
        }
        let f = m.tip_id();
        // B1..B3: headers only; B2 over-claims in the second round.
        let mut b = Vec::new();
        let mut p = f;
        for i in 0..3 {
            let delta = if b_invalid && i == 1 { 1 } else { 0 };
            let blk = attacker.child(&m, &p, delta, 9);
            m.accept_headers(&[blk.header], blk.header.timestamp)
                .unwrap();
            p = id(&blk);
            b.push(blk);
        }
        assert_eq!(m.header_height(), 8);

        let a1 = miner.mine_tip(&mut m);
        assert_eq!(m.tip_id(), id(&a1));
        let a2_bad = miner.child(&m, &id(&a1), 1, 0);
        assert!(matches!(
            submit(&mut m, &a2_bad),
            Err(SubmitError::Body(BlockError::CoinbaseAmount { .. }))
        ));
        assert!(m.invalid_reason(&id(&a2_bad)).is_some());
        assert_eq!(m.tip_id(), id(&a1));
        assert_eq!(m.template().prev_id, id(&a1), "template on A1");
        let a2 = miner.child(&m, &id(&a1), 0, 1);
        assert!(submit(&mut m, &a2).unwrap().on_best_chain, "A2' ties B2");
        assert_eq!(m.height(), 7);
        let missing: Vec<Hash> = m.missing_bodies(10).iter().map(|x| x.1).collect();
        assert_eq!(missing, b.iter().map(id).collect::<Vec<_>>());

        for blk in &b[..2] {
            let _ = submit(&mut m, blk);
            assert_eq!(m.tip_id(), id(&a2), "B1, B2 do not beat A2'");
        }
        let r = submit(&mut m, &b[2]).unwrap();
        if b_invalid {
            // B3 made B the target; B2 failed; back to A (already there).
            assert!(!r.on_best_chain);
            assert!(m.invalid_reason(&id(&b[1])).is_some());
            assert_eq!(m.tip_id(), id(&a2));
            assert_eq!(m.headers().is_valid(&id(&b[2])), Some(false));
            assert_eq!(m.best_header_id(), id(&a2));
            assert_eq!(m.template().prev_id, id(&a2));
            assert!(m.missing_bodies(10).is_empty());
            // B was connected up to B1 on the way (A disconnected) and undone.
            assert_eq!(m.deepest_reorg(), 2);
        } else {
            assert!(r.on_best_chain);
            assert_eq!((m.height(), m.tip_id()), (8, id(&b[2])));
        }
    }
}

// ---------------------------------------------------------------- (3)

/// Restart determinism: a block tree with many equal-work ties, delivered in
/// random orders (headers first or not, bodies shuffled), is replayed to the
/// same tip and state as live processing, and a second restart again.
#[test]
fn replay_reproduces_live_fork_choice_exactly() {
    // A tree on a scratch node: an 80-block trunk (so coinbases mature), a
    // payment in T81, and side branches with ties at several heights.
    let mut src = open_mem();
    let mut miner = Miner::new(5);
    let mut rng = ChaCha20Rng::seed_from_u64(55);
    let (alice, _) = WalletKeys::generate(&mut rng);
    let mut blocks: Vec<Block> = (0..80).map(|_| miner.mine_tip(&mut src)).collect();
    let pay = transfer(&src, &miner.keys, &alice, 0, &mut rng);
    let key_images: Vec<_> = match &pay {
        Transaction::Transfer(t) => t.inputs.iter().map(|i| i.key_image).collect(),
        _ => unreachable!(),
    };
    src.submit_tx(pay).unwrap();
    blocks.push(miner.mine_tip(&mut src)); // T81 spends
    let trunk_tip = id(&blocks[80]);
    let f = id(&blocks[79]);
    // Side branches (headers only on the scratch node; bodies kept here).
    let mut side = Vec::new();
    for (parent, n, nonce) in [
        (f, 1, 11),
        (f, 2, 12),
        (f, 2, 13),
        (trunk_tip, 1, 14),
        (trunk_tip, 1, 15),
        (id(&blocks[76]), 5, 16),
    ] {
        side.extend(miner.headers_only(&mut src, parent, n, nonce));
    }
    blocks.extend(side);
    let all_headers: Vec<BlockHeader> = blocks.iter().map(|b| b.header).collect();

    let mut tips = std::collections::HashSet::new();
    for seed in 0..16u64 {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        let mut order_rng = ChaCha20Rng::seed_from_u64(1000 + seed);
        let live = {
            let mut m = open_file(&path);
            if seed % 2 == 0 {
                // Header-first: every header, then bodies in any order.
                m.accept_headers(&all_headers, u64::MAX / 2).unwrap();
            }
            let mut todo: Vec<usize> = (0..blocks.len()).collect();
            // Shuffle only above the trunk's first 70 blocks (faster, and the
            // interesting part is at the top).
            for i in (71..todo.len()).rev() {
                let j = 71 + (order_rng.next_u64() as usize) % (i - 70);
                todo.swap(i, j);
            }
            while !todo.is_empty() {
                let mut rest = Vec::new();
                for i in todo {
                    match submit(&mut m, &blocks[i]) {
                        Ok(s) => assert!(s.body_kept),
                        Err(SubmitError::Header(
                            blacksilk_consensus::HeaderError::UnknownParent,
                        )) => rest.push(i),
                        Err(e) => panic!("{e:?}"),
                    }
                }
                todo = rest;
            }
            snapshot(&m, &key_images)
        };
        let replayed = snapshot(&open_file(&path), &key_images);
        assert_eq!(replayed, live, "seed {seed}: replay equals live");
        let again = snapshot(&open_file(&path), &key_images);
        assert_eq!(again, live, "seed {seed}: second restart");
        assert_eq!(live.height, 82, "five equal-work tips at height 82");
        tips.insert(live.tip);
    }
    assert!(
        tips.len() >= 3,
        "the order decides the ties: {} tips",
        tips.len()
    );
}

/// The sibling race of storage_recovery.rs, plus a tie at the tip resolved by
/// completion order when several bodies wait for one parent.
#[test]
fn waiting_siblings_complete_in_body_arrival_order() {
    let mut src = open_mem();
    let mut miner = Miner::new(6);
    let base: Vec<Block> = (0..4).map(|_| miner.mine_tip(&mut src)).collect();
    let p = id(&base[3]);
    let kids = miner.headers_only(&mut src, p, 1, 1);
    let kids2 = miner.headers_only(&mut src, p, 1, 2);
    let kids3 = miner.headers_only(&mut src, p, 1, 3);
    let (x, y, z) = (&kids[0], &kids2[0], &kids3[0]);
    for (first, second, third) in [(x, y, z), (z, x, y), (y, z, x)] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.dat");
        let tip = {
            let mut m = open_file(&path);
            let hs: Vec<BlockHeader> = base.iter().map(|b| b.header).collect();
            m.accept_headers(&hs, u64::MAX / 2).unwrap();
            // Headers of the siblings in the reverse order of their bodies.
            for s in [third, second, first] {
                m.accept_headers(&[s.header], u64::MAX / 2).unwrap();
            }
            for b in &base[..3] {
                submit(&mut m, b).unwrap();
            }
            for s in [first, second, third] {
                assert!(!submit(&mut m, s).unwrap().on_best_chain);
            }
            submit(&mut m, &base[3]).unwrap();
            assert_eq!(m.tip_id(), id(first), "first body stored wins");
            m.tip_id()
        };
        assert_eq!(open_file(&path).tip_id(), tip);
    }
}

// ---------------------------------------------------------------- (4)

/// A late equal-work body never reorganizes (no flapping), whichever side
/// completed first; the first complete stays until real work decides.
#[test]
fn a_late_equal_work_body_does_not_reorg() {
    let mut src = open_mem();
    let mut miner = Miner::new(7);
    let base: Vec<Block> = (0..5).map(|_| miner.mine_tip(&mut src)).collect();
    let f = id(&base[4]);
    let a = miner.headers_only(&mut src, f, 2, 1);
    let b = miner.headers_only(&mut src, f, 2, 2);
    for (first, second) in [(&a, &b), (&b, &a)] {
        let mut m = open_mem();
        for blk in &base {
            submit(&mut m, blk).unwrap();
        }
        submit(&mut m, &first[0]).unwrap();
        assert!(!submit(&mut m, &second[0]).unwrap().on_best_chain);
        assert_eq!(m.tip_id(), id(&first[0]));
        submit(&mut m, &first[1]).unwrap();
        assert!(!submit(&mut m, &second[1]).unwrap().on_best_chain);
        assert_eq!(m.tip_id(), id(&first[1]));
        assert_eq!(m.deepest_reorg(), 0, "no flapping");
        // A third block decides by work.
        let decider = miner.child(&m, &id(&second[1]), 0, 3);
        assert!(submit(&mut m, &decider).unwrap().on_best_chain);
        assert_eq!(m.deepest_reorg(), 2);
    }
}

// ---------------------------------------------------------------- (5)

/// Mempool round trip across the new reorg path: transactions of
/// disconnected blocks return and are revalidated against the new branch, so
/// one double-spent by the new branch does not return.
#[test]
fn transactions_return_to_the_mempool_across_a_body_complete_reorg() {
    let mut m = open_mem();
    let mut miner = Miner::new(8);
    let mut rng = ChaCha20Rng::seed_from_u64(88);
    let (alice, _) = WalletKeys::generate(&mut rng);
    for _ in 0..80 {
        miner.mine_tip(&mut m);
    }
    let f = m.tip_id();
    let kept = transfer(&m, &miner.keys, &alice, 0, &mut rng);
    let spent = transfer(&m, &miner.keys, &alice, 1, &mut rng);
    let rival = transfer(&m, &miner.keys, &alice, 1, &mut rng); // same output as `spent`
    assert_ne!(rival.hash(), spent.hash());
    m.submit_tx(kept.clone()).unwrap();
    m.submit_tx(spent.clone()).unwrap();
    let a1 = miner.mine_tip(&mut m);
    assert_eq!(a1.txs.len(), 3);
    assert!(m.mempool().is_empty());

    // Branch B (the rival in B1) arrives headers first, bodies in reverse.
    let t = m.template_on(&f).unwrap();
    let fee = rival.fee();
    let b1 = miner.build(&t, vec![rival.clone()], Some(t.reward + fee), 5);
    m.accept_headers(&[b1.header], b1.header.timestamp).unwrap();
    let b2 = miner.child(&m, &id(&b1), 0, 5);
    m.accept_headers(&[b2.header], b2.header.timestamp).unwrap();
    assert_eq!(m.tip_id(), id(&a1));
    submit(&mut m, &b2).unwrap();
    assert_eq!(m.tip_id(), id(&a1), "B2 waits for B1");
    assert!(submit(&mut m, &b1).unwrap().body_kept);
    assert_eq!(m.tip_id(), id(&b2), "B1 completes B: heavier, reorg");
    assert_eq!(m.deepest_reorg(), 1);
    assert!(m.mempool().contains(&kept.hash()), "returned");
    assert!(!m.mempool().contains(&spent.hash()), "double-spent by B1");
    assert!(!m.mempool().contains(&rival.hash()), "confirmed in B1");
    // It confirms again on B.
    let b3 = miner.mine_tip(&mut m);
    assert!(b3.txs.iter().any(|tx| tx.hash() == kept.hash()));
    assert!(m.mempool().is_empty());
}

// ---------------------------------------------------------------- (7)

/// 10 000 bodies arriving in reverse order (headers first) connect in time
/// linear in their number: at most a small factor slower than in-order
/// arrival, with `missing_bodies` polled after every body as the network
/// layer does.
#[test]
fn ten_thousand_bodies_in_reverse_order_stay_linear() {
    const N: usize = 10_000;
    let mut src = open_mem();
    let mut miner = Miner::new(9);
    let blocks: Vec<Block> = (0..N).map(|_| miner.mine_tip(&mut src)).collect();
    let headers: Vec<BlockHeader> = blocks.iter().map(|b| b.header).collect();

    let run = |order: &mut dyn Iterator<Item = &Block>| {
        let mut m = open_mem();
        for chunk in headers.chunks(2000) {
            m.accept_headers(chunk, u64::MAX / 2).unwrap();
        }
        let started = Instant::now();
        for b in order {
            submit(&mut m, b).unwrap();
            let _ = m.missing_bodies(256);
        }
        let took = started.elapsed();
        assert_eq!(m.height(), N as u64);
        assert!(m.missing_bodies(256).is_empty());
        took
    };
    let forward = run(&mut blocks.iter());
    let reverse = run(&mut blocks.iter().rev());
    println!("{N} bodies: in order {forward:?}, reverse {reverse:?}");
    assert!(
        reverse < forward * 4 + Duration::from_secs(5),
        "reverse arrival {reverse:?} vs in order {forward:?}"
    );
}

// ---------------------------------------------------------------- R10-1 low-work bodies

/// A cheap low-work side-branch body (a child of an early block) is not
/// stored or kept, although its header is accepted; near-tip forks are kept;
/// a heavier branch forking far below the tip is kept whether or not it is the
/// header-best branch (a candidate whose bodies are downloaded).
#[test]
fn low_work_side_branch_bodies_are_not_kept_but_candidates_always_are() {
    let depth = LOW_WORK_MARGIN_BLOCKS as usize; // regtest: difficulty 1 per block
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    let mut miner = Miner::new(10);
    let mut attacker = Miner::new(11);
    let (junk, near) = {
        let mut m = open_file(&path);
        let main: Vec<Block> = (0..depth + 50).map(|_| miner.mine_tip(&mut m)).collect();
        let tip = m.tip_id();
        // A child of genesis: header accepted, body neither stored nor kept.
        let junk = attacker.child(&m, &params().genesis_id(), 0, 1);
        let s = submit(&mut m, &junk).unwrap();
        assert!(!s.body_kept && !s.on_best_chain);
        assert!(m.knows_valid_header(&id(&junk)));
        assert!(!m.has_body(&id(&junk)));
        assert!(m.missing_bodies(10).is_empty(), "never requested");
        // Resubmitting is refused the same way (not a duplicate).
        assert!(!submit(&mut m, &junk).unwrap().body_kept);
        // Just inside the margin: kept (a locally mined deep side branch).
        let edge = main.len() - depth; // child work = tip work - (depth - 1)
        let near = attacker.child(&m, &id(&main[edge - 1]), 0, 2);
        assert!(submit(&mut m, &near).unwrap().body_kept);
        let outside = attacker.child(&m, &id(&main[edge - 3]), 0, 3);
        assert!(!submit(&mut m, &outside).unwrap().body_kept);
        assert_eq!(m.tip_id(), tip);
        (junk, near)
    };
    // Restart: only the kept side body is in the store.
    let mut m = open_file(&path);
    assert!(m.has_body(&id(&near)));
    assert!(m.header(&id(&junk)).is_none(), "the junk was never stored");
    let tip_height = m.height();

    // Two heavier branches forking 120 blocks below the tip: B (heaviest,
    // header-best, bodies withheld) and C (heavier than the tip, lighter
    // than B). C's deep bodies are candidates: requested and kept.
    let fork = m.block_at(tip_height - 120).unwrap();
    let b = attacker.headers_only(&mut m, id(&fork), 125, 21);
    let c = miner.headers_only(&mut m, id(&fork), 122, 22);
    assert_eq!(m.best_header_id(), id(b.last().unwrap()));
    let missing: Vec<Hash> = m.missing_bodies(1000).iter().map(|x| x.1).collect();
    assert_eq!(missing.len(), 125 + 122);
    assert!(c.iter().all(|blk| missing.contains(&id(blk))));
    for blk in &c {
        assert!(submit(&mut m, blk).unwrap().body_kept);
    }
    assert_eq!(m.tip_id(), id(c.last().unwrap()), "C connected, B withheld");
    assert_eq!(m.height(), tip_height + 2);
    assert_eq!(m.deepest_reorg(), 120);
    // B's bodies are still wanted (B is heavier); a lighter deep branch is not.
    assert_eq!(m.missing_bodies(1000).len(), 125);
    let d = attacker.child(&m, &id(&fork), 0, 23);
    assert!(!submit(&mut m, &d).unwrap().body_kept);
    // B's bodies, 120 blocks below the tip, arrive at last. B is the header
    // tip, which the leaf scan leaves out: they are kept because they lie on
    // the header-best chain, heavier than the connected tip, and B connects
    // (run C mutation census: no test submitted a header-best deep body).
    for blk in &b {
        assert!(submit(&mut m, blk).unwrap().body_kept);
    }
    assert_eq!(m.tip_id(), id(b.last().unwrap()), "B connected");
    assert!(m.missing_bodies(1000).is_empty());
}

/// A store written for another network or genesis is refused at startup.
#[test]
fn a_store_of_another_network_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    {
        let mut m = open_file(&path);
        let mut miner = Miner::new(12);
        miner.mine_tip(&mut m);
    }
    let mut other = params();
    other.network_id ^= 1;
    let err = ChainManager::open(
        other.clone(),
        TxRules::for_chain(&other),
        Arc::new(ZeroPow),
        Box::new(FileStore::open(&path).unwrap()),
        [7; 32],
    )
    .err()
    .expect("refused");
    assert!(
        err.to_string().contains("wrong network data directory"),
        "{err}"
    );
    assert_eq!(
        open_file(&path).height(),
        1,
        "the right network still opens"
    );
}

/// The low-work policy's candidate rule is strict (docs/blocks.md §8): the
/// bodies of a header tip with **more** work than the connected tip are
/// downloaded and kept. A deep branch whose header tip only equals the
/// connected tip's work (header-best because its headers came first) is no
/// candidate: its bodies below the margin are refused like any low-work side
/// branch (run C mutation census: no test had an equal-work header tip).
#[test]
fn an_equal_work_header_tip_is_not_a_candidate_for_deep_bodies() {
    let mut m = open_mem();
    let mut miner = Miner::new(13);
    let mut attacker = Miner::new(14);
    for _ in 0..LOW_WORK_MARGIN_BLOCKS as usize + 50 {
        miner.mine_tip(&mut m);
    }
    let tip_height = m.height();
    let fork = m.block_at(tip_height - 120).unwrap();
    // B: 121 headers from 120 blocks below the tip, one block heavier.
    let b = attacker.headers_only(&mut m, id(&fork), 121, 31);
    assert_eq!(m.best_header_id(), id(b.last().unwrap()));
    // The connected chain catches up to B's work with one block; B stays the
    // header tip (it reached that work first).
    let a = miner.child(&m, &m.tip_id(), 0, 32);
    assert!(submit(&mut m, &a).unwrap().body_kept);
    assert_eq!(m.tip_id(), id(&a));
    assert_eq!(m.height(), tip_height + 1);
    assert_eq!(m.best_header_id(), id(b.last().unwrap()));
    // B's deep bodies are not candidates any more.
    assert!(!submit(&mut m, &b[0]).unwrap().body_kept);
    assert!(!m.has_body(&id(&b[0])));
    // One more header on B makes it heavier again: now its bodies are kept.
    let b2 = attacker.headers_only(&mut m, id(b.last().unwrap()), 1, 33);
    assert_eq!(m.best_header_id(), id(&b2[0]));
    assert!(submit(&mut m, &b[0]).unwrap().body_kept);
}

/// The same for a side branch that is not the header tip: a deep branch
/// whose headers reach the connected tip's work, or one block less, is no
/// candidate (the leaf scan takes leaves with strictly more work); one block
/// more makes it one.
#[test]
fn an_equal_or_lighter_side_leaf_is_not_a_candidate_for_deep_bodies() {
    let mut m = open_mem();
    let mut miner = Miner::new(15);
    let mut attacker = Miner::new(16);
    for _ in 0..LOW_WORK_MARGIN_BLOCKS as usize + 50 {
        miner.mine_tip(&mut m);
    }
    let tip = m.tip_id();
    let fork = m.block_at(m.height() - 120).unwrap();
    // C: 119 then 120 headers from 120 blocks below the tip (one block less
    // than the tip's work, then equal): the tip stays the header tip.
    let c = attacker.headers_only(&mut m, id(&fork), 119, 41);
    assert_eq!(m.best_header_id(), tip);
    assert!(
        !submit(&mut m, &c[0]).unwrap().body_kept,
        "one block lighter"
    );
    let c2 = attacker.headers_only(&mut m, id(c.last().unwrap()), 1, 42);
    assert_eq!(m.best_header_id(), tip, "equal work: the first seen stays");
    assert!(!submit(&mut m, &c[0]).unwrap().body_kept, "equal work");
    // One block heavier: a candidate, its deep bodies kept.
    attacker.headers_only(&mut m, id(&c2[0]), 1, 43);
    assert!(submit(&mut m, &c[0]).unwrap().body_kept, "heavier");
}

/// When a block is invalidated, its parent becomes a leaf again if no valid
/// child remains: a branch cut back below its invalid tip is still a
/// candidate while it has more work than the connected tip, and its missing
/// bodies are still requested (run C mutation census: no test cut a
/// candidate branch that way).
#[test]
fn a_candidate_cut_back_below_an_invalid_tip_stays_a_candidate() {
    let mut m = open_mem();
    let mut miner = Miner::new(17);
    let mut attacker = Miner::new(18);
    for _ in 0..20 {
        miner.mine_tip(&mut m);
    }
    let fork = id(&m.block_at(m.height() - 5).unwrap());
    // B: the header tip, 5 blocks heavier than the connected tip. C: 3
    // blocks heavier; after its last block is invalidated, 2.
    let b = attacker.headers_only(&mut m, fork, 10, 51);
    let c = miner.headers_only(&mut m, fork, 8, 52);
    assert_eq!(m.best_header_id(), id(b.last().unwrap()));
    let wanted =
        |m: &ChainManager| -> Vec<Hash> { m.missing_bodies(1000).iter().map(|x| x.1).collect() };
    assert!(c.iter().all(|blk| wanted(&m).contains(&id(blk))));
    m.invalidate_block(id(c.last().unwrap())).unwrap();
    let after = wanted(&m);
    assert!(!after.contains(&id(c.last().unwrap())));
    for blk in &c[..7] {
        assert!(
            after.contains(&id(blk)),
            "C below its invalid tip is still wanted"
        );
    }
    assert!(b.iter().all(|blk| after.contains(&id(blk))));
}
