//! Chain manager: emission enforcement, body/header handling, reorganizations with
//! transactions, invalid blocks, mempool, and persistence with replay.

use blacksilk_chain::block::Block;
use blacksilk_chain::emission::block_reward;
use blacksilk_chain::manager::{
    ChainManager, StorePowCheck, StorePowMismatch, SubmitError, Template,
};
use blacksilk_chain::mempool::MempoolError;
use blacksilk_chain::store::{BlockStore, FileStore, MemoryStore};
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{
    BlockHeader, ChainParams, Hash, HeaderError, PowFunction, HEADER_VERSION,
};
use blacksilk_crypto::keys::{SubaddressIndex, SubaddressTable, WalletKeys};
use blacksilk_tx::builder::{
    build_coinbase, build_transfer, standard_fee, Decoy, InputPlan, Payment, SpendableOutput,
};
use blacksilk_tx::decoy::select_ring;
use blacksilk_tx::params::{TxRules, COINBASE_MATURITY, SPENDABLE_AGE};
use blacksilk_tx::scan::{scan_block, OwnedOutput};
use blacksilk_tx::types::{Transaction, Transfer};
use blacksilk_tx::validate::{BlockError, ChainView};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

thread_local! {
    /// The body of every block this test built, by id: the output range a
    /// template on a branch extends (B-OMR) needs the bodies the manager
    /// does not hold (headers sent alone, bodies dropped as invalid).
    static BUILT: std::cell::RefCell<std::collections::HashMap<Hash, Vec<Transaction>>> =
        Default::default();
}

/// Records `b`'s body ([`BUILT`]) and returns it.
fn remember(b: Block) -> Block {
    let id = b.id(params().network_id);
    BUILT.with(|m| m.borrow_mut().insert(id, b.txs.clone()));
    BLOB_HEIGHTS
        .lock()
        .unwrap()
        .insert(b.header.pow_blob(params().network_id), b.header.height);
    b
}

/// The height of every block this test process built, by mining blob: the
/// PoW test doubles see only the blob (docs/consensus.md §3).
static BLOB_HEIGHTS: std::sync::LazyLock<
    std::sync::Mutex<HashMap<[u8; blacksilk_consensus::POW_BLOB_SIZE], u64>>,
> = std::sync::LazyLock::new(Default::default);

/// The height of the block whose mining blob is `blob` (built by this test).
fn blob_height(blob: &[u8]) -> u64 {
    let key: [u8; blacksilk_consensus::POW_BLOB_SIZE] = blob.try_into().expect("a mining blob");
    *BLOB_HEIGHTS
        .lock()
        .unwrap()
        .get(&key)
        .expect("a block this test built")
}

/// The body of a block this test built.
fn known_body(id: &Hash) -> Option<Vec<Transaction>> {
    BUILT.with(|m| m.borrow().get(id).cloned())
}

/// Zero hash: meets any difficulty. Counts calls to show replay skips PoW,
/// and records the hot RandomX keys it is given.
#[derive(Default)]
struct ZeroPow {
    calls: AtomicUsize,
    hot: std::sync::Mutex<Vec<Vec<Hash>>>,
}
impl PowFunction for ZeroPow {
    fn pow_hash(&self, _: &Hash, _: &blacksilk_consensus::PowBlob) -> Hash {
        self.calls.fetch_add(1, Ordering::SeqCst);
        [0; 32]
    }
    fn set_hot_seeds(&self, seeds: &[Hash]) {
        self.hot.lock().unwrap().push(seeds.to_vec());
    }
}

fn params() -> ChainParams {
    ChainParams::regtest()
}

fn open(store: Box<dyn BlockStore>, pow: Arc<ZeroPow>) -> ChainManager {
    let p = params();
    let rules = TxRules::for_chain(&p);
    ChainManager::open(p, rules, pow, store, [7; 32]).unwrap()
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

    /// Builds a block from a template, with an optional coinbase amount override.
    fn build(
        &mut self,
        t: &Template,
        txs: Vec<Transaction>,
        claim: Option<u64>,
        nonce: u64,
    ) -> Block {
        let fees: u64 = txs.iter().map(Transaction::fee).sum();
        let amount = claim.unwrap_or(t.reward + fees);
        let cb = build_coinbase(
            t.height,
            &[Payment {
                address: self.keys.address(SubaddressIndex::PRIMARY),
                amount,
            }],
            &self.keys.hedge_secret(),
            &mut self.rng,
        )
        .unwrap();
        let mut all = vec![Transaction::Coinbase(cb)];
        all.extend(txs);
        let ids: Vec<Hash> = all.iter().map(Transaction::hash).collect();
        let (output_count, output_root) = t.outputs_after(&all);
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
            output_count,
            output_root,
            px_root: t.px_root,
        };
        remember(Block { header, txs: all })
    }

    fn mine_tip(&mut self, m: &mut ChainManager) -> Block {
        let t = m.template();
        let txs = t.txs.clone();
        let b = self.build(&t, txs, None, 0);
        let now = b.header.timestamp;
        m.submit_block(b.clone(), now).expect("valid block");
        b
    }
}

/// Wallet view of the manager's connected chain.
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

fn pay(
    m: &ChainManager,
    from: &WalletKeys,
    to: &WalletKeys,
    amount: u64,
    rng: &mut ChaCha20Rng,
) -> Transfer {
    let height = m.height() + 1;
    let owned = scan_all(m, from)
        .into_iter()
        .find(|o| {
            let age = if o.coinbase {
                COINBASE_MATURITY
            } else {
                SPENDABLE_AGE
            };
            height >= o.height + age && !m.state().is_key_image_spent(&o.key_image(from))
        })
        .expect("a spendable output");
    let state = m.state();
    let ring = select_ring(
        rng,
        &state.cumulative_outputs(),
        height,
        120,
        owned.global_index,
        |i| {
            state.output(i).is_some_and(|r| {
                let age = if r.coinbase {
                    COINBASE_MATURITY
                } else {
                    SPENDABLE_AGE
                };
                height >= r.height + age
            })
        },
    )
    .unwrap();
    let decoys = ring
        .iter()
        .filter(|&&i| i != owned.global_index)
        .map(|&i| Decoy {
            global_index: i,
            key: state.output(i).unwrap().key,
        })
        .collect();
    let plan = InputPlan {
        real: SpendableOutput::from(&owned),
        decoys,
    };
    let fee = standard_fee(1, 2, m.rules());
    build_transfer(
        from,
        vec![plan],
        &[Payment {
            address: to.address(SubaddressIndex::PRIMARY),
            amount,
        }],
        &from.address(SubaddressIndex::PRIMARY),
        fee,
        m.rules(),
        rng,
    )
    .unwrap()
}

#[test]
fn emission_is_enforced_exactly() {
    let mut m = open(Box::<MemoryStore>::default(), Arc::default());
    let mut miner = Miner::new(1);
    let mut expected_g = 0u64;
    for h in 1..=20 {
        assert_eq!(m.template().reward, block_reward(h, expected_g));
        miner.mine_tip(&mut m);
        expected_g += block_reward(h, expected_g);
    }
    assert_eq!(m.generated(), expected_g);
    let balance: u64 = scan_all(&m, &miner.keys)
        .iter()
        .map(|o| o.received.amount)
        .sum();
    assert_eq!(
        balance, expected_g,
        "the miner received exactly the emission"
    );

    // One unit too much, and one too little, are both invalid.
    let tip = m.tip_id();
    for delta in [1i64, -1] {
        let t = m.template();
        let claim = (t.reward as i64 + delta) as u64;
        let b = miner.build(&t, vec![], Some(claim), 0);
        let now = b.header.timestamp;
        match m.submit_block(b.clone(), now) {
            Err(SubmitError::Body(BlockError::CoinbaseAmount { .. })) => {}
            other => panic!("expected CoinbaseAmount, got {other:?}"),
        }
        assert_eq!(m.tip_id(), tip, "tip unchanged");
        // Its children are rejected as descendants of an invalid block.
        let child_t = Template {
            height: t.height + 1,
            prev_id: b.id(params().network_id),
            ..t.clone()
        };
        let child = miner.build(&child_t, vec![], None, 0);
        let now = child.header.timestamp;
        assert!(matches!(
            m.submit_block(child, now),
            Err(SubmitError::Header(HeaderError::InvalidParent))
        ));
    }
}

#[test]
fn body_must_match_header() {
    let mut m = open(Box::<MemoryStore>::default(), Arc::default());
    let mut miner = Miner::new(2);
    let t = m.template();
    let good = miner.build(&t, vec![], None, 0);
    let other = miner.build(&t, vec![], None, 0); // different coinbase randomness
    let mismatched = Block {
        header: good.header,
        txs: other.txs,
    };
    let now = good.header.timestamp;
    assert!(matches!(
        m.submit_block(mismatched, now),
        Err(SubmitError::BodyMismatch)
    ));
    assert_eq!(m.height(), 0, "nothing was accepted");
    // The header itself is still acceptable with its real body.
    m.submit_block(good.clone(), now).unwrap();
    assert_eq!(m.height(), 1);
    assert!(matches!(
        m.submit_block(good, now),
        Err(SubmitError::Duplicate)
    ));
}

#[test]
fn transactions_survive_reorgs_via_the_mempool() {
    let mut m = open(Box::<MemoryStore>::default(), Arc::default());
    let mut miner = Miner::new(3);
    let mut rng = ChaCha20Rng::seed_from_u64(33);
    let (alice, _) = WalletKeys::generate(&mut rng);
    for _ in 0..80 {
        miner.mine_tip(&mut m);
    }
    let tx = pay(&m, &miner.keys, &alice, 12_345, &mut rng);
    let id = m.submit_tx(Transaction::from(tx.clone())).unwrap();
    assert_eq!(
        m.submit_tx(Transaction::from(tx.clone())),
        Err(MempoolError::AlreadyKnown)
    );
    // A double spend of the same output is refused by the pool.
    let conflicting = pay(&m, &miner.keys, &alice, 999, &mut rng);
    assert_eq!(
        m.submit_tx(Transaction::from(conflicting)),
        Err(MempoolError::Conflict)
    );

    let fork_parent = m.tip_id();
    let t = m.template();
    assert_eq!(t.txs.len(), 1);
    assert_eq!(t.fees, tx.fee);
    miner.mine_tip(&mut m); // block A1 includes the payment
    assert!(!m.mempool().contains(&id));
    assert_eq!(scan_all(&m, &alice).len(), 1);
    let g_a = m.generated();

    // Branch B: two coinbase-only blocks on the same parent overtake A1.
    let tb1 = m.template_on_with(&fork_parent, &known_body).unwrap();
    let b1 = miner.build(&tb1, vec![], None, 1);
    let now = b1.header.timestamp;
    let s = m.submit_block(b1.clone(), now).unwrap();
    assert!(!s.on_best_chain, "equal work: first seen stays");
    let tb2 = m
        .template_on_with(&b1.id(params().network_id), &known_body)
        .unwrap();
    let b2 = miner.build(&tb2, vec![], None, 1);
    let now = b2.header.timestamp;
    let s = m.submit_block(b2, now).unwrap();
    assert!(s.on_best_chain);
    assert_eq!(m.deepest_reorg(), 1, "A1 was disconnected");

    // The payment is undone and back in the mempool; emission is per height.
    assert!(scan_all(&m, &alice).is_empty());
    assert!(m.mempool().contains(&id), "returned to the mempool");
    assert_eq!(m.generated(), g_a + block_reward(m.height(), g_a));
    // ...and confirms again on the new branch.
    miner.mine_tip(&mut m);
    assert_eq!(scan_all(&m, &alice).len(), 1);
    assert!(m.mempool().is_empty());
}

#[test]
fn invalid_side_branch_body_is_rejected_when_it_would_win() {
    let mut m = open(Box::<MemoryStore>::default(), Arc::default());
    let mut miner = Miner::new(4);
    for _ in 0..3 {
        miner.mine_tip(&mut m);
    }
    let parent = m.tip_id();
    let a1 = miner.mine_tip(&mut m);
    // B1 over-claims its reward; its header is valid, so it is stored as a side branch.
    let tb1 = m.template_on_with(&parent, &known_body).unwrap();
    let b1 = miner.build(&tb1, vec![], Some(tb1.reward + 1), 7);
    let now = b1.header.timestamp;
    assert!(
        m.submit_block(b1.clone(), now).is_ok(),
        "side branch body not checked yet"
    );
    // B2 would make branch B heavier: connecting B1 fails, B is invalidated, A stays.
    let tb2 = m
        .template_on_with(&b1.id(params().network_id), &known_body)
        .unwrap();
    let b2 = miner.build(&tb2, vec![], None, 7);
    let now = b2.header.timestamp;
    let r = m.submit_block(b2, now);
    assert!(r.is_err() || !r.unwrap().on_best_chain);
    assert_eq!(m.tip_id(), a1.id(params().network_id));
    assert!(matches!(
        m.invalid_reason(&b1.id(params().network_id)),
        Some(BlockError::CoinbaseAmount { .. })
    ));
}

#[test]
fn restart_replays_the_store_without_recomputing_pow() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    let mut rng = ChaCha20Rng::seed_from_u64(55);
    let (alice, _) = WalletKeys::generate(&mut rng);
    let (tip, height, outputs, generated, spent) = {
        let pow = Arc::new(ZeroPow::default());
        let mut m = open(Box::new(FileStore::open(&path).unwrap()), pow.clone());
        let mut miner = Miner::new(5);
        for _ in 0..75 {
            miner.mine_tip(&mut m);
        }
        let tx = pay(&m, &miner.keys, &alice, 5_000, &mut rng);
        let ki = tx.inputs[0].key_image;
        m.submit_tx(Transaction::from(tx)).unwrap();
        miner.mine_tip(&mut m);
        // A side branch block is stored too.
        let side = m
            .template_on_with(&m.headers().main_id_at(70).unwrap(), &known_body)
            .unwrap();
        let s = miner.build(&side, vec![], None, 9);
        let now = s.header.timestamp;
        m.submit_block(s, now).unwrap();
        assert!(pow.calls.load(Ordering::SeqCst) >= 77);
        (
            m.tip_id(),
            m.height(),
            m.state().output_count(),
            m.generated(),
            ki,
        )
    };

    let pow = Arc::new(ZeroPow::default());
    let m = open(Box::new(FileStore::open(&path).unwrap()), pow.clone());
    assert_eq!(
        pow.calls.load(Ordering::SeqCst),
        0,
        "stored PoW hashes are reused"
    );
    assert_eq!(m.tip_id(), tip);
    assert_eq!(m.height(), height);
    assert_eq!(m.state().output_count(), outputs);
    assert_eq!(m.generated(), generated);
    assert!(m.state().is_key_image_spent(&spent));
    assert_eq!(scan_all(&m, &alice).len(), 1);
}

#[test]
fn restart_after_torn_write_recovers_previous_block() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    let tip_before_last = {
        let mut m = open(Box::new(FileStore::open(&path).unwrap()), Arc::default());
        let mut miner = Miner::new(6);
        for _ in 0..5 {
            miner.mine_tip(&mut m);
        }
        let id = m.tip_id();
        miner.mine_tip(&mut m);
        id
    };
    let len = std::fs::metadata(&path).unwrap().len();
    let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    f.set_len(len - 10).unwrap();
    drop(f);
    let m = open(Box::new(FileStore::open(&path).unwrap()), Arc::default());
    assert_eq!(m.height(), 5);
    assert_eq!(m.tip_id(), tip_before_last);
}

// ---------------------------------------------------------------- header-first sync

/// Two managers: `src` mines, `dst` receives headers first and bodies later.
fn mined_source(blocks: u64, seed: u64) -> (ChainManager, Vec<Block>) {
    let mut src = open(Box::<MemoryStore>::default(), Arc::default());
    let mut miner = Miner::new(seed);
    let bs = (0..blocks).map(|_| miner.mine_tip(&mut src)).collect();
    (src, bs)
}

/// The test-only step delay (`set_step_delay_for_tests`) applies to exactly
/// the bounded validation calls that have blocks to connect (mutation run
/// E): not to an unbounded submission, not to a bounded call with nothing
/// to do, and to every drain step, the first (a released block queued, no
/// drain in progress yet) included. The bounds are one-sided where timing
/// allows: a delayed call takes at least the delay; an undelayed one takes
/// far less than it.
#[test]
fn the_test_step_delay_applies_to_drain_steps_with_blocks_to_connect() {
    use std::time::{Duration, Instant};
    const DELAY: Duration = Duration::from_secs(2);
    let (_, blocks) = mined_source(8, 26);
    let headers: Vec<BlockHeader> = blocks.iter().map(|b| b.header).collect();
    let now = headers.last().unwrap().timestamp;
    let mut m = open(Box::<MemoryStore>::default(), Arc::default());
    m.accept_headers(&headers, now).unwrap();
    m.set_step_delay_for_tests(Some(DELAY));
    // Bodies that wait for their parent's: nothing to connect yet.
    for b in blocks[1..4].iter().rev() {
        let t = Instant::now();
        m.submit_block_bounded(b.clone(), now, 1).unwrap();
        assert!(t.elapsed() < DELAY, "no block to connect: no delay");
    }
    let t = Instant::now();
    assert!(m.sync_step(1), "nothing pending");
    assert!(t.elapsed() < DELAY, "an idle step: no delay");
    // The gap-filling body: its own block queued, delayed.
    let t = Instant::now();
    m.submit_block_bounded(blocks[0].clone(), now, 1).unwrap();
    assert!(t.elapsed() >= DELAY, "the first drain step is delayed");
    let mut steps = 0;
    loop {
        let t = Instant::now();
        let done = m.sync_step(1);
        assert!(t.elapsed() >= DELAY, "every drain step is delayed");
        steps += 1;
        assert!(steps < 10, "the drain never ends");
        if done {
            break;
        }
    }
    assert_eq!(m.height(), 4);
    // An unbounded submission is never delayed, even with a block to connect.
    let t = Instant::now();
    m.submit_block(blocks[4].clone(), now).unwrap();
    assert!(t.elapsed() < DELAY, "unbounded: no delay");
    assert_eq!(m.height(), 5);
}

#[test]
fn headers_without_bodies_do_not_move_the_state() {
    let (_, blocks) = mined_source(30, 20);
    let mut dst = open(Box::<MemoryStore>::default(), Arc::default());
    let headers: Vec<BlockHeader> = blocks.iter().map(|b| b.header).collect();
    let now = headers.last().unwrap().timestamp;
    assert_eq!(dst.accept_headers(&headers, now), Ok(30));
    assert_eq!(dst.header_height(), 30);
    assert_eq!(dst.height(), 0, "no bodies yet");
    let missing = dst.missing_bodies(100);
    assert_eq!(missing.len(), 30);
    assert_eq!(missing[0].0, 1);
    // Re-sending the same headers is harmless.
    assert_eq!(dst.accept_headers(&headers, now), Ok(0));
    // Bodies arriving out of order connect as soon as the gap closes.
    for b in blocks.iter().skip(1).rev() {
        let now = b.header.timestamp;
        dst.submit_block(b.clone(), now).unwrap();
    }
    assert_eq!(dst.height(), 0);
    dst.submit_block(blocks[0].clone(), blocks[0].header.timestamp)
        .unwrap();
    assert_eq!(dst.height(), 30);
    assert!(dst.missing_bodies(10).is_empty());
}

#[test]
fn heavier_header_branch_without_bodies_keeps_the_current_chain() {
    let mut m = open(Box::<MemoryStore>::default(), Arc::default());
    let mut miner = Miner::new(21);
    for _ in 0..5 {
        miner.mine_tip(&mut m);
    }
    let fork = m.headers().main_id_at(2).unwrap();
    let tip = m.tip_id();
    // A 5-block side branch from height 2 (heavier: reaches height 7), headers only.
    let mut parent = fork;
    let mut side = Vec::new();
    for i in 0..5 {
        let t = m.template_on_with(&parent, &known_body).unwrap();
        let b = miner.build(&t, vec![], None, 100 + i);
        parent = b.id(params().network_id);
        m.accept_headers(&[b.header], b.header.timestamp).unwrap();
        side.push(b);
    }
    assert_eq!(m.header_height(), 7);
    assert_eq!(
        m.tip_id(),
        tip,
        "state stays on the chain whose bodies we have"
    );
    assert_eq!(m.height(), 5);
    // Partial bodies with less work than the current tip: still no switch.
    for b in &side[..2] {
        m.submit_block(b.clone(), b.header.timestamp).unwrap();
    }
    assert_eq!(m.tip_id(), tip);
    // All bodies: the heavier branch wins.
    for b in &side[2..] {
        m.submit_block(b.clone(), b.header.timestamp).unwrap();
    }
    assert_eq!(m.height(), 7);
    assert_eq!(m.tip_id(), side[4].id(params().network_id));
    // Mining continues on the tip after the side branch took over.
    let t = m.template();
    assert_eq!(t.prev_id, side[4].id(params().network_id));
    let next = miner.mine_tip(&mut m);
    assert_eq!(m.height(), 8);
    assert_eq!(m.tip_id(), next.id(params().network_id));
    assert_eq!(m.headers().tip_id(), m.tip_id());
    assert!(m.missing_bodies(10).is_empty());
}

/// W4-SYNC and RT-LAB F2 (mutation run D): the published summary says
/// whether the connected tip is on the best header chain (not while a
/// heavier branch's bodies are missing), and the summary cell calls its tip
/// listeners once per publication that changes the connected tip, with the
/// new summary already readable. Headers alone move no tip and call nothing.
#[test]
fn the_summary_flags_a_tip_off_the_best_header_chain_and_calls_tip_listeners() {
    let mut m = open(Box::<MemoryStore>::default(), Arc::default());
    let cell = m.summary_cell();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    {
        let (seen, reader) = (seen.clone(), cell.clone());
        cell.on_tip_change(move || seen.lock().unwrap().push(reader.load().tip_id));
    }
    assert!(format!("{cell:?}").contains("tip_listeners: 1"));
    let id = |b: &Block| b.id(params().network_id);
    let mut miner = Miner::new(22);
    let tips: Vec<Hash> = (0..5).map(|_| id(&miner.mine_tip(&mut m))).collect();
    assert_eq!(
        *seen.lock().unwrap(),
        tips,
        "one call per new tip, once published"
    );
    assert!(m.summary().tip_on_best_chain);
    // A heavier side branch from height 2 (to height 7), headers only.
    let mut parent = m.headers().main_id_at(2).unwrap();
    let mut side = Vec::new();
    for i in 0..5 {
        let t = m.template_on_with(&parent, &known_body).unwrap();
        let b = miner.build(&t, vec![], None, 100 + i);
        parent = id(&b);
        m.accept_headers(&[b.header], b.header.timestamp).unwrap();
        side.push(b);
    }
    let s = m.summary();
    assert_eq!((s.tip_id, s.best_header_id), (tips[4], parent));
    assert!(
        !s.tip_on_best_chain,
        "the connected tip is off the best header chain"
    );
    assert_eq!(seen.lock().unwrap().len(), 5, "headers move no tip");
    // The bodies: the branch takes over once heavier (at its fourth block).
    for b in &side {
        m.submit_block(b.clone(), b.header.timestamp).unwrap();
    }
    let s = m.summary();
    assert_eq!(s.tip_id, parent);
    assert!(s.tip_on_best_chain);
    assert_eq!(seen.lock().unwrap()[5..], [id(&side[3]), id(&side[4])]);
}

#[test]
fn locator_and_headers_after() {
    let (src, blocks) = mined_source(100, 22);
    let loc = src.locator();
    assert_eq!(loc[0], src.tip_id());
    assert_eq!(*loc.last().unwrap(), params().genesis_id());
    assert!(loc.len() <= 64);
    // Dense near the tip, then sparse.
    assert_eq!(loc[1], blocks[98].id(params().network_id));
    // Mutation run E: the shape of the locator, by height. Strictly
    // decreasing (no id twice, genesis once and last), consecutive for the
    // tip and at least 9 predecessors, then each gap twice the one before,
    // except the last, which stops at genesis.
    let heights: Vec<u64> = loc
        .iter()
        .map(|id| src.header(id).expect("on the best chain").height)
        .collect();
    assert!(heights.windows(2).all(|w| w[0] > w[1]), "{heights:?}");
    assert_eq!(*heights.last().unwrap(), 0);
    let gaps: Vec<u64> = heights.windows(2).map(|w| w[0] - w[1]).collect();
    let dense = gaps.iter().take_while(|&&g| g == 1).count();
    assert!(dense >= 9, "{heights:?}");
    let sparse = &gaps[dense..];
    assert_eq!(sparse[0], 2, "{heights:?}");
    for w in sparse.windows(2) {
        let last = std::ptr::eq(&w[1], sparse.last().unwrap());
        assert!(w[1] == 2 * w[0] || (last && w[1] < 2 * w[0]), "{heights:?}");
    }
    // A peer that knows up to block 40 gets 41.. from us.
    let peer_locator = vec![blocks[39].id(params().network_id), params().genesis_id()];
    let hs = src.headers_after(&peer_locator, &[0; 32], 2000);
    assert_eq!(hs.len(), 60);
    assert_eq!(hs[0].height, 41);
    let stop = blocks[49].id(params().network_id);
    assert_eq!(src.headers_after(&peer_locator, &stop, 2000).len(), 10);
    assert_eq!(src.headers_after(&peer_locator, &[0; 32], 5).len(), 5);
    // Unknown locator: from genesis.
    assert_eq!(src.headers_after(&[[9; 32]], &[0; 32], 2000).len(), 100);
}

/// docs/p2p.md §6: the locator holds the tip, then its 9 predecessors one by
/// one, then ids whose height gaps double (2, 4, 8, ...) back to genesis,
/// which ends it. On a 100-block chain: heights 100 to 91, then 89, 85, 77,
/// 61, 29 and 0. Run E found the docs saying 10 predecessors; the Lead's
/// decision (RT-MUTE) is that the docs follow the code. Bitcoin Core's
/// locator has 11 consecutive ids (the tip and 10 predecessors); the count is
/// not consensus-relevant: any decreasing locator ending at genesis finds the
/// fork with every peer.
#[test]
fn the_locator_has_the_tip_and_nine_predecessors_one_by_one() {
    let (src, _) = mined_source(100, 22);
    let heights: Vec<u64> = src
        .locator()
        .iter()
        .map(|id| src.header(id).expect("on the best chain").height)
        .collect();
    assert_eq!(
        heights,
        [100, 99, 98, 97, 96, 95, 94, 93, 92, 91, 89, 85, 77, 61, 29, 0]
    );
    // The shape, stated: 9 gaps of 1, then each gap twice the one before,
    // the last one cut at genesis.
    let gaps: Vec<u64> = heights.windows(2).map(|w| w[0] - w[1]).collect();
    let dense = gaps.iter().take_while(|&&g| g == 1).count();
    assert_eq!(dense, 9);
    for (k, g) in gaps[dense..gaps.len() - 1].iter().enumerate() {
        assert_eq!(*g, 2 << k);
    }
    assert!(*gaps.last().unwrap() <= 2 << (gaps.len() - 1 - dense));
}

#[test]
fn pow_jobs_use_seeds_from_the_batch() {
    use blacksilk_consensus::seed_height;
    // Long enough to cross the first RandomX key change (2048 + 64).
    let (src, blocks) = mined_source(2200, 23);
    let dst = open(Box::<MemoryStore>::default(), Arc::default());
    let headers: Vec<BlockHeader> = blocks.iter().map(|b| b.header).collect();
    let (_, jobs) = dst.pow_jobs(&headers).expect("extends genesis");
    for (h, (seed, bytes)) in headers.iter().zip(&jobs) {
        assert_eq!(bytes, &h.pow_blob(params().network_id));
        let sh = seed_height(h.height, 2048, 64);
        assert_eq!(
            *seed,
            src.headers().main_id_at(sh).unwrap(),
            "height {}",
            h.height
        );
    }
    assert!(
        jobs.iter().any(|(s, _)| *s != params().genesis_id()),
        "a key change is covered"
    );
    // A batch whose first header is the key block (height 2048) itself:
    // from height 2113 on, the key is that first header, taken from the
    // batch (mutation run E: the `sh >= base` edge).
    let mut part = open(Box::<MemoryStore>::default(), Arc::default());
    let now = headers.last().unwrap().timestamp;
    assert_eq!(part.accept_headers(&headers[..2047], now), Ok(2047));
    let tail = &headers[2047..];
    assert_eq!(tail[0].height, 2048);
    let (_, jobs) = part.pow_jobs(tail).expect("extends block 2047");
    let key = src.headers().main_id_at(2048).unwrap();
    for (h, (seed, _)) in tail.iter().zip(&jobs) {
        let want = src
            .headers()
            .main_id_at(seed_height(h.height, 2048, 64))
            .unwrap();
        assert_eq!(*seed, want, "height {}", h.height);
    }
    assert_eq!(jobs.last().unwrap().0, key, "the batch's own first header");
    // Not a chain / unknown parent: no jobs.
    assert!(dst.pow_jobs(&headers[1..]).is_none());
    let mut broken = headers[..3].to_vec();
    broken.swap(1, 2);
    assert!(dst.pow_jobs(&broken).is_none());
    // Either link alone breaks the chain (mutation run E): the right parent
    // at a wrong height, or the right height on another parent.
    let mut skips = headers[..2].to_vec();
    skips[1].height += 1;
    assert!(dst.pow_jobs(&skips).is_none(), "height gap");
    let mut orphan = headers[..3].to_vec();
    orphan[2].prev_id = [7; 32];
    assert!(dst.pow_jobs(&orphan).is_none(), "another parent");
    assert!(dst.pow_jobs(&headers[..3]).is_some());
}

/// The hot RandomX keys of the best header chain reach the PoW layer when
/// the manager opens and whenever they change, and only then (mutation run
/// E: `refresh_hot_seeds`): the genesis key, then, from the height where the
/// next key comes within the pin window, both keys.
#[test]
fn hot_randomx_keys_are_passed_on_when_they_change() {
    let pow = Arc::new(ZeroPow::default());
    let mut m = open(Box::<MemoryStore>::default(), pow.clone());
    let genesis = params().genesis_id();
    assert_eq!(*pow.hot.lock().unwrap(), vec![vec![genesis]], "at open");
    let mut miner = Miner::new(25);
    for _ in 0..2100 {
        miner.mine_tip(&mut m);
    }
    let hot = pow.hot.lock().unwrap().clone();
    let key = m.headers().main_id_at(2048).unwrap();
    assert_eq!(hot, vec![vec![genesis], vec![genesis, key]], "changes only");
    assert_eq!(
        hot.last().unwrap(),
        &blacksilk_chain::sync_policy::hot_seeds(m.headers())
    );
}

/// A batch whose first header does not sit at its parent's height + 1 gets no
/// jobs. Before 2026-09-27 a far height on a known parent looked its seed up
/// beyond the parent's branch and panicked (index out of bounds) through
/// this public API.
#[test]
fn pow_jobs_reject_a_height_gap() {
    let (src, blocks) = mined_source(3, 24);
    let mut far = blocks[0].header;
    far.height = 5_000; // seed height 4096, far above the parent (genesis)
    assert!(src.pow_jobs(&[far]).is_none());
    let mut gap = blocks[2].header;
    gap.height += 1;
    assert!(src.pow_jobs(&[gap]).is_none());
    // A well-formed batch still gets jobs.
    assert!(src.pow_jobs(&[blocks[2].header]).is_some());
}

/// The PoW cache is keyed by the RandomX key as well as the header bytes: a
/// hash computed under one seed is never returned for another.
#[test]
fn the_pow_cache_key_includes_the_seed() {
    use blacksilk_chain::manager::CachedPow;
    let pow = Arc::new(ZeroPow::default());
    let cache = CachedPow::new(pow.clone());
    let bytes = [5u8; blacksilk_consensus::POW_BLOB_SIZE];
    let (seed_a, seed_b) = ([1u8; 32], [2u8; 32]);
    cache.pow_hash(&seed_a, &bytes);
    assert_eq!(pow.calls.load(Ordering::SeqCst), 1);
    assert_eq!(cache.lookup(&seed_a, &bytes), Some([0; 32]));
    assert_eq!(cache.lookup(&seed_b, &bytes), None, "wrong seed misses");
    cache.pow_hash(&seed_b, &bytes);
    assert_eq!(pow.calls.load(Ordering::SeqCst), 2, "recomputed for seed b");
    cache.pow_hash(&seed_a, &bytes);
    assert_eq!(pow.calls.load(Ordering::SeqCst), 2, "seed a still cached");
    // compute_parallel skips only jobs cached under their own seed.
    cache.compute_parallel(&[(seed_a, bytes), ([3u8; 32], bytes)], 2);
    assert_eq!(pow.calls.load(Ordering::SeqCst), 3);
}

/// The `nth` mature, unspent output of `from`, with a ring.
fn plan_nth(m: &ChainManager, from: &WalletKeys, nth: usize, rng: &mut ChaCha20Rng) -> InputPlan {
    let height = m.height() + 1;
    let owned = scan_all(m, from)
        .into_iter()
        .filter(|o| {
            let age = if o.coinbase {
                COINBASE_MATURITY
            } else {
                SPENDABLE_AGE
            };
            height >= o.height + age && !m.state().is_key_image_spent(&o.key_image(from))
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
            state.output(i).is_some_and(|r| {
                let age = if r.coinbase {
                    COINBASE_MATURITY
                } else {
                    SPENDABLE_AGE
                };
                height >= r.height + age
            })
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

/// A node restarted from its block file rebuilds the PX state exactly: the
/// commitment tree, the pool, the nullifiers, the contract registry and the
/// registration list wallets download (docs/px.md §11.3, §13.4).
#[test]
fn restart_rebuilds_the_px_state_exactly() {
    use blacksilk_px::wallet::{self as pxw, Account};
    use blacksilk_tx::px::Registration;
    use blacksilk_tx::px_builder::{build_deploy, build_px, px_standard_fee, PxPlan};

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    let (tip, root, pool, nullifiers, log, contract) = {
        let mut m = open(Box::new(FileStore::open(&path).unwrap()), Arc::default());
        let mut miner = Miner::new(8);
        for _ in 0..75 {
            miner.mine_tip(&mut m);
        }
        let rules = *m.rules();
        // A PX deposit (a real proof) and a contract deploy, from two outputs.
        let amount = 5_000_000;
        let plan = plan_nth(&m, &miner.keys, 0, &mut miner.rng);
        let acct = Account::from_seed(&[3; 32]);
        let rng = &mut miner.rng;
        let witness = pxw::witness(
            m.state().px().root(),
            amount,
            0,
            [pxw::dummy_input(rng), pxw::dummy_input(rng)],
            [
                pxw::output(rng, acct.owner(0), amount),
                pxw::empty_output(rng),
            ],
        );
        let primary = miner.keys.address(SubaddressIndex::PRIMARY);
        let deposit = build_px(
            PxPlan {
                keys: Some(&miner.keys),
                inputs: vec![plan],
                change: Some(primary),
                payouts: vec![],
                witness,
                recipients: [Some(acct.address(0)), None],
                functions: vec![],
                fee: px_standard_fee(),
                window: Default::default(),
                hedge_secret: [0x5e; 32],
            },
            &rules,
            &mut miner.rng,
        )
        .unwrap();
        m.submit_tx(Transaction::Px(Box::new(deposit))).unwrap();
        let plan = plan_nth(&m, &miner.keys, 1, &mut miner.rng);
        let deploy = build_deploy(
            &miner.keys,
            vec![plan],
            &[Payment {
                address: primary,
                amount: 0,
            }],
            &primary,
            [4; 32],
            vec![Registration {
                elf: blacksilk_px::vault::VAULT_ELF.to_vec(),
                budget: blacksilk_px::vault::BUDGET,
                abi: blacksilk_tx::px::ABI_VERSION,
                out_words: 1,
            }],
            &rules,
            &mut miner.rng,
        )
        .unwrap();
        let contract = deploy.contract_id();
        m.submit_tx(Transaction::PxDeploy(Box::new(deploy)))
            .unwrap();
        miner.mine_tip(&mut m);
        let s = m.state();
        assert_eq!(s.px_pool(), amount as u128, "the deposit is in the block");
        assert_eq!(s.px_contract_log().len(), 1, "the deploy is in the block");
        (
            m.tip_id(),
            s.px().root(),
            s.px_pool(),
            s.px_nullifiers(0, u64::MAX),
            s.px_contract_log().to_vec(),
            contract,
        )
    };

    let m = open(Box::new(FileStore::open(&path).unwrap()), Arc::default());
    let s = m.state();
    assert_eq!(m.tip_id(), tip);
    assert_eq!(s.px().root(), root);
    assert_eq!(s.px_pool(), pool);
    assert_eq!(s.px_nullifiers(0, u64::MAX), nullifiers);
    assert_eq!(s.px_contract_log(), log.as_slice());
    assert!(s.px_contract_exists(&contract));
    assert_eq!(
        s.px_function(&contract, &blacksilk_px::vault::program().id())
            .map(|f| (f.budget, f.abi, f.out_words)),
        Some((
            blacksilk_px::vault::BUDGET,
            blacksilk_tx::px::ABI_VERSION,
            blacksilk_px::vault::OUT_WORDS
        ))
    );
}

/// Bodies arrive in any order during header-first sync (16 in flight, several
/// peers) and are stored in arrival order. A restart must replay them.
#[test]
fn restart_after_out_of_order_body_arrival_replays_the_store() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    let (_, blocks) = mined_source(20, 21);
    let tip = {
        let mut dst = open(Box::new(FileStore::open(&path).unwrap()), Arc::default());
        let headers: Vec<BlockHeader> = blocks.iter().map(|b| b.header).collect();
        let now = headers.last().unwrap().timestamp;
        dst.accept_headers(&headers, now).unwrap();
        for b in blocks.iter().rev() {
            dst.submit_block(b.clone(), b.header.timestamp).unwrap();
        }
        assert_eq!(dst.height(), 20);
        dst.tip_id()
    };
    let m = ChainManager::open(
        params(),
        TxRules::for_chain(&params()),
        Arc::new(ZeroPow::default()),
        Box::new(FileStore::open(&path).unwrap()),
        [7; 32],
    )
    .expect("the node restarts");
    assert_eq!(m.height(), 20);
    assert_eq!(m.tip_id(), tip);
}

/// A block store whose writes fail on request (a full disk, an I/O error),
/// writing nothing, as `FileStore` guarantees after undoing a failed append.
struct FlakyStore {
    inner: FileStore,
    fail: Arc<std::sync::atomic::AtomicBool>,
}
impl BlockStore for FlakyStore {
    fn append(&mut self, pow_hash: &Hash, block: &[u8]) -> std::io::Result<()> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(std::io::Error::other("disk full"));
        }
        self.inner.append(pow_hash, block)
    }
    fn load(&mut self) -> std::io::Result<Vec<blacksilk_chain::store::Record>> {
        self.inner.load()
    }
    fn bind(&mut self, identity: &blacksilk_chain::store::StoreIdentity) -> std::io::Result<()> {
        self.inner.bind(identity)
    }
}

/// A write failure during sync: the block is refused (not kept in memory as
/// if stored), the node keeps running, the block is accepted when offered
/// again, and a restart replays the store, including blocks whose parent was
/// written after them, or never.
#[test]
fn a_failed_block_write_during_sync_is_recoverable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    let (_, blocks) = mined_source(20, 22);
    let fail = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let store = FlakyStore {
            inner: FileStore::open(&path).unwrap(),
            fail: fail.clone(),
        };
        let mut m = open(Box::new(store), Arc::default());
        let headers: Vec<BlockHeader> = blocks.iter().map(|b| b.header).collect();
        m.accept_headers(&headers, headers.last().unwrap().timestamp)
            .unwrap();
        for b in &blocks[..5] {
            m.submit_block(b.clone(), b.header.timestamp).unwrap();
        }
        // The disk is full while block 6 arrives.
        fail.store(true, Ordering::SeqCst);
        assert!(matches!(
            m.submit_block(blocks[5].clone(), blocks[5].header.timestamp),
            Err(SubmitError::Store(_))
        ));
        assert_eq!(
            m.height(),
            5,
            "a block that was not stored is not connected"
        );
        fail.store(false, Ordering::SeqCst);
        // Later blocks arrive; block 6 is offered again last.
        for b in &blocks[6..] {
            m.submit_block(b.clone(), b.header.timestamp).unwrap();
        }
        assert_eq!(m.height(), 5);
        m.submit_block(blocks[5].clone(), blocks[5].header.timestamp)
            .unwrap();
        assert_eq!(m.height(), 20);
    }
    let m = open(Box::new(FileStore::open(&path).unwrap()), Arc::default());
    assert_eq!(
        m.height(),
        20,
        "restart replays blocks stored before their parent"
    );

    // If block 6 is never stored, a restart keeps blocks 1 to 5 and starts;
    // blocks 7 to 20 are downloaded again.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    {
        let mut m = open(Box::new(FileStore::open(&path).unwrap()), Arc::default());
        let headers: Vec<BlockHeader> = blocks.iter().map(|b| b.header).collect();
        m.accept_headers(&headers, headers.last().unwrap().timestamp)
            .unwrap();
        for (i, b) in blocks.iter().enumerate() {
            if i != 5 {
                m.submit_block(b.clone(), b.header.timestamp).unwrap();
            }
        }
    }
    let mut m = open(Box::new(FileStore::open(&path).unwrap()), Arc::default());
    assert_eq!(m.height(), 5);
    let headers: Vec<BlockHeader> = blocks.iter().map(|b| b.header).collect();
    m.accept_headers(&headers, headers.last().unwrap().timestamp)
        .unwrap();
    for b in &blocks[5..] {
        let _ = m.submit_block(b.clone(), b.header.timestamp);
    }
    assert_eq!(m.height(), 20);
}

// ---------------------------------------------------------------- mempool

/// A 1-input transfer of the `nth` spendable output of `from` to `to`, with
/// the given fee.
fn transfer_nth(
    m: &ChainManager,
    from: &WalletKeys,
    to: &WalletKeys,
    nth: usize,
    fee: u64,
    rng: &mut ChaCha20Rng,
) -> Transfer {
    let plan = plan_nth(m, from, nth, rng);
    build_transfer(
        from,
        vec![plan],
        &[Payment {
            address: to.address(SubaddressIndex::PRIMARY),
            amount: 1_000,
        }],
        &from.address(SubaddressIndex::PRIMARY),
        fee,
        m.rules(),
        rng,
    )
    .unwrap()
}

/// Admission: a tampered transaction and one below the minimum fee are
/// invalid and leave the pool untouched; valid ones are admitted.
#[test]
fn the_mempool_admits_only_valid_transactions() {
    let mut m = open(Box::<MemoryStore>::default(), Arc::default());
    let mut miner = Miner::new(31);
    let mut rng = ChaCha20Rng::seed_from_u64(1031);
    let (alice, _) = WalletKeys::generate(&mut rng);
    for _ in 0..80 {
        miner.mine_tip(&mut m);
    }
    let fee = standard_fee(1, 2, m.rules());
    // Tampered after signing: the fee changes the signed message.
    let mut tampered = transfer_nth(&m, &miner.keys, &alice, 0, fee, &mut rng);
    tampered.fee += 1;
    assert!(matches!(
        m.submit_tx(Transaction::from(tampered)),
        Err(MempoolError::Invalid(_))
    ));
    // Not the exact standard fee (the builder refuses to sign such a
    // transaction, so the fee is changed after signing): the fee rule (T8)
    // rejects it before the signatures are checked.
    let mut cheap = transfer_nth(&m, &miner.keys, &alice, 1, fee, &mut rng);
    cheap.fee = 1;
    assert!(matches!(
        m.submit_tx(Transaction::from(cheap)),
        Err(MempoolError::Invalid(
            blacksilk_tx::validate::TxError::FeeNotExact { .. }
        ))
    ));
    assert!(m.mempool().is_empty(), "nothing admitted");
    // A valid one is admitted, and a second input of the same wallet too.
    let a = transfer_nth(&m, &miner.keys, &alice, 2, fee, &mut rng);
    let b = transfer_nth(&m, &miner.keys, &alice, 3, fee, &mut rng);
    m.submit_tx(Transaction::from(a)).unwrap();
    m.submit_tx(Transaction::from(b)).unwrap();
    assert_eq!(m.mempool().len(), 2);
    assert_eq!(m.template().txs.len(), 2);
}

/// The mempool is not persisted (docs/blocks.md §7): after a restart it is
/// empty, the same transaction is accepted again, and it confirms.
#[test]
fn after_a_restart_the_mempool_is_rebuilt_by_resubmission() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    let mut rng = ChaCha20Rng::seed_from_u64(1032);
    let (alice, _) = WalletKeys::generate(&mut rng);
    let mut miner = Miner::new(32);
    let tx = {
        let mut m = open(Box::new(FileStore::open(&path).unwrap()), Arc::default());
        for _ in 0..80 {
            miner.mine_tip(&mut m);
        }
        let fee = standard_fee(1, 2, m.rules());
        let tx = Transaction::from(transfer_nth(&m, &miner.keys, &alice, 0, fee, &mut rng));
        m.submit_tx(tx.clone()).unwrap();
        assert_eq!(m.mempool().len(), 1);
        tx
    };
    let mut m = open(Box::new(FileStore::open(&path).unwrap()), Arc::default());
    assert!(m.mempool().is_empty(), "not persisted");
    m.submit_tx(tx.clone()).unwrap();
    miner.mine_tip(&mut m);
    assert!(m.mempool().is_empty());
    assert_eq!(scan_all(&m, &alice).len(), 1, "confirmed");
}

/// Mempool contents never change a block's verdict. Node A, with the
/// transactions pooled (their checks done on admission), and node B, which
/// never saw them, reach the same state from the same block. A block that
/// replaces a pooled transaction with a tampered copy is rejected by both:
/// the proof cache is keyed by the id, which commits to every byte.
#[test]
fn mempool_contents_never_change_a_blocks_verdict() {
    let dir = tempfile::tempdir().unwrap();
    let path_a = dir.path().join("a.dat");
    let mut rng = ChaCha20Rng::seed_from_u64(1033);
    let (alice, _) = WalletKeys::generate(&mut rng);
    let mut miner = Miner::new(33);
    let mut a = open(Box::new(FileStore::open(&path_a).unwrap()), Arc::default());
    for _ in 0..80 {
        miner.mine_tip(&mut a);
    }
    // B: the same chain, from A's store, with an empty mempool.
    let path_b = dir.path().join("b.dat");
    std::fs::copy(&path_a, &path_b).unwrap();
    let mut b = open(Box::new(FileStore::open(&path_b).unwrap()), Arc::default());
    assert_eq!(b.tip_id(), a.tip_id());

    let fee = standard_fee(1, 2, a.rules());
    for n in 0..3 {
        let tx = transfer_nth(&a, &miner.keys, &alice, n, fee, &mut rng);
        a.submit_tx(Transaction::from(tx)).unwrap();
    }
    let t = a.template();
    assert_eq!(t.txs.len(), 3);
    let block = miner.build(&t, t.txs.clone(), None, 0);

    // A tampered variant: one pooled transaction with a changed fee.
    let mut bad_txs = t.txs.clone();
    if let Transaction::Transfer(x) = &mut bad_txs[1] {
        x.fee += 1;
    }
    let bad = miner.build(&t, bad_txs, Some(t.reward + t.fees + 1), 1);
    let now = bad.header.timestamp;
    assert!(matches!(
        a.submit_block(bad.clone(), now),
        Err(SubmitError::Body(_))
    ));
    assert!(matches!(
        b.submit_block(bad, now),
        Err(SubmitError::Body(_))
    ));

    let now = block.header.timestamp;
    a.submit_block(block.clone(), now).unwrap();
    b.submit_block(block, now).unwrap();
    assert_eq!(a.tip_id(), b.tip_id());
    assert_eq!(a.state().output_count(), b.state().output_count());
    assert_eq!(a.generated(), b.generated());
    assert!(a.mempool().is_empty());
}

/// Measurement (docs/blocks.md §7): after every block the pool re-checks
/// each pooled v1 transaction in full (signatures and range proof) under the
/// chain lock. Prints the cost per transaction; run with `--nocapture`.
#[test]
fn mempool_revalidation_cost_per_transaction() {
    let mut m = open(Box::<MemoryStore>::default(), Arc::default());
    let mut miner = Miner::new(34);
    let mut rng = ChaCha20Rng::seed_from_u64(1034);
    let (alice, _) = WalletKeys::generate(&mut rng);
    let n = 40;
    for _ in 0..(60 + n + 1) {
        miner.mine_tip(&mut m);
    }
    let fee = standard_fee(1, 2, m.rules());
    for i in 0..n {
        let tx = transfer_nth(&m, &miner.keys, &alice, i, fee, &mut rng);
        m.submit_tx(Transaction::from(tx)).unwrap();
    }
    assert_eq!(m.mempool().len(), n);
    // An empty block: connecting it revalidates the whole pool.
    let t = m.template_on_with(&m.tip_id(), &known_body).unwrap();
    let empty = miner.build(&t, vec![], None, 7);
    let now = empty.header.timestamp;
    let start = std::time::Instant::now();
    m.submit_block(empty, now).unwrap();
    let per_tx = start.elapsed() / n as u32;
    assert_eq!(m.mempool().len(), n, "all still valid");
    println!(
        "revalidation after a block: {n} pooled transfers in {:?} ({per_tx:?} each)",
        start.elapsed()
    );
    // At the 50 MB v1 cap (about 20 000 one-input transfers of ~2.5 kB) this
    // cost is paid after every block, under the chain lock.
    println!(
        "extrapolated to a full v1 pool (20 000 transfers): {:?} per block",
        per_tx * 20_000
    );
}

/// After a plain extension the pool re-checks only the rules an extension can
/// change (`revalidate_after_extension`). Its verdict equals full validation
/// for a transaction that stays valid and for one whose input a block spent
/// with a competing transaction; and the pool drops the latter.
#[test]
fn revalidation_after_an_extension_agrees_with_full_validation() {
    use blacksilk_tx::validate::{revalidate_after_extension, validate_mempool_tx};
    let mut m = open(Box::<MemoryStore>::default(), Arc::default());
    let mut miner = Miner::new(35);
    let mut rng = ChaCha20Rng::seed_from_u64(1035);
    let (alice, _) = WalletKeys::generate(&mut rng);
    for _ in 0..80 {
        miner.mine_tip(&mut m);
    }
    let fee = standard_fee(1, 2, m.rules());
    let stays = Transaction::from(transfer_nth(&m, &miner.keys, &alice, 0, fee, &mut rng));
    let loses = Transaction::from(transfer_nth(&m, &miner.keys, &alice, 1, fee, &mut rng));
    // A competing spend of the same output as `loses` (other ring, other id).
    let rival = Transaction::from(transfer_nth(&m, &miner.keys, &alice, 1, fee, &mut rng));
    assert_ne!(rival.hash(), loses.hash());
    m.submit_tx(stays.clone()).unwrap();
    m.submit_tx(loses.clone()).unwrap();

    // A block with the rival (not from the pool), then more plain blocks.
    let t = m.template_on_with(&m.tip_id(), &known_body).unwrap();
    let b = miner.build(&t, vec![rival], Some(t.reward + fee), 3);
    let now = b.header.timestamp;
    m.submit_block(b, now).unwrap();
    for _ in 0..3 {
        let t = m.template_on_with(&m.tip_id(), &known_body).unwrap();
        let b = miner.build(&t, vec![], None, 4);
        let now = b.header.timestamp;
        m.submit_block(b, now).unwrap();
    }
    let next = m.height() + 1;
    for tx in [&stays, &loses] {
        assert_eq!(
            revalidate_after_extension(tx, m.state(), next).is_ok(),
            validate_mempool_tx(tx, m.state(), next, m.rules()).is_ok(),
        );
    }
    assert!(revalidate_after_extension(&stays, m.state(), next).is_ok());
    assert!(revalidate_after_extension(&loses, m.state(), next).is_err());
    assert!(m.mempool().contains(&stays.hash()));
    assert!(
        !m.mempool().contains(&loses.hash()),
        "the double spend left the pool"
    );
}

// ---------------------------------------------------------------- RandomX seed switch

/// Regtest rules with a short RandomX key epoch (16 blocks, lag 4): the key
/// switches at heights 21 and 37 instead of 2113, so the switch runs with real
/// RandomX in the test suite. Only the epoch length differs from the network
/// parameters (2048, lag 64); the code path is the same.
fn short_epoch_params() -> ChainParams {
    let mut p = params();
    p.seed_epoch = 16;
    p.seed_lag = 4;
    p
}

fn open_real(p: &ChainParams, store: Box<dyn BlockStore>) -> ChainManager {
    ChainManager::open(
        p.clone(),
        TxRules::for_chain(p),
        Arc::new(blacksilk_consensus::RandomXPow::new()),
        store,
        [9; 32],
    )
    .unwrap()
}

/// Mines `n` blocks on `parent` with real RandomX (regtest difficulty 1: any
/// hash passes, but every header's hash is computed and checked), 10 s apart.
fn mine_real(
    m: &mut ChainManager,
    miner: &mut Miner,
    parent: Hash,
    n: usize,
    tag: u64,
) -> Vec<Block> {
    let mut out = Vec::new();
    let mut p = parent;
    for _ in 0..n {
        let t = m.template_on_with(&p, &known_body).unwrap();
        let mut b = miner.build(&t, vec![], None, tag);
        let parent_time = m.headers().header(&p).unwrap().timestamp;
        b.header.timestamp = t.min_timestamp.max(parent_time + 10);
        let now = b.header.timestamp;
        m.submit_block(b.clone(), now).expect("valid block");
        p = b.id(params().network_id);
        out.push(b);
    }
    out
}

/// The RandomX key a block at `height` must use on `branch`, computed from the
/// test's own knowledge of the branch (`branch[k]` = id of its block at height
/// k), independently of the header chain: genesis up to height 20, the
/// branch's block 16 from 21, its block 32 from 37 (epoch 16, lag 4).
fn expected_seed(branch: &HashMap<u64, Hash>, genesis: Hash, height: u64) -> Hash {
    match height {
        0..=20 => genesis,
        21..=36 => branch[&16],
        _ => branch[&32],
    }
}

/// Reference light-mode RandomX hashes of `headers` (with their expected
/// seeds), one RandomX cache per distinct seed.
fn reference_hashes(jobs: &[(Hash, BlockHeader)]) -> HashMap<(Hash, HeaderBytes), Hash> {
    let mut out = HashMap::new();
    let mut seeds: Vec<Hash> = jobs.iter().map(|(s, _)| *s).collect();
    seeds.sort();
    seeds.dedup();
    for seed in seeds {
        let cache = blacksilk_randomx::Cache::new(&seed);
        let mut vm = blacksilk_randomx::Vm::light(&cache);
        for (s, h) in jobs.iter().filter(|(s, _)| *s == seed) {
            let bytes = h.pow_blob(params().network_id);
            out.insert((*s, bytes), vm.hash(&bytes));
        }
    }
    out
}

type HeaderBytes = [u8; blacksilk_consensus::POW_BLOB_SIZE];

/// Every header of `jobs` has a cached PoW hash under its expected seed, equal
/// to the reference RandomX hash. A manager that validated (or replayed) a
/// header under any other key would have cached it under that key instead.
fn assert_pow_under_expected_seeds(
    m: &ChainManager,
    jobs: &[(Hash, BlockHeader)],
    reference: &HashMap<(Hash, HeaderBytes), Hash>,
    what: &str,
) {
    for (seed, h) in jobs {
        let bytes = h.pow_blob(params().network_id);
        assert_eq!(
            m.pow_cache().lookup(seed, &bytes),
            Some(reference[&(*seed, bytes)]),
            "{what}: height {}",
            h.height
        );
    }
}

/// The RandomX key switch, with real RandomX (light verification): blocks on
/// either side of the switch verify; a restart replays across it; a fresh node
/// syncs the headers across it; and a heavier branch that forks before the
/// seed block, so that its blocks after the switch use a different key, wins
/// a reorganization and is itself verified with its own key.
///
/// At regtest difficulty 1 any hash passes, so passing validation alone would
/// not detect a wrong key. Every header's cached PoW hash is therefore checked
/// against a reference RandomX hash under the key the test expects.
#[test]
fn the_randomx_key_switch_works_across_sync_restart_and_reorg() {
    let p = short_epoch_params();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    let mut miner = Miner::new(36);
    let genesis = p.genesis_id();
    let (main, tip) = {
        let mut m = open_real(&p, Box::new(FileStore::open(&path).unwrap()));
        let blocks = mine_real(&mut m, &mut miner, genesis, 40, 1);
        assert_eq!(m.height(), 40);
        // Keys: genesis up to height 20, block 16 from 21, block 32 from 37.
        let id = |h: u64| m.headers().main_id_at(h).unwrap();
        let seed = |h: u64| m.headers().seed_id_for(id(h - 1), h);
        assert_eq!(seed(20), genesis);
        assert_eq!(seed(21), id(16));
        assert_eq!(seed(36), id(16));
        assert_eq!(seed(37), id(32));
        (blocks, m.tip_id())
    };
    let main_ids: HashMap<u64, Hash> = main
        .iter()
        .map(|b| (b.header.height, b.id(p.network_id)))
        .collect();
    let main_jobs: Vec<(Hash, BlockHeader)> = main
        .iter()
        .map(|b| {
            let h = b.header;
            (expected_seed(&main_ids, genesis, h.height), h)
        })
        .collect();

    // Restart: the store replays across both switches.
    let started = std::time::Instant::now();
    let m = open_real(&p, Box::new(FileStore::open(&path).unwrap()));
    assert_eq!(m.tip_id(), tip);
    println!("restart across 2 key switches: {:.1?}", started.elapsed());
    drop(m);

    // A fresh node: headers first (PoW computed in parallel, seeds from the
    // batch), then bodies.
    let mut fresh = open_real(&p, Box::<MemoryStore>::default());
    let headers: Vec<BlockHeader> = main.iter().map(|b| b.header).collect();
    let started = std::time::Instant::now();
    let (pow, jobs) = fresh.pow_jobs(&headers).unwrap();
    for ((seed, _), (expected, h)) in jobs.iter().zip(&main_jobs) {
        assert_eq!(seed, expected, "pow_jobs seed at height {}", h.height);
    }
    pow.compute_parallel(&jobs, 4);
    fresh
        .accept_headers(&headers, headers.last().unwrap().timestamp)
        .unwrap();
    println!(
        "header sync of 40 headers across 2 switches: {:.1?}",
        started.elapsed()
    );
    for b in &main {
        fresh.submit_block(b.clone(), b.header.timestamp).unwrap();
    }
    assert_eq!(fresh.tip_id(), tip);

    // A heavier branch forking at height 10, before the seed block 16: from
    // height 21 it uses its own block 16 as the key.
    let fork = main[9].id(p.network_id);
    let side = mine_real(&mut fresh, &mut miner, fork, 32, 2);
    assert_eq!(fresh.height(), 42, "the heavier branch won");
    let side_tip = fresh.tip_id();
    let side16 = side[5].id(p.network_id);
    assert_eq!(fresh.headers().main_id_at(16).unwrap(), side16);
    assert_eq!(
        fresh.headers().seed_id_for(side[20].id(p.network_id), 22),
        side16,
        "the branch's own key"
    );
    assert_ne!(side16, main[15].id(p.network_id));
    assert!(fresh.deepest_reorg() >= 30);

    // Reference hashes under the expected keys: the side branch shares main's
    // blocks up to height 10 and has its own from 11.
    let mut side_ids: HashMap<u64, Hash> = main_ids
        .iter()
        .filter(|(h, _)| **h <= 10)
        .map(|(h, id)| (*h, *id))
        .collect();
    side_ids.extend(side.iter().map(|b| (b.header.height, b.id(p.network_id))));
    assert_eq!(side_ids[&16], side16);
    let side_jobs: Vec<(Hash, BlockHeader)> = side
        .iter()
        .map(|b| {
            let h = b.header;
            (expected_seed(&side_ids, genesis, h.height), h)
        })
        .collect();
    assert!(side_jobs.iter().any(|(s, _)| *s == side_ids[&32]));
    let all_jobs: Vec<(Hash, BlockHeader)> = main_jobs.iter().chain(&side_jobs).copied().collect();
    let started = std::time::Instant::now();
    let reference = reference_hashes(&all_jobs);
    println!("reference hashes (5 keys): {:.1?}", started.elapsed());
    assert_pow_under_expected_seeds(&fresh, &main_jobs, &reference, "fresh node, main");
    assert_pow_under_expected_seeds(&fresh, &side_jobs, &reference, "fresh node, branch");

    // The original node receives the branch's blocks and reorganizes too.
    let mut m = open_real(&p, Box::new(FileStore::open(&path).unwrap()));
    assert_pow_under_expected_seeds(&m, &main_jobs, &reference, "replayed main");
    for b in &side {
        let _ = m.submit_block(b.clone(), b.header.timestamp);
    }
    assert_eq!(m.tip_id(), side_tip);
    assert_pow_under_expected_seeds(&m, &side_jobs, &reference, "received branch");
    drop(m);
    // ...and restarts onto it, trusting its stored hashes under the right keys.
    let m = open_real(&p, Box::new(FileStore::open(&path).unwrap()));
    assert_eq!(
        m.tip_id(),
        side_tip,
        "restart after a reorg across the key switch"
    );
    assert_pow_under_expected_seeds(&m, &all_jobs, &reference, "replay after the reorg");
}

// ------------------------------------------------ stored PoW check (TM2-5)

/// A PoW function that records the heights it hashes and answers the zero
/// hash, except at `forged`, where it answers another value: a store
/// written with [`ZeroPow`] then holds one stored hash that its header does
/// not produce, as a store with one planted block would.
struct Recheck {
    forged: Option<u64>,
    heights: std::sync::Mutex<Vec<u64>>,
}

impl Recheck {
    fn new(forged: Option<u64>) -> Arc<Self> {
        Arc::new(Self {
            forged,
            heights: Default::default(),
        })
    }

    fn heights(&self) -> Vec<u64> {
        let mut h = self.heights.lock().unwrap().clone();
        h.sort_unstable();
        h
    }
}

impl PowFunction for Recheck {
    fn pow_hash(&self, _: &Hash, header: &blacksilk_consensus::PowBlob) -> Hash {
        let height = blob_height(header);
        self.heights.lock().unwrap().push(height);
        if Some(height) == self.forged {
            [0xee; 32]
        } else {
            [0; 32]
        }
    }
}

/// A file store of `n` mined blocks written with [`ZeroPow`].
fn zero_pow_store(dir: &std::path::Path, n: usize) -> std::path::PathBuf {
    let path = dir.join("blocks.dat");
    let mut m = open(Box::new(FileStore::open(&path).unwrap()), Arc::default());
    let mut miner = Miner::new(77);
    for _ in 0..n {
        miner.mine_tip(&mut m);
    }
    path
}

fn open_checked(
    path: &std::path::Path,
    pow: Arc<Recheck>,
    seed: [u8; 32],
    check: StorePowCheck,
) -> std::io::Result<ChainManager> {
    let p = params();
    let rules = TxRules::for_chain(&p);
    ChainManager::open_checked(
        p,
        rules,
        pow,
        Box::new(FileStore::open(path).unwrap()),
        seed,
        check,
    )
}

/// TM2-5 (decisions "Agent 01"): `--verify-store-pow` recomputes every
/// stored hash and refuses a store with one that differs, naming the block;
/// the default sample checks 48 connected heights chosen from the start-up
/// seed plus the 16 highest connected blocks, and finds a forged block
/// among those 16 at every seed. `open` (trust) still starts on such a store, as every replay
/// did before the check.
#[test]
fn the_stored_pow_check_refuses_a_forged_hash() {
    let dir = tempfile::tempdir().unwrap();
    let path = zero_pow_store(dir.path(), 100);

    // Trust: the forged block is not noticed.
    let pow = Recheck::new(Some(50));
    let m = open_checked(&path, pow.clone(), [1; 32], StorePowCheck::Trust).unwrap();
    assert_eq!(m.height(), 100);
    assert!(pow.heights().is_empty(), "nothing recomputed");
    drop(m);

    // All: every block recomputed, the forged one refused.
    let pow = Recheck::new(Some(50));
    let e = open_checked(&path, pow.clone(), [1; 32], StorePowCheck::All)
        .err()
        .expect("refused");
    assert_eq!(pow.heights(), (1..=100).collect::<Vec<u64>>());
    let mismatch = e
        .get_ref()
        .and_then(|e| e.downcast_ref::<StorePowMismatch>())
        .expect("a StorePowMismatch");
    assert_eq!((mismatch.height, mismatch.index), (50, Some(49)));
    assert_eq!(
        (mismatch.checked, mismatch.mismatches, mismatch.total),
        (100, 1, 100)
    );
    assert!(e.to_string().contains("proof-of-work hash"), "{e}");

    // The default: 48 + 16 blocks, the 16 highest among them.
    let pow = Recheck::new(None);
    open_checked(&path, pow.clone(), [1; 32], StorePowCheck::NODE_DEFAULT).unwrap();
    let first = pow.heights();
    assert_eq!(first.len(), 64, "{first:?}");
    assert!((85..=100).all(|h| first.contains(&h)), "{first:?}");
    let pow = Recheck::new(None);
    open_checked(&path, pow.clone(), [2; 32], StorePowCheck::NODE_DEFAULT).unwrap();
    assert_ne!(
        pow.heights(),
        first,
        "another start-up seed, another sample"
    );

    // A forged block in the tip region is found by the default.
    let pow = Recheck::new(Some(99));
    let e = open_checked(&path, pow, [1; 32], StorePowCheck::NODE_DEFAULT)
        .err()
        .expect("refused");
    assert!(e.get_ref().unwrap().is::<StorePowMismatch>());

    // Older blocks: found when sampled. Across start-up seeds the sample
    // reaches every height; with 48 of 84 drawn, a seed that misses height
    // 10 and one that hits it both exist among the first 64 seeds.
    let (mut hit, mut miss) = (false, false);
    for s in 0..64u8 {
        let pow = Recheck::new(Some(10));
        match open_checked(&path, pow, [s; 32], StorePowCheck::NODE_DEFAULT) {
            Ok(_) => miss = true,
            Err(e) => {
                assert!(e.get_ref().unwrap().is::<StorePowMismatch>());
                hit = true;
            }
        }
        if hit && miss {
            break;
        }
    }
    assert!(hit && miss);

    // A store smaller than the sample is checked in full.
    let small = tempfile::tempdir().unwrap();
    let path = zero_pow_store(small.path(), 20);
    let pow = Recheck::new(None);
    open_checked(&path, pow.clone(), [1; 32], StorePowCheck::NODE_DEFAULT).unwrap();
    assert_eq!(pow.heights(), (1..=20).collect::<Vec<u64>>());
}

// ------------------------------------------------ RT-NODEOPS (red team of TM2-5)

/// A cheap PoW function that depends on the RandomX key: FNV-1a of
/// `seed ‖ header`, spread over 32 bytes. A store written with it holds
/// stored hashes that the start-up check reproduces only if it derives the
/// same key as the original validation did (any hash passes regtest
/// difficulty 1, so validation alone would not notice a wrong key).
#[derive(Default)]
struct SeedPow {
    seen: std::sync::Mutex<Vec<(u64, Hash)>>,
}

impl PowFunction for SeedPow {
    fn pow_hash(&self, seed: &Hash, header: &blacksilk_consensus::PowBlob) -> Hash {
        let height = blob_height(header);
        self.seen.lock().unwrap().push((height, *seed));
        let mut out = [0u8; 32];
        for (k, chunk) in out.chunks_mut(8).enumerate() {
            let mut h: u64 = 0xcbf2_9ce4_8422_2325 ^ k as u64;
            for b in seed.iter().chain(header) {
                h ^= u64::from(*b);
                h = h.wrapping_mul(0x0100_0000_01b3);
            }
            chunk.copy_from_slice(&h.to_le_bytes());
        }
        out
    }
}

fn open_seed_pow(
    p: &ChainParams,
    store: Box<dyn BlockStore>,
    pow: Arc<SeedPow>,
    check: StorePowCheck,
) -> std::io::Result<ChainManager> {
    ChainManager::open_checked(p.clone(), TxRules::for_chain(p), pow, store, [3; 32], check)
}

/// RT-NODEOPS (false refusal): a healthy store crossing the network's key
/// switch (epoch 2048, lag 64: the key changes at 2113) on two branches,
/// with a reorged-out branch, a heavier branch whose blocks above the
/// switch use their own key, and a stored block whose body is invalid,
/// passes `--verify-store-pow` (every stored hash recomputed under the key
/// the check derives) and the default sample.
#[test]
fn rt_the_store_check_passes_a_healthy_store_across_the_network_key_switch() {
    let mut p = params();
    p.seed_epoch = 2048;
    p.seed_lag = 64;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    let mut miner = Miner::new(4242);
    let (tip, main_2048, side_2048) = {
        let pow = Arc::new(SeedPow::default());
        let mut m = open_seed_pow(
            &p,
            Box::new(FileStore::open(&path).unwrap()),
            pow,
            StorePowCheck::Trust,
        )
        .unwrap();
        let mut ids = vec![p.genesis_id()];
        for _ in 0..2130 {
            let b = miner.mine_tip(&mut m);
            ids.push(b.id(p.network_id));
        }
        assert_eq!(m.height(), 2130);
        // A stored block with an invalid body (an inflated coinbase) on a
        // side fork: stored after its header was validated, refused on
        // its body (deterministically again at every replay).
        let t = m.template_on_with(&ids[2120], &known_body).unwrap();
        let mut bad = miner.build(&t, vec![], Some(t.reward * 1000), 9);
        bad.header.timestamp = t.min_timestamp.max(bad.header.timestamp);
        // On a side branch its body is stored and validated only if the
        // branch would win; either way the record is in the store.
        let _ = m.submit_block(bad.clone(), bad.header.timestamp);
        // A heavier branch from 2040, before the seed block 2048: above
        // 2112 it uses its own block 2048 as the key; the main blocks
        // 2041..2130 become a reorged-out branch.
        let mut parent = ids[2040];
        let mut side_ids = HashMap::new();
        for _ in 0..100 {
            let t = m.template_on_with(&parent, &known_body).unwrap();
            let b = miner.build(&t, vec![], None, 2);
            let now = b.header.timestamp;
            m.submit_block(b.clone(), now).expect("side block");
            parent = b.id(p.network_id);
            side_ids.insert(b.header.height, parent);
        }
        assert_eq!(m.height(), 2140, "the heavier branch won");
        assert!(m.deepest_reorg() >= 90);
        (m.tip_id(), ids[2048], side_ids[&2048])
    };
    assert_ne!(main_2048, side_2048);

    // Every stored hash recomputed: no false refusal.
    let pow = Arc::new(SeedPow::default());
    let m = open_seed_pow(
        &p,
        Box::new(FileStore::open(&path).unwrap()),
        pow.clone(),
        StorePowCheck::All,
    )
    .expect("a healthy store passes --verify-store-pow");
    assert_eq!(m.tip_id(), tip);
    let seen = pow.seen.lock().unwrap().clone();
    // 2130 main + 1 invalid-body + 100 side blocks, each recomputed once.
    assert_eq!(seen.len(), 2231, "every stored block recomputed");
    let keys: std::collections::BTreeSet<Hash> = seen
        .iter()
        .filter(|(h, _)| *h > 2112)
        .map(|(_, s)| *s)
        .collect();
    assert!(
        keys.contains(&main_2048) && keys.contains(&side_2048),
        "both keys used"
    );
    assert!(seen
        .iter()
        .filter(|(h, _)| *h <= 2112)
        .all(|(_, s)| *s == p.genesis_id()));
    drop(m);

    // The default sample over many start-up seeds.
    for s in 0..8u8 {
        let pow = Arc::new(SeedPow::default());
        let m = ChainManager::open_checked(
            p.clone(),
            TxRules::for_chain(&p),
            pow,
            Box::new(FileStore::open(&path).unwrap()),
            [s; 32],
            StorePowCheck::NODE_DEFAULT,
        )
        .expect("a healthy store passes the sample");
        assert_eq!(m.tip_id(), tip);
    }
}

/// RT-NODEOPS regression (was `rt_a_forged_tip_stored_first_escapes_the_tip_region`,
/// accepted at 18 of 20 seeds when the tip region was the 16 most recently
/// STORED records): a planted store that puts the forged connected tip first
/// in the file. The tip region is now the 16 highest CONNECTED blocks, so the
/// forged tip is refused at every start-up seed, and so is a store whose
/// later duplicate record carries the right hash for a forged first one.
#[test]
fn rt_a_forged_tip_stored_first_is_refused_at_every_seed() {
    let mut m = open(Box::<MemoryStore>::default(), Arc::default());
    let mut miner = Miner::new(99);
    let blocks: Vec<Block> = (0..1000).map(|_| miner.mine_tip(&mut m)).collect();
    drop(m);
    // Planted order: the 16 highest blocks first, then 1..=984.
    let planted = || {
        let mut s = MemoryStore::default();
        for b in blocks[984..].iter().chain(&blocks[..984]) {
            s.append(&[0; 32], &b.encode()).unwrap();
        }
        Box::new(s)
    };
    let p = params();
    for s in 0..20u8 {
        // The forged block is the tip, height 1000.
        let pow = Recheck::new(Some(1000));
        let e = ChainManager::open_checked(
            p.clone(),
            TxRules::for_chain(&p),
            pow,
            planted(),
            [s; 32],
            StorePowCheck::NODE_DEFAULT,
        )
        .err()
        .unwrap_or_else(|| panic!("seed {s}: the forged tip was accepted"));
        let m = e
            .get_ref()
            .unwrap()
            .downcast_ref::<StorePowMismatch>()
            .unwrap();
        assert_eq!(m.height, 1000);
    }

    // A forged first record of a block, then a copy with another hash: the
    // copy is never used by validation, and the two disagree.
    let mut st = MemoryStore::default();
    for b in &blocks[..10] {
        st.append(&[0; 32], &b.encode()).unwrap();
    }
    st.append(&[1; 32], &blocks[9].encode()).unwrap();
    let e = ChainManager::open_checked(
        p.clone(),
        TxRules::for_chain(&p),
        Recheck::new(None),
        Box::new(st),
        [0; 32],
        StorePowCheck::NODE_DEFAULT,
    )
    .err()
    .expect("conflicting stored hashes are refused");
    let m = e
        .get_ref()
        .unwrap()
        .downcast_ref::<StorePowMismatch>()
        .unwrap();
    assert_eq!((m.height, m.index), (10, Some(10)));
}

/// RT-NODEOPS (false refusal, real RandomX): a store holding a reorged-out
/// branch and a heavier branch across two key switches (short epochs) is
/// accepted by `--verify-store-pow`, every hash recomputed with RandomX
/// under the key the check derives.
#[test]
fn rt_the_store_check_passes_real_randomx_across_switches_and_a_reorg() {
    let p = short_epoch_params();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    let mut miner = Miner::new(37);
    let tip = {
        let mut m = open_real(&p, Box::new(FileStore::open(&path).unwrap()));
        let main = mine_real(&mut m, &mut miner, p.genesis_id(), 40, 1);
        let fork = main[9].id(p.network_id);
        mine_real(&mut m, &mut miner, fork, 32, 2);
        assert_eq!(m.height(), 42, "the heavier branch won");
        m.tip_id()
    };
    let started = std::time::Instant::now();
    let m = ChainManager::open_checked(
        p.clone(),
        TxRules::for_chain(&p),
        Arc::new(blacksilk_consensus::RandomXPow::new()),
        Box::new(FileStore::open(&path).unwrap()),
        [5; 32],
        StorePowCheck::All,
    )
    .expect("a healthy store passes --verify-store-pow");
    println!(
        "72 stored hashes over 5 keys recomputed in {:.1?}",
        started.elapsed()
    );
    assert_eq!(m.tip_id(), tip);
}
