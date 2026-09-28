//! The real chain manager, block state and mempool against the reference
//! model of `tests/model` (dossier 02 W-1; decisions, Agent 02: P0).
//!
//! - `every_delivery_order_of_small_trees_matches_the_model`: explicit-state
//!   search. Every order of body arrival (and headers-first) for small fixed
//!   trees with invalid bodies.
//! - `random_trees_and_deliveries_match_the_model`: proptest over random
//!   trees of up to 24 coinbase-only blocks, with over-claimed coinbases as
//!   invalid bodies, headers-first and orphan deliveries, bounded submission
//!   with random budgets (drains left pending across later arrivals), and a
//!   restart at the end.
//! - `random_reorganizations_with_transactions_match_the_model`: the same
//!   with real transfers in blocks and in the pool (double spends, blocks
//!   invalid by rule C2), checking the pool after every operation.
//! - `random_pool_operations_match_the_model`: the mempool alone with
//!   explicit heights: admission, conflicts, blocks, expiry, the
//!   recently-expired guard on the local path, readmission.
//!
//! After every operation the harness compares: the verdict, the connected
//! chain, header validity, kept bodies, `missing_bodies`, the deepest
//! reorganization, the pool, INV-1 in its declarative form (the tip has the
//! most work among blocks whose whole branch has valid bodies), INV-3 (the
//! state equals a fresh `MemoryChain` fed the connected bodies in order) and,
//! while a bounded drain is paused, INV-5 (never a lighter tip). A failure
//! prints the minimized input and the tree it describes.
//!
//! Runs are deterministic (fixed seeds). `BLACKSILK_MODEL_CASES` scales the
//! number of random cases (the defaults are sized for CI) and
//! `BLACKSILK_MODEL_SEED` shifts the seeds, for longer exploratory runs.

mod model;

use blacksilk_chain::block::Block;
use blacksilk_chain::emission::block_reward;
use blacksilk_chain::manager::{ChainManager, SubmitError};
use blacksilk_chain::mempool::{
    Mempool, MempoolError, Origin, MEMPOOL_EXPIRY_BLOCKS, RECENTLY_EXPIRED_BLOCKS,
};
use blacksilk_chain::store::{BlockStore, Marker, MemoryStore, Record, StoreIdentity};
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
use blacksilk_tx::scan::scan_block;
use blacksilk_tx::state::MemoryChain;
use blacksilk_tx::types::Transaction;
use blacksilk_tx::validate::ChainView;
use model::{Model, PoolModel, Spec, TxVerdict, Verdict, ROOT};
use proptest::prelude::*;
use proptest::test_runner::{Config, RngSeed, TestCaseError, TestRunner};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::{BTreeSet, HashSet};
use std::io;
use std::sync::{Arc, Mutex, OnceLock};

// ---------------------------------------------------------------- set-up

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

/// A block store the test can reopen: every manager opened on a clone
/// shares the records.
#[derive(Clone, Default)]
struct SharedStore(Arc<Mutex<MemoryStore>>);

impl BlockStore for SharedStore {
    fn append(&mut self, pow_hash: &Hash, block: &[u8]) -> io::Result<()> {
        self.0.lock().unwrap().append(pow_hash, block)
    }
    fn append_marker(&mut self, marker: &Marker) -> io::Result<()> {
        self.0.lock().unwrap().append_marker(marker)
    }
    fn load(&mut self) -> io::Result<Vec<Record>> {
        self.0.lock().unwrap().load()
    }
    fn bind(&mut self, identity: &StoreIdentity) -> io::Result<()> {
        self.0.lock().unwrap().bind(identity)
    }
}

fn open(store: SharedStore) -> ChainManager {
    let p = params();
    let rules = TxRules::for_chain(&p);
    ChainManager::open(p, rules, Arc::new(ZeroPow), Box::new(store), [7; 32]).unwrap()
}

fn miner_keys() -> WalletKeys {
    WalletKeys::generate(&mut ChaCha20Rng::seed_from_u64(0x3de1)).0
}

/// A block on `parent` (a known header of `src`) with `txs`; its coinbase
/// over-claims by one unit if `bad`. `nonce` tells siblings apart.
fn build_block(
    src: &ChainManager,
    parent: &Hash,
    txs: Vec<Transaction>,
    bad: bool,
    keys: &WalletKeys,
    nonce: u64,
) -> Block {
    let t = src.template_on(parent).expect("known parent");
    let mut rng = ChaCha20Rng::seed_from_u64(nonce ^ 0xb10c);
    let fees: u64 = txs.iter().map(Transaction::fee).sum();
    let cb = build_coinbase(
        t.height,
        &[Payment {
            address: keys.address(SubaddressIndex::PRIMARY),
            amount: t.reward + fees + u64::from(bad),
        }],
        &keys.hedge_secret(),
        &mut rng,
    )
    .unwrap();
    let mut all = vec![Transaction::Coinbase(cb)];
    all.extend(txs);
    let ids: Vec<Hash> = all.iter().map(Transaction::hash).collect();
    let header = BlockHeader {
        version: t.version,
        height: t.height,
        prev_id: t.prev_id,
        timestamp: t
            .min_timestamp
            .max(params().genesis.timestamp + 120 * t.height),
        difficulty: t.difficulty,
        tx_root: tx_root(&ids),
        nonce,
    };
    assert_eq!(header.version, HEADER_VERSION);
    Block { header, txs: all }
}

/// A trunk of coinbase-only blocks and transfers spending its first
/// coinbases: `TX_KEYS` key images, two transactions each (a double spend
/// pair), valid anywhere above the trunk (rings use trunk outputs only).
struct Fixture {
    trunk: Vec<Block>,
    txs: Vec<Transaction>,
    key_of: Vec<usize>,
}

const TRUNK: u64 = 90;
const TX_KEYS: usize = 4;

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let keys = miner_keys();
        let mut m = open(SharedStore::default());
        let mut trunk = Vec::new();
        for h in 1..=TRUNK {
            let b = build_block(&m, &m.tip_id(), vec![], false, &keys, 0x7000 + h);
            m.submit_block(b.clone(), NOW).unwrap();
            trunk.push(b);
        }
        let mut rng = ChaCha20Rng::seed_from_u64(0x7a);
        let mut txs = Vec::new();
        let mut key_of = Vec::new();
        for k in 0..TX_KEYS {
            for variant in 0..2u64 {
                txs.push(transfer(&m, &keys, k as u64 + 1, 1_000 + variant, &mut rng));
                key_of.push(k);
            }
        }
        Fixture { trunk, txs, key_of }
    })
}

/// A 1-input transfer of the coinbase of block `height` of `m` paying
/// `amount` to a fresh address.
fn transfer(
    m: &ChainManager,
    keys: &WalletKeys,
    height: u64,
    amount: u64,
    rng: &mut ChaCha20Rng,
) -> Transaction {
    let next = m.height() + 1;
    let table = SubaddressTable::new(keys.view_keys(), 1, 5);
    let b = m.block_at(height).unwrap();
    let first = m.state().first_output_at(height).unwrap();
    let owned = scan_block(keys.view_keys(), &table, &b.txs, height, first)
        .owned
        .remove(0);
    let state = m.state();
    let ring = select_ring(
        rng,
        &state.cumulative_outputs(),
        next,
        120,
        owned.global_index,
        |i| {
            state.output(i).is_some_and(|r| {
                let age = if r.coinbase {
                    COINBASE_MATURITY
                } else {
                    SPENDABLE_AGE
                };
                next >= r.height + age
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
    let (to, _) = WalletKeys::generate(rng);
    Transaction::from(
        build_transfer(
            keys,
            vec![InputPlan {
                real: SpendableOutput::from(&owned),
                decoys,
            }],
            &[Payment {
                address: to.address(SubaddressIndex::PRIMARY),
                amount,
            }],
            &keys.address(SubaddressIndex::PRIMARY),
            standard_fee(1, 2, m.rules()),
            m.rules(),
            rng,
        )
        .unwrap(),
    )
}

fn cases(default: u32) -> u32 {
    std::env::var("BLACKSILK_MODEL_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

/// A deterministic runner; `BLACKSILK_MODEL_SEED` shifts every property's
/// seed (for longer exploratory runs).
fn runner(cases: u32, seed: u64) -> TestRunner {
    let shift: u64 = std::env::var("BLACKSILK_MODEL_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    TestRunner::new(Config {
        cases,
        rng_seed: RngSeed::Fixed(seed ^ shift.wrapping_mul(0x9e37_79b9_7f4a_7c15)),
        failure_persistence: None,
        max_shrink_iters: 2_000,
        ..Config::default()
    })
}

/// Runs a property; a failure panics with the minimized input.
fn check<S: Strategy>(
    name: &str,
    mut runner: TestRunner,
    strategy: &S,
    test: impl Fn(S::Value) -> Result<(), TestCaseError>,
) where
    S::Value: std::fmt::Debug,
{
    if let Err(e) = runner.run(strategy, test) {
        panic!("{name}: the real code diverges from the model.\n{e}");
    }
}

// ---------------------------------------------------------------- harness

/// One operation of a scenario.
#[derive(Clone, Debug)]
enum Op {
    /// The header batch of the block's whole branch (known ones skipped).
    Headers(usize),
    /// The body. `budget`: bounded submission with at most this many
    /// validations per step; `pause`: leave the drain pending across the
    /// next operations (bounded only).
    Body {
        b: usize,
        budget: Option<usize>,
        pause: bool,
    },
    /// A transaction for the pool (from a peer).
    Tx(usize),
}

/// The real side: a manager over a store, the tree's blocks and ids.
struct Real {
    m: ChainManager,
    store: SharedStore,
    blocks: Vec<Option<Block>>,
    ids: Vec<Hash>,
    /// Work of [`ROOT`] (the model counts work above it).
    root_work: u128,
    root_height: u64,
    /// Tip work when the last drain began (INV-5).
    floor: u128,
    txs: Vec<Transaction>,
}

impl Real {
    /// A manager with the trunk (`trunk` blocks of the fixture), and the
    /// tree `shape` built on its tip. Fills `spec.difficulty`.
    fn new(spec: &mut Spec, trunk: usize, txs: Vec<Transaction>) -> Self {
        let f = fixture();
        let keys = miner_keys();
        let store = SharedStore::default();
        let mut m = open(store.clone());
        let mut src = open(SharedStore::default());
        for b in &f.trunk[..trunk] {
            m.submit_block(b.clone(), NOW).unwrap();
            src.submit_block(b.clone(), NOW).unwrap();
        }
        let root = m.tip_id();
        let mut ids = vec![root];
        let mut blocks = vec![None];
        spec.difficulty = vec![0];
        for b in 1..spec.len() {
            let body: Vec<Transaction> = spec.txs[b].iter().map(|&t| txs[t].clone()).collect();
            let block = build_block(
                &src,
                &ids[spec.parent[b]],
                body,
                !spec.claim_ok[b],
                &keys,
                b as u64,
            );
            src.accept_headers(&[block.header], NOW).unwrap();
            spec.difficulty.push(u128::from(block.header.difficulty));
            ids.push(block.id(params().network_id));
            blocks.push(Some(block));
        }
        let root_work = m.headers().work(&root).unwrap();
        Self {
            root_height: m.height(),
            m,
            store,
            blocks,
            ids,
            root_work,
            floor: root_work,
            txs,
        }
    }

    /// A new manager (at genesis, on a new store) for the same tree.
    fn replica(&self) -> Self {
        assert_eq!(self.root_height, 0, "replicas start from genesis");
        let store = SharedStore::default();
        Self {
            m: open(store.clone()),
            store,
            blocks: self.blocks.clone(),
            ids: self.ids.clone(),
            root_work: self.root_work,
            root_height: 0,
            floor: self.root_work,
            txs: self.txs.clone(),
        }
    }

    fn block(&self, b: usize) -> Block {
        self.blocks[b].clone().expect("a tree block")
    }

    fn tip_work(&self) -> u128 {
        self.m.headers().work(&self.m.tip_id()).unwrap()
    }

    /// Finishes a paused drain, checking INV-5 at every pause.
    fn finish_drain(&mut self, budget: usize) -> Result<(), TestCaseError> {
        while self.m.sync_pending() {
            prop_assert!(
                self.tip_work() >= self.floor,
                "INV-5: a paused drain rests on a lighter tip"
            );
            self.m.sync_step(budget);
        }
        self.floor = self.tip_work();
        Ok(())
    }

    fn index_of(&self, id: &Hash) -> Option<usize> {
        self.ids.iter().position(|x| x == id)
    }
}

fn verdict_of(r: Result<blacksilk_chain::Submitted, SubmitError>) -> Result<Verdict, String> {
    match r {
        Ok(s) if !s.body_kept => Err("body not kept (low-work policy)".into()),
        Ok(s) if s.on_best_chain => Ok(Verdict::Connected),
        Ok(_) => Ok(Verdict::Stored),
        Err(SubmitError::Duplicate) => Ok(Verdict::Duplicate),
        Err(SubmitError::Header(HeaderError::UnknownParent)) => Ok(Verdict::UnknownParent),
        Err(SubmitError::Header(HeaderError::InvalidParent)) => Ok(Verdict::InvalidParent),
        Err(SubmitError::Body(_)) => Ok(Verdict::BodyInvalid),
        Err(e) => Err(format!("unexpected error {e:?}")),
    }
}

fn tx_verdict_of(r: Result<Hash, MempoolError>) -> TxVerdict {
    match r {
        Ok(_) => TxVerdict::Added,
        Err(MempoolError::AlreadyKnown) => TxVerdict::AlreadyKnown,
        Err(MempoolError::Conflict) => TxVerdict::Conflict,
        Err(MempoolError::Invalid(_)) => TxVerdict::Invalid,
        Err(MempoolError::Expired) => TxVerdict::Expired,
        Err(e) => panic!("unexpected mempool error {e:?}"),
    }
}

/// Applies `op` to both sides and compares the verdicts (unless a paused
/// drain makes the real verdict provisional).
fn step(real: &mut Real, model: &mut Model, op: &Op) -> Result<(), TestCaseError> {
    match *op {
        Op::Headers(b) => {
            real.finish_drain(usize::MAX)?;
            let hs: Vec<BlockHeader> = model
                .spec
                .path(b)
                .into_iter()
                .map(|x| real.block(x).header)
                .collect();
            let got = real.m.accept_headers(&hs, NOW);
            let want = model.headers(b);
            match (got, want) {
                (Ok(g), Ok(w)) => prop_assert_eq!(g, w, "headers of {}", b),
                (Err((gi, ge)), Err(wi)) => {
                    prop_assert_eq!(gi, wi, "headers of {}: failing index", b);
                    prop_assert_eq!(ge, HeaderError::InvalidParent, "headers of {}", b);
                }
                (g, w) => prop_assert!(false, "headers of {}: real {:?}, model {:?}", b, g, w),
            }
        }
        Op::Body { b, budget, pause } => {
            let was_pending = real.m.sync_pending();
            let block = real.block(b);
            let want = model.body(b);
            let got = match budget {
                None => verdict_of(real.m.submit_block(block, NOW)),
                Some(n) => {
                    let first = real.m.submit_block_bounded(block, NOW, n);
                    match first {
                        Ok(s) if s.body_kept => {
                            if !pause {
                                real.finish_drain(n)?;
                            } else if real.m.sync_pending() {
                                prop_assert!(real.tip_work() >= real.floor, "INV-5");
                            }
                            verdict_of(real.m.verdict(s.id, s.height))
                        }
                        other => verdict_of(other),
                    }
                }
            };
            let got = got.map_err(TestCaseError::fail)?;
            if !was_pending && !real.m.sync_pending() {
                prop_assert_eq!(got, want, "body of {}", b);
            } else if want == Verdict::InvalidParent && real.m.header(&real.ids[b]).is_some() {
                // The model processes every operation to the end; the real
                // node checked this block's header while the drain that
                // finds its ancestor invalid was still paused, so the header
                // entered the tree (and was then marked invalid). Only the
                // verdict on a later child differs (InvalidParent instead of
                // UnknownParent); the chain is the same (informational
                // W2-02-I1, like dossier 02 F-7).
                model.header[b] = true;
            }
        }
        Op::Tx(t) => {
            real.finish_drain(usize::MAX)?;
            let got = tx_verdict_of(real.m.submit_tx(real.txs[t].clone()));
            let want = model.submit_tx(t);
            prop_assert_eq!(got, want, "transaction {}", t);
        }
    }
    if !real.m.sync_pending() {
        real.floor = real.tip_work();
    }
    Ok(())
}

/// Everything the connected chain and the pool determine, against the
/// model. Only at rest (no paused drain).
fn compare(real: &Real, model: &Model, fresh_state: bool) -> Result<(), TestCaseError> {
    let m = &real.m;
    prop_assert!(!m.sync_pending());
    // The connected chain.
    let tip = model.tip();
    prop_assert_eq!(
        real.index_of(&m.tip_id()),
        Some(tip),
        "tip (model {}, connected {:?})",
        tip,
        &model.connected
    );
    prop_assert_eq!(
        m.height(),
        real.root_height + model.connected.len() as u64 - 1
    );
    for (i, &x) in model.connected.iter().enumerate() {
        let h = real.root_height + i as u64;
        let id = m.block_at(h).map(|b| b.id(params().network_id));
        prop_assert_eq!(id, Some(real.ids[x]), "connected block at {}", h);
    }
    // INV-1, declaratively.
    prop_assert_eq!(
        real.tip_work() - real.root_work,
        model.best_valid_complete_work(),
        "INV-1: the tip does not have the most valid body-complete work"
    );
    prop_assert_eq!(
        m.deepest_reorg(),
        model.deepest_reorg,
        "deepest reorganization"
    );
    // Headers and bodies.
    for b in 1..model.spec.len() {
        let id = &real.ids[b];
        let known = m.header(id).is_some();
        if model.invalid[b] {
            prop_assert!(
                !known || m.headers().is_valid(id) == Some(false),
                "block {} should be invalid",
                b
            );
        } else {
            prop_assert_eq!(known, model.header[b], "header of {} known", b);
            if known {
                prop_assert_eq!(m.headers().is_valid(id), Some(true), "block {} valid", b);
            }
        }
        prop_assert_eq!(
            m.has_body(id),
            model.body[b].is_some(),
            "body of {} kept",
            b
        );
        prop_assert_eq!(
            m.invalid_reason(id).is_some(),
            model.failed[b],
            "block {} reported as the failing body",
            b
        );
    }
    // Downloads.
    let missing: BTreeSet<usize> = m
        .missing_bodies(usize::MAX)
        .iter()
        .map(|(_, id)| real.index_of(id).expect("a tree block"))
        .collect();
    prop_assert_eq!(missing, model.missing_bodies(), "missing_bodies");
    // The pool.
    let pool: BTreeSet<usize> = (0..real.txs.len())
        .filter(|&t| m.mempool().contains(&real.txs[t].hash()))
        .collect();
    prop_assert_eq!(m.mempool().len(), pool.len());
    prop_assert_eq!(
        pool,
        model.pool.iter().copied().collect::<BTreeSet<_>>(),
        "pool"
    );
    if fresh_state {
        state_equals_fresh_replay(real)?;
    }
    Ok(())
}

/// INV-3: the state equals the connected bodies applied in order to a
/// fresh `MemoryChain`, and `generated` equals the rewards along them.
fn state_equals_fresh_replay(real: &Real) -> Result<(), TestCaseError> {
    let m = &real.m;
    let mut fresh = MemoryChain::new();
    fresh.apply_block(&[]).unwrap();
    let mut generated = 0u64;
    for h in 1..=m.height() {
        let b = m.block_at(h).unwrap();
        fresh.apply_block(&b.txs).unwrap();
        generated += block_reward(h, generated);
    }
    let s = m.state();
    prop_assert_eq!(s.output_count(), fresh.output_count(), "INV-3: outputs");
    prop_assert_eq!(s.cumulative_outputs(), fresh.cumulative_outputs());
    prop_assert_eq!(s.px().root(), fresh.px().root());
    prop_assert_eq!(m.generated(), generated, "INV-3: generated");
    for tx in &real.txs {
        for k in tx.key_images() {
            prop_assert_eq!(
                s.is_key_image_spent(&k),
                fresh.is_key_image_spent(&k),
                "INV-3: key image"
            );
        }
    }
    Ok(())
}

/// INV-4: a manager reopened on the store has the live connected chain,
/// state and verdicts (the pool is not persisted).
fn restart_matches(real: &Real) -> Result<(), TestCaseError> {
    let live = &real.m;
    let again = open(real.store.clone());
    prop_assert_eq!(again.tip_id(), live.tip_id(), "INV-4: tip after a restart");
    prop_assert_eq!(again.height(), live.height());
    prop_assert_eq!(again.generated(), live.generated());
    prop_assert_eq!(again.state().output_count(), live.state().output_count());
    for h in 0..=live.height() {
        prop_assert_eq!(
            again.block_at(h).map(|b| b.id(params().network_id)),
            live.block_at(h).map(|b| b.id(params().network_id))
        );
    }
    for id in &real.ids {
        if again.header(id).is_some() {
            prop_assert_eq!(again.headers().is_valid(id), live.headers().is_valid(id));
        }
    }
    // The pool is empty after a restart (docs/blocks.md §7), also when the
    // replay itself reorganizes (finding W2-02-F1, fixed in `open`;
    // `a_restart_that_replays_a_failed_reorganization_starts_with_an_empty_pool`).
    // Checked here in its weaker form too: whatever the reopened pool holds
    // is valid at the tip, without conflicts.
    let mut keys = HashSet::new();
    for tx in real
        .txs
        .iter()
        .filter(|tx| again.mempool().contains(&tx.hash()))
    {
        for k in tx.key_images() {
            prop_assert!(
                !again.state().is_key_image_spent(&k),
                "a spent pooled input"
            );
            prop_assert!(keys.insert(*k.bytes()), "two pooled spends of one input");
        }
    }
    Ok(())
}

/// Runs a scenario: every operation on both sides, compared at rest.
fn run_scenario(
    spec: Spec,
    ops: &[Op],
    trunk: usize,
    txs: Vec<Transaction>,
    fresh_every_step: bool,
) -> Result<(), TestCaseError> {
    let mut spec = spec;
    let mut real = Real::new(&mut spec, trunk, txs);
    let mut model = Model::new(spec);
    for op in ops {
        step(&mut real, &mut model, op)?;
        if !real.m.sync_pending() {
            compare(&real, &model, fresh_every_step)?;
        }
    }
    real.finish_drain(usize::MAX)?;
    compare(&real, &model, true)?;
    restart_matches(&real)
}

// ---------------------------------------------------------------- shapes

/// A random tree: each block's parent (`None`: the previous block, so
/// chains grow long; `Some(r)`: any earlier block), whether its coinbase
/// over-claims, and its transactions.
#[derive(Clone, Debug)]
struct Shape(Vec<(Option<usize>, bool, Vec<usize>)>);

impl Shape {
    fn spec(&self, key_of: Vec<usize>) -> Spec {
        let mut s = Spec {
            parent: vec![ROOT],
            difficulty: vec![],
            claim_ok: vec![true],
            txs: vec![vec![]],
            key_of,
        };
        for (i, (p, bad, txs)) in self.0.iter().enumerate() {
            let b = i + 1;
            s.parent.push(match p {
                None => b - 1,
                Some(r) => r % b,
            });
            s.claim_ok.push(!bad);
            s.txs.push(txs.clone());
        }
        s
    }
}

fn shape(max_blocks: usize, n_txs: usize) -> impl Strategy<Value = Shape> {
    let tx = if n_txs == 0 {
        Just(vec![]).boxed()
    } else {
        prop_oneof![
            3 => Just(vec![]),
            2 => proptest::collection::vec(0..n_txs, 1..=2),
        ]
        .boxed()
    };
    proptest::collection::vec(
        (
            prop_oneof![3 => Just(None), 2 => (0usize..32).prop_map(Some)],
            proptest::bool::weighted(0.12),
            tx,
        ),
        1..=max_blocks,
    )
    .prop_map(Shape)
}

fn ops(max_ops: usize, n_txs: usize) -> impl Strategy<Value = Vec<(u8, usize, usize, bool)>> {
    // (kind, block or tx, budget, pause); mapped onto a shape in `to_ops`.
    let kinds = if n_txs == 0 { 10u8 } else { 12u8 };
    proptest::collection::vec(
        (
            0..kinds,
            0usize..32,
            0usize..5,
            proptest::bool::weighted(0.3),
        ),
        1..=max_ops,
    )
}

fn to_ops(raw: &[(u8, usize, usize, bool)], blocks: usize, n_txs: usize) -> Vec<Op> {
    raw.iter()
        .map(|&(k, x, budget, pause)| match k {
            0..=1 => Op::Headers(x % blocks + 1),
            10..=11 => Op::Tx(x % n_txs),
            _ => Op::Body {
                b: x % blocks + 1,
                // 0: whole submission; 1..=4: bounded with this budget.
                budget: (budget > 0).then_some(budget),
                pause: budget > 0 && pause,
            },
        })
        .collect()
}

/// A failing scenario in readable form: the tree (each block's parent,
/// coinbase, transactions with their key images) and the operations.
fn reproducer(spec: &Spec, ops: &[Op]) -> String {
    let mut out = String::from("reproducer (block 0 is the root):\n");
    for b in 1..spec.len() {
        let txs: Vec<(usize, usize)> = spec.txs[b].iter().map(|&t| (t, spec.key_of[t])).collect();
        let coinbase = if spec.claim_ok[b] {
            "valid coinbase"
        } else {
            "OVER-CLAIMING coinbase"
        };
        out += &format!(
            "  block {b}: parent {}, {coinbase}, txs (tx, key image) {txs:?}\n",
            spec.parent[b]
        );
    }
    out += &format!("  ops: {ops:?}");
    out
}

// ---------------------------------------------------------------- properties

/// Explicit-state search over small trees: every body arrival order, with
/// and without all headers first, against the model after every step.
#[test]
fn every_delivery_order_of_small_trees_matches_the_model() {
    // (parents, invalid bodies). Index 0 is genesis.
    let trees: &[(&[usize], &[usize])] = &[
        // Two branches; the longer one's tip is invalid, so the chain falls
        // back to a tie between the two survivors.
        (&[0, 1, 2, 0, 4, 5], &[6]),
        // An invalid first block under a long branch; two competitors.
        (&[0, 1, 2, 0, 4, 0], &[1]),
        // An invalid middle block of the heaviest branch, with siblings.
        (&[0, 1, 0, 3, 4, 4], &[4]),
        // Equal-work branches only: pure tie-breaking by completion order.
        (&[0, 1, 0, 3, 0, 5], &[]),
    ];
    let mut runs = 0;
    for &(parents, bad) in trees {
        let n = parents.len();
        let mut spec = Spec {
            parent: std::iter::once(ROOT)
                .chain(parents.iter().copied())
                .collect(),
            difficulty: vec![],
            claim_ok: (0..=n).map(|b| !bad.contains(&b)).collect(),
            txs: vec![vec![]; n + 1],
            key_of: vec![],
        };
        // Build the blocks once; each order replays them on a new manager.
        let template = Real::new(&mut spec, 0, vec![]);
        let mut order: Vec<usize> = (1..=n).collect();
        permutations(&mut order, 0, &mut |order| {
            for headers_first in [false, true] {
                let mut real = template.replica();
                let mut model = Model::new(spec.clone());
                let mut ops: Vec<Op> = Vec::new();
                if headers_first {
                    ops.extend((1..=n).map(Op::Headers));
                }
                ops.extend(order.iter().map(|&b| Op::Body {
                    b,
                    budget: None,
                    pause: false,
                }));
                let result = ops.iter().try_for_each(|op| {
                    step(&mut real, &mut model, op)?;
                    compare(&real, &model, true)
                });
                let result = result.and_then(|()| restart_matches(&real));
                if let Err(e) = result {
                    panic!(
                        "tree {parents:?} (invalid {bad:?}), headers first {headers_first}, \
                         bodies in order {order:?}: {e}"
                    );
                }
                runs += 1;
            }
        });
    }
    assert_eq!(runs, 2 * (720 * 4));
}

fn permutations(v: &mut Vec<usize>, k: usize, f: &mut impl FnMut(&[usize])) {
    if k == v.len() {
        f(v);
        return;
    }
    for i in k..v.len() {
        v.swap(k, i);
        permutations(v, k + 1, f);
        v.swap(k, i);
    }
}

/// Random trees of coinbase-only blocks and random deliveries (headers
/// first or not, orphans, duplicates, bounded drains paused across later
/// arrivals), then a restart.
#[test]
fn random_trees_and_deliveries_match_the_model() {
    let strategy = (shape(24, 0), ops(64, 0));
    check(
        "random_trees_and_deliveries_match_the_model",
        runner(cases(256), 0x02_0001),
        &strategy,
        |(shape, raw)| {
            let spec = shape.spec(vec![]);
            let ops = to_ops(&raw, shape.0.len(), 0);
            run_scenario(spec.clone(), &ops, 0, vec![], true)
                .map_err(|e| TestCaseError::fail(format!("{e}\n{}", reproducer(&spec, &ops))))
        },
    );
}

/// Random trees whose blocks carry real transfers (double-spend pairs, so
/// some blocks are invalid by C2 and some pooled transactions conflict), and
/// random transaction submissions: the pool after every reorganization.
#[test]
fn random_reorganizations_with_transactions_match_the_model() {
    let f = fixture();
    let n = f.txs.len();
    let strategy = (shape(12, n), ops(40, n));
    check(
        "random_reorganizations_with_transactions_match_the_model",
        runner(cases(24), 0x02_0002),
        &strategy,
        |(shape, raw)| {
            let spec = shape.spec(f.key_of.clone());
            let ops = to_ops(&raw, shape.0.len(), n);
            run_scenario(spec.clone(), &ops, TRUNK as usize, f.txs.clone(), false)
                .map_err(|e| TestCaseError::fail(format!("{e}\n{}", reproducer(&spec, &ops))))
        },
    );
}

/// Finding W2-02-F1 (minimized by `random_reorganizations_with_transactions_match_the_model`):
/// docs/blocks.md §7 says "the mempool is not persisted. After a restart it
/// is empty", but a replay that reorganizes pools the transactions of the
/// blocks it disconnects, as live processing does. Here the heavier branch
/// 1-2-3 fails at block 2 (a second spend of block 1's key image), the node
/// returns to 4-5, and block 1's transfer was pooled, live and again on every
/// restart. Decided: the code changes (`open` empties the pool after the
/// replay); this test failed before that fix and guards it.
#[test]
fn a_restart_that_replays_a_failed_reorganization_starts_with_an_empty_pool() {
    let f = fixture();
    let (t, key) = (4, f.key_of[4]);
    let mut spec = Spec {
        parent: vec![ROOT, 0, 1, 2, 0, 4],
        difficulty: vec![],
        claim_ok: vec![true; 6],
        txs: vec![vec![], vec![t], vec![t], vec![], vec![], vec![]],
        key_of: f.key_of.clone(),
    };
    let mut real = Real::new(&mut spec, TRUNK as usize, f.txs.clone());
    let mut model = Model::new(spec);
    for b in [4, 5, 1, 2, 3] {
        let op = Op::Body {
            b,
            budget: None,
            pause: false,
        };
        step(&mut real, &mut model, &op).unwrap();
    }
    assert!(model.failed[2] && model.connected == [ROOT, 4, 5]);
    assert_eq!(
        model.pool,
        [t],
        "live: block 1's transfer is back in the pool"
    );
    compare(&real, &model, true).unwrap();
    let again = open(real.store.clone());
    assert_eq!(again.tip_id(), real.m.tip_id());
    assert!(
        again.mempool().is_empty(),
        "after a restart the pool holds transaction {t} (key image {key})"
    );
}

/// One pool operation at an explicit next-block height.
#[derive(Clone, Debug)]
enum PoolOp {
    Add {
        t: usize,
        local: bool,
    },
    Readmit(usize),
    /// The next height grows by this much; expiry runs.
    Advance(u64),
    /// A reorganization lowers the next height by up to this much (never
    /// below the start); expiry runs at the lower height.
    Retreat(u64),
    /// A block with these transactions connects.
    Block(Vec<usize>),
}

fn pool_ops(n_txs: usize) -> impl Strategy<Value = Vec<PoolOp>> {
    proptest::collection::vec(
        prop_oneof![
            5 => (0..n_txs, any::<bool>()).prop_map(|(t, local)| PoolOp::Add { t, local }),
            1 => (0..n_txs).prop_map(PoolOp::Readmit),
            2 => (1u64..40).prop_map(PoolOp::Advance),
            1 => (MEMPOOL_EXPIRY_BLOCKS - 40..MEMPOOL_EXPIRY_BLOCKS + 40).prop_map(PoolOp::Advance),
            1 => (1u64..40).prop_map(PoolOp::Retreat),
            1 => proptest::collection::vec(0..n_txs, 0..=2).prop_map(PoolOp::Block),
        ],
        1..=40,
    )
}

/// The mempool alone: admission, conflicts, removal by a block, expiry at
/// exactly `MEMPOOL_EXPIRY_BLOCKS`, the recently-expired guard on the local
/// path only, readmission, and lower heights after a reorganization, against
/// [`PoolModel`]. One key image is
/// already spent on the chain.
#[test]
fn random_pool_operations_match_the_model() {
    let f = fixture();
    let keys = miner_keys();
    let mut m = open(SharedStore::default());
    for b in &f.trunk {
        m.submit_block(b.clone(), NOW).unwrap();
    }
    // Key image 3 is spent on the chain (its first transaction is mined).
    let spent_tx = 2 * (TX_KEYS - 1);
    let b = build_block(
        &m,
        &m.tip_id(),
        vec![f.txs[spent_tx].clone()],
        false,
        &keys,
        1,
    );
    m.submit_block(b, NOW).unwrap();
    let state = m.state();
    let rules = m.next_rules();
    let start = m.height() + 1;
    let n = f.txs.len();
    check(
        "random_pool_operations_match_the_model",
        runner(cases(128), 0x02_0003),
        &pool_ops(n),
        |ops| {
            let mut pool = Mempool::new();
            let mut model = PoolModel::new(
                f.key_of.clone(),
                HashSet::from([f.key_of[spent_tx]]),
                MEMPOOL_EXPIRY_BLOCKS,
                RECENTLY_EXPIRED_BLOCKS,
            );
            let mut height = start;
            for (i, op) in ops.iter().enumerate() {
                match op {
                    PoolOp::Add { t, local } => {
                        let origin = if *local { Origin::Local } else { Origin::Peer };
                        let got = tx_verdict_of(pool.add(
                            f.txs[*t].clone(),
                            state,
                            height,
                            &rules,
                            origin,
                        ));
                        prop_assert_eq!(got, model.add(*t, height, *local), "op {}: {:?}", i, op);
                    }
                    PoolOp::Readmit(t) => {
                        let got =
                            tx_verdict_of(pool.readmit(f.txs[*t].clone(), state, height, &rules));
                        prop_assert_eq!(got, model.readmit(*t, height), "op {}: {:?}", i, op);
                    }
                    PoolOp::Advance(k) => {
                        height += k;
                        prop_assert_eq!(pool.expire(height), model.expire(height), "op {}", i);
                    }
                    PoolOp::Retreat(k) => {
                        height = height.saturating_sub(*k).max(start);
                        prop_assert_eq!(pool.expire(height), model.expire(height), "op {}", i);
                    }
                    PoolOp::Block(txs) => {
                        let body: Vec<Transaction> =
                            txs.iter().map(|&t| f.txs[t].clone()).collect();
                        pool.remove_block(&body);
                        model.remove_block(txs);
                    }
                }
                for t in 0..n {
                    let id = f.txs[t].hash();
                    prop_assert_eq!(
                        pool.contains(&id),
                        model.pool.contains_key(&t),
                        "op {}: pooled {}",
                        i,
                        t
                    );
                    prop_assert_eq!(
                        pool.admitted_at(&id),
                        model.pool.get(&t).copied(),
                        "op {}: admitted {}",
                        i,
                        t
                    );
                    prop_assert_eq!(
                        pool.conflicts(&f.txs[t]),
                        model.conflicts(t),
                        "op {}: conflicts {}",
                        i,
                        t
                    );
                    prop_assert_eq!(
                        pool.recently_expired(&id, height),
                        model.recently_expired(t, height),
                        "op {}: guard {}",
                        i,
                        t
                    );
                }
                prop_assert_eq!(pool.len(), model.pool.len());
            }
            Ok(())
        },
    );
}
