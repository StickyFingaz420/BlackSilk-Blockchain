//! Stateful property test of the mempool against a real chain (dossier 12
//! W6; decisions, Agent 12: P0, required for the ring-digest revalidation
//! and the cheap readmission).
//!
//! Proptest drives random sequences of operations on a real `ChainManager`
//! (regtest, zero proof of work) and a pool of real v1 transfers:
//! - `Submit`: a transfer of one of the miner's outputs, with a ring of
//!   random mature outputs or of the newest mature ones (so reorganizations
//!   of a few blocks change what it resolves to), sometimes a double spend of
//!   a pooled or mined output;
//! - `Mine`: blocks on the tip or on an ancestor up to 70 blocks back (a
//!   reorganization, which returns the transactions of the disconnected
//!   blocks), the first block on the tip carrying the pool's own template;
//! - `Expire`: the pool's expiry at a height up to `MEMPOOL_EXPIRY_BLOCKS`
//!   ahead;
//! - `Select`: templates with random weight budgets.
//!
//! The pool under test follows the chain the way `finish_sync` is to
//! (`Mempool::update_after_chain_change`): the transactions of each
//! disconnected block are captured (`Returned::capture`) while the block is
//! connected, connected blocks are removed (`remove_block`), then the pool
//! expires, revalidates (the ring-digest path after a reorganization) and
//! readmits.
//!
//! After every operation:
//! - **differential:** the pool equals what full validation
//!   (`validate_mempool_tx`, every CLSAG and range proof verified again)
//!   decides at the next height: every entry that was pooled and still
//!   validates, plus every returned transaction that validates and conflicts
//!   with nothing kept. So the cheap path keeps no invalid transaction and
//!   drops no valid one here;
//! - the cheap path verifies nothing (`Mempool::full_validations` unchanged
//!   by a chain update);
//! - no two pooled transactions share a conflict key; byte accounting and the
//!   class caps hold; the recently-expired set holds no more than what expired
//!   (bounded memory);
//! - every template respects the weight budget and holds only pooled,
//!   pairwise non-conflicting transactions, and a template mined on the tip
//!   is accepted by the manager (a valid block body at `tip + 1`);
//! - until the first `Expire`, the manager's own pool (the current
//!   `finish_sync`) holds the same transactions.
//!
//! Complements `reference_model.rs` (fork choice and key-image-level pool
//! rules against an abstract model, rings never changing) with real ring
//! changes and a full-validation oracle. Deterministic (fixed seed);
//! `BLACKSILK_MODEL_CASES` scales the number of cases.

use blacksilk_chain::block::Block;
use blacksilk_chain::manager::{ChainManager, Template};
use blacksilk_chain::mempool::{
    conflict_keys, ChainChange, Mempool, MempoolError, Origin, Returned, COINBASE_RESERVE,
    MEMPOOL_EXPIRY_BLOCKS, MEMPOOL_MAX_BYTES,
};
use blacksilk_chain::store::MemoryStore;
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, PowFunction, HEADER_VERSION};
use blacksilk_crypto::keys::{SubaddressIndex, SubaddressTable, WalletKeys};
use blacksilk_tx::builder::{
    build_coinbase, build_transfer, standard_fee, Decoy, InputPlan, Payment, SpendableOutput,
};
use blacksilk_tx::decoy::select_ring;
use blacksilk_tx::params::{TxRules, COINBASE_MATURITY, RING_SIZE, SPENDABLE_AGE};
use blacksilk_tx::scan::{scan_block, OwnedOutput};
use blacksilk_tx::types::Transaction;
use blacksilk_tx::validate::{validate_mempool_tx, ChainView};
use proptest::prelude::*;
use proptest::test_runner::{Config, RngSeed, TestCaseError, TestRunner};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};

// ---------------------------------------------------------------- set-up

struct ZeroPow;
impl PowFunction for ZeroPow {
    fn pow_hash(&self, _: &Hash, _: &blacksilk_consensus::PowBlob) -> Hash {
        [0; 32]
    }
}

const NOW: u64 = u64::MAX / 2;
/// Coinbase-only blocks every case starts from: the coinbases of the first
/// blocks are mature at its tip.
const TRUNK: u64 = 75;

fn params() -> ChainParams {
    ChainParams::regtest()
}

fn open() -> ChainManager {
    let p = params();
    ChainManager::open(
        p.clone(),
        TxRules::for_chain(&p),
        Arc::new(ZeroPow),
        Box::<MemoryStore>::default(),
        [7; 32],
    )
    .unwrap()
}

fn wallet(seed: u64) -> WalletKeys {
    WalletKeys::generate(&mut ChaCha20Rng::seed_from_u64(seed)).0
}

/// A block on template `t` paying `keys`, with `txs`.
fn build(t: &Template, txs: Vec<Transaction>, keys: &WalletKeys, nonce: u64) -> Block {
    let mut rng = ChaCha20Rng::seed_from_u64(nonce ^ 0x5eed);
    let fees: u64 = txs.iter().map(Transaction::fee).sum();
    let cb = build_coinbase(
        t.height,
        &[Payment {
            address: keys.address(SubaddressIndex::PRIMARY),
            amount: t.reward + fees,
        }],
        &keys.hedge_secret(),
        &mut rng,
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
    Block { header, txs: all }
}

fn trunk() -> &'static Vec<Block> {
    static T: OnceLock<Vec<Block>> = OnceLock::new();
    T.get_or_init(|| {
        let keys = wallet(0x5701);
        let mut m = open();
        (1..=TRUNK)
            .map(|h| {
                let t = m.template_on(&m.tip_id()).unwrap();
                let b = build(&t, vec![], &keys, 0x1000 + h);
                m.submit_block(b.clone(), NOW).unwrap();
                b
            })
            .collect()
    })
}

fn mature(next: u64, created: u64, coinbase: bool) -> bool {
    let age = if coinbase {
        COINBASE_MATURITY
    } else {
        SPENDABLE_AGE
    };
    next >= created + age
}

// ---------------------------------------------------------------- operations

#[derive(Clone, Debug)]
enum Op {
    /// A transfer of the miner's `pick`-th mature output (modulo their
    /// number, spent or not); `newest`: decoys are the newest mature outputs.
    Submit { pick: usize, newest: bool },
    /// `n` blocks on the ancestor `back` blocks below the tip (0: the tip,
    /// the first block carrying the pool's template).
    Mine { back: u64, extra: u64 },
    /// The pool expires at `next + MEMPOOL_EXPIRY_BLOCKS - k`.
    Expire { k: u64 },
    /// A template with weight budget `weight` (0: the block's).
    Select { weight: u64 },
}

fn to_op(raw: (u8, u16, bool)) -> Op {
    let (kind, x, flag) = raw;
    match kind % 10 {
        0..=3 => Op::Submit {
            pick: x as usize,
            newest: flag,
        },
        4..=7 => {
            // Mostly extensions and shallow reorganizations; sometimes one
            // past the coinbase maturity or the spendable age.
            let back = match x % 9 {
                0..=2 => 0,
                3 => 1,
                4 => 2,
                5 => 5,
                6 => 11 + u64::from(x % 5),
                7 => 25,
                _ => 61 + u64::from(x % 9),
            };
            Op::Mine {
                back,
                extra: u64::from(flag),
            }
        }
        8 => Op::Expire {
            k: u64::from(x) % 40,
        },
        _ => Op::Select {
            weight: if flag { 0 } else { u64::from(x) * 16 },
        },
    }
}

// ---------------------------------------------------------------- harness

struct Harness {
    m: ChainManager,
    pool: Mempool,
    miner: WalletKeys,
    rng: ChaCha20Rng,
    /// The captured transactions of every block while it was connected, by
    /// block id.
    captured: HashMap<Hash, Vec<Returned>>,
    /// Connected block ids by height, as of the last operation.
    chain: Vec<Hash>,
    /// Whether the manager's own pool is still comparable (no `Expire` yet:
    /// it applies to the pool under test only).
    comparable: bool,
    nonce: u64,
    stats: Stats,
}

#[derive(Default, Debug)]
struct Stats {
    pooled: usize,
    ring_changed: usize,
    readmitted: usize,
    reorgs: usize,
    expired: usize,
}

impl Harness {
    fn new(seed: u64) -> Self {
        let mut m = open();
        for b in trunk() {
            m.submit_block(b.clone(), NOW).unwrap();
        }
        let mut h = Self {
            m,
            pool: Mempool::new(),
            miner: wallet(0x5701),
            rng: ChaCha20Rng::seed_from_u64(seed),
            captured: HashMap::new(),
            chain: Vec::new(),
            comparable: true,
            nonce: seed.wrapping_mul(1_000),
            stats: Stats::default(),
        };
        h.chain = h.connected();
        h.capture();
        h
    }

    fn next(&self) -> u64 {
        self.m.height() + 1
    }

    fn rules(&self) -> TxRules {
        self.m.next_rules()
    }

    fn connected(&self) -> Vec<Hash> {
        (0..=self.m.height())
            .map(|h| self.m.block_at(h).unwrap().id(params().network_id))
            .collect()
    }

    /// Captures the transactions of connected blocks not captured yet.
    fn capture(&mut self) {
        for h in 1..=self.m.height() {
            let b = self.m.block_at(h).unwrap();
            let id = b.id(params().network_id);
            if self.captured.contains_key(&id) {
                continue;
            }
            let rules = self.m.rules_at(h);
            let returned = b
                .txs
                .into_iter()
                .skip(1)
                .map(|tx| Returned::capture(tx, self.m.state(), &rules))
                .collect();
            self.captured.insert(id, returned);
        }
    }

    /// The miner's outputs on the connected chain, mature at the next height.
    fn owned(&self) -> Vec<OwnedOutput> {
        let keys = &self.miner;
        let table = SubaddressTable::new(keys.view_keys(), 1, 5);
        let next = self.next();
        let mut out = Vec::new();
        for h in 1..=self.m.height() {
            let b = self.m.block_at(h).unwrap();
            let first = self.m.state().first_output_at(h).unwrap();
            out.extend(
                scan_block(keys.view_keys(), &table, &b.txs, h, first)
                    .owned
                    .into_iter()
                    .filter(|o| mature(next, o.height, o.coinbase)),
            );
        }
        out
    }

    /// A transfer of `real`, with random decoys or the newest mature ones.
    fn transfer(&mut self, real: &OwnedOutput, newest: bool) -> Transaction {
        let next = self.next();
        let state = self.m.state();
        let is_mature = |i: u64| {
            state
                .output(i)
                .is_some_and(|r| mature(next, r.height, r.coinbase))
        };
        let decoys: Vec<u64> = if newest {
            (0..state.output_count())
                .rev()
                .filter(|&i| i != real.global_index && is_mature(i))
                .take(RING_SIZE - 1)
                .collect()
        } else {
            select_ring(
                &mut self.rng,
                &state.cumulative_outputs(),
                next,
                120,
                real.global_index,
                is_mature,
            )
            .unwrap()
            .into_iter()
            .filter(|&i| i != real.global_index)
            .collect()
        };
        let plan = InputPlan {
            real: SpendableOutput::from(real),
            decoys: decoys
                .into_iter()
                .map(|i| Decoy {
                    global_index: i,
                    key: state.output(i).unwrap().key,
                })
                .collect(),
        };
        let (to, _) = WalletKeys::generate(&mut self.rng);
        let rules = self.rules();
        Transaction::from(
            build_transfer(
                &self.miner,
                vec![plan],
                &[Payment {
                    address: to.address(SubaddressIndex::PRIMARY),
                    amount: 1_000 + self.rng.next_u64() % 1_000,
                }],
                &self.miner.address(SubaddressIndex::PRIMARY),
                standard_fee(1, 2, &rules),
                &rules,
                &mut self.rng,
            )
            .unwrap(),
        )
    }

    fn step(&mut self, op: &Op) -> Result<(), TestCaseError> {
        match op {
            Op::Submit { pick, newest } => {
                let owned = self.owned();
                if owned.is_empty() {
                    return Ok(());
                }
                let real = owned[pick % owned.len()].clone();
                let tx = self.transfer(&real, *newest);
                let (next, rules) = (self.next(), self.rules());
                let expected = if self.pool.conflicts(&tx) {
                    Err(MempoolError::Conflict)
                } else {
                    match validate_mempool_tx(&tx, self.m.state(), next, &rules) {
                        Ok(()) => Ok(tx.hash()),
                        Err(e) => Err(MempoolError::Invalid(e)),
                    }
                };
                let got = self
                    .pool
                    .add(tx.clone(), self.m.state(), next, &rules, Origin::Peer);
                prop_assert_eq!(got, expected);
                if got.is_ok() {
                    self.stats.pooled += 1;
                }
                let manager = self.m.submit_tx(tx);
                if self.comparable {
                    prop_assert_eq!(manager, got, "the manager's pool admits alike");
                }
            }
            Op::Mine { back, extra } => {
                let back = (*back).min(self.m.height() - 1);
                let parent = self.chain[(self.m.height() - back) as usize];
                // One more block than disconnected (regtest difficulty 1
                // at 120 s: more blocks, more work), sometimes two.
                let n = back + 1 + extra;
                // Another miner's keys on a rival branch: its outputs differ
                // from the disconnected ones at the same indices.
                let keys = if back == 0 {
                    self.miner.clone()
                } else {
                    wallet(self.rng.next_u64())
                };
                let mut p = parent;
                for i in 0..n {
                    let t = self.m.template_on(&p).unwrap();
                    let txs = if back == 0 && i == 0 {
                        self.template(t.height, 0)?
                    } else {
                        Vec::new()
                    };
                    self.nonce += 1;
                    let b = build(&t, txs, &keys, self.nonce);
                    p = b.id(params().network_id);
                    let r = self.m.submit_block(b, NOW);
                    prop_assert!(r.is_ok(), "block refused: {:?}", r.err());
                }
                prop_assert_eq!(self.m.tip_id(), p, "the new branch is connected");
                self.follow()?;
            }
            Op::Expire { k } => {
                let at = self.next() + MEMPOOL_EXPIRY_BLOCKS - k;
                let before: Vec<Hash> = self.pool.iter().map(Transaction::hash).collect();
                let n = self.pool.expire(at);
                for id in &before {
                    let old = self.pool.admitted_at(id).is_none();
                    prop_assert_eq!(old, self.pool.recently_expired(id, at));
                }
                prop_assert_eq!(before.len() - self.pool.len(), n);
                self.stats.expired += n;
                self.comparable = false;
            }
            Op::Select { weight } => {
                self.template(self.next(), *weight)?;
            }
        }
        self.invariants()
    }

    /// The pool under test after the chain moved, as `finish_sync` is to
    /// do it, checked against full validation.
    fn follow(&mut self) -> Result<(), TestCaseError> {
        let new = self.connected();
        let fork = self
            .chain
            .iter()
            .zip(&new)
            .take_while(|(a, b)| a == b)
            .count();
        // Disconnected blocks, tip first, as the manager returns them.
        let returned: Vec<Returned> = self.chain[fork..]
            .iter()
            .rev()
            .flat_map(|id| self.captured[id].clone())
            .collect();
        let reorganized = fork < self.chain.len();
        for h in fork..new.len() {
            let b = self.m.block_at(h as u64).unwrap();
            self.pool.remove_block(&b.txs);
        }
        self.chain = new;
        self.capture();
        if reorganized {
            self.stats.reorgs += 1;
        }

        // The oracle: full validation at the next height.
        let (next, rules) = (self.next(), self.rules());
        let state = self.m.state();
        let valid = |tx: &Transaction| validate_mempool_tx(tx, state, next, &rules).is_ok();
        let mut expected: HashSet<Hash> = HashSet::new();
        let mut keys = HashSet::new();
        for tx in self.pool.iter() {
            if valid(tx) {
                expected.insert(tx.hash());
                keys.extend(conflict_keys(tx));
            }
        }
        let mut readmit = 0;
        for r in &returned {
            let tx = r.tx();
            let id = tx.hash();
            if expected.contains(&id) || conflict_keys(tx).iter().any(|k| keys.contains(k)) {
                continue;
            }
            if valid(tx) {
                expected.insert(id);
                keys.extend(conflict_keys(tx));
                readmit += 1;
            }
        }

        let verified = self.pool.full_validations();
        let report = self.pool.update_after_chain_change(
            ChainChange {
                returned,
                reorganized,
            },
            state,
            next,
            &rules,
        );
        prop_assert_eq!(
            self.pool.full_validations(),
            verified,
            "a chain update verifies no signature or proof"
        );
        let got: HashSet<Hash> = self.pool.iter().map(Transaction::hash).collect();
        prop_assert_eq!(&got, &expected, "the pool equals full validation");
        prop_assert_eq!(report.readmission.readmitted, readmit);
        self.stats.ring_changed +=
            report.revalidation.ring_changed + report.readmission.ring_changed;
        self.stats.readmitted += readmit;
        if self.comparable {
            let manager: HashSet<Hash> = self.m.mempool().iter().map(Transaction::hash).collect();
            prop_assert_eq!(&manager, &got, "the manager's pool agrees");
        }
        Ok(())
    }

    /// A template of the pool under test at `height` with weight budget
    /// `weight` (0: the block's), checked against the budgets.
    fn template(&self, height: u64, weight: u64) -> Result<Vec<Transaction>, TestCaseError> {
        let rules = self.rules();
        let budget = if weight == 0 {
            rules.max_block_weight - COINBASE_RESERVE
        } else {
            weight
        };
        let state = self.m.state();
        let sel = self
            .pool
            .select(height, budget, state.px_pool(), state.px().free_leaves());
        let total: u64 = sel.iter().map(Transaction::weight).sum();
        prop_assert!(total <= budget, "weight {} > {}", total, budget);
        let mut seen = HashSet::new();
        for tx in &sel {
            prop_assert!(self.pool.contains(&tx.hash()));
            for k in conflict_keys(tx) {
                prop_assert!(seen.insert(k), "the template holds a conflict");
            }
        }
        if weight == 0 {
            prop_assert_eq!(sel.len(), self.pool.len(), "a small pool fits one block");
        }
        Ok(sel)
    }

    fn invariants(&self) -> Result<(), TestCaseError> {
        let mut keys = HashSet::new();
        let mut bytes = 0;
        for tx in self.pool.iter() {
            for k in conflict_keys(tx) {
                prop_assert!(keys.insert(k), "two pooled transactions share {:?}", k);
            }
            bytes += tx.encode().len();
        }
        prop_assert_eq!(self.pool.bytes(), bytes);
        prop_assert!(bytes <= MEMPOOL_MAX_BYTES);
        prop_assert!(self.pool.recently_expired_count() <= self.stats.expired);
        Ok(())
    }
}

fn cases(default: u32) -> u32 {
    std::env::var("BLACKSILK_MODEL_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

/// Random sequences of submissions, extensions, reorganizations of every
/// depth up to 69 blocks, expiry and templates; the pool is checked against
/// full validation after every operation (module docs).
#[test]
fn random_chain_and_pool_operations_match_full_validation() {
    let mut runner = TestRunner::new(Config {
        cases: cases(16),
        rng_seed: RngSeed::Fixed(0x12_5747),
        failure_persistence: None,
        max_shrink_iters: 64,
        ..Config::default()
    });
    let ops = proptest::collection::vec((any::<u8>(), any::<u16>(), any::<bool>()), 8..20);
    let totals = std::cell::RefCell::new(Stats::default());
    let result = runner.run(&ops, |raw| {
        let seed = raw.iter().fold(0u64, |a, (k, x, f)| {
            a.wrapping_mul(31) ^ (u64::from(*k) << 17) ^ (u64::from(*x) << 1) ^ u64::from(*f)
        });
        let mut h = Harness::new(seed);
        // Something to spend and a transaction to return on the first
        // reorganization: a transfer mined on the tip.
        let script: Vec<Op> = [
            Op::Submit {
                pick: 0,
                newest: true,
            },
            Op::Mine { back: 0, extra: 0 },
        ]
        .into_iter()
        .chain(raw.iter().copied().map(to_op))
        .collect();
        for (i, op) in script.iter().enumerate() {
            h.step(op)
                .map_err(|e| TestCaseError::fail(format!("op {i} {op:?}: {e}")))?;
        }
        let mut t = totals.borrow_mut();
        t.pooled += h.stats.pooled;
        t.ring_changed += h.stats.ring_changed;
        t.readmitted += h.stats.readmitted;
        t.reorgs += h.stats.reorgs;
        t.expired += h.stats.expired;
        Ok(())
    });
    if let Err(e) = result {
        panic!("the pool diverges from full validation:\n{e}");
    }
    // The run exercised every path.
    let t = totals.into_inner();
    println!("{t:?}");
    assert!(t.pooled > 0 && t.reorgs > 0 && t.readmitted > 0, "{t:?}");
    assert!(t.ring_changed > 0, "no ring changed: {t:?}");
}
