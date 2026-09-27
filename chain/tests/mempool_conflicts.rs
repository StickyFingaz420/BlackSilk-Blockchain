//! F1: output one-time keys as mempool conflict keys (docs/blocks.md §7).
//!
//! Consensus rule C4 requires every output one-time key to be unique on the
//! chain and within a block. Output keys are chosen by the sender, so an
//! attacker with their own transaction builder can give a valid transaction
//! any output key, including one copied from another pending transaction.
//! Before the fix the pool checked C4 only against the chain: two valid
//! pooled transactions sharing an output key both entered every template, and
//! every block built from it was invalid.
//!
//! These tests forge fully valid transactions with chosen output keys (the
//! attacker's side, [`forge`]) and check that the pool never holds two
//! transactions sharing one, that templates stay valid, and that a
//! conflicting pair cannot stall block production, across reorganizations
//! and restarts. Pool-level cases on synthetic transactions (PX, randomized
//! invariants, a deliberately broken invariant) are unit tests in
//! chain/src/mempool.rs.

use blacksilk_chain::block::Block;
use blacksilk_chain::manager::{ChainManager, SubmitError, Template};
use blacksilk_chain::mempool::{conflict_keys, Mempool, MempoolError};
use blacksilk_chain::store::{BlockStore, FileStore, MemoryStore};
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, PowFunction, HEADER_VERSION};
use blacksilk_crypto::bulletproofs_plus;
use blacksilk_crypto::clsag::{self, RingMember, RING_SIZE};
use blacksilk_crypto::commitment::commit;
use blacksilk_crypto::keys::{SubaddressIndex, SubaddressTable, WalletKeys};
use blacksilk_crypto::{Point, RistrettoPoint, Scalar};
use blacksilk_tx::builder::{
    build_coinbase, build_transfer, standard_fee, Decoy, InputPlan, Payment, SpendableOutput,
};
use blacksilk_tx::decoy::select_ring;
use blacksilk_tx::params::{TxRules, COINBASE_MATURITY, SPENDABLE_AGE};
use blacksilk_tx::scan::{scan_block, OwnedOutput};
use blacksilk_tx::types::{Input, Output, Transaction, Transfer};
use blacksilk_tx::validate::{validate_mempool_tx, BlockError, ChainView, TxError};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections::HashSet;
use std::sync::Arc;

// ---------------------------------------------------------------- harness
// (as chain/tests/manager.rs)

/// Zero hash: meets any difficulty.
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

    fn build(&mut self, t: &Template, txs: Vec<Transaction>, nonce: u64) -> Block {
        let fees: u64 = txs.iter().map(Transaction::fee).sum();
        let cb = build_coinbase(
            t.height,
            &[Payment {
                address: self.keys.address(SubaddressIndex::PRIMARY),
                amount: t.reward + fees,
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

    /// Mines the node's own template on its tip; panics if the block is
    /// refused (a stalled chain).
    fn mine_tip(&mut self, m: &mut ChainManager) -> Block {
        let t = m.template();
        assert_template_is_consistent(m, &t);
        let b = self.build(&t, t.txs.clone(), 0);
        let now = b.header.timestamp;
        m.submit_block(b.clone(), now)
            .expect("a block built from the template connects");
        b
    }

    /// Mines a block holding exactly `txs` on `parent` (not from the pool).
    fn mine_on(
        &mut self,
        m: &mut ChainManager,
        parent: &Hash,
        txs: Vec<Transaction>,
        nonce: u64,
    ) -> Result<Block, SubmitError> {
        let t = m.template_on(parent).unwrap();
        let b = self.build(&t, txs, nonce);
        let now = b.header.timestamp;
        m.submit_block(b.clone(), now).map(|_| b)
    }
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

/// The `nth` mature, unspent output of `from`, with a 16-member ring.
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

/// An honest wallet transfer (the wallet builder chooses the output keys).
fn honest(
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

// ---------------------------------------------------------------- the attacker

fn random_scalar(rng: &mut ChaCha20Rng) -> Scalar {
    let mut wide = [0u8; 64];
    rng.fill_bytes(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn random_point(rng: &mut ChaCha20Rng) -> Point {
    Point::from_point(RistrettoPoint::mul_base(&random_scalar(rng)))
}

/// The attacker's builder: a fully valid one-input v1 transfer spending the
/// `nth` output of `keys`, with the **chosen** output one-time keys
/// `out_keys` (at least two, distinct). Built with the public crypto API as
/// `blacksilk_tx::builder::build_transfer_signing` does, but without deriving
/// the output keys: all the value minus the fee goes to the first output, the
/// others carry zero; ephemerals are random points and the encrypted fields
/// are arbitrary (neither is checked by consensus).
///
/// Asserts that the result passes full mempool validation on its own.
fn forge(
    m: &ChainManager,
    keys: &WalletKeys,
    nth: usize,
    out_keys: &[Point],
    fee: u64,
    rng: &mut ChaCha20Rng,
) -> Transaction {
    let plan = plan_nth(m, keys, nth, rng);
    let real = &plan.real;
    // Spend secret and key image.
    let p = keys.one_time_secret(real.subaddress, &real.output_key_offset);
    assert_eq!(
        Point::from_point(RistrettoPoint::mul_base(&p)),
        real.key.one_time_key
    );
    let key_image = clsag::key_image(&p, &real.key.one_time_key);

    // Outputs sorted strictly by one-time key (T6).
    let mut out_keys = out_keys.to_vec();
    out_keys.sort();
    out_keys.dedup();
    assert!(out_keys.len() >= 2, "two distinct output keys at least");
    let amounts: Vec<u64> = (0..out_keys.len())
        .map(|j| if j == 0 { real.amount - fee } else { 0 })
        .collect();
    let masks: Vec<Scalar> = out_keys.iter().map(|_| random_scalar(rng)).collect();
    let (range_proof, commitments) = bulletproofs_plus::prove(&amounts, &masks, rng).unwrap();
    // One input: the pseudo-output mask is the sum of the output masks.
    let pseudo_mask: Scalar = masks.iter().sum();
    let pseudo_out = Point::from_point(commit(real.amount, &pseudo_mask));

    // The ring, ordered by global index.
    let mut members = plan.decoys.clone();
    members.push(Decoy {
        global_index: real.global_index,
        key: real.key,
    });
    members.sort_by_key(|d| d.global_index);
    let pos = members
        .iter()
        .position(|d| d.global_index == real.global_index)
        .unwrap();
    let ring: [RingMember; RING_SIZE] = std::array::from_fn(|j| RingMember {
        one_time_key: members[j].key.one_time_key,
        commitment: members[j].key.commitment,
    });

    let mut tx = Transfer {
        inputs: vec![Input {
            key_image,
            ring: std::array::from_fn(|j| members[j].global_index),
        }],
        outputs: out_keys
            .iter()
            .zip(&commitments)
            .map(|(k, c)| Output {
                one_time_key: *k,
                ephemeral: random_point(rng),
                view_tag: rng.next_u32() as u8,
                commitment: *c,
                enc_amount: [0xAA; 8],
                enc_anchor: [0x55; 16],
            })
            .collect(),
        fee,
        pseudo_outs: vec![pseudo_out],
        range_proof,
        signatures: vec![],
    };
    let message = tx.signature_message(m.rules().domain());
    let z = real.mask - pseudo_mask;
    let (sig, ki) = clsag::sign(&message, &ring, &pseudo_out, pos, &p, &z, rng).unwrap();
    assert_eq!(ki, key_image);
    tx.signatures.push(sig);
    let tx = Transaction::from(tx);
    validate_mempool_tx(&tx, m.state(), m.height() + 1, m.rules())
        .expect("the forged transaction is valid on its own");
    tx
}

fn out_keys(tx: &Transaction) -> Vec<Point> {
    tx.output_keys().iter().map(|k| k.one_time_key).collect()
}

// ---------------------------------------------------------------- checks

/// No two transactions share a conflict key.
fn assert_disjoint(txs: &[Transaction]) {
    let mut seen = HashSet::new();
    for tx in txs {
        for k in conflict_keys(tx) {
            assert!(seen.insert(k), "two transactions share {k:?}");
        }
    }
}

/// The template holds pairwise non-conflicting transactions, each still valid
/// on its own at the next height.
fn assert_template_is_consistent(m: &ChainManager, t: &Template) {
    assert_disjoint(&t.txs);
    for tx in &t.txs {
        validate_mempool_tx(tx, m.state(), m.height() + 1, m.rules()).unwrap();
    }
}

/// The whole pool (small pools fit in one template) has no shared key.
fn assert_pool_disjoint(m: &ChainManager) {
    let t = m.template();
    assert_eq!(
        t.txs.len(),
        m.mempool().len(),
        "the template holds the pool"
    );
    assert_disjoint(&t.txs);
}

/// A chain of 100 blocks mined alternately by `honest` and `attacker`, so
/// both own about 20 mature coinbase outputs, with 16-member rings.
struct World {
    m: ChainManager,
    honest: Miner,
    attacker: Miner,
    bob: WalletKeys,
    rng: ChaCha20Rng,
}

fn world(store: Box<dyn BlockStore>, seed: u64) -> World {
    let mut m = open(store);
    let mut honest = Miner::new(seed);
    let mut attacker = Miner::new(seed + 1_000);
    for h in 0..100 {
        if h % 2 == 0 {
            honest.mine_tip(&mut m);
        } else {
            attacker.mine_tip(&mut m);
        }
    }
    let mut rng = ChaCha20Rng::seed_from_u64(seed + 2_000);
    let (bob, _) = WalletKeys::generate(&mut rng);
    World {
        m,
        honest,
        attacker,
        bob,
        rng,
    }
}

// ---------------------------------------------------------------- tests

/// Without the fix: a block holding two valid transactions that share an
/// output key is invalid (C4, `DuplicateOneTimeKey`), so a pool admitting
/// both made every template produce invalid blocks. Consensus is unchanged
/// by the fix; this is the rule the pool now anticipates.
#[test]
fn a_block_holding_two_transactions_sharing_an_output_key_is_invalid() {
    let mut w = world(Box::<MemoryStore>::default(), 1);
    let fee = standard_fee(1, 2, w.m.rules());
    let k = random_point(&mut w.rng);
    let x1 = forge(
        &w.m,
        &w.attacker.keys,
        0,
        &[k, random_point(&mut w.rng)],
        fee,
        &mut w.rng,
    );
    let x2 = forge(
        &w.m,
        &w.attacker.keys,
        1,
        &[k, random_point(&mut w.rng)],
        fee,
        &mut w.rng,
    );
    let tip = w.m.tip_id();
    match w
        .honest
        .mine_on(&mut w.m, &tip, vec![x1.clone(), x2.clone()], 1)
    {
        Err(SubmitError::Body(BlockError::Tx {
            error: TxError::DuplicateOneTimeKey { .. },
            ..
        })) => {}
        other => panic!("expected DuplicateOneTimeKey, got {:?}", other.map(|_| ())),
    }
    assert_eq!(w.m.tip_id(), tip);
    // Each alone is fine.
    let tip = w.m.tip_id();
    w.honest.mine_on(&mut w.m, &tip, vec![x1], 2).unwrap();
    assert!(matches!(
        w.m.submit_tx(x2),
        Err(MempoolError::Invalid(TxError::DuplicateOneTimeKey { .. }))
    ));
}

/// Case 1: two valid transactions of the same attacker (different inputs)
/// with the same output key: the second is refused and the pool is unchanged.
#[test]
fn a_second_transaction_reusing_an_output_key_is_refused() {
    let mut w = world(Box::<MemoryStore>::default(), 2);
    let fee = standard_fee(1, 2, w.m.rules());
    let k = random_point(&mut w.rng);
    let x1 = forge(
        &w.m,
        &w.attacker.keys,
        0,
        &[k, random_point(&mut w.rng)],
        fee,
        &mut w.rng,
    );
    let x2 = forge(
        &w.m,
        &w.attacker.keys,
        1,
        &[random_point(&mut w.rng), k],
        fee,
        &mut w.rng,
    );
    let id = w.m.submit_tx(x1.clone()).unwrap();
    let bytes = w.m.mempool().bytes();
    assert_eq!(w.m.check_tx(&x2), Err(MempoolError::Conflict), "stem path");
    assert_eq!(w.m.submit_tx(x2.clone()), Err(MempoolError::Conflict));
    assert_eq!(w.m.mempool().len(), 1);
    assert_eq!(w.m.mempool().bytes(), bytes);
    assert!(w.m.mempool().contains(&id));
    assert!(!w.m.mempool().contains(&x2.hash()));
    let b = w.honest.mine_tip(&mut w.m);
    assert_eq!(b.txs[1..], [x1]);
    assert!(w.m.mempool().is_empty());
}

/// Cases 2 and 3: copying an output key of a pending honest transaction is
/// refused, even with a hundred times the fee (no replacement); the honest
/// transaction confirms.
#[test]
fn copying_a_pending_output_key_is_refused_whatever_the_fee() {
    let mut w = world(Box::<MemoryStore>::default(), 3);
    let fee = standard_fee(1, 2, w.m.rules());
    let h = honest(&w.m, &w.honest.keys, &w.bob, 0, &mut w.rng);
    let hid = w.m.submit_tx(h.clone()).unwrap();
    for (i, victim_key) in out_keys(&h).into_iter().enumerate() {
        for (j, f) in [fee, 100 * fee].into_iter().enumerate() {
            let x = forge(
                &w.m,
                &w.attacker.keys,
                2 * i + j,
                &[victim_key, random_point(&mut w.rng)],
                f,
                &mut w.rng,
            );
            assert_eq!(w.m.submit_tx(x), Err(MempoolError::Conflict), "fee {f}");
        }
    }
    assert_eq!(w.m.mempool().len(), 1);
    let b = w.honest.mine_tip(&mut w.m);
    assert_eq!(b.txs[1].hash(), hid);
    assert_eq!(scan_all(&w.m, &w.bob).len(), 1, "the payment confirmed");
}

/// Case 4: in both arrival orders exactly the first seen is kept, and the
/// outcome is the same on every run.
#[test]
fn first_seen_wins_in_both_orders_deterministically() {
    let mut w = world(Box::<MemoryStore>::default(), 4);
    let fee = standard_fee(1, 2, w.m.rules());
    let h = honest(&w.m, &w.honest.keys, &w.bob, 0, &mut w.rng);
    let x = forge(
        &w.m,
        &w.attacker.keys,
        0,
        &[out_keys(&h)[1], random_point(&mut w.rng)],
        10 * fee,
        &mut w.rng,
    );
    let (next, rules) = (w.m.height() + 1, *w.m.rules());
    for _run in 0..2 {
        for (first, second) in [(&h, &x), (&x, &h)] {
            let mut pool = Mempool::new();
            pool.add(first.clone(), w.m.state(), next, &rules).unwrap();
            assert_eq!(
                pool.add(second.clone(), w.m.state(), next, &rules),
                Err(MempoolError::Conflict)
            );
            assert_eq!(pool.len(), 1);
            assert!(pool.contains(&first.hash()));
            let sel = pool.select(u64::MAX, 0);
            assert_eq!(sel.len(), 1);
            assert_eq!(sel[0].hash(), first.hash());
        }
    }
    // Through the node: the attacker first, then the victim.
    w.m.submit_tx(x.clone()).unwrap();
    assert_eq!(w.m.submit_tx(h), Err(MempoolError::Conflict));
    let b = w.honest.mine_tip(&mut w.m);
    assert_eq!(b.txs[1..], [x]);
}

/// Case 5: several mutually conflicting transactions (every pair shares an
/// output key): in every arrival order exactly one, the first, is kept.
#[test]
fn of_several_mutually_conflicting_transactions_exactly_one_is_kept() {
    let mut w = world(Box::<MemoryStore>::default(), 5);
    let fee = standard_fee(1, 2, w.m.rules());
    let h = honest(&w.m, &w.honest.keys, &w.bob, 0, &mut w.rng);
    let (h0, h1) = (out_keys(&h)[0], out_keys(&h)[1]);
    let r = random_point(&mut w.rng);
    let a = &w.attacker.keys;
    let x1 = forge(&w.m, a, 0, &[h0, r], fee, &mut w.rng);
    let x2 = forge(&w.m, a, 1, &[h1, r], 2 * fee, &mut w.rng);
    let x3 = forge(&w.m, a, 2, &[h0, h1], 3 * fee, &mut w.rng);
    let all = [h, x1, x2, x3];
    for i in 0..all.len() {
        for j in i + 1..all.len() {
            let ki: HashSet<Point> = out_keys(&all[i]).into_iter().collect();
            assert!(out_keys(&all[j]).iter().any(|k| ki.contains(k)));
        }
    }
    let (next, rules) = (w.m.height() + 1, *w.m.rules());
    // All 24 orders.
    let mut orders = vec![vec![0usize, 1, 2, 3]];
    while let Some(o) = next_permutation(orders.last().unwrap()) {
        orders.push(o);
    }
    assert_eq!(orders.len(), 24);
    for order in &orders {
        let mut pool = Mempool::new();
        let results: Vec<_> = order
            .iter()
            .map(|&i| pool.add(all[i].clone(), w.m.state(), next, &rules))
            .collect();
        assert!(results[0].is_ok());
        assert!(results[1..]
            .iter()
            .all(|r| *r == Err(MempoolError::Conflict)));
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&all[order[0]].hash()));
    }
    // Through the node, then a block.
    for tx in &all {
        let _ = w.m.submit_tx(tx.clone());
    }
    assert_eq!(w.m.mempool().len(), 1);
    w.honest.mine_tip(&mut w.m);
}

fn next_permutation(v: &[usize]) -> Option<Vec<usize>> {
    let mut v = v.to_vec();
    let i = (0..v.len() - 1).rev().find(|&i| v[i] < v[i + 1])?;
    let j = (i + 1..v.len()).rev().find(|&j| v[j] > v[i])?;
    v.swap(i, j);
    v[i + 1..].reverse();
    Some(v)
}

/// Case 6: under repeated attack attempts, every template yields a block that
/// connects: block production is not stalled. Each round an honest payment
/// and two attacker transactions (one copying the payment's output key, one
/// copying the other's) arrive in varying orders.
#[test]
fn a_conflicting_pair_cannot_stall_block_production() {
    let mut w = world(Box::<MemoryStore>::default(), 6);
    let fee = standard_fee(1, 2, w.m.rules());
    for round in 0..5 {
        let h = honest(&w.m, &w.honest.keys, &w.bob, 0, &mut w.rng);
        let x = forge(
            &w.m,
            &w.attacker.keys,
            0,
            &[out_keys(&h)[round % 2], random_point(&mut w.rng)],
            50 * fee,
            &mut w.rng,
        );
        let k = random_point(&mut w.rng);
        let y1 = forge(
            &w.m,
            &w.attacker.keys,
            1,
            &[k, random_point(&mut w.rng)],
            fee,
            &mut w.rng,
        );
        let y2 = forge(
            &w.m,
            &w.attacker.keys,
            2,
            &[k, random_point(&mut w.rng)],
            9 * fee,
            &mut w.rng,
        );
        let order: Vec<&Transaction> = if round % 2 == 0 {
            vec![&h, &x, &y1, &y2]
        } else {
            vec![&x, &h, &y2, &y1]
        };
        let results: Vec<_> = order
            .iter()
            .map(|tx| w.m.submit_tx((*tx).clone()))
            .collect();
        assert!(results[0].is_ok() && results[2].is_ok());
        assert_eq!(results[1], Err(MempoolError::Conflict));
        assert_eq!(results[3], Err(MempoolError::Conflict));
        assert_pool_disjoint(&w.m);
        let height = w.m.height();
        let b = w.honest.mine_tip(&mut w.m);
        assert_eq!(
            w.m.height(),
            height + 1,
            "round {round}: the chain advanced"
        );
        assert_eq!(
            b.txs.len(),
            3,
            "coinbase and the two first-seen transactions"
        );
        assert!(w.m.mempool().is_empty());
    }
}

/// Case 7: an honest transaction confirmed on branch A; the attacker mines a
/// copy of its output key directly on branch B. Through reorganizations in
/// both directions the pool never holds two transactions sharing a key, the
/// loser of each reorganization is dropped, and every template connects.
#[test]
fn reorganizations_never_leave_conflicting_transactions_pooled() {
    let mut w = world(Box::<MemoryStore>::default(), 7);
    let fee = standard_fee(1, 2, w.m.rules());
    let fork = w.m.tip_id();
    let h = honest(&w.m, &w.honest.keys, &w.bob, 0, &mut w.rng);
    let x = forge(
        &w.m,
        &w.attacker.keys,
        0,
        &[out_keys(&h)[0], random_point(&mut w.rng)],
        fee,
        &mut w.rng,
    );
    // An unrelated honest payment that stays valid on both branches.
    let u = honest(&w.m, &w.honest.keys, &w.bob, 1, &mut w.rng);
    w.m.submit_tx(h.clone()).unwrap();
    assert_eq!(w.m.submit_tx(x.clone()), Err(MempoolError::Conflict));

    // Branch A: A1 confirms `h`.
    let a1 = w.honest.mine_tip(&mut w.m);
    assert_eq!(a1.txs[1].hash(), h.hash());
    w.m.submit_tx(u.clone()).unwrap();
    assert_pool_disjoint(&w.m);

    // Branch B from the fork: B1 holds the attacker's copy, B2 overtakes A.
    let b1 = w
        .attacker
        .mine_on(&mut w.m, &fork, vec![x.clone()], 1)
        .unwrap();
    let b2 = w
        .attacker
        .mine_on(&mut w.m, &b1.id(params().network_id), vec![], 1)
        .unwrap();
    assert_eq!(w.m.tip_id(), b2.id(params().network_id), "B is best");
    assert!(w.m.deepest_reorg() >= 1);
    // `h` came back from A1 but conflicts with `x` on chain: dropped.
    assert!(!w.m.mempool().contains(&h.hash()));
    assert!(w.m.mempool().contains(&u.hash()));
    assert!(matches!(
        w.m.submit_tx(h.clone()),
        Err(MempoolError::Invalid(TxError::DuplicateOneTimeKey { .. }))
    ));
    assert_pool_disjoint(&w.m);
    let b3 = w.attacker.mine_tip(&mut w.m); // confirms `u` on B
    assert_eq!(b3.txs[1].hash(), u.hash());

    // Back to A: A2..A4 make A heavier (fork + 4 against fork + 3).
    let mut parent = a1.id(params().network_id);
    for i in 0..3 {
        parent = w
            .honest
            .mine_on(&mut w.m, &parent, vec![], 10 + i)
            .unwrap()
            .id(params().network_id);
    }
    assert_eq!(w.m.tip_id(), parent, "A is best again");
    // `x` came back from B1 and conflicts with `h` on chain: dropped; `u`
    // came back from B3 and is pooled again.
    assert!(!w.m.mempool().contains(&x.hash()));
    assert!(w.m.mempool().contains(&u.hash()));
    assert_pool_disjoint(&w.m);
    for _ in 0..2 {
        w.honest.mine_tip(&mut w.m);
    }
    assert!(w.m.mempool().is_empty());
    assert_eq!(scan_all(&w.m, &w.bob).len(), 2, "h and u confirmed on A");
}

/// Case 8: the pool is not persisted. After a restart, the conflicting pair
/// resubmitted in the reverse order keeps only the first seen after the
/// restart, and the chain keeps advancing.
#[test]
fn after_a_restart_the_first_seen_of_a_conflicting_pair_wins() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    let (h, x, mut miner) = {
        let mut w = world(Box::new(FileStore::open(&path).unwrap()), 8);
        let fee = standard_fee(1, 2, w.m.rules());
        let h = honest(&w.m, &w.honest.keys, &w.bob, 0, &mut w.rng);
        let x = forge(
            &w.m,
            &w.attacker.keys,
            0,
            &[out_keys(&h)[1], random_point(&mut w.rng)],
            fee,
            &mut w.rng,
        );
        w.m.submit_tx(h.clone()).unwrap();
        assert_eq!(w.m.submit_tx(x.clone()), Err(MempoolError::Conflict));
        (h, x, w.honest)
    };
    let mut m = open(Box::new(FileStore::open(&path).unwrap()));
    assert!(m.mempool().is_empty(), "not persisted");
    m.submit_tx(x.clone()).unwrap();
    assert_eq!(m.submit_tx(h.clone()), Err(MempoolError::Conflict));
    assert_eq!(m.mempool().len(), 1);
    let b = miner.mine_tip(&mut m);
    assert_eq!(b.txs[1..], [x]);
    assert!(matches!(
        m.submit_tx(h),
        Err(MempoolError::Invalid(TxError::DuplicateOneTimeKey { .. }))
    ));
    miner.mine_tip(&mut m);
}

/// Case 9 (deploy): a transfer copying an output key of a pooled deploy is
/// refused. (PX transactions are covered on synthetic transactions in the
/// unit tests: building a real PX proof is too heavy for this suite.)
#[test]
fn copying_a_pooled_deploys_output_key_is_refused() {
    use blacksilk_tx::px::Registration;
    use blacksilk_tx::px_builder::build_deploy;
    let mut w = world(Box::<MemoryStore>::default(), 9);
    let fee = standard_fee(1, 2, w.m.rules());
    let rules = *w.m.rules();
    let primary = w.honest.keys.address(SubaddressIndex::PRIMARY);
    let plan = plan_nth(&w.m, &w.honest.keys, 0, &mut w.rng);
    let deploy = Transaction::PxDeploy(Box::new(
        build_deploy(
            &w.honest.keys,
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
            }],
            &rules,
            &mut w.rng,
        )
        .unwrap(),
    ));
    w.m.submit_tx(deploy.clone()).unwrap();
    for (i, k) in out_keys(&deploy).into_iter().enumerate() {
        let x = forge(
            &w.m,
            &w.attacker.keys,
            i,
            &[k, random_point(&mut w.rng)],
            100 * fee,
            &mut w.rng,
        );
        assert_eq!(w.m.submit_tx(x), Err(MempoolError::Conflict));
    }
    assert_eq!(w.m.mempool().len(), 1);
    w.honest.mine_tip(&mut w.m);
    assert!(w.m.mempool().is_empty());
}

/// Case 10: namespaces. An output one-time key with the same bytes as a
/// pooled transaction's key image does not conflict with it: both are pooled,
/// and the block holding both is valid (consensus keeps key images and
/// one-time keys apart too).
#[test]
fn an_output_key_equal_to_a_pooled_key_image_does_not_conflict() {
    let mut w = world(Box::<MemoryStore>::default(), 10);
    let fee = standard_fee(1, 2, w.m.rules());
    let h = honest(&w.m, &w.honest.keys, &w.bob, 0, &mut w.rng);
    let image = h.key_images()[0];
    let x = forge(
        &w.m,
        &w.attacker.keys,
        0,
        &[image, random_point(&mut w.rng)],
        fee,
        &mut w.rng,
    );
    assert!(out_keys(&x).contains(&image));
    w.m.submit_tx(h.clone()).unwrap();
    w.m.submit_tx(x.clone()).unwrap();
    assert_eq!(w.m.mempool().len(), 2);
    let b = w.honest.mine_tip(&mut w.m);
    assert_eq!(b.txs.len(), 3, "both confirmed in one valid block");
    assert!(w.m.state().is_key_image_spent(&image));
}
