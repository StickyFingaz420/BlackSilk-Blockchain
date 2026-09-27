//! D8 option B: output one-time keys are not unique across transactions
//! (docs/transactions.md §8.2, docs/blocks.md §7; dossier 13,
//! docs/reviews/v3-consensus-changes.md §1).
//!
//! An output one-time key `O` is public as soon as its transaction is relayed,
//! and a sender chooses it freely. Under the former rule C4 (`O` unique on the
//! chain and in the block) and its mempool counterpart (output keys as
//! first-seen conflict keys), anyone who saw a pending transaction could copy
//! one of its keys into a valid transaction of their own, for one fee, and get
//! the copy mined or pooled first: the victim's transaction was then invalid
//! on that branch for good (the front-running veto of dossier 13, F13-1).
//!
//! These tests forge fully valid transactions with chosen output keys (the
//! attacker's side, [`forge`] and [`forge_copy`]) and check that the attack
//! no longer works: copies are pooled next to the victim, blocks holding both
//! are valid, a copy mined first leaves the victim valid (and it confirms),
//! across reorganizations and restarts; the recipient's wallet credits only
//! the genuine output (the Janus check, spec §3.3 step 5). Key images still
//! conflict (C2). Within-transaction distinctness of one-time keys stays a
//! stateless rule for every kind (tx/tests/output_key_uniqueness.rs,
//! chain/tests/block_rules.rs).

use blacksilk_chain::block::Block;
use blacksilk_chain::manager::{ChainManager, SubmitError, Template};
use blacksilk_chain::mempool::{conflict_keys, MempoolError};
use blacksilk_chain::store::{BlockStore, FileStore, MemoryStore};
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, PowFunction, HEADER_VERSION};
use blacksilk_crypto::bulletproofs_plus;
use blacksilk_crypto::clsag::{self, RingMember, RING_SIZE};
use blacksilk_crypto::commitment::commit;
use blacksilk_crypto::keys::{SubaddressIndex, SubaddressTable, WalletKeys};
use blacksilk_crypto::stealth::ScanRejection;
use blacksilk_crypto::{Point, RistrettoPoint, Scalar};
use blacksilk_tx::builder::{
    build_coinbase, build_transfer, standard_fee, Decoy, InputPlan, Payment, SpendableOutput,
};
use blacksilk_tx::decoy::select_ring;
use blacksilk_tx::params::{TxRules, COINBASE_MATURITY, SPENDABLE_AGE};
use blacksilk_tx::scan::{scan_block, OwnedOutput};
use blacksilk_tx::types::{Input, Output, Transaction, Transfer};
use blacksilk_tx::validate::{validate_mempool_tx, ChainView, TxError};
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

/// The published fields of an output the attacker copies verbatim (all of
/// them but the commitment, which must open to the attacker's own amount for
/// the range proof and the balance).
#[derive(Clone, Copy)]
struct Published {
    one_time_key: Point,
    ephemeral: Point,
    view_tag: u8,
    enc_amount: [u8; 8],
    enc_anchor: [u8; 16],
}

impl Published {
    fn of(o: &Output) -> Self {
        Self {
            one_time_key: o.one_time_key,
            ephemeral: o.ephemeral,
            view_tag: o.view_tag,
            enc_amount: o.enc_amount,
            enc_anchor: o.enc_anchor,
        }
    }

    /// Only `key` is chosen; the other fields are arbitrary (consensus does
    /// not check them).
    fn key_only(key: Point, rng: &mut ChaCha20Rng) -> Self {
        Self {
            one_time_key: key,
            ephemeral: random_point(rng),
            view_tag: rng.next_u32() as u8,
            enc_amount: [0xAA; 8],
            enc_anchor: [0x55; 16],
        }
    }
}

/// The attacker's builder: a fully valid one-input v1 transfer spending the
/// `nth` output of `keys`, whose outputs publish exactly `outs` (at least two,
/// with distinct keys). Built with the public crypto API as
/// `blacksilk_tx::builder::build_transfer_signing` does, but without deriving
/// the outputs: all the value minus the fee goes to the first output, the
/// others carry zero.
///
/// Asserts that the result passes full mempool validation on its own.
fn forge_outputs(
    m: &ChainManager,
    keys: &WalletKeys,
    nth: usize,
    outs: &[Published],
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
    let mut outs = outs.to_vec();
    outs.sort_by_key(|o| o.one_time_key);
    assert!(outs.len() >= 2, "two outputs at least");
    assert!(
        outs.windows(2)
            .all(|w| w[0].one_time_key < w[1].one_time_key),
        "distinct keys within the transaction"
    );
    let amounts: Vec<u64> = (0..outs.len())
        .map(|j| if j == 0 { real.amount - fee } else { 0 })
        .collect();
    let masks: Vec<Scalar> = outs.iter().map(|_| random_scalar(rng)).collect();
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
        outputs: outs
            .iter()
            .zip(&commitments)
            .map(|(o, c)| Output {
                one_time_key: o.one_time_key,
                ephemeral: o.ephemeral,
                view_tag: o.view_tag,
                commitment: *c,
                enc_amount: o.enc_amount,
                enc_anchor: o.enc_anchor,
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

/// [`forge_outputs`] with the chosen one-time keys `out_keys` and arbitrary
/// other fields.
fn forge(
    m: &ChainManager,
    keys: &WalletKeys,
    nth: usize,
    out_keys: &[Point],
    fee: u64,
    rng: &mut ChaCha20Rng,
) -> Transaction {
    let outs: Vec<Published> = out_keys
        .iter()
        .map(|&k| Published::key_only(k, rng))
        .collect();
    forge_outputs(m, keys, nth, &outs, fee, rng)
}

/// A copy of `victim`'s output `j`, verbatim (key, ephemeral key, view tag,
/// encrypted amount and anchor), plus one arbitrary output.
fn forge_copy(
    m: &ChainManager,
    keys: &WalletKeys,
    nth: usize,
    victim: &Transaction,
    j: usize,
    fee: u64,
    rng: &mut ChaCha20Rng,
) -> Transaction {
    let Transaction::Transfer(v) = victim else {
        panic!("a transfer victim")
    };
    let copied = Published::of(&v.outputs[j]);
    let other = Published::key_only(random_point(rng), rng);
    let x = forge_outputs(m, keys, nth, &[copied, other], fee, rng);
    assert!(out_keys(&x).contains(&v.outputs[j].one_time_key));
    x
}

fn out_keys(tx: &Transaction) -> Vec<Point> {
    tx.output_keys().iter().map(|k| k.one_time_key).collect()
}

// ---------------------------------------------------------------- checks

/// No two transactions share a conflict key (key images, nullifiers,
/// contract ids; output keys are not conflict keys).
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

/// Bob's payment output of an honest transfer (the one paying `amount`).
fn payment_index(w: &World, h: &Transaction) -> usize {
    let height = w.m.height() + 1;
    let table = SubaddressTable::new(w.bob.view_keys(), 1, 5);
    let r = scan_block(
        w.bob.view_keys(),
        &table,
        std::slice::from_ref(h),
        height,
        0,
    );
    assert_eq!(r.owned.len(), 1);
    r.owned[0].index_in_tx
}

// ---------------------------------------------------------------- tests

/// A block holding two valid transactions that share an output key is valid
/// (it was invalid under C4, `DuplicateOneTimeKey`), and both confirm. The
/// pool admits both too: they conflict on nothing.
#[test]
fn a_block_holding_two_transactions_sharing_an_output_key_is_valid() {
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
    let b = w
        .honest
        .mine_on(&mut w.m, &tip, vec![x1.clone(), x2.clone()], 1)
        .expect("a block with a cross-transaction key repeat is valid");
    assert_eq!(w.m.tip_id(), b.id(params().network_id));
    for x in [&x1, &x2] {
        assert!(w.m.state().is_key_image_spent(&x.key_images()[0]));
    }
    // Two outputs with the same key now sit at two global indices.
    let n = w.m.state().output_count();
    let copies = (0..n)
        .filter(|&i| w.m.state().output(i).unwrap().key.one_time_key == k)
        .count();
    assert_eq!(copies, 2);
    // The pool: both admitted, both in one template, the block connects.
    let y1 = forge(
        &w.m,
        &w.attacker.keys,
        0,
        &[k, random_point(&mut w.rng)],
        fee,
        &mut w.rng,
    );
    let y2 = forge(
        &w.m,
        &w.attacker.keys,
        1,
        &[k, random_point(&mut w.rng)],
        fee,
        &mut w.rng,
    );
    w.m.submit_tx(y1.clone()).unwrap();
    assert_eq!(w.m.check_tx(&y2), Ok(y2.hash()), "stem path");
    w.m.submit_tx(y2.clone()).unwrap();
    let b = w.honest.mine_tip(&mut w.m);
    assert_eq!(b.txs.len(), 3);
    assert!(w.m.mempool().is_empty());
}

/// Copying any output key of a pending honest transaction, at the same or a
/// hundred times the fee, changes nothing for the victim: every copy is
/// pooled, one block confirms them all, and the recipient is credited once.
#[test]
fn copies_of_a_pending_output_key_are_pooled_and_the_victim_confirms() {
    let mut w = world(Box::<MemoryStore>::default(), 3);
    let fee = standard_fee(1, 2, w.m.rules());
    let h = honest(&w.m, &w.honest.keys, &w.bob, 0, &mut w.rng);
    let hid = w.m.submit_tx(h.clone()).unwrap();
    let mut copies = Vec::new();
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
            assert_eq!(w.m.check_tx(&x), Ok(x.hash()), "stem path, fee {f}");
            copies.push(w.m.submit_tx(x).expect("a copy is admitted"));
        }
    }
    assert_eq!(w.m.mempool().len(), 5);
    assert!(w.m.mempool().contains(&hid), "the victim stays pooled");
    let b = w.honest.mine_tip(&mut w.m);
    let ids: Vec<Hash> = b.txs.iter().map(Transaction::hash).collect();
    assert!(ids.contains(&hid));
    assert!(copies.iter().all(|c| ids.contains(c)));
    assert!(w.m.mempool().is_empty());
    assert_eq!(scan_all(&w.m, &w.bob).len(), 1, "the payment, once");
}

/// The front-running attack itself: the attacker mines a verbatim copy of
/// the victim's payment output (key, ephemeral key, view tag, encrypted
/// amount and anchor) BEFORE the victim's transaction. The victim's
/// transaction stays valid, stays pooled, and confirms in the next block;
/// the recipient's wallet refuses the copy (Janus, spec §3.3 step 5: the
/// copy's input context differs) and credits exactly the genuine output.
#[test]
fn a_copy_mined_first_leaves_the_victim_valid() {
    let mut w = world(Box::<MemoryStore>::default(), 11);
    let fee = standard_fee(1, 2, w.m.rules());
    let h = honest(&w.m, &w.honest.keys, &w.bob, 0, &mut w.rng);
    let j = payment_index(&w, &h);
    let x = forge_copy(&w.m, &w.attacker.keys, 0, &h, j, fee, &mut w.rng);
    let hid = w.m.submit_tx(h.clone()).unwrap();

    // Block N: the attacker's copy, mined directly (not from any pool).
    let tip = w.m.tip_id();
    w.attacker
        .mine_on(&mut w.m, &tip, vec![x.clone()], 1)
        .expect("the copy is valid");
    // The victim is untouched: pooled, and valid against the new tip.
    assert!(w.m.mempool().contains(&hid));
    assert_eq!(
        validate_mempool_tx(&h, w.m.state(), w.m.height() + 1, w.m.rules()),
        Ok(())
    );
    // Block N + 1: the victim confirms.
    let b = w.honest.mine_tip(&mut w.m);
    assert_eq!(b.txs[1].hash(), hid);

    // The recipient: the copy (first on chain, same `O`) is refused, the
    // genuine output is credited, once.
    let table = SubaddressTable::new(w.bob.view_keys(), 1, 5);
    let (hc, hh) = (w.m.height() - 1, w.m.height());
    let copy_block = w.m.block_at(hc).unwrap();
    let first = w.m.state().first_output_at(hc).unwrap();
    let r = scan_block(w.bob.view_keys(), &table, &copy_block.txs, hc, first);
    assert!(r.owned.is_empty(), "the copy is not credited");
    assert_eq!(r.rejected.len(), 1);
    assert_eq!(r.rejected[0].1, ScanRejection::JanusAnchorMismatch);
    let genuine = scan_all(&w.m, &w.bob);
    assert_eq!(genuine.len(), 1);
    assert_eq!(genuine[0].height, hh);
    assert_eq!(genuine[0].tx_hash, hid);
    assert_eq!(genuine[0].received.amount, 1_000);
}

/// Under repeated attempts every template connects and holds every pooled
/// transaction: an honest payment, a copy of its key and a pair of the
/// attacker's own transactions sharing a key, in varying orders.
#[test]
fn copies_never_stall_block_production() {
    let mut w = world(Box::<MemoryStore>::default(), 6);
    let fee = standard_fee(1, 2, w.m.rules());
    for round in 0..3 {
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
        for tx in order {
            w.m.submit_tx(tx.clone()).unwrap();
        }
        let height = w.m.height();
        let b = w.honest.mine_tip(&mut w.m);
        assert_eq!(
            w.m.height(),
            height + 1,
            "round {round}: the chain advanced"
        );
        assert_eq!(b.txs.len(), 5, "coinbase and all four");
        assert!(w.m.mempool().is_empty());
    }
    assert_eq!(scan_all(&w.m, &w.bob).len(), 3, "every payment, once");
}

/// An honest transaction confirmed on branch A; the attacker mines a copy of
/// its output key on branch B, which overtakes A. The honest transaction
/// returns to the pool, stays valid on B and confirms there; back on A, the
/// copy returns and confirms. Nothing is ever dropped for sharing a key.
#[test]
fn reorganizations_keep_both_the_victim_and_the_copy_valid() {
    let mut w = world(Box::<MemoryStore>::default(), 7);
    let fee = standard_fee(1, 2, w.m.rules());
    let fork = w.m.tip_id();
    let h = honest(&w.m, &w.honest.keys, &w.bob, 0, &mut w.rng);
    let j = payment_index(&w, &h);
    let x = forge_copy(&w.m, &w.attacker.keys, 0, &h, j, fee, &mut w.rng);
    w.m.submit_tx(h.clone()).unwrap();
    w.m.submit_tx(x.clone()).unwrap();

    // Branch A: A1 confirms both.
    let a1 = w.honest.mine_tip(&mut w.m);
    assert_eq!(a1.txs.len(), 3);

    // Branch B from the fork: B1 holds only the attacker's copy, B2 overtakes.
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
    // `h` came back from A1 and is valid next to `x` on chain: pooled.
    assert!(w.m.mempool().contains(&h.hash()));
    assert!(!w.m.mempool().contains(&x.hash()));
    let b3 = w.attacker.mine_tip(&mut w.m);
    assert_eq!(b3.txs[1].hash(), h.hash(), "h confirms on B");
    assert_eq!(scan_all(&w.m, &w.bob).len(), 1);

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
    assert!(w.m.mempool().is_empty(), "A1 already holds both");
    assert_eq!(scan_all(&w.m, &w.bob).len(), 1, "credited once on A");
}

/// The pool is not persisted. After a restart, with the copy already mined,
/// the victim's transaction is still admitted and confirms.
#[test]
fn after_a_restart_the_victim_confirms_after_its_copy() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    let (h, x, mut miner, bob) = {
        let mut w = world(Box::new(FileStore::open(&path).unwrap()), 8);
        let fee = standard_fee(1, 2, w.m.rules());
        let h = honest(&w.m, &w.honest.keys, &w.bob, 0, &mut w.rng);
        let j = payment_index(&w, &h);
        let x = forge_copy(&w.m, &w.attacker.keys, 0, &h, j, fee, &mut w.rng);
        w.m.submit_tx(x.clone()).unwrap();
        (h, x, w.honest, w.bob)
    };
    let mut m = open(Box::new(FileStore::open(&path).unwrap()));
    assert!(m.mempool().is_empty(), "not persisted");
    m.submit_tx(x.clone()).unwrap();
    let b = miner.mine_tip(&mut m);
    assert_eq!(b.txs[1..], [x]);
    let hid = m
        .submit_tx(h)
        .expect("the victim is admitted after its copy");
    let b = miner.mine_tip(&mut m);
    assert_eq!(b.txs[1].hash(), hid);
    assert_eq!(scan_all(&m, &bob).len(), 1);
}

/// Deploys: transfers copying the output keys of a pooled deploy are pooled
/// too, and one block confirms them all.
#[test]
fn copying_a_pooled_deploys_output_key_changes_nothing() {
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
        w.m.submit_tx(x).unwrap();
    }
    assert_eq!(w.m.mempool().len(), 3);
    let b = w.honest.mine_tip(&mut w.m);
    assert_eq!(b.txs.len(), 4);
    assert!(w.m.mempool().is_empty());
}

/// Key images still conflict (C2): of two transactions spending the same
/// output, the first seen is kept, whatever the fee, and the other is
/// refused on the stem and the fluff paths.
#[test]
fn a_second_spend_of_a_key_image_is_still_refused() {
    let mut w = world(Box::<MemoryStore>::default(), 2);
    let fee = standard_fee(1, 2, w.m.rules());
    let first = forge(
        &w.m,
        &w.attacker.keys,
        0,
        &[random_point(&mut w.rng), random_point(&mut w.rng)],
        fee,
        &mut w.rng,
    );
    let second = forge(
        &w.m,
        &w.attacker.keys,
        0,
        &[random_point(&mut w.rng), random_point(&mut w.rng)],
        100 * fee,
        &mut w.rng,
    );
    assert_eq!(first.key_images(), second.key_images());
    let id = w.m.submit_tx(first.clone()).unwrap();
    assert_eq!(w.m.check_tx(&second), Err(MempoolError::Conflict));
    assert_eq!(w.m.submit_tx(second.clone()), Err(MempoolError::Conflict));
    assert_eq!(w.m.mempool().len(), 1);
    assert!(w.m.mempool().contains(&id));
    let b = w.honest.mine_tip(&mut w.m);
    assert_eq!(b.txs[1..], [first]);
    assert!(matches!(
        w.m.submit_tx(second),
        Err(MempoolError::Invalid(TxError::KeyImageSpent { input: 0 }))
    ));
    assert_template_is_consistent(&w.m, &w.m.template());
}

/// Namespaces: an output one-time key with the same bytes as a pooled
/// transaction's key image does not conflict with it: both are pooled, and
/// the block holding both is valid.
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
