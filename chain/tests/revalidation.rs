//! Mempool revalidation with real v1 transfers and a real chain manager
//! (finding F3).
//!
//! After a plain extension the pool re-checks only the rules an extension can
//! change (`revalidate_after_extension`); after a reorganization it also
//! resolves every ring at the new next height (C1) and compares what it
//! resolves to with the entry's ring digest, verifying nothing (W2-12,
//! `chain/src/mempool/reorg.rs`). These tests make each path decide
//! something:
//! - an extension that creates a pooled transaction's output one-time key
//!   through a DIFFERENT transaction (the two share no key image): the
//!   extension check alone must drop it;
//! - a plain extension keeps valid transactions;
//! - a reorganization that replaces coinbase-only blocks changes what a pooled
//!   transaction's ring resolves to, and a reorganization to a shorter but
//!   heavier chain makes its ring member immature: full validation drops the
//!   transaction, and so does the reorg path (a changed ring digest, C1 at the
//!   new height), without verifying a signature, while the extension check
//!   alone would have kept it.
//!
//! To isolate `Mempool::revalidate` from `Mempool::remove_block` (which, since
//! output keys became conflict keys, also drops a pooled transaction sharing
//! an output key with a connected block), the tests use their own `Mempool`
//! instances, filled against the manager's state and revalidated explicitly;
//! `remove_block` is never called on them.

use blacksilk_chain::block::Block;
use blacksilk_chain::manager::{ChainManager, Template};
use blacksilk_chain::mempool::{conflict_keys, Mempool, Origin};
use blacksilk_chain::store::{BlockStore, MemoryStore};
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, PowFunction, HEADER_VERSION};
use blacksilk_crypto::clsag::{self, RingMember};
use blacksilk_crypto::commitment::commit;
use blacksilk_crypto::janus::ANCHOR_BYTES;
use blacksilk_crypto::keys::{SubaddressIndex, SubaddressTable, WalletKeys};
use blacksilk_crypto::{bulletproofs_plus as bpp, Point, RistrettoPoint, Scalar};
use blacksilk_tx::builder::{
    build_coinbase, build_transfer, standard_fee, Decoy, InputPlan, Payment, SpendableOutput,
};
use blacksilk_tx::decoy::select_ring;
use blacksilk_tx::params::{TxRules, COINBASE_MATURITY, RING_SIZE, SPENDABLE_AGE};
use blacksilk_tx::scan::{scan_block, OwnedOutput};
use blacksilk_tx::types::{Input, Output, Transaction, Transfer};
use blacksilk_tx::validate::{revalidate_after_extension, validate_mempool_tx, ChainView, TxError};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections::HashSet;
use std::sync::Arc;

// ------------------------------------------------------------------ helpers
// (from chain/tests/manager.rs)

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

fn open() -> ChainManager {
    let p = params();
    let rules = TxRules::for_chain(&p);
    let store: Box<dyn BlockStore> = Box::<MemoryStore>::default();
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

    /// A block from a template with the given transactions and timestamp
    /// (default: 120 s per height, which keeps regtest difficulty at 1).
    fn build(&mut self, t: &Template, txs: Vec<Transaction>, timestamp: Option<u64>) -> Block {
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
            timestamp: timestamp.unwrap_or_else(|| {
                t.min_timestamp
                    .max(params().genesis.timestamp + 120 * t.height)
            }),
            difficulty: t.difficulty,
            tx_root: tx_root(&ids),
            nonce: 0,
        };
        Block { header, txs: all }
    }

    /// Mines `n` coinbase-only blocks on `parent` (any known block), each
    /// `spacing` seconds after its parent (`None`: 120 s per height). Returns
    /// the id of the last one.
    fn mine_on(
        &mut self,
        m: &mut ChainManager,
        parent: Hash,
        n: usize,
        spacing: Option<u64>,
    ) -> Hash {
        let mut p = parent;
        for _ in 0..n {
            let t = m.template_on(&p).unwrap();
            let ts = spacing.map(|s| {
                let parent_time = m.headers().header(&p).unwrap().timestamp;
                t.min_timestamp.max(parent_time + s)
            });
            let b = self.build(&t, vec![], ts);
            let now = b.header.timestamp;
            m.submit_block(b.clone(), now).expect("valid block");
            p = b.id(params().network_id);
        }
        p
    }

    fn mine_tip(&mut self, m: &mut ChainManager, n: usize) {
        let tip = m.tip_id();
        self.mine_on(m, tip, n, None);
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

fn mature(height: u64, created: u64, coinbase: bool) -> bool {
    let age = if coinbase {
        COINBASE_MATURITY
    } else {
        SPENDABLE_AGE
    };
    height >= created + age
}

/// An input plan for the first mature, unspent output of `from` accepted by
/// `pick`, with a ring of outputs mature at the next height.
fn plan_where(
    m: &ChainManager,
    from: &WalletKeys,
    pick: impl Fn(&OwnedOutput) -> bool,
    rng: &mut ChaCha20Rng,
) -> InputPlan {
    let height = m.height() + 1;
    let owned = scan_all(m, from)
        .into_iter()
        .filter(|o| {
            mature(height, o.height, o.coinbase)
                && !m.state().is_key_image_spent(&o.key_image(from))
        })
        .find(|o| pick(o))
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
                .is_some_and(|r| mature(height, r.height, r.coinbase))
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

/// An honest 1-input, 2-output transfer of `plan` to `to`.
fn pay(
    m: &ChainManager,
    from: &WalletKeys,
    to: &WalletKeys,
    plan: InputPlan,
    rng: &mut ChaCha20Rng,
) -> Transfer {
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
    .unwrap()
}

fn random_scalar(rng: &mut ChaCha20Rng) -> Scalar {
    let mut wide = [0u8; 64];
    rng.fill_bytes(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn random_point(rng: &mut ChaCha20Rng) -> Point {
    Point::from_point(RistrettoPoint::mul_base(&random_scalar(rng)))
}

/// An attacker's fully valid 1-input, 2-output transfer, spending `plan` (its
/// own output) and creating one output with the chosen one-time key
/// `victim_key` (1 000 atomic units; the other output takes the change). The
/// same steps as `build_transfer_signing`: spend secret, key image, sorted
/// outputs, Bulletproofs+, pseudo-output, CLSAG over the signature message.
fn forge_with_output_key(
    keys: &WalletKeys,
    plan: InputPlan,
    victim_key: Point,
    rules: &TxRules,
    rng: &mut ChaCha20Rng,
) -> Transfer {
    let fee = standard_fee(1, 2, rules);
    let real = &plan.real;
    let p = keys.one_time_secret(real.subaddress, &real.output_key_offset);
    assert_eq!(
        Point::from_point(RistrettoPoint::mul_base(&p)),
        real.key.one_time_key
    );
    let key_image = clsag::key_image(&p, &real.key.one_time_key);

    // Outputs sorted by one-time key; the range proof follows that order.
    let mut outs = [
        (victim_key, 1_000u64, random_scalar(rng)),
        (
            random_point(rng),
            real.amount - fee - 1_000,
            random_scalar(rng),
        ),
    ];
    outs.sort_by_key(|o| o.0);
    let amounts: Vec<u64> = outs.iter().map(|o| o.1).collect();
    let masks: Vec<Scalar> = outs.iter().map(|o| o.2).collect();
    let (range_proof, commitments) = bpp::prove(&amounts, &masks, rng).unwrap();
    let outputs = outs
        .iter()
        .zip(&commitments)
        .map(|(o, c)| Output {
            one_time_key: o.0,
            ephemeral: random_point(rng),
            view_tag: 0,
            commitment: *c,
            enc_amount: [0; 8],
            enc_anchor: [0; ANCHOR_BYTES],
        })
        .collect();
    let pseudo_mask: Scalar = masks.iter().sum();
    let pseudo_out = Point::from_point(commit(real.amount, &pseudo_mask));

    // Ring, sorted by global index.
    let mut members = plan.decoys.clone();
    members.push(Decoy {
        global_index: real.global_index,
        key: real.key,
    });
    members.sort_by_key(|d| d.global_index);
    assert_eq!(members.len(), RING_SIZE);
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
        outputs,
        fee,
        pseudo_outs: vec![pseudo_out],
        range_proof,
        signatures: vec![],
    };
    let message = tx.signature_message(rules.domain());
    let (sig, ki) = clsag::sign(
        &message,
        &ring,
        &pseudo_out,
        pos,
        &p,
        &(real.mask - pseudo_mask),
        rng,
    )
    .unwrap();
    assert_eq!(ki, key_image);
    tx.signatures.push(sig);
    tx
}

// ------------------------------------------------------------------ extension

/// A pooled transfer `victim` whose output one-time key is created by a
/// different, valid transaction `forged` (the attacker's copy) in a newly
/// connected block. The two share no key image and no conflict key: output
/// keys are neither unique on chain nor conflict keys (D8 option B,
/// docs/reviews/v3-consensus-changes.md §1). Under the former rule C4 the
/// extension check dropped `victim` here, a front-running veto for one fee;
/// now it stays valid, on the extension path, in full validation, in both
/// pools, and it confirms.
#[test]
fn an_output_key_copied_by_another_mined_transaction_leaves_the_victim_valid() {
    let mut m = open();
    let mut attacker = Miner::new(301);
    let mut miner = Miner::new(302);
    let mut rng = ChaCha20Rng::seed_from_u64(1_303);
    let (alice, _) = WalletKeys::generate(&mut rng);
    attacker.mine_tip(&mut m, 10);
    miner.mine_tip(&mut m, 70);
    let next = m.height() + 1;

    let plan = plan_where(&m, &miner.keys, |_| true, &mut rng);
    let victim = Transaction::from(pay(&m, &miner.keys, &alice, plan, &mut rng));
    let plan = plan_where(&m, &miner.keys, |o| o.height > 12, &mut rng);
    let control = Transaction::from(pay(&m, &miner.keys, &alice, plan, &mut rng));
    let Transaction::Transfer(v) = &victim else {
        unreachable!()
    };
    let key = v.outputs[0].one_time_key;
    let plan = plan_where(&m, &attacker.keys, |_| true, &mut rng);
    let forged = Transaction::from(forge_with_output_key(
        &attacker.keys,
        plan,
        key,
        m.rules(),
        &mut rng,
    ));

    // All three are valid on their own.
    for tx in [&victim, &control, &forged] {
        assert_eq!(validate_mempool_tx(tx, m.state(), next, m.rules()), Ok(()));
    }
    // `forged` and `victim` share no conflict key: not the key image, and
    // output keys are not conflict keys.
    let a: HashSet<_> = conflict_keys(&victim).into_iter().collect();
    let b: HashSet<_> = conflict_keys(&forged).into_iter().collect();
    assert!(a.is_disjoint(&b));
    assert!(out_keys_of(&forged).contains(&key));
    assert!(conflict_keys(&control)
        .iter()
        .all(|k| !b.contains(k) && !a.contains(k)));

    // The manager's pool admits all three.
    m.submit_tx(victim.clone()).unwrap();
    m.submit_tx(control.clone()).unwrap();
    m.submit_tx(forged.clone()).unwrap();

    // An isolated pool holding the victim and the control.
    let mut pool = Mempool::new();
    pool.add(victim.clone(), m.state(), next, m.rules(), Origin::Peer)
        .unwrap();
    pool.add(control.clone(), m.state(), next, m.rules(), Origin::Peer)
        .unwrap();

    // The attacker mines `forged` directly (not from any pool).
    let t = m.template_on(&m.tip_id()).unwrap();
    let blk = attacker.build(&t, vec![forged.clone()], None);
    let now = blk.header.timestamp;
    assert!(m.submit_block(blk, now).unwrap().on_best_chain);
    let next = m.height() + 1;

    // The extension check keeps both, and agrees with full validation.
    for tx in [&victim, &control] {
        assert_eq!(revalidate_after_extension(tx, m.state(), next), Ok(()));
        assert_eq!(validate_mempool_tx(tx, m.state(), next, m.rules()), Ok(()));
    }

    // The isolated pool: no `remove_block`, only the extension path.
    pool.revalidate(m.state(), next, m.rules(), false);
    assert!(pool.contains(&victim.hash()));
    assert!(pool.contains(&control.hash()));
    assert_eq!(pool.len(), 2);

    // The manager's own pool (`remove_block`, then `revalidate`) kept them,
    // and the next block confirms them.
    assert!(m.mempool().contains(&victim.hash()));
    assert!(m.mempool().contains(&control.hash()));
    assert_eq!(m.mempool().len(), 2);
    let t = m.template();
    assert_eq!(t.txs.len(), 2);
    let blk = miner.build(&t, t.txs.clone(), None);
    let now = blk.header.timestamp;
    assert!(m.submit_block(blk, now).unwrap().on_best_chain);
    assert!(m.mempool().is_empty());
    assert!(m.state().is_key_image_spent(&v.inputs[0].key_image));
    // Alice holds both payments; the copy (an output with her payment's key
    // but not built for her) is not credited.
    assert_eq!(scan_all(&m, &alice).len(), 2);
}

fn out_keys_of(tx: &Transaction) -> Vec<Point> {
    tx.output_keys().iter().map(|k| k.one_time_key).collect()
}

/// A plain extension of coinbase-only blocks and of a block with an unrelated
/// transfer: the extension path keeps every valid pooled transaction, and at
/// each step its verdict equals full validation.
#[test]
fn a_plain_extension_keeps_valid_transactions() {
    let mut m = open();
    let mut miner = Miner::new(311);
    let mut rng = ChaCha20Rng::seed_from_u64(1_311);
    let (alice, _) = WalletKeys::generate(&mut rng);
    miner.mine_tip(&mut m, 80);
    let next = m.height() + 1;
    let mut pool = Mempool::new();
    let mut ids = Vec::new();
    for nth in 0..3 {
        let plan = plan_where(&m, &miner.keys, |o| o.height == 1 + nth, &mut rng);
        let tx = Transaction::from(pay(&m, &miner.keys, &alice, plan, &mut rng));
        ids.push(
            pool.add(tx, m.state(), next, m.rules(), Origin::Peer)
                .unwrap(),
        );
    }
    // An unrelated transfer mined in a block.
    let plan = plan_where(&m, &miner.keys, |o| o.height == 10, &mut rng);
    let other = Transaction::from(pay(&m, &miner.keys, &alice, plan, &mut rng));
    let t = m.template_on(&m.tip_id()).unwrap();
    let blk = miner.build(&t, vec![other], None);
    let now = blk.header.timestamp;
    m.submit_block(blk, now).unwrap();
    for round in 0..6 {
        let next = m.height() + 1;
        for id in &ids {
            let tx = pool.get(id).unwrap();
            assert_eq!(revalidate_after_extension(tx, m.state(), next), Ok(()));
            assert_eq!(validate_mempool_tx(tx, m.state(), next, m.rules()), Ok(()));
        }
        pool.revalidate(m.state(), next, m.rules(), false);
        assert_eq!(pool.len(), 3, "round {round}");
        miner.mine_tip(&mut m, 1);
    }
}

// ------------------------------------------------------------------ reorganizations

/// A deep reorganization replaces coinbase-only blocks, among them the block
/// whose coinbase output a pooled transfer spends. The transfer is in no
/// disconnected block and nothing it spends or creates appears on the new
/// branch, so `revalidate_after_extension` still accepts it; but its ring
/// indices now resolve to other outputs and its signature no longer verifies.
/// Full validation drops it; the reorg path drops it for its changed ring
/// digest, without verifying it (nothing is verified by any pool here).
#[test]
fn replacing_coinbase_only_blocks_changes_a_ring_and_needs_full_validation() {
    let mut m = open();
    let mut miner = Miner::new(321);
    let mut rival = Miner::new(322);
    let mut rng = ChaCha20Rng::seed_from_u64(1_321);
    let (alice, _) = WalletKeys::generate(&mut rng);
    miner.mine_tip(&mut m, 20);
    let fork_parent = m.tip_id();
    let x_height = m.height() + 1;
    // Mine until the coinbase of block `x_height` is mature for the next block.
    let more = (x_height + COINBASE_MATURITY - 1 - m.height()) as usize;
    miner.mine_tip(&mut m, more);
    assert_eq!(m.height() + 1, x_height + COINBASE_MATURITY);
    let next = m.height() + 1;
    let plan = plan_where(&m, &miner.keys, |o| o.height == x_height, &mut rng);
    let spent_index = plan.real.global_index;
    let tx = Transaction::from(pay(&m, &miner.keys, &alice, plan, &mut rng));
    m.submit_tx(tx.clone()).unwrap();
    let mut ext_pool = Mempool::new();
    ext_pool
        .add(tx.clone(), m.state(), next, m.rules(), Origin::Peer)
        .unwrap();
    let mut full_pool = Mempool::new();
    full_pool
        .add(tx.clone(), m.state(), next, m.rules(), Origin::Peer)
        .unwrap();

    // A rival branch of coinbase-only blocks from before `x_height`, one
    // block longer (regtest difficulty 1: more blocks, more work).
    let depth = m.height() - (x_height - 1);
    let manager_verified = m.mempool().full_validations();
    rival.mine_on(&mut m, fork_parent, depth as usize + 1, None);
    assert_eq!(m.deepest_reorg() as u64, depth);
    assert_eq!(m.height(), x_height + depth);
    let next = m.height() + 1;
    // The spent output's index now holds the rival's coinbase output.
    assert!(m.state().output(spent_index).is_some());
    assert!(!m.state().is_key_image_spent(&tx.key_images()[0]));

    // The extension check alone would keep it...
    assert_eq!(revalidate_after_extension(&tx, m.state(), next), Ok(()));
    ext_pool.revalidate(m.state(), next, m.rules(), false);
    assert!(ext_pool.contains(&tx.hash()));
    // ...full validation does not.
    assert_eq!(
        validate_mempool_tx(&tx, m.state(), next, m.rules()),
        Err(TxError::InvalidSignature { input: 0 })
    );
    let verified = full_pool.full_validations();
    let r = full_pool.revalidate(m.state(), next, m.rules(), true);
    assert!(!full_pool.contains(&tx.hash()));
    assert_eq!((r.ring_changed, r.invalid), (1, 0), "{r:?}");
    assert_eq!(full_pool.full_validations(), verified);
    // The manager used the reorg path, and verified nothing for it (the
    // disconnected blocks were coinbase-only: nothing returned).
    assert!(!m.mempool().contains(&tx.hash()));
    assert_eq!(m.mempool().full_validations(), manager_verified);
}

/// A reorganization to a shorter but heavier branch lowers the height, so a
/// pooled transfer whose (coinbase) input matured exactly at the old next
/// height becomes immature (C1). Nothing it spends or creates changes, so
/// `revalidate_after_extension` still accepts it; full validation drops it,
/// and so does the reorg path (C1 at the new height), unverified.
///
/// Construction: the chain is mined with 1 s blocks (difficulty rises), then
/// four slow blocks (1000 s: the difficulty falls). A rival branch of three fast
/// blocks from before the slow ones has more work with fewer blocks. (Under the
/// v3 rule the counted clock runs ahead of 1 s stamps by the step T/2 per
/// block, so the slow blocks must be slow enough to pass it before the
/// difficulty can fall; see docs/reviews/v3-consensus-changes.md#daa-lwma75-warm.)
#[test]
fn a_shorter_heavier_reorg_makes_a_ring_member_immature() {
    let mut m = open();
    let mut miner = Miner::new(331);
    let mut rival = Miner::new(332);
    let mut rng = ChaCha20Rng::seed_from_u64(1_331);
    let (alice, _) = WalletKeys::generate(&mut rng);
    let genesis = m.tip_id();
    miner.mine_on(&mut m, genesis, 80, Some(1));
    let fork_parent = m.tip_id();
    let fork_height = m.height();
    miner.mine_on(&mut m, fork_parent, 4, Some(1000));
    assert_eq!(m.height(), fork_height + 4);
    let old_next = m.height() + 1;
    let diffs: Vec<u64> = (fork_height..=m.height())
        .map(|h| m.block_at(h).unwrap().header.difficulty)
        .collect();
    // The slow blocks lowered the difficulty (block `fork_height + 1` has the
    // same difficulty on both branches; the rival's second block does not
    // fall).
    assert!(diffs[2] < diffs[1] && diffs[3] < diffs[2], "{diffs:?}");

    // Spend the coinbase that matures exactly at `old_next`.
    let created = old_next - COINBASE_MATURITY;
    let plan = plan_where(
        &m,
        &miner.keys,
        |o| o.coinbase && o.height == created,
        &mut rng,
    );
    let tx = Transaction::from(pay(&m, &miner.keys, &alice, plan, &mut rng));
    m.submit_tx(tx.clone()).unwrap();
    let mut ext_pool = Mempool::new();
    ext_pool
        .add(tx.clone(), m.state(), old_next, m.rules(), Origin::Peer)
        .unwrap();
    let mut full_pool = Mempool::new();
    full_pool
        .add(tx.clone(), m.state(), old_next, m.rules(), Origin::Peer)
        .unwrap();

    rival.mine_on(&mut m, fork_parent, 3, Some(1));
    assert_eq!(
        m.height(),
        fork_height + 3,
        "the 3-block branch must win (difficulties {diffs:?})"
    );
    assert_eq!(m.deepest_reorg(), 4);
    let next = m.height() + 1;
    assert!(next < created + COINBASE_MATURITY);

    assert_eq!(revalidate_after_extension(&tx, m.state(), next), Ok(()));
    ext_pool.revalidate(m.state(), next, m.rules(), false);
    assert!(ext_pool.contains(&tx.hash()));
    let err = validate_mempool_tx(&tx, m.state(), next, m.rules()).unwrap_err();
    match err {
        TxError::RingMemberTooYoung { input: 0, index } => {
            // The spent coinbase (or a decoy from the same block).
            assert_eq!(m.state().output(index).unwrap().height, created);
        }
        e => panic!("expected RingMemberTooYoung, got {e:?}"),
    }
    let verified = full_pool.full_validations();
    let r = full_pool.revalidate(m.state(), next, m.rules(), true);
    assert!(!full_pool.contains(&tx.hash()));
    assert_eq!((r.invalid, r.ring_changed), (1, 0), "{r:?}");
    assert_eq!(full_pool.full_validations(), verified);
    assert!(!m.mempool().contains(&tx.hash()));
}

/// W2-12 item 2 through the manager: a reorganization returning a mined
/// transfer pools it again without verifying it (`full_validations`
/// unchanged). Needs the manager to capture returned transactions before it
/// undoes their block (`Returned::capture`) and to call
/// `Mempool::update_after_chain_change`: the call-site change reported to the
/// chain-manager owner (W2-34b); until then the manager re-admits with
/// `Mempool::readmit`, which validates in full, and this test fails.
#[test]
fn a_reorganization_returning_a_transfer_readmits_it_unverified() {
    let mut m = open();
    let mut miner = Miner::new(341);
    let mut rival = Miner::new(342);
    let mut rng = ChaCha20Rng::seed_from_u64(1_341);
    let (alice, _) = WalletKeys::generate(&mut rng);
    miner.mine_tip(&mut m, 80);
    let plan = plan_where(&m, &miner.keys, |o| o.height == 1, &mut rng);
    let tx = Transaction::from(pay(&m, &miner.keys, &alice, plan, &mut rng));
    m.submit_tx(tx.clone()).unwrap();
    let fork_parent = m.tip_id();
    let t = m.template();
    assert_eq!(t.txs.len(), 1);
    let blk = miner.build(&t, t.txs.clone(), None);
    let now = blk.header.timestamp;
    m.submit_block(blk, now).unwrap();
    assert!(m.mempool().is_empty());
    let verified = m.mempool().full_validations();
    rival.mine_on(&mut m, fork_parent, 2, None);
    assert_eq!(m.deepest_reorg(), 1);
    assert!(m.mempool().contains(&tx.hash()), "returned to the pool");
    assert_eq!(m.mempool().full_validations(), verified, "nothing verified");
}
