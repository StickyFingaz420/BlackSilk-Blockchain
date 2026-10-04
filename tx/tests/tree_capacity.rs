//! PX tree capacity (I3, with 21-D; docs/reviews/v3-consensus-changes.md
//! #tree-capacity): a block whose PX output commitments would take the
//! commitment tree past `CAPACITY = 2^32` leaves is invalid
//! (`BlockError::PxTreeFull`), a PX transaction that no longer fits is
//! refused by the mempool (contextual `TxError::PxTreeFull`), and applying a
//! validated block never fails.
//!
//! A tree near capacity cannot be reached by applying blocks in a test, so
//! the chain starts from a test-only PX state of equal leaves
//! (`State::with_uniform_tree_for_tests`, the `test-hooks` feature of
//! `blacksilk-px`, enabled for these tests only).

mod common;

use blacksilk_px::state::{State as PxState, StateError};
use blacksilk_px::tree::CAPACITY;
use blacksilk_px_core::Digest;
use blacksilk_tx::params::PX_STANDARD_FEE;
use blacksilk_tx::px::PxTx;
use blacksilk_tx::state::{ApplyError, MemoryChain};
use blacksilk_tx::types::Transaction;
use blacksilk_tx::validate::{
    revalidate_after_extension, validate_block_transactions_cached, validate_px_without_proof,
    BlockError, ChainView, TxError,
};
use common::*;
use rand_chacha::rand_core::RngCore;

const LEAF: Digest = [7, 7, 7, 7, 7, 7, 7, 7];
const POOL: u128 = 1 << 100;

/// A chain whose PX tree has `free` leaves left, with a first (empty) block
/// applied.
fn near_full(seed: u64, free: u64) -> TestNet {
    let mut net = TestNet::new(seed, 0);
    net.chain = MemoryChain::with_px_state(PxState::with_uniform_tree_for_tests(
        CAPACITY - free,
        LEAF,
        POOL,
    ));
    net.mine(vec![], &mut []).unwrap();
    net
}

/// A PX transaction without v1 inputs, anchored at the current root, that
/// every rule but the proof accepts: the fee is paid out of the pool
/// (`bridge_out = fee`). `tag` makes its nullifiers and commitments unique.
fn px(net: &TestNet, tag: u32) -> PxTx {
    PxTx {
        inputs: vec![],
        outputs: vec![],
        payouts: vec![],
        fee: PX_STANDARD_FEE,
        bridge_in: 0,
        bridge_out: PX_STANDARD_FEE,
        window: Default::default(),
        anchor: net.chain.px().root(),
        nullifiers: [[tag, 1, 0, 0, 0, 0, 0, 0], [tag, 2, 0, 0, 0, 0, 0, 0]],
        commitments: [[tag, 3, 0, 0, 0, 0, 0, 0], [tag, 4, 0, 0, 0, 0, 0, 0]],
        ciphertexts: [px_ciphertext(), px_ciphertext()],
        functions: vec![],
        pseudo_outs: vec![],
        range_proof: None,
        signatures: vec![],
        proof: vec![],
    }
}

/// The block body `coinbase ‖ pxs`, with its context.
fn body(net: &mut TestNet, pxs: &[PxTx]) -> Vec<Transaction> {
    let fees = pxs.len() as u64 * PX_STANDARD_FEE;
    let mut txs = vec![net.coinbase(fees)];
    txs.extend(pxs.iter().map(|t| Transaction::Px(Box::new(t.clone()))));
    txs
}

/// Validates a block of `pxs` (the proofs vouched for: PX5 is not what is
/// tested here) and, if valid, applies it.
fn submit(net: &mut TestNet, pxs: &[PxTx]) -> Result<(), BlockError> {
    let txs = body(net, pxs);
    validate(net, &txs)?;
    net.chain
        .apply_block(&txs)
        .expect("a validated block applies");
    Ok(())
}

fn validate(net: &mut TestNet, txs: &[Transaction]) -> Result<(), BlockError> {
    let ctx = net.context(txs);
    let rules = net.rules;
    validate_block_transactions_cached(txs, &ctx, &net.chain, &rules, &mut net.rng, &|_| true)
}

/// Demonstration (run first with the rule disabled): with 4 leaves left, a
/// block of 3 PX transactions (6 leaves) passed validation, and applying it
/// then failed (before this change: panicked in `MemoryChain::apply_block`,
/// the same panic on every node). Now it is `PxTreeFull`, before any
/// cryptography. 2 transactions fill the tree exactly, and the root after
/// them is the full tree's (21-D), not the empty tree's.
#[test]
fn a_block_past_capacity_is_invalid_and_one_filling_it_exactly_is_valid() {
    let mut net = near_full(81, 4);
    assert_eq!(net.chain.px_tree_size(), CAPACITY - 4);
    let over = [px(&net, 1), px(&net, 2), px(&net, 3)];
    assert_eq!(
        submit(&mut net, &over),
        Err(BlockError::PxTreeFull { leaves: 6, free: 4 })
    );
    let exact = [px(&net, 1), px(&net, 2)];
    assert_eq!(submit(&mut net, &exact), Ok(()));
    assert_eq!(net.chain.px_tree_size(), CAPACITY);
    assert_eq!(net.chain.px().free_leaves(), 0);
    let empty_root = PxState::new().root();
    assert_ne!(net.chain.px().root(), empty_root);
    // Full: no leaf more, in any block; blocks without PX still connect.
    let one = [px(&net, 5)];
    assert_eq!(
        submit(&mut net, &one),
        Err(BlockError::PxTreeFull { leaves: 2, free: 0 })
    );
    assert_eq!(submit(&mut net, &[]), Ok(()));
}

/// The boundaries one leaf-pair at a time: with `free` leaves left, `n`
/// transactions (2n leaves) are valid iff `2n ≤ free`.
#[test]
fn the_boundary_is_exact_for_every_small_free_count() {
    for free in 0..=6u64 {
        for n in 0..=3u32 {
            let mut net = near_full(90 + free, free);
            let pxs: Vec<PxTx> = (0..n).map(|i| px(&net, 10 + i)).collect();
            let txs = body(&mut net, &pxs);
            let r = validate(&mut net, &txs);
            let leaves = 2 * n as u64;
            if leaves <= free {
                assert_eq!(r, Ok(()), "free {free}, {n} transactions");
            } else {
                assert_eq!(
                    r,
                    Err(BlockError::PxTreeFull { leaves, free }),
                    "free {free}, {n} transactions"
                );
            }
        }
    }
}

/// The mempool and revalidation paths: a PX transaction that no longer fits
/// the tree is refused with the contextual `PxTreeFull` (the tree may have
/// room on another branch), after every stateless rule.
#[test]
fn the_mempool_refuses_a_px_transaction_the_tree_cannot_take() {
    let net = near_full(82, 1);
    let t = px(&net, 1);
    let h = net.height();
    assert_eq!(
        validate_px_without_proof(&t, &net.chain, h, &net.rules),
        Err(TxError::PxTreeFull)
    );
    assert!(!TxError::PxTreeFull.is_stateless());
    assert_eq!(
        revalidate_after_extension(&Transaction::Px(Box::new(t.clone())), &net.chain, h),
        Err(TxError::PxTreeFull)
    );
    // A stateless fault is still reported first.
    let mut bad = t.clone();
    bad.fee += 1;
    assert!(matches!(
        validate_px_without_proof(&bad, &net.chain, h, &net.rules),
        Err(TxError::PxFeeNotStandard { .. })
    ));
    // With room for it, the capacity rule passes.
    let net = near_full(83, 2);
    let t = px(&net, 1);
    assert_eq!(
        validate_px_without_proof(&t, &net.chain, net.height(), &net.rules),
        Ok(())
    );
}

/// Validation is a superset of every failure of `apply_block`: over random
/// blocks near capacity, a valid block always applies, and a block refused
/// for capacity would fail to apply (unvalidated) with the tree's own
/// `TreeFull`, changing nothing.
#[test]
fn validation_implies_a_successful_apply_near_capacity() {
    let mut r = rng(0xCA9);
    let (mut valid, mut full) = (0, 0);
    for case in 0..60 {
        let free = r.next_u64() % 9;
        let mut net = near_full(1_000 + case, free);
        let n = (r.next_u64() % 5) as u32;
        let pxs: Vec<PxTx> = (0..n).map(|i| px(&net, 100 + i)).collect();
        let txs = body(&mut net, &pxs);
        let size = net.chain.px_tree_size();
        match validate(&mut net, &txs) {
            Ok(()) => {
                net.chain.apply_block(&txs).expect("valid ⇒ applies");
                assert_eq!(net.chain.px_tree_size(), size + 2 * n as u64);
                valid += 1;
            }
            Err(BlockError::PxTreeFull { .. }) => {
                let root = net.chain.px().root();
                assert_eq!(
                    net.chain.apply_block(&txs),
                    Err(ApplyError::Px(StateError::TreeFull))
                );
                assert_eq!(net.chain.px_tree_size(), size, "unchanged");
                assert_eq!(net.chain.px().root(), root);
                full += 1;
            }
            Err(e) => panic!("case {case}: {e:?}"),
        }
    }
    assert!(valid > 10 && full > 10, "{valid} {full}");
}

/// Reorganization and restart at capacity: the block that fills the tree
/// undoes exactly (the tree has room again, the old root is back) and
/// re-applies to the same full root; a second node started from the same
/// state and fed the same blocks reaches the same state.
#[test]
fn undo_and_replay_are_exact_at_capacity() {
    let mut net = near_full(84, 2);
    let before = (net.chain.px().root(), net.chain.px_tree_size());
    let pxs = [px(&net, 1)];
    let txs = body(&mut net, &pxs);
    validate(&mut net, &txs).unwrap();
    net.chain.apply_block(&txs).unwrap();
    let full = net.chain.px().root();
    assert_eq!(net.chain.px().free_leaves(), 0);
    // Reorganization: disconnect, then connect the same block again.
    assert!(net.chain.undo_block());
    assert_eq!((net.chain.px().root(), net.chain.px_tree_size()), before);
    assert!(net.chain.px_is_recent_root(&before.0));
    validate(&mut net, &txs).unwrap();
    net.chain.apply_block(&txs).unwrap();
    assert_eq!(net.chain.px().root(), full);
    // Restart: a node rebuilding from the same base and the same blocks.
    let mut replay = MemoryChain::with_px_state(PxState::with_uniform_tree_for_tests(
        CAPACITY - 2,
        LEAF,
        POOL,
    ));
    replay.apply_block(&[]).unwrap();
    replay.apply_block(&txs).unwrap();
    assert_eq!(replay.px().root(), full);
    assert_eq!(replay.px_tree_size(), CAPACITY);
    assert_eq!(
        replay.px_records(0, u64::MAX),
        net.chain.px_records(0, u64::MAX)
    );
    let last = replay.px_records(0, u64::MAX).last().unwrap().position;
    assert_eq!(last, CAPACITY - 1, "records count one leaf per commitment");
}
