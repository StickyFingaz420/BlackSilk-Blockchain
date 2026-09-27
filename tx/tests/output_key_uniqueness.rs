//! One-time-key uniqueness under D8 option B (docs/transactions.md §8,
//! docs/reviews/v3-consensus-changes.md §1).
//!
//! - **Within a transaction**, one-time keys are distinct for every kind:
//!   transfers and deploys (T6, the strict sort), coinbases (B7, the strict
//!   sort), PX transactions (the strict sort of each list, and
//!   `PxDuplicateOutputKey` across the hidden outputs and the payouts). These
//!   are stateless rules; the tests below check them against chain states that
//!   hold none of the keys, so they do not rely on any chain-wide rule.
//! - **Across transactions** (in one block, or against the chain), a repeated
//!   one-time key is valid: the former rule C4 is removed. A randomized
//!   property test draws blocks from a small key space so that repeats are
//!   frequent, and checks that a block is valid iff no transaction repeats a
//!   key within itself, and that applying and undoing such blocks keeps every
//!   copy as its own output.
//!
//! The randomized test uses a seeded ChaCha stream, not proptest (not yet a
//! dependency of this crate).

mod common;

use blacksilk_crypto::bulletproofs_plus as bpp;
use blacksilk_crypto::clsag::{self, RingMember};
use blacksilk_crypto::commitment::commit;
use blacksilk_crypto::{Point, RistrettoPoint, Scalar};
use blacksilk_px::delivery::CIPHERTEXT_BYTES;
use blacksilk_tx::builder::{standard_fee, Decoy, Payment};
use blacksilk_tx::params::{PX_STANDARD_FEE, RING_SIZE};
use blacksilk_tx::px::{check_px_structure, PxTx, Registration};
use blacksilk_tx::px_builder::build_deploy;
use blacksilk_tx::scan::OwnedOutput;
use blacksilk_tx::types::{CoinbaseOutput, Input, Output, Transaction, Transfer};
use blacksilk_tx::validate::{
    validate_block_transactions, validate_block_transactions_cached, validate_deploy,
    validate_transfer, BlockError, ChainView, TxError,
};
use common::*;
use rand_chacha::rand_core::RngCore;
use std::collections::HashMap;

fn random_scalar(r: &mut ChaCha20Rng) -> Scalar {
    let mut wide = [0u8; 64];
    r.fill_bytes(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn random_point(r: &mut ChaCha20Rng) -> Point {
    Point::from_point(RistrettoPoint::mul_base(&random_scalar(r)))
}

/// A one-input transfer from `from`'s output `real` whose outputs carry the
/// one-time keys `keys` (sorted; repeats allowed, to build invalid ones), all
/// value to the first. Balanced, with a valid range proof and CLSAG.
fn forge(net: &mut TestNet, from: &Wallet, real: &OwnedOutput, keys: &[Point]) -> Transfer {
    let fee = standard_fee(1, keys.len(), &net.rules);
    let plan = net.plan(real);
    let real = &plan.real;
    let p = from
        .keys
        .one_time_secret(real.subaddress, &real.output_key_offset);
    let key_image = clsag::key_image(&p, &real.key.one_time_key);
    let mut keys = keys.to_vec();
    keys.sort();
    let r = &mut net.rng;
    let amounts: Vec<u64> = (0..keys.len())
        .map(|j| if j == 0 { real.amount - fee } else { 0 })
        .collect();
    let masks: Vec<Scalar> = keys.iter().map(|_| random_scalar(r)).collect();
    let (range_proof, commitments) = bpp::prove(&amounts, &masks, r).unwrap();
    let pseudo_mask: Scalar = masks.iter().sum();
    let pseudo_out = Point::from_point(commit(real.amount, &pseudo_mask));
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
        outputs: keys
            .iter()
            .zip(&commitments)
            .map(|(k, c)| Output {
                one_time_key: *k,
                ephemeral: random_point(r),
                view_tag: 0,
                commitment: *c,
                enc_amount: [0; 8],
                enc_anchor: [0; 16],
            })
            .collect(),
        fee,
        pseudo_outs: vec![pseudo_out],
        range_proof,
        signatures: vec![],
    };
    let message = tx.signature_message(net.rules.domain());
    let z = real.mask - pseudo_mask;
    let (sig, _) = clsag::sign(&message, &ring, &pseudo_out, pos, &p, &z, r).unwrap();
    tx.signatures.push(sig);
    tx
}

/// How many outputs on `net`'s chain carry `key`.
fn copies_on_chain(net: &TestNet, key: &Point) -> usize {
    (0..net.chain.output_count())
        .filter(|&i| net.chain.output(i).unwrap().key.one_time_key == *key)
        .count()
}

// ------------------------------------------------------------ within a transaction

/// Transfers: a repeated key breaks the strict sort (T6), a stateless error
/// raised before any chain query, in the mempool path and in blocks.
#[test]
fn a_transfer_repeating_a_key_is_invalid() {
    let mut net = TestNet::new(1, 80);
    let miner = net.miner_clone();
    let real = miner.spendable(net.height())[0].clone();
    let k = random_point(&mut net.rng);
    let bad = forge(&mut net, &miner, &real, &[k, k]);
    let err = validate_transfer(&bad, &net.chain, net.height(), &net.rules).unwrap_err();
    assert_eq!(err, TxError::OutputsNotSorted);
    assert!(err.is_stateless());
    // The same spend with distinct keys is valid: only the repeat is at fault.
    let other = random_point(&mut net.rng);
    let good = forge(&mut net, &miner, &real, &[k, other]);
    assert_eq!(
        validate_transfer(&good, &net.chain, net.height(), &net.rules),
        Ok(())
    );
    let txs = vec![net.coinbase(bad.fee), Transaction::from(bad)];
    let ctx = net.context(&txs);
    assert_eq!(
        validate_block_transactions(&txs, &ctx, &net.chain, &net.rules, &mut rng(1)),
        Err(BlockError::Tx {
            index: 1,
            error: TxError::OutputsNotSorted
        })
    );
}

/// Deploys: their v1 part follows the transfer rules (T6).
#[test]
fn a_deploy_repeating_a_key_is_invalid() {
    let mut net = TestNet::new(2, 80);
    let miner = net.miner_clone();
    let real = miner.spendable(net.height())[0].clone();
    let plan = net.plan(&real);
    let rules = net.rules;
    let d = build_deploy(
        &miner.keys,
        vec![plan],
        &[Payment {
            address: miner.primary(),
            amount: 1,
        }],
        &miner.primary(),
        [3; 32],
        vec![Registration {
            elf: blacksilk_px::vault::VAULT_ELF.to_vec(),
            budget: blacksilk_px::vault::BUDGET,
        }],
        &rules,
        &mut net.rng,
    )
    .unwrap();
    assert_eq!(
        validate_deploy(&d, &net.chain, net.height(), &rules),
        Ok(())
    );
    let mut bad = d.clone();
    bad.outputs[1].one_time_key = bad.outputs[0].one_time_key;
    let err = validate_deploy(&bad, &net.chain, net.height(), &rules).unwrap_err();
    assert_eq!(err, TxError::OutputsNotSorted);
    assert!(err.is_stateless());
}

/// A PX transaction without v1 inputs whose payouts carry `payouts` keys and
/// amounts (every other rule but the proof passes under an open PX view).
fn px_with_payouts(net: &mut TestNet, payouts: &[Point]) -> PxTx {
    let Transaction::Coinbase(c) = net.coinbase(0) else {
        unreachable!()
    };
    let payouts: Vec<CoinbaseOutput> = payouts
        .iter()
        .map(|k| CoinbaseOutput {
            one_time_key: *k,
            amount: 10,
            ..c.outputs[0].clone()
        })
        .collect();
    let total = 10 * payouts.len() as u64;
    PxTx {
        inputs: vec![],
        outputs: vec![],
        payouts,
        fee: PX_STANDARD_FEE,
        bridge_in: 0,
        bridge_out: PX_STANDARD_FEE + total,
        anchor: [7; 8],
        nullifiers: [[1; 8], [2; 8]],
        commitments: [[3; 8], [4; 8]],
        ciphertexts: [vec![0; CIPHERTEXT_BYTES], vec![0; CIPHERTEXT_BYTES]],
        functions: vec![],
        pseudo_outs: vec![],
        range_proof: None,
        signatures: vec![],
        proof: vec![],
    }
}

/// PX: a key repeated within the payouts (the strict sort) or between the
/// hidden outputs and the payouts (`PxDuplicateOutputKey`, which under D8
/// option B is the only rule rejecting that repeat) is a stateless error.
#[test]
fn a_px_transaction_repeating_a_key_is_invalid() {
    let mut net = TestNet::new(3, 80);
    let (a, b) = (random_point(&mut net.rng), random_point(&mut net.rng));
    let (a, b) = (a.min(b), a.max(b));
    assert_eq!(
        check_px_structure(&px_with_payouts(&mut net, &[a, b])),
        Ok(())
    );
    let err = check_px_structure(&px_with_payouts(&mut net, &[a, a])).unwrap_err();
    assert_eq!(err, TxError::OutputsNotSorted);
    assert!(err.is_stateless());

    // A hidden output and a payout sharing a key: the v1 part of a valid
    // transfer (so a real hidden output) and a payout with its key.
    let miner = net.miner_clone();
    let alice = Wallet::new(&mut rng(300));
    let t = net.pay(&miner, &[(alice.primary(), 1_000)]);
    let mut px = px_with_payouts(&mut net, &[t.outputs[0].one_time_key]);
    px.inputs = t.inputs.clone();
    px.outputs = t.outputs.clone();
    px.pseudo_outs = t.pseudo_outs.clone();
    px.range_proof = Some(t.range_proof.clone());
    px.signatures = t.signatures.clone();
    px.bridge_in = t.fee;
    let err = check_px_structure(&px).unwrap_err();
    assert_eq!(
        err,
        TxError::PxDuplicateOutputKey {
            output: t.outputs.len()
        }
    );
    assert!(err.is_stateless());
    // In a block too, whatever the state (the PX proof is not reached).
    let tx = Transaction::Px(Box::new(px));
    let txs = vec![net.coinbase(tx.fee()), tx];
    let ctx = net.context(&txs);
    assert_eq!(
        validate_block_transactions_cached(
            &txs,
            &ctx,
            &net.chain,
            &net.rules,
            &mut rng(2),
            &|_| true
        ),
        Err(BlockError::Tx {
            index: 1,
            error: TxError::PxDuplicateOutputKey {
                output: t.outputs.len()
            }
        })
    );
}

// ------------------------------------------------------------ across transactions

/// The injected fault of a randomized case, if any.
#[derive(Clone, Copy, Debug)]
enum Fault {
    /// Transaction `i` (0-based among the non-coinbase ones) repeats a key.
    Tx(usize),
    /// The coinbase repeats a key.
    Coinbase,
}

/// Randomized property: over blocks whose one-time keys are drawn from a
/// space of five keys (so that repeats across transactions, and with the
/// coinbase, are frequent), a block is valid iff no transaction repeats a key
/// within itself; an invalid one fails with the stateless sort error of that
/// transaction. Every valid block is applied, undone and applied again, and
/// every copy of a key stays its own output.
#[test]
fn property_repeats_across_transactions_are_valid_and_within_one_are_not() {
    let mut net = TestNet::new(21, 100);
    let mut r = rng(0xD8);
    let space: Vec<Point> = (0..5).map(|_| random_point(&mut r)).collect();
    let mut model: HashMap<Point, usize> = space.iter().map(|k| (*k, 0)).collect();
    let (mut valid, mut invalid, mut cross) = (0, 0, 0);
    for case in 0..24 {
        let height = net.height();
        let n = 1 + (r.next_u64() % 3) as usize;
        let spendable: Vec<OwnedOutput> = net
            .miner
            .spendable(height)
            .into_iter()
            .take(n)
            .cloned()
            .collect();
        assert_eq!(spendable.len(), n, "case {case}: enough mature outputs");
        let fault = match case % 4 {
            0 => Some(Fault::Tx((r.next_u64() % n as u64) as usize)),
            1 if case % 8 == 1 => Some(Fault::Coinbase),
            _ => None,
        };
        let miner = net.miner_clone();
        let pick = |r: &mut ChaCha20Rng| space[(r.next_u64() % 5) as usize];
        let mut transfers = Vec::new();
        for (i, real) in spendable.iter().enumerate() {
            let a = pick(&mut r);
            let keys = if matches!(fault, Some(Fault::Tx(j)) if j == i) {
                vec![a, a]
            } else {
                let mut b = pick(&mut r);
                while b == a {
                    b = pick(&mut r);
                }
                vec![a, b]
            };
            transfers.push(forge(&mut net, &miner, real, &keys));
        }
        let fees: u64 = transfers.iter().map(|t| t.fee).sum();
        let Transaction::Coinbase(mut cb) = net.coinbase(fees) else {
            unreachable!()
        };
        match fault {
            Some(Fault::Coinbase) => {
                let mut second = cb.outputs[0].clone();
                second.amount = 1;
                cb.outputs[0].amount -= 1;
                cb.outputs.push(second);
            }
            _ if r.next_u64().is_multiple_of(2) => cb.outputs[0].one_time_key = pick(&mut r),
            _ => {}
        }
        let mut txs = vec![Transaction::Coinbase(cb)];
        txs.extend(transfers.into_iter().map(Transaction::from));
        let ctx = net.context(&txs);
        let got = validate_block_transactions(&txs, &ctx, &net.chain, &net.rules, &mut rng(9));
        match fault {
            Some(Fault::Tx(i)) => {
                assert_eq!(
                    got,
                    Err(BlockError::Tx {
                        index: i + 1,
                        error: TxError::OutputsNotSorted
                    }),
                    "case {case}"
                );
                invalid += 1;
            }
            Some(Fault::Coinbase) => {
                assert_eq!(
                    got,
                    Err(BlockError::CoinbaseOutputsNotSorted),
                    "case {case}"
                );
                invalid += 1;
            }
            None => {
                assert_eq!(got, Ok(()), "case {case}");
                valid += 1;
                // Repeats across the block's transactions (or with the chain).
                let keys: Vec<Point> = txs
                    .iter()
                    .flat_map(|t| t.output_keys())
                    .map(|k| k.one_time_key)
                    .collect();
                if keys.iter().any(|k| model.get(k).is_some_and(|&n| n > 0))
                    || (1..keys.len()).any(|i| keys[..i].contains(&keys[i]))
                {
                    cross += 1;
                }
                let before = net.chain.output_count();
                net.submit(txs.clone(), &mut []).unwrap();
                for k in &keys {
                    if let Some(n) = model.get_mut(k) {
                        *n += 1;
                    }
                }
                for k in &space {
                    assert_eq!(copies_on_chain(&net, k), model[k], "case {case}");
                }
                // Undo: the block's outputs and key images disappear, the
                // earlier copies stay.
                assert!(net.chain.undo_block());
                assert_eq!(net.chain.output_count(), before);
                for t in &txs[1..] {
                    assert!(!net.chain.is_key_image_spent(&t.key_images()[0]));
                }
                for k in &space {
                    let in_block = keys.iter().filter(|x| *x == k).count();
                    assert_eq!(copies_on_chain(&net, k), model[k] - in_block);
                }
                // And again.
                net.chain.apply_block(&txs).unwrap();
                for k in &space {
                    assert_eq!(copies_on_chain(&net, k), model[k]);
                }
            }
        }
    }
    println!("{valid} valid, {invalid} invalid, {cross} with cross-transaction repeats");
    assert!(
        valid >= 12 && invalid >= 6,
        "{valid} valid, {invalid} invalid"
    );
    assert!(cross >= 8, "{cross}");
    assert!(model.values().any(|&n| n >= 3), "{model:?}");
}
