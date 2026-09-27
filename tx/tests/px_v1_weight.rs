//! R12-2 (a′): the v1 part of PX and deploy transactions counts toward the
//! block weight limit (B6), `max_weight(n_in, n_out)` when `n_in > 0`; their
//! encoded bytes stay in the PX byte budget
//! (docs/reviews/v3-consensus-changes.md#r12-2).

mod common;

use blacksilk_crypto::clsag::{Clsag, RING_SIZE};
use blacksilk_crypto::{Point, RistrettoPoint, Scalar};
use blacksilk_tx::builder::Payment;
use blacksilk_tx::params::*;
use blacksilk_tx::px::{PxDeploy, PxTx, Registration};
use blacksilk_tx::px_builder::build_deploy;
use blacksilk_tx::types::{Input, Transaction};
use blacksilk_tx::validate::{validate_block_transactions, BlockError};
use common::*;

fn vault() -> Registration {
    Registration {
        elf: blacksilk_px::vault::VAULT_ELF.to_vec(),
        budget: blacksilk_px::vault::BUDGET,
    }
}

/// A valid, signed deploy of the vault paid from the miner's first `n`
/// spendable outputs, with one payment (two outputs).
fn deploy(net: &mut TestNet, n: usize, salt: u8) -> PxDeploy {
    let miner = net.miner_clone();
    let spendable: Vec<_> = miner
        .spendable(net.height())
        .into_iter()
        .take(n)
        .cloned()
        .collect();
    assert_eq!(spendable.len(), n, "enough mature outputs");
    let plans = spendable.iter().map(|o| net.plan(o)).collect();
    let rules = net.rules;
    build_deploy(
        &miner.keys,
        plans,
        &[Payment {
            address: miner.primary(),
            amount: 1,
        }],
        &miner.primary(),
        [salt; 32],
        vec![vault()],
        &rules,
        &mut net.rng,
    )
    .expect("deploy builds")
}

/// Demonstration (written before the rule): a block whose only weight
/// beyond its coinbase is the v1 part of a valid deploy (1 input, one CLSAG)
/// was accepted under a weight limit that part exceeds: PX and deploy
/// transactions weighed 0. Under the rule it is `WeightExceeded`.
#[test]
fn a_block_over_the_weight_limit_through_a_deploys_v1_part_is_rejected() {
    let mut net = TestNet::new(71, 80);
    let d = deploy(&mut net, 1, 1);
    let fee = d.fee;
    let txs = vec![net.coinbase(fee), Transaction::PxDeploy(Box::new(d))];
    let ctx = net.context(&txs);
    let mut small = net.rules;
    // Room for the coinbase and 1 000 more: the deploy's v1 part (one input,
    // two outputs) does not fit.
    small.max_block_weight = txs[0].weight() + 1_000;
    let r = validate_block_transactions(&txs, &ctx, &net.chain, &small, &mut rng(0));
    assert!(
        matches!(r, Err(BlockError::WeightExceeded { .. })),
        "a deploy's CLSAG escaped the weight limit: {r:?}"
    );
    // Under the real limit the block is valid.
    assert_eq!(
        validate_block_transactions(&txs, &ctx, &net.chain, &net.rules, &mut rng(0)),
        Ok(())
    );
}

fn pt(n: u64) -> Point {
    Point::from_point(RistrettoPoint::mul_base(&Scalar::from(n + 1)))
}

/// A structurally valid PX transaction with `n` v1 inputs and no hidden
/// outputs (its signatures, balance and proof are not valid: B6 comes
/// before all of them).
fn px_with_inputs(n: usize) -> PxTx {
    let mut inputs: Vec<Input> = (0..n)
        .map(|i| Input {
            key_image: pt(1_000 + i as u64),
            ring: std::array::from_fn(|j| j as u64),
        })
        .collect();
    inputs.sort_by_key(|i| i.key_image);
    PxTx {
        inputs,
        outputs: vec![],
        payouts: vec![],
        fee: PX_STANDARD_FEE,
        bridge_in: 0,
        bridge_out: 0,
        anchor: [0; 8],
        nullifiers: [[1, 0, 0, 0, 0, 0, 0, 0], [2, 0, 0, 0, 0, 0, 0, 0]],
        commitments: [[3; 8], [4; 8]],
        ciphertexts: [vec![0; 8], vec![0; 8]],
        functions: vec![],
        pseudo_outs: vec![pt(7); n],
        range_proof: None,
        signatures: vec![
            Clsag {
                c0: Scalar::ZERO,
                s: [Scalar::ZERO; RING_SIZE],
                d: pt(8),
            };
            n
        ],
        proof: vec![],
    }
}

/// The same for PX transactions: 64 v1 inputs (64 CLSAGs) no longer ride
/// free in the PX byte budget. Before the rule this block passed B6 and
/// failed only later; now B6 rejects it before any cryptography.
#[test]
fn a_px_transactions_v1_inputs_count_toward_the_weight_limit() {
    let mut net = TestNet::new(72, 1);
    let px = Transaction::Px(Box::new(px_with_inputs(64)));
    let txs = vec![net.coinbase(PX_STANDARD_FEE), px];
    let ctx = net.context(&txs);
    let mut small = net.rules;
    small.max_block_weight = txs[0].weight() + 50_000;
    let r = validate_block_transactions(&txs, &ctx, &net.chain, &small, &mut rng(0));
    assert!(
        matches!(r, Err(BlockError::WeightExceeded { .. })),
        "64 CLSAGs escaped the weight limit: {r:?}"
    );
}

/// Boundary: a block exactly at the weight limit, with a deploy's v1 part
/// contributing, is valid; one unit lower it is `WeightExceeded`.
#[test]
fn the_weight_limit_is_exact_with_a_deploy_contributing() {
    let mut net = TestNet::new(73, 80);
    let d = deploy(&mut net, 2, 3);
    let fee = d.fee;
    let txs = vec![net.coinbase(fee), Transaction::PxDeploy(Box::new(d))];
    let total: u64 = txs.iter().map(Transaction::weight).sum();
    assert_eq!(txs[1].weight(), max_weight(2, 2));
    let ctx = net.context(&txs);
    let mut rules = net.rules;
    rules.max_block_weight = total;
    assert_eq!(
        validate_block_transactions(&txs, &ctx, &net.chain, &rules, &mut rng(0)),
        Ok(())
    );
    rules.max_block_weight = total - 1;
    assert_eq!(
        validate_block_transactions(&txs, &ctx, &net.chain, &rules, &mut rng(0)),
        Err(BlockError::WeightExceeded {
            weight: total as u128,
            max: total - 1
        })
    );
}

fn deploy_shape(n: usize, k: usize) -> PxDeploy {
    let p = px_with_inputs(n);
    PxDeploy {
        inputs: p.inputs,
        outputs: (0..k)
            .map(|j| blacksilk_tx::types::Output {
                one_time_key: pt(50 + j as u64),
                ephemeral: pt(60),
                view_tag: 0,
                commitment: pt(61),
                enc_amount: [0; 8],
                enc_anchor: [0; 16],
            })
            .collect(),
        fee: 0,
        salt: [0; 32],
        programs: vec![vault()],
        pseudo_outs: p.pseudo_outs,
        range_proof: blacksilk_crypto::bulletproofs_plus::BppProof {
            a: pt(1),
            a1: pt(1),
            b: pt(1),
            r1: Scalar::ZERO,
            s1: Scalar::ZERO,
            d1: Scalar::ZERO,
            l: vec![],
            r: vec![],
        },
        signatures: p.signatures,
    }
}

/// Golden weights (the `max_weight` rows of tx/tests/data/max_weight.txt,
/// from the independent script): PX 0-in 0, PX 1-in/0-out 841, PX
/// 64-in/16-out 57 439, deploy 1-in/2-out 1 723, deploy 64-in/2-out 52 123.
#[test]
fn px_and_deploy_weight_vectors() {
    let px = |n: usize, k: usize| {
        let mut t = px_with_inputs(n);
        t.outputs = deploy_shape(1, k).outputs;
        Transaction::Px(Box::new(t)).weight()
    };
    assert_eq!(px(0, 0), 0);
    assert_eq!(px(1, 0), 841);
    assert_eq!(px(64, 16), 57_439);
    let dep = |n, k| Transaction::PxDeploy(Box::new(deploy_shape(n, k))).weight();
    assert_eq!(dep(1, 2), 1_723);
    assert_eq!(dep(64, 2), 52_123);
    // The proof and the payload never weigh: only the v1 part's shape.
    let mut big = px_with_inputs(1);
    big.proof = vec![0; 1 << 20];
    assert_eq!(Transaction::Px(Box::new(big)).weight(), 841);
}

/// Every CLSAG is paid for in the weight meter: a transfer weighs at least
/// 656 per input (key image 32, 16 one-byte ring varints, pseudo-output 32,
/// CLSAG 576), a PX or deploy v1 part at least 800 per input, so a valid
/// block holds at most ⌊MAX_BLOCK_WEIGHT / 656⌋ = 914 v1 inputs of all kinds.
#[test]
fn every_clsag_is_paid_for_in_the_weight_meter() {
    for n in 1..=MAX_INPUTS {
        for k in 0..=MAX_OUTPUTS {
            assert!(max_weight(n, k) >= 800 * n as u64, "({n}, {k})");
        }
    }
    let mut net = TestNet::new(74, 80);
    let miner = net.miner_clone();
    let t = net.pay(&miner, &[(miner.primary(), 5)]);
    let n = t.inputs.len() as u64;
    assert!(Transaction::from(t).weight() >= 656 * n);
    assert_eq!(MAX_BLOCK_WEIGHT / 656, 914);
}

/// The PX fee stays uniform and covers the v1 part of any PX transaction
/// at the v1 rate: `FEE_PER_WEIGHT × max_weight(64, 16) ≤ PX_STANDARD_FEE`.
#[test]
fn the_px_fee_covers_the_largest_px_v1_part() {
    let largest = FEE_PER_WEIGHT * max_weight(MAX_INPUTS, MAX_OUTPUTS);
    assert_eq!(largest, 1_148_780);
    assert!(largest <= PX_STANDARD_FEE, "{largest} > {PX_STANDARD_FEE}");
}
