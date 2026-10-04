//! Byte-equality guard for the two copies of the v1 input/output/CLSAG codec
//! (inventory-A D1, 2026-10-04).
//!
//! `Transfer` writes its inputs, outputs, pseudo-outputs, range proof and
//! CLSAGs inline (`tx/src/types.rs`); `PxDeploy` writes the same parts with
//! its own helpers (`tx/src/px.rs`). The two must agree byte for byte:
//! `Transaction::hash` of a deploy hashes `PxDeploy::base_bytes` and
//! `PxDeploy::prunable_bytes`, while `PxDeploy::signature_message` hashes
//! `as_transfer().base_hash()` and its range-proof bytes. A one-sided edit of
//! either copy would split the tx id from the signed message. Nothing pinned
//! the equality before this test; it changes no code.

mod common;

use blacksilk_tx::builder::Payment;
use blacksilk_tx::params::{KIND_PX_DEPLOY, KIND_TRANSFER, TX_VERSION};
use blacksilk_tx::px::{PxDeploy, Registration};
use blacksilk_tx::px_builder::build_deploy;
use blacksilk_tx::types::Transaction;
use blacksilk_tx::Transfer;
use common::*;

const VAULT_ELF: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../px/vault.elf"));

fn vault_registration() -> Registration {
    Registration {
        elf: VAULT_ELF.to_vec(),
        budget: blacksilk_px::vault::BUDGET,
        abi: blacksilk_tx::px::ABI_VERSION,
        out_words: 1,
    }
}

/// The deploy's prefix is the transfer prefix of its v1 part with the kind
/// byte replaced, followed by the payload (salt first).
fn assert_prefix_twins(d: &PxDeploy, t: &Transfer) {
    assert!(TX_VERSION < 0x80, "the version varint is one byte");
    let dp = d.prefix_bytes();
    let tp = t.prefix_bytes();
    assert_eq!(dp[0], TX_VERSION as u8);
    assert_eq!(tp[0], TX_VERSION as u8);
    assert_eq!(dp[1], KIND_PX_DEPLOY);
    assert_eq!(tp[1], KIND_TRANSFER);
    assert!(dp.len() > tp.len());
    assert_eq!(
        dp[2..tp.len()],
        tp[2..],
        "inputs, outputs and fee encode identically"
    );
    assert_eq!(
        dp[tp.len()..tp.len() + 32],
        d.salt,
        "the payload follows the fee"
    );
}

/// Every shared part of the two writers, and both decoders.
fn assert_twins(d: &PxDeploy) {
    let t = d.as_transfer();
    assert_eq!(d.base_bytes(), t.base_bytes(), "pseudo-outputs");
    assert_eq!(
        d.prunable_bytes(),
        t.prunable_bytes(),
        "range proof and CLSAGs"
    );
    assert_prefix_twins(d, &t);

    // Each encoding decodes through its own reader to the same parts.
    let dt = Transaction::PxDeploy(Box::new(d.clone()));
    let tt = Transaction::from(t.clone());
    let Transaction::PxDeploy(d2) = Transaction::decode(&dt.encode()).expect("deploy decodes")
    else {
        panic!("a deploy decodes as a deploy")
    };
    let Transaction::Transfer(t2) = Transaction::decode(&tt.encode()).expect("transfer decodes")
    else {
        panic!("a transfer decodes as a transfer")
    };
    assert_eq!(d2.as_transfer().encode_parts(), t2.encode_parts());
    assert_eq!(t2.encode_parts(), t.encode_parts());
}

trait Parts {
    fn encode_parts(&self) -> (Vec<u8>, Vec<u8>, Vec<u8>);
}

impl Parts for Transfer {
    fn encode_parts(&self) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        (
            self.prefix_bytes(),
            self.base_bytes(),
            self.prunable_bytes(),
        )
    }
}

/// A real signed deploy (one input, payment plus change).
#[test]
fn signed_deploy_shares_the_transfer_codec_bytes() {
    let mut net = TestNet::new(91, 80);
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
        [9; 32],
        vec![vault_registration()],
        &rules,
        &mut net.rng,
    )
    .expect("deploy builds");
    assert_twins(&d);
}

/// The parts of a real multi-input transfer, written through the deploy's
/// helpers, give the transfer's own bytes back (the deploy is not signed:
/// this is a codec check only).
#[test]
fn multi_input_transfer_parts_round_trip_through_the_deploy_writers() {
    let mut net = TestNet::new(92, 80);
    let miner = net.miner_clone();
    // More than one coinbase reward: at least two inputs.
    let t = net.pay(&miner, &[(miner.primary(), REWARD + REWARD / 2)]);
    assert!(t.inputs.len() >= 2, "{} inputs", t.inputs.len());
    let d = PxDeploy {
        inputs: t.inputs.clone(),
        outputs: t.outputs.clone(),
        fee: t.fee,
        salt: [7; 32],
        programs: vec![vault_registration()],
        pseudo_outs: t.pseudo_outs.clone(),
        range_proof: t.range_proof.clone(),
        signatures: t.signatures.clone(),
    };
    assert_eq!(d.as_transfer().encode_parts(), t.encode_parts());
    assert_twins(&d);
}
