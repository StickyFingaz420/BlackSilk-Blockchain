//! End-to-end transaction tests: build, relay (encode/decode), validate, apply,
//! scan, spend again, reorganize.

mod common;

use blacksilk_tx::builder::standard_fee;
use blacksilk_tx::types::Transaction;
use blacksilk_tx::validate::{validate_mempool_tx, validate_transfer, TxError};
use blacksilk_tx::{BlockError, ChainView};
use common::*;

#[test]
fn payment_round_trip_between_wallets() {
    let mut net = TestNet::new(1, 80);
    let mut rng = rng(2);
    let mut alice = Wallet::new(&mut rng);
    let mut bob = Wallet::new(&mut rng);

    // Miner -> Alice (a subaddress in another account).
    let alice_sub = alice.address(1, 4);
    let tx = net.pay(&net.miner_clone(), &[(alice_sub, 5_000_000)]);
    let fee1 = tx.fee;
    let miner_before = net.miner.balance();
    net.mine(vec![tx], &mut [&mut alice]).unwrap();
    assert_eq!(alice.balance(), 5_000_000);
    assert_eq!(
        alice.owned[0].received.subaddress,
        blacksilk_crypto::keys::SubaddressIndex::new(1, 4)
    );
    // Miner: spent one coinbase, got change, plus the new block reward and fee.
    assert_eq!(
        net.miner.balance(),
        miner_before - 5_000_000 - fee1 as u128 + REWARD as u128 + fee1 as u128
    );

    // Alice cannot spend before the 10-block spendable age.
    assert!(alice.spendable(net.height()).is_empty());
    for _ in 0..10 {
        net.mine(vec![], &mut [&mut alice]).unwrap();
    }
    assert_eq!(alice.spendable(net.height()).len(), 1);

    // Alice -> Bob, change back to Alice.
    let tx = net.pay(&alice, &[(bob.primary(), 1_234_567)]);
    let fee2 = tx.fee;
    net.mine(vec![tx], &mut [&mut alice, &mut bob]).unwrap();
    assert_eq!(bob.balance(), 1_234_567);
    assert_eq!(alice.balance(), 5_000_000 - 1_234_567 - fee2 as u128);
    assert_eq!(fee2, standard_fee(1, 2, &net.rules));
}

#[test]
fn encoding_is_canonical_and_hash_is_stable() {
    let mut net = TestNet::new(3, 80);
    let mut rng = rng(4);
    let alice = Wallet::new(&mut rng);
    let tx = Transaction::from(net.pay(&net.miner_clone(), &[(alice.primary(), 1000)]));
    let bytes = tx.encode();
    let decoded = Transaction::decode(&bytes).unwrap();
    assert_eq!(decoded, tx);
    assert_eq!(decoded.encode(), bytes);
    assert_eq!(decoded.hash(), tx.hash());
    let cb = net.coinbase(0);
    assert_eq!(Transaction::decode(&cb.encode()).unwrap(), cb);
}

/// Flipping any bit of a valid transaction's bytes makes it undecodable or
/// invalid: the signatures cover every byte (spec §4.4).
#[test]
fn every_modified_byte_is_rejected() {
    let mut net = TestNet::new(5, 80);
    let mut rng = rng(6);
    let alice = Wallet::new(&mut rng);
    let tx = Transaction::from(net.pay(&net.miner_clone(), &[(alice.primary(), 1000)]));
    let bytes = tx.encode();
    let height = net.height();
    assert!(validate_mempool_tx(&tx, &net.chain, height, &net.rules).is_ok());
    for i in 0..bytes.len() {
        for mask in [0x01u8, 0x80] {
            let mut b = bytes.clone();
            b[i] ^= mask;
            if let Ok(t) = Transaction::decode(&b) {
                assert!(
                    validate_mempool_tx(&t, &net.chain, height, &net.rules).is_err(),
                    "byte {i} ^ {mask:#x} still valid"
                );
            }
        }
    }
}

#[test]
fn double_spends_are_rejected() {
    let mut net = TestNet::new(7, 80);
    let mut rng = rng(8);
    let alice = Wallet::new(&mut rng);
    let bob = Wallet::new(&mut rng);
    let miner = net.miner_clone();
    let tx1 = net.pay(&miner, &[(alice.primary(), 1000)]);
    // Same coinbase output, different recipient: same key image.
    let tx2 = net.pay(&miner, &[(bob.primary(), 2000)]);
    assert_eq!(tx1.inputs[0].key_image, tx2.inputs[0].key_image);

    // Within one block.
    let mut n2 = TestNet::new(7, 80);
    let err = n2
        .mine(vec![tx1.clone(), tx2.clone()], &mut [])
        .unwrap_err();
    assert_eq!(
        err,
        BlockError::Tx {
            index: 2,
            error: TxError::KeyImageSpent { input: 0 }
        }
    );

    // Across blocks.
    net.mine(vec![tx1.clone()], &mut []).unwrap();
    let h = net.height();
    assert_eq!(
        validate_transfer(&tx2, &net.chain, h, &net.rules),
        Err(TxError::KeyImageSpent { input: 0 })
    );
    // Replaying the identical transaction.
    assert_eq!(
        validate_transfer(&tx1, &net.chain, h, &net.rules),
        Err(TxError::KeyImageSpent { input: 0 })
    );
    assert!(net.mine(vec![tx1], &mut []).is_err());
}

#[test]
fn reorg_undo_restores_state() {
    let mut net = TestNet::new(9, 80);
    let mut rng = rng(10);
    let alice = Wallet::new(&mut rng);
    let tx = net.pay(&net.miner_clone(), &[(alice.primary(), 1000)]);
    let outputs_before = net.chain.output_count();
    let h = net.height();
    net.mine(vec![tx.clone()], &mut []).unwrap();
    assert!(net.chain.is_key_image_spent(&tx.inputs[0].key_image));
    assert!(net.chain.has_one_time_key(&tx.outputs[0].one_time_key));
    // Disconnect: the spend and its outputs disappear, the tx is valid again.
    assert!(net.chain.undo_block());
    assert_eq!(net.chain.output_count(), outputs_before);
    assert!(!net.chain.is_key_image_spent(&tx.inputs[0].key_image));
    assert!(!net.chain.has_one_time_key(&tx.outputs[0].one_time_key));
    assert_eq!(validate_transfer(&tx, &net.chain, h, &net.rules), Ok(()));
}

#[test]
fn cross_network_replay_is_rejected() {
    let mut net = TestNet::new(11, 80);
    let mut rng = rng(12);
    let alice = Wallet::new(&mut rng);
    let tx = net.pay(&net.miner_clone(), &[(alice.primary(), 1000)]);
    let h = net.height();
    let mut testnet_rules = net.rules;
    testnet_rules.network_id = blacksilk_consensus::ChainParams::testnet().network_id;
    assert_eq!(validate_transfer(&tx, &net.chain, h, &net.rules), Ok(()));
    assert_eq!(
        validate_transfer(&tx, &net.chain, h, &testnet_rules),
        Err(TxError::InvalidSignature { input: 0 })
    );
}

#[test]
fn multi_input_multi_output() {
    let mut net = TestNet::new(13, 90);
    let mut rng = rng(14);
    let alice = Wallet::new(&mut rng);
    // More than one coinbase is needed to pay this.
    let targets: Vec<_> = (0..5).map(|i| (alice.address(0, i), REWARD - 1)).collect();
    let tx = net.pay(&net.miner_clone(), &targets);
    assert!(tx.inputs.len() >= 5);
    assert_eq!(tx.outputs.len(), 6);
    let mut alice = alice;
    net.mine(vec![tx], &mut [&mut alice]).unwrap();
    assert_eq!(alice.balance(), 5 * (REWARD as u128 - 1));
    assert_eq!(alice.owned.len(), 5);
}

#[test]
fn coinbase_is_not_accepted_in_the_mempool() {
    let mut net = TestNet::new(15, 1);
    let cb = net.coinbase(0);
    let h = net.height();
    assert_eq!(
        validate_mempool_tx(&cb, &net.chain, h, &net.rules),
        Err(TxError::CoinbaseNotAllowed)
    );
}
