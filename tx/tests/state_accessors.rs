//! The read side of the reference chain state (`blacksilk_tx::state::
//! MemoryChain`) that the node's RPC serves from: the outputs of each block,
//! the transactions of each block, the contract registry and its log, and
//! the fault hook. Mutation run E (docs/evidence/mutation-runE-2026-10-01/)
//! found these untested by the tx tests: the chain and node tests read them,
//! the tx tests did not.

mod common;

use blacksilk_tx::builder::Payment;
use blacksilk_tx::px::{PxDeploy, Registration};
use blacksilk_tx::px_builder::build_deploy;
use blacksilk_tx::state::{ApplyError, MemoryChain};
use blacksilk_tx::types::Transaction;
use blacksilk_tx::validate::ChainView;
use common::*;

const VAULT_ELF: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../px/vault.elf"));

/// A valid, signed deploy of the vault program from the miner's first
/// spendable coinbase.
fn vault_deploy(net: &mut TestNet) -> PxDeploy {
    let miner = net.miner_clone();
    let real = miner.spendable(net.height())[0].clone();
    let plan = net.plan(&real);
    let rules = net.rules;
    build_deploy(
        &miner.keys,
        vec![plan],
        &[Payment {
            address: miner.primary(),
            amount: 1,
        }],
        &miner.primary(),
        [9; 32],
        vec![Registration {
            elf: VAULT_ELF.to_vec(),
            budget: blacksilk_px::vault::BUDGET,
            abi: blacksilk_tx::px::ABI_VERSION,
            out_words: 1,
        }],
        &rules,
        &mut net.rng,
    )
    .expect("deploy builds")
}

/// Each applied block's first global output index, the cumulative output
/// counts and the block's transaction hashes, in block order; nothing past
/// the tip.
#[test]
fn block_outputs_and_transaction_hashes_are_kept_per_block() {
    let mut net = TestNet::new(71, 3);
    // Every coinbase of `TestNet` has exactly one output.
    assert_eq!(net.chain.output_count(), 3);
    assert_eq!(net.chain.first_output_at(0), Some(0));
    assert_eq!(net.chain.first_output_at(2), Some(2));
    assert_eq!(net.chain.first_output_at(3), None);
    assert_eq!(net.chain.cumulative_outputs(), vec![1, 2, 3]);
    let txs = vec![net.coinbase(0)];
    let hashes: Vec<_> = txs.iter().map(Transaction::hash).collect();
    net.submit(txs, &mut []).unwrap();
    assert_eq!(net.chain.block_tx_hashes(3), Some(hashes.as_slice()));
    assert_eq!(net.chain.block_tx_hashes(4), None);
    let earlier = net.chain.block_tx_hashes(0).expect("block 0");
    assert_eq!(earlier.len(), 1);
    assert_ne!(earlier, hashes.as_slice(), "every block keeps its own");
    assert!(net.chain.undo_block());
    assert_eq!(net.chain.block_tx_hashes(3), None);
    assert_eq!(net.chain.cumulative_outputs(), vec![1, 2, 3]);
}

/// A deploy registers its functions under its contract id, logged at its
/// height in block order; the block's undo removes both.
#[test]
fn a_deploy_is_registered_and_logged_until_its_block_is_undone() {
    let mut net = TestNet::new(72, 80);
    let d = vault_deploy(&mut net);
    let id = d.contract_id();
    let loaded = d.load_programs().expect("the vault loads");
    let height = net.height();
    let mut txs = vec![net.coinbase(d.fee)];
    txs.push(Transaction::PxDeploy(Box::new(d)));
    net.submit(txs, &mut []).unwrap();

    assert_eq!(net.chain.px_contract_log(), &[(height, id)]);
    let functions = net.chain.px_contract(&id).expect("registered");
    assert_eq!(functions.len(), 1);
    assert_eq!(functions[0].program_id, loaded[0].0.id());
    assert_eq!(functions[0].budget, blacksilk_px::vault::BUDGET);
    assert_eq!(
        (functions[0].abi, functions[0].out_words),
        (blacksilk_tx::px::ABI_VERSION, 1)
    );
    assert!(net.chain.px_contract(&[7; 8]).is_none());
    assert!(net.chain.px_contract_exists(&id));
    assert!(net
        .chain
        .px_function(&id, &functions[0].program_id)
        .is_some_and(|p| p.budget == blacksilk_px::vault::BUDGET && p.out_words == 1));
    assert!(
        net.chain.px_function(&id, &[3; 32]).is_none(),
        "another program"
    );
    assert!(net
        .chain
        .px_function(&[7; 8], &functions[0].program_id)
        .is_none());

    // An empty block on top leaves the log alone; undoing the deploy's
    // block removes the registration and its log entry.
    net.mine(vec![], &mut []).unwrap();
    assert!(net.chain.undo_block());
    assert_eq!(net.chain.px_contract_log(), &[(height, id)]);
    assert!(net.chain.undo_block());
    assert!(net.chain.px_contract_log().is_empty());
    assert!(net.chain.px_contract(&id).is_none());
    assert!(!net.chain.px_contract_exists(&id));
}

/// The fault hook makes exactly the next `apply_block` fail, changing
/// nothing.
#[test]
fn the_fault_hook_fails_the_next_apply_only() {
    let mut chain = MemoryChain::new();
    chain.apply_block(&[]).unwrap();
    chain.fail_next_apply_for_tests();
    assert_eq!(chain.apply_block(&[]), Err(ApplyError::Injected));
    assert_eq!(chain.next_height(), 1);
    assert_eq!(chain.apply_block(&[]), Ok(0));
    assert_eq!(chain.next_height(), 2);
}
