//! Miner and node agree on blocks using real RandomX.
//!
//! The "miner" here does what the miner binary does: take a template, build the
//! header, hash it with its own RandomX instance and check it with `check_hash`.
//! The "node" validates with `HeaderChain` + `RandomXPow`.

use blacksilk_consensus::{
    check_hash, merkle::tx_root, BlockHeader, ChainParams, HeaderChain, HeaderError, RandomXPow,
    HEADER_VERSION,
};
use blacksilk_randomx::{Cache, Vm};
use std::sync::Arc;

fn params_with_difficulty(d: u64) -> ChainParams {
    let mut p = ChainParams::regtest();
    p.initial_difficulty = d;
    p.genesis.difficulty = d;
    p
}

/// Miner side: build a header from the template and search for a nonce.
fn mine(chain: &HeaderChain, timestamp: u64, start_nonce: u64) -> BlockHeader {
    let t = chain.template();
    let cache = Cache::new(&t.seed_id);
    let mut vm = Vm::light(&cache);
    let mut header = BlockHeader {
        version: HEADER_VERSION,
        height: t.height,
        prev_id: t.prev_id,
        timestamp: timestamp.max(t.min_timestamp),
        difficulty: t.difficulty,
        tx_root: tx_root(&[[t.height as u8; 32]]),
        nonce: start_nonce,
    };
    while !check_hash(&vm.hash(&header.to_bytes()), header.difficulty) {
        header.nonce += 1;
    }
    header
}

#[test]
fn mined_blocks_are_accepted_by_the_node() {
    let params = params_with_difficulty(4);
    let genesis_time = params.genesis.timestamp;
    let mut node = HeaderChain::new(params, Arc::new(RandomXPow::new()));

    let mut time = genesis_time;
    for _ in 0..2 {
        time += 120;
        let header = mine(&node, time, 0);
        let accepted = node
            .accept(header, time)
            .expect("node accepts the miner's block");
        let reorg = accepted.reorg.expect("extends the tip");
        assert!(reorg.is_extension());
    }
    assert_eq!(node.height(), 2);
}

#[test]
fn insufficient_work_is_rejected() {
    let params = params_with_difficulty(8);
    let now = params.genesis.timestamp + 120;
    let node = HeaderChain::new(params, Arc::new(RandomXPow::new()));

    let t = node.template();
    let cache = Cache::new(&t.seed_id);
    let mut vm = Vm::light(&cache);
    let mut header = BlockHeader {
        version: HEADER_VERSION,
        height: t.height,
        prev_id: t.prev_id,
        timestamp: now,
        difficulty: t.difficulty,
        tx_root: [1; 32],
        nonce: 0,
    };
    // Find a nonce that does NOT meet the difficulty (7 in 8 chance per try).
    while check_hash(&vm.hash(&header.to_bytes()), header.difficulty) {
        header.nonce += 1;
    }
    assert_eq!(
        node.validate(&header, now),
        Err(HeaderError::InsufficientWork)
    );
}
