//! The RandomX key switch with the chain's hot keys (07 W1, F07-7): once the
//! next key's block exists, `sync_policy::hot_seeds` names it, and
//! `PowFunction::set_hot_seeds` builds its cache in the background, so the
//! first block under the new key costs its hash only, not a cache build, on
//! whatever path (under the chain lock here, as `submit_block` runs).
//!
//! Real RandomX (light), with the short key epoch of the chain tests (16,
//! lag 4: switches at 21 and 37). The manager itself passes the hot keys to
//! the PoW layer whenever its best header chain changes
//! (`ChainManager::refresh_hot_seeds`); the test never calls
//! `set_hot_seeds`. At both switches the new key's cache must be built
//! before its first block, which then builds no cache under the lock.

use blacksilk_chain::block::Block;
use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::store::MemoryStore;
use blacksilk_chain::sync_policy::hot_seeds;
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, RandomXPow};
use blacksilk_crypto::keys::{SubaddressIndex, WalletKeys};
use blacksilk_tx::builder::{build_coinbase, Payment};
use blacksilk_tx::params::TxRules;
use blacksilk_tx::types::Transaction;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn short_epoch_params() -> ChainParams {
    let mut p = ChainParams::regtest();
    p.seed_epoch = 16;
    p.seed_lag = 4;
    p
}

/// Builds the next block on the tip (coinbase only, regtest difficulty 1).
fn next_block(m: &ChainManager, keys: &WalletKeys, rng: &mut ChaCha20Rng) -> Block {
    let t = m.template();
    let cb = build_coinbase(
        t.height,
        &[Payment {
            address: keys.address(SubaddressIndex::PRIMARY),
            amount: t.reward,
        }],
        &keys.hedge_secret(),
        rng,
    )
    .unwrap();
    let txs = vec![Transaction::Coinbase(cb)];
    let ids: Vec<Hash> = txs.iter().map(Transaction::hash).collect();
    let parent_time = m.tip_header().timestamp;
    let (output_count, output_root) = t.outputs_after(&txs);
    let header = BlockHeader {
        version: t.version,
        height: t.height,
        prev_id: t.prev_id,
        timestamp: t.min_timestamp.max(parent_time + 10),
        difficulty: t.difficulty,
        tx_root: tx_root(&ids),
        nonce: 0,
        output_count,
        output_root,
        px_root: t.px_root,
    };
    Block { header, txs }
}

/// Submits the next block; returns how long the submission took.
fn submit_next(m: &mut ChainManager, keys: &WalletKeys, rng: &mut ChaCha20Rng) -> Duration {
    let b = next_block(m, keys, rng);
    let now = b.header.timestamp;
    let started = Instant::now();
    m.submit_block(b, now).expect("valid block");
    started.elapsed()
}

#[test]
fn the_manager_prebuilds_each_next_key_before_its_switch() {
    let p = short_epoch_params();
    let pow = Arc::new(RandomXPow::new());
    let mut m = ChainManager::open(
        p.clone(),
        TxRules::for_chain(&p),
        pow.clone(),
        Box::<MemoryStore>::default(),
        [4; 32],
    )
    .unwrap();
    let mut rng = ChaCha20Rng::seed_from_u64(21);
    let (keys, _) = WalletKeys::generate(&mut rng);

    // Switch heights and their keys: block 21 uses block 16's id, block 37
    // block 32's (epoch 16, lag 4).
    let mut ordinary = Duration::ZERO;
    let mut at_switch = Vec::new();
    for h in 1..=37u64 {
        if h == 21 || h == 37 {
            let k = m.headers().main_id_at(h - 5).expect("the key block exists");
            assert!(
                hot_seeds(m.headers()).contains(&k),
                "the next key is hot at {h}"
            );
            // The background build had the lag (4 blocks) to finish; in a
            // real network that is 64 blocks, about two hours.
            let deadline = Instant::now() + Duration::from_secs(120);
            while !pow.is_resident(&k) {
                assert!(Instant::now() < deadline, "key for {h} was not prebuilt");
                std::thread::sleep(Duration::from_millis(20));
            }
            let builds = pow.builds();
            at_switch.push(submit_next(&mut m, &keys, &mut rng));
            assert_eq!(pow.builds(), builds, "block {h} built no cache");
        } else {
            let took = submit_next(&mut m, &keys, &mut rng);
            if h == 20 {
                ordinary = took;
            }
        }
    }
    assert_eq!(m.height(), 37);
    // At most the hot keys plus one side slot stay built; the genesis key has
    // been released.
    let resident = pow.resident();
    assert!(resident.len() <= 3, "{resident:?}");
    println!(
        "block submission at the key switches (under the chain lock, prebuilt by the manager): \
         {at_switch:.1?}; an ordinary block {ordinary:.1?}"
    );
}
