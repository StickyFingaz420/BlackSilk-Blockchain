//! The RandomX key switch with the chain's hot keys (07 W1, F07-7): once the
//! next key's block exists, `sync_policy::hot_seeds` names it, and
//! `PowFunction::set_hot_seeds` builds its cache in the background, so the
//! first block under the new key costs its hash only, not a cache build, on
//! whatever path (under the chain lock here, as `submit_block` runs).
//!
//! Real RandomX (light), with the short key epoch of the chain tests (16,
//! lag 4: switches at 21 and 37). The first switch runs without a hot set
//! (the pre-W1 behaviour: the build happens inside the submission), the
//! second with it. Both submission times are printed (`--nocapture`).

use blacksilk_chain::block::Block;
use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::store::MemoryStore;
use blacksilk_chain::sync_policy::hot_seeds;
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, PowFunction, RandomXPow};
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
    let header = BlockHeader {
        version: t.version,
        height: t.height,
        prev_id: t.prev_id,
        timestamp: t.min_timestamp.max(parent_time + 10),
        difficulty: t.difficulty,
        tx_root: tx_root(&ids),
        nonce: 0,
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
fn a_prebuilt_next_key_takes_the_cache_build_off_the_switch() {
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

    // First switch (height 21, key = block 16), no hot set: the submission
    // of block 21 builds the key's cache itself.
    let mut before = Duration::ZERO;
    let mut hash = Duration::ZERO;
    for h in 1..=21u64 {
        let builds = pow.builds();
        let took = submit_next(&mut m, &keys, &mut rng);
        if h == 20 {
            hash = took;
        }
        if h == 21 {
            before = took;
            assert_eq!(
                pow.builds(),
                builds + 1,
                "block 21 built the new key's cache"
            );
        }
    }

    // From here the chain names its hot keys after every block, as the
    // manager hook does. Block 32 (the next key) exists at tip 32; block 37
    // is the first to use it.
    let key32 = |m: &ChainManager| m.headers().main_id_at(32);
    let mut after = Duration::ZERO;
    for h in 22..=37u64 {
        pow.set_hot_seeds(&hot_seeds(m.headers()));
        if h == 37 {
            let k = key32(&m).expect("block 32 exists");
            assert!(hot_seeds(m.headers()).contains(&k), "the next key is hot");
            // The background build had the lag (4 blocks) to finish; in a
            // real network that is 64 blocks, about two hours.
            let deadline = Instant::now() + Duration::from_secs(120);
            while !pow.is_resident(&k) {
                assert!(Instant::now() < deadline, "the next key was not prebuilt");
                std::thread::sleep(Duration::from_millis(20));
            }
            let builds = pow.builds();
            after = submit_next(&mut m, &keys, &mut rng);
            assert_eq!(pow.builds(), builds, "block 37 built no cache");
        } else {
            submit_next(&mut m, &keys, &mut rng);
        }
    }
    assert_eq!(m.height(), 37);
    // The old key (block 16) stays built while a branch within the anti-DoS
    // window may use it; the genesis key has been released.
    pow.set_hot_seeds(&hot_seeds(m.headers()));
    let resident = pow.resident();
    assert!(resident.len() <= 3, "{resident:?}");
    println!(
        "block submission at a key switch (under the chain lock): without prebuild {before:.1?}, \
         with prebuild {after:.1?}; an ordinary block {hash:.1?}"
    );
}
