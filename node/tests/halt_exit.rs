//! RTW1B-4: a node whose manager halted because a block that passed
//! validation failed to apply stops with its own exit status
//! (`HALT_EXIT_CODE`), which the systemd unit excludes from restarts: the
//! failure is deterministic, and a restart would replay into it in a loop.
//! Other stops keep status 1.
//!
//! The failure is injected (`ChainManager::fail_next_apply_for_tests`, the
//! `test-hooks` feature of `blacksilk-chain`, enabled for tests only): no
//! valid block fails to apply, so the release binary cannot be driven into
//! it; the status the binary exits with is `halt_exit_code` (src/main.rs).

use blacksilk_chain::block::Block;
use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::store::MemoryStore;
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, PowFunction, HEADER_VERSION};
use blacksilk_crypto::keys::{SubaddressIndex, WalletKeys};
use blacksilk_node::{
    halt_exit_code, halt_message, watch_store, Shared, HALT_EXIT_CODE, POISONED_EXIT_CODE,
};
use blacksilk_tx::builder::{build_coinbase, Payment};
use blacksilk_tx::params::TxRules;
use blacksilk_tx::types::Transaction;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct ZeroPow;
impl PowFunction for ZeroPow {
    fn pow_hash(&self, _: &Hash, _: &[u8]) -> Hash {
        [0; 32]
    }
}

/// A coinbase-only block on the tip.
fn next_block(c: &ChainManager, keys: &WalletKeys, rng: &mut ChaCha20Rng) -> Block {
    let t = c.template();
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
    let header = BlockHeader {
        version: HEADER_VERSION,
        height: t.height,
        prev_id: t.prev_id,
        timestamp: t
            .min_timestamp
            .max(c.params().genesis.timestamp + 120 * t.height),
        difficulty: t.difficulty,
        tx_root: tx_root(&ids),
        nonce: 0,
    };
    Block { header, txs }
}

#[test]
fn an_apply_failure_exits_with_the_halt_status_the_unit_does_not_restart() {
    let p = ChainParams::regtest();
    let m = ChainManager::open(
        p.clone(),
        TxRules::for_chain(&p),
        Arc::new(ZeroPow),
        Box::<MemoryStore>::default(),
        [9; 32],
    )
    .unwrap();
    let shared: Shared = Arc::new(Mutex::new(m));
    // The node's chain actor; the test writes through the lock it keeps.
    let (chain, _actor) = blacksilk_chain::actor::spawn_shared(shared.clone(), Default::default());
    let mut rng = ChaCha20Rng::seed_from_u64(0x4A17);
    let (keys, _) = WalletKeys::generate(&mut rng);
    {
        let mut c = shared.lock().unwrap();
        let b = next_block(&c, &keys, &mut rng);
        let now = b.header.timestamp;
        c.submit_block(b, now).unwrap();
        assert!(c.halted().is_none());
    }
    assert_eq!(halt_exit_code(&chain), 1, "not halted: the generic status");

    let failed = {
        let mut c = shared.lock().unwrap();
        c.fail_next_apply_for_tests();
        let b = next_block(&c, &keys, &mut rng);
        let id = b.id(p.network_id);
        let now = b.header.timestamp;
        let s = c.submit_block(b, now).unwrap();
        assert!(!s.on_best_chain);
        assert!(c.apply_halted());
        assert!(!c.store_failed());
        id
    };
    // The node's watcher fires, and the node exits with the halt status.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        tokio::time::timeout(
            Duration::from_secs(10),
            watch_store(&chain, Duration::from_millis(10)),
        )
        .await
        .expect("the watcher resolves")
        .unwrap();
    });
    assert_eq!(halt_exit_code(&chain), HALT_EXIT_CODE);
    let msg = halt_message(&chain);
    assert!(msg.contains(&hex::encode(&failed[..8])), "{msg}");
    // The way out: the flag with the block's full id (docs/testnet.md §9).
    assert!(
        msg.contains(&format!("--invalidate-block {}", hex::encode(failed))),
        "{msg}"
    );
    assert!(!msg.contains("\n"), "one log line: {msg:?}");
    // RTW3-8: the message says what invalidating costs and how to undo it.
    for part in [
        "consensus-valid by this build's rules",
        "forks this node off the network's chain",
        "Report the incident",
    ] {
        assert!(msg.contains(part), "{part:?} in {msg}");
    }
    assert!(
        msg.contains(&format!("--reconsider-block {}", hex::encode(failed))),
        "{msg}"
    );

    // Distinct from every other status the node exits with.
    assert!(![0, 1, 2, POISONED_EXIT_CODE].contains(&HALT_EXIT_CODE));
    // The shipped systemd unit does not restart on it (and still restarts
    // on other failures).
    let unit = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../deploy/systemd/blacksilk-node.service"),
    )
    .unwrap();
    let lines: Vec<&str> = unit.lines().map(str::trim).collect();
    assert!(lines.contains(&"Restart=on-failure"));
    let prevent: Vec<&str> = lines
        .iter()
        .filter_map(|l| l.strip_prefix("RestartPreventExitStatus="))
        .flat_map(|v| v.split_whitespace())
        .collect();
    assert!(
        prevent.contains(&HALT_EXIT_CODE.to_string().as_str()),
        "the unit must list the halt status"
    );
    // A configuration error or a build refusing the network (W4-GUARD).
    assert!(prevent.contains(&"2"), "the unit must list status 2");
}

/// The same halt found at start-up: `ChainManager::open` returns the replay's
/// apply failure as an `ApplyHalt` inside its `io::Error`, and the node maps
/// it to `HALT_EXIT_CODE` (src/main.rs), so a restart loop also stops there.
/// Any other open error (a corrupt store, a foreign network) keeps status 1.
#[test]
fn an_apply_failure_found_at_start_up_exits_with_the_halt_status() {
    use blacksilk_chain::manager::ApplyHalt;
    use blacksilk_node::open_exit_code;
    use std::io;

    let halt = io::Error::other(ApplyHalt("block 00ab at height 7 failed to apply".into()));
    assert_eq!(open_exit_code(&halt), HALT_EXIT_CODE);
    assert_eq!(halt.to_string(), "block 00ab at height 7 failed to apply");
    for other in [
        io::Error::new(io::ErrorKind::InvalidData, "corrupt record"),
        io::Error::other("store of another network"),
        io::Error::from(io::ErrorKind::NotFound),
    ] {
        assert_eq!(open_exit_code(&other), 1, "{other}");
    }
}
