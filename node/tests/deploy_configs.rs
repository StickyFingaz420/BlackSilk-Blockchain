//! Every shipped configuration file (`deploy/config/*.toml`) goes through the
//! node's own configuration parser, and its settings are what its name
//! promises; and the chain-level consensus constants are pinned.
//!
//! The parser (`src/config.rs`) is a module of the binary, not of the library,
//! so it is compiled into this test by path: the test exercises the exact code
//! the binary runs, `Config::resolve`, without a copy. (Moving `config` into
//! the library as `pub mod config` would make the `#[path]` unnecessary; it
//! also means `config.rs`'s own unit tests run a second time here.)
//!
//! Whether the node currently accepts a network (testnet is refused while its
//! genesis is not final) is the node's policy, not the files' concern. So each
//! file is resolved with the network overridden to regtest on the command line,
//! which parses and checks every key of the file; the file's own `network` key
//! is read from the TOML; and resolving the file as is must either give that
//! network or fail with a refusal of the network, never with a file error.

#[allow(dead_code)] // the test uses only part of the binary's module
#[path = "../src/config.rs"]
mod config;

use blacksilk_consensus::{ChainParams, Network};
use blacksilk_p2p::NetAddr;
use config::{resolve_seeds, Args, Config};
use std::path::{Path, PathBuf};

fn deploy_configs() -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../deploy/config");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect();
    files.sort();
    files
}

/// Resolves `path` with the network overridden on the command line (so the
/// result does not depend on which networks the node accepts).
fn resolve_as(path: &Path, network: &str) -> Result<Config, String> {
    Config::resolve(Args {
        config: Some(path.to_path_buf()),
        network: Some(network.into()),
        ..Args::default()
    })
}

/// The file's raw TOML (for the keys whose defaults depend on the network).
fn raw(path: &Path) -> toml::Table {
    toml::from_str(&std::fs::read_to_string(path).unwrap())
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn every_deploy_config_parses_and_is_set_up_as_named() {
    let files = deploy_configs();
    assert!(files.len() >= 5, "deploy/config holds the shipped configs");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for path in &files {
        let name = path.file_stem().unwrap().to_str().unwrap();
        let t = raw(path);
        let network = t
            .get("network")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| {
                panic!("{name}: names its network");
            });
        let p2p = t.get("p2p").and_then(|v| v.as_table());
        let allow_private = p2p
            .and_then(|p| p.get("allow_private"))
            .and_then(|v| v.as_bool());

        // Every key parses and resolves (network overridden, see the module docs).
        let c =
            resolve_as(path, "regtest").unwrap_or_else(|e| panic!("{name} does not parse: {e}"));
        assert!(
            t.contains_key("data_dir"),
            "{name}: names its data directory"
        );
        // The RPC has no authentication: loopback only.
        assert!(
            c.rpc_bind.ip().is_loopback(),
            "{name}: RPC on {}",
            c.rpc_bind
        );
        assert!(!c.repair_store, "{name}: repair is command line only");
        let p = c
            .p2p
            .as_ref()
            .unwrap_or_else(|| panic!("{name}: P2P enabled"));
        assert!(
            p.max_outbound > 0 && p.max_inbound > 0,
            "{name}: peer limits"
        );

        // As the file stands: its own network, or a refusal of that network
        // (not a file error, which names the file).
        let expected = match network {
            "regtest" => Network::Regtest,
            "testnet" => Network::Testnet,
            other => panic!("{name}: unexpected network {other:?}"),
        };
        match Config::resolve(Args {
            config: Some(path.clone()),
            ..Args::default()
        }) {
            Ok(own) => assert_eq!(own.network, expected, "{name}"),
            Err(e) => {
                assert_ne!(expected, Network::Regtest, "{name}: {e}");
                let file = path.to_string_lossy();
                assert!(
                    !e.contains(file.as_ref()) && e.contains(network),
                    "{name}: {e}"
                );
            }
        }

        match name {
            "regtest" => {
                assert_eq!(network, "regtest", "{name}");
                assert!(
                    p.listen.is_some_and(|a| a.ip().is_loopback()),
                    "{name}: local only"
                );
            }
            "testnet-node" | "testnet-seed" => {
                assert_eq!(network, "testnet", "{name}");
                assert_ne!(allow_private, Some(true), "{name}: public testnet");
                assert!(!p.proxy_only, "{name}");
            }
            "lab-testnet" => {
                assert_eq!(network, "testnet", "{name}");
                assert_eq!(allow_private, Some(true), "{name}: a LAN lab");
            }
            "testnet-tor" => {
                assert_eq!(network, "testnet", "{name}");
                // A Tor-only node: every connection through the proxy, no
                // clearnet listener, no clearnet address advertised, and no
                // seed that would need a (leaking) local DNS lookup.
                assert!(p.proxy_only && p.proxy.is_some(), "{name}: proxy only");
                assert!(
                    p.listen.is_none_or(|a| a.ip().is_loopback()),
                    "{name}: listens only for the local onion service"
                );
                assert!(
                    p.public_address.as_ref().is_none_or(NetAddr::is_onion),
                    "{name}: advertises no clearnet address"
                );
                assert_ne!(allow_private, Some(true), "{name}");
            }
            other => panic!(
                "deploy/config/{other}.toml is not covered by this test; add its expectations"
            ),
        }
        if p.proxy_only {
            rt.block_on(resolve_seeds(&p.seeds, true))
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            rt.block_on(resolve_seeds(&p.peers, true))
                .unwrap_or_else(|e| panic!("{name}: {e}"));
        }
    }
}

#[test]
fn a_typo_in_a_config_is_an_error() {
    // The parser is strict (deny_unknown_fields): a misspelt key in an
    // operator's copy of a shipped file must not be silently ignored. The
    // network is overridden, so the typo is the only possible error.
    let dir = tempfile::tempdir().unwrap();
    for path in deploy_configs() {
        let text = std::fs::read_to_string(&path)
            .unwrap()
            .replace("\r\n", "\n");
        assert!(text.contains("\n[p2p]\n"), "{}: has [p2p]", path.display());
        let copy = dir.path().join(path.file_name().unwrap());
        std::fs::write(&copy, &text).unwrap();
        assert!(resolve_as(&copy, "regtest").is_ok(), "{}", path.display());
        for bad in [
            format!("netwrok = \"testnet\"\n{text}"),
            text.replacen("\n[p2p]\n", "\n[p2p]\nmax_outbund = 3\n", 1),
        ] {
            std::fs::write(&copy, bad).unwrap();
            assert!(
                resolve_as(&copy, "regtest").is_err(),
                "{}: typo accepted",
                path.display()
            );
        }
    }
}

/// The chain-level consensus constants: network ids, genesis, difficulty and
/// time rules, the RandomX key schedule, the transaction and PX size and fee
/// rules, block limits and the emission curve. (`px/tests/consensus_fingerprint.rs`
/// pins the proof system, the zkVM and the PX kernel id; `blacksilk-px` cannot
/// reach these.)
///
/// **Changing any of these is a consensus change and requires a new network
/// id.** Update the pinned digest only in the same commit as the new id.
#[test]
fn chain_level_consensus_constants_are_pinned() {
    use blacksilk_chain::{block, emission};
    use blacksilk_tx::params as tx;
    use std::fmt::Write;

    let mut s = String::new();
    let mut add = |name: &str, value: &dyn std::fmt::Debug| {
        writeln!(s, "{name} = {value:?}").unwrap();
    };
    for p in [ChainParams::testnet(), ChainParams::regtest()] {
        let n = format!("{:?}", p.network);
        add(&format!("{n}.network_id"), &p.network_id);
        add(&format!("{n}.target_block_time"), &p.target_block_time);
        add(&format!("{n}.initial_difficulty"), &p.initial_difficulty);
        add(&format!("{n}.difficulty_window"), &p.difficulty_window);
        add(&format!("{n}.median_time_window"), &p.median_time_window);
        add(&format!("{n}.future_time_limit"), &p.future_time_limit);
        add(&format!("{n}.seed_epoch"), &p.seed_epoch);
        add(&format!("{n}.seed_lag"), &p.seed_lag);
        add(&format!("{n}.genesis"), &p.genesis.to_bytes());
        add(&format!("{n}.genesis_id"), &p.genesis_id());
        let r = tx::TxRules::for_chain(&p);
        add(
            &format!("{n}.rules"),
            &(r.network_id, r.fee_per_weight, r.max_block_weight),
        );
    }
    add("consensus.HEADER_SIZE", &blacksilk_consensus::HEADER_SIZE);
    add(
        "consensus.HEADER_VERSION",
        &blacksilk_consensus::HEADER_VERSION,
    );
    add("tx.TX_VERSION", &tx::TX_VERSION);
    add(
        "tx.KINDS",
        &[
            tx::KIND_COINBASE,
            tx::KIND_TRANSFER,
            tx::KIND_PX,
            tx::KIND_PX_DEPLOY,
        ],
    );
    add("tx.RING_SIZE", &tx::RING_SIZE);
    add("tx.MAX_TX_SIZE", &tx::MAX_TX_SIZE);
    add("tx.MAX_INPUTS", &tx::MAX_INPUTS);
    add("tx.MIN_OUTPUTS", &tx::MIN_OUTPUTS);
    add("tx.MAX_OUTPUTS", &tx::MAX_OUTPUTS);
    add("tx.MIN_COINBASE_OUTPUTS", &tx::MIN_COINBASE_OUTPUTS);
    add("tx.MAX_COINBASE_OUTPUTS", &tx::MAX_COINBASE_OUTPUTS);
    add("tx.SPENDABLE_AGE", &tx::SPENDABLE_AGE);
    add("tx.COINBASE_MATURITY", &tx::COINBASE_MATURITY);
    add("tx.FEE_PER_WEIGHT", &tx::FEE_PER_WEIGHT);
    add("tx.MAX_BLOCK_WEIGHT", &tx::MAX_BLOCK_WEIGHT);
    add("tx.MAX_PX_TX_SIZE", &tx::MAX_PX_TX_SIZE);
    add("tx.MAX_DEPLOY_TX_SIZE", &tx::MAX_DEPLOY_TX_SIZE);
    add("tx.MAX_PX_BLOCK_BYTES", &tx::MAX_PX_BLOCK_BYTES);
    add("tx.PX_FEE_PER_BYTE", &tx::PX_FEE_PER_BYTE);
    add("tx.PX_STANDARD_FEE", &tx::PX_STANDARD_FEE);
    add("tx.MAX_PAYOUTS", &tx::MAX_PAYOUTS);
    add("tx.MAX_FN_OUTPUT_WORDS", &tx::MAX_FN_OUTPUT_WORDS);
    add("tx.MAX_DEPLOY_PROGRAMS", &tx::MAX_DEPLOY_PROGRAMS);
    add("tx.MAX_PROGRAM_BYTES", &tx::MAX_PROGRAM_BYTES);
    add("chain.MAX_BLOCK_BYTES", &block::MAX_BLOCK_BYTES);
    add("chain.MAX_BLOCK_TXS", &block::MAX_BLOCK_TXS);
    add("emission.COIN", &emission::COIN);
    add("emission.MONEY_SUPPLY", &emission::MONEY_SUPPLY);
    add("emission.EMISSION_SPEED", &emission::EMISSION_SPEED);
    add("emission.TAIL_REWARD", &emission::TAIL_REWARD);
    // The curve itself, at a few points (height, coins generated before it).
    let curve: Vec<u64> = [
        (0, 0),
        (1, 0),
        (2, emission::block_reward(1, 0)),
        (1_000, 1_000 * emission::COIN),
        (1, emission::MONEY_SUPPLY - emission::COIN),
        (1, emission::MONEY_SUPPLY),
    ]
    .iter()
    .map(|&(h, g)| emission::block_reward(h, g))
    .collect();
    add("emission.block_reward samples", &curve);

    let mut h = blacksilk_crypto::hash::Hasher64::new("test/consensus-fingerprint");
    h.update(s.as_bytes());
    let digest: String = h.finalize()[..32]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        digest, CHAIN_LEVEL_DIGEST,
        "a consensus constant changed (this is a consensus change and requires a new network id); \
         current values:\n{s}"
    );
}

/// Changing any of these is a consensus change and requires a new network id.
const CHAIN_LEVEL_DIGEST: &str = "adec553ac756c7d2e19b5023f67c5d18cb60c143022b8a367f1407dffeccc20b";
