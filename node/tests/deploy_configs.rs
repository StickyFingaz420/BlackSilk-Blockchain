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
        // The RPC is plaintext HTTP (its cookie would travel in the clear):
        // loopback only.
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

/// The consensus fingerprint of every network
/// (`blacksilk_node::fingerprint::consensus_fingerprint`): the chain parameters
/// and genesis, the transaction, block and emission rules, the RandomX
/// configuration, and the PX side (proof system, zkVM, kernel and vault ids;
/// `px/tests/consensus_fingerprint.rs` pins that part on its own). The test
/// pins the value the node computes at run time, prints in `--version` and
/// the start-up log, and serves in `/info`.
///
/// **Changing any of these digests is a consensus change and requires a new
/// network id.** Update a pinned digest only in the same commit as the new id.
#[test]
fn consensus_fingerprints_are_pinned() {
    use blacksilk_node::fingerprint::{consensus_fingerprint, hex, manifest};
    for (network, pinned) in [
        (Network::Testnet, TESTNET_FINGERPRINT),
        (Network::Regtest, REGTEST_FINGERPRINT),
        (Network::Mainnet, MAINNET_FINGERPRINT),
    ] {
        assert_eq!(
            hex(&consensus_fingerprint(network)),
            pinned,
            "{network:?}: a consensus constant changed (this is a consensus change and requires \
             a new network id); current values:\n{}",
            manifest(network).render()
        );
    }
    // Every network's own parameters are in its fingerprint.
    for n in [Network::Testnet, Network::Regtest, Network::Mainnet] {
        let text = manifest(n).render();
        let p = ChainParams::for_network(n);
        assert!(text.contains(&format!("chain.network_id = {}", p.network_id)));
        assert!(text.contains(&hex(&p.genesis_id())));
    }
}

/// Changing this is a consensus change and requires a new network id.
///
/// v3 candidate values (branch `v3/candidate`): the v3 rule set, the rebuilt
/// kernel and vault ids, with the testnet's genesis and network id still the
/// retired v2 ones. The testnet value changes again when the v3 genesis is
/// generated at launch (docs/testnet-v3-genesis.md §6).
const TESTNET_FINGERPRINT: &str =
    "9ebc5cc817c71cf144eab8fbbc7601f8e9e17a2d98217b6e62f9df2091e5b17f";
/// Changing this is a consensus change and requires a new network id.
const REGTEST_FINGERPRINT: &str =
    "5df1f2267d609ceaab90f5368b368d4302da7542462f78323a9f88383d99fd2a";
/// Changing this is a consensus change and requires a new network id. (The
/// mainnet parameters are provisional; mainnet is not launched.)
const MAINNET_FINGERPRINT: &str =
    "6480dd9fc366c63bb93a0d13e6e60215c138d6a96e55ff5071d667cb8e3d6376";
