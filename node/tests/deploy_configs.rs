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

/// The fingerprints of every network (`blacksilk_node::fingerprint`, v3): the
/// **rules** fingerprint (every consensus constant, the rule samples and the
/// rule-revision list, including the PX side that
/// `px/tests/consensus_fingerprint.rs` pins on its own), the **identity**
/// fingerprint (network id, genesis, branch ids) and the **consensus**
/// fingerprint that combines them. The test pins the values the node
/// computes at run time, prints in `--version` and `--print-manifest`, and
/// serves in `/info`.
///
/// **Changing any of these digests is a consensus change.** Re-pin only in
/// the same commit as the change, with a `Consensus-Change:` trailer naming
/// its record (docs/reviews/v3-consensus-changes.md, section `fingerprint-v3`
/// for the procedure). A change of rules moves the rules and consensus
/// values of every network; the launch commit (the testnet beacon and genesis
/// time) moves only the testnet's identity and consensus values.
#[test]
fn consensus_fingerprints_are_pinned() {
    use blacksilk_node::fingerprint::{fingerprints, hex, manifest};
    for (network, [consensus, rules, identity]) in [
        (Network::Testnet, TESTNET),
        (Network::Regtest, REGTEST),
        (Network::Mainnet, MAINNET),
    ] {
        let f = fingerprints(network);
        assert_eq!(
            [hex(&f.consensus), hex(&f.rules), hex(&f.identity)],
            [consensus, rules, identity],
            "{network:?}: [consensus, rules, identity] changed (a consensus change: re-pin with \
             its record); current values:\n{}",
            manifest(network).render()
        );
    }
    // Every network's own identity is in its manifest.
    for n in [Network::Testnet, Network::Regtest, Network::Mainnet] {
        let text = manifest(n).render();
        let p = ChainParams::for_network(n);
        assert!(text.contains(&format!("chain.network_id = {}", p.network_id)));
        assert!(text.contains(&hex(&p.genesis_id())));
    }
}

/// `[consensus, rules, identity]` (fingerprint v3). Testnet v3: the final id
/// `0x0001D673`, the placeholder genesis time and no beacon yet, so the
/// identity and consensus values change at launch (docs/testnet-v3-genesis.md
/// §6) and the rules value does not. Re-pinned by RT-FP3 (rules and consensus;
/// identity unchanged); re-pinned by PX-R (rules and consensus: the golden PX
/// fixture samples and the revision PX-R:ciphertext-r-canonical-not-identity;
/// identity unchanged); re-pinned by RX-SALT (rules and consensus: BlackSilk's
/// RandomX salt, the known answer bs-1a and the revision
/// RX-SALT:blacksilk-randomx-argon2-salt; identity unchanged).
const TESTNET: [&str; 3] = [
    "8b96c3a385f3d92c782d3d840d3b0fe570aa20672b6f05e84f88929537c85ead",
    "9eab5567e5b648177f2c7093cc6b9c840cbff38d2dfc2cef542e56fc739280f5",
    "b333a99f2bcd5d351fe87d043e9cd17d6920c43c09021ea453bc14d9fec4b294",
];
/// `[consensus, rules, identity]` (fingerprint v3; RT-FP3; PX-R; RX-SALT).
const REGTEST: [&str; 3] = [
    "aebaf33756f6d6715b9a3ad0d89d493293d36ca93042ed31249afe7b6e1101bd",
    "1ad5f7f5b6011ba0c1d79b2db8dd56323ed99513bb8a4b46c4757b9459eb98dc",
    "dfab90c6b92c127ab987cc3285557ad9b71ccd29c05bf2024531c54f10f6cf87",
];
/// `[consensus, rules, identity]` (fingerprint v3; RT-FP3; PX-R; RX-SALT). The mainnet
/// parameters are provisional; mainnet is not launched.
const MAINNET: [&str; 3] = [
    "67a1e4b9737ff9d2ea9d5fde6c614fdca1647235bfb7e93796e44c65905af9cb",
    "55353dc42b5f0b5322514c6a8eaba6f20d0c44c19fe001ebc20747f5f59ed612",
    "2dbb1c3703d90367c2d4475adb86a0e57c1d8c6ebe5f698f53baa7ec27465088",
];
