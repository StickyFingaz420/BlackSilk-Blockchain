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
/// fingerprint (network id, genesis, initial difficulty, branch ids) and the
/// **consensus**
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
/// RX-SALT:blacksilk-randomx-argon2-salt; identity unchanged); re-pinned by
/// output-root (all three: the 172-byte header moves every genesis id; the
/// rules gain the output-range and mining-hash tags, the mining-blob
/// constants, their samples and the revision
/// OMR:header-output-mmr-px-root-and-mining-blob, after RX-SALT's); re-pinned
/// once by bs-zk-4 and px-deploy-row-caps together (rules and consensus: the
/// parameter set BS-ZK-4, the regenerated golden PX fixture, the deploy caps
/// and their verdict sample, `PX_MAX_LOG_HEIGHT`, and the revisions
/// ZK:BS-ZK-4-query-grinding-20 and B2:px-deploy-row-caps; identity unchanged);
/// re-pinned by fingerprint-sample-inputs (all three: every rule sample's
/// input is recorded next to its output, the key schedule gains the samples
/// 2E + L and 10E + L that see a dropped `- 1`, and D0 moves from the rules
/// to the identity manifest, so testnet and mainnet share one rules value; no
/// rule, network id, genesis id or D0 value changes); re-pinned by
/// fingerprint-px-samples (rules and consensus: contextual PX verdicts for
/// PX6, PX4 and B8 and block verdicts on the cached path, as boundary pairs;
/// no rule changes; identity unchanged).
const TESTNET: [&str; 3] = [
    "cacbadc8768c15fc399272108e2b9fe7a44b61b638eec9464d8aea4333cba2ca",
    "71a6053f320893f600fd41842cbeddbcf15c547131177b6468a3c6ada0911fa9",
    "fe014b5706d9b0b8737404cb45dd3489efe1a648bb1b10c8f9232308d1d1ee95",
];
/// `[consensus, rules, identity]` (fingerprint v3; RT-FP3; PX-R; RX-SALT;
/// output-root; bs-zk-4 with px-deploy-row-caps; fingerprint-sample-inputs;
/// fingerprint-px-samples).
const REGTEST: [&str; 3] = [
    "f90fef2537cd3d0aabeeeb2e5423c3c289b626d4649e76df031929126b82c889",
    "6ef5370540fe1388fa0fb713bca8bf4465777162f71bf7f61f13799315e469a5",
    "bc72c2dca0607b24ac771c102a6940237fcdf1a54d7294f3047624affda3bf0e",
];
/// `[consensus, rules, identity]` (fingerprint v3; RT-FP3; PX-R; RX-SALT;
/// output-root; bs-zk-4 with px-deploy-row-caps; fingerprint-sample-inputs;
/// fingerprint-px-samples).
/// The mainnet parameters are provisional; mainnet is not launched. Its rules
/// value is the testnet's (fingerprint-sample-inputs).
const MAINNET: [&str; 3] = [
    "d302f55e0f28079a687dacab66001af20edcc517c1324486f3058973a3cdcfac",
    "71a6053f320893f600fd41842cbeddbcf15c547131177b6468a3c6ada0911fa9",
    "70718cc76c9b5305e3e2b524ee286ca9a573b574986b6fab9394935dd9a4759e",
];
