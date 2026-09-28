//! Node configuration: command line, optional TOML file, built-in defaults.
//!
//! Precedence: command line > configuration file > defaults. Lists (peers,
//! seeds) from the file and the command line are combined.

use blacksilk_consensus::{ChainParams, Network};
use blacksilk_p2p::NetAddr;
use clap::Parser;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Built-in seed nodes per network (`host:port`, `ip:port` or `<onion>.onion:port`).
///
/// **Testnet operators:** add the long-running public testnet nodes here before
/// release. The lists are empty until real seed hosts exist; publishing made-up
/// addresses would send new nodes to machines nobody controls.
pub fn builtin_seeds(network: Network) -> &'static [&'static str] {
    match network {
        Network::Mainnet => &[],
        Network::Testnet => &[],
        Network::Regtest => &[],
    }
}

#[derive(Parser, Debug, Default)]
#[command(name = "blacksilk-node", version, about = "BlackSilk node")]
pub struct Args {
    /// TOML configuration file (see deploy/config/*.toml).
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// testnet or regtest (mainnet is not launched).
    #[arg(long)]
    pub network: Option<String>,
    /// Data directory (default: the OS data dir, e.g. %APPDATA%\BlackSilk\<network>).
    #[arg(long)]
    pub data_dir: Option<PathBuf>,
    /// RPC listen address. Loopback by default: every request needs the
    /// node's cookie (<data dir>/rpc.cookie), but the RPC is plaintext HTTP.
    #[arg(long)]
    pub rpc_bind: Option<SocketAddr>,
    /// Extra host name the RPC answers to besides loopback and its bound
    /// address, e.g. an onion service name (repeatable).
    #[arg(long = "rpc-allow-host")]
    pub rpc_allow_hosts: Vec<String>,
    /// P2P listen address (default 0.0.0.0:<p2p port>; none with --proxy-only).
    #[arg(long)]
    pub p2p_bind: Option<SocketAddr>,
    /// Do not accept inbound P2P connections.
    #[arg(long)]
    pub no_listen: bool,
    /// Disable P2P networking entirely (isolated node).
    #[arg(long)]
    pub no_p2p: bool,
    /// Our publicly reachable address to advertise (IP:port or <onion>.onion:port).
    #[arg(long)]
    pub public_address: Option<String>,
    /// Peer to stay connected to (repeatable).
    #[arg(long = "peer")]
    pub peers: Vec<String>,
    /// Connect only to --peer entries (no seeds, no discovered addresses).
    #[arg(long)]
    pub connect_only: bool,
    /// Seed node for discovery (repeatable; host:port, ip:port or onion).
    #[arg(long = "seed")]
    pub seeds: Vec<String>,
    /// Do not use the built-in seed list.
    #[arg(long)]
    pub no_builtin_seeds: bool,
    /// SOCKS5 proxy for outbound connections, e.g. Tor at 127.0.0.1:9050.
    #[arg(long)]
    pub proxy: Option<SocketAddr>,
    /// Only connect through --proxy (no clearnet connections).
    #[arg(long)]
    pub proxy_only: bool,
    #[arg(long)]
    pub max_outbound: Option<usize>,
    #[arg(long)]
    pub max_inbound: Option<usize>,
    /// Accept and dial private/loopback peer addresses (LAN or lab testnets only).
    #[arg(long)]
    pub allow_private: bool,
    /// File holding the network pre-shared key (64 hex characters): only
    /// nodes with the same key can connect (private testnets; docs/p2p.md §3).
    #[arg(long)]
    pub network_psk_file: Option<PathBuf>,
    /// Log filter, e.g. info, debug, blacksilk_p2p=debug.
    #[arg(long)]
    pub log: Option<String>,
    /// Repair a block store that refuses to load because of damage followed by
    /// valid data: the damaged part is moved to blocks.dat.damaged-<time>, the
    /// store is truncated there, and the dropped blocks are downloaded again.
    /// Command line only; use it only after that load error (docs/testnet.md §9).
    #[arg(long)]
    pub repair_store: bool,
    /// Mark the block with this id (64 hex characters) invalid before the
    /// chain loads: it and its descendants are never connected, and the
    /// node follows the best other branch. The verdict is stored in
    /// blocks.dat, so the flag is needed once (repeatable; command line
    /// only; docs/testnet.md §9).
    #[arg(long = "invalidate-block", value_name = "BLOCK_ID")]
    pub invalidate_blocks: Vec<String>,
    /// Cancel an earlier --invalidate-block of the block with this id
    /// (repeatable; command line only).
    #[arg(long = "reconsider-block", value_name = "BLOCK_ID")]
    pub reconsider_blocks: Vec<String>,
}

#[derive(Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    network: Option<String>,
    data_dir: Option<PathBuf>,
    rpc_bind: Option<SocketAddr>,
    #[serde(default)]
    rpc_allow_hosts: Vec<String>,
    log: Option<String>,
    #[serde(default)]
    p2p: FileP2p,
}

#[derive(Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
struct FileP2p {
    enabled: Option<bool>,
    bind: Option<SocketAddr>,
    listen: Option<bool>,
    public_address: Option<String>,
    #[serde(default)]
    peers: Vec<String>,
    #[serde(default)]
    seeds: Vec<String>,
    connect_only: Option<bool>,
    builtin_seeds: Option<bool>,
    proxy: Option<SocketAddr>,
    proxy_only: Option<bool>,
    max_outbound: Option<usize>,
    max_inbound: Option<usize>,
    allow_private: Option<bool>,
    network_psk_file: Option<PathBuf>,
}

/// The effective configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub network: Network,
    pub data_dir: PathBuf,
    pub rpc_bind: SocketAddr,
    /// Host names the RPC guard accepts besides loopback and the bound
    /// address (file and command line combined).
    pub rpc_allow_hosts: Vec<String>,
    pub log: String,
    pub p2p: Option<P2pConfig>,
    pub repair_store: bool,
    /// Blocks the operator invalidates, then reconsiders, before the chain
    /// loads (`--invalidate-block`, `--reconsider-block`).
    pub invalidate_blocks: Vec<[u8; 32]>,
    pub reconsider_blocks: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct P2pConfig {
    pub listen: Option<SocketAddr>,
    pub public_address: Option<NetAddr>,
    pub peers: Vec<String>,
    pub connect_only: bool,
    /// Seed entries, not yet resolved (see [`resolve_seeds`]).
    pub seeds: Vec<String>,
    pub proxy: Option<SocketAddr>,
    pub proxy_only: bool,
    pub max_outbound: usize,
    pub max_inbound: usize,
    pub allow_private: bool,
    /// The network pre-shared key's file, loaded at start
    /// (`blacksilk_p2p::transport::NetworkPsk::load`).
    pub network_psk_file: Option<PathBuf>,
}

/// Refuses to run a network whose genesis is not final (called at start-up).
/// Finality is consensus's [`ChainParams::genesis_is_final`]: regtest always,
/// testnet and mainnet only once their beacon is committed. The testnet v2
/// identity (`0x0001D672`) is retired, and the testnet stays disabled until
/// the v3 genesis is final (docs/testnet.md).
pub fn check_network_enabled(n: Network) -> Result<(), String> {
    if ChainParams::for_network(n).genesis_is_final() {
        Ok(())
    } else {
        Err(format!(
            "the {} is disabled until its v3 genesis is final (v2 is retired); use --network regtest",
            network_name(n)
        ))
    }
}

pub fn parse_network(s: &str) -> Result<Network, String> {
    match s {
        "testnet" => Ok(Network::Testnet),
        "regtest" => Ok(Network::Regtest),
        "mainnet" => Err("mainnet is not launched; its genesis block is not final".into()),
        other => Err(format!(
            "unknown network {other:?} (use testnet or regtest)"
        )),
    }
}

pub fn network_name(n: Network) -> &'static str {
    blacksilk_node::network_name(n)
}

/// Default ports: RPC 19333/29333/39333, P2P one above (docs/p2p.md §2).
pub fn default_p2p_port(n: Network) -> u16 {
    blacksilk_node::default_rpc_port(n) + 1
}

fn read_file(path: &Path) -> Result<FileConfig, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

impl Config {
    /// Merges command line, configuration file and defaults.
    pub fn resolve(args: Args) -> Result<Config, String> {
        let file = match &args.config {
            Some(p) => read_file(p)?,
            None => FileConfig::default(),
        };
        let network = parse_network(
            args.network
                .as_deref()
                .or(file.network.as_deref())
                .unwrap_or("testnet"),
        )?;
        let data_dir = args.data_dir.or(file.data_dir).unwrap_or_else(|| {
            dirs::data_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("BlackSilk")
                .join(network_name(network))
        });
        let rpc_bind = args.rpc_bind.or(file.rpc_bind).unwrap_or_else(|| {
            SocketAddr::from(([127, 0, 0, 1], blacksilk_node::default_rpc_port(network)))
        });
        let mut rpc_allow_hosts = file.rpc_allow_hosts;
        rpc_allow_hosts.extend(args.rpc_allow_hosts);
        for h in &rpc_allow_hosts {
            let name = h.trim().trim_end_matches('.');
            let valid = !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
            if !valid {
                return Err(format!(
                    "rpc allow host {h:?}: a host name without port (letters, digits, '.', '-')"
                ));
            }
        }
        rpc_allow_hosts.dedup();
        let log = args.log.or(file.log).unwrap_or_else(|| "info".into());

        let f = file.p2p;
        let enabled = !args.no_p2p && f.enabled.unwrap_or(true);
        let p2p = if enabled {
            let proxy = args.proxy.or(f.proxy);
            let proxy_only = args.proxy_only || f.proxy_only.unwrap_or(false);
            if proxy_only && proxy.is_none() {
                return Err("proxy_only needs a proxy".into());
            }
            let listen_enabled = !args.no_listen && f.listen.unwrap_or(true);
            let listen = if !listen_enabled {
                None
            } else {
                match args.p2p_bind.or(f.bind) {
                    Some(a) => Some(a),
                    // Listening on all interfaces would reveal a Tor-only node's
                    // clearnet address; require an explicit bind (e.g. an onion service).
                    None if proxy_only => None,
                    None => Some(SocketAddr::from(([0, 0, 0, 0], default_p2p_port(network)))),
                }
            };
            let public_address = args
                .public_address
                .or(f.public_address)
                .map(|s| NetAddr::parse(&s).ok_or(format!("bad public address {s:?}")))
                .transpose()?;
            let mut peers = f.peers;
            peers.extend(args.peers);
            let mut seeds = f.seeds;
            seeds.extend(args.seeds);
            if !args.no_builtin_seeds && f.builtin_seeds.unwrap_or(true) {
                seeds.extend(builtin_seeds(network).iter().map(|s| s.to_string()));
            }
            seeds.dedup();
            let connect_only = args.connect_only || f.connect_only.unwrap_or(false);
            if connect_only && peers.is_empty() {
                return Err("connect_only needs at least one peer".into());
            }
            Some(P2pConfig {
                listen,
                public_address,
                peers,
                connect_only,
                seeds,
                proxy,
                proxy_only,
                max_outbound: args.max_outbound.or(f.max_outbound).unwrap_or(8),
                max_inbound: args.max_inbound.or(f.max_inbound).unwrap_or(64),
                // Regtest is local by nature.
                allow_private: args.allow_private
                    || f.allow_private.unwrap_or(network == Network::Regtest),
                network_psk_file: args.network_psk_file.or(f.network_psk_file),
            })
        } else {
            None
        };
        let invalidate_blocks = parse_block_ids("--invalidate-block", &args.invalidate_blocks)?;
        let reconsider_blocks = parse_block_ids("--reconsider-block", &args.reconsider_blocks)?;
        if let Some(both) = invalidate_blocks
            .iter()
            .find(|id| reconsider_blocks.contains(id))
        {
            return Err(format!(
                "block {} is given to both --invalidate-block and --reconsider-block",
                hex::encode(both)
            ));
        }
        Ok(Config {
            network,
            data_dir,
            rpc_bind,
            rpc_allow_hosts,
            log,
            p2p,
            repair_store: args.repair_store,
            invalidate_blocks,
            reconsider_blocks,
        })
    }
}

/// Block ids given to `flag`: 64 hex characters each (a block id as the
/// RPC and the logs print it in full).
fn parse_block_ids(flag: &str, ids: &[String]) -> Result<Vec<[u8; 32]>, String> {
    ids.iter()
        .map(|s| {
            let s = s.trim();
            hex::decode(s)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .ok_or_else(|| format!("{flag} {s:?}: expected a block id of 64 hex characters"))
        })
        .collect()
}

/// Resolves seed and peer entries to addresses. Literal IPs and onion addresses are
/// used as is. Host names are looked up with system DNS, except in proxy-only mode:
/// a local DNS lookup would reveal to the resolver that this host runs a node.
pub async fn resolve_seeds(entries: &[String], proxy_only: bool) -> Result<Vec<NetAddr>, String> {
    let mut out = Vec::new();
    for e in entries {
        if let Some(a) = NetAddr::parse(e) {
            out.push(a);
            continue;
        }
        if proxy_only {
            return Err(format!(
                "{e}: host names are not resolved in proxy-only mode (local DNS would leak); \
                 use an IP or .onion address"
            ));
        }
        match tokio::net::lookup_host(e.as_str()).await {
            Ok(addrs) => {
                let before = out.len();
                out.extend(addrs.take(4).map(NetAddr::Ip));
                if out.len() == before {
                    log::warn!("seed {e}: no addresses");
                }
            }
            Err(err) => log::warn!("seed {e}: {err}"),
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

#[cfg(test)]
mod tests {

    #[test]
    fn retired_testnet_identity_is_refused_until_v3() {
        assert!(check_network_enabled(Network::Testnet).is_err());
        assert!(check_network_enabled(Network::Regtest).is_ok());
        assert!(parse_network("mainnet").is_err());
        // The node's gate is consensus's finality, for every network.
        for n in [Network::Mainnet, Network::Testnet, Network::Regtest] {
            assert_eq!(
                check_network_enabled(n).is_ok(),
                ChainParams::for_network(n).genesis_is_final()
            );
        }
    }

    #[test]
    fn rpc_allow_hosts_from_file_and_command_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.toml");
        std::fs::write(
            &path,
            "network = \"regtest\"\nrpc_allow_hosts = [\"a.onion\"]\n",
        )
        .unwrap();
        let p = path.to_str().unwrap();
        let c = Config::resolve(args(&["--config", p, "--rpc-allow-host", "node.lan"])).unwrap();
        assert_eq!(c.rpc_allow_hosts, vec!["a.onion", "node.lan"]);
        assert!(Config::resolve(args(&[]))
            .unwrap()
            .rpc_allow_hosts
            .is_empty());
        for bad in ["node.lan:80", "", "a b", "[::1]"] {
            assert!(
                Config::resolve(args(&["--rpc-allow-host", bad])).is_err(),
                "{bad:?}"
            );
        }
        // Unknown keys are still refused.
        std::fs::write(&path, "rpc_allow_host = [\"a.onion\"]\n").unwrap();
        assert!(Config::resolve(args(&["--config", p])).is_err());
    }

    /// W2-30 PSK: the key file comes from `[p2p] network_psk_file` or
    /// `--network-psk-file`, the command line winning; none by default.
    #[test]
    fn the_network_psk_file_comes_from_the_file_or_the_command_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.toml");
        std::fs::write(
            &path,
            "network = \"regtest\"\n[p2p]\nnetwork_psk_file = \"file.psk\"\n",
        )
        .unwrap();
        let p = path.to_str().unwrap();
        let psk = |c: Config| c.p2p.unwrap().network_psk_file;
        assert_eq!(
            psk(Config::resolve(args(&["--config", p])).unwrap()),
            Some(PathBuf::from("file.psk"))
        );
        assert_eq!(
            psk(Config::resolve(args(&["--config", p, "--network-psk-file", "cli.psk"])).unwrap()),
            Some(PathBuf::from("cli.psk"))
        );
        assert_eq!(psk(Config::resolve(args(&[])).unwrap()), None);
    }
    use super::*;

    fn args(v: &[&str]) -> Args {
        let mut all = vec!["blacksilk-node"];
        all.extend_from_slice(v);
        Args::parse_from(all)
    }

    #[test]
    fn defaults() {
        let c = Config::resolve(args(&[])).unwrap();
        assert_eq!(c.network, Network::Testnet);
        assert_eq!(c.rpc_bind, "127.0.0.1:29333".parse().unwrap());
        let p = c.p2p.unwrap();
        assert_eq!(p.listen, Some("0.0.0.0:29334".parse().unwrap()));
        assert!(!p.allow_private);
        assert_eq!(p.max_outbound, 8);
        assert!(p.public_address.is_none(), "never advertised by default");
    }

    #[test]
    fn file_then_command_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.toml");
        std::fs::write(
            &path,
            r#"
network = "regtest"
rpc_bind = "127.0.0.1:5000"
[p2p]
bind = "127.0.0.1:5001"
peers = ["10.0.0.1:39334"]
seeds = ["seed.example:39334"]
max_outbound = 3
"#,
        )
        .unwrap();
        let p = path.to_str().unwrap();
        let c = Config::resolve(args(&[
            "--config",
            p,
            "--peer",
            "10.0.0.2:39334",
            "--max-outbound",
            "5",
        ]))
        .unwrap();
        assert_eq!(c.network, Network::Regtest);
        assert_eq!(c.rpc_bind, "127.0.0.1:5000".parse().unwrap());
        let n = c.p2p.unwrap();
        assert_eq!(n.listen, Some("127.0.0.1:5001".parse().unwrap()));
        assert_eq!(n.peers, vec!["10.0.0.1:39334", "10.0.0.2:39334"]);
        assert_eq!(n.max_outbound, 5, "command line wins");
        assert!(n.allow_private, "regtest default");
        assert!(n.seeds.contains(&"seed.example:39334".to_string()));
    }

    #[test]
    fn errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, "netwrk = \"testnet\"\n").unwrap();
        assert!(
            Config::resolve(args(&["--config", path.to_str().unwrap()])).is_err(),
            "typos are errors"
        );
        assert!(Config::resolve(args(&["--network", "mainnet"])).is_err());
        assert!(Config::resolve(args(&["--proxy-only"])).is_err());
    }

    #[test]
    fn proxy_only_does_not_listen_on_clearnet_by_default() {
        let c = Config::resolve(args(&["--proxy", "127.0.0.1:9050", "--proxy-only"])).unwrap();
        assert_eq!(c.p2p.unwrap().listen, None);
    }

    /// `--invalidate-block` and `--reconsider-block` take full 64-hex block
    /// ids (repeatable); anything else, or one id given to both, is refused.
    #[test]
    fn operator_block_flags() {
        let a = "ab".repeat(32);
        let b = "0C".repeat(32);
        let c = Config::resolve(args(&[
            "--invalidate-block",
            &a,
            "--invalidate-block",
            &b,
            "--reconsider-block",
            &"01".repeat(32),
        ]))
        .unwrap();
        assert_eq!(c.invalidate_blocks, vec![[0xab; 32], [0x0c; 32]]);
        assert_eq!(c.reconsider_blocks, vec![[0x01; 32]]);
        assert!(Config::resolve(args(&[]))
            .unwrap()
            .invalidate_blocks
            .is_empty());
        for bad in ["abcd", &"ab".repeat(33), &"zz".repeat(32), ""] {
            let err = Config::resolve(args(&["--invalidate-block", bad])).unwrap_err();
            assert!(err.contains("64 hex characters"), "{err}");
        }
        let err = Config::resolve(args(&["--invalidate-block", &a, "--reconsider-block", &a]))
            .unwrap_err();
        assert!(err.contains("both"), "{err}");
    }

    #[tokio::test]
    async fn seed_resolution() {
        let r = resolve_seeds(&["1.2.3.4:29334".into(), "localhost:29334".into()], false)
            .await
            .unwrap();
        assert!(r.contains(&NetAddr::parse("1.2.3.4:29334").unwrap()));
        assert!(r.len() >= 2, "localhost resolves");
        let onion =
            "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion:29334".to_string();
        assert_eq!(
            resolve_seeds(std::slice::from_ref(&onion), true)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(
            resolve_seeds(&["seed.example:1".into()], true)
                .await
                .is_err(),
            "no DNS in proxy-only mode"
        );
    }
}
