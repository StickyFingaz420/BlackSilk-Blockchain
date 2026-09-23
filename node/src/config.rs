//! Node configuration: command line, optional TOML file, built-in defaults.
//!
//! Precedence: command line > configuration file > defaults. Lists (peers,
//! seeds) from the file and the command line are combined.

use blacksilk_consensus::Network;
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
    /// RPC listen address. Loopback by default; the RPC has no authentication.
    #[arg(long)]
    pub rpc_bind: Option<SocketAddr>,
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
    /// Log filter, e.g. info, debug, blacksilk_p2p=debug.
    #[arg(long)]
    pub log: Option<String>,
}

#[derive(Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    network: Option<String>,
    data_dir: Option<PathBuf>,
    rpc_bind: Option<SocketAddr>,
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
}

/// The effective configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub network: Network,
    pub data_dir: PathBuf,
    pub rpc_bind: SocketAddr,
    pub log: String,
    pub p2p: Option<P2pConfig>,
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
            })
        } else {
            None
        };
        Ok(Config {
            network,
            data_dir,
            rpc_bind,
            log,
            p2p,
        })
    }
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

    #[tokio::test]
    async fn seed_resolution() {
        let r = resolve_seeds(&["1.2.3.4:29334".into(), "localhost:29334".into()], false)
            .await
            .unwrap();
        assert!(r.contains(&NetAddr::parse("1.2.3.4:29334").unwrap()));
        assert!(r.len() >= 2, "localhost resolves");
        let onion = format!("{}.onion:29334", "a".repeat(56));
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
