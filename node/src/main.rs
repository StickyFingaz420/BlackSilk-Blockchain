//! `blacksilk-node`: opens and replays the block store, joins the P2P network
//! (docs/p2p.md) and serves the local RPC.

#![forbid(unsafe_code)]

use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::store::FileStore;
use blacksilk_consensus::{ChainParams, Network, RandomXPow};
use blacksilk_node::{default_rpc_port, network_name, router_with, App};
use blacksilk_p2p::{NetAddr, NetConfig, Network as P2p};
use blacksilk_tx::params::TxRules;
use clap::Parser;
use fs2::FileExt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Parser)]
#[command(name = "blacksilk-node", version, about = "BlackSilk node")]
struct Args {
    /// testnet or regtest (mainnet is not launched).
    #[arg(long, default_value = "testnet")]
    network: String,
    /// Data directory (default: the OS data dir, e.g. %APPDATA%\BlackSilk\<network>).
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// RPC listen address. Loopback by default; the RPC has no authentication.
    #[arg(long)]
    rpc_bind: Option<SocketAddr>,
    /// P2P listen address (default 0.0.0.0:<p2p port>; none with --proxy-only).
    #[arg(long)]
    p2p_bind: Option<SocketAddr>,
    /// Do not accept inbound P2P connections.
    #[arg(long)]
    no_listen: bool,
    /// Disable P2P networking entirely (isolated node).
    #[arg(long)]
    no_p2p: bool,
    /// Our publicly reachable address to advertise (IP:port or <onion>.onion:port).
    /// Not set: the node never advertises itself.
    #[arg(long)]
    public_address: Option<String>,
    /// Peer to stay connected to (repeatable).
    #[arg(long = "peer")]
    peers: Vec<String>,
    /// Seed node for initial discovery (repeatable).
    #[arg(long = "seed")]
    seeds: Vec<String>,
    /// SOCKS5 proxy for outbound connections, e.g. Tor at 127.0.0.1:9050.
    #[arg(long)]
    proxy: Option<SocketAddr>,
    /// Only connect through --proxy (no clearnet connections).
    #[arg(long)]
    proxy_only: bool,
    #[arg(long, default_value_t = 8)]
    max_outbound: usize,
    #[arg(long, default_value_t = 64)]
    max_inbound: usize,
}

/// Default P2P port per network (docs/p2p.md §2).
fn default_p2p_port(n: Network) -> u16 {
    default_rpc_port(n) + 1
}

fn parse_addrs(list: &[String], what: &str) -> Result<Vec<NetAddr>, String> {
    list.iter()
        .map(|s| NetAddr::parse(s).ok_or_else(|| format!("bad {what} address {s:?}")))
        .collect()
}

fn parse_network(s: &str) -> Result<Network, String> {
    match s {
        "testnet" => Ok(Network::Testnet),
        "regtest" => Ok(Network::Regtest),
        "mainnet" => Err("mainnet is not launched; its genesis block is not final".into()),
        other => Err(format!(
            "unknown network {other:?} (use testnet or regtest)"
        )),
    }
}

fn params_for(n: Network) -> ChainParams {
    match n {
        Network::Mainnet => ChainParams::mainnet(),
        Network::Testnet => ChainParams::testnet(),
        Network::Regtest => ChainParams::regtest(),
    }
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    if let Err(e) = run(Args::parse()) {
        log::error!("{e}");
        std::process::exit(1);
    }
}

fn run(args: Args) -> Result<(), String> {
    let network = parse_network(&args.network)?;
    let params = params_for(network);
    let data_dir = args.data_dir.unwrap_or_else(|| {
        dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("BlackSilk")
            .join(network_name(network))
    });
    std::fs::create_dir_all(&data_dir).map_err(|e| format!("{}: {e}", data_dir.display()))?;

    // One node per data directory.
    let lock_file = std::fs::File::create(data_dir.join("LOCK")).map_err(|e| e.to_string())?;
    lock_file
        .try_lock_exclusive()
        .map_err(|_| format!("{} is in use by another node", data_dir.display()))?;

    let store = FileStore::open(data_dir.join("blocks.dat")).map_err(|e| e.to_string())?;
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| format!("OS RNG: {e}"))?;
    log::info!("{}: loading {}", network_name(network), data_dir.display());
    let started = std::time::Instant::now();
    let manager = ChainManager::open(
        params.clone(),
        TxRules::for_chain(&params),
        Arc::new(RandomXPow::new()),
        Box::new(store),
        seed,
    )
    .map_err(|e| format!("block store: {e}"))?;
    log::info!(
        "chain loaded in {:.1?}: height {}, tip {}",
        started.elapsed(),
        manager.height(),
        hex::encode(&manager.tip_id()[..8])
    );

    let bind = args
        .rpc_bind
        .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], default_rpc_port(network))));
    if !bind.ip().is_loopback() {
        log::warn!(
            "RPC bound to non-loopback {bind}: it has no authentication; do not expose it publicly"
        );
    }
    let shared = Arc::new(Mutex::new(manager));

    let net_cfg = if args.no_p2p {
        None
    } else {
        let mut cfg = NetConfig::new(params.network_id);
        cfg.listen = if args.no_listen {
            None
        } else {
            match args.p2p_bind {
                Some(a) => Some(a),
                // With --proxy-only, listening on all interfaces would reveal the
                // node's clearnet address; bind explicitly (e.g. for an onion service).
                None if args.proxy_only => None,
                None => Some(SocketAddr::from(([0, 0, 0, 0], default_p2p_port(network)))),
            }
        };
        cfg.public_address = args
            .public_address
            .as_deref()
            .map(|s| NetAddr::parse(s).ok_or(format!("bad --public-address {s:?}")))
            .transpose()?;
        cfg.connect = parse_addrs(&args.peers, "--peer")?;
        cfg.seeds = parse_addrs(&args.seeds, "--seed")?;
        cfg.proxy = args.proxy;
        cfg.proxy_only = args.proxy_only;
        if cfg.proxy_only && cfg.proxy.is_none() {
            return Err("--proxy-only needs --proxy".into());
        }
        cfg.max_outbound = args.max_outbound;
        cfg.max_inbound = args.max_inbound;
        // Regtest runs locally: allow loopback/private peers.
        cfg.allow_private = network == Network::Regtest;
        cfg.data_dir = Some(data_dir.clone());
        Some(cfg)
    };

    let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    runtime.block_on(async move {
        let net = match net_cfg {
            Some(cfg) => {
                let listen = cfg.listen;
                let n = P2p::start(cfg, shared.clone())
                    .await
                    .map_err(|e| format!("P2P: {e}"))?;
                match listen {
                    Some(_) => log::info!("P2P listening on {}", n.local_addr().expect("bound")),
                    None => log::info!("P2P outbound only"),
                }
                Some(n)
            }
            None => {
                log::warn!("P2P disabled (--no-p2p)");
                None
            }
        };
        let listener = tokio::net::TcpListener::bind(bind)
            .await
            .map_err(|e| format!("bind {bind}: {e}"))?;
        log::info!("RPC listening on http://{bind}");
        let app = App {
            chain: shared,
            net: net.clone(),
        };
        let served = axum::serve(listener, router_with(app))
            .with_graceful_shutdown(async {
                let _ = tokio::signal::ctrl_c().await;
                log::info!("shutting down");
            })
            .await
            .map_err(|e| e.to_string());
        if let Some(n) = net {
            n.save();
        }
        served
    })
}
