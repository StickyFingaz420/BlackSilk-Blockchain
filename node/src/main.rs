//! `blacksilk-node`: opens and replays the block store, joins the P2P network
//! (docs/p2p.md) and serves the local RPC.

#![forbid(unsafe_code)]

mod config;

use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::store::FileStore;
use blacksilk_consensus::{ChainParams, RandomXPow};
use blacksilk_node::{router_with, App};
use blacksilk_p2p::{NetConfig, Network as P2p};
use blacksilk_tx::params::TxRules;
use clap::Parser;
use config::{network_name, resolve_seeds, Args, Config};
use fs2::FileExt;
use std::sync::{Arc, Mutex};

fn main() {
    let args = Args::parse();
    let cfg = match Config::resolve(args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("configuration error: {e}");
            std::process::exit(2);
        }
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(&cfg.log)).init();
    if let Err(e) = run(cfg) {
        log::error!("{e}");
        std::process::exit(1);
    }
}

fn run(cfg: Config) -> Result<(), String> {
    let network = cfg.network;
    let params = ChainParams::for_network(network);
    let data_dir = cfg.data_dir.clone();
    std::fs::create_dir_all(&data_dir).map_err(|e| format!("{}: {e}", data_dir.display()))?;

    // One node per data directory.
    let lock_file = std::fs::File::create(data_dir.join("LOCK")).map_err(|e| e.to_string())?;
    lock_file
        .try_lock_exclusive()
        .map_err(|_| format!("{} is in use by another node", data_dir.display()))?;

    let store = FileStore::open(data_dir.join("blocks.dat")).map_err(|e| e.to_string())?;
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| format!("OS RNG: {e}"))?;
    log::info!(
        "{}: loading {} (genesis {})",
        network_name(network),
        data_dir.display(),
        hex::encode(&params.genesis_id()[..8])
    );
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

    let bind = cfg.rpc_bind;
    if !bind.ip().is_loopback() {
        log::warn!(
            "RPC bound to non-loopback {bind}: it has no authentication; do not expose it publicly"
        );
    }
    let shared = Arc::new(Mutex::new(manager));
    let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    runtime.block_on(async move {
        let net = match cfg.p2p {
            Some(p) => {
                let mut nc = NetConfig::new(params.network_id);
                nc.listen = p.listen;
                nc.public_address = p.public_address;
                nc.connect = resolve_seeds(&p.peers, p.proxy_only).await?;
                nc.connect_only = p.connect_only;
                nc.seeds = resolve_seeds(&p.seeds, p.proxy_only).await?;
                nc.proxy = p.proxy;
                nc.proxy_only = p.proxy_only;
                nc.max_outbound = p.max_outbound;
                nc.max_inbound = p.max_inbound;
                nc.allow_private = p.allow_private;
                nc.data_dir = Some(data_dir.clone());
                if nc.seeds.is_empty() && nc.connect.is_empty() {
                    log::warn!(
                        "no seeds or peers configured: the node can only receive inbound connections"
                    );
                }
                let n = P2p::start(nc, shared.clone())
                    .await
                    .map_err(|e| format!("P2P: {e}"))?;
                match n.local_addr() {
                    Some(a) => log::info!("P2P listening on {a}"),
                    None => log::info!("P2P outbound only"),
                }
                Some(n)
            }
            None => {
                log::warn!("P2P disabled");
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
