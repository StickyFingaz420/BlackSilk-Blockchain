//! `blacksilk-node`: opens and replays the block store, then serves the local RPC.
//!
//! P2P networking is not part of this build yet (next phase). This node validates
//! and stores blocks from the local miner and serves wallets.

#![forbid(unsafe_code)]

use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::store::FileStore;
use blacksilk_consensus::{ChainParams, Network, RandomXPow};
use blacksilk_node::{default_rpc_port, network_name, router};
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
    let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(bind)
            .await
            .map_err(|e| format!("bind {bind}: {e}"))?;
        log::info!("RPC listening on http://{bind}");
        axum::serve(listener, router(shared))
            .with_graceful_shutdown(async {
                let _ = tokio::signal::ctrl_c().await;
                log::info!("shutting down");
            })
            .await
            .map_err(|e| e.to_string())
    })
}
