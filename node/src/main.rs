//! `blacksilk-node`: opens and replays the block store, joins the P2P network
//! (docs/p2p.md) and serves the local RPC.

#![forbid(unsafe_code)]

mod config;

use blacksilk_chain::actor::{self, ActorConfig};
use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::store::FileStore;
use blacksilk_consensus::{ChainParams, RandomXPow};
use blacksilk_node::fingerprint::{self, consensus_fingerprint, BUILD_COMMIT};
use blacksilk_node::serve::{self, RpcSettings};
use blacksilk_node::{halt_exit_code, halt_message, open_exit_code, watch_store, App};
use blacksilk_p2p::{NetConfig, Network as P2p};
use blacksilk_tx::params::TxRules;
use clap::{CommandFactory, FromArgMatches};
use config::{network_name, resolve_seeds, Args, Config};
use fs2::FileExt;
use std::sync::Arc;

/// Parses the command line. `-V` prints the version and commit; `--version`
/// adds the consensus fingerprint and genesis id of every network, which
/// operators compare before joining a network (docs/testnet.md).
fn parse_args() -> Args {
    // clap takes `'static` strings; this runs once per process.
    let long: &'static str = Box::leak(fingerprint::version_text().into_boxed_str());
    let short: &'static str =
        Box::leak(format!("{} (commit {BUILD_COMMIT})", fingerprint::VERSION).into_boxed_str());
    let matches = Args::command()
        .version(short)
        .long_version(long)
        .get_matches();
    Args::from_arg_matches(&matches).unwrap_or_else(|e| e.exit())
}

fn main() {
    let args = parse_args();
    let cfg = match Config::resolve(args)
        .and_then(|c| config::check_network_enabled(c.network).map(|()| c))
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("configuration error: {e}");
            std::process::exit(2);
        }
    };
    // Millisecond stamps: block races and relay delays are sub-second.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(&cfg.log))
        .format_timestamp_millis()
        .init();
    if let Err(stop) = run(cfg) {
        log::error!("{}", stop.message);
        std::process::exit(stop.code);
    }
}

/// Why the node stopped with an error, and its exit status: 1, or
/// `HALT_EXIT_CODE` when a validated block failed to apply (RTW1B-4).
struct Stop {
    code: i32,
    message: String,
}

impl From<String> for Stop {
    fn from(message: String) -> Self {
        Self { code: 1, message }
    }
}

fn run(cfg: Config) -> Result<(), Stop> {
    let network = cfg.network;
    let params = ChainParams::for_network(network);
    // Refuse to start on parameters the consensus code was not written for.
    params
        .check()
        .map_err(|e| format!("invalid chain parameters: {e}"))?;
    let data_dir = cfg.data_dir.clone();
    std::fs::create_dir_all(&data_dir).map_err(|e| format!("{}: {e}", data_dir.display()))?;

    // One node per data directory.
    let lock_file = std::fs::File::create(data_dir.join("LOCK")).map_err(|e| e.to_string())?;
    lock_file
        .try_lock_exclusive()
        .map_err(|_| format!("{} is in use by another node", data_dir.display()))?;

    let store_path = data_dir.join("blocks.dat");
    if cfg.repair_store {
        log::warn!(
            "--repair-store given: {} is checked, and everything from its first damaged \
             record on is moved aside (remove the flag after this run)",
            store_path.display()
        );
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        match FileStore::repair(&store_path, now).map_err(|e| format!("repair: {e}"))? {
            0 => log::warn!("{}: no damage found, nothing moved", store_path.display()),
            n => log::warn!(
                "{}: {n} bytes set aside; the node resyncs them",
                store_path.display()
            ),
        }
    }
    let store = FileStore::open(&store_path).map_err(|e| e.to_string())?;
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| format!("OS RNG: {e}"))?;
    // The node's identity. Every device of a network must show the same
    // genesis and fingerprint; the commit tells builds apart (docs/testnet.md).
    log::info!(
        "blacksilk-node {} commit {BUILD_COMMIT}",
        fingerprint::VERSION
    );
    log::info!(
        "{}: genesis {}, consensus fingerprint {}",
        network_name(network),
        hex::encode(params.genesis_id()),
        hex::encode(consensus_fingerprint(network))
    );
    log::info!("{}: loading {}", network_name(network), data_dir.display());
    let started = std::time::Instant::now();
    let manager = ChainManager::open(
        params.clone(),
        TxRules::at_height(&params, 0), // base constants; the manager selects rules per height
        Arc::new(RandomXPow::new()),
        Box::new(store),
        seed,
    )
    .map_err(|e| {
        let message = if e.kind() == std::io::ErrorKind::InvalidData {
            format!(
                "block store: {e}. If this reports a corrupt record followed by valid data, \
                 back up the data directory and restart once with --repair-store \
                 (docs/testnet.md §9)"
            )
        } else {
            format!("block store: {e}")
        };
        Stop {
            code: open_exit_code(&e),
            message,
        }
    })?;
    log::info!(
        "chain loaded in {:.1?}: height {}, tip {}",
        started.elapsed(),
        manager.height(),
        hex::encode(&manager.tip_id()[..8])
    );

    let bind = cfg.rpc_bind;
    if !bind.ip().is_loopback() {
        log::warn!(
            "RPC bound to non-loopback {bind}: it is plaintext HTTP, so anyone on the path can \
             read its cookie and every request; keep it on loopback or reach it over SSH, a VPN \
             or Tor (docs/testnet.md §11)"
        );
    }
    let rpc_settings = RpcSettings {
        allow_hosts: cfg.rpc_allow_hosts.clone(),
        ..RpcSettings::default()
    };
    // From here on only the chain actor reaches the manager: RPC and P2P
    // send it commands (docs/p2p.md §10).
    let (chain, actor_thread) = actor::spawn(manager, ActorConfig::default());
    let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    let stopper = chain.clone();
    let result = runtime.block_on(async move {
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
                let n = P2p::start_with(nc, chain.clone())
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
        // A halted node (its block store failed, or a validated block failed
        // to apply) accepts no block but would keep downloading bodies: stop
        // it, so that a restart recovers deterministically (docs/blocks.md
        // §6, §8).
        let store_failed = watch_store(&chain, std::time::Duration::from_secs(2));
        let watched = chain.clone();
        let app = App {
            chain,
            net: net.clone(),
        };
        let failed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let failed_flag = failed.clone();
        let reason = watched.clone();
        // The authenticated RPC: a fresh cookie in the data directory,
        // connection limits, and the guard (docs/blocks.md §9.1).
        let served = serve::run(listener, app, &data_dir, rpc_settings, async move {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => log::info!("shutting down"),
                Ok(()) = store_failed => {
                    failed_flag.store(true, std::sync::atomic::Ordering::SeqCst);
                    log::error!("{}; shutting down", halt_message(&reason));
                }
            }
        })
        .await;
        if let Some(n) = net {
            n.save();
        }
        if failed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(Stop {
                code: halt_exit_code(&watched),
                message: halt_message(&watched),
            });
        }
        Ok(served?)
    });
    // The runtime's tasks (and their handles) end with it; the actor then
    // stops between steps. A drain in progress is left to the replay at the
    // next start (every kept body is on disk: fsync before apply).
    drop(runtime);
    stopper.stop();
    drop(stopper);
    actor_thread.stop_and_join();
    result
}
