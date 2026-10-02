//! `blacksilk-node`: opens and replays the block store, joins the P2P network
//! (docs/p2p.md) and serves the local RPC.

#![forbid(unsafe_code)]

mod config;

use blacksilk_chain::actor::{self, ActorConfig};
use blacksilk_chain::manager::{
    ChainManager, OperatorMark, OperatorMarked, StorePowCheck, StorePowMismatch,
};
use blacksilk_chain::store::FileStore;
use blacksilk_consensus::{ChainParams, RandomXPow};
use blacksilk_node::fingerprint::{self, consensus_fingerprint, BUILD_COMMIT};
use blacksilk_node::serve::{self, RpcSettings};
use blacksilk_node::{
    datadir, halt_exit_code, halt_message, open_exit_code, overrides, randomx_self_test,
    shutdown_signal, watch_operator_fork, watch_store, App, MiningPolicy, NodeStatus,
    RANDOMX_SELF_TEST_EXIT_CODE,
};
use blacksilk_p2p::{NetConfig, Network as P2p};
use blacksilk_tx::params::TxRules;
use clap::{CommandFactory, FromArgMatches};
use config::{network_name, resolve_seeds, Args, Config};
use fs2::FileExt;
use std::path::Path;
use std::sync::Arc;

/// Parses the command line. `-V` prints the version and commit (and the
/// markers of test-only code compiled in, [`fingerprint::build_flags`]);
/// `--version` adds the build flags line, and the consensus, rules and
/// identity fingerprints and the genesis id of every network, which operators
/// compare before joining a network
/// (docs/testnet.md §2.1). `--print-manifest [NETWORK]` prints the full
/// consensus manifest of one network (default: every network) and exits.
fn parse_args() -> Args {
    // clap takes `'static` strings; this runs once per process.
    let long: &'static str = Box::leak(fingerprint::version_text().into_boxed_str());
    let short: &'static str = Box::leak(
        format!(
            "{} (commit {BUILD_COMMIT}){}",
            fingerprint::VERSION,
            fingerprint::build_flags().suffix()
        )
        .into_boxed_str(),
    );
    let matches = Args::command()
        .version(short)
        .long_version(long)
        .arg(
            clap::Arg::new(PRINT_MANIFEST)
                .long(PRINT_MANIFEST)
                .value_name("NETWORK")
                .num_args(0..=1)
                .help(
                    "Print the consensus manifest (rules and identity entries, their \
                     encodings and fingerprints) of NETWORK (testnet, regtest or mainnet; \
                     default: all) and exit",
                ),
        )
        .get_matches();
    if matches.contains_id(PRINT_MANIFEST) {
        print_manifest(
            matches
                .get_one::<String>(PRINT_MANIFEST)
                .map(String::as_str),
        );
    }
    Args::from_arg_matches(&matches).unwrap_or_else(|e| e.exit())
}

const PRINT_MANIFEST: &str = "print-manifest";

/// `--print-manifest`: prints and exits (0), or exits 2 on an unknown name.
fn print_manifest(network: Option<&str>) -> ! {
    let networks = match network {
        None => fingerprint::NETWORKS.to_vec(),
        Some(name) => match fingerprint::network_by_name(name) {
            Some(n) => vec![n],
            None => {
                eprintln!("unknown network {name:?} (use testnet, regtest or mainnet)");
                std::process::exit(2);
            }
        },
    };
    let texts: Vec<String> = networks
        .into_iter()
        .map(fingerprint::manifest_text)
        .collect();
    print!("{}", texts.join("\n"));
    std::process::exit(0);
}

/// `--randomx-self-test`: the per-device check (docs/testnet.md §2.1).
/// Prints the result and exits 0, or [`RANDOMX_SELF_TEST_EXIT_CODE`].
fn self_test_only() -> ! {
    match randomx_self_test() {
        Ok(took) => {
            println!(
                "RandomX self-test passed: {} reference vectors (light mode, the node's \
                 verification path) in {took:.1?}",
                blacksilk_randomx::self_test::VECTORS.len()
            );
            std::process::exit(0)
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(RANDOMX_SELF_TEST_EXIT_CODE)
        }
    }
}

fn main() {
    let args = parse_args();
    if args.randomx_self_test {
        self_test_only();
    }
    // A binary with test-only code (written by `cargo test`, which unifies
    // dev-dependency features, or by a fuzz build) runs only on regtest: it
    // is never evidence, genesis material or a shared network's node
    // (W4-GUARD). Checked before the network's own gate, so the reason shown
    // is the build. `--require-clean-build` (or BLACKSILK_REQUIRE_CLEAN_BUILD)
    // refuses it on regtest too, for runs that are evidence.
    let require_clean = blacksilk_chain::build_flags::require_clean(args.require_clean_build);
    let cfg = match Config::resolve(args)
        .and_then(|c| {
            fingerprint::build_flags()
                .check_run("blacksilk-node", c.network, require_clean)
                .map(|()| c)
        })
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

/// `--invalidate-block` and `--reconsider-block` (docs/blocks.md §8,
/// docs/testnet.md §9): appends the operator's verdicts to the block store
/// before the chain loads, so they apply to the replay (a block that halts
/// the node at start-up is never validated or applied again) and to every
/// later start. Nothing is written for a verdict already in force.
fn mark_blocks(params: &ChainParams, path: &Path, cfg: &Config) -> Result<(), Stop> {
    let marks: Vec<([u8; 32], OperatorMark)> = cfg
        .invalidate_blocks
        .iter()
        .map(|id| (*id, OperatorMark::Invalidate))
        .chain(
            cfg.reconsider_blocks
                .iter()
                .map(|id| (*id, OperatorMark::Reconsider)),
        )
        .collect();
    if marks.is_empty() {
        return Ok(());
    }
    let mut store = FileStore::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    for (id, mark) in marks {
        let block = hex::encode(id);
        let flag = match mark {
            OperatorMark::Invalidate => "--invalidate-block",
            OperatorMark::Reconsider => "--reconsider-block",
        };
        match ChainManager::mark_stored_block(params, &mut store, id, mark) {
            Ok(OperatorMarked::Appended { height }) => {
                let at = height.map_or_else(
                    || " (not in the block store yet)".to_string(),
                    |h| format!(" at height {h}"),
                );
                match mark {
                    OperatorMark::Invalidate => log::warn!(
                        "{flag}: block {block}{at} is marked invalid by the operator: it and \
                         its descendants are never connected, and the node follows the best \
                         other branch. The verdict is stored in {}; the flag is not needed \
                         again (undo it with --reconsider-block {block})",
                        path.display()
                    ),
                    OperatorMark::Reconsider => log::warn!(
                        "{flag}: the operator's invalidation of block {block}{at} is \
                         cancelled; the block is validated like any other again"
                    ),
                }
            }
            Ok(OperatorMarked::Unchanged) => match mark {
                OperatorMark::Invalidate => log::warn!(
                    "{flag}: block {block} is already marked invalid by the operator; \
                     nothing written"
                ),
                OperatorMark::Reconsider => log::warn!(
                    "{flag}: block {block} is not marked invalid by the operator; nothing \
                     written (a block that breaks a rule stays invalid)"
                ),
            },
            Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {
                return Err(Stop {
                    code: 2,
                    message: format!("{flag} {block}: {e}"),
                })
            }
            Err(e) => {
                return Err(Stop {
                    code: open_exit_code(&e),
                    message: format!("{flag} {block}: block store {}: {e}", path.display()),
                })
            }
        }
    }
    Ok(())
}

fn run(cfg: Config) -> Result<(), Stop> {
    let network = cfg.network;
    let params = ChainParams::for_network(network);
    // Refuse to start on parameters the consensus code was not written for.
    params
        .check()
        .map_err(|e| format!("invalid chain parameters: {e}"))?;
    let data_dir = cfg.data_dir.clone();
    // Owner-only on Unix (docs/testnet.md §4.5).
    datadir::create(&data_dir).map_err(|e| format!("{}: {e}", data_dir.display()))?;

    // One node per data directory.
    let lock_file = datadir::create_file(&data_dir.join("LOCK")).map_err(|e| e.to_string())?;
    lock_file
        .try_lock_exclusive()
        .map_err(|_| format!("{} is in use by another node", data_dir.display()))?;
    // Files an earlier run or a copy left readable by other local users.
    let tightened = datadir::tighten(&data_dir)
        .map_err(|e| format!("{}: permissions: {e}", data_dir.display()))?;
    if !tightened.changed.is_empty() {
        let list: Vec<String> = tightened
            .changed
            .iter()
            .map(|(p, mode)| format!("{} (was {mode:o})", p.display()))
            .collect();
        log::warn!(
            "data directory permissions tightened to owner-only: {}. Other local users could \
             read the node's private files (originated.json lists this node's own \
             transactions; docs/testnet.md §4.5)",
            list.join(", ")
        );
    }
    for (path, why) in &tightened.left {
        log::warn!(
            "{} is readable by other local users ({why}): make the data directory \
             owner-only (docs/testnet.md §4.5)",
            path.display()
        );
    }

    // This build must hash RandomX as the network does before it verifies
    // anything (decisions "Agent 08", TM2-3).
    if cfg.skip_randomx_self_test {
        log::warn!(
            "--skip-randomx-self-test: the RandomX start-up self-test is skipped; a build that \
             fails it verifies blocks differently from the network (for diagnosis only)"
        );
    } else {
        let took = randomx_self_test().map_err(|message| Stop {
            code: RANDOMX_SELF_TEST_EXIT_CODE,
            message,
        })?;
        log::info!(
            "RandomX self-test passed: {} reference vectors (light mode) in {took:.1?}",
            blacksilk_randomx::self_test::VECTORS.len()
        );
    }

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
    mark_blocks(&params, &store_path, &cfg)?;
    let store = FileStore::open(&store_path).map_err(|e| e.to_string())?;
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| format!("OS RNG: {e}"))?;
    // The node's identity. Every device of a network must show the same
    // genesis and fingerprint; the commit tells builds apart (docs/testnet.md).
    let flags = fingerprint::build_flags();
    log::info!(
        "blacksilk-node {} commit {BUILD_COMMIT}, {}",
        fingerprint::VERSION,
        flags.line()
    );
    if !flags.is_clean() {
        log::warn!(
            "this binary has test-only code compiled in ({}): for this repository's \
             regtest tests only, never evidence or a shared network",
            flags.render()
        );
    }
    log::info!(
        "{}: genesis {}, consensus fingerprint {}",
        network_name(network),
        hex::encode(params.genesis_id()),
        hex::encode(consensus_fingerprint(network))
    );
    log::info!("{}: loading {}", network_name(network), data_dir.display());
    // Stored proof-of-work hashes are re-verified: a sample, or all of
    // them (decisions "Agent 01", TM2-5).
    let pow_check = if cfg.verify_store_pow {
        log::info!(
            "--verify-store-pow: every stored proof-of-work hash is recomputed (RandomX, \
             light mode: about as long as verifying the chain's headers during a sync)"
        );
        StorePowCheck::All
    } else {
        StorePowCheck::NODE_DEFAULT
    };
    let started = std::time::Instant::now();
    let mut manager = ChainManager::open_checked(
        params.clone(),
        TxRules::at_height(&params, 0), // base constants; the manager selects rules per height
        Arc::new(RandomXPow::new()),
        Box::new(store),
        seed,
        pow_check,
    )
    .map_err(|e| {
        let forged = e
            .get_ref()
            .is_some_and(|inner| inner.is::<StorePowMismatch>());
        let message = if forged {
            format!(
                "block store {}: {e}. The node refuses to start on it. Keep the data directory \
                 {} unchanged as evidence and report it (docs/testnet-incident-response.md); \
                 to run the node, move the directory aside and let the node resync from its \
                 peers. Never copy a data directory between devices; one restored from a \
                 backup is checked in full with --verify-store-pow (docs/testnet.md §4.5)",
                store_path.display(),
                data_dir.display()
            )
        } else if e.kind() == std::io::ErrorKind::InvalidData {
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
    // The local clock is the only clock consensus reads (the future time
    // limit): refuse a clock that cannot be read or is before genesis, warn
    // when the stored chain is in its future (dossier 04 W4).
    match blacksilk_node::clock_check(
        blacksilk_node::system_clock(),
        &params,
        manager.tip_header().timestamp,
    ) {
        Err(e) => {
            return Err(Stop {
                code: 2,
                message: format!("clock check: {e}"),
            })
        }
        Ok(Some(warning)) => log::warn!("{warning}"),
        Ok(None) => {}
    }
    if cfg.mine_from_stale_tip {
        manager.set_template_latch();
        log::warn!(
            "--mine-from-stale-tip: block templates are served from the start, without \
             waiting to catch up with the network (for a network's first blocks on an old \
             genesis, or after every miner stopped); blocks mined on a tip the network has \
             passed are orphans"
        );
    }
    let mining = MiningPolicy {
        despite_operator_fork: cfg.mine_despite_operator_fork,
    };
    // `/info` lists the operator flags of this run (F48-9).
    let run_overrides = overrides(
        &cfg.invalidate_blocks,
        &cfg.reconsider_blocks,
        mining,
        cfg.mine_from_stale_tip,
        cfg.repair_store,
        cfg.skip_randomx_self_test,
    );
    if mining.despite_operator_fork {
        log::warn!(
            "--mine-despite-operator-fork: block templates are served even while a heavier \
             chain is refused only because of an --invalidate-block verdict"
        );
    }

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
        let mut psk_loaded = false;
        let net = match cfg.p2p {
            Some(p) => {
                let mut nc = NetConfig::new(params.network_id);
                nc.listen = p.listen;
                nc.onion_listen = p.onion_inbound;
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
                if let Some(path) = &p.network_psk_file {
                    nc.network_psk = Some(
                        blacksilk_p2p::transport::NetworkPsk::load(path)
                            .map_err(|e| format!("network PSK file {}: {e}", path.display()))?,
                    );
                    psk_loaded = true;
                    log::info!("P2P: network pre-shared key loaded; only nodes with it can connect");
                }
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
        // A heavier chain refused only because of the operator's verdicts
        // is warned about until it ends (RTW3-8).
        let _fork_watch = watch_operator_fork(&chain, std::time::Duration::from_secs(10), mining);
        let watched = chain.clone();
        let app = App {
            chain,
            net: net.clone(),
            mining,
            status: Arc::new(NodeStatus {
                network_psk_loaded: psk_loaded,
                overrides: run_overrides,
            }),
        };
        let failed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let failed_flag = failed.clone();
        let reason = watched.clone();
        // The authenticated RPC: a fresh cookie in the data directory,
        // connection limits, and the guard (docs/blocks.md §9.1).
        let served = serve::run(listener, app, &data_dir, rpc_settings, async move {
            tokio::select! {
                // Ctrl-C, or SIGTERM on Unix: the same clean stop.
                sig = shutdown_signal() => log::info!("{sig}: shutting down"),
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
