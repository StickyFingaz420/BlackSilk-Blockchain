//! `blacksilk-miner`: mines on a local node's templates with RandomX.

#![forbid(unsafe_code)]

use blacksilk_chain::address::decode_address;
use blacksilk_chain::emission::format_amount;
use blacksilk_consensus::Network;
use blacksilk_miner::{build_block, search, PowContext};
use blacksilk_rpc::{parse_hash, Client, RpcError};
use clap::Parser;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

#[derive(Parser)]
#[command(name = "blacksilk-miner", version, about = "BlackSilk RandomX miner")]
struct Args {
    /// Node RPC address.
    #[arg(long, default_value = "127.0.0.1:29333")]
    node: String,
    /// The node's RPC cookie: `rpc.cookie` in the node's data directory
    /// (docs/blocks.md §9.1). Default: the file named by
    /// BLACKSILK_RPC_COOKIE, if set.
    #[arg(long)]
    rpc_cookie: Option<PathBuf>,
    /// Address that receives block rewards.
    #[arg(long)]
    address: String,
    /// Mining threads (default: all logical CPUs).
    #[arg(long)]
    threads: Option<usize>,
    /// Light mode: 256 MiB instead of the 2 GiB dataset; much slower hashing.
    #[arg(long)]
    light: bool,
    /// Seconds before refreshing the template (new transactions, new tip).
    #[arg(long, default_value_t = 15)]
    refresh: u64,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn network(name: &str) -> Option<Network> {
    match name {
        "mainnet" => Some(Network::Mainnet),
        "testnet" => Some(Network::Testnet),
        "regtest" => Some(Network::Regtest),
        _ => None,
    }
}

/// The build commit, from the `BLACKSILK_BUILD_COMMIT` build-time environment
/// variable. Unlike the node (node/build.rs reads `.git`), this crate has no
/// build script, so a build without the variable reports `unknown`; the
/// release procedure sets it (docs/testnet.md, operator checks).
const BUILD_COMMIT: &str = match option_env!("BLACKSILK_BUILD_COMMIT") {
    Some(c) => c,
    None => "unknown",
};

/// Parses the command line with a `--version` that includes the commit.
fn parse_args() -> Args {
    use clap::{CommandFactory, FromArgMatches};
    // clap takes a `'static` string; this runs once per process.
    let version: &'static str = Box::leak(
        format!("{} (commit {BUILD_COMMIT})", env!("CARGO_PKG_VERSION")).into_boxed_str(),
    );
    let matches = Args::command().version(version).get_matches();
    Args::from_arg_matches(&matches).unwrap_or_else(|e| e.exit())
}

fn main() {
    let args = parse_args();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    if let Err(e) = run(args) {
        log::error!("{e}");
        std::process::exit(1);
    }
}

/// A client for `node` that sends the cookie read from `cookie` (else from
/// BLACKSILK_RPC_COOKIE) with every request.
fn connect(node: &str, cookie: Option<&Path>) -> Result<Client, String> {
    Client::try_new(node)
        .and_then(|c| c.with_cookie_option(cookie))
        .map_err(|e| e.to_string())
}

/// After a `401` the node has probably restarted with a new cookie: read it
/// again.
fn reconnect_on_401(e: &RpcError, client: &mut Client, args: &Args) {
    if !matches!(e, RpcError::Status(401, _)) {
        return;
    }
    match connect(&args.node, args.rpc_cookie.as_deref()) {
        Ok(c) => {
            *client = c;
            log::info!("RPC credential refused; cookie read again");
        }
        Err(e) => log::warn!("{e}"),
    }
}

fn run(args: Args) -> Result<(), String> {
    let mut client = connect(&args.node, args.rpc_cookie.as_deref())?;
    let info = client.info().map_err(|e| match e {
        RpcError::Status(401, _) => format!(
            "{e}: the node requires its RPC cookie; pass --rpc-cookie <node data dir>/{} or set {}",
            blacksilk_rpc::COOKIE_FILE,
            blacksilk_rpc::COOKIE_ENV
        ),
        e => e.to_string(),
    })?;
    let net = network(&info.network).ok_or("unknown network reported by node")?;
    let payout = decode_address(net, &args.address)
        .map_err(|e| format!("--address is not a valid {} address: {e:?}", info.network))?;
    let threads = args
        .threads
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()));
    log::info!(
        "mining on {} at height {} with {threads} threads ({} mode)",
        info.network,
        info.height,
        if args.light { "light" } else { "full" }
    );

    // Secret randomness for coinbase construction (hedged inside the builder).
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| format!("OS RNG: {e}"))?;
    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut hedge = [0u8; 32];
    getrandom::getrandom(&mut hedge).map_err(|e| format!("OS RNG: {e}"))?;
    seed.zeroize();

    let mut pow: Option<PowContext> = None;
    loop {
        let template = match client.template() {
            Ok(t) => t,
            Err(e) => {
                reconnect_on_401(&e, &mut client, &args);
                log::warn!("{e}; retrying in 5 s");
                std::thread::sleep(Duration::from_secs(5));
                continue;
            }
        };
        let seed_id = parse_hash(&template.seed_id).ok_or("bad seed id from node")?;
        if pow.as_ref().map(|p| p.seed()) != Some(&seed_id) {
            let started = Instant::now();
            log::info!(
                "initializing RandomX for seed {}",
                hex::encode(&seed_id[..8])
            );
            drop(pow.take()); // free the old dataset (2 GiB) before building the new one
            pow = Some(PowContext::new(seed_id, !args.light, threads));
            log::info!("RandomX ready in {:.1?}", started.elapsed());
        }
        let block = build_block(&template, &payout, &hedge, now(), &mut rng)
            .map_err(|e| format!("bad template: {e:?}"))?;
        // A fresh random nonce start for every template: a start kept and counted
        // up across templates would let anyone sort block nonces and cluster
        // every block, and so every coinbase output, by miner. Each template has
        // a fresh coinbase, so its header differs and restarting loses nothing.
        let nonce_start = rand_core::RngCore::next_u64(&mut rng);

        // Stop the search after `refresh` seconds to pick up a newer template.
        let stop = Arc::new(AtomicBool::new(false));
        let timer = {
            let stop = stop.clone();
            let secs = args.refresh;
            std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(secs);
                while Instant::now() < deadline && !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(200));
                }
                stop.store(true, Ordering::Relaxed);
            })
        };
        let started = Instant::now();
        let ctx = pow.as_ref().expect("initialized above");
        let (found, hashes) = search(ctx, &block.header, nonce_start, threads, u64::MAX, &stop);
        stop.store(true, Ordering::Relaxed);
        let _ = timer.join();
        log::debug!(
            "{hashes} hashes in {:.1?} ({:.1} H/s)",
            started.elapsed(),
            hashes as f64 / started.elapsed().as_secs_f64().max(1e-3)
        );

        if let Some(f) = found {
            let mut block = block;
            block.header.nonce = f.nonce;
            match client.submit_block(&block.encode()) {
                Ok(r) if r.accepted => log::info!(
                    "found block {} (reward {} BLK, {} txs)",
                    template.height,
                    format_amount(template.reward + template.fees),
                    block.txs.len() - 1
                ),
                Ok(r) => log::warn!(
                    "block {} rejected: {}",
                    template.height,
                    r.error.unwrap_or_default()
                ),
                Err(e) => {
                    log::warn!("submitting block {}: {e}", template.height);
                    reconnect_on_401(&e, &mut client, &args);
                }
            }
        }
    }
}
