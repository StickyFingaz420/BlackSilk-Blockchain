//! `blacksilk-miner`: mines on a local node's templates with RandomX.

#![forbid(unsafe_code)]

use blacksilk_chain::address::decode_address;
use blacksilk_chain::emission::format_amount;
use blacksilk_consensus::Network;
use blacksilk_miner::{build_block, search, PowContext};
use blacksilk_rpc::{parse_hash, Client};
use clap::Parser;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
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

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    if let Err(e) = run(Args::parse()) {
        log::error!("{e}");
        std::process::exit(1);
    }
}

fn run(args: Args) -> Result<(), String> {
    let client = Client::new(&args.node);
    let info = client.info().map_err(|e| e.to_string())?;
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
    let mut nonce_start = rand_core::RngCore::next_u64(&mut rng);
    loop {
        let template = match client.template() {
            Ok(t) => t,
            Err(e) => {
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
        nonce_start = nonce_start.wrapping_add(hashes);
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
                Err(e) => log::warn!("submitting block {}: {e}", template.height),
            }
        }
    }
}
