//! `blacksilk-stratum-bridge`: the xmrig gate's stratum bridge (`serve`) and
//! the offline recompute of its submit log (`recompute`). An evidence and
//! test tool, not part of the release package.

#![forbid(unsafe_code)]

// W4-GUARD: a fuzz build (`--cfg fuzzing`) compiles fuzz-only code into the
// libraries, and no fuzz target links this binary, so it refuses to build.
#[cfg(fuzzing)]
compile_error!(
    "refusing to build blacksilk-stratum-bridge with `--cfg fuzzing`: no fuzz target links it; build it with a plain `cargo build --release`"
);

use blacksilk_consensus::RandomXPow;
use blacksilk_stratum_bridge::build_guard::{parse_args, require_clean_build};
use blacksilk_stratum_bridge::recompute::{recompute, LightHasher, Options};
use blacksilk_stratum_bridge::{submit_log, Bridge, Config};
use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// Exit status of a configuration the operator must fix.
const CONFIG_EXIT_CODE: i32 = 78;

#[derive(Parser)]
#[command(
    name = "blacksilk-stratum-bridge",
    about = "Loopback-only stratum bridge for the xmrig compatibility gate (regtest; evidence tool)"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve stratum on a loopback address in front of a regtest node.
    Serve(Serve),
    /// Recompute every share of a submit log with blacksilk-randomx light
    /// mode; exit 1 on any mismatch or inconsistency.
    Recompute(Recompute),
}

#[derive(clap::Args)]
struct Serve {
    /// Node RPC address (regtest default port).
    #[arg(long, default_value = "127.0.0.1:39333")]
    node: String,
    /// The node's RPC cookie (`rpc.cookie` in its data directory); default:
    /// the file named by BLACKSILK_RPC_COOKIE.
    #[arg(long)]
    rpc_cookie: Option<PathBuf>,
    /// Listen address: loopback only.
    #[arg(long, default_value = "127.0.0.1:3334")]
    listen: SocketAddr,
    /// Regtest address that receives the block rewards.
    #[arg(long)]
    payout: String,
    /// The share-difficulty floor (about 3 x xmrig's hash rate, so the
    /// light-mode verification keeps up).
    #[arg(long)]
    min_share_diff: u64,
    /// Test knob (regtest only): a login `pass` of `diff=N` sets the
    /// session's floor (the probe).
    #[arg(long)]
    allow_session_diff: bool,
    /// Test knob (regtest only): the negative control. Label every job
    /// `rx/0`, never submit a block, identify results as Monero rx/0 hashes.
    #[arg(long, value_name = "ALGO")]
    negative_control_algo: Option<String>,
    /// Every stratum line in and out, with timestamps.
    #[arg(long)]
    log_stratum: Option<PathBuf>,
    /// One JSON line per submit, for `recompute`.
    #[arg(long)]
    log_submits: Option<PathBuf>,
    /// Seconds between job refreshes when the tip does not move.
    #[arg(long, default_value_t = 60)]
    refresh: u64,
}

#[derive(clap::Args)]
struct Recompute {
    /// The submit log (`serve --log-submits`).
    #[arg(long)]
    log: PathBuf,
    /// Only the records whose login agent starts with this. The gate run
    /// uses `XMRig/` (the probe's deliberate bad results would otherwise
    /// count); then every such submission must be recomputable, and at
    /// least one must exist.
    #[arg(long)]
    only_agent: Option<String>,
    /// The log is of a negative-control run: at least one rx/0 record is
    /// required, and every one must be Monero's rx/0 hash.
    #[arg(long)]
    expect_negative_control: bool,
}

fn main() {
    let args: Args = parse_args();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let flags = require_clean_build("blacksilk-stratum-bridge");
    log::info!(
        "blacksilk-stratum-bridge {} commit {}, {flags}",
        env!("CARGO_PKG_VERSION"),
        blacksilk_stratum_bridge::build_guard::BUILD_COMMIT
    );
    match args.command {
        Command::Serve(s) => serve(s),
        Command::Recompute(r) => {
            let (records, bad) = match submit_log::read(&r.log) {
                Ok(x) => x,
                Err(e) => {
                    eprintln!("error: {}: {e}", r.log.display());
                    std::process::exit(CONFIG_EXIT_CODE);
                }
            };
            for line in &bad {
                println!("UNREADABLE line {line}");
            }
            let options = Options {
                only_agent: r.only_agent,
                expect_negative_control: r.expect_negative_control,
            };
            let s = recompute(&records, &options, &mut LightHasher::default());
            print!("{}", s.render());
            if !s.passed() || !bad.is_empty() {
                std::process::exit(1);
            }
        }
    }
}

fn serve(s: Serve) {
    let mut c = Config::new(&s.node, &s.payout);
    c.rpc_cookie = s.rpc_cookie;
    c.listen = s.listen;
    c.min_share_diff = s.min_share_diff;
    c.allow_session_diff = s.allow_session_diff;
    c.negative_control_algo = s.negative_control_algo;
    c.stratum_log = s.log_stratum;
    c.submit_log = s.log_submits;
    c.refresh = Duration::from_secs(s.refresh.max(1));
    // The node's proof of work, as the node binary hashes it.
    match Bridge::start(c, Arc::new(RandomXPow::new())) {
        Ok(_bridge) => loop {
            std::thread::park();
        },
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(CONFIG_EXIT_CODE);
        }
    }
}
