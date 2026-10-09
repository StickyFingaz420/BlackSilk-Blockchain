//! `blacksilk-stratum-probe`: the gate's invalid-share client. It hashes with
//! `blacksilk-randomx` light mode itself and expects one exact reply per
//! case; it exits 1 if any case does not get it. An evidence and test tool,
//! not part of the release package.

#![forbid(unsafe_code)]

// W4-GUARD: a fuzz build (`--cfg fuzzing`) compiles fuzz-only code into the
// libraries, and no fuzz target links this binary, so it refuses to build.
#[cfg(fuzzing)]
compile_error!(
    "refusing to build blacksilk-stratum-probe with `--cfg fuzzing`: no fuzz target links it; build it with a plain `cargo build --release`"
);

use blacksilk_chain::address::decode_address;
use blacksilk_consensus::{Hash, Network, PowBlob};
use blacksilk_randomx::{Cache, Vm};
use blacksilk_rpc::Client;
use blacksilk_stratum_bridge::build_guard::{parse_args, require_clean_build};
use blacksilk_stratum_bridge::probe::{self, CaseResult, ProbeClient, PROBE_AGENT};
use blacksilk_stratum_bridge::stratum::ALGO_BLACKSILK;
use clap::{Parser, Subcommand};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "blacksilk-stratum-probe",
    about = "Invalid-share client of the xmrig compatibility gate (regtest; evidence tool)"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Args)]
struct Bridge {
    /// The bridge's address.
    #[arg(long, default_value = "127.0.0.1:3334")]
    bridge: SocketAddr,
    /// Ask for this session floor (`pass` `diff=N`; the bridge needs
    /// --allow-session-diff).
    #[arg(long)]
    diff: Option<u64>,
    /// The node, to check that every rejection leaves its tip unchanged.
    #[arg(long)]
    node: Option<String>,
    #[arg(long)]
    rpc_cookie: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Cases c, a, b, e, d, e2 on one session's current job.
    Cases(Bridge),
    /// Case f: another session's share on a new session (expects `Stale job`).
    Replay {
        #[command(flatten)]
        bridge: Bridge,
        #[arg(long)]
        job_id: String,
        #[arg(long)]
        nonce: String,
        #[arg(long)]
        result: String,
    },
    /// A block that fails its difficulty, straight to the node's /block
    /// (expects InsufficientWork; needs difficulty > 1).
    DirectToNode {
        #[arg(long, default_value = "127.0.0.1:39333")]
        node: String,
        #[arg(long)]
        rpc_cookie: Option<PathBuf>,
        /// A regtest address for the block's coinbase.
        #[arg(long)]
        payout: String,
    },
}

/// Light-mode BlackSilk RandomX, one cache at a time.
fn light_hasher() -> impl FnMut(&Hash, &PowBlob) -> Hash {
    let mut cache: Option<(Hash, Cache)> = None;
    move |seed, blob| {
        if cache.as_ref().is_none_or(|(s, _)| s != seed) {
            cache = None;
            cache = Some((*seed, Cache::new(seed)));
        }
        Vm::light(&cache.as_ref().expect("built").1).hash(blob)
    }
}

fn node_client(node: &str, cookie: Option<&std::path::Path>) -> Client {
    match Client::try_new(node).and_then(|c| c.with_cookie_option(cookie)) {
        Ok(c) => c,
        Err(e) => fail(&format!("node: {e}")),
    }
}

fn fail(m: &str) -> ! {
    eprintln!("error: {m}");
    std::process::exit(2);
}

fn login(b: &Bridge) -> ProbeClient {
    let pass = b.diff.map_or("x".to_string(), |d| format!("diff={d}"));
    match ProbeClient::login(b.bridge, PROBE_AGENT, &[ALGO_BLACKSILK], &pass) {
        Ok(Ok(c)) => c,
        Ok(Err(m)) => fail(&format!("login refused: {m}")),
        Err(e) => fail(&format!("bridge: {e}")),
    }
}

fn report(results: &[CaseResult]) {
    for r in results {
        println!("{}", r.render());
    }
    if results.iter().all(CaseResult::passed) {
        println!("probe: all {} cases PASS", results.len());
    } else {
        println!("probe: FAIL");
        std::process::exit(1);
    }
}

fn main() {
    let args: Args = parse_args();
    let flags = require_clean_build("blacksilk-stratum-probe");
    println!(
        "blacksilk-stratum-probe {}, {flags}",
        env!("CARGO_PKG_VERSION")
    );
    let mut rng = ChaCha20Rng::from_entropy_or_os();
    let mut hasher = light_hasher();
    match args.command {
        Command::Cases(b) => {
            let node = b
                .node
                .as_deref()
                .map(|n| node_client(n, b.rpc_cookie.as_deref()));
            let mut tip = || {
                node.as_ref()
                    .and_then(|c| c.tip(None, 0).ok())
                    .map(|t| t.tip)
            };
            let mut c = login(&b);
            println!("probe session {} job {}", c.session, c.job.job_id);
            match probe::run_cases(&mut c, &mut hasher, &mut tip, &mut rng) {
                Ok(r) => report(&r),
                Err(e) => fail(&format!("bridge: {e}")),
            }
        }
        Command::Replay {
            bridge,
            job_id,
            nonce,
            result,
        } => {
            let node = bridge
                .node
                .as_deref()
                .map(|n| node_client(n, bridge.rpc_cookie.as_deref()));
            let mut tip = || {
                node.as_ref()
                    .and_then(|c| c.tip(None, 0).ok())
                    .map(|t| t.tip)
            };
            let mut c = login(&bridge);
            match probe::replay(&mut c, &job_id, &nonce, &result, &mut tip) {
                Ok(r) => report(&[r]),
                Err(e) => fail(&format!("bridge: {e}")),
            }
        }
        Command::DirectToNode {
            node,
            rpc_cookie,
            payout,
        } => {
            let client = node_client(&node, rpc_cookie.as_deref());
            let payout = decode_address(Network::Regtest, &payout)
                .unwrap_or_else(|e| fail(&format!("--payout: {e:?}")));
            match probe::direct_to_node(&client, &payout, &mut hasher, &mut rng) {
                Ok(r) => report(&[r]),
                Err(e) => fail(&e),
            }
        }
    }
}

/// A ChaCha20 generator seeded from the OS.
trait FromOs {
    fn from_entropy_or_os() -> Self;
}

impl FromOs for ChaCha20Rng {
    fn from_entropy_or_os() -> Self {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("OS randomness");
        ChaCha20Rng::from_seed(seed)
    }
}
