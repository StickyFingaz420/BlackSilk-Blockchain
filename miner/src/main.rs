//! `blacksilk-miner`: mines on a local node's templates with RandomX.

#![forbid(unsafe_code)]

// W4-GUARD: a fuzz build (`--cfg fuzzing`) compiles fuzz-only code into the
// libraries (the transport's fixed ephemeral secrets on request), and no fuzz
// target links this binary (fuzz/Cargo.toml), so it refuses to build. A
// `compile_error!`, not a build script: a build script would be more
// build-time code, and cargo-deny then scans every dependency's files.
#[cfg(fuzzing)]
compile_error!(
    "refusing to build blacksilk-miner with `--cfg fuzzing`: no fuzz target links it; build it with a plain `cargo build --release`"
);

use blacksilk_chain::address::decode_address;
use blacksilk_chain::build_flags::BuildFlags;
use blacksilk_chain::emission::format_amount;
use blacksilk_consensus::Network;
use blacksilk_crypto::keys::Address;
use blacksilk_miner::{
    build_block, search, ContextBuilder, PowContext, RandomXBuilder, SeedPlan, SeedPlanner,
    TipSignal, TipSource, TipWatcher, TIP_WAIT_SECS,
};
use blacksilk_rpc::{self as rpc, parse_hash, Client, RpcError};
use clap::{Parser, ValueEnum};
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
    /// Address that receives block rewards (required to mine).
    #[arg(long, required_unless_present = "randomx_self_test")]
    address: Option<String>,
    /// Mining threads (default: all logical CPUs).
    #[arg(long)]
    threads: Option<usize>,
    /// Light mode: 256 MiB instead of the 2 GiB dataset; much slower hashing.
    #[arg(long)]
    light: bool,
    /// Build the next RandomX key's context in the background during the 64
    /// blocks before a key switch, so full-mode mining continues at the
    /// switch (peak memory about 4.4 GiB: two datasets and a cache).
    /// `auto` (the default): on in full mode; if the second dataset cannot
    /// be allocated, off for the rest of the run, and at a switch the miner
    /// mines in light mode while the new dataset is built. `on`: also in
    /// light mode, and without the fallback. `off`: the light-mode bridge
    /// only (docs/testnet.md §5). A bare `--prebuild` means `on`.
    #[arg(long, value_enum, default_value = "auto", num_args = 0..=1, default_missing_value = "on")]
    prebuild: Prebuild,
    /// Threads that build a RandomX dataset in the background (default: a
    /// quarter of the mining threads, at least 1). The first dataset, built
    /// before any hashing, uses all mining threads.
    #[arg(long)]
    build_threads: Option<usize>,
    /// Seconds before refreshing the template (new transactions). A new tip
    /// ends the work at once: the miner long-polls the node's `/tip`.
    #[arg(long, default_value_t = 15)]
    refresh: u64,
    /// Refuse to mine if this binary has test-only code compiled in, on
    /// regtest too (for runs that are evidence; also the environment variable
    /// BLACKSILK_REQUIRE_CLEAN_BUILD=1).
    #[arg(long)]
    require_clean_build: bool,
    /// Run only the RandomX self-test and exit: 0 on a match, 71 on a
    /// mismatch. The reference vectors in light mode, then (without
    /// --light) in full mode, building a 2 GiB dataset per test key
    /// (minutes): the per-device check before a trial (docs/testnet.md §5).
    #[arg(long)]
    randomx_self_test: bool,
    /// Mine without the RandomX start-up self-test (for diagnosis only: a
    /// build that fails it mines blocks the network rejects).
    #[arg(long)]
    skip_randomx_self_test: bool,
}

/// `--prebuild` (decisions "W2-09").
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Prebuild {
    Auto,
    On,
    Off,
}

impl Prebuild {
    fn plan(self, full: bool) -> SeedPlan {
        match self {
            Prebuild::Auto => SeedPlan {
                full,
                prebuild: full,
                fallback: true,
            },
            Prebuild::On => SeedPlan {
                full,
                prebuild: true,
                fallback: false,
            },
            Prebuild::Off => SeedPlan {
                full,
                prebuild: false,
                fallback: false,
            },
        }
    }
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

/// Exit status for a configuration the operator must fix (EX_CONFIG): a
/// payout address that is not valid on the node's network, a network
/// this miner does not know, or a binary with test-only code on a network
/// other than regtest (W4-GUARD). A restart cannot help, so the systemd unit
/// does not restart on it (`RestartPreventExitStatus`, RTW1B-4). Every
/// other failure exits with 1 and is restarted.
const CONFIG_EXIT_CODE: i32 = 78;

/// Exit status when the RandomX self-test fails (the node's
/// `RANDOMX_SELF_TEST_EXIT_CODE`, 71, `EX_OSERR`): this build hashes
/// differently from the reference, so every block it mines would be
/// rejected. A restart cannot help; the systemd unit does not restart on it.
const SELF_TEST_EXIT_CODE: i32 = 71;

/// Pause before retrying after a failed round: the node is unreachable,
/// busy (`503`), or served a template this miner cannot use.
const RETRY_AFTER: Duration = Duration::from_secs(5);

/// How often the hash rate is logged at info level.
const HASHRATE_EVERY: Duration = Duration::from_secs(60);

/// Parses the command line with a `--version` that includes the commit and the
/// markers of test-only code compiled in ([`BuildFlags`], W4-GUARD).
fn parse_args() -> Args {
    use clap::{CommandFactory, FromArgMatches};
    // clap takes `'static` strings; this runs once per process.
    let (short, long) =
        BuildFlags::of_chain_layer().version_texts(env!("CARGO_PKG_VERSION"), BUILD_COMMIT);
    let short: &'static str = Box::leak(short.into_boxed_str());
    let long: &'static str = Box::leak(long.into_boxed_str());
    let matches = Args::command()
        .version(short)
        .long_version(long)
        .get_matches();
    Args::from_arg_matches(&matches).unwrap_or_else(|e| e.exit())
}

/// Why the miner stopped.
enum Fatal {
    /// The operator must change the configuration ([`CONFIG_EXIT_CODE`]).
    Config(String),
    /// The RandomX self-test failed ([`SELF_TEST_EXIT_CODE`]).
    SelfTest(String),
    /// Anything else (exit status 1).
    Other(String),
}

/// The operator's message for a failed RandomX self-test.
fn self_test_message(what: &str) -> String {
    format!(
        "RandomX self-test failed: {what}. This build of the miner hashes differently from \
         the reference, so the node rejects every block it finds. Do not run it: rebuild \
         with the documented toolchain (tools/release-build.sh) and report the device (CPU, \
         OS, toolchain) and this line (docs/testnet.md §5)"
    )
}

/// First and longest pause of [`wait_for_node`].
const NODE_WAIT_FIRST: Duration = Duration::from_secs(5);
const NODE_WAIT_MAX: Duration = Duration::from_secs(60);

/// The pause after `d`: doubled, at most [`NODE_WAIT_MAX`].
fn next_wait(d: Duration) -> Duration {
    (d * 2).min(NODE_WAIT_MAX)
}

/// Connects to the node and reads its `/info`, waiting while it is not up
/// yet (its cookie missing, the RPC not answering, a `401` from a cookie
/// being replaced), with a growing pause (5 s doubling to 60 s), instead of
/// exiting: a miner started with or before its node keeps its process, so
/// the start-up self-test runs once (RT-NODEOPS). Only a malformed node
/// address is a configuration error.
fn wait_for_node(node: &str, cookie: Option<&Path>) -> Result<(Client, rpc::Info), Fatal> {
    Client::try_new(node).map_err(|e| Fatal::Config(e.to_string()))?;
    let mut wait = NODE_WAIT_FIRST;
    loop {
        let why = match connect(node, cookie) {
            Err(e) => e,
            Ok(c) => match c.info() {
                Ok(info) => return Ok((c, info)),
                Err(e @ RpcError::Status(401, _)) => format!(
                    "{e}: the node refused the RPC cookie; pass --rpc-cookie <node data \
                     dir>/{} or set {}",
                    blacksilk_rpc::COOKIE_FILE,
                    blacksilk_rpc::COOKIE_ENV
                ),
                Err(e) => e.to_string(),
            },
        };
        log::warn!(
            "waiting for the node at {node}: {why}; retrying in {} s",
            wait.as_secs()
        );
        std::thread::sleep(wait);
        wait = next_wait(wait);
    }
}

/// Set when the operator skipped the RandomX self-test: every hash-rate
/// line says so (RT-NODEOPS: an override must stay visible).
static SELF_TEST_SKIPPED: AtomicBool = AtomicBool::new(false);

/// The start-up self-test (decisions "Agent 08", TM2-3): the reference
/// vectors and BlackSilk's (`START_UP_VECTORS`) in light mode, the code
/// every node verifies with and this miner mines with in light mode. A full-mode dataset is checked against its
/// cache whenever one is built (`PowContext::try_new`).
fn start_up_self_test(skip: bool) -> Result<(), Fatal> {
    if skip {
        SELF_TEST_SKIPPED.store(true, Ordering::Relaxed);
        log::warn!(
            "--skip-randomx-self-test: the RandomX start-up self-test is skipped (for \
             diagnosis only); a build that fails it mines blocks the node rejects"
        );
        return Ok(());
    }
    let took = blacksilk_randomx::self_test::self_test_light()
        .map_err(|m| Fatal::SelfTest(self_test_message(&m.to_string())))?;
    log::info!(
        "RandomX self-test passed: {} known answers (reference and BlackSilk, light mode) in \
         {took:.1?}",
        blacksilk_randomx::self_test::START_UP_VECTORS.len()
    );
    Ok(())
}

/// `--randomx-self-test`: light mode, then full mode unless `light`.
fn self_test_only(light: bool, threads: usize) -> Result<(), Fatal> {
    use blacksilk_randomx::self_test::{check_full, START_UP_VECTORS};
    start_up_self_test(false)?;
    if !light {
        log::info!(
            "full mode: building a 2 GiB dataset for each of the test keys on {threads} \
             threads (minutes)"
        );
        let took = check_full(&START_UP_VECTORS, threads)
            .map_err(|m| Fatal::SelfTest(self_test_message(&m.to_string())))?;
        log::info!(
            "RandomX self-test passed: {} known answers (reference and BlackSilk, full mode) \
             in {took:.1?}",
            START_UP_VECTORS.len()
        );
    }
    Ok(())
}

fn main() {
    let args = parse_args();
    // Millisecond stamps: block races and relay delays are sub-second.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();
    let result = if args.randomx_self_test {
        let threads = args
            .threads
            .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()))
            .max(1);
        self_test_only(args.light, threads)
    } else {
        run(args)
    };
    match result {
        Ok(()) => {}
        Err(Fatal::Config(e)) => {
            log::error!("{e}");
            std::process::exit(CONFIG_EXIT_CODE);
        }
        Err(Fatal::SelfTest(e)) => {
            log::error!("{e}");
            std::process::exit(SELF_TEST_EXIT_CODE);
        }
        Err(Fatal::Other(e)) => {
            log::error!("{e}");
            std::process::exit(1);
        }
    }
}

/// A client for `node` that sends the cookie read from `cookie` (else from
/// BLACKSILK_RPC_COOKIE) with every request.
fn connect(node: &str, cookie: Option<&Path>) -> Result<Client, String> {
    Client::try_new(node)
        .and_then(|c| c.with_cookie_option(cookie))
        .map_err(|e| e.to_string())
}

/// What the mining loop asks of its node: the RPC client in the binary, a
/// chain in process in the tests.
trait Node {
    /// The template with the next RandomX key (`/template`).
    fn template(&mut self) -> Result<rpc::MiningTemplate, String>;
    fn submit_block(&mut self, block: &[u8]) -> Result<rpc::SubmitResult, String>;
}

/// The node's RPC, re-reading the cookie after a `401`.
struct RpcNode {
    client: Client,
    node: String,
    cookie: Option<PathBuf>,
}

impl RpcNode {
    /// After a `401` the node has probably restarted with a new cookie:
    /// read it again.
    fn check(&mut self, e: RpcError) -> String {
        if matches!(e, RpcError::Status(401, _)) {
            match connect(&self.node, self.cookie.as_deref()) {
                Ok(c) => {
                    self.client = c;
                    log::info!("RPC credential refused; cookie read again");
                }
                Err(e) => log::warn!("{e}"),
            }
        }
        e.to_string()
    }
}

impl Node for RpcNode {
    fn template(&mut self) -> Result<rpc::MiningTemplate, String> {
        self.client.mining_template().map_err(|e| self.check(e))
    }

    fn submit_block(&mut self, block: &[u8]) -> Result<rpc::SubmitResult, String> {
        self.client.submit_block(block).map_err(|e| self.check(e))
    }
}

/// The tip watcher's long poll, on its own connection to the node (the
/// cookie is read again after a `401`, as for [`RpcNode`]).
fn tip_source(node: String, cookie: Option<PathBuf>) -> TipSource {
    let mut client = connect(&node, cookie.as_deref()).ok();
    Box::new(move |after, wait| {
        if client.is_none() {
            client = Some(connect(&node, cookie.as_deref())?);
        }
        let c = client.as_ref().expect("set above");
        c.tip(after, wait).map_err(|e| {
            if matches!(e, RpcError::Status(401, _)) {
                client = None;
            }
            e.to_string()
        })
    })
}

/// How often a search checks its refresh deadline and the tip signal.
const STOP_CHECK_EVERY: Duration = Duration::from_millis(20);

/// The mining loop's state: one [`Miner::round`] per template.
struct Miner<N: Node, B: ContextBuilder<Ctx = PowContext>> {
    node: N,
    planner: SeedPlanner<B>,
    /// The node's tip as the tip watcher sees it (`None`: refresh only).
    tips: Option<TipSignal>,
    /// Templates abandoned because the node's tip moved (tests).
    abandoned: u64,
    payout: Address,
    /// The network's id: the mining blob commits to it (docs/consensus.md §3).
    network_id: u32,
    hedge: [u8; 32],
    rng: ChaCha20Rng,
    threads: usize,
    refresh: Duration,
    /// Hashes and time since the last hash-rate line.
    hashes: u64,
    since: Instant,
}

impl<N: Node, B: ContextBuilder<Ctx = PowContext>> Miner<N, B> {
    /// Fetches a template, prepares its RandomX context, searches nonces for
    /// `refresh` (or until a block is found) and submits a found block.
    /// `Ok(Some((height, accepted)))`: a block was found and submitted.
    /// `Err`: nothing was mined; the caller retries after [`RETRY_AFTER`].
    fn round(&mut self) -> Result<Option<(u64, bool)>, String> {
        let requested = Instant::now();
        let rpc::MiningTemplate {
            template,
            next_seed_id,
        } = self.node.template()?;
        let seed_id = parse_hash(&template.seed_id).ok_or("bad seed id from node")?;
        let prev_id = parse_hash(&template.prev_id).ok_or("bad parent id from node")?;
        // The next key only steers a background build; a malformed one is
        // ignored (the template's own key stays authoritative).
        let next = next_seed_id.as_deref().and_then(parse_hash);
        let ctx = self
            .planner
            .context(template.height, seed_id, next)
            .map_err(|e| format!("RandomX key {}: {e}", hex::encode(&seed_id[..8])))?;
        log::debug!(
            "template {} on {} (difficulty {})",
            template.height,
            &template.prev_id[..12.min(template.prev_id.len())],
            template.difficulty
        );
        // A template this binary cannot build a block from: an undecodable
        // transaction (a kind added by an activation this miner predates)
        // or a malformed field. Retried: a transient bad response must not
        // stop an unattended miner, and an outdated one says so every time.
        let block = build_block(&template, &self.payout, &self.hedge, now(), &mut self.rng)
            .map_err(|e| {
                format!(
                    "unusable template {}: {e:?} (is this miner outdated?)",
                    template.height
                )
            })?;
        // A fresh random nonce start for every template: a start kept and counted
        // up across templates would let anyone sort block nonces and cluster
        // every block, and so every coinbase output, by miner. Each template has
        // a fresh coinbase, so its header differs and restarting loses nothing.
        let nonce_start = rand_core::RngCore::next_u64(&mut self.rng);

        // Stop the search after `refresh` to pick up a newer template, or
        // as soon as the node's tip is no longer this template's parent
        // (stale work: a block found now could only be an orphan).
        let stop = Arc::new(AtomicBool::new(false));
        let timer = {
            let stop = stop.clone();
            let refresh = self.refresh;
            let tips = self.tips.clone();
            std::thread::spawn(move || {
                let deadline = Instant::now() + refresh;
                let mut moved = None;
                while Instant::now() < deadline && !stop.load(Ordering::Relaxed) {
                    moved = tips
                        .as_ref()
                        .and_then(|t| t.moved_since(&prev_id, requested));
                    if moved.is_some() {
                        break;
                    }
                    std::thread::sleep(STOP_CHECK_EVERY);
                }
                stop.store(true, Ordering::Relaxed);
                moved
            })
        };
        let started = Instant::now();
        let (found, hashes) = search(
            ctx,
            &block.header,
            self.network_id,
            nonce_start,
            self.threads,
            u64::MAX,
            &stop,
        );
        stop.store(true, Ordering::Relaxed);
        let moved = timer.join().unwrap_or(None);
        log::debug!(
            "{hashes} hashes in {:.1?} ({:.1} H/s)",
            started.elapsed(),
            hashes as f64 / started.elapsed().as_secs_f64().max(1e-3)
        );
        self.hashes += hashes;
        if self.since.elapsed() >= HASHRATE_EVERY {
            let rate = self.hashes as f64 / self.since.elapsed().as_secs_f64();
            let mode = if ctx.is_full() { "full" } else { "light" };
            if SELF_TEST_SKIPPED.load(Ordering::Relaxed) {
                log::warn!(
                    "hash rate {rate:.1} H/s ({mode} mode); RandomX self-test SKIPPED \
                     (--skip-randomx-self-test)"
                );
            } else {
                log::info!("hash rate {rate:.1} H/s ({mode} mode)");
            }
            self.hashes = 0;
            self.since = Instant::now();
        }

        let Some(f) = found else {
            if let Some(h) = moved {
                self.abandoned += 1;
                log::info!(
                    "new tip at height {h}: work on template {} abandoned after {:.1?}",
                    template.height,
                    started.elapsed()
                );
            }
            return Ok(None);
        };
        let mut block = block;
        block.header.nonce = f.nonce;
        let accepted = match self.node.submit_block(&block.encode()) {
            Ok(r) if r.accepted => {
                log::info!(
                    "found block {} (reward {} BLK, {} txs){}",
                    template.height,
                    format_amount(template.reward + template.fees),
                    block.txs.len() - 1,
                    // Accepted is not adopted: a rival of equal work seen
                    // first by the node stays its tip.
                    if r.on_best_chain == Some(false) {
                        "; not on the node's best chain"
                    } else {
                        ""
                    }
                );
                true
            }
            Ok(r) => {
                log::warn!(
                    "block {} rejected: {}",
                    template.height,
                    r.error.unwrap_or_default()
                );
                false
            }
            Err(e) => {
                log::warn!("submitting block {}: {e}", template.height);
                false
            }
        };
        Ok(Some((template.height, accepted)))
    }
}

/// A miner with test-only code compiled in ([`BuildFlags`]: written by
/// `cargo test` or a fuzz build) mines only on regtest (W4-GUARD). A
/// configuration error: a restart cannot help, the binary must be rebuilt.
/// `require_clean` (`--require-clean-build`) refuses it on regtest too.
fn check_build(flags: &BuildFlags, net: Network, require_clean: bool) -> Result<(), Fatal> {
    flags
        .check_run("blacksilk-miner", net, require_clean)
        .map_err(Fatal::Config)
}

fn run(args: Args) -> Result<(), Fatal> {
    let flags = BuildFlags::of_chain_layer();
    log::info!(
        "blacksilk-miner {} commit {BUILD_COMMIT}, {}",
        env!("CARGO_PKG_VERSION"),
        flags.line()
    );
    let require_clean = blacksilk_chain::build_flags::require_clean(args.require_clean_build);
    if require_clean {
        flags
            .check_clean("blacksilk-miner")
            .map_err(Fatal::Config)?;
    }
    // Before any hashing (decisions "Agent 08").
    start_up_self_test(args.skip_randomx_self_test)?;
    let (client, info) = wait_for_node(&args.node, args.rpc_cookie.as_deref())?;
    let net = network(&info.network).ok_or_else(|| {
        Fatal::Config(format!(
            "unknown network {:?} reported by node",
            info.network
        ))
    })?;
    check_build(&flags, net, require_clean)?;
    let address = args.address.as_deref().unwrap_or_default();
    let payout = decode_address(net, address).map_err(|e| {
        Fatal::Config(format!(
            "--address is not a valid {} address: {e:?}",
            info.network
        ))
    })?;
    let threads = args
        .threads
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()))
        .max(1);
    let build_threads = args.build_threads.unwrap_or(threads / 4).max(1);
    let plan = args.prebuild.plan(!args.light);
    log::info!(
        "mining on {} at height {} with {threads} threads ({} mode; prebuild {:?}: {}, {build_threads} build threads)",
        info.network,
        info.height,
        if args.light { "light" } else { "full" },
        args.prebuild,
        if plan.prebuild { "on" } else { "off" },
    );
    // Tip notification: a new block on the node ends the current work at
    // once instead of at the next refresh.
    let watcher = TipWatcher::spawn(
        tip_source(args.node.clone(), args.rpc_cookie.clone()),
        TIP_WAIT_SECS,
    )
    .map_err(|e| Fatal::Other(format!("tip watcher thread: {e}")))?;

    // Secret randomness for coinbase construction (hedged inside the builder).
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| Fatal::Other(format!("OS RNG: {e}")))?;
    let rng = ChaCha20Rng::from_seed(seed);
    let mut hedge = [0u8; 32];
    getrandom::getrandom(&mut hedge).map_err(|e| Fatal::Other(format!("OS RNG: {e}")))?;
    seed.zeroize();

    let mut miner = Miner {
        node: RpcNode {
            client,
            node: args.node.clone(),
            cookie: args.rpc_cookie.clone(),
        },
        planner: SeedPlanner::new(
            RandomXBuilder {
                threads: build_threads,
                first_threads: threads,
            },
            plan,
        ),
        tips: Some(watcher.signal()),
        abandoned: 0,
        payout,
        network_id: blacksilk_consensus::ChainParams::for_network(net).network_id,
        hedge,
        rng,
        threads,
        refresh: Duration::from_secs(args.refresh),
        hashes: 0,
        since: Instant::now(),
    };
    hedge.zeroize();
    loop {
        if let Err(e) = miner.round() {
            // A dataset that failed its self-test: never mine with this
            // build (a restart builds the same dataset).
            if let Some(m) = miner.planner.self_test_failure() {
                return Err(Fatal::SelfTest(self_test_message(m)));
            }
            log::warn!("{e}; retrying in {} s", RETRY_AFTER.as_secs());
            std::thread::sleep(RETRY_AFTER);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blacksilk_chain::block::Block;
    use blacksilk_chain::manager::ChainManager;
    use blacksilk_chain::store::MemoryStore;
    use blacksilk_consensus::{ChainParams, Hash, RandomXPow};
    use blacksilk_crypto::keys::{SubaddressIndex, WalletKeys};
    use blacksilk_miner::BuildError;
    use blacksilk_tx::params::TxRules;
    use std::sync::Mutex;

    /// A miner with test-only code mines only on regtest, and the refusal is
    /// a configuration error (no restart); a clean build mines anywhere.
    #[test]
    fn a_hooked_miner_mines_only_on_regtest() {
        let hooked = BuildFlags::default().with(Some("+test-hooks:chain"));
        for net in [Network::Testnet, Network::Mainnet] {
            match check_build(&hooked, net, false) {
                Err(Fatal::Config(e)) => assert!(e.contains("+test-hooks:chain"), "{e}"),
                _ => panic!("a hooked miner was not refused on {net:?}"),
            }
            assert!(check_build(&BuildFlags::default(), net, true).is_ok());
        }
        assert!(check_build(&hooked, Network::Regtest, false).is_ok());
        assert!(matches!(
            check_build(&hooked, Network::Regtest, true),
            Err(Fatal::Config(_))
        ));
    }

    /// A regtest chain in process with the short key epoch of the chain
    /// tests (16, lag 4: the first switch at height 21, key = block 16),
    /// served to the mining loop as its node would.
    struct ChainNode {
        chain: ChainManager,
        network_id: u32,
        /// Template heights that announced a next key.
        announced: Vec<u64>,
        /// Replace the next template's seed id (a malformed response).
        corrupt_seed: bool,
        /// Serve templates of this difficulty (a search that never ends).
        difficulty: Option<u64>,
    }

    impl Node for ChainNode {
        fn template(&mut self) -> Result<rpc::MiningTemplate, String> {
            let t = self.chain.template();
            let next = self.chain.next_seed_id(t.height, &t.prev_id);
            if next.is_some() {
                self.announced.push(t.height);
            }
            Ok(rpc::MiningTemplate {
                template: rpc::Template {
                    height: t.height,
                    prev_id: hex::encode(t.prev_id),
                    difficulty: self.difficulty.unwrap_or(t.difficulty),
                    seed_id: if std::mem::take(&mut self.corrupt_seed) {
                        "not hex".into()
                    } else {
                        hex::encode(t.seed_id)
                    },
                    min_timestamp: t.min_timestamp,
                    version: t.version,
                    reward: t.reward,
                    fees: t.fees,
                    txs: t.txs.iter().map(|tx| hex::encode(tx.encode())).collect(),
                    output_count: t.outputs.count(),
                    output_peaks: t.outputs.peaks().iter().map(hex::encode).collect(),
                    px_root: hex::encode(t.px_root),
                },
                next_seed_id: next.map(hex::encode),
            })
        }

        fn submit_block(&mut self, block: &[u8]) -> Result<rpc::SubmitResult, String> {
            let block = Block::decode(block).map_err(|e| format!("{e:?}"))?;
            Ok(match self.chain.submit_block(block, now()) {
                Ok(s) => rpc::SubmitResult {
                    accepted: true,
                    id: Some(hex::encode(s.id)),
                    on_best_chain: Some(s.on_best_chain),
                    error: None,
                },
                Err(e) => rpc::SubmitResult {
                    accepted: false,
                    id: None,
                    on_best_chain: None,
                    error: Some(format!("{e:?}")),
                },
            })
        }
    }

    /// The real RandomX builder, recording each build and the thread that
    /// ran it.
    struct Recording {
        inner: RandomXBuilder,
        builds: Arc<Mutex<Vec<(Hash, bool, String)>>>,
    }

    impl ContextBuilder for Recording {
        type Ctx = PowContext;
        fn seed(ctx: &PowContext) -> Hash {
            *ctx.seed()
        }
        fn is_full(ctx: &PowContext) -> bool {
            ctx.is_full()
        }
        fn build(&self, seed: &Hash, full: bool) -> Result<PowContext, BuildError> {
            let thread = std::thread::current().name().unwrap_or("").to_string();
            self.builds.lock().unwrap().push((*seed, full, thread));
            self.inner.build(seed, full)
        }
    }

    type Builds = Arc<Mutex<Vec<(Hash, bool, String)>>>;

    fn miner(prebuild: bool) -> (Miner<ChainNode, Recording>, Builds) {
        let mut p = ChainParams::regtest();
        p.seed_epoch = 16;
        p.seed_lag = 4;
        let chain = ChainManager::open(
            p.clone(),
            TxRules::for_chain(&p),
            Arc::new(RandomXPow::new()),
            Box::<MemoryStore>::default(),
            [4; 32],
        )
        .unwrap();
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        let (keys, _) = WalletKeys::generate(&mut rng);
        let builds = Builds::default();
        let m = Miner {
            node: ChainNode {
                chain,
                network_id: p.network_id,
                announced: Vec::new(),
                corrupt_seed: false,
                difficulty: None,
            },
            planner: SeedPlanner::new(
                Recording {
                    inner: RandomXBuilder {
                        threads: 1,
                        first_threads: 1,
                    },
                    builds: builds.clone(),
                },
                SeedPlan {
                    full: false,
                    prebuild,
                    fallback: false,
                },
            ),
            tips: None,
            abandoned: 0,
            payout: keys.address(SubaddressIndex::PRIMARY),
            network_id: ChainParams::regtest().network_id,
            hedge: [7; 32],
            rng,
            threads: 1,
            // Regtest difficulty 1 (the genesis gap): the first hash finds
            // the block, so the refresh never ends a round.
            refresh: Duration::from_secs(60),
            hashes: 0,
            since: Instant::now(),
        };
        (m, builds)
    }

    /// Mines one block; panics if the round fails or finds none.
    fn mine(m: &mut Miner<ChainNode, Recording>) -> u64 {
        let (height, accepted) = m
            .round()
            .expect("round")
            .expect("difficulty 1 finds a block");
        assert!(accepted, "block {height} accepted");
        height
    }

    /// A short regtest chain across a key switch, mined by the real loop
    /// (templates with `next_seed_id`, planner, RandomX light, submission):
    /// with `--prebuild` the next key's context is built on the planner's
    /// background thread inside the lag window and used at the switch,
    /// so the mining thread builds nothing there. The next key comes with
    /// the template (no `/blocks` lookup).
    #[test]
    fn prebuild_crosses_a_key_switch_without_building_on_the_mining_thread() {
        let (mut m, builds) = miner(true);
        for h in 1..=20 {
            assert_eq!(mine(&mut m), h);
        }
        let key16 = m.node.chain.block_at(16).unwrap().id(m.node.network_id);
        // Templates 17..=20 are the window (next key = block 16).
        assert_eq!(m.node.announced, vec![17, 18, 19, 20]);
        // The lag gives the build time; in a network it is 64 blocks.
        m.planner.finish_background();
        let before = builds.lock().unwrap().len();
        assert_eq!(mine(&mut m), 21, "the first block under the new key");
        assert_eq!(
            builds.lock().unwrap().len(),
            before,
            "no build at the switch"
        );
        for h in 22..=23 {
            assert_eq!(mine(&mut m), h);
        }
        let builds = builds.lock().unwrap().clone();
        let genesis_key = m.node.chain.block_at(0).unwrap().id(m.node.network_id);
        assert_eq!(builds.len(), 2, "{builds:?}");
        assert_eq!((builds[0].0, builds[0].1), (genesis_key, false));
        assert_eq!(
            builds[1],
            (key16, false, "randomx-build".to_string()),
            "the new key was prebuilt in the background"
        );
        assert_eq!(m.node.chain.height(), 23);
    }

    /// Without prebuild the announced key is not built ahead, and the
    /// switch builds the new key's context on the mining thread.
    #[test]
    fn without_prebuild_the_switch_builds_on_the_mining_thread() {
        let (mut m, builds) = miner(false);
        for h in 1..=21 {
            assert_eq!(mine(&mut m), h);
        }
        assert_eq!(m.node.announced, vec![17, 18, 19, 20]);
        let builds = builds.lock().unwrap().clone();
        assert_eq!(builds.len(), 2);
        assert_ne!(builds[1].2, "randomx-build", "{builds:?}");
    }

    /// A round the miner cannot use is an error the loop retries, not an
    /// exit: a malformed seed id, then an unreachable node.
    #[test]
    fn a_bad_template_is_retried_not_fatal() {
        let (mut m, _) = miner(false);
        m.node.corrupt_seed = true;
        let e = m.round().unwrap_err();
        assert!(e.contains("bad seed id"), "{e}");
        assert_eq!(mine(&mut m), 1, "the next round mines");

        struct Down;
        impl Node for Down {
            fn template(&mut self) -> Result<rpc::MiningTemplate, String> {
                Err("node returned HTTP 503: syncing: height 0, headers 3".into())
            }
            fn submit_block(&mut self, _: &[u8]) -> Result<rpc::SubmitResult, String> {
                unreachable!()
            }
        }
        let mut down = Miner {
            node: Down,
            planner: m.planner,
            tips: None,
            abandoned: 0,
            payout: m.payout,
            network_id: m.network_id,
            hedge: m.hedge,
            rng: m.rng,
            threads: 1,
            refresh: m.refresh,
            hashes: 0,
            since: Instant::now(),
        };
        assert!(down.round().unwrap_err().contains("503"));
    }

    /// Tip notification: a search on a template whose parent is no longer
    /// the node's tip stops within a check interval, long before the
    /// refresh, and the next round mines on the new tip.
    #[test]
    fn a_new_tip_abandons_stale_work_at_once() {
        let (mut m, _) = miner(false);
        assert_eq!(mine(&mut m), 1);
        let signal = TipSignal::default();
        m.tips = Some(signal.clone());
        // A search that cannot end on its own (refresh 60 s).
        m.node.difficulty = Some(u64::MAX);
        let tip = m.node.chain.tip_id();
        let rival: Hash = [0x77; 32];
        let notify = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            signal.observe(rival, 1);
        });
        let started = Instant::now();
        assert_eq!(m.round().unwrap(), None, "no block on a stale parent");
        let took = started.elapsed();
        notify.join().unwrap();
        assert!(took < Duration::from_secs(10), "stopped after {took:?}");
        assert!(took >= Duration::from_millis(250), "{took:?}");
        assert_eq!(m.abandoned, 1);
        assert_eq!(m.node.chain.tip_id(), tip);
        // The node's own tip, seen again, is not a change: the next round
        // mines normally.
        m.tips.as_ref().unwrap().observe(tip, 1);
        m.node.difficulty = None;
        assert_eq!(mine(&mut m), 2);
        assert_eq!(m.abandoned, 1);
    }

    /// `--prebuild`: `auto` prebuilds in full mode with the fallback, never
    /// in light mode; `on` always; `off` never; a bare flag is `on`.
    #[test]
    fn prebuild_modes() {
        let full = |p: Prebuild| {
            let s = p.plan(true);
            (s.prebuild, s.fallback)
        };
        assert_eq!(full(Prebuild::Auto), (true, true));
        assert_eq!(full(Prebuild::On), (true, false));
        assert_eq!(full(Prebuild::Off), (false, false));
        assert!(!Prebuild::Auto.plan(false).prebuild);
        assert!(Prebuild::On.plan(false).prebuild);
        let parse = |extra: &[&str]| {
            let mut argv = vec!["blacksilk-miner", "--address", "x"];
            argv.extend_from_slice(extra);
            Args::try_parse_from(argv).unwrap().prebuild
        };
        assert_eq!(parse(&[]), Prebuild::Auto);
        assert_eq!(parse(&["--prebuild"]), Prebuild::On);
        assert_eq!(parse(&["--prebuild", "off"]), Prebuild::Off);
        assert_eq!(parse(&["--prebuild=on"]), Prebuild::On);
    }

    /// RT-NODEOPS: waiting for the node backs off from 5 s to at most 60 s;
    /// a malformed node address is a configuration error at once.
    #[test]
    fn waiting_for_the_node_backs_off() {
        let mut d = NODE_WAIT_FIRST;
        let mut seen = vec![d.as_secs()];
        for _ in 0..6 {
            d = next_wait(d);
            seen.push(d.as_secs());
        }
        assert_eq!(seen, [5, 10, 20, 40, 60, 60, 60]);
        assert!(matches!(
            wait_for_node("https://127.0.0.1:1", None),
            Err(Fatal::Config(_))
        ));
    }

    /// TM2-3: the start-up self-test passes on this build, can be skipped
    /// (with a warning), and its failure message tells the operator what to
    /// do; the exit status is the node's.
    #[test]
    fn the_start_up_self_test() {
        assert!(start_up_self_test(false).is_ok());
        assert!(start_up_self_test(true).is_ok());
        assert!(self_test_only(true, 1).is_ok(), "light mode only");
        let m = self_test_message("RandomX hash test 1b (light mode): expected 00, computed 01");
        assert!(m.contains("1b") && m.contains("release-build.sh"), "{m}");
        assert_eq!(SELF_TEST_EXIT_CODE, 71);
        let parse = |extra: &[&str]| {
            let mut argv = vec!["blacksilk-miner", "--address", "x"];
            argv.extend_from_slice(extra);
            Args::try_parse_from(argv).unwrap()
        };
        let a = parse(&["--randomx-self-test", "--skip-randomx-self-test"]);
        assert!(a.randomx_self_test && a.skip_randomx_self_test);
        // The per-device check needs no payout address; mining does.
        assert!(Args::try_parse_from(["blacksilk-miner", "--randomx-self-test"]).is_ok());
        assert!(Args::try_parse_from(["blacksilk-miner"]).is_err());
        let a = parse(&[]);
        assert!(!a.randomx_self_test && !a.skip_randomx_self_test);
    }
}
