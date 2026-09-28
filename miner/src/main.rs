//! `blacksilk-miner`: mines on a local node's templates with RandomX.

#![forbid(unsafe_code)]

use blacksilk_chain::address::decode_address;
use blacksilk_chain::emission::format_amount;
use blacksilk_consensus::{ChainParams, Hash, Network};
use blacksilk_crypto::keys::Address;
use blacksilk_miner::{
    build_block, next_seed_height, search, ContextBuilder, PowContext, RandomXBuilder, SeedPlan,
    SeedPlanner,
};
use blacksilk_rpc::{self as rpc, parse_hash, Client, RpcError};
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
    /// Build the next RandomX key's context in the background during the 64
    /// blocks before a key switch, so full-mode mining continues at the
    /// switch. Peak memory in full mode about 4.4 GiB (two datasets and a
    /// cache) instead of 2.3 GiB. Off by default: at a switch the miner then
    /// mines in light mode while the new dataset is built (docs/testnet.md).
    #[arg(long)]
    prebuild: bool,
    /// Threads that build a RandomX dataset in the background (default: a
    /// quarter of the mining threads, at least 1).
    #[arg(long)]
    build_threads: Option<usize>,
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

/// Exit status for a configuration the operator must fix (EX_CONFIG): a
/// payout address that is not valid on the node's network, or a network
/// this miner does not know. A restart cannot help, so the systemd unit
/// does not restart on it (`RestartPreventExitStatus`, RTW1B-4). Every
/// other failure exits with 1 and is restarted.
const CONFIG_EXIT_CODE: i32 = 78;

/// Pause before retrying after a failed round: the node is unreachable,
/// busy (`503`), or served a template this miner cannot use.
const RETRY_AFTER: Duration = Duration::from_secs(5);

/// How often the hash rate is logged at info level.
const HASHRATE_EVERY: Duration = Duration::from_secs(60);

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

/// Why the miner stopped.
enum Fatal {
    /// The operator must change the configuration ([`CONFIG_EXIT_CODE`]).
    Config(String),
    /// Anything else (exit status 1).
    Other(String),
}

fn main() {
    let args = parse_args();
    // Millisecond stamps: block races and relay delays are sub-second.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();
    match run(args) {
        Ok(()) => {}
        Err(Fatal::Config(e)) => {
            log::error!("{e}");
            std::process::exit(CONFIG_EXIT_CODE);
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
    fn template(&mut self) -> Result<rpc::Template, String>;
    /// The id of the connected block at `height`.
    fn block_id_at(&mut self, height: u64) -> Result<Hash, String>;
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
    fn template(&mut self) -> Result<rpc::Template, String> {
        self.client.template().map_err(|e| self.check(e))
    }

    fn block_id_at(&mut self, height: u64) -> Result<Hash, String> {
        let blocks = self.client.blocks(height, 1).map_err(|e| self.check(e))?;
        let entry = blocks
            .blocks
            .first()
            .filter(|b| b.height == height)
            .ok_or_else(|| format!("the node has no block at height {height}"))?;
        parse_hash(&entry.id).ok_or_else(|| format!("bad block id at height {height}"))
    }

    fn submit_block(&mut self, block: &[u8]) -> Result<rpc::SubmitResult, String> {
        self.client.submit_block(block).map_err(|e| self.check(e))
    }
}

/// The next RandomX key of the templates on one tip, looked up once.
///
/// During the `seed_lag` blocks before a key switch the key block already
/// exists below the template's parent ([`next_seed_height`]); its id is read
/// from the node's `/blocks` once per template height and parent, so a
/// template refresh on the same tip costs no lookup. The template's
/// `seed_id` stays the only authority for the key a block is hashed with:
/// a wrong next key (a reorganization between the two requests) only wastes
/// a background build, which the planner discards.
#[derive(Default)]
struct NextSeed {
    /// (template height, parent) of the cached lookup, and its result.
    cached: Option<((u64, String), Hash)>,
    /// Lookups sent to the node (tests).
    lookups: u64,
}

impl NextSeed {
    fn lookup(
        &mut self,
        node: &mut impl Node,
        t: &rpc::Template,
        epoch: u64,
        lag: u64,
    ) -> Option<Hash> {
        let height = next_seed_height(t.height, epoch, lag)?;
        if let Some(((h, prev), id)) = &self.cached {
            if *h == t.height && *prev == t.prev_id {
                return Some(*id);
            }
        }
        self.lookups += 1;
        match node.block_id_at(height) {
            Ok(id) => {
                self.cached = Some(((t.height, t.prev_id.clone()), id));
                Some(id)
            }
            Err(e) => {
                // Not cached: the next template retries.
                log::warn!("next RandomX key (block {height}): {e}");
                None
            }
        }
    }
}

/// The mining loop's state: one [`Miner::round`] per template.
struct Miner<N: Node, B: ContextBuilder<Ctx = PowContext>> {
    node: N,
    planner: SeedPlanner<B>,
    next_seed: NextSeed,
    /// Whether next keys are looked up (only a prebuilding planner uses them).
    prebuild: bool,
    seed_epoch: u64,
    seed_lag: u64,
    payout: Address,
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
        let template = self.node.template()?;
        let seed_id = parse_hash(&template.seed_id).ok_or("bad seed id from node")?;
        let next = if self.prebuild {
            self.next_seed
                .lookup(&mut self.node, &template, self.seed_epoch, self.seed_lag)
        } else {
            None
        };
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

        // Stop the search after `refresh` to pick up a newer template.
        let stop = Arc::new(AtomicBool::new(false));
        let timer = {
            let stop = stop.clone();
            let refresh = self.refresh;
            std::thread::spawn(move || {
                let deadline = Instant::now() + refresh;
                while Instant::now() < deadline && !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(200));
                }
                stop.store(true, Ordering::Relaxed);
            })
        };
        let started = Instant::now();
        let (found, hashes) = search(
            ctx,
            &block.header,
            nonce_start,
            self.threads,
            u64::MAX,
            &stop,
        );
        stop.store(true, Ordering::Relaxed);
        let _ = timer.join();
        log::debug!(
            "{hashes} hashes in {:.1?} ({:.1} H/s)",
            started.elapsed(),
            hashes as f64 / started.elapsed().as_secs_f64().max(1e-3)
        );
        self.hashes += hashes;
        if self.since.elapsed() >= HASHRATE_EVERY {
            log::info!(
                "hash rate {:.1} H/s ({} mode)",
                self.hashes as f64 / self.since.elapsed().as_secs_f64(),
                if ctx.is_full() { "full" } else { "light" }
            );
            self.hashes = 0;
            self.since = Instant::now();
        }

        let Some(f) = found else {
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

fn run(args: Args) -> Result<(), Fatal> {
    let client = connect(&args.node, args.rpc_cookie.as_deref()).map_err(Fatal::Config)?;
    let info = client.info().map_err(|e| {
        Fatal::Other(match e {
            RpcError::Status(401, _) => format!(
                "{e}: the node requires its RPC cookie; pass --rpc-cookie <node data dir>/{} or set {}",
                blacksilk_rpc::COOKIE_FILE,
                blacksilk_rpc::COOKIE_ENV
            ),
            e => e.to_string(),
        })
    })?;
    let net = network(&info.network).ok_or_else(|| {
        Fatal::Config(format!(
            "unknown network {:?} reported by node",
            info.network
        ))
    })?;
    let payout = decode_address(net, &args.address).map_err(|e| {
        Fatal::Config(format!(
            "--address is not a valid {} address: {e:?}",
            info.network
        ))
    })?;
    let params = ChainParams::for_network(net);
    let threads = args
        .threads
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()))
        .max(1);
    let build_threads = args.build_threads.unwrap_or(threads / 4).max(1);
    let plan = SeedPlan {
        full: !args.light,
        prebuild: args.prebuild,
    };
    log::info!(
        "mining on {} at height {} with {threads} threads ({} mode; prebuild {}, {build_threads} build threads)",
        info.network,
        info.height,
        if args.light { "light" } else { "full" },
        if args.prebuild { "on" } else { "off" },
    );

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
            },
            plan,
        ),
        next_seed: NextSeed::default(),
        prebuild: args.prebuild,
        seed_epoch: params.seed_epoch,
        seed_lag: params.seed_lag,
        payout,
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
    use blacksilk_consensus::RandomXPow;
    use blacksilk_crypto::keys::{SubaddressIndex, WalletKeys};
    use blacksilk_miner::BuildError;
    use blacksilk_tx::params::TxRules;
    use std::sync::Mutex;

    /// A regtest chain in process with the short key epoch of the chain
    /// tests (16, lag 4: the first switch at height 21, key = block 16),
    /// served to the mining loop as its node would.
    struct ChainNode {
        chain: ChainManager,
        network_id: u32,
        /// `block_id_at` calls.
        id_lookups: Vec<u64>,
        /// Replace the next template's seed id (a malformed response).
        corrupt_seed: bool,
    }

    impl Node for ChainNode {
        fn template(&mut self) -> Result<rpc::Template, String> {
            let t = self.chain.template();
            Ok(rpc::Template {
                height: t.height,
                prev_id: hex::encode(t.prev_id),
                difficulty: t.difficulty,
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
            })
        }

        fn block_id_at(&mut self, height: u64) -> Result<Hash, String> {
            self.id_lookups.push(height);
            self.chain
                .block_at(height)
                .map(|b| b.id(self.network_id))
                .ok_or_else(|| format!("no block at {height}"))
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
                id_lookups: Vec::new(),
                corrupt_seed: false,
            },
            planner: SeedPlanner::new(
                Recording {
                    inner: RandomXBuilder { threads: 1 },
                    builds: builds.clone(),
                },
                SeedPlan {
                    full: false,
                    prebuild,
                },
            ),
            next_seed: NextSeed::default(),
            prebuild,
            seed_epoch: p.seed_epoch,
            seed_lag: p.seed_lag,
            payout: keys.address(SubaddressIndex::PRIMARY),
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
    /// (templates, next-key lookup, planner, RandomX light, submission):
    /// with `--prebuild` the next key's context is built on the planner's
    /// background thread inside the lag window and used at the switch,
    /// so the mining thread builds nothing there; the key lookup runs once
    /// per template height, only inside the window.
    #[test]
    fn prebuild_crosses_a_key_switch_without_building_on_the_mining_thread() {
        let (mut m, builds) = miner(true);
        for h in 1..=20 {
            assert_eq!(mine(&mut m), h);
        }
        let key16 = m.node.chain.block_at(16).unwrap().id(m.node.network_id);
        // Templates 17..=20 are the window (next key = block 16).
        assert_eq!(m.node.id_lookups, vec![16; 4]);
        assert_eq!(m.next_seed.lookups, 4);
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

    /// Without `--prebuild` nothing is looked up, and the switch builds the
    /// new key's context on the mining thread (the default).
    #[test]
    fn without_prebuild_the_switch_builds_on_the_mining_thread() {
        let (mut m, builds) = miner(false);
        for h in 1..=21 {
            assert_eq!(mine(&mut m), h);
        }
        assert!(m.node.id_lookups.is_empty());
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
            fn template(&mut self) -> Result<rpc::Template, String> {
                Err("HTTP 503 syncing".into())
            }
            fn block_id_at(&mut self, _: u64) -> Result<Hash, String> {
                unreachable!()
            }
            fn submit_block(&mut self, _: &[u8]) -> Result<rpc::SubmitResult, String> {
                unreachable!()
            }
        }
        let mut down = Miner {
            node: Down,
            planner: m.planner,
            next_seed: NextSeed::default(),
            prebuild: false,
            seed_epoch: 16,
            seed_lag: 4,
            payout: m.payout,
            hedge: m.hedge,
            rng: m.rng,
            threads: 1,
            refresh: m.refresh,
            hashes: 0,
            since: Instant::now(),
        };
        assert!(down.round().unwrap_err().contains("503"));
    }

    /// The next-key lookup: only inside the window, once per template
    /// height and parent, again after the parent changes, and not cached
    /// when it fails.
    #[test]
    fn the_next_key_is_looked_up_once_per_tip() {
        struct Ids {
            calls: Vec<u64>,
            fail: bool,
        }
        impl Node for Ids {
            fn template(&mut self) -> Result<rpc::Template, String> {
                unreachable!()
            }
            fn block_id_at(&mut self, height: u64) -> Result<Hash, String> {
                self.calls.push(height);
                if self.fail {
                    return Err("down".into());
                }
                Ok([height as u8; 32])
            }
            fn submit_block(&mut self, _: &[u8]) -> Result<rpc::SubmitResult, String> {
                unreachable!()
            }
        }
        let t = |height: u64, prev: &str| rpc::Template {
            height,
            prev_id: prev.into(),
            difficulty: 1,
            seed_id: String::new(),
            min_timestamp: 0,
            version: 1,
            reward: 0,
            fees: 0,
            txs: Vec::new(),
        };
        let mut node = Ids {
            calls: Vec::new(),
            fail: false,
        };
        let mut n = NextSeed::default();
        let (e, l) = (2048, 64);
        assert_eq!(n.lookup(&mut node, &t(2048, "a"), e, l), None);
        assert_eq!(n.lookup(&mut node, &t(2113, "a"), e, l), None);
        assert!(node.calls.is_empty(), "outside the window");
        assert_eq!(n.lookup(&mut node, &t(2049, "a"), e, l), Some([0; 32]));
        assert_eq!(n.lookup(&mut node, &t(2049, "a"), e, l), Some([0; 32]));
        assert_eq!(node.calls, vec![2048], "a refresh on the same tip");
        n.lookup(&mut node, &t(2049, "b"), e, l);
        n.lookup(&mut node, &t(2050, "c"), e, l);
        assert_eq!(node.calls, vec![2048; 3], "a new parent, a new height");
        node.fail = true;
        assert_eq!(n.lookup(&mut node, &t(2051, "d"), e, l), None);
        node.fail = false;
        assert_eq!(n.lookup(&mut node, &t(2051, "d"), e, l), Some([0; 32]));
        assert_eq!(node.calls.len(), 5, "a failure is not cached");
    }
}
