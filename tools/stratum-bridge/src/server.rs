//! The bridge: a loopback-only stratum server in front of one node.
//!
//! Threads:
//! - the accept thread (one thread per connection, at most
//!   [`Config::max_connections`] open connections and
//!   [`Config::max_sessions`] logged-in sessions);
//! - the work thread: long-polls the node's `/tip`, and on a new tip or every
//!   [`Config::refresh`] builds a block from `/template` with
//!   `blacksilk_miner::build_block` and sends every session a fresh job;
//! - one verifier thread that owns the share queue (bounded,
//!   [`Config::queue_capacity`]): it rebuilds the header, hashes
//!   `pow_blob` with the node's `PowFunction`, compares the result byte for
//!   byte, checks `check_hash` against the block's difficulty and submits the
//!   block with `rpc::Client::submit_block`. The reply is sent only after
//!   the node answered.
//!
//! The order of the share checks (each failure has a fixed reply,
//! [`crate::stratum`]): session id, job (of this session), `algo`, stale tip,
//! nonce and result format, duplicate, queue admission (a share is recorded as
//! seen only once it is on the queue, so a `Busy` share can be sent again),
//! then in the verifier: hash, result, block difficulty, node.

use crate::job::{blob_with_xmrig_nonce, decode_nonce, decode_result, with_extranonce, Job};
use crate::stratum::{self, JobObject, Line, LoginParams, Request, SubmitParams};
use crate::submit_log::{now_ms, LineLog, SubmitRecord};
use crate::target::target_hex;
use blacksilk_chain::address::decode_address;
use blacksilk_chain::block::Block;
use blacksilk_consensus::{check_hash, ChainParams, Hash, Network, PowBlob, PowFunction};
use blacksilk_crypto::keys::Address;
use blacksilk_randomx::{Cache, Variant, Vm};
use blacksilk_rpc::{self as rpc, parse_hash, Client};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::{BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

/// Jobs kept per session; an older job's shares get `Stale job`.
pub const JOBS_PER_SESSION: usize = 16;
/// Consecutive protocol errors after which a session is closed.
pub const MAX_PROTOCOL_ERRORS: u32 = 16;
/// Exit status when hashing panicked: a silent continue would hide a gate
/// failure.
pub const PANIC_EXIT_CODE: i32 = 70;

/// The bridge's settings.
#[derive(Clone, Debug)]
pub struct Config {
    /// The node's RPC address.
    pub node: String,
    /// The node's RPC cookie (`<datadir>/rpc.cookie`).
    pub rpc_cookie: Option<PathBuf>,
    /// Where to listen: a loopback address only.
    pub listen: SocketAddr,
    /// The payout address (of the node's network).
    pub payout: String,
    /// The session's share-difficulty floor: a job's share difficulty is
    /// `max(block difficulty, floor)`.
    pub min_share_diff: u64,
    /// Test knob (regtest only): a login `pass` of `diff=N` sets the session's
    /// floor to `N`.
    pub allow_session_diff: bool,
    /// Test knob (regtest only): label every job with this algorithm
    /// (`rx/0`), never submit a block, and identify the results as Monero's
    /// `rx/0` hashes (the gate's negative control).
    pub negative_control_algo: Option<String>,
    /// Every stratum line in and out, with a timestamp.
    pub stratum_log: Option<PathBuf>,
    /// One JSON line per submit ([`SubmitRecord`]).
    pub submit_log: Option<PathBuf>,
    /// New jobs at least this often (a fresh timestamp and extranonce).
    pub refresh: Duration,
    pub max_sessions: usize,
    /// Open connections, logged in or not (each has a thread); one more is
    /// closed at once.
    pub max_connections: usize,
    /// Capacity of the share queue; a full queue answers `Busy`.
    pub queue_capacity: usize,
    /// A session that sends nothing for this long is closed.
    pub read_timeout: Duration,
}

impl Config {
    pub fn new(node: &str, payout: &str) -> Self {
        Self {
            node: node.to_string(),
            rpc_cookie: None,
            listen: SocketAddr::from(([127, 0, 0, 1], 3334)),
            payout: payout.to_string(),
            min_share_diff: 1,
            allow_session_diff: false,
            negative_control_algo: None,
            stratum_log: None,
            submit_log: None,
            refresh: Duration::from_secs(60),
            max_sessions: 8,
            max_connections: 64,
            queue_capacity: 4,
            read_timeout: Duration::from_secs(120),
        }
    }
}

/// Why the bridge did not start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartError {
    /// `--listen` is not a loopback address.
    NotLoopback(SocketAddr),
    /// The node could not be reached or answered with an error.
    Rpc(String),
    /// `/info` names a network this build does not know.
    UnknownNetwork(String),
    /// `/info`'s network id is not the one this build has for that network.
    NetworkIdMismatch {
        network: String,
        reported: u32,
        expected: u32,
    },
    /// A test knob off regtest.
    TestKnobOffRegtest {
        knob: &'static str,
        network: String,
    },
    /// The bridge serves regtest only (an evidence tool).
    NotRegtest(String),
    /// `--negative-control-algo` other than `rx/0`.
    NegativeControlAlgo(String),
    Payout(String),
    Config(String),
    Io(String),
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartError::NotLoopback(a) => {
                write!(f, "refusing to listen on {a}: loopback addresses only")
            }
            StartError::Rpc(e) => write!(f, "node RPC: {e}"),
            StartError::UnknownNetwork(n) => write!(f, "the node reports unknown network {n:?}"),
            StartError::NetworkIdMismatch {
                network,
                reported,
                expected,
            } => write!(
                f,
                "the node reports network {network} with id {reported:#010x}; this build has \
                 {expected:#010x} for it"
            ),
            StartError::TestKnobOffRegtest { knob, network } => write!(
                f,
                "refusing {knob} on {network}: the test knobs are for regtest only"
            ),
            StartError::NotRegtest(n) => write!(
                f,
                "refusing to serve {n}: the bridge is an evidence tool for regtest only"
            ),
            StartError::NegativeControlAlgo(a) => write!(
                f,
                "--negative-control-algo {a:?}: only {:?} is supported",
                stratum::ALGO_RX0
            ),
            StartError::Payout(e) => write!(f, "--payout: {e}"),
            StartError::Config(e) => write!(f, "{e}"),
            StartError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for StartError {}

/// The hash the negative control identifies results with: Monero's `rx/0`.
pub trait ControlHash: Send + Sync {
    fn rx0_hash(&self, seed: &Hash, blob: &PowBlob) -> Hash;
}

/// `rx/0` in light mode (`Variant::MoneroRx0`), one cache at a time.
#[derive(Default)]
pub struct MoneroRx0Light {
    cache: Mutex<Option<(Hash, Arc<Cache>)>>,
}

impl ControlHash for MoneroRx0Light {
    fn rx0_hash(&self, seed: &Hash, blob: &PowBlob) -> Hash {
        let cache = {
            let mut c = lock(&self.cache);
            match &*c {
                Some((s, cache)) if s == seed => cache.clone(),
                _ => {
                    *c = None;
                    let cache = Arc::new(Cache::with_variant(seed, Variant::MoneroRx0));
                    *c = Some((*seed, cache.clone()));
                    cache
                }
            }
        };
        Vm::light(&cache).hash(blob)
    }
}

/// How a submit ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    OkOffBestChain,
    Unauthenticated,
    StaleJob,
    InvalidAlgo,
    InvalidNonce,
    InvalidResultFormat,
    InvalidResult,
    LowDifficulty,
    Duplicate,
    Busy,
    BlockRejected(String),
    Malformed,
    /// Negative control: the result is Monero's `rx/0` hash (expected).
    NcRx0Match,
    /// Negative control: the result is BlackSilk's hash (xmrig ignored the
    /// job's algorithm: the control failed).
    NcBlackSilkMatch,
    /// Negative control: neither.
    NcUnidentified,
}

impl Outcome {
    pub fn label(&self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::OkOffBestChain => "ok_off_best_chain",
            Outcome::Unauthenticated => "unauthenticated",
            Outcome::StaleJob => "stale_job",
            Outcome::InvalidAlgo => "invalid_algo",
            Outcome::InvalidNonce => "invalid_nonce",
            Outcome::InvalidResultFormat => "invalid_result_format",
            Outcome::InvalidResult => "invalid_result",
            Outcome::LowDifficulty => "low_difficulty",
            Outcome::Duplicate => "duplicate",
            Outcome::Busy => "busy",
            Outcome::BlockRejected(_) => "block_rejected",
            Outcome::Malformed => "malformed",
            Outcome::NcRx0Match => "nc_rx0_match",
            Outcome::NcBlackSilkMatch => "nc_blacksilk_match",
            Outcome::NcUnidentified => "nc_unidentified",
        }
    }

    /// `Ok(status)` for a success reply, `Err(message)` for an error.
    pub fn reply(&self) -> Result<&'static str, String> {
        match self {
            Outcome::Ok => Ok(stratum::STATUS_OK),
            Outcome::OkOffBestChain => Ok(stratum::STATUS_OFF_BEST_CHAIN),
            Outcome::Unauthenticated => Err(stratum::UNAUTHENTICATED.into()),
            Outcome::StaleJob => Err(stratum::STALE_JOB.into()),
            Outcome::InvalidAlgo => Err(stratum::INVALID_ALGO.into()),
            Outcome::InvalidNonce => Err(stratum::INVALID_NONCE.into()),
            Outcome::InvalidResultFormat
            | Outcome::InvalidResult
            | Outcome::NcRx0Match
            | Outcome::NcBlackSilkMatch
            | Outcome::NcUnidentified => Err(stratum::INVALID_RESULT.into()),
            Outcome::LowDifficulty => Err(stratum::LOW_DIFFICULTY.into()),
            Outcome::Duplicate => Err(stratum::DUPLICATE.into()),
            Outcome::Busy => Err(stratum::BUSY.into()),
            Outcome::BlockRejected(e) => Err(format!("{}{e}", stratum::BLOCK_REJECTED)),
            Outcome::Malformed => Err(stratum::MALFORMED.into()),
        }
    }
}

/// Whether a login agent is xmrig's (`XMRig/<version> ...`): a mismatch from
/// it is a `GATE-MISMATCH`; the probe's deliberate bad results are not.
pub fn is_xmrig(agent: &str) -> bool {
    agent.starts_with("XMRig/")
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn random_u32() -> u32 {
    let mut b = [0u8; 4];
    getrandom::getrandom(&mut b).expect("OS randomness");
    u32::from_le_bytes(b)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn connect(node: &str, cookie: Option<&std::path::Path>) -> Result<Client, rpc::RpcError> {
    Client::try_new(node)?.with_cookie_option(cookie)
}

/// What the bridge serves now: one block per template (and refresh).
struct Work {
    block: Block,
    seed: Hash,
    tip_id: Hash,
    block_diff: u64,
}

struct SessionJobs {
    jobs: VecDeque<Arc<Job>>,
    /// Nonces taken for verification, per job id.
    seen: HashMap<u64, HashSet<u32>>,
    last_extranonce: Option<u32>,
}

struct Session {
    id: String,
    agent: String,
    floor: u64,
    writer: Arc<Mutex<TcpStream>>,
    jobs: Mutex<SessionJobs>,
}

struct Task {
    session: Arc<Session>,
    job: Arc<Job>,
    req_id: Value,
    params: SubmitParams,
    nonce32: u32,
    nonce_raw: [u8; 4],
    result: Hash,
}

struct Settings {
    network_id: u32,
    algo: &'static str,
    negative_control: bool,
    min_share_diff: u64,
    allow_session_diff: bool,
    max_sessions: usize,
    read_timeout: Duration,
    refresh: Duration,
    payout: Address,
}

struct Shared {
    settings: Settings,
    pow: Arc<dyn PowFunction>,
    control: Arc<dyn ControlHash>,
    /// Modified only under `sessions`' lock (lock order: sessions, then
    /// current, then a session's jobs, then a writer).
    current: Mutex<Option<Arc<Work>>>,
    sessions: Mutex<BTreeMap<String, Arc<Session>>>,
    /// Extranonces given out for the current work (no two sessions share one).
    used_extranonces: Mutex<HashSet<u32>>,
    next_job: AtomicU64,
    /// Open connections ([`Config::max_connections`]).
    connections: AtomicUsize,
    max_connections: usize,
    queue: SyncSender<Task>,
    stratum_log: Option<LineLog>,
    submit_log: Option<LineLog>,
    stats: Mutex<BTreeMap<String, u64>>,
    stop: AtomicBool,
}

/// A running bridge. Dropping it stops the accept and work threads at their
/// next wake-up (sessions end with their connections).
pub struct Bridge {
    addr: SocketAddr,
    shared: Arc<Shared>,
}

impl Bridge {
    /// Starts a bridge hashing with `pow` (the node's `RandomXPow` in the
    /// binary; tests pass the node's own test double) and identifying
    /// negative-control results with Monero's `rx/0` in light mode.
    pub fn start(config: Config, pow: Arc<dyn PowFunction>) -> Result<Self, StartError> {
        Self::start_with(config, pow, Arc::new(MoneroRx0Light::default()))
    }

    /// [`Bridge::start`] with the negative control's hash given.
    pub fn start_with(
        config: Config,
        pow: Arc<dyn PowFunction>,
        control: Arc<dyn ControlHash>,
    ) -> Result<Self, StartError> {
        if !config.listen.ip().is_loopback() {
            return Err(StartError::NotLoopback(config.listen));
        }
        if config.min_share_diff == 0 {
            return Err(StartError::Config(
                "--min-share-diff must be at least 1".into(),
            ));
        }
        if config.max_sessions == 0 || config.queue_capacity == 0 || config.max_connections == 0 {
            return Err(StartError::Config(
                "the session limit and the queue capacity must be at least 1".into(),
            ));
        }
        let cookie = config.rpc_cookie.as_deref();
        let client = connect(&config.node, cookie).map_err(|e| StartError::Rpc(e.to_string()))?;
        let info = client.info().map_err(|e| StartError::Rpc(e.to_string()))?;
        let network = match info.network.as_str() {
            "mainnet" => Network::Mainnet,
            "testnet" => Network::Testnet,
            "regtest" => Network::Regtest,
            other => return Err(StartError::UnknownNetwork(other.to_string())),
        };
        let expected = ChainParams::for_network(network).network_id;
        if info.network_id != expected {
            return Err(StartError::NetworkIdMismatch {
                network: info.network.clone(),
                reported: info.network_id,
                expected,
            });
        }
        let off_regtest = |knob| StartError::TestKnobOffRegtest {
            knob,
            network: info.network.clone(),
        };
        if config.allow_session_diff && network != Network::Regtest {
            return Err(off_regtest("--allow-session-diff"));
        }
        if let Some(a) = &config.negative_control_algo {
            if network != Network::Regtest {
                return Err(off_regtest("--negative-control-algo"));
            }
            if a != stratum::ALGO_RX0 {
                return Err(StartError::NegativeControlAlgo(a.clone()));
            }
        }
        if network != Network::Regtest {
            return Err(StartError::NotRegtest(info.network.clone()));
        }
        let payout = decode_address(network, &config.payout)
            .map_err(|e| StartError::Payout(format!("not a {} address: {e:?}", info.network)))?;
        let open = |p: &Option<PathBuf>| -> Result<Option<LineLog>, StartError> {
            p.as_deref()
                .map(|p| {
                    LineLog::open(p).map_err(|e| StartError::Io(format!("{}: {e}", p.display())))
                })
                .transpose()
        };
        let stratum_log = open(&config.stratum_log)?;
        let submit_log = open(&config.submit_log)?;
        let listener = TcpListener::bind(config.listen)
            .map_err(|e| StartError::Io(format!("listen on {}: {e}", config.listen)))?;
        let addr = listener
            .local_addr()
            .map_err(|e| StartError::Io(e.to_string()))?;
        let negative_control = config.negative_control_algo.is_some();
        let algo = if negative_control {
            stratum::ALGO_RX0
        } else {
            stratum::ALGO_BLACKSILK
        };
        let (queue, rx) = mpsc::sync_channel(config.queue_capacity);
        let shared = Arc::new(Shared {
            settings: Settings {
                network_id: info.network_id,
                algo,
                negative_control,
                min_share_diff: config.min_share_diff,
                allow_session_diff: config.allow_session_diff,
                max_sessions: config.max_sessions,
                read_timeout: config.read_timeout,
                refresh: config.refresh,
                payout,
            },
            pow,
            control,
            current: Mutex::new(None),
            sessions: Mutex::new(BTreeMap::new()),
            used_extranonces: Mutex::new(HashSet::new()),
            next_job: AtomicU64::new(1),
            connections: AtomicUsize::new(0),
            max_connections: config.max_connections,
            queue,
            stratum_log,
            submit_log,
            stats: Mutex::new(BTreeMap::new()),
            stop: AtomicBool::new(false),
        });
        log::info!(
            "stratum bridge on {addr}: node {} network {} id {:#010x}, algo {algo}, share floor {}{}{}",
            config.node,
            info.network,
            info.network_id,
            config.min_share_diff,
            if config.allow_session_diff {
                ", --allow-session-diff"
            } else {
                ""
            },
            if negative_control {
                ", NEGATIVE CONTROL (no block is ever submitted)"
            } else {
                ""
            },
        );
        let verifier_client =
            connect(&config.node, cookie).map_err(|e| StartError::Rpc(e.to_string()))?;
        let s = shared.clone();
        std::thread::Builder::new()
            .name("verifier".into())
            .spawn(move || verifier(s, rx, verifier_client))
            .map_err(|e| StartError::Io(e.to_string()))?;
        // The first work before the first login, when the node has it.
        let mut work = WorkBuilder::new(client);
        if let Err(e) = work.refresh(&shared) {
            log::warn!("no work yet: {e}");
        }
        let s = shared.clone();
        std::thread::Builder::new()
            .name("work".into())
            .spawn(move || work.run(&s))
            .map_err(|e| StartError::Io(e.to_string()))?;
        let s = shared.clone();
        std::thread::Builder::new()
            .name("accept".into())
            .spawn(move || accept(s, listener))
            .map_err(|e| StartError::Io(e.to_string()))?;
        Ok(Self { addr, shared })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn network_id(&self) -> u32 {
        self.shared.settings.network_id
    }

    /// Outcome counts by [`Outcome::label`], and `blocks_submitted`.
    pub fn stats(&self) -> BTreeMap<String, u64> {
        lock(&self.shared.stats).clone()
    }

    /// The tip (template `prev_id`) of the current work, if any.
    pub fn current_tip(&self) -> Option<Hash> {
        lock(&self.shared.current).as_ref().map(|w| w.tip_id)
    }

    /// Stops accepting connections and building work.
    pub fn stop(&self) {
        if !self.shared.stop.swap(true, Ordering::SeqCst) {
            // Wake the accept thread.
            let _ = TcpStream::connect_timeout(&self.addr, Duration::from_secs(1));
        }
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        self.stop();
    }
}

fn count(shared: &Shared, label: &str) {
    *lock(&shared.stats).entry(label.to_string()).or_default() += 1;
}

fn log_line(shared: &Shared, session: &str, dir: &str, line: &str) {
    if let Some(l) = &shared.stratum_log {
        l.line(&format!("{} {session} {dir} {line}", now_ms()));
    }
}

fn send(shared: &Shared, writer: &Mutex<TcpStream>, session: &str, line: &str) {
    log_line(shared, session, ">", line);
    let mut w = lock(writer);
    if w.write_all(line.as_bytes())
        .and_then(|()| w.write_all(b"\n"))
        .and_then(|()| w.flush())
        .is_err()
    {
        log::debug!("session {session}: write failed");
    }
}

fn job_object(job: &Job) -> JobObject {
    JobObject {
        job_id: job.id.to_string(),
        blob: hex::encode(job.blob()),
        target: target_hex(job.share_diff),
        algo: job.algo.to_string(),
        height: job.height(),
        seed_hash: hex::encode(job.seed),
    }
}

/// A new job of `work` for `session` with a fresh extranonce. Called under
/// the sessions lock.
fn make_job(shared: &Shared, session: &Session, work: &Work) -> Arc<Job> {
    let mut jobs = lock(&session.jobs);
    let mut used = lock(&shared.used_extranonces);
    let extranonce = loop {
        let x = random_u32();
        if Some(x) != jobs.last_extranonce && used.insert(x) {
            break x;
        }
    };
    jobs.last_extranonce = Some(extranonce);
    let job = Arc::new(Job {
        id: shared.next_job.fetch_add(1, Ordering::SeqCst),
        session: session.id.clone(),
        block: with_extranonce(work.block.clone(), extranonce),
        extranonce,
        seed: work.seed,
        block_diff: work.block_diff,
        share_diff: work.block_diff.max(session.floor),
        tip_id: work.tip_id,
        algo: shared.settings.algo,
        network_id: shared.settings.network_id,
    });
    jobs.jobs.push_back(job.clone());
    while jobs.jobs.len() > JOBS_PER_SESSION {
        if let Some(old) = jobs.jobs.pop_front() {
            jobs.seen.remove(&old.id);
        }
    }
    job
}

// ------------------------------------------------------------------ work

struct WorkBuilder {
    client: Client,
    rng: ChaCha20Rng,
    hedge: Zeroizing<[u8; 32]>,
    last_build: Option<Instant>,
}

impl WorkBuilder {
    fn new(client: Client) -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(&mut seed[..]).expect("OS randomness");
        let mut hedge = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(&mut hedge[..]).expect("OS randomness");
        Self {
            client,
            rng: ChaCha20Rng::from_seed(*seed),
            hedge,
            last_build: None,
        }
    }

    /// Builds the block of the node's current template and sends every
    /// session a job of it.
    fn refresh(&mut self, shared: &Shared) -> Result<(), String> {
        let t = self
            .client
            .mining_template()
            .map_err(|e| e.to_string())?
            .template;
        let block = blacksilk_miner::build_block(
            &t,
            &shared.settings.payout,
            &self.hedge[..],
            now_secs(),
            &mut self.rng,
        )
        .map_err(|e| format!("template {}: {e:?}", t.height))?;
        let seed = parse_hash(&t.seed_id).ok_or("template seed_id")?;
        let tip_id = parse_hash(&t.prev_id).ok_or("template prev_id")?;
        if block.header.difficulty != t.difficulty || block.header.prev_id != tip_id {
            return Err("the built header does not carry the template".into());
        }
        let work = Arc::new(Work {
            block,
            seed,
            tip_id,
            block_diff: t.difficulty,
        });
        self.last_build = Some(Instant::now());
        let sessions = lock(&shared.sessions);
        *lock(&shared.current) = Some(work.clone());
        lock(&shared.used_extranonces).clear();
        for s in sessions.values() {
            let job = make_job(shared, s, &work);
            send(
                shared,
                &s.writer,
                &s.id,
                &stratum::job_notification(&job_object(&job)),
            );
        }
        log::info!(
            "work: height {} difficulty {} seed {} parent {} ({} sessions)",
            t.height,
            t.difficulty,
            &t.seed_id[..16],
            &t.prev_id[..16],
            sessions.len()
        );
        Ok(())
    }

    fn run(mut self, shared: &Shared) {
        let mut backoff = Duration::from_secs(1);
        while !shared.stop.load(Ordering::SeqCst) {
            let tip = lock(&shared.current).as_ref().map(|w| w.tip_id);
            let due = self
                .last_build
                .is_none_or(|t| t.elapsed() >= shared.settings.refresh);
            let need = match tip {
                None => true,
                Some(_) if due => true,
                Some(tip) => {
                    let left = shared
                        .settings
                        .refresh
                        .saturating_sub(self.last_build.map_or(Duration::ZERO, |t| t.elapsed()));
                    let wait = left.as_secs().clamp(1, rpc::MAX_TIP_WAIT_SECS);
                    match self.client.tip(Some(&tip), wait) {
                        Ok(t) => t.tip != hex::encode(tip) || self.due(shared),
                        Err(e) => {
                            log::warn!("node /tip: {e}; retrying in {} s", backoff.as_secs());
                            std::thread::sleep(backoff);
                            backoff = (backoff * 2).min(Duration::from_secs(30));
                            continue;
                        }
                    }
                }
            };
            if !need || shared.stop.load(Ordering::SeqCst) {
                continue;
            }
            match self.refresh(shared) {
                Ok(()) => backoff = Duration::from_secs(1),
                Err(e) => {
                    log::warn!("no new work: {e}; retrying in {} s", backoff.as_secs());
                    std::thread::sleep(backoff);
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                }
            }
        }
    }

    fn due(&self, shared: &Shared) -> bool {
        self.last_build
            .is_none_or(|t| t.elapsed() >= shared.settings.refresh)
    }
}

// --------------------------------------------------------------- sessions

fn accept(shared: Arc<Shared>, listener: TcpListener) {
    for conn in listener.incoming() {
        if shared.stop.load(Ordering::SeqCst) {
            break;
        }
        let Ok(stream) = conn else { continue };
        // A connection cap before any login: each connection has a thread.
        if shared.connections.fetch_add(1, Ordering::SeqCst) >= shared.max_connections {
            shared.connections.fetch_sub(1, Ordering::SeqCst);
            count(&shared, "connections_refused");
            log::warn!("connection refused: {} open", shared.max_connections);
            drop(stream);
            continue;
        }
        let s = shared.clone();
        if let Err(e) = std::thread::Builder::new()
            .name("session".into())
            .spawn(move || {
                let open = OpenConnection(s.clone());
                connection(s, stream);
                drop(open);
            })
        {
            shared.connections.fetch_sub(1, Ordering::SeqCst);
            log::warn!("no session thread: {e}");
        }
    }
}

/// Counts one open connection; released when its thread ends (a panic
/// included).
struct OpenConnection(Arc<Shared>);

impl Drop for OpenConnection {
    fn drop(&mut self) {
        self.0.connections.fetch_sub(1, Ordering::SeqCst);
    }
}

enum Next {
    Continue,
    Close,
}

fn connection(shared: Arc<Shared>, stream: TcpStream) {
    // Loopback only: the listener is bound to a loopback address; refuse
    // anything else anyway.
    if !stream.peer_addr().is_ok_and(|a| a.ip().is_loopback()) {
        return;
    }
    let _ = stream.set_read_timeout(Some(shared.settings.read_timeout));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_nodelay(true);
    let Ok(w) = stream.try_clone() else { return };
    let writer = Arc::new(Mutex::new(w));
    let mut reader = BufReader::new(stream);
    let mut session: Option<Arc<Session>> = None;
    let mut errors = 0u32;
    loop {
        let label = session.as_ref().map_or("-", |s| s.id.as_str()).to_string();
        let line = match stratum::read_line(&mut reader) {
            Ok(Line::Text(t)) => t,
            Ok(Line::TooLong) => {
                log_line(&shared, &label, "<", "<line too long>");
                send(
                    &shared,
                    &writer,
                    &label,
                    &stratum::error_line(&Value::Null, stratum::LINE_TOO_LONG),
                );
                break;
            }
            Ok(Line::NotUtf8) => {
                log_line(&shared, &label, "<", "<not utf-8>");
                send(
                    &shared,
                    &writer,
                    &label,
                    &stratum::error_line(&Value::Null, stratum::MALFORMED),
                );
                errors += 1;
                if errors >= MAX_PROTOCOL_ERRORS {
                    break;
                }
                continue;
            }
            Ok(Line::Eof) | Err(_) => break,
        };
        log_line(&shared, &label, "<", &line);
        if line.trim().is_empty() {
            continue;
        }
        let req: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(_) => {
                send(
                    &shared,
                    &writer,
                    &label,
                    &stratum::error_line(&Value::Null, stratum::MALFORMED),
                );
                errors += 1;
                if errors >= MAX_PROTOCOL_ERRORS {
                    break;
                }
                continue;
            }
        };
        let (next, ok) = match (req.method.as_str(), &session) {
            ("login", None) => match login(&shared, &writer, &req) {
                Some(s) => {
                    session = Some(s);
                    (Next::Continue, true)
                }
                None => (Next::Continue, false),
            },
            ("login", Some(_)) => {
                send(
                    &shared,
                    &writer,
                    &label,
                    &stratum::error_line(&req.id, stratum::ALREADY_LOGGED_IN),
                );
                (Next::Continue, false)
            }
            ("submit", Some(s)) => (submit(&shared, s, &req), true),
            ("keepalived", Some(s)) => {
                send(
                    &shared,
                    &writer,
                    &s.id,
                    &stratum::result_line(&req.id, json!({"status": stratum::STATUS_KEEPALIVED})),
                );
                (Next::Continue, true)
            }
            ("submit" | "keepalived", None) => {
                send(
                    &shared,
                    &writer,
                    &label,
                    &stratum::error_line(&req.id, stratum::NOT_LOGGED_IN),
                );
                (Next::Continue, false)
            }
            _ => {
                send(
                    &shared,
                    &writer,
                    &label,
                    &stratum::error_line(&req.id, stratum::UNSUPPORTED_METHOD),
                );
                (Next::Continue, false)
            }
        };
        if ok {
            errors = 0;
        } else {
            errors += 1;
        }
        if matches!(next, Next::Close) || errors >= MAX_PROTOCOL_ERRORS {
            break;
        }
    }
    if let Some(s) = session {
        lock(&shared.sessions).remove(&s.id);
        log::info!("session {} closed", s.id);
    }
    // Close the write side, then read and drop what the peer still sends
    // (briefly): closing with unread data would reset the connection and
    // could destroy the last reply (an over-long line's) before it is read.
    let _ = lock(&writer).shutdown(std::net::Shutdown::Write);
    let stream = reader.into_inner();
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    let _ = std::io::copy(&mut (&stream).take(1 << 20), &mut std::io::sink());
}

fn login(shared: &Shared, writer: &Arc<Mutex<TcpStream>>, req: &Request) -> Option<Arc<Session>> {
    let fail = |m: &str| {
        send(shared, writer, "-", &stratum::error_line(&req.id, m));
        None
    };
    let Ok(p) = serde_json::from_value::<LoginParams>(req.params.clone()) else {
        return fail(stratum::MALFORMED);
    };
    let st = &shared.settings;
    if !p.algo.iter().any(|a| a == st.algo) {
        return fail(stratum::UNSUPPORTED_ALGO);
    }
    let requested = p
        .pass
        .strip_prefix("diff=")
        .and_then(|n| n.parse::<u64>().ok())
        .filter(|n| *n >= 1);
    let floor = match requested {
        Some(_) if !st.allow_session_diff => return fail(stratum::SESSION_DIFF_REFUSED),
        Some(n) => n,
        None => st.min_share_diff,
    };
    let mut sessions = lock(&shared.sessions);
    let Some(work) = lock(&shared.current).clone() else {
        drop(sessions);
        return fail(stratum::NO_WORK);
    };
    if sessions.len() >= st.max_sessions {
        drop(sessions);
        return fail(stratum::TOO_MANY_SESSIONS);
    }
    let id = loop {
        let id = hex::encode(random_u32().to_le_bytes());
        if !sessions.contains_key(&id) {
            break id;
        }
    };
    let session = Arc::new(Session {
        id: id.clone(),
        agent: p.agent.clone(),
        floor,
        writer: writer.clone(),
        jobs: Mutex::new(SessionJobs {
            jobs: VecDeque::new(),
            seen: HashMap::new(),
            last_extranonce: None,
        }),
    });
    let job = make_job(shared, &session, &work);
    sessions.insert(id.clone(), session.clone());
    send(
        shared,
        writer,
        &id,
        &stratum::result_line(
            &req.id,
            json!({
                "id": id,
                "status": stratum::STATUS_OK,
                "extensions": ["algo", "keepalive"],
                "job": job_object(&job),
            }),
        ),
    );
    drop(sessions);
    log::info!(
        "session {id} logged in: agent {:?}, share floor {floor}",
        p.agent
    );
    Some(session)
}

/// Replies to and logs a submit that ends before the verifier.
fn reject(
    shared: &Shared,
    session: &Session,
    req: &Request,
    params: &SubmitParams,
    job: Option<&Job>,
    nonce_raw: Option<[u8; 4]>,
    outcome: Outcome,
) {
    finish(
        shared, session, &req.id, params, job, nonce_raw, None, None, outcome,
    );
}

/// Logs the record, counts the outcome, then replies.
#[allow(clippy::too_many_arguments)]
fn finish(
    shared: &Shared,
    session: &Session,
    req_id: &Value,
    params: &SubmitParams,
    job: Option<&Job>,
    nonce_raw: Option<[u8; 4]>,
    bridge_hash: Option<Hash>,
    block_id: Option<String>,
    outcome: Outcome,
) {
    let reply = outcome.reply();
    let line = match &reply {
        Ok(status) => stratum::result_line(req_id, json!({"status": status})),
        Err(m) => stratum::error_line(req_id, m),
    };
    let gate_mismatch = is_xmrig(&session.agent)
        && matches!(
            outcome,
            Outcome::InvalidResult
                | Outcome::NcRx0Match
                | Outcome::NcBlackSilkMatch
                | Outcome::NcUnidentified
        )
        && bridge_hash.is_some_and(|h| decode_result(&params.result) != Some(h));
    let blob = job.zip(nonce_raw).map(|(j, raw)| {
        let b = blob_with_xmrig_nonce(&j.blob(), raw);
        hex::encode(b)
    });
    let record = SubmitRecord {
        ts_ms: now_ms(),
        session: session.id.clone(),
        agent: session.agent.clone(),
        job_id: params.job_id.clone(),
        nonce: params.nonce.clone(),
        result: params.result.clone(),
        algo: params.algo.clone(),
        job_algo: job.map(|j| j.algo.to_string()),
        height: job.map(Job::height),
        seed: job.map(|j| hex::encode(j.seed)),
        blob,
        header_nonce: job
            .zip(nonce_raw)
            .map(|(j, raw)| j.header_for(u32::from_le_bytes(raw)).nonce),
        block_diff: job.map(|j| j.block_diff),
        share_diff: job.map(|j| j.share_diff),
        hashed: bridge_hash.is_some(),
        bridge_hash: bridge_hash.map(hex::encode),
        outcome: outcome.label().to_string(),
        reply: match reply {
            Ok(s) => s.to_string(),
            Err(m) => m,
        },
        gate_mismatch,
        block_id,
    };
    // Recorded and counted before the reply: whoever sees the reply also
    // sees its record.
    if let Some(l) = &shared.submit_log {
        l.line(&serde_json::to_string(&record).expect("a record encodes"));
    }
    count(shared, outcome.label());
    send(shared, &session.writer, &session.id, &line);
}

fn submit(shared: &Shared, session: &Arc<Session>, req: &Request) -> Next {
    let Ok(params) = serde_json::from_value::<SubmitParams>(req.params.clone()) else {
        reject(
            shared,
            session,
            req,
            &SubmitParams::default(),
            None,
            None,
            Outcome::Malformed,
        );
        return Next::Continue;
    };
    if params.id != session.id {
        reject(
            shared,
            session,
            req,
            &params,
            None,
            None,
            Outcome::Unauthenticated,
        );
        return Next::Close;
    }
    let job = params.job_id.parse::<u64>().ok().and_then(|id| {
        lock(&session.jobs)
            .jobs
            .iter()
            .find(|j| j.id == id)
            .cloned()
    });
    let Some(job) = job else {
        reject(shared, session, req, &params, None, None, Outcome::StaleJob);
        return Next::Continue;
    };
    let raw = decode_nonce(&params.nonce).map(u32::to_le_bytes);
    let early = |outcome| {
        reject(shared, session, req, &params, Some(&job), raw, outcome);
        Next::Continue
    };
    if params.algo.as_deref() != Some(job.algo) {
        return early(Outcome::InvalidAlgo);
    }
    if lock(&shared.current).as_ref().map(|w| w.tip_id) != Some(job.tip_id) {
        return early(Outcome::StaleJob);
    }
    let Some(nonce32) = decode_nonce(&params.nonce) else {
        return early(Outcome::InvalidNonce);
    };
    let Some(result) = decode_result(&params.result) else {
        return early(Outcome::InvalidResultFormat);
    };
    let nonce_raw = nonce32.to_le_bytes();
    // Duplicate check and queue admission under one lock: a share is
    // recorded as seen only once it is on the queue.
    let mut jobs = lock(&session.jobs);
    if jobs.seen.get(&job.id).is_some_and(|s| s.contains(&nonce32)) {
        drop(jobs);
        return early(Outcome::Duplicate);
    }
    let task = Task {
        session: session.clone(),
        job: job.clone(),
        req_id: req.id.clone(),
        params: params.clone(),
        nonce32,
        nonce_raw,
        result,
    };
    match shared.queue.try_send(task) {
        Ok(()) => {
            jobs.seen.entry(job.id).or_default().insert(nonce32);
            Next::Continue
        }
        Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
            drop(jobs);
            early(Outcome::Busy)
        }
    }
}

// --------------------------------------------------------------- verifier

fn verifier(shared: Arc<Shared>, rx: Receiver<Task>, client: Client) {
    loop {
        let task = match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(t) => t,
            Err(RecvTimeoutError::Timeout) => {
                if shared.stop.load(Ordering::SeqCst) {
                    return;
                }
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => return,
        };
        verify(&shared, &client, task);
    }
}

fn fatal(what: &str) -> ! {
    log::error!("GATE-INTERNAL {what}; exiting");
    eprintln!("error: GATE-INTERNAL {what}");
    std::process::exit(PANIC_EXIT_CODE);
}

fn verify(shared: &Shared, client: &Client, t: Task) {
    let job = &t.job;
    let header = job.header_for(t.nonce32);
    let blob = header.pow_blob(shared.settings.network_id);
    // The blob xmrig hashed (the served blob with its 4 bytes at 39) is the
    // node's pow_blob of the rebuilt header.
    if blob != blob_with_xmrig_nonce(&job.blob(), t.nonce_raw) {
        fatal("the rebuilt header's pow_blob differs from the served blob with the nonce");
    }
    let pow = shared.pow.clone();
    let seed = job.seed;
    let h = match catch_unwind(AssertUnwindSafe(|| pow.pow_hash(&seed, &blob))) {
        Ok(h) => h,
        Err(_) => fatal("pow_hash panicked"),
    };
    let xmrig = is_xmrig(&t.session.agent);
    let finish_with = |outcome: Outcome, block_id: Option<String>| {
        finish(
            shared,
            &t.session,
            &t.req_id,
            &t.params,
            Some(job),
            Some(t.nonce_raw),
            Some(h),
            block_id,
            outcome,
        )
    };
    if shared.settings.negative_control {
        let control = shared.control.clone();
        let rx0 = match catch_unwind(AssertUnwindSafe(|| control.rx0_hash(&seed, &blob))) {
            Ok(h) => h,
            Err(_) => fatal("the rx/0 hash panicked"),
        };
        let outcome = if t.result == h {
            Outcome::NcBlackSilkMatch
        } else if t.result == rx0 {
            Outcome::NcRx0Match
        } else {
            Outcome::NcUnidentified
        };
        if t.result != h {
            log::warn!(
                "GATE-MISMATCH (negative control, {}) session {} job {} nonce {} result {} bridge {}",
                outcome.label(),
                t.session.id,
                job.id,
                t.params.nonce,
                t.params.result,
                hex::encode(h)
            );
        } else {
            log::error!(
                "NEGATIVE CONTROL FAILED: session {} job {} returned BlackSilk's hash for an rx/0 job",
                t.session.id,
                job.id
            );
        }
        return finish_with(outcome, None);
    }
    if t.result != h {
        if xmrig {
            log::error!(
                "GATE-MISMATCH session {} job {} height {} seed {} blob {} nonce {} result {} bridge {}",
                t.session.id,
                job.id,
                job.height(),
                hex::encode(seed),
                hex::encode(blob),
                t.params.nonce,
                t.params.result,
                hex::encode(h)
            );
        } else {
            log::warn!(
                "invalid result from session {} job {} nonce {}",
                t.session.id,
                job.id,
                t.params.nonce
            );
        }
        return finish_with(Outcome::InvalidResult, None);
    }
    // Acceptance is decided by the block's difficulty: the share difficulty
    // only shaped the miner's filter.
    if !check_hash(&h, job.block_diff) {
        return finish_with(Outcome::LowDifficulty, None);
    }
    let block = job.block_for(t.nonce32);
    count(shared, "blocks_submitted");
    let outcome = match client.submit_block(&block.encode()) {
        Ok(r) if r.accepted && r.on_best_chain == Some(true) => {
            log::info!(
                "BLOCK height {} id {} nonce {} result {} session {}",
                job.height(),
                r.id.as_deref().unwrap_or("?"),
                header.nonce,
                t.params.result,
                t.session.id
            );
            (Outcome::Ok, r.id)
        }
        Ok(r) if r.accepted => {
            log::warn!(
                "block height {} id {} accepted off the best chain",
                job.height(),
                r.id.as_deref().unwrap_or("?")
            );
            (Outcome::OkOffBestChain, r.id)
        }
        Ok(r) => {
            let e = r.error.unwrap_or_else(|| "no reason given".into());
            log::error!("GATE-FAIL node rejected block height {}: {e}", job.height());
            (Outcome::BlockRejected(e), None)
        }
        Err(e) => {
            log::error!("GATE-FAIL block submission failed: {e}");
            (Outcome::BlockRejected(format!("rpc: {e}")), None)
        }
    };
    finish_with(outcome.0, outcome.1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_replies() {
        assert_eq!(Outcome::Ok.reply(), Ok("OK"));
        assert_eq!(Outcome::OkOffBestChain.reply(), Ok("OK_OFF_BEST_CHAIN"));
        assert_eq!(
            Outcome::BlockRejected("x".into()).reply(),
            Err("Block rejected: x".into())
        );
        assert_eq!(Outcome::NcRx0Match.reply(), Err("Invalid result".into()));
        assert!(is_xmrig(
            "XMRig/6.26.0 (Windows NT 10.0; Win64; x64) libuv/1.51.0 msvc/2022"
        ));
        assert!(!is_xmrig("blacksilk-stratum-probe/0.1.0"));
    }
}
