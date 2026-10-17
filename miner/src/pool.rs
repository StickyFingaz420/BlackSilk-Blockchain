//! Pool mode: a stratum client for BlackSilk Pool (the pool repository's
//! docs/PROTOCOL.md, sections 1 to 6).
//!
//! Monero-style JSON-RPC over plain TCP, one JSON object per line: `login`
//! (with the mode and fee the operator accepted in `pass`), `job` pushes,
//! `submit` and `keepalived`. The client mines a job's 47-byte blob with
//! the miner's own RandomX contexts ([`SeedPlanner`], keyed by the job's
//! `seed_hash`), iterating only the 4 nonce bytes 39..43 from a random start
//! per job, and submits every hash that meets the job's 64-bit target. The
//! pool recomputes every share.
//!
//! Everything the pool sends is untrusted and checked before use: line
//! length (16 384 bytes), JSON shape (a repeated field is malformed), the
//! job's id (canonical decimal), blob (47 bytes, the `BSilk/1` tag, zero
//! miner nonce bytes), target (16 hex, non-zero), algorithm (`rx/blacksilk`)
//! and key (32 bytes). A malformed message ends the session and the client
//! reconnects with a growing pause. The pool's `blacksilk` object in the
//! login reply must restate exactly the mode and fee the operator accepted;
//! otherwise the client refuses to mine ([`PoolError::Config`]).
//!
//! No TLS: the connection is plain TCP, so the payout address, the `pass`
//! confirmation and the shares are readable on the path. Use the pool's TLS
//! port through a local TLS client proxy, or its onion service through a
//! local forwarder, and point the miner at the local end (miner/README.md).

use crate::{search_shares, ContextBuilder, PowContext, SeedPlanner};
use blacksilk_consensus::header::POW_BLOB_TAG;
use blacksilk_consensus::{Hash, POW_BLOB_SIZE, POW_NONCE_OFFSET};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::json;
use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The only algorithm the pool serves and this client mines.
pub const ALGO: &str = "rx/blacksilk";

/// The longest line accepted from the pool, end of line excluded (the
/// pool's own limit, PROTOCOL.md section 1).
pub const MAX_LINE: usize = 16_384;

/// The largest fee in basis points (100 %).
pub const MAX_FEE_BP: u16 = 10_000;

/// Recent job ids of a session whose shares are still submitted (the pool
/// keeps 16 jobs per session; older ones answer `Stale job`).
const RECENT_JOBS: usize = 16;

/// Submits and keepalives awaiting a reply; a share found while this many
/// are outstanding is dropped (the pool's submit bucket holds 10).
const MAX_PENDING: usize = 32;

/// The longest pool-supplied text (error message, notice) that is logged,
/// in characters.
const MAX_LOGGED: usize = 400;

/// The payout mode the operator accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolMode {
    Pooled,
    Solo,
}

impl PoolMode {
    pub fn as_str(self) -> &'static str {
        match self {
            PoolMode::Pooled => "pooled",
            PoolMode::Solo => "solo",
        }
    }
}

/// Timeouts and pauses of the client (production values: [`Timing::default`]).
#[derive(Clone, Copy, Debug)]
pub struct Timing {
    /// Per address of the pool's host.
    pub connect: Duration,
    /// From the login request to its reply (the pool closes 10 s after the
    /// connect without a login).
    pub login_reply: Duration,
    /// A `keepalived` after this long without sending anything (the pool
    /// closes a session idle for 120 s).
    pub keepalive: Duration,
    /// The session ends after this long without any message from the pool
    /// (it refreshes jobs about every 30 s).
    pub silence: Duration,
    /// Per write to the pool.
    pub write: Duration,
    /// First and longest pause before reconnecting; it doubles per failed
    /// session.
    pub backoff_first: Duration,
    pub backoff_max: Duration,
    /// A session that lasted this long resets the pause.
    pub stable: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Timing {
            connect: Duration::from_secs(10),
            login_reply: Duration::from_secs(15),
            keepalive: Duration::from_secs(60),
            silence: Duration::from_secs(180),
            write: Duration::from_secs(10),
            backoff_first: Duration::from_secs(2),
            backoff_max: Duration::from_secs(60),
            stable: Duration::from_secs(60),
        }
    }
}

/// What the client needs to mine for a pool.
#[derive(Clone, Debug)]
pub struct PoolConfig {
    /// `host:port` of the pool's stratum port (or of a local proxy).
    pub pool: String,
    /// The payout address, sent as `login`.
    pub login: String,
    /// The mode the operator accepted (`--pool-mode`).
    pub mode: PoolMode,
    /// The fee in basis points the operator accepted (`--accept-fee`).
    pub fee_bp: u16,
    /// The `agent` string (no OS or CPU details: they fingerprint the rig).
    pub agent: String,
    /// Hashing threads.
    pub threads: usize,
    pub timing: Timing,
}

/// Why the client stopped mining for good.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PoolError {
    /// The operator must change the configuration: the pool refused the
    /// login's mode, fee, address or options, or published a fee or mode
    /// other than the accepted one. Reconnecting cannot help.
    Config(String),
    /// A RandomX dataset failed its self-test.
    SelfTest(String),
    /// Anything else (no OS randomness, no thread).
    Other(String),
}

/// What a client did before it was stopped (tests and the final log line).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub logins: u64,
    pub submitted: u64,
    pub accepted: u64,
    pub rejected: u64,
    /// Shares dropped: too many submits outstanding.
    pub dropped: u64,
}

/// Checks `--pool`: `host:port` with a non-zero port, no scheme, no path.
pub fn check_pool_address(s: &str) -> Result<(), String> {
    let bad = |why: &str| Err(format!("--pool {s:?}: {why} (expected host:port)"));
    if s.contains("://") {
        return bad("no scheme: plain TCP stratum only");
    }
    if s.is_empty() || s.len() > 255 || s.chars().any(|c| c.is_whitespace() || c == '/') {
        return bad("not a host and port");
    }
    let Some((host, port)) = s.rsplit_once(':') else {
        return bad("no port");
    };
    if host.is_empty() || host == "[]" {
        return bad("no host");
    }
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return bad("the port is not a number");
    }
    match port.parse::<u16>() {
        Ok(p) if p > 0 => Ok(()),
        _ => bad("the port is not in 1..=65535"),
    }
}

/// The `pass` field: the mode and fee the operator confirmed
/// (PROTOCOL.md section 3).
pub fn pass_field(mode: PoolMode, fee_bp: u16) -> String {
    format!("mode={};fee={fee_bp}", mode.as_str())
}

// ------------------------------------------------------------- the job

/// A validated job (PROTOCOL.md section 4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Job {
    /// Canonical decimal, as the pool sent it.
    pub id: String,
    /// `"BSilk/1"` ‖ mining_hash ‖ 4 zero nonce bytes ‖ 4 extranonce bytes.
    pub blob: [u8; POW_BLOB_SIZE],
    /// The share target: a hash meets it iff `u64_le(hash[24..32]) < target64`.
    pub target64: u64,
    pub height: u64,
    /// The RandomX key.
    pub seed: Hash,
}

#[derive(Deserialize)]
struct JobWire {
    job_id: String,
    blob: String,
    target: String,
    algo: String,
    height: u64,
    seed_hash: String,
}

/// Exactly `N` bytes from `2N` hex characters (either case).
fn hex_array<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != 2 * N {
        return None;
    }
    hex::decode(s).ok()?.try_into().ok()
}

/// A canonical decimal job id: digits only, no sign, no leading zero, at
/// most `u64::MAX`.
fn canonical_job_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 20
        && s.bytes().all(|b| b.is_ascii_digit())
        && (s == "0" || !s.starts_with('0'))
        && s.parse::<u64>().is_ok()
}

impl Job {
    fn from_wire(w: JobWire) -> Result<Job, String> {
        if !canonical_job_id(&w.job_id) {
            return Err(format!(
                "job id {:?} is not a canonical decimal",
                printable(&w.job_id)
            ));
        }
        if w.algo != ALGO {
            return Err(format!(
                "job algorithm {:?} is not {ALGO}",
                printable(&w.algo)
            ));
        }
        let blob: [u8; POW_BLOB_SIZE] = hex_array(&w.blob).ok_or_else(|| {
            format!(
                "job blob is not {} hex characters ({} received)",
                2 * POW_BLOB_SIZE,
                w.blob.len()
            )
        })?;
        if &blob[..POW_BLOB_TAG.len()] != POW_BLOB_TAG {
            return Err("job blob does not start with the BSilk/1 tag".into());
        }
        if blob[POW_NONCE_OFFSET..POW_NONCE_OFFSET + 4] != [0; 4] {
            return Err("job blob's miner nonce bytes 39..43 are not zero".into());
        }
        let target: [u8; 8] = hex_array(&w.target)
            .ok_or("job target is not 16 hex characters (the compact form is not accepted)")?;
        let target64 = u64::from_le_bytes(target);
        if target64 == 0 {
            return Err("job target is zero".into());
        }
        let seed: Hash = hex_array(&w.seed_hash).ok_or("job seed_hash is not 64 hex characters")?;
        Ok(Job {
            id: w.job_id,
            blob,
            target64,
            height: w.height,
            seed,
        })
    }

    /// Parses and validates a job object (the `params` of a `job`
    /// notification, or the login reply's `job`).
    pub fn from_json(s: &str) -> Result<Job, String> {
        let w: JobWire = serde_json::from_str(s).map_err(|e| format!("malformed job: {e}"))?;
        Job::from_wire(w)
    }
}

/// Pool-supplied text made safe for a log line: control characters (a
/// terminal escape, a forged line break) become `?`, and the text is cut
/// at [`MAX_LOGGED`] characters.
pub fn printable(s: &str) -> String {
    let mut out: String = s
        .chars()
        .take(MAX_LOGGED)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    if s.chars().count() > MAX_LOGGED {
        out.push('…');
    }
    out
}

// ------------------------------------------------------------- messages

#[derive(Deserialize)]
struct Probe {
    #[serde(default)]
    id: Option<u64>,
    #[serde(default)]
    method: Option<String>,
}

#[derive(Deserialize)]
struct Notify {
    params: JobWire,
}

#[derive(Deserialize)]
struct ErrWire {
    message: String,
}

#[derive(Deserialize)]
#[serde(bound = "T: DeserializeOwned")]
struct ReplyWire<T> {
    #[serde(default)]
    error: Option<ErrWire>,
    #[serde(default)]
    result: Option<T>,
}

#[derive(Deserialize)]
struct LoginWire {
    id: String,
    status: String,
    #[serde(default)]
    extensions: Vec<String>,
    job: JobWire,
    #[serde(default)]
    blacksilk: Option<NoticeWire>,
}

/// The login reply's `blacksilk` object. A pool-issued `stats_token` is
/// never read (this client does not ask for one) and so never logged.
#[derive(Deserialize)]
struct NoticeWire {
    mode: String,
    fee_bp: u16,
    policy_version: u32,
    #[serde(default)]
    synthetic: bool,
    #[serde(default)]
    notice: Option<String>,
}

#[derive(Debug, Deserialize)]
struct StatusWire {
    status: String,
}

/// A reply's `result`, or the pool's error message. `Err` on a malformed
/// reply (not exactly one of a non-null `result` and `error`).
fn parse_reply<T: DeserializeOwned>(line: &str) -> Result<Result<T, String>, String> {
    let r: ReplyWire<T> =
        serde_json::from_str(line).map_err(|e| format!("malformed reply: {e}"))?;
    match (r.result, r.error) {
        (Some(v), None) => Ok(Ok(v)),
        (None, Some(e)) => Ok(Err(e.message)),
        _ => Err("malformed reply: not exactly one of result and error".into()),
    }
}

/// One line from the pool, classified by the reader thread.
#[derive(Debug)]
enum Incoming {
    /// A `job` notification (validated, or why not).
    Job(Result<Job, String>),
    /// A reply to request `id` (`None`: a refusal at connect); parsed by
    /// the controller, which knows what was asked.
    Reply { id: Option<u64>, line: String },
    /// A notification this client does not know: ignored.
    Unknown(String),
    /// Not a JSON object of the protocol.
    Malformed(String),
}

fn classify(line: &str) -> Incoming {
    let probe: Probe = match serde_json::from_str(line) {
        Ok(p) => p,
        Err(e) => return Incoming::Malformed(format!("malformed message: {e}")),
    };
    match probe.method.as_deref() {
        Some("job") => Incoming::Job(
            serde_json::from_str::<Notify>(line)
                .map_err(|e| format!("malformed job: {e}"))
                .and_then(|n| Job::from_wire(n.params)),
        ),
        Some(m) => Incoming::Unknown(printable(m)),
        None => Incoming::Reply {
            id: probe.id,
            line: line.to_owned(),
        },
    }
}

/// A line read by [`read_line`].
#[derive(Debug, PartialEq, Eq)]
enum Line {
    Text(String),
    TooLong,
    NotUtf8,
    Eof,
}

/// Reads one line of at most [`MAX_LINE`] bytes before its end (`\n`, and
/// a `\r` before it). Never buffers more than that plus the end of line.
fn read_line<R: BufRead>(r: &mut R) -> std::io::Result<Line> {
    let mut buf = Vec::new();
    let n = r
        .by_ref()
        .take(MAX_LINE as u64 + 2)
        .read_until(b'\n', &mut buf)?;
    if n == 0 {
        return Ok(Line::Eof);
    }
    let ended = buf.last() == Some(&b'\n');
    if ended {
        buf.pop();
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
    }
    if buf.len() > MAX_LINE {
        return Ok(Line::TooLong);
    }
    if !ended {
        // The connection closed inside a line.
        return Ok(Line::Eof);
    }
    String::from_utf8(buf).map_or(Ok(Line::NotUtf8), |s| Ok(Line::Text(s)))
}

// ------------------------------------------------------------- the client

enum Event {
    In {
        conn: u64,
        msg: Incoming,
    },
    Closed {
        conn: u64,
        why: String,
    },
    Share {
        conn: u64,
        job_id: Arc<str>,
        nonce: u32,
        hash: Hash,
    },
    Fatal(PoolError),
}

/// Work for the hashing thread: a job of connection `conn`, mined until
/// `stop` is set.
struct Work {
    conn: u64,
    job: Job,
    stop: Arc<AtomicBool>,
}

/// What an outstanding request was.
enum Pending {
    Submit { job_id: Arc<str> },
    Keepalive,
}

/// Login replies that only a configuration change can fix (PROTOCOL.md
/// sections 3 and 5): retrying with the same settings cannot succeed.
const CONFIG_REFUSALS: &[&str] = &[
    "Mode required",
    "Fee confirmation required",
    "Fee mismatch",
    "Unknown mode",
    "Unknown option",
    "Malformed pass",
    "Policy mismatch",
    "Invalid diff",
    "Invalid stats token",
    "Invalid address",
    "Unsupported algo",
];

/// Submit errors after which the pool closes the session.
const CLOSING_ERRORS: &[&str] = &[
    "Unauthenticated",
    "your IP is banned",
    "IP Address currently banned",
    "Invalid job id",
];

/// How a session ended, short of a [`PoolError`].
type SessionEnd = Result<(), String>;

/// Mines for the pool until `shutdown` is set (then `Ok` with what was
/// done) or a [`PoolError`]. Reconnects after every other failure, with a
/// pause that grows from [`Timing::backoff_first`] to [`Timing::backoff_max`].
pub fn run<B>(
    cfg: PoolConfig,
    planner: SeedPlanner<B>,
    shutdown: Arc<AtomicBool>,
) -> Result<Summary, PoolError>
where
    B: ContextBuilder<Ctx = PowContext>,
{
    check_pool_address(&cfg.pool).map_err(PoolError::Config)?;
    if cfg.fee_bp > MAX_FEE_BP {
        return Err(PoolError::Config(format!(
            "--accept-fee {} is above {MAX_FEE_BP} basis points",
            cfg.fee_bp
        )));
    }
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| PoolError::Other(format!("OS RNG: {e}")))?;
    let rng = ChaCha20Rng::from_seed(seed);
    let (events_tx, events) = mpsc::channel::<Event>();
    let (work_tx, work_rx) = mpsc::channel::<Work>();
    let worker = {
        let events = events_tx.clone();
        let threads = cfg.threads.max(1);
        std::thread::Builder::new()
            .name("pool-hashing".into())
            .spawn(move || hashing_thread(planner, rng, threads, work_rx, events))
            .map_err(|e| PoolError::Other(format!("hashing thread: {e}")))?
    };
    let mut client = Client {
        cfg,
        events,
        events_tx,
        work_tx,
        shutdown,
        conn: 0,
        summary: Summary::default(),
        current: None,
        fatal: None,
    };
    let result = client.run_sessions();
    client.stop_job();
    let summary = client.summary;
    drop(client);
    let _ = worker.join();
    log::info!(
        "pool client stopped: {} logins, {} shares submitted, {} accepted, {} rejected, {} dropped",
        summary.logins,
        summary.submitted,
        summary.accepted,
        summary.rejected,
        summary.dropped
    );
    result.map(|()| summary)
}

/// The hashing thread: mines the latest job it was given, with the
/// planner's context for the job's key, until the job's stop flag is set.
fn hashing_thread<B>(
    mut planner: SeedPlanner<B>,
    mut rng: ChaCha20Rng,
    threads: usize,
    work: Receiver<Work>,
    events: Sender<Event>,
) where
    B: ContextBuilder<Ctx = PowContext>,
{
    let mut window = (Instant::now(), 0u64, Duration::ZERO);
    while let Ok(mut w) = work.recv() {
        while let Ok(newer) = work.try_recv() {
            w = newer;
        }
        if w.stop.load(Ordering::Relaxed) {
            continue;
        }
        let ctx = match planner.context(w.job.height, w.job.seed, None) {
            Ok(c) => c,
            Err(e) => {
                if let Some(m) = planner.self_test_failure() {
                    let _ = events.send(Event::Fatal(PoolError::SelfTest(m.to_owned())));
                    return;
                }
                log::warn!(
                    "RandomX key {}: {e}; job {} not mined",
                    hex::encode(&w.job.seed[..8]),
                    w.job.id
                );
                continue;
            }
        };
        // A fresh random start per job: a start counted up across jobs, or
        // xmrig's start at 0, would let anyone link this miner's shares and
        // blocks by their nonces (PROTOCOL.md section 8).
        let start = rng.next_u32();
        let job_id: Arc<str> = Arc::from(w.job.id.as_str());
        let conn = w.conn;
        let sink = |nonce: u32, hash: Hash| {
            let _ = events.send(Event::Share {
                conn,
                job_id: job_id.clone(),
                nonce,
                hash,
            });
        };
        let started = Instant::now();
        let hashes = search_shares(
            ctx,
            &w.job.blob,
            w.job.target64,
            start,
            threads,
            &w.stop,
            &sink,
        );
        window.1 += hashes;
        window.2 += started.elapsed();
        if window.0.elapsed() >= Duration::from_secs(60) {
            log::info!(
                "hash rate {:.1} H/s ({} mode)",
                window.1 as f64 / window.2.as_secs_f64().max(1e-3),
                if ctx.is_full() { "full" } else { "light" }
            );
            window = (Instant::now(), 0, Duration::ZERO);
        }
    }
}

struct Client {
    cfg: PoolConfig,
    events: Receiver<Event>,
    events_tx: Sender<Event>,
    work_tx: Sender<Work>,
    shutdown: Arc<AtomicBool>,
    /// The current connection's number (events of earlier ones are ignored).
    conn: u64,
    summary: Summary,
    /// The stop flag of the job being mined.
    current: Option<Arc<AtomicBool>>,
    /// A fatal event received while serving a session.
    fatal: Option<PoolError>,
}

/// One connection's state after login.
struct Session {
    stream: TcpStream,
    id: String,
    next_id: u64,
    keepalive: bool,
    recent: VecDeque<String>,
    pending: HashMap<u64, Pending>,
    last_sent: Instant,
    last_heard: Instant,
}

impl Client {
    fn stopping(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    fn stop_job(&mut self) {
        if let Some(s) = self.current.take() {
            s.store(true, Ordering::Relaxed);
        }
    }

    fn mine(&mut self, job: Job) {
        self.stop_job();
        let stop = Arc::new(AtomicBool::new(false));
        self.current = Some(stop.clone());
        let _ = self.work_tx.send(Work {
            conn: self.conn,
            job,
            stop,
        });
    }

    fn run_sessions(&mut self) -> Result<(), PoolError> {
        let t = self.cfg.timing;
        let mut pause = t.backoff_first;
        while !self.stopping() {
            let started = Instant::now();
            let end = self.session()?;
            self.stop_job();
            if self.stopping() {
                break;
            }
            if started.elapsed() >= t.stable {
                pause = t.backoff_first;
            }
            log::warn!(
                "pool {}: {}; reconnecting in {:.0?}",
                self.cfg.pool,
                end.err().unwrap_or_else(|| "session ended".into()),
                pause
            );
            let until = Instant::now() + pause;
            while Instant::now() < until && !self.stopping() {
                // Events of the ended connection are dropped meanwhile; a
                // fatal one still stops the client.
                if let Ok(Event::Fatal(e)) = self.events.recv_timeout(Duration::from_millis(50)) {
                    return Err(e);
                }
            }
            pause = (pause * 2).min(t.backoff_max);
        }
        Ok(())
    }

    fn connect(&self) -> Result<TcpStream, String> {
        let addrs = self
            .cfg
            .pool
            .to_socket_addrs()
            .map_err(|e| format!("resolving: {e}"))?;
        let mut last = "no address".to_owned();
        for a in addrs {
            match TcpStream::connect_timeout(&a, self.cfg.timing.connect) {
                Ok(s) => return Ok(s),
                Err(e) => last = format!("connecting to {a}: {e}"),
            }
        }
        Err(last)
    }

    /// One connection: connect, log in, mine its jobs until it ends.
    fn session(&mut self) -> Result<SessionEnd, PoolError> {
        self.conn += 1;
        let conn = self.conn;
        let stream = match self.connect() {
            Ok(s) => s,
            Err(e) => return Ok(Err(e)),
        };
        let _ = stream.set_nodelay(true);
        if let Err(e) = stream.set_write_timeout(Some(self.cfg.timing.write)) {
            return Ok(Err(format!("socket: {e}")));
        }
        let reading = match stream.try_clone() {
            Ok(s) => s,
            Err(e) => return Ok(Err(format!("socket: {e}"))),
        };
        let events = self.events_tx.clone();
        let reader = std::thread::Builder::new()
            .name("pool-reader".into())
            .spawn(move || reader_thread(reading, conn, events));
        if let Err(e) = reader {
            return Ok(Err(format!("reader thread: {e}")));
        }
        // The reader thread ends once the socket is shut down.
        let result = self.logged_in(&stream, conn);
        let _ = stream.shutdown(Shutdown::Both);
        result
    }

    fn logged_in(&mut self, stream: &TcpStream, conn: u64) -> Result<SessionEnd, PoolError> {
        let stream = match stream.try_clone() {
            Ok(s) => s,
            Err(e) => return Ok(Err(format!("socket: {e}"))),
        };
        let now = Instant::now();
        let mut s = Session {
            stream,
            id: String::new(),
            next_id: 2,
            keepalive: false,
            recent: VecDeque::new(),
            pending: HashMap::new(),
            last_sent: now,
            last_heard: now,
        };
        let login = json!({
            "id": 1,
            "jsonrpc": "2.0",
            "method": "login",
            "params": {
                "login": self.cfg.login,
                "pass": pass_field(self.cfg.mode, self.cfg.fee_bp),
                "agent": self.cfg.agent,
                "algo": [ALGO],
            }
        });
        if let Err(e) = send(&mut s, &login) {
            return Ok(Err(e));
        }
        let job = match self.await_login(&mut s, conn)? {
            Ok(j) => j,
            Err(e) => return Ok(Err(e)),
        };
        self.summary.logins += 1;
        s.recent.push_back(job.id.clone());
        log::info!(
            "pool job {} at height {} (share target {:016x})",
            job.id,
            job.height,
            job.target64
        );
        self.mine(job);
        let end = self.serve(&mut s, conn);
        match self.fatal.take() {
            Some(e) => Err(e),
            None => Ok(end),
        }
    }

    /// Waits for the login reply and checks it: the pool's refusal, the
    /// session id, the `blacksilk` restatement of mode and fee, the job.
    fn await_login(&mut self, s: &mut Session, conn: u64) -> Result<Step<Job>, PoolError> {
        let deadline = Instant::now() + self.cfg.timing.login_reply;
        loop {
            if self.stopping() {
                return Ok(Err("stopped".into()));
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok(Err("no login reply".into()));
            }
            let ev = match self
                .events
                .recv_timeout(left.min(Duration::from_millis(100)))
            {
                Ok(ev) => ev,
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => return Ok(Err("event channel".into())),
            };
            match ev {
                Event::Fatal(e) => return Err(e),
                Event::Closed { conn: c, why } if c == conn => return Ok(Err(why)),
                Event::In { conn: c, msg } if c == conn => {
                    s.last_heard = Instant::now();
                    match msg {
                        Incoming::Reply {
                            id: Some(1) | None,
                            line,
                        } => {
                            return self.check_login(s, &line);
                        }
                        Incoming::Reply { id, .. } => {
                            return Ok(Err(format!("reply to unknown request {id:?} before login")))
                        }
                        Incoming::Job(_) => return Ok(Err("job before the login reply".into())),
                        Incoming::Unknown(m) => {
                            log::warn!("pool sent an unknown notification {m:?}: ignored")
                        }
                        Incoming::Malformed(e) => return Ok(Err(e)),
                    }
                }
                _ => {}
            }
        }
    }

    fn check_login(&mut self, s: &mut Session, line: &str) -> Result<Step<Job>, PoolError> {
        let reply = match parse_reply::<LoginWire>(line) {
            Ok(r) => r,
            Err(e) => return Ok(Err(format!("login reply: {e}"))),
        };
        let r = match reply {
            Ok(r) => r,
            Err(message) => {
                let message = printable(&message);
                if CONFIG_REFUSALS.iter().any(|p| message.starts_with(p)) {
                    return Err(PoolError::Config(format!(
                        "the pool refused the login: {message} (accepted: --pool-mode {} \
                         --accept-fee {}); check the pool's published policy and set the \
                         options to match it",
                        self.cfg.mode.as_str(),
                        self.cfg.fee_bp
                    )));
                }
                return Ok(Err(format!("the pool refused the login: {message}")));
            }
        };
        if r.status != "OK" {
            return Ok(Err(format!("login status {:?}", printable(&r.status))));
        }
        if r.id.len() != 16 || !r.id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Ok(Err(
                "login reply: the session id is not 16 hex characters".into()
            ));
        }
        let Some(n) = r.blacksilk else {
            return Err(PoolError::Config(
                "the pool's login reply has no `blacksilk` object, so it does not state its \
                 mode and fee: refusing to mine (BlackSilk Pool sends it unless its operator \
                 turned `stratum.login_extension` off)"
                    .into(),
            ));
        };
        if n.mode != self.cfg.mode.as_str() || n.fee_bp != self.cfg.fee_bp {
            return Err(PoolError::Config(format!(
                "the pool states mode {:?} at fee {} bp (policy {}), but you accepted mode {} \
                 at fee {} bp: refusing to mine",
                printable(&n.mode),
                n.fee_bp,
                n.policy_version,
                self.cfg.mode.as_str(),
                self.cfg.fee_bp
            )));
        }
        let job = match Job::from_wire(r.job) {
            Ok(j) => j,
            Err(e) => return Ok(Err(format!("login reply: {e}"))),
        };
        log::info!(
            "logged in to pool {}: mode {}, fee {} bp ({}.{:02} %), policy version {}",
            self.cfg.pool,
            n.mode,
            n.fee_bp,
            n.fee_bp / 100,
            n.fee_bp % 100,
            n.policy_version
        );
        match &n.notice {
            Some(text) => log::warn!("pool notice: {}", printable(text)),
            None if self.cfg.mode == PoolMode::Pooled => {
                log::warn!("the pool sent no notice for pooled mode")
            }
            None => {}
        }
        if n.synthetic {
            log::warn!(
                "the pool serves SYNTHETIC work: shares are not network work and earn nothing"
            );
        }
        s.id = r.id;
        s.keepalive = r.extensions.iter().any(|e| e == "keepalive");
        Ok(Ok(job))
    }

    /// Mines the session's jobs and submits their shares until it ends.
    fn serve(&mut self, s: &mut Session, conn: u64) -> SessionEnd {
        let t = self.cfg.timing;
        loop {
            if self.stopping() {
                return Ok(());
            }
            let now = Instant::now();
            if now.duration_since(s.last_heard) >= t.silence {
                return Err(format!("nothing from the pool for {:.0?}", t.silence));
            }
            if s.keepalive && now.duration_since(s.last_sent) >= t.keepalive {
                let id = s.next_id;
                s.next_id += 1;
                let msg = json!({"id": id, "jsonrpc": "2.0", "method": "keepalived",
                                 "params": {"id": s.id}});
                send(s, &msg)?;
                s.pending.insert(id, Pending::Keepalive);
            }
            if s.pending.len() > MAX_PENDING * 2 {
                return Err("the pool does not answer its requests".into());
            }
            let ev = match self.events.recv_timeout(Duration::from_millis(100)) {
                Ok(ev) => ev,
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => return Err("event channel".into()),
            };
            match ev {
                Event::Fatal(e) => {
                    self.fatal = Some(e);
                    return Err("stopping".into());
                }
                Event::Closed { conn: c, why } if c == conn => return Err(why),
                Event::In { conn: c, msg } if c == conn => {
                    s.last_heard = Instant::now();
                    match msg {
                        Incoming::Job(Ok(job)) => {
                            log::info!(
                                "pool job {} at height {} (share target {:016x})",
                                job.id,
                                job.height,
                                job.target64
                            );
                            s.recent.push_back(job.id.clone());
                            if s.recent.len() > RECENT_JOBS {
                                s.recent.pop_front();
                            }
                            self.mine(job);
                        }
                        Incoming::Job(Err(e)) => return Err(format!("refused a job: {e}")),
                        Incoming::Reply { id, line } => self.reply(s, id, &line)?,
                        Incoming::Unknown(m) => {
                            log::warn!("pool sent an unknown notification {m:?}: ignored")
                        }
                        Incoming::Malformed(e) => return Err(e),
                    }
                }
                Event::Share {
                    conn: c,
                    job_id,
                    nonce,
                    hash,
                } if c == conn => {
                    if !s.recent.iter().any(|j| **j == *job_id) {
                        continue;
                    }
                    if s.pending.len() >= MAX_PENDING {
                        self.summary.dropped += 1;
                        continue;
                    }
                    let id = s.next_id;
                    s.next_id += 1;
                    let msg = json!({
                        "id": id,
                        "jsonrpc": "2.0",
                        "method": "submit",
                        "params": {
                            "id": s.id,
                            "job_id": &*job_id,
                            "nonce": hex::encode(nonce.to_le_bytes()),
                            "result": hex::encode(hash),
                            "algo": ALGO,
                        }
                    });
                    send(s, &msg)?;
                    s.pending.insert(id, Pending::Submit { job_id });
                    self.summary.submitted += 1;
                }
                _ => {}
            }
        }
    }

    fn reply(&mut self, s: &mut Session, id: Option<u64>, line: &str) -> SessionEnd {
        let Some(pending) = id.and_then(|id| s.pending.remove(&id)) else {
            // A refusal without id, or an answer to nothing we asked.
            return match parse_reply::<serde_json::Value>(line) {
                Ok(Err(m)) => Err(format!("the pool closed: {}", printable(&m))),
                _ => Err(format!("reply to unknown request {id:?}")),
            };
        };
        let r = parse_reply::<StatusWire>(line)?;
        match (pending, r) {
            (Pending::Submit { .. }, Ok(st)) if st.status == "OK" => {
                self.summary.accepted += 1;
                log::debug!("share accepted");
            }
            (Pending::Keepalive, Ok(st)) if st.status == "KEEPALIVED" => {}
            (_, Ok(st)) => {
                return Err(format!(
                    "unexpected reply status {:?}",
                    printable(&st.status)
                ))
            }
            (Pending::Submit { job_id }, Err(m)) => {
                self.summary.rejected += 1;
                let m = printable(&m);
                log::warn!("share on job {job_id} rejected: {m}");
                if CLOSING_ERRORS.iter().any(|p| m.starts_with(p)) {
                    return Err(format!("the pool closes the session: {m}"));
                }
            }
            (Pending::Keepalive, Err(m)) => {
                return Err(format!("keepalive refused: {}", printable(&m)))
            }
        }
        Ok(())
    }
}

/// A step's result, or why the session ended.
type Step<T> = Result<T, String>;

fn send(s: &mut Session, msg: &serde_json::Value) -> SessionEnd {
    let mut line = msg.to_string();
    line.push('\n');
    s.stream
        .write_all(line.as_bytes())
        .and_then(|()| s.stream.flush())
        .map_err(|e| format!("writing to the pool: {e}"))?;
    s.last_sent = Instant::now();
    Ok(())
}

/// Reads the pool's lines and classifies them, until the connection ends
/// (the controller shuts the socket down to end it).
fn reader_thread(stream: TcpStream, conn: u64, events: Sender<Event>) {
    let mut r = BufReader::new(stream);
    loop {
        let why = match read_line(&mut r) {
            Ok(Line::Text(s)) if s.trim().is_empty() => continue,
            Ok(Line::Text(s)) => {
                let msg = classify(&s);
                if events.send(Event::In { conn, msg }).is_err() {
                    return;
                }
                continue;
            }
            Ok(Line::TooLong) => format!("the pool sent a line longer than {MAX_LINE} bytes"),
            Ok(Line::NotUtf8) => "the pool sent a line that is not UTF-8".to_owned(),
            Ok(Line::Eof) => "connection closed by the pool".to_owned(),
            Err(e) => format!("reading from the pool: {e}"),
        };
        let _ = events.send(Event::Closed { conn, why });
        return;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job_json(blob: &str, target: &str, algo: &str, id: &str, seed: &str) -> String {
        format!(
            r#"{{"job_id":"{id}","blob":"{blob}","target":"{target}","algo":"{algo}","height":7,"seed_hash":"{seed}"}}"#
        )
    }

    fn good_blob() -> String {
        let mut b = POW_BLOB_TAG.to_vec();
        b.extend_from_slice(&[0xab; 32]);
        b.extend_from_slice(&[0; 4]);
        b.extend_from_slice(&[1, 2, 3, 4]);
        hex::encode(b)
    }

    #[test]
    fn a_valid_job_parses() {
        let seed = "11".repeat(32);
        let j = Job::from_json(&job_json(
            &good_blob(),
            "6688635ddc460300",
            ALGO,
            "1234",
            &seed,
        ))
        .unwrap();
        assert_eq!(j.id, "1234");
        assert_eq!(
            j.target64, 922_337_203_685_478,
            "PROTOCOL.md section 4 example"
        );
        assert_eq!(j.height, 7);
        assert_eq!(j.seed, [0x11; 32]);
        assert_eq!(&j.blob[43..], &[1, 2, 3, 4]);
    }

    /// Every malformed field refuses the job.
    #[test]
    fn malformed_jobs_are_refused() {
        let seed = "11".repeat(32);
        let blob = good_blob();
        let t = "ffffffffffffffff";
        let mut tagless = hex::decode(&blob).unwrap();
        tagless[0] = b'X';
        let mut nonced = hex::decode(&blob).unwrap();
        nonced[40] = 1;
        let cases = [
            job_json(&blob[..92], t, ALGO, "1", &seed),
            job_json(&format!("{blob}00"), t, ALGO, "1", &seed),
            job_json(&hex::encode(tagless), t, ALGO, "1", &seed),
            job_json(&hex::encode(nonced), t, ALGO, "1", &seed),
            job_json(&blob, "ffffffff", ALGO, "1", &seed),
            job_json(&blob, "0000000000000000", ALGO, "1", &seed),
            job_json(&blob, t, "rx/0", "1", &seed),
            job_json(&blob, t, ALGO, "01", &seed),
            job_json(&blob, t, ALGO, "-1", &seed),
            job_json(&blob, t, ALGO, "", &seed),
            job_json(&blob, t, ALGO, "99999999999999999999", &seed),
            job_json(&blob, t, ALGO, "1", &seed[..62]),
            job_json(&blob, t, ALGO, "1", &"zz".repeat(32)),
            // A repeated field.
            job_json(&blob, t, ALGO, "1", &seed)
                .replace(r#""height":7"#, r#""height":7,"height":8"#),
            // A missing field.
            job_json(&blob, t, ALGO, "1", &seed).replace(r#""height":7,"#, ""),
        ];
        for c in cases {
            assert!(Job::from_json(&c).is_err(), "accepted {c}");
        }
        assert!(Job::from_json(&job_json(&blob, t, ALGO, "0", &seed)).is_ok());
    }

    #[test]
    fn messages_are_classified() {
        let seed = "11".repeat(32);
        let job = job_json(&good_blob(), "ffffffffffffffff", ALGO, "5", &seed);
        let push = format!(r#"{{"jsonrpc":"2.0","method":"job","params":{job}}}"#);
        assert!(matches!(classify(&push), Incoming::Job(Ok(_))));
        let bad = push.replace(ALGO, "rx/0");
        assert!(matches!(classify(&bad), Incoming::Job(Err(_))));
        assert!(matches!(classify("not json"), Incoming::Malformed(_)));
        assert!(matches!(
            classify(r#"{"id":1,"id":2,"result":{"status":"OK"}}"#),
            Incoming::Malformed(_)
        ));
        assert!(matches!(
            classify(r#"{"id":"x","result":{"status":"OK"}}"#),
            Incoming::Malformed(_)
        ));
        assert!(matches!(
            classify(r#"{"jsonrpc":"2.0","method":"other","params":{}}"#),
            Incoming::Unknown(_)
        ));
        assert!(matches!(
            classify(r#"{"id":4,"jsonrpc":"2.0","error":null,"result":{"status":"OK"}}"#),
            Incoming::Reply { id: Some(4), .. }
        ));
        let ok = parse_reply::<StatusWire>(r#"{"id":4,"error":null,"result":{"status":"OK"}}"#);
        assert_eq!(ok.unwrap().unwrap().status, "OK");
        let err = parse_reply::<StatusWire>(
            r#"{"id":4,"error":{"code":-1,"message":"Stale job"},"result":null}"#,
        );
        assert_eq!(err.unwrap().unwrap_err(), "Stale job");
        assert!(parse_reply::<StatusWire>(r#"{"id":4,"error":null,"result":null}"#).is_err());
        assert!(parse_reply::<StatusWire>(
            r#"{"id":4,"error":{"code":-1,"message":"x"},"result":{"status":"OK"}}"#
        )
        .is_err());
    }

    #[test]
    fn lines_are_bounded() {
        let data = format!("{{\"a\":1}}\r\n{}\n", "x".repeat(MAX_LINE + 5));
        let mut r = BufReader::new(data.as_bytes());
        assert_eq!(read_line(&mut r).unwrap(), Line::Text("{\"a\":1}".into()));
        assert_eq!(read_line(&mut r).unwrap(), Line::TooLong);
        let exact = format!("{}\n", "y".repeat(MAX_LINE));
        let mut r = BufReader::new(exact.as_bytes());
        assert_eq!(read_line(&mut r).unwrap(), Line::Text("y".repeat(MAX_LINE)));
        assert_eq!(read_line(&mut r).unwrap(), Line::Eof);
        let endless = "z".repeat(MAX_LINE + 10);
        let mut r = BufReader::new(endless.as_bytes());
        assert_eq!(read_line(&mut r).unwrap(), Line::TooLong);
        let mut r = BufReader::new(&b"\xff\xfe\n"[..]);
        assert_eq!(read_line(&mut r).unwrap(), Line::NotUtf8);
        let mut r = BufReader::new(&b"{\"half\":"[..]);
        assert_eq!(read_line(&mut r).unwrap(), Line::Eof);
    }

    #[test]
    fn pool_addresses_and_pass() {
        for ok in [
            "127.0.0.1:3333",
            "pool.example:443",
            "[::1]:3333",
            "localhost:1",
        ] {
            assert!(check_pool_address(ok).is_ok(), "{ok}");
        }
        for bad in [
            "stratum+tcp://pool.example:3333",
            "pool.example",
            "pool.example:",
            ":3333",
            "pool.example:0",
            "pool.example:65536",
            "pool.example:33a",
            "pool example:3333",
            "pool.example:3333/x",
            "",
        ] {
            assert!(check_pool_address(bad).is_err(), "{bad}");
        }
        assert_eq!(pass_field(PoolMode::Pooled, 200), "mode=pooled;fee=200");
        assert_eq!(pass_field(PoolMode::Solo, 300), "mode=solo;fee=300");
    }

    #[test]
    fn pool_text_is_made_printable() {
        assert_eq!(printable("a\nb\x1b[31mc"), "a?b?[31mc");
        let long = "x".repeat(MAX_LOGGED + 10);
        assert_eq!(printable(&long).chars().count(), MAX_LOGGED + 1);
    }
}
