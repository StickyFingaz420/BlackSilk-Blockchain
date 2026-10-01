//! `blacksilk-labnet`: long-duration network test on one machine.
//!
//! - Starts N real `blacksilk-node` processes (regtest by default).
//! - Connects them in a ring with chords, every link going through a proxy that
//!   adds latency and jitter.
//! - Runs `blacksilk-miner` on two nodes, one in each partition group.
//! - Drives in-process wallets that send transactions through random nodes.
//! - Periodically partitions the network into two groups, both of which keep
//!   mining, then heals it, forcing reorganizations.
//!
//! Throughout it records heights, tips, mempools, peers and memory, and checks
//! invariants. At the end it verifies:
//! - convergence;
//! - a late-joining node discovering peers and syncing;
//! - every wallet restored from its seed against the fresh node seeing the same
//!   balance;
//! - supply conservation (Σ wallet balances = coins generated).
//!
//! This is not a substitute for multi-machine testing (docs/testnet.md §7). It
//! exercises the same code paths under controlled latency and partitions.

#![forbid(unsafe_code)]

mod proxy;

use blacksilk_chain::emission::{format_amount, COIN};
use blacksilk_consensus::{BlockHeader, ChainParams, Network, HEADER_SIZE};
use blacksilk_rpc::{Client, Info, MAX_HEADERS_PER_REQUEST};
use blacksilk_tx::params::TxRules;
use blacksilk_wallet::Wallet;
use clap::Parser;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Parser, Clone)]
#[command(about = "BlackSilk lab network: long-duration multi-node test")]
struct Args {
    /// Directory with blacksilk-node and blacksilk-miner binaries.
    #[arg(long)]
    bin_dir: PathBuf,
    /// Output directory (data, logs, metrics, summary). Must not exist.
    #[arg(long)]
    out: PathBuf,
    #[arg(long, default_value_t = 5)]
    nodes: usize,
    #[arg(long, default_value_t = 180)]
    duration_mins: u64,
    #[arg(long, default_value_t = 80)]
    latency_ms: u64,
    #[arg(long, default_value_t = 60)]
    jitter_ms: u64,
    /// Minutes between partitions; 0: no partitions.
    #[arg(long, default_value_t = 25)]
    partition_every_mins: u64,
    #[arg(long, default_value_t = 4)]
    partition_mins: u64,
    /// Partition groups: nodes below this index against the rest (default
    /// n/2). The second miner runs on this node, so each group keeps one
    /// miner. With 1, node 0 and its miner mine a private branch during
    /// each partition and release it at the heal (a withholding miner with
    /// half the hash rate).
    #[arg(long)]
    partition_split: Option<usize>,
    #[arg(long, default_value_t = 20)]
    tx_every_secs: u64,
    #[arg(long, default_value_t = 41000)]
    base_port: u16,
    #[arg(long, default_value_t = 1)]
    miner_threads: usize,
    /// regtest (10-second blocks) or testnet (the real testnet rules, 120 s blocks).
    #[arg(long, default_value = "regtest")]
    network: String,
    /// Private (PX) activity every this many minutes: a deposit, a private
    /// payment or a withdrawal by a random wallet (docs/px.md). Each proves for
    /// about a minute, during which the harness loop pauses. 0 disables it.
    #[arg(long, default_value_t = 0)]
    px_every_mins: u64,
    /// Run the miners in full mode (the miner's default: a 2 GiB dataset each)
    /// instead of light mode.
    #[arg(long)]
    miner_full: bool,
    /// Pass `--prebuild on` to the miners (the next RandomX key's context
    /// is built before the switch, also in light mode, without the `auto`
    /// fallback). On in evidence runs; otherwise the miner's default
    /// (`auto`) applies.
    #[arg(long)]
    prebuild: bool,
    /// With `--miner-full`: only the first miner (the warm-up miner, on node
    /// 0) runs in full mode; the second runs in light mode with one thread.
    /// One 2 GiB dataset on the machine instead of two.
    #[arg(long, requires = "miner_full")]
    light_second_miner: bool,
    /// The `--prebuild` value full-mode miners get when prebuild is on
    /// (`--prebuild` or `--evidence`): `on`, or `auto` (the miner's default:
    /// in full mode it prebuilds as well, and falls back to the light-mode
    /// bridge, with a warning in its log, only if the second dataset cannot
    /// be allocated). Light-mode miners always get `on`.
    #[arg(long, default_value = "on", value_parser = ["on", "auto"])]
    full_prebuild: String,
    /// `--build-threads` for full-mode miners (otherwise the miner's
    /// default: a quarter of `--miner-threads`, at least 1).
    #[arg(long)]
    miner_build_threads: Option<usize>,
    /// Skip the warm-up: both miners start at once, from the genesis
    /// difficulty. Its reorganizations are then counted with the rest.
    #[arg(long)]
    no_warmup: bool,
    /// Warm-up criterion: the mean interval of the last this many blocks...
    #[arg(long, default_value_t = 30)]
    warmup_window: u64,
    /// ...is at least this fraction of the target block time.
    #[arg(long, default_value_t = 0.75)]
    warmup_ratio: f64,
    /// Longest warm-up; a run whose warm-up ends here without meeting the
    /// criterion is not evidence.
    #[arg(long, default_value_t = 60)]
    warmup_max_mins: u64,
    /// An evidence run: refuses to start if `--duration-mins` is shorter
    /// than 10 minutes, turns on `--prebuild` (`on`), refuses
    /// `--no-warmup`, and exits with status 1 unless `summary.json` says
    /// `evidence: true`.
    #[arg(long)]
    evidence: bool,
    /// Lab links: `ring-chords` (node i dials i+1 and i+2; with 5 nodes every
    /// pair is linked) or `ring` (node i dials i+1 only: blocks cross up to
    /// n/2 hops, so multi-hop propagation can be measured).
    #[arg(long, default_value = "ring-chords", value_parser = ["ring-chords", "ring"])]
    topology: String,
    /// The late joiner's `--max-outbound`. It must reach
    /// min(this + 1, nodes) peers (`required_late_peers`)...
    #[arg(long, default_value_t = 4)]
    late_max_outbound: usize,
    /// ...within this many seconds of its start.
    #[arg(long, default_value_t = 120)]
    late_peers_secs: u64,
    /// Address-relay discovery (RT-LAB E2): after the wallet checks, a second
    /// joiner starts knowing only node 0, then this many relay nodes join
    /// (connect-only, `--peer` node 0, one every `--relay-gap-secs`). The
    /// joiner asked for addresses before they existed, so it can learn them
    /// only through address relay. 0 disables it.
    #[arg(long, default_value_t = 0)]
    relay_joiners: usize,
    #[arg(long, default_value_t = 15)]
    relay_gap_secs: u64,
    /// How long after the last relay node starts the joiner may take to
    /// connect to every relay node.
    #[arg(long, default_value_t = 120)]
    relay_wait_secs: u64,
}

/// Lab links as `(from, to)`: node `from` dials node `to` through a proxy.
fn topology_links(topology: &str, n: usize) -> Vec<(usize, usize)> {
    let hops: &[usize] = match topology {
        "ring" => &[1],
        _ => &[1, 2],
    };
    (0..n)
        .flat_map(|i| hops.iter().map(move |d| (i, (i + d) % n)))
        .collect()
}

/// The peers a joiner with `max_outbound` full-relay slots must reach in a
/// network of `nodes` advertised nodes: every outbound slot plus at least
/// one block-relay-only connection, or every node if there are fewer
/// (RT-LAB F4: a check of 2 peers passed without the mechanism under test).
fn required_late_peers(max_outbound: usize, nodes: usize) -> usize {
    (max_outbound + 1).min(nodes)
}

/// The shortest measured phase (after the warm-up) of a run that may be
/// labelled evidence (decisions "Labnet deep reorgs (INV-REORG)").
const EVIDENCE_MIN_SECS: u64 = 600;

/// How long after a partition heals its reorganizations count as the
/// heal's rather than as connected-network ones.
const HEAL_SECS: u64 = 60;

/// Phases of a run. Reorganizations and found blocks are reported per phase.
const WARMUP: &str = "warmup";
const CONNECTED: &str = "connected";
const PARTITION: &str = "partition";
const HEAL: &str = "heal";
const FINAL: &str = "final";

fn rpc_port(base: u16, i: usize) -> u16 {
    base + 20 * i as u16
}
fn p2p_port(base: u16, i: usize) -> u16 {
    base + 20 * i as u16 + 1
}
fn proxy_port(base: u16, from: usize, to: usize) -> u16 {
    base + 2000 + 40 * from as u16 + to as u16
}
fn local(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

struct Link {
    from: usize,
    to: usize,
    handle: proxy::LinkHandle,
}

#[derive(Default, Serialize)]
struct Report {
    started_unix: u64,
    /// The `--version` text of the node and miner binaries, checked free of
    /// test-only code before the run ([`checked_version`]).
    binaries: BTreeMap<String, String>,
    duration_secs: u64,
    nodes: usize,
    final_height: u64,
    partitions: u32,
    /// The first node of the second partition group (and the second
    /// miner's node).
    partition_split: usize,
    tx_attempts: u32,
    tx_submitted: u32,
    tx_failures: BTreeMap<String, u32>,
    px_attempts: u32,
    px_submitted: u32,
    px_failures: BTreeMap<String, u32>,
    /// The warm-up: a single miner until the difficulty nears equilibrium.
    warmup: Warmup,
    /// Seconds from the end of the warm-up to the end of the traffic phase:
    /// the measured part of the run.
    measured_secs: u64,
    /// Reorganizations (log lines summed over all nodes) after the warm-up.
    reorganizations: u32,
    max_reorg_depth: u64,
    /// Depth -> count, after the warm-up.
    reorg_depths: BTreeMap<u64, u32>,
    /// The warm-up's reorganizations, reported separately (not in the above).
    warmup_reorganizations: u32,
    warmup_max_reorg_depth: u64,
    /// All reorganizations by phase: warmup, connected, partition, heal (the
    /// first 60 s after a partition heals) and final (the checks).
    reorgs_by_phase: BTreeMap<String, ReorgStats>,
    /// Blocks the miners found (accepted by their node), by phase, and how
    /// many of them their node did not adopt at submission.
    blocks_found_by_phase: BTreeMap<String, FoundStats>,
    miner_prebuild: bool,
    /// Each miner's mode arguments (all but its node, cookie and payout
    /// address).
    miner_modes: Vec<String>,
    misbehavior_disconnects: u32,
    crashes: Vec<String>,
    network: String,
    /// Samples in which all nodes had the same tip (the rest caught a block in flight).
    all_equal_samples: u32,
    /// A node stayed on a stale tip for more than 90 s while connected and behind.
    stuck_incidents: u32,
    samples: u32,
    max_rss_mb: BTreeMap<String, f64>,
    converged_at_end: bool,
    mempools_drained_at_end: bool,
    topology: String,
    /// The late joiner reached the final tip, and `late_joiner_required_peers`
    /// peers within `--late-peers-secs` of its start.
    late_joiner_synced: bool,
    late_joiner_peers: usize,
    late_joiner_required_peers: usize,
    /// Seconds from the late joiner's start to the required peers.
    late_joiner_secs_to_required: Option<f64>,
    late_joiner_max_peers: usize,
    /// Address-relay discovery (`--relay-joiners`), when run.
    relay_discovery: Option<RelayDiscovery>,
    fresh_wallet_balances_match: bool,
    /// Private balances of fresh restores equal the long-running wallets'.
    fresh_wallet_px_balances_match: bool,
    supply_conserved: bool,
    generated: u64,
    wallet_total: u64,
    /// Of `wallet_total`, the part held privately (PX records).
    wallet_px_total: u64,
    proxy_bytes: u64,
    checks_passed: bool,
    /// Whether the run may be cited as evidence: `checks_passed`, a warm-up
    /// that reached its criterion, miners with `--prebuild`, and a measured
    /// phase of at least 10 minutes. `evidence_notes` says what is missing.
    evidence: bool,
    evidence_notes: Vec<String>,
}

/// RT-LAB E2: a joiner learning nodes that joined after it asked for
/// addresses, through address relay only.
#[derive(Default, Serialize)]
struct RelayDiscovery {
    /// The joiner's peers once it had asked every lab node (before the
    /// relay nodes started).
    joiner_peers_before: usize,
    /// Per relay node: seconds from its start to its connection from the
    /// joiner (`None`: not within `--relay-wait-secs` of the last start).
    relay_connected_after_secs: Vec<Option<f64>>,
    joiner_peers_at_end: usize,
    /// Every relay node was reached.
    all_reached: bool,
}

#[derive(Default, Serialize)]
struct Warmup {
    enabled: bool,
    /// The criterion was met (else the warm-up hit `--warmup-max-mins`).
    reached: bool,
    secs: u64,
    /// Node 0's height and tip difficulty when the warm-up ended.
    end_height: u64,
    end_difficulty: u64,
    /// The mean block interval over the criterion window at the end.
    mean_interval_secs: Option<f64>,
    window_blocks: u64,
    ratio: f64,
    target_secs: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
struct ReorgStats {
    count: u32,
    max_depth: u64,
    /// Depth -> count.
    depths: BTreeMap<u64, u32>,
}

impl ReorgStats {
    fn add(&mut self, depth: u64) {
        self.count += 1;
        self.max_depth = self.max_depth.max(depth);
        *self.depths.entry(depth).or_insert(0) += 1;
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
struct FoundStats {
    found: u32,
    not_on_best_chain: u32,
    /// Templates the miners abandoned because their node's tip moved (the
    /// miner's `/tip` long poll, dossier 09 I1).
    abandoned: u32,
}

/// The mean interval (seconds) of the newest `window` or more blocks, from
/// the times a node first reported each height (`height -> seconds`).
/// Heights can be missing (two blocks between samples); the base is the
/// newest recorded height at least `window` below the top.
fn mean_interval(arrivals: &BTreeMap<u64, f64>, window: u64) -> Option<f64> {
    let (&top, &t_top) = arrivals.iter().next_back()?;
    let limit = top.checked_sub(window.max(1))?;
    let (&base, &t_base) = arrivals.range(..=limit).next_back()?;
    Some((t_top - t_base) / (top - base) as f64)
}

/// Records when `height` was first seen at `secs`. The height seen first
/// (`start`) is not recorded: its time is when the harness first looked,
/// not when it was mined. Counting it put the miner's start, minutes for a
/// full-mode dataset build, into the window, which then ended the warm-up
/// at difficulty 1 (W4-RX run 1).
fn record_arrival(
    arrivals: &mut BTreeMap<u64, f64>,
    start: &mut Option<u64>,
    height: u64,
    secs: f64,
) {
    let start = *start.get_or_insert(height);
    if height > start {
        arrivals.entry(height).or_insert(secs);
    }
}

/// The warm-up criterion: with a single miner, the difficulty is near its
/// equilibrium once blocks come at close to the target interval
/// (`mean >= ratio * target`). Below equilibrium blocks come faster; the
/// ratio allows for the noise of a window of exponential solve times
/// (a standard deviation of about target/sqrt(window)).
fn warmed_up(mean: Option<f64>, target_secs: u64, ratio: f64) -> bool {
    mean.is_some_and(|m| m >= ratio * target_secs as f64)
}

/// Log-file sizes at which phases begin, to attribute every log line to the
/// phase in which it was written.
#[derive(Default)]
struct PhaseMarks {
    marks: Vec<(&'static str, BTreeMap<String, u64>)>,
}

impl PhaseMarks {
    /// Records that `phase` begins now: the current size of every node and
    /// miner log in `dir`.
    fn mark(&mut self, phase: &'static str, dir: &Path) {
        let mut sizes = BTreeMap::new();
        for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if is_process_log(&name) {
                // The size through an open handle: on Windows the directory
                // entry's size (`DirEntry::metadata`) lags while another
                // process appends, which put every line of the first
                // evidence run in the last phase.
                let len = File::open(entry.path())
                    .and_then(|f| f.metadata())
                    .map_or(0, |m| m.len());
                sizes.insert(name, len);
            }
        }
        self.marks.push((phase, sizes));
    }

    /// The phase of the byte at `pos` of log `file`: that of the last mark
    /// at or below `pos`. Before its first mark a file belongs to that
    /// mark's phase; a file no mark knows (started later) to [`FINAL`].
    fn phase_at(&self, file: &str, pos: u64) -> &'static str {
        let mut phase = None;
        for (p, sizes) in &self.marks {
            let Some(&at) = sizes.get(file) else { continue };
            if phase.is_none() || at <= pos {
                phase = Some(*p);
            } else {
                break;
            }
        }
        phase.unwrap_or(FINAL)
    }
}

fn is_process_log(name: &str) -> bool {
    (name.starts_with("node") || name.starts_with("miner")) && name.ends_with(".log")
}

/// The depth of a node's `reorganization: disconnecting <depth> block(s)`
/// line.
fn reorg_depth(line: &str) -> Option<u64> {
    let rest = line.split("reorganization: disconnecting ").nth(1)?;
    rest.split_whitespace().next()?.parse().ok()
}

/// What the logs say, by phase.
#[derive(Default)]
struct LogStats {
    reorgs: BTreeMap<String, ReorgStats>,
    found: BTreeMap<String, FoundStats>,
    misbehavior: u32,
}

impl LogStats {
    /// Adds the lines of log `file` (bytes), each in the phase in which it
    /// was written.
    fn add_log(&mut self, file: &str, bytes: &[u8], marks: &PhaseMarks) {
        let mut pos = 0u64;
        for raw in bytes.split_inclusive(|b| *b == b'\n') {
            let phase = marks.phase_at(file, pos);
            pos += raw.len() as u64;
            let line = String::from_utf8_lossy(raw);
            if file.starts_with("node") {
                if let Some(depth) = reorg_depth(&line) {
                    self.reorgs.entry(phase.into()).or_default().add(depth);
                }
                if line.contains("for misbehavior") {
                    self.misbehavior += 1;
                }
            } else if line.contains("found block ") {
                let f = self.found.entry(phase.into()).or_default();
                f.found += 1;
                f.not_on_best_chain += u32::from(line.contains("not on the node's best chain"));
            } else if line.contains("new tip at height ") && line.contains(" abandoned") {
                self.found.entry(phase.into()).or_default().abandoned += 1;
            }
        }
    }
}

/// The `--version` text of a binary this labnet launches, refused when it
/// names test-only code (W4-GUARD). `cargo test` writes binaries with
/// dev-dependency features unified (the chain actor's test hooks among
/// them, whose log grows without bound) to the path a plain `cargo build
/// --release` uses; a labnet run is evidence, so it never runs one. The node
/// must print `build flags: none`; no binary may print a `+test-hooks:` or
/// `+fuzzing:` marker.
fn checked_version(bin: &Path, needs_flags_line: bool) -> Result<String, String> {
    let out = Command::new(bin)
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("{}: {e}", bin.display()))?;
    let text = String::from_utf8_lossy(&out.stdout).replace('\r', "");
    if !out.status.success() {
        return Err(format!(
            "{} --version failed ({})",
            bin.display(),
            out.status
        ));
    }
    version_verdict(&text, needs_flags_line).map_err(|e| format!("{}: {e}", bin.display()))?;
    Ok(text.trim_end().to_string())
}

/// [`checked_version`]'s verdict on a `--version` text.
fn version_verdict(text: &str, needs_flags_line: bool) -> Result<(), String> {
    if ["+test-hooks:", "+fuzzing:"]
        .iter()
        .any(|m| text.contains(m))
    {
        return Err(format!(
            "built with test-only code ({}); rebuild it with a plain `cargo build --release` \
             from a clean commit (docs/testnet.md)",
            text.lines()
                .find(|l| l.contains("+test-hooks:") || l.contains("+fuzzing:"))
                .unwrap_or_default()
        ));
    }
    if needs_flags_line && !text.lines().any(|l| l == "build flags: none") {
        return Err(
            "--version has no `build flags: none` line (a build older than \
                    W4-GUARD cannot show its test code)"
                .into(),
        );
    }
    Ok(())
}
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn log(out: &mut File, msg: &str) {
    let line = format!("[{}] {msg}", unix_now());
    println!("{line}");
    let _ = writeln!(out, "{line}");
}

/// Resident memory of a process in MB (Windows: tasklist, Linux: /proc).
fn rss_mb(pid: u32) -> Option<f64> {
    if cfg!(windows) {
        let o = Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
            .output()
            .ok()?;
        let s = String::from_utf8_lossy(&o.stdout);
        let field = s.split("\",\"").nth(4)?;
        let kb: f64 = field
            .chars()
            .filter(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse()
            .ok()?;
        Some(kb / 1024.0)
    } else {
        let s = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        let line = s.lines().find(|l| l.starts_with("VmRSS:"))?;
        let kb: f64 = line.split_whitespace().nth(1)?.parse().ok()?;
        Some(kb / 1024.0)
    }
}

struct Proc {
    name: String,
    child: Child,
}

fn spawn(bin: &Path, args: &[String], log_path: &Path, name: &str) -> Proc {
    let f = File::create(log_path).expect("log file");
    let child = Command::new(bin)
        .args(args)
        .stdout(Stdio::from(f.try_clone().expect("dup")))
        .stderr(Stdio::from(f))
        .spawn()
        .unwrap_or_else(|e| panic!("starting {}: {e}", bin.display()));
    Proc {
        name: name.into(),
        child,
    }
}

/// How long a connected node may stay behind the best height without
/// progress before it counts as stuck.
const STUCK_AFTER: Duration = Duration::from_secs(90);

/// Stuck detection for one node, fed once per sample. A node is stuck if,
/// while the network has been connected for a while, it stays behind the
/// best height and its tip does not move for more than [`STUCK_AFTER`].
/// Trailing the miner's node by a block at every sample while advancing is
/// progress, not a stall: counting it was the seedrun2 false positive
/// (docs/evidence/labnet-reorg-2026-09-27).
#[derive(Default)]
struct StuckDetector {
    /// Since when the node has been behind at its current tip.
    since: Option<Instant>,
    /// Its tip at the previous sample.
    tip: String,
    /// An incident was already counted for this stall.
    reported: bool,
}

impl StuckDetector {
    /// Returns true when this sample starts a new stuck incident.
    fn observe(
        &mut self,
        now: Instant,
        tip: &str,
        height: u64,
        best: u64,
        connected_long: bool,
    ) -> bool {
        let moved = self.tip != tip;
        self.tip = tip.to_string();
        if height >= best || !connected_long || moved {
            self.since = (height < best && connected_long).then_some(now);
            self.reported = false;
            return false;
        }
        let since = *self.since.get_or_insert(now);
        if now.duration_since(since) > STUCK_AFTER && !self.reported {
            self.reported = true;
            return true;
        }
        false
    }
}

/// A node's RPC cookie: `rpc.cookie` in its data directory (docs/blocks.md
/// §9.1). The node writes it at start and removes it at shutdown.
fn cookie_path(data: &Path) -> PathBuf {
    data.join(blacksilk_rpc::COOKIE_FILE)
}

/// A client of the node at `port` with data directory `data`, sending its
/// cookie.
fn client(port: u16, data: &Path) -> Result<Client, blacksilk_rpc::RpcError> {
    Client::try_new(&local(port).to_string())?.with_cookie_file(&cookie_path(data))
}

/// Waits until the node answers an authenticated `/info`. The cookie is read
/// on every attempt: the node binds its RPC port before it writes the file.
fn wait_rpc(port: u16, data: &Path, secs: u64) -> Option<Client> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if let Ok(c) = client(port, data) {
            if c.info().is_ok() {
                return Some(c);
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    None
}

fn infos(clients: &[Client]) -> Vec<Option<Info>> {
    clients.iter().map(|c| c.info().ok()).collect()
}

fn node_args(
    a: &Args,
    i: usize,
    data: &Path,
    peers: &[SocketAddr],
    max_outbound: usize,
    connect_only: bool,
) -> Vec<String> {
    let mut v = vec![
        "--network".into(),
        a.network.clone(),
        "--allow-private".into(),
        "--data-dir".into(),
        data.display().to_string(),
        "--rpc-bind".into(),
        local(rpc_port(a.base_port, i)).to_string(),
        "--p2p-bind".into(),
        local(p2p_port(a.base_port, i)).to_string(),
        // Every node advertises its own P2P port, or no node is ever learned
        // (docs/p2p.md §9: a node without `--public-address` is never
        // advertised) and the late joiner, which knows only node 0, stays
        // with one peer: node 0's table stays empty (W4-RX, INV-PEERS). The
        // lab nodes are connect-only, so they never dial these direct ports
        // around the proxies; the late joiner does, after the run.
        "--public-address".into(),
        local(p2p_port(a.base_port, i)).to_string(),
        "--max-outbound".into(),
        max_outbound.to_string(),
        "--no-builtin-seeds".into(),
    ];
    for p in peers {
        v.push("--peer".into());
        v.push(p.to_string());
    }
    // Lab links must stay the proxied ones so partitions are complete; discovery
    // is exercised separately by the late joiner.
    if connect_only {
        v.push("--connect-only".into());
    }
    v
}

/// Why a run may not be labelled evidence (empty: it may).
fn evidence_notes(r: &Report) -> Vec<String> {
    let mut notes = Vec::new();
    if !r.checks_passed {
        notes.push("checks did not pass".into());
    }
    if !r.warmup.enabled {
        notes.push("no warm-up (--no-warmup)".into());
    } else if !r.warmup.reached {
        notes.push("the warm-up did not reach its criterion".into());
    }
    if !r.miner_prebuild {
        notes.push("miners without --prebuild".into());
    }
    if r.measured_secs < EVIDENCE_MIN_SECS {
        notes.push(format!(
            "measured phase {} s, shorter than {} s",
            r.measured_secs, EVIDENCE_MIN_SECS
        ));
    }
    notes
}

/// What one metrics sample needs besides the processes and the report.
struct Sampling<'a> {
    clients: &'a [Client],
    metrics: &'a mut File,
    stuck: &'a mut [StuckDetector],
}

impl Sampling<'_> {
    /// Records one metrics row and checks crashes and stuck nodes.
    fn sample(
        &mut self,
        journal: &mut File,
        phase: &str,
        procs: &mut [Proc],
        report: &mut Report,
        partitioned: bool,
        connected_since: Instant,
    ) {
        let now = Instant::now();
        report.samples += 1;
        let is = infos(self.clients);
        let col = |f: &dyn Fn(&Info) -> String| -> String {
            is.iter()
                .map(|i| i.as_ref().map_or("-".into(), f))
                .collect::<Vec<_>>()
                .join("/")
        };
        let heights = col(&|i| i.height.to_string());
        let hh = col(&|i| i.header_height.to_string());
        let tips = col(&|i| i.tip[..8].to_string());
        let mps = col(&|i| i.mempool_txs.to_string());
        let peers = col(&|i| i.peers.to_string());
        // Tip difficulties: a run starts at the genesis difficulty, and
        // its reorganization counts depend on how far the difficulty still
        // is from the miners' equilibrium (docs/evidence/labnet-reorg-2026-09-27).
        let difficulties = col(&|i| i.difficulty.to_string());
        let mut rss = Vec::new();
        for p in procs.iter_mut() {
            if let Ok(Some(status)) = p.child.try_wait() {
                let msg = format!("{} exited: {status}", p.name);
                if !report.crashes.contains(&msg) {
                    log(journal, &format!("CRASH: {msg}"));
                    report.crashes.push(msg);
                }
            }
            let mb = rss_mb(p.child.id()).unwrap_or(0.0);
            let e = report.max_rss_mb.entry(p.name.clone()).or_insert(0.0);
            *e = e.max(mb);
            rss.push(format!("{mb:.0}"));
        }
        let all_equal = is
            .iter()
            .all(|i| i.as_ref().map(|x| &x.tip) == is[0].as_ref().map(|x| &x.tip));
        report.all_equal_samples += all_equal as u32;
        // Stuck: behind the best height without progress (`StuckDetector`).
        let best = is.iter().flatten().map(|x| x.height).max().unwrap_or(0);
        let connected_long =
            !partitioned && now.duration_since(connected_since) > Duration::from_secs(120);
        for (k, info) in is.iter().enumerate() {
            let Some(info) = info else { continue };
            if self.stuck[k].observe(now, &info.tip, info.height, best, connected_long) {
                report.stuck_incidents += 1;
                log(
                    journal,
                    &format!(
                        "node{k} stuck at height {} while best is {best}",
                        info.height
                    ),
                );
            }
        }
        let _ = writeln!(
            self.metrics,
            "{},{},{},{},{},{},{},{},{},{}",
            unix_now(),
            partitioned,
            heights,
            hh,
            tips,
            mps,
            peers,
            rss.join("/"),
            difficulties,
            phase
        );
        let _ = self.metrics.flush();
    }
}

/// The late-joiner check: it reached the final tip, and its required peers
/// within `window_secs` of its start.
fn late_joiner_passed(synced: bool, required_at: Option<f64>, window_secs: u64) -> bool {
    synced && required_at.is_some_and(|t| t <= window_secs as f64)
}

/// The final chain file: one `height id` line per block, genesis first.
const FINAL_CHAIN_FILE: &str = "final-chain.txt";

/// `height id` lines of `headers` (concatenated encodings) as block ids of
/// network `nid`.
fn chain_lines(headers: &[u8], nid: u32) -> Result<String, String> {
    if !headers.len().is_multiple_of(HEADER_SIZE) {
        return Err(format!("{} header bytes", headers.len()));
    }
    let mut out = String::new();
    for chunk in headers.chunks(HEADER_SIZE) {
        let header = BlockHeader::from_bytes(chunk).ok_or("a header does not decode")?;
        out.push_str(&format!(
            "{} {}\n",
            header.height,
            hex::encode(header.id(nid))
        ));
    }
    Ok(out)
}

/// Writes node `c`'s connected chain as `height id` lines to `path`.
fn write_final_chain(c: &Client, net: Network, path: &Path) -> Result<(), String> {
    let nid = ChainParams::for_network(net).network_id;
    let mut out = String::new();
    let mut from = 0;
    loop {
        let h = c
            .headers(from, MAX_HEADERS_PER_REQUEST)
            .map_err(|e| e.to_string())?;
        let bytes = hex::decode(&h.headers).map_err(|e| e.to_string())?;
        if bytes.is_empty() {
            break;
        }
        out.push_str(&chain_lines(&bytes, nid)?);
        from += (bytes.len() / HEADER_SIZE) as u64;
        if from > h.height {
            break;
        }
    }
    std::fs::write(path, out).map_err(|e| e.to_string())
}

/// RT-LAB E2 (`--relay-joiners`): stops the first late joiner, starts a
/// second one knowing only node 0 with room for every node, waits until it
/// has asked the lab nodes, then starts the relay nodes one by one and
/// measures when the joiner connects to each. A relay node is connect-only
/// and dials only node 0, and the lab nodes are connect-only, so a second
/// peer of a relay node is the joiner.
fn relay_discovery(
    a: &Args,
    node_bin: &Path,
    procs: &mut [Proc],
    journal: &mut File,
) -> RelayDiscovery {
    let n = a.nodes;
    let mut r = RelayDiscovery::default();
    for p in procs.iter_mut().filter(|p| p.name == "node-late") {
        let _ = p.child.kill();
    }
    let node0 = local(p2p_port(a.base_port, 0));
    let joiner = n + 1;
    let data = a.out.join("node-e2");
    let args = node_args(a, joiner, &data, &[node0], n + a.relay_joiners + 1, false);
    let mut own = vec![spawn(
        node_bin,
        &args,
        &a.out.join("node-e2.log"),
        "node-e2",
    )];
    let Some(jc) = wait_rpc(rpc_port(a.base_port, joiner), &data, 60) else {
        log(journal, "relay discovery: the joiner did not start");
        for p in &mut own {
            let _ = p.child.kill();
        }
        return r;
    };
    let asked = Instant::now() + Duration::from_secs(60);
    while Instant::now() < asked {
        if jc.info().is_ok_and(|i| i.peers >= n) {
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    r.joiner_peers_before = jc.info().map_or(0, |i| i.peers);
    let mut relays = Vec::new();
    for k in 0..a.relay_joiners {
        let i = n + 2 + k;
        let data = a.out.join(format!("node-relay{k}"));
        let args = node_args(a, i, &data, &[node0], 1, true);
        let name = format!("node-relay{k}");
        own.push(spawn(
            node_bin,
            &args,
            &a.out.join(format!("{name}.log")),
            &name,
        ));
        let started = Instant::now();
        let client = wait_rpc(rpc_port(a.base_port, i), &data, 60);
        relays.push((started, client));
        log(journal, &format!("relay discovery: {name} started"));
        if k + 1 < a.relay_joiners {
            std::thread::sleep(Duration::from_secs(a.relay_gap_secs));
        }
    }
    let mut reached: Vec<Option<f64>> = vec![None; relays.len()];
    let deadline = Instant::now() + Duration::from_secs(a.relay_wait_secs);
    while Instant::now() < deadline && reached.iter().any(|x| x.is_none()) {
        for (k, (started, client)) in relays.iter().enumerate() {
            let two = client
                .as_ref()
                .is_some_and(|c| c.info().is_ok_and(|i| i.peers >= 2));
            if reached[k].is_none() && two {
                reached[k] = Some(started.elapsed().as_secs_f64());
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    r.joiner_peers_at_end = jc.info().map_or(0, |i| i.peers);
    r.all_reached = reached.iter().all(|x| x.is_some());
    r.relay_connected_after_secs = reached;
    log(
        journal,
        &format!(
            "relay discovery: joiner peers {} before, {} at the end; relay nodes reached after {:?} s",
            r.joiner_peers_before, r.joiner_peers_at_end, r.relay_connected_after_secs
        ),
    );
    for p in &mut own {
        let _ = p.child.kill();
    }
    r
}

fn main() {
    let a = Args::parse();
    assert!(a.nodes >= 4, "need at least 4 nodes");
    // Ports: proxies at base + 2000 + 40 * from + to, processes at
    // base + 20 * i (lab nodes, joiners, relay nodes) below base + 2000.
    assert!(a.nodes <= 40, "at most 40 nodes (the proxy port layout)");
    assert!(
        a.nodes + 2 + a.relay_joiners < 100,
        "too many relay nodes for the port layout"
    );
    if a.evidence {
        assert!(
            a.duration_mins * 60 >= EVIDENCE_MIN_SECS,
            "--evidence needs --duration-mins of at least {} (the measured phase after the warm-up)",
            EVIDENCE_MIN_SECS / 60
        );
        assert!(!a.no_warmup, "--evidence needs the warm-up");
    }
    let prebuild = a.prebuild || a.evidence;
    let net = match a.network.as_str() {
        "regtest" => Network::Regtest,
        "testnet" => Network::Testnet,
        other => panic!("unsupported network {other}"),
    };
    // The node refuses a network whose genesis is not final; say so before
    // starting anything.
    assert!(
        ChainParams::for_network(net).genesis_is_final(),
        "the {} genesis is not final: the node refuses it (use --network regtest)",
        a.network
    );
    assert!(
        !a.out.exists(),
        "{} exists; choose a new output directory",
        a.out.display()
    );
    std::fs::create_dir_all(&a.out).unwrap();
    let mut journal = File::create(a.out.join("journal.log")).unwrap();
    let mut metrics = File::create(a.out.join("metrics.csv")).unwrap();
    writeln!(
        metrics,
        "unix,partitioned,heights,header_heights,tips,mempools,peers,rss_mb,difficulties,phase"
    )
    .unwrap();
    let node_bin = a.bin_dir.join(if cfg!(windows) {
        "blacksilk-node.exe"
    } else {
        "blacksilk-node"
    });
    let miner_bin = a.bin_dir.join(if cfg!(windows) {
        "blacksilk-miner.exe"
    } else {
        "blacksilk-miner"
    });
    // Before anything starts: no binary with test-only code (W4-GUARD), this
    // one (its in-process wallets link the chain layer) included.
    let own = blacksilk_chain::build_flags::BuildFlags::of_chain_layer();
    assert!(
        own.is_clean(),
        "refusing to start: this blacksilk-labnet was built with test-only code ({}); \
         rebuild it with a plain `cargo build --release`",
        own.render()
    );
    let mut binaries = BTreeMap::new();
    for (name, bin, needs_flags_line) in [("node", &node_bin, true), ("miner", &miner_bin, false)] {
        let version = checked_version(bin, needs_flags_line)
            .unwrap_or_else(|e| panic!("refusing to start the labnet: {e}"));
        log(
            &mut journal,
            &format!("{name} binary: {}", version.replace('\n', " | ")),
        );
        binaries.insert(name.to_string(), version);
    }
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut report = Report {
        started_unix: unix_now(),
        nodes: a.nodes,
        topology: a.topology.clone(),
        binaries,
        ..Default::default()
    };
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).unwrap();
    let mut rng = ChaCha20Rng::from_seed(seed);
    let n = a.nodes;
    let split = a.partition_split.unwrap_or(n / 2);
    assert!(
        (1..n).contains(&split),
        "--partition-split must be between 1 and {}",
        n - 1
    );
    report.partition_split = split;
    let group = |i: usize| usize::from(i >= split);

    // Links (`--topology`), each through a proxy.
    let mut links = Vec::new();
    for (i, j) in topology_links(&a.topology, n) {
        let h = rt
            .block_on(proxy::start(
                local(proxy_port(a.base_port, i, j)),
                local(p2p_port(a.base_port, j)),
                Duration::from_millis(a.latency_ms),
                a.jitter_ms,
            ))
            .expect("proxy bind");
        links.push(Link {
            from: i,
            to: j,
            handle: h,
        });
    }

    // Nodes.
    let data_of = |i: usize| a.out.join(format!("node{i}"));
    let mut procs: Vec<Proc> = Vec::new();
    for i in 0..n {
        let peers: Vec<SocketAddr> = links
            .iter()
            .filter(|l| l.from == i)
            .map(|l| local(proxy_port(a.base_port, l.from, l.to)))
            .collect();
        let data = data_of(i);
        let args = node_args(&a, i, &data, &peers, peers.len(), true);
        procs.push(spawn(
            &node_bin,
            &args,
            &a.out.join(format!("node{i}.log")),
            &format!("node{i}"),
        ));
    }
    let clients: Vec<Client> = (0..n)
        .map(|i| {
            wait_rpc(rpc_port(a.base_port, i), &data_of(i), 60)
                .unwrap_or_else(|| panic!("node{i} did not start"))
        })
        .collect();
    log(&mut journal, &format!("{n} nodes up"));

    // Wallets: two miners (one per partition group) and three users.
    report.network = a.network.clone();
    let rules = TxRules::for_chain(&ChainParams::for_network(net));
    let mut wallets: Vec<(String, Wallet)> = Vec::new();
    for name in ["miner-a", "miner-b", "user-1", "user-2", "user-3"] {
        wallets.push((name.into(), Wallet::generate(net, 1).unwrap()));
    }
    report.miner_prebuild = prebuild;
    let miner_nodes = [0, split];
    // A miner's arguments, and its mode for the report.
    let miner_args = |k: usize, wallets: &mut Vec<(String, Wallet)>| -> (Vec<String>, String) {
        let node = miner_nodes[k];
        let addr = wallets[k].1.address(0, 0);
        let light_second = k == 1 && a.light_second_miner;
        let full = a.miner_full && !light_second;
        let threads = if light_second { 1 } else { a.miner_threads };
        let mut mode: Vec<String> = vec![
            "--threads".into(),
            threads.to_string(),
            "--refresh".into(),
            "5".into(),
        ];
        if !full {
            mode.push("--light".into());
        }
        if prebuild {
            mode.push("--prebuild".into());
            mode.push(if full {
                a.full_prebuild.clone()
            } else {
                "on".into()
            });
        }
        if let (true, Some(t)) = (full, a.miner_build_threads) {
            mode.push("--build-threads".into());
            mode.push(t.to_string());
        }
        let mut args: Vec<String> = vec![
            "--node".into(),
            local(rpc_port(a.base_port, node)).to_string(),
            "--rpc-cookie".into(),
            cookie_path(&data_of(node)).display().to_string(),
            "--address".into(),
            addr,
        ];
        args.extend(mode.iter().cloned());
        (args, format!("miner{k}: {}", mode.join(" ")))
    };
    let mut stuck: Vec<StuckDetector> = (0..n).map(|_| StuckDetector::default()).collect();
    let mut sampling = Sampling {
        clients: &clients,
        metrics: &mut metrics,
        stuck: &mut stuck,
    };
    let mut marks = PhaseMarks::default();
    let run_start = Instant::now();

    // Warm-up (decisions "Labnet deep reorgs (INV-REORG)"): the first miner
    // alone until the difficulty nears its equilibrium. Two miners from the
    // genesis difficulty mine in lockstep at difficulty 1 and split deeply
    // (docs/evidence/labnet-reorg-2026-09-27); those splits say nothing
    // about the network at a working difficulty.
    let target_secs = ChainParams::for_network(net).target_block_time;
    report.warmup = Warmup {
        enabled: !a.no_warmup,
        window_blocks: a.warmup_window,
        ratio: a.warmup_ratio,
        target_secs,
        ..Default::default()
    };
    let (args0, mode0) = miner_args(0, &mut wallets);
    report.miner_modes.push(mode0);
    procs.push(spawn(
        &miner_bin,
        &args0,
        &a.out.join("miner0.log"),
        "miner0",
    ));
    if !a.no_warmup {
        marks.mark(WARMUP, &a.out);
        log(
            &mut journal,
            &format!(
                "warm-up: miner0 alone until the mean interval of {} blocks is at least {} x {target_secs} s (at most {} min)",
                a.warmup_window, a.warmup_ratio, a.warmup_max_mins
            ),
        );
        let deadline = run_start + Duration::from_secs(a.warmup_max_mins * 60);
        let mut arrivals: BTreeMap<u64, f64> = BTreeMap::new();
        let mut start_height: Option<u64> = None;
        let mut next_sample = run_start;
        let mut last = None;
        while Instant::now() < deadline {
            if Instant::now() >= next_sample {
                next_sample = Instant::now() + Duration::from_secs(15);
                sampling.sample(
                    &mut journal,
                    WARMUP,
                    &mut procs,
                    &mut report,
                    false,
                    run_start,
                );
            }
            if let Ok(i) = clients[0].info() {
                record_arrival(
                    &mut arrivals,
                    &mut start_height,
                    i.height,
                    run_start.elapsed().as_secs_f64(),
                );
                last = Some(i);
            }
            let mean = mean_interval(&arrivals, a.warmup_window);
            report.warmup.mean_interval_secs = mean;
            if warmed_up(mean, target_secs, a.warmup_ratio) {
                report.warmup.reached = true;
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        report.warmup.secs = run_start.elapsed().as_secs();
        if let Some(i) = &last {
            report.warmup.end_height = i.height;
            report.warmup.end_difficulty = i.difficulty;
        }
        log(
            &mut journal,
            &format!(
                "warm-up {} after {} s at height {} (difficulty {}, mean interval {} s)",
                if report.warmup.reached {
                    "done"
                } else {
                    "ended WITHOUT reaching its criterion"
                },
                report.warmup.secs,
                report.warmup.end_height,
                report.warmup.end_difficulty,
                report
                    .warmup
                    .mean_interval_secs
                    .map_or("-".into(), |m| format!("{m:.1}"))
            ),
        );
    }
    let (args1, mode1) = miner_args(1, &mut wallets);
    report.miner_modes.push(mode1);
    procs.push(spawn(
        &miner_bin,
        &args1,
        &a.out.join("miner1.log"),
        "miner1",
    ));
    marks.mark(CONNECTED, &a.out);
    log(
        &mut journal,
        &format!("miners running on nodes 0 and {split} (one per partition group)"),
    );

    // Main loop: the measured phase.
    let start = Instant::now();
    let end = start + Duration::from_secs(a.duration_mins * 60);
    let mut next_sample = start;
    let mut next_tx = start + Duration::from_secs(60);
    // PX needs mature coinbase outputs first (60 blocks).
    let mut next_px = start + Duration::from_secs(60 * a.px_every_mins.max(12));
    let mut partition_until: Option<Instant> = None;
    let mut heal_until: Option<Instant> = None;
    let mut next_partition = start + Duration::from_secs(a.partition_every_mins * 60);
    let mut connected_since = start;
    while Instant::now() < end {
        let now = Instant::now();

        if heal_until.is_some_and(|t| now >= t) {
            heal_until = None;
            marks.mark(CONNECTED, &a.out);
        }
        // Partitions.
        if a.partition_every_mins > 0 && partition_until.is_none() && now >= next_partition {
            heal_until = None;
            marks.mark(PARTITION, &a.out);
            for l in &links {
                if group(l.from) != group(l.to) {
                    l.handle.set_up(false);
                }
            }
            partition_until = Some(now + Duration::from_secs(a.partition_mins * 60));
            report.partitions += 1;
            log(
                &mut journal,
                &format!(
                    "partition #{} started (groups split at node {})",
                    report.partitions, split
                ),
            );
        }
        if partition_until.is_some_and(|t| now >= t) {
            for l in &links {
                l.handle.set_up(true);
            }
            partition_until = None;
            connected_since = now;
            next_partition = now + Duration::from_secs(a.partition_every_mins * 60);
            heal_until = Some(now + Duration::from_secs(HEAL_SECS));
            marks.mark(HEAL, &a.out);
            log(&mut journal, "partition healed");
        }

        // Samples and invariants.
        if now >= next_sample {
            next_sample = now + Duration::from_secs(15);
            let partitioned = partition_until.is_some();
            let phase = if partitioned {
                PARTITION
            } else if heal_until.is_some() {
                HEAL
            } else {
                CONNECTED
            };
            sampling.sample(
                &mut journal,
                phase,
                &mut procs,
                &mut report,
                partitioned,
                connected_since,
            );
        }

        // Transactions.
        if now >= next_tx {
            next_tx = now + Duration::from_secs(a.tx_every_secs);
            let from = (rng.next_u32() as usize) % wallets.len();
            let node = (rng.next_u32() as usize) % n;
            let mut to = (rng.next_u32() as usize) % wallets.len();
            if to == from {
                to = (to + 1) % wallets.len();
            }
            let dest_str = wallets[to].1.address(0, rng.next_u32() % 4);
            let dest = blacksilk_chain::address::decode_address(net, &dest_str).unwrap();
            let amount = COIN / 10 + rng.next_u64() % COIN;
            let (name, w) = &mut wallets[from];
            let name = name.clone();
            match w.sync(&clients[node]) {
                Ok(_) if w.balance().unlocked > amount + COIN => {
                    report.tx_attempts += 1;
                    match w.transfer(&clients[node], &dest, amount, &rules, &mut rng) {
                        Ok(_) => {
                            report.tx_submitted += 1;
                        }
                        Err(e) => {
                            let key = format!("{e}").split(':').next().unwrap_or("?").to_string();
                            *report.tx_failures.entry(key).or_insert(0) += 1;
                            log(
                                &mut journal,
                                &format!("tx from {name} via node{node} failed: {e}"),
                            );
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => log(&mut journal, &format!("sync {name} via node{node}: {e}")),
            }
            // Unconfirmed spends expire inside the wallet (20 blocks); the harness
            // never clears them itself.
        }

        // Private (PX) activity.
        if a.px_every_mins > 0 && now >= next_px {
            next_px = now + Duration::from_secs(60 * a.px_every_mins);
            let from = (rng.next_u32() as usize) % wallets.len();
            let node = (rng.next_u32() as usize) % n;
            let mut to = (rng.next_u32() as usize) % wallets.len();
            if to == from {
                to = (to + 1) % wallets.len();
            }
            let px_dest_str = wallets[to].1.px_address(rng.next_u32() % 3);
            let px_dest = blacksilk_chain::address::decode_px_address(net, &px_dest_str).unwrap();
            let v1_dest_str = wallets[to].1.address(0, rng.next_u32() % 4);
            let v1_dest = blacksilk_chain::address::decode_address(net, &v1_dest_str).unwrap();
            let fee = blacksilk_tx::px_builder::px_standard_fee();
            let (name, w) = &mut wallets[from];
            let name = name.clone();
            if w.sync(&clients[node]).is_ok() {
                let (_, spendable) = w.px_balance();
                let unlocked = w.balance().unlocked;
                let result = if spendable >= COIN / 2 + fee {
                    report.px_attempts += 1;
                    if rng.next_u32() % 3 == 0 {
                        w.px_withdraw(&clients[node], &v1_dest, COIN / 10, &rules, &mut rng)
                            .map(|_| "withdraw")
                    } else {
                        w.px_send(&clients[node], &px_dest, COIN / 5, &rules, &mut rng)
                            .map(|_| "send")
                    }
                } else if unlocked > 2 * COIN {
                    report.px_attempts += 1;
                    w.px_deposit(&clients[node], COIN, &rules, &mut rng)
                        .map(|_| "deposit")
                } else {
                    Ok("none")
                };
                match result {
                    Ok("none") => {}
                    Ok(kind) => {
                        report.px_submitted += 1;
                        log(&mut journal, &format!("px {kind} by {name} via node{node}"));
                    }
                    Err(e) => {
                        let key = format!("{e}").split(':').next().unwrap_or("?").to_string();
                        *report.px_failures.entry(key).or_insert(0) += 1;
                        log(
                            &mut journal,
                            &format!("px by {name} via node{node} failed: {e}"),
                        );
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    report.measured_secs = start.elapsed().as_secs();
    marks.mark(FINAL, &a.out);
    log(&mut journal, "traffic phase over; final checks");

    // --- Final checks -----------------------------------------------------------
    for l in &links {
        l.handle.set_up(true);
    }
    // Convergence (tips equal) and drained mempools (miners keep mining).
    let deadline = Instant::now() + Duration::from_secs(600);
    let mut converged = false;
    let mut drained = false;
    while Instant::now() < deadline {
        let is = infos(&clients);
        converged = is.iter().all(|i| i.is_some())
            && is
                .iter()
                .all(|i| i.as_ref().map(|x| &x.tip) == is[0].as_ref().map(|x| &x.tip));
        drained = is
            .iter()
            .all(|i| i.as_ref().is_some_and(|x| x.mempool_txs == 0));
        if converged && drained {
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    report.converged_at_end = converged;
    report.mempools_drained_at_end = drained;
    // Stop the miners, then take a stable snapshot.
    for p in procs.iter_mut().filter(|p| p.name.starts_with("miner")) {
        let _ = p.child.kill();
    }
    std::thread::sleep(Duration::from_secs(20));
    let final_info = clients[0].info().ok();
    report.final_height = final_info.as_ref().map_or(0, |i| i.height);
    report.generated = final_info.as_ref().map_or(0, |i| i.generated);
    log(
        &mut journal,
        &format!(
            "converged={converged} drained={drained} height={}",
            report.final_height
        ),
    );

    // Late joiner: one direct peer (node 0), discovers the rest through Addr.
    // The final chain (height, id) from node 0: the report tool splits the
    // miners' found blocks into kept and stale by it.
    if let Err(e) = write_final_chain(&clients[0], net, &a.out.join(FINAL_CHAIN_FILE)) {
        log(&mut journal, &format!("final chain not written: {e}"));
    }

    // Late joiner: one direct peer (node 0), discovers the rest through Addr.
    let late = n;
    let data = a.out.join("node-late");
    let args = node_args(
        &a,
        late,
        &data,
        &[local(p2p_port(a.base_port, 0))],
        a.late_max_outbound,
        false,
    );
    let late_start = Instant::now();
    procs.push(spawn(
        &node_bin,
        &args,
        &a.out.join("node-late.log"),
        "node-late",
    ));
    let late_client = wait_rpc(rpc_port(a.base_port, late), &data, 60).expect("late node started");
    let required = required_late_peers(a.late_max_outbound, n);
    report.late_joiner_required_peers = required;
    let mut peer_log = File::create(a.out.join("late-peers.csv")).unwrap();
    writeln!(peer_log, "secs,peers,height").unwrap();
    let (mut synced, mut required_at) = (false, None);
    let deadline = late_start + Duration::from_secs(900);
    while Instant::now() < deadline {
        if let Ok(li) = late_client.info() {
            let secs = late_start.elapsed().as_secs_f64();
            let _ = writeln!(peer_log, "{secs:.1},{},{}", li.peers, li.height);
            report.late_joiner_peers = li.peers;
            report.late_joiner_max_peers = report.late_joiner_max_peers.max(li.peers);
            synced |= final_info.as_ref().is_some_and(|fi| li.tip == fi.tip);
            if li.peers >= required && required_at.is_none() {
                required_at = Some(secs);
            }
            let window_over = secs > a.late_peers_secs as f64;
            if synced && (required_at.is_some() || window_over) {
                break;
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    report.late_joiner_secs_to_required = required_at;
    report.late_joiner_synced = late_joiner_passed(synced, required_at, a.late_peers_secs);
    log(
        &mut journal,
        &format!(
            "late joiner synced={synced} peers={} (required {required}, reached after {}, max {})",
            report.late_joiner_peers,
            required_at.map_or("never".into(), |t| format!("{t:.1} s")),
            report.late_joiner_max_peers
        ),
    );

    // Fresh wallets from seed against the late node vs. long-running wallets.
    let mut all_match = true;
    let mut px_match = true;
    let mut total = 0u64;
    let mut px_total = 0u64;
    for (name, w) in &mut wallets {
        let _ = w.sync(&clients[0]);
        w.clear_pending();
        let mut fresh = Wallet::from_mnemonic(net, &w.mnemonic(), 1).unwrap();
        for i in 0..4 {
            fresh.address(0, i);
        }
        let fresh_ok = fresh.sync(&late_client).is_ok();
        for i in 0..3 {
            fresh.px_address(i);
        }
        let fresh_ok = fresh_ok && fresh.sync(&late_client).is_ok();
        let (b1, b2) = (w.balance(), fresh.balance());
        let (p1, p2) = (w.px_balance().0, fresh.px_balance().0);
        total += b1.total + p1;
        px_total += p1;
        let ok = fresh_ok && b1.total == b2.total;
        all_match &= ok;
        px_match &= fresh_ok && p1 == p2;
        log(
            &mut journal,
            &format!(
                "{name}: balance {} (fresh restore: {}), private {} (fresh restore: {}) {}",
                format_amount(b1.total),
                format_amount(b2.total),
                format_amount(p1),
                format_amount(p2),
                if ok && p1 == p2 { "OK" } else { "MISMATCH" }
            ),
        );
    }
    report.fresh_wallet_balances_match = all_match;
    report.fresh_wallet_px_balances_match = px_match;
    report.wallet_total = total;
    report.wallet_px_total = px_total;
    report.supply_conserved = total == report.generated;
    log(
        &mut journal,
        &format!(
            "supply: generated {} vs wallets {}",
            format_amount(report.generated),
            format_amount(total)
        ),
    );

    if a.relay_joiners > 0 {
        report.relay_discovery = Some(relay_discovery(&a, &node_bin, &mut procs, &mut journal));
    }

    for p in &mut procs {
        let _ = p.child.kill();
    }
    // Log analysis: every line in the phase in which it was written.
    let mut stats = LogStats::default();
    for entry in std::fs::read_dir(&a.out).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !is_process_log(&name) {
            continue;
        }
        let bytes = std::fs::read(entry.path()).unwrap_or_default();
        stats.add_log(&name, &bytes, &marks);
    }
    report.misbehavior_disconnects = stats.misbehavior;
    for (phase, r) in &stats.reorgs {
        if phase == WARMUP {
            report.warmup_reorganizations = r.count;
            report.warmup_max_reorg_depth = r.max_depth;
            continue;
        }
        report.reorganizations += r.count;
        report.max_reorg_depth = report.max_reorg_depth.max(r.max_depth);
        for (d, c) in &r.depths {
            *report.reorg_depths.entry(*d).or_insert(0) += c;
        }
    }
    report.reorgs_by_phase = stats.reorgs;
    report.blocks_found_by_phase = stats.found;
    report.proxy_bytes = links
        .iter()
        .map(|l| l.handle.bytes.load(std::sync::atomic::Ordering::Relaxed))
        .sum();
    report.duration_secs = run_start.elapsed().as_secs();
    report.checks_passed = report.crashes.is_empty()
        && report.converged_at_end
        && report.mempools_drained_at_end
        && report.late_joiner_synced
        && report
            .relay_discovery
            .as_ref()
            .is_none_or(|r| r.all_reached)
        && report.fresh_wallet_balances_match
        && report.fresh_wallet_px_balances_match
        && report.supply_conserved
        && report.misbehavior_disconnects == 0
        && report.stuck_incidents == 0;
    report.evidence_notes = evidence_notes(&report);
    report.evidence = report.evidence_notes.is_empty();
    let json = serde_json::to_string_pretty(&report).unwrap();
    std::fs::write(a.out.join("summary.json"), &json).unwrap();
    println!("{json}");
    rt.shutdown_background();
    let ok = report.checks_passed && (report.evidence || !a.evidence);
    std::process::exit(if ok { 0 } else { 1 });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// W4-GUARD: a launched binary that names test-only code is refused, and
    /// the node must say `build flags: none`.
    #[test]
    fn binaries_with_test_code_are_refused() {
        let clean = "0.1.0\ncommit abc\nbuild flags: none\nregtest: genesis 00\n";
        assert_eq!(version_verdict(clean, true), Ok(()));
        let miner = "blacksilk-miner 0.1.0 (commit abc)\n";
        assert_eq!(version_verdict(miner, false), Ok(()));
        // A node older than the guard cannot show its test code.
        assert!(version_verdict("0.1.0\ncommit abc\n", true).is_err());
        for marked in [
            "0.1.0\ncommit abc\nbuild flags: +test-hooks:px +test-hooks:tx\n",
            "blacksilk-miner 0.1.0 (commit abc) +test-hooks:chain\n",
            "0.1.0\ncommit abc\nbuild flags: +fuzzing:p2p\n",
        ] {
            let e = version_verdict(marked, false).unwrap_err();
            assert!(e.contains("test-only code"), "{e}");
        }
    }

    fn at(start: Instant, secs: u64) -> Instant {
        start + Duration::from_secs(secs)
    }

    /// The seedrun2 incident (metrics 1790507835-1790507911): node1 trailed
    /// the miner's node by one block at every sample while its height went
    /// 2556, 2559, 2564, 2566. It advanced, so it is not stuck.
    #[test]
    fn trailing_by_one_while_advancing_is_not_stuck() {
        let t0 = Instant::now();
        let mut d = StuckDetector::default();
        let samples = [(2556, 2557), (2559, 2560), (2564, 2565), (2566, 2567)];
        for (i, (h, best)) in samples.into_iter().enumerate() {
            let tip = format!("tip{h}");
            assert!(!d.observe(at(t0, 40 * i as u64), &tip, h, best, true));
        }
    }

    #[test]
    fn behind_at_the_same_tip_is_stuck_once() {
        let t0 = Instant::now();
        let mut d = StuckDetector::default();
        assert!(!d.observe(at(t0, 0), "a", 10, 11, true));
        assert!(!d.observe(at(t0, 60), "a", 10, 12, true));
        assert!(d.observe(at(t0, 91), "a", 10, 13, true));
        assert!(!d.observe(at(t0, 200), "a", 10, 14, true), "counted once");
        // Caught up, then stalled again: a new incident.
        assert!(!d.observe(at(t0, 210), "b", 14, 14, true));
        assert!(!d.observe(at(t0, 220), "b", 14, 15, true));
        assert!(d.observe(at(t0, 311), "b", 14, 16, true));
    }

    fn arrivals(v: &[(u64, f64)]) -> BTreeMap<u64, f64> {
        v.iter().copied().collect()
    }

    #[test]
    fn the_mean_interval_needs_a_full_window() {
        assert_eq!(mean_interval(&BTreeMap::new(), 3), None);
        let a = arrivals(&[(1, 0.0), (2, 1.0), (3, 2.0)]);
        assert_eq!(mean_interval(&a, 3), None, "only 2 intervals");
        let a = arrivals(&[(1, 0.0), (2, 1.0), (3, 2.0), (4, 32.0)]);
        assert_eq!(mean_interval(&a, 3), Some(32.0 / 3.0));
        // Heights 5 and 6 arrived between samples: the base is the newest
        // height at least the window below the top.
        let a = arrivals(&[(1, 0.0), (2, 1.0), (4, 12.0), (7, 42.0)]);
        assert_eq!(mean_interval(&a, 3), Some(30.0 / 3.0));
        assert_eq!(mean_interval(&a, 4), Some(41.0 / 5.0));
    }

    /// W4-RX run 1: a full-mode miner builds its dataset for about 290 s,
    /// then mines 30 blocks at difficulty 1 in about 25 s. Timed from the
    /// genesis, the window's mean was 10.4 s and the warm-up ended; the
    /// starting tip must not count.
    #[test]
    fn the_miners_start_is_not_a_block_interval() {
        let (mut arrivals, mut start) = (BTreeMap::new(), None);
        for s in 0..290 {
            record_arrival(&mut arrivals, &mut start, 0, s as f64);
        }
        for h in 1..=30 {
            record_arrival(&mut arrivals, &mut start, h, 290.0 + 0.8 * h as f64);
        }
        let mean = mean_interval(&arrivals, 30);
        assert!(!warmed_up(mean, 10, 0.75), "{mean:?}");
        record_arrival(&mut arrivals, &mut start, 31, 316.0);
        let mean = mean_interval(&arrivals, 30).expect("a full window");
        assert!(mean < 1.0 && !warmed_up(Some(mean), 10, 0.75));
        // The pre-fix computation, with the genesis at time 0.
        let mut old = arrivals.clone();
        old.insert(0, 0.0);
        old.remove(&31);
        assert!(warmed_up(mean_interval(&old, 30), 10, 0.75));
    }

    /// At difficulty 1 (the genesis gap) blocks come every 1-2 s against a
    /// 10 s target: not warmed up; near equilibrium they come at about T.
    #[test]
    fn the_warmup_ends_near_the_target_interval() {
        assert!(!warmed_up(None, 10, 0.75));
        assert!(!warmed_up(Some(1.2), 10, 0.75));
        assert!(!warmed_up(Some(7.4), 10, 0.75));
        assert!(warmed_up(Some(7.5), 10, 0.75));
        assert!(warmed_up(Some(11.0), 10, 0.75));
    }

    fn marks(v: &[(&'static str, &[(&str, u64)])]) -> PhaseMarks {
        PhaseMarks {
            marks: v
                .iter()
                .map(|(p, sizes)| {
                    let sizes = sizes.iter().map(|(f, s)| (f.to_string(), *s)).collect();
                    (*p, sizes)
                })
                .collect(),
        }
    }

    #[test]
    fn log_lines_belong_to_the_phase_they_were_written_in() {
        let m = marks(&[
            (WARMUP, &[("node0.log", 0), ("miner0.log", 0)]),
            (
                CONNECTED,
                &[("node0.log", 100), ("miner0.log", 50), ("miner1.log", 0)],
            ),
            (
                PARTITION,
                &[("node0.log", 200), ("miner0.log", 60), ("miner1.log", 10)],
            ),
        ]);
        assert_eq!(m.phase_at("node0.log", 0), WARMUP);
        assert_eq!(m.phase_at("node0.log", 99), WARMUP);
        assert_eq!(m.phase_at("node0.log", 100), CONNECTED);
        assert_eq!(m.phase_at("node0.log", 250), PARTITION);
        assert_eq!(m.phase_at("miner1.log", 5), CONNECTED);
        assert_eq!(m.phase_at("node-late.log", 0), FINAL, "started later");
    }

    /// Warm-up reorganizations are counted apart from the rest, by depth.
    #[test]
    fn reorganizations_and_found_blocks_are_split_by_phase() {
        let warm =
            "[t INFO blacksilk_chain] reorganization: disconnecting 22 block(s) above height 3\n";
        let later = "[t INFO blacksilk_chain] reorganization: disconnecting 2 block(s) above height 300\n\
                     [t WARN blacksilk_chain] reorganization: disconnecting 9 block(s) above height 310. A reorganization this deep\n\
                     [t INFO blacksilk_p2p] disconnecting peer 1.2.3.4 for misbehavior: x\n";
        let node = format!("{warm}{later}");
        let m = marks(&[
            (WARMUP, &[("node1.log", 0), ("miner0.log", 0)]),
            (
                CONNECTED,
                &[("node1.log", warm.len() as u64), ("miner0.log", 0)],
            ),
        ]);
        let mut s = LogStats::default();
        s.add_log("node1.log", node.as_bytes(), &m);
        s.add_log(
            "miner0.log",
            b"[t INFO blacksilk_miner] found block 5 (reward 1 BLK, 0 txs)\n\
              [t INFO blacksilk_miner] found block 6 (reward 1 BLK, 0 txs); not on the node's best chain\n\
              [t INFO blacksilk_miner] new tip at height 6: work on template 7 abandoned after 1.2s\n\
              [t WARN blacksilk_miner] block 7 rejected: x\n",
            &m,
        );
        assert_eq!(s.reorgs[WARMUP].count, 1);
        assert_eq!(s.reorgs[WARMUP].max_depth, 22);
        let c = &s.reorgs[CONNECTED];
        assert_eq!((c.count, c.max_depth), (2, 9));
        assert_eq!(c.depths, BTreeMap::from([(2, 1), (9, 1)]));
        assert_eq!(s.misbehavior, 1);
        assert_eq!(
            s.found[CONNECTED],
            FoundStats {
                found: 2,
                not_on_best_chain: 1,
                abandoned: 1,
            }
        );
    }

    #[test]
    fn a_short_or_unwarmed_run_is_not_evidence() {
        let mut r = Report {
            checks_passed: true,
            miner_prebuild: true,
            measured_secs: EVIDENCE_MIN_SECS,
            ..Default::default()
        };
        r.warmup.enabled = true;
        r.warmup.reached = true;
        assert!(evidence_notes(&r).is_empty());
        r.measured_secs = EVIDENCE_MIN_SECS - 1;
        assert_eq!(evidence_notes(&r).len(), 1);
        r.measured_secs = EVIDENCE_MIN_SECS;
        r.warmup.reached = false;
        r.miner_prebuild = false;
        assert_eq!(evidence_notes(&r).len(), 2);
    }

    /// INV-PEERS: every node advertises its own P2P port (without it no node
    /// is learned and the late joiner stays with one peer, W4-RX); the lab
    /// nodes stay connect-only, the late joiner does not.
    #[test]
    fn every_node_advertises_its_own_port() {
        let a = Args::try_parse_from(["labnet", "--bin-dir", "b", "--out", "o"]).unwrap();
        let peer = [local(proxy_port(a.base_port, 1, 2))];
        for (i, connect_only) in [(1, true), (4, false)] {
            let v = node_args(&a, i, Path::new("d"), &peer, 1, connect_only);
            let at = v.iter().position(|x| x == "--public-address");
            let advertised = at.map(|k| v[k + 1].clone());
            assert_eq!(
                advertised,
                Some(local(p2p_port(a.base_port, i)).to_string()),
                "{v:?}"
            );
            assert_eq!(v.contains(&"--connect-only".to_string()), connect_only);
        }
    }

    /// `ring-chords` (the default) links every pair of 5 nodes; `ring`
    /// links each node to its successor only, so a block crosses up to
    /// n/2 hops (RT-LAB F4).
    #[test]
    fn topologies() {
        let rc = topology_links("ring-chords", 5);
        assert_eq!(rc.len(), 10);
        let pairs: std::collections::BTreeSet<(usize, usize)> =
            rc.iter().map(|&(a, b)| (a.min(b), a.max(b))).collect();
        assert_eq!(pairs.len(), 10, "every pair of 5 nodes");
        let ring = topology_links("ring", 8);
        assert_eq!(ring, (0..8).map(|i| (i, (i + 1) % 8)).collect::<Vec<_>>());
        let a = Args::try_parse_from(["labnet", "--bin-dir", "b", "--out", "o"]).unwrap();
        assert_eq!(a.topology, "ring-chords");
        assert!(
            Args::try_parse_from(["l", "--bin-dir", "b", "--out", "o", "--topology", "star"])
                .is_err()
        );
    }

    /// RT-LAB F4: the old check (2 peers) passed with the GetAddr floor
    /// reverted. The joiner must fill its outbound slots plus one
    /// block-relay-only connection, or reach every node of a smaller network.
    #[test]
    fn the_late_joiner_must_fill_its_slots() {
        assert_eq!(required_late_peers(4, 5), 5);
        assert_eq!(required_late_peers(4, 12), 5);
        assert_eq!(required_late_peers(8, 5), 5);
        assert_eq!(required_late_peers(1, 5), 2);
        assert!(late_joiner_passed(true, Some(2.4), 120));
        assert!(!late_joiner_passed(true, Some(121.0), 120), "too late");
        assert!(!late_joiner_passed(true, None, 120), "never");
        assert!(!late_joiner_passed(false, Some(2.4), 120), "not synced");
    }

    #[test]
    fn the_final_chain_lists_ids_by_height() {
        let nid = ChainParams::regtest().network_id;
        let g = ChainParams::regtest().genesis;
        let mut h1 = g;
        h1.height = 1;
        h1.prev_id = g.id(nid);
        let mut bytes = g.to_bytes().to_vec();
        bytes.extend_from_slice(&h1.to_bytes());
        let text = chain_lines(&bytes, nid).unwrap();
        assert_eq!(
            text,
            format!(
                "0 {}\n1 {}\n",
                hex::encode(g.id(nid)),
                hex::encode(h1.id(nid))
            )
        );
        assert!(chain_lines(&bytes[..150], nid).is_err(), "a torn header");
    }

    /// E2's joiner has room for every node; its relay nodes are
    /// connect-only and dial node 0 only.
    #[test]
    fn relay_nodes_dial_node_0_only() {
        let a = Args::try_parse_from(["l", "--bin-dir", "b", "--out", "o", "--relay-joiners", "3"])
            .unwrap();
        assert_eq!(a.relay_joiners, 3);
        let node0 = local(p2p_port(a.base_port, 0));
        let v = node_args(&a, 7, Path::new("d"), &[node0], 1, true);
        let peers: Vec<&String> = v
            .iter()
            .zip(v.iter().skip(1))
            .filter(|(k, _)| *k == "--peer")
            .map(|(_, p)| p)
            .collect();
        assert_eq!(peers, [&node0.to_string()]);
        assert!(v.contains(&"--connect-only".to_string()));
        let at = v.iter().position(|x| x == "--public-address").unwrap();
        assert_eq!(v[at + 1], local(p2p_port(a.base_port, 7)).to_string());
    }

    #[test]
    fn partitions_and_level_nodes_are_never_stuck() {
        let t0 = Instant::now();
        let mut d = StuckDetector::default();
        for s in 0..10 {
            assert!(!d.observe(at(t0, 30 * s), "a", 10, 20, false));
        }
        let mut level = StuckDetector::default();
        for s in 0..10 {
            assert!(!level.observe(at(t0, 30 * s), "a", 10, 10, true));
        }
    }
}
