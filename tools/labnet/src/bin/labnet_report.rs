//! `blacksilk-labnet-report`: network metrics of a finished labnet run, from
//! the run's own files (docs/testnet.md §8).
//!
//! Evidence tooling, not used by any node, miner or wallet. It reads a run
//! directory written by `blacksilk-labnet` and prints what `summary.json`
//! does not hold. Block times come from the lab nodes' logs: a node's
//! `accepted (tip` line is a block its miner submitted by RPC (the origin),
//! a `received` line a block body arriving by P2P (a `blacksilk_p2p::net`
//! debug line, so the run needs `RUST_LOG=...,blacksilk_p2p::net=debug`).
//! - **difficulty** of node 0's tip over the measured phase (`metrics.csv`);
//! - **propagation:** per block every lab node logged, the time from its
//!   first to its last sighting, when that whole interval lies in a
//!   connected phase (after the warm-up, before the end checks, outside
//!   every partition and its `HEAL_SECS` heal window, and no partition
//!   starting inside it). Reported twice: without the heights where the lab
//!   nodes saw two blocks (`propagation`: a node that took the rival first
//!   fetches the other body only when a child makes it heavier), and with
//!   them (`propagation_with_contested`);
//! - **arrivals:** per receiving node, for every block whose origin accepted
//!   it in a connected phase, contested or not, the time from the origin's
//!   accept to the receiver's first sighting, and how many such blocks the
//!   receiver never saw (a race loser's body is never fetched);
//! - **found blocks by phase:** every origin accept, split by the phase in
//!   which it was mined, into blocks on the final chain and stale ones. It
//!   needs the final chain: `final-chain.txt` (written by the labnet at the
//!   end of a run), or derived here from node 0's block store (`--store`);
//! - **side branches** (with `--store`): every branch of node 0's store off
//!   the final chain, with its cumulative work (the sum of its headers'
//!   difficulties, as consensus counts work) and the final chain's over the
//!   same heights;
//! - **heals:** per heal, the seconds until the first `metrics.csv` sample
//!   with one tip on every lab node (15 s resolution), and each
//!   reorganization logged within `HEAL_SECS`;
//! - **joiners:** the late joiner's (and the relay-discovery joiner's)
//!   connections and address messages over time, and the size of the first
//!   `GetAddr` answer the late joiner got.
//!
//! The lab nodes' clocks are one machine's clock, so times across logs
//! compare directly.

#![forbid(unsafe_code)]

#[path = "../build_guard.rs"]
mod build_guard;

use blacksilk_chain::block::Block;
use blacksilk_chain::store::{BlockStore, FileStore, Record, StoreIdentity};
use blacksilk_consensus::{ChainParams, Hash, Network};
use clap::Parser;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "blacksilk-labnet-report",
    about = "Network metrics of a finished labnet run"
)]
struct Args {
    /// The run directory (`blacksilk-labnet --out`).
    run: PathBuf,
    /// Also write the metrics as JSON to this file.
    #[arg(long)]
    json: Option<PathBuf>,
    /// Node 0's block store (`blocks.dat`, read from a copy): derives
    /// `final-chain.txt` in the run directory when the run has none, and
    /// reports the side branches.
    #[arg(long)]
    store: Option<PathBuf>,
}

/// The labnet's heal window (`HEAL_SECS` in `main.rs`).
const HEAL_SECS: f64 = 60.0;

/// The final chain file (`FINAL_CHAIN_FILE` in `main.rs`).
const FINAL_CHAIN_FILE: &str = "final-chain.txt";

/// The length of the block ids the P2P log prints.
const SHORT: usize = 12;

/// Seconds since the Unix epoch of a log line's `[YYYY-MM-DDTHH:MM:SS(.mmm)Z`
/// stamp (env_logger), or `None`.
fn stamp(line: &str) -> Option<f64> {
    let s = line.strip_prefix('[')?;
    let end = s.find('Z')?;
    let s = &s[..end];
    let (date, time) = s.split_once('T')?;
    let mut d = date.split('-').map(|x| x.parse::<i64>().ok());
    let (y, m, day) = (d.next()??, d.next()??, d.next()??);
    let (hms, frac) = match time.split_once('.') {
        Some((a, b)) => (a, format!("0.{b}").parse::<f64>().ok()?),
        None => (time, 0.0),
    };
    let mut t = hms.split(':').map(|x| x.parse::<i64>().ok());
    let (hh, mm, ss) = (t.next()??, t.next()??, t.next()??);
    let days = days_from_civil(y, m, day);
    Some((days * 86_400 + hh * 3600 + mm * 60 + ss) as f64 + frac)
}

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's
/// algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The `[unix]` stamp of a journal line.
fn journal_stamp(line: &str) -> Option<f64> {
    line.strip_prefix('[')?.split(']').next()?.parse().ok()
}

/// Phase times from `journal.log`.
#[derive(Default, Debug, PartialEq)]
struct Journal {
    warmup_end: Option<f64>,
    partitions: Vec<f64>,
    heals: Vec<f64>,
    traffic_end: Option<f64>,
}

fn parse_journal(text: &str) -> Journal {
    let mut j = Journal::default();
    for line in text.lines() {
        let Some(t) = journal_stamp(line) else {
            continue;
        };
        if line.contains("] warm-up done") || line.contains("] warm-up ended") {
            j.warmup_end = Some(t);
        } else if line.contains("] partition #") && line.contains(" started") {
            j.partitions.push(t);
        } else if line.contains("] partition healed") {
            j.heals.push(t);
        } else if line.contains("] traffic phase over") {
            j.traffic_end = Some(t);
        }
    }
    j
}

impl Journal {
    /// Whether the whole interval `from..=to` lies in the connected,
    /// measured part of the run: a block mined just before a partition and
    /// delivered at the heal is the partition's, not a slow relay.
    fn connected_span(&self, from: f64, to: f64) -> bool {
        self.connected(from)
            && self.connected(to)
            && !self.partitions.iter().any(|&p| p >= from && p <= to)
    }

    /// Whether `t` is in the connected, measured part of the run.
    fn connected(&self, t: f64) -> bool {
        self.phase(t) == "connected"
    }

    /// The labnet phase at `t` (as `main.rs` marks them): `warmup`,
    /// `connected`, `partition` (from its start to its heal; a partition
    /// still up at the end of the traffic phase lasts until then), `heal`
    /// (`HEAL_SECS` after a heal) or `final` (the end checks).
    fn phase(&self, t: f64) -> &'static str {
        if self.warmup_end.is_some_and(|w| t < w) {
            return "warmup";
        }
        if self.traffic_end.is_some_and(|e| t > e) {
            return "final";
        }
        for (k, &p) in self.partitions.iter().enumerate() {
            match self.heals.get(k) {
                Some(&h) if t >= p && t <= h => return "partition",
                Some(&h) if t > h && t <= h + HEAL_SECS => return "heal",
                None if t >= p => return "partition",
                _ => {}
            }
        }
        "connected"
    }
}

/// A block's short id (the 12 hex digits the P2P log prints), height and
/// whether the line is an origin (`accepted (tip`, an RPC submission) rather
/// than a P2P `received` line.
fn block_event(line: &str) -> Option<(String, u64, bool)> {
    let at = line.find("block ")?;
    let rest = &line[at + 6..];
    let id: String = rest.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    if id.len() < SHORT {
        return None;
    }
    let accepted = rest.contains(" accepted (tip");
    let received = rest.contains(" received");
    let height = rest
        .split(" at height ")
        .nth(1)?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    (accepted || received).then(|| (id[..SHORT].to_string(), height, accepted))
}

/// One node's block sighting.
#[derive(Clone, Debug, PartialEq)]
struct Sighting {
    id: String,
    height: u64,
    t: f64,
    origin: bool,
}

type Events = Vec<Vec<Sighting>>;

fn sightings(log: &str) -> Vec<Sighting> {
    log.lines()
        .filter_map(|l| {
            let (id, height, origin) = block_event(l)?;
            Some(Sighting {
                id,
                height,
                t: stamp(l)?,
                origin,
            })
        })
        .collect()
}

/// Median, p90 and maximum of `v` in milliseconds.
#[derive(Default, Serialize, Debug, PartialEq)]
struct Dist {
    n: usize,
    median_ms: Option<u64>,
    p90_ms: Option<u64>,
    max_ms: Option<u64>,
}

fn dist(mut v: Vec<f64>) -> Dist {
    v.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
    let q = |p: f64| -> Option<u64> {
        let i = ((v.len() as f64 * p) as usize).min(v.len().checked_sub(1)?);
        Some((v[i] * 1000.0).round() as u64)
    };
    Dist {
        n: v.len(),
        median_ms: q(0.5),
        p90_ms: q(0.9),
        max_ms: v.last().map(|s| (s * 1000.0).round() as u64),
    }
}

#[derive(Default, Serialize, Debug, PartialEq)]
struct Propagation {
    blocks: usize,
    /// Heights at which the lab nodes saw more than one block (a race).
    contested_heights: usize,
    median_ms: Option<u64>,
    p90_ms: Option<u64>,
    max_ms: Option<u64>,
}

/// The ids seen at heights where the lab nodes saw more than one block, and
/// the number of such heights.
fn contested(events: &Events) -> (BTreeSet<&str>, usize) {
    let mut ids_at: BTreeMap<u64, BTreeSet<&str>> = BTreeMap::new();
    for s in events.iter().flatten() {
        ids_at.entry(s.height).or_default().insert(&s.id);
    }
    let rivals = ids_at.values().filter(|s| s.len() > 1);
    let heights = rivals.clone().count();
    (rivals.flatten().copied().collect(), heights)
}

/// First-to-last sighting times of the blocks every lab node logged whose
/// delivery was `connected`; with `skip_contested`, not at heights with a
/// rival block.
fn propagation(
    events: &Events,
    connected: impl Fn(f64, f64) -> bool,
    skip_contested: bool,
) -> (Propagation, Vec<f64>) {
    let mut by: BTreeMap<&str, BTreeMap<usize, f64>> = BTreeMap::new();
    for (node, ev) in events.iter().enumerate() {
        for s in ev {
            by.entry(&s.id).or_default().entry(node).or_insert(s.t);
        }
    }
    let (rival_ids, contested_heights) = contested(events);
    let mut spreads: Vec<f64> = by
        .iter()
        .filter(|(id, m)| m.len() == events.len() && !(skip_contested && rival_ids.contains(*id)))
        .filter_map(|(_, m)| {
            let first = m.values().cloned().fold(f64::INFINITY, f64::min);
            let last = m.values().cloned().fold(f64::NEG_INFINITY, f64::max);
            connected(first, last).then_some(last - first)
        })
        .collect();
    spreads.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
    let d = dist(spreads.clone());
    let p = Propagation {
        blocks: d.n,
        contested_heights,
        median_ms: d.median_ms,
        p90_ms: d.p90_ms,
        max_ms: d.max_ms,
    };
    (p, spreads)
}

/// Per receiving node: arrival times after the origin's accept.
#[derive(Default, Serialize, Debug, PartialEq)]
struct Receiver {
    node: usize,
    /// Blocks with an origin elsewhere, accepted there in a connected phase.
    blocks: usize,
    /// Of those, the ones this node never logged.
    never_seen: usize,
    arrival: Dist,
}

#[derive(Default, Serialize, Debug, PartialEq)]
struct Arrivals {
    /// Blocks with exactly one origin, accepted in a connected phase.
    blocks: usize,
    /// Of those, the ones at least one lab node never logged.
    not_seen_by_every_node: usize,
    /// Every receiver's arrival times together.
    all: Dist,
    receivers: Vec<Receiver>,
}

/// Arrival of every block whose origin accepted it while `connected`, at
/// every other lab node, contested blocks included.
fn arrivals(events: &Events, connected: impl Fn(f64) -> bool) -> Arrivals {
    let n = events.len();
    let mut seen: BTreeMap<&str, BTreeMap<usize, f64>> = BTreeMap::new();
    let mut origins: BTreeMap<&str, Vec<(usize, f64)>> = BTreeMap::new();
    for (node, ev) in events.iter().enumerate() {
        for s in ev {
            seen.entry(&s.id).or_default().entry(node).or_insert(s.t);
            if s.origin {
                origins.entry(&s.id).or_default().push((node, s.t));
            }
        }
    }
    let mut per: Vec<(usize, Vec<f64>)> = vec![(0, Vec::new()); n];
    let (mut blocks, mut partial, mut all) = (0, 0, Vec::new());
    for (id, o) in &origins {
        let [(origin, t0)] = o.as_slice() else {
            continue;
        };
        if !connected(*t0) {
            continue;
        }
        blocks += 1;
        let m = &seen[id];
        if m.len() < n {
            partial += 1;
        }
        for (node, (count, v)) in per.iter_mut().enumerate() {
            if node == *origin {
                continue;
            }
            *count += 1;
            if let Some(t) = m.get(&node) {
                v.push(t - t0);
                all.push(t - t0);
            }
        }
    }
    Arrivals {
        blocks,
        not_seen_by_every_node: partial,
        all: dist(all),
        receivers: per
            .into_iter()
            .enumerate()
            .map(|(node, (count, v))| Receiver {
                node,
                blocks: count,
                never_seen: count - v.len(),
                arrival: dist(v),
            })
            .collect(),
    }
}

/// Found (origin-accepted) blocks of one phase.
#[derive(Default, Serialize, Debug, PartialEq)]
struct Found {
    found: usize,
    on_final_chain: usize,
    stale: usize,
}

/// Every origin accept by the phase in which it happened, against the final
/// chain's short ids.
fn found_by_phase(
    events: &Events,
    journal: &Journal,
    final_chain: &BTreeSet<String>,
) -> BTreeMap<&'static str, Found> {
    let mut out: BTreeMap<&'static str, Found> = BTreeMap::new();
    let mut counted = BTreeSet::new();
    for s in events.iter().flatten().filter(|s| s.origin) {
        if !counted.insert(&s.id) {
            continue;
        }
        let f = out.entry(journal.phase(s.t)).or_default();
        f.found += 1;
        if final_chain.contains(&s.id) {
            f.on_final_chain += 1;
        } else {
            f.stale += 1;
        }
    }
    out
}

/// A stored block: height, parent, difficulty.
type StoredHeader = (u64, Hash, u64);

/// The chain ending at `tip` in `blocks`, from its lowest stored block up.
fn chain_to(blocks: &BTreeMap<Hash, StoredHeader>, tip: Hash) -> Vec<(u64, Hash)> {
    let mut out = Vec::new();
    let mut x = tip;
    while let Some(&(h, prev, _)) = blocks.get(&x) {
        out.push((h, x));
        x = prev;
    }
    out.reverse();
    out
}

/// Cumulative work (the sum of difficulties from the lowest stored block)
/// of every block of `blocks`.
fn cumulative_work(blocks: &BTreeMap<Hash, StoredHeader>) -> BTreeMap<Hash, u128> {
    let mut by_height: Vec<(&Hash, &StoredHeader)> = blocks.iter().collect();
    by_height.sort_by_key(|(_, (h, _, _))| *h);
    let mut work: BTreeMap<Hash, u128> = BTreeMap::new();
    for (id, (_, prev, d)) in by_height {
        let parent = work.get(prev).copied().unwrap_or(0);
        work.insert(*id, parent + u128::from(*d));
    }
    work
}

/// The block with the most cumulative work (ties: the lowest id, which
/// never happened in the lab runs; the report's height check catches it).
fn most_work(blocks: &BTreeMap<Hash, StoredHeader>) -> Option<Hash> {
    cumulative_work(blocks)
        .into_iter()
        .max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0)))
        .map(|(id, _)| id)
}

/// A branch of the store off the final chain.
#[derive(Serialize, Debug, PartialEq)]
struct SideBranch {
    /// The height of the last block it shares with the final chain.
    fork_height: u64,
    tip_height: u64,
    tip: String,
    /// `(height, cumulative work above the fork)` of the branch and of the
    /// final chain at the same heights.
    work: Vec<(u64, u128)>,
    final_chain_work: Vec<(u64, u128)>,
}

/// Every branch of `blocks` off `main` (the final chain's ids), one per
/// branch tip (a side block no stored side block extends).
fn side_branches(blocks: &BTreeMap<Hash, StoredHeader>, main: &[(u64, Hash)]) -> Vec<SideBranch> {
    let on_main: BTreeSet<Hash> = main.iter().map(|(_, id)| *id).collect();
    let main_at: BTreeMap<u64, Hash> = main.iter().copied().collect();
    let parents: BTreeSet<Hash> = blocks
        .iter()
        .filter(|(id, _)| !on_main.contains(*id))
        .map(|(_, (_, prev, _))| *prev)
        .collect();
    let mut out = Vec::new();
    for (tip, _) in blocks
        .iter()
        .filter(|(id, _)| !on_main.contains(*id) && !parents.contains(*id))
    {
        let side: Vec<(u64, Hash)> = chain_to(blocks, *tip)
            .into_iter()
            .filter(|(_, id)| !on_main.contains(id))
            .collect();
        let Some(&(first, _)) = side.first() else {
            continue;
        };
        let mut work = Vec::new();
        let mut w = 0u128;
        for (h, id) in &side {
            w += u128::from(blocks[id].2);
            work.push((*h, w));
        }
        let mut final_chain_work = Vec::new();
        let mut w = 0u128;
        for (h, _) in &side {
            let Some(id) = main_at.get(h) else { break };
            w += u128::from(blocks[id].2);
            final_chain_work.push((*h, w));
        }
        out.push(SideBranch {
            fork_height: first - 1,
            tip_height: side.last().expect("non-empty").0,
            tip: hex::encode(tip),
            work,
            final_chain_work,
        });
    }
    out.sort_by_key(|b| (b.fork_height, b.tip_height));
    out
}

/// The blocks of a store (read from a copy: `FileStore` opens for writing).
fn load_store(path: &Path, params: &ChainParams) -> Result<BTreeMap<Hash, StoredHeader>, String> {
    let copy =
        std::env::temp_dir().join(format!("labnet-report-{}-blocks.dat", std::process::id()));
    std::fs::copy(path, &copy).map_err(|e| format!("{}: {e}", path.display()))?;
    let result = (|| {
        let mut s = FileStore::open(&copy).map_err(|e| e.to_string())?;
        s.bind(&StoreIdentity::of(params))
            .map_err(|e| e.to_string())?;
        let mut out = BTreeMap::new();
        for r in s.load().map_err(|e| e.to_string())? {
            if let Record::Block((_, bytes)) = r {
                let b = Block::decode(&bytes).map_err(|e| format!("{e:?}"))?;
                let h = b.header;
                out.insert(h.id(params.network_id), (h.height, h.prev_id, h.difficulty));
            }
        }
        Ok(out)
    })();
    let _ = std::fs::remove_file(&copy);
    result
}

/// The `height id` lines of a final chain file, as short ids.
fn parse_final_chain(text: &str) -> BTreeSet<String> {
    text.lines()
        .filter_map(|l| l.split_whitespace().nth(1))
        .filter(|id| id.len() >= SHORT)
        .map(|id| id[..SHORT].to_string())
        .collect()
}

#[derive(Serialize, Debug, PartialEq)]
struct Heal {
    unix: u64,
    /// Seconds to the first sample with one tip everywhere (`None`: none).
    converged_after_secs: Option<u64>,
    /// `(node, depth, seconds after the heal)` of each reorganization.
    reorgs: Vec<(usize, u64, f64)>,
    /// Node heights at the last sample before the heal.
    heights_before: String,
}

/// The first sample at or after `heal` whose tips are all equal.
fn converged_after(rows: &[(u64, String, String)], heal: f64) -> Option<u64> {
    rows.iter()
        .filter(|(t, _, _)| *t as f64 >= heal)
        .find(|(_, _, tips)| {
            let v: Vec<&str> = tips.split('/').collect();
            !v.contains(&"-") && v.windows(2).all(|w| w[0] == w[1])
        })
        .map(|(t, _, _)| (*t as f64 - heal).round() as u64)
}

/// A joiner's connections and address messages, in seconds after its first
/// log line, and the largest address message it got from its first peer
/// (the `GetAddr` answer; the self-advertisement has one entry).
fn joiner_timeline(log: &str) -> (Vec<String>, Option<usize>) {
    let t0 = log.lines().find_map(stamp);
    let mut out = Vec::new();
    let mut answer = None;
    let mut peers = 0i64;
    for l in log.lines() {
        let (Some(t), Some(t0)) = (stamp(l), t0) else {
            continue;
        };
        let msg = l.split_once("] ").map_or(l, |(_, m)| m);
        let event = if msg.starts_with("connected ") && msg.contains(" peer ") {
            peers += 1;
            Some(format!("{msg} -> {peers} peers"))
        } else if msg.starts_with("disconnected peer") {
            peers -= 1;
            Some(format!("{msg} -> {peers} peers"))
        } else {
            if let Some(k) = msg
                .strip_prefix("peer 1: addr with ")
                .and_then(|r| r.split_whitespace().next()?.parse::<usize>().ok())
            {
                answer = Some(answer.unwrap_or(0).max(k));
            }
            (msg.contains(": addr with ") || msg.contains("getaddr answered")).then(|| msg.into())
        };
        if let Some(e) = event {
            out.push(format!("{:8.2} s  {e}", t - t0));
        }
    }
    (out, answer)
}

#[derive(Serialize)]
struct Report {
    /// This binary's `build flags:` line (always `none`: a build with
    /// test-only code refuses to run, W4-GUARD).
    build_flags: String,
    nodes: usize,
    difficulty_min: Option<u64>,
    difficulty_max: Option<u64>,
    /// Mean tip difficulty of the first and last third of the measured samples.
    difficulty_first_third: Option<f64>,
    difficulty_last_third: Option<f64>,
    propagation: Propagation,
    propagation_with_contested: Propagation,
    arrivals: Arrivals,
    /// Found blocks after the warm-up minus the final chain's blocks above
    /// the warm-up height (a count, without block ids).
    found_after_warmup: u64,
    on_final_chain_after_warmup: u64,
    stale_after_warmup: i64,
    /// By phase and block id (needs the final chain; `None` without it).
    found_by_phase: Option<BTreeMap<&'static str, Found>>,
    /// Blocks the nodes refused at the RPC (`block refused at the RPC`).
    refused_at_rpc: usize,
    templates_abandoned_after_warmup: u64,
    heals: Vec<Heal>,
    /// With `--store`: node 0's branches off the final chain.
    side_branches: Option<Vec<SideBranch>>,
    /// The largest address message the late joiner got from its first peer.
    late_joiner_getaddr_answer: Option<usize>,
    late_joiner: Vec<String>,
    /// The relay-discovery joiner (`--relay-joiners`), if the run had one.
    relay_joiner: Option<Vec<String>>,
}

fn read(p: &Path) -> String {
    std::fs::read(p)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default()
}

fn mean(v: &[u64]) -> Option<f64> {
    (!v.is_empty()).then(|| v.iter().sum::<u64>() as f64 / v.len() as f64)
}

fn main() {
    let a: Args = build_guard::parse_args();
    let build_flags = build_guard::require_clean_build("blacksilk-labnet-report");
    let summary: serde_json::Value = serde_json::from_str(&read(&a.run.join("summary.json")))
        .expect("summary.json (a finished run)");
    let n = summary["nodes"].as_u64().expect("nodes") as usize;
    let net = match summary["network"].as_str() {
        Some("testnet") => Network::Testnet,
        _ => Network::Regtest,
    };
    let params = ChainParams::for_network(net);
    let journal = parse_journal(&read(&a.run.join("journal.log")));

    // metrics.csv: unix, heights, tips, difficulties, phase.
    let metrics = read(&a.run.join("metrics.csv"));
    let mut lines = metrics.lines();
    let header: Vec<&str> = lines.next().unwrap_or("").split(',').collect();
    let col = |name: &str| header.iter().position(|h| *h == name).expect(name);
    let (cu, ch, ct, cd, cp) = (
        col("unix"),
        col("heights"),
        col("tips"),
        col("difficulties"),
        col("phase"),
    );
    let mut rows = Vec::new();
    let mut diffs = Vec::new();
    for l in lines {
        let f: Vec<&str> = l.split(',').collect();
        let Ok(t) = f[cu].parse::<u64>() else {
            continue;
        };
        rows.push((t, f[ch].to_string(), f[ct].to_string()));
        if f[cp] != "warmup" {
            if let Ok(d) = f[cd].split('/').next().unwrap_or("-").parse::<u64>() {
                diffs.push(d);
            }
        }
    }
    let third = (diffs.len() / 3).max(1).min(diffs.len());

    let events: Events = (0..n)
        .map(|i| sightings(&read(&a.run.join(format!("node{i}.log")))))
        .collect();
    let (prop, _) = propagation(&events, |f, l| journal.connected_span(f, l), true);
    let (prop_all, _) = propagation(&events, |f, l| journal.connected_span(f, l), false);
    let arr = arrivals(&events, |t| journal.connected(t));

    // The final chain: the run's file, or derived from node 0's store.
    let store = a
        .store
        .as_ref()
        .map(|p| load_store(p, &params).expect("the store"));
    let final_file = a.run.join(FINAL_CHAIN_FILE);
    let mut main_chain = None;
    if let Some(blocks) = &store {
        // The final tip: the stored block with the most work, as fork
        // choice picks it. The last metrics sample is not it: a partition
        // can be up at the end of the traffic phase (run4).
        let tip = most_work(blocks).expect("an empty store");
        let final_height = summary["final_height"].as_u64().unwrap_or(0);
        assert_eq!(
            blocks[&tip].0, final_height,
            "the store's most-work block is not at the run's final height"
        );
        let chain = chain_to(blocks, tip);
        if !final_file.exists() {
            let mut text = format!("0 {}\n", hex::encode(params.genesis_id()));
            for (h, id) in &chain {
                text.push_str(&format!("{h} {}\n", hex::encode(id)));
            }
            std::fs::write(&final_file, text).expect("write final-chain.txt");
        }
        main_chain = Some(chain);
    }
    let final_chain = final_file
        .exists()
        .then(|| parse_final_chain(&read(&final_file)));
    let found_by = final_chain
        .as_ref()
        .map(|c| found_by_phase(&events, &journal, c));
    let side = store
        .as_ref()
        .zip(main_chain.as_ref())
        .map(|(b, m)| side_branches(b, m));

    // Stale blocks after the warm-up, by count.
    let mut found = 0u64;
    for k in 0..2 {
        for l in read(&a.run.join(format!("miner{k}.log"))).lines() {
            if l.contains("found block ") {
                if let Some(t) = stamp(l) {
                    found += u64::from(journal.warmup_end.is_none_or(|w| t >= w));
                }
            }
        }
    }
    let final_height = summary["final_height"].as_u64().unwrap_or(0);
    let warm_height = summary["warmup"]["end_height"].as_u64().unwrap_or(0);
    let on_chain = final_height.saturating_sub(warm_height);
    let abandoned = summary["blocks_found_by_phase"]
        .as_object()
        .map(|m| {
            m.iter()
                .filter(|(k, _)| k.as_str() != "warmup")
                .map(|(_, v)| v["abandoned"].as_u64().unwrap_or(0))
                .sum()
        })
        .unwrap_or(0);
    let refused_at_rpc = (0..n)
        .map(|i| {
            read(&a.run.join(format!("node{i}.log")))
                .lines()
                .filter(|l| l.contains("block refused at the RPC"))
                .count()
        })
        .sum();

    // Heals.
    let heals = journal
        .heals
        .iter()
        .map(|&h| {
            let mut reorgs = Vec::new();
            for i in 0..n {
                for l in read(&a.run.join(format!("node{i}.log"))).lines() {
                    let Some(rest) = l.split("reorganization: disconnecting ").nth(1) else {
                        continue;
                    };
                    let (Some(t), Some(depth)) = (
                        stamp(l),
                        rest.split_whitespace().next().and_then(|d| d.parse().ok()),
                    ) else {
                        continue;
                    };
                    if t >= h && t <= h + HEAL_SECS {
                        reorgs.push((i, depth, ((t - h) * 10.0).round() / 10.0));
                    }
                }
            }
            let heights_before = rows
                .iter()
                .rfind(|(t, _, _)| (*t as f64) < h)
                .map_or(String::new(), |(_, hs, _)| hs.clone());
            Heal {
                unix: h as u64,
                converged_after_secs: converged_after(&rows, h),
                reorgs,
                heights_before,
            }
        })
        .collect();

    let (late_joiner, answer) = joiner_timeline(&read(&a.run.join("node-late.log")));
    let e2 = a.run.join("node-e2.log");
    let relay_joiner = e2.exists().then(|| joiner_timeline(&read(&e2)).0);

    let r = Report {
        build_flags,
        nodes: n,
        difficulty_min: diffs.iter().copied().min(),
        difficulty_max: diffs.iter().copied().max(),
        difficulty_first_third: mean(&diffs[..third]),
        difficulty_last_third: mean(&diffs[diffs.len() - third..]),
        propagation: prop,
        propagation_with_contested: prop_all,
        arrivals: arr,
        found_after_warmup: found,
        on_final_chain_after_warmup: on_chain,
        stale_after_warmup: found as i64 - on_chain as i64,
        found_by_phase: found_by,
        refused_at_rpc,
        templates_abandoned_after_warmup: abandoned,
        heals,
        side_branches: side,
        late_joiner_getaddr_answer: answer,
        late_joiner,
        relay_joiner,
    };
    let json = serde_json::to_string_pretty(&r).expect("json");
    if let Some(p) = &a.json {
        std::fs::write(p, &json).expect("write --json");
    }
    println!("{json}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_stamps_parse_to_unix_seconds() {
        // 2026-09-29T21:15:10.026Z = 1790716510.026 (date -u -d ... +%s).
        let t = stamp("[2026-09-29T21:15:10.026Z INFO  blacksilk_node] x").unwrap();
        assert!((t - 1_790_716_510.026).abs() < 1e-6, "{t}");
        assert_eq!(stamp("[1970-01-01T00:00:00Z INFO x] y"), Some(0.0));
        assert_eq!(stamp("[2000-03-01T00:00:00Z x"), Some(951_868_800.0));
        assert_eq!(stamp("no stamp"), None);
    }

    #[test]
    fn block_lines_of_both_kinds_give_the_short_id() {
        let acc =
            "[t INFO  blacksilk_node] block 16f9f692c812a7f0 at height 250 accepted (tip 250)";
        let rec = "[t DEBUG blacksilk_p2p::net::blocks] peer 1: block 16f9f692c812 at height 250 received";
        assert_eq!(block_event(acc), Some(("16f9f692c812".into(), 250, true)));
        assert_eq!(block_event(rec), Some(("16f9f692c812".into(), 250, false)));
        assert_eq!(
            block_event("[t] peer 1: 1 headers up to height 250 accepted"),
            None
        );
    }

    fn ev(v: &[(&str, u64, f64, bool)]) -> Vec<Sighting> {
        v.iter()
            .map(|(id, height, t, origin)| Sighting {
                id: id.to_string(),
                height: *height,
                t: *t,
                origin: *origin,
            })
            .collect()
    }

    /// Three nodes. a, b: every node. c: node 1 never saw it. d: every
    /// node, but e is a rival at its height, and node 1 never saw e.
    fn three_nodes() -> Events {
        vec![
            ev(&[
                ("aaaaaaaaaaaa", 1, 100.0, true),
                ("bbbbbbbbbbbb", 2, 200.0, true),
                ("cccccccccccc", 3, 300.0, true),
                ("dddddddddddd", 4, 400.0, true),
            ]),
            ev(&[
                ("aaaaaaaaaaaa", 1, 100.9, false),
                ("bbbbbbbbbbbb", 2, 201.0, false),
                ("dddddddddddd", 4, 402.0, false),
            ]),
            ev(&[
                ("aaaaaaaaaaaa", 1, 101.5, false),
                ("bbbbbbbbbbbb", 2, 200.5, false),
                ("cccccccccccc", 3, 300.1, false),
                ("dddddddddddd", 4, 400.1, false),
                ("eeeeeeeeeeee", 4, 399.0, true),
            ]),
        ]
    }

    #[test]
    fn propagation_with_and_without_contested_heights() {
        let events = three_nodes();
        let (p, s) = propagation(&events, |_, _| true, true);
        assert_eq!(s, vec![1.0, 1.5], "c: not on every node; d: contested");
        assert_eq!((p.blocks, p.contested_heights), (2, 1));
        assert_eq!(p.max_ms, Some(1500));
        let (p, s) = propagation(&events, |_, _| true, false);
        assert_eq!(s, vec![1.0, 1.5, 2.0], "d counts");
        assert_eq!(p.max_ms, Some(2000));
        let (p, _) = propagation(&events, |f, l| f < 150.0 && l < 150.0, true);
        assert_eq!((p.blocks, p.median_ms), (1, Some(1500)));
    }

    #[test]
    fn arrivals_count_every_block_and_the_ones_never_seen() {
        let events = three_nodes();
        let a = arrivals(&events, |_| true);
        assert_eq!(a.blocks, 5);
        // c (node 1), e (node 1; its origin is node 2, and node 0 never saw it).
        assert_eq!(a.not_seen_by_every_node, 2);
        let r0 = &a.receivers[0];
        assert_eq!((r0.blocks, r0.never_seen), (1, 1), "e only");
        let r1 = &a.receivers[1];
        assert_eq!((r1.blocks, r1.never_seen), (5, 2));
        assert_eq!(r1.arrival.max_ms, Some(2000), "d, contested, counts");
        let r2 = &a.receivers[2];
        assert_eq!((r2.blocks, r2.never_seen), (4, 0));
        assert_eq!(a.all.n, 3 + 4);
        let a = arrivals(&events, |t| t < 350.0);
        assert_eq!(a.blocks, 3, "origin in a connected phase only");
    }

    #[test]
    fn partitions_and_their_heal_windows_are_not_connected() {
        let j = parse_journal(
            "[100] warm-up done after 1 s\n[500] partition #1 started (x)\n\
             [680] partition healed\n[900] partition #2 started (x)\n\
             [2000] traffic phase over; final checks\n",
        );
        assert_eq!(j.partitions, vec![500.0, 900.0]);
        assert!(!j.connected(99.0), "warm-up");
        assert!(j.connected(499.0));
        assert!(
            !j.connected(600.0) && !j.connected(740.0),
            "partition, heal"
        );
        assert!(j.connected(741.0));
        assert!(!j.connected(2001.0), "end checks");
        // Mined 2 s before the cut, delivered at the heal (run1, block 272).
        assert!(!j.connected_span(498.0, 690.0));
        assert!(j.connected_span(400.0, 401.0));
        let phases: Vec<&str> = [50.0, 300.0, 600.0, 700.0, 800.0, 1500.0, 2500.0]
            .iter()
            .map(|&t| j.phase(t))
            .collect();
        assert_eq!(
            phases,
            [
                "warmup",
                "connected",
                "partition",
                "heal",
                "connected",
                "partition",
                "final"
            ],
            "partition #2 never healed before the end (run4)"
        );
    }

    #[test]
    fn found_blocks_split_by_phase_against_the_final_chain() {
        let j = parse_journal(
            "[150] warm-up done\n[250] partition #1 started\n[500] partition healed\n",
        );
        let events = three_nodes();
        let chain = parse_final_chain("0 genesis00000000\n1 aaaaaaaaaaaa1234\n2 bbbbbbbbbbbb\n3 cccccccccccc\n4 eeeeeeeeeeee99\n");
        let f = found_by_phase(&events, &j, &chain);
        assert_eq!(
            f["warmup"],
            Found {
                found: 1,
                on_final_chain: 1,
                stale: 0
            }
        );
        assert_eq!(f["connected"].found, 1, "b");
        assert_eq!(
            f["partition"],
            Found {
                found: 3,
                on_final_chain: 2,
                stale: 1
            },
            "c, d, e: d lost to e"
        );
    }

    fn id(b: u8) -> Hash {
        [b; 32]
    }

    /// Run4's heal 3 in miniature: a main chain 1..=3 and a two-block side
    /// branch off height 1; work is the sum of difficulties.
    #[test]
    fn side_branches_carry_their_work_against_the_final_chain() {
        let mut s: BTreeMap<Hash, StoredHeader> = BTreeMap::new();
        s.insert(id(1), (1, id(0), 10));
        s.insert(id(2), (2, id(1), 11));
        s.insert(id(3), (3, id(2), 12));
        s.insert(id(0xa2), (2, id(1), 9));
        s.insert(id(0xa3), (3, id(0xa2), 9));
        s.insert(id(0xb3), (3, id(2), 12));
        // id(3) and id(0xb3) both carry 10 + 11 + 12 = 33 (more than the
        // side branch's 28): the tie goes to the lower id.
        assert_eq!(most_work(&s), Some(id(3)));
        let main = chain_to(&s, id(3));
        assert_eq!(main, vec![(1, id(1)), (2, id(2)), (3, id(3))]);
        let b = side_branches(&s, &main);
        assert_eq!(b.len(), 2);
        assert_eq!(
            (b[0].fork_height, b[0].tip_height, &b[0].work),
            (1, 3, &vec![(2, 9), (3, 18)])
        );
        assert_eq!(b[0].final_chain_work, vec![(2, 11), (3, 23)]);
        assert_eq!((b[1].fork_height, &b[1].work), (2, &vec![(3, 12)]));
    }

    #[test]
    fn a_heal_converges_at_the_first_sample_with_one_tip() {
        let rows = vec![
            (100, "5/5/4".to_string(), "a/a/b".to_string()),
            (115, "6/6/6".to_string(), "c/c/-".to_string()),
            (130, "6/6/6".to_string(), "c/c/c".to_string()),
        ];
        assert_eq!(converged_after(&rows, 101.0), Some(29));
        assert_eq!(converged_after(&rows, 131.0), None);
    }

    #[test]
    fn the_joiner_timeline_and_its_getaddr_answer() {
        let log = "[2026-09-29T21:28:02.421Z INFO  blacksilk_node] start\n\
                   [2026-09-29T21:28:02.689Z INFO  blacksilk_p2p::net::conn] connected outbound peer 127.0.0.1:51001 (height 327)\n\
                   [2026-09-29T21:28:02.689Z DEBUG blacksilk_p2p::net::addr_relay] peer 1: addr with 1 entries\n\
                   [2026-09-29T21:28:02.689Z DEBUG blacksilk_p2p::net::addr_relay] peer 1: addr with 5 entries\n\
                   [2026-09-29T21:28:04.877Z DEBUG blacksilk_p2p::net::addr_relay] peer 3: addr with 9 entries\n\
                   [2026-09-29T21:28:05.000Z INFO  blacksilk_p2p::net::conn] disconnected peer 127.0.0.1:51001\n";
        let (t, answer) = joiner_timeline(log);
        assert_eq!(answer, Some(5), "peer 1's answer, not peer 3's");
        assert_eq!(t.len(), 5);
        assert!(t[0].starts_with("    0.27 s  connected outbound") && t[0].ends_with("-> 1 peers"));
        assert!(t[4].ends_with("-> 0 peers"));
    }
}
