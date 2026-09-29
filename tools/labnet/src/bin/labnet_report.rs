//! `blacksilk-labnet-report`: network metrics of a finished labnet run, from
//! the run's own files (docs/testnet.md §8).
//!
//! Evidence tooling, not used by any node, miner or wallet. It reads a run
//! directory written by `blacksilk-labnet` and prints what `summary.json`
//! does not hold:
//! - **difficulty** of node 0's tip over the measured phase (`metrics.csv`);
//! - **propagation:** per block, the time from its origin node's `accepted`
//!   line (the miner's RPC submission) to the last lab node's `received`
//!   line (the body arriving by P2P, a `blacksilk_p2p::net` debug line, so
//!   the run needs `RUST_LOG=...,blacksilk_p2p::net=debug`). Only blocks
//!   every lab node logged, first seen in a connected phase: after the
//!   warm-up, before the end checks, outside every partition and its
//!   `HEAL_SECS` heal window;
//! - **stale blocks:** blocks the miners found after the warm-up minus the
//!   blocks of the final chain above the warm-up height (only the two lab
//!   miners mine, so every other found block left the best chain);
//! - **heals:** per heal, the seconds until the first `metrics.csv` sample
//!   with one tip on every lab node (15 s resolution), and each
//!   reorganization logged within `HEAL_SECS`;
//! - **late joiner:** its connections and address messages over time
//!   (`node-late.log`).
//!
//! The lab nodes' clocks are one machine's clock, so times across logs
//! compare directly.

#![forbid(unsafe_code)]

use clap::Parser;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(about = "Network metrics of a finished labnet run")]
struct Args {
    /// The run directory (`blacksilk-labnet --out`).
    run: PathBuf,
    /// Also write the metrics as JSON to this file.
    #[arg(long)]
    json: Option<PathBuf>,
}

/// The labnet's heal window (`HEAL_SECS` in `main.rs`).
const HEAL_SECS: f64 = 60.0;

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
        if self.warmup_end.is_some_and(|w| t < w) || self.traffic_end.is_some_and(|e| t > e) {
            return false;
        }
        !self
            .partitions
            .iter()
            .enumerate()
            .any(|(k, &p)| t >= p && self.heals.get(k).is_none_or(|&h| t <= h + HEAL_SECS))
    }
}

/// A block's short id (the 12 hex digits the P2P log prints) and height in
/// a node's `accepted` (RPC) or `received` (P2P) line.
fn block_event(line: &str) -> Option<(String, u64, bool)> {
    let at = line.find("block ")?;
    let rest = &line[at + 6..];
    let id: String = rest.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    if id.len() < 12 {
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
    (accepted || received).then(|| (id[..12].to_string(), height, accepted))
}

#[derive(Default, Serialize, Debug, PartialEq)]
struct Propagation {
    blocks: usize,
    /// Heights at which the lab nodes saw more than one block (a race):
    /// left out, since a node that took the rival first fetches the other
    /// body only once a child makes it the heavier branch.
    contested_heights: usize,
    median_ms: Option<u64>,
    p90_ms: Option<u64>,
    max_ms: Option<u64>,
}

/// Origin-to-last-node times of the blocks every one of `nodes` logged, at
/// heights where no rival block was seen, whose delivery (first to last
/// sighting) was `connected`. `events[node]` lists `(id, height, t)` in log
/// order.
fn propagation(
    events: &[Vec<(String, u64, f64)>],
    connected: impl Fn(f64, f64) -> bool,
) -> (Propagation, Vec<f64>) {
    let mut by: BTreeMap<&str, BTreeMap<usize, f64>> = BTreeMap::new();
    let mut ids_at: BTreeMap<u64, BTreeSet<&str>> = BTreeMap::new();
    for (node, ev) in events.iter().enumerate() {
        for (id, h, t) in ev {
            by.entry(id).or_default().entry(node).or_insert(*t);
            ids_at.entry(*h).or_default().insert(id);
        }
    }
    let rivals = ids_at.values().filter(|s| s.len() > 1);
    let contested_heights = rivals.clone().count();
    let contested: BTreeSet<&str> = rivals.flatten().copied().collect();
    let mut spreads: Vec<f64> = by
        .iter()
        .filter(|(id, m)| m.len() == events.len() && !contested.contains(*id))
        .map(|(_, m)| m)
        .filter_map(|m| {
            let first = m.values().cloned().fold(f64::INFINITY, f64::min);
            let last = m.values().cloned().fold(f64::NEG_INFINITY, f64::max);
            connected(first, last).then_some(last - first)
        })
        .collect();
    spreads.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
    let q = |p: f64| -> Option<u64> {
        let i = ((spreads.len() as f64 * p) as usize).min(spreads.len().checked_sub(1)?);
        Some((spreads[i] * 1000.0).round() as u64)
    };
    let p = Propagation {
        blocks: spreads.len(),
        contested_heights,
        median_ms: q(0.5),
        p90_ms: q(0.9),
        max_ms: spreads.last().map(|s| (s * 1000.0).round() as u64),
    };
    (p, spreads)
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

#[derive(Serialize)]
struct Report {
    run: String,
    nodes: usize,
    difficulty_min: Option<u64>,
    difficulty_max: Option<u64>,
    /// Mean tip difficulty of the first and last third of the measured samples.
    difficulty_first_third: Option<f64>,
    difficulty_last_third: Option<f64>,
    propagation: Propagation,
    found_after_warmup: u64,
    on_final_chain_after_warmup: u64,
    stale_after_warmup: i64,
    templates_abandoned_after_warmup: u64,
    heals: Vec<Heal>,
    late_joiner: Vec<String>,
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
    let a = Args::parse();
    let summary: serde_json::Value = serde_json::from_str(&read(&a.run.join("summary.json")))
        .expect("summary.json (a finished run)");
    let n = summary["nodes"].as_u64().expect("nodes") as usize;
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

    // Block events per lab node.
    let events: Vec<Vec<(String, u64, f64)>> = (0..n)
        .map(|i| {
            read(&a.run.join(format!("node{i}.log")))
                .lines()
                .filter_map(|l| {
                    let (id, h, _) = block_event(l)?;
                    Some((id, h, stamp(l)?))
                })
                .collect()
        })
        .collect();
    let (prop, _) = propagation(&events, |f, l| journal.connected_span(f, l));

    // Stale blocks after the warm-up.
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

    // Late joiner.
    let late = read(&a.run.join("node-late.log"));
    let t0 = late.lines().find_map(stamp);
    let mut late_joiner = Vec::new();
    let mut peers = 0i64;
    for l in late.lines() {
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
            (msg.contains(": addr with ") || msg.contains("getaddr answered")).then(|| msg.into())
        };
        if let Some(e) = event {
            late_joiner.push(format!("{:8.2} s  {e}", t - t0));
        }
    }

    let r = Report {
        run: a.run.display().to_string(),
        nodes: n,
        difficulty_min: diffs.iter().copied().min(),
        difficulty_max: diffs.iter().copied().max(),
        difficulty_first_third: mean(&diffs[..third]),
        difficulty_last_third: mean(&diffs[diffs.len() - third..]),
        propagation: prop,
        found_after_warmup: found,
        on_final_chain_after_warmup: on_chain,
        stale_after_warmup: found as i64 - on_chain as i64,
        templates_abandoned_after_warmup: abandoned,
        heals,
        late_joiner,
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

    #[test]
    fn only_blocks_every_node_saw_in_a_connected_phase_count() {
        let ev =
            |v: &[(&str, u64, f64)]| v.iter().map(|(i, h, t)| (i.to_string(), *h, *t)).collect();
        let events = vec![
            ev(&[
                ("aaaaaaaaaaaa", 1, 100.0),
                ("bbbbbbbbbbbb", 2, 200.0),
                ("cccccccccccc", 3, 300.0),
            ]),
            ev(&[
                ("aaaaaaaaaaaa", 1, 100.9),
                ("bbbbbbbbbbbb", 2, 201.0),
                ("dddddddddddd", 4, 400.0),
            ]),
            ev(&[
                ("aaaaaaaaaaaa", 1, 101.5),
                ("bbbbbbbbbbbb", 2, 200.5),
                ("cccccccccccc", 3, 300.1),
                ("dddddddddddd", 4, 400.1),
                ("eeeeeeeeeeee", 4, 399.0),
            ]),
        ];
        let (p, s) = propagation(&events, |_, _| true);
        // c: not on every node; d: every node, but a rival (e) at its height.
        assert_eq!(s, vec![1.0, 1.5]);
        assert_eq!((p.blocks, p.contested_heights), (2, 1));
        assert_eq!(p.max_ms, Some(1500));
        let (p, _) = propagation(&events, |f, l| f < 150.0 && l < 150.0);
        assert_eq!((p.blocks, p.median_ms), (1, Some(1500)));
    }

    #[test]
    fn partitions_and_their_heal_windows_are_not_connected() {
        let j = parse_journal(
            "[100] warm-up done after 1 s\n[500] partition #1 started (x)\n\
             [680] partition healed\n[2000] traffic phase over; final checks\n",
        );
        assert_eq!(j.partitions, vec![500.0]);
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
}
