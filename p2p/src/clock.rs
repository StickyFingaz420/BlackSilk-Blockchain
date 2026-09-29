//! The local clock's offset against recent blocks, estimated for a warning
//! only (dossier 04 P2, W3; R1-C9; docs/p2p.md §6.1).
//!
//! **Never applied.** Every consensus check (the future time limit, FTL) uses
//! the local clock alone; nothing here changes it, and nothing here is sent
//! to a peer. BlackSilk's `Version` message carries no clock (a clock's skew
//! identifies a device: Kohno, Broido and claffy 2005; Murdoch 2006), so the
//! peer-time median of Bitcoin (whose offsets are warn-only since Bitcoin Core
//! 27.0) is not available. The estimate is drawn from blocks instead:
//!
//! - **Live arrivals.** When a header batch that is not a bulk-sync batch
//!   extends the best header chain, its proof of work verified, the offset
//!   `timestamp − arrival` of its last header is a sample. An honest sample
//!   is a few seconds to a few tens of seconds below zero (the miner's
//!   template age plus propagation).
//! - **Retro-confirmed future refusals.** A header refused only by the FTL
//!   is remembered (at most [`REFUSED_KEEP`], the first sighting kept); if
//!   the same header is accepted later, its proof of work verified, the
//!   offset `timestamp − first sighting` is a sample. This is what a slow
//!   clock produces: every new tip is refused until the clock reaches it. An
//!   unverified refusal is never a sample (the FTL is checked before the
//!   proof of work, so it costs a forger nothing).
//!
//! Each sample needs a header with valid proof of work at the chain's
//! difficulty, so a peer cannot move the estimate for free: an eclipsing
//! attacker can delay blocks (pushing the estimate below zero, which the
//! warning names as a possible cause), not forge them. The estimate is the
//! lower median of the last [`SAMPLES`] samples (one per block), reported
//! once [`MIN_SAMPLES`] samples from [`MIN_PEERS`] distinct peers are held.
//!
//! **Thresholds** (FTL = 360 s on every network): a WARN when the estimate's
//! magnitude exceeds FTL/3, an ERROR when it exceeds the FTL, repeated at
//! most every [`REPEAT`] while it lasts, and one INFO line when it falls
//! back below FTL/6 (hysteresis).

use crate::dandelion::PeerId;
use blacksilk_consensus::Hash;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Samples the estimate is the median of.
pub const SAMPLES: usize = 25;
/// Samples needed before an estimate is reported.
pub const MIN_SAMPLES: usize = 5;
/// Distinct peers the samples held must come from before an estimate is
/// reported.
pub const MIN_PEERS: usize = 3;
/// Headers refused only by the future time limit that are remembered.
pub const REFUSED_KEEP: usize = 64;
/// A warning is repeated at most this often while it lasts.
pub const REPEAT: Duration = Duration::from_secs(600);

/// The current estimate (`ClockMonitor::estimate`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockEstimate {
    /// Median of `block timestamp − local clock` over the samples, seconds:
    /// positive when the local clock is behind the blocks' timestamps.
    pub offset_secs: i64,
    pub samples: usize,
    pub peers: usize,
}

/// How far the estimate is from zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClockLevel {
    Normal,
    /// Above FTL/3.
    Warn,
    /// Above the FTL.
    Error,
}

/// A line to log (`ClockMonitor::note_accepted`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClockReport {
    pub level: ClockLevel,
    pub message: String,
}

/// A header accepted with its proof of work verified
/// (`ClockMonitor::note_accepted`).
#[derive(Clone, Copy, Debug)]
pub struct Accepted {
    pub id: Hash,
    pub timestamp: u64,
    /// The peer that sent it.
    pub peer: PeerId,
    /// Local time when its batch arrived.
    pub arrival: u64,
    /// It extended the best header chain outside bulk sync.
    pub live: bool,
}

#[derive(Clone, Copy, Debug)]
struct Sample {
    id: Hash,
    peer: PeerId,
    offset: i64,
}

/// The warn-only clock monitor (module docs).
#[derive(Debug, Default)]
pub struct ClockMonitor {
    samples: VecDeque<Sample>,
    /// Headers refused only by the future time limit: id and first
    /// sighting, oldest first.
    refused: VecDeque<(Hash, u64)>,
    level: Option<ClockLevel>,
    last_report: Option<Instant>,
}

impl ClockMonitor {
    /// A header was refused only by the future time limit at local time
    /// `now` (unverified: kept, never a sample by itself).
    pub fn note_future_refusal(&mut self, id: Hash, now: u64) {
        if self.refused.iter().any(|(r, _)| *r == id) {
            return; // the first sighting counts
        }
        if self.refused.len() >= REFUSED_KEEP {
            self.refused.pop_front();
        }
        self.refused.push_back((id, now));
    }

    /// Whether any refusal is remembered (callers skip computing ids
    /// otherwise).
    pub fn has_refusals(&self) -> bool {
        !self.refused.is_empty()
    }

    /// A header was accepted, its proof of work verified. It becomes a
    /// sample if it was refused by the future time limit before
    /// (`timestamp − first sighting`), or if `live` (it extended the best
    /// header chain outside bulk sync: `timestamp − arrival`). Returns a
    /// line to log when the level changes, or when a warning is due again.
    pub fn note_accepted(&mut self, a: Accepted, ftl: u64, mono: Instant) -> Option<ClockReport> {
        let offset = if let Some(pos) = self.refused.iter().position(|(r, _)| *r == a.id) {
            let (_, first) = self.refused.remove(pos).expect("found");
            diff(a.timestamp, first)
        } else if a.live {
            diff(a.timestamp, a.arrival)
        } else {
            return None;
        };
        if self.samples.iter().any(|s| s.id == a.id) {
            return None;
        }
        if self.samples.len() >= SAMPLES {
            self.samples.pop_front();
        }
        self.samples.push_back(Sample {
            id: a.id,
            peer: a.peer,
            offset,
        });
        self.evaluate(ftl, mono)
    }

    /// The estimate, once enough samples from enough peers are held.
    pub fn estimate(&self) -> Option<ClockEstimate> {
        if self.samples.len() < MIN_SAMPLES {
            return None;
        }
        let mut peers: Vec<PeerId> = self.samples.iter().map(|s| s.peer).collect();
        peers.sort_unstable();
        peers.dedup();
        if peers.len() < MIN_PEERS {
            return None;
        }
        let mut offsets: Vec<i64> = self.samples.iter().map(|s| s.offset).collect();
        offsets.sort_unstable();
        Some(ClockEstimate {
            offset_secs: offsets[(offsets.len() - 1) / 2],
            samples: offsets.len(),
            peers: peers.len(),
        })
    }

    fn evaluate(&mut self, ftl: u64, mono: Instant) -> Option<ClockReport> {
        let e = self.estimate()?;
        let magnitude = e.offset_secs.unsigned_abs();
        let prev = self.level.unwrap_or(ClockLevel::Normal);
        let level = if magnitude > ftl {
            ClockLevel::Error
        } else if magnitude > ftl / 3 || (prev > ClockLevel::Normal && magnitude >= ftl / 6) {
            // Above FTL/3, or not back below FTL/6 yet (hysteresis).
            ClockLevel::Warn
        } else {
            ClockLevel::Normal
        };
        self.level = Some(level);
        let due = self
            .last_report
            .is_none_or(|t| mono.saturating_duration_since(t) >= REPEAT);
        let report = match level {
            ClockLevel::Normal if prev > ClockLevel::Normal => Some(ClockReport {
                level,
                message: format!(
                    "the local clock is back within {} s of recent blocks' timestamps \
                     (median offset {} s over {} blocks from {} peers)",
                    ftl / 6,
                    e.offset_secs,
                    e.samples,
                    e.peers
                ),
            }),
            ClockLevel::Normal => None,
            _ if level > prev || due => Some(ClockReport {
                level,
                message: skew_message(e, ftl),
            }),
            _ => None,
        };
        if report.is_some() {
            self.last_report = Some(mono);
        }
        report
    }
}

/// `a − b` in seconds, saturating.
fn diff(a: u64, b: u64) -> i64 {
    if a >= b {
        i64::try_from(a - b).unwrap_or(i64::MAX)
    } else {
        i64::try_from(b - a).map_or(i64::MIN, |d| -d)
    }
}

fn skew_message(e: ClockEstimate, ftl: u64) -> String {
    let basis = format!(
        "median offset {} s over the last {} blocks from {} peers",
        e.offset_secs, e.samples, e.peers
    );
    if e.offset_secs > 0 {
        format!(
            "the local clock appears about {} s behind recent blocks' timestamps ({basis}). \
             Blocks stamped more than {ftl} s (the future time limit) ahead of this clock are \
             refused until it reaches them, so this node falls behind the network. Check the \
             system clock and NTP (docs/testnet.md §12.2); the estimate is never used for \
             validation",
            e.offset_secs
        )
    } else {
        format!(
            "the local clock appears about {} s ahead of recent blocks' timestamps ({basis}). \
             Blocks this node's miners stamp from it may be refused by peers as too far in \
             the future. This can also mean that the miners' clocks are slow or that peers \
             delay blocks. Check the system clock and NTP (docs/testnet.md §12.2); the \
             estimate is never used for validation",
            e.offset_secs.unsigned_abs()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FTL: u64 = 360;

    fn id(i: u64) -> Hash {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&i.to_le_bytes());
        h
    }

    fn live(i: u64, timestamp: u64, peer: PeerId, arrival: u64) -> Accepted {
        Accepted {
            id: id(i),
            timestamp,
            peer,
            arrival,
            live: true,
        }
    }

    /// Feeds live samples `offsets[i]` for blocks `first + i`, from peers
    /// cycling over `peers`; returns the reports.
    fn feed(
        m: &mut ClockMonitor,
        first: u64,
        offsets: &[i64],
        peers: u64,
        mono: Instant,
    ) -> Vec<ClockReport> {
        let arrival = 1_000_000u64;
        offsets
            .iter()
            .enumerate()
            .filter_map(|(i, &o)| {
                let ts = arrival.checked_add_signed(o).unwrap();
                m.note_accepted(
                    live(first + i as u64, ts, i as u64 % peers, arrival),
                    FTL,
                    mono,
                )
            })
            .collect()
    }

    #[test]
    fn the_estimate_is_the_lower_median_and_needs_samples_and_peers() {
        let mono = Instant::now();
        let mut m = ClockMonitor::default();
        assert!(feed(&mut m, 0, &[-5, -10, -20, -1], 3, mono).is_empty());
        assert_eq!(m.estimate(), None, "4 samples");
        feed(&mut m, 10, &[-30, -2], 3, mono);
        let e = m.estimate().unwrap();
        assert_eq!((e.samples, e.peers), (6, 3));
        // Sorted: -30 -20 -10 -5 -2 -1; the lower median is -10.
        assert_eq!(e.offset_secs, -10);
        // Two peers only: no estimate.
        let mut m = ClockMonitor::default();
        feed(&mut m, 0, &[-5; 10], 2, mono);
        assert_eq!(m.estimate(), None);
    }

    #[test]
    fn only_the_last_samples_count_one_per_block() {
        let mono = Instant::now();
        let mut m = ClockMonitor::default();
        feed(&mut m, 0, &[500; SAMPLES], 3, mono);
        feed(&mut m, 100, &[-3; SAMPLES], 3, mono);
        assert_eq!(m.estimate().unwrap().offset_secs, -3);
        assert_eq!(m.estimate().unwrap().samples, SAMPLES);
        // The same block again is not a second sample.
        let before = m.samples.len();
        assert!(m
            .note_accepted(live(100, 0, 1, 1_000_000), FTL, mono)
            .is_none());
        assert_eq!(m.samples.len(), before);
        assert_eq!(m.estimate().unwrap().offset_secs, -3);
    }

    #[test]
    fn a_header_that_is_not_live_and_was_not_refused_is_no_sample() {
        let mut m = ClockMonitor::default();
        let mut a = live(1, 5, 1, 1_000_000);
        a.live = false;
        m.note_accepted(a, FTL, Instant::now());
        assert!(m.samples.is_empty());
    }

    /// A slow clock: each new tip is refused by the FTL first, then accepted
    /// once the clock reaches it; the retro-confirmed samples carry the
    /// offset. Unconfirmed refusals are never samples, and the list is
    /// bounded.
    #[test]
    fn retro_confirmed_refusals_measure_a_slow_clock() {
        let mono = Instant::now();
        let mut m = ClockMonitor::default();
        let mut reports = Vec::new();
        for i in 0..6u64 {
            let ts = 2_000_000 + 60 * i;
            let local = ts - 400; // the clock is 400 s behind
            m.note_future_refusal(id(i), local);
            m.note_future_refusal(id(i), local + 10); // the first sighting counts
            let mut a = live(i, ts, i % 3, local + 40);
            a.live = false;
            reports.extend(m.note_accepted(a, FTL, mono));
        }
        assert_eq!(m.estimate().unwrap().offset_secs, 400);
        assert_eq!(reports.len(), 1, "{reports:?}");
        assert_eq!(reports[0].level, ClockLevel::Error);
        assert!(
            reports[0].message.contains("behind"),
            "{}",
            reports[0].message
        );
        // Refusals alone are never samples, and at most REFUSED_KEEP are kept.
        let mut m = ClockMonitor::default();
        for i in 0..(REFUSED_KEEP as u64 + 10) {
            m.note_future_refusal(id(i), 1);
        }
        assert!(m.samples.is_empty() && m.estimate().is_none());
        assert_eq!(m.refused.len(), REFUSED_KEEP);
        assert_eq!(m.refused.front().unwrap().0, id(10), "oldest dropped");
    }

    #[test]
    fn warnings_have_levels_repeat_limits_and_hysteresis() {
        let t0 = Instant::now();
        let mut m = ClockMonitor::default();
        // Honest offsets: silent.
        assert!(feed(&mut m, 0, &[-8; 10], 3, t0).is_empty());
        // A fast clock (blocks look 200 s old): one WARN when the median
        // crosses FTL/3 = 120, not one per block.
        let r = feed(&mut m, 100, &[-200; 20], 3, t0);
        assert_eq!(r.len(), 1, "{r:?}");
        assert_eq!(r[0].level, ClockLevel::Warn);
        assert!(r[0].message.contains("ahead"), "{}", r[0].message);
        // Still skewed: repeated only after REPEAT.
        assert!(feed(&mut m, 200, &[-200; 5], 3, t0 + REPEAT / 2).is_empty());
        let r = feed(&mut m, 300, &[-200], 3, t0 + REPEAT);
        assert_eq!(r.len(), 1);
        // Worse (past the FTL): an ERROR at once.
        let r = feed(&mut m, 400, &[-500; 25], 3, t0 + REPEAT);
        assert_eq!(r[0].level, ClockLevel::Error);
        assert_eq!(r.len(), 1, "{r:?}");
        // Back to 100 s: still above FTL/6 = 60, so no "back" line yet.
        let r = feed(&mut m, 500, &[-100; 25], 3, t0 + REPEAT);
        assert!(r.iter().all(|x| x.level != ClockLevel::Normal), "{r:?}");
        // Back to honest: one INFO line.
        let r = feed(&mut m, 600, &[-5; 25], 3, t0 + REPEAT);
        assert_eq!(
            r.iter().filter(|x| x.level == ClockLevel::Normal).count(),
            1,
            "{r:?}"
        );
        assert_eq!(m.level, Some(ClockLevel::Normal));
    }

    #[test]
    fn offsets_saturate() {
        assert_eq!(diff(u64::MAX, 0), i64::MAX);
        assert_eq!(diff(0, u64::MAX), i64::MIN);
        assert_eq!(diff(5, 7), -2);
    }
}
