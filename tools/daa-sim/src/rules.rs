//! Pluggable difficulty rules.
//!
//! [`ConsensusV3`] IS the consensus rule: it calls
//! [`blacksilk_consensus::difficulty::next_difficulty`] exactly as
//! `HeaderChain::required_difficulty` does. [`Lwma`] with window 60 is the pre-v3
//! consensus rule (LWMA-60, counted-clock step 1, no warm-up), frozen here as
//! [`legacy_next`] so that the selection and red-team evidence
//! (docs/evidence/daa-sim-2026-09-27/) stays reproducible after the v3 change.
//! Every other rule here is a candidate that exists only in this harness.

use blacksilk_consensus::difficulty::{difficulty_ancestors, next_difficulty, DIFFICULTY_WINDOW};

/// The pre-v3 consensus `next_difficulty` (rebuild/core before the v3 DAA change),
/// copied verbatim: LWMA-1, counted clock `this = max(ts, prev + 1)`, 6T cap,
/// floor `n²T/20`, no warm-up. Reads the last `window + 1` entries.
pub fn legacy_next(
    timestamps: &[u64],
    cumulative: &[u128],
    target: u64,
    window: usize,
    initial: u64,
) -> u64 {
    assert_eq!(timestamps.len(), cumulative.len());
    let take = timestamps.len().min(window + 1);
    let ts = &timestamps[timestamps.len() - take..];
    let cd = &cumulative[cumulative.len() - take..];
    let n = take.saturating_sub(1) as u128;
    if n == 0 {
        return initial;
    }
    let t = target as u128;

    let mut prev = ts[0] as u128;
    let mut weighted: u128 = 0;
    let mut sum_difficulty: u128 = 0;
    for i in 1..take {
        let this = if ts[i] as u128 > prev {
            ts[i] as u128
        } else {
            prev + 1
        };
        let solve_time = (this - prev).min(6 * t);
        prev = this;
        weighted += i as u128 * solve_time;
        sum_difficulty += cd[i] - cd[i - 1];
    }
    weighted = weighted.max(n * n * t / 20).max(1);

    let next = sum_difficulty * t * (n + 1) / (2 * weighted);
    next.clamp(1, u64::MAX as u128) as u64
}

/// The v3 consensus rule, called as `HeaderChain` calls it: the last
/// `difficulty_ancestors(75)` = 87 entries, window 75, and `cd[0]` (the anchor's
/// difficulty, `D0` for a branch from genesis) as the initial difficulty.
#[derive(Clone, Copy, Debug)]
pub struct ConsensusV3;

impl DifficultyRule for ConsensusV3 {
    fn name(&self) -> String {
        "LWMA-75 step T/2 warm 11 (v3 consensus)".into()
    }
    fn next(&self, ts: &[u64], cd: &[u128], target: u64) -> u64 {
        let from = ts
            .len()
            .saturating_sub(difficulty_ancestors(DIFFICULTY_WINDOW));
        let initial = cd[0].min(u64::MAX as u128) as u64;
        next_difficulty(&ts[from..], &cd[from..], target, DIFFICULTY_WINDOW, initial)
    }
}

/// A difficulty rule: the required difficulty of the child of the last block.
///
/// `ts` and `cd` are the whole simulated branch from its first block (the anchor,
/// usually genesis), oldest first, ending with the parent. `cd[i]` is the
/// cumulative difficulty including block `i`, and `cd[0]` is the anchor's own
/// difficulty (for genesis: `D0`, as in consensus). `target` is `T` in seconds.
pub trait DifficultyRule: Send + Sync {
    fn name(&self) -> String;
    fn next(&self, ts: &[u64], cd: &[u128], target: u64) -> u64;
}

/// A rule given as a closure, for quick experiments.
pub struct FnRule<F> {
    pub name: String,
    pub f: F,
}

impl<F: Fn(&[u64], &[u128], u64) -> u64 + Send + Sync> DifficultyRule for FnRule<F> {
    fn name(&self) -> String {
        self.name.clone()
    }
    fn next(&self, ts: &[u64], cd: &[u128], target: u64) -> u64 {
        (self.f)(ts, cd, target)
    }
}

/// The pre-v3 consensus LWMA-1 ([`legacy_next`]) with window `N` (60 before v3;
/// 90 was a candidate). The label "LWMA-60 (current)" is the one the committed
/// evidence tables print, kept so that regenerated tables stay byte-identical.
#[derive(Clone, Copy, Debug)]
pub struct Lwma {
    pub window: usize,
}

impl DifficultyRule for Lwma {
    fn name(&self) -> String {
        if self.window == 60 {
            "LWMA-60 (current)".into()
        } else {
            format!("LWMA-{}", self.window)
        }
    }
    fn next(&self, ts: &[u64], cd: &[u128], target: u64) -> u64 {
        // The pre-v3 consensus call passed the last N+1 blocks and
        // `initial_difficulty`, which is also the genesis difficulty (`cd[0]` of a
        // branch from genesis).
        let from = ts.len().saturating_sub(self.window + 1);
        let initial = cd[0].min(u64::MAX as u128) as u64;
        legacy_next(&ts[from..], &cd[from..], target, self.window, initial)
    }
}

/// LWMA-60 with a bounded rise: `next <= parent + max(1, parent * num / den)`.
#[derive(Clone, Copy, Debug)]
pub struct RiseCap {
    pub base: Lwma,
    pub num: u64,
    pub den: u64,
}

impl RiseCap {
    /// The largest difficulty allowed after a parent of difficulty `parent`.
    pub fn bound(&self, parent: u128) -> u128 {
        parent + (parent * self.num as u128 / self.den as u128).max(1)
    }
}

impl DifficultyRule for RiseCap {
    fn name(&self) -> String {
        let pct = self.num as f64 * 100.0 / self.den as f64;
        format!("LWMA-{} + rise <= {pct}%", self.base.window)
    }
    fn next(&self, ts: &[u64], cd: &[u128], target: u64) -> u64 {
        let next = self.base.next(ts, cd, target);
        let n = cd.len();
        if n < 2 {
            return next; // block 1: D0
        }
        let parent = cd[n - 1] - cd[n - 2];
        (next as u128).min(self.bound(parent)) as u64
    }
}

/// Integer ASERT (the aserti3-2d form, in difficulty rather than target), anchored
/// at the branch's first block:
/// `D(h+1) = D_anchor * 2^(-(ts_h - ts_anchor - T*h) / half_life)`.
#[derive(Clone, Copy, Debug)]
pub struct Asert {
    pub half_life: u64,
}

impl DifficultyRule for Asert {
    fn name(&self) -> String {
        format!("ASERT half-life {} h", self.half_life as f64 / 3600.0)
    }
    fn next(&self, ts: &[u64], cd: &[u128], target: u64) -> u64 {
        let anchor = cd[0];
        let h = (ts.len() - 1) as i128;
        let delta = ts[ts.len() - 1] as i128 - ts[0] as i128 - target as i128 * h;
        // Exponent in 1/65536 of a halving, rounded towards minus infinity.
        let exponent = (delta * 65_536).div_euclid(self.half_life as i128);
        let shifts = exponent >> 16;
        let frac = (exponent & 0xffff) as u128;
        // 2^(frac/65536) * 65536, the aserti3-2d cubic (error < 0.013%).
        let factor = 65_536
            + ((195_766_423_245_049 * frac
                + 971_821_376 * frac * frac
                + 5_127 * frac * frac * frac
                + (1u128 << 47))
                >> 48);
        let base = (anchor << 16) / factor;
        let d = if shifts >= 0 {
            if shifts >= 128 {
                0
            } else {
                base >> shifts
            }
        } else {
            let s = (-shifts).min(128) as u32;
            if s >= 128 || base > (u128::MAX >> s) {
                u128::MAX
            } else {
                base << s
            }
        };
        d.clamp(1, u64::MAX as u128) as u64
    }
}

/// The candidates compared in the report, the current rule first. The assignment's
/// set (LWMA-60, LWMA-90, rise caps of 2, 2.5, 3 and 5%, ASERT 2 h and 6 h) plus
/// caps of 1.75% and 2.25%, which bracket the 2% cap's acceptance window.
pub fn candidates() -> Vec<Box<dyn DifficultyRule>> {
    let lwma60 = Lwma { window: 60 };
    let cap = |num, den| RiseCap {
        base: lwma60,
        num,
        den,
    };
    vec![
        Box::new(lwma60),
        Box::new(Lwma { window: 90 }),
        Box::new(cap(7, 400)),
        Box::new(cap(2, 100)),
        Box::new(cap(9, 400)),
        Box::new(cap(5, 200)),
        Box::new(cap(3, 100)),
        Box::new(cap(5, 100)),
        Box::new(Asert { half_life: 7_200 }),
        Box::new(Asert { half_life: 21_600 }),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use blacksilk_consensus::ChainParams;

    fn steady(blocks: usize, t: u64, d: u64) -> (Vec<u64>, Vec<u128>) {
        let ts = (0..blocks as u64).map(|i| 1_000_000 + i * t).collect();
        let cd = (0..blocks as u128).map(|i| (i + 1) * d as u128).collect();
        (ts, cd)
    }

    #[test]
    fn lwma60_is_the_pre_v3_rule() {
        // The genesis-gap vector of the pre-v3 tools/genesis/tests/genesis.rs:
        // 100 -> 16.
        let ts = [1_790_000_000, 1_790_007_200];
        let cd = [100u128, 200];
        let rule = Lwma { window: 60 };
        assert_eq!(rule.next(&ts[..1], &cd[..1], 120), 100);
        assert_eq!(rule.next(&ts, &cd, 120), 16);
        // The pre-v3 floor vector (consensus/tests/golden.rs before v3): equal
        // timestamps, 60 blocks at 10 000 -> 101 666.
        let ts = [1_000_000u64; 61];
        let cd: Vec<u128> = (1..=61u128).map(|i| i * 10_000).collect();
        assert_eq!(rule.next(&ts, &cd, 120), 101_666);
        // A long history: the wrapper passes exactly the last N+1 blocks.
        let (ts, cd) = steady(500, 120, 10_000);
        assert_eq!(
            rule.next(&ts, &cd, 120),
            legacy_next(&ts[439..], &cd[439..], 120, 60, 1)
        );
    }

    #[test]
    fn consensus_v3_is_the_consensus_call() {
        let p = ChainParams::testnet();
        assert_eq!(p.difficulty_window, DIFFICULTY_WINDOW);
        assert_eq!(p.difficulty_ancestors(), 87);
        // The genesis gap: the 6T cap still gives 100 -> 16.
        let ts = [1_790_000_000, 1_790_007_200];
        let cd = [100u128, 200];
        assert_eq!(ConsensusV3.next(&ts[..1], &cd[..1], 120), 100);
        assert_eq!(ConsensusV3.next(&ts, &cd, 120), 16);
        // A long history: the wrapper passes exactly the last 87 blocks, and the
        // consensus function ignores anything older anyway.
        let (mut ts, cd) = steady(500, 120, 10_000);
        ts[500 - 88] = 0;
        let want = next_difficulty(&ts[413..], &cd[413..], 120, 75, 1);
        assert_eq!(ConsensusV3.next(&ts, &cd, 120), want);
        assert_eq!(next_difficulty(&ts, &cd, 120, 75, 1), want);
    }

    #[test]
    fn rise_cap_bounds_every_step_and_keeps_the_floor_moving() {
        let rule = RiseCap {
            base: Lwma { window: 60 },
            num: 2,
            den: 100,
        };
        // Compressed timestamps: LWMA alone would jump; the cap allows +2%.
        let mut ts = vec![1_000_000u64];
        let mut cd = vec![1_000_000u128];
        let mut d = 1_000_000u64;
        for _ in 0..200 {
            let prev_d = d;
            ts.push(ts.last().unwrap() + 1);
            cd.push(cd.last().unwrap() + prev_d as u128);
            d = rule.next(&ts, &cd, 120);
            assert!(d as u128 <= rule.bound(prev_d as u128), "{prev_d} -> {d}");
        }
        // At difficulty 1 the max(1, ..) term still lets the difficulty rise.
        let (ts, cd) = (vec![0, 1, 2], vec![1u128, 2, 3]);
        assert_eq!(rule.next(&ts, &cd, 10), 2);
    }

    #[test]
    fn asert_steady_state_and_half_life() {
        let rule = Asert { half_life: 7_200 };
        let (mut ts, cd) = steady(100, 120, 1_000_000);
        assert_eq!(rule.next(&ts, &cd, 120), 1_000_000);
        // One half-life behind schedule halves the difficulty; ahead doubles it.
        *ts.last_mut().unwrap() += 7_200;
        assert_eq!(rule.next(&ts, &cd, 120), 500_000);
        *ts.last_mut().unwrap() -= 14_400;
        assert_eq!(rule.next(&ts, &cd, 120), 2_000_000);
        // A quarter half-life ahead: 2^0.25 to within the polynomial's error.
        *ts.last_mut().unwrap() += 7_200 - 1_800;
        let d = rule.next(&ts, &cd, 120) as f64;
        assert!(
            (d / 1_000_000.0 / 2f64.powf(0.25) - 1.0).abs() < 2e-4,
            "{d}"
        );
    }
}
