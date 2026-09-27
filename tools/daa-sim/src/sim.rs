//! Simulated branches with the consensus timestamp rules.
//!
//! A [`Branch`] is the header chain as difficulty and timestamps see it. Every block
//! appended through [`Branch::push`] is checked with the consensus MTP and FTL
//! functions (`blacksilk_consensus::timestamp`), using the same windows as
//! `HeaderChain` (MTP over the last 11 blocks ending at the parent, strict; the FTL
//! against the local clock). A strategy that would produce an invalid header panics
//! instead of silently skewing a result.

use crate::rules::DifficultyRule;
use blacksilk_consensus::timestamp::{after_median_time_past, median, within_future_limit};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// Target block time `T` (testnet and mainnet; checked against `ChainParams`).
pub const TARGET: u64 = 120;
/// Future time limit in seconds.
pub const FTL: u64 = 360;
/// Median-time-past window.
pub const MTP_WINDOW: usize = 11;
/// Equilibrium difficulty at the reference hash rate. Large enough that integer
/// rounding (a 2% step of 120 is 2) does not distort the candidates.
pub const DEQ: u64 = 1_000_000;
/// Reference hash rate (hashes per second) at which `DEQ` gives one block per `T`.
pub const RATE: f64 = DEQ as f64 / TARGET as f64;
/// Timestamp of the first simulated block.
pub const START: u64 = 1_790_000_000;

#[derive(Clone, Debug)]
pub struct Branch {
    pub ts: Vec<u64>,
    pub cd: Vec<u128>,
}

impl Branch {
    /// A branch holding only a genesis block of difficulty `d0`.
    pub fn genesis(timestamp: u64, d0: u64) -> Self {
        Self {
            ts: vec![timestamp],
            cd: vec![d0 as u128],
        }
    }

    /// `blocks` on-target blocks of difficulty `d` (an equilibrium history).
    pub fn steady(blocks: usize, d: u64) -> Self {
        Self {
            ts: (0..blocks as u64).map(|i| START + i * TARGET).collect(),
            cd: (0..blocks as u128).map(|i| (i + 1) * d as u128).collect(),
        }
    }

    pub fn len(&self) -> usize {
        self.ts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ts.is_empty()
    }

    /// Cumulative work (the fork-choice quantity).
    pub fn work(&self) -> u128 {
        *self.cd.last().expect("non-empty")
    }

    pub fn tip_time(&self) -> u64 {
        *self.ts.last().expect("non-empty")
    }

    /// Difficulty of the last block.
    pub fn tip_difficulty(&self) -> u128 {
        let n = self.cd.len();
        if n == 1 {
            self.cd[0]
        } else {
            self.cd[n - 1] - self.cd[n - 2]
        }
    }

    fn recent(&self) -> &[u64] {
        &self.ts[self.ts.len().saturating_sub(MTP_WINDOW)..]
    }

    /// The median time past of a child (consensus `median_time_past(parent)`).
    pub fn mtp(&self) -> u64 {
        median(self.recent())
    }

    /// The lowest valid timestamp of a child.
    pub fn min_timestamp(&self) -> u64 {
        self.mtp() + 1
    }

    /// An honest miner's timestamp: its clock, raised to the MTP bound if needed.
    pub fn honest_stamp(&self, now: f64) -> u64 {
        (now as u64).max(self.min_timestamp())
    }

    /// The required difficulty of a child under `rule`.
    pub fn required(&self, rule: &dyn DifficultyRule) -> u64 {
        rule.next(&self.ts, &self.cd, TARGET)
    }

    /// Appends a block found at real time `now`, checking the consensus MTP and FTL
    /// rules. Panics on an invalid timestamp (a bug in the scenario).
    pub fn push(&mut self, timestamp: u64, difficulty: u64, now: f64) {
        assert!(
            after_median_time_past(timestamp, self.recent()),
            "MTP violated: {timestamp} <= {}",
            self.mtp()
        );
        assert!(
            within_future_limit(timestamp, now as u64, FTL),
            "FTL violated: {timestamp} > {now} + {FTL}"
        );
        self.ts.push(timestamp);
        self.cd.push(self.work() + difficulty as u128);
    }

    /// Appends without the timestamp checks (lookahead only; undo with [`Self::pop`]).
    pub(crate) fn push_raw(&mut self, timestamp: u64, difficulty: u64) {
        self.ts.push(timestamp);
        self.cd.push(self.work() + difficulty as u128);
    }

    pub(crate) fn pop(&mut self) {
        self.ts.pop();
        self.cd.pop();
    }

    /// The child difficulty if a block (`timestamp`, `difficulty`) were appended.
    pub fn next_if(&mut self, timestamp: u64, difficulty: u64, rule: &dyn DifficultyRule) -> u64 {
        self.push_raw(timestamp, difficulty);
        let d = self.required(rule);
        self.pop();
        d
    }
}

/// Runs `f` over `items` on `threads` worker threads, keeping the input order. The
/// results do not depend on the thread count (each item carries its own seed).
pub fn par_map<T: Sync, R: Send>(
    items: &[T],
    threads: usize,
    f: impl Fn(&T) -> R + Sync,
) -> Vec<R> {
    let next = AtomicUsize::new(0);
    let out: Mutex<Vec<Option<R>>> = Mutex::new((0..items.len()).map(|_| None).collect());
    std::thread::scope(|s| {
        for _ in 0..threads.clamp(1, items.len().max(1)) {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= items.len() {
                    break;
                }
                let r = f(&items[i]);
                out.lock().expect("no poisoned worker")[i] = Some(r);
            });
        }
    });
    out.into_inner()
        .expect("no poisoned worker")
        .into_iter()
        .map(|r| r.expect("every item ran"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Lwma;
    use blacksilk_consensus::ChainParams;

    #[test]
    fn constants_match_consensus() {
        for p in [ChainParams::testnet(), ChainParams::mainnet()] {
            assert_eq!(p.target_block_time, TARGET);
            assert_eq!(p.future_time_limit, FTL);
            assert_eq!(p.median_time_window, MTP_WINDOW);
            assert_eq!(p.difficulty_window, 75);
        }
    }

    #[test]
    fn steady_branch_is_at_equilibrium() {
        let b = Branch::steady(121, DEQ);
        assert_eq!(b.required(&Lwma { window: 60 }), DEQ);
        assert_eq!(b.tip_difficulty(), DEQ as u128);
        assert_eq!(b.min_timestamp(), START + 115 * TARGET + 1);
    }

    #[test]
    #[should_panic(expected = "MTP violated")]
    fn push_enforces_mtp() {
        let mut b = Branch::steady(20, DEQ);
        let t = b.mtp();
        b.push(t, DEQ, (START + 10_000) as f64);
    }

    #[test]
    #[should_panic(expected = "FTL violated")]
    fn push_enforces_ftl() {
        let mut b = Branch::steady(20, DEQ);
        let now = b.tip_time() as f64;
        b.push(b.tip_time() + FTL + 1, DEQ, now);
    }

    #[test]
    fn par_map_keeps_order() {
        let v: Vec<u64> = (0..100).collect();
        assert_eq!(
            par_map(&v, 4, |x| x * 2),
            (0..100).map(|x| x * 2).collect::<Vec<_>>()
        );
    }
}
