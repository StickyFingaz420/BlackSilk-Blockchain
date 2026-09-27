//! The scenarios. Each one takes a rule and its own seed; the report layer spreads
//! trials over threads and aggregates.
//!
//! Model: a miner with hash rate `H` finds a block of difficulty `D` after an
//! exponential time of mean `D / H` (a block of difficulty `D` takes `D` hashes on
//! average, docs/consensus.md §3). `RATE` is the reference total hash rate, at
//! which the equilibrium difficulty is `DEQ`.

use crate::rng::Rng;
use crate::rules::DifficultyRule;
use crate::sim::{Branch, DEQ, FTL, RATE, START, TARGET};

/// A success count.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rate {
    pub hits: u64,
    pub trials: u64,
}

impl Rate {
    pub fn p(&self) -> f64 {
        if self.trials == 0 {
            0.0
        } else {
            self.hits as f64 / self.trials as f64
        }
    }

    /// Binomial standard error.
    pub fn se(&self) -> f64 {
        let p = self.p();
        (p * (1.0 - p) / self.trials.max(1) as f64).sqrt()
    }

    pub fn add(&mut self, other: Rate) {
        self.hits += other.hits;
        self.trials += other.trials;
    }
}

/// How a private miner stamps its blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stamping {
    /// Its real clock (the baseline: a private branch with honest timestamps).
    Honest,
    /// Always `MTP + 1`, the lowest valid timestamp: every counted solve time is
    /// tiny, so the branch's own difficulty climbs as fast as the rule allows.
    Compressed,
}

impl Stamping {
    fn stamp(self, b: &Branch, now: f64) -> u64 {
        match self {
            Stamping::Honest => b.honest_stamp(now),
            Stamping::Compressed => b.min_timestamp(),
        }
    }
}

/// A block whose lowest valid timestamp (`MTP + 1`) is beyond the FTL at the time it
/// is found cannot be accepted yet: very fast blocks (difficulty far below the hash
/// rate) push the MTP ahead of the clock by one second per block. The miner holds
/// it until the clock allows the stamp; returns that time, or `None` if valid now.
fn held_back(timestamp: u64, now: f64) -> Option<f64> {
    (timestamp > now as u64 + FTL).then(|| (timestamp - FTL) as f64)
}

// --------------------------------------------------------------------------------
// The difficulty-raising race (Bahack).

/// One private-branch race. From an equilibrium chain, an attacker with share `q`
/// of the hash rate mines privately; the honest miners (`1 - q`) extend the public
/// chain with real-time stamps. The attacker wins if, at any time once the public
/// chain has `z` blocks after the fork, its branch has strictly more cumulative
/// work (so every node reorganizes to it). The race runs for `12 z + 240` target
/// block times, as in dossier 03.
pub fn race_trial(
    rule: &dyn DifficultyRule,
    q: f64,
    z: usize,
    stamping: Stamping,
    rng: &mut Rng,
) -> bool {
    let base = Branch::steady(121, DEQ);
    let mut public = base.clone();
    let mut private = base;
    let mut now = public.tip_time() as f64;
    let t_end = now + ((12 * z + 240) as u64 * TARGET) as f64;
    let (h_rate, a_rate) = ((1.0 - q) * RATE, q * RATE);
    let mut hd = public.required(rule);
    let mut ad = private.required(rule);
    let mut h_next = now + rng.exp() * hd as f64 / h_rate;
    let mut a_next = now + rng.exp() * ad as f64 / a_rate;
    let mut confirmations = 0;
    while h_next.min(a_next) < t_end {
        if h_next <= a_next {
            let t = public.honest_stamp(h_next);
            if let Some(later) = held_back(t, h_next) {
                h_next = later;
                continue;
            }
            now = h_next;
            public.push(t, hd, now);
            confirmations += 1;
            hd = public.required(rule);
            h_next = now + rng.exp() * hd as f64 / h_rate;
        } else {
            let t = stamping.stamp(&private, a_next);
            if let Some(later) = held_back(t, a_next) {
                a_next = later;
                continue;
            }
            now = a_next;
            private.push(t, ad, now);
            ad = private.required(rule);
            a_next = now + rng.exp() * ad as f64 / a_rate;
        }
        if confirmations >= z && private.work() > public.work() {
            return true;
        }
    }
    false
}

pub fn race(
    rule: &dyn DifficultyRule,
    q: f64,
    z: usize,
    stamping: Stamping,
    trials: usize,
    seed: u64,
) -> Rate {
    let mut rng = Rng::new(seed);
    let hits = (0..trials)
        .filter(|_| race_trial(rule, q, z, stamping, &mut rng))
        .count();
    Rate {
        hits: hits as u64,
        trials: trials as u64,
    }
}

// --------------------------------------------------------------------------------
// Full-history rewrite from genesis.

/// Cap on the private blocks of one genesis-fork trial (a branch at difficulty 1
/// could otherwise produce millions); a capped trial counts as a loss and is
/// reported.
pub const FORK_BLOCK_CAP: usize = 200_000;

/// Outcome of one genesis-fork trial.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForkOutcome {
    Win,
    Loss,
    Capped,
}

/// The chain runs `age` blocks from genesis (`D0 = DEQ`) at the full hash rate.
/// Then a miner with share `q` leaves and mines a private branch from genesis for
/// up to `horizon_s` seconds; it wins if its branch ever has strictly more work
/// than the public chain.
pub fn genesis_fork_trial(
    rule: &dyn DifficultyRule,
    q: f64,
    age: usize,
    stamping: Stamping,
    horizon_s: f64,
    rng: &mut Rng,
) -> ForkOutcome {
    let mut public = Branch::genesis(START, DEQ);
    let mut now = START as f64;
    for _ in 0..age {
        let d = public.required(rule);
        now += rng.exp() * d as f64 / RATE;
        public.push(public.honest_stamp(now), d, now);
    }
    let mut private = Branch::genesis(START, DEQ);
    let t_end = now + horizon_s;
    let (h_rate, a_rate) = ((1.0 - q) * RATE, q * RATE);
    let mut hd = public.required(rule);
    let mut ad = private.required(rule);
    let mut h_next = now + rng.exp() * hd as f64 / h_rate;
    let mut a_next = now + rng.exp() * ad as f64 / a_rate;
    while h_next.min(a_next) < t_end {
        if h_next <= a_next {
            let t = public.honest_stamp(h_next);
            if let Some(later) = held_back(t, h_next) {
                h_next = later;
                continue;
            }
            now = h_next;
            public.push(t, hd, now);
            hd = public.required(rule);
            h_next = now + rng.exp() * hd as f64 / h_rate;
        } else {
            let t = stamping.stamp(&private, a_next);
            if let Some(later) = held_back(t, a_next) {
                a_next = later;
                continue;
            }
            now = a_next;
            private.push(t, ad, now);
            if private.work() > public.work() {
                return ForkOutcome::Win;
            }
            if private.len() > FORK_BLOCK_CAP {
                return ForkOutcome::Capped;
            }
            ad = private.required(rule);
            a_next = now + rng.exp() * ad as f64 / a_rate;
        }
    }
    ForkOutcome::Loss
}

// --------------------------------------------------------------------------------
// Honest operation.

/// Mean honest solve time over `blocks` blocks at a constant hash rate (after a
/// 1 000-block burn-in), as `(sum of solve times, count)`.
pub fn honest_bias(rule: &dyn DifficultyRule, blocks: usize, rng: &mut Rng) -> (f64, usize) {
    let mut b = Branch::steady(121, DEQ);
    let mut now = b.tip_time() as f64;
    let (mut sum, mut count) = (0.0, 0);
    for k in 0..blocks + 1_000 {
        let d = b.required(rule);
        let dt = rng.exp() * d as f64 / RATE;
        now += dt;
        b.push(b.honest_stamp(now), d, now);
        if k >= 1_000 {
            sum += dt;
            count += 1;
        }
    }
    (sum, count)
}

/// How fast the difficulty follows a change of equilibrium.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Follow {
    /// Blocks after the change until a block's difficulty is within ±10% of the new
    /// equilibrium (`None`: not within `max_blocks`).
    pub blocks: Option<usize>,
    /// Wall-clock hours until then.
    pub hours: f64,
}

/// Solve time of a block: exponential with `rng`, or its expectation without.
fn solve_time(rng: &mut Option<&mut Rng>, d: u64, rate: f64) -> f64 {
    let e = match rng {
        Some(r) => r.exp(),
        None => 1.0,
    };
    e * d as f64 / rate
}

fn in_band(d: u64, eq: f64) -> bool {
    (d as f64 / eq - 1.0).abs() <= 0.1
}

/// From equilibrium, the hash rate jumps by `factor` (10.0 or 0.1).
pub fn step(
    rule: &dyn DifficultyRule,
    factor: f64,
    mut rng: Option<&mut Rng>,
    max_blocks: usize,
) -> Follow {
    let mut b = Branch::steady(121, DEQ);
    let start = b.tip_time() as f64;
    let mut now = start;
    let rate = factor * RATE;
    let eq = factor * DEQ as f64;
    for k in 1..=max_blocks {
        let d = b.required(rule);
        if in_band(d, eq) {
            return Follow {
                blocks: Some(k),
                hours: (now - start) / 3600.0,
            };
        }
        now += solve_time(&mut rng, d, rate);
        b.push(b.honest_stamp(now), d, now);
    }
    Follow {
        blocks: None,
        hours: (now - start) / 3600.0,
    }
}

/// Start-up: genesis difficulty `D0 = d0_factor * DEQ`, honest miners at the
/// reference rate from the genesis time. Returns the time to block 1 (seconds) and
/// the first height whose difficulty is within ±10% of equilibrium.
pub fn startup(
    rule: &dyn DifficultyRule,
    d0_factor: f64,
    mut rng: Option<&mut Rng>,
    max_blocks: usize,
) -> (f64, Follow) {
    let d0 = ((DEQ as f64 * d0_factor) as u64).max(1);
    let mut b = Branch::genesis(START, d0);
    let mut now = START as f64;
    let mut first = 0.0;
    for height in 1..=max_blocks {
        let d = b.required(rule);
        if in_band(d, DEQ as f64) {
            return (
                first,
                Follow {
                    blocks: Some(height),
                    hours: (now - START as f64) / 3600.0,
                },
            );
        }
        let dt = solve_time(&mut rng, d, RATE);
        if height == 1 {
            first = dt;
        }
        now += dt;
        b.push(b.honest_stamp(now), d, now);
    }
    (
        first,
        Follow {
            blocks: None,
            hours: (now - START as f64) / 3600.0,
        },
    )
}

/// The genesis-to-launch gap (docs/testnet-v3-genesis.md: `T_g` about 2 h before
/// mining starts).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Gap {
    /// Lowest difficulty reached, relative to equilibrium.
    pub min_ratio: f64,
    /// First height >= 2 whose difficulty is back at >= 90% of equilibrium.
    pub recovered_at: Option<usize>,
    /// Blocks found in the first 6 hours of mining, minus the 180 expected.
    pub extra_blocks_6h: i64,
}

/// Genesis at `START` with `D0 = d_eq` (the right value), miners at the rate that
/// `d_eq` was chosen for, starting `gap_s` seconds after the genesis timestamp.
pub fn genesis_gap(
    rule: &dyn DifficultyRule,
    d_eq: u64,
    gap_s: u64,
    mut rng: Option<&mut Rng>,
    max_blocks: usize,
) -> Gap {
    let rate = d_eq as f64 / TARGET as f64;
    let mut b = Branch::genesis(START, d_eq);
    let launch = (START + gap_s) as f64;
    let mut now = launch;
    let mut min_ratio = f64::MAX;
    let mut recovered_at = None;
    let mut in_6h = 0i64;
    for height in 1..=max_blocks {
        let d = b.required(rule);
        let ratio = d as f64 / d_eq as f64;
        min_ratio = min_ratio.min(ratio);
        if recovered_at.is_none() && height >= 2 && min_ratio < 0.9 && ratio >= 0.9 {
            recovered_at = Some(height);
        }
        now += solve_time(&mut rng, d, rate);
        if now <= launch + 6.0 * 3600.0 {
            in_6h += 1;
        } else if recovered_at.is_some() || min_ratio >= 0.9 {
            break;
        }
        b.push(b.honest_stamp(now), d, now);
    }
    Gap {
        min_ratio,
        recovered_at: if min_ratio >= 0.9 {
            Some(1)
        } else {
            recovered_at
        },
        extra_blocks_6h: in_6h - (6 * 3600 / TARGET) as i64,
    }
}

/// Hop-in/hop-out mining.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Hopper {
    /// Expected share of all blocks found by the hopper (lower is better).
    pub share: f64,
    /// Mean solve time of all blocks, in units of `T`.
    pub mean_st: f64,
    /// Fraction of blocks slower than `6 T` (stalls for the dedicated miners).
    pub slow: f64,
}

/// A hopper with 10x the dedicated hash rate mines while `D < 1.2 DEQ` and leaves
/// once `D > 2 DEQ` (dossier 03's hash-and-flee), over `blocks` blocks.
pub fn hopper(rule: &dyn DifficultyRule, blocks: usize, rng: &mut Rng) -> Hopper {
    const BIG: f64 = 10.0;
    let mut b = Branch::steady(121, DEQ);
    let mut now = b.tip_time() as f64;
    let mut on = false;
    let (mut hop, mut sum, mut slow) = (0.0, 0.0, 0usize);
    for _ in 0..blocks {
        let d = b.required(rule);
        if !on && (d as f64) < 1.2 * DEQ as f64 {
            on = true;
        } else if on && (d as f64) > 2.0 * DEQ as f64 {
            on = false;
        }
        let h = if on { 1.0 + BIG } else { 1.0 };
        let dt = rng.exp() * d as f64 / (h * RATE);
        if on {
            hop += BIG / (1.0 + BIG);
        }
        if dt > 6.0 * TARGET as f64 {
            slow += 1;
        }
        sum += dt;
        now += dt;
        b.push(b.honest_stamp(now), d, now);
    }
    let n = blocks as f64;
    Hopper {
        share: hop / n,
        mean_st: sum / n / TARGET as f64,
        slow: slow as f64 / n,
    }
}

// --------------------------------------------------------------------------------
// Timestamp-lowering strategies (dossier 04's families) by a 100% miner.

/// Where a periodic strategy puts a low stamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Low {
    /// `MTP + 1`.
    Mtp,
    /// `previous + 1`.
    PrevPlusOne,
}

/// A timestamp strategy. Every choice is clamped into the valid range
/// `[MTP + 1, now + FTL]`.
#[derive(Clone, Debug, PartialEq)]
pub enum Strategy {
    Honest,
    /// Every stamp at the FTL edge.
    AllFtl,
    /// Every stamp at `MTP + 1`.
    AllMtp,
    /// `b` of every `c` blocks low, the rest at the FTL edge.
    Cycle {
        b: usize,
        c: usize,
        low: Low,
    },
    /// One FTL-edge stamp every `c` blocks, the rest honest.
    EdgeEvery(usize),
    /// Low (`MTP + 1`) while the FTL edge is less than `x` s past the previous
    /// stamp, else jump by up to `6 T` (dossier 03's threshold policy).
    Threshold(u64),
    /// Myopic greedy: the candidate that minimises the next difficulty.
    Greedy,
    /// Two-step lookahead greedy: minimises the next two difficulties.
    Greedy2,
    /// A random periodic pattern: `None` = `MTP + 1`, `Some(a)` = previous + `a`.
    Pattern(Vec<Option<u64>>),
}

impl Strategy {
    pub fn family(&self) -> &'static str {
        match self {
            Strategy::Honest => "honest",
            Strategy::AllFtl => "all at FTL edge",
            Strategy::AllMtp => "all at MTP+1",
            Strategy::Cycle { .. } => "b-of-c cycles",
            Strategy::EdgeEvery(_) => "one FTL edge every c",
            Strategy::Threshold(_) => "threshold",
            Strategy::Greedy => "myopic greedy",
            Strategy::Greedy2 => "two-step greedy",
            Strategy::Pattern(_) => "random periodic patterns",
        }
    }

    pub fn label(&self) -> String {
        match self {
            Strategy::Cycle { b, c, low } => format!("{b}-of-{c} {low:?}"),
            Strategy::EdgeEvery(c) => format!("edge every {c}"),
            Strategy::Threshold(x) => format!("threshold {x}"),
            Strategy::Pattern(p) => format!("pattern period {}", p.len()),
            s => s.family().to_string(),
        }
    }

    /// The greedy candidates. The honest stamp comes first, so ties (common under a
    /// rise cap, where several stamps give the capped value) keep the honest choice.
    fn candidates(b: &Branch, now: f64) -> [u64; 5] {
        let (lo, hi) = (b.min_timestamp(), now as u64 + FTL);
        let prev = b.tip_time();
        [b.honest_stamp(now), lo, prev + 1, hi, prev + 6 * TARGET].map(|t| t.clamp(lo, hi))
    }

    /// The stamp of block `k` (difficulty `d`) found at real time `now`.
    pub fn stamp(
        &self,
        k: usize,
        b: &mut Branch,
        now: f64,
        d: u64,
        rule: &dyn DifficultyRule,
    ) -> u64 {
        let (lo, hi) = (b.min_timestamp(), now as u64 + FTL);
        let prev = b.tip_time();
        let t = match self {
            Strategy::Honest => b.honest_stamp(now),
            Strategy::AllFtl => hi,
            Strategy::AllMtp => lo,
            Strategy::Cycle { b: low_n, c, low } => {
                if k % c < *low_n {
                    match low {
                        Low::Mtp => lo,
                        Low::PrevPlusOne => prev + 1,
                    }
                } else {
                    hi
                }
            }
            Strategy::EdgeEvery(c) => {
                if k.is_multiple_of(*c) {
                    hi
                } else {
                    b.honest_stamp(now)
                }
            }
            Strategy::Threshold(x) => {
                if hi.saturating_sub(prev) < *x {
                    lo
                } else {
                    hi.min(prev + 6 * TARGET)
                }
            }
            Strategy::Greedy => *Self::candidates(b, now)
                .iter()
                .min_by_key(|&&t| b.next_if(t, d, rule))
                .expect("five candidates"),
            Strategy::Greedy2 => {
                let mut best = (u128::MAX, lo);
                for t1 in Self::candidates(b, now) {
                    let d1 = b.next_if(t1, d, rule);
                    b.push_raw(t1, d);
                    let now2 = now + d1 as f64 / RATE;
                    let d2 = Self::candidates(b, now2)
                        .iter()
                        .map(|&t2| b.next_if(t2, d1, rule))
                        .min()
                        .expect("five candidates");
                    b.pop();
                    let cost = d1 as u128 + d2 as u128;
                    if cost < best.0 {
                        best = (cost, t1);
                    }
                }
                best.1
            }
            Strategy::Pattern(p) => match p[k % p.len()] {
                None => lo,
                Some(a) => prev + a,
            },
        };
        t.clamp(lo, hi)
    }
}

/// Total solve time of `blocks` blocks mined by a 100% miner using `strategy`,
/// after a 200-block honest warm-up. The solve-time draws depend only on `seed`
/// and the block index, so strategies are compared on common random numbers.
pub fn lowering_run(
    rule: &dyn DifficultyRule,
    strategy: &Strategy,
    blocks: usize,
    seed: u64,
) -> f64 {
    let mut rng = Rng::new(seed);
    let mut b = Branch::steady(121, DEQ);
    let mut now = b.tip_time() as f64;
    for _ in 0..200 {
        let d = b.required(rule);
        now += rng.exp() * d as f64 / RATE;
        b.push(b.honest_stamp(now), d, now);
    }
    let mut total = 0.0;
    for k in 0..blocks {
        let d = b.required(rule);
        let dt = rng.exp() * d as f64 / RATE;
        now += dt;
        total += dt;
        let t = strategy.stamp(k, &mut b, now, d, rule);
        b.push(t, d, now);
    }
    total
}

/// The fixed strategy families (everything except the random patterns).
pub fn fixed_strategies() -> Vec<Strategy> {
    let mut v = vec![
        Strategy::AllFtl,
        Strategy::AllMtp,
        Strategy::Greedy,
        Strategy::Greedy2,
    ];
    for c in [2usize, 3, 4, 6, 10, 20, 30, 60, 120] {
        let mut bs = vec![1, c / 2, c - 1];
        bs.dedup();
        for b in bs {
            for low in [Low::Mtp, Low::PrevPlusOne] {
                v.push(Strategy::Cycle { b, c, low });
            }
        }
    }
    for c in [2usize, 3, 5, 10, 20, 30, 60] {
        v.push(Strategy::EdgeEvery(c));
    }
    for x in [1u64, 60, 120, 240, 360, 480, 720, 1_000] {
        v.push(Strategy::Threshold(x));
    }
    v
}

/// `n` random periodic patterns (dossier 03's generator).
pub fn random_patterns(n: usize, rng: &mut Rng) -> Vec<Strategy> {
    const PERIODS: [usize; 13] = [2, 3, 4, 5, 6, 10, 12, 20, 30, 60, 61, 90, 120];
    const JUMPS: [u64; 6] = [1, 30, 120, 240, 480, 720];
    (0..n)
        .map(|_| {
            let p = PERIODS[rng.below(PERIODS.len() as u64) as usize];
            let pattern = (0..p)
                .map(|_| {
                    if rng.unit() < rng.unit() {
                        None
                    } else {
                        Some(JUMPS[rng.below(JUMPS.len() as u64) as usize])
                    }
                })
                .collect();
            Strategy::Pattern(pattern)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Lwma;

    const LWMA60: Lwma = Lwma { window: 60 };

    #[test]
    fn deterministic_steps_match_dossier_03() {
        // Dossier 03 (independent Python port): 10x jump -> 91 blocks to 90%.
        let f = step(&LWMA60, 10.0, None, 2_000);
        assert!((85..=97).contains(&f.blocks.unwrap()), "{f:?}");
    }

    #[test]
    fn genesis_gap_dips_to_one_sixth() {
        let g = genesis_gap(&LWMA60, DEQ, 7_200, None, 2_000);
        assert!((0.16..0.18).contains(&g.min_ratio), "{g:?}");
        assert!(g.recovered_at.is_some());
    }

    #[test]
    fn strategies_stay_valid() {
        // Branch::push panics on any invalid stamp.
        let mut rng = Rng::new(1);
        let mut all = fixed_strategies();
        all.extend(random_patterns(5, &mut rng));
        for s in &all {
            lowering_run(&LWMA60, s, 150, 9);
        }
    }
}
