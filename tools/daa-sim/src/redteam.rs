//! Red-team study (RT-DAA, phase 2) of the rule chosen by the W0-03b selection study:
//! LWMA-1 with N = 75 and the counted clock `this = max(ts, prev + max(1, T/2))`
//! (docs/evidence/daa-sim-2026-09-27/selection.md; the results of this module are in
//! docs/evidence/daa-sim-2026-09-27/redteam.md).
//!
//! The selection study measured the rule against fixed attacker families. This module
//! searches for new attacks:
//!
//! - an independent checked-arithmetic port of the pseudocode ([`reference_next`]);
//! - stamp policies that see the counted clock ([`Anchor::Clock`]) and the window, and
//!   search over them: hill-climbing over periodic policies (periods aligned with the
//!   window) and over state-dependent table policies, and a rollout (one-step policy
//!   improvement) controller;
//! - state-dependent and window-timed race policies (Bahack) at q up to 0.45, and the
//!   difficulty the chain inherits after a successful race;
//! - selfish mining with work-based fork choice, combined with stamp policies;
//! - hoppers with relative thresholds, fixed durations and forward-stamped exits;
//! - low-difficulty, large-step and genesis-era regimes.
//!
//! Everything here is evidence, not consensus.

use crate::family::recommended;
use crate::rng::{derive, Rng};
use crate::rules::{DifficultyRule, Lwma};
use crate::scenarios::{genesis_fork_trial, startup, step, ForkOutcome, Stamping};
use crate::sim::{par_map, Branch, DEQ, FTL, RATE, TARGET};
use std::fmt::Write;

// --------------------------------------------------------------------------------
// The rule under attack, written again from the pseudocode.

/// The selection study's pseudocode, written independently of
/// [`crate::family::GenLwma`], with checked `u128` arithmetic: an overflow or
/// underflow panics instead of wrapping. `initial` is returned for a window of one
/// block (genesis only).
pub fn reference_next(
    timestamps: &[u64],
    cumulative: &[u128],
    target: u64,
    window: usize,
    initial: u64,
) -> u64 {
    assert_eq!(timestamps.len(), cumulative.len());
    let take = timestamps.len().min(window + 1);
    if take <= 1 {
        return initial;
    }
    let ts = &timestamps[timestamps.len() - take..];
    let cd = &cumulative[cumulative.len() - take..];
    let n = take as u128 - 1;
    let t = target as u128;
    let step = (t / 2).max(1);
    let cap = t.checked_mul(6).expect("6T");
    let mut prev = ts[0] as u128;
    let (mut weighted, mut sum_d) = (0u128, 0u128);
    for i in 1..take {
        let this = (ts[i] as u128).max(prev.checked_add(step).expect("prev + step"));
        let st = (this - prev).min(cap);
        prev = this;
        weighted = weighted
            .checked_add((i as u128).checked_mul(st).expect("i * st"))
            .expect("weighted");
        sum_d = sum_d
            .checked_add(cd[i].checked_sub(cd[i - 1]).expect("cumulative rises"))
            .expect("sum_d");
    }
    let floor = n
        .checked_mul(n)
        .and_then(|x| x.checked_mul(t))
        .expect("floor")
        / 20;
    let weighted = weighted.max(floor).max(1);
    let num = sum_d
        .checked_mul(t)
        .and_then(|x| x.checked_mul(n + 1))
        .expect("numerator");
    (num / (2 * weighted)).clamp(1, u64::MAX as u128) as u64
}

/// [`reference_next`] as a rule (window 75; `initial` is the anchor's difficulty, as
/// for [`Lwma`]).
#[derive(Clone, Copy, Debug)]
pub struct Reference;

impl DifficultyRule for Reference {
    fn name(&self) -> String {
        "reference port of the selection pseudocode".into()
    }
    fn next(&self, ts: &[u64], cd: &[u128], target: u64) -> u64 {
        let initial = cd[0].min(u64::MAX as u128) as u64;
        reference_next(ts, cd, target, 75, initial)
    }
}

/// Candidate fix (RT-DAA): the rule under attack, but the counted clock starts `warm`
/// blocks before the window instead of at the window's first stamp. The window's
/// anchor becomes `c_0 = max(ts[w0], ts[w0-1] + step, ..., ts[w0-warm] + warm*step)`,
/// so one low stamp at the start of the window no longer lowers the anchor. `warm = 0`
/// is the rule under attack. The rise bound is unchanged (every counted solve time is
/// still at least `step`).
#[derive(Clone, Copy, Debug)]
pub struct Anchored {
    pub window: usize,
    pub warm: usize,
}

impl Anchored {
    pub fn step(target: u64) -> u128 {
        (target as u128 / 2).max(1)
    }
}

impl DifficultyRule for Anchored {
    fn name(&self) -> String {
        format!(
            "LWMA-{} step T/2, clock warmed over {} blocks",
            self.window, self.warm
        )
    }
    fn next(&self, ts: &[u64], cd: &[u128], target: u64) -> u64 {
        let len = ts.len();
        let take = len.min(self.window + 1);
        if take <= 1 {
            return cd[0].min(u64::MAX as u128) as u64;
        }
        let w0 = len - take;
        let n = take as u128 - 1;
        let t = target as u128;
        let step = Self::step(target);
        let mut prev = ts[w0.saturating_sub(self.warm)] as u128;
        for &x in &ts[w0.saturating_sub(self.warm) + 1..=w0] {
            prev = (x as u128).max(prev + step);
        }
        let (mut weighted, mut sum_d) = (0u128, 0u128);
        for i in w0 + 1..len {
            let this = (ts[i] as u128).max(prev + step);
            weighted += (i - w0) as u128 * (this - prev).min(6 * t);
            prev = this;
            sum_d += cd[i] - cd[i - 1];
        }
        let weighted = weighted.max(n * n * t / 20).max(1);
        (sum_d * t * (n + 1) / (2 * weighted)).clamp(1, u64::MAX as u128) as u64
    }
}

// --------------------------------------------------------------------------------
// Subjects: the rule under attack and the current consensus rule as a reference.

/// A rule with the parameters of its counted clock (which the stamp policies see).
pub struct Subject {
    pub name: &'static str,
    pub rule: Box<dyn DifficultyRule>,
    pub window: usize,
    pub step: u64,
    /// Blocks before the window over which the counted clock is warmed up.
    pub warm: usize,
}

impl Subject {
    pub fn recommended() -> Self {
        Self {
            name: "LWMA-75 step T/2 (under attack)",
            rule: Box::new(recommended()),
            window: 75,
            step: TARGET / 2,
            warm: 0,
        }
    }
    /// The candidate fix [`Anchored`] with `warm` blocks.
    pub fn anchored(name: &'static str, warm: usize) -> Self {
        Self {
            name,
            rule: Box::new(Anchored { window: 75, warm }),
            window: 75,
            step: TARGET / 2,
            warm,
        }
    }
    pub fn current() -> Self {
        Self {
            name: "LWMA-60 step 1 (current consensus)",
            rule: Box::new(Lwma { window: 60 }),
            window: 60,
            step: 1,
            warm: 0,
        }
    }
    pub fn required(&self, b: &Branch) -> u64 {
        b.required(self.rule.as_ref())
    }
    /// The counted clock that a new block's solve time will be measured from in the
    /// next child's window (the window then starts at `ts[len - window]`).
    pub fn clock(&self, b: &Branch) -> u64 {
        counted_clock(&b.ts, self.window + self.warm, self.step)
    }
    /// Mean difficulty of the last `window` blocks.
    pub fn window_avg(&self, b: &Branch) -> f64 {
        let len = b.cd.len();
        let n = self.window.min(len - 1).max(1);
        (b.cd[len - 1] - b.cd[len - 1 - n]) as f64 / n as f64
    }
}

/// The counted clock over the last `window` stamps of `ts`.
pub fn counted_clock(ts: &[u64], window: usize, step: u64) -> u64 {
    let w = &ts[ts.len().saturating_sub(window)..];
    let mut prev = w[0];
    for &t in &w[1..] {
        prev = t.max(prev + step);
    }
    prev
}

pub(crate) fn held_back(timestamp: u64, now: f64) -> Option<f64> {
    (timestamp > now as u64 + FTL).then(|| (timestamp - FTL) as f64)
}

// --------------------------------------------------------------------------------
// Symbolic stamps and policies.

/// What a stamp is measured from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Anchor {
    /// The miner's clock.
    Now,
    /// The previous block's stamp.
    Prev,
    /// The counted clock of the next child's window ([`Subject::clock`]).
    Clock,
    /// The median time past (so `Mtp + 1` is the lowest valid stamp).
    Mtp,
}

/// A stamp `anchor + off`, clamped into the valid range `[MTP + 1, now + FTL]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Action {
    pub anchor: Anchor,
    pub off: i64,
}

impl Action {
    pub const fn new(anchor: Anchor, off: i64) -> Self {
        Self { anchor, off }
    }
    pub fn resolve(self, b: &Branch, now: f64, s: &Subject) -> u64 {
        let (lo, hi) = (b.min_timestamp(), now as u64 + FTL);
        let base = match self.anchor {
            Anchor::Now => now as u64,
            Anchor::Prev => b.tip_time(),
            Anchor::Clock => s.clock(b),
            Anchor::Mtp => b.mtp(),
        } as i64;
        ((base + self.off).max(0) as u64).clamp(lo, hi)
    }
    pub fn label(&self) -> String {
        let a = match self.anchor {
            Anchor::Now => "now",
            Anchor::Prev => "prev",
            Anchor::Clock => "clk",
            Anchor::Mtp => "mtp",
        };
        format!("{a}{:+}", self.off)
    }
}

/// The honest stamp.
pub const HONEST: Action = Action::new(Anchor::Now, 0);
/// The lowest valid stamp.
pub const LOW: Action = Action::new(Anchor::Mtp, 1);
/// The FTL edge.
pub const EDGE: Action = Action::new(Anchor::Now, FTL as i64);

/// The candidate stamps of the rollout controller (honest first: ties keep it).
pub const CANDIDATES: [Action; 14] = [
    HONEST,
    LOW,
    EDGE,
    Action::new(Anchor::Clock, 60),
    Action::new(Anchor::Clock, 120),
    Action::new(Anchor::Clock, 240),
    Action::new(Anchor::Clock, 360),
    Action::new(Anchor::Clock, 720),
    Action::new(Anchor::Prev, 360),
    Action::new(Anchor::Prev, 720),
    Action::new(Anchor::Now, -600),
    Action::new(Anchor::Now, -1_200),
    Action::new(Anchor::Now, -1_800),
    Action::new(Anchor::Prev, 1),
];

/// Number of counted-clock bins of a [`Policy::Table`].
pub const E_BINS: usize = 20;
/// Number of difficulty bins of a [`Policy::Table`].
pub const R_BINS: usize = 5;

/// A timestamp policy of the attacker.
#[derive(Clone, Debug, PartialEq)]
pub enum Policy {
    Honest,
    /// The same stamp for every block.
    Fixed(Action),
    /// `p[k % p.len()]` for the attacker's `k`-th block.
    Periodic(Vec<Action>),
    /// State-dependent: an action per (counted-clock offset bin, difficulty bin). The
    /// offset `e = clock - now` is binned in 120 s steps from -2040 s to +360 s; the
    /// difficulty relative to the window mean in the bins <0.9, <0.97, <1.03, <1.1, >=1.1.
    Table(Vec<Action>),
    /// Rollout (one-step policy improvement over `base`): each block takes the
    /// candidate stamp that minimises the expected time of the next `horizon` blocks
    /// when `base` stamps them (expected solve times).
    Rollout {
        horizon: usize,
        base: Box<Policy>,
    },
}

impl Policy {
    pub fn label(&self) -> String {
        match self {
            Policy::Honest => "honest".into(),
            Policy::Fixed(a) => format!("always {}", a.label()),
            Policy::Periodic(p) => format!(
                "periodic {}: [{}]",
                p.len(),
                p.iter().map(|a| a.label()).collect::<Vec<_>>().join(" ")
            ),
            Policy::Table(_) => "table policy".into(),
            Policy::Rollout { horizon, base } => {
                format!("rollout H={horizon} over {}", base.short())
            }
        }
    }

    pub fn short(&self) -> String {
        match self {
            Policy::Periodic(p) => format!("periodic {}", p.len()),
            Policy::Table(_) => "table".into(),
            p => p.label(),
        }
    }

    pub fn table_index(b: &Branch, now: f64, d: u64, s: &Subject) -> usize {
        let e = s.clock(b) as i64 - now as i64;
        let eb = ((e + 2_040).max(0) / 120).min(E_BINS as i64 - 1) as usize;
        let r = d as f64 / s.window_avg(b);
        let rb = [0.9, 0.97, 1.03, 1.1].iter().filter(|&&x| r >= x).count();
        eb * R_BINS + rb
    }

    /// The stamp of the attacker's `k`-th block (difficulty `d`), found at `now`.
    pub fn stamp(&self, k: usize, b: &mut Branch, now: f64, d: u64, s: &Subject) -> u64 {
        match self {
            Policy::Honest => b.honest_stamp(now),
            Policy::Fixed(a) => a.resolve(b, now, s),
            Policy::Periodic(p) => p[k % p.len()].resolve(b, now, s),
            Policy::Table(t) => t[Self::table_index(b, now, d, s)].resolve(b, now, s),
            Policy::Rollout { horizon, base } => {
                let mut tried: Vec<u64> = Vec::with_capacity(CANDIDATES.len());
                let mut best = (f64::MAX, b.honest_stamp(now));
                for a in CANDIDATES {
                    let t = a.resolve(b, now, s);
                    if tried.contains(&t) {
                        continue;
                    }
                    tried.push(t);
                    b.push_raw(t, d);
                    let cost = rollout_cost(b, now, k + 1, *horizon, base, s);
                    b.pop();
                    if cost < best.0 - 1e-9 {
                        best = (cost, t);
                    }
                }
                best.1
            }
        }
    }
}

/// Expected time of the next `horizon` blocks under `base` (expected solve times).
fn rollout_cost(
    b: &mut Branch,
    mut now: f64,
    k0: usize,
    horizon: usize,
    base: &Policy,
    s: &Subject,
) -> f64 {
    let mut cost = 0.0;
    for j in 0..horizon {
        let d = s.required(b);
        let mut dt = d as f64 / RATE;
        if let Some(later) = held_back(b.min_timestamp(), now + dt) {
            dt = later - now;
        }
        now += dt;
        cost += dt;
        let t = base.stamp(k0 + j, b, now, d, s);
        b.push_raw(t, d);
    }
    for _ in 0..horizon {
        b.pop();
    }
    cost
}

// --------------------------------------------------------------------------------
// Emission: a miner that stamps a fraction `alpha` of all blocks (1.0 = 100%).

/// Deterministic emission gain (expected solve times) of a 100% miner using `p`, over
/// `blocks` blocks after `burn` blocks: blocks/h over the target rate, minus 1. Honest
/// stamping gives exactly 0 here.
pub fn det_gain(s: &Subject, p: &Policy, burn: usize, blocks: usize) -> f64 {
    let mut b = Branch::steady(121, DEQ);
    let mut now = b.tip_time() as f64;
    let mut total = 0.0;
    for k in 0..burn + blocks {
        let d = s.required(&b);
        let mut dt = d as f64 / RATE;
        if let Some(later) = held_back(b.min_timestamp(), now + dt) {
            dt = later - now;
        }
        now += dt;
        if k >= burn {
            total += dt;
        }
        let t = p.stamp(k, &mut b, now, d, s);
        b.push(t, d, now);
    }
    blocks as f64 * TARGET as f64 / total - 1.0
}

/// Total solve time of `blocks` blocks after a 200-block honest warm-up (the model
/// of `scenarios::lowering_run`, which it equals for `alpha = 1`). Each block is the
/// attacker's with probability `alpha` (a separate stream, so the solve-time draws
/// are common to all policies); the others are stamped honestly.
pub fn sto_time(s: &Subject, p: &Policy, blocks: usize, seed: u64, alpha: f64) -> f64 {
    sto_time_from(s, p, blocks, 0, seed, alpha)
}

/// [`sto_time`] counting only the blocks from index `skip` on (the attacker's
/// policy runs from block 0): the sustained part, without the one-shot gain of the
/// first blocks.
pub fn sto_time_from(
    s: &Subject,
    p: &Policy,
    blocks: usize,
    skip: usize,
    seed: u64,
    alpha: f64,
) -> f64 {
    let mut rng = Rng::new(seed);
    let mut own = Rng::new(seed ^ 0xA11C_E000_0000_0001);
    let mut b = Branch::steady(121, DEQ);
    let mut now = b.tip_time() as f64;
    for _ in 0..200 {
        let d = s.required(&b);
        now += rng.exp() * d as f64 / RATE;
        b.push(b.honest_stamp(now), d, now);
    }
    let mut total = 0.0;
    let mut k = 0;
    for i in 0..blocks {
        let d = s.required(&b);
        let mut dt = rng.exp() * d as f64 / RATE;
        if let Some(later) = held_back(b.min_timestamp(), now + dt) {
            dt = later - now;
        }
        now += dt;
        if i >= skip {
            total += dt;
        }
        let t = if alpha >= 1.0 || own.unit() < alpha {
            k += 1;
            p.stamp(k - 1, &mut b, now, d, s)
        } else {
            b.honest_stamp(now)
        };
        b.push(t, d, now);
    }
    total
}

/// Stochastic emission gain on common random numbers: blocks/h over honest stamping
/// on the same draws, minus 1.
pub fn sto_gain(s: &Subject, p: &Policy, blocks: usize, seed: u64, alpha: f64) -> f64 {
    sto_time(s, &Policy::Honest, blocks, seed, alpha) / sto_time(s, p, blocks, seed, alpha) - 1.0
}

/// Sustained stochastic gain: blocks `skip..blocks` only.
pub fn sto_gain_from(s: &Subject, p: &Policy, blocks: usize, skip: usize, seed: u64) -> f64 {
    sto_time_from(s, &Policy::Honest, blocks, skip, seed, 1.0)
        / sto_time_from(s, p, blocks, skip, seed, 1.0)
        - 1.0
}

/// A random action for the search.
pub fn random_action(rng: &mut Rng) -> Action {
    let anchor = [Anchor::Now, Anchor::Prev, Anchor::Clock, Anchor::Mtp][rng.below(4) as usize];
    let off = match anchor {
        Anchor::Now => rng.below(28) as i64 * 60 - 1_320,
        Anchor::Prev => rng.below(13) as i64 * 60,
        Anchor::Clock => rng.below(13) as i64 * 60,
        Anchor::Mtp => 1,
    };
    Action::new(
        anchor,
        off.max(if anchor == Anchor::Prev { 1 } else { off }),
    )
}

fn mutate(a: Action, rng: &mut Rng) -> Action {
    if rng.below(3) == 0 {
        return random_action(rng);
    }
    let d = [-240i64, -60, -1, 1, 60, 240][rng.below(6) as usize];
    let lim = match a.anchor {
        Anchor::Now => (-2_400, FTL as i64),
        Anchor::Prev | Anchor::Clock => (1, 6 * TARGET as i64 + 360),
        Anchor::Mtp => (1, 1),
    };
    Action::new(a.anchor, (a.off + d).clamp(lim.0, lim.1))
}

/// Structured starting points for the periodic search: compressed runs of `run`
/// blocks, catch-up blocks at the counted clock + 6T, then the FTL edge.
pub fn structured_periodic(period: usize, run: usize, catch: usize) -> Vec<Action> {
    (0..period)
        .map(|i| {
            if i < run {
                LOW
            } else if i < run + catch {
                Action::new(Anchor::Clock, 6 * TARGET as i64)
            } else {
                EDGE
            }
        })
        .collect()
}

/// Hill-climbing over a policy vector with the deterministic model. Returns the best
/// vector, its gain and the number of evaluations.
pub fn climb(
    s: &Subject,
    init: Vec<Action>,
    table: bool,
    iters: usize,
    burn: usize,
    blocks: usize,
    seed: u64,
) -> (Vec<Action>, f64, usize) {
    let wrap = |v: Vec<Action>| {
        if table {
            Policy::Table(v)
        } else {
            Policy::Periodic(v)
        }
    };
    let mut rng = Rng::new(seed);
    let mut best = init;
    let mut best_g = det_gain(s, &wrap(best.clone()), burn, blocks);
    let mut evals = 1;
    for _ in 0..iters {
        let mut cand = best.clone();
        let changes = 1 + rng.below(3) as usize;
        for _ in 0..changes {
            let i = rng.below(cand.len() as u64) as usize;
            cand[i] = mutate(cand[i], &mut rng);
        }
        if cand == best {
            continue;
        }
        let g = det_gain(s, &wrap(cand.clone()), burn, blocks);
        evals += 1;
        if g >= best_g {
            best = cand;
            best_g = g;
        }
    }
    (best, best_g, evals)
}

// --------------------------------------------------------------------------------
// The difficulty-raising race with state-dependent policies.

/// A private-branch stamping policy for the race (Bahack). The attacker sees both
/// branches, the clock and the race horizon.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RacePolicy {
    Honest,
    /// Always `MTP + 1`.
    Compressed,
    /// Always at the counted clock + step (counts the minimum, keeps stamps high).
    Aligned,
    /// Compress only while the private branch trails by more than `x` public blocks
    /// of work (variance only when behind).
    Behind(f64),
    /// Compress while the private difficulty is below `x` times the public one.
    DCap(f64),
    /// The first `j` private blocks honest, then compressed (window timing: the
    /// pre-fork blocks leave the private window at j = 75).
    AfterBlocks(usize),
    /// The first `j` private blocks at the FTL edge, then compressed.
    ForwardThen(usize),
    /// Compressed until the fraction `f` of the horizon has passed, then honest.
    EarlyOnly(f64),
    /// Compressed while behind by more than `x` blocks of work or after the fraction
    /// `f` of the horizon.
    BehindOrLate(f64, f64),
    /// Compressed until z confirmations, then honest while ahead and compressed while
    /// behind.
    ThenBehind(f64),
}

impl RacePolicy {
    pub fn label(&self) -> String {
        match self {
            RacePolicy::Honest => "honest".into(),
            RacePolicy::Compressed => "compressed".into(),
            RacePolicy::Aligned => "aligned (clock + step)".into(),
            RacePolicy::Behind(x) => format!("behind>{x}"),
            RacePolicy::DCap(x) => format!("D-cap {x}x"),
            RacePolicy::AfterBlocks(j) => format!("honest {j} then compressed"),
            RacePolicy::ForwardThen(j) => format!("FTL edge {j} then compressed"),
            RacePolicy::EarlyOnly(f) => format!("compressed until {f} of horizon"),
            RacePolicy::BehindOrLate(x, f) => format!("behind>{x} or after {f}"),
            RacePolicy::ThenBehind(x) => format!("compressed to z, then behind>{x}"),
        }
    }

    /// The adaptive policies searched.
    pub fn search() -> Vec<RacePolicy> {
        let mut v = vec![RacePolicy::Aligned];
        for x in [-3.0, 0.0, 2.0, 5.0, 10.0] {
            v.push(RacePolicy::Behind(x));
        }
        for x in [1.5, 2.0, 3.0, 5.0] {
            v.push(RacePolicy::DCap(x));
        }
        for j in [10, 38, 75, 76, 100] {
            v.push(RacePolicy::AfterBlocks(j));
        }
        for j in [5, 20, 75] {
            v.push(RacePolicy::ForwardThen(j));
        }
        for f in [0.3, 0.6] {
            v.push(RacePolicy::EarlyOnly(f));
        }
        for (x, f) in [(2.0, 0.5), (5.0, 0.3)] {
            v.push(RacePolicy::BehindOrLate(x, f));
        }
        for x in [0.0, 3.0] {
            v.push(RacePolicy::ThenBehind(x));
        }
        v
    }

    #[allow(clippy::too_many_arguments)]
    fn compress(
        &self,
        private: &Branch,
        public: &Branch,
        hd: u64,
        ad: u64,
        frac: f64,
        own: usize,
        conf: usize,
        z: usize,
    ) -> Option<bool> {
        let behind = (public.work() as f64 - private.work() as f64) / hd as f64;
        Some(match *self {
            RacePolicy::Honest => false,
            RacePolicy::Compressed => true,
            RacePolicy::Aligned => return None,
            RacePolicy::Behind(x) => behind > x,
            RacePolicy::DCap(x) => (ad as f64) < x * hd as f64,
            RacePolicy::AfterBlocks(j) => own >= j,
            RacePolicy::ForwardThen(_) => true,
            RacePolicy::EarlyOnly(f) => frac < f,
            RacePolicy::BehindOrLate(x, f) => behind > x || frac >= f,
            RacePolicy::ThenBehind(x) => conf < z || behind > x,
        })
    }
}

/// Outcome of one race.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct RaceOutcome {
    pub win: bool,
    /// On a win: the private branch's next required difficulty over `DEQ` (what the
    /// chain inherits after the reorganization).
    pub inherited: f64,
}

/// One race, as `adaptive::race_trial` (same model, horizon and win condition) with a
/// state-dependent policy.
pub fn race_trial(s: &Subject, q: f64, z: usize, p: RacePolicy, rng: &mut Rng) -> RaceOutcome {
    let base = Branch::steady(121, DEQ);
    let mut public = base.clone();
    let mut private = base;
    let mut now = public.tip_time() as f64;
    let t0 = now;
    let horizon = ((12 * z + 240) as u64 * TARGET) as f64;
    let t_end = now + horizon;
    let (h_rate, a_rate) = ((1.0 - q) * RATE, q * RATE);
    let mut hd = s.required(&public);
    let mut ad = s.required(&private);
    let mut h_next = now + rng.exp() * hd as f64 / h_rate;
    let mut a_next = now + rng.exp() * ad as f64 / a_rate;
    let mut conf = 0;
    let mut own = 0;
    while h_next.min(a_next) < t_end {
        if h_next <= a_next {
            let t = public.honest_stamp(h_next);
            if let Some(later) = held_back(t, h_next) {
                h_next = later;
                continue;
            }
            now = h_next;
            public.push(t, hd, now);
            conf += 1;
            hd = s.required(&public);
            h_next = now + rng.exp() * hd as f64 / h_rate;
        } else {
            let frac = (a_next - t0) / horizon;
            let t = match p {
                RacePolicy::ForwardThen(j) if own < j => {
                    (a_next as u64 + FTL).max(private.min_timestamp())
                }
                _ => match p.compress(&private, &public, hd, ad, frac, own, conf, z) {
                    None => (s.clock(&private) + s.step).max(private.min_timestamp()),
                    Some(true) => private.min_timestamp(),
                    Some(false) => private.honest_stamp(a_next),
                },
            };
            if let Some(later) = held_back(t, a_next) {
                a_next = later;
                continue;
            }
            now = a_next;
            private.push(t, ad, now);
            own += 1;
            ad = s.required(&private);
            a_next = now + rng.exp() * ad as f64 / a_rate;
        }
        if conf >= z && private.work() > public.work() {
            return RaceOutcome {
                win: true,
                inherited: ad as f64 / DEQ as f64,
            };
        }
    }
    RaceOutcome::default()
}

/// Hits over `trials` races, and the inherited difficulties of the wins.
pub fn race(
    s: &Subject,
    q: f64,
    z: usize,
    p: RacePolicy,
    trials: usize,
    seed: u64,
) -> (u64, Vec<f64>) {
    let mut rng = Rng::new(seed);
    let mut inh = Vec::new();
    for _ in 0..trials {
        let o = race_trial(s, q, z, p, &mut rng);
        if o.win {
            inh.push(o.inherited);
        }
    }
    (inh.len() as u64, inh)
}

// --------------------------------------------------------------------------------
// Selfish mining with work-based fork choice.

/// A branch with the miner of each block (`true` = attacker).
#[derive(Clone, Debug)]
struct Owned {
    b: Branch,
    mine: Vec<bool>,
}

impl Owned {
    fn push(&mut self, t: u64, d: u64, now: f64, mine: bool) {
        self.b.push(t, d, now);
        self.mine.push(mine);
    }
    /// Makes `self` equal to `src`, which shares the first `fork` blocks.
    fn adopt(&mut self, src: &Owned, fork: usize) {
        self.b.ts.truncate(fork);
        self.b.cd.truncate(fork);
        self.mine.truncate(fork);
        self.b.ts.extend_from_slice(&src.b.ts[fork..]);
        self.b.cd.extend_from_slice(&src.b.cd[fork..]);
        self.mine.extend_from_slice(&src.mine[fork..]);
    }
}

/// Result of a selfish-mining run.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Selfish {
    /// The attacker's share of main-chain blocks.
    pub share: f64,
    /// Main-chain blocks per hour over the target rate, minus 1.
    pub rate: f64,
}

/// Eyal-Sirer SM1 with share `alpha` and tie parameter `gamma`, generalised to
/// work-based fork choice: the attacker decides by block lead as in SM1, but every
/// publication resolves by cumulative work (equal work is a tie, split by `gamma`).
/// The attacker stamps its private blocks with `p`; honest miners stamp honestly.
pub fn selfish(
    s: &Subject,
    alpha: f64,
    gamma: f64,
    p: &Policy,
    blocks: usize,
    seed: u64,
) -> Selfish {
    let mut rng = Rng::new(seed);
    let base = Branch::steady(121, DEQ);
    let start_len = base.len();
    let mut honest = Owned {
        mine: vec![false; start_len],
        b: base,
    };
    let mut attack = honest.clone();
    let mut fork = start_len;
    let mut tie = false;
    let t0 = honest.b.tip_time() as f64;
    let mut now = t0;
    let mut k = 0;
    while honest.b.len() < start_len + blocks {
        let hd = s.required(&honest.b);
        let ad = s.required(&attack.b);
        let g = if tie { gamma } else { 0.0 };
        let ta = rng.exp() * ad as f64 / (alpha * RATE);
        let th = rng.exp() * hd as f64 / ((1.0 - alpha) * (1.0 - g) * RATE);
        let tg = if g > 0.0 {
            rng.exp() * ad as f64 / ((1.0 - alpha) * g * RATE)
        } else {
            f64::MAX
        };
        if ta <= th && ta <= tg {
            let found = now + ta;
            let mut t = p.stamp(k, &mut attack.b, found, ad, s);
            k += 1;
            if let Some(later) = held_back(t, found) {
                now = later;
                t = t.min(now as u64 + FTL);
            } else {
                now = found;
            }
            attack.push(t, ad, now, true);
            if tie {
                honest.adopt(&attack, fork);
                fork = honest.b.len();
                tie = false;
            }
        } else if tg < th {
            now += tg;
            let t = attack.b.honest_stamp(now);
            attack.push(t, ad, now, false);
            honest.adopt(&attack, fork);
            fork = honest.b.len();
            tie = false;
        } else {
            now += th;
            let t = honest.b.honest_stamp(now);
            honest.push(t, hd, now, false);
            if tie {
                attack.adopt(&honest, fork);
                fork = honest.b.len();
                tie = false;
                continue;
            }
            let lead = attack.b.len() as i64 - honest.b.len() as i64;
            if lead < 0 {
                attack.adopt(&honest, fork);
                fork = honest.b.len();
            } else if lead <= 1 {
                // Publish: resolve by work.
                let (wa, wh) = (attack.b.work(), honest.b.work());
                if wa > wh {
                    honest.adopt(&attack, fork);
                    fork = honest.b.len();
                } else if wa < wh {
                    attack.adopt(&honest, fork);
                    fork = honest.b.len();
                } else {
                    tie = true;
                }
            }
        }
    }
    // Final: the attacker publishes a branch with more work.
    let fin = if attack.b.work() > honest.b.work() {
        &attack
    } else {
        &honest
    };
    let n = fin.b.len() - start_len;
    let mine = fin.mine[start_len..].iter().filter(|&&m| m).count();
    let span = fin.b.tip_time() as f64 - t0;
    Selfish {
        share: mine as f64 / n as f64,
        rate: n as f64 * TARGET as f64 / span.max(1.0) - 1.0,
    }
}

// --------------------------------------------------------------------------------
// Hoppers.

/// When a hopper mines.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum HopMode {
    /// On while `D < on * DEQ`, off once `D > off * DEQ` (the selection study's hopper).
    Abs,
    /// The same thresholds relative to the window mean difficulty.
    Rel,
    /// On when `D < on * DEQ`, for exactly `m` blocks.
    Duration(usize),
}

/// How a hopper stamps its own blocks.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum HopStamp {
    Honest,
    /// At the FTL edge (lowers the difficulty while it mines; the dedicated miners
    /// repay after it leaves).
    Edge,
    /// Honest, but the last `j` blocks of a fixed-duration hop at the FTL edge.
    EdgeLast(usize),
    /// `x` seconds ahead of its clock (at most the FTL): what a hopper could gain under
    /// a smaller FTL.
    Ahead(u64),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Hop {
    pub big: f64,
    pub mode: HopMode,
    pub on: f64,
    pub off: f64,
    pub stamp: HopStamp,
}

impl Hop {
    pub fn label(&self) -> String {
        let m = match self.mode {
            HopMode::Abs => format!("abs on<{} off>{}", self.on, self.off),
            HopMode::Rel => format!("rel on<{} off>{}", self.on, self.off),
            HopMode::Duration(m) => format!("on<{} for {m}", self.on),
        };
        let st = match self.stamp {
            HopStamp::Honest => "honest".to_string(),
            HopStamp::Edge => "edge".to_string(),
            HopStamp::EdgeLast(j) => format!("edge last {j}"),
            HopStamp::Ahead(x) => format!("{x} s ahead"),
        };
        format!("{}x, {m}, {st}", self.big)
    }

    /// The configurations searched.
    pub fn grid() -> Vec<Hop> {
        let mut v = Vec::new();
        for big in [1.0, 3.0, 10.0, 30.0, 100.0] {
            for mode in [HopMode::Abs, HopMode::Rel] {
                for on in [0.8, 0.9, 1.0, 1.05, 1.1, 1.2] {
                    for gap in [0.05, 0.1, 0.2, 0.5, 1.0] {
                        for stamp in [HopStamp::Honest, HopStamp::Edge] {
                            v.push(Hop {
                                big,
                                mode,
                                on,
                                off: on + gap,
                                stamp,
                            });
                        }
                    }
                }
            }
            for on in [0.9, 1.0, 1.1] {
                for m in [5, 10, 20, 40, 75] {
                    for stamp in [HopStamp::Honest, HopStamp::Edge, HopStamp::EdgeLast(3)] {
                        v.push(Hop {
                            big,
                            mode: HopMode::Duration(m),
                            on,
                            off: 0.0,
                            stamp,
                        });
                    }
                }
            }
        }
        v
    }
}

/// A hopper run: `(share, fair share)` as in `adaptive::hopper` (expected shares; the
/// block owner is drawn from a separate stream only to choose its stamp).
pub fn hop_run(s: &Subject, h: &Hop, blocks: usize, seed: u64) -> (f64, f64) {
    let mut rng = Rng::new(seed);
    let mut own = Rng::new(seed ^ 0x0B0B_0000_0000_0001);
    let mut b = Branch::steady(121, DEQ);
    let mut now = b.tip_time() as f64;
    let mut on = false;
    let mut left = 0usize;
    let frac = h.big / (1.0 + h.big);
    let (mut hop_blocks, mut hop_hashes, mut hashes) = (0.0, 0.0, 0.0);
    for _ in 0..blocks {
        let d = s.required(&b);
        let x = match h.mode {
            HopMode::Rel => d as f64 / s.window_avg(&b),
            _ => d as f64 / DEQ as f64,
        };
        match h.mode {
            HopMode::Abs | HopMode::Rel => {
                if !on && x < h.on {
                    on = true;
                } else if on && x > h.off {
                    on = false;
                }
            }
            HopMode::Duration(m) => {
                if !on && x < h.on {
                    on = true;
                    left = m;
                }
            }
        }
        let rate = if on { 1.0 + h.big } else { 1.0 };
        let mut dt = rng.exp() * d as f64 / (rate * RATE);
        // Very fast blocks can push MTP + 1 past the FTL: held until the clock allows.
        if let Some(later) = held_back(b.min_timestamp(), now + dt) {
            dt = later - now;
        }
        let mine = on && own.unit() < frac;
        if on {
            hop_blocks += frac;
            hop_hashes += frac * d as f64;
        }
        hashes += d as f64;
        now += dt;
        let ahead = match h.stamp {
            HopStamp::Honest => None,
            HopStamp::Edge => Some(FTL),
            HopStamp::EdgeLast(j) => (left <= j).then_some(FTL),
            HopStamp::Ahead(x) => Some(x.min(FTL)),
        };
        let t = if let (true, Some(x)) = (mine, ahead) {
            (now as u64 + x).max(b.min_timestamp())
        } else {
            b.honest_stamp(now)
        };
        b.push(t, d, now);
        if let HopMode::Duration(_) = h.mode {
            if on {
                left -= 1;
                if left == 0 {
                    on = false;
                }
            }
        }
    }
    (hop_blocks / blocks as f64, hop_hashes / hashes)
}

// --------------------------------------------------------------------------------
// Low-difficulty regimes.

/// Honest mining at an equilibrium difficulty `deq` (the hash rate is `deq / T`),
/// from a steady history at `max(1, round(deq))`.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct LowD {
    /// Mean solve time over `T`.
    pub mean_st: f64,
    /// Mean difficulty over `deq`.
    pub mean_d: f64,
    /// Fraction of blocks at difficulty 1.
    pub at_one: f64,
    /// Coefficient of variation of the difficulty.
    pub cv: f64,
    pub min_d: u64,
    pub max_d: u64,
}

pub fn low_d(s: &Subject, deq: f64, blocks: usize, seed: u64) -> LowD {
    let mut rng = Rng::new(seed);
    let rate = deq / TARGET as f64;
    let mut b = Branch::steady(121, (deq.round() as u64).max(1));
    let mut now = b.tip_time() as f64;
    let (mut sum_st, mut sum_d, mut sum_d2, mut ones) = (0.0, 0.0, 0.0, 0usize);
    let (mut min_d, mut max_d) = (u64::MAX, 0);
    let burn = 1_000;
    for k in 0..burn + blocks {
        let d = s.required(&b);
        let mut dt = rng.exp() * d as f64 / rate;
        if let Some(later) = held_back(b.min_timestamp(), now + dt) {
            dt = later - now;
        }
        now += dt;
        if k >= burn {
            sum_st += dt;
            sum_d += d as f64;
            sum_d2 += (d as f64).powi(2);
            ones += usize::from(d == 1);
            min_d = min_d.min(d);
            max_d = max_d.max(d);
        }
        b.push(b.honest_stamp(now), d, now);
    }
    let n = blocks as f64;
    let mean = sum_d / n;
    LowD {
        mean_st: sum_st / n / TARGET as f64,
        mean_d: mean / deq,
        at_one: ones as f64 / n,
        cv: ((sum_d2 / n - mean * mean).max(0.0)).sqrt() / mean,
        min_d,
        max_d,
    }
}

/// A 100% miner's blocks arriving far faster than the step: the chain at difficulty
/// 1, hash rate `deq / T` (so the ramp to `deq` is the compounding bound). Returns
/// the blocks until the difficulty is within 10% of `deq` and the elapsed hours
/// (expected solve times).
pub fn ramp_from_one(s: &Subject, deq: f64, max_blocks: usize) -> (Option<usize>, f64) {
    let rate = deq / TARGET as f64;
    let mut b = Branch::steady(121, 1);
    let start = b.tip_time() as f64;
    let mut now = start;
    for k in 1..=max_blocks {
        let d = s.required(&b);
        if (d as f64 / deq - 1.0).abs() <= 0.1 {
            return (Some(k), (now - start) / 3600.0);
        }
        let mut dt = d as f64 / rate;
        if let Some(later) = held_back(b.min_timestamp(), now + dt) {
            dt = later - now;
        }
        now += dt;
        b.push(b.honest_stamp(now), d, now);
    }
    (None, (now - start) / 3600.0)
}

// --------------------------------------------------------------------------------
// The study.

#[derive(Clone, Debug)]
pub struct RtConfig {
    pub seed: u64,
    pub threads: usize,
    /// Periodic search: periods, restarts per period, hill-climbing steps.
    pub periods: Vec<usize>,
    pub restarts: usize,
    pub iters: usize,
    /// Table search: restarts and steps.
    pub table_restarts: usize,
    pub table_iters: usize,
    /// Deterministic evaluation: burn-in and measured blocks.
    pub det_burn: usize,
    pub det_blocks: usize,
    /// Stochastic confirmation: fresh seeds and blocks.
    pub confirm_seeds: usize,
    pub confirm_blocks: usize,
    /// Rollout controllers: seeds and blocks (stochastic).
    pub rollout_seeds: usize,
    pub rollout_blocks: usize,
    /// The sustained gain counts blocks from this index on.
    pub rollout_skip: usize,
    pub qs: Vec<f64>,
    pub z: usize,
    pub screen_trials: usize,
    pub confirm_trials: usize,
    pub sm_blocks: usize,
    pub sm_seeds: usize,
    pub hop_blocks: usize,
    pub hop_confirm_blocks: usize,
    pub hop_confirm_seeds: usize,
    pub low_blocks: usize,
    pub fork_trials: usize,
}

impl RtConfig {
    pub fn full(seed: u64, threads: usize) -> Self {
        Self {
            seed,
            threads,
            periods: vec![1, 2, 3, 4, 5, 6, 10, 12, 15, 25, 38, 75, 76, 150],
            restarts: 6,
            iters: 600,
            table_restarts: 8,
            table_iters: 3_000,
            det_burn: 450,
            det_blocks: 1_500,
            confirm_seeds: 3,
            confirm_blocks: 10_000,
            rollout_seeds: 6,
            rollout_blocks: 3_000,
            rollout_skip: 1_000,
            qs: vec![0.3, 0.35, 0.4, 0.45],
            z: 100,
            screen_trials: 1_000,
            confirm_trials: 4_000,
            sm_blocks: 20_000,
            sm_seeds: 3,
            hop_blocks: 10_000,
            hop_confirm_blocks: 20_000,
            hop_confirm_seeds: 3,
            low_blocks: 20_000,
            fork_trials: 300,
        }
    }

    pub fn quick(seed: u64, threads: usize) -> Self {
        Self {
            periods: vec![1, 5, 38, 75],
            restarts: 2,
            iters: 60,
            table_restarts: 2,
            table_iters: 100,
            det_burn: 300,
            det_blocks: 600,
            confirm_seeds: 1,
            confirm_blocks: 2_000,
            rollout_seeds: 1,
            rollout_blocks: 600,
            rollout_skip: 200,
            screen_trials: 100,
            confirm_trials: 200,
            sm_blocks: 3_000,
            sm_seeds: 1,
            hop_blocks: 2_000,
            hop_confirm_blocks: 4_000,
            hop_confirm_seeds: 1,
            low_blocks: 3_000,
            fork_trials: 30,
            ..Self::full(seed, threads)
        }
    }
}

const TAG_CLIMB: u64 = 201;
const TAG_CONFIRM: u64 = 202;
const TAG_ROLL: u64 = 203;
const TAG_RSCREEN: u64 = 204;
const TAG_RCONFIRM: u64 = 205;
const TAG_SM: u64 = 206;
const TAG_HOP: u64 = 207;
const TAG_HOPC: u64 = 208;
const TAG_LOW: u64 = 209;
const TAG_FORK: u64 = 210;
const CHUNK: usize = 50;

fn qt(q: f64) -> u64 {
    (q * 1_000.0).round() as u64
}

/// One searched emission policy with its deterministic gain (search) and its
/// stochastic gains on fresh seeds (confirmation).
#[derive(Clone, Debug)]
pub struct Found {
    pub family: String,
    pub policy: Policy,
    pub det: f64,
    pub evals: usize,
    /// Per fresh seed, alpha = 1.
    pub sto: Vec<f64>,
}

impl Found {
    pub fn sto_mean(&self) -> f64 {
        self.sto.iter().sum::<f64>() / self.sto.len().max(1) as f64
    }
}

#[derive(Clone, Debug)]
pub struct RaceRow {
    pub q: f64,
    pub screen: Vec<(RacePolicy, u64)>,
    pub best: RacePolicy,
    pub honest: u64,
    pub compressed: u64,
    pub best_hits: u64,
    pub trials: u64,
    /// Inherited difficulty over DEQ on compressed wins (confirmation): median, max.
    pub inherited: (f64, f64),
}

impl RaceRow {
    pub fn p(&self, h: u64) -> f64 {
        h as f64 / self.trials as f64
    }
    pub fn excess(&self) -> f64 {
        self.p(self.compressed.max(self.best_hits)) - self.p(self.honest)
    }
}

#[derive(Clone, Debug)]
pub struct SubjectResult {
    pub name: String,
    pub emission: Vec<Found>,
    /// (policy, share of blocks the miner stamps, mean gain).
    pub large_miner: Vec<(String, f64, f64)>,
    /// Rollout controllers: label, per-seed (total gain, sustained gain).
    pub rollout: Vec<(String, Vec<(f64, f64)>)>,
    pub race: Vec<RaceRow>,
    pub selfish: Vec<(f64, f64, String, Selfish)>,
    pub hop_top: Vec<(Hop, f64, f64)>,
    pub hop_threshold_ref: f64,
    /// The most negative screening excess (a hopper that loses; not an attack).
    pub hop_min: f64,
    pub hop_evals: usize,
    pub low: Vec<(f64, LowD)>,
    pub ramps: Vec<(String, Option<usize>, f64, f64)>,
    pub fork: Vec<(f64, &'static str, u64, u64)>,
}

fn median(mut v: Vec<f64>) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
    v[v.len() / 2]
}

/// Runs the whole study for one subject. `progress` gets one line per phase.
pub fn run_subject(cfg: &RtConfig, s: &Subject, progress: &dyn Fn(&str)) -> SubjectResult {
    let seed = cfg.seed;
    let th = cfg.threads;

    // ---- Emission search (deterministic hill-climbing; seeds are rule-independent).
    progress("emission: periodic search");
    let mut jobs: Vec<(usize, usize)> = Vec::new();
    for &p in &cfg.periods {
        for r in 0..cfg.restarts {
            jobs.push((p, r));
        }
    }
    let periodic: Vec<(Vec<Action>, f64, usize)> = par_map(&jobs, th, |&(p, r)| {
        let mut rng = Rng::new(derive(seed, &[TAG_CLIMB, p as u64, r as u64]));
        let init = match r {
            0 => vec![HONEST; p],
            1 => structured_periodic(p, (p / 2).max(1), (p / 8).max(1).min(p - p / 2)),
            2 => structured_periodic(p, (p * 9 / 10).max(1), p - (p * 9 / 10).max(1)),
            _ => (0..p).map(|_| random_action(&mut rng)).collect(),
        };
        climb(
            s,
            init,
            false,
            cfg.iters,
            cfg.det_burn,
            cfg.det_blocks,
            derive(seed, &[TAG_CLIMB, p as u64, r as u64, 1]),
        )
    });
    progress("emission: table search");
    let tjobs: Vec<usize> = (0..cfg.table_restarts).collect();
    let tables: Vec<(Vec<Action>, f64, usize)> = par_map(&tjobs, th, |&r| {
        let mut rng = Rng::new(derive(seed, &[TAG_CLIMB, 9_999, r as u64]));
        let init = match r {
            0 => vec![HONEST; E_BINS * R_BINS],
            1 => vec![EDGE; E_BINS * R_BINS],
            _ => (0..E_BINS * R_BINS)
                .map(|_| random_action(&mut rng))
                .collect(),
        };
        climb(
            s,
            init,
            true,
            cfg.table_iters,
            cfg.det_burn,
            cfg.det_blocks,
            derive(seed, &[TAG_CLIMB, 9_999, r as u64, 1]),
        )
    });
    // Keep the best periodic policy per period and the best table; confirm them.
    let mut found: Vec<Found> = Vec::new();
    for &p in &cfg.periods {
        let best = jobs
            .iter()
            .zip(&periodic)
            .filter(|((pp, _), _)| *pp == p)
            .max_by(|a, b| a.1 .1.partial_cmp(&b.1 .1).expect("finite"))
            .expect("restarts");
        let evals = jobs
            .iter()
            .zip(&periodic)
            .filter(|((pp, _), _)| *pp == p)
            .map(|(_, r)| r.2)
            .sum();
        found.push(Found {
            family: format!("periodic, period {p}"),
            policy: Policy::Periodic(best.1 .0.clone()),
            det: best.1 .1,
            evals,
            sto: vec![],
        });
    }
    let bt = tables
        .iter()
        .max_by(|a, b| a.1.partial_cmp(&b.1).expect("finite"))
        .expect("restarts");
    found.push(Found {
        family: "state table (clock offset x D/avg)".into(),
        policy: Policy::Table(bt.0.clone()),
        det: bt.1,
        evals: tables.iter().map(|t| t.2).sum(),
        sto: vec![],
    });
    for f in [
        Policy::Fixed(EDGE),
        Policy::Periodic(structured_periodic(76, 38, 4)),
        Policy::Periodic(structured_periodic(75, 10, 1)),
    ] {
        found.push(Found {
            family: "hand-made reference".into(),
            det: det_gain(s, &f, cfg.det_burn, cfg.det_blocks),
            policy: f,
            evals: 1,
            sto: vec![],
        });
    }
    progress("emission: stochastic confirmation");
    let cjobs: Vec<(usize, u64)> = (0..found.len())
        .flat_map(|i| (0..cfg.confirm_seeds as u64).map(move |c| (i, c)))
        .collect();
    let gains = par_map(&cjobs, th, |&(i, c)| {
        sto_gain(
            s,
            &found[i].policy,
            cfg.confirm_blocks,
            derive(seed, &[TAG_CONFIRM, c]),
            1.0,
        )
    });
    for ((i, _), g) in cjobs.iter().zip(gains) {
        found[*i].sto.push(g);
    }
    // Large (not 100%) miners with the policy that did best in the confirmation.
    let top = found
        .iter()
        .max_by(|a, b| a.sto_mean().partial_cmp(&b.sto_mean()).expect("finite"))
        .expect("found")
        .policy
        .clone();
    let roll = Policy::Rollout {
        horizon: 76,
        base: Box::new(Policy::Honest),
    };
    let lm_pols = [top.clone(), roll];
    let ajobs: Vec<(usize, f64, u64)> = (0..2)
        .flat_map(|pi| {
            [0.5, 0.8]
                .into_iter()
                .flat_map(move |a| (0..cfg.rollout_seeds as u64).map(move |c| (pi, a, c)))
        })
        .collect();
    let ag = par_map(&ajobs, th, |&(pi, a, c)| {
        sto_gain(
            s,
            &lm_pols[pi],
            cfg.rollout_blocks,
            derive(seed, &[TAG_ROLL, c]),
            a,
        )
    });
    let mut large_miner = Vec::new();
    for (pi, p) in lm_pols.iter().enumerate() {
        for a in [0.5, 0.8] {
            let v: Vec<f64> = ajobs
                .iter()
                .zip(&ag)
                .filter(|((x, y, _), _)| *x == pi && *y == a)
                .map(|(_, g)| *g)
                .collect();
            large_miner.push((p.short(), a, v.iter().sum::<f64>() / v.len() as f64));
        }
    }

    progress("emission: rollout controllers");
    let bases = [
        (76usize, Policy::Honest),
        (150, Policy::Honest),
        (76, Policy::Fixed(EDGE)),
    ];
    let rjobs: Vec<(usize, u64)> = (0..bases.len())
        .flat_map(|i| (0..cfg.rollout_seeds as u64).map(move |c| (i, c)))
        .collect();
    let rg = par_map(&rjobs, th, |&(i, c)| {
        let p = Policy::Rollout {
            horizon: bases[i].0,
            base: Box::new(bases[i].1.clone()),
        };
        let sd = derive(seed, &[TAG_ROLL, c]);
        (
            sto_gain(s, &p, cfg.rollout_blocks, sd, 1.0),
            sto_gain_from(s, &p, cfg.rollout_blocks, cfg.rollout_skip, sd),
        )
    });
    let rollout = (0..bases.len())
        .map(|i| {
            let p = Policy::Rollout {
                horizon: bases[i].0,
                base: Box::new(bases[i].1.clone()),
            };
            (
                p.label(),
                rjobs
                    .iter()
                    .zip(&rg)
                    .filter(|((j, _), _)| *j == i)
                    .map(|(_, g)| *g)
                    .collect(),
            )
        })
        .collect();

    // ---- Races.
    progress("race: screening");
    let pols = RacePolicy::search();
    let chunks = (cfg.screen_trials / CHUNK).max(1);
    let mut sjobs = Vec::new();
    for &q in &cfg.qs {
        for (pi, _) in pols.iter().enumerate() {
            for c in 0..chunks as u64 {
                sjobs.push((q, pi, c));
            }
        }
    }
    let sh = par_map(&sjobs, th, |&(q, pi, c)| {
        race(
            s,
            q,
            cfg.z,
            pols[pi],
            CHUNK.min(cfg.screen_trials),
            derive(seed, &[TAG_RSCREEN, qt(q), c]),
        )
        .0
    });
    progress("race: confirmation");
    let mut race_rows = Vec::new();
    let cchunks = (cfg.confirm_trials / CHUNK).max(1);
    for &q in &cfg.qs {
        let screen: Vec<(RacePolicy, u64)> = pols
            .iter()
            .enumerate()
            .map(|(pi, &p)| {
                let h = sjobs
                    .iter()
                    .zip(&sh)
                    .filter(|((qq, ppi, _), _)| *qq == q && *ppi == pi)
                    .map(|(_, h)| *h)
                    .sum();
                (p, h)
            })
            .collect();
        let best = screen.iter().max_by_key(|(_, h)| *h).expect("policies").0;
        let cands = [RacePolicy::Honest, RacePolicy::Compressed, best];
        let cj: Vec<(usize, u64)> = (0..3)
            .flat_map(|i| (0..cchunks as u64).map(move |c| (i, c)))
            .collect();
        let res = par_map(&cj, th, |&(i, c)| {
            race(
                s,
                q,
                cfg.z,
                cands[i],
                CHUNK.min(cfg.confirm_trials),
                derive(seed, &[TAG_RCONFIRM, qt(q), c]),
            )
        });
        let hits = |i: usize| -> u64 {
            cj.iter()
                .zip(&res)
                .filter(|((j, _), _)| *j == i)
                .map(|(_, r)| r.0)
                .sum()
        };
        let inh: Vec<f64> = cj
            .iter()
            .zip(&res)
            .filter(|((j, _), _)| *j == 1)
            .flat_map(|(_, r)| r.1.clone())
            .collect();
        let max_inh = inh.iter().cloned().fold(0.0, f64::max);
        race_rows.push(RaceRow {
            q,
            screen,
            best,
            honest: hits(0),
            compressed: hits(1),
            best_hits: hits(2),
            trials: (cchunks * CHUNK.min(cfg.confirm_trials)) as u64,
            inherited: (median(inh), max_inh),
        });
    }

    // ---- Selfish mining.
    progress("selfish mining");
    let sm_pols = [
        Policy::Honest,
        Policy::Fixed(LOW),
        Policy::Fixed(EDGE),
        Policy::Fixed(Action::new(Anchor::Clock, 60)),
    ];
    let mut smj = Vec::new();
    for a in [0.25, 0.33, 0.4] {
        for g in [0.0, 0.5] {
            for (pi, _) in sm_pols.iter().enumerate() {
                for c in 0..cfg.sm_seeds as u64 {
                    smj.push((a, g, pi, c));
                }
            }
        }
    }
    let smr = par_map(&smj, th, |&(a, g, pi, c)| {
        selfish(
            s,
            a,
            g,
            &sm_pols[pi],
            cfg.sm_blocks,
            derive(seed, &[TAG_SM, qt(a), qt(g), c]),
        )
    });
    let mut selfish_rows = Vec::new();
    for a in [0.25, 0.33, 0.4] {
        for g in [0.0, 0.5] {
            for (pi, p) in sm_pols.iter().enumerate() {
                let v: Vec<Selfish> = smj
                    .iter()
                    .zip(&smr)
                    .filter(|((aa, gg, ppi, _), _)| *aa == a && *gg == g && *ppi == pi)
                    .map(|(_, r)| *r)
                    .collect();
                let n = v.len() as f64;
                selfish_rows.push((
                    a,
                    g,
                    p.label(),
                    Selfish {
                        share: v.iter().map(|x| x.share).sum::<f64>() / n,
                        rate: v.iter().map(|x| x.rate).sum::<f64>() / n,
                    },
                ));
            }
        }
    }

    // ---- Hoppers.
    progress("hoppers");
    let grid = Hop::grid();
    let hs = par_map(&grid, th, |h| {
        let (sh, fair) = hop_run(s, h, cfg.hop_blocks, derive(seed, &[TAG_HOP]));
        100.0 * (sh - fair)
    });
    let mut idx: Vec<usize> = (0..grid.len()).collect();
    idx.sort_by(|&a, &b| hs[b].partial_cmp(&hs[a]).expect("finite"));
    let hop_min = hs.iter().cloned().fold(f64::MAX, f64::min);
    let top: Vec<usize> = idx.into_iter().take(6).collect();
    let mut hop_jobs: Vec<(Hop, u64)> = Vec::new();
    let reference = Hop {
        big: 10.0,
        mode: HopMode::Abs,
        on: 1.2,
        off: 2.0,
        stamp: HopStamp::Honest,
    };
    for &i in &top {
        for c in 0..cfg.hop_confirm_seeds as u64 {
            hop_jobs.push((grid[i], c));
        }
    }
    for c in 0..cfg.hop_confirm_seeds as u64 {
        hop_jobs.push((reference, c));
    }
    let hc = par_map(&hop_jobs, th, |&(h, c)| {
        let (sh, fair) = hop_run(s, &h, cfg.hop_confirm_blocks, derive(seed, &[TAG_HOPC, c]));
        100.0 * (sh - fair)
    });
    let conf_of = |h: &Hop| -> f64 {
        let v: Vec<f64> = hop_jobs
            .iter()
            .zip(&hc)
            .filter(|((hh, _), _)| hh == h)
            .map(|(_, x)| *x)
            .collect();
        v.iter().sum::<f64>() / v.len() as f64
    };
    let hop_top = top
        .iter()
        .map(|&i| (grid[i], hs[i], conf_of(&grid[i])))
        .collect();
    let hop_threshold_ref = conf_of(&reference);

    // ---- Low difficulty, big steps, genesis era.
    progress("low difficulty and ramps");
    let deqs = [0.3, 0.7, 1.0, 1.5, 2.0, 3.0, 5.0, 10.0, 100.0];
    let low = par_map(&deqs, th, |&deq| {
        (
            deq,
            low_d(
                s,
                deq,
                cfg.low_blocks,
                derive(seed, &[TAG_LOW, (deq * 10.0) as u64]),
            ),
        )
    });
    let mut ramps = Vec::new();
    for f in [10.0, 100.0, 1_000.0] {
        let r = step(s.rule.as_ref(), f, None, 20_000);
        let b = r.blocks.unwrap_or(0) as f64;
        ramps.push((
            format!("hash rate x{f}"),
            r.blocks,
            r.hours,
            b - r.hours * 30.0,
        ));
    }
    for f in [0.01, 0.001] {
        let r = startup(s.rule.as_ref(), f, None, 20_000).1;
        let b = r.blocks.unwrap_or(0) as f64;
        ramps.push((
            format!("start-up from D0 = {f} DEQ"),
            r.blocks,
            r.hours,
            b - r.hours * 30.0,
        ));
    }
    let r = ramp_from_one(s, DEQ as f64, 20_000);
    ramps.push((
        "chain at D = 1, hash rate returns to DEQ".into(),
        r.0,
        r.1,
        r.0.unwrap_or(0) as f64 - r.1 * 30.0,
    ));
    progress("genesis fork");
    let mut fj = Vec::new();
    for q in [0.2, 0.3, 0.4] {
        for st in [Stamping::Honest, Stamping::Compressed] {
            for c in 0..(cfg.fork_trials / 10).max(1) as u64 {
                fj.push((q, st, c));
            }
        }
    }
    let fr = par_map(&fj, th, |&(q, st, c)| {
        let mut rng = Rng::new(derive(seed, &[TAG_FORK, qt(q), c]));
        (0..cfg.fork_trials.min(10))
            .map(|_| genesis_fork_trial(s.rule.as_ref(), q, 720, st, 10.0 * 86_400.0, &mut rng))
            .filter(|o| *o == ForkOutcome::Win)
            .count() as u64
    });
    let mut fork = Vec::new();
    for q in [0.2, 0.3, 0.4] {
        for (st, name) in [
            (Stamping::Honest, "honest"),
            (Stamping::Compressed, "compressed"),
        ] {
            let hits = fj
                .iter()
                .zip(&fr)
                .filter(|((qq, ss, _), _)| *qq == q && *ss == st)
                .map(|(_, h)| *h)
                .sum();
            let trials = ((cfg.fork_trials / 10).max(1) * cfg.fork_trials.min(10)) as u64;
            fork.push((q, name, hits, trials));
        }
    }

    SubjectResult {
        name: s.name.to_string(),
        emission: found,
        large_miner,
        rollout,
        race: race_rows,
        selfish: selfish_rows,
        hop_top,
        hop_threshold_ref,
        hop_min,
        hop_evals: grid.len(),
        low,
        ramps,
        fork,
    }
}

fn pct(x: f64) -> String {
    format!("{:+.2}%", 100.0 * x)
}

fn opt(x: Option<usize>) -> String {
    x.map_or("none".into(), |v| v.to_string())
}

/// The generated Markdown tables.
pub fn render(cfg: &RtConfig, res: &[SubjectResult], header: &str) -> String {
    let mut o = String::from(header);
    let _ = writeln!(o, "\n## Configuration\n");
    let _ = writeln!(
        o,
        "- Base seed `{:#x}`, {} threads. Every job seeds from the base seed and its coordinates only (never the rule), so both rules see the same draws.",
        cfg.seed, cfg.threads
    );
    let _ = writeln!(
        o,
        "- Emission search (deterministic model, expected solve times, honest = exactly 0): periods {:?}, {} restarts x {} hill-climbing steps each; table policy {} restarts x {} steps; each evaluation {} burn-in + {} measured blocks. Confirmation: {} fresh seeds x {} blocks, stochastic, gain over honest on the same draws. Rollout controllers: {} seeds x {} blocks.",
        cfg.periods, cfg.restarts, cfg.iters, cfg.table_restarts, cfg.table_iters, cfg.det_burn, cfg.det_blocks, cfg.confirm_seeds, cfg.confirm_blocks, cfg.rollout_seeds, cfg.rollout_blocks
    );
    let _ = writeln!(
        o,
        "- Race: z = {}, q in {:?}; screening {} trials per policy ({} policies) on seed set A; confirmation {} trials each of honest, compressed and the screened best on seed set B. Excess = max(compressed, best) - honest on B.",
        cfg.z,
        cfg.qs,
        cfg.screen_trials,
        RacePolicy::search().len(),
        cfg.confirm_trials
    );
    let _ = writeln!(
        o,
        "- Selfish mining: {} seeds x {} main-chain blocks. Hoppers: {} configurations x {} blocks, top 6 by hopper gain (excess) re-run on {} fresh seeds x {} blocks. Low difficulty: {} blocks after 1 000 burn-in. Genesis fork: {} trials per cell, age 720, 10-day horizon.",
        cfg.sm_seeds, cfg.sm_blocks, Hop::grid().len(), cfg.hop_blocks, cfg.hop_confirm_seeds, cfg.hop_confirm_blocks, cfg.low_blocks, cfg.fork_trials
    );
    for r in res {
        let _ = writeln!(o, "\n## {}\n", r.name);
        let _ = writeln!(o, "### Emission (100% miner unless stated)\n");
        let _ = writeln!(
            o,
            "| Family | Evaluations | Deterministic gain | Stochastic gain per fresh seed | Mean | Best policy |"
        );
        let _ = writeln!(o, "|---|---|---|---|---|---|");
        for f in &r.emission {
            let pol = match &f.policy {
                Policy::Periodic(p) if p.len() <= 16 => f.policy.label(),
                p => p.short(),
            };
            let _ = writeln!(
                o,
                "| {} | {} | {} | {} | {} | `{}` |",
                f.family,
                f.evals,
                pct(f.det),
                f.sto.iter().map(|g| pct(*g)).collect::<Vec<_>>().join(", "),
                pct(f.sto_mean()),
                pol
            );
        }
        for (p, a, g) in &r.large_miner {
            let _ = writeln!(
                o,
                "| miner stamps {:.0}% of blocks ({} seeds x {} blocks) | - | - | - | {} | `{p}` |",
                a * 100.0,
                cfg.rollout_seeds,
                cfg.rollout_blocks,
                pct(*g)
            );
        }
        let _ = writeln!(
            o,
            "\nRollout controllers ({} seeds x {} blocks; sustained = blocks {}..{} only, without the one-shot gain):\n",
            cfg.rollout_seeds, cfg.rollout_blocks, cfg.rollout_skip, cfg.rollout_blocks
        );
        let _ = writeln!(
            o,
            "| Controller | total gain per seed | mean | sustained gain per seed | mean | min |"
        );
        let _ = writeln!(o, "|---|---|---|---|---|---|");
        for (label, g) in &r.rollout {
            let n = g.len().max(1) as f64;
            let _ = writeln!(
                o,
                "| `{label}` | {} | {} | {} | {} | {} |",
                g.iter().map(|x| pct(x.0)).collect::<Vec<_>>().join(", "),
                pct(g.iter().map(|x| x.0).sum::<f64>() / n),
                g.iter().map(|x| pct(x.1)).collect::<Vec<_>>().join(", "),
                pct(g.iter().map(|x| x.1).sum::<f64>() / n),
                pct(g.iter().map(|x| x.1).fold(f64::MAX, f64::min))
            );
        }
        let _ = writeln!(o, "\n### Race (z = 100)\n");
        let _ = writeln!(
            o,
            "| q | honest | compressed | screened best | P(best) | excess | inherited D/DEQ on compressed wins (median, max) |"
        );
        let _ = writeln!(o, "|---|---|---|---|---|---|---|");
        for row in &r.race {
            let _ = writeln!(
                o,
                "| {} | {:.4} | {:.4} | {} | {:.4} | {} | {:.2}, {:.2} |",
                row.q,
                row.p(row.honest),
                row.p(row.compressed),
                row.best.label(),
                row.p(row.best_hits),
                pct(row.excess()),
                row.inherited.0,
                row.inherited.1
            );
        }
        for row in &r.race {
            let _ = writeln!(
                o,
                "\nScreening hits at q = {} (seed set A): {}",
                row.q,
                row.screen
                    .iter()
                    .map(|(p, h)| format!("{} {h}", p.label()))
                    .collect::<Vec<_>>()
                    .join("; ")
            );
        }
        let _ = writeln!(o, "\n### Selfish mining (work-based fork choice)\n");
        let _ = writeln!(
            o,
            "| alpha | gamma | attacker stamps | attacker share of main chain | main-chain rate vs target |"
        );
        let _ = writeln!(o, "|---|---|---|---|---|");
        for (a, g, l, sm) in &r.selfish {
            let _ = writeln!(
                o,
                "| {a} | {g} | {l} | {:.4} | {} |",
                sm.share,
                pct(sm.rate)
            );
        }
        let _ = writeln!(
            o,
            "\n### Hoppers ({} configurations searched)\n",
            r.hop_evals
        );
        let _ = writeln!(
            o,
            "| Hopper | screening excess (points) | confirmed excess (points) |"
        );
        let _ = writeln!(o, "|---|---|---|");
        for (h, a, b) in &r.hop_top {
            let _ = writeln!(o, "| {} | {:+.2} | {:+.2} |", h.label(), a, b);
        }
        let _ = writeln!(
            o,
            "| selection study's reference hopper (10x, abs on<1.2 off>2) | - | {:+.2} |",
            r.hop_threshold_ref
        );
        let _ = writeln!(
            o,
            "\nThe six largest hopper gains of the screening, confirmed on fresh seeds. The most negative screening excess was {:+.2} points (a hopper that overpays; not an attack).",
            r.hop_min
        );
        let _ = writeln!(o, "\n### Low difficulty (honest miners)\n");
        let _ = writeln!(
            o,
            "| D_eq | mean solve time / T | mean D / D_eq | blocks at D = 1 | CV of D | min D | max D |"
        );
        let _ = writeln!(o, "|---|---|---|---|---|---|---|");
        for (deq, l) in &r.low {
            let _ = writeln!(
                o,
                "| {deq} | {:.3} | {:.3} | {:.3} | {:.3} | {} | {} |",
                l.mean_st, l.mean_d, l.at_one, l.cv, l.min_d, l.max_d
            );
        }
        let _ = writeln!(o, "\n### Large upward steps (deterministic)\n");
        let _ = writeln!(
            o,
            "| Scenario | blocks to within 10% | hours | excess blocks (blocks - hours x 30) |"
        );
        let _ = writeln!(o, "|---|---|---|---|");
        for (l, b, h, e) in &r.ramps {
            let _ = writeln!(o, "| {l} | {} | {h:.2} | {e:.0} |", opt(*b));
        }
        let _ = writeln!(o, "\n### Genesis-fork rewrite (age 720, 10-day horizon)\n");
        let _ = writeln!(o, "| q | stamps | wins / trials |");
        let _ = writeln!(o, "|---|---|---|");
        for (q, st, h, t) in &r.fork {
            let _ = writeln!(o, "| {q} | {st} | {h}/{t} |");
        }
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenarios::{lowering_run, Strategy};

    #[test]
    fn honest_matches_lowering_run() {
        let s = Subject::recommended();
        let a = sto_time(&s, &Policy::Honest, 400, 11, 1.0);
        let b = lowering_run(s.rule.as_ref(), &Strategy::Honest, 400, 11);
        assert_eq!(a, b);
        assert!(det_gain(&s, &Policy::Honest, 100, 300).abs() < 1e-12);
    }

    #[test]
    fn counted_clock_matches_the_rule() {
        // The clock after compressed stamps runs step per block.
        let ts: Vec<u64> = vec![1_000, 1_001, 1_001, 1_002];
        assert_eq!(counted_clock(&ts, 75, 60), 1_180);
        assert_eq!(counted_clock(&ts, 75, 1), 1_003);
        assert_eq!(counted_clock(&ts, 2, 60), 1_061);
    }

    #[test]
    fn policies_stay_valid() {
        let s = Subject::recommended();
        let mut rng = Rng::new(2);
        for _ in 0..3 {
            let p: Vec<Action> = (0..7).map(|_| random_action(&mut rng)).collect();
            sto_time(&s, &Policy::Periodic(p), 200, 3, 1.0);
        }
        let t: Vec<Action> = (0..E_BINS * R_BINS)
            .map(|_| random_action(&mut rng))
            .collect();
        sto_time(&s, &Policy::Table(t), 200, 3, 0.5);
        let r = Policy::Rollout {
            horizon: 10,
            base: Box::new(Policy::Honest),
        };
        sto_time(&s, &r, 50, 3, 1.0);
        for p in RacePolicy::search() {
            race_trial(&s, 0.4, 10, p, &mut rng);
        }
        selfish(&s, 0.33, 0.5, &Policy::Fixed(LOW), 300, 4);
        for h in Hop::grid().iter().step_by(37) {
            hop_run(&s, h, 300, 5);
        }
    }

    #[test]
    fn selfish_matches_eyal_sirer() {
        // Eyal-Sirer SM1 revenue at alpha = 0.4, gamma = 0 is 0.484 (equal-difficulty
        // model); with honest stamps the work-based version must be close to it.
        let s = Subject::recommended();
        let r = selfish(&s, 0.4, 0.0, &Policy::Honest, 6_000, 6);
        assert!((r.share - 0.484).abs() < 0.03, "{r:?}");
    }
}
