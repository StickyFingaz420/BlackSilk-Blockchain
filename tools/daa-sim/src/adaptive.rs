//! Adaptive attackers and fairness metrics for the selection study (W0-03b).

use crate::rng::Rng;
use crate::rules::DifficultyRule;
use crate::sim::{Branch, DEQ, FTL, RATE, TARGET};

/// A private-branch stamping policy for the difficulty-raising race.
///
/// Forward stamping is never useful here: the branch's expected work equals its hashes
/// whatever its difficulty, and a lower difficulty only reduces the variance the
/// attacker lives on. So the policies choose how and when to compress.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Attack {
    /// Real-clock stamps (the baseline).
    Honest,
    /// Always `MTP + 1`.
    Compressed,
    /// Honest stamps until the public chain has `frac * z` blocks after the fork,
    /// then `MTP + 1` (compress late, to concentrate work at the decision point).
    Late(f64),
    /// The branch clock runs at `ratio` times real time since the fork (partial
    /// compression), never below `MTP + 1`.
    Ratio(f64),
}

impl Attack {
    pub fn label(&self) -> String {
        match self {
            Attack::Honest => "honest".into(),
            Attack::Compressed => "compressed".into(),
            Attack::Late(f) => format!("late({f})"),
            Attack::Ratio(r) => format!("ratio({r})"),
        }
    }

    fn stamp(&self, b: &Branch, now: f64, fork_t: f64, confirmations: usize, z: usize) -> u64 {
        match *self {
            Attack::Honest => b.honest_stamp(now),
            Attack::Compressed => b.min_timestamp(),
            Attack::Late(f) => {
                if confirmations as f64 >= f * z as f64 {
                    b.min_timestamp()
                } else {
                    b.honest_stamp(now)
                }
            }
            Attack::Ratio(r) => ((fork_t + r * (now - fork_t)) as u64).max(b.min_timestamp()),
        }
    }

    /// The adaptive policies searched in addition to honest and compressed.
    pub fn adaptive() -> Vec<Attack> {
        vec![
            Attack::Late(0.5),
            Attack::Late(0.8),
            Attack::Late(1.0),
            Attack::Ratio(0.1),
            Attack::Ratio(0.3),
            Attack::Ratio(0.6),
        ]
    }
}

fn held_back(timestamp: u64, now: f64) -> Option<f64> {
    (timestamp > now as u64 + FTL).then(|| (timestamp - FTL) as f64)
}

/// One race (same model as `scenarios::race_trial`) with an adaptive policy.
pub fn race_trial(
    rule: &dyn DifficultyRule,
    q: f64,
    z: usize,
    attack: Attack,
    rng: &mut Rng,
) -> bool {
    let base = Branch::steady(121, DEQ);
    let mut public = base.clone();
    let mut private = base;
    let mut now = public.tip_time() as f64;
    let fork_t = now;
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
            let t = attack.stamp(&private, a_next, fork_t, confirmations, z);
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
    attack: Attack,
    trials: usize,
    seed: u64,
) -> u64 {
    let mut rng = Rng::new(seed);
    (0..trials)
        .filter(|_| race_trial(rule, q, z, attack, &mut rng))
        .count() as u64
}

/// Hop-in/hop-out mining with a fairness reference.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct HopFair {
    /// Expected share of blocks found by the hopper.
    pub share: f64,
    /// Its share of the hashes spent (the fair share of blocks).
    pub fair: f64,
}

impl HopFair {
    /// Share minus fair share, in percentage points.
    pub fn excess_points(&self) -> f64 {
        100.0 * (self.share - self.fair)
    }
}

/// A hopper with `big` times the dedicated hash rate mines while `D < on * DEQ` and
/// leaves once `D > off * DEQ`. Per block of difficulty `D` the expected hashes spent
/// are `D`, of which the hopper spends `big / (1 + big)` while it is on; its fair
/// share of blocks is its share of all hashes.
pub fn hopper(
    rule: &dyn DifficultyRule,
    blocks: usize,
    on_t: f64,
    off_t: f64,
    big: f64,
    rng: &mut Rng,
) -> HopFair {
    let mut b = Branch::steady(121, DEQ);
    let mut now = b.tip_time() as f64;
    let mut on = false;
    let (mut hop_blocks, mut hop_hashes, mut hashes) = (0.0, 0.0, 0.0);
    let frac = big / (1.0 + big);
    for _ in 0..blocks {
        let d = b.required(rule);
        if !on && (d as f64) < on_t * DEQ as f64 {
            on = true;
        } else if on && (d as f64) > off_t * DEQ as f64 {
            on = false;
        }
        let h = if on { 1.0 + big } else { 1.0 };
        let dt = rng.exp() * d as f64 / (h * RATE);
        if on {
            hop_blocks += frac;
            hop_hashes += frac * d as f64;
        }
        hashes += d as f64;
        now += dt;
        b.push(b.honest_stamp(now), d, now);
    }
    HopFair {
        share: hop_blocks / blocks as f64,
        fair: hop_hashes / hashes,
    }
}

/// The hopper configurations searched: `(on, off, big)`.
pub const HOPPERS: [(f64, f64, f64); 4] = [
    (1.2, 2.0, 10.0),
    (1.05, 1.5, 10.0),
    (1.1, 1.3, 3.0),
    (1.0, 1.2, 1.0),
];

/// Hours until the difficulty is within +/-10% after the hash rate drops by
/// `factor` (expected solve times), or `None` within `max_blocks`.
pub fn drop_hours(
    rule: &dyn DifficultyRule,
    factor: f64,
    max_blocks: usize,
) -> (Option<usize>, f64) {
    let f = crate::scenarios::step(rule, factor, None, max_blocks);
    (f.blocks, f.hours)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Lwma;

    #[test]
    fn policies_stay_valid() {
        let mut rng = Rng::new(3);
        for a in [Attack::Honest, Attack::Compressed]
            .into_iter()
            .chain(Attack::adaptive())
        {
            for _ in 0..3 {
                race_trial(&Lwma { window: 60 }, 0.4, 20, a, &mut rng);
            }
        }
    }

    #[test]
    fn honest_hopper_share_is_near_fair_for_a_constant_miner() {
        // A "hopper" that never leaves is just more hash rate: share == fair.
        let mut rng = Rng::new(4);
        let h = hopper(&Lwma { window: 60 }, 3_000, 100.0, 100.0, 1.0, &mut rng);
        assert!(h.excess_points().abs() < 1.0, "{h:?}");
    }
}
