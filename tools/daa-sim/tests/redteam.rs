//! Pins the RT-DAA red-team findings (docs/evidence/daa-sim-2026-09-27/redteam.md)
//! on the rule chosen by the selection study (LWMA-75, counted clock step T/2) and on
//! the candidate fix (the counted clock warmed over the 11 blocks before the window).
//!
//! Fixed seeds and reduced sizes; the full study is
//! `cargo run --release -p blacksilk-daa-sim -- --redteam`.

use blacksilk_daa_sim::family::recommended;
use blacksilk_daa_sim::redteam::{
    reference_next, sto_gain, sto_gain_from, Action, Anchor, Anchored, Policy, Subject,
};
use blacksilk_daa_sim::rng::Rng;
use blacksilk_daa_sim::sim::{par_map, Branch, DEQ, START};
use blacksilk_daa_sim::DifficultyRule;

fn threads() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get().min(4))
}

/// A random history: out-of-order stamps (steps in [-back, +fwd)) and random block
/// difficulties up to `dmax`, from `ts0`.
fn history(
    rng: &mut Rng,
    len: usize,
    ts0: u64,
    back: i64,
    fwd: i64,
    dmax: u64,
) -> (Vec<u64>, Vec<u128>) {
    let mut ts = vec![ts0];
    let mut cd = vec![1 + rng.below(dmax) as u128];
    for _ in 1..len {
        let step = rng.below((back + fwd) as u64) as i64 - back;
        let last = *ts.last().unwrap() as i128;
        ts.push((last + step as i128).clamp(0, u64::MAX as i128) as u64);
        cd.push(cd.last().unwrap() + 1 + rng.below(dmax) as u128);
    }
    (ts, cd)
}

/// The independent checked port of the pseudocode, the harness rule and the fix with
/// no warm-up all agree, including out-of-order stamps, short windows and regtest.
#[test]
fn reference_port_equals_the_harness_rule() {
    let rule = recommended();
    let unwarmed = Anchored {
        window: 75,
        warm: 0,
    };
    let mut rng = Rng::new(0x7EA3);
    for len in [1usize, 2, 3, 10, 75, 76, 77, 200] {
        for _ in 0..40 {
            let (ts, cd) = history(&mut rng, len, 1_000_000, 900, 1_500, 2_000_000);
            for t in [120u64, 10] {
                let want = reference_next(&ts, &cd, t, 75, cd[0] as u64);
                assert_eq!(rule.next(&ts, &cd, t), want);
                assert_eq!(unwarmed.next(&ts, &cd, t), want);
            }
        }
    }
}

/// Checked arithmetic at the extremes: stamps near `u64::MAX`, difficulties near
/// `u64::MAX`, targets from 1 s to 2^40 s. No overflow or underflow; the result stays
/// in [1, u64::MAX] and under the rise bound `floor(sumD * T / (step * n))`.
#[test]
fn integer_extremes_do_not_overflow() {
    let mut rng = Rng::new(0x0F10);
    for t in [1u64, 2, 3, 10, 120, 1 << 40] {
        for (ts0, dmax) in [
            (0u64, 3u64),
            (u64::MAX - 5_000_000, u64::MAX - 1),
            (1_790_000_000, 1_000_000),
        ] {
            for len in [2usize, 76, 90] {
                let (ts, cd) = history(&mut rng, len, ts0, 5_000, 5_000, dmax);
                let next = reference_next(&ts, &cd, t, 75, 1);
                assert!(next >= 1);
                let take = len.min(76);
                let n = take as u128 - 1;
                let sum_d = cd[len - 1] - cd[len - take];
                let step = (t as u128 / 2).max(1);
                let bound = (sum_d * t as u128 / (step * n)).min(u64::MAX as u128);
                assert!(next as u128 <= bound, "{next} > {bound} (T {t})");
                // The fix warms the clock over up to 11 more stamps: same bound.
                let fix = Anchored {
                    window: 75,
                    warm: 11,
                }
                .next(&ts, &cd, t);
                assert!(fix >= 1 && fix as u128 <= bound, "{fix} > {bound} (T {t})");
            }
        }
    }
    // Saturation: difficulties at u64::MAX and compressed stamps clamp to u64::MAX.
    let ts: Vec<u64> = (0..76).map(|i| u64::MAX - 100 + i / 2).collect();
    let cd: Vec<u128> = (1..=76).map(|i| i * u64::MAX as u128).collect();
    assert_eq!(reference_next(&ts, &cd, 120, 75, 1), u64::MAX);
}

/// Golden vector of the window-start lag (the mechanism of the anchor-lag attack):
/// an on-target window whose oldest stamp is 1 300 s low. The rule under attack counts
/// the first solve time as 720 s (6T cap) instead of 120 s; the fix anchors the clock at
/// the previous stamp + T/2 and counts 180 s.
#[test]
fn window_start_lag_vector() {
    // 11 warm-up blocks + the 76-stamp window, 120 s apart, difficulty DEQ.
    let mut b = Branch::steady(87, DEQ);
    assert_eq!(b.required(&recommended()), DEQ);
    b.ts[11] -= 1_300;
    // weighted = 342 000 + 600: 75e6 * 120 * 76 / (2 * 342 600).
    assert_eq!(b.required(&recommended()), 998_248);
    assert_eq!(Subject::recommended().required(&b), 998_248);
    // Fix: c0 = ts[10] + 60, so st_1 = 180: 75e6 * 120 * 76 / (2 * 342 060).
    assert_eq!(
        b.required(&Anchored {
            window: 75,
            warm: 11
        }),
        999_824
    );
    assert_eq!(b.ts[0], START);
}

/// The anchor-lag attack: a rollout controller (one-step improvement over honest
/// stamping, 76-block horizon) gains more than 1% sustained emission on the rule under
/// attack (the selection criterion is <= +1%); the fix brings it well below.
#[test]
fn anchor_lag_attack_and_fix() {
    const BLOCKS: usize = 2_000;
    const SKIP: usize = 600;
    let seeds = [0x7EA3_0001u64, 0x7EA3_0002, 0x7EA3_0003];
    let p = Policy::Rollout {
        horizon: 76,
        base: Box::new(Policy::Honest),
    };
    let jobs: Vec<(bool, u64)> = [false, true]
        .into_iter()
        .flat_map(|fix| seeds.into_iter().map(move |s| (fix, s)))
        .collect();
    let g = par_map(&jobs, threads(), |&(fix, seed)| {
        let s = if fix {
            Subject::anchored("fix", 11)
        } else {
            Subject::recommended()
        };
        sto_gain_from(&s, &p, BLOCKS, SKIP, seed)
    });
    let mean = |fix: bool| {
        let v: Vec<f64> = jobs
            .iter()
            .zip(&g)
            .filter(|((f, _), _)| *f == fix)
            .map(|(_, x)| *x)
            .collect();
        v.iter().sum::<f64>() / v.len() as f64
    };
    let (attacked, fixed) = (mean(false), mean(true));
    println!("sustained rollout gain: rule {attacked:+.4}, fix {fixed:+.4} ({g:?})");
    assert!(attacked > 0.010, "{attacked}");
    assert!(fixed < 0.006, "{fixed}");
}

/// The strongest static policy the periodic search found on the rule under attack
/// (period 12, redteam.md): above +1% on the rule, and harmless on the fix.
#[test]
fn periodic_attack_and_fix() {
    let m = |o: i64| Action::new(Anchor::Mtp, o);
    let p = |o: i64| Action::new(Anchor::Prev, o);
    let pattern = vec![
        m(1),
        p(417),
        p(420),
        m(1),
        p(482),
        p(840),
        p(839),
        Action::new(Anchor::Now, -1_083),
        p(955),
        Action::new(Anchor::Clock, 720),
        m(1),
        m(1),
    ];
    let policy = Policy::Periodic(pattern);
    let g = par_map(&[false, true], threads(), |&fix| {
        let s = if fix {
            Subject::anchored("fix", 11)
        } else {
            Subject::recommended()
        };
        sto_gain(&s, &policy, 5_000, 0x7EA3_0100, 1.0)
    });
    println!("periodic-12 gain: rule {:+.4}, fix {:+.4}", g[0], g[1]);
    assert!(g[0] > 0.015, "{}", g[0]);
    assert!(g[1] < 0.005, "{}", g[1]);
}
