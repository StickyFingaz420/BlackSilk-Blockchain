//! Pins the key metrics of the rule recommended by the W0-03b selection study
//! (docs/evidence/daa-sim-2026-09-27/selection.md): LWMA-1 with the window N = 75
//! (was 60) and the monotone step `prev + 1` replaced by `prev + max(1, T/2)`
//! ("virtual clock step T/2").
//!
//! Reduced sizes and fixed seeds; the full study is
//! `cargo run --release -p blacksilk-daa-sim -- --selection`.

use blacksilk_daa_sim::adaptive::{self, Attack, HOPPERS};
use blacksilk_daa_sim::family::recommended;
use blacksilk_daa_sim::rng::{derive, Rng};
use blacksilk_daa_sim::scenarios::{
    fixed_strategies, genesis_gap, honest_bias, lowering_run, startup, step, Strategy,
};
use blacksilk_daa_sim::sim::{par_map, Branch, DEQ};
use blacksilk_daa_sim::{DifficultyRule, Lwma};

const SEED: u64 = 0x5E1E_C7ED;

fn threads() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get().min(4))
}

/// Exact integer behaviour: under fully compressed stamps the child is exactly
/// `floor(sumD * T * (n+1) / (2 * T/2 * n(n+1)/2))`, i.e. twice the window average,
/// and at difficulty 1 the rule still rises (to 2), so it cannot freeze.
#[test]
fn integer_vectors() {
    let rule = recommended();
    let ts: Vec<u64> = (0..61).map(|i| 1_000 + i).collect();
    let cd: Vec<u128> = (0..61).map(|i| (i + 1) * 1_000_000).collect();
    // sumD = 60e6, L = 60 * 60 * 61 / 2 = 109 800: 60e6 * 120 * 61 / 219 600.
    assert_eq!(rule.next(&ts, &cd, 120), 2_000_000);
    let ones: Vec<u128> = (1..=61).collect();
    assert_eq!(rule.next(&ts, &ones, 120), 2);
    // On-time blocks: unchanged; one 6T-capped gap as in the genesis gap: D0 / 6.
    let steady = Branch::steady(61, DEQ);
    assert_eq!(steady.required(&rule), DEQ);
    assert_eq!(rule.next(&[0, 7_200], &[100, 200], 120), 16);
    // Regtest (T = 10): the step is 5 s.
    assert_eq!(rule.next(&[0, 1, 2], &[1, 2, 3], 10), 2);
}

/// Deterministic follow metrics (expected solve times; no randomness).
#[test]
fn deterministic_follow_metrics() {
    let rule = recommended();
    let up = step(&rule, 10.0, None, 3_000).blocks;
    let down = step(&rule, 0.1, None, 3_000).blocks;
    let half = startup(&rule, 0.5, None, 3_000).1.blocks;
    let gap = genesis_gap(&rule, DEQ, 7_200, None, 3_000).recovered_at;
    println!("10x up {up:?}, 10x down {down:?}, 0.5xD0 {half:?}, gap {gap:?}");
    // Pinned exactly (criteria: <= 150, <= 150, <= 60, <= 120).
    assert_eq!(up, Some(113));
    assert_eq!(down, Some(130));
    assert_eq!(half, Some(2));
    assert_eq!(gap, Some(11));
}

fn race(rule: &dyn DifficultyRule, a: Attack, trials: usize) -> f64 {
    let chunks: Vec<u64> = (0..(trials / 50) as u64).collect();
    let hits: u64 = par_map(&chunks, threads(), |&c| {
        adaptive::race(rule, 0.4, 100, a, 50, derive(SEED, &[1, c]))
    })
    .into_iter()
    .sum();
    hits as f64 / trials as f64
}

/// The difficulty-raising race at q = 0.4, z = 100: the recommended rule keeps the
/// compressed and late-compress attackers near the honest baseline, while the
/// current rule on the same draws does not.
#[test]
fn raising_race_is_bounded() {
    const TRIALS: usize = 2_000;
    let rule = recommended();
    let honest = race(&rule, Attack::Honest, TRIALS);
    let worst = [Attack::Compressed, Attack::Late(1.0), Attack::Ratio(0.1)]
        .map(|a| race(&rule, a, TRIALS))
        .into_iter()
        .fold(0.0, f64::max);
    let current = race(&Lwma { window: 60 }, Attack::Compressed, TRIALS);
    println!(
        "q = 0.4, z = 100, {TRIALS} trials: honest {honest:.4}, worst attacker {worst:.4}; \
         current rule compressed {current:.4}"
    );
    // The criterion is +5%; allow three standard errors of this reduced run (~1.5 pts).
    assert!(worst - honest <= 0.065, "{worst} {honest}");
    assert!(current - honest >= 0.2, "{current}");
}

/// No timestamp strategy of dossier 04's fixed families gains a 100% miner more
/// than 1% blocks per hour (same draws as honest stamping).
#[test]
fn no_emission_gain() {
    let rule = recommended();
    let seed = derive(SEED, &[2]);
    let blocks = 1_500;
    let honest = lowering_run(&rule, &Strategy::Honest, blocks, seed);
    let strategies = fixed_strategies();
    let totals = par_map(&strategies, threads(), |s| {
        lowering_run(&rule, s, blocks, seed)
    });
    let mut worst = (f64::MIN, String::new());
    for (s, t) in strategies.iter().zip(totals) {
        let gain = honest / t - 1.0;
        if gain > worst.0 {
            worst = (gain, s.label());
        }
    }
    println!(
        "best lowering strategy: {} {:+.2}%",
        worst.1,
        100.0 * worst.0
    );
    assert!(worst.0 <= 0.01, "{worst:?}");
}

/// Honest bias within +-1.5% and hoppers within +-3 points of their fair share.
#[test]
fn bias_and_hoppers() {
    let rule = recommended();
    let seeds: Vec<u64> = (0..2).collect();
    let bias: Vec<f64> = par_map(&seeds, threads(), |&s| {
        let mut rng = Rng::new(derive(SEED, &[3, s]));
        let (sum, n) = honest_bias(&rule, 20_000, &mut rng);
        sum / n as f64 / 120.0 - 1.0
    });
    let bias = bias.iter().sum::<f64>() / bias.len() as f64;
    let hops = par_map(&HOPPERS, threads(), |&(on, off, big)| {
        let mut rng = Rng::new(derive(SEED, &[4]));
        adaptive::hopper(&rule, 10_000, on, off, big, &mut rng).excess_points()
    });
    println!("bias {:+.2}%, hopper excess points {hops:?}", 100.0 * bias);
    assert!(bias.abs() <= 0.015, "{bias}");
    for h in hops {
        assert!(h.abs() <= 3.0, "{h}");
    }
}
