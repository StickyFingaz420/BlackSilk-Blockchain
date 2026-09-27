//! Differential test: the v3 consensus `next_difficulty` equals the red-team's
//! warmed rule (`redteam::Anchored { window: 75, warm: 11 }`, the candidate fix of
//! docs/evidence/daa-sim-2026-09-27/redteam.md) on random adversarial histories.
//!
//! The two are separate implementations: `Anchored` was written in the harness
//! before the consensus change, and every harness result for the fix was measured
//! with it. Equality here is what makes that evidence apply to the consensus code.

use blacksilk_consensus::difficulty::{difficulty_ancestors, next_difficulty, DIFFICULTY_WINDOW};
use blacksilk_consensus::timestamp::median;
use blacksilk_consensus::ChainParams;
use blacksilk_daa_sim::redteam::Anchored;
use blacksilk_daa_sim::rng::Rng;
use blacksilk_daa_sim::{ConsensusV3, DifficultyRule};

const FIX: Anchored = Anchored {
    window: 75,
    warm: 11,
};

/// How the next stamp of a history is chosen.
fn next_stamp(rng: &mut Rng, ts: &[u64], t: u64, mode: u64) -> u64 {
    let last = *ts.last().unwrap();
    let mtp = median(&ts[ts.len().saturating_sub(11)..]);
    match (mode + rng.below(8)) % 8 {
        // The lowest stamp the MTP rule allows.
        0 => mtp.saturating_add(1),
        // The FTL edge relative to a clock at the previous stamp + T.
        1 => last.saturating_add(t).saturating_add(360),
        // Anywhere back to the MTP (non-monotone).
        2 => mtp.saturating_add(1 + rng.below(last.saturating_sub(mtp).max(1))),
        // Around on-target.
        3 | 4 => last.saturating_add(rng.below(3 * t + 1)),
        // A long gap (beyond the 6T cap).
        5 => last.saturating_add(6 * t + rng.below(100 * t + 1)),
        // Equal to the previous stamp.
        6 => last,
        // Unconstrained: any stamp within 2 000 s either way.
        _ => (last as i128 + rng.below(4_001) as i128 - 2_000).clamp(0, u64::MAX as i128) as u64,
    }
}

/// A random history of `len` blocks: adversarial stamps, random difficulties.
fn history(rng: &mut Rng, len: usize, t: u64, t0: u64, dmax: u64) -> (Vec<u64>, Vec<u128>) {
    let mode = rng.below(8);
    let mut ts = vec![t0];
    let mut cd = vec![1 + rng.below(dmax) as u128];
    for _ in 1..len {
        let s = next_stamp(rng, &ts, t, mode);
        ts.push(s);
        cd.push(cd.last().unwrap() + 1 + rng.below(dmax) as u128);
    }
    (ts, cd)
}

/// At least 10 000 histories per run: lengths 1..=200 (every window shorter than
/// 87 included), targets from 1 s to 2^40 s, stamps at the MTP and FTL edges,
/// non-monotone stamps, and difficulties up to u64::MAX.
#[test]
fn consensus_equals_the_warmed_redteam_rule() {
    let mut rng = Rng::new(0xD1FF_0075);
    let targets = [120u64, 10, 2, 3, 1, 600, 1 << 40];
    let dmaxes = [1u64, 3, 1_000, 1_000_000_000, u64::MAX - 1];
    let mut checked = 0usize;
    // Histories on which the warm-up changes the result: the test must be able
    // to tell the warmed rule from the unwarmed one.
    let mut warm_matters = 0usize;
    let unwarmed = Anchored {
        window: 75,
        warm: 0,
    };
    for round in 0..12_000u64 {
        let len = match round % 4 {
            0 => 1 + rng.below(88) as usize,  // genesis-near: 1..=88
            1 => 76 + rng.below(13) as usize, // around the warm-up: 76..=88
            _ => 1 + rng.below(200) as usize,
        };
        let t = targets[rng.below(targets.len() as u64) as usize];
        let dmax = dmaxes[rng.below(dmaxes.len() as u64) as usize];
        let t0 = if round % 10 == 9 {
            u64::MAX - 10_000_000 // stamps near u64::MAX
        } else {
            1_790_380_800 + rng.below(1_000_000)
        };
        let (ts, cd) = history(&mut rng, len, t, t0, dmax);
        let initial = cd[0].min(u64::MAX as u128) as u64;
        let want = FIX.next(&ts, &cd, t);
        // The whole history, and exactly the ancestors the chain fetches.
        assert_eq!(
            next_difficulty(&ts, &cd, t, DIFFICULTY_WINDOW, initial),
            want,
            "round {round}: len {len}, T {t}"
        );
        let from = len.saturating_sub(difficulty_ancestors(DIFFICULTY_WINDOW));
        assert_eq!(
            next_difficulty(&ts[from..], &cd[from..], t, DIFFICULTY_WINDOW, initial),
            want,
            "round {round}: ancestors only"
        );
        assert_eq!(ConsensusV3.next(&ts, &cd, t), want, "round {round}");
        warm_matters += usize::from(unwarmed.next(&ts, &cd, t) != want);
        checked += 1;
    }
    assert!(checked >= 10_000);
    assert!(
        warm_matters >= 1_000,
        "only {warm_matters} histories exercise the warm-up"
    );
    println!("{checked} histories, {warm_matters} where the warm-up changes the result");
}

/// The chain parameters of every built-in network use the rule the harness
/// measured: N = 75 and 87 ancestors.
#[test]
fn every_network_uses_the_measured_window() {
    for p in [
        ChainParams::mainnet(),
        ChainParams::testnet(),
        ChainParams::regtest(),
    ] {
        assert_eq!(p.difficulty_window, FIX.window);
        assert_eq!(p.difficulty_ancestors(), FIX.window + 1 + FIX.warm);
    }
}
