//! Reduced harness runs (fixed seeds, well under 60 s in release): the 03-F1
//! difficulty-raising attack reproduces against the consensus rule, and the
//! timestamp-lowering direction (03-F3 / 04-F10) stays negligible.

use blacksilk_daa_sim::rng::derive;
use blacksilk_daa_sim::scenarios::{fixed_strategies, lowering_run, race, Rate, Stamping};
use blacksilk_daa_sim::sim::par_map;
use blacksilk_daa_sim::Lwma;

const SEED: u64 = 0xF1;
const TRIALS: usize = 1_000;
const CHUNK: usize = 50;

/// The pre-v3 consensus rule (LWMA-60, step 1; `rules::legacy_next`), on which
/// 03-F1 was found.
const CURRENT: Lwma = Lwma { window: 60 };

fn race_rate(q: f64, z: usize, stamping: Stamping) -> Rate {
    let chunks: Vec<u64> = (0..(TRIALS / CHUNK) as u64).collect();
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get().min(4));
    let mut total = Rate::default();
    for r in par_map(&chunks, threads, |&c| {
        race(&CURRENT, q, z, stamping, CHUNK, derive(SEED, &[c]))
    }) {
        total.add(r);
    }
    total
}

/// 03-F1: an attacker with 40% of the hash rate who stamps its private blocks at
/// MTP + 1 overturns 100 confirmations far more often than the same attacker with
/// honest timestamps, because the compressed branch concentrates its work in a
/// few very hard blocks (Bahack's difficulty-raising attack).
#[test]
fn f1_difficulty_raising_attack_reproduces_on_the_current_rule() {
    let honest = race_rate(0.4, 100, Stamping::Honest);
    let compressed = race_rate(0.4, 100, Stamping::Compressed);
    println!(
        "q = 0.4, z = 100, {TRIALS} trials: compressed {:.3} ({}), honest baseline {:.3} ({})",
        compressed.p(),
        compressed.hits,
        honest.p(),
        honest.hits
    );
    assert!(honest.p() <= 0.05, "baseline {honest:?}");
    assert!(compressed.p() >= 0.20, "attack {compressed:?}");
    assert!(
        compressed.p() - honest.p() >= 0.15,
        "attack {compressed:?} vs baseline {honest:?}"
    );
}

/// 03-F3: no fixed timestamp-lowering family gains more than 1% blocks per hour
/// over honest stamping on the current rule (same solve-time draws).
#[test]
fn f3_timestamp_lowering_gains_at_most_one_percent() {
    let seed = derive(SEED, &[3]);
    let blocks = 1_500;
    let honest = lowering_run(
        &CURRENT,
        &blacksilk_daa_sim::scenarios::Strategy::Honest,
        blocks,
        seed,
    );
    let strategies = fixed_strategies();
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get().min(4));
    let totals = par_map(&strategies, threads, |s| {
        lowering_run(&CURRENT, s, blocks, seed)
    });
    for (s, t) in strategies.iter().zip(totals) {
        let gain = honest / t - 1.0;
        assert!(gain <= 0.01, "{} gains {:+.2}%", s.label(), 100.0 * gain);
    }
}
