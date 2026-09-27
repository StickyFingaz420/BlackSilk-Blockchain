//! LWMA-1 difficulty adjustment with a counted clock (spec §4).
//!
//! The rule of testnet v3 (docs/reviews/v3-consensus-changes.md, section
//! "daa-lwma75-warm"; evidence in docs/evidence/daa-sim-2026-09-27/):
//! - the window is the last `N` solve times (`N = 75` on every network);
//! - each solve time is counted on a clock that advances at least
//!   `step = max(1, T/2)` per block: `this = max(ts[i], prev + step)`, and at
//!   most `6T` of it counts;
//! - the clock is warmed over the [`DIFFICULTY_WARMUP`] blocks before the window,
//!   so a single low stamp at the window's start cannot restart it low;
//! - the weighted sum is floored at `n²T/20`, and the result is clamped to
//!   `[1, u64::MAX]`.

/// The window `N` of every built-in network.
pub const DIFFICULTY_WINDOW: usize = 75;

/// Blocks before the window over which the counted clock is warmed up (the MTP
/// window: a stamp can lie low only relative to that many predecessors).
pub const DIFFICULTY_WARMUP: usize = 11;

/// Identifies the difficulty rule, for the consensus fingerprint: two builds
/// with the same parameters but different rule code must not look alike.
pub const DIFFICULTY_RULE_ID: &str = "lwma1-n75-step-t/2-warm11-cap6t-floor20";

/// Ancestors (ending with the parent) that [`next_difficulty`] reads for a window
/// of `window` blocks: the window's `window + 1` stamps plus the warm-up. Every
/// caller fetches exactly this many (fewer only near genesis), so the count
/// cannot diverge between the validation, template and batch paths.
pub const fn difficulty_ancestors(window: usize) -> usize {
    window + 1 + DIFFICULTY_WARMUP
}

/// The counted clock's minimum advance per block: `max(1, T/2)`.
pub const fn clock_step(target: u64) -> u64 {
    if target / 2 > 1 {
        target / 2
    } else {
        1
    }
}

/// Next difficulty from the most recent ancestors, oldest first, ending with the
/// parent.
///
/// `timestamps[i]` and `cumulative[i]` (cumulative difficulty including block i)
/// belong to the same block. The last `window + 1` entries form the window; up to
/// [`DIFFICULTY_WARMUP`] entries before it warm the counted clock. Earlier entries
/// are ignored. With fewer entries (near genesis) the window and then the warm-up
/// start at the oldest entry given. With a single entry (genesis only) the result
/// is `initial`.
///
/// Arithmetic: every intermediate is `u128`. The largest is
/// `sum_difficulty · T · (n + 1)`, below `n·2^64 · T · (n + 1)`, which fits for
/// `T·N·(N + 1) < 2^64` (every network; at N = 75: T < 2^51). The clock stays below
/// `max(ts) + (N + 11)·step`.
pub fn next_difficulty(
    timestamps: &[u64],
    cumulative: &[u128],
    target: u64,
    window: usize,
    initial: u64,
) -> u64 {
    assert_eq!(timestamps.len(), cumulative.len());
    let len = timestamps.len();
    let take = len.min(window + 1);
    let n = take.saturating_sub(1) as u128;
    if n == 0 {
        return initial;
    }
    let t = target as u128;
    let step = clock_step(target) as u128;

    // The window's oldest block, and the start of the warm-up before it.
    let w0 = len - take;
    let from = w0.saturating_sub(DIFFICULTY_WARMUP);
    let mut prev = timestamps[from] as u128;
    for &ts in &timestamps[from + 1..=w0] {
        prev = (ts as u128).max(prev + step);
    }

    let mut weighted: u128 = 0;
    let mut sum_difficulty: u128 = 0;
    for i in 1..take {
        let this = (timestamps[w0 + i] as u128).max(prev + step);
        let solve_time = (this - prev).min(6 * t);
        prev = this;
        weighted += i as u128 * solve_time;
        sum_difficulty += cumulative[w0 + i] - cumulative[w0 + i - 1];
    }
    // Bound the maximum increase (and keep the divisor non-zero).
    weighted = weighted.max(n * n * t / 20).max(1);

    let next = sum_difficulty * t * (n + 1) / (2 * weighted);
    next.clamp(1, u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: u64 = 120;
    const N: usize = DIFFICULTY_WINDOW;

    /// Builds a chain history from per-block (solve time, difficulty) pairs.
    fn history(blocks: &[(u64, u64)]) -> (Vec<u64>, Vec<u128>) {
        let mut ts = vec![1_000_000u64];
        let mut cd = vec![blocks.first().map_or(1, |b| b.1) as u128];
        for &(st, d) in blocks {
            ts.push(ts.last().unwrap() + st);
            cd.push(cd.last().unwrap() + d as u128);
        }
        (ts, cd)
    }

    fn next(blocks: &[(u64, u64)]) -> u64 {
        let (ts, cd) = history(blocks);
        next_difficulty(&ts, &cd, T, N, 777)
    }

    #[test]
    fn genesis_only_uses_initial() {
        assert_eq!(next_difficulty(&[5], &[1], T, N, 777), 777);
    }

    #[test]
    fn ancestors_and_step() {
        assert_eq!(difficulty_ancestors(N), 87);
        assert_eq!(clock_step(120), 60);
        assert_eq!(clock_step(10), 5);
        assert_eq!(clock_step(3), 1);
        assert_eq!(clock_step(2), 1);
        assert_eq!(clock_step(1), 1);
        assert_eq!(clock_step(0), 1);
    }

    #[test]
    fn steady_state_is_exact() {
        // On-target stamps count T each, so the next difficulty is exact.
        assert_eq!(next(&vec![(T, 10_000); 200]), 10_000);
    }

    #[test]
    fn responds_to_hashrate_changes() {
        // Exact at 2x: every solve time T/2 is exactly one step.
        assert_eq!(next(&vec![(T / 2, 10_000); 200]), 20_000);
        assert_eq!(next(&vec![(2 * T, 10_000); 200]), 5_000);
    }

    #[test]
    fn increase_is_bounded_by_the_step() {
        // All blocks at the same second (or going backwards): each counts one
        // step, so the rise is at most T/step = 2x the window average.
        let (mut ts, cd) = history(&vec![(0, 10_000); 100]);
        for (i, t) in ts.iter_mut().enumerate() {
            *t -= i as u64 % 7; // out of order
        }
        let d = next_difficulty(&ts, &cd, T, N, 1);
        assert_eq!(d, 20_000);
    }

    #[test]
    fn single_huge_timestamp_is_capped() {
        let mut blocks = vec![(T, 10_000); 100];
        blocks.push((1_000_000, 10_000)); // one block claims a ~12-day solve time
        let d = next(&blocks);
        // The solve time is capped at 6T, so one lie cannot crater the difficulty.
        assert!(d > 8_000, "{d}");
    }

    #[test]
    fn early_chain_uses_short_window() {
        let d = next(&[(T / 4, 100), (T / 4, 100), (T / 4, 100)]);
        assert!(d > 100, "fast early blocks raise difficulty: {d}");
        assert!(next(&[(T * 10, 100)]) >= 1);
    }

    #[test]
    fn never_zero() {
        let d = next(&vec![(6 * T, 1); 100]);
        assert_eq!(d, 1);
    }

    /// Entries older than the warm-up are ignored.
    #[test]
    fn only_the_last_87_entries_matter() {
        let (mut ts, cd) = history(&vec![(T, 10_000); 200]);
        let want = next_difficulty(&ts, &cd, T, N, 1);
        let from = ts.len() - difficulty_ancestors(N);
        ts[from - 1] = 0;
        assert_eq!(next_difficulty(&ts, &cd, T, N, 1), want);
        assert_eq!(next_difficulty(&ts[from..], &cd[from..], T, N, 1), want);
    }

    /// The rule identifier names the constants the code uses: a change of the
    /// window or the warm-up without a new identifier fails here.
    #[test]
    fn rule_id_names_the_parameters() {
        assert_eq!(
            DIFFICULTY_RULE_ID,
            format!("lwma1-n{DIFFICULTY_WINDOW}-step-t/2-warm{DIFFICULTY_WARMUP}-cap6t-floor20")
        );
    }
}
