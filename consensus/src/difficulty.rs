//! LWMA-1 difficulty adjustment (spec §4).

/// Next difficulty from the most recent ancestors, oldest first, ending with the parent.
///
/// `timestamps[i]` and `cumulative[i]` (cumulative difficulty including block i) belong to
/// the same block. At most `window + 1` entries are used (the most recent ones).
pub fn next_difficulty(
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
    // Bound the maximum increase (and keep the divisor non-zero).
    weighted = weighted.max(n * n * t / 20).max(1);

    let next = sum_difficulty * t * (n + 1) / (2 * weighted);
    next.clamp(1, u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: u64 = 120;
    const N: usize = 60;

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
    fn steady_state_is_stable() {
        let d = next(&vec![(T, 10_000); 200]);
        // LWMA has a small known bias: stays within 2% of the true value.
        assert!((9_800..=10_200).contains(&d), "{d}");
    }

    #[test]
    fn responds_to_hashrate_changes() {
        let fast = next(&vec![(T / 2, 10_000); 200]);
        assert!(
            (19_000..=21_000).contains(&fast),
            "2x hashrate -> ~2x difficulty: {fast}"
        );
        let slow = next(&vec![(2 * T, 10_000); 200]);
        assert!(
            (4_750..=5_250).contains(&slow),
            "half hashrate -> ~half difficulty: {slow}"
        );
    }

    #[test]
    fn increase_is_bounded_and_timestamps_cannot_break_it() {
        // All blocks at the same second (or going backwards): no division by zero,
        // and the increase is capped by the minimum weighted solve time.
        let (mut ts, cd) = history(&vec![(0, 10_000); 100]);
        for (i, t) in ts.iter_mut().enumerate() {
            *t -= i as u64 % 7; // out of order
        }
        let d = next_difficulty(&ts, &cd, T, N, 1);
        // Upper bound: sum_D * T * (n+1) / (2 * n^2 T / 20) = 10 * D * (n+1) / n.
        assert!(d <= 10_000 * 10 * 61 / 60 + 1, "{d}");
        assert!(d > 10_000, "{d}");
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
}
