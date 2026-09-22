//! Timestamp rules (spec §5).

/// Median of `timestamps` (lower middle element for an even count).
pub fn median(timestamps: &[u64]) -> u64 {
    assert!(!timestamps.is_empty());
    let mut v = timestamps.to_vec();
    v.sort_unstable();
    v[(v.len() - 1) / 2]
}

/// Median-time-past rule: strictly after the median of the recent ancestors.
pub fn after_median_time_past(timestamp: u64, recent: &[u64]) -> bool {
    timestamp > median(recent)
}

/// Future-time-limit rule (depends on the local clock; not a permanent verdict).
pub fn within_future_limit(timestamp: u64, now: u64, future_time_limit: u64) -> bool {
    timestamp <= now.saturating_add(future_time_limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn median_odd_even() {
        assert_eq!(median(&[5, 1, 3]), 3);
        assert_eq!(median(&[4, 1, 3, 2]), 2);
        assert_eq!(median(&[9]), 9);
    }

    #[test]
    fn mtp_is_strict() {
        let recent = [100, 110, 120, 130, 140];
        assert!(!after_median_time_past(120, &recent));
        assert!(after_median_time_past(121, &recent));
        // A single manipulated ancestor cannot move the median much.
        assert!(after_median_time_past(121, &[100, 110, 120, 130, u64::MAX]));
    }

    #[test]
    fn future_limit() {
        assert!(within_future_limit(1360, 1000, 360));
        assert!(!within_future_limit(1361, 1000, 360));
        assert!(within_future_limit(u64::MAX, u64::MAX, 360));
    }
}
