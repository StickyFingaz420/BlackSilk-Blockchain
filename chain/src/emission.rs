//! Emission schedule (docs/blocks.md §1–§2): smooth emission with a permanent tail.

/// Atomic units per BLK.
pub const COIN: u64 = 100_000_000;
/// `M`: the main emission asymptote, 21 million BLK.
pub const MONEY_SUPPLY: u64 = 21_000_000 * COIN;
/// `S`: the emission speed shift for 120-second blocks.
pub const EMISSION_SPEED: u32 = 20;
/// Minimum block reward, paid forever: 0.6 BLK.
pub const TAIL_REWARD: u64 = 60_000_000;

/// `reward(h)` given `generated = G(h)`, the coins created by blocks `1..h` on the
/// same branch (fees excluded).
pub fn block_reward(height: u64, generated: u64) -> u64 {
    if height == 0 {
        return 0; // genesis has no transactions
    }
    let base = MONEY_SUPPLY.saturating_sub(generated) >> EMISSION_SPEED;
    base.max(TAIL_REWARD)
}

/// Formats atomic units as BLK with 8 decimals, e.g. `20.02716064`.
pub fn format_amount(atomic: u64) -> String {
    format!("{}.{:08}", atomic / COIN, atomic % COIN)
}

/// Parses a BLK amount such as `12`, `0.5` or `3.14159265` into atomic units.
/// Strict: no sign, at most 8 decimals, no overflow.
pub fn parse_amount(s: &str) -> Option<u64> {
    let (int, frac) = match s.split_once('.') {
        Some((i, f)) => (i, f),
        None => (s, ""),
    };
    if int.is_empty() && frac.is_empty() {
        return None;
    }
    if frac.len() > 8 || !int.bytes().chain(frac.bytes()).all(|b| b.is_ascii_digit()) {
        return None;
    }
    let int: u64 = if int.is_empty() { 0 } else { int.parse().ok()? };
    let mut frac_units: u64 = if frac.is_empty() {
        0
    } else {
        frac.parse().ok()?
    };
    for _ in frac.len()..8 {
        frac_units *= 10;
    }
    int.checked_mul(COIN)?.checked_add(frac_units)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOCKS_PER_YEAR: u64 = 262_800;

    fn emitted_after(blocks: u64) -> (u64, Option<u64>) {
        let mut g = 0u64;
        let mut tail_start = None;
        for h in 1..=blocks {
            let r = block_reward(h, g);
            if r == TAIL_REWARD && tail_start.is_none() {
                tail_start = Some(h);
            }
            g += r;
        }
        (g, tail_start)
    }

    #[test]
    fn first_rewards() {
        assert_eq!(block_reward(0, 0), 0);
        assert_eq!(block_reward(1, 0), 2_002_716_064); // 20.02716064 BLK
        assert_eq!(block_reward(1, MONEY_SUPPLY), TAIL_REWARD);
        assert_eq!(block_reward(1, u64::MAX), TAIL_REWARD);
    }

    #[test]
    fn curve_matches_spec() {
        // docs/blocks.md §2 table.
        let (g1, _) = emitted_after(BLOCKS_PER_YEAR);
        assert_eq!(g1 / COIN, 4_655_414);
        let (g4, _) = emitted_after(4 * BLOCKS_PER_YEAR);
        assert_eq!(g4 / COIN, 13_293_843);
        let (g, tail) = emitted_after(4_000_000);
        assert_eq!(tail, Some(3_678_315));
        assert!(g < u64::MAX / 1000, "no overflow risk for millennia");
    }

    #[test]
    fn reward_is_monotone_non_increasing() {
        let mut g = 0u64;
        let mut prev = u64::MAX;
        for h in 1..200_000 {
            let r = block_reward(h, g);
            assert!(r <= prev && r >= TAIL_REWARD);
            prev = r;
            g += r;
        }
    }

    #[test]
    fn amounts() {
        assert_eq!(format_amount(2_002_716_064), "20.02716064");
        assert_eq!(format_amount(1), "0.00000001");
        assert_eq!(parse_amount("20.02716064"), Some(2_002_716_064));
        assert_eq!(parse_amount("0.5"), Some(50_000_000));
        assert_eq!(parse_amount("12"), Some(12 * COIN));
        assert_eq!(parse_amount(".25"), Some(25_000_000));
        for bad in [
            "",
            ".",
            "1.123456789",
            "-1",
            "1,5",
            "1e3",
            " 1",
            "184467440738",
        ] {
            assert_eq!(parse_amount(bad), None, "{bad}");
        }
        assert_eq!(parse_amount(&format_amount(u64::MAX)), Some(u64::MAX));
    }
}
