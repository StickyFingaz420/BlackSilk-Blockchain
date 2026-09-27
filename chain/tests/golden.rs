//! Emission golden vectors (T-3), derived from docs/blocks.md §2 with an
//! independent Python script implementing
//! `reward(h) = max(TAIL, (M − G(h)) >> S)` (`reward(0) = 0`, TAIL once
//! `G(h) ≥ M`), `M = 21e6·10^8`, `S = 20`, `TAIL = 6·10^7`,
//! `G(h) = Σ reward(i), 0 < i < h`. Not copied from this crate's output.

use blacksilk_chain::emission::{block_reward, COIN, MONEY_SUPPLY, TAIL_REWARD};

/// `(h, G(h), reward(h))` from the script.
const POINTS: [(u64, u64, u64); 11] = [
    (1, 0, 2_002_716_064),
    (2, 2_002_716_064, 2_002_714_154),
    (3, 4_005_430_218, 2_002_712_244),
    (262_800, 465_539_846_280_723, 1_558_742_669),
    (262_801, 465_541_405_023_392, 1_558_741_183),
    (1_000_000, 1_290_822_089_776_647, 771_692_190),
    (1_051_201, 1_329_384_377_843_153, 734_916_326),
    (3_678_314, 2_037_085_395_466_954, 60_000_042), // last reward above the tail
    (3_678_315, 2_037_085_455_466_996, 60_000_000), // tail starts (blocks.md §2)
    (3_678_316, 2_037_085_515_466_996, 60_000_000),
    (4_000_000, 2_056_386_555_466_996, 60_000_000),
];

#[test]
fn constants_are_the_spec() {
    assert_eq!(COIN, 100_000_000);
    assert_eq!(MONEY_SUPPLY, 2_100_000_000_000_000);
    assert_eq!(TAIL_REWARD, 60_000_000);
}

#[test]
fn reward_at_pinned_points() {
    assert_eq!(block_reward(0, 0), 0, "genesis pays nothing");
    for (h, g, r) in POINTS {
        assert_eq!(block_reward(h, g), r, "reward({h})");
    }
    // (M − G) >> 20 just above and at the tail threshold:
    // (M − G) = 60 000 001·2^20 − 1 -> 60 000 000 (floor); ≥ M -> TAIL.
    let g = MONEY_SUPPLY - (60_000_001u64 << 20) + 1;
    assert_eq!(block_reward(5, g), 60_000_000);
    let g = MONEY_SUPPLY - (60_000_001u64 << 20);
    assert_eq!(block_reward(5, g), 60_000_001);
    assert_eq!(block_reward(5, MONEY_SUPPLY), TAIL_REWARD);
    assert_eq!(block_reward(5, u64::MAX), TAIL_REWARD);
}

#[test]
fn cumulative_emission_matches_the_script() {
    // Running the recurrence reproduces every pinned G(h), the tail start
    // 3 678 315 and G(4 000 001).
    let mut g = 0u64;
    let mut tail_start = None;
    let mut next = 0;
    for h in 1..=4_000_000u64 {
        if next < POINTS.len() && POINTS[next].0 == h {
            assert_eq!(g, POINTS[next].1, "G({h})");
            next += 1;
        }
        let r = block_reward(h, g);
        if r == TAIL_REWARD && tail_start.is_none() {
            tail_start = Some(h);
        }
        g += r;
    }
    assert_eq!(next, POINTS.len());
    assert_eq!(tail_start, Some(3_678_315));
    assert_eq!(g, 2_056_386_615_466_996);
}
