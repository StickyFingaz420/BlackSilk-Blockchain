//! Consensus golden vectors (T-3).
//!
//! Every expected value in this file was derived from the **specification**
//! (docs/consensus.md §2–§7), not from this crate's output: by hand where the
//! arithmetic is short (derivations in the comments), otherwise with an
//! independent Python script that implements the spec pseudocode and uses
//! `hashlib.blake2b(digest_size = 32)` for `H`. The genesis ids it produced
//! agree with the ids pinned in `params.rs` and docs/consensus.md §1.
//!
//! These tests exist so that an arithmetic change in the consensus code (an
//! off-by-one in a weight, a different clamp, another divisor) fails loudly
//! instead of passing loose range checks.

use blacksilk_consensus::difficulty::next_difficulty;
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::pow::{check_hash, seed_height};
use blacksilk_consensus::timestamp::{after_median_time_past, median, within_future_limit};
use blacksilk_consensus::{
    BlockHeader, ChainParams, Hash, HeaderChain, HeaderError, PowFunction, HEADER_VERSION,
};
use std::sync::{Arc, Mutex};

const T: u64 = 120;
const N: usize = 60;
const D0: u64 = 777;

/// History from `(solve time, difficulty)` pairs, starting at t = 1 000 000 with
/// cumulative difficulty equal to the first block's difficulty (its value does
/// not matter: only differences of `C` enter the formula).
fn history(blocks: &[(u64, u64)]) -> (Vec<u64>, Vec<u128>) {
    let mut ts = vec![1_000_000u64];
    let mut cd = vec![blocks.first().map_or(1, |b| b.1) as u128];
    for &(st, d) in blocks {
        ts.push(ts.last().unwrap() + st);
        cd.push(cd.last().unwrap() + d as u128);
    }
    (ts, cd)
}

fn lwma(ts: &[u64], cd: &[u128]) -> u64 {
    next_difficulty(ts, cd, T, N, D0)
}

fn lwma_blocks(blocks: &[(u64, u64)]) -> u64 {
    let (ts, cd) = history(blocks);
    lwma(&ts, &cd)
}

// ---------------------------------------------------------------- LWMA (§4)

#[test]
fn lwma_steady_state_is_exact() {
    // n = 60, st = T, d = D: L = T·Σi = 1830·T, S = 60·D,
    // next = 60·D·T·61 / (2·1830·T) = D exactly.
    assert_eq!(lwma_blocks(&[(T, 10_000); 60]), 10_000);
}

#[test]
fn lwma_hashrate_doubles_and_halves() {
    // st = T/2: L = 60·1830 = 109 800; next = 600 000·120·61 / 219 600 = 20 000.
    assert_eq!(lwma_blocks(&[(T / 2, 10_000); 60]), 20_000);
    // st = 2T: L = 240·1830 = 439 200; next = 4 392 000 000 / 878 400 = 5 000.
    assert_eq!(lwma_blocks(&[(2 * T, 10_000); 60]), 5_000);
}

#[test]
fn lwma_only_the_last_window_counts() {
    // 39 wildly different blocks before a steady window of 60: only the last
    // N + 1 entries are used, so the result is the steady-state value.
    let mut blocks = vec![(7u64, 999_999u64); 39];
    blocks.extend([(T, 10_000); 60]);
    assert_eq!(lwma_blocks(&blocks), 10_000);
    // Longer steady history: same.
    assert_eq!(lwma_blocks(&[(T, 10_000); 200]), 10_000);
}

#[test]
fn lwma_window_fill_phase() {
    // n = 0 (only genesis): D0.
    assert_eq!(lwma(&[5], &[1]), D0);
    // n = 1: next = d1·T·2 / (2·max(st, T/20)) = d1·T / max(st, 6).
    assert_eq!(lwma(&[1000, 1120], &[100, 200]), 100); // st = T
    assert_eq!(lwma(&[1000, 1030], &[100, 200]), 400); // st = T/4
                                                       // Equal timestamps: this = prev + 1, st = 1, L = max(1, 1·1·120/20 = 6) = 6:
                                                       // 100·120·2 / 12 = 2000.
    assert_eq!(lwma(&[1000, 1000], &[100, 200]), 2_000);
    // n = 10, mixed (st_i = 60 + 37i mod 200, d_i = 1000 + 113i mod 500): script.
    let blocks: Vec<(u64, u64)> = (1..=10u64)
        .map(|i| (60 + (i * 37) % 200, 1000 + (i * 113) % 500))
        .collect();
    assert_eq!(lwma_blocks(&blocks), 844);
}

#[test]
fn lwma_out_of_order_timestamps() {
    // t = [0, 50, 40, 400], d = [100, 200, 300]:
    //   i=1: this=50, st=50, L=50
    //   i=2: 40 ≤ 50 -> this=51, st=1, L=52
    //   i=3: this=400, st=349 (measured from 51, not 40 or 50), L=52+1047=1099
    //   floor 3·3·120/20 = 54; S = 600; next = 600·120·4 / 2198 = 131.
    assert_eq!(lwma(&[0, 50, 40, 400], &[5, 105, 305, 605]), 131);
    // Every timestamp 3 s earlier than its predecessor (d = 500 each): script.
    let ts: Vec<u64> = (0..61u64).map(|i| 10_000 - 3 * i).collect();
    let cd: Vec<u128> = (0..61u128).map(|i| i * 500).collect();
    assert_eq!(lwma(&ts, &cd), 5_083);
}

#[test]
fn lwma_solve_time_cap_is_6t() {
    // t = [0, 120, 120 + x], d = [1000, 1000]: i=1 st=120, i=2 st=min(720, x).
    // x ≥ 720: L = 120 + 2·720 = 1560; next = 2000·120·3 / 3120 = 230.
    assert_eq!(lwma(&[0, 120, 10_120], &[0, 1000, 2000]), 230);
    assert_eq!(lwma(&[0, 120, 840], &[0, 1000, 2000]), 230); // exactly 6T
    assert_eq!(lwma(&[0, 120, 841], &[0, 1000, 2000]), 230); // 6T + 1: capped
                                                             // x = 719 (below the cap): L = 120 + 1438 = 1558; 720 000 / 3116 = 231.
    assert_eq!(lwma(&[0, 120, 839], &[0, 1000, 2000]), 231);
    // A cap of 7T would give L = 1800 and 200 for the first case.
}

#[test]
fn lwma_increase_floor_is_n2_t_over_20() {
    // All timestamps equal: st = 1 each, L = 1830 < floor 60·60·120/20 = 21 600.
    // next = 600 000·120·61 / 43 200 = 101 666 (a divisor of 19 would give 96 583).
    assert_eq!(lwma_blocks(&[(0, 10_000); 60]), 101_666);
}

#[test]
fn lwma_clamps() {
    // Lower clamp: d = 1, st = 6T: next = 60·120·61 / (2·720·1830) = 0 -> 1.
    assert_eq!(lwma_blocks(&[(6 * T, 1); 60]), 1);
    assert_eq!(lwma_blocks(&[(1_000_000, 1); 60]), 1);
    // Upper clamp: d = u64::MAX with equal timestamps would give ~10.17·u64::MAX.
    assert_eq!(lwma_blocks(&[(0, u64::MAX); 60]), u64::MAX);
}

#[test]
fn lwma_mixed_window() {
    // st_i = 60 + (37i mod 200), d_i = 1000 + (113i mod 500), i = 1..=60: script.
    let blocks: Vec<(u64, u64)> = (1..=60u64)
        .map(|i| (60 + (i * 37) % 200, 1000 + (i * 113) % 500))
        .collect();
    assert_eq!(lwma_blocks(&blocks), 914);
}

// ----------------------------------------------------------- timestamps (§5)

#[test]
fn median_time_past_golden() {
    // Lower middle element for an even count.
    assert_eq!(median(&[10, 40, 20, 30]), 20);
    assert_eq!(median(&[3, 1, 2]), 2);
    let eleven = [9, 1, 8, 2, 7, 3, 6, 4, 5, 11, 10];
    assert_eq!(median(&eleven), 6);
    assert!(!after_median_time_past(6, &eleven));
    assert!(after_median_time_past(7, &eleven));
    // FTL: ≤ now + 360.
    assert!(within_future_limit(1_000 + 360, 1_000, 360));
    assert!(!within_future_limit(1_000 + 361, 1_000, 360));
}

// ------------------------------------------ header chain integration (§4–§6)

/// PoW that accepts everything and records the seeds it was asked for.
#[derive(Default)]
struct RecordingPow(Mutex<Vec<Hash>>);

impl PowFunction for RecordingPow {
    fn pow_hash(&self, seed: &Hash, _header: &[u8]) -> Hash {
        self.0.lock().unwrap().push(*seed);
        [0; 32] // satisfies every difficulty ≥ 1
    }
}

fn regtest_d0(d0: u64) -> ChainParams {
    let mut p = ChainParams::regtest();
    p.initial_difficulty = d0;
    p.genesis.difficulty = d0;
    p
}

fn child(chain: &HeaderChain, timestamp: u64) -> BlockHeader {
    let t = chain.template();
    BlockHeader {
        version: HEADER_VERSION,
        height: t.height,
        prev_id: t.prev_id,
        timestamp,
        difficulty: t.difficulty,
        tx_root: [0; 32],
        nonce: 0,
    }
}

/// Difficulties of blocks 1..=150 on regtest (T = 10, N = 60) with D0 = 1000,
/// genesis time 1 700 000 000 and block h at `t[h-1] + PATTERN[h mod 12]`,
/// from the spec pseudocode (script). The pattern includes decreasing
/// timestamps and solve times above 6T = 60.
const PATTERN: [i64; 12] = [10, 3, 25, -2, 1, 12, 10, 7, 70, -5, 4, 9];
const CHAIN_DIFFICULTIES: [u64; 150] = [
    1000, 3333, 1226, 1985, 3143, 3053, 2914, 3112, 1281, 1496, 1738, 1870, 1890, 2092, 1754, 1957,
    2181, 2202, 2198, 2264, 1501, 1617, 1739, 1802, 1811, 1910, 1734, 1845, 1962, 1976, 1978, 2016,
    1547, 1625, 1705, 1745, 1751, 1816, 1698, 1773, 1851, 1862, 1864, 1891, 1556, 1613, 1673, 1702,
    1706, 1754, 1667, 1723, 1781, 1789, 1791, 1811, 1552, 1598, 1645, 1668, 1671, 1722, 1630, 1684,
    1732, 1722, 1707, 1710, 1465, 1508, 1553, 1574, 1575, 1608, 1537, 1580, 1623, 1626, 1622, 1634,
    1410, 1448, 1488, 1507, 1507, 1540, 1473, 1513, 1555, 1559, 1558, 1572, 1358, 1393, 1431, 1448,
    1449, 1480, 1416, 1454, 1494, 1499, 1499, 1512, 1307, 1340, 1376, 1392, 1392, 1421, 1360, 1396,
    1434, 1439, 1438, 1451, 1255, 1285, 1319, 1334, 1333, 1361, 1302, 1335, 1372, 1375, 1375, 1387,
    1200, 1229, 1261, 1276, 1276, 1303, 1246, 1279, 1314, 1318, 1318, 1331, 1151, 1179, 1210, 1224,
    1224, 1250, 1196, 1227, 1261, 1265,
];

#[test]
fn header_chain_difficulty_and_mtp_golden() {
    let params = regtest_d0(1000);
    let mut chain = HeaderChain::new(params, Arc::new(RecordingPow::default()));
    let mut t = 1_700_000_000i64;
    // Median-time-past before blocks 1, 2, 3, 6, 11, 12, 21, 150 (script).
    let mtp_at = [
        (1u64, 1_700_000_000u64),
        (2, 1_700_000_000),
        (3, 1_700_000_003),
        (6, 1_700_000_026),
        (11, 1_700_000_039),
        (12, 1_700_000_049),
        (21, 1_700_000_171),
        (150, 1_700_001_728),
    ];
    for h in 1..=150u64 {
        let tpl = chain.template();
        assert_eq!(tpl.height, h);
        assert_eq!(
            tpl.difficulty,
            CHAIN_DIFFICULTIES[h as usize - 1],
            "difficulty of block {h}"
        );
        if let Some(&(_, mtp)) = mtp_at.iter().find(|(x, _)| *x == h) {
            assert_eq!(tpl.min_timestamp, mtp + 1, "MTP before block {h}");
            // The rule is strict: a timestamp equal to the MTP is refused.
            let mut at_mtp = child(&chain, mtp);
            at_mtp.nonce = 1;
            assert!(matches!(
                chain.validate(&at_mtp, u64::MAX),
                Err(HeaderError::TimestampTooOld { .. })
            ));
        }
        // A wrong difficulty (±1) is refused.
        for delta in [1i64, -1] {
            let mut bad = child(&chain, (t + PATTERN[h as usize % 12]) as u64);
            bad.difficulty = (bad.difficulty as i64 + delta) as u64;
            assert!(matches!(
                chain.validate(&bad, u64::MAX),
                Err(HeaderError::BadDifficulty { .. })
            ));
        }
        t += PATTERN[h as usize % 12];
        chain.accept(child(&chain, t as u64), u64::MAX).unwrap();
    }
    // Work: genesis + every block's difficulty.
    let total: u128 = 1000 + CHAIN_DIFFICULTIES.iter().map(|&d| d as u128).sum::<u128>();
    assert_eq!(total, 242_100); // script
    assert_eq!(chain.best_work(), total);
}

// ------------------------------------------------------ RandomX seed (§3.1)

#[test]
fn seed_height_schedule_golden() {
    // seed_height(h) = 0 if h ≤ E + L else (h − L − 1) & !(E − 1), E = 2048, L = 64.
    let cases = [
        (0u64, 0u64),
        (1, 0),
        (64, 0),
        (2048, 0),
        (2112, 0),
        (2113, 2048),
        (2114, 2048),
        (4096, 2048),
        (4160, 2048),
        (4161, 4096),
        (6208, 4096),
        (6209, 6144),
        (1_000_000, 999_424),
    ];
    for (h, s) in cases {
        assert_eq!(seed_height(h, 2048, 64), s, "height {h}");
    }
}

#[test]
fn header_chain_uses_the_spec_seed_block() {
    // A regtest chain to height 4161 with the network's E = 2048, L = 64: the
    // template's seed and the seed handed to the PoW function are the id of the
    // main-chain block at the spec's seed height.
    let pow = Arc::new(RecordingPow::default());
    let mut chain = HeaderChain::new(regtest_d0(1), pow.clone());
    let genesis = chain.tip_id();
    let expect = [
        (1u64, 0u64),
        (2112, 0),
        (2113, 2048),
        (4160, 2048),
        (4161, 4096),
    ];
    let mut t = 1_700_000_000u64;
    for h in 1..=4161u64 {
        let tpl = chain.template();
        if let Some(&(_, s)) = expect.iter().find(|(x, _)| *x == h) {
            let want = chain.main_id_at(s).unwrap();
            assert_eq!(tpl.seed_id, want, "seed for height {h}");
            if s == 0 {
                assert_eq!(want, genesis);
            }
        }
        t += 10;
        chain.accept(child(&chain, t), u64::MAX).unwrap();
        if let Some(&(_, s)) = expect.iter().find(|(x, _)| *x == h) {
            let used = *pow.0.lock().unwrap().last().unwrap();
            assert_eq!(used, chain.main_id_at(s).unwrap(), "PoW seed at {h}");
        }
    }
}

// ------------------------------------------------ header and block id (§2)

fn hex(b: &[u8]) -> String {
    hex::encode(b)
}

#[test]
fn header_bytes_and_id_golden() {
    let h = BlockHeader {
        version: 1,
        height: 42,
        prev_id: [7; 32],
        timestamp: 1_800_000_000,
        difficulty: 12_345,
        tx_root: [9; 32],
        nonce: 0xDEAD_BEEF,
    };
    // Layout of §2, written out field by field (script).
    assert_eq!(
        hex(&h.to_bytes()),
        "01000000\
         2a00000000000000\
         0707070707070707070707070707070707070707070707070707070707070707\
         00d2496b00000000\
         3930000000000000\
         0909090909090909090909090909090909090909090909090909090909090909\
         efbeadde00000000"
    );
    // id = Blake2b-256("BlackSilk/block-id" ‖ LE32(network_id) ‖ header) (script).
    assert_eq!(
        hex(&h.id(0x00DE_B06E)),
        "4b798523f86f62286ac96f847da2b92c19482ae1dad2a36ffec8bb4b7d21b9b7"
    );
    assert_eq!(
        hex(&h.id(0x0001_D672)),
        "049e180a7fa223456981bdb0b4f97d5dbc04d4f971ad5479bc917328c3069a5f"
    );
}

#[test]
fn genesis_ids_golden() {
    // From the §1 parameters (version 1, height 0, zero prev_id and tx_root,
    // timestamp, D0, nonce 0) with the script; the testnet value is also the
    // one printed in docs/consensus.md §1.
    assert_eq!(
        hex(&ChainParams::testnet().genesis_id()),
        "6556f92dee4df050cfb113a2b4ba234794274854b69f7c8a39755ec7a66b037d"
    );
    assert_eq!(
        hex(&ChainParams::regtest().genesis_id()),
        "087d6fd4efbc45eb0a895dd0680a7fd305208cae239b1b4275d7148b29a569b7"
    );
    // Mainnet genesis time is provisional (§1): this pins today's value only.
    assert_eq!(
        hex(&ChainParams::mainnet().genesis_id()),
        "5f6a73da4d6f67fcb4487942d9ff6b7066b668f23bc6a739e2a17d5a8b358ed4"
    );
}

// ------------------------------------------------------- Merkle root (§7)

#[test]
fn merkle_root_golden() {
    let ids: Vec<Hash> = (1..=5u8).map(|i| [i; 32]).collect();
    let expected = [
        "6bf22d230bc6f17e2dc9bdce220e8696630a067ab5029fb66d91e6ecd74c7c54",
        "e7ee5228698f31758aa7e13445bc54d4c4b37303a90d5ca4677fad9976d1187b",
        "a7346514f635523b73d3adb12bf49a26cf1a8063afc422025e203cde74e5ecbe",
        "0109df2aab187b4d42772b14ecca768edafd14ef2665d1fe94c9d2022ee8658b",
        "daf740e7aa956cb636ee5d465a8d6fe03480fcfe405ebe98a17dd888bab43bb5",
    ];
    for (k, e) in expected.iter().enumerate() {
        assert_eq!(hex(&tx_root(&ids[..k + 1])), *e, "{} leaves", k + 1);
    }
    assert_eq!(tx_root(&[]), [0; 32]);
}

// ------------------------------------------------------- check_hash (§3)

fn from_hex(s: &str) -> Hash {
    hex::decode(s).unwrap().try_into().unwrap()
}

#[test]
fn check_hash_boundaries_golden() {
    // For each d: h_max = floor((2^256 − 1) / d) satisfies h·d < 2^256, and
    // h_max + 1 does not (script; 32-byte little-endian).
    let cases = [
        (
            2u64,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "0000000000000000000000000000000000000000000000000000000000000080",
        ),
        (
            3,
            "5555555555555555555555555555555555555555555555555555555555555555",
            "5655555555555555555555555555555555555555555555555555555555555555",
        ),
        (
            12_345,
            "3d8d8d06e46c650d4a752869b9abdfce4891b245d70bed217c8e717c074f0500",
            "3e8d8d06e46c650d4a752869b9abdfce4891b245d70bed217c8e717c074f0500",
        ),
        (
            (1 << 32) + 1,
            "ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000",
            "0000000001000000ffffffff00000000ffffffff00000000ffffffff00000000",
        ),
        (
            u64::MAX,
            "0100000000000000010000000000000001000000000000000100000000000000",
            "0200000000000000010000000000000001000000000000000100000000000000",
        ),
    ];
    for (d, max_ok, min_bad) in cases {
        assert!(check_hash(&from_hex(max_ok), d), "h_max for d = {d}");
        assert!(!check_hash(&from_hex(min_bad), d), "h_max + 1 for d = {d}");
        assert!(check_hash(&[0; 32], d));
        assert!(!check_hash(&[0xff; 32], d));
    }
    assert!(check_hash(&[0xff; 32], 1));
    assert!(!check_hash(&[0; 32], 0), "difficulty 0 is invalid");
}
