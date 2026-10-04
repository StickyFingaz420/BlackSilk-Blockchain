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
const N: usize = 75;
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
//
// The v3 rule: N = 75, counted clock step max(1, T/2) = 60 s at T = 120, warmed
// over the 11 blocks before the window. The sum of i for i = 1..=75 is 2 850.

#[test]
fn lwma_steady_state_is_exact() {
    // n = 75, st = T, d = D: L = T·Σi = 2850·T, S = 75·D,
    // next = 75·D·T·76 / (2·2850·T) = D exactly.
    assert_eq!(lwma_blocks(&[(T, 10_000); 75]), 10_000);
}

#[test]
fn lwma_hashrate_doubles_and_halves() {
    // st = T/2 = one step: L = 60·2850 = 171 000; next = 750 000·120·76 / 342 000
    // = 20 000.
    assert_eq!(lwma_blocks(&[(T / 2, 10_000); 75]), 20_000);
    // st = 2T: L = 240·2850 = 684 000; next = 6 840 000 000 / 1 368 000 = 5 000.
    assert_eq!(lwma_blocks(&[(2 * T, 10_000); 75]), 5_000);
}

#[test]
fn lwma_only_the_last_window_counts() {
    // 39 wildly different blocks before 11 steady warm-up blocks and a steady
    // window of 75: only the last N + 1 + 11 entries are read, so the result is
    // the steady-state value.
    let mut blocks = vec![(7u64, 999_999u64); 39];
    blocks.extend([(T, 10_000); 86]);
    assert_eq!(lwma_blocks(&blocks), 10_000);
    // Longer steady history: same.
    assert_eq!(lwma_blocks(&[(T, 10_000); 200]), 10_000);
    // The warm-up does read the 11 blocks before the window: with the 7 s blocks
    // right before it, the clock enters the window 583 s ahead of its oldest
    // stamp, so the first solve times count one step each (script: 10 092).
    let mut blocks = vec![(7u64, 999_999u64); 39];
    blocks.extend([(T, 10_000); 75]);
    assert_eq!(lwma_blocks(&blocks), 10_092);
}

#[test]
fn lwma_window_fill_phase() {
    // n = 0 (only genesis): D0.
    assert_eq!(lwma(&[5], &[1]), D0);
    // n = 1 (no warm-up block exists): next = d1·T·2 / (2·max(st, T/20)) with
    // st = max(t1, t0 + 60) − t0.
    assert_eq!(lwma(&[1000, 1120], &[100, 200]), 100); // st = T
                                                       // A 30 s solve time counts one step (60): 100·120·2 / 120 = 200.
    assert_eq!(lwma(&[1000, 1030], &[100, 200]), 200);
    // Equal timestamps: also one step, 200.
    assert_eq!(lwma(&[1000, 1000], &[100, 200]), 200);
    // n = 10, mixed (st_i = 60 + 37i mod 200 ≥ one step, d_i = 1000 + 113i mod 500):
    // script. No solve time is below the step, so this is also the pre-v3 value.
    let blocks: Vec<(u64, u64)> = (1..=10u64)
        .map(|i| (60 + (i * 37) % 200, 1000 + (i * 113) % 500))
        .collect();
    assert_eq!(lwma_blocks(&blocks), 844);
}

#[test]
fn lwma_out_of_order_timestamps() {
    // t = [0, 50, 40, 400], d = [100, 200, 300], step 60:
    //   i=1: this = max(50, 0 + 60) = 60, st = 60, L = 60
    //   i=2: this = max(40, 120) = 120, st = 60, L = 180
    //   i=3: this = max(400, 180) = 400, st = 280 (from the clock, not 40 or 50),
    //        L = 180 + 840 = 1020
    //   floor 3·3·120/20 = 54; S = 600; next = 600·120·4 / 2040 = 141.
    assert_eq!(lwma(&[0, 50, 40, 400], &[5, 105, 305, 605]), 141);
    // Every timestamp 3 s earlier than its predecessor (d = 500 each, n = 60):
    // every solve time counts one step, L = 60·1830 = 109 800, S = 30 000,
    // next = 30 000·120·61 / 219 600 = 1 000.
    let ts: Vec<u64> = (0..61u64).map(|i| 10_000 - 3 * i).collect();
    let cd: Vec<u128> = (0..61u128).map(|i| i * 500).collect();
    assert_eq!(lwma(&ts, &cd), 1_000);
}

#[test]
fn lwma_solve_time_cap_is_6t() {
    // t = [0, 120, 120 + x], d = [1000, 1000]: i=1 st=120, i=2 st=min(720, x)
    // for x ≥ 60 (below 60 the step counts 60).
    // x ≥ 720: L = 120 + 2·720 = 1560; next = 2000·120·3 / 3120 = 230.
    assert_eq!(lwma(&[0, 120, 10_120], &[0, 1000, 2000]), 230);
    assert_eq!(lwma(&[0, 120, 840], &[0, 1000, 2000]), 230); // exactly 6T
    assert_eq!(lwma(&[0, 120, 841], &[0, 1000, 2000]), 230); // 6T + 1: capped
                                                             // x = 719 (below the cap): L = 120 + 1438 = 1558; 720 000 / 3116 = 231.
    assert_eq!(lwma(&[0, 120, 839], &[0, 1000, 2000]), 231);
    // A cap of 7T would give L = 1800 and 200 for the first case.
}

#[test]
fn lwma_increase_is_bounded_by_the_step() {
    // All timestamps equal: each solve time counts one step (60), L = 60·2850 =
    // 171 000, above the floor 75·75·120/20 = 33 750; next = 750 000·120·76 /
    // 342 000 = 20 000, twice the window average. The floor n²T/20 cannot bind
    // under the v3 rule: L ≥ step·n(n+1)/2 > n²T/20 for every n ≥ 1.
    // (A step of 1, the pre-v3 rule, would give 101 666 here.)
    assert_eq!(lwma_blocks(&[(0, 10_000); 75]), 20_000);
}

#[test]
fn lwma_clamps() {
    // Lower clamp: d = 1, st = 6T: next = 75·120·76 / (2·720·2850) = 0 -> 1.
    assert_eq!(lwma_blocks(&[(6 * T, 1); 75]), 1);
    assert_eq!(lwma_blocks(&[(1_000_000, 1); 75]), 1);
    // Upper clamp: d = u64::MAX with equal timestamps would give 2·u64::MAX.
    assert_eq!(lwma_blocks(&[(0, u64::MAX); 75]), u64::MAX);
}

#[test]
fn lwma_mixed_window() {
    // st_i = 60 + (37i mod 200), d_i = 1000 + (113i mod 500), i = 1..=75: script.
    let blocks: Vec<(u64, u64)> = (1..=75u64)
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
    fn pow_hash(&self, seed: &Hash, _header: &blacksilk_consensus::PowBlob) -> Hash {
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
        ..Default::default()
    }
}

/// Difficulties of blocks 1..=150 on regtest (T = 10, N = 75, step 5 s, warm-up
/// 11) with D0 = 1000,
/// genesis time 1 700 000 000 and block h at `t[h-1] + PATTERN[h mod 12]`,
/// from the spec pseudocode (script). The pattern includes decreasing
/// timestamps and solve times above 6T = 60.
const PATTERN: [i64; 12] = [10, 3, 25, -2, 1, 12, 10, 7, 70, -5, 4, 9];
const CHAIN_DIFFICULTIES: [u64; 150] = [
    1000, 2000, 882, 1176, 1470, 1764, 1974, 2095, 822, 914, 1005, 1096, 1188, 1279, 1124, 1199,
    1274, 1349, 1408, 1449, 949, 995, 1040, 1085, 1130, 1175, 1095, 1136, 1176, 1217, 1249, 1273,
    972, 1002, 1031, 1060, 1090, 1119, 1066, 1094, 1121, 1148, 1170, 1187, 974, 995, 1017, 1039,
    1060, 1082, 1043, 1063, 1084, 1104, 1121, 1133, 969, 986, 1003, 1020, 1037, 1054, 1023, 1040,
    1056, 1072, 1085, 1095, 963, 977, 991, 1005, 1019, 1033, 1007, 1020, 1036, 1039, 1054, 1063,
    943, 947, 950, 951, 966, 980, 957, 969, 981, 992, 1002, 1009, 897, 905, 913, 921, 933, 946,
    922, 934, 945, 956, 966, 974, 865, 874, 883, 893, 904, 916, 893, 904, 915, 926, 935, 943, 838,
    847, 856, 866, 876, 887, 865, 875, 886, 897, 906, 913, 812, 820, 829, 839, 849, 859, 837, 847,
    857, 868, 876, 883, 785, 793, 802, 811, 821, 830, 809, 818, 828, 838,
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
    assert_eq!(total, 153_943); // script
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
        output_count: 77,
        output_root: [10; 32],
        px_root: [11; 32],
        nonce: 0xDEAD_BEEF,
    };
    // Layout of §2, written out field by field (tools/vectors/output_mmr.py).
    assert_eq!(
        hex(&h.to_bytes()),
        "01000000\
         2a00000000000000\
         0707070707070707070707070707070707070707070707070707070707070707\
         00d2496b00000000\
         3930000000000000\
         0909090909090909090909090909090909090909090909090909090909090909\
         4d00000000000000\
         0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a\
         0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b\
         efbeadde00000000"
    );
    // id = Blake2b-256("BlackSilk/block-id" ‖ LE32(network_id) ‖ header) (script).
    assert_eq!(
        hex(&h.id(0x00DE_B06E)),
        "b55e333ef752369d2e92c58bec523681c45437771ccbb60620499c5801f25fac"
    );
    assert_eq!(
        hex(&h.id(0x0001_D673)),
        "c2a5633f91ff1fe41cc7404e7df102fbca2c5314b0f9bc682cf20a6ee78e83e6"
    );
    // The mining blob (§3): "BSilk/1" ‖ H32("mining-hash", LE32(network_id) ‖
    // header[0..164]) ‖ LE64(nonce) (script).
    assert_eq!(
        hex(&h.pow_blob(0x00DE_B06E)),
        "4253696c6b2f31\
         c5f088aff29464163b4516459f5e38ce6e9c5588247dae5f0cab3ca8fc8c2b13\
         efbeadde00000000"
    );
    assert_eq!(
        hex(&h.pow_blob(0xFFFF_FF00)),
        "4253696c6b2f31\
         64e94536fa0fbac21a14ded371c121f6b9401e5a1e47e44bafb6a70bf6818729\
         efbeadde00000000"
    );
}

#[test]
fn genesis_ids_golden() {
    // From the §1 parameters (version 1, height 0, zero prev_id and tx_root,
    // no outputs, the empty PX root, timestamp, D0, nonce 0) with
    // tools/vectors/output_mmr.py. Testnet: the v3 id 0x0001D673 with the
    // placeholder genesis time and no beacon (fingerprint v3; the launch
    // commit changes it). Before the 172-byte header (#output-root) it was
    // 08b9e7c9…6bcf; the retired v2 value was 6556f92d…037d.
    assert_eq!(
        hex(&ChainParams::testnet().genesis_id()),
        "b16090df9c6ad30233696ac8db2030e876dfc9ed6b8ed8af40a42cda0b75a1d0"
    );
    assert_eq!(
        hex(&ChainParams::regtest().genesis_id()),
        "3dbdba2aca8842cd3e02c7d8c72078f77ff132cc3c84a7f8b87891d0cc106141"
    );
    // Mainnet genesis time is provisional (§1): this pins today's value only.
    assert_eq!(
        hex(&ChainParams::mainnet().genesis_id()),
        "59f74a4965f7302ad4db6e7993d8f3542ddb147c84819dd63dd71f9f76f784e5"
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

// --------------------------------------------- independent header vectors

/// Every line of `consensus/tests/data/header_vectors.txt`, written by the
/// independent `tools/vectors/output_mmr.py` (`--check` regenerates and
/// compares it), against the Rust implementation: the 172-byte layout, block
/// ids, mining blobs, the empty PX root and the genesis ids (RT-OMR L2).
#[test]
fn header_vectors_match_the_independent_file() {
    let text = include_str!("data/header_vectors.txt");
    let sample = BlockHeader {
        version: 1,
        height: 42,
        prev_id: [7; 32],
        timestamp: 1_800_000_000,
        difficulty: 12_345,
        tx_root: [9; 32],
        output_count: 77,
        output_root: [10; 32],
        px_root: [11; 32],
        nonce: 0xDEAD_BEEF,
    };
    let mut kat = blacksilk_consensus::genesis::GenesisSpec {
        network_id: blacksilk_consensus::genesis::TEST_VECTOR_NETWORK_ID,
        timestamp: 1_790_000_000,
        difficulty: 100,
        needs_beacon: false,
        beacon: None,
    }
    .header(1);
    kat.nonce = 0x220A_7227_0A81_8150;
    let mut seen = 0;
    for line in text.lines().filter(|l| !l.starts_with('#')) {
        let (name, value) = line.split_once(": ").expect("`name: hex` line");
        let rust = match name {
            "sample header" => hex(&sample.to_bytes()),
            "sample id (0x00DEB06E)" => hex(&sample.id(0x00DE_B06E)),
            "sample id (0x0001D673)" => hex(&sample.id(0x0001_D673)),
            "sample pow_blob (0x00deb06e)" => hex(&sample.pow_blob(0x00DE_B06E)),
            "sample pow_blob (0xffffff00)" => hex(&sample.pow_blob(0xFFFF_FF00)),
            "empty PX root (header encoding)" => hex(&blacksilk_consensus::genesis::EMPTY_PX_ROOT),
            "genesis id testnet" => hex(&ChainParams::testnet().genesis_id()),
            "genesis id regtest" => hex(&ChainParams::regtest().genesis_id()),
            "genesis id mainnet" => hex(&ChainParams::mainnet().genesis_id()),
            "genesis id tools/genesis KAT" => hex(&kat.id(0xFFFF_FF00)),
            other => panic!("unknown vector {other}"),
        };
        assert_eq!(rust, value, "{name}");
        seen += 1;
    }
    assert_eq!(seen, 10);
}

/// A RandomX known answer on a mining blob, with BlackSilk's salt
/// (`"BlackSilk/RandomX/v1"`, #rx-salt): the sample header's blob on regtest,
/// keyed by the regtest genesis id (the key of blocks 1..=2112). Computed by
/// this implementation (no independent RandomX with this salt exists here);
/// it pins the whole PoW input path: blob layout, mining hash, salt.
#[test]
fn randomx_known_answer_on_a_mining_blob() {
    let sample = BlockHeader {
        version: 1,
        height: 42,
        prev_id: [7; 32],
        timestamp: 1_800_000_000,
        difficulty: 12_345,
        tx_root: [9; 32],
        output_count: 77,
        output_root: [10; 32],
        px_root: [11; 32],
        nonce: 0xDEAD_BEEF,
    };
    let p = ChainParams::regtest();
    let h = blacksilk_randomx::hash_light(&p.genesis_id(), &sample.pow_blob(p.network_id));
    assert_eq!(
        hex(&h),
        "410e353c0ecbcea5389d97931ed60ce2a4382c30619de617728a4d858e2d97c1"
    );
}
