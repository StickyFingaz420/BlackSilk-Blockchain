//! Pinned tests of the genesis procedure (docs/testnet-v3-genesis.md §8; R15 §4.4).

use blacksilk_consensus::difficulty::next_difficulty;
use blacksilk_consensus::{ChainParams, HEADER_VERSION};
use blacksilk_genesis::*;

/// Bitcoin block 0, `H = 0`, the placeholder network id.
fn kat_inputs() -> GenesisInputs {
    GenesisInputs {
        network_id: V3_NETWORK_ID_PLACEHOLDER,
        timestamp: 1_790_000_000,
        difficulty: 100,
        btc_height: 0,
        btc_hash: parse_beacon_hex(BITCOIN_GENESIS_HASH_HEX).unwrap(),
    }
}

/// The digest behind the known-answer nonce, pinned. Recompute by hand:
/// `printf 'BlackSilk/genesis-nonce/v1'` ‖ `73 d6 01 00` (LE32 0x0001D673) ‖
/// eight zero bytes (LE64 0) ‖ the 32 bytes of `000000000019d668…8ce26f`,
/// into `b2sum -l 256`. Cross-checked with Python's `hashlib.blake2b(digest_size=32)`.
const KAT_DIGEST: &str = "3c437d97cf3b1e3550d4d1476da14eea569da954da543bbc86031233de167e19";
const KAT_NONCE: u64 = 0x351e_3bcf_977d_433c;
const KAT_GENESIS_ID: &str = "f35c4e2bf9ba7fee251d88efcf2314f1a59fa7b1968d5c7d3e28ffe4711a714e";

#[test]
fn known_answer_bitcoin_block_0() {
    let i = kat_inputs();
    assert_eq!(
        hex(&nonce_preimage_digest(i.network_id, 0, &i.btc_hash)),
        KAT_DIGEST
    );
    assert_eq!(
        derive_genesis_nonce(i.network_id, 0, &i.btc_hash),
        KAT_NONCE
    );
    // The nonce is the first 8 digest bytes, little-endian.
    let d = parse_beacon_hex(KAT_DIGEST).unwrap();
    assert_eq!(KAT_NONCE, u64::from_le_bytes(d[..8].try_into().unwrap()));
    let g = build(&i).unwrap();
    assert_eq!(g.header.nonce, KAT_NONCE);
    assert_eq!(hex(&g.id), KAT_GENESIS_ID);
}

/// The internal (reversed) byte order of the Bitcoin hash gives another
/// nonce: using it by mistake cannot go unnoticed.
#[test]
fn reversed_byte_order_gives_another_nonce() {
    let i = kat_inputs();
    let mut reversed = i.btc_hash;
    reversed.reverse();
    assert_ne!(reversed, i.btc_hash);
    assert_ne!(
        derive_genesis_nonce(i.network_id, 0, &reversed),
        derive_genesis_nonce(i.network_id, 0, &i.btc_hash)
    );
    // The display-order hex starts with the leading zeros people see.
    assert_eq!(&i.btc_hash[..4], &[0, 0, 0, 0]);
}

/// Every input is bound: the network id, the beacon height and each beacon
/// byte change the nonce.
#[test]
fn every_input_changes_the_nonce() {
    let i = kat_inputs();
    let base = derive_genesis_nonce(i.network_id, i.btc_height, &i.btc_hash);
    assert_ne!(derive_genesis_nonce(i.network_id + 1, 0, &i.btc_hash), base);
    assert_ne!(derive_genesis_nonce(i.network_id, 1, &i.btc_hash), base);
    for byte in 0..32 {
        let mut b = i.btc_hash;
        b[byte] ^= 1;
        assert_ne!(
            derive_genesis_nonce(i.network_id, 0, &b),
            base,
            "byte {byte}"
        );
    }
}

/// Every genesis field but the nonce is fixed by the announced inputs, so no
/// edit can move entropy into another field.
#[test]
fn all_genesis_fields_are_fixed() {
    let i = kat_inputs();
    let g = build(&i).unwrap();
    let h = g.header;
    assert_eq!(h.version, HEADER_VERSION);
    assert_eq!(h.version, 1);
    assert_eq!(h.height, 0);
    assert_eq!(h.prev_id, [0; 32]);
    assert_eq!(h.tx_root, [0; 32]);
    assert_eq!(h.timestamp, i.timestamp);
    assert_eq!(h.difficulty, i.difficulty);
    assert_eq!(h.nonce, derive_genesis_nonce(i.network_id, 0, &i.btc_hash));
    assert_eq!(g.id, h.id(i.network_id));
    assert_eq!(g.bytes(), h.to_bytes());
    // The same layout as the built-in genesis headers, which differ only in
    // the announced fields and the nonce.
    let t = ChainParams::testnet().genesis;
    assert_eq!(
        (t.version, t.height, t.prev_id, t.tx_root),
        (h.version, h.height, h.prev_id, h.tx_root)
    );
}

/// The registry: the placeholder is not a used id, and every used id (v1, the
/// rehearsal, v2, mainnet, regtest) is refused.
#[test]
fn used_network_ids_are_refused() {
    assert_eq!(check_network_id(V3_NETWORK_ID_PLACEHOLDER), Ok(()));
    for (id, _) in NETWORK_ID_REGISTRY {
        assert_eq!(
            check_network_id(*id),
            Err(GenesisError::NetworkIdReused(*id))
        );
        let mut i = kat_inputs();
        i.network_id = *id;
        assert_eq!(build(&i), Err(GenesisError::NetworkIdReused(*id)));
    }
    for id in [0x0001_D670, 0x0001_D671, 0x0001_D672] {
        assert!(registry_name(id).is_some(), "{id:#x}");
    }
    // The built-in networks' ids are all registered.
    for p in [
        ChainParams::testnet(),
        ChainParams::mainnet(),
        ChainParams::regtest(),
    ] {
        assert!(registry_name(p.network_id).is_some(), "{:#x}", p.network_id);
    }
    assert_eq!(check_network_id(0), Err(GenesisError::NetworkIdZero));
}

/// The timestamp is fixed before the beacon: `generate` refuses one in the
/// future; `verify` recomputes from the inputs, clock-free, and refuses a
/// wrong id.
#[test]
fn generate_and_verify() {
    let i = kat_inputs();
    assert_eq!(
        generate(&i, i.timestamp - 1),
        Err(GenesisError::TimestampInFuture {
            timestamp: i.timestamp,
            now: i.timestamp - 1
        })
    );
    let g = generate(&i, i.timestamp).unwrap();
    assert_eq!(verify(&i, &g.id), Ok(g));
    let mut wrong = g.id;
    wrong[31] ^= 1;
    assert_eq!(
        verify(&i, &wrong),
        Err(GenesisError::IdMismatch { computed: g.id })
    );
    let mut zero = i;
    zero.difficulty = 0;
    assert_eq!(build(&zero), Err(GenesisError::Difficulty));
    // The report and the constants carry the full id and the nonce.
    let r = report(&i, &g);
    assert!(r.contains(&hex(&g.id)) && r.contains(&g.header.nonce.to_string()));
    let c = rust_constants(&i, &g);
    assert!(c.contains(&hex(&g.id)) && c.contains(&format!("{:#018x}", g.header.nonce)));
}

/// The starting difficulty from a measured honest hash rate errs low (SX1):
/// half the expected work of one block, at least 1.
#[test]
fn starting_difficulty_from_measured_hash_rate() {
    // 1.7 H/s in total (seven light-mode verifiers would be far slower; the
    // value is an example input), 120 s blocks: 204 hashes per block, D0 = 102.
    assert_eq!(starting_difficulty(1_700, 120), 102);
    assert_eq!(starting_difficulty(0, 120), 1);
    assert_eq!(starting_difficulty(1, 120), 1);
    assert_eq!(starting_difficulty(u64::MAX, u64::MAX), u64::MAX);
    // Monotone in the rate.
    assert!(starting_difficulty(10_000, 120) > starting_difficulty(5_000, 120));
}

/// R15 §4.1: block 1 arrives 7 200 s after `T_g`. LWMA caps the solve time at
/// 6T, so block 2's difficulty is ⌊100·120·2 / (2·720)⌋ = 16, and honest
/// 120 s blocks bring it back up within the window.
///
/// Under the v3 rule (N = 75, counted clock step T/2, warm-up 11) the climb is
/// additive: a block of difficulty d takes 120·d/100 s here, below the step
/// while d < 50, so each counts one step and the difficulty rises by 8 per
/// block: 24, 32, 40, 48, 56 (values from tools/vectors/lwma_warm.py). D0 / 2 is
/// reached at the fifth block after the gap (k = 4).
#[test]
fn genesis_to_launch_gap_is_absorbed_by_lwma() {
    let p = ChainParams::testnet();
    let (t, n, d0) = (p.target_block_time, p.difficulty_window, 100u64);
    let mut ts = vec![1_790_000_000u64];
    let mut cd = vec![d0 as u128];
    // Block 1 at difficulty D0 (the genesis history alone gives D0).
    assert_eq!(next_difficulty(&ts, &cd, t, n, d0), d0);
    ts.push(ts[0] + 7_200);
    cd.push(cd[0] + d0 as u128);
    let d2 = next_difficulty(&ts, &cd, t, n, d0);
    assert_eq!(d2, 16);
    // Honest miners at the rate D0 was chosen for: the difficulty climbs back
    // to at least D0 / 2 within one window of on-target blocks.
    let mut d = d2;
    let mut reached = None;
    let mut climb = Vec::new();
    for k in 0..n as u64 {
        ts.push(ts.last().unwrap() + t * d / d0.max(1)); // a block of difficulty d takes d/D0 of T
        cd.push(cd.last().unwrap() + d as u128);
        d = next_difficulty(&ts, &cd, t, n, d0);
        climb.push(d);
        if reached.is_none() && d >= d0 / 2 {
            reached = Some(k);
        }
    }
    assert_eq!(reached, Some(4), "difficulty stayed at {d}");
    assert_eq!(climb[..5], [24, 32, 40, 48, 56]);
}
