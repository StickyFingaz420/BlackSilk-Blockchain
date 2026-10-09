//! The 64-bit share target xmrig filters hashes with.
//!
//! xmrig submits a hash iff `u64::from_le_bytes(hash[24..32]) < target64`,
//! a strict comparison (`CpuWorker.cpp`). BlackSilk's `check_hash` reads the
//! hash as a little-endian 256-bit integer, so `hash[24..32]` is its most
//! significant limb `t`, and `check_hash(H, d)` (`H·d < 2^256`) implies
//! `t·d < 2^64`, so `t ≤ ⌈2^64/d⌉ − 1`. The bridge therefore sends the
//! ceiling `target64(d) = min(⌈2^64/d⌉, u64::MAX)`: no hash that meets `d`
//! is filtered out, except at `d = 1`, where the cap drops the single top limb
//! `u64::MAX` (probability 2^-64; the documented exception). The filter is
//! coarser than `check_hash` the other way, so the bridge always re-runs
//! `check_hash` on the full hash.
//!
//! Only the 16-hex (8-byte) form is ever sent: xmrig's 8-hex compact form
//! divides by zero for a value of 0.

/// `min(⌈2^64/d⌉, u64::MAX)`, computed in `u128`. `d` must be at least 1
/// (difficulty 0 is never satisfied and never served).
pub fn target64(d: u64) -> u64 {
    assert!(d >= 1, "difficulty 0 has no target");
    let d = d as u128;
    let t = ((1u128 << 64) + d - 1) / d;
    t.min(u64::MAX as u128) as u64
}

/// The job's `target` field: the little-endian bytes of [`target64`] as 16
/// lowercase hex characters.
pub fn target_hex(d: u64) -> String {
    hex::encode(target64(d).to_le_bytes())
}

/// How xmrig reads a job's `target` (`Job::setTarget`, v6.26.0): 16 hex
/// characters are a little-endian u64; 8 are a compact little-endian u32 `t`
/// read as `u64::MAX / (u32::MAX / t)`; anything else is 0 (rejected).
/// For tests and the evidence; the bridge never sends the compact form.
pub fn xmrig_decode_target(target: &str) -> u64 {
    let Ok(bytes) = hex::decode(target) else {
        return 0;
    };
    match bytes.len() {
        8 => u64::from_le_bytes(bytes.try_into().expect("8 bytes")),
        4 => {
            let t = u32::from_le_bytes(bytes.try_into().expect("4 bytes"));
            if t == 0 {
                // xmrig divides by zero here (undefined behaviour); never sent.
                return 0;
            }
            u64::MAX / (u64::from(u32::MAX) / u64::from(t))
        }
        _ => 0,
    }
}

/// The difficulty xmrig logs for a job: `Job::toDiff = u64::MAX / target`.
/// With the ceiling target this is `d − 1` for `2 ≤ d < 2^32` and 1 for
/// `d = 1`.
pub fn xmrig_to_diff(target64: u64) -> u64 {
    if target64 == 0 {
        0
    } else {
        u64::MAX / target64
    }
}

/// xmrig's local filter: whether it would submit `hash` against `target64`.
pub fn xmrig_would_submit(hash: &[u8; 32], target64: u64) -> bool {
    u64::from_le_bytes(hash[24..32].try_into().expect("8 bytes")) < target64
}

#[cfg(test)]
mod tests {
    use super::*;
    use blacksilk_consensus::check_hash;
    use rand_chacha::rand_core::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    fn hash_with(limbs: [u64; 4]) -> [u8; 32] {
        let mut h = [0u8; 32];
        for (i, l) in limbs.iter().enumerate() {
            h[8 * i..8 * i + 8].copy_from_slice(&l.to_le_bytes());
        }
        h
    }

    const DS: [u64; 10] = [
        1,
        2,
        3,
        7,
        1000,
        1 << 32,
        (1 << 32) + 1,
        1 << 63,
        (1 << 63) + 1,
        u64::MAX,
    ];

    #[test]
    fn known_values() {
        assert_eq!(target64(1), u64::MAX);
        assert_eq!(target64(2), 1 << 63);
        // ⌈2^64/3⌉ = 6148914691236517206; the floor form drops the
        // boundary limb 6148914691236517205.
        assert_eq!(target64(3), 6_148_914_691_236_517_206);
        assert_eq!(target64(1 << 32), 1 << 32);
        assert_eq!(target64(u64::MAX), 2);
        assert_eq!(target_hex(1), "ffffffffffffffff");
        assert_eq!(target_hex(2), "0000000000000080");
        assert_eq!(target_hex(1 << 32).len(), 16);
    }

    /// At every difficulty, the largest top limb a passing hash can have is
    /// below the target, and a hash whose top limb equals the target fails
    /// `check_hash` (consensus's own function). d = 1 is the exception: top
    /// limb `u64::MAX` passes `check_hash` but is not below the capped target.
    #[test]
    fn boundaries_against_check_hash() {
        for d in DS {
            let t = target64(d);
            let boundary = (((1u128 << 64) + d as u128 - 1) / d as u128 - 1) as u64;
            // The boundary limb with the smallest low limbs passes.
            let low = hash_with([0, 0, 0, boundary]);
            assert!(check_hash(&low, d), "d={d}");
            if d == 1 {
                assert_eq!(boundary, u64::MAX);
                assert!(!xmrig_would_submit(&low, t), "the documented d=1 exception");
                // Every other top limb is below the target.
                assert!(xmrig_would_submit(&hash_with([!0, !0, !0, !1]), t));
                continue;
            }
            assert!(boundary < t, "d={d}");
            assert!(xmrig_would_submit(&low, t), "d={d}");
            // A top limb equal to the target always fails the exact rule.
            assert!(!check_hash(&hash_with([0, 0, 0, t]), d), "d={d}");
            // The filter is coarser: the boundary limb with full low limbs
            // can pass xmrig's filter and fail check_hash (the bridge
            // re-checks).
            let high = hash_with([!0, !0, !0, boundary]);
            assert!(xmrig_would_submit(&high, t));
            if d.is_power_of_two() {
                assert!(check_hash(&high, d), "d={d}");
            }
        }
    }

    /// Random hashes: whatever passes `check_hash` passes xmrig's filter
    /// (outside the d = 1 exception, which has probability 2^-64).
    #[test]
    fn no_passing_hash_is_filtered_out() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        for d in DS {
            let t = target64(d);
            for _ in 0..2000 {
                let mut h = [0u8; 32];
                rng.fill_bytes(&mut h);
                // Shift the top limb into the interesting range.
                let top = u64::from_le_bytes(h[24..32].try_into().unwrap()) % t.max(1);
                let near = top.saturating_add(rng.next_u64() % 3);
                h[24..32].copy_from_slice(&near.to_le_bytes());
                if d == 1 && near == u64::MAX {
                    continue; // the documented exception
                }
                if check_hash(&h, d) {
                    assert!(xmrig_would_submit(&h, t), "d={d} h={}", hex::encode(h));
                }
            }
        }
    }

    /// The `target` field decoded the way xmrig decodes it gives back
    /// `target64`, and xmrig's logged difficulty is `d − 1` (1 for d = 1).
    #[test]
    fn xmrig_decode_and_to_diff_round_trip() {
        for d in [1u64, 2, 3, 7, 1000, 12_345, (1 << 32) - 1] {
            let hex = target_hex(d);
            assert_eq!(hex.len(), 16);
            let t = xmrig_decode_target(&hex);
            assert_eq!(t, target64(d), "d={d}");
            let logged = xmrig_to_diff(t);
            if d == 1 {
                assert_eq!(logged, 1);
            } else {
                assert_eq!(logged, d - 1, "d={d}");
            }
        }
        // The compact form, for completeness: never sent.
        assert_eq!(xmrig_decode_target("00000000"), 0);
        assert_eq!(xmrig_decode_target("ffffffff"), u64::MAX);
        assert_eq!(xmrig_decode_target("abc"), 0);
        assert_eq!(xmrig_decode_target("00"), 0);
    }
}
