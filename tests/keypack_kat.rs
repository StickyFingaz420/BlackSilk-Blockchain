//! Test for ML-DSA-44 key packing against official KATs

use std::fs;
use std::path::Path;
use hex::decode;
use BlackSilk::mldsa44::keypack::{pack_t1, pack_t0, pack_s1, pack_s2};
use BlackSilk::mldsa44::poly::Poly;
use BlackSilk::mldsa44::params::{N, K, L};

/// Parse a single KAT vector from the .kat file
fn parse_kat_vector(kat: &str, field: &str) -> Option<Vec<u8>> {
    for line in kat.lines() {
        if line.starts_with(field) {
            let hex = line.split('=').nth(1)?.trim();
            return decode(hex).ok();
        }
    }
    None
}

/// Convert a byte slice to a Poly (N=256, i32)
fn bytes_to_poly(bytes: &[u8], bits: usize) -> Poly {
    let mut poly = [0i32; N];
    let mut acc = 0u32;
    let mut acc_bits = 0;
    let mut j = 0;
    for &b in bytes {
        acc |= (b as u32) << acc_bits;
        acc_bits += 8;
        while acc_bits >= bits && j < N {
            poly[j] = (acc & ((1 << bits) - 1)) as i32;
            acc >>= bits;
            acc_bits -= bits;
            j += 1;
        }
    }
    poly
}

#[test]
fn test_keypack_against_kat() {
    let kat_path = Path::new("tests/ml_dsa_44.kat");
    let kat_data = fs::read_to_string(kat_path).expect("KAT file missing");
    let vectors: Vec<&str> = kat_data.split("count = ").skip(1).collect();
    for (i, vec_str) in vectors.iter().enumerate() {
        // Example: parse t1, t0, s1, s2, and their packed hex
        let t1_bytes = parse_kat_vector(vec_str, "t1 =").expect("t1 missing");
        let t0_bytes = parse_kat_vector(vec_str, "t0 =").expect("t0 missing");
        let s1_bytes = parse_kat_vector(vec_str, "s1 =").expect("s1 missing");
        let s2_bytes = parse_kat_vector(vec_str, "s2 =").expect("s2 missing");
        let t1_poly: [Poly; K] = [bytes_to_poly(&t1_bytes, 10); K];
        let t0_poly: [Poly; K] = [bytes_to_poly(&t0_bytes, 13); K];
        let s1_poly: [Poly; L] = [bytes_to_poly(&s1_bytes, 3); L];
        let s2_poly: [Poly; K] = [bytes_to_poly(&s2_bytes, 3); K];
        let packed_t1 = pack_t1(&t1_poly);
        let packed_t0 = pack_t0(&t0_poly);
        let packed_s1 = pack_s1(&s1_poly);
        let packed_s2 = pack_s2(&s2_poly);
        let expected_t1 = parse_kat_vector(vec_str, "pkey_t1 =").expect("pkey_t1 missing");
        let expected_t0 = parse_kat_vector(vec_str, "pkey_t0 =").expect("pkey_t0 missing");
        let expected_s1 = parse_kat_vector(vec_str, "skey_s1 =").expect("skey_s1 missing");
        let expected_s2 = parse_kat_vector(vec_str, "skey_s2 =").expect("skey_s2 missing");
        assert_eq!(packed_t1, expected_t1, "t1 mismatch in vector {}", i);
        assert_eq!(packed_t0, expected_t0, "t0 mismatch in vector {}", i);
        assert_eq!(packed_s1, expected_s1, "s1 mismatch in vector {}", i);
        assert_eq!(packed_s2, expected_s2, "s2 mismatch in vector {}", i);
    }
}
