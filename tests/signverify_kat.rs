//! ML-DSA-44 signature generation and verification KAT test

use std::fs;
use std::path::Path;
use hex::decode;
use BlackSilk::mldsa44::sign::sign;
use BlackSilk::mldsa44::verify::verify;

/// Parse a single KAT vector from the .kat file
fn parse_kat_vector<'a>(kat: &'a str, field: &str) -> Option<&'a str> {
    for line in kat.lines() {
        if line.starts_with(field) {
            return line.split('=').nth(1).map(|s| s.trim());
        }
    }
    None
}

#[test]
fn test_sign_and_verify_against_kat() {
    let kat_path = Path::new("tests/ml_dsa_44.kat");
    let kat_data = fs::read_to_string(kat_path).expect("KAT file missing");
    let vectors: Vec<&str> = kat_data.split("count = ").skip(1).collect();
    for (i, vec_str) in vectors.iter().enumerate() {
        let msg_hex = parse_kat_vector(vec_str, "msg =").expect("msg missing");
        let sk_hex = parse_kat_vector(vec_str, "skey =").expect("skey missing");
        let pk_hex = parse_kat_vector(vec_str, "pkey =").expect("pkey missing");
        let sig_hex = parse_kat_vector(vec_str, "sig =").expect("sig missing");
        let msg = decode(msg_hex).expect("msg hex");
        let sk = decode(sk_hex).expect("skey hex");
        let pk = decode(pk_hex).expect("pkey hex");
        let expected_sig = decode(sig_hex).expect("sig hex");
        // Sign
        let sig = sign(&msg, &sk);
        assert_eq!(sig, expected_sig, "Signature mismatch in vector {}", i);
        // Verify
        let verified = verify(&msg, &sig, &pk);
        assert!(verified, "Signature verification failed in vector {}", i);
    }
}
