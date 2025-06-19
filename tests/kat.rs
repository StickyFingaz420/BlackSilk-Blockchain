// Professional ML-DSA-44 Known-Answer Test Harness for Rust
//
// Place this file as: <workspace-root>/tests/kat.rs
// Requires: hex = "0.4" in Cargo.toml
// Place your KAT file at <workspace-root>/kats/ml_dsa_44.kat
// Implement your ML-DSA-44 API in src/mldsa44.rs

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use hex::decode;

use BlackSilk::mldsa44::{keygen_api, sign_api, verify_api};

/// Parse a NIST-style KAT file into a vector of test cases.
fn parse_kat_file(path: &str) -> Vec<HashMap<String, Vec<u8>>> {
    let file = File::open(path).expect("KAT file not found");
    let reader = BufReader::new(file);
    let mut vectors = Vec::new();
    let mut current = HashMap::new();

    for line in reader.lines() {
        let line = line.expect("Read error");
        let line = line.trim();
        if line.is_empty() {
            if !current.is_empty() {
                vectors.push(current.clone());
                current.clear();
            }
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim().to_string();
            let value = value.trim();
            let value_bytes = decode(value).expect("Hex decode error");
            current.insert(key, value_bytes);
        }
    }
    if !current.is_empty() {
        vectors.push(current);
    }
    vectors
}

#[test]
fn test_mldsa44_kat() {
    let kat_vectors = parse_kat_file("kats/ml_dsa_44.kat");
    for (i, vector) in kat_vectors.iter().enumerate() {
        let seed = &vector["seed"];
        let msg = &vector["msg"];
        let expected_pk = &vector["pk"];
        let expected_sk = &vector["sk"];
        let expected_sig = &vector["sig"];

        let (pk, sk) = keygen_api(seed);
        assert_eq!(&pk, expected_pk, "PK mismatch at test {}", i);
        assert_eq!(&sk, expected_sk, "SK mismatch at test {}", i);

        let sig = sign_api(&sk, msg);
        assert_eq!(&sig, expected_sig, "SIG mismatch at test {}", i);

        let valid = verify_api(&pk, msg, &sig);
        assert!(valid, "Signature verification failed at test {}", i);
    }
    println!("All KATs passed!");
}

// --- Example ML-DSA-44 API (to be implemented in your crate) ---
// pub mod mldsa44 {
//     pub fn keygen(seed: &[u8]) -> (Vec<u8>, Vec<u8>) { /* ... */ }
//     pub fn sign(sk: &[u8], msg: &[u8]) -> Vec<u8> { /* ... */ }
//     pub fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool { /* ... */ }
// }
