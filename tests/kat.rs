// Professional ML-DSA-44 Known-Answer Test Harness for Rust (NIST FIPS 204 JSON KATs)
//
// Place this file as: <workspace-root>/tests/kat.rs
// Requires: serde, serde_json, hex in Cargo.toml
// Uses official NIST JSON KATs in <workspace-root>/kats/

use std::fs::File;
use std::io::BufReader;
use serde::Deserialize;
use hex::decode;
use BlackSilk::mldsa44::{keygen_api, sign_api, verify_api};

#[derive(Deserialize, Debug)]
struct KeyGenTest {
    pk: String,
    sk: String,
    // seed is not present in NIST KATs, so make it optional
    seed: Option<String>,
}

#[derive(Deserialize, Debug)]
struct KeyGenTestGroup {
    tests: Vec<KeyGenTest>,
}

#[derive(Deserialize, Debug)]
struct KeyGenRoot {
    testGroups: Vec<KeyGenTestGroup>,
}

#[derive(Deserialize, Debug)]
struct SigGenTest {
    msg: String,
    sig: String,
}

#[derive(Deserialize, Debug)]
struct SigGenTestGroup {
    sk: String,
    tests: Vec<SigGenTest>,
}

#[derive(Deserialize, Debug)]
struct SigGenRoot {
    testGroups: Vec<SigGenTestGroup>,
}

#[derive(Deserialize, Debug)]
struct SigVerTest {
    msg: String,
    sig: String,
    result: bool,
}

#[derive(Deserialize, Debug)]
struct SigVerTestGroup {
    pk: String,
    tests: Vec<SigVerTest>,
}

#[derive(Deserialize, Debug)]
struct SigVerRoot {
    testGroups: Vec<SigVerTestGroup>,
}

#[test]
fn test_keygen_kat() {
    let file = File::open("kats/ML-DSA-keyGen-FIPS204.json").expect("KAT file not found");
    let reader = BufReader::new(file);
    let root: KeyGenRoot = serde_json::from_reader(reader).expect("JSON parse error");
    for group in root.testGroups {
        for (i, t) in group.tests.iter().enumerate() {
            // Use zero seed if not present
            let seed = t.seed.as_ref().map(|s| decode(s).unwrap()).unwrap_or(vec![0u8; 48]);
            let expected_pk = decode(&t.pk).unwrap();
            let expected_sk = decode(&t.sk).unwrap();
            let (pk, sk) = keygen_api(&seed);
            if pk != expected_pk {
                eprintln!("PK mismatch at test {}\nExpected: {:02x?}\nActual:   {:02x?}", i, expected_pk, pk);
            }
            if sk != expected_sk {
                eprintln!("SK mismatch at test {}\nExpected: {:02x?}\nActual:   {:02x?}", i, expected_sk, sk);
            }
            assert_eq!(pk, expected_pk, "PK mismatch at test {}", i);
            assert_eq!(sk, expected_sk, "SK mismatch at test {}", i);
        }
    }
}

#[test]
fn test_siggen_kat() {
    let file = File::open("kats/ML-DSA-sigGen-FIPS204.json").expect("KAT file not found");
    let reader = BufReader::new(file);
    let root: SigGenRoot = serde_json::from_reader(reader).expect("JSON parse error");
    for group in root.testGroups {
        let sk = decode(&group.sk).unwrap();
        for (i, t) in group.tests.iter().enumerate() {
            let msg = decode(&t.msg).unwrap();
            let expected_sig = decode(&t.sig).unwrap();
            let sig = sign_api(&sk, &msg);
            assert_eq!(sig, expected_sig, "SIG mismatch at test {}", i);
        }
    }
}

#[test]
fn test_sigver_kat() {
    let file = File::open("kats/ML-DSA-sigVer-FIPS204.json").expect("KAT file not found");
    let reader = BufReader::new(file);
    let root: SigVerRoot = serde_json::from_reader(reader).expect("JSON parse error");
    for group in root.testGroups {
        let pk = decode(&group.pk).unwrap();
        for (i, t) in group.tests.iter().enumerate() {
            let msg = decode(&t.msg).unwrap();
            let sig = decode(&t.sig).unwrap();
            let valid = verify_api(&pk, &msg, &sig);
            assert_eq!(valid, t.result, "Verify mismatch at test {}", i);
        }
    }
}
