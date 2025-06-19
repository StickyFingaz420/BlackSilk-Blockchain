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
    tcId: u32,
    signature: String,
}

#[derive(Deserialize, Debug)]
struct SigGenTestGroup {
    #[serde(default)]
    sk: Option<String>,
    #[serde(default)]
    pk: Option<String>,
    #[serde(default)]
    msg: Option<String>,
    tests: Vec<SigGenTest>,
}

#[derive(Deserialize, Debug)]
struct SigGenRoot {
    testGroups: Vec<SigGenTestGroup>,
}

#[derive(Deserialize, Debug)]
struct SigVerTest {
    tcId: u32,
    testPassed: bool,
}

#[derive(Deserialize, Debug)]
struct SigVerTestGroup {
    #[serde(default)]
    pk: Option<String>,
    #[serde(default)]
    msg: Option<String>,
    #[serde(default)]
    signature: Option<String>,
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
            let seed = t.seed.as_ref().map(|s| decode(s).unwrap()).unwrap_or(vec![0u8; 32]);
            let expected_pk = decode(&t.pk).unwrap();
            let expected_sk = decode(&t.sk).unwrap();
            let (pk, sk) = keygen_api(&seed);
            if pk != expected_pk {
                eprintln!("PK mismatch at test {}\nSeed: {}\nExpected PK: {:02x?}\nActual PK:   {:02x?}\nExpected PK (raw): {:?}\nActual PK (raw):   {:?}", i, hex::encode(&seed), expected_pk, pk, expected_pk, pk);
            }
            if sk != expected_sk {
                eprintln!("SK mismatch at test {}\nSeed: {}\nExpected SK: {:02x?}\nActual SK:   {:02x?}\nExpected SK (raw): {:?}\nActual SK (raw):   {:?}", i, hex::encode(&seed), expected_sk, sk, expected_sk, sk);
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
    for (gidx, group) in root.testGroups.iter().enumerate() {
        let (sk, msg) = match (&group.sk, &group.msg) {
            (Some(sk), Some(msg)) => (sk, msg),
            _ => continue, // skip groups missing required fields
        };
        let sk = decode(sk).unwrap();
        let msg = decode(msg).unwrap();
        for (tidx, test) in group.tests.iter().enumerate() {
            let expected_sig = decode(&test.signature).unwrap();
            let sig = sign_api(&sk, &msg);
            if sig != expected_sig {
                eprintln!("SIG mismatch at group {}, test {}\nExpected: {:02x?}\nActual:   {:02x?}", gidx, tidx, expected_sig, sig);
            }
            assert_eq!(sig, expected_sig, "SIG mismatch at group {}, test {}", gidx, tidx);
        }
    }
}

#[test]
fn test_sigver_kat() {
    let file = File::open("kats/ML-DSA-sigVer-FIPS204.json").expect("KAT file not found");
    let reader = BufReader::new(file);
    let root: SigVerRoot = serde_json::from_reader(reader).expect("JSON parse error");
    for (gidx, group) in root.testGroups.iter().enumerate() {
        let (pk, msg, sig) = match (&group.pk, &group.msg, &group.signature) {
            (Some(pk), Some(msg), Some(sig)) => (pk, msg, sig),
            _ => continue, // skip groups missing required fields
        };
        let pk = decode(pk).unwrap();
        let msg = decode(msg).unwrap();
        let sig = decode(sig).unwrap();
        for (tidx, test) in group.tests.iter().enumerate() {
            let expected = test.testPassed;
            let valid = verify_api(&pk, &msg, &sig);
            if valid != expected {
                eprintln!("Verify mismatch at group {}, test {}\nExpected: {}\nActual:   {}", gidx, tidx, expected, valid);
            }
            assert_eq!(valid, expected, "Verify mismatch at group {}, test {}", gidx, tidx);
        }
    }
}
