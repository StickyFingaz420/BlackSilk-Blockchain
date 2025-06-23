// Professional ML-DSA-44 Known-Answer Test Harness for Rust (NIST FIPS 204 JSON KATs)
//
// Place this file as: <workspace-root>/tests/kat.rs
// Requires: serde, serde_json, hex in Cargo.toml
// Uses official NIST JSON KATs in <workspace-root>/kats/

use std::fs::File;
use std::io::BufReader;
use serde::Deserialize;
use hex::decode;
use ml_dsa_44::{Keypair, sign, verify};

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
            let seed = t.seed.as_ref().map(|s| decode(s).unwrap()).unwrap_or(vec![0u8; 32]);
            let expected_pk = decode(&t.pk).unwrap();
            let expected_sk = decode(&t.sk).unwrap();
            let seed_arr: [u8; 32] = seed.as_slice().try_into().expect("Seed must be 32 bytes");
            let keypair = Keypair::from_seed(&seed_arr).expect("Keypair from seed failed");
            assert_eq!(keypair.public_key.as_bytes(), expected_pk.as_slice(), "PK mismatch at test {}", i);
            assert_eq!(keypair.secret_key.as_bytes(), expected_sk.as_slice(), "SK mismatch at test {}", i);
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
            _ => continue,
        };
        let sk = decode(sk).unwrap();
        let msg = decode(msg).unwrap();
        let secret_key = ml_dsa_44::SecretKey::from_bytes(&sk).expect("SecretKey decode");
        for (tidx, test) in group.tests.iter().enumerate() {
            let expected_sig = decode(&test.signature).unwrap();
            let sig = sign(&msg, &secret_key).expect("Sign failed");
            assert_eq!(sig.as_bytes(), expected_sig.as_slice(), "SIG mismatch at group {}, test {}", gidx, tidx);
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
            _ => continue,
        };
        let pk = decode(pk).unwrap();
        let msg = decode(msg).unwrap();
        let sig = decode(sig).unwrap();
        let public_key = ml_dsa_44::PublicKey::from_bytes(&pk).expect("PublicKey decode");
        let signature = ml_dsa_44::Signature::from_bytes(&sig).expect("Signature decode");
        for (tidx, test) in group.tests.iter().enumerate() {
            let expected = test.testPassed;
            let valid = verify(&signature, &msg, &public_key).expect("Verify failed");
            assert_eq!(valid, expected, "Verify mismatch at group {}, test {}", gidx, tidx);
        }
    }
}
