//! ML-DSA-44 unit and integration tests (FIPS 204)

use super::*;
use rand_core::OsRng;

#[test]
fn test_keygen_sign_verify_roundtrip() {
    let mut rng = OsRng;
    let (pk, sk) = keygen(&mut rng).expect("keygen");
    let message = b"test message for mldsa44";
    let sig = try_sign(&sk, message, &mut rng).expect("sign");
    assert!(verify(&pk, message, &sig), "verify");
}

#[test]
fn test_signature_rejects_modified_message() {
    let mut rng = OsRng;
    let (pk, sk) = keygen(&mut rng).expect("keygen");
    let message = b"test message for mldsa44";
    let sig = try_sign(&sk, message, &mut rng).expect("sign");
    let bad_message = b"tampered message";
    assert!(!verify(&pk, bad_message, &sig), "verify should fail on tampered message");
}

#[test]
fn test_signature_rejects_modified_signature() {
    let mut rng = OsRng;
    let (pk, sk) = keygen(&mut rng).expect("keygen");
    let message = b"test message for mldsa44";
    let mut sig = try_sign(&sk, message, &mut rng).expect("sign");
    sig.0[0] ^= 0xFF; // Corrupt the signature
    assert!(!verify(&pk, message, &sig), "verify should fail on tampered signature");
}
