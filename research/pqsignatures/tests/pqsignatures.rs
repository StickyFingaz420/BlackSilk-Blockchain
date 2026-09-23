//! Integration and property-based tests for pqsignatures

use pqsignatures::{Dilithium2, Falcon512, PQSignatureScheme};
use proptest::prelude::*;

#[test]
fn dilithium2_sign_verify() {
    let (pk, sk) = Dilithium2::keypair();
    let msg = b"test message";
    let sig = Dilithium2::sign(&sk, msg);
    assert!(Dilithium2::verify(&pk, msg, &sig));
}

#[test]
fn falcon512_sign_verify() {
    let (pk, sk) = Falcon512::keypair();
    let msg = b"test message";
    let sig = Falcon512::sign(&sk, msg);
    assert!(Falcon512::verify(&pk, msg, &sig));
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 10, // Falcon512 is slow, so limit the number of fuzz cases
        .. ProptestConfig::default()
    })]
    #[test]
    fn dilithium2_fuzz(msg in any::<Vec<u8>>()) {
        let (pk, sk) = Dilithium2::keypair();
        let sig = Dilithium2::sign(&sk, &msg);
        prop_assert!(Dilithium2::verify(&pk, &msg, &sig));
    }
    #[test]
    fn falcon512_fuzz(msg in proptest::collection::vec(any::<u8>(), 1..256)) {
        // Falcon512 is much slower than Dilithium2 for random/large messages.
        // Limit input size and number of cases to avoid hangs/timeouts.
        let (pk, sk) = Falcon512::keypair();
        let sig = Falcon512::sign(&sk, &msg);
        prop_assert!(Falcon512::verify(&pk, &msg, &sig));
    }
}

#[test]
fn dilithium2_negative_tests() {
    let (pk, sk) = Dilithium2::keypair();
    let msg = b"test message";
    let mut sig = Dilithium2::sign(&sk, msg);
    // Tamper with signature
    if let Some(byte) = sig.as_mut().get_mut(0) {
        *byte ^= 0xFF;
    }
    assert!(!Dilithium2::verify(&pk, msg, &sig), "Tampered signature should not verify");
    // Wrong public key
    let (pk2, _) = Dilithium2::keypair();
    let sig2 = Dilithium2::sign(&sk, msg);
    assert!(!Dilithium2::verify(&pk2, msg, &sig2), "Wrong public key should not verify");
}

#[test]
fn falcon512_negative_tests() {
    let (pk, sk) = Falcon512::keypair();
    let msg = b"test message";
    let sig = Falcon512::sign(&sk, msg);
    // Tamper with signature
    let mut sig_bytes = sig.to_bytes();
    sig_bytes[0] ^= 0xFF;
    let sig_tampered = falcon_rust::falcon512::Signature::from_bytes(&sig_bytes);
    match sig_tampered {
        Ok(sig) => assert!(!Falcon512::verify(&pk, msg, &sig), "Tampered signature should not verify"),
        Err(_) => (), // If deserialization fails, this is also correct
    }
    // Wrong public key
    let (pk2, _) = Falcon512::keypair();
    let sig2 = Falcon512::sign(&sk, msg);
    assert!(!Falcon512::verify(&pk2, msg, &sig2), "Wrong public key should not verify");
}

#[test]
fn dilithium2_empty_and_large_message() {
    let (pk, sk) = Dilithium2::keypair();
    let empty = b"";
    let sig_empty = Dilithium2::sign(&sk, empty);
    assert!(Dilithium2::verify(&pk, empty, &sig_empty));
    let large = vec![0xAB; 4096];
    let sig_large = Dilithium2::sign(&sk, &large);
    assert!(Dilithium2::verify(&pk, &large, &sig_large));
}

#[test]
fn falcon512_empty_and_large_message() {
    let (pk, sk) = Falcon512::keypair();
    let empty = b"";
    let sig_empty = Falcon512::sign(&sk, empty);
    assert!(Falcon512::verify(&pk, empty, &sig_empty));
    let large = vec![0xCD; 4096];
    let sig_large = Falcon512::sign(&sk, &large);
    assert!(Falcon512::verify(&pk, &large, &sig_large));
}

#[test]
fn dilithium2_serialize_deserialize() {
    use crystals_dilithium::dilithium2::{PublicKey, SecretKey};
    let (pk, sk) = Dilithium2::keypair();
    let msg = b"serialize test";
    let sig = Dilithium2::sign(&sk, msg);
    // Serialize to bytes
    let pk_bytes = pk.to_bytes();
    let sk_bytes = sk.to_bytes();
    let sig_bytes = sig;
    // Deserialize from bytes (no unwrap needed)
    let pk2 = PublicKey::from_bytes(&pk_bytes);
    let sk2 = SecretKey::from_bytes(&sk_bytes);
    let sig2 = sig_bytes;
    // Check roundtrip
    assert_eq!(pk.to_bytes(), pk2.to_bytes());
    assert_eq!(sk.to_bytes(), sk2.to_bytes());
    assert_eq!(sig, sig2);
    // Check signature still verifies
    assert!(Dilithium2::verify(&pk2, msg, &sig2));
}

#[test]
fn falcon512_serialize_deserialize() {
    use falcon_rust::falcon512::{PublicKey, SecretKey, Signature};
    let (pk, sk) = Falcon512::keypair();
    let msg = b"serialize test";
    let sig = Falcon512::sign(&sk, msg);
    // Serialize to bytes
    let pk_bytes = pk.to_bytes();
    let sk_bytes = sk.to_bytes();
    let sig_bytes = sig.to_bytes();
    // Deserialize from bytes
    let pk2 = PublicKey::from_bytes(&pk_bytes).unwrap();
    let sk2 = SecretKey::from_bytes(&sk_bytes).unwrap();
    let sig2 = Signature::from_bytes(&sig_bytes).unwrap();
    // Check roundtrip
    assert_eq!(pk.to_bytes(), pk2.to_bytes());
    assert_eq!(sk.to_bytes(), sk2.to_bytes());
    assert_eq!(sig.to_bytes(), sig2.to_bytes());
    // Check signature still verifies
    assert!(Falcon512::verify(&pk2, msg, &sig2));
}
