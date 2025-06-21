// Deep integration tests for ML-DSA-44 Rust wrapper
// use ml_dsa_44::{Keypair, sign, sign_with_context, verify, verify_with_context, constants, PublicKey, SecretKey, Signature, MlDsaError};

#[test]
fn test_random_and_deterministic_keygen() {
    // Random keypair
    let keypair1 = Keypair::generate().expect("Random keypair generation failed");
    assert_eq!(keypair1.public_key.0.len(), constants::PUBLIC_KEY_BYTES);
    assert_eq!(keypair1.secret_key.0.len(), constants::SECRET_KEY_BYTES);

    // Deterministic keypair
    let seed = [42u8; constants::SEED_BYTES];
    let keypair2 = Keypair::from_seed(&seed).expect("Deterministic keypair generation failed");
    let keypair3 = Keypair::from_seed(&seed).expect("Deterministic keypair generation failed");
    assert_eq!(keypair2.public_key.0, keypair3.public_key.0);
    assert_eq!(keypair2.secret_key.0, keypair3.secret_key.0);
}

#[test]
fn test_sign_and_verify_basic() {
    let keypair = Keypair::generate().unwrap();
    let message = b"integration test message";
    let signature = sign(message, &keypair.secret_key).unwrap();
    let is_valid = verify(&signature, message, &keypair.public_key).unwrap();
    assert!(is_valid);
}

#[test]
fn test_sign_and_verify_with_context() {
    let keypair = Keypair::generate().unwrap();
    let message = b"context test message";
    let context = b"test-context";
    let signature = sign_with_context(message, context, &keypair.secret_key).unwrap();
    let is_valid = verify_with_context(&signature, message, context, &keypair.public_key).unwrap();
    assert!(is_valid);
}

#[test]
fn test_invalid_signature() {
    let keypair = Keypair::generate().unwrap();
    let message = b"message";
    let mut signature = sign(message, &keypair.secret_key).unwrap();
    // Corrupt the signature
    signature.data[0] ^= 0xFF;
    let is_valid = verify(&signature, message, &keypair.public_key).unwrap();
    assert!(!is_valid);
}

#[test]
fn test_wrong_public_key() {
    let keypair1 = Keypair::generate().unwrap();
    let keypair2 = Keypair::generate().unwrap();
    let message = b"wrong key test";
    let signature = sign(message, &keypair1.secret_key).unwrap();
    let is_valid = verify(&signature, message, &keypair2.public_key).unwrap();
    assert!(!is_valid);
}

#[test]
fn test_empty_and_large_message() {
    let keypair = Keypair::generate().unwrap();
    // Empty message
    let empty = b"";
    let sig_empty = sign(empty, &keypair.secret_key).unwrap();
    let valid_empty = verify(&sig_empty, empty, &keypair.public_key).unwrap();
    assert!(valid_empty);
    // Large message
    let large = vec![0xAB; 10_000];
    let sig_large = sign(&large, &keypair.secret_key).unwrap();
    let valid_large = verify(&sig_large, &large, &keypair.public_key).unwrap();
    assert!(valid_large);
}

#[test]
fn test_key_serialization() {
    let keypair = Keypair::generate().unwrap();
    let pk_bytes = keypair.public_key.0;
    let sk_bytes = keypair.secret_key.0;
    let pk2 = PublicKey(pk_bytes);
    let sk2 = SecretKey(sk_bytes);
    let message = b"serialize test";
    let sig = sign(message, &sk2).unwrap();
    let valid = verify(&sig, message, &pk2).unwrap();
    assert!(valid);
}
