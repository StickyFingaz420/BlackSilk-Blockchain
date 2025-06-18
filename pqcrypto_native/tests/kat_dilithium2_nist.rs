//! Roundtrip sign/verify test for Dilithium2
use pqcrypto_native::algorithms::dilithium::Dilithium2;
use pqcrypto_native::traits::SignatureScheme;
use std::time::Instant;

#[test]
fn test_dilithium2_sign_verify_roundtrip() {
    let start = Instant::now();
    let (pk, sk) = Dilithium2::keypair_from_seed(&[0u8; 32]).unwrap();
    let msg = b"test message";
    let sig = Dilithium2::sign(&sk, msg).unwrap();
    assert!(Dilithium2::verify(&pk, msg, &sig).is_ok());
    let elapsed = start.elapsed();
    println!("[timing] test_dilithium2_sign_verify_roundtrip: {:?}", elapsed);
}
