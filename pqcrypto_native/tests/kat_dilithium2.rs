//! Known-answer test (KAT) stub for Dilithium2
use pqcrypto_native::algorithms::dilithium::Dilithium2;
use pqcrypto_native::traits::SignatureScheme;

#[test]
fn test_dilithium2_sign_verify_roundtrip() {
    let start = std::time::Instant::now();
    let (pk, sk) = Dilithium2::keypair_from_seed(&[0u8; 32]).unwrap();
    let msg = b"test message";
    let sig = Dilithium2::sign(&sk, msg).unwrap();
    assert!(Dilithium2::verify(&pk, msg, &sig).is_ok());
    let elapsed = start.elapsed();
    println!("test_dilithium2_sign_verify_roundtrip took: {:.2?}", elapsed);
}
