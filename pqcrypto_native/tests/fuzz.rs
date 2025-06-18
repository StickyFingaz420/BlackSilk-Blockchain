//! Fuzzing stub for PQ signature schemes
#![cfg(feature = "fuzzing")]
use pqcrypto_native::algorithms::dilithium::Dilithium2;
use pqcrypto_native::traits::SignatureScheme;
use std::time::Instant;

#[test]
fn fuzz_sign_verify_roundtrip() {
    let start = Instant::now();
    for i in 0..100 {
        let seed = [i as u8; 16];
        let msg = vec![i as u8; 32];
        let (pk, sk) = Dilithium2::keypair_from_seed(&seed).unwrap();
        let sig = Dilithium2::sign(&sk, &msg).unwrap();
        assert!(Dilithium2::verify(&pk, &msg, &sig).is_ok());
    }
    let elapsed = start.elapsed();
    println!("[timing] fuzz_sign_verify_roundtrip: {:?}", elapsed);
}
