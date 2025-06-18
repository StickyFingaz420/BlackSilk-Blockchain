//! Fuzzing and property-based tests for Falcon512 and Dilithium2
use pqcrypto_native::algorithms::falcon::Falcon512;
use pqcrypto_native::algorithms::dilithium::Dilithium2;
use pqcrypto_native::traits::SignatureScheme;

#[test]
fn fuzz_falcon512_sign_verify_roundtrip() {
    for i in 0..100 {
        let seed = [i as u8; 32];
        let msg = vec![i as u8; 64];
        let (pk, sk) = Falcon512::keypair_from_seed(&seed).unwrap();
        let sig = Falcon512::sign(&sk, &msg).unwrap();
        assert!(Falcon512::verify(&pk, &msg, &sig).is_ok());
    }
}

#[test]
fn fuzz_dilithium2_sign_verify_varied_msg() {
    let (pk, sk) = Dilithium2::keypair_from_seed(&[42u8; 32]).unwrap();
    for len in 0..128 {
        let msg = vec![0xAB; len];
        let sig = Dilithium2::sign(&sk, &msg).unwrap();
        assert!(Dilithium2::verify(&pk, &msg, &sig).is_ok());
    }
}

#[test]
fn negative_falcon512_signature_should_fail() {
    let (pk, sk) = Falcon512::keypair_from_seed(&[1u8; 32]).unwrap();
    let msg = b"test message";
    let mut sig = Falcon512::sign(&sk, msg).unwrap();
    // Flip a byte in the signature
    if let Some(byte) = sig.0.get_mut(0) {
        *byte ^= 0xFF;
    }
    assert!(Falcon512::verify(&pk, msg, &sig).is_err());
}

#[test]
fn negative_dilithium2_signature_should_fail() {
    let (pk, sk) = Dilithium2::keypair_from_seed(&[1u8; 32]).unwrap();
    let msg = b"test message";
    let mut sig = Dilithium2::sign(&sk, msg).unwrap();
    // Flip a byte in the signature
    if let Some(byte) = sig.0.get_mut(0) {
        *byte ^= 0xFF;
    }
    assert!(Dilithium2::verify(&pk, msg, &sig).is_err());
}

#[test]
fn deep_fuzz_signature_verification() {
    // Test 100 different seeds and 100 message lengths for each
    for seed_val in 0u8..100 {
        let seed = [seed_val; 32];
        let (pk_falcon, sk_falcon) = Falcon512::keypair_from_seed(&seed).unwrap();
        let (pk_dilithium, sk_dilithium) = Dilithium2::keypair_from_seed(&seed).unwrap();
        for msg_len in 0..100 {
            let msg: Vec<u8> = (0..msg_len).map(|i| (i as u8).wrapping_add(seed_val)).collect();
            // Falcon512
            let sig_falcon = Falcon512::sign(&sk_falcon, &msg).unwrap();
            assert!(Falcon512::verify(&pk_falcon, &msg, &sig_falcon).is_ok(),
                "Falcon512 failed for seed={:?} msg_len={}", seed, msg_len);
            // Dilithium2
            let sig_dilithium = Dilithium2::sign(&sk_dilithium, &msg).unwrap();
            assert!(Dilithium2::verify(&pk_dilithium, &msg, &sig_dilithium).is_ok(),
                "Dilithium2 failed for seed={:?} msg_len={}", seed, msg_len);
        }
    }
}
