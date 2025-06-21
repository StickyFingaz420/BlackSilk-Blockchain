//! Deep integration tests for ML-DSA-44 quantum signature pipeline

use BlackSilk::mldsa44::keygen::keygen;
use BlackSilk::mldsa44::sign::sign;
use BlackSilk::mldsa44::verify::verify;
use BlackSilk::mldsa44::params::SECRET_KEY_BYTES;
use rand::Rng;

fn random_message(len: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..len).map(|_| rng.gen()).collect()
}

#[test]
fn test_sign_verify_random_messages() {
    for msg_len in [1, 32, 64, 128, 256, 1024, 4096] {
        let msg = random_message(msg_len);
        let mut seed = [0u8; 32];
        rand::thread_rng().fill(&mut seed);
        let (pk, sk) = keygen(&seed);
        println!("msg_len: {}, pk_len: {}, sk_len: {}", msg_len, pk.len(), sk.len());
        if sk.len() != SECRET_KEY_BYTES {
            println!("DEBUG: seed = {:02x?}", seed);
            println!("DEBUG: sk = {:02x?}", sk);
        }
        assert_eq!(sk.len(), SECRET_KEY_BYTES, "Secret key length is not correct: got {}, expected {}", sk.len(), SECRET_KEY_BYTES);
        let sig = sign(&msg, &sk);
        assert!(verify(&msg, &sig, &pk), "Signature failed for msg_len {}", msg_len);
        // Tamper with signature
        let mut bad_sig = sig.clone();
        if !bad_sig.is_empty() { bad_sig[0] ^= 0xFF; }
        assert!(!verify(&msg, &bad_sig, &pk), "Tampered signature verified for msg_len {}", msg_len);
        // Tamper with public key
        let mut bad_pk = pk.clone();
        if !bad_pk.is_empty() { bad_pk[0] ^= 0xFF; }
        assert!(!verify(&msg, &sig, &bad_pk), "Tampered public key verified for msg_len {}", msg_len);
    }
}

#[test]
fn test_sign_verify_kat_vectors() {
    // Optionally, re-use the KAT file for additional coverage
    let kat_path = std::path::Path::new("tests/ml_dsa_44.kat");
    if let Ok(kat_data) = std::fs::read_to_string(kat_path) {
        let vectors: Vec<&str> = kat_data.split("count = ").skip(1).collect();
        for (i, vec_str) in vectors.iter().enumerate() {
            let msg_hex = vec_str.lines().find(|l| l.starts_with("msg =")).and_then(|l| l.split('=').nth(1)).map(|s| s.trim()).unwrap();
            let sk_hex = vec_str.lines().find(|l| l.starts_with("skey =")).and_then(|l| l.split('=').nth(1)).map(|s| s.trim()).unwrap();
            let pk_hex = vec_str.lines().find(|l| l.starts_with("pkey =")).and_then(|l| l.split('=').nth(1)).map(|s| s.trim()).unwrap();
            let sig_hex = vec_str.lines().find(|l| l.starts_with("sig =")).and_then(|l| l.split('=').nth(1)).map(|s| s.trim()).unwrap();
            let msg = hex::decode(msg_hex).unwrap();
            let sk = hex::decode(sk_hex).unwrap();
            let pk = hex::decode(pk_hex).unwrap();
            let expected_sig = hex::decode(sig_hex).unwrap();
            let sig = sign(&msg, &sk);
            assert_eq!(sig, expected_sig, "KAT signature mismatch in vector {}", i);
            assert!(verify(&msg, &sig, &pk), "KAT signature verification failed in vector {}", i);
        }
    }
}

#[test]
fn test_quantum_address_encoding_decoding() {
    use primitives::{StealthAddress, PublicKey, QuantumScheme, Address};
    // Generate Dilithium2 address
    let (priv_view, pub_view) = pqcrypto_native::dilithium2::keypair();
    let (priv_spend, pub_spend) = pqcrypto_native::dilithium2::keypair();
    let stealth = StealthAddress {
        view_key: PublicKey::Dilithium2(pub_view.clone()),
        spend_key: PublicKey::Dilithium2(pub_spend.clone()),
    };
    let addr = Address { stealth: stealth.clone(), scheme: Some(QuantumScheme::Dilithium2) };
    let encoded = addr.encode();
    let decoded = Address::decode(&encoded).expect("decode");
    // Check roundtrip
    match (&decoded.stealth.view_key, &stealth.view_key) {
        (PublicKey::Dilithium2(a), PublicKey::Dilithium2(b)) => assert_eq!(a, b),
        _ => panic!("View key type mismatch"),
    }
    match (&decoded.stealth.spend_key, &stealth.spend_key) {
        (PublicKey::Dilithium2(a), PublicKey::Dilithium2(b)) => assert_eq!(a, b),
        _ => panic!("Spend key type mismatch"),
    }
}

#[test]
fn test_hybrid_address_support() {
    use primitives::{StealthAddress, PublicKey, QuantumScheme, Address};
    // Generate hybrid address (Ed25519 + Dilithium2)
    let (priv_view, pub_view) = pqcrypto_native::dilithium2::keypair();
    let classical_view = [1u8; 32];
    let hybrid_view = PublicKey::Hybrid {
        classical: classical_view,
        quantum: pub_view.clone(),
        scheme: QuantumScheme::Dilithium2,
    };
    let (priv_spend, pub_spend) = pqcrypto_native::dilithium2::keypair();
    let classical_spend = [2u8; 32];
    let hybrid_spend = PublicKey::Hybrid {
        classical: classical_spend,
        quantum: pub_spend.clone(),
        scheme: QuantumScheme::Dilithium2,
    };
    let stealth = StealthAddress {
        view_key: hybrid_view,
        spend_key: hybrid_spend,
    };
    let addr = Address { stealth, scheme: Some(QuantumScheme::Dilithium2) };
    let encoded = addr.encode();
    let decoded = Address::decode(&encoded).expect("decode");
    // Check roundtrip
    match &decoded.stealth.view_key {
        PublicKey::Hybrid { classical, quantum, scheme } => {
            assert_eq!(classical, &classical_view);
            assert_eq!(quantum, &pub_view);
            assert_eq!(scheme, &QuantumScheme::Dilithium2);
        },
        _ => panic!("View key type mismatch"),
    }
}
