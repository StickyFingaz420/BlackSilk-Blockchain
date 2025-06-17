//! Integration test for PQ signature roundtrip
use crate::wrapper::{keypair_from_seed, sign, verify, seed_from_phrase, PQAlgorithm};

#[test]
fn test_dilithium2_roundtrip() {
    let phrase = "test seed phrase for pqcrypto";
    let seed = seed_from_phrase(phrase);
    let (pk, sk) = keypair_from_seed(PQAlgorithm::Dilithium2, &seed);
    let msg = b"hello pq world";
    let sig = sign(PQAlgorithm::Dilithium2, &sk, msg);
    assert!(verify(PQAlgorithm::Dilithium2, &pk, msg, &sig));
}

#[test]
fn test_falcon512_roundtrip() {
    let phrase = "another test phrase for falcon";
    let seed = seed_from_phrase(phrase);
    let (pk, sk) = keypair_from_seed(PQAlgorithm::Falcon512, &seed);
    let msg = b"pq signature test";
    let sig = sign(PQAlgorithm::Falcon512, &sk, msg);
    assert!(verify(PQAlgorithm::Falcon512, &pk, msg, &sig));
}

#[test]
fn test_signature_tampering() {
    let phrase = "tamper test";
    let seed = seed_from_phrase(phrase);
    let (pk, sk) = keypair_from_seed(PQAlgorithm::Dilithium2, &seed);
    let msg = b"secure message";
    let mut sig = sign(PQAlgorithm::Dilithium2, &sk, msg);
    // Tamper with the signature
    sig[0] ^= 0xFF;
    assert!(!verify(PQAlgorithm::Dilithium2, &pk, msg, &sig));
}

#[test]
fn test_wrong_key_fails() {
    let phrase1 = "key1";
    let phrase2 = "key2";
    let seed1 = seed_from_phrase(phrase1);
    let seed2 = seed_from_phrase(phrase2);
    let (pk1, sk1) = keypair_from_seed(PQAlgorithm::Falcon512, &seed1);
    let (pk2, _sk2) = keypair_from_seed(PQAlgorithm::Falcon512, &seed2);
    let msg = b"wrong key test";
    let sig = sign(PQAlgorithm::Falcon512, &sk1, msg);
    // Should fail with wrong public key
    assert!(!verify(PQAlgorithm::Falcon512, &pk2, msg, &sig));
}

#[test]
fn test_empty_message() {
    let phrase = "empty message";
    let seed = seed_from_phrase(phrase);
    let (pk, sk) = keypair_from_seed(PQAlgorithm::Dilithium2, &seed);
    let msg = b"";
    let sig = sign(PQAlgorithm::Dilithium2, &sk, msg);
    assert!(verify(PQAlgorithm::Dilithium2, &pk, msg, &sig));
}

#[test]
fn test_deterministic_keygen() {
    let phrase = "deterministic phrase";
    let seed1 = seed_from_phrase(phrase);
    let seed2 = seed_from_phrase(phrase);
    let (pk1, sk1) = keypair_from_seed(PQAlgorithm::Falcon512, &seed1);
    let (pk2, sk2) = keypair_from_seed(PQAlgorithm::Falcon512, &seed2);
    assert_eq!(pk1, pk2);
    assert_eq!(sk1, sk2);
}

#[test]
fn test_key_and_signature_sizes() {
    let phrase = "size check";
    let seed = seed_from_phrase(phrase);
    let (pk, sk) = keypair_from_seed(PQAlgorithm::Dilithium2, &seed);
    let msg = b"size test";
    let sig = sign(PQAlgorithm::Dilithium2, &sk, msg);
    let expected_pk = unsafe { crate::wrapper::bitcoin_pqc_public_key_size(PQAlgorithm::Dilithium2.to_c()) };
    let expected_sk = unsafe { crate::wrapper::bitcoin_pqc_secret_key_size(PQAlgorithm::Dilithium2.to_c()) };
    let expected_sig = unsafe { crate::wrapper::bitcoin_pqc_signature_size(PQAlgorithm::Dilithium2.to_c()) };
    assert_eq!(pk.len(), expected_pk);
    assert_eq!(sk.len(), expected_sk);
    assert!(sig.len() <= expected_sig);
}

#[test]
fn test_max_length_message() {
    let phrase = "max length message";
    let seed = seed_from_phrase(phrase);
    let (pk, sk) = keypair_from_seed(PQAlgorithm::Dilithium2, &seed);
    // 10 KB message
    let msg = vec![0xAB; 10 * 1024];
    let sig = sign(PQAlgorithm::Dilithium2, &sk, &msg);
    assert!(verify(PQAlgorithm::Dilithium2, &pk, &msg, &sig));
}

#[test]
fn test_multiple_signatures_unique() {
    let phrase = "multi sig unique";
    let seed = seed_from_phrase(phrase);
    let (pk, sk) = keypair_from_seed(PQAlgorithm::Falcon512, &seed);
    let msg1 = b"msg1";
    let msg2 = b"msg2";
    let sig1 = sign(PQAlgorithm::Falcon512, &sk, msg1);
    let sig2 = sign(PQAlgorithm::Falcon512, &sk, msg2);
    println!("sk: {:02x?}", sk);
    println!("msg1: {:02x?}", msg1);
    println!("msg2: {:02x?}", msg2);
    println!("sig1: {:02x?}", sig1);
    println!("sig2: {:02x?}", sig2);
    assert_ne!(sig1, sig2, "Signatures for different messages should differ");
    assert!(verify(PQAlgorithm::Falcon512, &pk, msg1, &sig1));
    assert!(verify(PQAlgorithm::Falcon512, &pk, msg2, &sig2));
}

#[test]
fn test_cross_scheme_fail() {
    let phrase = "cross scheme";
    let seed = seed_from_phrase(phrase);
    let (pk_d, sk_d) = keypair_from_seed(PQAlgorithm::Dilithium2, &seed);
    let (pk_f, sk_f) = keypair_from_seed(PQAlgorithm::Falcon512, &seed);
    let msg = b"cross scheme test";
    let sig_d = sign(PQAlgorithm::Dilithium2, &sk_d, msg);
    let sig_f = sign(PQAlgorithm::Falcon512, &sk_f, msg);
    // Should not verify with the other scheme
    assert!(!verify(PQAlgorithm::Falcon512, &pk_f, msg, &sig_d));
    assert!(!verify(PQAlgorithm::Dilithium2, &pk_d, msg, &sig_f));
}

#[test]
fn test_random_seed_variation() {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut seed1 = [0u8; 128];
    let mut seed2 = [0u8; 128];
    rng.fill_bytes(&mut seed1);
    rng.fill_bytes(&mut seed2);
    println!("seed1: {:02x?}", seed1);
    println!("seed2: {:02x?}", seed2);
    let (pk1, sk1) = keypair_from_seed(PQAlgorithm::Dilithium2, &seed1);
    let (pk2, sk2) = keypair_from_seed(PQAlgorithm::Dilithium2, &seed2);
    println!("pk1: {:02x?}", pk1);
    println!("pk2: {:02x?}", pk2);
    println!("sk1: {:02x?}", sk1);
    println!("sk2: {:02x?}", sk2);
    assert_ne!(pk1, pk2, "Random seeds should produce different keys");
    assert_ne!(sk1, sk2, "Random seeds should produce different keys");
}

#[test]
fn test_manual_signature_invalid() {
    let phrase = "manual sign test";
    let seed = seed_from_phrase(phrase);
    let (pk, _sk) = keypair_from_seed(PQAlgorithm::Dilithium2, &seed);
    let msg = b"manually constructed signature should fail";
    // Manually construct an invalid signature (all zeros, correct length)
    let sig_len = unsafe { crate::wrapper::bitcoin_pqc_signature_size(PQAlgorithm::Dilithium2.to_c()) };
    let bad_sig = vec![0u8; sig_len];
    assert!(!verify(PQAlgorithm::Dilithium2, &pk, msg, &bad_sig), "Manual all-zero signature should not verify");
    // Manually construct a random signature (wrong length)
    let bad_sig2 = vec![0xAB; sig_len - 5];
    assert!(!verify(PQAlgorithm::Dilithium2, &pk, msg, &bad_sig2), "Manual wrong-length signature should not verify");
}

#[test]
fn test_falcon512_deep_diagnostics() {
    let phrase = "falcon deep diagnostics";
    let seed = seed_from_phrase(phrase);
    let (pk, sk) = keypair_from_seed(PQAlgorithm::Falcon512, &seed);
    let msg = b"diagnostic message for falcon512";
    // Check key sizes
    let pk_size = pk.len();
    let sk_size = sk.len();
    let expected_pk = unsafe { crate::wrapper::bitcoin_pqc_public_key_size(PQAlgorithm::Falcon512.to_c()) };
    let expected_sk = unsafe { crate::wrapper::bitcoin_pqc_secret_key_size(PQAlgorithm::Falcon512.to_c()) };
    assert_eq!(pk_size, expected_pk, "Falcon512 public key size mismatch");
    assert_eq!(sk_size, expected_sk, "Falcon512 secret key size mismatch");
    // Try signing
    let sig = sign(PQAlgorithm::Falcon512, &sk, msg);
    assert!(!sig.is_empty(), "Falcon512 signature should not be empty");
    let sig_size = sig.len();
    let expected_sig = unsafe { crate::wrapper::bitcoin_pqc_signature_size(PQAlgorithm::Falcon512.to_c()) };
    assert!(sig_size <= expected_sig, "Falcon512 signature size too large");
    // Try verifying
    let verified = verify(PQAlgorithm::Falcon512, &pk, msg, &sig);
    assert!(verified, "Falcon512 signature verification failed");
    // Try tampering
    let mut bad_sig = sig.clone();
    bad_sig[0] ^= 0xFF;
    assert!(!verify(PQAlgorithm::Falcon512, &pk, msg, &bad_sig), "Tampered Falcon512 signature should not verify");
    // Try different message
    let msg2 = b"different message";
    assert!(!verify(PQAlgorithm::Falcon512, &pk, msg2, &sig), "Signature should not verify for different message");
    // Try different key
    let seed2 = seed_from_phrase("falcon deep diagnostics 2");
    let (pk2, _sk2) = keypair_from_seed(PQAlgorithm::Falcon512, &seed2);
    assert!(!verify(PQAlgorithm::Falcon512, &pk2, msg, &sig), "Signature should not verify with different public key");
}

#[test]
fn test_falcon512_varied_seeds_and_messages() {
    let seeds = [
        "falcon seed 1", "falcon seed 2", "falcon seed 3", "falcon seed 4", "falcon seed 5"
    ];
    let messages: Vec<&[u8]> = vec![
        b"short" as &[u8],
        b"a bit longer message for falcon" as &[u8],
        &[0u8; 1024][..], // 1KB
        &[0xAB; 4096][..], // 4KB
        b"edge case message \0 with null byte" as &[u8],
    ];
    for seed_phrase in &seeds {
        let seed = seed_from_phrase(seed_phrase);
        let (pk, sk) = keypair_from_seed(PQAlgorithm::Falcon512, &seed);
        for msg in &messages {
            let sig = sign(PQAlgorithm::Falcon512, &sk, msg);
            let verified = verify(PQAlgorithm::Falcon512, &pk, msg, &sig);
            assert!(verified, "Falcon512 failed for seed '{:?}' and message of len {}", seed_phrase, msg.len());
        }
    }
}

#[test]
fn test_falcon512_repeated_sign_verify() {
    let phrase = "falcon repeat test";
    let seed = seed_from_phrase(phrase);
    let (pk, sk) = keypair_from_seed(PQAlgorithm::Falcon512, &seed);
    let msg = b"repeated sign/verify for falcon512";
    for i in 0..100 {
        let sig = sign(PQAlgorithm::Falcon512, &sk, msg);
        let verified = verify(PQAlgorithm::Falcon512, &pk, msg, &sig);
        assert!(verified, "Falcon512 failed on iteration {}", i);
    }
}

#[test]
fn test_falcon512_debug_failing_cases() {
    let phrase1 = "debug falcon fail 1";
    let phrase2 = "debug falcon fail 2";
    let seed1 = seed_from_phrase(phrase1);
    let seed2 = seed_from_phrase(phrase2);
    let (pk1, sk1) = keypair_from_seed(PQAlgorithm::Falcon512, &seed1);
    let (pk2, _sk2) = keypair_from_seed(PQAlgorithm::Falcon512, &seed2);
    let msg = b"debug falcon failure";
    let sig = sign(PQAlgorithm::Falcon512, &sk1, msg);
    println!("pk1: {:02x?}", pk1);
    println!("sk1: {:02x?}", sk1);
    println!("pk2: {:02x?}", pk2);
    println!("sig: {:02x?}", sig);
    let verified1 = verify(PQAlgorithm::Falcon512, &pk1, msg, &sig);
    let verified2 = verify(PQAlgorithm::Falcon512, &pk2, msg, &sig);
    println!("verify with pk1: {}", verified1);
    println!("verify with pk2: {}", verified2);
    assert!(verified1, "Falcon512 should verify with correct key");
    assert!(!verified2, "Falcon512 should not verify with wrong key");
}
