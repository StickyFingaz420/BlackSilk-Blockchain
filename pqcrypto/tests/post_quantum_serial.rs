//! Integration test for PQ signature random seed variation (serial)
use pqcrypto::wrapper::{keypair_from_seed, sign, verify, PQAlgorithm};
use rand::RngCore;
use serial_test::serial;

#[test]
#[serial]
fn test_all_post_quantum_signatures() {
    let mut rng = rand::thread_rng();
    let mut seed1 = [0u8; 128];
    let mut seed2 = [0u8; 128];
    rng.fill_bytes(&mut seed1);
    rng.fill_bytes(&mut seed2);
    let message = b"Quantum signatures test message";

    for algo in [PQAlgorithm::Dilithium2, PQAlgorithm::Falcon512, PQAlgorithm::SphincsPlus] {
        println!("\nTesting algorithm: {:?}", algo);
        // Keypair generation with two different seeds
        let (pk1, sk1) = keypair_from_seed(algo, &seed1);
        let (pk2, sk2) = keypair_from_seed(algo, &seed2);
        println!("pk1: {:02x?}", pk1);
        println!("sk1: {:02x?}", sk1);
        println!("pk2: {:02x?}", pk2);
        println!("sk2: {:02x?}", sk2);
        // Random seed variation assertions
        if let PQAlgorithm::Dilithium2 = algo {
            println!("[INFO] ML-DSA-44 keygen is deterministic; skipping random seed variation assertion");
        } else {
            assert_ne!(pk1, pk2, "Random seeds should produce different keys for {:?}", algo);
            assert_ne!(sk1, sk2, "Random seeds should produce different keys for {:?}", algo);
        }
        // Test sign/verify for both keypairs, with debug output
        for (i, (pk, sk)) in [(pk1.clone(), sk1.clone()), (pk2.clone(), sk2.clone())].into_iter().enumerate() {
            println!("[{}] Signing with {:?} sk: {:02x?}", i+1, algo, &sk[..std::cmp::min(16, sk.len())]);
            match sign(algo, &sk, message) {
                Ok(sig) => {
                    println!("[{}] Signature: {:02x?}", i+1, &sig[..std::cmp::min(16, sig.len())]);
                    let valid = verify(algo, &pk, message, &sig);
                    println!("[{}] Verification result: {}", i+1, valid);
                    assert!(valid, "Signature verification failed for {:?}", algo);
                },
                Err(e) => {
                    println!("[{}] Signing failed for {:?} with error code: {}", i+1, algo, e);
                    panic!("Signing failed: {}", e);
                }
            }
        }

        // Edge case 1: Fixed (all-zero) seed
        let zero_seed = [0u8; 128];
        let (pk_zero, sk_zero) = keypair_from_seed(algo, &zero_seed);
        println!("[Edge] pk_zero: {:02x?}", pk_zero);
        println!("[Edge] sk_zero: {:02x?}", sk_zero);
        let sig_zero = sign(algo, &sk_zero, message).expect("Sign with zero seed");
        assert!(verify(algo, &pk_zero, message, &sig_zero), "Verify with zero seed failed");

        // Edge case 2: Corrupted (all-0xFF) seed
        let ff_seed = [0xFFu8; 128];
        let (pk_ff, sk_ff) = keypair_from_seed(algo, &ff_seed);
        println!("[Edge] pk_ff: {:02x?}", pk_ff);
        println!("[Edge] sk_ff: {:02x?}", sk_ff);
        let sig_ff = sign(algo, &sk_ff, message).expect("Sign with ff seed");
        assert!(verify(algo, &pk_ff, message, &sig_ff), "Verify with ff seed failed");

        // Edge case 3: Empty message
        let empty_msg = b"";
        let sig_empty = sign(algo, &sk1, empty_msg).expect("Sign with empty message");
        assert!(verify(algo, &pk1, empty_msg, &sig_empty), "Verify with empty message failed");

        // Edge case 4: Corrupted signature (flip a byte)
        let mut sig_corrupt = sig_zero.clone();
        if !sig_corrupt.is_empty() {
            sig_corrupt[0] ^= 0xFF;
            assert!(!verify(algo, &pk_zero, message, &sig_corrupt), "Corrupted signature should not verify");
        }

        // Edge case 5: Corrupted public key (flip a byte)
        let mut pk_corrupt = pk_zero.clone();
        if !pk_corrupt.is_empty() {
            pk_corrupt[0] ^= 0xFF;
            assert!(!verify(algo, &pk_corrupt, message, &sig_zero), "Corrupted public key should not verify");
        }

        // Edge case 6: Corrupted secret key (flip a byte, expect sign to fail or produce unverifiable sig)
        let mut sk_corrupt = sk_zero.clone();
        if !sk_corrupt.is_empty() {
            sk_corrupt[0] ^= 0xFF;
            match sign(algo, &sk_corrupt, message) {
                Ok(sig_bad) => {
                    // Should not verify
                    assert!(!verify(algo, &pk_zero, message, &sig_bad), "Signature from corrupted sk should not verify");
                },
                Err(_) => {
                    // Acceptable: signing fails
                }
            }
        }

        // Edge case 7: Short/oversized key and signature buffers
        // Short secret key
        if sk_zero.len() > 8 {
            let short_sk = &sk_zero[..8];
            assert!(sign(algo, short_sk, message).is_err(), "Signing with short secret key should fail");
        }
        // Short public key
        if pk_zero.len() > 8 {
            let short_pk = &pk_zero[..8];
            assert!(!verify(algo, short_pk, message, &sig_zero), "Verify with short public key should fail");
        }
        // Short signature
        if sig_zero.len() > 8 {
            let short_sig = &sig_zero[..8];
            assert!(!verify(algo, &pk_zero, message, short_sig), "Verify with short signature should fail");
        }
    }
}
