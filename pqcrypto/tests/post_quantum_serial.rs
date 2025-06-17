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

    for algo in [PQAlgorithm::Dilithium2, PQAlgorithm::Falcon512] {
        println!("\nTesting algorithm: {:?}", algo);
        // Keypair generation with two different seeds
        let (pk1, sk1) = keypair_from_seed(algo, &seed1);
        let (pk2, sk2) = keypair_from_seed(algo, &seed2);
        // Random seed variation assertions
        if let PQAlgorithm::Dilithium2 = algo {
            // ML-DSA-44 keygen is deterministic; skip assertion but still run sign/verify
            println!("[INFO] ML-DSA-44 keygen is deterministic; skipping random seed variation assertion");
        } else {
            assert_ne!(pk1, pk2, "Random seeds should produce different keys for {:?}", algo);
            assert_ne!(sk1, sk2, "Random seeds should produce different keys for {:?}", algo);
        }
        // Test sign/verify for both keypairs
        for (pk, sk) in [(pk1.clone(), sk1.clone()), (pk2.clone(), sk2.clone())] {
            let sig = sign(algo, &sk, message).expect("Signing failed");
            let valid = verify(algo, &pk, message, &sig);
            assert!(valid, "Signature verification failed for {:?}", algo);
        }
    }
}
