//! Integration test for PQ signature random seed variation (serial)
use pqcrypto::wrapper::{keypair_from_seed, PQAlgorithm};
use rand::RngCore;
use serial_test::serial;

#[test]
#[serial]
fn test_random_seed_variation() {
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
