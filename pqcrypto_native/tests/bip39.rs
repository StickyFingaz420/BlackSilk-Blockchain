//! Test BIP39 mnemonic to PQ seed integration

use pqcrypto_native::*;
use std::time::Instant;

#[test]
fn test_bip39_mnemonic_to_seed() {
    let start = Instant::now();
    // Example 12-word BIP39 mnemonic (English)
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = bip39_mnemonic_to_seed(mnemonic, Some("testpass")).unwrap();
    assert_eq!(seed.len(), 32);
    // Use the seed to generate a Falcon keypair (will be random due to upstream, but should not panic)
    let _ = generate_falcon_keypair_from_seed(&seed);
    // Use the seed to generate a Dilithium keypair (will be random due to upstream, but should not panic)
    let _ = generate_dilithium_keypair_from_seed(&seed);
    let elapsed = start.elapsed();
    println!("[timing] test_bip39_mnemonic_to_seed: {:?}", elapsed);
}
