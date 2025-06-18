//! API ergonomics and address integration tests for pqcrypto_native

use pqcrypto_native::*;
use std::time::Instant;

#[test]
fn test_falcon_address_from_mnemonic() {
    let start = Instant::now();
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let keypair = falcon_keypair_from_mnemonic(mnemonic, None).unwrap();
    let address = falcon_address(&keypair.public);
    println!("[Falcon] mnemonic: {}", mnemonic);
    println!("[Falcon] public key: {:x?}", keypair.public.as_ref());
    println!("[Falcon] secret key: {:x?}", keypair.secret.as_ref());
    println!("[Falcon] address: {}", address);
    assert!(!address.is_empty());
    let elapsed = start.elapsed();
    println!("[timing] test_falcon_address_from_mnemonic: {:?}", elapsed);
}

#[test]
fn test_dilithium_address_from_mnemonic() {
    let start = Instant::now();
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let keypair = dilithium_keypair_from_mnemonic(mnemonic, None).unwrap();
    let address = dilithium_address(&keypair.public);
    println!("[Dilithium] mnemonic: {}", mnemonic);
    println!("[Dilithium] public key: {:x?}", keypair.public.as_ref());
    println!("[Dilithium] secret key: {:x?}", keypair.secret.as_ref());
    println!("[Dilithium] address: {}", address);
    assert!(!address.is_empty());
    let elapsed = start.elapsed();
    println!("[timing] test_dilithium_address_from_mnemonic: {:?}", elapsed);
}

#[test]
fn test_pq_address_generic() {
    let start = Instant::now();
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let keypair = falcon_keypair_from_mnemonic(mnemonic, None).unwrap();
    let addr1 = pq_address(keypair.public.as_ref());
    let addr2 = falcon_address(&keypair.public);
    println!("[Generic PQ] address: {}", addr1);
    assert_eq!(addr1, addr2);
    let elapsed = start.elapsed();
    println!("[timing] test_pq_address_generic: {:?}", elapsed);
}
