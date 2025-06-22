//! Deep integration test: keygen → sign → verify → dump → mdump → mimport → verify again, with real signature bytes
use super::*;
use std::fs;
use std::path::PathBuf;
use pqsignatures::{Dilithium2, PQSignatureScheme};

#[test]
fn test_full_signature_cycle() {
    // 1. Keygen (real Dilithium2 keypair)
    let (dilithium2_pk, dilithium2_sk) = Dilithium2::keypair();
    let test_address = "sigcycleaddr";
    let test_keypair = PQKeypair {
        dilithium2_pk: dilithium2_pk.to_bytes().to_vec(),
        dilithium2_sk: dilithium2_sk.to_bytes().to_vec(),
        falcon512_pk: vec![],
        falcon512_sk: vec![],
    };
    let key_path = PathBuf::from(format!("{}/{}.json", KEY_DIR, test_address));
    fs::create_dir_all(KEY_DIR).unwrap();
    fs::write(&key_path, serde_json::to_string(&test_keypair).unwrap()).unwrap();

    // 2. Sign a message
    let message = b"hello quantum world";
    let sk = Dilithium2::secret_key_from_bytes(&test_keypair.dilithium2_sk).unwrap();
    let sig = sk.sign(message);
    println!("Signature (hex): {}", hex::encode(&sig));

    // 3. Verify
    let pk = Dilithium2::public_key_from_bytes(&test_keypair.dilithium2_pk).unwrap();
    let verified = pk.verify(message, &sig);
    assert!(verified, "Signature verification failed");
    println!("Signature verified: {}", verified);

    // 4. Dump
    let loaded = load_keypair_by_address(test_address).unwrap();
    assert_eq!(loaded.dilithium2_pk, test_keypair.dilithium2_pk);

    // 5. mdump
    let out_path = PathBuf::from("wallet_data/sigcycle_mdump.json");
    handle_mdump(&out_path);
    let json = fs::read_to_string(&out_path).unwrap();
    assert!(json.contains("sigcycleaddr"));

    // 6. mimport (simulate import to a new address)
    let import_path = PathBuf::from("wallet_data/sigcycle_mimport.json");
    fs::copy(&out_path, &import_path).unwrap();
    let imported_addr = "sigcycleimported";
    let mut dumps: Vec<pqkey::KeyDump> = serde_json::from_str(&json).unwrap();
    dumps[0].address = imported_addr.to_string();
    fs::write(&import_path, serde_json::to_string(&dumps).unwrap()).unwrap();
    handle_mimport(&import_path);
    let imported = load_keypair_by_address(imported_addr).unwrap();
    assert_eq!(imported.dilithium2_pk, test_keypair.dilithium2_pk);

    // 7. Verify again with imported key
    let pk2 = Dilithium2::public_key_from_bytes(&imported.dilithium2_pk).unwrap();
    let verified2 = pk2.verify(message, &sig);
    assert!(verified2, "Signature verification failed after import");
    println!("Signature verified after import: {}", verified2);

    // 8. Print all key and signature hex
    println!("Public key (hex): {}", hex::encode(&test_keypair.dilithium2_pk));
    println!("Private key (hex): {}", hex::encode(&test_keypair.dilithium2_sk));
    println!("Signature (hex): {}", hex::encode(&sig));

    // Cleanup
    fs::remove_file(&key_path).ok();
    fs::remove_file(&out_path).ok();
    fs::remove_file(&import_path).ok();
    let imported_path = PathBuf::from(format!("{}/{}.json", KEY_DIR, imported_addr));
    fs::remove_file(&imported_path).ok();
}
