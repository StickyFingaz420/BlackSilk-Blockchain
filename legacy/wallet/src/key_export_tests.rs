//! Unit tests for PQ key export/import (dump, mdump, mimport)
use super::*;
use std::fs;
use std::path::PathBuf;

#[test]
fn test_dump_and_mdump_roundtrip() {
    // Setup: create a test keypair and save it
    let test_address = "testaddr123";
    let test_keypair = PQKeypair {
        dilithium2_pk: vec![1,2,3,4],
        dilithium2_sk: vec![5,6,7,8],
        falcon512_pk: vec![],
        falcon512_sk: vec![],
    };
    let key_path = PathBuf::from(format!("{}/{}.json", KEY_DIR, test_address));
    fs::create_dir_all(KEY_DIR).unwrap();
    fs::write(&key_path, serde_json::to_string(&test_keypair).unwrap()).unwrap();

    // Test dump public
    let loaded = load_keypair_by_address(test_address).unwrap();
    assert_eq!(loaded.dilithium2_pk, vec![1,2,3,4]);

    // Test mdump
    let out_path = PathBuf::from("wallet_data/test_mdump.json");
    handle_mdump(&out_path);
    let json = fs::read_to_string(&out_path).unwrap();
    assert!(json.contains("testaddr123"));

    // Test mimport (simulate import to a new address)
    let import_path = PathBuf::from("wallet_data/test_mimport.json");
    fs::copy(&out_path, &import_path).unwrap();
    let imported_addr = "importedaddr456";
    let mut entries: Vec<KeyEntry> = serde_json::from_str(&json).unwrap();
    entries[0].address = imported_addr.to_string();
    fs::write(&import_path, serde_json::to_string(&KeyStore { keys: entries }).unwrap()).unwrap();
    handle_mimport(&import_path);
    let imported = load_keyentry(imported_addr).unwrap();
    assert_eq!(imported.dilithium2_pk, bs58::encode(&[1,2,3,4]).into_string());

    // Cleanup
    fs::remove_file(&key_path).ok();
    fs::remove_file(&out_path).ok();
    fs::remove_file(&import_path).ok();
    let imported_path = PathBuf::from(format!("{}/{}.json", KEY_DIR, imported_addr));
    fs::remove_file(&imported_path).ok();
}
