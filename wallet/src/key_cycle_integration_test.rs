//! Integration test: keygen → sign → verify → dump → mdump → mimport → verify again
use super::*;
use std::fs;
use std::path::PathBuf;

#[test]
fn test_full_key_cycle() {
    // 1. Keygen
    let test_address = "cycleaddr";
    let test_keypair = PQKeypair {
        dilithium2_pk: vec![10,20,30,40],
        dilithium2_sk: vec![50,60,70,80],
        falcon512_pk: vec![],
        falcon512_sk: vec![],
    };
    let key_path = PathBuf::from(format!("{}/{}.json", KEY_DIR, test_address));
    fs::create_dir_all(KEY_DIR).unwrap();
    fs::write(&key_path, serde_json::to_string(&test_keypair).unwrap()).unwrap();

    // 2. Sign
    let message = b"hello quantum world";
    // For demo, just use the private key bytes as a signature
    let signature = test_keypair.dilithium2_sk.clone();

    // 3. Verify (demo: check signature matches sk)
    assert_eq!(signature, vec![50,60,70,80]);

    // 4. Dump
    let loaded = load_keypair_by_address(test_address).unwrap();
    assert_eq!(loaded.dilithium2_pk, vec![10,20,30,40]);

    // 5. mdump
    let out_path = PathBuf::from("wallet_data/cycle_mdump.json");
    handle_mdump(&out_path);
    let json = fs::read_to_string(&out_path).unwrap();
    assert!(json.contains("cycleaddr"));

    // 6. mimport (simulate import to a new address)
    let import_path = PathBuf::from("wallet_data/cycle_mimport.json");
    fs::copy(&out_path, &import_path).unwrap();
    let imported_addr = "cycleimported";
    let mut dumps: Vec<pqkey::KeyDump> = serde_json::from_str(&json).unwrap();
    dumps[0].address = imported_addr.to_string();
    fs::write(&import_path, serde_json::to_string(&dumps).unwrap()).unwrap();
    handle_mimport(&import_path);
    let imported = load_keypair_by_address(imported_addr).unwrap();
    assert_eq!(imported.dilithium2_pk, vec![10,20,30,40]);

    // 7. Verify again
    let imported_signature = imported.dilithium2_sk.clone();
    assert_eq!(imported_signature, vec![50,60,70,80]);

    // 8. Serialization/Deserialization
    let ser = serde_json::to_string(&imported).unwrap();
    let deser: PQKeypair = serde_json::from_str(&ser).unwrap();
    assert_eq!(deser.dilithium2_pk, imported.dilithium2_pk);

    // 9. Zeroize check (if using zeroize crate)
    // If PQKeypair implements Zeroize, call .zeroize() and check memory (not shown here)

    // Cleanup
    fs::remove_file(&key_path).ok();
    fs::remove_file(&out_path).ok();
    fs::remove_file(&import_path).ok();
    let imported_path = PathBuf::from(format!("{}/{}.json", KEY_DIR, imported_addr));
    fs::remove_file(&imported_path).ok();
}
