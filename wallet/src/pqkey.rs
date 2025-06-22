/// PQ key management for wallet: Dilithium2 and Falcon512
use pqsignatures::{Dilithium2, Falcon512, PQSignatureScheme};
use serde::{Serialize, Deserialize};
use bip39::Mnemonic;
use bs58;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyEntry {
    pub address: String,
    pub mnemonic: String, // unique per address
    pub dilithium2_pk: String, // bs58
    pub dilithium2_sk: String, // bs58
    pub falcon512_pk: String,  // bs58
    pub falcon512_sk: String,  // bs58
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct KeyStore {
    pub keys: Vec<KeyEntry>,
}

impl KeyEntry {
    pub fn from_keypair(address: String, mnemonic: String, pq: &PQKeypair) -> Self {
        Self {
            address,
            mnemonic,
            dilithium2_pk: bs58::encode(&pq.dilithium2_pk).into_string(),
            dilithium2_sk: bs58::encode(&pq.dilithium2_sk).into_string(),
            falcon512_pk: bs58::encode(&pq.falcon512_pk).into_string(),
            falcon512_sk: bs58::encode(&pq.falcon512_sk).into_string(),
        }
    }
    pub fn to_keypair(&self) -> PQKeypair {
        PQKeypair {
            dilithium2_pk: bs58::decode(&self.dilithium2_pk).into_vec().unwrap_or_default(),
            dilithium2_sk: bs58::decode(&self.dilithium2_sk).into_vec().unwrap_or_default(),
            falcon512_pk: bs58::decode(&self.falcon512_pk).into_vec().unwrap_or_default(),
            falcon512_sk: bs58::decode(&self.falcon512_sk).into_vec().unwrap_or_default(),
        }
    }
}

//! PQ key management for wallet: Dilithium2 and Falcon512
use pqsignatures::{Dilithium2, Falcon512, PQSignatureScheme};
use serde::{Serialize, Deserialize};
use bip39::{Mnemonic, Language};

#[derive(Serialize, Deserialize, Clone)]
pub struct PQKeypair {
    pub dilithium2_pk: Vec<u8>,
    pub dilithium2_sk: Vec<u8>,
    pub falcon512_pk: Vec<u8>,
    pub falcon512_sk: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyDump {
    pub address: String,
    pub public_key: String,
    pub private_key: Option<String>,
    pub seed: Option<String>,
}

impl PQKeypair {
    pub fn generate() -> Self {
        let (dpk, dsk) = Dilithium2::keypair();
        let (fpk, fsk) = Falcon512::keypair();
        Self {
            dilithium2_pk: dpk.to_bytes().to_vec(),
            dilithium2_sk: dsk.to_bytes().to_vec(),
            falcon512_pk: fpk.to_bytes().to_vec(),
            falcon512_sk: fsk.to_bytes().to_vec(),
        }
    }
    pub fn save_to_file(&self, path: &str) -> std::io::Result<()> {
        let data = serde_json::to_vec(self).unwrap();
        std::fs::write(path, data)
    }
    pub fn load_from_file(path: &str) -> std::io::Result<Self> {
        let data = std::fs::read(path)?;
        Ok(serde_json::from_slice(&data).unwrap())
    }
    pub fn to_keydump(&self, address: String, include_private: bool, include_seed: bool) -> KeyDump {
        KeyDump {
            address,
            public_key: hex::encode(&self.dilithium2_pk), // Example: use Dilithium2 PK
            private_key: if include_private { Some(hex::encode(&self.dilithium2_sk)) } else { None },
            seed: if include_seed { Some("seed_placeholder".to_string()) } else { None }, // TODO: real seed if available
        }
    }
}

pub const KEY_DIR: &str = "wallet_data/keys";

pub fn load_keypair_by_address(address: &str) -> Option<PQKeypair> {
    let path = format!("{}/{}.json", KEY_DIR, address);
    PQKeypair::load_from_file(&path).ok()
}

pub fn load_all_keypairs() -> Vec<(String, PQKeypair)> {
    let mut result = Vec::new();
    if let Ok(entries) = std::fs::read_dir(KEY_DIR) {
        for entry in entries.flatten() {
            if let Some(fname) = entry.file_name().to_str() {
                if fname.ends_with(".json") {
                    let address = fname.trim_end_matches(".json").to_string();
                    if let Ok(kp) = PQKeypair::load_from_file(&format!("{}/{}", KEY_DIR, fname)) {
                        result.push((address, kp));
                    }
                }
            }
        }
    }
    result
}

// Generate a new PQKeypair and mnemonic (multi-seed)
pub fn generate_keypair_with_mnemonic() -> (PQKeypair, String) {
    let pq = PQKeypair::generate();
    let entropy: [u8; 32] = rand::random();
    let mnemonic = Mnemonic::from_entropy(&entropy).unwrap().to_string();
    (pq, mnemonic)
}

// Save a KeyEntry to file
pub fn save_keyentry(address: &str, entry: &KeyEntry) -> std::io::Result<()> {
    let path = format!("{}/{}.json", KEY_DIR, address);
    let data = serde_json::to_vec_pretty(entry).unwrap();
    std::fs::write(path, data)
}

// Load a KeyEntry from file
pub fn load_keyentry(address: &str) -> Option<KeyEntry> {
    let path = format!("{}/{}.json", KEY_DIR, address);
    let data = std::fs::read(path).ok()?;
    serde_json::from_slice(&data).ok()
}

// Load all KeyEntries
pub fn load_all_keyentries() -> Vec<KeyEntry> {
    let mut result = Vec::new();
    if let Ok(entries) = std::fs::read_dir(KEY_DIR) {
        for entry in entries.flatten() {
            if let Some(fname) = entry.file_name().to_str() {
                if fname.ends_with(".json") {
                    let address = fname.trim_end_matches(".json");
                    if let Some(ke) = load_keyentry(address) {
                        result.push(ke);
                    }
                }
            }
        }
    }
    result
}

// Mass dump all keys to JSON
pub fn handle_mdump(output: &std::path::Path) {
    let all = load_all_keyentries();
    let ks = KeyStore { keys: all };
    match serde_json::to_string_pretty(&ks) {
        Ok(json) => {
            if let Err(e) = std::fs::write(output, json) {
                eprintln!("Failed to write mdump: {e}");
            } else {
                println!("Exported {} key entries to {:?}", ks.keys.len(), output);
            }
        }
        Err(e) => eprintln!("Serialization error: {e}"),
    }
}

// Mass import all keys from JSON
pub fn handle_mimport(input: &std::path::Path) {
    match std::fs::read_to_string(input) {
        Ok(data) => match serde_json::from_str::<KeyStore>(&data) {
            Ok(ks) => {
                for entry in ks.keys {
                    let address = entry.address.clone();
                    let path = std::path::PathBuf::from(format!("{}/{}.json", KEY_DIR, address));
                    if path.exists() {
                        println!("[SKIP] {} already exists", address);
                        continue;
                    }
                    if let Ok(json) = serde_json::to_string_pretty(&entry) {
                        if let Err(e) = std::fs::write(&path, json) {
                            eprintln!("[FAIL] {}: {e}", address);
                        } else {
                            println!("[IMPORTED] {}", address);
                        }
                    }
                }
            }
            Err(e) => eprintln!("JSON parse error: {e}"),
        },
        Err(e) => eprintln!("Failed to read file: {e}"),
    }
}

// Remove legacy KeyDump and related logic
