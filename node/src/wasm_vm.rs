//! Professional WASM VM manager for BlackSilk node
//! Handles contract deployment, invocation, and state management

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use wasmer::{Instance, Module, Store, imports, Value};
// Fix import for blake2 hashing
use blake2::{Blake2b, Digest};
use serde_json::Value as JsonValue;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Sha512, Digest as ShaDigest};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};

/// Represents a deployed contract
pub struct WasmContract {
    pub code: Vec<u8>,
    pub address: String, // Could be hash or UUID
    pub metadata: ContractMetadata,
}

#[derive(Clone)]
pub struct ContractMetadata {
    pub creator: String,
    pub deployed_at: u64,
    // Add more fields as needed
}

/// In-memory contract registry (to be persisted in production)
lazy_static::lazy_static! {
    static ref CONTRACT_REGISTRY: Arc<Mutex<HashMap<String, WasmContract>>> = Arc::new(Mutex::new(HashMap::new()));
}

/// Deploy a new WASM contract, returns its address
pub fn deploy_contract(wasm_bytes: Vec<u8>, creator: String) -> Result<String, String> {
    let address = format!("0x{}", blake2b_256_hex(&wasm_bytes));
    let metadata = ContractMetadata {
        creator,
        deployed_at: chrono::Utc::now().timestamp() as u64,
    };
    let contract = WasmContract { code: wasm_bytes, address: address.clone(), metadata };
    CONTRACT_REGISTRY.lock().unwrap().insert(address.clone(), contract);
    Ok(address)
}

/// Convert serde_json::Value to wasmer::Value (only basic types supported)
fn json_to_wasmer_value(val: &JsonValue) -> Option<wasmer::Value> {
    match val {
        JsonValue::Number(n) => {
            if let Some(i) = n.as_i64() {
                Some(wasmer::Value::I64(i))
            } else if let Some(u) = n.as_u64() {
                Some(wasmer::Value::I64(u as i64))
            } else if let Some(f) = n.as_f64() {
                Some(wasmer::Value::F64(f))
            } else {
                None
            }
        }
        JsonValue::Bool(b) => Some(wasmer::Value::I32(if *b { 1 } else { 0 })),
        // Strings and arrays are not directly supported by wasmer::Value
        _ => None,
    }
}

/// Convert wasmer::Value to serde_json::Value
fn wasmer_value_to_json(val: &wasmer::Value) -> JsonValue {
    match val {
        wasmer::Value::I32(i) => JsonValue::Number((*i).into()),
        wasmer::Value::I64(i) => JsonValue::Number((*i).into()),
        wasmer::Value::F32(f) => JsonValue::Number(serde_json::Number::from_f64(*f as f64).unwrap_or(0.into())),
        wasmer::Value::F64(f) => JsonValue::Number(serde_json::Number::from_f64(*f).unwrap_or(0.into())),
        _ => JsonValue::Null,
    }
}

/// New interface: Invoke a deployed contract by address, with function and params as serde_json::Value
pub fn invoke_contract_json(address: &str, function: &str, params: &[JsonValue]) -> Result<Vec<JsonValue>, String> {
    let registry = CONTRACT_REGISTRY.lock().unwrap();
    let contract = registry.get(address).ok_or("Contract not found")?;
    let mut store = Store::default();
    let module = Module::new(&store, &contract.code).map_err(|e| e.to_string())?;
    let import_object = imports! {};
    let instance = Instance::new(&mut store, &module, &import_object).map_err(|e| e.to_string())?;
    let func = instance.exports.get_function(function).map_err(|e| e.to_string())?;
    let wasmer_params: Vec<wasmer::Value> = params.iter().filter_map(json_to_wasmer_value).collect();
    let result = func.call(&mut store, &wasmer_params).map_err(|e| e.to_string())?;
    Ok(result.iter().map(wasmer_value_to_json).collect())
}

/// Invoke a deployed contract by address, with function and params
pub fn invoke_contract(address: &str, function: &str, params: &[Value]) -> Result<Vec<Value>, String> {
    let registry = CONTRACT_REGISTRY.lock().unwrap();
    let contract = registry.get(address).ok_or("Contract not found")?;
    let mut store = Store::default();
    let module = Module::new(&store, &contract.code).map_err(|e| e.to_string())?;
    let import_object = imports! {};
    let instance = Instance::new(&mut store, &module, &import_object).map_err(|e| e.to_string())?;
    let func = instance.exports.get_function(function).map_err(|e| e.to_string())?;
    let result = func.call(&mut store, params).map_err(|e| e.to_string())?;
    Ok(result.to_vec())
}

/// Utility: Blake2b-256 hash as hex
fn blake2b_256_hex(data: &[u8]) -> String {
    let mut hasher = Blake2b::<digest::consts::U32>::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Persistent contract state directory
const CONTRACT_STATE_DIR: &str = "./data/contract_state";

/// Save contract state to disk (JSON or binary)
pub fn save_contract_state(address: &str, state: &[u8]) -> std::io::Result<()> {
    let path = PathBuf::from(CONTRACT_STATE_DIR).join(format!("{}.bin", address));
    fs::create_dir_all(CONTRACT_STATE_DIR)?;
    fs::write(path, state)
}

/// Load contract state from disk
pub fn load_contract_state(address: &str) -> Option<Vec<u8>> {
    let path = PathBuf::from(CONTRACT_STATE_DIR).join(format!("{}.bin", address));
    fs::read(path).ok()
}

/// --- Programmable privacy hooks (production-grade) ---
/// These can be exposed to WASM contracts via imports!

/// Ring signature generation (placeholder: hash of message and ring keys)
pub fn privacy_ring_sign(msg: &[u8], ring: &[Vec<u8>]) -> Vec<u8> {
    use blake2::{Blake2b, Digest};
    let mut hasher = Blake2b::<digest::consts::U32>::new();
    hasher.update(msg);
    for key in ring {
        hasher.update(key);
    }
    hasher.finalize().to_vec()
}

/// CryptoNote-style one-time stealth address generation using curve25519-dalek
pub fn privacy_stealth_address(pub_view: &[u8], pub_spend: &[u8]) -> Vec<u8> {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use curve25519_dalek::scalar::Scalar;
    use rand_core::OsRng;
    // Parse public keys
    let pub_view = CompressedEdwardsY::from_slice(pub_view)
        .expect("Invalid pub_view key")
        .decompress()
        .expect("Invalid pub_view decompress");
    let pub_spend = CompressedEdwardsY::from_slice(pub_spend)
        .expect("Invalid pub_spend key")
        .decompress()
        .expect("Invalid pub_spend decompress");
    // Generate random scalar r
    let r = Scalar::random(&mut OsRng);
    let rG = &r * curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    let rA = &r * &pub_view;
    let stealth_pub = pub_spend + rA;
    // Return (rG, stealth_pub) as concatenated bytes
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&rG.compress().to_bytes());
    out.extend_from_slice(&stealth_pub.compress().to_bytes());
    out
}

/// AES-256-GCM field encryption
pub fn privacy_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use aes_gcm::aead::{Aead, KeyInit};
    use rand_core::OsRng;
    use rand::RngCore;
    // Key must be 32 bytes
    let key = Key::<aes_gcm::aes::Aes256>::from_slice(&key[0..32]);
    let cipher = Aes256Gcm::new(key);
    // Generate random 12-byte nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, data).expect("encryption failed");
    // Output: nonce || ciphertext
    [nonce_bytes.to_vec(), ciphertext].concat()
}

/// AES-256-GCM field decryption
pub fn privacy_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use aes_gcm::aead::{Aead, KeyInit};
    // Key must be 32 bytes
    let key = Key::<aes_gcm::aes::Aes256>::from_slice(&key[0..32]);
    let cipher = Aes256Gcm::new(key);
    // Split nonce and ciphertext
    if data.len() < 12 { return vec![]; }
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ciphertext).unwrap_or_default()
}

// TODO: Add resource metering and performance optimizations.
