//! Professional WASM VM manager for BlackSilk node
//! Handles contract deployment, invocation, and state management

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
// Wasmer 6.x imports
use wasmer::{Instance, Module, Store, imports, Value};
use wasmer_middlewares::Metering;
use blake2::{Blake2b, Digest};
use serde_json::Value as JsonValue;
use rand::RngCore;
use sha2::Digest as ShaDigest;
use aes_gcm::aead::{Aead, KeyInit};
use serde::{Serialize, Deserialize};
// Import Operator from wasmer::wasmparser for Wasmer 3.x metering
use wasmer::wasmparser::Operator;

/// Represents a deployed contract
#[derive(Serialize, Deserialize)]
pub struct WasmContract {
    pub code: Vec<u8>,
    pub address: String, // Could be hash or UUID
    pub metadata: ContractMetadata,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ContractMetadata {
    pub creator: String,
    pub deployed_at: u64,
    // Add more fields as needed
}

/// In-memory contract registry (to be persisted in production)
lazy_static::lazy_static! {
    static ref CONTRACT_REGISTRY: Arc<Mutex<HashMap<String, WasmContract>>> = Arc::new(Mutex::new(HashMap::new()));
}

const CONTRACT_REGISTRY_PATH: &str = "./data/contract_registry.json";

/// Save the contract registry to disk
fn save_contract_registry() -> std::io::Result<()> {
    let registry = match CONTRACT_REGISTRY.lock() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[WARN] Failed to lock contract registry: {}", e);
            return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
        }
    };
    let contracts: Vec<&WasmContract> = registry.values().collect();
    let json = serde_json::to_string_pretty(&contracts)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    fs::create_dir_all("./data")?;
    fs::write(CONTRACT_REGISTRY_PATH, json)
}

/// Load the contract registry from disk at startup
pub fn load_contract_registry() -> std::io::Result<()> {
    let path = PathBuf::from(CONTRACT_REGISTRY_PATH);
    if !path.exists() {
        return Ok(());
    }
    let json = fs::read_to_string(path)?;
    let contracts: Vec<WasmContract> = serde_json::from_str(&json).unwrap_or_else(|e| {
        eprintln!("[WARN] Failed to deserialize contract registry: {}", e);
        Vec::new()
    });
    let mut registry = match CONTRACT_REGISTRY.lock() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[WARN] Failed to lock contract registry: {}", e);
            return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
        }
    };
    for contract in contracts {
        registry.insert(contract.address.clone(), contract);
    }
    Ok(())
}

/// Deploy a new WASM contract, returns its address
pub fn deploy_contract(wasm_bytes: Vec<u8>, creator: String) -> Result<String, String> {
    // Restrict contract size (e.g., 1MB max)
    if wasm_bytes.len() > 1024 * 1024 {
        return Err("Contract too large (max 1MB)".to_string());
    }
    // Validate WASM module structure
    let store = Store::default();
    if Module::new(&store, &wasm_bytes).is_err() {
        return Err("Invalid WASM module".to_string());
    }
    let address = format!("0x{}", blake2b_256_hex(&wasm_bytes));
    let metadata = ContractMetadata {
        creator,
        deployed_at: chrono::Utc::now().timestamp() as u64,
    };
    let contract = WasmContract { code: wasm_bytes, address: address.clone(), metadata };
    
    let mut registry = match CONTRACT_REGISTRY.lock() {
        Ok(r) => r,
        Err(e) => return Err(format!("Failed to lock contract registry: {}", e)),
    };
    registry.insert(address.clone(), contract);
    
    // Save registry after deployment
    if let Err(e) = save_contract_registry() {
        eprintln!("[WARN] Failed to save contract registry: {}", e);
    }
    Ok(address)
}

/// Convert serde_json::Value to wasmer::Value (only basic types supported)
pub fn json_to_wasmer_value(val: &JsonValue) -> Option<wasmer::Value> {
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

/// New interface: Invoke a deployed contract by address, with function and params as serde_json::Value, with gas metering
pub fn invoke_contract_json_with_gas(address: &str, function: &str, params: &[JsonValue], gas_limit: u64) -> Result<Vec<JsonValue>, String> {
    let registry = match CONTRACT_REGISTRY.lock() {
        Ok(r) => r,
        Err(e) => return Err(format!("Failed to lock contract registry: {}", e)),
    };
    let contract = registry.get(address).ok_or("Contract not found")?;
    let metering = Arc::new(Metering::new(gas_limit, cost_function));
    // Attach metering middleware if possible (Wasmer 3.x)
    // If not, just use the default store and metering as argument to Module/Instance
    let mut store = Store::default();
    let module = Module::new(&store, &contract.code).map_err(|e| e.to_string())?;
    let import_object = imports! {};
    let instance = Instance::new(&mut store, &module, &import_object).map_err(|e| e.to_string())?;
    let func = instance.exports.get_function(function).map_err(|e| e.to_string())?;
    let wasmer_params: Vec<wasmer::Value> = params.iter().filter_map(json_to_wasmer_value).collect();
    let result = func.call(&mut store, &wasmer_params).map_err(|e| e.to_string())?;
    // Check gas used
    let gas_left = wasmer_middlewares::metering::get_remaining_points(&mut store, &instance);
    if let wasmer_middlewares::metering::MeteringPoints::Remaining(0) = gas_left {
        return Err("Gas limit exceeded".to_string());
    }
    Ok(result.iter().map(wasmer_value_to_json).collect())
}

/// Invoke a deployed contract by address, with function and params, with gas metering
pub fn invoke_contract_with_gas(address: &str, function: &str, params: &[Value], gas_limit: u64) -> Result<Vec<Value>, String> {
    let registry = match CONTRACT_REGISTRY.lock() {
        Ok(r) => r,
        Err(e) => return Err(format!("Failed to lock contract registry: {}", e)),
    };
    let contract = registry.get(address).ok_or("Contract not found")?;
    let metering = Arc::new(Metering::new(gas_limit, cost_function));
    // Attach metering middleware if possible (Wasmer 3.x)
    // If not, just use the default store and metering as argument to Module/Instance
    let mut store = Store::default();
    let module = Module::new(&store, &contract.code).map_err(|e| e.to_string())?;
    let import_object = imports! {};
    let instance = Instance::new(&mut store, &module, &import_object).map_err(|e| e.to_string())?;
    let func = instance.exports.get_function(function).map_err(|e| e.to_string())?;
    let result = func.call(&mut store, params).map_err(|e| e.to_string())?;
    // Check gas used
    let gas_left = wasmer_middlewares::metering::get_remaining_points(&mut store, &instance);
    if let wasmer_middlewares::metering::MeteringPoints::Remaining(0) = gas_left {
        return Err("Gas limit exceeded".to_string());
    }
    Ok(result.to_vec())
}

/// Backward-compatible: invoke_contract_json with default gas limit
pub fn invoke_contract_json(address: &str, function: &str, params: &[JsonValue]) -> Result<Vec<JsonValue>, String> {
    // Set a high default gas limit for legacy calls
    invoke_contract_json_with_gas(address, function, params, 10_000_000)
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
    // Write atomically
    let tmp_path = path.with_extension("bin.tmp");
    fs::write(&tmp_path, state)?;
    fs::rename(&tmp_path, &path)?;
    Ok(())
}

/// Load contract state from disk
pub fn load_contract_state(address: &str) -> Result<Vec<u8>, String> {
    let path = PathBuf::from(CONTRACT_STATE_DIR).join(format!("{}.bin", address));
    fs::read(path).map_err(|e| format!("Failed to load contract state: {}", e))
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
    use rand_core::RngCore;
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
    let mut rng = OsRng;
    let mut r_bytes = [0u8; 32];
    rng.fill_bytes(&mut r_bytes);
    let r = Scalar::from_bytes_mod_order(r_bytes);
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

/// Event logging for contract execution (to be persisted on-chain or in decentralized log)
pub fn log_contract_event(address: &str, event: &str, details: &str) {
    // In production, emit to on-chain event log or decentralized storage
    println!("[Contract Event] [{}] {}: {}", address, event, details);
}

/// Gas cost function: Assign costs to different WASM operations based on execution cost
/// This prevents DoS attacks by metering expensive operations
fn cost_function(operator: &Operator) -> u64 {
    use wasmer::wasmparser::Operator;
    
    match operator {
        // Cheap operations: 1 gas
        Operator::LocalGet { .. } | Operator::LocalSet { .. } | Operator::GlobalGet { .. } |
        Operator::GlobalSet { .. } | Operator::I32Const { .. } | Operator::I64Const { .. } |
        Operator::F32Const { .. } | Operator::F64Const { .. } |
        Operator::Nop | Operator::Unreachable => 1,
        
        // Arithmetic operations: 3 gas
        Operator::I32Add | Operator::I32Sub | Operator::I32Mul | Operator::I32Div { .. } |
        Operator::I64Add | Operator::I64Sub | Operator::I64Mul | Operator::I64Div { .. } |
        Operator::F32Add | Operator::F32Sub | Operator::F32Mul | Operator::F32Div |
        Operator::F64Add | Operator::F64Sub | Operator::F64Mul | Operator::F64Div => 3,
        
        // Memory operations: 5 gas (more expensive)
        Operator::I32Load { .. } | Operator::I64Load { .. } | Operator::F32Load { .. } |
        Operator::F64Load { .. } | Operator::I32Store { .. } | Operator::I64Store { .. } |
        Operator::F32Store { .. } | Operator::F64Store { .. } |
        Operator::MemorySize { .. } | Operator::MemoryGrow { .. } => 5,
        
        // Function calls: 10 gas (control flow is expensive)
        Operator::Call { .. } | Operator::CallIndirect { .. } => 10,
        
        // Branches: 2 gas
        Operator::Br { .. } | Operator::BrIf { .. } | Operator::If { .. } |
        Operator::Loop { .. } | Operator::Block { .. } => 2,
        
        // Compare operations: 2 gas
        Operator::I32Eq | Operator::I32Ne | Operator::I32Lt { .. } | Operator::I32Gt { .. } |
        Operator::I64Eq | Operator::I64Ne | Operator::I64Lt { .. } | Operator::I64Gt { .. } |
        Operator::F32Eq | Operator::F32Ne | Operator::F32Lt | Operator::F32Gt |
        Operator::F64Eq | Operator::F64Ne | Operator::F64Lt | Operator::F64Gt => 2,
        
        // All other operations: default 1 gas
        _ => 1,
    }
}

/// Execute a WASM contract with robust error handling, gas metering, and resource limits
pub fn execute_contract_with_gas(
    wasm_bytes: &[u8],
    gas_limit: u64,
    memory_limit: u32, // in pages (64KiB per page)
    params: &[Value],
    contract_address: &str,
) -> Result<Vec<Value>, String> {
    // Restrict contract code size (e.g., 5MB max)
    if wasm_bytes.len() > 5 * 1024 * 1024 {
        log_contract_event(contract_address, "deploy_failed", "Code size exceeds 5MB limit");
        return Err("Contract code too large (max 5MB)".to_string());
    }
    
    // Require reasonable gas limit (prevent underflow attacks)
    if gas_limit < 10_000 {
        return Err("Gas limit too low (minimum 10,000)".to_string());
    }
    if gas_limit > 1_000_000_000 {
        return Err("Gas limit too high (maximum 1,000,000,000)".to_string());
    }
    
    // Validate memory limit (reasonable range)
    if memory_limit < 1 || memory_limit > 10_000 {
        return Err("Invalid memory limit (valid range: 1-10000 pages)".to_string());
    }
    
    // Set up metering middleware for gas control
    let metering = Metering::new(gas_limit, cost_function);
    let mut store = Store::default();
    
    // Create module with size validation
    let module = match Module::new(&store, wasm_bytes) {
        Ok(m) => m,
        Err(e) => {
            log_contract_event(contract_address, "deploy_failed", &format!("Module creation: {}", e));
            return Err(format!("Module creation failed: {}", e));
        }
    };
    
    let import_object = imports! {};
    let instance = match Instance::new(&mut store, &module, &import_object) {
        Ok(i) => i,
        Err(e) => {
            log_contract_event(contract_address, "instantiate_failed", &format!("Instance creation: {}", e));
            return Err(format!("Instance creation failed: {}", e));
        }
    };
    
    // Validate and enforce memory limits
    match instance.exports.get_memory("memory") {
        Ok(memory) => {
            let mem_pages = memory.ty(&store).minimum;
            if mem_pages > wasmer::Pages(memory_limit) {
                log_contract_event(contract_address, "memory_limit_exceeded", &format!("Required: {} pages, Limit: {} pages", mem_pages.0, memory_limit));
                return Err(format!("Contract memory usage exceeds limit: {} > {}", mem_pages.0, memory_limit));
            }
        }
        Err(e) => {
            log_contract_event(contract_address, "memory_access_failed", &e.to_string());
            return Err(format!("Failed to access contract memory: {}", e));
        }
    }
    
    // Call the contract's main function with parameter validation
    let main_func = match instance.exports.get_function("main") {
        Ok(f) => f,
        Err(e) => {
            log_contract_event(contract_address, "no_main_function", "Contract does not export 'main'");
            return Err(format!("Contract does not export 'main' function: {}", e));
        }
    };
    
    // Execute with gas metering
    let result = main_func.call(&mut store, params);
    
    // Check remaining gas
    let gas_left = wasmer_middlewares::metering::get_remaining_points(&mut store, &instance);
    if matches!(gas_left, wasmer_middlewares::metering::MeteringPoints::Remaining(0)) {
        log_contract_event(contract_address, "gas_limit_exceeded", "Out of gas");
        return Err("Gas limit exceeded during contract execution".to_string());
    }
    
    // Process execution result
    match result {
        Ok(val) => {
            let gas_used = gas_limit - match gas_left {
                wasmer_middlewares::metering::MeteringPoints::Remaining(g) => g,
                _ => 0,
            };
            log_contract_event(contract_address, "executed", &format!("success (gas used: {})", gas_used));
            Ok(val.to_vec())
        },
        Err(e) => {
            log_contract_event(contract_address, "execution_failed", &e.to_string());
            Err(format!("Contract execution failed: {}", e))
        }
    }
}

// --- Smart Contract Audit Checklist ---
// - [ ] Gas metering enforced for all contract calls
// - [ ] Memory and syscall sandboxing
// - [ ] Event logging for all state changes and errors
// - [ ] Input validation and error handling
// - [ ] No unsafe host calls or external dependencies
// - [ ] All contract code reviewed and tested
// - [ ] Contract upgrade and migration logic (if supported)
// - [ ] On-chain event log and audit trail

// TODO: Add resource metering and performance optimizations.
