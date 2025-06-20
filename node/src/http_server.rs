//! HTTP API server for BlackSilk node
//! Provides REST endpoints for wallets and external applications

use std::collections::HashMap;
use std::net::TcpStream;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use primitives::{Block, Transaction};
use crate::{CHAIN, MEMPOOL, add_to_mempool, validate_transaction};
use crate::randomx_verifier::RandomXVerifier;
use crate::wasm_vm;

lazy_static::lazy_static! {
    /// Global RandomX verifier with CPU-only enforcement
    static ref RANDOMX_VERIFIER: RandomXVerifier = RandomXVerifier::new();
}

/// Calculate merkle root for a list of transactions
fn calculate_merkle_root(transactions: &[Transaction]) -> [u8; 32] {
    use crate::randomx::{randomx_hash, get_optimal_flags};
    if transactions.is_empty() {
        return [0; 32]; // Empty merkle root for blocks with no transactions
    }
    // Hash each transaction using SHA256, then concatenate
    let mut tx_hashes = Vec::new();
    for tx in transactions {
        if let Ok(tx_bytes) = serde_json::to_vec(tx) {
            let hash = sha2::Sha256::digest(&tx_bytes);
            tx_hashes.extend_from_slice(&hash);
        }
    }
    // Use RandomX to hash the concatenated transaction hashes
    let key = b"blacksilk_merkle_root";
    let flags = get_optimal_flags();
    randomx_hash(key, &tx_hashes, flags)
}

/// Save chain to disk (persistence)
pub fn save_chain_to_disk(chain: &crate::Chain, data_dir: &std::path::Path) {
    use std::fs::{File, create_dir_all};
    use std::io::Write;
    use std::path::Path;
    // Ensure data directory exists
    if let Err(e) = create_dir_all(data_dir) {
        println!("[Chain] Failed to create data dir {:?}: {}", data_dir, e);
        return;
    }
    let chain_path = data_dir.join("chain.json");
    if let Ok(chain_json) = serde_json::to_string_pretty(&chain.blocks) {
        if let Ok(mut file) = File::create(&chain_path) {
            let _ = file.write_all(chain_json.as_bytes());
            println!("[Chain] Blockchain saved to disk at {:?}", chain_path);
        } else {
            println!("[Chain] Failed to create chain file at {:?}", chain_path);
        }
    } else {
        println!("[Chain] Failed to serialize chain for saving");
    }
}

/// HTTP request/response types
#[derive(Serialize, Deserialize)]
pub struct GetBlocksResponse {
    pub blocks: Vec<Block>,
    pub total_height: u64,
}

/// Marketplace data storage endpoints
#[derive(Serialize, Deserialize)]
pub struct MarketplaceDataRequest {
    pub data: String, // Base64 encoded marketplace data
    pub timestamp: i64,
}

#[derive(Serialize, Deserialize)]
pub struct MarketplaceDataResponse {
    pub tx_hash: String,
    pub success: bool,
    pub message: String,
}

#[derive(Serialize, Deserialize)]
pub struct MarketplaceTransactionResponse {
    pub data: Option<String>, // Base64 encoded data
    pub timestamp: Option<i64>,
    pub block_height: Option<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct MarketplaceTransactionsResponse {
    pub transactions: Vec<MarketplaceTransaction>,
}

#[derive(Serialize, Deserialize)]
pub struct MarketplaceTransaction {
    pub tx_hash: String,
    pub data: String,
    pub timestamp: i64,
    pub block_height: Option<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct SubmitTransactionRequest {
    pub transaction: Transaction,
}

#[derive(Serialize, Deserialize)]
pub struct SubmitTransactionResponse {
    pub success: bool,
    pub message: String,
    pub tx_hash: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct GetMempoolResponse {
    pub transactions: Vec<Transaction>,
    pub count: usize,
}

#[derive(Serialize, Deserialize)]
pub struct NodeInfoResponse {
    pub version: String,
    pub network: String,
    pub height: u64,
    pub peers: u32,
    pub difficulty: u64,
}

#[derive(Serialize, Deserialize)]
pub struct GetBlockTemplateRequest {
    pub address: String,
}

#[derive(Serialize, Deserialize)]
pub struct GetBlockTemplateResponse {
    pub header: Vec<u8>,
    pub difficulty: u64,
    pub seed: Vec<u8>,
    pub coinbase_address: String,
    pub height: u64,
    pub prev_hash: Vec<u8>,
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize)]
pub struct SubmitBlockRequest {
    pub header: Vec<u8>,
    pub nonce: u64,
    pub hash: Vec<u8>,
    pub miner_address: Option<String>, // Miner address for coinbase reward
}

#[derive(Serialize, Deserialize)]
pub struct SubmitBlockResponse {
    pub success: bool,
    pub message: String,
}

/// Simple HTTP server implementation using std library
pub async fn start_http_server(port: u16, data_dir: std::path::PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    use std::net::TcpListener;
    use std::thread;
    let addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&addr)?;
    println!("[HTTP] Server listening on http://{}", addr);
    for stream in listener.incoming() {
        let data_dir = data_dir.clone();
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    if let Err(e) = handle_http_request(stream, &data_dir) {
                        eprintln!("[HTTP] Error handling request: {}", e);
                    }
                });
            }
            Err(e) => {
                eprintln!("[HTTP] Connection failed: {}", e);
            }
        }
    }
    Ok(())
}

/// Synchronous HTTP server startup (blocks current thread)
pub fn start_http_server_sync(port: u16, data_dir: std::path::PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    use std::net::TcpListener;
    use std::thread;
    
    let addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&addr)?;
    println!("[HTTP] Server listening on http://{}", addr);
    
    for stream in listener.incoming() {
        let data_dir = data_dir.clone();
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    if let Err(e) = handle_http_request(stream, &data_dir) {
                        eprintln!("[HTTP] Error handling request: {}", e);
                    }
                });
            }
            Err(e) => {
                eprintln!("[HTTP] Connection failed: {}", e);
            }
        }
    }
    
    Ok(())
}

fn handle_http_request(mut stream: TcpStream, data_dir: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{BufRead, BufReader};
    
    let mut reader = BufReader::new(&stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        send_error_response(&mut stream, 400, "Bad Request")?;
        return Ok(());
    }
    
    let method = parts[0];
    let path = parts[1];
    
    println!("[HTTP] Received request: {} {}", method, path);
    
    // Parse headers to get content length for POST requests
    let mut headers = HashMap::new();
    let mut content_length = 0;
    
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line.trim().is_empty() {
            break;
        }
        
        if let Some(colon_pos) = line.find(':') {
            let key = line[..colon_pos].trim().to_lowercase();
            let value = line[colon_pos + 1..].trim();
            
            if key == "content-length" {
                content_length = value.parse().unwrap_or(0);
            }
            
            headers.insert(key, value.to_string());
        }
    }
    
    // Read request body for POST requests
    let mut body = Vec::new();
    if method == "POST" && content_length > 0 {
        println!("[HTTP] Reading POST body, content_length: {}", content_length);
        body.resize(content_length, 0);
        match std::io::Read::read_exact(&mut reader, &mut body) {
            Ok(_) => {
                println!("[HTTP] Successfully read {} bytes", body.len());
            }
            Err(e) => {
                println!("[HTTP] Error reading body: {}", e);
                send_error_response(&mut stream, 400, "Error reading request body")?;
                return Ok(());
            }
        }
    } else if method == "POST" {
        println!("[HTTP] POST request with no content-length or content-length = 0");
    }
    
    // Route the request
    println!("[HTTP] Routing: method='{}', path='{}', body_len={}", method, path, body.len());
    match (method, path) {
        ("GET", path) if path.starts_with("/get_blocks") => {
            println!("[HTTP] Matched: GET /get_blocks");
            handle_get_blocks(&mut stream, path)?;
        }
        ("POST", "/submit_tx") => {
            println!("[HTTP] Matched: POST /submit_tx");
            handle_submit_transaction(&mut stream, &body)?;
        }
        ("GET", "/mempool") => {
            println!("[HTTP] Matched: GET /mempool");
            handle_get_mempool(&mut stream)?;
        }
        ("GET", "/info") => {
            println!("[HTTP] Matched: GET /info");
            handle_node_info(&mut stream)?;
        }
        ("GET", "/health") => {
            println!("[HTTP] Matched: GET /health");
            send_json_response(&mut stream, 200, &serde_json::json!({"status": "ok"}))?;
        }
        ("POST", "/get_block_template") => {
            println!("[HTTP] Matched: POST /get_block_template");
            handle_get_block_template(&mut stream, &body)?;
        }
        ("POST", "/submit_block") => {
            println!("[HTTP] Matched: POST /submit_block");
            handle_submit_block(&mut stream, &body, data_dir)?;
        }
        // Marketplace data storage endpoints
        ("POST", "/api/marketplace/data") => {
            handle_marketplace_data_submit(&mut stream, &body)?;
        }
        ("GET", path) if path.starts_with("/api/marketplace/data/") => {
            handle_marketplace_data_get(&mut stream, path)?;
        }
        ("GET", "/api/marketplace/transactions") => {
            handle_marketplace_transactions_get(&mut stream)?;
        }
        ("POST", "/api/contract/deploy") => {
            handle_contract_deploy(&mut stream, &body)?;
        }
        ("POST", "/api/contract/invoke") => {
            handle_contract_invoke(&mut stream, &body)?;
        }
        ("GET", path) if path.starts_with("/api/contract/state/") => {
            handle_contract_state_query(&mut stream, path)?;
        }
        _ => {
            println!("[HTTP] No route matched for: {} {}", method, path);
            send_error_response(&mut stream, 404, "Not Found")?;
        }
    }
    
    Ok(())
}

fn handle_get_blocks(stream: &mut TcpStream, path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Parse query parameters
    let from_height = if let Some(query_start) = path.find('?') {
        let query = &path[query_start + 1..];
        parse_query_param(query, "from_height").unwrap_or(0)
    } else {
        0
    };
    
    let chain = CHAIN.lock().unwrap();
    let blocks: Vec<Block> = chain.blocks
        .iter()
        .filter(|block| block.header.height >= from_height)
        .cloned()
        .collect();
    
    // Check if client expects simple format (for wallet compatibility)
    let use_simple_format = path.contains("simple=true") || path.contains("wallet=true");
    
    if use_simple_format {
        // Return just the blocks array for wallet compatibility
        send_json_response(stream, 200, &blocks)?;
    } else {
        // Return full response with metadata
        let response = GetBlocksResponse {
            total_height: chain.blocks.len() as u64,
            blocks,
        };
        send_json_response(stream, 200, &response)?;
    }
    
    Ok(())
}

fn handle_submit_transaction(stream: &mut TcpStream, body: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let body_str = std::str::from_utf8(body)?;
    
    match serde_json::from_str::<Transaction>(body_str) {
        Ok(transaction) => {
            if validate_transaction(&transaction) {
                add_to_mempool(transaction.clone());
                
                // Broadcast to P2P network
                use crate::{broadcast_message, P2PMessage};
                broadcast_message(&P2PMessage::Transaction(transaction.clone()));
                
                let response = SubmitTransactionResponse {
                    success: true,
                    message: "Transaction accepted".to_string(),
                    tx_hash: Some("0x".to_string() + &format!("{:x}", sha2::Sha256::digest(&serde_json::to_vec(&transaction).unwrap_or_default()))),
                };
                send_json_response(stream, 200, &response)?;
            } else {
                let response = SubmitTransactionResponse {
                    success: false,
                    message: "Transaction validation failed".to_string(),
                    tx_hash: None,
                };
                send_json_response(stream, 400, &response)?;
            }
        }
        Err(e) => {
            let response = SubmitTransactionResponse {
                success: false,
                message: format!("Invalid transaction format: {}", e),
                tx_hash: None,
            };
            send_json_response(stream, 400, &response)?;
        }
    }
    
    Ok(())
}

fn handle_get_mempool(stream: &mut TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let mempool = MEMPOOL.lock().unwrap();
    let response = GetMempoolResponse {
        count: mempool.len(),
        transactions: mempool.clone(),
    };
    
    send_json_response(stream, 200, &response)?;
    Ok(())
}

fn handle_node_info(stream: &mut TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    use crate::{current_network, PEER_COUNT};
    
    let chain = CHAIN.lock().unwrap();
    let current_height = chain.blocks.len() as u64;
    let network = current_network();
    let current_difficulty = if current_height > 0 {
        chain.tip().header.difficulty
    } else {
        network.get_difficulty()
    };
    
    // Get peer count from global atomic counter
    let peer_count = PEER_COUNT.load(std::sync::atomic::Ordering::Relaxed);
    
    let response = NodeInfoResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        network: format!("{:?}", network).to_lowercase(),
        height: current_height,
        peers: peer_count,
        difficulty: current_difficulty,
    };
    
    send_json_response(stream, 200, &response)?;
    Ok(())
}

fn send_json_response<T: Serialize>(
    stream: &mut TcpStream,
    status: u16,
    data: &T,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    
    let json = serde_json::to_string(data)?;
    let response = format!(
        "HTTP/1.1 {} OK\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
         Access-Control-Allow-Headers: Content-Type\r\n\
         \r\n\
         {}",
        status,
        json.len(),
        json
    );
    
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    Ok(())
}

fn send_error_response(
    stream: &mut TcpStream,
    status: u16,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    
    let response = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {}",
        status,
        message,
        message.len(),
        message
    );
    
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    Ok(())
}

fn parse_query_param(query: &str, param: &str) -> Option<u64> {
    for pair in query.split('&') {
        if let Some(eq_pos) = pair.find('=') {
            let key = &pair[..eq_pos];
            let value = &pair[eq_pos + 1..];
            
            if key == param {
                return value.parse().ok();
            }
        }
    }
    None
}

fn handle_get_block_template(stream: &mut TcpStream, body: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    use crate::{CHAIN, MEMPOOL, current_network};
    
    match serde_json::from_slice::<GetBlockTemplateRequest>(body) {
        Ok(req) => {
            let chain = CHAIN.lock().unwrap();
            let _mempool = MEMPOOL.lock().unwrap();
            
            // Get the latest block
            let prev_block = chain.blocks.back().unwrap();
            let height = prev_block.header.height + 1;
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            // Get current network and calculate difficulty
            let network = current_network();
            let difficulty = network.calculate_next_difficulty(&chain);
            
            // Create block template with mempool transactions
            let header_data = format!("{}:{}:{}:{}", 
                height, 
                hex::encode(&prev_block.header.pow.hash), 
                timestamp, 
                req.address
            );
            
            // Generate RandomX seed from previous block hash
            let seed = prev_block.header.pow.hash.to_vec();
            
            let response = GetBlockTemplateResponse {
                header: header_data.as_bytes().to_vec(),
                difficulty, // Use calculated difficulty instead of hardcoded value
                seed,
                coinbase_address: req.address,
                height,
                prev_hash: prev_block.header.pow.hash.to_vec(),
                timestamp,
            };
            
            println!("[Mining] Block template generated - Height: {}, Difficulty: {}", height, difficulty);
            send_json_response(stream, 200, &response)?;
        }
        Err(e) => {
            let response = serde_json::json!({
                "success": false,
                "message": format!("Invalid request format: {}", e)
            });
            send_json_response(stream, 400, &response)?;
        }
    }
    
    Ok(())
}

fn handle_submit_block(stream: &mut TcpStream, body: &[u8], data_dir: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    use crate::{CHAIN, current_network, broadcast_message, P2PMessage};
    use primitives::{Block, BlockHeader, Coinbase, Pow};
    use std::time::{SystemTime, UNIX_EPOCH};
    use std::sync::MutexGuard;
    use std::panic;

    println!("[HTTP] Entered handle_submit_block");

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        // Step 1: Parse request
        let req = match serde_json::from_slice::<SubmitBlockRequest>(body) {
            Ok(r) => r,
            Err(e) => {
                let response = SubmitBlockResponse {
                    success: false,
                    message: format!("Invalid block format: {}", e),
                };
                send_json_response(stream, 400, &response)?;
                return Ok::<(), Box<dyn std::error::Error>>(());
            }
        };
        let peer_id = req.miner_address.as_deref().unwrap_or("unknown");
        println!("[HTTP] Parsed block submission from peer: {}", peer_id);

        // Step 2: Build block header (need chain tip for prev_hash/height, so get tip under lock, then release)
        let (prev_hash, prev_height, emission, current_difficulty) = {
            let chain = CHAIN.lock().unwrap();
            let prev_block = chain.tip();
            (
                prev_block.header.pow.hash,
                prev_block.header.height,
                chain.emission.clone(),
                current_network().get_difficulty(),
            )
        };
        let new_height = prev_height + 1;
        let block_header = BlockHeader {
            version: 1,
            prev_hash,
            merkle_root: calculate_merkle_root(&[]),
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            height: new_height,
            difficulty: current_difficulty,
            pow: Pow {
                nonce: req.nonce,
                hash: req.hash.clone().try_into().unwrap_or([0; 32]),
            },
        };
        println!("[RandomX] Verifying block submission from peer: {}", peer_id);
        // Step 3: RandomX verification (expensive!)
        let verification_result = RANDOMX_VERIFIER.verify_block_pow(&block_header, Some(peer_id));
        println!("[RandomX] Verification time: {:.2}ms", verification_result.verification_time_ms);
        if verification_result.is_suspicious {
            println!("[RandomX] ⚠️  SUSPICIOUS: {}", verification_result.reason);
        }
        if !verification_result.is_valid {
            println!("[RandomX] ❌ Block REJECTED: {}", verification_result.reason);
            let response = SubmitBlockResponse {
                success: false,
                message: format!("RandomX verification failed: {}", verification_result.reason),
            };
            send_json_response(stream, 400, &response)?;
            return Ok::<(), Box<dyn std::error::Error>>(());
        }
        let hash_val = if req.hash.len() >= 8 {
            u64::from_le_bytes([
                req.hash[0], req.hash[1], req.hash[2], req.hash[3],
                req.hash[4], req.hash[5], req.hash[6], req.hash[7]
            ])
        } else {
            u64::MAX
        };
        if hash_val >= current_difficulty {
            let response = SubmitBlockResponse {
                success: false,
                message: format!("Block does not meet difficulty target (hash: {}, difficulty: {})", hash_val, current_difficulty),
            };
            send_json_response(stream, 400, &response)?;
            return Ok::<(), Box<dyn std::error::Error>>(());
        }
        // Step 4: Build block (coinbase, etc.)
        let block_reward = emission.block_reward(new_height);
        let miner_address = req.miner_address
            .unwrap_or_else(|| {
                let header_str = String::from_utf8_lossy(&req.header);
                let parts: Vec<&str> = header_str.split(':').collect();
                if parts.len() >= 4 {
                    parts[3].to_string()
                } else {
                    "unknown_miner".to_string()
                }
            });
        let coinbase = Coinbase {
            reward: block_reward,
            to: miner_address.clone(),
        };
        let new_block = Block {
            header: block_header,
            coinbase,
            transactions: vec![],
        };
        // Step 5: Lock chain, add block, save, broadcast
        println!("[HTTP] Adding block to chain...");
        let mut chain = CHAIN.lock().unwrap();
        if chain.add_block(new_block.clone()) {
            let hash_hex = hex::encode(&req.hash);
            println!("[HTTP] Saving chain to disk...");
            save_chain_to_disk(&chain, data_dir);
            drop(chain);
            println!("[HTTP] Broadcasting new block to P2P network...");
            broadcast_message(&P2PMessage::Block(new_block));
            println!("[Mining] ✅ Block {} created and added to chain! Hash: {}", new_height, hash_hex);
            println!("[Mining] Block reward: {} atomic units to {}", block_reward, miner_address);
            println!("[RandomX] CPU-only verification PASSED - Block accepted");
            let response = SubmitBlockResponse {
                success: true,
                message: format!("Block {} accepted and added to chain with hash: {} (RandomX verified)", new_height, hash_hex),
            };
            send_json_response(stream, 200, &response)?;
        } else {
            let response = SubmitBlockResponse {
                success: false,
                message: "Block validation failed during chain addition".to_string(),
            };
            send_json_response(stream, 400, &response)?;
        }
        Ok(())
    }));

    if let Err(e) = result {
        println!("[PANIC] handle_submit_block panicked: {:?}", e);
        let response = SubmitBlockResponse {
            success: false,
            message: "Internal server error (panic in block submission)".to_string(),
        };
        let _ = send_json_response(stream, 500, &response);
    }
    Ok(())
}

// Marketplace data storage functions
fn handle_marketplace_data_submit(stream: &mut TcpStream, body: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let request: MarketplaceDataRequest = serde_json::from_slice(body)?;
    
    // Decode the base64 data using the new API
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let marketplace_data = STANDARD.decode(&request.data)?;
    
    // Create a professional marketplace data transaction
    use sha2::{Sha256, Digest};
    let mut signature_hasher = Sha256::new();
    Digest::update(&mut signature_hasher, &marketplace_data);
    Digest::update(&mut signature_hasher, &request.timestamp.to_le_bytes());
    Digest::update(&mut signature_hasher, b"MARKETPLACE_DATA");
    let signature = hex::encode(signature_hasher.finalize());
    
    // Create a transaction with marketplace data in metadata
    let tx = Transaction {
        kind: primitives::TransactionKind::Payment, // Data-only tx, not a contract
        inputs: vec![], // No financial inputs for data storage
        outputs: vec![], // No financial outputs for data storage
        fee: 0, // No fee for data storage transactions
        extra: vec![], // Marketplace data stored in metadata field
        metadata: Some(format!("MARKETPLACE:{}", request.data)), // Store the base64 marketplace data
        signature, // Cryptographic signature of the data and timestamp
        quantum_signature: None, // Add this field for quantum support
    };
    
    // Add to mempool for blockchain inclusion
    add_to_mempool(tx.clone());
    
    // Calculate transaction hash
    let tx_bytes = serde_json::to_vec(&tx)?;
    let mut hasher = sha2::Sha256::new();
    hasher.update(&tx_bytes);
    let tx_hash = hex::encode(hasher.finalize());
    
    println!("[Marketplace] 📦 Stored marketplace data with hash: {}", tx_hash);
    
    let response = MarketplaceDataResponse {
        tx_hash,
        success: true,
        message: "Marketplace data stored successfully".to_string(),
    };
    
    send_json_response(stream, 200, &response)
}

fn handle_marketplace_data_get(stream: &mut TcpStream, path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Extract transaction hash from path: /api/marketplace/data/{hash}
    let hash = path.strip_prefix("/api/marketplace/data/")
        .ok_or("Invalid path format")?;
    
    // Search for the transaction in the blockchain
    let chain = CHAIN.lock().unwrap();
    
    for block in &chain.blocks {
        for tx in &block.transactions {
            // Calculate this transaction's hash
            let tx_bytes = serde_json::to_vec(tx).unwrap_or_default();
            let mut hasher = sha2::Sha256::new();
            hasher.update(&tx_bytes);
            let tx_hash = hex::encode(hasher.finalize());
            
            if tx_hash == hash {
                // Check if this is a marketplace transaction
                if let Some(metadata) = &tx.metadata {
                    if metadata.starts_with("MARKETPLACE:") {
                        let data = metadata.strip_prefix("MARKETPLACE:").unwrap_or("");
                        let response = MarketplaceTransactionResponse {
                            data: Some(data.to_string()),
                            timestamp: Some(block.header.timestamp as i64),
                            block_height: Some(block.header.height),
                        };
                        return send_json_response(stream, 200, &response);
                    }
                }
            }
        }
    }
    
    // Also check mempool for pending transactions
    let mempool = MEMPOOL.lock().unwrap();
    for tx in &*mempool {
        let tx_bytes = serde_json::to_vec(tx).unwrap_or_default();
        let mut hasher = sha2::Sha256::new();
        hasher.update(&tx_bytes);
        let tx_hash = hex::encode(hasher.finalize());
        
        if tx_hash == hash {
            if let Some(metadata) = &tx.metadata {
                if metadata.starts_with("MARKETPLACE:") {
                    let data = metadata.strip_prefix("MARKETPLACE:").unwrap_or("");
                    let response = MarketplaceTransactionResponse {
                        data: Some(data.to_string()),
                        timestamp: None, // Not yet in a block
                        block_height: None,
                    };
                    return send_json_response(stream, 200, &response);
                }
            }
        }
    }
    
    // Transaction not found
    send_error_response(stream, 404, "Transaction not found")
}

fn handle_marketplace_transactions_get(stream: &mut TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let mut transactions = Vec::new();
    
    // Get all marketplace transactions from the blockchain
    let chain = CHAIN.lock().unwrap();
    
    for block in &chain.blocks {
        for tx in &block.transactions {
            if let Some(metadata) = &tx.metadata {
                if metadata.starts_with("MARKETPLACE:") {
                    let data = metadata.strip_prefix("MARKETPLACE:").unwrap_or("");
                    
                    // Calculate transaction hash
                    let tx_bytes = serde_json::to_vec(tx).unwrap_or_default();
                    let mut hasher = sha2::Sha256::new();
                    hasher.update(&tx_bytes);
                    let tx_hash = hex::encode(hasher.finalize());
                    
                    transactions.push(MarketplaceTransaction {
                        tx_hash,
                        data: data.to_string(),
                        timestamp: block.header.timestamp as i64,
                        block_height: Some(block.header.height),
                    });
                }
            }
        }
    }
    
    // Also include pending transactions from mempool
    let mempool = MEMPOOL.lock().unwrap();
    for tx in &*mempool {
        if let Some(metadata) = &tx.metadata {
            if metadata.starts_with("MARKETPLACE:") {
                let data = metadata.strip_prefix("MARKETPLACE:").unwrap_or("");
                
                let tx_bytes = serde_json::to_vec(tx).unwrap_or_default();
                let mut hasher = sha2::Sha256::new();
                hasher.update(&tx_bytes);
                let tx_hash = hex::encode(hasher.finalize());
                
                transactions.push(MarketplaceTransaction {
                    tx_hash,
                    data: data.to_string(),
                    timestamp: chrono::Utc::now().timestamp(),
                    block_height: None, // Not yet in a block
                });
            }
        }
    }
    
    let response = MarketplaceTransactionsResponse { transactions };
    send_json_response(stream, 200, &response)
}

#[derive(Serialize, Deserialize)]
struct ContractDeployRequest {
    wasm_code: Vec<u8>,
    creator: String,
    metadata: Option<String>,
}
#[derive(Serialize, Deserialize)]
struct ContractDeployResponse {
    address: String,
    success: bool,
    message: String,
}
fn handle_contract_deploy(stream: &mut TcpStream, body: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let req: ContractDeployRequest = serde_json::from_slice(body)?;
    match wasm_vm::deploy_contract(req.wasm_code, req.creator) {
        Ok(address) => send_json_response(stream, 200, &ContractDeployResponse {
            address,
            success: true,
            message: "Contract deployed successfully".to_string(),
        }),
        Err(e) => send_json_response(stream, 400, &ContractDeployResponse {
            address: "".to_string(),
            success: false,
            message: e,
        }),
    }
}

#[derive(Serialize, Deserialize)]
struct ContractInvokeRequest {
    address: String,
    function: String,
    params: Vec<serde_json::Value>, // JSON array
}
#[derive(Serialize, Deserialize)]
struct ContractInvokeResponse {
    result: Option<Vec<serde_json::Value>>,
    success: bool,
    message: String,
}
fn handle_contract_invoke(stream: &mut TcpStream, body: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let req: ContractInvokeRequest = serde_json::from_slice(body)?;
    match wasm_vm::invoke_contract_json(&req.address, &req.function, &req.params) {
        Ok(result) => send_json_response(stream, 200, &ContractInvokeResponse {
            result: Some(result),
            success: true,
            message: "Contract invoked successfully".to_string(),
        }),
        Err(e) => send_json_response(stream, 400, &ContractInvokeResponse {
            result: None,
            success: false,
            message: e,
        }),
    }
}

fn handle_contract_state_query(stream: &mut TcpStream, path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let address = path.trim_start_matches("/api/contract/state/");
    match wasm_vm::load_contract_state(address) {
        Ok(state) => send_json_response(stream, 200, &serde_json::json!({"address": address, "state": base64::encode(state)})),
        Err(_) => send_json_response(stream, 404, &serde_json::json!({"error": "State not found"})),
    }
}
