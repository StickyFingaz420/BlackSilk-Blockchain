//! HTTP API server for BlackSilk node
//! Provides REST endpoints for wallets and external applications

use std::collections::HashMap;
use std::net::TcpStream;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use primitives::{Block, Transaction};
use crate::{CHAIN, MEMPOOL, add_to_mempool, validate_transaction};
use crate::randomx_verifier::RandomXVerifier;

lazy_static::lazy_static! {
    /// Global RandomX verifier with CPU-only enforcement
    static ref RANDOMX_VERIFIER: RandomXVerifier = RandomXVerifier::new();
}

/// Calculate merkle root for a list of transactions
fn calculate_merkle_root(transactions: &[Transaction]) -> [u8; 32] {
    if transactions.is_empty() {
        return [0; 32]; // Empty merkle root for blocks with no transactions
    }
    
    // For now, simple hash of all transaction data
    let mut hasher = sha2::Sha256::new();
    for tx in transactions {
        if let Ok(tx_bytes) = serde_json::to_vec(tx) {
            hasher.update(&tx_bytes);
        }
    }
    hasher.finalize().into()
}

/// Save chain to disk (persistence)
fn save_chain_to_disk(chain: &crate::Chain) {
    use std::fs::File;
    use std::io::Write;
    
    if let Ok(chain_json) = serde_json::to_string_pretty(&chain.blocks) {
        if let Ok(mut file) = File::create("/workspaces/BlackSilk-Blockchain/chain.json") {
            let _ = file.write_all(chain_json.as_bytes());
            println!("[Chain] Blockchain saved to disk");
        }
    }
}

/// HTTP request/response types
#[derive(Serialize, Deserialize)]
pub struct GetBlocksResponse {
    pub blocks: Vec<Block>,
    pub total_height: u64,
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
pub async fn start_http_server(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    use std::net::TcpListener;
    use std::thread;
    
    let addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&addr)?;
    println!("[HTTP] Server listening on http://{}", addr);
    
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(|| {
                    if let Err(e) = handle_http_request(stream) {
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
pub fn start_http_server_sync(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    use std::net::TcpListener;
    use std::thread;
    
    let addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&addr)?;
    println!("[HTTP] Server listening on http://{}", addr);
    
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(|| {
                    if let Err(e) = handle_http_request(stream) {
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

fn handle_http_request(mut stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
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
        body.resize(content_length, 0);
        std::io::Read::read_exact(&mut reader, &mut body)?;
    }
    
    // Route the request
    match (method, path) {
        ("GET", path) if path.starts_with("/get_blocks") => {
            handle_get_blocks(&mut stream, path)?;
        }
        ("POST", "/submit_tx") => {
            handle_submit_transaction(&mut stream, &body)?;
        }
        ("GET", "/mempool") => {
            handle_get_mempool(&mut stream)?;
        }
        ("GET", "/info") => {
            handle_node_info(&mut stream)?;
        }
        ("GET", "/health") => {
            send_json_response(&mut stream, 200, &serde_json::json!({"status": "ok"}))?;
        }
        ("POST", "/mining/get_block_template") => {
            handle_get_block_template(&mut stream, &body)?;
        }
        ("POST", "/mining/submit_block") => {
            handle_submit_block(&mut stream, &body)?;
        }
        _ => {
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
    let chain = CHAIN.lock().unwrap();
    let response = NodeInfoResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        network: std::env::var("BLACKSILK_NETWORK").unwrap_or_else(|_| "testnet".to_string()),
        height: chain.blocks.len() as u64,
        peers: 0, // TODO: Get actual peer count
        difficulty: 1, // TODO: Get actual difficulty
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

fn handle_submit_block(stream: &mut TcpStream, body: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    use crate::{CHAIN, current_network, broadcast_message, P2PMessage};
    use primitives::{Block, BlockHeader, Coinbase, Pow};
    use std::time::{SystemTime, UNIX_EPOCH};
    
    match serde_json::from_slice::<SubmitBlockRequest>(body) {
        Ok(req) => {
            // Extract peer information for suspicious behavior tracking
            let peer_id = req.miner_address.as_deref().unwrap_or("unknown");
            
            // Build the BlockHeader from the submitted data
            let mut chain = CHAIN.lock().unwrap();
            let prev_block = chain.tip();
            let new_height = prev_block.header.height + 1;
            
            // Get current network configuration  
            let network = current_network();
            let current_difficulty = network.get_difficulty();
            
            // Create block header for verification
            let block_header = BlockHeader {
                version: 1,
                prev_hash: prev_block.header.pow.hash,
                merkle_root: calculate_merkle_root(&[]), // Empty for now
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                height: new_height,
                difficulty: current_difficulty,
                pow: Pow {
                    nonce: req.nonce,
                    hash: req.hash.clone().try_into().unwrap_or([0; 32]),
                },
            };
            
            // CRITICAL: Full RandomX CPU-Only Verification
            println!("[RandomX] Verifying block submission from peer: {}", peer_id);
            let verification_result = RANDOMX_VERIFIER.verify_block_pow(&block_header, Some(peer_id));
            
            // Log verification results
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
                return Ok(());
            }
            
            // Check if hash meets current difficulty (redundant check after RandomX verification)
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
                return Ok(());
            }
            
            // CREATE AND ADD REAL BLOCK TO CHAIN
            // Calculate block reward based on emission schedule
            let block_reward = chain.emission.block_reward(new_height);
            
            // Create coinbase transaction for miner reward
            let miner_address = req.miner_address
                .unwrap_or_else(|| {
                    // Try to extract from header data (format: height:prev_hash:timestamp:address)
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
            
            // Create the new block
            let new_block = Block {
                header: block_header,
                coinbase,
                transactions: vec![], // No user transactions in this block
            };
            
            // Validate and add block to chain
            if chain.add_block(new_block.clone()) {
                let hash_hex = hex::encode(&req.hash);
                
                // Save chain to disk
                save_chain_to_disk(&chain);
                
                // Broadcast new block to P2P network
                drop(chain); // Release lock before broadcast
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
        }
        Err(e) => {
            let response = SubmitBlockResponse {
                success: false,
                message: format!("Invalid block format: {}", e),
            };
            send_json_response(stream, 400, &response)?;
        }
    }
    
    Ok(())
}
