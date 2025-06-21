//! BlackSilk Node - Testnet Bootstrap
//!
//! BlackSilk Blockchain Tokenomics
//! - No premine, no ICO. All coins are mined.
//! - Initial block reward: 5 BLK (atomic units)
//! - Block time: 120 seconds
//! - Halving every 1,051,200 blocks (~4 years)
//! - Supply cap: 21,000,000 BLK
//! - No tail emission: after cap, miners receive only transaction fees
//! See README and docs/architecture.md for full details.

#[macro_use]
extern crate lazy_static;

pub mod http_server;
pub mod randomx_verifier;
pub mod randomx;
pub mod wasm_vm;

use blake2::{Blake2b, Digest};
use blake2::digest::Update;
use digest::consts::U32;
use std::sync::atomic::{AtomicU32, Ordering};
use i2p::I2pClient;
use primitives::{TransactionKind, ContractTx, StealthAddress, types::PublicKey};
use serde::{Serialize, Deserialize};

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

/// Helper function for Blake2b hashing
fn blake2b(data: &[u8]) -> Vec<u8> {
    let mut hasher = Blake2b::<U32>::new();
    Update::update(&mut hasher, data);
    hasher.finalize().to_vec()
}

pub mod config {
    pub const TESTNET_MAGIC: u32 = 0x1D670; // July 26, 1953
    pub const MAINNET_MAGIC: u32 = 0xB1A6C; // May 24, 2025
    
    // Network Ports Configuration
    pub const TESTNET_P2P_PORT: u16 = 8333;     // P2P port for testnet
    pub const TESTNET_HTTP_PORT: u16 = 9333;    // HTTP API port for testnet
    pub const TESTNET_TOR_PORT: u16 = 10333;    // Tor hidden service port for testnet
    
    pub const MAINNET_P2P_PORT: u16 = 1776;     // P2P port for mainnet
    pub const MAINNET_HTTP_PORT: u16 = 2776;    // HTTP API port for mainnet  
    pub const MAINNET_TOR_PORT: u16 = 3776;     // Tor hidden service port for mainnet
    
    /// Block time in seconds (2 minutes) - FIXED TARGET
    pub const BLOCK_TIME_SEC: u64 = 120;
    
    /// Difficulty adjustment parameters
    pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 60; // Adjust every 60 blocks (~2 hours)
    pub const TESTNET_DIFFICULTY: u64 = 1;              // Minimal difficulty for testnet mining
    pub const MAINNET_DIFFICULTY: u64 = 100_000_000;    // Starting mainnet difficulty
    
    /// Initial block reward in atomic units (5 BLK)
    pub const GENESIS_REWARD: u64 = 5_000_000;
    /// Halving interval in blocks (~4 years at 2 min/block)
    pub const HALVING_INTERVAL: u64 = 1_051_200;
    /// No tail emission after cap (miners receive only fees after cap)
    pub const TAIL_EMISSION: u64 = 0;
    /// Maximum supply: 21 million BLK (in atomic units)
    pub const SUPPLY_CAP: u64 = 21_000_000 * 1_000_000;
    
    // Genesis timestamp for both networks - October 5, 1986
    pub const MAINNET_GENESIS_TIMESTAMP: u64 = 528_854_400; // October 5, 1986
    pub const TESTNET_GENESIS_TIMESTAMP: u64 = 528_854_400; // October 5, 1986
}

/// Network selection with proper port configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    fn from_env_or_default() -> Self {
        match std::env::var("BLACKSILK_NETWORK").as_deref() {
            Ok("mainnet") => Network::Mainnet,
            _ => Network::Testnet,
        }
    }
    
    pub fn get_ports(&self) -> NetworkPorts {
        match self {
            Network::Mainnet => NetworkPorts {
                p2p: config::MAINNET_P2P_PORT,
                http: config::MAINNET_HTTP_PORT,
                tor: config::MAINNET_TOR_PORT,
            },
            Network::Testnet => NetworkPorts {
                p2p: config::TESTNET_P2P_PORT,
                http: config::TESTNET_HTTP_PORT,
                tor: config::TESTNET_TOR_PORT,
            },
        }
    }
    
    pub fn get_difficulty(&self) -> u64 {
        match self {
            Network::Mainnet => config::MAINNET_DIFFICULTY,
            Network::Testnet => config::TESTNET_DIFFICULTY,
        }
    }
    
    /// Calculate next difficulty based on recent block times
    pub fn calculate_next_difficulty(&self, chain: &Chain) -> u64 {
        match self {
            Network::Testnet => {
                // Testnet: Keep fixed low difficulty for experiments
                config::TESTNET_DIFFICULTY
            },
            Network::Mainnet => {
                // Mainnet: Automatic difficulty adjustment every 60 blocks
                let current_height = chain.blocks.len() as u64;
                
                if current_height < config::DIFFICULTY_ADJUSTMENT_INTERVAL {
                    return config::MAINNET_DIFFICULTY; // Starting difficulty
                }
                
                if current_height % config::DIFFICULTY_ADJUSTMENT_INTERVAL != 0 {
                    // Not time for adjustment yet, return current difficulty
                    return chain.tip().header.difficulty;
                }
                
                // Calculate average block time over last 60 blocks
                let recent_blocks: Vec<_> = chain.blocks
                    .iter()
                    .rev()
                    .take(config::DIFFICULTY_ADJUSTMENT_INTERVAL as usize)
                    .collect();
                
                if recent_blocks.len() < 2 {
                    return chain.tip().header.difficulty;
                }
                
                let time_span = recent_blocks.first().unwrap().header.timestamp 
                    - recent_blocks.last().unwrap().header.timestamp;
                
                let expected_time = config::DIFFICULTY_ADJUSTMENT_INTERVAL * config::BLOCK_TIME_SEC;
                let current_difficulty = chain.tip().header.difficulty;
                
                // Adjust difficulty to maintain 120-second block time
                let new_difficulty = if time_span == 0 {
                    current_difficulty
                } else {
                    (current_difficulty * expected_time) / time_span
                };
                
                // Limit difficulty changes to prevent extreme swings
                let max_change = current_difficulty / 4; // 25% max change
                let min_difficulty = current_difficulty.saturating_sub(max_change);
                let max_difficulty = current_difficulty.saturating_add(max_change);
                
                new_difficulty.clamp(min_difficulty.max(1000), max_difficulty)
            }
        }
    }
    
    pub fn get_magic(&self) -> u32 {
        match self {
            Network::Mainnet => config::MAINNET_MAGIC,
            Network::Testnet => config::TESTNET_MAGIC,
        }
    }
    
    /// Get network configuration with privacy settings
    pub fn get_privacy_config(&self) -> network::privacy::PrivacyConfig {
        use network::privacy::{PrivacyConfig, PrivacyMode};
        
        match self {
            Network::Mainnet => PrivacyConfig {
                privacy_mode: PrivacyMode::Tor, // Mainnet prefers Tor
                tor_only: false,
                hidden_service_port: self.get_ports().tor,
                ..Default::default()
            },
            Network::Testnet => PrivacyConfig {
                privacy_mode: PrivacyMode::Disabled, // Testnet allows all for development
                tor_only: false,
                hidden_service_port: self.get_ports().tor,
                ..Default::default()
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetworkPorts {
    pub p2p: u16,
    pub http: u16,
    pub tor: u16,
}

use primitives::{Block, BlockHeader, Coinbase};
use primitives::{QuantumSignature};
use pqcrypto_native;
use std::collections::{VecDeque, HashSet};
use std::io::{Write, BufRead};
use std::net::{TcpListener, TcpStream, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use once_cell::sync::OnceCell;

/// Global network configuration
static CURRENT_NETWORK: OnceCell<Network> = OnceCell::new();

/// Get current network (defaults to testnet)
pub fn current_network() -> &'static Network {
    CURRENT_NETWORK.get_or_init(|| Network::Testnet)
}

/// Set current network (should be called early in main)
pub fn set_network(network: Network) -> Result<(), Network> {
    CURRENT_NETWORK.set(network)
}

#[derive(Serialize, Deserialize, Debug)]
pub enum P2PMessage {
    Version { version: u32, node: String },
    Ping,
    Pong,
    Block(primitives::Block),
    Transaction(primitives::Transaction),
    PeerList(Vec<String>),
    GetBlocks { from_height: u64 },
    Blocks(Vec<primitives::Block>),
    GetMempool,
    Mempool(Vec<primitives::Transaction>),
    // ... add more as needed
}

fn send_message(stream: &mut TcpStream, msg: &P2PMessage) -> std::io::Result<()> {
    let json = serde_json::to_string(msg)?;
    stream.write_all(json.as_bytes())?;
    stream.write_all(b"\n")?;
    Ok(())
}

fn read_message(stream: &mut TcpStream) -> Option<P2PMessage> {
    let mut buf = String::new();
    let mut reader = std::io::BufReader::new(stream);
    match reader.read_line(&mut buf) {
        Ok(0) => None, // EOF
        Ok(_) => serde_json::from_str(&buf).ok(),
        Err(_) => None,
    }
}

lazy_static! {
    pub static ref PEERS: Arc<Mutex<Vec<TcpStream>>> = Arc::new(Mutex::new(Vec::new()));
}

// Transaction pool (mempool)
lazy_static::lazy_static! {
    pub static ref MEMPOOL: Arc<Mutex<Vec<primitives::Transaction>>> = Arc::new(Mutex::new(Vec::new()));
}

lazy_static! {
    pub static ref CHAIN: Arc<Mutex<Chain>> = Arc::new(Mutex::new(Chain::new()));
}

// Global peer counter for tracking active connections
pub static PEER_COUNT: AtomicU32 = AtomicU32::new(0);

pub fn broadcast_message(msg: &P2PMessage) {
    let peers = PEERS.lock().unwrap();
    for peer in peers.iter() {
        let mut peer = peer.try_clone().unwrap();
        let _ = send_message(&mut peer, msg);
    }
}

fn handle_client(mut stream: TcpStream) {
    println!("[P2P] New peer: {}", stream.peer_addr().unwrap());
    
    // Increment peer count
    PEER_COUNT.fetch_add(1, Ordering::Relaxed);
    
    {
        let mut peers = PEERS.lock().unwrap();
        peers.push(stream.try_clone().unwrap());
        // Send current peer list to the new peer
        let peer_addrs: Vec<String> = peers.iter().filter_map(|s| s.peer_addr().ok().map(|a| a.to_string())).collect();
        let _ = send_message(&mut stream, &P2PMessage::PeerList(peer_addrs));
    }
    let version = P2PMessage::Version { version: 1, node: "BlackSilkNode".to_string() };
    let _ = send_message(&mut stream, &version);
    loop {
        match read_message(&mut stream) {
            Some(msg) => {
                println!("[P2P] Received: {:?}", msg);
                match msg {
                    P2PMessage::Ping => { let _ = send_message(&mut stream, &P2PMessage::Pong); },
                    P2PMessage::Pong => {},
                    P2PMessage::Version { .. } => {},
                    P2PMessage::Block(block) => {
                        let mut chain = CHAIN.lock().unwrap();
                        if chain.blocks.back().map_or(true, |b| block.header.prev_hash == b.header.pow.hash) {
                            if chain.add_block(block.clone()) {
                                println!("[Chain] Block added");
                                broadcast_message(&P2PMessage::Block(block));
                            } else {
                                println!("[Chain] Block rejected");
                            }
                        } else {
                            println!("[Chain] Block does not extend current chain. Possible fork or reorg needed.");
                            // TODO: Handle chain reorg (fork resolution)
                        }
                    },
                    P2PMessage::Transaction(tx) => {
                        if validate_transaction(&tx) {
                            add_to_mempool(tx.clone());
                            broadcast_message(&P2PMessage::Transaction(tx));
                            println!("[Mempool] Transaction accepted");
                        } else {
                            println!("[Mempool] Invalid transaction rejected");
                        }
                    },
                    P2PMessage::PeerList(peers) => {
                        println!("[P2P] Received peer list: {:?}", peers);
                    },
                    P2PMessage::GetBlocks { from_height } => {
                        let chain = CHAIN.lock().unwrap();
                        let blocks: Vec<_> = chain.blocks.iter().filter(|b| b.header.height >= from_height).cloned().collect();
                        let _ = send_message(&mut stream, &P2PMessage::Blocks(blocks));
                    },
                    P2PMessage::Blocks(blocks) => {
                        let mut chain = CHAIN.lock().unwrap();
                        if blocks.len() > chain.blocks.len() {
                            drop(chain); // unlock before reorg
                            maybe_reorg_chain(blocks);
                        } else {
                            for block in blocks {
                                if chain.blocks.back().map_or(true, |b| block.header.prev_hash == b.header.pow.hash) {
                                    chain.add_block(block);
                                } else {
                                    println!("[Chain] Received block does not extend current chain. Fork handling needed.");
                                }
                            }
                        }
                    },
                    P2PMessage::GetMempool => {
                        let mempool = get_mempool();
                        let _ = send_message(&mut stream, &P2PMessage::Mempool(mempool));
                    },
                    P2PMessage::Mempool(txs) => {
                        for tx in txs {
                            if validate_transaction(&tx) {
                                add_to_mempool(tx);
                            }
                        }
                    },
                }
            }
            None => {
                println!("[P2P] Peer disconnected");
                break;
            }
        }
    }
    // On disconnect:
    {
        let mut peers = PEERS.lock().unwrap();
        peers.retain(|s| s.peer_addr().unwrap() != stream.peer_addr().unwrap());
    }
    
    // Decrement peer count
    PEER_COUNT.fetch_sub(1, Ordering::Relaxed);
}

// Minimal CryptoNote-style ring signature verification
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::Sha256;

/// Verifies a minimal CryptoNote-style ring signature.
/// - `ring`: Vec of public keys (as [u8; 32])
/// - `sig`: signature bytes (expected: ring.len() pairs of (c, r), each 32 bytes)
/// - `msg`: message bytes
pub fn validate_ring_signature(ring: &[primitives::types::Hash], sig: &[u8], msg: &[u8]) -> bool {
    let n = ring.len();
    if n == 0 || sig.len() != n * 64 {
        println!("[VER] Invalid signature length");
        return false;
    }
    if n == 1 {
        // Special case: single-member ring
        let c = Scalar::from_canonical_bytes(sig[0..32].try_into().unwrap());
        let r = Scalar::from_canonical_bytes(sig[32..64].try_into().unwrap());
        if bool::from(c.is_none()) || bool::from(r.is_none()) {
            println!("[VER] Invalid c or r for n=1");
            return false;
        }
        let c = c.unwrap();
        let r = r.unwrap();
        let pk = CompressedEdwardsY(ring[0]).decompress();
        if pk.is_none() {
            println!("[VER] Invalid pubkey for n=1");
            return false;
        }
        let l0 = EdwardsPoint::mul_base(&r) + pk.unwrap() * c;
        let mut hasher = Sha256::new();
        digest::Update::update(&mut hasher, l0.compress().as_bytes());
        digest::Update::update(&mut hasher, msg);
        let mut c_bytes = [0u8; 32];
        c_bytes.copy_from_slice(&hasher.finalize_reset()[..32]);
        let c_check = Scalar::from_bytes_mod_order(c_bytes);
        let valid = c == c_check;
        println!("[VER] n=1: c == c_check? {}", valid);
        return valid;
    }
    // Parse signature: (c_0, r_0), (c_1, r_1), ...
    let mut c_vec = Vec::with_capacity(n);
    let mut r_vec = Vec::with_capacity(n);
    for i in 0..n {
        let c = Scalar::from_canonical_bytes(sig[i*64..i*64+32].try_into().unwrap());
        let r = Scalar::from_canonical_bytes(sig[i*64+32..i*64+64].try_into().unwrap());
        if bool::from(c.is_none()) || bool::from(r.is_none()) {
            println!("[VER] Invalid c or r at {}", i);
            return false;
        }
        c_vec.push(c.unwrap());
        r_vec.push(r.unwrap());
        println!("[VER] parsed c[{}]: {:?}", i, c_vec[i]);
        println!("[VER] parsed r[{}]: {:?}", i, r_vec[i]);
    }
    // Parse public keys
    let mut pubkeys = Vec::with_capacity(n);
    for (i, pk_bytes) in ring.iter().enumerate() {
        let pt = CompressedEdwardsY(*pk_bytes).decompress();
        if pt.is_none() {
            println!("[VER] Invalid pubkey at {}", i);
            return false;
        }
        pubkeys.push(pt.unwrap());
    }
    // Recompute challenge chain
    let mut hasher = Sha256::new();
    let l0 = EdwardsPoint::mul_base(&r_vec[0]);
    println!("[VER] L_0: {:?}", l0.compress().to_bytes());
    digest::Update::update(&mut hasher, l0.compress().as_bytes());
    digest::Update::update(&mut hasher, msg);
    let mut c_bytes = [0u8; 32];
    c_bytes.copy_from_slice(&hasher.finalize_reset()[..32]);
    let mut c = Scalar::from_bytes_mod_order(c_bytes);
    println!("[VER] verifier c_0: {:?}", c);
    for i in 1..n {
        let l = EdwardsPoint::mul_base(&r_vec[i]) + pubkeys[i] * c_vec[i];
        println!("[VER] verifier L_{}: {:?}", i, l.compress().to_bytes());
        digest::Update::update(&mut hasher, l.compress().as_bytes());
        digest::Update::update(&mut hasher, msg);
        let mut c_bytes = [0u8; 32];
        c_bytes.copy_from_slice(&hasher.finalize_reset()[..32]);
        c = Scalar::from_bytes_mod_order(c_bytes);
        println!("[VER] verifier c_{}: {:?}", (i + 1) % n, c);
        if c != c_vec[(i + 1) % n] {
            println!("[VER] Challenge mismatch at {}", (i + 1) % n);
            return false;
        }
    }
    // Final challenge must close the loop: c == c_vec[0]
    let valid = c == c_vec[0];
    println!("[VER] verifier final: c == c_0? {}", valid);
    valid
}

lazy_static! {
    static ref KEY_IMAGES: Arc<Mutex<std::collections::HashSet<primitives::types::Hash>>> = Arc::new(Mutex::new(std::collections::HashSet::new()));
}

/// Collect all key images from the chain and mempool
fn all_seen_key_images() -> HashSet<primitives::types::Hash> {
    let chain = CHAIN.lock().unwrap();
    let mempool = MEMPOOL.lock().unwrap();
    let mut set = HashSet::new();
    for block in &chain.blocks {
        for tx in &block.transactions {
            for input in &tx.inputs {
                set.insert(input.key_image);
            }
        }
    }
    for tx in mempool.iter() {
        for input in &tx.inputs {
            set.insert(input.key_image);
        }
    }
    set
}

pub fn validate_transaction(tx: &primitives::Transaction) -> bool {
    if tx.outputs.is_empty() {
        println!("[Validation] Transaction missing outputs");
        return false;
    }
    let seen_key_images = all_seen_key_images();
    for input in &tx.inputs {
        // Ring signature validation
        if !validate_ring_signature(&input.ring_sig.ring, &input.ring_sig.signature, &tx.extra) {
            println!("[Validation] Ring signature failed");
            return false;
        }
        // Double-spend prevention
        if seen_key_images.contains(&input.key_image) {
            println!("[Validation] Double-spend detected (key image reused)");
            return false;
        }
        // Quantum signature validation (if present)
        if let Some(qsig) = &input.ring_sig.quantum {
            if !validate_quantum_signature(qsig, &tx.extra) {
                println!("[Validation] Quantum ring signature failed");
                return false;
            }
        }
    }
    for output in &tx.outputs {
        // Enforce confidential amounts: every output must have a valid range proof (Bulletproof)
        if output.range_proof.is_empty() {
            println!("[Validation] Output missing range proof (confidential amount required)");
            return false;
        }
        if !validate_range_proof(&output.range_proof, &output.amount_commitment) {
            println!("[Validation] Range proof failed (invalid confidential amount)");
            return false;
        }
    }
    // Quantum transaction signature validation (if present)
    if let Some(qsig) = &tx.quantum_signature {
        if !validate_quantum_signature(qsig, &tx.extra) {
            println!("[Validation] Quantum transaction signature failed");
            return false;
        }
    }
    // Smart contract transaction validation
    match &tx.kind {
        TransactionKind::Contract(contract_tx) => {
            match contract_tx {
                ContractTx::Deploy { wasm_code, creator, .. } => {
                    // Basic WASM validation: can we parse the module?
                    if wasmer::Module::validate(&wasmer::Store::default(), wasm_code).is_err() {
                        println!("[Validation] Invalid WASM contract code");
                        return false;
                    }
                    // Check creator address validity
                    if !validate_address(creator) {
                        println!("[Validation] Invalid creator address");
                        return false;
                    }
                }
                ContractTx::Invoke { contract_address, function, .. } => {
                    // Optionally: check contract exists, function name format, etc.
                    // Params should be valid serialized data (JSON/bincode)
                    if !validate_address(contract_address) || function.is_empty() {
                        println!("[Validation] Invalid contract call parameters");
                        return false;
                    }
                }
            }
        }
        _ => {}
    }
    true
}

fn validate_quantum_signature(qsig: &QuantumSignature, msg: &[u8]) -> bool {
    match qsig {
        QuantumSignature::Dilithium2 { pk, sig } => {
            pqcrypto_native::dilithium2::verify(msg, sig, pk).is_ok()
        }
        QuantumSignature::Falcon512 { pk, sig } => {
            pqcrypto_native::falcon512::verify(msg, sig, pk).is_ok()
        }
        QuantumSignature::MLDSA44 { pk, sig } => {
            pqcrypto_native::mldsa44::verify(msg, sig, pk).is_ok()
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmissionSchedule {
    pub genesis_reward: u64,
    pub halving_interval: u64,
    pub supply_cap: u64,
}

impl EmissionSchedule {
    pub fn block_reward(&self, height: u64) -> u64 {
        let mut reward = self.genesis_reward;
        let halvings = height / self.halving_interval;
        for _ in 0..halvings {
            reward /= 2;
        }
        // Enforce no tail emission and supply cap
        if reward == 0 {
            return 0;
        }
        // Optionally, enforce supply cap logic here if needed
        reward
    }
}

pub fn default_emission() -> EmissionSchedule {
    EmissionSchedule {
        genesis_reward: config::GENESIS_REWARD,
        halving_interval: config::HALVING_INTERVAL,
        supply_cap: config::SUPPLY_CAP,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chain {
    pub blocks: VecDeque<Block>,
    pub emission: EmissionSchedule,
    pub network: Network,
}

impl Chain {
    pub fn new() -> Self {
        let network = Network::from_env_or_default();
        let emission = default_emission();
        let genesis = Self::genesis_block_with_params(&emission, &network);
        let mut blocks = VecDeque::new();
        blocks.push_back(genesis);
        Self { blocks, emission, network }
    }
    
    pub fn new_for_network(network: Network) -> Self {
        let emission = default_emission();
        let genesis = Self::genesis_block_with_params(&emission, &network);
        let mut blocks = VecDeque::new();
        blocks.push_back(genesis);
        Self { blocks, emission, network }
    }
    
    /// Generate a proper genesis address based on the network
    fn generate_genesis_address() -> String {
        // Generate a real BlackSilk address for genesis block
        // This should be a deterministic address based on known genesis keys
        let genesis_pub_key = [0u8; 32]; // Genesis public key (could be derived from known seed)
        let checksum = blake2b(&genesis_pub_key);
        format!("BlackSilk{}", hex::encode(&checksum[..20]))
    }
    
    fn genesis_block_with_params(emission: &EmissionSchedule, network: &Network) -> Block {
        let timestamp = match network {
            Network::Mainnet => config::MAINNET_GENESIS_TIMESTAMP,
            Network::Testnet => config::TESTNET_GENESIS_TIMESTAMP,
        };
        
        Block {
            header: BlockHeader {
                version: 1,
                prev_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                timestamp,
                height: 0,
                difficulty: network.get_difficulty(),
                pow: primitives::Pow { nonce: 0, hash: [0u8; 32] },
            },
            coinbase: Coinbase {
                reward: emission.genesis_reward,
                to: Self::generate_genesis_address(),
            },
            transactions: vec![],
        }
    }
    
    /// Calculate next difficulty using automatic adjustment algorithm
    pub fn calculate_next_difficulty(&self) -> u64 {
        let current_height = self.blocks.len() as u64;
        
        // Don't adjust difficulty for first few blocks
        if current_height < config::DIFFICULTY_ADJUSTMENT_INTERVAL {
            return self.network.get_difficulty();
        }
        
        // For testnet, keep difficulty very low for experiments
        if matches!(self.network, Network::Testnet) {
            return config::TESTNET_DIFFICULTY;
        }
        
        // Mainnet: Automatic difficulty adjustment every 60 blocks
        if current_height % config::DIFFICULTY_ADJUSTMENT_INTERVAL == 0 {
            let adjustment_start = current_height - config::DIFFICULTY_ADJUSTMENT_INTERVAL;
            let start_block = &self.blocks[adjustment_start as usize];
            let end_block = self.blocks.back().unwrap();
            
            let actual_time = end_block.header.timestamp - start_block.header.timestamp;
            let expected_time = config::DIFFICULTY_ADJUSTMENT_INTERVAL * config::BLOCK_TIME_SEC;
            
            let current_difficulty = end_block.header.difficulty;
            
            // Adjust difficulty to maintain 120-second block time
            let new_difficulty = if actual_time > 0 {
                (current_difficulty * expected_time) / actual_time
            } else {
                current_difficulty * 2 // Double if time calculation fails
            };
            
            // Limit adjustment to 4x change maximum (prevent huge swings)
            let max_adjustment = current_difficulty * 4;
            let min_adjustment = current_difficulty / 4;
            
            new_difficulty.max(min_adjustment).min(max_adjustment)
        } else {
            // Use previous block's difficulty
            self.blocks.back().unwrap().header.difficulty
        }
    }

    pub fn tip(&self) -> &Block {
        self.blocks.back().unwrap()
    }

    pub fn add_block(&mut self, block: Block) -> bool {
        // Set coinbase reward for this height
        let expected_reward = self.emission.block_reward(block.header.height);
        if block.coinbase.reward != expected_reward {
            println!("[Chain] Invalid coinbase reward: got {}, expected {}", block.coinbase.reward, expected_reward);
            return false;
        }
        if !validate_block(&block) {
            println!("[Chain] Block validation failed at height {}", block.header.height);
            return false;
        }
        // Process contract transactions
        for tx in &block.transactions {
            if let TransactionKind::Contract(contract_tx) = &tx.kind {
                match contract_tx {
                    ContractTx::Deploy { wasm_code, creator, .. } => {
                        let _ = wasm_vm::deploy_contract(wasm_code.clone(), creator.clone());
                    }
                    ContractTx::Invoke { contract_address, function, params, .. } => {
                        // Deserialize params as Vec<serde_json::Value>
                        let params_vec: Vec<serde_json::Value> = match serde_json::from_slice(params) {
                            Ok(v) => v,
                            Err(_) => continue,
                        };
                        let _ = wasm_vm::invoke_contract_json(contract_address, function, &params_vec);
                    }
                }
            }
        }
        self.blocks.push_back(block);
        true
    }
}

pub fn validate_block(block: &Block) -> bool {
    // Basic block validation without chain context
    validate_block_with_chain(block, None)
}

pub fn validate_block_with_chain(block: &Block, chain: Option<&Chain>) -> bool {
    // Check block has at least one transaction (coinbase)
    if block.transactions.is_empty() {
        println!("[Validation] Block missing coinbase transaction");
        return false;
    }
    // Check coinbase is first and has no inputs
    if !block.transactions[0].inputs.is_empty() {
        println!("[Validation] First transaction is not coinbase");
        return false;
    }
    // Check all transactions (except coinbase) have at least one input and output
    for (i, tx) in block.transactions.iter().enumerate().skip(1) {
        if tx.inputs.is_empty() || tx.outputs.is_empty() {
            println!("[Validation] Tx {} missing inputs or outputs", i);
            return false;
        }
    }
    
    // Enhanced validation with chain context
    if let Some(chain) = chain {
        // Validate block height sequence
        if block.header.height > 0 {
            let prev_block = chain.tip();
            if block.header.height != prev_block.header.height + 1 {
                println!("[Validation] Invalid block height: expected {}, got {}", 
                    prev_block.header.height + 1, block.header.height);
                return false;
            }
            // Validate previous hash
            if block.header.prev_hash != prev_block.header.pow.hash {
                println!("[Validation] Invalid previous hash");
                return false;
            }
        }
        
        // Validate coinbase reward
        let expected_reward = chain.emission.block_reward(block.header.height);
        if block.coinbase.reward != expected_reward {
            println!("[Validation] Invalid coinbase reward: got {}, expected {}", 
                block.coinbase.reward, expected_reward);
            return false;
        }
        
        // Validate difficulty (simplified check)
        if block.header.height > 0 {
            let expected_difficulty = chain.network.calculate_next_difficulty(chain);
            if block.header.difficulty != expected_difficulty {
                println!("[Validation] Invalid difficulty: got {}, expected {}", 
                    block.header.difficulty, expected_difficulty);
                // For now, just warn instead of rejecting
                // return false;
            }
        }
    }
    
    // TODO: Check merkle root, signatures, and block hash
    true
}

pub mod network {
    pub mod privacy;
}
use network::privacy::{PrivacyConfig, is_onion_address, is_i2p_address};
// use once_cell::sync::OnceCell; (already imported above)

static PRIVACY_CONFIG: OnceCell<PrivacyConfig> = OnceCell::new();

fn get_privacy_config() -> &'static PrivacyConfig {
    PRIVACY_CONFIG.get_or_init(|| PrivacyConfig {
        tor_only: true, // Enforce Tor/I2P only
        ..PrivacyConfig::default()
    })
}

pub fn connect_to_peer(addr: &str) {
    let privacy = get_privacy_config();
    let mode = &privacy.privacy_mode;
    match mode {
        crate::network::privacy::PrivacyMode::Auto => {
            // Try Tor first
            if is_onion_address(addr) {
                println!("[Privacy] Auto mode: trying Tor for {}", addr);
                // In a real implementation, use Tor SOCKS5 here
                // For now, fall through to clearnet if not available
            } else if is_i2p_address(addr) && privacy.i2p_enabled {
                println!("[Privacy] Auto mode: trying I2P for {}", addr);
                let sam_addr = privacy.i2p_proxy.as_deref().unwrap_or(i2p::DEFAULT_SAM_ADDR);
                match I2pClient::new(sam_addr, "blacksilk", "STREAM") {
                    Ok(mut client) => {
                        println!("[I2P] Connected to I2P peer {} via SAM {}", addr, sam_addr);
                        let version = P2PMessage::Version { version: 1, node: "BlackSilkNode-I2P".to_string() };
                        let data = serde_json::to_vec(&version).unwrap();
                        if let Err(e) = client.send_to(addr, &data) {
                            eprintln!("[I2P] Failed to send to I2P peer {}: {}", addr, e);
                        }
                        return;
                    }
                    Err(e) => {
                        eprintln!("[I2P] Failed to connect to I2P peer {}: {}", addr, e);
                    }
                }
            } else {
                println!("[Privacy] Auto mode: falling back to clearnet for {}", addr);
            }
        }
        _ => {
            if privacy.tor_only && !(is_onion_address(addr) || is_i2p_address(addr)) {
                println!("[Privacy] Connection to non-Tor/I2P address blocked: {}", addr);
                return;
            }
            if is_i2p_address(addr) && privacy.i2p_enabled {
                let sam_addr = privacy.i2p_proxy.as_deref().unwrap_or(i2p::DEFAULT_SAM_ADDR);
                match I2pClient::new(sam_addr, "blacksilk", "STREAM") {
                    Ok(mut client) => {
                        println!("[I2P] Connected to I2P peer {} via SAM {}", addr, sam_addr);
                        let version = P2PMessage::Version { version: 1, node: "BlackSilkNode-I2P".to_string() };
                        let data = serde_json::to_vec(&version).unwrap();
                        if let Err(e) = client.send_to(addr, &data) {
                            eprintln!("[I2P] Failed to send to I2P peer {}: {}", addr, e);
                        }
                        return;
                    }
                    Err(e) => {
                        eprintln!("[I2P] Failed to connect to I2P peer {}: {}", addr, e);
                    }
                }
                return;
            }
        }
    }
    // Default: clearnet connection
    let mut retries = 3;
    while retries > 0 {
        match TcpStream::connect(addr) {
            Ok(mut stream) => {
                println!("[P2P] Connected to peer {}", addr);
                let version = P2PMessage::Version { version: 1, node: "BlackSilkNode".to_string() };
                if let Err(e) = send_message(&mut stream, &version) {
                    eprintln!("[P2P] Failed to send version message: {}", e);
                }
                return;
            }
            Err(e) => {
                eprintln!("[P2P] Failed to connect to {}: {}", addr, e);
            }
        }
        retries -= 1;
        if retries > 0 {
            println!("[P2P] Retrying connection... ({} attempts left)", retries);
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    }
    println!("[P2P] All attempts to connect to peer {} failed.", addr);
}

pub fn start_p2p_server(port: u16) {
    let privacy = get_privacy_config();
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).expect("Failed to bind P2P port");
    println!("[P2P] Listening for peers on {}", addr);
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                // Check remote address for Tor/I2P enforcement
                let remote = s.peer_addr().map(|a| a.to_string()).unwrap_or_default();
                if privacy.tor_only && !(is_onion_address(&remote) || is_i2p_address(&remote)) {
                    println!("[Privacy] Rejected clearnet connection from {}", remote);
                    continue;
                }
                thread::spawn(|| handle_client(s));
            }
            Err(e) => println!("[P2P] Connection failed: {}", e),
        }
    }
}

pub fn start_node_with_port_and_connect(port: u16, connect_addr: Option<String>) {
    let network = Network::from_env_or_default();
    let magic = match network {
        Network::Mainnet => config::MAINNET_MAGIC,
        Network::Testnet => config::TESTNET_MAGIC,
    };
    println!("[BlackSilk Node] Starting {:?} node on port {} (magic: 0x{:X})", network, port, magic);
    let chain = Chain::new_for_network(network);
    println!("[BlackSilk Node] Genesis block height: {}", chain.tip().header.height);
    if let Some(addr) = connect_addr {
        connect_to_peer(&addr);
    }
    start_p2p_server(port);
    // TODO: Networking, consensus, mining, إلخ
}

pub fn start_node_with_args(port: u16, connect_addr: Option<String>, data_dir: Option<PathBuf>) {
    let network = Network::from_env_or_default();
    let magic = match network {
        Network::Mainnet => config::MAINNET_MAGIC,
        Network::Testnet => config::TESTNET_MAGIC,
    };
    if let Some(ref dir) = data_dir {
        println!("[BlackSilk Node] Using data directory: {}", dir.display());
        // هنا يمكنك تفعيل منطق تغيير مسار التخزين إذا أردت
        // مثال: std::env::set_current_dir(dir).unwrap();
    }
    println!("[BlackSilk Node] Starting {:?} node on port {} (magic: 0x{:X})", network, port, magic);
    let chain = Chain::new_for_network(network.clone());
    println!("[BlackSilk Node] Genesis block height: {}", chain.tip().header.height);
    if let Some(addr) = connect_addr {
        connect_to_peer(&addr);
    }
    // Start P2P server in a separate thread so it doesn't block
    std::thread::spawn(move || {
        start_p2p_server(port);
    });
    
    // Wait a moment for P2P to start, then start HTTP server
    std::thread::sleep(std::time::Duration::from_millis(200));
    
    // Start HTTP API server on the proper network port
    let network_ports = network.get_ports();
    let http_port = network_ports.http;
    println!("[BlackSilk Node] Starting HTTP API server on port {}", http_port);
    
    // Force stdout flush
    use std::io::{self, Write};
    io::stdout().flush().unwrap();
    
    // Start HTTP server in a new thread
    let _http_handle = std::thread::spawn(move || {
        println!("[HTTP] HTTP thread starting...");
        io::stdout().flush().unwrap();
        let data_dir = data_dir.clone().unwrap_or_else(|| PathBuf::from("./data"));
        match http_server::start_http_server_sync(http_port, data_dir) {
            Ok(_) => {
                println!("[HTTP] HTTP server stopped normally");
            }
            Err(e) => {
                eprintln!("[HTTP] HTTP server failed: {}", e);
            }
        }
    });
    
    // Keep the main thread alive
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    
    // TODO: Networking, consensus, mining, إلخ
}

/// Placeholder for node startup
pub fn start_node() {
    let network = Network::from_env_or_default();
    let (port, magic) = match network {
        Network::Mainnet => (config::MAINNET_P2P_PORT, config::MAINNET_MAGIC),
        Network::Testnet => (config::TESTNET_P2P_PORT, config::TESTNET_MAGIC),
    };
    println!("[BlackSilk Node] Starting {:?} node on port {} (magic: 0x{:X})", network, port, magic);
    let chain = Chain::new_for_network(network);
    println!("[BlackSilk Node] Genesis block height: {}", chain.tip().header.height);
    start_p2p_server(port);
    // TODO: Networking, consensus, mining, إلخ
}

pub fn start_p2p_server_with_privacy(
    port: u16, 
    privacy_manager: Arc<crate::network::privacy::PrivacyManager>,
    peers: Vec<String>
) -> Result<(), Box<dyn std::error::Error>> {
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr)?;
    println!("[P2P] Enhanced privacy-aware server listening on {}", addr);
    
    // Display privacy manager stats
    let stats = privacy_manager.get_stats();
    println!("[Privacy] Starting with {} total connections", stats.total_connections);
    
    // Connect to initial peers with privacy validation
    for peer_addr in peers {
        let peer_socket: SocketAddr = peer_addr.parse()
            .map_err(|e| format!("Invalid peer address {}: {}", peer_addr, e))?;
        
        if privacy_manager.allow_connection(&peer_socket, true) {
            println!("[P2P] Connecting to validated peer: {}", peer_addr);
            let privacy_clone = privacy_manager.clone();
            std::thread::spawn(move || {
                connect_to_peer_with_privacy(&peer_addr, privacy_clone);
            });
        } else {
            println!("[Privacy] Peer {} rejected by privacy policy", peer_addr);
        }
    }
    
    // Main server loop with privacy filtering
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                if let Ok(peer_addr) = s.peer_addr() {
                    // Check privacy policy before accepting connection
                    if privacy_manager.allow_connection(&peer_addr, false) {
                        // Register the connection
                        privacy_manager.register_connection(peer_addr, false);
                        
                        let privacy_clone = privacy_manager.clone();
                        std::thread::spawn(move || {
                            handle_client_with_privacy(s, privacy_clone);
                        });
                    } else {
                        println!("[Privacy] Incoming connection from {} rejected by privacy policy", peer_addr);
                        // Connection is automatically dropped
                    }
                } else {
                    println!("[P2P] Failed to get peer address, rejecting connection");
                }
            }
            Err(e) => {
                println!("[P2P] Connection error: {}", e);
            }
        }
    }
    
    Ok(())
}

fn connect_to_peer_with_privacy(addr: &str, privacy_manager: Arc<crate::network::privacy::PrivacyManager>) {
    println!("[P2P] Attempting privacy-aware connection to {}", addr);
    
    let mut retries = 3;
    while retries > 0 {
        match TcpStream::connect(addr) {
            Ok(mut stream) => {
                if let Ok(peer_addr) = stream.peer_addr() {
                    privacy_manager.register_connection(peer_addr, true);
                    
                    println!("[P2P] Privacy-validated connection established to {}", addr);
                    let version = P2PMessage::Version { 
                        version: 1, 
                        node: "BlackSilkNode-Privacy".to_string() 
                    };
                    
                    if let Err(e) = send_message(&mut stream, &version) {
                        eprintln!("[P2P] Failed to send version message: {}", e);
                        privacy_manager.unregister_connection(&stream.peer_addr().unwrap());
                    } else {
                        // Connection established, wait for messages
                        let _ = handle_client_with_privacy(stream, privacy_manager);
                        return;
                    }
                }
            }
            Err(e) => {
                eprintln!("[P2P] Failed to connect to {}: {}", addr, e);
            }
        }
        retries -= 1;
        if retries > 0 {
            println!("[P2P] Retrying connection... ({} attempts left)", retries);
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    }
    println!("[P2P] All attempts to connect to peer {} failed.", addr);
}

/// Add a transaction to the mempool
pub fn add_to_mempool(tx: primitives::Transaction) {
    let mut mempool = MEMPOOL.lock().unwrap();
    mempool.push(tx);
}

/// Get a copy of the current mempool
pub fn get_mempool() -> Vec<primitives::Transaction> {
    let mempool = MEMPOOL.lock().unwrap();
    mempool.clone()
}

/// Stub for chain reorg logic
pub fn maybe_reorg_chain(_blocks: Vec<primitives::Block>) {
    // TODO: Implement chain reorganization logic
    println!("[Chain] Reorg logic not yet implemented");
}

/// Stub for range proof validation
pub fn validate_range_proof(_proof: &[u8], _commitment: &[u8]) -> bool {
    // TODO: Implement Bulletproofs or other range proof validation
    true
}

/// Stub for privacy-aware client handler
pub fn handle_client_with_privacy(_stream: std::net::TcpStream, _privacy_manager: std::sync::Arc<crate::network::privacy::PrivacyManager>) -> std::io::Result<()> {
    // TODO: Implement privacy-aware client handling
    Ok(())
}

/// Validate an Address (classical or quantum)
fn validate_address(addr: &primitives::Address) -> bool {
    // Example: check encoding, scheme, and key lengths
    match &addr.stealth {
        StealthAddress { view_key, spend_key } => {
            match (view_key, spend_key) {
                (PublicKey::Ed25519(v), PublicKey::Ed25519(s)) => v.len() == 32 && s.len() == 32,
                (PublicKey::Dilithium2(v), PublicKey::Dilithium2(s)) => v.len() > 32 && s.len() > 32,
                (PublicKey::Falcon512(v), PublicKey::Falcon512(s)) => v.len() > 32 && s.len() > 32,
                (PublicKey::MLDSA44(v), PublicKey::MLDSA44(s)) => v.len() > 32 && s.len() > 32,
                (PublicKey::Hybrid { .. }, PublicKey::Hybrid { .. }) => true, // Add more checks if needed
                _ => false,
            }
        }
    }
}
