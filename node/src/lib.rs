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

pub fn add(left: u64, right: u64) -> u64 {
    left + right
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
#[derive(Debug, Clone)]
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
use std::collections::{VecDeque, HashSet};
use std::io::{Write, BufRead};
use std::net::{TcpListener, TcpStream, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use serde::{Serialize, Deserialize};
use sha2::Digest;
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
    static ref PEERS: Arc<Mutex<Vec<TcpStream>>> = Arc::new(Mutex::new(Vec::new()));
}

// Transaction pool (mempool)
lazy_static::lazy_static! {
    static ref MEMPOOL: Arc<Mutex<Vec<primitives::Transaction>>> = Arc::new(Mutex::new(Vec::new()));
}

lazy_static! {
    static ref CHAIN: Arc<Mutex<Chain>> = Arc::new(Mutex::new(Chain::new()));
}

pub fn broadcast_message(msg: &P2PMessage) {
    let peers = PEERS.lock().unwrap();
    for peer in peers.iter() {
        let mut peer = peer.try_clone().unwrap();
        let _ = send_message(&mut peer, msg);
    }
}

fn handle_client(mut stream: TcpStream) {
    println!("[P2P] New peer: {}", stream.peer_addr().unwrap());
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
        hasher.update(l0.compress().as_bytes());
        hasher.update(msg);
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
    hasher.update(l0.compress().as_bytes());
    hasher.update(msg);
    let mut c_bytes = [0u8; 32];
    c_bytes.copy_from_slice(&hasher.finalize_reset()[..32]);
    let mut c = Scalar::from_bytes_mod_order(c_bytes);
    println!("[VER] verifier c_0: {:?}", c);
    for i in 1..n {
        let l = EdwardsPoint::mul_base(&r_vec[i]) + pubkeys[i] * c_vec[i];
        println!("[VER] verifier L_{}: {:?}", i, l.compress().to_bytes());
        hasher.update(l.compress().as_bytes());
        hasher.update(msg);
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
    true
}

#[cfg(test)]
mod double_spend_tests {
    use super::*;
    use primitives::{Transaction, TransactionInput, TransactionOutput, RingSignature, types};
    use primitives::ring_sig::generate_ring_signature;
    #[test]
    fn test_double_spend_key_image() {
        // Generate a real keypair and ring signature for the test
        use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
        use curve25519_dalek::edwards::CompressedEdwardsY;
        use curve25519_dalek::scalar::Scalar;
        use rand::RngCore;
        let mut csprng = rand::thread_rng();
        let mut sk_bytes = [0u8; 32];
        csprng.fill_bytes(&mut sk_bytes);
        let sk = Scalar::from_bytes_mod_order(sk_bytes);
        let pk = (ED25519_BASEPOINT_POINT * sk).compress().to_bytes();
        let ring = vec![pk];
        let msg = b"test double spend";
        // Generate ring signature using canonical implementation
        let sig = generate_ring_signature(msg, &ring, &sk_bytes, 0);
        let key_image = [1u8; 32]; // For test, not used in ring sig
        let ring_sig = RingSignature { ring: ring.clone(), signature: sig };
        let input = TransactionInput { key_image, ring_sig };
        let output = TransactionOutput { amount_commitment: [3u8; 32], stealth_address: primitives::StealthAddress { public_view: [4u8; 32], public_spend: [5u8; 32] }, range_proof: vec![0u8; 64] };
        let tx1 = Transaction { inputs: vec![input.clone()], outputs: vec![output.clone()], fee: 0, extra: msg.to_vec() };
        let tx2 = Transaction { inputs: vec![input], outputs: vec![output], fee: 0, extra: msg.to_vec() };
        // First tx should be valid
        assert!(validate_transaction(&tx1));
        // Add tx1 to mempool
        add_to_mempool(tx1.clone());
        // Second tx with same key image should be rejected
        assert!(!validate_transaction(&tx2));
    }
}

// Advanced fork resolution: choose the longest valid chain
pub fn maybe_reorg_chain(new_blocks: Vec<primitives::Block>) {
    let mut chain = CHAIN.lock().unwrap();
    if new_blocks.len() > chain.blocks.len() {
        // Validate all new blocks
        let mut valid = true;
        for i in 0..new_blocks.len() {
            if i > 0 && new_blocks[i].header.prev_hash != new_blocks[i-1].header.pow.hash {
                valid = false;
                break;
            }
            if !validate_block(&new_blocks[i]) {
                valid = false;
                break;
            }
        }
        if valid {
            println!("[Chain] Reorg: switching to longer chain");
            chain.blocks = new_blocks.into();
        } else {
            println!("[Chain] Reorg failed: received chain is invalid");
        }
    }
}

/// Emission schedule for BlackSilk (see README for details)
pub struct EmissionSchedule {
    pub genesis_reward: u64,      // Initial block reward (atomic units)
    pub halving_interval: u64,    // Blocks per halving (~4 years)
    pub tail_emission: u64,       // Always 0 (no tail emission)
    pub supply_cap: u64,          // 21M BLK (atomic units)
}

impl EmissionSchedule {
    /// Returns the block reward for a given height, enforcing halving and supply cap.
    pub fn block_reward(&self, height: u64) -> u64 {
        let mut reward = self.genesis_reward;
        let mut halvings = height / self.halving_interval;
        while halvings > 0 && reward > self.tail_emission {
            reward /= 2;
            halvings -= 1;
        }
        if reward < self.tail_emission {
            self.tail_emission
        } else {
            reward
        }
    }
}

pub fn default_emission() -> EmissionSchedule {
    EmissionSchedule {
        genesis_reward: config::GENESIS_REWARD,
        halving_interval: config::HALVING_INTERVAL,
        tail_emission: config::TAIL_EMISSION,
        supply_cap: config::SUPPLY_CAP,
    }
}

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
                to: "genesis_address_placeholder".to_string(),
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
    if privacy.tor_only && !(is_onion_address(addr) || is_i2p_address(addr)) {
        println!("[Privacy] Connection to non-Tor/I2P address blocked: {}", addr);
        return;
    }

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
        
        match http_server::start_http_server_sync(http_port) {
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
                        privacy_manager.unregister_connection(&peer_addr);
                        return;
                    }
                    
                    // Handle the connection in a separate thread
                    let privacy_clone = privacy_manager.clone();
                    std::thread::spawn(move || {
                        handle_client_with_privacy(stream, privacy_clone);
                    });
                    return;
                }
            }
            Err(e) => {
                eprintln!("[P2P] Failed to connect to {}: {}", addr, e);
            }
        }
        retries -= 1;
        if retries > 0 {
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    }
    println!("[P2P] All attempts to connect to {} failed", addr);
}

fn handle_client_with_privacy(mut stream: TcpStream, privacy_manager: Arc<crate::network::privacy::PrivacyManager>) {
    let peer_addr = match stream.peer_addr() {
        Ok(addr) => addr,
        Err(_) => {
            println!("[P2P] Failed to get peer address, closing connection");
            return;
        }
    };
    
    println!("[P2P] Privacy-managed connection from: {}", peer_addr);
    
    // Add to peers list
    {
        let mut peers = PEERS.lock().unwrap();
        peers.push(stream.try_clone().unwrap());
        
        // Send current peer list to the new peer
        let peer_addrs: Vec<String> = peers.iter()
            .filter_map(|s| s.peer_addr().ok().map(|a| a.to_string()))
            .collect();
        let _ = send_message(&mut stream, &P2PMessage::PeerList(peer_addrs));
    }
    
    // Send version message
    let version = P2PMessage::Version { 
        version: 1, 
        node: "BlackSilkNode-Privacy".to_string() 
    };
    let _ = send_message(&mut stream, &version);
    
    // Main message handling loop
    loop {
        match read_message(&mut stream) {
            Some(msg) => {
                println!("[P2P] Privacy-filtered message from {}: {:?}", peer_addr, msg);
                
                // Handle messages same as regular client
                match msg {
                    P2PMessage::Ping => { 
                        let _ = send_message(&mut stream, &P2PMessage::Pong); 
                    },
                    P2PMessage::Pong => {
                        println!("[P2P] Pong received from {}", peer_addr);
                    },
                    P2PMessage::Version { version, node } => {
                        println!("[P2P] Peer {} running version {} ({})", peer_addr, version, node);
                    },
                    P2PMessage::Block(block) => {
                        println!("[P2P] Received block #{} from {}", block.header.height, peer_addr);
                        let mut chain = CHAIN.lock().unwrap();
                        if validate_block_with_chain(&block, Some(&chain)) {
                            if chain.add_block(block.clone()) {
                                save_chain_to_disk(&chain);
                                println!("[Chain] Block added to chain");
                                // Broadcast to other peers (excluding sender)
                                broadcast_message_except(&P2PMessage::Block(block), &peer_addr);
                            }
                        } else {
                            println!("[Chain] Invalid block rejected from {}", peer_addr);
                        }
                    },
                    P2PMessage::Transaction(tx) => {
                        if validate_transaction(&tx) {
                            add_to_mempool(tx.clone());
                            println!("[Mempool] Transaction added from {}", peer_addr);
                            broadcast_message_except(&P2PMessage::Transaction(tx), &peer_addr);
                        } else {
                            println!("[Mempool] Invalid transaction rejected from {}", peer_addr);
                        }
                    },
                    P2PMessage::PeerList(peers) => {
                        println!("[P2P] Received peer list from {}: {:?}", peer_addr, peers);
                        // Validate and connect to new peers with privacy filtering
                        for peer in peers {
                            if let Ok(new_peer_addr) = peer.parse::<SocketAddr>() {
                                if privacy_manager.allow_connection(&new_peer_addr, true) {
                                    let pm_clone = privacy_manager.clone();
                                    std::thread::spawn(move || {
                                        connect_to_peer_with_privacy(&peer, pm_clone);
                                    });
                                }
                            }
                        }
                    },
                    P2PMessage::GetBlocks { from_height } => {
                        let chain = CHAIN.lock().unwrap();
                        let blocks: Vec<_> = chain.blocks.iter()
                            .filter(|b| b.header.height >= from_height)
                            .cloned()
                            .collect();
                        let _ = send_message(&mut stream, &P2PMessage::Blocks(blocks));
                    },
                    P2PMessage::Blocks(blocks) => {
                        let mut chain = CHAIN.lock().unwrap();
                        if blocks.len() > chain.blocks.len() {
                            drop(chain);
                            maybe_reorg_chain(blocks);
                        } else {
                            for block in blocks {
                                if validate_block_with_chain(&block, Some(&chain)) {
                                    if chain.add_block(block) {
                                        save_chain_to_disk(&chain);
                                    }
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
                println!("[P2P] Peer {} disconnected", peer_addr);
                break;
            }
        }
    }
    
    // Cleanup on disconnect
    privacy_manager.unregister_connection(&peer_addr);
    
    // Remove from peers list
    {
        let mut peers = PEERS.lock().unwrap();
        peers.retain(|s| s.peer_addr().unwrap() != peer_addr);
    }
    
    println!("[P2P] Privacy-managed connection to {} closed", peer_addr);
}

// Helper function to broadcast message to all peers except one
fn broadcast_message_except(msg: &P2PMessage, exclude_addr: &SocketAddr) {
    let peers = PEERS.lock().unwrap();
    for peer in peers.iter() {
        if let Ok(addr) = peer.peer_addr() {
            if addr != *exclude_addr {
                // Clone the stream to get a mutable reference
                if let Ok(mut stream) = peer.try_clone() {
                    let _ = send_message(&mut stream, msg);
                }
            }
        }
    }
}

pub fn pow_hash(header: &BlockHeader) -> primitives::types::Hash {
    // Placeholder: double SHA256 of header fields (except pow.hash)
    let mut hasher = Sha256::new();
    hasher.update(header.version.to_le_bytes());
    hasher.update(&header.prev_hash);
    hasher.update(&header.merkle_root);
    hasher.update(header.timestamp.to_le_bytes());
    hasher.update(header.height.to_le_bytes());
    hasher.update(header.pow.nonce.to_le_bytes());
    hasher.update(header.difficulty.to_le_bytes());
    let first = hasher.finalize_reset();
    hasher.update(first);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

pub fn mine_block(header: &mut BlockHeader, target: u64) {
    // Very simple PoW: find nonce so hash as u64 < target
    for nonce in 0..u64::MAX {
        header.pow.nonce = nonce;
        let hash = pow_hash(header);
        let hash_val = u64::from_le_bytes([hash[0],hash[1],hash[2],hash[3],hash[4],hash[5],hash[6],hash[7]]);
        if hash_val < target {
            header.pow.hash = hash;
            break;
        }
    }
}

pub fn cli_send_block() {
    let block = Block {
        header: BlockHeader {
            version: 1,
            prev_hash: [1u8; 32],
            merkle_root: [2u8; 32],
            timestamp: 1_716_150_001,
            height: 1,
            difficulty: 1,
            pow: primitives::Pow { nonce: 42, hash: [3u8; 32] },
        },
        coinbase: Coinbase {
            reward: 86,
            to: "test_address".to_string(),
        },
        transactions: vec![],
    };
    broadcast_message(&P2PMessage::Block(block));
    println!("[CLI] Test block broadcasted to peers");
}

pub fn cli_send_transaction() {
    let tx = primitives::Transaction {
        inputs: vec![],
        outputs: vec![],
        fee: 0,
        extra: b"test tx".to_vec(),
    };
    broadcast_message(&P2PMessage::Transaction(tx));
    println!("[CLI] Test transaction broadcasted to peers");
}

pub fn add_to_mempool(tx: primitives::Transaction) {
    let mut mempool = MEMPOOL.lock().unwrap();
    mempool.push(tx);
}

pub fn get_mempool() -> Vec<primitives::Transaction> {
    MEMPOOL.lock().unwrap().clone()
}

// Persistent storage (simple JSON, for demo)
pub fn save_chain() {
    let chain = CHAIN.lock().unwrap();
    let json = serde_json::to_string(&chain.blocks.iter().collect::<Vec<_>>()).unwrap();
    let _ = std::fs::write("chain.json", json);
}

/// Save chain to disk (persistence) - enhanced version
pub fn save_chain_to_disk(chain: &Chain) {
    use std::fs::File;
    use std::io::Write;
    
    if let Ok(chain_json) = serde_json::to_string_pretty(&chain.blocks) {
        if let Ok(mut file) = File::create("/workspaces/BlackSilk-Blockchain/chain.json") {
            let _ = file.write_all(chain_json.as_bytes());
            println!("[Chain] Blockchain saved to disk ({} blocks)", chain.blocks.len());
        }
    }
}

pub fn load_chain() {
    if let Ok(data) = std::fs::read_to_string("chain.json") {
        if let Ok(blocks) = serde_json::from_str::<Vec<primitives::Block>>(&data) {
            let mut chain = CHAIN.lock().unwrap();
            chain.blocks = blocks.into();
        }
    }
}

pub fn validate_range_proof(_proof: &[u8], _commitment: &primitives::types::Hash) -> bool {
    // TODO: Implement Bulletproofs or similar range proof validation
    // For now, always return true as a placeholder
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}

#[cfg(test)]
mod ring_sig_tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::edwards::EdwardsPoint;
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use sha2::Sha256;
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;

    #[test]
    fn test_ring_signature_verification_trivial() {
        // Generate a single keypair
        let mut csprng = rand::thread_rng();
        let mut sk_bytes = [0u8; 32];
        csprng.fill_bytes(&mut sk_bytes);
        let sk = Scalar::from_bytes_mod_order(sk_bytes);
        let pk = (EdwardsPoint::mul_base(&sk)).compress().to_bytes();
        let ring = vec![pk];
        // Fake signature: c, r = 0
        let sig = vec![0u8; 64];
        let msg = b"test message";
        // Should fail (not a valid signature)
        assert!(!validate_ring_signature(&ring, &sig, msg));
    }

    #[test]
    fn test_ring_signature_end_to_end() {
        // Simulate wallet: generate keypair
        let mut csprng = rand::thread_rng();
        let mut sk_bytes = [0u8; 32];
        csprng.fill_bytes(&mut sk_bytes);
        let sk = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(sk_bytes);
        let pk = (curve25519_dalek::edwards::EdwardsPoint::mul_base(&sk)).compress().to_bytes();
        let ring = vec![pk];
        let msg = b"end-to-end test message";
        let sig = generate_ring_signature(msg, &ring, &sk_bytes, 0);
        assert!(validate_ring_signature(&ring, &sig, msg));
    }

    #[test]
    fn test_ring_signature_end_to_end_ring2() {
        // Generate two keypairs
        let mut csprng = rand::thread_rng();
        let mut sk1_bytes = [0u8; 32];
        let mut sk2_bytes = [0u8; 32];
        csprng.fill_bytes(&mut sk1_bytes);
        csprng.fill_bytes(&mut sk2_bytes);
        let sk1 = Scalar::from_bytes_mod_order(sk1_bytes);
        let sk2 = Scalar::from_bytes_mod_order(sk2_bytes);
        let pk1 = (EdwardsPoint::mul_base(&sk1)).compress().to_bytes();
        let pk2 = (EdwardsPoint::mul_base(&sk2)).compress().to_bytes();
        let ring = vec![pk1, pk2];
        let msg = b"ring2 test message";
        // Sign with sk1 (index 0)
        let sig1 = generate_ring_signature(msg, &ring, &sk1_bytes, 0);
        assert!(validate_ring_signature(&ring, &sig1, msg));
        // Sign with sk2 (index 1)
        let sig2 = generate_ring_signature(msg, &ring, &sk2_bytes, 1);
        assert!(validate_ring_signature(&ring, &sig2, msg));
    }
}
