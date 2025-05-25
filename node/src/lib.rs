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

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

pub mod config {
    pub const TESTNET_MAGIC: u32 = 0x1D670; // July 26, 1953
    pub const MAINNET_MAGIC: u32 = 0xB1A6C; // Example: May 24, 2025
    pub const DEFAULT_P2P_PORT: u16 = 1776;
    pub const MAINNET_P2P_PORT: u16 = 1977;
    /// Block time in seconds (2 minutes)
    pub const BLOCK_TIME_SEC: u64 = 120;
    /// Initial block reward in atomic units (5 BLK)
    pub const GENESIS_REWARD: u64 = 5_000_000;
    /// Halving interval in blocks (~4 years at 2 min/block)
    pub const HALVING_INTERVAL: u64 = 1_051_200;
    /// No tail emission after cap (miners receive only fees after cap)
    pub const TAIL_EMISSION: u64 = 0;
    /// Maximum supply: 21 million BLK (in atomic units)
    pub const SUPPLY_CAP: u64 = 21_000_000 * 1_000_000;
    // Mainnet genesis timestamp (example)
    pub const MAINNET_GENESIS_TIMESTAMP: u64 = 1_716_150_000; // May 24, 2025
    pub const TESTNET_GENESIS_TIMESTAMP: u64 = 1_716_150_000; // May 19, 2025
}

/// Network selection
#[derive(Debug)]
enum Network {
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
}

use primitives::{Block, BlockHeader, Coinbase};
use std::collections::{VecDeque, HashSet};
use std::io::{Write, BufRead};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use serde::{Serialize, Deserialize};
use sha2::Digest;
use once_cell::sync::OnceCell;
use primitives::ring_sig::generate_ring_signature;

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
}

impl Chain {
    pub fn new() -> Self {
        let emission = default_emission();
        let genesis = Self::genesis_block_with_params(&emission, config::TESTNET_GENESIS_TIMESTAMP);
        let mut blocks = VecDeque::new();
        blocks.push_back(genesis);
        Self { blocks, emission }
    }
    pub fn new_for_network(network: Network) -> Self {
        let emission = default_emission();
        let genesis = match network {
            Network::Mainnet => Self::genesis_block_with_params(&emission, config::MAINNET_GENESIS_TIMESTAMP),
            Network::Testnet => Self::genesis_block_with_params(&emission, config::TESTNET_GENESIS_TIMESTAMP),
        };
        let mut blocks = VecDeque::new();
        blocks.push_back(genesis);
        Self { blocks, emission }
    }
    fn genesis_block_with_params(emission: &EmissionSchedule, timestamp: u64) -> Block {
        Block {
            header: BlockHeader {
                version: 1,
                prev_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                timestamp,
                height: 0,
                difficulty: 1,
                pow: primitives::Pow { nonce: 0, hash: [0u8; 32] },
            },
            coinbase: Coinbase {
                reward: emission.genesis_reward,
                to: "genesis_address_placeholder".to_string(),
            },
            transactions: vec![],
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
    // TODO: Check merkle root, signatures, and block hash
    true
}

mod network {
    pub mod privacy;
}
pub mod mining;
pub mod escrow;
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
    let chain = Chain::new_for_network(network);
    println!("[BlackSilk Node] Genesis block height: {}", chain.tip().header.height);
    if let Some(addr) = connect_addr {
        connect_to_peer(&addr);
    }
    start_p2p_server(port);
    // TODO: Networking, consensus, mining, إلخ
}

/// Placeholder for node startup
pub fn start_node() {
    let network = Network::from_env_or_default();
    let (port, magic) = match network {
        Network::Mainnet => (config::MAINNET_P2P_PORT, config::MAINNET_MAGIC),
        Network::Testnet => (config::DEFAULT_P2P_PORT, config::TESTNET_MAGIC),
    };
    println!("[BlackSilk Node] Starting {:?} node on port {} (magic: 0x{:X})", network, port, magic);
    let chain = Chain::new_for_network(network);
    println!("[BlackSilk Node] Genesis block height: {}", chain.tip().header.height);
    start_p2p_server(port);
    // TODO: Networking, consensus, mining, إلخ
}

pub fn start_node_with_port(port: u16) {
    println!("[BlackSilk Node] Starting Testnet node on port {} (magic: 0x{:X})", port, config::TESTNET_MAGIC);
    let chain = Chain::new();
    println!("[BlackSilk Node] Genesis block height: {}", chain.tip().header.height);
    start_p2p_server(port);
    // TODO: Networking, consensus, mining, إلخ
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
