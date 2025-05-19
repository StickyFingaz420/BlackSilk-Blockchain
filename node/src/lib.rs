//! BlackSilk Node - Testnet Bootstrap

#[macro_use]
extern crate lazy_static;

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

pub mod config {
    pub const TESTNET_MAGIC: u32 = 0x1D670; // July 26, 1953
    pub const DEFAULT_P2P_PORT: u16 = 1776;
    pub const BLOCK_TIME_SEC: u64 = 120; // 2 minutes
    pub const GENESIS_REWARD: u64 = 86; // BLK
    pub const HALVING_INTERVAL: u64 = 125_000;
    pub const TAIL_EMISSION: u64 = 50_000_000; // 0.5 BLK in atomic units
    pub const SUPPLY_CAP: u64 = 21_000_000 * 1_000_000; // 21M BLK, atomic units
}

use primitives::{Block, BlockHeader, Coinbase};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::io::{Write, BufRead};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use serde::{Serialize, Deserialize};

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
                        println!("[P2P] Received block: height {}", block.header.height);
                        // Optionally broadcast to other peers
                        broadcast_message(&P2PMessage::Block(block));
                    },
                    P2PMessage::Transaction(tx) => {
                        println!("[P2P] Received transaction");
                        broadcast_message(&P2PMessage::Transaction(tx));
                    },
                    P2PMessage::PeerList(peers) => {
                        println!("[P2P] Received peer list: {:?}", peers);
                    },
                    P2PMessage::GetBlocks { from_height } => {
                        let chain = Chain::new(); // TODO: use real chain
                        let blocks: Vec<_> = chain.blocks.iter().filter(|b| b.header.height >= from_height).cloned().collect();
                        let _ = send_message(&mut stream, &P2PMessage::Blocks(blocks));
                    },
                    P2PMessage::Blocks(blocks) => {
                        println!("[P2P] Received {} blocks", blocks.len());
                        // TODO: add to chain
                    },
                    P2PMessage::GetMempool => {
                        let mempool = get_mempool();
                        let _ = send_message(&mut stream, &P2PMessage::Mempool(mempool));
                    },
                    P2PMessage::Mempool(txs) => {
                        println!("[P2P] Received mempool: {} txs", txs.len());
                        // TODO: add to mempool
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

pub struct EmissionSchedule {
    pub genesis_reward: u64,
    pub halving_interval: u64,
    pub tail_emission: u64,
    pub supply_cap: u64,
}

impl EmissionSchedule {
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
        let genesis = Self::genesis_block(&emission);
        let mut blocks = VecDeque::new();
        blocks.push_back(genesis);
        Self { blocks, emission }
    }

    pub fn genesis_block(emission: &EmissionSchedule) -> Block {
        Block {
            header: BlockHeader {
                version: 1,
                prev_hash: [0u8; 32],
                merkle_root: [0u8; 32], // TODO: real merkle root
                timestamp: 1_716_150_000, // Example: May 19, 2025
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

pub fn connect_to_peer(addr: &str) {
    match TcpStream::connect(addr) {
        Ok(mut stream) => {
            println!("[P2P] Connected to peer {}", addr);
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
                                println!("[P2P] Received block: height {}", block.header.height);
                                broadcast_message(&P2PMessage::Block(block));
                            },
                            P2PMessage::Transaction(tx) => {
                                println!("[P2P] Received transaction");
                                broadcast_message(&P2PMessage::Transaction(tx));
                            },
                            P2PMessage::PeerList(peers) => {
                                println!("[P2P] Received peer list: {:?}", peers);
                            },
                            P2PMessage::GetBlocks { from_height } => {
                                println!("[P2P] Sync request for blocks from height {}", from_height);
                                // TODO: Handle block synchronization
                            },
                            P2PMessage::Blocks(blocks) => {
                                println!("[P2P] Received blocks: {:?}", blocks);
                                // TODO: Handle received blocks
                            },
                            P2PMessage::GetMempool => {
                                let mempool = get_mempool();
                                let _ = send_message(&mut stream, &P2PMessage::Mempool(mempool));
                            },
                            P2PMessage::Mempool(transactions) => {
                                println!("[P2P] Received mempool transactions: {:?}", transactions);
                                // TODO: Handle received mempool transactions
                            },
                        }
                    }
                    None => {
                        println!("[P2P] Disconnected from peer");
                        break;
                    }
                }
            }
        }
        Err(e) => println!("[P2P] Failed to connect to {}: {}", addr, e),
    }
}

pub fn start_p2p_server(port: u16) {
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).expect("Failed to bind P2P port");
    println!("[P2P] Listening for peers on {}", addr);
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                thread::spawn(|| handle_client(s));
            }
            Err(e) => println!("[P2P] Connection failed: {}", e),
        }
    }
}

pub fn start_node_with_port_and_connect(port: u16, connect_addr: Option<String>) {
    println!("[BlackSilk Node] Starting Testnet node on port {} (magic: 0x{:X})", port, config::TESTNET_MAGIC);
    let chain = Chain::new();
    println!("[BlackSilk Node] Genesis block height: {}", chain.tip().header.height);
    if let Some(addr) = connect_addr {
        connect_to_peer(&addr);
    }
    start_p2p_server(port);
    // TODO: Networking, consensus, mining, etc.
}

/// Placeholder for node startup
pub fn start_node() {
    println!("[BlackSilk Node] Starting Testnet node on port {} (magic: 0x{:X})", config::DEFAULT_P2P_PORT, config::TESTNET_MAGIC);
    let chain = Chain::new();
    println!("[BlackSilk Node] Genesis block height: {}", chain.tip().header.height);
    start_p2p_server(config::DEFAULT_P2P_PORT);
    // TODO: Networking, consensus, mining, etc.
}

pub fn start_node_with_port(port: u16) {
    println!("[BlackSilk Node] Starting Testnet node on port {} (magic: 0x{:X})", port, config::TESTNET_MAGIC);
    let chain = Chain::new();
    println!("[BlackSilk Node] Genesis block height: {}", chain.tip().header.height);
    start_p2p_server(port);
    // TODO: Networking, consensus, mining, etc.
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
use std::fs;

pub fn save_chain(chain: &Chain) {
    let json = serde_json::to_string(&chain.blocks.iter().collect::<Vec<_>>()).unwrap();
    let _ = fs::write("chain.json", json);
}

pub fn load_chain() -> Option<Vec<primitives::Block>> {
    if let Ok(data) = fs::read_to_string("chain.json") {
        serde_json::from_str(&data).ok()
    } else {
        None
    }
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
