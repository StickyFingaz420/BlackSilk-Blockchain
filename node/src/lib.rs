//! BlackSilk Node - Testnet Bootstrap

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

use primitives::{Block, BlockHeader, Transaction, Coinbase};
use std::collections::VecDeque;
use std::net::{TcpListener, TcpStream};
use std::thread;

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
                nonce: 0,
                difficulty: 1,
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

    pub fn add_block(&mut self, mut block: Block) -> bool {
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

fn handle_client(stream: TcpStream) {
    println!("[P2P] New peer: {}", stream.peer_addr().unwrap());
    // TODO: Read/write messages
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

pub fn connect_to_peer(addr: &str) {
    match TcpStream::connect(addr) {
        Ok(mut stream) => {
            println!("[P2P] Connected to peer {}", addr);
            // TODO: Send/receive handshake
        }
        Err(e) => println!("[P2P] Failed to connect to {}: {}", addr, e),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
