//! BlackSilk Primitives - Core Types

pub mod types {
    pub type BlkAmount = u64; // atomic units
    pub type BlockHeight = u64;
    pub type Address = String; // placeholder for stealth address
    pub type Hash = [u8; 32];
    // Add more types as needed
}

pub fn add(left: u64, right: u64) -> u64 {
    left + right
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

use serde::{Serialize, Deserialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionInput {
    pub key_image: types::Hash, // for ring signature
    pub ring: Vec<types::Hash>, // decoy outputs
    pub signature: Vec<u8>,     // placeholder for ring signature
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionOutput {
    pub amount_commitment: types::Hash, // Pedersen commitment
    pub stealth_address: types::Address,
    pub range_proof: Vec<u8>, // Bulletproofs
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub inputs: Vec<TransactionInput>,
    pub outputs: Vec<TransactionOutput>,
    pub fee: types::BlkAmount,
    pub extra: Vec<u8>, // for encrypted memo, etc.
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    pub version: u16,
    pub prev_hash: types::Hash,
    pub merkle_root: types::Hash,
    pub timestamp: u64,
    pub height: types::BlockHeight,
    pub nonce: u64,
    pub difficulty: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Coinbase {
    pub reward: types::BlkAmount,
    pub to: types::Address,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub coinbase: Coinbase,
    pub transactions: Vec<Transaction>,
}

impl Block {
    pub fn is_genesis(&self) -> bool {
        self.header.height == 0
    }
}
