//! BlackSilk Primitives - Core Types

pub mod types {
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;

    /// Amount in atomic units (1 BLK = 1_000_000 atomic units). Max supply: 21,000,000 BLK.
    pub type BlkAmount = u64; // atomic units
    pub type BlockHeight = u64;
    pub type Hash = [u8; 32];

    /// Stealth address structure
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct StealthAddress {
        pub public_view: [u8; 32],
        pub public_spend: [u8; 32],
    }

    impl StealthAddress {
        /// Generate a new stealth address
        pub fn generate() -> (Scalar, Scalar, Self) {
            let mut csprng = rand::thread_rng();
            let priv_view = Scalar::random(&mut csprng);
            let priv_spend = Scalar::random(&mut csprng);
            let pub_view = (ED25519_BASEPOINT_POINT * priv_view).compress().to_bytes();
            let pub_spend = (ED25519_BASEPOINT_POINT * priv_spend).compress().to_bytes();
            let stealth = StealthAddress {
                public_view: pub_view,
                public_spend: pub_spend,
            };
            (priv_view, priv_spend, stealth)
        }
    }
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
    pub ring_sig: RingSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionOutput {
    pub amount_commitment: types::Hash, // Pedersen commitment
    pub stealth_address: StealthAddress,
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
pub struct Pow {
    pub nonce: u64,
    pub hash: types::Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    pub version: u16,
    pub prev_hash: types::Hash,
    pub merkle_root: types::Hash,
    pub timestamp: u64,
    pub height: types::BlockHeight,
    pub difficulty: u64,
    pub pow: Pow,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RingSignature {
    pub ring: Vec<types::Hash>, // decoy public keys
    pub signature: Vec<u8>,    // placeholder
}

pub mod zkp; // zk-SNARKs and advanced ZKP integration
pub mod escrow; // Escrow contract and dispute voting
pub mod ring_sig;
