//! BlackSilk Primitives - Core Types

#[macro_use]
extern crate serde;

pub mod types {
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use sha2::Sha512;
    use sha2::Digest;
    use serde::{Serialize, Deserialize};
    use curve25519_dalek::digest::Update;

    /// Amount in atomic units (1 BLK = 1_000_000 atomic units). Max supply: 21,000,000 BLK.
    pub type BlkAmount = u64; // atomic units
    pub type BlockHeight = u64;
    pub type Hash = [u8; 32];

    /// Enum for supported public key types (classical and quantum)
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub enum PublicKey {
        Ed25519([u8; 32]),
        Dilithium2(Vec<u8>),
        Falcon512(Vec<u8>),
        MLDSA44(Vec<u8>),
        // Hybrid (classical + quantum)
        Hybrid {
            classical: [u8; 32],
            quantum: Vec<u8>,
            scheme: QuantumScheme,
        },
    }

    /// Enum for quantum signature schemes
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub enum QuantumScheme {
        Dilithium2,
        Falcon512,
        MLDSA44,
    }

    /// Stealth address structure for privacy-preserving transactions.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct StealthAddress {
        pub view_key: PublicKey,
        pub spend_key: PublicKey,
    }

    impl StealthAddress {
        /// Generate a new stealth address (classical, quantum, or hybrid)
        ///
        /// # Returns
        /// Tuple of (private_view, private_spend, StealthAddress)
        pub fn generate(scheme: Option<QuantumScheme>) -> (Vec<u8>, Vec<u8>, Self) {
            match scheme {
                Some(QuantumScheme::Dilithium2) => {
                    // Generate Dilithium2 keys (placeholder)
                    let (priv_view, pub_view) = pqcrypto_native::dilithium2::keypair();
                    let (priv_spend, pub_spend) = pqcrypto_native::dilithium2::keypair();
                    let stealth = StealthAddress {
                        view_key: PublicKey::Dilithium2(pub_view),
                        spend_key: PublicKey::Dilithium2(pub_spend),
                    };
                    (priv_view, priv_spend, stealth)
                }
                Some(QuantumScheme::Falcon512) => {
                    let (priv_view, pub_view) = pqcrypto_native::falcon512::keypair();
                    let (priv_spend, pub_spend) = pqcrypto_native::falcon512::keypair();
                    let stealth = StealthAddress {
                        view_key: PublicKey::Falcon512(pub_view),
                        spend_key: PublicKey::Falcon512(pub_spend),
                    };
                    (priv_view, priv_spend, stealth)
                }
                Some(QuantumScheme::MLDSA44) => {
                    let (priv_view, pub_view) = pqcrypto_native::mldsa44::keypair();
                    let (priv_spend, pub_spend) = pqcrypto_native::mldsa44::keypair();
                    let stealth = StealthAddress {
                        view_key: PublicKey::MLDSA44(pub_view),
                        spend_key: PublicKey::MLDSA44(pub_spend),
                    };
                    (priv_view, priv_spend, stealth)
                }
                None => {
                    // Classical Ed25519
                    let seed = [42u8; 32];
                    let priv_view = Scalar::from_hash(Sha512::new().chain(seed));
                    let priv_spend = Scalar::from_hash(Sha512::new().chain(seed));
                    let pub_view = (ED25519_BASEPOINT_POINT * priv_view).compress().to_bytes();
                    let pub_spend = (ED25519_BASEPOINT_POINT * priv_spend).compress().to_bytes();
                    let stealth = StealthAddress {
                        view_key: PublicKey::Ed25519(pub_view),
                        spend_key: PublicKey::Ed25519(pub_spend),
                    };
                    (priv_view.to_bytes().to_vec(), priv_spend.to_bytes().to_vec(), stealth)
                }
            }
        }
    }

    pub type Address = String; // Define Address as a type alias for String
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
pub enum ContractTx {
    Deploy {
        wasm_code: Vec<u8>,
        creator: Address, // updated
        metadata: Option<String>,
    },
    Invoke {
        contract_address: Address, // updated
        function: String,
        params: Vec<u8>, // serialized params (e.g., JSON or bincode)
        caller: Address, // updated
        metadata: Option<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TransactionKind {
    Payment,
    Contract(ContractTx),
    // ...future types...
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub kind: TransactionKind,
    pub inputs: Vec<TransactionInput>,
    pub outputs: Vec<TransactionOutput>,
    pub fee: types::BlkAmount,
    pub extra: Vec<u8>, // for encrypted memo, etc.
    pub metadata: Option<String>, // for marketplace data
    pub signature: String, // transaction signature/hash (legacy/classical)
    pub quantum_signature: Option<QuantumSignature>, // quantum signature (optional, for hybrid)
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
    pub to: Address, // updated
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
pub struct QuantumSignature {
    pub ring: Vec<types::Hash>, // decoy public keys
    pub signature: Vec<u8>,    // quantum signature bytes
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RingSignature {
    pub ring: Vec<types::Hash>, // decoy public keys
    pub signature: Vec<u8>,    // classical signature bytes
    pub quantum: Option<QuantumSignature>, // quantum signature (optional, for hybrid)
}

pub mod zkp; // zk-SNARKs and advanced ZKP integration
pub mod escrow; // Escrow contract and dispute voting
pub mod ring_sig;

pub use crate::types::{StealthAddress, Address};

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use sha2::Sha512;
use sha2::Digest;
use rand::RngCore;

/// Generate a stealth address
pub fn generate_stealth_address(_view_key: &RistrettoPoint, spend_key: &RistrettoPoint) -> RistrettoPoint {
    let mut rng = rand::thread_rng();
    let mut random_bytes_for_scalar = [0u8; 32]; // 32 bytes for Scalar::from_bytes_mod_order
    rng.fill_bytes(&mut random_bytes_for_scalar);
    let r_scalar = Scalar::from_bytes_mod_order(random_bytes_for_scalar);
    
    let r_point = r_scalar * RISTRETTO_BASEPOINT_POINT; // This is R = r*G

    let mut hasher = Sha512::new();
    hasher.update(r_point.compress().as_bytes()); // r_point is RistrettoPoint, so .compress() is valid
    hasher.update(spend_key.compress().as_bytes()); // spend_key is &RistrettoPoint
    let hash_output_array = hasher.finalize(); // GenericArray<u8, U64>

    // Convert the 64-byte hash output to a scalar
    // Scalar::from_bytes_mod_order_wide expects a &[u8; 64]
    let h_scalar = Scalar::from_bytes_mod_order_wide(hash_output_array.as_slice().try_into().expect("Hash output size mismatch"));

    // Calculate the stealth public key: P = H(r*A || B)*G + B
    // Where A is recipient's view public key (not used here as per original simplified draft)
    // and B is recipient's spend public key.
    // The formula used here is H(r*G || B_pub)*G + B_pub, which is a common variant.
    // Or, if r_point is H(r*view_key)*G, then P = r_point + spend_key
    // The current formula is P_stealth = h_scalar * G + spend_key
    (h_scalar * RISTRETTO_BASEPOINT_POINT) + spend_key
}
