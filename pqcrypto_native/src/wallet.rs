//! PQ Wallet/Address module (scaffold)
//!
//! This module provides hierarchical deterministic (HD) key derivation and address encoding for PQ keys.
//!
//! # Example
//!
//! ```rust
//! use pqcrypto_native::wallet::{derive_child_seed, encode_address};
//! let master_seed = b"pq-wallet-master-seed";
//! let child_seed = derive_child_seed(master_seed, 0);
//! let address = encode_address(&[0u8; 32]);
//! ```

/// Derive a child seed from a master seed and index (simple hash-based KDF)
pub fn derive_child_seed(master_seed: &[u8], index: u32) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(master_seed);
    hasher.update(&index.to_le_bytes());
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

use alloc::vec;
use alloc::vec::Vec;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::string::ToString;

/// Encode a public key as a PQ address (hash + base58)
pub fn encode_address(pubkey: &[u8]) -> String {
    use sha2::{Sha256, Digest};
    use bs58;
    let hash = Sha256::digest(pubkey);
    bs58::encode(hash).into_string()
}
