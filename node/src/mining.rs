//! BlackSilk RandomX Mining Implementation

use crate::primitives::{Block, BlockHeader, Pow};
use randomx_rs::{RandomXCache, RandomXFlags, RandomXVM};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// RandomX configuration
const RX_DATASET_ITEMS: u64 = 1 << 21; // 2^21 items
const RX_CACHE_ACCESSES: u64 = 1 << 20; // 2^20 accesses
const RX_PROGRAM_SIZE: u64 = 1 << 12; // 4KB program size
const RX_PROGRAM_ITERATIONS: u64 = 1 << 8; // 256 iterations

/// RandomX mining context
pub struct MiningContext {
    vm: Arc<RandomXVM>,
    cache: Arc<RandomXCache>,
    flags: RandomXFlags,
}

impl MiningContext {
    /// Create new mining context
    pub fn new(seed: &[u8]) -> Self {
        let flags = RandomXFlags::default()
            | RandomXFlags::FLAG_LARGE_PAGES
            | RandomXFlags::FLAG_HARD_AES
            | RandomXFlags::FLAG_FULL_MEM;
            
        let cache = Arc::new(RandomXCache::new(seed, flags).expect("Failed to create RandomX cache"));
        let vm = Arc::new(RandomXVM::new(cache.clone(), flags).expect("Failed to create RandomX VM"));
        
        Self {
            vm,
            cache,
            flags,
        }
    }
    
    /// Update mining seed (e.g. on epoch change)
    pub fn update_seed(&mut self, new_seed: &[u8]) {
        self.cache = Arc::new(RandomXCache::new(new_seed, self.flags).expect("Failed to create RandomX cache"));
        self.vm = Arc::new(RandomXVM::new(self.cache.clone(), self.flags).expect("Failed to create RandomX VM"));
    }
}

/// Mine a block using RandomX
pub fn mine_block(
    header: &mut BlockHeader,
    context: &MiningContext,
    target: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    // Prepare block header for hashing
    let mut pre_pow = prepare_header_bytes(header);
    
    for nonce in 0..u64::MAX {
        header.pow.nonce = nonce;
        pre_pow[24..32].copy_from_slice(&nonce.to_le_bytes());
        
        // Calculate RandomX hash
        let hash = context.vm.calculate_hash(&pre_pow)?;
        
        // Check if hash meets target
        if check_pow(&hash, target) {
            header.pow.hash.copy_from_slice(&hash);
            return Ok(());
        }
    }
    
    Err("Mining failed - nonce space exhausted".into())
}

/// Verify RandomX proof-of-work
pub fn verify_pow(
    header: &BlockHeader,
    context: &MiningContext,
) -> Result<bool, Box<dyn std::error::Error>> {
    let pre_pow = prepare_header_bytes(header);
    let hash = context.vm.calculate_hash(&pre_pow)?;
    
    // Verify hash matches stored hash
    if hash != header.pow.hash {
        return Ok(false);
    }
    
    // Verify hash meets target
    Ok(check_pow(&hash, header.difficulty))
}

/// Prepare header bytes for RandomX hashing
fn prepare_header_bytes(header: &BlockHeader) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(header.version.to_le_bytes());
    hasher.update(&header.prev_hash);
    hasher.update(&header.merkle_root);
    hasher.update(header.timestamp.to_le_bytes());
    hasher.update(header.height.to_le_bytes());
    hasher.update(header.difficulty.to_le_bytes());
    hasher.update(header.pow.nonce.to_le_bytes());
    hasher.finalize().to_vec()
}

/// Check if hash meets target difficulty
fn check_pow(hash: &[u8], target: u64) -> bool {
    let hash_val = u64::from_le_bytes(hash[0..8].try_into().unwrap());
    hash_val < target
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_randomx_mining() {
        let seed = b"BlackSilk RandomX test seed";
        let context = MiningContext::new(seed);
        
        let mut header = BlockHeader {
            version: 1,
            prev_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            height: 1,
            difficulty: u64::MAX >> 20, // Easy target for test
            pow: Pow {
                nonce: 0,
                hash: [0; 32],
            },
        };
        
        mine_block(&mut header, &context, header.difficulty).unwrap();
        assert!(verify_pow(&header, &context).unwrap());
    }
    
    #[test]
    fn test_invalid_pow() {
        let seed = b"BlackSilk RandomX test seed";
        let context = MiningContext::new(seed);
        
        let header = BlockHeader {
            version: 1,
            prev_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            height: 1,
            difficulty: u64::MAX >> 20,
            pow: Pow {
                nonce: 0,
                hash: [0; 32], // Invalid hash
            },
        };
        
        assert!(!verify_pow(&header, &context).unwrap());
    }
} 