//! Pure Rust implementation of the RandomX proof-of-work algorithm
//! 
//! RandomX is a proof-of-work algorithm that is optimized for general-purpose CPUs.
//! It uses random code execution together with several memory-hard techniques to
//! minimize the efficiency advantage of specialized hardware.

#![cfg_attr(feature = "nightly", feature(stdsimd))]
#![cfg_attr(feature = "nightly", feature(avx512_target_feature))]

mod aes;
mod argon;
mod blake;
mod cache;
mod config;
mod dataset;
mod vm;
mod error;
mod jit;
mod machine;

pub use error::RandomXError;
use config::*;

/// The size of a RandomX hash output in bytes
pub const HASH_SIZE: usize = 32;

/// Flags to control RandomX VM behavior
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flags(u32);

impl Flags {
    /// Default configuration with no optimizations
    pub const DEFAULT: Flags = Flags(0);
    
    /// Use large pages for memory allocations
    pub const LARGE_PAGES: Flags = Flags(1);
    
    /// Use hardware AES if available
    pub const HARDWARE_AES: Flags = Flags(2);
    
    /// Full memory mode (2080 MB)
    pub const FULL_MEM: Flags = Flags(4);
    
    /// Enable JIT compilation
    pub const JIT: Flags = Flags(8);
}

/// A RandomX virtual machine instance
pub struct RandomXVM {
    flags: Flags,
    cache: Option<cache::Cache>,
    dataset: Option<dataset::Dataset>,
    machine: machine::Machine,
}

impl RandomXVM {
    /// Create a new RandomX VM instance
    pub fn new(flags: Flags) -> Result<Self, RandomXError> {
        let cache = if flags.0 & Flags::FULL_MEM.0 == 0 {
            Some(cache::Cache::new(flags)?)
        } else {
            None
        };

        let dataset = if flags.0 & Flags::FULL_MEM.0 != 0 {
            Some(dataset::Dataset::new(flags)?)
        } else {
            None
        };

        let machine = machine::Machine::new(flags, cache.as_ref(), dataset.as_ref())?;

        Ok(Self {
            flags,
            cache,
            dataset,
            machine,
        })
    }

    /// Calculate a RandomX hash
    pub fn calculate_hash(&mut self, input: &[u8]) -> Result<[u8; HASH_SIZE], RandomXError> {
        self.machine.calculate_hash(input)
    }

    /// Initialize the VM cache with a key
    pub fn init_cache(&mut self, key: &[u8]) -> Result<(), RandomXError> {
        if let Some(cache) = &mut self.cache {
            cache.init(key)?;
        }
        Ok(())
    }

    /// Initialize the VM dataset
    pub fn init_dataset(&mut self, start_item: u64, item_count: u64) -> Result<(), RandomXError> {
        if let Some(dataset) = &mut self.dataset {
            dataset.init(self.cache.as_ref().ok_or(RandomXError::NoCache)?, start_item, item_count)?;
        }
        Ok(())
    }

    /// Validates a RandomX proof-of-work submission.
    pub fn validate_pow(&mut self, header: &[u8], nonce: u64, target: &[u8]) -> Result<bool, RandomXError> {
        let mut input = Vec::with_capacity(header.len() + 8);
        input.extend_from_slice(header);
        input.extend_from_slice(&nonce.to_le_bytes());

        let hash = self.calculate_hash(&input)?;
        Ok(hash.as_slice() <= target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::decode;

    #[test]
    fn test_randomx_basic() {
        let key = b"RandomX example key";
        let input = b"RandomX example input";
        
        let mut vm = RandomXVM::new(Flags::DEFAULT).unwrap();
        vm.init_cache(key).unwrap();
        
        let hash = vm.calculate_hash(input).unwrap();
        assert_eq!(hash.len(), HASH_SIZE);
    }

    #[test]
    fn test_pow_validation() {
        let header = b"test block header";
        let nonce = 12345u64;
        let target = &[0xff; 32]; // Easy target for testing
        
        let mut vm = RandomXVM::new(Flags::DEFAULT).unwrap();
        vm.init_cache(b"test key").unwrap();
        
        let result = vm.validate_pow(header, nonce, target).unwrap();
        assert!(result);
    }
}
