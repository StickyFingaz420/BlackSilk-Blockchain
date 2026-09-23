//! RandomX cache implementation

use crate::{
    config::*,
    error::RandomXError,
    aes::AesContext,
};

use argon2::{Argon2, Params};
use blake2::{Blake2b512, Digest};
use parking_lot::RwLock;
use std::sync::Arc;

#[cfg(feature = "large_pages")]
use region::{protect, Protection};

/// RandomX cache structure
pub struct Cache {
    /// Memory buffer containing the cache data
    memory: Box<[u8]>,
    /// JIT-compiled initialization code
    #[cfg(feature = "jit")]
    jit: Option<crate::jit::JitCompiler>,
    /// Cache key used for the current initialization
    key: Vec<u8>,
    /// Reciprocal values cache
    reciprocal_cache: Arc<RwLock<Vec<(u64, u64)>>>,
    /// Flags controlling cache behavior
    flags: crate::Flags,
}

impl Cache {
    /// Create a new cache with the specified flags
    pub fn new(flags: crate::Flags) -> Result<Self, RandomXError> {
        let memory = if flags.0 & crate::Flags::LARGE_PAGES.0 != 0 {
            #[cfg(feature = "large_pages")]
            {
                let mem = vec![0u8; ARGON_MEMORY * 1024].into_boxed_slice();
                unsafe {
                    protect(
                        mem.as_ptr(),
                        mem.len(),
                        Protection::READ_WRITE,
                    ).map_err(|e| RandomXError::MemoryAlloc(e.to_string()))?;
                }
                mem
            }
            #[cfg(not(feature = "large_pages"))]
            return Err(RandomXError::Config("Large pages not supported".into()));
        } else {
            vec![0u8; ARGON_MEMORY * 1024].into_boxed_slice()
        };

        Ok(Self {
            memory,
            #[cfg(feature = "jit")]
            jit: if flags.0 & crate::Flags::JIT.0 != 0 {
                Some(crate::jit::JitCompiler::new()?)
            } else {
                None
            },
            key: Vec::new(),
            reciprocal_cache: Arc::new(RwLock::new(Vec::new())),
            flags,
        })
    }

    /// Initialize the cache with a key
    pub fn init(&mut self, key: &[u8]) -> Result<(), RandomXError> {
        if self.key == key {
            return Ok(());
        }

        // Step 1: Initialize memory with Argon2d
        let params = Params::new(
            ARGON_MEMORY as u32,
            ARGON_ITERATIONS,
            ARGON_LANES,
            None,
        ).map_err(|e| RandomXError::CacheInit(e.to_string()))?;

        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2d,
            argon2::Version::V0x13,
            params,
        );

        let mut salt = Vec::with_capacity(key.len() + 8);
        salt.extend_from_slice(key);
        salt.extend_from_slice(b"RandomX\x03");

        argon2.hash_password_into(
            key,
            &salt,
            &mut self.memory,
        ).map_err(|e| RandomXError::CacheInit(e.to_string()))?;

        // Step 2: Generate SuperscalarHash programs
        let mut hasher = Blake2b512::new();
        hasher.update(key);
        let mut seed = hasher.finalize();

        let mut reciprocals = Vec::with_capacity(CACHE_ACCESSES);
        for i in 0..CACHE_ACCESSES {
            // Generate a SuperscalarHash program
            let program = self.generate_program(&seed[..]);
            
            // Calculate reciprocal values
            for instr in program.iter() {
                if let Some(recip) = self.calculate_reciprocal(instr) {
                    reciprocals.push(recip);
                }
            }

            // Update seed for next program
            hasher = Blake2b512::new();
            hasher.update(&seed);
            seed = hasher.finalize();
        }

        // Update reciprocal cache
        *self.reciprocal_cache.write() = reciprocals;

        // Store the key
        self.key = key.to_vec();

        Ok(())
    }

    /// Get a reference to the cache memory
    pub fn memory(&self) -> &[u8] {
        &self.memory
    }

    /// Get a reference to the reciprocal cache
    pub fn reciprocal_cache(&self) -> Arc<RwLock<Vec<(u64, u64)>>> {
        self.reciprocal_cache.clone()
    }

    /// Generate a SuperscalarHash program from a seed
    fn generate_program(&self, seed: &[u8]) -> Vec<u64> {
        let mut program = Vec::with_capacity(PROGRAM_SIZE);
        let aes = AesContext::new(seed[..32].try_into().unwrap())
            .expect("AES initialization failed");

        let mut state = [0u8; 16];
        for _ in 0..PROGRAM_SIZE {
            aes.encrypt_block(&mut state);
            program.push(u64::from_le_bytes(state[..8].try_into().unwrap()));
        }

        program
    }

    /// Calculate reciprocal value for IMUL_RCP instruction
    fn calculate_reciprocal(&self, instr: &u64) -> Option<(u64, u64)> {
        // Extract divisor from instruction
        let divisor = (instr >> 32) as u32;
        if divisor == 0 {
            return None;
        }

        // Calculate reciprocal
        let recip = u64::MAX / divisor as u64;
        Some((divisor as u64, recip))
    }
}

impl Drop for Cache {
    fn drop(&mut self) {
        if self.flags.0 & crate::Flags::LARGE_PAGES.0 != 0 {
            #[cfg(feature = "large_pages")]
            unsafe {
                let _ = protect(
                    self.memory.as_ptr(),
                    self.memory.len(),
                    Protection::NONE,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_initialization() {
        let mut cache = Cache::new(crate::Flags::DEFAULT).unwrap();
        
        // Test initial state
        assert_eq!(cache.key.len(), 0);
        assert_eq!(cache.reciprocal_cache.read().len(), 0);
        
        // Initialize with a key
        let key = b"test key";
        cache.init(key).unwrap();
        
        // Verify initialization
        assert_eq!(cache.key, key);
        assert!(!cache.reciprocal_cache.read().is_empty());
        
        // Test memory contents
        assert!(!cache.memory().iter().all(|&x| x == 0));
    }

    #[test]
    fn test_cache_reinitialization() {
        let mut cache = Cache::new(crate::Flags::DEFAULT).unwrap();
        
        // Initialize with first key
        let key1 = b"key 1";
        cache.init(key1).unwrap();
        let memory1 = cache.memory().to_vec();
        
        // Initialize with same key - should be no-op
        cache.init(key1).unwrap();
        assert_eq!(cache.memory(), &memory1);
        
        // Initialize with different key
        let key2 = b"key 2";
        cache.init(key2).unwrap();
        assert_ne!(cache.memory(), &memory1);
    }
}
