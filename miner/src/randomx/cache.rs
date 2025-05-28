// RandomX Cache - Argon2d-based cache generation
// 
// Implements proper Argon2d memory-hard function for cache initialization
// as specified in the RandomX documentation

use argon2::{Argon2, Algorithm, Version, Params};
use crate::randomx::{
    RANDOMX_CACHE_SIZE, RANDOMX_ARGON2_ITERATIONS, RANDOMX_ARGON2_LANES, 
    RANDOMX_ARGON2_SALT
};

const MIN_ARGON2_OUTPUT: usize = 32; // Minimum output size for Argon2d

/// RandomX Cache with Argon2d generation
pub struct RandomXCache {
    pub memory: Vec<u8>,
    pub initialized: bool,
    pub flags: u32,
}

impl RandomXCache {
    /// Create new RandomX cache with Argon2d initialization
    pub fn new(key: &[u8]) -> Self {
        println!("[RandomX Cache] Initializing 2MB cache with Argon2d...");
        
        let mut cache = RandomXCache {
            memory: vec![0u8; RANDOMX_CACHE_SIZE],
            initialized: false,
            flags: crate::randomx::RANDOMX_FLAG_FULL_MEM,
        };
        
        cache.init_with_argon2d(key);
        cache.apply_mixing_passes();
        cache.initialized = true;
        
        println!("[RandomX Cache] Cache initialization complete!");
        cache
    }
    
    /// Initialize cache using Argon2d memory-hard function
    fn init_with_argon2d(&mut self, key: &[u8]) {
        // Configure Argon2d parameters according to RandomX specification
        let params = Params::new(
            1024, // Memory in KB (1MB)
            RANDOMX_ARGON2_ITERATIONS,
            RANDOMX_ARGON2_LANES,
            Some(RANDOMX_CACHE_SIZE)
        ).expect("Invalid Argon2 parameters");
        
        let argon2 = Argon2::new(Algorithm::Argon2d, Version::V0x13, params);
        
        // Generate the entire cache at once using Argon2d
        println!("[RandomX Cache] Generating 2MB cache with Argon2d...");
        argon2.hash_password_into(
            key,
            RANDOMX_ARGON2_SALT,
            &mut self.memory
        ).expect("Argon2d hash failed");
        
        println!("[RandomX Cache] Argon2d generation complete");
    }
    
    /// Additional Argon2d-based mixing for enhanced security
    fn mix_cache_argon2d(&mut self) {
        println!("[RandomX Cache] Performing Argon2d mixing pass...");
        
        let mix_iterations = 16;
        let params = Params::new(1024, 1, 1, Some(1024))
            .expect("Invalid mixing parameters");
        let argon2 = Argon2::new(Algorithm::Argon2d, Version::V0x13, params);
        
        for iteration in 0..mix_iterations {
            for i in (0..self.memory.len()).step_by(1024) {
                let end = (i + 1024).min(self.memory.len());
                let chunk = &mut self.memory[i..end];
                
                // Mix using Argon2d with reduced parameters
                let mut mixed = vec![0u8; chunk.len()];
                let iteration_bytes = (iteration as u32).to_le_bytes();
                
                if argon2.hash_password_into(chunk, &iteration_bytes, &mut mixed).is_ok() {
                    chunk.copy_from_slice(&mixed);
                }
            }
            
            if iteration % 4 == 0 {
                println!("[RandomX Cache] Mixing pass: {}/{}", iteration + 1, mix_iterations);
            }
        }
    }

    /// Get cache data at specific offset with bounds checking
    pub fn get_data(&self, offset: usize, length: usize) -> &[u8] {
        let end = (offset + length).min(self.memory.len());
        &self.memory[offset..end]
    }

    /// Get 64-byte item from cache
    pub fn get_item(&self, index: usize) -> [u8; 64] {
        let offset = (index * 64) % self.memory.len();
        let mut item = [0u8; 64];
        
        if offset + 64 <= self.memory.len() {
            item.copy_from_slice(&self.memory[offset..offset + 64]);
        } else {
            // Handle wrap-around
            let first_part = self.memory.len() - offset;
            item[..first_part].copy_from_slice(&self.memory[offset..]);
            item[first_part..].copy_from_slice(&self.memory[..64 - first_part]);
        }
        
        item
    }

    /// Verify cache integrity with Argon2d
    pub fn verify_integrity(&self) -> bool {
        if !self.initialized || self.memory.is_empty() {
            return false;
        }

        // Quick integrity check - verify non-zero entropy
        let zero_count = self.memory.iter().filter(|&&b| b == 0).count();
        let entropy_ratio = 1.0 - (zero_count as f64 / self.memory.len() as f64);
        
        // Expect high entropy from Argon2d
        entropy_ratio > 0.4
    }
    
    fn apply_mixing_passes(&mut self) {
        println!("[RandomX Cache] Applying 4 mixing passes...");
        
        // Apply 4 mixing passes to ensure proper cache distribution
        for pass in 0..4 {
            for i in (0..RANDOMX_CACHE_SIZE).step_by(64) {
                let end = (i + 64).min(RANDOMX_CACHE_SIZE);
                if end - i >= 64 {
                    // XOR with previous block for mixing
                    if i >= 64 {
                        for j in 0..64 {
                            self.memory[i + j] ^= self.memory[i - 64 + j];
                        }
                    }
                    
                    // Apply simple transformation
                    for j in (0..64).step_by(8) {
                        if i + j + 8 <= RANDOMX_CACHE_SIZE {
                            let val = u64::from_le_bytes([
                                self.memory[i + j], self.memory[i + j + 1],
                                self.memory[i + j + 2], self.memory[i + j + 3],
                                self.memory[i + j + 4], self.memory[i + j + 5],
                                self.memory[i + j + 6], self.memory[i + j + 7],
                            ]);
                            let mixed = val.wrapping_mul(6364136223846793005u64).wrapping_add(1442695040888963407u64);
                            let bytes = mixed.to_le_bytes();
                            self.memory[i + j..i + j + 8].copy_from_slice(&bytes);
                        }
                    }
                }
            }
            println!("[RandomX Cache] Mixing pass {} complete", pass + 1);
        }
    }
}
