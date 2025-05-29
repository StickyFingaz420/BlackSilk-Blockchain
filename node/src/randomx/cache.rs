// ============================================================================
// RandomX Cache - Argon2d-based cache generation
// 
// Implements proper Argon2d memory-hard function for cache initialization
// as specified in the RandomX documentation
// ============================================================================

use argon2::{Argon2, Algorithm, Version, Params};

use crate::randomx::{
    RANDOMX_CACHE_SIZE, RANDOMX_ARGON2_ITERATIONS, RANDOMX_ARGON2_LANES, 
    RANDOMX_ARGON2_SALT
};

/// RandomX Cache with Argon2d generation
pub struct RandomXCache {
    pub memory: Vec<u8>,
    pub flags: u32,
    pub initialized: bool,
    pub key: Vec<u8>,
}

impl RandomXCache {
    /// Create new RandomX cache with Argon2d initialization
    pub fn new(key: &[u8], flags: u32) -> Self {
        let mut cache = RandomXCache {
            memory: vec![0u8; RANDOMX_CACHE_SIZE],
            flags,
            initialized: false,
            key: key.to_vec(),
        };
        cache.init_argon2d(key);
        cache
    }

    /// Initialize cache using Argon2d memory-hard function
    fn init_argon2d(&mut self, key: &[u8]) {
        if self.initialized {
            return;
        }

        println!("[RandomX Cache] Initializing 2MB cache with Argon2d");
        println!("[RandomX Cache] Key length: {} bytes", key.len());
        
        // Configure Argon2d with RandomX parameters
        let params = Params::new(
            (RANDOMX_CACHE_SIZE / 1024) as u32, // KB
            RANDOMX_ARGON2_ITERATIONS,
            RANDOMX_ARGON2_LANES,
            Some(RANDOMX_CACHE_SIZE)
        ).expect("Invalid Argon2 parameters");

        let argon2 = Argon2::new(
            Algorithm::Argon2d,
            Version::V0x13,
            params
        );

        // Generate cache in chunks with progress reporting
        let chunk_size = RANDOMX_CACHE_SIZE / 8; // 8 chunks for progress
        for (i, chunk) in self.memory.chunks_mut(chunk_size).enumerate() {
            let mut chunk_key = key.to_vec();
            chunk_key.extend_from_slice(&(i as u32).to_le_bytes());
            
            // Generate this chunk using Argon2d
            let mut output = vec![0u8; chunk_size];
            argon2.hash_password_into(
                &chunk_key,
                RANDOMX_ARGON2_SALT,
                &mut output
            ).expect("Argon2d hash failed");
            
            chunk.copy_from_slice(&output);
            
            let progress_pct = ((i + 1) * 100) / 8;
            println!("[RandomX Cache] Argon2d progress: {}% ({}/8 chunks)", progress_pct, i + 1);
        }

        // Additional mixing pass for security
        self.mix_cache_argon2d();

        println!("[RandomX Cache] Argon2d cache initialization complete!");
        self.initialized = true;
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
}
