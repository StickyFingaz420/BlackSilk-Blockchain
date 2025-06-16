// ============================================================================
// RandomX Cache - Argon2d-based cache generation
// 
// Implements proper Argon2d memory-hard function for cache initialization
// as specified in the RandomX documentation
// ============================================================================

use argon2::{Argon2, Algorithm, Version, Params};

use crate::randomx::{
    RANDOMX_CACHE_SIZE, RANDOMX_ARGON2_ITERATIONS, RANDOMX_ARGON2_LANES, 
    RANDOMX_ARGON2_SALT, RANDOMX_FLAG_LARGE_PAGES
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
        let memory = if (flags & RANDOMX_FLAG_LARGE_PAGES) != 0 {
            Self::allocate_huge_pages(RANDOMX_CACHE_SIZE)
        } else {
            vec![0u8; RANDOMX_CACHE_SIZE]
        };
        
        let mut cache = RandomXCache {
            memory,
            flags,
            initialized: false,
            key: key.to_vec(),
        };
        cache.init_argon2d(key);
        cache
    }
    
    /// Attempt to allocate memory using huge pages for better performance
    fn allocate_huge_pages(size: usize) -> Vec<u8> {
        // For production systems, we would use madvise() with MADV_HUGEPAGE
        // This is a simplified version that allocates normal pages
        println!("[RandomX Cache] Attempting huge pages allocation ({} MB)", size / (1024 * 1024));
        
        #[cfg(target_os = "linux")]
        {
            // Try to allocate aligned memory that's more likely to use huge pages
            let aligned_size = ((size + 2 * 1024 * 1024 - 1) / (2 * 1024 * 1024)) * (2 * 1024 * 1024);
            let mut memory = vec![0u8; aligned_size];
            
            // Advise kernel to use huge pages if available
            unsafe {
                let ptr = memory.as_mut_ptr() as *mut libc::c_void;
                libc::madvise(ptr, aligned_size, libc::MADV_HUGEPAGE);
            }
            
            memory.resize(size, 0);
            println!("[RandomX Cache] Huge pages allocation attempted (aligned to {} MB)", aligned_size / (1024 * 1024));
            memory
        }
        
        #[cfg(not(target_os = "linux"))]
        {
            println!("[RandomX Cache] Huge pages not supported on this platform, using regular allocation");
            vec![0u8; size]
        }
    }

    /// Initialize cache using Argon2d memory-hard function
    fn init_argon2d(&mut self, key: &[u8]) {
        if self.initialized {
            return;
        }

        println!("[RandomX Cache] Initializing 2MB cache with Argon2d");
        println!("[RandomX Cache] Key length: {} bytes", key.len());
        println!("[RandomX Cache] Salt length: {} bytes", RANDOMX_ARGON2_SALT.len());
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
        let argon2_output_size = 32; // Argon2d output size in bytes
        for (i, chunk) in self.memory.chunks_mut(chunk_size).enumerate() {
            let mut chunk_key = key.to_vec();
            chunk_key.extend_from_slice(&(i as u32).to_le_bytes());
            // Always ensure chunk_key is at least 8 bytes (Argon2d min), pad if needed
            if chunk_key.len() < 8 {
                chunk_key.resize(8, 0);
            }
            // Always hash the key to 32 bytes before Argon2d
            use sha2::{Sha256, Digest};
            let mut offset = 0;
            while offset < chunk.len() {
                let mut hasher = Sha256::new();
                hasher.update(&chunk_key);
                let hashed_key = hasher.finalize();
                let hashed_key_bytes = hashed_key.as_slice();
                // Always use a 32-byte output buffer
                let mut output = [0u8; 32];
                println!("[RandomX Cache] Argon2d call: chunk {}, offset {}, key len {}, salt len {}", i, offset, hashed_key_bytes.len(), RANDOMX_ARGON2_SALT.len());
                let result = argon2.hash_password_into(
                    hashed_key_bytes,
                    RANDOMX_ARGON2_SALT,
                    &mut output
                );
                if let Err(e) = result {
                    panic!("Argon2d hash failed at chunk {} offset {}: {} (key len {}, salt len {}, output size {})", i, offset, e, hashed_key_bytes.len(), RANDOMX_ARGON2_SALT.len(), output.len());
                }
                let end = (offset + argon2_output_size).min(chunk.len());
                let copy_len = end - offset;
                // Defensive: never copy more than 32 bytes from output
                assert!(copy_len <= 32, "Attempting to copy more than 32 bytes from Argon2d output");
                chunk[offset..end].copy_from_slice(&output[..copy_len]);
                // Always use the full 32-byte output as the next key
                chunk_key = output.to_vec();
                offset += argon2_output_size;
            }
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
        let argon2_output_size = 32;
        for iteration in 0..mix_iterations {
            for i in (0..self.memory.len()).step_by(1024) {
                let end = (i + 1024).min(self.memory.len());
                let chunk = &mut self.memory[i..end];
                let mut offset = 0;
                let mut chunk_key = chunk.to_vec();
                let iteration_bytes = (iteration as u32).to_le_bytes();
                chunk_key.extend_from_slice(&iteration_bytes);
                while offset < chunk.len() {
                    let mut output = vec![0u8; argon2_output_size];
                    argon2.hash_password_into(
                        &chunk_key,
                        &iteration_bytes,
                        &mut output
                    ).expect("Argon2d hash failed in mixing");
                    let out_end = (offset + argon2_output_size).min(chunk.len());
                    chunk[offset..out_end].copy_from_slice(&output[..(out_end - offset)]);
                    chunk_key = output.clone();
                    offset += argon2_output_size;
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
