// ============================================================================
// BlackSilk Rust Native RandomX CPU-Only Implementation
// 
// 100% Pure Rust RandomX implementation following the complete specification
// - Argon2d cache generation (2MB)
// - Blake2b scratchpad initialization  
// - SuperscalarHash dataset expansion (2.08 GB)
// - Full RandomX VM with integer/FP/SIMD operations
// - CPU timing enforcement for GPU/ASIC resistance
// - Memory requirements enforcement (~2.08 GiB per NUMA node)
// ============================================================================

pub mod cache;
pub mod dataset;
pub mod aes_generator;
pub mod vm;
pub mod instruction;
pub mod superscalar;
pub mod blake2b_generator;

// Re-export main types
pub use cache::RandomXCache;
pub use dataset::RandomXDataset;
pub use vm::RandomXVM;
pub use aes_generator::AesGenerator;
pub use blake2b_generator::Blake2bGenerator;

// RandomX Constants (Full specification compliance)
pub const RANDOMX_HASH_SIZE: usize = 32;
pub const RANDOMX_DATASET_ITEM_SIZE: usize = 64;
pub const RANDOMX_DATASET_ITEM_COUNT: usize = 33554432; // 2^25 = 2.08 GB dataset
pub const RANDOMX_CACHE_SIZE: usize = 2097152; // 2MB cache
pub const RANDOMX_SCRATCHPAD_L1: usize = 16384; // 16KB L1 cache
pub const RANDOMX_SCRATCHPAD_L2: usize = 262144; // 256KB L2 cache  
pub const RANDOMX_SCRATCHPAD_L3: usize = 2097152; // 2MB L3 scratchpad

pub const DATASET_SIZE: usize = RANDOMX_DATASET_ITEM_COUNT * RANDOMX_DATASET_ITEM_SIZE;

// RandomX VM Configuration
pub const RANDOMX_PROGRAM_ITERATIONS: usize = 2048;
pub const RANDOMX_PROGRAM_COUNT: usize = 8;
pub const RANDOMX_INSTRUCTION_COUNT: usize = 256;

// RandomX Flags (CPU-only optimization)
pub const RANDOMX_FLAG_DEFAULT: u32 = 0;
pub const RANDOMX_FLAG_LARGE_PAGES: u32 = 1;
pub const RANDOMX_FLAG_HARD_AES: u32 = 2;
pub const RANDOMX_FLAG_FULL_MEM: u32 = 4;
pub const RANDOMX_FLAG_SECURE: u32 = 16;
pub const RANDOMX_FLAG_ARGON2_SSSE3: u32 = 32;
pub const RANDOMX_FLAG_ARGON2_AVX2: u32 = 64;

// Argon2d parameters for cache generation
pub const RANDOMX_ARGON2_ITERATIONS: u32 = 3;
pub const RANDOMX_ARGON2_LANES: u32 = 1;
pub const RANDOMX_ARGON2_SALT: &[u8] = b"RandomX\x03";

// Memory allocation alignment for optimal CPU performance
pub const RANDOMX_ALIGNMENT: usize = 64;

/// Calculate RandomX hash with full CPU-only verification
pub fn randomx_hash(key: &[u8], input: &[u8]) -> [u8; 32] {
    let cache = RandomXCache::new(key);
    let dataset = Some(RandomXDataset::new(&cache, 1));
    
    let mut vm = RandomXVM::new(&cache, dataset.as_ref());
    vm.calculate_hash(input)
}

/// Get optimal RandomX flags for CPU-only mining
pub fn get_optimal_flags() -> u32 {
    let mut flags = RANDOMX_FLAG_DEFAULT;
    
    // Always use hard AES for performance
    if is_x86_feature_detected!("aes") {
        flags |= RANDOMX_FLAG_HARD_AES;
    }
    
    // Use full memory mode for maximum ASIC resistance
    flags |= RANDOMX_FLAG_FULL_MEM;
    
    // Optimize Argon2d based on CPU features
    if is_x86_feature_detected!("avx2") {
        flags |= RANDOMX_FLAG_ARGON2_AVX2;
    } else if is_x86_feature_detected!("ssse3") {
        flags |= RANDOMX_FLAG_ARGON2_SSSE3;
    }
    
    flags
}

/// Verify CPU timing to detect GPU/ASIC mining attempts
pub fn verify_cpu_timing(hash_time_ns: u64, expected_min_ns: u64) -> bool {
    // Reject hashes computed suspiciously fast (potential GPU/ASIC)
    hash_time_ns >= expected_min_ns
}
