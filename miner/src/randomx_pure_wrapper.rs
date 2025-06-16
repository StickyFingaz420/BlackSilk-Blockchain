// Pure Rust RandomX wrapper - replaces FFI bindings
// Provides the same API as the C RandomX library but implemented in pure Rust

pub use crate::randomx_pro::*;

// Re-export types with the same names as FFI
pub type randomx_cache = crate::randomx_pro::RandomXCache;
pub type randomx_dataset = crate::randomx_pro::RandomXDataset;
pub type randomx_vm = crate::randomx_pro::RandomX;

// Simple hash function for single use (no VM management needed)
// WARNING: Do NOT use this function for mining threads! It allocates a new dataset and is only for one-off test hashes.
// For mining, always use the shared RandomXVM and RandomXDataset from randomx/vm.rs.
pub fn randomx_hash(flags: u32, seed: &[u8], input: &[u8], output: &mut [u8]) {
    if flags & crate::randomx_pro::RANDOMX_FLAG_FULL_MEM == 0 {
        log::error!("Attempted to use RandomX in light mode or without full dataset. This is forbidden.");
        panic!("RandomX mining must use full dataset (2GB) for CPU-only enforcement.");
    }
    // Only use cache (light mode), never allocate dataset here
    let mut rx = crate::randomx_pro::RandomX::new(flags & !crate::randomx_pro::RANDOMX_FLAG_FULL_MEM);
    rx.init(seed);
    let hash = rx.calculate_hash(input);
    let output_len = output.len();
    let hash_len = hash.len();
    let copy_len = hash_len.min(output_len);
    output[..copy_len].copy_from_slice(&hash[..copy_len]);
}
