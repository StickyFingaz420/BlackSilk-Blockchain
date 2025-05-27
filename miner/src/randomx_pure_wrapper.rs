// Pure Rust RandomX wrapper - replaces FFI bindings
// Provides the same API as the C RandomX library but implemented in pure Rust

pub use crate::randomx_pro::*;

// Re-export types with the same names as FFI
pub type randomx_cache = crate::randomx_pro::RandomXCache;
pub type randomx_dataset = crate::randomx_pro::RandomXDataset;
pub type randomx_vm = crate::randomx_pro::RandomX;

// Simple hash function for single use (no VM management needed)
pub fn randomx_hash(flags: u32, seed: &[u8], input: &[u8], output: &mut [u8]) {
    let mut rx = crate::randomx_pro::RandomX::new(flags);
    rx.init(seed);
    let hash = rx.calculate_hash(input);
    let output_len = output.len();
    let hash_len = hash.len();
    let copy_len = hash_len.min(output_len);
    output[..copy_len].copy_from_slice(&hash[..copy_len]);
}
