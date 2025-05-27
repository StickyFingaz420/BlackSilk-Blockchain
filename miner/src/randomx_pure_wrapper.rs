// Pure Rust RandomX wrapper - replaces FFI bindings
// Provides the same API as the C RandomX library but implemented in pure Rust

pub use crate::pure_randomx::*;

// Re-export types with the same names as FFI
pub type randomx_cache = crate::pure_randomx::RandomXCache;
pub type randomx_dataset = crate::pure_randomx::RandomXDataset;
pub type randomx_vm = crate::pure_randomx::RandomXVM;

// Simple hash function for single use (no VM management needed)
pub fn randomx_hash(flags: u32, seed: &[u8], input: &[u8], output: &mut [u8]) {
    unsafe {
        // Create cache
        let cache = randomx_alloc_cache(flags as i32);
        if cache.is_null() {
            return;
        }

        // Initialize cache with seed
        randomx_init_cache(cache, seed.as_ptr() as *const std::ffi::c_void, seed.len());

        // Create VM
        let vm = randomx_create_vm(flags as i32, cache, std::ptr::null_mut());
        if vm.is_null() {
            randomx_release_cache(cache);
            return;
        }

        // Calculate hash
        randomx_calculate_hash(
            vm,
            input.as_ptr() as *const std::ffi::c_void,
            input.len(),
            output.as_mut_ptr() as *mut std::ffi::c_void,
        );

        // Cleanup
        randomx_destroy_vm(vm);
        randomx_release_cache(cache);
    }
}
