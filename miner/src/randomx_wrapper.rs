//! High-performance RandomX wrapper for BlackSilk mining
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]
#![allow(dead_code)]

use crate::randomx_ffi::*;
use std::ffi::c_void;
use std::ptr;

// Constants from RandomX
pub const RANDOMX_HASH_SIZE: usize = 32;
pub const RANDOMX_DATASET_ITEM_SIZE: usize = 64;

pub struct RandomXCache {
    ptr: *mut randomx_cache,
}

pub struct RandomXDataset {
    ptr: *mut randomx_dataset,
}

pub struct RandomXVM {
    ptr: *mut randomx_vm,
}

impl RandomXCache {
    pub fn new(flags: randomx_flags) -> Result<Self, &'static str> {
        let ptr = unsafe { randomx_alloc_cache(flags) };
        if ptr.is_null() {
            Err("Failed to allocate RandomX cache")
        } else {
            Ok(RandomXCache { ptr })
        }
    }

    pub fn init(&mut self, key: &[u8]) {
        unsafe {
            randomx_init_cache(self.ptr, key.as_ptr() as *const c_void, key.len());
        }
    }

    pub fn as_ptr(&self) -> *mut randomx_cache {
        self.ptr
    }
}

impl Drop for RandomXCache {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                randomx_release_cache(self.ptr);
            }
        }
    }
}

impl RandomXDataset {
    pub fn new(flags: randomx_flags) -> Result<Self, &'static str> {
        let ptr = unsafe { randomx_alloc_dataset(flags) };
        if ptr.is_null() {
            Err("Failed to allocate RandomX dataset")
        } else {
            Ok(RandomXDataset { ptr })
        }
    }

    pub fn init(&mut self, cache: &RandomXCache, start_item: u32, item_count: u32) {
        unsafe {
            randomx_init_dataset(self.ptr, cache.as_ptr(), start_item as u64, item_count as u64);
        }
    }

    pub fn as_ptr(&self) -> *mut randomx_dataset {
        self.ptr
    }
}

impl Drop for RandomXDataset {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                randomx_release_dataset(self.ptr);
            }
        }
    }
}

impl RandomXVM {
    pub fn new_full(flags: randomx_flags, cache: Option<&RandomXCache>, dataset: Option<&RandomXDataset>) -> Result<Self, &'static str> {
        let ptr = unsafe {
            randomx_create_vm(
                flags,
                cache.map_or(ptr::null_mut(), |c| c.as_ptr()),
                dataset.map_or(ptr::null_mut(), |d| d.as_ptr()),
            )
        };
        
        if ptr.is_null() {
            Err("Failed to create RandomX VM")
        } else {
            Ok(RandomXVM { ptr })
        }
    }

    pub fn new_light(flags: randomx_flags, cache: &RandomXCache) -> Result<Self, &'static str> {
        Self::new_full(flags, Some(cache), None)
    }

    pub fn calculate_hash(&mut self, input: &[u8]) -> [u8; RANDOMX_HASH_SIZE] {
        let mut output = [0u8; RANDOMX_HASH_SIZE];
        unsafe {
            randomx_calculate_hash(
                self.ptr,
                input.as_ptr() as *const c_void,
                input.len(),
                output.as_mut_ptr() as *mut c_void,
            );
        }
        output
    }
}

impl Drop for RandomXVM {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                randomx_destroy_vm(self.ptr);
            }
        }
    }
}

// Unsafe implementations for thread safety - RandomX VMs are thread-safe
unsafe impl Send for RandomXVM {}
unsafe impl Sync for RandomXVM {}
unsafe impl Send for RandomXCache {}
unsafe impl Sync for RandomXCache {}
unsafe impl Send for RandomXDataset {}
unsafe impl Sync for RandomXDataset {}

pub fn get_recommended_flags() -> randomx_flags {
    unsafe { randomx_get_flags() }
}

pub fn get_dataset_item_count() -> u32 {
    unsafe { randomx_dataset_item_count() as u32 }
}

// Legacy compatibility function
pub unsafe fn randomx_hash(
    flags: u32,
    seed: &[u8],
    input: &[u8],
    output: &mut [u8],
) {
    // Allocate cache
    let cache = randomx_alloc_cache(flags as i32);
    assert!(!cache.is_null(), "Failed to allocate RandomX cache");
    // Initialize cache with seed
    randomx_init_cache(cache, seed.as_ptr() as *const c_void, seed.len());
    // Create VM
    let vm = randomx_create_vm(flags as i32, cache, ptr::null_mut());
    assert!(!vm.is_null(), "Failed to create RandomX VM");
    // Calculate hash
    randomx_calculate_hash(vm, input.as_ptr() as *const c_void, input.len(), output.as_mut_ptr() as *mut c_void);
    // Clean up
    randomx_destroy_vm(vm);
    randomx_release_cache(cache);
}
