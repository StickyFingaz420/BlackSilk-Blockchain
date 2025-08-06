//! RandomX dataset implementation for mining mode

use crate::{
    config::*,
    error::RandomXError,
    cache::Cache,
};

use std::sync::Arc;
use parking_lot::RwLock;

#[cfg(feature = "large_pages")]
use region::{protect, Protection};

/// RandomX dataset for fast mode
pub struct Dataset {
    /// Memory buffer containing the dataset
    memory: Box<[u8]>,
    /// Item count in the dataset
    item_count: u64,
    /// Initialization state
    initialized: Arc<RwLock<bool>>,
    /// Configuration flags
    flags: crate::Flags,
}

impl Dataset {
    /// Create a new dataset
    pub fn new(flags: crate::Flags) -> Result<Self, RandomXError> {
        let size = DATASET_BASE_SIZE + DATASET_EXTRA_SIZE;
        
        let memory = if flags.0 & crate::Flags::LARGE_PAGES.0 != 0 {
            #[cfg(feature = "large_pages")]
            {
                let mem = vec![0u8; size].into_boxed_slice();
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
            vec![0u8; size].into_boxed_slice()
        };

        Ok(Self {
            memory,
            item_count: (DATASET_BASE_SIZE + DATASET_EXTRA_SIZE) as u64 / DATASET_ITEM_SIZE as u64,
            initialized: Arc::new(RwLock::new(false)),
            flags,
        })
    }

    /// Initialize the dataset using a cache
    pub fn init(
        &mut self,
        cache: &Cache,
        start_item: u64,
        item_count: u64,
    ) -> Result<(), RandomXError> {
        if *self.initialized.read() {
            return Ok(());
        }

        if start_item + item_count > self.item_count {
            return Err(RandomXError::DatasetInit("Invalid item range".into()));
        }

        let start_offset = start_item as usize * DATASET_ITEM_SIZE;
        let end_offset = (start_item + item_count) as usize * DATASET_ITEM_SIZE;

        // Initialize dataset items
        let cache_memory = cache.memory();
        let reciprocals = cache.reciprocal_cache();

        #[cfg(feature = "jit")]
        if self.flags.0 & crate::Flags::JIT.0 != 0 {
            // Use JIT-compiled initialization function
            todo!("JIT dataset initialization");
        }

        // Initialize items using the cache
        for item in 0..item_count {
            let item_index = start_item + item;
            let offset = (item_index as usize * DATASET_ITEM_SIZE) - start_offset;
            
            self.init_dataset_item(
                item_index,
                &mut self.memory[offset..offset + DATASET_ITEM_SIZE],
                cache_memory,
                &reciprocals.read(),
            )?;
        }

        if start_item + item_count == self.item_count {
            *self.initialized.write() = true;
        }

        Ok(())
    }

    /// Initialize a single dataset item
    fn init_dataset_item(
        &self,
        item_index: u64,
        output: &mut [u8],
        cache: &[u8],
        reciprocals: &[(u64, u64)],
    ) -> Result<(), RandomXError> {
        // Register file for SuperscalarHash
        let mut r = [0u64; 8];
        
        // Initialize registers with item index
        r[0] = item_index;
        r[1] = item_index >> 32;
        
        // Execute SuperscalarHash programs using cache data
        for i in 0..CACHE_ACCESSES {
            let offset = (item_index as usize + i * 16) % (cache.len() / 64) * 64;
            let cache_item = &cache[offset..offset + 64];
            
            // Mix cache data into registers
            for j in 0..8 {
                let value = u64::from_le_bytes(cache_item[j * 8..(j + 1) * 8].try_into().unwrap());
                r[j] ^= value;
            }
            
            // Apply reciprocal values
            if let Some(&(divisor, reciprocal)) = reciprocals.get(i) {
                for reg in r.iter_mut() {
                    if *reg == divisor {
                        *reg = reciprocal;
                    }
                }
            }
        }

        // Write final register values to output
        for i in 0..8 {
            output[i * 8..(i + 1) * 8].copy_from_slice(&r[i].to_le_bytes());
        }

        Ok(())
    }

    /// Get a reference to the dataset memory
    pub fn memory(&self) -> &[u8] {
        &self.memory
    }

    /// Get the total number of items in the dataset
    pub fn item_count(&self) -> u64 {
        self.item_count
    }

    /// Check if the dataset is fully initialized
    pub fn is_initialized(&self) -> bool {
        *self.initialized.read()
    }
}

impl Drop for Dataset {
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
    use crate::Flags;

    #[test]
    fn test_dataset_initialization() {
        // Create cache
        let mut cache = Cache::new(Flags::DEFAULT).unwrap();
        cache.init(b"test key").unwrap();
        
        // Create dataset
        let mut dataset = Dataset::new(Flags::DEFAULT).unwrap();
        assert!(!dataset.is_initialized());
        
        // Initialize part of dataset
        dataset.init(&cache, 0, 100).unwrap();
        assert!(!dataset.is_initialized());  // Not fully initialized yet
        
        // Memory should contain non-zero data
        assert!(!dataset.memory()[..100 * DATASET_ITEM_SIZE]
            .iter()
            .all(|&x| x == 0));
            
        // Initialize rest of dataset
        dataset.init(&cache, 100, dataset.item_count() - 100).unwrap();
        assert!(dataset.is_initialized());
    }

    #[test]
    fn test_dataset_item_generation() {
        let mut cache = Cache::new(Flags::DEFAULT).unwrap();
        cache.init(b"test key").unwrap();
        
        let dataset = Dataset::new(Flags::DEFAULT).unwrap();
        
        // Generate two items
        let mut item1 = vec![0u8; DATASET_ITEM_SIZE];
        let mut item2 = vec![0u8; DATASET_ITEM_SIZE];
        
        dataset.init_dataset_item(
            0,
            &mut item1,
            cache.memory(),
            &cache.reciprocal_cache().read(),
        ).unwrap();
        
        dataset.init_dataset_item(
            1,
            &mut item2,
            cache.memory(),
            &cache.reciprocal_cache().read(),
        ).unwrap();
        
        // Items should be different
        assert_ne!(item1, item2);
        
        // Generate same item again - should be identical
        let mut item1_repeat = vec![0u8; DATASET_ITEM_SIZE];
        dataset.init_dataset_item(
            0,
            &mut item1_repeat,
            cache.memory(),
            &cache.reciprocal_cache().read(),
        ).unwrap();
        
        assert_eq!(item1, item1_repeat);
    }
}
