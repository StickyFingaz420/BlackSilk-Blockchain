//! RandomX Cache (256 MiB, key-dependent) and Dataset (~2 GiB, derived from the Cache).

use crate::argon2d::{self, QWORDS_IN_BLOCK};
use crate::config::{
    ARGON_MEMORY, CACHE_ACCESSES, CACHE_LINE_SIZE, CACHE_SIZE, DATASET_ITEM_COUNT,
};
use crate::superscalar::{self, Blake2Generator, SsOp, SsProgram};
use std::collections::TryReserveError;

/// `len` zero words, or the allocation error (no abort).
fn zeroed(len: usize) -> Result<Vec<u64>, TryReserveError> {
    let mut v = Vec::new();
    v.try_reserve_exact(len)?;
    v.resize(len, 0);
    Ok(v)
}

const SUPERSCALAR_MUL0: u64 = 6364136223846793005;
const SUPERSCALAR_ADD: [u64; 8] = [
    0,
    9298411001130361340,
    12065312585734608966,
    9306329213124626780,
    5281919268842080866,
    10536153434571861004,
    3398623926847679864,
    9549104520008361294,
];

/// Key-dependent RandomX cache. Sufficient on its own for verification ("light mode").
pub struct Cache {
    memory: Vec<u64>,
    /// The SuperscalarHash programs as generated (the reference form).
    #[cfg_attr(not(test), allow(dead_code))]
    programs: Vec<SsProgram>,
    /// The same programs in execution form, decoded once (`SsProgram::compile`).
    compiled: Vec<Compiled>,
    key: Vec<u8>,
}

/// One SuperscalarHash program in execution form.
struct Compiled {
    ops: Vec<SsOp>,
    address_register: usize,
}

impl Cache {
    /// Builds the cache for `key` (Argon2d fill + 8 SuperscalarHash programs).
    /// Takes roughly a second and allocates 256 MiB.
    pub fn new(key: &[u8]) -> Self {
        let memory = vec![0u64; ARGON_MEMORY as usize * QWORDS_IN_BLOCK];
        Self::with_memory(key, memory)
    }

    /// [`Cache::new`], but an allocation failure is returned instead of
    /// aborting the process (for optional builds such as a miner's prebuild).
    /// The cache is the same.
    pub fn try_new(key: &[u8]) -> Result<Self, TryReserveError> {
        let memory = zeroed(ARGON_MEMORY as usize * QWORDS_IN_BLOCK)?;
        Ok(Self::with_memory(key, memory))
    }

    fn with_memory(key: &[u8], mut memory: Vec<u64>) -> Self {
        argon2d::fill_memory(key, &mut memory);

        let mut gen = Blake2Generator::new(key, 0);
        let programs: Vec<SsProgram> = (0..CACHE_ACCESSES)
            .map(|_| superscalar::generate(&mut gen))
            .collect();
        let compiled = programs
            .iter()
            .map(|p| {
                assert!(p.address_register < 8, "superscalar address register");
                Compiled {
                    ops: p.compile(),
                    address_register: p.address_register,
                }
            })
            .collect();

        Self {
            memory,
            programs,
            compiled,
            key: key.to_vec(),
        }
    }

    /// The key this cache was built from.
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    #[cfg(test)]
    pub(crate) fn memory(&self) -> &[u64] {
        &self.memory
    }

    /// Computes Dataset item `item_number` from the cache (spec 7.3).
    pub(crate) fn dataset_item(&self, item_number: u64) -> [u64; 8] {
        const LINES: u64 = (CACHE_SIZE / CACHE_LINE_SIZE) as u64;
        let mut r = [0u64; 8];
        r[0] = item_number.wrapping_add(1).wrapping_mul(SUPERSCALAR_MUL0);
        for i in 1..8 {
            r[i] = r[0] ^ SUPERSCALAR_ADD[i];
        }
        let mut register_value = item_number;
        for prog in &self.compiled {
            let line = ((register_value & (LINES - 1)) as usize) * 8;
            superscalar::run(&prog.ops, &mut r);
            let mix: &[u64; 8] = self.memory[line..line + 8].try_into().unwrap();
            for (reg, mix) in r.iter_mut().zip(mix) {
                *reg ^= mix;
            }
            register_value = r[prog.address_register];
        }
        r
    }

    /// [`Self::dataset_item`] through the reference interpreter
    /// (`SsProgram::execute`), for the differential tests.
    #[cfg(test)]
    pub(crate) fn dataset_item_reference(&self, item_number: u64) -> [u64; 8] {
        const LINES: u64 = (CACHE_SIZE / CACHE_LINE_SIZE) as u64;
        let mut r = [0u64; 8];
        r[0] = item_number.wrapping_add(1).wrapping_mul(SUPERSCALAR_MUL0);
        for i in 1..8 {
            r[i] = r[0] ^ SUPERSCALAR_ADD[i];
        }
        let mut register_value = item_number;
        for prog in &self.programs {
            let line = ((register_value & (LINES - 1)) as usize) * 8;
            prog.execute(&mut r);
            for (reg, mix) in r.iter_mut().zip(&self.memory[line..line + 8]) {
                *reg ^= mix;
            }
            register_value = r[prog.address_register];
        }
        r
    }
}

/// Fully expanded RandomX dataset (~2080 MiB), used for fast mining ("full mode").
pub struct Dataset {
    items: Vec<u64>,
    key: Vec<u8>,
}

impl Dataset {
    /// Expands the dataset from `cache` using `threads` worker threads.
    pub fn new(cache: &Cache, threads: usize) -> Self {
        let items = vec![0u64; DATASET_ITEM_COUNT as usize * 8];
        Self::with_items(cache, threads, items)
    }

    /// [`Dataset::new`], but an allocation failure is returned instead of
    /// aborting the process (for optional builds such as a miner's prebuild).
    /// The dataset is the same.
    pub fn try_new(cache: &Cache, threads: usize) -> Result<Self, TryReserveError> {
        let items = zeroed(DATASET_ITEM_COUNT as usize * 8)?;
        Ok(Self::with_items(cache, threads, items))
    }

    fn with_items(cache: &Cache, threads: usize, mut items: Vec<u64>) -> Self {
        let threads = threads.max(1);
        let total = DATASET_ITEM_COUNT as usize;
        let per_thread = total.div_ceil(threads);
        std::thread::scope(|s| {
            for (t, chunk) in items.chunks_mut(per_thread * 8).enumerate() {
                s.spawn(move || {
                    let first = (t * per_thread) as u64;
                    for (i, out) in chunk.as_chunks_mut::<8>().0.iter_mut().enumerate() {
                        *out = cache.dataset_item(first + i as u64);
                    }
                });
            }
        });
        Self {
            items,
            key: cache.key.clone(),
        }
    }

    /// The key the dataset was derived from.
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    pub(crate) fn item(&self, item_number: u64) -> [u64; 8] {
        let base = item_number as usize * 8;
        self.items[base..base + 8].try_into().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fallible constructors report an allocation that cannot succeed
    /// instead of aborting (`lib.rs` checks they build the same cache).
    #[test]
    fn an_impossible_allocation_is_an_error() {
        assert!(zeroed(usize::MAX).is_err());
        assert_eq!(zeroed(3).unwrap(), vec![0, 0, 0]);
    }
}
