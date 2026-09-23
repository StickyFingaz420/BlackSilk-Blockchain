// ============================================================================
// Blake2b Generator - Blake2b-based pseudorandom data generation
// 
// Implements Blake2b hash function for scratchpad initialization and
// other cryptographic operations in RandomX
// ============================================================================

use blake2::{Blake2b, Digest};
use blake2::digest::Update;
use digest::consts::U64;

/// Blake2b-based pseudorandom generator for RandomX
pub struct Blake2bGenerator {
    state: Blake2b<U64>,
    counter: u64,
}

impl Blake2bGenerator {
    /// Create new Blake2b generator with seed
    pub fn new(seed: &[u8]) -> Self {
        let mut state = Blake2b::<U64>::new();
        Update::update(&mut state, seed);
        
        Blake2bGenerator {
            state,
            counter: 0,
        }
    }

    /// Generate random bytes using Blake2b
    pub fn generate(&mut self, output: &mut [u8]) {
        let mut hasher = self.state.clone();
        Update::update(&mut hasher, &self.counter.to_le_bytes());
        
        let hash = hasher.finalize();
        let hash_bytes = hash.as_slice();
        
        if output.len() <= hash_bytes.len() {
            output.copy_from_slice(&hash_bytes[..output.len()]);
        } else {
            // Generate multiple hashes for longer output
            let mut offset = 0;
            while offset < output.len() {
                let mut chunk_hasher = self.state.clone();
                Update::update(&mut chunk_hasher, &self.counter.to_le_bytes());
                Update::update(&mut chunk_hasher, &offset.to_le_bytes());
                
                let chunk_hash = chunk_hasher.finalize();
                let chunk_bytes = chunk_hash.as_slice();
                let copy_len = (output.len() - offset).min(chunk_bytes.len());
                
                output[offset..offset + copy_len].copy_from_slice(&chunk_bytes[..copy_len]);
                offset += copy_len;
                self.counter += 1;
            }
        }
        
        self.counter += 1;
    }

    /// Generate specific amount of pseudorandom data
    pub fn generate_vec(&mut self, length: usize) -> Vec<u8> {
        let mut output = vec![0u8; length];
        self.generate(&mut output);
        output
    }

    /// Generate 64-bit integer
    pub fn generate_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.generate(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    /// Generate 32-bit integer
    pub fn generate_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.generate(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    /// Reseed the generator
    pub fn reseed(&mut self, new_seed: &[u8]) {
        self.state = Blake2b::<U64>::new();
        Update::update(&mut self.state, new_seed);
        self.counter = 0;
    }
}
