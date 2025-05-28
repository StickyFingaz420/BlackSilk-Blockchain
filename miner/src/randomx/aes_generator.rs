// ============================================================================
// AES Generator - AES-based pseudorandom generator for RandomX
// 
// Implements AES encryption for pseudorandom number generation in scratchpad
// initialization and other RandomX operations
// ============================================================================

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::cipher::generic_array::GenericArray;

/// AES-based pseudorandom generator
pub struct AesGenerator {
    cipher: Aes128,
    state: [u8; 16],
    counter: u64,
}

impl AesGenerator {
    /// Create new AES generator with key
    pub fn new(key: &[u8]) -> Self {
        let mut aes_key = [0u8; 16];
        let key_len = key.len().min(16);
        aes_key[..key_len].copy_from_slice(&key[..key_len]);
        
        let cipher = Aes128::new(GenericArray::from_slice(&aes_key));
        let mut state = [0u8; 16];
        
        // Initialize state with key material
        if key.len() >= 16 {
            state.copy_from_slice(&key[..16]);
        } else {
            state[..key.len()].copy_from_slice(key);
        }
        
        AesGenerator {
            cipher,
            state,
            counter: 0,
        }
    }

    /// Generate random block using AES encryption
    pub fn generate_block(&mut self) -> [u8; 16] {
        // Increment counter and mix into state
        self.counter += 1;
        let counter_bytes = self.counter.to_le_bytes();
        for i in 0..8 {
            self.state[i] ^= counter_bytes[i];
        }
        
        // Encrypt state
        let mut block = GenericArray::from_slice(&self.state).clone();
        self.cipher.encrypt_block(&mut block);
        
        let result = *block.as_ref();
        self.state = result;
        result
    }

    /// Generate arbitrary amount of pseudorandom data
    pub fn generate(&mut self, output: &mut [u8]) {
        let mut offset = 0;
        while offset < output.len() {
            let block = self.generate_block();
            let copy_len = (output.len() - offset).min(16);
            output[offset..offset + copy_len].copy_from_slice(&block[..copy_len]);
            offset += copy_len;
        }
    }

    /// Generate vector of random bytes
    pub fn generate_vec(&mut self, length: usize) -> Vec<u8> {
        let mut output = vec![0u8; length];
        self.generate(&mut output);
        output
    }

    /// Generate 64-bit integer
    pub fn generate_u64(&mut self) -> u64 {
        let block = self.generate_block();
        u64::from_le_bytes([
            block[0], block[1], block[2], block[3],
            block[4], block[5], block[6], block[7]
        ])
    }

    /// Generate 32-bit integer
    pub fn generate_u32(&mut self) -> u32 {
        let block = self.generate_block();
        u32::from_le_bytes([block[0], block[1], block[2], block[3]])
    }

    /// Reseed generator with new key
    pub fn reseed(&mut self, key: &[u8]) {
        let mut aes_key = [0u8; 16];
        let key_len = key.len().min(16);
        aes_key[..key_len].copy_from_slice(&key[..key_len]);
        
        self.cipher = Aes128::new(GenericArray::from_slice(&aes_key));
        self.counter = 0;
        
        // Reinitialize state
        if key.len() >= 16 {
            self.state.copy_from_slice(&key[..16]);
        } else {
            self.state = [0u8; 16];
            self.state[..key.len()].copy_from_slice(key);
        }
    }

    /// Mix additional entropy into generator state
    pub fn mix_entropy(&mut self, entropy: &[u8]) {
        for (i, &byte) in entropy.iter().enumerate() {
            self.state[i % 16] ^= byte;
        }
        
        // Encrypt mixed state
        let mut block = GenericArray::from_slice(&self.state).clone();
        self.cipher.encrypt_block(&mut block);
        self.state = *block.as_ref();
    }
}
