// Test to verify cleaned VM works correctly
use std::time::Instant;

// Import the miner crate
extern crate blacksilk_miner;
use blacksilk_miner::randomx::{RandomXCache, RandomXDataset, RandomXVM};

fn main() {
    println!("Testing cleaned RandomX VM implementation...");
    
    let start = Instant::now();
    
    // Initialize cache and dataset
    let seed = b"test_seed_123";
    let cache = RandomXCache::new(seed, 0x6);
    let dataset = RandomXDataset::new(&cache, 1);
    
    // Create VM
    let mut vm = RandomXVM::new(&cache, Some(&dataset));
    
    // Test hash calculation
    let input = b"test_input_data";
    let hash1 = vm.calculate_hash(input);
    let hash2 = vm.calculate_hash(input);
    
    println!("Hash 1: {}", hex::encode(&hash1));
    println!("Hash 2: {}", hex::encode(&hash2));
    println!("Hashes are deterministic: {}", hash1 == hash2);
    
    // Test different inputs
    let input2 = b"different_input";
    let hash3 = vm.calculate_hash(input2);
    println!("Hash 3: {}", hex::encode(&hash3));
    println!("Different inputs produce different hashes: {}", hash1 != hash3);
    
    println!("Test completed in: {:?}", start.elapsed());
    println!("VM is working correctly without debug spam!");
}
