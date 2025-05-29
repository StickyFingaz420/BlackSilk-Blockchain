// Simple VM test to isolate the issue

use std::path::Path;
use std::env;

// Add the miner source to the path
fn main() {
    env::set_var("CARGO_MANIFEST_DIR", "/workspaces/BlackSilk-Blockchain/miner");
    
    println!("Testing RandomX VM directly...");
    
    // Basic imports that would be needed
    use miner::randomx::{RandomXCache, RandomXDataset, RandomXVM};
    
    let seed = b"test_seed_12345678901234567890123";
    let input = b"test_input_data_for_hashing_12345678901234567890";
    
    println!("Creating cache...");
    let cache = RandomXCache::new(seed);
    
    println!("Creating dataset...");
    let dataset = RandomXDataset::new(&cache, 1);
    
    println!("Creating VM...");
    let mut vm = RandomXVM::new(&cache, Some(&dataset));
    
    println!("Calculating hash...");
    let hash = vm.calculate_hash(input);
    
    println!("Hash result: {:?}", hash);
}
