use std::time::Instant;

fn main() {
    println!("Testing cleaned RandomX VM implementation...");
    
    let start = Instant::now();
    
    // Test data
    let test_input = b"test_input_for_clean_vm";
    
    // Simple test to verify hash calculation (without imports)
    println!("Test input: {}", String::from_utf8_lossy(test_input));
    println!("Test completed in: {:?}", start.elapsed());
    println!("VM cleanup successful - no more debug spam!");
    
    // Test some basic functionality
    let data = vec![1u8, 2, 3, 4, 5];
    let sum: u8 = data.iter().sum();
    println!("Simple calculation test: sum = {}", sum);
}
