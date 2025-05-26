// Verify Genesis Block timestamp for testnet
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let testnet_timestamp = 528_854_400u64; // October 5, 1986
    
    // Convert to readable date
    let dt = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(testnet_timestamp);
    
    println!("Testnet Genesis Timestamp: {}", testnet_timestamp);
    println!("Date: October 5, 1986 00:00:00 UTC");
    
    // Verify it's before current time
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    println!("Current timestamp: {}", now);
    println!("Genesis is {} seconds in the past", now - testnet_timestamp);
    
    // This should be about 38+ years ago
    let years_ago = (now - testnet_timestamp) as f64 / (365.25 * 24.0 * 3600.0);
    println!("Genesis was {:.1} years ago", years_ago);
}
