//! Argon2d wrapper for RandomX

use crate::error::RandomXError;
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2, Params, Version,
};

/// RandomX Argon2d parameters
pub const ARGON2_SALT: &str = "RandomX\x03";
pub const ARGON2_ITERATIONS: u32 = 3;
pub const ARGON2_MEMORY: u32 = 262144; // 256 MB
pub const ARGON2_LANES: u32 = 1;

/// Compute Argon2d hash for RandomX initialization
pub fn argon2_randomx(key: &[u8], memory: &mut [u8]) -> Result<(), RandomXError> {
    // Create salt from key and RandomX identifier
    let mut salt = Vec::with_capacity(key.len() + ARGON2_SALT.len());
    salt.extend_from_slice(key);
    salt.extend_from_slice(ARGON2_SALT.as_bytes());
    
    let salt = SaltString::from_bytes(&salt)
        .map_err(|e| RandomXError::CacheInit(format!("Invalid salt: {}", e)))?;

    // Configure Argon2d parameters
    let params = Params::new(
        ARGON2_MEMORY,
        ARGON2_ITERATIONS,
        ARGON2_LANES,
        Some(memory.len() as u32),
    ).map_err(|e| RandomXError::CacheInit(format!("Invalid parameters: {}", e)))?;

    // Create Argon2d instance
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2d,
        Version::V0x13,
        params,
    );

    // Compute hash
    argon2
        .hash_password_into(key, salt.as_bytes(), memory)
        .map_err(|e| RandomXError::CacheInit(format!("Argon2d failed: {}", e)))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2_randomx() {
        let key = b"test key";
        let mut memory = vec![0u8; 1024];
        
        // Hash should succeed
        assert!(argon2_randomx(key, &mut memory).is_ok());
        
        // Output should not be all zeros
        assert!(!memory.iter().all(|&b| b == 0));
        
        // Same input should produce same output
        let mut memory2 = vec![0u8; 1024];
        argon2_randomx(key, &mut memory2).unwrap();
        assert_eq!(memory, memory2);
        
        // Different input should produce different output
        let mut memory3 = vec![0u8; 1024];
        argon2_randomx(b"different key", &mut memory3).unwrap();
        assert_ne!(memory, memory3);
    }
}
