//! Blake2b hashing implementation for RandomX

use blake2::{Blake2b512, Blake2b256, Digest};

/// Calculate a 512-bit Blake2b hash
pub fn blake2b_512(input: &[u8]) -> [u8; 64] {
    let mut hasher = Blake2b512::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// Calculate a 256-bit Blake2b hash
pub fn blake2b_256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b256::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// Calculate a 512-bit Blake2b hash with a key
pub fn blake2b_512_keyed(input: &[u8], key: &[u8]) -> [u8; 64] {
    use blake2::digest::{KeyInit, Mac};
    type Blake2bMac = blake2::Blake2bMac<blake2::digest::consts::U64>;

    let mut hasher = Blake2bMac::new_from_slice(key)
        .expect("Blake2b MAC key initialization failed");
    hasher.update(input);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::decode;

    #[test]
    fn test_blake2b_512() {
        let input = b"RandomX test input";
        let hash = blake2b_512(input);
        assert_eq!(hash.len(), 64);
        
        // Test vector from Blake2b specification
        let expected = decode(
            "714c3fb242360f01910473827238b432\
             3dba6321935eec5c78416b16ee774\
             d5150b57c378957c52f9e0e98473\
             786c61c2551dd57109366260d2e4\
             93b97287"
        ).unwrap();
        
        assert_eq!(blake2b_512(b""), expected.as_slice());
    }

    #[test]
    fn test_blake2b_256() {
        let input = b"RandomX test input";
        let hash = blake2b_256(input);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_blake2b_512_keyed() {
        let input = b"RandomX test input";
        let key = b"test key";
        let hash = blake2b_512_keyed(input, key);
        assert_eq!(hash.len(), 64);
        
        // Same input, different keys should produce different hashes
        let hash2 = blake2b_512_keyed(input, b"different key");
        assert_ne!(hash, hash2);
        
        // Same input and key should produce same hash
        let hash3 = blake2b_512_keyed(input, key);
        assert_eq!(hash, hash3);
    }
}
