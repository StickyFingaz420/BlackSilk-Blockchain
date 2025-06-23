//! # ML-DSA-44 Rust Library
//!
//! **Module-Lattice-Based Digital Signature Algorithm (ML-DSA-44)**
//!
//! ## Overview
//! ML-DSA-44 is a post-quantum digital signature algorithm designed to be secure against attacks by quantum computers. This Rust library provides a safe, ergonomic interface to the ML-DSA-44 implementation.
//!
//! ## Key Features
//! - Post-quantum security: Resistant to quantum computer attacks
//! - Deterministic key generation: Generate keys from seeds for reproducible results
//! - Context-aware signing: Support for additional context data in signatures
//! - Memory-safe: Safe Rust API with proper error handling
//! - Zero-copy operations: Efficient memory usage where possible
//!
//! ## Algorithm Parameters
//! | Parameter   | Size (bytes) |
//! |------------|--------------|
//! | Public Key | 1,312        |
//! | Secret Key | 2,560        |
//! | Signature  | ≤ 2,420      |
//! | Seed       | 32           |
//!
//! ## Installation
//! ```toml
//! [dependencies]
//! ml-dsa-44 = "0.1.0"
//! ```
//!
//! ## API Reference & Usage Examples
//! ```rust
//! use ml_dsa_44::{Keypair, sign, verify};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Generate keypair
//!     let keypair = Keypair::generate()?;
//!
//!     // Sign message
//!     let message = b"Hello, post-quantum world!";
//!     let signature = sign(message, &keypair.secret_key)?;
//!
//!     // Verify signature
//!     let is_valid = verify(&signature, message, &keypair.public_key)?;
//!     assert!(is_valid);
//!     Ok(())
//! }
//! ```
//!
//! For more, see the README and examples directory.

use std::os::raw::{c_int, c_uchar};

/// ML-DSA-44 algorithm constants
pub mod constants {
    pub const PUBLIC_KEY_BYTES: usize = 1312;
    pub const SECRET_KEY_BYTES: usize = 2560;
    pub const SIGNATURE_BYTES: usize = 2420;
    pub const SEED_BYTES: usize = 32;
}

/// Error types for ML-DSA-44 operations
#[derive(Debug, Clone, PartialEq)]
pub enum MlDsaError {
    KeyGeneration,
    Signing,
    Verification,
    InvalidSignature,
    InvalidInput,
}

impl std::fmt::Display for MlDsaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MlDsaError::KeyGeneration => write!(f, "Key generation failed"),
            MlDsaError::Signing => write!(f, "Signing failed"),
            MlDsaError::Verification => write!(f, "Verification failed"),
            MlDsaError::InvalidSignature => write!(f, "Invalid signature"),
            MlDsaError::InvalidInput => write!(f, "Invalid input"),
        }
    }
}

impl std::error::Error for MlDsaError {}

pub type Result<T> = std::result::Result<T, MlDsaError>;

/// Public key (1312 bytes)
#[derive(Clone)]
pub struct PublicKey(pub [u8; constants::PUBLIC_KEY_BYTES]);

/// Secret key (2560 bytes)
#[derive(Clone)]
pub struct SecretKey(pub [u8; constants::SECRET_KEY_BYTES]);

/// Digital signature (up to 2420 bytes)
#[derive(Clone)]
pub struct Signature {
    pub data: Vec<u8>,
}

/// Keypair containing public and secret keys
#[derive(Clone)]
pub struct Keypair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

// FFI declarations
extern "C" {
    fn PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(
        pk: *mut c_uchar,
        sk: *mut c_uchar,
    ) -> c_int;

    fn PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair_from_fseed(
        pk: *mut c_uchar,
        sk: *mut c_uchar,
        seed: *const c_uchar,
    ) -> c_int;

    fn PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(
        sig: *mut c_uchar,
        siglen: *mut libc::size_t,
        m: *const c_uchar,
        mlen: libc::size_t,
        sk: *const c_uchar,
    ) -> c_int;

    fn PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature_ctx(
        sig: *mut c_uchar,
        siglen: *mut libc::size_t,
        m: *const c_uchar,
        mlen: libc::size_t,
        ctx: *const c_uchar,
        ctxlen: libc::size_t,
        sk: *const c_uchar,
    ) -> c_int;

    fn PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(
        sig: *const c_uchar,
        siglen: libc::size_t,
        m: *const c_uchar,
        mlen: libc::size_t,
        pk: *const c_uchar,
    ) -> c_int;

    fn PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify_ctx(
        sig: *const c_uchar,
        siglen: libc::size_t,
        m: *const c_uchar,
        mlen: libc::size_t,
        ctx: *const c_uchar,
        ctxlen: libc::size_t,
        pk: *const c_uchar,
    ) -> c_int;
}

impl Keypair {
    /// Generate a new keypair using system randomness
    pub fn generate() -> Result<Self> {
        let mut pk = [0u8; constants::PUBLIC_KEY_BYTES];
        let mut sk = [0u8; constants::SECRET_KEY_BYTES];

        let result = unsafe {
            PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
        };

        if result != 0 {
            return Err(MlDsaError::KeyGeneration);
        }

        Ok(Keypair {
            public_key: PublicKey(pk),
            secret_key: SecretKey(sk),
        })
    }

    /// Generate keypair from a 32-byte seed (deterministic)
    pub fn from_seed(seed: &[u8; constants::SEED_BYTES]) -> Result<Self> {
        let mut pk = [0u8; constants::PUBLIC_KEY_BYTES];
        let mut sk = [0u8; constants::SECRET_KEY_BYTES];

        let result = unsafe {
            PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair_from_fseed(
                pk.as_mut_ptr(),
                sk.as_mut_ptr(),
                seed.as_ptr(),
            )
        };

        if result != 0 {
            return Err(MlDsaError::KeyGeneration);
        }

        Ok(Keypair {
            public_key: PublicKey(pk),
            secret_key: SecretKey(sk),
        })
    }
}

/// Sign a message with the secret key
pub fn sign(message: &[u8], secret_key: &SecretKey) -> Result<Signature> {
    let mut sig = vec![0u8; constants::SIGNATURE_BYTES];
    let mut siglen = constants::SIGNATURE_BYTES;

    let result = unsafe {
        PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(
            sig.as_mut_ptr(),
            &mut siglen,
            message.as_ptr(),
            message.len(),
            secret_key.0.as_ptr(),
        )
    };

    if result != 0 {
        return Err(MlDsaError::Signing);
    }

    sig.truncate(siglen);
    Ok(Signature { data: sig })
}

/// Sign a message with context data
pub fn sign_with_context(
    message: &[u8],
    context: &[u8],
    secret_key: &SecretKey,
) -> Result<Signature> {
    let mut sig = vec![0u8; constants::SIGNATURE_BYTES];
    let mut siglen = constants::SIGNATURE_BYTES;

    let result = unsafe {
        PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature_ctx(
            sig.as_mut_ptr(),
            &mut siglen,
            message.as_ptr(),
            message.len(),
            context.as_ptr(),
            context.len(),
            secret_key.0.as_ptr(),
        )
    };

    if result != 0 {
        return Err(MlDsaError::Signing);
    }

    sig.truncate(siglen);
    Ok(Signature { data: sig })
}

/// Verify a signature
pub fn verify(signature: &Signature, message: &[u8], public_key: &PublicKey) -> Result<bool> {
    let result = unsafe {
        PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(
            signature.data.as_ptr(),
            signature.data.len(),
            message.as_ptr(),
            message.len(),
            public_key.0.as_ptr(),
        )
    };

    Ok(result == 0)
}

/// Verify a signature with context data
pub fn verify_with_context(
    signature: &Signature,
    message: &[u8],
    context: &[u8],
    public_key: &PublicKey,
) -> Result<bool> {
    let result = unsafe {
        PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify_ctx(
            signature.data.as_ptr(),
            signature.data.len(),
            message.as_ptr(),
            message.len(),
            context.as_ptr(),
            context.len(),
            public_key.0.as_ptr(),
        )
    };

    Ok(result == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = Keypair::generate().unwrap();
        assert_eq!(keypair.public_key.0.len(), constants::PUBLIC_KEY_BYTES);
        assert_eq!(keypair.secret_key.0.len(), constants::SECRET_KEY_BYTES);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = Keypair::generate().unwrap();
        let message = b"Hello, ML-DSA-44!";
        
        let signature = sign(message, &keypair.secret_key).unwrap();
        let is_valid = verify(&signature, message, &keypair.public_key).unwrap();
        
        assert!(is_valid);
    }

    #[test]
    fn test_sign_and_verify_with_context() {
        let keypair = Keypair::generate().unwrap();
        let message = b"Hello, world!";
        let context = b"test context";
        
        let signature = sign_with_context(message, context, &keypair.secret_key).unwrap();
        let is_valid = verify_with_context(&signature, message, context, &keypair.public_key).unwrap();
        
        assert!(is_valid);
    }

    #[test]
    fn test_deterministic_keygen() {
        let seed = [42u8; constants::SEED_BYTES];
        let keypair1 = Keypair::from_seed(&seed).unwrap();
        let keypair2 = Keypair::from_seed(&seed).unwrap();
        
        assert_eq!(keypair1.public_key.0, keypair2.public_key.0);
        assert_eq!(keypair1.secret_key.0, keypair2.secret_key.0);
    }

    #[test]
    fn test_deterministic_keypair() {
        let seed = [42u8; 32];
        let keypair = Keypair::from_seed(&seed).expect("Keygen failed");
        // Optionally: compare to known KAT vectors here
        assert_eq!(keypair.public_key.0.len(), 1312);
        assert_eq!(keypair.secret_key.0.len(), 2560);
    }
}

#[cfg(target_os = "windows")]
#[link(name = "advapi32")]
extern "system" {}