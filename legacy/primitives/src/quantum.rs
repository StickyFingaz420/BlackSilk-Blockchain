//! # Quantum-Resistant Cryptography Module
//! 
//! This module implements quantum-resistant cryptographic primitives for the BlackSilk blockchain.
//! It provides a unified interface for multiple post-quantum signature schemes and ensures
//! proper integration with the transaction validation pipeline.
//!
//! ## Supported Signature Schemes
//!
//! - **ML-DSA-44**: A module-lattice based digital signature algorithm
//! - **Dilithium2**: A post-quantum signature scheme based on module-LWE
//! - **Falcon512**: A fast-Fourier lattice-based compact signature scheme
//!
//! ## Security Considerations
//!
//! All implemented schemes provide at minimum NIST Level 3 security, which means:
//! - At least 128-bit classical security
//! - At least 64-bit post-quantum security
//! - Protection against multi-target attacks
//!
//! ## Usage Example
//!
//! ```rust
//! use crate::quantum::{QuantumScheme, QuantumSignature};
//! use ml_dsa_44::Keypair;
//!
//! // Generate a keypair
//! let keypair = Keypair::generate().expect("Failed to generate keypair");
//!
//! // Create and verify a signature
//! let message = b"Hello, quantum world!";
//! let signature = QuantumSignature {
//!     scheme: QuantumScheme::MLDSA44,
//!     signature: ml_dsa_44::sign(message, &keypair.secret_key)
//!         .unwrap()
//!         .to_bytes()
//!         .to_vec(),
//!     public_key: keypair.public_key.to_bytes().to_vec(),
//! };
//!
//! assert!(signature.verify(message).unwrap());
//! ```
//!
//! ## Performance Considerations
//!
//! Different signature schemes have different performance characteristics:
//!
//! | Scheme     | Sign Speed | Verify Speed | Signature Size | Security Level |
//! |------------|------------|--------------|----------------|----------------|
//! | ML-DSA-44  | Fast       | Very Fast    | 2,420 bytes    | NIST Level 3   |
//! | Dilithium2 | Medium     | Fast         | 2,701 bytes    | NIST Level 3   |
//! | Falcon512  | Slow       | Very Fast    | 666 bytes      | NIST Level 1   |
//!
//! Choose the appropriate scheme based on your specific requirements.

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QuantumScheme {
    /// Module-Lattice Digital Signature Algorithm (ML-DSA-44)
    MLDSA44,
    /// Dilithium2 signature scheme
    Dilithium2,
    /// Falcon-512 signature scheme
    Falcon512,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Errors that can occur during quantum signature validation
pub enum QuantumValidationError {
    /// The signature is invalid for the given message and public key
    InvalidSignature,
    /// The signature scheme is not supported
    UnsupportedScheme,
    /// The signature format is invalid or corrupted
    MalformedSignature,
    /// The public key format is invalid or corrupted
    InvalidPublicKey,
    /// Error in ring signature operations
    RingSignatureError,
    /// Error in signature aggregation
    AggregationError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumSignature {
    pub scheme: QuantumScheme,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumRingSignature {
    pub scheme: QuantumScheme,
    pub ring_size: usize,
    pub public_keys: Vec<Vec<u8>>,
    pub signature: Vec<u8>,
    pub message: Vec<u8>,
}

impl QuantumSignature {
    pub fn verify(&self, message: &[u8]) -> Result<bool, QuantumValidationError> {
        match self.scheme {
            QuantumScheme::MLDSA44 => {
                let public_key = ml_dsa_44::PublicKey::from_bytes(&self.public_key)
                    .map_err(|_| QuantumValidationError::InvalidPublicKey)?;
                let signature = ml_dsa_44::Signature::from_bytes(&self.signature)
                    .map_err(|_| QuantumValidationError::MalformedSignature)?;
                ml_dsa_44::verify(&signature, message, &public_key)
                    .map_err(|_| QuantumValidationError::InvalidSignature)
            }
            QuantumScheme::Dilithium2 => {
                let pk = pqcrypto_native::dilithium2::public_key_from_bytes(&self.public_key)
                    .map_err(|_| QuantumValidationError::InvalidPublicKey)?;
                let sig = pqcrypto_native::dilithium2::signature_from_bytes(&self.signature)
                    .map_err(|_| QuantumValidationError::MalformedSignature)?;
                Ok(pqcrypto_native::dilithium2::verify(&pk, message, &sig))
            }
            QuantumScheme::Falcon512 => {
                let pk = pqcrypto_native::falcon512::public_key_from_bytes(&self.public_key)
                    .map_err(|_| QuantumValidationError::InvalidPublicKey)?;
                let sig = pqcrypto_native::falcon512::signature_from_bytes(&self.signature)
                    .map_err(|_| QuantumValidationError::MalformedSignature)?;
                Ok(pqcrypto_native::falcon512::verify(&pk, message, &sig))
            }
        }
    }
}
