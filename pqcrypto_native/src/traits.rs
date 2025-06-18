//! Core signature traits and types for PQ signature library
//!
//! # Example: Using a signature scheme
//!
//! ```rust
//! use pqcrypto_native::algorithms::dilithium::Dilithium2;
//! use pqcrypto_native::traits::SignatureScheme;
//!
//! let seed = b"example-seed";
//! let (pk, sk) = Dilithium2::keypair_from_seed(seed).unwrap();
//! let msg = b"hello";
//! let sig = Dilithium2::sign(&sk, msg).unwrap();
//! assert!(Dilithium2::verify(&pk, msg, &sig).is_ok());
//! ```

/// Opaque error type for signature operations
///
/// This error type is intentionally opaque to avoid leaking side-channel information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureError {
    /// The key is invalid or malformed
    InvalidKey,
    /// The signature is invalid or malformed
    InvalidSignature,
    /// Signature verification failed
    VerificationFailed,
    /// Other error (e.g., bad seed length)
    Other,
}

use core::ops::Deref;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use alloc::vec;
use alloc::vec::Vec;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::string::ToString;

/// Trait for post-quantum signature schemes
///
/// Implement this trait for each algorithm. All operations are deterministic and constant-time where possible.
///
/// Associated types are type-safe wrappers for public key, secret key, and signature.
pub trait SignatureScheme {
    type PublicKey: AsRef<[u8]> + ConstantTimeEq + Clone + core::fmt::Debug;
    type SecretKey: AsRef<[u8]> + Zeroize + Clone + core::fmt::Debug;
    type Signature: AsRef<[u8]> + ConstantTimeEq + Clone + core::fmt::Debug;

    /// Deterministic keypair generation from a seed
    fn keypair_from_seed(seed: &[u8]) -> Result<(Self::PublicKey, Self::SecretKey), SignatureError>;
    /// Sign a message
    fn sign(sk: &Self::SecretKey, msg: &[u8]) -> Result<Self::Signature, SignatureError>;
    /// Verify a signature
    fn verify(pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> Result<(), SignatureError>;
}

/// Type-safe wrapper for public keys
///
/// Implements constant-time equality.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey<const N: usize>(pub [u8; N]);
impl<const N: usize> AsRef<[u8]> for PublicKey<N> {
    fn as_ref(&self) -> &[u8] { &self.0 }
}
impl<const N: usize> Deref for PublicKey<N> {
    type Target = [u8; N];
    fn deref(&self) -> &<Self as Deref>::Target { &self.0 }
}
impl<const N: usize> ConstantTimeEq for PublicKey<N> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

/// Type-safe wrapper for secret keys (zeroizes on drop)
///
/// Implements zeroize on drop for secure memory handling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretKey<const N: usize>(pub [u8; N]);
impl<const N: usize> AsRef<[u8]> for SecretKey<N> {
    fn as_ref(&self) -> &[u8] { &self.0 }
}
impl<const N: usize> Deref for SecretKey<N> {
    type Target = [u8; N];
    fn deref(&self) -> &<Self as Deref>::Target { &self.0 }
}
impl<const N: usize> Zeroize for SecretKey<N> {
    fn zeroize(&mut self) { self.0.zeroize(); }
}
impl<const N: usize> Drop for SecretKey<N> {
    fn drop(&mut self) { self.zeroize(); }
}

/// Type-safe wrapper for signatures
///
/// Implements constant-time equality.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature<const N: usize>(pub [u8; N]);
impl<const N: usize> AsRef<[u8]> for Signature<N> {
    fn as_ref(&self) -> &[u8] { &self.0 }
}
impl<const N: usize> Deref for Signature<N> {
    type Target = [u8; N];
    fn deref(&self) -> &<Self as Deref>::Target { &self.0 }
}
impl<const N: usize> ConstantTimeEq for Signature<N> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

/// Type-safe wrapper for variable-length signatures
///
/// Implements constant-time equality for equal-length slices.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureVec(pub Vec<u8>);
impl AsRef<[u8]> for SignatureVec {
    fn as_ref(&self) -> &[u8] { &self.0 }
}
impl ConstantTimeEq for SignatureVec {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        // Constant-time comparison for equal-length slices, false otherwise
        if self.0.len() != other.0.len() {
            subtle::Choice::from(0)
        } else {
            self.0.ct_eq(&other.0)
        }
    }
}
