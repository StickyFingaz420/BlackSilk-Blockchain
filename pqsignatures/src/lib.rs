//! pqsignatures: Production-grade, secure, constant-time Rust post-quantum signature schemes
//!
//! # Supported Algorithms
//! - Dilithium2 (pure Rust, via crystals-dilithium)
//! - Falcon512 (pure Rust, via falcon-rust)
//!
//! # Features
//! - Secure key handling (zeroize)
//! - Property-based and negative testing
//! - Idiomatic error handling
//! - Serialization/deserialization helpers
//!
//! # Quick Start
//! ```rust
//! use pqsignatures::{Dilithium2, Falcon512, PQSignatureScheme};
//! // Dilithium2
//! let (pk, sk) = Dilithium2::keypair();
//! let msg = b"hello";
//! let sig = Dilithium2::sign(&sk, msg);
//! assert!(Dilithium2::verify(&pk, msg, &sig));
//! // Falcon512
//! let (pk, sk) = Falcon512::keypair();
//! let sig = Falcon512::sign(&sk, msg);
//! assert!(Falcon512::verify(&pk, msg, &sig));
//! ```
//!
//! # Integration Example
//! To use in another crate (e.g., wallet):
//! ```rust
//! use pqsignatures::{Dilithium2, PQSignatureScheme};
//! // Generate keys and sign a transaction
//! let (pk, sk) = Dilithium2::keypair();
//! let tx_bytes = b"tx data";
//! let sig = Dilithium2::sign(&sk, tx_bytes);
//! // Verify signature in node
//! assert!(Dilithium2::verify(&pk, tx_bytes, &sig));
//! ```
//!
//! # Test Suite
//! - Run `cargo test -p pqsignatures` for all positive, negative, and fuzz tests.
//! - Falcon512 fuzzing is limited for performance reasons.
//!
//! # Security Notes
//! - All secret keys are zeroized on drop.
//! - All operations are intended to be constant-time (pending upstream implementation).

pub mod error;
pub mod traits;
pub mod dilithium2;
pub mod falcon512;

// Re-exports
pub use error::*;
pub use traits::*;
pub use dilithium2::*;
pub use falcon512::*;
