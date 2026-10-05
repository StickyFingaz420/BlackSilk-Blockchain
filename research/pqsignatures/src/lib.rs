//! pqsignatures: a parked research prototype (not built by the BlackSilk
//! workspace, not reviewed, used by no BlackSilk crate; AUDIT.md S7) wrapping
//! third-party post-quantum signature crates. No security property, constant
//! time included, is claimed or verified.
//!
//! # Supported Algorithms
//! - Dilithium2 (pure Rust, via crystals-dilithium)
//! - Falcon512 (pure Rust, via falcon-rust)
//!
//! # Features
//! - No key zeroization: the scheme types are the upstream crates' own
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
//! - Secret keys are not zeroized by this crate (the Dilithium2 and Falcon512
//!   key types are the upstream ones). `hybrid.rs` and `mldsa44.rs` are not
//!   modules of the crate (never compiled) and do not build as written.
//! - No constant-time property is claimed or verified (upstream crates, not reviewed).

pub mod error;
pub mod traits;
pub mod dilithium2;
pub mod falcon512;

// Re-exports
pub use error::*;
pub use traits::*;
pub use dilithium2::*;
pub use falcon512::*;
