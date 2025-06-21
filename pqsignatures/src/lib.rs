//! pqsignatures: Production-grade, secure, constant-time Rust post-quantum signature schemes
//!
//! - Dilithium2, Falcon512, ML-DSA-44
//! - Secure key handling (zeroize)
//! - Hybrid signature support
//! - Test vectors and fuzzing
//! - Idiomatic error handling and documentation

pub mod error;
pub mod hybrid;
pub mod traits;
pub mod dilithium2;
pub mod falcon512;
pub mod mldsa44;

// Re-exports
pub use error::*;
pub use hybrid::*;
pub use traits::*;
pub use dilithium2::*;
pub use falcon512::*;
pub use mldsa44::*;
