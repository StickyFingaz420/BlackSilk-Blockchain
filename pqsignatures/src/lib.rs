//! pqsignatures: Production-grade, secure, constant-time Rust post-quantum signature schemes
//!
//! - Dilithium2, Falcon512
//! - Secure key handling (zeroize)
//! - Test vectors and fuzzing
//! - Idiomatic error handling and documentation

pub mod error;
pub mod traits;
pub mod dilithium2;
pub mod falcon512;

// Re-exports
pub use error::*;
pub use traits::*;
pub use dilithium2::*;
pub use falcon512::*;
