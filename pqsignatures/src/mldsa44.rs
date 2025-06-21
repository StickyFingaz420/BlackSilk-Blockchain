// ML-DSA-44: Pure Rust implementation using ml-dsa crate
use zeroize::Zeroize;
use crate::traits::PQSignatureScheme;
use ml_dsa::{PublicKey, SecretKey, Signature};

pub struct MLDSA44PublicKey(pub Vec<u8>);
pub struct MLDSA44SecretKey(pub Vec<u8>);
pub struct MLDSA44Signature(pub Vec<u8>);

impl Zeroize for MLDSA44SecretKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

// Remove MLDSA44 and all ML-DSA-44 support for workspace compatibility.

// === Porting Plan ===
// 1. Port ML-DSA-44 parameter constants and core math (hashing, tree, etc.)
// 2. Port keygen, sign, and verify routines from PQClean C to idiomatic Rust
// 3. Ensure constant-time, zeroize, and secure memory handling
// 4. Add test vectors and property-based tests
// 5. Document all security caveats and audit requirements
