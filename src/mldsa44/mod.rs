//! ML-DSA-44 public API (pure Rust)
//! Implements NIST FIPS 204 ML-DSA-44: keygen, sign, verify

pub mod params;
pub mod poly;
pub mod packing;
pub mod random;
pub mod hash;
pub mod sign;
pub mod verify;
pub mod keygen;
pub mod util;

use crate::mldsa44::keygen::keygen;
use crate::mldsa44::sign::sign;
use crate::mldsa44::verify::verify;

/// Generate a keypair from a 32-byte seed
pub fn keygen_api(seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    keygen(seed)
}

/// Sign a message with a secret key
pub fn sign_api(sk: &[u8], msg: &[u8]) -> Vec<u8> {
    sign(sk, msg)
}

/// Verify a signature
pub fn verify_api(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    verify(pk, msg, sig)
}
