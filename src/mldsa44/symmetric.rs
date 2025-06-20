//! SHAKE256 and SHAKE128 utilities for ML-DSA-44 (Dilithium2, FIPS 204)
//! Uses the `sha3` crate for XOF primitives.

use sha3::{Shake128, Shake256, digest::{Update, ExtendableOutput, XofReader}};

/// Expand a seed using SHAKE256 (output length in bytes)
pub fn shake256(seed: &[u8], outlen: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    let mut xof = hasher.finalize_xof();
    let mut out = vec![0u8; outlen];
    xof.read(&mut out);
    out
}

/// Expand a seed using SHAKE128 (output length in bytes)
pub fn shake128(seed: &[u8], outlen: usize) -> Vec<u8> {
    let mut hasher = Shake128::default();
    hasher.update(seed);
    let mut xof = hasher.finalize_xof();
    let mut out = vec![0u8; outlen];
    xof.read(&mut out);
    out
}
