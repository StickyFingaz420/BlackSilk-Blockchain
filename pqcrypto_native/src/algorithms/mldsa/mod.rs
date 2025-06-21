//! Pure Rust implementation of ML-DSA-44 (FIPS 204, final version of Dilithium)
//!
//! Re-export submodules for ML-DSA
pub mod mldsa_ntt;
// Public keypair() for ML-DSA-44 (stub, implement actual logic as needed)
pub fn keypair() -> (Vec<u8>, Vec<u8>) {
    // TODO: Replace with actual ML-DSA-44 keypair generation logic
    // For now, return empty vectors or call the real function if available
    (vec![], vec![])
}

// Public verify() for ML-DSA-44
pub fn verify(msg: &[u8], sig: &[u8], pk: &[u8]) -> Result<(), ()> {
    // You may need to adapt this to your actual types
    // This is a placeholder for the real verification logic
    // Example:
    // let pk = ...; let sig = ...; // convert to correct types
    // MLDSA44::verify(&pk, msg, &sig).map_err(|_| ())
    unimplemented!("Implement ML-DSA-44 signature verification here")
}

use alloc::vec::Vec;
