// ML-DSA-44 Rust API implementation stub
// Place this file at: <workspace-root>/src/mldsa44.rs
// Replace all stubs with your real ML-DSA-44 implementation.

pub fn keygen(seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // TODO: Implement ML-DSA-44 key generation using the provided seed
    // Return (public_key, secret_key)
    unimplemented!("Implement ML-DSA-44 keygen");
}

pub fn sign(sk: &[u8], msg: &[u8]) -> Vec<u8> {
    // TODO: Implement ML-DSA-44 signing using the secret key and message
    // Return signature
    unimplemented!("Implement ML-DSA-44 sign");
}

pub fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    // TODO: Implement ML-DSA-44 signature verification
    // Return true if valid, false otherwise
    unimplemented!("Implement ML-DSA-44 verify");
}
