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
pub mod keypack;

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

#[cfg(test)]
mod kat_dump {
    use super::*;
    use hex;
    use crate::mldsa44::params::{PUBLIC_KEY_BYTES, SECRET_KEY_BYTES};
    #[test]
    fn dump_pk_sk_allzero_seed() {
        let seed = [0u8; 32];
        let (pk, sk) = keygen_api(&seed);
        println!("PK: {}", hex::encode(&pk));
        println!("SK: {}", hex::encode(&sk));
        // Optionally, assert length matches reference
        assert_eq!(pk.len(), PUBLIC_KEY_BYTES);
        assert_eq!(sk.len(), SECRET_KEY_BYTES);
    }
}
