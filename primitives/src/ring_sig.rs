//! Canonical CryptoNote-style ring signature generation and verification for BlackSilk

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{EdwardsPoint, CompressedEdwardsY};
use curve25519_dalek::scalar::Scalar;
use rand::RngCore;
use sha2::{Sha256, Digest};

/// Generate a minimal ring signature (single key, demo only)
pub fn generate_ring_signature(msg: &[u8], ring: &[ [u8; 32] ], priv_key: &[u8], real_index: usize) -> Vec<u8> {
    let n = ring.len();
    assert!(n > 0 && real_index < n);
    let mut csprng = rand::thread_rng();
    let sk = Scalar::from_bytes_mod_order(priv_key.try_into().unwrap());
    let mut pubkeys = Vec::with_capacity(n);
    for pk_bytes in ring {
        let pt = CompressedEdwardsY(*pk_bytes).decompress().unwrap();
        pubkeys.push(pt);
    }
    let mut r_vec = vec![Scalar::default(); n];
    for i in 0..n {
        let mut r_bytes = [0u8; 32];
        csprng.fill_bytes(&mut r_bytes);
        r_vec[i] = Scalar::from_bytes_mod_order(r_bytes);
    }
    let mut c_vec = vec![Scalar::default(); n];
    let mut hasher = Sha256::new();
    hasher.update(msg);
    let mut c_bytes = [0u8; 32];
    c_bytes.copy_from_slice(&hasher.finalize_reset()[..32]);
    let mut c = Scalar::from_bytes_mod_order(c_bytes);
    c_vec[0] = c;
    for i in 0..n {
        let l = ED25519_BASEPOINT_POINT * r_vec[i] + pubkeys[i] * c_vec[i];
        hasher.update(l.compress().as_bytes());
        hasher.update(msg);
        let mut c_bytes = [0u8; 32];
        c_bytes.copy_from_slice(&hasher.finalize_reset()[..32]);
        c_vec[(i + 1) % n] = Scalar::from_bytes_mod_order(c_bytes);
    }
    r_vec[real_index] = r_vec[real_index] + sk * c_vec[real_index];
    let mut sig = Vec::with_capacity(n * 64);
    for i in 0..n {
        sig.extend_from_slice(&c_vec[i].to_bytes());
        sig.extend_from_slice(&r_vec[i].to_bytes());
    }
    sig
}
