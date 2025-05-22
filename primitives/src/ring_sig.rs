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
    println!("[DEBUG] priv_key: {:x?}", priv_key);
    println!("[DEBUG] ring: {:?}", ring);
    println!("[DEBUG] msg: {:x?}", msg);
    // Generate random scalars for all except real_index
    let mut r_vec = vec![Scalar::from_bytes_mod_order([0u8; 32]); n];
    for i in 0..n {
        if i != real_index {
            let mut r_bytes = [0u8; 32];
            csprng.fill_bytes(&mut r_bytes);
            r_vec[i] = Scalar::from_bytes_mod_order(r_bytes);
        }
    }
    // Generate random k for real_index (used to compute r at the end)
    let mut k_bytes = [0u8; 32];
    csprng.fill_bytes(&mut k_bytes);
    let k = Scalar::from_bytes_mod_order(k_bytes);
    // Compute the challenge chain, starting at (real_index + 1) % n
    let mut c_vec = vec![Scalar::from_bytes_mod_order([0u8; 32]); n];
    let mut hasher = Sha256::new();
    hasher.update(msg);
    let mut c_bytes = [0u8; 32];
    c_bytes.copy_from_slice(&hasher.finalize_reset()[..32]);
    let mut c = Scalar::from_bytes_mod_order(c_bytes);
    let start = (real_index + 1) % n;
    c_vec[start] = c;
    // Forward loop: fill c_vec in ring order
    for i in 0..n {
        let idx = (start + i) % n;
        let l = if idx == real_index {
            ED25519_BASEPOINT_POINT * k + pubkeys[idx] * c_vec[idx]
        } else {
            ED25519_BASEPOINT_POINT * r_vec[idx] + pubkeys[idx] * c_vec[idx]
        };
        hasher.update(l.compress().as_bytes());
        hasher.update(msg);
        let mut c_bytes = [0u8; 32];
        c_bytes.copy_from_slice(&hasher.finalize_reset()[..32]);
        let next_idx = (idx + 1) % n;
        if next_idx != start {
            c_vec[next_idx] = Scalar::from_bytes_mod_order(c_bytes);
        } else {
            // When we close the ring, c_vec[start] must match the computed value
            // This is the check the verifier will do
            break;
        }
        c = Scalar::from_bytes_mod_order(c_bytes);
    }
    // Compute r for real_index: r = k - sk * c_vec[real_index]
    r_vec[real_index] = k - sk * c_vec[real_index];
    // Rotate c_vec and r_vec so that index 0 is the verifier's starting point
    let mut sig = Vec::with_capacity(n * 64);
    for i in 0..n {
        let idx = (i + start) % n;
        sig.extend_from_slice(&c_vec[idx].to_bytes());
        sig.extend_from_slice(&r_vec[idx].to_bytes());
        println!("[DEBUG] sig c[{}]: {:?}", i, c_vec[idx]);
        println!("[DEBUG] sig r[{}]: {:?}", i, r_vec[idx]);
    }
    sig
}
