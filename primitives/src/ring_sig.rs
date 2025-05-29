//! Canonical CryptoNote-style ring signature generation and verification for BlackSilk

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use rand::RngCore;
use sha2::{Sha256, Digest};

/// Generate a minimal ring signature (single key, demo only)
pub fn generate_ring_signature(msg: &[u8], ring: &[ [u8; 32] ], priv_key: &[u8], real_index: usize) -> Vec<u8> {
    let n = ring.len();
    assert!(n > 0 && real_index < n);
    if n == 1 {
        // Special case: single-member ring
        let mut csprng = rand::thread_rng();
        let sk = Scalar::from_bytes_mod_order(priv_key.try_into().unwrap());
        let mut k_bytes = [0u8; 32];
        csprng.fill_bytes(&mut k_bytes);
        let k = Scalar::from_bytes_mod_order(k_bytes);
        let l0 = ED25519_BASEPOINT_POINT * k;
        let mut hasher = Sha256::new();
        hasher.update(l0.compress().as_bytes());
        hasher.update(msg);
        let mut c_bytes = [0u8; 32];
        c_bytes.copy_from_slice(&hasher.finalize_reset()[..32]);
        let c = Scalar::from_bytes_mod_order(c_bytes);
        let r = k - sk * c;
        let mut sig = Vec::with_capacity(64);
        sig.extend_from_slice(&c.to_bytes());
        sig.extend_from_slice(&r.to_bytes());
        return sig;
    }
    // Rotate ring so real_index is at 0
    let mut ring_rot = vec![[0u8; 32]; n];
    for i in 0..n {
        ring_rot[i] = ring[(i + real_index) % n];
    }
    let mut pubkeys = Vec::with_capacity(n);
    for pk_bytes in &ring_rot {
        let pt = CompressedEdwardsY(*pk_bytes).decompress().unwrap();
        pubkeys.push(pt);
    }
    let mut csprng = rand::thread_rng();
    let sk = Scalar::from_bytes_mod_order(priv_key.try_into().unwrap());
    // Generate random scalars for all except 0 (real_index)
    let mut r_vec = vec![Scalar::from_bytes_mod_order([0u8; 32]); n];
    for i in 1..n {
        let mut r_bytes = [0u8; 32];
        csprng.fill_bytes(&mut r_bytes);
        r_vec[i] = Scalar::from_bytes_mod_order(r_bytes);
    }
    // Generate random k for real_index (index 0)
    let mut k_bytes = [0u8; 32];
    csprng.fill_bytes(&mut k_bytes);
    let k = Scalar::from_bytes_mod_order(k_bytes);
    // Compute c_0 = H(L_0, msg) where L_0 = k*G
    let mut hasher = Sha256::new();
    let l0 = ED25519_BASEPOINT_POINT * k;
    hasher.update(l0.compress().as_bytes());
    hasher.update(msg);
    let mut c_bytes = [0u8; 32];
    c_bytes.copy_from_slice(&hasher.finalize_reset()[..32]);
    let mut c_vec = vec![Scalar::from_bytes_mod_order([0u8; 32]); n];
    c_vec[1 % n] = Scalar::from_bytes_mod_order(c_bytes);
    // Forward loop: fill c_vec in ring order
    for i in 1..n {
        let l = ED25519_BASEPOINT_POINT * r_vec[i] + pubkeys[i] * c_vec[i];
        println!("[GEN] L_{}: {:?}", i, l.compress().to_bytes());
        hasher.update(l.compress().as_bytes());
        hasher.update(msg);
        let mut c_bytes = [0u8; 32];
        c_bytes.copy_from_slice(&hasher.finalize_reset()[..32]);
        c_vec[(i + 1) % n] = Scalar::from_bytes_mod_order(c_bytes);
        println!("[GEN] c_vec[{}]: {:?}", (i + 1) % n, c_vec[(i + 1) % n]);
    }
    // Compute r for real_index (index 0): r = k - sk * c_vec[0]
    r_vec[0] = k - sk * c_vec[0];
    // Serialize signature as (c_0, r_0), (c_1, r_1), ...
    let mut sig = Vec::with_capacity(n * 64);
    for i in 0..n {
        sig.extend_from_slice(&c_vec[i].to_bytes());
        sig.extend_from_slice(&r_vec[i].to_bytes());
    }
    // Rotate signature back so real_index is at the original position
    let mut sig_final = Vec::with_capacity(n * 64);
    for i in 0..n {
        let idx = (i + n - real_index) % n;
        println!("[GEN] sig[{}]: c={:?} r={:?}", i, c_vec[idx], r_vec[idx]);
        sig_final.extend_from_slice(&sig[idx * 64..(idx + 1) * 64]);
    }
    println!("[GEN] sig_final: {:x?}", sig_final);
    sig_final
}
