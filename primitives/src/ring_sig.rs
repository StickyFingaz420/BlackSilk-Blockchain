//! Canonical CryptoNote-style ring signature generation and verification for BlackSilk

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use sha2::{Sha256, Digest};

/// Generate a canonical CryptoNote-style ring signature
///
/// # Arguments
/// * `msg` - The message to sign.
/// * `ring` - The ring of public keys.
/// * `priv_key` - The signer's private key.
/// * `real_index` - The index of the real signer in the ring.
///
/// # Returns
/// A vector containing the serialized ring signature.
///
/// # Security Warning
/// Only use with secure, random keys and validated public keys. Do not expose private keys.
pub fn generate_ring_signature(msg: &[u8], ring: &[[u8; 32]], priv_key: &[u8], real_index: usize) -> Vec<u8> {
    
    use rand::RngCore;
    let n = ring.len();
    assert!(n > 0 && real_index < n);
    let mut csprng = rand::thread_rng();
    let sk = Scalar::from_bytes_mod_order(priv_key[..32].try_into().unwrap());
    let mut pubkeys = Vec::with_capacity(n);
    for pk_bytes in ring {
        let pt = CompressedEdwardsY(*pk_bytes).decompress().expect("Invalid public key");
        pubkeys.push(pt);
    }
    let mut c = vec![Scalar::from(0u64); n];
    let mut r = vec![Scalar::from(0u64); n];
    // Step 1: generate random alpha for real_index, random r for all except real_index
    let mut alpha_bytes = [0u8; 32];
    csprng.fill_bytes(&mut alpha_bytes);
    let alpha = Scalar::from_bytes_mod_order(alpha_bytes);
    for i in 0..n {
        if i != real_index {
            let mut r_bytes = [0u8; 32];
            csprng.fill_bytes(&mut r_bytes);
            r[i] = Scalar::from_bytes_mod_order(r_bytes);
        }
    }
    // Step 2: compute the first challenge after the real index
    let mut hasher = Sha256::new();
    let mut idx = (real_index + 1) % n;
    let l = &ED25519_BASEPOINT_POINT * &alpha;
    hasher.update(l.compress().as_bytes());
    hasher.update(msg);
    let mut c_bytes = [0u8; 32];
    c_bytes.copy_from_slice(&hasher.finalize_reset()[..32]);
    c[idx] = Scalar::from_bytes_mod_order(c_bytes);
    // Step 3: propagate challenges and commitments around the ring
    for _ in 0..n-1 {
        let l = &ED25519_BASEPOINT_POINT * &r[idx] + pubkeys[idx] * c[idx];
        hasher.update(l.compress().as_bytes());
        hasher.update(msg);
        let mut c_bytes = [0u8; 32];
        c_bytes.copy_from_slice(&hasher.finalize_reset()[..32]);
        let next_idx = (idx + 1) % n;
        c[next_idx] = Scalar::from_bytes_mod_order(c_bytes);
        idx = next_idx;
    }
    // Step 4: compute r for the real index
    r[real_index] = alpha - sk * c[real_index];
    // Step 5: output signature as (c_0, r_0, ..., c_{n-1}, r_{n-1})
    let mut sig = Vec::with_capacity(n * 64);
    for i in 0..n {
        sig.extend_from_slice(&c[i].to_bytes());
        sig.extend_from_slice(&r[i].to_bytes());
    }
    sig
}

/// Verify a canonical CryptoNote-style ring signature
///
/// # Arguments
/// * `msg` - The signed message.
/// * `ring` - The ring of public keys.
/// * `sig` - The serialized ring signature.
///
/// # Returns
/// `true` if the signature is valid, `false` otherwise.
///
/// # Security Warning
/// Only use with validated public keys and signatures.
pub fn verify_ring_signature(msg: &[u8], ring: &[[u8; 32]], sig: &[u8]) -> bool {
    
    let n = ring.len();
    if sig.len() != n * 64 {
        return false;
    }
    let mut pubkeys = Vec::with_capacity(n);
    for pk_bytes in ring {
        if let Some(pt) = CompressedEdwardsY(*pk_bytes).decompress() {
            pubkeys.push(pt);
        } else {
            return false;
        }
    }
    let mut c = Vec::with_capacity(n);
    let mut r = Vec::with_capacity(n);
    for i in 0..n {
        let c_i = Scalar::from_bytes_mod_order(sig[i * 64..i * 64 + 32].try_into().unwrap());
        let r_i = Scalar::from_bytes_mod_order(sig[i * 64 + 32..(i + 1) * 64].try_into().unwrap());
        c.push(c_i);
        r.push(r_i);
    }
    let mut hasher = Sha256::new();
    let mut c_check = c[0];
    for i in 0..n {
        let l = &ED25519_BASEPOINT_POINT * &r[i] + pubkeys[i] * c_check;
        hasher.update(l.compress().as_bytes());
        hasher.update(msg);
        let mut c_bytes = [0u8; 32];
        c_bytes.copy_from_slice(&hasher.finalize_reset()[..32]);
        c_check = Scalar::from_bytes_mod_order(c_bytes);
        if i < n - 1 && c_check != c[i + 1] {
            return false;
        }
    }
    // The final challenge must match c_0
    c_check == c[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    
    
    use rand::RngCore;

    #[test]
    fn test_ring_signature_verification() {
        
        use curve25519_dalek::scalar::Scalar;
        use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
        use rand::rngs::OsRng;
        use rand::RngCore;

        let msg = b"Test message";
        let mut rng = OsRng;
        let mut priv_keys = Vec::new();
        let mut ring = Vec::new();
        for _ in 0..3 {
            let mut sk_bytes = [0u8; 32];
            rng.fill_bytes(&mut sk_bytes);
            let sk = Scalar::from_bytes_mod_order(sk_bytes);
            let pk = (&ED25519_BASEPOINT_POINT * &sk).compress().to_bytes();
            priv_keys.push(sk_bytes);
            ring.push(pk);
        }
        let real_index = 1;
        let sig = generate_ring_signature(msg, &ring, &priv_keys[real_index], real_index);
        assert!(verify_ring_signature(msg, &ring, &sig));

        // Tamper with the signature
        let mut tampered_sig = sig.clone();
        tampered_sig[0] ^= 1;
        assert!(!verify_ring_signature(msg, &ring, &tampered_sig));
    }

    #[test]
    fn test_verify_ring_signature_valid() {
        
        use curve25519_dalek::scalar::Scalar;
        use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
        use rand::rngs::OsRng;
        use rand::RngCore;

        let msg = b"Test message";
        let mut rng = OsRng;
        let mut priv_keys = Vec::new();
        let mut ring = Vec::new();
        for _ in 0..3 {
            let mut sk_bytes = [0u8; 32];
            rng.fill_bytes(&mut sk_bytes);
            let sk = Scalar::from_bytes_mod_order(sk_bytes);
            let pk = (&ED25519_BASEPOINT_POINT * &sk).compress().to_bytes();
            priv_keys.push(sk_bytes);
            ring.push(pk);
        }
        let real_index = 0;
        let sig = generate_ring_signature(msg, &ring, &priv_keys[real_index], real_index);
        assert!(verify_ring_signature(msg, &ring, &sig));
    }

    #[test]
    fn test_verify_ring_signature_invalid() {
        
        use curve25519_dalek::scalar::Scalar;
        use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
        use rand::rngs::OsRng;
        use rand::RngCore;

        let msg = b"Test message";
        let mut rng = OsRng;
        let mut priv_keys = Vec::new();
        let mut ring = Vec::new();
        for _ in 0..3 {
            let mut sk_bytes = [0u8; 32];
            rng.fill_bytes(&mut sk_bytes);
            let sk = Scalar::from_bytes_mod_order(sk_bytes);
            let pk = (&ED25519_BASEPOINT_POINT * &sk).compress().to_bytes();
            priv_keys.push(sk_bytes);
            ring.push(pk);
        }
        // Generate a valid signature, then tamper with it
        let real_index = 0;
        let mut sig = generate_ring_signature(msg, &ring, &priv_keys[real_index], real_index);
        sig[0] ^= 0xFF; // Tamper with the signature
        assert!(!verify_ring_signature(msg, &ring, &sig));
    }

    #[test]
    fn test_debug_ring_signature() {
        
        use curve25519_dalek::scalar::Scalar;
        use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
        use rand::rngs::OsRng;
        use rand::RngCore;

        let msg = b"Debug message";
        let mut rng = OsRng;
        let mut priv_keys = Vec::new();
        let mut ring = Vec::new();
        for _ in 0..3 {
            let mut sk_bytes = [0u8; 32];
            rng.fill_bytes(&mut sk_bytes);
            let sk = Scalar::from_bytes_mod_order(sk_bytes);
            let pk = (&ED25519_BASEPOINT_POINT * &sk).compress().to_bytes();
            priv_keys.push(sk_bytes);
            ring.push(pk);
        }
        let real_index = 2;
        let sig = generate_ring_signature(msg, &ring, &priv_keys[real_index], real_index);
        assert!(verify_ring_signature(msg, &ring, &sig));
    }
}
