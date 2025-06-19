//! ML-DSA-44 key generation logic
use crate::mldsa44::params::*;
use crate::mldsa44::poly::{Poly, poly_sample_eta, poly_ntt, poly_inv_ntt, poly_pointwise, poly_pack, poly_add};

/// Generate a keypair (public key, secret key) using NTT-based primitives
pub fn keygen(seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // Sample secret polynomials s1, s2
    let mut s1 = poly_sample_eta(seed, 0);
    let mut s2 = poly_sample_eta(seed, 1);
    // NTT transform s1 for later use
    poly_ntt(&mut s1);
    // Sample matrix A (for simplicity, use seed and nonce)
    let mut a = poly_sample_eta(seed, 2); // In real impl, expand matrix A properly
    poly_ntt(&mut a);
    // Compute t = A * s1 + s2 (all in NTT domain)
    let t_ntt = poly_pointwise(&a, &s1);
    let mut t = t_ntt;
    poly_inv_ntt(&mut t);
    let t = poly_add(&t, &s2);
    // Pack public and secret keys
    let pk = poly_pack(&t);
    let sk = [poly_pack(&s1), poly_pack(&s2)].concat();
    (pk, sk)
}
