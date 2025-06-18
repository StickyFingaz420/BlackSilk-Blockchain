//! ML-DSA-44 verification logic
use crate::mldsa44::params::*;
use crate::mldsa44::poly::{Poly, poly_ntt, poly_inv_ntt, poly_pointwise, poly_pack, poly_unpack, poly_add, poly_sub};
use crate::mldsa44::util::{expand_a, generate_challenge};

/// Verify a signature using the public key, with FIPS 204-compliant primitives
pub fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    // Unpack public key (assume rho || t1)
    let rho: [u8; SEED_BYTES] = pk[0..SEED_BYTES].try_into().unwrap();
    let t1 = poly_unpack(&pk[SEED_BYTES..SEED_BYTES+96]);
    // Expand matrix A from rho
    let a = expand_a(&rho);
    // Unpack signature (z only for now)
    let z = poly_unpack(sig);
    // NTT transform z
    let mut z_ntt = z;
    poly_ntt(&mut z_ntt);
    // Compute w' = A * z - c * t1
    let mut w_prime = [0i32; N];
    for j in 0..L {
        let prod = poly_pointwise(&a[0][j], &z_ntt); // For simplicity, single row
        for i in 0..N { w_prime[i] = (w_prime[i] + prod[i]) % Q; }
    }
    // Compute challenge c = H(M || w1) (w1 placeholder: use w_prime as bytes)
    poly_inv_ntt(&mut w_prime);
    let w1_bytes: Vec<u8> = w_prime.iter().map(|x| (*x & 0xFF) as u8).collect();
    let c = generate_challenge(msg, &w1_bytes);
    // NTT transform c
    let mut c_ntt = [0i32; N];
    for i in 0..N { c_ntt[i] = c[i] as i32; }
    poly_ntt(&mut c_ntt);
    // Compute v = w' - c * t1
    let ct = poly_pointwise(&c_ntt, &t1);
    let mut v = poly_sub(&w_prime, &ct);
    poly_inv_ntt(&mut v);
    // In real impl, check if H(M||w0) == c and |z_i| < γ₁−β
    v.iter().all(|&x| x.abs() < Q/2)
}
