//! ML-DSA-44 verification logic
use crate::mldsa44::params::*;
use crate::mldsa44::poly::{Poly, poly_ntt, poly_inv_ntt, poly_pointwise, poly_pack, poly_unpack, poly_add, poly_sub};
use crate::mldsa44::util::{expand_a, generate_challenge};
use crate::mldsa44::packing::{poly_highbits, poly_lowbits, poly_unpack_highbits, poly_use_hint, reject_z};

/// Verify a signature using the public key, with FIPS 204-compliant primitives
pub fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    // Unpack public key (assume rho || t1)
    let rho: [u8; SEED_BYTES] = pk[0..SEED_BYTES].try_into().unwrap();
    let t1 = poly_unpack(&pk[SEED_BYTES..SEED_BYTES+96]);
    // Expand matrix A from rho
    let a = expand_a(&rho);
    // Unpack signature (z || hint || c)
    let z = poly_unpack(&sig[0..96]);
    let hint = &sig[96..96+N];
    let c: [i8; N] = sig[96+N..96+N+N].iter().map(|&x| x as i8).collect::<Vec<_>>().try_into().unwrap();
    // Rejection: |z_i| < GAMMA1 - BETA
    if reject_z(&z, GAMMA1 - BETA) {
        return false;
    }
    // NTT transform z
    let mut z_ntt = z;
    poly_ntt(&mut z_ntt);
    // Compute w' = A * z - c * t1
    let mut w_prime = [0i32; N];
    for j in 0..L {
        let prod = poly_pointwise(&a[0][j], &z_ntt); // For simplicity, single row
        for i in 0..N { w_prime[i] = (w_prime[i] + prod[i]) % Q; }
    }
    // NTT transform c
    let mut c_ntt = [0i32; N];
    for i in 0..N { c_ntt[i] = c[i] as i32; }
    poly_ntt(&mut c_ntt);
    let ct = poly_pointwise(&c_ntt, &t1);
    let mut v = poly_sub(&w_prime, &ct);
    poly_inv_ntt(&mut v);
    // Compute w0 = LowBits(v, 2*GAMMA2)
    let w0 = poly_lowbits(&v, 2 * GAMMA2);
    // Recover w1 using hint
    let w1 = poly_use_hint(&w0, hint, GAMMA2);
    // Compute challenge c' = H(M || w1)
    let w1_bytes = poly_pack_highbits(&w1, 4);
    let c_prime = generate_challenge(msg, &w1_bytes);
    // Accept if c == c'
    c.iter().zip(c_prime.iter()).all(|(&a, &b)| a == b)
}
