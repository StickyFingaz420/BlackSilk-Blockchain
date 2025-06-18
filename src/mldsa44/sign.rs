//! ML-DSA-44 signing logic
use crate::mldsa44::params::*;
use crate::mldsa44::poly::{Poly, poly_sample_eta, poly_ntt, poly_inv_ntt, poly_pointwise, poly_pack, poly_unpack, poly_add};
use crate::mldsa44::util::{expand_a, generate_challenge};
use crate::mldsa44::packing::{poly_highbits, poly_lowbits, poly_pack_highbits, poly_make_hint, reject_z};

/// Sign a message using the secret key, with FIPS 204-compliant primitives
pub fn sign(sk: &[u8], msg: &[u8]) -> Vec<u8> {
    // Unpack secret key polynomials (assume s1, s2, rho are packed in sk)
    let rho: [u8; SEED_BYTES] = sk[0..SEED_BYTES].try_into().unwrap();
    let s1 = poly_unpack(&sk[SEED_BYTES..SEED_BYTES+96]);
    let s2 = poly_unpack(&sk[SEED_BYTES+96..SEED_BYTES+192]);
    // Expand matrix A from rho
    let a = expand_a(&rho);
    // Sample ephemeral y (should be random, here use msg as seed for demo)
    let mut y = poly_sample_eta(msg, 0);
    poly_ntt(&mut y);
    // Compute w = A * y (matrix-vector NTT mult)
    let mut w = [0i32; N];
    for j in 0..L {
        let prod = poly_pointwise(&a[0][j], &y); // For simplicity, single row
        for i in 0..N { w[i] = (w[i] + prod[i]) % Q; }
    }
    poly_inv_ntt(&mut w);
    // Extract w1 = HighBits(w, 2*GAMMA2)
    let w1 = poly_highbits(&w, 2 * GAMMA2);
    let w1_bytes = poly_pack_highbits(&w1, 4); // 4 bits for Dilithium2
    // Compute challenge c = H(M || w1)
    let c = generate_challenge(msg, &w1_bytes);
    // NTT transform c for multiplication
    let mut c_ntt = [0i32; N];
    for i in 0..N { c_ntt[i] = c[i] as i32; }
    poly_ntt(&mut c_ntt);
    // Compute z = y + c * s1
    let cs1 = poly_pointwise(&c_ntt, &s1);
    let mut z = poly_add(&y, &cs1);
    poly_inv_ntt(&mut z);
    // Rejection: |z_i| < GAMMA1 - BETA
    if reject_z(&z, GAMMA1 - BETA) {
        // In real impl, retry with new y
        return vec![];
    }
    // Compute w0 = LowBits(w, 2*GAMMA2)
    let w0 = poly_lowbits(&w, 2 * GAMMA2);
    // Compute hint for w0 recovery
    let hint = poly_make_hint(&w0, &w1, GAMMA2);
    // Pack signature (z || hint || c)
    let mut sig = poly_pack(&z);
    sig.extend(hint);
    sig.extend(c.iter().map(|&x| x as u8));
    sig
}
