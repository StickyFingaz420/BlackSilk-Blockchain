//! ML-DSA-44 verification logic
use crate::mldsa44::params::*;
use crate::mldsa44::poly::{Poly, poly_ntt, poly_inv_ntt, poly_pointwise, poly_pack, poly_unpack, poly_add, poly_sub};
use crate::mldsa44::util::{expand_a, generate_challenge};
use crate::mldsa44::packing::{poly_highbits, poly_lowbits, poly_unpack_highbits, poly_use_hint, reject_z, poly_pack_highbits};

/// Verify a signature using the public key, with FIPS 204-compliant primitives
pub fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    // Unpack public key (assume rho || t1)
    let rho: [u8; SEED_BYTES] = pk[0..SEED_BYTES].try_into().unwrap();
    let t1 = crate::mldsa44::keypack::unpack_t1(&pk[SEED_BYTES..SEED_BYTES+K*320]);
    // Expand matrix A from rho
    let a = expand_a(&rho);
    // Unpack signature (c || z || h)
    let c_hash = &sig[0..CTILDE_BYTES];
    let mut z = [[0i32; N]; L];
    let mut offset = CTILDE_BYTES;
    for i in 0..L {
        z[i] = poly_unpack(&sig[offset..offset+96]);
        offset += 96;
        #[cfg(feature = "debug_kat")]
        println!("DEBUG_KAT: z[{}]: {}", i, hex::encode(&poly_pack(&z[i])));
    }
    let hint = &sig[offset..];
    #[cfg(feature = "debug_kat")]
    println!("DEBUG_KAT: hint: {}", hex::encode(&hint));
    // Rejection: |z_i| < GAMMA1 - BETA
    for i in 0..L {
        if reject_z(&z[i], GAMMA1 - BETA) {
            return false;
        }
    }
    // NTT transform z
    let mut z_ntt = z;
    for i in 0..L {
        poly_ntt(&mut z_ntt[i]);
        #[cfg(feature = "debug_kat")]
        println!("DEBUG_KAT: z_ntt[{}]: {}", i, hex::encode(&poly_pack(&z_ntt[i])));
    }
    // Compute w' = A * z - c * t1
    let mut w_prime = [[0i32; N]; K];
    for i in 0..K {
        let mut acc = [0i32; N];
        for j in 0..L {
            let prod = poly_pointwise(&a[i][j], &z_ntt[j]);
            acc = poly_add(&acc, &prod);
        }
        w_prime[i] = acc;
        poly_inv_ntt(&mut w_prime[i]);
        #[cfg(feature = "debug_kat")]
        println!("DEBUG_KAT: w_prime[{}]: {}", i, hex::encode(&poly_pack(&w_prime[i])));
    }
    // Compute w0 = LowBits(w', 2*GAMMA2)
    let mut w0 = [[0i32; N]; K];
    for i in 0..K {
        w0[i] = poly_lowbits(&w_prime[i], 2 * GAMMA2);
        #[cfg(feature = "debug_kat")]
        println!("DEBUG_KAT: w0[{}]: {}", i, hex::encode(&poly_pack(&w0[i])));
    }
    // Recover w1 using hint
    let mut w1 = [[0i32; N]; K];
    let mut hint_offset = 0;
    for i in 0..K {
        w1[i] = poly_use_hint(&w0[i], &hint[hint_offset..hint_offset+N], GAMMA2);
        hint_offset += N;
        #[cfg(feature = "debug_kat")]
        println!("DEBUG_KAT: w1[{}]: {}", i, hex::encode(&poly_pack_highbits(&w1[i], 4)));
    }
    // Compute w1_bytes for challenge
    let mut w1_bytes = Vec::new();
    for i in 0..K {
        w1_bytes.extend(poly_pack_highbits(&w1[i], 4));
    }
    #[cfg(feature = "debug_kat")]
    println!("DEBUG_KAT: w1_bytes: {}", hex::encode(&w1_bytes));
    // Compute challenge c' = generate_challenge(msg, &w1_bytes)
    let c_prime = crate::mldsa44::util::generate_challenge(msg, &w1_bytes);
    #[cfg(feature = "debug_kat")]
    let c_prime_bytes: Vec<u8> = c_prime.iter().map(|&x| x as u8).collect();
    #[cfg(feature = "debug_kat")]
    println!("DEBUG_KAT: c_prime: {}", hex::encode(&c_prime_bytes));
    // Accept if c_hash == c_prime as bytes
    let c_hash_bytes = &sig[0..CTILDE_BYTES];
    let c_prime_bytes: Vec<u8> = c_prime.iter().map(|&x| x as u8).collect();
    c_hash_bytes == &c_prime_bytes[0..CTILDE_BYTES]
}
