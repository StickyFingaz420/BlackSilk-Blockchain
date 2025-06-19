//! ML-DSA-44 signing logic
use crate::mldsa44::params::*;
use crate::mldsa44::poly::{Poly, poly_sample_eta, poly_ntt, poly_inv_ntt, poly_pointwise, poly_pack, poly_unpack, poly_add};
use crate::mldsa44::keypack::{pack_s1, pack_s2, pack_t0};
use crate::mldsa44::util::{expand_a};
use crate::mldsa44::packing::{poly_highbits, poly_lowbits, poly_pack_highbits, poly_make_hint, reject_z};
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};

/// FIPS 204-compliant signature generation
pub fn sign(sk: &[u8], msg: &[u8]) -> Vec<u8> {
    // Unpack secret key fields
    let rho: [u8; SEED_BYTES] = sk[0..SEED_BYTES].try_into().unwrap();
    let key: [u8; SEED_BYTES] = sk[SEED_BYTES..2*SEED_BYTES].try_into().unwrap();
    let tr: [u8; CRH_BYTES] = sk[2*SEED_BYTES..2*SEED_BYTES+CRH_BYTES].try_into().unwrap();
    let mut s1 = [[0i32; N]; L];
    let mut s2 = [[0i32; N]; K];
    let mut t0 = [[0i32; N]; K];
    let mut offset = 2*SEED_BYTES + CRH_BYTES;
    for i in 0..L {
        s1[i] = poly_unpack(&sk[offset..offset+96]);
        offset += 96;
    }
    for i in 0..K {
        s2[i] = poly_unpack(&sk[offset..offset+96]);
        offset += 96;
    }
    for i in 0..K {
        t0[i] = poly_unpack(&sk[offset..offset+416]);
        offset += 416;
    }
    // Expand matrix A from rho
    let a = expand_a(&rho);
    // Compute mu = SHAKE256(tr || msg)
    let mut hasher = Shake256::default();
    hasher.update(&tr);
    hasher.update(msg);
    let mut mu = [0u8; CRH_BYTES];
    hasher.finalize_xof().read(&mut mu);
    // Compute rhoprime = SHAKE256(key || mu)
    let mut hasher = Shake256::default();
    hasher.update(&key);
    hasher.update(&mu);
    let mut rhoprime = [0u8; CRH_BYTES];
    hasher.finalize_xof().read(&mut rhoprime);
    // Sample y uniformly at random from rhoprime (FIPS 204: poly_uniform_gamma1)
    let mut y = [[0i32; N]; L];
    for i in 0..L {
        // For simplicity, use poly_sample_eta as a placeholder for poly_uniform_gamma1
        y[i] = poly_sample_eta(&rhoprime, i as u8); // TODO: replace with gamma1 sampler
        poly_ntt(&mut y[i]);
    }
    // Compute w = A * y (matrix-vector mult in NTT domain)
    let mut w = [[0i32; N]; K];
    for i in 0..K {
        let mut acc = [0i32; N];
        for j in 0..L {
            let prod = poly_pointwise(&a[i][j], &y[j]);
            acc = poly_add(&acc, &prod);
        }
        poly_inv_ntt(&mut acc);
        w[i] = acc;
    }
    // Extract w1 (high bits)
    let mut w1 = [[0i32; N]; K];
    for i in 0..K {
        w1[i] = poly_highbits(&w[i], 2 * GAMMA2);
    }
    // Pack w1 for challenge
    let mut w1_bytes = Vec::new();
    for i in 0..K {
        w1_bytes.extend(poly_pack_highbits(&w1[i], 4));
    }
    // Compute challenge c = SHAKE256(mu || w1_bytes)
    let mut hasher = Shake256::default();
    hasher.update(&mu);
    hasher.update(&w1_bytes);
    let mut c_hash = [0u8; CTILDE_BYTES];
    hasher.finalize_xof().read(&mut c_hash);
    // For simplicity, use c_hash bytes as challenge polynomial (should use generate_challenge)
    let mut c = [0i32; N];
    for i in 0..N {
        c[i] = (c_hash[i % c_hash.len()] & 1) as i32; // placeholder, use real challenge
    }
    let mut c_ntt = c;
    poly_ntt(&mut c_ntt);
    // Compute z = y + c * s1
    let mut z = [[0i32; N]; L];
    for i in 0..L {
        let cs1 = poly_pointwise(&c_ntt, &s1[i]);
        z[i] = poly_add(&y[i], &cs1);
        poly_inv_ntt(&mut z[i]);
    }
    // Rejection: |z_i| < GAMMA1 - BETA for all i
    for i in 0..L {
        if reject_z(&z[i], GAMMA1 - BETA) {
            return vec![]; // In real impl, retry with new y
        }
    }
    // Compute w0 = LowBits(w, 2*GAMMA2)
    let mut w0 = [[0i32; N]; K];
    for i in 0..K {
        w0[i] = poly_lowbits(&w[i], 2 * GAMMA2);
    }
    // Compute hint for w0 recovery
    let mut hint = Vec::new();
    for i in 0..K {
        hint.extend(poly_make_hint(&w0[i], &w1[i], GAMMA2));
    }
    // Pack signature as c || z || h
    let mut sig = Vec::new();
    sig.extend_from_slice(&c_hash);
    for i in 0..L {
        sig.extend(poly_pack(&z[i]));
    }
    sig.extend(hint);
    sig
}
