//! Utility functions for ML-DSA-44
// Implement hex conversion, error handling, etc.
//! Matrix A expansion (ExpandA) for ML-DSA-44 (FIPS 204)
//! Generates A ∈ R_{K×L}^q in NTT form from 32-byte seed ρ
use crate::mldsa44::params::{N, Q, K, L, SEED_BYTES, TAU};
use crate::mldsa44::poly::{Poly, poly_ntt};
use sha3::{Shake128, Shake256, digest::{Update, ExtendableOutput, XofReader}};

/// ExpandA: Generate matrix A in NTT form from 32-byte seed ρ
pub fn expand_a(rho: &[u8; SEED_BYTES]) -> Vec<Vec<Poly>> {
    let mut a = vec![vec![[0i32; N]; L]; K];
    for i in 0..K {
        for j in 0..L {
            let mut hasher = Shake128::default();
            hasher.update(rho);
            hasher.update(&[j as u8, i as u8]);
            let mut xof = hasher.finalize_xof();
            let mut coeffs = [0i32; N];
            let mut filled = 0;
            let mut buf = [0u8; 3];
            while filled < N {
                xof.read(&mut buf);
                let val = ((buf[0] as u32) | ((buf[1] as u32) << 8) | ((buf[2] as u32) << 16)) & 0x7FFFFF; // 23 bits
                if val < Q as u32 {
                    coeffs[filled] = val as i32;
                    filled += 1;
                }
            }
            let mut poly = coeffs;
            poly_ntt(&mut poly);
            a[i][j] = poly;
        }
    }
    a
}

/// Generate challenge polynomial c from message and w1 (FIPS 204, Hamming weight TAU)
pub fn generate_challenge(msg: &[u8], w1: &[u8]) -> [i8; N] {
    let mut hasher = Shake256::default();
    hasher.update(msg);
    hasher.update(w1);
    let mut xof = hasher.finalize_xof();
    let mut c = [0i8; N];
    let mut signs = [0u8; 8];
    xof.read(&mut signs);
    let mut pos = 0;
    let mut cnt = 0;
    let mut used = [false; N];
    while cnt < TAU {
        let mut buf = [0u8; 2];
        xof.read(&mut buf);
        let idx = ((buf[0] as usize) | ((buf[1] as usize) << 8)) % N;
        if !used[idx] {
            used[idx] = true;
            let sign = ((signs[cnt / 8] >> (cnt % 8)) & 1) as i8;
            c[idx] = 1 - 2 * sign; // +1 or -1
            cnt += 1;
        }
    }
    c
}
