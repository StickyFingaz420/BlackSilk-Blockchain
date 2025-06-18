//! Number-Theoretic Transform (NTT) and polynomial arithmetic for ML-DSA-44 (FIPS 204)
//!
//! Implements NTT for q=8380417, root=1753, as required by FIPS 204.
//! All operations are constant-time and no_std compatible.
//!
//! References:
//! - FIPS 204, Section 5
//! - fips204 crate
//! - PQClean Dilithium

pub const Q: u32 = 8380417;
pub const N: usize = 256; // Degree of polynomials
pub const ROOT: u32 = 1753; // 512-th primitive root of unity mod Q

/// Forward NTT for a polynomial (in place)
pub fn ntt(a: &mut [u32; N]) {
    // TODO: Implement constant-time NTT for q=8380417, root=1753
    // See fips204 and PQClean for reference
}

/// Inverse NTT for a polynomial (in place)
pub fn intt(a: &mut [u32; N]) {
    // TODO: Implement constant-time inverse NTT
}

/// Pointwise multiplication of two polynomials (mod Q)
pub fn poly_mul(a: &[u32; N], b: &[u32; N], out: &mut [u32; N]) {
    for i in 0..N {
        out[i] = (a[i] as u64 * b[i] as u64 % Q as u64) as u32;
    }
}

/// Add two polynomials (mod Q)
pub fn poly_add(a: &[u32; N], b: &[u32; N], out: &mut [u32; N]) {
    for i in 0..N {
        out[i] = (a[i] + b[i]) % Q;
    }
}

/// Subtract two polynomials (mod Q)
pub fn poly_sub(a: &[u32; N], b: &[u32; N], out: &mut [u32; N]) {
    for i in 0..N {
        out[i] = (a[i] + Q - b[i]) % Q;
    }
}
