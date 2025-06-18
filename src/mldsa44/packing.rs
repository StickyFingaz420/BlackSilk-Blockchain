//! Packing and unpacking keys and signatures for ML-DSA-44
// Implement bit packing/unpacking as per FIPS 204

use crate::mldsa44::params::{N, Q, GAMMA1, GAMMA2};

/// Extract high bits of a polynomial (FIPS 204 HighBits)
pub fn poly_highbits(a: &[i32; N], alpha: i32) -> [i32; N] {
    let mut r = [0i32; N];
    for i in 0..N {
        r[i] = (a[i] + alpha/2) / alpha;
    }
    r
}

/// Extract low bits of a polynomial (FIPS 204 LowBits)
pub fn poly_lowbits(a: &[i32; N], alpha: i32) -> [i32; N] {
    let mut r = [0i32; N];
    for i in 0..N {
        r[i] = a[i] - alpha * ((a[i] + alpha/2) / alpha);
    }
    r
}

/// Pack a polynomial with high bits only (for t1, w1, etc.)
pub fn poly_pack_highbits(a: &[i32; N], bits: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity((N * bits as usize + 7) / 8);
    let mut acc = 0u32;
    let mut acc_bits = 0u32;
    for &coeff in a.iter() {
        acc |= (coeff as u32) << acc_bits;
        acc_bits += bits;
        while acc_bits >= 8 {
            out.push((acc & 0xFF) as u8);
            acc >>= 8;
            acc_bits -= 8;
        }
    }
    if acc_bits > 0 {
        out.push(acc as u8);
    }
    out
}

/// Unpack a polynomial with high bits only
pub fn poly_unpack_highbits(bytes: &[u8], bits: u32) -> [i32; N] {
    let mut r = [0i32; N];
    let mut acc = 0u32;
    let mut acc_bits = 0u32;
    let mut idx = 0;
    for i in 0..N {
        while acc_bits < bits {
            acc |= (bytes[idx] as u32) << acc_bits;
            acc_bits += 8;
            idx += 1;
        }
        r[i] = (acc & ((1 << bits) - 1)) as i32;
        acc >>= bits;
        acc_bits -= bits;
    }
    r
}

/// Compute the hint for w0 recovery (FIPS 204, see PQClean poly.c)
pub fn poly_make_hint(w0: &[i32; N], w1: &[i32; N], gamma2: i32) -> Vec<u8> {
    let mut hint = Vec::with_capacity(N);
    for i in 0..N {
        // If w0[i] is in the upper half of the interval, set hint bit
        let needs_hint = (w0[i] > gamma2) || (w0[i] < -gamma2);
        hint.push(needs_hint as u8);
    }
    hint
}

/// Apply the hint to recover w1 from w0 (FIPS 204, see PQClean poly.c)
pub fn poly_use_hint(w0: &[i32; N], hint: &[u8], gamma2: i32) -> [i32; N] {
    let mut w1 = [0i32; N];
    for i in 0..N {
        if hint[i] != 0 {
            w1[i] = (w0[i] + gamma2) / (2 * gamma2);
        } else {
            w1[i] = w0[i] / (2 * gamma2);
        }
    }
    w1
}

/// FIPS 204-compliant signature rejection logic for z and w0
pub fn reject_z(z: &[i32; N], bound: i32) -> bool {
    for &zi in z.iter() {
        if zi.abs() >= bound {
            return true;
        }
    }
    false
}

pub fn reject_w0(w0: &[i32; N], bound: i32) -> bool {
    for &wi in w0.iter() {
        if wi.abs() >= bound {
            return true;
        }
    }
    false
}
