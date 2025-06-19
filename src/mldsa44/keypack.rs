//! FIPS 204-compliant key packing for ML-DSA-44 (Dilithium2)
//! Implements pack_t1, pack_t0, pack_s1, pack_s2 as per reference

use crate::mldsa44::params::*;
use crate::mldsa44::poly::Poly;

/// Pack t1 (high bits of t) for K polynomials (bit-exact, 10 bits per coeff)
pub fn pack_t1(t: &[Poly; K]) -> Vec<u8> {
    let mut out = Vec::with_capacity(K * 320);
    for poly in t.iter() {
        for i in (0..N).step_by(4) {
            let c0 = poly[i + 0] as u16;
            let c1 = poly[i + 1] as u16;
            let c2 = poly[i + 2] as u16;
            let c3 = poly[i + 3] as u16;
            out.push((c0 & 0xFF) as u8);
            out.push(((c0 >> 8) | ((c1 & 0x3F) << 2)) as u8);
            out.push(((c1 >> 6) | ((c2 & 0x0F) << 4)) as u8);
            out.push(((c2 >> 4) | ((c3 & 0x03) << 6)) as u8);
            out.push((c3 >> 2) as u8);
        }
    }
    out
}

/// Pack t0 (low bits of t) for K polynomials (bit-exact, 13 bits per coeff)
pub fn pack_t0(t: &[Poly; K]) -> Vec<u8> {
    let mut out = Vec::with_capacity(K * 416);
    for poly in t.iter() {
        for i in (0..N).step_by(8) {
            let mut tvals = [0u16; 8];
            for j in 0..8 {
                tvals[j] = ((1 << 12) - poly[i + j]) as u16;
            }
            out.push((tvals[0] & 0xFF) as u8);
            out.push(((tvals[0] >> 8) | ((tvals[1] & 0x1F) << 5)) as u8);
            out.push(((tvals[1] >> 3) | ((tvals[2] & 0x03) << 10)) as u8);
            out.push(((tvals[2] >> 2) & 0xFF) as u8);
            out.push(((tvals[2] >> 10) | ((tvals[3] & 0x7F) << 3)) as u8);
            out.push(((tvals[3] >> 5) | ((tvals[4] & 0x0F) << 6)) as u8);
            out.push(((tvals[4] >> 4) & 0xFF) as u8);
            out.push(((tvals[4] >> 12) | ((tvals[5] & 0x3F) << 1)) as u8);
            out.push(((tvals[5] >> 7) | ((tvals[6] & 0x1F) << 4)) as u8);
            out.push(((tvals[6] >> 5) | ((tvals[7] & 0x07) << 7)) as u8);
            out.push(((tvals[7] >> 3) & 0xFF) as u8);
        }
    }
    out
}

/// Pack s1 (L polynomials, 3 bits per coeff, 8 coeffs per 3 bytes)
pub fn pack_s1(s1: &[Poly; L]) -> Vec<u8> {
    let mut out = Vec::with_capacity(L * 96);
    for poly in s1.iter() {
        for i in (0..N).step_by(8) {
            let mut t = [0u8; 8];
            for j in 0..8 {
                t[j] = (ETA as i32 - poly[i + j]) as u8;
            }
            out.push((t[0] >> 0) | (t[1] << 3) | (t[2] << 6));
            out.push(((t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7)) & 0xFF);
            out.push(((t[5] >> 1) | (t[6] << 2) | (t[7] << 5)) & 0xFF);
        }
    }
    out
}

/// Pack s2 (K polynomials, 3 bits per coeff, 8 coeffs per 3 bytes)
pub fn pack_s2(s2: &[Poly; K]) -> Vec<u8> {
    let mut out = Vec::with_capacity(K * 96);
    for poly in s2.iter() {
        for i in (0..N).step_by(8) {
            let mut t = [0u8; 8];
            for j in 0..8 {
                t[j] = (ETA as i32 - poly[i + j]) as u8;
            }
            out.push((t[0] >> 0) | (t[1] << 3) | (t[2] << 6));
            out.push(((t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7)) & 0xFF);
            out.push(((t[5] >> 1) | (t[6] << 2) | (t[7] << 5)) & 0xFF);
        }
    }
    out
}
