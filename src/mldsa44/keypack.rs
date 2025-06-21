//! FIPS 204-compliant key packing for ML-DSA-44 (Dilithium2)
//! Implements pack_t1, pack_t0, pack_s1, pack_s2 as per reference

use crate::mldsa44::params::*;
use crate::mldsa44::poly::Poly;

/// Pack t1 (high bits of t) for K polynomials (bit-exact, 10 bits per coeff)
pub fn pack_t1(t: &[Poly; K]) -> Vec<u8> {
    let mut out = Vec::with_capacity(K * 320);
    for poly in t.iter() {
        // C reference packs coefficients in increasing order (0..N)
        for i in (0..N).step_by(4) {
            let c0 = (poly[i + 0] as u32) & 0x3FF;
            let c1 = (poly[i + 1] as u32) & 0x3FF;
            let c2 = (poly[i + 2] as u32) & 0x3FF;
            let c3 = (poly[i + 3] as u32) & 0x3FF;
            out.push((c0 >> 0) as u8);
            out.push(((c0 >> 8) | (c1 << 2)) as u8);
            out.push(((c1 >> 6) | (c2 << 4)) as u8);
            out.push(((c2 >> 4) | (c3 << 6)) as u8);
            out.push((c3 >> 2) as u8);
        }
    }
    out
}

/// Pack t0 (low bits of t) for K polynomials (bit-exact, 13 bits per coeff)
pub fn pack_t0(t: &[Poly; K]) -> Vec<u8> {
    let mut out = Vec::with_capacity(K * 416);
    for (poly_idx, poly) in t.iter().enumerate() {
        let start_len = out.len();
        for i in (0..N).step_by(8) {
            // Print group index for debug
            println!("DEBUG: pack_t0 poly {} group starting at i={}", poly_idx, i);
            let mut tvals = [0u32; 8];
            for j in 0..8 {
                tvals[j] = ((poly[i + j] + (1 << 12)) as u32) & 0x1FFF;
            }
            out.push((tvals[0] & 0xFF) as u8);
            out.push(((tvals[0] >> 8) | ((tvals[1] & 0x1F) << 5)) as u8);
            out.push(((tvals[1] >> 3) & 0xFF) as u8);
            out.push(((tvals[1] >> 11) | ((tvals[2] & 0x3F) << 2)) as u8);
            out.push(((tvals[2] >> 6) | ((tvals[3] & 0x7F) << 7)) as u8);
            out.push(((tvals[3] >> 1) & 0xFF) as u8);
            out.push(((tvals[3] >> 9) | ((tvals[4] & 0x0F) << 4)) as u8);
            out.push(((tvals[4] >> 4) & 0xFF) as u8);
            out.push(((tvals[4] >> 12) | ((tvals[5] & 0x7F) << 1)) as u8);
            out.push(((tvals[5] >> 7) | ((tvals[6] & 0x3F) << 6)) as u8);
            out.push(((tvals[6] >> 2) & 0xFF) as u8);
            out.push(((tvals[6] >> 10) | ((tvals[7] & 0x1F) << 3)) as u8);
            out.push(((tvals[7] >> 5) & 0xFF) as u8);
        }
        let poly_len = out.len() - start_len;
        println!("DEBUG: pack_t0 poly {} output len = {}", poly_idx, poly_len);
    }
    println!("DEBUG: pack_t0 total output len = {}", out.len());
    out
}

/// Pack s1 (L polynomials, 2 bits per coeff, 4 coeffs per byte)
pub fn pack_s1(s1: &[Poly; L]) -> Vec<u8> {
    let mut out = Vec::with_capacity(L * 80);
    for poly in s1.iter() {
        let mut poly_bytes = Vec::with_capacity(80);
        let mut i = 0;
        while i + 3 < N {
            let c0 = (poly[i + 0] as u8) & 0x03;
            let c1 = (poly[i + 1] as u8) & 0x03;
            let c2 = (poly[i + 2] as u8) & 0x03;
            let c3 = (poly[i + 3] as u8) & 0x03;
            poly_bytes.push(c0 | (c1 << 2) | (c2 << 4) | (c3 << 6));
            i += 4;
        }
        if i < N {
            let mut last = 0u8;
            for j in 0..(N - i) {
                last |= ((poly[i + j] as u8) & 0x03) << (2 * j);
            }
            poly_bytes.push(last);
        }
        while poly_bytes.len() < 80 {
            poly_bytes.push(0);
        }
        out.extend_from_slice(&poly_bytes);
    }
    out
}

/// Pack s2 (K polynomials, 2 bits per coeff, 4 coeffs per byte)
pub fn pack_s2(s2: &[Poly; K]) -> Vec<u8> {
    let mut out = Vec::with_capacity(K * 80);
    for poly in s2.iter() {
        let mut poly_bytes = Vec::with_capacity(80);
        let mut i = 0;
        while i + 3 < N {
            let c0 = (poly[i + 0] as u8) & 0x03;
            let c1 = (poly[i + 1] as u8) & 0x03;
            let c2 = (poly[i + 2] as u8) & 0x03;
            let c3 = (poly[i + 3] as u8) & 0x03;
            poly_bytes.push(c0 | (c1 << 2) | (c2 << 4) | (c3 << 6));
            i += 4;
        }
        if i < N {
            let mut last = 0u8;
            for j in 0..(N - i) {
                last |= ((poly[i + j] as u8) & 0x03) << (2 * j);
            }
            poly_bytes.push(last);
        }
        while poly_bytes.len() < 80 {
            poly_bytes.push(0);
        }
        out.extend_from_slice(&poly_bytes);
    }
    out
}

/// Unpack t1 (high bits of t) for K polynomials (10 bits per coeff, 4 coeffs per 5 bytes)
pub fn unpack_t1(bytes: &[u8]) -> [Poly; K] {
    let mut out = [[0i32; N]; K];
    for k in 0..K {
        let offset = k * 320;
        let b = &bytes[offset..offset+320];
        let mut idx = 0;
        for i in (0..N).step_by(4) {
            let c0 = (((b[idx+0] as u32) | ((b[idx+1] as u32) << 8)) & 0x3FF) as i32;
            let c1 = (((b[idx+1] as u32) >> 2 | ((b[idx+2] as u32) << 6)) & 0x3FF) as i32;
            let c2 = (((b[idx+2] as u32) >> 4 | ((b[idx+3] as u32) << 4)) & 0x3FF) as i32;
            let c3 = (((b[idx+3] as u32) >> 6 | ((b[idx+4] as u32) << 2)) & 0x3FF) as i32;
            out[k][i+0] = c0;
            out[k][i+1] = c1;
            out[k][i+2] = c2;
            out[k][i+3] = c3;
            idx += 5;
        }
    }
    out
}

/// Unpack t0 (low bits of t) for K polynomials (13 bits per coeff, 8 coeffs per 13 bytes)
pub fn unpack_t0(bytes: &[u8]) -> [Poly; K] {
    let mut out = [[0i32; N]; K];
    for k in 0..K {
        let offset = k * 416;
        let b = &bytes[offset..offset+416];
        let mut idx = 0;
        for i in (0..N).step_by(8) {
            let mut t = [0u32; 8];
            t[0] = ((b[idx+0] as u32) | ((b[idx+1] as u32) << 8)) & 0x1FFF;
            t[1] = (((b[idx+1] as u32) >> 5) | ((b[idx+2] as u32) << 3) | ((b[idx+3] as u32) << 11)) & 0x1FFF;
            t[2] = (((b[idx+3] as u32) >> 2) | ((b[idx+4] as u32) << 6)) & 0x1FFF;
            t[3] = (((b[idx+4] as u32) >> 7) | ((b[idx+5] as u32) << 1) | ((b[idx+6] as u32) << 9)) & 0x1FFF;
            t[4] = (((b[idx+6] as u32) >> 4) | ((b[idx+7] as u32) << 4) | ((b[idx+8] as u32) << 12)) & 0x1FFF;
            t[5] = (((b[idx+8] as u32) >> 1) | ((b[idx+9] as u32) << 7)) & 0x1FFF;
            t[6] = (((b[idx+9] as u32) >> 6) | ((b[idx+10] as u32) << 2) | ((b[idx+11] as u32) << 10)) & 0x1FFF;
            t[7] = (((b[idx+11] as u32) >> 3) | ((b[idx+12] as u32) << 5)) & 0x1FFF;
            for j in 0..8 {
                out[k][i+j] = t[j] as i32 - (1 << 12);
            }
            idx += 13;
        }
    }
    out
}
