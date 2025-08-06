use sha3::Shake256;
use sha3::digest::{Update, ExtendableOutput};
use std::convert::TryInto;

use super::constants::*;

/// Expands matrix A from seed rho
pub fn expand_a(matrix: &mut [[u8; POLY_BYTES * L]; K], rho: &[u8]) {
    let mut shake = Shake256::default();
    shake.update(rho);
    
    for i in 0..K {
        for j in 0..L {
            let mut buf = [0u8; POLY_BYTES];
            shake.update(&[i as u8, j as u8]);
            shake.finalize_xof_into(&mut buf);
            matrix[i][j * POLY_BYTES..(j + 1) * POLY_BYTES]
                .copy_from_slice(&buf[..POLY_BYTES]);
        }
    }
}

/// Samples polynomial with tau nonzero entries
pub fn sample_in_ball(out: &mut [u8], seed: &[u8], offset: usize) {
    let mut shake = Shake256::default();
    shake.update(&[offset as u8]);
    shake.update(seed);
    
    let mut signs = 0u64;
    let mut indices = [0u32; TAU];
    let mut idx = 0;
    
    let mut buf = [0u8; TAU * 2];
    shake.finalize_xof_into(&mut buf);
    
    for i in 0..TAU {
        // Rejection sample indices in [0, N)
        loop {
            let idx_bytes = &buf[i * 2..(i + 1) * 2];
            let idx_raw = u16::from_le_bytes([idx_bytes[0], idx_bytes[1]]) as u32;
            if idx_raw < N as u32 {
                indices[idx] = idx_raw;
                idx += 1;
                break;
            }
            shake.update(&[i as u8]);
            let mut next_idx = [0u8; 2];
            shake.finalize_xof_into(&mut next_idx);
            buf[i * 2..(i + 1) * 2].copy_from_slice(&next_idx);
        }
        
        if i < 64 {
            signs |= (buf[TAU + (i / 8)] >> (i % 8) & 1) as u64;
        }
    }
    
    // Fill output with sampled values
    for i in 0..TAU {
        let idx = indices[i] as usize;
        let sign = ((signs >> i) & 1) as u32;
        let coef = sign * (Q - 1) + (1 - sign);
        
        out[idx * 4..(idx + 1) * 4]
            .copy_from_slice(&coef.to_le_bytes());
    }
}

/// Matrix multiplication: t = As1
pub fn matrix_multiply(t: &mut [u8], matrix: &[[u8; POLY_BYTES * L]; K], s1: &[u8]) {
    for i in 0..K {
        for j in 0..L {
            let mut accum = 0u64;
            
            for k in 0..N {
                let a_ij = u32::from_le_bytes(matrix[i][j * POLY_BYTES + k * 4..
                                                     j * POLY_BYTES + (k + 1) * 4]
                                                .try_into().unwrap());
                                                
                let s1_j = u32::from_le_bytes(s1[j * POLY_BYTES + k * 4..
                                                j * POLY_BYTES + (k + 1) * 4]
                                                .try_into().unwrap());
                                                
                accum = (accum + a_ij as u64 * s1_j as u64) % Q as u64;
            }
            
            t[i * constants::POLY_BYTES + k * 4..(i + 1) * constants::POLY_BYTES]
                .copy_from_slice(&(accum as u32).to_le_bytes());
        }
    }
}

/// Vector addition: t += s2
pub fn add_vectors(t: &mut [u8], s2: &[u8]) {
    for i in 0..K {
        for j in 0..N {
            let t_i = u32::from_le_bytes(t[i * constants::POLY_BYTES + j * 4..
                                         i * constants::POLY_BYTES + (j + 1) * 4]
                                         .try_into().unwrap());
                                         
            let s2_i = u32::from_le_bytes(s2[i * constants::POLY_BYTES + j * 4..
                                           i * constants::POLY_BYTES + (j + 1) * 4]
                                           .try_into().unwrap());
                                           
            let sum = (t_i + s2_i) % Q;
            t[i * constants::POLY_BYTES + j * 4..i * constants::POLY_BYTES + (j + 1) * 4]
                .copy_from_slice(&sum.to_le_bytes());
        }
    }
}

/// Pack t0 part of t
pub fn pack_t0(out: &mut [u8], t: &[u8]) {
    // TODO: Implement actual packing function
    out.copy_from_slice(&t[..constants::T0_BYTES]);
}

/// Pack t1 part of t
pub fn pack_t1(out: &mut [u8], t: &[u8]) {
    // TODO: Implement actual packing function  
    out.copy_from_slice(&t[constants::T0_BYTES..]);
}

/// Pack s1 coefficients
pub fn pack_s1(out: &mut [u8], s1: &[u8]) {
    // TODO: Implement actual packing function
    out.copy_from_slice(s1);
}

/// Pack s2 coefficients  
pub fn pack_s2(out: &mut [u8], s2: &[u8]) {
    // TODO: Implement actual packing function
    out.copy_from_slice(s2);
}
