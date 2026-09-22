//! AesGenerator1R, AesGenerator4R and AesHash1R (spec chapter 3).
//!
//! `aesenc`/`aesdec` are single AES rounds with the exact semantics of the x86
//! `AESENC`/`AESDEC` instructions, provided by the RustCrypto `aes` crate.

use aes::hazmat::{cipher_round, equiv_inv_cipher_round};
use aes::Block;

/// Builds a 128-bit constant the way the reference `_mm_set_epi32(a, b, c, d)` does
/// (`d` is the least significant 32-bit lane).
const fn key(a: u32, b: u32, c: u32, d: u32) -> [u8; 16] {
    let (d, c, b, a) = (
        d.to_le_bytes(),
        c.to_le_bytes(),
        b.to_le_bytes(),
        a.to_le_bytes(),
    );
    [
        d[0], d[1], d[2], d[3], c[0], c[1], c[2], c[3], b[0], b[1], b[2], b[3], a[0], a[1], a[2],
        a[3],
    ]
}

const HASH_1R_STATE: [[u8; 16]; 4] = [
    key(0xd7983aad, 0xcc82db47, 0x9fa856de, 0x92b52c0d),
    key(0xace78057, 0xf59e125a, 0x15c7b798, 0x338d996e),
    key(0xe8a07ce4, 0x5079506b, 0xae62c7d0, 0x6a770017),
    key(0x7e994948, 0x79a10005, 0x07ad828d, 0x630a240c),
];
const HASH_1R_XKEY0: [u8; 16] = key(0x06890201, 0x90dc56bf, 0x8b24949f, 0xf6fa8389);
const HASH_1R_XKEY1: [u8; 16] = key(0xed18f99b, 0xee1043c6, 0x51f4e03c, 0x61b263d1);

const GEN_1R_KEYS: [[u8; 16]; 4] = [
    key(0xb4f44917, 0xdbb5552b, 0x62716609, 0x6daca553),
    key(0x0da1dc4e, 0x1725d378, 0x846a710d, 0x6d7caf07),
    key(0x3e20e345, 0xf4c0794f, 0x9f947ec6, 0x3f1262f1),
    key(0x49169154, 0x16314c88, 0xb1ba317c, 0x6aef8135),
];

const GEN_4R_KEYS: [[u8; 16]; 8] = [
    key(0x99e5d23f, 0x2f546d2b, 0xd1833ddb, 0x6421aadd),
    key(0xa5dfcde5, 0x06f79d53, 0xb6913f55, 0xb20e3450),
    key(0x171c02bf, 0x0aa4679f, 0x515e7baf, 0x5c3ed904),
    key(0xd8ded291, 0xcd673785, 0xe78f5d08, 0x85623763),
    key(0x229effb4, 0x3d518b6d, 0xe3d6a7a6, 0xb5826f73),
    key(0xb272b7d2, 0xe9024d4e, 0x9c10b3d9, 0xc7566bf3),
    key(0xf63befa7, 0x2ba9660a, 0xf765a38b, 0xf273c9e7),
    key(0xc0b0762d, 0x0c06d1fd, 0x915839de, 0x7a7cd609),
];

#[inline(always)]
fn enc(state: &mut Block, key: &[u8; 16]) {
    cipher_round(state, Block::from_slice(key));
}

#[inline(always)]
fn dec(state: &mut Block, key: &[u8; 16]) {
    equiv_inv_cipher_round(state, Block::from_slice(key));
}

fn load(state: &[u8; 64]) -> [Block; 4] {
    core::array::from_fn(|i| *Block::from_slice(&state[16 * i..16 * i + 16]))
}

fn store(dst: &mut [u8], s: &[Block; 4]) {
    for (i, b) in s.iter().enumerate() {
        dst[16 * i..16 * i + 16].copy_from_slice(b);
    }
}

/// AesGenerator1R: fills `out` (multiple of 64 bytes) and writes the final state back.
pub(crate) fn fill_aes_1rx4(state: &mut [u8; 64], out: &mut [u8]) {
    let (chunks, rest) = out.as_chunks_mut::<64>();
    assert!(rest.is_empty(), "output must be a multiple of 64 bytes");
    let mut s = load(state);
    for chunk in chunks {
        dec(&mut s[0], &GEN_1R_KEYS[0]);
        enc(&mut s[1], &GEN_1R_KEYS[1]);
        dec(&mut s[2], &GEN_1R_KEYS[2]);
        enc(&mut s[3], &GEN_1R_KEYS[3]);
        store(chunk, &s);
    }
    store(state, &s);
}

/// AesGenerator4R: fills `out` (multiple of 64 bytes) from `state`.
pub(crate) fn fill_aes_4rx4(state: &[u8; 64], out: &mut [u8]) {
    let (chunks, rest) = out.as_chunks_mut::<64>();
    assert!(rest.is_empty(), "output must be a multiple of 64 bytes");
    let k = &GEN_4R_KEYS;
    let mut s = load(state);
    for chunk in chunks {
        for round in 0..4 {
            dec(&mut s[0], &k[round]);
            enc(&mut s[1], &k[round]);
            dec(&mut s[2], &k[round + 4]);
            enc(&mut s[3], &k[round + 4]);
        }
        store(chunk, &s);
    }
}

/// AesHash1R: 512-bit fingerprint of `input` (multiple of 64 bytes).
pub(crate) fn hash_aes_1rx4(input: &[u8]) -> [u8; 64] {
    let (chunks, rest) = input.as_chunks::<64>();
    assert!(rest.is_empty(), "input must be a multiple of 64 bytes");
    let mut s: [Block; 4] = core::array::from_fn(|i| *Block::from_slice(&HASH_1R_STATE[i]));
    for chunk in chunks {
        let k: [[u8; 16]; 4] =
            core::array::from_fn(|i| chunk[16 * i..16 * i + 16].try_into().unwrap());
        enc(&mut s[0], &k[0]);
        dec(&mut s[1], &k[1]);
        enc(&mut s[2], &k[2]);
        dec(&mut s[3], &k[3]);
    }
    for xkey in [&HASH_1R_XKEY0, &HASH_1R_XKEY1] {
        enc(&mut s[0], xkey);
        dec(&mut s[1], xkey);
        enc(&mut s[2], xkey);
        dec(&mut s[3], xkey);
    }
    let mut out = [0u8; 64];
    store(&mut out, &s);
    out
}
