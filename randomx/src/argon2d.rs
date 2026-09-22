//! Argon2d memory fill as used by RandomX cache initialization (spec chapter 7.1).
//!
//! RandomX keeps the raw Argon2 memory (not the final tag), with `outlen = 0` in
//! the initial hash, one lane, and version 0x13.

use crate::config::{ARGON_ITERATIONS, ARGON_LANES, ARGON_MEMORY, ARGON_SALT};
use crate::hash::blake2b_long;
use blake2::digest::{Digest, Update};
use blake2::Blake2b512;

pub(crate) const QWORDS_IN_BLOCK: usize = 128;
const SYNC_POINTS: u32 = 4;
const VERSION: u32 = 0x13;
const TYPE_ARGON2D: u32 = 0;

type Block = [u64; QWORDS_IN_BLOCK];

/// Fills `memory` (`ARGON_MEMORY * 128` quadwords) from `key`.
pub(crate) fn fill_memory(key: &[u8], memory: &mut [u64]) {
    assert_eq!(memory.len(), ARGON_MEMORY as usize * QWORDS_IN_BLOCK);
    let lane_length = ARGON_MEMORY;
    let segment_length = ARGON_MEMORY / (ARGON_LANES * SYNC_POINTS);

    // H0 plus 8 bytes for the block counter and lane index.
    let mut seed = [0u8; 72];
    seed[..64].copy_from_slice(&initial_hash(key));

    let mut block_bytes = [0u8; 1024];
    for i in 0..2u32 {
        seed[64..68].copy_from_slice(&i.to_le_bytes());
        seed[68..72].copy_from_slice(&0u32.to_le_bytes()); // lane 0
        blake2b_long(&mut block_bytes, &seed);
        let dst = &mut memory[i as usize * QWORDS_IN_BLOCK..(i as usize + 1) * QWORDS_IN_BLOCK];
        for (q, chunk) in dst.iter_mut().zip(block_bytes.as_chunks::<8>().0) {
            *q = u64::from_le_bytes(*chunk);
        }
    }

    for pass in 0..ARGON_ITERATIONS {
        for slice in 0..SYNC_POINTS {
            fill_segment(memory, pass, slice, segment_length, lane_length);
        }
    }
}

fn initial_hash(key: &[u8]) -> [u8; 64] {
    let mut h = Blake2b512::new();
    for v in [
        ARGON_LANES,
        0, /* outlen */
        ARGON_MEMORY,
        ARGON_ITERATIONS,
        VERSION,
        TYPE_ARGON2D,
    ] {
        Update::update(&mut h, &v.to_le_bytes());
    }
    Update::update(&mut h, &(key.len() as u32).to_le_bytes());
    Update::update(&mut h, key);
    Update::update(&mut h, &(ARGON_SALT.len() as u32).to_le_bytes());
    Update::update(&mut h, ARGON_SALT);
    Update::update(&mut h, &0u32.to_le_bytes()); // secret length
    Update::update(&mut h, &0u32.to_le_bytes()); // associated data length
    h.finalize().into()
}

fn fill_segment(memory: &mut [u64], pass: u32, slice: u32, segment_length: u32, lane_length: u32) {
    let starting_index = if pass == 0 && slice == 0 { 2 } else { 0 };
    let first_offset = slice * segment_length + starting_index;
    let mut prev_offset = if first_offset.is_multiple_of(lane_length) {
        first_offset + lane_length - 1
    } else {
        first_offset - 1
    };

    for index in starting_index..segment_length {
        let curr_offset = slice * segment_length + index;
        if curr_offset % lane_length == 1 {
            prev_offset = curr_offset - 1;
        }
        let pseudo_rand = memory[prev_offset as usize * QWORDS_IN_BLOCK];
        let ref_index = index_alpha(
            pass,
            slice,
            index,
            pseudo_rand as u32,
            segment_length,
            lane_length,
        );

        let prev = read_block(memory, prev_offset);
        let reference = read_block(memory, ref_index);
        let curr = &mut memory[curr_offset as usize * QWORDS_IN_BLOCK..][..QWORDS_IN_BLOCK];
        fill_block(&prev, &reference, curr, pass != 0);

        prev_offset += 1;
    }
}

/// Reference block position within the (single) lane; `same_lane` is always true.
fn index_alpha(
    pass: u32,
    slice: u32,
    index: u32,
    pseudo_rand: u32,
    segment_length: u32,
    lane_length: u32,
) -> u32 {
    let reference_area_size: u32 = if pass == 0 {
        if slice == 0 {
            index - 1
        } else {
            slice * segment_length + index - 1
        }
    } else {
        lane_length - segment_length + index - 1
    };

    let mut relative_position = pseudo_rand as u64;
    relative_position = (relative_position * relative_position) >> 32;
    let relative_position =
        reference_area_size as u64 - 1 - ((reference_area_size as u64 * relative_position) >> 32);

    let start_position: u64 = if pass != 0 && slice != SYNC_POINTS - 1 {
        ((slice + 1) * segment_length) as u64
    } else {
        0
    };
    ((start_position + relative_position) % lane_length as u64) as u32
}

fn read_block(memory: &[u64], index: u32) -> Block {
    memory[index as usize * QWORDS_IN_BLOCK..][..QWORDS_IN_BLOCK]
        .try_into()
        .unwrap()
}

fn fill_block(prev: &Block, reference: &Block, next: &mut [u64], with_xor: bool) {
    let mut r: Block = [0; QWORDS_IN_BLOCK];
    for i in 0..QWORDS_IN_BLOCK {
        r[i] = reference[i] ^ prev[i];
    }
    let mut tmp = r;
    if with_xor {
        for i in 0..QWORDS_IN_BLOCK {
            tmp[i] ^= next[i];
        }
    }

    for i in 0..8 {
        let b = 16 * i;
        blake2_round(
            &mut r,
            [
                b,
                b + 1,
                b + 2,
                b + 3,
                b + 4,
                b + 5,
                b + 6,
                b + 7,
                b + 8,
                b + 9,
                b + 10,
                b + 11,
                b + 12,
                b + 13,
                b + 14,
                b + 15,
            ],
        );
    }
    for i in 0..8 {
        let b = 2 * i;
        blake2_round(
            &mut r,
            [
                b,
                b + 1,
                b + 16,
                b + 17,
                b + 32,
                b + 33,
                b + 48,
                b + 49,
                b + 64,
                b + 65,
                b + 80,
                b + 81,
                b + 96,
                b + 97,
                b + 112,
                b + 113,
            ],
        );
    }

    for i in 0..QWORDS_IN_BLOCK {
        next[i] = tmp[i] ^ r[i];
    }
}

#[inline(always)]
fn f_bla_mka(x: u64, y: u64) -> u64 {
    let xy = (x & 0xFFFF_FFFF).wrapping_mul(y & 0xFFFF_FFFF);
    x.wrapping_add(y).wrapping_add(xy.wrapping_mul(2))
}

#[inline(always)]
fn g(v: &mut Block, a: usize, b: usize, c: usize, d: usize) {
    v[a] = f_bla_mka(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = f_bla_mka(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = f_bla_mka(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = f_bla_mka(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

#[inline(always)]
fn blake2_round(v: &mut Block, i: [usize; 16]) {
    g(v, i[0], i[4], i[8], i[12]);
    g(v, i[1], i[5], i[9], i[13]);
    g(v, i[2], i[6], i[10], i[14]);
    g(v, i[3], i[7], i[11], i[15]);
    g(v, i[0], i[5], i[10], i[15]);
    g(v, i[1], i[6], i[11], i[12]);
    g(v, i[2], i[7], i[8], i[13]);
    g(v, i[3], i[4], i[9], i[14]);
}
