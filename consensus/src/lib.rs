//! BlackSilk header-chain consensus.
//!
//! Implements `docs/consensus.md`: the block header format, RandomX proof of work
//! (via `blacksilk-randomx`), LWMA-1 difficulty, timestamp rules, the transaction
//! Merkle root, best-chain selection and reorganization.
//!
//! The node validates with [`HeaderChain`], and the miner builds and checks
//! work with [`BlockTemplate`], [`BlockHeader`] and [`pow::check_hash`]. Both use
//! this crate, so they cannot disagree on what a valid block is.
//!
//! Everything here is deterministic integer arithmetic (plus RandomX, whose
//! floating point is emulated exactly). The only external input is the local clock,
//! used solely for the non-final future-time-limit check.

#![forbid(unsafe_code)]

// Consensus decoding and arithmetic assume 64-bit `usize` (lengths, counts and
// weights must convert identically on every node).
#[cfg(not(target_pointer_width = "64"))]
compile_error!("BlackSilk supports 64-bit targets only");

// Consensus bytes (headers, ids, the RandomX register file and scratchpad, the
// genesis nonce) are written with explicit little-endian conversions, but no
// big-endian build has ever been tested against the vectors, so none is
// allowed to run consensus (decision "Agent 08"; dossiers 01 and 05). Lift this
// only together with a big-endian CI leg that passes every vector.
#[cfg(target_endian = "big")]
compile_error!("BlackSilk supports little-endian targets only (untested on big-endian)");

pub mod chain;
pub mod difficulty;
pub mod hash;
pub mod header;
pub mod merkle;
pub mod params;
pub mod pow;
pub mod schedule;
pub mod timestamp;

pub use chain::{Accepted, BlockTemplate, HeaderChain, HeaderError, Reorg};
pub use difficulty::DIFFICULTY_RULE_ID;
pub use hash::Hash;
pub use header::{BlockHeader, HEADER_SIZE, HEADER_VERSION, NONCE_OFFSET};
pub use params::{ChainParams, Network, ParamsError};
pub use pow::{check_hash, seed_height, PowFunction, RandomXPow};
pub use schedule::{Epoch, Schedule};

#[cfg(test)]
mod tests {
    /// The byte layout of consensus encodings is explicit little-endian, not the
    /// host's order: the header of docs/consensus.md §2 field by field.
    #[test]
    fn consensus_encodings_are_explicit_little_endian() {
        let h = crate::BlockHeader {
            version: 0x0403_0201,
            height: 0x0c0b_0a09_0807_0605,
            prev_id: [0; 32],
            timestamp: 0x1413_1211_100f_0e0d,
            difficulty: 0x1c1b_1a19_1817_1615,
            tx_root: [0; 32],
            nonce: 0x2423_2221_201f_1e1d,
        };
        let b = h.to_bytes();
        assert_eq!(b[0..12], [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        assert_eq!(b[44..60], (13..=28).collect::<Vec<u8>>()[..]);
        assert_eq!(b[crate::NONCE_OFFSET..], [29, 30, 31, 32, 33, 34, 35, 36]);
        assert_eq!(crate::BlockHeader::from_bytes(&b), Some(h));
    }
}
