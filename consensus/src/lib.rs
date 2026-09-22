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

pub mod chain;
pub mod difficulty;
pub mod hash;
pub mod header;
pub mod merkle;
pub mod params;
pub mod pow;
pub mod timestamp;

pub use chain::{Accepted, BlockTemplate, HeaderChain, HeaderError, Reorg};
pub use hash::Hash;
pub use header::{BlockHeader, HEADER_SIZE, HEADER_VERSION, NONCE_OFFSET};
pub use params::{ChainParams, Network};
pub use pow::{check_hash, seed_height, PowFunction, RandomXPow};
