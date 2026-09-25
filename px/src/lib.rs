//! BlackSilk private execution (PX), host side (docs/px.md).
//!
//! - [`perm`]: the Poseidon2 permutation for `blacksilk-px-core` on the host;
//! - [`tree`]: the depth-32 commitment tree (full tree for wallets and tests,
//!   constant-size frontier for nodes);
//! - [`state`]: the consensus state (tree frontier, root window, nullifier
//!   set, pool balance) with block application and undo;
//! - [`wallet`]: keys from the wallet seed, record creation, witnesses;
//! - [`delivery`]: hybrid (Ristretto + ML-KEM-768) record encryption;
//! - [`prove`]: proving and verifying transfers with the kernel program;
//! - [`vault`]: the reference private contract (a hash-locked vault), host
//!   side;
//! - [`share`]: sharing a record's opening off chain, sealed to an address.
//!
//! Consensus uses [`state`] and [`prove`] through `blacksilk-tx` (transaction
//! kinds 2 and 3, docs/px.md §11).

#![forbid(unsafe_code)]

pub mod delivery;
pub mod perm;
pub mod prove;
pub mod share;
pub mod state;
pub mod tree;
pub mod vault;
pub mod wallet;

pub use blacksilk_px_core as core;
