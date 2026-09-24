//! BlackSilk private execution (PX), host side (docs/px.md).
//!
//! - [`perm`]: the Poseidon2 permutation for `blacksilk-px-core` on the host;
//! - [`tree`]: the depth-32 commitment tree (full tree for wallets and tests,
//!   constant-size frontier for nodes);
//! - [`state`]: the consensus state (tree frontier, root window, nullifier
//!   set, pool balance) with block application and undo;
//! - [`wallet`]: keys from the wallet seed, record creation, witnesses;
//! - [`delivery`]: hybrid (Ristretto + ML-KEM-768) record encryption;
//! - [`prove`]: proving and verifying transfers with the kernel program.
//!
//! **Not consensus yet.** Nothing here is wired into block validation; that is
//! a later phase (AUDIT.md R8).

#![forbid(unsafe_code)]

pub mod delivery;
pub mod perm;
pub mod prove;
pub mod state;
pub mod tree;
pub mod wallet;

pub use blacksilk_px_core as core;
