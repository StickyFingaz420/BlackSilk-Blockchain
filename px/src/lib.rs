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
//! - [`share`]: sharing a record's opening off chain, sealed to an address;
//! - [`fingerprint`]: the consensus manifest and its PX-side entries.
//!
//! Consensus uses [`state`] and [`prove`] through `blacksilk-tx` (transaction
//! kinds 2 and 3, docs/px.md §11).

#![forbid(unsafe_code)]

pub mod delivery;
pub mod fingerprint;
pub mod perm;
pub mod prove;
pub mod share;
pub mod state;
pub mod tree;
pub mod vault;
pub mod wallet;

pub use blacksilk_px_core as core;

/// The build marker of this crate's test-only code (the PX test constructors):
/// `Some("+test-hooks:px")` when the `test-hooks` feature is compiled
/// in, `None` otherwise. A dev-dependency of a `cargo test` build turns the
/// feature on, and cargo unifies it into every binary that invocation builds;
/// the string is in a binary only when the hooks are. Binaries print it in
/// `--version` and refuse every network but regtest while it is set
/// (`blacksilk_chain::build_flags`, W4-GUARD).
#[cfg(feature = "test-hooks")]
pub const TEST_HOOKS_MARKER: Option<&str> = Some("+test-hooks:px");
/// See the `test-hooks` variant: `None`, no test-only code compiled in.
#[cfg(not(feature = "test-hooks"))]
pub const TEST_HOOKS_MARKER: Option<&str> = None;
/// Whether this crate's `test-hooks` feature is compiled in.
pub const TEST_HOOKS: bool = TEST_HOOKS_MARKER.is_some();
