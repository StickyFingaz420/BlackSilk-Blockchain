//! BlackSilk chain layer (`docs/blocks.md`): block format, emission, the chain
//! manager that keeps the header chain and the transaction state consistent across
//! reorganizations, the mempool, block storage and address strings.
//!
//! Shared by the node (validation), the miner (templates, block format) and the
//! wallet (addresses, amounts).

#![forbid(unsafe_code)]

pub mod actor;
pub mod address;
pub mod block;
pub mod build_flags;
pub mod emission;
pub mod manager;
pub mod mempool;
pub mod store;
pub mod sync_policy;

pub use block::Block;
pub use manager::{ChainManager, SubmitError, Submitted, Template};

/// The build marker of this crate's test-only code (fault injection, the step delay, and the chain actor's linearization log and panic command):
/// `Some("+test-hooks:chain")` when the `test-hooks` feature is compiled
/// in, `None` otherwise. A dev-dependency of a `cargo test` build turns the
/// feature on, and cargo unifies it into every binary that invocation builds;
/// the string is in a binary only when the hooks are. Binaries print it in
/// `--version` and refuse every network but regtest while it is set
/// (`blacksilk_chain::build_flags`, W4-GUARD).
#[cfg(feature = "test-hooks")]
pub const TEST_HOOKS_MARKER: Option<&str> = Some("+test-hooks:chain");
/// See the `test-hooks` variant: `None`, no test-only code compiled in.
#[cfg(not(feature = "test-hooks"))]
pub const TEST_HOOKS_MARKER: Option<&str> = None;
/// Whether this crate's `test-hooks` feature is compiled in.
pub const TEST_HOOKS: bool = TEST_HOOKS_MARKER.is_some();
