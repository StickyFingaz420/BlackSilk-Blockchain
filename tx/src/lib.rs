//! BlackSilk transactions (`docs/transactions.md`).
//!
//! | Module | Content |
//! |---|---|
//! | [`params`] | consensus constants and per-network [`params::TxRules`] |
//! | [`codec`] | strict canonical encoding |
//! | [`types`] | transaction format, hashing, weight |
//! | [`px`] | private-execution transactions and private-contract deploys |
//! | [`validate`] | stateless, contextual and block-level rules |
//! | [`state`] | reference in-memory chain state with reorg undo |
//! | [`builder`] | wallet-side transfer and coinbase construction |
//! | [`scan`] | wallet-side scanning (view keys only) |
//! | [`decoy`] | wallet-side decoy selection (gamma picker) |
//!
//! Cryptography lives in `blacksilk-crypto`; header-chain rules live in
//! `blacksilk-consensus`, whose `merkle::tx_root` commits to [`types::Transaction::hash`].

#![forbid(unsafe_code)]

pub mod builder;
pub mod codec;
pub mod decoy;
pub mod params;
pub mod px;
pub mod px_builder;
pub mod scan;
pub mod state;
pub mod types;
pub mod validate;

pub use types::{Coinbase, Input, Output, Transaction, Transfer};
pub use validate::{BlockContext, BlockError, ChainView, TxError};

/// The build marker of this crate's test-only code (fault injection and the PX test constructors):
/// `Some("+test-hooks:tx")` when the `test-hooks` feature is compiled
/// in, `None` otherwise. A dev-dependency of a `cargo test` build turns the
/// feature on, and cargo unifies it into every binary that invocation builds;
/// the string is in a binary only when the hooks are. Binaries print it in
/// `--version` and refuse every network but regtest while it is set
/// (`blacksilk_chain::build_flags`, W4-GUARD).
#[cfg(feature = "test-hooks")]
pub const TEST_HOOKS_MARKER: Option<&str> = Some("+test-hooks:tx");
/// See the `test-hooks` variant: `None`, no test-only code compiled in.
#[cfg(not(feature = "test-hooks"))]
pub const TEST_HOOKS_MARKER: Option<&str> = None;
/// Whether this crate's `test-hooks` feature is compiled in.
pub const TEST_HOOKS: bool = TEST_HOOKS_MARKER.is_some();
