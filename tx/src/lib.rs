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
