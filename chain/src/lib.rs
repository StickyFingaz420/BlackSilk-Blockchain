//! BlackSilk chain layer (`docs/blocks.md`): block format, emission, the chain
//! manager that keeps the header chain and the transaction state consistent across
//! reorganizations, the mempool, block storage and address strings.
//!
//! Shared by the node (validation), the miner (templates, block format) and the
//! wallet (addresses, amounts).

#![forbid(unsafe_code)]

pub mod address;
pub mod block;
pub mod emission;
pub mod manager;
pub mod mempool;
pub mod store;

pub use block::Block;
pub use manager::{ChainManager, SubmitError, Submitted, Template};
