//! `blacksilk-stratum-bridge`: an evidence and test tool for the pre-freeze
//! xmrig compatibility gate. It is not part of the release package, and no
//! node, miner or wallet links it.
//!
//! A loopback-only, Monero-style stratum server that lets a (locally
//! patched, `rx/blacksilk`) xmrig mine regtest blocks on a BlackSilk node.
//! Everything consensus-related is the node's own code: blocks from
//! `blacksilk_miner::build_block`, the PoW input from
//! `BlockHeader::pow_blob`, the hash from the node's `PowFunction`
//! (`RandomXPow::pow_hash` in the binary), the target check from
//! `check_hash`, and the node access through `blacksilk_rpc::Client`.
//! Nothing is re-implemented; a disagreement between xmrig and the node is
//! reported (`GATE-MISMATCH`), never worked around.
//!
//! Modules: [`target`] (the 64-bit share target), [`job`] (blob, nonce
//! layout), [`stratum`] (wire format, fixed reply strings), [`server`] (the
//! bridge), [`submit_log`] and [`recompute`] (every submit recorded and
//! recomputed offline), [`probe`] (the invalid-share client) and
//! [`build_guard`] (the `--version` format and the clean-build check).

#![forbid(unsafe_code)]

pub mod build_guard;
pub mod job;
pub mod probe;
pub mod recompute;
pub mod server;
pub mod stratum;
pub mod submit_log;
pub mod target;

pub use server::{Bridge, Config, ControlHash, MoneroRx0Light, Outcome, StartError};
