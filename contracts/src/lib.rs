//! BlackSilk confidential contracts (docs/research/wasm-contracts.md).
//!
//! **Frozen research, not consensus.** PX is the only consensus contract
//! platform (ADR-28-1, owner decision D22; docs/contracts.md, "Private contracts
//! on PX"). This crate is outside the root workspace, with its own Cargo.lock,
//! and no node, wallet or miner crate depends on it (README.md).
//!
//! | Module | Spec | Content |
//! |---|---|---|
//! | [`types`] | §4, §9.4 | notes, facts, fixed-layout records |
//! | [`profile`] | §9.1 | the consensus Wasm module profile |
//! | [`exec`] | §9 | deterministic execution: host API, fuel, storage accounting |
//! | [`state`] | §10 | contract state, diffs, per-block undo |
//! | [`smt`] | §10.2 | the sparse Merkle tree behind the state root |
//!
//! Signatures, claims and membership proofs are verified by the transaction
//! layer (`blacksilk-tx`) before execution; this crate exposes them to
//! contracts as facts.

#![forbid(unsafe_code)]

pub mod exec;
pub mod profile;
pub mod smt;
pub mod state;
pub mod types;

pub use exec::{CallRequest, DeployRequest, ExecError, Executor, Receipt};
pub use state::{ContractState, StateDiff};
pub use types::{ClaimFact, Id, MemberFact, Note, NoteBody, PrivateNote};
