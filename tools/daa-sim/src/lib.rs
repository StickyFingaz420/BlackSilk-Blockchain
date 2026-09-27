//! Difficulty-rule simulation harness (research dossier 03, W1).
//!
//! This crate is evidence, not consensus. It drives the real consensus rules
//! ([`blacksilk_consensus::difficulty::next_difficulty`] and the MTP/FTL checks of
//! [`blacksilk_consensus::timestamp`]) and a set of candidate difficulty rules through
//! honest and adversarial mining scenarios:
//!
//! - honest block-time bias;
//! - hash-rate steps (10x up and down);
//! - hop-in/hop-out mining;
//! - timestamp-lowering strategies (dossier 04's families);
//! - the difficulty-raising private-branch race (Bahack 2013) by attacker share and
//!   confirmation depth;
//! - a full-history rewrite from genesis;
//! - start-up from a mis-set `D0`, and the genesis-to-launch gap.
//!
//! Candidate rules live here only ([`rules`]); nothing in this crate changes what
//! the node accepts. Randomness comes from an in-crate xoshiro256** generator with
//! fixed seeds, so every table is reproducible bit for bit on a given platform.

#![forbid(unsafe_code)]

pub mod adaptive;
pub mod family;
pub mod report;
pub mod rng;
pub mod rules;
pub mod scenarios;
pub mod selection;
pub mod sim;

pub use rules::{candidates, Asert, DifficultyRule, FnRule, Lwma, RiseCap};
pub use sim::Branch;
