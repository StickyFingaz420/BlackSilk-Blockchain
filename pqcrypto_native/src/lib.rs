#![no_std]

#[macro_use]
extern crate alloc;

/// Native Rust PQ Key Generation Library
/// Implements deterministic keypair generation for Dilithium, Falcon, ML-DSA

pub mod algorithms;
pub mod utils;
pub mod wallet;
pub mod traits;
