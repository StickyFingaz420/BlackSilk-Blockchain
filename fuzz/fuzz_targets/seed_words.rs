//! The 27-word seed parser. The body and its invariants:
//! src/targets/seed_words.rs (shared with wallet/tests/fuzz_seed.rs).
//!
//! The parser is compiled from its own source file, wallet/src/seed.rs,
//! included by path: depending on the wallet crate would pull its RPC client
//! (reqwest, hyper), clap and argon2 into this workspace for one module that
//! needs none of them. The module has no `crate::` paths and only the
//! dependencies this workspace already has (consensus, crypto, zeroize,
//! getrandom), so this is the same code the wallet runs; the wallet test runs
//! the same body against the wallet crate itself.
#![no_main]
use libfuzzer_sys::fuzz_target;

#[path = "../../wallet/src/seed.rs"]
#[allow(dead_code)] // Only the parser and encoder are exercised here.
mod seed;

#[path = "../src/targets/seed_words.rs"]
#[allow(dead_code)] // `seeds` is for src/seeds.rs and the stable driver.
mod body;

fuzz_target!(|data: &[u8]| body::run(data));
