//! `Addr` messages (v2 entries): canonical form and round trips. The body and
//! its invariants: src/targets/addr_v2.rs (shared with
//! p2p/tests/fuzz_addr.rs).
#![no_main]
use libfuzzer_sys::fuzz_target;

#[path = "../src/targets/addr_v2.rs"]
#[allow(dead_code)] // `seeds` is for src/seeds.rs and the stable driver.
mod body;

fuzz_target!(|data: &[u8]| body::run(data));
