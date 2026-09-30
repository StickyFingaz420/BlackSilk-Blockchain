//! The transport's key exchange and the first frame after it, from an
//! unauthenticated peer. The body and its invariants:
//! src/targets/transport_handshake.rs (shared with
//! p2p/tests/fuzz_handshake.rs).
#![no_main]
use libfuzzer_sys::fuzz_target;

#[path = "../src/targets/transport_handshake.rs"]
#[allow(dead_code)] // `seeds` is for src/seeds.rs and the stable driver.
mod body;

fuzz_target!(|data: &[u8]| body::run(data));
