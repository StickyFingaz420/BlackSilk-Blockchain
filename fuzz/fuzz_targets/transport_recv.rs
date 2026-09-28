//! The transport's receive path (`recv_limited`) against an authentic peer
//! and a scripted relay. The body and its invariants:
//! src/targets/transport_recv.rs (shared with p2p/tests/fuzz_transport.rs).
#![no_main]
use libfuzzer_sys::fuzz_target;

#[path = "../src/targets/transport_recv.rs"]
#[allow(dead_code)] // `seeds` is for src/seeds.rs and the stable driver.
mod body;

fuzz_target!(|data: &[u8]| body::run(data));
