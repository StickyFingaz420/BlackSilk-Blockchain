//! One connection's handshake negotiation and per-peer protocol, against a
//! scripted peer that holds the session keys, on a paused clock. The body
//! and its invariants: src/targets/peer_protocol.rs (shared with
//! p2p/tests/fuzz_peer_protocol.rs).
#![no_main]
use libfuzzer_sys::fuzz_target;

#[path = "../src/targets/peer_protocol.rs"]
#[allow(dead_code)] // `seeds` is for src/seeds.rs and the stable driver.
mod body;
#[path = "../src/targets/chain_fixture.rs"]
#[allow(dead_code)]
mod chain_fixture;

fuzz_target!(|data: &[u8]| {
    // Both ends' ephemeral secrets fixed: an input replays exactly (fuzz
    // builds only; `transport::fuzzing`).
    #[cfg(fuzzing)]
    blacksilk_p2p::transport::fuzzing::set_ephemeral_seed(Some(7));
    body::run(data)
});
