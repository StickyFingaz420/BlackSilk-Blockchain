//! The transport's key exchange and the first frame after it, against a
//! peer that does NOT hold the session keys (it sends arbitrary key bytes
//! and arbitrary frame bytes). Shallow by design. The body and its
//! invariants: src/targets/transport_keyless_peer.rs (shared with
//! p2p/tests/fuzz_keyless_peer.rs).
#![no_main]
use libfuzzer_sys::fuzz_target;

#[path = "../src/targets/transport_keyless_peer.rs"]
#[allow(dead_code)] // `seeds` is for src/seeds.rs and the stable driver.
mod body;

fuzz_target!(|data: &[u8]| body::run(data));
