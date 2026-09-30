//! The transport's key exchange against a peer without the session keys,
//! under the stable fuzz driver: the body of the `transport_keyless_peer`
//! fuzz target (fuzz/src/targets/transport_keyless_peer.rs: the peer's key,
//! valid, invalid or cut short, then raw bytes against the first
//! `recv_limited`) on seeded mutations of its seed corpus.
//! `BLACKSILK_FUZZ_ITERS` scales it (fuzz/src/targets/driver.rs).

#[path = "../../fuzz/src/targets/driver.rs"]
mod driver;
#[path = "../../fuzz/src/targets/transport_keyless_peer.rs"]
mod target;

#[test]
fn a_keyless_peer_never_gets_a_payload_through() {
    let seeds: Vec<Vec<u8>> = target::seeds().into_iter().map(|(_, s)| s).collect();
    driver::drive("transport_keyless_peer", &seeds, 4096, target::run);
}
