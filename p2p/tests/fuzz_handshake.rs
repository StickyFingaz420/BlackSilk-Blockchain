//! The transport's key exchange under the stable fuzz driver: the body of
//! the `transport_handshake` fuzz target (fuzz/src/targets/
//! transport_handshake.rs: an unauthenticated peer's key, valid, invalid or
//! cut short, then raw bytes against the first `recv_limited`) on seeded
//! mutations of its seed corpus. `BLACKSILK_FUZZ_ITERS` scales it
//! (fuzz/src/targets/driver.rs).

#[path = "../../fuzz/src/targets/driver.rs"]
mod driver;
#[path = "../../fuzz/src/targets/transport_handshake.rs"]
mod target;

#[test]
fn transport_handshake_survives_mutation() {
    let seeds: Vec<Vec<u8>> = target::seeds().into_iter().map(|(_, s)| s).collect();
    driver::drive("transport_handshake", &seeds, 4096, target::run);
}
