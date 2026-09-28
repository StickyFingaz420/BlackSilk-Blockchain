//! The transport's receive path under the stable fuzz driver: the body of
//! the `transport_recv` fuzz target (fuzz/src/targets/transport_recv.rs: a
//! real handshake, then scripted authentic, tampered, truncated, replayed
//! and raw frames against `recv_limited`) on seeded mutations of its seed
//! corpus. `BLACKSILK_FUZZ_ITERS` scales it (fuzz/src/targets/driver.rs).

#[path = "../../fuzz/src/targets/driver.rs"]
mod driver;
#[path = "../../fuzz/src/targets/transport_recv.rs"]
mod target;

#[test]
fn transport_receive_survives_mutation() {
    let seeds: Vec<Vec<u8>> = target::seeds().into_iter().map(|(_, s)| s).collect();
    driver::drive("transport_recv", &seeds, 4096, target::run);
}
