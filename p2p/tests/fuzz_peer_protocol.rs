//! One connection's handshake negotiation and per-peer protocol under the
//! stable fuzz driver: the body of the `peer_protocol` fuzz target
//! (fuzz/src/targets/peer_protocol.rs: a scripted peer holding the session
//! keys against the node's own connection code, on a paused clock, checked
//! against a model of the negotiation) on seeded mutations of its seed
//! corpus. `BLACKSILK_FUZZ_ITERS` scales it (fuzz/src/targets/driver.rs).

#[path = "../../fuzz/src/targets/chain_fixture.rs"]
#[allow(dead_code)]
mod chain_fixture;
#[path = "../../fuzz/src/targets/driver.rs"]
mod driver;
#[path = "../../fuzz/src/targets/peer_protocol.rs"]
mod target;

#[test]
fn the_negotiation_follows_its_model_and_the_protocol_keeps_its_invariants() {
    let seeds: Vec<Vec<u8>> = target::seeds().into_iter().map(|(_, s)| s).collect();
    driver::drive("peer_protocol", &seeds, 256, target::run);
    println!("peer_protocol: {}", target::reached());
}
