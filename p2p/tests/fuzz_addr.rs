//! The `Addr` (v2 entries) codec under the stable fuzz driver: the body of
//! the `addr_v2` fuzz target (fuzz/src/targets/addr_v2.rs: canonical form,
//! per-entry, text and listen-form round trips) on seeded mutations of its
//! seed corpus. `BLACKSILK_FUZZ_ITERS` scales it
//! (fuzz/src/targets/driver.rs).

#[path = "../../fuzz/src/targets/driver.rs"]
mod driver;
#[path = "../../fuzz/src/targets/addr_v2.rs"]
mod target;

#[test]
fn addr_messages_survive_mutation() {
    let seeds: Vec<Vec<u8>> = target::seeds().into_iter().map(|(_, s)| s).collect();
    driver::drive("addr_v2", &seeds, 64 * 1024, target::run);
}
