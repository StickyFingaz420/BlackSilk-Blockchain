//! Record delivery from a malicious sender under the stable fuzz driver: the
//! body of the `delivery_plain` fuzz target (fuzz/src/targets/
//! delivery_plain.rs) on seeded mutations of its seeds.
//! `BLACKSILK_FUZZ_ITERS` scales it (fuzz/src/targets/driver.rs).

#[path = "../../fuzz/src/targets/driver.rs"]
mod driver;
#[path = "../../fuzz/src/targets/delivery_plain.rs"]
mod target;

#[test]
fn delivery_plain_survives_mutation() {
    let seeds: Vec<Vec<u8>> = target::seeds().into_iter().map(|(_, s)| s).collect();
    driver::drive("delivery_plain", &seeds, 256, target::run);
    assert!(target::OPENED.load(std::sync::atomic::Ordering::Relaxed) > 0);
}
