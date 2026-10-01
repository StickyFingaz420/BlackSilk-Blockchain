//! Wallet-side output scanning under the stable fuzz driver: the body of the
//! `scan_outputs` fuzz target (fuzz/src/targets/scan_outputs.rs: decoded
//! transactions, and edits that splice real owned outputs into other
//! transactions or tamper with their fields, scanned by the paid wallet and a
//! stranger, each checked against an independent derivation with the
//! wallet's secret keys) on seeded mutations of its seed corpus.
//! `BLACKSILK_FUZZ_ITERS` scales it (fuzz/src/targets/driver.rs).

#[path = "../../fuzz/src/targets/driver.rs"]
mod driver;
#[path = "../../fuzz/src/targets/scan_outputs.rs"]
mod target;

#[test]
fn scanning_recognizes_exactly_the_outputs_paying_the_wallet() {
    let seeds: Vec<Vec<u8>> = target::seeds().into_iter().map(|(_, s)| s).collect();
    driver::drive("scan_outputs", &seeds, 1 << 16, target::run);
    println!("scan_outputs: {}", target::reached());
}
