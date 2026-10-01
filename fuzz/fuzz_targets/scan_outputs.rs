//! Wallet-side output scanning: decoded transactions, and real owned
//! outputs spliced into other transactions or tampered with, scanned by the
//! paid wallet and a stranger. The body and its invariants:
//! src/targets/scan_outputs.rs (shared with tx/tests/fuzz_scan.rs).
#![no_main]
use libfuzzer_sys::fuzz_target;

#[path = "../src/targets/scan_outputs.rs"]
#[allow(dead_code)] // `seeds` is for src/seeds.rs and the stable driver.
mod body;

fuzz_target!(|data: &[u8]| body::run(data));
