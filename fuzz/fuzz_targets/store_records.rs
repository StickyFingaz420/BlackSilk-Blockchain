//! `blocks.dat` v2 records: bind, load, repair. The body and its invariants:
//! src/targets/store_records.rs (shared with chain/tests/fuzz_store.rs).
#![no_main]
use libfuzzer_sys::fuzz_target;

#[path = "../src/targets/store_records.rs"]
#[allow(dead_code)] // `seeds` is for src/seeds.rs and the stable driver.
mod body;

fuzz_target!(|data: &[u8]| body::run(data));
