//! Record delivery from a malicious sender, who can make the view tag and
//! the AEAD pass for any plaintext: the code after decryption. The body and
//! its invariants: src/targets/delivery_plain.rs (shared with
//! px/tests/fuzz_delivery_plain.rs).
#![no_main]
use libfuzzer_sys::fuzz_target;

#[path = "../src/targets/delivery_plain.rs"]
#[allow(dead_code)] // `seeds` is for src/seeds.rs and the stable driver.
mod body;

fuzz_target!(|data: &[u8]| body::run(data));
