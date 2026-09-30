//! The PX kernel, differentially: the native kernel and the kernel program
//! in the zkVM give the same verdict on any input words, and an accepted
//! witness fits the prover's budget. The body and its invariants:
//! src/targets/kernel_diff.rs (shared with px/tests/fuzz.rs).
#![no_main]
use libfuzzer_sys::fuzz_target;

#[path = "../src/targets/kernel_diff.rs"]
#[allow(dead_code)] // `check` and `Verdict` are for the stable test.
mod body;

fuzz_target!(|data: &[u8]| body::run_bytes(data));
