//! Structure-aware edits of a real PX transfer proof, re-encoded and decoded
//! again. The body and its invariants: src/targets/proof_struct.rs (shared
//! with tx/tests/fuzz_decode.rs).
//!
//! The base proof is the seed generator's transfer proof
//! (`corpus/proof_decode/transfer`, written by `cargo run --release --bin
//! seeds` in `fuzz/`), read once. `BLACKSILK_FUZZ_SEEDS` names another
//! directory holding the generator's `corpus/`.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

#[path = "../src/targets/proof_struct.rs"]
#[allow(dead_code)] // `seeds` is for src/seeds.rs and the stable test.
mod body;

fn base() -> &'static body::Base {
    static B: OnceLock<body::Base> = OnceLock::new();
    B.get_or_init(|| {
        let dir = std::env::var("BLACKSILK_FUZZ_SEEDS").unwrap_or_else(|_| ".".into());
        let path = std::path::Path::new(&dir).join("corpus/proof_decode/transfer");
        let bytes = std::fs::read(&path).unwrap_or_else(|e| {
            panic!(
                "{}: {e} (run the seed generator first: cargo run --release --bin seeds)",
                path.display()
            )
        });
        body::Base::transfer(bytes)
    })
}

fuzz_target!(|data: &[u8]| body::run(base(), data));
