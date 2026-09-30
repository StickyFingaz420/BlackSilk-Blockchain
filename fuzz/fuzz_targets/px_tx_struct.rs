//! Structure-aware edits of a real PX transaction, re-encoded and decoded
//! again. The body and its invariants: src/targets/px_tx_struct.rs (shared
//! with tx/tests/fuzz_decode.rs).
//!
//! The base is the seed generator's PX transaction with a short proof blob
//! (`corpus/tx_decode/px_short_proof`, written by `cargo run --release --bin
//! seeds` in `fuzz/`; the proof is opaque bytes to everything checked here),
//! read once. `BLACKSILK_FUZZ_SEEDS` names another directory holding the
//! generator's `corpus/`.
#![no_main]
use blacksilk_consensus::ChainParams;
use blacksilk_tx::params::{SigDomain, TxRules};
use blacksilk_tx::px::PxTx;
use blacksilk_tx::types::Transaction;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

#[path = "../src/targets/px_tx_struct.rs"]
#[allow(dead_code)] // `seeds` is for src/seeds.rs and the stable test.
mod body;

fn base() -> &'static (PxTx, SigDomain) {
    static B: OnceLock<(PxTx, SigDomain)> = OnceLock::new();
    B.get_or_init(|| {
        let dir = std::env::var("BLACKSILK_FUZZ_SEEDS").unwrap_or_else(|_| ".".into());
        let path = std::path::Path::new(&dir).join("corpus/tx_decode/px_short_proof");
        let bytes = std::fs::read(&path).unwrap_or_else(|e| {
            panic!(
                "{}: {e} (run the seed generator first: cargo run --release --bin seeds)",
                path.display()
            )
        });
        let Ok(Transaction::Px(tx)) = Transaction::decode(&bytes) else {
            panic!("{}: not a PX transaction", path.display());
        };
        let domain = TxRules::for_chain(&ChainParams::regtest()).domain();
        (*tx, domain)
    })
}

fuzz_target!(|data: &[u8]| {
    let (tx, domain) = base();
    body::run(tx, *domain, data)
});
