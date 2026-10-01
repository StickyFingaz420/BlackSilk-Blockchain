//! The admission of a relayed PX transaction: structure-aware edits of a
//! real PX deposit (and of its decoded proof) through the node's admission
//! steps and verification, on a fixed regtest chain with a registered
//! contract. The body and its invariants: src/targets/px_admission.rs
//! (shared with p2p/tests/fuzz_px_admission.rs).
//!
//! The chain is rebuilt at start (deterministic); the base transaction is
//! the seed generator's (`corpus/px_admission_base/tx`, written by `cargo
//! run --release --bin seeds` in `fuzz/` for the same chain), read once.
//! `BLACKSILK_FUZZ_SEEDS` names another directory holding the generator's
//! `corpus/`.
#![no_main]
use blacksilk_tx::types::Transaction;
use libfuzzer_sys::fuzz_target;

#[path = "../src/targets/px_admission.rs"]
#[allow(dead_code)] // `seeds` is for src/seeds.rs and the stable driver.
mod body;
#[path = "../src/targets/chain_fixture.rs"]
#[allow(dead_code)]
mod chain_fixture;
#[path = "../src/targets/proof_struct.rs"]
#[allow(dead_code)]
mod proof_struct;
#[path = "../src/targets/px_tx_struct.rs"]
#[allow(dead_code)]
mod px_tx_struct;

/// Built once per process (the chain manager is not `Sync`; libFuzzer runs
/// the target on one thread).
fn base() -> &'static body::Base {
    thread_local! {
        static B: &'static body::Base = Box::leak(Box::new(build()));
    }
    B.with(|b| *b)
}

fn build() -> body::Base {
    let dir = std::env::var("BLACKSILK_FUZZ_SEEDS").unwrap_or_else(|_| ".".into());
    let path = std::path::Path::new(&dir).join("corpus/px_admission_base/tx");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "{}: {e} (run the seed generator first: cargo run --release --bin seeds)",
            path.display()
        )
    });
    let Ok(Transaction::Px(tx)) = Transaction::decode(&bytes) else {
        panic!("{}: not a PX transaction", path.display());
    };
    let (chain, _, contract) = body::chain();
    body::Base::new(chain, contract, *tx)
}

fuzz_target!(|data: &[u8]| body::run(base(), data));
