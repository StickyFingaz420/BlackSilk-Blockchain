//! The admission of a relayed PX transaction under the stable fuzz driver:
//! the body of the `px_admission` fuzz target (fuzz/src/targets/
//! px_admission.rs: structure-aware edits of a real PX deposit and of its
//! decoded proof, through the node's admission steps and verification on a
//! fixed regtest chain with a registered contract) on seeded mutations of
//! its seed corpus. `BLACKSILK_FUZZ_ITERS` scales it
//! (fuzz/src/targets/driver.rs).
//!
//! PX-proving (one proof, 4 to 6 GB): ignored by default, so it never runs
//! beside other tests; CI runs it alone (`-- --ignored`) with the other
//! PX-proving tests.

#[path = "../../fuzz/src/targets/chain_fixture.rs"]
#[allow(dead_code)]
mod chain_fixture;
#[path = "../../fuzz/src/targets/driver.rs"]
mod driver;
#[path = "../../fuzz/src/targets/proof_struct.rs"]
#[allow(dead_code)]
mod proof_struct;
#[path = "../../fuzz/src/targets/px_tx_struct.rs"]
#[allow(dead_code)]
mod px_tx_struct;
#[path = "../../fuzz/src/targets/px_admission.rs"]
mod target;

use std::sync::atomic::{AtomicUsize, Ordering};

/// Panics anywhere in the process, contained or not: a Plonky3 panic the
/// verifier or the decoder contains (`catch_unwind`) is a finding too.
static PANICS: AtomicUsize = AtomicUsize::new(0);

#[test]
#[ignore = "PX-proving: run alone, with -- --ignored"]
fn px_admission_refuses_early_only_what_full_validation_refuses() {
    let (chain, mut miner, contract) = target::chain();
    let tx = target::deposit(&chain, &mut miner);
    let base = target::Base::new(chain, contract, tx);
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        PANICS.fetch_add(1, Ordering::SeqCst);
        default(info);
    }));
    let seeds: Vec<Vec<u8>> = target::seeds().into_iter().map(|(_, s)| s).collect();
    driver::drive("px_admission", &seeds, 256, |data| {
        let before = PANICS.load(Ordering::SeqCst);
        target::run(&base, data);
        assert_eq!(
            PANICS.load(Ordering::SeqCst),
            before,
            "a panic was contained during admission (see the message above)"
        );
    });
    println!("px_admission: {}", target::reached());
    // A digest of every input's verdicts, in order, and of the base
    // transaction (its proof included): two runs on the same tree must
    // print the same. `BLACKSILK_FUZZ_VERDICTS` names a file for the
    // per-input lines, to compare two runs line by line.
    let verdicts = target::VERDICTS.lock().unwrap();
    let digest = |parts: &[&[u8]]| {
        parts
            .iter()
            .flat_map(|p| p.iter())
            .fold(0xcbf2_9ce4_8422_2325u64, |h, &b| {
                (h ^ b as u64).wrapping_mul(0x0000_0100_0000_01b3)
            })
    };
    let lines: Vec<u8> = verdicts
        .iter()
        .flat_map(|l| l.bytes().chain(*b"\n"))
        .collect();
    println!(
        "px_admission: {} verdicts, digest {:016x}; base transaction digest {:016x}",
        verdicts.len(),
        digest(&[&lines]),
        digest(&[&base.encoded()])
    );
    if let Ok(path) = std::env::var("BLACKSILK_FUZZ_VERDICTS") {
        std::fs::write(&path, &lines).expect("the verdicts file");
    }
}
