//! Record delivery and shares: arbitrary bytes never panic `open` or
//! `open_share`, and nothing opens without the recipient's keys.
#![no_main]
use blacksilk_px::delivery;
use blacksilk_px::share;
use blacksilk_px::wallet::Account;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn account() -> &'static Account {
    static A: OnceLock<Account> = OnceLock::new();
    A.get_or_init(|| Account::from_seed(&[42; 32]))
}

fuzz_target!(|data: &[u8]| {
    let a = account();
    let keys = a.delivery_keys(0);
    let owner = a.owner(0);
    let (cm, rho) = ([1u32; 8], [2u32; 8]);
    // A ciphertext that opens would have to encrypt a record committing to
    // `cm`, a 2^-124 event for fuzzed bytes.
    assert!(delivery::open(&keys, &owner, data, &cm, &rho).is_none());
    let _ = share::open_share(&keys, &owner, data);
});
