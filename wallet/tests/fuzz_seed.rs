//! The 27-word seed parser under the stable fuzz driver: the body of the
//! `seed_words` fuzz target (fuzz/src/targets/seed_words.rs: a spec
//! Reed–Solomon encoder as oracle, verdicts by the number of changed words,
//! canonical re-encoding, parse and parse_correcting agreement) on seeded
//! mutations of its seed corpus, against the wallet crate itself.
//! `BLACKSILK_FUZZ_ITERS` scales it (fuzz/src/targets/driver.rs).

#[path = "../../fuzz/src/targets/driver.rs"]
mod driver;
#[path = "../../fuzz/src/targets/seed_words.rs"]
mod target;

/// What the target body names `super::seed`.
mod seed {
    pub use blacksilk_wallet::seed::{Seed, SeedError};
}

#[test]
fn seed_words_survive_mutation() {
    let seeds: Vec<Vec<u8>> = target::seeds().into_iter().map(|(_, s)| s).collect();
    driver::drive("seed_words", &seeds, 1024, target::run);
}
