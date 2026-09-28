//! A stable-toolchain driver for the fuzz target bodies in this directory.
//!
//! libFuzzer needs a nightly toolchain (and, on Windows, the MSVC ASan
//! runtime). The crate tests that include a target body with `#[path]` run it
//! through this driver instead: seeded, repeatable mutations of the target's
//! seed corpus (bit flips, byte overwrites, insertions, deletions,
//! truncations, duplication and splices of two seeds) plus purely random
//! inputs. No coverage feedback: it is a regression net that runs in every
//! `cargo test`, not a replacement for the coverage-guided campaigns
//! (fuzz/run_campaign.sh).
//!
//! `BLACKSILK_FUZZ_ITERS` sets the number of inputs (default 2,000, so the
//! normal suite stays fast); `BLACKSILK_FUZZ_SEED` the generator's seed.
//! Every seed input also runs unmutated, first.

/// SplitMix64: small, fast, and good enough to pick mutations; no dependency.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed)
    }

    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A value in `0..n` (`n > 0`).
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// The number of inputs a driver run feeds its target.
pub fn iterations() -> u64 {
    env_u64("BLACKSILK_FUZZ_ITERS", 2_000)
}

/// One mutation of `input` (possibly using `other`, another seed).
pub fn mutate(rng: &mut Rng, input: &mut Vec<u8>, other: &[u8], max_len: usize) {
    let rounds = 1 + rng.below(4);
    for _ in 0..rounds {
        match rng.below(9) {
            0 | 1 if !input.is_empty() => {
                let i = rng.below(input.len());
                input[i] ^= 1 << rng.below(8);
            }
            2 if !input.is_empty() => {
                let i = rng.below(input.len());
                input[i] = [0, 1, 0x7f, 0x80, 0xff][rng.below(5)] ^ (rng.next() as u8 & 1);
            }
            3 if !input.is_empty() => {
                let i = rng.below(input.len());
                input[i] = rng.next() as u8;
            }
            4 => {
                let i = rng.below(input.len() + 1);
                let n = 1 + rng.below(8);
                for _ in 0..n {
                    input.insert(i, rng.next() as u8);
                }
            }
            5 if !input.is_empty() => {
                let i = rng.below(input.len());
                let n = 1 + rng.below((input.len() - i).min(16));
                input.drain(i..i + n);
            }
            6 if !input.is_empty() => input.truncate(rng.below(input.len())),
            7 if !input.is_empty() => {
                // Duplicate a slice (repeated records, entries, frames).
                let i = rng.below(input.len());
                let n = 1 + rng.below((input.len() - i).min(64));
                let copy = input[i..i + n].to_vec();
                let at = rng.below(input.len() + 1);
                input.splice(at..at, copy);
            }
            8 if !other.is_empty() => {
                // Splice: our prefix, the other seed's suffix.
                let cut = rng.below(input.len() + 1);
                let from = rng.below(other.len());
                input.truncate(cut);
                input.extend_from_slice(&other[from..]);
            }
            _ => {}
        }
    }
    input.truncate(max_len);
}

/// Runs `target` on every seed, then on `iterations()` mutants and random
/// inputs of at most `max_len` bytes. Returns the number of inputs run.
pub fn drive(name: &str, seeds: &[Vec<u8>], max_len: usize, target: impl Fn(&[u8])) -> u64 {
    assert!(!seeds.is_empty(), "{name}: no seeds");
    let seed = env_u64("BLACKSILK_FUZZ_SEED", 0x6273_6675_7a7a);
    let mut rng = Rng::new(seed ^ name.bytes().fold(0u64, |h, b| h.rotate_left(5) ^ b as u64));
    for s in seeds {
        target(s);
    }
    let n = iterations();
    for _ in 0..n {
        let input = if rng.below(16) == 0 {
            let len = rng.below(max_len.min(4096) + 1);
            (0..len).map(|_| rng.next() as u8).collect()
        } else {
            let mut m = seeds[rng.below(seeds.len())].clone();
            let other = &seeds[rng.below(seeds.len())];
            mutate(&mut rng, &mut m, other, max_len);
            m
        };
        // A failure prints its input, so it can be minimized and kept as a
        // regression (fuzz/regressions/).
        if let Err(e) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| target(&input))) {
            let hex: String = input.iter().map(|b| format!("{b:02x}")).collect();
            eprintln!("{name}: failing input ({} bytes): {hex}", input.len());
            std::panic::resume_unwind(e);
        }
    }
    let total = seeds.len() as u64 + n;
    println!("{name}: {total} inputs (seed {seed:#x}); no panic, every invariant held");
    total
}
