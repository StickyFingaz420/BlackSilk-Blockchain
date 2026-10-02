//! Start-up self-test of this build's RandomX (decisions "Agent 08"; the
//! second threat-model round, TM2-3).
//!
//! A RandomX build that hashes differently from everyone else (a
//! miscompilation, an unexpected floating-point environment, a different
//! AES backend) would show only as a fork. The node and the miner therefore
//! hash the reference implementation's known answers ([`VECTORS`], "Hash
//! test 1a" to "1f" of `src/tests/tests.cpp`) with the code they run, before
//! they verify or mine anything, and refuse to start on a mismatch.
//!
//! - [`self_test_light`]: the six vectors in light mode, the mode every node
//!   verifies with. The three keys' caches are built one at a time (256 MiB
//!   peak) and each key's vectors are hashed in parallel. The cost is about
//!   three cache builds and two light hashes (a few seconds; docs/testnet.md
//!   §4.2 has the measured figure).
//! - [`check_dataset`]: a miner's full-mode dataset against the cache it
//!   was expanded from (sampled items, and one hash in both modes). A
//!   full-mode run of the vectors themselves needs a 2 GiB dataset per key,
//!   too slow for every start: the miner's `--randomx-self-test` runs it on
//!   request.
//!
//! The vectors run through the same [`Cache`], [`Dataset`] and [`Vm`] code
//! that verifies and mines, in the same process, so the AES backend the
//! `aes` crate selects at run time is the one tested.

use crate::config::DATASET_ITEM_COUNT;
use crate::{Cache, Dataset, Vm, HASH_SIZE};
use std::time::{Duration, Instant};

/// One known answer: `Vm::light(&Cache::new(key)).hash(input) == hash`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vector {
    /// The reference's name, e.g. "1a".
    pub name: &'static str,
    pub key: &'static [u8],
    pub input: &'static [u8],
    pub hash: [u8; HASH_SIZE],
}

/// `N` bytes from `2 N` hex digits (compile time; a malformed literal fails
/// the build).
const fn unhex<const N: usize>(s: &str) -> [u8; N] {
    const fn digit(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("not a lowercase hex digit"),
        }
    }
    let b = s.as_bytes();
    assert!(b.len() == 2 * N, "wrong hex length");
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = (digit(b[2 * i]) << 4) | digit(b[2 * i + 1]);
        i += 1;
    }
    out
}

const KEY_000: &[u8] = b"test key 000";
const KEY_001: &[u8] = b"test key 001";
/// The 31-byte key of "Hash test 1f" (upstream PR #326).
const KEY_1F: [u8; 31] = unhex("7797373ea4633194640bf8d8c3b66724d6aa7bd2dc20e009df2f8f1710abe8");
const LOREM: &[u8] = b"sed do eiusmod tempor incididunt ut labore et dolore magna aliqua";
const INPUT_1E: [u8; 76] = unhex(
    "0b0b98bea7e805e0010a2126d287a2a0cc833d312cb786385a7c2f9de69d25537f584a9bc9977b00000000666fd8753bf61a8631f12984e3fd44f4014eca629276817b56f32e9b68bd82f416",
);
const INPUT_1F: [u8; 76] = unhex(
    "1010e1eaf8cf067b37b5f0ee031ab23ed1755e090a3af4415830145853e2be3e1f6821fed84dae58d00e00da5214d6c1f2d0622e0abd51f9373d04e0b0f8e6d6514d90689721c4aac5a9bb0d",
);

/// The reference implementation's hash tests 1a to 1f (light mode), the
/// vectors this crate's own tests pin (`lib.rs`, `hash_1a` to `hash_1f`).
pub const VECTORS: [Vector; 6] = [
    Vector {
        name: "1a",
        key: KEY_000,
        input: b"This is a test",
        hash: unhex("639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f"),
    },
    Vector {
        name: "1b",
        key: KEY_000,
        input: b"Lorem ipsum dolor sit amet",
        hash: unhex("300a0adb47603dedb42228ccb2b211104f4da45af709cd7547cd049e9489c969"),
    },
    Vector {
        name: "1c",
        key: KEY_000,
        input: LOREM,
        hash: unhex("c36d4ed4191e617309867ed66a443be4075014e2b061bcdaf9ce7b721d2b77a8"),
    },
    Vector {
        name: "1d",
        key: KEY_001,
        input: LOREM,
        hash: unhex("e9ff4503201c0c2cca26d285c93ae883f9b1d30c9eb240b820756f2d5a7905fc"),
    },
    Vector {
        name: "1e",
        key: KEY_001,
        input: &INPUT_1E,
        hash: unhex("c56414121acda1713c2f2a819d8ae38aed7c80c35c2a769298d34f03833cd5f1"),
    },
    Vector {
        name: "1f",
        key: &KEY_1F,
        input: &INPUT_1F,
        hash: unhex("78af2a1864c42abce36d2e8983e13df99b2af0ce1362999af09fab004d4435a8"),
    },
];

/// A self-test failure: what differed, the expected and the computed value
/// (hex).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mismatch {
    pub what: String,
    pub expected: String,
    pub got: String,
}

impl std::fmt::Display for Mismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: expected {}, computed {}",
            self.what, self.expected, self.got
        )
    }
}

impl std::error::Error for Mismatch {}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn words_hex(words: &[u64]) -> String {
    hex(&words
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect::<Vec<u8>>())
}

/// Hashes `vectors` in light mode and compares every answer. Keys are taken
/// in order of first use, one cache at a time; a key's vectors are hashed in
/// parallel. Returns the time taken, or the first mismatch (in `vectors`
/// order).
pub fn check_light(vectors: &[Vector]) -> Result<Duration, Mismatch> {
    let started = Instant::now();
    let mut keys: Vec<&[u8]> = Vec::new();
    for v in vectors {
        if !keys.contains(&v.key) {
            keys.push(v.key);
        }
    }
    let mut results: Vec<(usize, [u8; HASH_SIZE])> = Vec::with_capacity(vectors.len());
    for key in keys {
        let cache = Cache::new(key);
        std::thread::scope(|s| {
            let handles: Vec<_> = vectors
                .iter()
                .enumerate()
                .filter(|(_, v)| v.key == key)
                .map(|(i, v)| {
                    let cache = &cache;
                    s.spawn(move || (i, Vm::light(cache).hash(v.input)))
                })
                .collect();
            for h in handles {
                // A panic while hashing is a failure of this build too: it
                // propagates and stops the process.
                results.push(h.join().unwrap_or_else(|p| std::panic::resume_unwind(p)));
            }
        });
    }
    results.sort_unstable_by_key(|(i, _)| *i);
    for (i, got) in results {
        let v = &vectors[i];
        if got != v.hash {
            return Err(Mismatch {
                what: format!("RandomX hash test {} (light mode)", v.name),
                expected: hex(&v.hash),
                got: hex(&got),
            });
        }
    }
    Ok(started.elapsed())
}

/// [`check_light`] on the reference vectors [`VECTORS`].
pub fn self_test_light() -> Result<Duration, Mismatch> {
    check_light(&VECTORS)
}

/// Hashes `vectors` in full mode: per key, a cache and its dataset (2 GiB,
/// expanded on `threads` threads; one dataset at a time), the dataset
/// checked with [`check_dataset`], then the key's vectors. Minutes per key:
/// the miner's `--randomx-self-test` (the per-device check), not its start.
pub fn check_full(vectors: &[Vector], threads: usize) -> Result<Duration, Mismatch> {
    let started = Instant::now();
    let mut keys: Vec<&[u8]> = Vec::new();
    for v in vectors {
        if !keys.contains(&v.key) {
            keys.push(v.key);
        }
    }
    for key in keys {
        let cache = Cache::new(key);
        let dataset = Dataset::new(&cache, threads.max(1));
        check_dataset(&cache, &dataset)?;
        let mut vm = Vm::full(&dataset);
        for v in vectors.iter().filter(|v| v.key == key) {
            let got = vm.hash(v.input);
            if got != v.hash {
                return Err(Mismatch {
                    what: format!("RandomX hash test {} (full mode)", v.name),
                    expected: hex(&v.hash),
                    got: hex(&got),
                });
            }
        }
    }
    Ok(started.elapsed())
}

/// Dataset items [`check_dataset`] compares with the cache: the first, the
/// last and evenly spread ones between (the expansion runs in per-thread
/// chunks, so every chunk boundary region is near some sample).
pub const DATASET_SAMPLES: u64 = 4096;

/// The item numbers [`check_items`] compares among `count` items: `samples`
/// of them, the first and the last included.
fn sample_items(count: u64, samples: u64) -> impl Iterator<Item = u64> {
    let samples = samples.clamp(2, count.max(2));
    let last = count.saturating_sub(1);
    (0..samples).map(move |k| {
        // Evenly spread, ending exactly at the last item.
        (u128::from(k) * u128::from(last) / u128::from(samples - 1)) as u64
    })
}

/// Compares the items `item(n)` of an expanded dataset with the cache's own
/// computation at [`DATASET_SAMPLES`] item numbers.
fn check_items(cache: &Cache, count: u64, item: impl Fn(u64) -> [u64; 8]) -> Result<(), Mismatch> {
    for n in sample_items(count, DATASET_SAMPLES) {
        let (want, got) = (cache.dataset_item(n), item(n));
        if want != got {
            return Err(Mismatch {
                what: format!("RandomX dataset item {n}"),
                expected: words_hex(&want),
                got: words_hex(&got),
            });
        }
    }
    Ok(())
}

/// Checks a full-mode dataset against the cache it was expanded from: the
/// same key, sampled items equal to the cache's computation, and one input
/// hashed alike in full and light mode. Costs one light hash (the light
/// mode itself is covered by [`self_test_light`]).
pub fn check_dataset(cache: &Cache, dataset: &Dataset) -> Result<(), Mismatch> {
    if cache.key() != dataset.key() {
        return Err(Mismatch {
            what: "RandomX dataset key".into(),
            expected: hex(cache.key()),
            got: hex(dataset.key()),
        });
    }
    check_items(cache, DATASET_ITEM_COUNT, |n| dataset.item(n))?;
    let input = b"BlackSilk full-mode self-test";
    let (light, full) = (Vm::light(cache).hash(input), Vm::full(dataset).hash(input));
    if light != full {
        return Err(Mismatch {
            what: "RandomX full-mode hash (against light mode)".into(),
            expected: hex(&light),
            got: hex(&full),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pinned copies are the reference values (the strings of
    /// `lib.rs`'s `hash_1a`..`hash_1f`), and 1a is the fingerprint's known
    /// answer.
    #[test]
    fn the_vectors_are_the_reference_ones() {
        let names: Vec<&str> = VECTORS.iter().map(|v| v.name).collect();
        assert_eq!(names, ["1a", "1b", "1c", "1d", "1e", "1f"]);
        assert_eq!(VECTORS[0].key, crate::FINGERPRINT_KAT.key);
        assert_eq!(VECTORS[0].input, crate::FINGERPRINT_KAT.input);
        assert_eq!(hex(&VECTORS[0].hash), crate::FINGERPRINT_KAT.hash);
        assert_eq!(
            hex(&VECTORS[5].hash),
            "78af2a1864c42abce36d2e8983e13df99b2af0ce1362999af09fab004d4435a8"
        );
        assert_eq!(KEY_1F.len(), 31);
        assert_eq!(hex(&KEY_1F[..4]), "7797373e");
    }

    /// The self-test passes on this build, and a wrong answer is reported
    /// with the vector's name (the check is not vacuous).
    #[test]
    fn the_self_test_passes_and_detects_a_wrong_answer() {
        self_test_light().expect("this build hashes the reference vectors");
        let mut wrong = VECTORS[1];
        wrong.hash[31] ^= 1;
        let e = check_light(&[VECTORS[0], wrong]).unwrap_err();
        assert_eq!(e.what, "RandomX hash test 1b (light mode)");
        assert_eq!(e.got, hex(&VECTORS[1].hash));
        assert!(e.to_string().contains("expected"), "{e}");
    }

    /// The dataset check compares the items it is given with the cache's
    /// (a dataset of 2 GiB is too big for a unit test: the item source is
    /// the cache itself here, then one corrupted item).
    #[test]
    fn the_dataset_check_detects_a_wrong_item() {
        let cache = Cache::new(b"test key 000");
        let count = 1 << 20;
        assert!(check_items(&cache, count, |n| cache.dataset_item(n)).is_ok());
        let bad = sample_items(count, DATASET_SAMPLES).nth(1000).unwrap();
        let e = check_items(&cache, count, |n| {
            let mut it = cache.dataset_item(n);
            if n == bad {
                it[3] ^= 1 << 40;
            }
            it
        })
        .unwrap_err();
        assert_eq!(e.what, format!("RandomX dataset item {bad}"));
    }

    /// The miner's per-device check in full mode passes (one key: a 2 GiB
    /// dataset; run with the crate's other `--ignored` full-mode test).
    #[test]
    #[ignore]
    fn the_full_mode_check_passes() {
        let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
        check_full(&VECTORS[..1], threads).expect("full mode");
    }

    /// The samples cover the first and last item, are increasing and
    /// distinct, and stay in range.
    #[test]
    fn dataset_samples_span_the_dataset() {
        let s: Vec<u64> = sample_items(DATASET_ITEM_COUNT, DATASET_SAMPLES).collect();
        assert_eq!(s.len() as u64, DATASET_SAMPLES);
        assert_eq!(s[0], 0);
        assert_eq!(*s.last().unwrap(), DATASET_ITEM_COUNT - 1);
        assert!(s.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(sample_items(1, 8).collect::<Vec<_>>(), [0, 0]);
    }
}
