//! Equivalence-harness support (dossier 06 W2, dossier 05 C5): deterministic
//! (key, input) cases, a pinned digest over their hashes, and a differential
//! comparison of a candidate hash function against the current implementation.
//!
//! Any future optimized RandomX path (a batched dataset, a different
//! scratchpad layout, an FPU fast path) must pass `differential` against
//! [`light_hash`] on [`random_cases`], and leave the pinned digests and the
//! reference corpus in `tests/equivalence.rs` unchanged. Include this file
//! from a test with `mod support;`.
//!
//! What this cannot do: compare the VM state after one program or one
//! iteration. `Vm::run`, `execute` and the register file are private to
//! `vm.rs`, and reaching them would need a change to that file (a
//! `#[cfg(test)]` hook or dossier 06 W2's `reference.rs`); this harness is
//! deliberately test-only. A divergence is therefore localized only to the
//! (key, input) pair, not to a program or instruction.

#![allow(dead_code)] // each test binary uses its own subset

use blacksilk_randomx::{Cache, Vm, HASH_SIZE};
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use std::fmt;

pub type Hash = [u8; HASH_SIZE];

/// One RandomX hashing case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Case {
    pub key: Vec<u8>,
    pub input: Vec<u8>,
}

/// SplitMix64: a fixed, dependency-free stream, so every case is reproducible
/// from its seed on every platform.
pub struct Rng(pub u64);

impl Rng {
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_u64() as u8).collect()
    }
}

/// Input lengths that matter: BlackSilk's 47-byte PoW blob, Monero's 76-byte
/// hashing blob, a 100-byte header, the Blake2b block edges and the empty input.
const INPUT_LENGTHS: [usize; 10] = [47, 76, 100, 0, 1, 63, 64, 128, 129, 255];

/// `keys` keys of 32 bytes (BlackSilk's seed shape), `per_key` inputs each,
/// all derived from `seed`. Lengths cycle through `INPUT_LENGTHS` and then
/// random lengths below 512. Cases are grouped by key, so a hasher that
/// keeps its cache while the key is unchanged builds one cache per key.
pub fn random_cases(seed: u64, keys: usize, per_key: usize) -> Vec<Case> {
    let mut rng = Rng(seed);
    let mut cases = Vec::with_capacity(keys * per_key);
    for _ in 0..keys {
        let key = rng.bytes(32);
        for j in 0..per_key {
            let len = match INPUT_LENGTHS.get(j) {
                Some(&n) => n,
                None => (rng.next_u64() % 512) as usize,
            };
            let input = rng.bytes(len);
            cases.push(Case {
                key: key.clone(),
                input,
            });
        }
    }
    cases
}

/// The current implementation in light mode (what nodes verify with). Keeps
/// the cache of the last key, so grouped cases build one cache per key.
#[derive(Default)]
pub struct LightHasher {
    current: Option<(Vec<u8>, Cache)>,
}

impl LightHasher {
    pub fn hash(&mut self, case: &Case) -> Hash {
        if self.current.as_ref().is_none_or(|(k, _)| *k != case.key) {
            // Drop the old cache (256 MiB) before building the next one.
            self.current = None;
            self.current = Some((case.key.clone(), Cache::new(&case.key)));
        }
        let (_, cache) = self.current.as_ref().expect("cache just built");
        Vm::light(cache).hash(&case.input)
    }
}

/// The reference hash function of the harness: [`LightHasher`] as a closure.
pub fn light_hash() -> impl FnMut(&Case) -> Hash {
    let mut h = LightHasher::default();
    move |case| h.hash(case)
}

const DIGEST_DOMAIN: &[u8] = b"BlackSilk/RandomX/equivalence-digest/v1";

/// Blake2b-256 over the domain tag, then for each case: the key length (u32
/// LE), key, input length (u32 LE), input and its 32-byte hash.
pub fn digest(cases: &[Case], mut hash: impl FnMut(&Case) -> Hash) -> String {
    let mut h = Blake2bVar::new(32).expect("32-byte Blake2b");
    h.update(DIGEST_DOMAIN);
    for case in cases {
        h.update(&(case.key.len() as u32).to_le_bytes());
        h.update(&case.key);
        h.update(&(case.input.len() as u32).to_le_bytes());
        h.update(&case.input);
        h.update(&hash(case));
    }
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).expect("32-byte output");
    hex::encode(out)
}

/// The first case on which two hash functions disagree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mismatch {
    pub index: usize,
    pub case: Case,
    pub reference: Hash,
    pub candidate: Hash,
}

impl fmt::Display for Mismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "case {}: key={} input={} reference={} candidate={}",
            self.index,
            hex::encode(&self.case.key),
            hex::encode(&self.case.input),
            hex::encode(self.reference),
            hex::encode(self.candidate)
        )
    }
}

/// Runs both hash functions on every case and returns the number compared,
/// or the first disagreement.
pub fn differential(
    cases: &[Case],
    mut reference: impl FnMut(&Case) -> Hash,
    mut candidate: impl FnMut(&Case) -> Hash,
) -> Result<usize, Mismatch> {
    for (index, case) in cases.iter().enumerate() {
        let (r, c) = (reference(case), candidate(case));
        if r != c {
            return Err(Mismatch {
                index,
                case: case.clone(),
                reference: r,
                candidate: c,
            });
        }
    }
    Ok(cases.len())
}

/// One known answer of the reference corpus.
pub struct KnownAnswer {
    pub case: Case,
    pub hash: Hash,
}

/// Parses `key_hex input_hex hash_hex` lines ("-" for an empty field);
/// `#` starts a comment line.
pub fn parse_corpus(text: &str) -> Vec<KnownAnswer> {
    let field = |s: &str| {
        if s == "-" {
            Vec::new()
        } else {
            hex::decode(s).expect("hex field")
        }
    };
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let parts: Vec<&str> = l.split_whitespace().collect();
            assert_eq!(parts.len(), 3, "corpus line: {l}");
            KnownAnswer {
                case: Case {
                    key: field(parts[0]),
                    input: field(parts[1]),
                },
                hash: field(parts[2]).try_into().expect("32-byte hash"),
            }
        })
        .collect()
}
