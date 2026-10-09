//! RandomX equivalence harness (dossier 06 W2, dossier 05 C5; light mode).
//!
//! - `pinned_digest`: Blake2b over the hashes of 16 fixed pseudo-random
//!   (key, input) cases (2 keys of 32 bytes, 8 inputs each). Any change of a
//!   single hash changes the digest.
//! - `reference_corpus`: known answers produced by the reference
//!   implementation (tevador/RandomX v1.2.3 with BlackSilk's Argon2 salt,
//!   built off-tree; provenance in the data file's header). Its first 16
//!   entries are the digest cases, so the pinned digest is a reference value,
//!   not only a self-consistency value; the remaining entries (keys of 0, 1,
//!   31, 60, 61 and 128 bytes, inputs up to 2048 bytes) are hashed here.
//! - `pinned_digest_large` (ignored): 256 cases over 8 keys.
//! - `reused_vm_matches_fresh_vm` and the harness self-test: the
//!   differential API of `support`, for future candidate implementations.
//!
//! Run: `cargo test --release -p blacksilk-randomx --test equivalence`
//! (add `-- --ignored` for the large digest).

mod support;

use blacksilk_randomx::{Cache, Vm};
use support::{
    differential, digest, light_hash, parse_corpus, random_cases, Case, LightHasher, Rng,
};

/// Seeds of the case sets (changing one changes the cases, hence the pins).
const SEED_DIGEST: u64 = 0x0B5F_E901_0000_0016;
const SEED_LARGE: u64 = 0x0B5F_E901_0000_0256;
const SEED_DIFF: u64 = 0x0B5F_E901_D1FF_0004;
const SEED_EDGE: u64 = 0x0B5F_E901_ED6E_0008;

/// Blake2b digest of `random_cases(SEED_DIGEST, 2, 8)` (see `support::digest`),
/// computed from the reference implementation's hashes (`reference_corpus`
/// checks that).
const PINNED_DIGEST: &str = "de221b9e7096ee78781dccb49e1f350a55b7ee7c6d669a94f68a6496f4da12ab";
/// Blake2b digest of `random_cases(SEED_LARGE, 8, 32)`, also computed from the
/// reference implementation's hashes (2026-10-09, the driver of the corpus
/// file's header; the 256 hashes themselves are not committed).
const PINNED_DIGEST_LARGE: &str =
    "babcf78ebcd06cc16a5e951d8d3acea198a41f1f90d2ffe51265b4869ad5e0c1";

const CORPUS: &str = include_str!("data/randomx-reference-light-v1.txt");

fn digest_cases() -> Vec<Case> {
    random_cases(SEED_DIGEST, 2, 8)
}

/// Key and input shapes the random cases do not cover. Keys longer than 60
/// bytes reach Argon2 in full but SuperscalarHash only through their first
/// 60 bytes (`MAX_KEY_SIZE`), as in the reference.
fn edge_cases() -> Vec<Case> {
    let mut rng = Rng(SEED_EDGE);
    [
        (0, 0),
        (1, 47),
        (31, 76),
        (60, 100),
        (61, 100),
        (128, 1),
        (32, 1000),
        (32, 2048),
    ]
    .into_iter()
    .map(|(k, n)| Case {
        key: rng.bytes(k),
        input: rng.bytes(n),
    })
    .collect()
}

#[test]
fn pinned_digest() {
    assert_eq!(digest(&digest_cases(), light_hash()), PINNED_DIGEST);
}

#[test]
fn reference_corpus() {
    let corpus = parse_corpus(CORPUS);
    let (digest_part, edge_part) = corpus.split_at(16);

    // The digest cases, hashed by the reference: their digest is the pin.
    let cases = digest_cases();
    assert_eq!(digest_part.len(), cases.len());
    for (kat, case) in digest_part.iter().zip(&cases) {
        assert_eq!(&kat.case, case, "corpus order must follow digest_cases()");
    }
    let mut reference_hashes = digest_part.iter().map(|k| k.hash);
    let reference_digest = digest(&cases, |_| {
        reference_hashes.next().expect("one hash per case")
    });
    assert_eq!(
        reference_digest, PINNED_DIGEST,
        "the pinned digest is the reference's"
    );

    // The edge cases, hashed here.
    assert_eq!(
        edge_part.iter().map(|k| k.case.clone()).collect::<Vec<_>>(),
        edge_cases(),
        "corpus order must follow edge_cases()"
    );
    let mut hasher = LightHasher::default();
    let mismatches: Vec<String> = edge_part
        .iter()
        .filter_map(|kat| {
            let got = hasher.hash(&kat.case);
            (got != kat.hash).then(|| {
                format!(
                    "key={} ({} B) input_len={} reference={} ours={}",
                    hex::encode(&kat.case.key),
                    kat.case.key.len(),
                    kat.case.input.len(),
                    hex::encode(kat.hash),
                    hex::encode(got)
                )
            })
        })
        .collect();
    assert!(
        mismatches.is_empty(),
        "{} of {} reference answers differ:\n{}",
        mismatches.len(),
        edge_part.len(),
        mismatches.join("\n")
    );
}

#[test]
#[ignore = "256 light-mode hashes over 8 keys (minutes)"]
fn pinned_digest_large() {
    assert_eq!(
        digest(&random_cases(SEED_LARGE, 8, 32), light_hash()),
        PINNED_DIGEST_LARGE
    );
}

/// A VM reused across inputs gives the same hashes as a fresh VM per input
/// (no state leaks from one hash into the next).
#[test]
fn reused_vm_matches_fresh_vm() {
    let cases = random_cases(SEED_DIFF, 1, 4);
    let cache = Cache::new(&cases[0].key);
    let mut reused = Vm::light(&cache);
    let compared = differential(
        &cases,
        |c| Vm::light(&cache).hash(&c.input),
        |c| reused.hash(&c.input),
    )
    .unwrap_or_else(|m| panic!("{m}"));
    assert_eq!(compared, 4);
}

/// The harness itself: identical functions pass; a candidate that differs on
/// one case is reported at exactly that case. No RandomX work.
#[test]
fn differential_reports_the_first_mismatch() {
    let cases = random_cases(1, 3, 5);
    let fake = |c: &Case| {
        let mut h = [0u8; 32];
        for (i, b) in c.key.iter().chain(&c.input).enumerate() {
            h[i % 32] ^= b.wrapping_add(i as u8);
        }
        h
    };
    assert_eq!(differential(&cases, fake, fake), Ok(15));
    let broken = |c: &Case| {
        let mut h = fake(c);
        if *c == cases[7] {
            h[31] ^= 1;
        }
        h
    };
    let m = differential(&cases, fake, broken).unwrap_err();
    assert_eq!(m.index, 7);
    assert_eq!(m.case, cases[7]);
    assert_ne!(m.reference, m.candidate);
    // The digest sees the same one-bit change.
    assert_ne!(digest(&cases, fake), digest(&cases, broken));
}

/// The case sets as `key_hex input_hex` lines ("-" when empty), in corpus
/// order (digest cases, edge cases, then the large set), for the off-tree
/// reference driver that produced `data/randomx-reference-light-v1.txt`.
/// Writes to the file named by `BLACKSILK_RX_REQUESTS`; without it (for
/// example in CI's `--ignored` run) it does nothing.
#[test]
#[ignore = "writes the reference-driver request file; not a check"]
fn write_reference_requests() {
    let Ok(path) = std::env::var("BLACKSILK_RX_REQUESTS") else {
        println!("BLACKSILK_RX_REQUESTS is not set; nothing written");
        return;
    };
    let field = |b: &[u8]| {
        if b.is_empty() {
            "-".to_string()
        } else {
            hex::encode(b)
        }
    };
    let lines: Vec<String> = digest_cases()
        .into_iter()
        .chain(edge_cases())
        .chain(random_cases(SEED_LARGE, 8, 32))
        .map(|c| format!("{} {}", field(&c.key), field(&c.input)))
        .collect();
    std::fs::write(&path, lines.join("\n") + "\n").expect("write requests");
}
