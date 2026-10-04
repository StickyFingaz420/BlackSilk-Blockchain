//! The output Merkle mountain range (rule B-OMR, docs/consensus.md §7.1)
//! against the independent vectors of `tools/vectors/output_mmr.py`
//! (`tx/tests/data/output_mmr.txt`), computed there from the recursive
//! definition: leaf hashes, peaks, and roots for sizes 0 to 1 000, through
//! both the frontier (validation, miners) and the full range (the node's
//! state).
//!
//! Regenerate with `python tools/vectors/output_mmr.py --write`; `--check`
//! verifies the committed file.

use blacksilk_crypto::hash::{h32, tags};
use blacksilk_tx::mmr::{leaf, OutputFrontier, OutputMmr};

const TABLE: &str = include_str!("data/output_mmr.txt");

/// The script's i-th output.
fn vector_output(i: u64) -> ([u8; 32], [u8; 32], u64, bool) {
    // Untagged Blake2b-256.
    let b = |label: &[u8]| {
        blacksilk_consensus::hash::H::new()
            .chain(label)
            .chain(&i.to_le_bytes())
            .finish()
    };
    (
        b(b"mmr-vector/key"),
        b(b"mmr-vector/commitment"),
        i / 3,
        i.is_multiple_of(3),
    )
}

fn unhex(s: &str) -> [u8; 32] {
    assert_eq!(s.len(), 64, "{s}");
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

#[test]
fn the_output_range_matches_the_independent_vectors() {
    let leaves: Vec<[u8; 32]> = (0..1_000)
        .map(|i| {
            let (k, c, h, cb) = vector_output(i);
            leaf(&k, &c, h, cb)
        })
        .collect();
    let mut full = OutputMmr::new();
    for l in &leaves {
        full.push(*l);
    }
    let (mut n_leaf, mut n_peaks, mut n_root) = (0, 0, 0);
    for line in TABLE.lines().filter(|l| !l.starts_with('#')) {
        let v: Vec<&str> = line.split_whitespace().collect();
        let n: usize = v[1].parse().unwrap();
        match v[0] {
            "leaf" => {
                assert_eq!(leaves[n], unhex(v[2]), "leaf {n}");
                n_leaf += 1;
            }
            "peaks" => {
                let want: Vec<[u8; 32]> = if v[2] == "-" {
                    vec![]
                } else {
                    v[2].split(',').map(unhex).collect()
                };
                assert_eq!(full.frontier_at(n as u64).unwrap().peaks(), &want[..]);
                n_peaks += 1;
            }
            "root" => {
                let mut f = OutputFrontier::new();
                for l in &leaves[..n] {
                    f.push(*l);
                }
                assert_eq!(f.root(), unhex(v[2]), "frontier root {n}");
                assert_eq!(
                    full.frontier_at(n as u64).unwrap().root(),
                    unhex(v[2]),
                    "full-range root {n}"
                );
                n_root += 1;
            }
            other => panic!("unknown line {other}"),
        }
    }
    assert_eq!((n_leaf, n_peaks, n_root), (6, 6, 24));
    // The tags the script uses are the crate's.
    assert_eq!(
        h32(tags::OUTPUT_MMR_ROOT, &[&0u64.to_le_bytes()]),
        h32("output-mmr/root", &[&0u64.to_le_bytes()])
    );
}
