//! Real-permutation known-answer vectors for `Hk`, the tree node, the empty
//! roots (including the genesis PX root), frontier roots and the record
//! formulas (dossier 19 item 2, R2-C11 / P0-10).
//!
//! **Provenance.** `tests/data/hk_vectors.txt` is produced by
//! `tools/vectors/poseidon2_hk.py`, an independent Python implementation
//! (standard library only, test tooling, not core):
//! - Poseidon2-BabyBear-16 written from the paper's matrix definition, with the
//!   round constants and internal diagonal transcribed from the Plonky3 0.7.0
//!   registry source (`--registry` re-checks the transcription), and checked
//!   against Plonky3's own width-16 test vector;
//! - the sponge, node, tree and record formulas written from docs/px.md §2–§3
//!   and zk.md §4; the tree root from full levels, not a frontier.
//!
//! It shares no code with px-core or Plonky3. What it does share is the
//! instance (p, t = 16, α = 7, R_F = 8, R_P = 13 and the constants): these
//! vectors pin that BlackSilk computes `Hk` with that instance, not that the
//! instance is secure.
//!
//! Regenerate only for a deliberate consensus change:
//! `python tools/vectors/poseidon2_hk.py --write`; `--check` verifies the file.

use blacksilk_px::perm::HostPerm;
use blacksilk_px::state::State;
use blacksilk_px::tree::{empty_roots, Frontier, Tree};
use blacksilk_px::vault::{lock_of, LOCK_DOMAIN};
use blacksilk_px_core::call::{Call, OutSpec};
use blacksilk_px_core::hash::{domain, hash, node, Sponge};
use blacksilk_px_core::kernel::TREE_DEPTH;
use blacksilk_px_core::record::{
    contract_nullifier, diversifier, nullifier, output_rho, Keys, Record,
};
use blacksilk_px_core::{Digest, Permutation, P, ZERO_DIGEST};
use std::collections::BTreeMap;

const VECTORS: &str = include_str!("data/hk_vectors.txt");

/// Number of vectors in the file; a changed count means the file changed.
const COUNT: usize = 157;

fn vectors() -> BTreeMap<&'static str, &'static str> {
    let mut map = BTreeMap::new();
    for line in VECTORS.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, value) = line.split_once(" = ").expect("`name = hex` line");
        assert!(map.insert(name, value).is_none(), "duplicate vector {name}");
    }
    map
}

fn hex(words: &[u32]) -> String {
    words.iter().map(|w| format!("{w:08x}")).collect()
}

/// The script's input generator: `(seed · 1000003 + k · 0x9E3779B1) mod p`.
fn seq(n: usize, seed: u64) -> Vec<u32> {
    (0..n as u64)
        .map(|k| ((seed * 1_000_003 + k * 0x9E37_79B1) % P as u64) as u32)
        .collect()
}

fn digest(xs: &[u32]) -> Digest {
    xs.try_into().expect("8 elements")
}

fn leaf(i: u64) -> Digest {
    digest(&seq(8, 0x1000 + i))
}

fn limbs16(v: u64) -> [u32; 4] {
    [0, 1, 2, 3].map(|i| ((v >> (16 * i)) & 0xffff) as u32)
}

const DOMAINS: [(&str, u32); 10] = [
    ("SK", domain::SK),
    ("NK", domain::NK),
    ("AK", domain::AK),
    ("OWNER", domain::OWNER),
    ("DIVERSIFIER", domain::DIVERSIFIER),
    ("RECORD", domain::RECORD),
    ("NULLIFIER", domain::NULLIFIER),
    ("RHO", domain::RHO),
    ("IO", domain::IO),
    ("NULLIFIER_CONTRACT", domain::NULLIFIER_CONTRACT),
];
const LENGTHS: [usize; 8] = [0, 1, 7, 8, 9, 24, 52, 92];
const TREE_SIZES: [u64; 24] = [
    1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 300,
];

/// Checks one vector and records that it was checked.
struct Checker {
    want: BTreeMap<&'static str, &'static str>,
    seen: Vec<String>,
}

impl Checker {
    fn new() -> Self {
        Checker {
            want: vectors(),
            seen: Vec::new(),
        }
    }

    fn check(&mut self, name: &str, got: &[u32]) {
        let want = self
            .want
            .get(name)
            .unwrap_or_else(|| panic!("vector {name} missing from the file"));
        assert_eq!(hex(got), *want, "vector {name}");
        self.seen.push(name.to_string());
    }

    fn all_checked(&self) {
        assert_eq!(self.want.len(), COUNT, "the vector file changed size");
        for name in self.want.keys() {
            assert!(
                self.seen.iter().any(|s| s == name),
                "vector {name} is in the file but no test checks it"
            );
        }
    }
}

fn permutation(c: &mut Checker) {
    let mut perm = HostPerm::new();
    let mut s: [u32; 16] = [
        894848333, 1437655012, 1200606629, 1690012884, 71131202, 1749206695, 1717947831, 120589055,
        19776022, 42382981, 1831865506, 724844064, 171220207, 1299207443, 227047920, 1783754913,
    ];
    perm.permute(&mut s);
    c.check("perm.p3_kat", &s);
    let mut s: [u32; 16] = core::array::from_fn(|i| i as u32);
    perm.permute(&mut s);
    c.check("perm.iota", &s);
    let mut s = [0u32; 16];
    perm.permute(&mut s);
    c.check("perm.zero", &s);
}

fn domains_and_lengths(c: &mut Checker) {
    let mut perm = HostPerm::new();
    for (name, dom) in DOMAINS {
        for n in LENGTHS {
            let input = seq(n, dom as u64 + n as u64);
            let fast = hash(&mut perm, dom, &[&input]);
            let mut sponge = Sponge::new(dom, n as u32);
            sponge.absorb_all(&mut perm, &input);
            assert_eq!(sponge.finish(&mut perm), fast, "{name}/{n}: Sponge vs hash");
            c.check(&format!("hk.{name}.{n}"), &fast);
        }
    }
    c.check("hk.LOCK.8", &hash(&mut perm, LOCK_DOMAIN, &[&seq(8, 7)]));
}

fn nodes_and_empty_roots(c: &mut Checker) {
    let mut perm = HostPerm::new();
    c.check("node.zero", &node(&mut perm, &ZERO_DIGEST, &ZERO_DIGEST));
    let (a, b) = (digest(&seq(8, 1)), digest(&seq(8, 2)));
    c.check("node.ab", &node(&mut perm, &a, &b));
    c.check("node.ba", &node(&mut perm, &b, &a));

    let empty = empty_roots(&mut perm);
    for (h, e) in empty.iter().enumerate() {
        c.check(&format!("empty.{h}"), e);
    }
    let genesis = State::new().root();
    assert_eq!(genesis, empty[TREE_DEPTH]);
    c.check("genesis_px_root", &genesis);
    // Pinned inline as well: regenerating the file cannot move it unnoticed.
    assert_eq!(
        hex(&genesis),
        "46bcf20f54ecc12d5c53bf8e05063e0141d8e7266c11feea06cff9750f993ffd"
    );
}

fn frontier_roots(c: &mut Checker) {
    let mut perm = HostPerm::new();
    let empty = empty_roots(&mut perm);
    let mut frontier = Frontier::default();
    let mut tree = Tree::new(&mut perm);
    let mut sizes = TREE_SIZES.iter().peekable();
    for i in 0..*TREE_SIZES.last().unwrap() {
        frontier.append(&mut perm, leaf(i)).unwrap();
        tree.append(&mut perm, leaf(i)).unwrap();
        if sizes.peek() == Some(&&(i + 1)) {
            sizes.next();
            let root = frontier.root(&mut perm, &empty);
            assert_eq!(root, tree.root(), "size {}", i + 1);
            c.check(&format!("frontier.{}", i + 1), &root);
        }
    }
}

fn records(c: &mut Checker) {
    let mut perm = HostPerm::new();
    let sk = digest(&seq(8, 11));
    let keys = Keys::derive(&mut perm, &sk);
    c.check("key.nk", &keys.nk);
    c.check("key.ak", &keys.ak);
    let d = diversifier(&mut perm, &sk, 0x0001_2345);
    c.check("key.diversifier", &d);
    let owner = keys.owner(&mut perm, &d);
    c.check("key.owner", &owner);

    let (contract, asset) = (digest(&seq(8, 21)), digest(&seq(8, 22)));
    let value = 0x0123_4567_89AB_CDEF;
    let (data, rho, rcm) = (
        digest(&seq(8, 23)),
        digest(&seq(8, 24)),
        digest(&seq(8, 25)),
    );
    let record = Record {
        owner,
        contract,
        asset,
        value,
        data,
        rho,
        rcm,
    };
    let cm = record.commit(&mut perm);
    c.check("record.commit", &cm);
    c.check(
        "record.commit_plain",
        &Record::plain(owner, value, data, rho, rcm).commit(&mut perm),
    );
    let nf = nullifier(&mut perm, &keys.nk, &rho, &cm);
    c.check("record.nullifier", &nf);
    c.check(
        "record.contract_nullifier",
        &contract_nullifier(&mut perm, &contract, &rcm, &cm),
    );
    for j in 0..2 {
        c.check(&format!("record.rho.{j}"), &output_rho(&mut perm, &nf, j));
    }

    let call = Call {
        contract,
        approve: [Some(cm), None],
        spec: [
            None,
            Some(OutSpec {
                owner,
                contract,
                value: 5000,
                data: digest(&seq(8, 26)),
            }),
        ],
        blind: digest(&seq(8, 27)),
    };
    c.check("call.io_hash", &call.io_hash(&mut perm));

    c.check("vault.lock_of", &lock_of(&digest(&seq(8, 31))));
    // The value limbs the script uses are the record's.
    assert_eq!(limbs16(value), blacksilk_px_core::record::limbs(value));
}

#[test]
fn the_permutation_matches_the_independent_implementation() {
    permutation(&mut Checker::new());
}

#[test]
fn every_consensus_domain_and_length_matches() {
    domains_and_lengths(&mut Checker::new());
}

#[test]
fn nodes_empty_roots_and_the_genesis_root_match() {
    nodes_and_empty_roots(&mut Checker::new());
}

#[test]
fn frontier_and_full_tree_roots_match() {
    frontier_roots(&mut Checker::new());
}

#[test]
fn keys_records_nullifiers_rho_io_hash_and_lock_match() {
    records(&mut Checker::new());
}

/// Every vector in the file is checked, and the file has the expected size.
#[test]
fn every_vector_in_the_file_is_checked() {
    let mut c = Checker::new();
    permutation(&mut c);
    domains_and_lengths(&mut c);
    nodes_and_empty_roots(&mut c);
    frontier_roots(&mut c);
    records(&mut c);
    c.all_checked();
}
