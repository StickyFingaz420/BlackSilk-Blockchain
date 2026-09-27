//! Upstream advisory suite (24 I3, I6): one negative test per Plonky3 fix made
//! after 0.7.0 that applies to BlackSilk's configuration, each naming its
//! upstream pull request, plus the integrity pin of the patched crates in
//! `third_party/`.
//!
//! BlackSilk runs Plonky3 `=0.7.0`. Each fix below is **absent** from 0.7.0
//! (dossier 24 §3.1, checked with the GitHub compare API); BlackSilk closes the
//! gap with its own rule, run before or around the Plonky3 verifier
//! (docs/proof-system.md §4–§6). Where the 0.7.0 verifier alone still accepts
//! the rewrite, the test asserts that too, so an upstream change is noticed.
//! A proof that must be refused may be refused at decode (`Encoding`) or by
//! verification (`Invalid`, or `VerifierPanicked` for a contained panic), but
//! never accepted and never with an escaped panic.

use blacksilk_crypto::hash::Hasher64;
use blacksilk_zk::config::{ProverConfig, Val, VerifierConfig};
use blacksilk_zk::{decode_proof, encode_proof, prove, verify, Proof, ZkError};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::{InteractionBuilder, LookupBus};
use p3_matrix::dense::RowMajorMatrix;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

const RANGE: LookupBus<'static> = LookupBus::new("test/range");
const LIMITS: [usize; 2] = [16, 16];
const N: usize = 256;

/// Two tables: a counter whose values are looked up in a range table. With
/// `preprocessed`, the range table's values are a Plonky3-preprocessed column
/// (so its instance opens `preprocessed_local`, the case of #2256).
#[derive(Clone, Copy, Debug)]
enum Toy {
    Counter,
    Range,
    PreRange,
}

impl<F: p3_field::Field> BaseAir<F> for Toy {
    fn width(&self) -> usize {
        match self {
            Toy::Counter | Toy::PreRange => 1,
            Toy::Range => 2,
        }
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        match self {
            Toy::PreRange => Some(RowMajorMatrix::new(
                (0..N as u32).map(F::from_u32).collect(),
                1,
            )),
            _ => None,
        }
    }
    fn preprocessed_width(&self) -> usize {
        usize::from(matches!(self, Toy::PreRange))
    }
    /// The range table reads only the current preprocessed row, so the proof
    /// opens its preprocessed column at ζ only (`preprocessed_next` is None).
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }
}

impl<AB: AirBuilder<F = Val> + InteractionBuilder> Air<AB> for Toy {
    fn eval(&self, b: &mut AB) {
        let main: Vec<AB::Expr> = b
            .main()
            .current_slice()
            .iter()
            .map(|v| (*v).into())
            .collect();
        match self {
            Toy::Counter => RANGE.lookup_key(b, [main[0].clone()], 1),
            Toy::Range => {
                let next: Vec<AB::Expr> =
                    b.main().next_slice().iter().map(|v| (*v).into()).collect();
                b.when_first_row().assert_zero(main[0].clone());
                b.when_transition()
                    .assert_zero(next[0].clone() - main[0].clone() - AB::Expr::ONE);
                RANGE.table_entry(b, [main[0].clone()], main[1].clone());
            }
            Toy::PreRange => {
                let v: AB::Expr = b.preprocessed().current_slice()[0].into();
                RANGE.table_entry(b, [v], main[0].clone());
            }
        }
    }
}

/// Counter over `i / 2` for `i < N`; the range table provides each value
/// twice for the first `N / 2` values.
fn statement(preprocessed: bool) -> ([Toy; 2], Vec<RowMajorMatrix<Val>>, Vec<Vec<Val>>) {
    let counter = RowMajorMatrix::new((0..N as u32).map(|i| Val::from_u32(i / 2)).collect(), 1);
    let mult: Vec<Val> = (0..N)
        .map(|v| if v < N / 2 { Val::TWO } else { Val::ZERO })
        .collect();
    if preprocessed {
        (
            [Toy::Counter, Toy::PreRange],
            vec![counter, RowMajorMatrix::new(mult, 1)],
            vec![vec![], vec![]],
        )
    } else {
        let mut table = Vec::with_capacity(2 * N);
        for (v, m) in mult.iter().enumerate() {
            table.extend([Val::from_u32(v as u32), *m]);
        }
        (
            [Toy::Counter, Toy::Range],
            vec![counter, RowMajorMatrix::new(table, 2)],
            vec![vec![], vec![]],
        )
    }
}

fn proof(preprocessed: bool, seed: u64) -> ([Toy; 2], Proof, Vec<Vec<Val>>) {
    let (airs, traces, pv) = statement(preprocessed);
    let cfg = ProverConfig::new(&[seed as u8; 32], &mut ChaCha20Rng::seed_from_u64(seed));
    let p = prove(&cfg, &airs, &traces, &pv, &LIMITS).expect("honest proof");
    (airs, p, pv)
}

fn copy(p: &Proof) -> Proof {
    decode_proof(&encode_proof(p)).expect("an honest proof decodes")
}

/// Verifies with the caller's panics caught too: a panic escaping `verify`
/// fails the test, as does acceptance.
fn verify_refuses(airs: &[Toy], p: &Proof, pv: &[Vec<Val>], what: &str) -> ZkError {
    let v = VerifierConfig::new();
    match catch_unwind(AssertUnwindSafe(|| verify(&v, airs, p, pv, &LIMITS))) {
        Err(_) => panic!("{what}: a panic escaped verify()"),
        Ok(Ok(())) => panic!("{what}: accepted"),
        Ok(Err(e)) => e,
    }
}

#[test]
fn honest_proofs_verify() {
    for pre in [false, true] {
        let (airs, p, pv) = proof(pre, 1);
        let v = VerifierConfig::new();
        assert_eq!(verify(&v, &airs, &copy(&p), &pv, &LIMITS), Ok(()));
    }
}

/// Plonky3 #2106 (canonical proof-of-work witnesses at 0 bits). With
/// `COMMIT_POW_BITS = 0`, 0.7.0 neither absorbs nor checks the commit-phase
/// witnesses: rewriting **any** of them still verifies (a relayer could change
/// a transaction id), and the decoder refuses it (rule C1). The query witness
/// (16 bits) is bound: rewriting it fails verification.
#[test]
fn pr_2106_every_commit_phase_witness_rewrite_is_refused() {
    let (airs, p, pv) = proof(false, 2);
    let v = VerifierConfig::new();
    let n = p.opening_proof.1.commit_pow_witnesses.len();
    assert!(n > 0);
    for i in 0..n {
        for value in [1u32, 12_345, 2_013_265_920] {
            let mut r = copy(&p);
            r.opening_proof.1.commit_pow_witnesses[i] = Val::from_u32(value);
            // 0.7.0 alone accepts it (why rule C1 exists); `verify` applies
            // rule C1 itself (RTW1 defence in depth).
            assert!(
                matches!(
                    verify(&v, &airs, &r, &pv, &LIMITS),
                    Err(ZkError::Encoding(_))
                ),
                "witness {i} = {value} verified"
            );
            assert!(
                matches!(decode_proof(&encode_proof(&r)), Err(ZkError::Encoding(_))),
                "witness {i} = {value} decoded"
            );
        }
    }
    let mut q = copy(&p);
    q.opening_proof.1.query_pow_witness += Val::ONE;
    let bytes = encode_proof(&q);
    match decode_proof(&bytes) {
        Err(ZkError::Encoding(_)) => {}
        Ok(d) => {
            let e = verify_refuses(&airs, &d, &pv, "query witness + 1");
            assert!(matches!(e, ZkError::Invalid(_)), "{e:?}");
        }
        Err(e) => panic!("{e:?}"),
    }
}

/// Plonky3 #2256 (present-but-empty `preprocessed_next`). 0.7.0 compares only
/// lengths; on a table **with** preprocessed columns, `Some([])` reaches
/// `VerticalPair::new` and panics inside the verifier. The decoder refuses it
/// (rule C2); called directly, `verify` contains the panic (`VerifierPanicked`)
/// or refuses it, and never lets it escape. The same for `preprocessed_local`
/// on a table without preprocessed columns.
#[test]
fn pr_2256_present_but_empty_preprocessed_openings_are_refused() {
    let (airs, p, pv) = proof(true, 3);
    let pre_table = 1;
    assert!(p.opened_values.instances[pre_table]
        .base_opened_values
        .preprocessed_local
        .is_some());
    assert!(p.opened_values.instances[pre_table]
        .base_opened_values
        .preprocessed_next
        .is_none());
    // The upstream panic case: preprocessed width > 0, next row claimed empty.
    let mut r = copy(&p);
    r.opened_values.instances[pre_table]
        .base_opened_values
        .preprocessed_next = Some(vec![]);
    assert!(matches!(
        decode_proof(&encode_proof(&r)),
        Err(ZkError::Encoding(_))
    ));
    // `verify` applies rule C2 before Plonky3 runs (RTW1 defence in depth),
    // so the upstream panic is not reached.
    let e = verify_refuses(&airs, &r, &pv, "#2256 preprocessed_next = Some([])");
    println!("#2256 direct verify: {e:?}");
    assert!(matches!(e, ZkError::Encoding(_)), "{e:?}");
    // `preprocessed_local = Some([])` on the table without preprocessing: the
    // 0.7.0 verifier alone accepts it (an unbound field, so a relayer could
    // change a transaction id). The decoder refuses it, and so does `verify`
    // (rule C2 applied again); consensus paths still decode before they verify.
    let mut r = copy(&p);
    let o = &mut r.opened_values.instances[0].base_opened_values;
    assert!(o.preprocessed_local.is_none());
    o.preprocessed_local = Some(vec![]);
    assert!(matches!(
        decode_proof(&encode_proof(&r)),
        Err(ZkError::Encoding(_))
    ));
    assert!(matches!(
        verify(&VerifierConfig::new(), &airs, &r, &pv, &LIMITS),
        Err(ZkError::Encoding(_))
    ));
}

/// Plonky3 #2033 (fold schedule derived, not read from the proof). 0.7.0
/// accepts any per-round arities that sum right; BlackSilk requires the
/// canonical schedule (rule V3, R4-02) before Plonky3 runs.
#[test]
fn pr_2033_a_non_canonical_fold_schedule_is_refused() {
    let (airs, traces, pv) = {
        // Both tables at 2^12 rows: input height 16, final 9, canonical [4, 3].
        let n = 1usize << 12;
        let counter = RowMajorMatrix::new((0..n as u32).map(|i| Val::from_u32(i / 2)).collect(), 1);
        let mut table = Vec::with_capacity(2 * n);
        for v in 0..n {
            let m = if v < n / 2 { Val::TWO } else { Val::ZERO };
            table.extend([Val::from_u32(v as u32), m]);
        }
        (
            [Toy::Counter, Toy::Range],
            vec![counter, RowMajorMatrix::new(table, 2)],
            vec![vec![], vec![]],
        )
    };
    let cfg = ProverConfig::new(&[4; 32], &mut ChaCha20Rng::seed_from_u64(4));
    let p = prove(&cfg, &airs, &traces, &pv, &LIMITS).unwrap();
    let arities: Vec<u8> = p
        .opening_proof
        .1
        .commit_phase_openings
        .iter()
        .map(|o| o.log_arity)
        .collect();
    assert_eq!(arities, vec![4, 3]);
    let mut r = copy(&p);
    r.opening_proof.1.commit_phase_openings[0].log_arity = 3;
    r.opening_proof.1.commit_phase_openings[1].log_arity = 4;
    let r = decode_proof(&encode_proof(&r)).expect("the schedule is a verify rule");
    match verify_refuses(&airs, &r, &pv, "#2033 swapped arities") {
        ZkError::Invalid(e) => assert!(e.contains("not the canonical"), "{e}"),
        e => panic!("{e:?}"),
    }
}

/// Plonky3 #2277 (`MerkleCap` deserialization). 0.7.0 deserializes any root
/// count and compares only root 0 at cap height 0, while the transcript
/// absorbs all: a prover could append roots. The decoder requires exactly one
/// (rule C3, F24-2); a proof with a 2- or 3-root cap is never accepted.
#[test]
fn pr_2277_merkle_caps_with_other_root_counts_are_refused() {
    let (airs, p, pv) = proof(false, 5);
    for count in [2usize, 3] {
        let mut r = copy(&p);
        let root = r.commitments.main.roots()[0];
        r.commitments.main =
            postcard::from_bytes(&postcard::to_allocvec(&vec![root; count]).unwrap()).unwrap();
        assert!(matches!(
            decode_proof(&encode_proof(&r)),
            Err(ZkError::Encoding(_))
        ));
        let e = verify_refuses(&airs, &r, &pv, "#2277 extra cap roots");
        println!("{count}-root main cap, direct verify: {e:?}");
    }
}

// ------------------------------------------------ third_party integrity (24 I6)

/// The patched Plonky3 crates and the digest of their tracked files. The
/// patches are reviewed diffs against the registry sources
/// (third_party/README.md); any other change must be reviewed the same way
/// and this pin updated in the same commit.
const PATCHED: &[(&str, &str)] = &[
    (
        "p3-dft",
        "66963a144deb94759048ccf260dd7817307cda719d6c86c86864ccc385ee378a",
    ),
    (
        "p3-fri",
        "b163f77715e0a517a39da1b0c3575a7fa93b005326333278580d82cbb5d4778a",
    ),
    (
        "p3-merkle-tree",
        "16ed1e7db117e10db14d1a613502640357c7f9853e38d63bd78d922a6259780f",
    ),
];

/// Files of `dir` (recursively), as sorted '/'-separated relative paths,
/// without build outputs (`target/`, `Cargo.lock`).
fn files(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if path.is_dir() {
            if name != "target" {
                files(root, &path, out);
            }
        } else if name != "Cargo.lock" {
            let rel = path.strip_prefix(root).unwrap();
            let rel: Vec<String> = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().to_string())
                .collect();
            out.push((rel.join("/"), path));
        }
    }
}

/// Digest of a crate's files: path and content of each, with CRLF line ends
/// normalized to LF (git may check text files out either way).
fn crate_digest(dir: &Path) -> (String, usize) {
    let mut list = Vec::new();
    files(dir, dir, &mut list);
    list.sort();
    let mut h = Hasher64::new("zk/third-party-integrity");
    for (rel, path) in &list {
        let bytes = std::fs::read(path).unwrap();
        let mut normalized = Vec::with_capacity(bytes.len());
        for (i, b) in bytes.iter().enumerate() {
            if *b == b'\r' && bytes.get(i + 1) == Some(&b'\n') {
                continue;
            }
            normalized.push(*b);
        }
        h.update(&(rel.len() as u64).to_le_bytes());
        h.update(rel.as_bytes());
        h.update(&(normalized.len() as u64).to_le_bytes());
        h.update(&normalized);
    }
    let d: String = h.finalize()[..32]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    (d, list.len())
}

#[test]
fn third_party_patched_crates_are_pinned() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../third_party");
    let mut report = String::new();
    let mut ok = true;
    for (name, pinned) in PATCHED {
        let (digest, count) = crate_digest(&root.join(name));
        report.push_str(&format!("{name}: {digest} ({count} files)\n"));
        ok &= digest == *pinned;
    }
    println!("{report}");
    assert!(
        ok,
        "a patched Plonky3 crate in third_party/ changed. Review the diff against the \
         registry sources (third_party/README.md), then update PATCHED in the same commit:\n\
         {report}"
    );
}
