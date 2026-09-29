//! The circuit fingerprint (23 W2, 22 W4, RTW1-3): `CIRCUIT_ID` names the
//! BVM-1 constraint system, and this test ties the name to the constraints
//! themselves. It fingerprints every table of the reference statements of 1
//! to `MAX_EXECUTIONS` executions (`air::check::fingerprint`: their constraint
//! evaluations at seeded points, widths and table order, the contents of the
//! byte table and of the reference programs', images' and outputs' public
//! columns, the next-row column sets and the constraint hints), together with
//! the reference statements' `statement_digest`, the height limits and the
//! blinding width, and requires the digest to be the one pinned for the
//! current `CIRCUIT_ID`.
//!
//! **When this test fails** because an AIR, a bus, a table's width, a fixed
//! table, a public-column layout, a next-row set or the table order changed:
//! that is a consensus change. In the same commit, bump `CIRCUIT_ID`
//! (zkvm/src/prove.rs) and **append** a line to `REVISIONS` (the failure
//! message prints its `prev`), then set `REVISIONS_HEAD`, and set
//! `CIRCUIT_DIGEST` and `CIRCUIT_DIGEST_METHOD` (zkvm/src/prove.rs, listed in
//! the consensus manifest) to the new line. If only the
//! digest's coverage changed (a new `DIGEST_METHOD`, no AIR change), append a
//! line with the same id and the new method. Never edit an existing line:
//! `the_revisions_are_append_only` enforces it with a hash chain (RTW1-6).
//! Native, no proving; instant.

use blacksilk_crypto::hash::Hasher64;
use blacksilk_zk::config::Val;
use blacksilk_zkvm::air::check::{fingerprint, FingerprintBuilder};
use blacksilk_zkvm::air::trace::{self, Part, Statement, MAX_EXECUTIONS};
use blacksilk_zkvm::air::{util, Table};
use blacksilk_zkvm::asm::{reg::*, Asm};
use blacksilk_zkvm::prove::{
    limits, statement_digest, CIRCUIT_DIGEST, CIRCUIT_DIGEST_METHOD, CIRCUIT_ID,
};
use blacksilk_zkvm::Program;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::InteractionBuilder;
use std::borrow::Cow;
use std::sync::Arc;

/// One circuit revision: its id, the method its digest was computed with,
/// the digest, and the chain hash of every earlier line (`chain`), so an
/// edit of an earlier line breaks every later one.
#[derive(Clone, Copy, Debug)]
struct Revision {
    id: &'static [u8],
    method: u32,
    digest: &'static str,
    prev: &'static str,
}

/// The digest method `circuit_digest` implements:
/// 1. constraint evaluations, widths, table order, height limits and the
///    blinding width (until RTW1-3);
/// 2. method 1, plus the contents of the fixed and public columns, the
///    next-row column sets, the constraint hints and the reference
///    statements' `statement_digest` (RTW1-3).
const DIGEST_METHOD: u32 = 2;

/// Every circuit revision, oldest first. The last line must be the current
/// `CIRCUIT_ID` with the current `DIGEST_METHOD`. Append only.
const REVISIONS: &[Revision] = &[
    Revision {
        id: b"BlackSilk/zkvm/BVM-1/circuit/v1",
        method: 1,
        digest: "cfbeee3350f718f0a38083ec4778922dbb328888cfaf2fd800a531a09934a75a",
        prev: "48a4804476f3276b0d870f2ae19c56715b852024e0714119794f867d756f9f95",
    },
    // RTW1-3: the same circuit; the digest now also covers the fixed and
    // public columns and the next-row sets (docs/reviews/v3-consensus-changes.md,
    // "Follow-up (RTW1-3/6/8)").
    Revision {
        id: b"BlackSilk/zkvm/BVM-1/circuit/v1",
        method: 2,
        digest: "bcaba6c607782a75a0b9130eddb8d284dd35a95350355d9d9d87fe5db3cbe941",
        prev: "7159af12979b292dcdff8f5f993f8b33f3d303ea5443100f42b26f4f29cb6a99",
    },
];

/// The chain hash of the whole of `REVISIONS`: appending a line updates it,
/// so an in-place edit of the last line cannot pass on its own either.
const REVISIONS_HEAD: &str = "cc0110b051aedcbe605c4167ffd1fd5e54c7370cdf7c69c9485c9534ed1b9657";

const SEED: u64 = 0x4253_2d42_564d_3100; // "BS-BVM1\0"
const POINTS: usize = 4;
/// The tag of the reference statements: their programs, exit codes and
/// outputs, whose public columns the digest hashes.
const REFERENCE_TAG: u32 = 1;

fn program(tag: u32) -> Arc<Program> {
    let mut p = Asm::new(0x1_0000);
    p.write_reg(A0).halt(tag);
    Arc::new(p.finish().unwrap())
}

/// The statement of `n` executions (1 ..= MAX_EXECUTIONS).
fn statement(n: usize, tag: u32) -> Statement {
    let mut st = Statement::single(program(tag), tag, vec![tag], [0; 32]);
    for e in 1..n {
        st.others.push(Part {
            program: program(tag + e as u32),
            exit_code: 0,
            output: vec![e as u32],
            budget: None,
        });
    }
    st
}

fn hex(d: &[u8]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// The circuit digest (method `DIGEST_METHOD`): for the reference statements
/// of 1 to `MAX_EXECUTIONS` executions, the fingerprints of their table lists,
/// their statement digests and their height limits; then the blinding width
/// and `MAX_EXECUTIONS` (hashed first).
fn circuit_digest() -> [u8; 32] {
    let mut h = Hasher64::new("zkvm/circuit-digest");
    h.update(&(MAX_EXECUTIONS as u64).to_le_bytes());
    h.update(&(util::BLIND_WIDTH as u64).to_le_bytes());
    for n in 1..=MAX_EXECUTIONS {
        let airs = trace::tables(&statement(n, REFERENCE_TAG));
        h.update(&fingerprint(&airs, SEED, POINTS));
        h.update(&statement_digest(&airs));
        for l in limits(&airs) {
            h.update(&(l as u64).to_le_bytes());
        }
    }
    let mut d = [0u8; 32];
    d.copy_from_slice(&h.finalize()[..32]);
    d
}

/// The chain hash of `revisions` (hex): every line's id, method and digest,
/// in order.
fn chain(revisions: &[Revision]) -> String {
    let mut h = Hasher64::new("zkvm/circuit-revisions");
    h.update(&(revisions.len() as u64).to_le_bytes());
    for r in revisions {
        h.update(&(r.id.len() as u64).to_le_bytes());
        h.update(r.id);
        h.update(&r.method.to_le_bytes());
        h.update(&(r.digest.len() as u64).to_le_bytes());
        h.update(r.digest.as_bytes());
    }
    hex(&h.finalize()[..32])
}

/// The append-only rules of `REVISIONS` (RTW1-6): every line carries the
/// chain hash of the lines before it, `head` is the chain of all of them,
/// methods increase per id, and digests are distinct.
fn check_revisions(revisions: &[Revision], head: &str) -> Result<(), String> {
    for (i, r) in revisions.iter().enumerate() {
        let expected = chain(&revisions[..i]);
        if r.prev != expected {
            return Err(format!(
                "line {i} has prev {}, but the chain of the lines before it is {expected}: \
                 an earlier line was edited, removed or reordered",
                r.prev
            ));
        }
        for later in &revisions[i + 1..] {
            if r.id == later.id && r.method >= later.method {
                return Err(format!(
                    "line {i}: an (id, method) pair is repeated or out of order"
                ));
            }
            if r.digest == later.digest {
                return Err(format!("line {i}: two lines share a digest"));
            }
        }
    }
    let actual = chain(revisions);
    if actual != head {
        return Err(format!(
            "REVISIONS_HEAD is {head}, but the chain of REVISIONS is {actual}: after \
             appending a line, set REVISIONS_HEAD to it; never edit an existing line"
        ));
    }
    Ok(())
}

#[test]
fn the_air_digest_is_pinned_to_the_circuit_id() {
    let digest = hex(&circuit_digest());
    let last = REVISIONS.last().unwrap();
    assert_eq!(
        CIRCUIT_ID, last.id,
        "CIRCUIT_ID must be the last entry of REVISIONS"
    );
    assert_eq!(
        last.method, DIGEST_METHOD,
        "the last entry of REVISIONS must use the current digest method"
    );
    assert_eq!(
        digest,
        last.digest,
        "the BVM-1 constraint system changed (an AIR, a bus, a width, a fixed table, a \
         public-column layout, a next-row set, the table order or a limit). This is a \
         consensus change: bump CIRCUIT_ID in zkvm/src/prove.rs and append (new id, \
         DIGEST_METHOD, this digest, prev = {}) to REVISIONS in the same commit",
        chain(REVISIONS)
    );
    // The consensus manifest lists the pinned digest (px/src/fingerprint.rs,
    // RTW1-6): it must be this line.
    assert_eq!(
        (CIRCUIT_DIGEST, CIRCUIT_DIGEST_METHOD),
        (last.digest, last.method),
        "zkvm/src/prove.rs CIRCUIT_DIGEST and CIRCUIT_DIGEST_METHOD must be the last line of \
         REVISIONS (set them in the same commit)"
    );
}

/// RTW1-6: the pinned list passes; an in-place edit of any line, a removed,
/// reordered or duplicated line, or a changed head fails.
#[test]
fn the_revisions_are_append_only() {
    check_revisions(REVISIONS, REVISIONS_HEAD).unwrap();
    assert!(REVISIONS.len() >= 2, "the edits below need two lines");
    type Edit = fn(&mut Vec<Revision>);
    let edits: [(&str, Edit); 9] = [
        ("an old digest", |r| r[0].digest = "00"),
        ("an old id", |r| {
            r[0].id = b"BlackSilk/zkvm/BVM-1/circuit/v0"
        }),
        ("an old method", |r| r[0].method = 0),
        ("an old prev", |r| r[0].prev = "00"),
        ("the last digest", |r| {
            let l = r.len() - 1;
            r[l].digest = "00";
        }),
        ("a removed first line", |r| {
            r.remove(0);
        }),
        ("a removed last line", |r| {
            r.pop();
        }),
        ("a reorder", |r| r.swap(0, 1)),
        ("a duplicated line", |r| {
            let l = *r.last().unwrap();
            r.push(l);
        }),
    ];
    for (what, edit) in edits {
        let mut r = REVISIONS.to_vec();
        edit(&mut r);
        assert!(
            check_revisions(&r, REVISIONS_HEAD).is_err(),
            "{what} passed the append-only check"
        );
    }
    assert!(check_revisions(REVISIONS, "00").is_err(), "a changed head");
}

/// A table with its public columns replaced by zeros of the same shape.
#[derive(Clone, Debug)]
struct Blank(Table);

impl BaseAir<Val> for Blank {
    fn width(&self) -> usize {
        self.0.width()
    }
    fn num_public_values(&self) -> usize {
        BaseAir::<Val>::num_public_values(&self.0)
    }
    fn num_periodic_columns(&self) -> usize {
        BaseAir::<Val>::num_periodic_columns(&self.0)
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        let cols = BaseAir::<Val>::periodic_columns(&self.0);
        Cow::Owned(cols.iter().map(|c| vec![Val::ZERO; c.len()]).collect())
    }
}

impl<'a> Air<FingerprintBuilder<'a>> for Blank {
    fn eval(&self, b: &mut FingerprintBuilder<'a>) {
        self.0.eval(b)
    }
}

/// The constraint evaluations do not depend on the programs, outputs and exit
/// codes (the same constraints for every statement shape), while the hashed
/// public columns do: hence the fixed reference statements.
#[test]
fn only_the_public_columns_depend_on_the_programs() {
    for n in 1..=MAX_EXECUTIONS {
        let a = trace::tables(&statement(n, REFERENCE_TAG));
        let b = trace::tables(&statement(n, 77));
        let blank = |t: &[Table]| -> Vec<Blank> { t.iter().cloned().map(Blank).collect() };
        assert_eq!(
            fingerprint(&blank(&a), SEED, POINTS),
            fingerprint(&blank(&b), SEED, POINTS),
            "{n} executions: the constraints depend on the programs"
        );
        assert_ne!(
            fingerprint(&a, SEED, POINTS),
            fingerprint(&b, SEED, POINTS),
            "{n} executions: the public columns are not hashed"
        );
    }
    // Deterministic.
    let airs = trace::tables(&statement(2, REFERENCE_TAG));
    assert_eq!(
        fingerprint(&airs, SEED, POINTS),
        fingerprint(&airs, SEED, POINTS)
    );
    assert_eq!(circuit_digest(), circuit_digest());
}

/// A table with one mutation added to its constraints or to the data the
/// prover and verifier take from it (the mutation drill, done in code rather
/// than by editing an AIR).
#[derive(Clone, Debug)]
enum Mutated {
    /// The table unchanged.
    Same(Table),
    /// One more constraint: `main[0] = 0`.
    ExtraConstraint(Table),
    /// One more constraint that is a multiple of an existing kind: `2·main[0] = 0`.
    ScaledConstraint(Table),
    /// One more interaction on a new bus.
    ExtraInteraction(Table),
    /// One public-column entry (column, row) plus one: a fixed-table entry or
    /// a public layout (RTW1-3).
    PublicEntry(Table, usize, usize),
    /// The main next-row set without its last column (RTW1-3).
    MainNextRow(Table),
    /// The preprocessed next-row set with one more column (RTW1-3).
    PreprocessedNextRow(Table),
    /// A constraint-degree hint where the table gives none.
    DegreeHint(Table),
}

impl BaseAir<Val> for Mutated {
    fn width(&self) -> usize {
        self.table().width()
    }
    fn num_public_values(&self) -> usize {
        BaseAir::<Val>::num_public_values(self.table())
    }
    fn num_periodic_columns(&self) -> usize {
        BaseAir::<Val>::num_periodic_columns(self.table())
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        let cols = BaseAir::<Val>::periodic_columns(self.table());
        match self {
            Mutated::PublicEntry(_, c, r) => {
                let mut cols = cols.into_owned();
                cols[*c][*r] += Val::ONE;
                Cow::Owned(cols)
            }
            _ => cols,
        }
    }
    fn preprocessed_width(&self) -> usize {
        BaseAir::<Val>::preprocessed_width(self.table())
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        let mut v = BaseAir::<Val>::main_next_row_columns(self.table());
        if matches!(self, Mutated::MainNextRow(_)) {
            v.pop();
        }
        v
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        let mut v = BaseAir::<Val>::preprocessed_next_row_columns(self.table());
        if matches!(self, Mutated::PreprocessedNextRow(_)) {
            v.push(v.len());
        }
        v
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        match self {
            Mutated::DegreeHint(_) => Some(3),
            _ => BaseAir::<Val>::max_constraint_degree(self.table()),
        }
    }
}

impl Mutated {
    fn table(&self) -> &Table {
        match self {
            Mutated::Same(t)
            | Mutated::ExtraConstraint(t)
            | Mutated::ScaledConstraint(t)
            | Mutated::ExtraInteraction(t)
            | Mutated::PublicEntry(t, ..)
            | Mutated::MainNextRow(t)
            | Mutated::PreprocessedNextRow(t)
            | Mutated::DegreeHint(t) => t,
        }
    }
}

impl<'a> Air<FingerprintBuilder<'a>> for Mutated {
    fn eval(&self, b: &mut FingerprintBuilder<'a>) {
        use p3_air::WindowAccess;
        self.table().eval(b);
        let x: Val = b.main().current_slice()[0];
        match self {
            Mutated::ExtraConstraint(_) => b.assert_zero(x),
            Mutated::ScaledConstraint(_) => b.assert_zero(x.double()),
            Mutated::ExtraInteraction(_) => b.push_interaction("test/mutation", [x], 1),
            _ => {}
        }
    }
}

/// Every single mutation of any one table of the two-execution statement
/// (constraints, interactions, a first and a last public-column entry, the
/// next-row sets, a constraint hint), a swap of two tables, and a changed
/// execution id each change the fingerprint.
#[test]
fn every_mutation_changes_the_fingerprint() {
    let airs = trace::tables(&statement(2, REFERENCE_TAG));
    let same: Vec<Mutated> = airs.iter().cloned().map(Mutated::Same).collect();
    let base = fingerprint(&same, SEED, POINTS);
    assert_eq!(
        base,
        fingerprint(&airs, SEED, POINTS),
        "the wrapper is neutral"
    );
    let mut seen = std::collections::BTreeSet::from([base]);
    let wraps: [fn(Table) -> Mutated; 6] = [
        Mutated::ExtraConstraint,
        Mutated::ScaledConstraint,
        Mutated::ExtraInteraction,
        Mutated::MainNextRow,
        Mutated::PreprocessedNextRow,
        Mutated::DegreeHint,
    ];
    let mut public = 0;
    for t in 0..airs.len() {
        let mut mutations: Vec<Mutated> = wraps.iter().map(|w| w(airs[t].clone())).collect();
        let cols = BaseAir::<Val>::periodic_columns(&airs[t]);
        if let Some(last) = cols.last() {
            mutations.push(Mutated::PublicEntry(airs[t].clone(), 0, 0));
            mutations.push(Mutated::PublicEntry(
                airs[t].clone(),
                cols.len() - 1,
                last.len() - 1,
            ));
            public += 1;
        }
        for mutation in mutations {
            let mut m = same.clone();
            m[t] = mutation;
            assert!(
                seen.insert(fingerprint(&m, SEED, POINTS)),
                "mutation of table {t} ({:?}) not seen",
                m[t]
            );
        }
    }
    // The byte table, and the program, image and output of both executions.
    assert_eq!(public, 7, "tables with public columns");
    // Table order.
    let mut swapped = airs.clone();
    swapped.swap(4, 5);
    assert_ne!(fingerprint(&swapped, SEED, POINTS), base);
    // Execution ids are part of the constraints (bus tags).
    let mut other_exec = airs.clone();
    let cpu = other_exec
        .iter()
        .position(|t| matches!(t, Table::Cpu(0)))
        .unwrap();
    other_exec[cpu] = Table::Cpu(3);
    assert_ne!(fingerprint(&other_exec, SEED, POINTS), base);
    println!(
        "{} distinct fingerprints over {} tables",
        seen.len(),
        airs.len()
    );
}

/// RTW1-3, the red team's case: the byte table with one XOR entry wrong.
struct ByteMut;

impl BaseAir<Val> for ByteMut {
    fn width(&self) -> usize {
        Table::Byte.width()
    }
    fn num_periodic_columns(&self) -> usize {
        Table::Byte.num_periodic_columns()
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        let mut c = Table::Byte.periodic_columns().into_owned();
        c[4][0] += Val::ONE; // one XOR table entry wrong
        Cow::Owned(c)
    }
}

impl<AB: AirBuilder<F = Val> + InteractionBuilder> Air<AB> for ByteMut {
    fn eval(&self, b: &mut AB) {
        <Table as Air<AB>>::eval(&Table::Byte, b)
    }
}

/// RTW1-3: a changed lookup-table entry changes the fingerprint (it did not
/// before: the fingerprint evaluated the constraints at random periodic
/// values and never hashed the table itself).
#[test]
fn rtw1_3_a_changed_byte_table_entry_changes_the_fingerprint() {
    assert_ne!(
        ByteMut.periodic_columns()[4][0],
        Table::Byte.periodic_columns()[4][0]
    );
    let a = fingerprint(&[Table::Byte], 1, 4);
    let b = fingerprint(&[ByteMut], 1, 4);
    assert_ne!(
        a, b,
        "a changed lookup table must change the circuit digest"
    );
}

/// RTW1-3: one entry of a public layout (the reference program, image and
/// output of every execution) and one next-row set each change the digest of
/// the full statement.
#[test]
fn rtw1_3_layout_and_next_row_mutations_change_the_fingerprint() {
    let airs = trace::tables(&statement(MAX_EXECUTIONS, REFERENCE_TAG));
    let same: Vec<Mutated> = airs.iter().cloned().map(Mutated::Same).collect();
    let base = fingerprint(&same, SEED, POINTS);
    let mut layouts = 0;
    for (t, air) in airs.iter().enumerate() {
        if matches!(
            air,
            Table::Program(..) | Table::Image(..) | Table::Output(..)
        ) {
            let mut m = same.clone();
            m[t] = Mutated::PublicEntry(air.clone(), 0, 0);
            assert_ne!(fingerprint(&m, SEED, POINTS), base, "layout of table {t}");
            layouts += 1;
        }
        let mut m = same.clone();
        m[t] = Mutated::MainNextRow(air.clone());
        assert_ne!(
            fingerprint(&m, SEED, POINTS),
            base,
            "next-row set of table {t}"
        );
    }
    assert_eq!(layouts, 3 * MAX_EXECUTIONS);
}
