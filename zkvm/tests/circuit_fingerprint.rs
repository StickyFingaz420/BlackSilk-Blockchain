//! The circuit fingerprint (23 W2, 22 W4): `CIRCUIT_ID` names the BVM-1
//! constraint system, and this test ties the name to the constraints
//! themselves. It fingerprints every table of the statements of 1 to
//! `MAX_EXECUTIONS` executions (their constraint evaluations at seeded
//! points, widths and table order; `air::check::fingerprint`), together with
//! the height limits and the blinding width, and requires the digest to be
//! the one pinned for the current `CIRCUIT_ID`.
//!
//! **When this test fails** because an AIR, a bus, a table's width or the
//! table order changed: that is a consensus change. In the same commit,
//! bump `CIRCUIT_ID` (zkvm/src/prove.rs) and **append** its new digest to
//! `REVISIONS`. Never edit an existing line: an old id keeps its digest.
//! Native, no proving; instant.

use blacksilk_crypto::hash::Hasher64;
use blacksilk_zk::config::Val;
use blacksilk_zkvm::air::check::{fingerprint, FingerprintBuilder};
use blacksilk_zkvm::air::trace::{self, Part, Statement, MAX_EXECUTIONS};
use blacksilk_zkvm::air::{util, Table};
use blacksilk_zkvm::asm::{reg::*, Asm};
use blacksilk_zkvm::prove::{limits, CIRCUIT_ID};
use blacksilk_zkvm::Program;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::InteractionBuilder;
use std::sync::Arc;

/// Every circuit revision and its digest, oldest first. The last line must
/// be the current `CIRCUIT_ID`.
const REVISIONS: &[(&[u8], &str)] = &[(
    b"BlackSilk/zkvm/BVM-1/circuit/v1",
    "cfbeee3350f718f0a38083ec4778922dbb328888cfaf2fd800a531a09934a75a",
)];

const SEED: u64 = 0x4253_2d42_564d_3100; // "BS-BVM1\0"
const POINTS: usize = 4;

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

/// The circuit digest: the fingerprints of the table lists of 1 to
/// `MAX_EXECUTIONS` executions, their height limits, the blinding width and
/// `MAX_EXECUTIONS`. Programs do not enter (`tag` is there to show it).
fn circuit_digest(tag: u32) -> [u8; 32] {
    let mut h = Hasher64::new("zkvm/circuit-digest");
    h.update(&(MAX_EXECUTIONS as u64).to_le_bytes());
    h.update(&(util::BLIND_WIDTH as u64).to_le_bytes());
    for n in 1..=MAX_EXECUTIONS {
        let airs = trace::tables(&statement(n, tag));
        h.update(&fingerprint(&airs, SEED, POINTS));
        for l in limits(&airs) {
            h.update(&(l as u64).to_le_bytes());
        }
    }
    let mut d = [0u8; 32];
    d.copy_from_slice(&h.finalize()[..32]);
    d
}

#[test]
fn the_air_digest_is_pinned_to_the_circuit_id() {
    let digest = hex(&circuit_digest(1));
    let (id, pinned) = REVISIONS.last().unwrap();
    assert_eq!(
        CIRCUIT_ID, *id,
        "CIRCUIT_ID must be the last entry of REVISIONS"
    );
    assert_eq!(
        digest, *pinned,
        "the BVM-1 constraint system changed (an AIR, a bus, a width, the table order or a \
         limit). This is a consensus change: bump CIRCUIT_ID in zkvm/src/prove.rs and append \
         (new id, this digest) to REVISIONS in the same commit"
    );
    // Revisions are distinct in both columns.
    for (i, a) in REVISIONS.iter().enumerate() {
        for b in &REVISIONS[i + 1..] {
            assert_ne!(a.0, b.0, "a circuit id is listed twice");
            assert_ne!(a.1, b.1, "two circuit ids share a digest");
        }
    }
}

#[test]
fn the_digest_depends_on_the_constraints_not_on_the_programs() {
    // Other programs, outputs and exit codes: the same circuit.
    assert_eq!(circuit_digest(1), circuit_digest(77));
    // Deterministic.
    let airs = trace::tables(&statement(2, 1));
    assert_eq!(
        fingerprint(&airs, SEED, POINTS),
        fingerprint(&airs, SEED, POINTS)
    );
}

/// A table with one mutation added to its constraints (the mutation drill,
/// done in code rather than by editing an AIR).
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
}

impl Mutated {
    fn table(&self) -> &Table {
        match self {
            Mutated::Same(t)
            | Mutated::ExtraConstraint(t)
            | Mutated::ScaledConstraint(t)
            | Mutated::ExtraInteraction(t) => t,
        }
    }
}

impl<'a> Air<FingerprintBuilder<'a>> for Mutated {
    fn eval(&self, b: &mut FingerprintBuilder<'a>) {
        use p3_air::WindowAccess;
        self.table().eval(b);
        let x: Val = b.main().current_slice()[0];
        match self {
            Mutated::Same(_) => {}
            Mutated::ExtraConstraint(_) => b.assert_zero(x),
            Mutated::ScaledConstraint(_) => b.assert_zero(x.double()),
            Mutated::ExtraInteraction(_) => b.push_interaction("test/mutation", [x], 1),
        }
    }
}

/// Every single mutation of any one table of the two-execution statement, a
/// swap of two tables, and a changed execution id each change the fingerprint.
#[test]
fn every_mutation_changes_the_fingerprint() {
    let airs = trace::tables(&statement(2, 1));
    let same: Vec<Mutated> = airs.iter().cloned().map(Mutated::Same).collect();
    let base = fingerprint(&same, SEED, POINTS);
    assert_eq!(
        base,
        fingerprint(&airs, SEED, POINTS),
        "the wrapper is neutral"
    );
    let mut seen = std::collections::BTreeSet::from([base]);
    let wraps: [fn(Table) -> Mutated; 3] = [
        Mutated::ExtraConstraint,
        Mutated::ScaledConstraint,
        Mutated::ExtraInteraction,
    ];
    for t in 0..airs.len() {
        for wrap in wraps {
            let mut m = same.clone();
            m[t] = wrap(airs[t].clone());
            assert!(
                seen.insert(fingerprint(&m, SEED, POINTS)),
                "mutation of table {t} ({:?}) not seen",
                m[t]
            );
        }
    }
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
