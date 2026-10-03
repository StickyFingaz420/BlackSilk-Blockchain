//! Cell census of the BVM-1 traces (W4-MUTAIR; TM2-X 1.8 item 1;
//! docs/evidence/mutation-air-2026-10-02).
//!
//! For every table, every column and the probed rows (padding rows
//! included), one cell of an honest trace is changed: `+1`, `−1`, set to `0`,
//! set to `p − 1`, and swapped with the same cell of the next row. The
//! constraint checker must reject each change, or the cell must be on the
//! explicit list of cells that are unconstrained by design ([`free_by_design`],
//! each with its reason). A change that is accepted and not on the list is an
//! under-constrained cell: the test fails and names it.
//!
//! The existing single-cell probes (`vm.rs`, `alu.rs`, `multi.rs`) cover the
//! CPU, memory, ALU and POSEIDON2 tables, real rows only, with additive
//! changes. This census adds the byte, program, image, output and blinding
//! tables, padding rows, the absolute values `0` and `p − 1`, and row swaps.
//!
//! The default test probes every real row and a sample of padding rows; the
//! ignored test probes every row of every table (minutes in a debug build).

use blacksilk_zk::config::Val;
use blacksilk_zkvm::air::check::check;
use blacksilk_zkvm::air::trace::{self, Statement};
use blacksilk_zkvm::air::{cpu, Table};
use blacksilk_zkvm::asm::{reg::*, Asm};
use blacksilk_zkvm::isa::Op;
use blacksilk_zkvm::{run, MAX_CYCLES};
use p3_air::{Air, AirBuilder, BaseAir, RowWindow};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

const BASE: u32 = 0x1_0000;
const DATA: u32 = 0x10_0000;

/// Table names in `trace::tables` order (single execution).
const NAMES: [&str; 13] = [
    "byte",
    "program",
    "image",
    "mem_init",
    "cpu",
    "alu_add",
    "alu_bit",
    "alu_lt",
    "alu_shift",
    "alu_mul",
    "output",
    "poseidon2",
    "blind",
];

/// Evaluates one row (the same `eval` code the prover runs), recording
/// whether a constraint fails and every interaction.
struct Eval<'a> {
    main: RowWindow<'a, Val>,
    prep: RowWindow<'a, Val>,
    public: &'a [Val],
    first: Val,
    last: Val,
    transition: Val,
    failed: bool,
    constraints: usize,
    msgs: Vec<(String, Vec<u32>, Val)>,
}

impl<'a> AirBuilder for Eval<'a> {
    type F = Val;
    type Expr = Val;
    type Var = Val;
    type PreprocessedWindow = RowWindow<'a, Val>;
    type MainWindow = RowWindow<'a, Val>;
    type PublicVar = Val;
    type PeriodicVar = Val;

    fn main(&self) -> Self::MainWindow {
        self.main
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        &self.prep
    }

    fn is_first_row(&self) -> Val {
        self.first
    }

    fn is_last_row(&self) -> Val {
        self.last
    }

    fn is_transition(&self) -> Val {
        self.transition
    }

    fn assert_zero<I: Into<Val>>(&mut self, x: I) {
        if x.into() != Val::ZERO {
            self.failed = true;
        }
        self.constraints += 1;
    }

    fn public_values(&self) -> &[Val] {
        self.public
    }

    fn periodic_values(&self) -> &[Val] {
        use p3_air::WindowAccess;
        self.prep.current_slice()
    }
}

fn canonical(v: impl IntoIterator<Item = Val>) -> Vec<u32> {
    v.into_iter().map(|x| x.as_canonical_u32()).collect()
}

impl InteractionBuilder for Eval<'_> {
    fn push_interaction<E: Into<Val>>(
        &mut self,
        bus_name: &str,
        fields: impl IntoIterator<Item = E>,
        count: impl Into<Count<Val>>,
    ) {
        let (c, _) = count.into().into_parts();
        let f = canonical(fields.into_iter().map(Into::into));
        self.msgs.push((bus_name.to_string(), f, c));
    }

    fn push_local_interaction(&mut self, tuples: impl IntoIterator<Item = (Vec<Val>, Count<Val>)>) {
        for (fields, count) in tuples {
            self.msgs
                .push(("(local)".into(), canonical(fields), count.into_parts().0));
        }
    }

    fn push_exclusive_interaction(
        &mut self,
        bus_name: &str,
        branches: impl IntoIterator<Item = (Val, Count<Val>, Vec<Val>)>,
    ) {
        for (flag, count, fields) in branches {
            self.msgs.push((
                bus_name.to_string(),
                canonical(fields),
                count.into_parts().0 * flag,
            ));
        }
    }
}

type Key = (usize, String, Vec<u32>);

/// Incremental checker for changes of several cells of one table: only the
/// rows whose constraints read a changed cell (the row and its predecessor)
/// are re-evaluated, and the bus sums are adjusted.
struct Census<'x> {
    airs: &'x [Table],
    traces: Vec<RowMajorMatrix<Val>>,
    preps: Vec<Option<RowMajorMatrix<Val>>>,
    public: &'x [Vec<Val>],
    buses: BTreeMap<Key, Val>,
}

impl<'x> Census<'x> {
    fn new(airs: &'x [Table], traces: &[RowMajorMatrix<Val>], public: &'x [Vec<Val>]) -> Self {
        assert_eq!(
            check(airs, traces, public),
            vec![],
            "baseline must be valid"
        );
        let mut c = Census {
            airs,
            traces: traces.to_vec(),
            preps: airs.iter().map(|a| a.periodic_columns_matrix()).collect(),
            public,
            buses: BTreeMap::new(),
        };
        for t in 0..airs.len() {
            for r in 0..c.traces[t].height() {
                let (failed, msgs) = c.eval(t, r);
                assert!(!failed);
                for (k, n) in msgs {
                    *c.buses.entry(k).or_insert(Val::ZERO) += n;
                }
            }
        }
        c
    }

    fn eval(&self, t: usize, r: usize) -> (bool, Vec<(Key, Val)>) {
        let tr = &self.traces[t];
        let (h, w) = (tr.height(), tr.width());
        let n = (r + 1) % h;
        let empty: Vec<Val> = Vec::new();
        let (pc, pn): (&[Val], &[Val]) = match &self.preps[t] {
            Some(p) => {
                let pw = p.width();
                (
                    &p.values[r * pw..(r + 1) * pw],
                    &p.values[n * pw..(n + 1) * pw],
                )
            }
            None => (&empty, &empty),
        };
        let mut b = Eval {
            main: RowWindow::from_two_rows(
                &tr.values[r * w..(r + 1) * w],
                &tr.values[n * w..(n + 1) * w],
            ),
            prep: RowWindow::from_two_rows(pc, pn),
            public: &self.public[t],
            first: Val::from_bool(r == 0),
            last: Val::from_bool(r == h - 1),
            transition: Val::from_bool(r != h - 1),
            failed: false,
            constraints: 0,
            msgs: Vec::new(),
        };
        self.airs[t].eval(&mut b);
        let msgs = b
            .msgs
            .into_iter()
            // Global buses balance across tables; local ones within a table.
            .map(|(bus, f, c)| ((if bus == "(local)" { t } else { usize::MAX }, bus, f), c))
            .collect();
        (b.failed, msgs)
    }

    /// Whether setting the given `(row, column, value)` cells of table `t`
    /// is rejected.
    fn rejects(&mut self, t: usize, cells: &[(usize, usize, Val)]) -> bool {
        let (h, w) = (self.traces[t].height(), self.traces[t].width());
        let rows: BTreeSet<usize> = cells
            .iter()
            .flat_map(|&(r, _, _)| [(r + h - 1) % h, r])
            .collect();
        let before: Vec<_> = rows.iter().map(|&r| self.eval(t, r).1).collect();
        let old: Vec<Val> = cells
            .iter()
            .map(|&(r, c, _)| self.traces[t].values[r * w + c])
            .collect();
        for &(r, c, x) in cells {
            self.traces[t].values[r * w + c] = x;
        }
        let after: Vec<_> = rows.iter().map(|&r| self.eval(t, r)).collect();
        for (&(r, c, _), x) in cells.iter().zip(&old).rev() {
            self.traces[t].values[r * w + c] = *x;
        }
        if after.iter().any(|(failed, _)| *failed) {
            return true;
        }
        let mut delta: BTreeMap<Key, Val> = BTreeMap::new();
        for m in &before {
            for (k, n) in m {
                *delta.entry(k.clone()).or_insert(Val::ZERO) -= *n;
            }
        }
        for (_, m) in &after {
            for (k, n) in m {
                *delta.entry(k.clone()).or_insert(Val::ZERO) += *n;
            }
        }
        delta
            .iter()
            .any(|(k, d)| *self.buses.get(k).unwrap_or(&Val::ZERO) + *d != Val::ZERO)
    }
}

/// A program exercising every instruction class and every syscall.
fn kitchen_sink() -> Asm {
    let mut p = Asm::new(BASE);
    let mut bytes = vec![0xf3, 0x82, 0x81, 0x70, 7, 0, 0, 0];
    bytes.resize(64, 1);
    p.data(DATA, bytes, 128);
    p.li(S0, DATA).li(T0, 0x8000_0005).li(T1, 3);
    for op in [
        Op::Add,
        Op::Sub,
        Op::Xor,
        Op::Or,
        Op::And,
        Op::Slt,
        Op::Sltu,
        Op::Sll,
        Op::Srl,
        Op::Sra,
        Op::Mul,
        Op::Mulh,
        Op::Mulhsu,
        Op::Mulhu,
    ] {
        p.r(op, A1, T0, T1).write_reg(A1);
    }
    p.imm(Op::Addi, A1, T0, -7)
        .imm(Op::Slti, A1, T0, 0)
        .imm(Op::Sltiu, A2, T1, -1)
        .imm(Op::Xori, A1, A1, 0x55)
        .imm(Op::Ori, A1, A1, 0x0f)
        .imm(Op::Andi, A1, A1, 0x3c)
        .imm(Op::Slli, A1, T0, 3)
        .imm(Op::Srli, A1, T0, 0)
        .imm(Op::Srai, A1, T0, 31)
        .write_reg(A1)
        .load(Op::Lb, A1, S0, 0)
        .load(Op::Lbu, A1, S0, 1)
        .load(Op::Lh, A1, S0, 2)
        .load(Op::Lhu, A1, S0, 0)
        .load(Op::Lw, A1, S0, 4)
        .write_reg(A1)
        .store(Op::Sb, T0, S0, 9)
        .store(Op::Sh, T0, S0, 14)
        .store(Op::Sw, T1, S0, 16)
        .load(Op::Lw, A1, S0, 12)
        .write_reg(A1)
        .i(Op::Lui, A1, 0, 0, 0x1234_5000u32 as i32)
        .i(Op::Auipc, A2, 0, 0, 0x1000)
        .write_reg(A2)
        .jal(RA, "sub")
        .li(T2, 0)
        .branch(Op::Beq, T2, T1, "never")
        .branch(Op::Bne, T2, T1, "b1")
        .label("never")
        .halt(9)
        .label("b1")
        .branch(Op::Blt, T0, T1, "b2")
        .halt(8)
        .label("b2")
        .branch(Op::Bge, T0, T1, "never")
        .branch(Op::Bltu, T0, T1, "never")
        .branch(Op::Bgeu, T0, T1, "b3")
        .halt(7)
        .label("b3")
        // An equality of equal operands (ALU_LT with d = 0), offset 4.
        .branch(Op::Beq, T0, T0, "b4")
        .label("b4")
        .ecall(1)
        .write_reg(A0)
        .i(Op::Fence, 0, 0, 0, 0)
        .li(A0, DATA)
        .ecall(3)
        .load(Op::Lw, A1, S0, 60)
        .write_reg(A1)
        .halt(0)
        .label("sub")
        .li(A0, 77)
        .imm(Op::Jalr, ZERO, RA, 0);
    p
}

fn statement() -> (Statement, Vec<RowMajorMatrix<Val>>) {
    let program = Arc::new(kitchen_sink().finish().unwrap());
    let exec = run(&program, &[1234], MAX_CYCLES).expect("halts");
    let st = Statement::single(program, exec.exit_code, exec.output.clone(), [7; 32]);
    let traces = trace::build(&st, &exec);
    (st, traces)
}

/// Whether row `r` of table `t` is a real row (by the table's own selector).
fn is_real(st: &Statement, traces: &[RowMajorMatrix<Val>], t: usize, r: usize) -> bool {
    let tr = &traces[t];
    let w = tr.width();
    let row = &tr.values[r * w..(r + 1) * w];
    let nz = |cols: std::ops::Range<usize>| cols.into_iter().any(|c| row[c] != Val::ZERO);
    match t {
        0 => nz(0..4),                  // byte: some multiplicity
        1 => r < st.program.code.len(), // program: an instruction row
        2 => r < trace::image(&st.program).len(),
        3 | 4 => row[0] == Val::ONE, // mem_init, cpu: is_real
        5 => nz(0..2),
        6..=8 => nz(0..3),
        9 => nz(0..4),
        10 => r < st.output.len(),
        11 => row[blacksilk_zkvm::air::poseidon::P2_COLS] == Val::ONE,
        _ => row[0] == Val::ONE, // blind
    }
}

/// A probed change: its kind and the `(row, column, value)` cells it sets.
type Change = (&'static str, Vec<(usize, usize, Val)>);

/// The changes probed for one cell.
fn changes(traces: &[RowMajorMatrix<Val>], t: usize, r: usize, c: usize) -> Vec<Change> {
    let tr = &traces[t];
    let (h, w) = (tr.height(), tr.width());
    let x = tr.values[r * w + c];
    let n = (r + 1) % h;
    let y = tr.values[n * w + c];
    let mut out = Vec::new();
    for (kind, z) in [
        ("+1", x + Val::ONE),
        ("-1", x - Val::ONE),
        ("=0", Val::ZERO),
        ("=p-1", Val::NEG_ONE),
    ] {
        if z != x
            && !out
                .iter()
                .any(|(_, v): &(&str, Vec<(usize, usize, Val)>)| v[0].2 == z)
        {
            out.push((kind, vec![(r, c, z)]));
        }
    }
    if y != x {
        out.push(("swap", vec![(r, c, y), (n, c, x)]));
    }
    out
}

/// One accepted change.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Accepted {
    table: &'static str,
    column: usize,
    real: bool,
    kind: &'static str,
}

/// Why an accepted change of cell `(r, c)` of table `t` is harmless by
/// design, or `None` (an under-constrained cell).
///
/// - **Padding rows** (the table's selector is 0): every constraint on these
///   columns and every interaction they enter is multiplied by the selector,
///   so they reach no bus and no other row. The lists are exact: a column
///   that becomes free on padding rows fails the census.
/// - **Inverse witnesses of a zero** (real rows): `ALU_LT`'s inverse when
///   `d = 0` and `ALU_SHIFT`'s inverse when the amount is 0; the zero test's
///   result does not depend on them.
/// - **Row swaps that move a whole row**: the two rows differ only in the
///   swapped cell, so the swap exchanges the rows; a table without
///   transition constraints provides the same multiset of messages.
fn free_by_design(
    traces: &[RowMajorMatrix<Val>],
    t: usize,
    r: usize,
    c: usize,
    real: bool,
    kind: &str,
) -> Option<&'static str> {
    let tr = &traces[t];
    let (h, w) = (tr.height(), tr.width());
    let row = |r: usize| &tr.values[r * w..(r + 1) * w];
    if kind == "swap" {
        let n = (r + 1) % h;
        let others_equal = (0..w).all(|k| k == c || row(r)[k] == row(n)[k]);
        if others_equal && !matches!(t, 3 | 4) {
            return Some("the swap exchanges two whole rows of a table without transitions");
        }
    }
    if !real {
        // Inclusive column ranges (air/alu_*.rs, air/memory.rs layouts).
        let free: &[(usize, usize)] = match t {
            5 => &[(2, 13)],                   // alu_add: a, b, c
            6 => &[(3, 14)],                   // alu_bit: a, b, c
            7 => &[(23, 23)],                  // alu_lt: inv
            9 => &[(4, 6), (8, 10)],           // alu_mul: a0..a2, b0..b2
            8 => &[(3, 6), (8, 14), (33, 33)], // alu_shift: a, b1..b3, c, inv
            4 => &[
                (cpu::CLK, cpu::CLK),
                (cpu::NEXT_PC, cpu::NEXT_PC),
                (cpu::A, cpu::DB + 2), // both register reads
                (cpu::OUT, cpu::OUT),
            ],
            3 => &[(10, 14), (16, 19)], // mem_init: final value and ts, d
            _ => &[],
        };
        // POSEIDON2 (air/poseidon.rs): is_real, clk, ptr (4), ph, key, exec,
        // then 16 words of in (4), ts, diff (3), out (4), two flags.
        let p2 = blacksilk_zkvm::air::poseidon::P2_COLS;
        let words = p2 + 9;
        if t == 11 && (c == p2 + 1 || c == p2 + 8) {
            return Some("a padding row's POSEIDON2 clk or execution tag");
        }
        if free.iter().any(|&(lo, hi)| (lo..=hi).contains(&c)) {
            return Some("a padding row's column that only selector-gated rules read");
        }
        if t == 11 && c >= words && c < words + 16 * 14 && (c - words) % 14 < 12 {
            return Some("a padding row's POSEIDON2 word (bytes, timestamp, difference)");
        }
        return None;
    }
    match (t, c) {
        (7, 23) if (11..15).all(|k| row(r)[k] == Val::ZERO) => Some("ALU_LT inverse of d = 0"),
        (8, 33) if row(r)[21] == Val::ONE => Some("ALU_SHIFT inverse of a zero amount"),
        _ => None,
    }
}

fn census(all_rows: bool) -> (usize, BTreeMap<Accepted, usize>) {
    let (st, traces) = statement();
    let airs = trace::tables(&st);
    let public = trace::public_values(&st);
    let mut c = Census::new(&airs, &traces, &public);
    let mut tried = 0;
    let mut accepted: BTreeMap<Accepted, usize> = BTreeMap::new();
    for t in 0..airs.len() {
        let h = traces[t].height();
        let w = traces[t].width();
        let mut rows: Vec<usize> = Vec::new();
        let mut padding = 0;
        for r in 0..h {
            let real = is_real(&st, &traces, t, r);
            let keep =
                all_rows || real && (t != 0 || r % 61 == 0) || !real && (padding < 2 || r == h - 1);
            if !real {
                padding += 1;
            }
            if keep {
                rows.push(r);
            }
        }
        for r in rows {
            let real = is_real(&st, &traces, t, r);
            for col in 0..w {
                for (kind, cells) in changes(&traces, t, r, col) {
                    tried += 1;
                    if !c.rejects(t, &cells) {
                        let a = Accepted {
                            table: NAMES[t],
                            column: col,
                            real,
                            kind,
                        };
                        if free_by_design(&traces, t, r, col, real, kind).is_none() {
                            *accepted.entry(a).or_insert(0) += 1;
                        }
                    }
                }
            }
        }
    }
    (tried, accepted)
}

fn report(tried: usize, accepted: &BTreeMap<Accepted, usize>) {
    println!(
        "{tried} cell changes probed; {} accepted classes",
        accepted.len()
    );
    for (a, n) in accepted {
        println!("accepted: {a:?} ×{n}");
    }
}

#[test]
fn every_cell_change_is_rejected_or_free_by_design() {
    let (tried, accepted) = census(false);
    report(tried, &accepted);
    assert!(
        accepted.is_empty(),
        "{} under-constrained cell classes",
        accepted.len()
    );
}

#[test]
#[ignore = "every row of every table: minutes; run for the census evidence"]
fn every_cell_change_of_every_row_is_rejected_or_free_by_design() {
    let (tried, accepted) = census(true);
    report(tried, &accepted);
    assert!(
        accepted.is_empty(),
        "{} under-constrained cell classes",
        accepted.len()
    );
}

// ---- the oracle itself (W4-MUTAIR run B: check.rs) ----
//
// The census and the negative traces trust `air::check` and its incremental
// `MutationChecker`. These tests check the checker: its shape errors, its
// counts, and that the incremental answer equals a full re-check, for changes
// that must be caught and for changes that must not be.

#[test]
fn the_checker_reports_every_shape_mismatch() {
    use blacksilk_zkvm::air::check::Violation;
    let (st, traces) = statement();
    let airs = trace::tables(&st);
    let public = trace::public_values(&st);
    // The table counts are checked first and stop the check; a table's own
    // shape error skips that table (its buses then do not balance).
    let shape_only = |v: &[Violation]| matches!(v, [Violation::Shape(_)]);
    let has_shape = |v: &[Violation]| v.iter().any(|x| matches!(x, Violation::Shape(_)));
    assert!(
        shape_only(&check(&airs[1..], &traces, &public)),
        "fewer tables"
    );
    assert!(
        shape_only(&check(&airs, &traces[1..], &public)),
        "fewer traces"
    );
    assert!(
        shape_only(&check(&airs, &traces, &public[1..])),
        "fewer public values"
    );
    // One table of the wrong width, then of a height that is not a power of two.
    let t = 5;
    let (h, w) = (traces[t].height(), traces[t].width());
    let mut wide = traces.clone();
    wide[t] = RowMajorMatrix::new(vec![Val::ZERO; h * (w + 1)], w + 1);
    assert!(has_shape(&check(&airs, &wide, &public)), "width");
    let mut short = traces.clone();
    short[t] = RowMajorMatrix::new(traces[t].values[..(h - 1) * w].to_vec(), w);
    assert!(has_shape(&check(&airs, &short, &public)), "height");
}

#[test]
fn shapes_count_every_constraint_and_interaction() {
    use blacksilk_zkvm::air::check::shapes;
    let (st, traces) = statement();
    let airs = trace::tables(&st);
    let public = trace::public_values(&st);
    let census = Census::new(&airs, &traces, &public);
    let sh = shapes(&airs, &traces, &public);
    assert_eq!(sh.len(), airs.len());
    for (t, s) in sh.iter().enumerate() {
        let tr = &census.traces[t];
        let w = tr.width();
        let prep = census.preps[t].as_ref();
        let pw = prep.map_or(0, |p| p.width());
        let empty: Vec<Val> = Vec::new();
        let (pc, pn): (&[Val], &[Val]) = match prep {
            Some(p) => (&p.values[..pw], &p.values[pw..2 * pw]),
            None => (&empty, &empty),
        };
        let mut b = Eval {
            main: RowWindow::from_two_rows(&tr.values[..w], &tr.values[w..2 * w]),
            prep: RowWindow::from_two_rows(pc, pn),
            public: &public[t],
            first: Val::ONE,
            last: Val::ZERO,
            transition: Val::ONE,
            failed: false,
            constraints: 0,
            msgs: Vec::new(),
        };
        airs[t].eval(&mut b);
        assert_eq!(
            (s.constraints, s.interactions, s.main_width, s.prep_width),
            (b.constraints, b.msgs.len(), w, pw),
            "table {t} ({})",
            NAMES[t]
        );
        assert!(s.constraints > 0 || t == 12, "table {t} has constraints");
    }
}

/// `MutationChecker` (the single-cell probes of vm.rs, alu.rs and multi.rs)
/// must answer exactly what a full `check` of the changed traces answers:
/// for changes it must catch, and for changes it must not (zero deltas, free
/// witness cells, free padding cells), on first, middle and last rows. Each
/// free probe follows a caught probe of the same row, so a probe that does
/// not restore its cell shows up.
#[test]
fn the_mutation_checker_agrees_with_the_full_checker() {
    use blacksilk_zkvm::air::check::MutationChecker;
    let (st, traces) = statement();
    let airs = trace::tables(&st);
    let public = trace::public_values(&st);
    let mut m = MutationChecker::new(&airs, &traces, &public);
    let full = |t: usize, r: usize, c: usize, d: Val| {
        let mut x = traces.clone();
        let w = x[t].width();
        x[t].values[r * w + c] += d;
        !check(&airs, &x, &public).is_empty()
    };
    let w = |t: usize| traces[t].width();
    let h = |t: usize| traces[t].height();
    let cell = |t: usize, r: usize, c: usize| traces[t].values[r * w(t) + c];
    // ALU_LT rows with d = 0 (inverse free) and ALU_SHIFT rows with a zero
    // amount (inverse free).
    let lt_free = (0..h(7))
        .find(|&r| cell(7, r, 2) == Val::ONE && (11..15).all(|k| cell(7, r, k) == Val::ZERO))
        .expect("an EQ of equal operands");
    let sh_free = (0..h(8))
        .find(|&r| cell(8, r, 21) == Val::ONE && (0..3).any(|k| cell(8, r, k) == Val::ONE))
        .expect("a shift by zero");
    let cpu_pad = (0..h(4))
        .find(|&r| cell(4, r, cpu::IS_REAL) == Val::ZERO)
        .unwrap();
    let mut probes = Vec::new();
    for (t, r, caught_col, free_col) in [
        (7, lt_free, 3, 23),
        (8, sh_free, 3, 33),
        (4, cpu_pad, cpu::IS_REAL, cpu::CLK),
        (4, h(4) - 1, cpu::IS_REAL, cpu::NEXT_PC),
        (5, h(5) - 1, 0, 2),
        (5, 0, 0, 2),
        (3, h(3) - 1, 0, 10),
    ] {
        for d in [Val::ONE, -Val::ONE] {
            probes.push((t, r, caught_col, d));
            probes.push((t, r, free_col, d));
        }
        probes.push((t, r, caught_col, Val::ZERO));
    }
    let (mut yes, mut no) = (0, 0);
    for (t, r, c, d) in probes {
        let expected = full(t, r, c, d);
        assert_eq!(
            m.caught(t, r, c, d),
            expected,
            "table {t} row {r} column {c} delta {d}"
        );
        if expected {
            yes += 1;
        } else {
            no += 1;
        }
    }
    // First, middle and last rows of every table, against this file's own
    // incremental checker (a full check per probe would take minutes).
    let mut census = Census::new(&airs, &traces, &public);
    for t in 0..airs.len() {
        for r in [0, 1, h(t) / 2, h(t) - 1] {
            for c in [0, w(t) / 2, w(t) - 1] {
                let x = cell(t, r, c) + Val::ONE;
                assert_eq!(
                    m.caught(t, r, c, Val::ONE),
                    census.rejects(t, &[(r, c, x)]),
                    "table {t} row {r} column {c}"
                );
            }
        }
    }
    assert!(
        yes > 0 && no >= 14,
        "both answers occur: {yes} caught, {no} not"
    );
}
