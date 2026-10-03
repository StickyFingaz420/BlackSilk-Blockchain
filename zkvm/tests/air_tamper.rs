//! Negative traces for the BVM-1 constraints (W4-MUTAIR, threat model round 2
//! TM2-1; docs/evidence/mutation-air-2026-10-02).
//!
//! Each test forges the trace of a **false** execution (a wrong ALU result, a
//! load returning a stale value, a read from the future, a skipped
//! instruction, a jump to the wrong place, a run that never halts, a digest
//! word with a second byte encoding) and requires the constraint oracle
//! (`air::check`) to reject it.
//!
//! The forgeries are **targeted**: everything else is kept consistent (the
//! byte table's multiplicities are recomputed, the chains of the memory
//! argument are re-linked, the ALU rows are rebuilt for the forged claim),
//! and each test asserts which single rule rejects the trace. Weakening that
//! rule therefore lets the false trace pass: these tests are the negative
//! half of the AIR's mutation oracle, next to the honest traces (completeness)
//! and the single-cell mutation tests. The circuit-fingerprint pins are not
//! part of that oracle: they change with every AIR edit and prove nothing
//! about soundness.
//!
//! Non-proving: only the constraint checker runs.

use blacksilk_zk::config::Val;
use blacksilk_zkvm::air::check::{check, Violation};
use blacksilk_zkvm::air::program::{class, f};
use blacksilk_zkvm::air::trace::{self, Statement};
use blacksilk_zkvm::air::util::alu_op;
use blacksilk_zkvm::air::{alu_mul, cpu, poseidon, Table, MIN_HEIGHT};
use blacksilk_zkvm::asm::{reg::*, Asm};
use blacksilk_zkvm::exec::Execution;
use blacksilk_zkvm::isa::Op;
use blacksilk_zkvm::{run, Program, MAX_CYCLES};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use std::sync::Arc;

const BASE: u32 = 0x1_0000;
const DATA: u32 = 0x10_0000;

// Table indices of a single-execution statement (`trace::tables`).
const BYTE: usize = 0;
const MEM_INIT: usize = 3;
const CPU: usize = 4;
const ADD: usize = 5;
const BIT: usize = 6;
const LT: usize = 7;
const SHIFT: usize = 8;
const MUL: usize = 9;
const P2: usize = 11;

/// `MEM_INIT` columns (air/memory.rs).
mod init {
    pub const IS_REAL: usize = 0;
    pub const KEY: usize = 1;
    pub const KB: usize = 2;
    pub const VF: usize = 10;
    pub const TF: usize = 14;
    pub const II: usize = 15;
    pub const D: usize = 16;
}

/// `ALU_ADD` columns (air/alu_add.rs).
mod add {
    pub const SUB: usize = 1;
    pub const A: usize = 2;
    pub const C: usize = 10;
    pub const K: usize = 14;
}

/// `ALU_LT` columns (air/alu_lt.rs).
mod lt {
    pub const A: usize = 3;
    pub const SA: usize = 19;
    pub const RA: usize = 20;
    pub const INV: usize = 23;
    pub const R: usize = 24;
}

/// `ALU_SHIFT` columns (air/alu_shift.rs).
mod shift {
    pub const A: usize = 3;
    pub const C: usize = 11;
    pub const Z: usize = 21;
    pub const EL: usize = 22;
    pub const EH: usize = 25;
    pub const P: usize = 29;
    pub const INV: usize = 33;
    pub const Q: usize = 34;
}

/// `ALU_MUL` columns (air/alu_mul.rs).
mod mul {
    pub const A: usize = 4;
    pub const C: usize = 12;
    pub const P: usize = 20;
    pub const LO: usize = 28;
    pub const HI: usize = 36;
}

/// Per-word `POSEIDON2` columns, relative to the word's base (air/poseidon.rs).
mod p2 {
    pub const PER_WORD: usize = 14;
    pub const TS: usize = 4;
    pub const DIFF: usize = 5;
    pub const OUT: usize = 8;
}

fn v(x: u32) -> Val {
    Val::from_u32(x)
}

fn byte_op(op: u32, x: u32, y: u32) -> u32 {
    match op {
        1 => x & y,
        2 => x | y,
        _ => x ^ y,
    }
}

/// A statement with its traces, tables and public values.
struct Case {
    st: Statement,
    airs: Vec<Table>,
    traces: Vec<RowMajorMatrix<Val>>,
    public: Vec<Vec<Val>>,
}

impl Case {
    /// The honest trace of `exec` (asserted valid), or of a forged witness.
    fn of(program: Arc<Program>, exec: &Execution) -> Self {
        let st = Statement::single(program, exec.exit_code, exec.output.clone(), [7; 32]);
        let traces = trace::build(&st, exec);
        let airs = trace::tables(&st);
        let public = trace::public_values(&st);
        Case {
            st,
            airs,
            traces,
            public,
        }
    }

    fn honest(asm: &Asm, input: &[u32]) -> Self {
        let (program, exec) = execute(asm, input);
        let c = Case::of(program, &exec);
        assert_eq!(c.violations(), vec![], "the honest trace is valid");
        c
    }

    fn violations(&self) -> Vec<Violation> {
        check(&self.airs, &self.traces, &self.public)
    }

    fn w(&self, t: usize) -> usize {
        self.traces[t].width()
    }

    fn get(&self, t: usize, r: usize, c: usize) -> Val {
        self.traces[t].values[r * self.w(t) + c]
    }

    fn u(&self, t: usize, r: usize, c: usize) -> u32 {
        self.get(t, r, c).as_canonical_u32()
    }

    fn set(&mut self, t: usize, r: usize, c: usize, x: Val) {
        let w = self.w(t);
        self.traces[t].values[r * w + c] = x;
    }

    /// Writes the four little-endian bytes of `x` at columns `c..c + 4`.
    fn set_word(&mut self, t: usize, r: usize, c: usize, x: u32) {
        for i in 0..4 {
            self.set(t, r, c + i, v((x >> (8 * i)) & 0xff));
        }
    }

    fn word(&self, t: usize, r: usize, c: usize) -> u32 {
        (0..4).fold(0, |a, i| a | (self.u(t, r, c + i) << (8 * i)))
    }

    /// Rows of table `t` whose values satisfy `pred`.
    fn find(&self, t: usize, pred: impl Fn(&[Val]) -> bool) -> Vec<usize> {
        let w = self.w(t);
        (0..self.traces[t].height())
            .filter(|&r| pred(&self.traces[t].values[r * w..(r + 1) * w]))
            .collect()
    }

    /// Real CPU rows of instruction class `cls` (and ALU op `op`, if given).
    fn cpu_rows(&self, cls: usize, op: Option<u32>) -> Vec<usize> {
        self.find(CPU, |r| {
            r[cpu::IS_REAL] == Val::ONE
                && r[cpu::INS + f::FLAGS + cls] == Val::ONE
                && op.is_none_or(|o| r[cpu::INS + f::ALU_OP] == v(o))
        })
    }

    /// The single row of ALU table `t` providing `(op, a, b)` with the given
    /// flag column set (`a` at `a_col`, `b` right after it).
    fn alu_row(&self, t: usize, flag: usize, a_col: usize, a: u32, b: u32) -> usize {
        let rows = self.find(t, |r| {
            r[flag] == Val::ONE
                && (0..4).all(|i| r[a_col + i] == v((a >> (8 * i)) & 0xff))
                && (0..4).all(|i| r[a_col + 4 + i] == v((b >> (8 * i)) & 0xff))
        });
        assert_eq!(rows.len(), 1, "one ALU row for the request");
        rows[0]
    }

    /// Recomputes the byte table's multiplicities for every lookup of a byte
    /// pair (or a correct byte operation) the forged traces make, so that the
    /// only unbalanced byte messages left are those that are not in the table.
    fn rebalance_bytes(&mut self) {
        let w = self.w(BYTE);
        for x in self.violations() {
            let Violation::Unbalanced { bus, message, net } = x else {
                continue;
            };
            let slot = match (bus.as_str(), message.as_slice()) {
                ("bvm/byte-range", &[a, b]) if a < 256 && b < 256 => Some((a * 256 + b, 0)),
                ("bvm/byte-op", &[op, a, b, c])
                    if (1..=3).contains(&op) && a < 256 && b < 256 && c == byte_op(op, a, b) =>
                {
                    Some((a * 256 + b, op as usize))
                }
                _ => None,
            };
            if let Some((row, col)) = slot {
                self.traces[BYTE].values[row as usize * w + col] += v(net);
            }
        }
    }
}

fn execute(asm: &Asm, input: &[u32]) -> (Arc<Program>, Execution) {
    let program = Arc::new(asm.finish().unwrap());
    let exec = run(&program, input, MAX_CYCLES).expect("halts");
    (program, exec)
}

/// Asserts that the forged trace is rejected, and only by violations that
/// `expected` accepts (the targeted rule).
fn assert_rejected_only_by(what: &str, v: &[Violation], expected: impl Fn(&Violation) -> bool) {
    assert!(
        !v.is_empty(),
        "{what}: the forged trace satisfies every constraint"
    );
    assert!(
        v.iter().all(expected),
        "{what}: the forgery is not targeted; violations: {v:?}"
    );
}

fn is_constraint(x: &Violation, t: usize, r: usize) -> bool {
    matches!(x, Violation::Constraint { table, row, .. } if *table == t && *row == r)
}

fn is_range_miss(x: &Violation, msg: &[u32]) -> bool {
    matches!(x, Violation::Unbalanced { bus, message, .. } if bus == "bvm/byte-range" && message == msg)
}

/// A non-byte value in a range lookup (the message cannot be in the table).
fn is_non_byte_range(x: &Violation) -> bool {
    matches!(x, Violation::Unbalanced { bus, message, .. }
        if bus == "bvm/byte-range" && message.iter().any(|m| *m >= 256))
}

/// The number of instructions `block` assembles to.
fn len_of(block: fn(&mut Asm)) -> u32 {
    let mut a = Asm::new(BASE);
    block(&mut a);
    a.finish().unwrap().code.len() as u32
}

/// A block without pc-dependent instructions: writes 7, halts with 3.
fn block(a: &mut Asm) {
    a.imm(Op::Addi, A1, ZERO, 7).write_reg(A1).halt(3);
}

/// The witness with control redirected after step `j` by `delta` bytes: step
/// `j` continues at `next_pc + delta`, and every later step runs at its pc
/// plus `delta` (an identical copy of the code it ran).
fn redirect(exec: &Execution, j: usize, delta: u32) -> Execution {
    let mut e = exec.clone();
    e.steps[j].next_pc = e.steps[j].next_pc.wrapping_add(delta);
    for s in &mut e.steps[j + 1..] {
        s.pc = s.pc.wrapping_add(delta);
        s.next_pc = s.next_pc.wrapping_add(delta);
    }
    e
}

/// Index of the first step executing `op`.
fn step_of(exec: &Execution, op: Op) -> usize {
    exec.steps
        .iter()
        .position(|s| s.instr.op == op)
        .expect("the program executes the instruction")
}

/// The CPU row of a step: rows are in step order.
fn cpu_row(j: usize) -> usize {
    j
}

// ---- control flow ----

/// Jumps (JAL, JALR, taken and not-taken branches, both polarities) that
/// continue at an identical copy of their real target: every row is a valid
/// instruction of the program, every bus balances, and only the next-pc rule
/// of the jump's row rejects the trace.
#[test]
fn a_jump_to_an_identical_copy_of_its_target_is_rejected() {
    let n = len_of(block) * 4;
    // (program, jumping op, delta from the real target to the copy)
    let mut cases: Vec<(&str, Asm, Op, u32)> = Vec::new();
    let mut a = Asm::new(BASE);
    a.jal(ZERO, "copy");
    block(&mut a);
    a.label("copy");
    block(&mut a);
    cases.push(("JAL", a, Op::Jal, n.wrapping_neg()));
    let mut a = Asm::new(BASE);
    a.jal(RA, "f");
    block(&mut a);
    block(&mut a);
    a.label("f").imm(Op::Jalr, ZERO, RA, 0);
    cases.push(("JALR", a, Op::Jalr, n));
    for (name, op, x, y, taken) in [
        ("BEQ taken", Op::Beq, 1, 1, true),
        ("BNE not taken", Op::Bne, 1, 1, false),
        ("BLT not taken", Op::Blt, 1, 0x8000_0000, false),
        ("BGE taken", Op::Bge, 2, 1, true),
        ("BLTU taken", Op::Bltu, 1, 0x8000_0000, true),
        ("BGEU not taken", Op::Bgeu, 1, 0x8000_0000, false),
    ] {
        let mut a = Asm::new(BASE);
        a.li(T0, x).li(T1, y).branch(op, T0, T1, "copy");
        block(&mut a);
        a.label("copy");
        block(&mut a);
        let delta = if taken { n.wrapping_neg() } else { n };
        cases.push((name, a, op, delta));
    }
    for (name, asm, op, delta) in cases {
        let (program, exec) = execute(&asm, &[]);
        let honest = Case::of(program.clone(), &exec);
        assert_eq!(honest.violations(), vec![], "{name}: honest");
        let j = step_of(&exec, op);
        let forged = Case::of(program, &redirect(&exec, j, delta));
        assert_rejected_only_by(name, &forged.violations(), |x| {
            is_constraint(x, CPU, cpu_row(j))
        });
    }
}

/// The whole execution run on an identical copy of the code that starts
/// elsewhere: only the first-row rule `pc = entry` rejects it.
#[test]
fn an_execution_that_does_not_start_at_the_entry_is_rejected() {
    let mut a = Asm::new(BASE);
    block(&mut a);
    block(&mut a);
    let (program, exec) = execute(&a, &[]);
    let mut e = exec.clone();
    let n = len_of(block) * 4;
    for s in &mut e.steps {
        s.pc += n;
        s.next_pc += n;
    }
    let forged = Case::of(program, &e);
    assert_rejected_only_by("entry", &forged.violations(), |x| is_constraint(x, CPU, 0));
}

/// An instruction without effect is skipped: either its predecessor claims
/// the right next pc and the following row starts elsewhere (the transition
/// rule), or the predecessor claims the skip itself (the next-pc rule).
#[test]
fn a_skipped_instruction_is_rejected() {
    let mut a = Asm::new(BASE);
    a.li(T0, 5)
        .imm(Op::Addi, ZERO, ZERO, 0)
        .imm(Op::Addi, A1, T0, 1)
        .write_reg(A1)
        .halt(0);
    let (program, exec) = execute(&a, &[]);
    let k = 1; // the no-op
    assert_eq!(exec.steps[k].instr.rd, 0);
    for claim_skip in [false, true] {
        let mut e = exec.clone();
        e.steps.remove(k);
        for s in &mut e.steps[k..] {
            s.clk -= 1;
        }
        if claim_skip {
            e.steps[k - 1].next_pc += 4;
        }
        let forged = Case::of(program.clone(), &e);
        assert_rejected_only_by(
            &format!("skip (claimed by the predecessor: {claim_skip})"),
            &forged.violations(),
            |x| is_constraint(x, CPU, k - 1),
        );
    }
}

/// The execution continues after a `HALT` (the same halting code runs twice):
/// only the rule that nothing runs after a halt rejects it.
#[test]
fn running_past_a_halt_is_rejected() {
    let mut a = Asm::new(BASE);
    a.li(T0, 1).halt(0).halt(0);
    let (program, exec) = execute(&a, &[]);
    let n = exec.steps.len();
    let h = n - 1; // the first (and only executed) ECALL
    let tail = len_of(|a| {
        a.halt(0);
    }) as usize;
    let mut e = exec.clone();
    for s in &exec.steps[n - tail..] {
        let mut s = *s;
        s.pc += 4 * tail as u32;
        s.next_pc += 4 * tail as u32;
        s.clk += tail as u32;
        e.steps.push(s);
    }
    let forged = Case::of(program, &e);
    assert_rejected_only_by("run past halt", &forged.violations(), |x| {
        is_constraint(x, CPU, cpu_row(h))
    });
}

/// The execution stops without a `HALT` (its last step dropped), on a row in
/// the middle of the table (transition rule) and on the table's last row (the
/// last-row rule).
#[test]
fn an_execution_that_stops_without_halting_is_rejected() {
    for fill_the_table in [false, true] {
        let mut a = Asm::new(BASE);
        a.li(T0, 1);
        if fill_the_table {
            // 1 + nops + 2 (li a0, li a7) rows remain: exactly MIN_HEIGHT.
            for _ in 0..MIN_HEIGHT - 3 {
                a.imm(Op::Addi, ZERO, ZERO, 0);
            }
        }
        a.halt(0);
        let (program, exec) = execute(&a, &[]);
        let mut e = exec.clone();
        e.steps.pop();
        let last = e.steps.len() - 1;
        let forged = Case::of(program, &e);
        assert_eq!(forged.traces[CPU].height() == e.steps.len(), fill_the_table);
        assert_rejected_only_by(
            &format!("no halt (full table: {fill_the_table})"),
            &forged.violations(),
            |x| is_constraint(x, CPU, last),
        );
    }
}

// ---- the memory argument ----

/// A load returns the word's initial value after a store, through a second
/// `MEM_INIT` row for the same key (a second history starting at 0). Every
/// bus balances; only the strictly-increasing-keys rule (the range of the
/// key difference) rejects it.
#[test]
fn a_load_cannot_return_a_stale_value_through_a_duplicated_key() {
    let mut a = Asm::new(BASE);
    a.data(DATA, vec![0; 4], 64);
    a.li(S0, DATA)
        .li(T0, 0x55)
        .store(Op::Sw, T0, S0, 0)
        .load(Op::Lw, ZERO, S0, 0)
        .halt(0);
    let mut c = Case::honest(&a, &[]);
    let st_row = c.cpu_rows(class::STORE, None)[0];
    let ld_row = c.cpu_rows(class::LOAD, None)[0];
    let ts = |row: usize, slot: u32| 4 * (row as u32 + 1) + slot;
    let (ts3_store, ts2_load) = (ts(st_row, 3), ts(ld_row, 2));
    let key = DATA / 4;

    // The load reads 0 at timestamp 0 (the second history's start).
    c.set_word(CPU, ld_row, cpu::M, 0);
    c.set(CPU, ld_row, cpu::TM, Val::ZERO);
    let d = ts2_load - 1;
    for i in 0..3 {
        c.set(CPU, ld_row, cpu::DM + i, v((d >> (8 * i)) & 0xff));
    }
    c.set_word(CPU, ld_row, cpu::C, 0);

    // The first history ends at the store; the second one at the load.
    let rows = c.find(MEM_INIT, |r| {
        r[init::IS_REAL] == Val::ONE && r[init::KEY] == v(key)
    });
    let first = rows[0];
    c.set(MEM_INIT, first, init::TF, v(ts3_store));
    let w = c.w(MEM_INIT);
    let h = c.traces[MEM_INIT].height();
    assert_eq!(
        c.get(MEM_INIT, h - 1, init::IS_REAL),
        Val::ZERO,
        "room for a row"
    );
    let m = &mut c.traces[MEM_INIT].values;
    m.copy_within((first + 1) * w..(h - 1) * w, (first + 2) * w);
    let second = first + 1;
    let mut row = vec![Val::ZERO; w];
    row[init::IS_REAL] = Val::ONE;
    row[init::KEY] = v(key);
    for i in 0..4 {
        row[init::KB + i] = v((key >> (8 * i)) & 0xff);
    }
    row[init::TF] = v(ts2_load);
    row[init::II] = Val::ZERO;
    // key = key + 1 + D, so D = −1 = p − 1 = 0x7800_0000.
    let minus_one = Val::ORDER_U32 - 1;
    for i in 0..4 {
        row[init::D + i] = v((minus_one >> (8 * i)) & 0xff);
    }
    m[second * w..(second + 1) * w].copy_from_slice(&row);
    c.rebalance_bytes();
    // range_bits(D3, 3) looks up (D3, D3·32) = (120, 3840).
    assert_rejected_only_by("duplicated key", &c.violations(), |x| {
        is_range_miss(x, &[120, 3840])
    });
}

/// A register read consumes the entry a **later** access produces (the chain
/// of `x0`'s accesses reordered into a cycle, every message balanced): only
/// the range check of the read's timestamp difference rejects it, for each
/// byte position of the difference.
#[test]
fn a_register_read_from_the_future_is_rejected() {
    let mut a = Asm::new(BASE);
    for k in 0..6 {
        a.imm(Op::Addi, A1, ZERO, k);
    }
    a.halt(0);
    let honest = Case::honest(&a, &[]);
    // x0's accesses in timestamp order: (row, t column, d column, ts).
    let mut acc = Vec::new();
    for r in honest.find(CPU, |r| r[cpu::IS_REAL] == Val::ONE) {
        for (idx, t_col, d_col, slot) in
            [(f::RS1, cpu::TA, cpu::DA, 0), (f::RS2, cpu::TB, cpu::DB, 1)]
        {
            if honest.u(CPU, r, cpu::INS + idx) == 0 {
                acc.push((r, t_col, d_col, 4 * (r as u32 + 1) + slot));
            }
        }
    }
    assert!(acc.len() >= 3);
    let (i, j, s) = (acc[0], acc[1], acc[2]);
    let tp_i = honest.u(CPU, i.0, i.1);
    let x = (v(i.3) - v(j.3) - Val::ONE).as_canonical_u32();
    let inv256 = v(256).inverse();
    for (name, d) in [
        ("top byte", [v(x & 0xff), v((x >> 8) & 0xff), v(x >> 16)]),
        ("low byte", [v(x), Val::ZERO, Val::ZERO]),
        ("middle byte", [Val::ZERO, v(x) * inv256, Val::ZERO]),
    ] {
        let mut c = Case {
            st: honest.st.clone(),
            airs: honest.airs.clone(),
            traces: honest.traces.clone(),
            public: honest.public.clone(),
        };
        // i consumes j's entry; j still consumes i's; s consumes i's old one.
        c.set(CPU, i.0, i.1, v(j.3));
        for (k, dk) in d.iter().enumerate() {
            c.set(CPU, i.0, i.2 + k, *dk);
        }
        c.set(CPU, s.0, s.1, v(tp_i));
        let ds = s.3 - tp_i - 1;
        for k in 0..3 {
            c.set(CPU, s.0, s.2 + k, v((ds >> (8 * k)) & 0xff));
        }
        c.rebalance_bytes();
        assert_rejected_only_by(name, &c.violations(), is_non_byte_range);
        assert_eq!(c.violations().len(), 1, "{name}");
    }
}

/// A sign-extending byte load claims a zero extension, with the sign bit moved
/// into the low seven bits: only their range check rejects it.
#[test]
fn a_signed_load_cannot_drop_its_sign() {
    let mut a = Asm::new(BASE);
    a.data(DATA, vec![0xf3, 0x82, 0, 0], 64);
    a.li(S0, DATA)
        .load(Op::Lb, ZERO, S0, 0)
        .load(Op::Lh, ZERO, S0, 0)
        .halt(0);
    let mut c = Case::honest(&a, &[]);
    let rows = c.cpu_rows(class::LOAD, None);
    // LB: sign byte 0xf3; LH: sign byte 0x82.
    for (r, value, sign) in [(rows[0], 0xf3u32, 0xf3u32), (rows[1], 0x82f3, 0x82)] {
        assert_eq!(c.u(CPU, r, cpu::SGN), 1);
        c.set(CPU, r, cpu::SGN, Val::ZERO);
        c.set(CPU, r, cpu::SR, v(sign));
        c.set_word(CPU, r, cpu::C, value);
    }
    c.rebalance_bytes();
    assert_rejected_only_by("dropped sign", &c.violations(), |x| {
        is_range_miss(x, &[0xf3, 0x1e6]) || is_range_miss(x, &[0x82, 0x104])
    });
    assert_eq!(c.violations().len(), 2);
}

// ---- ALU tables ----

/// The ALU requests of `ops` on `(a, b)`, each computed into `x0` (no
/// register write depends on the result, so a forged result changes only the
/// CPU row's claim and the ALU row providing it).
fn alu_program(reqs: &[(Op, u32, u32)]) -> Asm {
    let mut p = Asm::new(BASE);
    for &(op, a, b) in reqs {
        p.li(T0, a).li(T1, b).r(op, ZERO, T0, T1);
    }
    p.halt(0);
    p
}

/// Sets the CPU's claimed result of its request `(op, a, b)`.
fn claim(c: &mut Case, op: u32, a: u32, b: u32, result: u32) {
    let rows = c.find(CPU, |r| {
        r[cpu::IS_REAL] == Val::ONE
            && r[cpu::INS + f::FLAGS + class::ALU_RR] == Val::ONE
            && r[cpu::INS + f::ALU_OP] == v(op)
            && (0..4).all(|i| r[cpu::A + i] == v((a >> (8 * i)) & 0xff))
            && (0..4).all(|i| r[cpu::B + i] == v((b >> (8 * i)) & 0xff))
    });
    assert_eq!(rows.len(), 1);
    c.set_word(CPU, rows[0], cpu::C, result);
}

/// A false sum (or difference) with carries solved in the field: the four
/// byte equations hold and the bus balances; only the carries' booleanity
/// rejects it.
#[test]
fn an_addition_with_non_boolean_carries_is_rejected() {
    let (a, b) = (0x1234_5678u32, 0x0101_0101u32);
    let mut c = Case::honest(&alu_program(&[(Op::Add, a, b), (Op::Sub, a, b)]), &[]);
    let inv256 = v(256).inverse();
    for (op, sub) in [(alu_op::ADD, false), (alu_op::SUB, true)] {
        let r = c.alu_row(ADD, if sub { add::SUB } else { 0 }, add::A, a, b);
        let truth = if sub {
            a.wrapping_sub(b)
        } else {
            a.wrapping_add(b)
        };
        let lie = truth ^ 1;
        claim(&mut c, op, a, b, lie);
        c.set_word(ADD, r, add::C, lie);
        // ADD: a + b = c; SUB: b + c = a.
        let (uu, vv, ww) = if sub { (b, lie, a) } else { (a, b, lie) };
        let byte = |x: u32, i: usize| v((x >> (8 * i)) & 0xff);
        let mut carry = Val::ZERO;
        for i in 0..4 {
            let k = (byte(uu, i) + byte(vv, i) + carry - byte(ww, i)) * inv256;
            c.set(ADD, r, add::K + i, k);
            carry = k;
        }
        c.rebalance_bytes();
        assert_rejected_only_by(
            "non-boolean carries",
            &c.violations(),
            |x| matches!(x, Violation::Constraint { table, .. } if *table == ADD),
        );
        // Restore for the next case: the oracle checks one forgery at a time.
        c = Case::honest(&alu_program(&[(Op::Add, a, b), (Op::Sub, a, b)]), &[]);
    }
}

/// A comparison whose operand's sign bit is moved into its low seven bits:
/// the signed comparison then reads it as positive. Only the range check of
/// those seven bits rejects it.
#[test]
fn a_signed_comparison_cannot_hide_a_sign_bit() {
    let (a, b) = (0x8000_0005u32, 3u32);
    let mut c = Case::honest(&alu_program(&[(Op::Slt, a, b)]), &[]);
    let r = c.alu_row(LT, 0, lt::A, a, b);
    assert_eq!(c.u(LT, r, lt::R), 1);
    c.set(LT, r, lt::SA, Val::ZERO);
    c.set(LT, r, lt::RA, v(0x80));
    // Both "positive": a <s b iff a <u b, which is false.
    c.set(LT, r, lt::R, Val::ZERO);
    claim(&mut c, alu_op::SLT, a, b, 0);
    c.rebalance_bytes();
    assert_rejected_only_by("hidden sign", &c.violations(), |x| {
        is_range_miss(x, &[0x80, 0x100])
    });
}

/// `a == b` claimed for different operands, with the inverse witness zeroed:
/// only the zero test `s · z = 0` rejects it. The branch has offset 4, so
/// its outcome does not change the next pc.
#[test]
fn an_equality_cannot_be_claimed_for_different_operands() {
    let (a, b) = (7u32, 9u32);
    let mut p = Asm::new(BASE);
    p.li(T0, a)
        .li(T1, b)
        .branch(Op::Beq, T0, T1, "next")
        .label("next")
        .halt(0);
    let mut c = Case::honest(&p, &[]);
    let r = c.alu_row(LT, 2, lt::A, a, b);
    c.set(LT, r, lt::INV, Val::ZERO);
    c.set(LT, r, lt::R, Val::ONE);
    let br = c.cpu_rows(class::BRANCH, None)[0];
    c.set(CPU, br, cpu::COND, Val::ONE);
    assert_rejected_only_by("false equality", &c.violations(), |x| {
        is_constraint(x, LT, r)
    });
}

/// MULHU's high word off by one: one product byte takes 256 more and its
/// carry one less, so every byte equation holds and the bus balances. Only
/// the product bytes' range check rejects it.
#[test]
fn a_product_byte_cannot_absorb_a_carry() {
    let (a, b) = (0xffff_ffffu32, 0xffff_fff0u32);
    let mut c = Case::honest(&alu_program(&[(Op::Mulhu, a, b)]), &[]);
    let r = c.alu_row(MUL, 3, mul::A, a, b);
    let k = 3;
    let (p3, p4) = (c.u(MUL, r, mul::P + k), c.u(MUL, r, mul::P + k + 1));
    let carry = c.u(MUL, r, mul::LO + k) + 256 * c.u(MUL, r, mul::HI + k);
    assert!(carry >= 1 && p4 >= 1);
    c.set(MUL, r, mul::P + k, v(p3 + 256));
    c.set(MUL, r, mul::LO + k, v((carry - 1) & 0xff));
    c.set(MUL, r, mul::HI + k, v((carry - 1) >> 8));
    c.set(MUL, r, mul::P + k + 1, v(p4 - 1));
    let lie = c.word(MUL, r, mul::C) - 1;
    c.set_word(MUL, r, mul::C, lie);
    claim(&mut c, alu_op::MULHU, a, b, lie);
    c.rebalance_bytes();
    let p2 = c.u(MUL, r, mul::P + 2);
    assert_rejected_only_by("carry into a product byte", &c.violations(), |x| {
        is_range_miss(x, &[p2, p3 + 256])
    });
}

/// A shift by a nonzero amount claims `s = 0` (so `c = a`, no product): only
/// `z · s = 0` rejects it.
#[test]
fn a_shift_cannot_claim_a_zero_amount() {
    let (a, b) = (0x8765_4321u32, 1u32);
    let mut c = Case::honest(&alu_program(&[(Op::Srl, a, b)]), &[]);
    let r = c.alu_row(SHIFT, 1, shift::A, a, b);
    c.set(SHIFT, r, shift::Z, Val::ONE);
    c.set(SHIFT, r, shift::INV, Val::ZERO);
    for j in 0..3 {
        c.set(SHIFT, r, shift::EL + j, Val::ZERO);
    }
    for k in 0..4 {
        c.set(SHIFT, r, shift::EH + k, v((k == 0) as u32));
        c.set(SHIFT, r, shift::P + k, v((k == 0) as u32));
    }
    c.set(SHIFT, r, shift::Q, Val::ONE);
    c.set_word(SHIFT, r, shift::C, a);
    claim(&mut c, alu_op::SRL, a, b, a);
    // The delegated product is no longer requested: remove its row.
    let m = c.alu_row(MUL, 3, mul::A, a, 1 << 31);
    for col in 0..alu_mul::WIDTH {
        c.set(MUL, m, col, Val::ZERO);
    }
    c.rebalance_bytes();
    assert_rejected_only_by("zero shift amount", &c.violations(), |x| {
        is_constraint(x, SHIFT, r)
    });
}

/// SLL by 1 claims the product by 4 (exponent 2 instead of 1), with a valid
/// power-of-two witness and an honest multiplier row for it: only the
/// exponent rule rejects it.
#[test]
fn a_shift_cannot_use_another_power_of_two() {
    let (a, b) = (0x0123_4567u32, 1u32);
    let mut c = Case::honest(&alu_program(&[(Op::Sll, a, b)]), &[]);
    let r = c.alu_row(SHIFT, 0, shift::A, a, b);
    c.set(SHIFT, r, shift::EL, Val::ZERO);
    c.set(SHIFT, r, shift::EL + 1, Val::ONE);
    c.set(SHIFT, r, shift::Q, v(4));
    c.set(SHIFT, r, shift::P, v(4));
    let lie = a.wrapping_mul(4);
    c.set_word(SHIFT, r, shift::C, lie);
    claim(&mut c, alu_op::SLL, a, b, lie);
    // The multiplier row for (MUL, a, 2) becomes an honest row for (MUL, a, 4).
    let m = c.alu_row(MUL, 0, mul::A, a, 2);
    let honest = alu_mul::trace(
        &[(alu_op::MUL, a, 4)],
        &mut blacksilk_zkvm::air::byte::ByteCounter::new(),
        MIN_HEIGHT,
    );
    for col in 0..alu_mul::WIDTH {
        c.set(MUL, m, col, honest.values[col]);
    }
    c.rebalance_bytes();
    assert_rejected_only_by("wrong exponent", &c.violations(), |x| {
        is_constraint(x, SHIFT, r)
    });
}

// ---- POSEIDON2 ----

/// One `POSEIDON2` call on a buffer that is never accessed again.
fn poseidon_once() -> Asm {
    let mut p = Asm::new(BASE);
    let bytes: Vec<u8> = (0..16u32)
        .flat_map(|k| (k.wrapping_mul(0x0765_4321) % 0x7800_0001).to_le_bytes())
        .collect();
    p.data(DATA, bytes, 64);
    p.li(A0, DATA).ecall(3).halt(0);
    p
}

/// A digest word written to memory as its value plus p, the same field
/// element (so the permutation constraints hold) but another 32-bit word for
/// the program: only the canonical-encoding check rejects it.
#[test]
fn a_digest_word_has_a_single_byte_encoding() {
    let mut c = Case::honest(&poseidon_once(), &[]);
    let k = (0..16)
        .find(|&k| {
            let base = poseidon::WIDTH - 16 * p2::PER_WORD;
            c.word(P2, 0, base + k * p2::PER_WORD + p2::OUT) >= 1 << 24
        })
        .expect("a large output word");
    let base = poseidon::WIDTH - 16 * p2::PER_WORD + k * p2::PER_WORD;
    let out = c.word(P2, 0, base + p2::OUT);
    let forged = out + Val::ORDER_U32;
    c.set_word(P2, 0, base + p2::OUT, forged);
    let key = DATA / 4 + k as u32;
    let row = c.find(MEM_INIT, |r| {
        r[init::IS_REAL] == Val::ONE && r[init::KEY] == v(key)
    })[0];
    c.set_word(MEM_INIT, row, init::VF, forged);
    c.rebalance_bytes();
    assert_rejected_only_by("second encoding", &c.violations(), is_non_byte_range);
    assert_eq!(c.violations().len(), 1);
}

/// A buffer word's timestamp difference written with a non-byte limb (the
/// same field value): only the difference's range check rejects it, for
/// each limb.
#[test]
fn a_poseidon2_timestamp_difference_must_be_three_bytes() {
    let honest = Case::honest(&poseidon_once(), &[]);
    let base0 = poseidon::WIDTH - 16 * p2::PER_WORD;
    let inv256 = v(256).inverse();
    let inv65536 = v(65536).inverse();
    for k in [0usize, 5] {
        let base = base0 + k * p2::PER_WORD;
        let d: Val = (0..3)
            .map(|i| honest.get(P2, 0, base + p2::DIFF + i) * v(1 << (8 * i)))
            .sum();
        for (name, limbs) in [
            ("low limb", [d, Val::ZERO, Val::ZERO]),
            ("middle limb", [Val::ZERO, d * inv256, Val::ZERO]),
            ("top limb", [Val::ZERO, Val::ZERO, d * inv65536]),
        ] {
            if limbs.iter().all(|x| x.as_canonical_u32() < 256) {
                continue;
            }
            let mut c = Case {
                st: honest.st.clone(),
                airs: honest.airs.clone(),
                traces: honest.traces.clone(),
                public: honest.public.clone(),
            };
            for (i, x) in limbs.iter().enumerate() {
                c.set(P2, 0, base + p2::DIFF + i, *x);
            }
            assert_eq!(c.u(P2, 0, base + p2::TS), honest.u(P2, 0, base + p2::TS));
            c.rebalance_bytes();
            assert_rejected_only_by(name, &c.violations(), is_non_byte_range);
        }
    }
}

// ---- lying generators (TM2-X 1.8 item 2) ----
//
// The trace generator recomputes every ALU result and the permutation itself,
// and refuses a witness that disagrees, so the interpreter cannot make it lie.
// These tests lie one level down: the interpreter runs a program `P'` that
// differs from the statement's program `P` in one instruction (the same
// registers, another operation), the generator builds every table honestly
// from that run, and only the lying row's decoded fields are set back to
// `P`'s instruction. The ALU tables are then rebuilt honestly from the
// requests the forged CPU makes. Every column that depends on the wrong
// result is consistent with it, and the statement claims the output the
// wrong result leads to.

/// Every ALU request the real CPU rows make, as `trace.rs` records them.
fn alu_requests(c: &Case) -> Vec<(u32, u32, u32)> {
    let code_end = c.st.program.code_end();
    let mut out = Vec::new();
    for r in c.find(CPU, |r| r[cpu::IS_REAL] == Val::ONE) {
        let is = |cls: usize| c.u(CPU, r, cpu::INS + f::FLAGS + cls) == 1;
        let op = c.u(CPU, r, cpu::INS + f::ALU_OP);
        let (a, b) = (c.word(CPU, r, cpu::A), c.word(CPU, r, cpu::B));
        let imm = c.word(CPU, r, cpu::INS + f::IMM);
        let pc = c.u(CPU, r, cpu::PC);
        let addr = c.word(CPU, r, cpu::S);
        if is(class::ALU_RR) || is(class::BRANCH) {
            out.push((op, a, b));
        }
        if is(class::ALU_RI) {
            out.push((op, a, imm));
        }
        if is(class::AUIPC) {
            out.push((alu_op::ADD, pc, imm));
        }
        if is(class::JAL) || is(class::JALR) {
            out.push((alu_op::ADD, pc, 4));
        }
        if is(class::LOAD) || is(class::STORE) || is(class::JALR) {
            out.push((alu_op::ADD, a, imm));
        }
        if is(class::LOAD) || is(class::STORE) {
            out.push((alu_op::SLTU, addr, 0x1000));
        }
        if is(class::STORE) {
            out.push((alu_op::SLTU, addr, code_end));
        }
        if c.u(CPU, r, cpu::SP2) == 1 {
            out.push((alu_op::SLTU, b, code_end));
            out.push((alu_op::SLTU, b, 0x0fff_ffc1));
        }
    }
    out
}

/// Rebuilds the five ALU tables honestly (same heights) for the CPU's
/// requests, then the byte table's multiplicities.
fn rebuild_alu(c: &mut Case) {
    use blacksilk_zkvm::air::byte::ByteCounter;
    use blacksilk_zkvm::air::{alu_add, alu_bit, alu_lt, alu_shift};
    let reqs = alu_requests(c);
    let by = |set: &[u32]| -> Vec<(u32, u32, u32)> {
        reqs.iter()
            .copied()
            .filter(|r| set.contains(&r.0))
            .collect()
    };
    let mut bytes = ByteCounter::new();
    let h: Vec<usize> = c.traces.iter().map(|t| t.height()).collect();
    let add = alu_add::trace(&by(&[alu_op::ADD, alu_op::SUB]), &mut bytes, h[ADD]);
    let bit = alu_bit::trace(
        &by(&[alu_op::XOR, alu_op::OR, alu_op::AND]),
        &mut bytes,
        h[BIT],
    );
    let lt = alu_lt::trace(
        &by(&[alu_op::SLT, alu_op::SLTU, alu_op::EQ]),
        &mut bytes,
        h[LT],
    );
    let mut mul_reqs = by(&[alu_op::MUL, alu_op::MULH, alu_op::MULHSU, alu_op::MULHU]);
    let shift = alu_shift::trace(
        &by(&[alu_op::SLL, alu_op::SRL, alu_op::SRA]),
        &mut bytes,
        h[SHIFT],
        &mut mul_reqs,
    );
    let mul = alu_mul::trace(&mul_reqs, &mut bytes, h[MUL]);
    for (t, m) in [(ADD, add), (BIT, bit), (LT, lt), (SHIFT, shift), (MUL, mul)] {
        assert_eq!(m.height(), h[t], "table {t} keeps its height");
        c.traces[t] = trace::with_blinding(m);
    }
    c.rebalance_bytes();
}

/// The forged case: `lie` (the program the interpreter runs) differs from
/// `truth` (the statement's program) in one instruction; the generator's
/// trace of `lie`'s run, with that instruction's row decoded as `truth`'s
/// instruction, and the ALU tables rebuilt. Returns the case and the row.
fn lying_generator(truth: &Asm, lie: &Asm) -> (Case, usize) {
    use blacksilk_zkvm::air::program::fields;
    use blacksilk_zkvm::isa::decode;
    let p = Arc::new(truth.finish().unwrap());
    let q = Arc::new(lie.finish().unwrap());
    assert_eq!(p.code.len(), q.code.len());
    let diff: Vec<usize> = (0..p.code.len())
        .filter(|&i| p.code[i] != q.code[i])
        .collect();
    assert_eq!(diff.len(), 1, "the programs differ in one instruction");
    let pc = p.code_base + 4 * diff[0] as u32;
    let exec = run(&q, &[], MAX_CYCLES).expect("halts");
    let k = exec
        .steps
        .iter()
        .position(|s| s.pc == pc)
        .expect("executed");
    let mut c = Case::of(p.clone(), &exec);
    let fv = fields(&decode(p.code[diff[0]]).unwrap());
    for (i, x) in fv.iter().enumerate() {
        c.set(CPU, cpu_row(k), cpu::INS + i, *x);
    }
    rebuild_alu(&mut c);
    (c, cpu_row(k))
}

/// The ALU op id of an operation (`program::fields`).
fn op_id(op: Op) -> u32 {
    use blacksilk_zkvm::air::program::fields;
    use blacksilk_zkvm::isa::Instr;
    let x = Instr {
        op,
        rd: 1,
        rs1: 1,
        rs2: 1,
        imm: 0,
    };
    fields(&x)[f::ALU_OP].as_canonical_u32()
}

/// For each ALU operation, the generator computes another operation's result
/// on the same registers and carries it through the rest of the execution
/// (it is written out). Only the ALU bus rejects the trace: the ALU tables,
/// built honestly, provide the true result, never the claimed one.
#[test]
fn a_lying_generator_cannot_change_an_alu_result() {
    let (x, y) = (0x8000_0005u32, 3u32);
    for (truth, lie) in [
        (Op::Add, Op::Or),
        (Op::Sub, Op::Xor),
        (Op::Xor, Op::Or),
        (Op::Or, Op::Add),
        (Op::And, Op::Sltu),
        (Op::Slt, Op::Sltu),
        (Op::Sltu, Op::Slt),
        (Op::Sll, Op::Srl),
        (Op::Srl, Op::Sra),
        (Op::Sra, Op::Srl),
        (Op::Mul, Op::Mulhu),
        (Op::Mulh, Op::Mulhu),
        (Op::Mulhsu, Op::Mulhu),
        (Op::Mulhu, Op::Mul),
    ] {
        let prog = |op: Op| {
            let mut a = Asm::new(BASE);
            a.li(T0, x)
                .li(T1, y)
                .r(op, A1, T0, T1)
                .write_reg(A1)
                .halt(0);
            a
        };
        let (c, _) = lying_generator(&prog(truth), &prog(lie));
        assert_ne!(
            trace::alu_result(op_id(truth), x, y),
            c.st.output[0],
            "{truth:?} as {lie:?}: the lie differs from the truth"
        );
        assert_rejected_only_by(
            &format!("{truth:?} as {lie:?}"),
            &c.violations(),
            |v| matches!(v, Violation::Unbalanced { bus, .. } if bus == "bvm/alu"),
        );
    }
}

/// Loads: the generator returns another width's or signedness's value (the
/// same address and registers), carried through the execution. Only the
/// load-value rules of the lying row reject it.
#[test]
fn a_lying_generator_cannot_change_a_loaded_value() {
    for (truth, lie) in [
        (Op::Lw, Op::Lbu),
        (Op::Lw, Op::Lhu),
        (Op::Lh, Op::Lhu),
        (Op::Lb, Op::Lbu),
        (Op::Lbu, Op::Lb),
        (Op::Lhu, Op::Lh),
        (Op::Lh, Op::Lb),
    ] {
        let prog = |op: Op| {
            let mut a = Asm::new(BASE);
            a.data(DATA, vec![0xf3, 0x82, 0x81, 0x80], 64);
            a.li(S0, DATA).load(op, A1, S0, 0).write_reg(A1).halt(0);
            a
        };
        let (c, k) = lying_generator(&prog(truth), &prog(lie));
        assert_rejected_only_by(&format!("{truth:?} as {lie:?}"), &c.violations(), |v| {
            is_constraint(v, CPU, k)
        });
    }
}

/// Branches: the generator evaluates the opposite condition (BEQ as BNE, BLT
/// as BGE, ...), and the execution continues on the other path through an
/// identical copy of the code. Only the next-pc rule of the branch rejects it.
#[test]
fn a_lying_generator_cannot_flip_a_branch() {
    for (truth, lie, x, y) in [
        (Op::Beq, Op::Bne, 1, 1),
        (Op::Bne, Op::Beq, 1, 1),
        (Op::Blt, Op::Bge, 1, 0x8000_0000),
        (Op::Bge, Op::Blt, 1, 0x8000_0000),
        (Op::Bltu, Op::Bgeu, 1, 0x8000_0000),
        (Op::Bgeu, Op::Bltu, 1, 0x8000_0000),
    ] {
        let prog = |op: Op| {
            let mut a = Asm::new(BASE);
            a.li(T0, x).li(T1, y).branch(op, T0, T1, "copy");
            block(&mut a);
            a.label("copy");
            block(&mut a);
            a
        };
        let (c, k) = lying_generator(&prog(truth), &prog(lie));
        assert_rejected_only_by(&format!("{truth:?} as {lie:?}"), &c.violations(), |v| {
            is_constraint(v, CPU, k)
        });
    }
}

/// POSEIDON2: a different digest word (in its canonical encoding) is carried
/// through every dependent column: the call's output bytes and permutation
/// column, the load of it, the register chain, the write, the claimed
/// output, the final memory values and the ALU rows. The generator computes
/// the permutation itself and cannot be made to lie, so the dependent columns
/// are patched; only the permutation's constraints reject the trace.
#[test]
fn a_lying_generator_cannot_change_a_poseidon2_output() {
    let mut p = Asm::new(BASE);
    let bytes: Vec<u8> = (0..16u32)
        .flat_map(|k| (k.wrapping_mul(0x0765_4321) % 0x7800_0001).to_le_bytes())
        .collect();
    p.data(DATA, bytes, 64);
    p.li(A0, DATA)
        .ecall(3)
        .li(S0, DATA)
        .load(Op::Lw, A1, S0, 0)
        .write_reg(A1)
        .halt(0);
    let mut c = Case::honest(&p, &[]);
    let out = c.st.output[0];
    let lie = if out + 1 < Val::ORDER_U32 {
        out + 1
    } else {
        out - 1
    };
    let call_row = c.find(CPU, |r| r[cpu::SP2] == Val::ONE)[0];
    // The claimed output.
    c.st.output = vec![lie];
    c.airs = trace::tables(&c.st);
    c.public = trace::public_values(&c.st);
    let out_t = 10;
    let h = c.traces[out_t].height();
    c.traces[out_t] = trace::with_blinding(blacksilk_zkvm::air::with_public_columns(
        &c.airs[out_t],
        RowMajorMatrix::new(vec![Val::ZERO; h], 1),
    ));
    // The call's output word 0: permutation column, bytes, canonical flag.
    let base = poseidon::WIDTH - 16 * p2::PER_WORD;
    c.set(P2, 0, poseidon::P2_OUT, v(lie));
    c.set_word(P2, 0, base + p2::OUT, lie);
    c.set(P2, 0, base + 13, v((lie >> 24 == 120) as u32));
    // Every later CPU value equal to the digest word, and the final memory
    // values, become the lie.
    for r in c.find(CPU, |r| r[cpu::IS_REAL] == Val::ONE) {
        if r <= call_row {
            continue;
        }
        for col in [cpu::A, cpu::B, cpu::C, cpu::CP, cpu::M, cpu::N] {
            if c.word(CPU, r, col) == out {
                c.set_word(CPU, r, col, lie);
            }
        }
    }
    for r in c.find(MEM_INIT, |r| r[init::IS_REAL] == Val::ONE) {
        if c.word(MEM_INIT, r, init::VF) == out {
            c.set_word(MEM_INIT, r, init::VF, lie);
        }
    }
    rebuild_alu(&mut c);
    assert_rejected_only_by("lying digest", &c.violations(), |v| is_constraint(v, P2, 0));
}

/// Controls for the forgery machinery: applied without a lie, each helper
/// leaves an honest trace valid, so the rejections above come from the lies.
#[test]
fn the_forgery_machinery_preserves_honest_traces() {
    let mut kitchen = Asm::new(BASE);
    kitchen
        .data(DATA, vec![0xf3, 0x82, 0x81, 0x70], 64)
        .li(S0, DATA)
        .li(T0, 0x8000_0005)
        .li(T1, 3);
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
        kitchen.r(op, A1, T0, T1).write_reg(A1);
    }
    kitchen
        .load(Op::Lb, A1, S0, 1)
        .store(Op::Sh, T0, S0, 8)
        .li(A0, DATA)
        .ecall(3)
        .write_reg(A1)
        .halt(0);
    let mut c = Case::honest(&kitchen, &[]);
    c.rebalance_bytes();
    rebuild_alu(&mut c);
    assert_eq!(c.violations(), vec![], "rebuild_alu and rebalance_bytes");
    let (p, e) = execute(&kitchen, &[]);
    let same = Case::of(p, &redirect(&e, 3, 0));
    assert_eq!(same.violations(), vec![], "redirect by 0");
    let mut a = Asm::new(BASE);
    a.li(T0, 1)
        .li(T1, 1)
        .r(Op::Add, A1, T0, T1)
        .write_reg(A1)
        .halt(0);
    let (c, _) = lying_generator(&a, &{
        let mut b = Asm::new(BASE);
        b.li(T0, 1)
            .li(T1, 1)
            .r(Op::Or, A1, T0, T1)
            .write_reg(A1)
            .halt(0);
        b
    });
    assert_rejected_only_by(
        "control lie",
        &c.violations(),
        |v| matches!(v, Violation::Unbalanced { bus, .. } if bus == "bvm/alu"),
    );
}

/// Register keys (`REG_BASE + r`) and memory word keys (`address / 4`) must
/// be disjoint: a program that uses the highest memory word (key
/// `2^26 − 1`) and x0 satisfies the constraints, and its `MEM_INIT` holds both
/// keys once. A register base of `2^26 − 1` would alias x0 with this word.
#[test]
fn the_top_memory_word_and_the_registers_have_distinct_keys() {
    use blacksilk_zkvm::air::util::REG_BASE;
    let top = (1u32 << 28) - 4;
    let mut a = Asm::new(BASE);
    a.li(S0, top)
        .li(T0, 0x1234_5678)
        .store(Op::Sw, T0, S0, 0)
        .load(Op::Lw, A1, S0, 0)
        .r(Op::Add, A1, A1, ZERO)
        .write_reg(A1)
        .halt(0);
    let c = Case::honest(&a, &[]);
    assert_eq!(c.st.output, vec![0x1234_5678]);
    for key in [top / 4, REG_BASE] {
        assert_eq!(
            c.find(MEM_INIT, |r| r[init::IS_REAL] == Val::ONE
                && r[init::KEY] == v(key))
                .len(),
            1,
            "key {key:#x}"
        );
    }
}

/// Honest corner cases the other honest traces miss (found by the census): an
/// execution that fills the CPU table exactly (its `HALT` on the table's last
/// row), byte accesses at offset 3, a `JALR` whose sum is odd, a read of the
/// initial stack pointer, code whose pc needs all 28 bits, and `POSEIDON2`
/// buffers whose pointer has nonzero low and top bytes. Each must satisfy
/// every constraint.
#[test]
fn honest_corner_cases_satisfy_every_constraint() {
    // HALT on the CPU table's last row: 1 + nops + 3 rows = MIN_HEIGHT.
    let mut a = Asm::new(BASE);
    a.li(T0, 1);
    for _ in 0..MIN_HEIGHT - 4 {
        a.imm(Op::Addi, ZERO, ZERO, 0);
    }
    a.halt(0);
    let c = Case::honest(&a, &[]);
    let h = c.traces[CPU].height();
    assert_eq!(h, MIN_HEIGHT);
    assert_eq!(c.u(CPU, h - 1, cpu::SH), 1, "the halt is the last row");

    // Offset 3 (LB, LBU, SB), an odd JALR sum, the initial sp.
    let mut a = Asm::new(BASE);
    a.data(DATA, vec![1, 2, 3, 0x84], 64);
    a.li(S0, DATA)
        .load(Op::Lb, A1, S0, 3)
        .write_reg(A1)
        .load(Op::Lbu, A1, S0, 3)
        .write_reg(A1)
        .li(T0, 0x5a)
        .store(Op::Sb, T0, S0, 3)
        .load(Op::Lw, A1, S0, 0)
        .write_reg(A1)
        .imm(Op::Addi, A1, SP, 0)
        .write_reg(A1)
        .jal(RA, "f")
        .halt(0)
        .label("f")
        // ra + 1 is odd: the target is ra (bit 0 cleared).
        .imm(Op::Jalr, ZERO, RA, 1);
    let c = Case::honest(&a, &[]);
    assert_eq!(
        c.st.output,
        vec![0xffff_ff84, 0x84, 0x5a03_0201, blacksilk_zkvm::STACK_TOP]
    );

    // Code at the top of the allowed range: pc needs all 28 bits.
    let mut a = Asm::new(0x0fe0_0000);
    a.li(T0, 3).r(Op::Add, A1, T0, T0).write_reg(A1).halt(0);
    let c = Case::honest(&a, &[]);
    assert_eq!(c.u(CPU, 0, cpu::PB + 3), 0x0f);

    // POSEIDON2 at a pointer with nonzero low and top bytes.
    let ptr = 0x0123_4564u32;
    let mut a = Asm::new(BASE);
    a.data(ptr, vec![0; 64], 64);
    a.li(A0, ptr)
        .ecall(3)
        .li(S0, ptr)
        .load(Op::Lw, A1, S0, 0)
        .write_reg(A1)
        .halt(0);
    Case::honest(&a, &[]);
}

// ---- the trace generator (W4-MUTAIR run B: trace.rs) ----

/// A program using every budgeted table: loops, ALU operations, a shift by a
/// nonzero amount (delegated to the multiplier), memory and POSEIDON2.
fn budget_program() -> Asm {
    let mut p = Asm::new(BASE);
    p.data(DATA, vec![0; 64], 128);
    p.li(S0, DATA).li(T0, 5).li(T1, 0x1234_5678);
    p.label("loop")
        .r(Op::Add, A1, T1, T0)
        .r(Op::Xor, A1, A1, T1)
        .r(Op::Sll, A2, A1, T0)
        .r(Op::Mul, A2, A2, T1)
        .store(Op::Sw, A2, S0, 4)
        .imm(Op::Addi, T0, T0, -1)
        .branch(Op::Bne, T0, ZERO, "loop")
        .li(A0, DATA)
        .ecall(3)
        .load(Op::Lw, A1, S0, 0)
        .write_reg(A1)
        .halt(0);
    p
}

/// Real rows of table `t` (by its flag columns `flags`).
fn real_rows(c: &Case, t: usize, flags: std::ops::Range<usize>) -> usize {
    c.find(t, |r| flags.clone().any(|k| r[k] != Val::ZERO))
        .len()
}

/// `trace::usage` reports exactly the rows the generator fills, and a
/// budgeted statement takes its fixed shape: every table at the height
/// `Statement::shape` gives, single and with a further execution.
#[test]
fn a_budgeted_statement_takes_its_fixed_shape() {
    use blacksilk_zkvm::air::trace::{usage, Budget, Part};
    let (program, exec) = execute(&budget_program(), &[]);
    let c = Case::of(program.clone(), &exec);
    assert_eq!(c.violations(), vec![]);
    let used = usage(&program, &exec);
    assert_eq!(
        used,
        Budget {
            cycles: real_rows(&c, CPU, 0..1),
            keys: real_rows(&c, MEM_INIT, 0..1),
            add: real_rows(&c, ADD, 0..2),
            bit: real_rows(&c, BIT, 0..3),
            lt: real_rows(&c, LT, 0..3),
            shift: real_rows(&c, SHIFT, 0..3),
            mul: real_rows(&c, MUL, 0..4),
            poseidon: real_rows(&c, P2, poseidon::P2_COLS..poseidon::P2_COLS + 1),
        }
    );
    assert!(used.shift > 0 && used.mul > used.shift - 1 && used.poseidon == 1);
    // Budgets above the usage, each table's its own size.
    let budget = Budget {
        cycles: 600,
        keys: 300,
        add: 1100,
        bit: 2100,
        lt: 4100,
        shift: 270,
        mul: 520,
        poseidon: 3,
    };
    let mut st = Statement::single(
        program.clone(),
        exec.exit_code,
        exec.output.clone(),
        [7; 32],
    );
    assert_eq!(st.shape(), None);
    st.budget = Some(budget);
    assert_eq!(st.budgets(), Some(vec![budget]));
    let shape = st.shape().expect("a fixed shape");
    let traces = trace::build(&st, &exec);
    let heights: Vec<usize> = traces.iter().map(|t| t.height()).collect();
    assert_eq!(heights, shape);
    assert_eq!(
        check(&trace::tables(&st), &traces, &trace::public_values(&st)),
        vec![]
    );
    // A further budgeted execution appends its own five tables.
    st.others.push(Part {
        program: program.clone(),
        exit_code: exec.exit_code,
        output: exec.output.clone(),
        budget: Some(used),
    });
    assert_eq!(st.budgets(), Some(vec![budget, used]));
    let shape = st.shape().unwrap();
    let traces = trace::build_multi(&st, &[&exec, &exec]);
    assert_eq!(traces.iter().map(|t| t.height()).collect::<Vec<_>>(), shape);
    assert_eq!(
        check(&trace::tables(&st), &traces, &trace::public_values(&st)),
        vec![]
    );
}

/// The generator cross-checks the interpreter's witness: a step whose
/// written value differs from the value the generator computes stops trace
/// generation (a bug, never a false trace).
#[test]
fn the_generator_refuses_a_diverging_witness() {
    let (program, mut exec) = execute(&budget_program(), &[]);
    let k = exec
        .steps
        .iter()
        .position(|s| s.instr.op == Op::Add && s.instr.rd != 0)
        .unwrap();
    exec.steps[k].rd_val ^= 1;
    let st = Statement::single(program, exec.exit_code, exec.output.clone(), [7; 32]);
    let r = std::panic::catch_unwind(|| trace::build(&st, &exec));
    assert!(r.is_err(), "a diverging witness was accepted");
}

/// Blinding values are uniform field elements: spread over the whole field,
/// never a constant or a narrow range.
#[test]
fn blinding_values_cover_the_field() {
    use rand_chacha::rand_core::SeedableRng;
    let (program, exec) = execute(&budget_program(), &[]);
    let mut c = Case::of(program, &exec);
    trace::randomize_blinding(
        &mut c.traces,
        &mut rand_chacha::ChaCha20Rng::seed_from_u64(3),
    );
    assert_eq!(c.violations(), vec![]);
    let n = c.traces.len() - 1;
    let w = c.w(n);
    let values: Vec<u32> = (0..n)
        .flat_map(|t| (1..w).map(move |k| (t, k)))
        .map(|(t, k)| c.u(n, t, k))
        .collect();
    let high = values.iter().filter(|&&x| x >= 1 << 30).count();
    let low = values.iter().filter(|&&x| x < 1 << 27).count();
    assert!(
        high > values.len() / 4 && low > 0 && high < values.len(),
        "{values:?}"
    );
}

/// `trace::blinded` (hand-assembled tables in tests) appends the blinding
/// columns and the Blind table.
#[test]
fn hand_assembled_tables_are_blinded() {
    use blacksilk_zkvm::air::alu_add;
    use blacksilk_zkvm::air::byte::ByteCounter;
    let mut counter = ByteCounter::new();
    let add = alu_add::trace(&[], &mut counter, MIN_HEIGHT);
    let byte = blacksilk_zkvm::air::with_public_columns(&Table::Byte, counter.trace());
    let (airs, traces) = trace::blinded(vec![Table::Byte, Table::AluAdd], vec![byte, add]);
    assert_eq!((airs.len(), traces.len()), (3, 3));
    assert!(matches!(airs[2], Table::Blind));
    let public = vec![vec![]; 3];
    assert_eq!(check(&airs, &traces, &public), vec![]);
}
