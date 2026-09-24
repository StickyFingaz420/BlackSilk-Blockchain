//! Builds every table's trace from an execution (zkvm.md §6).
//!
//! The CPU trace is produced by replaying the execution with its own record
//! of each key's last value and timestamp, cross-checked against the
//! interpreter's witness: any divergence between the two stops trace
//! generation with a panic (a bug, never an input error).

use super::byte::ByteCounter;
use super::memory::{self, InitRow};
use super::program::{class, f, fields};
use super::util::{alu_op, bytes, matrix, REG_BASE};
use super::{
    alu_add, alu_bit, alu_lt, alu_mul, alu_shift, cpu, poseidon, program, Table, MIN_HEIGHT,
};
use crate::exec::{image_words, Execution};
use crate::isa::Op;
use crate::program::Program;
use crate::Syscall;
use blacksilk_zk::config::Val;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

/// The public part of a BVM-1 statement: the main execution (id 0), any
/// further executions proven in the same batch (ids 1, 2, …; zkvm.md §6.5),
/// and the binding shared by all of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    pub program: Arc<Program>,
    pub exit_code: u32,
    pub output: Vec<u32>,
    /// The caller's transaction binding (zk.md §5.2).
    pub binding: [u8; 32],
    /// Further executions of the same proof.
    pub others: Vec<Part>,
    /// The main execution's row budget. When every execution has one, the
    /// statement has a **fixed shape** ([`Statement::shape`]).
    pub budget: Option<Budget>,
}

/// One further execution of a multi-execution statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part {
    pub program: Arc<Program>,
    pub exit_code: u32,
    pub output: Vec<u32>,
    pub budget: Option<Budget>,
}

/// Rows an execution may use in each witness-dependent table (zkvm.md §8).
///
/// A program's budget is public (fixed per program). With budgets, every
/// table height is a function of the programs alone, so the public heights
/// reveal nothing about the execution: not its length, its memory use, its
/// operation mix or its number of Poseidon2 calls. An execution that needs
/// more rows than its budget cannot be proven.
///
/// `mul` counts `MUL`-family requests including those `ALU_SHIFT` delegates
/// (every shift by a nonzero amount).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Budget {
    pub cycles: usize,
    pub keys: usize,
    pub add: usize,
    pub bit: usize,
    pub lt: usize,
    pub shift: usize,
    pub mul: usize,
    pub poseidon: usize,
}

fn pow2(n: usize) -> usize {
    n.max(MIN_HEIGHT).next_power_of_two()
}

/// Most executions one proof may cover (the kernel and four functions,
/// zk.md §5.1).
pub const MAX_EXECUTIONS: usize = 5;

/// Tables per extra execution: `PROGRAM, IMAGE, MEM_INIT, CPU, OUTPUT`.
pub const TABLES_PER_EXTRA: usize = 5;
/// Tables of a single-execution proof.
pub const BASE_TABLES: usize = 12;

impl Statement {
    /// A single-execution statement (no budget).
    pub fn single(
        program: Arc<Program>,
        exit_code: u32,
        output: Vec<u32>,
        binding: [u8; 32],
    ) -> Self {
        Statement {
            program,
            exit_code,
            output,
            binding,
            others: Vec::new(),
            budget: None,
        }
    }

    /// Every execution's budget, if all have one.
    pub fn budgets(&self) -> Option<Vec<Budget>> {
        let mut v = vec![self.budget?];
        for p in &self.others {
            v.push(p.budget?);
        }
        Some(v)
    }

    /// The fixed table heights of a statement whose executions all have
    /// budgets, in [`tables`] order; `None` otherwise. Depends only on the
    /// programs, their outputs and their budgets (all public).
    ///
    /// # Panics
    /// If some but not all executions have a budget.
    pub fn shape(&self) -> Option<Vec<usize>> {
        let has = self.budget.is_some();
        assert!(
            self.others.iter().all(|p| p.budget.is_some() == has),
            "either every execution has a budget or none"
        );
        let b = self.budgets()?;
        let sum = |f: fn(&Budget) -> usize| b.iter().map(f).sum::<usize>();
        let own = |program: &Program, output: &[u32], bud: &Budget| {
            [
                program::height(program, MIN_HEIGHT),
                pow2(image(program).len()),
                pow2(bud.keys),
                pow2(bud.cycles),
                pow2(output.len()),
            ]
        };
        let main = own(&self.program, &self.output, &b[0]);
        let mut v = vec![
            1 << 16,
            main[0],
            main[1],
            main[2],
            main[3],
            pow2(sum(|x| x.add)),
            pow2(sum(|x| x.bit)),
            pow2(sum(|x| x.lt)),
            pow2(sum(|x| x.shift)),
            pow2(sum(|x| x.mul)),
            main[4],
            pow2(sum(|x| x.poseidon)),
        ];
        for (p, bud) in self.others.iter().zip(&b[1..]) {
            v.extend(own(&p.program, &p.output, bud));
        }
        Some(v)
    }

    /// Every execution, main first: `(program, exit code, output)`.
    pub fn parts(&self) -> Vec<(&Arc<Program>, u32, &Vec<u32>)> {
        let mut v = vec![(&self.program, self.exit_code, &self.output)];
        v.extend(
            self.others
                .iter()
                .map(|p| (&p.program, p.exit_code, &p.output)),
        );
        v
    }

    /// Index of execution `e`'s CPU table in [`tables`].
    pub fn cpu_table(e: usize) -> usize {
        if e == 0 {
            4
        } else {
            BASE_TABLES + TABLES_PER_EXTRA * (e - 1) + 3
        }
    }
}

/// Reference result of an ALU operation (the ALU tables prove exactly this).
pub fn alu_result(op: u32, a: u32, b: u32) -> u32 {
    match op {
        alu_op::ADD => a.wrapping_add(b),
        alu_op::SUB => a.wrapping_sub(b),
        alu_op::XOR => a ^ b,
        alu_op::OR => a | b,
        alu_op::AND => a & b,
        alu_op::SLT | alu_op::SLTU | alu_op::EQ => alu_lt::result(op, a, b),
        alu_op::SLL | alu_op::SRL | alu_op::SRA => alu_shift::result(op, a, b),
        _ => alu_mul::result(op, a, b),
    }
}

/// The initial image of the memory argument: memory words and registers,
/// sorted by key.
pub fn image(program: &Program) -> Vec<(u32, u32)> {
    let mut v: Vec<(u32, u32)> = image_words(program).into_iter().collect();
    v.extend(memory::register_image());
    v.sort_unstable();
    v
}

/// The tables of a statement, in proof order. Built by prover and verifier
/// alike from public data only.
///
/// Execution 0 uses the single-execution layout; each further execution `e`
/// appends its own `PROGRAM, IMAGE, MEM_INIT, CPU, OUTPUT` tables. The byte,
/// ALU and Poseidon2 tables are shared.
///
/// # Panics
/// If the statement has more than [`MAX_EXECUTIONS`] executions.
pub fn tables(st: &Statement) -> Vec<Table> {
    assert!(st.others.len() < MAX_EXECUTIONS, "too many executions");
    let mut v = vec![
        Table::Byte,
        Table::Program(st.program.clone(), 0),
        Table::Image(Arc::new(image(&st.program)), 0),
        Table::MemInit(0),
        Table::Cpu(0),
        Table::AluAdd,
        Table::AluBit,
        Table::AluLt,
        Table::AluShift,
        Table::AluMul,
        Table::Output(Arc::new(st.output.clone()), 0),
        Table::Poseidon2,
    ];
    for (i, p) in st.others.iter().enumerate() {
        let e = i as u32 + 1;
        v.extend([
            Table::Program(p.program.clone(), e),
            Table::Image(Arc::new(image(&p.program)), e),
            Table::MemInit(e),
            Table::Cpu(e),
            Table::Output(Arc::new(p.output.clone()), e),
        ]);
    }
    v
}

/// Public values per table (only the CPU has any).
pub fn public_values(st: &Statement) -> Vec<Vec<Val>> {
    let parts = st.parts();
    let mut out = vec![vec![]; BASE_TABLES + TABLES_PER_EXTRA * st.others.len()];
    for (e, (program, exit_code, output)) in parts.into_iter().enumerate() {
        let mut cpu_pv = vec![Val::from_u32(program.entry)];
        cpu_pv.extend(bytes(program.code_end()));
        cpu_pv.extend(bytes(exit_code));
        cpu_pv.push(Val::from_u32(output.len() as u32));
        // Every execution carries the same binding.
        for chunk in st.binding.chunks(2) {
            cpu_pv.push(Val::from_u32(
                u16::from_le_bytes([chunk[0], chunk[1]]) as u32
            ));
        }
        debug_assert_eq!(cpu_pv.len(), cpu::pv::COUNT);
        out[Statement::cpu_table(e)] = cpu_pv;
    }
    out
}

struct Replay {
    state: HashMap<u32, (u32, u32)>,
}

impl Replay {
    /// Accesses `key` at `ts`: returns the previous `(value, ts)` and records
    /// the new value.
    fn access(&mut self, key: u32, value: u32, ts: u32) -> (u32, u32) {
        let prev = *self
            .state
            .get(&key)
            .expect("every key starts in the image or at zero");
        assert!(prev.1 < ts, "timestamps must increase");
        self.state.insert(key, (value, ts));
        prev
    }
}

fn diff(ts: u32, prev_ts: u32, counter: &mut ByteCounter) -> [Val; 3] {
    let d = ts - prev_ts - 1;
    assert!(d < 1 << 24, "timestamp difference out of range");
    let b = d.to_le_bytes();
    counter.range(b[0] as u32, b[1] as u32);
    counter.range(b[2] as u32, 0);
    [b[0], b[1], b[2]].map(|x| Val::from_u32(x as u32))
}

/// Builds all traces for a single-execution statement.
pub fn build(st: &Statement, exec: &Execution) -> Vec<RowMajorMatrix<Val>> {
    build_multi(st, &[exec])
}

/// State shared by all executions of a proof: byte-table counts, ALU
/// requests and Poseidon2 calls.
struct Shared {
    counter: ByteCounter,
    alu: BTreeMap<&'static str, Vec<(u32, u32, u32)>>,
    p2_calls: Vec<poseidon::Call>,
}

impl Shared {
    fn push_alu(&mut self, op: u32, a: u32, b: u32) {
        let table = match op {
            alu_op::ADD | alu_op::SUB => "add",
            alu_op::XOR | alu_op::OR | alu_op::AND => "bit",
            alu_op::SLT | alu_op::SLTU | alu_op::EQ => "lt",
            alu_op::SLL | alu_op::SRL | alu_op::SRA => "shift",
            _ => "mul",
        };
        self.alu.entry(table).or_default().push((op, a, b));
    }

    fn take(&mut self, k: &str) -> Vec<(u32, u32, u32)> {
        self.alu.remove(k).unwrap_or_default()
    }
}

/// The traces of one execution's own tables.
struct ExecTraces {
    program: RowMajorMatrix<Val>,
    image: RowMajorMatrix<Val>,
    init: RowMajorMatrix<Val>,
    cpu: RowMajorMatrix<Val>,
    output: RowMajorMatrix<Val>,
}

fn dummy(len: usize) -> RowMajorMatrix<Val> {
    RowMajorMatrix::new(vec![Val::ZERO; len.max(MIN_HEIGHT).next_power_of_two()], 1)
}

/// Builds all traces of a (possibly multi-execution) statement; `execs[e]`
/// is the interpreter's witness of execution `e`.
pub fn build_multi(st: &Statement, execs: &[&Execution]) -> Vec<RowMajorMatrix<Val>> {
    let parts = st.parts();
    assert_eq!(parts.len(), execs.len(), "one witness per execution");
    // Minimum heights: the fixed shape if the statement has one. A table
    // that outgrows its budget comes out taller; the prover detects that.
    let shape = st.shape();
    let min = |t: usize| shape.as_ref().map_or(MIN_HEIGHT, |s| s[t]);
    let mut sh = Shared {
        counter: ByteCounter::new(),
        alu: BTreeMap::new(),
        p2_calls: Vec::new(),
    };
    let mut per: Vec<ExecTraces> = parts
        .into_iter()
        .zip(execs)
        .enumerate()
        .map(|(e, ((program, exit_code, output), exec))| {
            assert_eq!(exec.exit_code, exit_code);
            assert_eq!(&exec.output, output);
            let cpu_t = Statement::cpu_table(e);
            // MEM_INIT precedes CPU in both layouts.
            exec_traces(e as u32, program, exec, &mut sh, min(cpu_t - 1), min(cpu_t))
        })
        .collect();

    let (add, bit, lt, shift, mut mul) = (
        sh.take("add"),
        sh.take("bit"),
        sh.take("lt"),
        sh.take("shift"),
        sh.take("mul"),
    );
    let t_add = alu_add::trace(&add, &mut sh.counter, min(5));
    let t_bit = alu_bit::trace(&bit, &mut sh.counter, min(6));
    let t_lt = alu_lt::trace(&lt, &mut sh.counter, min(7));
    // Shifts delegate their products to ALU_MUL: build them first.
    let t_shift = alu_shift::trace(&shift, &mut sh.counter, min(8), &mut mul);
    let t_mul = alu_mul::trace(&mul, &mut sh.counter, min(9));
    let t_p2 = poseidon::trace(&sh.p2_calls, &mut sh.counter, min(11));
    let rest = per.split_off(1);
    let main = per.pop().expect("the main execution");
    let mut out = vec![
        sh.counter.trace(),
        main.program,
        main.image,
        main.init,
        main.cpu,
        t_add,
        t_bit,
        t_lt,
        t_shift,
        t_mul,
        main.output,
        t_p2,
    ];
    for x in rest {
        out.extend([x.program, x.image, x.init, x.cpu, x.output]);
    }
    tables(st)
        .iter()
        .zip(out)
        .map(|(t, m)| super::with_public_columns(t, m))
        .collect()
}

/// Replays execution `e` against its witness and builds its own tables;
/// records its ALU requests, byte checks and Poseidon2 calls in `sh`.
fn exec_traces(
    e: u32,
    prog: &Program,
    exec: &Execution,
    sh: &mut Shared,
    init_min: usize,
    cpu_min: usize,
) -> ExecTraces {
    let img = image(prog);
    let img_map: HashMap<u32, u32> = img.iter().copied().collect();
    // Every key used starts from its image value or zero.
    let mut state: HashMap<u32, (u32, u32)> = img.iter().map(|&(k, v)| (k, (v, 0))).collect();
    for acc in &exec.accesses {
        let key = match acc.space {
            crate::exec::Space::Reg => REG_BASE + acc.addr,
            crate::exec::Space::Mem => acc.addr,
        };
        state.entry(key).or_insert((0, 0));
    }
    let mut replay = Replay { state };
    let mut counts = vec![0u32; prog.code.len()];
    let mut rows = Vec::with_capacity(exec.steps.len());
    let mut out_idx = 0u32;
    let code_end = prog.code_end();

    for s in &exec.steps {
        let x = s.instr;
        let fv = fields(&x);
        let get = |k: usize| fv[k].as_canonical_u32();
        let is = |k: usize| get(f::FLAGS + k) == 1;
        counts[((s.pc - prog.code_base) / 4) as usize] += 1;
        let mut r = vec![Val::ZERO; cpu::WIDTH];
        let clk = s.clk;
        let ts = |slot: u32| 4 * (clk + 1) + slot;
        r[cpu::IS_REAL] = Val::ONE;
        r[cpu::CLK] = Val::from_u32(clk);
        r[cpu::PC] = Val::from_u32(s.pc);
        r[cpu::NEXT_PC] = Val::from_u32(s.next_pc);
        r[cpu::INS..cpu::INS + f::COUNT].copy_from_slice(&fv);
        let imm = x.imm as u32;

        // Register reads.
        for (col, t_col, d_col, idx, val, slot) in [
            (cpu::A, cpu::TA, cpu::DA, get(f::RS1), s.rs1_val, 0),
            (cpu::B, cpu::TB, cpu::DB, get(f::RS2), s.rs2_val, 1),
        ] {
            let (prev, pts) = replay.access(REG_BASE + idx, val, ts(slot));
            assert_eq!(prev, val, "register x{idx} diverged at clk {clk}");
            r[col..col + 4].copy_from_slice(&bytes(val));
            r[t_col] = Val::from_u32(pts);
            r[d_col..d_col + 3].copy_from_slice(&diff(ts(slot), pts, &mut sh.counter));
        }
        let (a, b) = (s.rs1_val, s.rs2_val);

        // pc bytes.
        r[cpu::PB..cpu::PB + 4].copy_from_slice(&bytes(s.pc));
        sh.counter.word(s.pc);
        sh.counter.range_bits(s.pc >> 24, 4);

        // Addresses.
        let addr_use = is(class::LOAD) || is(class::STORE) || is(class::JALR);
        let mem = is(class::LOAD) || is(class::STORE);
        let addr = a.wrapping_add(imm);
        if addr_use {
            sh.push_alu(alu_op::ADD, a, imm);
            r[cpu::S..cpu::S + 4].copy_from_slice(&bytes(addr));
            sh.counter.range_bits(addr >> 24, 4);
            let s0 = addr & 0xff;
            r[cpu::L0] = Val::from_u32(s0 & 1);
            r[cpu::L1] = Val::from_u32((s0 >> 1) & 1);
            r[cpu::H] = Val::from_u32(s0 >> 2);
            sh.counter.range_bits(s0 >> 2, 6);
        }
        let off = addr & 3;
        let mut word_before = 0;
        if mem {
            let m = s.mem.expect("memory op");
            assert_eq!(m.addr, addr);
            word_before = m.word_before;
            r[cpu::O + off as usize] = Val::ONE;
            let wk = addr / 4;
            r[cpu::WK] = Val::from_u32(wk);
            sh.push_alu(alu_op::SLTU, addr, 0x1000);
            let (prev, pts) = replay.access(wk, m.word_before, ts(2));
            assert_eq!(prev, m.word_before, "memory diverged at clk {clk}");
            r[cpu::M..cpu::M + 4].copy_from_slice(&bytes(m.word_before));
            r[cpu::TM] = Val::from_u32(pts);
            r[cpu::DM..cpu::DM + 3].copy_from_slice(&diff(ts(2), pts, &mut sh.counter));
            if is(class::STORE) {
                sh.push_alu(alu_op::SLTU, addr, code_end);
                replay.access(wk, m.word_after, ts(3));
                r[cpu::N..cpu::N + 4].copy_from_slice(&bytes(m.word_after));
                sh.counter.word(m.word_after);
            }
        }

        // The computed value.
        let alu_op_v = get(f::ALU_OP);
        let computed: Option<u32> = if is(class::ALU_RR) {
            sh.push_alu(alu_op_v, a, b);
            Some(alu_result(alu_op_v, a, b))
        } else if is(class::ALU_RI) {
            sh.push_alu(alu_op_v, a, imm);
            Some(alu_result(alu_op_v, a, imm))
        } else if is(class::LUI) {
            Some(imm)
        } else if is(class::AUIPC) {
            sh.push_alu(alu_op::ADD, s.pc, imm);
            Some(s.pc.wrapping_add(imm))
        } else if is(class::JAL) || is(class::JALR) {
            sh.push_alu(alu_op::ADD, s.pc, 4);
            Some(s.pc.wrapping_add(4))
        } else if is(class::LOAD) {
            let v = word_before >> (8 * off);
            let signed = get(f::SIGNED) == 1;
            let val = match x.op {
                Op::Lb => v as u8 as i8 as i32 as u32,
                Op::Lbu => v as u8 as u32,
                Op::Lh => v as u16 as i16 as i32 as u32,
                Op::Lhu => v as u16 as u32,
                _ => word_before,
            };
            if signed {
                let sign_byte = if x.op == Op::Lb {
                    v & 0xff
                } else {
                    (v >> 8) & 0xff
                };
                r[cpu::SGN] = Val::from_u32(sign_byte >> 7);
                r[cpu::SR] = Val::from_u32(sign_byte & 127);
                sh.counter.range_bits(sign_byte & 127, 7);
            }
            Some(val)
        } else if let Some(Syscall::Read { value }) = s.syscall {
            Some(value)
        } else {
            None
        };
        if let Some(cv) = computed {
            r[cpu::C..cpu::C + 4].copy_from_slice(&bytes(cv));
            sh.counter.word(cv);
            if x.rd != 0 && x.op != Op::Ecall {
                assert_eq!(cv, s.rd_val, "computed value diverged at clk {clk}");
            }
        }

        // Branches.
        if is(class::BRANCH) {
            sh.push_alu(alu_op_v, a, b);
            r[cpu::COND] = Val::from_u32(alu_result(alu_op_v, a, b));
        }

        // Register write.
        let is_read = matches!(s.syscall, Some(Syscall::Read { .. }));
        if get(f::RD_WRITE) == 1 || is_read {
            let rd = get(f::RD);
            let cv = computed.expect("writing instructions compute a value");
            let (prev, pts) = replay.access(REG_BASE + rd, cv, ts(3));
            r[cpu::CP..cpu::CP + 4].copy_from_slice(&bytes(prev));
            r[cpu::TC] = Val::from_u32(pts);
            r[cpu::DC..cpu::DC + 3].copy_from_slice(&diff(ts(3), pts, &mut sh.counter));
        }

        // Syscalls.
        r[cpu::OUT] = Val::from_u32(out_idx);
        match s.syscall {
            Some(Syscall::Halt { .. }) => r[cpu::SH] = Val::ONE,
            Some(Syscall::Read { .. }) => r[cpu::SRD] = Val::ONE,
            Some(Syscall::Write { .. }) => {
                r[cpu::SWR] = Val::ONE;
                out_idx += 1;
            }
            Some(Syscall::Poseidon2 { ptr }) => {
                use p3_symmetric::Permutation;
                r[cpu::SP2] = Val::ONE;
                sh.push_alu(alu_op::SLTU, ptr, code_end);
                sh.push_alu(alu_op::SLTU, ptr, 0x0fff_ffc1);
                let ts2 = 4 * (clk + 1) + 2;
                let mut input = [0u32; 16];
                let mut prev_ts = [0u32; 16];
                for k in 0..16u32 {
                    let key = ptr / 4 + k;
                    let (v, pts) = *replay
                        .state
                        .get(&key)
                        .expect("buffer word starts in the image or at zero");
                    replay.access(key, v, ts2);
                    input[k as usize] = v;
                    prev_ts[k as usize] = pts;
                }
                let mut state = input.map(Val::from_u32);
                blacksilk_zk::config::permutation().permute_mut(&mut state);
                let output = state.map(|x| x.as_canonical_u32());
                for k in 0..16u32 {
                    replay.access(ptr / 4 + k, output[k as usize], ts2 + 1);
                }
                sh.p2_calls.push(poseidon::Call {
                    exec: e,
                    clk,
                    ptr,
                    input,
                    prev_ts,
                    output,
                });
            }
            None => {}
        }
        rows.push(r);
    }

    // MEM_INIT: every image key and every touched key, sorted.
    let mut init: Vec<InitRow> = replay
        .state
        .iter()
        .map(|(&key, &(fin, fin_ts))| InitRow {
            key,
            init: img_map.get(&key).copied().unwrap_or(0),
            fin,
            fin_ts,
            in_image: img_map.contains_key(&key),
        })
        .collect();
    init.sort_unstable_by_key(|x| x.key);

    ExecTraces {
        program: program::trace(prog, &counts, MIN_HEIGHT),
        image: dummy(img.len()),
        init: memory::init_trace(&init, &mut sh.counter, init_min),
        cpu: matrix(rows, cpu::WIDTH, cpu_min),
        output: dummy(out_idx as usize),
    }
}

/// The rows an execution actually uses in each budgeted table: what its
/// program's [`Budget`] must cover. Used to set budgets from measurements.
pub fn usage(program: &Program, exec: &Execution) -> Budget {
    let mut sh = Shared {
        counter: ByteCounter::new(),
        alu: BTreeMap::new(),
        p2_calls: Vec::new(),
    };
    exec_traces(0, program, exec, &mut sh, MIN_HEIGHT, MIN_HEIGHT);
    let mut keys: std::collections::HashSet<u32> =
        image(program).into_iter().map(|(k, _)| k).collect();
    for acc in &exec.accesses {
        keys.insert(match acc.space {
            crate::exec::Space::Reg => REG_BASE + acc.addr,
            crate::exec::Space::Mem => acc.addr,
        });
    }
    let n = |k: &str| sh.alu.get(k).map_or(0, |v| v.len());
    let shifts = sh.alu.get("shift").cloned().unwrap_or_default();
    let delegated = shifts
        .iter()
        .filter(|&&(op, a, b)| alu_shift::mul_request(op, a, b).is_some())
        .count();
    Budget {
        cycles: exec.steps.len(),
        keys: keys.len(),
        add: n("add"),
        bit: n("bit"),
        lt: n("lt"),
        shift: n("shift"),
        mul: n("mul") + delegated,
        poseidon: sh.p2_calls.len(),
    }
}
