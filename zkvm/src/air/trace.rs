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
use super::{alu_add, alu_bit, alu_lt, alu_mul, alu_shift, cpu, program, Table, MIN_HEIGHT};
use crate::exec::{image_words, Execution};
use crate::isa::Op;
use crate::program::Program;
use crate::Syscall;
use blacksilk_zk::config::Val;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

/// The public part of a BVM-1 statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    pub program: Arc<Program>,
    pub exit_code: u32,
    pub output: Vec<u32>,
    /// The caller's transaction binding (zk.md §5.2).
    pub binding: [u8; 32],
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
pub fn tables(st: &Statement) -> Vec<Table> {
    vec![
        Table::Byte,
        Table::Program(st.program.clone()),
        Table::Image(Arc::new(image(&st.program))),
        Table::MemInit,
        Table::Cpu,
        Table::AluAdd,
        Table::AluBit,
        Table::AluLt,
        Table::AluShift,
        Table::AluMul,
        Table::Output(Arc::new(st.output.clone())),
    ]
}

/// Public values per table (only the CPU has any).
pub fn public_values(st: &Statement) -> Vec<Vec<Val>> {
    let mut cpu_pv = vec![Val::from_u32(st.program.entry)];
    cpu_pv.extend(bytes(st.program.code_end()));
    cpu_pv.extend(bytes(st.exit_code));
    cpu_pv.push(Val::from_u32(st.output.len() as u32));
    for chunk in st.binding.chunks(2) {
        cpu_pv.push(Val::from_u32(
            u16::from_le_bytes([chunk[0], chunk[1]]) as u32
        ));
    }
    debug_assert_eq!(cpu_pv.len(), cpu::pv::COUNT);
    let mut out = vec![vec![]; 11];
    out[4] = cpu_pv;
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

/// Builds all traces for an execution of `st.program`.
pub fn build(st: &Statement, exec: &Execution) -> Vec<RowMajorMatrix<Val>> {
    let prog = &st.program;
    assert_eq!(exec.exit_code, st.exit_code);
    assert_eq!(exec.output, st.output);
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
    let mut counter = ByteCounter::new();
    let mut alu: BTreeMap<&'static str, Vec<(u32, u32, u32)>> = BTreeMap::new();
    let mut push_alu = |op: u32, a: u32, b: u32| {
        let table = match op {
            alu_op::ADD | alu_op::SUB => "add",
            alu_op::XOR | alu_op::OR | alu_op::AND => "bit",
            alu_op::SLT | alu_op::SLTU | alu_op::EQ => "lt",
            alu_op::SLL | alu_op::SRL | alu_op::SRA => "shift",
            _ => "mul",
        };
        alu.entry(table).or_default().push((op, a, b));
    };
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
            r[d_col..d_col + 3].copy_from_slice(&diff(ts(slot), pts, &mut counter));
        }
        let (a, b) = (s.rs1_val, s.rs2_val);

        // pc bytes.
        r[cpu::PB..cpu::PB + 4].copy_from_slice(&bytes(s.pc));
        counter.word(s.pc);
        counter.range_bits(s.pc >> 24, 4);

        // Addresses.
        let addr_use = is(class::LOAD) || is(class::STORE) || is(class::JALR);
        let mem = is(class::LOAD) || is(class::STORE);
        let addr = a.wrapping_add(imm);
        if addr_use {
            push_alu(alu_op::ADD, a, imm);
            r[cpu::S..cpu::S + 4].copy_from_slice(&bytes(addr));
            counter.range_bits(addr >> 24, 4);
            let s0 = addr & 0xff;
            r[cpu::L0] = Val::from_u32(s0 & 1);
            r[cpu::L1] = Val::from_u32((s0 >> 1) & 1);
            r[cpu::H] = Val::from_u32(s0 >> 2);
            counter.range_bits(s0 >> 2, 6);
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
            push_alu(alu_op::SLTU, addr, 0x1000);
            let (prev, pts) = replay.access(wk, m.word_before, ts(2));
            assert_eq!(prev, m.word_before, "memory diverged at clk {clk}");
            r[cpu::M..cpu::M + 4].copy_from_slice(&bytes(m.word_before));
            r[cpu::TM] = Val::from_u32(pts);
            r[cpu::DM..cpu::DM + 3].copy_from_slice(&diff(ts(2), pts, &mut counter));
            if is(class::STORE) {
                push_alu(alu_op::SLTU, addr, code_end);
                replay.access(wk, m.word_after, ts(3));
                r[cpu::N..cpu::N + 4].copy_from_slice(&bytes(m.word_after));
                counter.word(m.word_after);
            }
        }

        // The computed value.
        let alu_op_v = get(f::ALU_OP);
        let computed: Option<u32> = if is(class::ALU_RR) {
            push_alu(alu_op_v, a, b);
            Some(alu_result(alu_op_v, a, b))
        } else if is(class::ALU_RI) {
            push_alu(alu_op_v, a, imm);
            Some(alu_result(alu_op_v, a, imm))
        } else if is(class::LUI) {
            Some(imm)
        } else if is(class::AUIPC) {
            push_alu(alu_op::ADD, s.pc, imm);
            Some(s.pc.wrapping_add(imm))
        } else if is(class::JAL) || is(class::JALR) {
            push_alu(alu_op::ADD, s.pc, 4);
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
                counter.range_bits(sign_byte & 127, 7);
            }
            Some(val)
        } else if let Some(Syscall::Read { value }) = s.syscall {
            Some(value)
        } else {
            None
        };
        if let Some(cv) = computed {
            r[cpu::C..cpu::C + 4].copy_from_slice(&bytes(cv));
            counter.word(cv);
            if x.rd != 0 && x.op != Op::Ecall {
                assert_eq!(cv, s.rd_val, "computed value diverged at clk {clk}");
            }
        }

        // Branches.
        if is(class::BRANCH) {
            push_alu(alu_op_v, a, b);
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
            r[cpu::DC..cpu::DC + 3].copy_from_slice(&diff(ts(3), pts, &mut counter));
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
            Some(Syscall::Poseidon2 { .. }) => {
                panic!("the POSEIDON2 syscall is not yet provable (zkvm.md §6, ZK-3c)")
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

    let take = |alu: &mut BTreeMap<&'static str, Vec<(u32, u32, u32)>>, k: &str| {
        alu.remove(k).unwrap_or_default()
    };
    let (add, bit, lt, shift, mul) = (
        take(&mut alu, "add"),
        take(&mut alu, "bit"),
        take(&mut alu, "lt"),
        take(&mut alu, "shift"),
        take(&mut alu, "mul"),
    );
    let t_init = memory::init_trace(&init, &mut counter, MIN_HEIGHT);
    let t_add = alu_add::trace(&add, &mut counter, MIN_HEIGHT);
    let t_bit = alu_bit::trace(&bit, &mut counter, MIN_HEIGHT);
    let t_lt = alu_lt::trace(&lt, &mut counter, MIN_HEIGHT);
    let t_shift = alu_shift::trace(&shift, &mut counter, MIN_HEIGHT);
    let t_mul = alu_mul::trace(&mul, &mut counter, MIN_HEIGHT);
    let t_cpu = matrix(rows, cpu::WIDTH, MIN_HEIGHT);
    let dummy = |len: usize| {
        RowMajorMatrix::new(vec![Val::ZERO; len.max(MIN_HEIGHT).next_power_of_two()], 1)
    };
    vec![
        counter.trace(),
        program::trace(prog, &counts, MIN_HEIGHT),
        dummy(img.len()),
        t_init,
        t_cpu,
        t_add,
        t_bit,
        t_lt,
        t_shift,
        t_mul,
        dummy(st.output.len()),
    ]
}
