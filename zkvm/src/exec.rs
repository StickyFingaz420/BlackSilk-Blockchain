//! The reference interpreter (docs/zkvm.md §2–5).
//!
//! This is the normative executable definition of BVM-1: the constraint
//! tables must accept exactly the executions this interpreter produces. It
//! also records the witness the tables are built from:
//! - one [`Step`] per cycle;
//! - one [`Access`] per register or memory access, with the previous value and
//!   the previous timestamp of that address (the offline memory argument,
//!   zkvm.md §6.3).
//!
//! Timestamps are `4·clk + slot` with slots: 0 = first register read (rs1),
//! 1 = second register read (rs2), 2 = memory read, 3 = register write (rd) or
//! memory write. Registers and memory are separate address spaces, and within
//! one space every address's timestamps strictly increase.

use crate::isa::{decode, Instr, Op};
use crate::program::Program;
use crate::{Syscall, MAX_INPUT_WORDS, MAX_OUTPUT_WORDS, MEM_SIZE, NULL_GUARD, STACK_TOP};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_symmetric::Permutation;
use std::collections::HashMap;

/// Register or memory address space.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Space {
    /// Registers `x0..x31`; the address is the register number.
    Reg,
    /// Memory; the address is the word index (`byte address / 4`).
    Mem,
}

/// One access in the offline memory argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Access {
    pub space: Space,
    pub addr: u32,
    pub prev_value: u32,
    /// 0 if the address was never accessed before (its initial value).
    pub prev_ts: u32,
    pub value: u32,
    pub ts: u32,
}

/// A memory operation of a load/store (byte address and the whole word).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemOp {
    pub addr: u32,
    pub word_before: u32,
    pub word_after: u32,
}

/// One executed instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Step {
    pub clk: u32,
    pub pc: u32,
    pub instr: Instr,
    pub rs1_val: u32,
    pub rs2_val: u32,
    /// Value written to `rd` (0 when the instruction writes nothing or rd = x0).
    pub rd_val: u32,
    pub mem: Option<MemOp>,
    pub syscall: Option<Syscall>,
    pub next_pc: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrapKind {
    InvalidInstruction(u32),
    PcOutOfCode,
    MisalignedAccess,
    AccessOutOfRange,
    NullGuard,
    /// Stores must target addresses at or above the end of the code segment.
    StoreBelowCodeEnd,
    CycleLimit,
    InputExhausted,
    OutputFull,
    UnknownSyscall(u32),
    NonCanonicalField,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Trap {
    pub clk: u32,
    pub pc: u32,
    pub kind: TrapKind,
}

/// A completed execution and its witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Execution {
    pub exit_code: u32,
    pub output: Vec<u32>,
    pub steps: Vec<Step>,
    pub accesses: Vec<Access>,
    /// Initial value of every touched memory word (word index → value).
    pub mem_init: Vec<(u32, u32)>,
}

struct Machine<'a> {
    program: &'a Program,
    regs: [u32; 32],
    mem: HashMap<u32, u32>,
    /// Initial values of memory words from the program image.
    image: HashMap<u32, u32>,
    last_ts: HashMap<(Space, u32), u32>,
    accesses: Vec<Access>,
    touched: HashMap<u32, u32>,
    input: &'a [u32],
    input_pos: usize,
    output: Vec<u32>,
    clk: u32,
    pc: u32,
}

/// The initial memory image: the code words (so loads from the code segment
/// read real instruction words, as on RISC-V) and the file-backed data bytes.
pub fn image_words(program: &Program) -> HashMap<u32, u32> {
    let mut image: HashMap<u32, u32> = HashMap::new();
    for (k, w) in program.code.iter().enumerate() {
        image.insert(program.code_base / 4 + k as u32, *w);
    }
    for seg in &program.data {
        for (i, b) in seg.bytes.iter().enumerate() {
            let addr = seg.base + i as u32;
            let w = image.entry(addr / 4).or_insert(0);
            *w |= (*b as u32) << (8 * (addr % 4));
        }
    }
    image
}

impl<'a> Machine<'a> {
    fn trap(&self, kind: TrapKind) -> Trap {
        Trap {
            clk: self.clk,
            pc: self.pc,
            kind,
        }
    }

    fn record(&mut self, space: Space, addr: u32, prev_value: u32, value: u32, slot: u32) {
        let ts = 4 * self.clk + slot + 4; // timestamps start at 4; 0 means "initial"
        let prev_ts = self.last_ts.insert((space, addr), ts).unwrap_or(0);
        debug_assert!(prev_ts < ts);
        self.accesses.push(Access {
            space,
            addr,
            prev_value,
            prev_ts,
            value,
            ts,
        });
    }

    fn read_reg(&mut self, r: u8, slot: u32) -> u32 {
        let v = self.regs[r as usize];
        self.record(Space::Reg, r as u32, v, v, slot);
        v
    }

    fn write_reg(&mut self, r: u8, v: u32) {
        if r == 0 {
            return;
        }
        let prev = self.regs[r as usize];
        self.regs[r as usize] = v;
        self.record(Space::Reg, r as u32, prev, v, 3);
    }

    fn check_addr(&self, addr: u32, align: u32, store: bool) -> Result<(), Trap> {
        if !addr.is_multiple_of(align) {
            return Err(self.trap(TrapKind::MisalignedAccess));
        }
        if addr >= MEM_SIZE {
            return Err(self.trap(TrapKind::AccessOutOfRange));
        }
        if addr < NULL_GUARD {
            return Err(self.trap(TrapKind::NullGuard));
        }
        if store && addr < self.program.code_end() {
            return Err(self.trap(TrapKind::StoreBelowCodeEnd));
        }
        Ok(())
    }

    fn word(&mut self, index: u32) -> u32 {
        if let Some(v) = self.mem.get(&index) {
            return *v;
        }
        let v = self.image.get(&index).copied().unwrap_or(0);
        self.touched.entry(index).or_insert(v);
        v
    }

    fn read_word(&mut self, index: u32, slot: u32) -> u32 {
        let v = self.word(index);
        self.record(Space::Mem, index, v, v, slot);
        v
    }

    fn write_word(&mut self, index: u32, v: u32, slot: u32) {
        let prev = self.word(index);
        self.mem.insert(index, v);
        self.record(Space::Mem, index, prev, v, slot);
    }

    fn step(&mut self) -> Result<Option<Step>, Trap> {
        let pc = self.pc;
        let word = self
            .program
            .fetch(pc)
            .ok_or_else(|| self.trap(TrapKind::PcOutOfCode))?;
        let x = decode(word).map_err(|_| self.trap(TrapKind::InvalidInstruction(word)))?;
        // Every cycle reads exactly two registers (slots 0 and 1). ECALL reads
        // the syscall number (a7 = x17) and its argument (a0 = x10).
        let (r1, r2) = if x.op == Op::Ecall {
            (17, 10)
        } else {
            (x.rs1, x.rs2)
        };
        let rs1 = self.read_reg(r1, 0);
        let rs2 = self.read_reg(r2, 1);
        let imm = x.imm as u32;
        let mut next_pc = pc.wrapping_add(4);
        let mut rd_val: Option<u32> = None;
        let mut mem = None;
        let mut syscall = None;
        let branch = |cond: bool| {
            if cond {
                pc.wrapping_add(imm)
            } else {
                pc.wrapping_add(4)
            }
        };
        match x.op {
            Op::Lui => rd_val = Some(imm),
            Op::Auipc => rd_val = Some(pc.wrapping_add(imm)),
            Op::Jal => {
                rd_val = Some(pc.wrapping_add(4));
                next_pc = pc.wrapping_add(imm);
            }
            Op::Jalr => {
                rd_val = Some(pc.wrapping_add(4));
                next_pc = rs1.wrapping_add(imm) & !1;
            }
            Op::Beq => next_pc = branch(rs1 == rs2),
            Op::Bne => next_pc = branch(rs1 != rs2),
            Op::Blt => next_pc = branch((rs1 as i32) < (rs2 as i32)),
            Op::Bge => next_pc = branch((rs1 as i32) >= (rs2 as i32)),
            Op::Bltu => next_pc = branch(rs1 < rs2),
            Op::Bgeu => next_pc = branch(rs1 >= rs2),
            Op::Lb | Op::Lh | Op::Lw | Op::Lbu | Op::Lhu => {
                let addr = rs1.wrapping_add(imm);
                let align = match x.op {
                    Op::Lw => 4,
                    Op::Lh | Op::Lhu => 2,
                    _ => 1,
                };
                self.check_addr(addr, align, false)?;
                let w = self.read_word(addr / 4, 2);
                let shift = 8 * (addr % 4);
                let v = w >> shift;
                rd_val = Some(match x.op {
                    Op::Lb => v as u8 as i8 as i32 as u32,
                    Op::Lh => v as u16 as i16 as i32 as u32,
                    Op::Lbu => v as u8 as u32,
                    Op::Lhu => v as u16 as u32,
                    _ => w,
                });
                mem = Some(MemOp {
                    addr,
                    word_before: w,
                    word_after: w,
                });
            }
            Op::Sb | Op::Sh | Op::Sw => {
                let addr = rs1.wrapping_add(imm);
                let (align, mask) = match x.op {
                    Op::Sw => (4, 0xffff_ffffu32),
                    Op::Sh => (2, 0xffff),
                    _ => (1, 0xff),
                };
                self.check_addr(addr, align, true)?;
                let shift = 8 * (addr % 4);
                let before = self.read_word(addr / 4, 2);
                let after = (before & !(mask << shift)) | ((rs2 & mask) << shift);
                self.write_word(addr / 4, after, 3);
                mem = Some(MemOp {
                    addr,
                    word_before: before,
                    word_after: after,
                });
            }
            Op::Addi | Op::Add => {
                rd_val = Some(rs1.wrapping_add(if x.op == Op::Add { rs2 } else { imm }))
            }
            Op::Sub => rd_val = Some(rs1.wrapping_sub(rs2)),
            Op::Slti | Op::Slt => {
                let b = if x.op == Op::Slt { rs2 } else { imm };
                rd_val = Some(((rs1 as i32) < (b as i32)) as u32);
            }
            Op::Sltiu | Op::Sltu => {
                let b = if x.op == Op::Sltu { rs2 } else { imm };
                rd_val = Some((rs1 < b) as u32);
            }
            Op::Xori | Op::Xor => rd_val = Some(rs1 ^ if x.op == Op::Xor { rs2 } else { imm }),
            Op::Ori | Op::Or => rd_val = Some(rs1 | if x.op == Op::Or { rs2 } else { imm }),
            Op::Andi | Op::And => rd_val = Some(rs1 & if x.op == Op::And { rs2 } else { imm }),
            Op::Slli | Op::Sll => {
                let s = if x.op == Op::Sll { rs2 } else { imm } & 31;
                rd_val = Some(rs1 << s);
            }
            Op::Srli | Op::Srl => {
                let s = if x.op == Op::Srl { rs2 } else { imm } & 31;
                rd_val = Some(rs1 >> s);
            }
            Op::Srai | Op::Sra => {
                let s = if x.op == Op::Sra { rs2 } else { imm } & 31;
                rd_val = Some(((rs1 as i32) >> s) as u32);
            }
            Op::Mul => rd_val = Some(rs1.wrapping_mul(rs2)),
            Op::Mulh => rd_val = Some(((rs1 as i32 as i64 * rs2 as i32 as i64) >> 32) as u32),
            Op::Mulhsu => rd_val = Some(((rs1 as i32 as i64 * rs2 as i64) >> 32) as u32),
            Op::Mulhu => rd_val = Some(((rs1 as u64 * rs2 as u64) >> 32) as u32),
            Op::Fence => {}
            Op::Ecall => {
                let (number, a0) = (rs1, rs2);
                let call = match number {
                    0 => Syscall::Halt { code: a0 },
                    1 => {
                        let v = *self
                            .input
                            .get(self.input_pos)
                            .ok_or_else(|| self.trap(TrapKind::InputExhausted))?;
                        self.input_pos += 1;
                        rd_val = Some(v);
                        Syscall::Read { value: v }
                    }
                    2 => {
                        if self.output.len() >= MAX_OUTPUT_WORDS {
                            return Err(self.trap(TrapKind::OutputFull));
                        }
                        self.output.push(a0);
                        Syscall::Write { value: a0 }
                    }
                    3 => {
                        // All 16 words are read and written: each must be a valid,
                        // writable, aligned address.
                        for k in 0..16u32 {
                            let addr = a0
                                .checked_add(4 * k)
                                .ok_or_else(|| self.trap(TrapKind::AccessOutOfRange))?;
                            self.check_addr(addr, 4, true)?;
                        }
                        let mut state = [p3_baby_bear::BabyBear::ZERO; 16];
                        let mut words = [0u32; 16];
                        for (k, w) in words.iter_mut().enumerate() {
                            *w = self.read_word(a0 / 4 + k as u32, 2);
                            if *w >= p3_baby_bear::BabyBear::ORDER_U32 {
                                return Err(self.trap(TrapKind::NonCanonicalField));
                            }
                            state[k] = p3_baby_bear::BabyBear::from_u32(*w);
                        }
                        blacksilk_zk::config::permutation().permute_mut(&mut state);
                        for (k, s) in state.iter().enumerate() {
                            self.write_word(a0 / 4 + k as u32, s.as_canonical_u32(), 3);
                        }
                        Syscall::Poseidon2 { ptr: a0 }
                    }
                    n => return Err(self.trap(TrapKind::UnknownSyscall(n))),
                };
                syscall = Some(call);
                if let Some(v) = rd_val {
                    self.write_reg(10, v);
                }
                let step = Step {
                    clk: self.clk,
                    pc,
                    instr: x,
                    rs1_val: number,
                    rs2_val: a0,
                    rd_val: rd_val.unwrap_or(0),
                    mem: None,
                    syscall,
                    next_pc,
                };
                self.pc = next_pc;
                return Ok(Some(step));
            }
        }
        if let Some(v) = rd_val {
            self.write_reg(x.rd, v);
        }
        // A jump, branch or fall-through out of the code traps at the next
        // fetch (PcOutOfCode): an execution never runs outside its program.
        let step = Step {
            clk: self.clk,
            pc,
            instr: x,
            rs1_val: rs1,
            rs2_val: rs2,
            rd_val: if x.rd == 0 { 0 } else { rd_val.unwrap_or(0) },
            mem,
            syscall,
            next_pc,
        };
        self.pc = next_pc;
        Ok(Some(step))
    }
}

/// Runs `program` on `input` for at most `max_cycles` cycles.
///
/// Returns the execution and its witness if the program halts; any trap, or
/// running out of cycles, is an error (such an execution has no proof).
pub fn run(program: &Program, input: &[u32], max_cycles: u32) -> Result<Execution, Trap> {
    let mut m = Machine {
        program,
        regs: [0; 32],
        mem: HashMap::new(),
        image: image_words(program),
        last_ts: HashMap::new(),
        accesses: Vec::new(),
        touched: HashMap::new(),
        input,
        input_pos: 0,
        output: Vec::new(),
        clk: 0,
        pc: program.entry,
    };
    if input.len() > MAX_INPUT_WORDS {
        return Err(m.trap(TrapKind::InputExhausted));
    }
    m.regs[2] = STACK_TOP;
    let mut steps = Vec::new();
    loop {
        if m.clk >= max_cycles {
            return Err(m.trap(TrapKind::CycleLimit));
        }
        let step = m.step()?.expect("a step");
        steps.push(step);
        m.clk += 1;
        if let Some(Syscall::Halt { code }) = step.syscall {
            let mut mem_init: Vec<(u32, u32)> = m.touched.into_iter().collect();
            mem_init.sort_unstable();
            return Ok(Execution {
                exit_code: code,
                output: m.output,
                steps,
                accesses: m.accesses,
                mem_init,
            });
        }
    }
}
