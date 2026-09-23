//! `PROGRAM`: the committed program (zkvm.md §6.1).
//!
//! One preprocessed row per instruction, computed by the verifier from the
//! program image, holding the instruction's decoded fields ([`Fields`]). The
//! main trace holds one column: how often the instruction executed. The CPU
//! looks up `(pc, fields…)` on every cycle, so it can only execute
//! instructions of this program, decoded exactly as below.
//!
//! Padding rows (all zero, `is_real = 0`) may not be looked up: their
//! multiplicity is constrained to zero.

use super::util::{alu_op, c, prep, row, PROGRAM};
use crate::isa::{decode, Instr, Op};
use crate::program::Program;
use blacksilk_zk::config::Val;
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;

/// Instruction class flags (exactly one is set per instruction).
pub mod class {
    pub const ALU_RR: usize = 0;
    pub const ALU_RI: usize = 1;
    pub const LUI: usize = 2;
    pub const AUIPC: usize = 3;
    pub const JAL: usize = 4;
    pub const JALR: usize = 5;
    pub const BRANCH: usize = 6;
    pub const LOAD: usize = 7;
    pub const STORE: usize = 8;
    pub const FENCE: usize = 9;
    pub const ECALL: usize = 10;
    pub const COUNT: usize = 11;
}

/// Offsets of the decoded fields after `pc` (and in the CPU after its own
/// instruction base column).
pub mod f {
    pub const FLAGS: usize = 0; // 11 class flags
    pub const ALU_OP: usize = 11; // ALU op, or compare op for branches
    pub const BR_NEG: usize = 12; // branch taken on the negated comparison
    pub const KB: usize = 13; // byte access
    pub const KH: usize = 14; // half-word access
    pub const KW: usize = 15; // word access
    pub const SIGNED: usize = 16; // sign-extending load
    pub const RS1: usize = 17;
    pub const RS2: usize = 18;
    pub const RD: usize = 19;
    pub const RD_WRITE: usize = 20; // writes rd, rd ≠ 0 (ECALL: see the CPU)
    pub const IMM: usize = 21; // 4 bytes of the sign-extended immediate
    pub const IMM_F: usize = 25; // the immediate as a signed field element
    pub const COUNT: usize = 26;
}

/// The decoded fields of an instruction, as the program table holds them.
pub fn fields(x: &Instr) -> [Val; f::COUNT] {
    use class::*;
    let mut v = [Val::ZERO; f::COUNT];
    let set = |v: &mut [Val; f::COUNT], i: usize, x: u32| v[i] = Val::from_u32(x);
    let (cls, op, neg, width, signed): (usize, u32, bool, u32, bool) = match x.op {
        Op::Add => (ALU_RR, alu_op::ADD, false, 0, false),
        Op::Sub => (ALU_RR, alu_op::SUB, false, 0, false),
        Op::Sll => (ALU_RR, alu_op::SLL, false, 0, false),
        Op::Slt => (ALU_RR, alu_op::SLT, false, 0, false),
        Op::Sltu => (ALU_RR, alu_op::SLTU, false, 0, false),
        Op::Xor => (ALU_RR, alu_op::XOR, false, 0, false),
        Op::Srl => (ALU_RR, alu_op::SRL, false, 0, false),
        Op::Sra => (ALU_RR, alu_op::SRA, false, 0, false),
        Op::Or => (ALU_RR, alu_op::OR, false, 0, false),
        Op::And => (ALU_RR, alu_op::AND, false, 0, false),
        Op::Mul => (ALU_RR, alu_op::MUL, false, 0, false),
        Op::Mulh => (ALU_RR, alu_op::MULH, false, 0, false),
        Op::Mulhsu => (ALU_RR, alu_op::MULHSU, false, 0, false),
        Op::Mulhu => (ALU_RR, alu_op::MULHU, false, 0, false),
        Op::Addi => (ALU_RI, alu_op::ADD, false, 0, false),
        Op::Slti => (ALU_RI, alu_op::SLT, false, 0, false),
        Op::Sltiu => (ALU_RI, alu_op::SLTU, false, 0, false),
        Op::Xori => (ALU_RI, alu_op::XOR, false, 0, false),
        Op::Ori => (ALU_RI, alu_op::OR, false, 0, false),
        Op::Andi => (ALU_RI, alu_op::AND, false, 0, false),
        Op::Slli => (ALU_RI, alu_op::SLL, false, 0, false),
        Op::Srli => (ALU_RI, alu_op::SRL, false, 0, false),
        Op::Srai => (ALU_RI, alu_op::SRA, false, 0, false),
        Op::Lui => (LUI, 0, false, 0, false),
        Op::Auipc => (AUIPC, 0, false, 0, false),
        Op::Jal => (JAL, 0, false, 0, false),
        Op::Jalr => (JALR, 0, false, 0, false),
        Op::Beq => (BRANCH, alu_op::EQ, false, 0, false),
        Op::Bne => (BRANCH, alu_op::EQ, true, 0, false),
        Op::Blt => (BRANCH, alu_op::SLT, false, 0, false),
        Op::Bge => (BRANCH, alu_op::SLT, true, 0, false),
        Op::Bltu => (BRANCH, alu_op::SLTU, false, 0, false),
        Op::Bgeu => (BRANCH, alu_op::SLTU, true, 0, false),
        Op::Lb => (LOAD, 0, false, 1, true),
        Op::Lh => (LOAD, 0, false, 2, true),
        Op::Lw => (LOAD, 0, false, 4, false),
        Op::Lbu => (LOAD, 0, false, 1, false),
        Op::Lhu => (LOAD, 0, false, 2, false),
        Op::Sb => (STORE, 0, false, 1, false),
        Op::Sh => (STORE, 0, false, 2, false),
        Op::Sw => (STORE, 0, false, 4, false),
        Op::Fence => (FENCE, 0, false, 0, false),
        Op::Ecall => (ECALL, 0, false, 0, false),
    };
    set(&mut v, f::FLAGS + cls, 1);
    set(&mut v, f::ALU_OP, op);
    set(&mut v, f::BR_NEG, neg as u32);
    set(&mut v, f::KB, (width == 1) as u32);
    set(&mut v, f::KH, (width == 2) as u32);
    set(&mut v, f::KW, (width == 4) as u32);
    set(&mut v, f::SIGNED, signed as u32);
    let (rs1, rs2, rd) = if x.op == Op::Ecall {
        (17, 10, 10)
    } else {
        (x.rs1, x.rs2, x.rd)
    };
    let writes = matches!(cls, ALU_RR | ALU_RI | LUI | AUIPC | JAL | JALR | LOAD);
    set(&mut v, f::RS1, rs1 as u32);
    set(&mut v, f::RS2, rs2 as u32);
    set(&mut v, f::RD, rd as u32);
    set(&mut v, f::RD_WRITE, (writes && rd != 0) as u32);
    for (i, b) in (x.imm as u32).to_le_bytes().iter().enumerate() {
        set(&mut v, f::IMM + i, *b as u32);
    }
    v[f::IMM_F] = Val::from_i32(x.imm);
    v
}

pub const WIDTH: usize = 1;
/// `pc`, the fields, `is_real`.
pub const PREP_WIDTH: usize = 1 + f::COUNT + 1;
const IS_REAL: usize = 1 + f::COUNT;

/// Height of the program table for `program`.
pub fn height(program: &Program, min: usize) -> usize {
    program.code.len().max(min).next_power_of_two()
}

/// The preprocessed program table (verifier-computed).
pub fn preprocessed(program: &Program, min: usize) -> RowMajorMatrix<Val> {
    let h = height(program, min);
    let mut v = vec![Val::ZERO; h * PREP_WIDTH];
    for (k, w) in program.code.iter().enumerate() {
        let x = decode(*w).expect("programs hold only valid instructions");
        let r = &mut v[k * PREP_WIDTH..(k + 1) * PREP_WIDTH];
        r[0] = Val::from_u32(program.code_base + 4 * k as u32);
        r[1..1 + f::COUNT].copy_from_slice(&fields(&x));
        r[IS_REAL] = Val::ONE;
    }
    RowMajorMatrix::new(v, PREP_WIDTH)
}

pub fn eval<AB: AirBuilder + InteractionBuilder>(b: &mut AB) {
    let (m, _) = row(b);
    let (p, _) = prep(b);
    let mult = m[0].clone();
    // Padding rows cannot be looked up.
    b.assert_zero(mult.clone() * (c::<AB>(1) - p[IS_REAL].clone()));
    PROGRAM.table_entry(b, p[..1 + f::COUNT].to_vec(), mult);
}

/// Multiplicity column from execution counts per instruction index.
pub fn trace(program: &Program, counts: &[u32], min: usize) -> RowMajorMatrix<Val> {
    let h = height(program, min);
    let mut v = vec![Val::ZERO; h];
    for (k, n) in counts.iter().enumerate() {
        v[k] = Val::from_u32(*n);
    }
    RowMajorMatrix::new(v, WIDTH)
}
