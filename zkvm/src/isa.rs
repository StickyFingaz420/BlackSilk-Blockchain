//! RV32I + Zmmul instruction decoding and encoding (docs/zkvm.md §4).
//!
//! Decoding is strict: every encoding BVM-1 does not implement is an error,
//! including reserved bits that the RISC-V specification defines (e.g. bit 25
//! of RV32 shift immediates, the `funct3` of `JALR`). `EBREAK`, CSR access,
//! `FENCE.I` and all compressed (16-bit) encodings are rejected.
//!
//! [`encode`] is the exact inverse of [`decode`] on valid instructions (tested),
//! and is used to build test programs without an external toolchain.

/// The operations of BVM-1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Op {
    Lui,
    Auipc,
    Jal,
    Jalr,
    Beq,
    Bne,
    Blt,
    Bge,
    Bltu,
    Bgeu,
    Lb,
    Lh,
    Lw,
    Lbu,
    Lhu,
    Sb,
    Sh,
    Sw,
    Addi,
    Slti,
    Sltiu,
    Xori,
    Ori,
    Andi,
    Slli,
    Srli,
    Srai,
    Add,
    Sub,
    Sll,
    Slt,
    Sltu,
    Xor,
    Srl,
    Sra,
    Or,
    And,
    Mul,
    Mulh,
    Mulhsu,
    Mulhu,
    Fence,
    Ecall,
}

/// A decoded instruction. Unused register fields are 0; `imm` is the
/// sign-extended immediate (for `LUI`/`AUIPC` already shifted left by 12, for
/// shifts the 5-bit shift amount).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Instr {
    pub op: Op,
    pub rd: u8,
    pub rs1: u8,
    pub rs2: u8,
    pub imm: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// A 16-bit (compressed) encoding: the low two bits are not `11`.
    Compressed(u32),
    /// An encoding BVM-1 does not implement.
    Illegal(u32),
}

const OP_LUI: u32 = 0b0110111;
const OP_AUIPC: u32 = 0b0010111;
const OP_JAL: u32 = 0b1101111;
const OP_JALR: u32 = 0b1100111;
const OP_BRANCH: u32 = 0b1100011;
const OP_LOAD: u32 = 0b0000011;
const OP_STORE: u32 = 0b0100011;
const OP_IMM: u32 = 0b0010011;
const OP_REG: u32 = 0b0110011;
const OP_MISC_MEM: u32 = 0b0001111;
const OP_SYSTEM: u32 = 0b1110011;
const ECALL: u32 = 0x0000_0073;

fn bits(w: u32, hi: u32, lo: u32) -> u32 {
    (w >> lo) & ((1u32 << (hi - lo + 1)) - 1)
}

fn sign_extend(value: u32, width: u32) -> i32 {
    let shift = 32 - width;
    ((value << shift) as i32) >> shift
}

fn imm_i(w: u32) -> i32 {
    (w as i32) >> 20
}

fn imm_s(w: u32) -> i32 {
    sign_extend((bits(w, 31, 25) << 5) | bits(w, 11, 7), 12)
}

fn imm_b(w: u32) -> i32 {
    sign_extend(
        (bits(w, 31, 31) << 12)
            | (bits(w, 7, 7) << 11)
            | (bits(w, 30, 25) << 5)
            | (bits(w, 11, 8) << 1),
        13,
    )
}

fn imm_u(w: u32) -> i32 {
    (w & 0xffff_f000) as i32
}

fn imm_j(w: u32) -> i32 {
    sign_extend(
        (bits(w, 31, 31) << 20)
            | (bits(w, 19, 12) << 12)
            | (bits(w, 20, 20) << 11)
            | (bits(w, 30, 21) << 1),
        21,
    )
}

/// Decodes one 32-bit instruction word.
pub fn decode(w: u32) -> Result<Instr, DecodeError> {
    if w & 0b11 != 0b11 {
        return Err(DecodeError::Compressed(w));
    }
    let illegal = Err(DecodeError::Illegal(w));
    let opcode = w & 0x7f;
    let rd = bits(w, 11, 7) as u8;
    let rs1 = bits(w, 19, 15) as u8;
    let rs2 = bits(w, 24, 20) as u8;
    let f3 = bits(w, 14, 12);
    let f7 = bits(w, 31, 25);
    let make = |op, rd, rs1, rs2, imm| {
        Ok(Instr {
            op,
            rd,
            rs1,
            rs2,
            imm,
        })
    };
    match opcode {
        OP_LUI => make(Op::Lui, rd, 0, 0, imm_u(w)),
        OP_AUIPC => make(Op::Auipc, rd, 0, 0, imm_u(w)),
        OP_JAL => make(Op::Jal, rd, 0, 0, imm_j(w)),
        OP_JALR if f3 == 0 => make(Op::Jalr, rd, rs1, 0, imm_i(w)),
        OP_BRANCH => {
            let op = match f3 {
                0b000 => Op::Beq,
                0b001 => Op::Bne,
                0b100 => Op::Blt,
                0b101 => Op::Bge,
                0b110 => Op::Bltu,
                0b111 => Op::Bgeu,
                _ => return illegal,
            };
            make(op, 0, rs1, rs2, imm_b(w))
        }
        OP_LOAD => {
            let op = match f3 {
                0b000 => Op::Lb,
                0b001 => Op::Lh,
                0b010 => Op::Lw,
                0b100 => Op::Lbu,
                0b101 => Op::Lhu,
                _ => return illegal,
            };
            make(op, rd, rs1, 0, imm_i(w))
        }
        OP_STORE => {
            let op = match f3 {
                0b000 => Op::Sb,
                0b001 => Op::Sh,
                0b010 => Op::Sw,
                _ => return illegal,
            };
            make(op, 0, rs1, rs2, imm_s(w))
        }
        OP_IMM => match f3 {
            0b000 => make(Op::Addi, rd, rs1, 0, imm_i(w)),
            0b010 => make(Op::Slti, rd, rs1, 0, imm_i(w)),
            0b011 => make(Op::Sltiu, rd, rs1, 0, imm_i(w)),
            0b100 => make(Op::Xori, rd, rs1, 0, imm_i(w)),
            0b110 => make(Op::Ori, rd, rs1, 0, imm_i(w)),
            0b111 => make(Op::Andi, rd, rs1, 0, imm_i(w)),
            // RV32: shamt[5] (bit 25) must be 0.
            0b001 if f7 == 0 => make(Op::Slli, rd, rs1, 0, rs2 as i32),
            0b101 if f7 == 0 => make(Op::Srli, rd, rs1, 0, rs2 as i32),
            0b101 if f7 == 0b0100000 => make(Op::Srai, rd, rs1, 0, rs2 as i32),
            _ => illegal,
        },
        OP_REG => {
            let op = match (f7, f3) {
                (0, 0b000) => Op::Add,
                (0b0100000, 0b000) => Op::Sub,
                (0, 0b001) => Op::Sll,
                (0, 0b010) => Op::Slt,
                (0, 0b011) => Op::Sltu,
                (0, 0b100) => Op::Xor,
                (0, 0b101) => Op::Srl,
                (0b0100000, 0b101) => Op::Sra,
                (0, 0b110) => Op::Or,
                (0, 0b111) => Op::And,
                (1, 0b000) => Op::Mul,
                (1, 0b001) => Op::Mulh,
                (1, 0b010) => Op::Mulhsu,
                (1, 0b011) => Op::Mulhu,
                // DIV/DIVU/REM/REMU are not part of BVM-1 (RV32I + Zmmul);
                // guests divide in software (zkvm.md §4, decision ZK-3a).
                _ => return illegal,
            };
            make(op, rd, rs1, rs2, 0)
        }
        // FENCE (any predecessor/successor set) is a no-op; FENCE.I is rejected.
        OP_MISC_MEM if f3 == 0 => make(Op::Fence, 0, 0, 0, 0),
        OP_SYSTEM if w == ECALL => make(Op::Ecall, 0, 0, 0, 0),
        _ => illegal,
    }
}

fn r(op: u32, rd: u8, f3: u32, rs1: u8, rs2: u8, f7: u32) -> u32 {
    (f7 << 25) | ((rs2 as u32) << 20) | ((rs1 as u32) << 15) | (f3 << 12) | ((rd as u32) << 7) | op
}

fn i(op: u32, rd: u8, f3: u32, rs1: u8, imm: i32) -> u32 {
    ((imm as u32 & 0xfff) << 20) | ((rs1 as u32) << 15) | (f3 << 12) | ((rd as u32) << 7) | op
}

fn s(op: u32, f3: u32, rs1: u8, rs2: u8, imm: i32) -> u32 {
    let imm = imm as u32;
    (bits(imm, 11, 5) << 25)
        | ((rs2 as u32) << 20)
        | ((rs1 as u32) << 15)
        | (f3 << 12)
        | (bits(imm, 4, 0) << 7)
        | op
}

fn b(f3: u32, rs1: u8, rs2: u8, imm: i32) -> u32 {
    let imm = imm as u32;
    (bits(imm, 12, 12) << 31)
        | (bits(imm, 10, 5) << 25)
        | ((rs2 as u32) << 20)
        | ((rs1 as u32) << 15)
        | (f3 << 12)
        | (bits(imm, 4, 1) << 8)
        | (bits(imm, 11, 11) << 7)
        | OP_BRANCH
}

fn j(rd: u8, imm: i32) -> u32 {
    let imm = imm as u32;
    (bits(imm, 20, 20) << 31)
        | (bits(imm, 10, 1) << 21)
        | (bits(imm, 11, 11) << 20)
        | (bits(imm, 19, 12) << 12)
        | ((rd as u32) << 7)
        | OP_JAL
}

/// Encodes an instruction. Panics on values that cannot be encoded (a test or
/// assembler bug, never reachable from untrusted input).
pub fn encode(x: &Instr) -> u32 {
    let (rd, rs1, rs2, imm) = (x.rd, x.rs1, x.rs2, x.imm);
    assert!(rd < 32 && rs1 < 32 && rs2 < 32, "register out of range");
    match x.op {
        Op::Lui => (imm as u32 & 0xffff_f000) | ((rd as u32) << 7) | OP_LUI,
        Op::Auipc => (imm as u32 & 0xffff_f000) | ((rd as u32) << 7) | OP_AUIPC,
        Op::Jal => j(rd, imm),
        Op::Jalr => i(OP_JALR, rd, 0, rs1, imm),
        Op::Beq => b(0b000, rs1, rs2, imm),
        Op::Bne => b(0b001, rs1, rs2, imm),
        Op::Blt => b(0b100, rs1, rs2, imm),
        Op::Bge => b(0b101, rs1, rs2, imm),
        Op::Bltu => b(0b110, rs1, rs2, imm),
        Op::Bgeu => b(0b111, rs1, rs2, imm),
        Op::Lb => i(OP_LOAD, rd, 0b000, rs1, imm),
        Op::Lh => i(OP_LOAD, rd, 0b001, rs1, imm),
        Op::Lw => i(OP_LOAD, rd, 0b010, rs1, imm),
        Op::Lbu => i(OP_LOAD, rd, 0b100, rs1, imm),
        Op::Lhu => i(OP_LOAD, rd, 0b101, rs1, imm),
        Op::Sb => s(OP_STORE, 0b000, rs1, rs2, imm),
        Op::Sh => s(OP_STORE, 0b001, rs1, rs2, imm),
        Op::Sw => s(OP_STORE, 0b010, rs1, rs2, imm),
        Op::Addi => i(OP_IMM, rd, 0b000, rs1, imm),
        Op::Slti => i(OP_IMM, rd, 0b010, rs1, imm),
        Op::Sltiu => i(OP_IMM, rd, 0b011, rs1, imm),
        Op::Xori => i(OP_IMM, rd, 0b100, rs1, imm),
        Op::Ori => i(OP_IMM, rd, 0b110, rs1, imm),
        Op::Andi => i(OP_IMM, rd, 0b111, rs1, imm),
        Op::Slli => r(OP_IMM, rd, 0b001, rs1, imm as u8 & 31, 0),
        Op::Srli => r(OP_IMM, rd, 0b101, rs1, imm as u8 & 31, 0),
        Op::Srai => r(OP_IMM, rd, 0b101, rs1, imm as u8 & 31, 0b0100000),
        Op::Add => r(OP_REG, rd, 0b000, rs1, rs2, 0),
        Op::Sub => r(OP_REG, rd, 0b000, rs1, rs2, 0b0100000),
        Op::Sll => r(OP_REG, rd, 0b001, rs1, rs2, 0),
        Op::Slt => r(OP_REG, rd, 0b010, rs1, rs2, 0),
        Op::Sltu => r(OP_REG, rd, 0b011, rs1, rs2, 0),
        Op::Xor => r(OP_REG, rd, 0b100, rs1, rs2, 0),
        Op::Srl => r(OP_REG, rd, 0b101, rs1, rs2, 0),
        Op::Sra => r(OP_REG, rd, 0b101, rs1, rs2, 0b0100000),
        Op::Or => r(OP_REG, rd, 0b110, rs1, rs2, 0),
        Op::And => r(OP_REG, rd, 0b111, rs1, rs2, 0),
        Op::Mul => r(OP_REG, rd, 0b000, rs1, rs2, 1),
        Op::Mulh => r(OP_REG, rd, 0b001, rs1, rs2, 1),
        Op::Mulhsu => r(OP_REG, rd, 0b010, rs1, rs2, 1),
        Op::Mulhu => r(OP_REG, rd, 0b011, rs1, rs2, 1),
        Op::Fence => 0x0ff0_000f,
        Op::Ecall => ECALL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_OPS: [Op; 43] = [
        Op::Lui,
        Op::Auipc,
        Op::Jal,
        Op::Jalr,
        Op::Beq,
        Op::Bne,
        Op::Blt,
        Op::Bge,
        Op::Bltu,
        Op::Bgeu,
        Op::Lb,
        Op::Lh,
        Op::Lw,
        Op::Lbu,
        Op::Lhu,
        Op::Sb,
        Op::Sh,
        Op::Sw,
        Op::Addi,
        Op::Slti,
        Op::Sltiu,
        Op::Xori,
        Op::Ori,
        Op::Andi,
        Op::Slli,
        Op::Srli,
        Op::Srai,
        Op::Add,
        Op::Sub,
        Op::Sll,
        Op::Slt,
        Op::Sltu,
        Op::Xor,
        Op::Srl,
        Op::Sra,
        Op::Or,
        Op::And,
        Op::Mul,
        Op::Mulh,
        Op::Mulhsu,
        Op::Mulhu,
        Op::Fence,
        Op::Ecall,
    ];

    /// Canonical field values of a random instruction of `op`.
    fn sample(op: Op, seed: u64) -> Instr {
        let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0x2545_f491_4f6c_dd1d;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let reg = |v: u64| (v % 32) as u8;
        let (rd, rs1, rs2) = (reg(next()), reg(next()), reg(next()));
        let simm = |v: u64, w: u32| sign_extend(v as u32 & ((1 << w) - 1), w);
        use Op::*;
        match op {
            Lui | Auipc => Instr {
                op,
                rd,
                rs1: 0,
                rs2: 0,
                imm: (next() as u32 & 0xffff_f000) as i32,
            },
            Jal => Instr {
                op,
                rd,
                rs1: 0,
                rs2: 0,
                imm: simm(next(), 21) & !1,
            },
            Jalr | Lb | Lh | Lw | Lbu | Lhu | Addi | Slti | Sltiu | Xori | Ori | Andi => Instr {
                op,
                rd,
                rs1,
                rs2: 0,
                imm: simm(next(), 12),
            },
            Beq | Bne | Blt | Bge | Bltu | Bgeu => Instr {
                op,
                rd: 0,
                rs1,
                rs2,
                imm: simm(next(), 13) & !1,
            },
            Sb | Sh | Sw => Instr {
                op,
                rd: 0,
                rs1,
                rs2,
                imm: simm(next(), 12),
            },
            Slli | Srli | Srai => Instr {
                op,
                rd,
                rs1,
                rs2: 0,
                imm: (next() % 32) as i32,
            },
            Fence | Ecall => Instr {
                op,
                rd: 0,
                rs1: 0,
                rs2: 0,
                imm: 0,
            },
            _ => Instr {
                op,
                rd,
                rs1,
                rs2,
                imm: 0,
            },
        }
    }

    #[test]
    fn encode_decode_round_trip_for_every_op() {
        for op in ALL_OPS {
            for seed in 0..200 {
                let x = sample(op, seed);
                assert_eq!(decode(encode(&x)), Ok(x), "{op:?} seed {seed}");
            }
        }
    }

    #[test]
    fn known_encodings() {
        // Values from the RISC-V specification / GNU assembler.
        assert_eq!(
            decode(0x0050_0093).unwrap(),
            Instr {
                op: Op::Addi,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm: 5
            }
        ); // addi x1, x0, 5
        assert_eq!(
            decode(0x0020_81b3).unwrap(),
            Instr {
                op: Op::Add,
                rd: 3,
                rs1: 1,
                rs2: 2,
                imm: 0
            }
        ); // add x3, x1, x2
        assert_eq!(decode(0x4020_81b3).unwrap().op, Op::Sub);
        assert_eq!(decode(0x0220_81b3).unwrap().op, Op::Mul);
        assert_eq!(decode(0xfff0_0093).unwrap().imm, -1); // addi x1, x0, -1
        assert_eq!(decode(0x0000_0073).unwrap().op, Op::Ecall);
        assert_eq!(
            decode(0x0000_006f).unwrap(),
            Instr {
                op: Op::Jal,
                rd: 0,
                rs1: 0,
                rs2: 0,
                imm: 0
            }
        ); // j .
        assert_eq!(decode(0xfe00_0ee3).unwrap().imm, -4); // beq x0, x0, -4
        assert_eq!(decode(0x1234_5537).unwrap().imm, 0x1234_5000); // lui x10, 0x12345
    }

    #[test]
    fn unsupported_encodings_are_rejected() {
        for w in [
            0x0010_0073u32, // ebreak
            0x3000_2073,    // csrrs (CSR access)
            0x0000_100f,    // fence.i
            0x0200_1093,    // slli with shamt[5] set (RV64 only)
            0x0000_1067,    // jalr with funct3 != 0
            0x0000_3003,    // ld (RV64)
            0x0000_3023,    // sd (RV64)
            0x0000_705b,    // unknown opcode
            0x0220_c1b3,    // div x3, x1, x2 (not in BVM-1)
            0x0220_d1b3,    // divu
            0x0220_e1b3,    // rem
            0x0220_f1b3,    // remu
            0x8000_0033,    // add with illegal funct7
            0x0000_0053,    // fadd.s (F extension)
            0x0000_002f,    // amo (A extension)
            0xffff_ffff,
        ] {
            assert!(
                matches!(decode(w), Err(DecodeError::Illegal(_))),
                "{w:#010x}"
            );
        }
        for w in [0x0000_4501u32, 0x0000_8082, 0x0000_0000, 0xffff_fffe] {
            assert!(
                matches!(decode(w), Err(DecodeError::Compressed(_))),
                "{w:#010x}"
            );
        }
    }

    #[test]
    fn immediates_cover_their_full_range() {
        for imm in [-2048, -1, 0, 1, 2047] {
            let x = Instr {
                op: Op::Addi,
                rd: 1,
                rs1: 2,
                rs2: 0,
                imm,
            };
            assert_eq!(decode(encode(&x)).unwrap().imm, imm);
        }
        for imm in [-4096, -2, 2, 4094] {
            let x = Instr {
                op: Op::Beq,
                rd: 0,
                rs1: 1,
                rs2: 2,
                imm,
            };
            assert_eq!(decode(encode(&x)).unwrap().imm, imm);
        }
        for imm in [-(1 << 20), -2, 2, (1 << 20) - 2] {
            let x = Instr {
                op: Op::Jal,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm,
            };
            assert_eq!(decode(encode(&x)).unwrap().imm, imm);
        }
    }
}
