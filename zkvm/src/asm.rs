//! A minimal assembler for building BVM-1 programs in tests and tools
//! without an external RISC-V toolchain. Labels are resolved at [`Asm::finish`].

use crate::isa::{encode, Instr, Op};
use crate::program::{Program, ProgramError, Segment};
use std::collections::HashMap;

/// ABI register names used in tests.
pub mod reg {
    pub const ZERO: u8 = 0;
    pub const RA: u8 = 1;
    pub const SP: u8 = 2;
    pub const T0: u8 = 5;
    pub const T1: u8 = 6;
    pub const T2: u8 = 7;
    pub const A0: u8 = 10;
    pub const A1: u8 = 11;
    pub const A2: u8 = 12;
    pub const A7: u8 = 17;
    pub const S0: u8 = 8;
    pub const S1: u8 = 9;
}

enum Item {
    Word(Instr),
    /// Branch or JAL to a label, patched at finish.
    Jump(Instr, String),
}

pub struct Asm {
    base: u32,
    items: Vec<Item>,
    labels: HashMap<String, u32>,
    data: Vec<Segment>,
}

impl Asm {
    pub fn new(base: u32) -> Self {
        Self {
            base,
            items: Vec::new(),
            labels: HashMap::new(),
            data: Vec::new(),
        }
    }

    fn pc(&self) -> u32 {
        self.base + 4 * self.items.len() as u32
    }

    pub fn label(&mut self, name: &str) -> &mut Self {
        let pc = self.pc();
        assert!(
            self.labels.insert(name.to_string(), pc).is_none(),
            "duplicate label {name}"
        );
        self
    }

    pub fn i(&mut self, op: Op, rd: u8, rs1: u8, rs2: u8, imm: i32) -> &mut Self {
        self.items.push(Item::Word(Instr {
            op,
            rd,
            rs1,
            rs2,
            imm,
        }));
        self
    }

    /// `rd ← rs1 op rs2`.
    pub fn r(&mut self, op: Op, rd: u8, rs1: u8, rs2: u8) -> &mut Self {
        self.i(op, rd, rs1, rs2, 0)
    }

    /// `rd ← rs1 op imm`.
    pub fn imm(&mut self, op: Op, rd: u8, rs1: u8, imm: i32) -> &mut Self {
        self.i(op, rd, rs1, 0, imm)
    }

    /// Loads a 32-bit constant (LUI + ADDI).
    pub fn li(&mut self, rd: u8, value: u32) -> &mut Self {
        let upper = value.wrapping_add(0x800) & 0xffff_f000;
        let lower = value.wrapping_sub(upper) as i32;
        if upper != 0 {
            self.i(Op::Lui, rd, 0, 0, upper as i32);
            self.imm(Op::Addi, rd, rd, lower)
        } else {
            self.imm(Op::Addi, rd, 0, lower)
        }
    }

    /// `mem[rs1 + off] ← rs2` (op = SB/SH/SW).
    pub fn store(&mut self, op: Op, rs2: u8, rs1: u8, off: i32) -> &mut Self {
        self.i(op, 0, rs1, rs2, off)
    }

    /// `rd ← mem[rs1 + off]` (op = LB/LH/LW/LBU/LHU).
    pub fn load(&mut self, op: Op, rd: u8, rs1: u8, off: i32) -> &mut Self {
        self.i(op, rd, rs1, 0, off)
    }

    /// Conditional branch to `label`.
    pub fn branch(&mut self, op: Op, rs1: u8, rs2: u8, label: &str) -> &mut Self {
        self.items.push(Item::Jump(
            Instr {
                op,
                rd: 0,
                rs1,
                rs2,
                imm: 0,
            },
            label.into(),
        ));
        self
    }

    /// `JAL rd, label`.
    pub fn jal(&mut self, rd: u8, label: &str) -> &mut Self {
        self.items.push(Item::Jump(
            Instr {
                op: Op::Jal,
                rd,
                rs1: 0,
                rs2: 0,
                imm: 0,
            },
            label.into(),
        ));
        self
    }

    pub fn ecall(&mut self, number: u32) -> &mut Self {
        self.li(reg::A7, number);
        self.i(Op::Ecall, 0, 0, 0, 0)
    }

    /// `WRITE a0 ← reg`.
    pub fn write_reg(&mut self, r: u8) -> &mut Self {
        self.imm(Op::Addi, reg::A0, r, 0);
        self.ecall(2)
    }

    pub fn halt(&mut self, code: u32) -> &mut Self {
        self.li(reg::A0, code);
        self.ecall(0)
    }

    pub fn data(&mut self, base: u32, bytes: Vec<u8>, mem_size: u32) -> &mut Self {
        self.data.push(Segment {
            base,
            bytes,
            mem_size,
        });
        self
    }

    pub fn finish(&self) -> Result<Program, ProgramError> {
        let mut code = Vec::with_capacity(self.items.len());
        for (k, item) in self.items.iter().enumerate() {
            let pc = self.base + 4 * k as u32;
            let x = match item {
                Item::Word(x) => *x,
                Item::Jump(x, label) => {
                    let target = *self
                        .labels
                        .get(label)
                        .unwrap_or_else(|| panic!("unknown label {label}"));
                    Instr {
                        imm: target.wrapping_sub(pc) as i32,
                        ..*x
                    }
                }
            };
            code.push(encode(&x));
        }
        Program::new(self.base, self.base, code, self.data.clone())
    }
}
