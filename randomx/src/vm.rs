//! The RandomX virtual machine: program generation, execution and hashing
//! (spec chapters 2, 4 and 5; reference `bytecode_machine`, `vm_interpreted`).

use crate::aes_gen::{fill_aes_1rx4, fill_aes_4rx4, hash_aes_1rx4};
use crate::config::*;
use crate::dataset::{Cache, Dataset};
use crate::fpu::{self, Rounding};
use crate::hash::{blake2b_256, blake2b_512};
use crate::superscalar::{is_zero_or_power_of_2, reciprocal};

const MANTISSA_SIZE: u32 = 52;
const MANTISSA_MASK: u64 = (1 << MANTISSA_SIZE) - 1;
const EXPONENT_MASK: u64 = (1 << 11) - 1;
const EXPONENT_BIAS: u64 = 1023;
const DYNAMIC_EXPONENT_BITS: u32 = 4;
const STATIC_EXPONENT_BITS: u32 = 4;
const CONST_EXPONENT_BITS: u64 = 0x300;
const DYNAMIC_MANTISSA_MASK: u64 = (1 << (MANTISSA_SIZE + DYNAMIC_EXPONENT_BITS)) - 1;
const FSCAL_MASK: u64 = 0x80F0_0000_0000_0000;

const PROGRAM_BYTES: usize = 128 + 8 * PROGRAM_SIZE;

/// Where Dataset items come from.
enum Memory<'a> {
    /// Items are computed on demand from the cache (verification).
    Light(&'a Cache),
    /// Items are read from the precomputed dataset (mining).
    Full(&'a Dataset),
}

impl Memory<'_> {
    #[inline]
    fn item(&self, n: u64) -> [u64; 8] {
        match self {
            Memory::Light(c) => c.dataset_item(n),
            Memory::Full(d) => d.item(n),
        }
    }
}

type FReg = [f64; 2];

#[derive(Clone, Copy)]
enum Src {
    Reg(usize),
    Imm(u64),
}

/// Pre-decoded instruction ("bytecode").
#[derive(Clone, Copy)]
enum Op {
    IaddRs {
        dst: usize,
        src: usize,
        shift: u32,
        imm: u64,
    },
    IaddM {
        dst: usize,
        src: Option<usize>,
        imm: u64,
        mask: u32,
    },
    IsubR {
        dst: usize,
        src: Src,
    },
    IsubM {
        dst: usize,
        src: Option<usize>,
        imm: u64,
        mask: u32,
    },
    ImulR {
        dst: usize,
        src: Src,
    },
    ImulM {
        dst: usize,
        src: Option<usize>,
        imm: u64,
        mask: u32,
    },
    ImulhR {
        dst: usize,
        src: usize,
    },
    ImulhM {
        dst: usize,
        src: Option<usize>,
        imm: u64,
        mask: u32,
    },
    IsmulhR {
        dst: usize,
        src: usize,
    },
    IsmulhM {
        dst: usize,
        src: Option<usize>,
        imm: u64,
        mask: u32,
    },
    InegR {
        dst: usize,
    },
    IxorR {
        dst: usize,
        src: Src,
    },
    IxorM {
        dst: usize,
        src: Option<usize>,
        imm: u64,
        mask: u32,
    },
    IrorR {
        dst: usize,
        src: Src,
    },
    IrolR {
        dst: usize,
        src: Src,
    },
    IswapR {
        dst: usize,
        src: usize,
    },
    /// `dst` 0..3 = f registers, 4..7 = e registers.
    FswapR {
        dst: usize,
    },
    FaddR {
        dst: usize,
        src: usize,
    },
    FaddM {
        dst: usize,
        src: usize,
        imm: u64,
        mask: u32,
    },
    FsubR {
        dst: usize,
        src: usize,
    },
    FsubM {
        dst: usize,
        src: usize,
        imm: u64,
        mask: u32,
    },
    FscalR {
        dst: usize,
    },
    FmulR {
        dst: usize,
        src: usize,
    },
    FdivM {
        dst: usize,
        src: usize,
        imm: u64,
        mask: u32,
    },
    FsqrtR {
        dst: usize,
    },
    Cbranch {
        reg: usize,
        target: i32,
        imm: u64,
        mask: u64,
    },
    Cfround {
        src: usize,
        rot: u32,
    },
    Istore {
        dst: usize,
        src: usize,
        imm: u64,
        mask: u32,
    },
    Nop,
}

struct ProgramConfig {
    e_mask: [u64; 2],
    read_reg: [usize; 4],
}

#[inline(always)]
fn sign_extend(imm32: u32) -> u64 {
    imm32 as i32 as i64 as u64
}

fn small_positive_float_bits(entropy: u64) -> u64 {
    let mut exponent = entropy >> 59;
    let mantissa = entropy & MANTISSA_MASK;
    exponent += EXPONENT_BIAS;
    exponent &= EXPONENT_MASK;
    exponent <<= MANTISSA_SIZE;
    exponent | mantissa
}

fn static_exponent(entropy: u64) -> u64 {
    let mut exponent = CONST_EXPONENT_BITS;
    exponent |= (entropy >> (64 - STATIC_EXPONENT_BITS)) << DYNAMIC_EXPONENT_BITS;
    exponent << MANTISSA_SIZE
}

fn float_mask(entropy: u64) -> u64 {
    const MASK22: u64 = (1 << 22) - 1;
    (entropy & MASK22) | static_exponent(entropy)
}

/// Opcode ranges ("ceilings") derived from the frequency table.
struct Ceil;
macro_rules! ceilings {
    ($($name:ident = $prev:expr, $freq:expr;)*) => {
        impl Ceil { $(const $name: u16 = $prev + $freq as u16;)* }
    };
}
ceilings! {
    IADD_RS = 0, FREQ_IADD_RS;
    IADD_M = Ceil::IADD_RS, FREQ_IADD_M;
    ISUB_R = Ceil::IADD_M, FREQ_ISUB_R;
    ISUB_M = Ceil::ISUB_R, FREQ_ISUB_M;
    IMUL_R = Ceil::ISUB_M, FREQ_IMUL_R;
    IMUL_M = Ceil::IMUL_R, FREQ_IMUL_M;
    IMULH_R = Ceil::IMUL_M, FREQ_IMULH_R;
    IMULH_M = Ceil::IMULH_R, FREQ_IMULH_M;
    ISMULH_R = Ceil::IMULH_M, FREQ_ISMULH_R;
    ISMULH_M = Ceil::ISMULH_R, FREQ_ISMULH_M;
    IMUL_RCP = Ceil::ISMULH_M, FREQ_IMUL_RCP;
    INEG_R = Ceil::IMUL_RCP, FREQ_INEG_R;
    IXOR_R = Ceil::INEG_R, FREQ_IXOR_R;
    IXOR_M = Ceil::IXOR_R, FREQ_IXOR_M;
    IROR_R = Ceil::IXOR_M, FREQ_IROR_R;
    IROL_R = Ceil::IROR_R, FREQ_IROL_R;
    ISWAP_R = Ceil::IROL_R, FREQ_ISWAP_R;
    FSWAP_R = Ceil::ISWAP_R, FREQ_FSWAP_R;
    FADD_R = Ceil::FSWAP_R, FREQ_FADD_R;
    FADD_M = Ceil::FADD_R, FREQ_FADD_M;
    FSUB_R = Ceil::FADD_M, FREQ_FSUB_R;
    FSUB_M = Ceil::FSUB_R, FREQ_FSUB_M;
    FSCAL_R = Ceil::FSUB_M, FREQ_FSCAL_R;
    FMUL_R = Ceil::FSCAL_R, FREQ_FMUL_R;
    FDIV_M = Ceil::FMUL_R, FREQ_FDIV_M;
    FSQRT_R = Ceil::FDIV_M, FREQ_FSQRT_R;
    CBRANCH = Ceil::FSQRT_R, FREQ_CBRANCH;
    CFROUND = Ceil::CBRANCH, FREQ_CFROUND;
    ISTORE = Ceil::CFROUND, FREQ_ISTORE;
}

fn mem_mask(mod_: u8) -> u32 {
    if !mod_.is_multiple_of(4) {
        SCRATCHPAD_L1_MASK
    } else {
        SCRATCHPAD_L2_MASK
    }
}

/// Memory operand: `src == dst` reads from a fixed address in L3.
fn mem_operand(dst: usize, src: usize, mod_: u8) -> (Option<usize>, u32) {
    if src != dst {
        (Some(src), mem_mask(mod_))
    } else {
        (None, SCRATCHPAD_L3_MASK)
    }
}

fn compile(bytes: &[u8]) -> Vec<Op> {
    let mut register_usage = [-1i32; 8];
    let mut ops = Vec::with_capacity(PROGRAM_SIZE);
    for (i, ins) in bytes.as_chunks::<8>().0.iter().enumerate() {
        let opcode = ins[0] as u16;
        let dst = ins[1] as usize % 8;
        let src = ins[2] as usize % 8;
        let mod_ = ins[3];
        let imm32 = u32::from_le_bytes(ins[4..8].try_into().unwrap());
        let i = i as i32;
        let reg_or_imm = |signed: bool| {
            if src != dst {
                Src::Reg(src)
            } else if signed {
                Src::Imm(sign_extend(imm32))
            } else {
                Src::Imm(imm32 as u64)
            }
        };

        let op = if opcode < Ceil::IADD_RS {
            register_usage[dst] = i;
            let imm = if dst == REGISTER_NEEDS_DISPLACEMENT {
                sign_extend(imm32)
            } else {
                0
            };
            Op::IaddRs {
                dst,
                src,
                shift: ((mod_ >> 2) % 4) as u32,
                imm,
            }
        } else if opcode < Ceil::IADD_M {
            register_usage[dst] = i;
            let (src, mask) = mem_operand(dst, src, mod_);
            Op::IaddM {
                dst,
                src,
                imm: sign_extend(imm32),
                mask,
            }
        } else if opcode < Ceil::ISUB_R {
            register_usage[dst] = i;
            Op::IsubR {
                dst,
                src: reg_or_imm(true),
            }
        } else if opcode < Ceil::ISUB_M {
            register_usage[dst] = i;
            let (src, mask) = mem_operand(dst, src, mod_);
            Op::IsubM {
                dst,
                src,
                imm: sign_extend(imm32),
                mask,
            }
        } else if opcode < Ceil::IMUL_R {
            register_usage[dst] = i;
            Op::ImulR {
                dst,
                src: reg_or_imm(true),
            }
        } else if opcode < Ceil::IMUL_M {
            register_usage[dst] = i;
            let (src, mask) = mem_operand(dst, src, mod_);
            Op::ImulM {
                dst,
                src,
                imm: sign_extend(imm32),
                mask,
            }
        } else if opcode < Ceil::IMULH_R {
            register_usage[dst] = i;
            Op::ImulhR { dst, src }
        } else if opcode < Ceil::IMULH_M {
            register_usage[dst] = i;
            let (src, mask) = mem_operand(dst, src, mod_);
            Op::ImulhM {
                dst,
                src,
                imm: sign_extend(imm32),
                mask,
            }
        } else if opcode < Ceil::ISMULH_R {
            register_usage[dst] = i;
            Op::IsmulhR { dst, src }
        } else if opcode < Ceil::ISMULH_M {
            register_usage[dst] = i;
            let (src, mask) = mem_operand(dst, src, mod_);
            Op::IsmulhM {
                dst,
                src,
                imm: sign_extend(imm32),
                mask,
            }
        } else if opcode < Ceil::IMUL_RCP {
            if !is_zero_or_power_of_2(imm32 as u64) {
                register_usage[dst] = i;
                Op::ImulR {
                    dst,
                    src: Src::Imm(reciprocal(imm32)),
                }
            } else {
                Op::Nop
            }
        } else if opcode < Ceil::INEG_R {
            register_usage[dst] = i;
            Op::InegR { dst }
        } else if opcode < Ceil::IXOR_R {
            register_usage[dst] = i;
            Op::IxorR {
                dst,
                src: reg_or_imm(true),
            }
        } else if opcode < Ceil::IXOR_M {
            register_usage[dst] = i;
            let (src, mask) = mem_operand(dst, src, mod_);
            Op::IxorM {
                dst,
                src,
                imm: sign_extend(imm32),
                mask,
            }
        } else if opcode < Ceil::IROR_R {
            register_usage[dst] = i;
            Op::IrorR {
                dst,
                src: reg_or_imm(false),
            }
        } else if opcode < Ceil::IROL_R {
            register_usage[dst] = i;
            Op::IrolR {
                dst,
                src: reg_or_imm(false),
            }
        } else if opcode < Ceil::ISWAP_R {
            if src != dst {
                register_usage[dst] = i;
                register_usage[src] = i;
                Op::IswapR { dst, src }
            } else {
                Op::Nop
            }
        } else if opcode < Ceil::FSWAP_R {
            Op::FswapR { dst }
        } else if opcode < Ceil::FADD_R {
            Op::FaddR {
                dst: dst % 4,
                src: src % 4,
            }
        } else if opcode < Ceil::FADD_M {
            Op::FaddM {
                dst: dst % 4,
                src,
                imm: sign_extend(imm32),
                mask: mem_mask(mod_),
            }
        } else if opcode < Ceil::FSUB_R {
            Op::FsubR {
                dst: dst % 4,
                src: src % 4,
            }
        } else if opcode < Ceil::FSUB_M {
            Op::FsubM {
                dst: dst % 4,
                src,
                imm: sign_extend(imm32),
                mask: mem_mask(mod_),
            }
        } else if opcode < Ceil::FSCAL_R {
            Op::FscalR { dst: dst % 4 }
        } else if opcode < Ceil::FMUL_R {
            Op::FmulR {
                dst: dst % 4,
                src: src % 4,
            }
        } else if opcode < Ceil::FDIV_M {
            Op::FdivM {
                dst: dst % 4,
                src,
                imm: sign_extend(imm32),
                mask: mem_mask(mod_),
            }
        } else if opcode < Ceil::FSQRT_R {
            Op::FsqrtR { dst: dst % 4 }
        } else if opcode < Ceil::CBRANCH {
            let reg = dst;
            let target = register_usage[reg];
            let shift = (mod_ >> 4) as u32 + JUMP_OFFSET;
            let mut imm = sign_extend(imm32) | (1u64 << shift);
            // Clear the bit below the condition mask; limits successive jumps.
            imm &= !(1u64 << (shift - 1));
            let mask = (CONDITION_MASK as u64) << shift;
            register_usage = [i; 8];
            Op::Cbranch {
                reg,
                target,
                imm,
                mask,
            }
        } else if opcode < Ceil::CFROUND {
            Op::Cfround {
                src,
                rot: imm32 & 63,
            }
        } else if opcode < Ceil::ISTORE {
            let mask = if (mod_ >> 4) < STORE_L3_CONDITION {
                mem_mask(mod_)
            } else {
                SCRATCHPAD_L3_MASK
            };
            Op::Istore {
                dst,
                src,
                imm: sign_extend(imm32),
                mask,
            }
        } else {
            Op::Nop
        };
        ops.push(op);
    }
    ops
}

/// A RandomX virtual machine bound to a Cache (light mode) or Dataset (full mode).
pub struct Vm<'a> {
    memory: Memory<'a>,
    scratchpad: Vec<u8>,
    r: [u64; 8],
    f: [FReg; 4],
    e: [FReg; 4],
    a: [FReg; 4],
    fprc: Rounding,
    ma: u32,
    mx: u32,
    dataset_offset: u64,
    config: ProgramConfig,
}

impl<'a> Vm<'a> {
    /// Verification VM: needs only the 256 MiB cache, computes dataset items on demand.
    pub fn light(cache: &'a Cache) -> Self {
        Self::with_memory(Memory::Light(cache))
    }

    /// Mining VM: reads the fully expanded ~2 GiB dataset.
    pub fn full(dataset: &'a Dataset) -> Self {
        Self::with_memory(Memory::Full(dataset))
    }

    fn with_memory(memory: Memory<'a>) -> Self {
        Self {
            memory,
            scratchpad: vec![0u8; SCRATCHPAD_L3],
            r: [0; 8],
            f: [[0.0; 2]; 4],
            e: [[0.0; 2]; 4],
            a: [[0.0; 2]; 4],
            fprc: Rounding::Nearest,
            ma: 0,
            mx: 0,
            dataset_offset: 0,
            config: ProgramConfig {
                e_mask: [0; 2],
                read_reg: [0, 2, 4, 6],
            },
        }
    }

    /// Computes the RandomX hash of `input` (spec chapter 2).
    pub fn hash(&mut self, input: &[u8]) -> [u8; 32] {
        let mut seed = blake2b_512(input);
        fill_aes_1rx4(&mut seed, &mut self.scratchpad);
        self.fprc = Rounding::Nearest;
        for _ in 0..PROGRAM_COUNT - 1 {
            self.run(&seed);
            seed = blake2b_512(&self.register_file());
        }
        self.run(&seed);

        let mut regs = self.register_file();
        regs[192..256].copy_from_slice(&hash_aes_1rx4(&self.scratchpad));
        blake2b_256(&regs)
    }

    fn register_file(&self) -> [u8; 256] {
        let mut out = [0u8; 256];
        for (i, v) in self.r.iter().enumerate() {
            out[8 * i..8 * i + 8].copy_from_slice(&v.to_le_bytes());
        }
        for (g, group) in [&self.f, &self.e, &self.a].into_iter().enumerate() {
            for (i, reg) in group.iter().enumerate() {
                for (lane, v) in reg.iter().enumerate() {
                    let o = 64 + 64 * g + 16 * i + 8 * lane;
                    out[o..o + 8].copy_from_slice(&v.to_bits().to_le_bytes());
                }
            }
        }
        out
    }

    fn run(&mut self, seed: &[u8; 64]) {
        let mut program = [0u8; PROGRAM_BYTES];
        fill_aes_4rx4(seed, &mut program);
        self.initialize(&program[..128]);
        let ops = compile(&program[128..]);
        self.execute(&ops);
    }

    fn initialize(&mut self, cfg: &[u8]) {
        let entropy = |i: usize| u64::from_le_bytes(cfg[8 * i..8 * i + 8].try_into().unwrap());
        for i in 0..4 {
            self.a[i][0] = f64::from_bits(small_positive_float_bits(entropy(2 * i)));
            self.a[i][1] = f64::from_bits(small_positive_float_bits(entropy(2 * i + 1)));
        }
        self.ma = (entropy(8) & CACHE_LINE_ALIGN_MASK as u64) as u32;
        self.mx = entropy(10) as u32;
        let mut address_registers = entropy(12);
        for (k, rr) in self.config.read_reg.iter_mut().enumerate() {
            *rr = 2 * k + (address_registers & 1) as usize;
            address_registers >>= 1;
        }
        self.dataset_offset = (entropy(13) % (DATASET_EXTRA_ITEMS + 1)) * CACHE_LINE_SIZE as u64;
        self.config.e_mask = [float_mask(entropy(14)), float_mask(entropy(15))];
    }

    #[inline(always)]
    fn load64(&self, addr: usize) -> u64 {
        u64::from_le_bytes(self.scratchpad[addr..addr + 8].try_into().unwrap())
    }

    #[inline(always)]
    fn store64(&mut self, addr: usize, v: u64) {
        self.scratchpad[addr..addr + 8].copy_from_slice(&v.to_le_bytes());
    }

    /// Two signed 32-bit integers converted to doubles (exact).
    #[inline(always)]
    fn load_f(&self, addr: usize) -> FReg {
        let lo = u32::from_le_bytes(self.scratchpad[addr..addr + 4].try_into().unwrap()) as i32;
        let hi = u32::from_le_bytes(self.scratchpad[addr + 4..addr + 8].try_into().unwrap()) as i32;
        [lo as f64, hi as f64]
    }

    #[inline(always)]
    fn mask_e(&self, x: FReg) -> FReg {
        [
            f64::from_bits((x[0].to_bits() & DYNAMIC_MANTISSA_MASK) | self.config.e_mask[0]),
            f64::from_bits((x[1].to_bits() & DYNAMIC_MANTISSA_MASK) | self.config.e_mask[1]),
        ]
    }

    #[inline(always)]
    fn mem_addr(&self, src: Option<usize>, imm: u64, mask: u32) -> usize {
        let base = src.map_or(0, |s| self.r[s]);
        (base.wrapping_add(imm) & mask as u64) as usize
    }

    #[inline(always)]
    fn src_val(&self, src: Src) -> u64 {
        match src {
            Src::Reg(s) => self.r[s],
            Src::Imm(v) => v,
        }
    }

    fn execute(&mut self, ops: &[Op]) {
        self.r = [0; 8];
        let mut sp_addr0 = self.mx;
        let mut sp_addr1 = self.ma;
        let [rr0, rr1, rr2, rr3] = self.config.read_reg;

        for _ in 0..PROGRAM_ITERATIONS {
            let sp_mix = self.r[rr0] ^ self.r[rr1];
            sp_addr0 ^= sp_mix as u32;
            sp_addr0 &= SCRATCHPAD_L3_MASK64;
            sp_addr1 ^= (sp_mix >> 32) as u32;
            sp_addr1 &= SCRATCHPAD_L3_MASK64;
            let (a0, a1) = (sp_addr0 as usize, sp_addr1 as usize);

            for i in 0..8 {
                self.r[i] ^= self.load64(a0 + 8 * i);
            }
            for i in 0..4 {
                self.f[i] = self.load_f(a1 + 8 * i);
            }
            for i in 0..4 {
                let v = self.load_f(a1 + 8 * (4 + i));
                self.e[i] = self.mask_e(v);
            }

            self.execute_program(ops);

            let read_ptr = self.dataset_offset + (self.ma & CACHE_LINE_ALIGN_MASK) as u64;
            self.mx ^= (self.r[rr2] ^ self.r[rr3]) as u32;
            let item = self.memory.item(read_ptr / CACHE_LINE_SIZE as u64);
            for (reg, v) in self.r.iter_mut().zip(item) {
                *reg ^= v;
            }
            std::mem::swap(&mut self.mx, &mut self.ma);

            for i in 0..8 {
                self.store64(a1 + 8 * i, self.r[i]);
            }
            for i in 0..4 {
                for lane in 0..2 {
                    let v = self.f[i][lane].to_bits() ^ self.e[i][lane].to_bits();
                    self.f[i][lane] = f64::from_bits(v);
                    self.store64(a0 + 16 * i + 8 * lane, v);
                }
            }
            sp_addr0 = 0;
            sp_addr1 = 0;
        }
    }

    fn execute_program(&mut self, ops: &[Op]) {
        let mut pc: i32 = 0;
        let n = ops.len() as i32;
        while pc < n {
            let mode = self.fprc;
            match ops[pc as usize] {
                Op::IaddRs {
                    dst,
                    src,
                    shift,
                    imm,
                } => {
                    self.r[dst] =
                        self.r[dst].wrapping_add((self.r[src] << shift).wrapping_add(imm));
                }
                Op::IaddM {
                    dst,
                    src,
                    imm,
                    mask,
                } => {
                    let v = self.load64(self.mem_addr(src, imm, mask));
                    self.r[dst] = self.r[dst].wrapping_add(v);
                }
                Op::IsubR { dst, src } => self.r[dst] = self.r[dst].wrapping_sub(self.src_val(src)),
                Op::IsubM {
                    dst,
                    src,
                    imm,
                    mask,
                } => {
                    let v = self.load64(self.mem_addr(src, imm, mask));
                    self.r[dst] = self.r[dst].wrapping_sub(v);
                }
                Op::ImulR { dst, src } => self.r[dst] = self.r[dst].wrapping_mul(self.src_val(src)),
                Op::ImulM {
                    dst,
                    src,
                    imm,
                    mask,
                } => {
                    let v = self.load64(self.mem_addr(src, imm, mask));
                    self.r[dst] = self.r[dst].wrapping_mul(v);
                }
                Op::ImulhR { dst, src } => self.r[dst] = mulh(self.r[dst], self.r[src]),
                Op::ImulhM {
                    dst,
                    src,
                    imm,
                    mask,
                } => {
                    let v = self.load64(self.mem_addr(src, imm, mask));
                    self.r[dst] = mulh(self.r[dst], v);
                }
                Op::IsmulhR { dst, src } => self.r[dst] = smulh(self.r[dst], self.r[src]),
                Op::IsmulhM {
                    dst,
                    src,
                    imm,
                    mask,
                } => {
                    let v = self.load64(self.mem_addr(src, imm, mask));
                    self.r[dst] = smulh(self.r[dst], v);
                }
                Op::InegR { dst } => self.r[dst] = self.r[dst].wrapping_neg(),
                Op::IxorR { dst, src } => self.r[dst] ^= self.src_val(src),
                Op::IxorM {
                    dst,
                    src,
                    imm,
                    mask,
                } => {
                    let v = self.load64(self.mem_addr(src, imm, mask));
                    self.r[dst] ^= v;
                }
                Op::IrorR { dst, src } => {
                    self.r[dst] = self.r[dst].rotate_right((self.src_val(src) & 63) as u32)
                }
                Op::IrolR { dst, src } => {
                    self.r[dst] = self.r[dst].rotate_left((self.src_val(src) & 63) as u32)
                }
                Op::IswapR { dst, src } => self.r.swap(dst, src),
                Op::FswapR { dst } => {
                    if dst < 4 {
                        self.f[dst].swap(0, 1);
                    } else {
                        self.e[dst - 4].swap(0, 1);
                    }
                }
                Op::FaddR { dst, src } => {
                    let a = self.a[src];
                    let f = &mut self.f[dst];
                    f[0] = fpu::add(f[0], a[0], mode);
                    f[1] = fpu::add(f[1], a[1], mode);
                }
                Op::FaddM {
                    dst,
                    src,
                    imm,
                    mask,
                } => {
                    let v = self.load_f(self.mem_addr(Some(src), imm, mask));
                    let f = &mut self.f[dst];
                    f[0] = fpu::add(f[0], v[0], mode);
                    f[1] = fpu::add(f[1], v[1], mode);
                }
                Op::FsubR { dst, src } => {
                    let a = self.a[src];
                    let f = &mut self.f[dst];
                    f[0] = fpu::sub(f[0], a[0], mode);
                    f[1] = fpu::sub(f[1], a[1], mode);
                }
                Op::FsubM {
                    dst,
                    src,
                    imm,
                    mask,
                } => {
                    let v = self.load_f(self.mem_addr(Some(src), imm, mask));
                    let f = &mut self.f[dst];
                    f[0] = fpu::sub(f[0], v[0], mode);
                    f[1] = fpu::sub(f[1], v[1], mode);
                }
                Op::FscalR { dst } => {
                    for lane in 0..2 {
                        self.f[dst][lane] =
                            f64::from_bits(self.f[dst][lane].to_bits() ^ FSCAL_MASK);
                    }
                }
                Op::FmulR { dst, src } => {
                    let a = self.a[src];
                    let e = &mut self.e[dst];
                    e[0] = fpu::mul(e[0], a[0], mode);
                    e[1] = fpu::mul(e[1], a[1], mode);
                }
                Op::FdivM {
                    dst,
                    src,
                    imm,
                    mask,
                } => {
                    let raw = self.load_f(self.mem_addr(Some(src), imm, mask));
                    let v = self.mask_e(raw);
                    let e = &mut self.e[dst];
                    e[0] = fpu::div(e[0], v[0], mode);
                    e[1] = fpu::div(e[1], v[1], mode);
                }
                Op::FsqrtR { dst } => {
                    let e = &mut self.e[dst];
                    e[0] = fpu::sqrt(e[0], mode);
                    e[1] = fpu::sqrt(e[1], mode);
                }
                Op::Cbranch {
                    reg,
                    target,
                    imm,
                    mask,
                } => {
                    self.r[reg] = self.r[reg].wrapping_add(imm);
                    if self.r[reg] & mask == 0 {
                        pc = target;
                    }
                }
                Op::Cfround { src, rot } => {
                    self.fprc = Rounding::from_bits(self.r[src].rotate_right(rot));
                }
                Op::Istore {
                    dst,
                    src,
                    imm,
                    mask,
                } => {
                    let addr = (self.r[dst].wrapping_add(imm) & mask as u64) as usize;
                    self.store64(addr, self.r[src]);
                }
                Op::Nop => {}
            }
            pc += 1;
        }
    }
}

#[inline(always)]
fn mulh(a: u64, b: u64) -> u64 {
    ((a as u128 * b as u128) >> 64) as u64
}

#[inline(always)]
fn smulh(a: u64, b: u64) -> u64 {
    ((a as i64 as i128 * b as i64 as i128) >> 64) as u64
}
