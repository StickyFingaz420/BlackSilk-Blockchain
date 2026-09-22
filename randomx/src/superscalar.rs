//! SuperscalarHash program generation and execution (spec chapter 6).
//!
//! The generator simulates instruction decoding and port scheduling of a
//! reference x86 CPU. Every random draw and every scheduling decision is
//! consensus-relevant, so this is a faithful port of the reference
//! `superscalar.cpp` (tevador/RandomX, BSD-3-Clause).

use crate::config::{REGISTER_NEEDS_DISPLACEMENT, SUPERSCALAR_LATENCY, SUPERSCALAR_MAX_SIZE};
use crate::hash::blake2b_512;

/// Pseudo-random byte stream seeded by the cache key (spec 3.4).
pub(crate) struct Blake2Generator {
    data: [u8; 64],
    index: usize,
}

impl Blake2Generator {
    pub(crate) fn new(seed: &[u8], nonce: u32) -> Self {
        let mut data = [0u8; 64];
        let n = seed.len().min(60);
        data[..n].copy_from_slice(&seed[..n]);
        data[60..64].copy_from_slice(&nonce.to_le_bytes());
        Self { data, index: 64 }
    }

    fn check_data(&mut self, needed: usize) {
        if self.index + needed > self.data.len() {
            self.data = blake2b_512(&self.data);
            self.index = 0;
        }
    }

    pub(crate) fn get_byte(&mut self) -> u8 {
        self.check_data(1);
        let b = self.data[self.index];
        self.index += 1;
        b
    }

    pub(crate) fn get_u32(&mut self) -> u32 {
        self.check_data(4);
        let v = u32::from_le_bytes(self.data[self.index..self.index + 4].try_into().unwrap());
        self.index += 4;
        v
    }
}

/// `floor(2^x / divisor)` for the largest `x` that keeps the result in 64 bits.
pub(crate) fn reciprocal(divisor: u32) -> u64 {
    assert!(divisor != 0);
    let divisor = divisor as u64;
    let p2exp63 = 1u64 << 63;
    let q = p2exp63 / divisor;
    let r = p2exp63 % divisor;
    let shift = 64 - divisor.leading_zeros();
    (q << shift) + ((r << shift) / divisor)
}

pub(crate) fn is_zero_or_power_of_2(x: u64) -> bool {
    x & x.wrapping_sub(1) == 0
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub(crate) enum SsType {
    IsubR = 0,
    IxorR = 1,
    IaddRs = 2,
    ImulR = 3,
    IrorC = 4,
    IaddC7 = 5,
    IxorC7 = 6,
    IaddC8 = 7,
    IxorC8 = 8,
    IaddC9 = 9,
    IxorC9 = 10,
    ImulhR = 11,
    IsmulhR = 12,
    ImulRcp = 13,
}

/// One instruction of a generated SuperscalarHash program.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SsInstr {
    pub(crate) opcode: SsType,
    pub(crate) dst: u8,
    pub(crate) src: u8,
    pub(crate) mod_: u8,
    pub(crate) imm32: u32,
    /// Precomputed `reciprocal(imm32)` for `IMUL_RCP`.
    pub(crate) rcp: u64,
}

impl SsInstr {
    /// Reference 8-byte encoding (opcode, dst, src, mod, imm32 LE); used by the test vectors.
    #[cfg(test)]
    pub(crate) fn to_bytes(self) -> [u8; 8] {
        let imm = self.imm32.to_le_bytes();
        [
            self.opcode as u8,
            self.dst,
            self.src,
            self.mod_,
            imm[0],
            imm[1],
            imm[2],
            imm[3],
        ]
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct SsProgram {
    pub(crate) instrs: Vec<SsInstr>,
    pub(crate) address_register: usize,
}

impl SsProgram {
    pub(crate) fn execute(&self, r: &mut [u64; 8]) {
        for ins in &self.instrs {
            let d = ins.dst as usize;
            let s = ins.src as usize;
            match ins.opcode {
                SsType::IsubR => r[d] = r[d].wrapping_sub(r[s]),
                SsType::IxorR => r[d] ^= r[s],
                SsType::IaddRs => r[d] = r[d].wrapping_add(r[s] << ((ins.mod_ >> 2) & 3)),
                SsType::ImulR => r[d] = r[d].wrapping_mul(r[s]),
                SsType::IrorC => r[d] = r[d].rotate_right(ins.imm32),
                SsType::IaddC7 | SsType::IaddC8 | SsType::IaddC9 => {
                    r[d] = r[d].wrapping_add(ins.imm32 as i32 as i64 as u64)
                }
                SsType::IxorC7 | SsType::IxorC8 | SsType::IxorC9 => {
                    r[d] ^= ins.imm32 as i32 as i64 as u64
                }
                SsType::ImulhR => r[d] = ((r[d] as u128 * r[s] as u128) >> 64) as u64,
                SsType::IsmulhR => {
                    r[d] = ((r[d] as i64 as i128 * r[s] as i64 as i128) >> 64) as u64
                }
                SsType::ImulRcp => r[d] = r[d].wrapping_mul(ins.rcp),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Simulated CPU model
// ---------------------------------------------------------------------------

type Port = u8;
const P_NULL: Port = 0;
const P0: Port = 1;
const P1: Port = 2;
const P5: Port = 4;
const P01: Port = P0 | P1;
const P05: Port = P0 | P5;
const P015: Port = P0 | P1 | P5;

#[derive(Clone, Copy)]
struct MacroOp {
    latency: i32,
    uop1: Port,
    uop2: Port,
    dependent: bool,
}

impl MacroOp {
    /// `_size` is the x86 encoding size; it documents the decoder slot the op
    /// fits in but does not influence generation.
    const fn new(_size: i32, latency: i32, uop1: Port, uop2: Port) -> Self {
        Self {
            latency,
            uop1,
            uop2,
            dependent: false,
        }
    }
    const fn dependent(self) -> Self {
        Self {
            dependent: true,
            ..self
        }
    }
    fn is_simple(&self) -> bool {
        self.uop2 == P_NULL
    }
    fn is_eliminated(&self) -> bool {
        self.uop1 == P_NULL
    }
}

const SUB_RR: MacroOp = MacroOp::new(3, 1, P015, P_NULL);
const XOR_RR: MacroOp = MacroOp::new(3, 1, P015, P_NULL);
const IMUL_R_OP: MacroOp = MacroOp::new(3, 4, P1, P5);
const MUL_R: MacroOp = MacroOp::new(3, 4, P1, P5);
const MOV_RR: MacroOp = MacroOp::new(3, 0, P_NULL, P_NULL);
const LEA_SIB: MacroOp = MacroOp::new(4, 1, P01, P_NULL);
const IMUL_RR: MacroOp = MacroOp::new(4, 3, P1, P_NULL);
const ROR_RI: MacroOp = MacroOp::new(4, 1, P05, P_NULL);
const ADD_RI: MacroOp = MacroOp::new(7, 1, P015, P_NULL);
const XOR_RI: MacroOp = MacroOp::new(7, 1, P015, P_NULL);
const MOV_RI64: MacroOp = MacroOp::new(10, 1, P015, P_NULL);

struct InstrInfo {
    ty: Option<SsType>, // None = NOP / INVALID
    ops: &'static [MacroOp],
    result_op: i32,
    dst_op: i32,
    src_op: i32,
}

const fn info(
    ty: SsType,
    ops: &'static [MacroOp],
    result_op: i32,
    dst_op: i32,
    src_op: i32,
) -> InstrInfo {
    InstrInfo {
        ty: Some(ty),
        ops,
        result_op,
        dst_op,
        src_op,
    }
}

static ISUB_R: InstrInfo = info(SsType::IsubR, &[SUB_RR], 0, 0, 0);
static IXOR_R: InstrInfo = info(SsType::IxorR, &[XOR_RR], 0, 0, 0);
static IADD_RS: InstrInfo = info(SsType::IaddRs, &[LEA_SIB], 0, 0, 0);
static IMUL_R: InstrInfo = info(SsType::ImulR, &[IMUL_RR], 0, 0, 0);
static IROR_C: InstrInfo = info(SsType::IrorC, &[ROR_RI], 0, 0, -1);
static IADD_C7: InstrInfo = info(SsType::IaddC7, &[ADD_RI], 0, 0, -1);
static IXOR_C7: InstrInfo = info(SsType::IxorC7, &[XOR_RI], 0, 0, -1);
static IADD_C8: InstrInfo = info(SsType::IaddC8, &[ADD_RI], 0, 0, -1);
static IXOR_C8: InstrInfo = info(SsType::IxorC8, &[XOR_RI], 0, 0, -1);
static IADD_C9: InstrInfo = info(SsType::IaddC9, &[ADD_RI], 0, 0, -1);
static IXOR_C9: InstrInfo = info(SsType::IxorC9, &[XOR_RI], 0, 0, -1);
static IMULH_R: InstrInfo = info(SsType::ImulhR, &[MOV_RR, MUL_R, MOV_RR], 1, 0, 1);
static ISMULH_R: InstrInfo = info(SsType::IsmulhR, &[MOV_RR, IMUL_R_OP, MOV_RR], 1, 0, 1);
static IMUL_RCP: InstrInfo = info(SsType::ImulRcp, &[MOV_RI64, IMUL_RR.dependent()], 1, 1, -1);
static NOP: InstrInfo = InstrInfo {
    ty: None,
    ops: &[],
    result_op: 0,
    dst_op: 0,
    src_op: 0,
};

static SLOT_3: [&InstrInfo; 2] = [&ISUB_R, &IXOR_R];
static SLOT_3L: [&InstrInfo; 4] = [&ISUB_R, &IXOR_R, &IMULH_R, &ISMULH_R];
static SLOT_4: [&InstrInfo; 2] = [&IROR_C, &IADD_RS];
static SLOT_7: [&InstrInfo; 2] = [&IXOR_C7, &IADD_C7];
static SLOT_8: [&InstrInfo; 2] = [&IXOR_C8, &IADD_C8];
static SLOT_9: [&InstrInfo; 2] = [&IXOR_C9, &IADD_C9];

struct DecoderBuffer {
    index: i32,
    counts: &'static [i32],
}

static BUF_484: DecoderBuffer = DecoderBuffer {
    index: 0,
    counts: &[4, 8, 4],
};
static BUF_7333: DecoderBuffer = DecoderBuffer {
    index: 1,
    counts: &[7, 3, 3, 3],
};
static BUF_3733: DecoderBuffer = DecoderBuffer {
    index: 2,
    counts: &[3, 7, 3, 3],
};
static BUF_493: DecoderBuffer = DecoderBuffer {
    index: 3,
    counts: &[4, 9, 3],
};
static BUF_4444: DecoderBuffer = DecoderBuffer {
    index: 4,
    counts: &[4, 4, 4, 4],
};
static BUF_3310: DecoderBuffer = DecoderBuffer {
    index: 5,
    counts: &[3, 3, 10],
};
static DEFAULT_BUFFERS: [&DecoderBuffer; 4] = [&BUF_484, &BUF_7333, &BUF_3733, &BUF_493];

fn fetch_next(
    ty: Option<SsType>,
    cycle: i32,
    mul_count: i32,
    gen: &mut Blake2Generator,
) -> &'static DecoderBuffer {
    if matches!(ty, Some(SsType::ImulhR) | Some(SsType::IsmulhR)) {
        return &BUF_3310;
    }
    if mul_count < cycle + 1 {
        return &BUF_4444;
    }
    if ty == Some(SsType::ImulRcp) {
        return if gen.get_byte() & 1 != 0 {
            &BUF_484
        } else {
            &BUF_493
        };
    }
    DEFAULT_BUFFERS[(gen.get_byte() & 3) as usize]
}

const INVALID_GROUP: i32 = -1;

#[derive(Clone, Copy)]
struct RegisterInfo {
    latency: i32,
    last_op_group: i32,
    last_op_par: i32,
}

impl Default for RegisterInfo {
    fn default() -> Self {
        Self {
            latency: 0,
            last_op_group: INVALID_GROUP,
            last_op_par: -1,
        }
    }
}

struct Instruction {
    info: &'static InstrInfo,
    src: i32,
    dst: i32,
    mod_: i32,
    imm32: u32,
    op_group: i32,
    op_group_par: i32,
    can_reuse: bool,
    group_par_is_source: bool,
}

impl Instruction {
    /// Equivalent of the reference's static, zero-initialized `SuperscalarInstruction::Null`.
    fn null() -> Self {
        Self {
            info: &NOP,
            src: -1,
            dst: -1,
            mod_: 0,
            imm32: 0,
            op_group: 0,
            op_group_par: 0,
            can_reuse: false,
            group_par_is_source: false,
        }
    }

    fn ty(&self) -> Option<SsType> {
        self.info.ty
    }

    fn create_for_slot(
        &mut self,
        gen: &mut Blake2Generator,
        slot_size: i32,
        fetch_type: i32,
        is_last: bool,
    ) {
        let info: &'static InstrInfo = match slot_size {
            3 if is_last => SLOT_3L[(gen.get_byte() & 3) as usize],
            3 => SLOT_3[(gen.get_byte() & 1) as usize],
            4 if fetch_type == 4 && !is_last => &IMUL_R,
            4 => SLOT_4[(gen.get_byte() & 1) as usize],
            7 => SLOT_7[(gen.get_byte() & 1) as usize],
            8 => SLOT_8[(gen.get_byte() & 1) as usize],
            9 => SLOT_9[(gen.get_byte() & 1) as usize],
            10 => &IMUL_RCP,
            _ => unreachable!("invalid decoder slot size"),
        };
        self.create(info, gen);
    }

    fn create(&mut self, info: &'static InstrInfo, gen: &mut Blake2Generator) {
        self.info = info;
        self.src = -1;
        self.dst = -1;
        self.can_reuse = false;
        self.group_par_is_source = false;
        let ty = info.ty.expect("create() is never called with NOP");
        match ty {
            SsType::IsubR => {
                self.mod_ = 0;
                self.imm32 = 0;
                self.op_group = SsType::IaddRs as i32;
                self.group_par_is_source = true;
            }
            SsType::IxorR => {
                self.mod_ = 0;
                self.imm32 = 0;
                self.op_group = SsType::IxorR as i32;
                self.group_par_is_source = true;
            }
            SsType::IaddRs => {
                self.mod_ = gen.get_byte() as i32;
                self.imm32 = 0;
                self.op_group = SsType::IaddRs as i32;
                self.group_par_is_source = true;
            }
            SsType::ImulR => {
                self.mod_ = 0;
                self.imm32 = 0;
                self.op_group = SsType::ImulR as i32;
                self.group_par_is_source = true;
            }
            SsType::IrorC => {
                self.mod_ = 0;
                loop {
                    self.imm32 = (gen.get_byte() & 63) as u32;
                    if self.imm32 != 0 {
                        break;
                    }
                }
                self.op_group = SsType::IrorC as i32;
                self.op_group_par = -1;
            }
            SsType::IaddC7 | SsType::IaddC8 | SsType::IaddC9 => {
                self.mod_ = 0;
                self.imm32 = gen.get_u32();
                self.op_group = SsType::IaddC7 as i32;
                self.op_group_par = -1;
            }
            SsType::IxorC7 | SsType::IxorC8 | SsType::IxorC9 => {
                self.mod_ = 0;
                self.imm32 = gen.get_u32();
                self.op_group = SsType::IxorC7 as i32;
                self.op_group_par = -1;
            }
            SsType::ImulhR | SsType::IsmulhR => {
                self.can_reuse = true;
                self.mod_ = 0;
                self.imm32 = 0;
                self.op_group = ty as i32;
                self.op_group_par = gen.get_u32() as i32;
            }
            SsType::ImulRcp => {
                self.mod_ = 0;
                loop {
                    self.imm32 = gen.get_u32();
                    if !is_zero_or_power_of_2(self.imm32 as u64) {
                        break;
                    }
                }
                self.op_group = SsType::ImulRcp as i32;
                self.op_group_par = -1;
            }
        }
    }

    fn select_destination(
        &mut self,
        cycle: i32,
        allow_chained_mul: bool,
        registers: &[RegisterInfo; 8],
        gen: &mut Blake2Generator,
    ) -> bool {
        let mut available = Vec::with_capacity(8);
        for (i, reg) in registers.iter().enumerate() {
            let i32_ = i as i32;
            if reg.latency <= cycle
                && (self.can_reuse || i32_ != self.src)
                && (allow_chained_mul
                    || self.op_group != SsType::ImulR as i32
                    || reg.last_op_group != SsType::ImulR as i32)
                && (reg.last_op_group != self.op_group || reg.last_op_par != self.op_group_par)
                && (self.ty() != Some(SsType::IaddRs) || i != REGISTER_NEEDS_DISPLACEMENT)
            {
                available.push(i32_);
            }
        }
        match select_register(&available, gen) {
            Some(r) => {
                self.dst = r;
                true
            }
            None => false,
        }
    }

    fn select_source(
        &mut self,
        cycle: i32,
        registers: &[RegisterInfo; 8],
        gen: &mut Blake2Generator,
    ) -> bool {
        let available: Vec<i32> = (0..8)
            .filter(|&i| registers[i as usize].latency <= cycle)
            .collect();
        let rnd = REGISTER_NEEDS_DISPLACEMENT as i32;
        if available.len() == 2
            && self.ty() == Some(SsType::IaddRs)
            && (available[0] == rnd || available[1] == rnd)
        {
            self.op_group_par = rnd;
            self.src = rnd;
            return true;
        }
        match select_register(&available, gen) {
            Some(r) => {
                self.src = r;
                if self.group_par_is_source {
                    self.op_group_par = r;
                }
                true
            }
            None => false,
        }
    }

    fn to_instr(&self) -> SsInstr {
        let opcode = self.ty().expect("only real instructions are emitted");
        let src = if self.src >= 0 { self.src } else { self.dst };
        SsInstr {
            opcode,
            dst: self.dst as u8,
            src: src as u8,
            mod_: self.mod_ as u8,
            imm32: self.imm32,
            rcp: if opcode == SsType::ImulRcp {
                reciprocal(self.imm32)
            } else {
                0
            },
        }
    }
}

fn select_register(available: &[i32], gen: &mut Blake2Generator) -> Option<i32> {
    match available.len() {
        0 => None,
        1 => Some(available[0]),
        n => Some(available[(gen.get_u32() % n as u32) as usize]),
    }
}

const CYCLE_MAP_SIZE: usize = SUPERSCALAR_LATENCY as usize + 4;
const LOOK_FORWARD_CYCLES: i32 = 4;
const MAX_THROWAWAY_COUNT: i32 = 256;

type PortBusy = [[Port; 3]; CYCLE_MAP_SIZE];

fn schedule_uop(commit: bool, uop: Port, port_busy: &mut PortBusy, mut cycle: i32) -> i32 {
    // Ports are tried in the order P5 -> P0 -> P1.
    while (cycle as usize) < CYCLE_MAP_SIZE {
        let c = cycle as usize;
        if uop & P5 != 0 && port_busy[c][2] == 0 {
            if commit {
                port_busy[c][2] = uop;
            }
            return cycle;
        }
        if uop & P0 != 0 && port_busy[c][0] == 0 {
            if commit {
                port_busy[c][0] = uop;
            }
            return cycle;
        }
        if uop & P1 != 0 && port_busy[c][1] == 0 {
            if commit {
                port_busy[c][1] = uop;
            }
            return cycle;
        }
        cycle += 1;
    }
    -1
}

fn schedule_mop(
    commit: bool,
    mop: &MacroOp,
    port_busy: &mut PortBusy,
    mut cycle: i32,
    dep_cycle: i32,
) -> i32 {
    if mop.dependent {
        cycle = cycle.max(dep_cycle);
    }
    if mop.is_eliminated() {
        return cycle;
    }
    if mop.is_simple() {
        return schedule_uop(commit, mop.uop1, port_busy, cycle);
    }
    // Both uOPs must execute in the same cycle.
    while (cycle as usize) < CYCLE_MAP_SIZE {
        let cycle1 = schedule_uop(false, mop.uop1, port_busy, cycle);
        let cycle2 = schedule_uop(false, mop.uop2, port_busy, cycle);
        if cycle1 >= 0 && cycle1 == cycle2 {
            if commit {
                schedule_uop(true, mop.uop1, port_busy, cycle1);
                schedule_uop(true, mop.uop2, port_busy, cycle2);
            }
            return cycle1;
        }
        cycle += 1;
    }
    -1
}

fn is_multiplication(ty: Option<SsType>) -> bool {
    matches!(
        ty,
        Some(SsType::ImulR) | Some(SsType::ImulhR) | Some(SsType::IsmulhR) | Some(SsType::ImulRcp)
    )
}

pub(crate) fn generate(gen: &mut Blake2Generator) -> SsProgram {
    let mut port_busy: PortBusy = [[0; 3]; CYCLE_MAP_SIZE];
    let mut registers = [RegisterInfo::default(); 8];
    let mut current = Instruction::null();
    let mut program: Vec<SsInstr> = Vec::with_capacity(SUPERSCALAR_MAX_SIZE);

    let mut macro_op_index: i32 = 0;
    let mut cycle: i32 = 0;
    let mut dep_cycle: i32 = 0;
    let mut ports_saturated = false;
    let mut mul_count: i32 = 0;
    let mut throw_away_count: i32 = 0;

    let mut decode_cycle: i32 = 0;
    while decode_cycle < SUPERSCALAR_LATENCY
        && !ports_saturated
        && program.len() < SUPERSCALAR_MAX_SIZE
    {
        let decode_buffer = fetch_next(current.ty(), decode_cycle, mul_count, gen);
        let mut buffer_index: usize = 0;

        while buffer_index < decode_buffer.counts.len() {
            let top_cycle = cycle;

            if macro_op_index >= current.info.ops.len() as i32 {
                if ports_saturated || program.len() >= SUPERSCALAR_MAX_SIZE {
                    break;
                }
                current.create_for_slot(
                    gen,
                    decode_buffer.counts[buffer_index],
                    decode_buffer.index,
                    decode_buffer.counts.len() == buffer_index + 1,
                );
                macro_op_index = 0;
            }

            let mop = current.info.ops[macro_op_index as usize];
            let mut schedule_cycle = schedule_mop(false, &mop, &mut port_busy, cycle, dep_cycle);
            if schedule_cycle < 0 {
                ports_saturated = true;
                break;
            }

            if macro_op_index == current.info.src_op {
                let mut forward = 0;
                while forward < LOOK_FORWARD_CYCLES
                    && !current.select_source(schedule_cycle, &registers, gen)
                {
                    schedule_cycle += 1;
                    cycle += 1;
                    forward += 1;
                }
                if forward == LOOK_FORWARD_CYCLES {
                    if throw_away_count < MAX_THROWAWAY_COUNT {
                        throw_away_count += 1;
                        macro_op_index = current.info.ops.len() as i32;
                        continue;
                    }
                    current = Instruction::null();
                    break;
                }
            }

            if macro_op_index == current.info.dst_op {
                let mut forward = 0;
                while forward < LOOK_FORWARD_CYCLES
                    && !current.select_destination(
                        schedule_cycle,
                        throw_away_count > 0,
                        &registers,
                        gen,
                    )
                {
                    schedule_cycle += 1;
                    cycle += 1;
                    forward += 1;
                }
                if forward == LOOK_FORWARD_CYCLES {
                    if throw_away_count < MAX_THROWAWAY_COUNT {
                        throw_away_count += 1;
                        macro_op_index = current.info.ops.len() as i32;
                        continue;
                    }
                    current = Instruction::null();
                    break;
                }
            }
            throw_away_count = 0;

            schedule_cycle =
                schedule_mop(true, &mop, &mut port_busy, schedule_cycle, schedule_cycle);
            if schedule_cycle < 0 {
                ports_saturated = true;
                break;
            }

            dep_cycle = schedule_cycle + mop.latency;

            if macro_op_index == current.info.result_op {
                let ri = &mut registers[current.dst as usize];
                ri.latency = dep_cycle;
                ri.last_op_group = current.op_group;
                ri.last_op_par = current.op_group_par;
            }

            buffer_index += 1;
            macro_op_index += 1;

            if schedule_cycle >= SUPERSCALAR_LATENCY {
                ports_saturated = true;
            }
            cycle = top_cycle;

            if macro_op_index >= current.info.ops.len() as i32 {
                program.push(current.to_instr());
                mul_count += is_multiplication(current.ty()) as i32;
            }
        }
        cycle += 1;
        decode_cycle += 1;
    }

    // The address register is the one with the longest dependency chain,
    // assuming 1-cycle latency and unlimited parallelism (an "ASIC" model).
    let mut asic_latencies = [0i32; 8];
    for ins in &program {
        let lat_dst = asic_latencies[ins.dst as usize] + 1;
        let lat_src = if ins.dst != ins.src {
            asic_latencies[ins.src as usize] + 1
        } else {
            0
        };
        asic_latencies[ins.dst as usize] = lat_dst.max(lat_src);
    }
    let mut max = 0;
    let mut address_register = 0;
    for (i, &lat) in asic_latencies.iter().enumerate() {
        if lat > max {
            max = lat;
            address_register = i;
        }
    }

    SsProgram {
        instrs: program,
        address_register,
    }
}
