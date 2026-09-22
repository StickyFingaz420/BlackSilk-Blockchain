//! RandomX v1 parameters (reference `configuration.h`, `common.hpp`).
//! These values are consensus-critical and must not be changed.

pub(crate) const ARGON_MEMORY: u32 = 262_144; // KiB, i.e. 1024-byte blocks
pub(crate) const ARGON_ITERATIONS: u32 = 3;
pub(crate) const ARGON_LANES: u32 = 1;
pub(crate) const ARGON_SALT: &[u8] = b"RandomX\x03";

pub(crate) const CACHE_ACCESSES: usize = 8;
pub(crate) const SUPERSCALAR_LATENCY: i32 = 170;
pub(crate) const SUPERSCALAR_MAX_SIZE: usize = 3 * SUPERSCALAR_LATENCY as usize + 2;

pub(crate) const DATASET_BASE_SIZE: u64 = 2_147_483_648;
pub(crate) const DATASET_EXTRA_SIZE: u64 = 33_554_368;
pub(crate) const DATASET_ITEM_SIZE: u64 = 64;
pub(crate) const DATASET_ITEM_COUNT: u64 =
    (DATASET_BASE_SIZE + DATASET_EXTRA_SIZE) / DATASET_ITEM_SIZE;
pub(crate) const DATASET_EXTRA_ITEMS: u64 = DATASET_EXTRA_SIZE / DATASET_ITEM_SIZE;

pub(crate) const CACHE_SIZE: usize = ARGON_MEMORY as usize * 1024;
pub(crate) const CACHE_LINE_SIZE: usize = 64;
pub(crate) const CACHE_LINE_ALIGN_MASK: u32 =
    ((DATASET_BASE_SIZE - 1) as u32) & !(CACHE_LINE_SIZE as u32 - 1);

pub(crate) const PROGRAM_SIZE: usize = 256;
pub(crate) const PROGRAM_ITERATIONS: usize = 2048;
pub(crate) const PROGRAM_COUNT: usize = 8;

pub(crate) const SCRATCHPAD_L3: usize = 2_097_152;
pub(crate) const SCRATCHPAD_L2: usize = 262_144;
pub(crate) const SCRATCHPAD_L1: usize = 16_384;

pub(crate) const SCRATCHPAD_L1_MASK: u32 = (SCRATCHPAD_L1 as u32 / 8 - 1) * 8;
pub(crate) const SCRATCHPAD_L2_MASK: u32 = (SCRATCHPAD_L2 as u32 / 8 - 1) * 8;
pub(crate) const SCRATCHPAD_L3_MASK: u32 = (SCRATCHPAD_L3 as u32 / 8 - 1) * 8;
pub(crate) const SCRATCHPAD_L3_MASK64: u32 = (SCRATCHPAD_L3 as u32 / 64 - 1) * 64;

pub(crate) const JUMP_BITS: u32 = 8;
pub(crate) const JUMP_OFFSET: u32 = 8;
pub(crate) const CONDITION_MASK: u32 = (1 << JUMP_BITS) - 1;
pub(crate) const STORE_L3_CONDITION: u8 = 14;

pub(crate) const REGISTER_NEEDS_DISPLACEMENT: usize = 5;

/// Instruction frequencies per 256 opcodes, in opcode order.
pub(crate) const FREQ_IADD_RS: u8 = 16;
pub(crate) const FREQ_IADD_M: u8 = 7;
pub(crate) const FREQ_ISUB_R: u8 = 16;
pub(crate) const FREQ_ISUB_M: u8 = 7;
pub(crate) const FREQ_IMUL_R: u8 = 16;
pub(crate) const FREQ_IMUL_M: u8 = 4;
pub(crate) const FREQ_IMULH_R: u8 = 4;
pub(crate) const FREQ_IMULH_M: u8 = 1;
pub(crate) const FREQ_ISMULH_R: u8 = 4;
pub(crate) const FREQ_ISMULH_M: u8 = 1;
pub(crate) const FREQ_IMUL_RCP: u8 = 8;
pub(crate) const FREQ_INEG_R: u8 = 2;
pub(crate) const FREQ_IXOR_R: u8 = 15;
pub(crate) const FREQ_IXOR_M: u8 = 5;
pub(crate) const FREQ_IROR_R: u8 = 8;
pub(crate) const FREQ_IROL_R: u8 = 2;
pub(crate) const FREQ_ISWAP_R: u8 = 4;
pub(crate) const FREQ_FSWAP_R: u8 = 4;
pub(crate) const FREQ_FADD_R: u8 = 16;
pub(crate) const FREQ_FADD_M: u8 = 5;
pub(crate) const FREQ_FSUB_R: u8 = 16;
pub(crate) const FREQ_FSUB_M: u8 = 5;
pub(crate) const FREQ_FSCAL_R: u8 = 6;
pub(crate) const FREQ_FMUL_R: u8 = 32;
pub(crate) const FREQ_FDIV_M: u8 = 4;
pub(crate) const FREQ_FSQRT_R: u8 = 6;
pub(crate) const FREQ_CBRANCH: u8 = 25;
pub(crate) const FREQ_CFROUND: u8 = 1;
pub(crate) const FREQ_ISTORE: u8 = 16;

const _: () = assert!(
    FREQ_IADD_RS as u32
        + FREQ_IADD_M as u32
        + FREQ_ISUB_R as u32
        + FREQ_ISUB_M as u32
        + FREQ_IMUL_R as u32
        + FREQ_IMUL_M as u32
        + FREQ_IMULH_R as u32
        + FREQ_IMULH_M as u32
        + FREQ_ISMULH_R as u32
        + FREQ_ISMULH_M as u32
        + FREQ_IMUL_RCP as u32
        + FREQ_INEG_R as u32
        + FREQ_IXOR_R as u32
        + FREQ_IXOR_M as u32
        + FREQ_IROR_R as u32
        + FREQ_IROL_R as u32
        + FREQ_ISWAP_R as u32
        + FREQ_FSWAP_R as u32
        + FREQ_FADD_R as u32
        + FREQ_FADD_M as u32
        + FREQ_FSUB_R as u32
        + FREQ_FSUB_M as u32
        + FREQ_FSCAL_R as u32
        + FREQ_FMUL_R as u32
        + FREQ_FDIV_M as u32
        + FREQ_FSQRT_R as u32
        + FREQ_CBRANCH as u32
        + FREQ_CFROUND as u32
        + FREQ_ISTORE as u32
        == 256
);
