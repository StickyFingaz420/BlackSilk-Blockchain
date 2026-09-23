/// RandomX configuration constants

// Dataset parameters
pub const DATASET_BASE_SIZE: usize = 2147483648;  // 2 GB
pub const DATASET_EXTRA_SIZE: usize = 33554368;   // 32 MB
pub const DATASET_ITEM_SIZE: usize = 64;

// Program parameters
pub const PROGRAM_SIZE: usize = 256;
pub const PROGRAM_ITERATIONS: usize = 2048;
pub const PROGRAM_COUNT: usize = 8;

// Memory/Cache parameters
pub const ARGON_MEMORY: usize = 262144;           // 256 KB for Argon2d
pub const ARGON_ITERATIONS: u32 = 3;
pub const ARGON_LANES: u32 = 1;
pub const CACHE_ACCESSES: usize = 8;

// Scratchpad sizes
pub const SCRATCHPAD_L1: usize = 16384;          // 16 KB
pub const SCRATCHPAD_L2: usize = 262144;         // 256 KB
pub const SCRATCHPAD_L3: usize = 2097152;        // 2 MB

// VM configuration
pub const VM_REGISTERS: usize = 8;
pub const VM_FLOAT_REGISTERS: usize = 4;
pub const REGISTER_SIZE: usize = 8;              // 64-bit registers

// Instruction frequencies (out of 256)
pub const FREQ_IADD_RS: u32 = 16;
pub const FREQ_IADD_M: u32 = 16;
pub const FREQ_ISUB_R: u32 = 16;
pub const FREQ_ISUB_M: u32 = 16;
pub const FREQ_IMUL_R: u32 = 16;
pub const FREQ_IMUL_M: u32 = 16;
pub const FREQ_IMULH_R: u32 = 4;
pub const FREQ_IMULH_M: u32 = 4;
pub const FREQ_ISMULH_R: u32 = 4;
pub const FREQ_ISMULH_M: u32 = 4;
pub const FREQ_IMUL_RCP: u32 = 8;
pub const FREQ_INEG_R: u32 = 2;
pub const FREQ_IXOR_R: u32 = 15;
pub const FREQ_IXOR_M: u32 = 15;
pub const FREQ_IROR_R: u32 = 8;
pub const FREQ_IROL_R: u32 = 8;
pub const FREQ_ISWAP_R: u32 = 4;
pub const FREQ_FSWAP_R: u32 = 4;
pub const FREQ_FADD_R: u32 = 16;
pub const FREQ_FADD_M: u32 = 16;
pub const FREQ_FSUB_R: u32 = 16;
pub const FREQ_FSUB_M: u32 = 16;
pub const FREQ_FSCAL_R: u32 = 6;
pub const FREQ_FMUL_R: u32 = 8;
pub const FREQ_FDIV_M: u32 = 8;
pub const FREQ_FSQRT_R: u32 = 6;
pub const FREQ_CBRANCH: u32 = 8;
pub const FREQ_CFROUND: u32 = 1;
pub const FREQ_ISTORE: u32 = 16;
pub const FREQ_NOP: u32 = 1;

// Safety checks
const _: () = assert!(DATASET_BASE_SIZE > 0 && (DATASET_BASE_SIZE & (DATASET_BASE_SIZE - 1)) == 0,
    "DATASET_BASE_SIZE must be a power of 2");
const _: () = assert!(DATASET_EXTRA_SIZE % DATASET_ITEM_SIZE == 0,
    "DATASET_EXTRA_SIZE must be divisible by DATASET_ITEM_SIZE");
const _: () = assert!(PROGRAM_SIZE > 0 && PROGRAM_SIZE <= 32768,
    "PROGRAM_SIZE must be between 1 and 32768");
const _: () = assert!(SCRATCHPAD_L3 >= SCRATCHPAD_L2 && SCRATCHPAD_L2 >= SCRATCHPAD_L1,
    "Scratchpad sizes must be L3 >= L2 >= L1");
const _: () = assert!((SCRATCHPAD_L1 & (SCRATCHPAD_L1 - 1)) == 0,
    "SCRATCHPAD_L1 must be a power of 2");
const _: () = assert!(FREQ_IADD_RS + FREQ_IADD_M + FREQ_ISUB_R + FREQ_ISUB_M + FREQ_IMUL_R +
    FREQ_IMUL_M + FREQ_IMULH_R + FREQ_IMULH_M + FREQ_ISMULH_R + FREQ_ISMULH_M +
    FREQ_IMUL_RCP + FREQ_INEG_R + FREQ_IXOR_R + FREQ_IXOR_M + FREQ_IROR_R +
    FREQ_IROL_R + FREQ_ISWAP_R + FREQ_FSWAP_R + FREQ_FADD_R + FREQ_FADD_M +
    FREQ_FSUB_R + FREQ_FSUB_M + FREQ_FSCAL_R + FREQ_FMUL_R + FREQ_FDIV_M +
    FREQ_FSQRT_R + FREQ_CBRANCH + FREQ_CFROUND + FREQ_ISTORE + FREQ_NOP == 256,
    "Instruction frequencies must sum to 256");
