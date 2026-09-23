//! BVM-1, the BlackSilk zero-knowledge virtual machine (docs/zkvm.md).
//!
//! | Module | Spec | Content |
//! |---|---|---|
//! | [`isa`] | §4 | strict RV32IM decoding and encoding |
//! | [`program`] | §3 | ELF loading, program ids |
//! | [`exec`] | §2–5 | the reference interpreter and its witness |
//!
//! The constraint tables that prove executions are built on this witness
//! (ZK-3, in progress).

#![forbid(unsafe_code)]

pub mod air;
pub mod asm;
pub mod exec;
pub mod isa;
pub mod program;
pub mod prove;

pub use exec::{run, Execution, Trap, TrapKind};
pub use program::{Program, ProgramError, Segment};

/// Memory size in bytes (addresses `0 .. MEM_SIZE`).
pub const MEM_SIZE: u32 = 1 << 28;
/// Accesses below this address trap (null-pointer guard).
pub const NULL_GUARD: u32 = 0x1000;
/// Initial stack pointer (`x2`).
pub const STACK_TOP: u32 = MEM_SIZE - 16;
/// Space reserved below `STACK_TOP` for the stack; segments must end below it.
pub const STACK_SIZE: u32 = 1 << 20;
/// Largest program, in instructions.
pub const CODE_LIMIT_WORDS: usize = 1 << 16;
/// Largest total file-backed data, in bytes.
pub const DATA_LIMIT_BYTES: usize = 1 << 20;
/// Cycle limit per execution; keeps every timestamp below 2^24 (zkvm.md §6.3).
pub const MAX_CYCLES: u32 = 1 << 21;
/// Longest private input and public output streams, in words.
pub const MAX_INPUT_WORDS: usize = 1 << 16;
pub const MAX_OUTPUT_WORDS: usize = 1 << 12;

/// A system call executed by `ECALL` (zkvm.md §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Syscall {
    Halt { code: u32 },
    Read { value: u32 },
    Write { value: u32 },
    Poseidon2 { ptr: u32 },
}
