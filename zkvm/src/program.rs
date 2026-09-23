//! Programs: strict ELF loading and program ids (docs/zkvm.md §3).
//!
//! A program is the entry point, one executable segment (code) and up to
//! [`MAX_DATA_SEGMENTS`] non-executable segments (read-only data, data, bss).
//! Only file-backed bytes form the image; memory beyond them is zero.
//!
//! The ELF parser is our own (no dependency) and accepts only what BVM-1
//! needs: 32-bit little-endian RISC-V executables with `PT_LOAD` segments.
//! Section headers, symbols and other program headers (`PT_NOTE`,
//! `PT_GNU_STACK`, `PT_RISCV_ATTRIBUTES`) are ignored and do not affect the
//! program id.

use crate::isa::{decode, DecodeError};
use crate::{CODE_LIMIT_WORDS, DATA_LIMIT_BYTES, MEM_SIZE, NULL_GUARD, STACK_SIZE, STACK_TOP};
use blacksilk_crypto::hash::{tags, Hasher64};

pub const MAX_DATA_SEGMENTS: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    pub base: u32,
    pub bytes: Vec<u8>,
    /// Size in memory (≥ `bytes.len()`); the tail is zero (bss).
    pub mem_size: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    pub entry: u32,
    pub code_base: u32,
    /// Instruction words, all valid BVM-1 instructions.
    pub code: Vec<u32>,
    pub data: Vec<Segment>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProgramError {
    Elf(&'static str),
    Layout(&'static str),
    InvalidInstruction { pc: u32, error: DecodeError },
}

fn u16_at(b: &[u8], off: usize) -> Result<u16, ProgramError> {
    b.get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or(ProgramError::Elf("truncated"))
}

fn u32_at(b: &[u8], off: usize) -> Result<u32, ProgramError> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or(ProgramError::Elf("truncated"))
}

const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const EM_RISCV: u16 = 243;
const ET_EXEC: u16 = 2;

impl Program {
    /// Builds a program directly (tests, assembler). Validates like an ELF.
    pub fn new(
        entry: u32,
        code_base: u32,
        code: Vec<u32>,
        data: Vec<Segment>,
    ) -> Result<Self, ProgramError> {
        let p = Self {
            entry,
            code_base,
            code,
            data,
        };
        p.validate()?;
        Ok(p)
    }

    /// Parses a statically linked RV32 ELF executable.
    pub fn from_elf(elf: &[u8]) -> Result<Self, ProgramError> {
        let e = ProgramError::Elf;
        if elf.len() < 52 || &elf[..4] != b"\x7fELF" {
            return Err(e("not an ELF file"));
        }
        if elf[4] != 1 || elf[5] != 1 || elf[6] != 1 {
            return Err(e("not a 32-bit little-endian ELF version 1"));
        }
        if u16_at(elf, 16)? != ET_EXEC {
            return Err(e("not an executable"));
        }
        if u16_at(elf, 18)? != EM_RISCV {
            return Err(e("not RISC-V"));
        }
        // e_flags: RVC (bit 0) must be clear, float ABI (bits 1-2) soft, RVE clear.
        let flags = u32_at(elf, 36)?;
        if flags & 0b1111 != 0 {
            return Err(e("compressed, hard-float or RVE ABI"));
        }
        let entry = u32_at(elf, 24)?;
        let phoff = u32_at(elf, 28)? as usize;
        let phentsize = u16_at(elf, 42)? as usize;
        let phnum = u16_at(elf, 44)? as usize;
        if phentsize != 32 || phnum == 0 || phnum > 16 {
            return Err(e("unexpected program header table"));
        }
        let mut code: Option<(u32, Vec<u32>)> = None;
        let mut data = Vec::new();
        let mut writable = Vec::new();
        for i in 0..phnum {
            let h = phoff
                .checked_add(i * phentsize)
                .ok_or(e("program header offset overflow"))?;
            if u32_at(elf, h)? != PT_LOAD {
                continue;
            }
            let offset = u32_at(elf, h + 4)? as usize;
            let vaddr = u32_at(elf, h + 8)?;
            let filesz = u32_at(elf, h + 16)? as usize;
            let memsz = u32_at(elf, h + 20)?;
            let flags = u32_at(elf, h + 24)?;
            if memsz == 0 {
                continue;
            }
            if (memsz as usize) < filesz {
                return Err(e("segment memory size below file size"));
            }
            let bytes = elf
                .get(offset..offset.checked_add(filesz).ok_or(e("segment overflow"))?)
                .ok_or(e("segment outside the file"))?
                .to_vec();
            if flags & PF_X != 0 {
                if code.is_some() {
                    return Err(e("more than one executable segment"));
                }
                if !vaddr.is_multiple_of(4)
                    || !bytes.len().is_multiple_of(4)
                    || memsz as usize != bytes.len()
                {
                    return Err(e("code segment misaligned or with bss"));
                }
                let words = bytes
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|c| u32::from_le_bytes(*c))
                    .collect();
                code = Some((vaddr, words));
            } else {
                if flags & PF_W != 0 {
                    writable.push(vaddr);
                }
                data.push(Segment {
                    base: vaddr,
                    bytes,
                    mem_size: memsz,
                });
            }
        }
        let (code_base, code) = code.ok_or(e("no executable segment"))?;
        // Stores are only allowed at or above the end of the code (zkvm.md §2),
        // so a writable segment below the code could never be written.
        if writable.iter().any(|&base| base < code_base) {
            return Err(e("writable segment below the code segment"));
        }
        Self::new(entry, code_base, code, data)
    }

    fn validate(&self) -> Result<(), ProgramError> {
        let l = ProgramError::Layout;
        let limit = STACK_TOP - STACK_SIZE;
        let within =
            |base: u32, size: u64| base >= NULL_GUARD && (base as u64) + size <= limit as u64;
        if self.code.is_empty() || self.code.len() > CODE_LIMIT_WORDS {
            return Err(l("code size"));
        }
        if !self.code_base.is_multiple_of(4) || !within(self.code_base, self.code.len() as u64 * 4)
        {
            return Err(l("code segment outside the allowed range"));
        }
        if !self.entry.is_multiple_of(4) || !self.in_code(self.entry) {
            return Err(l("entry point outside the code segment"));
        }
        if self.data.len() > MAX_DATA_SEGMENTS {
            return Err(l("too many data segments"));
        }
        let mut ranges = vec![(self.code_base as u64, self.code_end() as u64)];
        let mut total = 0usize;
        for s in &self.data {
            if (s.mem_size as usize) < s.bytes.len() || !within(s.base, s.mem_size as u64) {
                return Err(l("data segment outside the allowed range"));
            }
            total += s.bytes.len();
            ranges.push((s.base as u64, s.base as u64 + s.mem_size as u64));
        }
        if total > DATA_LIMIT_BYTES {
            return Err(l("data size"));
        }
        ranges.sort();
        if ranges.windows(2).any(|w| w[0].1 > w[1].0) {
            return Err(l("overlapping segments"));
        }
        debug_assert!(limit <= MEM_SIZE);
        for (i, w) in self.code.iter().enumerate() {
            decode(*w).map_err(|error| ProgramError::InvalidInstruction {
                pc: self.code_base + 4 * i as u32,
                error,
            })?;
        }
        Ok(())
    }

    pub fn code_end(&self) -> u32 {
        self.code_base + 4 * self.code.len() as u32
    }

    pub fn in_code(&self, addr: u32) -> bool {
        addr >= self.code_base && addr < self.code_end()
    }

    /// The instruction word at `pc` (which must be in the code segment).
    pub fn fetch(&self, pc: u32) -> Option<u32> {
        if !pc.is_multiple_of(4) || !self.in_code(pc) {
            return None;
        }
        self.code.get(((pc - self.code_base) / 4) as usize).copied()
    }

    /// `program_id` (zkvm.md §3): commits to the entry point, the code and the
    /// file-backed data bytes with their addresses. Data segments are hashed in
    /// address order, each as `base ‖ len ‖ bytes`.
    pub fn id(&self) -> [u8; 32] {
        let mut h = Hasher64::new(tags::ZKVM_PROGRAM);
        h.update(&self.entry.to_le_bytes())
            .update(&self.code_base.to_le_bytes())
            .update(&(self.code.len() as u32).to_le_bytes());
        for w in &self.code {
            h.update(&w.to_le_bytes());
        }
        let mut data: Vec<&Segment> = self.data.iter().filter(|s| !s.bytes.is_empty()).collect();
        data.sort_by_key(|s| s.base);
        h.update(&(data.len() as u32).to_le_bytes());
        for s in data {
            h.update(&s.base.to_le_bytes())
                .update(&(s.bytes.len() as u32).to_le_bytes())
                .update(&s.bytes);
        }
        let wide = h.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&wide[..32]);
        id
    }
}
