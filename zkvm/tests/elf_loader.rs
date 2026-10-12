//! ELF loading and program layout limits (docs/zkvm.md §3).
//!
//! `Program::from_elf` runs on every PX deploy, so each rule here is a
//! consensus rule. Every rejection test starts from an ELF the loader accepts
//! and breaks exactly one thing; every limit is tested at the limit (accepted)
//! and one past it (rejected).

use blacksilk_zkvm::asm::{reg::*, Asm};
use blacksilk_zkvm::isa::Op;
use blacksilk_zkvm::program::MAX_DATA_SEGMENTS;
use blacksilk_zkvm::{run, Program, Segment, TrapKind};
use blacksilk_zkvm::{
    CODE_LIMIT_WORDS, DATA_LIMIT_BYTES, MAX_CYCLES, MAX_INPUT_WORDS, STACK_SIZE, STACK_TOP,
};

const BASE: u32 = 0x1_0000;
const DATA: u32 = 0x10_0000;
/// Lowest address the stack region starts at; code and data must end at or below it.
const LIMIT: u32 = STACK_TOP - STACK_SIZE;

const PT_NULL: u32 = 0;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

/// One program header and the file bytes it points to.
struct Seg {
    ptype: u32,
    vaddr: u32,
    flags: u32,
    bytes: Vec<u8>,
    memsz: u32,
}

fn load(vaddr: u32, flags: u32, bytes: Vec<u8>, memsz: u32) -> Seg {
    Seg {
        ptype: PT_LOAD,
        vaddr,
        flags,
        bytes,
        memsz,
    }
}

fn null_header() -> Seg {
    Seg {
        ptype: PT_NULL,
        vaddr: 0,
        flags: 0,
        bytes: Vec::new(),
        memsz: 0,
    }
}

fn put16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// A 32-bit little-endian RISC-V ELF header with the program header table at
/// `phoff`.
fn elf_header(entry: u32, phoff: u32, phnum: u16) -> Vec<u8> {
    let mut h = vec![0u8; 52];
    h[..4].copy_from_slice(b"\x7fELF");
    h[4] = 1; // ELFCLASS32
    h[5] = 1; // ELFDATA2LSB
    h[6] = 1; // EV_CURRENT
    put16(&mut h, 16, 2); // ET_EXEC
    put16(&mut h, 18, 243); // EM_RISCV
    put32(&mut h, 20, 1); // e_version
    put32(&mut h, 24, entry);
    put32(&mut h, 28, phoff);
    put32(&mut h, 36, 0); // e_flags: no RVC, soft float
    put16(&mut h, 40, 52); // e_ehsize
    put16(&mut h, 42, 32); // e_phentsize
    put16(&mut h, 44, phnum);
    h
}

fn program_header(
    ptype: u32,
    offset: u32,
    vaddr: u32,
    filesz: u32,
    memsz: u32,
    flags: u32,
) -> [u8; 32] {
    let mut p = [0u8; 32];
    put32(&mut p, 0, ptype);
    put32(&mut p, 4, offset);
    put32(&mut p, 8, vaddr);
    put32(&mut p, 12, vaddr);
    put32(&mut p, 16, filesz);
    put32(&mut p, 20, memsz);
    put32(&mut p, 24, flags);
    put32(&mut p, 28, 4);
    p
}

/// ELF header at 0, program headers right after it, then each segment's bytes
/// at a 4-byte aligned offset.
fn build(entry: u32, segs: &[Seg]) -> Vec<u8> {
    let phnum = u16::try_from(segs.len()).unwrap();
    let mut elf = elf_header(entry, 52, phnum);
    let mut offset = 52 + 32 * segs.len();
    let mut headers = Vec::new();
    let mut payload = Vec::new();
    for s in segs {
        let off = if s.bytes.is_empty() { 0 } else { offset };
        headers.extend_from_slice(&program_header(
            s.ptype,
            off as u32,
            s.vaddr,
            s.bytes.len() as u32,
            s.memsz,
            s.flags,
        ));
        payload.extend_from_slice(&s.bytes);
        offset += s.bytes.len();
        while !offset.is_multiple_of(4) {
            payload.push(0);
            offset += 1;
        }
    }
    elf.extend_from_slice(&headers);
    elf.extend_from_slice(&payload);
    elf
}

fn words_to_bytes(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

/// `halt(0)` assembled at `BASE`.
fn halt_code() -> Vec<u32> {
    let mut a = Asm::new(BASE);
    a.halt(0);
    a.finish().unwrap().code
}

fn code_seg() -> Seg {
    let bytes = words_to_bytes(&halt_code());
    let n = bytes.len() as u32;
    load(BASE, PF_R | PF_X, bytes, n)
}

fn valid_elf() -> Vec<u8> {
    build(BASE, &[code_seg()])
}

/// A valid one-word instruction (`addi t0, t0, 0`).
fn nop() -> u32 {
    let mut a = Asm::new(BASE);
    a.imm(Op::Addi, T0, T0, 0);
    a.finish().unwrap().code[0]
}

fn nops(base: u32, n: usize) -> Result<Program, blacksilk_zkvm::ProgramError> {
    Program::new(base, base, vec![nop(); n], Vec::new())
}

fn data_seg(base: u32, len: usize) -> Segment {
    Segment {
        base,
        bytes: vec![0xa5; len],
        mem_size: len as u32,
    }
}

fn with_data(data: Vec<Segment>) -> Result<Program, blacksilk_zkvm::ProgramError> {
    Program::new(BASE, BASE, halt_code(), data)
}

#[test]
fn the_reference_elf_loads() {
    let p = Program::from_elf(&valid_elf()).expect("valid ELF");
    assert_eq!(
        p,
        Program::new(BASE, BASE, halt_code(), Vec::new()).unwrap()
    );
    assert_eq!(run(&p, &[], MAX_CYCLES).unwrap().exit_code, 0);
}

#[test]
fn a_wrong_magic_byte_is_rejected() {
    for i in 0..4 {
        let mut elf = valid_elf();
        elf[i] ^= 1;
        assert!(Program::from_elf(&elf).is_err(), "magic byte {i}");
    }
}

#[test]
fn inputs_shorter_than_an_elf_header_are_rejected_without_panicking() {
    let full = valid_elf();
    let inputs: Vec<&[u8]> = vec![
        &[],
        &[0x7f],
        b"\x7fEL",
        b"\x7fELF",
        &full[..5],
        &full[..6],
        &full[..7],
        &full[..51],
    ];
    for input in inputs {
        assert!(Program::from_elf(input).is_err(), "{} bytes", input.len());
    }
}

#[test]
fn each_identification_byte_is_checked_on_its_own() {
    for (i, v) in [(4, 2u8), (5, 2), (5, 0), (6, 0), (6, 2)] {
        let mut elf = valid_elf();
        elf[i] = v;
        assert!(Program::from_elf(&elf).is_err(), "e_ident[{i}] = {v}");
    }
}

#[test]
fn a_program_header_entry_size_other_than_32_is_rejected() {
    // One header, so a 40-byte stride would still read it correctly.
    for size in [40u16, 28, 0] {
        let mut elf = valid_elf();
        put16(&mut elf, 42, size);
        assert!(Program::from_elf(&elf).is_err(), "e_phentsize {size}");
    }
}

#[test]
fn sixteen_program_headers_load_and_seventeen_do_not() {
    let headers = |n: usize| {
        let mut segs = vec![code_seg()];
        segs.extend((1..n).map(|_| null_header()));
        build(BASE, &segs)
    };
    let p = Program::from_elf(&headers(16)).expect("16 program headers are allowed");
    assert_eq!(p.code, halt_code());
    assert!(Program::from_elf(&headers(17)).is_err());
    let mut none = valid_elf();
    put16(&mut none, 44, 0);
    assert!(Program::from_elf(&none).is_err());
}

#[test]
fn code_segment_of_a_length_not_a_multiple_of_four_is_rejected() {
    let mut bytes = words_to_bytes(&halt_code());
    bytes.push(0);
    let n = bytes.len() as u32;
    let elf = build(BASE, &[load(BASE, PF_R | PF_X, bytes, n)]);
    assert!(Program::from_elf(&elf).is_err());
}

#[test]
fn code_segment_with_bss_is_rejected() {
    let bytes = words_to_bytes(&halt_code());
    let n = bytes.len() as u32;
    let elf = build(BASE, &[load(BASE, PF_R | PF_X, bytes, n + 4)]);
    assert!(Program::from_elf(&elf).is_err());
}

#[test]
fn writable_segment_below_the_code_is_rejected_and_above_it_is_accepted() {
    let below = 0x2000;
    let rw = |base| {
        build(
            BASE,
            &[code_seg(), load(base, PF_R | PF_W, vec![1, 2, 3, 4], 4)],
        )
    };
    assert!(Program::from_elf(&rw(below)).is_err());
    // The same segment read-only is fine: only writability is wrong.
    let ro = build(BASE, &[code_seg(), load(below, PF_R, vec![1, 2, 3, 4], 4)]);
    assert_eq!(Program::from_elf(&ro).unwrap().data[0].base, below);
    let p = Program::from_elf(&rw(DATA)).expect("writable data above the code");
    assert_eq!(p.data[0].base, DATA);
}

#[test]
fn data_segment_with_bss_loads_and_the_bss_reads_as_zero() {
    let mut a = Asm::new(BASE);
    a.li(T0, DATA)
        .load(Op::Lw, A1, T0, 0)
        .write_reg(A1)
        .load(Op::Lw, A1, T0, 16)
        .write_reg(A1)
        .halt(0);
    let code = a.finish().unwrap().code;
    let bytes = words_to_bytes(&code);
    let n = bytes.len() as u32;
    let elf = build(
        BASE,
        &[
            load(BASE, PF_R | PF_X, bytes, n),
            load(DATA, PF_R | PF_W, vec![1, 2, 3, 4], 20),
        ],
    );
    let p = Program::from_elf(&elf).expect("data with bss");
    assert_eq!(
        p.data,
        vec![Segment {
            base: DATA,
            bytes: vec![1, 2, 3, 4],
            mem_size: 20
        }]
    );
    let out = run(&p, &[], MAX_CYCLES).unwrap().output;
    assert_eq!(out, vec![0x0403_0201, 0]);
}

#[test]
fn a_segment_with_memory_size_below_file_size_is_rejected() {
    let elf = build(BASE, &[code_seg(), load(DATA, PF_R, vec![1, 2, 3, 4], 3)]);
    assert!(Program::from_elf(&elf).is_err());
}

#[test]
fn code_of_exactly_the_word_limit_loads_and_one_more_word_does_not() {
    assert!(nops(BASE, CODE_LIMIT_WORDS).is_ok());
    assert!(nops(BASE, CODE_LIMIT_WORDS + 1).is_err());
    assert!(nops(BASE, 0).is_err());
}

#[test]
fn code_ending_exactly_at_the_stack_region_loads_and_past_it_does_not() {
    assert!(nops(LIMIT - 12, 3).is_ok());
    assert!(nops(LIMIT - 8, 3).is_err());
    assert!(nops(LIMIT - 4, 1).is_ok());
    assert!(nops(LIMIT, 1).is_err());
}

#[test]
fn the_maximum_number_of_data_segments_loads_and_one_more_does_not() {
    let segs = |n: usize| {
        (0..n)
            .map(|k| data_seg(DATA + 0x1000 * k as u32, 16))
            .collect()
    };
    assert_eq!(
        with_data(segs(MAX_DATA_SEGMENTS)).unwrap().data.len(),
        MAX_DATA_SEGMENTS
    );
    assert!(with_data(segs(MAX_DATA_SEGMENTS + 1)).is_err());
}

#[test]
fn data_of_exactly_the_byte_limit_loads_and_one_more_byte_does_not() {
    let half = DATA_LIMIT_BYTES / 2;
    let second = DATA + half as u32 + 0x1000;
    // Split over two segments, so the total is what is limited.
    assert!(with_data(vec![data_seg(DATA, half), data_seg(second, half)]).is_ok());
    assert!(with_data(vec![data_seg(DATA, half), data_seg(second, half + 1)]).is_err());
    assert!(with_data(vec![data_seg(DATA, DATA_LIMIT_BYTES)]).is_ok());
    assert!(with_data(vec![data_seg(DATA, DATA_LIMIT_BYTES + 1)]).is_err());
    // bss does not count towards the limit.
    let bss = Segment {
        base: DATA,
        bytes: vec![1; 4],
        mem_size: DATA_LIMIT_BYTES as u32 + 4096,
    };
    assert!(with_data(vec![bss]).is_ok());
}

#[test]
fn an_elf_whose_last_bytes_are_its_program_header_loads() {
    // 84 bytes: the ELF header, then the only program header at the very end.
    // The single code word lives in the ignored e_shoff field (offset 32).
    let mut elf = elf_header(BASE, 52, 1);
    put32(&mut elf, 32, nop());
    elf.extend_from_slice(&program_header(PT_LOAD, 32, BASE, 4, 4, PF_R | PF_X));
    assert_eq!(elf.len(), 84);
    let p = Program::from_elf(&elf).expect("minimal ELF");
    assert_eq!(p.code, vec![nop()]);
    assert_eq!((p.entry, p.code_base), (BASE, BASE));
}

#[test]
fn input_of_exactly_the_word_limit_runs_and_one_more_word_traps() {
    let p = Program::new(BASE, BASE, halt_code(), Vec::new()).unwrap();
    let ok = run(&p, &vec![7; MAX_INPUT_WORDS], MAX_CYCLES).expect("input at the limit");
    assert_eq!(ok.exit_code, 0);
    let err = run(&p, &vec![7; MAX_INPUT_WORDS + 1], MAX_CYCLES).expect_err("input past the limit");
    assert_eq!(err.kind, TrapKind::InputExhausted);
}
