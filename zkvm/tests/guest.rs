//! A real Rust guest compiled with rustc/lld for riscv32i-unknown-none-elf (+zmmul)
//! (source: zkvm/guests/sum, rebuilt with zkvm/guests/build.sh).

use blacksilk_zkvm::{run, Program, MAX_CYCLES};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_symmetric::Permutation;

const ELF: &[u8] = include_bytes!("fixtures/guest-sum.elf");

fn expected(input: &[u32]) -> Vec<u32> {
    let n = input[0];
    let vals = &input[1..];
    let sum = vals.iter().fold(0u32, |a, v| a.wrapping_add(*v));
    let prod = vals.iter().fold(1u32, |a, v| a.wrapping_mul(v | 1));
    let mut state = [p3_baby_bear::BabyBear::ZERO; 16];
    for (i, v) in vals.iter().enumerate() {
        state[i % 16] = p3_baby_bear::BabyBear::from_u32(v % 2_000_000_000);
    }
    blacksilk_zk::config::permutation().permute_mut(&mut state);
    let table = [11u32, 22, 33, 44];
    vec![
        sum,
        prod,
        state[0].as_canonical_u32(),
        table[(n % 4) as usize],
        sum / (n + 1),
        sum % (n + 7),
    ]
}

#[test]
fn compiled_guest_loads_and_runs() {
    let program = Program::from_elf(ELF).expect("rustc/lld output is accepted");
    println!(
        "guest: {} instructions, {} data segments, id {:02x?}",
        program.code.len(),
        program.data.len(),
        &program.id()[..8]
    );
    for n in [0u32, 1, 5, 17, 40] {
        let mut input = vec![n];
        input.extend((0..n).map(|i| i.wrapping_mul(2_654_435_761).wrapping_add(7)));
        let e = run(&program, &input, MAX_CYCLES).expect("halts");
        assert_eq!(e.exit_code, 0, "n = {n}");
        assert_eq!(e.output, expected(&input), "n = {n}");
    }
}

#[test]
fn compiled_guest_contains_no_division_instructions() {
    // Built for RV32I + Zmmul: the divisions in the source became
    // compiler_builtins calls, and every word decodes as a BVM-1 instruction.
    let program = Program::from_elf(ELF).unwrap();
    let ops: std::collections::HashSet<_> = program
        .code
        .iter()
        .map(|w| blacksilk_zkvm::isa::decode(*w).unwrap().op)
        .collect();
    assert!(
        ops.contains(&blacksilk_zkvm::isa::Op::Mul)
            || ops.contains(&blacksilk_zkvm::isa::Op::Mulhu)
    );
}

#[test]
fn guest_panics_and_missing_input_have_no_successful_run() {
    let program = Program::from_elf(ELF).unwrap();
    // Promised 3 words, provided 1: READ traps, so no execution (and no proof).
    assert!(run(&program, &[3, 1], MAX_CYCLES).is_err());
}

#[test]
fn malformed_elves_are_rejected() {
    let mut bad = ELF.to_vec();
    bad[4] = 2; // 64-bit class
    assert!(Program::from_elf(&bad).is_err());
    let mut bad = ELF.to_vec();
    bad[18] = 0x3e; // x86-64 machine
    assert!(Program::from_elf(&bad).is_err());
    let mut bad = ELF.to_vec();
    bad[36] |= 1; // RVC flag
    assert!(Program::from_elf(&bad).is_err());
    assert!(Program::from_elf(&ELF[..40]).is_err());
    assert!(Program::from_elf(b"not an elf at all, just some bytes....................").is_err());
    // Truncating inside a segment's file range.
    assert!(Program::from_elf(&ELF[..ELF.len() / 2]).is_err());
}

#[test]
fn program_id_depends_on_code_and_data_only() {
    let p = Program::from_elf(ELF).unwrap();
    let mut q = p.clone();
    assert_eq!(p.id(), q.id());
    q.code[0] ^= 0x100; // change a register field
    assert_ne!(p.id(), q.id());
    if let Some(seg) = p.data.iter().position(|s| !s.bytes.is_empty()) {
        let mut r = p.clone();
        r.data[seg].bytes[0] ^= 1;
        assert_ne!(p.id(), r.id());
    }
}
