//! Differential and robustness fuzzing of the VM (pure Rust, seeded,
//! repeatable; `BLACKSILK_FUZZ_ITERS` scales the campaign).
//!
//! - **Interpreter vs constraints:** random straight-line programs (every
//!   ALU operation, loads and stores of every width, forward branches,
//!   `WRITE`, `POSEIDON2`, `READ`) run in the reference interpreter; every
//!   execution that halts must satisfy every constraint of every table and
//!   balance every bus. A sample is proven and verified.
//! - **Loader and interpreter robustness:** mutated ELF files never panic
//!   the loader; programs that load never panic the interpreter.

use blacksilk_zkvm::air::check::check;
use blacksilk_zkvm::air::trace::{self, Statement};
use blacksilk_zkvm::asm::{reg::*, Asm};
use blacksilk_zkvm::isa::Op;
use blacksilk_zkvm::{prove, run, Program};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::sync::Arc;

const BASE: u32 = 0x1_0000;
const DATA: u32 = 0x10_0000;

fn iters(default: usize) -> usize {
    std::env::var("BLACKSILK_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Scratch registers: t0–t2, a1–a5 (a0, a7 and s0 have fixed roles here).
const REGS: [u8; 8] = [T0, T1, T2, A1, A2, 13, 14, 15];

fn reg(rng: &mut ChaCha20Rng) -> u8 {
    REGS[rng.next_u32() as usize % REGS.len()]
}

/// A random straight-line program with forward branches; always halts
/// unless an instruction traps.
fn random_program(rng: &mut ChaCha20Rng, len: usize) -> Arc<Program> {
    let mut p = Asm::new(BASE);
    // 64 bytes of data: canonical field elements, so POSEIDON2 can run.
    let mut data = Vec::new();
    for _ in 0..16 {
        data.extend((rng.next_u32() % 0x7800_0001).to_le_bytes());
    }
    p.data(DATA, data, 256);
    p.li(S0, DATA);
    for &r in &REGS {
        p.li(r, rng.next_u32());
    }
    let rr = [
        Op::Add,
        Op::Sub,
        Op::Xor,
        Op::Or,
        Op::And,
        Op::Slt,
        Op::Sltu,
        Op::Sll,
        Op::Srl,
        Op::Sra,
        Op::Mul,
        Op::Mulh,
        Op::Mulhsu,
        Op::Mulhu,
    ];
    let ri = [Op::Addi, Op::Slti, Op::Sltiu, Op::Xori, Op::Ori, Op::Andi];
    let sh = [Op::Slli, Op::Srli, Op::Srai];
    let loads = [
        (Op::Lb, 1),
        (Op::Lbu, 1),
        (Op::Lh, 2),
        (Op::Lhu, 2),
        (Op::Lw, 4),
    ];
    let stores = [(Op::Sb, 1), (Op::Sh, 2), (Op::Sw, 4)];
    let branches = [Op::Beq, Op::Bne, Op::Blt, Op::Bge, Op::Bltu, Op::Bgeu];
    let mut label = 0;
    for _ in 0..len {
        match rng.next_u32() % 12 {
            0..=3 => {
                let op = rr[rng.next_u32() as usize % rr.len()];
                p.r(op, reg(rng), reg(rng), reg(rng));
            }
            4 | 5 => {
                let op = ri[rng.next_u32() as usize % ri.len()];
                let imm = (rng.next_u32() % 4096) as i32 - 2048;
                p.imm(op, reg(rng), reg(rng), imm);
            }
            6 => {
                let op = sh[rng.next_u32() as usize % sh.len()];
                p.imm(op, reg(rng), reg(rng), (rng.next_u32() % 32) as i32);
            }
            7 => {
                let (op, w) = loads[rng.next_u32() as usize % loads.len()];
                // Loads from the data words 16..64 (never the hashed buffer).
                let off = 64 + (rng.next_u32() % (192 / w)) * w;
                p.load(op, reg(rng), S0, off as i32);
            }
            8 => {
                let (op, w) = stores[rng.next_u32() as usize % stores.len()];
                let off = 64 + (rng.next_u32() % (192 / w)) * w;
                p.store(op, reg(rng), S0, off as i32);
            }
            9 => {
                // Forward branch over the next instruction.
                let op = branches[rng.next_u32() as usize % branches.len()];
                let l = format!("l{label}");
                label += 1;
                p.branch(op, reg(rng), reg(rng), &l);
                let op = rr[rng.next_u32() as usize % rr.len()];
                p.r(op, reg(rng), reg(rng), reg(rng));
                p.label(&l);
            }
            10 => {
                p.write_reg(reg(rng));
            }
            _ => {
                // Hash the (canonical) buffer, or read an input word.
                if rng.next_u32().is_multiple_of(2) {
                    p.imm(Op::Addi, A0, S0, 0).ecall(3);
                } else {
                    p.ecall(1).imm(Op::Addi, reg(rng), A0, 0);
                }
            }
        }
    }
    p.halt(rng.next_u32() % 4);
    Arc::new(p.finish().unwrap())
}

#[test]
fn random_programs_satisfy_every_constraint() {
    let mut rng = ChaCha20Rng::seed_from_u64(2026);
    let n = iters(300);
    let (mut halted, mut trapped, mut proven) = (0, 0, 0);
    for i in 0..n {
        let len = 5 + rng.next_u32() as usize % 120;
        let program = random_program(&mut rng, len);
        let input: Vec<u32> = (0..64).map(|_| rng.next_u32()).collect();
        let Ok(exec) = run(&program, &input, 1 << 16) else {
            trapped += 1;
            continue;
        };
        halted += 1;
        let st = Statement::single(
            program.clone(),
            exec.exit_code,
            exec.output.clone(),
            [0; 32],
        );
        let traces = trace::build(&st, &exec);
        let v = check(&trace::tables(&st), &traces, &trace::public_values(&st));
        assert!(v.is_empty(), "program {i}: {:?}", &v[..v.len().min(5)]);
        // A few are proven and verified end to end.
        if proven < 2 && i % 97 == 0 {
            let (st, proof) = prove::prove(program, &input, [0; 32], &mut rng).unwrap();
            assert_eq!(prove::verify(&st, &proof), Ok(()));
            proven += 1;
        }
    }
    println!("{n} random programs: {halted} halted and satisfied every constraint, {trapped} trapped, {proven} proven");
    assert!(
        halted > n / 2,
        "the generator should mostly produce halting programs"
    );
}

#[test]
fn mutated_elfs_never_panic_the_loader_or_the_interpreter() {
    let seeds: [&[u8]; 2] = [
        include_bytes!("fixtures/guest-sum.elf"),
        include_bytes!("fixtures/guest-arith.elf"),
    ];
    let mut rng = ChaCha20Rng::seed_from_u64(99);
    let n = iters(3000);
    let (mut loaded, mut ran) = (0, 0);
    for seed in seeds {
        for _ in 0..n {
            let mut v = seed.to_vec();
            for _ in 0..1 + rng.next_u32() % 4 {
                let i = rng.next_u32() as usize % v.len();
                v[i] = rng.next_u32() as u8;
            }
            if rng.next_u32() % 10 == 0 {
                v.truncate(rng.next_u32() as usize % v.len());
            }
            let Ok(p) = Program::from_elf(&v) else {
                continue;
            };
            loaded += 1;
            let input: Vec<u32> = (0..8).map(|_| rng.next_u32() % 100).collect();
            if run(&p, &input, 1 << 14).is_ok() {
                ran += 1;
            }
        }
    }
    println!(
        "{} mutated ELFs: {loaded} loaded, {ran} halted; no panic",
        2 * n
    );
}
