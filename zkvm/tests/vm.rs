//! End-to-end tests of the BVM-1 constraint system (docs/zkvm.md §9).

use blacksilk_zk::config::Val;
use blacksilk_zkvm::air::check::{check, MutationChecker};
use blacksilk_zkvm::air::trace::{self, Statement};
use blacksilk_zkvm::air::{cpu, memory};
use blacksilk_zkvm::asm::{reg::*, Asm};
use blacksilk_zkvm::isa::Op;
use blacksilk_zkvm::{prove, run, MAX_CYCLES};
use p3_field::PrimeCharacteristicRing;
use rand_chacha::rand_core::SeedableRng;
use std::sync::Arc;

const BASE: u32 = 0x1_0000;
const DATA: u32 = 0x10_0000;

/// A program exercising every instruction class.
fn kitchen_sink() -> Asm {
    let mut p = Asm::new(BASE);
    p.data(DATA, vec![0xf3, 0x82, 0x81, 0x80, 7, 0, 0, 0], 64);
    p.li(S0, DATA)
        // ALU register-register and immediate.
        .li(T0, 0x8000_0005)
        .li(T1, 3)
        .r(Op::Add, A1, T0, T1)
        .write_reg(A1)
        .r(Op::Sub, A1, T1, T0)
        .write_reg(A1)
        .r(Op::Xor, A1, T0, T1)
        .r(Op::Or, A2, T0, T1)
        .r(Op::And, A1, A1, A2)
        .write_reg(A1)
        .r(Op::Slt, A1, T0, T1)
        .write_reg(A1)
        .r(Op::Sltu, A1, T0, T1)
        .write_reg(A1)
        .r(Op::Sll, A1, T0, T1)
        .r(Op::Srl, A2, T0, T1)
        .r(Op::Sra, A1, A1, A2)
        .write_reg(A1)
        .r(Op::Mul, A1, T0, T1)
        .write_reg(A1)
        .r(Op::Mulh, A1, T0, T1)
        .r(Op::Mulhsu, A2, T0, T1)
        .r(Op::Mulhu, A1, A1, A2)
        .write_reg(A1)
        .imm(Op::Addi, A1, T0, -7)
        .imm(Op::Xori, A1, A1, 0x55)
        .imm(Op::Srai, A1, A1, 3)
        .write_reg(A1)
        .imm(Op::Sltiu, A1, T1, -1)
        .imm(Op::Slti, A2, T0, 0)
        .r(Op::Add, A1, A1, A2)
        .write_reg(A1)
        // Writes to x0 compute but do not write.
        .r(Op::Add, ZERO, T0, T1)
        .imm(Op::Addi, ZERO, ZERO, 9)
        .write_reg(ZERO)
        // Loads of every width and signedness, stores of every width.
        .load(Op::Lb, A1, S0, 0)
        .write_reg(A1)
        .load(Op::Lbu, A1, S0, 1)
        .write_reg(A1)
        .load(Op::Lh, A1, S0, 2)
        .write_reg(A1)
        .load(Op::Lhu, A1, S0, 0)
        .write_reg(A1)
        .load(Op::Lw, A1, S0, 4)
        .write_reg(A1)
        .li(T2, 0xabcd_ef12)
        .store(Op::Sb, T2, S0, 9)
        .store(Op::Sh, T2, S0, 14)
        .store(Op::Sw, T2, S0, 16)
        .load(Op::Lw, A1, S0, 8)
        .write_reg(A1)
        .load(Op::Lw, A1, S0, 12)
        .write_reg(A1)
        .load(Op::Lw, A1, S0, 16)
        .write_reg(A1)
        // Loads from the code segment return instruction words.
        .li(T2, BASE)
        .load(Op::Lw, A1, T2, 0)
        .write_reg(A1)
        // Upper immediates and jumps.
        .i(Op::Lui, A1, 0, 0, 0x1234_5000u32 as i32)
        .write_reg(A1)
        .i(Op::Auipc, A1, 0, 0, 0x1000)
        .write_reg(A1)
        .jal(RA, "sub")
        .write_reg(A0)
        // A loop with branches of every kind.
        .li(T0, 0)
        .li(T1, 10)
        .label("loop")
        .imm(Op::Addi, T0, T0, 1)
        .branch(Op::Beq, T0, T1, "done")
        .branch(Op::Bne, T0, T1, "loop")
        .label("done")
        .branch(Op::Blt, T1, T0, "never")
        .branch(Op::Bge, T1, T0, "ok1")
        .label("never")
        .halt(9)
        .label("ok1")
        .li(T2, u32::MAX)
        .branch(Op::Bltu, T2, T0, "never")
        .branch(Op::Bgeu, T2, T0, "ok2")
        .halt(8)
        .label("ok2")
        .ecall(1)
        .write_reg(A0)
        .i(Op::Fence, 0, 0, 0, 0)
        .halt(0)
        .label("sub")
        .li(A0, 77)
        .imm(Op::Jalr, ZERO, RA, 0);
    p
}

fn statement(asm: &Asm, input: &[u32]) -> (Statement, Vec<p3_matrix::dense::RowMajorMatrix<Val>>) {
    let program = Arc::new(asm.finish().unwrap());
    let exec = run(&program, input, MAX_CYCLES).expect("halts");
    let st = Statement {
        program,
        exit_code: exec.exit_code,
        output: exec.output.clone(),
        binding: [7; 32],
    };
    let traces = trace::build(&st, &exec);
    (st, traces)
}

#[test]
fn every_instruction_class_satisfies_the_constraints() {
    let (st, traces) = statement(&kitchen_sink(), &[4242]);
    let v = check(&trace::tables(&st), &traces, &trace::public_values(&st));
    assert!(v.is_empty(), "{v:?}");
    assert_eq!(st.exit_code, 0);
}

#[test]
fn wrong_public_statement_is_caught_by_the_oracle() {
    let (st, traces) = statement(&kitchen_sink(), &[1]);
    for bad in [
        Statement {
            exit_code: 1,
            ..st.clone()
        },
        Statement {
            output: {
                let mut o = st.output.clone();
                o[3] ^= 1;
                o
            },
            ..st.clone()
        },
        Statement {
            output: {
                let mut o = st.output.clone();
                o.pop();
                o
            },
            ..st.clone()
        },
    ] {
        assert!(!check(&trace::tables(&bad), &traces, &trace::public_values(&bad)).is_empty());
    }
}

#[test]
fn every_single_cell_mutation_of_real_cpu_and_memory_rows_is_caught() {
    let (st, traces) = statement(&kitchen_sink(), &[5]);
    let airs = trace::tables(&st);
    let public = trace::public_values(&st);
    let mut m = MutationChecker::new(&airs, &traces, &public);
    let mut accepted = Vec::new();
    let mut tried = 0;
    // (table index, is_real column, width)
    for (t, real_col, w) in [
        (4usize, cpu::IS_REAL, cpu::WIDTH),
        (3, 0, memory::INIT_WIDTH),
    ] {
        let tr = &traces[t];
        let rows = tr.values.len() / w;
        for r in 0..rows {
            if tr.values[r * w + real_col] != Val::ONE {
                continue;
            }
            for col in 0..w {
                for delta in [Val::ONE, -Val::ONE] {
                    tried += 1;
                    if !m.caught(t, r, col, delta) {
                        accepted.push((t, r, col));
                    }
                }
            }
        }
    }
    accepted.sort();
    accepted.dedup();
    assert!(
        accepted.is_empty(),
        "{} under-constrained cells (table, row, column): {:?}",
        accepted.len(),
        &accepted[..accepted.len().min(40)]
    );
    println!("{tried} mutations, all caught");
}

#[test]
fn a_lying_prover_cannot_change_a_register_value() {
    let (st, mut traces) = statement(&kitchen_sink(), &[5]);
    let w = cpu::WIDTH;
    // Row 5 reads a register; claim a different value in A (and nothing else).
    traces[4].values[5 * w + cpu::A] += Val::ONE;
    assert!(!check(&trace::tables(&st), &traces, &trace::public_values(&st)).is_empty());
}

#[test]
fn a_small_program_proves_and_verifies_and_statements_are_bound() {
    let mut p = Asm::new(BASE);
    p.ecall(1)
        .imm(Op::Addi, S0, A0, 0)
        .ecall(1)
        .r(Op::Mul, S0, S0, A0)
        .write_reg(S0)
        .halt(3);
    let program = Arc::new(p.finish().unwrap());
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
    let (st, proof) = prove::prove(program.clone(), &[6, 7], [1; 32], &mut rng).expect("proves");
    assert_eq!(st.output, vec![42]);
    assert_eq!(st.exit_code, 3);
    println!(
        "VM proof: {} bytes",
        blacksilk_zk::encode_proof(&proof).len()
    );
    assert_eq!(prove::verify(&st, &proof), Ok(()));
    // Every public part is bound.
    let wrong = [
        Statement {
            exit_code: 0,
            ..st.clone()
        },
        Statement {
            output: vec![43],
            ..st.clone()
        },
        Statement {
            binding: [2; 32],
            ..st.clone()
        },
        Statement {
            program: Arc::new({
                let mut q = Asm::new(BASE);
                q.ecall(1)
                    .imm(Op::Addi, S0, A0, 0)
                    .ecall(1)
                    .r(Op::Add, S0, S0, A0)
                    .write_reg(S0)
                    .halt(3);
                q.finish().unwrap()
            }),
            ..st.clone()
        },
    ];
    for (i, bad) in wrong.iter().enumerate() {
        assert!(
            prove::verify(bad, &proof).is_err(),
            "wrong statement {i} verified"
        );
    }
}

/// The VM's actual proof shape must stay inside the BS-ZK-1 envelope and
/// reach ≥ 100 proven bits (docs/zk.md §9.3). Committed columns are counted
/// conservatively: main + preprocessed + one extension column (5 base
/// columns) per bus interaction, plus quotient chunks of the maximum degree.
#[test]
fn the_vm_shape_meets_the_security_floor() {
    use blacksilk_zk::params::{self, ProofShape};
    use blacksilk_zkvm::air::check::shapes;
    let (st, traces) = statement(&kitchen_sink(), &[5]);
    let sh = shapes(&trace::tables(&st), &traces, &trace::public_values(&st));
    let constraints: usize = sh.iter().map(|s| s.constraints).sum();
    let max_degree = 5; // the CPU's next-pc constraint (degree 5) is the highest
    let quotient_chunks = sh.len() * (max_degree - 1) * params::EXTENSION_DEGREE;
    let columns: usize = sh
        .iter()
        .map(|s| s.main_width + s.prep_width + params::EXTENSION_DEGREE * s.interactions)
        .sum::<usize>()
        + quotient_chunks;
    let shape = ProofShape {
        constraints,
        max_degree,
        committed_columns: columns,
        log_height: params::MAX_LOG_HEIGHT,
    };
    let sec = params::security(&shape);
    println!("VM shape: {sh:?}\n{shape:?}\n{sec:?}");
    assert!(
        columns <= params::MAX_COMMITTED_COLUMNS,
        "{columns} committed columns"
    );
    assert!(sec.johnson_bits >= params::MIN_PROVEN_BITS, "{sec:?}");
}

/// A real Rust program compiled by rustc/lld (zkvm/guests/arith): the
/// execution satisfies every constraint, proves and verifies, and the proof
/// does not verify for a different output.
#[test]
fn a_compiled_rust_guest_proves_and_verifies() {
    let program = Arc::new(
        blacksilk_zkvm::Program::from_elf(include_bytes!("fixtures/guest-arith.elf")).unwrap(),
    );
    let vals: Vec<u32> = (0..24u32)
        .map(|i| i.wrapping_mul(2_654_435_761) >> 7)
        .collect();
    let mut input = vec![vals.len() as u32];
    input.extend(&vals);
    // Reference results.
    let mut sorted = vals.clone();
    sorted.sort();
    let sum = sorted.iter().fold(0u32, |s, x| s.wrapping_add(*x));
    let mix = sorted.iter().fold(0x9e37_79b9u32, |c, x| {
        c.wrapping_mul(31).wrapping_add(x / 7 + x % 13)
    });
    let expected = vec![sorted[sorted.len() / 2], sum, mix, *sorted.last().unwrap()];

    let exec = run(&program, &input, MAX_CYCLES).unwrap();
    assert_eq!(exec.output, expected);
    println!("guest-arith: {} cycles", exec.steps.len());
    let st = Statement {
        program: program.clone(),
        exit_code: 0,
        output: expected.clone(),
        binding: [3; 32],
    };
    let traces = trace::build(&st, &exec);
    assert_eq!(
        check(&trace::tables(&st), &traces, &trace::public_values(&st)),
        vec![]
    );

    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(2);
    let (st, proof) = prove::prove(program, &input, [3; 32], &mut rng).unwrap();
    assert_eq!(st.output, expected);
    assert_eq!(prove::verify(&st, &proof), Ok(()));
    let mut forged = st.clone();
    forged.output[0] ^= 1;
    assert!(prove::verify(&forged, &proof).is_err());
}
