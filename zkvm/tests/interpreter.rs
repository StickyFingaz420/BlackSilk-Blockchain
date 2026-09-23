//! Reference interpreter tests (docs/zkvm.md §9 item 1, item 4).

use blacksilk_zkvm::asm::{reg::*, Asm};
use blacksilk_zkvm::exec::{Space, Step};
use blacksilk_zkvm::isa::Op;
use blacksilk_zkvm::{run, Execution, Program, ProgramError, Segment, Syscall, TrapKind};
use blacksilk_zkvm::{MAX_CYCLES, NULL_GUARD, STACK_TOP};
use std::collections::HashMap;

const BASE: u32 = 0x1_0000;
const DATA: u32 = 0x10_0000;

fn exec(asm: &Asm, input: &[u32]) -> Execution {
    run(&asm.finish().expect("valid program"), input, MAX_CYCLES).expect("halts")
}

fn trap_of(asm: &Asm, input: &[u32]) -> TrapKind {
    run(&asm.finish().expect("valid program"), input, MAX_CYCLES)
        .expect_err("must trap")
        .kind
}

/// Runs `op rd=a0, t0, t1` with t0 = a, t1 = b and returns a0.
fn binop(op: Op, a: u32, b: u32) -> u32 {
    let mut p = Asm::new(BASE);
    p.li(T0, a)
        .li(T1, b)
        .r(op, A1, T0, T1)
        .write_reg(A1)
        .halt(0);
    exec(&p, &[]).output[0]
}

fn immop(op: Op, a: u32, imm: i32) -> u32 {
    let mut p = Asm::new(BASE);
    p.li(T0, a).imm(op, A1, T0, imm).write_reg(A1).halt(0);
    exec(&p, &[]).output[0]
}

/// Independent reference semantics (RISC-V spec, written with i128/i64 math).
fn reference(op: Op, a: u32, b: u32) -> u32 {
    let (sa, sb) = (a as i32 as i128, b as i32 as i128);
    let (ua, ub) = (a as u128, b as u128);
    match op {
        Op::Add => (ua + ub) as u32,
        Op::Sub => (ua.wrapping_sub(ub)) as u32,
        Op::Sll => ((ua << (b & 31)) & 0xffff_ffff) as u32,
        Op::Srl => (ua >> (b & 31)) as u32,
        Op::Sra => (sa >> (b & 31)) as u32,
        Op::Slt => (sa < sb) as u32,
        Op::Sltu => (ua < ub) as u32,
        Op::Xor => a ^ b,
        Op::Or => a | b,
        Op::And => a & b,
        Op::Mul => (sa * sb) as u32,
        Op::Mulh => ((sa * sb) >> 32) as u32,
        Op::Mulhsu => ((sa * ub as i128) >> 32) as u32,
        Op::Mulhu => ((ua * ub) >> 32) as u32,
        _ => unreachable!(),
    }
}

const EDGE: [u32; 12] = [
    0,
    1,
    2,
    3,
    31,
    32,
    0x7fff_ffff,
    0x8000_0000,
    0x8000_0001,
    0xffff_fffe,
    0xffff_ffff,
    0x1234_5678,
];

#[test]
fn register_ops_match_the_reference_on_edge_values() {
    let ops = [
        Op::Add,
        Op::Sub,
        Op::Sll,
        Op::Srl,
        Op::Sra,
        Op::Slt,
        Op::Sltu,
        Op::Xor,
        Op::Or,
        Op::And,
        Op::Mul,
        Op::Mulh,
        Op::Mulhsu,
        Op::Mulhu,
    ];
    // All edge pairs in one program per op (much faster than one run per pair).
    for op in ops {
        let mut p = Asm::new(BASE);
        for a in EDGE {
            for b in EDGE {
                p.li(T0, a).li(T1, b).r(op, A1, T0, T1).write_reg(A1);
            }
        }
        p.halt(0);
        let out = exec(&p, &[]).output;
        let mut k = 0;
        for a in EDGE {
            for b in EDGE {
                assert_eq!(out[k], reference(op, a, b), "{op:?} {a:#x} {b:#x}");
                k += 1;
            }
        }
    }
}

#[test]
fn hardware_division_is_not_part_of_bvm1() {
    // DIV/DIVU/REM/REMU (funct7 = 1, funct3 = 4..7) are rejected when loading.
    for f3 in 4u32..8 {
        let div = (1 << 25) | (2 << 20) | (1 << 15) | (f3 << 12) | (3 << 7) | 0b0110011;
        assert!(
            Program::new(BASE, BASE, vec![div], vec![]).is_err(),
            "funct3 {f3}"
        );
    }
}

#[test]
fn immediate_ops_and_shift_amounts() {
    assert_eq!(immop(Op::Addi, 5, -6), u32::MAX);
    assert_eq!(immop(Op::Slti, (-1i32) as u32, 0), 1);
    assert_eq!(
        immop(Op::Sltiu, 1, -1),
        1,
        "the immediate is sign-extended, then compared unsigned"
    );
    assert_eq!(immop(Op::Xori, 0xff, -1), !0xffu32);
    assert_eq!(immop(Op::Andi, 0xffff_ffff, 0x7ff), 0x7ff);
    assert_eq!(immop(Op::Slli, 1, 31), 0x8000_0000);
    assert_eq!(immop(Op::Srai, 0x8000_0000, 31), u32::MAX);
    assert_eq!(immop(Op::Srli, 0x8000_0000, 31), 1);
    // Register shifts use only the low 5 bits.
    assert_eq!(binop(Op::Sll, 1, 33), 2);
    assert_eq!(binop(Op::Srl, 4, 0xffff_ffe1), 2);
}

#[test]
fn x0_is_always_zero() {
    let mut p = Asm::new(BASE);
    p.li(T0, 99)
        .r(Op::Add, ZERO, T0, T0)
        .imm(Op::Addi, ZERO, ZERO, 5)
        .write_reg(ZERO)
        .halt(0);
    let e = exec(&p, &[]);
    assert_eq!(e.output, vec![0]);
    assert!(
        e.accesses
            .iter()
            .all(|a| !(a.space == Space::Reg && a.addr == 0 && a.value != 0)),
        "x0 never holds a non-zero value"
    );
}

#[test]
fn loads_and_stores_with_sign_extension() {
    let mut p = Asm::new(BASE);
    p.li(S0, DATA)
        .li(T0, 0x8081_82f3)
        .store(Op::Sw, T0, S0, 0)
        .load(Op::Lb, A1, S0, 0)
        .write_reg(A1) // 0xf3 → -13
        .load(Op::Lbu, A1, S0, 0)
        .write_reg(A1) // 0xf3
        .load(Op::Lh, A1, S0, 2)
        .write_reg(A1) // 0x8081 → sign-extended
        .load(Op::Lhu, A1, S0, 2)
        .write_reg(A1)
        .load(Op::Lw, A1, S0, 0)
        .write_reg(A1)
        .li(T1, 0xaa)
        .store(Op::Sb, T1, S0, 1) // byte 1 only
        .load(Op::Lw, A1, S0, 0)
        .write_reg(A1)
        .li(T1, 0x1234)
        .store(Op::Sh, T1, S0, 2)
        .load(Op::Lw, A1, S0, 0)
        .write_reg(A1)
        .halt(0);
    let e = exec(&p, &[]);
    assert_eq!(
        e.output,
        vec![
            0xffff_fff3,
            0xf3,
            0xffff_8081,
            0x8081,
            0x8081_82f3,
            0x8081_aaf3,
            0x1234_aaf3
        ]
    );
}

#[test]
fn initial_data_and_bss_are_visible() {
    let mut p = Asm::new(BASE);
    p.data(DATA, vec![1, 2, 3, 4, 5], 64);
    p.li(S0, DATA)
        .load(Op::Lw, A1, S0, 0)
        .write_reg(A1)
        .load(Op::Lbu, A1, S0, 4)
        .write_reg(A1)
        .load(Op::Lw, A1, S0, 60)
        .write_reg(A1) // bss
        .halt(0);
    assert_eq!(exec(&p, &[]).output, vec![0x0403_0201, 5, 0]);
}

#[test]
fn branches_jumps_and_a_loop() {
    // sum = 1 + 2 + ... + 100 with a backward branch; call/return with JAL/JALR.
    let mut p = Asm::new(BASE);
    p.li(T0, 0)
        .li(T1, 1)
        .li(T2, 101)
        .label("loop")
        .r(Op::Add, T0, T0, T1)
        .imm(Op::Addi, T1, T1, 1)
        .branch(Op::Bne, T1, T2, "loop")
        .write_reg(T0)
        .jal(RA, "double")
        .write_reg(A0)
        .halt(0)
        .label("double")
        .r(Op::Add, A0, T0, T0)
        .imm(Op::Jalr, ZERO, RA, 0);
    assert_eq!(exec(&p, &[]).output, vec![5050, 10100]);
    // Signed vs unsigned branches.
    let mut p = Asm::new(BASE);
    p.li(T0, u32::MAX)
        .li(T1, 1)
        .branch(Op::Blt, T0, T1, "signed_less")
        .halt(1)
        .label("signed_less")
        .branch(Op::Bltu, T0, T1, "wrong")
        .branch(Op::Bgeu, T0, T1, "ok")
        .label("wrong")
        .halt(2)
        .label("ok")
        .halt(0);
    assert_eq!(exec(&p, &[]).exit_code, 0);
}

#[test]
fn auipc_lui_and_jalr_low_bit() {
    let mut p = Asm::new(BASE);
    p.i(Op::Auipc, A1, 0, 0, 0x2000)
        .write_reg(A1)
        .i(Op::Lui, A1, 0, 0, 0x7fff_f000u32 as i32)
        .write_reg(A1)
        // JALR clears bit 0 of the target.
        .li(T0, BASE + 4 * 20 + 1)
        .imm(Op::Jalr, ZERO, T0, 0);
    while p.finish().unwrap().code.len() < 20 {
        p.halt(9);
    }
    p.halt(0);
    let e = exec(&p, &[]);
    assert_eq!(e.output, vec![BASE + 0x2000, 0x7fff_f000]);
    assert_eq!(e.exit_code, 0);
}

#[test]
fn syscalls_read_write_halt() {
    let mut p = Asm::new(BASE);
    p.ecall(1)
        .imm(Op::Addi, S0, A0, 0)
        .ecall(1)
        .r(Op::Add, S0, S0, A0)
        .write_reg(S0)
        .halt(42);
    let e = exec(&p, &[40, 2]);
    assert_eq!(e.output, vec![42]);
    assert_eq!(e.exit_code, 42);
    assert!(matches!(
        e.steps.last().unwrap().syscall,
        Some(Syscall::Halt { code: 42 })
    ));
    // Input exhaustion and unknown syscalls trap.
    assert_eq!(trap_of(&p, &[40]), TrapKind::InputExhausted);
    let mut q = Asm::new(BASE);
    q.ecall(99);
    assert_eq!(trap_of(&q, &[]), TrapKind::UnknownSyscall(99));
}

#[test]
fn poseidon2_syscall_permutes_in_place() {
    use p3_field::{PrimeCharacteristicRing, PrimeField32};
    use p3_symmetric::Permutation;
    let mut p = Asm::new(BASE);
    p.li(S0, DATA);
    for k in 0..16u32 {
        p.li(T0, k * 1000 + 7).store(Op::Sw, T0, S0, 4 * k as i32);
    }
    p.imm(Op::Addi, A0, S0, 0).ecall(3);
    for k in 0..16 {
        p.load(Op::Lw, A1, S0, 4 * k).write_reg(A1);
    }
    p.halt(0);
    let out = exec(&p, &[]).output;
    let mut state: [p3_baby_bear::BabyBear; 16] =
        core::array::from_fn(|k| p3_baby_bear::BabyBear::from_u32(k as u32 * 1000 + 7));
    blacksilk_zk::config::permutation().permute_mut(&mut state);
    let expected: Vec<u32> = state.iter().map(|x| x.as_canonical_u32()).collect();
    assert_eq!(out, expected);

    // A non-canonical element (≥ p) traps.
    let mut q = Asm::new(BASE);
    q.li(S0, DATA)
        .li(T0, p3_baby_bear::BabyBear::ORDER_U32)
        .store(Op::Sw, T0, S0, 0)
        .imm(Op::Addi, A0, S0, 0)
        .ecall(3);
    assert_eq!(trap_of(&q, &[]), TrapKind::NonCanonicalField);
    // A buffer overlapping the code segment traps.
    let mut q = Asm::new(BASE);
    q.li(A0, BASE - 32).ecall(3);
    assert_eq!(trap_of(&q, &[]), TrapKind::StoreBelowCodeEnd);
}

#[test]
fn memory_traps() {
    type Case = (Box<dyn Fn(&mut Asm)>, TrapKind);
    let cases: Vec<Case> = vec![
        (
            Box::new(|p| {
                p.li(S0, DATA + 1).load(Op::Lw, A1, S0, 0);
            }),
            TrapKind::MisalignedAccess,
        ),
        (
            Box::new(|p| {
                p.li(S0, DATA + 1).load(Op::Lh, A1, S0, 0);
            }),
            TrapKind::MisalignedAccess,
        ),
        (
            Box::new(|p| {
                p.li(S0, DATA + 2).store(Op::Sw, A1, S0, 0);
            }),
            TrapKind::MisalignedAccess,
        ),
        (
            Box::new(|p| {
                p.li(S0, 0).load(Op::Lw, A1, S0, 0);
            }),
            TrapKind::NullGuard,
        ),
        (
            Box::new(|p| {
                p.li(S0, NULL_GUARD - 4).store(Op::Sw, A1, S0, 0);
            }),
            TrapKind::NullGuard,
        ),
        (
            Box::new(|p| {
                p.li(S0, 1 << 28).load(Op::Lw, A1, S0, 0);
            }),
            TrapKind::AccessOutOfRange,
        ),
        (
            Box::new(|p| {
                p.li(S0, u32::MAX - 3).load(Op::Lw, A1, S0, 0);
            }),
            TrapKind::AccessOutOfRange,
        ),
        (
            Box::new(|p| {
                p.li(S0, BASE).store(Op::Sw, A1, S0, 0);
            }),
            TrapKind::StoreBelowCodeEnd,
        ),
        (
            Box::new(|p| {
                p.li(S0, BASE + 3).store(Op::Sb, A1, S0, 0);
            }),
            TrapKind::StoreBelowCodeEnd,
        ),
    ];
    for (i, (build, kind)) in cases.into_iter().enumerate() {
        let mut p = Asm::new(BASE);
        build(&mut p);
        p.halt(0);
        assert_eq!(trap_of(&p, &[]), kind, "case {i}");
    }
}

#[test]
fn code_is_readable_and_stores_below_the_code_end_trap() {
    // Loads from the code segment return the instruction words (RISC-V semantics).
    let mut p = Asm::new(BASE);
    p.li(S0, BASE).load(Op::Lw, A1, S0, 0).write_reg(A1).halt(0);
    let prog = p.finish().unwrap();
    let e = run(&prog, &[], MAX_CYCLES).unwrap();
    assert_eq!(e.output, vec![prog.code[0]]);
    // A read-only segment below the code: loads work, stores trap.
    let mut p = Asm::new(BASE);
    p.data(0x8000, vec![7, 0, 0, 0], 4);
    p.li(S0, 0x8000)
        .load(Op::Lw, A1, S0, 0)
        .write_reg(A1)
        .halt(0);
    assert_eq!(exec(&p, &[]).output, vec![7]);
    let mut p = Asm::new(BASE);
    p.data(0x8000, vec![7, 0, 0, 0], 4);
    p.li(S0, 0x8000).store(Op::Sw, A1, S0, 0).halt(0);
    assert_eq!(trap_of(&p, &[]), TrapKind::StoreBelowCodeEnd);
}

#[test]
fn control_leaving_the_code_traps() {
    let mut p = Asm::new(BASE);
    p.li(T0, BASE - 4).imm(Op::Jalr, ZERO, T0, 0);
    assert_eq!(trap_of(&p, &[]), TrapKind::PcOutOfCode);
    let mut p = Asm::new(BASE);
    p.li(T0, BASE + 2).imm(Op::Jalr, ZERO, T0, 0).halt(0);
    assert_eq!(trap_of(&p, &[]), TrapKind::PcOutOfCode, "misaligned target");
    // Falling off the end of the code.
    let mut p = Asm::new(BASE);
    p.li(T0, 1);
    assert_eq!(trap_of(&p, &[]), TrapKind::PcOutOfCode);
}

#[test]
fn infinite_loops_hit_the_cycle_limit() {
    let mut p = Asm::new(BASE);
    p.label("spin").jal(ZERO, "spin");
    let prog = p.finish().unwrap();
    assert_eq!(
        run(&prog, &[], 1000).unwrap_err().kind,
        TrapKind::CycleLimit
    );
}

#[test]
fn invalid_instructions_are_rejected_at_load_time() {
    for bad in [0x0010_0073u32, 0x0000_4501, 0x3000_2073] {
        assert!(matches!(
            Program::new(BASE, BASE, vec![0x0000_0013, bad], vec![]),
            Err(ProgramError::InvalidInstruction { pc, .. }) if pc == BASE + 4
        ));
    }
}

#[test]
fn layout_rules() {
    let nop = vec![0x0000_0013u32, 0x0000_0073];
    assert!(Program::new(BASE, BASE, nop.clone(), vec![]).is_ok());
    assert!(
        Program::new(BASE + 2, BASE, nop.clone(), vec![]).is_err(),
        "misaligned entry"
    );
    assert!(
        Program::new(BASE + 8, BASE, nop.clone(), vec![]).is_err(),
        "entry outside code"
    );
    assert!(
        Program::new(0, 0, nop.clone(), vec![]).is_err(),
        "code in the null guard"
    );
    assert!(
        Program::new(STACK_TOP - 8, STACK_TOP - 8, nop.clone(), vec![]).is_err(),
        "code in the stack"
    );
    let seg = |base, len: usize, mem| Segment {
        base,
        bytes: vec![0; len],
        mem_size: mem,
    };
    assert!(
        Program::new(BASE, BASE, nop.clone(), vec![seg(BASE + 4, 4, 4)]).is_err(),
        "data overlaps code"
    );
    assert!(
        Program::new(BASE, BASE, nop.clone(), vec![seg(DATA, 8, 4)]).is_err(),
        "mem_size < file size"
    );
    assert!(
        Program::new(
            BASE,
            BASE,
            nop.clone(),
            vec![seg(DATA, 4, 8), seg(DATA + 4, 4, 4)]
        )
        .is_err(),
        "overlapping data"
    );
    assert!(
        Program::new(BASE, BASE, nop, vec![seg(DATA, 4, 4); 5]).is_err(),
        "too many segments"
    );
}

#[test]
fn executions_are_deterministic_and_the_access_log_is_consistent() {
    let mut p = Asm::new(BASE);
    p.data(DATA, vec![9; 16], 4096);
    p.li(S0, DATA)
        .li(T2, 50)
        .label("loop")
        .load(Op::Lw, T0, S0, 0)
        .r(Op::Add, T0, T0, T2)
        .store(Op::Sw, T0, S0, 4)
        .store(Op::Sb, T2, S0, 1)
        .imm(Op::Addi, T2, T2, -1)
        .branch(Op::Bne, T2, ZERO, "loop")
        .ecall(1)
        .write_reg(A0)
        .halt(0);
    let a = exec(&p, &[123]);
    let b = exec(&p, &[123]);
    assert_eq!(a, b);

    // Offline memory argument invariants (zkvm.md §6.3): per address, each
    // access reads the previous access's value at a strictly larger timestamp,
    // and the first access reads the initial value.
    let init: HashMap<u32, u32> = a.mem_init.iter().copied().collect();
    let mut last: HashMap<(Space, u32), (u32, u32)> = HashMap::new();
    for acc in &a.accesses {
        let key = (acc.space, acc.addr);
        match last.get(&key) {
            Some(&(v, t)) => {
                assert_eq!(acc.prev_value, v);
                assert_eq!(acc.prev_ts, t);
                assert!(acc.ts > t);
            }
            None => {
                assert_eq!(acc.prev_ts, 0);
                let expected = match acc.space {
                    Space::Mem => init[&acc.addr],
                    Space::Reg => {
                        if acc.addr == 2 {
                            STACK_TOP
                        } else {
                            0
                        }
                    }
                };
                assert_eq!(acc.prev_value, expected, "{acc:?}");
            }
        }
        if acc.space == Space::Reg && acc.addr == 0 {
            assert_eq!(acc.value, 0);
        }
        last.insert(key, (acc.value, acc.ts));
    }
    // Every step reads exactly two registers.
    let per_clk = a
        .accesses
        .iter()
        .filter(|x| x.space == Space::Reg && x.ts % 4 < 2)
        .count();
    assert_eq!(per_clk, 2 * a.steps.len());
    let _: &Step = &a.steps[0];
}
