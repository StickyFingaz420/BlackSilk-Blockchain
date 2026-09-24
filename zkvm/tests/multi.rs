//! Several executions in one proof (zkvm.md §6.5): executions are isolated
//! (memory, code, outputs, syscalls), every part of the statement is bound,
//! and single-cell forgeries across the tagged buses are caught.

use blacksilk_zk::config::Val;
use blacksilk_zkvm::air::check::{check, MutationChecker};
use blacksilk_zkvm::air::trace::{self, Budget, Part, Statement};
use blacksilk_zkvm::air::{cpu, poseidon};
use blacksilk_zkvm::asm::{reg::*, Asm};
use blacksilk_zkvm::isa::Op;
use blacksilk_zkvm::{prove, run, Program, MAX_CYCLES};
use p3_field::PrimeCharacteristicRing;
use rand_chacha::rand_core::SeedableRng;
use std::sync::Arc;

const BASE: u32 = 0x1_0000;
const DATA: u32 = 0x10_0000;

/// Stores `tag` at DATA, hashes the buffer at DATA, and outputs DATA[0] and
/// the value it stored: with shared memory, the two executions would clobber
/// each other.
fn program(tag: u32) -> Arc<Program> {
    let mut p = Asm::new(BASE);
    p.data(DATA, vec![0; 64], 64);
    p.li(S0, DATA)
        .li(T0, tag)
        .store(Op::Sw, T0, S0, 4)
        .ecall(1)
        .store(Op::Sw, A0, S0, 8)
        .imm(Op::Addi, A0, S0, 0)
        .ecall(3)
        .load(Op::Lw, A1, S0, 0)
        .write_reg(A1)
        .ecall(1)
        .write_reg(A0)
        .halt(tag);
    Arc::new(p.finish().unwrap())
}

fn statement() -> (Statement, Vec<p3_matrix::dense::RowMajorMatrix<Val>>) {
    let (p0, p1, p2) = (program(5), program(6), program(7));
    let (i0, i1, i2) = ([10u32, 11], [20u32, 21], [30u32, 31]);
    let e0 = run(&p0, &i0, MAX_CYCLES).unwrap();
    let e1 = run(&p1, &i1, MAX_CYCLES).unwrap();
    let e2 = run(&p2, &i2, MAX_CYCLES).unwrap();
    let mut st = Statement::single(p0, e0.exit_code, e0.output.clone(), [9; 32]);
    for (p, e) in [(p1, &e1), (p2, &e2)] {
        st.others.push(Part {
            program: p,
            exit_code: e.exit_code,
            output: e.output.clone(),
            budget: None,
        });
    }
    let traces = trace::build_multi(&st, &[&e0, &e1, &e2]);
    (st, traces)
}

#[test]
fn executions_are_isolated_and_satisfy_the_constraints() {
    let (st, traces) = statement();
    // Each execution saw only its own memory: different stored words give
    // different digests, and each outputs its own second input.
    assert_ne!(st.output[0], st.others[0].output[0]);
    assert_ne!(st.others[0].output[0], st.others[1].output[0]);
    assert_eq!(st.output[1], 11);
    assert_eq!(st.others[1].output[1], 31);
    assert_eq!(
        (st.exit_code, st.others[0].exit_code, st.others[1].exit_code),
        (5, 6, 7)
    );
    let v = check(&trace::tables(&st), &traces, &trace::public_values(&st));
    assert!(v.is_empty(), "{v:?}");
}

#[test]
fn every_part_of_a_multi_execution_statement_is_bound() {
    let (st, traces) = statement();
    let mut wrong = Vec::new();
    // Outputs swapped between executions.
    let mut s = st.clone();
    std::mem::swap(&mut s.output, &mut s.others[0].output);
    wrong.push(s);
    // Programs swapped (the outputs then belong to the other program).
    let mut s = st.clone();
    std::mem::swap(&mut s.program, &mut s.others[1].program);
    wrong.push(s);
    // A different exit code of an extra execution.
    let mut s = st.clone();
    s.others[1].exit_code = 5;
    wrong.push(s);
    // A changed output word of an extra execution.
    let mut s = st.clone();
    s.others[0].output[1] ^= 1;
    wrong.push(s);
    for (i, bad) in wrong.iter().enumerate() {
        assert!(
            !check(&trace::tables(bad), &traces, &trace::public_values(bad)).is_empty(),
            "wrong statement {i} satisfied the constraints"
        );
    }
}

#[test]
fn every_single_cell_mutation_of_extra_executions_and_poseidon2_is_caught() {
    let (st, traces) = statement();
    let airs = trace::tables(&st);
    let public = trace::public_values(&st);
    let mut m = MutationChecker::new(&airs, &traces, &public);
    let mut accepted = Vec::new();
    let mut tried = 0;
    let mut targets = vec![(11usize, poseidon::WIDTH, None)];
    for e in 1..=2 {
        targets.push((Statement::cpu_table(e), cpu::WIDTH, Some(cpu::IS_REAL)));
    }
    for (t, w, real_col) in targets {
        let rows = traces[t].values.len() / w;
        for r in 0..rows {
            let real = match real_col {
                Some(c) => traces[t].values[r * w + c] == Val::ONE,
                None => r < 3, // the three Poseidon2 calls
            };
            if !real {
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
    accepted.dedup();
    assert!(accepted.is_empty(), "under-constrained cells: {accepted:?}");
    println!("{tried} mutations, all caught");
}

#[test]
fn three_executions_prove_and_verify_in_one_proof() {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(3);
    let (p0, p1) = (program(5), program(6));
    let t = std::time::Instant::now();
    let (st, proof) = prove::prove_multi(
        &[(p0.clone(), &[1, 2]), (p1.clone(), &[3, 4]), (p0, &[5, 6])],
        [4; 32],
        &mut rng,
    )
    .unwrap();
    println!(
        "3-execution proof: {} bytes, {:.1?}",
        blacksilk_zk::encode_proof(&proof).len(),
        t.elapsed()
    );
    assert_eq!(st.others.len(), 2);
    assert_eq!(prove::verify(&st, &proof), Ok(()));
    // Dropping, reordering or altering an execution is rejected.
    let mut s = st.clone();
    s.others.pop();
    assert!(prove::verify(&s, &proof).is_err());
    let mut s = st.clone();
    s.others.swap(0, 1);
    assert!(prove::verify(&s, &proof).is_err());
    let mut s = st.clone();
    s.others[1].output[1] = 7;
    assert!(prove::verify(&s, &proof).is_err());
    let mut s = st.clone();
    s.binding[0] ^= 1;
    assert!(prove::verify(&s, &proof).is_err());
}

/// Completeness at the limits: Plonky3's verifier rejects any proof whose
/// LogUp weight `Σ count_weight · height` reaches p (the bound that rules out
/// multiplicity wrap-around). The largest statement the verifier accepts —
/// the maximum number of executions, every table at its height limit — must
/// stay below it, or large honest proofs would be rejected.
#[test]
fn the_logup_multiplicity_bound_holds_for_the_largest_statement() {
    use blacksilk_zk::config::Challenge;
    use p3_field::PrimeField32;
    use p3_lookup::Lookups;
    let p = program(1);
    let mut st = Statement::single(p.clone(), 0, vec![], [0; 32]);
    for _ in 1..trace::MAX_EXECUTIONS {
        st.others.push(Part {
            program: p.clone(),
            exit_code: 0,
            output: vec![],
            budget: None,
        });
    }
    let tables = trace::tables(&st);
    let limits = prove::limits(&tables);
    let mut sum: u128 = 0;
    for (t, &log_h) in tables.iter().zip(&limits) {
        let w = Lookups::<Val>::from_air::<Challenge, _>(t).total_count_weight() as u128;
        sum += w << log_h;
    }
    let order = Val::ORDER_U32 as u128;
    println!(
        "LogUp weight at the limits: {sum} = {:.2}% of p",
        100.0 * sum as f64 / order as f64
    );
    assert!(sum < order, "weight {sum} ≥ p");
}

/// A program whose work depends on a secret: it loops `n` times (n read from
/// the private input), hashing each round.
fn secret_loop() -> Arc<Program> {
    let mut p = Asm::new(BASE);
    p.data(DATA, vec![0; 64], 64);
    p.ecall(1)
        .imm(Op::Addi, S1, A0, 0)
        .li(S0, DATA)
        .label("loop")
        .branch(Op::Beq, S1, ZERO, "done")
        .imm(Op::Addi, A0, S0, 0)
        .ecall(3)
        .imm(Op::Addi, S1, S1, -1)
        .jal(ZERO, "loop")
        .label("done")
        .load(Op::Lw, A1, S0, 0)
        .write_reg(A1)
        .halt(0);
    Arc::new(p.finish().unwrap())
}

const LOOP_BUDGET: Budget = Budget {
    cycles: 1_000,
    keys: 200,
    add: 300,
    bit: 64,
    lt: 300,
    shift: 64,
    mul: 64,
    poseidon: 100,
};

/// With a budget, the proof's shape (every table height) is the same
/// whether the secret loop runs once or 90 times: the heights reveal nothing
/// about the secret. Without one, they differ.
#[test]
fn a_budget_fixes_the_shape_whatever_the_secret() {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(8);
    let p = secret_loop();
    let mut shapes = Vec::new();
    for n in [1u32, 90] {
        let (st, proof) = prove::prove_shaped(
            &[(p.clone(), &[n])],
            Some(&[LOOP_BUDGET]),
            [1; 32],
            &mut rng,
        )
        .unwrap();
        assert_eq!(prove::verify(&st, &proof), Ok(()));
        shapes.push(proof.degree_bits.clone());
    }
    assert_eq!(
        shapes[0], shapes[1],
        "budgeted shapes must not depend on the secret"
    );
    // Unbudgeted, the same two runs have different shapes (the leak budgets close).
    let (_, a) = prove::prove_multi(&[(p.clone(), &[1])], [1; 32], &mut rng).unwrap();
    let (_, b) = prove::prove_multi(&[(p.clone(), &[90])], [1; 32], &mut rng).unwrap();
    assert_ne!(a.degree_bits, b.degree_bits);
}

/// An execution beyond its budget cannot be proven; a proof of another shape
/// does not verify against a budgeted statement.
#[test]
fn budgets_are_enforced_by_prover_and_verifier() {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(9);
    let p = secret_loop();
    // 200 rounds need more rows than the budget allows.
    assert!(matches!(
        prove::prove_shaped(
            &[(p.clone(), &[200])],
            Some(&[LOOP_BUDGET]),
            [1; 32],
            &mut rng
        ),
        Err(prove::ProveError::BudgetExceeded(_))
    ));
    // An unbudgeted proof (execution-sized tables) is rejected for the
    // budgeted statement.
    let (st_free, free) = prove::prove_multi(&[(p.clone(), &[3])], [1; 32], &mut rng).unwrap();
    let mut st_budget = st_free.clone();
    st_budget.budget = Some(LOOP_BUDGET);
    assert!(prove::verify(&st_budget, &free).is_err());
    let (st_b, bud) = prove::prove_shaped(
        &[(p.clone(), &[3])],
        Some(&[LOOP_BUDGET]),
        [1; 32],
        &mut rng,
    )
    .unwrap();
    assert_eq!(prove::verify(&st_b, &bud), Ok(()));
    // A statement without budgets accepts any valid shape, including this
    // padded one; PX statements always carry budgets (px::prove).
    let mut st_unbudgeted = st_b.clone();
    st_unbudgeted.budget = None;
    assert_eq!(prove::verify(&st_unbudgeted, &bud), Ok(()));
    // A different registered budget changes the shape: rejected.
    let mut other = st_b.clone();
    other.budget = Some(Budget {
        cycles: 5_000,
        ..LOOP_BUDGET
    });
    assert!(prove::verify(&other, &bud).is_err());
}
