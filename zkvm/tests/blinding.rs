//! Terminal blinding (finding ZK-F29, docs/reviews/terminal-blinding.md).
//!
//! 1. **The leak and its fix, end to end.** An observer replays the
//!    verifier's transcript and computes the Program-table terminal that each
//!    hypothesis about the private input would produce.
//!    - Against an *unblinded* proof it identifies the input.
//!    - Against a blinded proof it cannot. Moreover, for **every** hypothesis
//!      there are blinding values that reproduce the published terminal
//!      exactly; the test constructs them.
//! 2. **Soundness of the blinding bus.** Missing, duplicated, altered or
//!    extra blinding messages, selector abuse, and attempts to stand in for
//!    a message of another bus are all rejected.
//! 3. **Randomness.** The blinding values are fresh, uniform-looking and
//!    keep the bus balanced.

use blacksilk_zk::analysis::Observer;
use blacksilk_zk::config::{Challenge, ProverConfig, Val, VerifierConfig};
use blacksilk_zkvm::air::check::check;
use blacksilk_zkvm::air::trace::{self, Statement};
use blacksilk_zkvm::air::util::{BLIND_VALUES, BLIND_WIDTH};
use blacksilk_zkvm::air::Table;
use blacksilk_zkvm::asm::{reg::*, Asm};
use blacksilk_zkvm::isa::Op;
use blacksilk_zkvm::program::Program;
use blacksilk_zkvm::prove::{self, limits, statement_digest};
use blacksilk_zkvm::{run, MAX_CYCLES};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::Arc;

const BASE: u32 = 0x1_0000;
/// The Program table's index in `trace::tables` order.
const PROGRAM: usize = 1;

/// Reads a private word; loops 3 times if it is 0, else 7 times; outputs a
/// constant. The public statement is identical for both inputs; only the
/// execution counts (the Program table's multiplicities) differ.
fn branching() -> Arc<Program> {
    let mut p = Asm::new(BASE);
    p.ecall(1) // A0 = input
        .li(T0, 0)
        .li(T1, 3)
        .branch(Op::Beq, A0, ZERO, "loop")
        .li(T1, 7)
        .label("loop")
        .imm(Op::Addi, T0, T0, 1)
        .branch(Op::Blt, T0, T1, "loop")
        .li(A1, 42)
        .write_reg(A1)
        .halt(0);
    Arc::new(p.finish().unwrap())
}

fn statement_and_traces(prog: &Arc<Program>, input: u32) -> (Statement, Vec<RowMajorMatrix<Val>>) {
    let exec = run(prog, &[input], MAX_CYCLES).unwrap();
    let st = Statement::single(prog.clone(), exec.exit_code, exec.output.clone(), [9; 32]);
    let traces = trace::build(&st, &exec);
    (st, traces)
}

/// Proves `traces` exactly as `prove::prove_shaped` does, but **without**
/// randomizing the blinding values (the pre-fix behaviour).
fn prove_unblinded(st: &Statement, traces: &[RowMajorMatrix<Val>]) -> blacksilk_zk::Proof {
    let airs = trace::tables(st);
    let mut rng = ChaCha20Rng::seed_from_u64(3);
    let cfg = ProverConfig::for_statement(&statement_digest(&airs), &[7; 32], &mut rng);
    blacksilk_zk::prove(
        &cfg,
        &airs,
        traces,
        &trace::public_values(st),
        &limits(&airs),
    )
    .unwrap()
}

/// Sets table `t`'s first-row blinding values.
fn with_values(m: &RowMajorMatrix<Val>, v: &[Val; BLIND_VALUES]) -> RowMajorMatrix<Val> {
    let mut m = m.clone();
    let w = m.width;
    m.values[w - BLIND_VALUES..w].copy_from_slice(v);
    m
}

/// Solves `Σ_j r_j · basis_j = target` over the base field, where `basis_j`
/// are extension elements viewed as vectors of coordinates.
fn solve(basis: &[Challenge; BLIND_VALUES], target: Challenge) -> Option<[Val; BLIND_VALUES]> {
    let n = BLIND_VALUES;
    // Augmented matrix: row i = coordinate i.
    let mut a: Vec<Vec<Val>> = (0..n)
        .map(|i| {
            let mut row: Vec<Val> = basis
                .iter()
                .map(|b| b.as_basis_coefficients_slice()[i])
                .collect();
            row.push(target.as_basis_coefficients_slice()[i]);
            row
        })
        .collect();
    for col in 0..n {
        let pivot = (col..n).find(|&r| a[r][col] != Val::ZERO)?;
        a.swap(col, pivot);
        let inv = a[col][col].inverse();
        for x in a[col].iter_mut() {
            *x *= inv;
        }
        for r in 0..n {
            if r != col && a[r][col] != Val::ZERO {
                let f = a[r][col];
                let pivot_row = a[col].clone();
                for (x, p) in a[r].iter_mut().zip(pivot_row) {
                    *x -= f * p;
                }
            }
        }
    }
    let mut out = [Val::ZERO; BLIND_VALUES];
    for (i, o) in out.iter_mut().enumerate() {
        *o = a[i][n];
    }
    Some(out)
}

/// For the Program table: the blinding values under which `hypothesis` (a
/// zero-blinded Program trace) produces exactly `published`, if any.
fn explain(
    obs: &Observer,
    air: &Table,
    hypothesis: &RowMajorMatrix<Val>,
    published: Challenge,
) -> Option<[Val; BLIND_VALUES]> {
    explain_table(obs, PROGRAM, air, hypothesis, &[], published)
}

/// As [`explain`], for table `t` with public values `pv`. Because the
/// fingerprint map is a bijection, blinding values reproducing `published`
/// **always** exist (review round 2, T1): this recovers them, it is not a
/// test of hiding. Used to check which values a real proof used.
fn explain_table(
    obs: &Observer,
    t: usize,
    air: &Table,
    hypothesis: &RowMajorMatrix<Val>,
    pv: &[Val],
    published: Challenge,
) -> Option<[Val; BLIND_VALUES]> {
    let ch = &obs.challenges[t];
    // The blinding lookup is the table's last: its (bus offset, combiner).
    let (prefix, beta) = (ch[ch.len() - 2], ch[ch.len() - 1]);
    let t0 = obs.terminal(t, air, hypothesis, pv).unwrap();
    // fp(r) = Σ_j r_j β^(7−j) (Horner, the last element on β^0); the first
    // row consumes once, contributing σ/(prefix − fp(r)). Find σ from the
    // gadget itself with a probe.
    let probe = [Val::ONE; BLIND_VALUES];
    let t_probe = obs
        .terminal(t, air, &with_values(hypothesis, &probe), pv)
        .unwrap();
    let fp = |r: &[Val; BLIND_VALUES]| -> Challenge {
        r.iter()
            .enumerate()
            .map(|(j, v)| beta.exp_u64((BLIND_VALUES - 1 - j) as u64) * Challenge::from(*v))
            .sum()
    };
    let contrib = |r: &[Val; BLIND_VALUES]| (prefix - fp(r)).inverse();
    let sigma = if t_probe - t0 == contrib(&probe) - contrib(&[Val::ZERO; BLIND_VALUES]) {
        Challenge::ONE
    } else {
        assert_eq!(
            t_probe - t0,
            contrib(&[Val::ZERO; BLIND_VALUES]) - contrib(&probe),
            "the blinding contribution has the expected form"
        );
        -Challenge::ONE
    };
    // published = t0 − σ·contrib(0) + σ·contrib(r)  ⇒  solve for fp(r).
    let d = (published - t0) * sigma + contrib(&[Val::ZERO; BLIND_VALUES]);
    let target = prefix - d.inverse();
    let basis: [Challenge; BLIND_VALUES] =
        std::array::from_fn(|j| beta.exp_u64((BLIND_VALUES - 1 - j) as u64));
    let r = solve(&basis, target)?;
    // Check it end to end with the gadget.
    let got = obs.terminal(t, air, &with_values(hypothesis, &r), pv)?;
    (got == published).then_some(r)
}

#[test]
fn an_observer_reads_the_input_from_an_unblinded_proof() {
    let prog = branching();
    let (st, traces) = statement_and_traces(&prog, 0);
    let (_, alt) = statement_and_traces(&prog, 1);
    let airs = trace::tables(&st);
    let public = trace::public_values(&st);
    let proof = prove_unblinded(&st, &traces);
    let obs = Observer::new(
        &VerifierConfig::for_statement(&statement_digest(&airs)),
        &airs,
        &proof,
        &public,
    );
    // The observer reproduces every published terminal from the true
    // traces: the transcript replay is exact.
    for (i, air) in airs.iter().enumerate() {
        assert_eq!(
            obs.terminal(i, air, &traces[i], &public[i]),
            proof.lookup_terminals[i].as_ref().map(|t| t.0),
            "table {i}"
        );
    }
    // And it tells the inputs apart from the Program table alone.
    let published = proof.lookup_terminals[PROGRAM].as_ref().unwrap().0;
    let h0 = obs
        .terminal(PROGRAM, &airs[PROGRAM], &traces[PROGRAM], &[])
        .unwrap();
    let h1 = obs
        .terminal(PROGRAM, &airs[PROGRAM], &alt[PROGRAM], &[])
        .unwrap();
    assert_eq!(published, h0, "input 0 matches");
    assert_ne!(published, h1, "input 1 is rejected: the leak");
}

/// On a blinded proof the observer's direct test matches no hypothesis. The
/// second half (blinding values explaining each hypothesis) always succeeds
/// by the bijection argument, blinded or not (review round 2, T1): it checks
/// the algebra, and is **not** evidence of hiding. Hiding rests on the
/// argument in terminal-blinding.md §3 and on the randomness checks below.
#[test]
fn a_blinded_proof_matches_no_hypothesis_directly() {
    let prog = branching();
    let mut rng = ChaCha20Rng::seed_from_u64(11);
    let (st, proof) = prove::prove(prog.clone(), &[0], [9; 32], &mut rng).unwrap();
    assert!(prove::verify(&st, &proof).is_ok());
    let airs = trace::tables(&st);
    let public = trace::public_values(&st);
    let obs = Observer::new(
        &VerifierConfig::for_statement(&statement_digest(&airs)),
        &airs,
        &proof,
        &public,
    );
    let published = proof.lookup_terminals[PROGRAM].as_ref().unwrap().0;
    let (_, h0) = statement_and_traces(&prog, 0); // the truth
    let (_, h1) = statement_and_traces(&prog, 1);
    // The direct test no longer matches either hypothesis ...
    for h in [&h0, &h1] {
        let t = obs
            .terminal(PROGRAM, &airs[PROGRAM], &h[PROGRAM], &[])
            .unwrap();
        assert_ne!(t, published);
    }
    // ... and each hypothesis explains the published terminal exactly, with
    // some blinding values: the terminal does not favour either.
    for (name, h) in [("input 0", &h0), ("input 1", &h1)] {
        let r = explain(&obs, &airs[PROGRAM], &h[PROGRAM], published);
        assert!(
            r.is_some(),
            "{name}: no blinding values explain the terminal"
        );
    }
}

#[test]
fn the_same_input_proven_twice_publishes_unrelated_program_terminals() {
    // Different proofs of the same witness: the published terminals are
    // explained by different blinding values (fresh randomness per proof).
    let prog = branching();
    let (_, truth) = statement_and_traces(&prog, 0);
    let mut seen = Vec::new();
    for seed in [21u64, 22] {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let (st, proof) = prove::prove(prog.clone(), &[0], [9; 32], &mut rng).unwrap();
        let airs = trace::tables(&st);
        let public = trace::public_values(&st);
        let obs = Observer::new(
            &VerifierConfig::for_statement(&statement_digest(&airs)),
            &airs,
            &proof,
            &public,
        );
        let published = proof.lookup_terminals[PROGRAM].as_ref().unwrap().0;
        let r = explain(&obs, &airs[PROGRAM], &truth[PROGRAM], published).unwrap();
        assert!(r.iter().any(|v| *v != Val::ZERO));
        seen.push(r);
    }
    assert_ne!(seen[0], seen[1]);
}

// ---- soundness of the blinding bus (constraint oracle) ----

fn honest() -> (Vec<Table>, Vec<RowMajorMatrix<Val>>, Vec<Vec<Val>>) {
    let prog = branching();
    let (st, mut traces) = statement_and_traces(&prog, 1);
    trace::randomize_blinding(&mut traces, &mut ChaCha20Rng::seed_from_u64(5));
    let airs = trace::tables(&st);
    let public = trace::public_values(&st);
    assert_eq!(
        check(&airs, &traces, &public),
        vec![],
        "randomized traces are valid"
    );
    (airs, traces, public)
}

fn rejected(airs: &[Table], traces: &[RowMajorMatrix<Val>], public: &[Vec<Val>]) -> bool {
    !check(airs, traces, public).is_empty()
}

#[test]
fn a_missing_blinding_message_is_rejected() {
    let (airs, mut traces, public) = honest();
    let blind = traces.len() - 1;
    traces[blind].values[3 * BLIND_WIDTH] = Val::ZERO; // table 3's provision
                                                       // With real = 0 its values must be zero too; clear them as well, so only
                                                       // the balance is at stake.
    for v in &mut traces[blind].values[3 * BLIND_WIDTH + 1..4 * BLIND_WIDTH] {
        *v = Val::ZERO;
    }
    assert!(rejected(&airs, &traces, &public));
}

#[test]
fn a_duplicated_blinding_message_is_rejected() {
    let (airs, mut traces, public) = honest();
    let blind = traces.len() - 1;
    let n = traces.len() - 1;
    // Provide table 2's message a second time, on a padding row.
    let src: Vec<Val> = traces[blind].values[2 * BLIND_WIDTH..3 * BLIND_WIDTH].to_vec();
    traces[blind].values[n * BLIND_WIDTH..(n + 1) * BLIND_WIDTH].copy_from_slice(&src);
    assert!(rejected(&airs, &traces, &public));
}

#[test]
fn an_altered_blinding_value_on_either_side_is_rejected() {
    let (airs, traces, public) = honest();
    let blind = traces.len() - 1;
    let mut a = traces.clone();
    let w = a[4].width;
    a[4].values[w - 1] += Val::ONE; // the CPU's consumed message
    assert!(rejected(&airs, &a, &public));
    let mut b = traces.clone();
    b[blind].values[4 * BLIND_WIDTH + 1] += Val::ONE; // its provision
    assert!(rejected(&airs, &b, &public));
}

#[test]
fn the_selector_admits_exactly_one_message_per_table() {
    let (airs, traces, public) = honest();
    let blind = traces.len() - 1;
    let n = traces.len() - 1;
    // A second consumption on row 1, with a matching extra provision, so the
    // bus would balance: the transition constraint still rejects it.
    let mut a = traces.clone();
    let w = a[5].width;
    let sel = w - BLIND_WIDTH;
    a[5].values[w + sel] = Val::ONE;
    let mut extra = vec![Val::ONE];
    extra.extend(std::iter::repeat_n(Val::ZERO, BLIND_VALUES));
    a[blind].values[n * BLIND_WIDTH..(n + 1) * BLIND_WIDTH].copy_from_slice(&extra);
    assert!(rejected(&airs, &a, &public));
    // No consumption on the first row, with the provision removed: the
    // first-row constraint rejects it.
    let mut b = traces.clone();
    b[5].values[sel] = Val::ZERO;
    for v in &mut b[blind].values[5 * BLIND_WIDTH..6 * BLIND_WIDTH] {
        *v = Val::ZERO;
    }
    assert!(rejected(&airs, &b, &public));
}

/// A **pure** bus imbalance: one ALU_ADD row claims a different but
/// internally consistent addition (`a0` and `c0` both + 1), so every local
/// constraint holds and only bus balances fail. With random blinding, the
/// release prover produces a proof, and the verifier must reject it through
/// the global terminal sum: the blinding bus cannot absorb the imbalance.
#[test]
fn blinding_cannot_hide_an_unbalanced_real_bus() {
    use blacksilk_zkvm::air::check::Violation;
    let prog = branching();
    let (st, traces) = statement_and_traces(&prog, 0);
    let airs = trace::tables(&st);
    let public = trace::public_values(&st);
    let add = 5;
    let w = traces[add].width;
    // alu_add layout: ADD, SUB flags, a0..a3 (2..6), b0..b3, c0..c3 (10..14).
    let row = (0..traces[add].height())
        .find(|&r| {
            let v = &traces[add].values[r * w..(r + 1) * w];
            v[0] == Val::ONE
                && p3_field::PrimeField32::as_canonical_u32(&v[2]) < 255
                && p3_field::PrimeField32::as_canonical_u32(&v[10]) < 255
        })
        .expect("an ADD row with room in its low bytes");
    let mut bad = traces.clone();
    bad[add].values[row * w + 2] += Val::ONE;
    bad[add].values[row * w + 10] += Val::ONE;
    let v = check(&airs, &bad, &public);
    assert!(!v.is_empty());
    assert!(
        v.iter().all(|x| matches!(
            x,
            Violation::Unbalanced { .. } | Violation::LocalUnbalanced { .. }
        )),
        "only bus balances fail: {v:?}"
    );
    for seed in 0..3u64 {
        let mut t = bad.clone();
        trace::randomize_blinding(&mut t, &mut ChaCha20Rng::seed_from_u64(seed));
        let mut rng = ChaCha20Rng::seed_from_u64(100 + seed);
        let cfg = ProverConfig::for_statement(&statement_digest(&airs), &[1; 32], &mut rng);
        let proof = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            blacksilk_zk::prove(&cfg, &airs, &t, &public, &limits(&airs))
        }));
        if cfg!(debug_assertions) {
            // Plonky3's debug checker refuses to prove it: nothing to verify.
            assert!(!matches!(proof, Ok(Ok(_))), "debug prover accepted it");
            continue;
        }
        let p = proof
            .expect("the release prover does not check balances")
            .expect("a proof is produced");
        let err = prove::verify(&st, &p).expect_err("seed {seed}: the forged proof verified");
        assert!(
            format!("{err:?}").contains("TerminalSum"),
            "rejected by the terminal sum, got {err:?}"
        );
    }
}

/// On the real `prove` path, **every** table's first row carries nonzero
/// blinding values, fresh per proof. Recovered from the published terminals
/// with the true witness (possible in a test; for tables with public sums an
/// observer can do the same, which is harmless: the values carry no witness
/// data). A prover path that skipped randomization would fail here.
#[test]
fn every_table_of_a_real_proof_is_blinded_with_fresh_values() {
    let prog = branching();
    let (_, truth) = statement_and_traces(&prog, 0);
    let mut seen: Vec<Vec<[Val; BLIND_VALUES]>> = Vec::new();
    for seed in [31u64, 32] {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let (st, proof) = prove::prove(prog.clone(), &[0], [9; 32], &mut rng).unwrap();
        let airs = trace::tables(&st);
        let public = trace::public_values(&st);
        let obs = Observer::new(
            &VerifierConfig::for_statement(&statement_digest(&airs)),
            &airs,
            &proof,
            &public,
        );
        let blind = airs.len() - 1;
        let mut per = Vec::new();
        for t in 0..blind {
            let published = proof.lookup_terminals[t].as_ref().unwrap().0;
            let v = explain_table(&obs, t, &airs[t], &truth[t], &public[t], published)
                .unwrap_or_else(|| panic!("table {t}: no blinding values"));
            assert!(
                v.iter().any(|x| *x != Val::ZERO),
                "table {t} is not blinded"
            );
            per.push(v);
        }
        seen.push(per);
    }
    for (t, (a, b)) in seen[0].iter().zip(&seen[1]).enumerate() {
        assert_ne!(a, b, "table {t}: the same blinding values in two proofs");
    }
}

#[test]
fn the_blind_table_rejects_non_boolean_rows_and_dirty_padding() {
    let (airs, traces, public) = honest();
    let blind = traces.len() - 1;
    let n = traces.len() - 1;
    let mut a = traces.clone();
    a[blind].values[0] = Val::TWO; // real = 2
    assert!(rejected(&airs, &a, &public));
    let mut b = traces.clone();
    b[blind].values[n * BLIND_WIDTH + 3] = Val::ONE; // padding row, nonzero value
    assert!(rejected(&airs, &b, &public));
}

// ---- randomness ----

#[test]
fn blinding_values_are_fresh_nonzero_and_keep_the_bus_balanced() {
    let prog = branching();
    let (st, base) = statement_and_traces(&prog, 0);
    let airs = trace::tables(&st);
    let public = trace::public_values(&st);
    let n = base.len() - 1;
    let values = |seed: u64| -> Vec<Val> {
        let mut t = base.clone();
        trace::randomize_blinding(&mut t, &mut ChaCha20Rng::seed_from_u64(seed));
        assert_eq!(check(&airs, &t, &public), vec![]);
        (0..n)
            .flat_map(|i| {
                let w = t[i].width;
                t[i].values[w - BLIND_VALUES..w].to_vec()
            })
            .collect()
    };
    let (a, b) = (values(1), values(2));
    assert_eq!(a.len(), n * BLIND_VALUES);
    assert!(
        a.iter().all(|v| *v != Val::ZERO),
        "no zero value (probability ~2^-31 each)"
    );
    let mut distinct = a.clone();
    distinct.sort_by_key(p3_field::PrimeField32::as_canonical_u32);
    distinct.dedup();
    assert_eq!(distinct.len(), a.len(), "all distinct");
    assert!(a.iter().zip(&b).all(|(x, y)| x != y), "fresh per seed");
}
