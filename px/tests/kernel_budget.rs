//! The kernel's fixed row budgets (`prove::kernel_budget`) against every
//! honest transaction shape (RTW1C-1).
//!
//! The kernel runs the same instructions for every witness of one `n_fn`
//! except a few data-dependent comparisons (`read_spec`'s foreign-contract
//! test, the output-owner rule, `by_own_contract`, the approval checks). A
//! kernel execution that needs more rows than its budget in any table can
//! still be proven only while the padded, shared table happens to have room
//! (`pow2` of the sum of every execution's budget), so whether a transaction
//! is provable would depend on the functions it calls: a liveness failure,
//! and the per-execution check in `prove::prove` now refuses it outright.
//!
//! This test enumerates every shape the kernel accepts, for `n_fn = 0, 1, 2`:
//! each input a user record, a dummy or a record of one of two contracts;
//! each output a user record or a record of one of two contracts; each
//! function's contract; every approval and specification pattern. A shape is
//! kept when it satisfies the kernel's rules (checked against the native
//! kernel, which must accept it, and the pinned guest, which must exit 0).
//! Every table of every accepted shape must stay at or below 95% of the
//! budget for its `n_fn`. No proof is built. The shapes and their witnesses:
//! fuzz/src/targets/kernel_shapes.rs (shared with the fuzz seed generator).

#[path = "../../fuzz/src/targets/kernel_shapes.rs"]
mod shapes;

use blacksilk_px::perm::HostPerm;
use blacksilk_px::prove::{self, kernel_program, witness_words};
use blacksilk_px::tree::Tree;
use blacksilk_px::wallet;
use blacksilk_px_core::call::MAX_FN;
use blacksilk_px_core::kernel::{self, SliceSource};
use blacksilk_zkvm::air::trace::{self, Budget};
use blacksilk_zkvm::{run, MAX_CYCLES};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use shapes::{valid_shapes, In, Out, Shape, CONTRACTS};

const TABLES: [&str; 8] = [
    "cycles", "keys", "add", "bit", "lt", "shift", "mul", "poseidon",
];

fn rows(b: &Budget) -> [usize; 8] {
    [
        b.cycles, b.keys, b.add, b.bit, b.lt, b.shift, b.mul, b.poseidon,
    ]
}

#[test]
fn every_honest_kernel_shape_fits_its_budget_with_headroom() {
    let shapes = valid_shapes();
    // Measure in parallel: each shape is one guest run and one trace count.
    let threads = std::thread::available_parallelism().map_or(2, |n| n.get().min(4));
    let chunk = shapes.len().div_ceil(threads);
    let measured: Vec<(usize, [usize; 8])> = std::thread::scope(|s| {
        let handles: Vec<_> = shapes
            .chunks(chunk)
            .enumerate()
            .map(|(t, part)| {
                s.spawn(move || {
                    part.iter()
                        .enumerate()
                        .map(|(k, shape)| {
                            let w = shape.witness((t * chunk + k) as u64);
                            let words = witness_words(&w);
                            let public = kernel::transfer(
                                &mut HostPerm::new(),
                                &mut SliceSource::new(&words),
                            )
                            .unwrap_or_else(|e| {
                                panic!("the kernel rejects honest shape {shape:?}: {e:?}")
                            });
                            let exec = run(&kernel_program(), &words, MAX_CYCLES).unwrap();
                            assert_eq!(exec.exit_code, 0, "{shape:?}");
                            let used = trace::usage(&kernel_program(), &exec);
                            (public.n_fn, rows(&used))
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("a measuring thread panicked"))
            .collect()
    });
    let mut errors = Vec::new();
    let mut counts = [0usize; MAX_FN + 1];
    let mut max = [[0usize; 8]; MAX_FN + 1];
    let mut widest = [[0usize; 8]; MAX_FN + 1];
    for (k, (n_fn, used)) in measured.iter().enumerate() {
        counts[*n_fn] += 1;
        for t in 0..8 {
            if used[t] > max[*n_fn][t] {
                max[*n_fn][t] = used[t];
                widest[*n_fn][t] = k;
            }
        }
    }
    for n_fn in 0..=MAX_FN {
        let budget = rows(&prove::kernel_budget(n_fn));
        println!("n_fn = {n_fn}: {} shapes", counts[n_fn]);
        for t in 0..8 {
            let (u, b) = (max[n_fn][t], budget[t]);
            println!(
                "  {:8} max {u:6} of {b:6} ({:.1}%), widest {:?}",
                TABLES[t],
                100.0 * u as f64 / b as f64,
                shapes[widest[n_fn][t]]
            );
            // 95%: headroom against small future changes (the budgets are
            // the measured maximum plus about 6%).
            if u * 100 > b * 95 {
                errors.push(format!(
                    "n_fn = {n_fn}: {} uses {u} of {b} in the widest shape {:?}",
                    TABLES[t], shapes[widest[n_fn][t]]
                ));
            }
        }
        assert!(counts[n_fn] > 0, "no shape with n_fn = {n_fn}");
    }
    assert!(errors.is_empty(), "{errors:#?}");
}

/// The enumeration's rule set agrees with the kernel: a sample of shapes the
/// predicate refuses is refused by the native kernel too (so the budget test
/// above does not skip an accepted shape).
#[test]
fn the_shape_rules_match_the_kernel() {
    let ins = [In::User, In::Dummy, In::Contract(0), In::Contract(1)];
    let outs = [Out::User, Out::Contract(0), Out::Contract(1)];
    let flags = |m: usize| [m & 1 == 1, m & 2 == 2];
    let (mut accepted, mut refused) = (0, 0);
    let mut seed = 0u64;
    for i0 in ins {
        for i1 in ins {
            for o0 in outs {
                for o1 in outs {
                    // Every one-function shape (two contracts × approvals × specs).
                    for x in 0..32 {
                        let shape = Shape {
                            ins: [i0, i1],
                            outs: [o0, o1],
                            fns: vec![(x % 2, flags((x / 2) % 4), flags(x / 8))],
                        };
                        seed += 1;
                        let w = shape.witness(seed);
                        let ok = kernel::transfer(
                            &mut HostPerm::new(),
                            &mut SliceSource::new(&witness_words(&w)),
                        )
                        .is_ok();
                        assert_eq!(ok, shape.is_valid(), "{shape:?}");
                        if ok {
                            accepted += 1;
                        } else {
                            refused += 1;
                        }
                    }
                }
            }
        }
    }
    assert!(accepted > 0 && refused > 0);
}

/// Defence in depth (RTW1C-1): `prove` measures every execution against its
/// own budget before proving. A LOCK of the reference vault with a budget one
/// row short in one table is refused with `OverBudget` for that execution,
/// even though the padded shared table would have had room; with the
/// registered budget it passes the check (the proof itself is not built
/// here: the refusal comes first).
#[test]
fn an_execution_over_its_own_budget_is_refused_before_proving() {
    use blacksilk_px::prove::TransferError;
    use blacksilk_px::vault::{self, Terms};
    use blacksilk_px_core::call::Window;
    let mut rng = ChaCha20Rng::seed_from_u64(5);
    let c = CONTRACTS[0];
    let secret = wallet::random_digest(&mut rng);
    let terms = Terms::claim_only(&c, &secret);
    let blind = wallet::random_digest(&mut rng);
    let (input, fw) = vault::lock_call(&c, 500, &terms, 0, &blind, &Window::UNBOUNDED);
    let mut w = wallet::witness(
        Tree::new(&mut HostPerm::new()).root(),
        500,
        0,
        [wallet::dummy_input(&mut rng), wallet::dummy_input(&mut rng)],
        [
            wallet::contract_output(&mut rng, c, 500, terms.data(&c)),
            wallet::empty_output(&mut rng),
        ],
    );
    w.n_fn = 1;
    w.functions[0] = Some(fw);
    let exec = run(&vault::program(), &input, MAX_CYCLES).unwrap();
    let used = trace::usage(&vault::program(), &exec);
    let mut short = vault::BUDGET;
    short.bit = used.bit - 1;
    assert_eq!(
        prove::over_budget(&used, &short),
        Some(("bit", used.bit, used.bit - 1))
    );
    assert_eq!(prove::over_budget(&used, &vault::BUDGET), None);
    match prove::prove(
        &w,
        &[(vault::program(), input, short)],
        &Window::UNBOUNDED,
        [1; 32],
        &mut rng,
    ) {
        Err(TransferError::OverBudget {
            execution: 1,
            table: "bit",
            used: u,
            budget: b,
        }) => assert_eq!((u, b), (used.bit, used.bit - 1)),
        other => panic!("expected OverBudget, got {:?}", other.map(|_| ())),
    }
    // The kernel's own budget is checked the same way: this execution fits
    // `kernel_budget(1)` and not the smaller `n_fn = 0` budget.
    let kexec = run(&kernel_program(), &witness_words(&w), MAX_CYCLES).unwrap();
    let kused = trace::usage(&kernel_program(), &kexec);
    assert_eq!(prove::over_budget(&kused, &prove::kernel_budget(1)), None);
    assert!(prove::over_budget(&kused, &prove::kernel_budget(0)).is_some());
}

/// A function program that writes `words`, then counts down from `spins`
/// (cycles only), and halts with exit code 0.
fn busy_writer(words: &[u32], spins: u32) -> std::sync::Arc<blacksilk_zkvm::Program> {
    use blacksilk_zkvm::asm::{
        reg::{T0, T1, ZERO},
        Asm,
    };
    use blacksilk_zkvm::isa::Op;
    let mut a = Asm::new(0x1_0000);
    for &w in words {
        a.li(T0, w).write_reg(T0);
    }
    if spins > 0 {
        a.li(T1, spins)
            .label("spin")
            .imm(Op::Addi, T1, T1, -1)
            .branch(Op::Bne, T1, ZERO, "spin");
    }
    a.halt(0);
    std::sync::Arc::new(a.finish().expect("assembles"))
}

/// A function program that writes `words` and halts with exit code 0.
fn writer(words: &[u32]) -> std::sync::Arc<blacksilk_zkvm::Program> {
    busy_writer(words, 0)
}

/// `prove` checks each function's prefix before anything else about the
/// function (mutation run E): a function that writes the kernel's prefix
/// exactly, and nothing after it, passes the check (and is then measured
/// against its budget, here a zero one); one that writes less than a
/// prefix, or a prefix with one word changed, is `FunctionMismatch` before
/// its budget is measured. Nothing is proven: every case is refused first.
/// An execution that uses exactly its budget fits it.
#[test]
fn a_functions_prefix_is_checked_before_its_budget() {
    use blacksilk_px::prove::TransferError;
    use blacksilk_px::vault::{self, Terms};
    use blacksilk_px_core::call::{function_prefix, Window, ABI_VERSION, PREFIX_WORDS};
    let mut rng = ChaCha20Rng::seed_from_u64(6);
    let c = CONTRACTS[0];
    let secret = wallet::random_digest(&mut rng);
    let terms = Terms::claim_only(&c, &secret);
    let blind = wallet::random_digest(&mut rng);
    let (_, fw) = vault::lock_call(&c, 500, &terms, 0, &blind, &Window::UNBOUNDED);
    let mut w = wallet::witness(
        Tree::new(&mut HostPerm::new()).root(),
        500,
        0,
        [wallet::dummy_input(&mut rng), wallet::dummy_input(&mut rng)],
        [
            wallet::contract_output(&mut rng, c, 500, terms.data(&c)),
            wallet::empty_output(&mut rng),
        ],
    );
    w.n_fn = 1;
    w.functions[0] = Some(fw);
    let words = witness_words(&w);
    let public = kernel::transfer(&mut HostPerm::new(), &mut SliceSource::new(&words)).unwrap();
    let (contract, io_hash) = &public.functions[0];
    let prefix = function_prefix(ABI_VERSION, io_hash, contract, &Window::UNBOUNDED);
    assert_eq!(prefix.len(), PREFIX_WORDS);
    let zero = Budget {
        cycles: 0,
        keys: 0,
        add: 0,
        bit: 0,
        lt: 0,
        shift: 0,
        mul: 0,
        poseidon: 0,
    };
    let attempt = |program, rng: &mut ChaCha20Rng| {
        prove::prove(
            &w,
            &[(program, vec![], zero)],
            &Window::UNBOUNDED,
            [2; 32],
            rng,
        )
        .map(|_| ())
    };
    // First (the prover's own shape check cannot catch it, so nothing else
    // refuses it before proving): a function far over its budget, beyond
    // the room the padded shared tables would leave, is refused by the
    // per-execution check with `OverBudget`, not by the prover's shape
    // check (`BudgetExceeded`).
    match attempt(busy_writer(&prefix, 100_000), &mut rng) {
        Err(TransferError::OverBudget {
            execution: 1,
            table: "cycles",
            ..
        }) => {}
        other => panic!("expected OverBudget, got {other:?}"),
    }
    // Exactly the prefix: past the prefix check, refused by the budget.
    match attempt(writer(&prefix), &mut rng) {
        Err(TransferError::OverBudget {
            execution: 1,
            table: "cycles",
            ..
        }) => {}
        other => panic!("expected OverBudget, got {other:?}"),
    }
    // Shorter than a prefix, or one word changed: refused at the prefix.
    let short = writer(&prefix[..3]);
    assert!(matches!(
        attempt(short, &mut rng),
        Err(TransferError::FunctionMismatch(0))
    ));
    for i in [0, 1, 9, PREFIX_WORDS - 1] {
        let mut wrong = prefix;
        wrong[i] ^= 1;
        let mut out = wrong.to_vec();
        out.push(7);
        assert!(
            matches!(
                attempt(writer(&out), &mut rng),
                Err(TransferError::FunctionMismatch(0))
            ),
            "word {i}"
        );
    }
    // An execution using exactly its budget fits it.
    let exec = run(&kernel_program(), &words, MAX_CYCLES).unwrap();
    let used = trace::usage(&kernel_program(), &exec);
    assert_eq!(prove::over_budget(&used, &used), None);
}

/// The deploy caps (record `px-deploy-row-caps`) reserve the kernel's share of
/// the shared tables with `kernel_budget(MAX_FN)`. That covers every call with
/// fewer functions only if the kernel's budget does not shrink as functions are
/// added: `K(0) ≤ K(1) ≤ … ≤ K(MAX_FN)` on every field (red team L1).
#[test]
fn kernel_budgets_grow_with_the_function_count() {
    let fields = |b: Budget| {
        [
            b.cycles, b.keys, b.add, b.bit, b.lt, b.shift, b.mul, b.poseidon,
        ]
    };
    for n in 1..=MAX_FN {
        let (lo, hi) = (
            fields(prove::kernel_budget(n - 1)),
            fields(prove::kernel_budget(n)),
        );
        for (i, (a, b)) in lo.iter().zip(&hi).enumerate() {
            assert!(
                a <= b,
                "field {i}: kernel_budget({}) > kernel_budget({n})",
                n - 1
            );
        }
    }
}

/// A function program that writes `words`, then runs `nops` no-ops and a
/// spin loop of `spins` iterations, and halts with exit code 0.
fn padded_writer(words: &[u32], spins: u32, nops: u32) -> std::sync::Arc<blacksilk_zkvm::Program> {
    use blacksilk_zkvm::asm::{
        reg::{T0, T1, ZERO},
        Asm,
    };
    use blacksilk_zkvm::isa::Op;
    let mut a = Asm::new(0x1_0000);
    for &w in words {
        a.li(T0, w).write_reg(T0);
    }
    for _ in 0..nops {
        a.imm(Op::Addi, ZERO, ZERO, 0);
    }
    if spins > 0 {
        a.li(T1, spins)
            .label("spin")
            .imm(Op::Addi, T1, T1, -1)
            .branch(Op::Bne, T1, ZERO, "spin");
    }
    a.halt(0);
    std::sync::Arc::new(a.finish().expect("assembles"))
}

/// A `padded_writer` of `words` that halts after exactly `cycles` cycles.
fn writer_of_cycles(words: &[u32], cycles: usize) -> std::sync::Arc<blacksilk_zkvm::Program> {
    let steps = |p: &blacksilk_zkvm::Program| run(p, &[], MAX_CYCLES).unwrap().steps.len();
    // Each spin is two cycles (`li` of a large count can take two
    // instructions): leave a margin of spins, then fill the rest with no-ops.
    let base = steps(&padded_writer(words, 1, 0));
    let spins = 1 + (cycles - base).saturating_sub(16) / 2;
    let short = steps(&padded_writer(words, spins as u32, 0));
    let p = padded_writer(words, spins as u32, (cycles - short) as u32);
    assert_eq!(steps(&p), cycles);
    p
}

/// The prover's early stop at the cycle cap (red team I2, record
/// `px-deploy-row-caps`), at its boundary, without proving: every case is
/// refused before any proving work.
/// - Budget 2^15, a run of exactly 2^15 cycles: the run completes and its
///   cycles fit (the check moves on to the next table, `keys`, which the
///   budget leaves at 0).
/// - Budget 2^15, a run of 2^15 + 1 cycles: completes (the stop is one cycle
///   past the limit) and is refused as over budget in `cycles`, used 2^15 + 1.
/// - Budget 2^15, a run longer than 2^15 + 1: stopped early, `OverBudget`
///   with `used` = 2^15 + 1 (the limit plus one, a lower bound).
/// - A zero budget, a run past 2^15 and a wrong prefix: the early stop comes
///   first, so the error is `OverBudget` in `cycles`, not `FunctionMismatch`
///   (for runs up to 2^15 cycles the prefix is still checked first:
///   `a_functions_prefix_is_checked_before_its_budget`).
#[test]
fn the_function_run_stops_at_the_cycle_cap() {
    use blacksilk_px::prove::{TransferError, FN_RUN_LOG_CYCLES};
    use blacksilk_px::vault::{self, Terms};
    use blacksilk_px_core::call::{function_prefix, Window, ABI_VERSION};
    let cap = 1usize << FN_RUN_LOG_CYCLES;
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let c = CONTRACTS[0];
    let secret = wallet::random_digest(&mut rng);
    let terms = Terms::claim_only(&c, &secret);
    let blind = wallet::random_digest(&mut rng);
    let (_, fw) = vault::lock_call(&c, 500, &terms, 0, &blind, &Window::UNBOUNDED);
    let mut w = wallet::witness(
        Tree::new(&mut HostPerm::new()).root(),
        500,
        0,
        [wallet::dummy_input(&mut rng), wallet::dummy_input(&mut rng)],
        [
            wallet::contract_output(&mut rng, c, 500, terms.data(&c)),
            wallet::empty_output(&mut rng),
        ],
    );
    w.n_fn = 1;
    w.functions[0] = Some(fw);
    let words = witness_words(&w);
    let public = kernel::transfer(&mut HostPerm::new(), &mut SliceSource::new(&words)).unwrap();
    let (contract, io_hash) = &public.functions[0];
    let prefix = function_prefix(ABI_VERSION, io_hash, contract, &Window::UNBOUNDED);
    let budget = |cycles| Budget {
        cycles,
        keys: 0,
        add: 0,
        bit: 0,
        lt: 0,
        shift: 0,
        mul: 0,
        poseidon: 0,
    };
    let attempt = |program, b: Budget, rng: &mut ChaCha20Rng| {
        prove::prove(
            &w,
            &[(program, vec![], b)],
            &Window::UNBOUNDED,
            [3; 32],
            rng,
        )
        .map(|_| ())
    };
    let cycles_over = |r: Result<(), TransferError>| match r {
        Err(TransferError::OverBudget {
            execution: 1,
            table: "cycles",
            used,
            budget,
        }) => Some((used, budget)),
        _ => None,
    };

    // Exactly 2^15 cycles within a 2^15 budget: past the cycle check.
    match attempt(writer_of_cycles(&prefix, cap), budget(cap), &mut rng) {
        Err(TransferError::OverBudget {
            execution: 1,
            table: "keys",
            ..
        }) => {}
        other => panic!("expected the keys table to be the first over budget, got {other:?}"),
    }
    // 2^15 + 1 cycles: the run completes and is over budget by one.
    assert_eq!(
        cycles_over(attempt(
            writer_of_cycles(&prefix, cap + 1),
            budget(cap),
            &mut rng
        )),
        Some((cap + 1, cap))
    );
    // Longer: stopped at the limit plus one.
    assert_eq!(
        cycles_over(attempt(
            writer_of_cycles(&prefix, cap + 100),
            budget(cap),
            &mut rng
        )),
        Some((cap + 1, cap))
    );
    // A zero budget, past the cap, with a wrong prefix: the early stop wins.
    let mut wrong = prefix;
    wrong[0] ^= 1;
    assert_eq!(
        cycles_over(attempt(
            writer_of_cycles(&wrong, cap + 100),
            budget(0),
            &mut rng
        )),
        Some((cap + 1, 0))
    );
    // The same wrong prefix within the cap: the prefix is checked first.
    assert!(matches!(
        attempt(writer_of_cycles(&wrong, cap), budget(0), &mut rng),
        Err(TransferError::FunctionMismatch(0))
    ));
}
