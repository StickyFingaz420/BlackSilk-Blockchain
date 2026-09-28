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
//! budget for its `n_fn`. No proof is built.

use blacksilk_px::perm::HostPerm;
use blacksilk_px::prove::{self, kernel_program, witness_words};
use blacksilk_px::tree::Tree;
use blacksilk_px::wallet::{self, Account};
use blacksilk_px_core::call::{OutSpec, MAX_FN};
use blacksilk_px_core::kernel::{self, FunctionWitness, SliceSource, Witness, N_IN, N_OUT};
use blacksilk_px_core::record::Record;
use blacksilk_px_core::{Digest, ZERO_DIGEST};
use blacksilk_zkvm::air::trace::{self, Budget};
use blacksilk_zkvm::{run, MAX_CYCLES};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Two contract ids: shapes with one or two contracts.
const CONTRACTS: [Digest; 2] = [[0x100, 1, 2, 3, 4, 5, 6, 7], [0x200, 1, 2, 3, 4, 5, 6, 7]];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum In {
    User,
    Dummy,
    /// A record of `CONTRACTS[k]`.
    Contract(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Out {
    User,
    /// A record of `CONTRACTS[k]`.
    Contract(usize),
}

/// A transaction shape: input and output kinds, and for each function its
/// contract, approved inputs and specified outputs.
#[derive(Clone, Debug)]
struct Shape {
    ins: [In; N_IN],
    outs: [Out; N_OUT],
    fns: Vec<(usize, [bool; N_IN], [bool; N_OUT])>,
}

impl Shape {
    /// The kernel's rules on the shape (px-core/src/kernel.rs): approvals
    /// only of records of the function's contract, exactly one per contract
    /// input; specifications only of user outputs or the function's own
    /// contract's records, at most one per output, and one for every
    /// contract output.
    fn is_valid(&self) -> bool {
        for (i, input) in self.ins.iter().enumerate() {
            let approvals: Vec<usize> = self.fns.iter().filter(|f| f.1[i]).map(|f| f.0).collect();
            match input {
                In::Contract(c) => {
                    if approvals.len() != 1 || approvals[0] != *c {
                        return false;
                    }
                }
                _ => {
                    if !approvals.is_empty() {
                        return false;
                    }
                }
            }
        }
        for (j, output) in self.outs.iter().enumerate() {
            let specs: Vec<usize> = self.fns.iter().filter(|f| f.2[j]).map(|f| f.0).collect();
            if specs.len() > 1 {
                return false;
            }
            match output {
                Out::Contract(c) => {
                    if specs != [*c] {
                        return false;
                    }
                }
                Out::User => {}
            }
        }
        true
    }

    /// A witness of this shape (random openings; balanced with a bridge-in
    /// when every input is a dummy).
    fn witness(&self, seed: u64) -> Witness {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let mut perm = HostPerm::new();
        let mut tree = Tree::new(&mut perm);
        let acct = Account::from_seed(&[9; 32]);
        let mut recs = Vec::new();
        let mut total = 0u64;
        for (k, kind) in self.ins.iter().enumerate() {
            let value = 1_000 + 7 * k as u64;
            let r = match kind {
                In::Dummy => {
                    recs.push(None);
                    continue;
                }
                In::User => Record::plain(
                    acct.owner(0),
                    value,
                    [0; 8],
                    wallet::random_digest(&mut rng),
                    wallet::random_digest(&mut rng),
                ),
                In::Contract(c) => Record {
                    owner: ZERO_DIGEST,
                    contract: CONTRACTS[*c],
                    asset: ZERO_DIGEST,
                    value,
                    data: wallet::random_digest(&mut rng),
                    rho: wallet::random_digest(&mut rng),
                    rcm: wallet::random_digest(&mut rng),
                },
            };
            let cm = r.commit(&mut perm);
            let pos = tree.append(&mut perm, cm).unwrap();
            total += value;
            recs.push(Some((r, pos)));
        }
        let inputs: Vec<_> = self
            .ins
            .iter()
            .zip(&recs)
            .map(|(kind, rec)| match (kind, rec) {
                (In::Dummy, _) => wallet::dummy_input(&mut rng),
                (In::User, Some((r, p))) => acct.spend(0, r, *p, tree.path(*p).unwrap()),
                (In::Contract(_), Some((r, p))) => {
                    wallet::contract_input(&mut rng, r, *p, tree.path(*p).unwrap())
                }
                _ => unreachable!(),
            })
            .collect();
        let bridge_in = if total == 0 { 500 } else { 0 };
        let all = total + bridge_in;
        let values = [all / 2, all - all / 2];
        let outs: Vec<_> = (0..N_OUT)
            .map(|j| {
                let d = wallet::random_digest(&mut rng);
                match self.outs[j] {
                    Out::User => wallet::output(&mut rng, d, values[j]),
                    Out::Contract(c) => {
                        wallet::contract_output(&mut rng, CONTRACTS[c], values[j], d)
                    }
                }
            })
            .collect();
        let mut w = wallet::witness(
            tree.root(),
            bridge_in,
            0,
            [inputs[0].clone(), inputs[1].clone()],
            [outs[0].clone(), outs[1].clone()],
        );
        w.n_fn = self.fns.len();
        for (f, (c, approve, specs)) in self.fns.iter().enumerate() {
            let spec = [0, 1].map(|j| {
                specs[j].then(|| OutSpec {
                    owner: outs[j].owner,
                    contract: outs[j].contract,
                    value: outs[j].value,
                    data: outs[j].data,
                })
            });
            w.functions[f] = Some(FunctionWitness {
                contract: CONTRACTS[*c],
                blind: wallet::random_digest(&mut rng),
                approve: *approve,
                spec,
            });
        }
        w
    }
}

/// Every shape the kernel accepts, for `n_fn = 0..=MAX_FN`.
fn valid_shapes() -> Vec<Shape> {
    let ins = [In::User, In::Dummy, In::Contract(0), In::Contract(1)];
    let outs = [Out::User, Out::Contract(0), Out::Contract(1)];
    let flags = |m: usize| [m & 1 == 1, m & 2 == 2];
    let mut shapes = Vec::new();
    for i0 in ins {
        for i1 in ins {
            for o0 in outs {
                for o1 in outs {
                    for n_fn in 0..=MAX_FN {
                        // Per function: contract (2) × approvals (4) × specs (4).
                        let per_fn: usize = 2 * 4 * 4;
                        for code in 0..per_fn.pow(n_fn as u32) {
                            let mut c = code;
                            let mut fns = Vec::new();
                            for _ in 0..n_fn {
                                let x = c % per_fn;
                                c /= per_fn;
                                fns.push((x % 2, flags((x / 2) % 4), flags(x / 8)));
                            }
                            let shape = Shape {
                                ins: [i0, i1],
                                outs: [o0, o1],
                                fns,
                            };
                            if shape.is_valid() {
                                shapes.push(shape);
                            }
                        }
                    }
                }
            }
        }
    }
    shapes
}

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
