//! Freeze gates B2 (widest PX proof against `MAX_PROOF_BYTES`, verifier cost)
//! and B3 (P-5 re-run on the frozen kernel for n_fn = 0, 1, 2).
//! Evidence: docs/evidence/freeze-b2-b3-2026-10-04/README.md.
//!
//! Subcommands (release build; every proving subcommand proves ONE proof at
//! a time and must run alone on the machine, with at least 9 GB free):
//!
//! - `check`: no proving. Builds every witness class natively (kernel and
//!   function guests run, exit codes checked), prints the fixed table heights
//!   and FRI schedules of every configuration.
//! - `b2 <config> <count> <dir> [--check-only]`: proves and verifies `count`
//!   two-function proofs of configuration `base`, `coarse18`, `dense18`,
//!   or `v12mem`; appends one row per proof to `<dir>/b2.csv` and
//!   saves the first proof as `<dir>/<config>.bin`. First prints the
//!   configuration's table heights, weighted cells and modelled memory. With
//!   `--check-only` it stops there, after the admission checks and a native
//!   run of the case: no proving.
//!
//!   `coarse18` and `dense18` predate the V12 deploy caps (record
//!   `px-deploy-row-caps`): they still prove, but `verify` now refuses their
//!   shape (a table above 2^16 rows), so their runs fail after proving.
//!   `v12mem` is the memory-widest V12 shape (see `v12_shape`): every
//!   budget and program passes the V12 deploy rules, asserted at run time.
//!   `v12_schedule_search` shows that no vault-based V12 pair has a longer
//!   FRI schedule, so the same proof is also the longest-schedule one.
//! - `p5 <n_fn> <per class> <dir>`: the P-5 campaign for one function count;
//!   appends to `<dir>/p5.csv` (resumable: rows already present are skipped).
//!   Asserts, exactly, that every proof of the shape has the same
//!   non-digest bytes.
//! - `model <dir>`: no proving. Validates the size model against every
//!   proof in the CSVs (exact), compares the digest counts with uniform
//!   query positions, searches every reachable set of table heights for the
//!   widest proof, and extrapolates the verifier time.
//!
//! Size model ("proof surgery"): a proof's encoded length depends on the
//! statement's widths (fixed per table kind), on the set of table heights
//! (tree depths and the FRI folding schedule, `honest_fri_schedule`) and on
//! the number of pruned Merkle digests, which the verifier pins to the
//! frontier of the public query positions (`p3-merkle-tree` pruning.rs,
//! `restore_paths`). `synth` takes a real proof of the widths, sets its
//! degree bits, schedule and digest counts to the target's, and encodes it
//! with the real encoder.

use blacksilk_px::perm::HostPerm;
use blacksilk_px::prove::{
    self, kernel_budget, kernel_program, prove_transfer, public_words, FN_RUN_LOG_CYCLES,
    PX_MAX_LOG_HEIGHT,
};
use blacksilk_px::state::State;
use blacksilk_px::tree::Tree;
use blacksilk_px::vault;
use blacksilk_px::wallet::{self, Account};
use blacksilk_px_core::call::{function_prefix, Window, ABI_VERSION, MAX_FN, PREFIX_WORDS};
use blacksilk_px_core::kernel::{self as pxkernel, FunctionWitness, Witness};
use blacksilk_px_core::record::Record;
use blacksilk_px_core::{Digest, ZERO_DIGEST};
use blacksilk_zk::params::{LOG_BLOWUP, MAX_LOG_HEIGHT, MAX_PROOF_BYTES, NUM_QUERIES};
use blacksilk_zk::Proof;
use blacksilk_zkvm::air::trace::{self, Budget, Part, Statement};
use blacksilk_zkvm::air::{program as program_table, MIN_HEIGHT};
use blacksilk_zkvm::Program;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

const C: Digest = [0x100, 1, 2, 3, 4, 5, 6, 7];
const C2: Digest = [0x200, 1, 2, 3, 4, 5, 6, 7];
const W: Window = Window::UNBOUNDED;
/// Agent 22's threshold for a deploy-time proof-size bound.
const AGENT22_BYTES: usize = 3_800_000;

// ------------------------------------------------------------ measurement

/// Where a proof's bytes go: the digest counts of every pruned multiproof
/// (input batches, then FRI commit-phase steps) and everything else.
#[derive(Clone, Debug)]
struct Parts {
    total: usize,
    batch_digests: Vec<usize>,
    step_arity: Vec<usize>,
    step_digests: Vec<usize>,
    /// `total` minus every digest and its vector's length prefix.
    nondigest: usize,
    degree_bits: Vec<usize>,
}

fn varint_len(mut v: usize) -> usize {
    let mut n = 1;
    while v >= 0x80 {
        v >>= 7;
        n += 1;
    }
    n
}

fn digest_bytes(count: usize) -> usize {
    32 * count + varint_len(count)
}

fn parts(proof: &Proof) -> Parts {
    let total = blacksilk_zk::encode_proof(proof).len();
    let fri = &proof.opening_proof.1;
    let batch_digests: Vec<usize> = fri
        .input_openings
        .iter()
        .map(|b| b.opening_proof.1.sibling_hashes.len())
        .collect();
    let step_arity: Vec<usize> = fri
        .commit_phase_openings
        .iter()
        .map(|s| s.log_arity as usize)
        .collect();
    let step_digests: Vec<usize> = fri
        .commit_phase_openings
        .iter()
        .map(|s| s.opening_proof.1.sibling_hashes.len())
        .collect();
    let digest_total: usize = batch_digests
        .iter()
        .chain(&step_digests)
        .map(|&c| digest_bytes(c))
        .sum();
    Parts {
        total,
        nondigest: total - digest_total,
        batch_digests,
        step_arity,
        step_digests,
        degree_bits: proof.degree_bits.clone(),
    }
}

fn join(v: &[usize]) -> String {
    v.iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>()
        .join(";")
}

fn split(s: &str) -> Vec<usize> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split(';').map(|x| x.parse().unwrap()).collect()
}

const HEADER: &str = "kind,n_fn,class,index,total,nondigest,batch_digests,step_arity,step_digests,degree_bits,prove_s,verify_ms";

struct Row {
    kind: String,
    n_fn: usize,
    class: String,
    index: usize,
    p: Parts,
    prove_s: f64,
    verify_ms: Vec<f64>,
}

fn write_row(path: &Path, r: &Row) {
    let new = !path.exists();
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();
    if new {
        writeln!(f, "{HEADER}").unwrap();
    }
    writeln!(
        f,
        "{},{},{},{},{},{},{},{},{},{},{:.2},{}",
        r.kind,
        r.n_fn,
        r.class,
        r.index,
        r.p.total,
        r.p.nondigest,
        join(&r.p.batch_digests),
        join(&r.p.step_arity),
        join(&r.p.step_digests),
        join(&r.p.degree_bits),
        r.prove_s,
        r.verify_ms
            .iter()
            .map(|x| format!("{x:.1}"))
            .collect::<Vec<_>>()
            .join(";")
    )
    .unwrap();
}

fn read_rows(path: &Path) -> Vec<Row> {
    let Ok(s) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    s.lines()
        .skip(1)
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let c: Vec<&str> = l.split(',').collect();
            Row {
                kind: c[0].into(),
                n_fn: c[1].parse().unwrap(),
                class: c[2].into(),
                index: c[3].parse().unwrap(),
                p: Parts {
                    total: c[4].parse().unwrap(),
                    nondigest: c[5].parse().unwrap(),
                    batch_digests: split(c[6]),
                    step_arity: split(c[7]),
                    step_digests: split(c[8]),
                    degree_bits: split(c[9]),
                },
                prove_s: c[10].parse().unwrap(),
                verify_ms: c[11].split(';').map(|x| x.parse().unwrap()).collect(),
            }
        })
        .collect()
}

// ---------------------------------------------------------------- fixture

struct Fixture {
    alice: Account,
    tree: Tree,
    user: Vec<(Record, u64)>,
    /// Vault records of `C`: `(record, position, secret)`.
    vaults: Vec<(Record, u64, Digest)>,
}

fn fixture() -> Fixture {
    let mut rng = ChaCha20Rng::seed_from_u64(99);
    let mut perm = HostPerm::new();
    let alice = Account::from_seed(&[7; 32]);
    let mut tree = Tree::new(&mut perm);
    let mut user = Vec::new();
    for i in 0..4u32 {
        let r = Record::plain(
            alice.owner(i),
            1_000 + i as u64,
            [0; 8],
            wallet::random_digest(&mut rng),
            wallet::random_digest(&mut rng),
        );
        let cm = r.commit(&mut perm);
        user.push((r, tree.append(&mut perm, cm).unwrap()));
    }
    let mut vaults = Vec::new();
    for k in 0..8u64 {
        let secret = wallet::random_digest(&mut rng);
        let r = Record {
            owner: ZERO_DIGEST,
            contract: C,
            asset: ZERO_DIGEST,
            value: 500 + k,
            data: vault::record_data(&C, &secret),
            rho: wallet::random_digest(&mut rng),
            rcm: wallet::random_digest(&mut rng),
        };
        let cm = r.commit(&mut perm);
        vaults.push((r, tree.append(&mut perm, cm).unwrap(), secret));
    }
    Fixture {
        alice,
        tree,
        user,
        vaults,
    }
}

fn with_functions(mut w: Witness, fns: &[FunctionWitness]) -> Witness {
    w.n_fn = fns.len();
    for (k, f) in fns.iter().enumerate() {
        w.functions[k] = Some(*f);
    }
    w
}

/// A witness and its function calls `(contract, private input)`.
type Case = (Witness, Vec<(Digest, Vec<u32>)>);

fn transfer_case(f: &Fixture, class: &str, k: usize, rng: &mut ChaCha20Rng) -> Case {
    let spend = |i: usize| {
        let (r, pos) = &f.user[i];
        f.alice.spend(i as u32, r, *pos, f.tree.path(*pos).unwrap())
    };
    let root = f.tree.root();
    let amount = 1 + rng.next_u64() % 1_000_000;
    let (i, j) = (k % 4, (k + 1) % 4);
    let w = match class {
        "deposit" => wallet::witness(
            State::new().root(),
            amount,
            0,
            [wallet::dummy_input(rng), wallet::dummy_input(rng)],
            [
                wallet::output(rng, f.alice.owner(20), amount),
                wallet::empty_output(rng),
            ],
        ),
        "pay2" => {
            let total = f.user[i].0.value + f.user[j].0.value;
            let pay = rng.next_u64() % total;
            wallet::witness(
                root,
                0,
                0,
                [spend(i), spend(j)],
                [
                    wallet::output(rng, f.alice.owner(21), pay),
                    wallet::output(rng, f.alice.owner(22), total - pay),
                ],
            )
        }
        "pay1" => {
            let total = f.user[i].0.value;
            let pay = rng.next_u64() % total;
            wallet::witness(
                root,
                0,
                0,
                [spend(i), wallet::dummy_input(rng)],
                [
                    wallet::output(rng, f.alice.owner(23), pay),
                    wallet::output(rng, f.alice.owner(24), total - pay),
                ],
            )
        }
        "withdraw" => {
            let total = f.user[i].0.value;
            let out = 1 + rng.next_u64() % total;
            wallet::witness(
                root,
                0,
                out,
                [spend(i), wallet::dummy_input(rng)],
                [
                    wallet::output(rng, f.alice.owner(25), total - out),
                    wallet::empty_output(rng),
                ],
            )
        }
        _ => unreachable!("{class}"),
    };
    (w, vec![])
}

/// LOCK under contract `c` of `value` into output `j`.
fn lock(
    c: &Digest,
    value: u64,
    j: usize,
    rng: &mut ChaCha20Rng,
) -> (Vec<u32>, FunctionWitness, Digest) {
    let secret = wallet::random_digest(rng);
    let terms = vault::Terms::claim_only(c, &secret);
    let data = terms.data(c);
    let blind = wallet::random_digest(rng);
    let (input, fw) = vault::lock_call(c, value, &terms, j, &blind, &W);
    (input, fw, data)
}

/// CLAIM of vault record `v` (input `i`) to `recipient` (output `j`).
fn claim(
    v: &(Record, u64, Digest),
    recipient: &Digest,
    i: usize,
    j: usize,
    rng: &mut ChaCha20Rng,
) -> (Vec<u32>, FunctionWitness) {
    let (r, _, secret) = v;
    let terms = vault::Terms::claim_only(&r.contract, secret);
    let blind = wallet::random_digest(rng);
    vault::claim_call(r, secret, &terms, recipient, i, j, &blind, &W)
}

fn contract_in(
    f: &Fixture,
    v: &(Record, u64, Digest),
    rng: &mut ChaCha20Rng,
) -> blacksilk_px_core::kernel::InputWitness {
    wallet::contract_input(rng, &v.0, v.1, f.tree.path(v.1).unwrap())
}

/// One- and two-function cases. `lock_contract` is the contract of the LOCK
/// in `claim_lock` (B2 uses a second contract so the two functions can
/// carry different budgets).
fn function_case(
    f: &Fixture,
    class: &str,
    k: usize,
    rng: &mut ChaCha20Rng,
    lock_contract: Digest,
) -> Case {
    let root = f.tree.root();
    match class {
        "lock" => {
            let (r, pos) = &f.user[k % 4];
            let value = 1 + rng.next_u64() % r.value;
            let (input, fw, data) = lock(&C, value, 0, rng);
            let w = wallet::witness(
                root,
                0,
                0,
                [
                    f.alice
                        .spend((k % 4) as u32, r, *pos, f.tree.path(*pos).unwrap()),
                    wallet::dummy_input(rng),
                ],
                [
                    wallet::contract_output(rng, C, value, data),
                    wallet::output(rng, f.alice.owner(26), r.value - value),
                ],
            );
            (with_functions(w, &[fw]), vec![(C, input)])
        }
        "claim" => {
            let v = &f.vaults[k % 8];
            let recipient = f.alice.owner(27);
            let (input, fw) = claim(v, &recipient, 0, 0, rng);
            let w = wallet::witness(
                root,
                0,
                0,
                [contract_in(f, v, rng), wallet::dummy_input(rng)],
                [
                    wallet::output(rng, recipient, v.0.value),
                    wallet::empty_output(rng),
                ],
            );
            (with_functions(w, &[fw]), vec![(C, input)])
        }
        "claim_lock" => {
            // W28-3's pair: CLAIM of a vault record (input 0) to output 0,
            // and a LOCK of a bridged-in amount into output 1.
            let v = &f.vaults[k % 8];
            let recipient = f.alice.owner(28);
            let (cin, cfw) = claim(v, &recipient, 0, 0, rng);
            let relock = 1 + rng.next_u64() % 100_000;
            let (lin, lfw, data) = lock(&lock_contract, relock, 1, rng);
            let w = wallet::witness(
                root,
                relock,
                0,
                [contract_in(f, v, rng), wallet::dummy_input(rng)],
                [
                    wallet::output(rng, recipient, v.0.value),
                    wallet::contract_output(rng, lock_contract, relock, data),
                ],
            );
            (
                with_functions(w, &[cfw, lfw]),
                vec![(C, cin), (lock_contract, lin)],
            )
        }
        "lock_lock" => {
            let (i, j) = (k % 4, (k + 1) % 4);
            let (ri, pi) = &f.user[i];
            let (rj, pj) = &f.user[j];
            let total = ri.value + rj.value;
            let v0 = 1 + rng.next_u64() % (total - 1);
            let (in0, fw0, d0) = lock(&C, v0, 0, rng);
            let (in1, fw1, d1) = lock(&C, total - v0, 1, rng);
            let w = wallet::witness(
                root,
                0,
                0,
                [
                    f.alice.spend(i as u32, ri, *pi, f.tree.path(*pi).unwrap()),
                    f.alice.spend(j as u32, rj, *pj, f.tree.path(*pj).unwrap()),
                ],
                [
                    wallet::contract_output(rng, C, v0, d0),
                    wallet::contract_output(rng, C, total - v0, d1),
                ],
            );
            (with_functions(w, &[fw0, fw1]), vec![(C, in0), (C, in1)])
        }
        "claim_claim" => {
            // Crossed approvals: function k claims input k to output k.
            let a = &f.vaults[k % 8];
            let b = &f.vaults[(k + 3) % 8];
            let recipient = f.alice.owner(29);
            let (in0, fw0) = claim(a, &recipient, 0, 0, rng);
            let (in1, fw1) = claim(b, &recipient, 1, 1, rng);
            let w = wallet::witness(
                root,
                0,
                0,
                [contract_in(f, a, rng), contract_in(f, b, rng)],
                [
                    wallet::output(rng, recipient, a.0.value),
                    wallet::output(rng, recipient, b.0.value),
                ],
            );
            (with_functions(w, &[fw0, fw1]), vec![(C, in0), (C, in1)])
        }
        _ => unreachable!("{class}"),
    }
}

fn classes(n_fn: usize) -> &'static [&'static str] {
    match n_fn {
        0 => &["deposit", "pay2", "pay1", "withdraw"],
        1 => &["lock", "claim"],
        2 => &["claim_lock", "lock_lock", "claim_claim"],
        _ => unreachable!(),
    }
}

fn case(
    f: &Fixture,
    n_fn: usize,
    class: &str,
    k: usize,
    rng: &mut ChaCha20Rng,
    lock_contract: Digest,
) -> Case {
    if n_fn == 0 {
        transfer_case(f, class, k, rng)
    } else {
        function_case(f, class, k, rng, lock_contract)
    }
}

// ----------------------------------------------------------------- budgets

/// Every `b2` configuration.
const CONFIGS: [&str; 4] = ["base", "coarse18", "dense18", "v12mem"];

/// A B2 configuration: the program and budget of `C`'s function (the CLAIM)
/// and of `C2`'s (the LOCK); the kernel's budget is `kernel_budget(2)`.
/// Shared tables have the height `pow2(kernel + f0 + f1)`.
struct Shape {
    programs: [Arc<Program>; 2],
    budgets: [Budget; 2],
    /// Built under the V12 deploy caps (and checked against them).
    v12: bool,
}

impl Shape {
    fn parts(&self) -> [(Arc<Program>, Budget); 2] {
        [0, 1].map(|k| (self.programs[k].clone(), self.budgets[k]))
    }

    fn registry(&self) -> Registry {
        let [p0, p1] = self.parts();
        [(C, p0), (C2, p1)].into()
    }
}

fn config(name: &str) -> Shape {
    if name.starts_with("v12") {
        return v12_shape(name);
    }
    let (b0, b1) = pre_v12_config(name);
    Shape {
        programs: [vault::program(), vault::program()],
        budgets: [b0, b1],
        v12: false,
    }
}

/// The configurations measured before the V12 caps, with vault programs.
fn pre_v12_config(name: &str) -> (Budget, Budget) {
    let k = kernel_budget(2);
    let v = vault::BUDGET;
    let shared = |target: usize, kx: usize, vx: usize| target - kx - vx;
    match name {
        "base" => (v, v),
        // One shared table (add, 27 columns) at 2^18: the folding schedule
        // keeps its large arities.
        "coarse18" => (
            Budget {
                add: shared(1 << 18, k.add, v.add),
                ..v
            },
            v,
        ),
        // Many distinct heights up to 2^18: a fine folding schedule.
        "dense18" => (
            Budget {
                add: shared(1 << 18, k.add, v.add),
                lt: shared(1 << 17, k.lt, v.lt),
                shift: shared(1 << 15, k.shift, v.shift),
                mul: shared(1 << 14, k.mul, v.mul),
                poseidon: shared(1 << 11, k.poseidon, v.poseidon),
                keys: 1 << 14,
                ..v
            },
            v,
        ),
        _ => panic!("unknown configuration {name}"),
    }
}

/// `tx::px::budget_is_provable` (R7-5), restated here because `blacksilk-tx`
/// depends on this crate: a budget a deploy may register.
fn registrable(b: &Budget) -> bool {
    let max = 1usize << MAX_LOG_HEIGHT;
    let k = kernel_budget(1);
    b.cycles <= blacksilk_zkvm::MAX_CYCLES as usize
        && b.keys <= max
        && [
            (b.add, k.add),
            (b.bit, k.bit),
            (b.lt, k.lt),
            (b.shift, k.shift),
            (b.mul, k.mul),
            (b.poseidon, k.poseidon),
        ]
        .iter()
        .all(|&(x, kx)| x.checked_add(kx).is_some_and(|s| s <= max))
}

/// The statement of the kernel plus function calls `(program, budget)`
/// with the vault's output length, built as `prove::statement` builds it.
fn statement(kernel_out: usize, parts: &[(Arc<Program>, Budget)]) -> Statement {
    let mut st = Statement::single(kernel_program(), 0, vec![0; kernel_out], [0; 32]);
    st.budget = Some(kernel_budget(parts.len()));
    for (program, b) in parts {
        st.others.push(Part {
            program: program.clone(),
            exit_code: 0,
            output: vec![0; PREFIX_WORDS + vault::OUT_WORDS as usize],
            budget: Some(*b),
        });
    }
    st
}

fn degree_bits(kernel_out: usize, parts: &[(Arc<Program>, Budget)]) -> Vec<usize> {
    statement(kernel_out, parts)
        .shape()
        .unwrap()
        .iter()
        .map(|h| h.trailing_zeros() as usize + 1)
        .collect()
}

/// The degree bits of the kernel plus vault calls with `budgets`.
fn vault_degree_bits(kernel_out: usize, budgets: &[Budget]) -> Vec<usize> {
    let parts: Vec<_> = budgets.iter().map(|b| (vault::program(), *b)).collect();
    degree_bits(kernel_out, &parts)
}

fn lde_heights(db: &[usize]) -> BTreeSet<usize> {
    db.iter().map(|d| d + LOG_BLOWUP).collect()
}

// -------------------------------------------------------------- V12 shapes

/// The V12 deploy caps (record `px-deploy-row-caps`; `blacksilk-tx` params
/// `PX_FN_LOG_*` and `PX_LOG_*`), restated: `blacksilk-tx` depends on this
/// crate, so its `budget_is_provable` and `program_is_provable` cannot be
/// called here. `v12_admit` checks the restatement against the V12 table
/// that tx/tests/deploy_rules.rs pins against the real caps
/// (`the_largest_allowed_budget_is_the_v12_table`).
const V12_FN_LOG_CYCLES: u32 = 15;
const V12_FN_LOG_KEYS: u32 = 14;
const V12_FN_LOG_PROGRAM: u32 = 14;
const V12_FN_LOG_IMAGE: u32 = 14;
const V12_LOG_ADD: u32 = 16;
const V12_LOG_BIT: u32 = 14;
const V12_LOG_LT: u32 = 16;
const V12_LOG_SHIFT: u32 = 14;
const V12_LOG_MUL: u32 = 14;
const V12_LOG_POSEIDON: u32 = 11;
/// The per-function maxima `[cycles, keys, add, bit, lt, shift, mul,
/// poseidon]` that tx/tests/deploy_rules.rs pins.
const V12_TABLE: [usize; 8] = [32_768, 16_384, 20_168, 7_192, 22_493, 7_367, 7_367, 948];
const FIELD_NAMES: [&str; 8] = [
    "cycles", "keys", "add", "bit", "lt", "shift", "mul", "poseidon",
];
/// Memory keys a padded vault program leaves for the keys its run touches
/// outside the image (the stack): the keys budget counts every image word
/// too (`trace::usage`), so a program whose image fills the keys cap can
/// run within it only if it touches no key outside its image. Registering
/// such a program is harmless: its calls fail client-side with
/// `OverBudget`, and the deployer has paid the deploy fee. `check_fit`
/// asserts that the room suffices.
const KEY_ROOM: usize = 1024;
/// `addi x0, x0, 0`.
const NOP: u32 = 0x0000_0013;

fn fields(b: &Budget) -> [usize; 8] {
    [
        b.cycles, b.keys, b.add, b.bit, b.lt, b.shift, b.mul, b.poseidon,
    ]
}

fn from_fields(f: [usize; 8]) -> Budget {
    let [cycles, keys, add, bit, lt, shift, mul, poseidon] = f;
    Budget {
        cycles,
        keys,
        add,
        bit,
        lt,
        shift,
        mul,
        poseidon,
    }
}

/// `blacksilk_tx::px::budget_is_provable`, restated.
fn v12_budget_ok(b: &Budget) -> bool {
    let k = kernel_budget(MAX_FN);
    let within = |x: usize, kx: usize, log: u32| {
        x.checked_mul(MAX_FN)
            .and_then(|s| s.checked_add(kx))
            .is_some_and(|s| s <= 1usize << log)
    };
    b.cycles <= 1usize << V12_FN_LOG_CYCLES
        && b.keys <= 1usize << V12_FN_LOG_KEYS
        && within(b.add, k.add, V12_LOG_ADD)
        && within(b.bit, k.bit, V12_LOG_BIT)
        && within(b.lt, k.lt, V12_LOG_LT)
        && within(b.shift, k.shift, V12_LOG_SHIFT)
        && within(b.mul, k.mul, V12_LOG_MUL)
        && within(b.poseidon, k.poseidon, V12_LOG_POSEIDON)
}

/// `blacksilk_tx::px::program_is_provable`, restated.
fn v12_program_ok(p: &Program) -> bool {
    let image = trace::image(p).len().max(MIN_HEIGHT).next_power_of_two();
    program_table::height(p, MIN_HEIGHT) <= 1usize << V12_FN_LOG_PROGRAM
        && image <= 1usize << V12_FN_LOG_IMAGE
}

/// Every budget field at its largest V12 value (`largest_allowed` in
/// tx/tests/deploy_rules.rs): `K.x + MAX_FN·b.x ≤ 2^cap` for the shared
/// tables.
fn v12_largest() -> Budget {
    let k = kernel_budget(MAX_FN);
    let shared = |kx: usize, log: u32| ((1usize << log) - kx) / MAX_FN;
    Budget {
        cycles: 1 << V12_FN_LOG_CYCLES,
        keys: 1 << V12_FN_LOG_KEYS,
        add: shared(k.add, V12_LOG_ADD),
        bit: shared(k.bit, V12_LOG_BIT),
        lt: shared(k.lt, V12_LOG_LT),
        shift: shared(k.shift, V12_LOG_SHIFT),
        mul: shared(k.mul, V12_LOG_MUL),
        poseidon: shared(k.poseidon, V12_LOG_POSEIDON),
    }
}

/// The vault program with its code padded by `NOP`s to `code_len` words.
/// The padding follows the vault's last instruction and is never executed;
/// the vault has no segment above its code, so the layout stays valid.
/// Different lengths give different program ids.
fn padded_vault(code_len: usize) -> Arc<Program> {
    let v = vault::program();
    assert!(code_len >= v.code.len(), "padding cannot shorten the vault");
    let mut code = v.code.clone();
    code.resize(code_len, NOP);
    Arc::new(
        Program::new(v.entry, v.code_base, code, v.data.clone())
            .expect("the padded vault is a valid program"),
    )
}

/// Image words besides the code: data and the 32 registers.
fn image_extra() -> usize {
    let v = vault::program();
    trace::image(&v).len() - v.code.len()
}

/// The V12 shape. Both functions run the vault (the CLAIM under `C`, the
/// LOCK under `C2`), padded where a program table must be taller; the two
/// programs differ.
///
/// `v12mem`, the memory-widest pair: every budget and program table at its
///   V12 cap; the function output tables at the vault's 2^8 rows (22 output
///   words; up to 2^9 are allowed with `MAX_FN_OUTPUT_WORDS` = 256 plus the
///   prefix, a negligible difference of about 0.04 M weighted cells). Both
///   budgets are `v12_largest()` (the V12 table: add and lt at
///   2^16, bit, shift and mul at 2^14, Poseidon2 at 2^11 shared rows; cycles
///   2^15 and keys 2^14 per function), and both programs have their program
///   and image tables at 2^14 rows (`2^14 - extra - KEY_ROOM` code words).
///   It is the budget-cap study's "every field at its cap" statement.
fn v12_shape(name: &str) -> Shape {
    match name {
        "v12mem" => {
            let top = v12_largest();
            let len = (1 << V12_FN_LOG_IMAGE) - image_extra() - KEY_ROOM;
            Shape {
                programs: [padded_vault(len), padded_vault(len - 1)],
                budgets: [top, top],
                v12: true,
            }
        }
        _ => panic!("unknown configuration {name}"),
    }
}

/// A function's own tables in `v12_schedule_search` (log2 heights).
#[derive(Clone, Copy, Debug)]
struct Own {
    code_len: usize,
    program_log: usize,
    image_log: usize,
    keys_log: usize,
    cycles_log: usize,
}

fn log2_ceil(n: usize) -> usize {
    n.max(MIN_HEIGHT).next_power_of_two().trailing_zeros() as usize
}

/// Every tuple of indices below `sizes`, last index fastest.
fn odometer(sizes: &[usize]) -> Vec<Vec<usize>> {
    let mut out = vec![vec![]];
    for &n in sizes {
        out = out
            .into_iter()
            .flat_map(|p: Vec<usize>| {
                (0..n).map(move |i| {
                    let mut q = p.clone();
                    q.push(i);
                    q
                })
            })
            .collect();
    }
    out
}

/// The longest-schedule V12 pair of vault-based functions. A proof's length grows
/// with its FRI rounds, and the folding schedule (`honest_fri_schedule`)
/// stops at every distinct table height, while the tallest table of every
/// PX statement is the 2^16-row byte table. The search enumerates every
/// allowed realization: each shared table at any height from the vault
/// pair's to its cap; per function, keys and cycles at any height from the
/// vault's to the cap, and a padded vault whose program and image tables are
/// at (h, h) or (h, h + 1) rows. It keeps the longest schedule, then the
/// most distinct heights, then the most rows, and realizes it with budgets
/// and programs whose real `Statement::shape` is asserted to match.
fn v12_schedule_search() -> Shape {
    let k = kernel_budget(MAX_FN);
    let v = vault::BUDGET;
    let top = v12_largest();
    let vault_len = vault::program().code.len();
    let extra = image_extra();
    // Shared tables: (index in `fields`, index in the shape).
    let shared: [(usize, usize); 6] = [(2, 5), (3, 6), (4, 7), (5, 8), (6, 9), (7, 11)];
    let (kf, vf, tf) = (fields(&k), fields(&v), fields(&top));
    let shared_opts: Vec<Vec<usize>> = shared
        .iter()
        .map(|&(f, _)| {
            let cap = log2_ceil(kf[f] + MAX_FN * tf[f]);
            (log2_ceil(kf[f] + MAX_FN * vf[f])..=cap).collect()
        })
        .collect();
    // Program variants: (code length, program log, image log, least keys log).
    let mut lens = vec![vault_len];
    for h in 12..=V12_FN_LOG_IMAGE as usize {
        lens.push((1 << h) - extra - KEY_ROOM);
        if h < V12_FN_LOG_IMAGE as usize {
            lens.push(1 << h);
        }
    }
    let mut variants: Vec<(usize, usize, usize, usize)> = Vec::new();
    for len in lens.into_iter().filter(|&l| l >= vault_len) {
        let p = padded_vault(len);
        let image_len = trace::image(&p).len();
        let pl = program_table::height(&p, MIN_HEIGHT).trailing_zeros() as usize;
        let il = log2_ceil(image_len);
        let kl = log2_ceil(v.keys.max(image_len + KEY_ROOM));
        if v12_program_ok(&p)
            && kl <= V12_FN_LOG_KEYS as usize
            && !variants.iter().any(|x| (x.1, x.2) == (pl, il))
        {
            variants.push((len, pl, il, kl));
        }
    }
    let mut owns: Vec<Own> = Vec::new();
    for &(code_len, program_log, image_log, kl) in &variants {
        for keys_log in kl..=V12_FN_LOG_KEYS as usize {
            for cycles_log in log2_ceil(v.cycles)..=V12_FN_LOG_CYCLES as usize {
                owns.push(Own {
                    code_len,
                    program_log,
                    image_log,
                    keys_log,
                    cycles_log,
                });
            }
        }
    }
    // The fixed heights: those of the vault pair.
    let f = fixture();
    let mut rng = ChaCha20Rng::seed_from_u64(0);
    let kernel_out = run_case(
        &function_case(&f, "claim_lock", 0, &mut rng, C2),
        &vault_registry(v, v),
    )
    .expect("the vault pair runs");
    let base: Vec<usize> = vault_degree_bits(kernel_out, &[v, v])
        .iter()
        .map(|d| d - 1)
        .collect();
    let heights = |sh: &[usize], o: [&Own; 2]| -> Vec<usize> {
        let mut h = base.clone();
        for (j, &(_, t)) in shared.iter().enumerate() {
            h[t] = shared_opts[j][sh[j]];
        }
        for (e, o) in o.iter().enumerate() {
            let b = 12 + 5 * e;
            h[b] = o.program_log;
            h[b + 1] = o.image_log;
            h[b + 2] = o.keys_log;
            h[b + 3] = o.cycles_log;
        }
        h
    };
    let shared_sizes: Vec<usize> = shared_opts.iter().map(Vec::len).collect();
    let tuples = odometer(&shared_sizes);
    type Best = ((usize, usize, usize), Vec<usize>, [usize; 2]);
    let mut best: Option<Best> = None;
    for sh in &tuples {
        for i in 0..owns.len() {
            // Symmetric in the two functions: i <= j covers every height set.
            for j in i..owns.len() {
                let h = heights(sh, [&owns[i], &owns[j]]);
                let distinct: BTreeSet<usize> = h.iter().cloned().collect();
                let rows: usize = h.iter().map(|&x| 1usize << x).sum();
                let db: Vec<usize> = h.iter().map(|x| x + 1).collect();
                let score = (
                    blacksilk_zk::honest_fri_schedule(&db).len(),
                    distinct.len(),
                    rows,
                );
                if best.as_ref().is_none_or(|b| score > b.0) {
                    best = Some((score, sh.clone(), [i, j]));
                }
            }
        }
    }
    let (score, sh, [i, j]) = best.expect("the vault pair itself is a realization");
    // Realize: shared sums `S` with `pow2(K + S) = 2^h`, split over the two
    // functions with each part at least the vault's and at most the cap.
    let mut b = [fields(&v), fields(&v)];
    for (n, &(fi, _)) in shared.iter().enumerate() {
        let h = shared_opts[n][sh[n]];
        let sum = (1usize << h).min(kf[fi] + MAX_FN * tf[fi]) - kf[fi];
        let b0 = tf[fi].min(sum - vf[fi]);
        let b1 = sum - b0;
        assert!(vf[fi] <= b0 && vf[fi] <= b1 && b1 <= tf[fi]);
        b[0][fi] = b0;
        b[1][fi] = b1;
    }
    let o = [owns[i], owns[j]];
    for e in 0..2 {
        b[e][0] = 1 << o[e].cycles_log;
        b[e][1] = 1 << o[e].keys_log;
    }
    // Distinct programs: one word more or less where both use one variant.
    let len1 = match (o[0].code_len == o[1].code_len, o[1].code_len == vault_len) {
        (false, _) => o[1].code_len,
        (true, true) => vault_len + 1,
        (true, false) => o[1].code_len - 1,
    };
    let shape = Shape {
        programs: [padded_vault(o[0].code_len), padded_vault(len1)],
        budgets: b.map(from_fields),
        v12: true,
    };
    let real: Vec<usize> = degree_bits(kernel_out, &shape.parts())
        .iter()
        .map(|d| d - 1)
        .collect();
    assert_eq!(
        real,
        heights(&sh, [&o[0], &o[1]]),
        "schedule search: the realization has the searched heights"
    );
    println!(
        "schedule search: {} shared-table choices x {} per function; best: {} FRI rounds, {} distinct heights, {} rows",
        tuples.len(),
        owns.len(),
        score.0,
        score.1,
        score.2
    );
    shape
}

/// The V12 deploy rules on a shape, after self-checks of the restatement.
fn v12_admit(name: &str, shape: &Shape) {
    assert_eq!(
        FN_RUN_LOG_CYCLES, V12_FN_LOG_CYCLES,
        "the prover's cycle stop is the cycles cap"
    );
    assert_eq!(MAX_FN, 2);
    let top = v12_largest();
    assert_eq!(
        fields(&top),
        V12_TABLE,
        "the restated caps give the pinned V12 table"
    );
    assert!(v12_budget_ok(&top));
    for (i, field) in FIELD_NAMES.iter().enumerate() {
        let mut f = fields(&top);
        f[i] += 1;
        assert!(!v12_budget_ok(&from_fields(f)), "{field} one above its cap");
    }
    assert!(v12_program_ok(&vault::program()));
    // The program rule at its boundary: an image of exactly 2^14 words is
    // allowed, one word more is refused.
    let at_cap = (1 << V12_FN_LOG_IMAGE) - image_extra();
    assert_eq!(
        trace::image(&padded_vault(at_cap)).len(),
        1 << V12_FN_LOG_IMAGE
    );
    assert!(v12_program_ok(&padded_vault(at_cap)), "image at the cap");
    assert!(
        !v12_program_ok(&padded_vault(at_cap + 1)),
        "image one word above the cap"
    );
    for e in 0..2 {
        assert!(
            v12_budget_ok(&shape.budgets[e]),
            "{name}: budget {e} {:?} is not allowed",
            shape.budgets[e]
        );
        assert!(
            v12_program_ok(&shape.programs[e]),
            "{name}: program {e} is not allowed"
        );
    }
    assert_ne!(
        shape.programs[0].id(),
        shape.programs[1].id(),
        "{name}: two distinct programs"
    );
    println!("{name}: both budgets and both programs pass the V12 deploy rules (restated)");
}

/// The native run of every function call against its budget, as the prover
/// checks it (`trace::usage`).
fn check_fit(c: &Case, reg: &Registry) {
    for (e, (contract, input)) in c.1.iter().enumerate() {
        let (p, b) = &reg[contract];
        let exec = blacksilk_zkvm::run(p, input, blacksilk_zkvm::MAX_CYCLES)
            .unwrap_or_else(|t| panic!("function {e}: {t:?}"));
        let used = trace::usage(p, &exec);
        for ((name, u), cap) in FIELD_NAMES.iter().zip(fields(&used)).zip(fields(b)) {
            assert!(u <= cap, "function {e}: {name} uses {u}, budget {cap}");
        }
        let image = trace::image(p).len();
        println!(
            "function {e}: {} code words, image {image}, used {:?} ({} keys outside the image), budget {:?}",
            p.code.len(),
            fields(&used),
            used.keys - image,
            fields(b)
        );
    }
}

/// The tables in proof order (`trace::tables`, kernel and two functions).
const TABLE_NAMES: [&str; 23] = [
    "byte",
    "k.program",
    "k.image",
    "k.mem_init",
    "k.cpu",
    "alu.add",
    "alu.bit",
    "alu.lt",
    "alu.shift",
    "alu.mul",
    "k.output",
    "poseidon2",
    "f0.program",
    "f0.image",
    "f0.mem_init",
    "f0.cpu",
    "f0.output",
    "f1.program",
    "f1.image",
    "f1.mem_init",
    "f1.cpu",
    "f1.output",
    "blind",
];

/// Million weighted cells of a statement: rows x (main width + 8 x quotient
/// chunks + 24), the budget-cap study's measure (lookup columns omitted).
fn weighted_cells(st: &Statement, verbose: bool) -> f64 {
    let heights = st.shape().unwrap();
    let db: Vec<usize> = heights
        .iter()
        .map(|h| h.trailing_zeros() as usize + 1)
        .collect();
    let airs = trace::tables(st);
    let widths = blacksilk_zk::analysis::trace_widths(&airs);
    let chunks = blacksilk_zk::analysis::quotient_chunks(&airs, &db);
    let mut cells = 0f64;
    for (t, &h) in heights.iter().enumerate() {
        let c = h * (widths[t] + 8 * chunks[t] + 24);
        cells += c as f64;
        if verbose {
            println!(
                "    {:<12} 2^{:<2} = {h:>6} rows, width {:>3}, quotient chunks {:>2}, {:>6.2} M cells",
                TABLE_NAMES[t],
                h.trailing_zeros(),
                widths[t],
                chunks[t],
                c as f64 / 1e6
            );
        }
    }
    cells / 1e6
}

/// Table heights, weighted cells and the budget-cap study's memory model.
fn report(name: &str, kernel_out: usize, shape: &Shape) {
    let st = statement(kernel_out, &shape.parts());
    let heights = st.shape().unwrap();
    assert_eq!(heights.len(), TABLE_NAMES.len());
    let db: Vec<usize> = heights
        .iter()
        .map(|h| h.trailing_zeros() as usize + 1)
        .collect();
    println!("{name}: budget C  {:?}", shape.budgets[0]);
    println!("{name}: budget C2 {:?}", shape.budgets[1]);
    println!("{name}: table heights");
    let cells = weighted_cells(&st, true);
    let v = vault::BUDGET;
    let vault_pair = [(vault::program(), v), (vault::program(), v)];
    let base = weighted_cells(&statement(kernel_out, &vault_pair), false);
    let distinct: BTreeSet<u32> = heights.iter().map(|h| h.trailing_zeros()).collect();
    println!(
        "{name}: tallest 2^{}, {} distinct heights {distinct:?}, FRI schedule {:?}",
        heights.iter().max().unwrap().trailing_zeros(),
        distinct.len(),
        blacksilk_zk::honest_fri_schedule(&db)
    );
    println!(
        "{name}: {cells:.1} M weighted cells (base {base:.1}); modelled peak memory L {:.0} MB, M {:.0} MB (docs/evidence/budget-cap-2026-10-04)",
        755.0 + 141.1 * cells,
        6446.0 + 235.0 * (cells - base)
    );
    if shape.v12 {
        assert!(
            heights.iter().all(|&h| h <= 1 << PX_MAX_LOG_HEIGHT),
            "{name}: every table within the PX shape check"
        );
    }
}

// ----------------------------------------------------------------- proving

struct Proved {
    p: Parts,
    bytes: Vec<u8>,
    prove_s: f64,
    verify_ms: Vec<f64>,
}

/// The registered function of each contract: its program and budget.
type Registry = HashMap<Digest, (Arc<Program>, Budget)>;

/// `C` and `C2` with the vault program and the given budgets.
fn vault_registry(b0: Budget, b1: Budget) -> Registry {
    [(C, (vault::program(), b0)), (C2, (vault::program(), b1))].into()
}

fn prove_case(c: &Case, reg: &Registry, rng: &mut ChaCha20Rng) -> Proved {
    let (w, calls) = c;
    let mut h = [0u8; 32];
    rng.fill_bytes(&mut h);
    let functions: Vec<_> = calls
        .iter()
        .map(|(c, input)| (reg[c].0.clone(), input.clone(), reg[c].1))
        .collect();
    let t = Instant::now();
    let (public, fcalls, proof) = if functions.is_empty() {
        let (public, proof) = prove_transfer(w, h, rng).expect("proves");
        (public, vec![], proof)
    } else {
        prove::prove(w, &functions, &W, h, rng).expect("proves")
    };
    let prove_s = t.elapsed().as_secs_f64();
    let bytes = blacksilk_zk::encode_proof(&proof);
    assert!(bytes.len() <= MAX_PROOF_BYTES, "{} bytes", bytes.len());
    // As a node receives it: strict decoding under the PX limits.
    let decoded = blacksilk_zk::decode_proof_with(&bytes, &prove::PROOF_LIMITS).expect("decodes");
    let ids: HashMap<Digest, ([u8; 32], Budget)> =
        reg.iter().map(|(c, (p, b))| (*c, (p.id(), *b))).collect();
    let registry =
        |c: &Digest, p: &[u8; 32]| ids.get(c).and_then(|(id, b)| (id == p).then_some(*b));
    let mut verify_ms = Vec::new();
    for _ in 0..3 {
        let t = Instant::now();
        assert_eq!(
            prove::verify(&public, &fcalls, &W, h, &decoded, registry),
            Ok(())
        );
        verify_ms.push(t.elapsed().as_secs_f64() * 1e3);
    }
    Proved {
        p: parts(&proof),
        bytes,
        prove_s,
        verify_ms,
    }
}

fn cmd_b2(name: &str, count: usize, dir: &Path, check_only: bool) {
    let f = fixture();
    let shape = config(name);
    if shape.v12 {
        v12_admit(name, &shape);
    } else {
        assert!(registrable(&shape.budgets[0]) && registrable(&shape.budgets[1]));
    }
    let reg = shape.registry();
    // The first case natively: kernel and function exits, prefixes, and every
    // function's use against its budget, as the prover checks them.
    let mut rng = ChaCha20Rng::seed_from_u64(30_000);
    let first = function_case(&f, "claim_lock", 0, &mut rng, C2);
    let kernel_out = run_case(&first, &reg).unwrap_or_else(|e| panic!("{name}: {e}"));
    check_fit(&first, &reg);
    report(name, kernel_out, &shape);
    if name == "v12mem" {
        // No vault-based V12 pair has more FRI rounds, and the search's
        // pick (most rounds, then distinct heights, then rows) folds exactly
        // as v12mem does.
        let s = v12_schedule_search();
        let schedule =
            |sh: &Shape| blacksilk_zk::honest_fri_schedule(&degree_bits(kernel_out, &sh.parts()));
        assert_eq!(
            schedule(&s),
            schedule(&shape),
            "v12mem has the search's schedule"
        );
        println!(
            "{name}: no vault-based V12 pair has more FRI rounds; schedule {:?}",
            schedule(&shape)
        );
    }
    if check_only {
        println!("{name}: check only, no proof");
        return;
    }
    let csv = dir.join("b2.csv");
    let done: BTreeSet<usize> = read_rows(&csv)
        .into_iter()
        .filter(|r| r.class == name)
        .map(|r| r.index)
        .collect();
    for k in 0..count {
        if done.contains(&k) {
            continue;
        }
        let mut rng = ChaCha20Rng::seed_from_u64(30_000 + k as u64);
        let c = function_case(&f, "claim_lock", k, &mut rng, C2);
        let r = prove_case(&c, &reg, &mut rng);
        println!(
            "b2 {name} #{k}: {} bytes (nondigest {}), prove {:.1} s, verify {:?} ms, schedule {:?}",
            r.p.total, r.p.nondigest, r.prove_s, r.verify_ms, r.p.step_arity
        );
        if k == 0 {
            std::fs::write(dir.join(format!("{name}.bin")), &r.bytes).unwrap();
        }
        write_row(
            &csv,
            &Row {
                kind: "b2".into(),
                n_fn: 2,
                class: name.into(),
                index: k,
                p: r.p,
                prove_s: r.prove_s,
                verify_ms: r.verify_ms,
            },
        );
    }
}

fn cmd_p5(n_fn: usize, per_class: usize, dir: &Path) {
    let f = fixture();
    let reg = vault_registry(vault::BUDGET, vault::BUDGET);
    let csv = dir.join("p5.csv");
    let rows = read_rows(&csv);
    let done: BTreeSet<usize> = rows
        .iter()
        .filter(|r| r.n_fn == n_fn)
        .map(|r| r.index)
        .collect();
    let mut nondigest: Option<usize> = rows.iter().find(|r| r.n_fn == n_fn).map(|r| r.p.nondigest);
    let names = classes(n_fn);
    for k in 0..per_class * names.len() {
        if done.contains(&k) {
            continue;
        }
        let class = names[k % names.len()];
        let mut rng = ChaCha20Rng::seed_from_u64(((n_fn as u64 + 1) << 32) + k as u64);
        let c = case(&f, n_fn, class, k / names.len(), &mut rng, C);
        let r = prove_case(&c, &reg, &mut rng);
        // Exact assertion (ZP-2): everything but the pruned digests has one
        // length per shape.
        assert_eq!(
            *nondigest.get_or_insert(r.p.nondigest),
            r.p.nondigest,
            "n_fn {n_fn}: non-digest bytes differ ({class} #{k})"
        );
        println!(
            "p5 n_fn {n_fn} {class} #{k}: {} bytes, digests {:?} / {:?}, prove {:.1} s",
            r.p.total, r.p.batch_digests, r.p.step_digests, r.prove_s
        );
        if k == 0 {
            std::fs::write(dir.join(format!("p5_nfn{n_fn}.bin")), &r.bytes).unwrap();
        }
        write_row(
            &csv,
            &Row {
                kind: "p5".into(),
                n_fn,
                class: class.into(),
                index: k,
                p: r.p,
                prove_s: r.prove_s,
                verify_ms: r.verify_ms,
            },
        );
    }
}

// --------------------------------------------------------------- the check

fn run_case(c: &Case, reg: &Registry) -> Result<usize, String> {
    let (w, calls) = c;
    let public = pxkernel::transfer(
        &mut HostPerm::new(),
        &mut blacksilk_px_core::kernel::SliceSource::new(&prove::witness_words(w)),
    )
    .map_err(|e| format!("native kernel: {e:?}"))?;
    let k = blacksilk_zkvm::run(
        &kernel_program(),
        &prove::witness_words(w),
        blacksilk_zkvm::MAX_CYCLES,
    )
    .map_err(|t| format!("kernel guest: {t:?}"))?;
    if k.exit_code != 0 || k.output != public_words(&public) {
        return Err("kernel guest diverged".into());
    }
    for (i, (c, input)) in calls.iter().enumerate() {
        let e = blacksilk_zkvm::run(&reg[c].0, input, blacksilk_zkvm::MAX_CYCLES)
            .map_err(|t| format!("function {i}: {t:?}"))?;
        let (contract, io_hash) = &public.functions[i];
        let prefix = function_prefix(ABI_VERSION, io_hash, contract, &W);
        if e.exit_code != 0 || e.output.len() < PREFIX_WORDS || e.output[..PREFIX_WORDS] != prefix {
            return Err(format!(
                "function {i}: exit {} or prefix mismatch",
                e.exit_code
            ));
        }
    }
    Ok(public_words(&public).len())
}

fn cmd_check() {
    let f = fixture();
    let vaults = vault_registry(vault::BUDGET, vault::BUDGET);
    let mut kernel_out = 0;
    for n_fn in 0..=2 {
        for class in classes(n_fn) {
            for k in 0..3 {
                let mut rng = ChaCha20Rng::seed_from_u64(k as u64);
                let c = case(&f, n_fn, class, k, &mut rng, C);
                kernel_out = run_case(&c, &vaults).unwrap_or_else(|e| panic!("{class} #{k}: {e}"));
            }
            println!("n_fn {n_fn} {class}: native kernel, guest and functions OK");
        }
    }
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    run_case(&function_case(&f, "claim_lock", 0, &mut rng, C2), &vaults)
        .expect("claim_lock with C2");
    for n_fn in 0..=2usize {
        let db = vault_degree_bits(kernel_out, &vec![vault::BUDGET; n_fn]);
        println!(
            "n_fn {n_fn} (vault budgets): degree bits {db:?}, LDE heights {:?}, schedule {:?}",
            lde_heights(&db),
            blacksilk_zk::honest_fri_schedule(&db)
        );
    }
    for name in CONFIGS {
        let shape = config(name);
        let [a, b] = shape.budgets;
        let db = degree_bits(kernel_out, &shape.parts());
        println!(
            "{name}: registrable (R7-5) {}, V12 {}, degree bits {db:?}, LDE heights {:?}, schedule {:?}",
            registrable(&a) && registrable(&b),
            shape.v12,
            lde_heights(&db),
            blacksilk_zk::honest_fri_schedule(&db)
        );
    }
}

// ------------------------------------------------------------------- model

/// Pruned digests and verifier compressions of a binary tree of `depth`
/// levels opened at `leaves` (the frontier walk of pruning.rs).
fn frontier(leaves: &mut Vec<usize>, depth: usize) -> (usize, usize) {
    leaves.sort_unstable();
    leaves.dedup();
    let mut cur = std::mem::take(leaves);
    let (mut digests, mut compressions) = (0, 0);
    for _ in 0..depth {
        let mut next = Vec::with_capacity(cur.len());
        let mut i = 0;
        while i < cur.len() {
            let parent = cur[i] >> 1;
            if i + 1 < cur.len() && cur[i + 1] >> 1 == parent {
                i += 2;
            } else {
                digests += 1;
                i += 1;
            }
            next.push(parent);
        }
        compressions += next.len();
        cur = next;
    }
    *leaves = cur;
    (digests, compressions)
}

/// The trees of a proof with `degree_bits` and `batches` input batches:
/// `(depth, shift)`, the leaf of query index `q` being `q >> shift`.
fn trees(degree_bits: &[usize], batches: usize) -> (usize, Vec<(usize, usize)>, Vec<usize>) {
    let m = degree_bits.iter().max().unwrap() + LOG_BLOWUP;
    let mut t = vec![(m, 0); batches];
    let schedule = blacksilk_zk::honest_fri_schedule(degree_bits);
    let mut cur = m;
    for &a in &schedule {
        t.push((cur - a, m - cur + a));
        cur -= a;
    }
    (m, t, schedule)
}

/// One draw of uniform query positions: per-tree digest counts and the
/// total verifier compressions.
fn draw(m: usize, t: &[(usize, usize)], rng: &mut ChaCha20Rng) -> (Vec<usize>, usize) {
    let q: Vec<usize> = (0..NUM_QUERIES)
        .map(|_| (rng.next_u64() as usize) & ((1usize << m) - 1))
        .collect();
    let mut counts = Vec::with_capacity(t.len());
    let mut comp = 0;
    for &(depth, shift) in t {
        let mut leaves: Vec<usize> = q.iter().map(|x| x >> shift).collect();
        let (d, c) = frontier(&mut leaves, depth);
        counts.push(d);
        comp += c;
    }
    (counts, comp)
}

/// Worst case over ANY query positions: at most `min(k, 2^(d-l-1))`
/// boundary digests at level `l`.
fn worst_digests(depth: usize) -> usize {
    (0..depth)
        .map(|l| NUM_QUERIES.min(1usize << (depth - l - 1)))
        .sum()
}

/// The encoded length of `base` with the given degree bits, folding
/// schedule and digest counts (the real encoder; see the module header).
fn synth(base: &[u8], degree_bits: &[usize], schedule: &[usize], counts: &[usize]) -> usize {
    let mut p = blacksilk_zk::decode_proof(base).unwrap();
    p.degree_bits = degree_bits.to_vec();
    let fri = &mut p.opening_proof.1;
    let nb = fri.input_openings.len();
    assert_eq!(counts.len(), nb + schedule.len());
    let digest = fri.input_openings[0].opening_proof.1.sibling_hashes[0];
    for (b, &c) in fri.input_openings.iter_mut().zip(counts) {
        b.opening_proof.1.sibling_hashes = vec![digest; c];
    }
    let tmpl = fri.commit_phase_openings[0].clone();
    let zero = tmpl.sibling_values[0][0];
    let queries = tmpl.sibling_values.len();
    let commit = fri.commit_phase_commits[0].clone();
    let pow = fri.commit_pow_witnesses.first().copied();
    fri.commit_phase_openings = schedule
        .iter()
        .zip(&counts[nb..])
        .map(|(&a, &c)| {
            let mut s = tmpl.clone();
            s.log_arity = a as u8;
            s.sibling_values = vec![vec![zero; (1 << a) - 1]; queries];
            s.opening_proof.1.sibling_hashes = vec![digest; c];
            s
        })
        .collect();
    fri.commit_phase_commits = vec![commit; schedule.len()];
    if let Some(w) = pow {
        fri.commit_pow_witnesses = vec![w; schedule.len()];
    }
    blacksilk_zk::encode_proof(&p).len()
}

fn mean(v: &[f64]) -> f64 {
    v.iter().sum::<f64>() / v.len() as f64
}

fn sd(v: &[f64]) -> f64 {
    let m = mean(v);
    (v.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / (v.len() as f64 - 1.0).max(1.0)).sqrt()
}

fn median(v: &[f64]) -> f64 {
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    s[s.len() / 2]
}

/// Two-sample KS statistic and its asymptotic p-value.
fn ks(a: &[f64], b: &[f64]) -> (f64, f64) {
    let mut sa = a.to_vec();
    let mut sb = b.to_vec();
    sa.sort_by(|x, y| x.partial_cmp(y).unwrap());
    sb.sort_by(|x, y| x.partial_cmp(y).unwrap());
    let (mut i, mut j, mut d) = (0, 0, 0f64);
    while i < sa.len() && j < sb.len() {
        let x = sa[i].min(sb[j]);
        while i < sa.len() && sa[i] <= x {
            i += 1;
        }
        while j < sb.len() && sb[j] <= x {
            j += 1;
        }
        d = d.max((i as f64 / sa.len() as f64 - j as f64 / sb.len() as f64).abs());
    }
    let n = (sa.len() * sb.len()) as f64 / (sa.len() + sb.len()) as f64;
    let lambda = (n.sqrt() + 0.12 + 0.11 / n.sqrt()) * d;
    let mut p = 0.0;
    for k in 1..100 {
        let k = k as f64;
        p += 2.0 * (-1f64).powi(k as i32 - 1) * (-2.0 * k * k * lambda * lambda).exp();
    }
    (d, p.clamp(0.0, 1.0))
}

/// Permutation p-values for the difference of means and KS statistic.
fn permutation(a: &[f64], b: &[f64], rng: &mut ChaCha20Rng) -> (f64, f64) {
    let (dm, dk) = ((mean(a) - mean(b)).abs(), ks(a, b).0);
    let pooled: Vec<f64> = a.iter().chain(b).cloned().collect();
    let rounds = 20_000;
    let (mut m, mut k) = (0, 0);
    let mut v = pooled.clone();
    for _ in 0..rounds {
        for i in (1..v.len()).rev() {
            let j = (rng.next_u64() % (i as u64 + 1)) as usize;
            v.swap(i, j);
        }
        let (x, y) = v.split_at(a.len());
        if (mean(x) - mean(y)).abs() >= dm - 1e-9 {
            m += 1;
        }
        if ks(x, y).0 >= dk - 1e-12 {
            k += 1;
        }
    }
    (m as f64 / rounds as f64, k as f64 / rounds as f64)
}

/// Every reachable set of table heights of a two-function statement: the
/// kernel's tables and Byte/Blind are fixed; each flexible table can take
/// any height in its range. Returns the reachable LDE-height sets with one
/// realization (per-table heights, log2).
struct Flex {
    name: &'static str,
    lo: usize,
    hi: usize,
}

fn realize(need: &[usize], flex: &[Flex]) -> Option<Vec<(usize, usize)>> {
    // Bipartite matching: heights to tables (augmenting paths).
    let mut owner: Vec<Option<usize>> = vec![None; flex.len()];
    fn aug(
        h: usize,
        need: &[usize],
        flex: &[Flex],
        seen: &mut [bool],
        owner: &mut [Option<usize>],
    ) -> bool {
        for t in 0..flex.len() {
            if !seen[t] && flex[t].lo <= need[h] && need[h] <= flex[t].hi {
                seen[t] = true;
                if owner[t].is_none() || aug(owner[t].unwrap(), need, flex, seen, owner) {
                    owner[t] = Some(h);
                    return true;
                }
            }
        }
        false
    }
    for h in 0..need.len() {
        let mut seen = vec![false; flex.len()];
        if !aug(h, need, flex, &mut seen, &mut owner) {
            return None;
        }
    }
    Some(
        owner
            .iter()
            .enumerate()
            .filter_map(|(t, o)| o.map(|h| (t, need[h])))
            .collect(),
    )
}

/// `(expected bytes, log2 heights, (table, height) assignment, schedule)`.
type Widest = (f64, BTreeSet<usize>, Vec<(usize, usize)>, Vec<usize>);

fn log2_pow2(n: usize) -> usize {
    n.max(blacksilk_zkvm::air::MIN_HEIGHT)
        .next_power_of_two()
        .trailing_zeros() as usize
}

fn cmd_model(dir: &Path) {
    let mut rows = read_rows(&dir.join("b2.csv"));
    rows.extend(read_rows(&dir.join("p5.csv")));
    let base_path = [dir.join("base.bin"), dir.join("p5_nfn2.bin")]
        .into_iter()
        .find(|p| p.exists())
        .expect("a two-function proof (base.bin or p5_nfn2.bin)");
    let base = std::fs::read(&base_path).unwrap();
    let base_parts = parts(&blacksilk_zk::decode_proof(&base).unwrap());
    let batches = base_parts.batch_digests.len();
    println!(
        "model base: {} ({} bytes, {batches} input batches)",
        base_path.display(),
        base_parts.total
    );

    // 1. Exact validation of the size model on every real proof of the
    //    two-function widths.
    let mut checked = 0;
    for r in rows.iter().filter(|r| r.n_fn == 2) {
        let (_, _, schedule) = trees(&r.p.degree_bits, batches);
        assert_eq!(
            schedule, r.p.step_arity,
            "{} {} #{}: schedule",
            r.kind, r.class, r.index
        );
        let counts: Vec<usize> =
            r.p.batch_digests
                .iter()
                .chain(&r.p.step_digests)
                .cloned()
                .collect();
        let s = synth(&base, &r.p.degree_bits, &schedule, &counts);
        assert_eq!(
            s, r.p.total,
            "{} {} #{}: model {s} vs real {}",
            r.kind, r.class, r.index, r.p.total
        );
        checked += 1;
    }
    println!("size model exact on {checked} real two-function proofs (every configuration)");

    // 2. Input batches share their digest count (one tree depth, one query
    //    set) in every real proof.
    let equal = rows
        .iter()
        .all(|r| r.p.batch_digests.iter().all(|&c| c == r.p.batch_digests[0]));
    println!("every real proof: all input batches have the same digest count: {equal}");

    // 3. Real digest counts vs uniform query positions, per shape/config.
    let mut rng = ChaCha20Rng::seed_from_u64(20_261_004);
    let mut groups: BTreeMap<(usize, String), Vec<&Row>> = BTreeMap::new();
    for r in &rows {
        let key = if r.kind == "p5" {
            (r.n_fn, "p5".to_string())
        } else {
            (r.n_fn, r.class.clone())
        };
        groups.entry(key).or_default().push(r);
    }
    for ((n_fn, g), rs) in &groups {
        let db = &rs[0].p.degree_bits;
        let (m, t, _) = trees(db, rs[0].p.batch_digests.len());
        let sims: Vec<(Vec<usize>, usize)> = (0..20_000).map(|_| draw(m, &t, &mut rng)).collect();
        let real_auth: Vec<f64> = rs
            .iter()
            .map(|r| {
                r.p.batch_digests
                    .iter()
                    .chain(&r.p.step_digests)
                    .sum::<usize>() as f64
            })
            .collect();
        let sim_auth: Vec<f64> = sims
            .iter()
            .map(|(c, _)| c.iter().sum::<usize>() as f64)
            .collect();
        let (d, p) = ks(&real_auth, &sim_auth);
        println!(
            "n_fn {n_fn} {g}: {} proofs; total digests real mean {:.1} sd {:.1}, uniform-query model mean {:.1} sd {:.1}; KS {d:.3}, p = {p:.3}",
            rs.len(),
            mean(&real_auth),
            sd(&real_auth),
            mean(&sim_auth),
            sd(&sim_auth)
        );
        for (i, _) in t.iter().enumerate() {
            let real: Vec<f64> = rs
                .iter()
                .map(|r| {
                    r.p.batch_digests
                        .iter()
                        .chain(&r.p.step_digests)
                        .nth(i)
                        .copied()
                        .unwrap() as f64
                })
                .collect();
            let sim: Vec<f64> = sims.iter().map(|(c, _)| c[i] as f64).collect();
            println!(
                "    tree {i} (depth {}): real mean {:.1}, model mean {:.1} sd {:.1}",
                t[i].0,
                mean(&real),
                mean(&sim),
                sd(&sim)
            );
        }
    }

    // 3b. P-5 class comparisons (sanity check only; ZP-2): per class, total
    //     bytes; pairwise permutation tests within each function count.
    for n_fn in 0..=2usize {
        let by: Vec<(&str, Vec<f64>)> = classes(n_fn)
            .iter()
            .map(|c| {
                (
                    *c,
                    rows.iter()
                        .filter(|r| r.kind == "p5" && r.n_fn == n_fn && r.class == *c)
                        .map(|r| r.p.total as f64)
                        .collect::<Vec<f64>>(),
                )
            })
            .filter(|(_, v)| v.len() > 1)
            .collect();
        for (c, v) in &by {
            println!(
                "p5 n_fn {n_fn} {c}: n {}, mean {:.0}, sd {:.0}, min {:.0}, max {:.0}",
                v.len(),
                mean(v),
                sd(v),
                v.iter().cloned().fold(f64::MAX, f64::min),
                v.iter().cloned().fold(0.0, f64::max)
            );
        }
        for a in 0..by.len() {
            for b in a + 1..by.len() {
                let (pm, pk) = permutation(&by[a].1, &by[b].1, &mut rng);
                println!(
                    "p5 n_fn {n_fn}: {} vs {}: mean difference {:.0} bytes, p(mean) = {pm:.3}, p(KS) = {pk:.3}",
                    by[a].0,
                    by[b].0,
                    (mean(&by[a].1) - mean(&by[b].1)).abs()
                );
            }
        }
    }

    // 4. The widest proof over every reachable set of table heights.
    let kernel_out = {
        let f = fixture();
        let mut rng = ChaCha20Rng::seed_from_u64(0);
        run_case(
            &function_case(&f, "claim_lock", 0, &mut rng, C),
            &vault_registry(vault::BUDGET, vault::BUDGET),
        )
        .unwrap()
    };
    let base_db = vault_degree_bits(kernel_out, &[vault::BUDGET, vault::BUDGET]);
    assert_eq!(base_db, base_parts.degree_bits);
    // Table order (trace::tables): 0 Byte, 1-4 kernel PROGRAM/IMAGE/MEM_INIT/CPU,
    // 5-9 ALU add/bit/lt/shift/mul, 10 kernel OUTPUT, 11 Poseidon2,
    // 12-16 function 0 PROGRAM/IMAGE/MEM_INIT/CPU/OUTPUT, 17-21 function 1, 22 Blind.
    let k2 = kernel_budget(2);
    let v = vault::BUDGET;
    let max_h = MAX_LOG_HEIGHT;
    let max_cpu = (blacksilk_zkvm::MAX_CYCLES as usize).trailing_zeros() as usize;
    let fixed_idx = [0usize, 1, 2, 3, 4, 10, 22];
    let shared = |kx: usize, fmin: usize| Flex {
        name: "shared",
        lo: log2_pow2(kx + 2 * fmin),
        hi: max_h,
    };
    // (a) Two functions running the reference vault program (its program,
    //     image and output tables fixed; budgets at or above its use).
    let vault_flex = |db: &[usize]| {
        let _ = db;
        vec![
            Flex {
                name: "add",
                ..shared(k2.add, v.add)
            },
            Flex {
                name: "bit",
                ..shared(k2.bit, v.bit)
            },
            Flex {
                name: "lt",
                ..shared(k2.lt, v.lt)
            },
            Flex {
                name: "shift",
                ..shared(k2.shift, v.shift)
            },
            Flex {
                name: "mul",
                ..shared(k2.mul, v.mul)
            },
            Flex {
                name: "poseidon",
                ..shared(k2.poseidon, v.poseidon)
            },
            Flex {
                name: "f0.keys",
                lo: log2_pow2(v.keys),
                hi: max_h,
            },
            Flex {
                name: "f0.cycles",
                lo: log2_pow2(v.cycles),
                hi: max_cpu,
            },
            Flex {
                name: "f1.keys",
                lo: log2_pow2(v.keys),
                hi: max_h,
            },
            Flex {
                name: "f1.cycles",
                lo: log2_pow2(v.cycles),
                hi: max_cpu,
            },
        ]
    };
    let vault_fixed: Vec<usize> = fixed_idx
        .iter()
        .chain(&[12, 13, 16, 17, 18, 21])
        .map(|&i| base_db[i] - 1)
        .collect();
    // (b) Any two registered programs: a minimal program reaches the
    //     smallest heights of its own tables; a 256 KiB ELF reaches at most
    //     2^16 program rows (MAX_PROGRAM_BYTES / 4).
    let min_l = blacksilk_zk::params::MIN_LOG_HEIGHT;
    let any_flex = || {
        let mut v = vec![
            Flex {
                name: "add",
                ..shared(k2.add, 0)
            },
            Flex {
                name: "bit",
                ..shared(k2.bit, 0)
            },
            Flex {
                name: "lt",
                ..shared(k2.lt, 0)
            },
            Flex {
                name: "shift",
                ..shared(k2.shift, 0)
            },
            Flex {
                name: "mul",
                ..shared(k2.mul, 0)
            },
            Flex {
                name: "poseidon",
                ..shared(k2.poseidon, 0)
            },
        ];
        for _ in 0..2 {
            v.push(Flex {
                name: "fn.program",
                lo: min_l,
                hi: 16,
            });
            v.push(Flex {
                name: "fn.image",
                lo: min_l,
                hi: 16,
            });
            v.push(Flex {
                name: "fn.keys",
                lo: min_l,
                hi: max_h,
            });
            v.push(Flex {
                name: "fn.cycles",
                lo: min_l,
                hi: max_cpu,
            });
            v.push(Flex {
                name: "fn.output",
                lo: min_l,
                hi: min_l + 2,
            });
        }
        v
    };
    let any_fixed: Vec<usize> = fixed_idx.iter().map(|&i| base_db[i] - 1).collect();

    // Expected digests per tree depth under uniform queries.
    let mut e_digest = vec![0f64; 32];
    for (d, e) in e_digest.iter_mut().enumerate().take(28) {
        let n = 4_000;
        let mut s = 0usize;
        for _ in 0..n {
            let mut l: Vec<usize> = (0..NUM_QUERIES)
                .map(|_| (rng.next_u64() as usize) & ((1usize << d) - 1))
                .collect();
            s += frontier(&mut l, d).0;
        }
        *e = s as f64 / n as f64;
    }
    // Expected size of a height set (log2 table heights), memoized on the
    // schedule: the non-digest bytes depend on the schedule only.
    let mut memo: HashMap<Vec<usize>, usize> = HashMap::new();
    let mut expected = |heights: &BTreeSet<usize>| -> (f64, Vec<usize>) {
        // Synthetic degree bits with exactly these heights (23 tables).
        let mut db: Vec<usize> = heights.iter().map(|h| h + 1).collect();
        while db.len() < base_db.len() {
            db.push(db[0]);
        }
        let (_, t, schedule) = trees(&db, batches);
        let zero = *memo
            .entry(schedule.clone())
            .or_insert_with(|| synth(&base, &db, &schedule, &vec![0; t.len()]));
        let dig: f64 = t
            .iter()
            .map(|&(d, _)| 32.0 * e_digest[d] + varint_len(e_digest[d] as usize) as f64 - 1.0)
            .sum();
        (zero as f64 + dig, schedule)
    };
    for (label, fixed, flex) in [
        ("vault programs", vault_fixed.clone(), vault_flex(&base_db)),
        ("any programs", any_fixed.clone(), any_flex()),
    ] {
        let fixed_set: BTreeSet<usize> = fixed.iter().cloned().collect();
        let free: Vec<usize> = (min_l..=max_h).filter(|h| !fixed_set.contains(h)).collect();
        let mut best: Option<Widest> = None;
        let mut reachable = 0;
        for mask in 0u32..(1 << free.len()) {
            let extra: Vec<usize> = free
                .iter()
                .enumerate()
                .filter(|(i, _)| mask >> i & 1 == 1)
                .map(|(_, &h)| h)
                .collect();
            let Some(assign) = realize(&extra, &flex) else {
                continue;
            };
            // Every flexible table not assigned must sit at a height already
            // in the set (its minimum, or any reachable member).
            let set: BTreeSet<usize> = fixed_set.iter().chain(&extra).cloned().collect();
            let assigned: BTreeSet<usize> = assign.iter().map(|&(t, _)| t).collect();
            let ok = (0..flex.len())
                .filter(|t| !assigned.contains(t))
                .all(|t| set.iter().any(|&h| flex[t].lo <= h && h <= flex[t].hi));
            if !ok {
                continue;
            }
            reachable += 1;
            let (e, schedule) = expected(&set);
            if best.as_ref().is_none_or(|b| e > b.0) {
                best = Some((e, set, assign, schedule));
            }
        }
        let (e, set, assign, schedule) = best.unwrap();
        println!(
            "\nwidest, {label}: {reachable} reachable height sets; largest expected size {e:.0} bytes"
        );
        println!("  table heights (log2) {set:?}, schedule {schedule:?}");
        for (t, h) in &assign {
            println!("    {} at 2^{h}", flex[*t].name);
        }
        if label == "vault programs" {
            // Realize it with registrable budgets and the real statement shape.
            let mut b = [v, v];
            for (t, h) in &assign {
                let target = 1usize << h;
                match flex[*t].name {
                    "add" => b[0].add = target - k2.add - v.add,
                    "bit" => b[0].bit = target - k2.bit - v.bit,
                    "lt" => b[0].lt = target - k2.lt - v.lt,
                    "shift" => b[0].shift = target - k2.shift - v.shift,
                    "mul" => b[0].mul = target - k2.mul - v.mul,
                    "poseidon" => b[0].poseidon = target - k2.poseidon - v.poseidon,
                    "f0.keys" => b[0].keys = target,
                    "f0.cycles" => b[0].cycles = target,
                    "f1.keys" => b[1].keys = target,
                    "f1.cycles" => b[1].cycles = target,
                    _ => unreachable!(),
                }
            }
            let db = vault_degree_bits(kernel_out, &b);
            let real: BTreeSet<usize> = db.iter().map(|d| d - 1).collect();
            println!("  budgets: C {:?}", b[0]);
            println!("           C2 {:?}", b[1]);
            println!(
                "  registrable: {}; statement heights {real:?} (equal to the set: {})",
                registrable(&b[0]) && registrable(&b[1]),
                real == set
            );
        }
        // Also the largest at each maximum height (how the bound depends on
        // MAX_LOG_HEIGHT).
        let _ = &e;
        // Distribution at the widest set (joint draws of one query set).
        let mut db: Vec<usize> = set.iter().map(|h| h + 1).collect();
        while db.len() < base_db.len() {
            db.push(db[0]);
        }
        let (m, t, schedule) = trees(&db, batches);
        let zero = synth(&base, &db, &schedule, &vec![0; t.len()]);
        let mut sizes = Vec::new();
        let mut comps = Vec::new();
        for _ in 0..20_000 {
            let (c, comp) = draw(m, &t, &mut rng);
            sizes.push((zero + c.iter().map(|&x| digest_bytes(x) - 1).sum::<usize>()) as f64);
            comps.push(comp as f64);
        }
        let worst = zero
            + t.iter()
                .map(|&(d, _)| digest_bytes(worst_digests(d)) - 1)
                .sum::<usize>();
        let over = |x: f64| sizes.iter().filter(|&&s| s > x).count() as f64 / sizes.len() as f64;
        let max = sizes.iter().cloned().fold(0.0, f64::max);
        let min = sizes.iter().cloned().fold(f64::MAX, f64::min);
        println!(
            "  20,000 uniform query draws: mean {:.0}, sd {:.0}, min {min:.0}, max {max:.0}; P(> 3.8 MB) = {:.4}, P(> 4 MiB) = {:.4}",
            mean(&sizes),
            sd(&sizes),
            over(AGENT22_BYTES as f64),
            over(MAX_PROOF_BYTES as f64)
        );
        println!("  worst case over any query positions: {worst} bytes");
        println!("  verifier compressions: mean {:.0}", mean(&comps));
        WIDEST.with(|w| {
            w.borrow_mut()
                .push((label.to_string(), db.clone(), mean(&comps)))
        });
    }

    // 5. Verifier time: real medians per configuration against the model's
    //    compressions, and a microbenchmark of one 2-to-1 compression.
    use p3_symmetric::PseudoCompressionFunction;
    let compress = blacksilk_zk::config::Compress::new(blacksilk_zk::config::permutation());
    let mut x = [[<p3_baby_bear::BabyBear as p3_field::PrimeCharacteristicRing>::ONE; 8]; 2];
    let n = 2_000_000;
    let t0 = Instant::now();
    for _ in 0..n {
        let y = compress.compress(x);
        x[0] = y;
    }
    let per = t0.elapsed().as_secs_f64() / n as f64;
    println!(
        "\none Poseidon2 2-to-1 compression: {:.3} us ({:?})",
        per * 1e6,
        x[0][0]
    );
    let mut points = Vec::new();
    for ((n_fn, g), rs) in &groups {
        if *n_fn != 2 {
            continue;
        }
        let db = &rs[0].p.degree_bits;
        let (m, t, _) = trees(db, batches);
        let comp = mean(
            &(0..4_000)
                .map(|_| draw(m, &t, &mut rng).1 as f64)
                .collect::<Vec<_>>(),
        );
        let v: Vec<f64> = rs.iter().map(|r| median(&r.verify_ms)).collect();
        println!(
            "n_fn 2 {g}: verify median of medians {:.1} ms (min {:.1}, max {:.1}), model compressions {comp:.0}",
            median(&v),
            v.iter().cloned().fold(f64::MAX, f64::min),
            v.iter().cloned().fold(0.0, f64::max)
        );
        points.push((comp, median(&v)));
    }
    if let Some(&(c0, t0)) = points.iter().min_by(|a, b| a.0.partial_cmp(&b.0).unwrap()) {
        // Least-squares slope through the measured configurations.
        let n = points.len() as f64;
        let (mx, my) = (
            points.iter().map(|p| p.0).sum::<f64>() / n,
            points.iter().map(|p| p.1).sum::<f64>() / n,
        );
        let sxy: f64 = points.iter().map(|p| (p.0 - mx) * (p.1 - my)).sum();
        let sxx: f64 = points.iter().map(|p| (p.0 - mx) * (p.0 - mx)).sum();
        let slope = if sxx > 0.0 { sxy / sxx } else { f64::NAN };
        println!(
            "fitted slope {:.3} us per compression (microbenchmark {:.3} us)",
            slope * 1e3,
            per * 1e6
        );
        WIDEST.with(|w| {
            for (label, _, comp) in w.borrow().iter() {
                let fit = t0 + slope * (comp - c0);
                let micro = t0 + per * 1e3 * (comp - c0);
                println!(
                    "verifier, widest ({label}): about {fit:.0} ms (fitted slope), {micro:.0} ms (compression cost only), from {t0:.0} ms at {c0:.0} compressions"
                );
            }
        });
    }
}

thread_local! {
    static WIDEST: std::cell::RefCell<Vec<(String, Vec<usize>, f64)>> = const { std::cell::RefCell::new(Vec::new()) };
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = |i: usize| -> PathBuf {
        let d = PathBuf::from(&args[i]);
        std::fs::create_dir_all(&d).unwrap();
        d
    };
    match args.get(1).map(String::as_str) {
        Some("check") => cmd_check(),
        Some("b2") => cmd_b2(
            &args[2],
            args[3].parse().unwrap(),
            &dir(4),
            match args.get(5).map(String::as_str) {
                None => false,
                Some("--check-only") => true,
                Some(x) => panic!("unknown flag {x}"),
            },
        ),
        Some("p5") => cmd_p5(args[2].parse().unwrap(), args[3].parse().unwrap(), &dir(4)),
        Some("model") => cmd_model(&dir(2)),
        _ => eprintln!("usage: freeze_b2_b3 check | b2 <config> <count> <dir> [--check-only] | p5 <n_fn> <per class> <dir> | model <dir>"),
    }
}
