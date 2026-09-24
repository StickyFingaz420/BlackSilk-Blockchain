//! The unified proof (docs/px.md §7): a contract function and the kernel in
//! one batch proof. Uses the example vault contract (`zkvm/guests/vault`):
//! LOCK puts value under a hash lock, CLAIM releases it to a recipient.

use blacksilk_px::perm::HostPerm;
use blacksilk_px::prove::{self, kernel_program, witness_words, TransferError, VerifyError};
use blacksilk_px::state::State;
use blacksilk_px::tree::Tree;
use blacksilk_px::wallet::{self, Account};
use blacksilk_px_core::call::OutSpec;
use blacksilk_px_core::hash::hash;
use blacksilk_px_core::kernel::{self, Error, FunctionWitness, Public, SliceSource, Witness};
use blacksilk_px_core::record::Record;
use blacksilk_px_core::{Digest, ZERO_DIGEST};
use blacksilk_zkvm::air::trace::{self, Budget, Statement};
use blacksilk_zkvm::{run, Program, MAX_CYCLES};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::{Arc, OnceLock};

const LOCK_DOMAIN: u32 = 0x5641_0001;
const C: Digest = [0x100, 1, 2, 3, 4, 5, 6, 7];
const OTHER: Digest = [0x200, 1, 2, 3, 4, 5, 6, 7];

fn vault() -> Arc<Program> {
    static P: OnceLock<Arc<Program>> = OnceLock::new();
    P.get_or_init(|| Arc::new(Program::from_elf(include_bytes!("fixtures/vault.elf")).unwrap()))
        .clone()
}

/// The vault's registered row budget: measured use of the larger of LOCK and
/// CLAIM plus ~6% (checked in `budgets_leave_headroom`).
const VAULT_BUDGET: Budget = Budget {
    cycles: 6_000,
    keys: 2_200,
    add: 4_300,
    bit: 200,
    lt: 3_400,
    shift: 200,
    mul: 200,
    poseidon: 22,
};

/// The consensus registry of the test: the vault program belongs to `C`,
/// with `VAULT_BUDGET`.
fn registry(contract: &Digest, program: &[u8; 32]) -> Option<Budget> {
    (*contract == C && *program == vault().id()).then_some(VAULT_BUDGET)
}

fn lock_of(secret: &Digest) -> Digest {
    hash(&mut HostPerm::new(), LOCK_DOMAIN, &[secret])
}

fn words(parts: &[&[u32]]) -> Vec<u32> {
    parts.concat()
}

/// LOCK: the function's input and the kernel's view of its transcript.
fn lock_call(value: u64, lock: Digest, j: usize, blind: Digest) -> (Vec<u32>, FunctionWitness) {
    let input = words(&[
        &[0],
        &C,
        &blind,
        &[value as u32, (value >> 32) as u32],
        &lock,
        &[j as u32],
    ]);
    let mut spec = [None; 2];
    spec[j] = Some(OutSpec {
        owner: ZERO_DIGEST,
        contract: C,
        value,
        data: lock,
    });
    let fw = FunctionWitness {
        contract: C,
        blind,
        approve: [false; 2],
        spec,
    };
    (input, fw)
}

/// CLAIM of vault record `rec` (input slot `i`) to `recipient` (output `j`).
fn claim_call(
    rec: &Record,
    secret: Digest,
    recipient: Digest,
    i: usize,
    j: usize,
    blind: Digest,
) -> (Vec<u32>, FunctionWitness) {
    let input = words(&[
        &[1],
        &C,
        &blind,
        &[rec.value as u32, (rec.value >> 32) as u32],
        &rec.data,
        &rec.rho,
        &rec.rcm,
        &secret,
        &recipient,
        &[i as u32, j as u32],
    ]);
    let mut approve = [false; 2];
    approve[i] = true;
    let mut spec = [None; 2];
    spec[j] = Some(OutSpec {
        owner: recipient,
        contract: ZERO_DIGEST,
        value: rec.value,
        data: [0; 8],
    });
    let fw = FunctionWitness {
        contract: C,
        blind,
        approve,
        spec,
    };
    (input, fw)
}

fn with_functions(mut w: Witness, fns: &[FunctionWitness]) -> Witness {
    w.n_fn = fns.len();
    for (k, f) in fns.iter().enumerate() {
        w.functions[k] = Some(*f);
    }
    w
}

fn native(w: &Witness) -> Result<Public, Error> {
    kernel::transfer(
        &mut HostPerm::new(),
        &mut SliceSource::new(&witness_words(w)),
    )
}

struct Setup {
    rng: ChaCha20Rng,
    state: State,
    tree: Tree,
    bob: Account,
    secret: Digest,
    /// The vault record in the tree and its position.
    vault_rec: Record,
    vault_pos: u64,
}

/// Runs LOCK (proven and verified), applies it, and returns the setup for
/// CLAIM.
fn locked() -> Setup {
    locked_with(true)
}

/// As [`locked`]; without `prove_it`, the LOCK statement comes from the
/// native kernel (same state, no proof), for tests that only need the setup.
fn locked_with(prove_it: bool) -> Setup {
    let mut rng = ChaCha20Rng::seed_from_u64(31);
    let mut perm = HostPerm::new();
    let mut state = State::new();
    let mut tree = Tree::new(&mut perm);
    let bob = Account::from_seed(&[4; 32]);
    let secret = wallet::random_digest(&mut rng);
    let lock = lock_of(&secret);
    let blind = wallet::random_digest(&mut rng);
    let (input, fw) = lock_call(500, lock, 0, blind);
    let outs = [
        wallet::contract_output(&mut rng, C, 500, lock),
        wallet::empty_output(&mut rng),
    ];
    let w = with_functions(
        wallet::witness(
            state.root(),
            500,
            0,
            [wallet::dummy_input(&mut rng), wallet::dummy_input(&mut rng)],
            outs.clone(),
        ),
        &[fw],
    );
    let public = if prove_it {
        let (public, calls, proof) =
            prove::prove(&w, &[(vault(), input, VAULT_BUDGET)], [5; 32], &mut rng)
                .expect("LOCK proves");
        assert_eq!(calls[0].outputs, vec![0]); // the public selector
        assert_eq!(
            prove::verify(&public, &calls, [5; 32], &proof, registry),
            Ok(())
        );
        public
    } else {
        native(&w).expect("LOCK is valid")
    };
    state.apply_block(&[public]).unwrap();
    let recs: Vec<Record> = (0..2)
        .map(|j| wallet::created_record(&public, j, &outs[j]))
        .collect();
    let mut pos = Vec::new();
    for r in &recs {
        let cm = r.commit(&mut perm);
        pos.push(tree.append(&mut perm, cm).unwrap());
    }
    assert_eq!(tree.root(), state.root());
    Setup {
        rng,
        state,
        tree,
        bob,
        secret,
        vault_rec: recs[0],
        vault_pos: pos[0],
    }
}

fn claim_witness(s: &mut Setup, secret: Digest, recipient: Digest) -> (Vec<u32>, Witness) {
    let blind = wallet::random_digest(&mut s.rng);
    let (input, fw) = claim_call(&s.vault_rec, secret, recipient, 0, 0, blind);
    let path = s.tree.path(s.vault_pos).unwrap();
    let inputs = [
        wallet::contract_input(&mut s.rng, &s.vault_rec, s.vault_pos, path),
        wallet::dummy_input(&mut s.rng),
    ];
    let outs = [
        wallet::output(&mut s.rng, recipient, s.vault_rec.value),
        wallet::empty_output(&mut s.rng),
    ];
    let w = with_functions(wallet::witness(s.tree.root(), 0, 0, inputs, outs), &[fw]);
    (input, w)
}

#[test]
fn lock_then_claim_proves_verifies_and_pays_the_recipient() {
    let mut s = locked();
    let bob_owner = s.bob.owner(0);
    let secret = s.secret;
    let (input, w) = claim_witness(&mut s, secret, bob_owner);
    let t = std::time::Instant::now();
    let (public, calls, proof) =
        prove::prove(&w, &[(vault(), input, VAULT_BUDGET)], [6; 32], &mut s.rng)
            .expect("CLAIM proves");
    let size = blacksilk_zk::encode_proof(&proof).len();
    println!(
        "unified proof (kernel + vault): {size} bytes, {:.1?}",
        t.elapsed()
    );
    assert_eq!(
        prove::verify(&public, &calls, [6; 32], &proof, registry),
        Ok(())
    );
    // Bob receives the vault's value.
    let bob_rec = wallet::created_record(&public, 0, &w.outputs[0]);
    assert_eq!((bob_rec.owner, bob_rec.value), (bob_owner, 500));
    assert_eq!(bob_rec.commit(&mut HostPerm::new()), public.commitments[0]);

    // Verification needs the registry: an unregistered program is refused.
    assert_eq!(
        prove::verify(&public, &calls, [6; 32], &proof, |_, _| None),
        Err(VerifyError::Unregistered(0))
    );
    // The same proof as a plain transfer, or with the function dropped.
    assert_eq!(
        prove::verify_transfer(&public, [6; 32], &proof),
        Err(VerifyError::Shape)
    );
    // Altered function outputs, io_hash, contract or binding: rejected.
    let mut bad_calls = calls.clone();
    bad_calls[0].outputs[0] = 0;
    assert!(prove::verify(&public, &bad_calls, [6; 32], &proof, registry).is_err());
    let mut p = public;
    p.functions[0].1[0] ^= 1;
    assert!(prove::verify(&p, &calls, [6; 32], &proof, registry).is_err());
    assert!(prove::verify(&public, &calls, [7; 32], &proof, registry).is_err());

    // The state accepts the claim once.
    s.state.apply_block(&[public]).unwrap();
    assert!(s.state.apply_block(&[public]).is_err());
}

#[test]
fn a_wrong_secret_cannot_claim() {
    let mut s = locked();
    let wrong = wallet::random_digest(&mut s.rng);
    let bob_owner = s.bob.owner(0);
    let (input, w) = claim_witness(&mut s, wrong, bob_owner);
    // The kernel alone accepts (it cannot see the lock logic); the function
    // halts with its error code, so no proof exists.
    assert!(native(&w).is_ok());
    let exec = run(&vault(), &input, MAX_CYCLES).unwrap();
    assert_eq!(exec.exit_code, 2);
    assert!(matches!(
        prove::prove(&w, &[(vault(), input, VAULT_BUDGET)], [6; 32], &mut s.rng),
        Err(TransferError::Execution(_))
    ));
}

/// The kernel's contract rules, each violated alone (natively and in the
/// guest, with the same error).
#[test]
fn contract_rules_reject_their_violations() {
    let mut s = locked();
    let bob_owner = s.bob.owner(0);
    let eve = Account::from_seed(&[9; 32]).owner(0);
    let secret = s.secret;
    let (_, base) = claim_witness(&mut s, secret, bob_owner);
    assert!(native(&base).is_ok());
    let mut cases: Vec<(&str, Witness, Error)> = Vec::new();
    let mut add = |name: &'static str, f: &dyn Fn(&mut Witness), e: Error| {
        let mut w = base.clone();
        f(&mut w);
        cases.push((name, w, e));
    };
    // The caller redirects the payout: the function specified Bob.
    add(
        "redirect",
        &|w| w.outputs[0].owner = eve,
        Error::SpecMismatch,
    );
    add("amount", &|w| w.outputs[0].value -= 1, Error::SpecMismatch);
    // Spending the vault record without its function.
    add("no function", &|w| w.n_fn = 0, Error::Unauthorized);
    // The function approves the dummy too.
    add(
        "approve dummy",
        &|w| {
            let f = w.functions[0].as_mut().unwrap();
            f.approve = [true, true];
        },
        Error::ApprovalMismatch,
    );
    // The function approves only the dummy: the vault record is unauthorized
    // (checked first, at input 0).
    add(
        "approve only dummy",
        &|w| {
            let f = w.functions[0].as_mut().unwrap();
            f.approve = [false, true];
        },
        Error::Unauthorized,
    );
    // A function of another contract approves the vault record.
    add(
        "foreign approval",
        &|w| w.functions[0].as_mut().unwrap().contract = OTHER,
        Error::ApprovalMismatch,
    );
    // Creating a record of the contract without its function.
    add(
        "forge contract output",
        &|w| {
            w.outputs[1].contract = C;
            w.outputs[1].owner = ZERO_DIGEST;
        },
        Error::Unauthorized,
    );
    // A function specifying a record of another contract.
    add(
        "foreign spec",
        &|w| {
            let f = w.functions[0].as_mut().unwrap();
            f.spec[1] = Some(OutSpec {
                owner: ZERO_DIGEST,
                contract: OTHER,
                value: 0,
                data: [0; 8],
            });
        },
        Error::SpecForeignContract,
    );
    // Two functions specifying one output.
    add(
        "conflict",
        &|w| {
            let mut f2 = w.functions[0].unwrap();
            f2.approve = [false, false];
            w.functions[1] = Some(f2);
            w.n_fn = 2;
        },
        Error::SpecConflict,
    );
    add(
        "zero contract",
        &|w| w.functions[0].as_mut().unwrap().contract = ZERO_DIGEST,
        Error::ZeroContract,
    );
    add(
        "dummy contract",
        &|w| {
            w.inputs[1].contract = C;
        },
        Error::DummyContract,
    );
    // A contract record's owner is fixed to 0: a record with the vault's
    // contents under another contract is not in the tree.
    add(
        "other contract input",
        &|w| {
            w.inputs[0].contract = OTHER;
            w.functions[0].as_mut().unwrap().contract = OTHER;
            w.functions[0].as_mut().unwrap().spec = [None, None];
        },
        Error::NotInTree,
    );
    let mut n = 0;
    for (name, w, e) in &cases {
        let got = native(w).err();
        assert_eq!(got, Some(*e), "case {name}");
        let exec = run(&kernel_program(), &witness_words(w), MAX_CYCLES).unwrap();
        assert_eq!(exec.exit_code, e.exit_code(), "guest, case {name}");
        n += 1;
    }
    println!("{n} contract rejection cases");
}

/// A function whose transcript differs from the kernel's (another blind, an
/// approval of another record) is detected: its `io_hash` differs, so the
/// statement cannot be satisfied.
#[test]
fn a_function_transcript_must_match_the_kernel() {
    let mut s = locked();
    let bob_owner = s.bob.owner(0);
    let secret = s.secret;
    let (input, w) = claim_witness(&mut s, secret, bob_owner);
    let mut other = input.clone();
    other[9] ^= 1; // the blind
    assert!(matches!(
        prove::prove(&w, &[(vault(), other, VAULT_BUDGET)], [6; 32], &mut s.rng),
        Err(TransferError::FunctionMismatch(0))
    ));
    // The kernel's io_hash equals the function's for the matching transcript.
    let public = native(&w).unwrap();
    let exec = run(&vault(), &input, MAX_CYCLES).unwrap();
    assert_eq!(exec.output[..8], public.functions[0].1);
}

/// Kernel executions with a contract input and with a user input do the same
/// work: the kernel's table heights are identical.
#[test]
fn record_kinds_are_not_revealed_by_trace_heights() {
    let mut s = locked();
    let bob_owner = s.bob.owner(0);
    let secret = s.secret;
    let (_, contract_w) = claim_witness(&mut s, secret, bob_owner);
    // A user-record spend with one (LOCK) function and the same shape.
    let mut perm = HostPerm::new();
    let alice = Account::from_seed(&[3; 32]);
    let rec = Record::plain(
        alice.owner(0),
        70,
        [0; 8],
        wallet::random_digest(&mut s.rng),
        wallet::random_digest(&mut s.rng),
    );
    let cm = rec.commit(&mut perm);
    let pos = s.tree.append(&mut perm, cm).unwrap();
    let blind = wallet::random_digest(&mut s.rng);
    let (_, fw) = lock_call(70, lock_of(&secret), 0, blind);
    let user_w = with_functions(
        wallet::witness(
            s.tree.root(),
            0,
            0,
            [
                alice.spend(0, &rec, pos, s.tree.path(pos).unwrap()),
                wallet::dummy_input(&mut s.rng),
            ],
            [
                wallet::contract_output(&mut s.rng, C, 70, lock_of(&secret)),
                wallet::empty_output(&mut s.rng),
            ],
        ),
        &[fw],
    );
    let mut heights = Vec::new();
    let mut cycles = Vec::new();
    for w in [&contract_w, &user_w] {
        let public = native(w).expect("valid");
        let exec = run(&kernel_program(), &witness_words(w), MAX_CYCLES).unwrap();
        cycles.push(exec.steps.len());
        let st = Statement::single(
            kernel_program(),
            0,
            blacksilk_px::prove::public_words(&public),
            [0; 32],
        );
        heights.push(
            trace::build(&st, &exec)
                .iter()
                .map(|t| t.values.len() / t.width)
                .collect::<Vec<_>>(),
        );
    }
    println!("kernel cycles: {cycles:?}");
    assert_eq!(heights[0], heights[1]);
}

fn fits(name: &str, used: &Budget, budget: &Budget, errors: &mut Vec<String>) {
    let pairs = [
        ("cycles", used.cycles, budget.cycles),
        ("keys", used.keys, budget.keys),
        ("add", used.add, budget.add),
        ("bit", used.bit, budget.bit),
        ("lt", used.lt, budget.lt),
        ("shift", used.shift, budget.shift),
        ("mul", used.mul, budget.mul),
        ("poseidon", used.poseidon, budget.poseidon),
    ];
    for (t, u, b) in pairs {
        // 95%: headroom against small future changes; a witness can never
        // leak through the shape, it can only fail to prove.
        if u * 100 > b * 95 {
            errors.push(format!("{name}: {t} uses {u} of {b}"));
        }
    }
}

/// Every tested execution uses at most 95% of each budgeted table: the
/// kernel with 0, 1 and 2 functions (user, contract and dummy inputs), and
/// both vault functions.
#[test]
fn budgets_leave_headroom() {
    let mut s = locked_with(false);
    let mut errors = Vec::new();
    let bob_owner = s.bob.owner(0);
    let secret = s.secret;
    let (claim_input, claim_w) = claim_witness(&mut s, secret, bob_owner);
    // n_fn = 0: a dummy-only bridge-in.
    let mut plain = claim_w.clone();
    plain.n_fn = 0;
    plain.inputs = [
        wallet::dummy_input(&mut s.rng),
        wallet::dummy_input(&mut s.rng),
    ];
    plain.bridge_in = 500;
    // n_fn = 2: CLAIM plus a LOCK of the payout into a new vault record.
    let blind = wallet::random_digest(&mut s.rng);
    let (lock_input, mut lock_fw) = lock_call(500, lock_of(&secret), 1, blind);
    lock_fw.spec = [None, lock_fw.spec[1]];
    let mut two = claim_w.clone();
    two.outputs[1] = wallet::contract_output(&mut s.rng, C, 500, lock_of(&secret));
    two.outputs[0].value = 0;
    two.functions[0].as_mut().unwrap().spec[0]
        .as_mut()
        .unwrap()
        .value = 0;
    let claim_fw = two.functions[0].unwrap();
    two = with_functions(two, &[claim_fw, lock_fw]);
    for (name, w) in [
        ("kernel n_fn=0", &plain),
        ("kernel n_fn=1", &claim_w),
        ("kernel n_fn=2", &two),
    ] {
        let public = native(w).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let exec = run(&kernel_program(), &witness_words(w), MAX_CYCLES).unwrap();
        let used = trace::usage(&kernel_program(), &exec);
        println!("{name}: {used:?}");
        fits(name, &used, &prove::kernel_budget(public.n_fn), &mut errors);
    }
    for (name, input) in [("vault CLAIM", &claim_input), ("vault LOCK", &lock_input)] {
        let exec = run(&vault(), input, MAX_CYCLES).unwrap();
        let used = trace::usage(&vault(), &exec);
        println!("{name}: {used:?}");
        fits(name, &used, &VAULT_BUDGET, &mut errors);
    }
    assert!(errors.is_empty(), "{errors:#?}");
}
