//! The unified proof (docs/px.md §7): a contract function and the kernel in
//! one batch proof. Uses the example vault contract (`zkvm/guests/vault`):
//! LOCK puts value under a hash lock, CLAIM releases it to a recipient, and
//! REFUND returns it after a timeout (docs/contracts.md §8).

use blacksilk_px::perm::HostPerm;
use blacksilk_px::prove::{self, kernel_program, witness_words, TransferError, VerifyError};
use blacksilk_px::state::State;
use blacksilk_px::tree::Tree;
use blacksilk_px::vault::{self, Terms};
use blacksilk_px::wallet::{self, Account};
use blacksilk_px_core::call::{OutSpec, Window, ABI_VERSION, PREFIX_WORDS};
use blacksilk_px_core::kernel::{self, Error, FunctionWitness, Public, SliceSource, Witness};
use blacksilk_px_core::record::Record;
use blacksilk_px_core::{Digest, ZERO_DIGEST};
use blacksilk_zkvm::air::trace::{self, Budget, Statement};
use blacksilk_zkvm::{run, Program, MAX_CYCLES};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::Arc;

const C: Digest = [0x100, 1, 2, 3, 4, 5, 6, 7];
const OTHER: Digest = [0x200, 1, 2, 3, 4, 5, 6, 7];
/// The window of a transaction that needs none (PX6).
const W: Window = Window::UNBOUNDED;

// The reference vault contract (`blacksilk_px::vault`), under contract id `C`.
const VAULT_BUDGET: Budget = vault::BUDGET;

fn vault() -> Arc<Program> {
    vault::program()
}

/// The consensus registry of the test: the vault program belongs to `C`,
/// with `VAULT_BUDGET`.
fn registry(contract: &Digest, program: &[u8; 32]) -> Option<Budget> {
    (*contract == C && *program == vault().id()).then_some(VAULT_BUDGET)
}

/// Terms claimable with `secret`, without a timeout.
fn terms_of(secret: &Digest) -> Terms {
    Terms::claim_only(&C, secret)
}

/// The data of a vault record of `C` claimable with `secret`.
fn data_of(secret: &Digest) -> Digest {
    vault::record_data(&C, secret)
}

/// LOCK: the function's input and the kernel's view of its transcript.
fn lock_call(value: u64, terms: &Terms, j: usize, blind: Digest) -> (Vec<u32>, FunctionWitness) {
    vault::lock_call(&C, value, terms, j, &blind, &W)
}

/// CLAIM of vault record `rec` (input slot `i`) to `recipient` (output `j`),
/// without a timeout.
fn claim_call(
    rec: &Record,
    secret: Digest,
    recipient: Digest,
    i: usize,
    j: usize,
    blind: Digest,
) -> (Vec<u32>, FunctionWitness) {
    vault::claim_call(
        rec,
        &secret,
        &Terms::claim_only(&rec.contract, &secret),
        &recipient,
        i,
        j,
        &blind,
        &W,
    )
}

#[test]
fn the_vault_program_id_is_pinned() {
    let id: String = vault().id().iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(id, vault::VAULT_PROGRAM_ID.trim());
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

/// The pinned kernel guest's exit code on `w`.
fn guest(w: &Witness) -> u32 {
    run(&kernel_program(), &witness_words(w), MAX_CYCLES)
        .unwrap()
        .exit_code
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
    let terms = terms_of(&secret);
    let blind = wallet::random_digest(&mut rng);
    let (input, fw) = lock_call(500, &terms, 0, blind);
    let outs = [
        wallet::contract_output(&mut rng, C, 500, data_of(&secret)),
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
            prove::prove(&w, &[(vault(), input, VAULT_BUDGET)], &W, [5; 32], &mut rng)
                .expect("LOCK proves");
        assert_eq!(calls[0].outputs, vec![vault::LOCK]); // the public selector
        assert_eq!(calls[0].abi, ABI_VERSION);
        assert_eq!(
            prove::verify(&public, &calls, &W, [5; 32], &proof, registry),
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
    let (public, calls, proof) = prove::prove(
        &w,
        &[(vault(), input, VAULT_BUDGET)],
        &W,
        [6; 32],
        &mut s.rng,
    )
    .expect("CLAIM proves");
    let size = blacksilk_zk::encode_proof(&proof).len();
    println!(
        "unified proof (kernel + vault): {size} bytes, {:.1?}",
        t.elapsed()
    );
    assert_eq!(
        prove::verify(&public, &calls, &W, [6; 32], &proof, registry),
        Ok(())
    );
    // The function prefix carries the transaction's validity window (PX6):
    // the same proof does not verify for a transaction with another window.
    let window = Window {
        not_before: 0,
        not_after: 99,
    };
    assert!(prove::verify(&public, &calls, &window, [6; 32], &proof, registry).is_err());
    // Nor under another call ABI than the program's registered one (F-28-1).
    let mut other_abi = calls.clone();
    other_abi[0].abi = ABI_VERSION + 1;
    assert!(prove::verify(&public, &other_abi, &W, [6; 32], &proof, registry).is_err());
    // The claim publishes the vault record's contract nullifier, which any
    // holder of the opening computes (wallets track spends with it).
    assert_eq!(
        public.nullifiers[0],
        blacksilk_px_core::record::contract_nullifier(
            &mut HostPerm::new(),
            &C,
            &s.vault_rec.rcm,
            &s.vault_rec.commit(&mut HostPerm::new())
        )
    );
    // Bob receives the vault's value.
    let bob_rec = wallet::created_record(&public, 0, &w.outputs[0]);
    assert_eq!((bob_rec.owner, bob_rec.value), (bob_owner, 500));
    assert_eq!(bob_rec.commit(&mut HostPerm::new()), public.commitments[0]);

    // Verification needs the registry: an unregistered program is refused.
    assert_eq!(
        prove::verify(&public, &calls, &W, [6; 32], &proof, |_, _| None),
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
    assert!(prove::verify(&public, &bad_calls, &W, [6; 32], &proof, registry).is_err());
    let mut p = public;
    p.functions[0].1[0] ^= 1;
    assert!(prove::verify(&p, &calls, &W, [6; 32], &proof, registry).is_err());
    assert!(prove::verify(&public, &calls, &W, [7; 32], &proof, registry).is_err());
    // A hand-built statement with more than MAX_FN functions is a shape
    // error, not a panic (F-20-5).
    let mut too_many = public;
    too_many.n_fn = 3;
    let three = vec![calls[0].clone(); 3];
    assert_eq!(
        prove::verify(&too_many, &three, &W, [6; 32], &proof, registry),
        Err(VerifyError::Shape)
    );

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
    // The kernel approves the real record (it fills in the input's actual
    // commitment); the function rebuilds the record from the terms of the
    // secret it is given, so with a wrong secret it approves another
    // commitment: its transcript (`io_hash`) differs from the kernel's, and
    // no proof exists.
    assert!(native(&w).is_ok());
    let exec = run(&vault(), &input, MAX_CYCLES).unwrap();
    let public = native(&w).unwrap();
    assert_ne!(
        exec.output[1..9],
        public.functions[0].1,
        "a wrong secret yields another transcript"
    );
    assert!(matches!(
        prove::prove(
            &w,
            &[(vault(), input, VAULT_BUDGET)],
            &W,
            [6; 32],
            &mut s.rng
        ),
        Err(TransferError::FunctionMismatch(0))
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

/// PX-F5 (docs/reviews/px-f4-f5-analysis.md §3): the kernel refuses an
/// output with `contract ≠ 0` and `owner ≠ 0`, even when the contract's own
/// function specified exactly that record. Such a record could never be
/// spent (contract records are spent by approval, with owner 0), so its
/// value would be burned by a buggy contract.
///
/// Native and guest (the kernel ELF run in the interpreter, no proving).
fn owned_contract_output() -> (Witness, Witness) {
    let mut rng = ChaCha20Rng::seed_from_u64(41);
    let state = State::new();
    let secret = wallet::random_digest(&mut rng);
    let blind = wallet::random_digest(&mut rng);
    let (_, fw) = lock_call(500, &terms_of(&secret), 0, blind);
    let outs = [
        wallet::contract_output(&mut rng, C, 500, data_of(&secret)),
        wallet::empty_output(&mut rng),
    ];
    let ok = with_functions(
        wallet::witness(
            state.root(),
            500,
            0,
            [wallet::dummy_input(&mut rng), wallet::dummy_input(&mut rng)],
            outs,
        ),
        &[fw],
    );
    // The same LOCK, where the function specifies (and the caller creates)
    // the vault record with an owner.
    let owner = Account::from_seed(&[5; 32]).owner(0);
    let mut bad = ok.clone();
    bad.outputs[0].owner = owner;
    bad.functions[0].as_mut().unwrap().spec[0]
        .as_mut()
        .unwrap()
        .owner = owner;
    (ok, bad)
}

#[test]
fn a_contract_output_with_an_owner_is_rejected() {
    let (ok, bad) = owned_contract_output();
    assert!(native(&ok).is_ok());
    assert_eq!(native(&bad).err(), Some(Error::ContractOutputOwner));
    // Every earlier exit code is unchanged: the variant is appended.
    assert_eq!(Error::DummyContract.exit_code(), 16);
    assert_eq!(Error::ContractOutputOwner.exit_code(), 17);
    // A user output (contract 0) keeps its owner; a contract output with
    // owner 0 is the valid form (`ok`).
    assert_eq!(ok.outputs[0].owner, ZERO_DIGEST);
    let guest = |w: &Witness| {
        run(&kernel_program(), &witness_words(w), MAX_CYCLES)
            .unwrap()
            .exit_code
    };
    assert_eq!(guest(&ok), 0);
    // The pinned guest (rebuilt with PX-F5) agrees with the native kernel.
    // Before the rebuild the pinned pre-F5 kernel accepted `bad` with exit
    // code 0 (this assertion read `assert_eq!(guest(&bad), 0)` in the PX-F5
    // commit): the rule is new.
    assert_eq!(guest(&bad), Error::ContractOutputOwner.exit_code());
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
        prove::prove(
            &w,
            &[(vault(), other, VAULT_BUDGET)],
            &W,
            [6; 32],
            &mut s.rng
        ),
        Err(TransferError::FunctionMismatch(0))
    ));
    // A function echoing another window than the transaction's (PX6).
    let mut late = input.clone();
    late[19] = 5; // not_after, low word
    assert!(matches!(
        prove::prove(
            &w,
            &[(vault(), late, VAULT_BUDGET)],
            &W,
            [6; 32],
            &mut s.rng
        ),
        Err(TransferError::FunctionMismatch(0))
    ));
    // The kernel's io_hash equals the function's for the matching transcript,
    // after the ABI word; the window follows the contract.
    let public = native(&w).unwrap();
    let exec = run(&vault(), &input, MAX_CYCLES).unwrap();
    assert_eq!(exec.output[0], ABI_VERSION);
    assert_eq!(exec.output[1..9], public.functions[0].1);
    assert_eq!(exec.output[9..17], C);
    assert_eq!(exec.output[17..PREFIX_WORDS], W.words());
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
    let (_, fw) = lock_call(70, &terms_of(&secret), 0, blind);
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
                wallet::contract_output(&mut s.rng, C, 70, data_of(&secret)),
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

/// A two-function transaction (W28-3): CLAIM of the vault record (input 0)
/// to `recipient` (output 0) and, in the same transaction, a LOCK of
/// `relock` bridged in into a new vault record (output 1). Returns the two
/// functions' inputs and the witness.
fn claim_and_lock(s: &mut Setup, recipient: Digest, relock: u64) -> (Vec<u32>, Vec<u32>, Witness) {
    let secret = s.secret;
    let (claim_input, mut w) = claim_witness(s, secret, recipient);
    let lock_secret = wallet::random_digest(&mut s.rng);
    let blind = wallet::random_digest(&mut s.rng);
    let (lock_input, lock_fw) = lock_call(relock, &terms_of(&lock_secret), 1, blind);
    w.outputs[1] = wallet::contract_output(&mut s.rng, C, relock, data_of(&lock_secret));
    w.bridge_in = relock;
    let claim_fw = w.functions[0].unwrap();
    (
        claim_input,
        lock_input,
        with_functions(w, &[claim_fw, lock_fw]),
    )
}

/// Two vault records of `C` in a tree (claimable with `secrets[k]`, no
/// timeout), and a witness in which function `k` claims record `k` (input
/// `k`) to `recipient` (output `k`): crossed approvals, one per input.
struct TwoVaults {
    rng: ChaCha20Rng,
    tree: Tree,
    recs: [Record; 2],
    pos: [u64; 2],
    secrets: [Digest; 2],
}

fn two_vaults() -> TwoVaults {
    let mut rng = ChaCha20Rng::seed_from_u64(53);
    let mut perm = HostPerm::new();
    let mut tree = Tree::new(&mut perm);
    let secrets = [
        wallet::random_digest(&mut rng),
        wallet::random_digest(&mut rng),
    ];
    let mut recs = Vec::new();
    let mut pos = Vec::new();
    for (k, secret) in secrets.iter().enumerate() {
        let r = Record {
            owner: ZERO_DIGEST,
            contract: C,
            asset: ZERO_DIGEST,
            value: 300 + 100 * k as u64,
            data: data_of(secret),
            rho: wallet::random_digest(&mut rng),
            rcm: wallet::random_digest(&mut rng),
        };
        let cm = r.commit(&mut perm);
        pos.push(tree.append(&mut perm, cm).unwrap());
        recs.push(r);
    }
    TwoVaults {
        rng,
        tree,
        recs: [recs[0], recs[1]],
        pos: [pos[0], pos[1]],
        secrets,
    }
}

/// The crossed two-claim witness of `v` and the functions' inputs.
fn crossed_claims(v: &mut TwoVaults, recipient: Digest) -> (Vec<Vec<u32>>, Witness) {
    let mut inputs_fn = Vec::new();
    let mut fws = Vec::new();
    for k in 0..2 {
        let blind = wallet::random_digest(&mut v.rng);
        let (input, fw) = claim_call(&v.recs[k], v.secrets[k], recipient, k, k, blind);
        inputs_fn.push(input);
        fws.push(fw);
    }
    let inputs = [0, 1].map(|k| {
        wallet::contract_input(
            &mut v.rng,
            &v.recs[k],
            v.pos[k],
            v.tree.path(v.pos[k]).unwrap(),
        )
    });
    let outs = [0, 1].map(|k| wallet::output(&mut v.rng, recipient, v.recs[k].value));
    let w = with_functions(wallet::witness(v.tree.root(), 0, 0, inputs, outs), &fws);
    (inputs_fn, w)
}

/// F-20-1: a contract input is approved by exactly one function. Two
/// functions approving one record are refused with `ApprovalConflict`
/// (natively and by the pinned guest); two functions approving different
/// records (crossed approvals) stay valid. With `MAX_FN = 2` no input can
/// have three approvals: a third function is `TooManyFunctions` before any
/// input is read. Precedence: a mismatching approval is reported first
/// (`ApprovalMismatch`, raised as the approvals are read), and the conflict
/// is reported before tree membership, which is decided after both inputs.
#[test]
fn an_input_approved_by_two_functions_is_rejected() {
    let mut v = two_vaults();
    let bob = Account::from_seed(&[4; 32]).owner(0);
    let (fn_inputs, crossed) = crossed_claims(&mut v, bob);
    // Crossed approvals: valid, natively and in the guest, and each function
    // run reports the kernel's transcript.
    let public = native(&crossed).expect("crossed approvals are valid");
    assert_eq!(guest(&crossed), 0);
    for (k, input) in fn_inputs.iter().enumerate() {
        let exec = run(&vault(), input, MAX_CYCLES).unwrap();
        assert_eq!(exec.exit_code, 0);
        assert_eq!(exec.output[1..9], public.functions[k].1, "function {k}");
    }

    let mut cases: Vec<(&str, Witness, Error)> = Vec::new();
    let mut add = |name: &'static str, f: &dyn Fn(&mut Witness), e: Error| {
        let mut w = crossed.clone();
        f(&mut w);
        cases.push((name, w, e));
    };
    // Both functions approve input 0 (the second one specifies output 1).
    add(
        "double approval",
        &|w| w.functions[1].as_mut().unwrap().approve = [true, false],
        Error::ApprovalConflict,
    );
    // Both functions approve both inputs: refused at input 0.
    add(
        "double approval of both inputs",
        &|w| {
            for f in w.functions.iter_mut().flatten() {
                f.approve = [true, true];
            }
        },
        Error::ApprovalConflict,
    );
    // The first approval is correct, the second is by a foreign contract:
    // the mismatch is reported, not the conflict.
    add(
        "double approval, second foreign",
        &|w| {
            let f = w.functions[1].as_mut().unwrap();
            f.contract = OTHER;
            f.approve = [true, false];
        },
        Error::ApprovalMismatch,
    );
    // A double approval of a record that is not in the tree: the conflict is
    // reported first (membership is decided after both inputs).
    add(
        "double approval, not in tree",
        &|w| {
            w.functions[1].as_mut().unwrap().approve = [true, false];
            w.inputs[0].rcm[0] ^= 1;
        },
        Error::ApprovalConflict,
    );
    // A double approval of a dummy input: a dummy is never approvable.
    add(
        "double approval of a dummy",
        &|w| {
            w.inputs[1].dummy = true;
            w.inputs[1].contract = ZERO_DIGEST;
            w.inputs[1].value = 0;
            w.functions[0].as_mut().unwrap().approve = [true, true];
            w.functions[1].as_mut().unwrap().approve = [false, true];
        },
        Error::ApprovalMismatch,
    );
    // A third function (a "triple approval"): not expressible.
    add("three functions", &|w| w.n_fn = 3, Error::TooManyFunctions);
    for (name, w, e) in &cases {
        if *e == Error::TooManyFunctions {
            // `Witness::write` writes only MAX_FN functions: build the words
            // by hand, the count word being the fifth after VERSION, anchor
            // and the two bridge amounts.
            let mut words = witness_words(&crossed);
            words[1 + 8 + 4] = 3;
            assert_eq!(
                kernel::transfer(&mut HostPerm::new(), &mut SliceSource::new(&words)).err(),
                Some(*e),
                "case {name}"
            );
            let exec = run(&kernel_program(), &words, MAX_CYCLES).unwrap();
            assert_eq!(exec.exit_code, e.exit_code(), "guest, case {name}");
            continue;
        }
        assert_eq!(native(w).err(), Some(*e), "case {name}");
        assert_eq!(guest(w), e.exit_code(), "guest, case {name}");
    }
}

/// Every kernel error keeps its exit code (appended variants only, so a
/// guest halting with a code means the same rule in every build).
#[test]
fn kernel_exit_codes_are_append_only() {
    let table = [
        (Error::Version, 2),
        (Error::NonCanonical, 3),
        (Error::NotBoolean, 4),
        (Error::DummyWithValue, 5),
        (Error::NotInTree, 6),
        (Error::DuplicateNullifier, 7),
        (Error::Unbalanced, 8),
        (Error::TooManyFunctions, 9),
        (Error::ZeroContract, 10),
        (Error::Unauthorized, 11),
        (Error::ApprovalMismatch, 12),
        (Error::SpecMismatch, 13),
        (Error::SpecForeignContract, 14),
        (Error::SpecConflict, 15),
        (Error::DummyContract, 16),
        (Error::ContractOutputOwner, 17),
        (Error::ApprovalConflict, 18),
    ];
    for (e, code) in table {
        assert_eq!(e.exit_code(), code, "{e:?}");
    }
}

/// The vault's timeout and refund (W28-4) and its lock binding (F-28-7),
/// run in the pinned vault guest against the native kernel's view of the
/// same call. A run "matches" when the guest halts with 0 and writes the
/// prefix the verifier builds for the transaction (ABI, the kernel's
/// `io_hash`, the contract, the window): only then can a proof exist.
#[test]
fn the_vault_enforces_its_timeout_refund_and_lock_binding() {
    let mut rng = ChaCha20Rng::seed_from_u64(61);
    let mut perm = HostPerm::new();
    let mut tree = Tree::new(&mut perm);
    let secret = wallet::random_digest(&mut rng);
    let refund_secret = wallet::random_digest(&mut rng);
    let timeout = 100u64;
    let terms = Terms {
        claim_lock: vault::lock_of(&C, &secret),
        refund_lock: vault::refund_lock_of(&C, &refund_secret),
        timeout,
    };
    let rec = Record {
        owner: ZERO_DIGEST,
        contract: C,
        asset: ZERO_DIGEST,
        value: 700,
        data: terms.data(&C),
        rho: wallet::random_digest(&mut rng),
        rcm: wallet::random_digest(&mut rng),
    };
    let cm = rec.commit(&mut perm);
    let pos = tree.append(&mut perm, cm).unwrap();
    // A record of another vault instance holding this instance's terms (a
    // lock copied across instances, F-28-7).
    let copied = Record {
        contract: OTHER,
        ..rec
    };
    let cm = copied.commit(&mut perm);
    let copied_pos = tree.append(&mut perm, cm).unwrap();
    let carol = Account::from_seed(&[7; 32]).owner(0);

    // Runs a CLAIM (with `key` as the secret) or a REFUND (with `key` as the
    // refund secret) of `rec` in a transaction with `window`: the guest's exit
    // code, and whether its prefix is the statement's.
    let mut release = |selector: u32, key: &Digest, rec: &Record, pos: u64, window: Window| {
        let blind = wallet::random_digest(&mut rng);
        let (input, fw) = if selector == vault::CLAIM {
            vault::claim_call(rec, key, &terms, &carol, 0, 0, &blind, &window)
        } else {
            vault::refund_call(rec, key, &terms, &carol, 0, 0, &blind, &window)
        };
        let inputs = [
            wallet::contract_input(&mut rng, rec, pos, tree.path(pos).unwrap()),
            wallet::dummy_input(&mut rng),
        ];
        let outs = [
            wallet::output(&mut rng, carol, rec.value),
            wallet::empty_output(&mut rng),
        ];
        let w = with_functions(wallet::witness(tree.root(), 0, 0, inputs, outs), &[fw]);
        let exec = run(&vault(), &input, MAX_CYCLES).unwrap();
        let matches = match native(&w) {
            Ok(public) => {
                let (c, io) = public.functions[0];
                exec.exit_code == 0
                    && exec.output[..PREFIX_WORDS]
                        == blacksilk_px_core::call::function_prefix(ABI_VERSION, &io, &c, &window)
            }
            Err(_) => false,
        };
        (exec.exit_code, matches)
    };
    let window = |not_before: u64, not_after: u64| Window {
        not_before,
        not_after,
    };
    // CLAIM: only in a window that ends before the timeout.
    assert_eq!(
        release(vault::CLAIM, &secret, &rec, pos, window(0, 99)),
        (0, true)
    );
    assert_eq!(
        release(vault::CLAIM, &secret, &rec, pos, window(40, 99)),
        (0, true)
    );
    assert_eq!(
        release(vault::CLAIM, &secret, &rec, pos, window(0, 100)).0,
        2
    );
    assert_eq!(release(vault::CLAIM, &secret, &rec, pos, window(0, 0)).0, 2);
    assert_eq!(
        release(vault::CLAIM, &secret, &rec, pos, window(150, 0)).0,
        2
    );
    // REFUND: only in a window that starts at the timeout or later.
    assert_eq!(
        release(vault::REFUND, &refund_secret, &rec, pos, window(100, 0)),
        (0, true)
    );
    assert_eq!(
        release(vault::REFUND, &refund_secret, &rec, pos, window(250, 900)),
        (0, true)
    );
    assert_eq!(
        release(vault::REFUND, &refund_secret, &rec, pos, window(99, 0)).0,
        2
    );
    assert_eq!(
        release(vault::REFUND, &refund_secret, &rec, pos, window(0, 0)).0,
        2
    );
    // The wrong key opens nothing: the refund secret does not claim, the
    // claim secret does not refund (the transcript differs: no proof).
    assert_eq!(
        release(vault::CLAIM, &refund_secret, &rec, pos, window(0, 99)),
        (0, false)
    );
    assert_eq!(
        release(vault::REFUND, &secret, &rec, pos, window(100, 0)),
        (0, false)
    );
    // The lock binds the contract (F-28-7): a record of another vault
    // instance holding this instance's terms does not open with the secret.
    assert_ne!(vault::lock_of(&C, &secret), vault::lock_of(&OTHER, &secret));
    assert_eq!(
        release(vault::CLAIM, &secret, &copied, copied_pos, window(0, 99)),
        (0, false)
    );

    // LOCK: without a timeout the refund lock must be zero.
    let blind = wallet::random_digest(&mut rng);
    let bad = Terms {
        timeout: 0,
        ..terms
    };
    let (input, _) = vault::lock_call(&C, 700, &bad, 0, &blind, &W);
    assert_eq!(run(&vault(), &input, MAX_CYCLES).unwrap().exit_code, 2);
    // With one, it creates exactly the record whose data is the terms.
    let (input, fw) = vault::lock_call(&C, 700, &terms, 0, &blind, &W);
    assert_eq!(fw.spec[0].unwrap().data, terms.data(&C));
    let w = with_functions(
        wallet::witness(
            State::new().root(),
            700,
            0,
            [wallet::dummy_input(&mut rng), wallet::dummy_input(&mut rng)],
            [
                wallet::contract_output(&mut rng, C, 700, terms.data(&C)),
                wallet::empty_output(&mut rng),
            ],
        ),
        &[fw],
    );
    let exec = run(&vault(), &input, MAX_CYCLES).unwrap();
    assert_eq!(exec.exit_code, 0);
    assert_eq!(exec.output[1..9], native(&w).unwrap().functions[0].1);
    assert_eq!(exec.output[PREFIX_WORDS..], [vault::LOCK]);
}

/// W28-3 (P0 evidence, F-28-2): a transaction calling two functions (CLAIM
/// of a vault record and LOCK of a new one) proves and verifies end to end,
/// and the verifier refuses the calls swapped, an altered output of the
/// second function, or its registration missing. Prints the proof size and
/// the prove and verify times.
#[test]
fn a_two_function_transaction_proves_and_verifies() {
    let mut s = locked_with(false);
    let bob_owner = s.bob.owner(0);
    let (claim_input, lock_input, w) = claim_and_lock(&mut s, bob_owner, 300);
    assert_eq!(w.n_fn, 2);
    assert!(native(&w).is_ok());
    assert_eq!(guest(&w), 0);
    let t = std::time::Instant::now();
    let (public, calls, proof) = prove::prove(
        &w,
        &[
            (vault(), claim_input, VAULT_BUDGET),
            (vault(), lock_input, VAULT_BUDGET),
        ],
        &W,
        [8; 32],
        &mut s.rng,
    )
    .expect("CLAIM + LOCK proves");
    let prove_time = t.elapsed();
    let size = blacksilk_zk::encode_proof(&proof).len();
    let t = std::time::Instant::now();
    assert_eq!(
        prove::verify(&public, &calls, &W, [8; 32], &proof, registry),
        Ok(())
    );
    let verify_time = t.elapsed();
    println!(
        "two-function proof (kernel + CLAIM + LOCK): {size} bytes, prove {prove_time:.1?}, \
         verify {verify_time:.1?}"
    );
    assert!(size <= blacksilk_zk::params::MAX_PROOF_BYTES);
    assert_eq!(public.n_fn, 2);
    assert_eq!(
        (calls[0].outputs.as_slice(), calls[1].outputs.as_slice()),
        (&[vault::CLAIM][..], &[vault::LOCK][..])
    );
    // Swapped calls: each function's prefix is bound to its position.
    let swapped = vec![calls[1].clone(), calls[0].clone()];
    assert!(prove::verify(&public, &swapped, &W, [8; 32], &proof, registry).is_err());
    // An altered output of the second function.
    let mut altered = calls.clone();
    altered[1].outputs[0] = vault::CLAIM;
    assert!(prove::verify(&public, &altered, &W, [8; 32], &proof, registry).is_err());
    // The second function's registration missing.
    let seen = std::cell::Cell::new(0);
    let first_only = |c: &Digest, p: &[u8; 32]| {
        seen.set(seen.get() + 1);
        if seen.get() > 1 {
            None
        } else {
            registry(c, p)
        }
    };
    assert_eq!(
        prove::verify(&public, &calls, &W, [8; 32], &proof, first_only),
        Err(VerifyError::Unregistered(1))
    );
    // Another window: another statement.
    let window = Window {
        not_before: 1,
        not_after: 0,
    };
    assert!(prove::verify(&public, &calls, &window, [8; 32], &proof, registry).is_err());
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
/// kernel with 0, 1 and 2 functions (user, contract and dummy inputs; for
/// two functions both the CLAIM + LOCK shape and the widest branch profile,
/// two contract inputs with crossed approvals and both outputs specified),
/// and every vault entry point (LOCK with a timeout, CLAIM, REFUND).
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
    // n_fn = 2: CLAIM plus a LOCK into a new vault record.
    let (_, _, two) = claim_and_lock(&mut s, bob_owner, 300);
    // n_fn = 2, the widest branches: two contract inputs, crossed approvals.
    let mut v = two_vaults();
    let (_, crossed) = crossed_claims(&mut v, bob_owner);
    for (name, w) in [
        ("kernel n_fn=0", &plain),
        ("kernel n_fn=1", &claim_w),
        ("kernel n_fn=2 claim+lock", &two),
        ("kernel n_fn=2 crossed claims", &crossed),
    ] {
        let public = native(w).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let exec = run(&kernel_program(), &witness_words(w), MAX_CYCLES).unwrap();
        assert_eq!(exec.exit_code, 0, "{name}");
        let used = trace::usage(&kernel_program(), &exec);
        println!("{name}: {used:?}");
        fits(name, &used, &prove::kernel_budget(public.n_fn), &mut errors);
    }
    // The vault entry points, with a timeout (the longest inputs).
    let refund_secret = wallet::random_digest(&mut s.rng);
    let terms = Terms {
        claim_lock: vault::lock_of(&C, &secret),
        refund_lock: vault::refund_lock_of(&C, &refund_secret),
        timeout: 1_000,
    };
    let rec = Record {
        data: terms.data(&C),
        ..s.vault_rec
    };
    let blind = wallet::random_digest(&mut s.rng);
    let lock_input = vault::lock_call(&C, 500, &terms, 0, &blind, &W).0;
    let before = Window {
        not_before: 0,
        not_after: 999,
    };
    let after = Window {
        not_before: 1_000,
        not_after: 0,
    };
    let claim_timed = vault::claim_call(&rec, &secret, &terms, &bob_owner, 0, 0, &blind, &before).0;
    let refund = vault::refund_call(
        &rec,
        &refund_secret,
        &terms,
        &bob_owner,
        1,
        1,
        &blind,
        &after,
    )
    .0;
    for (name, input) in [
        ("vault CLAIM", &claim_input),
        ("vault CLAIM with a timeout", &claim_timed),
        ("vault LOCK with a timeout", &lock_input),
        ("vault REFUND", &refund),
    ] {
        let exec = run(&vault(), input, MAX_CYCLES).unwrap();
        assert_eq!(exec.exit_code, 0, "{name}");
        let used = trace::usage(&vault(), &exec);
        println!("{name}: {used:?}");
        fits(name, &used, &VAULT_BUDGET, &mut errors);
    }
    assert!(errors.is_empty(), "{errors:#?}");
}
