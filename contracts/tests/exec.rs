//! Execution tests (docs/contracts.md §9, §20 item 4–5) on small WAT modules.

use blacksilk_contracts::exec::{fuel, MAX_DEPTH};
use blacksilk_contracts::profile::{self, ProfileError};
use blacksilk_contracts::{
    CallRequest, ContractState, DeployRequest, ExecError, Executor, Note, NoteBody, StateDiff,
};
use blacksilk_crypto::{Point, RistrettoPoint, Scalar};

const FUEL: u64 = 5_000_000;

fn wasm(src: &str) -> Vec<u8> {
    wat::parse_str(src).expect("valid WAT")
}

fn id(n: u8) -> [u8; 32] {
    [n; 32]
}

/// Deploys `code` as contract `n` in its own block and commits it.
fn deploy(state: &mut ContractState, exec: &Executor, n: u8, code: &[u8]) {
    let r = exec
        .deploy(
            state,
            &DeployRequest {
                contract_id: id(n),
                code: code.to_vec(),
                fuel_limit: FUEL,
                storage_limit: 1 << 20,
                ..Default::default()
            },
        )
        .expect("deploy");
    state.begin_block();
    state.commit(r.diff);
}

fn call(target: u8) -> CallRequest {
    CallRequest {
        target: id(target),
        fuel_limit: FUEL,
        storage_limit: 1 << 16,
        ..Default::default()
    }
}

const COUNTER: &str = r#"
(module
  (import "bs" "get" (func $get (param i32 i32 i32 i32) (result i32)))
  (import "bs" "set" (func $set (param i32 i32 i32 i32)))
  (memory (export "memory") 1 1)
  (data (i32.const 0) "count")
  (func (export "bs_call")
    (if (i32.eq (call $get (i32.const 0) (i32.const 5) (i32.const 16) (i32.const 8)) (i32.const -1))
      (then (i64.store (i32.const 16) (i64.const 0))))
    (i64.store (i32.const 16) (i64.add (i64.load (i32.const 16)) (i64.const 1)))
    (call $set (i32.const 0) (i32.const 5) (i32.const 16) (i32.const 8))))
"#;

#[test]
fn counter_persists_across_calls_and_undo_restores_the_root() {
    let exec = Executor::new();
    let mut s = ContractState::new();
    deploy(&mut s, &exec, 1, &wasm(COUNTER));
    let root0 = s.root();
    for expected in 1u64..=3 {
        let r = exec.call(&s, &call(1)).unwrap();
        s.begin_block();
        s.commit(r.diff);
        assert_eq!(
            s.get(&id(1), b"count"),
            Some(&expected.to_le_bytes().to_vec())
        );
    }
    for _ in 0..3 {
        assert!(s.undo_block());
    }
    assert_eq!(s.root(), root0);
    assert!(s.get(&id(1), b"count").is_none());
}

#[test]
fn execution_is_deterministic_and_fuel_is_pinned() {
    let exec = Executor::new();
    let mut a = ContractState::new();
    deploy(&mut a, &exec, 1, &wasm(COUNTER));
    let r1 = exec.call(&a, &call(1)).unwrap();
    // Another executor (fresh module cache) on an identically built state.
    let exec2 = Executor::new();
    let mut b = ContractState::new();
    deploy(&mut b, &exec2, 1, &wasm(COUNTER));
    let r2 = exec2.call(&b, &call(1)).unwrap();
    assert_eq!(r1, r2);
    assert_eq!(a.root(), b.root());
    // Golden fuel: any change to the engine, its version or the host costs
    // changes this number, which is a consensus change (§16.3).
    assert_eq!(r1.fuel_used, GOLDEN_COUNTER_FUEL, "fuel schedule changed");
    assert_eq!(r1.storage_used, 32 + 5 + 8);
}

/// Fuel of the first counter call: instantiation (code bytes) + get + set +
/// wasmi 0.38 instruction fuel. Pinned by the test above.
const GOLDEN_COUNTER_FUEL: u64 = 1_807;

#[test]
fn infinite_loop_runs_out_of_fuel() {
    let exec = Executor::new();
    let mut s = ContractState::new();
    deploy(
        &mut s,
        &exec,
        1,
        &wasm(
            r#"(module (memory (export "memory") 1 1) (func (export "bs_call") (loop $l (br $l))))"#,
        ),
    );
    let mut req = call(1);
    req.fuel_limit = 100_000;
    assert_eq!(exec.call(&s, &req), Err(ExecError::OutOfFuel));
}

#[test]
fn too_little_fuel_for_instantiation_fails() {
    let exec = Executor::new();
    let mut s = ContractState::new();
    let code = wasm(COUNTER);
    deploy(&mut s, &exec, 1, &code);
    let mut req = call(1);
    req.fuel_limit = code.len() as u64 * fuel::INSTANTIATE_PER_BYTE - 1;
    assert_eq!(exec.call(&s, &req), Err(ExecError::OutOfFuel));
}

#[test]
fn abort_returns_the_code_and_writes_nothing() {
    let exec = Executor::new();
    let mut s = ContractState::new();
    deploy(
        &mut s,
        &exec,
        1,
        &wasm(
            r#"(module
              (import "bs" "set" (func $set (param i32 i32 i32 i32)))
              (import "bs" "abort" (func $abort (param i32)))
              (memory (export "memory") 1 1)
              (func (export "bs_call")
                (call $set (i32.const 0) (i32.const 1) (i32.const 0) (i32.const 1))
                (call $abort (i32.const 42))))"#,
        ),
    );
    let root = s.root();
    assert_eq!(exec.call(&s, &call(1)), Err(ExecError::Abort(42)));
    assert_eq!(s.root(), root);
}

#[test]
fn storage_limit_and_key_rules_are_enforced() {
    let exec = Executor::new();
    let mut s = ContractState::new();
    deploy(
        &mut s,
        &exec,
        1,
        &wasm(
            r#"(module
              (import "bs" "set" (func $set (param i32 i32 i32 i32)))
              (memory (export "memory") 1 1)
              (func (export "bs_call")
                (call $set (i32.const 0) (i32.const 1) (i32.const 0) (i32.const 100))))"#,
        ),
    );
    let mut req = call(1);
    req.storage_limit = 32 + 1 + 100 - 1;
    assert_eq!(
        exec.call(&s, &req),
        Err(ExecError::StorageLimit {
            used: 133,
            limit: 132
        })
    );
    req.storage_limit = 133;
    assert_eq!(exec.call(&s, &req).unwrap().storage_used, 133);

    // Empty keys and out-of-bounds pointers trap.
    for body in [
        "(call $set (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 1))",
        "(call $set (i32.const 0) (i32.const 65) (i32.const 0) (i32.const 1))",
        "(call $set (i32.const 65530) (i32.const 10) (i32.const 0) (i32.const 1))",
        "(call $set (i32.const 0) (i32.const 1) (i32.const 0) (i32.const 4097))",
    ] {
        let mut s = ContractState::new();
        deploy(
            &mut s,
            &exec,
            2,
            &wasm(&format!(
                r#"(module
                  (import "bs" "set" (func $set (param i32 i32 i32 i32)))
                  (memory (export "memory") 1 1)
                  (func (export "bs_call") {body}))"#
            )),
        );
        assert!(
            matches!(exec.call(&s, &call(2)), Err(ExecError::Trap(_))),
            "{body}"
        );
    }
}

const NOTE_HANDLER: &str = r#"
(module
  (import "bs" "consumed_count" (func $cc (result i32)))
  (import "bs" "created_count" (func $nc (result i32)))
  (import "bs" "approve" (func $approve (param i32)))
  (import "bs" "accept" (func $accept (param i32)))
  (import "bs" "input_len" (func $input_len (result i32)))
  (memory (export "memory") 1 1)
  (func (export "bs_call") (local $i i32) (local $n i32)
    ;; With a non-empty input, do nothing (to test the approval rule).
    (if (i32.gt_u (call $input_len) (i32.const 0)) (then (return)))
    (local.set $n (call $cc))
    (block $d (loop $l
      (br_if $d (i32.ge_u (local.get $i) (local.get $n)))
      (call $approve (local.get $i))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $l)))
    (local.set $i (i32.const 0))
    (local.set $n (call $nc))
    (block $d (loop $l
      (br_if $d (i32.ge_u (local.get $i) (local.get $n)))
      (call $accept (local.get $i))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $l)))))
"#;

fn public_note(n: u8, owner: u8, amount: u64) -> Note {
    Note {
        id: [n; 32],
        owner: id(owner),
        policy: vec![],
        height: 1,
        body: NoteBody::Public { amount },
    }
}

#[test]
fn notes_must_be_approved_and_accepted_by_their_owner() {
    let exec = Executor::new();
    let mut s = ContractState::new();
    deploy(&mut s, &exec, 1, &wasm(NOTE_HANDLER));
    deploy(&mut s, &exec, 2, &wasm(COUNTER));
    // Put a note into contract 1.
    let mut req = call(1);
    req.created = vec![public_note(0x50, 1, 700)];
    let r = exec.call(&s, &req).unwrap();
    assert_eq!(r.diff.notes_created.len(), 1);
    assert_eq!(r.storage_used, 200);
    s.begin_block();
    s.commit(r.diff);
    assert!(s.note(&[0x50; 32]).is_some());

    // Consume it and create a new one: fine when the owner approves.
    let mut req = call(1);
    req.consumed = vec![[0x50; 32]];
    req.created = vec![public_note(0x51, 1, 600)];
    assert!(exec.call(&s, &req).is_ok());
    // The owner declines (input makes it return early): invalid.
    req.input = vec![1];
    assert_eq!(
        exec.call(&s, &req),
        Err(ExecError::NoteNotApproved([0x50; 32]))
    );
    req.consumed.clear();
    assert_eq!(
        exec.call(&s, &req),
        Err(ExecError::NoteNotAccepted([0x51; 32]))
    );

    // A contract that never looks at notes cannot receive or release them.
    let mut req = call(2);
    req.access = vec![id(1)];
    req.consumed = vec![[0x50; 32]];
    assert_eq!(
        exec.call(&s, &req),
        Err(ExecError::NoteNotApproved([0x50; 32]))
    );
    // Notes of contracts outside {target} ∪ access are refused.
    let mut req = call(2);
    req.consumed = vec![[0x50; 32]];
    assert_eq!(
        exec.call(&s, &req),
        Err(ExecError::OutsideAccessList(id(1)))
    );
    let mut req = call(2);
    req.created = vec![public_note(0x52, 1, 1)];
    assert_eq!(
        exec.call(&s, &req),
        Err(ExecError::OutsideAccessList(id(1)))
    );
    // Unknown and duplicate notes.
    let mut req = call(1);
    req.consumed = vec![[0x99; 32]];
    assert_eq!(exec.call(&s, &req), Err(ExecError::UnknownNote([0x99; 32])));
    let mut req = call(1);
    req.created = vec![public_note(0x50, 1, 1)];
    assert_eq!(
        exec.call(&s, &req),
        Err(ExecError::DuplicateNote([0x50; 32]))
    );
}

/// Forwards to the first 32-byte id of its input with the rest as input, then
/// stores the callee's result under "r". With less than 32 bytes it returns "leaf".
const FORWARDER: &str = r#"
(module
  (import "bs" "input_len" (func $input_len (result i32)))
  (import "bs" "input_read" (func $input_read (param i32)))
  (import "bs" "call" (func $call (param i32 i32 i32) (result i32)))
  (import "bs" "result_read" (func $result_read (param i32)))
  (import "bs" "return_write" (func $return_write (param i32 i32)))
  (import "bs" "set" (func $set (param i32 i32 i32 i32)))
  (memory (export "memory") 1 1)
  (data (i32.const 0) "leaf")
  (data (i32.const 8) "r")
  (func (export "bs_call") (local $len i32) (local $r i32)
    (local.set $len (call $input_len))
    (call $input_read (i32.const 1024))
    (if (i32.lt_u (local.get $len) (i32.const 32))
      (then (call $return_write (i32.const 0) (i32.const 4)) (return)))
    (local.set $r (call $call (i32.const 1024) (i32.const 1056)
                              (i32.sub (local.get $len) (i32.const 32))))
    (call $result_read (i32.const 2048))
    (call $set (i32.const 8) (i32.const 1) (i32.const 2048) (local.get $r))
    (call $return_write (i32.const 2048) (local.get $r))))
"#;

fn chain_input(ids: &[u8]) -> Vec<u8> {
    ids.iter().flat_map(|n| id(*n)).collect()
}

#[test]
fn cross_contract_calls_depth_and_reentrancy() {
    let exec = Executor::new();
    let mut s = ContractState::new();
    let code = wasm(FORWARDER);
    for n in 1..=6 {
        deploy(&mut s, &exec, n, &code);
    }
    let with_access = |input: &[u8]| CallRequest {
        access: (2..=6).map(id).collect(),
        input: chain_input(input),
        ..call(1)
    };

    // 1 → 2: 2 returns "leaf", 1 stores it.
    let r = exec.call(&s, &with_access(&[2])).unwrap();
    assert_eq!(
        r.diff.kv.get(&(id(1), b"r".to_vec())),
        Some(&Some(b"leaf".to_vec()))
    );
    // Depth MAX_DEPTH (1 → 2 → 3 → 4) is fine; one more traps.
    assert_eq!(MAX_DEPTH, 4);
    let r = exec.call(&s, &with_access(&[2, 3, 4])).unwrap();
    assert_eq!(
        r.diff.kv.get(&(id(4), b"r".to_vec())),
        None,
        "4 is the leaf and stores nothing"
    );
    assert!(r.diff.kv.contains_key(&(id(3), b"r".to_vec())));
    assert!(matches!(
        exec.call(&s, &with_access(&[2, 3, 4, 5])),
        Err(ExecError::Trap(m)) if m.contains("depth")
    ));
    // Reentrancy: 1 → 2 → 1, and 1 → 1.
    for path in [&[2u8, 1][..], &[1][..], &[2, 3, 2][..]] {
        assert!(
            matches!(exec.call(&s, &with_access(path)), Err(ExecError::Trap(m)) if m.contains("reentrant")),
            "{path:?}"
        );
    }
    // Callee outside the access list.
    let mut req = with_access(&[2]);
    req.access = vec![id(3)];
    assert!(matches!(exec.call(&s, &req), Err(ExecError::Trap(m)) if m.contains("access list")));
    // Unknown contracts in the access list are rejected before execution.
    let mut req = with_access(&[2]);
    req.access.push(id(9));
    assert_eq!(exec.call(&s, &req), Err(ExecError::UnknownContract(id(9))));
}

#[test]
fn auth_keys_are_visible_to_contracts() {
    let exec = Executor::new();
    let mut s = ContractState::new();
    deploy(
        &mut s,
        &exec,
        1,
        &wasm(
            r#"(module
              (import "bs" "input_read" (func $input_read (param i32)))
              (import "bs" "auth_has" (func $auth_has (param i32) (result i32)))
              (import "bs" "abort" (func $abort (param i32)))
              (memory (export "memory") 1 1)
              (func (export "bs_call")
                (call $input_read (i32.const 0))
                (if (i32.eqz (call $auth_has (i32.const 0))) (then (call $abort (i32.const 7))))))"#,
        ),
    );
    let key = Point::from_point(RistrettoPoint::mul_base(&Scalar::from(5u64)));
    let mut req = call(1);
    req.input = key.bytes().to_vec();
    assert_eq!(exec.call(&s, &req), Err(ExecError::Abort(7)));
    req.auth_keys = vec![key];
    assert!(exec.call(&s, &req).is_ok());
}

#[test]
fn keysets_append_and_validate_points() {
    let exec = Executor::new();
    let mut s = ContractState::new();
    deploy(
        &mut s,
        &exec,
        1,
        &wasm(
            r#"(module
              (import "bs" "input_read" (func $input_read (param i32)))
              (import "bs" "keyset_add" (func $add (param i32 i32) (result i32)))
              (import "bs" "keyset_len" (func $len (param i32) (result i32)))
              (import "bs" "abort" (func $abort (param i32)))
              (memory (export "memory") 1 1)
              (func (export "bs_call")
                (call $input_read (i32.const 0))
                (if (i32.ne (call $add (i32.const 3) (i32.const 0)) (call $len (i32.const 3)))
                  (then))
                (if (i32.ne (call $len (i32.const 3)) (i32.const 1)) (then (call $abort (i32.const 1))))))"#,
        ),
    );
    let key = Point::from_point(RistrettoPoint::mul_base(&Scalar::from(9u64)));
    let mut req = call(1);
    req.input = key.bytes().to_vec();
    let r = exec.call(&s, &req).unwrap();
    assert_eq!(r.storage_used, 36);
    s.begin_block();
    s.commit(r.diff);
    assert_eq!(s.keyset(&id(1), 3), &[key]);
    // Identity and invalid encodings trap.
    for bad in [[0u8; 32], [0xff; 32]] {
        let mut req = call(1);
        req.input = bad.to_vec();
        assert!(matches!(exec.call(&s, &req), Err(ExecError::Trap(_))));
    }
}

#[test]
fn deploy_runs_init_and_charges_code_storage() {
    let exec = Executor::new();
    let s = ContractState::new();
    let code = wasm(
        r#"(module
          (import "bs" "set" (func $set (param i32 i32 i32 i32)))
          (memory (export "memory") 1 1)
          (data (i32.const 0) "initok")
          (func (export "bs_init") (call $set (i32.const 0) (i32.const 4) (i32.const 4) (i32.const 2)))
          (func (export "bs_call")))"#,
    );
    let req = DeployRequest {
        contract_id: id(1),
        code: code.clone(),
        fuel_limit: FUEL,
        storage_limit: 1 << 20,
        ..Default::default()
    };
    let r = exec.deploy(&s, &req).unwrap();
    assert_eq!(
        r.diff.kv.get(&(id(1), b"init".to_vec())),
        Some(&Some(b"ok".to_vec()))
    );
    assert_eq!(r.storage_used, code.len() as u64 + 32 + 4 + 2);
    let mut s = ContractState::new();
    s.begin_block();
    s.commit(r.diff);
    assert_eq!(exec.deploy(&s, &req), Err(ExecError::ContractExists(id(1))));
    // The same code again under a new id is not charged for the code bytes.
    let r = exec
        .deploy(
            &s,
            &DeployRequest {
                contract_id: id(2),
                ..req.clone()
            },
        )
        .unwrap();
    assert_eq!(r.storage_used, 32 + 4 + 2);
    // Too small a storage limit.
    let mut small = req.clone();
    small.contract_id = id(3);
    small.code.push(0); // trailing garbage: rejected by the profile
    assert!(matches!(
        exec.deploy(&s, &small),
        Err(ExecError::Profile(_))
    ));
    let _ = StateDiff::default();
}

// ---- module profile (§9.1) ----

fn check(src: &str) -> Result<profile::ModuleInfo, ProfileError> {
    profile::check(&wasm(src))
}

const OK_MINIMAL: &str = r#"(module (memory (export "memory") 1 1) (func (export "bs_call")))"#;

#[test]
fn profile_accepts_minimal_and_full_modules() {
    assert_eq!(
        check(OK_MINIMAL),
        Ok(profile::ModuleInfo { has_init: false })
    );
    assert!(check(COUNTER).is_ok());
    assert!(check(FORWARDER).is_ok());
    assert!(check(NOTE_HANDLER).is_ok());
    // One bounded funcref table and a declared element segment are fine.
    assert!(check(
        r#"(module (memory (export "memory") 1 32) (table 2 4 funcref)
           (func $f) (elem (i32.const 0) $f)
           (func (export "bs_call") (call_indirect (i32.const 0))))"#
    )
    .is_ok());
}

#[test]
fn profile_rejects_everything_outside_the_profile() {
    let cases: &[(&str, &str)] = &[
        (
            "float local",
            r#"(module (memory (export "memory") 1 1) (func (export "bs_call") (local f32)))"#,
        ),
        (
            "float op",
            r#"(module (memory (export "memory") 1 1) (func (export "bs_call") (drop (f64.add (f64.const 1) (f64.const 2)))))"#,
        ),
        (
            "float global",
            r#"(module (memory (export "memory") 1 1) (global f32 (f32.const 0)) (func (export "bs_call")))"#,
        ),
        (
            "float param",
            r#"(module (memory (export "memory") 1 1) (func (param f64)) (func (export "bs_call")))"#,
        ),
        (
            "simd",
            r#"(module (memory (export "memory") 1 1) (func (export "bs_call") (drop (v128.const i32x4 0 0 0 0))))"#,
        ),
        (
            "start",
            r#"(module (memory (export "memory") 1 1) (func $s) (start $s) (func (export "bs_call")))"#,
        ),
        (
            "foreign import",
            r#"(module (import "env" "f" (func)) (memory (export "memory") 1 1) (func (export "bs_call")))"#,
        ),
        (
            "unknown host fn",
            r#"(module (import "bs" "exec" (func)) (memory (export "memory") 1 1) (func (export "bs_call")))"#,
        ),
        (
            "wrong signature",
            r#"(module (import "bs" "height" (func (result i32))) (memory (export "memory") 1 1) (func (export "bs_call")))"#,
        ),
        (
            "imported memory",
            r#"(module (import "bs" "memory" (memory 1 1)) (func (export "bs_call")))"#,
        ),
        ("no memory", r#"(module (func (export "bs_call")))"#),
        (
            "unbounded memory",
            r#"(module (memory (export "memory") 1) (func (export "bs_call")))"#,
        ),
        (
            "memory too large",
            r#"(module (memory (export "memory") 1 33) (func (export "bs_call")))"#,
        ),
        (
            "memory not exported",
            r#"(module (memory 1 1) (func (export "bs_call")))"#,
        ),
        (
            "no bs_call",
            r#"(module (memory (export "memory") 1 1) (func (export "run")))"#,
        ),
        (
            "bs_call type",
            r#"(module (memory (export "memory") 1 1) (func (export "bs_call") (param i32)))"#,
        ),
        (
            "bs_init type",
            r#"(module (memory (export "memory") 1 1) (func (export "bs_call")) (func (export "bs_init") (result i32) (i32.const 0)))"#,
        ),
        (
            "unbounded table",
            r#"(module (memory (export "memory") 1 1) (table 1 funcref) (func (export "bs_call")))"#,
        ),
        (
            "table too large",
            r#"(module (memory (export "memory") 1 1) (table 1 2000 funcref) (func (export "bs_call")))"#,
        ),
        (
            "two tables",
            r#"(module (memory (export "memory") 1 1) (table 1 1 funcref) (table 1 1 funcref) (func (export "bs_call")))"#,
        ),
        (
            "externref table",
            r#"(module (memory (export "memory") 1 1) (table 1 1 externref) (func (export "bs_call")))"#,
        ),
        (
            "passive data",
            r#"(module (memory (export "memory") 1 1) (data "x") (func (export "bs_call")))"#,
        ),
        (
            "passive elem",
            r#"(module (memory (export "memory") 1 1) (table 1 1 funcref) (func $f) (elem func $f) (func (export "bs_call")))"#,
        ),
        (
            "too many locals",
            r#"(module (memory (export "memory") 1 1) (func (export "bs_call") (local i32 i32) (local i64) ))"#,
        ),
        (
            "tail call",
            r#"(module (memory (export "memory") 1 1) (func $f) (func (export "bs_call") (return_call $f)))"#,
        ),
        (
            "sat trunc",
            r#"(module (memory (export "memory") 1 1) (func (export "bs_call") (drop (i32.trunc_sat_f32_s (f32.const 0)))))"#,
        ),
    ];
    for (name, src) in cases {
        let src = if *name == "too many locals" {
            // 257 i32 locals.
            format!(
                r#"(module (memory (export "memory") 1 1) (func (export "bs_call") (local {})))"#,
                "i32 ".repeat(257)
            )
        } else {
            src.to_string()
        };
        assert!(check(&src).is_err(), "{name} must be rejected");
    }
    // Exactly 256 locals is fine.
    let ok = format!(
        r#"(module (memory (export "memory") 1 1) (func (export "bs_call") (local {})))"#,
        "i32 ".repeat(256)
    );
    assert!(check(&ok).is_ok());
    // Size limit.
    let big = format!(
        r#"(module (memory (export "memory") 1 1) (data (i32.const 0) "{}") (func (export "bs_call")))"#,
        "a".repeat(profile::MAX_CODE)
    );
    assert!(matches!(check(&big), Err(ProfileError::TooLarge(_))));
    assert!(profile::check(b"\0asm garbage").is_err());
}

#[test]
fn host_api_table_matches_the_linker() {
    let names: Vec<&str> = profile::HOST_API.iter().map(|(n, _, _)| *n).collect();
    assert_eq!(names, blacksilk_contracts::exec::HOST_FUNCTIONS);
    // And every host function can be imported with its declared signature.
    let abi = |t: &profile::Abi| match t {
        profile::Abi::I32 => "i32",
        profile::Abi::I64 => "i64",
    };
    let mut imports = String::new();
    for (name, params, results) in profile::HOST_API {
        let p: Vec<_> = params.iter().map(abi).collect();
        let r: Vec<_> = results.iter().map(abi).collect();
        imports.push_str(&format!(
            r#"(import "bs" "{name}" (func (param {}) (result {})))"#,
            p.join(" "),
            r.join(" ")
        ));
    }
    let src =
        format!(r#"(module {imports} (memory (export "memory") 1 1) (func (export "bs_call")))"#);
    let code = wasm(&src);
    assert!(profile::check(&code).is_ok());
    // It also instantiates: the linker defines every import with that type.
    let exec = Executor::new();
    let mut s = ContractState::new();
    deploy(&mut s, &exec, 1, &code);
    assert!(exec.call(&s, &call(1)).is_ok());
}

#[test]
fn unbounded_recursion_traps_inside_the_interpreter() {
    // Must be a deterministic Wasm trap, never a stack overflow of the node.
    let exec = Executor::new();
    let mut s = ContractState::new();
    deploy(
        &mut s,
        &exec,
        1,
        &wasm(
            r#"(module (memory (export "memory") 1 1)
              (func $f (param i64) (call $f (i64.add (local.get 0) (i64.const 1))))
              (func (export "bs_call") (call $f (i64.const 0))))"#,
        ),
    );
    for _ in 0..2 {
        let r = exec.call(&s, &call(1));
        assert!(
            matches!(r, Err(ExecError::Trap(_)) | Err(ExecError::OutOfFuel)),
            "{r:?}"
        );
    }
}

#[test]
fn memory_cannot_grow_past_its_declared_maximum() {
    let exec = Executor::new();
    let mut s = ContractState::new();
    deploy(
        &mut s,
        &exec,
        1,
        &wasm(
            r#"(module
              (import "bs" "abort" (func $abort (param i32)))
              (memory (export "memory") 1 32)
              (func (export "bs_call")
                ;; Growing to the maximum works, one page more returns -1.
                (if (i32.ne (memory.grow (i32.const 31)) (i32.const 1)) (then (call $abort (i32.const 1))))
                (if (i32.ne (memory.grow (i32.const 1)) (i32.const -1)) (then (call $abort (i32.const 2))))))"#,
        ),
    );
    let r = exec.call(&s, &call(1)).unwrap();
    // Growth is charged: far more than the tiny code itself.
    assert!(r.fuel_used > 10_000, "{}", r.fuel_used);
}

#[test]
fn a_failing_callee_fails_the_whole_call() {
    let exec = Executor::new();
    let mut s = ContractState::new();
    deploy(&mut s, &exec, 1, &wasm(FORWARDER));
    deploy(
        &mut s,
        &exec,
        2,
        &wasm(
            r#"(module (import "bs" "abort" (func $abort (param i32)))
              (memory (export "memory") 1 1) (func (export "bs_call") (call $abort (i32.const 9))))"#,
        ),
    );
    let req = CallRequest {
        access: vec![id(2)],
        input: chain_input(&[2]),
        ..call(1)
    };
    assert_eq!(exec.call(&s, &req), Err(ExecError::Abort(9)));
}

#[test]
fn contracts_see_only_their_own_notes() {
    let exec = Executor::new();
    let mut s = ContractState::new();
    deploy(&mut s, &exec, 1, &wasm(NOTE_HANDLER));
    // Contract 2 reads consumed note 0 although it owns none: index out of range.
    deploy(
        &mut s,
        &exec,
        2,
        &wasm(
            r#"(module (import "bs" "consumed" (func $c (param i32 i32)))
              (memory (export "memory") 1 1) (func (export "bs_call") (call $c (i32.const 0) (i32.const 0))))"#,
        ),
    );
    let mut req = call(1);
    req.created = vec![public_note(0x60, 1, 5)];
    let r = exec.call(&s, &req).unwrap();
    s.begin_block();
    s.commit(r.diff);
    let mut req = call(2);
    req.access = vec![id(1)];
    req.consumed = vec![[0x60; 32]];
    assert!(matches!(exec.call(&s, &req), Err(ExecError::Trap(m)) if m.contains("index")));
}
