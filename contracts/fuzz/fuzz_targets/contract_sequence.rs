//! The contract engine under sequences of operations (AUDIT.md "Coverage-guided
//! fuzzing"): deploys, calls with fuzzed inputs and limits, block ends and
//! rollbacks, against one persistent `ContractState`. Checks:
//! - **Determinism:** every call gives an identical result (receipt or error)
//!   on two independent executors, against the same state;
//! - **Limits:** fuel and storage used never exceed the limits;
//! - **Rollback:** undoing a block restores exactly the state root before it;
//! - **Recovery:** replaying the committed diffs into a fresh state gives the
//!   same root;
//! - no panic anywhere.
#![no_main]
use blacksilk_contracts::{CallRequest, ContractState, DeployRequest, Executor, StateDiff};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

/// Stores, deletes, reads, burns fuel or aborts, as its input's first byte
/// says. Key: input bytes 1..9; value: bytes 9.. .
const KV: &str = r#"
(module
  (import "bs" "input_len" (func $len (result i32)))
  (import "bs" "input_read" (func $read (param i32)))
  (import "bs" "set" (func $set (param i32 i32 i32 i32)))
  (import "bs" "del" (func $del (param i32 i32)))
  (import "bs" "get" (func $get (param i32 i32 i32 i32) (result i32)))
  (import "bs" "return_write" (func $ret (param i32 i32)))
  (import "bs" "abort" (func $abort (param i32)))
  (memory (export "memory") 2 2)
  (func (export "bs_call")
    (local $n i32) (local $op i32) (local $i i32) (local $r i32)
    (local.set $n (call $len))
    (if (i32.gt_u (local.get $n) (i32.const 4096)) (then (call $abort (i32.const 1))))
    (call $read (i32.const 0))
    (local.set $op (i32.load8_u (i32.const 0)))
    (block $done
      (if (i32.eqz (local.get $op)) (then
        (call $set (i32.const 1) (i32.const 8) (i32.const 9)
          (select (i32.sub (local.get $n) (i32.const 9)) (i32.const 0)
            (i32.gt_u (local.get $n) (i32.const 9))))
        (br $done)))
      (if (i32.eq (local.get $op) (i32.const 1)) (then
        (call $del (i32.const 1) (i32.const 8))
        (br $done)))
      (if (i32.eq (local.get $op) (i32.const 2)) (then
        (local.set $r (call $get (i32.const 1) (i32.const 8) (i32.const 8192) (i32.const 1024)))
        (if (i32.gt_s (local.get $r) (i32.const 0)) (then
          (call $ret (i32.const 8192)
            (select (local.get $r) (i32.const 1024) (i32.lt_s (local.get $r) (i32.const 1024))))))
        (br $done)))
      (if (i32.eq (local.get $op) (i32.const 3)) (then
        (loop $l
          (local.set $i (i32.add (local.get $i) (i32.const 1)))
          (br_if $l (i32.lt_u (local.get $i)
            (i32.mul (i32.load8_u (i32.const 1)) (i32.const 1000)))))
        (br $done)))
      (if (i32.eq (local.get $op) (i32.const 4)) (then
        (call $abort (i32.load8_u (i32.const 1))))))))
"#;

/// A counter: increments a stored value on every call.
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

fn modules() -> &'static [Vec<u8>; 2] {
    static M: OnceLock<[Vec<u8>; 2]> = OnceLock::new();
    M.get_or_init(|| {
        [
            wat::parse_str(KV).unwrap(),
            wat::parse_str(COUNTER).unwrap(),
        ]
    })
}

const IDS: [[u8; 32]; 2] = [[1; 32], [2; 32]];

struct Chain {
    state: ContractState,
    /// Committed diffs per block, in order.
    blocks: Vec<Vec<StateDiff>>,
    /// The state root before each block began.
    roots: Vec<[u8; 32]>,
}

impl Chain {
    fn new_block(&mut self) {
        let root = self.state.root();
        self.roots.push(root);
        self.state.begin_block();
        self.blocks.push(Vec::new());
    }

    fn commit(&mut self, diff: StateDiff) {
        self.state.commit(diff.clone());
        self.blocks.last_mut().unwrap().push(diff);
    }
}

fuzz_target!(|data: &[u8]| {
    let (a, b) = (Executor::new(), Executor::new());
    let mut chain = Chain {
        state: ContractState::new(),
        blocks: Vec::new(),
        roots: Vec::new(),
    };
    chain.new_block();
    for (id, code) in IDS.iter().zip(modules()) {
        let req = DeployRequest {
            contract_id: *id,
            code: code.clone(),
            fuel_limit: 10_000_000,
            storage_limit: 1 << 20,
            ..Default::default()
        };
        let r = a
            .deploy(&chain.state, &req)
            .expect("the fixed modules deploy");
        assert_eq!(b.deploy(&chain.state, &req), Ok(r.clone()));
        chain.commit(r.diff);
    }
    let mut i = 0;
    let mut next = || {
        let x = data.get(i).copied();
        i += 1;
        x
    };
    while let Some(op) = next() {
        match op % 4 {
            0 | 1 => {
                let target = IDS[(next().unwrap_or(0) % 2) as usize];
                let len = (next().unwrap_or(0) % 64) as usize;
                let input: Vec<u8> = (0..len).map(|_| next().unwrap_or(0)).collect();
                let fuel_limit = 1_000 + next().unwrap_or(0) as u64 * 20_000;
                let storage_limit = next().unwrap_or(0) as u64 * 64;
                let req = CallRequest {
                    target,
                    input,
                    fuel_limit,
                    storage_limit,
                    ..Default::default()
                };
                let r1 = a.call(&chain.state, &req);
                let r2 = b.call(&chain.state, &req);
                assert_eq!(r1, r2, "the same call gave different results");
                if let Ok(r) = r1 {
                    assert!(r.fuel_used <= fuel_limit, "fuel over the limit");
                    assert!(r.storage_used <= storage_limit, "storage over the limit");
                    chain.commit(r.diff);
                }
            }
            2 => chain.new_block(),
            _ => {
                // Keep the deploy block.
                if chain.blocks.len() > 1 {
                    assert!(chain.state.undo_block());
                    chain.blocks.pop();
                    let before = chain.roots.pop().unwrap();
                    assert_eq!(chain.state.root(), before, "undo did not restore the root");
                }
            }
        }
    }
    // Recovery: replaying the committed diffs gives the same state.
    let mut fresh = ContractState::new();
    for block in &chain.blocks {
        fresh.begin_block();
        for d in block {
            fresh.commit(d.clone());
        }
    }
    assert_eq!(fresh.root(), chain.state.root(), "replay differs");
});
