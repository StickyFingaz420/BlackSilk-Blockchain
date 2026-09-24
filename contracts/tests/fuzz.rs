//! Mutation fuzzing of the contract engine (pure Rust, seeded, repeatable;
//! `BLACKSILK_FUZZ_ITERS` scales it): mutated and random Wasm modules never
//! panic the module check, and those that pass never panic deployment or a
//! call; every outcome is an `Ok` or a typed error, within the fuel limit.

use blacksilk_contracts::{CallRequest, ContractState, DeployRequest, Executor};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

const MODULE: &str = r#"
(module
  (import "bs" "get" (func $get (param i32 i32 i32 i32) (result i32)))
  (import "bs" "set" (func $set (param i32 i32 i32 i32)))
  (memory (export "memory") 1 1)
  (data (i32.const 0) "count")
  (func (export "bs_call")
    (local $i i32)
    (if (i32.eq (call $get (i32.const 0) (i32.const 5) (i32.const 16) (i32.const 8)) (i32.const -1))
      (then (i64.store (i32.const 16) (i64.const 0))))
    (loop $l
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br_if $l (i32.lt_u (local.get $i) (i32.const 50))))
    (i64.store (i32.const 16) (i64.add (i64.load (i32.const 16)) (i64.const 1)))
    (call $set (i32.const 0) (i32.const 5) (i32.const 16) (i32.const 8))))
"#;

fn iters() -> usize {
    std::env::var("BLACKSILK_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2000)
}

#[test]
fn mutated_modules_never_panic_the_engine() {
    let seed = wat::parse_str(MODULE).unwrap();
    let exec = Executor::new();
    assert!(exec.check_module(&seed).is_ok());
    let mut rng = ChaCha20Rng::seed_from_u64(11);
    let n = iters();
    let (mut checked, mut deployed, mut called) = (0, 0, 0);
    for k in 0..n {
        let mut m = seed.clone();
        if k % 10 == 0 {
            let len = rng.next_u32() as usize % 512;
            m = (0..len).map(|_| rng.next_u32() as u8).collect();
        } else {
            for _ in 0..1 + rng.next_u32() % 3 {
                let i = rng.next_u32() as usize % m.len();
                m[i] = rng.next_u32() as u8;
            }
        }
        if exec.check_module(&m).is_err() {
            continue;
        }
        checked += 1;
        let state = ContractState::new();
        let Ok(r) = exec.deploy(
            &state,
            &DeployRequest {
                contract_id: [1; 32],
                code: m,
                fuel_limit: 1_000_000,
                storage_limit: 1 << 16,
                ..Default::default()
            },
        ) else {
            continue;
        };
        deployed += 1;
        let mut state = state;
        state.begin_block();
        state.commit(r.diff);
        if exec
            .call(
                &state,
                &CallRequest {
                    target: [1; 32],
                    fuel_limit: 100_000,
                    storage_limit: 1 << 16,
                    ..Default::default()
                },
            )
            .is_ok()
        {
            called += 1;
        }
    }
    println!("{n} mutated modules: {checked} passed the check, {deployed} deployed, {called} called; no panic");
}
