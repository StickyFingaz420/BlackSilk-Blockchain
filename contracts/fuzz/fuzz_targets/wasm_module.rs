//! The confidential-contract engine: arbitrary modules never panic the check;
//! those that pass never panic deployment or a call (fuel-bounded).
#![no_main]
use blacksilk_contracts::{CallRequest, ContractState, DeployRequest, Executor};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let exec = Executor::new();
    if exec.check_module(data).is_err() {
        return;
    }
    let state = ContractState::new();
    let Ok(r) = exec.deploy(
        &state,
        &DeployRequest {
            contract_id: [1; 32],
            code: data.to_vec(),
            fuel_limit: 1_000_000,
            storage_limit: 1 << 16,
            ..Default::default()
        },
    ) else {
        return;
    };
    let mut state = state;
    state.begin_block();
    state.commit(r.diff);
    let _ = exec.call(
        &state,
        &CallRequest {
            target: [1; 32],
            fuel_limit: 100_000,
            storage_limit: 1 << 16,
            ..Default::default()
        },
    );
});
