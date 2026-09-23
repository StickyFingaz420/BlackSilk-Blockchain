//! Integration tests for wasm_vm.rs: contract deployment, invocation, state, and error handling

use super::wasm_vm::*;
use serde_json::json;

#[test]
fn test_deploy_and_invoke_contract() {
    // Minimal valid WASM (empty module)
    let wasm_bytes = wat::parse_str("(module (func (export \"add\") (param i32 i32) (result i32) local.get 0 local.get 1 i32.add))").unwrap();
    let creator = "test_creator".to_string();
    let address = deploy_contract(wasm_bytes.clone(), creator.clone()).expect("deploy");
    // Call exported function with gas limit
    let params = vec![json!(2), json!(3)];
    let result = invoke_contract_json_with_gas(&address, "add", &params, 100_000).expect("invoke");
    assert_eq!(result[0], json!(5));
}

#[test]
fn test_gas_limit_exceeded() {
    let wasm_bytes = wat::parse_str("(module (func (export \"loop_forever\") (loop br 0)))").unwrap();
    let creator = "test_creator".to_string();
    let address = deploy_contract(wasm_bytes.clone(), creator.clone()).expect("deploy");
    let params = vec![];
    let result = invoke_contract_json_with_gas(&address, "loop_forever", &params, 10);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Gas limit exceeded"));
}

#[test]
fn test_invalid_contract_rejected() {
    let invalid_bytes = vec![0, 1, 2, 3, 4];
    let creator = "test_creator".to_string();
    let result = deploy_contract(invalid_bytes, creator);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Invalid WASM module"));
}

#[test]
fn test_contract_too_large() {
    let large_bytes = vec![0; 2 * 1024 * 1024]; // 2MB
    let creator = "test_creator".to_string();
    let result = deploy_contract(large_bytes, creator);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Contract too large"));
}
