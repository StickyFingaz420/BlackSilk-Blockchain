//! Writes seed corpora for the two Wasm contract fuzz targets (moved here from
//! `fuzz/` with the D22 "D-freeze" decision). `cargo run --release --bin seeds`
//! (from `contracts/fuzz/`).

use std::path::Path;

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

fn put(target: &str, name: &str, bytes: &[u8]) {
    let dir = Path::new("corpus").join(target);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(name), bytes).unwrap();
    println!("corpus/{target}/{name}: {} bytes", bytes.len());
}

fn main() {
    // A contract module.
    put("wasm_module", "counter", &wat::parse_str(MODULE).unwrap());

    // Contract sequences (contract_sequence): call = [op 0, target, len, input.., fuel, storage].
    let key = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let mut set_get = vec![0u8, 0, 12, 0];
    set_get.extend(key);
    set_get.extend([9, 9, 9, 10, 10]); // value, fuel, storage
    set_get.push(2); // end the block
    set_get.extend([0, 0, 9, 2]);
    set_get.extend(key);
    set_get.extend([10, 0]); // read it back
    set_get.extend([0, 1, 0, 10, 10]); // the counter
    set_get.push(3); // undo the block
    put("contract_sequence", "set_get_undo", &set_get);
    put(
        "contract_sequence",
        "burn",
        &[0, 0, 2, 3, 200, 1, 0, 2, 0, 0, 2, 3, 255, 255, 0],
    );
}
