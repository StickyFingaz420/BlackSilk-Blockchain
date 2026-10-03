#!/usr/bin/env bash
# W4-MUTAIR run A: the constraint files of zkvm/src/air (trace.rs and
# check.rs are run B). Oracle: the aggregated non-proving AIR tests
# (src/zkvm/tests/air_oracle.rs in the census copy; proving tests compiled out).
set -u
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
unset CARGO_TARGET_DIR
cd "$(dirname "$0")"
F=()
for f in cpu alu_add alu_bit alu_lt alu_mul alu_shift memory poseidon program byte util mod; do
  F+=(-f "zkvm/src/air/$f.rs")
done
cargo mutants -d src -p blacksilk-zkvm "${F[@]}" --profile mutants --jobs 2 \
  --timeout 600 --build-timeout 2400 --cap-lints true -o "$1" \
  -C=--config=profile.mutants.package.blacksilk-zkvm.opt-level=1 -C=--test=air_oracle \
  -- -- --test-threads=2
