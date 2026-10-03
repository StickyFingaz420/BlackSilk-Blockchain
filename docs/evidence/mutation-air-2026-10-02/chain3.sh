#!/usr/bin/env bash
# Release arithmetic: run A's kills whose logs show an overflow panic, with
# overflow checks and debug assertions off (own target via cargo-mutants copies).
cd "$(dirname "$0")"
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0; unset CARGO_TARGET_DIR
F=(); for f in cpu alu_add alu_bit alu_lt alu_mul alu_shift memory poseidon program byte util mod; do F+=(-f "zkvm/src/air/$f.rs"); done
mapfile -t X < ovfA.args
RUSTFLAGS="-C overflow-checks=off -C debug-assertions=off" cargo mutants -d src -p blacksilk-zkvm "${F[@]}" "${X[@]}" \
  --profile mutants --jobs 2 --baseline skip --timeout 600 --build-timeout 3600 --cap-lints true \
  -o C:/bszkeval/w4-mutair-scratch/outOA -C=--config=profile.mutants.package.blacksilk-zkvm.opt-level=1 \
  -C=--test=air_oracle -- -- --test-threads=2 > ovfA.log 2>&1
echo chain3 done
