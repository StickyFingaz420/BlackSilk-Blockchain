#!/usr/bin/env bash
# rerunA (run A's 21 survivors and 1 timeout, with the final tests), the
# timeout in isolation, the constant hand mutants, then run B. Sequential.
cd "$(dirname "$0")"
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0; unset CARGO_TARGET_DIR
F=(); for f in cpu alu_add alu_bit alu_lt alu_mul alu_shift memory poseidon program byte util mod; do F+=(-f "zkvm/src/air/$f.rs"); done
cfg=-C=--config=profile.mutants.package.blacksilk-zkvm.opt-level=1
mapfile -t X < rerunA.args
cargo mutants -d src -p blacksilk-zkvm "${F[@]}" "${X[@]}" --profile mutants --jobs 2 --baseline skip \
  --timeout 600 --build-timeout 2400 --cap-lints true -o C:/bszkeval/w4-mutair-scratch/outRA \
  $cfg -C=--test=air_oracle -- -- --test-threads=2 > rerunA.log 2>&1
python mkre.py <(echo "zkvm/src/air/poseidon.rs:69:32: replace + with *") | tr -d '\r' > timeoutA.args
mapfile -t T < timeoutA.args
cargo mutants -d src -p blacksilk-zkvm -f zkvm/src/air/poseidon.rs "${T[@]}" --profile mutants --jobs 1 --baseline skip \
  --timeout 1800 --build-timeout 2400 --cap-lints true -o C:/bszkeval/w4-mutair-scratch/outTA \
  $cfg -C=--test=air_oracle -- -- --test-threads=2 > timeoutA.log 2>&1
./hand.sh hand.txt C:/bszkeval/w4-mutair-scratch/outH > hand.log 2>&1
./runB.sh C:/bszkeval/w4-mutair-scratch/outB > runB.log 2>&1
echo chain2 done
