#!/usr/bin/env bash
# rerunB: run B1's 52 survivors and 2 timeouts with the final tests.
cd "$(dirname "$0")"
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0; unset CARGO_TARGET_DIR
mapfile -t X < rerunB.args
cargo mutants -d src -p blacksilk-zkvm -f zkvm/src/air/trace.rs -f zkvm/src/air/check.rs "${X[@]}" \
  --profile mutants --jobs 2 --baseline skip --timeout 900 --build-timeout 2400 --cap-lints true \
  -o C:/bszkeval/w4-mutair-scratch/outRB -C=--config=profile.mutants.package.blacksilk-zkvm.opt-level=1 \
  -C=--test=air_oracle -- -- --test-threads=2 > rerunB.log 2>&1
echo chain5 done
