#!/usr/bin/env bash
# run E: tx/src/types.rs, codec.rs, state.rs with all non-proving tx tests
set -u
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
unset CARGO_TARGET_DIR
cd /c/bszkeval/wt-w4-mute
mapfile -t T < /c/bszkeval/w4-mute-scratch/ev/txtests.args
date -u +"start %H:%M" > /c/bszkeval/w4-mute-scratch/runT.time
cargo mutants -p blacksilk-tx -f tx/src/types.rs -f tx/src/codec.rs -f tx/src/state.rs \
  --profile mutants --jobs 2 --timeout-multiplier 5 --minimum-test-timeout 300 \
  --build-timeout 2400 --cap-lints true -o /c/bszkeval/w4-mute-scratch/runT "${T[@]}"
echo "exit $?" >> /c/bszkeval/w4-mute-scratch/runT.time
date -u +"end %H:%M" >> /c/bszkeval/w4-mute-scratch/runT.time
