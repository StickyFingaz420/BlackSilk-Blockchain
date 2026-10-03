#!/usr/bin/env bash
# run E: px/src/prove.rs (statement, prove, verify), state.rs, tree.rs
set -u
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
S=/c/bszkeval/w4-mute-scratch
cd /c/bszkeval/wt-w4-mute
mapfile -t T < $S/ev/pxtests.args
date -u +"start %H:%M" > $S/runP.time
# manual baseline (--test-package: the tool's baseline cannot run these targets)
B=()
for a in "${T[@]}"; do B+=("${a#-C=}"); done
CARGO_TARGET_DIR=C:/bszkeval/t-w4-mute-mut cargo test --locked --profile mutants -p blacksilk-px -p blacksilk-tx "${B[@]}" > $S/runP.baseline.log 2>&1
echo "baseline exit $?" >> $S/runP.time
date -u +"baseline end %H:%M" >> $S/runP.time
cargo mutants -p blacksilk-px -f px/src/prove.rs -f px/src/state.rs -f px/src/tree.rs \
  --exclude-re 'check_shape' --exclude-re '^px/src/prove\.rs:9[0-9]:' \
  --test-package blacksilk-px,blacksilk-tx --baseline skip \
  --profile mutants --jobs 2 --timeout 900 --build-timeout 2400 --cap-lints true \
  -o $S/runP "${T[@]}"
echo "exit $?" >> $S/runP.time
date -u +"end %H:%M" >> $S/runP.time
