#!/usr/bin/env bash
set -u
S=/c/bszkeval/w4-mute-scratch
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
until grep -q "^queueT end" $S/queueT.time 2>/dev/null; do sleep 30; done
cd /c/bszkeval/wt-w4-mute
unset CARGO_TARGET_DIR
mapfile -t T < $S/ev/pxtests.args
B=(); for a in "${T[@]}"; do B+=("${a#-C=}"); done
date -u +"rerunP start %H:%M" >> $S/queueP.time
# manual baseline on the same tree (the final tests)
CARGO_TARGET_DIR=C:/bszkeval/t-w4-mute-mut cargo test --locked --profile mutants -p blacksilk-px -p blacksilk-tx "${B[@]}" > $S/rerunP.baseline.log 2>&1
echo "rerunP baseline exit $?" >> $S/queueP.time
mapfile -t R < $S/ev/rerunP.args
cargo mutants -p blacksilk-px -f px/src/prove.rs -f px/src/state.rs -f px/src/tree.rs "${R[@]}" \
  --test-package blacksilk-px,blacksilk-tx --baseline skip \
  --profile mutants --jobs 2 --timeout 600 --build-timeout 2400 --cap-lints true \
  -o $S/rerunP "${T[@]}" > $S/rerunP.log 2>&1
echo "rerunP exit $?" >> $S/queueP.time
# timeoutP: check_budget -> Ok(()) with only the prefix-before-budget test
mapfile -t O < $S/ev/timeoutP.args
cargo mutants -p blacksilk-px -f px/src/prove.rs "${O[@]}" --baseline skip \
  --profile mutants --jobs 1 --timeout 300 --build-timeout 2400 --cap-lints true \
  -o $S/timeoutP -C=--test=kernel_budget -- -- --exact a_functions_prefix_is_checked_before_its_budget > $S/timeoutP.log 2>&1
echo "timeoutP exit $?" >> $S/queueP.time
date -u +"boundaryP start %H:%M" >> $S/queueP.time
CARGO_TARGET_DIR=C:/bszkeval/t-w4-mute-bndP bash tools/boundary-mutants.sh run $S/bndP 900 \
  px/src/prove.rs px/src/state.rs px/src/tree.rs -- test --locked --profile mutants -p blacksilk-px -p blacksilk-tx "${B[@]}" \
  > $S/bndP.log 2>&1
echo "boundaryP exit $?" >> $S/queueP.time
date -u +"handP start %H:%M" >> $S/queueP.time
python $S/hand.py $S/ev/handP.tsv $S/handP-copy C:/bszkeval/t-w4-mute-handP $S/handP.txt 900 -- \
  test --locked --profile mutants -p blacksilk-px -p blacksilk-tx "${B[@]}" > $S/handP.log 2>&1
echo "handP exit $?" >> $S/queueP.time
date -u +"queueP end %H:%M" >> $S/queueP.time
