#!/usr/bin/env bash
set -u
S=/c/bszkeval/w4-mute-scratch
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
until grep -q "^queueO2 end" $S/queueO2.time 2>/dev/null; do sleep 30; done
cd /c/bszkeval/wt-w4-mute
unset CARGO_TARGET_DIR
mapfile -t O < $S/ev/timeoutP.args
date -u +"timeoutP2 start %H:%M" >> $S/queueO3.time
cargo mutants -p blacksilk-px -f px/src/prove.rs "${O[@]}" --baseline skip \
  --profile mutants --jobs 1 --timeout 300 --build-timeout 2400 --cap-lints true \
  -o $S/timeoutP2 -C=--test=kernel_budget -- -- --exact a_functions_prefix_is_checked_before_its_budget > $S/timeoutP2.log 2>&1
echo "timeoutP2 exit $?" >> $S/queueO3.time
date -u +"queueO3 end %H:%M" >> $S/queueO3.time
