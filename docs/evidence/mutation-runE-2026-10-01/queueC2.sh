#!/usr/bin/env bash
set -u
S=/c/bszkeval/w4-mute-scratch
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
until grep -q "^queueC end" $S/queueC.time 2>/dev/null; do sleep 30; done
cd /c/bszkeval/wt-w4-mute
unset CARGO_TARGET_DIR
mapfile -t R < $S/ev/hookC2.args
date -u +"hookC2 start %H:%M" >> $S/queueC2.time
cargo mutants -p blacksilk-chain -f chain/src/manager/submission.rs "${R[@]}" --profile mutants --jobs 1 \
  --baseline skip --timeout 600 --build-timeout 3600 --cap-lints true -o $S/hookC2 -C=--test=manager -- -- \
  --exact the_test_step_delay_applies_to_drain_steps_with_blocks_to_connect > $S/hookC2.log 2>&1
echo "hookC2 exit $?" >> $S/queueC2.time
date -u +"queueC2 end %H:%M" >> $S/queueC2.time
