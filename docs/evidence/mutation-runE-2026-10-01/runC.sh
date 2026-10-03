#!/usr/bin/env bash
set -u
S=/c/bszkeval/w4-mute-scratch
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
until grep -q "^queueO3 end" $S/queueO3.time 2>/dev/null; do sleep 30; done
cd /c/bszkeval/wt-w4-mute
unset CARGO_TARGET_DIR
mapfile -t C < $S/ev/chaintests.args
date -u +"start %H:%M" > $S/runC.time
cargo mutants -p blacksilk-chain -f chain/src/manager/submission.rs -f chain/src/manager/header_sync.rs \
  --profile mutants --jobs 2 --timeout-multiplier 4 --minimum-test-timeout 300 --build-timeout 2400 \
  --cap-lints true -o $S/runC "${C[@]}" -- -- --skip restart_rebuilds_the_px_state_exactly > $S/runC.log 2>&1
echo "exit $?" >> $S/runC.time
date -u +"end %H:%M" >> $S/runC.time
