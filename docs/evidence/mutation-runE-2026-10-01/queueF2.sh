#!/usr/bin/env bash
set -u
S=/c/bszkeval/w4-mute-scratch
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
until grep -q "^queueF end" $S/queueF.time 2>/dev/null; do sleep 30; done
cd /c/bszkeval/wt-w4-mute
unset CARGO_TARGET_DIR
mapfile -t C < $S/ev/chaintests.args
mapfile -t R < $S/ev/ovfC.args
date -u +"ovfC start %H:%M" >> $S/queueF2.time
RUSTFLAGS="-C overflow-checks=off -C debug-assertions=off" cargo mutants -p blacksilk-chain \
  -f chain/src/manager/submission.rs -f chain/src/manager/header_sync.rs "${R[@]}" --profile mutants --jobs 1 \
  --baseline skip --timeout 1200 --build-timeout 3600 --cap-lints true -o $S/ovfC "${C[@]}" -- -- \
  --skip restart_rebuilds_the_px_state_exactly > $S/ovfC.log 2>&1
echo "ovfC exit $?" >> $S/queueF2.time
date -u +"queueF2 end %H:%M" >> $S/queueF2.time
