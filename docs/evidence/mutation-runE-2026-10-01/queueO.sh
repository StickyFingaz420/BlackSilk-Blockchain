#!/usr/bin/env bash
set -u
S=/c/bszkeval/w4-mute-scratch
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
until grep -q "^queueP end" $S/queueP.time 2>/dev/null; do sleep 30; done
cd /c/bszkeval/wt-w4-mute
unset CARGO_TARGET_DIR
mapfile -t T < $S/ev/txtests-rerun.args
mapfile -t R < $S/ev/ovfT.args
date -u +"ovfT start %H:%M" >> $S/queueO.time
RUSTFLAGS="-C overflow-checks=off -C debug-assertions=off" cargo mutants -p blacksilk-tx \
  -f tx/src/types.rs -f tx/src/codec.rs -f tx/src/state.rs "${R[@]}" --profile mutants --jobs 2 \
  --baseline skip --timeout 700 --build-timeout 3600 --cap-lints true -o $S/ovfT "${T[@]}" > $S/ovfT.log 2>&1
echo "ovfT exit $?" >> $S/queueO.time
mapfile -t P < $S/ev/pxtests.args
mapfile -t R < $S/ev/ovfP.args
RUSTFLAGS="-C overflow-checks=off -C debug-assertions=off" cargo mutants -p blacksilk-px \
  -f px/src/prove.rs -f px/src/state.rs -f px/src/tree.rs "${R[@]}" --test-package blacksilk-px,blacksilk-tx \
  --profile mutants --jobs 2 --baseline skip --timeout 600 --build-timeout 3600 --cap-lints true \
  -o $S/ovfP "${P[@]}" > $S/ovfP.log 2>&1
echo "ovfP exit $?" >> $S/queueO.time
date -u +"queueO end %H:%M" >> $S/queueO.time
