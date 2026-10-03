#!/usr/bin/env bash
set -u
S=/c/bszkeval/w4-mute-scratch
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
until grep -q "^queueF2 end" $S/queueF2.time 2>/dev/null; do sleep 30; done
cd /c/bszkeval/wt-w4-mute
unset CARGO_TARGET_DIR
mapfile -t R < $S/ev/rerunW.args
date -u +"start %H:%M" > $S/rerunW.time
cargo mutants -p blacksilk-wallet -f wallet/src/headers.rs -f wallet/src/wallet/sync.rs "${R[@]}" \
  --profile mutants --jobs 1 --timeout 600 --build-timeout 2400 --cap-lints true -o $S/rerunW -C=--lib > $S/rerunW.log 2>&1
echo "exit $?" >> $S/rerunW.time
date -u +"end %H:%M" >> $S/rerunW.time
