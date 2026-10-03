#!/usr/bin/env bash
set -u
S=/c/bszkeval/w4-mute-scratch
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
cd /c/bszkeval/wt-w4-mute
unset CARGO_TARGET_DIR
mapfile -t R < $S/ev/ovfW.args
RUSTFLAGS="-C overflow-checks=off -C debug-assertions=off" cargo mutants -p blacksilk-wallet \
  -f wallet/src/headers.rs -f wallet/src/wallet/sync.rs "${R[@]}" --profile mutants --jobs 1 --baseline skip \
  --timeout 600 --build-timeout 3600 --cap-lints true -o $S/ovfW -C=--lib > $S/ovfW.log 2>&1
echo "exit $? $(date -u +%H:%M)" > $S/ovfW.time
