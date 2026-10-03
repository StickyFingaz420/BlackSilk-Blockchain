#!/usr/bin/env bash
# RT-MUTE item 3: the locator's boundary mutant 22:26 against the new exact-shape test
set -u
S=/c/bszkeval/w4-mute-scratch
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
cd /c/bszkeval/wt-w4-mute
BM_FILTER='header_sync\.rs:(21|24):' CARGO_TARGET_DIR=C:/bszkeval/t-w4-mute-bndLoc \
  bash tools/boundary-mutants.sh run $S/bndLoc 900 chain/src/manager/header_sync.rs -- \
  test --locked --profile mutants -p blacksilk-chain --test manager -- --exact the_locator_has_the_tip_and_nine_predecessors_one_by_one locator_and_headers_after > $S/bndLoc.log 2>&1
echo "exit $? $(date -u +%H:%M)" > $S/bndLoc.time
