#!/usr/bin/env bash
set -u
S=/c/bszkeval/w4-mute-scratch
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
cd /c/bszkeval/wt-w4-mute
date -u +"boundaryW start %H:%M" >> $S/queueWB.time
BM_FILTER='^wallet/src/headers\.rs|^wallet/src/wallet/sync\.rs:157:' CARGO_TARGET_DIR=C:/bszkeval/t-w4-mute-bndW \
  bash tools/boundary-mutants.sh run $S/bndW 900 wallet/src/headers.rs wallet/src/wallet/sync.rs -- \
  test --locked --profile mutants -p blacksilk-wallet --lib > $S/bndW.log 2>&1
echo "boundaryW exit $?" >> $S/queueWB.time
python $S/hand.py $S/ev/handW.tsv $S/handW-copy C:/bszkeval/t-w4-mute-handW $S/handW.txt 900 -- \
  test --locked --profile mutants -p blacksilk-wallet --lib > $S/handW.log 2>&1
echo "handW exit $?" >> $S/queueWB.time
date -u +"queueWB end %H:%M" >> $S/queueWB.time
