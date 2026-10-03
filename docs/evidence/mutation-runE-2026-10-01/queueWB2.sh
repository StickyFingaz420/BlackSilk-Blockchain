#!/usr/bin/env bash
set -u
S=/c/bszkeval/w4-mute-scratch
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
until grep -q "^queueWB end" $S/queueWB.time 2>/dev/null; do sleep 30; done
cd /c/bszkeval/wt-w4-mute
rm -rf $S/handW2-copy
python $S/hand.py $S/ev/handW2.tsv $S/handW2-copy C:/bszkeval/t-w4-mute-handW $S/handW2.txt 900 -- \
  test --locked --profile mutants -p blacksilk-wallet --lib > $S/handW2.log 2>&1
echo "handW2 exit $?" >> $S/queueWB2.time
BM_FILTER='^wallet/src/headers\.rs:363:' CARGO_TARGET_DIR=C:/bszkeval/t-w4-mute-bndW \
  bash tools/boundary-mutants.sh run $S/bndW2 900 wallet/src/headers.rs -- \
  test --locked --profile mutants -p blacksilk-wallet --lib > $S/bndW2.log 2>&1
echo "boundaryW2 exit $?" >> $S/queueWB2.time
date -u +"queueWB2 end %H:%M" >> $S/queueWB2.time
