#!/usr/bin/env bash
set -u
S=/c/bszkeval/w4-mute-scratch
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
until grep -q "^end" $S/runW.time 2>/dev/null; do sleep 30; done
cd /c/bszkeval/wt-w4-mute
rm -rf $S/handC2-copy
date -u +"handC2 start %H:%M" >> $S/queueF.time
python $S/hand.py $S/ev/handC2.tsv $S/handC2-copy C:/bszkeval/t-w4-mute-handC $S/handC2.txt 900 -- \
  test --locked --profile mutants -p blacksilk-chain --test storage_recovery > $S/handC2.log 2>&1
echo "handC2 exit $?" >> $S/queueF.time
date -u +"queueF end %H:%M" >> $S/queueF.time
