#!/usr/bin/env bash
set -u
S=/c/bszkeval/w4-mute-scratch
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
until grep -q "^queueO end" $S/queueO.time 2>/dev/null; do sleep 30; done
cd /c/bszkeval/wt-w4-mute
unset CARGO_TARGET_DIR
mapfile -t T < $S/ev/txtests-rerun.args
B=(); for a in "${T[@]}"; do B+=("${a#-C=}"); done
date -u +"handT start %H:%M" >> $S/queueO2.time
python $S/hand.py $S/ev/handT.tsv $S/handT-copy C:/bszkeval/t-w4-mute-handT $S/handT.txt 900 -- \
  test --locked --profile mutants -p blacksilk-tx "${B[@]}" > $S/handT.log 2>&1
echo "handT exit $?" >> $S/queueO2.time
date -u +"queueO2 end %H:%M" >> $S/queueO2.time
