#!/usr/bin/env bash
set -u
S=/c/bszkeval/w4-mute-scratch
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
until grep -q "^exit" $S/runP.time 2>/dev/null; do sleep 30; done
cd /c/bszkeval/wt-w4-mute
unset CARGO_TARGET_DIR
mapfile -t T < $S/ev/txtests-rerun.args
mapfile -t R < $S/ev/rerunT.args
date -u +"rerunT start %H:%M" >> $S/queueT.time
cargo mutants -p blacksilk-tx -f tx/src/types.rs -f tx/src/codec.rs -f tx/src/state.rs "${R[@]}" \
  --profile mutants --jobs 2 --timeout 700 --build-timeout 2400 --cap-lints true \
  -o $S/rerunT "${T[@]}" > $S/rerunT.log 2>&1
echo "rerunT exit $?" >> $S/queueT.time
# boundary pass and hand mutants: oracle arguments without -C=
B=(); for a in "${T[@]}"; do B+=("${a#-C=}"); done
date -u +"boundaryT start %H:%M" >> $S/queueT.time
CARGO_TARGET_DIR=C:/bszkeval/t-w4-mute-bndT bash tools/boundary-mutants.sh run $S/bndT 900 \
  tx/src/types.rs tx/src/codec.rs tx/src/state.rs -- test --locked --profile mutants -p blacksilk-tx "${B[@]}" \
  > $S/bndT.log 2>&1
echo "boundaryT exit $?" >> $S/queueT.time
date -u +"handT start %H:%M" >> $S/queueT.time
python $S/hand.py $S/ev/handT.tsv $S/handT-copy C:/bszkeval/t-w4-mute-handT $S/handT.txt 900 -- \
  test --locked --profile mutants -p blacksilk-tx "${B[@]}" > $S/handT.log 2>&1
echo "handT exit $?" >> $S/queueT.time
date -u +"queueT end %H:%M" >> $S/queueT.time
