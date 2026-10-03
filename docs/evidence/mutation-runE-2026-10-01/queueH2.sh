#!/usr/bin/env bash
set -u
S=/c/bszkeval/w4-mute-scratch
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
until grep -q "^end" $S/timeoutH.time 2>/dev/null; do sleep 30; done
cd /c/bszkeval/wt-w4-mute
unset CARGO_TARGET_DIR
mapfile -t H < $S/ev/headers-final2.tests
TG=(--lib --test network --test liveness --test withheld_body --test sync_policy --test outbound_policy)
date -u +"start %H:%M" > $S/queueH2.time
# rerunH2: what rerunH left (missed), with the two newest unit tests
cat $S/rerunH/mutants.out/missed.txt | python $S/mkre.py > $S/ev/rerunH2.args
mapfile -t R < $S/ev/rerunH2.args
cargo mutants -p blacksilk-p2p -f p2p/src/net/headers.rs "${R[@]}" --baseline skip \
  --profile mutants --jobs 1 --timeout 600 --build-timeout 2400 --cap-lints true -o $S/rerunH2 \
  -C=--lib -C=--test=network -C=--test=liveness -C=--test=withheld_body -C=--test=sync_policy -C=--test=outbound_policy \
  -- -- --exact --test-threads=4 "${H[@]}" > $S/rerunH2.log 2>&1
echo "rerunH2 exit $?" >> $S/queueH2.time
B=(test --locked --profile mutants -p blacksilk-p2p "${TG[@]}" -- --exact --test-threads=4 "${H[@]}")
CARGO_TARGET_DIR=C:/bszkeval/t-w4-mute-bndH bash tools/boundary-mutants.sh run $S/bndH 1200 \
  p2p/src/net/headers.rs -- "${B[@]}" > $S/bndH.log 2>&1
echo "boundaryH exit $?" >> $S/queueH2.time
python $S/hand.py $S/ev/handH.tsv $S/handH-copy C:/bszkeval/t-w4-mute-handH $S/handH.txt 1200 -- "${B[@]}" > $S/handH.log 2>&1
echo "handH exit $?" >> $S/queueH2.time
date -u +"queueH2 end %H:%M" >> $S/queueH2.time
