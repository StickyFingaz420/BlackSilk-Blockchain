#!/usr/bin/env bash
set -u
S=/c/bszkeval/w4-mute-scratch
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
until grep -q "^end" $S/runH.time 2>/dev/null; do sleep 30; done
cd /c/bszkeval/wt-w4-mute
unset CARGO_TARGET_DIR
mapfile -t H < $S/ev/headers-final.tests
TG=(--lib --test network --test liveness --test withheld_body --test sync_policy --test outbound_policy)
cat $S/runH/mutants.out/missed.txt $S/runH/mutants.out/timeout.txt | python $S/mkre.py > $S/ev/rerunH.args
date -u +"start %H:%M" > $S/rerunH.time
for i in 1 2 3; do
  CARGO_TARGET_DIR=C:/bszkeval/t-w4-mute-mut cargo test --locked --profile mutants -p blacksilk-p2p "${TG[@]}" \
    -- --exact --test-threads=4 "${H[@]}" > $S/rerunH.baseline$i.log 2>&1
  echo "baseline $i exit $? $(date -u +%H:%M)" >> $S/rerunH.time
done
mapfile -t R < $S/ev/rerunH.args
cargo mutants -p blacksilk-p2p -f p2p/src/net/headers.rs "${R[@]}" --baseline skip \
  --profile mutants --jobs 1 --timeout 600 --build-timeout 2400 --cap-lints true -o $S/rerunH \
  -C=--lib -C=--test=network -C=--test=liveness -C=--test=withheld_body -C=--test=sync_policy -C=--test=outbound_policy \
  -- -- --exact --test-threads=4 "${H[@]}" > $S/rerunH.log 2>&1
echo "exit $?" >> $S/rerunH.time
date -u +"end %H:%M" >> $S/rerunH.time
