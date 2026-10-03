#!/usr/bin/env bash
# run E: p2p/src/net/headers.rs (all but end_of, censused in run D)
set -u
S=/c/bszkeval/w4-mute-scratch
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
until grep -q "^queueC2 end" $S/queueC2.time 2>/dev/null; do sleep 30; done
cd /c/bszkeval/wt-w4-mute
unset CARGO_TARGET_DIR
mapfile -t H < $S/ev/headers.tests
date -u +"start %H:%M" > $S/runH.time
for i in 1 2 3; do
  CARGO_TARGET_DIR=C:/bszkeval/t-w4-mute-mut cargo test --locked --profile mutants -p blacksilk-p2p --lib \
    --test network --test liveness --test withheld_body --test sync_policy -- --exact --test-threads=4 "${H[@]}" \
    > $S/runH.baseline$i.log 2>&1
  echo "baseline $i exit $? $(date -u +%H:%M)" >> $S/runH.time
done
cargo mutants -p blacksilk-p2p -f p2p/src/net/headers.rs --exclude-re 'end_of' --baseline skip \
  --profile mutants --jobs 1 --timeout 600 --build-timeout 2400 --cap-lints true -o $S/runH \
  -C=--lib -C=--test=network -C=--test=liveness -C=--test=withheld_body -C=--test=sync_policy \
  -- -- --exact --test-threads=4 "${H[@]}" > $S/runH.log 2>&1
echo "exit $?" >> $S/runH.time
date -u +"end %H:%M" >> $S/runH.time
