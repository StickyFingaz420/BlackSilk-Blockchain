#!/usr/bin/env bash
# run E: hand mutants of conn.rs and maintenance_loop that survived handM2, on the final tests
set -u
S=/c/bszkeval/w4-mute-scratch
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
cd /c/bszkeval/wt-w4-mute
mapfile -t H < $S/ev/conn-final.tests
TG=(--lib --test network --test liveness --test connection_policy --test outbound_policy --test addr_relay --test transport_adversarial)
until grep -q "^workspace exit" $S/tier1.time && [ -f $S/ovfM.time ]; do sleep 30; done
date -u +"start %H:%M" > $S/queueM4.time
python $S/hand.py $S/ev/handM4.tsv $S/handM4-copy C:/bszkeval/t-w4-mute-handM4 $S/handM4.txt 900 -- \
  test --locked --profile mutants -p blacksilk-p2p "${TG[@]}" -- --exact --test-threads=4 "${H[@]}" > $S/handM4.log 2>&1
echo "handM4 exit $? $(date -u +%H:%M)" >> $S/queueM4.time
