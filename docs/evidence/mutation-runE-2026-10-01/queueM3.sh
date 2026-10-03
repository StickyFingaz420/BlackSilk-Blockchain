#!/usr/bin/env bash
# run E: hand mutants of conn.rs and maintenance_loop that survived handM2, on the final tests
set -u
S=/c/bszkeval/w4-mute-scratch
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
cd /c/bszkeval/wt-w4-mute
mapfile -t H < $S/ev/conn-final.tests
TG=(--lib --test network --test liveness --test connection_policy --test outbound_policy --test addr_relay --test transport_adversarial)
date -u +"start %H:%M" > $S/queueM3.time
python $S/hand.py $S/ev/handM3.tsv $S/handM3-copy C:/bszkeval/t-w4-mute-handM3 $S/handM3.txt 900 -- \
  test --locked --profile mutants -p blacksilk-p2p "${TG[@]}" -- --exact --test-threads=4 "${H[@]}" > $S/handM3.log 2>&1
echo "handM3 exit $? $(date -u +%H:%M)" >> $S/queueM3.time
