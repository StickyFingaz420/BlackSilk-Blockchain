#!/usr/bin/env bash
# run E: boundary pass and hand mutants for conn.rs and maintenance_loop
set -u
S=/c/bszkeval/w4-mute-scratch
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
cd /c/bszkeval/wt-w4-mute
mapfile -t H < $S/ev/conn-final.tests
TG=(--lib --test network --test liveness --test connection_policy --test outbound_policy --test addr_relay --test transport_adversarial)
date -u +"start %H:%M" > $S/queueM2.time
BM_FILTER='conn\.rs|maintenance\.rs:(119|167|179):' CARGO_TARGET_DIR=C:/bszkeval/t-w4-mute-bndM2 \
  bash tools/boundary-mutants.sh run $S/bndM2 900 p2p/src/net/conn.rs p2p/src/net/maintenance.rs -- \
  test --locked --profile mutants -p blacksilk-p2p "${TG[@]}" -- --exact --test-threads=4 "${H[@]}" > $S/bndM2.log 2>&1
echo "bndM2 exit $? $(date -u +%H:%M)" >> $S/queueM2.time
python $S/hand.py $S/ev/handM.tsv $S/handM2-copy C:/bszkeval/t-w4-mute-handM2 $S/handM2.txt 900 -- \
  test --locked --profile mutants -p blacksilk-p2p "${TG[@]}" -- --exact --test-threads=4 "${H[@]}" > $S/handM2.log 2>&1
echo "handM2 exit $? $(date -u +%H:%M)" >> $S/queueM2.time
