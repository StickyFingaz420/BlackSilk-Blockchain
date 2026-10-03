#!/usr/bin/env bash
set -u
S=/c/bszkeval/w4-mute-scratch
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
# (provingP moved to the end of the queue)
cd /c/bszkeval/wt-w4-mute
unset CARGO_TARGET_DIR
mapfile -t C < $S/ev/chaintests.args
F=(-f chain/src/manager/submission.rs -f chain/src/manager/header_sync.rs)
SK=(--skip restart_rebuilds_the_px_state_exactly)
mapfile -t R < $S/ev/rerunC.args
date -u +"rerunC start %H:%M" >> $S/queueC.time
cargo mutants -p blacksilk-chain "${F[@]}" "${R[@]}" --profile mutants --jobs 2 --timeout 900 \
  --build-timeout 2400 --cap-lints true -o $S/rerunC "${C[@]}" -- -- "${SK[@]}" > $S/rerunC.log 2>&1
echo "rerunC exit $?" >> $S/queueC.time
mapfile -t R < $S/ev/hookC.args
cargo mutants -p blacksilk-chain "${F[@]}" "${R[@]}" --profile mutants --jobs 1 --timeout-multiplier 4 \
  --minimum-test-timeout 600 --build-timeout 3600 --cap-lints true -o $S/hookC -C=--test=actor_order > $S/hookC.log 2>&1
echo "hookC exit $?" >> $S/queueC.time
mapfile -t R < $S/ev/timeoutC1.args
cargo mutants -p blacksilk-chain "${F[@]}" "${R[@]}" --profile mutants --jobs 1 --baseline skip --timeout 300 \
  --build-timeout 3600 --cap-lints true -o $S/timeoutC1 -C=--test=fork_choice -- -- \
  a_withheld_body_cannot_stall_block_production an_equal_work_side_branch_is_not_fetched \
  a_side_branchs_stored_bodies_are_not_listed_as_missing > $S/timeoutC1.log 2>&1
echo "timeoutC1 exit $?" >> $S/queueC.time
mapfile -t R < $S/ev/timeoutC2.args
cargo mutants -p blacksilk-chain "${F[@]}" "${R[@]}" --profile mutants --jobs 1 --baseline skip --timeout 300 \
  --build-timeout 3600 --cap-lints true -o $S/timeoutC2 -C=--lib -- -- manager::submission::tests > $S/timeoutC2.log 2>&1
echo "timeoutC2 exit $?" >> $S/queueC.time
B=(); for a in "${C[@]}"; do B+=("${a#-C=}"); done
date -u +"boundaryC start %H:%M" >> $S/queueC.time
CARGO_TARGET_DIR=C:/bszkeval/t-w4-mute-bndC bash tools/boundary-mutants.sh run $S/bndC 1800 \
  chain/src/manager/submission.rs chain/src/manager/header_sync.rs -- test --locked --profile mutants \
  -p blacksilk-chain "${B[@]}" -- --skip restart_rebuilds_the_px_state_exactly > $S/bndC.log 2>&1
echo "boundaryC exit $?" >> $S/queueC.time
date -u +"handC start %H:%M" >> $S/queueC.time
python $S/hand.py $S/ev/handC.tsv $S/handC-copy C:/bszkeval/t-w4-mute-handC $S/handC.txt 1800 -- \
  test --locked --profile mutants -p blacksilk-chain "${B[@]}" -- --skip restart_rebuilds_the_px_state_exactly > $S/handC.log 2>&1
echo "handC exit $?" >> $S/queueC.time
date -u +"queueC end %H:%M" >> $S/queueC.time
