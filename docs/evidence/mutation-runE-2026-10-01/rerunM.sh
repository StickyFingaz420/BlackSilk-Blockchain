#!/usr/bin/env bash
# run E: runM's survivors and timeouts against the final conn test list
set -u
S=/c/bszkeval/w4-mute-scratch
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
cd /c/bszkeval/wt-w4-mute
unset CARGO_TARGET_DIR
mapfile -t H < $S/ev/conn-final.tests
TG=(--lib --test network --test liveness --test connection_policy --test outbound_policy --test addr_relay --test transport_adversarial)
cat $S/runM/mutants.out/missed.txt $S/runM/mutants.out/timeout.txt | python $S/mkre.py > $S/ev/rerunM.args
date -u +"start %H:%M" > $S/rerunM.time
for i in 1 2; do
  CARGO_TARGET_DIR=C:/bszkeval/t-w4-mute-rerunM cargo test --locked --profile mutants -p blacksilk-p2p "${TG[@]}" \
    -- --exact --test-threads=4 "${H[@]}" > $S/rerunM.baseline$i.log 2>&1
  echo "baseline $i exit $? $(date -u +%H:%M)" >> $S/rerunM.time
done
mapfile -t R < $S/ev/rerunM.args
cargo mutants -p blacksilk-p2p -f p2p/src/net/conn.rs -f p2p/src/net/maintenance.rs "${R[@]}" --baseline skip \
  --profile mutants --jobs 1 --timeout 900 --build-timeout 2400 --cap-lints true -o $S/rerunM \
  -C=--lib -C=--test=network -C=--test=liveness -C=--test=connection_policy -C=--test=outbound_policy \
  -C=--test=addr_relay -C=--test=transport_adversarial \
  -- -- --exact --test-threads=4 "${H[@]}" > $S/rerunM.log 2>&1
echo "exit $?" >> $S/rerunM.time
date -u +"end %H:%M" >> $S/rerunM.time
