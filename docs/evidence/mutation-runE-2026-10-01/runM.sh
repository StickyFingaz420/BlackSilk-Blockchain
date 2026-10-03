#!/usr/bin/env bash
# run E: p2p/src/net/conn.rs (but knows_tip, run D) and maintenance.rs maintenance_loop
set -u
S=/c/bszkeval/w4-mute-scratch
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
# (starts at once, beside the p2p headers follow-ups)
cd /c/bszkeval/wt-w4-mute
unset CARGO_TARGET_DIR
mapfile -t H < $S/ev/conn.tests
TG=(--lib --test network --test liveness --test connection_policy --test outbound_policy --test addr_relay --test transport_adversarial)
date -u +"start %H:%M" > $S/runM.time
for i in 1 2; do
  CARGO_TARGET_DIR=C:/bszkeval/t-w4-mute-mut cargo test --locked --profile mutants -p blacksilk-p2p "${TG[@]}" \
    -- --exact --test-threads=4 "${H[@]}" > $S/runM.baseline$i.log 2>&1
  echo "baseline $i exit $? $(date -u +%H:%M)" >> $S/runM.time
done
cargo mutants -p blacksilk-p2p -f p2p/src/net/conn.rs -f p2p/src/net/maintenance.rs \
  --re '^p2p/src/net/conn\.rs' --re ' maintenance_loop( |$)' --exclude-re 'knows_tip' --baseline skip \
  --profile mutants --jobs 1 --timeout 900 --build-timeout 2400 --cap-lints true -o $S/runM \
  -C=--lib -C=--test=network -C=--test=liveness -C=--test=connection_policy -C=--test=outbound_policy \
  -C=--test=addr_relay -C=--test=transport_adversarial \
  -- -- --exact --test-threads=4 "${H[@]}" > $S/runM.log 2>&1
echo "exit $?" >> $S/runM.time
date -u +"end %H:%M" >> $S/runM.time
