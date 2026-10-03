#!/usr/bin/env bash
# The prove.rs mutants only a proving test can judge: one at a time, release
# (the mutants profile builds px's own code unoptimized: one baseline took
# more than 80 minutes), >= 7 GB free at the start; manual baseline first.
set -u
S=/c/bszkeval/w4-mute-scratch
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
free() { powershell "(Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory" | tr -d '\r'; }
until [ "$(free)" -ge 7000000 ]; do sleep 30; done
cd /c/bszkeval/wt-w4-mute
unset CARGO_TARGET_DIR
P1=a_function_writing_only_its_prefix_proves_and_verifies
P2=lock_then_claim_proves_verifies_and_pays_the_recipient
date -u +"release start %H:%M free $(free)" >> $S/provingQ.time
CARGO_TARGET_DIR=C:/bszkeval/t-w4-mute-rel cargo test --locked --release -p blacksilk-px --test unified \
  -- --exact --test-threads=1 $P1 $P2 > $S/provingQ.baseline.log 2>&1
echo "baseline exit $? $(date -u +%H:%M)" >> $S/provingQ.time
mapfile -t R < $S/ev/provingP1.args
cargo mutants -p blacksilk-px -f px/src/prove.rs "${R[@]}" --baseline skip \
  --profile release --jobs 1 --timeout 2400 --build-timeout 3600 --cap-lints true \
  -o $S/provingP1 -C=--test=unified -- -- --exact --test-threads=1 $P1 > $S/provingP1.log 2>&1
echo "P1 exit $? $(date -u +%H:%M)" >> $S/provingQ.time
mapfile -t R < $S/ev/provingP2.args
cargo mutants -p blacksilk-px -f px/src/prove.rs "${R[@]}" --baseline skip \
  --profile release --jobs 1 --timeout 2400 --build-timeout 3600 --cap-lints true \
  -o $S/provingP2 -C=--test=unified -- -- --exact --test-threads=1 $P2 > $S/provingP2.log 2>&1
echo "P2 exit $? $(date -u +%H:%M)" >> $S/provingQ.time
date -u +"end %H:%M" >> $S/provingQ.time
