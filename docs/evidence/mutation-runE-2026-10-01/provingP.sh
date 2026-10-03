#!/usr/bin/env bash
# The prove.rs mutants only a proving test can judge: one at a time, with
# the two PX-proving unified tests (manual baseline first). >= 7 GB free.
set -u
S=/c/bszkeval/w4-mute-scratch
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
until grep -q "^end" $S/runC.time 2>/dev/null; do sleep 30; done
free() { powershell "(Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory" | tr -d ''; }
until [ "$(free)" -ge 7000000 ]; do sleep 30; done
cd /c/bszkeval/wt-w4-mute
unset CARGO_TARGET_DIR
TESTS="lock_then_claim_proves_verifies_and_pays_the_recipient a_function_writing_only_its_prefix_proves_and_verifies"
date -u +"start %H:%M free $(powershell '(Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory')" > $S/provingP.time
CARGO_TARGET_DIR=C:/bszkeval/t-w4-mute-mut cargo test --locked --profile mutants -p blacksilk-px --test unified \
  -- --exact --test-threads=1 $TESTS > $S/provingP.baseline.log 2>&1
echo "baseline exit $? $(date -u +%H:%M)" >> $S/provingP.time
mapfile -t R < $S/ev/provingP.args
cargo mutants -p blacksilk-px -f px/src/prove.rs "${R[@]}" --baseline skip \
  --profile mutants --jobs 1 --timeout 2400 --build-timeout 2400 --cap-lints true \
  -o $S/provingP -C=--test=unified -- -- --exact --test-threads=1 $TESTS > $S/provingP.log 2>&1
echo "exit $?" >> $S/provingP.time
date -u +"end %H:%M" >> $S/provingP.time
