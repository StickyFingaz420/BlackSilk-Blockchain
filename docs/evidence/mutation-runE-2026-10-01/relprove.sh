#!/usr/bin/env bash
# The new PX-proving test, release, alone, with >= 7 GB free at its start.
set -u
S=/c/bszkeval/w4-mute-scratch
export CARGO_TARGET_DIR=C:/bszkeval/t-w4-mute-rel CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
cd /c/bszkeval/wt-w4-mute
cargo test --locked --release -p blacksilk-px --test unified --no-run > $S/rel-build.log 2>&1
echo "build exit $? $(date -u +%H:%M)" > $S/relprove.time
free() { powershell "(Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory" | tr -d '\r'; }
until [ "$(free)" -ge 7000000 ]; do sleep 30; done
echo "free $(free) at $(date -u +%H:%M:%S)" >> $S/relprove.time
cargo test --locked --release -p blacksilk-px --test unified -- --exact --test-threads=1 \
  a_function_writing_only_its_prefix_proves_and_verifies > $S/rel-unified-new.log 2>&1
echo "test exit $? $(date -u +%H:%M:%S)" >> $S/relprove.time
