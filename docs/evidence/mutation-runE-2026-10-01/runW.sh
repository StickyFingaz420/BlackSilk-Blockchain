#!/usr/bin/env bash
# run E: wallet/src/headers.rs, and in wallet/src/wallet/sync.rs the dense PoW
# batch check, the header feed and its linkage, and the tip-age refusal
set -u
S=/c/bszkeval/w4-mute-scratch
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
cd /c/bszkeval/wt-w4-mute
unset CARGO_TARGET_DIR
RE=$(cat $S/ev/wallet.re)
date -u +"start %H:%M" > $S/runW.time
cargo mutants -p blacksilk-wallet -f wallet/src/headers.rs -f wallet/src/wallet/sync.rs \
  --re '^wallet/src/headers\.rs' --re "$RE" \
  --profile mutants --jobs 1 --timeout-multiplier 5 --minimum-test-timeout 300 --build-timeout 2400 \
  --cap-lints true -o $S/runW -C=--lib > $S/runW.log 2>&1
echo "exit $?" >> $S/runW.time
date -u +"end %H:%M" >> $S/runW.time
