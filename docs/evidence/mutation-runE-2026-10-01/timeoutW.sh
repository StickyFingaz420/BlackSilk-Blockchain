#!/usr/bin/env bash
set -u
S=/c/bszkeval/w4-mute-scratch
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
cd /c/bszkeval/wt-w4-mute
unset CARGO_TARGET_DIR
F=(-f wallet/src/headers.rs -f wallet/src/wallet/sync.rs)
mapfile -t R < $S/ev/timeoutW1.args
cargo mutants -p blacksilk-wallet "${F[@]}" "${R[@]}" --baseline skip --profile mutants --jobs 1 --timeout 300 \
  --build-timeout 2400 --cap-lints true -o $S/timeoutW1 -C=--lib -- -- --exact \
  wallet::tests_sync::a_malformed_header_feed_page_is_refused > $S/timeoutW1.log 2>&1
echo "W1 exit $?" >> $S/timeoutW.time
mapfile -t R < $S/ev/timeoutW2.args
cargo mutants -p blacksilk-wallet "${F[@]}" "${R[@]}" --baseline skip --profile mutants --jobs 1 --timeout 120 \
  --build-timeout 2400 --cap-lints true -o $S/timeoutW2 -C=--lib -- -- --exact \
  wallet::tests_sync::the_header_checks_threads_and_key_blocks > $S/timeoutW2.log 2>&1
echo "W2 exit $?" >> $S/timeoutW.time
date -u +"end %H:%M" >> $S/timeoutW.time
