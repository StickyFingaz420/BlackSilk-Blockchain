#!/usr/bin/env bash
# RT-MUTE F2: confirm RT's tests kill E43's 128:59/136:59 and E40's two mutants
set -u
S=/c/bszkeval/w4-mute-scratch
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
cd /c/bszkeval/wt-w4-mute
unset CARGO_TARGET_DIR
mapfile -t P < $S/ev/f2p.args
mapfile -t W < $S/ev/f2w.args
cargo mutants -p blacksilk-p2p -f p2p/src/net/maintenance.rs "${P[@]}" --baseline skip --profile mutants --jobs 1 \
  --timeout 600 --build-timeout 2400 --cap-lints true -o $S/f2p -C=--lib -- -- --exact \
  net::maintenance::tests::an_elapsed_time_equal_to_a_zero_limit_does_not_trigger_it > $S/f2p.log 2>&1
echo "p2p exit $? $(date -u +%H:%M)" >> $S/f2.time
cargo mutants -p blacksilk-wallet -f wallet/src/wallet/sync.rs "${W[@]}" --baseline skip --profile mutants --jobs 1 \
  --timeout 600 --build-timeout 2400 --cap-lints true -o $S/f2w -C=--lib -- -- \
  the_tip_age_limits_are_strict_at_their_exact_second > $S/f2w.log 2>&1
echo "wallet exit $? $(date -u +%H:%M)" >> $S/f2.time
