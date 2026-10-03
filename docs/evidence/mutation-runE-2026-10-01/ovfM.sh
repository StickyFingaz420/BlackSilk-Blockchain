#!/usr/bin/env bash
# run E: release arithmetic for runM's one overflow-only kill (conn.rs 215:25)
set -u
S=/c/bszkeval/w4-mute-scratch
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
until grep -q "handM3 exit" $S/queueM3.time 2>/dev/null; do sleep 30; done
cd /c/bszkeval/wt-w4-mute
unset CARGO_TARGET_DIR
mapfile -t R < $S/ev/ovfM.args
RUSTFLAGS="-C overflow-checks=off -C debug-assertions=off" cargo mutants -p blacksilk-p2p \
  -f p2p/src/net/conn.rs "${R[@]}" --profile mutants --jobs 1 --baseline skip \
  --timeout 600 --build-timeout 3600 --cap-lints true -o $S/ovfM -C=--test=network \
  -- -- --exact at_most_eight_unknown_frames_are_skipped_in_the_handshake an_extended_version_and_unknown_handshake_messages_are_accepted > $S/ovfM.log 2>&1
echo "exit $? $(date -u +%H:%M)" > $S/ovfM.time
