#!/usr/bin/env bash
# run E tier 1: the CI's non-PX test job (release), in its own target directory
set -u
S=/c/bszkeval/w4-mute-scratch
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=C:/bszkeval/t-w4-mute-rel
cd /c/bszkeval/wt-w4-mute
date -u +"start %H:%M $(git rev-parse --short HEAD)" > $S/tier1.time
tx_tests=$(ls tx/tests | sed -n 's/\.rs$//p' | grep -vx 'px_consensus\|fuzz_decode' | sed 's/^/--test /')
cargo test --locked --release --no-fail-fast -p blacksilk-tx --lib $tx_tests > $S/tier1-tx.log 2>&1
echo "tx exit $? $(date -u +%H:%M)" >> $S/tier1.time
px_tests=$(ls px/tests | sed -n 's/\.rs$//p' | grep -vx 'proof\|unified' | sed 's/^/--test /')
cargo test --locked --release --no-fail-fast -p blacksilk-px --lib $px_tests > $S/tier1-px.log 2>&1
echo "px exit $? $(date -u +%H:%M)" >> $S/tier1.time
cargo test --locked --release --workspace --no-fail-fast \
  --exclude blacksilk-tx --exclude blacksilk-px -- \
  --skip restart_rebuilds_the_px_state_exactly \
  --skip px_transactions_travel_the_stem --skip invalid_px_transactions_get_the_relaying_peer_penalized \
  --skip private_funds_move_over_rpc --skip px_records_follow_a_reorganization \
  --skip a_vault_is_deployed --skip an_uncertain_vault_lock > $S/tier1-ws.log 2>&1
echo "workspace exit $? $(date -u +%H:%M)" >> $S/tier1.time
