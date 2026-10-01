#!/usr/bin/env bash
# Mutation run D, items 3 and 4 (p2p admission and W4-SYNC; chain summary),
# before (base export) and after (the working tree). -j2.
set -u
unset CARGO_TARGET_DIR
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
S=C:/bszkeval/w4-mutd-scratch
T=C:/bszkeval/wt-w4-mutd
mapfile -t AP < $S/admissionP.args
mapfile -t SP < $S/syncP.args
mapfile -t SC < $S/summaryC.args
mapfile -t AT < $S/admission.tests
mapfile -t ST < $S/sync.tests
COMMON=(--profile mutants --jobs 2 --baseline skip --build-timeout 2400 --cap-lints true)
SYNCFILES=(-f p2p/src/net/state.rs -f p2p/src/net/conn.rs -f p2p/src/net/maintenance.rs -f p2p/src/net/headers.rs)
stamp() { echo "$1 $(date -u +%H:%M)" >> $S/p2p.times; }
for side in ${SIDES:-before after}; do
  if [ $side = before ]; then D=$S/base; else D=$T; fi
  stamp "$side-admission-start"
  cargo mutants -d $D -p blacksilk-p2p -f p2p/src/net/admission.rs "${AP[@]}" "${COMMON[@]}" --timeout 300 \
    -o $S/$side-admissionP -C=--lib -C=--test=network -- -- --exact --test-threads=4 "${AT[@]}" > $S/$side-admissionP.log 2>&1
  stamp "$side-sync-start"
  cargo mutants -d $D -p blacksilk-p2p "${SYNCFILES[@]}" "${SP[@]}" "${COMMON[@]}" --timeout 600 \
    -o $S/$side-syncP -C=--test=network -C=--test=liveness -C=--test=withheld_body -- -- --exact --test-threads=4 "${ST[@]}" > $S/$side-syncP.log 2>&1
  stamp "$side-summary-start"
  cargo mutants -d $D -p blacksilk-chain -f chain/src/manager/summary.rs "${SC[@]}" --test-package blacksilk-chain,blacksilk-p2p "${COMMON[@]}" --timeout 600 \
    -o $S/$side-summaryC -C=--test=manager -C=--test=network -C=--test=liveness -C=--test=withheld_body -- -- --exact --test-threads=4 "${ST[@]}" the_summary_flags_a_tip_off_the_best_header_chain_and_calls_tip_listeners > $S/$side-summaryC.log 2>&1
  stamp "$side-end"
done
