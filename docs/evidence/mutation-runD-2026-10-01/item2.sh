#!/usr/bin/env bash
# Mutation run D, item 2 and the zk analysis helpers: before (base export)
# and after (the working tree). -j2.
set -u
unset CARGO_TARGET_DIR
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
S=C:/bszkeval/w4-mutd-scratch
T=C:/bszkeval/wt-w4-mutd
mapfile -t AZ < $S/analysisZ.args
mapfile -t PW < $S/proveW.args
mapfile -t VW < $S/validateW.args
mapfile -t TX < $S/txtests.args
COMMON=(--profile mutants --jobs 2 --baseline skip --build-timeout 2400 --cap-lints true)
stamp() { echo "$1 $(date -u +%H:%M)" >> $S/item2.times; }
for side in before after; do
  if [ $side = before ]; then D=$S/base; EXTRA=(); else D=$T; EXTRA=(-C=--test=px_proof_wiring); fi
  stamp "$side-analysis-start"
  cargo mutants -d $D -p blacksilk-zk -f zk/src/lib.rs "${AZ[@]}" --test-package blacksilk-px \
    "${COMMON[@]}" --timeout 300 -o $S/$side-analysisA -C=--test=proof_limits > $S/$side-analysisA.log 2>&1
  stamp "$side-prove-start"
  cargo mutants -d $D -p blacksilk-px -f px/src/prove.rs "${PW[@]}" --test-package blacksilk-px,blacksilk-tx \
    "${COMMON[@]}" --timeout 450 -o $S/$side-proveW -C=--test=proof_limits "${TX[@]}" "${EXTRA[@]}" > $S/$side-proveW.log 2>&1
  stamp "$side-validate-start"
  cargo mutants -d $D -p blacksilk-tx -f tx/src/validate.rs "${VW[@]}" \
    "${COMMON[@]}" --timeout 450 -o $S/$side-validateW "${TX[@]}" "${EXTRA[@]}" > $S/$side-validateW.log 2>&1
  stamp "$side-end"
done
