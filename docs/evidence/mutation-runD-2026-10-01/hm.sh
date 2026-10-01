#!/usr/bin/env bash
# Hand mutants of `ChainSummary::tip_on_best_chain` (cargo-mutants does not
# mutate struct field values): HM1 = true, HM2 = false. Oracle: the chain
# summary test and the p2p sync tests of run D.
set -u
S=C:/bszkeval/w4-mutd-scratch
export CARGO_TARGET_DIR=C:/bszkeval/t-w4-mutd-hm CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
mapfile -t ST < $S/sync.tests
cd $S/hm
F=chain/src/manager/summary.rs
cp $F $S/summary.rs.orig
for hm in true false; do
  cp $S/summary.rs.orig $F
  sed -i "s|tip_on_best_chain: m.headers().is_on_main(&tip_id),|tip_on_best_chain: $hm,|" $F
  grep -n "tip_on_best_chain: $hm," $F
  echo "=== HM tip_on_best_chain = $hm" 
  cargo test --locked --profile mutants -p blacksilk-chain --test manager -- --exact the_summary_flags_a_tip_off_the_best_header_chain_and_calls_tip_listeners 2>&1 | grep -E "^test |test result|panicked at" -A2
  cargo test --locked --profile mutants -p blacksilk-p2p --test network --test liveness --test withheld_body -- --exact --test-threads=4 "${ST[@]}" 2>&1 | grep -E "^test .*FAILED|test result|panicked at" -A2
done
cp $S/summary.rs.orig $F
