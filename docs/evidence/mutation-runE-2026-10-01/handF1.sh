#!/usr/bin/env bash
set -u
S=/c/bszkeval/w4-mute-scratch
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
cd /c/bszkeval/wt-w4-mute
python $S/hand.py $S/ev/handF1.tsv $S/handF1-copy C:/bszkeval/t-w4-mute-handF1 $S/handF1.txt 1800 -- test --locked --profile mutants -p blacksilk-tx --lib --test adversarial --test block_pipeline --test chain_integration --test deploy_rules --test encoding_rules --test exact_fee --test fuzz_scan --test malleability --test max_weight_encoder --test max_weight_vectors --test mutation_regressions --test output_key_uniqueness --test privacy --test px_proof_wiring --test px_v1_weight --test px_window --test revalidate_after_extension --test state_accessors --test transfers --test tree_capacity --test upgrade --test validation_order  > $S/handF1.log 2>&1
echo "exit $? $(date -u +%H:%M)" > $S/handF1.time
