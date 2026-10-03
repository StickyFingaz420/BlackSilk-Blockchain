#!/usr/bin/env bash
# W4-MUTAIR run B: trace.rs and check.rs. B1: everything but the circuit
# fingerprint, with the AIR oracle. B2: check.rs's fingerprint code, whose
# own oracle is the fingerprint pins (circuit_fingerprint.rs) plus the AIR oracle.
set -u
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
unset CARGO_TARGET_DIR
cd "$(dirname "$0")"
mkdir -p "$1"
cfg=-C=--config=profile.mutants.package.blacksilk-zkvm.opt-level=1
fp='fingerprint|FingerprintBuilder|update_values'
cargo mutants -d src -p blacksilk-zkvm -f zkvm/src/air/trace.rs -f zkvm/src/air/check.rs \
  --exclude-re "$fp" --profile mutants --jobs 2 --timeout 600 --build-timeout 2400 \
  --cap-lints true -o "$1/B1" $cfg -C=--test=air_oracle -- -- --test-threads=2
mkdir -p "$1"; cargo mutants -d src -p blacksilk-zkvm -f zkvm/src/air/check.rs --re "$fp" \
  --profile mutants --jobs 2 --timeout 600 --build-timeout 2400 --cap-lints true \
  -o "$1/B2" $cfg -C=--test=air_oracle -C=--test=circuit_fingerprint -- -- --test-threads=2
