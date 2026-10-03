#!/bin/bash
# Times the pow_pool_bench harness (chain/tests/pow_pool_bench.rs) idle or
# under busy-loop processes, which it starts and stops by PID.
# usage: measure.sh <bench exe> <tag> <load procs> <headers> [repo chain dir]
# The bench exe is `cargo test --release -p blacksilk-chain --test
# pow_pool_bench --no-run`'s test binary; the chain dir defaults to
# ../../../chain relative to this script.
EXE=$1; TAG=$2; L=$3; N=$4
CHAIN=${5:-"$(cd "$(dirname "$0")/../../../chain" && pwd)"}
cd "$CHAIN" || exit 2
pids=()
for i in $(seq 1 "$L"); do ( while :; do :; done ) & pids+=($!); done
echo "$TAG load=$L pids: ${pids[*]}"
sleep 2
for r in 1 2 3; do
  "$EXE" --ignored --nocapture --test-threads=1 bench_cheap_chunks 2>&1 | grep -E "cheap" | sed "s/^/$TAG run$r /"
done
POWPOOL_HEADERS=$N "$EXE" --ignored --nocapture --test-threads=1 bench_randomx_batch 2>&1 | grep -E "ms" | sed "s/^/$TAG /"
for p in "${pids[@]}"; do kill "$p"; done
echo "$TAG done"
