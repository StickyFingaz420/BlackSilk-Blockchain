#!/bin/bash
# usage: measure.sh <exe> <tag> <load_procs> <headers>
EXE=$1; TAG=$2; L=$3; N=$4; S=C:/bszkeval/w4-powpool-scratch
cd C:/bszkeval/wt-w4-powpool/chain
pids=()
for i in $(seq 1 $L); do ( while :; do :; done ) & pids+=($!); done
echo "$TAG load=$L pids: ${pids[*]}"
sleep 2
for r in 1 2 3; do
  $EXE --ignored --nocapture --test-threads=1 bench_cheap_chunks 2>&1 | grep -E "cheap" | sed "s/^/$TAG run$r /"
done
POWPOOL_HEADERS=$N $EXE --ignored --nocapture --test-threads=1 bench_randomx_batch 2>&1 | grep -E "ms" | sed "s/^/$TAG /"
for p in "${pids[@]}"; do kill $p; done
echo "$TAG done"
