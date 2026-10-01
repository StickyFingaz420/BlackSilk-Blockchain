#!/usr/bin/env bash
# W4-STATEFUL final campaign: build from the clean commit, then each
# stateful target for 600 s, one after the other.
set -uo pipefail
source C:/bszkeval/w4-stateful-scratch/env.sh
cd "$FZ"
echo "commit $(git rev-parse --short HEAD) dirty=$(git status --porcelain | wc -l)" > "$SC/logs/final-build.log"
cargo +"$TC" fuzz build -O -a --fuzz-dir . >> "$SC/logs/final-build.log" 2>&1 || { echo "build failed"; exit 1; }
for t in peer_protocol scan_outputs px_admission; do
  bash "$SC/run1.sh" "$t" 600 final
done
