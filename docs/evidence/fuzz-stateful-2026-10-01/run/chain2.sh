#!/usr/bin/env bash
# W4-STATEFUL fix pass: build from the clean commit, add the new seeds, then
# each changed target alone (peer_protocol and scan_outputs 600 s,
# px_admission 1,500 s: its corpus load alone can take 10 minutes).
set -uo pipefail
source C:/bszkeval/w4-stateful-scratch/env.sh
cd "$FZ"
echo "commit $(git rev-parse --short HEAD) dirty=$(git status --porcelain | wc -l)" > "$SC/logs/fix-build.log"
cargo +"$TC" fuzz build -O -a --fuzz-dir . >> "$SC/logs/fix-build.log" 2>&1 || { echo "build failed"; exit 1; }
cargo +"$TC" build --locked --release --bin seeds >> "$SC/logs/fix-build.log" 2>&1 || { echo "seeds build failed"; exit 1; }
(cd "$SC" && "$CARGO_TARGET_DIR/release/seeds.exe" peer_protocol scan_outputs px_admission > "$SC/logs/fix-seeds.log" 2>&1)
bash "$SC/run1.sh" peer_protocol 600 fix
bash "$SC/run1.sh" scan_outputs 600 fix
bash "$SC/run1.sh" px_admission 1500 fix
echo CHAIN2DONE
