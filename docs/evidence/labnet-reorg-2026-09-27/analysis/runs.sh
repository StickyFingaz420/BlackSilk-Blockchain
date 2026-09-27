#!/bin/bash
# INV-REORG: identical-flag labnet runs, current (t-inv-reorg) vs pre-v3 base (t-inv-reorg-base).
cd C:/bszkeval/inv-reorg
run() { # name target port
  RUST_LOG=info "C:/bszkeval/$2/release/blacksilk-labnet.exe" --bin-dir "C:/bszkeval/$2/release" --out "C:/bszkeval/inv-reorg/$1" --nodes 4 --duration-mins 4 --latency-ms 20 --jitter-ms 10 --partition-every-mins 60 --partition-mins 1 --tx-every-secs 20 --base-port "$3" --miner-threads 1 > "C:/bszkeval/inv-reorg/$1.out" 2>&1
  echo "$1 exit $?"
}
run cur-2 t-inv-reorg 47300
run base-2 t-inv-reorg-base 47500
run cur-3 t-inv-reorg 47300
run base-3 t-inv-reorg-base 47500
