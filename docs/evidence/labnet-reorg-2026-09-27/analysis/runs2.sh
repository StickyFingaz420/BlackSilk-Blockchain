#!/bin/bash
# INV-REORG: confirmation runs on rebuild/core 180d1ca + inv-reorg commits.
cd C:/bszkeval/inv-reorg
B=C:/bszkeval/t-inv-reorg/release
RUST_LOG="info,blacksilk_p2p=debug,blacksilk_chain=debug,blacksilk_miner=debug" "$B/blacksilk-labnet.exe" --bin-dir "$B" --out C:/bszkeval/inv-reorg/c180-dbg1 --nodes 4 --duration-mins 4 --latency-ms 20 --jitter-ms 10 --partition-every-mins 60 --partition-mins 1 --tx-every-secs 20 --base-port 47300 --miner-threads 1 > C:/bszkeval/inv-reorg/c180-dbg1.out 2>&1
echo "c180-dbg1 exit $?"
RUST_LOG=info "$B/blacksilk-labnet.exe" --bin-dir "$B" --out C:/bszkeval/inv-reorg/c180-2 --nodes 4 --duration-mins 4 --latency-ms 20 --jitter-ms 10 --partition-every-mins 60 --partition-mins 1 --tx-every-secs 20 --base-port 47300 --miner-threads 1 > C:/bszkeval/inv-reorg/c180-2.out 2>&1
echo "c180-2 exit $?"
