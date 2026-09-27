W2-36b evidence (RPC wiring), 2026-09-27. Base commit 2985a50.
Environment: CARGO_TARGET_DIR=C:/bszkeval/t-w2-rpc-wire CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0, Windows 10.

base-demo-node_binary.log
  node/tests/node_binary.rs run against the base source (only the test file added):
  cargo test --locked --release -p blacksilk-node --test node_binary
  The binary answered 200 to GET /info without a credential, wrote no cookie,
  and rejected --rpc-allow-host.

mutant-stem-leak-tx_status.log
  node/src/lib.rs temporarily changed so /tx/status answers "pooled" for a
  transaction in the P2P stempool; tx_status.rs fails with "stem state reported".
  The change was reverted before the commit.

after-suite.log
  cargo test --locked --release -p blacksilk-node -p blacksilk-rpc -p blacksilk-miner
    -p blacksilk-labnet -- --skip consensus_fingerprints_are_pinned

labnet-*.{json,log}
  blacksilk-labnet --bin-dir <target>/release --out <target>/labnet-run1 --nodes 4
    --duration-mins 4 --latency-ms 20 --jitter-ms 10 --partition-every-mins 60
    --partition-mins 1 --tx-every-secs 20 --base-port 47100 --miner-threads 1
  Miners got --rpc-cookie <node data dir>/rpc.cookie; the harness clients read the
  same file. Exit 0, checks_passed true, final height 141. Only one transaction was
  attempted in the short run (refused while the node was synchronizing), so /tx over
  the cookie is covered by node/tests/tx_status.rs, not by this run.
