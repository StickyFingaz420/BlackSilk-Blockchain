# Evidence: testnet v2 reset rehearsal (2026-09-26)

**One machine** (Windows 10, 8 logical CPUs), separate node and miner processes, every
link through a proxy adding latency and jitter (docs/testnet.md §8).
- **This is local multi-process testing, not the seven-device validation**
  (docs/testnet-v2-validation.md).
- **Build:** the Option A working tree on top of `b4262e1`, committed afterwards
  (BS-ZK-2, terminal blinding, minimum height 2^8, the v2 identity).
- The P-5 campaign ran at the same time; that affects time, not results.

## `reset-rehearsal-v2/`: the v2 identity under the testnet rules

The identity is in the code: network id `0x0001_D672` (`"network_id":120434` in `/info`),
genesis time 2026-09-26 00:00 UTC, genesis `6556f92dee4df050…037d`. `reset-rehearsal-v2/metrics.csv` shows tip
`6556f92d…` at height 0.

```sh
blacksilk-labnet --bin-dir <release dir> --out rehearsal-v2 --nodes 5 --duration-mins 30 \
  --network testnet --base-port 43000
```

**Result:** `checks_passed: true`.
- 31 min, height 23 (120-second blocks), 1 partition, 4 reorganizations (maximum
  depth 2);
- converged, mempools drained; the late joiner synced (3 peers);
- wallets restored from seed match; supply conserved (460.61986259 BLK);
- 0 misbehaviour disconnects, no crashes; peak memory 267 MB per process.
- There were no transactions: testnet coinbase outputs mature after 60 blocks.

**Isolation** (`old-identity-node.log`):
- A node built from `b4262e1` (testnet v1: `0x0001_D670`, genesis `bbeb1a9f…`) was
  pointed at rehearsal node 0 for 150 s.
- All 14 handshake attempts failed (13 `Decrypt`, 1 connection reset). The v1 node
  stayed on its own genesis.

## `px-regtest/`: private traffic under partitions, same build

```sh
blacksilk-labnet --bin-dir <release dir> --out px-regtest-v2 --nodes 5 --duration-mins 60 \
  --latency-ms 80 --jitter-ms 60 --partition-every-mins 20 --partition-mins 3 \
  --tx-every-secs 20 --px-every-mins 4 --base-port 45000
```

**Result:** `checks_passed: true`.

| Item | Result |
|---|---|
| Duration | 62 min |
| Final height | 408 |
| Partitions | 2 |
| Reorganizations | 115, maximum depth 14 |
| v1 transfers | 62 attempted, 61 submitted. 1 decoy-selection failure early on: a young chain has too few ring members, as in earlier runs |
| PX transactions | 6 attempted, 6 submitted, 0 failures: 4 deposits, 1 private send, 1 withdrawal |
| Convergence | all nodes on one tip; mempools drained |
| Late joiner | synced, 3 peers |
| Wallets restored from seed | v1 **and** private balances identical for all 5 wallets |
| Supply | generated = Σ wallets (v1 + private) = 8,169.49596152 BLK |
| Misbehaviour disconnects between honest nodes | 0 |
| Peak memory | 270–296 MB per process |

- **Harness retries:** the journal's "node is still synchronizing (N of N+1 blocks)"
  lines are wallet syncs refused while a node was one block behind its best header.
  The harness retried them.
- The same pattern appears in the 2026-09-25 runs.

**Not covered here** (docs/testnet-v2-validation.md): real networks between devices;
PX under testnet timing; contracts under the new build (covered by `wallet/tests/e2e.rs`);
72-hour stability; operator procedures.
