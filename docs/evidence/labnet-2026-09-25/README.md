# Evidence: multi-process network runs (2026-09-25)

**One machine** (Windows 10, 8 logical CPUs), separate node and miner processes, every
link through a proxy adding latency and jitter (docs/testnet.md §8). **This is local
multi-process testing, not the seven-machine trial.**

## `px-regtest/`: private (PX) traffic under partitions

```sh
blacksilk-labnet --bin-dir <release dir> --out labnet-px --nodes 5 --duration-mins 60 \
  --latency-ms 80 --jitter-ms 60 --partition-every-mins 20 --partition-mins 3 \
  --tx-every-secs 20 --px-every-mins 4
```

**Result:** `checks_passed: true`.

| Item | Result |
|---|---|
| Duration | 62 min |
| Final height | 391 |
| Partitions | 2 |
| Reorganizations | 70, maximum depth 17 |
| v1 transfers | 83 attempted, 80 submitted. 3 `NotEnoughOutputs` decoy failures in the first 6 minutes: a young chain has fewer than 16 eligible ring members; also seen in the 2026-09-23 runs |
| PX transactions | 5 attempted, 5 submitted, 0 failures: 3 deposits and 2 private sends. No withdrawal was drawn at random; withdrawals are covered by `wallet/tests/e2e.rs` |
| Convergence | all nodes on one tip; mempools drained |
| Late joiner | synced, 3 peers |
| Wallets restored from seed | v1 **and** private balances identical for all 5 wallets |
| Supply | generated = Σ wallets (v1 + private) = 7,829.16375721 BLK |
| Misbehaviour disconnects between honest nodes | 0 |
| Peak memory | 270–297 MB per process |

## `reset-rehearsal/`: a testnet reset on one machine

A scratch copy of the workspace with the proposed identity change
(docs/testnet-reset-plan.md §3):
- network id `0x0001_D671`;
- genesis time 2026-09-25 00:00 UTC;
- the new pinned genesis id `192fad73cdf88e26274217df7906e200fbd0c81ae1708f56fb622b0328be2bf6`
  (the pin test passes).

```sh
blacksilk-labnet ... --nodes 5 --duration-mins 30 --network testnet
```

**Result:** `checks_passed: true`.
- 30 min, height 25 (120-second blocks), 2 partitions, 3 reorganizations (depth 1);
- converged; late joiner synced; wallets restored from seed match; supply conserved;
- 0 misbehaviour disconnects.
- There were no transactions: testnet coinbase outputs mature after 60 blocks
  (2 hours).

**Isolation** (`old-identity-node.log`):
- A node of the **current** testnet build (network id `0x0001_D670`, genesis
  `bbeb1a9f…`) was pointed at a rehearsal node. Every attempt failed: `handshake
  failed: Decrypt`, 12 attempts in 2 minutes.
- The old node stayed on its own genesis with 0 peers. The two networks cannot mix.

**Not covered here** (the seven-machine trial's checklist, docs/testnet-reset-plan.md
§5): real network conditions between machines; PX and contracts under testnet timing;
operator procedures.
