# Labnet: the first real RandomX seed switch (height 2113), light-mode miners

Internal engineering evidence, not an audit.

## Setup
- **Binaries:** built from commit `83fceee` (before P2P round 3 and the v3 merge).
- **Network:** 4 regtest nodes plus a late joiner. Blocks every 10 seconds, with the same 2048/64 seed schedule as the testnet.
- **Mining:** real RandomX, 2 light-mode miners with 1 thread each.
- **Conditions:** proxy latency and jitter, a partition every 25 minutes for 4 minutes, and a v1 transaction every 20 seconds.
- **Duration:** 450 minutes (27,496 s).

## Results (summary.json)
- **Heights:** final height 2781. The seed switch at 2113 was crossed and all nodes agreed afterwards: the switch at the network's real parameters was exercised with light-mode miners.
- **Reorganisations:** 637, max depth 24, caused by partitions and competing miners.
- **Stability:** no misbehaviour disconnects and no crashes.
- **End state:** converged at the end, mempools drained, the late joiner synced.
- **Wallets and supply:**
  - fresh-wallet balances match;
  - supply conserved: generated 5,562,176,851,248 equals the wallet total;
  - PX was not exercised (0 PX transactions).
- **`checks_passed: false`:** one stuck incident. node1 stayed one block behind (2566 vs 2567) for more than 90 s while connected, at unix time 1790507911. The info-level logs cannot explain it. This is an OPEN liveness item, to be re-checked in the phase-2 evidence runs with debug logging and labnet instrumentation.

## Not demonstrated
- **A full-mode miner across the switch.** This is the explicit remaining requirement.
- **Current code:** these binaries predate the phase-2 changes.
