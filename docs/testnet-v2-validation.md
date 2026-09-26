# Testnet v2: seven-device validation checklist

**For:** the owner and the operators of the seven testnet devices.

**Status:** the reset was approved by the owner on 2026-09-26 (docs/testnet-reset-plan.md).
- The identity is fixed in the code and was rehearsed locally (§0).
- **The validation below has not been run.** Only the operators can run it, on their
  own devices.
- Nothing here is evidence until an operator reports it, together with the evidence
  listed in §4.
- The testnet is a functional trial. It is not evidence of production readiness, and
  no external audit has taken place.

## 0. What was done before handing over (one machine only)

- **Local rehearsal** (docs/evidence/labnet-2026-09-26/):
  - 5 node processes and 2 miners on one machine, with the v2 identity;
  - a v1 node was refused at every handshake;
  - private traffic was run on regtest with the same build.
- **The rehearsal does not replace this checklist.**
  - It had no real network between machines.
  - It ran no PX transactions under testnet timing: coinbase outputs need 60 blocks,
    about 2 hours.

## 1. Identity every device must show

| Item | Value |
|---|---|
| Commit | the release commit announced by the owner. Every device records `git rev-parse HEAD` |
| Network | `testnet`, network id `0x0001D672` (`"network_id":120434` in `/info`) |
| Genesis | the node's first log line: `testnet: loading … (genesis 6556f92dee4df050)`. Full id `6556f92dee4df050cfb113a2b4ba234794274854b69f7c8a39755ec7a66b037d` |
| Genesis time | 2026-09-26 00:00:00 UTC |

## 2. Procedure

Follow docs/testnet-reset-plan.md §4. In short:
1. stop the old node and miner;
2. build the release commit (docs/testnet.md §2);
3. move the old data directory aside (keep it for rollback);
4. start the seed or first node, then the others;
5. create **new** wallet files;
6. start the miners.

The labels A–G below name the seven devices. Choose at least two different networks,
for example home and cloud.

## 3. Checks

Run `deploy/scripts/check-node.sh <rpc>` for heights, tips and peers. Every check
records **who ran it, when, on which devices, and the result**.

| # | Area | What to do | Pass criterion |
|---|---|---|---|
| V1 | Identity | Start all seven nodes | All seven show the §1 genesis and network id |
| V2 | Isolation | Point one v1 node (old build and data) at a v2 node, started with `--log debug` | Handshakes refused (`handshake failed` lines, logged at debug level); the v1 node keeps `peers: 0` and its height does not change |
| V3 | Peer discovery | Give B–G only A as `--peer` | Within 5 min every node has `peers ≥ 2` |
| V4 | Mining | Run miners on at least 3 devices (A, C, F) | All `tip` values equal within one block; each miner's wallet receives rewards for its own blocks; difficulty adjusts (the `difficulty` field changes as hash rate changes) |
| V5 | Block validation | Watch all node logs during V4–V9 | No valid block rejected; no `misbehaving_disconnects` between honest nodes (`/info`); every node accepts the same tip |
| V6 | Sync | After ≥ 100 blocks start a new node H with an empty data directory and one peer | H reaches the tip (`header_height` = `height` = others' height) and has the same tip hash |
| V7 | Transaction relay (v1) | After 60 blocks, send a transfer from A's wallet to C's address through B's RPC (`--node <B>`) | C's wallet shows it after the next block; the transaction reaches every mempool (`mempool_txs`) before inclusion. Optional, with `--log debug` on B: B forwards it on the stem rather than announcing it at once |
| V8 | Transaction relay (PX) | `px-deposit`, then `px-send` to another device's PX address, then `px-withdraw` | Each confirms; balances match on the sender and the receiver; `/info` `mempool_txs` drains |
| V9 | Contracts (optional) | Deploy the vault, lock for another device, claim (reset-plan §5, item 6) | The claimer receives the record and the funds; every holder sees the spend |
| V10 | Fee rule | Submit a PX transaction with a non-standard fee (a developer build only) | The RPC refuses it. Relayed over P2P it is dropped and scores 20 misbehaviour points (threshold 100): the fifth such relay ends in `disconnecting peer … for misbehavior` (info level) on the receiving node |
| V11 | Reorganization | Block traffic between {A, B, C} and {D, E, F, G} for 20 min with miners on both sides, then heal | Within 5 min all tips are equal; the minority logs `reorganization: disconnecting …`; orphaned transactions return to the mempool and confirm; wallet balances follow (`balance`, `px-balance`, `px-records`) |
| V12 | Restart and recovery | Stop one node uncleanly (kill), restart it on the same data directory | It resumes, reaches the tip, and reports the same `tip` and `generated` (`/info`) and the same `root` and `total` (`/px/commitments`) as the others |
| V13 | Wallet recovery | Restore each wallet from its 24 words against H (`restore --network testnet`) | v1 and private balances equal the original wallet's |
| V14 | Supply | At the end, sum all wallet balances (v1 and PX) | Equal to `generated` in `/info`, with every miner's wallet included. Fees return to miners, so nothing is left over. Only if every wallet on the network takes part |
| V15 | Stability | Keep everything running ≥ 72 h | No crash; memory flat; all nodes on one tip; no verifier-panic warnings |
| V16 | Resources | Record proof verification (node log) and each node's memory while PX transactions arrive | No hang; verification of a PX transaction takes well under a second; memory stays flat (no growth across hours) |

**If a check fails:**
- stop and record the failure;
- follow docs/testnet-incident-response.md;
- the rollback procedure is docs/testnet-reset-plan.md §6;
- never reuse network id `0x0001D672` for a different genesis.

## 4. Evidence to send back

Every result is recorded in AUDIT.md only from this evidence, and only as reported.
- the commit id per device;
- `check-node.sh` output at start, after V4, after V11 and at the end;
- node and miner logs;
- the wallet outputs for V7, V8 and V13;
- the times of the partition and the heal.
