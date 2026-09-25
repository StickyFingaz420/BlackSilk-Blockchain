# Testnet reset plan (for the owner's approval; NOT executed)

Status: **plan (2026-09-25). No reset has been performed.** The owner approves the
reset and the seven-machine trial separately (AUDIT.md R8). The testnet is a
functional trial, not evidence of production readiness
(docs/reviews/external-review-scope.md §5).

## 1. Why a reset

The current testnet (genesis 2026-09-23, network id `0x0001_D670`) runs the v1 rules.
The builds under review add consensus rules that apply **from genesis**, with no
activation height. Old and new nodes would fork at the first block containing a PX
transaction or deploy, and every other difference below. A clean chain avoids a mixed
network.

## 2. Consensus-breaking changes that the new genesis includes

Every item is intentional, active from height 0, and specified in the linked section.

| # | Change | Specification | Finding |
|---|---|---|---|
| 1 | Transaction kind 2 (PX transaction) and kind 3 (private-contract deploy) | px.md §11.1, §11.2 | ZK-6 |
| 2 | Rules PX1–PX5: anchor window of 100, nullifiers, registry, pool ≥ 0, proof | px.md §11.3 | ZK-6 |
| 3 | The PX fee is **exactly** `PX_STANDARD_FEE` = 8,912,896 atomic units | px.md §11.5 | ZK-F23 |
| 4 | Record ciphertext of **1,241 bytes** (plaintext with the contract field) | px.md §6 | ZK-F22 |
| 5 | Block limits: an 8 MiB PX budget; `MAX_BLOCK_BYTES` = 9,454,144; P2P `MAX_FRAME` = `MAX_BLOCK_BYTES` + 64 KiB | px.md §11.5; p2p.md | ZK-6 |
| 6 | The proof system: BS-ZK-2 (108 queries, degree-8 extension), proof version 1, statement digest, fixed shapes and budgets | zk.md §9; zkvm.md §6 | ZK-F4, F13, F14 |
| 7 | The pinned kernel program id (`px/kernel.id`) | px.md §4.3 | — |
| 8 | Poseidon2 `Hk` (a known-answer pin) and all PX domains | px.md §2 | — |

**Not consensus, but in the new builds:**
- the `/px/contracts` RPC (ZK-F27);
- verifier-panic logging;
- the wallet's contract commands;
- the reference vault program (`px/vault.id`), which is registered by a deploy, not
  built into consensus.

## 3. The identity change (proposed, not applied)

| Item | Now | Proposed |
|---|---|---|
| `ChainParams::testnet()` network id (`consensus/src/params.rs`) | `0x0001_D670` | `0x0001_D671` (any new value; it separates the networks at the P2P handshake and in every block id) |
| `TESTNET_GENESIS_TIME` | 2026-09-23 00:00 UTC | the chosen launch time |
| `TESTNET_GENESIS_ID` (the pinned test in `consensus/src/params.rs`) | `bbeb1a9f…` | recomputed from the two values above; the test pins it |
| docs/testnet.md §1 | the old id and time | updated |
| Seed-node list | as deployed | the same hosts, restarted on the new build |

With a new network id, old nodes fail the handshake with new ones
(`transport::tests::different_networks_cannot_talk`), so the two chains cannot mix.

## 4. Procedure

1. **Freeze:** stop all old testnet nodes and miners.
2. **Build:** check out the approved commit and build node, miner and wallet in
   release mode (docs/testnet.md §2). Record the commit id on every machine.
3. **Data:** move each node's old data directory aside, keeping it for the rollback.
   Start with empty data.
4. **Seed nodes first,** then the other machines (docs/testnet.md §6, §7).
5. **Wallets:**
   - create **new** wallet files;
   - an existing seed may be restored on the new network (`restore --restore-height 1`),
     but old testnet coins do not exist there;
   - do not point an old wallet file at the new network: it would try to reconcile a
     chain that no longer exists.
6. **Mining:** start the miners, and let the chain pass coinbase maturity (60 blocks)
   before transaction tests.

## 5. Verification checklist (seven machines)

| # | Check | Pass criterion |
|---|---|---|
| 1 | Genesis | Every node reports the same genesis id: the new pinned value |
| 2 | Isolation | An old-build node cannot connect (handshake refused) |
| 3 | Sync | A node joining late syncs headers first to the tip |
| 4 | v1 transfers | Wallets on different machines send and receive |
| 5 | PX flows | Deposit, private send, withdraw; balances match on every wallet |
| 6 | Contracts | Deploy the vault; lock for another machine's wallet; that wallet receives the record, claims (fee from v1 and from PX), and every holder sees the spend |
| 7 | Fee rule | A PX transaction with a non-standard fee is refused and the relaying peer is penalized |
| 8 | Reorganizations | During a partition the chain forks and converges; PX state and wallets follow (`px-records`, balances) |
| 9 | Restart | A node restarted from its data directory reaches the same PX root, pool and registration list |
| 10 | Relay limits | No honest peer is penalized; no misbehaviour disconnects between honest nodes |
| 11 | Resources | Proof verification time per PX transaction; memory; no hang (liveness, ZK-F11, F21, F28) |
| 12 | Logs | No verifier-panic warnings; no unexpected errors |

Results go into a trial report with evidence (logs, metrics, `summary.json` where
labnet is used), remaining risks and limitations.

## 6. Rollback

- If the new network fails a critical check, stop it.
- Restore the old data directories and the old build if the old testnet is still
  needed.
- Record the failure, fix it, and repeat the reset with a new network id. Never reuse
  an id for a different genesis.

## 7. Local rehearsal before the trial

- Before the seven machines, the procedure is rehearsed on one machine: a scratch copy
  with a new testnet id and genesis time, and a multi-process run with the labnet tool
  (`--network testnet`).
- A node of the old identity must be refused.
- The rehearsal result is recorded in AUDIT.md.
- It is local, multi-process testing; it does not replace the multi-machine trial.
