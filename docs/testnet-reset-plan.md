# Testnet reset plan (approved; NOT yet executed on the testnet machines)

Status (2026-09-27): the v2 identity is approved and fixed in code (§3), for the
confirmed consensus parameters (BS-ZK-2 with terminal blinding and minimum height
2^8). The seven-device trial is **not** authorized until the owner approves the
readiness report after the hardening round
(docs/reviews/completion-readiness-2026-09-26.md §6). Gates:
docs/testnet-launch-checklist.md. The reset itself runs on the operators' machines;
until they report it, **no reset has been performed**. The testnet is a functional
trial, not evidence of production readiness (docs/reviews/external-review-scope.md
§5).

## 0. Gates before execution (owner decision, 2026-09-25)

The plan is approved in principle. It is executed only after **all** of these, and an
explicit approval:

| Gate | State |
|---|---|
| Internal multi-pass review of the critical components (docs/reviews/review-status.md §3). **External review: none engaged; not a gate** (owner decision 2026-09-25) | **In progress** |
| CI validated: the workflow run on GitHub, all jobs green | **Passed** for commit `d6534c3` (run 36177083290, 2026-09-25): lint, audit, fuzz-smoke and test all green; later commits passed through `87278ac` (runs #69–#74). `7826289` is unpushed; its new jobs `guests` and `randomx-full` have never run on GitHub. To be confirmed again on the release commit |
| Extended contract-engine fuzzing | **Done:** 6 hours on `wasm_module` and 4 hours on `contract_sequence`, 0 crashes (AUDIT.md) |
| Local reset rehearsal | **Done for v2** on 2026-09-26 (§7a): passed, isolation confirmed. The 2026-09-25 rehearsal (§7) predates the blinding |
| Internal review of the ZK changes | Rounds 2–4 done (internal-review-log.md) |

The seven-machine trial follows only after the owner approves the final readiness
report.

## 1. Why a reset

The testnet v1 (genesis 2026-09-23, network id `0x0001_D670`) runs the v1 rules.
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
| 9 | Terminal blinding: 9 blinding columns in every table, the `bvm/blind` bus and the `Blind` table (changes every proof's tables and shapes) | docs/reviews/terminal-blinding.md | ZK-F29 |
| 10 | Minimum table height 2^8 (`MIN_LOG_HEIGHT`), enforced by the verifier | zk.md §9.3; zk-coverage.md | ZK-F30 |

**Not consensus, but in the new builds:**
- the `/px/contracts` RPC (ZK-F27);
- verifier-panic logging;
- the wallet's contract commands;
- the reference vault program (`px/vault.id`), which is registered by a deploy, not
  built into consensus.

## 3. The identity change (applied in the code, 2026-09-26)

| Item | v1 | v2 |
|---|---|---|
| `ChainParams::testnet()` network id (`consensus/src/params.rs`) | `0x0001_D670` | **`0x0001_D672`**. `0x0001_D671` was used by the 2026-09-25 rehearsal and is never reused |
| `TESTNET_GENESIS_TIME` | 2026-09-23 00:00 UTC | **2026-09-26 00:00 UTC** (`1790380800`) |
| `TESTNET_GENESIS_ID` (pinned by a test in `consensus/src/params.rs`) | `bbeb1a9f…` | **`6556f92dee4df050cfb113a2b4ba234794274854b69f7c8a39755ec7a66b037d`** |
| docs/testnet.md §1, docs/consensus.md | v1 | updated |
| Seed-node list | empty | **still empty** (`builtin_seeds()` in `node/src/config.rs`). There are no seed nodes; operators connect with explicit `--peer` lists |

With a new network id, old nodes fail the handshake with new ones
(`transport::tests::different_networks_cannot_talk`), so the two chains cannot mix.

## 4. Procedure

1. **Freeze:** stop all old testnet nodes and miners.
2. **Build:** check out the approved commit and build node, miner and wallet in
   release mode (docs/testnet.md §2). Record the commit id on every machine.
3. **Data:** move each node's old data directory aside, keeping it for the rollback.
   Start with empty data.
4. **The first node first** (device A), then the other machines with `--peer`
   pointing to A (and to each other if wanted). There are no seed nodes: the built-in
   list is empty (docs/testnet.md §6, §7, §12).
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
| 11 | Resources | Proof verification time per PX transaction; memory recorded against chain height (it grows with the chain, PX-F1; testnet-v2-validation.md V15); no hang (liveness, ZK-F11, F21, F28) |
| 12 | Logs | No verifier-panic warnings; no unexpected errors |

Results go into a trial report with evidence (logs, metrics, `summary.json` where
labnet is used), remaining risks and limitations.

## 6. Rollback

- If the new network fails a critical check, stop it.
- Restore the old data directories and the old build if the old testnet is still
  needed.
- Record the failure, fix it, and repeat the reset with a new network id. Never reuse
  an id for a different genesis.

## 7a. Local rehearsal of the v2 identity (done 2026-09-26)

**Result:** passed; evidence in `docs/evidence/labnet-2026-09-26/`.
- **The v2 network:** a 30-minute, 5-node run under the testnet rules passed every
  labnet check.
- **Isolation:** a v1 node (`b4262e1`) was refused at all 14 handshake attempts.
- **Private traffic:** a 62-minute regtest run with the same build passed: 6 PX
  transactions, 115 reorganizations, and restored wallets matching (private balances
  included).
- **Next:** the seven-device validation (docs/testnet-v2-validation.md), run by the
  operators.

## 7. Local rehearsal before the trial (done 2026-09-25)

**Result:** passed; evidence in `docs/evidence/labnet-2026-09-25/reset-rehearsal/`.
- **New identity:** the scratch copy's new testnet identity pinned a new genesis id
  (`192fad73…bf6`).
- **The new network:** a 30-minute, 5-node run on it passed every labnet check.
- **Isolation:** a node of the current identity was refused at every handshake
  attempt.
- **Private traffic** was rehearsed separately on regtest
  (`docs/evidence/labnet-2026-09-25/px-regtest/`: 5 PX transactions under partitions;
  restored wallets match, private balances included).

The procedure itself:

- Before the seven machines, the procedure is rehearsed on one machine: a scratch copy
  with a new testnet id and genesis time, and a multi-process run with the labnet tool
  (`--network testnet`).
- A node of the old identity must be refused.
- The rehearsal result is recorded in AUDIT.md.
- It is local, multi-process testing; it does not replace the multi-machine trial.
