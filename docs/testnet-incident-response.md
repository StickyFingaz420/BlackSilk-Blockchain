# Testnet rollback and incident-response plan

Status: **proposed operating procedure, 2026-09-25; awaiting the owner's approval of
the procedure and the communication setup (§1a).**
- It covers the **experimental testnet**, where coins have no value. The priority
  there is evidence, correctness and user privacy, not uptime.
- Not rehearsed yet (docs/testnet-launch-checklist.md G14).
- It is designed for the project's current resources: **one owner and decision-maker,
  no external incident lead, no external auditors.**

## 1. Roles

| Role | Who | Responsibility |
|---|---|---|
| **Owner (incident lead)** | The project owner | Declares incidents and their severity; decides pauses, emergency releases, resets and every public statement; approves disclosure; keeps the incident record |
| **Development support** | The owner with the AI engineering assistant, working in the repository | Diagnosis, reproduction, fixes, tests, the patched release, AUDIT.md entries. **The assistant acts only through the repository and the owner:** it cannot reach operators, watch machines, or act while the owner is away |
| **Operators** | Whoever runs each testnet machine (initially the owner's own machines) | Watch the signals (§3), preserve evidence (§5), follow the owner's instructions |

### 1a. Communication setup (proposed; the owner chooses)

| Purpose | Proposal | Why | To be decided |
|---|---|---|---|
| **Private vulnerability reports** | GitHub private vulnerability reporting on the repository (SECURITY.md already points there) | Encrypted in transit, tied to the repository, no personal address published | The owner enables it: Settings → Code security → Private vulnerability reporting (a repository security setting) |
| **Operators' private channel** | An end-to-end encrypted group: for example a Signal group, or an encrypted Matrix room with verified devices | Incident details must not leak before a fix | Which tool; the member list; the owner verifies each member's identity/safety number |
| **Public announcements** | The repository (a pinned GitHub issue or discussion, and README) | Visible, permanent, no extra account needed | Whether to add a chat or mailing list |
| **Backup contact** | A second route to reach operators if the main channel fails (for example email) | Single-channel failure | Which one |

## 1b. Limitations of this procedure (stated plainly)

- **A single point of failure.** Everything depends on the owner being reachable.
  There is no 24-hour coverage, no deputy and no second person who can authorize a
  pause. Mitigation: operators may pause their own machines on their own judgement for
  S1 signals (§4.1); anyone may stop their own miner or node at any time.
- **No outside expertise on call.** A cryptographic or ZK soundness incident may exceed
  what the project can diagnose quickly. The response then is to pause, preserve
  evidence and say so publicly, not to guess.
- **No protocol-level pause.** Stopping the network needs the operators' cooperation.
- **Detection depends on people watching.** There is no automated alerting yet.
- **Not rehearsed** (§8).

## 2. Severity

| Level | Meaning | Examples | Response |
|---|---|---|---|
| **S1: critical** | Consensus, soundness or privacy failure | Nodes disagree on valid blocks; supply check fails; a proof that should fail verifies; a leak of private data | Immediate. Pause (§4.1, §4.9). Private until fixed |
| **S2: high** | Network-wide availability or a wallet losing funds | Chain stalls; many nodes crash; W-class wallet bug | Within hours |
| **S3: medium** | Local or recoverable | One node crashing; a deep reorganization with a known cause | Within a day |
| **S4: low** | Cosmetic or documentation | Misleading message | Normal work |

## 3. Detection signals

| Signal | Where | Suspected cause | Level to start at |
|---|---|---|---|
| `WARN reorganization: disconnecting N block(s)` (N ≥ 10) | Node log; `/info` `deepest_reorg` | Partition, eclipse or hash-power attack (K4) | S3; S1 if no partition explains it |
| Nodes on different tips for more than 30 minutes while connected | `/info` `tip` on each machine | Consensus divergence | **S1** |
| Supply check fails: generated ≠ Σ outputs, v1 plus private | Labnet-style supply audit. **No tool for the real testnet yet:** labnet computes it from its own wallets. A standalone audit tool is a pre-launch item | Inflation bug | **S1** |
| `VerifierPanicked` warnings | Node log | A proof input crashes the verifier | S2 (S1 if reproducible from outside) |
| Panic, crash loop, memory growth | Service manager, `peak memory` | Bug or resource exhaustion | S2 or S3 |
| Misbehaviour disconnects between honest nodes | `/info` `misbehaving_disconnects` | False-ban bug (like L1) or an attack | S3 |
| Wallet reports funds wrong, or `Uncertain` repeatedly | Users | Wallet bug or node trouble | S2 |
| An external vulnerability report | SECURITY.md channel | — | Per content |

## 4. Procedures

### 4.1 Halt (S1)

- **There is no kill switch in the protocol.** Halting means operators stop their own
  processes; nobody can stop the network remotely. That is intended.

**Steps:**
1. The owner tells operators, over the private channel, to **stop miners
   first**, then nodes.
2. Operators preserve evidence (§5) before anything else is changed.
3. A public notice says that the testnet is paused for investigation, **without
   technical details** until a fix exists.

### 4.2 Consensus divergence
1. Halt (§4.1).
2. Collect the block files and logs from nodes on each side.
3. Find the first block the sides disagree on, and re-validate it with the current
   release, in a test harness, from both data directories.
4. The fix is either:
   - a bug in the rejecting side: patch and release;
   - a bug in the accepting side (invalid block accepted): patch, and **reset**,
     because the chain contains an invalid block.
5. A reset follows docs/testnet-reset-plan.md with a **new network id**; ids are never
   reused.

### 4.3 Soundness or inflation (a forged proof, a supply mismatch)
1. Halt.
2. Preserve everything.
3. Treat it as the most severe case: any PX output after the first bad block is
   suspect.
4. The only safe recovery on the testnet is a fix plus a reset.
5. Record it as a finding for the independent reviewer.
6. Publish after the fix.

### 4.4 Deep reorganization (at least 10 blocks)
1. Establish the cause from peer lists and timing: a partition (an operator's network)
   or unexplained.
2. Explained and healed: record it (S3).
3. Unexplained: check the block timestamps and the miners' addresses on the winning
   branch.
4. A hash-power attack on a testnet is expected to be possible (K1, K4). Record it;
   there is no rollback, because the policy is most-work.
5. Collect data for the mainnet finality decision (k4-reorg-policy.md §5).

### 4.5 Node crash or resource exhaustion
1. Restart with the same data directory. The node rebuilds its state from the block
   file (tested by `restart_rebuilds_the_px_state_exactly`).
2. If it crashes again, keep the data directory and run a clean copy from genesis on
   the same release.
3. File the crash with the logs.

### 4.6 Wallet incident
1. Tell users to **stop sending** and keep their wallet files: the stored transactions
   and rings are in them.
2. Do not advise `clear-pending` or restoring from the seed until the cause is known.
   Both can make later spends linkable (wallet-review.md W-5).

### 4.7 Privacy leak
1. Establish what leaks, and whether it is observable retroactively on chain.
2. Warn users privately if there is a user action that limits damage.
3. Fix it, then publish, including how to tell whether one was affected.
4. Record it in privacy-review.md.

### 4.8 A vulnerability report from outside
1. Acknowledge within 2 working days; assess the level (§2).
2. Keep it private until a fixed release is running on the testnet, then credit the
   reporter if they wish.

### 4.9 Conditions for pausing the testnet

The owner pauses (halts miners, then nodes) on any of these:
- persistent disagreement between honest nodes on the valid chain (§4.2);
- a failed supply check or any sign of inflation, including a proof that should fail
  but verifies (§4.3);
- a privacy failure that keeps leaking while the network runs (§4.7);
- a crash that any peer can trigger remotely (a denial of service with a packet or
  transaction);
- a wallet bug that loses funds or makes spends linkable, until users are warned
  (§4.6).

**Operators pause their own machines without waiting** when they observe the first two
signals directly. They report at once in the private channel.

**Resuming** requires, in the owner's judgement: a fix, a test that reproduces the
problem and passes with the fix, and a green CI run of the release.

### 4.10 Communicating known risks to testnet participants

- **Before anyone joins:** a notice in the README and the testnet guide. It says:
  - experimental software;
  - **no external audit or independent review** (docs/reviews/review-status.md);
  - coins without value;
  - the network may be reset;
  - the known privacy limitations (privacy-review.md §3 and §4, in plain words);
  - the provisional K4 policy (deep reorganizations are possible);
  - how to report problems privately.
- **During an incident:**
  - a public notice that the network is paused or degraded, with what users should
    do (for example: stop sending, keep wallet files);
  - technical detail only after a fix, unless users need it to protect themselves.
- **After an incident:** a short public post-mortem (what, impact, fix, what changed)
  and an AUDIT.md entry.

### 4.11 Emergency release

1. Fix on a branch; add the regression test.
2. Run the full suite locally; push; require the CI run of that exact commit to pass
   **before** operators are told to upgrade. Inspect its logs.
3. Tag the commit.
4. Tell operators, over the private channel:
   - the tag and its CI run;
   - the order of upgrades (all nodes, then miners);
   - whether the data directories stay compatible.
5. If the fix changes consensus, it needs a reset (§6), which requires the owner's
   explicit decision and a new network id.

## 5. Evidence preservation

Before restarting or upgrading anything, each operator saves:
- the node's data directory (block file, `bans.json`), or a copy of it;
- the node and miner logs for the incident window, at their original level;
- `/info` output and the peer list at the time;
- the exact binaries and their version (`--version`), and the release commit.

These go to the owner. **Logs contain IP addresses of peers; treat them as
private.**

## 6. Rollback of a bad release

- Every release is a tagged commit with a green CI run. Operators keep the previous
  binaries.
- **A release with no consensus change:** operators reinstall the previous binaries
  and restart. The data directory stays compatible.
- **A release with a consensus change** (testnet only, and only after a reset): there
  is no rollback on the same chain. Recovery is another reset with a new network id
  (docs/testnet-reset-plan.md §6).
- **Wallet files** written by a newer wallet may carry fields an older wallet ignores
  (`#[serde(default)]` in the reader). Rolling a wallet back loses the stored
  transactions and rings. Users should keep a copy of the wallet file before
  upgrading.

## 7. After every S1 or S2 incident

- An AUDIT.md entry: timeline, cause, fix, the test that now covers it, and what the
  detection missed.
- Update this plan if a step did not work.
- Update the readiness checklist if a gate was wrong.

## 8. Rehearsal (required by G14 before launch)

On the labnet, or the machines before launch:
1. Stop miners, then nodes, on the lead's instruction. Preserve evidence as in §5.
   Restart.
2. Roll back a release with no consensus change: install the previous binaries,
   restart, and confirm sync.
3. Rehearse the reset (done once on one machine: docs/testnet-reset-plan.md §7).
