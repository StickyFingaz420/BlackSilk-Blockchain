# BlackSilk Development Completion & Testnet Readiness Report

> **Snapshot of `5e667bd`; several P0 items were addressed afterwards — see AUDIT.md
> R14.** (Banner added 2026-09-27. The hardening round from `7826289` onward changed
> P2P, storage, the mempool, reproducibility and the RandomX evidence; the text below
> is unchanged and describes the state at `5e667bd`.)

**Date:** 2026-09-26. **Commit reviewed:** `5e667bd` (branch `rebuild/core`).

**Status of this report:** internal work only.
- Five fresh-context review agents and the author did the gap analysis.
- The author checked each high-severity claim against the source. §7 lists these
  checks.
- **No external audit or independent review has taken place** (review-status.md).
- Passing tests shows that the cases tested behave as expected, and nothing more.

**Classifications:**
- **Verified:** complete and verified by tests.
- **Needs testing:** complete, but needs further testing.
- **Partial:** partially implemented.
- **Not implemented.**
- **Deferred.**
- **Blocked.**

## 1. Verdict

**1. Is the core development finished? No, though it is close for a controlled,
trusted trial.**
- **What is complete:**
  - every component needed to run the chain exists, is integrated and passes 423
    tests;
  - those components are consensus, RandomX, v1 private transactions, PX
    zero-knowledge transactions, private contracts (the demonstration vault), P2P,
    the node, the miner and the wallet;
  - local multi-process runs converge through partitions and reorganizations, with
    private traffic.
- **Important work is still missing or partial:**
  - **Node robustness:** several denial-of-service and liveness weaknesses in P2P,
    one of which can ban honest peers.
  - **Scalable storage:** every block body is held in memory, and every block is
    re-validated at each restart.
  - **Measured sync and restart at realistic chain sizes.**
  - **RandomX evidence:** full-mode mining and the seed-key switch have never been
    exercised.
  - **Release reproducibility:** the consensus-pinned kernel binary cannot be rebuilt
    and checked against its source.
  - **Operations:** seed nodes, monitoring and release binaries.
  - **Internal review:** only about 29% of the review matrix defined in
    review-status.md is done (22 of 77 cells).
- **Transparent smart contracts** (the Wasm engine) exist but are **not
  integrated** into the chain (M3, deferred).

**2. Is the testnet v2 reset the right next step? Not yet.**
- The identity itself is sound, and the reset remains the right step.
- I recommend a **short hardening round before the seven-device trial** (§6, P0).
  - All P0 items are node-level, not consensus.
  - They do not change the genesis, the network id or any cryptographic parameter,
    so **no new reset is needed**.
- Without them, the trial is likely to fail for reasons already known:
  - honest peers banned during synchronization;
  - stalls while syncing large private-transaction blocks;
  - a node that cannot restart after a failed disk write.
  Such failures teach nothing new.
- **One consensus-level decision belongs before the trial:** PX-F4 and PX-F5
  (kernel rules, §5). Changing them after the trial starts would force another reset.

## 2. Status by area

| Area | Status | Basis and main gaps |
|---|---|---|
| **Consensus rules** (header, LWMA, MTP/FTL, chain selection) | **Verified** (unit level) | Integer-only, invalid cases tested. Gaps: no fuzz or property test of LWMA; no test of the genesis-to-launch gap; FTL on regtest exceeds LWMA's recommended bound (minor). No reorg-depth limit and no minimum chain work (policy K4) |
| **Block validation** | **Verified** | Sizes checked before decoding; block-wide duplicate sets; exact coinbase. Worst-case validation time never measured; validation runs under one global lock |
| **Transactions and privacy (v1)** | **Needs testing** | CLSAG, BP+, canonical encodings, identity rejection, anti-burning: well tested. The Janus anchor is the project's own construction; no external vectors. **Anonymity is not meaningful on a young, 7-participant chain** (decoy ages, coinbase-heavy outputs, collusion) |
| **ZK / zkVM** | **Needs testing** | Statistical, conditional zero knowledge (zk-coverage.md): 9 items open or upstream-dependent. Circuits reviewed internally for soundness. Open: ZK-F4, the verifier's cost on adversarial proofs (**never measured**); ZK-F3 (latent); zkVM F1, F3, F4 (low) |
| **PX consensus and state** | **Verified** (unit and single-node) | PX1–PX5, the fee rule, atomic apply/undo. Test gaps: duplicate nullifier in one block, pool underflow and PX byte budget at block level. **Design decisions open: PX-F4, PX-F5 (consensus)** |
| **Smart contracts** | **Partial** | Private contracts via PX work end to end, but only the **demonstration** vault (no timeout, no refund, not trustless). Transparent Wasm contracts: **Not implemented in the chain** (M3, deferred) |
| **RandomX and mining** | **Needs testing** | Pure Rust, 5 reference vectors. **Full mode has never been validated** (its test is ignored; every run used light mode) and is the miner's default. **The seed-key switch at height 2113 has never run with real RandomX.** No cross-platform comparison. The miner polls every 15 s and does not prepare the next dataset (all miners stall about 133 s or more at each switch) |
| **P2P / networking** | **Partial** | Transport, codec (fuzzed), Dandelion++, scoring: implemented. **Confirmed defects:** header batches are RandomX-hashed before cheap checks (N-1); honest relays of a header later found invalid are banned (ban-on-InvalidParent); requested blocks are dropped by the byte limit (N-3); header hashing blocks the peer's read loop and pings (N-14). Unbounded pre-handshake connections, exact-IP bans, no inbound eviction, eclipse weaknesses (N-4 to N-9). Tor inbound collapses on one ban (N-6). Unpenalized invalid-signature spam (N-11) |
| **Node** | **Needs testing** | Config, data-directory lock, graceful shutdown. The chain lock is taken on async threads (stall risk) |
| **Wallet** | **Needs testing** | Encryption at rest (Argon2id + AES-GCM), crash-safe submissions, ring reuse, locks: tested. **Trusts its node for proof of work and validity** (fake balances possible from a remote node). Restore gaps (W-F7 and others). Empty passwords accepted; no directory fsync; one vacuous test assertion; no rescan or sweep |
| **Mempool** | **Partial** | First-seen conflicts, size caps, fee eviction, reorg return. **No unit tests for its policies.** Every block fully re-verifies every pooled v1 transaction under the lock (DoS; cost unmeasured). No expiry |
| **Reorg / rollback / recovery** | **Needs testing** | Undo is complete and tested at depths 1 to 3; labnet up to depth 17 with PX. No deterministic deep PX reorg test. PX-F6: dependent PX transactions are dropped (undocumented for users) |
| **Chain state and storage** | **Partial** | Append-only log with CRC and fsync; torn-tail recovery tested. **Bug: a failed or partial append (for example, disk full) leaves the node unable to restart** (confirmed). All bodies and undo data are kept in RAM (PX-F1, PX-F2). **Every restart re-validates every block**, PX proofs included (PX-F3). No indexes or pruning. Side branches and unvalidated bodies are stored forever |
| **Fees and emission** | **Verified** | Exact emission, tail 0.6 BLK, u128 sums, minimum fee checked; the exact PX fee is a consensus rule |
| **Genesis / network parameters** | **Verified** (testnet v2, regtest); mainnet **Not implemented** (deliberately) | v2 genesis pinned and rehearsed. Anyone can pre-mine from the public genesis before launch (low difficulty, no depth limit) |
| **RPC / API** | **Partial** | Loopback by default. No authentication, rate limit, timeout or Host check; **0 tests of the router**. Plaintext only: remote wallets cannot use TLS or Tor (the docs' Tor advice is not supported by the client) |
| **CLI** | **Verified** for the trial | Node, miner, wallet and labnet work. Missing: multi-recipient, sweep, rescan, account restore |
| **Security and cryptography** | **Needs testing** | Pure-Rust primitives, hedged randomness, no unsafe code in project crates (checked). **No external review** of CLSAG, BP+, Janus, Poseidon2, the delivery combiner or the circuits. ML-KEM crate is pre-1.0. Private vulnerability reporting on GitHub is **disabled**, while SECURITY.md points reporters to it |
| **DoS / resource limits** | **Partial** | Many limits exist. The gaps are N-1 to N-4, N-11 to N-13, mempool revalidation, ZK-F4 and PX-F1 (all above) |
| **Sync and bootstrap** | **Partial** | Header-first sync works; tested only with zero-cost PoW and a 1,121-block labnet joiner. **Built-in seed list empty** (Blocked on hosts); stale peer tables never fall back to seeds. Sync at realistic size never measured |
| **Testnet tooling** | **Partial** | Labnet: verified on one machine. `deploy/` (systemd, Docker, install script): **written, never executed**; the install script likely fails under sudo. No metrics endpoint, alerting, explorer, faucet or release binaries |
| **Documentation** | **Needs testing** (it needs correction) | The reviews are careful. **Stale or contradictory:** README (layout, "PX is a design"), the AUDIT.md header, roadmap statuses, the reset plan's seed statement, proof figures in px.md. Trial authorization is inconsistent across the reset plan, launch checklist and validation checklist. Present-tense "audited" wording in docs/zk.md (design language). V15 "memory flat" cannot hold while PX-F1 is open |
| **CI / build / reproducibility** | **Partial** | CI with 4 jobs, pinned actions and toolchain; lint, audit and fuzz-smoke green on `5e667bd`, **test job still running**. No `rust-toolchain.toml`. **`px/kernel.elf` (consensus-pinned) is a committed binary that nothing rebuilds and compares; its toolchain is unrecorded.** Linux x86_64 only; no Windows or ARM64. Ignored tests never run. No debug-assertion runs. No releases, tags or signatures. `legacy/` carries about 115 MB of tracked build artifacts |

## 3. Consensus-critical and security-critical work remaining

**Consensus-critical** (changing any of these needs your explicit approval; the ones
marked "reset" need a new testnet identity):
1. **PX-F4 and PX-F5 (reset if changed).**
   - PX-F4: a contract function fixes an output's owner, value and data, but the
     caller picks its `rcm`.
   - PX-F5: contract outputs are not forced to `owner = 0`.
   - Decide now: either fix them in the kernel, or accept and document them as trust
     assumptions of contracts.
2. **Kernel binary reproducibility.** The consensus-pinned `kernel.id` is derived
   from a committed ELF that no one can currently prove was built from the reviewed
   source. Record the toolchain and add a rebuild-and-compare check. This is not a
   rule change.
3. **RandomX full mode and the seed switch.**
   - A full-mode bug would not split the chain, because nodes verify in light mode.
     It would, however, make every block a full-mode miner finds invalid.
   - The seed-switch path must be exercised before we rely on it at height 2113.
   - A cross-device hash check is also needed.
4. **Reorg depth and minimum chain work** (policy K4). Acceptable for a trusted
   trial. It must be revisited before any public network (pre-mining risk from the
   public genesis).

**Security-critical (node, not consensus):**
1. N-1: header-batch PoW amplification.
2. Honest peers banned by `InvalidParent`.
3. N-3: requested blocks dropped by the byte limit.
4. N-14: header hashing blocks read loops and pings.
5. The storage failed-append bug.
6. N-2: unvalidated side-branch bodies stored forever.
7. N-4, N-5 and N-9: pre-handshake flood, exact-IP bans and no inbound eviction.
8. Mempool revalidation cost.
9. N-11: invalid-signature spam.
10. ZK-F4: verifier cost on adversarial proofs, unmeasured.
11. Memory growth: PX-F1, PX-F2 and N-12.
12. The wallet trusts its node.
13. RPC hardening.
14. Private vulnerability reporting disabled.

## 4. Known issues from earlier internal reviews that are still unresolved

| Source | Open |
|---|---|
| Round 1, PX | **PX-F1** (bodies in RAM), **PX-F2** (undo memory), **PX-F3** (re-verification at restart and on reorg), **PX-F4** and **PX-F5** (kernel design), **PX-F6** (dependent PX transactions dropped on reorg), PX-F7 to F11 (low: verifier cost, full tree, duplicate program ids PX-F9, precheck, panic containment) |
| Round 1, ZK | **ZK-F3** (latent API hazard), **ZK-F4** (verifier DoS cost, unmeasured), ZK F5 to F10 (low; F7 to F9 partly fixed in docs) |
| Round 1, zkVM | F1 (`MAX_OUTPUT_WORDS` not enforced; harmless while PX pins the length), F3, F4 (low) |
| Round 1, wallet | **W-F6 residual** (no PoW check), **W-F7** (restore scans account 0 only), F12, **W-F13**, **W-F15**, the W-5 residuals (rings lost on restore) |
| Earlier rounds | P-6 (Dandelion stem probing, low); N1 (eclipse resistance untested) and N4 (Dandelion parameters) in assumptions.md; R5 items (no peer authentication, no padding, recognizable handshake, no I2P); roadmap items 7 to 10 and 14 |
| Process | **About 29% of the review matrix done** (22 of 77 cells). No component has all seven passes, and none has the integration pass. **v1 transactions, chain management and reorganizations, P2P, record delivery, RandomX and difficulty, and Poseidon2 have no pass** under the current process (only the pre-process reviews R1 to R6) |

**Closed in this cycle:** ZK-F29, ZK-F30, Z2 (withdrawn), round 2 T1 to T5, S1, S2,
round 3 and round 4 findings.

## 5. What to do before, during and after the seven-device trial

**Before** (the P0 list in §6), plus these operator conditions:
- NTP on every device;
- hardware requirements published:
  - PX proving peaks at about 3.8 GB and takes about 45 s;
  - a full-mode miner needs 2.3 GB;
  - one light-mode hash takes about 0.45 s;
- RPC kept on loopback and firewalled;
- fresh data directories and a deleted `peers.json` (never reuse the rehearsal's
  data);
- explicit `--peer` lists if devices share a NAT;
- participants told that **v1 anonymity at this scale is not meaningful**: the trial
  tests mechanics, not anonymity;
- wallet files backed up, not only seeds;
- non-empty wallet passwords.

**During:**
- V1 to V16 with evidence;
- run past the **first seed switch (height 2113, about 70 h)**: extend the run beyond
  72 h so the switch is inside it;
- per device, record:
  - sync time, restart time, and RSS against chain size;
  - PX verification and proving time;
  - reorg depths;
  - bans and disconnects;
  - clock skew;
- cross-device agreement on tip, root and `generated`;
- a deliberate multi-block reorg across a PX deposit and a withdrawal;
- a disk-full test on one node;
- rehearse the incident response and the rollback.

**After the trial, before any public testnet:**
- storage redesign: bodies on disk, indexes, bounded undo, and restart without full
  re-validation;
- P2P hardening: N-2, N-4 to N-9, N-11 to N-13;
- seed nodes;
- metrics and alerting;
- RPC hardening;
- wallet: TLS or SOCKS for remote nodes, and a PoW check;
- decoy calibration from real data;
- mempool: verification cache, tests and expiry;
- a CI matrix (Windows, ARM64), scheduled ignored tests, and a debug-assertion job;
- signed and reproducible releases;
- the remaining review passes (the integration pass first);
- removal of `legacy/` artifacts;
- transparent contracts (M3) and a production contract design (timeouts, refunds);
- the Plonky3 report decision;
- Dandelion++ parameters.

## 6. Next development tasks, in priority order

**P0: before the seven-device trial.** None changes consensus, cryptographic
parameters or the v2 identity.
1. **Confirm CI green on `5e667bd`.** The test job was still running when this report
   was written.
2. **Decide PX-F4 and PX-F5.** This is the owner's decision.
   - If the kernel changes, that is a consensus change and a new identity (v3). I
     will explain it and ask first.
   - Otherwise, document both as contract trust assumptions.
3. **P2P fixes:**
   - cheap header checks before any RandomX, and one header at most per unsolicited
     batch (N-1);
   - no ban for relaying a header that is later found invalid;
   - requested blocks exempt from the byte limit (N-3);
   - header hashing off the peer's read loop (N-14).
   Each fix gets a regression test.
4. **Storage:** truncate a failed or partial append back to the previous length, and
   add a test.
5. **Measurements, with real RandomX:**
   - sync of a chain of 5,000 or more blocks from 3 or more peers;
   - restart time and memory with 100 or more PX transactions;
   - mempool revalidation time at a full pool;
   - the verifier's cost on adversarial proofs at the largest registrable budget
     (ZK-F4).
   Each result either goes into the operator docs or is fixed.
6. **RandomX:**
   - run the full-mode test;
   - a short full-mode mining run;
   - a fixed-vector hash check on every device class, ARM64 included if present.
7. **Reproducibility:**
   - `rust-toolchain.toml` (1.98.1);
   - the guest toolchain recorded;
   - a CI job that rebuilds `kernel.elf` and `vault.elf` and compares their ids.
8. **Mempool unit tests** (eviction, class caps, the non-negative PX pool in `select`),
   and the PX block-level test gaps.
9. **Operator documentation:**
   - hardware requirements, NTP, topology, and the anonymity statement;
   - fix V15 (memory grows with the chain until PX-F1 is fixed), V10 (it needs a
     tool) and V16 (use per-device figures);
   - fix the reset plan's seed statement;
   - one consistent trial authorization across the reset plan, the checklist,
     AUDIT.md and the validation list;
   - update README, the AUDIT.md header, the roadmap and the px.md figures.
10. **Your settings:** enable GitHub private vulnerability reporting, and choose the
    operators' channel (G14).
11. **Review passes:** at least an adversarial and a consensus pass for the components
    with none that every block depends on (v1 transactions, chain management and
    reorganizations, P2P, RandomX and difficulty). Alternatively, record your
    acceptance of that gap for the trial.

**P1: during the trial:** §5 "During".

**P2: after the trial, before a public testnet:** §5 "After", ordered as storage,
P2P, bootstrap and monitoring, wallet trust and privacy, mempool, CI and releases,
then review completion.

## 7. How the key claims were checked

The author re-read the code for each of these:
- **N-1:** `p2p/src/net.rs:852-876` computes PoW for the whole batch before
  `accept_headers`.
- **InvalidParent ban:** `chain/src/manager.rs:590-593` returns `InvalidParent` for
  a stored invalid header. `net.rs:890` scores it 100, which is the ban threshold.
- **N-3:** `net.rs:672-686` sends every frame through the byte bucket (burst 16 MB,
  4 MB/s; `p2p/src/limits.rs:70`) and drops frames over the limit, including
  requested blocks (up to 16 in flight, each up to about 9.2 MB).
- **N-14:** `handle()` is awaited inside the read loop (`net.rs:689`).
- **Storage:** `chain/src/store.rs:85-87` appends without truncating on error, and
  `load` refuses a corrupt record that is followed by valid data (`store.rs:108-115`).
- **Restart:** `ChainManager::open` replays every stored block through
  `submit_inner` (`manager.rs:200-223`).
- **Mempool:** `revalidate` runs `validate_mempool_tx` on every entry after each
  block (`chain/src/mempool.rs:247-262`), and the file has no test module.
- **Kernel ELF:** `zkvm/guests/build.sh` states the output depends on the exact rustc
  version; there is no `rust-toolchain.toml`.
- **Private vulnerability reporting:** the GitHub API returns `enabled: false`.

**Estimates not yet measured:** the cost figures for N-1 (about 900 CPU-seconds per
batch), mempool revalidation, restart time and ZK-F4. They are extrapolated from the
documented 0.45 s per light hash and about 0.2 s per PX verification. P0 item 5
measures them.
