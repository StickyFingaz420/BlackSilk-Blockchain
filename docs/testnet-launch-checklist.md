# Experimental testnet: launch readiness checklist

> **Historical snapshot (the v2-era launch checklist, last updated 2026-09-27); not maintained.** The current project and testnet
> status, the launch gates and the open items are kept only in
> [STATUS.md](STATUS.md). The v2 identity this document refers to is **retired**, and
> the testnet is disabled until the v3 genesis is generated at launch
> ([testnet-v3-genesis.md](testnet-v3-genesis.md)).
> The v3 trial's launch preconditions (the protocol freeze, `D0`, signing, the
> network pre-shared key, the endpoint checklist) are step 0 of
> [testnet-v3-genesis.md](testnet-v3-genesis.md) §6; their status is in STATUS.md.

Status: **2026-09-27. Not ready; not all gates are passed.**
- **Trial authorization:** the v2 identity is approved and fixed in code. The
  seven-device trial is **not** authorized until the owner approves the readiness
  report after the hardening round (docs/reviews/completion-readiness-2026-09-26.md
  §6). Gates: this document.
- The testnet is reset and launched only when every gate below is **Passed** (or
  explicitly accepted by the owner, with the reason recorded) and the owner has
  approved the final readiness report.
- The hardening round (commit `7826289` onward, AUDIT.md R14) changes P2P, storage and
  the mempool; the gate states below predate its review.
- Related documents:
  - the reset procedure: docs/testnet-reset-plan.md;
  - the remaining work: docs/testnet-roadmap.md.

**Gate states:** Passed · In progress · Not started · Blocked · Accepted (a known gap,
accepted by the owner).

| # | Gate | Evidence required | State |
|---|---|---|---|
| G1 | **Internal multi-pass security and privacy review** of every critical component (review-status.md §3) | The review log (internal-review-log.md) with findings, fixes and tests per component and pass. **No external audit exists; the readiness report must say so** | **In progress.** Round 1 done for four components. It found that the proofs were not zero-knowledge as configured (ZK-F29, ZK-F30). **Both are fixed in code** (R12: terminal blinding and minimum height 2^8), and rounds 2–4 reviewed the fix (R13). Zero knowledge is claimed only as statistical and conditional (zk-coverage.md) |
| G2 | **Findings resolved or accepted** | Every finding recorded in AUDIT.md with its fix and test, or the owner's written acceptance | In progress (depends on G1) |
| G3 | **CI green on GitHub** | A GitHub Actions run of the release commit, every job passed (six since `7826289`: lint, test, randomx-full, guests, audit, fuzz-smoke) | **Passed for `d6534c3`** (run 36177083290, the four jobs that existed then green); later commits passed through `87278ac` (runs #69–#74). `7826289` is unpushed and has not run. The jobs `guests` and `randomx-full`, added in `7826289`, **have never run on GitHub**. Re-run required for the release commit, with all six jobs |
| G4 | **Consensus and state-management validation** | Full suite; restart rebuild; supply check under labnet; review area 5 | In progress: internal tests pass; internal review passes pending |
| G5 | **Multi-machine testing** | docs/testnet.md §7 on real machines, including a 72-hour run | Not started (after G1–G3) |
| G6 | **Reorganization and recovery** | Partitions and reorgs between machines; restart and resync; the K4 policy (docs/consensus.md §8) | In progress: labnet on one machine (reorgs up to depth 17), restart rebuild test; K4 documented |
| G7 | **Reset and rollback procedures** | A rehearsed reset (reset-plan §7); a written rollback (§6) | In progress: rehearsal done on one machine; rollback written, not rehearsed |
| G8 | **Wallet and private-transaction testing** | e2e tests for v1, PX, vault; wallet-review.md findings closed or accepted | In progress: W-1 to W-5 fixed (W-5 by ring reuse, with residuals: rings lost on a restore from seed) |
| G9 | **Network resilience and adversarial testing** | Invalid-PX penalty tests; misbehaviour scoring; fuzzing; multi-node adversarial scenarios | In progress: single-node and two-node cases; fuzzing (about 531 M executions plus the contract-engine runs); multi-node adversarial scenarios not yet. Known open P2P defects (completion-readiness-2026-09-26.md §2–§3): N-4 (unbounded pre-handshake connections), N-5 (exact-IP bans), N-6 (inbound Tor peers share 127.0.0.1), N-9 (no inbound eviction), N-11 (unpenalized invalid-signature relays), N-12 (memory growth) |
| G10 | **Supply conservation** | Labnet supply checks; multi-machine supply audit (generated = Σ wallets, v1 plus private) | In progress: labnet passes (62 min); multi-machine not yet |
| G11 | **Known privacy limitations published** | privacy-review.md P-1 to P-9 and §4 stated in user docs | In progress: documented in the reviews; the user guidance in docs/px.md §12 now covers P-9; a full cross-check of user docs against P-1 to P-9 is pending |
| G12 | **Genesis and consensus-affecting changes** | reset-plan §2 complete and matching the code; the genesis pin test | In progress: reset-plan §2 and §3 updated for v2 (2026-09-26); genesis pin test passes |
| G13 | **Operational documentation** | docs/testnet.md (running, mining, monitoring, troubleshooting, operator requirements); a peer list for the trial | In progress: operator requirements and procedures written (docs/testnet.md §12, 2026-09-27; not yet used by an operator). The built-in seed list is empty; the trial uses explicit `--peer` lists |
| G14 | **Rollback and incident-response plan** | The owner as incident lead; a private reporting route; an operators' channel; severities; pause conditions; emergency release; evidence; communication of known risks; a rehearsal | **Partially implemented:** the procedure is written around the owner (docs/testnet-incident-response.md, SECURITY.md). Awaiting: the owner's approval and choice of channels (§1a); GitHub private vulnerability reporting enabled (the owner's setting); a rehearsal (§8); no automated alerting |

## Before the owner's final approval

- [ ] Every gate Passed or Accepted, with its evidence linked.
- [ ] The readiness report states, separately:
  - what is verified internally;
  - that **no independent external audit** has taken place (review-status.md);
  - the open risks;
  - what is deferred.
- [ ] The release commit and binaries are pinned; the CI run of that commit is linked.
- [ ] The Plonky3 upstream report is filed or deliberately withheld (the owner's call).
