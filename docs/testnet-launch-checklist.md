# Experimental testnet: launch readiness checklist

Status: **2026-09-25. Not ready; not all gates are passed.**
- The testnet is reset and launched only when every gate below is **Passed** (or
  explicitly accepted by the owner, with the reason recorded) and the owner has
  approved the final readiness report.
- Related documents:
  - the reset procedure: docs/testnet-reset-plan.md;
  - the remaining work: docs/testnet-roadmap.md.

**Gate states:** Passed · In progress · Not started · Blocked · Accepted (a known gap,
accepted by the owner).

| # | Gate | Evidence required | State |
|---|---|---|---|
| G1 | **Independent security and privacy review** of the five critical areas (review-package.md) | A written report by a qualified external reviewer, at a pinned commit | **Not started.** Candidates: reviewer-candidates.md |
| G2 | **Findings resolved or accepted** | Every finding recorded in AUDIT.md with its fix and test, or the owner's written acceptance | Not started (depends on G1) |
| G3 | **CI green on GitHub** | A GitHub Actions run of the release commit, all four jobs passed | **Passed for `d6534c3`** (run 36177083290, all four jobs green). Re-run required for the release commit |
| G4 | **Consensus and state-management validation** | Full suite; restart rebuild; supply check under labnet; review area 5 | In progress: internal tests pass; independent review pending |
| G5 | **Multi-machine testing** | docs/testnet.md §7 on real machines, including a 72-hour run | Not started (after G1–G3) |
| G6 | **Reorganization and recovery** | Partitions and reorgs between machines; restart and resync; the K4 policy (docs/consensus.md §8) | In progress: labnet on one machine (reorgs up to depth 17), restart rebuild test; K4 documented |
| G7 | **Reset and rollback procedures** | A rehearsed reset (reset-plan §7); a written rollback (§6) | In progress: rehearsal done on one machine; rollback written, not rehearsed |
| G8 | **Wallet and private-transaction testing** | e2e tests for v1, PX, vault; wallet-review.md findings closed or accepted | In progress: W-1 to W-5 fixed (W-5 by ring reuse, with residuals: rings lost on a restore from seed) |
| G9 | **Network resilience and adversarial testing** | Invalid-PX penalty tests; misbehaviour scoring; fuzzing; multi-node adversarial scenarios | In progress: single-node and two-node cases; fuzzing (about 531 M executions plus the contract-engine runs); multi-node adversarial scenarios not yet |
| G10 | **Supply conservation** | Labnet supply checks; multi-machine supply audit (generated = Σ wallets, v1 plus private) | In progress: labnet passes (62 min); multi-machine not yet |
| G11 | **Known privacy limitations published** | privacy-review.md P-1 to P-9 and §4 stated in user docs | In progress: documented in the reviews; the user guidance in docs/px.md §12 now covers P-9; a full cross-check of user docs against P-1 to P-9 is pending |
| G12 | **Genesis and consensus-affecting changes** | reset-plan §2 complete and matching the code; the genesis pin test | In progress: documented; to be re-checked after G2 |
| G13 | **Operational documentation** | docs/testnet.md (running, mining, monitoring, troubleshooting); seed nodes set | In progress: the seed-node list is empty (AUDIT.md) |
| G14 | **Rollback and incident-response plan** | Who decides, how nodes are told, how a bad release is withdrawn, how a consensus bug is handled (halt, fix, reset) | **Partially implemented:** docs/testnet-incident-response.md and SECURITY.md written; `/info` now reports `deepest_reorg` and `misbehaving_disconnects`. Missing: named roles and channels, a rehearsal (§8), a supply-audit tool for the real testnet, and GitHub private vulnerability reporting enabled (the owner's setting) |

## Before the owner's final approval

- [ ] Every gate Passed or Accepted, with its evidence linked.
- [ ] The readiness report states, separately:
  - what is verified internally;
  - what is independently reviewed;
  - the open risks;
  - what is deferred.
- [ ] The release commit and binaries are pinned; the CI run of that commit is linked.
- [ ] The Plonky3 upstream report is filed or deliberately withheld (the owner's call).
