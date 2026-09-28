# Pre-testnet roadmap and maturity matrix

> **Historical snapshot (the v2-era roadmap and maturity matrix, last updated 2026-09-27); not maintained.** The current project and testnet
> status, the launch gates and the open items are kept only in
> [STATUS.md](STATUS.md). The v2 identity this document refers to is **retired**, and
> the testnet is disabled until the v3 genesis is generated at launch
> ([testnet-v3-genesis.md](testnet-v3-genesis.md)). The Wasm contract-engine rows (wasmi and its fuzzing) are **not testnet evidence**:
> the engine is frozen research outside the build (decision D22,
> [research/wasm-contracts.md](research/wasm-contracts.md)), and PX is the only
> consensus contract platform.

Status: **2026-09-25, internal; statuses updated 2026-09-27** (each updated entry is
dated). The owner approves every step that changes the network; nothing here
authorizes a reset or a launch. The v2 identity is approved and fixed in code. The
seven-device trial is **not** authorized until the owner approves the readiness report
after the hardening round (docs/reviews/completion-readiness-2026-09-26.md §6). Gates:
docs/testnet-launch-checklist.md.

## 1. Maturity levels

| Level | Meaning |
|---|---|
| L1 Implemented | The code exists and builds |
| L2 Passed internal tests | Tests written by the project pass (unit, integration, fuzzing, labnet) |
| L3 Reviewed by the development team | A written internal review exists (AUDIT.md, docs/reviews/) |
| L4 Internally reviewed (multi-pass) | All seven internal review passes done and recorded (review-status.md §3), findings fixed or accepted. **Not an external review** |
| L5 Ready for testnet evaluation | L4 reached, and the reset gates passed |
| L6 Ready for production | A testnet run completed, a multi-pass review of the final code, operations procedures in place. (An external audit would be an item here if a reviewer were engaged; none is planned, owner decision 2026-09-25) |

## 2. Matrix per component

✅ reached · ◐ partly · — not reached.

| Component | L1 | L2 | L3 | L4 | L5 | L6 | Notes |
|---|---|---|---|---|---|---|---|
| RandomX PoW (pure-Rust port) | ✅ | ✅ | ✅ | — | — | — | Reference vectors. Full mode: official vectors and full/light agreement on 1,024 random inputs, run locally 2026-09-25 and 2026-09-27 (opt-in test); its CI job has not yet run on GitHub. The seed-key switch is exercised only with a short test epoch (2026-09-27) |
| Consensus: difficulty, timestamps, chain selection | ✅ | ✅ | ✅ | — | — | — | No reorg-depth limit, by documented policy; deep reorgs warned (assumptions.md K4) |
| v1 transactions (CLSAG, BP+, stealth outputs) | ✅ | ✅ | ✅ | — | — | — | AUDIT.md R3 |
| Chain manager, storage, mempool | ✅ | ✅ | ✅ | — | — | — | Restart rebuild tested. Storage corruption tests exist (2026-09-27, hardening round: torn tail, mid-file corruption, `--repair-store`, injected write failures); a real full disk is untested. Bodies and undo data stay in memory (PX-F1, PX-F2) |
| P2P, Dandelion++ | ✅ | ✅ | ✅ | — | — | — | Labnet on one machine only; P-6 (privacy-review §3b). Hardening round in progress (2026-09-27, AUDIT.md R14); open: N-4, N-5, N-6, N-9, N-11, N-12 |
| Node and RPC | ✅ | ✅ | ◐ | — | — | — | Reviewed as part of R4 |
| Miner | ✅ | ✅ | ✅ | — | — | — | AUDIT.md R4 |
| Wallet, v1 | ✅ | ✅ | ✅ | — | — | — | Error handling reviewed (wallet-review.md); W-5 fixed with residuals |
| ZK proof system configuration (BS-ZK-2, Plonky3 0.7.0 with 3 patches) | ✅ | ✅ | ✅ | — | — | — | Critical review area 2 |
| BVM-1 zkVM circuits | ✅ | ✅ | ✅ | — | — | — | Critical review area 3 |
| PX kernel, records, `Hk` | ✅ | ✅ | ✅ | — | — | — | Critical review areas 1 and 4 |
| PX consensus integration | ✅ | ✅ | ✅ | — | — | — | Critical review area 5 |
| Record delivery (hybrid KEM) | ✅ | ✅ | ✅ | — | — | — | Review area 6 |
| Contract-record distribution, sealed shares | ✅ | ✅ | ✅ | — | — | — | docs/px.md §13 |
| Vault contract | ✅ | ✅ | ✅ | — | — | — | **Demonstration only:** no timeout, no refund, not trustless |
| Wallet, PX and contracts | ✅ | ✅ | ◐ | — | — | — | Review area 8 |
| Transparent contract engine (wasmi) | ✅ | ✅ | ✅ | — | — | — | **Not integrated into the chain** (milestone M3, chain integration, not done); not in the testnet |

**No component has reached L4** (still true on 2026-09-27; the multi-pass internal review is in progress), so none
is ready for testnet evaluation (L5).

**External review: none.** No external audit has been engaged or completed, and none is
currently planned (owner decision 2026-09-25, review-status.md).

## 3. Work remaining before the testnet

Each item carries one of the report classifications.

| # | Item | Status |
|---|---|---|
| 1 | Internal multi-pass review of every critical component (review-status.md §3) | **Partially implemented:** process defined; passes in progress. External review: none engaged (owner decision) |
| 2 | Resolve the internal review's findings, then re-run the suite, the fuzzing and the rehearsal | **Partially implemented:** follows 1 |
| 3 | CI running on GitHub, all jobs green | **Complete and verified** for commit `d6534c3` (run 36177083290); later commits passed through `87278ac` (runs #69–#74). **2026-09-27:** `7826289` is unpushed; its new jobs `guests` and `randomx-full` have never run on GitHub. It must stay green up to the release commit. CI does not replace review |
| 4 | Extended contract-engine fuzzing | **Done** (2026-09-25): 6 hours on `wasm_module` and 4 hours on `contract_sequence`, 0 crashes (AUDIT.md) |
| 5 | Reorg-depth policy (assumptions.md K4) | **Complete; internal multi-pass review pending:** no limit, a warning at 10 blocks, deepest reorg tracked (docs/consensus.md §8). Owner may revise; mainnet revisits limits or checkpoints |
| 6 | Multi-node adversarial tests: a malicious peer sending valid-looking but conflicting PX transactions across a partition; a deep reorg across PX deposits and withdrawals | **Partially implemented:** the single-node and two-node cases are tested; labnet reorgs up to depth 17 with PX traffic |
| 7 | Real multi-machine tests (docs/testnet.md §7) | **Not implemented:** after the review, with approval |
| 8 | Recovery, restart, reorg and reset tests on real machines | **Partially implemented:** restart rebuild (one node) and the reset rehearsal (one machine) |
| 9 | Partition tests between real machines | **Partially implemented:** simulated only (labnet proxy) |
| 10 | Supply and private-state consistency under long runs | **Partially implemented:** checked by labnet (62 min, 5 processes); a 72-hour run is required by docs/testnet.md §7 step 7 |
| 11 | Wallet error handling (clear messages for node errors, rejected transactions, insufficient private funds, stale anchors) | **Complete; internal multi-pass review pending** (docs/reviews/wallet-review.md): W-1 to W-5 fixed, including two high privacy issues (W-1, W-2); W-5 by ring reuse, with residuals. Open: friendlier messages |
| 12 | Documentation of every genesis-affecting change | **Complete; internal multi-pass review pending:** docs/testnet-reset-plan.md §2 |
| 13 | Launch checklist and rollback plan | **Partially implemented:** docs/testnet-launch-checklist.md (14 gates) and docs/testnet-incident-response.md (roles, severities, signals, procedures, evidence, release rollback). Not rehearsed; roles not named |
| 14 | Cross-platform determinism (Linux, ARM64) | **Partially implemented:** the full suite passes on Linux x86_64 in CI. There is no cross-platform comparison of identical hashes or roots, and no ARM64. **2026-09-27:** the `randomx-full` CI job (Linux) would compare the official vectors on a second platform, but has not yet run |
| 15 | Dandelion++ parameters for BlackSilk's network size (assumptions.md N4) | **Deferred:** needs testnet measurements |
| 16 | Plonky3 anonymous report | **Complete but awaiting approval:** not submitted |
| 17 | Contracts beyond the vault; transparent-contract chain integration (M3) | **Deferred** |
| 18 | Proof size (about 2.2 MB transfer, 2.7 MB vault call; 3 PX transactions per block) | **Deferred:** aggregation-study.md |
