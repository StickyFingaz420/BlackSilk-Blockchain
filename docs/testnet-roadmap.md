# Pre-testnet roadmap and maturity matrix

Status: **2026-09-25, internal.** The owner approves every step that changes the
network; nothing here authorizes a reset or a launch. The gates for the reset are in
docs/testnet-reset-plan.md §0.

## 1. Maturity levels

| Level | Meaning |
|---|---|
| L1 Implemented | The code exists and builds |
| L2 Passed internal tests | Tests written by the project pass (unit, integration, fuzzing, labnet) |
| L3 Reviewed by the development team | A written internal review exists (AUDIT.md, docs/reviews/) |
| L4 Internally reviewed (multi-pass) | All seven internal review passes done and recorded (review-status.md §3), findings fixed or accepted. **Not an external review** |
| L5 Ready for testnet evaluation | L4 reached, and the reset gates passed |
| L6 Ready for production | A testnet run completed, an audit of the final code, operations procedures in place |

## 2. Matrix per component

✅ reached · ◐ partly · — not reached.

| Component | L1 | L2 | L3 | L4 | L5 | L6 | Notes |
|---|---|---|---|---|---|---|---|
| RandomX PoW (pure-Rust port) | ✅ | ✅ | ✅ | — | — | — | Reference vectors; full mode opt-in test (AUDIT.md R1) |
| Consensus: difficulty, timestamps, chain selection | ✅ | ✅ | ✅ | — | — | — | No reorg-depth limit, by documented policy; deep reorgs warned (assumptions.md K4) |
| v1 transactions (CLSAG, BP+, stealth outputs) | ✅ | ✅ | ✅ | — | — | — | AUDIT.md R3 |
| Chain manager, storage, mempool | ✅ | ✅ | ✅ | — | — | — | Restart rebuild tested; not tested against disk corruption |
| P2P, Dandelion++ | ✅ | ✅ | ✅ | — | — | — | Labnet on one machine only; P-6 (privacy-review §3b) |
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

**No component has reached L4** (the multi-pass internal review is in progress), so none
is ready for testnet evaluation (L5).

**External review: none.** No external audit has been engaged or completed, and none is
currently planned (owner decision 2026-09-25, review-status.md).

## 3. Work remaining before the testnet

Each item carries one of the report classifications.

| # | Item | Status |
|---|---|---|
| 1 | Internal multi-pass review of every critical component (review-status.md §3) | **Partially implemented:** process defined; passes in progress. External review: none engaged (owner decision) |
| 2 | Resolve the internal review's findings, then re-run the suite, the fuzzing and the rehearsal | **Partially implemented:** follows 1 |
| 3 | CI running on GitHub, all jobs green | **Complete and verified** for commit `d6534c3` (run 36177083290). It must stay green up to the release commit. CI does not replace review |
| 4 | Extended contract-engine fuzzing | **Partially implemented:** runs in progress (AUDIT.md when finished) |
| 5 | Reorg-depth policy (assumptions.md K4) | **Complete; internal multi-pass review pending:** no limit, a warning at 10 blocks, deepest reorg tracked (docs/consensus.md §8). Owner may revise; mainnet revisits limits or checkpoints |
| 6 | Multi-node adversarial tests: a malicious peer sending valid-looking but conflicting PX transactions across a partition; a deep reorg across PX deposits and withdrawals | **Partially implemented:** the single-node and two-node cases are tested; labnet reorgs up to depth 17 with PX traffic |
| 7 | Real multi-machine tests (docs/testnet.md §7) | **Not implemented:** after the review, with approval |
| 8 | Recovery, restart, reorg and reset tests on real machines | **Partially implemented:** restart rebuild (one node) and the reset rehearsal (one machine) |
| 9 | Partition tests between real machines | **Partially implemented:** simulated only (labnet proxy) |
| 10 | Supply and private-state consistency under long runs | **Partially implemented:** checked by labnet (62 min, 5 processes); a 72-hour run is required by docs/testnet.md §7 step 7 |
| 11 | Wallet error handling (clear messages for node errors, rejected transactions, insufficient private funds, stale anchors) | **Complete; internal multi-pass review pending** (docs/reviews/wallet-review.md): W-1 to W-5 fixed, including two high privacy issues (W-1, W-2); W-5 by ring reuse, with residuals. Open: friendlier messages |
| 12 | Documentation of every genesis-affecting change | **Complete; internal multi-pass review pending:** docs/testnet-reset-plan.md §2 |
| 13 | Launch checklist and rollback plan | **Partially implemented:** docs/testnet-launch-checklist.md (14 gates) and docs/testnet-incident-response.md (roles, severities, signals, procedures, evidence, release rollback). Not rehearsed; roles not named |
| 14 | Cross-platform determinism (Linux, ARM64) | **Partially implemented:** the full suite passes on Linux x86_64 in CI. There is no cross-platform comparison of identical hashes or roots, and no ARM64 |
| 15 | Dandelion++ parameters for BlackSilk's network size (assumptions.md N4) | **Deferred:** needs testnet measurements |
| 16 | Plonky3 anonymous report | **Complete but awaiting approval:** not submitted |
| 17 | Contracts beyond the vault; transparent-contract chain integration (M3) | **Deferred** |
| 18 | Proof size (~2 MB; ~4 PX transactions per block) | **Deferred:** aggregation-study.md |
