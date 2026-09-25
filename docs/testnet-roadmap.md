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
| L4 Independently reviewed | A qualified outside reviewer has examined the code and reported |
| L5 Ready for testnet evaluation | L4 findings resolved, and the reset gates passed |
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
| Wallet, v1 | ✅ | ✅ | ✅ | — | — | — | Error handling reviewed (wallet-review.md); W-5 open |
| ZK proof system configuration (BS-ZK-2, Plonky3 0.7.0 with 3 patches) | ✅ | ✅ | ✅ | — | — | — | Critical review area 2 |
| BVM-1 zkVM circuits | ✅ | ✅ | ✅ | — | — | — | Critical review area 3 |
| PX kernel, records, `Hk` | ✅ | ✅ | ✅ | — | — | — | Critical review areas 1 and 4 |
| PX consensus integration | ✅ | ✅ | ✅ | — | — | — | Critical review area 5 |
| Record delivery (hybrid KEM) | ✅ | ✅ | ✅ | — | — | — | Review area 6 |
| Contract-record distribution, sealed shares | ✅ | ✅ | ✅ | — | — | — | docs/px.md §13 |
| Vault contract | ✅ | ✅ | ✅ | — | — | — | **Demonstration only:** no timeout, no refund, not trustless |
| Wallet, PX and contracts | ✅ | ✅ | ◐ | — | — | — | Review area 8 |
| Transparent contract engine (wasmi) | ✅ | ✅ | ✅ | — | — | — | **Not integrated into the chain** (milestone M3, chain integration, not done); not in the testnet |

**No component has reached L4.** So none is ready for testnet evaluation (L5) under
the owner's rule that the independent review comes first.

## 3. Work remaining before the testnet

Each item carries one of the report classifications.

| # | Item | Status |
|---|---|---|
| 1 | Independent security review (docs/reviews/review-package.md) | **Not implemented:** not started; needs the owner to engage a reviewer |
| 2 | Resolve the review's findings, then re-run the suite, the fuzzing and the rehearsal | **Blocked** on 1 |
| 3 | CI running on GitHub, all jobs green | **Partially implemented:** hardened and pushed 2026-09-25; it had never run before. Results of the first run go into AUDIT.md |
| 4 | Extended contract-engine fuzzing | **Partially implemented:** runs in progress (AUDIT.md when finished) |
| 5 | Reorg-depth policy (assumptions.md K4) | **Complete but awaiting independent review:** no limit, a warning at 10 blocks, deepest reorg tracked (docs/consensus.md §8). Owner may revise; mainnet revisits limits or checkpoints |
| 6 | Multi-node adversarial tests: a malicious peer sending valid-looking but conflicting PX transactions across a partition; a deep reorg across PX deposits and withdrawals | **Partially implemented:** the single-node and two-node cases are tested; labnet reorgs up to depth 17 with PX traffic |
| 7 | Real multi-machine tests (docs/testnet.md §7) | **Not implemented:** after the review, with approval |
| 8 | Recovery, restart, reorg and reset tests on real machines | **Partially implemented:** restart rebuild (one node) and the reset rehearsal (one machine) |
| 9 | Partition tests between real machines | **Partially implemented:** simulated only (labnet proxy) |
| 10 | Supply and private-state consistency under long runs | **Partially implemented:** checked by labnet (62 min, 5 processes); a 72-hour run is required by docs/testnet.md §7 step 7 |
| 11 | Wallet error handling (clear messages for node errors, rejected transactions, insufficient private funds, stale anchors) | **Complete but awaiting independent review** (docs/reviews/wallet-review.md): four findings fixed, including two high privacy issues (W-1, W-2: re-spending an input with a new ring). Open: W-5 (ring reuse), friendlier messages |
| 12 | Documentation of every genesis-affecting change | **Complete but awaiting independent review:** docs/testnet-reset-plan.md §2 |
| 13 | Launch checklist and rollback plan | **Partially implemented:** reset plan §4–§6. A single checklist for the day, with named owners per step, is still to be written |
| 14 | Cross-platform determinism (Linux, ARM64) | **Not implemented:** Linux comes with the first CI run |
| 15 | Dandelion++ parameters for BlackSilk's network size (assumptions.md N4) | **Deferred:** needs testnet measurements |
| 16 | Plonky3 anonymous report | **Complete but awaiting approval:** not submitted |
| 17 | Contracts beyond the vault; transparent-contract chain integration (M3) | **Deferred** |
| 18 | Proof size (~2 MB; ~4 PX transactions per block) | **Deferred:** aggregation-study.md |
