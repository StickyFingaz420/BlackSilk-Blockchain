# Phase 2 implementation waves (DRAFT; finalized after dossiers 24 and 41–50)

## Rules

- **Parallelism:** at most 3 building agents at a time (revised: the machine is a 4-core / 8-thread i7-6700 with 16 GB RAM); each agent uses its own `CARGO_TARGET_DIR` and `CARGO_BUILD_JOBS=2`. Target dirs are deleted after merge.
- **Branches:** each agent works in a worktree on a temporary branch from the current `rebuild/core` tip. The coordinator reviews and merges, re-runs the affected suites, and deletes the worktree and branch.
- **Security-critical items:** each goes through research, implementation, regression test, adversarial test, integration test and final review. The red team (50) reviews every consensus diff.
- **Consensus changes:** each carries the 15-step record, either in `docs/reviews/v3-consensus-changes.md` (one section per change) or in the commit.
- **File ownership:** only the owning agent writes a file during a wave. Shared files (`validate.rs`, `manager.rs`, `wallet.rs`, `net.rs`, `node/src/lib.rs`, `fingerprint.rs`) are changed in sequence. Final ownership comes from 46's map.

## Wave 0: prerequisites (mostly mechanical or test-only)

- **46:** split `net.rs` into modules. Pure moves; the diff must be moved code only.
- **03 W1:** `tools/daa-sim` harness. Reproduces F1 against the real `next_difficulty`.
- **05 C1 + C10:** RandomX vector 1f; doc truth.
- **Test-only vector packs** (no source change):
  - 15 W3 (CLSAG vectors);
  - 16 BPP-3 (BP+ vectors);
  - 17 item 1 (stealth vectors);
  - 19 item 2 (Hk vectors);
  - 01 item 2 (a negative test per block rule);
  - 11 I1 (tx golden corpus; frozen later).
- **34 Stage 0:** liveness tests L1–L6. L1, L3 and L4 are expected to fail today and are marked `#[ignore = "fails until Stage 1"]`.

## Wave 1: v3 consensus bundle (sequenced, heavy review)

- **CB-A, consensus crate:**
  - 03 W2 rise cap, with R chosen by the harness;
  - 01 F-05 reorder;
  - big-endian guard;
  - 40 `genesis.rs` (`GenesisSpec`, `Beacon`, `genesis_is_final`);
  - `ChainParams::check`.
- **CB-B1, tx rules:**
  - D8 option B, plus the wallet key-image dedupe;
  - CLSAG D ≠ identity;
  - exact v1 fee;
  - R12-2 (a′);
  - tree-capacity rule, together with 21-D (tree root at capacity);
  - 10 early PX proof decode (policy only).
- **CB-B2, PX kernel and call ABI:**
  - F-20-1 `ApprovalConflict`;
  - `ABI_VERSION` and `out_words` registry;
  - PX6 validity window;
  - vault changes (contract id in the lock hash, timeout and refund);
  - 43 does the ONE kernel and vault rebuild, and 20 re-measures the budgets.
- **CB-B3, zk:**
  - exact `NUM_RANDOM_CODEWORDS` per hidden opening (22 W2 = 26 ZP-7);
  - 25 W1 params fix;
  - 27 W6 deterministic grinding (policy only);
  - AIR digest tied to `CIRCUIT_ID` (22 W4, 23 W2).

## Wave 2: P0 policy work (parallel where the files are disjoint)

- **12:** ring-digest revalidation, readmission, stateful test, expiry with the recently-expired guard.
- **07:** `SeedCache`, shared `worth_verifying` in `chain/src/sync_policy.rs` (with 31 S1).
- **34:** Stage 1 (slow lane, summary snapshot, RPC off-lock PoW, RPC semaphore).
- **36:** RPC guard, serve limits, cookie auth, `/block` gate, `/tx/status`.
- **30:** pre-`Verack` cap, no ban on decrypt failure, transport version in the KDF.
- **32:** W0 quick hardening, onion validation, new `Addr` format.
- **33:** privacy regression suite; originated-transaction set and persistence.
- **37:** seed v1 (27 words), derived hedge keys, key vectors.
- **21:** `ANCHOR_MIN_DEPTH`.
- **35:** refuse legacy stores; `blocks.dat` v2 typed records.
- **09:** labnet instrumentation, template readiness gate.
- **02:** reference model plus proptest.
- **04:** clock sanity and docs.
- **29:** freeze Wasm out of the workspace.
- **Docs:** P0 doc truth items, coordinated by 47.

## Wave 3: P1 (this phase)

34 Stage 2 (actor), then Stage 4; the transport v2 attempt; addrman v2; RX-presync design; storage S4–S7; wallet W1/W3/W4/W5; 39 W1; fuzz/property matrix (41); mutation testing (42); CI/reproducibility (43); supply-chain enforcement (44); benchmarks (45).

## Wave 4: freeze and evidence

- Fingerprint v3 (40, one commit); golden vectors and the proof freeze.
- Full suite; fuzz rerun with `-O -a`; mutation runs.
- RandomX full-mode miner across 2113.
- P-5 re-run; widest-proof and verifier-cost measurement.
- Labnet adversarial runs; supply audit with a PX pool.

## Wave 5: second threat-model round

Then a genesis rehearsal, and the final genesis procedure (the owner and a second operator are needed at the reveal).
