# Smart contracts: completion assessment

Status: **internal assessment, 2026-09-27. No external audit.** BlackSilk is **not**
complete while the Wasm contract system is not integrated; this document says what
exists and what remains.

## 0. Two contract systems

The repository has two contract designs, and they are at very different stages.

| | **PX private contracts** (docs/px.md §7, §13) | **Wasm confidential contracts** (docs/contracts.md) |
|---|---|---|
| Model | Contract functions are zkVM (RISC-V) programs proven with the PX kernel. State and calls are private; only the program id and the number of calls are public | WebAssembly code executed by every node (wasmi). Ring-anonymous callers, confidential (Pedersen) balances; code and key–value state are public |
| Consensus | **Active from genesis in testnet v2** (kinds 2 and 3, the PX deploy registry) | **Not in consensus.** No transaction kind, no state root in blocks, no activation height |
| What exists | Kernel, function binding, registry, wallet commands, delivery, record sharing; one **demonstration** contract (the vault) | Crypto (M1), engine and state (M2); no chain integration (M3), no SDK or example contracts (M4), no wallet or RPC (M5), no calibration (M6) |

**A spec conflict to resolve first.**
- docs/contracts.md §5 assigns transaction **kinds 2 and 3** to Wasm calls and
  deploys.
- The PX transaction and the PX deploy took kinds 2 and 3 in consensus.
- Integrating the Wasm system therefore needs new kind numbers (for example 4 and 5)
  and a revised spec.
- This is a design decision for the owner, together with whether both systems should
  exist at all.

## 1. What is implemented

- **PX private contracts:**
  - consensus rules PX1–PX5 and the deploy registry (px.md §11);
  - kernel function binding (approve and specify, `io_hash`);
  - up to 2 functions per transaction;
  - budgets fixing each function's proof shape;
  - on-chain delivery and off-chain sealed shares of contract records;
  - wallet `px-deploy`, `px-contracts`, `px-records`, `px-share`, `px-import`, and the
    vault commands.
  - **Tested:**
    - consensus: `a_private_contract_is_deployed_and_used_through_consensus`;
    - end to end over RPC:
      `a_vault_is_deployed_locked_delivered_shared_and_claimed_over_rpc`;
    - mutation tests of the kernel and function binding;
    - fuzz targets: `kernel_diff` and `zkvm_elf`.
- **Wasm contracts (`contracts/`, not wired to the chain):**
  - the module profile check;
  - the wasmi `=0.38.0` executor with fuel;
  - 31 host functions;
  - cross-contract calls with depth and reentrancy limits;
  - state with key–value entries, notes, key sets and deduplicated code;
  - atomic diffs with per-block undo;
  - a sparse-Merkle state root;
  - M1 cryptography: Schnorr kernel and auth signatures, scoped linkable ring
    signatures, range, equality and reveal claims.
  - **Tested:**
    - 29 engine and state tests, including determinism across two engines with a
      pinned fuel count;
    - fuzz targets `wasm_module` and `contract_sequence` (6 h and 4 h, 0 crashes;
      AUDIT.md);
    - crypto known-answer and adversarial tests.

## 2. What is demonstration code only

- **The vault** (`px/src/vault.rs`, `zkvm/guests/vault`): a hash-lock with no timeout,
  no refund, and a locker who can also claim. It is not trustless, not a swap, and
  not suitable for real value.
- Nothing in the Wasm system is reachable from a node.

## 3. What remains, by area

| Area | PX private contracts | Wasm contracts |
|---|---|---|
| **Consensus integration** | Done. Open design items: PX-F4, PX-F5 (px-f4-f5-analysis.md) | All of M3: new kind numbers; K/X/KB validation rules; coinbase v2 with `state_root`; activation (height or reset); block-level ordering of calls |
| **Deployment and execution** | Deploy and registry done. **Missing:** an SDK for writing function programs (only hand-built guests), and tooling to compute budgets | A deploy path, a call builder, host bindings (SDK), and the 5 example contracts (M4) |
| **Fees and resources** | Exact PX fee (consensus); fixed proof shapes; the 8 MiB PX block budget. ZK-F4 (verifier cost of adversarial proofs at the largest budget) is unmeasured | Fuel schedule pinned but **not calibrated**; storage accounting implemented but not priced; block fuel limit and fee formulas provisional (contracts.md §12) |
| **State persistence and rollback** | Registry and records follow reorganizations (tested at depth 1–3; labnet to depth 17). All PX state is rebuilt by replay at restart (PX-F3; slow for large chains) | The in-crate undo is tested. It is not connected to the chain manager, the store or restart |
| **Privacy** | Statistical zero knowledge, conditional (zk-coverage.md). Public: program id, number of calls, timing (privacy-review.md P-8). PX-F4 affects multi-party contracts' openings, not privacy | Designed (contracts.md §15): public code and state, anonymous callers, confidential balances. **Not re-reviewed** against the PX system now in consensus |
| **Deterministic execution** | Proven execution: determinism is what the proof checks | wasmi interpretation, no floats or SIMD; golden fuel test; differential between two engine instances. **No cross-platform test** and no second implementation |
| **Security testing and fuzzing** | Kernel differential fuzzing, mutation tests, internal reviews rounds 1–4 | Fuzzing of module parsing and call sequences; **no** chain-level adversarial tests (none possible before integration); wasmi's internal `unsafe` not reviewed by us (relies on its external audit) |
| **Wallet and RPC** | Done for the vault; general contract calls need per-contract host code | M5 not started |

## 4. What a genuine v1 release requires

- **Decide the scope:** PX private contracts only, or both systems. If both, renumber
  the Wasm kinds and revise contracts.md §5.
- **PX contracts:**
  - PX-F4 B and PX-F5 B (a kernel change);
  - a function-program SDK and budget tooling;
  - at least one non-demonstration contract with a timeout and refund (an escrow);
  - the ZK-F4 measurement and budget caps;
  - documentation of the multi-party trust model.
- **Wasm contracts, if kept:** M3 to M6 of contracts.md §19, each ending green, with
  reorg and restart tests on contract state, fee calibration, labnet with contract
  traffic, and a privacy review of the combined system.
- Internal review passes for the contract components (review-status.md §3). External
  review is not a gate (owner decision), but it is recommended before value is at
  stake.

## 5. Required before the private testnet trial, and what can wait

**Required before the seven-device trial:**
1. Your decision on PX-F4 and PX-F5, and therefore on whether the kernel changes
   before the trial (px-f4-f5-analysis.md §5).
2. User documentation stating that:
   - the vault is a demonstration: no timeout, no refund, not trustless;
   - multi-party contract state depends on the caller delivering openings (PX-F4);
   - Wasm contracts are not part of the testnet.
3. Nothing else. The trial does not need the Wasm system, which is not consensus and
   cannot be reached from a node.

**Safe to defer until after the first controlled testnet:**
- all of Wasm M3 to M6, and the kind-number and scope decision (needed before M3
  starts);
- the function SDK, budget tooling and a production escrow contract;
- fee calibration for contracts;
- the combined privacy review.
- Activating any new contract consensus design requires your explicit approval and a
  new testnet identity or activation height.

**The project should not be called complete** until the scope decision is made, and
either the Wasm system is integrated and tested or it is removed from scope.
