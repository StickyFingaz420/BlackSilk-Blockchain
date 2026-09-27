# R7: Smart-contract strategy and implementation review

**Reviewer:** R7 (senior reviewer, internal).
**Date:** 2026-09-27.
**Commit:** `rebuild/core` @ `f677e55`.
**Status:** internal review, not an audit. Read-only: no files changed and no builds run.

**Scope:**
- **PX private contracts:**
  - `px-core/src/{call,kernel,record}.rs`;
  - `px/src/{prove,vault}.rs`;
  - `zkvm/guests/vault`;
  - `tx/src/{px,validate,state}.rs` (registry and PX3/PX5);
  - `wallet/src/px.rs` (anchor policy);
  - `zkvm/src/program.rs` (ELF loading).
- **Wasm confidential contracts:**
  - `contracts/`;
  - `docs/contracts.md`;
  - `crypto/src/{schnorr,membership,claims}.rs`, checked only for who uses them.
- **Documents:**
  - docs/px.md;
  - docs/reviews/contracts-completion-assessment.md;
  - px-f4-f5-analysis.md;
  - privacy-review.md (P-8).

**Evidence tags:**
- **[math]:** mathematically established;
- **[test: name]:** tested, with the test's name;
- **[src]:** read in the source;
- **[assumed]**;
- **[unknown]**;
- **[web]:** an external source, cited in §10.

---

## 0. Executive summary

1. **Recommendation: converge on PX as BlackSilk's single contract platform. Remove the
   Wasm confidential-contract system from the v1 scope.** Keep `contracts/` as frozen
   research, out of the default workspace build. Do not renumber its kinds and do not
   integrate it. Revisit it only if, after the testnet, there is proven demand for
   shared public state that PX cannot serve.
   - If that demand appears, the Wasm engine is worth reviving in one form only: as a
     **public "finalize" phase attached to PX calls** (Aleo's model). It should never be
     a second, parallel contract system with its own value layer.
2. **The main reasons:**
   - **Anonymity set.** The Wasm design ties callers to the v1 1-of-16 ring anonymity
     set, with public code, public state, public call input and linkable note
     consumption. PX gives full-set anonymity through nullifiers, private state, and
     hash-based ownership that survives a quantum adversary.
   - **Tiers of privacy.** Running both creates two privacy tiers. It also splits
     users, liquidity and anonymity sets.
   - **Consensus cost.** It roughly doubles the consensus attack surface:
     - a second VM whose pinned wasmi has about 120 internal `unsafe` blocks;
     - a state root in the coinbase;
     - fuel calibration;
     - re-execution DoS in the mempool (S12);
     - MEV exposure of public state.
   - **The owner's priorities.** Both of the above conflict with the stated order:
     privacy first, security second, maintainability.
3. **What PX needs before it is a real contract platform, as opposed to a single
   demonstration vault.** Four protocol-level gaps block most useful contracts. These are
   new findings; the existing assessment does not list them:
   - **R7-1 (high):** functions cannot see block height or time, so **no timeout, refund,
     HTLC, vesting or auction deadline can be written**. The vault's missing timeout is a
     platform limitation, not a demonstration shortcut.
   - **R7-2 (high):** there is no authorization primitive except a shared secret in the
     prover's witness. Multi-party authorization (escrow arbiter, k-of-n) is impossible
     without sharing secrets.
   - **R7-3 (medium):** the two functions of a transaction cannot see each other. There
     is no verified cross-contract message, so no composability.
   - **R7-4 (high, scalability):**
     - a shared contract-state record can be updated at most once per block by
       consensus, and in practice once per 16 blocks (about 32 min) under the wallet's
       canonical-anchor policy;
     - the whole chain carries about 3–4 PX transactions per block;
     - shared-state applications (AMMs, order books, registries) are therefore not viable
       on PX until aggregation exists.
4. **Economics and auditability:**
   - **R7-5 (medium):** the deployer chooses a registered budget freely, up to 2^22 rows
     per table, while the PX fee is flat. So the fee does not price verifier or prover
     cost. This deepens ZK-F4.
   - **R7-8 and R7-9 (medium):** users cannot audit what a contract does or reveals.
     Contracts are opaque ELFs, public outputs are up to 256 uninterpreted words, and
     there is no manifest, no source link and no reproducible build.
5. **Minimal safe path (§8):**
   - Nothing consensus-related before the seven-device trial; documentation only.
   - Then **bundle every kernel-statement change into the already-planned v3 genesis**:
     PX-F4 B, PX-F5 B, a validity window for functions (R7-1), a budget cap with fee
     classes (R7-5), and the platform-neutral kernel rebuild. This avoids a second reset.
     Also add a kernel-id-by-height schedule, so that later kernel changes need an
     activation height rather than a new genesis.
   - The SDK, ABI, manifest, test harness and generic wallet client come after, as
     tooling with no consensus impact.
   - Cross-contract messages and escrow/HTLC come next. Aggregation or recursion is the
     gate for shared-state applications and for hiding which function ran.

---

## 1. What exists (verified)

### 1.1 PX private contracts

| Item | Status | Evidence |
|---|---|---|
| Contract records (`contract ≠ 0`, `owner = 0`), a contract nullifier depending only on the opening | Complete and verified | [src] px-core/src/record.rs:190-200; kernel.rs:323-325 |
| Function binding: a hiding `io_hash` over approvals, output specs and `blind`; the kernel recomputes it from the actual commitments | Complete and verified | [src] call.rs:53-80, kernel.rs:308-321, 356-385; [test: `px/tests/unified.rs`, 12 rule violations native = guest] |
| Registry: `(contract, program_id) → budget`; PX3 checks registration, PX5 verifies with the registered budget | Complete and verified | [src] validate.rs:427-431, 437-455; state.rs:273-283; [test: `a_private_contract_is_deployed_and_used_through_consensus`] |
| Fixed proof shape per program (budget) | Complete and verified | [src] prove.rs:118-140; [test: `budgets_leave_headroom`] |
| At most 2 functions per transaction; 2 inputs and 2 outputs in total | Complete (a design constant) | [src] call.rs:30, kernel.rs:53-54 |
| Delivery and sharing of contract records | Complete, but requires further testing (PX-F4 trust) | docs/px.md §13; [test: `a_vault_is_deployed_locked_delivered_shared_and_claimed_over_rpc`] |
| Guest SDK | Partially implemented: 4 syscalls (`read`, `write`, `halt`, `poseidon2`) | [src] zkvm/sdk/src |
| Contract SDK, ABI, manifest, generic wallet client | Not implemented | px.md §13.4.1: each contract needs hand-written host code |
| Time or height inside functions | **Not implemented** (R7-1) | [src] function public outputs are opaque to consensus: tx/src/px.rs:325-341; validate.rs has no rule over them |
| Cross-function or cross-contract messages | **Not implemented** (R7-3) | [src] io_hash is per function: call.rs:56-79 |

### 1.2 Wasm confidential contracts

| Item | Status | Evidence |
|---|---|---|
| Module profile, wasmi `=0.38.0` executor, host API, fuel, state, SMT, undo | Complete, but requires further testing (C-1 to C-5 open) | [src] contracts/src; 30 `#[test]`s (exec 18, fuzz 1, smt 5, state 3, types 3) |
| Schnorr, membership and claims crypto | Complete, with no consumer | [src] grep: no crate outside `crypto/` uses `schnorr::`, `membership::` or `claims::`; `contracts` does not verify facts itself (exec.rs:8-9) |
| Chain integration (M3), SDK and examples (M4), wallet and RPC (M5), calibration (M6) | Not implemented | contracts-completion-assessment.md §0 |
| Workspace membership | The crate builds and tests in CI, and wasmi 0.38 is in Cargo.lock, but no node, wallet or tx crate depends on it | [src] Cargo.toml:14; Cargo.lock:2751 |

---

## 2. The 13 questions, per subsystem

### 2.1 PX private contracts

| # | Answer |
|---|---|
| 1. Implemented | Kernel with function binding; registry; deploy; fixed shapes; delivery and share; the vault; wallet commands (§1.1). |
| 2. Correct and well-designed | See the list after this table. |
| 3. Incomplete | SDK and ABI; generic wallet client; budget tooling; any non-demonstration contract; time; authorization; composition (R7-1, R7-2, R7-3). |
| 4. Fragile | Every new contract needs hand-written host code that must reproduce the function's transcript exactly (`FunctionMismatch`), which is error-prone. Contract authors can leak through up to 256 free public output words (R7-8), and can make commitments guessable with a public-data `rcm` after PX-F4 B (px-f4-f5-analysis.md). |
| 5. Exploitable | Known: PX-F4 (griefing by withholding openings) and PX-F5 (burn). New: R7-5, a flat fee for deployer-chosen verification cost (DoS economics; severity bounded by the 4 MiB proof cap and ZK-F4, both unmeasured). |
| 6. Inefficient | Each function adds about 0.5 MB and about 9 s of proving (vault: 2.69 MB, ~53 s, against a 2.18 MB transfer, [measured, brief]). A deploy stores up to 1 MiB of ELF, permanently and in RAM (R7-11). |
| 7. Does not scale | Shared state (R7-4); 3–4 PX transactions per block chain-wide; 2 inputs and 2 outputs; 8 field elements of state per record (R7-7). |
| 8. Missing | Time; authorization; messages; SDK and ABI; manifest and reproducible builds; events (encrypted logs); an upgrade story; budget pricing. |
| 9. Redesign | The function public-output format: a structured header that consensus interprets (validity window, message commitments). The fee: budget classes instead of one flat fee. |
| 10. Innovate | PQ-friendly authorization inside functions: Poseidon2 hash-based one-time or few-time signatures (WOTS or XMSS-style) are cheap with the `POSEIDON2` syscall (R7-2). Hiding message commitments between functions (R7-3). Batch settlement in the Penumbra style for shared-state applications, later. |
| 11. Before the testnet | Documentation only (§8, phase 0). The kernel batch goes with the v3 genesis if the owner approves (phase 1). |
| 12. Deferrable | SDK, ABI and client (phase 2); messages, escrow and HTLC (phase 3); aggregation, function privacy and public finalize (phase 4). |
| 13. Never change | See §9. |

What is correct and well-designed (question 2):
- Hash-based ownership.
- The kernel stays small; functions carry the contract logic.
- Contracts approve the effects the caller declares.
- Functions are bound by one public `io_hash`.
- The registry is mandatory in `verify`.
- Fixed shapes stop trace-length leakage.
- Balance is checked in `u128`.
- Proofs are bound to `h_tx`.

### 2.2 Wasm confidential contracts

| # | Answer |
|---|---|
| 1. Implemented | M1 and M2 (§1.2). |
| 2. Correct | A deterministic profile; eager compilation; floats banned; no reentrancy; atomic failure; SMT root with a reference test; the approval and acceptance model. |
| 3. Incomplete | M3 to M6; everything that touches the chain. |
| 4. Fragile | The consensus pin on a third-party interpreter (fuel schedule, parser, stack limits). Upgrading wasmi is a consensus change. About 120 `unsafe` blocks inside wasmi 0.38 have not been reviewed. |
| 5. Exploitable (by design) | Public call input and state give front-running and MEV. Note creation and consumption are linkable. Anonymity is only 1 of 16, against v1 decoy-selection analysis. Re-execution DoS in the mempool is S12 (the spec admits it as a residual risk). |
| 6. Inefficient | Re-execution after every tip change (§13 of the spec). |
| 7. Does not scale | Sequential execution; per-contract re-execution caps. |
| 8. Missing | See question 3. |
| 9. Redesign | If ever revived: only as a public finalize over PX, with no separate value layer (§6). |
| 10. Innovate | Scoped membership (linkable ring signatures with a common base) is useful. It could be re-expressed in PX as contract-scoped tags: a function outputs `Hk(TAG, scope, member_secret)` and consensus keeps a per-contract set of used tags. This is PQ and full-set, whereas the Wasm version is 1 of 16 over Ristretto. |
| 11. Before the testnet | Nothing. Mark it out of scope in the docs. |
| 12. Deferrable | All of it. |
| 13. Never change | Nothing here is in consensus, so nothing is frozen. |

---

## 3. New findings

Known items (PX-F4, PX-F5, C-1 to C-5, ZK-F4, "deploys act as cheap transfers", "approval
not tied to value accounting", raw-u32 output words) are not re-reported. Where this
review deepens one, it says so.

### R7-1: functions cannot observe block height or time, so time-dependent contracts cannot be written

- **Severity:** high (platform capability).
- **Classification:** not implemented.
- **Where:**
  - `px-core/src/kernel.rs:216-395`: the witness has no height, and the public
    statement carries only the anchor;
  - `tx/src/px.rs:325-341`: function outputs are decoded as opaque words;
  - `tx/src/validate.rs:414-475`: no rule reads them;
  - the vault guest: no time input.
- **Scenario:**
  - An HTLC's refund path must hold "after height H, the locker may reclaim". A function
    receives only its private input, and the prover controls that input, so it can
    claim any height. Nothing public binds the function to the chain height.
  - The anchor does not help either. The function does not see the kernel's anchor, and
    an anchor is a Merkle root, not a height.
  - So refunds, deadlines, vesting, auctions with closing times and HTLC swaps are
    impossible, not merely unimplemented. The vault's "no timeout" (px.md §13.4) is
    presented as a limitation of the demonstration, but it is a limitation of the
    platform.
- **Confidence:** high [src].
- **Recommendation:** a **validity window in the function ABI.**
  - Every function's public output after `io_hash ‖ contract` starts with
    `[not_before, not_after]` (u32 heights; `0` and `u32::MAX` mean unbounded).
  - Consensus rejects the transaction unless
    `not_before ≤ block_height ≤ not_after` for every function.
  - A refund function asserts `not_before ≥ deadline` (a value from its record data).
    A claim function asserts `not_after < deadline`.
  - Mempool and templates drop transactions outside the window. This also partly
    addresses the known "no mempool expiry".
- **Recommendation details:**
  - **Why:** without it, no contract more useful than a hash lock exists.
  - **Security:**
    - positive: it makes trustless swaps and refunds possible;
    - risk: reorg edge cases, standard as for Zcash `nExpiryHeight`;
    - the function must use the window only through the public output.
  - **Privacy:**
    - windows are public and can fingerprint;
    - the SDK should use standard windows (for example `[anchor_height, anchor_height + 64]`) unless a deadline requires otherwise;
    - a refund reveals its deadline bucket, which is inherent and acceptable if bucketed.
  - **Performance:** negligible.
  - **Complexity:** low.
  - **Consensus:** **CONSENSUS** (a new rule over function outputs; the kernel is
    unchanged if the window is function-level).
  - **Identity:** a new identity, or an activation height; bundle with v3.
  - **Difficulty:** S–M.
  - **Priority:** P1, with the v3 bundle.

### R7-2: no authorization primitive except knowing a secret

- **Severity:** high (platform capability and safety).
- **Classification:** not implemented.
- **Where:**
  - `px-core/src/kernel.rs:308-321`: a function approves by commitment only;
  - it never sees the owner or key of user inputs;
  - the vault authorizes by the hash preimage `secret`.
- **Scenario:**
  - A 2-of-3 escrow (buyer, seller, arbiter) must require two parties.
  - The only way a function can check a party is a secret in the **prover's** witness.
    One prover would then need two parties' secrets, which means sharing them, which
    destroys the model.
  - The same holds for "only the beneficiary may withdraw", unless the beneficiary is
    the prover and the secret sits in the record, as in the vault.
  - The Wasm design solved this with auth keys and Schnorr. PX has no equivalent.
- **Confidence:** high [src].
- **Recommendation:**
  - **(a) Short term, SDK-level, no consensus change:**
    - *approval records*: a party authorizes by creating a contract record of kind
      "approval(action_hash)", which the acting transaction consumes;
    - it costs one transaction per approving party, but works today.
  - **(b) Medium term:** a Poseidon2-based few-time signature (WOTS+ or XMSS-style)
    verified inside the function.
    - Keys are `Hk`-derived per contract and role, as in contracts.md §14.2.
    - It is post-quantum and needs no new assumption beyond `Hk`.
    - It costs about several hundred Poseidon2 calls per signature. **[unknown]**
      Measure against budgets.
- **Recommendation details:**
  - **Why:** multi-party contracts are the point of contracts.
  - **Security:** (a) is sound by construction; (b) needs its own review.
  - **Privacy:** keys are fresh per contract and role, and are revealed only inside the
    proof.
  - **Performance:** (b) adds prover rows.
  - **Consensus:** none for either (both are function logic).
  - **Identity:** none.
  - **Difficulty:** (a) M; (b) L.
  - **Priority:** P2.

### R7-3: the two functions of a transaction cannot communicate

- **Severity:** medium.
- **Classification:** not implemented.
- **Where:** `call.rs:56-79` (the transcript is per function); `prove.rs:118-140`.
- **Scenario:**
  - Contract A (a token) wants to pay only if contract B (an order) agreed on the price.
  - Both functions can run in one transaction, and the kernel's balance makes them
    atomic. But A cannot verify anything B computed.
  - "Co-inclusion" gives atomicity, not composition.
- **Confidence:** high [src].
- **Recommendation:** **hiding message commitments.**
  - A function may output, in its structured header, `sent = [m_1..]` and
    `received = [m'_1..]` with `m = Hk(MSG, from ‖ to ‖ payload ‖ blind_m)`.
  - Consensus requires the multiset of sent messages to equal the multiset received
    within the transaction, with `from` and `to` checked against the calling contracts.
  - The content stays private; only the fact that A and B exchanged a message is public,
    and that is already visible from which contracts were called.
  - This is the "call stack hash" idea of Aztec's private kernel, done at the
    transaction level without recursion [web: Aztec circuits].
- **Recommendation details:**
  - **Security:** needs a careful domain separation of `from` and `to`.
  - **Privacy:** neutral.
  - **Performance:** a few hashes.
  - **Consensus:** **CONSENSUS**.
  - **Identity:** yes, or an activation height.
  - **Difficulty:** M.
  - **Priority:** P3. It is not needed before contracts exist that want it, and
    `MAX_FN = 2` allows only one edge.

### R7-4: shared contract state is throughput-bounded

- **Severity:** high (scalability).
- **Classification:** accepted limitation (architectural) until aggregation.
- **Where:**
  - `px/src/state.rs:26` (the root window);
  - px.md §5: anchors never refer to the current block;
  - `wallet/src/px.rs:54-58`: `ANCHOR_INTERVAL = 16`;
  - brief: about 3 PX transactions per 8 MiB block;
  - PX-F4 (openings must be delivered to every participant).
- **Scenario:**
  - A contract whose state is one record (a pool, a DAO treasury, a counter) can be
    updated only by a transaction whose anchor already contains that record.
  - Under consensus, that means at most once per block.
  - Under the wallet's privacy-preserving policy, the anchor is a height that is a
    multiple of 16, so at most once every 16 blocks (about 32 min).
  - Two concurrent users collide on the nullifier; the loser has spent about 50 s
    proving for nothing and must also learn the new opening.
  - Chain-wide, every contract call competes for about 3–4 PX slots per 2-minute block.
- **Consequence:**
  - PX is viable for **bilateral and UTXO-style** contracts: escrow, HTLC, vesting,
    vaults, private voting with tags, sealed bids.
  - It is **not viable** for AMMs, order books or shared registries, and the platform
    documentation should say so.
- **Confidence:** high [src], [math] for the bounds.
- **Recommendation:**
  - Document it now (P0 documentation).
  - Architectural fixes, all P3:
    - aggregation (docs/reviews/aggregation-study.md);
    - later, a Penumbra-style **batch settlement** primitive, in which users burn inputs
      into a per-block batch and the net flow is computed publicly [web: Penumbra];
    - or an Aleo-style public finalize (§6).

### R7-5: deployer-chosen budgets up to 2^22 rows, under a flat fee

- **Severity:** medium.
- **Classification:** partially implemented. It deepens ZK-F4 and "deploys act as cheap
  transfers".
- **Where:**
  - `tx/src/px.rs:129-145`: each budget field is bounded only by
    `1 << MAX_LOG_HEIGHT = 2^22` (zk/src/params.rs:74);
  - `tx/src/px.rs:679-683`: every PX transaction pays exactly `PX_STANDARD_FEE`;
  - `zkvm/src/lib.rs:37`: `MAX_CYCLES = 2^21`.
- **Scenario:**
  - An attacker deploys a function with a near-maximal budget for about 0.02 BLK.
  - Each call pays the same 0.089 BLK as a 25k-cycle transfer. The PX byte budget still
    caps count and size, and `MAX_PROOF_BYTES` (4 MiB) caps the proof.
  - But the verifier works on tables of 2^21–2^22 rows through logarithmic-depth FRI
    openings, and the honest prover of such a function needs far more than today's
    3.8 GB peak.
  - The verifier cost at the largest shapes is exactly ZK-F4, and it is unmeasured.
  - Whether one such proof fits in 4 MiB is unknown. If it does not, the function is
    uncallable, which is a liveness problem for its users, not a DoS.
- **Confidence:** medium. The code facts are [src]; the cost magnitude is [unknown].
- **Recommendation:**
  - **Consensus caps on registered budgets:**
    - set a maximum per table and a maximum total, from ZK-F4 measurements;
    - reject at deploy, where the deploy fee also prices the ELF bytes.
  - **Fee classes:** replace the single standard fee by a small set of fee classes keyed
    by the summed budgets of the called programs.
    - This leaks nothing new: the program ids are already public (P-8), so the class is
      derivable.
    - It keeps "same fee for the same shape", which is the privacy property that
      matters.
- **Recommendation details:**
  - **Security:** closes a pricing gap.
  - **Privacy:** neutral.
  - **Consensus:** **CONSENSUS**.
  - **Identity:** v3 bundle.
  - **Difficulty:** S (caps); M (classes).
  - **Priority:** P1 for the caps, P2 for the classes.

### R7-6: duplicate program ids in one deploy; the first budget wins

- **Severity:** low.
- **Classification:** complete but requires further testing.
- **Where:**
  - `tx/src/state.rs:273-283`: `find` returns the first match;
  - `tx/src/px.rs:506-532` and `check_deploy_structure`: there is no duplicate check.
- **Scenario:**
  - A deploy registers the same ELF twice with budgets b1 and b2. Verifiers always use
    b1.
  - A wallet that picks b2 from `/px/contracts` builds proofs that fail PX5: a liveness
    confusion, not a soundness issue.
- **Confidence:** high [src].
- **Recommendation:**
  - Reject duplicate program ids at deploy.
  - **Consensus:** CONSENSUS, trivial; v3 bundle.
  - **Difficulty:** S.
  - **Priority:** P2.

### R7-7: two inputs, two outputs and 248 bits of state per record limit contract shapes

- **Severity:** medium (design).
- **Classification:** accepted limitation, to be documented.
- **Where:**
  - `kernel.rs:53-54` (`N_IN = N_OUT = 2`);
  - `record.rs:140-148` (`data: [u32; 8]`, each element < p).
- **Scenario:**
  - "Consume state and a user payment, write the new state, a payout and change" needs
    3 outputs.
  - Swapping or crediting with change is impossible in one transaction, so it must be
    split, which costs another ~50 s proof and adds linkability.
  - Richer state needs a hash commitment in `data`, with the preimage delivered off
    chain, which adds to the PX-F4 delivery burden.
- **Confidence:** high [src].
- **Recommendation:**
  - The SDK should offer a "state = `Hk` of a larger struct" pattern, with delivery.
  - Consider `N_OUT = 3` or 4 only together with aggregation, because it increases
    kernel rows for every transaction.
  - **Consensus:** CONSENSUS if changed.
  - **Priority:** P3.

### R7-8: function public outputs are an unconstrained leak channel

- **Severity:** medium (privacy footgun).
- **Classification:** partially implemented.
- **Where:**
  - `tx/src/params.rs:33` (`MAX_FN_OUTPUT_WORDS = 256`);
  - `tx/src/px.rs:331-335`.
- **Scenario:**
  - A careless or malicious contract author publishes the amount, a recipient owner tag,
    or a secret-derived value in its public outputs. The vault publishes only its
    selector.
  - Users cannot tell before calling. Wallets show nothing.
  - Nothing distinguishes intentional public data (a selector, a window) from leakage.
- **Confidence:** high [src].
- **Recommendation:**
  - The ABI (§7.2) declares a typed public-output schema in the contract manifest.
  - The wallet displays "this call will publish: selector, window, …" and refuses
    contracts without a manifest, unless forced.
  - Consensus can cap the output words per registered program at deploy, as part of the
    manifest.
  - **Consensus:** policy; the optional cap is CONSENSUS.
  - **Difficulty:** M.
  - **Priority:** P2.

### R7-9: contracts are not auditable by their users

- **Severity:** medium.
- **Classification:** not implemented.
- **Where:**
  - a deploy carries raw ELFs (tx/src/px.rs:456-467);
  - px.md §4.3: reproducibility depends on the rustc version;
  - brief: the kernel ELF reproduces only on Windows.
- **Scenario:**
  - A user cannot verify which source produced a registered program, so a malicious
    deployer can publish "escrow" source that differs from the ELF.
  - In Aleo, programs are deployed as source-level Aleo instructions, which are
    inspectable [web: Aleo].
  - In Aztec, contract artifacts and class ids are published, and class registration
    commits to bytecode [web: Aztec].
- **Confidence:** high [src].
- **Recommendation:**
  - A **contract manifest** (§7.2) with the source hash, the toolchain id and a
    reproducible-build recipe (container-pinned, platform-neutral; shared with the fix
    for the kernel's reproducibility).
  - A `px-verify-contract` tool: build from source, compare program ids.
  - Optionally, commit the manifest hash into the deploy payload and so into the
    contract id: CONSENSUS if made mandatory; policy if it is only a registry-side
    annotation.
  - **Difficulty:** M.
  - **Priority:** P2.

### R7-10: the Wasm-only crypto has no consumer

- **Severity:** info.
- **Classification:** deferred.
- **Where:** `crypto/src/{schnorr,membership,claims}.rs`. Grep finds no user outside
  `crypto/`.
- **Implication:** the code is shipped and CI-tested but unreachable. If Wasm is dropped,
  move these modules behind a `contracts-research` feature or into `research/`, so that
  they do not appear in reviews as consensus crypto.
- **Consensus:** none. **Priority:** P3.

### R7-11: deploy state growth, quantified (deepens "deploys act as cheap transfers")

- **Severity:** medium.
- **Classification:** partially implemented.
- **Where:**
  - `tx/src/params.rs:19,22,24`: deploy ≤ 1 MiB; PX budget 8 MiB per block; 2 atomic
    units per byte;
  - `tx/src/state.rs:176-190`: every program is decoded and held in RAM, and re-decoded
    on replay (PX-F3).
- **Arithmetic** [math]:
  - Filling every block's PX budget with deploys costs about 16.8M atomic units, which
    is 0.17 BLK per block (`COIN = 1e8`, chain/src/emission.rs:4).
  - It adds 8 MiB of **permanent, un-prunable, RAM-resident** state per block.
  - At 720 blocks a day, that is about 5.6 GiB a day, or about 2 TiB a year.
- **Recommendation:**
  - Price deploy bytes like permanent state: at least 10× the transaction byte rate,
    which is the contracts.md §12 principle.
  - Deduplicate identical programs by id across contracts.
  - Load programs lazily.
  - **Consensus:** CONSENSUS (fee); the deduplication and lazy loading are none.
  - **Priority:** P1 (fee, in the v3 bundle) and P2 (deduplication and lazy loading).

### R7-12: the Wasm design would create a weaker second privacy tier

- **Severity:** high (strategic).
- **Classification:** design finding; deferred.
- **Where:** contracts.md §2, §15:
  - callers are 1-of-16 CLSAG;
  - code, key–value state, call input, access list, fuel and storage limits, and note
    consumption are public;
  - it is Ristretto-only, not PQ (§16.5).
- **Scenario:**
  - A user who interacts with a Wasm contract falls into the v1 anonymity set: ring 16,
    subject to the decoy-selection and chain-reaction analysis known from Monero.
  - A PX user is hidden among all PX records.
  - Every Wasm contract becomes a public meeting point (public state and linkable notes),
    and front-running is explicitly possible (§15.3).
  - The contracts.md §15 privacy analysis has not been re-reviewed against PX being in
    consensus (assessment §3).
- **Confidence:** high [src], [assumed] for the cross-tier attack magnitude.
- **Recommendation:** §6.

---

## 4. Strategic options

| | **A. Keep both** | **B. Integrate Wasm as the main platform** | **C. PX-only** | **D. PX-only now; optionally a public finalize later (recommended)** |
|---|---|---|---|---|
| **User privacy** | Two tiers; split anonymity sets; the weakest tier defines practical privacy for mixed users | 1-of-16 callers, public state, MEV | Full-set anonymity, private state, PQ ownership; leaks which contract and function ran (P-8) | Same as C. A later finalize would add public state explicitly, per contract, as the author's choice |
| **Developer experience** | Two SDKs, two mental models | Best: Rust to Wasm, a key–value store, a familiar model | Hardest: UTXO-style state, delivery, 2×2 slots, no time (until R7-1) | C plus an SDK and ABI that hide the kernel |
| **Performance and capacity** | Wasm calls: hundreds per block; PX: 3–4 per block | Hundreds of calls per block; cheap verification | 3–4 per block; ~50 s proving; ~2.5 MB per call | C until aggregation |
| **Auditability** | Wasm: code and state public, easy to audit; PX: opaque | Easy | Needs manifest and reproducible builds (R7-9) | Same, with the manifest |
| **Consensus complexity** | PX, plus kinds 4 and 5, a coinbase v2 state root, fuel, a second VM and a second value layer | Same as A in practice (PX already exists) | Existing | Small, targeted rules (window, messages, budget caps) |
| **Attack surface** | Largest: wasmi `unsafe`, fuel calibration, re-execution DoS, MEV, two value-conservation proofs | Large | Smallest | Small; grows only if the finalize is adopted |
| **Pure Rust / no unsafe** | wasmi adds ~120 unsafe blocks | Same | Clean | Clean |
| **Completion effort** | M3–M6 (XL) plus PX work | XL | L | L, phased |

**Why not B, even though it has the better developer experience and throughput.** The
project's first priority is privacy.
- A public-state, ring-16 contract layer is what the Secret, Aztec and Aleo designs
  explicitly move away from. Aztec and Aleo keep public state as an explicit, separate
  phase, not the default [web].
- Monero-style ring anonymity is also the weakest privacy component BlackSilk ships.

**Why not A.**
- It carries all of B's cost and C's cost.
- Worse, a user's privacy degrades to the tier of the least private counterparty they
  interact with.

**Why D rather than C.** D is C with an explicit door.
- **Public shared state has real uses:** liquidity, registries, governance tallies.
- **Where it would go:** if it is ever added, it should be a *per-contract public
  mapping updated by a finalize step* whose inputs are public outputs of a proven
  private function. This is Aleo's async/finalize model [web: Aleo], or Aztec's split
  into private functions (proven by the user) and public functions (executed by the
  sequencer in the AVM) [web: Aztec].
- **Why that form:** value never lives in the public layer. It stays in PX records, so
  conservation remains one kernel proof.
- **The engine:** the existing wasmi engine and SMT (`contracts/src/exec.rs`, `smt.rs`)
  are candidate building blocks for that finalize. The value layer of contracts.md
  (notes, the Mimblewimble kernel, BP+ claims, ring callers) should **not** be revived.

---

## 5. Comparison with other systems

| System | Execution model | What is public | Lessons for BlackSilk |
|---|---|---|---|
| **Zexe (Bowe et al., IEEE S&P 2020)** [web] | Records with birth and death predicates, proven under a "records nano-kernel"; function privacy through recursion | Only nullifiers and commitments. In the full scheme, not even which predicate ran | PX *is* a Zexe-style design without recursion. Function privacy (hiding P-8) needs recursion; that is the aggregation-study path. Zexe's "local data" commitment across predicates is the precedent for R7-3 |
| **Aleo** (snarkVM/Leo) [web] | Transitions proven client-side; an optional `async` finalize executes public mapping updates on chain; programs upgradable through a constructor with policies (`@noupgrade`, `@admin`, `@checksum`, `@custom`) since 2025 | Program id, function name, and public inputs and outputs of each transition; finalize arguments | Closest analogue to option D. Its upgrade design (a constructor fixed at deploy; an edition counter; only the newest edition executable) is a good template if upgrades are ever wanted. Aleo, like PX, reveals which function ran; BlackSilk is not behind the state of the art there |
| **Aztec** (Noir / Aztec.nr) [web] | Private functions proven on the user's device and folded by recursive private kernels, which hides which private functions ran; public functions run in the AVM by the sequencer; notes delivered through encrypted logs with **three delivery modes: offchain, onchain unconstrained, onchain constrained** (verified in circuit) | Public calls, public state, note hashes, nullifiers, logs | Two direct lessons. (1) Aztec's constrained delivery is PX-F4 option D, and Aztec considers it necessary when "the sender cannot be trusted to deliver", at the highest cost. PX-F4 option B plus SDK patterns covers the cheaper modes. (2) Function hiding needs recursion. Also: a mature SDK (Aztec.nr) with macros and state-variable types, which PX lacks |
| **Secret Network** [web] | CosmWasm contracts in SGX enclaves; encrypted state and inputs | Access patterns, which contract was called, gas | A TEE-based model: confidentiality depends on hardware. In 2022 the xAPIC and ÆPIC Leak disclosures allowed extraction of the consensus seed, which would enable retroactive decryption of all transactions (sgx.fail). Confirms the project principle "no trusted hardware"; never adopt a TEE model |
| **Penumbra** [web] | No general-purpose contracts: fixed-function private actions, including a DEX with **sealed-input batch swaps** (amounts encrypted to validators, only the net flow per block revealed, one clearing price) | Batch totals; public liquidity positions (opened anonymously) | Shared-state DeFi with privacy is done by **protocol-level batch primitives**, not by general contracts. This is the right model for R7-4, if ever needed. It also shows that a privacy chain can succeed without Turing-complete public contracts |
| **Zcash** [web] | No contracts. Zcash Shielded Assets (ZIP 226/227) add multi-asset transfer, burn and issuance in Orchard, targeted at NU7 | Issuance data; otherwise shielded | Conservatism: Zcash adds programmability in small, audited, fixed-function steps. PX's asset field (`asset = 0`, kernel-fixed) should follow the same path: a ZSA-like asset extension in the kernel, not contract-issued tokens first |

**Where BlackSilk stands, carefully stated.**
- PX's model (hash-based records, a fixed kernel, zkVM functions, one batch STARK) is
  architecturally in the Zexe, Aleo and Aztec family.
- It is behind all of them in tooling (SDK and ABI), time, authorization, composition
  and throughput.
- It is behind Aztec in function privacy.
- No claim of being "comparable", "competitive" or "first" is supported. Do not make one.

---

## 6. Recommendation

1. **Owner decision (requested):**
   - adopt **PX as the only contract platform** for testnet and v1;
   - declare the Wasm system **out of scope**: this satisfies the completion
     assessment's condition "integrated … or removed from scope";
   - no kind renumbering.
2. **Housekeeping (no consensus impact):**
   - mark docs/contracts.md "superseded research; not planned for v1";
   - remove `contracts` from the default workspace members, or keep it but exclude it
     from release builds;
   - keep its tests runnable manually;
   - move schnorr, membership and claims behind a feature (R7-10).
   - **Effect:** wasmi and its `unsafe` leave the release supply chain.
3. **Evolve PX into a platform** along §8, with the capability set of §7.
4. **Revisit public state after the testnet**, only with evidence of demand, and only in
   the finalize form (§4, D).

---

## 7. What a genuine v1 contract platform requires

Each item lists why it is needed, its security, privacy and performance impact, its
consensus impact, whether it needs a new testnet identity, its difficulty and its
priority.

### 7.1 Protocol capabilities

| Capability | Design | Security | Privacy | Performance | Consensus | Identity | Diff. | Prio |
|---|---|---|---|---|---|---|---|---|
| **Time** (R7-1) | Function validity window in the output header | Makes refunds sound | Bucketed windows | none | CONSENSUS | v3 bundle | S–M | P1 |
| **Opening determinism** (PX-F4 B) | The function fixes `rcm` | Removes the griefing channel | Needs a lint against public-derived `rcm` | none | CONSENSUS (kernel) | v3 | M | P1 |
| **Burn guard** (PX-F5 B) | The kernel forces owner = 0 on contract outputs | Closes the burn channel | none | none | CONSENSUS (kernel) | v3 | S | P1 |
| **Budget caps and fee classes** (R7-5, R7-11) | Caps at deploy; fee by budget class; deploy-byte price | DoS economics | none (ids already public) | none | CONSENSUS | v3 | S–M | P1 |
| **Authorization** (R7-2) | Approval-record pattern now; Poseidon2 few-time signatures later | Multi-party | Fresh keys per role | +rows | none | none | M / L | P2 |
| **Cross-contract messages** (R7-3) | Hiding message commitments, tx-level matching | Composition | Neutral | ~none | CONSENSUS | activation height | M | P3 |
| **Contract-scoped tags** (anonymous voting and claims) | A function outputs a tag; consensus keeps a per-contract used-tag set, like nullifiers | Double-vote prevention | Full-set anonymity; PQ | small state | CONSENSUS | activation height | M | P3 |
| **Events and logs privacy** | No public events. "Events" are encrypted to designated viewers (the delivery ciphertext format) or off-chain shares; public outputs only through the manifest schema | — | A public event log is exactly the leak to avoid (Aztec treats public logs as public) | — | none | none | M | P2 |
| **Upgradeability** | **v1: none** (immutable registry, as today; migrate through the contract's own functions). If needed later: Aleo-style edition counter with a policy fixed at deploy (`noupgrade` / `admin-key` / `checksum`), with a mandatory delay | Upgrades are the top rug-pull vector; immutability is the safe default | An admin key links deployments | none | CONSENSUS if added | activation height | L | P3 |
| **Kernel-id schedule** | `kernel_id(height)` in the params, so future kernel changes activate at a height | Avoids resets | none | none | CONSENSUS (mechanism) | v3 | S | P1 |

### 7.2 Tooling (no consensus impact, no new identity)

1. **`px-contract-sdk`** (`no_std`, riscv32), over `zkvm-sdk`:
   - typed `Record` and `State<T>`, with an `Hk` commitment for large state (R7-7);
   - a `Call` builder that makes it impossible to approve foreign records or specify
     foreign contracts (kernel errors turned into compile-time or type errors);
   - the output-header writer: `io_hash ‖ contract ‖ window ‖ messages ‖ typed public
     outputs`;
   - `rcm` derivation helpers after PX-F4 B, with a refusal to derive from public data;
   - authorization patterns (R7-2);
   - macros for selectors.
   - Difficulty M–L. P2.
2. **Contract ABI and manifest** (JSON or CBOR, hashed):
   - contract name and version;
   - functions: selector, private input schema, public output schema, window semantics;
   - record data schemas;
   - program ids and budgets;
   - source hash, toolchain id and build recipe;
   - who receives each output's delivery.
   - Difficulty M. P2.
3. **A generic wallet client** driven by the manifest. It replaces per-contract host code
   such as `px::vault`, and removes the `FunctionMismatch` fragility because the host
   and the guest share the SDK's transcript code. Difficulty L. P2.
4. **Testing tools:**
   - a **native simulator**: the same SDK code compiled natively, run with the native
     kernel (as px-core already does), for millisecond unit tests;
   - differential native-versus-guest runs (as `kernel_diff`);
   - a **budget tool**: `trace::usage` over a generated worst-case corpus, reporting
     headroom (px.md §13.4.1 step 2);
   - a negative-test generator for every kernel rule the contract depends on;
   - a slow-tier end-to-end proof test;
   - `cargo-fuzz` harnesses over function input decoding.
   - Difficulty M. P2.
5. **User auditability:**
   - `px-verify-contract`: reproducible build, then an id comparison (R7-9);
   - the wallet displays the manifest's public-output schema before every call (R7-8);
   - the wallet refuses unknown contracts unless forced;
   - platform-neutral reproducible builds, which also fix the kernel's Windows-only
     reproduction.
   - Difficulty M. P2.
6. **Reference contracts, each with abuse tests:**
   - escrow with timeout and refund, plus an arbiter using approval records;
   - an HTLC (enables atomic swaps with other chains that support hash locks);
   - vesting;
   - private voting with tags (once tags exist).
   - These replace the vault as the showcase. P2 (escrow and HTLC after R7-1).
7. **Documentation:**
   - the platform's capability envelope: bilateral and UTXO-style contracts only; no
     shared-state DeFi (R7-4);
   - the multi-party trust model (PX-F4);
   - what is always public (P-8).
   - P0 for the envelope statement.

---

## 8. Minimal safe path from today's code

**Phase 0: before the seven-device trial (documentation only; no consensus impact).**
- The items of assessment §5 (vault demonstration; PX-F4 trust; Wasm not in the testnet).
- Add to them:
  - "functions cannot see time; no refunds are possible yet" (R7-1);
  - "shared-state contracts are not supported" (R7-4);
  - "public function outputs are chosen by the contract author" (R7-8).
- Record the owner's scope decision (§6). **P0.**

**Phase 1: the v3 genesis bundle (CONSENSUS; the owner already chose a fresh v3 genesis for M1).**
- **What goes in:** one reviewed batch of kernel-statement and rule changes, so that
  contracts do not force a second reset:
  - PX-F4 B and PX-F5 B (kernel);
  - the function output header with a validity window (R7-1);
  - budget caps and a deploy-byte price (R7-5, R7-11);
  - duplicate-program rejection (R7-6);
  - the platform-neutral kernel rebuild (the new kernel id is a consensus change anyway);
  - the kernel-id-by-height schedule.
- **Process:** each item follows analysis, evidence, proposal, security review, tests,
  implementation and integration review, with explicit owner approval.
- **Fallback:** if the timeline cannot absorb the bundle, ship v3 with only the
  schedule mechanism and activate the rest at a height later.
- **Cost of skipping:** this is the single biggest risk-reduction in this report,
  because without it every later contract fix is a reset.

**Phase 2: tooling (no consensus impact).**
- SDK, ABI and manifest, simulator, budget tool, generic client, `px-verify-contract`.
- Port the vault to the SDK as the first consumer (its program id changes; that is a new
  deploy, not consensus).

**Phase 3: real contracts and composition.**
- Escrow, HTLC and vesting, with abuse tests.
- Measure ZK-F4 at the capped budgets.
- Message commitments (R7-3) and contract-scoped tags at an activation height.

**Phase 4: scale and function privacy.**
- Aggregation or recursion: unlocks throughput (R7-4) and hiding which function ran
  (P-8, Zexe and Aztec-level function privacy).
- Only then evaluate batch settlement (Penumbra-style) or a public finalize (Aleo-style,
  possibly reusing the wasmi engine) for shared state.

---

## 9. What should never be changed (without overwhelming evidence)

- **Value lives only in PX records:** conservation is one kernel statement in `u128`
  arithmetic. Never add a second value layer: not Wasm notes, and not a public
  contract-held balance.
- **Contracts approve declared effects; they do not move value.** The approval and
  specification model and the `io_hash` binding.
- **The mandatory registry argument in `prove::verify`,** and PX3 before PX5.
- **Fixed proof shapes per registered budget.**
- **Hash-based ownership and nullifiers;** `rho` derived from `nf_0` (no Faerie Gold).
- **Immutable registry entries** (for v1).
- **No trusted hardware, no trusted setup** (the Secret Network 2022 lesson).
- **The atomic-failure rule** (an invalid call is an invalid transaction; no fee-paying
  failed calls that leak attempts).

---

## 10. Deferred, with justification

- The Wasm M3–M6: deferred indefinitely, out of scope (§6).
- Public finalize and batch settlement: after aggregation (R7-4).
- Upgradeability: after v1; immutable by default.
- `N_IN` or `N_OUT` above 2 and `MAX_FN` above 2: only with aggregation, because every
  transaction pays the rows.
- Poseidon2 signatures: after the approval-record pattern proves insufficient.

---

## 11. Sources

**Repository** (source-read):
- px-core/src/kernel.rs, call.rs, record.rs;
- px/src/prove.rs, vault.rs;
- zkvm/guests/vault;
- tx/src/px.rs, validate.rs, state.rs, params.rs;
- zkvm/src/program.rs, lib.rs;
- zk/src/params.rs;
- wallet/src/px.rs:54-58;
- contracts/src/*;
- docs/px.md, contracts.md;
- docs/reviews/contracts-completion-assessment.md, px-f4-f5-analysis.md,
  privacy-review.md.

**External:**
- Aztec, private and public execution, kernels:
  https://docs.aztec.network/developers/docs/foundational-topics/advanced/circuits ;
  https://docs.aztec.network/developers/docs/foundational-topics/call_types ;
  https://docs.aztec.network/protocol-specs/circuits/private-kernel-tail
- Aztec, note delivery modes (constrained and unconstrained):
  https://docs.aztec.network/developers/docs/foundational-topics/advanced/storage/note_discovery
- Aleo, transitions, async/finalize:
  https://developer.aleo.org/guides/aleo/language/ ; https://docs.aleo.org/learn/core-concepts/programs/index.html
- Aleo, program upgradability (constructor, policies):
  https://developer.aleo.org/guides/program_upgradability/ ;
  https://github.com/ProvableHQ/ARCs/discussions/94
- Zexe: Bowe, Chiesa, Green, Miers, Mishra, Wu, "Zexe: Enabling Decentralized Private
  Computation", IEEE S&P 2020: https://www.cs.umd.edu/~imiers/pdf/zexe.pdf
- Secret Network SGX, 2022: https://sgx.fail/ ;
  https://www.theblock.co/post/190914/secret-network-says-it-resolved-risk-from-intel-hardware-vulnerability
- Penumbra DEX and batch swaps: https://protocol.penumbra.zone/main/dex.html ;
  https://protocol.penumbra.zone/main/dex/swap.html
- Zcash Shielded Assets: https://zips.z.cash/zip-0226 ; https://zips.z.cash/zip-0227 ;
  https://zechub.wiki/zcash-tech/zcash-shielded-assets. The NU7 timing is reported by
  secondary sources and is unverified here.

**Confidence notes:**
- All code facts are [src] at `f677e55`.
- Cost magnitudes for R7-5 and the Poseidon2 signature cost are [unknown] until measured.
- External facts are as of the cited pages, retrieved 2026-09-27.
