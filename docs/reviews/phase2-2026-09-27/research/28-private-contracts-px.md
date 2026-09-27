# 28 private-contracts-px: research dossier (phase 1)

**Author:** specialist agent 28 (private-contracts-px). This is internal engineering research, not an audit.
**Commit read:** `rebuild/core` @ `9e422d8` (the v3/candidate merge). Read-only. No builds or tests were run.
**Evidence tags:**
- **[math]:** mathematically established;
- **[test: name]:** covered by a named test, which I read but did not run;
- **[src]:** read in the source;
- **[web]:** a primary source, cited in §8;
- **[assumed]**;
- **[unknown]**.

---

## 0. Summary

1. **Architecture decision (ADR-28-1): PX is the only consensus contract platform.**
   - The Wasm engine stays frozen research, outside the default build (R7 option D).
   - A public "finalize" phase attached to PX calls stays the only admissible future door for public state.
   - I confirm R7's reasoning against the primary sources (Aleo, Aztec, Zexe, Neptune, Penumbra). No second value layer.
2. **Two new findings are material before the protocol freeze.**
   - **F-28-1 (Medium):** the function-call ABI is unversioned, and the reserved `verifier_id` is never dispatched. So the first kernel generation that changes `Call`/`OutSpec`/`N_IN`/`N_OUT` will **strand every deployed contract and the value in its records**. Every planned contract improvement (B′, clock, messages, shape classes, user-owned contract records) is such a change.
   - **F-28-2 (Medium, evidence):** no `n_fn = 2` transaction has ever been proven and verified. The shape is consensus-reachable, but it is exercised only natively.
3. **The function clock (R5-3 vs R7-1).**
   - I challenge R5-3: the root window stores digests without heights, and roots repeat across blocks without PX, so "the anchor's height" is ambiguous (F-28-3).
   - I recommend a **transaction-level validity window `[not_before, not_after]`**, echoed by the verifier into every function's prefix. This is the CLTV model: Bitcoin BIP 65, Zcash ZIP 203, Aztec `expiration_timestamp`, and Neptune's kernel `timestamp` read by scripts through the kernel hash.
   - The kernel is unchanged; the vault id and the PX tx format change.
4. **PX-F4 B′.** Not in v3. It goes into the first kernel generation (G2), after ABI versioning and verifier dispatch exist, together with F-20-1. The `rcm` must stay prover-choosable (I2-F1).
5. **Message commitments and contract-scoped tags** both have designs here that reuse existing machinery:
   - messages are statement-built, like `io_hash`;
   - tags go into the existing nullifier set, with node-side domain separation.
   Both are G2, activated by height.
6. **A contract-author security checklist** (§3.7) and a **`docs/contracts.md` rewrite plan** (§3.8) are included.

---

## 1. Scope and what I read

**Commit:** `9e422d8` (`git rev-parse --short HEAD`).

**Reviews and specifications, read in full:**
- `C:/bszkeval/p2/brief.md`;
- roster entries 20–29 and 46–50;
- `docs/reviews/full-review-2026-09-27/`: R5-px, R7-contracts, I1-private-computation and I2-identity-governance, all in full;
- SX1 and SX2 (every PX and contract row);
- `v3-plan.md`;
- `docs/reviews/full-review-2026-09-27.md` (register rows 837–1031; decision table D1–D22; never-change list);
- `docs/reviews/autonomous-session-2026-09-27.md` (in full);
- `docs/reviews/px-f4-f5-analysis.md` (in full);
- `docs/reviews/v3-upgrade-mechanism.md` §1, §2.6, §5–§8;
- `docs/px.md` §7, §10, §11.2–§11.5 and §13 (in full);
- `docs/contracts.md` (banner, outline, §1);
- neighbour dossier `C:/bszkeval/p2/research/20-px-kernel.md` (findings and plan).

**Code:**
- `px-core/src/{call,kernel,record,lib}.rs` (in full); `px-core/src/hash.rs` (domains);
- `px/src/{prove,vault,state,share}.rs` (in full);
- `zkvm/guests/vault/src/main.rs` (in full); `zkvm/sdk/src/lib.rs` (in full);
- `tx/src/px.rs` (in full); `tx/src/params.rs` (in full);
- `tx/src/validate.rs` (PX rules; `validate_px*`; `check_px_proof`; `revalidate_after_extension`);
- `tx/src/state.rs` (registry);
- `consensus/src/schedule.rs` (epochs, `verifier_id`);
- `zkvm/src/air/trace.rs` (Budget, output table height).

**Tests (names and bodies where relevant):**
- `px/tests/unified.rs`: `lock_then_claim_proves_verifies_and_pays_the_recipient`, `a_wrong_secret_cannot_claim`, `contract_rules_reject_their_violations`, `a_contract_output_with_an_owner_is_rejected`, `a_function_transcript_must_match_the_kernel`, `record_kinds_are_not_revealed_by_trace_heights`, `budgets_leave_headroom`;
- `px/tests/kernel.rs`;
- `tx/tests/deploy_rules.rs` (all 9 tests);
- `tx/tests/px_consensus.rs` (`a_private_contract_is_deployed_and_used_through_consensus`);
- `tx/tests/upgrade.rs`;
- `px/tests/elf_paths.rs`;
- the fuzz target list (`contract_sequence` is the Wasm engine, not PX).

---

## 2. Current state

### 2.1 What exists

| Item | Status | Evidence |
|---|---|---|
| Record model: user records (`contract = 0`) and contract records (`contract ≠ 0`, `owner = 0`); the contract nullifier depends only on the opening | Complete | [src] `px-core/src/record.rs:190-200`, `kernel.rs:276-330` |
| Approve and specify model with a hiding `io_hash` shared by the kernel and the function | Complete | [src] `call.rs:53-88`, `kernel.rs:229-395`; [test: `contract_rules_reject_their_violations`, 12+ cases native = guest] |
| PX-F5 enforced (contract output ⇒ owner 0) | Complete, on the merged tree; takes effect with the v3 kernel id | [src] `kernel.rs:348-352`; [test: `a_contract_output_with_an_owner_is_rejected`] |
| Registry `(contract, program_id) → (Program, Budget)`; mandatory in `verify`; PX3 before PX5 | Complete | [src] `prove.rs:222-241`, `validate.rs:528-575`, `tx/src/state.rs:189-202,294-307`; [test: `a_private_contract_is_deployed_and_used_through_consensus`] |
| Deploy rules (v3): exact fee, provable budgets, distinct program ids, 1 MiB block deploy budget | Complete | [src] `tx/src/px.rs:475-480,767-824`, `params.rs:31-49`; [test: `tx/tests/deploy_rules.rs`, 9 tests incl. `a_block_over_the_deploy_budget_is_invalid`] |
| Contract id = `H64(first key image ‖ salt ‖ H32(payload))` mod p | Complete | [src] `tx/src/px.rs:593-607` |
| Height-scheduled epochs with `branch_id` and a reserved `verifier_id` | Branch id complete; **verifier id reserved, not dispatched** | [src] `schedule.rs:17-33`; `TxRules` has no verifier field (`params.rs:99-107`); `check_px_proof` always uses the one `kernel_program()` (`validate.rs:538-575`, `prove.rs:30-41`) |
| Guest SDK: `read`, `write`, `halt`, `poseidon2` | Minimal | [src] `zkvm/sdk/src/lib.rs` |
| Contract SDK, ABI or manifest, generic wallet client, time, authorization, composition | Not implemented | [src]; px.md §13.4.1 |
| Reference contract: the hash-locked vault (LOCK, CLAIM) | Complete (demonstration only) | [src] `zkvm/guests/vault/src/main.rs`, `px/src/vault.rs` |

### 2.2 Correct and well designed (evidence)

- **Value never lives in contract logic.** Functions approve and specify; conservation is one `u128` kernel equation [math][src `kernel.rs:262,331,364,388`].
- **The function is bound to its contract through the verifier-built prefix,** and the registry is keyed by `(contract, program id)`. Cross-instance approvals fail [src `prove.rs:118-140,233-238`; R5-8].
- **Fixed proof shapes per registered budget:** the trace length does not leak the path taken [src `prove.rs:54-71,127-138`; test `record_kinds_are_not_revealed_by_trace_heights`].
- **Atomic failure:** an invalid call is an invalid transaction, so failed attempts are not published [src].
- **The v3 deploy economics are now sane** [test: `the_deploy_fee_is_the_standard_transfer_fee_plus_the_payload_rate`, `a_block_over_the_deploy_budget_is_invalid`]:
  - 50 atomic units per payload byte;
  - an exact fee;
  - a 1 MiB per-block deploy cap.

### 2.3 What the tests prove, and what they do not

**Proven** [test]:
- the one-function flows (LOCK, CLAIM) end to end, through consensus and RPC;
- every tested kernel rule, native = guest;
- the deploy structure rules.

**Not proven:**
- **Any `n_fn = 2` proof.** `budgets_leave_headroom` builds an `n_fn = 2` witness and only measures `trace::usage` natively (`unified.rs:549-566`). Every proving path uses `n_fn ≤ 1`: `px_consensus.rs:535,632`, `proof_bench.rs:94,115`, `proof_length_campaign.rs:233,254`, `wallet.rs:2307,2476` [src, grep]. See F-28-2.
- **A double approval** of one input by two functions (F-20-1, owned by 20).
- **A function-level time or authorization pattern:** none exists.

---

## 3. Problems in scope

### 3.1 Should PX be the only consensus contract platform? (ADR-28-1)

**Decision proposed:** Yes. Adopt R7 option D:
- PX only, for the testnet and v1;
- Wasm (`contracts/`) frozen as research and removed from the default workspace and release builds (the build and banner mechanics belong to 29);
- the `crypto::{schnorr, membership, claims}` modules gated behind a feature (R7-10, R16-11).

**Why the problem exists:** two designs were started before PX reached consensus. The Wasm design gives:
- 1-of-16 ring callers;
- public code, state and inputs;
- a second value layer (notes plus a Mimblewimble kernel);
- about 120 `unsafe` blocks in wasmi.

**Security and privacy consequences of keeping both:**
- two privacy tiers, with a user's privacy degrading to that of the weakest counterparty;
- a doubled consensus attack surface (a second VM, fuel calibration, re-execution DoS, MEV);
- a second conservation argument.

**Literature and prior art** [web]:
- **Aleo:**
  - private transitions are proven client-side;
  - `block.height` is available **only** in the public finalize scope, which validators execute publicly;
  - a public mapping is an explicit per-program choice.
- **Aztec:**
  - private functions run on the user's device;
  - public functions run in the AVM;
  - the private kernel folds the private call stack.
- **Zexe:** records with birth and death predicates; function privacy through recursion.
- **Neptune Cash:**
  - lock and type scripts are hidden behind commitments;
  - scripts read the transaction kernel through its MAST hash;
  - there are no general public contracts.
- **Penumbra:** no general contracts; fixed-function actions, with batch swaps for shared-state DeFi.

**None of the privacy-first systems uses a public-state VM as its default contract layer.** Where public state exists (Aleo finalize, Aztec public functions), value and logic stay in one conservation model, and public state is an explicit, opt-in phase.

**Trade-offs and risks:**
- PX has the worst developer experience and throughput (about 3 PX transactions per block).
- The ADR accepts this and scopes PX to bilateral and UTXO-style contracts until aggregation exists (R7-4). The docs must say so (P0).
- The risk: a demand for shared state appears. The answer then is a finalize phase over PX with no value layer (R7 §4 D), never a revived Wasm value layer.

**Tests:** none (a scope decision). The build change is 29's.

**Invariants:**
- value lives only in PX records;
- contracts approve declared effects and never move value;
- no TEE, no trusted setup, no committee.

### 3.2 The function clock (R5-3 / R7-1)

**Problem [src]:**
- A function sees only its private input (`zkvm/guests/vault/src/main.rs:62-120`).
- The prefix is `io_hash ‖ contract` (`call.rs:83-88`).
- `validate_px` receives `height` but uses it only to resolve rings (`validate.rs:592-627`).

So no timeout, refund, HTLC, vesting or auction deadline can be expressed. SX1 is right that this is a *capability* gap, not a security bug. But it is also the prerequisite for any trustless swap, so the vault's warning ("not a trustless swap") is structural.

**The two proposals, compared:**

| | R5-3 "anchor height" | R7-1 "function validity window" | **Proposed: tx-level window, verifier-echoed (CLTV model)** |
|---|---|---|---|
| **What the function learns** | The height of the anchor root (proof-time evidence) | A window it writes in its own outputs, checked by consensus | A `[not_before, not_after]` pair from the transaction prefix, which the verifier places in every function's prefix. The function reads it as private input, echoes it, and asserts on it (`not_before ≥ T` for a refund, `not_after < T` for a claim) |
| **Precision** | **Ambiguous** (F-28-3): roots have no height index and repeat across blocks with no PX output. "Before T" needs a `ROOT_WINDOW` = 100-block slack | Exact inclusion height | Exact inclusion height |
| **Composition with `n_fn = 2`** | Per-anchor, shared | One window per function; consensus checks every one | One window per transaction, shared by both functions |
| **Kernel change** | None | None | None (the kernel never sees the window; `function_prefix` is host and guest code outside the kernel's logic) |
| **Format change** | Function prefix | Function output header | PX tx prefix (+2 varints, under `h_tx`) and the function prefix (+2 words) |
| **Prior art [web]** | Aztec private functions read the *anchor block* header (`block_number`, `timestamp`) | Zcash `nExpiryHeight` (ZIP 203); Aztec `expiration_timestamp` | Bitcoin BIP 65 (the script checks the tx's `nLockTime`; consensus checks `nLockTime` against the block). Neptune: `kernel.timestamp` reaches scripts through the kernel MAST hash, and "the transaction timestamp does not exceed the block timestamp". Aztec pairs an anchor with `expiration_timestamp` |

**Security:**
- **Positive:** refunds and HTLCs become sound.
- **Reorg behaviour (standard, as for Zcash expiry):**
  - after a reorg, a transaction can become expired: drop it;
  - a transaction can also become premature (the tip is lower): keep it in the wallet only, and refuse it in the mempool as contextual.
- **Censorship:** a miner can delay a claim past `not_after`. This is inherent to every HTLC, and authors must size the margins (checklist §3.7).

**Privacy:**
- The window is public.
- Plain transfers must carry one constant default, `(0, 0)` meaning "unbounded", or they fingerprint.
- Contract windows should be bucketed (multiples of 16, aligned with the wallet anchor policy). A refund reveals its deadline bucket, which is inherent.

**Consensus integration** (exact points):
- `PxTx::prefix_bytes` / `decode_body` gain two varints (`tx/src/px.rs:228-263,301-369`);
- `check_px_structure`: `not_after == 0 || not_before ≤ not_after`;
- a contextual rule `PX6`: `not_before ≤ h ≤ not_after` (0 = unbounded), in `check_px_state` or next to it. It needs the height, which `validate_px_without_proof` already receives.
- **`revalidate_after_extension` has no height parameter** (`validate.rs:712-746`). It must gain one, or pooled window transactions would survive expiry. The PX anchor window already makes validity non-monotone, so the mempool must already handle expiry-by-extension.
- `TxError::PxWindow` is contextual (never misbehaviour: height races at the edges);
- templates skip out-of-window transactions;
- `prove::statement` builds `function_prefix(io_hash, contract, window)`.

**Identity:** a new PX transaction format and new vectors. The kernel id is unchanged; the vault ELF and id change (it must echo the window). **Fits v3** at low cost.

**What could go wrong:**
- **Echo omitted:** a function that echoes but never asserts gets no protection. That is author error; the SDK types make the window a required argument.
- **Consensus split:** mismatched height semantics between the mempool (`tip + 1`) and a block (`h`). Test at the boundaries.

**Tests:**
- boundary tests `h = not_before − 1, not_before, not_after, not_after + 1`;
- a reorg that expires a pooled transaction;
- `revalidate_after_extension` at expiry;
- a vault (or HTLC guest) refund before and after T, native = guest;
- a function that echoes a wrong window yields no proof (a statement mismatch);
- P2P: a window error is not scored.

**Invariants:** the kernel statement is unchanged; the window is covered by `h_tx`.

**Recommendation:**
- **Include in v3 if the owner accepts a vault rebuild.** The cost is S–M and it fixes the ABI now (see F-28-1).
- Otherwise, reserve the two prefix words in the ABI now, pinned to `(0, 0)`, and activate the rule by height later. That is only possible once F-28-1's versioning exists.

### 3.3 Message commitments between functions (R7-3)

**Problem [src]:** each function's transcript is private to it (`call.rs:56-79`). With `n_fn = 2`, co-inclusion gives atomicity (one balance equation) but no composition: A cannot know what B computed.

**Proposed design (G2), statement-built, like `io_hash`:**
- The transaction carries an optional public message commitment `m = Hk(MSG, from ‖ to ‖ payload ‖ blind_m)`.
- The verifier puts `m` into A's prefix as `msg_out` and into B's prefix as `msg_in`.
- Equality is then enforced by construction, as `io_hash` is shared between the kernel and a function (docs/px.md §7.2).
- Each function checks inside itself that `from` (respectively `to`) equals its own contract input, through SDK-enforced code.
- **No comparison logic in consensus;** only statement construction.
- This matches:
  - Aztec's private kernel, which checks call-request hashes against the callee's public inputs [web];
  - Zexe's "local data" given to every predicate [web], restricted to one edge.

**Security:**
- A message does not authorize value; it conditions the functions' own approvals and specs.
- **It must not ship before F-20-1** (one approval per input). Otherwise two co-approving functions can fork state regardless of messages.

**Privacy:**
- The contents are hidden (blind).
- The fact that A and B interacted is already public (P-8).

**Consensus:** the tx format, the function prefix and the ABI version. The kernel is unchanged.

**Tests:**
- a mismatched `msg_in` gives no proof;
- a `from` spoof is rejected by the SDK function (native = guest);
- A without B, and B without A, are refused by statement shape.

**Priority:** P3 (G2).

### 3.4 Contract-scoped tags (R7, I1 B4, I2 §4.1)

**Need:** one-person-one-vote, one-time claims, and rate-limiting nullifiers, without consuming a unique record. I2 prefers credential-state records with no consensus change. That covers sequential scopes (≤ 248 bits of state) but serializes on one record.

**Prior art [web]:**
- Penumbra keeps "per-proposal nullifier sets for voting, entirely distinct from the main nullifier set";
- Semaphore's nullifier is `hash(scope, secret)` recorded by the contract.

**Proposed design (G2):**
- A function may output up to `T ≤ 2` tags in its structured header.
- The node inserts `Hk(NF_TAG, contract ‖ tag)` into the **existing** nullifier set: the same PX2 check, the same undo, the same pruning story.
- The node computes the contract binding natively, so a function of contract A cannot burn B's tags.
- No new state structure, no new undo code.

**Costs:**
- growth of the nullifier set;
- the node-side Poseidon2 hash (cheap).

**Risks:**
- a tag must derive from `sk`-bound or holder-secret material (I2-F2), never from FVK material;
- the scope must be fixed by the program, not the prover (I2 MEM-1).

**Priority:** P3 (G2), only with a measured use case beyond credential state.

### 3.5 PX-F4 option B′: timing

**Facts [src]:**
- The caller chooses `rcm` for outputs a function specifies (`kernel.rs:343-363`; `io_hash` omits `rcm`: `call.rs:69-76`).
- B′ (R5-15): `OutSpec` gains an optional `rcm_seed`, and the kernel derives `rcm = Hk(RCM, seed ‖ rho'_j)`.
- `rho'_j = Hk(RHO, nf_0 ‖ j)` is public-derivable, so seed holders can recompute the opening from the chain.

**What B′ changes:**
- the kernel (a new id);
- `IO_LEN` and `io_hash` (every function ELF);
- the witness layout.

**Timing recommendation: in G2, not in v3.** I agree with SX1, I2-F1 and D16. Reasons:
1. It changes the call ABI, which after F-28-1 should happen exactly once per generation, together with messages, tags, shape classes and user-owned contract records.
2. No multi-party contract exists for the trial.
3. It must keep a prover-chosen `rcm` when no seed is given (I2-F1 credential refresh).

**Precondition:** F-28-1 (versioned ABI plus verifier dispatch), so that v3 vault records are not stranded by G2.

**Lint:** refuse seeds derived only from public data. With such a seed, `cm` becomes guessable and the contract nullifier public: SX2's public-`rcm` corollary.

**Tests:**
- seed and no-seed paths, native = guest;
- `rcm` recomputable from the chain given the seed;
- the public-seed lint;
- the credential-refresh pattern still possible.

### 3.6 Function height window vs. deploy rules and the registry

The deploy rules are complete [test]. Two remaining gaps belong to my scope.

**(a) Public output length is unpinned (F-28-5).**
- A function may publish 0–256 words per call (`tx/src/px.rs:331`). The output table height is `pow2(len)` (`trace.rs:134`), so it is public too.
- R7-8 covers the content. The *length* also varies per call of the same program and can fingerprint.
- **Fix:** register an exact `out_words` per program at deploy (a deploy format change, CONSENSUS, v3-cheap). Consensus requires `outputs.len() == out_words`.

**(b) The registry has no ABI version (F-28-1).** See §4.

### 3.7 Contract-author security checklist (deliverable)

To be published as `docs/contracts.md` §6 (see §3.8). Each item cites its evidence.

1. **"Self" is a checked input.** Read `contract` from input and bind it through `function_prefix`. Wallets and verifiers pin the **contract id**, never only the program id: the same ELF can be registered under many contracts (R5-8, I2 §3.2).
2. **A contract is its whole program set.** Any registered program can approve any record of the contract (docs/px.md §13.4, P-1). Tag every record's `data` with a type and version word, and check it in every function.
3. **Account for approved value.** For every approved input, specify outputs that cover its value, or document where it goes (px-f4-f5-analysis §4a; F-20-2).
4. **Assume co-approval until F-20-1 lands.** A second function of your contract in the same transaction can approve the same input. Linear state (unique items, sequence numbers, approval records) can fork (F-20-1).
5. **Contract outputs have owner 0.** This is enforced since PX-F5; a user payout with an unopenable owner still burns (F-20-6).
6. **Delivery (PX-F4).** The caller chooses `rcm` and writes the ciphertext.
   - Any multi-party state is griefable (lock or burn) by a caller who withholds the opening.
   - Design so that the party who needs a record is the one who creates it, or accept the griefing risk explicitly.
7. **Contract nullifiers are visible to every holder of the opening** (R3-7, I2-F1). An issued credential gives zero anonymity on first use without a holder refresh step.
8. **Authority from `sk`, not FVK material.** Programs that confer authority (votes, reserves, shows) must derive `ak`/`nk` from `sk` (I2-F2).
9. **Public outputs.** Publish a fixed number of words, with no amounts, owners or secret-derived values. Declare them in the manifest (R7-8, F-28-5).
10. **Application hashes.** Use your own domain constant outside PX's `0x0050_58xx` range, **and include the contract id**. The vault's `Hk(LOCK, secret)` omits it, so a reused secret works across vault instances (F-28-7).
11. **Randomness.** Draw the `io_hash` blind and every author-chosen `rcm` from a CSPRNG, fresh per call (R-6; autonomous report §6: the vault flows' blinds are still unhedged).
12. **Budget.** Measure the worst case of *every* valid path, and keep headroom. A path over budget cannot be proven: funds are stuck (P-2, `budgets_leave_headroom`).
13. **Canonical input.** Check every read field element (`canonical`). Halt with codes, never with located panics (R15-6; `elf_paths.rs`).
14. **Time.** Until §3.2 lands there is no clock: no refunds, no deadlines. After it lands, assert on the echoed window. Size the margins for censorship (a miner can delay a claim).
15. **Shapes.** 2 inputs and 2 outputs in total, and 248 bits of `data`. Larger state goes into `Hk(state)`, with the preimage delivered (R7-7).
16. **Immutability.** Registrations never change. Include a migration function if the contract must outlive a kernel generation (F-28-1).
17. **Reproducibility.** Pin the ELF and its id (like `px/vault.id`), build path-neutrally with the pinned toolchain, and publish the source hash (R7-9).
18. **Anonymity set.** Calls reveal the contract and program (P-8). A contract with few users gives little anonymity; show the set size in the UI (I2 §4.5).
19. **Front-running.** Whoever holds the opening plus the function's secret can race you (the vault docs).
20. **Tests before deploy.** Every rule violation native = guest, an end-to-end proof, budget headroom, and `n_fn = 2` interactions if the contract allows them.

### 3.8 `docs/contracts.md` rewrite plan

`docs/contracts.md` today presents the Wasm system as "v0.2: model approved, implementation in progress", with a banner. It contradicts ADR-28-1 and the consolidated D22.

**Plan** (owner: 28; the Wasm file move is coordinated with 29; the consistency check with 47):
1. `git mv docs/contracts.md docs/research/wasm-contracts.md`. Put a top banner on it: "Superseded research; not planned for v1; kinds 2/3 belong to PX; not consensus." Content otherwise unchanged (history).
2. A new `docs/contracts.md`, **"Private contracts on PX"** (normative where marked):
   - **§1 Scope and the ADR** (PX-only; the finalize door; why).
   - **§2 Capability envelope:**
     - bilateral and UTXO-style contracts only;
     - no shared-state DeFi (R7-4);
     - no clock until §3.2 lands;
     - about 3 PX transactions per block;
     - what is always public (P-8).
   - **§3 The model:** records, approve and specify, `io_hash`, registry. This moves from px.md §7, and px.md keeps a pointer.
   - **§4 The function ABI:** prefix layout, ABI version, window (when adopted), public-output rules.
   - **§5 Deploy rules:** fee, budgets, distinct ids, block cap, immutability, contract id derivation (and I2-F5's privacy note).
   - **§6 The author security checklist** (§3.7).
   - **§7 Delivery and sharing:** move px.md §13.1–§13.3, and correct the share claim (R5-4).
   - **§8 The reference vault and its limits.**
   - **§9 Roadmap:** G2 contents, tooling and recursion, with each item's consensus impact.
   - **§10 Prior art:** the careful statements of R7 §5 and I1 §7, with no "first" claims.
3. Remove the Wasm "v1.1 confidential tokens" statements from zk.md §14/§17 cross-references (with 47).

### 3.9 Roadmap

| Phase | Content | Consensus | Gate |
|---|---|---|---|
| **A (v3 freeze)** | F-28-1 ABI version plus registry field; §3.2 window (owner decision); F-28-5 `out_words`; F-20-1 (20); F-28-2 evidence; docs (capability envelope, checklist, contracts.md rewrite, share-claim fix) | yes (tx and deploy formats, vault id; F-20-1 the kernel id) | freeze |
| **B (tooling)** | `px-contract-sdk` (typed `Call` builder that makes foreign approvals and specs unrepresentable; window assertions; conservation lint; hedged blinds); manifest (ABI, output schema, budgets, source hash); generic wallet client; `px-verify-contract`; reference escrow and HTLC (need the window) with abuse tests | none | after the trial starts |
| **C (G2 kernel generation, activated by height)** | verifier dispatch by `epoch.verifier_id` and registry ABI version; B′; messages; tags; user-owned contract records (R5-10); shape classes plus multi-asset (I1 B1) | yes (new verifier) | the verifier-dispatch design reviewed; the proof cache keyed by verifier (R16-8) |
| **D (scale and function privacy)** | recursion (A5a, then A5c); finalize for public state, only with evidence of demand | yes | Plonky3-recursion maturity |

---

## 4. New findings

| ID | Title | Severity | Status | Where | Confidence |
|---|---|---|---|---|---|
| F-28-1 | The function-call ABI is unversioned and `verifier_id` is not dispatched: the first kernel generation that changes the call format strands every deployed contract and its records | **Medium** (architecture; consensus-adjacent; value-locking at G2) | Not implemented | `px-core/src/call.rs:30,53,83-88`; `kernel.rs:53-54`; `px/src/prove.rs:30-41,118-140`; `consensus/src/schedule.rs:27-33`; `tx/src/params.rs:99-107`; `tx/src/validate.rs:538-575`; `tx/src/state.rs:189-202` | High (mechanism); medium (timing) |
| F-28-2 | No `n_fn = 2` transaction has ever been proven and verified; the shape is consensus-reachable but exercised only natively | **Medium** (evidence gap on a consensus path) | Partially implemented (native only) | `px/tests/unified.rs:549-566`; `tx/tests/px_consensus.rs:535,632`; `px/examples/proof_bench.rs:94,115`; `wallet/src/wallet.rs:2307,2476` | High (grep of every `n_fn` use) |
| F-28-3 | R5-3's "anchor height as a clock" is under-specified: the root window has no height index and roots repeat across blocks without PX; "before T" carries a 100-block slack | Low (design correctness of a proposal) | Not implemented (proposal) | `px/src/state.rs:26,42,86-88,141-145` | High |
| F-28-4 | R7-2's "approval record" authorization pattern is unsafe until F-20-1 is fixed: one approval record can authorize two co-included actions | Medium (contingent; no current consumer) | Not implemented | `kernel.rs:313-326` (F-20-1); R7-2 | High |
| F-28-5 | Function public-output length is unpinned per program, so it varies per call and fingerprints; deepens R7-8 | Low | Partially implemented | `tx/src/px.rs:325-341`; `tx/src/params.rs:45`; `zkvm/src/air/trace.rs:134` | High |
| F-28-6 | Records carry no type tag, and a contract is its whole program set: intra-contract type confusion is an author responsibility, documented only for the vault | Low | Accepted limitation (docs owed) | `kernel.rs:313-326`; docs/px.md §13.4 | High |
| F-28-7 | The vault's lock hash is not bound to the contract id: a secret reused across vault instances claims in any instance whose opening one holds | Informational | Accepted limitation (checklist) | `zkvm/guests/vault/src/main.rs:94`; `px/src/vault.rs:72-74` | High |
| F-28-8 | Confirmation: R5-4's share claim ("reveals nothing to anyone but the addressee") is still in the source at HEAD | Low (docs, P0 per the consolidated report) | Not implemented | `px/src/share.rs:15-17` | High |
| F-28-9 | `docs/contracts.md` still presents Wasm as an approved model in progress, and `contracts` is a default workspace member, although D22 recommends option D | Low (claims and scope) | Not implemented | `docs/contracts.md:17-22`; `Cargo.toml:14` | High |

### F-28-1 (Medium): unversioned call ABI; no verifier dispatch

**Mechanism [src]:**
- Every function ELF compiles in `px_core::call::{Call::io_hash, function_prefix}`: the vault does, at `main.rs:14,116`.
- `IO_LEN` depends on `N_IN` and `N_OUT` (`call.rs:53`), and the prefix is fixed at 16 words.
- The verifier builds each function's expected prefix from the kernel's `(contract, io_hash)` with the current code (`prove.rs:129-131`), and always uses the one pinned kernel.
- The schedule carries `verifier_id` (`schedule.rs:27`), but `TxRules` does not, and `check_px_proof` never selects a verifier.

**Scenario:**
1. At a height H, G2 activates B′ or messages (a new `io_hash` layout) or shape classes (a new `IO_LEN`).
2. After H, the kernel computes the new transcript. An old vault ELF computes the old one.
3. No proof can satisfy both, so every contract deployed before H is uncallable.
4. Its contract records (the locked value) are stranded unless the old verifier stays available for calls to old-ABI contracts.
5. The same holds on the testnet for any record locked during the trial.

**Why it exists:** the upgrade mechanism was built for signature domains (`branch_id`), which need no program change. The function ABI is inside third-party programs, which cannot be rebuilt by an upgrade.

**Prior art [web]:**
- **Zcash:** old pools stay spendable-out (ZIP 211 disables only adding value to Sprout). Each generation's verifier coexists.
- **Aleo:** programs carry an `edition`, and upgrades are explicit per program.

**Recommendation:**
- **(v3, P0 decision, S):**
  - add `ABI_VERSION` as the first prefix word;
  - record `abi` per registered program at deploy (a deploy format field; consensus);
  - the verifier puts the registered `abi` into the prefix.
- **(G2, P1 design before the first kernel activation):**
  - dispatch the verifier by `(epoch.verifier_id, abi)`;
  - keep old-generation kernels for calls whose functions are all of the old ABI, at least until a published sunset height;
  - require an "old ABI ⇒ outputs only to user records or to new-ABI contracts" rule, in the ZIP 211 style;
  - key the proof cache by verifier (R16-8).

**Trade-offs:**
- Keeping old kernels grows the verifier set. Sunset heights bound it.
- The alternative, a multi-ABI kernel, grows kernel rows for every transaction. Not recommended.

**Tests:**
- the ABI word must match the registration;
- a regtest two-epoch activation in which an old-ABI vault record is still claimable after H, and a new-ABI call is refused before H;
- the proof cache is not reused across verifiers.

**Invariant:** registrations stay immutable. The ABI is part of the registration.

### F-28-2 (Medium): the `n_fn = 2` path has never been proven

**Facts [src]:**
- The only `n_fn = 2` witness (CLAIM plus LOCK of one vault) is checked natively and measured (`unified.rs:549-566`).
- Every prove/verify path uses `n_fn ≤ 1`. The widest-proof size is known to be unmeasured (P0-3).
- Beyond size, the untested elements are:
  - the two-part `statement` ordering;
  - the shared-table sums at `kernel_budget(2)` plus two function budgets;
  - `FunctionMismatch` indexing for `k = 1`;
  - the verifier's acceptance of such a proof.
- A latent defect there is either a liveness failure (uncallable combinations) or, worse, a verifier-side divergence.

**Fix:**
- an end-to-end test proving and verifying CLAIM+LOCK with `n_fn = 2`, including through `validate_px` and a block (slow tier);
- negatives: swapped function order, an output altered in function 1, one registration missing;
- record the size against `MAX_PROOF_BYTES` for 22.

**Priority:** P0 evidence, before the freeze.

### F-28-3 (Low): the anchor-height clock is ambiguous

- `State.roots` is a `VecDeque<Digest>`, with a root pushed per block even when no commitment is appended (`state.rs:141-145`).
- `is_recent_root` is a `contains` (`:86-88`). No root→height map exists, contrary to R5-3's "the root window already knows it".
- A canonical "anchor height" needs either a declared `anchor_height` field (checked as `root_at(anchor_height) == anchor`) or a min/max convention. Either way "before T" is only accurate to within `ROOT_WINDOW`.
- The §3.2 design avoids this.

### F-28-4 (Medium, contingent): approval records vs. F-20-1

- R7-2(a) proposes that a party authorizes an action by creating an "approval(action_hash)" contract record, which the acting transaction consumes.
- Under the current kernel, two functions of the same contract in one transaction can both approve that single record (F-20-1). One authorization then satisfies two actions.
- The SDK must not ship the pattern before F-20-1's `ApprovalConflict` rule, or the pattern must specify every output slot. That is fragile.

### F-28-5 to F-28-9

As in the table. Fixes:
- **F-28-5:** a registered `out_words` (v3, with F-28-1's deploy field).
- **F-28-6:** checklist items 2 and 4.
- **F-28-7:** checklist item 10. The vault LOCK domain gains the contract id at the next vault rebuild (free in v3: the vault is rebuilt anyway).
- **F-28-8:** a doc-comment fix plus the R5-4 wallet fix (P2).
- **F-28-9:** §3.8, and 29's workspace change.

---

## 5. Implementation plan for phase 2

| # | Work item | Files (ownership) | Visibility | Identity | Tests | Bench | Docs | Diff. | Prio |
|---|---|---|---|---|---|---|---|---|---|
| W28-1 | **Function ABI v1:** prefix = `ABI_VERSION ‖ io_hash ‖ contract ‖ not_before ‖ not_after` (window words pinned to 0 if the §3.2 rule is deferred); registry `abi` and `out_words` per program in the deploy payload | `px-core/src/call.rs` (`function_prefix`, constants; **28**; confirm with 43 that the kernel ELF is unchanged); `px/src/prove.rs::statement` (**28**, coordinate with 22); `tx/src/px.rs` (deploy payload, `read_budget` neighbour; coordinate with 11); `tx/src/state.rs` registry entry (coordinate with 21) | **CONSENSUS** | v3: new vault id, new PX and deploy vectors; kernel id unchanged (to verify) | wrong ABI word → no proof; `outputs.len() ≠ out_words` → `PxShape`; registry round-trip and undo; golden vectors | none | contracts.md §4; px.md §7.2, §11.2 | S–M | **P0** (decision) / P1 |
| W28-2 | **Transaction validity window (PX6)** | `tx/src/px.rs` (prefix fields, structure rule); `tx/src/validate.rs` (PX6, `revalidate_after_extension(height)`; coordinate with 10/11); `chain/src/mempool.rs` template filter (coordinate with 12); `p2p` scoring as contextual (coordinate with 30/31); `zkvm/guests/vault/src/main.rs` + `px/src/vault.rs` (echo; **28**); wallet default `(0, 0)` (coordinate with 38) | **CONSENSUS** | v3 (tx format; vault id) | boundary heights; reorg expiry; revalidation at expiry; window not scored; native = guest echo mismatch; new `tx/tests/px_window.rs` | none | contracts.md §2, §4; px.md §11 | M | **P0 decision** / P1 (owner may defer to an activation) |
| W28-3 | **`n_fn = 2` end-to-end proof test**, plus negatives | `px/tests/unified.rs` (new test; shared with 20; **28** writes the contract case); `tx/tests/px_consensus.rs` (slow tier) | none | none | prove and verify CLAIM+LOCK; swapped order, altered output k = 1, missing registration; size recorded for 22 | proof size and time for `n_fn = 2` | px.md §8 | S | **P0** |
| W28-4 | **Vault rebuild alignment:** contract id in the lock hash (F-28-7); hedged blind and `rcm` in the vault flows | `zkvm/guests/vault/src/main.rs`, `px/src/vault.rs` (**28**); `wallet/src/wallet.rs` vault flows (coordinate with 37/38); ELF and id rebuild by **43** (once, with the kernel) | CONSENSUS (vault id only) | v3 vault id | lock/claim unchanged semantics; cross-instance secret reuse fails | none | contracts.md §8 | S | P1 |
| W28-5 | **Docs:** ADR-28-1; `docs/contracts.md` rewrite (§3.8); author checklist (§3.7); capability envelope; R5-4 claim fix; F-4 as a griefable trust assumption | `docs/contracts.md` (**28**), `docs/research/wasm-contracts.md` (move; with 29), `docs/px.md` §7/§13 (**28**; §4 is 20's), `px/src/share.rs` doc comment (**28**) | none | none | doc-claim grep in CI (with 47) | none | as listed | S–M | **P0** (envelope, share claim) / P1 |
| W28-6 | **`px-contract-sdk`** (no_std guest crate plus host mirror): typed `Call` builder, window assertions, conservation lint, type-tagged `data`, hedged blinds; port the vault onto it | new `px-sdk/` or `zkvm/px-sdk/` (**28**); `px/src/vault.rs` | none (a new vault id is a new deploy) | none | native simulator = guest; builder refuses foreign approvals, specs and unbalanced approvals; property tests | vault cycles before and after | contracts.md §4, §6 | M–L | P2 |
| W28-7 | **Manifest and `px-verify-contract`** (ABI, output schema, budgets, source hash, toolchain); wallet refuses unknown contracts unless forced | new `tools/px-verify-contract/`; wallet display (coordinate with 38) | none | none | reproducible build → id match; tampered manifest refused | none | contracts.md §4 | M | P2 |
| W28-8 | **Reference escrow and HTLC** with abuse tests (after W28-2) | new guests under `zkvm/guests/`; host helpers | none (deploys) | none | refund before and after the deadline; co-approval attempt; griefing documented | proof size per call | contracts.md §8 | M | P2 |
| W28-9 | **G2 design document:** verifier dispatch plus ABI coexistence and sunset (F-28-1); B′; messages (§3.3); tags (§3.4); user-owned contract records | design doc `docs/reviews/px-g2-design.md` (**28**, with 20 and 46) | none (design) | — | test plan for each | — | new doc | M | P1 (design) / P3 (impl.) |

**Invariants every item keeps:**
- R5 §6 and R7 §9 (value only in PX records; approve and specify; mandatory registry; immutable registrations; fixed shapes; hash-based ownership; `rho` from `nf_0`);
- the kernel error codes are append-only;
- no function sees another's data except through a statement-built public value.

---

## 6. Dependencies and conflicts

- **20 px-kernel:** F-20-1 (a prerequisite for W28-6 approval patterns and §3.3); their W7 call builder = my W28-6 (I propose that I own it and 20 reviews); their W4 checklist = my §3.7 (I propose that I own the checklist, fed by their kernel items); px.md split (20: §4; 28: §7, §13).
- **22 px-proof-system:** `prove::statement` edits (W28-1); the `n_fn = 2` size (W28-3) feeds their widest-proof measurement.
- **10/11 (block/tx validation):** the PX6 rule and the format fields in `tx/src/px.rs` and `validate.rs`.
- **12 mempool:** template filter and expiry eviction for windows.
- **21 px-nullifiers:** the registry entry in `tx/src/state.rs`; tags in the nullifier set (G2).
- **26 zk-privacy:** P-5 re-run after the new vault ELF and prefix.
- **29 wasm-contracts-review:** ADR-28-1, file move, workspace exclusion.
- **30/31 p2p:** window errors contextual (no score).
- **37/38 wallet:** default window, hedged vault blinds, manifest display.
- **40 testnet-genesis / 43 CI-reproducibility:** one rebuild of the kernel and vault after all v3 items; id reproduction.
- **46 architecture:** the verifier-dispatch design (F-28-1) touches the consensus-core separation.
- **47 docs:** the contracts.md move, cross-references in zk.md §14/§17.
- **50 red-team:** attack the window boundaries and the ABI dispatch.

---

## 7. Open questions for the coordinator

1. **Owner decision:** include the §3.2 transaction window in v3 (my recommendation, S–M, vault rebuild), or reserve zeroed prefix words and activate later?
2. Accept ADR-28-1 (PX-only, option D) as recorded? It is D22 in the consolidated report, not yet signed.
3. Accept F-28-1's v3 part (ABI word plus registry `abi`/`out_words`) as a consensus item before the freeze?
4. Ownership: may 28 own `px-core/src/call.rs::function_prefix`, the vault guest and host, `docs/contracts.md`, and the SDK crate, with 20 owning `kernel.rs` and 22 owning `prove.rs`, where I edit only `statement`?
5. Should the author checklist live in `docs/contracts.md` (my proposal), with px.md linking to it?

---

## 8. Sources

**Repository** (source-read at `9e422d8`): the files listed in §1.

**External (retrieved 2026-09-27):**
- Aleo, special operands (`self.caller`, `self.signer`, `block.height` finalize-only): https://developer.aleo.org/guides/aleo/special_operands/
- Aleo, program upgradability (constructor, `edition`): https://developer.aleo.org/guides/program_upgradability/ ; ARC-0006: https://github.com/ProvableHQ/ARCs/discussions/94
- Aleo, language guide (async/finalize, mappings): https://developer.aleo.org/guides/aleo/language/
- Aztec, function context (anchor block header; `set_expiration_timestamp`, formerly `include_by_timestamp`): https://docs.aztec.network/developers/docs/aztec-nr/framework-description/functions/context ; rename in v4.0.2: https://newreleases.io/project/github/AztecProtocol/aztec-packages/release/v4.0.2
- Aztec, private kernel tail and call types: https://docs.aztec.network/protocol-specs/circuits/private-kernel-tail ; https://docs.aztec.network/developers/docs/foundational-topics/call_types
- Aztec, note discovery and delivery modes (offchain, unconstrained, constrained): https://docs.aztec.network/developers/docs/foundational-topics/advanced/storage/note_discovery
- Zexe: Bowe, Chiesa, Green, Miers, Mishra, Wu, "Zexe: Enabling Decentralized Private Computation", IEEE S&P 2020, https://eprint.iacr.org/2018/962 (predicates and local data from the paper body; the abstract covers DPC and recursion)
- Neptune Cash:
  - transaction kernel fields (incl. `timestamp`);
  - lock and type scripts receive `transaction_kernel_mast_hash`;
  - merge takes the max timestamp;
  - https://docs.neptune.cash/consensus/transaction.html
- Neptune Cash, block rule "the transaction timestamp does not exceed the block timestamp": https://docs.neptune.cash/consensus/block.html ; whitepaper: https://neptune.cash/whitepaper
- Penumbra governance (per-proposal nullifier sets): https://protocol.penumbra.zone/main/governance.html ; transaction model: https://protocol.penumbra.zone/main/transactions.html ; DEX and batch swaps: https://protocol.penumbra.zone/main/dex/swap.html
- Semaphore (scoped nullifiers): https://docs.semaphore.pse.dev/faq
- Zcash ZIP 203 (transaction expiry, `nExpiryHeight`): https://zips.z.cash/zip-0203 ; ZIP 211 (disabling new value into Sprout): https://zips.z.cash/zip-0211
- Bitcoin BIP 65 (OP_CHECKLOCKTIMEVERIFY): https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki (from my knowledge of the BIP; not re-fetched in this session)

**Confidence notes:**
- All code facts are [src] at `9e422d8`. No test was run.
- The claim that the kernel ELF is unchanged by a `function_prefix` edit is [assumed] and must be confirmed by a reproduce run (43).
- External facts are as published on the cited pages.
