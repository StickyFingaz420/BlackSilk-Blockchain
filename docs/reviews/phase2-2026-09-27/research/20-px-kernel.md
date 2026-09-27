# 20 px-kernel: research dossier (phase 1)

- Agent: specialist 20 (px-kernel), BlackSilk engineering phase 2, phase 1 (research and briefing).
- Internal engineering review, **not an audit**. No builds or tests were run (brief §4); every
  "tested" tag names an existing test that I read but did not re-run.
- Repository: `rebuild/core` at **`9e422d8`** (`git rev-parse --short HEAD`).
- Evidence classes used: **[math]** established by argument here; **[test: name]** covered by a named
  existing test (not re-run); **[src]** read in the source; **[assumed]**; **[unknown]**.

---

## 1. Scope and what I read

**Code (in full):**
- `px-core/src/{kernel,call,record,hash,lib}.rs`, `px-core/Cargo.toml`
- `zkvm/guests/kernel/src/main.rs`, `zkvm/guests/vault/src/main.rs`, `zkvm/sdk/src/lib.rs`,
  `zkvm/guests/{Cargo.toml,rust-toolchain.toml,build.sh}`
- `px/src/prove.rs`, `px/src/state.rs`, `px/src/vault.rs`, `px/src/wallet.rs` (witness builders,
  l. 355–502), `px/kernel.id`
- `tx/src/px.rs` (decode l. 301–369, `binding`, `public()`, `check_px_structure`,
  `check_px_balance`, `budget_is_provable`), `tx/src/validate.rs` (PX1–PX5, l. 510–572),
  `tx/src/state.rs` (`px_function`, l. 294–308)
- `tools/supply-audit/src/lib.rs` (pool accounting, grep)

**Tests (in full):** `px/tests/kernel.rs`, `px/tests/unified.rs`, `px/tests/fuzz.rs`,
`fuzz/fuzz_targets/kernel_diff.rs`, `fuzz/src/seeds.rs` (kernel seed, grep), `px-core/src/hash.rs`
unit tests.

**Docs and reports:** `docs/px.md` §1–§11 (l. 1–660), `docs/zk.md` §4–§7 (l. 200–425),
`docs/reviews/full-review-2026-09-27.md` (PX rows, findings register, v3 decision table),
`docs/reviews/autonomous-session-2026-09-27.md` (§4–§10), `docs/reviews/full-review-2026-09-27/R5-px.md`
(full), `SX1-core-crossreview.md` (full), `docs/reviews/px-f4-f5-analysis.md` (full),
`docs/reviews/v3-upgrade-mechanism.md` §9 (R2-C6 cost and headroom), grep of R7, I1, zk-security-review.
Roster entries 19, 20, 21, 22, 23, 26, 28, 41, 42, 43.

**Git history of the kernel:** `53d3b49` (platform-neutral build; kernel id `0577e667…`),
`c280928` (PX-F5), `bb437ad`, `d50df02`.

---

## 2. Current state

### 2.1 What exists

- **One kernel source** (`px-core/src/kernel.rs::transfer`, ~180 lines of logic), `no_std`,
  `forbid(unsafe_code)`, no dependencies. It is compiled natively (with the Plonky3 Poseidon2
  permutation, `HostPerm`) and to `riscv32i+zmmul` as the pinned guest `px/kernel.elf`
  (rustc 1.98.1, `opt-level=2`, LTO, `panic=abort`, `--strip-all`). Consensus pins the **ELF id**
  (`px/kernel.id` = `0577e667…`), not the source [src].
- **Statement (VERSION 2):** 2 inputs, 2 outputs, `n_fn ≤ MAX_FN = 2` functions. Public output
  `46 + 16·n_fn` words: anchor, two nullifiers, two commitments, bridge in/out, `n_fn`, and
  `(contract, io_hash)` per function [src].
- **Verifier side:** `prove::verify` rebuilds the statement from `PxTx::public()`, looks up each
  function's program by `(contract, program_id)` in the immutable registry (PX3/PX5), fixes the
  kernel budget by `n_fn` and the function budgets from the registry, binds `h_tx` [src].
- **16 kernel error codes** (exit 2..17), `ContractOutputOwner` (PX-F5) appended last [src].

### 2.2 What is correct and well designed (with evidence)

| Property | Evidence |
|---|---|
| Integer balance `Σv_i + b_in = Σv'_j + b_out` in `u128`; no field wrap possible (u64 inputs, 4 terms ≤ 2^66) | [math], [test: `every_check_rejects_its_violation` "wrap", "more out", "less out", "bridge in/out"] |
| Every witness word used as a field element is canonical-checked before hashing; flags are strict booleans (`boolean()`); `u64` words are split into 16-bit limbs before hashing, so they need no canonical check | [src] `kernel.rs:159-188`, `record.rs:63`; [test: "non-canonical", "non-canonical out", NotBoolean on the dummy flag] |
| User ownership: `nk, ak` derived from witness `sk`; owner recomputed; forging needs a preimage of `Hk(AK/NK,·)` or an `OWNER` collision | [math under Hk], [test: `only_the_owner_can_spend`, "sk", "diversifier"] |
| Record-kind separation: `cm` binds `owner` and `contract`; contract inputs are rebuilt with `owner = 0`, user inputs with the `sk`-derived owner, so neither kind can be spent as the other | [math under Hk CR], [test: "other contract input"] |
| Nullifier determinism: user `nf = Hk(NF, nk‖rho‖cm)` with `nk` bound to `cm` via the owner tag; contract `nf = Hk(NFC, C‖rcm‖cm)` with `C, rcm` bound by `cm`. One record ⇒ one nullifier | [math under Hk CR] |
| Faerie Gold: `rho'_j = Hk(RHO, nf_0‖j)`; `nf_0` is chain-unique because the state inserts **both** nullifiers of every transfer, dummies included (`px/src/state.rs:121-126`, `validate.rs:523-527`) | [math], [src], [test: `a_real_transfer_is_accepted…` (rho differ)] |
| Dummies: value 0, user kind, never approvable; their nullifiers enter the set; a dummy cannot reproduce a victim's nullifier without the victim's `nk` | [src] `kernel.rs:302-318`, [math], [test: "dummy with value", "dummy contract", "approve dummy"] |
| Contract authority: a contract input needs ≥ 1 approval by a function **of the same contract** (`ApprovalMismatch`, `Unauthorized`); a contract output must be specified by a function of its contract; a spec may name only its own contract or 0 (`SpecForeignContract`); ≤ 1 specifier per output (`SpecConflict`); registry is mandatory in `verify` | [src], [test: `contract_rules_reject_their_violations` (12 cases), `lock_then_claim…` (unregistered)] |
| PX-F5: `contract ≠ 0 ∧ owner ≠ 0` output rejected (exit 17), native and pinned guest agree | [test: `a_contract_output_with_an_owner_is_rejected`] |
| `io_hash` layout: `IO_LEN = 8 + 2·9 + 2·29 + 8 = 92` elements matches the absorb sequence; a wrong length would halt through `invalid_input` | [math], [src] `call.rs:53-79` |
| `n_fn` bound: witness `n_fn > 2` → `TooManyFunctions`; tx decode caps functions at `MAX_FN`; `Public::write` and `kernel_budget` are only reached with `n_fn ≤ 2` on the consensus path | [src] `kernel.rs:231-234`, `tx/src/px.rs:325,716` |
| Native/guest agreement on successes and every targeted rejection; random word mutations (400 iters) and a coverage-guided target | [test: `both()` in kernel.rs/unified.rs; `mutated_witnesses_get_the_same_verdict…`; `fuzz_targets/kernel_diff.rs`] |
| Trace shape: fixed per-`n_fn` kernel budgets, verifier accepts only that shape; constant-work code is defence in depth | [src] `prove.rs:52-73`; [test: `successful_executions_have_identical_trace_heights`, `record_kinds_are_not_revealed_by_trace_heights`, `budgets_leave_headroom`] |
| Turnstile/containment: `pool' = pool + b_in − b_out ≥ 0`, `u128`, in block order; independent supply audit | [src] `px/src/state.rs:127-130`, `tx/src/validate.rs:1039-1058`, `tools/supply-audit` |
| v1-side bridge: `Σ pseudo − Σ hidden = (fee + b_in + payouts − b_out)·H`; without v1 inputs `v = 0` exactly | [src] `tx/src/px.rs:732-754` |

### 2.3 What the tests actually prove, and what they do not

- They prove that **specific** witnesses (a plain spend, deposits, withdrawals, a vault LOCK/CLAIM,
  and 20 + 12 + 1 single-violation mutants) get identical verdicts natively and in the pinned ELF.
- They do **not** prove agreement on the function paths beyond those cases: the random and
  coverage-guided differential campaigns start from a **single `n_fn = 0` seed**
  (`fuzz/src/seeds.rs:147-177`, `px/tests/fuzz.rs:29-60`). Mutating the `n_fn` word shifts the
  whole layout, so those campaigns essentially never reach an accepted witness with functions [src].
- Several checks have **no isolated negative test** (§4, F-20-3), so a mutant that deletes them
  would likely survive. [src]
- Because every native test compares against the **pinned** guest ELF, any semantic mutation of
  the native `px-core` source that the corpus exercises is detected as a native/guest divergence.
  This makes the existing differential harness a ready-made oracle for mutation testing (§5, W3).

---

## 3. Independent soundness argument, and the problems in scope

### 3.1 Soundness argument (what an accepted PX proof implies)

**Assumptions.**
- A1: knowledge soundness of the BVM-1 batch STARK for the exact statement (pinned kernel ELF,
  exit 0, exact output words, shaped budgets, `h_tx`) [assumed; roster 22–25].
- A2: **the pinned ELF computes exactly `px_core::kernel::transfer`** on every input (compiler
  correctness for riscv32; the ELF, not the source, is consensus) [assumed; evidenced only by
  differential tests].
- A3: `Hk` collision resistance, preimage resistance, PRF security keyed by `nk` [assumed; roster 19].
- A4: tree binding of depth-32 `node()` from leaf anchoring and fixed depth (≈2^124, R2-C6
  argument, not a proof) [assumed; roster 19/21].
- A5: registry integrity: programs of contract `C` are exactly those in `C`'s deploy, immutable,
  and `C` is fresh (`DuplicateContract`) [src].

**Derived properties** (each [math] given A1–A5, from the code at `9e422d8`):
1. **No inflation within PX.** Every accepted statement satisfies the integer balance; each input
   value is bound by `cm`, which is in the tree (real) or 0 (dummy). Across transactions, value is
   conserved because every record is spent at most once (property 3). Independently of A1–A4, the
   pool bounds withdrawals to deposits (containment).
2. **Authorization.** A user record's spend implies knowledge of a preimage `sk` of its `(ak, nk)`.
   A contract record's spend implies an accepted execution of a program registered to the record's
   contract whose transcript approves exactly that `cm`. A contract record can be created only as
   the exact spec of such an execution, with `owner = 0`.
3. **Single spend.** The nullifier is a deterministic function of the record (`nk` is bound by
   `owner`; `C, rcm` by `cm`); the domains `NF` and `NFC` separate the two kinds; the state accepts a
   nullifier once. A dummy cannot emit a victim's nullifier without the victim's `nk` (A3).
4. **No Faerie Gold.** `rho'` is injective in `(nf_0, j)` except with an `Hk` collision, and `nf_0`
   is globally unique; so no two records share `rho`, and `nf` covers `cm` anyway.
5. **Spec integrity.** Any output a function specifies has exactly its `(owner, contract, value, data)`
   (`rho` from the kernel, `rcm` from the caller); at most one function specifies it.
6. **Binding.** The proof is bound to `h_tx`, which covers every public field, the network and the
   branch; CLSAGs cover the proof.

**What the argument does NOT give (gaps).**
- G1 **An input may be approved by several functions** (F-20-1): "consumed once" holds for the
  record, but not for the *authority* the approval conveys.
- G2 **Per-function / per-contract value conservation is not enforced** (the "value-accounting
  footgun"): only global balance holds.
- G3 **Openings of function-specified outputs are caller-controlled** (PX-F4).
- G4 **A2 is not established**; the source-level claim "no separate circuit that could drift" is true
  only modulo the compiler (F-20-4).
- G5 Tree binding (A4) is an argument, not a proof (roster 19).

**Root cause common to G1–G3.** A function sees only its own private input, never the transaction:
not the other inputs, not the other functions, not `nf_0`/`rho`, not `rcm`, not the bridge terms. In
Zexe, by contrast, every birth and death predicate is evaluated on the transaction's full *local
data* (all consumed and created records' contents, memorandum, auxiliary input) [Zexe, ePrint
2018/962], so a predicate can enforce conservation and uniqueness itself. BlackSilk's
approve-and-specify model trades that power for privacy and a small transcript; the kernel must
therefore enforce the transaction-level rules a function cannot see. It does so for outputs
(`SpecConflict`) but not for inputs (G1).

### 3.2 Problem-by-problem answers

#### (a) Ownership
- **Problem / status:** sound as argued (§3.1-2). Hash-based, post-quantum-friendly; `d` is a free
  witness (wallet policy), which is correct because only the owner tag is committed.
- **Consequence of a break:** theft of user records. None found.
- **Class:** consensus- and privacy-critical.
- **Literature:** Zerocash/Sapling PRF-based nullifiers; Orchard adds a discrete-log component and a
  separate spend-authorization signature (Orchard book, nullifiers and keys). BlackSilk's choice
  (no DL) is the post-quantum one; its cost is R5-13 (no delegated proving), already recorded.
- **Tests that prove it:** existing `only_the_owner_can_spend`, "sk", "diversifier". Add a property
  test: for random `(sk, d) ≠ (sk', d')`, the spend under `(sk', d')` is `NotInTree` (toy and real
  permutation).
- **Invariants never to change:** owner recomputed from `sk` inside the kernel; `nk`-based user
  nullifier; `d` never trusted from the record alone.

#### (b) Balance and the turnstile
- **Status:** correct [math, test]. The pool (`u128`, checked_sub, in block order, atomic, exact undo)
  gives containment independent of the proof system, which is exactly the lesson of ZIP-209 and of
  the two Zcash counterfeiting incidents (BCTV14, CVE-2019-7167; Orchard, disclosed 2026-06-04, "an
  under-constrained element … arbitrary false inputs into an elliptic curve multiplication"): a
  soundness bug is only bounded by pool accounting. BlackSilk has had that rule from day one.
- **Residual:** containment bounds PX→v1 only; inside PX, a soundness break could still
  steal/inflate *within* the pool (e.g. shield-pool dilution). This is inherent (Zcash has the same
  property per pool).
- **Tests:** existing wrap and ±1 cases; add a property test (random values incl. `u64::MAX`,
  random bridge terms) that `Ok ⇔ exact integer equality`, against an independent oracle (W2).
- **Invariants:** `u128` integer sums, never field sums; pool ≥ 0 in order; bridge terms public.

#### (c) Bridge in / out
- **Status:** correct [src]. Both terms are public `u64`, read as two raw words (no canonical check
  needed), matched word-for-word by the verifier. Both may be nonzero in one transaction; the v1
  side and the pool each account them. A PX-only transaction has `b_out = fee + b_in + payouts`, so a
  plain private payment publishes `b_out = PX_STANDARD_FEE`, a constant (no leak).
- **Privacy:** amounts are public by design (containment); documented (px.md §12).
- **Invariants:** bridge terms are statement words, never witness-only values.

#### (d) Function specs and approvals
- **Status:** output side complete (exact match, ≤ 1 specifier, own-contract or user only, F5).
  **Input side has G1 (F-20-1, new).**
- **Consequence of G1:** see F-20-1. Value theft is prevented by global balance in the 2×2 shape;
  what breaks is the **linearity of contract state/authority**: one consumed record can authorize
  two transitions in one transaction.
- **Literature:** the mirror image of Cardano's *double satisfaction* (one output satisfies two
  validators; "the most commonly found issue during audits of Cardano smart contracts"; fix:
  "outputs associated with a given input are only counted once across all possible validations").
  BlackSilk already prevents the output-side form (`SpecConflict`) but not the input-side form.
  Aleo: each transition consumes its own records and publishes their serial numbers; a transaction
  may not repeat a serial number, so one record belongs to exactly one transition.
- **Proposed fix:** exactly one approving function per contract input (new appended error
  `ApprovalConflict`, exit 18). Constant work: one counter per input.
- **Trade-offs:** forbids a (hypothetical) contract that splits one transition's validation of one
  record across two programs; such a contract can put both checks in one program or chain two
  transactions. New kernel id (bundled with the v3 rebuild, which is not yet frozen).
- **Tests:** new mutation case "double approval" (native + guest), a positive case that two
  functions approving **different** inputs still pass, budget re-measure.
- **Invariants:** approvals identify exact `cm`; ≤ 1 specifier per output; a function's contract is
  a checked input tied to the registry (R5-8).

#### (e) PX-F5 (now enforced)
- **Status:** Complete and verified at the level claimed [test: `a_contract_output_with_an_owner_is_rejected`,
  native and pinned guest]. My independent check: the rule makes the input and output sides state
  the same invariant (`contract ≠ 0 ⇒ owner = 0`); it runs before the spec loop, so a buggy spec
  yields exit 17 rather than 13 (fine); it removes the only way a *function* could burn contract
  value silently.
- **Residual (informational, F-20-6):** a *user* output with `owner = 0` (or any tag nobody can open)
  is still accepted: a function spec or a caller can burn a payout. This is not fixable by a rule
  (a random owner burns equally) and needs only an SDK lint.
- **Future:** R5-10 user-owned contract records relax F5 deliberately in a later kernel generation.

#### (f) PX-F4 (deferred)
- **My view: agree with deferral (R5, SX1, I2-F1).** Option B/B′ changes the call format that the
  contract-model redesign (clock, user-owned records, larger shapes) will change again; I2-F1
  requires `rcm` to stay prover-choosable for the contract nullifier's issuer-unlinkability.
- **Independent addition:** F4 is a symptom of the same root cause as G1/G2: the function cannot see
  `nf_0`/`rho` or fix `rcm`, so it cannot bind any delivery to the output's `cm`. Any future
  function-level constrained delivery (Aztec lets contracts "constrain [the tag] inside the circuit")
  needs the kernel to expose `rho'_j` (or `nf_0`) to the function transcript, not only `rcm`. Record
  this as a requirement for B′ (roster 28).
- **Tests when done:** B′ derivation vectors; a caller that garbles the ciphertext cannot make a
  B′-seeded record unopenable by seed holders.

#### (g) The value-accounting footgun
- **Status:** accepted limitation (R5 §2, register "approval not tied to value"). I agree the kernel
  should **not** enforce per-contract conservation: it would need the kernel to attribute value to
  contracts (a per-asset/per-contract balance, cf. ZIP-226/227 per-asset balance for ZSA), which
  forbids legitimate flows (contract-paid fees, partial releases) and adds public structure.
- **But:** the footgun is larger than stated. Combined with G1, even a function that *does* conserve
  its own value (approve V, specify V) can be composed with a second approval of the same record; the
  global balance then makes the *caller* fund the duplicate, so value is safe but state is forked.
  Fixing G1 in the kernel leaves only the single-function footgun, which a host-side `Call` builder
  can check (sum of approved values ≤ sum of specified values of that contract + declared fee flows).
- **Tests:** builder unit tests; every host helper (`px/src/vault.rs`) asserts conservation.

#### (h) `n_fn` bounds
- **Status:** sound on the consensus path [src]. Witness `n_fn` > 2 → exit 9 (**untested**, F-20-3);
  decode caps at 2; `check_px_structure` rechecks.
- **Robustness (F-20-5, informational):** `prove::verify` and `Public::write` index `functions[k]`
  and `kernel_budget(n_fn)` panics for `n_fn > 2`; any non-consensus caller of this public API with a
  hand-built `Public` panics instead of getting `VerifyError::Shape`.

#### (i) Constant-work shape
- **Status:** heights are fixed by budgets and checked by the verifier (the primary defence);
  constant work is defence in depth [src, test]. Budgets have 5–10% headroom (v3-upgrade-mechanism
  §9: `n_fn=0` 24,586/26,500; `n_fn=1` 28,388/31,200; `n_fn=2` 32,020/35,600).
- **Gap (F-20-3):** `budgets_leave_headroom` measures one witness per shape, not the **worst branch
  profile** (both functions approving both inputs, every spec present, contract outputs in both
  slots). Exceeding a budget is a *liveness* failure (the call cannot be proven), never a leak. The
  per-branch difference is tens of cycles, so the risk is low, but a changed kernel (G1 fix, R2-C6)
  must be re-measured with the worst case.
- **Invariant:** the verifier accepts only the exact budgeted shape; no data-dependent loop bounds in
  the kernel.

#### (j) The native/guest differential
- **Status:** strong for the tested corpus; thin for functions (§2.3).
- **The compiler is in the trusted base (F-20-4).** zkSecurity: "if the compiled assembly code does
  not reflect the intended source code logic, this can result in catastrophic security issues";
  Arguzz (arXiv 2509.10819) found 11 soundness/completeness bugs in six production zkVMs by
  metamorphic testing, showing how easily a zkVM stack diverges from intent. For BlackSilk the
  relevant divergence is *source vs pinned ELF*: the consensus rule is whatever the ELF does.
  Mitigations: structure-aware differential fuzzing with function-rich seeds (W2); a spec-level
  N-version oracle (W2); state A2 in the docs (W4). ISA-level formal verification of the ELF is
  research-level (no production tool for this stack) [assumed].

---

## 4. New findings

| ID | Title | Severity | Status | Where | Confidence |
|---|---|---|---|---|---|
| F-20-1 | One contract input may be approved by several functions: one consumption authorizes several transitions (input-side "double satisfaction") | **Medium** (latent; consensus-critical to fix; not exploitable with the vault) | Not implemented | `px-core/src/kernel.rs:313-326` | High (mechanism, [src]); medium (impact depends on future contracts) |
| F-20-2 | The value-accounting footgun is wider than documented: it composes with F-20-1 and with multi-program contracts | Low | Accepted limitation (docs) | `kernel.rs:313-326, 366-386`; px-f4-f5-analysis.md §4a | High |
| F-20-3 | Kernel checks without an isolated negative test; function paths absent from the differential corpora; worst-case branch profile absent from the headroom test | Low (assurance) | Partially implemented | `px/tests/{kernel,unified,fuzz}.rs`, `fuzz/src/seeds.rs:147-177` | High |
| F-20-4 | "What a proof establishes is exactly what `transfer` computes" omits the compiler: the pinned riscv32 ELF, not the source, is the rule | Low (claim accuracy) / Accepted limitation | Accepted limitation (docs owed) | `px-core/src/lib.rs:11-12`; docs/px.md §1, §4.3 | High |
| F-20-5 | `prove::verify` / `Public::write` panic on `n_fn > MAX_FN` instead of returning `Shape` | Informational | Not implemented | `px/src/prove.rs:118-140, 228-243`; `kernel.rs:152-155` | High |
| F-20-6 | User outputs with `owner = 0` (or any unopenable tag) are accepted: a function spec can burn a payout | Informational | Accepted limitation | `kernel.rs:342-387` | High |
| F-20-7 | Spec/doc drift in the kernel's normative texts | Low (docs) | Not implemented | see below | High |

### F-20-1 (Medium): multiple approvals of one contract input

**Code.** `kernel.rs:313-326`:

```rust
let mut approved = false;
for call in calls.iter_mut().take(n_fn) {
    if let Some(a) = call.approve[i].as_mut() {
        if dummy || !is_contract || !digest_eq(&call.contract, &contract) {
            return Err(Error::ApprovalMismatch);
        }
        *a = cm;
        approved = true;   // no count: any number of calls may approve input i
    }
}
```

Every approving call gets `cm` in its transcript; nothing limits approvals per input. On the output
side the analogous rule exists (`specs > 1 ⇒ SpecConflict`, l. 381).

**Scenario (value-0 state, costless).** Contract `C` holds a unique item as a contract record
`N = (owner 0, C, value 0, data = item‖holder)`. Its function `move(N, new_holder)` approves `N`
(slot `i`) and specifies one successor `N'` (slot `j`), a natural single-transition design. A caller
proves one transaction with `n_fn = 2`, both executions of `move`, both approving input 0 (`N`), one
specifying slot 0 = `N'(holder X)`, the other slot 1 = `N''(holder Y)`. Every kernel rule passes: both
approvals are same-contract, real, contract-kind; the specs are on different slots; value 0 + 0 =
0 + 0. Result: **the unique item now exists twice** (distinct `rho`, distinct nullifiers). The same
applies to one-shot "approval records" (R7-2's authorization pattern: one approval record can
authorize two action executions in one transaction), sequence numbers, vote tallies (I2), or any
linear state machine whose transition emits one record.

**Scenario with value.** For value-carrying records the caller must fund the duplicate (global
balance), so no value is stolen in the 2×2 shape; the state is still forked (e.g. a "closed" escrow
continues). The vault is unaffected: two CLAIMs of one vault record must fund the second payout.

**Why it exists.** Functions cannot see each other (§3.1 root cause), and the designers closed the
output-side case (`SpecConflict`) but not the input side.

**Prior art.** Cardano "double satisfaction" (Plutus docs; Vacuumlabs audit series): the canonical
mitigation is that each resource is counted by exactly one validation. Aleo: a record's serial number
is produced by exactly one transition and may not repeat within a transaction. Zexe: each consumed
record's death predicate runs once, on the whole transaction's local data.

**Fix (consensus).** Count approvals per input; `approvals > 1 ⇒ ApprovalConflict` (appended, exit
18). Keep the loop branch-free on success (a counter increment is constant work). New kernel id.

**Alternatives.** (A) Document as a contract-author rule ("specify every output slot, or assume a
co-approving twin"): fragile, silent. (B) Kernel rule (recommended). (C) Give functions a view of all
approvals (Zexe-style local data): larger transcript, privacy cost across contracts, a redesign.

**Tests.** Native + guest case "double approval" in `contract_rules_reject_their_violations`; a
positive case (two functions of one contract approving *different* inputs) stays accepted; budgets
re-measured; a proof-level test is unnecessary (the prover refuses rejected witnesses) but the
differential corpus gets a seed.

**Confidence.** High that the kernel accepts the witness (read directly; the `conflict` test at
`unified.rs:322-331` explicitly clears `f2.approve` to avoid it). Impact on real contracts: medium,
since none exist yet.

### F-20-2 (Low): the value-accounting footgun, restated
Approving a record does not tie its value to any output; additionally (F-20-1) an approval can be
shared, and a contract with several programs can split approval and specification across programs in
one transaction. Recommendation: fix F-20-1 in the kernel; keep per-contract conservation out of the
kernel (agree with R5); a host-side `Call` builder that refuses unbalanced transitions, and an author
checklist (roster 28).

### F-20-3 (Low): assurance gaps in kernel tests
Untested rejections (no case in `px/tests`):
- `TooManyFunctions` (exit 9): never produced by any test (`grep` finds no use outside `kernel.rs`).
- `NotBoolean` on an **approve** flag and on a spec **present** flag (only the dummy flag is tested).
- `SpecMismatch` on the **`data`** and **`contract`** fields (only `owner` and `value` are mutated).
  Dropping `digest_eq(&o.data, &data)` would let a LOCK caller store a different lock than the
  function specified, and I expect no current test to fail.
- `ApprovalMismatch` for a **real user** input (only dummy and foreign-contract approvals are tested;
  the `!is_contract` branch is masked by `DummyContract`/`dummy`).
- `Unauthorized` on the **output** side when a spec with `contract = 0` exists but the output is a
  contract record (reaches `SpecMismatch`; fine, but pin the precedence).
Corpora: `kernel_diff` and `px/tests/fuzz.rs` start from one `n_fn = 0` witness. Headroom: one witness
per shape (§3.2 i).

### F-20-4 (Low / accepted): the compiler in the trusted base
`px-core/src/lib.rs:11-12` and docs/px.md §1 state that there is "no separate circuit description
that could drift". The ELF produced by rustc 1.98.1/LLVM for riscv32 *is* that second description.
The claim should read "no hand-written circuit; the proven statement is the pinned ELF, which is
checked against the native build by differential testing". Evidence to add: W2 campaigns with
execution counts; optionally a second build at another opt level run differentially (tooling only,
no consensus impact).

### F-20-5 (Info): panics on out-of-range `n_fn` in a public API
`verify` checks `calls.len() == public.n_fn` and then indexes `public.functions[k]`; `statement()`
calls `kernel_budget(public.n_fn)`, which panics above 2. Consensus decodes at most 2, so this is not
reachable from the network [src]. Return `VerifyError::Shape` for `n_fn > MAX_FN` (non-consensus).

### F-20-6 (Info): burnable user payouts
A spec or caller may create `contract = 0, owner = 0`. Not a rule candidate (a random tag burns
equally); SDK lint "payout owner must be a derivable address tag".

### F-20-7 (Low): normative-text drift
- `docs/zk.md` §6.3 item 5: "Otherwise, as for dummies, the output is value 0 with a random owner"
  is false (user outputs carry value to any owner); no mention of PX-F5 or `DummyContract`.
- `docs/zk.md` §6.1 lists `program_id_f` among the kernel's public inputs; the kernel does not output
  it (the registry lookup does).
- `docs/zk.md` §7.2: `io_hash` over "(inputs digest, approved, created, public outputs)" and "state
  digest updates": not implemented; the real layout is `call.rs:14-16`.
- `docs/zk.md` §7.1: the pinned kernel "embeds one developer's absolute Windows source path": stale
  since `53d3b49`.
- `px-core/src/record.rs:49-50`: "In v2.0 `contract` and `asset` must be zero": stale for `contract`.
- `px-core/src/kernel.rs:26-30` (module docs): the check list omits PX-F5 and `DummyContract`.
- `docs/px.md` §4.4 and §8 cycle figures predate PX-F5 and the neutral build (re-measure, P0-3).

---

## 5. Implementation plan for phase 2

Order: W1 must precede the single neutral rebuild of the v3 kernel (with the R2-C6 decision), then
W5, then the id pin. W2–W4 can run in parallel with W1.

| # | Work item | Files (ownership) | Externally visible | Identity impact | Tests | Bench | Docs | Diff. | Prio |
|---|---|---|---|---|---|---|---|---|---|
| W1 | **Exactly one approval per contract input** (`ApprovalConflict`, exit 18, appended) | `px-core/src/kernel.rs`; `px/tests/unified.rs` (new cases); rebuilt `px/kernel.elf`, `px/kernel.id` (**rebuild owned by the coordinator/43**, done once, last) | **CONSENSUS** | New kernel id (bundle into v3 before freeze); vault id unchanged | Native+guest "double approval" rejected; two functions approving different inputs accepted; exit-code table test; differential seed | Kernel cycles per shape (tiny) | px.md §4.1, §4.2 table, §7.2; zk.md §6.3 | S | **P0** |
| W2 | **Kernel test completion + structure-aware differential + spec oracle** | `px/tests/kernel.rs`, `px/tests/unified.rs`, new `px/tests/kernel_spec.rs` (an independent plain-Rust oracle of §4.1 over the typed `Witness`, with a random witness generator covering `n_fn` 0–2, approvals, specs, dummies, contract inputs/outputs, bridges; proptest, native only with the toy and real permutations; a sample run in the guest); `fuzz/src/seeds.rs` (kernel_diff seeds with 1–2 functions, contract inputs, conflict and F5 cases); `px/tests/fuzz.rs` (function-rich base witnesses) | none | none | Every error code 2–18 produced in isolation natively and in the guest; oracle ≡ kernel on ≥ 10^5 generated witnesses (native) and ≥ 10^3 in the guest; `TooManyFunctions`, `NotBoolean` (approve/present), `SpecMismatch` (data, contract), user-input `ApprovalMismatch` | Campaign counts recorded | px.md §9.3 | M | **P0** |
| W3 | **Mutation campaign on the kernel** using the pinned-ELF differential as oracle | no source changes; config and run by roster **42** (`cargo-mutants` on `px-core/src/{kernel,call,record}.rs`, oracle: `px` tests `kernel`, `unified`, `kernel_spec`, `fuzz`) | none | none | Target: no surviving mutant in `transfer`, `io_hash`, `Record::commit`, `nullifier`, `output_rho` except documented equivalent mutants | Run time per mutant (native tests only are seconds; guest runs ~ms each) | Evidence file under docs/evidence | M | P1 |
| W4 | **Normative-text and claim corrections** (F-20-4, F-20-7) plus a **contract-author checklist** section (footgun, F-20-1 status, F-4 griefing, F-20-6, "self" contract is a checked input R5-8, never derive `rcm` from public data) | `docs/px.md` §1, §4, §7, §9; `docs/zk.md` §6–§7; doc comments in `px-core/src/{lib,record,kernel}.rs` (comment-only edits; **do not rebuild the ELF for them**: comments do not change the ELF, but confirm with a reproduce run) | none | none (verify id unchanged) | `px/tests/elf_paths.rs` and reproduce stay green | — | as listed | S | P1 |
| W5 | **Worst-case branch witnesses in `budgets_leave_headroom`**; re-measure after W1 (and R2-C6 if adopted); set budgets | `px/tests/unified.rs`; `px/src/prove.rs::kernel_budget` (budget constants: **consensus**, same rebuild window as W1) | CONSENSUS only if budgets change | Budgets are part of the statement shape | Max-approval/max-spec witnesses for `n_fn` 1, 2 at ≤ 95% | Cycles and table heights per shape | px.md §4.4, §8 | S | **P0** (with W1) |
| W6 | `verify`/`statement` return `Shape` for `n_fn > MAX_FN`; `Public::write` debug-guard | `px/src/prove.rs` | none | none | Unit test with `n_fn = 3` returns `Shape` | — | — | S | P2 |
| W7 | Host `Call` builder with conservation and slot checks (F-20-2, F-20-6) | new `px/src/call_builder.rs` + `px/src/vault.rs` using it (**coordinate with 28**, who owns the contract model) | none | none | Refuses unbalanced/owner-0 payouts; vault helpers pass | — | author guide | M | P2 |
| W8 | Kernel generation items (B′ with `rho` exposed to the transcript, R5-10, clock, shapes) | px-core, call format (**28 leads**) | CONSENSUS | New ids | Per item | Proof sizes | contracts.md | L | P3 |

Invariants that every item above must keep: the §6 "never change" list of R5 (hash-based ownership,
`nk` nullifiers, `u128` balance, `rho` from `nf_0`, `nf` binding `cm`, `asset` in `cm`, one kernel
source with a pinned ELF id, fixed shapes, pool containment, mandatory registry, canonical checks,
depth 32 and block-end anchors) plus: **error codes are append-only**; every kernel change is
re-measured against the budgets before the id is pinned.

---

## 6. Dependencies and conflicts

- **19 hash-domain-separation:** R2-C6 (feed-forward) is the other pending kernel change; W1 and
  R2-C6 must share **one** rebuild and one re-measure (W5). A new error needs no new domain.
- **21 px-nullifiers-commitments:** my single-spend argument relies on their nullifier/anchor analysis;
  no file overlap (they own `px/src/state.rs`, `tx/src/state.rs`).
- **22 px-proof-system / 25 zk-soundness:** assumption A1; the widest two-function proof must be
  re-measured after W1/W5 (P0-3).
- **23 zkvm-bvm:** assumption A1 for the ISA/syscall tables; the `SYS_READ` trap past end of input is
  relied on.
- **26 zk-privacy:** P-5 must be re-run on the rebuilt kernel.
- **28 private-contracts-px:** owns the contract model, F4 B′, the author checklist placement and W7;
  F-20-1's fix changes the rules they document. Agree on who writes px.md §7.
- **41 fuzzing:** W2 seeds in `fuzz/src/seeds.rs` (shared file: coordinate edits).
- **42 mutation-formal:** runs W3; my oracle test (W2) is their px-core oracle.
- **43 ci-reproducibility:** owns the single neutral rebuild and cross-OS id reproduction after W1/W5.
- **40 testnet-genesis:** the kernel id enters the v3 identity; W1 must land before the freeze.
- **47 docs-spec-consistency:** W4 edits in `docs/px.md`/`docs/zk.md`.

## 7. Open questions for the coordinator

1. **Accept F-20-1 as a v3 consensus item?** It is cheap (one counter, one appended error) and the
   kernel is being rebuilt anyway (R2-C6 decision pending). If the owner declines, W4 must document it
   as a contract-author rule and W7's builder must refuse co-approval.
2. Who owns the single kernel rebuild and budget re-pin (W1+W5 with 19's R2-C6)? I propose 43 builds,
   20 re-measures and edits `kernel_budget`.
3. Is `proptest` acceptable as a dev-dependency of `px` (the brief says it is usable), and may the
   oracle test run a sample of generated witnesses in the guest interpreter in CI (≈ ms each)?
4. Should `docs/zk.md` §6–§7 be rewritten to match the implementation or marked "superseded by
   px.md" like §5.1? (47/28 overlap.)

## 8. Sources

- Bowe, Chiesa, Green, Miers, Mishra, Wu, *Zexe: Enabling Decentralized Private Computation*, IEEE S&P
  2020, ePrint 2018/962: https://eprint.iacr.org/2018/962 (predicates evaluated on the transaction's
  local data: all records consumed and created, memorandum, auxiliary input).
- ZIP 209, *Prohibit Negative Shielded Chain Value Pool Balances*: https://zips.z.cash/zip-0209
- Zebra book, value pools RFC: https://zebra.zfnd.org/dev/rfcs/0012-value-pools.html
- Zcash Community Forum, *The Orchard Counterfeiting Vulnerability—And Next Steps* (2026-06):
  https://forum.zcashcommunity.com/t/the-orchard-counterfeiting-vulnerability-and-next-steps/56015
- Electric Coin Co., *Zcash Counterfeiting Vulnerability Successfully Remediated* (CVE-2019-7167) and
  *Fixing Vulnerabilities in the Zcash Protocol* (Faerie Gold): https://electriccoin.co/blog/fixing-zcash-vulns/
- Orchard book, nullifiers: https://zcash.github.io/orchard/design/nullifiers.html
- ZIP 227 issue #955, ρ uniqueness in issuance actions (derive ρ from txid and index; add to the
  nullifier set): https://github.com/zcash/zips/issues/955
- Plutus documentation, common weaknesses, *Double satisfaction*:
  https://plutus.cardano.intersectmbo.org/docs (mirror of the page:
  https://github.com/cardano2vn/plutus/blob/main/doc/reference/common-weaknesses/double-satisfaction.rst);
  Vacuumlabs, *Cardano Vulnerabilities #1 — Double Satisfaction* (pointer):
  https://medium.com/@vacuumlabs_auditing/cardano-vulnerabilities-1-double-satisfaction-219f1bc9665e
- Aleo developer documentation, inclusion proofs and serial numbers:
  https://developer.aleo.org/concepts/advanced/inclusion_proof/
- Aztec documentation: note discovery and constrained tags
  https://docs.aztec.network/developers/docs/concepts/advanced/storage/note_discovery ; private kernel
  (siloing by contract address) https://docs.aztec.network/protocol-specs/circuits/private-kernel-tail
- zkSecurity, *zkVM Security: What Could Go Wrong?*: https://blog.zksecurity.xyz/posts/zkvm-security/
- Hochrainer, Wüstholz, Christakis, *Arguzz: Testing zkVMs for Soundness and Completeness Bugs*,
  arXiv 2509.10819: https://arxiv.org/abs/2509.10819
- cargo-mutants: https://mutants.rs/ , https://github.com/sourcefrog/cargo-mutants
