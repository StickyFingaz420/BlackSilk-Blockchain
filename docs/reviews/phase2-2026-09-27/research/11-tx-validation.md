# 11 tx-validation: research dossier (phase 2, phase 1)

**Internal engineering research. Not an audit.** Nothing here claims that BlackSilk, or any
part of it, is secure, audited, proven or production-ready. This work was read-only: no
builds and no tests were run by this agent.

- **Agent:** 11 tx-validation.
- **Commit:** `9e422d8` (`git rev-parse --short HEAD` on `rebuild/core`; the v3 candidate is
  merged into it).
- **Date:** 2026-09-27.

---

## 1. Scope and what I read

**Roster scope:** `tx/src/validate.rs`, `tx/src/px.rs` (structure), `tx/tests/validation_order.rs`,
and the T/C rules of `docs/transactions.md`. **Roster questions:**
1. Are the stateless/contextual classification and the rule set complete and right?
2. Is the PX output-word encoding (the docs are said to require field-canonical words; the
   code reads raw `u32`) a consensus decision?
3. Is `TreeFull` unreachable?

**Code read in full:**
- `tx/src/validate.rs` (1,132 lines);
- `tx/src/px.rs` (824);
- `tx/src/types.rs` (524);
- `tx/src/params.rs`;
- `tx/src/state.rs`;
- `tx/src/lib.rs`;
- `px/src/state.rs`;
- `px/src/prove.rs` (`statement`, `verify`, `prove`).

**Code read in part:**
- `tx/src/builder.rs` (`max_weight`, `standard_fee`);
- `px/src/tree.rs` (capacity);
- `px-core/src/kernel.rs` (`Public::write`, `elem`);
- `px-core/src/call.rs` (`function_prefix`);
- `zkvm/src/air/memory.rs` (`output_preprocessed`, `output_eval`, `image_preprocessed`);
- `zkvm/src/air/util.rs::bytes`;
- `zkvm/src/air/trace.rs` (`public_values`, tables);
- `zkvm/src/prove.rs::statement_digest`;
- `zkvm/src/exec.rs` (`WRITE`);
- `zk/src/config.rs::challenger`;
- `zk/src/lib.rs::check_canonical_form`;
- `chain/src/manager.rs` (block connect, 940–975);
- `p2p/src/net.rs` (2260–2380: admission and scoring).

**Tests read:**
- in full: `tx/tests/validation_order.rs` (1,058 lines);
- test names and relevant bodies: `adversarial.rs`, `malleability.rs`, `px_consensus.rs`,
  `deploy_rules.rs`, `upgrade.rs`, `revalidate_after_extension.rs`, `transfers.rs`,
  `chain_integration.rs`, `fuzz_decode.rs`, `privacy.rs`;
- `chain/tests/golden.rs` (names).

I also grepped every `TxError`/`BlockError` variant across `tx/tests`, `chain/tests` and
`p2p/tests` (§2.4).

**Docs read:**
- `docs/transactions.md` §4 (format), §5, §8 (rules), §15, §16;
- `docs/px.md` §4.2–4.4, §7.2, §11;
- `docs/zkvm.md` §5–§6.1;
- `docs/p2p.md` §10 (scoring rows);
- `AUDIT.md:880–905` (ZK-3c);
- `docs/reviews/zk-security-review.md` §3.3.

**Reviews read:**
- `docs/reviews/full-review-2026-09-27.md` (the §1 summary and every register row about
  tx, TreeFull or output words);
- `docs/reviews/autonomous-session-2026-09-27.md` (all);
- `R6-tx-mempool.md` (all);
- the rows about TreeFull and output words in R1, R5, R7, R10, R15 and R16;
- the SX1 and SX2 rows on R6 and P0-1(f);
- the original brief's "known items" list (`C:/bszkeval/review-brief.md:125–131`), which is
  where the output-word item comes from;
- the neighbouring dossiers 10, 13 and 01 (headings and ownership notes only).

---

## 2. Current state

### 2.1 Architecture of the rules (what exists)

| Layer | Where | Rules |
|---|---|---|
| Strict decode | `types.rs:384-419`, `px.rs:301-369`, `524-550`, `codec.rs` | Version, kind, per-kind size cap, bounded counts (inputs, outputs, payouts ≤ 16, functions ≤ `MAX_FN`, output words ≤ 256, programs 1–16, ELF ≤ 256 KiB, budgets ≤ 2^22), canonical points, scalars and varints, digests `< p`, fixed 1,241-byte ciphertexts, no trailing bytes |
| Stateless structure | `validate.rs:301` `check_structure`; `px.rs:644` `check_px_structure`; `px.rs:787` `check_deploy_structure` | T1, T3–T8, T10 shape, T11; PX counts, sorting, cross-list key uniqueness, distinct nullifiers, exact PX fee; deploy: v1 structure, exact fee, provable budgets, loadable and distinct programs |
| Stateless crypto | `check_balance`, `check_px_balance`, `check_range_proof` | T9, T10 |
| Contextual | `check_uniqueness_of`, `check_px_state`, pool, `resolve_input_rings`, `check_ring_signatures` | C2, C4, PX1–PX3, PX4, C1, C3 |
| PX5 | `check_px_proof` | Proof against the registered programs and budgets, bound to `h_tx(domain)` |
| Block | `validate_block_transactions_cached` | B1, B2, B7, structure, B5, B6 (v1 weight, the 8 MiB PX bytes, the 1 MiB deploy bytes), B3, T9, C2/C4/PX1–4 with block-wide sets, C1/C3, a BP+ batch, PX5 (with the mempool proof cache) |
| Classification | `TxError::is_stateless` (exhaustive match, `validate.rs:245`), `is_stateless_at` (`:807`) | Drives P2P penalties (`p2p/src/net.rs:2289`, `:2354`) |

### 2.2 What is correct and well designed

1. **Stateless before contextual in every mempool path, with PX5 last.**
   - `validate_transfer`, `validate_deploy` and `validate_px_without_proof` run
     structure → balance → range proof before any chain query.
   - The PX5 exception is deliberate and safe: the proof is verified only after PX1–PX4
     and C1/C3 pass, so a cheap contextual failure can never force proof work.
   - Evidence: tested (`a_stateless_error_never_follows_a_contextual_check`,
     `bad_range_proof_with_bad_signature_is_stateless_and_touches_no_chain_state`, and
     the deploy and PX variants, which assert zero chain queries).
2. **Verdict neutrality of the reorder** (R6 TX-1 and TX-3 fixed in `b33a1ce`).
   - A differential over about 45 corpus entries on two chain states checks that the new
     mempool path, a verbatim copy of the old path, and block validation give the same
     verdict.
   - Evidence: tested (`verdicts_are_unchanged_over_a_corpus_on_two_chain_states`).
   - The corpus is hand-written, so this is not a proof of equivalence; see F11-5.
3. **Classification is complete and exhaustive at compile time.**
   - `is_stateless` is an exhaustive `match`.
   - `every_error_variant_is_classified` pins all 36 variants.
   - I re-derived each row (§3.1): every "stateless" variant is a function of the
     transaction bytes plus per-network constants. Every "contextual" one depends on
     branch state.
   - Evidence: source-read plus tested.
4. **Masking resistance.** This analysis is new here; it explains why the ordering
   matters and is not cosmetic.
   - Bitcoin Core 30.0 stopped penalizing consensus-invalid transactions altogether
     (PR #33050). The reason: an attacker could always make a consensus failure look
     like an unpunished non-standardness failure by tripping that check first, so the
     penalty gave no DoS protection.
   - In BlackSilk every stateless rule runs before any contextual one. An attacker can
     therefore **not** mask a stateless fault behind a contextual one to escape the
     penalty.
   - The only stateless rule behind contextual ones is PX5. Masking it (for example with
     a stale anchor) only skips the proof verification, so the attacker gains no free
     CPU.
   - The remaining free CPU is `InvalidSignature` over young rings. It is bounded by the
     per-peer input budget in P2P, not by the classification (see
     `validate.rs:233-244` and `SIGNATURE_BURIAL`).
   - Evidence: source-read.
5. **The PX side of apply matches validation, except for capacity.**
   - `px/src/state.rs::apply_inner` can fail with `UnknownAnchor`, `DoubleSpend`,
     `PoolUnderflow` and `TreeFull`.
   - Block validation checks the first three with the same semantics: the anchor is in
     the parent's window; nullifiers are unique across the chain and the block; the pool
     evolves in block order and is checked.
   - `TreeFull` is **not** checked (F11-2).
   - Evidence: source-read; tested for the three (`px/tests/state.rs`, `px_consensus`).
6. **Canonical encodings.**
   - Digests are read with `< p` (`read_digest`, `px.rs:110`).
   - Output words are fixed 4-byte little-endian (`px.rs:258`, `:334`).
   - Every varint is minimal.
   - There is exactly one encoding per decoded value.
   - Evidence: tested (`fuzz_decode`, `malleability` for transfers and coinbase);
     source-read for PX and deploys.
7. **Every rule is scoped by domain.**
   - Transfer, deploy and PX signature messages and `h_tx` all commit to
     `LE32(network_id) ‖ LE32(branch_id)`.
   - Evidence: tested (`every_message_and_the_px_binding_commit_to_branch_and_network`,
     `cross_network_replay_is_rejected`).
8. **Activation grace.** `is_stateless_at` reclassifies `PxProof` as contextual within
   ±60 blocks of an activation, and P2P does the same for `InvalidSignature`.
   - Evidence: tested (`px_proof_failures_are_contextual_near_an_activation`).
   - This is the right idea, but it is incomplete for structural rules (F11-3).

### 2.3 What the tests prove, and do not prove

- **Proved:**
  - one negative case per T and C rule for transfers (`adversarial.rs` t3…c4);
  - the deploy rules (`deploy_rules.rs`, 9 tests);
  - PX value creation and anchors (`px_consensus.rs`, proving);
  - order and classification (`validation_order.rs`);
  - extension-only revalidation (`revalidate_after_extension.rs`, 10);
  - the upgrade domain (`upgrade.rs`, 8).
- **Not proved:** see the per-variant coverage in §2.4 and the missing golden vectors
  (F11-5).
- There is no **generated** differential. The mempool and block compositions agree only
  on the hand-written corpus. This matters because the lesson of CVE-2018-17144 is exactly
  a divergence between the mempool and block paths over an intra-transaction duplicate
  (Bitcoin Core skipped the duplicate-input check in block validation, which enabled a DoS
  and, in 0.15–0.16.2, inflation).

### 2.4 Per-rule test coverage (grep count of each asserted error in `tx/`, `chain/`, `p2p/` tests)

**Fully or adequately covered (≥ 3 assertions with the exact variant):**
- every T/C transfer variant;
- `PxFeeNotStandard`, `PxUnknownAnchor`, `PxNullifierSpent`, `PxUnregistered`, `PxProof`;
- `PxDuplicateOutputKey`, `PxNullifierRepeated`, `PxDuplicateProgram`, `PxBudgetTooLarge`,
  `DeployFeeNotExact`, `DuplicateContract`;
- `CoinbaseAmount`.

**Uncovered or covered only weakly:**

| Variant | Assertions | Gap |
|---|---|---|
| `BlockError::CoinbaseOutputCount` | 0 | No test for 0 or 17 coinbase outputs through the validator (decode catches it, but the validator is the rule of record) |
| `BlockError::CoinbaseEphemeralIdentity` | 0 | — |
| `BlockError::CoinbaseDuplicateOneTimeKey` | 0 | No test of a coinbase `O` equal to an **on-chain** key (sorting cannot catch that), nor of a later transaction in the block reusing a coinbase key |
| `BlockError::PxBytesExceeded` | 0 | The 8 MiB PX budget has no boundary test (the deploy budget has one) |
| `TxError::PxShape` | classification only | No transaction with `functions.len() > MAX_FN` through `check_px_structure` |
| `TxError::PxInvalidProgram` | classification only | The corpus entry "deploy bad program" checks the verdict, not the variant |
| `TxError::WeightOverflow` | classification only | Unreachable (weight ≤ ~104 k); should be documented as defensive |
| `TxError::PxPoolUnderflow`, in-block order | revalidation only | No block with two PX transactions, each valid alone, that together underflow |
| `BlockError::UnexpectedCoinbase`, `CoinbaseHeight`, `WeightExceeded`, `RangeProofBatch`, `CoinbaseOutputKeyIdentity` | 1 each | Adequate as smoke tests; no boundary cases (weight exactly at the limit) |
| PX2 across two transactions of one block | not found | Nullifier reuse between two transactions of one block |
| PX3 within one block | not found | A deploy and a call to it in the same block (must fail `PxUnregistered`: "usable from the next block") |
| `DuplicateContract` within one block | not found | Two identical deploys (they also share a key image, so C2 fires first; needs a crafted case) |

### 2.5 Evidence classes in brief

- Classification correctness: source-read plus tested.
- Order: tested.
- Verdict equivalence of the mempool and block paths: tested on a corpus only.
- Output-word soundness: source-read (§3.2).
- TreeFull reachability: mathematically estimated, from a measured proof size (§3.3).

---

## 3. The problems in scope

### 3.1 Classification and rule completeness (roster Q1)

**The problem.** `is_stateless` decides peer penalties. It must be:
- **sound**: never penalize an honest relay;
- **useful**: penalize what is provably the sender's fault.

**Row-by-row re-derivation.** All 36 variants hold under the current single-epoch schedule.
The non-obvious rows:
- **`PxProof` is stateless.** The statement is `(Public(tx), registered (program, budget)
  per function, h_tx(domain))`.
  - `Public` and `h_tx` are functions of the transaction and the domain.
  - A registry entry is fixed by `(contract id, program id)`, and the contract id hashes
    the whole payload (`px.rs:593`, 248 bits taken mod p, so about 124-bit collision
    resistance).
  - PX3 is checked first, so a stateless `PxProof` is only ever reported when the entries
    exist.
  - Correct.
- **`InvalidSignature` is contextual.** Ring indices resolve per branch. This is correct.
  Monero's verification cache for the same reason keys input verification on the
  transaction together with its **dereferenced** ring data (`make_input_verification_id`
  in `tx_verification_utils.h`). The depth-based penalty in P2P (60 blocks) is the sound
  refinement.
- **`PxUnregistered` for contract 0 or a zero contract.** Contextual, although such a
  contract can never exist (the chance that a contract id is all zeros is 2^-248).
  Negligible imprecision (Accepted).
- **`FeeTooLow`, `TooLarge`, `PxFeeNotStandard`, `DeployFeeNotExact`, `PxBudgetTooLarge`**
  depend on rule parameters: `fee_per_weight`, the size caps, `kernel_budget(1)` and
  `MAX_CYCLES`. They are stateless **only because there is one epoch**. See F11-3.

**Rule completeness against the spec (T1–T11, C1–C4, PX1–PX5, B1–B7):**
- Every spec rule is implemented.
- Implemented rules that the spec does not enumerate as numbered rules:
  - `PxDuplicateOutputKey` and `PxNullifierRepeated`;
  - the cross-field PX counts;
  - the ciphertext length;
  - the output-word count;
  - `k > 0 ⇒ n > 0`;
  - the deploy rules (listed in px.md §11.3 prose).
- One rule is **missing** from both: PX tree capacity (§3.3).

**Consequences.** No wrong verdict exists today. The gaps are:
- latent classification under multi-epoch schedules (F11-3);
- a spec that is not complete enough for a second implementation (F11-6).

**Consensus-critical?** The classification is P2P policy only; the rules are consensus.

**Prior art.**
- Zebra separates "semantic" verification (consensus rules checkable without chain state,
  in `zebra-consensus`) from "contextual" verification (in `zebra-state`). BlackSilk's
  split is the same idea.
- Monero splits `ver_non_input_consensus` / `ver_mixed_rct_semantics` from the input
  proofs over dereferenced rings (`ver_input_proofs_rings`).
- Bitcoin Core's `TxValidationResult` separates `TX_CONSENSUS` from context
  (`TX_MISSING_INPUTS`, `TX_PREMATURE_SPEND`, `TX_CONFLICT`). Its former
  `*_RECENT_CONSENSUS_CHANGE` states were exactly BlackSilk's activation grace. They were
  removed with the move to no transaction penalties at all (#31269, #33050).

**Tests that prove it.**
- A property test: for random mutations of valid transactions of every kind, any error
  that `is_stateless()` calls stateless is also raised by the same transaction against a
  **different** random chain state (a second `MemoryChain` built from another seed) and at
  another height. That turns the definition "on every branch, at every height" into an
  executable check.
- The per-rule vectors of item I1.

**Invariants that must never change:**
- stateless rules run before any chain query in the mempool paths;
- PX5 runs only after PX1–PX4 and C1/C3;
- the classification match stays exhaustive;
- a contextual error is never penalized outside the depth rule.

### 3.2 PX function output words: field-canonical or raw `u32`? (roster Q2)

**The problem as registered.**
- The original brief's known list said: "PX function output words: docs say
  field-canonical, code reads raw u32" (`C:/bszkeval/review-brief.md:130`).
- This became register row D12 ("pick one and document it; either is a rule"), SX2
  P0-1(f) and R15 A2.

**What the docs actually say.** I searched every tracked document.
- **No document requires function public output words to be field-canonical.**
- The only "canonical field elements" statement about "input and output words" is
  `AUDIT.md:902` (ZK-3c) and `zk-security-review.md:134`. Both describe the **Poseidon2
  syscall's** 16-word buffer, which is a BabyBear state and must be `< p`
  (`docs/zkvm.md` §5, `POSEIDON2` row: "Each word must be a canonical field element,
  **else trap**").
- `docs/px.md` §4.2 says that "every element **read as a field element** must be
  canonical". That is about the kernel's witness words.
- The item is a **misattribution**. The docs do not contradict the code; they are only
  silent about function output words.

**What the code and circuit do** (source-read, end to end):

| Layer | Encoding of an output word `w` | Injective? |
|---|---|---|
| Transaction codec | `w.to_le_bytes()` exactly 4 bytes; decode `u32::from_le_bytes` with no range check (`px.rs:258-260`, `:333-335`) | Yes: one encoding per `u32` |
| Tx id, `h_tx`, signature message | The prefix bytes above | Yes |
| Guest | The `WRITE` syscall appends the 32-bit register `a0` (`exec.rs:342-345`) | — |
| AIR | The `OUTPUT` table's preprocessed rows are `(index, b0, b1, b2, b3, is_real)` with `b_i = Val::from_u8(byte_i(w))` (`memory.rs:40-70`, `util.rs:188`). The CPU's output message carries the register's range-checked bytes (zkvm.md §6: "Words are 4 bytes … because a 32-bit word does not fit in the 31-bit field") | Yes: byte limbs < 256 never wrap |
| Fiat–Shamir | `statement_digest` hashes the periodic and preprocessed columns via `as_canonical_u32` (`zkvm/src/prove.rs:67-91`). The limbs are canonical, so the digest is injective in `w`. It is absorbed before any challenge (`zk/src/config.rs:69-86`) | Yes, which excludes the "unfaithful claims" / Frozen-Heart class (OtterSec 2025–26) for outputs |
| Kernel's own outputs | `Public::write` already emits raw 32-bit halves of `bridge_in` and `bridge_out` (`kernel.rs:141-155`), which can be ≥ p | The convention is system-wide: **public output words are machine words, not field elements** |

**Decision (recommended): keep raw `u32` and document it as normative.** Close D12 and
SX2 P0-1(f) as "no consensus change".

Reasons:
1. **Soundness.** No aliasing exists. The known aliasing bug class (a value and value + p
   mapping to one field element: circomlib `Num2Bits`, 0xPARC zk-bug-tracker) needs a
   field-element representation. Words here are 4 range-checked bytes at every layer.
2. **A field-canonical rule would be a restriction with no benefit.**
   - It would reject every function that `WRITE`s a value in `[p, 2^32)`: about 53% of
     the `u32` space (p ≈ 2.013·10^9), for example −1 as `i32`, packed bytes, or hash
     words.
   - An honest function would then have proofs that verify at the zkVM level but whose
     transaction fails a decode rule. That is a liveness trap for contract authors and a
     new consensus rule to test.
   - It would also be inconsistent with the kernel's own raw words.
3. **Prior art.**
   - RISC Zero's journal is a byte string whose SHA-256 digest enters the receipt claim.
   - SP1 commits public values as bytes (`commit_slice`), with a SHA-256 or Blake3 digest.
   - Neither exposes public outputs as field elements to the application.
   - BlackSilk's raw words match this model.
4. **Consensus identity.** Keeping the current behaviour changes nothing. Adopting
   field-canonical would be a CONSENSUS narrowing and would need the full 12-step
   discipline for zero security gain.

**What could go wrong with keeping it?** Only mis-interpretation by host code: a contract
helper that feeds output words into `Hk` as field elements without reducing them. That is
a contract-tooling rule. `px::vault` reads only the selector (0 or 1).
- Document: "host code must not treat output words as field elements; use
  `px_core::canonical` or a byte encoding".

**Tests that prove it:**
- a zkVM-level test (roster 23 owns `zkvm/tests`): a tiny assembled program `WRITE`s
  `0xFFFF_FFFF`, `p`, `p − 1`, `0x8000_0000`. It proves and verifies, and it is rejected
  when any claimed word is changed to `w ± p (mod 2^32)`, `w ^ 1`, or when the output
  count changes;
- a tx-level vector: a PX transaction with such words round-trips through the codec, and
  its id and `h_tx` are pinned (golden);
- a decode test that `outputs.len() = 257` fails `CountOutOfRange`.

**Invariants:**
- one 4-byte little-endian encoding per word;
- words covered by `h_tx` and the tx id;
- the byte-limb `OUTPUT` table;
- the statement digest absorbed before the first challenge.

### 3.3 `TreeFull` (roster Q3)

**The problem.** `px/src/state.rs:135-138` fails with `StateError::TreeFull` after 2^32
leaves (`tree.rs:18`, `CAPACITY = 1 << TREE_DEPTH`). Block validation does not check
capacity. `MemoryChain::apply_block` then `expect`s success (`tx/src/state.rs:205-208`), and
so does `chain/src/manager.rs:955` through it. So the first block that overflows would
**panic every node at the same height**: a global halt (R1, R10).

**Is it unreachable today?** Yes, by a wide margin; mathematically estimated:
- Each PX transaction appends exactly 2 leaves, and each must carry a proof that verifies.
- Measured honest proofs are 2.03–2.05 MB (px.md §4.4). The fixed shape and the fixed
  query count leave the prover no way to shrink one materially. Grinding the query-PoW
  witness to make queries collide saves only pruned Merkle nodes, a few percent at most
  [assumed].
- So at most ⌊8 MiB / ~1.9 MB⌋ = 4 PX transactions fit per block, which is ≤ 8 leaves
  per block.
- Hence ≥ 2^32 / 8 = 2^29 blocks ≈ 2,040 years at 120 s. Even at a hypothetical 1 MB
  proof it would be ≥ 1,000 years.
- The existing claim ("≤ 4,320 leaves per day", R5) agrees.

**Why it still matters:**
1. **Unreachability rests on a non-consensus quantity:** the minimum size of a valid
   proof. A future verifier upgrade (Plonky3 0.8, recursion or aggregation: register P3,
   I4) that shrinks PX transactions to about 10 KB allows ≈ 8 MiB / 10 KB ≈ 838
   transactions, which is ≈ 1,677 leaves per block. That is 2^32 / 1,677 ≈ 2.56 M
   blocks ≈ **9.7 years**. The capacity rule must exist before such an upgrade, and adding
   it later is a separate activation.
2. **The failure mode is the worst possible one:** a deterministic crash of every honest
   node, not a rejected block.
3. **Prior art: Zcash makes it a consensus rule.** The protocol spec says: "A block MUST
   NOT add Orchard note commitments that would result in the Orchard note commitment tree
   exceeding its capacity of 2^MerkleDepth^Orchard leaf nodes", and likewise for Sapling
   and Sprout. Zebra returns `NoteCommitmentTreeError::FullTree` as a block error
   (`zebra-chain/src/orchard/tree.rs`) and never panics.

**Consensus-critical?** Yes (liveness). It is a narrowing rule that no reachable chain can
trigger.

**Proposed solution (item I3):**
- `ChainView::px_tree_size() -> u64`, implemented by `MemoryChain` from
  `px.size()`.
- Block phase: `size + 2·(#PX txs) ≤ CAPACITY`, else `BlockError::PxTreeFull`.
  Checked with the other B6 budgets, before any cryptography.
- Mempool: `size + 2 ≤ CAPACITY`, else `TxError::PxTreeFull`, **contextual**.
- `MemoryChain::apply_block` returns a `Result` (or the manager fail-stops with a clear
  message) instead of panicking. That is defence in depth for R16-6 ("validate, then
  `expect`").

**Trade-offs and what could go wrong:**
- It formally adds a consensus rule, so it must ride the v3 reset (cheap now, since the
  testnet has not launched).
- Once the tree is full, PX is closed until a new-tree epoch is designed (Zcash's answer
  is new pools per upgrade). That is a known end-state, documented, and far off.
- The risk of the change itself is an off-by-one. Test it at `CAPACITY − 2`,
  `CAPACITY − 1` and `CAPACITY`.

**Tests:**
- a test-only `Frontier` or `State` constructor at a given size (`px/src/tree.rs`, owned by
  21), to place the tree at `2^32 − 3` and apply one, two, then three PX transactions:
  - exact-boundary accept and reject;
  - the mempool contextual error;
  - no panic anywhere;
  - `validate(block) = Ok ⇒ apply(block) = Ok`, as a property over random PX blocks.
- `apply_block` and `undo` must be exact at the boundary.

**Invariants:**
- validation is a superset of every failure condition of `apply_block` (make this an
  explicit, documented invariant);
- the anchor is "end of an earlier block";
- the tree depth is 32.

### 3.4 Structure checks are not total over in-memory transactions (defence in depth)

**The problem.**
- Several limits exist only in decode:
  - `MAX_PAYOUTS` (`px.rs:304`);
  - `MAX_FN_OUTPUT_WORDS` (`:331`);
  - ciphertext length exactly `CIPHERTEXT_BYTES` (`:321-324`);
  - program count and ELF size (`:529-532`);
  - the budget ≤ 2^22 (`read_budget`), subsumed by `budget_is_provable`.
- `check_px_structure` and `check_deploy_structure` accept in-memory values beyond them.
- Worse, ciphertexts are written **without a length prefix** (`px.rs:249-251`). Two
  distinct in-memory transactions, with ciphertexts `([a‖b],[c])` and `([a],[b‖c])`, have
  identical prefix bytes, hence the **same tx id and `h_tx`**.

**Security consequence today:** none found.
- Every external ingress decodes first: P2P at `net.rs:2140`, RPC at `node/src/lib.rs:275`,
  blocks at `chain/src/block.rs:73`.
- `MemoryChain`'s own test uses 3-byte ciphertexts (`state.rs` tests), which shows that the
  type admits them.

**Risk.** A future path (a JSON RPC, a wallet self-check, an embedded library user) that
validates a non-decoded transaction would get "valid" for an object whose encoding is a
different transaction.

**Solution (item I4):**
- Add the missing checks to the `check_*_structure` functions (stateless variants that
  already exist: `OutputCount`, `PxShape`, `TooLarge`).
- Add the invariant test "`validate_*(tx) = Ok ⇒ decode(encode(tx)) == tx`" for every kind,
  over the corpus and random mutations.

**Identity impact:** none. For every decodable transaction the new checks are implied by
decode, so no block's verdict changes. The argument is that decode ⊆ the new checks; a
fuzz test over `Transaction::decode` outputs confirms it.

### 3.5 Other items

- **Scheduled rules versus "stateless" (F11-3).**
  - `is_stateless` is defined as "invalid on every branch, at every height". Once a second
    epoch exists, any rule whose parameters change at the activation (fee rate, size caps,
    `PX_STANDARD_FEE` through `MAX_PROOF_BYTES`, kernel budgets) makes its "stateless"
    error height-dependent near the boundary.
  - Only `PxProof` (and, in P2P, `InvalidSignature`) is relaxed today.
  - The P2P cheap path uses `is_stateless()`, not `_at` (`net.rs:2289`).
  - `deploy_fee` uses the constant `FEE_PER_WEIGHT`, not `rules.fee_per_weight`
    (`px.rs:477`), and `TxRules::at_height` hard-codes the constant (`params.rs:124`).
    So a fee-rate change by schedule would be silently partial.
  - Fix: within `ACTIVATION_GRACE_BLOCKS`, **every** `TxError` is contextual (the simplest
    sound rule, as Bitcoin's former `RECENT_CONSENSUS_CHANGE`). Route P2P through `_at`.
    Thread `rules` into `deploy_fee`.
- **Consensus functions in wallet modules (F11-7).** `builder::max_weight` sets the exact
  deploy fee (consensus, `DeployFeeNotExact`) but lives in the wallet builder
  (`builder.rs:121`). This is one instance of R16-4 and R16-5. Move it to a consensus
  module, re-export it for wallets, and pin golden values.
- **The "every valid transaction fits in a block" invariants are not const-asserted
  (F11-10).**
  - `MAX_PX_TX_SIZE (4.25 MiB) ≤ MAX_PX_BLOCK_BYTES (8 MiB)` holds but is not asserted
    (the deploy analogues are, at `params.rs:47-48`).
  - The largest transfer weight (≤ 100 kB plus the clawback, ≈ 104 k) is below 600 k plus
    the coinbase reserve.
  - Add `const _: () = assert!(…)`.
- **Zero-input PX transaction-id malleability** depends only on proof canonicity: the
  prunable part is the proof alone, and nothing signs it.
  - `4b277cd` closed the free commit-PoW witnesses.
  - The query-PoW witness is bound, because query indices are sampled after it.
  - This is owned by 22; I record the dependency only.
- **R12-2 (weight-0 v1 inputs).** Unchanged. Owned by 10 and 14 (F10-1, F10-2). The block
  rule B6 in `validate.rs` is where it lands.

---

## 4. New findings

| ID | Severity | Status | Location | Scenario | Confidence |
|---|---|---|---|---|---|
| **F11-1** | Informational (closes a P0 decision) | Complete but requires further testing | `tx/src/px.rs:51,258-260,331-335`; `zkvm/src/air/memory.rs:40-79`; `zkvm/src/air/util.rs:188`; `zkvm/src/prove.rs:67-91`; `px-core/src/kernel.rs:141-155` | The "docs field-canonical vs code raw u32" item is a misattribution: the canonical-word text (`AUDIT.md:902`, `zk-security-review.md:134`, `zkvm.md` §5) concerns the Poseidon2 syscall buffer. Function output words are raw 32-bit words, injective at every layer (codec, `h_tx`, byte-limb AIR table, statement digest). **Decision: keep raw `u32`, document it as normative; no consensus change.** A field-canonical rule would reject ~53% of word values for no soundness gain | High (source-read end to end; not yet tested with words ≥ p) |
| **F11-2** | Low (testnet) / Medium (before any proof-size-reducing upgrade) | Not implemented | `px/src/state.rs:135-138`; `tx/src/state.rs:205-208`; `tx/src/validate.rs:968-996` (no capacity check) | A block overflowing 2^32 leaves passes validation and panics every node at `apply_block` (a global halt). Unreachable today (≥ 2^29 blocks ≈ 2,040 years at ≤ 4 PX per block); ≈ 10 years if PX transactions shrink to ~10 KB. Zcash makes capacity an explicit consensus rule | High (math from the measured proof size) |
| **F11-3** | Low (latent; single epoch) | Partially implemented | `tx/src/validate.rs:245-284,807-813`; `p2p/src/net.rs:2289`; `tx/src/px.rs:477`; `tx/src/params.rs:124` | After a second epoch changes a structural parameter, honest relays of transactions built for the neighbouring epoch are penalized as "stateless" (P2P cheap path), splitting honest peers around the activation. A scheduled fee-rate change would not reach `deploy_fee` | High (source-read) |
| **F11-4** | Low | Not implemented | `tx/src/px.rs:249-251` (unprefixed ciphertexts), `:644-729`, `:787-824` | Validation is not total over in-memory transactions: a non-decoded `PxTx` with over-long payouts, output words or ciphertexts passes structure. Two different in-memory transactions can share one id. Not reachable from the network (all ingress decodes) | High |
| **F11-5** | Medium (evidence; freeze blocker) | Partially implemented | `tx/tests/*`, `chain/tests/golden.rs` | Six block/tx variants have no exact-error vector (§2.4), several in-block cases are untested, and **no golden vector pins a tx encoding, tx id, signature message, `h_tx`, contract id or deploy fee value**. "Hash is stable" (`transfers.rs:53`) compares against itself, not a pinned value. An accidental change to any of these would pass CI and silently fork the frozen v3 identity (SX2 P0-2) | High |
| **F11-6** | Low | Partially implemented | `docs/transactions.md` §8, §8.5; `docs/px.md` §11.3 | The PX and deploy structure rules are not enumerated with rule ids. §8.5 lists only key-image conflicts (stale; R6 MP-8). The capacity rule and the output-word encoding are unspecified. The spec is not sufficient for an independent implementation | High |
| **F11-7** | Low | Partially implemented | `tx/src/builder.rs:121-148`; `tx/src/px.rs:475-480` | A consensus function (`max_weight`, which determines the exact deploy fee) lives in a wallet module; a wallet-motivated edit forks consensus | High |
| **F11-8** | Accepted limitation | — | `tx/src/validate.rs:528-531` | A call to a zero or all-zero contract id gets contextual `PxUnregistered` although it is invalid on every branch; negligible | High |
| **F11-9** | Informational | Complete and verified | `tx/src/validate.rs:578-672` | The stateless-first order prevents penalty masking (compare Bitcoin #33050); PX5 last costs no free CPU | High |
| **F11-10** | Informational | Not implemented | `tx/src/params.rs:47-48` | "Every valid transaction fits in a block" is const-asserted for deploys only | High |

**Challenges to existing reports:**
- **Register row "Known: PX output words: docs field-canonical, code raw u32" (Low, PI,
  CONS), D12 and SX2 P0-1(f).** The premise is wrong (F11-1). It should be closed as
  "documentation gap; the current rule is kept".
- **"TreeFull (known) … unreachable", P3.** The conclusion holds for the current proof
  system only. It deserves a rule in v3, because the argument depends on a non-consensus
  quantity (F11-2).

---

## 5. Implementation plan for phase 2

Ownership split of `tx/src/validate.rs` (agreed in principle with dossier 10 §"ownership
warning"):
- **11 owns** the single-transaction functions, `TxError`, `is_stateless(_at)`, and the
  capacity check;
- **10 owns** the block-phase reordering, caching and parallelism;
- **13** owns `check_uniqueness_of` if C4 changes.

| # | Item | Files (ownership) | External effect | Identity | Tests | Bench | Docs | Diff. | Prio |
|---|---|---|---|---|---|---|---|---|---|
| I1 | **Transaction golden corpus and per-rule vectors.** Pinned hex of a transfer, coinbase, zero-input PX, PX with a v1 part and functions (output words 0, `p−1`, `p`, `0xFFFFFFFF`), and a deploy. Pinned tx id, prefix/base/prunable hashes, `sig_message(domain)`, `h_tx(domain)`, contract id, `deploy_fee`, `standard_fee(n,k)` for all 64×15 shapes (or a hash of the table), `PX_STANDARD_FEE`. One exact-error vector per `TxError` and `BlockError` variant, including every gap of §2.4 | **new** `tx/tests/golden_tx.rs`, **new** `tx/tests/rule_vectors.rs`, `tx/tests/common/mod.rs` (additive helpers) | none | none (pins v3) | Golden (independent derivation: a Python/`blake2b` script, as `f6c98c3` did for consensus); unit; regression; mutation check (cargo-mutants on `px.rs` and `validate.rs`: every non-equivalent mutant must be caught) | — | transactions.md §16 (test plan points at the files) | M | **P0** (before the freeze) |
| I2 | **Close D12: raw `u32` output words, normative.** Docs plus tests only | `docs/px.md` §7.2, §11.1 (a normative sentence), `docs/zkvm.md` §5 (`WRITE` emits a raw 32-bit word; only `POSEIDON2` words are field elements), `docs/transactions.md` T2 row; tests: tx-level vector in I1; zkvm-level test in **`zkvm/tests/` (owner 23)** | none | none | A program writing words ≥ p proves and verifies; `w ± p`, bit-flip and count mutations rejected | — | Also correct the register row and D12 in the review docs (**47**) | S | **P0** (decision), P1 (tests) |
| I3 | **PX tree capacity rule** (Zcash-style) and a panic-free apply | `tx/src/validate.rs` (`ChainView::px_tree_size`, `TxError::PxTreeFull` contextual, `BlockError::PxTreeFull`, mempool check in `validate_px_without_proof` and `revalidate_after_extension`), `tx/src/state.rs` (impl; `apply_block` → `Result`), test `ChainView` impls in `tx/tests/{adversarial,revalidate_after_extension,validation_order}.rs`, `px/src/tree.rs` / `px/src/state.rs` test constructor (**21**), `chain/src/manager.rs:955` (handle the `Result`; **10/01**) | **CONSENSUS** (narrowing; no reachable chain affected) | rides the v3 reset | Boundary `CAPACITY−2/−1/0`; mempool contextual; property `validate ⇒ apply Ok`; undo exact at the boundary; the 36→37 variant classification test | — | px.md §11.3 (new row "Capacity"), transactions.md §8.3 (B8), consensus discipline record (12 steps) | M | **P1** (P0 if the owner wants it in v3; later costs an activation) |
| I4 | **Total structure checks** plus the round-trip invariant | `tx/src/px.rs` (`check_px_structure`: payouts ≤ 16, words ≤ 256 per function, ciphertext length; `check_deploy_structure`: program count and size), new test `tx/tests/roundtrip.rs` | none (decode ⊆ checks) | none | `validate Ok ⇒ decode(encode(tx)) == tx` over the corpus plus mutations; the ambiguous-ciphertext pair is rejected | — | px.md §11.1 | S | P2 |
| I5 | **Activation-aware classification** | `tx/src/validate.rs` (`is_stateless_at`: every error contextual within the grace window), `p2p/src/net.rs:2289` (use `_at`; **30/31**), `tx/src/px.rs` (`deploy_fee(…, rules)`), `tx/src/params.rs:124` (take `fee_per_weight` from the epoch; **14**) | policy (plus identity-neutral plumbing) | none | A two-epoch schedule with a changed fee rate: a transaction built for epoch 1 relayed at A−1 is not penalized; far from A it is | — | p2p.md §10, consensus.md §11 | S | P2 |
| I6 | **Move consensus fee functions out of the wallet builder** | `tx/src/builder.rs` → **new** `tx/src/weight.rs` (or `params.rs`, **14** coordinates), re-exported | none | none | I1 golden table for `max_weight` | — | transactions.md §8.4 | S | P2 |
| I7 | **Rule-id registry in the spec**: PS1–PSn (PX structure), D1–Dn (deploy), B8 (capacity); every `TxError`/`BlockError` variant mapped to one id; `validate.rs` doc table updated; §8.5 conflict list corrected | `docs/transactions.md` §8, `docs/px.md` §11.3, `tx/src/validate.rs` (doc comments only) | none | none | A test asserting the doc table lists every variant (a grep test, as the classification test does) | — | yes | S | P1 |
| I8 | **Const asserts** "every valid transaction fits in a block" | `tx/src/params.rs` (**14** coordinates) | none | none | Compile-time | — | — | S | P3 |
| I9 | **Property test of the stateless definition** (§3.1): a stateless error must recur on an unrelated chain state and height | new `tx/tests/classification_property.rs` | none | none | Seeded randomized loop (the project's convention) | — | — | S | P2 |

**Order:** I1 and I2 first (freeze blockers and a decision), then I3 (it must enter v3 or
wait for an activation), then I7, then I4, I5, I6, I9 and I8.

---

## 6. Dependencies and conflicts

- **10 block-validation-pipeline:**
  - shares `tx/src/validate.rs` (the block phases). I3's B-rule goes next to the B6
    budgets; 10 is reordering those phases, so sequence I3 after 10's item 1, or agree the
    hunk;
  - 10's early proof decoding covers the empty-proof issue (F10-2), which I do not
    duplicate.
- **13 mempool-frontrunning-c4:**
  - option B or C rewrites `check_uniqueness_of`, the C4 variants, `ChainView::has_one_time_key`
    and the classification table;
  - I1's vectors for C4, `CoinbaseDuplicateOneTimeKey` and `PxDuplicateOutputKey` must be
    written after the D8 decision, or updated with it;
  - I3 adds a `ChainView` method; coordinate the trait edits in one commit.
- **14 fee-economics:** `params.rs`, `deploy_fee`, `max_weight` (I5, I6, I8); the R12-2 weight
  rule touches B6.
- **21 px-nullifiers-commitments:** the tree and state constructors, and the tree-full
  analysis (I3); agree who writes the px-side test hook.
- **22 px-proof-system:** proof canonicity (zero-input PX transaction-id malleability) and
  `MAX_PROOF_BYTES` (which feeds `PX_STANDARD_FEE`).
- **23 zkvm-bvm:** the output-word zkVM test (I2).
- **30/31 P2P:** `is_stateless_at` in the cheap path (I5).
- **01 consensus-core, 40 genesis, 47 docs:**
  - the golden corpus and fingerprint (I1): whether transaction golden vectors live in
    `tx/tests` (proposed) or in a central corpus;
  - the consensus-discipline record for I3;
  - register corrections (I2).
- **12 mempool-architecture:** §8.5 conflict-key docs (I7) and
  `revalidate_after_extension` (I3 adds the capacity check).

---

## 7. Open questions for the coordinator

1. Does the owner accept closing **D12 / SX2 P0-1(f)** as "keep raw `u32`, docs only" (F11-1)?
   It removes one CONSENSUS row from the v3 table.
2. Should the **capacity rule (I3)** ride the v3 reset (recommended: it is free now and needs
   an activation later), or be deferred with a documented horizon?
3. Who owns the **transaction golden corpus**: 11 (in `tx/tests`, proposed) or 01 (central)?
   Either way it must be frozen on the final v3 rule set, after the D8 (C4) and R12-2
   decisions.
4. Given Bitcoin Core's move to **no penalties for invalid transactions** (#33050), should
   BlackSilk keep transaction penalties? My view: keep them. The stateless-first order
   removes the masking argument that motivated Bitcoin's change, and BlackSilk's
   verification is far costlier per transaction. But record the reasoning in p2p.md §10.
5. The split of `validate.rs` ownership between 10, 11 and 13 for phase 2 (proposed in §5).

---

## 8. Sources

1. Bitcoin Core, `src/consensus/validation.h` (`TxValidationResult`):
   https://github.com/bitcoin/bitcoin/blob/master/src/consensus/validation.h
2. Bitcoin Core PR #33050, "net, validation: don't punish peers for consensus-invalid txs"
   (merged 2025-08-12, v30.0): https://github.com/bitcoin/bitcoin/pull/33050
3. Bitcoin Optech newsletter #405 (on removing `RECENT_CONSENSUS_CHANGE`, #31269):
   https://bitcoinops.org/en/newsletters/2026/05/15/
4. Bitcoin Core, CVE-2018-17144 full disclosure:
   https://bitcoincore.org/en/2018/09/20/notice/
5. Monero, `src/cryptonote_core/tx_verification_utils.h` (`ver_input_proofs_rings`,
   `make_input_verification_id`, `ver_mixed_rct_semantics`, `ver_non_input_consensus`):
   https://github.com/monero-project/monero/blob/master/src/cryptonote_core/tx_verification_utils.h
6. The Zebra Book, Design Overview (semantic vs contextual verification):
   https://zebra.zfnd.org/dev/overview.html
7. The Zebra Book, RFC 0002 Parallel Verification:
   https://zebra.zfnd.org/dev/rfcs/0002-parallel-verification.html
8. The Zebra Book, RFC 0005 State Updates:
   https://zebra.zfnd.org/dev/rfcs/0005-state-updates.html
9. Zebra, `zebra-chain/src/orchard/tree.rs` (`NoteCommitmentTreeError::FullTree`, citing the
   spec rule): https://github.com/ZcashFoundation/zebra/blob/main/zebra-chain/src/orchard/tree.rs
10. Zcash Protocol Specification, §3.8 Note Commitment Trees (the tree-capacity consensus
    rules): https://zips.z.cash/protocol/protocol.pdf
11. RISC Zero, "Receipts 101" (journal = public outputs, committed by SHA-256 digest in the
    claim): https://dev.risczero.com/api/zkvm/receipts
12. Succinct SP1 docs, advanced proof generation / public values (`commit_slice`, digest):
    https://docs.succinct.xyz/docs/sp1/generating-proofs/advanced
13. OtterSec, "Unfaithful claims: breaking 6 zkVMs" (public claims not absorbed before
    challenges): https://osec.io/blog/zkvms-unfaithful-claims/
14. 0xPARC zk-bug-tracker (aliasing / non-canonical field element bugs, circomlib
    `Num2Bits`): https://github.com/0xPARC/zk-bug-tracker/blob/main/README.md
15. A. Brömme, "Canonicalization Failures as a Recurring Vulnerability Class" (arXiv
    2608.06508, 2026): https://arxiv.org/abs/2608.06508
16. Monero, "A post-mortem of the burning bug" (context for C4; owned by 13):
    https://web.getmonero.org/2018/09/25/a-post-mortum-of-the-burning-bug.html

**Repository sources** (commit `9e422d8`) are cited inline by `file:line`.
