# 16 bulletproofs-plus: research dossier (phase 2, phase 1)

Author: specialist agent 16. Date: 2026-09-27. Repository commit: `9e422d8` (`rebuild/core`).
This is internal engineering work. It is not an audit, and nothing here claims that BlackSilk's BP+ is secure. It records evidence of what the code does and what the tests show.

---

## 1. Scope and what I read

**Code (read in full):**
- `crypto/src/bulletproofs_plus.rs` (848 lines): the prover, the single-MSM verifier, the batch verifier, and 12 unit tests.
- Supporting code:
  - `crypto/src/generators.rs`, `crypto/src/hash.rs` (tags, `Hasher64::to_scalar`, `h32`), `crypto/src/point.rs` (canonical decoding);
  - `crypto/src/commitment.rs`, `crypto/src/nonce.rs` (`HedgedRng`), `crypto/src/claims.rs:60-95` (range claims built on BP+).
- Call sites:
  - `tx/src/validate.rs:300-386` (T10: `check_structure`, `check_range_proof`), `:595-606` (PX), `:1098-1119` (the block batch);
  - `tx/src/px.rs:643-730` (PX shape), `:787-806` (deploy);
  - `tx/src/types.rs:130-195` (`read_bpp` / `write_bpp`);
  - `tx/src/builder.rs:120-140, 340-360`, `tx/src/px_builder.rs:443`;
  - `chain/src/manager.rs:298-337, 940-955` (the batch-weight RNG), `node/src/main.rs:84-100` (its seed from `getrandom`);
  - `node/src/fingerprint.rs:100-160`.

**Tests read:**
- `crypto/src/bulletproofs_plus.rs::tests` (12 tests);
- `crypto/tests/malleability.rs` (the BP+ part: `bpp_every_field_alteration_fails`, `bpp_commitment_alterations_fail`, `bpp_non_canonical_scalars_are_rejected_by_decoding`, `batch_verify_agrees_with_individual_verification`, `batch_weights_prevent_cancelling_errors`);
- `tx/tests/adversarial.rs:443-540` (`t10_range_proof`, `inflation_with_negative_output_is_rejected`);
- `tx/tests/malleability.rs:170-210`;
- `fuzz/fuzz_targets/tx_decode.rs`.

**Docs and reports:**
- `docs/transactions.md` §1.3, §1.4, §7, §8, §9, §13–§16;
- `docs/reviews/full-review-2026-09-27.md` (BP+ rows, R2-C11, P1-13, P2-2, P2-11, the never-change list item 10, risk 6);
- `docs/reviews/autonomous-session-2026-09-27.md`;
- `full-review-2026-09-27/R2-crypto.md` §5–§6 and the tables; R12 (BP+ timing); R13 (T-1, T-3, T-6, T-12); `v3-plan.md` (A20); SX1 (R6 option C relies on BP+ being a proof of knowledge).

**Roster neighbours checked:** 10, 11, 14, 15, 18, 19, 41, 42, 44, 45, 47.

---

## 2. Current state

### 2.1 Conformance with ePrint 2020/735 (Fig. 1 WIP, Fig. 3 aggregated range proof)

I re-derived every verifier coefficient independently of R2 and compared it with `Msm::add` (`bulletproofs_plus.rs:434-485`). Evidence: **math (re-derived) + source-read**.

- **Prover WIP round.** `L`, `R`, the folds of `a`, `b`, `G` and `H`, and `α' = α + e²d_L + e⁻²d_R` all match Fig. 1 (`:281-334`).
- **Final round.** `A1 = rG0 + sH0 + (r·y·b + s·y·a)H + δG`, `B = r·y·s·H + ηG`, `r1 = r + ae`, `s1 = s + be`, `d1 = η + δe + α̂e²` (`:337-357`). This matches Fig. 1 for n = 1.
- **Range-proof reduction.** `d_(64j+b) = z^(2(j+1))·2^b`, `←y_i = y^(N−i)`, and `α̂ = α + Σ z^(2(j+1))·y^(N+1)·γ_j` (`:266-273`) match Fig. 3. The constant is `ζ = (z − z²)Σy^i − z·y^(N+1)·(2^64−1)·Σ z^(2(j+1))` (`:465-468`).
- **Folded exponents in the single-MSM verifier.**
  - The recurrence `s[i] = s[i − 2^lg]·e_t²` with `t = rounds − 1 − lg` is correct. Round t splits on bit (rounds−1−t), counted from the most significant bit first.
  - The G generator carries `y^(−i)·s_i`: the `y^(−h)` factors accumulate to `y^(−i)`.
  - The H generator carries `s_(n−1−i) = s_i⁻¹`.
  - The signs of all RHS−LHS terms (A: −e², A1: −e, B: −1, L_t: −e²e_t², R_t: −e²e_t⁻², V_j: −e²y^(N+1)z^(2(j+1))) are correct.
- **Padding slots** (M > k). These have zero bits, and neither side includes a `V` for them. This is consistent, and sound: an extracted opening of the identity is (0, 0) under DL.
- **Cross-check.** The optimized verifier agrees with the round-by-round verifier on valid proofs and on two classes of invalid proof [test: `optimized_verifier_matches_naive_verifier`, k ∈ {1,2,3,5,8}]. The honest prover computes `â_L` and `â_R` directly and never computes `ζ`. So honest proofs that verify show that the verifier's `ζ` agrees with the prover's algebra [tested: `proves_and_verifies_every_output_count`, k = 1..16].
- **Limitation.** `verify_naive` shares `challenges()`, `powers()` and `z_even_powers()`, and the module-level derivation, with the code under test. It is not an independent oracle for the transcript or for errors made at the derivation level (see F-5).

### 2.2 Fiat–Shamir

Evidence: **source-read; tested indirectly**.

- **Transcript.** `t0 = H32("bp+/init", LE8(64) ‖ LE8(M) ‖ LE8(k) ‖ V_0..V_(k−1))`; `y = Hs(t0 ‖ A)`; `z = Hs(t0 ‖ A ‖ y)`; `e_t = Hs(e_(t−1) ‖ L_t ‖ R_t)` with `e_(−1) = z`; `e = Hs(e_last ‖ A1 ‖ B)` (`:111-147`, `:380-408`).
  - Every challenge depends on the full statement and on all prior prover messages.
  - The statement's public values are `(g, h, Gbp, Hbp, V, n)`. The generators are protocol constants, derived from the domain tags, so fixing them in code is equivalent to hashing them.
  - This is the fix that Trail of Bits (Frozen Heart) and Dao–Miller–Wright–Grubbs (IEEE S&P 2023) prescribe. Their attacks need `V` (or `n`) to be absent from the hash. Here both are present.
- **Tags.** Domain tags are length-prefixed and distinct [tested: `hash::tests::tags_are_distinct_and_short`].
- **Challenge chaining.** Chaining goes through a 32-byte scalar (about 252 bits). Collision resistance is then about 126 bits, the same as the group. Monero chains the same way (`transcript_update`) [math, and Monero source].
- **Zero challenges.** Any zero challenge is rejected on both sides (`:257`, `:309`, `:348`, `:397`). ZenGo X's BP+ audit of Monero (2021, §5.2) found exactly this check missing for `e`. Here it is present.
- **Responses.** `r1`, `s1` and `d1` are not hashed, which is normal for FS responses. Changing them breaks the final equation unless a DL relation among `G0'`, `H0'`, `H` and `G` is known [math]. Third-party malleability is covered by `bpp_every_field_alteration_fails` for single-field changes (tested). A formal non-malleability (simulation-extractability) proof exists for FS **Bulletproofs** (Ganesh et al., Eurocrypt 2022; JoC 2024). No such proof exists for **BP+**. ZenGo X §3.2 notes that the theorem does not apply to BP+ [literature]. Status: **assumed**.

### 2.3 Encoding and input validation

Evidence: **source-read; tested**.

- **Points** are canonical Ristretto (`Point::decode`, RFC 9496) [tested: `point::tests::non_canonical_points_rejected`].
- **Scalars** use `from_canonical_bytes` [tested: `bpp_non_canonical_scalars_are_rejected_by_decoding`].
- **Round count.** It is implied by `k`, and no length prefix is sent (`types.rs:173-195`) [tested: `malformed_shapes_are_rejected_without_panicking`, `t7_t10_t11_shapes`].
- **Torsion.** The QuarksLab 2018 critical-bug classes (non-reduced scalars, invalid points) do not apply: the group has prime order, and dalek's MSMs are used instead of hand-written multiexp code. Neither does the ZenGo X 5.1/6.1 torsion discussion [source-read].
- **Identity elements** (`A`, `L`, `R`, `V`) are accepted. They are mathematically legal. Monero's MRL rejected an "identity check" as adding no security (ZenGo X §5.1 response) [literature]. I agree.

### 2.4 Batch verification

- **Weights.** Each proof gets an independent weight in `[1, 2^128)`. The weights come from `ChainManager.rng`, a `ChaCha20Rng` seeded once per process from `getrandom` (`node/src/main.rs:84-85`, `manager.rs:337`). This RNG is used only for this purpose (`manager.rs:951`) [source-read].
- **Soundness.** If any equation is non-zero, the weighted sum is zero with probability ≤ 2^-128 for weights the attacker cannot predict. This is the small-exponents test of Bellare–Garay–Rabin 1998 [math]. Monero uses full-width `skGen()` weights; Tari's audited BP+ uses random weights too [literature].
- **Mixed sizes** share the generator prefix and one MSM (`:506-520`) [tested: `batch_verification`, sizes 1..5].
- **Tests.**
  - The batch agrees with individual verification on all 128 subsets of 7 fixed items (3 valid, 4 invalid, one of them a shape mismatch) [tested: `batch_verify_agrees_with_individual_verification`].
  - Cancelling errors fail under random weights and pass under unit weights [tested: `batch_weights_prevent_cancellation`, `batch_weights_prevent_cancelling_errors`].
- **Consensus.** A valid batch passes under any weights (exact algebra). The weights never influence consensus, except through a false accept with probability ≤ 2^-128 [math].

### 2.5 Prover hygiene and randomness

Evidence: **source-read**.

- **Hedging.** All nonces come from `HedgedRng(secrets = amounts ‖ masks, context = "bp+" ‖ V…, rng)` (`:214-222`). The statement is a function of the witness. So under a constant RNG the proof is deterministic per witness, and two different statements never share nonces (R2 §6, confirmed).
- **Constant-time secret operations.**
  - Secret-dependent MSMs use `multiscalar_mul` (the constant-time version).
  - Vartime is used only on generators with public challenges, and in the verifier.
  - dalek is pinned at `=4.1.3`, which contains the fix for RUSTSEC-2024-0344 (timing variability in `Scalar52::sub`).
- **Zeroization.** R2-C10 reported that `r_, s_, δ, η, a0, b0` were not zeroized. They now are (`:358-363`), so that part is fixed. `d_l` and `d_r` in each round are still not wiped (`:291-292`). Everything here is best effort, because `Scalar: Copy` leaves stack copies.

### 2.6 Limits

- `MAX_OUTPUTS = 16`, `N ≤ 1024`, and `BP_MAX_GENERATORS = 1024` (`generators.rs:14`). This matches Monero's `maxM = 16`.
- `tx::MAX_OUTPUTS = 16` is a separate constant (`tx/src/params.rs:60`). If it were ever raised above 16, `bpp::rounds` would return `None`. That is a safe failure (`RangeProofShape`), but nothing asserts the coupling.
- The cost per proof is linear in N and is charged through Monero's clawback (§8.4; workstream 14).

### 2.7 What the tests do NOT prove

- **No pinned known-answer vector** for any BP+ proof, transcript challenge, or generator.
  - Prover and verifier share the code. An accidental change to a tag, the header layout, the generator derivation or the challenge order keeps every existing test green, yet it is a **silent hard fork**, because old proofs stop verifying.
  - R2-C11 ("pinned BP+ proof", P2-11) is still open for BP+: no hex vector exists in `crypto/` or `tx/tests`, and `consensus/tests/golden.rs` has none.
  - Spec §16.1 requires generator KATs; none are pinned.
- **No fuzz target** calls `bpp::verify` or `batch_verify` (`tx_decode.rs` runs only the structure checks).
- **No malicious-prover test for padding-slot abuse.** Example: k = 3, M = 4, with a nonzero "value" in slot 3, which has no commitment.
- **No test that a changed statement changes every challenge** (a weak-FS regression oracle).
- **The batch/individual differential is fixed, not randomized.** 7 hand-picked items is not the property test that R13 T-1 asks for.
- **No benchmark** (R12 §19 asks for single BP+ at k = 2 and 16, and batches of 1, 10 and 381).

---

## 3. Problems in scope (the standard questions)

### P-A: Batch weights depend entirely on the node's RNG (roster question, "A20")

- **What and why.**
  - `batch_verify` draws its weights only from `rng`. If `rng` is predictable (a constant, a known seed, or an OS RNG that "succeeds" with bad entropy), an attacker can pre-compute the weights.
  - Two invalid proofs can then be made to cancel: `w1·δ1 + w2·δ2 = 0`, for example `δ1 = w2·x`, `δ2 = −w1·x` in `d1`.
  - `batch_weights_prevent_cancellation` shows the attack at `w = (1, 1)` (`:801-816`).
  - The ChaCha offset is predictable too: it equals the number of BP+ proofs validated since start-up, which is public for a node that has just synced.
- **Security consequence.** A miner could produce a block containing out-of-range outputs, and that block would be **accepted only by nodes whose weights it predicted**. The result is inflation on those nodes and a chain split against healthy nodes.
- **Classification.** Consensus-critical in effect: validity diverges between nodes. It is not a consensus-rule change.
- **Reachability today.** `getrandom` failure aborts start-up. On Linux the syscall blocks until the pool is initialized; on Windows it uses `ProcessPrng`. Every test harness uses a fixed seed (`[3;32]`), but those are tests. **Low severity.**
- **A second defect under a constant-zero RNG.** The zero-rejection loop (`:533-540`) **never terminates**, so a hang follows (Informational).
- **Literature.** Bellare–Garay–Rabin 1998: weights must be unpredictable to the prover. Monero uses random `skGen()` weights. Tari RFC-0181 requires random weights and per-proof fallback. Zcash and ed25519 batch validators take a caller CSPRNG.
- **Fix: hedged weights.**
  - `seed = H64("bp+/batch", 32 fresh rng bytes ‖ LE64(#items) ‖ for each item: LE8(k) ‖ V… ‖ the proof's full canonical encoding)`, then `w_i = low128(H64("bp+/batch/w", seed ‖ LE64(i)))`, re-deriving (counter++) if it is zero.
  - With a good RNG, nothing changes.
  - With a constant RNG the weights become a random-oracle function of the entire batch. For any batch with an invalid member, the set of weight vectors that zero the sum admits at most one value of the last non-zero-error weight. So `Pr ≤ 2^-128` per hash query, and Q queries give `Q·2^-128` [math: ROM plus prime order].
  - **Every byte that verification reads must be hashed.** In particular `r1`, `s1`, `d1` and the commitments. `e` alone does not bind the responses.
- **Trade-offs.**
  - One Blake2b pass over the batch bytes: at most about 1 MB per block, about 1–2 ms, against an MSM of tens of ms.
  - It adds a new tag (`bp+/batch`, `bp+/batch/w`), which is local and not consensus.
  - What could go wrong: hashing only part of the proof reopens the attack. The tests below guard against that.
- **Tests.**
  1. A demonstration test: clone a ChaCha20Rng, pre-draw its weights, and build a cancelling pair. The *current* `batch_verify` accepts it. This documents the failure, and is `#[test]` in crypto only.
  2. With hedged weights: the same pair under `ZeroRng` and under the cloned RNG is rejected.
  3. `ZeroRng` terminates.
  4. For every field and commitment, changing it changes the derived weights.
- **Invariants.** Batch acceptance of valid proofs stays exact, so the weights never affect consensus. The verification equation does not change.

### P-B: No pinned vectors for the transcript, the proofs or the generators (R2-C11, P2-11; I raise it to P0)

- **What and why.** Only the prover/verifier self-consistency is tested. This was noted in R2 as "P2", but my evidence disagrees with that priority. The transcript, the tags, `BITS` and the generators are on the never-change list (item 10), yet **no test fails** when they change.
  - During phase 2, about 50 parallel workstreams touch `hash.rs`: 19 (domain registry), 46 (a crypto split, R16-11) and 18 (hedging).
  - An accidental edit would pass CI and fork every node that runs the old code.
- **Classification.** Consensus safety; test gap.
- **Literature.** Monero pins BP+ vectors in `tests/unit_tests/bulletproofs_plus.cpp`, and consensus golden vectors are standard practice (Zebra and Bitcoin Core `test/data`). Tari pins proofs as well.
- **Fix.**
  - `crypto/tests/bpp_vectors.rs` with pinned hex for:
    - (a) `H`, `Gbp[0]`, `Gbp[1]`, `Gbp[1023]`, `Hbp[0]`, `Hbp[1023]`, and a Blake2b digest of all 2048 generators;
    - (b) for fixed `(amounts, masks)` at k ∈ {1, 2, 3, 16}: `t0`, `y`, `z`, every `e_t`, `e`, and the full proof encoding. The prover is deterministic under `ZeroRng`, because it is hedged.
  - **Accept vectors** (the verifier must accept the pinned bytes) are consensus.
  - **Prover-determinism vectors** are wallet-side. Label them separately, so that a legitimate prover change touches only the second set.
  - Put reject vectors in the same file: each single-field mutation, with the expected `false`.
- **Trade-offs.** Vectors freeze behaviour. That is the purpose; any intended change becomes explicit. Encoding lives in `tx` (`write_bpp`), so the crypto test needs a local encoder that follows spec §7 byte for byte. It is also cross-checked from `tx/tests` through `write_bpp` (one line).
- **Invariants.** Spec §7 transcript, tags, `BITS = 64`, `MAX_OUTPUTS = 16`, generator derivation.

### P-C: The oracle is not independent (the verifier cross-check shares code)

- **What.** `verify_naive` reuses `challenges()` and the helpers. A transcript error, such as z hashing the wrong thing, is invisible to it. Only honest-proof acceptance and 3 malicious-witness tests probe soundness.
- **Literature.**
  - ZenGo X found that the paper's WEE proof for the aggregated range proof was **wrong**. It assumed the `V_j` exponent vectors were constant. Their correction keeps the claim.
  - Audits of Monero (QuarksLab, Kudelski, ZenGo X, JP Aumasson) and Tari (Quarkslab 2023) found mostly validation, multiexp, zero-challenge and overflow bugs.
- **Fix (tests only).**
  1. A second verifier in `crypto/tests/`. It should be written literally from Fig. 3 in the paper's notation, with its **own** transcript code written from spec §7 and not calling crate internals. It needs a public accessor or recomputation from the encoding. Ideally a different author (agent) writes it.
  2. A broader malicious-prover suite through a `#[cfg(test)]` hook on `prove_bits`:
     - random non-binary `a_L` entries;
     - padding-slot values (k = 3 → M = 4, with slot 3 non-zero);
     - `a_R ≠ a_L − 1`;
     - a wrong γ;
     - a proof made for M = 4 presented with k = 4 commitments where one is the identity;
     - each must fail.
  3. A "statement binds every challenge" test: changing any `V_j`, `k` or `M` changes `y`, `z`, every `e_t` and `e`.
- **Invariants.** None change; this is tests only.

### P-D: No fuzzing of the verification path

- `bpp::verify` and `batch_verify` get arbitrary inputs only through structure-aware unit mutations.
- **Fix:** a `bpp_verify` fuzz target (workstream 41 owns `fuzz/`). It decodes via `read_bpp_pub` for k ∈ 1..16, runs `verify`, and checks:
  - no panic;
  - `verify == batch_verify([item])`;
  - a batch of the item with a known-valid proof equals `verify(item)`;
  - and, for a mutant that verifies, its bytes equal the seed proof's bytes (the non-malleability oracle, R13 #3).

### P-E: The fixed-item batch differential is not a property test (R13 T-1)

- **Fix:** a proptest (or a seeded loop, following the crate's style) over random batch sizes 0..24.
  - Use random k per item, and random corruption per item: none, a scalar change, a point replacement, the commitment set, or the wrong shape.
  - Check `batch_verify(items) == items.all(verify)`, with at least 256 cases.
  - Include duplicated and identical invalid proofs, and pairs made to cancel under unit weights.

### P-F: Aggregation limit coupling (Informational)

- `generators::BP_MAX_GENERATORS` must equal `BITS·MAX_OUTPUTS`, and `tx::MAX_OUTPUTS` must be ≤ `bpp::MAX_OUTPUTS`. Neither is asserted.
- **Fix:** `const _: () = assert!(...)` in `bulletproofs_plus.rs` and in `tx/src/params.rs`.
- Suggest that the fingerprint include `crypto.BPP_BITS`, `crypto.BPP_MAX_OUTPUTS` and a generator digest (workstream 40 or 46 owns `node/src/fingerprint.rs`).

---

## 4. New findings

| ID | Severity | Status | Location | Scenario | Confidence |
|---|---|---|---|---|---|
| **BPP-1** Batch weights are not hedged; a predictable RNG permits cancelling invalid proofs | Low (needs a broken or predictable OS RNG; the impact would be inflation plus a split) | Not implemented | `crypto/src/bulletproofs_plus.rs:530-543`; `chain/src/manager.rs:337,951` | Weights known in advance → `w1δ1 + w2δ2 = 0` → a block with out-of-range outputs is accepted by the victim node | High |
| **BPP-2** A constant-zero RNG makes `batch_verify` loop forever | Informational | Not implemented | `bulletproofs_plus.rs:533-540` | The weight is always 0 → infinite loop (a node hang), reachable only with a broken RNG | High |
| **BPP-3** No pinned BP+ / transcript / generator vectors: a consensus-breaking edit passes all tests | Medium (consensus-safety test gap during mass parallel refactoring) | Not implemented (R2-C11 still open for BP+) | `crypto/src/bulletproofs_plus.rs` tests; `crypto/src/generators.rs:56-70` | A tag rename or header reorder in `hash.rs`/`bulletproofs_plus.rs` → old proofs fail on new nodes; CI stays green | High |
| **BPP-4** The cross-check verifier shares transcript and helper code with the implementation | Low | Partially implemented | `bulletproofs_plus.rs:567-614` | A transcript-derivation bug is invisible to `verify_naive` | High |
| **BPP-5** No malicious-prover test for padding slots, or for "the statement changes every challenge" | Low | Not implemented | tests | A regression that skipped padding constraints, or dropped `k` from `t0`, would go unnoticed | Medium–High |
| **BPP-6** `verify_weighted` silently truncates when `weights.len() < items.len()` (a `zip`) | Informational | Not implemented | `bulletproofs_plus.rs:516` | A future internal caller passing fewer weights skips verifying proofs | High (latent only) |
| **BPP-7** Per-round WIP nonces `d_l` and `d_r` are not zeroized (R2-C10 remainder) | Informational (memory hygiene) | Partially implemented (the final-round secrets were fixed) | `bulletproofs_plus.rs:291-292` | Memory disclosure → `d_l`/`d_r` plus the public `d1` narrow down `α̂` (which needs all the others too) | High |
| **BPP-8** No fuzz target for BP+ verification | Low | Not implemented | `fuzz/fuzz_targets/` | A panic or divergence on crafted proofs goes undetected | High |
| **BPP-9** The docs overstate or mismatch | Informational | Not implemented | `docs/transactions.md` §9.3 ("the model in which … BP+ are proven"), §16.4 ("honest prover refuses out-of-range values"; `u64` makes this unrepresentable), §7 (batch weights "from the verifier's CSPRNG": to be updated for hedging), §13 (non-malleability of BP+ FS is assumed, not proven) | Reader over-trust | High |
| **BPP-10** The aggregation constants are coupled only implicitly | Informational | Not implemented | `generators.rs:14`, `bulletproofs_plus.rs:68`, `tx/src/params.rs:60` | Raising one limit fails safe (shape error), but silently | High |

**Correction to earlier reports.**
- R2 §5 lists "final-round nonces not zeroized". That has been fixed; only the per-round `d_l`/`d_r` remain.
- R2 rates the pinned proof P2. I rate BPP-3 **P0**, because phase 2 is a mass parallel refactor touching `hash.rs` and `crypto/`.

No Critical or High issue was found in the BP+ algebra, the transcript, decoding or batching.

---

## 5. Implementation plan for phase 2

| # | Item | Files (ownership) | Consensus? | Identity impact | Tests | Bench | Docs | Size | Priority |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Pinned KATs: generators (points + digest of all 2048), transcript challenges and full proof bytes for k ∈ {1,2,3,16}, accept and reject vectors; prover-determinism set labelled separately | **new** `crypto/tests/bpp_vectors.rs` (16); one cross-check line in `tx/tests/malleability.rs` via `write_bpp` (coordinate with 11) | none (pins current consensus) | none | KAT, reject vectors | – | `transactions.md` §16.4 (reference the vectors) | S | **P0** |
| 2 | Hedged batch weights (`seed = H64(tag, fresh ‖ full batch encoding)`); terminate under `ZeroRng`; `assert_eq!(weights.len(), items.len())` | `crypto/src/bulletproofs_plus.rs` (16); `crypto/src/hash.rs` add 2 tags to `tags` + `ALL` (coordinate with 19, which owns the registry) | **no** (local verifier choice; outcome identical except with probability ≤ 2^-128) | none | demonstration test (the current code accepts under a predicted RNG); regression under ZeroRng / cloned RNG; weight-sensitivity to every field; termination | batch at 1/10/381 before and after (hash overhead < 5%) | `transactions.md` §7 batch paragraph; `nonce.rs` doc table (18) | S | **P1** |
| 3 | Independent paper-literal verifier with its own transcript code; malicious-prover suite (padding slot, `a_R ≠ a_L−1`, wrong γ, random non-binary); "statement changes every challenge" test | `crypto/src/bulletproofs_plus.rs` `#[cfg(test)]` module only (16); optionally **new** `crypto/tests/bpp_independent.rs` | none | none | differential, adversarial | – | – | M | **P1** |
| 4 | Randomized batch-vs-single property test (≥ 256 cases, mixed k and corruption kinds) | `crypto/tests/malleability.rs` BP+ section (16) | none | none | property | – | – | S | **P1** |
| 5 | Fuzz target `bpp_verify` (decode, verify, batch-of-one equality, non-malleability oracle) | **new** `fuzz/fuzz_targets/bpp_verify.rs`, `fuzz/Cargo.toml` (**41 owns** `fuzz/`; 16 supplies the target) | none | none | fuzz campaign ≥ 10^7 execs with `-O -a` | – | – | S | P1 |
| 6 | Const asserts on the limit coupling; zeroize `d_l`/`d_r` | `crypto/src/bulletproofs_plus.rs`, `crypto/src/generators.rs` (16); `tx/src/params.rs` one line (11/14) | none | none | compile-time | – | – | S | P2 |
| 7 | Docs corrections (BPP-9): §9.3 wording ("the interactive protocol is proven (WEE, with the ZenGo X correction); FS soundness follows from general results for special-sound multi-round protocols (Attema–Fehr–Klooß); non-malleability of FS-BP+ is assumed"); §16.4; §7 hedged batching; §13 | `docs/transactions.md` §7, §9, §13, §16 (**47 coordinates** docs; 16 supplies the text) | none | none | – | – | yes | S | P1 |
| 8 | Fingerprint entries `crypto.BPP_BITS`, `crypto.BPP_MAX_OUTPUTS`, and a generator digest | `node/src/fingerprint.rs` (40/46 own it) | none (operational) | **the fingerprint value changes** (pre-freeze; acceptable) | fingerprint test update | – | `testnet.md` | S | P2 |
| 9 | Benchmarks: single k = 2 and 16; batch 1/10/381; hedged vs unhedged | bench harness (**45 owns**) | none | none | – | yes | R12 figures | S | P2 |
| 10 | (Future) batch-failure attribution by bisection, for parallel split verification (P2-2) | `crypto/src/bulletproofs_plus.rs` API (16), used by 10 | none | none | property: the reported index is the lowest invalid | parallel split timing | – | S | P3 |

Items 1–4 and 6 lie entirely within `crypto/src/bulletproofs_plus.rs` and `crypto/tests/*bpp*`, so they can run in one worktree without conflict. Item 2 touches `hash.rs` for two tags only.

---

## 6. Dependencies and conflicts

- **10 block-validation-pipeline** owns `tx/src/validate.rs`. Item 2 keeps the `batch_verify(items, rng)` signature, so there is no conflict. Any split or parallel batch (P2-2) must keep one weight per proof from a hedged seed.
- **11 tx-validation**: the T10 vectors; the `write_bpp` cross-check line.
- **14 fee-economics**: the clawback formula depends on `proof_len` and M. No change is proposed.
- **15 clsag**: the same pattern (a pinned vector plus an independent verifier). Share the vector-file conventions.
- **18 crypto-randomness**: item 2 is a new hedging site (verifier side). 18 owns `nonce.rs` and the §10 table.
- **19 hash-domain-separation**: registers `bp+/batch` and `bp+/batch/w`. The BP+ tags are on the never-change list.
- **41 fuzzing**: owns the target from item 5. **42 mutation**: run `cargo-mutants` on `bulletproofs_plus.rs` after items 1–4. Survivors in `Msm::add` would show vector gaps.
- **44 supply-chain**: dalek `=4.1.3` (RUSTSEC-2024-0344 is fixed). The SIMD backend's `unsafe` is inside the dependency.
- **45 benchmarks**: item 9. **47 docs**: item 7. **46 architecture**: if `crypto` is split (R16-11), move the vectors with BP+.

## 7. Open questions for the coordinator

1. Do you accept raising BPP-3 (pinned vectors) to **P0**, given the parallel edits to `hash.rs` and `crypto/`?
2. Hedged batch weights (item 2): do you agree that this is policy-only and needs no consensus-discipline process? My position: yes, because the outcome is identical except with probability ≤ 2^-128.
3. Should the independent verifier (item 3) be written by a *different* agent (for example 15 or 42), to get genuine implementation diversity?
4. Should we keep 128-bit weights (dalek-style; 2^-128 matches the group's roughly 126-bit security) or move to full-width weights like Monero? I recommend keeping 128-bit.
5. Should the fingerprint include crypto constants (item 8), and who owns `fingerprint.rs`?

## 8. Sources

- Chung, Han, Ju, Kim, Seo. *Bulletproofs+: Shorter Proofs for a Privacy-Enhanced Distributed Ledger*. IACR ePrint 2020/735. https://eprint.iacr.org/2020/735
- Bünz, Bootle, Boneh, Poelstra, Wuille, Maxwell. *Bulletproofs*. IEEE S&P 2018; ePrint 2017/1066. https://eprint.iacr.org/2017/1066.pdf
- ZenGo X (S. Bagad et al.). *Monero Bulletproofs+ Security Audit*, v1.1, 15 Feb 2021. It covers the WEE-proof correction (§3.3), missing `e = 0` check (§5.2), identity checks (§5.1, rejected by MRL) and malleability discussion (§3.2). https://suyash67.github.io/homepage/assets/pdfs/bulletproofs_plus_audit_report_v1.1.pdf
- Monero CCS. *Bulletproofs+ Audit* (ZenGo X) and *Bulletproofs+ Audit 2* (JP Aumasson). https://ccs.getmonero.org/proposals/bulletproofs-plus-audit.html ; https://ccs.getmonero.org/proposals/bulletproofs-plus-audit-jp.html
- Monero source, `src/ringct/bulletproofs_plus.cc`: the reduced-scalar checks, zero-challenge checks, `skGen()` batch weights and transcript. https://github.com/monero-project/monero/blob/master/src/ringct/bulletproofs_plus.cc
- Quarkslab. *Security Audit of Monero Bulletproofs* (2018): multiexp bugs, overflow, missing input validation, zero challenges. https://blog.quarkslab.com/security-audit-of-monero-bulletproofs.html
- Kudelski Security. *Monero Bulletproofs Security Audit* (2018). https://ostif.org/wp-content/uploads/2018/07/KudelskiBulletproofsFinal.pdf
- Trail of Bits. *The Frozen Heart vulnerability in Bulletproofs* (2022). https://blog.trailofbits.com/2022/04/15/the-frozen-heart-vulnerability-in-bulletproofs/
- Dao, Miller, Wright, Grubbs. *Weak Fiat-Shamir Attacks on Modern Proof Systems*. IEEE S&P 2023; ePrint 2023/691. https://eprint.iacr.org/2023/691
- Trail of Bits. *A mistake in the bulletproofs paper could have led to the theft of millions of dollars* (2023). https://blog.trailofbits.com/2023/08/02/a-mistake-in-the-bulletproofs-paper-could-have-led-to-the-theft-of-millions-of-dollars/
- Attema, Fehr, Klooß. *Fiat-Shamir Transformation of Multi-Round Interactive Proofs*. TCC 2022 / JoC 2023; ePrint 2021/1377. https://eprint.iacr.org/2021/1377
- Ganesh, Orlandi, Pancholi, Takahashi, Tschudi. *Fiat–Shamir Bulletproofs are Non-Malleable (in the Algebraic Group Model)*. Eurocrypt 2022; ePrint 2021/1393. https://eprint.iacr.org/2021/1393. Also the JoC 2024 ROM version: https://link.springer.com/article/10.1007/s00145-024-09525-2
- Dao, Grubbs. *Spartan and Bulletproofs are Simulation-Extractable (for Free!)*. Eurocrypt 2023; ePrint 2023/494. https://eprint.iacr.org/2023/494.pdf
- Bellare, Garay, Rabin. *Fast Batch Verification for Modular Exponentiation and Digital Signatures*. Eurocrypt 1998. https://people.csail.mit.edu/rivest/voting/papers/BellareGarayRabin-BatchVerificationWithApplicationsToCryptographyAndChecking.pdf
- Tari. *RFC-0181: Bulletproofs+ range proving*: random batch weights, per-proof fallback. https://rfc.tari.com/RFC-0181_BulletproofsPlus ; implementation and Quarkslab 2023 audit: https://github.com/tari-project/bulletproofs-plus ; https://www.tari.com/updates/2023-10-31-update-121
- RustSec. *RUSTSEC-2024-0344*: curve25519-dalek timing variability, fixed in 4.1.3. https://rustsec.org/advisories/RUSTSEC-2024-0344.html
- RFC 9496. *The ristretto255 and decaf448 Groups*. https://www.rfc-editor.org/rfc/rfc9496
