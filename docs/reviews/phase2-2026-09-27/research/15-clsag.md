# 15 clsag: research dossier (phase 2, phase 1)

Author: specialist agent 15 (clsag). Date: 2026-09-27. Repository commit: `9e422d8`
(`rebuild/core`). Read-only research; no builds or tests were run. This is internal
engineering work, not an audit.

---

## 1. Scope and what I read

**Code (read in full):**
- `crypto/src/clsag.rs` (1003 lines: implementation plus 15 unit tests and the pinned vector)
- `crypto/src/hash.rs` (`Hasher64`, `Hs`, `Hp`, tags), `crypto/src/point.rs` (canonical
  decoding), `crypto/src/nonce.rs` (`HedgedRng`), `crypto/src/lib.rs`, `crypto/Cargo.toml`
- `crypto/tests/malleability.rs` (CLSAG and BP+ non-malleability)
- `crypto/src/membership.rs` `verify` (the sister LSAG-style scheme, for comparison only)
- Consumers: `tx/src/validate.rs` (T4/T5 `check_structure` 300-360, C1 `resolve_input_rings`
  400-432, C3 `check_ring_signatures` 450-469, C2/C4 `check_uniqueness_of` 488-509, block path
  1027-1097), `tx/src/types.rs` (`read_clsag`/`write_clsag` 198-214, `signature_message`
  274-287), `tx/src/px.rs` (`read_sigs` 204-216, PX and deploy `signature_message`,
  `prefix_bytes` with the kind byte), `tx/src/codec.rs` (`Reader::point`/`scalar`),
  `tx/src/builder.rs` 360-460 and `tx/src/px_builder.rs` 430-535 (pseudo-mask derivation,
  signing, self-check), `tx/src/state.rs` 274 (key-image set keyed by bytes),
  `p2p/src/net.rs` 2325-2360 (`SIGNATURE_BURIAL`).
- Tests touching CLSAG: `tx/tests/adversarial.rs` (`c3_signatures`, `assemble`),
  `tx/tests/malleability.rs` (non-canonical `s + ℓ` for every CLSAG scalar),
  `chain/tests/{mempool_conflicts,revalidation}.rs` (signing helpers), `fuzz/fuzz_targets/`
  (no CLSAG-specific target exists).

**Docs and reports:** `docs/transactions.md` §1.1-1.2, §3.4, §4.4, §5, §6, §6.1, §8, §9, §13,
§14, §15, §16; `docs/reviews/full-review-2026-09-27.md` (register, never-change list, risks);
`docs/reviews/autonomous-session-2026-09-27.md`; `full-review-2026-09-27/R2-crypto.md` §4,
§12, §13; `SX1-core-crossreview.md`; `R12-performance.md` (R12-2, t_clsag); `R13-testing-
supplychain.md` (T-1/T-3/T-6/T-12); `C:/bszkeval/p2/brief.md`; roster entries 10-19, 38,
41, 42, 45, 47.

**Primary external sources read:** ePrint 2019/654 (full text, latest version), the
Aumasson/Vennard OSTIF CLSAG review (2020, full text), Monero `src/ringct/rctSigs.cpp`
(`CLSAG_Gen`, `verRctCLSAGSimple`, `verRctNonSemanticsSimple`, current master), monero-oxide
`ringct/clsag/src/lib.rs` (`Clsag::verify`), the Cypher Stack review of Zano d/v-CLSAG
(2024, `main.tex`) and the Monero post on CLSAG proof revisions, RFC 9496, RUSTSEC-2024-0344.
Full list in §8.

---

## 2. Current state

### 2.1 What exists

A single-signer 2-CLSAG (d = 2: spend key `P`, commitment offset `Cr − C'`) with ring 16,
over Ristretto255, Blake2b-512 domain-tagged hashing, and RFC 9496 element derivation for
`Hp`. Signing is hedged (secrets + full transcript + 32 CSPRNG bytes). Verification is a
straight 16-round loop with vartime MSMs on public data and a constant-time final compare.

### 2.2 Conformance with ePrint 2019/654 and Monero (line by line)

| Element | ePrint 2019/654 Def. 10 | Monero `rctSigs.cpp` | BlackSilk `clsag.rs` | Verdict |
|---|---|---|---|---|
| Aggregation coefficients | `μ_j = H_j(Q ‖ T ‖ {D_j})`, `H_j(x) = H(j ‖ x)` | `H(AGG_0 ‖ P[] ‖ C[] ‖ I ‖ D/8 ‖ C_offset)`, `AGG_1` likewise | `Hs("clsag/agg-P"/"clsag/agg-C", P[] ‖ Cr[] ‖ I ‖ D ‖ C')` (75-101) | Match (Monero order; different tags are the paper's domain separation) [source-read] |
| Round hash | `H_0(Q ‖ m ‖ L ‖ R)` | `H(ROUND ‖ P[] ‖ C[] ‖ C_offset ‖ m ‖ L ‖ R)` | `Hs("clsag/round", P[] ‖ Cr[] ‖ C' ‖ m ‖ L ‖ R)` (102-114) | Match with Monero [source-read] |
| `L_i`, `R_i` | `s·G + c·W_i`, `s·H_i + c·𝔚` | same, with `C_i = C_nonzero_i − C_offset` | same (246-252, 276-285) | Match [source-read; tested: `signs_and_verifies_at_every_index`] |
| Final response | `s_ℓ = α − c_ℓ·w_ℓ` | `sc_mulsub(c, μP·p + μC·z, a)` | 255 | Match [source-read] |
| Key image | `T = x·Hp(X_ℓ)` | `p·hash_to_p3(P)` | `p·Hp("key-image", P)` (59-66) | Match; prime order removes the cofactor [math] |
| Scalar canonicity | `σ ∈ F^{n+1}` | `sc_check` on every `s` and `c1` | enforced at decode (`decode_scalar`, `Reader::scalar`) | Match [tested: `clsag_non_canonical_scalars_are_rejected_by_decoding`, `tx/tests/malleability.rs`] |
| Linking tag ≠ identity | required since 2024 (Cypher Stack) | `sig.I != identity` | `key_image.is_identity()` in `verify` (269) and T4 (validate.rs:312) | Match [tested: `identity_key_image_is_rejected`, `clsag_identity_key_image_and_d`] |
| **Auxiliary tag `D` ≠ identity** | secret keys drawn from `(F_p^*)^d`, so honest `D ≠ 0` | **`8·D != identity` ("Bad auxiliary key image")** | **not checked** (T11 only requires decoding) | **Deviation, finding C1** |
| Intermediate `c_i ≠ 0` | not in paper | rejects `c_new == 0` ("Bad signature hash") | not checked | Negligible (2^-252); finding C6, no change recommended |
| Parallel verification | n/a | one thread-pool task per input | serial | Performance only (workstream 10) |

**Conclusion.** Apart from the `D ≠ identity` rule, the BlackSilk CLSAG is the Monero
construction with Ristretto255 and BlackSilk hashes substituted [source-read, cross-checked
against Monero master and monero-oxide]. R2's statement that the transcript matches is
confirmed. The existing claim "BlackSilk follows Monero's construction, except that
Ristretto removes the cofactor handling" (`docs/transactions.md` §6.1) is **slightly
inaccurate**: Monero's `D` check is not cofactor handling only, it also rejects `D = 0`.

### 2.3 What is correct and well designed

- **Prime-order group, canonical encodings.** `Point::decode` uses dalek's
  `CompressedRistretto::decompress` (RFC 9496 §4.3.1), so every key image has exactly one
  encoding; the spent-key-image set is keyed by those bytes (`tx/src/state.rs:274`,
  `validate.rs:497`). The Monero 2017 torsion double-spend class cannot occur [math; tested
  negatively: `point.rs::non_canonical_points_rejected`, `clsag_every_point_alteration_fails`].
  **Roster question answered:** torsion does not apply; canonicity holds for `I`, `D`,
  ring members and `C'`. The residual gap is only that the invalid-encoding list of RFC 9496
  Appendix A.2 is not pinned (finding C4).
- **Linking-tag check (Cypher Stack 2024).** The LSAG-lineage unforgeability proof silently
  needs every verifier round to embed the previous challenge through a nonzero point; the
  cheapest sufficient check is that the linking tag is not the identity. BlackSilk checks it
  twice (T4 stateless, and `verify`) [source-read]. **Complete and verified.**
- **Signer safety.** `sign` refuses wrong `p` (constant-time byte compare) and wrong `z`
  (dalek `RistrettoPoint` equality is constant-time) before any output, so a wallet bug
  cannot emit a signature leaking secrets [tested: `wrong_secrets_are_refused_by_the_signer`,
  `amount_mismatch_cannot_be_signed`].
- **Hedged nonces (F2).** The stream binds label, `m`, `C'`, `I`, `D`, `π`, all `P[i]`,
  all `Cr[i]`, with length-prefixed items [tested: `nonce_stream_binds_every_transcript_input`,
  `broken_rng_ring_change_alone_changes_nonces`, `broken_rng_message_key_image_and_d_change_nonces`,
  `pre_f2_derivation_leaks_the_spend_key_and_fix_prevents_it` (a working key-recovery
  regression), `nonce_label_domain_separation`].
- **Statement binding.** The signed message (`tx/sig-message`) covers network id, branch
  id, prefix (kind byte, key images, ring indices, outputs, fee, deploy payload), pseudo-outs
  and the BP+ bytes; PX additionally covers the PX proof. Ring *contents* are bound by the
  transcript. Each CLSAG is bound to its own `I` and `C'` through `μP`, `μC` [source-read;
  tested: `c3_signatures`, `tx/tests/malleability.rs`, `tx/tests/upgrade.rs` (branch id)].
- **Ring hygiene** is enforced by consensus outside `clsag.rs`: strictly increasing ring
  indices (T5, decoder rejects zero deltas), identity output keys rejected everywhere
  (T6, B7, PX `px.rs:672`), global one-time-key uniqueness (C4), so ring members are
  distinct non-identity points and two outputs never share a key image [source-read].
- **Side channels.** Secret arithmetic uses dalek constant-time paths; the pinned dalek is
  `=4.1.3`, the first release fixed for RUSTSEC-2024-0344 (compiler-inserted branch in
  `Scalar52::sub`) [source-read `crypto/Cargo.toml`; advisory read]. The loop always runs
  15 iterations; indexing by `π` is a co-resident cache channel only (R2, Info, standard).

### 2.4 What the tests actually prove

| Property | Evidence | Class |
|---|---|---|
| Completeness at every index | `signs_and_verifies_at_every_index`, `property_random_rings` (24 random) | tested |
| Soundness against single-field tampering | `any_modification_invalidates`, `clsag_every_scalar_alteration_fails`, `clsag_every_point_alteration_fails` (±1, neg, zero, ×2, +G, identity, swaps, rotations) | tested (mutation-style, not proof) |
| Keyless forgery | `keyless_forgery_fails` (8 random tuples) | tested, weak evidence; the real argument is the paper's reduction [mathematically established in the ROM, with the 2024 correction] |
| Linkability | `key_images_link_spends_of_the_same_output` | tested |
| Balance via CLSAG | `amount_mismatch_cannot_be_signed` | tested |
| Hedging | F2 tests above | tested |
| Byte-exact stability | `nonce_and_signature_test_vector` | tested, **self-generated** (pins behaviour, proves nothing about correctness) |
| Anonymity | `responses_look_uniform` (non-zero, distinct) | sanity only; the real argument is RO-DDH (paper Thm 4) [assumed/mathematical] |
| Conformance with an independent implementation | none | **unknown** |
| `D = identity` behaviour | `clsag_identity_key_image_and_d` replaces `D` of a valid signature by identity and expects failure; this proves only that a *mutated* signature fails, not that the rule exists | tested, but misleading name (finding C1) |
| Verify never panics on arbitrary input | no fuzz target | unknown (types make panics unlikely) [source-read] |
| Cost | no benchmark; R12's 2-4 ms is an estimate | unknown |

---

## 3. Problems in scope

### P1. `D = identity` is accepted (finding C1)

- **What and why.** `verify` rejects `I = 0` but not `D = 0`. It was written from the
  paper's `Verify`, whose signature space `G^d` includes the identity; Monero and
  monero-oxide both reject it (`verRctCLSAGSimple`: `CHECK_AND_ASSERT_MES(!(D_8 ==
  rct::identity()), false, "Bad auxiliary key image!")`; monero-oxide `ClsagError::InvalidD`).
  The paper's key generation draws secret keys from `(F_p^*)^d`, so an honest `D` is never 0.
- **When does it happen?** `D = z·Hp(P_π)`, so `D = 0 ⇔ z = 0 ⇔ C' = Cr[π]`. The honest
  builder derives pseudo masks from the hedged stream, so this occurs with probability
  about 2^-252. A buggy or hand-rolled wallet that reuses the input's mask as the
  pseudo-output mask would produce it.
- **Consequences.**
  - Soundness: none known. With `I ≠ 0`, `𝔚 = μP·I + μC·D ≠ 0` except with negligible
    probability, which is the Cypher Stack condition [math].
  - Privacy: a signature with `D = 0` is *always* accompanied by `C' = Cr[π]`, which
    reveals the real spend to everyone (compare `C'` with the 16 ring commitments). The
    check turns a silent full deanonymization into a rejected transaction.
  - Conformance: a Monero-derived second implementation would reject such a block while
    BlackSilk accepts it: a latent chain split between implementations.
- **Classification.** Consensus-critical (validity rule), privacy-relevant (defence in
  depth), Low severity.
- **Prior art.** Monero (since CLSAG, 2020) and monero-oxide reject it; the paper's key
  space excludes it.
- **Alternatives.** (a) Consensus rule `D ≠ identity` in `clsag::verify` (and listed under
  T11 as stateless); (b) wallet-only refusal of `z = 0`; (c) a broader consensus rule
  "`C'` differs from every ring commitment" (covers the same real-member case plus the
  decoy case, which needs knowledge of a decoy's opening and is harmless). Recommended:
  (a) + (b). (c) adds 16 comparisons per input for no extra security.
- **What could go wrong.** A rule change after launch would need activation; before the
  freeze it rides the genesis rule set. Existing self-pinned vectors are unaffected
  (their `D ≠ 0`). Error classification: `D = 0` is decidable from the signature alone, so
  it can be reported as a stateless error (a new `TxError` variant or a `DecodeError`),
  which peer scoring may penalize; keeping it inside `verify` alone would make it
  contextual (`InvalidSignature`). Decide consistently with workstream 11.
- **Tests.** A signature produced with `z = 0` through a test-only signer (the reference
  signer of P3 with explicit nonces) that verifies today and must fail after the change;
  a builder test that `sign` returns a new `ClsagError::ZeroCommitmentSecret`; a stateless
  classification test; golden reject vector.
- **Invariants.** Never relax `I ≠ identity`; never accept a signature that fails today.

### P2. No external or independent anchor for correctness (R2-C11 part, roster question 2)

- **What and why.** The only vector is self-generated (`clsag.rs:930-1002`). Because of Δ1
  (Ristretto) and BlackSilk's own tags, no third-party vector can exist: I searched for
  Ristretto CLSAG implementations; the ones found (crate-crypto/CLSAG, the `nazgul` crate)
  use their own transcripts and are not interoperable [web search, §8].
- **Consequences.** A transcript error symmetric in `sign` and `verify` (for example a
  wrong item order, a missing item, or a tag typo) passes every existing test, because each
  test uses the same `Transcript`. Once the testnet launches, such an error becomes
  consensus and would need a hard fork to fix. Consensus-critical; testing gap.
- **How others solve it.** Monero relies on its unit tests plus the external review; the
  monero-oxide crate re-implemented CLSAG independently and is exercised against real
  mainnet transactions, which is a de facto cross-implementation. Zcash and Bitcoin
  maintain spec-level test vectors (ZIP test vectors, BIP-340 `test-vectors.csv` with
  intermediate values and negative cases).
- **Proposed solution (a four-tier plan, see §5 W2-W5).**
  1. **Independent reference implementation in test code**, written from
     `docs/transactions.md` §6.1 only: its own Blake2b calls (not `Hasher64`), its own tag
     encoding, its own loop, and a signer that takes explicit `α` and `s[i]`. Differential
     tests in both directions over random rings, all 16 indices and adversarial inputs.
  2. **Normative known-answer file** (`crypto/tests/vectors/clsag.json`) generated by the
     reference signer with explicit nonces (so the vectors do not depend on `HedgedRng`),
     with intermediate values (`Hp_i`, `μP`, `μC`, every `c_i`, `W`) and negative vectors
     (identity `I`, identity `D`, `c0 + 1`, swapped `s`, rotated ring, non-canonical
     encodings at the decoder). This follows the BIP-340 vector style and doubles as a
     second-implementation base (workstream 01 golden vectors).
  3. **Monero structural conformance (optional, P2).** A test-only CLSAG core generic over
     (group, `Hs`, `Hp`, tags). Instantiate once with Ed25519 + Keccak + Monero
     `hash_to_ec` and verify two or three real Monero mainnet CLSAGs from a checked-in
     fixture of public chain data. Instantiate once with Ristretto + BlackSilk tags and
     require byte equality with `clsag.rs`. This anchors the algebra and item order to the
     deployed, externally reviewed scheme. Cost: dev-only pure-Rust `sha3` plus a port of
     `ge_fromfe_frombytes_vartime` (or monero-oxide's generator crate). Keep it in an
     out-of-workspace tool crate (like `fuzz/`) so no dependency enters the workspace lock
     (decision for workstream 44).
  4. **External primitive anchors.** RFC 9496 Appendix A.3 (element derivation) vectors
     pin `Hp`; A.1/A.2 pin encode/decode. These are the only true external vectors
     reachable for BlackSilk's CLSAG building blocks.
- **Trade-offs.** Tier 1 catches implementation slips, not specification errors. Tier 3
  catches specification drift from Monero but costs a fixture and dev dependencies. A
  "different author" requirement (R2) is only approximated by agents; the reference must
  not import `clsag.rs` internals.
- **Invariants.** The verification equation, tags, `Hp`, key-image definition and message
  definition are on the never-change list (full review item 10); tests only pin them.

### P3. Batch-verification safety (roster question 3)

- **Finding.** CLSAG cannot be batch-verified by random linear combination. Each `c_{i+1}`
  is a hash of the previous round's `L_i`, `R_i`, so every point must be computed and
  compressed individually [math]. Neither Monero nor monero-oxide batches CLSAG; Monero
  parallelizes per input (`verRctNonSemanticsSimple` thread pool) [source-read].
  BlackSilk has no CLSAG batch and no CLSAG cache [source-read `validate.rs`, `chain/src`].
  **Status: safe by absence.**
- **What is safe:**
  - **Per-input parallelism** is deterministic if the verdict is `all(ok)` and the reported
    error is the lowest failing `(tx, input)` index (compute all, then take the minimum),
    so `TxError` stays identical to the serial path (peer scoring depends on it).
  - **A verified-signature cache** is sound only if keyed by the full statement: the hash
    of the signature bytes, `m`, `C'`, `I` and the *resolved* ring bytes (not the global
    indices). A tx-id key is unsound across reorgs deeper than the spendable age, because
    the same indices can resolve to different outputs (R12 §I6 warns about the same
    thing). The branch id is inside `m`.
  - **A `Hp(P)` cache** (R2 P3 suggestion) is sound as an in-memory memo keyed by `P`
    bytes. If persisted, it must be recomputed or integrity-checked on load: a corrupted
    stored `Hp` changes which signatures verify.
- **Owner.** Workstream 10 (implementation); this dossier supplies the soundness conditions.
  Tests: parallel == serial differential over mixed valid/invalid blocks, including the
  error index.

### P4. Assumption statement in the docs (finding C3)

- `docs/transactions.md` §9 says "Nothing else is assumed" beyond DL, DDH and ROM, and
  §13 says "CLSAG unforgeability under DL in the ROM". The published CLSAG proof (ePrint
  2019/654, Thm 2) reduces to a κ-one-more DL variant, and Cypher Stack (2024) found two
  gaps: the implicit nonzero requirement (satisfied here, P1/§2.3) and a flawed OMDL
  reduction, which they repaired with a reduction to plain DL whose bound is loose
  (`O(ε²/q²)`, non-tight). The Monero post says neither Monero nor Zano is affected.
- **Consequence.** Not a vulnerability; an accuracy issue under the owner's
  no-overclaim policy. Informational.
- **Fix.** Docs: cite the 2024 correction, say that the reduction is non-tight, and say
  that BlackSilk satisfies the added nonzero-tag condition by rejecting `I = identity`.

### P5. Cost is unmeasured (R12-2 dependency)

- There is no CLSAG benchmark; R12's `t_clsag ≈ 2-4 ms` is an estimate
  [R12-performance.md:151]. R12-2 (about 12,100 CLSAGs per block) is a P0 decision that
  needs the measured number. Per verification: 16 `Hp` (two Elligator maps plus a
  Blake2b-512 each), 16 three-term and 16 two-term vartime MSMs, 32 compressions, 18
  Blake2b calls. Possible optimizations that do not change consensus: vartime precomputation
  for `W` and `G` (monero-oxide precomputes `I`, `D`), the `Hp` memo, and per-input
  parallelism. None changes a byte of any signature. Owner: 45/10. Liveness and
  performance, not consensus.

### P6. Test-coverage gaps

- No fuzz target for `clsag::verify` (R13 T-6); no cargo-mutants run on `clsag.rs` (T-12).
- `clsag_identity_key_image_and_d` suggests that `D = identity` is rejected by rule; it is
  only a mutation test (finding C1).
- No test that a signature for input `j` cannot be moved to input `k` of the same
  transaction when both inputs use the **same ring** (the ring indices of two inputs may
  coincide, since T5 is per input). It fails today because `I` and `C'` enter `μ` and the
  inputs are sorted by key image [math], but it is not pinned.
- No property test that `verify` is a deterministic pure function of its inputs across
  randomized repeated calls (trivial, but useful for the parallel path).

---

## 4. New findings

| ID | Severity | Status | Location | Scenario | Confidence |
|---|---|---|---|---|---|
| **C1** | Low | Not implemented | `crypto/src/clsag.rs:262-271` (`verify`), `tx/src/validate.rs:300-360` (T11 has no `D` rule), `docs/transactions.md:453,532` | A wallet that sets the pseudo-out mask equal to the input mask (`z = 0`) produces `D = 0` and `C' = Cr[π]`; BlackSilk accepts the transaction and the real spend is visible to everyone; Monero and monero-oxide reject the same signature (`"Bad auxiliary key image"`, `InvalidD`), so a Monero-derived second implementation would split. Soundness is unaffected because `I ≠ 0` is enforced. | High (both reference implementations read in source) |
| **C2** | Low (testing; consensus-risk multiplier) | Partially implemented | `crypto/src/clsag.rs:930-1002` | Only a self-generated vector exists; a symmetric transcript slip in `Transcript::new` passes all tests. | High |
| **C3** | Informational | Not implemented (docs) | `docs/transactions.md:593-597, 1051` | The docs claim unforgeability "under DL"; the published proof uses κ-OMDL and was found to have gaps (Cypher Stack 2024); the repaired reduction to DL is non-tight. | High |
| **C4** | Low | Not implemented | `crypto/src/hash.rs:250-300` (`kat_matches_definition` is self-referential), `crypto/src/point.rs` tests | `Hp` (key-image base) and decode are pinned only against dalek itself; RFC 9496 A.1-A.3 vectors are absent. A dalek upgrade that changed `from_uniform_bytes` would silently change every key image (consensus). The dependency is pinned `=4.1.3`, which mitigates. | High |
| **C5** | Low (docs drift) | Not implemented | `docs/transactions.md:1068` | The docs say invalid-signature relays are "not penalized: an open defect (N-11)", but `p2p/src/net.rs:2325-2360` penalizes `InvalidSignature` when all ring members are ≥ `SIGNATURE_BURIAL = 60` deep (register R6 TX-2: fixed). | Medium (read the gate, not its tests) |
| **C6** | Informational | Accepted limitation | `crypto/src/clsag.rs:285` | Monero rejects an intermediate challenge equal to zero; BlackSilk does not. Probability 2^-252 per round; no security effect. Recommend **not** adding a rule (it would be a consensus rule that is never exercised). Record the deviation in §14. | High |
| **C7** | Informational | Accepted limitation | `crypto/src/clsag.rs:217-255` | Secret index `π` used for array indexing and loop start (co-resident cache channel only); temporaries such as `μP·p + μC·z` are `Copy` scalars and not zeroized. Consistent with R2 §12 and R2-C10 ("best effort"). | High |
| **C8** | Informational | Not implemented (tests) | `tx/tests/malleability.rs`, `crypto/tests/malleability.rs` | Cross-input signature transplant with identical rings is not pinned by a test (it fails today by construction). | High |

No Critical, High or Medium issue was found in `clsag.rs`. The construction, transcript,
canonicity, hedging and linking-tag check are correct according to the evidence above.

---

## 5. Implementation plan for phase 2

Ordered by priority. Ownership lists the files to modify; the coordinator assigns final
ownership.

| # | Item | Files (ownership) | Consensus | Identity impact | Tests | Bench | Docs | Size | Priority |
|---|---|---|---|---|---|---|---|---|---|
| **W1** | **Reject `D = identity`** (C1): add `if sig.d.is_identity() { return false; }` in `clsag::verify`; add a stateless structural check under T11 (a new `TxError::SignatureAuxIdentity { input }` or equivalent, classified stateless) for transfer, PX and deploy; `sign` refuses `z == 0` with `ClsagError::ZeroCommitmentSecret` | `crypto/src/clsag.rs`; `tx/src/validate.rs` (`check_structure`, the PX/deploy structure path); `tx/src/px.rs` (PX structure checks near 655); `tx/src/lib.rs` or wherever `TxError` lives (coordinate with 11) | **Yes** (tightening; genesis rule set, no activation needed before launch) | Changes the rule set, not any existing honest transaction; the genesis block body is empty. If rule-set digests or golden vectors hash the rule list, update them. | unit: `z = 0` signature verifies before, fails after; `sign` refusal; stateless classification; golden reject vector; regression: every existing vector unchanged | none | `transactions.md` §6.1 verification line, §8.1 T11, §13, §14 (note Monero parity), §16 item 3 | S | **P0** (before freeze; rule change) |
| **W2** | **Independent reference CLSAG** (C2 tier 1): a test-only module written from §6.1 alone (own Blake2b usage, own tag encoding, explicit-nonce signer); differential sign/verify both directions over all 16 indices, 256 random cases, adversarial cases | `crypto/tests/clsag_reference.rs` (new) | No | none | differential, property | none | §16 item 3 | S | **P1** |
| **W3** | **Normative KAT file** (C2 tier 2): at least 6 accept vectors (π = 0, 6, 15; one with `C'` equal to a decoy's commitment; one with a single-input builder-shaped statement) and at least 8 reject vectors, each with intermediate values; loaded by a test in `crypto` and referenced by the spec | `crypto/tests/vectors/clsag.json` (new), `crypto/tests/clsag_vectors.rs` (new); spec appendix in `docs/transactions.md` | No (pins current rules; W1's reject vector included) | none | KAT, negative | none | new §6.2 "Test vectors" | S | **P0** (freeze requires pinned vectors, R13 item 2) |
| **W4** | **RFC 9496 vectors** (C4): A.1 multiples, A.2 invalid encodings, A.3 element derivation; plus a KAT for `key_image_base` built on A.3 | `crypto/src/point.rs` tests, `crypto/src/hash.rs` tests (coordinate with 19, which owns `hash.rs`) | No | none | KAT | none | §16 item 1 | S | **P1** |
| **W5** | **Fuzz target `clsag_verify`**: structure-aware (start from a valid signature, mutate any field or ring member or message); oracles: no panic, and accept only when every byte equals the original | `fuzz/fuzz_targets/clsag_verify.rs` (new), `fuzz/Cargo.toml` (coordinate with 41) | No | none | fuzz | none | `fuzz/` README | S | **P1** |
| **W6** | **Mutation testing** of `clsag.rs`: run cargo-mutants, triage survivors, add killing tests (for example, a mutant that drops `D` from `μ` must be killed by W2/W3) | tests only in `crypto/tests/` (coordinate with 42) | No | none | mutation | none | test report | S | **P1** |
| **W7** | **Pinning tests** (C8, P6): cross-input transplant with identical rings; `verify` determinism; rename or re-document `clsag_identity_key_image_and_d` after W1 so it tests the rule, not a mutation | `crypto/tests/malleability.rs`, `tx/tests/malleability.rs` | No | none | adversarial, regression | none | none | S | **P1** |
| **W8** | **Benchmarks**: `sign`, `verify`, `key_image_base`, 64-input transaction; feed R12-2 | `crypto/benches/clsag.rs` (new) or the workstream-45 harness | No | none | none | yes (single thread, and 1/2/4/8 threads for W9) | R12 data | S | **P0 as data for the R12-2 decision** (owner 45) |
| **W9** | **Per-input parallel C3 with deterministic error index**; optional in-memory `Hp` memo; optional statement-keyed verified-signature cache | `tx/src/validate.rs` (C3 loop), `chain/src/manager.rs` (owner 10) | No (the verdict and the error are identical) | none | parallel == serial differential over mixed blocks, including error indices | yes | `transactions.md` §8 note | M | P2 (owner 10) |
| **W10** | **Monero structural conformance harness** (C2 tier 3): generic core, Ed25519/Keccak instance verifying real Monero CLSAG fixtures, Ristretto instance byte-equal to `clsag.rs` | `tools/clsag-conformance/` (new, out of workspace like `fuzz/`), fixture JSON of public Monero data | No | none | differential | none | `reviews/` note | M | P2 (needs a 44 decision on dev dependencies) |
| **W11** | **Docs accuracy** (C3, C5, P1): assumption statement with the 2024 correction; stale N-11 text; "follows Monero except cofactor" wording; §14 row listing C1/C6 parity decisions | `docs/transactions.md` §6.1, §9, §13, §14 (owner 47) | No | none | none | none | as listed | S | P1 |

Suggested sequence: W3 and W2 first (they pin the current behaviour, including a vector
that W1 then flips to reject), then W1, then W4 to W7, with W8 feeding workstream 10/14 and
the R12-2 decision.

---

## 6. Dependencies and conflicts

- **01 consensus-core:** W1 adds a validity rule; the golden-vector corpus should import
  W3's vectors.
- **10 block-validation-pipeline:** W8 data for R12-2; W9 parallel C3 and cache conditions
  (§3 P3). `validate.rs` C3 loop ownership overlaps with 10.
- **11 tx-validation:** the new T11 stateless variant and its classification; `TxError`
  and `check_structure` ownership overlaps with 11. One of us should own the edit.
- **13 mempool-frontrunning-c4:** no conflict; C4 is what guarantees distinct key images
  for distinct outputs (I rely on it in §2.3).
- **16 bulletproofs-plus:** shares `crypto/tests/malleability.rs`; coordinate edits.
- **18 crypto-randomness:** owns `nonce.rs`; CLSAG hedging is already complete (F2); the
  membership nonce (R2-C5) is theirs.
- **19 hash-domain-separation:** owns `hash.rs`; W4's `Hp` vectors touch its tests; tags
  `clsag/*` must stay unchanged.
- **38 wallet-privacy:** decoy selection and same-ring-for-two-inputs are wallet privacy
  questions, not CLSAG ones.
- **41 fuzzing, 42 mutation-formal:** W5, W6.
- **44 supply-chain:** W10 dev dependencies (`sha3`, possibly monero-oxide crates).
- **45 benchmarks:** W8.
- **47 docs-spec-consistency:** W11 (C3, C5).

---

## 7. Open questions for the coordinator

1. **W1 classification:** should `D = identity` be a stateless error (penalizable, in
   `check_structure`) or stay inside `verify` as `InvalidSignature` (contextual)? I
   recommend stateless: it is decidable from the transaction alone, like `I = identity`
   (T4).
2. Does any rule-set digest, branch-id derivation or golden vector hash the list of
   validity rules, so that W1 changes a pinned identity? I found none in scope, but 01
   and 40 should confirm.
3. **W10:** is a checked-in fixture of public Monero chain data and a dev-only `sha3`
   dependency in an out-of-workspace crate acceptable under the pure-Rust and supply-chain
   policy? If not, W2 + W3 + W4 are the fallback, and the conformance claim stays "matches
   Monero by source reading".
4. Should C6 (Monero's zero-challenge check) be adopted anyway for strict Monero parity?
   My recommendation is no; I ask for a recorded decision.

---

## 8. Sources

- B. Goodell, S. Noether, A. Blue, "Concise Linkable Ring Signatures and Forgery Against
  Adversarial Keys", IACR ePrint 2019/654 (latest revision July 2020).
  https://eprint.iacr.org/2019/654
- J.-P. Aumasson, A. Vennard, "Monero CLSAG review" (OSTIF), 29 July 2020.
  https://www.getmonero.org/resources/research-lab/audits/clsag.pdf ; announcement
  https://www.getmonero.org/2020/07/31/clsag-audit.html
- Monero, `src/ringct/rctSigs.cpp` (`CLSAG_Gen`, `verRctCLSAGSimple`,
  `verRctNonSemanticsSimple`), master.
  https://github.com/monero-project/monero/blob/master/src/ringct/rctSigs.cpp
- monero-oxide, `monero-oxide/ringct/clsag/src/lib.rs` (`Clsag::verify`, `InvalidD`).
  https://github.com/monero-oxide/monero-oxide/tree/main/monero-oxide/ringct/clsag
- Cypher Stack, "Zano d/v-CLSAG review" (2024), source and final report.
  https://github.com/cypherstack/zano-clsag-review (release `final`:
  https://github.com/cypherstack/zano-clsag-review/releases/tag/final)
- Monero Project, "CLSAG security proof revisions", 8 March 2024.
  https://www.getmonero.org/2024/03/08/clsag-security-proof-revisions.html
- RFC 9496, "The ristretto255 and decaf448 Groups" (§4.3.1 decode, §4.3.4 element
  derivation, Appendix A test vectors). https://www.rfc-editor.org/rfc/rfc9496.html
- RUSTSEC-2024-0344, curve25519-dalek timing variability in `Scalar29::sub`/`Scalar52::sub`,
  patched in 4.1.3. https://rustsec.org/advisories/RUSTSEC-2024-0344.html
- BIP-340 test-vector format (the style model for W3).
  https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
- Other Ristretto CLSAG implementations (checked for interoperable vectors; none exist):
  https://github.com/crate-crypto/CLSAG ; https://crates.io/crates/nazgul
- Monero FCMP++ (the long-term replacement of rings; context for the statistical-anonymity
  limitation). https://www.getmonero.org/2024/04/27/fcmps.html ;
  https://ccs.getmonero.org/proposals/fcmp++-research.html
