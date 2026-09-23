# Security review: contract cryptography (balance kernel, scoped membership, claims)

Status: **internal review, M1 (2026-09-23).** Written by the implementer, so it is
not independent. It prepares the external review ([contracts.md](../contracts.md)
§16.4) by stating each construction, what it must guarantee, the argument, the tests
that exercise the argument, and the open questions. Nothing here counts as a proof
until an external cryptographer has checked it.

| Construction | Code | Spec |
|---|---|---|
| Tagged Schnorr (kernel, auth, claim-eq, claim-val) | `crypto/src/schnorr.rs` | contracts.md §6.2, §7.1, §8 |
| Scoped membership (linkable ring signature with a scope base) | `crypto/src/membership.rs` | §7.2 |
| Range, equality and reveal claims | `crypto/src/claims.rs` | §8 |
| Balance kernel: the transaction equation | (M3: `tx`) | §6 |

**Assumptions:** those of transactions.md §9, and nothing else:
- DL and DDH in Ristretto255;
- the random-oracle model for Blake2b-based `Hs`/`Hp`;
- independent generators;
- a hedged CSPRNG.

---

## 1. Tagged Schnorr signatures

**Construction.**

```
R = t·G,  c = Hs(tag, K ‖ R ‖ m),  s = t + c·k;   verify: K ≠ 0 and s·G − c·K = R
```

The tag is length-prefixed with the `BlackSilk/v1/` domain (§1.2 of transactions.md).

**Required properties:**
- existential unforgeability under chosen-message attack, per tag and key;
- signatures under one tag are useless under another;
- a signature cannot be moved to another key.

**Argument.**
- This is textbook Schnorr with key prefixing. EUF-CMA holds under DL in the ROM
  (Pointcheval–Stern forking lemma).
- The tag is part of the hash input, so the four uses are four independent random
  oracles. The tests `any_modification_invalidates` (tag case) and
  `claim_tags_are_not_interchangeable` check this.
- Key prefixing binds `K`, which prevents the related-key and key-substitution
  issues of unprefixed Schnorr.

**Review findings, fixed in the design:**

| # | Issue | Resolution | Test |
|---|---|---|---|
| SCH-1 | For `K = identity`, any `(s·G, s)` verifies. The balance kernel's `E` is the identity whenever masks cancel, e.g. equal numbers of public notes on both sides. | `verify` rejects the identity key. The spec requires `E ≠ identity` and a builder-only mask in every call (K2). | `identity_key_is_rejected` |
| SCH-2 | Nonce reuse across two messages reveals `k`. | Hedged nonces over the secret, tag, key and message (§10). | `broken_rng_does_not_reuse_nonces` (constant RNG) |
| SCH-3 | Signing with a mismatched secret could leak information if the caller is buggy. | The signer checks `k·G = K` in constant time first. | `wrong_secret_is_refused` |
| SCH-4 | Malleable encodings. | Canonical point and scalar decoding only; every bit flip is rejected or invalid. | `any_modification_invalidates`, `non_canonical_scalar_is_rejected_in_decoding` |

**Open questions:** none specific to Schnorr.

---

## 2. Balance kernel (design review; implemented in M3)

**Statement.** For a call with:
- pseudo-outputs `C'_k`;
- consumed notes `N_i`;
- outputs `Cm_j`;
- new notes `M_j`;
- fee `f`:

```
E = Σ C'_k + Σ N_i − Σ Cm_j − Σ M_j − f·H,   E ≠ 0,   Schnorr_{contract/kernel}(E, sig_message)
```

**Required properties:**
- **K-1:** no inflation;
- **K-2:** consuming a note requires knowing its opening;
- **K-3:** non-malleability.

**Argument for K-1.** The reduction knows the openings of every commitment on chain.
- It created the honest ones itself.
- Adversarial ones are extracted from their range proofs: BP+ is knowledge-sound
  (Chung et al. 2020, Thm. 3).
- Each pseudo-output's opening follows from its CLSAG. CLSAG extracts `z` with
  `C_{π} − C' = z·G` (Goodell et al. 2019), so `C'` opens to the value of `C_π`.
- Forking the kernel yields `e` with `E = e·G`.
- `E` then equals `Δ·H + ρ·G`, with `Δ = Σ in − Σ out − f` and `ρ` known.
- If `Δ ≢ 0 (mod ℓ)`, then `H = ((e − ρ)/Δ)·G`, which breaks DL.
- All amounts are in `[0, 2^64)`, with at most 80 terms per side, so
  `|Δ| < 2^71 < ℓ`. Hence `Δ = 0` over the integers.

This is the Mimblewimble argument. Fuchsbauer, Orrù and Seurin (EUROCRYPT 2019) prove
it formally for aggregate cash systems.

**Argument for K-2.** The same extraction gives the reduction `e` and the openings of
every term other than the `N_i`. So it obtains an opening of `Σ N_i`.
- A single consumed note: the builder knew its opening.
- Several notes: it knew the opening of their sum. That is enough to know each one
  as soon as it knows any subset. Notes created by others are independent, so it
  cannot know their sum without knowing them.
- **Rogue commitment attempt:** make the victim's note cancel by creating a new note
  `M = N_victim + X` in the same transaction. This fails, because `M` must be
  range-proven in that transaction, and BP+ extraction then yields `M`'s opening,
  hence `N_victim`'s. Public new notes have public openings by definition.

**Argument for K-3.**
- `sig_message` covers every non-signature byte.
- A third party would need a spend key (CLSAG) or `e` (kernel).
- Rule K2 of contracts.md (`n ≥ 1` or a private output) puts a builder-only mask
  into `e`.

**Review findings, fixed in the spec during M0/M1:**

| # | Issue | Resolution |
|---|---|---|
| KER-1 | A call built only from public notes has `E` computable by anyone; with equal counts of public notes on both sides, `E = 0`. Anyone could re-sign it with altered outputs, fee or input. | Rule K2 (at least one ring input or one private output), plus SCH-1. |
| KER-2 | Without inputs, a counterparty who knows every term's opening (e.g. a note consumed back to its creator) could re-sign. | Wallet rule: calls without ring inputs always carry an output to the builder's own address (contracts.md §6.3). |

**Open questions for external review:**
- **KER-Q1:** Tightness and composition of the multi-extractor argument. BP+,
  several CLSAGs and the kernel are all rewound in one ROM game. FOS19 handles
  Schnorr kernels plus range proofs, but not CLSAG ring inputs in the same excess.
- **KER-Q2:** Whether "knowledge of the aggregate opening" (K-2) is the right
  guarantee for contracts that assume "the consumer knows *this* note's amount".

---

## 3. Scoped membership (anonymous voting)

**Construction.** A bLSAG with a common tag base
`B = Hp("contract/scope", owner ‖ set ‖ len ‖ scope)`:
- tag `I = x·B`;
- ring size 1–16;
- the ring, `B`, `I` and the message are hashed into every challenge.

**Required properties:**

| # | Property | Argument | Tests |
|---|---|---|---|
| M-1 | Correctness at every size and index | Standard | `signs_and_verifies_for_every_size_and_index` (1–16 × all indices) |
| M-2 | Unforgeability: only a member can sign | Rewinding two challenges at the real index yields `x` with `x·G = P_π` (DL, ROM) | `outsiders_cannot_sign` |
| M-3 | Linkability: one tag per member per scope | The same extraction gives `x` with `P_π = x·G` and `I = x·B`, so `I` is determined by the member | `tags_link_within_a_scope_only` |
| M-4 | Non-frameability: no one can produce another member's tag | Producing `I_victim` requires `x_victim` (CDH/DL); a signature with a foreign tag fails | `framing_with_another_members_tag_fails` |
| M-5 | Anonymity within the ring | bLSAG anonymity under DDH: `(B, I = x·B, P = x·G)` looks like a random triple | `responses_look_uniform` (sanity only; anonymity is not testable) |
| M-6 | Unlinkability across scopes and contracts | Different `B` per `(owner, set, scope)`; `x·B1`, `x·B2` unlinkable under DDH | `tags_link_within_a_scope_only`, `scope_encoding_is_unambiguous` |
| M-7 | Tag differs from the CLSAG key image of the same key | Different bases | `tags_link_within_a_scope_only` |
| M-8 | Transcript binds everything | Any change of message, ring member, order, size, scope, owner, set, tag, `c0` or `s_i` fails | `any_modification_invalidates` |
| M-9 | Identity tag or member rejected | `x = 0` and identity members excluded | `identity_tag_and_members_are_rejected` |
| M-10 | Nonce safety with a broken RNG | Hedged nonces | `broken_rng_does_not_reuse_nonces` |

**Review findings (requirements on contracts and the SDK):**

| # | Issue | Resolution |
|---|---|---|
| MEM-1 | **The prover chooses the scope bytes.** A contract that accepts any scope lets a member vote once per scope, i.e. unlimited times. | The contract must compare the proof's scope with the expected one (e.g. `"proposal-17"`). The SDK voting helper takes the expected scope as a parameter and rejects others; tested in M4. |
| MEM-2 | A key registered in two sets of one contract gets two unrelated tags. | Contracts must accept a given action from one set only; documented in the SDK. |
| MEM-3 | Small rings. | Contracts require `r = 16`, or `r = |set|` for smaller sets (spec §7.2). |
| MEM-4 | Tag knowledge after key compromise: whoever learns `x` can compute the member's tag in every scope, and so link its past actions. | Inherent to linkable ring signatures; documented (spec §7.2). |

**Open questions for external review:**
- **MEM-Q1:** Anonymity against *adversarially chosen ring keys*. Contracts add keys
  supplied by anyone. Ring key-prefixing is present, but the formal model
  (Bender–Katz–Morselli) should be checked for the fixed-base variant.
- **MEM-Q2:** Linkability with a fixed base when the adversary controls several
  members' keys: can it produce tags outside `{x_i·B}`? The standard answer is no,
  by a multi-fork extraction, but it should be confirmed for this transcript.

---

## 4. Claims

**Range claim.** BP+ over `V0 = C − min·H` and `V1 = max·H − C`, with masks `y` and
`−y`.
- **Argument:** `a0, a1 ∈ [0, 2^64)` and `a0 + a1 = max − min` over the integers
  (the sum is below `2^65 < ℓ`). So `v = min + a0 ∈ [min, max]`.
- The argument does **not** need `C` itself to be range-proven.
- The statement (`min`, `max`, `C`) enters the BP+ transcript through `V0` and `V1`,
  and the transaction binds the claim list through `claims_hash`.

| Test | Checks |
|---|---|
| `range_claims_hold_exactly_at_the_bounds` | `v` at both bounds, `0`, `2^64 − 1`, degenerate `min = max`; moving a bound invalidates the proof |
| `honest_prover_refuses_false_or_bad_statements` | Out of range, `min > max`, wrong opening |
| `a_false_range_statement_cannot_be_proven_by_shifting_openings` | A proof for another commitment does not transfer; a wrap-around statement cannot be built; `min > max` never verifies |
| `range_proof_mutations_are_rejected` | Scalar and point mutations; a truncated proof |

**Equality and reveal claims.** Schnorr under separate tags, over `C_a − C_b` and
`C − v·H`, with `sig_message` as the message. Sound by binding (DL).

| Test | Checks |
|---|---|
| `equality_claims` | Equal amounts pass; unequal amounts cannot be signed or forged; order, message and self-equality handled |
| `reveal_claims` | Exact value, off-by-one, message binding, public-note mask 1 |
| `claim_tags_are_not_interchangeable` | An equality signature is not a reveal or auth signature over the same key |

**Review findings:**

| # | Issue | Resolution |
|---|---|---|
| CLM-1 | Equality between a commitment and itself (or reveal over a mask-0 commitment) has the identity as key, so it would be forgeable. | Refused by the prover (`Degenerate`) and rejected by the verifier (SCH-1). The transaction layer additionally requires `ref_a ≠ ref_b` (M3). |
| CLM-2 | A BP+ claim proof is not bound to one transaction by itself. | It proves a true fact about a public commitment, so replay gains nothing. The claim list is bound via `claims_hash` ⊂ `sig_message`. |
| CLM-3 | A reveal claim deliberately makes an amount public. | The SDK and wallet must show the user what a claim reveals. Range claims leak the interval by design. |

**Open questions for external review:**
- **CLM-Q1:** Composition of an aggregated BP+ (`k = 2`) whose two commitments are
  affinely related (`V0 + V1` is public). No property of BP+ relies on the
  commitments being independent, but this should be confirmed.

---

## 5. Coverage summary and residual risk

- **New crypto tests:** 24 (Schnorr 7, membership 10, claims 7). The existing tag
  distinctness test now also covers the 19 new tags. The crypto crate total is 86, all
  passing.
- **Implementation quality:** `#![forbid(unsafe_code)]` holds. Secrets are zeroized.
  Secret-dependent operations are constant time. Variable-time multi-scalar
  multiplication is used on public data only.
- **Residual risk:**
  - The open questions KER-Q1/Q2, MEM-Q1/Q2 and CLM-Q1.
  - The kernel is reviewed here only as a design. Its implementation is reviewed
    again in M3, with adversarial transaction-level tests (inflation, rogue notes,
    re-signing, `E = 0`).
