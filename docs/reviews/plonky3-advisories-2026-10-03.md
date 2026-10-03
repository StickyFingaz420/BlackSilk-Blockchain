# Plonky3 security advisories against BlackSilk's pinned Plonky3 (2026-10-03)

**Kind:** internal engineering review (agent ZK-ADVISORY, phase 2). It is not an audit and
not independent review. It does not claim that the proof system is sound. It checks one
question: do the published Plonky3 security advisories affect the Plonky3 code that
BlackSilk compiles and runs, including the local patches in `third_party/`?

**Result: no advisory applies. No code change, no consensus change.** Each verdict below
rests on code read in this tree and on the published advisory text, quoted with its URL.
The same conclusion was reached earlier in `docs/reviews/dependency-review.md` §5a and
dossier 24 (`docs/reviews/phase2-2026-09-27/research/24-plonky3-verifier-security.md`);
this document re-derives it at the level of the patched files and functions.

## 0. What BlackSilk runs

| Item | Value | Evidence |
|---|---|---|
| Plonky3 version | every `p3-*` crate at `0.7.0` | `Cargo.lock` |
| Source commit of the published crates | `fb9382687f8f62f4478e1757bbdcea9036d75f51` (tag `v0.7.0`, committed 2026-09-04) | `.cargo_vcs_info.json` of each registry copy; `https://api.github.com/repos/Plonky3/Plonky3/commits/v0.7.0` |
| Local patches | `p3-fri`, `p3-merkle-tree`, `p3-dft` via `[patch.crates-io]` | `Cargo.toml` |
| What the patches change | exactly one file each: `p3-fri/src/hiding_pcs.rs`, `p3-merkle-tree/src/hiding_mmcs.rs`, `p3-dft/src/radix_2_dit_parallel.rs` (lock scope only, plus a test) | `diff -rq --strip-trailing-cr` of each `third_party/` crate against the cargo registry copy of 0.7.0, run 2026-10-03; `third_party/README.md` |
| Files that carry the advisory fixes | `p3-fri/src/verifier.rs`, `prover.rs`, `two_adic_pcs.rs`: **byte-identical to upstream 0.7.0** | same diff |
| Verifier path | `zk::verify` calls `p3_batch_stark::verify_batch` (`zk/src/lib.rs`), then `HidingFriPcs::verify` and `TwoAdicFriPcs::verify`, then the native `p3_fri::verifier::verify_fri`. No recursive or custom verifier exists. | `zk/src/lib.rs`, `third_party/p3-fri/src/hiding_pcs.rs` |
| Challenger | `DuplexChallenger<BabyBear, Poseidon2BabyBear<16>, 16, 8>`, pre-seeded with `PARAMS_ID` and the statement digest (`ProverChallenger` on the prover side; it only changes how the PoW nonce is searched) | `zk/src/config.rs` |
| Merkle leaf hash / node compression | `PaddingFreeSponge<Perm, 16, 8, 8>` / `TruncatedPermutation<Perm, 2, 8, 16>`, both on the same width-16 Poseidon2 `Perm`; salted leaves (`MerkleTreeHidingMmcs`, 4 salt elements) | `zk/src/config.rs`, `zk/src/params.rs` |
| FRI | `HidingFriPcs`, log blow-up 3, 108 queries, max log-arity 4, log final poly length 6, query PoW 16, commit PoW 0; mixed table heights (yes) | `zk/src/params.rs` |

## 1. Advisories found

The Plonky3 advisories page (`https://github.com/Plonky3/Plonky3/security/advisories`,
fetched 2026-10-03) lists exactly five advisories, the five named in the task:

| GHSA | Title (as published) | Severity | Published |
|---|---|---|---|
| GHSA-vj64-rjf3-w3v7 | "MultiField32Challenger: transcript malleability and challenge entropy loss" | High | 2026-05-15 |
| GHSA-3g92-f9ch-qjcm | "The sponge construction used to get a hash function from a cryptographic permutation is not collision resistant for inputs of different lengths" | Low | 2026-04-16 |
| GHSA-f69f-5fx9-w9r9 | "Missing final polynomial degree check in FRI verifier" | High | 2025-06-03 |
| GHSA-m23j-cj9m-ppg9 | "Missing size checks in FRI verifier" | High | 2025-03-28 |
| GHSA-vrmm-4mm5-38vm | "Purported opened values not included in transcript" | High | 2025-01-27 |

**Other advisories.** The GitHub Advisory Database search for "plonky3"
(`https://github.com/advisories?query=plonky3`) also returns GHSA-c873-wfhp-wx5m, "SP1 has
missing verifier checks and fiat-shamir observations", package `sp1-stark`. That is an SP1
advisory, not a Plonky3 one. BlackSilk does not depend on any `sp1-*` crate (`Cargo.lock`:
0 matches), so it does not apply. No other Plonky3 advisory was found. The web search
results for 2026 GHSA numbers in other ecosystems (GHSA-mf92-479x-3373, Spring Security;
GHSA-hj7x-879w-vrp7, Pingora) were checked and are unrelated.

## 2. Verdicts

### 2.1 GHSA-f69f-5fx9-w9r9: unrandomized roll-in and missing final-polynomial degree check (highest priority)

| Field | Finding |
|---|---|
| Source | `https://github.com/Plonky3/Plonky3/security/advisories/GHSA-f69f-5fx9-w9r9` |
| Bug (quoted) | "When rolling in polynomials of lower degree, the FRI prover and verifier were just adding in the low degree polynomials without any randomness" (a prover could make high-degree parts cancel); and "The native FRI verifier was missing a final polynomial degree" check. "Projects using recent versions of the native FRI verifier are vulnerable." |
| Crate / functions | `p3-fri`: `prover.rs` (commit phase, roll-in of reduced openings), `verifier.rs` (`verify_fri`, the per-query fold and the final polynomial check) |
| Affected / patched | affected: commits up to and including `ad4fd24`; fix: commit `e784f44924e12a5a6799f3b03c18d1fa6b1a111e` (2025-06-03). The fix multiplies each rolled-in reduced opening by `beta.square()` in prover and verifier, and adds `if proof.final_poly.len() != config.final_poly_len() { return Err(...) }` (`https://github.com/Plonky3/Plonky3/commit/e784f44924e12a5a6799f3b03c18d1fa6b1a111e`) |
| Is the fix in our version? | **Yes.** GitHub compare `e784f44...v0.7.0`: status "ahead", ahead by 764, behind by 0, merge base = `e784f44`. So `v0.7.0` contains the fix. |
| Is it in the code we compile? | **Yes, verbatim from upstream.** `third_party/p3-fri/src/verifier.rs` (identical to upstream 0.7.0): `fold_query` rolls in with `let beta_pow = beta.exp_power_of_2(log_arity); folded_eval += beta_pow * ro;`, under the comment "We use `beta^arity` as the random factor to maintain independence". `prover.rs` does the same (`*c += beta_pow * x`). `beta^arity` is the variable-arity generalization of the fix's `beta^2` (arity 2): the folded polynomial uses the powers `beta^0 .. beta^(arity-1)`, so `beta^arity` is a fresh power. `verify_fri` checks `proof.final_poly.len() != params.final_poly_len()` (error `FinalPolyLengthMismatch`) before observing the polynomial. The 0.7.0 verifier also adds checks the fix did not have: zero queries, query-count per round, arity bound, `FoldScheduleTooLong`, `FinalFoldHeightMismatch`, the H_in = H_fold cross-check, the initial reduced-opening height, and leftover reduced openings. |
| Does BlackSilk's configuration exercise the path? | **Yes**: PX tables have different heights, so reduced openings are rolled in at lower heights. That path runs the fixed code. |
| Our patches | The patch to `hiding_pcs.rs` only moves lock scopes (`get_quotient_ldes`, `commit`, the `widen` helper); `HidingFriPcs::verify` is upstream's and calls the inner (fixed) verifier. |
| Existing tests | `zk/tests/decode_bounds.rs` (a proof with a lengthened `final_poly` is refused); `zk/tests/rt_pxdos_differential.rs` (final polynomial resizes); upstream's `final_poly_length_mismatch` and `final_poly_mismatch` in `third_party/p3-fri/src/verifier.rs` (run in the upstream checkout only, `third_party/README.md`); `zk/tests/upstream_advisories.rs::third_party_patched_crates_are_pinned` pins the patched crates' bytes, so the verifier file cannot drift silently. |
| **Verdict** | **NOT AFFECTED** (fix present in 0.7.0; the compiled file is upstream's, unmodified). |
| Residual (unchanged) | The advisory is a reminder that mixed-height roll-in has no published soundness theorem (res-freeze §8.5). The fix makes the roll-in random; it does not supply a proof. This stays an analysed-by-argument item in docs/zk.md §9.3. |

### 2.2 GHSA-m23j-cj9m-ppg9: missing size checks in the FRI verifier

| Field | Finding |
|---|---|
| Source | `https://github.com/Plonky3/Plonky3/security/advisories/GHSA-m23j-cj9m-ppg9` |
| Bug (quoted) | The native FRI verifier "was missing size checks; a proof with an invalid shape could cause it to skip checks." |
| Crate / function | `p3-fri` verifier (`verify_fri` and the input-opening check) |
| Affected / patched | before commit `367f76133c3e614f65e856ef21c4963237d6907d` / that commit and later (2025-03-28) |
| Is the fix in our version? | **Yes.** Compare `367f761...v0.7.0`: ahead by 855, behind by 0, merge base = `367f761`. |
| Code we compile | `verify_fri` and `open_inputs` (unmodified upstream 0.7.0) check: commit-phase openings count = commits count; every round opens exactly `num_queries`; sibling count per query = arity − 1; PoW witness count; final polynomial length; input batch count; opened rows per query and per matrix; matrix widths pinned to the claimed evaluation count, not the proof (`MatrixWithoutOpeningPoints`, `PointEvaluationCountMismatch`); `OpeningPointMatchesQueryPoint`. `p3-batch-stark` pins each instance's opened widths to the AIR (`TraceLocalWidthMismatch`, `QuotientChunksCountMismatch`, and others). BlackSilk adds a canonical decode with shape bounds before Plonky3 sees the proof (`zk/src/bounds.rs`, `crate::decode_proof`). |
| **Verdict** | **NOT AFFECTED.** |

### 2.3 GHSA-vrmm-4mm5-38vm: opened values missing from the transcript

| Field | Finding |
|---|---|
| Source | `https://github.com/Plonky3/Plonky3/security/advisories/GHSA-vrmm-4mm5-38vm` |
| Bug (quoted) | PCS implementations failed to include "purported opened values as part of the Fiat-Shamir transcript", so a prover could change them after the challenges. |
| Affected / patched | before commit `b5ec4d96bc752e78990db0707f6b60c4f3d9930a` (PR #627, 2025-01-27) / that commit and later |
| Is the fix in our version? | **Yes.** Compare `b5ec4d9...v0.7.0`: ahead by 933, behind by 0, merge base = `b5ec4d9`. |
| Code we compile | `TwoAdicFriPcs::verify` (`third_party/p3-fri/src/two_adic_pcs.rs`, unmodified) observes every opened value (`challenger.observe_algebra_slice(...)` over round, matrix, point) before `verify_fri` samples `alpha`; the prover's `open` observes the same values in the same order. `HidingFriPcs::verify` first appends the hidden random-codeword openings to the public ones (with count checks at three levels) and then calls the inner `verify`, so the hidden values are observed too. |
| **Verdict** | **NOT AFFECTED.** |

### 2.4 GHSA-3g92-f9ch-qjcm: `PaddingFreeSponge` not collision-resistant across input lengths

| Field | Finding |
|---|---|
| Source | `https://github.com/Plonky3/Plonky3/security/advisories/GHSA-3g92-f9ch-qjcm`; GitHub Advisory Database lists the package as `p3-symmetric` |
| Bug (quoted) | "if the number of elements to hash is not a multiple of the rate, `hash_iter` pads by elements of the current state", so inputs of different lengths can collide. Collision resistance holds "in circumstances where the number of elements to be hashed is known and fixed in advance (as is the case for most STARKS)". |
| Affected / patched | `< 0.6` / `>= 0.6`. The fix is documentation on `PaddingFreeSponge` and a new `Pad10Sponge`; `PaddingFreeSponge` itself is unchanged by design. `p3-symmetric` 0.7.0 `src/sponge.rs` carries both (module docs: "`PaddingFreeSponge` -- for fixed-length inputs ... Not suitable when the attacker controls input length"). |
| Does BlackSilk use it? | **Yes**: `Hash = PaddingFreeSponge<Perm, 16, 8, 8>` is the Merkle leaf hash of `MerkleTreeHidingMmcs` (`zk/src/config.rs`). It is the only use in the workspace (search for `PaddingFreeSponge`, `hash_iter`, `hash_slice`, `CryptographicHasher` outside `third_party/`; the two other hits are archived benches under `docs/evidence/`). |
| Can an attacker choose the leaf length? | **No.** Every leaf's length is fixed by verifier-side data: (1) `open_inputs` builds each matrix's `Dimensions.width` from the claimed evaluation count, never from the opened row (comment in `verifier.rs`: "Pin each matrix width to its claimed evaluation count, never to the proof"); (2) `p3-batch-stark` pins the claimed counts to the AIR widths; (3) `MerkleTreeHidingMmcs::verify_batch` and `verify_multi_batch` call `check_widths(dimensions, rows)` on the unsalted rows, then the inner tree checks the salted widths (row + `MERKLE_SALT_ELEMS`), so the salt length is pinned too; (4) heights come from the verified degree bits. The leaf input is the concatenation of all same-height rows plus salts, of a length known to the verifier at each tree position. |
| **Verdict** | **NOT AFFECTED** (the vulnerable construction is used, but only on fixed-length inputs, the case the advisory states is collision-resistant). |
| Residual | This depends on the width pinning staying in place. A future change that derives a width from proof data would reopen it. Switching to `Pad10Sponge` would change every commitment, so it is a consensus and fingerprint change; not recommended now (no exploit path), worth considering at the next parameter-set change. |

### 2.5 GHSA-vj64-rjf3-w3v7 / CVE-2026-46654: `MultiField32Challenger`

| Field | Finding |
|---|---|
| Source | `https://github.com/Plonky3/Plonky3/security/advisories/GHSA-vj64-rjf3-w3v7`; `https://github.com/advisories/GHSA-vj64-rjf3-w3v7` |
| Bug (quoted) | In `challenger/src/multi_field_challenger.rs`, `MultiField32Challenger::duplexing` (and `field/src/helpers.rs`): "partial-chunk aliasing" (packing via `reduce_32` without length markers), a "non-injective squeeze" (`split_32`), and "high-bit truncation" for 254-bit fields. Distinct transcripts can yield identical challenges. |
| Affected / patched | `p3-challenger` `< 0.4.3` and `>= 0.5.0, < 0.5.3` / `0.4.3`, `0.5.3` (both 2026-05-15). crates.io lists 0.6.0 (2026-06-11) and 0.7.0 (2026-09-04) as later releases. |
| Our version | `p3-challenger` 0.7.0, outside both affected ranges. Its `multi_field_challenger.rs` carries the fix (an absorb length tag in the capacity, `absorb length tag must fit in a u8`, and the test `test_partial_absorb_length_distinct_from_padded_equivalent`). |
| Does BlackSilk use it? | **No.** The challenger is `DuplexChallenger<BabyBear, Poseidon2BabyBear<16>, 16, 8>`, a single-field duplex sponge; no `MultiField32Challenger` anywhere in the workspace. |
| **Verdict** | **NOT AFFECTED** (not used, and the version is patched). |

## 3. Topic 5 checks (res-freeze §5 and §8.5)

### 3.1 FRI statistical bits with the effective rate ρ⁺

`p3-security` 0.8.0 (`security/src/proximity.rs` at tag `v0.8.0`) computes the
unique-decoding agreement as α = (1 + ρ⁺)/2 with ρ⁺ = (k + max_combo)/n, where k is the
committed trace length and n = k · 2^log_blowup. **0.7.0 has the identical function**
(`p3-security-0.7.0/src/proximity.rs`, `alpha_udr`), and BlackSilk's calculator already
uses it with max_combo = 2 (ζ and gζ; `zk/src/params.rs`, `stark_params`) and with the
committed height `log_height + 1`. So the 0.8 formula changes nothing for BlackSilk.

Recomputation (`−log2 α` per query, × 108 queries, + 16 grinding bits):

| Committed log2 k | ρ⁺ | Bits per query | Statistical (108 queries) | With 16 grinding bits |
|---|---|---|---|---|
| plain ρ = 1/8 (no ρ⁺) | 0.125 | 0.830075 | 89.648 | 105.648 |
| 9 (smallest: trace 2^8, ZK doubled) | 0.1254883 | 0.829449 | **89.580** | **105.580** |
| 10 | 0.1252441 | 0.829762 | 89.614 | 105.614 |
| 12 | 0.1250610 | 0.829997 | 89.640 | 105.640 |
| 16 | 0.1250038 | 0.830070 | 89.648 | 105.648 |
| 23 (largest: trace 2^22, ZK doubled) | 0.1250000 | 0.830075 | 89.648 | 105.648 |

- The worst case over the envelope is **89.58 statistical, 105.58 with grinding**, at the
  smallest committed height. ρ⁺ costs at most 0.07 bits.
- **Rounding note:** the documented "89.7 / about 105.7" (docs/zk.md §9.3 and res-freeze
  §5.2) round 89.648 up; with plain ρ the exact figure is 89.65, with ρ⁺ 89.58. The honest
  rounding is **89.6 statistical + 16 grinding, about 105.6**, which is the figure the test
  comment in `zk/src/params.rs` already uses ("about 105.6"). The integer floor stays 105.
  The 100-bit unique-decoding floor is unaffected. Suggested doc edit for the docs owner:
  replace "89.7" with "89.6" in docs/zk.md §9.3.

### 3.2 LogUp: field characteristic versus total multiplicity

- Condition (LogUp, ePrint 2022/1530; res-freeze §8.5): the multiset identity implies
  inclusion only if the total query multiplicity stays below p = 2^31 − 2^27 + 1
  = 2,013,265,921 (about 2^30.9).
- **Plonky3 0.7.0 enforces it in the verifier.** `p3_batch_stark::verify_batch`
  (`src/verifier/mod.rs`) calls `check_multiplicity_height_bound(all_lookups,
  &trace_heights)`, which computes Σ_i w_i · h_i exactly (`BigUint`) over every AIR's
  lookups, with h_i the public trace heights and w_i the declared per-row count bounds
  (`Count::bounded(expr, weight)`), and refuses the proof if the sum reaches p
  (`MultiplicityHeightBoundExceeded`). The prover runs the same check. Provided (table)
  sides have weight 0, as they should: their multiplicities are free field elements.
- **BlackSilk's declarations:** every query in `zkvm/src/air/` uses
  `Count::bounded(…, 1)` (the byte-range, byte-op, ALU, program, image, output, syscall,
  blind and memory buses), and the helpers document the count as `∈ {0, 1}`.
- **Precondition (BlackSilk's, not Plonky3's):** the check trusts that each AIR
  constrains every count to its declared bound ("The height check trusts that
  constraint; it never reads committed values to confirm it", `p3-lookup` `count.rs`).
  This review did not re-verify every call site's boolean constraint. The AIR cell census
  of W4-MUTAIR is the place for that; a per-site test ("every `Count::bounded(e, 1)`
  expression is constrained to {0, 1}") would close it.
- Note: `zk/tests/soundness_calc.rs` models up to 2^22 rows × 1,024 interactions
  (2^32 > p) for the LogUp **error** term. That is a deliberately generous count for the
  error bound, not a claim about the characteristic condition; a shape that large would be
  refused by the height-bound check above (a completeness limit, not a soundness one).
- **Verdict:** the characteristic condition is enforced at verification, conditional on
  the AIR count constraints.

### 3.3 Which Merkle theorem of ePrint 2026/089 applies

- Configuration (`zk/src/config.rs`): the leaf hash is an **overwrite sponge**
  (`PaddingFreeSponge`, width 16, rate 8) on `Perm = Poseidon2BabyBear<16>`, and the node
  compression is `TruncatedPermutation<Perm, 2, 8, 16>` on **the same `Perm` instance
  type and constants** (`default_babybear_poseidon2_16()`, one `permutation()` cloned
  into both).
- Per the verified summary in res-freeze §8.5: Theorem 3 covers the overwrite-sponge leaf
  hash on the same permutation as the compression; Theorem 2 covers a leaf hash on a
  different permutation (Plonky3's common width-24 leaf / width-16 node setup). **So
  Theorem 3 applies to BlackSilk**, which is what `zk/src/params.rs` (`COLLISION_BITS`)
  and docs/zk.md §9.3 already state: (4q² + 2q)/(|H| − 1), |H| = p^8, giving q ≈ 2^122.6,
  floored to 122.
- Remark 1's injective-padding requirement: `PaddingFreeSponge` is not length-injective
  (section 2.4), but every leaf position has a verifier-fixed length, so the map is
  injective on each position's input domain. That is the same argued (not proven)
  adaptation already recorded in `zk/src/params.rs`, together with salted leaves and
  mixed-height injection. This review did not re-read the paper; it relies on the
  res-freeze §8.5 verification of Theorems 2 and 3.

## 4. Consensus effect and actions

- **No code change.** Nothing here changes `CIRCUIT_ID`, the verifier's acceptance set or
  the consensus fingerprint. No Lead decision is needed for the advisories.
- **Docs (optional, for the docs owner):** "89.7" → "89.6" in docs/zk.md §9.3 (3.1).
- **Follow-up (P2 test item):** a census test that each `Count::bounded(e, 1)` in the zkVM
  AIRs is constrained to {0, 1} (3.2).
- **Watch:** re-check the advisories page when moving to Plonky3 0.8.x (the `p3-dft`
  patch can go then; `third_party/README.md`).

## 5. Method and limits

- Advisory texts were fetched from GitHub on 2026-10-03 and treated as data. Ancestry of
  each fixing commit was checked with the GitHub compare API against `v0.7.0`, and the tag
  was resolved to `fb93826`, the commit recorded in every registry crate's
  `.cargo_vcs_info.json`.
- Code was read in this tree (`third_party/`) and in the cargo registry copies of the
  unpatched 0.7.0 crates (`p3-batch-stark`, `p3-lookup`, `p3-symmetric`,
  `p3-challenger`, `p3-security`, `p3-uni-stark`, `p3-commit`).
- No proofs were generated and no tests were added: no advisory applies, and the
  relevant tamper tests already exist (2.1). The bit table was computed with `awk` from
  the formula above.
- Limits: this checks published advisories only. It does not show that Plonky3 0.7.0 is
  free of unpublished defects, and it does not prove the soundness of the configured
  protocol (mixed-height batching, the batch-STARK composition and the Merkle adaptation
  remain argued, as docs/zk.md §9.3 states).
