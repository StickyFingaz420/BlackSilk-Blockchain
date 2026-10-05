# 25 zk-soundness: dossier (phase 1, research and briefing)

> Historical record (2026-09-27). Superseded where it conflicts with the code: the ZK parameter set is BS-ZK-4 (ee0e96f; BS-ZK-3 in 73372e9). Current: [docs/consensus.md](../../../consensus.md), [docs/STATUS.md](../../../STATUS.md).

Specialist 25, BlackSilk engineering phase 2, 2026-09-27. **Internal engineering work, not
an audit.** I was read-only on the repository and ran no cargo builds. All figures below
come from Python re-derivations in my scratchpad (a line-by-line port of `p3-security`
0.7.0 and an independent soundcalc-style calculator). A Rust test must reproduce them
before any document cites them as "tested".

---

## 1. Scope and what I read

**Commit:** `9e422d8` (`rebuild/core`).

**Code (read in full):**
- `zk/src/params.rs`, `zk/src/config.rs`, `zk/src/lib.rs`
- `zk/examples/param_study.rs`
- `zk/tests/proofs.rs` (`toy_shape_meets_the_security_floor`)
- `zkvm/tests/multi.rs:330-372` and `zkvm/tests/vm.rs:285-316` (the shape tests)
- `zkvm/src/prove.rs:20-60` and `:180-215` (`limits`, `CIRCUIT_ID`, exact-shape verify)
- `zkvm/src/air/trace.rs:95-150` (`Statement::shape`)
- `px/src/prove.rs:43-70` (kernel budgets) and `px/src/vault.rs:54`
- `tx/src/px.rs:133` and `:765-783` (`budget_is_provable`)
- `zkvm/src/lib.rs:37` (`MAX_CYCLES`)
- `third_party/p3-fri/src/verifier.rs` (the PoW, schedule and query-sampling sites)

**Registry Plonky3 0.7.0 (read in full):**
- `p3-uni-stark/src/security.rs`
- `p3-security/src/{lib,shape,proximity,fri,deep,air,ldt,error,stark,logup,grinding}.rs`
- `p3-security/src/assumption.rs` (lines 1-300)
- `p3-challenger/src/{duplex_challenger.rs:284-290, grinding_challenger.rs:39-48}`

**Docs:**
- `docs/zk.md` §9 and §12–13
- `docs/zkvm.md:360`
- `docs/reviews/query-policy.md`
- `docs/reviews/full-review-2026-09-27.md` (R4-01, R4-09, R4-12, P1-12, D13, C15)
- `docs/reviews/autonomous-session-2026-09-27.md`
- `docs/reviews/full-review-2026-09-27/R4-zk.md` (complete)
- `SX1-core-crossreview.md` (R4-01 row, I1 A1)
- the `assumptions.md` Z1 row

**Roster:** own entry 25; neighbours 22 (px-proof-system), 24 (plonky3-verifier-security),
26 (zk-privacy), 27 (zk-performance) and 19 (hash, Poseidon2 margins).

**External code:** `ethereum/soundcalc` main (`pcs/fri.py`, `pcs/pcs.py`, `proxgaps/*`,
`circuits/deep_ali.py`, `lookups/logup.py`, `common/utils.py`), downloaded to the
scratchpad. I only read public sources; nothing from the repository was sent anywhere.

**Scratchpad calculators** (not in the repo):
- `calc.py`: the port of `p3-security` 0.7's `ProvenSecurity` path. It has a `0.8`
  variant with the #2048 fixes: the composite `m` sweep, `floor` in `compute_upper_m`,
  and zk chunk doubling in DEEP.
- `indep.py`: a soundcalc/BCHKS25-style independent calculator. It adds the per-round
  commit errors of the real schedule, a DEEP union over tables, a LogUp term, and QROM
  heuristics.

---

## 2. Current state

### 2.1 Parameters

| Parameter | Value |
|---|---|
| Field | BabyBear |
| Challenge field | degree-8 extension, log2 = 8·log2 p = 247.28 (code uses 247) |
| Blow-up | ρ = 1/8 |
| Queries | s = 108 |
| Query grinding | 16 bits |
| Commit-phase grinding | 0 bits |
| Maximum folding arity | 16 |
| Final polynomial length | 2^6 |
| Hash | Poseidon2 digest of 8 elements: ~123.6 bits of collision resistance (code: 123) |
| Envelope | log2 height 8..22, 6,000 honest / 15,709 adversarial committed columns |

### 2.2 What is correct and well designed

- **Figures from proven bounds only.** The figures come from `p3-security`'s proven
  path (UDR, and the BCHKS25 Johnson regime), never from `ConjecturedSecurity` [source-read].
- **Batched-function count.** `num_batched_functions` is set to the committed-column
  count (`params.rs:152`), which avoids the headline 0.7 bug (#2048: the default of 1
  dropped the batching round) [source-read]. The documents also account for ×2 opening
  points (31,418 ≤ 65,536 tested) [tested: `every_shape_within_limits_meets_both_security_targets`].
- **Query grinding is real and correctly placed.**
  - The verifier observes the final polynomial and the arities, then runs
    `check_witness(16, w)` before sampling queries (`third_party/p3-fri/src/verifier.rs:317-335`).
  - `check_witness` observes the witness and requires `sample_bits(16) == 0`
    (`grinding_challenger.rs:42-48`) [source-read].
  - Commit-phase grinding is 0 bits and credited as 0, and the stray-witness malleability
    is closed by `check_canonical_form` [source-read; tested by `zk/tests` per the session report].
- **Query indices are uniform.** They come from `sample_bits(log_max_lde)`, the low bits
  of a canonical BabyBear element (`duplex_challenger.rs:284-290`).
  - Since p − 1 = 15·2^27, the low b bits are uniform up to a 1/p bias for every b ≤ 27.
  - The largest LDE is 2^(22+1+3) = 2^26 ≤ 2^27 [mathematically established].
- **Fiat–Shamir binds everything first.** `PARAMS_ID` and the statement digest (with
  `CIRCUIT_ID`) are absorbed before any commitment (`config.rs:78-88`) [source-read].
- **The eq. (17) hiding budget holds** under the stricter 0.8 reading too (§3.8)
  [mathematically established].
- **The UDR figure is query-bound and domain-independent** [mathematically established]:
  - ρ⁺ = (k + 2)/n ≈ 1/8, so each query gives −log2(9/16) = 0.8301 bits;
  - 108 queries give 89.65 bits, plus 16 grinding bits = **105.65**;
  - it is 105.58 at the smallest shape, because the +2/n term matters there.

### 2.3 What the tests actually prove

- **`every_shape_within_limits_meets_both_security_targets` (`zk/src/params.rs:180`).**
  - It proves that *`p3-security` 0.7 as called*, on its grid, returns Johnson ≥ 120 and
    UDR ≥ 100.
  - It does **not** prove that the call is fed the right domain (R4-01). The grid runs
    over *pre-ZK* heights 8..22, while committed polynomials have degree bits 9..23.
  - It does not prove that the model covers the batch protocol (§3.4).
- **The shape tests** (`zkvm/tests/multi.rs:372`, `vm.rs:315`, `zk/tests/proofs.rs:359`)
  assert only `johnson_bits ≥ 100`. That is weaker than the envelope test and asserts
  nothing on UDR (R4-12, still open) [source-read].
- **No test cross-checks the calculator** against a second implementation [source-read].

---

## 3. Problems in scope

### 3.1 R4-01 recomputed: the off-by-one is real, but its numerical effect is nil

**Why it exists:**
- `security()` calls `ProvenSecurity::compute(&p, 1 << shape.log_height)` (`zk/src/params.rs:153`).
- Plonky3 documents the argument as the *post-ZK* committed size
  (`p3-uni-stark-0.7.0/src/security.rs`, `compute_from_proof`).
- Under hiding FRI, a table of height H is committed as a degree < 2H polynomial:
  `degree_bits = log2 H + 1` (`zk/src/lib.rs:147-150`, `zkvm/src/prove.rs:211`).

**Recomputation.** Worst case of the grid: 5,000 constraints, degree 8, max_combo 2.

| Calculator | log2 k (committed) | Batched functions N | UDR bits | Johnson bits (reported) | Johnson algebraic (cap removed) | Binding term |
|---|---|---|---|---|---|---|
| p3-security 0.7 port | 22 (as coded, pre-ZK) | 65,536 | 105.65 | 123 | — | UDR: query; JB: collision |
| p3-security 0.7 port | **23 (correct, post-ZK)** | 65,536 | **105.65** | **123** | 165.4 | UDR: query; JB: collision |
| p3-security 0.7 port | 23 | 31,418 | 105.65 | 123 | 166.4 (m = 141; batch term) | same |
| 0.7 port + #2048 fixes (composite m sweep, floor upper-m, zk DEEP chunks) | 23 | 31,418 | 105.65 | 123 | ≥ 154 | same |
| Independent (soundcalc/BCHKS25 formulas, UDR commit (γn+1), JBR gap √ρ/100 ⇒ m = 50, per-round commit, 32-table DEEP union, LogUp term) | 23 | 31,418 | **105.65** | **123.6** | 174.1 (batch) | same |
| Independent | 17 (PX kernel-only: 2^16 rows) | 31,418 | 105.65 | 123.6 | 176.4 (query) | same |
| Johnson regime using **only** the peer-reviewed BCIKS20 bound (the (m+½)^7·n²/(3ρ^{3/2}) form) | 23 | 31,418 | — | 123 | 160.2 (m = 5) | collision |

**UDR term breakdown at log2 k = 23, N = 31,418 (independent calculator):**

| Term | Bits |
|---|---|
| query | 105.6 |
| batch | 207.5 |
| worst commit round | 222.5 |
| DEEP (×32 tables) | 216.1 |
| ALI | 235.0 |
| LogUp | ≥ 209 |
| collision | 123.6 |

**Conclusions (mathematically established from the stated formulas; tag: computed, not yet tested):**
1. **R4-01 changes no reported figure.** At the correct post-ZK size, UDR is still
   105.65 (floor 105) and Johnson still 123. SX1 was right that the severity is low.
   R4's estimate of "119–121 Johnson bits" does not materialise.
2. **The "≥ 123 Johnson bits" is the hash-collision cap** (`COLLISION_BITS = 123`), not
   an FRI figure. The algebraic Johnson-regime soundness is ≥ 154–174 bits, depending on
   the calculator and `m`.
   - R4 §3.1 says the 123 comes from "commit-phase/batching terms, whose |D|² scaling
     needs the 247-bit field". That is **incorrect** for 0.7: it uses the BCHKS25 bound,
     linear in n. Even the old |D|² bound (BCIKS20) gives ≥ 160 bits here.
3. **The operative proven soundness of BS-ZK-2 is min(105.6 UDR, 123.6 hash) = 105 bits.**
   - It includes 16 bits of grinding. The information-theoretic IOP part is 89.65 bits.
   - The Johnson figure is useful only as "hash-bounded at 123, algebraic margin ≥ 30 bits".

**Security consequences.** None on the protocol. The documents over-attribute the 123 to
proximity-gap theory, and they do not say that 16 of the 105 bits are computational
(grinding).

**Classification:** documentation and evidence. Not consensus-critical, not
privacy-critical.

**Fix:**
- call `ProvenSecurity::compute_from_proof(log_height + 1, &p)`;
- add a second, independent closed-form calculator in Rust as a differential test (§5, W1–W2).

**Trade-offs:** none. The fix only renames the input and makes the grid cover degree
bits 9..23.

**Invariant:** the figure is always computed on the committed (post-ZK) domain.

### 3.2 Proximity-gap conjecture risk (2025–2026 results)

**Literature state (primary sources, §8):**
- **Up to capacity: refuted.** The correlated-agreement / proximity-gaps conjecture up to
  capacity (BCIKS20 conjecture; WHIR MCA; DEEP-FRI list-decoding) is false.
  - Diamond–Gruen (ePrint 2025/2010) refutes the BCIKS capacity conjecture.
  - Crites–Stewart (ePrint 2025/2046) refutes three capacity conjectures and proposes
    restricting them to the list-decoding capacity bound.
  - Kambiré (arXiv 2604.09724, Apr 2026) shows failure O(1/log n) below capacity over
    prime fields, for a family of RS codes on multiplicative subgroups.
  - Gao–Yang–Xu–Kan (arXiv 2607.10572) turn list-decoding counterexamples into MCA lower
    bounds.
  - `ethereum/soundcalc` has **removed its capacity (CBR) regime** because of these results.
- **Up to Johnson: proven and improving.**
  - BCIKS20 (FOCS 2020 / J. ACM 2023) gives O(n²) exceptional points.
  - BCHKS25 (ePrint 2025/2055, Nov 2025, preprint) improves this to O(n), with the
    explicit Theorem 1.5/4.2 bound used by 0.7 and soundcalc.
  - Dao–Kominers–Thaler "Reed–Solomon Codes Beyond Johnson" (ePrint 2026/2056, Sep 2026,
    preprint, Lean-verified in ArkLib) gives explicit MCA bounds strictly beyond Johnson,
    and O(n/η³) above Johnson. Plonky3 PR #2282 adopted it.
  - Goyal–Guruswami–Sun–Wootters (arXiv 2607.08516) and Jeronimo (arXiv 2609.05870, 3
    weeks old) prove capacity-type gaps for random ensembles or with n^{O_γ(1)} lists.
    Neither yet gives concrete bounds for the smooth 2-adic subgroups FRI uses.

**Risk to BlackSilk: none today** [mathematically established from §3.1].
- The UDR figure uses no list-decoding result at all.
- The Johnson figure holds even with only the peer-reviewed BCIKS20 theorem.
- Nothing uses the capacity regime.

**The risk is prospective.** Every parameter-reduction proposal in the review must be
checked against this:
- R5 #8 "~60 queries";
- R12 I18 "49–71 queries";
- I1 A1 grinding;
- R4-09 option (c).

The Johnson-only options (71 queries at blow-up 8; 53 at blow-up 16) remain *proven*
under BCHKS25 or BCIKS20. However:
- they then rest on the list-decoding theorems, and on a hash cap of 123 bits;
- **no** option may use `ConjecturedSecurity` (the random-words heuristic, which
  p3-uni-stark 0.7 exposes), the ethSTARK `s·log2(1/ρ)` heuristic, or DKT26/Jeronimo
  (unreviewed preprints).

**Invariant:**
- parameter sets are sized only by the proven UDR bound, and the Johnson bound under
  peer-reviewed or at least widely cross-checked theorems;
- never by conjectured regimes.

**Tests:**
- a test that fails if `params.rs` or the examples import `ConjecturedSecurity`
  (a grep-style test, or keep the call site in one module);
- the differential calculator (W2) keeps a "BCIKS20-only" Johnson column.

### 3.3 Grinding and query count

- The UDR target leaves **5.65 bits** of margin at 108 queries: 102 is the minimum for
  ≥ 100 [math].
- Raising grinding (R4 option d, I1 A1):
  - 20 bits keeps UDR ≥ 105.6 with 103 queries (−5 queries, about −4.6% of the linear
    proof bytes);
  - 24 bits keeps it with 98 queries.
  - Each +4 bits costs 16× the grinding work: about 2^20 Poseidon2 permutations on
    average. That is prover time, and the verifier is unaffected.
- **Caveat:** grinding bits are computational, whereas the queries are statistical.
  They count in the ROM against an adversary whose budget is measured in Poseidon2
  calls, not information-theoretically. The docs should say "105 bits (89.7 statistical
  + 16 grinding)".
- A grinding change is a new parameter set (proof bytes and transcript change). It
  belongs with 27/22 as an owner decision, not a phase-2 default.

### 3.4 Terms the calculator does not model

`p3-uni-stark`'s `ProvenSecurity` passes `extras = &[]` and models a single-table
uni-STARK. BlackSilk proves a p3-batch-stark with LogUp over up to about 23–32 tables of
different heights. Unmodelled [source-read]:

| Unmodelled item | Bits (independent calculator, log2 k = 23) | Binding? |
|---|---|---|
| LogUp fingerprint: ε ≤ N·(W+2)/\|EF\| (`p3-security/src/logup.rs`), with a conservative N = 2^22·1,024 interactions and W = 64 | ≥ 209 | no |
| DEEP union over tables (one ζ, each table opened at ζ and g_i·ζ), 32 tables | 216 (UDR), 209 (JB) | no |
| Mixed-height FRI: reduced openings rolled in with β-powers at each input height (`verifier.rs:626-627`) | covered by the commit-round bound ×(1 + rolled heights); ≥ 215 | no [assumed: no formal analysis of Plonky3's mixed-matrix FRI exists in the papers I found] |
| Prover-chosen arity before R4-02: ≤ 4^rounds factor on the commit error | closed by `check_fri_schedule` | n/a |
| ALI with shared α across tables | constraints summed (conservative) | no |

**Consequence:** none numerically. But "the calculator covers the protocol" is false as
a statement. The docs must say that these terms are bounded separately (this dossier)
and are ≥ 200 bits.

**Fix:** add the LogUp and table-union terms to `zk::params::security` as `extras`
through `p3_security::stark::proven_security_report`, which is public in 0.7. Or compute
them in the independent calculator (W2).

### 3.5 Height envelope reachable in consensus (correction to SX1)

SX1 limited R4-01 to "unshaped extremes": "every consensus PX statement has an exact
shape … far below 2^21 rows". That holds for the kernel (2^16 rows). But
`budget_is_provable` (`tx/src/px.rs:767-783`) admits a registered function budget with:
- `keys ≤ 2^22`;
- shared ALU entries summing to ≤ 2^22;

and `Statement::shape` turns budgets into pow2 heights (`zkvm/src/air/trace.rs:120-150`).

So consensus-verified shapes **can** claim 2^22-row tables (committed degree bits 23).
For soundness, what matters is the heights the verifier accepts, not what honest
provers can afford.

**Consequence:** the envelope must be analysed at committed log2 k = 23. §3.1 shows the
figures hold there. [source-read; confidence high]

### 3.6 Post-quantum soundness is claimed but not quantified

- `docs/zk.md:592-594` says "Parameters are sized with the quantum bound noted
  separately". **No such bound exists** anywhere in `docs/` or `zk/` (grep).
- P6 claims "plausible post-quantum security for soundness".

**QROM:**
- Chiesa–Manohar–Spooner (TCC 2019, ePrint 2019/834) show that BCS-compiled IOPs with
  round-by-round soundness are secure in the QROM. The bound is commonly stated as
  O(t²·ε_rbr + t³/2^λ) [assumed: the abstract confirms "explicit bounds, tight up to
  small factors"; I did not verify the exact constants in the PDF].
- Heuristically, a Grover-style attack halves the bits:

| Term | Classical | Quantum (heuristic) |
|---|---|---|
| UDR round-by-round | 105.6 | ~53 |
| Johnson algebraic | ~166 | ~83 |
| Hash collisions (BHT) | 123.6 | ~82 (ignoring memory cost) |

These are heuristic estimates, not a theorem instantiation.

**Consequence:** the documents claim something that was never computed.

**Fix:** state the quantum figures with their assumptions, or remove the sentence and
downgrade P6 to "hash-based; quantum soundness not quantified". The brief forbids
unverified claims.

**Classification:** claim accuracy. Not consensus.

### 3.7 p3-security 0.7 accounting bugs (Plonky3 #2048): exposure matrix

| 0.7 bug (#2048) | BlackSilk exposure | Evidence |
|---|---|---|
| `num_batched_functions` defaulted to 1 | Avoided: set to the column count | `params.rs:152` |
| ZK quotient-chunk doubling not applied in DEEP | Δ ≈ −1 bit on DEEP (220.8 → 219.9), non-binding | calc.py |
| `max_combo` not checked against next-row reads | max_combo = 2 is correct (`local`/`next` only) | `params.rs:149-150` |
| Conjectured path inconsistency | Not used | source |
| `best_ldr_m` optimised the LDT term only | Johnson is collision-capped; any m ∈ [3, 1000] gives ≥ 154 algebraic | calc.py |
| `compute_upper_m` ceil vs floor | Only changes the m range; non-binding | calc.py |
| `LOG2_E` rounded down (`fixed.rs`) | Used by the conjectured/fixed paths only, not `ProvenSecurity` | source |
| Folding-coefficient `u64` overflow | Arity 16, far from overflow | source |
| ζ and lookup-challenge grinding credited but unpaid | BlackSilk credits neither (0 bits) | source |
| Circle-FRI rate-1 hole | Not used (two-adic FRI, blow-up 8) | source |
| DKT26 (#2282) raises Johnson figures | Would not change the reported 123 (hash cap) | — |

**Conclusion:** no 0.7 calculator bug changes a BlackSilk figure.

### 3.8 Hiding budget under the 0.8 rule (for 26)

Plonky3 0.8 `HidingFriPcs` now enforces two things (fetched `fri/src/hiding_pcs.rs`, main):
- trace height N ≥ 2·(num_queries + D·(number of opening points, **including translates**));
- `num_random_codewords ≥ Challenge::DIMENSION`, checked by the verifier too.

For BlackSilk:
- **Budget.** Two opening points (ζ, gζ) give 2·(108 + 16) = 248 ≤ 256. It still
  holds, but the query ceiling at `MIN_LOG_HEIGHT = 8` is **112**, not 120 as R4 §3.1
  says. The `params.rs:164-170` comment models n_F = 1 "with the factor 2 for the
  translate", which is a different reading. The const assertion should use the
  upstream form.
- **Random codewords.** `NUM_RANDOM_CODEWORDS = 4 < 8`. `params.rs:45-57` argues that
  the separate randomization polynomial R spans the extension. This is a
  **zero-knowledge** question, not a soundness one. I refer it to 26 (and 24) as a
  potential divergence from upstream's current requirement. Soundness is unaffected.

### 3.9 Other items

- **Query-index uniformity invariant.** If `MAX_LOG_HEIGHT + 1 + LOG_BLOWUP` ever
  exceeded 27, query positions would become non-uniform. At 28 bits, half the residues
  have probability 8/7.5 times the average, which weakens the query term. Nothing
  enforces this today.
  - Add `const _: () = assert!(MAX_LOG_HEIGHT + 1 + LOG_BLOWUP <= 27)`, with a comment
    citing `duplex_challenger.rs:284-290` and p − 1 = 15·2^27.
- **Constraint count and degree are not bound to the envelope.**
  - The grid assumes ≤ 5,000 constraints and degree ≤ 8. The shape tests compute
    `constraints` but never assert it is ≤ 5,000.
  - The ALI term is not binding (≥ 208 bits even at 2^30 constraints), but the envelope
    claim should be checked.
- **Citation error inherited from p3-security.** ePrint 2024/1553 is titled "STARK-based
  Signatures from the RPO Permutation" (Atapoor, Delpech de Saint Guilhem, Al Kindi),
  not "On the Security of STARKs with FRI". BlackSilk docs should cite it correctly if
  they cite it.
- **Integer truncation.** `CHALLENGE_FIELD_BITS = 247` (true 247.28) and
  `COLLISION_BITS = 123` (true 123.64) are floor-rounded. That is conservative and fine.

**Invariants that must never change (soundness):**
1. The figure is computed on the committed post-ZK domain, from proven bounds only.
2. UDR ≥ 100 unless the owner re-decides it (D-policy).
3. Query grinding is checked before query sampling, and commit-PoW witnesses are zero
   while the bits are 0.
4. `PARAMS_ID`, `CIRCUIT_ID` and the statement digest come before the first challenge.
5. log2 max LDE ≤ 27 (uniform query indices).
6. 2·(s + D·n_F) ≤ 2^MIN_LOG_HEIGHT with n_F = 2.
7. The hash cap (~123.6) is ≥ the Johnson target. Raising the target above 123 requires
   a wider digest, not more queries.
8. `check_fri_schedule` stays (it removes the unanalysed 4^rounds prover freedom).

---

## 4. New findings

| ID | Severity | Status | Location | Scenario | Confidence |
|---|---|---|---|---|---|
| **ZS-1** (R4-01 recomputed) | Low | Not implemented (fix); figures verified by calculation only | `zk/src/params.rs:153`, `:185` (grid), `zk/examples/param_study.rs:35` | Security is computed on the pre-ZK domain (degree bits 8..22 instead of 9..23). Recomputed at the correct size, UDR = 105.65 and Johnson = 123 are unchanged (§3.1). R4's "119–121" scenario does not occur. | High |
| **ZS-2** (attribution of the 123) | Low (claim accuracy) | Not implemented | `docs/zk.md:568-570`, `docs/reviews/query-policy.md:27`, `docs/zkvm.md:360`, `assumptions.md` Z1, R4 §3.1 | The "≥ 123 Johnson bits" is the Poseidon2 collision cap; the algebraic Johnson bound is ≥ 154–174. The operative proven soundness is 105 bits, of which 16 are grinding (89.65 statistical). The docs present 123 as an FRI/proximity result and do not split out the grinding. | High |
| **ZS-3** (quantum bound missing) | Medium (false claim in the spec) | Not implemented | `docs/zk.md:592-594`, `:486` (P6), `:811` | The doc states a quantum bound is "noted separately"; none exists. Heuristic QROM: ~53 bits UDR, ~82 bits for hash collisions. A PQ-soundness claim without numbers breaks the no-unverified-claims rule. | High (absence); medium (heuristic numbers) |
| **ZS-4** (unmodelled batch-STARK terms) | Low | Not implemented | `zk/src/params.rs:142-158`; `p3-uni-stark-0.7.0/src/security.rs` (`extras = &[]`) | LogUp, the multi-table DEEP union and mixed-height FRI are not in the computed figure. Bounded here at ≥ 205 bits (non-binding), but "the calculator covers the protocol" is not true. | High (fact); medium (bounds, since mixed-height FRI has no published analysis) |
| **ZS-5** (consensus shapes reach 2^22) | Low | — (correction to SX1) | `tx/src/px.rs:767-783`, `zkvm/src/air/trace.rs:120-150` | Registered function budgets can produce 2^22-row tables in consensus-verified PX shapes, so the post-ZK 2^23 domain is in scope for consensus. The figures hold there (ZS-1). | High |
| **ZS-6** (query-index uniformity not enforced) | Low (hardening) | Not implemented | `zk/src/params.rs` (no assertion); `p3-challenger-0.7.0/src/duplex_challenger.rs:284-290` | A future `MAX_LOG_HEIGHT ≥ 24` or `LOG_BLOWUP ≥ 5` at 2^22 would make query positions biased (8/7 ratio at 28 bits). The calculator would silently over-report. | High |
| **ZS-7** (tests assert the wrong floor) | Low | Partially implemented (R4-12) | `zkvm/tests/multi.rs:372`, `zkvm/tests/vm.rs:315`, `zk/tests/proofs.rs:359` | The real shape tests assert only `johnson ≥ 100`. A regression that dropped UDR below 100 on the real widest statement would pass them. Constraint count ≤ 5,000 is not asserted. | High |
| **ZS-8** (hiding budget and codeword count versus 0.8's rule) | Informational here; referred to 26/24 | — | `zk/src/params.rs:57`, `:164-170` | Upstream counts both opening points (budget 248 ≤ 256, ceiling 112 queries, not 120) and requires ≥ 8 random codewords; BlackSilk uses 4 and argues R covers it. This concerns ZK, not soundness. | High (fact); ZK impact unknown (26) |
| **ZS-9** (R4 §3.1 reasoning error) | Informational | — | `docs/reviews/full-review-2026-09-27/R4-zk.md:251,488` | "|D|²-type commit and batching terms need the 247-bit field" is wrong for 0.7 (BCHKS25 is linear in n). The R4-09 policy picture (Johnson forces degree 8) should be re-derived before any parameter decision. | Medium (I did not recompute degree-5/6 extensions over the whole envelope) |

**No Critical or High finding.** I found no soundness defect in the parameter set; the
issues are about evidence and claims.

---

## 5. Implementation plan for phase 2

| # | Work item | Files (ownership) | Consensus? | Identity | Tests | Docs | Size | Priority |
|---|---|---|---|---|---|---|---|---|
| **W1** | Post-ZK domain: `security()` calls `ProvenSecurity::compute_from_proof(shape.log_height + 1, &p)`. Rename the doc of `ProofShape::log_height` to "trace height (pre-ZK)". Extend the grid comment to degree bits 9..23. Update `param_study.rs` the same way. | `zk/src/params.rs`, `zk/examples/param_study.rs` | None (evidence only) | None | The existing envelope test (must still pass); a new unit test pinning `security()` at the worst corner to UDR = 105 and JB = 123 (regression vector) | — | S | **P0** (cheap, removes a known false input before the freeze) |
| **W2** | Independent Rust calculator (differential test), pure `f64`, no new dependency, about 120 lines under `#[cfg(test)]`: UDR/JBR per BCHKS25 (soundcalc formulas), the BCIKS20-only Johnson column, per-round commit errors of `honest_fri_schedule`, a DEEP union ×32 tables, a LogUp term with a conservative (N, W), the collision cap. It asserts (a) agreement with `p3-security` within ±1 bit on UDR and Johnson over the grid, (b) every extra term ≥ 200 bits, (c) the UDR floor ≥ 100 and the Johnson floor ≥ 120 in both. | `zk/src/params.rs` (test module) or new `zk/tests/soundness_calc.rs` | None | None | Differential and property tests over the grid; golden vectors from this dossier: 105.65 / 123 / 166.4 / 174.1 / 160.2 | `docs/zk.md` §9.3 cites it | M | **P0** (accept criterion of roster 25) |
| **W3** | Const invariants: `assert!(MAX_LOG_HEIGHT + 1 + LOG_BLOWUP <= 27)` (ZS-6); the eq. (17) assertion rewritten in the upstream form with two opening points, `2*(NUM_QUERIES + EXTENSION_DEGREE*2) <= 1 << MIN_LOG_HEIGHT` (ZS-8; 248 ≤ 256); `assert!(TARGET_JOHNSON_BITS <= COLLISION_BITS)`. | `zk/src/params.rs` | None (compile-time; values unchanged) | None | Compile-time | Comment in params | S | P1 |
| **W4** | Shape tests assert both floors, `unique_decoding_bits ≥ MIN_PROVEN_BITS && johnson_bits ≥ TARGET_JOHNSON_BITS`, and `constraints ≤ 5_000`, `max_degree ≤ MAX_CONSTRAINT_DEGREE` (ZS-7 / R4-12). Add the shaped PX two-function statement at its real (exact) shape. | `zkvm/tests/multi.rs`, `zkvm/tests/vm.rs`, `zk/tests/proofs.rs`; PX shape test in `px/tests/` (coordinate with 22) | None | None | Those tests (proving-heavy: CI only) | — | S | P1 |
| **W5** | Doc corrections (ZS-2, ZS-3, ZS-4, ZS-5, ZS-9). Replace "≥ 123 Johnson / ≥ 105 UD" with "105 bits proven (unique decoding; 89.7 statistical + 16 grinding) and a 123-bit hash cap; Johnson-regime algebraic ≥ 150, not binding". Add the calculator version and input convention. List the unmodelled terms with bounds. Add a quantum paragraph with heuristic numbers and assumptions, or remove the "noted separately" sentence. Add a "proximity-gap literature status (Sep 2026)" note. | `docs/zk.md` §9.3, §12.1; `docs/zkvm.md` §7; `docs/reviews/query-policy.md`; `docs/reviews/assumptions.md` (Z1); `docs/reviews/external-review-scope.md` / `review-package.md` figures (coordinate with 47) | None | None | — | as listed | S | **P0** (claims must be true at freeze) |
| **W6** | Guard against conjectured regimes: a test (or module-privacy arrangement) that `ConjecturedSecurity` / `conjectured_*` are not used by parameter code. It documents the invariant in `query-policy.md` §4. | `zk/src/params.rs` (test), `docs/reviews/query-policy.md` | None | None | Source-scan test | — | S | P2 |
| **W7** | Parameter-policy re-analysis for any future set (BS-ZK-3): grinding 20/24 (103/98 queries), the Johnson-only options, and the extension degree (re-derive R4-09 at degree 5/6 with W2). Output: a table for the owner. **Not a code change before the freeze.** | none (study); later `zk/src/params.rs` as a new set | Would be CONSENSUS (new parameter set) | New identity | W2 grid on the candidate set | `query-policy.md` | M | P3 |

**Benchmarks:** none required for W1–W6. W7 needs the grinding time at 20/24 bits
(owner 27).

---

## 6. Dependencies and conflicts

- **22 (px-proof-system).** Owns `zk/src/lib.rs` (verify, schedule, canonical form) and
  `MAX_PROOF_BYTES`. W1–W3 touch only `zk/src/params.rs`. Coordinate if 22 changes
  `MAX_ADVERSARIAL_COLUMNS` or `MAX_PROOF_BYTES` (these enter N).
- **24 (plonky3-verifier-security).** The #2048/#2282 exposure matrix (§3.7) can be
  merged into their advisory table. ZS-8 (0.8 hiding checks) goes to them for the
  migration plan.
- **26 (zk-privacy).** ZS-8: random-codeword count versus upstream's `≥ DIMENSION`, and
  the budget with two opening points. The eq. (17) assertion change (W3) must be agreed
  with 26.
- **27 (zk-performance).** Grinding and query trade-offs (W7). Any query change must
  respect the 112-query ceiling at `MIN_LOG_HEIGHT = 8` (ZS-8).
- **19 (hash, Poseidon2 margins).** The 123-bit collision cap is the binding term of the
  Johnson figure. A Poseidon2 weakness lowers the protocol figure directly.
- **47 (docs-spec-consistency).** Owns the wording across the docs listed in W5. I
  supply the numbers.
- **28 / 20.** ZS-5 (function budgets up to 2^22) interacts with any change to
  `budget_is_provable`.
- **Conflicts:** `zk/src/params.rs` is touched by W1–W3 and W6. It should have one owner
  (25) in phase 2, with 26 reviewing the eq. (17) line.

---

## 7. Open questions for the coordinator

1. **Headline figure.** Do we publish **"105 bits proven (unique decoding), hash cap
   123"** as the headline, and keep Johnson only as a margin statement (W5)?
   Recommended: yes.
2. **Quantum soundness.** Should the spec state heuristic QROM numbers (about 53 / 82
   bits), or withdraw the quantified-PQ implication and keep "hash-based, not
   quantified"?
3. **Placement of W2.** Should W2 live in `zk` as a test-only module (my
   recommendation: no dependency, pure Rust), or in `tools/` as a standalone calculator
   binary?
4. **Random-codeword count (ZS-8).** Does the coordinator want 26 to decide before the
   freeze whether BlackSilk follows upstream's `num_random_codewords ≥ 8`? It would
   change proof bytes (a new parameter set) if adopted.
5. **Function budgets.** Should consensus cap registered function budgets below 2^22
   (ZS-5)? That is a liveness and capacity question for 20/28; soundness does not need
   it.

---

## 8. Sources

**Papers:**
- Ben-Sasson, Carmon, Ishai, Kopparty, Saraf. *Proximity Gaps for Reed–Solomon Codes*
  (FOCS 2020; J. ACM 2023). https://eprint.iacr.org/2020/654
- Ben-Sasson, Carmon, Haböck, Kopparty, Saraf. *On Proximity Gaps for Reed–Solomon
  Codes* (BCHKS25; approved 2025-11-09). https://eprint.iacr.org/2025/2055
- Diamond, Gruen. *On the Distribution of the Distances of Random Words* (2025; refutes
  the BCIKS capacity conjecture). https://eprint.iacr.org/2025/2010
- Crites, Stewart. *On Reed–Solomon Proximity Gaps Conjectures* (2025).
  https://eprint.iacr.org/2025/2046
- Kambiré. *Proximity Gaps Conjecture Fails Near Capacity over Prime Fields* (Apr 2026).
  https://arxiv.org/abs/2604.09724
- Gao, Yang, Xu, Kan. *List-Decoding Counterexamples Yield Lower Bounds on Mutual
  Correlated Agreement Error* (Jul 2026). https://arxiv.org/abs/2607.10572
- Goyal, Guruswami, Sun, Wootters. *Locality of Curve-Decoding and Improved Proximity
  Gaps* (Jul 2026). https://arxiv.org/abs/2607.08516
- Jeronimo. *Algorithmic List Decoding at Capacity and Optimal Proximity Gaps for
  Reed–Solomon Codes* (Sep 2026). https://arxiv.org/abs/2609.05870
- Dao, Kominers, Thaler. *Reed–Solomon Codes Beyond Johnson: Efficient Decoding and
  Smaller Cryptographic Proofs* (DKT26; Sep 2026 preprint; Lean/ArkLib-verified bounds).
  https://eprint.iacr.org/2026/2056
- Ben-Sasson. *ethSTARK Documentation* (rev. 2025-06-08). https://eprint.iacr.org/2021/582
- Atapoor, Delpech de Saint Guilhem, Al Kindi. *STARK-based Signatures from the RPO
  Permutation* (cited by p3-security as the source of Theorems 2–3).
  https://eprint.iacr.org/2024/1553
- Haböck. *A summary on the FRI low degree test* (DEEP-ALI Theorem 8, used by
  soundcalc). https://eprint.iacr.org/2022/1216
- Haböck, Al Kindi. *A note on adding zero-knowledge to STARKs* (§4.2, eq. 17).
  https://eprint.iacr.org/2024/1037
- Haböck. *Multivariate lookups based on logarithmic derivatives* (LogUp).
  https://eprint.iacr.org/2022/1530
- Chiesa, Manohar, Spooner. *Succinct Arguments in the Quantum Random Oracle Model*
  (TCC 2019). https://eprint.iacr.org/2019/834

**Code and pull requests:**
- Ethereum Foundation. *soundcalc* (UDR/JBR; CBR removed after DG25/CS25).
  https://github.com/ethereum/soundcalc (files `soundcalc/pcs/fri.py`, `pcs/pcs.py`,
  `proxgaps/johnson_bound.py`, `proxgaps/unique_decoding.py`, `circuits/deep_ali.py`,
  `lookups/logup.py`)
- Plonky3 PR #2048 (accounting and grinding hygiene fixes).
  https://github.com/Plonky3/Plonky3/pull/2048
- Plonky3 PR #2282 (DKT26 Johnson MCA bound).
  https://github.com/Plonky3/Plonky3/pull/2282
- Plonky3 `fri/src/hiding_pcs.rs` (main; hiding budget and `num_random_codewords ≥
  DIMENSION`). https://github.com/Plonky3/Plonky3/blob/main/fri/src/hiding_pcs.rs
- Plonky3 0.7.0 crates in the local cargo registry: `p3-security`, `p3-uni-stark`
  (`security.rs`), `p3-challenger`.
