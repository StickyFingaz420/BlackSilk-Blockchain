# 24 plonky3-verifier-security: research dossier (phase 2, phase 1)

> Historical record (2026-09-27). Superseded where it conflicts with the code: the ZK parameter set is BS-ZK-4 (ee0e96f; BS-ZK-3 in 73372e9). Current: [docs/consensus.md](../../../consensus.md), [docs/STATUS.md](../../../STATUS.md).

**Internal engineering research, not an audit.** Nothing here claims that BlackSilk, Plonky3
or any configuration of them is secure, audited or proven. Zero knowledge is discussed only
as statistical and conditional (docs/reviews/zk-coverage.md §3).

- **Agent:** 24 plonky3-verifier-security. **Mode:** read-only on the repository; no cargo
  builds or tests were run. One local Python script re-implements the p3-security 0.7.0
  formulas (arithmetic only, outside the repository; Appendix A).
- **Commit:** `9e422d8` (`rebuild/core`, v3/candidate merged). The FRI schedule rule (R4-02,
  `147fb06`) and `CIRCUIT_ID` (R4-11) are therefore **on the branch now**; the full review
  (written at `54c4827`) predates that.
- **Date of upstream checks:** 2026-09-27 (GitHub API and raw sources of `v0.8.0` and `main`).

---

## 1. Scope and what I read

**Brief and roster:** `C:/bszkeval/p2/brief.md` (whole), roster entries 20-29 (own entry 24;
neighbours 22, 25, 26, 27), plus 41-44 and 47 for ownership of tests, CI, supply chain, docs.

**Reviews:** `docs/reviews/full-review-2026-09-27.md` (§1-§3.5, register rows R4-xx, ZK-F3/F4,
P0-P3 lists, never-change list); `docs/reviews/autonomous-session-2026-09-27.md` (whole);
`full-review-2026-09-27/R4-zk.md` (whole); `SX1-core-crossreview.md` (R4 rows, v3 decisions);
`docs/reviews/internal-review-log.md` (rounds 3-5: Z2, R3-2, R3-6, M3);
`docs/reviews/zk-coverage.md` (R/codeword rows); `docs/reviews/dependency-review.md` (§1, §3,
§5a advisories); `docs/zk.md` §9.2-9.3 and P4 (security figures).

**Code (BlackSilk):** `zk/src/lib.rs`, `zk/src/config.rs`, `zk/src/params.rs` (all lines);
`zk/tests/proofs.rs`, `zk/tests/field_mutations.rs`, `zk/tests/pins.rs`;
`zkvm/src/prove.rs` (limits, `CIRCUIT_ID`, `statement_digest`, shaped verify);
`px/tests/fri_schedule.rs`; `px/src/fingerprint.rs` (zk manifest); `tx/src/validate.rs`
(PX proof path, `VerifierPanicked` handling); `tx/src/params.rs` (PX size/fee);
workspace `Cargo.toml` (`[patch.crates-io]`), `zk/Cargo.toml`, `zkvm/Cargo.toml`;
`.github/workflows/ci.yml` (grep).

**third_party:** `third_party/README.md`, `UPSTREAM-REPORT.md`; `diff -r --strip-trailing-cr`
of all three crates against the registry copies (result in §2.4).

**Plonky3 0.7.0 registry sources read in depth:** `p3-batch-stark/src/verifier/mod.rs` (all),
`proof.rs`; `p3-fri/src/verifier.rs` (verify_fri, open_inputs), `proof.rs`,
`hiding_pcs.rs` (verify, commit, get_quotient_ldes), `two_adic_pcs.rs` (verify);
`p3-merkle-tree/src/hiding_mmcs.rs`, `mmcs/mod.rs` (pruned verify), `pruning.rs`;
`p3-symmetric/src/hash.rs` (`MerkleCap`); `p3-challenger/src/duplex_challenger.rs`,
`grinding_challenger.rs`; `p3-uni-stark/src/security.rs`, `proof.rs`;
`p3-security/src/{stark,fri,proximity,assumption,deep,air,fixed}.rs`; `p3-lookup` types.

**Plonky3 0.8.0 / main (raw GitHub):** `fri/src/hiding_pcs.rs`, `merkle-tree/src/hiding_mmcs.rs`,
`batch-stark/src/proof.rs`, `fri/src/proof.rs`, workspace `Cargo.toml`.

**Upstream primary sources:** v0.8.0 release notes (141 non-perf entries, 220 commits since
v0.7.0); PR bodies #2033, #2048, #2100 (and its `hiding_pcs.rs` diff), #2105, #2106, #2107,
#2109, #2125, #2131, #2256, #2257, #2263, #2276, #2277, #2278, #2282; issues #1746, #1766;
all merged PRs 2026-09-20..27; all issues since 2026-06-01; the 5 GitHub security advisories
of Plonky3/Plonky3; compare API to confirm each fix is **not** in the v0.7.0 tag.
Papers: ePrint 2026/089 (Plonky3 Merkle tree analysis), 2024/1037, 2025/2055, 2026/2056
(DKT26), 2024/1553; `ethereum/soundcalc`.

---

## 2. Current state (with evidence classes)

### 2.1 What BlackSilk runs

- Plonky3 `=0.7.0` exact pins on every p3 crate in `zk` and `zkvm`; `p3-fri`,
  `p3-merkle-tree`, `p3-dft` replaced via `[patch.crates-io]` [source-read].
- Configuration: BabyBear, `BinomialExtensionField<_, 8>`, Poseidon2-16, `PaddingFreeSponge<16,8,8>`
  leaves, `TruncatedPermutation<2,8,16>` nodes, `MerkleTreeHidingMmcs` (4 salts, cap height 0),
  `HidingFriPcs` (4 random codewords, blow-up 8, 108 queries, arity ≤ 16, final length 64,
  commit PoW 0, query PoW 16), `DuplexChallenger<16,8>` pre-seeded with `PARAMS_ID` and the
  statement digest (which starts with `CIRCUIT_ID`) [source-read: `zk/src/config.rs:41-115`,
  `zkvm/src/prove.rs:59-91`].
- Verification is `p3_batch_stark::verify_batch` behind BlackSilk pre-checks and `catch_unwind`
  [source-read: `zk/src/lib.rs:126-174`]. The consensus path always goes through
  `decode_proof` first (`tx/src/validate.rs:539`) [source-read].

### 2.2 BlackSilk-level verifier checks and what the tests prove

| Check | Where | Evidence |
|---|---|---|
| Table count, public-value count, `degree_bits` in `[MIN+1, min(limit,MAX)+1]` before Plonky3 | `zk/src/lib.rs:133-156` | tested: `claimed_heights_and_table_counts_are_checked_first` |
| Exact shape for budgeted (PX) statements | `zkvm/src/prove.rs:214-227` | source-read; exercised by every PX consensus test |
| Canonical FRI folding schedule (R4-02, #2033 equivalent) | `zk/src/lib.rs:157,188-248` | tested: `honest_proofs_use_the_canonical_fri_schedule` (8 height pairs), `a_non_canonical_fri_schedule_is_refused` (field tamper), `schedule_tests::*` (all 2^15 subsets), `px/tests/fri_schedule.rs` (n_fn 0..2) |
| Commit-phase grinding witnesses must be 0 (#2106 equivalent) | `zk/src/lib.rs:316-327` | tested: `unbound_proof_fields_cannot_be_rewritten` (mutates element 0 only; shows 0.7 accepts the rewrite) |
| No present-but-empty optional opening (#2256 equivalent) | `zk/src/lib.rs:328-340` | tested for `preprocessed_next` on a table **without** preprocessed columns only |
| Strict postcard decode, re-encode equality, size cap, version byte | `zk/src/lib.rs:266-294` | tested: `encoding_is_strict`, `byte_mutations_never_verify_and_never_panic_the_caller`, `every_field_element_mutation_is_refused` (~6,750 mutations, release) |
| Panics contained; `panic = "abort"` refused at compile time | `zk/src/lib.rs:18-21,158-173` | source-read; mutation tests count caught panics |
| Fresh setup config for preprocessed commitments (ZK-F3) | `zk/src/lib.rs:120,162-166` | tested: `statements_with_preprocessed_tables_verify` |
| Transcript domain separation: `PARAMS_ID`, statement digest incl. `CIRCUIT_ID` | `zk/src/config.rs:78-88`; `zkvm/src/prove.rs:59-91` | tested: `zkvm/tests/circuit_id.rs` (digest vector) |
| Poseidon2 permutation pinned | `zk/tests/pins.rs` | tested |

### 2.3 What the 0.7.0 verifier already does itself (source-read)

The 0.7.0 batch-STARK/FRI/MMCS verifiers are far more defensive than earlier releases. I
confirmed in the registry sources:
- instance-count, public-value, trace width (local and next), quotient chunk count and
  dimension, `random` presence and width, preprocessed width, terminal presence and
  permutation-width checks (`p3-batch-stark verifier/mod.rs:370-566, 643-659`);
- LogUp multiplicity height bound (`:455-456`);
- all opened values observed before FRI (`p3-fri two_adic_pcs.rs` verify, GHSA-vrmm fix);
- FRI: zero-query guard, per-round query counts, arity bounds, global-height cross-check,
  two-adicity bound, final-polynomial length, per-point evaluation counts
  (`PointEvaluationCountMismatch`), opening-point ≠ query-point (`p3-fri verifier.rs:195-316,
  694-860`);
- MMCS: commit-reachable heights (#1766 fix), exact pruned-sibling counts, duplicate-query
  agreement, row widths pinned before salting (`mmcs/mod.rs:518-603`, `hiding_mmcs.rs:171-280`);
- `DuplexChallenger` absorbs are prefix-free (unused rate slots zeroed and the length added to
  the first capacity element, `duplex_challenger.rs:88-111`), so the partial-block aliasing of
  GHSA-vj64 does not apply to this challenger.

### 2.4 third_party patches

`diff -r --strip-trailing-cr` against the registry at `9e422d8`: exactly three source files
differ (`hiding_pcs.rs`, `hiding_mmcs.rs`, `radix_2_dit_parallel.rs`); `verifier.rs` and every
other verifier file are byte-identical to upstream [source-read, re-done by me]. I re-read the
diffs: RNG draws happen under the lock in upstream order; widening, tree building and twiddle
computation happen after release; `w` is computed equivalently; peak memory kept. The patches
touch **prover code only**. `widen_matches_with_random_cols` pins the equivalence, but it runs
only in a manual upstream checkout (third_party is excluded from the workspace and CI)
[tested manually per README 2026-09-25; not in CI].

**Upstream status (checked 2026-09-27):** `v0.8.0` and `main` still hold the `spin::Mutex`
across `with_random_cols` in `HidingFriPcs::commit` (line 247-249), `get_quotient_ldes`
(line 496-499) and `MerkleTreeHidingMmcs::commit` (line 137); `p3-dft` is fixed in 0.8.0. The
issue in `UPSTREAM-REPORT.md` is still unfiled [source-read].

---

## 3. Problems in scope

### 3.1 Which upstream fixes after 0.7.0 matter to BlackSilk? (advisory table)

Every PR below was confirmed **absent** from the `v0.7.0` tag with the compare API
(`v0.7.0...<merge sha>` = "ahead": #2033 +19, #2048 +31, #2100 +63, #2106 +72, #2256 +166,
#2277 +188). v0.7.0 was published 2026-09-07; v0.8.0 on 2026-09-23; no 0.8.x since.

| Upstream item | What it fixes | Applies to BlackSilk's 0.7 configuration? | Class |
|---|---|---|---|
| #2033 fold schedule derived | Prover-chosen FRI arities accepted if they sum right | **Yes** (0.7 `verifier.rs:218-232`) | Malleability by the prover / outside analysed protocol |
| #2106 canonical PoW witnesses at 0 bits | `check_witness(0,w)` accepts anything unabsorbed | **Yes** for `commit_pow_witnesses` (COMMIT_POW_BITS = 0). `query_pow_witness` is bound (16 bits). 0.7 has no `batch_pow`/`ood_pow` fields | Third-party malleability (tx id) |
| #2256 present-but-empty `preprocessed_next` | Length-only check; `Some([])` reaches `VerticalPair::new` and panics | **Yes** (0.7 `verifier/mod.rs:536-546`). Same length-only gap for `preprocessed_local` on tables without preprocessing | Third-party malleability + verifier panic |
| #2277 `MerkleCap` deserialization | Any root count accepted by `derive(Deserialize)` | **Yes**; and the 0.7 verifier compares only `commit[cap_idx]`, so **extra roots are accepted** (§3.5) | Prover-side encoding freedom (not in the PR text; my reading) |
| #2100 hiding-FRI budgets | Masking budget `N ≥ 2(q + D·points)`; **`num_random_codewords ≥ D`**; single-use private prover data; verifier pins hidden opening counts | **Partly**: budget met (248 ≤ 256); **codeword minimum not met (4 < 8)**; hidden counts unpinned in 0.7 | Privacy (conditional ZK) — §3.4 |
| #2048 accounting and grinding hygiene | Several over-reports in `p3-security`; batch-stark grinding sites | Mostly **no** on BlackSilk's call path (§3.3) | Documentation accuracy |
| #2107 / #2125 shape pinned / derived | FRI shape read from the proof | Covered: BlackSilk pins heights, schedule, `PARAMS_ID` | — |
| #2257 `degree_bits` below PCS minimum | Circle PCS panic | **No** (two-adic; BlackSilk rejects `db < 9` anyway) | — |
| #2263 interpolation at zero | Panic at z = 0 | Only if ζ = 0 (probability 2^-247); contained by `catch_unwind` | — |
| #2276 periodic shape rule | `period ≤ height` vs tiling | **No**: all lengths are powers of two and verifier-supplied | — |
| #1947 public inputs by trace position; #2278 | multi-stark | **No** (batch-stark 0.7 observes public values in `observe_main`) | — |
| #2131 DEEP batching over LDE domain | `p3_security::budget` | **No** (BlackSilk uses `StarkSecurityParams`, not `budget`) | — |
| #2282 DKT26 Johnson bound | Tighter MCA bound | Raises algebraic terms; **no effect** on reported figures (collision cap binds) | — |
| #2260 sumcheck HVZK RNG | sumcheck | **No**; BlackSilk's hiding RNGs are `StdRng` from a hedged seed (`config.rs:124-151`) | — |
| GHSA-vrmm, -m23j, -f69f | Pre-0.7 FRI/transcript bugs | **No** (fixes inside v0.7.0; dependency-review §5a) | — |
| GHSA-3g92 `PaddingFreeSponge` lengths | Variable-length collisions | Used as leaf hash; lengths pinned by `check_widths` → not exploitable (dependency-review §5a) | — |
| GHSA-vj64 `MultiField32Challenger` | Transcript malleability | **No** (not used) | — |
| Lock-scope livelock (ours, ZK-F11/21/28) | Prover hang | **Yes**; patched locally; still open upstream for p3-fri and p3-merkle-tree | Liveness (prover) |

### 3.2 Are they covered by BlackSilk-level checks? (coverage matrix)

| Item | Reachable in 0.7 | BlackSilk rule | Test today | Gap / action |
|---|---|---|---|---|
| #2033 schedule | Yes | `check_fri_schedule` (consensus, v3 rules) | honest + tamper + exhaustive + PX shapes | Tamper test only (upstream built a genuinely re-proved forged proof). Acceptable: the rule is structural and runs before Plonky3. Keep. |
| #2106 commit witnesses | Yes | `check_canonical_form` (all elements via `any`) | element 0 only | **Add** last-element and every-element cases; add `query_pow_witness` rewrite → `Invalid` |
| #2106 other witness fields | No (fields absent in 0.7) | — | — | Re-check at 0.8 (`batch_pow`, `ood_pow`, `lookup_pow` appear) |
| #2256 `preprocessed_next` | Yes (panic path when `pre_w > 0`) | `check_canonical_form` at decode; `catch_unwind` at verify | only `pre_w = 0` case | **Add** the `pre_w > 0` case (the upstream panic) at decode **and** a direct `verify()` call proving the panic is contained (`VerifierPanicked`, not an escape) |
| `preprocessed_local` `Some([])` (pre_w = 0) | Yes (unbound) | same | no | **Add** |
| `trace_next` / `random` `Some([])` | No (0.7 rejects) | redundant belt-and-braces | no | Keep; optional test |
| #2277 / extra cap roots | Yes | **none** | none | **F24-2**: add `num_roots() == 1` for every commitment |
| Hidden codeword opening counts | Yes (unpinned in 0.7; pinned in 0.8) | **none** (documented R3-6) | none | **F24-3**: pin to `NUM_RANDOM_CODEWORDS` |
| #2100 hiding budget | n/a (prover) | `const` assert `2(8+108) ≤ 256` + verifier `db ≥ 9` | compile-time | **F24-5**: add upstream's stricter form `2(108 + 8·2) = 248 ≤ 256` |
| #2100 codewords ≥ D | Invariant not met | none | none | **F24-1** (decision) |
| #2100 single-use prover data | n/a | fresh `ProverConfig` per proof; one opening per commitment | no | Low value; document |
| Lock livelock | Yes | third_party patches | `zkvm/tests/stress.rs`; upstream suites manual only | **F24-8**: CI + integrity pin |

### 3.3 What is the calculator "bug" (R4-01)?

**What the problem is and why it exists.** Two separate things were conflated:

1. **BlackSilk's call** passes the pre-ZK height: `ProvenSecurity::compute(&p, 1 << shape.log_height)`
   (`zk/src/params.rs:153`), while under ZK the committed polynomials live on `2·H`
   (`degree_bits = log2 H + 1`; 0.7 doc of `compute_from_proof`, `p3-uni-stark security.rs:326-330`).
   The envelope test also stops at `log_height = 22` though proofs may claim degree bits 23.
2. **The 0.7 calculator's own accounting bugs** (listed in #2048). I traced each against
   BlackSilk's actual call path (`StarkSecurityParams::new` + explicit `num_batched_functions`
   + `ProvenSecurity::compute`, `extras = []`, `GrindingSites::NONE`):

| #2048 item | On BlackSilk's path? | Direction |
|---|---|---|
| `num_batched_functions` defaults to 1 | No: BlackSilk sets committed columns (up to 65,536 tested) | — |
| ZK quotient doubling missing in `from_air` | No: `from_air` unused; column counts measured on real proofs (M3) | — |
| `LOG2_E` rounded down | No: `fixed.rs` is not wired into the f64 path (its own module doc says so) | — |
| `compute_upper_m` uses `ceil` | Yes | may admit one inadmissible `m`; LDR algebraic terms only |
| `best_ldr_m` optimises the LDT term only | Yes | Here it **understates** (0.7 picks m≈141-160 → 165-169 bits; composite-optimal m≈33-54 → 176 bits) |
| folding coefficient overflow | No (arity 16) | — |
| grinding sites not credited | No (BlackSilk grinds only in FRI) | — |

**Numbers** (my re-implementation of the 0.7 f64 formulas, Appendix A; evidence class:
*computed*, not produced by the Rust crate — the params test should confirm):

| Case (5,000 constraints, degree 8) | UDR bits | Johnson algebraic min (uncapped) | Reported Johnson |
|---|---|---|---|
| log_trace 22 (what is passed today), 6,000-65,536 columns | 105.65 (query term) | 165.5-176.6 | **123 = `COLLISION_BITS`** |
| log_trace 23 (correct post-ZK), 6,000-65,536 columns | 105.65 | 165.4-176.4 | **123** |

So the off-by-one **changes neither headline number**: the UDR figure is query-bound
(108·log2(1/0.5625) + 16 = 105.65) and the Johnson figure is the collision cap, which binds by
more than 40 bits. The real accuracy issue is the cap itself:

- `COLLISION_BITS = 123` is a generic-birthday figure for an 8-element digest. The first
  rigorous analysis of Plonky3's Merkle tree (Coratger, Khovratovich, Mennink, Wagner, ePrint
  2026/089, ACM CCS 2026) shows that the `TruncatedPermutation` node compression is **not**
  collision-resistant or one-way, and proves strong position-binding and extractability of the
  tree only through leaf pre-hashing and fixed topology; with an overwrite-sponge leaf hash on
  the same permutation (BlackSilk's case) the bound is `(4q² + 2q)/(|H| − 1)` (Thm 3), and the
  paper's concrete figure for 8×31-bit digests is ≈ 122.7 bits (Remark 6, `6q²/|H|`). With
  log2 p = 30.91 that is ≈ 122.3-122.6 bits. Extractability, not collision resistance, is what
  BCS needs.
- The same paper's Appendix C states the jagged (mixed-height injection) MMCS stays in scope
  **because injection points are fixed by public matrix dimensions** — which is exactly what
  the 0.7 commit-reachable-height check and BlackSilk's exact shapes provide.

**Security consequences:** none for the protocol; the documented "≥ 123 Johnson bits" is about
0.5-1 bit optimistic, and "Johnson" is a misnomer for a hash-bound figure. Not
consensus-critical; privacy-neutral.

**Literature / other projects:** `soundcalc` (ethereum) is the independent calculator 0.7 says
it was cross-checked against; 0.8 adds DKT26 (ePrint 2026/2056) and #2048's corrections.
R2-C6 reached the same "leaf anchoring + fixed depth" conclusion for BlackSilk's own `Hk`
tree; ePrint 2026/089 now gives a citable proof for the Plonky3 tree.

**Fix and trade-offs:** pass `log_height + 1` (or `compute_from_proof`), extend the envelope to
`MAX_LOG_HEIGHT + 1`, set `COLLISION_BITS = 122` with the citation, and assert which term binds.
`COLLISION_BITS` is in the consensus fingerprint manifest (`px/src/fingerprint.rs:190`), so
the fingerprint changes (free before the freeze; no validation rule changes). 122 ≥
`TARGET_JOHNSON_BITS` = 120, so no parameter moves.

**Tests:** params test asserts both targets over degree bits 9..=23 and that the reported
Johnson figure equals `COLLISION_BITS` (binding term); a cross-check against `soundcalc` or
the 0.8 crate in a scratch crate, recorded in docs with the calculator version.

**Invariants:** UDR ≥ 100 by the query term; the eq. 17 masking relation; `COLLISION_BITS` ≤
the proven Merkle/FS bound.

### 3.4 Upstream now requires `num_random_codewords ≥ extension degree` (F24-1)

**What:** #2100 (merged 2026-09-09, in 0.8.0) makes `HidingFriPcs` reject, on both prover and
**verifier** side, any configuration with fewer random codewords per committed matrix than
`Challenge::DIMENSION`, documented as "required to mask extension-field batching"
(0.8 `fri/src/hiding_pcs.rs:78-79, 152-176, 326-331`). BS-ZK-2 uses 4 with a degree-8
extension (`zk/src/params.rs:57`).

**Why it exists here:** BlackSilk raised the count to 8 (BS-ZK-3) on finding Z2, then
reverted after internal round 3 on the argument that the paper's mask `R` is the separate
per-table randomization polynomial of `NUM_RANDOM_CODEWORDS + 8` columns, which already spans
the extension; the per-matrix codewords were judged "additional masking"
(internal-review-log.md rounds 2-3; zk-coverage.md rows "FRI mask R", "Per-matrix codewords").
My source reading supports the premise that every committed height in a BlackSilk proof has an
`R` (main, permutation, quotient chunks and preprocessed matrices are all at the table's
extended height). Upstream nevertheless now treats `≥ D` codewords as a hard invariant, gives
no proof in the PR, and keeps `R` unchanged (0.8 `hiding_pcs.rs:706-738`). The two positions
cannot both be "necessary"; the upstream one is at least a strong signal that the round-3
conclusion needs an explicit written argument rather than a withdrawal.

**Consequences:** if upstream's invariant reflects a real leak, BS-ZK-2 proofs may reveal
more than the statistical-ZK statement allows about PX witnesses (privacy-critical). If it is
merely conservative, BS-ZK-2 is fine but **cannot be migrated to 0.8 unchanged** (the 0.8
verifier returns `InsufficientHidingRandomCodewords`). Consensus-relevant only through the
parameter set (proof format).

**Options:** (a) write the argument (ePrint 2024/1037 Protocol 2 / Lemma 2 applied to
Plonky3's `R`) and ask upstream for the rationale of the `≥ D` rule (public issue; owner
decides); (b) move to 8 codewords at the v3 reset (measured before: +10-13 % size, time,
memory; internal-review-log round 3) — a new `PARAMS_ID`; (c) keep 4 and accept a documented
divergence from upstream plus a 0.8 migration blocker. **Recommendation:** P0 decision before
the freeze, analysis led by #26 with me supporting; default to (b) if no written argument
survives review, because privacy outranks size in the brief's priority order.

**Tests:** whichever is chosen, a test in `zkvm/tests/vm.rs` that every committed matrix of a
real proof has exactly `NUM_RANDOM_CODEWORDS` hidden columns (§3.5), plus the P-5 re-run.

### 3.5 Unpinned proof-shape fields left by 0.7 (F24-2, F24-3)

**F24-2, cap root count.** `MerkleCap` derives `Deserialize` without the power-of-two/length
invariant (0.7 `p3-symmetric hash.rs:24-31`; fixed upstream by #2277). The 0.7 MMCS verifier
compares only `commit[cap_idx]` for the frontier node indices (`mmcs/mod.rs:890-895`;
`mmcs/batch.rs:268`), and with `cap_height = 0` the only index is 0. `DuplexChallenger`
observes **all** roots (`duplex_challenger.rs:206-218`). So a **prover** can append arbitrary
digests to any commitment (`main`, `permutation`, `quotient_chunks`, `random`, each FRI
`commit_phase_commits` entry), re-run Fiat-Shamir, and obtain a valid proof; nothing in
`check_canonical_form` rejects it. It is **not** third-party malleability (the roots are in
the transcript) and not a soundness issue. Consequences: a non-canonical proof encoding, and
a cheap, unauthenticated data channel of ~31 bytes of field data per 32 bytes (bounded by
`MAX_PROOF_BYTES`; the PX fee is fixed at the maximum size, `tx/src/params.rs:41`, so the space
is paid for). A 3-root cap would also violate an invariant that `height()` relies on (no
verifier call today, per #2277). Confidence: medium-high (source-read, not demonstrated —
producing such a proof needs a modified prover).

**F24-3, hidden random-codeword openings.** The 0.7 `HidingFriPcs::verify` checks only the
round/matrix/point nesting of the hidden opened values and appends whatever length each point
carries (`hiding_pcs.rs:403-439`); the FRI verifier then pins widths from the first point and
requires every point to match (`verifier.rs:742-754, 842-851`). So a prover may use any number
of hidden columns per matrix, including 0. BlackSilk documented this (R3-6: "affects only that
prover's own privacy"). 0.8 now pins the count (`HidingRandomOpeningValueCountMismatch`,
0.8 `hiding_pcs.rs:395-407`). Pinning it in BlackSilk (a) makes the consensus proof shape exact,
(b) makes a wallet regression that drops hiding **fail loudly** at every node instead of
silently degrading one user's privacy, and (c) removes the second padding channel.

**Fix:** in `check_canonical_form` (decode time): every commitment has exactly one root;
every hidden-opening vector has exactly `NUM_RANDOM_CODEWORDS` entries per point (verify on
real proofs whether the preprocessed round also carries 4 in 0.7 — it is committed with the
`VerifierConfig::setup()` hiding PCS, so it should). Consensus tightening (rejects only
non-honest encodings), free at the v3 reset. **Trade-off/risk:** a wrong expected count is a
liveness split; mitigate with the honest-proof test on every consensus shape (as for R4-02).

### 3.6 third_party patches and upstream coordination

- Patches are correct and value-preserving (§2.4); verifier code is untouched.
- Risks: (1) no automated check that `third_party` still equals "registry + reviewed diff";
  (2) upstream suites and the vendored tests never run in CI; (3) 0.8 and `main` still carry the
  livelock in two sites, so any migration must re-port the patches; (4) the drafted upstream
  issue is unfiled. Plonky3 still has no `SECURITY.md` but does publish GHSAs (private reporting
  exists); the livelock is liveness-only, so a public issue remains appropriate.

### 3.7 Migration plan to 0.8 as a new parameter set (P3)

**Principle (never-change list item 19):** never upgrade in place; 0.8 becomes a new
`PARAMS_ID` (e.g. `BlackSilk/zk/BS-ZK-3`) activated at a height, or at a reset. Every proof
changes (typed Fiat-Shamir #1603/#2090/#2091, FRI transcript #2035/#2086, derived shape #2125,
new witness fields).

**Step list:**
1. **Scratch crate** (outside consensus) compiling BlackSilk's config on 0.8; read the
   `p3-air`/`p3-batch-stark` API breaks (#1947 public-input binding, #2281 preprocessed
   grouping, lookup planning #2146).
2. **Decide F24-1** first (0.8 refuses 4 codewords).
3. **Transcript binding:** re-express `PARAMS_ID` and the statement digest (with `CIRCUIT_ID`)
   through the typed layer's instance label; keep a test that the first challenge differs per
   `PARAMS_ID` / `CIRCUIT_ID`.
4. **Canonical-form rules:** drop `check_fri_schedule` (derived upstream, `log_arity` no
   longer serialized) but keep its test as a differential; keep BlackSilk's witness==0 rule and
   extend it to `batch_pow_witness`, `ood_pow_witness`, `lookup_pow_witness` (0.8 checks them
   too — keep both, belt and braces); keep cap-root and hidden-width rules (0.8 pins the
   latter; #2277 fixes the former at deserialization).
5. **Re-port the lock patches** to `p3-fri` and `p3-merkle-tree`; drop the `p3-dft` patch;
   re-run upstream suites and `zkvm/tests/stress.rs`.
6. **Security figures** from 0.8 `p3-security` (DKT26, #2048 fixes) **and** `soundcalc`;
   `COLLISION_BITS` from ePrint 2026/089.
7. **ZK re-review:** terminal blinding (does 0.8 publish LogUp terminals the same way?),
   hiding budget at MIN_LOG_HEIGHT with 8 codewords, P-5 proof-length campaign.
8. **Measure** proof size, prove/verify time, adversarial verifier time (with #22, #27);
   optionally adopt grinding sites (#2048) to cut queries (R4-09 option d).
9. **Activation mechanics:** either (i) at a reset, only 0.8 linked; or (ii) at a height, both
   verifiers linked: Cargo allows two semver-incompatible versions via renamed dependencies
   (`p3-fri-08 = { package = "p3-fri", version = "=0.8.0" }`) and a second `[patch.crates-io]`
   key with `package = ...`; every PX proof carries its `PROOF_VERSION`; nodes pick the verifier
   by the rule set at the height (docs/reviews/v3-upgrade-mechanism.md).
10. **Golden vectors:** one 0.7 and one 0.8 proof, each accepted by its own verifier and
    rejected by the other.

**What could go wrong:** an unnoticed transcript-order change (golden vectors catch it); a
patched-crate re-port error (upstream suites + stress test); dual-version dependency bloat and
two `spin`/`rand` generations; 0.8 is days old and pre-1.0 — wait for a 0.8.x or later
release and re-read its advisories before starting.

---

## 4. New findings

| ID | Severity | Status | Location | Scenario | Confidence |
|---|---|---|---|---|---|
| **F24-1** | **Medium** (privacy; conditional-ZK claim) | Blocked (needs analysis/decision) | `zk/src/params.rs:57`; upstream 0.8 `fri/src/hiding_pcs.rs:78-79,152-176,326-331` | Upstream now requires ≥ 8 per-matrix random codewords for a degree-8 extension "to mask extension-field batching"; BS-ZK-2 uses 4 on an internal argument that `R` suffices. Either BS-ZK-2 leaks beyond its ZK statement, or it is a documented divergence that also blocks a 0.8 migration | High (fact); unknown (impact) |
| **F24-2** | Low | Not implemented | `zk/src/lib.rs:314-342`; 0.7 `p3-symmetric/src/hash.rs:24-31`, `p3-merkle-tree/src/mmcs/mod.rs:890-895` | A prover appends extra roots to any Merkle cap; the proof verifies; encoding not canonical; ~1.8 MB of free-form data per PX tx | Medium-high (source-read) |
| **F24-3** | Low | Not implemented (documented as R3-6) | 0.7 `p3-fri/src/hiding_pcs.rs:403-439`; `zk/src/params.rs:16-24` | Hidden-column count unpinned: a buggy or malicious wallet silently weakens its own hiding, and proof shape is not exact; 0.8 pins it | High |
| **F24-4** | Low (docs) | Not implemented | `zk/src/params.rs:65,142-158,185`; docs/zk.md §9.3, P4 | R4-01 resolved: the pre-ZK height changes no reported figure; the "≥ 123 Johnson" figure is the hash cap, and the proven Merkle extractability bound is ≈ 122.3-122.6 bits (ePrint 2026/089) | High (computed + paper) |
| **F24-5** | Low | Not implemented | `zk/src/params.rs:170` | The eq. 17 `const` assert (232 ≤ 256) is weaker than upstream's conservative budget 2·(108 + 8·2) = 248 ≤ 256; a future query-count change (e.g. 113) would pass BlackSilk's assert and fail upstream's | High |
| **F24-6** | Low (test gap) | Partially implemented | `zk/tests/proofs.rs:453-490` | #2106 test mutates only witness 0; #2256 test covers only the no-preprocessing case, not the upstream panic case; no test calls `verify()` on such a proof directly | High |
| **F24-7** | Informational | Accepted limitation (for now) | `zk/src/params.rs:142-158` | Calculator omits the LogUp term and multi-table composition (`extras = []`); my estimate ≥ 200 bits in the 247-bit field, so not binding | Medium (estimate) |
| **F24-8** | Low (process) | Partially implemented | `third_party/`, `.github/workflows/ci.yml`, `third_party/UPSTREAM-REPORT.md` | No integrity pin of the patched crates, their tests are not in CI, no golden verifier vector detects Plonky3 behaviour drift, and the livelock is still unreported upstream while present in 0.8/main | High |
| F24-9 | Informational | Complete and verified (as of 2026-09-27) | docs/reviews/dependency-review.md §5a | Still 5 GHSAs, none applying; no RustSec entries for `p3-*`; no 0.8.x release | High |

**Challenge to the existing reports.**
- R4 (§3.2) expected the Johnson figure "may move by a few bits in either direction" with the
  corrected domain. Under the 0.7 formulas it does not move at all: the collision cap binds by
  > 40 bits. SX1's "low, docs only" severity is confirmed; the docs change is the cap's
  justification, not the domain.
- R4 §4 and zk-coverage.md call the per-matrix codewords "additional masking"; upstream 0.8
  now enforces them as necessary. The round-3 withdrawal of Z2 was a correct reading of *how*
  0.7 builds `R`, but it did not establish that 4 codewords are enough; that remains open (F24-1).

---

## 5. Implementation plan for phase 2

| # | Work item | Files (ownership) | External effect | Identity | Tests | Docs | Diff. | Prio |
|---|---|---|---|---|---|---|---|---|
| I1 | **Resolve F24-1**: written argument or switch to 8 codewords | analysis in `docs/reviews/zk-coverage.md` (#26 owner); if switched: `zk/src/params.rs` (#25/#22), `PARAMS_ID` bump | Consensus (proof format) if switched | New PARAMS_ID; fingerprint | vm.rs hidden-width test; P-5 re-run; size/time bench | zk.md §9.3, zk-coverage.md, internal-review-log | M | **P0 (decision)** |
| I2 | **Canonical shape rules**: one root per cap (all commitments incl. FRI rounds); hidden openings exactly `NUM_RANDOM_CODEWORDS` per point | `zk/src/lib.rs::check_canonical_form` (**#22 owns the file**; I supply the rule text and tests) | Consensus tightening (v3 rules) | None beyond v3 | honest proofs on every consensus shape (n_fn 0..2) pass; tampered caps/widths → `Encoding` | zk.md §10, px.md | S | **P0** (ride the reset) |
| I3 | **Advisory negative-test suite** `zk/tests/upstream_advisories.rs` (new; **mine**): #2106 every witness element + `query_pow_witness`; #2256 `pre_w > 0` no-next case at decode and via direct `verify()` (must be `VerifierPanicked` or `Invalid`, never an escaped panic); `preprocessed_local Some([])`; #2033 tamper; #2277 extra root and 3-root cap; hidden-width ±1; `degree_bits` < min / > max; opening count mismatches | new test file only | None | None | as listed; each test names its advisory | dependency-review §5a table | S | **P1** |
| I4 | **Calculator accuracy (R4-01)**: pass `log_height + 1`; envelope 9..=23; `COLLISION_BITS = 122` (cite 2026/089); assert UDR ≥ 100 and Johnson == cap in `zkvm/tests/{multi,vm}.rs` envelope tests | `zk/src/params.rs` (**#25 owner**), `zkvm/tests/multi.rs`, `vm.rs` (#23) | None | Fingerprint value changes (COLLISION_BITS) | params test; soundcalc cross-check recorded | zk.md §9.3 + P4, query-policy.md | S | **P1** |
| I5 | Second hiding-budget assert `2*(NUM_QUERIES + EXTENSION_DEGREE*2) <= 1 << MIN_LOG_HEIGHT` | `zk/src/params.rs` (#25) | None | None | compile-time | zk.md eq. 17 note | S | P1 |
| I6 | **third_party integrity**: `third_party/CHECKSUMS.sha256` + test that hashes the vendored trees; CI job running `cargo test --locked --manifest-path third_party/<crate>/Cargo.toml` for the three crates | `third_party/**` (**mine**), `zk/tests/third_party_integrity.rs` (**mine**), `.github/workflows/ci.yml` (**#43 owner**) | None | None | integrity test; upstream suites (208 tests) in CI | third_party/README.md | S | P1 |
| I7 | **Golden verifier vector**: a stored toy proof (fixed statement) that must decode and verify, plus its SHA-256; one-byte-flip must fail | `zk/tests/fixtures/`, `zk/tests/golden_proof.rs` (**mine**) | None | None | golden accept + reject | dependency-review §3 | S | P2 |
| I8 | Update `UPSTREAM-REPORT.md` with the 0.8/main line numbers; owner decides to file (A/B) | `third_party/UPSTREAM-REPORT.md`, `third_party/upstream/*` (**mine**) | None | None | — | — | S | P2 |
| I9 | Documentation: dependency-review §5a gains a "post-0.7 fixes" table (§3.1 here) and the coverage matrix; zk.md P4/§9.3 wording ("hash-bound", ≈ 122) | `docs/reviews/dependency-review.md` (**mine**, coordinate #44), `docs/zk.md` (#25/#47) | None | None | — | as named | S | P1 |
| I10 | **0.8 migration** as BS-ZK-3 (plan §3.7), after the trial and after a 0.8.x | new scratch crate first; later `zk/`, `zkvm/`, `third_party/` | New parameter set | New identity / activation | golden per version, differential, full ZK suites, stress | zk.md, v3-upgrade-mechanism.md | L | P3 |

Benchmarks: I1 (if switched) proof size / prove time / memory per shape; I10 full set. None for
I2-I9.

---

## 6. Dependencies and conflicts

- **#22 px-proof-system:** owns `zk/src/lib.rs` (`check_canonical_form`, schedule, decode) and
  `MAX_PROOF_BYTES`. I2 must be implemented by #22 or handed to me explicitly. F24-2/F24-3 bear
  on #22's "widest proof vs cap" and adversarial-verifier-cost measurements (padded proofs).
- **#25 zk-soundness:** owns `zk/src/params.rs` and the figures; I4/I5 are its files. My
  Appendix A numbers are an input to its independent recomputation (soundcalc / 0.8).
- **#26 zk-privacy:** lead on F24-1; P-5 re-run if the codeword count changes.
- **#27 zk-performance:** SIMD builds do not touch `third_party`; if #27 proposes patching
  `p3-monty-31`, it joins my integrity pin (I6).
- **#23 zkvm-bvm:** envelope tests in `zkvm/tests/{multi,vm}.rs` (I4, I1 hidden-width test).
- **#41 fuzzing / #42 mutation:** structure-aware ZK verifier fuzzing should include cap-root
  and hidden-width mutations; mutation testing of `check_canonical_form`.
- **#43 CI:** I6's CI job. **#44 supply chain:** shared interest in `third_party` and pins;
  proposed split: #44 owns `Cargo.lock`/deny config, I own `third_party/**`.
- **#40 genesis/fingerprint:** I1 and I4 change fingerprint entries; must land before the freeze.
- **#47 docs:** zk.md wording.

---

## 7. Open questions for the coordinator

1. F24-1: does the owner accept "switch to 8 codewords at the reset unless #26 produces a
   written argument that survives review"? Should we ask Plonky3 (public issue) for the
   rationale of #2100's `≥ D` rule, and under which draft (named/anonymous)?
2. I2 ownership: may I edit `check_canonical_form` in `zk/src/lib.rs`, or does #22 implement
   the two rules from my tests?
3. I4: is changing `COLLISION_BITS` (fingerprint-visible, not validation-visible) acceptable
   now, or should docs alone carry the 122-bit statement until the freeze batch?
4. Should the upstream livelock issue be filed now (owner's A/B choice)?
5. Is a dual-verifier activation (two Plonky3 versions linked) ever wanted, or will every
   proof-system change ride a reset while the network is a testnet?

---

## 8. Sources

- Plonky3 v0.8.0 release: https://github.com/Plonky3/Plonky3/releases/tag/v0.8.0 (2026-09-23);
  compare v0.7.0...v0.8.0 (220 commits): https://github.com/Plonky3/Plonky3/compare/v0.7.0...v0.8.0
- PR #2033 fold schedule: https://github.com/Plonky3/Plonky3/pull/2033
- PR #2048 accounting and grinding hygiene: https://github.com/Plonky3/Plonky3/pull/2048
- PR #2100 PCS budgets / hiding FRI: https://github.com/Plonky3/Plonky3/pull/2100
- PR #2105 / #2106 canonical grinding witnesses: https://github.com/Plonky3/Plonky3/pull/2105 ,
  https://github.com/Plonky3/Plonky3/pull/2106
- PR #2107 / #2125 FRI shape: https://github.com/Plonky3/Plonky3/pull/2107 ,
  https://github.com/Plonky3/Plonky3/pull/2125
- PR #2109 grinding vs model: https://github.com/Plonky3/Plonky3/pull/2109
- PR #2131 DEEP batching budget: https://github.com/Plonky3/Plonky3/pull/2131
- PR #2256 present-but-empty preprocessed_next: https://github.com/Plonky3/Plonky3/pull/2256
- PR #2257 degree_bits minimum: https://github.com/Plonky3/Plonky3/pull/2257
- PR #2263 interpolation at zero: https://github.com/Plonky3/Plonky3/pull/2263
- PR #2276 periodic shape: https://github.com/Plonky3/Plonky3/pull/2276
- PR #2277 MerkleCap deserialization: https://github.com/Plonky3/Plonky3/pull/2277
- PR #2278 optional sections (multi-stark): https://github.com/Plonky3/Plonky3/pull/2278
- PR #2282 DKT26 Johnson bound: https://github.com/Plonky3/Plonky3/pull/2282
- Issue #1766 MMCS dimensions: https://github.com/Plonky3/Plonky3/issues/1766 ; issue #1746:
  https://github.com/Plonky3/Plonky3/issues/1746
- Plonky3 security advisories: https://github.com/Plonky3/Plonky3/security/advisories
  (GHSA-vj64-rjf3-w3v7 / CVE-2026-46654, GHSA-3g92-f9ch-qjcm, GHSA-f69f-5fx9-w9r9,
  GHSA-m23j-cj9m-ppg9, GHSA-vrmm-4mm5-38vm)
- Plonky3 0.8.0 sources: https://raw.githubusercontent.com/Plonky3/Plonky3/v0.8.0/fri/src/hiding_pcs.rs ,
  .../merkle-tree/src/hiding_mmcs.rs , .../batch-stark/src/proof.rs , .../fri/src/proof.rs
- T. Coratger, D. Khovratovich, B. Mennink, B. Wagner, "The Billion Dollar Merkle Tree",
  ePrint 2026/089 (ACM CCS 2026): https://eprint.iacr.org/2026/089
- U. Haböck, A. Al Kindi, "A note on adding zero-knowledge to STARKs", ePrint 2024/1037:
  https://eprint.iacr.org/2024/1037
- Ben-Sasson, Carmon, Haböck, Kopparty, Saraf, "On Proximity Gaps for Reed-Solomon Codes",
  ePrint 2025/2055: https://eprint.iacr.org/2025/2055
- Dao, Kominers, Thaler, "Reed-Solomon Codes Beyond Johnson", ePrint 2026/2056:
  https://eprint.iacr.org/2026/2056
- "On the Security of STARKs with FRI" (round-by-round bounds), ePrint 2024/1553:
  https://eprint.iacr.org/2024/1553
- Grassi, Khovratovich, Schofnegger, "Poseidon2", ePrint 2023/323: https://eprint.iacr.org/2023/323
- ethereum/soundcalc: https://github.com/ethereum/soundcalc
- Chiesa, Orrù, "A Fiat-Shamir transformation from duplex sponges", ePrint 2025/536:
  https://eprint.iacr.org/2025/536 (cited by 2026/089 for the duplex FS setting)

---

## Appendix A. Re-implementation of the p3-security 0.7.0 proven-security path

Arithmetic only; mirrors `p3-uni-stark 0.7.0 ProvenSecurity::compute_from_proof` →
`p3_security::stark::proven_security_report` with `FriRegime`, `extras = []`,
`GrindingSites::NONE`, as called by `zk/src/params.rs::security`. Kept outside the repository
(scratchpad). Key formulas: UDR query term `16 − 108·log2((1 + (k+2)/n)/2)`; LDR per `m`:
query `16 − 108·log2((1+1/(2m))·√ρ)`, commit `min(BCHKS25 linear, n/q)`, batching
`247 − (log n + log2(2(m+½)^5/3) + 4.5 + log2(cols − 1))`, ALI/DEEP with
`L = (m+½)/√ρ`; `m ∈ [3, min(compute_upper_m, 1000)]` chosen by the LDT-only term (0.7) or by
the full composite (for comparison); result capped at `COLLISION_BITS = 123`.

Selected output (5,000 constraints, degree 8):

```
lt=22 cols=6000  : UDR 105.65 | 0.7 m=160 uncapped 168.90 (batch binds) | composite m=54 uncapped 176.56 (query)
lt=22 cols=65536 : UDR 105.65 | 0.7 m=160 uncapped 165.45               | composite m=37 uncapped 175.91
lt=23 cols=6000  : UDR 105.65 | 0.7 m=141 uncapped 168.81               | composite m=49 uncapped 176.39
lt=23 cols=65536 : UDR 105.65 | 0.7 m=141 uncapped 165.36               | composite m=33 uncapped 175.66
UDR terms at lt=23 (ALI, DEEP, commit, query, batch@65536): 234.7, 220.8, 217.1, 105.65, 205.0
Reported (capped): Johnson 123, UDR 105 in every case, lt 8..23.
```

Evidence class: computed (independent re-implementation); to be confirmed by the Rust params
test (I4) and by `soundcalc` (#25).
