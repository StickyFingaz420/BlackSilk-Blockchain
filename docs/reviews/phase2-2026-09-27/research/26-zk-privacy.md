# 26 zk-privacy: research dossier (phase 2, phase 1)

Specialist 26, BlackSilk engineering phase 2. **Internal engineering work, not an audit.**
Nothing here claims that BlackSilk or its proofs are secure, proven or perfectly
zero-knowledge. Zero knowledge (ZK) is discussed only as **statistical and conditional**.
Read-only: no repository file was changed and no build or test was run.

Evidence tags:
- **[math]:** mathematically established (the argument is given here);
- **[test: name]:** tested;
- **[src]:** source-read;
- **[assumed]**;
- **[unknown]**;
- **[est]:** my estimate.

---

## 1. Scope and what I read

**Commit:** `9e422d8` (`rebuild/core`, after the v3/candidate merge). Working tree clean.

**Documents:**
- `C:/bszkeval/p2/brief.md`; roster entries 18–27 (mine is 26).
- `docs/reviews/zk-coverage.md` (all), `docs/reviews/terminal-blinding.md` (all).
- `docs/reviews/privacy-review.md`: §3 (P-1 to P-11), §3a (P-5 in detail), §3b (query
  positions, proof size).
- `docs/reviews/assumptions.md` (Z7, Z8, Z11, Z12, Z13, I2).
- `docs/reviews/full-review-2026-09-27.md` (§3.5, the findings register, the ZK rows);
  `docs/reviews/autonomous-session-2026-09-27.md` (all).
- Source reports:
  - `R4-zk.md` (all);
  - `R3-privacy.md` §4.2;
  - `I1-private-computation.md` (the ZK parts);
  - `SX1` (the R4-01 and R2-C6 rows);
  - `SX2` (the R8-18, D-1 and R16-3 rows).
- `docs/zk.md` (the ZK claims, §9, R1, the risk table), `docs/zkvm.md` V4, `docs/px.md`
  §4.4 (the byte-length paragraph).
- **P-5 evidence:** `docs/evidence/p5-2026-09-25/`, `p5-2026-09-26/`, `p5-2026-09-26b/`
  (each README and `campaign-output.txt`, plus the CSV header and first rows).
- `third_party/README.md`.

**Code** (read in full or in the relevant part):
- `zk/src/config.rs`, `zk/src/lib.rs`, `zk/src/params.rs`.
- `zkvm/src/prove.rs`: `CIRCUIT_ID`, `statement_digest`, `prove_shaped`, `limits`,
  `verify`.
- `zkvm/src/air/trace.rs`: `with_blinding`, `blind_trace`, `randomize_blinding`,
  `uniform`, `exec_traces`.
- `zkvm/src/air/util.rs`: `BLIND_VALUES`, `blind_consume`, `blind_provide`.
- `zkvm/src/air/byte.rs`.
- `px/src/prove.rs`; `px/examples/proof_length_campaign.rs`.
- `third_party/p3-fri/src/hiding_pcs.rs`: `commit`, `commit_preprocessing`,
  `get_quotient_ldes`, `open_with_preprocessing`, `verify`,
  `get_opt_randomization_poly_commitment`, `get_zp_cis`.
- `third_party/p3-fri/src/prover.rs` (`open_inputs`, index shifts);
  `third_party/p3-fri/src/two_adic_pcs.rs` (per-height alpha offsets).
- Registry Plonky3 0.7.0:
  - `p3-lookup`: `challenges.rs`; `logup.rs` (denominators, the terminal constraint,
    `verify_terminal_sum`, `LookupTerminal`);
  - `p3-batch-stark`: `proof.rs`, and the ZK part of `prover.rs` (R committed before
    ζ, the opening rounds);
  - upstream's "only statistically ZK" notes: `p3-uni-stark/src/prover.rs:329` and
    `p3-batch-stark/src/prover.rs:469`;
  - `p3-monty-31/src/monty_31.rs:154` (field sampling).
- `zk/Cargo.toml`, `Cargo.lock` (rand 0.10.3, rand_chacha 0.3).

**Tests read:**
- `zk/tests/proofs.rs` (`proofs_are_randomized`, the schedule tests);
- the schedule unit tests in `zk/src/lib.rs`;
- `px/tests/proof.rs` (`a_private_transfer_proves_verifies_and_applies_once`,
  `length_parts`);
- `zkvm/tests/blinding.rs` (all nine tests);
- `zkvm/tests/circuit_id.rs`;
- `px/tests/fri_schedule.rs` (names only).

**Git history checked:**
- `c280928` (PX-F5);
- `147fb06` (FRI schedule);
- `de824a4` (`CIRCUIT_ID`);
- `53d3b49` (platform-neutral kernel/vault ELFs, new ids, budgets re-measured).

**Primary sources read for this dossier:**
- The full text of Haböck and Al Kindi, ePrint 2024/1037, version of 20 February 2025:
  - §2 (Protocol 2, Lemmas 1–2);
  - §3 (eq. 3, Lemma 3);
  - §4.1–4.2 (eqs. 9, 10, 16, 17, Lemma 5, Theorem 8);
  - Appendix A.
- The Plonky3 v0.8.0 release notes and PR #2260.
- Other citations in §8.

---

## 2. Current state

### 2.1 What exists and is correct

**S1. Plonky3 randomizes the quotient by the paper's Lagrange decomposition (§4.2), not
the FFT decomposition (§3).** [src] `hiding_pcs.rs:197-307, 528-545`; paper eqs. (3),
(13)–(17).
- `get_quotient_ldes` adds `v_{H_i}·t_i` to every chunk but the last. The last chunk
  compensates, using the normalizers `c_i` from `get_zp_cis` (the Lagrange selectors of
  eq. 12).
- So eqs. (16) and (17) are the right conditions.
- Eq. (3) is not. It would need `2·d·(e·n_F+n_D)+n_D ≤ h`, and it would fail badly: for
  d = 4, 2·4·116 + 108 = 1,036 > 256.

**S2. Eq. (17) holds for every committed witness matrix.** [src] `hiding_pcs.rs:128-160`;
[math]; the `const` assertion at `zk/src/params.rs:170`.
- With e = 8, n_F = 1 and n_D = 108: 2·(8+108) = 232 ≤ h = |H| ≥ 256.
- Plonky3 interleaves one random row per trace row. The committed polynomial is
  therefore `w + v_H·r`, with `r` uniform of degree < |H|.
- So h = |H| exactly, the paper's upper edge.

**S3. Eq. (16) holds.** [src] `hiding_pcs.rs:223-238, 276-302`; [math].
- Each chunk randomizer has h_p equal to the chunk evaluation height, which is at least
  |H| ≥ 256. zk-coverage reads it as |H|; I read 2|H| [est]; either suffices.
- n_F + n_D = 109.
- The chunk randomizers are drawn per flattened base column. That is equivalent to a
  uniform `t_i ∈ F[X]`, with F the degree-8 extension, as the paper requires.

**S4. Each input matrix is opened at one point per query.** [src]
`third_party/p3-fri/src/prover.rs:383-409`.
- Shorter tables are opened at `index >> bits_reduced`.
- So n_D = 108 bounds the number of distinct domain points per matrix.

**S5. The FRI mask R is committed before ζ and before the FRI batching challenge α.**
[src] `p3-batch-stark prover.rs:463-481`; `hiding_pcs.rs:489-509, 381-408`.
- There is one R per table, at that table's extended height.
- Each R has 12 base columns: 4 hidden, and 8 public at ζ.

**S6. LogUp publishes exactly one terminal per table.** [src] `p3-batch-stark
proof.rs:22` (`Vec<Option<LookupTerminal>>`); `p3-lookup logup.rs:405-431`.
- The terminal is a single running sum over all of the table's buses.
- The verifier only checks that the terminals sum to zero.
- So one blinding term per table hides that table's terminal.

**S7. Terminal blinding is correctly built.** [src] `trace.rs:443-467`,
`util.rs:25-62`, `p3-lookup challenges.rs`; [test: `zkvm/tests/blinding.rs`, 9 tests].
- The values are fresh and uniform (rejection sampling).
- A selector admits exactly one message, on row 0.
- Padding is forced to zero.
- There are 8 values, the extension degree.
- Buses are separated by `prefix = α + (bus+1)·β^W`.

**S8. Randomness is uniform and hedged.** [src] `config.rs:130-151`,
`prove.rs:166-198`.
- Plonky3 samples BabyBear by rejection on 31 bits (`monty_31.rs:154-165`). Masks are
  therefore uniform whenever the bit stream is.
- The prover's seeds are `BLAKE2b-512(ZK_PROVER_SEED, witness digest, 32 OS bytes)`,
  split into two `StdRng` seeds (ChaCha12 in rand 0.10).
- The blinding seed is `BLAKE2b(ZK_BLIND_SEED, witness digest, 32 fresh bytes)`, which
  seeds ChaCha20.
- The witness digest covers every run's input and `h_tx`.

**S9. Within a shape, a proof's length depends only on the public query positions.**
[src] `zk/src/lib.rs:250-261`; [test:
`px/tests/proof.rs::a_private_transfer_proves_verifies_and_applies_once` (2 witnesses);
the campaign assertion over 260 proofs, `docs/evidence/p5-2026-09-26b/`].
- Field elements are fixed 4-byte arrays.
- The only variable part is the pruned Merkle multiproof (upstream 0.7.0 `pruning.rs`).
  Its size depends only on the index set and the tree heights.

**S10. `CIRCUIT_ID`, the canonical FRI schedule and the canonical-form rule do not
affect ZK** (§3.1). [src], [math].

### 2.2 What the tests actually prove (and do not)

- **`zkvm/tests/blinding.rs::an_observer_reads_the_input_from_an_unblinded_proof`**
  demonstrates the ZK-F29 leak without blinding. It is strong evidence of the problem.
- **`every_table_of_a_real_proof_is_blinded_with_fresh_values`** runs the real `prove`
  path on a **toy program**, not a PX shape.
  - It shows that every table's blinding values are nonzero and differ between two
    proofs.
  - So it proves the mechanism runs. It does not prove hiding.
- **`proofs_are_randomized`** shows that two proofs of one statement differ, also with a
  zero RNG (so hedging works). It proves freshness, not hiding.
- **The P-5 campaign** proves the **layout invariant**: over 260 proofs, the
  non-authentication bytes are exactly constant per shape.
  - Its permutation tests have little power. With sd ≈ 4,800 B and n = 50 per class,
    the smallest mean shift detectable with 80% power at the Bonferroni level 0.05/14 is
    about 3.75 × 4,800·√(2/50) ≈ **3,600 B** [est].
  - They are a sanity check, not evidence of independence.
- **No test can establish statistical ZK.** As zk.md §808 and terminal-blinding.md §3
  say, hiding rests on the argument (§3.2 below) and on the randomness conditions.

---

## 3. Problems in scope

### 3.1 Is the statistical-ZK claim still conditional-correct after the v3 changes?

**Yes [src, math].** For each change, I checked whether it adds witness-dependent data
to the proof or changes the randomization.

| Change | Effect on ZK |
|---|---|
| `CIRCUIT_ID` (`de824a4`) | Adds a public constant to `statement_digest`, i.e. to the transcript prefix. The simulator absorbs the same public bytes. No effect |
| Canonical FRI schedule (`147fb06`) | Verifier-side only. The honest schedule is `honest_fri_schedule(degree_bits)`, a function of the public shape. Honest proofs are unchanged and no witness data is added. No effect |
| Canonical form (`4b277cd`) | Commit-phase grinding witnesses must be 0, and optional openings must be non-empty. Both are honest, public values. No effect |
| PX-F5 (`c280928`) | A kernel check. The kernel's execution profile changes, but budgets fix every table height and terminal blinding hides the profile. No effect on the argument; the P-5 constants may change (§3.4) |
| Neutral ELFs (`53d3b49`) | New programs, hence possibly new Program, Image and Output table heights, and new constant parts. No effect on the argument; the P-5 constants must be re-measured |

**What *would* break the ZK argument** (see the invariants in §3.6):
- a query count above 120, a larger extension, or a minimum height below 2^8 (eq. 17);
- `BLIND_VALUES` ≠ the extension degree;
- any proving path that skips `randomize_blinding`;
- a Plonky3 upgrade that changes `HidingFriPcs`. 0.8's fused hiding LDE (PR #2015) must
  be re-read.

### 3.2 The updated conditional-ZK statement (the main deliverable)

**Model.** Honest-verifier ZK (HVZK) of the interactive oracle proof (IOP), compiled with
Fiat–Shamir and salted Merkle trees.
- If the Merkle hash is modelled as a random oracle and the salts have enough entropy,
  the compiled argument keeps the IOP's zero knowledge (Ben-Sasson, Chiesa, Spooner,
  TCC 2016-B).
- The paper states that HVZK suffices for the non-interactive proof.

**The per-table core (the conditions of Theorem 8) is met [src, math]:** S1–S4 above.

**The FRI mask built from base-field polynomials can be quantified [math].** zk-coverage
§3 item 4 records only upstream's note ("only statistically ZK"). The bound:
- R's 12 base columns `r_k` enter the FRI batch with the powers `α^{o+k}`. The offset
  `o` is per height (`two_adic_pcs.rs:627`). So the effective mask is
  `R_eff = Σ_k α^{o+k} r_k`.
- Let each `r_k` be uniform in `F_p[X]<n`. Then `R_eff` is uniform in `F[X]<n` if and
  only if the powers `{α^{o+k}}` span F over F_p.
- α^o is invertible, so this holds iff `1, α, …, α^7` are independent, i.e. iff α lies
  in no proper subfield.
- The largest proper subfield is F_{p^4}. The failure probability is therefore
  `p^4/p^8 = p^−4 ≈ 2^−123.6`.
- Plonky3 opens R at ζ (8 public values) and batches the DEEP quotient
  `Q = (R − R(ζ))/(X − ζ)`.
  - For uniform R, the map `R ↦ (R(ζ), Q)` is a bijection. So Q is uniform of degree
    < n − 1 = 2|H| − 1, and independent of R(ζ).
  - That is exactly the paper's mask degree bound `|H| + h − 1`, with h = |H|.
  - **This confirms round 3's internal argument.**

**The items zk-coverage §3 lists as open, re-assessed:**

| §3 item | Status proposed | Reason |
|---|---|---|
| 1. Many tables, mixed heights | **Closable by internal argument** [math; needs a second internal check] | See the argument below the table |
| 2. LogUp incompleteness (Appendix A) | **Quantified** [math]; stays statistical | The honest prover fails only if a challenge hits a pole `α_bus = fp(row)` of a row with nonzero multiplicity. (Rows with zero multiplicity get the placeholder denominator 1, `logup.rs:715-719`.) By the union bound, Pr ≤ N/|F|, with N the number of denominators (≤ about 2^28 [est]); that is ≤ 2^−219. The statistical distance between accepted and simulated transcripts is at most this |
| 3. Multi-phase traces | **Closable** [math] | Lemmas 1 and 5 hold for **any fixed** column polynomial, as long as its randomizer is fresh and independent. The permutation columns are committed through the same `commit` (interleaved random rows), with randomness independent of the challenges. Multi-phase adds only the incompleteness (item 2) and the terminals (blinded) |
| 4. R from base-field polynomials | **Quantified:** ≤ 2^−123.6 per height class | Above |
| 5. Preprocessed/periodic columns, per-table next points | **Closable** [math] | Public polynomials enter the constraint identity as known functions, so the step "the quotient is determined by the witness values at Q*" of Lemmas 3 and 5 still holds. Next points: each table has its own g_T and its own randomizers |
| 6. ζ not rejected from H ∪ D | **Negligible:** ≤ (|H|+|D|)/|F| ≲ 2^27/2^247.3 ≈ 2^−220 per table | The Galois orbit of ζ lies in H only if ζ does |
| 7. Plonky3 matches the paper | Stays **U**, narrowed | This review re-read `get_quotient_ldes` (Lagrange), `commit` (h = |H|), `open_inputs` (1 point per query) and R's ordering. That is not a verification |
| 8. Salted Merkle (4 salt elements ≈ 123.6 bits) | C | Hiding holds in the ROM up to about q·2^−123.6, for q hash queries per leaf guess |
| 9. HVZK and Fiat–Shamir | C | Standard (BCS16) |
| 10. Randomness | C, **refined** | In practice hiding is **computational**: every mask comes from ChaCha12 (`StdRng`) or ChaCha20, seeded with 256 bits. "Statistical" describes the IOP with ideal randomness, not the deployed prover. See N2 |
| 11. Our components | C | Terminal blinding: ≤ 2^−123.6 from the β-subfield event. The circuits are reviewed, not proven |

**Argument for item 1 (mixed heights).**
- Plonky3 rolls one batch polynomial per height class into FRI
  (`num_reduced[log_height]`). Every class contains at least one table, hence at least
  one independent R.
- Lemma 2 applies to each class. Given the class's input openings, its batch polynomial
  is uniform on an affine subspace, independently across classes.
- The whole FRI transcript (all rounds, all sibling openings) is a deterministic function
  of these polynomials and of public challenges.
- So a simulator that samples each class's batch polynomial uniformly from its subspace
  reproduces the distribution.
- The per-table witness openings are independent across tables: each table has its own
  randomizers, and its own translate g_T.

**Proposed text for zk-coverage.md §4** (the updated statement, for the docs owner to
place there):

> **Zero knowledge, as far as internal analysis supports it.** Assume:
> - (i) Poseidon2 is modelled as a random oracle for Fiat–Shamir and Merkle hashing;
> - (ii) the prover's ChaCha-based generators and their hedged seeds are
>   indistinguishable from random;
> - (iii) Plonky3 0.7.0 with the three patched crates implements the construction as
>   read (U).
>
> Then the honest-verifier IOP underlying a BS-ZK-2 proof is statistically
> zero-knowledge, with distance at most about `k·2^−123.6 + 2^−219 + T·2^−220`. Here:
> - k ≤ 2 + (the number of height classes) counts the subfield events: the FRI-mask α
>   per height class, and the LogUp β of the terminal blinding;
> - T is the number of tables.
>
> The compiled proof is zero-knowledge in the random-oracle model, up to that distance
> plus the salt-guessing term, and **computationally** so under (ii).
>
> This rests on internal arguments: the rows marked "closable" in §3, reviewed
> internally only. It is not a proof. Perfect zero knowledge is not claimed, and nothing
> here has been independently verified.

### 3.3 Does the proof length leak anything?

**Within a shape: no [math].** Two independent arguments:
1. **Length adds nothing to the proof.** Length is a deterministic function of (shape,
   Q). The query positions Q are a public function of the proof bytes, and any function
   of a proof reveals at most what the proof reveals. So length adds nothing to what ZK
   already covers.
2. **Q does not depend on the witness, even without ZK.** Under the ROM that soundness
   already assumes, Q is the challenger's output after grinding. It is uniform whatever
   the witness (privacy-review §3a.2), so the length distribution is identical for every
   witness.

**Across shapes:** the length reveals the shape (`n_fn` and the called functions'
budgets). The transaction states these publicly anyway.

**Residual metadata** (outside my scope; noted for 33 and 38): at the link level, the
~2.2 MB size identifies a PX upload and its origin (R8-18).

**What the P-5 evidence proves:** only the layout invariant (S9).
- The statistical tests are underpowered (§2.2), and argument 2 makes them unnecessary
  for privacy.
- What matters is that the invariant **stays true**. A Plonky3 change, a codec change
  or an optional field could make a non-authentication part witness-dependent.
- That is a regression risk. Exact assertions catch it better than permutation tests
  (§5, ZP-2 and ZP-3).

**A real length-related privacy issue (N1): the constant part identifies the prover
implementation.**
- The verifier does not pin the hidden widths: `NUM_RANDOM_CODEWORDS` per matrix, and
  R's hidden columns.
- So two wallets with different hiding settings produce proofs of different constant
  length. That partitions the anonymity set.

### 3.4 What must P-5 re-run on the new kernel?

**Why the constants are unknown.**
- The kernel and vault ELFs changed in `53d3b49`: the kernel from 21,148 to 15,360 B,
  the vault from 13,432 to 7,528 B.
- Program and Image table heights follow the program size, not the budgets.
- So the constant parts (1,811,565 B for transfers, 2,359,622 B for vault calls) are
  **[unknown]** for v3.
- The commit's note "shape heights unchanged" covers only the budgeted tables.

**What the re-run must cover** (the specification is ZP-2 in §5):
- every consensus shape: `n_fn` = 0, 1 **and 2** (the last never measured);
- exact assertions, with the constants pinned;
- the recorded identities (commit, program ids, circuit and parameter tags);
- the widest proof against `MAX_PROOF_BYTES`, in the same run (shared with 22).

### 3.5 Witness randomness

- **Correct:** the seeds are hedged and bound to the statement, sampling is uniform, and
  the proof and blinding streams use separate tags [src].
- **`CryptoRng` bound:** it sits at the API boundary, so the problem fixed by Plonky3
  #2260 does not arise [src].
- **The draw order depends on thread scheduling** (third_party README).
  - This is harmless for secrecy, but proof bytes cannot be reproduced from a seed.
  - So no golden-proof ZK regression test is possible; tests must check structure
    instead.
- **Not zeroized** [src `config.rs:117-156`]:
  - the two `StdRng` states inside `ProverConfig` outlive the proof in memory until it
    is dropped, and so does every mask;
  - they are never zeroized;
  - anyone who can read the prover's memory already has the witness, so this is
    Informational.
- **Tag reuse:** `ZK_PROVER_SEED` tags both the witness digest (`prove.rs:167`) and the
  seed derivation (`config.rs:137`).
  - The two inputs are structured differently, so the impact is negligible [est].
  - Informational; for 19.

### 3.6 Invariants that must never change

1. **The randomization bounds.**
   - `2·(EXTENSION_DEGREE·1 + NUM_QUERIES) ≤ 2^MIN_LOG_HEIGHT`, with h = |H|;
     and n_F + n_D ≤ h_p.
   - Treat {queries, extension degree, minimum height} as one parameter triple (R4
     §3.1).
2. **Terminal blinding.**
   - `BLIND_VALUES == EXTENSION_DEGREE`.
   - Every real proving path writes one fresh blinding message per table.
   - **Every** table is blinded, the Byte table included (N3).
3. **The FRI mask.** R is committed before ζ and α, and spans the extension (width ≥
   `EXTENSION_DEGREE`).
4. **Quotient randomization** uses the Lagrange decomposition, with `num_chunks > 1`.
5. **Length.** Field encoding is fixed-width, so proof length is a function of shape
   and Q. Consensus statements have fixed shapes.
6. **Prover randomness.** Seeds are hedged, the RNG must satisfy `CryptoRng`, and no
   production prover path is deterministic.
7. **Challenges.** Honest-verifier ZK relies on the verifier's randomness coming from
   Fiat–Shamir. Never accept verifier-chosen challenges from the network.

### 3.7 Literature and how established projects solve it

- **Randomizing outside H, with the right degree bound:** ePrint 2024/1037 compares the
  FFT, canonical and Lagrange decompositions. FFT needs a d-fold larger h. Plonky3 chose
  Lagrange, so BlackSilk inherits the cheaper bound.
- **The FRI mask:** the construction from Aurora/BSCR+19, reproduced as Protocol 2 of
  2024/1037, uses R over the extension field.
  - Plonky3 builds R from base-field columns, hence the α-subfield term quantified above.
  - Perfect ZK would need R sampled as a true extension polynomial and combined with
    fixed basis coefficients rather than powers of α.
  - That is a Plonky3 change (P3), not worth making for 2^−123.6.
- **Lookup and permutation incompleteness:** 2024/1037 Appendix A.
  - Perfect ZK needs the constraints muted at critical points.
  - The authors themselves recommend statistical ZK for combined LogUp arguments.
  - LogUp itself: Haböck, ePrint 2022/1530.
- **Compiling to a hash-based argument while keeping ZK:** BCS16 (salted Merkle, ROM).
- **Terminal publication:**
  - Plonky3 0.7 publishes the per-table sums in the clear; BlackSilk's blinding bus is
    its own construction.
  - I found no upstream equivalent in the 0.8 release notes.
  - 0.8's logUp* and multilinear lookups change the lookup layer, so the blinding must be
    re-reviewed on migration (24).
- **Multilinear/WHIR ZK:** the newer constructions restart the ZK analysis from zero
  (I1-A4), so they are not for this testnet:
  - the hiding WHIR in `p3-whir` 0.8;
  - VEIL, ePrint 2026/683;
  - the SoK, ePrint 2026/1367.

---

## 4. New findings

| ID | Title | Severity | Status | Location | Confidence |
|---|---|---|---|---|---|
| **N1** | The verifier does not pin the hiding widths, so the constant proof length fingerprints the prover implementation | Low (privacy; latent until a second prover exists) | Not implemented | `third_party/p3-fri/src/hiding_pcs.rs:449-484` (only nesting checked); `zk/src/params.rs:16-24` (documented as unpinned); `zk/src/lib.rs:314-342` (the canonical-form check has no width rule) | high (fact), medium (impact) |
| **N2** | The "statistical ZK" wording omits that the deployed prover's masks are PRG outputs: the practical guarantee is computational (ROM + ChaCha) | Low (claim accuracy) | Not implemented (docs) | `zk/src/config.rs:12-16, 117-151`; `docs/reviews/zk-coverage.md` §4; `assumptions.md` Z7, Z12 | high |
| **N3** | terminal-blinding.md C1 lists the **Byte** table as a table "whose real sum is public". It is not: its four multiplicity columns are witness-dependent main columns (the byte-usage histogram) | Low (doc error). No leak today, because the Byte table is blinded like every table. It becomes a leak if anyone "optimizes" by not blinding the "public-sum" tables | Not implemented (docs) | `docs/reviews/terminal-blinding.md` §3 C1; `zkvm/src/air/byte.rs:1-5, 45-58` | high |
| **N4** | `BLIND_VALUES = 8` is hard-coded, not tied to `params::EXTENSION_DEGREE` by a compile-time assertion | Low (hardening) | Not implemented | `zkvm/src/air/util.rs:31` | high |
| **N5** | Fail-open blinding (terminal-blinding §6a, Z3) is guarded only by a test on a toy program. There is no blinding test on the PX shapes (`n_fn` = 1, 2) and no runtime guard | Low | Partially implemented | `zkvm/src/prove.rs:179-197`; `zkvm/tests/blinding.rs:437` | high |
| **N6** | zk-coverage §3 items 1, 3, 4, 5 and 6 can be quantified or closed by argument (§3.2); the documents still list them as bare "O" | Informational (evidence upgrade) | Complete but requires further testing (a second internal check of the argument) | `docs/reviews/zk-coverage.md` §3; `assumptions.md` Z7 | medium–high |
| **N7** | The P-5 campaign cannot be compared with the current kernel: the constants are unknown after the ELF change, `n_fn = 2` was never measured, and the statistical part has low power (a minimum detectable effect of ≈ 3.6 KB) | Medium (evidence gap; P0 per autonomous session §6) | Not implemented | `docs/evidence/p5-2026-09-26b/`; `px/examples/proof_length_campaign.rs` | high |
| **N8** | The prover's RNG state is not zeroized | Informational | Accepted limitation | `zk/src/config.rs:117-156` | high |
| **N9** | Tag reuse: `ZK_PROVER_SEED` tags both the witness digest and the seed derivation | Informational | Accepted limitation | `zkvm/src/prove.rs:167-168`, `zk/src/config.rs:137` | high |

**Scenarios:**

**N1 (prover fingerprinting).**
- A second wallet (a fork, or a later BlackSilk release) uses `NUM_RANDOM_CODEWORDS = 2`.
- Its transfer proofs are shorter by a constant amount: 2 × 4 B × 108 queries per
  committed matrix, plus the matching salt and Merkle overhead.
- An observer groups PX transactions by their constant part and tells which software
  produced each. That splits an anonymity set that is already small (about 2,160 PX per
  day at most).
- **Fix:** a consensus narrowing rule.
  - Every hidden-opening vector must have exactly `NUM_RANDOM_CODEWORDS` entries per
    point, R's round included.
  - Honest proofs are unaffected.
  - It also bounds adversarial padding of the hidden columns, so
    `MAX_ADVERSARIAL_COLUMNS` no longer needs to account for them.

**N3 (the Byte table is not a public-sum table).**
- A future optimization, following the document, stops blinding the Image, Output and
  Byte tables.
- The Byte terminal then publishes `Σ m_i/(prefix − fp(i))`, a function of the witness's
  byte histogram.
- An observer can test hypotheses against it, exactly as in
  `an_observer_reads_the_input_from_an_unblinded_proof`.

**N5 (a proving path that skips blinding).**
- A refactor routes PX proving through `trace::build_multi` and `blacksilk_zk::prove`
  directly.
- The proofs verify and leak (ZK-F29 again).
- The toy-program test still passes, because it exercises `zkvm::prove::prove`.

---

## 5. Implementation plan for phase 2

**Identity impact:** none for every item except ZP-7, which is free at the v3 reset and
otherwise height-activated.

**Benchmarks:** none, except the ~5 h of machine time for ZP-2.

| # | Item | Files (ownership) | Visibility | Tests | Docs | Size | Prio |
|---|---|---|---|---|---|---|---|
| **ZP-1** | The updated conditional-ZK statement (details below the table) | `docs/reviews/zk-coverage.md`; `docs/reviews/terminal-blinding.md` (§3 C1); `docs/reviews/assumptions.md` (Z7, Z12); `docs/zkvm.md` (V4); `docs/zk.md` (R1, §808) | nothing | — | the files listed | S | **P0** |
| **ZP-2** | P-5 re-run on the frozen v3 kernel (specification below) | `px/examples/proof_length_campaign.rs` (extend); new `docs/evidence/p5-<date>/`; `docs/reviews/privacy-review.md` §3a; `docs/reviews/review-package.md`; `AUDIT.md` | nothing | the campaign's exact assertions | the files listed | M | **P0** (after the freeze) |
| **ZP-3** | Length-invariance unit test (cheap, CI-able; details below the table) | new `zk/tests/length_invariance.rs` | nothing | a property test (proptest over index sets) | privacy-review §3a (cite the test) | S | P1 |
| **ZP-4** | Tie `BLIND_VALUES` to the extension degree: `const _: () = assert!(BLIND_VALUES == blacksilk_zk::params::EXTENSION_DEGREE);` | `zkvm/src/air/util.rs` | nothing | compile-time | terminal-blinding §3 | S | P1 |
| **ZP-5** | Fail-closed blinding (details below the table) | `zkvm/src/prove.rs`, `zkvm/src/air/trace.rs` (shared with 23) | nothing | Regression: `prove_shaped` refuses a zero-blinded trace. Adapt the existing oracle tests | terminal-blinding §6a (mark done) | S–M | P1 |
| **ZP-6** | Blinding test on real PX shapes (details below the table) | new `px/tests/blinding.rs` | nothing | as described | terminal-blinding §3 | S | P1 |
| **ZP-7** | Pin the hiding widths (N1) as a canonical-form rule (details below the table) | `zk/src/lib.rs` (`check_canonical_form`; shared with **22**) | **CONSENSUS** (narrowing) | Negative: a proof with one extra or one missing hidden column per point is refused. Positive: honest proofs of every shape pass | zk.md proof rules; the D-1 normative spec | S | P1 if it rides the reset, else P2 |
| **ZP-8** | Assert eq. (16) at compile time next to eq. (17) (details below the table) | `zk/src/params.rs` (shared with **25**) | nothing | compile-time | zk-coverage §2 | S | P2 |
| **ZP-9** | Zeroize the `ProverConfig` RNGs on drop. `StdRng` cannot be zeroized, so keep only the seeds, in a zeroizing wrapper, and rebuild the generators from them | `zk/src/config.rs` | nothing | — | — | S | P3 |

**ZP-1 details.**
- Replace zk-coverage §4 with the text in §3.2.
- Re-grade §3 items 1, 3, 4, 5 and 6 as "argued/quantified (internal)", and add the
  written arguments as a new §6.
- Add the PRG/computational condition (N2) and the Byte-table correction (N3).
- Update Z7, Z12 and Z13 to match.

**ZP-3 details.**
- Commit two `ValMmcs` matrices of the same shape but different values.
- Open both at the same index sets: random sets, several heights, with duplicates.
- Assert that the `postcard` sizes of the openings are equal.
- Also check that the size is a function of the index set and the height alone.

**ZP-5 details.**
- (a) In `prove_shaped`, after `randomize_blinding`, refuse to prove if any table's
  blinding vector is all zero (probability 2^−247 for an honest prover).
- (b) Make `trace::build_multi` return a non-provable `UnblindedTraces` newtype.
  `randomize_blinding` becomes the only way to obtain provable traces; tests use an
  explicit `test_only_zero_blinded()`.

**ZP-6 details.**
- Run `every_table_of_a_real_proof_is_blinded_with_fresh_values` on a plain transfer
  (`n_fn = 0`) and on a vault call (`n_fn = 1`), with the kernel witness as the truth.
- It is heavy (2–4 proofs), so put it in the opt-in heavy suite.

**ZP-7 details.**
- The rule: in every round, for every matrix and every point, exactly
  `NUM_RANDOM_CODEWORDS` hidden values, R's round included.
- It needs the full consensus pipeline (brief §3). Honest proofs are unaffected, so it
  can ride the v3 reset or wait for a later activation height.

**ZP-8 details.**
- The assertion: `1 + NUM_QUERIES <= 1 << MIN_LOG_HEIGHT`. This is conservative:
  h_p = chunk height ≥ |H|.
- Add a comment naming the Lagrange decomposition as its premise.

### ZP-2: the P-5 re-run specification

**When:** after the protocol freeze, on the exact release-candidate commit. That means
kernel `0577e667…` and vault `666f7aab…`, or whatever ids the freeze pins. A run before
the freeze is superseded by any kernel change.

**Record:**
- the commit and `rustc -vV`;
- OS and CPU;
- `PARAMS_ID` and `CIRCUIT_ID`;
- the kernel and vault ids;
- the Plonky3 crate hashes (the `third_party` diff);
- the start and end times, and the command line.

**Shapes and classes** (interleaved, with fixed witness seeds):

| Shape | Classes | n per class |
|---|---|---|
| `n_fn = 0` | deposit, pay2, pay1, withdraw; add **pay-max** (amounts near the u64 maximum) and **pay-zero-change** (edge values) | 30 |
| `n_fn = 1` (vault) | lock, claim; add a class relevant to PX-F5 (a contract output with owner = 0) | 30 |
| `n_fn = 2` (**new**; e.g. two vault calls, or the widest registered pair) | two classes that differ in the functions' private inputs | 20 |

**Exact assertions** (these carry the result):
1. **The non-authentication length is identical within each shape.** Assert it, and
   **pin** it: first as a constant in the tool output, then in `privacy-review.md` and in
   a test.
2. **`degree_bits` is identical within each shape** and equals the `Statement::shape`
   heights.
3. **Every proof verifies**, including through the strict `decode_proof`, and its length
   is ≤ `MAX_PROOF_BYTES`. Report the maximum of the `n_fn = 2` classes as the
   "widest proof" figure for 22 / P0-3.
4. **The hidden-opening widths are as configured** (the N1 invariant), whether or not
   ZP-7 is adopted.
5. **Optional: the query set explains the authentication length.** This needs a
   transcript-replay helper, for example `zk::analysis::Observer` extended to the query
   phase. With it, recompute Q and the pruned frontier size and assert equality. Without
   it, ZP-3 covers the invariant at the MMCS level.

**Statistical part (a sanity check only):**
- Run the permutation tests as before, over all pairs within each shape, with a
  Bonferroni threshold.
- Report the minimum detectable effect next to the p-values.
- Do not present the p-values as evidence of independence.

**Acceptance:**
- Assertions 1–4 must hold.
- A failure of assertion 1 or 2 is a privacy bug (a witness-dependent layout) and blocks
  the testnet.
- A significant p-value while assertions 1 and 2 hold would point at the query-position
  mechanism. It must be investigated, not dismissed.

**Cost [est]:**
- about 170 transfer-class proofs at ~45 s;
- 60 vault proofs at ~55 s;
- 40 two-function proofs at ~70 s.

That is about 3.5 h single-process on the reference machine. Run it alone: the machine is
shared and has 16 GB of memory.

**Also re-run in the same window:** `zkvm/tests/blinding.rs` and ZP-6.

---

## 6. Dependencies and conflicts

| Workstream | Interaction |
|---|---|
| **22 px-proof-system** | ZP-7 extends `check_canonical_form`; 22 owns `zk/src/lib.rs`, so make it one coordinated change. The widest-proof measurement is shared with the `n_fn = 2` class of ZP-2 |
| **23 zkvm-bvm** | ZP-4 and ZP-5 touch `zkvm/src/air/util.rs`, `air/trace.rs` and `prove.rs`. Any AIR change (R4-07/08) must keep invariant 2 and redo ZP-6 |
| **24 plonky3-verifier-security** | A 0.8 migration invalidates §3.2 row 7. PR #2015 (fused hiding LDE) and the lookup rewrite (#1968, #2145) require re-deriving h, h_p and the terminal publication |
| **25 zk-soundness** | Shares `zk/src/params.rs` (ZP-8). Any parameter proposal must re-check eq. (17): queries > 120, a larger extension, or `MIN_LOG_HEIGHT` < 8 breaks ZK |
| **27 zk-performance** | The grinding, query and extension trade-offs (R4-09 options) are constrained by the parameter triple. SIMD does not affect ZK. A degree reduction (R4-07) changes only the chunk count, and eq. (16) still holds |
| **18 crypto-randomness** | The hedged prover seeds; the PRG condition (N2) |
| **19 hash-domain-separation** | N9 (tag reuse); `CIRCUIT_ID` and `PARAMS_ID` |
| **20 px-kernel** | Constant-work shape. A kernel change after the freeze invalidates ZP-2 |
| **33 / 38 network and wallet privacy** | Link-level size (R8-18) is theirs. N1 is a wallet-diversity concern |
| **41 / 42 fuzzing, mutation** | Their fuzz and mutation targets could include "a proof with extra hidden columns" (ZP-7) |
| **47 docs-spec-consistency** | The ZP-1 wording across zk.md, zkvm.md V4, assumptions.md and review-package.md |

---

## 7. Open questions for the coordinator

1. **ZP-7 (pinning the hiding widths).** Include it in the v3 rule set now (free at the
   reset, and narrowing only), or defer it to a height activation? It sits in 22's file.
2. **Grading of zk-coverage §3.** May items 1, 3 and 5 be re-graded "argued (internal),
   pending a second internal check", and items 4 and 6 "quantified"? Or should they stay
   "O" until a separate reviewer re-derives §3.2? (The same-model review caveat applies.)
3. **Scheduling ZP-2.** It must run on the frozen commit, alone on the machine, for about
   3.5–5 h. Who owns the freeze signal?
4. **P-5 framing.** Agree to present the statistical tests as a sanity check only (with
   the minimum detectable effect), and the exact assertions as the evidence?
5. **N2 wording.** Adopt "computational in practice (PRG); statistical for the
   underlying IOP" across the documents? This changes a sentence the owner has approved
   before.

---

## 8. Sources

- U. Haböck, Al Kindi. *A note on adding zero-knowledge to STARKs.* IACR ePrint
  2024/1037, version of 20 February 2025. https://eprint.iacr.org/2024/1037
  - eq. 3: the FFT bound;
  - eqs. 9–10: the canonical decomposition;
  - eqs. 13–17, Lemma 5, Theorem 8: the Lagrange decomposition;
  - Protocol 2 and Lemmas 1–2: the FRI mask;
  - Appendix A: permutation arguments.
- E. Ben-Sasson, A. Chiesa, M. Riabzev, N. Spooner, M. Virza, N. Ward. *Aurora:
  Transparent succinct arguments for R1CS.* EUROCRYPT 2019; ePrint 2018/828.
  https://eprint.iacr.org/2018/828
- E. Ben-Sasson, A. Chiesa, N. Spooner. *Interactive Oracle Proofs.* TCC 2016-B; ePrint
  2016/116. https://eprint.iacr.org/2016/116 (the BCS compiler; ZK with salted Merkle
  trees in the ROM)
- U. Haböck. *Multivariate lookups based on logarithmic derivatives* (LogUp). ePrint
  2022/1530. https://eprint.iacr.org/2022/1530
- U. Haböck. *A summary on the FRI low-degree test.* ePrint 2022/1216.
  https://eprint.iacr.org/2022/1216
- G. Arnon, A. Chiesa, G. Fenzi, E. Yogev. *WHIR.* ePrint 2024/1586.
  https://eprint.iacr.org/2024/1586
- *VEIL: Lightweight zero-knowledge for hash-based multilinear proof systems.* ePrint
  2026/683. https://eprint.iacr.org/2026/683
- *SoK: Hash-based polynomial commitments and low-degree tests.* ePrint 2026/1367.
  https://eprint.iacr.org/2026/1367
- Plonky3:
  - v0.8.0 release notes: https://github.com/Plonky3/Plonky3/releases/tag/v0.8.0
  - PR #2260, *require a cryptographic RNG for HVZK mask sampling* (merged 2026-09-20):
    https://github.com/Plonky3/Plonky3/pull/2260
  - PR #2015 (fused hiding LDE): https://github.com/Plonky3/Plonky3/pull/2015
  - PR #2145 (logUp*): https://github.com/Plonky3/Plonky3/pull/2145
  - 0.7.0 source in the local registry:
    - `p3-uni-stark/src/prover.rs:329` and `p3-batch-stark/src/prover.rs:469` ("only
      statistically ZK");
    - `p3-lookup/src/challenges.rs`, `logup.rs`;
    - `p3-monty-31/src/monty_31.rs:154`.
- `rand` 0.10, `StdRng` (ChaCha12): https://docs.rs/rand/0.10/rand/rngs/struct.StdRng.html
