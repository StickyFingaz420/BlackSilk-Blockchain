# Zero knowledge of PX proofs: what is covered, and what remains assumed

Status: **internal analysis, 2026-09-26, parameter set BS-ZK-2. No external audit.**

- The target is **statistical zero knowledge**, not perfect zero knowledge (§4).
- This document does **not** claim that the ZK system is proven or security-complete.
- It records which ingredients follow a published construction (and whether our
  configuration meets that construction's stated conditions), which rest on our own
  arguments, and which remain open.

**Reference:** U. Haböck and Al Kindi, *A note on adding zero-knowledge to STARKs*,
ePrint 2024/1037 (version of 20 February 2025). Plonky3's `HidingFriPcs` cites it.

## 1. The published construction

The paper proves honest-verifier zero knowledge for a small-field STARK: **one AIR,
one trace length**, FRI as the polynomial commitment, and the Lagrange quotient
decomposition (§4.2, Lemma 5, Theorem 8). Honest-verifier zero knowledge suffices for
the non-interactive proof, per the paper. It needs three things.

1. **Witness randomization.**
   - Each witness column is randomized with `h` degrees of freedom, and each quotient
     chunk with `h_p`, such that `n_F + n_D ≤ h_p` (eq. 16) and
     `2·(e·n_F + n_D) ≤ h ≤ |H|` (eq. 17).
   - The terms:
     - `e` is the extension degree;
     - `n_F` is the number of out-of-domain points; the factor 2 accounts for their
       translates by `g`;
     - `n_D` is the number of FRI queries;
     - `|H|` is the trace length.
2. **A FRI mask `R`** (Protocol 2, Lemma 2), uniformly random over the extension field
   and committed before the batching challenge. It makes the rest of the FRI
   transcript independent of the witness.
3. **Permutation and lookup arguments** are treated separately (Appendix A). They are
   **not complete**, and "a single successful run reveals information on the
   witness". In most cases this is "not an obstacle for **statistical**
   zero-knowledge"; perfect zero knowledge needs further modifications.

## 2. How BS-ZK-2 relates to it

| Ingredient | In BlackSilk (BS-ZK-2) | Status | Checked by |
|---|---|---|---|
| Witness randomization, eq. (17) | e = 8, n_F = 1 (one ζ, opened at ζ and ζ·g), n_D = 108: **2·(8 + 108) = 232**. Plonky3 interleaves one random row per trace row, so `h = |H|`. **Minimum table height 256** | **Condition met for every table, with a margin of 24.** The former minimum of 64 (and the former 128-row tables) did not meet it (ZK-F30) | `const` assertion in `zk/src/params.rs`, every build; the minimum height is enforced by prover and verifier (`zk/src/lib.rs`) |
| Quotient randomization, eq. (16) and eqs. 13–14 | Plonky3's `get_quotient_ldes` follows §4.2 (chunk randomizers `v_{H_i}·t_i`, the last chunk compensating); `h_p` equals the chunk height `|H| ≥ 256 ≥ 109` | Condition met (read in source, internal review round 3) | Source; the chunk count depends on `get_log_num_quotient_chunks` (U) |
| FRI mask `R` | Plonky3 commits a **separate randomization polynomial per table** (`get_opt_randomization_poly_commitment`) with `NUM_RANDOM_CODEWORDS + EXTENSION_DEGREE` = 12 base-field columns, at the table's height. The first 8 dimensions make `R` span the extension field | Present for every table. Upstream calls this construction **"only statistically ZK"** (R is built from base-field polynomials) | The **verifier** rejects a missing `R` or a public `R` opening other than 8 wide, and checks `R` on each table's extended trace domain (its height). Test `zkvm/tests/vm.rs::every_table_commits_a_full_extension_randomization_polynomial`: in a real proof, one `R` per table, 12 columns wide at every query (the hidden columns are not pinned by the verifier). The vendored `p3-fri` test `randomization_polynomial_spans_the_extension_at_each_table_height` checks `get_opt_randomization_poly_commitment` under upstream's test configuration (2 codewords, degree-4 extension); it runs only in the manual upstream checkout (third_party/README.md), not in our suite or CI |
| Per-matrix codewords (`NUM_RANDOM_CODEWORDS` = 4) | Extra random columns in every committed matrix | **Additional masking, not the paper's `R`** (§5) | — |
| LogUp terminals | Published by Plonky3, not treated by the paper. **Our terminal blinding** (terminal-blinding.md) | Covered by our own argument (C), about 2^−124 | constraints and tests in `zkvm` |

The tests listed are **additional safety checks**: they confirm that the mechanisms
are present in real proofs. They do not replace the argument.

## 3. Where the theorem does not directly apply (open)

These are the limits of carrying the paper's result over to our system. Each is
**open** (O) unless marked otherwise.

1. **Many tables, mixed heights.** The theorem covers one AIR with one trace length.
   We batch 13 to 23 tables of different heights, which Plonky3's FRI folds in at
   different rounds, each height with its own `R`. The conditions hold per table; that
   the composition keeps the transcript independent of the witness is not proven.
2. **LogUp (Appendix A).** Our tables communicate through LogUp buses. Besides the
   terminals (which we blind), the incompleteness of such arguments leaks a little in
   every accepted proof; the paper expects this to allow only **statistical** zero
   knowledge.
   - What an accepted proof reveals is that the challenges avoid the witness-dependent
     poles of the LogUp fractions.
   - For a bus with N terms this event has probability at most about N/|F|, i.e.
     about 2^−224 for N up to 2^23 over the 247-bit field.
   - This is our unverified estimate (U), not a proof.
3. **Multi-phase traces.** The LogUp permutation columns are committed after the
   lookup challenges (a second trace phase). The paper's lemmas cover a single-phase
   witness.
4. **`R` from base-field polynomials** is statistically, not perfectly, uniform
   (upstream's own note).
5. **Preprocessed and periodic columns and per-table next points** are outside the
   paper's model.
6. **The out-of-domain point is not rejected from `H ∪ D`**, as the paper assumes.
   The probability is negligible, but it is a gap in the stated hypothesis.
7. **Plonky3 matches the paper's protocols (U).** We read `HidingFriPcs::commit`,
   `get_quotient_ldes`, `get_opt_randomization_poly_commitment` and
   `TwoAdicFriPcs::open`; that is not a verification.
   - One known deviation: Protocol 2 adds `R` itself to the batch. Plonky3 instead
     opens `R` at ζ (8 public values) and adds `R`'s DEEP quotient `(R(X) − R(ζ))/(X − ζ)`.
   - Round 3 argued that this quotient is uniform and independent of `R(ζ)`.
   - That argument is internal, not the paper's.
8. **Salted Merkle commitments** (4 salt elements, about 124 bits) hide unopened rows
   (C).
9. **Honest verifier and Fiat–Shamir:** standard, assumed (C).
10. **Randomness:** the prover's hedged seeds and the blinding seed (Z12) (C).
11. **Our components:**
    - the terminal blinding: our argument, internally reviewed twice;
    - the zkVM circuits: internally reviewed, not proven.

## 4. What can be said

- **Statistical zero knowledge, conditionally.** It holds if the items of §3 hold. The
  per-table randomization and masking conditions of the published construction are
  met and checked in every build or by tests.
- **Not claimed:**
  - perfect zero knowledge;
  - that Theorem 8 covers this system as a whole;
  - that the ZK system is proven, complete or independently audited
    (review-status.md).
- These items are tracked in assumptions.md (Z7, Z11–Z13).

## 5. Correction of an earlier analysis (2026-09-26)

- **What was wrong.** Internal review round 2 (finding Z2) and the author's follow-up
  analysis held that the FRI mask consisted of the `NUM_RANDOM_CODEWORDS` per-matrix
  columns. With 4 of them it would have spanned only half of the degree-8 extension.
  On that premise the owner approved 8 codewords (BS-ZK-3), and 8 were implemented
  and measured (about +10–13% in size, time and memory).
- **How it was found.** Internal review round 3 showed that Plonky3 builds the mask
  `R` from a separate polynomial with `EXTENSION_DEGREE` extra columns. BS-ZK-2's mask
  therefore already spanned the extension. The author verified this in the source.
- **Outcome.** The change was reverted before any commit (owner decision: Option A).
  Z2 is withdrawn (internal-review-log.md).
