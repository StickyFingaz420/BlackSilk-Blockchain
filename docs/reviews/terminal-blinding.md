# Terminal blinding (fix for ZK-F29) and the minimum table height (ZK-F30)

Status: **implemented and committed (design approved by the owner, 2026-09-26).
Internal work; no external audit. The ZK system as a whole is NOT claimed to be
security-complete.** Consensus-affecting: it changes the tables of every proof, so it
takes effect only with a testnet reset.

## 1. The problem

- Plonky3 0.7.0's batch prover publishes, for every table with lookups, the LogUp
  **terminal**: the sum over the table's rows of `count / (bus offset − fingerprint)`.
- The hiding PCS masks commitments and openings, not these values.
- An observer can replay the transcript to obtain the challenges, then compute the
  terminal each hypothesis about the witness would produce.
- Demonstrated end to end: `zkvm/tests/blinding.rs::an_observer_reads_the_input_from_an_unblinded_proof`
  reads a program's private input from its Program-table terminal. For the PX kernel,
  33 distinct execution profiles occur over 100 witnesses (`px/examples/execution_profile.rs`).

## 2. The construction (our circuit code only; Plonky3 is unchanged)

- **Every table** gets 9 extra main columns: a selector `s` and eight values
  `v0..v7`.
  - First row: `s = 1`. Every other row: `s = 0` and `v = 0`.
  - The first row **consumes** `(v0..v7)` once on a dedicated bus, `bvm/blind`.
- **A new last table, `Blind`**, has rows `(real, v0..v7)`:
  - `real` is boolean;
  - padding rows hold zeros;
  - each real row **provides** its values once.
- **The prover** writes fresh random values into each table's first row and the
  matching row of `Blind` (`trace::randomize_blinding`). The seed is BLAKE2b(tag,
  witness digest, 32 OS-random bytes), as for the proof's other randomness.
- **Minimum table height** raised from 2^6 to 2^8 (`zk::params::MIN_LOG_HEIGHT`),
  for ZK-F30.

Code: `zkvm/src/air/util.rs` (`blind_consume`, `blind_provide`), `zkvm/src/air/mod.rs`,
`zkvm/src/air/trace.rs`, `zkvm/src/prove.rs`, `zk/src/params.rs`.

## 3. Why it hides the terminals

**Notation.**
- `S_T`: table T's unblinded sum.
- `u_T = 1/(p_B − fp(v_T))`: T's blinding term, where `p_B` is the blinding bus's
  offset and `fp(v) = Σ_j v_j β^(7−j)`.
- Published: `S_T ± u_T` for every table T, and `Σ_T u_T` (with the opposite sign) as
  the `Blind` table's terminal.

**Guaranteed mathematically, given the stated conditions:**
1. **`fp` is a bijection from F^8 onto the extension field whenever `β` is outside
   every proper subfield.**
   - Then `1, β, …, β^7` are linearly independent over F.
   - The largest proper subfield has p^4 ≈ 2^124 elements, so a random `β`
     (sampled after the blinding values are committed, hence independent of them)
     falls in a proper subfield with probability about 2^−124.
2. **For uniform, independent `v_T`, `u_T` is uniform on the nonzero elements**
   (up to a 2^−248 exclusion): `x ↦ 1/(p_B − x)` is a bijection.
3. **Every table's published terminal is therefore independent of its `S_T`,**
   up to a statistical distance of about 2^−124 (dominated by the subfield event in
   point 1).
   - The whole published vector is uniform subject only to its sum being zero, which
     holds for every honest witness.
   - So an observer learns nothing about any individual `S_T`.

**Conditions (not proven here):**
- **C1:** the blinding values of every table **whose real sum depends on the
  witness** are uniform and unknown to the observer (the seed derivation, ChaCha20,
  and the OS RNG).
  - Corrected after internal review round 2 (Z1): the earlier wording said "never
    revealed", which is not true for every table.
  - For tables whose real sum is public (the Image, Output and Byte tables), an
    observer can compute the blinding term and invert it to recover the values.
  - That is harmless: the values are independent per table and carry no witness
    data.
- **C2:** the hiding PCS keeps the committed columns, the blinding columns included,
  hidden at the opened points. This is the remaining part of assumption Z7, and needs
  enough random rows for the number of openings. With the minimum height 2^8 (256
  random rows) against 108 queries plus 2 out-of-domain points, the counting argument
  of ZK-F30 is satisfied with margin. This is a counting argument, not a proof about
  Plonky3's hiding PCS.
  - **It covers the per-column openings only** (internal review round 2, Z2).
  - The FRI commit-phase openings are masked with `NUM_RANDOM_CODEWORDS = 4`
    base-field random codewords combined with extension-field powers: a
    4-dimensional base-field subspace of the degree-8 extension. That is the same
    pattern §3 "Width" rejects for the blinding values.
  - Whether this suffices needs a simulator argument (cf. ePrint 2024/1037), which
    the project has not made.
  - **OPEN** (assumptions.md Z7). A remedy would be 8 or more random codewords; that
    changes proofs, so it is an owner decision.
- **Width.** With only 4 random values, `fp` would reach a 4-dimensional subspace. An
  observer could then test hypotheses by solving a linear system. Eight values (the
  extension degree) are needed, and used.

**What the tests show (corrected after internal review round 2, T1):**
- **The leak without blinding:**
  `an_observer_reads_the_input_from_an_unblinded_proof`. The observer's transcript
  replay reproduces all 13 published terminals exactly and reads the input.
- **Blinding is applied, and freshly, on the real proving path:**
  - `every_table_of_a_real_proof_is_blinded_with_fresh_values`: every table's
    blinding values, recovered from real proofs, are nonzero and differ between
    proofs;
  - `the_same_input_proven_twice_publishes_unrelated_program_terminals`;
  - `blinding_values_are_fresh_nonzero_and_keep_the_bus_balanced`.
- **Not evidence of hiding:**
  - `a_blinded_proof_matches_no_hypothesis_directly` only shows the values are
    nonzero.
  - Its reconstruction of blinding values for every hypothesis **always** succeeds,
    blinded or not, because `fp` is a bijection. The earlier version of this note
    wrongly presented it as empirical evidence.
- **Hiding therefore rests on the argument above (points 1 to 3) and on C1 and C2,
  not on tests.** A statistical test of hiding would test the random generator, not
  the construction.

## 4. Why it is sound

**Guaranteed, under LogUp soundness (C, U):**
1. **Bus separation.**
   - Plonky3 separates buses by an additive offset one power of `β` above every
     payload term (`p3-lookup` `Challenges`), sampled after the main commitment.
   - A message on `bvm/blind` and a message on any other bus have different
     fingerprints as polynomials in `α, β`.
   - So the global terminal sum can vanish only if each bus balances on its own,
     except at roots of a nonzero rational function: probability about
     (degree / |EF|), negligible.
   - Blinding values cannot cancel, or stand in for, any real message.
2. **Blinding values are committed before the challenges.** They are main-trace
   columns, so the prover cannot adapt them to `α, β`.
3. **No new freedom for real buses.**
   - The blinding columns appear only on the blinding bus.
   - The selector pattern admits exactly one consumption per table (first row).
   - Every other blinding cell is constrained to zero, in the Blind table's padding
     too.
   - The multiplicity bound (`Σ weight·height < p`) holds, because every blinding
     count is boolean.

**Tested:**

| Test | Checks |
|---|---|
| `a_missing_blinding_message_is_rejected` | a consumed message has no provision |
| `a_duplicated_blinding_message_is_rejected` | an extra provision |
| `an_altered_blinding_value_on_either_side_is_rejected` | one side's value changed |
| `the_selector_admits_exactly_one_message_per_table` | a second consumption (even with a matching provision); none on the first row |
| `blinding_cannot_hide_an_unbalanced_real_bus` | A **pure** bus imbalance (an ALU row with a different but internally consistent addition; the oracle confirms only bus balances fail), with random blinding over 3 seeds. In release builds a proof **is produced** and the verifier rejects it with the terminal-sum error. Debug builds cannot produce it (Plonky3's debug checker), and the test says so explicitly |
| `alu.rs::a_blinding_bus_message_cannot_stand_in_for_an_alu_result` | A false ALU claim plus well-formed (8-element) extra provisions on the blinding bus. Only bus balances fail; in release a proof is produced and rejected by the terminal sum |
| `the_blind_table_rejects_non_boolean_rows_and_dirty_padding` | `real = 2`; a nonzero value in a padding row |

**Earlier versions of these two tests were vacuous** (internal review round 2, T2 and
T3):
- the first broke a local ALU constraint rather than a bus;
- the second used a 13-element tuple on an 8-wide bus, which Plonky3 refuses with a
  panic before any proof exists.

Neither ever reached the verifier. Both are corrected as above.

**Mutation tests** now include every blinding column; every mutation is caught.

## 5. Consensus and determinism

- **The verifier's statement is a deterministic function of public data.** The tables
  list (with `Blind` last), the shapes (`Blind` at the minimum height) and the
  constraints are the same for every node. Nothing here depends on build mode
  (`cfg(debug_assertions)`) or on the platform.
- **Verification is deterministic.** Blinding values influence only the prover's
  commitments; verification never reads them in the clear.
- **Proofs are randomized**, as before.
- **Consensus impact:**
  - every proof gains a 13th table (or more, with functions);
  - small tables are taller;
  - old proofs no longer verify and new ones do not verify under the old rules.

  This is a consensus change and requires the planned testnet reset (owner decision).

## 6. Costs

See §8 (measured before and after on the same machine).

## 6a. Fail-open risk (internal review round 2, Z3)

- All-zero blinding values satisfy every constraint, and `trace::build` /
  `build_multi` produce zero-blinded traces (for the oracle and tests). A proving
  path that skipped `randomize_blinding` would produce valid proofs that leak again,
  and no verifier could tell.
- Today only `prove::prove_shaped` calls the prover, and it randomizes.
- The guard is a test: `every_table_of_a_real_proof_is_blinded_with_fresh_values`
  fails if the real proving path leaves any table unblinded.
- **Hardening option, not done:** make the trace builder take the RNG, so that a
  zero-blinded trace cannot be proven by accident.

## 6b. Envelope (internal review round 2, S1 and S2)

- **S1:** the Blind table's height limit is now the minimum height (`prove::limits`),
  so an unshaped proof cannot claim a 2^22-row Blind table.
- **S2:** the widest PX statement (kernel plus two functions, 23 tables) commits
  4,984 columns, counted conservatively. That is above the former analysis envelope
  of 4,000, and about 4,560 of them predate blinding.
  - `MAX_COMMITTED_COLUMNS` is raised to 6,000.
  - The security calculator still gives 123 bits (Johnson) and 105 bits (unique
    decoding) across the whole envelope
    (`zk::params::tests::every_shape_within_limits_meets_both_security_targets`), and
    for this shape (`zkvm/tests/multi.rs::the_widest_multi_execution_shape_stays_in_the_envelope`).
  - It is an analysis bound; verifiers do not enforce it.

## 7. What this does not address

- The rest of Z7 (the hiding PCS's zero knowledge as configured) is not proven by the
  project.
- Other leaks through proof size (P-5) and public data (P-8) are separate.
- The Blind table's own openings are protected only as well as C2 holds.

## 8. Measurements (2026-09-26)

**Setup:**
- `cargo run --release -p blacksilk-px --example proof_bench -- 3`;
- Windows 10, 8 logical CPUs, otherwise idle;
- "before" = commit `76cfa7a` (unblinded), built in a separate worktree;
- "after" = the uncommitted change;
- 3 proofs per row, so timings are indicative only.

| | Before | After | Change |
|---|---|---|---|
| Transfer: size | 2,034,920 B | 2,179,111 B | +7.1% |
| Transfer: prove | 42.0 s | 45.7 s | +8.8% |
| Transfer: verify | 0.195 s | 0.209 s | +7% |
| Vault LOCK: size | 2,483,894 B | 2,689,061 B | +8.3% |
| Vault LOCK: prove | 50.4 s | 53.8 s | +6.7% |
| Vault LOCK: verify | 0.234 s | 0.293 s | +25% (small sample; noisy) |
| Tables per transfer | 12 | 13 | +Blind |
| Opened main columns | 834 | 951 | +9 per table, +9 for Blind |
| Permutation columns (extension) | 832 | 944 | +8 per table, +16 for Blind |
| Smallest heights | Output 2^6, Poseidon2 2^7 | 2^8 | minimum raised |

**Consequences:**
- Blocks hold about 3.8 transfer proofs instead of about 4.1 (8 MiB PX budget).
- The P-5 constants of the unblinded layout (non-authentication parts of 1,663,016 B
  and 2,148,177 B) are superseded.
  - The campaign was re-run on this layout on 2026-09-26
    (docs/evidence/p5-2026-09-26/): 1,811,565 B and 2,359,622 B, constant per shape.
  - No significant class dependence (minimum p = 0.071 over 14 tests).
- Both proofs remain far below the 4 MiB proof limit for the measured shapes. The
  two-function worst case is not measured.

**Tests** (same machine):
- `zkvm/tests/blinding.rs`: 9 passed.
- `zkvm/tests/alu.rs`: 6 passed, including the stand-in attack.
- All zkvm and zk suites pass; the mutation tests now cover every blinding column.
- **Full workspace: 419 passed, 0 failed, 2 ignored (opt-in), 2,550 s.**
