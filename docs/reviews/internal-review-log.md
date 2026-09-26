# Internal review log

Status: **internal work only. No external audit or independent review has taken place**
(review-status.md).

**How each round was done.** Each review pass was run by a fresh-context review agent
that was given only:
- the code;
- the specifications;
- the pass's objectives.

It was not given the author's reasoning. The author then **verified** each finding
against the source, or by a test or measurement, before accepting it. The
"Verified" column says how.

**Limitation (review-status.md §3):**
- The review agents and the implementing agent are the same underlying model, so
  their blind spots may be correlated.
- These passes are internal review, not an external audit.

## Round 1 (2026-09-25/26)

| Component | Passes | Reviewer | Report |
|---|---|---|---|
| ZK configuration: Plonky3 0.7.0 hiding mode, BS-ZK-2, the three patches | implementation, adversarial, privacy (ZK), patch diff, failure | fresh-context agent | summarized below |
| PX kernel, function binding, PX consensus, reorganization | implementation, adversarial, consensus, reorganization, failure, privacy | fresh-context agent | summarized below |
| BVM-1 circuits (all AIR tables, buses, memory, control, Poseidon2) | adversarial soundness (under-constraint search) | fresh-context agent | summarized below |
| Wallet (v1 and PX), including recovery | failure and recovery, privacy, adversarial node, reorganization, implementation | fresh-context agent | summarized below |

### Critical and high findings

| # | Finding | Verified by the author | Status |
|---|---|---|---|
| **ZK-F29** | **Proofs are not zero-knowledge as configured: the per-table LogUp terminals are published unblinded.** In `p3-batch-stark` 0.7.0 each table's terminal is computed from the real trace rows and public challenges (`prover.rs:249-259`), published in `BatchProof::lookup_terminals` and absorbed into the transcript. The hiding PCS masks commitments and openings, but not these values; `p3-lookup` has no zero-knowledge handling. The Program table's terminal depends only on the per-instruction execution counts. | **Yes.** Source: read `prover.rs` and searched `p3-lookup` for ZK handling (none). **Measured:** `px/examples/execution_profile.rs` ran the kernel on 100 witnesses. It produced **33 distinct execution-count vectors**. `pay2` (two real inputs) never shares a profile with `pay1` (one real input and a dummy), and the profiles vary within classes with amounts and keys. So a proof reveals at least whether a private payment spends one or two real records, and some amount-dependent information. | **Fixed in code** (R12, terminal blinding; reviewed in rounds 2–4). Originally OPEN, critical |
| **ZK-F30** | **Small tables may be opened at more points than their hiding randomness covers.** A table of h rows gets h random rows; the verifier sees each column at up to 108 query points plus two out-of-domain points. With h = 64 (`MIN_LOG_HEIGHT = 6`), about 104–110 openings exceed the 64 random degrees of freedom, so linear relations on witness values leak. **Correction (2026-09-26):** the Poseidon2 table is shared by all executions of a proof, so the vault's budget does not create a 64-row table. In the measured transfer layout the smallest witness table was Poseidon2 at 128 rows (about 110 openings: a margin of 18, below the counting argument's comfort). **Correction (round 3):** that count was wrong. The bound is 2·(e·n_F + n_D) = 232 (ePrint 2024/1037, eq. 17), which a 128-row table does not meet; the minimum height 256 meets it (Z13), and Output (64 rows) holds public data. Budgets below 128 (for example small registered functions) could still produce 64-row witness tables. | **Partly.** The vault budget and the minimum height were confirmed in the source (`px/src/vault.rs:54`, `zk/src/params.rs:66`). The counting argument (C) is the standard one, but it has not been checked against a written Plonky3 zero-knowledge theorem, and no test demonstrates extraction. | **Fixed in code** (R12: minimum height 2^8; 232 ≤ 256, Z13). Originally OPEN, high |
| W-F1 | "Stored before sending" existed only in memory: a crash during the up-to-120 s submission lost the reservation, the stored transaction, the rings and a vault opening | Yes (source) | **Fixed.** `Wallet::set_autosave`: the wallet file is saved before the transaction is handed to the node. Test `the_wallet_is_saved_before_a_transaction_leaves_it` reads the file at submission time |
| W-F2 | **Ring-member queries excluded the real input**, so the node could identify it as the one ring member never requested. This predates this week's work. Retries would also have singled it out by intersection | Yes (source) | **Fixed.** One `/outputs` request per input, containing the real output, the stored members and a pool of about 60 candidates, shuffled; decoys are chosen locally. Test `ring_queries_never_single_out_the_real_input` |
| W-F3 | A node behind the wallet (or one lying about its height) made it drop stored transactions and rings | Yes (source) | **Fixed.** Inputs that are not currently visible do not count as buried; rings are kept until the spend is buried beyond the reorganization window; a node still synchronizing is refused. Test `a_node_behind_the_wallet_does_not_make_it_forget_its_transactions` |

### Medium findings

| # | Finding | Verified | Status |
|---|---|---|---|
| W-F4 | A reorganization deeper than the 720 kept block ids was taken for a fresh wallet: no rescan, stale outputs | Yes (source); the new test fails on the old logic | **Fixed.** Test `a_reorganization_deeper_than_the_kept_window_rescans` |
| W-F5 | A refused submission dropped its rings; a lying node could force fresh rings | Yes | **Fixed.** Rings are always kept. Test `a_refused_transaction_still_pins_its_rings` |
| W-F6 | Blocks from the node were not checked to extend the previous block | Yes | **Fixed** (prev-id linkage). **Open:** the wallet does not check proof of work; it trusts its node for that (documented) |
| W-F7 | A restore from the seed scans only account 0 (and 50 addresses ahead), and 20 PX addresses ahead | Yes (source) | **Open.** Documented; a restore option for more accounts is planned |
| W-F8 | Two processes on one wallet file could overwrite each other or corrupt the file | Yes | **Fixed.** Exclusive `<wallet>.lock` for the whole command; a per-process temporary file |
| PX-F1 | All block bodies stay in memory forever; cheap PX deploys (about 8 MiB per block) can grow a node's memory by gigabytes per day | Yes (source: `chain/src/manager.rs` `bodies`) | **Open.** A node change (not consensus): keep bodies on disk only |
| PX-F4 | A function fixes an output's owner, contract, value and data, but the caller picks its `rcm` and writes its ciphertext. A third-party payout or shared contract state can be made unopenable | Yes (source: `px-core/src/kernel.rs`) | **Open (design).** Letting functions fix `rcm` changes the kernel (consensus; owner decision). Otherwise it is documented as a trust assumption of contracts |
| ZK-F3 | Reusing a `VerifierConfig` rejects valid proofs, because verification draws salts from the config's RNG, contrary to its documentation | Not yet reproduced | **Open** (latent; today every verification uses a fresh config) |
| ZK-F4 | Every verification recomputes the preprocessed commitments (the 2^16-row byte table and more) before it can reject: a denial-of-service cost | Not measured | **Open** |

### Low and informational (selection)

- **zkVM (the circuit review found no critical, high or medium soundness issue):**
  - F1: `MAX_OUTPUT_WORDS` is not enforced by the verifier. Harmless today, because PX pins the output length.
  - F3: the verifier relies on `Program::validate` invariants it does not re-check.
  - F4: the periodic-repetition argument (sound, but not written down or tested).
- **PX:**
  - F5: contract outputs are not forced to have `owner = 0` (a kernel change);
  - F6: reorganizations drop dependent PX transactions;
  - F2, F3: undo records and proof re-verification on restart and reorganization;
  - F7–F11: verifier cost, a full tree, duplicate program ids, precheck, panic containment.
- **ZK:**
  - F5: the prover chooses how many random codewords to use (malleability);
  - F6: the calculator does not cover the real PX multi-execution shapes (the unique-decoding bits do not depend on shape);
  - F7–F10: panic containment, decoder amplification, documentation mismatches (BabyBear^5 vs ^8, 128 vs 123 bits, 130–230 KB vs 2 MB), the zero-statement API.
- **Wallet:**
  - F10: spoofed acceptance; wording is now "submitted";
  - F11: a malformed distribution panicked the decoy selector. **Fixed:** it is now an error; tests added;
  - F12: an `Invalid` verdict can be transient;
  - F13: `first_output` is trusted;
  - F14: `clear-pending` deleted contract-record openings. **Fixed;**
  - F15: the restore height is taken from the node;
  - F16: wrong error message. **Fixed.**

## Round 2 (2026-09-26): terminal blinding (commit dfa82bf)

**Reviewer:** a fresh-context agent. It had the code and the design, but not the
author's test results. **No soundness break and no gap in the terminal hiding were
found.** Findings, each verified by the author:

| # | Finding | Verified | Status |
|---|---|---|---|
| T1 (medium) | The "consistent with every hypothesis" test succeeds for any published value, unblinded included (`fp` is a bijection): it is not evidence of hiding | Yes (algebra) | **Fixed in the docs and the test name.** Hiding rests on the argument; new test `every_table_of_a_real_proof_is_blinded_with_fresh_values` checks that blinding is applied on the real proving path |
| T2 (medium) | The unbalanced-bus test broke a local ALU constraint, and in debug builds never produced a proof | Yes | **Fixed.** A pure bus imbalance (the oracle confirms only bus balances fail); in release a proof is produced and rejected by the terminal-sum check |
| T3 (medium) | The stand-in test used a 13-element tuple on the 8-wide blinding bus; Plonky3 panics before proving, so the proof check never ran | Yes | **Fixed.** Well-formed 8-element provisions; a proof is produced and rejected |
| T4, T5 (low) | Only the Program table's terminal was checked; no tests for `real = 2` or dirty padding in the Blind table | Yes | **Fixed.** Tests added |
| S1 (low) | The Blind table's height limit was 2^22 in unshaped proofs | Yes | **Fixed.** Limited to the minimum height |
| S2 (medium) | The widest PX statement commits 4,984 columns, beyond the 4,000-column analysis envelope; about 4,560 predate blinding | **Measured** | **Fixed.** Envelope raised to 6,000; the security bits are unchanged (123/105); new envelope test for 3 executions. (Round 4: 4,999 measured) |
| Z1 (info) | The note's condition "blinding values never revealed" is false for tables with public sums (harmless) | Yes | **Fixed** (the condition is restated) |
| ~~Z2 (medium)~~ (a review finding; not assumption Z2 of assumptions.md) | Plonky3's FRI mask used 4 base-field random codewords: a 4-dimensional subspace of the degree-8 extension. The published construction (ePrint 2024/1037, Lemma 2) needs a mask uniform over the extension | **Accepted in error.** The author checked the paper and the per-matrix codewords, but not how Plonky3 builds the mask | **Withdrawn in round 3: not established, and contradicted by the source.** The mask is a separate polynomial `R` with `EXTENSION_DEGREE` extra columns per table. The change made for it (8 codewords, BS-ZK-3) was reverted before any commit. See round 3 |
| Z3 (low) | Fail-open: zero blinding satisfies every constraint; a proving path that skipped randomization would leak | Yes | **Mitigated by a test**; making the builder take the RNG is a hardening option |
| Z4 (low) | The new domain tag was missing from the tag-uniqueness list | Yes | **Fixed** |
| Z5 (info) | The blinding RNG state is not zeroized | Yes | Accepted (the values are in the traces anyway) |

## Round 3 (2026-09-26): the BS-ZK-3 change, its assertions, test and ZK coverage docs

**Scope:**
- the uncommitted BS-ZK-3 change (8 random codewords), made to fix Z2;
- its `const` assertions and new test;
- the new zk-coverage.md.

**Reviewer:** a fresh-context agent. It had the code, the paper (ePrint 2024/1037) and
the Plonky3 sources.

**Main result: an analysis error by the author.**
- **The Z2 premise was wrong.**
  - Plonky3 0.7 builds the paper's mask `R` from a separate randomization polynomial:
    one per table, committed before ζ, with `NUM_RANDOM_CODEWORDS + EXTENSION_DEGREE`
    base-field columns.
  - FRI batches `R` with α-powers into every reduced opening at its height, so `R`
    already spans the whole extension (statistically).
  - The 4 per-matrix codewords are additional masking, not `R`.
- **How the author went wrong.** The author accepted Z2 after checking the paper and
  the per-matrix codewords, but never traced how the mask is actually constructed.
  The author then presented that premise to the owner as established. The owner
  approved 8 codewords on it, and the change was implemented and measured (about
  +10–13% proof size, proving time and memory).
- **The author verified round 3's reading in the source:**
  - `p3-batch-stark` `prover.rs:462-478`;
  - `hiding_pcs.rs` (`get_opt_randomization_poly_commitment`);
  - `two_adic_pcs.rs:595-650`;
  - the verifier's check of `R`'s opening width (`verifier/mod.rs:516-524`).
- **Owner decision (Option A):**
  - revert to 4 codewords and parameter set BS-ZK-2;
  - replace the checks with checks of `R` itself;
  - describe the result as statistical zero knowledge.

**Lesson.** A finding about a third-party mechanism is verified only once the mechanism
itself has been traced in the source, not the parameter that appears to control it.
The earlier rows' "Verified" column records what was actually checked.

| # | Finding | Verified | Status |
|---|---|---|---|
| R3-1 (high, rationale) | Z2's premise is contradicted by the source; BS-ZK-2's mask already spans the extension | Yes (source) | **Z2 withdrawn; change reverted** (Option A) |
| R3-2 (medium) | The assertion `NUM_RANDOM_CODEWORDS >= EXTENSION_DEGREE` checks the wrong object; nothing of ours checks `R` | Yes | **Fixed.** Assertion removed. The verifier already checks `R`'s presence, public width and height (round 4). New test: in a real proof every table commits an `R` 12 columns wide at every query (`zkvm/tests/vm.rs`, strengthened in round 4). A vendored `p3-fri` test (upstream's configuration; run only in the manual upstream checkout) |
| R3-3 (medium) | The new codeword test was a tautology (the PCS drains exactly that many values by construction) | Yes | **Fixed.** Test removed, replaced as in R3-2 |
| R3-4 (medium) | zk-coverage.md and Z7 claimed Theorem 8's hypotheses were met, and framed the result as perfect HVZK. Theorem 8 covers one single-phase AIR with one trace length; Appendix A says lookup arguments leak and allow only statistical ZK | Yes (paper) | **Fixed.** Rewritten as statistical and conditional, with the limits listed |
| R3-5 (medium) | Open items missing: upstream's "only statistically ZK" note for `R`; the Appendix A leakage; ζ not rejected from H ∪ D; the dependence on `get_log_num_quotient_chunks`; multi-phase traces | Yes | **Documented** (zk-coverage.md §3) |
| R3-6 (low) | The verifier does not pin `NUM_RANDOM_CODEWORDS`: a modified prover can omit the codewords. This affects only that prover's own privacy, not soundness | Yes (source) | **Documented** (`zk/src/params.rs` header) |
| R3-7 (low) | "h ≥ 256 per chunk" should say `h_p` = the chunk height H; "per matrix" should say per height class | Yes | **Fixed** |
| R3-8 (low) | "does not count the translate by g" misleads: the factor 2 counts it | Yes | **Fixed** (terminal-blinding.md C2) |
| R3-9 (low, info) | Stale references to the parameter set; "BabyBear^5" in `zk/src/lib.rs` | Yes | **Fixed** |

**Confirmed (the reviewer's classifications: P paper, S source, U unverified):**
- the eq. (17) instantiation, 2·(8 + 108) = 232 ≤ 256 (P, S);
- h = |H| (S) and h_p = H (S);
- the quotient randomization matches eqs. 13–14 (S, P);
- the minimum height is enforced by the prover and verifier (S).

**Not confirmed:** that Plonky3 matches the paper's protocols (U; zk-coverage.md §3).

## Round 4 (2026-09-26): the Option A revert, the `R` checks, the ZK documentation, the testnet v2 identity

**Reviewer:** a fresh-context agent, read-only.

**Scope:** the uncommitted diff after the revert to BS-ZK-2.

**Main result:**
- No overclaim was found (perfect ZK, "proven", "Theorem 8 met", independent audit).
- No stale reference to BS-ZK-3 remains.
- The analysis error is recorded honestly.
- The genesis ids were recomputed independently and match.

| # | Finding | Verified | Status |
|---|---|---|---|
| M1 (medium) | The docs overstated the new `R` tests. The verifier already rejects a missing or narrow `R`, so the proof-level test added nothing. The vendored test uses upstream's configuration and runs only in the manual upstream checkout | Yes (source) | **Fixed.** The proof-level test now pins `R`'s full committed width (12 columns) at every query of every table, which the verifier does not check. The docs say what the verifier checks and where each test runs. The vendored test asserts the exact width |
| M2 (medium) | The reset plan and the launch checklist still described v1 as current and the identity as "proposed", and omitted the blinding and the minimum height from the consensus changes | Yes | **Fixed** (reset-plan §0–§3; checklist G1, G12; consensus.md says "planned reset") |
| M3 (medium) | The committed-column count behind the envelope ignored Plonky3's doubled quotient chunks under ZK, the per-matrix codewords and `R` | **Measured** on real proofs: 4,999 committed base columns for the widest statement (3 executions, 23 tables) against the earlier estimate of 4,984, and 3,115 for one execution. The estimate was slightly low, so it was not an upper bound; the reviewer's concern that the width might exceed 6,000 did not materialize | **Fixed.** Both envelope tests now measure the width on a real proof. The envelope (6,000) holds with a margin of about 1,000. The security figures are unchanged: 123 and 105 bits, which stay the same up to 65,536 columns (the params test; after the verification pass below) |
| L1–L8 (low) | A reference to Z14, which does not exist; stale "margin of 18" statements; a redundant assertion; an unverified item listed as confirmed; "enforced by a `const` assertion"; wording relative to uncommitted work; a stale test comment; an incomplete header | Yes | **Fixed** |
| V1 (medium; verification pass of the fixes) | The verifier does not pin the hidden columns, so a malicious proof could pad FRI-batched columns beyond the 6,000 envelope, and the "65,536" figure was not in a committed test | Yes (source) | **Fixed.** `MAX_ADVERSARIAL_COLUMNS` = 6,000 + `MAX_PROOF_BYTES`/(4·108) = 15,709 caps any accepted proof (each column costs 4 bytes per query); the params test now covers it and 65,536: 123/105 bits. Pinning the hidden widths in the verifier would be a consensus change, not made |
| V2–V10 (low; verification pass) | A P-5 citation ahead of the evidence; envelope definitions; stale statuses (ZK-F29, ZK-F30, P-10, fuzzing gate); a split table cell; three wordings of the Appendix A estimate; a genesis citation; checklist criteria that need debug logs or a non-existent `/info` field | Yes | **Fixed** |
| I1 (info) | The Appendix A leakage can be estimated (about N/\|F\|); the deviation of Plonky3's use of `R` from Protocol 2 should be named | Yes | **Documented** (zk-coverage.md §3, as unverified estimates) |

## What rounds 2 to 4 did not cover

- `isa.rs` (the decoder);
- a proof of zero knowledge for the whole system (round 3 checked only the per-table conditions of the paper; zk-coverage.md §3);
- Poseidon2 cryptanalysis;
- the delivery KEM;
- P2P and Dandelion++;
- RandomX and difficulty;
- v1 transaction cryptography (CLSAG, BP+);
- the vault program's own execution profile.
