# 22 px-proof-system: research dossier (phase 2, phase 1)

**Internal engineering research, not an audit.** Read-only on the repository. No builds, tests or benchmarks were run by this agent. Zero knowledge is claimed only as statistical and conditional (docs/reviews/zk-coverage.md §3). Every number marked [est] is my estimate and must be measured before anyone relies on it.

Evidence classes used below: **[math]** mathematically established; **[test: name]** covered by a named existing test (not run by me); **[src]** source-read by me at `file:line`; **[assumed]**; **[unknown]**; **[est]** estimate.

---

## 1. Scope and what I read

**Commit:** `9e422d8` (`rebuild/core`, after the merge of `v3/candidate`).

**Code (read in full unless noted):**
- `zk/src/lib.rs` (prove, verify, `honest_fri_schedule`, `check_fri_schedule`, `encode_proof`, `decode_proof`, `check_canonical_form`, `analysis`), `zk/src/config.rs`, `zk/src/params.rs`.
- `zkvm/src/prove.rs` (`limits`, `CIRCUIT_ID`, `statement_digest`, `prove_shaped`, `verify`); `zkvm/src/air/mod.rs` (Table, periodic columns); `zkvm/src/air/byte.rs` (head); `zkvm/src/air/program.rs` (`preprocessed`).
- `px/src/prove.rs` (kernel budgets, statement, prove, verify); `px/src/fingerprint.rs`.
- `tx/src/px.rs` (proof field decode `:351`, `read_budget` `:129-133`, `budget_is_provable` `:767-783`, `check_deploy_structure` `:787-830`); `tx/src/validate.rs:535-570` (`check_px_proof`); `tx/src/params.rs`; `consensus/src/schedule.rs:1-80`; `chain/src/mempool.rs` (PX ordering, grep).
- Patched Plonky3: `third_party/README.md`; `third_party/p3-fri/src/{config.rs:150-230, prover.rs:180-280, verifier.rs:190-860, hiding_pcs.rs:411-487, two_adic_pcs.rs:675-760, periodic.rs:175-260, proof.rs}`; `third_party/p3-merkle-tree/src/{hiding_mmcs.rs (salt width pinning), mmcs/mod.rs:840-960 (pruned verify, duplicate-query check), pruning.rs (exact sibling count)}`.
- Registry Plonky3 0.7.0: `p3-batch-stark-0.7.0/src/verifier/mod.rs:98-330, 430-560` (opening points, shape validation); `p3-commit-0.7.0/src/domain.rs:382-418` (periodic evaluation with batch inversion); `p3-uni-stark-0.7.0/src/security.rs:312-350`; `p3-security-0.7.0/src/stark.rs:36-54, 196-276` (collision cap); `serde-1.0.229/src/core/private/size_hint.rs` (1 MiB preallocation cap).

**Tests read:** `zk/tests/proofs.rs` (all 12 tests), `zk/tests/field_mutations.rs` (structure), `zk/tests/pins.rs`, `zk/src/lib.rs` `schedule_tests`, `zk/src/params.rs` tests, `px/tests/fri_schedule.rs`, `px/tests/proof.rs` (head), `px/tests/unified.rs:300-360, 530-580` (`budgets_leave_headroom`, the n_fn = 2 witness), `zkvm/tests/multi.rs:300-372` (widest-shape envelope test), `zkvm/tests/circuit_id.rs` (via grep), `fuzz/fuzz_targets/proof_decode.rs`, `tx/tests/malleability.rs` and `tx/tests/px_consensus.rs` (test lists).

**Docs and reports:** `docs/reviews/full-review-2026-09-27.md` (§1, §3.5, register rows for ZK, §5 P0-3/P1-12, §6 v3 bundle, §8-§10), `docs/reviews/autonomous-session-2026-09-27.md` (all), `full-review-2026-09-27/R4-zk.md` (all), `SX1-core-crossreview.md` (all), `SX2-systems-crossreview.md` (ZK rows), `R12`/`R13`/`R7` ZK-F4 rows (grep), `docs/zk.md` §9.3 and the measurement table (`:540-600`, `:700-720`), `docs/px.md` size rows, `docs/reviews/v3-upgrade-mechanism.md` §9-§10, `docs/testnet-v3-genesis.md` and `px-f4-f5-analysis.md` (proof-related lines), `AUDIT.md` ZK-F4/ZK-F13 rows, `docs/reviews/review-package.md:108`.

---

## 2. Current state

### 2.1 What exists and is well designed

| Claim | Evidence |
|---|---|
| **Strict wire format.** `decode_proof` rejects > `MAX_PROOF_BYTES`, unknown version, trailing bytes, any encoding that does not re-encode byte-identically, and a panicking decoder (caught). | [src `zk/src/lib.rs:266-294`], [test: `encoding_is_strict`, `byte_mutations_never_verify_and_never_panic_the_caller`], fuzz target `proof_decode` (round-trip oracle) |
| **Canonical form (M1/M2).** Non-zero commit-phase grinding witnesses (at `COMMIT_POW_BITS = 0`) and present-but-empty optional openings are rejected at decode. This is the same fix upstream later made (Plonky3 #2106). | [src `:314-342`], [test: `unbound_proof_fields_cannot_be_rewritten`, which also asserts the 0.7.0 verifier alone still accepts the rewrite] |
| **No other relayer malleability found.** Pruned Merkle proofs require the exact sibling count; duplicate queries must carry identical rows *and* salts (salted rows are compared); salted row widths are pinned to the verifier-known matrix width; FRI input matrix widths are pinned to the claimed evaluation count; the query PoW witness is observed before index sampling, so changing it changes the queries. | [src `third_party/p3-merkle-tree/src/pruning.rs:252-310`, `mmcs/mod.rs:564-575`, `hiding_mmcs.rs:183-206`, `p3-fri/src/verifier.rs:735-755`, `:319-336`]; [test: `field_mutations`, ~6,000 elements] |
| **Shape pre-checks before Plonky3.** Table count, per-table degree bits within `[MIN+1, min(limit, MAX)+1]`, then the FRI schedule rule, then Plonky3 behind `catch_unwind`; `panic = "unwind"` enforced by `compile_error!`. PX statements additionally require the exact shaped heights. | [src `zk/src/lib.rs:16-21, 126-174`; `zkvm/src/prove.rs:209-232`], [test: `claimed_heights_and_table_counts_are_checked_first`] |
| **R4-02 is implemented correctly.** `check_fri_schedule` requires the schedule to equal `honest_fri_schedule(degree_bits)`. I re-derived equivalence with the prover: the prover's FRI inputs are one reduced opening per distinct log height `db + LOG_BLOWUP` (every input of a table lies on a domain of size `2^db`: trace, `R`, randomized quotient chunks and permutation, `p3-batch-stark verifier/mod.rs:120-260`); the commit phase peeks the next smaller input and calls `compute_log_arity_for_round` (`prover.rs:216-229`), which the check reuses. All input heights are ≥ 12 > final height 9, so every input is rolled in before the final polynomial. This is what Plonky3 0.8 does by derivation (#2033, #2125). | [src, math], [test: `honest_schedules_are_well_formed` (all 2^15 subsets), `known_schedules`, `honest_proofs_use_the_canonical_fri_schedule` (8 height pairs, real proofs, incl. a preprocessed table via `statements_with_preprocessed_tables_verify` which runs the same `verify`), `a_non_canonical_fri_schedule_is_refused`, `every_consensus_shape_has_a_well_formed_canonical_schedule`; PX proofs in `tx px_consensus` pass through the check] |
| **R4-11 is implemented.** `CIRCUIT_ID = "BlackSilk/zkvm/BVM-1/circuit/v1"` is the first input of `statement_digest`, which the challenger absorbs after `PARAMS_ID` and before any commitment. | [src `zkvm/src/prove.rs:47-91`, `zk/src/config.rs:78-88`], [test: `the_circuit_tag_is_the_first_input_of_the_statement_digest`] |
| **Frozen-Heart defence.** All verifier-supplied periodic data (programs, images, outputs, byte table) is hashed into the statement digest before any challenge; public values (with `h_tx`) are observed by Plonky3. | [src], [test: `wrong_public_values_and_binding_are_rejected`] |
| **Periodic columns are evaluated efficiently by the verifier** (one batch inversion per distinct period, `p3-commit-0.7.0/src/domain.rs:382-418`). The slow per-value-inversion evaluator in `third_party/p3-fri/src/periodic.rs:209-258` is not on the verify path. | [src] (I checked this because it would otherwise have been a verifier-cost finding) |
| **Prover randomness** is hedged (OS RNG ⊕ witness digest) for Merkle salts, PCS codewords and terminal blinding. | [src `zk/src/config.rs:130-151`, `zkvm/src/prove.rs:166-198`], [test: `proofs_are_randomized` with a zero RNG] |
| **Deserializer preallocation** is capped at 1 MiB per sequence by serde (`size_hint::cautious`), so a lying length prefix cannot allocate gigabytes. | [src `serde-1.0.229/src/core/private/size_hint.rs:12-23`], postcard pinned `=1.1.3` (SX2 R16-3 is closed) [src `zk/Cargo.toml:34-35`] |

### 2.2 What the tests do not prove

- **No test measures a two-function (widest) PX proof size or verification time.** `the_widest_multi_execution_shape_stays_in_the_envelope` measures *columns* (4,999) on an unshaped toy 3-execution proof, not bytes, and asserts only Johnson ≥ 100 [src `zkvm/tests/multi.rs:337-372`]. `budgets_leave_headroom` builds an n_fn = 2 witness (CLAIM + LOCK) but only runs it, it does not prove it [src `px/tests/unified.rs:549-570`].
- **No adversarial verifier-cost measurement (ZK-F4).** Measured honest: transfer 0.207-0.212 s, vault 0.254-0.265 s [docs/zk.md:711, one machine].
- **No golden proof.** No stored proof must keep verifying under the frozen rules; honest proofs are not byte-reproducible (third_party/README.md), so a golden proof must be a stored file.
- **Nothing ties `CIRCUIT_ID` to the AIRs.** An AIR change without a bump passes every existing pin.
- **The security envelope test still uses the pre-ZK size** (R4-01) and the widest-shape test does not assert the unique-decoding floor (R4-12).

---

## 3. Problems in scope

### 3.1 Proof-shape rules and canonical form

**Problem.** One field of the proof shape is still prover-chosen: the number of hidden random-codeword openings per matrix and point. `HidingFriPcs::verify` checks only the nesting counts (rounds, matrices, points) and then appends whatever values are present [src `third_party/p3-fri/src/hiding_pcs.rs:449-485`]; the Merkle check then accepts any width consistent with those openings (`p3-fri/src/verifier.rs:735-755`). `check_canonical_form` does not check it [src `zk/src/lib.rs:314-342`]; `params.rs:16-24` documents the gap and bounds it by `MAX_PROOF_BYTES` (`MAX_ADVERSARIAL_COLUMNS` = 15,709).

**Why it exists.** Plonky3 0.7.0 does not pin it. Upstream `main` now does: `HidingRandomOpeningValueCountMismatch` rejects any count other than `num_random_codewords` (0 for a preprocessed round) [upstream `fri/src/hiding_pcs.rs`, fetched 2026-09-27; PR number not verified, plausibly within the typed-layer work of #2129].

**Consequences.**
- *Not* relayer malleability: changing the count needs the committed data, so only the prover can do it [src, reasoning as SX1 for R4-02].
- Soundness: extra batched columns are already accounted up to 15,709 and tested to 65,536 [test: `every_shape_within_limits_meets_both_security_targets`]. No soundness break.
- **Verifier cost:** a *valid* proof can be padded to the 4 MiB cap, so the worst verifier cost is reachable without any invalid proof (see §3.3).
- **Privacy:** proof length becomes a prover-implementation choice. A wallet built with a different codeword count (or a different library) produces proofs of a distinguishable length, which partitions the PX anonymity set. Honest BlackSilk wallets all use 4, so today this is a latent channel, not a leak. (Coordinate with 26: the P-5 campaign assumes length depends only on Merkle pruning.)
- **Block space:** a padded PX tx (≈ 4.45 MB) fits once per 8 MiB PX budget, where honest transfers fit 3 times, at the same flat fee. Honest miners are protected by policy: templates sort by fee per byte [src `chain/src/mempool.rs:413`], so padded transactions go last and are evicted first. Residual: a miner or a quiet pool. Low.

**Literature and practice.** Plonky3 0.8 moved from "check the proof's shape" to "derive the shape from the configuration" (#2033 fold schedule, #2125 commit-round shape, #2106 canonical grinding witnesses). ZIP 244 separates `txid` from authorizing data precisely because proofs can be malleated; BlackSilk instead puts the proof bytes in the tx id, so it must keep *exactly one* valid encoding per honest proof, which is the rationale of `4b277cd` [ZIP 244; BIP 141].

**Proposed fix (CONSENSUS tightening).** In `check_canonical_form`: every entry of `proof.opening_proof.0` (round → matrix → point) has length exactly `NUM_RANDOM_CODEWORDS`, with the preprocessed-round exception derived exactly as the 0.7 prover does (BlackSilk PX has no Plonky3-preprocessed round; the zk toy test does). This is a decode-time, O(proof) structural check.

**Trade-offs / what could go wrong.** A wrong expected count rejects honest proofs, a liveness split. Must be derived from the honest prover and tested on every consensus shape (n_fn = 0, 1, 2) and on the toy statements with and without preprocessed tables. It changes the rule set, so it must ride the protocol freeze (the testnet has not launched; a reset is authorized).

**Tests.** A positive test on real proofs of every shape; a negative test that builds a valid proof with `NUM_RANDOM_CODEWORDS + 1` (a test-only `ProverConfig`) and with 0, both refused at decode; the 0.7.0-verifier-alone acceptance asserted (as `unbound_proof_fields_cannot_be_rewritten` does), so an upstream fix is noticed.

**Invariants.** One valid encoding per honest proof; canonical-form checks run before any expensive work; never relax `4b277cd`.

### 3.2 `MAX_PROOF_BYTES` against the widest two-function proof

**Problem.** `MAX_PROOF_BYTES` = 4 MiB (4,194,304) [src `zk/src/params.rs:97`]. Measured: transfer 2,178,213-2,180,408 B (3,115 committed columns), vault call 2,687,952-2,688,822 B [docs/zk.md:711]. The widest shape (kernel + 2 functions, 23 tables, 4,999 columns) is not measured; the docs estimate 3.0-3.3 MB [docs/zk.md:716].

**My estimate [est].** Each extra execution added ≈ 510 KB (transfer → vault). Two functions: ≈ 3.2 MB, plus one Merkle level because the n_fn = 2 kernel CPU table is 2^16 rows (35,600 cycles) [src `px/src/prove.rs:58`]. With *registered* budgets at the height limits (non-CPU tables up to 2^22, CPU 2^21; `budget_is_provable`, `tx/src/px.rs:767-783`), only log factors grow: about +6 Merkle levels on ≈ 10 trees × 108 queries × 32 B (≈ +200 KB before pruning) and about +2 FRI rounds (≈ +100 KB). Upper estimate ≈ 3.6 MB: 14% headroom, not the 25-45% the docs imply. Such budgets are practically unprovable (peak prover memory is already 3.8 GB at 2^16 heights), so they matter for the bound, not for users.

**Consequences.** If a real shape exceeds the cap, that function combination becomes uncallable (liveness for that contract, not safety): the wallet finds out only after ≈ 60 s of proving. Nothing checks proof size at deploy time.

**Consensus?** The cap is consensus; the measurement is evidence only. Must close before the v3 ids and genesis are frozen (full review P0-3, SX1 §3 item 4).

**Fix.** Measure (plan in §5, W1). If the measured widest realistic proof plus the analytic height allowance exceeds about 90% of the cap, choose one of: (a) a deploy-time bound on registered budgets (consensus, 28's rule file); (b) raise the cap (changes `MAX_PX_TX_SIZE` and the flat PX fee: an owner economic decision, 14); (c) accept and document that large-budget pairs may be unprovable. With §3.1 in place, size becomes a deterministic function of the shape plus Merkle pruning, so the bound can be stated exactly.

**Invariants.** `MAX_PX_TX_SIZE = MAX_PROOF_BYTES + 256 KiB` and the flat fee are coupled (`tx/src/params.rs:17, 41`); change them together or not at all.

### 3.3 Verifier resource usage and adversarial cost (ZK-F4)

**Structure of the cost [src].** After the O(1) pre-checks, the verifier:
1. builds the tables and the statement digest: rebuilds each program's periodic columns (≤ 2^16 × 28 values per function, `zkvm/src/air/mod.rs:136-144`, not cached, rebuilt again inside Plonky3; R4 §3.7) and hashes them;
2. symbolic-evaluates each AIR for quotient-chunk counts (fixed per table kind);
3. verifies all input Merkle openings first (`open_inputs`, `verifier.rs:694-790`): cost ∝ opened bytes, i.e. ∝ proof size;
4. folds 108 query chains and checks the final polynomial, then the commit-phase Merkle openings: ∝ proof size;
5. evaluates constraints at ζ (fixed per AIR) and periodic columns at ζ (O(period) per distinct period with one batch inversion).

**Consequence.** An invalid proof can be crafted to fail at the last check (a wrong final-polynomial coefficient, or the last commit-phase Merkle root), so its cost ≈ the cost of a valid proof of the same size. Since §3.1 lets a *valid* proof be padded to 4 MiB, the worst case is ≈ valid-4-MiB cost + two maximal (2^16-instruction) function programs. R12 estimated ≈ 0.45 s scalar [R12 §, est]; I estimate 0.4-0.6 s single-threaded, with the program periodic columns adding tens of ms each [est]. This is bounded and linear: I found no super-linear path. **Unknown until measured**, including with `RAYON_NUM_THREADS=1`.

**Decode memory (new, §4 F22-7).** `postcard::take_from_bytes::<Proof>` materializes the whole structure before any check. The deepest types are `Vec<Vec<Vec<T>>>` (`BatchMultiOpening::opened_values`, hiding-MMCS salts) and `Vec<CommitPhaseMultiStep>` [src `third_party/p3-fri/src/proof.rs:13-78`]. An empty inner `Vec` costs 1 input byte and 24 bytes of memory; a 3-byte `CommitPhaseMultiStep` costs roughly 70-80 bytes. So a crafted 4 MiB proof can transiently allocate about 25× its size, ≈ 100 MB [est], before `check_fri_schedule` rejects it in O(1). Rate-limited by the PX relay bucket (2/s) and freed immediately; a block could carry 1-2 such proofs. Low.

**Literature.** Zebra runs proof verification on dedicated blocking/rayon pools behind batching services [zebra-consensus docs]; Bitcoin Core bounds per-block validation work (sigops) rather than per-proof; for STARKs the verifier is O(λ·log² n) in theory and linear in proof bytes in practice [ethSTARK 2021/582]. The usual mitigation for deserialization amplification is to bound total element counts, or to parse with a schema that is derived from the verifier's expected shape (the direction of Plonky3 0.8's derived shapes, #2125).

**Fix.** Measurement first (W1). If decode peak exceeds ~64 MB per proof, add a shape-directed pre-parse: with §3.1 and the derived schedule, the verifier knows every vector length before reading the proof, so the decoder can reject any length prefix that differs. This is a larger change (it would need a custom `Deserialize` or a pre-scan over postcard varints) and is P2.

### 3.4 R4-02 (FRI schedule) and R4-11 (circuit id): are they correct now?

- **R4-02: correct** (§2.1). Two notes: (1) the check lives in `verify`, not `decode_proof`. That is fine for consensus (a non-canonical schedule is not relayer-malleable), but the rule must never be dropped from any verify path (block, mempool, reorg re-verification). (2) A Plonky3 0.8 migration makes it redundant (the schedule is derived, #2125); the rule and its test should stay as a regression oracle until then.
- **R4-11: present but not mechanically bound to the AIRs.** `CIRCUIT_ID` is a hand-maintained string. Nothing fails if an AIR, a bus or the table order changes and the tag does not. The consensus fingerprint pins only the string [src `px/src/fingerprint.rs:199-203`]. A tightening AIR change would reject old proofs (would be caught by a golden proof, if one existed); a *relaxing* change would not be caught by anything. **Fix (W4):** a test that hashes, per table kind, the width, periodic width, public-value count, the `Debug` rendering of the symbolic constraints and of the lookups (Plonky3 is pinned `=0.7.0`, so the rendering is stable), pins the digest, and names `CIRCUIT_ID` in its failure message; add the digest to the consensus fingerprint.

### 3.5 R4-01 / R4-12: the security figures

- `params.rs:153` still passes `1 << shape.log_height` (pre-ZK); under ZK the committed size is `2H` [src]. Not fixed.
- **Why the headline Johnson figure is robust anyway:** `p3-security` 0.7 caps every regime at the commitment-collision term (`stark.rs:53-54, 275-276`), and BlackSilk sets `COLLISION_BITS = 123`. The 123 is therefore the hash cap, not an algebraic term. With a 247-bit challenge field, the |D|²-type batching and commit terms at |D| = 2^26 sit around 2^-160 [est], far above the cap, so a one-bit domain change cannot move the figure. The unique-decoding figure is query-bound: 108 · log2(1/0.5625) + 16 = 105.6 bits [math]. The 0.7 calculator bugs fixed in #2048 all overstated security; none understated it [PR #2048]. So the fix is mechanical and should not change the documented numbers, **but this must be confirmed by recomputation** (25 owns the independent calculation).
- The widest-shape test asserts `johnson_bits ≥ MIN_PROVEN_BITS` only [src `zkvm/tests/multi.rs:370`]: R4-12 is open.

### 3.6 Consensus constants outside the fingerprint

`kernel_budget(0..=2)` fixes the exact heights every PX proof must have (`zkvm::prove::verify` rejects any other shape), and `consensus::schedule` says `VERIFIER_PX_1` *means* "kernel, parameter set and kernel budgets" [src `consensus/src/schedule.rs:30-33`]. But `px_entries()` fingerprints the vault budget and not the kernel budgets [src `px/src/fingerprint.rs:252-264`]. The same holds for `zkvm::prove::limits`, `MAX_EXECUTIONS` and the table layout (covered by W4). Two builds that differ only in a re-measured budget (the v3 notes plan exactly such re-measurements, `v3-upgrade-mechanism.md` §9) would show the same fingerprint and split on the first PX transaction. **Fix (W5):** add `px.kernel.BUDGET[n]` for n = 0, 1, 2 and `zkvm.limits` to the manifest.

### 3.7 Verifier id not dispatched

`TxRules` has no verifier id; `check_px_proof` always runs the one verifier [src `tx/src/validate.rs:537-570`]; `SUPPORTED_VERIFIERS` is checked only in a test [src `tx/tests/upgrade.rs:82-90`]. Correct for one epoch. A Plonky3 0.8 migration (24, "new parameter set") needs a dispatch on the epoch's verifier id. Informational; owner 46/24.

### 3.8 Invariants that must never change

- One valid encoding per honest proof; strict decode (size, version, trailing bytes, re-encode identity, catch_unwind); `4b277cd` rules.
- The canonical FRI schedule rule, until the verifier derives the schedule itself.
- `PARAMS_ID` then the statement digest (starting with `CIRCUIT_ID`) absorbed before any commitment.
- Pre-checks on table count and degree bits before any Plonky3 code; `panic = "unwind"` with `catch_unwind`.
- Exact shaped heights for PX statements.
- `VerifierConfig` never proves; prover randomness is hedged and fresh per proof.
- Parameter constants are a new parameter set, never an in-place edit.

---

## 4. Findings

| ID | Severity | Status | Where | Scenario | Confidence |
|---|---|---|---|---|---|
| **F22-1** Hidden-codeword opening count not pinned: proof width and size are prover-chosen | Low (privacy latent, verifier-cost enabler; consensus hygiene) | Not implemented | `zk/src/lib.rs:314-342`; `third_party/p3-fri/src/hiding_pcs.rs:449-485`; `zk/src/params.rs:16-24` | A prover pads every matrix with extra codewords: the proof stays valid up to 4 MiB, takes 1 PX slot per block at the flat fee, and costs every node the maximal verification. A different wallet implementation is distinguishable by proof length. Mitigated for honest miners by fee-per-byte ordering (`chain/src/mempool.rs:413`). Upstream main now pins the count. | High (fact); medium (impact) |
| **F22-2** Widest two-function proof unmeasured against `MAX_PROOF_BYTES`; no deploy-time size bound | Medium | Not implemented (known; my estimate: 3.2 MB realistic, ≤ 3.6 MB at height limits, 14% headroom) | `zk/src/params.rs:97`; `tx/src/px.rs:767-783`; `docs/zk.md:715-716` | A registered pair of functions whose shape exceeds 4 MiB is uncallable; the wallet discovers this after the proving time. | Medium ([est]) |
| **F22-3** Adversarial verifier cost (ZK-F4) unmeasured | Medium | Not implemented (known); refined: linear in bytes, worst case reachable by a valid padded proof or an invalid proof failing at the last check | `zk/src/lib.rs:126-174`; `third_party/p3-fri/src/verifier.rs:340-440` | 2 PX/s relay budget × ≈ 0.5 s [est] single-threaded, while the chain lock is held on some paths (R6 MP-1). | Medium |
| **F22-4** `CIRCUIT_ID` not mechanically bound to the AIRs | Medium (consensus-divergence detection) | Not implemented | `zkvm/src/prove.rs:59`; `px/src/fingerprint.rs:199-203` | An AIR relaxation merged without a tag bump: every pin passes, and builds disagree on which proofs are valid. | High |
| **F22-5** Kernel budgets and per-table limits missing from the consensus fingerprint | Medium (detection gap) | Not implemented | `px/src/fingerprint.rs:252-264`; `px/src/prove.rs:54-71`; `consensus/src/schedule.rs:30-33` | A budget re-measured on one branch: identical fingerprint, chain split on the first PX tx. | High |
| **F22-6** R4-01 still open (pre-ZK size in the calculator); R4-12 still open (widest test asserts only Johnson ≥ 100) | Low (claim accuracy) | Not implemented | `zk/src/params.rs:153, 185`; `zkvm/tests/multi.rs:370` | An external recomputation disagrees with a documented input. Figures very likely unchanged, because 123 is the collision cap (`p3-security stark.rs:53-54`). | High (fact); medium (no change in figures) |
| **F22-7** Decode memory amplification ≈ 25× before any shape check | Low | Not implemented; needs measurement | `zk/src/lib.rs:278-280`; `third_party/p3-fri/src/proof.rs:13-78` | A peer relays crafted 4 MiB proofs full of empty vectors: ≈ 100 MB transient each [est], bounded by the 2/s PX bucket. | Medium ([est]) |
| **F22-8** No golden proof (zk toy or PX) | Medium (regression evidence; SX2 P0-2) | Not implemented | `zk/tests`, `px/tests` | A dependency or AIR change silently changes verifier semantics; nothing stored fails. | High |
| **F22-9** R4-02 and R4-11 fixes verified | Informational | Complete but requires further testing (R4-02: complete and verified by argument and tests) | `zk/src/lib.rs:188-248`; `zkvm/src/prove.rs:47-91` | — | High |
| **F22-10** "ZK-F4" names two different things: AUDIT.md (BS-ZK-1 margin, fixed) and the review register (adversarial verifier cost, open) | Informational (docs) | Not implemented | `AUDIT.md:988`; `zk/src/params.rs:12`; `docs/zk.md:507, 882`; full-review register row ZK-F4 | Readers conclude the verifier-cost item is fixed. Rename the open item (e.g. ZK-VC1). | High |
| **F22-11** PX verifier id not dispatched | Informational | Deferred (single epoch) | `tx/src/validate.rs:537-570`; `tx/src/params.rs:75-76` | The first second verifier needs code, not a table entry. | High |
| **F22-12** "3 PX per block" holds for transfers only: n_fn = 2 proofs fit 2, padded proofs 1 | Informational (docs) | Not implemented | `docs/px.md:648` | Capacity planning uses the wrong figure. | Medium ([est] sizes) |
| **F22-13** Program periodic columns rebuilt on every call (already R4 §3.7) | Informational (perf) | Not implemented | `zkvm/src/air/mod.rs:136-144` | A few ms to tens of ms per function per verification. | High |

I found **no** relayer-malleability path, soundness break or verifier panic path in scope beyond those already fixed.

---

## 5. Implementation plan for phase 2

Order: measure (W1), decide (W2), then pin (W4, W5, W6) after the freeze-relevant changes.

| # | Item | Files (ownership) | External effect | Identity | Tests | Bench | Docs | Diff. | Prio |
|---|---|---|---|---|---|---|---|---|---|
| **W1** | **Measurement harness: widest proof and ZK-F4.** (a) Prove the n_fn = 2 shape (CLAIM + LOCK, fixture from `unified.rs:549`) 5×: size min/max, prove time, verify time, peak RSS. (b) A height-scaling series with a test function at 2^16, 2^17, 2^18 non-CPU heights (as far as RAM allows) to fit the per-level byte slope; extrapolate to the limits. (c) Adversarial verify: a valid proof padded to ≈ 4 MiB with a test-only codeword count (possible before W2; after W2 the same proof becomes W2's rejection test), and an invalid proof with a corrupted last final-poly coefficient; time each with `RAYON_NUM_THREADS=1` and default. (d) Decode peak memory for a crafted 4 MiB postcard proof (empty vectors), with a counting global allocator in the test binary. | new `px/examples/proof_limits.rs`; new `px/tests/proof_limits.rs` (`#[ignore]`, release only); new `zk/tests/decode_memory.rs` | none | none | ignored tests that assert size ≤ 0.9 × `MAX_PROOF_BYTES` for the widest realistic shape and verify time ≤ a recorded ceiling | the four measurements above; record machine, commit, rustc | `docs/zk.md` measurement table (§9, `:700-720`); `docs/evidence/` new run | M | **P0** |
| **W2** | **Pin the hidden-codeword count** in `check_canonical_form` (§3.1). Owner decision required (CONSENSUS). | `zk/src/lib.rs` (22) | CONSENSUS (tightening; honest proofs unaffected) | Rule-set change; ride the freeze; fingerprint unchanged (constant already pinned), golden vectors after | positive on every PX shape and on toy statements with/without preprocessed tables; negative with count ±1 and 0; 0.7.0-alone acceptance assertion | none | `zk/src/params.rs` doc (§ "verifier does not enforce"), `docs/zk.md` §9, `docs/zkvm.md` §10 | S | **P0 decision / P1 implementation** |
| **W3** | **R4-01 / R4-12:** pass the post-ZK size (`log_height + 1`, or `compute_from_proof`) in `security()`; the envelope loop covers post-ZK 9..=23; the widest-shape and `vm.rs` tests assert both bounds; add a shaped PX two-function statement. | `zk/src/params.rs` (25 or 22: coordinator); `zkvm/tests/multi.rs`, `zkvm/tests/vm.rs` (23) | none | none | the two tests | none | `docs/zk.md` §9.3 with calculator version; `query-policy.md` | S | P1 |
| **W4** | **AIR digest pin** bound to `CIRCUIT_ID` (§3.4). | `zkvm/tests/circuit_id.rs` (23/22); `px/src/fingerprint.rs` (22) | none | fingerprint value changes (pinned test values update) | pinned digest; a mutation check that changing one constraint changes it | none | `docs/zkvm.md` §7, `docs/zk.md` §9.3 | S | P1 |
| **W5** | **Fingerprint kernel budgets and table limits** (§3.6). | `px/src/fingerprint.rs` (22); `px/tests/consensus_fingerprint.rs`, node fingerprint pin test (01/43) | none | fingerprint value changes | pinned fingerprint | none | fingerprint doc | S | P1 |
| **W6** | **Golden proofs:** one toy zk proof (≈ 240 KB) and one PX transfer proof (≈ 2.2 MB) with their statements, stored as files; each must verify; stored rewrites (schedule swap, non-zero witness, empty opening, codeword count ±1) must be refused. Generate only **after** W2 and the kernel freeze. | new `zk/tests/golden.rs` + `zk/tests/fixtures/`; new `px/tests/golden_proof.rs` + `px/tests/fixtures/` (22) | none | none | as described | none | `docs/zk.md` evidence list | S-M | P1 (P0 for the freeze tag, per SX2 P0-2) |
| **W7** | **Deploy-time proof-size bound**, only if W1 shows < 10% headroom at the height limits. | `tx/src/px.rs` `budget_is_provable` (28/11) | CONSENSUS | rule change | deploy rule tests | W1 | `docs/px.md` §11 | S | P1 (conditional) |
| **W8** | **Decode hardening** if W1(d) exceeds ~64 MB: shape-directed length checks before or during decode. | `zk/src/lib.rs` (22) | none (rejects only proofs the verifier would reject) | none | crafted-proof memory test | W1(d) | `docs/zkvm.md` §10 | M | P2 |
| **W9** | **Structure-aware verifier fuzz target with a time oracle** (R13 item 8). | new `fuzz/fuzz_targets/proof_verify.rs` (41) | none | none | fuzz | slow-unit report | fuzz doc | M | P2 |
| **W10** | **Docs:** ZK-F4 renaming (F22-10); shape-dependent PX capacity (F22-12); `MAX_ADVERSARIAL_COLUMNS` wording after W2. | `docs/zk.md`, `docs/px.md`, register (47) | none | none | — | — | as listed | S | P1 |
| **W11** | Cache program periodic columns per `Arc<Program>` (F22-13). | `zkvm/src/air/mod.rs` (23/27) | none | none | verify equality old/new | verify time | — | S | P3 |

---

## 6. Dependencies and conflicts

- **20 px-kernel:** kernel budget re-measurement (PX-F5, any R2-C6) changes W1's numbers and W5's pinned values. W1 and W6 run after the kernel freeze.
- **23 zkvm-bvm:** owns `zkvm/src/air/*` and `zkvm/tests/*`. W3 (tests), W4 and W11 touch its files: coordinator assigns.
- **24 plonky3-verifier-security:** the upstream codeword-count pin (W2) belongs in its coverage matrix; the 0.8 migration makes `check_fri_schedule` redundant (#2125) and needs verifier-id dispatch (F22-11). Advisories GHSA-3g92 (sponge padding) and GHSA-vj64 (MultiField32Challenger) do not appear to affect BlackSilk (fixed-width leaves; `DuplexChallenger`; 0.7.0 is past the patched versions), but that is 24's call.
- **25 zk-soundness:** W3's recomputation; I recommend 25 owns the calculator change and the independent soundcalc/0.8 figures, and I own nothing in `params.rs` beyond doc wording after W2.
- **26 zk-privacy:** W2 changes the proof-length model (length then depends only on shape and pruning); P-5 must be re-run after W2 and the kernel freeze.
- **27 zk-performance / 45 benchmarks:** share W1's harness (proof_bench style); SIMD changes verify times, so record build flags.
- **28 private-contracts-px / 11 tx-validation:** W7 lives in `tx/src/px.rs`.
- **14 fee-economics:** raising `MAX_PROOF_BYTES` changes the flat PX fee.
- **01 consensus-core / 43 ci-reproducibility:** fingerprint pins (W4, W5); golden-vector freeze order.
- **41 fuzzing:** W9. **34 chain-actor-concurrency / 10 block-validation-pipeline:** where verification runs (under the lock or not) sets the real impact of F22-3.
- **47 docs:** W10.

---

## 7. Open questions for the coordinator

1. **W2 (CONSENSUS):** include the hidden-codeword pin in the frozen rule set? My recommendation: yes. It is the same class as R4-02 (already included), it is what upstream now does, and it makes proof size and verifier cost a function of the shape.
2. Who owns the `security()` fix in `zk/src/params.rs`: 25 (my preference) or 22?
3. Is a 2.2 MB binary fixture acceptable in the repository for the PX golden proof (W6), or should the golden set be the toy proof plus a PX proof generated in CI and pinned by hash? (Proofs are not reproducible from a seed, so a hash pin needs a stored file.)
4. If W1 shows the widest realistic proof above 3.8 MB: which of W7 (deploy bound), a larger cap (fee change) or a documented limitation?
5. Should the n_fn = 2 two-vault test proof (W1a) become a permanent ignored test in the release suite?

---

## 8. Sources

- Plonky3 PR #2033, "derive the folding schedule instead of accepting the prover's": https://github.com/Plonky3/Plonky3/pull/2033
- Plonky3 PR #2125, commit-round shape derived from configuration: https://github.com/Plonky3/Plonky3/pull/2125
- Plonky3 PR #2107, FRI shape fields bound to the transcript seed (tests): https://github.com/Plonky3/Plonky3/pull/2107
- Plonky3 PR #2106, canonical grinding witnesses at zero PoW bits: https://github.com/Plonky3/Plonky3/pull/2106
- Plonky3 PR #2048, calculator accounting fixes (all overstated security): https://github.com/Plonky3/Plonky3/pull/2048
- Plonky3 PR #2129, binding hiding claims through the typed layer: https://github.com/Plonky3/Plonky3/pull/2129
- Plonky3 main, `fri/src/hiding_pcs.rs` (`HidingRandomOpeningValueCountMismatch`): https://raw.githubusercontent.com/Plonky3/Plonky3/main/fri/src/hiding_pcs.rs
- Plonky3 v0.8.0 release: https://github.com/Plonky3/Plonky3/releases/tag/v0.8.0
- Plonky3 security advisories (GHSA-vj64-rjf3-w3v7, GHSA-3g92-f9ch-qjcm, GHSA-f69f-5fx9-w9r9, GHSA-m23j-cj9m-ppg9, GHSA-vrmm-4mm5-38vm): https://github.com/Plonky3/Plonky3/security/advisories
- GHSA-3g92-f9ch-qjcm (PaddingFreeSponge variable length): https://github.com/Plonky3/Plonky3/security/advisories/GHSA-3g92-f9ch-qjcm
- GHSA-vj64-rjf3-w3v7 (MultiField32Challenger): https://github.com/Plonky3/Plonky3/security/advisories/GHSA-vj64-rjf3-w3v7
- ZIP 244, transaction identifier non-malleability: https://zips.z.cash/zip-0244
- BIP 141, segregated witness (txid vs wtxid): https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
- Q. Dao, J. Miller, O. Wright, P. Grubbs, "Weak Fiat-Shamir Attacks on Modern Proof Systems", IEEE S&P 2023, ePrint 2023/691: https://eprint.iacr.org/2023/691
- ethSTARK documentation (StarkWare), ePrint 2021/582: https://eprint.iacr.org/2021/582
- U. Haböck, A. Al Kindi, "A note on adding zero-knowledge to STARKs", ePrint 2024/1037: https://eprint.iacr.org/2024/1037
- E. Ben-Sasson, D. Carmon, Y. Ishai, S. Kopparty, S. Saraf, "Proximity Gaps for Reed-Solomon Codes", ePrint 2020/654: https://eprint.iacr.org/2020/654
- ethereum/soundcalc, a soundness calculator for hash-based proof systems: https://github.com/ethereum/soundcalc
- Zebra `zebra_consensus` (verification services, batch verifiers on blocking pools): https://docs.rs/zebra-consensus/latest/zebra_consensus/
- serde `size_hint::cautious` (1 MiB preallocation cap): local registry copy `serde-1.0.229/src/core/private/size_hint.rs`, upstream https://github.com/serde-rs/serde
