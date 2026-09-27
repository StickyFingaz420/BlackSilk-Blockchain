# v3 consensus changes (phase 2 record)

One section per consensus change of the testnet v3 rule set (phase 2, from 2026-09-27).
Each section follows the consensus-change record of the phase-2 implementation brief:
problem; demonstrated failure; prior art; alternatives; affected components; activation;
compatibility; reorg, wallet, mining and P2P implications; vectors; tests; suite results;
open review points; plus identity impact, documentation and review status (15 steps).
Internal engineering record, not an audit.

The testnet has not launched; every change here activates as a v3 genesis base rule
(the v3 reset), not at a height.

---

## BS-ZK-3: eight random codewords per committed matrix (F24-1)

Owner: W1-CB-B3 (zk). Decisions: "Agent 24" F24-1 (adopt 8), "Agent 25", "Agent 26"
(wording), "Agent 50" (new parameter set).

1. **Problem.** BS-ZK-2 hides each committed matrix with 4 random codewords
   (`NUM_RANDOM_CODEWORDS`) while the challenge field has degree 8. Plonky3 0.8 (PR #2100,
   `fri/src/hiding_pcs.rs`) now requires at least `Challenge::DIMENSION` random codewords
   per committed matrix, on prover **and** verifier side, "to mask extension-field
   batching". BlackSilk's internal round-3 argument that the separate mask polynomial `R`
   already spans the extension (docs/reviews/internal-review-log.md) is unwritten; no
   written proof of either position exists. The zero-knowledge claim (statistical,
   conditional) should not rest on a divergence from the upstream invariant.
2. **Demonstrated failure.** The invariant is violated by construction: the `const`
   assertion `NUM_RANDOM_CODEWORDS >= EXTENSION_DEGREE` added in `zk/src/params.rs` does
   not compile with BS-ZK-2's value (4 < 8), and the Plonky3 0.8 verifier would reject
   every BS-ZK-2 proof (`InsufficientHidingRandomCodewords`; dossier 24 §3.4). No leak has
   been demonstrated; the change is precautionary (privacy before size, brief §3).
3. **Prior art.** Plonky3 PR #2100 (0.8.0); Haböck and Al Kindi, ePrint 2024/1037
   (Protocol 2, §4.2 eqs. 16–17); upstream keeps `R` unchanged and adds the codeword
   minimum on top.
4. **Alternatives.** (a) Keep 4 with a written argument reviewed by agent 50 before the
   freeze (none was produced); (b) 8 codewords (chosen); (c) keep 4 as a documented
   divergence, which also blocks a Plonky3 0.8 migration.
5. **Affected components.** `zk/src/params.rs` (`NUM_RANDOM_CODEWORDS`, `PARAMS_ID`,
   `OPENING_POINTS`, the eq. 16/17 and codeword assertions); every proof's bytes and
   transcript; the PX consensus fingerprint (`px/src/fingerprint.rs` entries
   `zk.PARAMS_ID`, `zk.NUM_RANDOM_CODEWORDS`). No verifier code changes: the hiding PCS
   verifier does not read the codeword count (the hidden-count rule is the next section).
6. **Activation.** v3 genesis base rule (reset). `PARAMS_ID` becomes
   `BlackSilk/zk/BS-ZK-3`.
7. **Compatibility.** BS-ZK-2 proofs do not verify under BS-ZK-3 (different
   `PARAMS_ID` in the transcript) and vice versa. Records, nullifiers and the tree do not
   depend on the proof system.
8. **Reorg, wallet, mining, P2P.** Wallets must prove with the new set (same binary);
   proofs are larger (measured below), still under `MAX_PROOF_BYTES` for the toy
   statements; PX proofs are re-measured by the coordinator (not in this change). No
   mining, reorg or P2P logic changes.
9. **Vectors.** `PARAMS_ID` = `BlackSilk/zk/BS-ZK-3`; the PX-side fingerprint digest
   pinned in `px/tests/consensus_fingerprint.rs` changes (the new value is printed by
   that test; it is updated once, with the v3 network identity).
10. **Tests.** Compile-time: eq. 17 with both opening points
    (2·(108 + 8·2) = 248 ≤ 256), eq. 16 (2 + 108 ≤ 256), codewords ≥ extension degree.
    Runtime: the whole `zk` suite (honest proofs, mutations, schedule);
    `zkvm/tests/vm.rs::every_table_commits_a_full_extension_randomization_polynomial`
    (width `NUM_RANDOM_CODEWORDS + EXTENSION_DEGREE` of `R` at every query) and
    `zkvm/tests/multi.rs::the_widest_multi_execution_shape_stays_in_the_envelope`.
    New: `zk/tests/toy_measure.rs` (ignored; size and time of the toy proofs).
11. **Suite results** (2026-09-27, release):
    - `cargo test --release -p blacksilk-zk`: 17 passed, 0 failed, 1 ignored (the timing
      test), before and after.
    - `zkvm` `the_widest_multi_execution_shape_stays_in_the_envelope`: passes; **5,851**
      committed columns (4,999 at BS-ZK-2) against `MAX_COMMITTED_COLUMNS` = 6,000, a thin
      margin; `the_vm_shape_meets_the_security_floor` (3,591 columns) and
      `every_table_commits_a_full_extension_randomization_polynomial` pass.
    - `px` `consensus_fingerprint`: **fails as expected** (the pinned digest; update with
      the v3 network identity, owner 40).
    - Toy proofs (`toy_measure`, 5 proofs per shape, three interleaved runs of each
      binary on a machine shared with other builds, so times are noisy):

      | Shape | BS-ZK-2 size | BS-ZK-3 size | BS-ZK-2 prove | BS-ZK-3 prove | BS-ZK-2 verify | BS-ZK-3 verify |
      |---|---|---|---|---|---|---|
      | 2 tables × 2^8 | 201,830–207,654 B | 228,038–234,566 B | 136–449 ms | 131–339 ms | 21–26 ms | 16–28 ms |
      | 2 tables × 2^12 | 323,220–332,884 B | 351,348–356,756 B | 1.50–2.14 s | 1.89–2.43 s | 20–43 ms | 25–37 ms |

      About +13 % bytes at 2^8 and +8 % at 2^12; proving roughly +15 % at 2^12 (noisy);
      verification within the noise.
12. **Open review points.** (i) PX proof size and time at BS-ZK-3, and the widest
    (n_fn = 2) proof against `MAX_PROOF_BYTES` (coordinator, W1 measurement window);
    (ii) the P-5 proof-length campaign must be re-run on BS-ZK-3 (agent 26);
    (iii) the committed-column margin (5,851 of 6,000): a table-width increase would
    need `MAX_COMMITTED_COLUMNS` raised (the figures hold to 65,536 columns);
    (iv) reversal only if agent 26's 4-codeword argument passes agent 50 before the freeze.
13. **Identity impact.** New `PARAMS_ID`; the consensus fingerprint changes (PX side and
    the node's); part of the v3 identity.
14. **Documentation.** `docs/zk.md` §9.3 (current set, eq. 16/17 wording, reason),
    §11 (not yet re-measured on PX proofs); `docs/proof-system.md` §2.
15. **Review status.** Implemented and tested by W1-CB-B3; red-team review (agent 50)
    pending.

---

## Canonical proof shape: exact hidden openings and one root per Merkle cap

Owner: W1-CB-B3 (zk). Items 22 W2 = 26 ZP-7 = 24 I2 (merged into one rule by the
decisions for agents 22, 24 and 26) and F24-2. Decision "Agent 50": the preprocessed-round
exception is derived from the proof structure; mutation tests at every position.

1. **Problem.** Two proof fields are still prover-chosen under Plonky3 0.7.0.
   (a) The hidden random-codeword openings (`opening_proof.0`, per round, matrix and
   point): `HidingFriPcs::verify` checks only how they nest and appends whatever values
   are present, so a prover picks the hidden width. That gives a second padding channel up
   to `MAX_PROOF_BYTES` (a valid proof of maximal verification cost), a proof-length
   fingerprint of the proving implementation, and lets a buggy wallet drop its own hiding
   silently. (b) `MerkleCap` derives `Deserialize` with any root count; the 0.7.0 MMCS
   verifier compares only root 0 (cap height 0) while the challenger absorbs all roots,
   so a prover can append roots to any commitment (about 31 bytes of free data per root).
   Neither is third-party malleability (both change the transcript), but each breaks "one
   honest proof, one encoding, a length fixed by the shape".
2. **Demonstrated failure.** The new tests fail on the parent commit (73372e9, without
   the rule): `every_hidden_opening_count_mutation_is_refused` (a proof with one more
   hidden value at round 0 decodes) and `every_merkle_cap_root_count_mutation_is_refused`
   (a cap with 0 roots decodes): `test result: FAILED. 3 passed; 2 failed` (log
   `C:/bszkeval/t-w1-zk/item2-before.log`).
3. **Prior art.** Plonky3 0.8 pins the hidden count
   (`HidingRandomOpeningValueCountMismatch`, 0 for a preprocessed round) and fixes
   `MerkleCap` deserialization (PR #2277); ZIP 244 and BIP 141 on proof malleability and
   transaction ids (BlackSilk keeps proofs inside the id, so it needs one encoding).
4. **Alternatives.** Leave both open and bound them by `MAX_PROOF_BYTES` (status quo,
   R3-6); or pin at decode time (chosen: O(proof) structural checks before any
   expensive work).
5. **Affected components.** `zk/src/lib.rs` (`check_canonical_form`, new
   `check_hidden_openings`), called by `decode_proof`, hence by every consensus path that
   decodes a PX proof (`tx/src/validate.rs`); no change to Plonky3 or to `verify`.
6. **Activation.** v3 genesis base rule.
7. **Compatibility.** Honest proofs from this code base are unaffected (they carry
   exactly `NUM_RANDOM_CODEWORDS` hidden values per point, none in the preprocessed round,
   and one root per cap). A proof from another prover implementation that uses another
   codeword count or cap height is refused.
8. **Reorg, wallet, mining, P2P.** A wrong expected count would reject honest proofs (a
   liveness split); mitigated by the honest-proof tests on both round structures. The
   derivation: the preprocessed round exists iff an instance opens `preprocessed_local`,
   and its position is Plonky3's `Pcs::PREPROCESSED_TRACE_IDX`; the Plonky3 verifier then
   checks the preprocessed widths against the AIRs, so a proof cannot move the exception.
   PX statements have no Plonky3-preprocessed tables (zkVM public data are periodic
   columns), so for PX every point carries `NUM_RANDOM_CODEWORDS`. Relay and mempool
   refuse such proofs at decode, as blocks do.
9. **Vectors.** The toy proofs of `zk/tests/proofs.rs`: 4 hidden rounds without, 5 with
   a preprocessed table (round 3 empty).
10. **Tests** (`zk/tests/proofs.rs`): `honest_proofs_have_the_canonical_hidden_openings_and_caps`;
    `every_hidden_opening_count_mutation_is_refused` (every position of two proofs,
    +1 and −1: 38 positions; a preprocessed round filled with codewords; a round too
    many and too few; the honest proofs still verify);
    `every_merkle_cap_root_count_mutation_is_refused` (0, 2 and 3 roots in each of the
    four batch commitments and every FRI commitment: 18 mutations).
11. **Suite results.** `cargo test --release -p blacksilk-zk --test proofs`: 15 passed,
    0 failed (log `C:/bszkeval/t-w1-zk/item2-after.log`). PX consensus tests, which decode
    real PX proofs through this rule, are run by the coordinator after merge.
12. **Open review points.** (i) Run the PX suites (`tx px_consensus`, `px proof`,
    `unified`) to confirm honest PX proofs pass the rule; (ii) the adversarial
    verifier-cost measurement (ZK-F4 / F22-3) should now use an invalid proof, since a
    valid padded one is refused; (iii) at a Plonky3 0.8 migration keep both rules as
    belt and braces.
13. **Identity impact.** Rule-set change only; no constant or fingerprint entry changes.
14. **Documentation.** `docs/proof-system.md` §5 (C3, C4) and §7; `zk/src/params.rs`
    module text (the count is now pinned).
15. **Review status.** Implemented and tested by W1-CB-B3; red-team review (agent 50)
    pending.
