# v3 consensus changes: records

Status: **records of consensus changes to the v3 genesis base rule set, made before the
v3 freeze.** The testnet v3 has not launched and no final genesis exists; each change
here is part of the rule set from genesis, with no activation height. This is internal
engineering work, not an audit. Each section follows the 15-step discipline of the
phase-2 brief: problem, demonstrated failure, prior art, alternatives, affected
components, activation, compatibility, reorg, wallet, mining and P2P implications,
vectors, regression tests, suite results, and open review points.

Commits touching a consensus path cite a section here in a `Consensus-Change:` trailer
(.github/scripts/consensus-gate.sh).
Headings are cited verbatim by commit trailers (as `§N` or as the heading anchor), so
they are never renamed. Index:

- §1 D8 option B (tx; W1-CB-B1a)
- §2 CLSAG `D ≠ identity` (crypto, tx; W1-CB-B1a)
- §3 RT-14 genesis id in the signature domain (tx; W1-CB-B1a)
- BS-ZK-3: eight random codewords (zk; W1-CB-B3)
- Canonical proof shape (zk; W1-CB-B3)
- Soundness figures, COLLISION_BITS = 122 (zk; W1-CB-B3)

New sections are appended at the end.

---

## §1 D8 option B: no cross-transaction one-time-key uniqueness (former rule C4)

Decision: D8, option B (decisions.md "D8 / C4: DECIDED, option B"); dossiers 13 and
17, with SX1 correction 1 and red-team RT-10 (dossier 50 §5.1).

**1. Problem.** Rule C4 required every output one-time key `O` to be new on the chain and
in the block. `O` is public as soon as a transaction is relayed and is chosen freely by
its sender, so anyone who saw a pending transaction (a Dandelion stem relay, a miner, any
well-connected node) could put a copy of one of its keys into a valid transaction of
their own, for one fee, and get it mined first: the victim's transaction was then invalid
on that branch for good (`DuplicateOneTimeKey`). The mempool's first-seen rule on output
keys (`ConflictKind::OutputKey`) kept the same veto as policy. It was repeatable against
every rebuild, and each forced rebroadcast of the same key images is one more stem
sample of the same origin (dossier 13 F13-1, F13-2).

**2. Demonstrated failure** (tests written first, run on the base commit `cef9013`):
- `chain/tests/mempool_conflicts.rs`, rewritten as the inverted attack tests: 7 of 9 fail
  on the base, each with the attack succeeding: `a_copy_mined_first_leaves_the_victim_valid`
  (the victim is evicted from the pool once the copy is mined),
  `after_a_restart_the_victim_confirms_after_its_copy` (`Invalid(DuplicateOneTimeKey)`),
  `a_block_holding_two_transactions_sharing_an_output_key_is_valid`
  (`Body(Tx { index: 2, error: DuplicateOneTimeKey { output: 1 } })`), and the pool
  cases (`Conflict`). The key-image and namespace cases pass on both.
- `chain/tests/revalidation.rs::an_output_key_copied_by_another_mined_transaction_leaves_the_victim_valid`
  fails on the base (the victim and the copy share the `OutputKey` conflict key).
- `chain/tests/block_rules.rs`: the two formerly ignored D8 tests, flipped, fail on the
  base (`DuplicateOneTimeKey` instead of the transaction's own later rule; the replayed
  coinbase key rejected).
- `tx/tests/output_key_uniqueness.rs::property_repeats_across_transactions_are_valid_and_within_one_are_not`
  fails on the base at its first valid case (`Tx { index: 2, error: DuplicateOneTimeKey }`).
- Wallet: `one_output_is_credited_per_key_image_the_largest_then_the_lowest_index` and
  `a_later_duplicate_replaces_the_credited_output_only_if_larger` fail on the base (two
  outputs credited for one key image).

**3. Prior art.** Monero has no output-key uniqueness rule of any kind (`check_tx_outputs`,
`check_outs_valid`) and handles the burning bug in the wallet (keep the largest amount per
key image). Carrot requires output keys to be unique within a transaction only (§4.3)
and binds derivations to an input context (§7.2, §9.1.4). Zcash's ZIP 227 derives issued
notes' ρ from a unique transaction element instead of a ledger uniqueness rule, naming
"road-blocking" as the risk of copyable unique values (zips#955). Sources: dossier 13 §9.

**4. Alternatives.** Keep C4 (rejected: a free, repeatable veto the Dandelion embargo
cannot repair); option C, uniqueness on `(O, Cm)` (rejected: keeps the state, still lets
a miner grief clear PX payouts through a coinbase output, F13-5); keep plus policy
(rejected: miners still win). Dossier 13 §4 step 4.

**5. Affected components.**
- `tx/src/validate.rs`: C4 removed from the mempool paths, `revalidate_after_extension`
  and block validation (chain and within the block, and the coinbase loop);
  `ChainView::has_one_time_key`, `TxError::DuplicateOneTimeKey` and
  `BlockError::CoinbaseDuplicateOneTimeKey` removed; C2 is `check_key_images`.
- `tx/src/state.rs`: the one-time-key set and its undo removed.
- `tx/src/px.rs`: `PxDuplicateOutputKey` is now the only rule rejecting a key shared by a
  PX transaction's hidden outputs and payouts (comment).
- `chain/src/mempool.rs`: `ConflictKind::OutputKey` removed.
- `wallet/src/wallet/sync.rs`: one credited output per key image (largest amount, then
  lowest index); `wallet/src/wallet/px_flows.rs`: comment that decoys are not filtered.
- Kept unchanged, and pinned by tests: within-transaction distinctness for every kind
  (T6 sort for transfers and deploys, B7 sort for coinbases, the list sorts and
  `PxDuplicateOutputKey` for PX transactions). No new error variant.
- Not affected: encodings, transaction ids, signature messages, `h_tx`, the PX kernel,
  `CIRCUIT_ID`, key derivations.

**6. Activation.** v3 genesis base rule set, unconditionally from genesis; no `Epoch`
field. After launch this would be a relaxation (blocks that were invalid become valid),
so a hard fork through the schedule.

**7. Compatibility.** No encoding changes; every existing transaction vector is
unchanged. Only blocks holding a cross-transaction key repeat change verdict (invalid to
valid). Third-party wallets must run the anchor check (§3.3 step 5); it was already
normative (transactions.md §12.5). The consensus fingerprint gets a rule-revision entry
from agent 40 (not in this commit).

**8. Reorg, wallet, mining and P2P implications.**
- Reorg: a transaction and a copy of its key are valid on both branches; a returned
  transaction re-enters the pool. Undo no longer maintains a key set (outputs are
  records by global index). Tested: `reorganizations_keep_both_the_victim_and_the_copy_valid`,
  the property test's undo/re-apply.
- Wallet: Lemma 2 (transactions.md §3.1) means the Janus check credits only the genuine
  output, whatever the order; defence in depth credits one output per key image, the
  largest amount then the lowest index (RT-10), with a local warning. Decoy selection
  does not filter duplicates (F13-7). A copy mined before the genuine output is tested
  at the chain level and in the wallet.
- Mining: a template may hold a transaction and its copy; both are valid. Key-image,
  nullifier and contract-id conflicts still apply.
- P2P: copies are ordinary fee-paying transactions; no score changes (the contextual
  `DuplicateOneTimeKey` is gone). The stem pool's conflict keys never included output
  keys (`p2p/src/net/stem.rs::stem_keys`), so it needs no change.

**9. Vectors.** As Rust tests in the v3 rule set (the R14 conformance set does not exist
yet): (i) two transactions sharing `O` with different `Cm` in one block: valid
(`a_block_holding_two_transactions_sharing_an_output_key_is_valid`); (ii) a coinbase
repeating an on-chain key verbatim, same `(O, R, anchor)`: valid
(`b4_a_coinbase_key_already_on_chain_is_valid`); (iii) a within-transaction repeat for
every kind: invalid, stateless (`tx/tests/output_key_uniqueness.rs`,
`b7_a_coinbase_repeating_a_one_time_key_is_rejected`,
`px_output_and_payout_sharing_a_key_is_stateless`); (iv) the fingerprint entry: agent 40.

**10. Regression tests.** Listed in step 2, plus
`a_one_time_key_already_on_chain_does_not_invalidate_a_transfer` (tx adversarial), the
mempool unit tests (`output_one_time_keys_are_not_conflict_keys`,
`a_shared_output_key_is_not_a_conflict_across_all_kinds`,
`a_block_creating_a_pooled_output_key_evicts_nothing`, the randomized invariants), and
`a_copy_mined_before_the_genuine_output_is_not_credited` (wallet). The randomized
property test uses a seeded ChaCha stream, not proptest, which is not yet a dependency.

**11. Suite results.** See the commit message of this change and the final report of
work item CB-B1a (exact commands and counts).

**12. Open review points.**
- Red team (50) reviews the final diff, in particular the claim that no other rule's
  argument depended on C4 (`revalidate_after_extension` and the proof cache do not).
- Lemma 2 is an internal argument over BlackSilk's own Janus construction; it has had no
  external review.
- Not done here: the P2P end-to-end stem test (dossier 50 §5.1 test 8) and the decoy
  chi-square test (test 5); the stem pool needs no change, and decoy selection never
  looks at keys (a comment pins the intent).
- `docs/contracts.md` (the non-integrated Wasm research engine) still describes a C4
  extension to private notes; left to its owners.

---

## §2 CLSAG: the auxiliary image `D` must not be the identity

Decision: agent 15 W1 (decisions.md "Agent 15 (CLSAG)"); dossier 15 finding C1.

**1. Problem.** `clsag::verify` rejected `I = identity` but not `D = identity`.
`D = z·Hp(P[π])` is the identity exactly when `z = 0`, i.e. when the pseudo-output equals
the real member's commitment (`C' = Cr[π]`), which reveals the real input to everyone.
Monero (`verRctCLSAGSimple`, "Bad auxiliary key image") and monero-oxide (`InvalidD`)
reject it, so a Monero-derived second implementation would split from BlackSilk on such a
signature. Soundness is not affected (`I ≠ identity` is enforced).

**2. Demonstrated failure** (tests first, on the item-1 commit, which does not touch
CLSAG): `crypto/tests/clsag_vectors.rs::d_identity_is_rejected` (un-ignored) fails: the
`z = 0` reference signature is accepted. `clsag::tests::a_zero_commitment_secret_is_refused`
fails: `sign` signs `z = 0`. `tx/tests/adversarial.rs::t11_an_identity_auxiliary_image_is_a_stateless_fault`
fails: the error is the contextual `InvalidSignature { input: 0 }`.

**3. Prior art.** Monero since CLSAG (2020) and monero-oxide reject `D = identity`; the
CLSAG paper draws secrets from `(F_p^*)^d`, so an honest `D` is never the identity.
Monero's zero-challenge check is not adopted (decisions, C6).

**4. Alternatives.** Wallet-only refusal of `z = 0` (not enough for conformance); a rule
"`C'` differs from every ring commitment" (16 comparisons per input for no extra
security). Chosen: the verification rule plus the signer refusal (dossier 15 P1).

**5. Affected components.** `crypto/src/clsag.rs` (`verify` rejects `D = identity`;
`sign` returns `ClsagError::ZeroCommitmentSecret`); `tx/src/validate.rs` (T11
`check_aux_images` in `check_structure`, new stateless `TxError::AuxKeyImageIdentity`);
`tx/src/px.rs` (the same check in `check_px_structure`; deploys go through
`check_structure`).

**6. Activation.** v3 genesis base rule set, from genesis. A tightening; after launch it
would need an activation height.

**7. Compatibility.** No honest transaction changes: the builder draws pseudo-output
masks at random, so `z = 0` occurs with probability about 2^-252. All pinned vectors are
unchanged except the renamed key prefix of the `z = 0` vector
(`reject_pending_cb_b1.` to `reject.d_identity.`; values unchanged).

**8. Reorg, wallet, mining and P2P implications.** None for reorgs and mining. The error
is stateless (decidable from the transaction alone), so a peer relaying such a
transaction is penalized, like `KeyImageIdentity`. Wallets: `sign` refuses `z = 0`.

**9. Vectors.** `reject.d_identity.*` in `crypto/tests/vectors/clsag.txt` (pinned inputs,
intermediates and signature); the reference verifier in `crypto/tests/clsag_vectors.rs`
has the rule, and `d_identity_vector_values` shows that the §6.1 loop alone closes on it.

**10. Regression tests.** Step 2's three tests, plus
`tx/tests/validation_order.rs::px_and_deploy_identity_auxiliary_images_are_stateless`
(PX and deploys, no chain query) and the classification list
(`every_error_variant_is_classified`, 36 variants).

**11. Suite results.** In the commit message and the CB-B1a final report.

**12. Open review points.** None specific; the rule follows Monero exactly.

---

## §3 RT-14: the genesis id in every signature domain

Decision: red-team RT-14, adopted for v3 (decisions.md "Agent 50", RT-14; owner CB-B1).

**1. Problem.** The v1 signature messages (`sig_message` of transfers, deploys and PX
transactions) and the PX binding `h_tx` committed to `LE32(network_id) ‖ LE32(branch_id)`
only. A rehearsal chain and the final chain (or a release candidate, or a retired
identity) can share both ids. Replay of a transaction between them was then blocked only
by chain state: ring indices and PX anchors that almost surely differ, not by the
signature itself.

**2. Demonstrated failure** (test first, on the item-3 commit `efd1f6d`):
`tx/tests/upgrade.rs::a_transaction_signed_for_another_genesis_is_invalid` fails: a
transfer signed under regtest's rules validates (`Ok(())`) under the rules of a chain
identical but for its genesis timestamp (same network id and branch id).

**3. Prior art.** EIP-155 binds Ethereum transaction signatures to a chain id; Zcash's
ZIP 244 digests include the consensus branch id. BlackSilk's P2P session key already
binds the genesis id (p2p.md, the session key `k`; test `different_genesis_ids_cannot_talk`).

**4. Alternatives.** Keep relying on state mismatch (RT-14 rated it Info for that reason);
a fresh network id for every rehearsal (already the policy, testnet-v3-genesis: reserved
rehearsal ids) but not enforced by the signature. Chosen: bind the genesis id, free at the
v3 reset.

**5. Affected components.** `tx/src/params.rs`: `SigDomain` gains `genesis_id` and
encodes as `LE32(network_id) ‖ LE32(branch_id) ‖ genesis_id` (40 bytes,
`SIG_DOMAIN_BYTES`); `TxRules` gains `genesis_id`, filled by `TxRules::at_height` from
`ChainParams::genesis_id`, so every path (node, mempool, templates, wallet, miner-side
tools) gets it from the chain parameters. `node/src/fingerprint.rs`: the `TxRules`
destructuring names the new field (its value is already the manifest's
`chain.genesis_id`; no fingerprint value changes). Kernel, program ids and `CIRCUIT_ID`
are unaffected: `h_tx` is a public input of the proof, absorbed in the transcript, never
a guest input (reviews/v3-upgrade-mechanism.md §1 checked this for the branch id; the
genesis id enters in the same place).

**6. Activation.** v3 genesis base rule set. It changes every signature message and
every PX statement, so after launch it would need a new branch id; before the freeze it
is free.

**7. Compatibility.** Every existing signature and PX proof becomes invalid (they bind
the old 8-byte domain). No encoding changes: transaction bytes and ids keep their format;
only the signed and proved messages change. Pinned vectors: none pin a v1 signature
message or an `h_tx` (the CLSAG vectors sign fixed messages), so none change; the
fingerprint pins do not change.

**8. Reorg, wallet, mining and P2P implications.** None for reorgs and mining. Wallets
sign with `Wallet::next_block_rules`, built from the wallet's chain parameters, so a
wallet and its node agree when their genesis ids agree (the wallet already refuses a
node with another genesis id, RT-15). P2P: a replayed transaction from another chain
fails C3 (contextual `InvalidSignature`, not penalized, like a transaction from another
epoch).

**9. Vectors.** `domain_bytes_are_network_then_branch_then_genesis` pins the 40-byte
layout; `every_message_and_the_px_binding_commit_to_branch_network_and_genesis` checks
that each of the four domain-bound hashes changes with the genesis id alone.

**10. Regression tests.** Step 2's test (the replay is refused with `InvalidSignature`,
and the PX binding and message differ), plus the two above.

**11. Suite results.** In the commit message and the CB-B1a final report. PX-proving
tests (fresh proofs over the new `h_tx`) are run by the coordinator after the merge.

**12. Open review points.** Agent 40's rule-revision list should record the domain
layout change (the fingerprint's constant list cannot see it).


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
      binary; machine: 4-core/8-thread i7-6700, 16 GB, Windows 10, rustc 1.98.1,
      release profile; binaries built from 7163f12 (4 codewords) and from this change;
      the machine was shared with other agents' builds, so times are noisy; raw output
      `C:/bszkeval/t-w1-zk/toy-measure-item1.log`):

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

---

## Soundness figures: COLLISION_BITS = 122, post-ZK domain, independent calculator

Owner: W1-CB-B3 (zk). Items 25 W1, W2, W3 (part), 24 I4, I5; decisions "Agent 24"
(`COLLISION_BITS` = 122 citing ePrint 2026/089), "Agent 25" (headline, W2 in `zk` as a
test module), "Agent 50" (R2-C6 wording: Theorem 3 only; our evaluation; argued, not
proven; "extractable", not "binding").

1. **Problem.** (a) `COLLISION_BITS` = 123 was the generic birthday bound of an
   8-element digest (8·log2 p / 2 ≈ 123.6). The first analysis of Plonky3's Merkle tree
   (ePrint 2026/089) shows the `TruncatedPermutation` node compression is not
   collision-resistant on its own and proves extractability with an overwrite-sponge
   leaf hash at (4q² + 2q)/(|H| − 1) (Theorem 3), about 2^122.6 for |H| = p^8 (our
   evaluation). The documented "≥ 123 Johnson bits" was therefore about one bit
   optimistic, and presented a hash bound as a proximity-gap figure. (b) `security()`
   passed the pre-ZK trace height to `p3-security`, whose input is the committed
   (post-ZK) size (R4-01). (c) No second calculator checked the figures; nothing
   asserted which term binds; nothing enforced the ≤ 2^27 domain that uniform query
   sampling needs.
2. **Demonstrated failure.** (a) By calculation: `collision_bits_is_the_floor_of_the_merkle_extractability_bound`
   gives log2 q = 122.6 < 123. (b) None in the figures: at the correct domain the
   reported bits are unchanged (unique decoding 105, query-bound and domain-independent;
   Johnson capped by the commitment term); the input was wrong, not the output
   (dossier 25 §3.1, now tested). (c) Absence of a check, not a failure.
3. **Prior art.** ePrint 2026/089 (ACM CCS 2026) Theorem 3; `ethereum/soundcalc`
   (UDR/JBR formulas; capacity regime removed); BCIKS20 (ePrint 2020/654), BCHKS25
   (ePrint 2025/2055); ethSTARK (ePrint 2021/582); Plonky3 PR #2048 (0.7 calculator
   accounting, none of which applies on BlackSilk's call path, dossier 25 §3.7).
4. **Alternatives.** Keep 123 and fix only the docs (rejected by decision "Agent 24":
   the fingerprint changes before the freeze anyway); a wider digest to reach 128 (a
   new hash configuration; not needed for the ≥ 120 target).
5. **Affected components.** `zk/src/params.rs` (`COLLISION_BITS`, `security`, new
   `security_report`, two `const` assertions); `zk/tests/soundness_calc.rs` (new);
   `zk/tests/proofs.rs` (`toy_shape_meets_the_security_floor` asserts both floors). The
   consensus fingerprint entry `zk.COLLISION_BITS`. No proof byte, transcript or
   validation rule changes: `COLLISION_BITS` enters only the calculator.
6. **Activation.** v3 genesis base rule (fingerprint only).
7. **Compatibility.** Proofs are unaffected. Two builds that differ only here would show
   different consensus fingerprints but agree on every proof.
8. **Reorg, wallet, mining, P2P.** None.
9. **Vectors.** `COLLISION_BITS` = 122 = floor((8·log2 p − 2)/2); at the largest shape
   (degree bits 23, 5,000 constraints of degree 8, 65,536 batched functions): unique
   decoding 105.65 bits (89.65 statistical + 16 grinding; p3-security floor 105),
   Johnson reported 122; algebraic Johnson 175.7 (BCHKS25, m = 34) and 159.6 (BCIKS20
   only, m = 4). Pinned by `headline_figures_at_the_largest_shape`.
10. **Tests.** `params::tests::every_shape_within_limits_meets_both_security_targets`
    (1,440 shapes, degree bits 9..=23: both floors; the report equals `security`; the
    unique-decoding binding term is the low-degree test, the Johnson binding term is the
    commitment term; Johnson = `COLLISION_BITS`); `zk/tests/soundness_calc.rs`:
    `the_independent_calculator_agrees_with_p3_security` (±1 bit UDR, exact Johnson;
    non-query terms ≥ 200 bits including LogUp and a 32-table DEEP union; Johnson
    algebraic ≥ 150 under BCHKS25 and BCIKS20 alone; both floors),
    `headline_figures_at_the_largest_shape`,
    `collision_bits_is_the_floor_of_the_merkle_extractability_bound`. Compile time:
    `MAX_LOG_HEIGHT + 1 + LOG_BLOWUP ≤ 27`, `TARGET_JOHNSON_BITS ≤ COLLISION_BITS`.
11. **Suite results.** Independent calculator over 1,440 shapes: UDR ≥ 105.58 bits
    (query-bound; other terms ≥ 205.3); Johnson algebraic ≥ 175.7 (BCHKS25), ≥ 159.6
    (BCIKS20 only); reported Johnson = 122. `cargo test --release -p blacksilk-zk`:
    23 passed, 0 failed, 1 ignored (the timing test). The PX-side fingerprint pin fails
    as expected (item "BS-ZK-3", 9).
12. **Open review points.** (i) The adaptation of Theorem 3 to BlackSilk's salted tree
    is argued, not proven (agent 50); (ii) mixed-height FRI inputs have no published
    analysis; (iii) the zkVM shape tests (`zkvm/tests/multi.rs`, `vm.rs`) still assert
    only `johnson_bits ≥ MIN_PROVEN_BITS` (R4-12, owner 23); (iv) the calculator
    example `zk/examples/param_study.rs` still passes the pre-ZK height (outside this
    change's file scope; figures unaffected).
13. **Identity impact.** Consensus fingerprint entry `zk.COLLISION_BITS` 123 → 122.
14. **Documentation.** `docs/zk.md` §9.1 (P4), §9.3 (grid, independent calculator,
    headline, commitment term, unmodelled terms); `docs/proof-system.md` §2 (R5, R6,
    security figures) and §7.
15. **Review status.** Implemented and tested by W1-CB-B3; red-team review (agent 50)
    pending.
