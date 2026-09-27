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
- daa-lwma75-warm (consensus; W1-CB-A)
- f05-header-check-order (consensus; W1-CB-A)
- genesis-beacon (consensus; W1-CB-A)
- rt1-unknown-upgrade-pow (consensus, p2p; W1-CB-A)
- exact-v1-fee (tx; W1-CB-B1b)
- expiry-guard (chain mempool policy; W1-CB-B1b)
- r12-2 (tx, chain; W1-CB-B1b)
- tree-capacity (px, tx, chain; W1-CB-B1b)

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

---

## daa-lwma75-warm: LWMA-75 with a counted clock of step T/2, warmed over 11 blocks

Owner: W1-CB-A (consensus bundle). Decisions: "Agent 03", "DAA update", "DAA DECIDED",
"DAA FINAL (after RT-DAA)". Rule id `lwma1-n75-step-t/2-warm11-cap6t-floor20`
(`consensus::difficulty::DIFFICULTY_RULE_ID`).

1. **Problem.** The pre-v3 rule (LWMA-60, counted clock `prev + 1`) lets a private branch
   with compressed timestamps raise its own difficulty by about 17% per block (5–20× per
   block near genesis), concentrating the branch's work in a few very hard blocks. Under
   most-work fork choice, the probability that such a branch overturns `z` confirmations
   stops shrinking with `z` (Bahack's difficulty-raising attack; dossier 03-F1, High). The
   first replacement candidate (LWMA-75 with a counted-clock step of `T/2`, W0-03b) then
   failed the emission criterion under the red team (RT-DAA RT-1): the clock restarted at
   the raw stamp of each window's oldest block, so a low stamp there let a window count
   real time its predecessor had not counted.
2. **Demonstrated failure.**
   - 03-F1 on the pre-v3 rule: `tools/daa-sim/tests/f1.rs`
     (`f1_difficulty_raising_attack_reproduces_on_the_current_rule`) and the tables in
     `docs/evidence/daa-sim-2026-09-27/`.
   - RT-1 on the unwarmed candidate: `tools/daa-sim/tests/redteam.rs`
     (`anchor_lag_attack_and_fix`, `periodic_attack_and_fix`).
   - On the consensus code at base `32054d4`, the red-team golden case (87 on-target
     blocks at D = 10^6, the window's oldest stamp 1 300 s low) evaluated with N = 75
     returns the unwarmed value: `consensus/tests/lwma_warm.rs`
     `window_start_lag_golden_case` failed with `left: 998248, right: 999824`.
3. **Prior art.** Bahack 2013 (arXiv:1312.7013); Garay–Kiayias–Leonardos, CRYPTO 2017
   (the dampening filter τ); zawy12 LWMA-1 (issue #3) and timestamp attacks (issue #30);
   BCH aserti3-2d; Zcash §7.7.3 (averaging window with damping); Monero's sorted and cut
   window. Full citations in dossier 03 §8.
4. **Alternatives.** 29 candidates in the selection study (`selection.md`): symmetric
   solve-time clamps, rise and fall caps of 2–3%, weighted-sum floors, ASERT with
   half-lives of 45 min to 6 h, an LWMA/ASERT hybrid, signed solve times, and the counted
   clock with steps T/3 to 2T/3 at N = 60, 75, 90. Only LWMA-75 with step T/2 met every
   criterion on two seeds. The red team compared warm-up lengths 0, 1, 11 and 75
   (`anchor_ablation`): 11 removes the anchor-lag gain, 75 buys nothing more.
5. **Affected components.**
   - `consensus/src/difficulty.rs`: the rule, `DIFFICULTY_WINDOW` (75),
     `DIFFICULTY_WARMUP` (11), `difficulty_ancestors(N)` (N + 1 + 11 = 87),
     `clock_step`, `DIFFICULTY_RULE_ID`.
   - `consensus/src/params.rs`: `difficulty_window = DIFFICULTY_WINDOW` on every network;
     `ChainParams::difficulty_ancestors()`, the one ancestor count.
   - `consensus/src/chain.rs`: both callers, `required_difficulty` (validation, templates,
     replay and submission all go through `HeaderChain`) and `overlay_context` (the batch
     pre-check of header sync), fetch `difficulty_ancestors()`. No other crate computes a
     difficulty (repository-wide grep for `next_difficulty` and `difficulty_window`).
   - `tools/daa-sim`: the pre-v3 rule is frozen as `rules::legacy_next`, so the committed
     evidence stays reproducible; `ConsensusV3` calls the new consensus rule.
6. **Activation.** A v3 genesis base rule from height 1 on every network. No height
   switch.
7. **Compatibility.** Every difficulty after block 1 differs from the pre-v3 rule, so
   no pre-v3 chain validates under v3. The testnet v2 identity is retired and the v3
   genesis is not yet generated; regtest chains are local and are recreated. Genesis ids
   are unchanged (the rule is not in the header).
8. **Reorg, wallet, mining and P2P implications.**
   - Reorg: the rise per block is bounded at `⌊S·T/(step·n)⌋` (2× the window average), so
     a compressed branch cannot concentrate work; the residual race excess at q = 0.4 is
     left to the park-on-deep-reorg policy (02).
   - Mining: the template difficulty comes from the same function; miners need no change.
   - P2P: the claimed-work gate is unchanged. The presync bound (31) must be re-derived
     with a rise of at most 2× the window average per block.
   - Wallet: none (no wallet code computes a difficulty).
   - Liveness: after a genesis gap the difficulty recovers additively at low difficulty
     (+8 per block from 16 in `genesis_to_launch_gap_is_absorbed_by_lwma`). Settling after
     100× or 1000× hash-rate increases takes a few hundred blocks (`redteam.md`, RT-6).
9. **Vectors.**
   - `consensus/tests/data/lwma_vectors.txt`: 159 vectors from
     `tools/vectors/lwma_warm.py`, a standard-library Python script written from the spec
     text (docs/consensus.md §4), not from the Rust. It covers steady state (7
     difficulties, 4 targets), 2×/10× up and down (whole window and step changes of 1–75
     blocks), genesis-near windows of 1–89 ancestors, the 1-second-block run on regtest
     and testnet timing (including a chain grown from D = 1), the genesis gap (4 gaps and a
     40-block recovery), warm-up edge cases (low and high stamps at positions 0–20, the
     88th ancestor ignored, partial warm-ups of 77–86), the 6T cap and step boundaries,
     u128 extremes (difficulties and stamps at u64::MAX, T = 2^51 − 1, T = 1, 2, 3), and 40
     random adversarial histories. `--check` regenerates and compares.
   - The red-team golden case: this exact configuration (87 ancestors) takes the warm-up,
     so **999 824** applies; the unwarmed value 998 248 applies only when the 11 warm-up
     ancestors are absent (vector `redteam_lag_1300_nowarm`, 76 ancestors). Note: the
     stamp sequence is a function vector; in a steady chain the MTP rule would refuse a
     stamp that low (lowest valid: `ts[5] + 1`), and an attacker reaches the same lag with
     earlier forward stamps.
10. **Tests.**
    - `consensus/tests/lwma_warm.rs`: `window_start_lag_golden_case`,
      `independent_vectors` (all 159).
    - `tools/daa-sim/tests/consensus_differential.rs`:
      `consensus_equals_the_warmed_redteam_rule`: consensus `next_difficulty` (on the whole
      history and on exactly the 87 fetched ancestors) and `ConsensusV3` equal
      `redteam::Anchored { window: 75, warm: 11 }` on 12 000 random histories (lengths
      1–200, 76–88 and 1–88 emphasized; T from 1 s to 2^40 s; stamps at the MTP and FTL
      edges, equal, backwards, and near u64::MAX; difficulties up to u64::MAX). 2 059 of
      them differ from the unwarmed rule, so the test discriminates.
      `every_network_uses_the_measured_window`.
    - `consensus/src/difficulty.rs` unit tests (exact steady state, 2× and ½×, the step
      bound, ancestor count, rule id names the constants).
    - `consensus/src/chain.rs`: `precheck_agrees_with_sequential_validation_and_computes_no_pow`
      now mutates at positions 11, 12, 74–77 and 86–88 (the window and warm-up edges).
    - Re-derived expected values (each changed value explained):
      - `consensus/tests/golden.rs`: N = 60 → 75 throughout. Steady state and 2×/½× stay
        exact (hand derivations with Σi = 2 850). `lwma_only_the_last_window_counts`: the
        warm-up now reads 11 blocks before the window, so the steady case needs 86 steady
        blocks, and a new assertion pins 10 092 for 7 s blocks just before the window
        (clock 583 s ahead). `lwma_window_fill_phase`: 400 → 200 and 2 000 → 200 (a 30 s
        or 0 s solve time counts one step of 60 s); 844 unchanged (every solve time ≥ 60).
        `lwma_out_of_order_timestamps`: 131 → 141 (hand derivation in the test) and
        5 083 → 1 000 (every solve time counts one step). The floor test becomes
        `lwma_increase_is_bounded_by_the_step`: 101 666 → 20 000 (the floor no longer binds;
        the step does). Clamps unchanged. `lwma_mixed_window` (now 75 blocks): 914 from the
        script. `header_chain_difficulty_and_mtp_golden`: all 150 difficulties and the total
        work (242 100 → 153 943) from the script; the MTP values are unchanged, which
        cross-checks the script's chain model.
      - `tools/genesis/tests/genesis.rs` (`genesis_to_launch_gap_is_absorbed_by_lwma`): block 2
        stays 16 (the 6T cap); the climb is now pinned exactly (24, 32, 40, 48, 56; D0/2 at
        k = 4) instead of "within the window".
      - `tools/daa-sim`: `lwma60_is_the_pre_v3_rule` (was `lwma60_is_the_consensus_call`),
        `generalised_default_equals_the_pre_v3_rule`, the new `consensus_v3_is_the_consensus_call`,
        and `constants_match_consensus` (window 75).
11. **Suite results** (this change, release, `--locked`, Windows x86_64, rustc 1.98.1):
    - `-p blacksilk-consensus`: 59 passed (lib 38, golden 17, lwma_warm 2,
      randomx_end_to_end 2).
    - `-p blacksilk-daa-sim`: 37 passed (lib 23, consensus_differential 2, f1 2, redteam 5,
      selection 5).
    - `-p blacksilk-genesis`: 10 passed.
    - `-p blacksilk-node`: 40 passed, 2 ignored (after re-pinning the fingerprints).
    - `-p blacksilk-p2p` (skipping the two PX-proving tests): 80 passed, 4 ignored.
    - `-p blacksilk-chain -- --skip restart_rebuilds_the_px_state_exactly`: 111 passed,
      **1 failed**, 2 ignored: `chain/tests/revalidation.rs`
      `a_shorter_heavier_reorg_makes_a_ring_member_immature`. Its construction (80
      one-second blocks, then three 60 s blocks against a two-block fast rival) no longer
      lowers the difficulty: the one-second blocks put the counted clock about 320 s ahead
      of the stamps, and 60 s gaps only repay that lag (difficulties `[84, 86, 88, 90]`),
      which is the rule working as intended. The file belongs to branch w1-tx-a, so it is
      not edited here. A re-derived construction (four 1 000 s blocks against a
      three-block one-second rival, deepest reorg 4; work 260 against 264, found with
      `lwma_warm.py`) passes all 4 tests of the file when applied locally; it is handed
      to the coordinator.
12. **Open review points.**
    - The floor `n²T/20` cannot bind under this rule (`L ≥ step·n(n+1)/2`), so mutants of
      the floor survive by construction: to be justified in 42's mutation run.
    - The hopper criterion is relaxed to ±5 points for the testnet only (decision "DAA
      FINAL"); reopen before any mainnet.
    - 31 must re-derive the presync bound under the 2× per-block rise.
    - Fingerprint: `DIFFICULTY_RULE_ID` is not yet in the manifest (see step 13).
13. **Identity impact.** The consensus fingerprint's `chain.difficulty_window` entry
    changes (60 → 75) on every network, so the pinned fingerprints in
    `node/tests/deploy_configs.rs` are re-pinned in this change. The rule id is **not**
    wired into `node/src/fingerprint.rs` (owner 40, the single fingerprint-v3 commit): it
    belongs in `chain_entries` next to `chain.difficulty_window`, as a text entry
    `chain.difficulty_rule = DIFFICULTY_RULE_ID` (with `DIFFICULTY_WARMUP` if the
    manifest keeps numeric entries), and `lwma_warm.rs`'s golden case is a candidate
    `rules.samples` entry.
14. **Documentation.** `docs/consensus.md` §1 (N = 75), §4 (rewritten: the rule, exact
    semantics, deviations from zawy's reference, known limits, vectors) and §5 (the
    regtest `N·T/20` figure), in this change.
15. **Review status.** Selection (W0-03b) and red team (RT-DAA) done on the harness
    rule; this change is shown equal to the red team's `Anchored` rule by the differential
    test. The consensus implementation has not had a separate adversarial review.

---

## f05-header-check-order: permanent header rules before the future time limit

Owner: W1-CB-A. Decisions: "Agent 01" (F-05 reorder accepted before the freeze).

1. **Problem.** `check_rules` checked the future time limit (FTL, not permanent: it
   depends on the local clock) before the difficulty rule (permanent). A header with a
   wrong difficulty and a far-future timestamp was reported as
   `TimestampTooFarInFuture`: unpenalized and re-evaluated later. A peer could wrap any
   permanently invalid header this way to avoid scoring (dossier 01 F-05, Low).
2. **Demonstrated failure.** On base `32054d4`, the new vector test
   `chain::tests::header_check_order_vectors` failed at its first row:
   `difficulty + future: TimestampTooFarInFuture { limit: 1700000680, got: 1700010320 }`.
3. **Prior art.** Bitcoin Core `ContextualCheckBlockHeader`: `bad-diffbits`,
   `time-too-old` and the time-warp checks are `BLOCK_INVALID_HEADER` first, then
   `time-too-new` as `BLOCK_TIME_FUTURE`.
4. **Alternatives.** Keep the order and document it (a second implementation must copy it
   to score identically); or return every failing rule (a larger API change). Rejected:
   the reorder is smaller and makes the scoring order-independent of clock skew.
5. **Affected components.** `consensus/src/chain.rs::check_rules` (the single definition
   used by `validate` and `precheck_batch`). New order: version, height, difficulty, MTP,
   FTL, then PoW in `validate`.
6. **Activation.** v3 genesis base rule set (policy-visible only).
7. **Compatibility.** Validity is unchanged: a header is valid iff every rule holds, and
   the conjunction does not depend on the order. Only the reported error, and so P2P
   scoring, changes for headers that break both a permanent rule and the FTL.
8. **Reorg, wallet, mining and P2P implications.** P2P: such headers are now penalized
   (`BadDifficulty` and `TimestampTooOld` are permanent). A header that is only too far in
   the future is still unpenalized. No reorg, wallet or mining effect.
9. **Vectors.** `header_check_order_vectors`: 7 rows of mutation sets and their
   first-failing error (difficulty + future, difficulty + too old, height + difficulty,
   height + future, too old, future, difficulty) plus the FTL-before-PoW case, each
   checked for `validate` and `precheck_batch` and for permanence.
10. **Tests.** The vector test above; the existing
    `precheck_agrees_with_sequential_validation_and_computes_no_pow` and
    `rejects_each_invalid_field` still pass unchanged.
11. **Suite results.** `-p blacksilk-consensus`: 63 passed (lib 42, golden 17, lwma_warm 2,
    randomx_end_to_end 2). Wider suites: see the RT-1 section (run once on the final
    branch).
12. **Open review points.** 30/31: scoring of the new first errors is the existing
    `penalized()` classification; no p2p change was needed.
13. **Identity impact.** None (no constant or genesis change).
14. **Documentation.** `docs/consensus.md` §6 (the order and why it does not change
    validity), in this change.
15. **Review status.** Internal; the validity-invariance argument is the conjunction.

---

## genesis-beacon: the genesis nonce is derived in consensus from a committed beacon

Owner: W1-CB-A. Decisions: "Agent 40" (nonce derived in consensus from the committed
beacon; `GenesisSpec`/`Beacon`; `genesis_is_final()`; no pasted nonce, no runtime
override). Dossier 40 F40-2 (Medium).

1. **Problem.** `ChainParams::base` hard-coded `nonce: 0`, and the ceremony tool printed
   a `TESTNET_GENESIS_NONCE` constant to paste into consensus code at launch: the final
   commit would have been a structural consensus edit under time pressure, and nothing
   tied a pasted nonce to its announced beacon (F40-2).
2. **Demonstrated failure.** Source-level: `params.rs` had no place for a beacon, and
   `tools/genesis::rust_constants` emitted a nonce constant. No test could assert
   "testnet nonce == derive(beacon)" (R15 §4.4 test 2 did not exist).
3. **Prior art.** Zcash's genesis carries public not-before data and `chainparams.cpp`
   asserts the genesis hash; Ethereum Frontier derived its genesis from an announced
   script plus a public block hash (dossier 40 §3 P1).
4. **Alternatives.** Paste the nonce plus a test that recomputes it (two values that can
   disagree until the test runs); a runtime `--genesis-beacon` flag (rejected by the
   decision: any operator could run a private genesis under the real id).
5. **Affected components.**
   - New `consensus/src/genesis.rs`: `NONCE_DOMAIN`, `nonce_preimage`,
     `nonce_preimage_digest`, `derive_genesis_nonce`, `parse_display_hex`, `Beacon`,
     `GenesisSpec` (`nonce`, `is_final`, `header`).
   - `consensus/src/params.rs`: `TESTNET_BEACON = None`, `MAINNET_BEACON = None`;
     `base()` builds the genesis from the spec; `ChainParams::genesis_spec()`,
     `genesis_is_final()`; `check()` refuses a nonce that disagrees with the beacon.
   - `tools/genesis`: re-exports the consensus derivation (its own copy removed), builds
     its header through `GenesisSpec`, and `rust_constants` now prints the
     `TESTNET_BEACON` value to commit, never a nonce constant.
6. **Activation.** Genesis construction only; no validity rule.
7. **Compatibility.** No beacon is committed on any network, so every nonce stays 0 and
   the testnet (v2, retired), regtest and mainnet genesis ids are byte-identical
   (`genesis_ids_are_pinned`, `genesis_ids_golden` unchanged).
8. **Reorg, wallet, mining and P2P implications.** None now. At launch the final commit
   changes `TESTNET_BEACON` (and the network id, genesis time and D0 per
   docs/testnet-v3-genesis.md) and the pinned ids and fingerprints.
9. **Vectors.** The tool's known answer (Bitcoin block 0, H = 0, id `0x0001D673`: digest
   `3c437d97…`, nonce `0x351e3bcf977d433c`, independently recomputed in Python by
   dossier 40) now also pinned in consensus (`genesis::tests::known_answer_bitcoin_block_0`).
10. **Tests.** `genesis::tests`: known answer, preimage layout, strict display hex, nonce
    from a dummy beacon (every input moves it; finality follows the beacon; a local
    network needs none). `params::tests`: `genesis_finality_follows_the_committed_beacon`,
    `a_committed_beacon_derives_the_nonce` (dummy beacon, test only),
    `check_refuses_each_broken_invariant` (a pasted nonce). `tools/genesis`: all 10
    existing tests pass through the consensus derivation; `rust_constants` emits a beacon,
    no nonce constant, and the tool's header equals `GenesisSpec::header`.
11. **Suite results.** `-p blacksilk-consensus` lib 49 passed; `-p blacksilk-genesis` 10
    passed. Wider suites: see the RT-1 section.
12. **Open review points.**
    - Not wired in this branch (outside the "consensus and tools/genesis" scope of the
      assignment): `node/src/config.rs` still gates the testnet on its own
      `TESTNET_GENESIS_FINAL = false`; it should call `ChainParams::genesis_is_final()`
      (40 item 3), as should the wallet, miner, supply-audit and labnet (F40-5).
    - The tool's registry semantics, the reserved test-vector id and the rehearsal range
      (F40-1, F40-11) are 40's item 2 and unchanged here.
    - No final genesis is generated; the dummy beacon exists only in tests.
13. **Identity impact.** None now (ids unchanged). The final commit is data-only:
    `TESTNET_BEACON: None -> Some(..)` plus the announced constants and pins.
14. **Documentation.** `docs/consensus.md` §1 (genesis construction and finality), in
    this change.
15. **Review status.** Internal; the derivation is the tool's, moved and cross-checked by
    the unchanged tool tests.

---

## rt1-unknown-upgrade-pow: UnknownUpgrade only for headers with real proof of work

Owner: W1-CB-A. Decisions: "Agent 50" RT-1 (adopted: `UnknownUpgrade` only for PoW-valid
headers; disconnect without a ban after N; operator warning only past a peer or work
threshold).

1. **Problem.** `check_rules` returned `UnknownUpgrade` for any header whose version
   exceeded the schedule's maximum, before proof of work. P2P does not penalize it and
   warned the operator once per peer. So a peer could stream unknown-version headers at
   zero hash cost, never be scored, keep its slot, and make any single inbound connection
   raise an "upgrade needed" warning (a social-engineering lever) (dossier 50 RT-1,
   Medium).
2. **Demonstrated failure.** On base `32054d4`, `chain::tests::unknown_upgrade_needs_valid_proof_of_work`
   failed: a newer-version header with junk proof of work returned
   `left: UnknownUpgrade { version: 7 }, right: InsufficientWork`.
3. **Prior art.** Bitcoin Core warns about unknown rules only from PoW-valid blocks of its
   own chain and only past a signalling threshold (`WarningBitsConditionChecker`, PR
   #16713); it never warns from one peer's unverified header.
4. **Alternatives.** Penalize every unknown version (breaks the upgrade signal of honest
   newer peers); keep it free but rate-limit (still free spam and a single-peer warning).
5. **Affected components.**
   - `consensus/src/chain.rs`: an unknown version is `BadHeight` if the height is wrong,
     else `UnknownUpgrade` from `check_rules` (unconfirmed); `validate` then checks the
     RandomX hash against the difficulty this node requires at that position (not the
     header's claimed difficulty) and returns `InsufficientWork` if it fails.
     `precheck_batch` (no PoW) reports it unconfirmed; the doc of
     `HeaderError::UnknownUpgrade` says so.
   - `p2p/src/net/headers.rs` (`verify_headers`): the unconfirmed header is included in
     the `worth_verifying` gate, hashed off the chain lock after its prefix, and
     classified by `validate`; `note_unknown_upgrade` replaces the per-peer warning.
   - `p2p/src/net/state.rs`: `Peer::unknown_upgrades`, `State::upgrades`
     (`UpgradeReports`), `UNKNOWN_UPGRADE_DISCONNECT = 3`, `UNKNOWN_UPGRADE_WARN_PEERS = 2`.
   - `p2p/src/net/blocks.rs`: the block path uses `note_unknown_upgrade` (its header is
     already PoW-confirmed by `validate`). `p2p/src/net.rs`, `conn.rs`: field init.
6. **Activation.** Node policy with the v3 rule set; the final verdict (header rejected)
   is unchanged.
7. **Compatibility.** No validity change: every such header was and is rejected. Only the
   error class of an unknown-version header with junk PoW (now permanent), and scoring,
   change. If a future upgrade changes the proof of work, old nodes see
   `InsufficientWork` for the new headers; they must upgrade then anyway.
8. **Reorg, wallet, mining and P2P implications.**
   - P2P: an unknown-version header costs the sender real work at our difficulty. A peer
     sending 3 of them is disconnected, never banned. The operator is warned once, when
     2 distinct peers reported one or one extends a branch reaching our best work. An
     unknown-version header on a low-work branch fails `worth_verifying` first (no hash,
     no warning).
   - Cost to us: one RandomX hash per unknown-version header that passes the work gate,
     the same as any other well-formed header.
   - No reorg, wallet or mining effect.
9. **Vectors.** `header_check_order_vectors` (F-05 section) and the RT-1 tests below.
10. **Tests.**
    - `consensus/src/chain.rs`: `unknown_upgrade_needs_valid_proof_of_work` (junk PoW:
      `InsufficientWork`, permanent; real PoW: `UnknownUpgrade`, not permanent; a header
      claiming difficulty 1 still needs the required work; a known wrong version stays
      `BadVersion`; a wrong height is `BadHeight`). `rejects_each_invalid_field` now grinds
      its unknown-version header to real work. `precheck_agrees_with_sequential_validation_and_computes_no_pow`
      states the confirmation: the pre-check's `UnknownUpgrade` is confirmed by `validate`
      to `UnknownUpgrade` or `InsufficientWork` exactly as the PoW decides.
    - `p2p/src/net/state.rs`: `upgrade_reports_warn_past_a_threshold_and_disconnect_after_n`.
    - `p2p/tests/network.rs`: `unknown_version_headers_need_real_proof_of_work` (junk PoW
      at the end of a requested batch: the peer is penalized and disconnected, the prefix
      stored; real PoW as tip announcements: score 0, still connected after 2, disconnected
      at the 3rd without a penalty or a ban).
11. **Suite results.** Final branch state (all six items), release, `--locked`, Windows x86_64,
    rustc 1.98.1, PX-proving tests skipped (`restart_rebuilds_the_px_state_exactly`,
    `px_transactions_travel_the_stem_and_confirm_everywhere`,
    `invalid_px_transactions_get_the_relaying_peer_penalized`):
    - `blacksilk-consensus`: 71 passed (lib 50, golden 17, lwma_warm 2, randomx 2).
    - `blacksilk-daa-sim`: 37 passed. `blacksilk-genesis`: 10 passed.
    - `blacksilk-node`: 40 passed, 2 ignored.
    - `blacksilk-p2p`: 82 passed, 4 ignored, 2 skipped (PX).
    - `blacksilk-chain`: 111 passed, **1 failed** (`revalidation.rs`
      `a_shorter_heavier_reorg_makes_a_ring_member_immature`, the DAA-dependent
      construction explained in the daa-lwma75-warm section, step 11), 2 ignored,
      1 skipped (PX).
    - `cargo clippy --locked -p blacksilk-{consensus,daa-sim,genesis,node,p2p,chain}
      --all-targets -- -D warnings`: clean. `cargo fmt --all -- --check`: clean.
12. **Open review points.**
    - `docs/p2p.md` §6 still describes the per-peer warning; it was on branch w1-tx-a's
      file list, so it is not edited here (one paragraph for the coordinator: the §11
      rules of docs/consensus.md, as updated here).
    - The thresholds (3 reports, 2 peers) are policy constants; 30/31 may tune them.
    - The warning is not rate-limited beyond "once per run".
13. **Identity impact.** None.
14. **Documentation.** `docs/consensus.md` §6 item 1 and §11 (network-layer rules), in
    this change.
15. **Review status.** Internal; implements the red team's fix (a)–(c).

### Follow-up (RTW1-1)

Owner: FX-RTW1-1. Red-team findings RTW1-1 (Medium) and RTW1-10 (Info) against the RT-1
change above. Internal review, not an audit.

1. **Problem.** `check_rules` returns `UnknownUpgrade` before the difficulty rule, so an
   unknown-version header's claimed difficulty is never checked, yet `worth_verifying`
   summed it. An unknown-version header anchored at an old parent (genesis) claiming
   `difficulty = u64::MAX` passed the anti-DoS work gate and was RandomX-hashed. The
   same trick could force RandomX cache builds for old seed epochs (`RandomXPow` keeps
   two), and a second connection from the same attacker, inbound, could trip the "node
   may need an upgrade" warning. RTW1-10: `ChainParams::check` accepted `seed_lag = 0`,
   and `HeaderChain::new` could only panic on bad parameters.
2. **Demonstrated failure** (tests written first, run on base `2985a50`):
   - `p2p/tests/network.rs::a_deep_fork_unknown_version_header_claiming_max_difficulty_is_not_hashed`
     failed with `the claimed difficulty bought a hash`, `left: 1, right: 0` (the red
     team's `rtw1_unknown_version_bypasses_the_work_gate`, inverted).
   - `an_old_epoch_unknown_version_header_triggers_no_cache_build` failed with `an
     old-epoch key was hashed`, `left: 1, right: 0` (a fork 101 blocks below a tip of
     2200, inside the anti-DoS window, whose key is genesis while the current key is
     block 2048).
3. **Prior art.** Bitcoin Core's anti-DoS header work threshold counts only work it
   computes itself; its unknown-rules warning uses its own chain's blocks, not one
   peer's unverified headers (as in the RT-1 section).
4. **Alternatives.** Reject unknown-version headers whose claimed difficulty differs
   from ours (rejected: a newer release may change the difficulty rule, which is why
   the difficulty is not checked); drop unknown-version headers entirely (rejected:
   loses the upgrade signal RT-1 kept).
5. **Affected components.**
   - `consensus/src/chain.rs`: `HeaderChain::required_difficulty_after(anchor, branch)`
     (the difficulty required of a child of a pre-checked, possibly unstored branch; no
     proof of work); `HeaderChain::try_new` returning `Result<_, ParamsError>`, with
     `new` its panicking wrapper for compiled-in parameters.
   - `consensus/src/params.rs`: `check` requires `1 ≤ seed_lag < seed_epoch`
     (`ParamsError::SeedSchedule`).
   - `p2p/src/net/headers.rs` (`verify_headers`): the unknown-version header enters the
     work gate at the required difficulty (a); it is hashed only if its RandomX key on
     its own branch is the key of our next block or the next key after it
     (`seed_is_live`), otherwise it is dropped unhashed (c). `UpgradeWork` replaces
     `reaches_best_work`: the required-difficulty work reaches the anti-DoS threshold
     (`threshold`) and our best work (`heavy`). A failed `UnknownUpgrade` lowers the
     peer's claimed height to ours (nothing past it is usable).
   - `p2p/src/net/state.rs`: `UpgradeReports` counts a report toward the warning only
     if it comes from an outbound peer and passes the threshold (b). Reporters are keyed
     by `upgrade_reporter_key` (network group; whole address with `allow_private`), not
     by connection; at most `UNKNOWN_UPGRADE_WARN_PEERS` (2) keys are held.
   - `p2p/src/net/blocks.rs`: the block path counts toward the disconnect only (it is
     not reached in practice: no unknown-version header is ever stored, so no such
     block is requested or kept). `p2p/src/net.rs`: `Network::upgrade_warned`.
6. **Activation.** Node policy; the `seed_lag` check is a parameter invariant that every
   built-in network already meets (lag 64).
7. **Compatibility.** No validity change: no header or block changes verdict, and no
   built-in parameter set changes. Only which unknown-version headers are hashed, and
   which reports count toward the warning, change.
8. **Reorg, wallet, mining and P2P implications.**
   - P2P: an unknown-version header costs its sender the work this node requires at
     its position, and is hashed only under a live key. An unknown-version header on a
     fork behind a key switch is never hashed or reported, even if honest.
   - The warning now needs outbound reporters: a node with only inbound peers is never
     warned. Two outbound peers in one network group count once.
   - No reorg, wallet or mining effect.
9. **Vectors.** The regression tests below.
10. **Tests.**
    - `p2p/tests/network.rs`: `a_deep_fork_unknown_version_header_claiming_max_difficulty_is_not_hashed`,
      `an_old_epoch_unknown_version_header_triggers_no_cache_build` (zero pow calls:
      the pow function is where `RandomXPow` builds a cache; the same header on the
      tip is hashed once), `only_distinct_outbound_reporters_trigger_the_upgrade_warning`
      (3 inbound reporters from distinct addresses, on the tip and on a near fork:
      hashed, not scored, no warning; one outbound reporter reconnecting: no warning;
      a second outbound reporter: warning).
    - `p2p/src/net/state.rs`: `upgrade_reports_warn_past_a_threshold_and_disconnect_after_n`
      (rewritten: keys, reconnects, non-qualifying heavy reports, the bound),
      `upgrade_reporters_are_keyed_by_group`.
    - `consensus/src/chain.rs`: `required_difficulty_after_matches_the_stored_branch`,
      `try_new_reports_invalid_parameters`; `consensus/src/params.rs`:
      `check_refuses_each_broken_invariant` gains `seed_lag = 0`.
    - The RT-1 tests pass unchanged (`unknown_version_headers_need_real_proof_of_work`,
      `unknown_upgrade_needs_valid_proof_of_work`).
11. **Suite results.** See the commit message of this change (exact command and counts).
12. **Open review points.**
    - `docs/p2p.md` §10 ("the first per peer is logged at WARN") and `docs/consensus.md`
      §11 (the warning's peer threshold) predate RTW1-1 and were outside this item's
      file list; `docs/p2p.md` §6 is current.
    - `ChainManager::open` (`chain/src/manager/replay.rs`) still calls
      `HeaderChain::new` with caller-supplied parameters; the node checks them at start
      (`node/src/main.rs`). Moving `open` to `try_new` belongs to the chain owners.
    - Keying by network group lets two honest outbound peers in one /16 count once; an
      attacker holding outbound slots in two groups can still raise the warning, with
      real work at our required difficulty inside the anti-DoS window.
13. **Identity impact.** None.
14. **Documentation.** `docs/p2p.md` §6 ("Headers of an unknown version"), in this change.
15. **Review status.** Internal; implements the red team's fix (a)–(c) and RTW1-10.

---

<a id="exact-v1-fee"></a>

## Exact v1 fee (T8): `fee = FEE_PER_WEIGHT × max_weight(n_in, n_out)`

Decision: agent 38 W8, "Exact v1 fee (W8), DECIDED for the v3 genesis" (decisions.md,
Agent 38); dossiers 38 §3.7, 14 §3.4 (FE-4) and 11 (F11-7). Work item CB-B1b item 1.

**1. Problem.** T8 required `fee ≥ min_fee(weight)`. The official wallet pays exactly
`standard_fee(n, k) = min_fee(max_weight(n, k))`, but any other amount was valid, so a
third-party wallet's own fee computation, a "priority" multiple or a buggy fee singled
out its wallet on chain and, through the change output, its later real inputs. v1 was
the only kind whose fee was a free field: PX fees (`PX_STANDARD_FEE`) and deploy fees
(`deploy_fee`) were already exact.

**2. Demonstrated failure** (test first, on the base commit `f1fc15a`):
`tx/tests/exact_fee.rs::a_transfer_not_paying_exactly_the_standard_fee_is_rejected`
fails: signed, balanced 1-input 2-output transfers paying 34 461, 34 459 and 68 920
atomic units (standard 34 460) are all accepted, by `validate_transfer` and in a block:
`accepted (fee, mempool, block): [(34461, Ok(()), Ok(())), (34459, Ok(()), Ok(())),
(68920, Ok(()), Ok(()))]`.

**3. Prior art.** Monero: non-standard fees cluster by wallet implementation (Rucknium,
Monero non-standard fees: about 10 % of transactions, five or more clusters; 62 %
positive predictive value for the real input created by a same-fingerprint transaction);
monero#5711 proposes consensus fee discretization; research-lab#70 shows that
high-precision fees leak creation time. Zcash ZIP-317 prices by public shape (logical
actions). Sources: dossier 38 §3.7, dossier 14 §8.

**4. Alternatives.** Keep "≥" and document the fingerprint (rejected by the decision);
fee tiers `{1, 4, 20} × standard` (R-FEE1: ≤ 1.6 bits, keeps a priority escape; possible
later as a relaxation by activation, through `TxRules::standard_fee`); a dynamic,
anchor-indexed fee (P3 mainnet design, dossier 14 §3.6).

**5. Affected components.**
- `tx/src/params.rs`: `max_weight` moves here from the wallet builder (it is a
  consensus function; F11-7) and `TxRules::standard_fee(n, k) = min_fee(max_weight(n, k))`
  is the single definition of the v1 fee rule.
- `tx/src/validate.rs`: `check_structure` = `check_shape` (T1, T3–T7, T10 shape, T11) +
  `check_fee` (T8 exact); `TxError::FeeTooLow` becomes `TxError::FeeNotExact { fee,
  required }` (stateless, as before).
- `tx/src/px.rs`: `deploy_fee(n, k, programs, rules)` takes `&TxRules` and uses
  `rules.standard_fee` for its v1 part (was the constant `FEE_PER_WEIGHT`; FE-5);
  `check_deploy_structure` checks the transfer shape with `check_shape` (no more
  "relaxed rules with a zero fee rate" hack); `PxDeploy::required_fee(rules)`.
- `tx/src/builder.rs`, `tx/src/px_builder.rs`: `build_transfer` refuses a non-standard fee
  (self-check); `build_transfer_signing` self-checks the shape only (its callers own the
  fee rule); `build_deploy` passes the real rules.
- `wallet/src/wallet/contracts.rs`: `deploy_fee(…, &rules)`.
- **Deploys.** The same rule already applied: a deploy's fee was exact
  (`DeployFeeNotExact`) with its v1 part `FEE_PER_WEIGHT × max_weight(n, k)`. The v1
  part is now computed by the same `TxRules::standard_fee`, so one function governs both.
  PX transactions keep `PX_STANDARD_FEE` (which exceeds the v1 fee of any PX v1 part).

**6. Activation.** v3 genesis base rule set, from genesis; no `Epoch` field. After launch
this would be a tightening (needs an activation height); relaxing it to tiers later is an
activation through `TxRules`.

**7. Compatibility.** No encoding, id, signature-message or `h_tx` change. Every
transaction the official wallet builds is unchanged (it already paid exactly the standard
fee). Only transfers with another fee change verdict (valid to invalid). No pinned
vector changes. The fingerprint's constant list does not change (`FEE_PER_WEIGHT` is
unchanged); the rule change belongs in agent 40's rule-revision list.

**8. Reorg, wallet, mining and P2P implications.** Reorgs: none (a stateless rule).
Wallet: `standard_fee` is unchanged; a wallet that computed another fee now gets
`BuildError::SelfCheck(FeeNotExact)` before signing leaves the builder. Mining and the
mempool: v1 fee rates now differ only by the ratio `max_weight / weight` of a shape, so
honest users cannot outbid; congestion is policy (eviction, expiry; dossier 12 P4). P2P:
`FeeNotExact` is stateless, so relaying such a transaction is penalized as `FeeTooLow`
was. Tests that paid "a hundred times the fee" to show that fees do not matter
(`chain/tests/mempool_conflicts.rs`) now pay the standard fee: no other fee is valid.

**9. Vectors.** `tx/tests/data/max_weight.txt`: `max_weight(n, k)` and the exact fee for
every `n = 1..64`, `k = 0..16` (1 088 rows; `k = 0, 1` are PX v1-part shapes), generated
by the independent, standard-library Python script `tools/vectors/max_weight.py`
(derived from the spec layout, §4.1, §4.2, §7, §8.4, not from the Rust code; `--check`
compares). Anchors: `max_weight(1, 2) = 1 723` (fee 34 460), `max_weight(64, 16) =
57 439`, `max_weight(1, 0) = 841`. (Dossier 14 quoted 57 449 for `(64, 16)`; the
spec-derived value is 57 439, and the Rust function agrees with the script.)

**10. Regression tests.**
- `tx/tests/exact_fee.rs`: the demonstration; `a_non_standard_fee_is_a_stateless_fee_not_exact`
  (mempool and block, error and class); `the_builder_refuses_a_non_standard_fee`;
  `the_deploy_fee_uses_the_same_standard_fee_function` (a doubled fee rate moves the
  transfer fee and the deploy's v1 part together).
- `tx/tests/max_weight_vectors.rs`: the golden table; a property test that
  `max_weight(n, k) ≥ weight` for random and extreme encodings (ring entries and fee
  over the whole `u64` range, 10-byte varints) of every valid shape (3 840 cases).
- `tx/tests/adversarial.rs::t8_fee` (every non-standard fee, `FeeNotExact`), `t9_balance`
  (a raised fee is caught by T8 first; T9 alone still rejects it).
- `wallet/tests/e2e.rs::the_wallet_pays_the_exact_v1_fee_for_every_shape` (1-input and
  many-input transfers over RPC; the pooled fee equals `TxRules::standard_fee`).

**11. Suite results.** In the commit message and the CB-B1b final report.

**12. Open review points.**
- Red team (50) reviews the rule and the claim that no honest wallet path produces a
  non-standard fee (the wallet uses `standard_fee`, deploys `deploy_fee`, PX
  `PX_STANDARD_FEE`).
- Agent 40: add the rule revision and weight samples to the fingerprint manifest.
- `TxError::is_stateless` treats `FeeNotExact` as stateless; if a later epoch changes
  `fee_per_weight`, it becomes height-dependent near the activation (F11-3; P2 item).

---

<a id="expiry-guard"></a>

## Mempool expiry (2 160 blocks) and the recently-expired guard (30 blocks)

**Policy, not consensus.** No block's validity changes; this section follows the 15-step
form because the decisions log bundles it with the consensus items (Agent 38 "Expiry",
Agent 12 "Expiry"). No `Consensus-Change` path is touched.

Decision: decisions.md, Agent 38 "Expiry: 2160 blocks from admission height, uniform for
ALL classes (deploys too); the recently-expired guard (R = 30) ships in the SAME change";
Agent 12 "Expiry". Dossiers 12 P3/W5 and 38 §3.4/W4n. Work item CB-B1b item 2.

**1. Problem.** Nothing expired from the pool: a transaction that was never mined (a
standard-fee transfer behind a full pool, or one whose rival won elsewhere) kept its
key images locked in every pool until those nodes restarted, and diverging pools never
re-converged (dossier 12 M12-5). An expiry counted from each node's admission height
alone opens an origin oracle (dossier 38 F38-3): 2 160 = 108 × 20, so a wallet's
20-block resubmission lands on the block at which its own node expires the transaction;
the node re-stems it to a peer that still pools it, and an honest relay never stems a
long-fluffed transaction, so the peer learns the origin.

**2. Demonstrated failure.** No expiry existed on the base commit: a pooled transaction
stayed pooled indefinitely (the new tests fail on the base by construction: there is no
`Mempool::expire` and no `MempoolError::Expired`). The oracle is a design consequence of
admission-height expiry without a guard (dossier 38 §3.4); the guard is what the tests
pin.

**3. Prior art.** Monero: `CRYPTONOTE_MEMPOOL_TX_LIVETIME` = 3 days, expired
transactions kept in `m_timed_out_transactions` so they are not re-accepted. Bitcoin
Core: `DEFAULT_MEMPOOL_EXPIRY_HOURS = 336`. Zcash ZIP 203 puts an expiry height in the
transaction, which BlackSilk rejects (a per-wallet value fingerprints; full review
never-change row 29). Sources: dossier 12 §8, dossier 38 §3.4.

**4. Alternatives.** Expiry counted from the first sighting by any node (not uniform);
720 blocks for deploys (dossier 14; rejected for uniformity, decisions Agent 38); expiry
without the guard (rejected: the oracle above); flushing on every reorganization
(dossier 12 P1 (c), rejected).

**5. Affected components.** `chain/src/mempool.rs`: `MEMPOOL_EXPIRY_BLOCKS = 2 160`,
`RECENTLY_EXPIRED_BLOCKS = 30`, `Entry::admitted`, `Mempool::expire`, `readmit`,
`recently_expired`, `admitted_at`, `MempoolError::Expired` (checked in `precheck`, so on
`add` and `check`, before any validation). `chain/src/manager/fork_choice.rs`:
`finish_sync` expires before re-admitting returned transactions, which use `readmit`.
P2P and RPC need no change: `Expired` is not `Invalid`, so no peer is penalized and the
stem and relay paths drop it (`p2p/src/net/admission.rs`, the `Err(_) => {}` arms);
`/tx` answers `Expired`.

**6. Activation.** None (node policy), effective on upgrade.

**7. Compatibility.** No consensus or encoding effect. Nodes with and without it relay
the same transactions except expired ones.

**8. Reorg, wallet, mining and P2P implications.** Reorg: expiry and the guard compare
against the current next height, so after a reorganization to a lower height nothing
expires early and the guard lasts longer, never shorter; a transaction returned by a
disconnected block is pooled even inside the guard window, with a fresh admission
height (it was on the best chain: no re-injection by its origin). Wallet: the wallet
still resubmits every 20 blocks; after expiry network-wide its node answers `Expired`
for 30 blocks and stems nothing. The wallet-side redesign (probe semantics, no
re-injection before `relayed + E + R`, `NETWORK_EXPIRY_BLOCKS = 2 160 + 30` taken from
`chain`) is dossier 38 W4, not in this change. Mining: templates never see expired
entries. P2P: pool re-announcement with backoff is dossier 38 W4n (owners 33/30), not in
this change.

**9. Vectors.** The constants (2 160, 30) in `chain/src/mempool.rs`; no wire vectors.

**10. Regression tests.** `chain/src/mempool.rs` unit tests
`a_transaction_expires_exactly_at_its_admission_height_plus_the_expiry` (every kind,
the exact block, keys and bytes released), `an_expired_transaction_is_refused_for_the_guard_window_only`
(both ends of the window, only the same id), `expiry_and_the_guard_follow_the_height_across_reorganizations`;
`chain/tests/mempool_expiry.rs::a_pooled_transaction_expires_is_guarded_and_comes_back_after_a_reorganization`
(a real transfer through the chain manager: pooled one block before expiry, gone at
admission + 2 160, `Expired` on `submit_tx` and `check_tx`, readmitted with a fresh
admission height after a reorganization disconnects a block carrying it, then mined).

**11. Suite results.** In the commit message and the CB-B1b final report.

**12. Open review points.**
- The guard is per node and by transaction id. It assumes honest nodes admit a
  transaction within a few blocks of each other; a node that first saw it much later
  (for example after a restart and a rebroadcast) expires it later, and the wallet
  redesign (W4) must not re-inject before `relayed + 2 160 + 30`.
- The recently-expired set is bounded by what expires within 30 blocks, which the pool
  caps bound; it is not persisted (neither is the pool).

---

<a id="r12-2"></a>

## R12-2 (a′): the v1 part of PX and deploy transactions counts toward the block weight

Decision: decisions.md, Agent 14 "R12-2: option (a′) is accepted provisionally", Agent 10
"R12-2: 14's option (a′) and 10's option (a) are the same rule … Adopted for the v3
genesis", Agent 50 "R12-2 (a′): `Mempool::select` charges PX and deploys against BOTH
budgets, in the SAME commit". Dossiers 14 §3.1 (FE-1, FE-6) and 10 §3.1 (F10-1). Work
item CB-B1b item 3.

**1. Problem.** `Transaction::weight` was 0 for PX and deploy transactions, so their v1
inputs (up to 64 each, one 16-member CLSAG per input) were metered only by the PX byte
budget. A valid block could carry about 2 530 CLSAGs (a full v1 lane, 1 MiB of 64-input
deploys, three 64-input PX transactions) against about 886 for the v1 lane alone: about
5–10 s of single-threaded verification under the chain lock per block, with fees
recycled to a miner stuffing its own block (dossier 14 §3.1, dossier 10 §3.1; figures
are estimates from 2–4 ms per CLSAG).

**2. Demonstrated failure** (tests first):
`tx/tests/px_v1_weight.rs::a_block_over_the_weight_limit_through_a_deploys_v1_part_is_rejected`
fails: a block whose only weight beyond its coinbase is a valid 1-input deploy validates
(`Ok(())`) under a weight limit of `coinbase + 1 000`, which the deploy's v1 part
(`max_weight(1, 2) = 1 723`) exceeds. `a_px_transactions_v1_inputs_count_toward_the_weight_limit`
fails: a block with a 64-input PX transaction passes B6 under a limit of `coinbase +
50 000` (`max_weight(64, 0)` is larger) and fails only later.
Run on the parent commit `87c83ff`: `a deploy's CLSAG escaped the weight limit: Ok(())`
and `64 CLSAGs escaped the weight limit: Err(Tx { index: 1, error: Unbalanced })` (the
block got as far as the balance check; B6 did not see the 64 inputs).

**3. Prior art.** Bitcoin meters signature operations separately (BIP 141 sigop cost
≤ 80 000; BIP 54 per-transaction sigops). Monero has no separate lane: every byte of a
transaction counts toward block weight, so ring signatures are always paid in weight.
Zcash ZIP-317 prices by logical actions. The common principle: every verification
resource falls under a consensus meter (dossier 14 §3.1).

**4. Alternatives.** (a) charge only the v1 bytes of PX/deploy transactions to the
weight and only the rest to the PX budget (a new byte partition to specify and test;
rejected for (a′)'s simplicity); (b) a separate `MAX_BLOCK_INPUTS` counter (a third
template dimension, not tied to fees); (c) a lower per-transaction input cap (does not
bound the block); (d) accept (another reset later).

**5. Affected components.**
- `tx/src/types.rs`: `Transaction::weight` of a PX or deploy transaction with `n > 0`
  v1 inputs and `k` hidden outputs is `max_weight(n, k)` (the exact-fee function,
  tx/src/params.rs); 0 without inputs. `px_bytes` is unchanged (the full encoded
  length), so the v1 bytes count in both budgets (at most about 57 KB of the 8 MiB PX
  lane per 64-input transaction).
- `tx/src/validate.rs`: none in logic; B6 already sums `Transaction::weight` for every
  transaction, before any cryptography (doc comments only).
- `chain/src/mempool.rs` (`Mempool::select`, same commit): every candidate is charged
  against the weight budget, PX and deploys also against the PX budget (and deploys the
  deploy sub-budget); the order is PX transactions first (their fee is uniform), then
  transfers and deploys by fee per weight (the same unit for both, no cross-unit
  comparison; FE-6).
- The PX fee stays exactly `PX_STANDARD_FEE`: `FEE_PER_WEIGHT × max_weight(64, 16) =
  1 148 780 ≤ PX_STANDARD_FEE = 8 912 896`, so the fixed fee covers the v1 part of any
  PX transaction and stays uniform (no per-shape component, which would fingerprint the
  input count). A deploy's fee already pays `FEE_PER_WEIGHT × max_weight(n, k)` for its
  v1 part, exactly its new weight at the v1 rate.

**6. Activation.** v3 genesis base rule set, from genesis. After launch it would be a
tightening (activation height).

**7. Compatibility.** No encoding, id or signature change. Blocks whose v1 weight plus
PX/deploy v1 parts exceed `MAX_BLOCK_WEIGHT` become invalid; no honest template
produces one (the template test below). The fingerprint's constant list does not see
the rule: agent 40 adds weight samples (`weight` of PX 0-in, 1-in/0-out, 64-in/16-out,
deploy 1-in/2-out, 64-in/2-out) to the manifest.

**8. Reorg, wallet, mining and P2P implications.** Reorg: none (a pure block sum).
Wallet: nothing changes (fees are unchanged). Mining: templates charge both budgets; PX
transactions come first, so v1 congestion cannot keep a PX transaction with v1 inputs
out (it needs at most 57 439 weight of the 597 000). P2P: none.

**9. Vectors.** `Transaction::weight` of PX 0-in (0), PX 1-in/0-out (841), PX
64-in/16-out (57 439), deploy 1-in/2-out (1 723), deploy 64-in/2-out (52 123): each
equals the `max_weight` row of `tx/tests/data/max_weight.txt` (independent script).
Boundary: a block at exactly the weight limit with a deploy contributing is valid; one
unit lower is `WeightExceeded`.

**10. Regression tests.** `tx/tests/px_v1_weight.rs`: the two demonstrations; the
weight vectors; the boundary (limit exact and −1, with a real deploy);
`every_clsag_is_paid_for_in_the_weight_meter` (weight ≥ 656 per input for random
transfers and ≥ 800 per input for PX and deploys, so a valid block holds at most
⌊600 000 / 656⌋ = 914 v1 inputs across all kinds); `the_px_fee_covers_the_largest_px_v1_part`.
`chain/src/mempool.rs`: `templates_respect_both_budgets_for_every_kind` (randomized:
synthetic pools of transfers, PX with and without inputs and deploys, random budgets;
every template's total weight, PX bytes, deploy bytes and pool stay within bounds),
`px_with_v1_inputs_are_selected_under_v1_congestion`, and the updated selection tests.

**11. Suite results.** In the commit message and the CB-B1b final report.

**12. Open review points.**
- "Final only after agent 10's worst-block benchmark and the red-team review"
  (decisions, Agent 14): the benchmark (dossier 10 item 3) has not been run in this
  change; the expected bound is about 914 CLSAGs plus 3 PX proofs per valid block.
- The invalid-block worst case (F10-2) is closed separately by early proof decoding
  (docs/transactions.md §8.3); this rule also bounds it through B6.
- Agent 40: weight samples in the fingerprint manifest.

---

<a id="tree-capacity"></a>

## PX tree capacity (I3) with 21-D, a fallible apply that halts, and 21-F

Decision: decisions.md, Agent 11 "Tree-capacity rule (I3): rides the v3 reset … `apply_block`
returns a Result, with no panic path"; Agent 21 "Tree capacity: the frontier stores the
full root at the last append (21-D). It merges before or with 11's capacity rule" and
"Undo compaction (21-F): done now … gated by a property test"; Agent 50 "Tree capacity:
21-D lands with or before the rule; count leaves per output (not a literal 2); templates
enforce it; an apply failure after validation stops the node, and must NOT mark the
block invalid"; Agent 48 F48-5 (never auto-invalidate). Dossiers 11 §3.3 (F11-2) and 21
§3.4, §3.6 (F21-1, F21-2, F21-4, F21-8). Work item CB-B1b item 4.

**1. Problem.**
- No rule bounded the PX commitment tree (depth 32, `CAPACITY = 2^32` leaves). A block
  overflowing it passed validation and then panicked every node in
  `MemoryChain::apply_block` (`expect`): a deterministic global halt. Unreachable at
  today's proof size (≥ 2^29 blocks), about 10 years away if PX transactions shrank to
  about 10 KB (dossier 11 §3.3); the rule is free now and needs an activation later.
- 21-D (F21-1): at exactly `CAPACITY`, `Frontier::root` folded the all-zero size bits
  and returned the empty tree's root; the append that filled the tree computed the full
  root and dropped it. Under an exact-fill rule the last block's recorded root would be
  wrong and its records unspendable.
- 21-F (F21-4): every block's undo cloned the whole root window (100 roots, 3.2 KB) and
  the frontier (about 1 KB), about 4.2 KB per block kept for ever, even for blocks
  without PX transactions.
- F21-8: the record log computed positions as `2 × index`, a literal 2.

**2. Demonstrated failure.**
Tests first, run on the item's code with the B8 checks not yet added (the parent
commit `af5418c` has no test hook, so the tests could not be written against it):
- `tx/tests/tree_capacity.rs`: with 4 leaves left, a block of 3 PX transactions (6
  leaves) passed validation and applying it failed, `a validated block applies:
  Px(TreeFull)` (on `af5418c` the same point was an `expect` panic in
  `MemoryChain::apply_block`, on every node); `validation_implies_a_successful_apply_near_capacity`
  failed the same way; the mempool accepted a PX transaction with 1 leaf left
  (`left: Ok(()) right: Err(PxTreeFull)`).
- 21-D, with the `full_root` return removed from `Frontier::root`:
  `the_last_append_keeps_the_full_root` failed with `assertion left != right failed:
  not the empty tree's root` (the root at `size = CAPACITY` was the empty tree's).

**3. Prior art.** The Zcash protocol specification makes capacity a block rule ("A block
MUST NOT add … note commitments that would result in the … note commitment tree
exceeding its capacity"); Zebra returns `NoteCommitmentTreeError::FullTree` as a block
error and never panics. Bitcoin Core and Zebra stop on an internal failure to connect a
validated block rather than marking it invalid. Sources: dossier 11 §8, dossier 21 §8.

**4. Alternatives.** Leave one leaf unused (`size + leaves < CAPACITY`) instead of 21-D
(dossier 21 §3.4; rejected: the decision chose the exact semantics); defer the rule
(rejected: an activation later); a new-tree epoch when full (future design; once full,
PX is closed until then, documented).

**5. Affected components.**
- `px/src/tree.rs` (21-D): `Frontier::full_root`, set by the append at position
  `CAPACITY − 1`, returned by `root()`; `Frontier::uniform_for_tests` (test-only).
- `px/src/state.rs` (21-F): `Undo` keeps the frontier only if the block appended
  (boxed) and only the root its push evicted; `undo` pops the block's root and restores
  the evicted one; a failed `apply_block` restores what it changed without touching the
  window. `State::free_leaves`; `State::with_uniform_tree_for_tests` (test-only).
- `tx/src/validate.rs`: `ChainView::px_tree_size`; block rule B8
  (`BlockError::PxTreeFull { leaves, free }`), with the B6 budgets, before any
  cryptography: the block's PX output commitments, counted per commitment, must fit in
  `CAPACITY − size`; contextual `TxError::PxTreeFull` in `validate_px_without_proof`
  and `revalidate_after_extension`.
- `tx/src/state.rs`: `MemoryChain::apply_block` returns `Result<u64, ApplyError>`
  and is atomic (programs loaded and the PX state applied before anything else
  changes); record positions count one leaf per commitment (F21-8);
  `MemoryChain::with_px_state`; test-only fault injection.
- `chain/src/mempool.rs`: `Mempool::select` takes the free leaves and never selects
  more PX commitments than fit.
- `chain/src/manager/*`: an apply failure after validation sets `apply_failed`
  (`ChainManager::halted`), is logged naming the block, leaves the block valid and
  unconnected, and refuses every further block (`SubmitError::Halted`); `open` fails
  with the reason when replay hits it. `node`: the store watcher stops the node on any
  halt, with the reason. `p2p/src/net/blocks.rs`: `Halted` is not the peer's fault.
- Features: `blacksilk-px/test-hooks` and `blacksilk-tx/test-hooks` (test constructors
  and fault injection), enabled only by dev-dependencies (tx, chain). A CI check that
  no release build enables them is owed (agent 43, as for the actor test feature).

**6. Activation.** v3 genesis base rule set (B8), from genesis. 21-D changes no root
below capacity; 21-F is not consensus (identical behaviour, proven by the property test).

**7. Compatibility.** No reachable chain is affected (B8 cannot trigger below 2^32
leaves); no encoding, id or root changes; fingerprint constants unchanged (`CAPACITY` is
already in the PX fingerprint). The rule revision belongs in agent 40's list.

**8. Reorg, wallet, mining and P2P implications.** Reorg: undo is exact at capacity
(tested), and a restart replays to the same full root. Wallet: none (the wallet's full
`Tree` was already correct at capacity; the frontier now agrees with it). Mining:
templates never exceed the free leaves. P2P: `PxTreeFull` is contextual (not penalized);
`SubmitError::Halted` penalizes no peer. Node: halts rather than marking a block
invalid; F48-5's quarantine marker and `--invalidate-block` (35 S5) are not part of
this change.

**9. Vectors.** Boundary: with `free` leaves left, `n` PX transactions are valid iff
`2n ≤ free`, for `free = 0..6`, `n = 0..3`; the full root after the exact fill equals
the fold of the last leaf's path (`the_last_append_keeps_the_full_root`).

**10. Regression tests.**
- `px/src/tree.rs`: `the_last_append_keeps_the_full_root` (21-D),
  `a_uniform_frontier_matches_the_tree_of_equal_leaves` (the test constructor is the
  frontier of equal leaves, sizes 0–300).
- `px/src/state.rs`: `compact_undo_equals_the_full_clone_reference` (21-F: 4 000
  random steps of apply, failed apply and undo, compared with a full clone before every
  block, the window's eviction included), `an_empty_blocks_undo_is_small`,
  `a_block_filling_the_tree_is_applied_and_one_more_leaf_is_refused`.
- `tx/tests/tree_capacity.rs`: the demonstration; the boundary table; the mempool and
  revalidation error; `validation_implies_a_successful_apply_near_capacity` (random
  blocks: valid ⇒ applies; refused ⇒ the unvalidated apply fails atomically);
  `undo_and_replay_are_exact_at_capacity`.
- `chain/src/mempool.rs`: `templates_never_exceed_the_free_leaves`.
- `chain/src/manager` unit test `an_apply_failure_after_validation_halts_without_invalidating`
  (injected failure: the block stays valid and unconnected, further blocks are refused
  with `Halted`, `halted()` names the block; after a restart the stored block connects).

**11. Suite results.** In the commit message and the CB-B1b final report.

**12. Open review points.**
- Once the tree is full, PX is closed until a new-tree epoch is designed (documented;
  far off at current proof sizes).
- The fault-injection feature is compiled into test builds only; agent 43 to add the
  release-build check.
- Red team (50): the claim that validation is a superset of every `apply_block` failure
  (anchor, nullifiers, pool, capacity, program loading).
