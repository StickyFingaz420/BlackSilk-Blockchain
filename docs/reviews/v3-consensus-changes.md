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
