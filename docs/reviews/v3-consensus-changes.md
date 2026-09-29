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
- Soundness figures, COLLISION_BITS = 122 (zk; W1-CB-B3); Follow-up (RTW1-3/6/8) (zkvm, zk; FX-RTW1-ZK)
- daa-lwma75-warm (consensus; W1-CB-A)
- f05-header-check-order (consensus; W1-CB-A)
- genesis-beacon (consensus; W1-CB-A)
- rt1-unknown-upgrade-pow (consensus, p2p; W1-CB-A)
- exact-v1-fee (tx; W1-CB-B1b)
- expiry-guard (chain mempool policy; W1-CB-B1b)
- r12-2 (tx, chain; W1-CB-B1b)
- tree-capacity (px, tx, chain; W1-CB-B1b)
- approval-conflict (px-core kernel; W1-CB-B2)
- px-call-abi (px-core, px, tx; W1-CB-B2)
- px6-validity-window (px-core, px, tx, chain mempool; W1-CB-B2)
- vault-v3 (vault guest and host, wallet; W1-CB-B2)
- guest-rebuild (kernel and vault ELFs and ids, guest link layout; W1-CB-B2); Follow-up (RTW1C-9)
- kernel-budget-shapes (px; FX-RTW1C); Follow-ups (RT-W1c) in px6-validity-window and vault-v3
- fingerprint-v3 (node, px, zkvm, consensus network id, tools/genesis; W4-40); Follow-up (RT-FP3) (FX-RTFP3)

New sections are appended at the end.

**Record template checklist** (every new section, RT-FP3):

- The heading is `## <key>: <title>`, optionally preceded by `<a id="<key>"></a>`.
  Commit trailers and `REVISIONS` cite the key exactly (`#<key>`, `§N`, or the
  heading's anchor); the consensus gate refuses a trailer whose section does not
  exist.
- **One `Revision:` line** directly under the heading: `Revision: <id>` when the
  change adds or changes a validity or proof-acceptance rule, and then the same
  commit appends `Revision { id: "<id>", record: "<key>" }` to `REVISIONS` in
  node/src/fingerprint.rs; otherwise `Revision: none (<reason>)`. The test
  `fingerprint::tests::revision_lines_are_the_revision_list` requires the ids of
  the records, in order, to be `REVISIONS`, and the gate requires the line in
  the cited section.
- If the rule is reachable by a cheap call on fixed inputs, a **rule sample** in
  the manifest (node/src/fingerprint.rs, px/src/fingerprint.rs), or a verdict
  sample on the fixture transfer.
- The **re-pin procedure** (`fingerprint-v3`): render the manifests before and
  after in separate target directories, map every changed entry to its record in
  the commit message, re-pin `node/tests/deploy_configs.rs` and
  `px/tests/consensus_fingerprint.rs`, and cite the record in the trailer.

---

## §1 D8 option B: no cross-transaction one-time-key uniqueness (former rule C4)

Revision: D8-B:one-time-keys-unique-within-tx-only

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

Revision: CLSAG:D-not-identity

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

Revision: RT-14:sig-domain-network-branch-genesis

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

Revision: F24-1:eight-random-codewords

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

Revision: I2:exact-hidden-openings-one-cap-root

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

Revision: none (a constant, `zk.COLLISION_BITS`, listed in the manifest)

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

### Follow-up (RTW1-3/6/8)

Owner: FX-RTW1-ZK. Red-team findings RTW1-3 (Medium), RTW1-6 (Low), RTW1-8 (Low/Info)
and an Info item (defence in depth), against the circuit fingerprint (decisions "Agent
22" W4, "Agent 23" W2) and the zk records above. Internal review, not an audit.

1. **Problem.**
   - RTW1-3: `zkvm::air::check::fingerprint` evaluated every table's constraints at
     random periodic values and never hashed the periodic columns themselves. A
     soundness-relevant edit of the byte lookup table (`byte::preprocessed`, e.g. one
     wrong XOR entry) or of the program, image or output public-column layouts
     (`program::preprocessed`, `memory::image_preprocessed`,
     `memory::output_preprocessed`) passed the pin next to `CIRCUIT_ID`. The next-row
     column sets (`main_next_row_columns`, `preprocessed_next_row_columns`), which the
     prover and verifier read instead of the constraints, were not hashed either.
   - RTW1-6: `REVISIONS` was append-only by comment only; an in-place edit of an old
     line passed.
   - RTW1-8: `docs/zkvm.md` §7, `docs/zk.md` §15 and `px/src/fingerprint.rs` still
     named BS-ZK-2 and "≥ 123 bits Johnson"; "about 105 bits proven" read as a proof;
     `docs/proof-system.md` said "binding terms" for the limiting terms.
   - Info: `zk::verify` did not apply the canonical-form rules; only `decode_proof`
     did, so a caller holding a `Proof` built in memory could accept rewrites C1/C2.
2. **Demonstrated failure.** The red team's test (`zkvm/tests/rtw1_fp.rs` of the demo
   patch: the byte table with `c[4][0] += 1`) run on base `c3bd12c`:
   `RTW1 fp equal despite a changed byte table: true`, `assertion left != right failed:
   a changed lookup table must change the circuit digest`, `test result: FAILED. 0
   passed; 1 failed` (log `C:/bszkeval/t-fx-rtw1-zk-before.log`). The same body is now
   `circuit_fingerprint.rs::rtw1_3_a_changed_byte_table_entry_changes_the_fingerprint`
   and passes. RTW1-6 and the Info item: absence of a check (on base, the advisory
   suite asserted that a direct `verify` accepts the C1 and C2 rewrites).
3. **Prior art.** Plonky3 documents periodic columns as public parameters that "must be
   committed during initialization of the Fiat–Shamir transcript" (p3-air 0.7.0
   `BaseAir::periodic_columns`), which `statement_digest` does for every proof; a
   circuit pin must cover them the same way. Append-only logs with a hash chain
   (Certificate Transparency, RFC 6962; git's parent hashes).
4. **Alternatives.** (a) Hash only the fixed byte table in `fingerprint` (rejected: the
   layout functions for programs, images and outputs are equally soundness-relevant);
   (b) keep `fingerprint` statement-independent and pin only `statement_digest` of a
   reference statement (partly adopted: both are hashed); (c) for RTW1-6, pin the full
   list of earlier entries in a second constant (equivalent to a chain; the chain is
   smaller and self-checking). For the Info item, keeping `verify` permissive to retain
   the upstream canary (rejected: correctness over a change signal; the rules are kept
   regardless of upstream).
5. **Affected components.**
   - `zkvm/src/air/check.rs` `fingerprint`: additionally hashes, per table, the contents
     of its periodic columns (count, then each column with its length) and of its
     preprocessed trace (if any), both next-row column sets, and the
     `num_constraints` / `max_constraint_degree` hints. The constraint evaluations are
     unchanged (same seeded stream). Test and documentation code only: no prover,
     verifier or transcript path calls `fingerprint`.
   - `zkvm/tests/circuit_fingerprint.rs`: the digest is taken on fixed reference
     statements (`REFERENCE_TAG`) and also hashes their `statement_digest`;
     `REVISIONS` lines carry (id, digest method, digest, chain hash of the earlier
     lines), with a pinned head `REVISIONS_HEAD`.
   - `zk/src/lib.rs` `verify`: runs `check_canonical_form` after V1–V2, before the FRI
     schedule rule (`ZkError::Encoding`).
   - Docs: `docs/proof-system.md` §2, §3, §5, §6, §7; `docs/zk.md` §9.3, §12, §13 item 7,
     §15; `docs/zkvm.md` §7; the module comment of `px/src/fingerprint.rs`.
6. **Activation.** v3 genesis base rules; nothing activates. The AIRs, the proof bytes
   and the transcript are unchanged.
7. **Compatibility.** Every proof that verified before verifies now, on consensus paths:
   they decode with `decode_proof` first (tx `decode_px_proof`, then
   `check_px_proof_decoded`), so every proof reaching `verify` is already canonical and
   the new check cannot change a verdict. A direct caller of `verify` with a
   non-canonical in-memory proof now gets `Encoding` instead of acceptance (C1, C2) or
   `Invalid` / `VerifierPanicked` (C3, C4, the #2256 case).
8. **Reorg, wallet, mining, P2P.** None. Wallets verify their own honest proofs, which
   are canonical.
9. **Vectors.** `CIRCUIT_ID` stays `BlackSilk/zkvm/BVM-1/circuit/v1`. The pinned
   circuit digest is the last line of `REVISIONS` in
   `zkvm/tests/circuit_fingerprint.rs` (digest method 2; the method-1 line is kept).
   **Why the id does not change:** `CIRCUIT_ID` names the constraint system and is
   absorbed into every transcript; the AIRs, buses, widths, table order, periodic
   layouts and limits are byte-for-byte unchanged, so every honest proof and every
   verdict is unchanged. Only the digest's coverage grew. Bumping the id would change
   every transcript for no constraint change and would make the id track the test's
   hashing method instead of the circuit. The decision "Agent 23" requires an AIR
   change to bump the id and the digest together; it does not require the converse. A
   coverage change is recorded as a new line with the same id and a new digest
   method, so the (id, method) pair never repeats and each digest stays distinct.
10. **Tests.** `zkvm/tests/circuit_fingerprint.rs`:
    `the_air_digest_is_pinned_to_the_circuit_id` (re-pinned);
    `the_revisions_are_append_only` (RTW1-6: an edited old digest, id, method or prev,
    an edited last digest, a removed first or last line, a reorder, a duplicate and a
    changed head are each refused); `only_the_public_columns_depend_on_the_programs`
    (with public columns blanked, the fingerprints of tag 1 and 77 agree for 1 to
    `MAX_EXECUTIONS` executions; unblanked they differ);
    `every_mutation_changes_the_fingerprint` (now also, per table, the main and
    preprocessed next-row sets and a degree hint, and for the 7 tables with public
    columns a first and a last entry: all distinct);
    `rtw1_3_a_changed_byte_table_entry_changes_the_fingerprint` (the red team's case);
    `rtw1_3_layout_and_next_row_mutations_change_the_fingerprint` (every program,
    image and output layout and every table's next-row set of the widest statement).
    `zk/tests/proofs.rs::verify_itself_refuses_non_canonical_proofs` (every hidden
    position +1, one −1 per proof, a filled preprocessed round, a missing round, a
    2-root cap, a commit witness, an empty opening: each `Encoding` from `verify`);
    `unbound_proof_fields_cannot_be_rewritten` and
    `upstream_advisories.rs::{pr_2106_…, pr_2256_…}` now assert that `verify` refuses
    the rewrites.
11. **Suite results.** (2026-09-27, release, this change)
    - `cargo test --locked --release -p blacksilk-zk -p blacksilk-zkvm -- --test-threads=2`:
      zk 34 passed, 0 failed, 2 ignored (timing tests); zkvm 74 passed, 0 failed,
      1 ignored (`stress`); `circuit_fingerprint` 6 passed (log
      `C:/bszkeval/t-fx-rtw1-zk-zk-zkvm.log`).
    - `cargo test --locked --release -p blacksilk-px --lib`: 19 passed, 0 failed.
    - `cargo clippy --locked -p blacksilk-zk -p blacksilk-zkvm --all-targets -- -D warnings`:
      clean. PX-proving suites were not run (not allowed for this change); the PX-side
      consensus fingerprint does not change (item 13).
12. **Open review points.** (i) Wire the digest into the PX consensus manifest in the
    single fingerprint-v3 commit (deferred; proposed entry in the FX-RTW1-ZK report):
    today it is tied to `CIRCUIT_ID` only by a test. (ii) The chain makes an in-place
    edit visible, not impossible: rewriting every later `prev` and the head is still
    possible and must be caught in review. (iii) The advisory suite no longer detects
    an upstream fix of #2106 / #2256 through `verify`; revisit at a Plonky3 migration.
    (iv) The digest covers the reference statements' layouts; a layout function whose
    change shows only on other statements (larger programs, more image words) is
    caught only if it also changes the reference layouts. (v) Stale claims outside this
    change's files are listed in the FX-RTW1-ZK report (px.md §9.1, testnet.md,
    testnet-reset-plan.md, testnet-roadmap.md, `zk/src/params.rs` module text,
    `zkvm/tests/vm.rs`).
13. **Identity impact.** None: `CIRCUIT_ID`, `PARAMS_ID`, proof bytes and the consensus
    fingerprint are unchanged. The test-side circuit digest changes (method 2).
14. **Documentation.** As in item 5.
15. **Review status.** Implemented and tested by FX-RTW1-ZK; red-team re-review
    pending.

---

## daa-lwma75-warm: LWMA-75 with a counted clock of step T/2, warmed over 11 blocks

Revision: 03-F1:lwma75-step-t/2-warm11

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

Revision: none (the order of header checks; every verdict unchanged)

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

Revision: none (the genesis construction: identity, not a rule)

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

Revision: none (the error class of an unknown-version header; every verdict unchanged)

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

Revision: T8:exact-v1-fee

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

Revision: none (mempool policy)

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

### Follow-up (RT-W1b, FX-RTW1B)

Red-team RTW1B-1 (Medium, privacy) showed that §5 and §8 above were wrong as written:
applying the guard on the stem and relay paths made a later-admitting stem peer a
Dandelion black hole, so the origin's embargo fired and it fluffed the transaction
itself. Decision (RT-W1b): the guard applies only on the local origination path
(`Mempool::add`/`check` with `Origin::Local`: RPC `/tx` and `Network::submit_tx`);
peer relay and stem admit a guard-listed transaction normally (`Origin::Peer`).
RTW1B-5: `readmit` now keeps the guard entry when readmission fails. Tests:
`rtw1b_a_later_stem_peer_admits_the_origins_reinjection` (chain),
`a_recently_expired_transaction_is_stemmed_for_a_peer_but_not_originated` (p2p, real
TCP). Guard entries are still not persisted; 33 W2 (originated set) and 38 W4 (wallet
rebroadcast) are required before any privacy claim (RTW1B-2). Merged in 5ec35db.

---

<a id="r12-2"></a>

## R12-2 (a′): the v1 part of PX and deploy transactions counts toward the block weight

Revision: R12-2:a-prime-v1-part-weight

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

### Follow-up (RT-W1b, FX-RTW1B)

The block rule was accepted as is. Red-team RTW1B-3 showed the template claim in §5
("the same unit for both, no cross-unit comparison") was false: a deploy's exact fee
includes 50 per program byte, which is not a weight, so vault-sized deploys outranked
every transfer (11 deploys displaced 367 of 382 transfers in the demonstration).
`Mempool::select` now ranks transfers and deploys by `weight_fee / weight`, where a
deploy's `weight_fee` is its v1 part `rules.standard_fee(n_in, n_out)`; program-byte
fees buy no priority. RTW1B-9: `max_weight` is a `const fn` and
`max_weight(64, 16) × FEE_PER_WEIGHT ≤ PX_STANDARD_FEE` is a compile-time assertion.
Measured worst v1 block (red team, D5): 888 CLSAGs, about 1.9 s single-threaded;
agent 10's benchmark with PX proofs is still owed. Merged in 5ec35db.

---

<a id="tree-capacity"></a>

## PX tree capacity (I3) with 21-D, a fallible apply that halts, and 21-F

Revision: I3:px-tree-capacity

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

---

<a id="approval-conflict"></a>

## approval-conflict: one approval per contract input (F-20-1)

Revision: F-20-1:approval-conflict

Decision: decisions.md, Agent 20 "F-20-1 … ACCEPTED as a v3 consensus item. It adds an
`ApprovalConflict` error (exit 18) and needs a new kernel id. It lands in the SINGLE v3
kernel rebuild"; Agent 50 "F-20-1: accepted, with the listed tests (double/triple
approvals, crossed approvals allowed, error precedence, exit-code table)". Dossier 20
§3.1 (G1), §3.2 (d), §4 F-20-1. Work item CB-B2 item 1.

**1. Problem.** The kernel (`px-core/src/kernel.rs`) let any number of called functions
approve one contract input: every approval matched, so all passed. One consumed record
could then authorize two transitions of its contract in one transaction (the input-side
mirror of Cardano's "double satisfaction"). Value stays conserved by the global balance
(the caller funds any duplicate), but linear contract state forks: a unique item, a
one-shot approval record (R7-2, F-28-4) or a sequence number could be duplicated. The
output side already had the rule (`SpecConflict`).

**2. Demonstrated failure.** On the base commit `b4d9ff9`, a CLAIM witness of the
reference vault with a second function (a copy of CLAIM approving the same input 0 and
specifying output 1) was accepted by the native kernel and by the pinned kernel guest
(exit code 0): scratch test `base_accepts_a_double_approval`, log
`C:/bszkeval/w1-cb-b2/base-demo.log` ("native: Ok("accepted")", "pinned guest exit
code: 0").

**3. Prior art.** Cardano double satisfaction (Plutus documentation, "common
weaknesses"): each resource counted by exactly one validation. Aleo: a record's serial
number is produced by exactly one transition. Zexe: each consumed record's death
predicate runs once, on the whole transaction's local data. Sources: dossier 20 §8.

**4. Alternatives.** (A) Document it as a contract-author rule: fragile and silent.
(B) The kernel rule (chosen). (C) Give functions a view of all approvals (Zexe-style
local data): a larger transcript, a privacy cost across contracts, a redesign.

**5. Affected components.** `px-core/src/kernel.rs`: an approval counter per input
(`approvals > 1 ⇒ ApprovalConflict`), appended as the last `Error` variant (exit code
18), checked right after the approvals are read, next to `Unauthorized` (the two are
exclusive). The kernel ELF (`px/kernel.elf`, new id; section `guest-rebuild`). No
host-side rule changes.

**6. Activation.** v3 genesis base rule set; the pinned kernel is the rule.

**7. Compatibility.** A new kernel id (every PX proof). Exit codes 2–17 unchanged
(append-only). No honest transaction built by the wallet has a double approval (the
vault flows approve one input per call). The kernel budgets were re-measured and are
unchanged (section `guest-rebuild`).

**8. Reorg, wallet, mining and P2P implications.** None beyond the new kernel id: the
rule is inside the proof, so a transaction with a double approval has no proof.

**9. Vectors.** The rejection cases of `an_input_approved_by_two_functions_is_rejected`
(native and guest exit codes) and the exit-code table
(`kernel_exit_codes_are_append_only`).

**10. Regression tests** (`px/tests/unified.rs`, native and the pinned guest):
- `an_input_approved_by_two_functions_is_rejected`: a double approval of input 0, a
  double approval of both inputs (refused at input 0); crossed approvals (function `k`
  approves input `k`) valid, with each function's transcript equal to the kernel's;
  precedence: a double approval whose second approval is by a foreign contract gives
  `ApprovalMismatch`, a double approval of a record not in the tree gives
  `ApprovalConflict` (membership is decided after both inputs), a double approval of a
  dummy gives `ApprovalMismatch`; a third function ("triple approval") is not
  expressible with `MAX_FN = 2` and gives `TooManyFunctions` first.
- `kernel_exit_codes_are_append_only`: every error's exit code, 2–18.
- `contract_rules_reject_their_violations` (12 cases) unchanged.

**11. Suite results.** Section `guest-rebuild` §11 (one run for the whole bundle).

**12. Open review points.** Red team (50): the precedence choices, and whether any
legitimate contract pattern needs two functions to approve one record (dossier 20: none
known; such a contract can put both checks in one program).

---

<a id="px-call-abi"></a>

## px-call-abi: a versioned function prefix, and ABI and output words in the registry (F-28-1, F-28-5)

Revision: F-28-1:abi-word-and-registry-out-words

Decision: decisions.md, Agent 28 "F-28-1 v3 part: ACCEPTED as a v3 consensus item. An
`ABI_VERSION` word leads the function prefix. The registry records `abi` and
`out_words` for each program. Verifier selection by (epoch, abi) is designed now
(W28-9) and implemented with the second kernel generation"; Agent 50 "PX6/ABI: … deploys
reject an unsupported ABI; the ABI and out_words are inside the contract-id payload
hash". Dossier 28 §3.6, §4 F-28-1, F-28-5, §5 W28-1. Work item CB-B2 item 2.

**1. Problem.**
- F-28-1: the call format (`Call`, `OutSpec`, `N_IN`, `N_OUT`, the 16-word prefix
  `io_hash ‖ contract`) was compiled into every function program with no version, and
  nothing recorded which format a registered program used. The first kernel generation
  that changes the format would make every deployed contract uncallable and strand the
  value in its records.
- F-28-5: a function could publish 0–256 output words per call, varying between calls
  of one program, so the length (and the output table height) could fingerprint calls.

**2. Demonstrated failure.** Not a failing behaviour but a missing field: on `b4d9ff9`
the deploy payload carries only `elf ‖ budget` per program (`deploy_payload_bytes`), the
registry entry only `(program, budget)`, the prefix has no version word, and
`check_px_structure` and PX3 accept any output length. The tests below do not compile
on the base (the fields do not exist).

**3. Prior art.** Zcash keeps each pool's verifier and lets old pools be spent out (ZIP
211); Aleo programs carry an `edition`. Sources: dossier 28 §8.

**4. Alternatives.** A multi-ABI kernel (every transaction pays for all formats;
rejected); no versioning until the second generation (then the first contracts are
stranded; rejected); an output length pinned per call by the caller (no privacy gain;
rejected).

**5. Affected components.**
- `px-core/src/call.rs`: `ABI_VERSION = 1`, `PREFIX_WORDS = 21`, `Window`,
  `function_prefix(abi, io_hash, contract, window)` =
  `abi ‖ io_hash ‖ contract ‖ window words` (the window is section
  `px6-validity-window`).
- `px/src/prove.rs`: `FunctionCall::abi`; the statement's function prefixes use each
  call's registered ABI and the transaction's window; `prove` writes `ABI_VERSION`;
  `verify`/`check_shape` take the window; a statement with `n_fn > MAX_FN` is `Shape`
  instead of a panic (F-20-5).
- `tx/src/px.rs`: `Registration { elf, budget, abi, out_words }` (`Registration::new`
  for the current ABI); the payload appends `varint(abi) ‖ varint(out_words)` per
  program, so the contract id covers them; decoding bounds `out_words ≤
  MAX_FN_OUTPUT_WORDS`; `check_deploy_structure` refuses `abi ≠ ABI_VERSION`
  (`TxError::PxUnsupportedAbi`, stateless) and `out_words > MAX_FN_OUTPUT_WORDS`
  (`PxShape`).
- `tx/src/validate.rs`: `ChainView::px_function` returns `PxProgram { program, budget,
  abi, out_words }`; PX3 also requires `outputs.len() == out_words`
  (`TxError::PxOutputWords`, stateless for scoring: a registration is fixed by its
  contract id); PX5 takes the ABI from the registry. `tx/src/state.rs`: the registry
  stores both fields.
- `tx/src/px_builder.rs`, `wallet`: builders and the vault deploy use
  `Registration::new(.., vault::OUT_WORDS)`; `wallet/src/main.rs` `px-deploy` takes
  `--out-words` per program; `check_vault_deploy` requires the current ABI and one
  output word.

**6. Activation.** v3 genesis base rule set.

**7. Compatibility.** New deploy encoding (two varints per program), new contract ids,
new vault id (its prefix changed); the kernel does not use the prefix. The deploy fee
covers the two extra payload bytes per program through the per-byte rate.

**8. Reorg, wallet, mining and P2P implications.** Registry undo unchanged (entries are
removed whole). Wallets must register `out_words` for custom programs (CLI flag).
`PxUnsupportedAbi` and `PxOutputWords` are stateless (a relaying peer is penalized, as
for any structure fault). Verifier selection by (epoch, ABI) is designed in
docs/contracts.md §4.2 and not implemented (W28-9).

**9. Vectors.** The contract id changes with the ABI, the output words or the budget
(`registrations_carry_their_abi_and_output_words`); the prefix layout
(`a_function_transcript_must_match_the_kernel`: word 0 is `ABI_VERSION`, words 1–8 the
kernel's `io_hash`, 9–16 the contract, 17–20 the window).

**10. Regression tests.**
- `tx/tests/px_window.rs::registrations_carry_their_abi_and_output_words`: contract id
  sensitivity; an unsupported ABI refused by the builder's self-check
  (`PxUnsupportedAbi`); too many output words refused (`PxShape`) and not decodable;
  the bound itself decodes.
- `tx/tests/px_consensus.rs::a_private_contract_is_deployed_and_used_through_consensus`
  (proving): the registry records budget, ABI and output words; a claim with one more
  output word is `PxOutputWords` before the proof; a claim with another window is
  refused (its v1 signatures cover the prefix, so `InvalidSignature` comes first;
  the proof alone refuses it in `px/tests/unified.rs`).
- `px/tests/unified.rs::lock_then_claim_proves_verifies_and_pays_the_recipient`
  (proving): the proof does not verify under another ABI or another window; a
  statement with three functions is `Shape`.
- `chain/tests/manager.rs::restart_rebuilds_the_px_state_exactly` (proving): the
  registry keeps ABI and output words across a restart.
- `wallet/src/wallet/contracts.rs::a_vault_deploy_needs_the_current_abi_and_one_output_word`.

**11. Suite results.** Section `guest-rebuild` §11.

**12. Open review points.** W28-9 (verifier dispatch, coexistence and sunset) must be
reviewed before any second generation is designed. The fingerprint does not list
`ABI_VERSION` or `PREFIX_WORDS` yet (owed to agent 40's fingerprint v3; both are in the
vault's id, and the ABI is a deploy rule).

---

<a id="px6-validity-window"></a>

## px6-validity-window: the transaction validity window (PX6)

Revision: PX6:validity-window

Decision: decisions.md, Agent 28 "Validity window, PX6: ACCEPTED for v3. Transactions
carry `[not_before, not_after]` in the PX prefix, covered by h_tx and copied into each
function prefix. The rule is contextual and never scored. Default (0,0) means
unbounded"; Agent 50 "the mempool refuses premature transactions;
`revalidate_after_extension` takes the height; templates filter by the window; the
proof cache never skips PX6"; Agent 48 AT-5. Dossier 28 §3.2, F-28-3. Work item CB-B2
item 3.

**1. Problem.** A contract function had no clock: it sees only its private input, and
the root window cannot give an unambiguous height (F-28-3). No timeout, refund, HTLC or
deadline could be expressed, and the reference vault had no refund.

**2. Demonstrated failure.** On `b4d9ff9` the vault guest has no refund entry: selector
2 halts with 2 (`base_vault_has_no_refund`, `C:/bszkeval/w1-cb-b2/base-demo.log`), and a
PX transaction has no field a function or consensus could use as a bound. The PX6
behaviours below are new; each test fails to compile on the base. The checks that must
not be skipped were verified to be load-bearing by mutation (§11).

**3. Prior art.** Bitcoin BIP 65 (the script checks the transaction's `nLockTime`,
consensus checks `nLockTime` against the block); Zcash ZIP 203 (`nExpiryHeight`,
contextual); Aztec `expiration_timestamp`; Neptune Cash (scripts read the kernel's
timestamp through its hash, and the timestamp is checked against the block). Sources:
dossier 28 §3.2, §8.

**4. Alternatives.** An anchor-height clock (R5-3; ambiguous, F-28-3); a per-function
window in each function's output header (R7-1; one window per call, several rules);
reserving zeroed prefix words and activating later (rejected: the testnet reset is
free now).

**5. Affected components.**
- `px-core/src/call.rs`: `Window { not_before, not_after }` (`contains`,
  `is_well_formed`, `words`), in the function prefix.
- `tx/src/px.rs`: `PxTx::window`, two varints in the prefix after `bridge_out` (so in
  `h_tx` and the transaction id); `check_px_structure` refuses an inverted window
  (`PxWindowInverted`, stateless).
- `tx/src/validate.rs`: `check_px_window(tx, height)` (`TxError::PxWindow`,
  contextual); in `validate_px` / `validate_px_without_proof`, first among the
  contextual rules; in `revalidate_after_extension(tx, chain, height)` (new `height`
  argument) and so in `revalidate_between`; in the block path for every PX transaction,
  in the per-transaction contextual loop, independent of the verified-proof cache.
- `chain/src/mempool.rs`: `revalidate` passes the next height to the extension check;
  `select(height, ..)` skips PX transactions whose window excludes the template's
  height; `chain/src/manager/template.rs` passes it. `p2p/src/net/admission.rs` passes
  the next height to `revalidate_after_extension` (one argument; its classification
  already treats contextual errors as unscored).
- `tx/src/px_builder.rs`: `PxPlan::window`; the window enters both hedge contexts.
  Wallets use `Window::UNBOUNDED` except for vault claims and refunds with a timeout
  (section `vault-v3`).

**6. Activation.** v3 genesis base rule set.

**7. Compatibility.** New PX transaction encoding (two varints, two bytes for the
default); every PX transaction id, `h_tx` and proof changes; the kernel is unchanged by
the window (the vault id changes: it echoes the window).

**8. Reorg, wallet, mining and P2P implications.**
- Reorg: after a reorganization a pooled transaction can become premature again
  (dropped by the full revalidation; the wallet keeps it and resubmits) or valid again
  after expiring (the wallet resubmits). Heights race at the edges, so PX6 is never
  scored.
- Mining: templates select by the window; the block path rejects a transaction outside
  it whatever the cache says.
- Wallet: `(0, 0)` by default, so no fingerprint; a claim window ends at `T − 1`, a
  refund window starts at `T`; wallets should round `T` (docs/contracts.md §4.3, px.md
  §12).
- P2P: relay admission checks PX6 at the next height (contextual: not penalized, the
  rejection is cached per tip).

**9. Vectors.** The boundary table of `the_window_holds_exactly_between_its_ends`:
window `[20, 30]` valid at 20, 25, 30, invalid at 19 and 31; `(0, 0)` valid at 0, 1 and
`u64::MAX`; `[20, 0]` valid at `u64::MAX`.

**10. Regression tests.**
- `tx/tests/px_window.rs` (no proving): encoding round trip and `h_tx` binding,
  unbounded by default; inverted window stateless; the boundary table and
  classification (`is_stateless`, `is_stateless_at`), a stateless fault reported first;
  `revalidation_after_an_extension_expires_the_window`;
  `a_cached_proof_never_skips_the_window` (blocks validated with every proof vouched
  for by the cache: premature and expired transactions refused with `PxWindow`, the
  edges valid).
- `chain/src/mempool.rs`: `templates_take_only_transactions_whose_window_contains_the_height`,
  `revalidation_drops_transactions_outside_their_window` (extension expiry at the next
  height; a reorganization to a lower height drops a transaction premature again).
- `tx/tests/px_consensus.rs::a_vault_refund_obeys_its_validity_window_through_consensus`
  (proving): a real vault refund with window `[T, 0]` is `PxWindow` at every height
  below `T` and valid at `T`, `T + 1`, `T + 1000`; a block at `T − 1` including it is
  refused with the proof vouched for by the cache; the block at `T` connects and pays
  the refund.
- `px/tests/unified.rs`: a proof does not verify under another window; a function
  echoing another window is `FunctionMismatch`.

**11. Suite results.** Section `guest-rebuild` §11.

**12. Open review points.** Red team (50): the window boundaries, template and mempool
interplay across reorganizations, and whether premature transactions can load relays
at no cost (they are refused after the stateless checks and the proof decode, and the
rejection is cached per tip).

### Follow-up (RT-W1c, FX-RTW1C): PX6 before the range proof, and the expiring-soon policy

Red team RT-W1c (internal review, not an audit), decisions.md "RT-W1c": PX6 ACCEPT WITH
CHANGES; RTW1C-4 and RTW1C-5.

- **RTW1C-5 (check order; consensus path, verdicts unchanged).** In
  `tx/src/validate.rs::validate_px_checks` (mempool, RPC and relay full validation) PX6
  now runs right after the proof decode and **before** the Bulletproofs+ range proof,
  so a premature or expired transaction costs no range-proof verification. Every rule
  is a pure check, so validity is unchanged; only a transaction that is both outside
  its window and invalid for its range proof gets `PxWindow` (contextual, unscored)
  instead of `RangeProofInvalid` on this path. Relay admission's cheap phase already
  checked PX6 without the range proof, so the two paths now agree. The block path is
  unchanged. Demonstrated: `tx/tests/px_window.rs::the_window_is_checked_before_the_range_proof`
  (a PX transaction with a real v1 part and a broken range proof: `PxWindow` when
  premature, `RangeProofInvalid` inside its window) fails on the base with
  `RangeProofInvalid` for the premature case (log
  `C:/bszkeval/fx-rtw1c/base-rtw1c5.log`).
- **RTW1C-4 (expiring-soon policy; not consensus).** `tx::validate::px_expires_soon`:
  `not_after ≠ 0 ∧ not_after < next + PX_EXPIRING_SOON_BLOCKS` (3, Zcash's
  `TX_EXPIRING_SOON_THRESHOLD`). `chain/src/mempool.rs`: `add` and `check` refuse such
  a PX transaction first (`MempoolError::ExpiringSoon`, before any validation, so a
  relay spends no proof verification on it); `readmit` (a reorganization) skips it;
  pooled transactions are not re-checked against it. The relay and stem paths reach it
  through `submit_tx` / `check_tx`; their `(_, Err(_), _)` arm drops it unscored. The
  relay's cheap phase (`p2p/src/net/admission.rs`, not in this work item's ownership)
  still decodes the proof and takes a node-wide PX token before that refusal; the
  change owed there: in the cheap closure, for `Transaction::Px(t)`, refuse early as a
  contextual failure when `validate::px_expires_soon(t, c.height() + 1)` (a
  `ctx_reject`, never `misbehave`). The wallet builds no claim within the margin
  (section `vault-v3`, Follow-up). Tests:
  `tx/tests/px_window.rs::a_window_ending_within_three_blocks_expires_soon`,
  `chain/src/mempool.rs::transactions_expiring_soon_are_refused_but_readmitted`.

---

<a id="vault-v3"></a>

## vault-v3: the reference vault with contract-bound locks, hedged blinds, a timeout and a refund (W28-4)

Revision: none (a program rebuild: its id is listed in the manifest)

Decision: decisions.md, Agent 28 "Vault changes (W28-4): the lock hash includes the
contract id, and blinds are hedged. The vault is rebuilt ONCE together with the kernel"
and "The vault gains a timeout and refund path"; Agent 37 (the vault secret derivation
`px/wallet/vault-secret/v1`, K6). Dossier 28 F-28-7, §3.2, W28-4. Work item CB-B2 item
4. The vault is a demonstration contract, not consensus code; its program id is pinned
and fingerprinted.

**1. Problem.** The lock hash `Hk(LOCK, secret)` did not bind the contract, so a secret
reused across vault instances opened every instance whose opening one held (F-28-7);
the vault had no timeout and no refund; its function blind and record `rcm` came from
the caller's RNG only (transactions.md §10).

**2. Demonstrated failure.** On `b4d9ff9`: the pinned vault guest accepted a CLAIM of a
record of another contract with the same secret (exit 0,
`base_lock_hash_ignores_the_contract`), and had no refund (`base_vault_has_no_refund`);
log `C:/bszkeval/w1-cb-b2/base-demo.log`.

**3. Prior art.** HTLCs (Bitcoin BIP 65 / BIP 199), with a claim before and a refund
after a timeout; application hashes that include the contract instance (Aztec's
contract-address siloing). Sources: dossier 28 §3.7 item 10, §8.

**4. Alternatives.** A cleartext timeout in the record data (the remaining words cannot
hold two 248-bit locks; truncation would weaken the lock binding; rejected); a refund
paid to a fixed owner with no refund secret (anyone holding the opening could trigger
it and withhold the new record's opening, PX-F4; rejected).

**5. Affected components.**
- `zkvm/guests/vault/src/main.rs`: record data `Hk(TERMS, C ‖ claim_lock ‖ refund_lock
  ‖ timeout₁₆[4])`, `claim_lock = Hk(LOCK, C ‖ secret)`, `refund_lock = Hk(REFUND, C ‖
  refund_secret)`; LOCK (a zero refund lock without a timeout), CLAIM (with a timeout,
  only if `not_after ≠ 0 ∧ not_after < T`), REFUND (only with a timeout and
  `not_before ≥ T`); the window read from the input and echoed in the prefix; public
  output: the selector. Domains `0x5641_0001..3` (application range).
- `px/src/vault.rs`: `Terms`, `lock_of(contract, secret)`, `refund_lock_of`,
  `record_data`, `lock_call`, `claim_call`, `refund_call` (window argument), `REFUND`,
  `OUT_WORDS = 1`, `BUDGET` re-measured.
- `px/src/wallet.rs`: `hedged_digest` and the labels `px/witness/fn-blind/v1`,
  `px/witness/contract-rcm/v1`.
- `wallet/src/wallet/contracts.rs`: `px_vault_lock` (no timeout, unchanged API),
  `px_vault_lock_until` (timeout; returns the terms), `px_vault_claim`,
  `px_vault_claim_with_terms`, `px_vault_refund`, `px_vault_refund_secret_for`
  (`H32("px/wallet/vault-secret/v1", hk_px ‖ net ‖ contract ‖ rho ‖ "refund")`); the
  blind and the record `rcm` hedged with `hk_px`. `wallet/src/wallet/keys.rs`: the K6
  recovery compares the claim-only record data (the derivation itself is unchanged).
- `tools/vectors/poseidon2_hk.py` and `px/tests/data/hk_vectors.txt`: the lock, refund
  lock and terms vectors.

**6. Activation.** A new pinned vault id at the v3 genesis (section `guest-rebuild`).

**7. Compatibility.** New vault id and record format; no earlier vault exists on any
launched network. The W2-37 vault secret derivation is unchanged; its recovery tests
pass.

**8. Reorg, wallet, mining and P2P implications.** A claim window reveals the timeout
(round it); a claim can be censored until the refund is valid (leave a margin); the
refund needs the timeout, which the wallet returns at lock time and does not store (a
record without a timeout recovers fully from the seed).

**9. Vectors.** `vault.lock_of`, `vault.refund_lock_of`, `vault.terms` in
`px/tests/data/hk_vectors.txt`, from the independent Python implementation
(`tools/vectors/poseidon2_hk.py --check`).

**10. Regression tests.**
- `px/tests/unified.rs::the_vault_enforces_its_timeout_refund_and_lock_binding` (the
  pinned vault guest against the native kernel's statement): CLAIM only with a window
  ending before `T`, REFUND only from `T`; the wrong key opens nothing; a copied lock in
  another instance does not open; LOCK without a timeout needs a zero refund lock.
- `px/tests/unified.rs::budgets_leave_headroom`: LOCK with a timeout, CLAIM, CLAIM with a
  timeout, REFUND within 95% of `vault::BUDGET`.
- `px/tests/hk_vectors.rs` (the three vectors).
- `tx/tests/px_consensus.rs::a_vault_refund_obeys_its_validity_window_through_consensus`
  (proving).
- `wallet/src/wallet/contracts.rs`: the refund secret is seed-recoverable and distinct
  from the claim secret; `px_vault_secret` opens only records without a timeout.
- `wallet/src/wallet/keys.rs` K6 tests (unchanged: `a_restored_wallet_recovers_its_vault_secret`,
  `vault_secrets_are_deterministic_and_bound_to_the_record`).

**11. Suite results.** Section `guest-rebuild` §11.

**12. Open review points.** The wallet CLI has no command for locks with a timeout,
claims with terms or refunds (library only; `wallet/src/main.rs` is outside this work
item). A dedicated tag for the refund-secret derivation (instead of the suffix) is a
choice for agent 19's registry.

### Follow-up (RT-W1c, FX-RTW1C): rounded windows, a seed-recoverable refund, not an HTLC

Red team RT-W1c (internal review, not an audit), decisions.md "RT-W1c": vault-v3 ACCEPT
WITH CHANGES; RTW1C-2, -3, -6, -7, -8. Wallet side only: the vault guest, its id, its
budget and the kernel are unchanged, so nothing here is a consensus change.

- **RTW1C-2 (Low/Medium, privacy): windows no longer reveal `T`.** §8 above ("a claim
  window reveals the timeout") is superseded. The wallet requires `T` to be a multiple
  of 16 (`VAULT_TIMEOUT_GRANULE`), and builds a claim for the next block `n` with
  `[0, min(T − 1, round_up16(n + 3) + 31)]` and a refund with `[max(T,
  round_down16(n)), ∞)` (`vault_claim_window`, `vault_refund_window`). A claim window
  always ends at `16k − 1` and a refund window always starts at `16k`, so they show
  `T` only when the rounded bound is itself `T − 1` (a claim within about 50 blocks
  before `T`) or `T` (a refund within 16 blocks after it). Test
  `wallet::contracts::vault_windows_do_not_reveal_the_timeout` (every `T ≤ 2 000` and
  every next height up to `T + 99`); on the base the claim ended at `T − 1` and the
  refund started at `T` always.
- **RTW1C-3 (Medium, funds at risk): the refund survives a restore.** On the base a
  locker restored from its seed could not refund a lock delivered to the counterparty:
  the record's `rcm` was hedged-random and existed only in the wallet file and the
  counterparty's ciphertext, and the timeout was not stored at all. Now (the simpler
  of the two options in the decision, extended by what it lacked):
  - the terms (claim lock, timeout) are stored in the wallet file before the lock is
    sent (`Wallet::vault_terms`, `px_vault_refund_stored`, `px_vault_terms`);
  - the `rcm` of a lock with a timeout is derived, `H32("px/wallet/vault-rcm/v1",
    hk_px ‖ u8 network ‖ C ‖ rho_vault)` (`px_vault_rcm_for`);
  - the claim lock is not derivable when the counterparty chose the secret (the swap
    case), so the lock's change output, which goes to the locker's own address 1,
    carries the claim lock in its `data`: inside its commitment and its ciphertext to
    the locker, invisible to anyone else and never published when the change is spent;
  - `Wallet::recover_vault_locks` (at load, and before a stored-terms refund) finds each
    held change with nonzero data whose `rho` is `output_rho(nf, 1)` of a record this
    wallet spent in the same block (only its own locks qualify), rebuilds the vault
    record (`rho = output_rho(nf, 0)`, the derived `rcm` and refund lock, the value from
    the lock's inputs, fee and change) for every usable vault contract, and searches
    `T` over the multiples of 16 from 4 096 blocks below the lock's block to
    `MAX_VAULT_TIMEOUT_AHEAD` = 2^20 above it, keeping a candidate only if its
    commitment is in the lock's block.

  Why not "the opening and `T` to self in the change ciphertext": the delivery
  plaintext has a fixed length (consensus fixes the ciphertext length) and holds exactly
  one record, so the only free space is the change record's own 248-bit `data`, which
  the claim lock fills; the rest is derived or searched. Test
  `wallet::contracts::a_restored_locker_recovers_its_timed_lock_and_can_refund`: a
  restored wallet that knows only its spent input, its change, the block's commitments
  and the vault contract recovers the record (opening, value, position) and the terms
  for a counterparty-chosen secret; the pinned vault guest accepts its REFUND at `T`
  within `vault::BUDGET`, with the prefix the kernel requires; the native kernel
  accepts spending the recovered record; the terms survive the wallet file, and a file
  saved before the recovery recovers at load; another seed and a lock without the
  marker recover nothing; a full unmatched search is timed and printed. On the base
  none of this existed (the `rcm` was random, so no restore could rebuild the record).
- **RTW1C-4 (wallet side).** A claim whose window would end within 3 blocks of the
  next block is not built; the lock requires `T − 1 ≥ n + 3`
  (`vault_timeouts_are_rounded_and_bounded`).
- **RTW1C-6 (Info).** docs/contracts.md §8 and px.md §13.4 state that the vault is
  **not an HTLC**: a claim proves the secret without publishing it, so no atomic swap
  is possible with two vaults.
- **RTW1C-7 (Info).** The refund secret has its own tag, `px/wallet/vault-refund/v1`,
  instead of the `"refund"` suffix; the new `rcm` tag is `px/wallet/vault-rcm/v1`.
  Both are in `crypto::hash::tags::ALL` (the distinctness test) and pinned with the
  other frozen wallet tags (`frozen_wallet_tags_are_pinned`); the coordinator adds them
  to the frozen list in decisions.md. The derivations are covered by
  `the_refund_secret_and_rcm_have_their_own_tags`.
- **RTW1C-8 (Info).** Before every lock the wallet dry-runs every way out of the new
  record with its real opening: CLAIM with the secret and, with a timeout, REFUND with
  its refund secret, each checked for exit code 0, the kernel's prefix (a wrong secret
  gives another `io_hash`), exactly `vault::OUT_WORDS` output words and the registered
  budget (`a_lock_dry_runs_every_way_out_of_the_record`). docs/contracts.md §6 item 21
  is the author-checklist rule.
- **Open.** The wallet CLI still has no commands for timed locks, stored-terms refunds
  or the recovery (`wallet/src/main.rs`, outside this work item). A recovered record
  that was already claimed or refunded before the restore is listed until its refund
  is refused (the wallet does not query nullifiers).

---

<a id="guest-rebuild"></a>

## guest-rebuild: the single v3 kernel and vault rebuild, with the guest link layout (CI-1)

Revision: none (a program rebuild: the ids are listed in the manifest)

Decision: decisions.md, Agent 43 "W4 single kernel/vault rebuild: gated on all
guest-affecting merges (20 F-20-1, 28 ABI/PX6/vault, 19 comments), plus W5 script
hardening first"; "CI-1 fix DECIDED: the guest linker script starts SECTIONS at 0x10000
… A `/DISCARD/ : { *(.comment) }` rule … The zkvm id definition is UNCHANGED … New
tests: no PT_LOAD at offset 0, and no .comment section. Acceptance: byte-identical ELFs
on windows, ubuntu and ubuntu-arm in CI at the rebuild commit." Work item CB-B2 item 5
(with W28-3, item 6).

**1. Problem.** The first `PT_LOAD` of the pinned guests started at file offset 0, so
the program id covered the ELF header, whose `e_shoff` moves with the host-specific
`.comment` strings: Linux rebuilt different ids (CI-1). And every guest-affecting v3 item
needs one rebuild, done once.

**2. Demonstrated failure.** On `b4d9ff9`, `px/kernel.elf` and `px/vault.elf` have a
`PT_LOAD` at file offset 0 (size `0x130` for the kernel) and a 153-byte `.comment`
(`C:/bszkeval/w1-cb-b2/base-elf-layout.log`); the new test
`pinned_guests_load_no_header_and_carry_no_comment` fails on that layout by
construction (`the_layout_checks_detect_the_default_layout` exercises the detector on
it). The Linux mismatch itself is in CI runs 84/85 (decisions.md CI-1).

**3. Prior art.** Reproducible builds compare whole artifacts across hosts (Bitcoin
Core and Monero Guix builds); linker scripts that keep headers out of loaded segments
are common for bare-metal images. Sources: dossier 43 §8.

**4. Alternatives.** `--nmagic` (ids agree but files still differ; `reproduce.sh` would
compare loaded bytes only); a post-link `objcopy`; changing the program-id definition
(a consensus change in zkvm; not needed).

**5. Affected components.** `zkvm/guests/guest.ld` (new); `GUEST_FLAGS` in
`zkvm/guests/build.sh` and `.cargo/config.toml` (`-Clink-arg=-Tguest.ld`);
`px/kernel.elf`, `px/kernel.id`, `px/vault.elf`, `px/vault.id` (rebuilt);
`zkvm/tests/fixtures/guest-{sum,arith}.elf` (relinked by `build.sh`);
`zkvm/guests/reproduce.sh` and `.github/scripts/guests-reproduce.sh` (a `SUMMARY` line
per guest and a CI notice with each host's ids and hashes); `px/tests/elf_paths.rs`
(the layout tests); `zkvm/guests/README.md`. The zkvm id definition is unchanged.

**The rebuild** (Windows, rustc 1.98.1 `48a229cea`, `x86_64-pc-windows-gnu`), inputs:
F-20-1 (kernel), the ABI and window prefix and the v3 vault (vault), and the layout
(both):

| Guest | Program id (`px/*.id`) | ELF sha256 | Bytes |
|---|---|---|---|
| kernel | `ef75a53554b953c1f8f199064b1ae1cd9a08a51f75e0f49fe510d66035c522b4` | `f30c54a78c9557d1b647030fb0a85c88b60fee7601f970e3a0336aaf22bc3fb3` | 19 076 |
| vault | `3fdec8034d22fb685bb52b341695a98a5629ced43736aacf0dce86c9c036b9da` | `134a40dc050a4be28dadce635ebd4191fa02e393a3c4d55f05f8419be403bbcf` | 13 444 |

Previous (the pre-rebuild neutral build): kernel `0577e667…`, vault `666f7aab…`. The
first `PT_LOAD` of each is at file offset `0x1000`; neither has a `.comment`.

**Budgets re-measured** (`budgets_leave_headroom`, which now includes the widest kernel
branch profile, two contract inputs with crossed approvals, and every vault entry):
- kernel: unchanged (`n_fn = 2` with crossed claims uses 32 182 of 35 600 cycles; the
  tightest table is `lt`, 19 316 of 20 400, 94.7%);
- vault: raised to cycles 6 000, keys 2 700, add 4 300, bit 260, lt 3 900, shift 240,
  mul 240, poseidon 27 (REFUND, the widest entry, uses 5 539 cycles, 2 544 keys and
  25 Poseidon2 rows).

**6. Activation.** v3 genesis: the kernel id is consensus; the vault id is pinned and
fingerprinted.

**7. Compatibility.** Every PX proof changes (new kernel id). Fingerprint changes (the
full manifest diff: before `C:/bszkeval/w1-cb-b2/manifest-before.txt`, after
`manifest-after.txt`): `px.KERNEL_PROGRAM_ID` (this section and `approval-conflict`),
`px.VAULT_PROGRAM_ID` (this section, `px-call-abi`, `px6-validity-window`, `vault-v3`),
`px.vault.BUDGET` (`vault-v3`); nothing else. The digests follow: PX side `4189f436…`,
node testnet `ca6d87d5…`, regtest `9975ed2e…`, mainnet `9fcfac47…` (re-pinned in
`px/tests/consensus_fingerprint.rs` and `node/tests/deploy_configs.rs`).

**8. Reorg, wallet, mining and P2P implications.** None beyond the ids.

**9. Vectors.** The ids and hashes above; `reproduce.sh` checks them on every CI host.

**10. Regression tests.** `px/tests/elf_paths.rs::pinned_guests_load_no_header_and_carry_no_comment`
and `the_layout_checks_detect_the_default_layout`; `the_vault_program_id_is_pinned`;
the kernel id pin in `px/tests/proof.rs`; native = guest in `px/tests/kernel.rs`,
`unified.rs`, `fuzz.rs`; `zkvm/tests/guest.rs`, `vm.rs`, `fuzz.rs` on the relinked
fixtures.

**W28-3 evidence (P0, F-28-2).** A two-function transaction (kernel + vault CLAIM +
vault LOCK), proven and verified end to end
(`px/tests/unified.rs::a_two_function_transaction_proves_and_verifies`), measured on this
machine (i7-6700, one proving test at a time; other agents' builds may have been
running): **3 629 639 bytes**, prove 119.9 s, verify 369 ms. In the same run the kernel
plus one function (CLAIM) gave 3 009 904 bytes in 65.6 s. The two-function proof is
below `MAX_PROOF_BYTES` (4 MiB) and below the 3.8 MB threshold of decision 22 (above it,
"a deploy-time proof-size bound"), with a 4.5% margin to 3.8 MB. Agent 22's widest-proof
measurement (other function pairs, larger budgets) is still owed.

**11. Suite results** (branch `w1-cb-b2`, release builds on this machine; the exact
commands and counts are in the W1-CB-B2 final report):
- non-PX suites (tx, px-core and px without proving, chain, wallet, node, p2p, the
  zkvm guest fixtures): 597 passed, 2 failed, 5 ignored on the first run; the two
  failures were `tx/tests/deploy_rules.rs`'s independent fee formula, which lacked the
  two new payload fields; after that fix `deploy_rules` passed 9 of 9. The relinked
  fixtures also pass `zkvm/tests/vm.rs` (2) and `fuzz.rs` (14).
- PX-proving, one at a time with at least 7 GB free: px `unified` 12, `proof` 3; tx
  `px_consensus` 4 (a first run failed one expectation, a window change refused by the
  v1 signatures before the proof; corrected), `fuzz_decode` 1; chain
  `restart_rebuilds_the_px_state_exactly` 1; wallet `private_funds_move_over_rpc`,
  `px_records_follow_a_reorganization`, `a_vault_is_deployed…`,
  `an_uncertain_vault_lock…` 4; p2p `px_transactions_travel_the_stem…`,
  `invalid_px_transactions_get_the_relaying_peer_penalized` 2. All passed.
- Mutation checks: each of 7 new checks removed in turn (the block-path PX6, the
  extension revalidation's PX6, the template filter, the admission PX6, the native
  `ApprovalConflict`, the inverted-window rule, the ABI rule) is caught by its test.
- `cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --check`
  clean; `guests-reproduce.sh` on Windows byte-identical.

**12. Open review points.**
- The Linux x86_64 and arm64 CI legs must reproduce the same bytes after the push
  (coordinator), and one operator build (owner). If they differ, the fallback is the
  zkvm id-rule change in dossier 43 (a consensus change, not taken here).
- Agent 40's fingerprint v3 should list `ABI_VERSION`, `PREFIX_WORDS`, the vault's
  REFUND entry, domains and `OUT_WORDS` (`px/src/fingerprint.rs` notes them).
- Agent 26's P-5 re-run on the new kernel and vault, and agent 22's widest-proof
  measurement.

### Follow-up (RT-W1c, FX-RTW1C): the budget claim corrected (RTW1C-9)

Red team RT-W1c (internal review, not an audit) found the "kernel: unchanged" line of
§5 above wrong. `budgets_leave_headroom` measured four sampled witnesses (CLAIM-shaped
calls, whose specified outputs are user payouts), not every shape the kernel accepts. A
specified **contract** output and some approval patterns take the kernel's few
data-dependent comparisons (`read_spec`'s foreign-contract test, the output-owner rule,
`by_own_contract`), and on this rebuild's budgets:
- `n_fn = 1`, one function specifying two contract outputs from two user inputs (two
  new records of one contract in one call): `bit` 1 714 of 1 700 (100.8%, **over**);
  a partial withdrawal (a contract input and a contract output): `bit` 1 692 of 1 700
  (99.5%); two contract inputs and two contract outputs: `lt` 17 012 of 17 900 (95.0%);
- `n_fn = 2`, contract outputs: `bit` 1 842 of 1 900 (96.9%), `lt` 19 381 of 20 400
  (95.0%).

The widest profile quoted above (`lt` 19 316 of 20 400, 94.7%) was therefore not the
widest. The kernel ELF and id of this rebuild are unaffected; the budgets are prover and
verifier parameters, raised in section `kernel-budget-shapes` below (logs
`C:/bszkeval/fx-rtw1c/base-demo.log`, the red team's demonstration, and
`C:/bszkeval/fx-rtw1c/base-kernel-budget.log`, the exhaustive test on the base).

---

<a id="kernel-budget-shapes"></a>

## kernel-budget-shapes: the kernel budgets cover every honest shape, and each execution fits its own budget (RTW1C-1)

Revision: RTW1C-1:kernel-budgets-cover-every-shape

Decision: decisions.md, "RT-W1c (CB-B2 red team), Lead decisions 2026-09-28":
"RTW1C-1 (Medium, liveness, pre-existing): kernel budgets raised so every honest shape
uses at most 95% of every table, verified by an exhaustive or property test over all
shapes. This must land BEFORE the freeze." Work item FX-RTW1C.

**1. Problem.** `prove::kernel_budget(n_fn)` fixes the kernel's table heights for each
function count (px.md §4.4). Honest shapes exceeded it (section `guest-rebuild`,
Follow-up). An over-budget kernel execution was not refused by itself: the shared ALU
and Poseidon2 tables are padded to `pow2(Σ budgets)` over the kernel and every called
function, and the prover only checked the padded heights. So whether such a transaction
could be proven depended on the other calls' registered budgets: with a function budget
`B_f` such that `1 700 + B_f` is a power of two, a one-function transaction with two
contract outputs was unprovable (liveness), and the same transaction proved with other
functions.

**2. Demonstrated failure.** On the base `e986250`:
- the red team's scratch test (`C:/bszkeval/rt-w1c-demo.patch`, log
  `C:/bszkeval/fx-rtw1c/base-demo.log`): `n1 C+C one fn approves both, specs both
  contract outs: … bit 1714/1700 (100.8%) … OVER95=["bit", "lt"]`;
- the new exhaustive test `px/tests/kernel_budget.rs::every_honest_kernel_shape_fits_its_budget_with_headroom`
  fails on the base budgets with the four violations listed in the `guest-rebuild`
  Follow-up (log `C:/bszkeval/fx-rtw1c/base-kernel-budget.log`).

**3. Prior art.** Fixed-shape proofs are the norm for private transactions: a Groth16
circuit (Zcash Sprout, Sapling) has one shape per statement type, so no witness can
exceed it; zkVMs that pad traces to a power of two per execution (RISC Zero's segments)
choose the padded size from the actual execution and publish it, which reveals the
length, the trade-off BlackSilk's fixed budgets avoid (px.md §4.4, R-5). The lesson
taken here: a fixed shape is only safe if it provably covers every honest execution.

**4. Alternatives.**
- (A) Make the kernel strictly constant-work (evaluate every comparison
  unconditionally): a kernel rebuild (new ELF and id) for a few dozen rows, and the
  budgets would still need a measured margin. Not taken now; recorded for the next
  kernel change.
- (B) Raise the budgets over the maximum of every accepted shape, and refuse any
  execution over its own budget before proving (chosen: no ELF change, deterministic
  provability).
- (C) A budget per shape class: the class would be public in the proof shape (a
  privacy loss). Rejected.

**5. Affected components.**
- `px/src/prove.rs`: `kernel_budget(1)`: `bit` 1 700 → 1 850, `lt` 17 900 → 18 050;
  `kernel_budget(2)`: `bit` 1 900 → 2 000, `lt` 20 400 → 20 550 (each the maximum over
  every accepted shape plus about 6%, rounded up to 50). `n_fn = 0` and every other
  table unchanged (all at or below 94.2%). `prove` runs the kernel guest and every
  function before proving and refuses an execution over its own budget in any table
  (`TransferError::OverBudget { execution, table, used, budget }`); the new
  `prove::over_budget` names the first such table.
- `px/src/fingerprint.rs`: the kernel budgets enter the consensus manifest as
  `px.kernel.BUDGET.n_fn_0`, `…_1`, `…_2` (they were missing: two nodes with different
  budgets disagree on every PX proof).
- `tx/src/px.rs::budget_is_provable` (unchanged code) reads `kernel_budget(1)`: the
  largest `bit` and `lt` a deploy may register fall by 150 rows each (from `2^22 −
  1 700` to `2^22 − 1 850`, and from `2^22 − 17 900` to `2^22 − 18 050`).
- The kernel ELF and program id, and the vault ELF, id and budget, are **unchanged**:
  the budgets are prover and verifier parameters only.

**6. Activation.** v3 genesis base rule set (no launched network has the old budgets).

**7. Compatibility.** Every PX proof that calls one or two functions has a new
statement shape (the kernel's heights); proofs made with the old budgets do not verify.
The padded shared tables change only where a power of two is crossed: with the vault,
`n_fn = 1`'s `bit` table goes from `pow2(1 700 + 260) = 2 048` to `pow2(1 850 + 260) =
4 096` rows; its `lt` table (`pow2(18 050 + 3 900)`) and every `n_fn = 2` vault
combination keep their heights. Fingerprint changes: the three new entries only (the
manifest diff and the digests are in the commit message).

**8. Reorg, wallet, mining and P2P implications.** None beyond the new shapes: the
wallet and the builders call `prove`, which now refuses an over-budget call before any
proving work with a precise error instead of a shape failure.

**9. Vectors.** The budget table itself (fingerprint entries `px.kernel.BUDGET.n_fn_*`).
The enumeration's counts: 4 accepted shapes with `n_fn = 0`, 162 with 1, 1 600 with 2
(input kinds user, dummy and two contracts; output kinds user and two contracts; each
function's contract; every approval and specification pattern).

**10. Regression tests** (`px/tests/kernel_budget.rs`, no proving):
- `every_honest_kernel_shape_fits_its_budget_with_headroom`: every accepted shape,
  checked by the native kernel and the pinned guest (exit 0), uses at most 95% of every
  table of its budget; it prints the widest shape per table;
- `the_shape_rules_match_the_kernel`: the enumeration's validity predicate equals the
  native kernel's verdict on every one-function shape (so no accepted shape is
  skipped);
- `an_execution_over_its_own_budget_is_refused_before_proving`: a vault LOCK with a
  budget one row short in `bit` is `OverBudget { execution: 1, table: "bit", .. }`;
  the kernel's `n_fn = 1` execution fits `kernel_budget(1)` and not `kernel_budget(0)`;
- `px/tests/unified.rs::budgets_leave_headroom`: now the vault entries and the vault
  flows' kernel executions (the kernel's shapes moved to the exhaustive test);
- `px/tests/consensus_fingerprint.rs`, `node/tests/deploy_configs.rs`: re-pinned.

**11. Suite results.** In the FX-RTW1C final report (one run for all RT-W1c fixes;
the commands are listed there).

**12. Open review points.**
- The enumeration covers record kinds, contracts and patterns, not values: values and
  positions are handled branch-free (px.md §4.4 and its constant-work tests), which the
  red team may re-check.
- Alternative (A) at the next kernel change; agent 22's widest-proof measurement should
  be re-run with the new `n_fn = 1` shape.

---

<a id="fingerprint-v3"></a>

## fingerprint-v3: rules and identity fingerprints, rule samples, rule revisions, and the testnet v3 network id

Revision: none (the fingerprint is not a validity rule)

Owner: W4-40. Decisions: "Agent 40" (40 lands all entries in one commit after every
rule decision; the digest is split into rules and identity; `--print-manifest`; the
rules fingerprint in `/info`; network ids: final `0x0001D673`, rehearsal ids reserved
at `0x0001D6E0`–`EF`, the known answer on a reserved test-only id), "Fingerprint pins
during the pre-freeze v3 window" (the new network id and the final values come with
fingerprint v3), "Agent 03" / "DAA FINAL" (a difficulty-rule identifier), "Agent 14"
(weight samples, a general "rule samples" section), "D8 / C4" (a rule-revision list),
"R2-C6" (the Poseidon2 instance in the fingerprint), "Agent 22" W5 / "Agent 23" W2
(the circuit digest), RTW1-6. Dossier 40 F40-6, F40-7, §3 P4. Internal engineering
work, not an audit.

**1. Problem.**
- The consensus fingerprint covered constants only (F40-6). Most v3 changes are rule
  code (D8 option B, CLSAG `D ≠ identity`, RT-14's domain layout, exact fee, R12-2, tree
  capacity, F-20-1, the ABI word, PX6): two builds that differ in one of them had equal
  fingerprints and would fork on the first transaction that uses the difference.
- The genesis and the network id were inside the one digest (F40-7): a release
  candidate and the final build must differ, so operators had no digest proving "the
  rules did not change between the candidate and the launch".
- Entries owed by earlier records were missing: `DIFFICULTY_RULE_ID`
  (daa-lwma75-warm §13), the circuit digest (Follow-up RTW1-3/6/8 §12 (i)),
  `ABI_VERSION` and `PREFIX_WORDS` (px-call-abi §12), the vault's REFUND entry, REFUND
  and TERMS domains and `OUT_WORDS` (guest-rebuild §12), weight samples (exact-v1-fee
  §12, r12-2 §7), rule revisions (§1 §7, §3 §12, exact-v1-fee §7, tree-capacity §7).
- The testnet still carried the retired v2 id `0x0001D672`, and the genesis known
  answer used `0x0001D673`, the id decided as the final testnet id.

**2. Demonstrated failure.** On base `419725e` (rendered with a scratch test in a
separate target directory, `C:/bszkeval/w4-fp3-scratch/manifest-before-*.txt`):
the manifest has no entry that any of the ten rule-code changes above moves (no
sample, no revision, no difficulty rule id), so it cannot tell a build with a
reverted rule from this one; the testnet's `chain.network_id` is `120434`
(`0x0001D672`); `chain.genesis` and `chain.genesis_id` are entries of the single
digest. The absence of the owed entries is visible in the same files.

**3. Prior art.** Zcash's consensus branch id names a rule set independently of the
chain (ZIP 200, ZIP 244); Bitcoin Core's `chainparams` asserts the genesis hash
separately from the rules; Ethereum's EIP-2124 fork id is a checksum of the genesis
hash and the fork block numbers passed, one value for the chain and its rule history
(dossier 40 §3 P4). Known-answer rule samples are the approach of test-vector files
(dossier 01, consensus/tests/golden.rs): the manifest carries a few of them so that a
code change moves the digest the node shows.

**4. Alternatives.** (a) Hash the rule source code (rejected: it changes with comments
and formatting and does not identify behaviour); (b) samples only, no revision list
(rejected: a sample exists only where a rule function can be called on cheap fixed
inputs; CLSAG, D8-B and the canonical-proof rules cannot be sampled without building
signatures or proofs); (c) a revision list only (rejected: hand-maintained, and
forgetting an entry would go unnoticed; samples backstop it); (d) keep one digest and
publish the genesis separately (rejected by the decision: operators need a rules digest
equal from the release candidate to the launch). Chosen: rules manifest (constants,
samples, revisions) and identity manifest, each hashed, and the consensus fingerprint
as the hash of both.

**5. Affected components.**
- `node/src/fingerprint.rs`: `rules_manifest`, `identity_manifest`,
  `rules_fingerprint`, `identity_fingerprint`, `consensus_fingerprint` (now
  `H64("node/consensus-fingerprint/v2", encode([rules, identity]))`), `fingerprints`
  (computed once per process), `REVISIONS`, the chain-side rule samples,
  `manifest_text` (`--print-manifest`), `network_by_name`, the `--version` text.
  `ChainParams` and `TxRules` stay destructured, now sorting every field into rules
  or identity.
- `px/src/fingerprint.rs`: `zkvm.CIRCUIT_DIGEST(_METHOD)`, `px_core.call.ABI_VERSION`,
  `PREFIX_WORDS`, the vault's REFUND and TERMS domains, REFUND entry and `OUT_WORDS`,
  and `px_samples` (Poseidon2, `Hk`, node, commitment, nullifier, kernel exit codes,
  function prefix, PX6 window).
- `zkvm/src/prove.rs`: `pub const CIRCUIT_DIGEST`, `CIRCUIT_DIGEST_METHOD` (values of
  the last `REVISIONS` line; `zkvm/tests/circuit_fingerprint.rs` asserts equality).
- `tx/src/types.rs`: `v1_part_weight` made `pub` (no logic change) for the R12-2
  weight sample.
- `node/src/main.rs`: `--print-manifest [NETWORK]`. `node/src/lib.rs` and
  `rpc/src/lib.rs`: `/info` gains `rules_fingerprint` and `identity_fingerprint`
  (optional fields; wallet test mocks set them to `None`).
- Network id: `consensus/src/params.rs` testnet `0x0001_D673` (the genesis time stays
  the v2 value as a placeholder until `T_g`; no beacon); `consensus/src/genesis.rs`
  `TEST_VECTOR_NETWORK_ID = 0xFFFF_FF00` and the known answer on it;
  `tools/genesis`: `TESTNET_V3_NETWORK_ID` replaces `V3_NETWORK_ID_PLACEHOLDER`, the
  known answer moves to the test-vector id, the registry test no longer requires the
  testnet's id to be registered before its genesis exists.
- Docs: testnet.md §1 and §2.1, consensus.md §1, testnet-v3-genesis.md §3,
  proof-system.md §3 (circuit identity), STATUS.md §1.

**The rule-revision list** (`REVISIONS`, one per reviewed validity or
proof-acceptance change, in record order): §1 D8-B, §2 CLSAG D, §3 RT-14, BS-ZK-3,
Canonical proof shape, daa-lwma75-warm, exact-v1-fee, r12-2, tree-capacity,
approval-conflict, px-call-abi, px6-validity-window, kernel-budget-shapes. **Not
revisions:** f05-header-check-order, rt1-unknown-upgrade-pow, the RTW1C-5 check order
and the RTW1-3 `verify` hardening (error classes or order only, verdicts unchanged);
expiry-guard (mempool policy); genesis-beacon (identity); guest-rebuild and vault-v3
(their effect is the program ids, which are listed); Soundness figures (the
`COLLISION_BITS` constant, listed). A test requires every entry to name an existing
record here and to be unique.

**Frozen wallet-side registry tags** (`seed/master/v1`, `wallet/hedge-key/v1`,
`px/wallet/hedge-key/v1`, `px/wallet/vault-secret/v1`, `px/wallet/vault-refund/v1`,
`px/wallet/vault-rcm/v1`): **not listed.** They derive wallet secrets; no node
computes them, and a chain accepts any value they could produce, so two nodes with
different tags agree on every block. They are pinned by the crypto crate's
`frozen_wallet_tags_are_pinned` instead. The hash domain prefix `crypto.DOMAIN_PREFIX`
(which every consensus tag uses) was and stays listed.

**Rule samples** (all on fixed inputs; network-independent except the fees, which
read the network's `TxRules`): `next_difficulty` at T = 120, N = 75 (steady, the
red-team golden case 999 824, the window-only 998 248, a genesis-only history),
`clock_step`, `difficulty_ancestors`; `median` and `after_median_time_past`;
`check_hash` at the 2^256 boundary; a block id and two Merkle roots; the genesis nonce
of Bitcoin block 0 on the test-vector id; the 40-byte signature domain; `max_weight`,
the PX/deploy v1-part weight (0 without inputs), `standard_fee` and `deploy_fee`;
plus the existing emission and seed-height samples and the PX samples above. A RandomX
hash is not sampled (a light-mode hash needs a 256 MiB cache, too costly for `/info`);
the RandomX constants stay copies, as before.

**6. Activation.** None: the fingerprint is not a validity rule. The network id is part
of the v3 genesis identity (no launched network has it).

**7. Compatibility.** Every fingerprint value changes on every network (the manifest
gained entries and the consensus digest's construction changed; its domain is now
`…/v2`). The testnet's genesis id changes with its network id (the pinned
`genesis_ids_are_pinned` and `genesis_ids_golden` values, recomputed independently in
Python from the spec). Every testnet signature and PX statement changes with it (RT-14
binds the genesis id), which affects no launched chain. Regtest and mainnet ids,
genesis blocks and every regtest vector are unchanged. `/info` gains two optional
fields; older clients ignore them and old nodes' JSON still decodes.

**Entry-level diff** (base `419725e` against this change, per network, from the
rendered manifests; every changed entry maps to a record):

| Entry | Change | Record |
|---|---|---|
| `chain.network_id`, `rules.network_id`, `chain.genesis_id` (testnet only) | `0x0001D672` → `0x0001D673`, and the genesis id that follows | this section (network id) |
| `schedule.epoch[0]` (4 values) | split into `schedule.epoch[0] (activation, header version, verifier id)` (rules) and `schedule.branch_ids` (identity); values unchanged | this section (split) |
| `chain.network`, `chain.genesis`, `rules.branch_id` | moved to the identity manifest, values unchanged | this section (split) |
| `chain.difficulty_rule`, `chain.DIFFICULTY_WARMUP` | added | daa-lwma75-warm §13 |
| `tx.SIG_DOMAIN_BYTES`, `rules.sample.sig_domain` | added | §3 RT-14 |
| `tx.SUPPORTED_VERIFIERS` | added (the verifier ids this build implements; the schedule's `verifier_id` was already listed) | this section |
| `zkvm.CIRCUIT_DIGEST`, `zkvm.CIRCUIT_DIGEST_METHOD` | added | Follow-up (RTW1-3/6/8) §12 (i) |
| `px_core.call.ABI_VERSION`, `px_core.call.PREFIX_WORDS`, `px.sample.function_prefix` | added | px-call-abi §12; px6-validity-window (the window words) |
| `px.vault.entry` → `px.vault.entry (LOCK, CLAIM, REFUND)`; `px.vault.REFUND_DOMAIN`, `TERMS_DOMAIN`, `OUT_WORDS` | REFUND entry and fields added | vault-v3, guest-rebuild §12 |
| `px.sample.poseidon2`, `Hk`, `node`, `commit`, `nullifier` | added | decisions "R2-C6" (the Poseidon2 instance); this section |
| `px.kernel.exit_codes` | added | approval-conflict (exit 18) |
| `px.sample.window.contains`, `is_well_formed` | added | px6-validity-window |
| `rules.sample.next_difficulty`, `clock_step`, `difficulty_ancestors` | added | daa-lwma75-warm §13 (golden case) |
| `rules.sample.median`, `after_median_time_past`, `check_hash`, `block_id`, `tx_root` | added (unchanged rules, sampled) | this section (dossier 40 §3 P4) |
| `rules.sample.genesis_nonce` | added | genesis-beacon; this section (test-vector id) |
| `rules.sample.max_weight`, `standard_fee`, `deploy_fee` | added | exact-v1-fee §12 |
| `rules.sample.px_v1_part_weight` | added | r12-2 §7, §12 |
| `rules.revision.len`, `rules.revision[0..12]` | added | each entry's own record (list above) |

Every other base entry is unchanged (testnet: 118 of 123; regtest and mainnet: 121 of
123, the two not unchanged being the split `schedule.epoch[0]` and the renamed vault
entry list). The digests, before and after, are in the commit message.

**8. Reorg, wallet, mining and P2P implications.** None from the fingerprint: it is
computed, printed and served, never checked against peers. Operators compare the
**rules** fingerprint of the release candidate with the final build's, and the
consensus fingerprint and genesis id at launch (testnet.md §2.1). The network id
change: wallets, miners and nodes read it from `ChainParams`, so they agree; testnet
stays disabled (`genesis_is_final` is false) until the launch commit.

**9. Vectors.**
- Testnet v3 genesis id (placeholder genesis, nonce 0) and the known answer on
  `0xFFFFFF00` (digest, nonce, genesis id): recomputed by an independent standard-library
  Python script written from the spec text (`hashlib.blake2b`), which also reproduces
  the pinned v2 testnet id and the old `0x0001D673` known answer; values in
  `consensus/src/params.rs`, `consensus/tests/golden.rs`, `consensus/src/genesis.rs`,
  `tools/genesis/tests/genesis.rs`.
- The three fingerprints of every network: recomputed by a second independent Python
  script from the `--print-manifest` output (it hashes the printed encodings with the
  printed domains, re-derives the consensus digest, and decodes each encoding back to
  the printed `name = value` lines: all equal); the PX-side pin was recomputed from the
  printed rules encoding the same way.
- The samples equal the golden values of their own suites
  (`samples_are_the_golden_values`: the DAA golden case, `max_weight(1, 2) = 1 723`,
  `(64, 16) = 57 439`, `(1, 0) = 841`, `(64, 2) = 52 123`, the known-answer nonce).

**10. Tests.**
- `node/src/fingerprint.rs`: `rules_fingerprint_excludes_identity` (no rules entry
  names or equals the network id, genesis or branch id; the identity manifest holds
  exactly them; testnet and mainnet rules differ only in `D0`),
  `consensus_combines_rules_and_identity`, `every_revision_is_unique_and_recorded`,
  `samples_are_the_golden_values`, `a_changed_sample_changes_the_rules_fingerprint`,
  `entry_names_are_unique_printable_ascii`, `manifest_text_recomputes` (the printed
  encodings hash to the printed digests), `rules_manifest_holds_the_px_entries_and_samples`,
  `version_text_names_every_network`, `stable_across_calls`, `networks_differ`.
- `node/tests/deploy_configs.rs::consensus_fingerprints_are_pinned`: consensus, rules
  and identity per network (re-pinned); `px/tests/consensus_fingerprint.rs` (re-pinned).
- `node/tests/info_identity.rs`: `/info` serves both new fields.
- `zkvm/tests/circuit_fingerprint.rs::the_air_digest_is_pinned_to_the_circuit_id`:
  `CIRCUIT_DIGEST` is the last `REVISIONS` line.
- `consensus` (`known_answer_bitcoin_block_0`, `genesis_ids_are_pinned`,
  `genesis_ids_golden`) and `tools/genesis` (`known_answer_bitcoin_block_0`,
  `used_network_ids_are_refused`): the new id and known answer.

**11. Suite results** (2026-09-29, release, `--locked`, this machine):
- `cargo fmt --all -- --check`, `cargo clippy --locked --workspace --all-targets -- -D
  warnings`: clean. `cargo deny check`, doc-lint, unicode scan: clean. Cargo.lock
  unchanged.
- Non-PX: every workspace crate except tx, px and zk, skipping the seven PX-proving
  tests: 1 000 passed, 0 failed, 4 ignored; tx (lib and every test file except
  `px_consensus`, `fuzz_decode`): 133 passed; px (lib and every test file except
  `proof`, `unified`): 61 passed; zk (lib and every test file except `proofs`): 18
  passed, 2 ignored (timing).
- PX-proving, one at a time, each started at 7 GB free or more, `--test-threads=1`:
  tx `px_consensus` 4, `fuzz_decode` 1; px `proof` 3, `unified` 12; zk `proofs` 16;
  chain `restart_rebuilds_the_px_state_exactly` 1; wallet e2e PX 4; p2p PX 2. All
  passed, 0 failed.
- Not run: a code mutant of a sampled rule (the LWMA `(n + 1) → n` check of dossier
  40); the unit test substitutes sample values instead.

**12. Open review points.**
- **F40-1 is not closed.** Once the testnet genesis exists, step 7 of
  testnet-v3-genesis.md registers `0x0001D673`; the tool's `build`/`verify` then refuse
  it, so "operators re-run `verify`" fails after the launch. The registry semantics
  (verify accepts a built-in network's own id with its announced inputs) and the
  enforced rehearsal range are dossier 40 item 2, not this change.
- The revision list is hand-maintained; a rule change that forgets its entry and moves
  no sample is caught only in review. The red team (50) should check the list against
  the records, and the consensus-change template should gain the checklist item.
- Samples cover functions callable on cheap fixed inputs. CLSAG, D8-B, the
  canonical-proof rules, tree capacity and PX6's block-path placement have no sample
  (revision only).
- The RandomX configuration stays a copy (no public accessor in `blacksilk-randomx`,
  01 F-09); the circuit digest is a pinned copy tied by a test.
- An independent recompute script in the repository (dossier 40 item 5,
  `verify_manifest.py`) is not part of this change; the scratch scripts used here are
  not committed.
- The start-up log still prints only the consensus fingerprint.

**13. Identity impact.** Every network's fingerprints change; the testnet's network id
and genesis id change (pre-launch, intended). Regtest and mainnet ids unchanged. At the
launch, the beacon and `T_g` change only the testnet's identity and consensus
fingerprints; its rules fingerprint must stay equal to the release candidate's.

**14. Documentation.** testnet.md §1, §2.1; consensus.md §1; testnet-v3-genesis.md §3;
proof-system.md §3; STATUS.md §1; this record. Values are referenced, not copied.

**15. Review status.** Implemented and tested by W4-40; red-team review pending.

### Follow-up (RT-FP3)

Owner: FX-RTFP3. Decisions: "RT-FP3 (fingerprint v3 coverage)" (verdict ACCEPT WITH
CHANGES: the construction is sound, the coverage is not), "Agent 40", "Fingerprint pins
during the pre-freeze v3 window" (re-pin procedure), "Engineering process" (Tier 3).
Internal engineering work, not an audit. Not a rule change: no verdict of any node
changes, so no `REVISIONS` entry and no `Revision:` id.

**1. Problem.** The red team (RT-FP3) applied seven consensus mutations, each alone:
the LWMA lower clamp `1 → 2`, the future time limit `<=` → `<`, the `tx/hash` tag, the
empty leaf of the PX tree, RandomX `PROGRAM_ITERATIONS 2048 → 1024`, the Bulletproofs+
weight clawback `4/5 → 1/2`, and the key-image order rule T4 disabled. Every mutant
compiled, behaved differently (a scratch test showed each effect), and left every
fingerprint identical (`C:/bszkeval/rt-fp3-demo.patch`, `rt-fp3-*-manifest.txt`).
Causes: the RandomX entries were copies; no hash tag was listed; the samples missed
the FTL boundary, the clamp, the tree's empty roots, weights of real transactions and
every verdict; the revision list was not tied to the records; the gate's path list
missed crypto, RandomX, the transaction types and the chain manager; a dirty tree
reported a clean commit.

**2. Demonstrated failure.** The red team's demonstration on `3a14978` (above). The
acceptance test of this follow-up re-applies the same seven mutations
(`tools/fingerprint-mutations.sh`, results in §11).

**3. Prior art.** As the parent record (known-answer samples, Zcash branch ids,
EIP-2124). The verdict samples follow the golden-corpus idea of dossier 11 item I1
(one exact-error vector per error class) on a single pinned fixture. The pinned-copy
pattern (`zkvm.CIRCUIT_DIGEST`, a value the crate's test requires the code to compute)
is reused for the RandomX known answer.

**4. Alternatives.** (a) Compute a RandomX hash at start-up (rejected: a 256 MiB cache
in `--version` and `/info`); (b) build the fixture transaction at start-up (rejected:
proving and signing in the fingerprint; the fixture is pinned data instead, with its
generator in the repository); (c) verdict samples as a pinned test digest only (not
needed: the full manifest computes in about 55 ms cold in release, measured below, so
the verdicts are in the manifest itself); (d) a second cut-over for the gate's new
paths instead of waivers (rejected by the assignment: waivers with reasons).

**5. Affected components** (items of the decision):
- RTFP3-2: `randomx/src/lib.rs` `config_entries()` (every `config.rs` constant, read
  from the crate) and `FINGERPRINT_KAT` (vector 1a), asserted by `tests::hash_1a`;
  the node lists both instead of copies.
- RTFP3-1: `crypto/src/hash.rs` `tags::CONSENSUS` (the 25 tags a node hashes with to
  reach a verdict; wallet, P2P, prover and Wasm tags excluded, tested);
  `px/src/fingerprint.rs` `crypto_entries()`: the tags, generator `H`, the first and
  last Bulletproofs+ generators, `commit(5, 3)` and the key image of the secret 7;
  the fixture transfer's id and signature message, and the fixture coinbase's id.
- RTFP3-3/4: `node/src/fingerprint.rs` `transaction_samples()` on the pinned fixture
  `node/src/fingerprint_fixture.txt` (a 2-input, 3-output transfer signed under
  `fixture_rules()`: the test-vector network id, the v3 branch id, a fixed genesis id;
  its coinbase; its 32 ring members), generated by `node/tests/fingerprint_fixture.rs`:
  `Transaction::weight` of the transfer (the clawback applies), the coinbase and a PX
  transaction with and without a v1 part; and `validate_transfer` verdicts of the
  transfer and of 20 variants, one per error class a transfer can reach
  (`TooLarge` and `WeightOverflow` cannot be reached by a transfer within the count
  limits).
- RTFP3-5/6/7: `within_future_limit` at `now + FTL − 1`, `now + FTL`, `now + FTL + 1`;
  `next_difficulty` clamped to 1; the empty leaf and roots at heights 1 and 32, and the
  root of a three-leaf tree by the frontier, the full tree and a path.
- RTFP3-11: `zk/src/config.rs` `transcript_sample()` (the verifier's challenger on a
  fixed statement and three words: one extension challenge, one base element, 20 bits),
  listed as `px.sample.zk.transcript`.
- RTFP3-12: the kernel exit codes from an exhaustive match with a compile-time check of
  the list against the variant order; `Epoch` destructured in the manifest.
- RTFP3-8: a `Revision:` line in every record section (this file); the test
  `revision_lines_are_the_revision_list` (every section has exactly one; the ids, in
  order, are `REVISIONS`; each `record` key matches exactly one section: no prefix
  match); the record template checklist (top of this file); the consensus gate refuses
  a trailer whose cited section does not exist, and, once the record has `Revision:`
  lines, a section without one (`consensus-gate.sh --selftest`).
- RTFP3-10: the gate's paths gain `crypto/`, `randomx/`, `third_party/`,
  `chain/src/manager/`, `tx/src/{types,codec,state}.rs`, `px/src/{prove,state,tree}.rs`
  and the fixture; the 18 earlier commits that touched them without a trailer are in
  `.github/consensus-gate-waivers.txt`, each with its reason.
- RTFP3-9/15: `node/build.rs` and `build_id.rs` mark a dirty tree (`<commit>-dirty`) and
  refuse a dirty release build unless `BLACKSILK_ALLOW_DIRTY=1`; testnet.md §2.1 now
  names the binary hash as the check that a binary is the announced code and states
  what the fingerprints do not show.
- RTFP3-13/14: `tools/genesis` (reserved ids, `--final`, `--rehearsal`, `verify` of a
  registered built-in genesis); testnet-v3-genesis.md §3, §6, §8.
- RTFP3-16: the floor `n²T/20` of the LWMA is unreachable (proof and the mutant table
  in [mutation-exemptions.md](mutation-exemptions.md), E1); the rule id is unchanged.
- The gate path list, the fixture and the record changes; docs testnet.md §2.1,
  testnet-v3-genesis.md, STATUS.md §1 and §8.

**6. Activation.** None: the fingerprint is not a validity rule.

**7. Compatibility.** The rules fingerprint of every network changes (80 entries
added), and with it the consensus fingerprint; the identity fingerprints are unchanged
(no network id or genesis changed). Re-pinned: `node/tests/deploy_configs.rs` (all
three networks) and `px/tests/consensus_fingerprint.rs`.

**Entry-level diff** (base `680f9f9`, rendered with `--print-manifest` from a build in a
separate target directory, against this change; the same on every network): 173 base
entries, all unchanged in name and value; 80 added, none removed or changed.

| Added entries | Record |
|---|---|
| `randomx.SUPERSCALAR_MAX_SIZE`, `DATASET_ITEM_SIZE`, `DATASET_ITEM_COUNT`, `DATASET_EXTRA_ITEMS`, `CACHE_SIZE`, `CACHE_LINE_SIZE`, `CACHE_LINE_ALIGN_MASK`, `SCRATCHPAD_L1_L2_L3_L3_64_MASKS`, `CONDITION_MASK`, `STORE_L3_CONDITION`, `REGISTER_NEEDS_DISPLACEMENT` (the listed RandomX entries keep their names and values, now read from the crate) | this follow-up, RTFP3-2 |
| `randomx.KAT.key`, `KAT.input`, `KAT.hash` | RTFP3-2 |
| `crypto.hash.tags.CONSENSUS.len`, `crypto.hash.tags.CONSENSUS[0..24]` | RTFP3-1 |
| `crypto.BP_MAX_GENERATORS`, `crypto.sample.generator_H`, `bp_G[0]`, `bp_H[0]`, `bp_G[1023]`, `bp_H[1023]`, `commit(5, 3)`, `key_image(7, 7G)` | RTFP3-1 |
| `px.sample.tree.empty[0]`, `empty[1]`, `empty[32]`, `px.sample.tree.root(…) of 3 leaves` | RTFP3-7 |
| `px.sample.zk.transcript([7; 32], [1, 2, 3])` | RTFP3-11 |
| `rules.sample.next_difficulty([0, 1000], [1, 2], T 120, N 75, D0 1)` | RTFP3-6 |
| `rules.sample.within_future_limit (1359, 1360, 1361; now 1000, FTL 360)` | RTFP3-5 |
| `rules.sample.weight (fixture …)` | RTFP3-3 |
| `rules.sample.tx_hash (fixture transfer)`, `signature_message (…)`, `tx_hash (fixture coinbase)` | RTFP3-1 |
| `rules.sample.verdict (…)`, 21 entries | RTFP3-4 |

The digests before and after, per network, are in the commit message; the after
values were recomputed from the printed encodings by an independent standard-library
Python script (FX-RTFP3 scratch), which also decoded each encoding (246 rules entries):
equal.

**8. Reorg, wallet, mining and P2P implications.** None: the fingerprint is computed,
printed and served, never checked against peers. Development builds: a release build
of uncommitted work now needs `BLACKSILK_ALLOW_DIRTY=1` (the crates that build the node:
node, wallet, supply-audit, labnet).

**9. Vectors.** The fixture (pinned data, with its deterministic generator); the
RandomX known answer (the reference's vector 1a); the verdict classes asserted by
`samples_are_the_golden_values`.

**10. Tests.** node: `revision_lines_are_the_revision_list`, the extended
`samples_are_the_golden_values`, `fingerprint_cost` (ignored, timing),
`tests/fingerprint_fixture.rs` (`the_fixture_is_a_valid_transfer`, and the ignored
generator), `tests/build_id.rs` (`sha1_and_blob_ids`, `index_parsing`,
`dirty_paths_compares_like_git_status`, `object_format`,
`this_repository_index_parses`); randomx: `config_entries_are_the_reference_values`
and `hash_1a` on `FINGERPRINT_KAT`; crypto: `consensus_tags_are_listed_tags`;
tools/genesis: `reserved_ids_need_their_purpose`,
`verify_accepts_a_registered_built_in_genesis`, and the updated registry tests; the
gate: `consensus-gate.sh --selftest`; the acceptance script
`tools/fingerprint-mutations.sh`.

**Start-up cost** (`fingerprint_cost`, release, this machine, while another agent ran
a full-mode miner): every network's fingerprints from a cold process 54 to 58 ms
(the transaction samples about 30 ms of it); warm 3 ms. Well under the 1 s budget, so
the verdicts are computed at run time rather than pinned by a test.

**11. Suite results.** See the next paragraph (filled in by the commit that records
them).

**12. Open review points.**
- Coverage stays sample-based. Rules a transfer fixture cannot reach have no verdict
  sample: PX and deploy rules (a PX verdict needs a proof), block-level rules (B1 to B8,
  coinbase rules), header and chain rules beyond the samples, CLSAG and Bulletproofs+
  internals that keep the fixture's verdicts, and the canonical-proof rules. They are
  covered by revisions and the build commit only. A PX verdict sample on a pinned
  proof (verification costs about a second) could be a pinned test digest.
- The dirty mark misses untracked files and staged-only changes, and a SHA-256
  repository is compared by size and time only. Reproducible node builds, the check
  the operator procedure now names, are not demonstrated.
- A release build of uncommitted work fails without `BLACKSILK_ALLOW_DIRTY=1`; every
  agent running release tests on a dirty worktree must set it.
- The gate's `Revision:` check applies once the record has `Revision:` lines, that is
  from this change on; older commits are checked for existing sections only.
- The equivalent-mutant exemption E1 depends on the networks' target times (regtest
  T = 10 observes `% 20`, which is therefore not exempt).
