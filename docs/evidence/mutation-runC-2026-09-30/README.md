# Mutation run C: transaction rules, fork choice, crypto, blocks (Wave 4 freeze gate)

Internal engineering evidence, not an audit. A mutation census shows which code
changes the tests notice; it does not show that the code is correct or secure.

The gate (decisions "Agent 42" and "W4-MUT and RT-MUT", run C): zero unexplained
missed mutants per completed file. Every survivor is killed by a new test or
explained in [mutation-exemptions.md](../../reviews/mutation-exemptions.md) (E8–E12,
E14, E15, E23–E28; E13 and E16 were withdrawn when their mutants were killed).
Red team RT-MUTC reviewed the first version (§ After RT-MUTC).
Run C's scope, in priority order: tx/src/validate.rs, tx/src/px.rs,
chain/src/manager/fork_choice.rs, tx/src/params.rs, crypto/, chain/src/block.rs and
chain/src/emission.rs. What this run completed and what remains is in § Scope status.

## Result in brief

| File | Mutants | Caught (run) | Missed (run) | Unviable | After the new tests |
|---|---|---|---|---|---|
| tx/src/validate.rs | 138 | 107 | 19 | 12 | 11 killed by non-proving tests, 4 by the proving test `px_consensus` (2 of them by its new assertions), 2 equivalent (E8); 2 diagnostic only (E9) |
| tx/src/px.rs | 174 | 131 | 28 | 15 | 26 killed (3 of them first timed out on an unbounded test loop, § Timeouts), 2 equivalent (E10) |
| tx/src/params.rs | 93 | 72 | 4 | 17 | 4 killed |
| chain/src/manager/fork_choice.rs | 87 | 53 (+8 timeouts) | 26 | 0 | 10 killed by non-proving tests, 1 by a new proving test, 3 equivalent (E11), 12 log only (E12); the 8 timeouts: 3 fail assertions, 5 are genuine hangs (§ Timeouts) |
| crypto/src/clsag.rs | 97 | 51 (+2 timeouts) | 0 | 44 | nothing to resolve; the 2 timeouts fail assertions |
| crypto/src/bulletproofs_plus.rs | 314 | 218 (+10 timeouts) | 6 | 80 | 4 first exempted as unreachable (E13), now gone: the checks moved into `any_zero`, whose 3 mutants a unit test kills (§ After RT-MUTC); 2 equivalent (E14); the 10 timeouts: 9 fail assertions, 1 genuine hang |
| crypto/ (the 12 other files) | 273 | 171 (+7 timeouts) | 20 | 75 | 14 killed by new unit tests (the `Hash for Point` mutant by RT-MUTC's test, first exempted as E16), 6 unobservable in safe Rust (E15); the 7 timeouts: 6 fail assertions, 1 genuine hang |
| chain/src/block.rs | 18 | 11 | 5 | 2 | 5 killed |
| chain/src/emission.rs | 19 | 19 | 0 | 0 | nothing to resolve |

- **No survivor revealed a bug in a consensus rule.** Every rule the survivors
  pointed at is implemented as specified; only its test was missing (or, for 34
  mutants, no test can observe the change: § Result in brief, last items).
- **The rules that had no test at their boundary, now tested** (tx/tests/
  mutation_regressions.rs unless noted):
  - T3's upper bounds (64 inputs; PX: 64 inputs, 16 hidden outputs, outputs only
    with inputs; 2 functions);
  - B6's PX byte budget (8 MiB) and the deploy budget (1 MiB,
    tx/tests/deploy_rules.rs), both inclusive;
  - T1 for PX transactions and deploys at their size caps;
  - PX4 on the mempool path (the pool must cover the withdrawal, the transaction's
    own deposit counted) and in blocks (the pool evolves in block order);
  - the PX v1-side balance (`check_px_balance`): **no non-proving test checked that
    an unbalanced PX transaction is refused**, and no test at all had a negative
    `v` (the `-Scalar` branch);
  - a deploy of a registered contract id in a block (`DuplicateContract`, through a
    chain view that registers the id alone: on a consistent chain C2 fires first);
  - the PX encoding round trip part by part, and which parts `h_tx`, the CLSAG
    message and the transaction id cover;
  - the PX output context (`H32("input-context/px", nullifiers ‖ key images)`);
  - a deploy's CLSAGs and id cover its payload;
  - a deploy's output words (at most 256) and its size cap;
  - the PX size and fee constants (4 MiB + 256 KiB, 8 912 896).
- **Two PX5 order rules needed the proving test** (tx/tests/px_consensus.rs, new
  assertions in `a_private_contract_is_deployed_and_used_through_consensus`, with
  no extra proof except one bridge-in):
  - the shape step: a well-formed proof of another statement shape is the stateless
    `PxProof` before any CLSAG (`check_px_proof_shape`);
  - in a block, each proof is shape-checked against its own statement: the claim
    (one function) is mined with a kernel-only bridge-in (the `px_slot` counter).
- **Fork choice (chain/src/manager/fork_choice.rs), now tested**
  (chain/tests/fork_choice.rs, chain/tests/activation.rs):
  - the low-work body policy's candidate rules: a header-best deep branch's
    bodies are kept; an equal-work header tip, and a side leaf of equal or one
    block less work, are no candidates;
  - a candidate cut back below an invalidated tip stays a candidate (its parent
    becomes a leaf again);
  - the transactions of the last block before an activation return under the new
    rules (the rules of a disconnected block's own height);
  - **the proof cache vouches only under the rules the pool verified under**: a
    pooled PX proof (no v1 inputs) bound to the new branch id, in a side-branch
    block below the activation, is verified and refused. Under the mutant
    (`same_rules` negated) the side branch was **accepted**. A new proving test,
    `a_pooled_px_proof_vouches_for_nothing_under_other_rules`, `#[ignore]`d (two
    PX proofs; § Proving tests).
  - `set_step_delay_for_tests` (a test hook) is checked by `actor_order`.
- **The coinbase reward check** (`block_reward(h, generated)` at 362 and
  `generated + reward` at 388) was already fully caught: `+` → `*` at 388:59 fails
  the fork_choice tests, `+` → `-` an overflow check, and under release arithmetic
  `emission_is_enforced_exactly` (§ Release arithmetic).
- **crypto/: CLSAG had no survivor.** Bulletproofs+'s 6 survivors are its
  zero-challenge guards (unreachable without a hash preimage; now a tested helper,
  § After RT-MUTC) and an unused tail of
  the `y` powers. In the other files, new unit tests: an anchor's `Debug` never
  shows its bytes; points order by their encoding through every comparison
  operator (the T4 and T6 sort rules depend on it; `partial_cmp` had no test); the
  membership verifier refuses a signature with a spare response and one made over
  a ring with an identity member (both valid by the ring equations);
  `MemberSig::encoded_len`; `SubaddressTable::is_empty`.
- **chain/src/block.rs:** the block size bound `MAX_BLOCK_BYTES` was tested only
  symbolically (now pinned to 9 454 144 bytes, docs/px.md §11.5), and
  `Block::weight` had no test (it has no caller in the workspace). emission.rs had
  no survivor.
- **Equivalent, diagnostic or unobservable (exempt):** 29 cargo-mutants mutants
  (E8 2, E9 2, E10 2, E11 3, E12 12, E14 2, E15 6) and 9 boundary-pass mutants (E12
  1, E23–E28 8; § Boundary pass). E15 (6 zeroize-on-drop mutants) is a limit of the
  oracle, not an equivalence.
- **Boundary pass** (cargo-mutants never mutates `>=` into `>` or `<=` into `<`): 39
  mutants over run C's scope and runs A and B's (consensus, px-core); 3 survivors
  killed by new tests, 9 equivalent (§ Boundary pass).

## Setup

- **Tool:** cargo-mutants 27.1.0, as runs A and B (docs/evidence/mutation-2026-09-29/).
- **Toolchain:** rustc 1.98.1 (x86_64-pc-windows-msvc).
- **Code:** branch `w4-mutc` on base `6a2b3b7` (`rebuild/core`, with runs A and B
  merged). No non-test source line was changed.
  - `runV` and `runP` ran on the base, except that `runP` copied the tree after this
    work's first test edits: tx/tests/deploy_rules.rs's new
    `a_block_of_exactly_the_deploy_budget_is_valid` was in its test set (it kills no
    px.rs or params.rs mutant: it concerns the block rule at validate.rs 1214).
    tx/tests/mutation_regressions.rs was not in `runV`'s or `runP`'s test set.
  - `runF` (fork_choice.rs) ran on the tree of commit `ee16b9f` (the tx tests;
    uncommitted when it started), without the new chain tests.
  - `runK` and `runK2` (crypto/) ran on the tree of `3187986`, before the new
    crypto tests; `runB` (block.rs, emission.rs) on the tree of `565d440`, before
    the new block_rules tests.
  - The re-runs ran on the final test code.
- **Profile:** `[profile.mutants]` of the root Cargo.toml (overflow checks and debug
  assertions on; see § Release arithmetic).
- **Machine:** 4 cores / 8 threads, 16 GB, shared with other agents' builds.
- **Environment:** `CARGO_BUILD_JOBS=2`, `CARGO_INCREMENTAL=0`, `CARGO_TARGET_DIR`
  unset for cargo-mutants (it builds in its own copy of the tree).

## Oracles

- **Non-proving tx tests** (`txtests.args`): the lib unit tests and 17 of the 19
  integration test targets: adversarial, block_pipeline, chain_integration,
  deploy_rules, exact_fee, malleability, max_weight_encoder, max_weight_vectors,
  output_key_uniqueness, privacy, px_v1_weight, px_window,
  revalidate_after_extension, transfers, tree_capacity, upgrade, validation_order.
  The re-runs add mutation_regressions (`txtests-rerun.args`). Baseline: 62 s of
  tests; malleability (42 s) and max_weight_vectors (39 s) dominate.
- **Excluded from the census:** `px_consensus` and `fuzz_decode`, which build PX
  proofs (4–6 GB and minutes each, impl-brief). The mutants only a proving test can
  judge were run separately against `px_consensus` alone, one at a time
  (`provingC`), with at least 7 GB free.
- **Not used for the tx files:** the chain, node, wallet and p2p tests, which also
  call these rules.
- **Crypto tests for crypto/:** the crate's lib unit tests and its 4 integration
  test targets (bpp_vectors, clsag_vectors, malleability, stealth_vectors). Baseline:
  29 s build + 4 s of tests; timeout 300 s. The mutated crate builds at opt-level 3
  (`[profile.mutants.package.blacksilk-crypto]`). The tx and chain tests, which
  also exercise these primitives, were not used.
- **Chain tests for block.rs and emission.rs** (`chaintestsB.args`): the lib unit
  tests and golden, block_malleability, block_rules, manager, fork_choice,
  store_format, storage_recovery (`--skip restart_rebuilds_the_px_state_exactly`).
- **Chain tests for fork_choice.rs** (`chaintests.args`): the lib unit tests and
  activation, actor_equivalence, block_rules, fork_choice, golden, manager,
  mempool_conflicts, mempool_expiry, operator_invalidation, reference_model,
  revalidation, rt_w3_regressions, storage_recovery, store_format, with
  `--skip restart_rebuilds_the_px_state_exactly` (PX-proving). Baseline: 97 s build
  + 434 s of tests (reference_model 217 s, manager 100 s, fork_choice 45 s, lib 35
  s); the timeout was set to 1 739 s. Left out: actor_order (timing-sensitive
  liveness; used for the one test-hook mutant, `hookF`), actor_bench (ignored),
  fuzz_block, fuzz_store and mempool_stateful (property volume), seed_switch (real
  RandomX), block_malleability (the block codec, not fork choice).

## Commands

Run from the repository root. `$T` is the content of `txtests.args` (the re-runs:
`txtests-rerun.args`).

```text
# runV: validate.rs (baseline 171 s build + 62 s test; timeout set to 314 s)
cargo mutants -p blacksilk-tx -f tx/src/validate.rs --profile mutants --jobs 2 \
  --timeout-multiplier 5 --minimum-test-timeout 300 --build-timeout 2400 \
  --cap-lints true -o <out> $T
# runP: px.rs and params.rs (same tree and test set as runV's baseline)
cargo mutants -p blacksilk-tx -f tx/src/px.rs -f tx/src/params.rs --profile mutants \
  --jobs 2 --timeout 314 --baseline skip --build-timeout 2400 --cap-lints true -o <out> $T
# rerunC: the 51 survivors of runV and runP, final tests (baseline run, passed)
cargo mutants -p blacksilk-tx -f tx/src/validate.rs -f tx/src/px.rs -f tx/src/params.rs \
  --profile mutants --jobs 2 --timeout 314 --build-timeout 2400 --cap-lints true \
  -o <out> <rerunC.args> $T
# timeoutC: rerunC's 3 timeouts, after the bounded test loop, one at a time
cargo mutants -p blacksilk-tx -f tx/src/px.rs --profile mutants --jobs 1 --timeout 314 \
  --baseline skip --build-timeout 2400 --cap-lints true -o <out> <timeoutC.args> $T
# provingC: the 4 survivors only a proving test can judge, px_consensus alone
cargo mutants -p blacksilk-tx -f tx/src/validate.rs --profile mutants --jobs 1 \
  --timeout-multiplier 3 --minimum-test-timeout 900 --build-timeout 2400 \
  --cap-lints true -o <out> <provingC.args> -C=--test=px_consensus -- -- --test-threads=1
# ovfC: the tx mutants whose kill could rest on an overflow check (§ Release arithmetic)
RUSTFLAGS="-C overflow-checks=off -C debug-assertions=off" cargo mutants -p blacksilk-tx \
  -f tx/src/validate.rs -f tx/src/px.rs --profile mutants --jobs 1 --timeout 314 \
  --build-timeout 3600 --cap-lints true -o <out> <ovfC.args> $T

# $C is the content of chaintests.args; $S is
# `-- -- --skip restart_rebuilds_the_px_state_exactly`.
# runF: fork_choice.rs (baseline 97 s build + 434 s test; timeout set to 1 739 s)
cargo mutants -p blacksilk-chain -f chain/src/manager/fork_choice.rs --profile mutants \
  --jobs 2 --timeout-multiplier 4 --minimum-test-timeout 300 --build-timeout 2400 \
  --cap-lints true -o <out> $C $S
# rerunF: runF's survivors but the test hook, with the new chain tests (baseline run)
cargo mutants -p blacksilk-chain -f chain/src/manager/fork_choice.rs --profile mutants \
  --jobs 1 --timeout 1739 --build-timeout 2400 --cap-lints true -o <out> <rerunF.args> $C $S
# hookF: the test hook, with actor_order (baseline run)
cargo mutants -p blacksilk-chain -f chain/src/manager/fork_choice.rs --profile mutants \
  --jobs 1 --timeout-multiplier 4 --minimum-test-timeout 600 --build-timeout 3600 \
  --cap-lints true -o <out> <hookF.args> -C=--test=actor_order
# timeoutF: 5 of runF's timeouts, with the tests that hung skipped (§ Timeouts)
cargo mutants -p blacksilk-chain -f chain/src/manager/fork_choice.rs --profile mutants \
  --jobs 1 --baseline skip --timeout 900 --build-timeout 3600 --cap-lints true \
  -o <out> <timeoutF.args> $C -- -- --skip restart_rebuilds_the_px_state_exactly \
  --skip a_no_op_activation_flushes_the_pool_and_switches_the_branch \
  --skip a_marked_header_and_its_descendants_are_refused_at_header_time \
  --skip descendants_arriving_later_are_refused \
  --skip invalidating_a_buried_block_reorgs_to_the_best_other_branch \
  --skip invalidating_the_tip_reorgs_to_its_parent_and_survives_restarts \
  --skip a_bounded_reorganization_never_stops_on_a_lighter_tip
# provingF: 376:60, with the new ignored proving test alone (manual baseline below)
cargo mutants -p blacksilk-chain -f chain/src/manager/fork_choice.rs --profile mutants \
  --jobs 1 --baseline skip --timeout 5400 --build-timeout 3600 --cap-lints true \
  -o <out> <provingF.args> -C=--test=activation -- -- --ignored --test-threads=1
# ovfF: the fork_choice mutants whose kill could rest on an overflow check
RUSTFLAGS="-C overflow-checks=off -C debug-assertions=off" cargo mutants \
  -p blacksilk-chain -f chain/src/manager/fork_choice.rs --profile mutants --jobs 2 \
  --timeout 1739 --build-timeout 3600 --cap-lints true -o <out> <ovfF.args> $C $S
```

```text
# runK: clsag.rs and bulletproofs_plus.rs (baseline 29 s build + 4 s test)
cargo mutants -p blacksilk-crypto -f crypto/src/clsag.rs -f crypto/src/bulletproofs_plus.rs \
  --profile mutants --jobs 2 --timeout-multiplier 5 --minimum-test-timeout 300 \
  --build-timeout 2400 --cap-lints true -o <out>
# runK2: the other 12 files (same tree and tests as runK's baseline)
cargo mutants -p blacksilk-crypto -f crypto/src/{schnorr,stealth,commitment,membership,keys,
  hash,claims,janus,point,nonce,generators,wordlist}.rs --profile mutants --jobs 2 \
  --timeout 300 --baseline skip --build-timeout 2400 --cap-lints true -o <out>
# ovfK: the 8 crypto mutants whose kill could rest on an overflow check
RUSTFLAGS="-C overflow-checks=off -C debug-assertions=off" cargo mutants \
  -p blacksilk-crypto -f crypto/src/clsag.rs -f crypto/src/bulletproofs_plus.rs \
  --profile mutants --jobs 2 --timeout 300 --build-timeout 3600 --cap-lints true \
  -o <out> <ovfK.args>
# runB: block.rs and emission.rs ($B: chaintestsB.args)
cargo mutants -p blacksilk-chain -f chain/src/block.rs -f chain/src/emission.rs \
  --profile mutants --jobs 2 --timeout-multiplier 4 --minimum-test-timeout 300 \
  --build-timeout 2400 --cap-lints true -o <out> $B $S
# rerunB: runB's 5 survivors, with the new block_rules tests
cargo mutants -p blacksilk-chain -f chain/src/block.rs --profile mutants --jobs 2 \
  --timeout 1739 --build-timeout 2400 --cap-lints true -o <out> <rerunB.args> $B $S
# timeoutK, timeoutK2: the 19 crypto timeouts, with the tests that hung skipped
# (timeoutK.skips; timeoutK2: whole test modules), 120 s (§ Timeouts)
# rerunK: the 26 survivors, with the new unit tests (baseline run)
cargo mutants -p blacksilk-crypto <the 14 files> --profile mutants --jobs 2 --timeout 300 \
  --build-timeout 2400 --cap-lints true -o <out> <rerunK.args>
```

`provingF`'s baseline was run by hand on the same tree and profile, with at least 7 GB
free: `cargo test --locked --profile mutants -p blacksilk-chain --test activation --
--ignored --test-threads=1`, 1 passed in 1 854 s (in parallel with `rerunF`).

The `--re` filter files follow run A's convention (each mutant's name, anchored,
every character but a letter, a digit or a space as a one-character class, and
`[ ] \ ^ -` escaped with a backslash). `cargo mutants --list` with each filter file
returns exactly its mutants (checked for `rerunC.args`: 51 of 51).

**Times (UTC, 2026-09-30):**

| Run | Start | End | Mutants |
|---|---|---|---|
| runV | 03:01 | 05:49 | 138 |
| runP | 05:49 | 10:10 | 267 |
| rerunC | 10:12 | 11:34 | 51 |
| timeoutC | 11:34 | 11:40 | 3 |
| provingC | 11:40 | 12:37 | 4 (baseline 98 s build + 718 s test) |
| runF | 12:38 | 17:28 | 87 |
| ovfC | 17:29 | 17:37 | 4 |
| rerunF | 17:30 | 20:49 | 25 |
| provingF | 18:52 | 19:25 | 1 |
| hookF | 19:32 | 19:35 | 1 |
| timeoutF | 19:35 | 20:53 | 5 |
| ovfF | 20:54 | 21:34 | 8 |
| runK | 21:36 | 22:49 | 411 |
| ovfK | 22:51 | 22:52 | 8 |
| runK2 | 22:53 | 23:43 | 273 |
| timeoutK (2026-10-01) | 23:45 | 00:05 | 19 |
| timeoutK2 | 00:06 | 00:24 | 16 |
| rerunK | 00:24 | 00:30 | 26 |
| runB | 00:30 | 00:58 | 37 |
| rerunB | 01:02 | 01:10 | 5 |

**Outputs:** each subdirectory holds the tool's `caught.txt`, `missed.txt`,
`timeout.txt` and `unviable.txt` for that run.

## Survivors and their resolution

### tx/src/validate.rs (runV: 19 missed)

| Mutant | Resolution |
|---|---|
| 398:20 `n > MAX_INPUTS` → `==`, `>=` (T3) | killed: `t3_count_bounds_are_inclusive` |
| 445:13 `size > MAX_TX_SIZE` → `==`, `>=` (T1) | equivalent: E8 (a shaped transfer never exceeds 57 439 bytes) |
| 661:5 `check_px_proof` → `Ok(())` | killed: `check_px_proof_refuses_proof_bytes_that_do_not_decode` (the function had no caller and no test) |
| 677:5 `px_calls` → `Ok(vec![])` | killed by the proving test: `px_consensus` (the LOCK block) |
| 701:5 `check_px_proof_shape` → `Ok(())` | killed by the proving test: `px_consensus`, new assertion (a one-function proof in a kernel-only statement is `PxProof` before the CLSAG) |
| 720:5 `check_px_proof_decoded` → `Ok(())` | killed by the proving test: `px_consensus` (a tampered ciphertext) |
| 747:5 `hex_id` → `String::new()`, `"xyzzy"` | diagnostic only: E9 |
| 814:49 `<` → `==`, `<=`; 814:24 `+` → `-` (PX4, mempool) | killed: `px4_the_pool_must_cover_the_withdrawal_on_the_mempool_path`, `px4_counts_the_transactions_own_deposit` |
| 1200:17 `> MAX_PX_BLOCK_BYTES` → `==`, `>=` | killed: `the_px_byte_budget_is_inclusive` |
| 1214:21 `> MAX_DEPLOY_BLOCK_BYTES` → `>=` | killed: `a_block_of_exactly_the_deploy_budget_is_valid` (deploy_rules.rs) |
| 1299:30 `pool + bridge_in` → `-` (PX4, block) | killed: `px4_the_pool_evolves_in_block_order` |
| 1308:25 `px_slot += 1` → `*=` | killed by the proving test: `px_consensus`, new assertion (a claim and a bridge-in in one uncached block) |
| 1312:50 `exists \|\| !insert` → `&&` (`DuplicateContract`) | killed: `a_block_deploy_of_a_registered_contract_id_is_a_duplicate` |

### tx/src/px.rs (runP: 28 missed)

| Mutant | Resolution |
|---|---|
| 295:9 `base_bytes` → `vec![]`; 303:9 `range_proof_bytes` → `vec![]`; 311:9 `prunable_bytes` → `vec![0]`; 410:9 `base_hash`, 414:9 `prunable_hash` → default | killed: `px_encoding_round_trips_and_its_hashes_cover_the_specified_parts` |
| 327:9 `encoded_len` → 0, 1 | killed: `a_px_transaction_of_exactly_the_size_cap_is_well_formed` and the size-exact helper |
| 480:9 `output_context` → `[0; 32]`, `[1; 32]` | killed: `px_output_context_is_the_specified_hash_of_nullifiers_and_key_images` |
| 609:9 `PxDeploy::prefix_hash` → default | killed: `a_deploys_signatures_and_id_cover_its_payload_and_fee` |
| 708 `k > MAX_OUTPUTS \|\| (k > 0 && n == 0)`: `>` → `==`, `>=`; `\|\|` → `&&`; `k > 0` → `<` | killed: `px_v1_counts_are_bounded_inclusively_and_outputs_need_inputs` |
| 770:25 guard `k > 0` → `true`; 770:27 `>` → `>=` | equivalent: E10 (`rounds(0)` is `None`: the same `RangeProofShape`) |
| 772:36 `l != rounds \|\| r != rounds` → `&&` | killed: `px_range_proof_shape_is_checked_on_both_point_lists` |
| 778:27 `> MAX_FN` → `==`, `>=` | killed: `px_function_count_is_bounded_inclusively` |
| 786:13 `> MAX_PX_TX_SIZE` → `==`, `>=` | killed: `a_px_transaction_of_exactly_the_size_cap_is_well_formed` |
| 799:5 `check_px_balance` → `Ok(())`; 802:41 `&&` → `\|\|`; 811:9 and 811:24 `delete -` | killed: `px_v1_balance_holds_exactly_for_either_sign_of_v` |
| 859:13 `> MAX_DEPLOY_TX_SIZE` → `==`, `>=` | killed: `a_deploy_of_exactly_the_size_cap_is_well_formed` |
| 877:33 `out_words > MAX_FN_OUTPUT_WORDS` → `>=` | killed: `a_deploys_output_words_are_bounded_inclusively` |

### tx/src/params.rs (runP: 4 missed)

| Mutant | Resolution |
|---|---|
| 18:73 `+` → `-`; 18:79 `*` → `+`, `/` (`MAX_PX_TX_SIZE`) | killed: `px_size_and_fee_constants_have_their_specified_values` (also `the_px_byte_budget_is_inclusive`) |
| 42:50 `*` → `+` (`PX_STANDARD_FEE`) | killed: same test |

The node's consensus fingerprint pins these constants too (`tx.*` in
node/src/fingerprint.rs); the node tests were not an oracle of this run.

Re-runs: `rerunC` 38 caught, 10 missed, 3 timeouts; the 10 are E8 (2), E9 (2), E10 (2)
and the 4 proving-only mutants; `timeoutC` 3 caught; `provingC` 4 caught.

### chain/src/manager/fork_choice.rs (runF: 26 missed, 8 timeouts)

| Mutant | Resolution |
|---|---|
| 40:9 `set_step_delay_for_tests` → `()` (a test hook) | killed: `actor_order` (`hookF`) |
| 54:25 `<` → `<=`, `==` in `ancestor_at`; 252:9 `fork_height` → 0 | equivalent: E11 (the same answer by a longer walk) |
| 70:37 `best_work > tip_work` → `==`, `<`, `>=` (`keeps_body`) | killed: `low_work_side_branch_bodies_are_not_kept_but_candidates_always_are` (B's deep bodies), `an_equal_work_header_tip_is_not_a_candidate_for_deep_bodies` |
| 76:30 `tip_work + 1` → `-`, `*` (the leaf scan) | killed: `an_equal_or_lighter_side_leaf_is_not_a_candidate_for_deep_bodies` |
| 173:72 `== Some(true)` → `!=`; 174:12 `delete !` (`drop_invalid`: the parent becomes a leaf) | killed: `a_candidate_cut_back_below_an_invalid_tip_stays_a_candidate` |
| 314:22, 320:29 ×3 (reorg log level); 347:56 ×2 (the uncaptured count); 442:20 ×3, 450:20 ×3 (`finish_sync`'s log guards) | log only: E12 |
| 325:47 `connected.len() - 1` → `+`, `/` (the rules a disconnected block's transactions return under) | killed: `transactions_of_the_last_block_before_the_activation_return_under_the_new_rules` (activation.rs) |
| 376:60 `validated_under() == Some(rules.domain())` → `!=` (when the proof cache may vouch) | killed by the new proving test: `a_pooled_px_proof_vouches_for_nothing_under_other_rules` (`provingF`; under the mutant the side branch with the foreign proof was accepted) |

Re-runs: `rerunF` 9 caught, 16 missed = E11 (3), E12 (12) and 376:60; `provingF` 1
caught; `hookF` 1 caught.

### crypto/ (runK and runK2: 26 missed, 19 timeouts)

| Mutant | Resolution |
|---|---|
| bulletproofs_plus.rs 257:26 (prover) and 397:26, 397:47, 397:68 (verifier) `\|\|` → `&&` in the zero-challenge guards | first exempted (E13, unreachable); the guards are now `any_zero`, with a unit test (§ After RT-MUTC) |
| bulletproofs_plus.rs 260:31 and 453:35 `powers(&y, n + 2)` → `n * 2` | equivalent: E14 |
| janus.rs 42:9 `Debug for Anchor` → empty | killed: `an_anchor_never_prints_its_bytes` |
| keys.rs 254:9 `SubaddressTable::is_empty` → `true`, `false` | killed: `a_subaddress_table_counts_its_entries` |
| membership.rs 85 `MemberSig::encoded_len` (6 mutants) | killed: `signs_and_verifies_for_every_size_and_index` (new assertion, `32·(1 + r)`) |
| membership.rs 204:34 `\|\|` → `&&` (sizes) | killed: `sizes_and_lengths_are_enforced` (a spare response) |
| membership.rs 208:26 `\|\|` → `&&` (identity tag or member) | killed: `identity_tag_and_members_are_rejected` (a signature valid over a ring with an identity member) |
| point.rs 66:9 `partial_cmp` → `None`; 77:9 `Debug` → empty | killed: `points_order_by_their_encoding_through_every_operator` |
| janus.rs 48:9, keys.rs 141:9, 208:9, 217:9, nonce.rs 102:9, stealth.rs 42:9 `Drop` → `()` | unobservable in safe Rust: E15 |
| point.rs 60:9 `Hash for Point` → `()` | first exempted (E16, performance only); killed by RT-MUTC's `a_point_hashes_as_its_encoding` |

Re-run: `rerunK` 13 caught, 13 missed = E13 (4), E14 (2), E15 (6), E16 (1), before the
RT-MUTC changes; E13's and E16's mutants are killed since (§ After RT-MUTC).

### chain/src/block.rs (runB: 5 missed)

| Mutant | Resolution |
|---|---|
| 11:67 `+` → `-`; 11:72 `*` → `+`, `/` (`MAX_BLOCK_BYTES`) | killed: `decode_rejects_more_than_max_block_bytes` (block_rules.rs, the value pinned) |
| 84:9 `Block::weight` → 0, 1 | killed: `a_blocks_weight_is_the_sum_of_its_transactions` (block_rules.rs) |

Re-run: `rerunB` 5 caught. No runB kill rests on an overflow panic (no overflow in
its logs).

## Timeouts

`rerunC` timed out on 3 px.rs mutants (311:9 `prunable_bytes` → `vec![0]`, 327:9
`encoded_len` → 0 and → 1). The cause was in this work's new test code, not in the
product: the helper that pads a PX transaction's proof to an exact encoded size
looped until the size matched, which never happens once `encoded_len` is broken.
The loop is now bounded (8 steps, then an assertion). Re-run in isolation
(`timeoutC`, `-j1`): 3 caught, each by assertions, in 6 minutes. No tx mutant is
caught by a hang.

`runF` timed out on 8 fork_choice.rs mutants (timeout 1 739 s). From runF's logs:
- 282:9 `sync_state` → `false`, 354:33 `&&` → `||` and 354:28 `==` → `!=` (the
  budget check) already **fail assertions** in the lib unit tests
  (`a_bounded_reorganization_never_stops_on_a_lighter_tip`,
  `bounded_submission_reaches_the_unbounded_result_in_bounded_steps`, and others)
  before a later test hangs: caught by assertion.
- The other 5 are **genuine hangs** of the product, re-run with the tests that hung
  skipped (`timeoutF`): each then hangs in the next test that meets an invalid body
  or an invalidation (the actor_equivalence tests, or the new
  `a_candidate_cut_back_below_an_invalid_tip_stays_a_candidate`), and no test fails
  an assertion first:
  - 135:9 `invalidate` → `()` and 153:9 `drop_invalid` → `vec![]`,
    `vec![Default::default()]` (the whole body replaced): an invalid body is never
    marked, so `sync_state` retries the same target forever;
  - 219:15 `delete !` in `invalidate_block`: `while self.sync_step(usize::MAX) {}`
    loops once the drain is done;
  - 254:18 `-=` → `/=` in `fork_height`: the walk never descends.

  These loops are inside the manager's own calls, so a test cannot bound them
  without running the manager on another thread; they hide no assertion. They count
  as caught by the timeout, as run A's two `tx_root` loops do.

The 19 crypto timeouts (timeout 300 s) were re-run with the tests that hung skipped
(`timeoutK`, then whole test modules in `timeoutK2`, 120 s). A hanging test holds a
test thread, and once 8 hang the binary's other tests never start, so a hang can hide
assertions:
- **16 fail assertions** (in runK/runK2's logs or once the hanging tests are
  skipped): the 9 Bulletproofs+ prover mutants (zero challenges, `prove_bits` →
  `None`, the inverted retry guards; `forged_out_of_range_proofs_fail` fails, and
  `prove`'s retry loop hangs the rest), clsag.rs 259:23 and 259:28, hash.rs 248:9
  (`finalize` → zeros: 22 tests fail, the hash known answers among them) and 255:9,
  nonce.rs 61:9, membership.rs 183:13 and 187:23 (16; with 187:28 below, 17).
- **2 are genuine hangs only:** bulletproofs_plus.rs 537:18 (`batch_verify` draws
  weights until one is zero: never) and nonce.rs 75:18 (`HedgedRng::scalar` returns
  only a zero scalar: never). Each loops on every call, so every test that reaches it
  hangs.
- membership.rs 187:28 (`(i + 1) / n`: the ring loop never closes) was a hang only
  in timeoutK; with the final tests it **fails an assertion**:
  `identity_tag_and_members_are_rejected` (re-run `m187`, `-j1`, 120 s, the
  membership tests: that test FAILED, the others hang).

## Release arithmetic

The census builds with overflow checks and debug assertions on, so a mutant can be
caught by an overflow panic that a release build would not have. Every caught
mutant's log was searched for overflow panics (`with overflow`, `attempt to negate`)
and debug assertions: 4 tx, 8 fork_choice and 8 crypto mutants had failures that
were all overflow panics in the first failing test binary (`ovfC.args`, `ovfF.args`,
`ovfK.args`; runB had none). They
were re-run with both switched off (`RUSTFLAGS="-C overflow-checks=off -C
debug-assertions=off"`; the rustc command lines in the logs carry both flags):

- **tx (`ovfC`): 4 of 4 caught**, each by a panic a release build keeps (slice and
  index bounds): `digest_bytes` 126:24 and `contract_id` 661:58 (`+` → `-`: a range
  end past the slice), `read_bytes` 249:29 (a slice end before its start, in
  `px_encoding_round_trips_and_its_hashes_cover_the_specified_parts`),
  validate.rs 1308:25 `px_slot -= 1` (index `usize::MAX`, in
  `px4_the_pool_evolves_in_block_order`).
- **fork_choice (`ovfF`): 7 of 8 caught** by assertions or panics a release build
  keeps: 104:32 (`next_complete_seq -= 1`: the reference model's assertion),
  253:52 (an index out of bounds), 323:40 and 323:44 ×2 (`expect("above genesis")`,
  `expect("non-empty")`), 388:59 `generated - reward` (`emission_is_enforced_exactly`
  asserts the template reward), 424:34 (`flushed at the activation`, activation.rs).
  **1 timeout:** 305:58 `== Some(&cur)` → `!=` (the fork search in `sync_state`):
  in release the depth wraps and the loop never reaches the target, a genuine hang
  in every test that syncs, caught by the timeout.

- **crypto (`ovfK`): 8 of 8 caught** (bulletproofs_plus.rs 382:32, 448:35 ×2,
  448:39 ×2, 98:37; clsag.rs 147:32, 148:32).

No mutant of this run survives release arithmetic.

## Boundary pass

**Why.** cargo-mutants 27.1 replaces `>` with `>=` and `<` with `<=`, but never `>=`
with `>` or `<=` with `<`: the off-by-one at an inclusive bound, where consensus limits
live (red team RT-MUTC found two such survivors by hand). From run C on, every census
adds this pass (Lead, RT-MUTC).

**Tool.** `tools/boundary-mutants.sh` (with `tools/run-with-timeout.ps1` on Windows):
- `list FILE...` prints one mutant per `>=` / `<=` of the non-test code (outside
  comments, string literals and `#[cfg(test)]` items; `>>=` and `<<=` excluded);
- `run SCRATCH TIMEOUT FILE... -- CARGO_ARGS` copies HEAD with `git archive`, applies
  each mutant (two bytes changed), builds it (`--no-run`; a build failure is
  `unviable`), runs `cargo CARGO_ARGS` within TIMEOUT and records `caught`, `missed`,
  `timeout` or `unviable` in `SCRATCH/out/outcomes.txt`, with a log per mutant.

**Oracles:** those of the census for each file (§ Oracles): the tx set with
mutation_regressions (`txtests-rerun.args`), `chaintests.args` and `chaintestsB.args`
with `--skip restart_rebuilds_the_px_state_exactly`, the crypto crate's tests; for runs
A and B, the whole consensus suite and run B's px-core/px set plus
`--test mutation_regressions`. Profile `mutants`, `CARGO_BUILD_JOBS=2`.

**Commands** (`$X` the oracle arguments above, without `-C=`; one target directory per
crate set):

```text
tools/boundary-mutants.sh run <scratch> 600 tx/src/validate.rs tx/src/px.rs tx/src/params.rs \
  -- test --locked --profile mutants -p blacksilk-tx $TX
tools/boundary-mutants.sh run <scratch> 1800 chain/src/manager/fork_choice.rs \
  -- test --locked --profile mutants -p blacksilk-chain $C -- --skip restart_rebuilds_the_px_state_exactly
tools/boundary-mutants.sh run <scratch> 1800 chain/src/block.rs chain/src/emission.rs \
  -- test --locked --profile mutants -p blacksilk-chain $B -- --skip restart_rebuilds_the_px_state_exactly
tools/boundary-mutants.sh run <scratch> 300 crypto/src/*.rs -- test --locked --profile mutants -p blacksilk-crypto
tools/boundary-mutants.sh run <scratch> 300 consensus/src/*.rs -- test --locked --profile mutants -p blacksilk-consensus
tools/boundary-mutants.sh run <scratch> 600 px-core/src/*.rs -- test --locked --profile mutants \
  -p blacksilk-px-core -p blacksilk-px --lib --test kernel --test fuzz --test state --test hk_vectors \
  --test kernel_budget --test consensus_fingerprint --test delivery --test elf_paths --test fri_schedule \
  --test mutation_regressions
```

**Results** (outcome files in `boundary/`; times UTC, 2026-10-01):

| Run | Commit | Files | Mutants | Caught | Missed | Unviable | Time |
|---|---|---|---|---|---|---|---|
| bpT | `120e8f2` | tx validate, px, params | 13 | 7 | 5 | 1 | 07:11–08:02 |
| bpF | `934fe30` | fork_choice.rs | 3 | 2 | 1 | 0 | 07:16–07:50 |
| bpB | `934fe30` | block.rs, emission.rs | 1 | 1 | 0 | 0 | 07:50–07:58 |
| bpK | `5394b45` | crypto/ (14 files) | 4 | 3 | 1 | 0 | 06:53–06:56 |
| bpA | `934fe30` | consensus/ (run A's scope) | 12 | 10 | 2 | 0 | 08:11–08:15 |
| bpX | `934fe30` | px-core/ (run B's scope) | 6 | 3 | 3 | 0 | 08:11–08:17 |
| bpK2, bpX2 | `934fe30`, `55d84f4` | the killed survivors, after their tests | 2 | 2 | 0 | 0 | |

No boundary mutant timed out.

**Survivors:**

| Mutant | Resolution |
|---|---|
| crypto/src/hash.rs 219:17 `len <= u8::MAX` → `<` (the domain tag's one-byte length) | killed: `a_tag_of_exactly_255_bytes_is_the_longest` (bpK2) |
| px-core/src/lib.rs 38:10 `s >= P` → `>` (BabyBear `add`) | killed: `field_addition_reduces_a_sum_of_exactly_p_to_zero` (px/tests/mutation_regressions.rs; bpX2) |
| tx/src/px.rs 808:23 `v >= 0` → `>` | equivalent: E23 (`−0 = 0`) |
| tx/src/params.rs 49:46, 50:43, 127:76 (`const` assertions) | equivalent: E24 (they still hold; no code) |
| tx/src/params.rs 103:10 `m <= 2` → `<` | equivalent: E25 (the clawback is 0 at two outputs) |
| chain/src/manager/fork_choice.rs 314:22 (the reorg warning threshold) | log only: E12 |
| consensus/src/params.rs 198:62 `>= 1 << 64` → `>` | equivalent: E26 (`n(n + 1)·T` is never exactly 2^64) |
| consensus/src/pow.rs 28:15 `height <= epoch + lag` → `<` | equivalent: E27 |
| px-core/src/hash.rs 116:61, 165:37 `pos >= 8` → `>` | equivalent: E28 (`pos < 8` always holds there) |

The unviable mutant is params.rs 48:49 (`MAX_DEPLOY_TX_SIZE < MAX_DEPLOY_BLOCK_BYTES`,
both 1 MiB: the `const` assertion fails).

**Agreement with RT-MUTC's manual mutants.** RT ran 10 of these by hand (release
build, the same tx and chain test sets): validate.rs 348 and 1001, px.rs 692, 844,
845, 848 and fork_choice.rs 354 caught in both; px.rs 141 (`*x >= P`) and
fork_choice.rs 66 (`>= tip_work − margin`) missed by RT, now caught by RT's tests
`px_digest_words_must_be_canonical_field_elements` and
`the_low_work_margin_is_inclusive`; params.rs 103 missed in both (E25).

**Runs A and B** (consensus, px-core): 18 boundary mutants, 13 caught; the 5
survivors are 1 killed (px-core `add`) and 4 equivalent (E26–E28). Runs A and B's
census missed this operator class entirely; their evidence
(docs/evidence/mutation-2026-09-29/) is completed by this section.

## After RT-MUTC

Red team RT-MUTC confirmed the proof-cache finding, the 5 proving-only kills and
E8–E12 and E14. Lead decision: accepted with fixes, done here:
- RT's tests cherry-picked (`df406aa`, `7f44d16`, `46d2e6f`, `fe5d67b`):
  `a_point_hashes_as_its_encoding` (kills E16's mutant: E16 withdrawn),
  `px_digest_words_must_be_canonical_field_elements` (px.rs 141 at P − 1, P, P + 1,
  `u32::MAX`), `the_low_work_margin_is_inclusive` (fork_choice.rs 66).
- E13 withdrawn: the zero-challenge checks of Bulletproofs+ moved into the pure
  helper `any_zero` (commit `b3e4e40`; the same comparisons, without side effects; the
  Bulletproofs+ vectors unchanged), and its 3 mutants (`→ true`, `→ false`, `==` →
  `!=`) are caught by `any_zero_finds_a_zero_challenge_in_any_position`
  (`anyzeroK/`; `→ true` and `!=` also hang the prover's retry loop, after the
  test's assertion fails).
- The validate.rs count corrected (11 killed by non-proving tests, not 13), and
  membership.rs 187:28 reclassified (it fails an assertion).
- `a_pooled_px_proof_vouches_for_nothing_under_other_rules` also asserts the recorded
  verdict, `BlockError::Tx { index: 1, error: PxProof }`: passed (mutants profile,
  alone, 8.8 GB free at the start, 2 059 s).
- **Latent risk (RT):** P2P caches the ids of transactions refused for a stateless
  reason (`recent_rejects`) and never re-checks them; `FeeNotExact` and
  `DeployFeeNotExact` are stateless. If an epoch changed the fee rule, valid
  transactions paying the new fee would be blacklisted. New test
  `fee_rules_are_the_same_in_every_epoch_while_fee_errors_are_stateless`
  (tx/tests/upgrade.rs) fails, naming the fix (make the fee errors contextual near an
  activation in `is_stateless_at`, as `PxProof` is), as soon as two epochs' fee rules
  differ; demonstrated by raising `fee_per_weight` by one in a second epoch.
- The boundary pass (above).

## Limits

- **Operators.** The census covers cargo-mutants' mutation operators, not every
  possible fault.
- **Oracles.** For the tx files, non-proving tx tests only, plus `px_consensus` for
  4 mutants; the chain, node and wallet tests, which exercise the same rules, were
  not used. For fork_choice.rs, 15 of the chain crate's test targets (§ Oracles),
  plus actor_order for one test hook and the new ignored proving test for one
  mutant. For crypto/, the crate's own tests only. For block.rs and emission.rs, 8
  chain test targets.
- **Timeouts as kills.** 5 fork_choice and 2 crypto mutants (and 1 fork_choice
  mutant in release arithmetic) are caught only because the code then loops
  forever. A hang is a weaker oracle than an assertion. The liveness hardening that
  would turn them into assertions (progress checks in `sync_state` and
  `fork_height`, bounded signing loops, `batch_verify`'s weights) is a product
  change, owned by a separate agent (Lead, RT-MUTC).
- **Zeroization (E15)** is not checked by any test: safe Rust cannot observe it.
- **Proof verification itself** (Plonky3, the zkVM AIR) is outside this census: a
  PX5 mutant is killed when a real, tampered or misplaced proof changes a verdict.
- **Synthetic transactions.** Most new tests build transactions field by field
  (unsigned, with shaped but invalid range proofs): they test one rule each, as
  tx/tests/revalidate_after_extension.rs does. Two use a chain view that answers
  differently from any consistent chain (every anchor recent, a set pool, a
  registered contract id alone), stated in each test.
- **Unviable mutants** (tx 12, 15, 17; fork_choice none; crypto 44, 80, 75; block
  2) do not compile, mostly `Default::default()` for types without `Default`, or
  constants that break a `const` assertion.

## Proving tests

- `tx/tests/px_consensus.rs` (in CI's PX-proving step already): two new assertions
  in `a_private_contract_is_deployed_and_used_through_consensus` and one extra proof
  (a bridge-in). Locally, in the mutants profile, the test binary took 718 s.
- `chain/tests/activation.rs` `a_pooled_px_proof_vouches_for_nothing_under_other_rules`
  is new and builds two proofs (1 854 s locally, mutants profile, in parallel with
  another run). It is `#[ignore]`d, so that CI's non-PX step (which runs the chain
  tests in parallel) and the overflow job do not run it. **It is not yet run by CI:**
  the PX-proving step needs a line running
  `cargo test --locked --release -p blacksilk-chain --test activation -- --ignored
  --test-threads=1` (the step's `run` helper appends its own `--
  --test-threads=1`, so it cannot take `--ignored` as is); the workflow is outside
  this work's files (for the Lead).

## Scope status

- **Done:** tx/src/validate.rs, tx/src/px.rs, tx/src/params.rs,
  chain/src/manager/fork_choice.rs, crypto/ (all 14 files), chain/src/block.rs,
  chain/src/emission.rs: every item of the run's scope.
- **W4-PXDOS's decode bounds** (`decode_px_proof` with `PROOF_LIMITS`) are on the
  unmerged branch `w4-pxdos`, not on this run's base `6a2b3b7`: their mutants were
  not censused and need a run after that merge.
