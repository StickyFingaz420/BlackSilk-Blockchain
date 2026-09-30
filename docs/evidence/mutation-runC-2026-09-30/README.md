# Mutation run C: the transaction rules (Wave 4 freeze gate)

Internal engineering evidence, not an audit. A mutation census shows which code
changes the tests notice; it does not show that the code is correct or secure.

The gate (decisions "Agent 42" and "W4-MUT and RT-MUT", run C): zero unexplained
missed mutants per completed file. Every survivor is killed by a new test or
explained in [mutation-exemptions.md](../../reviews/mutation-exemptions.md) (E8–E10).
Run C's scope, in priority order: tx/src/validate.rs, tx/src/px.rs,
chain/src/manager/fork_choice.rs, tx/src/params.rs, crypto/, chain/src/block.rs and
chain/src/emission.rs. What this run completed and what remains is in § Scope status.

## Result in brief

| File | Mutants | Caught (run) | Missed (run) | Unviable | After the new tests |
|---|---|---|---|---|---|
| tx/src/validate.rs | 138 | 107 | 19 | 12 | 13 killed by non-proving tests, 4 by the proving test `px_consensus` (2 of them by its new assertions), 2 equivalent (E8); 2 diagnostic only (E9) |
| tx/src/px.rs | 174 | 131 | 28 | 15 | 26 killed (3 of them first timed out on an unbounded test loop, § Timeouts), 2 equivalent (E10) |
| tx/src/params.rs | 93 | 72 | 4 | 17 | 4 killed |

- **No survivor revealed a bug in a transaction rule.** Every rule the survivors
  pointed at is implemented as specified; only its test was missing.
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
- **Equivalent or diagnostic (exempt):** 6 mutants, E8–E10.

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
- **Not used:** the chain, node, wallet and p2p tests, which also call these rules.

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
```

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

## Timeouts

`rerunC` timed out on 3 px.rs mutants (311:9 `prunable_bytes` → `vec![0]`, 327:9
`encoded_len` → 0 and → 1). The cause was in this work's new test code, not in the
product: the helper that pads a PX transaction's proof to an exact encoded size
looped until the size matched, which never happens once `encoded_len` is broken.
The loop is now bounded (8 steps, then an assertion). Re-run in isolation
(`timeoutC`, `-j1`): 3 caught, each by assertions, in 6 minutes. No timeout remains,
and no mutant of this run is caught by a hang.

## Release arithmetic

Every mutant this run reports as caught was checked for a kill that could rest on an
overflow check or a debug assertion alone, which a release build does not have:

- the survivors' kills (rerunC, timeoutC, provingC) are assertion failures of the
  named tests, each a comparison of a verdict or a value (the logs show the failing
  assertion);
- in runV and runP, a caught mutant whose only failure could be an overflow panic
  would be one on an arithmetic operator; the arithmetic of these files is
  `u128`/`i128` sums of `u64` values (no overflow possible), the saturating
  `px_free_leaves`, the `checked_sub` of the block pool, and `max_weight`'s `u64`
  arithmetic (at most 57 439 for valid shapes). **Left to do (RT):** re-run the caught
  arithmetic mutants under `RUSTFLAGS="-C overflow-checks=off -C
  debug-assertions=off"` as run A's `ovfA`, to confirm by execution.

## Limits

- **Operators.** The census covers cargo-mutants' mutation operators, not every
  possible fault.
- **Oracles.** Non-proving tx tests only, plus `px_consensus` for 4 mutants. The
  chain, node and wallet tests, which exercise the same rules, were not used.
- **Proof verification itself** (Plonky3, the zkVM AIR) is outside this census: a
  PX5 mutant is killed when a real, tampered or misplaced proof changes a verdict.
- **Synthetic transactions.** Most new tests build transactions field by field
  (unsigned, with shaped but invalid range proofs): they test one rule each, as
  tx/tests/revalidate_after_extension.rs does. Two use a chain view that answers
  differently from any consistent chain (every anchor recent, a set pool, a
  registered contract id alone), stated in each test.
- **Unviable mutants** (12, 15 and 17) do not compile, mostly `Default::default()`
  for types without `Default`, or constants that break a `const` assertion.

## Scope status

- **Done:** tx/src/validate.rs, tx/src/px.rs, tx/src/params.rs (items 1, 2, 4).
- **W4-PXDOS's decode bounds** (`decode_px_proof` with `PROOF_LIMITS`) are on the
  unmerged branch `w4-pxdos`, not on this run's base `6a2b3b7`: their mutants were
  not censused and need a run after that merge.
