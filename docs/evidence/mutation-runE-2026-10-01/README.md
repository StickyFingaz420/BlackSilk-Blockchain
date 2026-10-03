# Mutation run E: transaction encoding and state, PX statement and state, header sync, the wallet's checks (Wave 4 freeze gate)

Internal engineering evidence, not an audit. A mutation census shows which code
changes the tests notice; it does not show that the code is correct or secure.

The gate (decisions "Agent 42", "W4-MUT and RT-MUT", "Run C and RT-MUTC", "RT-MUTD"):
zero unexplained missed mutants per completed file or function set. Every survivor is
killed by a new test or explained in
[mutation-exemptions.md](../../reviews/mutation-exemptions.md) (run E's entries: E29
onward). Run E is the last scope before the consensus freeze: consensus-critical code
no earlier run had censused, in this order (decision "RT-MUTD", run E scope):

1. `tx/src/types.rs`, `tx/src/codec.rs` (strict decoding);
2. `tx/src/state.rs` (apply, undo, the registry);
3. `px/src/prove.rs` beyond run D's `PROOF_LIMITS`, `check_shape` and
   `check_shape_bits` (the statement, `prove`'s checks, `verify`),
   `px/src/state.rs`, `px/src/tree.rs`;
4. `chain/src/manager/submission.rs`, `chain/src/manager/header_sync.rs`;
5. `p2p/src/net/headers.rs`, `conn.rs` `run_connection`, `maintenance.rs`
   `maintenance_loop`;
6. the wallet's consensus checks (`wallet/src/headers.rs`, the header-check and
   tip-age parts of `wallet/src/wallet/sync.rs`).

Excluded: `chain/src/manager/pow_cache.rs` (another agent is changing it; it gets its
own census after that merge).

## Result in brief

| Scope | Mutants | Caught | Missed | Timeouts | Unviable | After the new tests |
|---|---|---|---|---|---|---|
| tx/src/codec.rs | 71 | 65 | 5 | 0 | 1 | 4 killed; 1 equivalent (E29) |
| tx/src/types.rs | 90 | 70 | 7 | 0 | 13 | 7 killed |
| tx/src/state.rs | 69 | 48 | 16 | 0 | 5 | 16 killed |
| px/src/prove.rs (beyond run D's functions) | 64 | 35 | 21 | 1 | 7 | 17 killed (7 of them by PX-proving runs); 4 equivalent (E31 ×2, E42 ×2); the timeout killed in isolation |
| px/src/state.rs | 27 | 24 | 0 | 0 | 3 | — |
| px/src/tree.rs | 66 | 56 | 2 | 0 | 8 | 2 killed |
| chain/src/manager/header_sync.rs | 63 | 50 | 9 | 1 | 3 | 8 killed; 1 equivalent (E32); the timeout fails assertions in isolation |
| chain/src/manager/submission.rs | 41 | 27 | 7 | 3 | 4 | 5 killed; 2 log lines (E33); the timeouts fail assertions in isolation |
| wallet/src/headers.rs | 89 | 54 | 29 | 1 | 5 | 28 killed; 1 equivalent (E37); the timeout is a genuine hang |
| wallet/src/wallet/sync.rs (the header-check and tip-age functions) | 80 | 62 | 16 | 0 | 2 | 16 killed (2 by the red team, E40 withdrawn: § Follow-up) |
| p2p/src/net/headers.rs (but `end_of`) | 154 | 83 | 56 | 11 | 4 | 46 killed; 10 exempt (E36 ×4, E38 ×4, E39 ×2); the timeouts fail assertions in isolation |
| p2p/src/net/conn.rs (but `knows_tip`) | 80 | 61 | 18 | 0 | 1 | 18 killed |
| p2p/src/net/maintenance.rs `maintenance_loop` | 56 | 31 | 22 | 0 | 3 | 16 killed (2 by the red team: § Follow-up); 6 oracle limits (E43) |
| boundary pass (`>=` → `>`, `<=` → `<`), all scopes | 29 | 19 | 10 | 0 | 0 | 1 killed (wallet 363:29; conn.rs 272:55 was killed before its counted pass, `bndM2`); E30, E34, E35, E41 ×2, E43 ×3; the locator mutant 22:26, killed in the follow-up |
| hand mutants (constants and limits), all scopes | — | — | — | — | — | § Hand mutants: all caught or unviable but E29, E30, E35 ×2, the locator finding and E44 ×2 |

Every file of the scope is complete: each survivor is killed or explained in
[mutation-exemptions.md](../../reviews/mutation-exemptions.md) (E29–E44; E40 withdrawn in
the follow-up). Run E changed no non-test source line; the follow-up (§ Follow-up
(RT-MUTE)) changed a doc comment and named two constants, with no behavior change.

- **No survivor revealed a bug in a consensus rule, a bound or peer scoring.** Every
  cap and limit held at its edge once tested there; the boundary pass found no
  off-by-one. The survivors were rules without a test of their own, code only
  proving tests reach, and comparisons whose edge no test can produce.
- **Finding, not a consensus rule (for the Lead):** docs/p2p.md §6 says the block
  locator holds the tip and 10 predecessors one by one; the code gives 9 (§ chain).
  An ignored test states the documented version. Neither the code nor the sentence
  was changed.
- **What had no test of its own before** (each now has one): the CLSAG message's
  coverage of the range proof (`Transfer::range_proof_bytes`: every honest test
  passed with an empty range-proof encoding in the signed message); each kind's size
  cap at its edge; a deploy applied to the reference state; `verify`'s guard before
  the proof check; the locator's shape; RandomX keys handed to the PoW function; the
  wallet header check's own link test, its context and keys on resume, the dense
  tail's edge and the malformed header-feed pages; the header queue's per-origin room
  (every network test ran with `allow_private`); the clock monitor (no network test
  read it); the block-request timeout and the late block requests; the per-IP limit
  at registration; the idle timeout.
- **Two races in run E's own tests** produced false kills in the first conn and
  maintenance passes; they were fixed and the passes re-run (§ p2p conn.rs).

## Setup

- **Tool:** cargo-mutants 27.1.0, as runs A–D.
- **Toolchain:** rustc 1.98.1 (x86_64-pc-windows-msvc).
- **Code:** branch `w4-mute` on base `a100a19` (`w4-mutd`: runs A–D and the exemption
  numbering E1–E28). No non-test source line was changed.
  - Each first census ("before") ran on the worktree with the test code of its start
    time: `runT` before any run E test; `runP` with the tx tests of `a81cadb` (they
    reach no px code that the px tests do not); `runC` with the chain test of
    `274fc7b`, which only the boundary pass needs (cargo-mutants never makes its
    mutant); `runH` and `runW` before any p2p or wallet test of this run.
  - The re-runs ran on the final test code of their files.
- **Profile:** `[profile.mutants]` of the root Cargo.toml (overflow checks and debug
  assertions on), except the release-arithmetic re-runs (§ Release arithmetic).
- **Machine:** 4 cores / 8 threads, 16 GB, shared with other agents' builds and tests
  (one of them held 4.5 GB for hours; another agent's cargo-mutants ran beside every
  p2p run). cargo-mutants `--jobs 2` for one run at a time (tx, px, chain); `--jobs 1`
  for two runs side by side (p2p headers.rs and the wallet), for conn/maintenance, for
  the isolation runs and for the proving runs.
- **Environment:** `CARGO_BUILD_JOBS=2`, `CARGO_INCREMENTAL=0`, `CARGO_TARGET_DIR`
  unset for cargo-mutants (it builds in its own copy of the tree); the hand-mutant and
  boundary scripts and every manual baseline build in target directories of their own
  (`t-w4-mute-mut` and `t-w4-mute-rerunM` for the manual baselines;
  `t-w4-mute-bnd{T,P,C,W,H,M2}`, `t-w4-mute-hand{T,P,C,W,H,M2,M3,M4}`), never one shared with ordinary builds (RT-MUTD's
  stale-mtime hazard), each copy at its own path.

## Oracles

- **tx (`runT`):** the tx lib tests and the 19 non-proving integration targets of
  `txtests.args` (run D's 17 plus `mutation_regressions` and `px_proof_wiring`).
  Baseline by the tool: 301 s build, 133 s test. The re-runs, the boundary pass and
  the hand mutants add the two new targets (`txtests-rerun.args`: `encoding_rules`,
  `state_accessors`). Left out: `px_consensus` and `fuzz_decode` (PX-proving).
- **px (`runP`):** `--test-package blacksilk-px,blacksilk-tx`, the targets of
  `pxtests.args`: the px lib tests, `consensus_fingerprint`, `elf_paths`,
  `fri_schedule`, `hk_vectors`, `kernel`, `kernel_budget`, `mutation_regressions`,
  `proof_limits`, `state`, and tx's `tree_capacity`, `px_proof_wiring`,
  `state_accessors` (tx's `MemoryChain` holds the PX state). Manual baseline (the
  tool's cannot run `--test-package` targets, run B): all passed, 35 s of tests. Left
  out: px `proof`, `unified`, `fuzz` and `delivery` (proving, or unrelated to the
  scope).
- **Proving-only mutants (`provingP`):** the checks `prove` runs after proving, judged
  by px `unified`'s `lock_then_claim_proves_verifies_and_pays_the_recipient` and the
  new `a_function_writing_only_its_prefix_proves_and_verifies`, one mutant at a time,
  with at least 7 GB free (§ px/src/prove.rs).

## Commands

Run from the repository root of the worktree. `$X` is the content of the named
file, one argument per line (`mapfile -t X < file`; the `--re` filters contain
spaces); the files are in this directory, LF line endings. The `--re` filters follow
run A's convention (`mkre.py`, run D's: each mutant's name, anchored, every
character but a letter, a digit or a space as a one-character class). The scripts
that ran them (`runT.sh` … `provingQ.sh`) are in this directory.

```text
# runT: tx/src/types.rs, codec.rs, state.rs (baseline by the tool: 301 s build, 133 s test)
cargo mutants -p blacksilk-tx -f tx/src/types.rs -f tx/src/codec.rs -f tx/src/state.rs \
  --profile mutants --jobs 2 --timeout-multiplier 5 --minimum-test-timeout 300 \
  --build-timeout 2400 --cap-lints true -o <out> $txtests
# rerunT: runT's 28 survivors, final tests ($txtests_rerun adds encoding_rules, state_accessors)
cargo mutants -p blacksilk-tx -f tx/src/types.rs -f tx/src/codec.rs -f tx/src/state.rs $rerunT \
  --profile mutants --jobs 2 --timeout 700 --build-timeout 2400 --cap-lints true -o <out> $txtests_rerun

# runP: px/src/prove.rs (but run D's PROOF_LIMITS and check_shape*), state.rs, tree.rs
# (manual baseline first: cargo test --locked --profile mutants -p blacksilk-px -p blacksilk-tx <targets>)
cargo mutants -p blacksilk-px -f px/src/prove.rs -f px/src/state.rs -f px/src/tree.rs \
  --exclude-re check_shape --exclude-re '^px/src/prove\.rs:9[0-9]:' \
  --test-package blacksilk-px,blacksilk-tx --baseline skip --profile mutants --jobs 2 \
  --timeout 900 --build-timeout 2400 --cap-lints true -o <out> $pxtests
# rerunP (12 survivors), timeoutP2 (check_budget -> Ok(()), one test):
cargo mutants -p blacksilk-px -f px/src/prove.rs $timeoutP --baseline skip --profile mutants \
  --jobs 1 --timeout 300 --build-timeout 2400 --cap-lints true -o <out> -C=--test=kernel_budget \
  -- -- --exact a_functions_prefix_is_checked_before_its_budget
# provingP1/P2: the checks after proving, one PX-proving unified test each, >= 7 GB free
cargo mutants -p blacksilk-px -f px/src/prove.rs $provingP1 --baseline skip --profile mutants \
  --jobs 1 --timeout 3000 --build-timeout 2400 --cap-lints true -o <out> -C=--test=unified -- -- \
  --exact --test-threads=1 a_function_writing_only_its_prefix_proves_and_verifies

# runC: chain header_sync.rs, submission.rs ($chaintests: run C's chain targets but reference_model)
cargo mutants -p blacksilk-chain -f chain/src/manager/submission.rs -f chain/src/manager/header_sync.rs \
  --profile mutants --jobs 2 --timeout-multiplier 4 --minimum-test-timeout 300 --build-timeout 2400 \
  --cap-lints true -o <out> $chaintests -- -- --skip restart_rebuilds_the_px_state_exactly
# hookC (actor_order), hookC2 (the new step-delay test), timeoutC1 (fork_choice tests),
# timeoutC2 (manager::submission unit tests): as runC with the filter and the named tests

# runW: wallet/src/headers.rs, and sync.rs's header-check and tip-age functions ($wallet_re)
cargo mutants -p blacksilk-wallet -f wallet/src/headers.rs -f wallet/src/wallet/sync.rs \
  --re '^wallet/src/headers\.rs' --re "$wallet_re" --profile mutants --jobs 1 \
  --timeout-multiplier 5 --minimum-test-timeout 300 --build-timeout 2400 --cap-lints true \
  -o <out> -C=--lib

# runH: p2p/src/net/headers.rs (but end_of); three manual baselines first
cargo mutants -p blacksilk-p2p -f p2p/src/net/headers.rs --exclude-re end_of --baseline skip \
  --profile mutants --jobs 1 --timeout 600 --build-timeout 2400 --cap-lints true -o <out> \
  -C=--lib -C=--test=network -C=--test=liveness -C=--test=withheld_body -C=--test=sync_policy \
  -- -- --exact --test-threads=4 $headers_tests
# rerunH: the 56 survivors and 11 timeouts, $headers_final_tests, plus -C=--test=outbound_policy

# runM: p2p/src/net/conn.rs (but knows_tip) and maintenance.rs maintenance_loop; two manual baselines
cargo mutants -p blacksilk-p2p -f p2p/src/net/conn.rs -f p2p/src/net/maintenance.rs \
  --re '^p2p/src/net/conn\.rs' --re ' maintenance_loop( |$)' --exclude-re knows_tip --baseline skip \
  --profile mutants --jobs 1 --timeout 900 --build-timeout 2400 --cap-lints true -o <out> \
  -C=--lib -C=--test=network -C=--test=liveness -C=--test=connection_policy -C=--test=outbound_policy \
  -C=--test=addr_relay -C=--test=transport_adversarial -- -- --exact --test-threads=4 $conn_tests
# rerunM: the 40 survivors ($rerunM), the same with $conn_final_tests (rerunM.sh)

# release arithmetic (ovfT, ovfP, ovfC, ovfW): each scope's command with
RUSTFLAGS="-C overflow-checks=off -C debug-assertions=off" --baseline skip and the $ovf* filter

# boundary pass, per scope (bndT shown):
CARGO_TARGET_DIR=<own dir> bash tools/boundary-mutants.sh run <scratch> 900 \
  tx/src/types.rs tx/src/codec.rs tx/src/state.rs -- test --locked --profile mutants -p blacksilk-tx <targets>
# hand mutants, per scope (handT shown; hand*.tsv: name, path, line, old, new):
python hand.py handT.tsv <copy dir> <own target dir> handT.txt 900 -- test --locked --profile mutants \
  -p blacksilk-tx <targets>
```

## Survivors and their resolution

### tx/src/codec.rs, types.rs, state.rs (runT: 28 missed)

| Mutant | Resolution |
|---|---|
| codec.rs 52:44 `\|` → `^` in `Writer::varint` | equivalent: E29 (bit 7 of the masked byte is always 0) |
| codec.rs 71:9 `Writer::len` → 0, 1; 75:9 `Writer::is_empty` → `true`, `false` | killed: `the_writers_length_counts_the_bytes_written` (no product code reads them) |
| types.rs 248:9 `Transfer::range_proof_bytes` → `vec![]`, `vec![0]`, `vec![1]` | killed: `a_transfers_signature_message_covers_its_range_proof` (tx/tests/encoding_rules.rs). Signing and verifying both call it, so every honest test passed: the CLSAG message would not have covered the range proof, and a signed transfer could have carried another valid range proof for the same commitments |
| types.rs 398:24 `>` → `>=` (the global size cap before the kind is read); 413:24 `>` → `>=` (each kind's cap); 409:13 and 410:13 `delete match arm` `KIND_PX`, `KIND_PX_DEPLOY` (PX and deploys held to the transfer's 100 000 bytes) | killed: `each_kinds_size_cap_is_inclusive` (a buffer of exactly each kind's cap is not `TooLarge`, one byte more is). The existing test checked only cap + 1 |
| state.rs 113:9 `fail_next_apply_for_tests` → `()` | killed: `the_fault_hook_fails_the_next_apply_only` (tx/tests/state_accessors.rs; the chain tests used it already) |
| state.rs 146:9 `block_tx_hashes` (3 mutants) | killed: `block_outputs_and_transaction_hashes_are_kept_per_block` (the node's RPC reads it) |
| state.rs 189:9 `px_contract` → `None`, `Some(empty)`; 195:9 `px_contract_log` (3); 273:17 `delete match arm Transaction::PxDeploy(_)` in `apply_block` (a deploy registers nothing); 318:47 `-` → `+` in `undo_block` (the log is never cut back); 359:9 `px_function` → `None`; 362:37 `==` → `!=`; 372:9 `px_contract_exists` → `false` | killed: `a_deploy_is_registered_and_logged_until_its_block_is_undone`. **No non-proving tx test applied a deploy to the reference state**: the registry was exercised only by px_consensus (PX-proving) and the chain tests |
| state.rs 347:9 `px_is_recent_root` → `true`; 351:9 `px_nullifier_spent` → `false` | killed: `the_chain_views_px_answers_follow_the_applied_blocks` (state.rs unit test). The rules PX1 and PX2 are tested against mock chain views (tx/tests/revalidate_after_extension.rs, validation_order.rs), and px `State` itself is tested; what had no non-proving tx test was the reference view's delegation to it |

Re-run (`rerunT`, final tests, the 28 and the filter-ignoring `delete field`
mutant of `with_px_state`): 28 caught, 1 missed (E29).

### px/src/prove.rs, state.rs, tree.rs (runP: 23 missed, 1 timeout)

| Mutant | Resolution |
|---|---|
| prove.rs 166:29, 166:59 `\|\|` → `&&` in `statement` | equivalent: E31 (both callers check the same terms first) |
| prove.rs 198:26 `>` → `>=` in `over_budget` | killed: `a_functions_prefix_is_checked_before_its_budget` (an execution using exactly its budget fits it) |
| prove.rs 281:45 `\|\|` → `&&`; 281:30 `<` → `==`, `<=` (the prefix check before proving) | killed: the same test, with a function program from the zkvm assembler: an exact prefix passes (then fails its zero budget: `OverBudget`), a three-word output and a prefix with one word changed are `FunctionMismatch` before the budget is measured, and nothing is proven |
| prove.rs 209:5 `check_budget` → `Ok(())` (timeout: the old test went on to prove) | killed: a function far over its budget, beyond the padded tables' room, is `OverBudget` from the per-execution check before the prover's shape check would return `BudgetExceeded`, without proving (`timeoutP2`, the test alone: caught; in the whole oracle the older `an_execution_over_its_own_budget_is_refused_before_proving` still goes on to prove under this mutant) |
| prove.rs 335:20 (`>` → `==`, `<`, `>=`), 335:29, 335:44 (`verify`'s guard); 418:5 `verify_transfer` → `Ok(())` | killed: `verify_judges_the_statement_before_the_proof` (px/tests/proof_limits.rs, hollow proofs: a right-shaped statement reaches the proof check and fails it; another call count, `MAX_FN + 1` functions and an unregistered program are refused first, without a panic; `verify_transfer` takes function-less statements only) |
| prove.rs 293:21, 293:26, 293:39 (the kernel part after proving), 301:27, 309:30 (`==`, `>`, `<=`), 309:45, 309:76 (each function part after proving) | only a proving test reaches them (`provingP1`, `provingP2`: release, one PX-proving unified test, one mutant at a time). Caught: 293:21, 293:39, 301:27, 309:76 (every honest proof refused), 309:30 `==` and `<=` (by the new `a_function_writing_only_its_prefix_proves_and_verifies`: a function writing exactly its prefix), 309:30 `>` (by `lock_then_claim_proves_verifies_and_pays_the_recipient`: the vault writes more than its prefix). 293:26 and 309:45 `\|\|` → `&&` are equivalent: E42 (they repeat the checks before proving on the same deterministic runs) |
| tree.rs 175:9 `Tree::leaf` → `None`, `Some(Default)` | killed: `frontier_and_full_tree_agree_and_paths_verify` now reads the leaves back |

Re-run (`rerunP`, final tests, the 12 non-proving survivors and the filter-ignoring
`delete field` mutant of `PROOF_LIMITS`): 13 caught.

`px/src/state.rs`: 24 caught, 3 unviable, nothing missed.

### chain/src/manager/header_sync.rs, submission.rs (runC: 16 missed, 4 timeouts)

| Mutant | Resolution |
|---|---|
| header_sync.rs 19:23 `\|\|` → `&&` (the loop's end), 23:22 `*=` → `+=`, `/=` (the step), 27:44 `!=` → `==` (the genesis entry) in `locator` | killed: `locator_and_headers_after` now checks the locator's shape by height (strictly decreasing, so no id twice; genesis once and last; consecutive near the tip; then each gap twice the one before, the last stopping at genesis). It had checked only the first two ids, the last and the length |
| header_sync.rs 68:29 `<` → `<=` in `missing_bodies` | equivalent: E32 (one more main-chain entry, always cut by the final truncation) |
| header_sync.rs 80:55 `+` → `-`, `*` (`tip_work + 1`, the side-branch range) | killed: `an_equal_work_side_branch_is_not_fetched` (tests/fork_choice.rs; the existing equal-work test had its rival as the header-best tip, which the scan skips anyway) |
| header_sync.rs 87:52 `&&` → `\|\|` (a stored body listed again) | killed: `a_side_branchs_stored_bodies_are_not_listed_as_missing` |
| header_sync.rs 115:49 `\|\|` → `&&` in `pow_jobs` (a batch broken by one link) | killed: `pow_jobs_use_seeds_from_the_batch` (a wrong height on the right parent, the right height on another parent; the old case broke both) |
| submission.rs 140:24 `delete !`, 211:26 `!=` → `==` | log lines only: E33 |
| submission.rs 178:59, 179:39, 179:42 (the test-only step delay's condition, `#[cfg(feature = "test-hooks")]`) | 178:59 caught by chain's `actor_order` (`hookC`); 179:39 and 179:42 survived it and are killed by `the_test_step_delay_applies_to_drain_steps_with_blocks_to_connect` (tests/manager.rs; `hookC2`) |
| submission.rs 262:9 `refresh_hot_seeds` → `()`, 263:16 `!=` → `==` | killed: `hot_randomx_keys_are_passed_on_when_they_change` (a recording `PowFunction` stand-in: the genesis key at open, both keys from height 2048, nothing else) |
| timeouts: header_sync.rs 75:19 `+=` → `*=` (`missing_bodies` never advances); submission.rs 50:9 `sync_step` → `false`, 177:9 `drain_ready` → `false`, 187:20 `delete !` | in isolation, each fails assertions (`timeoutC1`: three fork_choice tests, among them `a_withheld_body_cannot_stall_block_production`'s exact list; `timeoutC2`: the bounded-submission unit tests, whose drain loops now assert an end). In the full oracle other tests loop on the manager's own calls (`while !self.sync_step(…)`) and hang |

Re-run (`rerunC`, final tests, the 16 and the 4 timeouts): 10 caught, 6 missed,
4 timeouts: the missed are E32, E33 (2) and the 3 test-hook mutants (resolved by
`hookC`, `hookC2` above); the timeouts are the 4 above.

**Finding (not a consensus rule; for the Lead).** docs/p2p.md §6 says the locator
holds "the tip, then 10 predecessors one by one"; `locator` holds the tip and 9
(heights 100 to 91 of a 100-block chain, then 89, 85, …). The boundary pass's
22:26 `>=` → `>` (`out.len() > 10`) is exactly the documented version, and the
tests cannot tell (any locator that ends at the genesis finds the fork; a fork 10
blocks deep is found one header later). The ignored test
`the_locator_has_the_tip_and_ten_predecessors_one_by_one` (tests/manager.rs) fails
on the code and passes under that mutant. Either the code or the sentence changes;
no change was made here. Resolved in § Follow-up (RT-MUTE): the docs follow the code.

### The wallet's header check (runW: 45 missed, 1 timeout)

Scope: `wallet/src/headers.rs` whole, and in `wallet/src/wallet/sync.rs` the dense
proof-of-work batch check and the header feed (`check_batch`, `for_each_header`,
`fetch_headers`, `node_id_at`) and the tip-age refusal (`note_tip_age`, `tip_age`,
`check_fresh_tip`, `stale_tip_limits`, `sync_to_send`). Oracle: the wallet lib tests
(the scripted node of `mock_chain`; baseline 345 s build, 74 s test).

| Mutant | Resolution |
|---|---|
| headers.rs 159:45, 167:18, 170:45 (`HeaderCheck::resume`'s start: too few headers, the link checks) | killed: `a_header_check_resumes_only_from_linked_headers_with_enough_context` (a wrong height alone, a wrong parent alone, one header too few) |
| headers.rs 188 ×3 (the sampling threshold) | killed: `the_header_check_samples_at_the_requested_rate` (half of 600 headers expected: within six standard deviations; forced and full sampling compute all) |
| headers.rs 210 ×2, 222 (`threads`, `set_threads`), 232 ×2 (`has_seed`) | killed: `the_header_checks_threads_and_key_blocks` |
| headers.rs 237 ×3 (`seeds`), 249 ×4 (`context`), 253, 254 ×2 (`trim`) | killed: `a_restores_header_check_hands_its_context_and_keys_to_the_next` (a restore that scans fewer blocks than the context, also on a chain shorter than it: the next check resumes, reading no header below; the context has no genesis and at most `context_len` headers). **In the existing resume test the scanned blocks alone held the context and the key block, so the check's own context and key blocks were never used** |
| headers.rs 279:50 `>=` → `<` (`POW_BATCH`) | killed: `deferred_proof_of_work_is_computed_in_batches_of_pow_batch` (none computed below 256 queued, all 256 at the edge, the rest at `flush`) |
| headers.rs 299:26 (`pow_checked`) | killed: the sampling test (it counts with `pow_checked`) |
| headers.rs 319:36 `\|\|` → `&&` (a header must extend the last one by height **and** parent) | killed: `a_header_check_refuses_a_header_off_its_parent_or_height`. **The header check's own link test was untested on its own**: the header feed's and the scan's link checks refused the same headers first |
| headers.rs 368:29 `>` → `==`, `>=` (the future time limit) | killed: `the_header_checks_future_time_limit_is_inclusive` |
| headers.rs 373:41 `>` → `>=` (a difficulty-1 header queued for hashing) | killed: the batch test (it counts only headers above difficulty 1) |
| headers.rs 412:33 `>` → `>=` (`first_failure`'s skip) | equivalent: E37 |
| headers.rs 423:16 `==` → `!=` (helper threads) | killed: `deferred_proof_of_work_runs_on_helper_threads` (the stand-in's first hash waits up to 30 s for a hash on another thread) |
| sync.rs 64:31 ×2, 65:37 (`stale_tip_limits`) | killed: `a_withheld_tip_is_reported_and_blocks_transactions` now states the limits by value (10 and 60 target block times plus the future time limit, docs/blocks.md) |
| sync.rs 139:59 `>` → `>=` (the dense tail's lower edge) | killed: `the_dense_tail_is_exactly_the_last_720_headers_and_the_first` (with sampling off, exactly the first scanned header and the last 720 are hashed; a forgery one below the tail passes the unsampled check, one at its lowest header does not) |
| sync.rs 163 ×3 (the header feed page checks) | killed: `a_malformed_header_feed_page_is_refused` (a page from another height, an empty page, a partial header, more headers than asked; a feed read in a loop is cut off after 1 000 requests so the test fails instead of hanging) |
| sync.rs 222 ×2 (`node_id_at`) | killed: the same test (the reorganization check's single header, of another height or served as another's) |
| sync.rs 561, 562, 565 (the tip header's source in `note_tip_age`) | killed: `the_tip_age_comes_from_the_wallets_header_or_the_nodes_checked_one` |
| sync.rs 576:16, 618:40 `>` → `>=` (the tip-age limits at their exact second) | oracle limit: E40 (no injectable clock); withdrawn in the follow-up, killed by the red team's test |
| timeout: headers.rs 254:33 `>` → `<` in `trim` | a genuine hang: `trim` pops while the context is shorter than its length, so every check loops in `HeaderCheck::build` (`timeoutW2`, one test, 120 s); no test can fail an assertion first |

Re-run (`rerunW`, final tests, the 45 and the timeout): 41 caught, 3 missed (E37,
E40 ×2), 2 timeouts: the `trim` hang, and 163:37 (`||` → `&&`: an empty page let
through, the feed loop never advancing), which in isolation with the bounded feed
fails its assertion (`timeoutW1`: caught).

### p2p/src/net/headers.rs (runH: 56 missed, 11 timeouts)

Scope: the whole file but `end_of` (run D). Oracle: p2p's lib tests and the
network, liveness, withheld_body and sync_policy targets, filtered by full test
name under `--exact` to the header-sync tests (`headers.tests`: run D's sync list,
the header-queue, unknown-version, invalid-header and anti-DoS tests, and the
headers and state unit tests by their full paths; 44 tests), `--test-threads=4`.
Three baselines on the same profile, all passed (45 to 126 s). The re-run adds the
new tests and outbound_policy's two stale-tip rotation tests
(`headers-final.tests`, 61).

| Mutant | Resolution |
|---|---|
| 50:23 `*` → `+`, 58:36 ×3 (the header queue's total and per-origin room) | killed: `net::headers::tests::the_header_queue_has_room_per_origin_and_in_total` (144 in total by default, 2 per IP, `allow_private`, zero limits counting as one). **Every network test runs with `allow_private`, so the per-origin limit was never read** |
| 129:28 guard → `true` (a second `GetHeaders` while one is outstanding) | killed: `a_second_header_request_waits_for_the_outstanding_one` (a raw loopback peer; two more requests while one is unanswered send nothing before the answer to a later ping) |
| 138:35, 140:30 `>` → `<` (the locator after a batch) | killed: `a_request_after_a_batch_starts_its_locator_at_the_batch` |
| 140:30 `>` → `==`, `>=`; 142:46 ×2 (the trim over 64 ids) | unreachable: E36 |
| 164:5, 166:49 ×2, 175:26, 180:20 (the owed replies, `headers_grace`) | killed: `owed_header_replies_expire_and_are_taken_once` |
| 236:51 `\|\|` → `&&` (a batch that is not a chain) | killed: `a_solicited_batch_that_is_not_a_chain_is_scored_on_arrival` (`UNCONNECTED_HEADERS` on the read loop for a wrong parent alone and a wrong height alone; the existing tests broke both) |
| 331:32 `+` → `-` (`UpgradeWork::of`) | killed: `one_outbound_reporter_on_our_best_work_warns_at_once` |
| 347:21 ×2 (`batch_seed`: the key from the batch itself) | killed: `an_unknown_version_header_keyed_by_its_own_batch_is_hashed` (a batch repeating our blocks from the key block 2 048, ending in an unknown-version header at 2 113) |
| 399:20 ×2 (the per-origin count after the worker) | killed: `the_header_queue_counts_return_to_zero_after_the_worker` |
| 434:25, 439:25 (`delete match arm`: the claimed height lowered after `InvalidParent` and `UnknownUpgrade`), 428:55 guard → `true` (lowered after an unsolicited low-work header) | killed: `relaying_headers_of_a_block_with_an_invalid_body_is_not_penalized` and the unknown-version batch test now check the peer's claimed height; `an_unsolicited_low_work_header_keeps_the_peers_claimed_height` |
| 475:26 `>` → `<` (only a batch that does not connect is scored, not one header) | killed: `an_unconnected_batch_is_scored_and_an_unconnected_announcement_is_not` |
| 489:23 guard → `false` (a panic in the PoW jobs ends the worker silently) | killed: `a_panic_in_the_header_pow_jobs_stops_the_node` (a child process: exit `POISONED_EXIT_CODE`, the reason on stderr) |
| 489:23 guard → `true` | oracle limit: E39 (a cancelled task at shutdown) |
| 576:36, 729:21 ×2, 747:12 `>=` | equivalent: E38 |
| 611:8 `delete !` (a banned departed sender's batch) | killed: `a_banned_departed_senders_batch_is_abandoned_unchecked` (`verify_headers` called directly: loopback peers are never IP-banned, so no network test reached the branch) |
| 668:14 `>` → `==`, `<` (the sender's liveness between chunks) | killed: `a_departed_senders_batch_stops_at_the_next_chunk` |
| 668:14 `>` → `>=` | oracle limit: E39 (a departure inside the pre-check command) |
| 675:73 `+` → `*` (the next chunk's jobs) | killed: `header_batches_are_hashed_off_the_chain_actor` (with the current chunk's jobs, every later chunk was hashed on the chain actor under its lock, unnoticed) |
| 747 ×6 (the live-arrival test of the clock monitor), 778:5, 784 ×3, 785 ×3 (`note_clock`) | killed: `clock_samples_come_from_live_arrivals_only` (network: five announcements from three peers give the estimate; a side-branch header, a tip sent again, a heavier rival ending at our height and a taller, lighter branch add none) and `net::headers::tests::note_clock_samples_refused_headers_and_live_arrivals` (the refusal path). **No network test read the clock monitor** |
| 754 ×4 (`new_tip`, the outbound-rotation mark) | killed: `net::headers::tests::only_a_delivered_new_tip_marks_the_peer` (a new tip on our best chain marks the peer; a new side-branch header and our tip sent again do not). outbound_policy's rotation tests did not notice the mark widened (`rerunH`: 754:26 and 754:22 `<` survived them) |
| timeouts: 111:9, 126:9, 129:28 → `false`, 230:12, 236 ×4, 668:21, 679:17 | each fails assertions in its log (15 to 28 tests failed) before a later test hangs: caught |
| timeout: 373:41 `==` → `!=` (a full batch taken for not full) | no assertion failed: every test passed, the deep-fork one slowly (the maintenance tick asked again from our own tip). Now killed: `a_heavier_fork_deeper_than_one_batch_syncs` checks that the second request starts at the full batch's last header |

Re-runs: `rerunH` (final tests but the last three, 61 tests): 47 caught, 13 missed,
7 timeouts. The 13: E36 (4), E38 (4), E39 (2), and 754:26, 754:22 `<`, 785:25, whose
tests (`only_a_delivered_new_tip_marks_the_peer`,
`note_clock_samples_refused_headers_and_live_arrivals`) were written after `rerunH`
started; `rerunH2` (the 13, 64 tests): those 3 caught, and 142:46 `/` "caught" by a
failure of `the_upgrade_warning_thresholds_are_inclusive` that is not the mutant's —
it is E36. That failure was first taken for a slow registration (the helper's wait was
raised to 20 s); it recurred in the conn/maintenance passes and is a race in the test:
the first reporter was dropped while `dialed_raw_peer` counted outbound peers for the
second. Fixed in `1b4d01d` (the reporters stay connected). The 7 timeouts, each
alone with tests that reach it (`timeoutH-*`): 7 caught, each by a failed assertion
(373:41 by the deep-fork test's new check).

Boundary pass (`bndH`): 51:32 (the queue total), 180:20 (`add_grace`), 333:29 and
334:25 (the upgrade thresholds, by the new `the_upgrade_warning_thresholds_are_inclusive`),
346:11 (`batch_seed`'s first branch: the batch-keyed test, where the seed lookup
then panics on the actor and the node stops with `POISONED_EXIT_CODE`): 5 of 5
caught. Hand mutants (`handH`): `MAX_HEADER_GRACE` 8 → 7, 9; `HEADERS_TIMEOUT` 60 →
59, 61; the queue total `2 ×` → `3 ×`: 5 of 5 caught. Release arithmetic: no caught
mutant's log in `runH` or `rerunH` shows an arithmetic-overflow panic.

### p2p/src/net/conn.rs, maintenance.rs `maintenance_loop` (runM: 40 missed)

Scope: `conn.rs` whole but `knows_tip` (run D), and `maintenance_loop` in
`maintenance.rs`. Oracle: p2p's lib tests and the network, liveness,
connection_policy, outbound_policy, addr_relay and transport_adversarial targets,
filtered by full test name under `--exact` to the connection and maintenance tests
(`conn.tests`: the handshake, limits, eviction, ban, seed, feeler, relay and timeout
tests, 57), `--test-threads=4`, `--jobs 1`. Two baselines on the same profile, both
passed. The re-run's list (`conn-final.tests`, 76; 80 for `handM3`) adds the new
tests. runM: 136 mutants, 92 caught, 40 missed, no timeout, 4 unviable.

| Mutant | Resolution |
|---|---|
| conn.rs 52:30 `*` → `+` (`BULK_OUTBOX`) | killed: `net::conn::tests::the_outboxes_hold_64_control_messages_and_32_block_frames` (docs/p2p.md §10 states both sizes) |
| conn.rs 125 ×3 (`via_tor`: which connections get the Tor key-exchange timeout) | killed: `a_silent_connection_waits_five_seconds_on_clearnet_and_ten_over_tor` (a silent inbound connection on clearnet leaves after the 5 s key-exchange timeout; over Tor-loopback, `allow_private` off and no onion listener, after 10 s) |
| conn.rs 213:28 `<` → `<=`, 215:25 `+=` → `*=` (the unknown frames skipped before `Verack`) | killed: `at_most_eight_unknown_frames_are_skipped_in_the_handshake` (8 complete the handshake, a 9th closes it unregistered; docs/p2p.md §4) |
| conn.rs 243:46 `delete !` (`addr_relay` of an inbound peer that asked for no transaction relay) | killed: `our_address_is_advertised_only_where_addresses_are_relayed` |
| conn.rs 268:25 `delete !`, 271:25 `\|\|` → `&&` (the registration check: a ban that came in during the handshake, the per-IP limit) | killed: `a_ban_during_the_handshake_refuses_the_connection_at_registration` and `the_per_ip_limit_is_rechecked_at_registration` |
| conn.rs 286:21 `&&` → `\|\|` (an inbound connection moving its address to *tried*) | killed: `an_inbound_connection_never_moves_its_address_to_tried` (outbound_policy) |
| conn.rs 305:26, 306 ×3 (an onion listen address stored only from our hidden service's connections) | killed: `an_onion_listen_address_is_stored_only_from_our_hidden_service` (addr_relay) |
| conn.rs 330:45 `&&` → `\|\|` (`relay_txs` of a block-relay-only connection) | killed: `net::conn::tests::a_block_relay_only_peer_relays_no_transactions_whatever_it_asks` |
| conn.rs 522:45 `!=` → `==` (a departing peer's block requests) | killed: `a_block_request_moves_on_when_its_peer_leaves` |
| conn.rs 536:25, 537:9 (a departing peer's place in the announcer queues) | killed: `a_transaction_request_moves_on_when_its_peer_leaves`, now with a third announcer |
| maintenance.rs 84:56 `+` → `-` (the first save at 5 s) | killed: `net::maintenance::tests::the_first_save_of_the_address_table_comes_5_s_after_the_start` |
| maintenance.rs 119:44 `&&` → `\|\|` (the trickle delay) | killed: `net::maintenance::tests::an_announcement_waits_for_its_trickle_delay` |
| maintenance.rs 128:59 `>` → `<` (a seed's address fetch left at once) | killed: `a_silent_seed_has_the_whole_timeout_to_answer` (connection_policy) |
| maintenance.rs 133:49 `>` → `==` (an unanswered ping never times out) | killed: `net::maintenance::tests::a_peer_that_never_answers_a_ping_is_left_after_the_pong_timeout` |
| maintenance.rs 136:59 `>` → `<` (a ping at every tick) | killed: `net::maintenance::tests::an_answering_peer_is_pinged_once_per_interval` |
| maintenance.rs 142:60 ×2, 157:62 ×2, 167:60 `<=` → `>`, 171:62 `==` (the header, block and transaction request timeouts; the late block requests kept) | killed: `net::maintenance::tests::a_header_request_times_out_after_the_headers_timeout` and `requests_time_out_after_their_timeouts_and_late_ones_are_kept_as_long` (ages set in the state, 10 s below and above each limit). **No test reached the block-request timeout or the late block requests**: the network tests' blocks were answered or their peers left |
| maintenance.rs 181:38 `<` → `<=` (`LATE_TXS_MAX`) | killed: `net::maintenance::tests::late_transaction_requests_are_capped` |
| maintenance.rs 228:13 `&&` → `\|\|`, 228:46 `>` → `<` (a save at every change) | killed: the first-save test |
| maintenance.rs 128:59, 133:49, 136:59, 142:60, 157:62, 171:62, 216:46, 228:46 `>` → `>=` | oracle limit: E43 (the elapsed time equal to the limit to the clock's resolution) |

Re-run (`rerunM`, final tests, the 40): 32 caught, 8 missed (E43). Each caught
mutant's log fails the test named above. Boundary pass (`bndM2`, on `42d3f90`):
conn.rs 272:55 (the per-IP limit at registration, by
`the_per_ip_limit_is_rechecked_at_registration`: an outbound connection to the same
IP registered while an inbound one was in its handshake), 275:49 (the onion class
cap), 277:40 (the inbound limit) caught; maintenance.rs 119:51, 167:60 and 179:55
missed: E43. A first pass (`bndM-old`, on `9fc1700`) had 272:55 missed and 167:60,
179:55 "caught" by two races in run E's own tests (below); it is kept for the record.
Release arithmetic (`ovfM`): runM's one overflow-only kill, conn.rs 215:25 `+=` →
`-=` (the skipped-frame count): caught without overflow checks, by
`at_most_eight_unknown_frames_are_skipped_in_the_handshake` (the count wraps, so the
second unknown frame already closes the handshake).

**Two races in run E's own tests, fixed in `1b4d01d`.** The first boundary and hand
passes "caught" mutants by failures that were not the mutants':
`at_most_eight_unknown_frames_are_skipped_in_the_handshake` unwrapped a write and a
read after the node had closed at the 9th unknown frame (a connection reset on
Windows), and `the_upgrade_warning_thresholds_are_inclusive` dropped its first
reporter while `dialed_raw_peer` counted outbound peers for the second (taken in
`rerunH2` for a slow registration). Both passes were re-run on the fixed tests
(`bndM2`, `handM2`, `handM3`); `runM`'s and `rerunM`'s caught mutants each fail a
test of their own rule.

## Boundary pass

`tools/boundary-mutants.sh run` (run C's script: `>=` → `>` and `<=` → `<`, which
cargo-mutants 27.1.0 never makes, one at a time in a `git archive` copy of HEAD, each
built in the script's own target directory), with each scope's oracle; in
wallet/src/wallet/sync.rs only the scope's comparison (`BM_FILTER`), in
maintenance.rs only `maintenance_loop`'s. Results in `bndT/`, `bndP/`, `bndC/`,
`bndW/`, `bndW2/`, `bndH/`, `bndM2/` (`outcomes.txt`); the p2p ones are in their
sections above.

| Mutant | Result |
|---|---|
| tx/src/types.rs 327:14 `m <= 2` → `<` (`Transfer::weight`) | missed: equivalent, E30 (the clawback at two outputs is 0) |
| tx/src/codec.rs 51:17 `v >= 0x80` → `>` (`Writer::varint`) | caught (`varint_round_trip`, the two-byte uniqueness test) |
| tx/src/state.rs 331:49 `<= to` → `<` (`height_range`) | caught (`height_ranges_match_a_linear_filter`, `undo_shrinks_the_record_log`) |
| px/src/state.rs 186:40 `<=` → `<` (a `debug_assert!` on the root window) | caught by the assertion itself (`compact_undo_equals_the_full_clone_reference`); a release build has no assertion to mutate |
| px/src/tree.rs 64:22 `>=` → `>` (`Frontier::append`, the consensus tree's capacity) | caught (`the_last_append_keeps_the_full_root`) |
| px/src/tree.rs 92:22 `<=` → `<` (the test constructor's own `assert!`) | caught (tx's `tree_capacity` tests build a full tree with it) |
| px/src/tree.rs 151:16 `>=` → `>` (`Tree::append`, the full test tree) | missed: unreachable, E34 |
| px/src/tree.rs 180:16 `>=` → `>` (`Tree::path`) | caught (`frontier_and_full_tree_agree_and_paths_verify`) |
| chain submission.rs 139:63 `store_failures >= STORE_FAILURE_LIMIT` → `>` | caught (`a_full_disk_fails_the_store_without_changing_state`) |
| chain header_sync.rs 19:36 `out.len() >= 63` → `>` | missed: unreachable, E35 |
| chain header_sync.rs 22:26 `out.len() >= 10` → `>` | missed: the documented locator (§ chain, the finding) |
| chain header_sync.rs 124:34 `sh >= base` → `>` (`pow_jobs`: a key from the batch itself) | caught by the new assertion in `pow_jobs_use_seeds_from_the_batch` (a batch starting at the key block 2048; the seed lookup then walks past the parent and panics) |
| wallet headers.rs 185:36 `samples >= expected` → `>` | missed: equivalent, E41 (the same threshold at the edge) |
| wallet headers.rs 279:50 `>= POW_BATCH` → `>` | caught (`deferred_proof_of_work_is_computed_in_batches_of_pow_batch`) |
| wallet headers.rs 363:29 `timestamp <= mtp` → `<` | missed in `bndW`; killed by `the_header_check_refuses_a_timestamp_equal_to_the_median_time_past` (`bndW2`: caught) |
| wallet headers.rs 371:56 `draw <= threshold` → `<` | missed: E41 (a draw equal to the threshold, 2^-64 per header) |
| wallet headers.rs 412:14 `i >= jobs.len()` → `>` | caught |
| wallet sync.rs 157:13 `h <= hi` → `<` (`for_each_header`) | caught |

## Hand mutants (constants and limits)

`hand.py` (this directory): each mutant a one-line textual change in a `git archive`
copy of HEAD, built in the script's own target directory, then the scope's oracle;
the file is restored and touched after each. Results in `handT.txt`, `handP.txt`,
`handC.txt`, `handC2.txt`, `handW.txt`, `handW2.txt`, `handH.txt` (§ p2p headers.rs),
`handM2.txt`, `handM3.txt`, `handM4.txt`.

| Mutant | Result |
|---|---|
| codec.rs `Reader::varint` `0..10` → `0..9`; `i == 9` → `i == 8`; `low > 1` → `low > 0`, `low > 2` | caught |
| codec.rs `0..10` → `0..11` | missed: equivalent, E29 (no iteration at `i = 9` falls through) |
| types.rs `Transfer::weight` `320 * m` → 321, 319; `* 4 / 5` → `* 3 / 5`, `* 4 / 4` | caught |
| types.rs `m <= 2` → `m <= 1` | missed: equivalent, E30 |
| types.rs the global cap `+ 1`, `- 1`; each kind's cap `+ 1`, `- 1` | caught |
| px state.rs `ROOT_WINDOW` 100 → 99, 101 | caught (the consensus fingerprint pin, `px_side_consensus_constants_are_pinned`) |
| px tree.rs `CAPACITY` `1 << TREE_DEPTH` → `(1 << TREE_DEPTH) - 1` | caught (`the_last_append_keeps_the_full_root`) |
| px prove.rs `kernel_budget` n_fn 0 cycles 26 500 → 26 501; n_fn 2 bit 2 000 → 1 999 | caught (the fingerprint pin) |
| chain `STORE_FAILURE_LIMIT` 3 → 2, 4 | missed in `handC` (the test used the constant symbolically); killed after `storage_recovery`'s full-disk test states the number (`handC2`: both caught) |
| chain `locator` cap 63 → 62, 64 | missed: unreachable, E35 |
| chain `locator` dense prefix `>= 10` → `>= 9` | caught |
| chain `locator` dense prefix `>= 10` → `>= 11` | missed: the documented locator (§ chain, the finding) |
| chain `locator` `step *= 2` → `step *= 3` | caught |
| wallet `HEADER_SAMPLES` 16 → 15, 17 | missed in `handW` (the restore test bounds the sample loosely); killed after `the_header_checks_threads_and_key_blocks` states the number (`handW2`: both caught) |
| wallet `POW_BATCH` 256 → 255, 257 | caught |
| wallet `DENSE_POW_TAIL` 720 → 719, 721 | unviable: a `const` assertion ties it to `KEPT_BLOCK_IDS` (the dense-tail test states 720 too) |
| wallet `STALE_TIP_WARN_BLOCKS` 10 → 9, 11; `STALE_TIP_REFUSE_BLOCKS` 60 → 59, 61 | caught |
| p2p conn.rs `OUTBOX` 64 → 63, 65; `BULK_OUTBOX` `2 × SERVE_BLOCKS_PER_REQUEST` ± 1 | caught (`handM2`: the outbox-size test, docs/p2p.md §10) |
| p2p conn.rs `HANDSHAKE_UNKNOWN_FRAMES` 8 → 7, 9 | caught (`handM2`: `at_most_eight_unknown_frames_are_skipped_in_the_handshake`) |
| p2p conn.rs `KEY_EXCHANGE_TIMEOUT` 5 → 4 s; `HANDSHAKE_TIMEOUT` 10 → 9 s; `HANDSHAKE_DEADLINE` 20 → 19 s | caught (`handM2`: the silent-connection and drip-fed tests, now bounding the close from below at the timeout) |
| p2p conn.rs `KEY_EXCHANGE_TIMEOUT` 5 → 6 s; `HANDSHAKE_TIMEOUT` 10 → 11 s; `HANDSHAKE_DEADLINE` 20 → 21 s; `IDLE_TIMEOUT` 180 → 179, 181 s | missed in `handM2` (the behavior tests' upper bounds keep a margin for load; no test reached the idle timeout); caught in `handM3` by `net::conn::tests::the_connection_timeouts_are_the_specified_ones` (docs/p2p.md §4 and "Liveness" state 5, 10, 20 and 180 s) and, for 179 s, the new `a_silent_registered_peer_is_left_after_the_idle_timeout` |
| p2p maintenance.rs `PONG_TIMEOUT` 30 → 29, 31 s | caught (`handM2`: `a_peer_that_never_answers_a_ping_is_left_after_the_pong_timeout`, which states 30 s) |
| p2p maintenance.rs `SAVE_INTERVAL` 60 → 59, 61 s | missed in `handM2` (the first save comes 5 s after the start whatever the interval); caught in `handM3` (the first-save test states 60 s: docs/p2p.md §9, "within a minute of changing") |
| p2p maintenance.rs the first save's `5 s` → 4 s | caught (`handM2`: the first-save test) |
| p2p maintenance.rs the first save's `5 s` → 6 s | missed (`handM2`, `handM3`, `handM4`): E44 (an unnamed, unspecified delay; only its lower side is testable without a wall-clock upper bound) |
| p2p maintenance.rs `chunks(500)` → 499, 501 (ids per `InvTx`) | missed in `handM2`; caught in `handM3` by `queued_announcements_go_out_in_messages_of_at_most_500_ids` (`MAX_INV`, the most a peer decodes) |
| p2p maintenance.rs the outbound round's `2 s` → 1 s | missed in `handM2`; caught in `handM3` by `outbound_connections_are_maintained_every_two_seconds` (docs/p2p.md §9) |
| p2p maintenance.rs the outbound round's `2 s` → 3 s | missed in `handM2` and, alone, in `handM4`: E44, with a recommendation to name the delay. `handM3`'s "caught" was four network tests timing out while the release test suite ran beside it, not this mutant |

## Release arithmetic

The census builds with overflow checks and debug assertions on, so a mutant can be
caught by an overflow panic that a release build would not have. Every caught
mutant's log of `runT` and `runP` was searched for an arithmetic-overflow panic; the
ones found were re-run with `RUSTFLAGS="-C overflow-checks=off -C
debug-assertions=off"`:

- **tx (`ovfT`): 4 of 4 caught** (codec.rs 104:18 `+=` → `-=` in `Reader::u8`,
  state.rs 122:9 `output_count` → 0, 267:34 `+=` → `-=` in `apply_block`, types.rs
  335:61 `+` → `-` in `encoded_len`), plus the filter-ignoring `delete field` mutant.
- **px (`ovfP`): 7 of 7 caught** (prove.rs 284:24, state.rs 169:34, tree.rs 20:29,
  29:13, 81:19, 158:82, 159:42), plus the `delete field` mutant.
- **chain (`ovfC`): 7 of 7 caught** (header_sync.rs 67:51, 75:19 `+=` → `-=`, 109:42,
  124:34 `>=` → `<`, 180:17; submission.rs 138:37, 154:28).
- **wallet (`ovfW`): 7 of 7 caught** (headers.rs 177:24, 299:26, 318:36, 388:49;
  sync.rs 64:35, 128:34, 158:29).
- **p2p:** headers.rs: none (no caught mutant's log of `runH` or `rerunH` shows an
  overflow panic); conn.rs (`ovfM`): 1 of 1 caught
  (215:25 `+=` → `-=`, § p2p conn.rs).

## Follow-up (RT-MUTE, Lead decision: accepted with fixes)

The red team (branch `rt-mute`) and the Lead's decision RT-MUTE confirmed E29–E39,
E41, E42 and E44, and asked for the fixes below. `rebuild/core` was merged into
`w4-mute` first (`93332f4`), then the red team's six test commits were
cherry-picked (`64d2dec`, `e37861f`, `59a909b`, `c7e51b5`, `76c8bb6`, `ffd513c`).

- **F1, signed-message coverage (Medium).** Run E closed the range-proof gap of a
  transfer's CLSAG message only. The red team's tests cover the rest. Each of the five
  survivors, applied as a hand mutant to a `git archive` copy (`handF1.tsv`,
  `handF1.txt`; oracle: tx's lib tests and every non-proving tx target), is caught.
  This is 5 of 5:
  - the transfer message without its pseudo-outputs (types.rs 283), by
    `a_transfers_signature_message_covers_its_pseudo_outputs`;
  - the deploy message without its pseudo-outputs (px.rs 633) or its range-proof term
    (px.rs 634: a signed deploy could have carried another range proof);
  - the deploy id without its base (types.rs 455) or its prunable part (types.rs 456),
    by `a_deploys_signature_message_covers_its_pseudo_outputs_and_range_proof`.

  **Not done:** adding deploy and PX samples to the node's pinned fingerprint. The rule
  samples (`transaction_samples`) are part of `rules_manifest`, whose digest is the
  rules fingerprint (node/src/fingerprint.rs). Any new sample entry therefore changes
  the rules and consensus fingerprints and their pins. That is not a pure test-sample
  addition, so it was left for a Lead decision.
- **F2, E40 and part of E43 withdrawn.** The red team's tests kill the following,
  confirmed with cargo-mutants on their own tests (`f2p`, `f2w`: 4 of 4 caught):
  - the tip-age limits at their exact second (wallet sync.rs 576:16, 618:40), by
    `the_tip_age_limits_are_strict_at_their_exact_second`, which reads whole seconds and
    repeats a try across a second boundary;
  - the ping interval and the address-fetch timeout (maintenance.rs 136:59, 128:59),
    by `an_elapsed_time_equal_to_a_zero_limit_does_not_trigger_it`. It uses zero
    limits and future instants, so the elapsed time saturates to exactly the limit.

  E40 is withdrawn. E43 is narrowed and reworded as "comparisons against constant
  limits (no clock seam)": the mutants whose limit is configurable could be made equal
  and are killed; constant limits cannot be.
- **The locator (Lead decision: the docs follow the code), `217ddd0`.** The following
  now say the tip and 9 predecessors one by one, then doubling gaps back to genesis:
  - docs/p2p.md §6;
  - the doc comment of `ChainManager::locator` (header_sync.rs).

  The record notes two points:
  - Bitcoin Core's locator has 11 consecutive ids;
  - the count is not consensus-relevant: any decreasing locator that ends at genesis
    interoperates.

  The ignored test became `the_locator_has_the_tip_and_nine_predecessors_one_by_one`.
  It checks the exact heights (100 to 91, then 89, 85, 77, 61, 29, 0) and the shape:
  9 dense gaps, then each gap doubling, ending at genesis. The boundary mutant (now line
  24:26 after the comment, run E's 22:26) is caught (`bndLoc`). 21:36 stays E35.
- **E44 named, `a91c178`.** `FIRST_SAVE_DELAY` (5 s) and `OUTBOUND_ROUND` (2 s) are
  named constants in maintenance.rs, with no behavior change.
  `the_first_save_delay_and_the_outbound_round_are_the_specified_ones` pins them.
- **F4, the outbound_policy flake, `1c6d42f`.** `table_of` built its table with one
  key. Loopback addresses heard from one source share one *new* bucket, and
  `AddrMan::add` drops an address whose slot is taken, so random ports could collide.
  `table_of` now tries keys until every address is placed, and checks the count.
  `lost_outbound_peers_are_replaced` (8 addresses) passed 50 of 50 runs (`f4.txt`).
- **F5, L7, `dbc95ab`.** The liveness test L7 now measures the header's wait in drain
  steps (blocks connected between the announcement and the acceptance), not wall time.
  - The bound: at most 4 steps (8 blocks). A regression to four waits is at least 5.
  - The step is 1 s (was 300 ms), so a second of load costs at most the one step of
    slack.
  - The old bound, `2·STEP + 700 ms`, was measured at 1.61 s under load.
  - Five local runs: 4 blocks each.

**Checks of the follow-up** (on `d1c8ec0`, the merge of `rebuild/core` included):
`cargo fmt --all --check`; `cargo clippy --locked --workspace --all-targets -- -D
warnings`; CI's non-PX test job in release (`tier1.sh`: tx 167 passed, px 74, the rest
of the workspace 1278; no failure); `consensus-gate.sh a100a19 HEAD` (101 commits, 9 on
consensus paths, pass), `lockfile-gate.sh a100a19 HEAD`, `unicode-scan.sh`,
`doc-lint.sh`, `tools/check-test-features.sh` (now present after the merge: every
test-only feature and `cfg(fuzzing)` crate is marked) and `cargo deny check`: pass.

**Follow-up commits** (after `81ca133`; `93332f4` merges `rebuild/core`):

- `64d2dec` p2p maintenance tests: a zero ping interval and address-fetch timeout are strict (RT-MUTE, against E43)
- `e37861f` wallet tests: the tip-age limits are strict at their exact second (RT-MUTE, against E40)
- `59a909b` tx tests: a deploy's CLSAG message covers its pseudo-outputs and range proof (RT-MUTE)
- `c7e51b5` tx tests: a deploy's id covers its pseudo-outputs, range proof and signatures (RT-MUTE)
- `76c8bb6` tx tests: a transfer's CLSAG message covers its pseudo-outputs (RT-MUTE)
- `ffd513c` rt-mute tests: rustfmt
- `217ddd0` chain, docs: the block locator holds the tip and 9 predecessors one by one
- `a91c178` p2p: name FIRST_SAVE_DELAY and OUTBOUND_ROUND in the maintenance loop
- `1c6d42f` p2p tests: table_of tries table keys until every address has its own slot
- `dbc95ab` p2p tests: L7 measures the header's wait in drain steps, not wall time
- `d1c8ec0` docs: run E follow-up (RT-MUTE): F1 confirmed, E40 withdrawn, E43 narrowed, E44 named
- this follow-up's evidence update

**Full-set "kills" by timing assertions must be re-checked in isolation.** In run E,
two races in run E's own tests (§ p2p conn.rs) and a test suite running beside a hand
mutant (`handM3`, the outbound round) turned load into "caught" verdicts. Treat a kill
whose failing assertion is a wall-clock bound (a time limit, `wait_until`, a
registration wait) as unconfirmed until the mutant fails the same test alone, on an
otherwise idle oracle (`handM4` was that re-check).

## Times

UTC, 2026-10-01 to 2026-10-03, the machine shared throughout (`*.time` in this
directory):

- `runT` 15:22–20:01 (Oct 1), `runP` 20:02–22:17, `rerunT`, `rerunP` and the tx/px
  boundary, hand and overflow passes until 01:08 (Oct 2);
- `runC` 01:08–03:41, the chain follow-ups until 12:29;
- `runH` 07:08–15:05 and `runW` 07:19–11:50 side by side; `rerunW` 12:30–14:30;
  `rerunH` 15:05–19:24; `provingP` (release) 19:04–20:39; `timeoutH` 20:39–21:24;
  `rerunH2` and the headers boundary and hand passes 21:24–22:23;
- `runM` 20:40 (Oct 2)–00:11 (Oct 3); `rerunM` 00:14–01:34; `bndM2` 00:14–00:39;
  `handM2` until 01:46; `handM3` 01:50–03:30; `ovfM` 03:32; `handM4` 05:13–05:33; tier 1 (`tier1.sh`, release) 01:50–05:12.

## Limits

- **Operators.** The census covers cargo-mutants' operators, the boundary pass's two
  and the hand mutants; a caught mutant shows only that some test notices that change.
- **Function scope.** wallet/src/wallet/sync.rs and maintenance.rs were censused for
  the scope's functions only; conn.rs and headers.rs whole but the functions run D
  censused (`knows_tip`, `end_of`).
- **Oracles.** Filtered test lists (full names under `--exact`) for the p2p scopes;
  a mutant that only an unlisted test notices counts as missed. The PX-proving tests
  were oracles only for prove.rs's checks after proving (two unified tests, release,
  one mutant at a time).
- **Wall-clock rules.** The p2p timing tests bound an observed close or save exactly
  from below (a timeout never fires early) and only loosely from above (in this run a
  5 s close was observed after more than 7.5 s under load, `facb993`). Upper-side
  mutants are caught only where a test states the specified value (docs/p2p.md);
  E43 and E44 hold what no test can observe.
- **Timeouts as kills.** Each timeout was re-run in isolation and fails an assertion
  there, except wallet `trim` (254:33), a genuine hang counted as caught.
- **Release arithmetic** covered the overflow-only kills (`ovfT`, `ovfP`, `ovfC`,
  `ovfW`, `ovfM`); every other kill fails an assertion.

## Scope status

All six items of the run E scope are complete, in order: tx types.rs and codec.rs;
tx state.rs; px prove.rs, state.rs and tree.rs; chain submission.rs and
header_sync.rs; p2p headers.rs, conn.rs and `maintenance_loop`; the wallet's checks.
Left for others: `chain/src/manager/pow_cache.rs` (excluded, another agent's
change); the Lead's review of E29–E44 and of the locator finding; CI's PX-proving
step runs the new unified test (`a_function_writing_only_its_prefix_proves_and_verifies`).

## Checks (tier 1)

On the final test code (`e8e517f`; `c08f5d8` changes only a test module's comment):
`cargo fmt --all --check`; `cargo clippy --locked --workspace --all-targets -- -D
warnings`; CI's non-PX test job in release (`tier1.sh`: tx lib and integration tests
but `px_consensus` and `fuzz_decode`, 164 passed; px but `proof` and `unified`, 74
passed; the rest of the workspace with CI's PX skips, 1216 passed; no failure);
`consensus-gate.sh a100a19 HEAD` (3 commits touch consensus paths, each with the
trailer), `lockfile-gate.sh a100a19 HEAD` (no lockfile change), `unicode-scan.sh`,
`doc-lint.sh` and `cargo deny check`: pass. `tools/check-test-features.sh` (taken
from `rebuild/core`, as the base has none) fails on the base's missing markers
(`TEST_HOOKS_MARKER` in tx, chain and px; `FUZZING_MARKER` in p2p), which later
`rebuild/core` commits add; this run touches none of it. The new PX-proving test
(`a_function_writing_only_its_prefix_proves_and_verifies`) passed locally in release
(71 s, at least 7 GB free); CI's PX-proving step runs it.

## Commits

On branch `w4-mute` (base `a100a19`), tests and evidence only; the commits touching
consensus-gated paths carry `Consensus-Change: none: tests only`:

- `a81cadb` tx tests: kill the survivors of mutation run E in codec.rs, types.rs and state.rs
- `9f952e6` px tests: kill the survivors of mutation run E in prove.rs and tree.rs
- `274fc7b` chain tests: a header batch starting at a RandomX key block takes its key from the batch
- `fd5200e` px tests: the per-execution budget check refuses before the prover's shape check
- `7a12c4a` chain tests: kill the survivors of mutation run E in header_sync.rs and submission.rs
- `a54698d` chain tests: the test-only step delay applies to exactly the drain steps with work
- `cbde48f` chain tests: pin STORE_FAILURE_LIMIT at the specified 3
- `49488e3` p2p, wallet tests: first survivors of mutation run E in headers.rs and the wallet's header check
- `489abcf` p2p, wallet tests: more survivors of mutation run E (header sync, the wallet's header check)
- `bb96b9a` p2p, wallet tests: the header queue counts after the worker; malformed header-feed pages
- `4fc9ed3` p2p tests: the header worker's corrections of a peer's claimed height
- `42b30a4` p2p, wallet tests: a panic in the header PoW jobs stops the node; the reorg check's header
- `9bc6943` p2p, wallet tests: unconnected batches against announcements; the tip age's header
- `5513513` p2p tests: a banned departed sender's batch is abandoned before the pre-check
- `0d0c9e9` p2p tests: a departed sender's batch stops costing hashes at the next chunk
- `1c10a7a` p2p tests: header batches are hashed off the chain actor
- `c3cae30` p2p tests: the clock monitor samples live arrivals only
- `0817477` p2p tests: the clock monitor test covers a same-height rival and a taller, lighter branch
- `192756e` p2p tests: a full header batch is continued from its last header at once
- `233b5e1` wallet tests: the malformed-feed test cuts a feed read in a loop off
- `d5f431c` p2p tests: note_clock samples refused headers and the last header of a live arrival
- `2749405` wallet tests: a timestamp equal to the median time past is refused
- `b8f76e8` wallet tests: pin HEADER_SAMPLES at 16
- `154a55f` tx, p2p tests: clippy (a const assertion; a state lock in its own scope)
- `f22afdf` p2p tests: only a delivered new tip marks the peer
- `5020114` p2p tests: the upgrade-warning thresholds are inclusive
- `41b8cd0` p2p tests: the key-exchange timeouts; the outbox sizes
- `facb993` p2p tests: the clearnet key-exchange bound at 9 s (load margin)
- `e3f1729` p2p tests: the handshake's unknown-frame bound; our address only where addresses relay
- `ecf8e3c` p2p tests: a dialed raw peer gets 20 s to register
- `21d3df6` p2p tests: a ban during the handshake refuses the connection at registration
- `d1e3311` p2p tests: inbound peers never reach tried; onion listen addresses only via our hidden service
- `f2a6feb` p2p tests: a block-relay-only peer relays no transactions whatever it asks
- `9745bcb` p2p tests: a departing peer's block and transaction requests move on at once
- `9fc1700` p2p tests: the trickle delay holds announcements; the first address save comes 5 s after start
- `1b4d01d` p2p tests: the maintenance loop's timeouts, the per-IP re-check at registration; two test races fixed
- `42d3f90` p2p tests: exact lower bounds for the handshake timeouts and the pong timeout
- `8e66873` p2p tests: the idle timeout, and the specified connection timeouts by value
- `e8e517f` p2p tests: announcements in messages of at most 500 ids; outbound rounds every 2 s
- `c08f5d8` p2p tests: the maintenance tests' module comment names what they cover
- this evidence and E29–E44 in docs/reviews/mutation-exemptions.md
