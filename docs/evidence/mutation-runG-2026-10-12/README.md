# Mutation run G: the consensus code after run E, RandomX, the zk and zkvm verifier paths, store replay, fingerprints (freeze gate 1.1)

Internal engineering work, not an audit. A mutation census shows which code changes
the tests notice; it does not show that the code is correct or secure.

The gate (decisions "Agent 42", "W4-MUT and RT-MUT", "RT-MUTD"): zero unexplained
missed mutants per completed file or function set. Every survivor is killed by a new
test or explained in [mutation-exemptions.md](../../reviews/mutation-exemptions.md)
(run G's entries: E65 to E86). **Run G does not meet the criterion:** one
RandomX mutant (`superscalar.rs` 742:24) is neither killed nor shown equivalent
(§ Open items (a)). It is listed as open, not exempt, and nothing about it is
accepted; the owner decides between funding further research and formally accepting
the residual. Of the 160 survivors, 80 are killed by new tests (each with a kill
record, § Kill confirmation), 79 are exempt (77 shown equivalent or log-only from the
code, E69's two on width-1 builds only; E82's two by a probabilistic argument,
labelled so) and 1 is open. The eight
fingerprint mutants that showed a structural weakness of the manifest, and three
formerly exempt ones (E84, E85, now superseded), are killed since the manifest
records the sample inputs (§ Open items (b), closed).

Revised 2026-10-13 after the red team's review: every kill made by then re-run at the
then final commit `dfed6a5` (§ Kill confirmation), the open-sample criterion stated and applied (three G7 mutants
moved from E84 and E85 to open), and the aarch64 limit of E69. Revised again on
2026-10-13: the two `superscalar.rs` 783:42 mutants are killed by a new reference
corpus line (`a2fbac1`, § G3), and the reachability research on 742:24 is stated in
§ Open items (a). Revised again on 2026-10-13: the change fingerprint-sample-inputs
(`1a74131`, branch `consensus/fingerprint-sample-inputs`) records the rule samples'
inputs in the node manifest (the exceptions are listed in the record, item 5); it kills the eight open G7 mutants and the three G7
mutants that E84 and E85 exempted (§ Kill confirmation, `runFPSI`). Revised again on
2026-10-13: the counts were recounted mutant by mutant from the raw cargo-mutants
outcomes (a ledger of all 1 848 mutants, an internal record), the kill records were
checked against the final commit `cf2414e`, and open item (a) states the research
on 742:24, including a proof (R1) that removes every run with a throwaway from it.

## Scope

Run G picks up what run F left (decision "Run F stopped") and the consensus code
added after run E. It ran from 2026-10-10 to 2026-10-12, one batch at a time, in this
order: the pilot, G9, G2, G5, G4, G6, G10, G3, G7.

| Batch | Code |
|---|---|
| Pilot | G1 below; the RX-SALT part of G3 (`R2`); the first 20 mutants of G2 (`runG2`, 05b2ef2: 20 caught; superseded by G2) |
| G1 | `consensus/src/header.rs` whole and the consensus diff after run E (`chain.rs`, `genesis.rs`, `hash.rs`, `params.rs`, `pow.rs`: the 172-byte header, the mining hash and blob, `pow_meets`, `ChainParams::check`, `RandomXPow::pow_hash`) |
| G9 | `chain/src/manager/pow_cache.rs` and `template.rs` whole, `Template::outputs_after`, `miner/src/lib.rs` `build_block` |
| G2 | `tx/src/mmr.rs` whole (the output range of B-OMR); the diff of `tx/src/px.rs`, `state.rs`, `validate.rs` (B-PXR, PX-R `check_ciphertext_r`, the deploy row caps) |
| G5 | `zk/src/config.rs`, `params.rs`, `lib.rs` but `decode_proof` and `analysis::` (the verifier, prover checks, challenger, grinding, security parameters) |
| G4 | the diff of `px/src/prove.rs` and `px/src/state.rs` (the per-function cycle limit, `root_after`) |
| G6 | `chain/src/manager/replay.rs` whole; `chain/src/store.rs`: its diff and `operator_records`, `next_valid_record`, `parse_frame`, `decode_body`, `valid_prefix` |
| G10 | `zkvm/src/exec.rs`, `program.rs`, `prove.rs` whole (the ELF loader and layout rules are consensus rules: every deploy runs `Program::from_elf`, `tx/src/px.rs` `load_programs`) |
| G3 | R1: `randomx/src/vm.rs` and `superscalar.rs` whole (the interpreter rewrite); R2: the RX-SALT diff (`argon2d.rs`, `config.rs`, `dataset.rs`, `lib.rs`, `self_test.rs`) |
| G7 | `node/src/fingerprint.rs` and `px/src/fingerprint.rs` whole |

Not in run G:

- **G8**, the supply audit (`tools/supply-audit`): deferred to before the trial.
- **Outside the gate** (a post-freeze campaign): p2p relay and DoS, PX delivery,
  decoy selection, the mempool.
- The rest of `randomx/` outside R1 and the R2 diff, the rest of `zk/src/lib.rs`
  (`decode_proof`, `analysis::`; run D covered the decode bounds), and of
  `chain/src/store.rs` (run F).

Run F's chain results that the overload invalidated are not reused: G6 censused
`replay.rs` and the store functions again from the start.

## Method

- **Tool:** cargo-mutants 27.1.0, `--profile mutants` (the root Cargo.toml: the test
  profile with overflow checks and debug assertions on), `--cap-lints true`,
  `--build-timeout 2400`, `--jobs 2` for first stages, `--jobs 1` for timeout re-runs
  and checks. Toolchain rustc 1.98.1 (x86_64-pc-windows-msvc). `CARGO_BUILD_JOBS=2`,
  `CARGO_INCREMENTAL=0`, `CARGO_TARGET_DIR` unset (cargo-mutants builds in its own
  copy), `TMP` in a per-batch directory.
- **Selection:** whole files with `-f`, a diff with `--in-diff`, or a list of mutant
  names as anchored `--re` filters (one per name, every character but a letter, digit
  or space escaped). The selections were checked with `--list` (the lists are internal
records).
- **Two-stage oracle.** Stage 1: the cheap tests that reach the code. Stage 2: the
  stage-1 survivors against every remaining test target that fits in memory (G5 and
  G10 have a stage 3 across packages; G3 has a stage 2b against
  `consensus/tests/golden.rs`). A mutant is missed only if it survives every stage.
- **Cross-package stages** use `--test-package` with `--baseline skip` (the tool's own
  baseline cannot run another package's `--test` targets). Every catch in such a stage
  was confirmed by the failing test's name in the mutant's log, not by the exit code
  alone.
- **Memory guard.** A guard process watched every cargo-mutants run: every 5 s it
  stopped, by PID, any process of the batch's copy whose working set exceeded 4 GB,
  and logged peaks and free memory. A guard stop makes the tool record "caught". Each
  guard-stopped catch was re-run alone under an oracle that cannot reach the memory
  limit: G6's three (`runG6v`: all three caught by assertions) and G5's two
  (`runG5v`: `lib.rs:232:17` `-=` → `/=` caught by
  `schedule_tests::known_schedules`; `-=` → `+=` was **voided** and counted as a
  timeout, since its schedule grows without bound). The guard does not watch
  `rustc`: px `fingerprint.rs:553:11` `+=` → `*=` (a const evaluation that never ends)
  ran rustc unguarded at 0.02 GB free for 38 min before its build timeout.
- **Environment-failure scan.** Every mutant log of every run was searched for
  `0xC0000142`, `os error 1455` and `0xC0000409` (the run F overload signatures): none
  in any run.
- **Timeouts** were re-run alone at `--jobs 1` with a longer limit (`runG9s2t`,
  `runG5t`, `runG6t`, `runG3t`, `runR2t`) to separate a hang from a slow run. A timeout
  counts as detected in the first score; the second score counts catches only.
- **Scores:** (caught + timeout) / viable, and caught / viable. Viable = mutants −
  unviable.
- **Known tool quirks.** `delete field` mutants are not filtered by `--re`; they ride
  along in re-runs and are not counted there (G3 `superscalar.rs:292:13`, G7's three,
  G5's four `analysis::quotient_chunks` field deletions, which are in G5's first-stage
  count because `--exclude-re` does not filter them either; G4's kill check picked up
  `px/src/prove.rs:104:5` `delete field max_instances`, outside G4's diff: not counted,
  not classified here). cargo-mutants 27.1.0 makes no `>=` → `>` and `<=` → `<`
  mutants (run C's boundary pass is not repeated in run G). A mutant that makes a
  `const` evaluation loop forever shows up as a build timeout.

## Result in brief

| Batch | Base | Mutants | Unviable | Viable | Caught | Timeout | Missed | (c+t)/v | c/v |
|---|---|---|---|---|---|---|---|---|---|
| G1 | `05b2ef2` | 27 | 1 | 26 | 24 | 0 | 2 | 92.3% | 92.3% |
| G9 | `05b2ef2` | 98 | 10 | 88 | 79 | 5 | 4 | 95.5% | 89.8% |
| G2 | `a36d68c` | 116 | 4 | 112 | 111 | 0 | 1 | 99.1% | 99.1% |
| G5 | `a36d68c` | 167 | 23 | 144 | 113 | 8 | 23 | 84.0% | 78.5% |
| G4 | `9e3983e` | 20 | 2 | 18 | 15 | 0 | 3 | 83.3% | 83.3% |
| G6 | `9e3983e` | 186 | 15 | 171 | 144 | 6 | 21 | 87.7% | 84.2% |
| G10 | `a652275` | 304 | 7 | 297 | 266 | 0 | 31 | 89.6% | 89.6% |
| G3 R1 | `f7ccd19` | 715 | 17 | 698 | 631 | 16 | 51 | 92.7% | 90.4% |
| G3 R2 | `05b2ef2`, re-checked at `f7ccd19` | 53 | 19 | 34 | 31 | 1 | 2 | 94.1% | 91.2% |
| G7 | `90be46f` | 162 | 19 | 143 | 120 | 1 | 22 | 84.6% | 83.9% |
| **Total** | | **1 848** | **117** | **1 731** | **1 534** | **37** | **160** | **90.8%** | **88.6%** |

G3 together: 768 mutants, 732 viable, 662 caught, 17 timeouts, 53 missed: 92.8% and
90.4%; 97.8% excluding the 38 equivalents shown from the code (E76 to E80), 98.3%
excluding all 41 (with E81 and E82).

What the columns are, and are not:

- **Unviable** (117): the mutated code does not build. Not a kill and not a survivor.
- **Timeout** (37): a genuine hang or an unbounded run, re-run alone with a longer
  limit (§ Method) and still not finished; not re-run: G5's voided guard stop and
  G7's px `fingerprint.rs:553:11` (a build timeout, a const evaluation that never
  ends). Counted as detected in the first score only, never as caught.
- **Caught**: a test failed under the mutant in one of the batch's stages, with the
  tests at the batch's base. G3 R2's base is the re-check at `f7ccd19`, so its 31
  include 4 pilot survivors caught there by tests the pilot added (`bd5c73d`,
  `runG3a`) and 2 that only the ignored full-mode tests catch (`runG3b`); G1's two
  pilot survivors are counted as missed and killed instead, since G1 was not
  re-checked.
- **Missed** (160): survived every stage. Each is resolved below as killed by a new
  test, exempt, or open.

The 160 survivors:

| Batch | Killed by new tests | Equivalent or log-only (exempt) | Open |
|---|---|---|---|
| G1 | 2 | 0 | 0 |
| G9 | 3 | 1 (E65) | 0 |
| G2 | 0 | 1 (E66) | 0 |
| G5 | 13 | 10 (E67 to E70; E69 on width-1 builds only) | 0 |
| G4 | 2 | 1 (E71) | 0 |
| G6 | 5 | 4 (E72) + 12 log-only (E73) | 0 (one low item on E73's warning, § Open items) |
| G10 | 28 | 3 (E74, E75) | 0 |
| G3 | 2 (R2) + 9 (R1) | 41 (E76 to E82; E82's 2 by a probabilistic argument) | 1 (742:24) |
| G7 | 5 + 11 (fingerprint-sample-inputs) | 6 (E83, E86; E84 and E85 superseded, their 3 mutants are among the 11 killed) | 0 |
| **Total** | **80** | **79** | **1** |

(Before fingerprint-sample-inputs: G7 5 killed, 9 exempt (E83 to E86), 8 open; total
69, 82, 9.)

- **Two security-critical test gaps** were found, each now killed: the RandomX
  IMUL_RCP power-of-two NOP rule (G3) and the store repair's handling of operator
  verdicts past a damaged length field (G6). Neither was a bug in the shipped code:
  the code was right and no test held it.
- **No survivor lets a verifier accept an invalid proof or block**, changes a pinned
  soundness parameter unnoticed, or changes today's fingerprint (per batch below),
  **except possibly the open RandomX mutant** (`superscalar.rs` 742:24): if its state
  is reachable by a run without any throwaway (every run with one is proven
  equivalent), it may generate a different SuperscalarHash program, so a different PoW
  hash, and a node built with it would disagree with reference RandomX on which blocks
  are valid (§ Open items (a)). The shipped code has the reference's loop bound there.
  The two 783:42 mutants, open before, do reach such a state: a key on which they
  change the program is now a reference corpus line, which kills them (§ G3).
- No production line was changed by run G; the killing tests are merged in
  `rebuild/core` up to `dfed6a5`, and the 783:42 corpus line is `a2fbac1` (branch
  `g11/rx783-vector`, tests and test data only). The fingerprint kills
  (fingerprint-sample-inputs, `1a74131`) do change production code, the node's
  manifest construction, not a validity rule, with a re-pin of every fingerprint.

## G1: consensus header and the post-run-E diff (05b2ef2)

Oracle: blacksilk-consensus lib and tests. 2 missed: `params.rs` 228:13 and 229:13
(`||` → `&&` in `ChainParams::check`): each genesis field was only tested together.
Killed by `check_refuses_each_genesis_field_alone` (`b445997`, consensus/src/params.rs).
The unviable mutant is `BlockHeader::pow_blob` → `Default` (no `Default` for the blob).

## G9: PoW cache, template, `outputs_after`, `build_block` (05b2ef2)

Stage 1: chain lib, `pow_pool`, `rt_pow_pool_stress`, `manager`, `output_root`,
`block_rules` (`runG9s1`); miner targets (`runG9m`). Stage 2: run F's chain targets
plus `output_root`, `pow_pool`, `rt_pow_pool_stress` (`runG9s2`): the 6 `template.rs`
mempool-check survivors caught there.

- **Every mutant that could make the cache return a wrong or forged hash was caught in
  stage 1.**
- Test gaps, killed by `e18548d`:
  - `pow_cache.rs:289:26` `<` → `==` and `<=` in `HashPool::start`: a false "helper
    thread ended" error log at every start. Killed by
    `starting_the_pool_logs_no_error_when_no_helper_ended` (chain/tests/pow_pool_log.rs).
  - `miner/src/lib.rs:56:37` `+` → `-`: the coinbase paid the reward minus the fees, a
    block the node refuses with `CoinbaseAmount` (the miner would lose every block with
    fees). Killed by `the_coinbase_pays_the_reward_plus_the_fees`.
- Equivalent: `pow_cache.rs:289:26` `<` → `>` (E65).
- Timeouts (5: `Batch::work` → `()`, its counter `+=` → `*=` and `==` → `!=`,
  `Batch::wait` `<` → `==` and `<=`): real deadlocks (no job done, or a notification
  lost), still timeouts alone (`runG9s2t`). None changes a stored hash.
- Gap noted (open, § Open items): the pool tests have no internal deadline, so a
  deadlock is a hung run, not a failed test.

## G2: output MMR, B-PXR, PX-R and deploy caps (a36d68c)

Stage 1 (`runG2s1m`, `runG2s1d`): tx lib and the non-proving targets of
`G2-s1.tests` (`output_mmr_vectors`, `block_pipeline`, `chain_integration`,
`validation_order`, `mutation_regressions`, `deploy_rules`, `px_proof_wiring`,
`px_window`, `state_accessors`, `revalidate_after_extension`,
`output_key_uniqueness`, `tree_capacity`). Stage 2 (`runG2s2`): every non-PX-proving
tx target and G9's chain set plus `block_malleability`, `mempool_stateful`,
`reference_model`, `fuzz_block`.

- `validate.rs:1374:23` (the `px_root` guard → `true`, B-PXR) survived stage 1 and was
  caught in stage 2 only by the chain `output_root` tests. A tx-level test was added:
  `b_pxr_a_header_px_root_one_bit_off_is_refused` (`a550e82`,
  tx/tests/mutation_regressions.rs).
- Equivalent: `mmr.rs:186:18` `<` → `<=` in `OutputMmr::truncate` (E66).

## G5: zk config, verifier and parameters (a36d68c)

Stage 1 (`runG5s1`): zk lib and `pins`, `soundness_calc`, `decode_bounds`, `proofs`,
`upstream_advisories`, `field_mutations`, `grinding`. Stage 2a (`runG5s2a`): every zk
target. Stage 2b (`runG5s2b`): px `consensus_fingerprint`, `proof_limits`, tx
`px_proof_wiring`. Stage 3 (`runG5s3`): zkvm `alu` (a 2^16-row table at its height
limit).

- Oracle note: blacksilk-zk has no pinned proof-byte fixtures; every verify test
  proves toy statements. (Added 2026-10-14, after this run: node/tests/px_tamper.rs
  now sweeps single-bit changes of the golden PX transfer fixture's pinned proof,
  verify only; a later run can use it as an oracle for the verifier paths,
  docs/STATUS.md golden-fixture row.)
- **No survivor lets the verifier accept an invalid, forged or non-canonical proof,
  or changes a soundness parameter without a pin failing.**
- Test gaps (13 survivors, plus 5 mutants that only stage 3 caught), killed by
  `627ad70` (zk/tests/proofs.rs) and `690cd72` (zk/tests/soundness_calc.rs):
  - the at-limit heights, `lib.rs` 172:66 `+` → `-` and `*`, 173:50 `>` → `>=`,
    114:48 `>` → `==` and `>=`: **a liveness gap**, honest PX proofs at their height
    limit would be refused; only zkvm `alu` caught them. Now
    `tables_exactly_at_their_height_limit_prove_and_verify`;
  - `prove` and `verify` count and height checks one at a time (`lib.rs` 101:9,
    102:9, 103:9, 114:41, 157:15, 157:36, 163:9, 164:9 `||` → `&&`):
    `prove_refuses_each_count_mismatch_alone`,
    `prove_refuses_each_height_violation_alone`,
    `verify_refuses_each_count_mismatch_alone`. 163:9 is an out-of-bounds panic
    outside `catch_unwind`, a denial of service through a direct `zk::verify` call
    only (the consensus path pins `degree_bits` first);
  - `lib.rs:634:21` (`analysis::quotient_chunks`, `preprocessed_width`):
    `quotient_chunk_analysis_matches_real_proofs`;
  - `params.rs` 213:65 and 232:48 (`+` → `-`, `*`: the committed domain of the
    security figures): `the_security_figures_are_computed_on_the_committed_domain`.
- `lib.rs:637:21` (`num_periodic_columns`) is caught by the existing px
  `proof_limits` (stage 2b; checked by the lead).
- Equivalent (10): E67, E68, E69 (width-1 builds only; killed on aarch64, § Open
  items (f)), E70.
- Timeouts (8, still timeouts alone, `runG5t`): `smallest_pow_witness` scans of the
  whole field or endless loops (250:64 `*`, 254:26 `==`, `>`, 254:63 `|`, `^`, 258:15
  `*=`), `VerifierConfig::for_statement` → `Default` (infinite recursion), and the
  voided guard stop `lib.rs:232:17` `-=` → `+=` (an unbounded schedule).

## G4: px prove and state diff (9e3983e)

Stage 1 (`runG4s1`): px lib, `consensus_fingerprint`, `proof_limits`,
`kernel_budget`. Stage 2a (`runG4s2a`): px `state`, `fri_schedule`, `elf_paths`,
`mutation_regressions`, `kernel`, `fuzz`; tx `px_proof_wiring`, `px_io_limits`,
`deploy_rules`. px `unified` needs more than 7 GB and was not run; px `proof` cannot
reach the function loop.

- Test gap: `prove.rs` 301:20 (the trap guard → `true`) and 302:21 (`&&` → `||`): a
  trap other than the cycle limit was reported as `OverBudget` instead of
  `Execution` (a prover-side error only). Killed by
  `a_function_trap_other_than_the_cycle_limit_is_an_execution_error` (`b4781ed`,
  px/tests/kernel_budget.rs); confirmed by `runG4k1` (2 of 2 caught).
- Equivalent: `prove.rs:302:38` `<` → `<=` for every deployable budget (E71).

## G6: chain store and replay (9e3983e)

Stage 1 (`runG6s1`): chain lib, `storage_recovery`, `store_format`, `fuzz_store`,
`operator_invalidation`, `rt_w3_regressions`, `actor_equivalence`, `manager` without
`restart_rebuilds_the_px_state_exactly` (3.6 GB and 825 s alone). Stage 2
(`runG6s2`): every chain target but that test, plus node lib, `halt_exit` and
`node_binary`: `replay.rs:662:5` (`full_hex`) caught there.

- **SECURITY-CRITICAL TEST GAP:** `store.rs:968:25` `==` → `!=` in `operator_records`:
  the repair would follow a damaged length field and drop operator verdicts (the
  RTW3-7 class: the node could reconnect a block the operator invalidated). Killed by
  `repair_keeps_the_operator_records_past_a_damaged_length_field` and
  `repair_ignores_a_frame_inside_a_damaged_last_record` (`969d5a9`, chain/src/store.rs).
- Other test gaps, killed by `969d5a9` and `cc6926b` (chain/tests/manager.rs):
  - `replay.rs:243:24` `+` → `-`: an overflow panic at start when there are more
    verdict markers than checkpoints: `a_store_with_verdict_markers_and_no_checkpoint_opens`;
  - `replay.rs` 446:36 (guard → `true`) and 446:54 (`&&` → `||`): a block stored twice
    was refused, so the node could not restart:
    `a_block_stored_twice_around_its_parent_restarts_under_every_check`;
  - `store.rs:339:28` `<` → `<=` in `decode_body`:
    `a_block_record_of_the_pow_hash_alone_loads_with_empty_block_bytes`.
  - Confirmed by `runG6k1` and `runG6k2` (5 of 5 caught).
- Equivalent (4): `store.rs` 912:15, 939:15, 969:33, 971:81 (E72, as E63 and E64).
- Log lines only (12): E73 (as E12 and E33), among them `log_operator_verdicts` → `()`
  (§ Open items).
- Timeouts (6, `next_valid_record` 985:5 ×2, 989:12 ×2, 993:12 ×2): re-run alone
  (`runG6t`); five fail assertions in their logs before hanging, `993:12` `*=` is an
  infinite loop.

## G10: zkvm executor, loader and prover glue (a652275)

Stage 1 (`runG10s1`): zkvm lib, `interpreter`, `guest`, `circuit_id`,
`circuit_fingerprint`, `alu`, `vm` and `multi` without their heavy proving tests.
Stage 2 (`runG10s2`): every zkvm target at `--test-threads=1` (8 caught: the 7
`prove.rs` survivors, so `prove.rs` is 19 of 19, and `program.rs:172:72`). Stage 3 (`runG10s3`): px `kernel`,
`kernel_budget`, `elf_paths`, `fuzz`, `proof_limits` and tx `deploy_rules` (none
caught).

- **No confirmed security issue in the shipped code.** The loader and layout rules
  are consensus rules, and no test held most of them one at a time.
- Test gaps, killed by `310f50b` (zkvm/tests/elf_loader.rs, one fault at a time) and
  `017dd82` (zkvm/tests/interpreter.rs, vm.rs); confirmed by `runG10k` (28 of 28
  caught):
  - `program.rs` `from_elf`: the magic (82:27 `||` → `&&`; 82:22 `<` → `==`, a panic
    on short input), the identification bytes (85:39), the program-header entry size
    and count (103:28, 103:42, 103:51 `==` and `>=`), the code segment's alignment
    and bss (136:21, 137:21), a writable segment below the code (162:45 `==`, `>`),
    `memsz` below `filesz` (124:33); `u16_at` and `u32_at` (44:20, 50:20, a panic on a
    small `phoff`);
  - `program.rs` `validate`: the code word limit (173:33; 173:52 `==` and `>=`), the
    code end against the stack region (176:96 `+`, `/`), the data segment count
    (183:28 `==`, `>=`), the data byte limit (192:19, 195:18 `==`, `>=`);
  - `exec.rs`: `check_addr` at its boundaries (179:17, 182:26: under the mutant the
    executor would refuse one address at the boundary that the AIR accepts; the AIR,
    `air/cpu.rs` 319 to 342, enforces
    `addr ≥ 0x1000` and a store address `≥ CODE_END`, and proving and verifying at
    both boundaries shows they agree), the input word limit (433:20 `==`, `>=`).
  - The `>=` mutants at a limit and the `check_addr` ones only refuse honest inputs at
    their edge (liveness); the others accept a malformed program or panic. The lead's
    summary counts 20 security-relevant and 8 liveness-only; its two lists overlap
    (162:45 `>` is in both), so this document lists the mutants by rule instead.
- Equivalent (3), each surviving the new tests (`runG10keq`): `exec.rs:288:57` (E74);
  `program.rs` 162:45 `<` → `<=` and 82:22 `<` → `<=` (E75).

## G3: RandomX (R1 at f7ccd19; R2 at 05b2ef2, re-checked at f7ccd19)

R1 stage 1 (`runG3s1`): randomx lib and `equivalence` (every official and BlackSilk
light vector, SuperscalarHash, dataset and AES vectors, compiled-against-reference
programs, the FPU directed tests, pinned digests, the reference corpus). Stage 2
(`runG3s2`): the same with `--include-ignored` (the 10^7-per-op FPU oracle, the
256-hash pinned digest), but the full-mode tests. Stage 2b (`runG3s2b`):
consensus `golden` (the known answer on a mining blob). R2: the pilot (`runR2`),
part A at f7ccd19 (`runG3a`), part B with the two ignored full-mode tests
(`runG3b`).

- **SECURITY-CRITICAL TEST GAP:** `superscalar.rs` 60:5 (`is_zero_or_power_of_2` →
  `false`), 60:7 `&` → `|` and `^`: an IMUL_RCP with an immediate of 0 or 2^k is no
  longer a NOP, so the hash changes (concrete input "G3 rcp probe 26476422", key
  "test key 000": `344e1255…` against `e7ebcd8c…`; about once in 2 million hashes; an
  immediate of 0 panics). The reference tevador/RandomX v1.2.3 with BlackSilk's salt
  (interpreter, JIT and auto) gives `344e1255…`, the same as ours. Killed by the truth
  table `zero_and_powers_of_two_are_recognised`, the vm test
  `imul_rcp_by_zero_or_a_power_of_two_is_a_nop` (`34a2842`) and a new reference
  corpus line (`9a8c5f2`, randomx/tests/data/randomx-reference-light-v1.txt, read by
  `equivalence`); the corpus test alone catches it.
- Scheduler contract tests (`34a2842`) kill 656:60, 664:28, 686:5 and 718:5
  (`the_port_map_spans_the_latency_plus_four_cycles`,
  `a_uop_is_never_scheduled_past_the_map`, `a_saturated_map_fails_with_minus_one`,
  `a_macro_op_on_a_saturated_map_fails_with_minus_one`).
- R2: `bd5c73d`'s tests (`salt_validator_*`, `the_start_up_self_test_does_the_work`)
  kill `config.rs` 27:5, 31:13 ×2 and `self_test.rs:287:5` (`runG3a`); the ignored
  full-mode tests catch 304:44 and 363:24 (`runG3b`); `a1f28b9`'s
  `the_full_mode_check_detects_a_wrong_answer` and
  `the_dataset_check_rejects_another_cache` kill `self_test.rs` 295:5 and 356:5. The
  R2 timeout, `config.rs:35:11` `+=` → `*=`, is a build timeout (a const evaluation
  that never ends: it cannot ship).
- Equivalent: 38 shown from the code (E76 to E80); `706:28` (E81); 782:41 and 807:41
  by a probabilistic reachability argument (E82).
- **Security-critical test gap, killed after the run** (the mutants change the PoW
  hash, like 60:5 and 60:7): 783:42 `throw_away_count += 1` → `-=` and `*=`
  (the source-throwaway counter). Under the key `727872656163683119d820` followed by
  21 zero bytes ("rxreach1", 2152473 as a little-endian u64, 16 zero bytes),
  SuperscalarHash program 2 of 8 throws an IMUL_R away for want of a source; the next
  IMUL_R may then chain a multiply (`throw_away_count > 0`), so its candidate
  destinations are r0 and r5, and under either mutant r0 only. One `u32` draw fewer
  shifts the generator's stream, and programs 2 to 7 differ. "This is a test" hashes
  to `95a05dbf…034a` here and in the reference (tevador/RandomX v1.2.3 with
  BlackSilk's salt, `kat-corpus` driver; interpreter, JIT and auto modes alike,
  re-run 2026-10-13), and to `5640debc…22a1` under both mutants. The key came from a
  search over 4 million keys (32 million programs: 17 IMUL_R source throwaways, 1 of
  them changing the program under the mutants). Killed by corpus line 26 (`a2fbac1`,
  the second entry of `targeted_cases()` in `randomx/tests/equivalence.rs`); kill
  check `runG3k783` (§ Kill confirmation).
- **OPEN (1 mutant):** 742:24, § Open items (a).
- Timeouts (R1: 16 still time out alone at 300 s, `runG3t`, where 5 others were
  caught): the generator (`superscalar.rs` 34:9, 36:20, 41:9 ×2), 60:5 → `true` (the
  IMUL_RCP immediate loop never ends), the cycle counters (684:15, 716:15, 804:29 ×2),
  `ri` (`vm.rs` 35:5 ×2, 35:16), the CBRANCH immediate (485:46, 487:20, 488:48) and the
  program counter (901:16).

## G7: the node and px fingerprint modules (90be46f)

Stage 1 (`runG7s1node`, `runG7s1px`): the fingerprint pin tests (node lib,
`deploy_configs`, `px_fixture`, `fingerprint_fixture`, `info_identity`; px lib,
`consensus_fingerprint`). Stage 2: every node target (`runG7s2node`); the cheap px
targets and every node target (`runG7s2px`: 4 caught).

- **No survivor changes today's fingerprint or makes it differ across honest
  builds.**
- Test gaps, killed by `5189c98` (`i_appends_one_signed_entry`: px 78:9
  `Manifest::i`), `9931b2e` (`fixture_parsers_skip_blank_lines`: node 721:17,
  788:17), `2e8410f` (node/tests/px_fixture.rs: `an_unknown_anchor_is_refused`, node
  868:9 `px_is_recent_root`; `a_bridge_out_above_the_pool_is_refused`, node 874:9
  `px_pool`).
- Equivalent (9 at the run): E83 to E86; 6 after fingerprint-sample-inputs (E83,
  E86; E84 and E85 are superseded).
- **STRUCTURAL WEAKNESS (8, open at the run; killed by fingerprint-sample-inputs,
  `1a74131`, together with the exempt 480:48, 1007:58 and 1253:54):** § Open items (b).
- Timeout: px 553:11 `*=` (a const evaluation that never ends: a build timeout).

## Kill confirmation

**Every one of the 80 killed mutants has a kill record after its test landed:** 67 in
the confirmation run `runGconf` (at `dfed6a5`), 2 in `runG3k783` (at `a2fbac1`) and
11 in `runFPSI` (at `1a74131`), the 11 re-run again at the final commit `cf2414e`
(below), as are the four node kills of `runGconf` (`runGnode-cf2414e`, below). Between `dfed6a5` and `cf2414e` the only changed files are
node/src/fingerprint.rs, node/tests/deploy_configs.rs, randomx/tests/equivalence.rs,
randomx test data and randomx/README.md (`git diff --stat dfed6a5 cf2414e`), and
randomx/ is unchanged from `a2fbac1` to `cf2414e`. So the 63 `runGconf` kills outside
node and the two 783:42 kills stand on the same crate source at `cf2414e`, with the
killing tests unchanged or only appended to. The four node kills of `runGconf`
(721:17, 788:17, 868:9, 874:9 at `dfed6a5`) sit in a region that is textually
identical at `cf2414e` (lines 705 to 880 then, 889 to 1064 now), but the rest of
node/src/fingerprint.rs changed, so they were re-run at `cf2414e`: `runGnode-cf2414e`
(2026-10-13, a detached worktree at `cf2414e`, cargo-mutants 27.1.0, `--profile
mutants --cap-lints true --jobs 1`, `-p blacksilk-node -f node/src/fingerprint.rs`,
anchored `--re`, oracle `--lib --test px_fixture`): **4 of 4 caught**, 0 missed, 0
timeouts, environment-failure scan clean. 905:17 and 972:17 (`delete match arm []`
in `Fixture::parse` and `PxFixture::parse`) fail `fixture_parsers_skip_blank_lines`;
1052:9 (`px_is_recent_root` → `true`) fails `an_unknown_anchor_is_refused`; 1058:9
(`px_pool` → 1) fails `a_bridge_out_above_the_pool_is_refused`. The three `delete
field` mutants (1228:9, 1296:21, 1308:21) rode along: caught, not counted. In sum,
15 kills have a run at `cf2414e` itself (the 11 fingerprint-sample kills and these
4); the other 65 were run at `dfed6a5` or `a2fbac1`, on crate source identical at
`cf2414e`.

The confirmation run (`runGconf`, at `dfed6a5`, 2026-10-12 16:15 to 2026-10-13 01:17,
9 h 02) re-ran all 67 kills made before it, one package at a time (consensus, miner,
node, px, chain, zk, randomx, zkvm), against each batch's union oracle plus the new
targets: **67 of 67 caught**, 0 missed, 0 timeouts. The environment-failure scan was clean, and the memory
guard (which this time also watched `rustc` and would abort below 1 GB free) stopped
nothing. The per-mutant outcomes and failing test names are in `runGconf-summary.txt`.

- 8 unrequested `delete field` mutants rode along (node 1023:9, 1091:21, 1103:21; px
  `prove.rs:104:5`; zk `lib.rs` 635:21, 636:21, 637:21; randomx `superscalar.rs:292:13`):
  all caught, not counted.
- Cross-package runs used `--baseline skip`, with each catch confirmed by the failing
  test's name.
- cargo stops at the first failing test binary, so a later killing target is not
  always reached: for example the randomx 60:x mutants failed in the lib tests before
  the `equivalence` corpus test ran. The record names the tests that did fail.
- zk doctests were not run; no killing test is a doctest.

**The two kills added after it** (783:42 `-=` and `*=`) have their own record,
`runG3k783` (2026-10-13, at `a2fbac1`, `--jobs 1`, oracle `--test=equivalence`):
both caught by `reference_corpus`, each with "1 of 10 reference answers differ" and
`reference=95a05dbf…034a ours=5640debc…22a1` for the new corpus line. In the same
run 742:24 `<=` was missed (all 4 `equivalence` tests pass), as expected; the
unrequested `delete field` mutant `superscalar.rs:292:13` rode along (caught, not
counted).

**The fingerprint kills** have their own record, `runFPSI` (2026-10-13, at
`1a74131`, cargo-mutants 27.1.0, `--profile mutants --cap-lints true --jobs 1`,
`-p blacksilk-node -f node/src/fingerprint.rs`, anchored `--re`, oracle `--lib --test
deploy_configs --test px_fixture`): **11 of 11 caught**, 0 missed, 0 timeouts. Line
numbers moved with the change; the mapping (run G line at `90be46f`, the same at
`85a8753` → line at `1a74131` and at `cf2414e`, same function and expression) and the
failing tests in `runFPSI`:

| Run G | `1a74131` | `cf2414e` | Mutation | Caught by |
|---|---|---|---|---|
| 318:28 | 352:11 | 352:11 | `chain_entries`: `seed_epoch + seed_lag` (`e + l`), `+ → -` | `samples_are_the_golden_values` |
| 458:44 | 500:36 | 500:36 | `chain_entries`: `MONEY_SUPPLY - COIN`, `- → +` | `samples_are_the_golden_values` |
| 480:48 (E84) | 528:48 | 528:48 | `rule_samples`: `(i + 1) * 1_000_000`, `+ → *` | `samples_are_the_golden_values` |
| 482:12 | 530:12 | 530:12 | `rule_samples`: `ts[11] -= 1_300`, `-= → /=` | `samples_are_the_golden_values` |
| 1007:58 (E85) | 1216:58 | 1207:58 | `compute_transaction_samples`: `plus_g`, `+ → -` | `consensus_fingerprints_are_pinned` |
| 1023:36 | 1259:36 | 1228:36 | `compute_transaction_samples`: `rules.branch_id ^ 1`, `^ → &` | `every_verdict_variant_records_a_distinct_input` |
| 1194:47 | 1481:47 | 1504:47 | `px_transaction_samples`: `ciphertexts[0][31] \|= 0x80`, `\|= → &=` | `consensus_fingerprints_are_pinned` |
| 1208:52 | 1495:52 | 1518:52 | `px_transaction_samples`: `bridge_in += 1`, `+= → -=` | `consensus_fingerprints_are_pinned` |
| 1218:42 | 1505:42 | 1528:42 | `px_transaction_samples`: `proof.len() / 2`, `/ → %` | `consensus_fingerprints_are_pinned` |
| 1251:51 | 1543:51 | 1569:51 | `px_transaction_samples`: `programs[0].abi += 1`, `+= → -=` | `consensus_fingerprints_are_pinned` |
| 1253:54 (E85) | 1545:54 | 1571:54 | `px_transaction_samples`: `salt[0] ^= 1`, `^= → &=` | `consensus_fingerprints_are_pinned` |

At `cf2414e` the independent re-check (`evidence-p1-cf2414e`, `runTargets`, same tool,
flags and oracle) caught all 11 at the lines of the third column, with the three
`delete field` mutants riding along (caught, not counted).

Three unrequested `delete field` mutants rode along (1259:9 `branch_id`, 1327:21
`spent`, 1339:21 `missing`): all caught, not counted. The new code's own mutants were
swept too, over every mutant on the changed lines of node/src/fingerprint.rs (same
tool, flags and oracle): the red team's sweep at `1b7191b`, 60 mutants, 59 caught,
1 unviable (1388:9 `Sampled::of -> Default`), 0 missed (internal record, not in the
repository); and after the red-team hardening, the re-listed sweep at `cb2f58a`
(`runFPSIsweep`), 67 mutants, 66 caught, 1 unviable (1411:9, the same mutant), 0
missed. A scratch mutation of
consensus/src/pow.rs `seed_height` (the dropped `- 1`, never committed) fails
`samples_are_the_golden_values`: the keys at 2E + L = 4 160 and 10E + L = 20 544 move
from 2 048 and 18 432 to 4 096 and 20 480, while the five heights sampled before are
unchanged. Internal records (`runFPSI`, `runFPSI-summary.txt`,
`seed-minus1-mutation.txt`, `runFPSIsweep`) are in the lead's scratch area (`C:/bszkeval/g11-scratch/fpsi/`).

**E69 on aarch64.** E69's two mutants (`config.rs` 250:64 and 253:35) are killed on
aarch64 (CI job `arm64`, run 38521517518 at `16d4fe9`, § Open items (f)) but remain
exempt on width-1 x86_64 builds, where they are equivalent. x86_64 is a supported
target, so they stay counted among the 79 exempt: the counts (80 killed, 79 exempt,
1 open) do not change.

Earlier kill checks, kept for the record: `runG4k1`, `runG6k1`, `runG6k2`, `runG10k`
(and `runG10keq`, the equivalents' survival), `runG3a`, `runG3b`.

## Open items

These are stated as open. None is exempt.

- **(a) RandomX `superscalar.rs:742:24` (1 mutant): neither killed nor shown
  equivalent. OPEN.** `decode_cycle < SUPERSCALAR_LATENCY` → `<=` runs one more
  decode cycle when the loop reaches decode cycle 170 before the ports saturate. (The
  two 783:42 mutants listed here before are killed, § G3.) Line numbers in this item
  are randomx/src/superscalar.rs at `cf2414e`, the same as at `f7ccd19`, the batch's
  base (only test modules were appended since).
  - **The shipped code agrees with the reference here.** The reference
    `superscalar.cpp` (tevador/RandomX v1.2.3, line 678) has the identical loop bound,
    `decodeCycle < RANDOMX_SUPERSCALAR_LATENCY && !portsSaturated && programSize <
    SuperscalarMaxSize`, and the same loop body. The mutant differs from both only in
    one state, m1: the top of the loop at decode cycle 170, ports unsaturated, fewer
    than 512 instructions.
  - **R0 (from the code, as E77):** at most 510 instructions exist before the ports
    saturate. Each instruction commits at least one macro-op that is not eliminated
    into a free (cycle, port) slot (`schedule_uop` writes a slot only where it is 0,
    662 to 687), and every commit while the ports are unsaturated is below cycle 170
    (837 to 838), so at m1 `program.len() ≤ 3 · 170 = 510`; the size bounds (744,
    753) decide nothing there.
  - **R1 (proof, deterministic): on every run that reaches m1 after at least one
    throwaway (or a null break, which needs 256 of them), the mutant's extra pass
    draws nothing and pushes nothing, so it is equivalent there.**
    1. `cycle` never falls below its value at the start of an inner pass: it changes
       only at 778 and 803 (+1 per failed try), at 840 (back to `top_cycle`, taken at
       750) and at 847 (+1, with `decode_cycle`). A throwaway (782 to 785, 807 to 810)
       follows four failed tries (+4) and its `continue` skips 840. So after the first
       throwaway `cycle ≥ decode_cycle + 4` at every top of the outer loop, and at m1
       `cycle ≥ 174`.
    2. Then the pass of decode cycle 169 did not end by filling its buffer: its last
       commit would have started from `top_cycle ≥ 173`, so been scheduled at 173 or
       later, and 837 to 838 would have saturated the ports. It did not end at 753 to
       754 either (that needs saturation or 512 instructions, R0), nor at 767 to 769
       or 820 to 822 (both saturate). So it ended at 787 to 788 or 812 to 813, the
       null break after 256 consecutive throwaways, with `current` the NOP. This
       holds too when the first throwaway falls inside the pass of decode cycle 169
       (`cycle ≥ 169` at its start, so `≥ 173` after it): a commit that fills the
       buffer ends the pass, so it comes after that throwaway and starts from
       `top_cycle ≥ 173` (750; the `continue` skipped 840, and 840 never resets
       below a later `top_cycle`), and `schedule_mop` never returns a cycle below
       its start (689 to 719, 662 to 687), so 837 to 838 or 767 to 769 saturate.
    3. The extra pass: `fetch_next(None, 170, mul_count, gen)` (746; 400 to 420)
       returns `BUF_4444` without a draw (409 to 410), since `mul_count ≤ 170`: each
       multiplication (IMUL_R, IMULH_R, ISMULH_R, IMUL_RCP; 343, 351 to 353) commits
       exactly one uop that needs port P1 (IMUL_RR, MUL_R, IMUL_R_OP; 306, 307, 310),
       each in its own free slot below cycle 170. The NOP has no macro-op, so 756 calls
       `create_for_slot(gen, 4, 4, false)`, which takes IMUL_R without a draw (483),
       and `create` draws nothing for IMUL_R (520 to 525). `schedule_mop(false,
       IMUL_RR, …)` with `cycle ≥ 174` reaches `schedule_uop`, whose loop needs
       `cycle < CYCLE_MAP_SIZE = 174` (656, 664): it returns −1, 767 to 769 set
       `ports_saturated` and break, and the loop ends. No draw, no instruction, no
       register written: the same program, and the same generator state for the next
       programs of the cache (randomx/src/dataset.rs 75 to 77 generates the 8
       programs in sequence from one generator).

    This replaces the probabilistic argument of the earlier revision ("no throwaway
    in the whole program, otherwise at least 211 consecutive equal Blake2 outputs,
    about 2^-6700"). Only runs with no throwaway at all can tell the mutant apart.
  - **R2 and R3 (stated by the research, argument not written out or independently
    reviewed): claimed necessary conditions for m1 with no throwaway.** The research
    record gives each as a one-line result only; no written argument exists, so
    neither is a verified proof; the search pruning and the descent lead below use
    them as assumptions only. Only R0 and R1 are established (R1 checked line by line
    by two reviewers). As stated: every P1 slot of the early cycles holds a
    multiplication uop (the record's N1 and N4; it works with `L(d) = M(d) − d`,
    where M(c) is `mul_count` at the start of decode cycle c, 738 and 844). The
    record's one-line statement says cycles 0 to 169, but the models prune with N1
    on cycles 0 to 168 only (`cycle <= 168` for a commit, `c <= 168` for the P1 slot
    of a finished decode cycle: the record's `m742.rs` 740, 779 and 789, and its
    other models alike); cycle 169 is left to the end windows below, and in case A
    it is fully free. The end of the program is claimed to be forced into one of two
    windows (the record's end windows e = 166 and e = 167): (A) the forced decode
    configuration 3310, with cycle 169 fully free and M(169) = 169, or (B) the
    default configuration 493, with M(169) = 170 and ports P0 and P5 free at cycle
    169. And the hop lemma: a destination-selection failure at a cycle (a one-cycle
    hop that is not a throwaway) of an IMUL_R needs at least 4 ready registers last
    written by an IMUL_R, and of an IMUL_RCP at least 5 ready registers last written
    by an IMUL_RCP.
  - **Negative results: why the search did not close it.**
    - A register-free model of the scheduler (ports, decode configurations,
      multiplication counts, no registers) does reach m1 (a beam witness: a period-2
      pattern after an IMUL_RCP alternating the configurations 493 and 3310). That
      witness needs all 8 registers unavailable for 3 cycles, which the real
      generator cannot give, so registers are essential to any proof; an exhaustive
      register-free search was infeasible anyway (stopped at decode cycle 6).
    - A window model with the full register logic, starting at decode cycle s from
      an unknown history, cannot close it: the unknown history may supply 5
      registers already tagged IMUL_RCP (or 4 tagged IMUL_R), exactly the hop lemma's
      requirement. Its search from s = 165 did not finish its first level (stopped at
      a 6.1 GB working set).
    - A tag model from decode cycle 0 (exact ports and types; registers as latency
      and group, with the parameter comparisons over-approximated) is sound and
      validated, but grows too fast: 9, 2 234, 60 835, 33 530 and 578 346 states at
      the decode boundaries 0 to 4, about 927 million intermediate states at decode
      cycle 4 (1 077 s); stopped. Infeasible at this rate.
  - **Validation of the models:** each agrees with the real generator on 12 001 keys
    (96 008 programs, among them "test key 000"): the register-free model on every
    decision (128 251 871) and state, the full model with Blake2 draws, the window
    model (573 042 windows, 204 529 162 events) and the tag model (74 393 555
    selection attempts).
  - **Searches, none of which reached m1:** 32 million real programs (4 million keys;
    272 without a throwaway, the latest loop exit at decode cycle 168); 1.5 million
    tilted states at decode cycle 169 (importance sampling, 20 million tilted
    programs; neither case's port pattern occurred); beam search and hill climbing;
    adversarial full-model beams (300 and 2 000 wide, forced collision rates 0 and
    30%: many states with no throwaway that meet N1 and N4 at decode cycle
    169, none in case A or B); tag-guided full-model beams (width 1 000). None of
    this is a bound; it is evidence only.
  - **Lead, unproven: a descent argument.** In one case, where decode cycle e − 1 is
    the IMUL_RCP follow-on buffer 493 with an IMUL_RR as the hop, the forced port
    shape repeats one level down: MUL_R must sit at e − 2 and cycle e − 2 must be
    fully free, so the P1 booking at e − 1 was made at decode cycle e − 3 or earlier
    by a multiplication that skipped a free P1 slot at e − 2, that is, another hop,
    with its own register-tag requirement. If every branch descended like this back
    to decode cycle 0, where no register is tagged, the descent would be a proof.
    Not checked: the default-493 case at e − 1, and hops by an IMUL_R from a 4444
    buffer. This is the suggested next step if the research continues.
  - **Status: OPEN. No proof that m1 is unreachable, and no key that reaches it.**
    The shipped code equals the reference (`superscalar.cpp:678`), so this is a
    test-adequacy gap, not a known consensus risk: if m1 were reachable, a node built
    with the *mutant* would compute a different SuperscalarHash program for that key,
    so different dataset items and PoW hashes, and disagree with reference RandomX (a
    consensus split, not a forged proof); the shipped code would not. No direct test
    exists without restructuring production code. **The gate's criterion (zero
    unexplained survivors) is not met.** The owner may either fund further research
    (the descent argument) or formally accept the residual; nothing is accepted yet.
  - The research artefacts (the instrumented copies, the models and their
    validation, the sampling, beam, climbing and search runs, the reference request
    and output) are internal records in the lead's scratch area
    (`C:/bszkeval/g11-scratch/G3/rxreach/` and `G3/rx742/`), not in the repository.
- **(b) The fingerprint manifest records sample outputs, not their inputs (8 G7
  mutants). CLOSED (2026-10-13)** by fingerprint-sample-inputs (`1a74131`; record
  docs/reviews/v3-consensus-changes.md#fingerprint-sample-inputs; decisions
  "Fingerprint sample inputs and D0 as identity"): the rule samples record their inputs
  next to their outputs (exceptions in the record, item 5), the key schedule is sampled at 2E + L and 10E + L, and D0 moved
  to the identity manifest. All eight open mutants and the three exempt ones (480:48,
  1007:58, 1253:54) are caught (`runFPSI`, § Kill confirmation). The analysis as
  written at the run follows. **Criterion:** a sample mutant is open when the mutated sample input no
  longer catches a plausible rule change that the original input catches, even though
  today's rule gives the same verdict or output for both. It is exempt only when no
  plausible rule change tells the two inputs apart (E84, E85). The open ones, node
  `fingerprint.rs`:
  - 318:28 (a key-schedule sample height: a compound off-by-one switching the RandomX
    key one block early);
  - 458:44 (an emission sample: a change of the tail floor);
  - 1194:47 (the PX `R` top-bit sample);
  - 1218:42 (the truncated-proof sample);
  - 1251:51 (the unsupported-ABI sample: the original `abi = 2` catches a relaxation
    to "refuse only `abi < ABI_VERSION`", accepting newer ABIs; the mutated `abi = 0`
    does not);
  - 482:12 (the low-stamp difficulty sample, `ts[11] = 770` instead of `1_000_020`:
    both are lifted by the warm-up or capped at `6T` today, but a rule that leaves a
    stamp unlifted when it lies at most some tolerance low, for a tolerance between
    1 240 s and about 10^6 s, for example 7 200 s, moves only the original sample;
    E84 has the analysis);
  - 1023:36 (the other-branch sample: the original `BRANCH_ID_V3 ^ 1` is `"BSv2"`, so
    it catches a rule accepting the previous version's branch id; the mutated 1 does
    not);
  - 1208:52 (the PX `bridge_in + 1` sample becomes `− 1`: a balance check relaxed to
    an inequality in one direction is caught by only one of them).

  No test can kill them; the
  fix is to encode the sample inputs in the manifest, a manifest and encoding change
  with a re-pin. Related: the key-schedule samples cannot see a lone dropped `-1` in
  `seed_height` (the consensus property tests do). **Pre-freeze decision**, together
  with the D0 placement (G4/TM2-10).
- **(c) G6 `log_operator_verdicts` → `()` (low).** Exempt as log-only (E73), but its
  warning is the operator-facing message of RTW3-11; only a log-capture test can hold
  it.
- **(d) Heavy oracles not run locally.** px `unified` (more than 7 GB; G4, G5, G10), tx
  `px_consensus` and `fuzz_decode` (PX-proving; G2), and
  `restart_rebuilds_the_px_state_exactly` (G6, also skipped in G9 and G2). The
  reasoning that they could not kill a remaining survivor is **not run**: in each of
  those batches every remaining survivor is either equivalent (no test can kill it)
  or log-only (a test without log capture cannot), and G4's two real survivors were
  killed by a light test.
- **(e) The pool tests have no internal deadline (G9):** a deadlock hangs the run
  instead of failing a test.
- **(f) The BabyBear packing-width caveat (G5).** E69 holds only where the BabyBear
  packing has width 1: x86_64 without AVX2 or AVX-512 (the repository sets no target
  feature), as in this run. **It does not hold on a target the project already
  builds:** NEON is a default target feature on aarch64, where `p3-monty-31` 0.7.0
  uses `PackedMontyField31Neon` (width 4), and CI builds on `ubuntu-24.04-arm`. There
  (and on opt-in AVX2 or AVX-512 builds) the two mutants make the prover panic, at an
  underflow or at `grind`'s assertion of the verifier's `check_witness`; they never
  give an invalid proof, since the witness is checked with the verifier's code before
  use. **Resolved for aarch64 (2026-10-14):** on the arm64 runner both mutants are
  killed (CI job `arm64`, run 38521517518 at `16d4fe9`; each fails
  `the_prover_grinds_the_smallest_valid_nonce` and the other four non-ignored
  grinding tests). The width-1 exemption stands for x86_64 builds only; opt-in
  AVX2/AVX-512 x86_64 builds are not run in CI.

- **(g) Verdict samples are derived-`Debug` text (fingerprint, outside this run's
  survivors).** The rules fingerprint's verdict samples are `format!("{:?}")` text of
  `Result<(), TxError>`, whose format the standard library does not guarantee across
  Rust versions. Builds are pinned to 1.98.1 in CI, Docker and the guests; a root
  `rust-toolchain.toml` is ruled out (decisions "Agent 45", per SX2). A local build
  with another toolchain could therefore print another fingerprint (consensus itself
  is unaffected). Follow-up before the freeze: a stable explicit verdict encoding.
  Record: v3-consensus-changes.md#fingerprint-sample-inputs, item 12. **CLOSED
  (2026-10-14)** by v3-consensus-changes.md#fingerprint-stable-verdicts (internal
  red team (2026-10-14): merge with fixes (F1 wording, F2 status), applied; merged
  into rebuild/core after this review): the verdict samples are
  `TxError::fingerprint_text`, a hand-written, exhaustive text equal to the old one
  byte for byte, so no manifest value or pin changed and `Debug` no longer reaches
  the fingerprint.
- **Line numbers.** The G7 mapping (§ Kill confirmation) gives the lines at `1a74131`
  and at `cf2414e`; after the red-team commits (`cb2f58a`) seven of the eleven moved,
  by −9, −31, +23 (three) and +26 (two) lines (independent re-check at `cf2414e`: all
  11 targeted mutants caught; sweep of the changed lines 67 mutants, 66 caught, 1
  unviable; internal record `evidence-p1-cf2414e`).

## Reproduction

- **Code:** a worktree of `rebuild/core` at each batch's base (table above); every
  killing test is merged in `rebuild/core` up to `dfed6a5`, except the 783:42 corpus
  line (`a2fbac1`). No production line changed between the bases and `dfed6a5` or
  `a2fbac1`: the only changes are appended test modules and test data, so the cited
  line numbers hold there.
- **Evidence files are not in the repository.** The confirmation run's
  `runGconf-<package>` directories, `runGconf-summary.txt` and its scripts
  (`runGconf.sh`, `seqGconf.sh`, `memguardconf.ps1`) are internal records, as are the
  run scripts, `--re` argument
  files, mutant lists (`lists/`), diffs (`diffs/`), memory-guard logs and each run's
  `outcomes.json` and logs (`runG1`, `runR2`, `runR2t`, `runG9s1`, `runG9m`,
  `runG9s2`, `runG9s2t`, `runG2s1m`, `runG2s1d`, `runG2s2`, `runG5s1`, `runG5s2a`,
  `runG5s2b`, `runG5s3`, `runG5t`, `runG5v`, `runG4s1`, `runG4s2a`, `runG4k1`,
  `runG6s1`, `runG6s2`, `runG6t`, `runG6v`, `runG6k1`, `runG6k2`, `runG10s1`,
  `runG10s2`, `runG10s3`, `runG10k`, `runG10keq`, `runG3a`, `runG3b`, `runG3s1`,
  `runG3t`, `runG3s2`, `runG3s2b`, `runG7s1node`, `runG7s1px`, `runG7s2node`,
  `runG7s2px`), all in the lead's scratch area with the lead's batch summary. The RandomX reachability probe (8 million programs) and the reference
  RandomX comparison are internal records there too, as are the later reachability
  research on 783:42 and 742:24 (`G3/rxreach/`: 32 million programs, the tilted
  sampling, beam and climbing runs, the reference request and outputs; `G3/rx742/`:
  the models, their validation and searches, `RESULTS.txt`), the `runG3k783` kill
  check, the `runGnode-cf2414e` re-run of the four node kills, and `ledger-runG.tsv`, one line per mutant of the 1 848 (batch, base, the
  outcome in each stage, the final status, the kill record or exemption).
- **Command shape** (stage 1 of G6 shown; the others differ in package, files and
  targets as listed per batch):

```text
cargo mutants -p blacksilk-chain -f chain/src/manager/replay.rs -f chain/src/store.rs $RE \
  --profile mutants --jobs 2 --timeout 600 --build-timeout 2400 --cap-lints true -o <out> \
  -C=--lib -C=--test=storage_recovery -C=--test=store_format -C=--test=fuzz_store \
  -C=--test=operator_invalidation -C=--test=rt_w3_regressions -C=--test=actor_equivalence \
  -C=--test=manager -- -- --skip restart_rebuilds_the_px_state_exactly
# cross-package stage (G5 stage 2b shown):
cargo mutants -p blacksilk-zk -f zk/src/config.rs -f zk/src/params.rs -f zk/src/lib.rs \
  --exclude-re 'decode_proof|analysis::' $RE --test-package blacksilk-px --test-package blacksilk-tx \
  --baseline skip --profile mutants --jobs 2 --timeout 600 --build-timeout 2400 --cap-lints true \
  -o <out> -C=--test=consensus_fingerprint -C=--test=proof_limits -C=--test=px_proof_wiring
```

`$RE` is one `--re=^<escaped mutant name>$` per listed mutant.
