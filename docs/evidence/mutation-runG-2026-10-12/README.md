# Mutation run G: the consensus code after run E, RandomX, the zk and zkvm verifier paths, store replay, fingerprints (freeze gate 1.1)

Internal engineering work, not an audit. A mutation census shows which code changes
the tests notice; it does not show that the code is correct or secure.

The gate (decisions "Agent 42", "W4-MUT and RT-MUT", "RT-MUTD"): zero unexplained
missed mutants per completed file or function set. Every survivor is killed by a new
test or explained in [mutation-exemptions.md](../../reviews/mutation-exemptions.md)
(run G's entries: E65 to E86). **Run G does not meet the criterion yet:** three
RandomX mutants at two sites are neither killed nor shown equivalent, and five
fingerprint mutants show a structural weakness of the manifest that no test can
kill (§ Open items). They are listed as open, not exempt.

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
  `schedule_tests::known_schedules`; `+=` → `*=` was **voided** and counted as a
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
90.4%; 97.8% excluding the 38 equivalents proven from the code (E76 to E80), 98.3%
excluding all 41 (with E81 and E82).

The 160 survivors:

| Batch | Killed by new tests | Equivalent or log-only (exempt) | Open |
|---|---|---|---|
| G1 | 2 | 0 | 0 |
| G9 | 3 | 1 (E65) | 0 |
| G2 | 0 | 1 (E66) | 0 |
| G5 | 13 | 10 (E67 to E70) | 0 |
| G4 | 2 | 1 (E71) | 0 |
| G6 | 5 | 4 (E72) + 12 log-only (E73) | 0 (one low item on E73's warning, § Open items) |
| G10 | 28 | 3 (E74, E75) | 0 |
| G3 | 2 (R2) + 7 (R1) | 41 (E76 to E82) | 3 |
| G7 | 5 | 12 (E83 to E86) | 5 |
| **Total** | **67** | **85** | **8** |

- **Two security-critical test gaps** were found, each now killed: the RandomX
  IMUL_RCP power-of-two NOP rule (G3) and the store repair's handling of operator
  verdicts past a damaged length field (G6). Neither was a bug in the shipped code:
  the code was right and no test held it.
- **No survivor lets a verifier accept an invalid proof or block**, changes a pinned
  soundness parameter unnoticed, or changes today's fingerprint (per batch below).
- No production line was changed by run G; the killing tests are merged in
  `rebuild/core` up to `dfed6a5`.

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
  proves toy statements.
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
- Equivalent (10): E67, E68, E69 (on this build only: the BabyBear packing width,
  § Open items), E70.
- Timeouts (8, still timeouts alone, `runG5t`): `smallest_pow_witness` scans of the
  whole field or endless loops (250:64 `*`, 254:26 `==`, `>`, 254:63 `|`, `^`, 258:15
  `*=`), `VerifierConfig::for_statement` → `Default` (infinite recursion), and the
  voided guard stop `lib.rs:232:17` `+=` → `*=` (an unbounded schedule).

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
  - `exec.rs`: `check_addr` at its boundaries (179:17, 182:26: the executor was
    stricter than the AIR by one address; the AIR, `air/cpu.rs` 319 to 342, enforces
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
- Equivalent: 38 proven from the code (E76 to E80); `706:28` (E81); 782:41 and 807:41
  by a probabilistic reachability argument (E82).
- **OPEN (3 mutants at 2 sites):** § Open items (a).
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
- Equivalent (12): E83 to E86.
- **STRUCTURAL WEAKNESS (5, open):** § Open items (b).
- Timeout: px 553:11 `*=` (a const evaluation that never ends: a build timeout).

## Kill confirmation

Kills confirmed by a cargo-mutants re-run on the final tests: G4 (`runG4k1`), G6
(`runG6k1`, `runG6k2`), G10 (`runG10k`; the equivalents' survival `runG10keq`), R2
(`runG3a`, `runG3b`). For the other kills (G1, G9, G2, G5, G3 R1, G7, R2's two
full-mode ones), the batch reports state that each new test fails under its mutant;
the lead checked the reports, and there is no re-run record of them.

## Open items

These are stated as open. None is exempt.

- **(a) RandomX `superscalar.rs:742:24` and `783:42` (3 mutants), unkilled, not
  equivalent.** 742:24 `decode_cycle < SUPERSCALAR_LATENCY` → `<=` runs one more decode
  cycle when the loop ends by its cycle count rather than by saturated ports; 783:42
  `throw_away_count += 1` → `-=` and `*=` after a source throwaway changes
  `allow_chained_mul` for the next destination choice. Both are local state of
  `generate()`; in a probe over 1 million keys and 8 million programs neither ever
  changed a program (the loop never ended by its cycle count; the chained-multiply
  choice after a source throwaway never differed). No proof of unreachability is
  known, and no direct test exists without restructuring production code. They are
  the reason the gate's criterion is not met.
- **(b) The fingerprint manifest records sample outputs, not their inputs (5 G7
  mutants).** node `fingerprint.rs` 318:28 (a key-schedule sample height: a compound
  off-by-one switching the RandomX key one block early), 458:44 (an emission sample:
  a change of the tail floor), 1194:47 (the PX `R` top-bit sample), 1218:42 (the
  truncated-proof sample), 1251:51 (the unsupported-ABI sample). Each replaces a sample
  input with another giving the same output, so a future rule bug that only the
  original input exercises would not move the fingerprint. No test can kill them; the
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
- **(f) The BabyBear packing-width caveat (G5).** E69 holds on this build, whose
  BabyBear packing has width 1 (x86_64 without AVX2 or AVX-512 target features; the
  repository sets none). On a NEON, AVX2 or AVX-512 build those two mutants would
  panic the prover (never an invalid proof); a run on such a build would kill them.

## Reproduction

- **Code:** a worktree of `rebuild/core` at each batch's base (table above); every
  killing test is merged in `rebuild/core` up to `dfed6a5`. No production line
  changed between the bases and `dfed6a5`: the only source changes are the appended
  test modules, so the cited line numbers hold at `dfed6a5`.
- **Evidence files are not in the repository.** The run scripts, `--re` argument
  files, mutant lists (`lists/`), diffs (`diffs/`), memory-guard logs and each run's
  `outcomes.json` and logs (`runG1`, `runR2`, `runR2t`, `runG9s1`, `runG9m`,
  `runG9s2`, `runG9s2t`, `runG2s1m`, `runG2s1d`, `runG2s2`, `runG5s1`, `runG5s2a`,
  `runG5s2b`, `runG5s3`, `runG5t`, `runG5v`, `runG4s1`, `runG4s2a`, `runG4k1`,
  `runG6s1`, `runG6s2`, `runG6t`, `runG6v`, `runG6k1`, `runG6k2`, `runG10s1`,
  `runG10s2`, `runG10s3`, `runG10k`, `runG10keq`, `runG3a`, `runG3b`, `runG3s1`,
  `runG3t`, `runG3s2`, `runG3s2b`, `runG7s1node`, `runG7s1px`, `runG7s2node`,
  `runG7s2px`) are internal records in the lead's scratch area, with the lead's batch
  summary. The RandomX reachability probe (8 million programs) and the reference
  RandomX comparison are internal records there too.
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
