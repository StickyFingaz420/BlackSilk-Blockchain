# Mutation census of `consensus` and `px-core` (Wave 4 freeze gate)

Internal engineering evidence, not an audit. A mutation census shows which code
changes the tests notice; it does not show that the code is correct or secure.

The gate (decisions "Agent 42", P0): zero unexplained missed mutants in
`blacksilk-consensus` and `blacksilk-px-core`. Every survivor is killed by a test or
explained in [mutation-exemptions.md](../../reviews/mutation-exemptions.md).

## Result in brief

| Crate | Mutants | Caught | Missed | Timeout | Unviable |
|---|---|---|---|---|---|
| consensus, run A (before) | 405 | 289 | 28 | 48 | 40 |
| consensus, after | 405 | 310, plus the 48 timeouts, all classified (below) | 7, all exempt (E1–E4) | 48 re-run in isolation: 25 fail an assertion, 23 real hangs | 40 |
| px-core, run B (before) | 244 | 219 | 15 | 0 | 10 |
| px-core, after | 244 | 229 | 5, all exempt (E5–E7) | 0 | 10 |

- **Killed by new tests:** 21 consensus survivors and 10 px-core survivors
  (§ Survivors). Each was re-run against the new tests and is now caught.
- **Equivalent (exempt):** 12 mutants, 7 in consensus and 5 in px-core. No input can
  observe them; the arguments are in the register. None of them is a mutant of a
  reachable rule that a test could see.
- **Timeouts:** all 48 of run A were re-run one at a time with a narrower test set.
  - 25 now fail an assertion within seconds.
  - 23 are real hangs, which the suite catches by its timeout: 2 infinite loops in
    `tx_root` and 21 lost wake-ups or releases in the RandomX cache store.
  - Run B had none.
- **No survivor revealed a bug in a consensus rule.**
  - Three of the killed px-core survivors would weaken a kernel rule if the code
    changed that way (`digest_eq`'s fold, the specifier count, the spec
    comparison). The code is correct; only the tests were missing.
  - Run B's test set never ran the kernel's contract-function paths natively.
- **One flaky test found and fixed (§ Flaky baseline).** It was a measurement race
  in the test, not in the code.

## Setup

- **Tool:** cargo-mutants 27.1.0 (`cargo install --locked cargo-mutants`), a
  pure-Rust test tool outside the repository (decisions "Agent 42"; 44).
- **Toolchain:** rustc 1.98.1 (x86_64-pc-windows-msvc).
- **Code:** branch `w4-mut` on base `d6f4609` (`rebuild/core`), with the
  working-tree changes of this work. No non-test source line of either crate was
  changed.
  - Run A ran on the base with `[profile.mutants]` and the fixed seed-cache test.
  - Run B also had this work's consensus test edits, which px-core's tests never
    build.
  - The re-runs ran on the final test code, which is the committed code.
- **Profile:** `[profile.mutants]` in the root `Cargo.toml`: the test profile, every
  dependency at opt-level 3, the mutated crate and px at the test profile's
  opt-level. Overflow checks and debug assertions are on.
- **Machine:** 4 cores / 8 threads, 16 GB. It was shared with a single-core fuzzer
  (W4-FUZZ) and at times its builds (decisions "Wave 4 start").
- **Environment:** `CARGO_BUILD_JOBS=2`, `CARGO_INCREMENTAL=0`. `CARGO_TARGET_DIR`
  was unset for cargo-mutants, which copies the tree into a scratch directory
  per job: a shared target directory would serialize the jobs and rebuild on every
  path change.

## Commands

Run from the repository root.

**Run A (consensus):** the whole consensus test suite, `-j2`. The timeout was set
automatically to 300 s, against a baseline test time of 32 s.

```text
cargo mutants -p blacksilk-consensus --profile mutants --jobs 2 \
  --timeout-multiplier 5 --minimum-test-timeout 300 --cap-lints true -o <out>
```

**Run B (px-core):** px-core's tests plus px's non-proving differential tests, `-j2`.

```text
cargo mutants -p blacksilk-px-core --test-package blacksilk-px-core,blacksilk-px \
  --profile mutants --jobs 2 --baseline skip --timeout 300 --build-timeout 1800 \
  --cap-lints true -o <out> -C=--lib -C=--test=kernel -C=--test=fuzz -C=--test=state \
  -C=--test=hk_vectors -C=--test=kernel_budget -C=--test=consensus_fingerprint \
  -C=--test=delivery -C=--test=elf_paths -C=--test=fri_schedule
```

- **Why px's tests.** px-core's own tests are 4 toy-permutation unit tests. The
  oracle is px:
  - its tests compare the native kernel, built from the mutated source, with the
    committed, pinned guest ELF run in the interpreter;
  - they check the `Hk` known answers and the pinned PX consensus entries.
- **Excluded: `proof` and `unified`.** They build PX proofs, at 4–6 GB and minutes
  each (impl-brief). The census needed no proving test: every px-core survivor was
  killed or proved equivalent without one.
- **Also not used as oracles:** tx, chain and wallet, which also depend on px-core.
- **Why `--baseline skip`.** cargo-mutants 27.1.0 runs its baseline against the
  mutated package only, so `--test=kernel` fails there (`no test target named
  kernel in blacksilk-px-core`). The baseline was run by hand instead, with the same
  selection on the unmutated tree: 65 tests passed in 24 s.
- **Why `-C` and not `--cargo-test-arg`.** `-C` restricts the build to the selected
  targets as well. A first attempt with px at opt-level 3, building every px test
  target, took 200–500 s per mutant, and was stopped after 5 mutants.

**Re-runs:** the same configuration, restricted to the listed mutants with the
`--re` filters in `rerunA.args` and `rerunB.args`. Run B's re-run adds
`-C=--test=mutation_regressions`.

- Each filter is the mutant's name, anchored, with every character other than a
  letter, a digit or a space written as a one-character class (`[+]`, `[:]`).
- The five characters `[ ] \ ^ -` are escaped with a backslash instead.
- `cargo mutants --list` with each filter file returns exactly the mutants of the
  matching list.

**Timeout isolation:** `-j1` and a 120 s timeout, with nothing else from this work
running.

- **timeoutG:** the non-cache timeouts (`timeoutG.args`), tested with golden and
  lwma_warm, whose PoW stub needs no nonce search, plus the lib tests without
  `chain::tests` and `pow::tests`:

  ```text
  ... --jobs 1 --timeout 120 -C=--lib -C=--test=golden -C=--test=lwma_warm \
    <filters> -- -- --skip chain::tests --skip pow::tests
  ```

- **timeoutS:** the RandomX cache-store timeouts (`timeoutS.args`), tested with
  `pow::tests` alone, whose baseline is about 1 s:

  ```text
  ... --jobs 1 --timeout 120 -C=--lib <filters> -- -- pow::tests
  ```

**Times (UTC, 2026-09-29):**

| Run | Start | End | Duration |
|---|---|---|---|
| Run A | 15:54 | 18:30 | 2 h 36 min |
| Run B | 18:59 | 19:35 | 37 min |
| Re-run B | 19:38 | 19:48 | 10 min |
| Re-run A | 19:48 | 19:52 | 4 min |
| timeoutG | 19:53 | 19:58 | 5 min |
| timeoutS | 19:58 | 20:41 | 43 min |

**Outputs:** each subdirectory holds the tool's `caught.txt`, `missed.txt`,
`timeout.txt` and `unviable.txt` for that run: `runA`, `runB`, `rerunA`, `rerunB`,
`timeoutG` and `timeoutS`.

## Flaky baseline

The first run A stopped at its baseline.
`pow::tests::the_caches_alive_stay_bounded_under_many_keys` failed with "peak 6
caches alive" (bound: 5), on the unmutated tree.

- **Measured.** Looped under load, the test failed 12 times in 200 runs.
- **Cause.** When the last `Arc` of a cache is dropped, the store sees it gone (its
  weak count reads zero) before the cache's destructor has decremented the test's
  `live` counter. A build that starts in that window counts the dying cache.
- **Demonstration.** A 1 ms sleep inside the stand-in cache's destructor widened the
  window: 6 failures in 20 runs, with peaks up to 9.
- **Fix, in the test only.** Hashing threads now release under the read side of an
  `RwLock`, and a build counts itself under the write side. The peak then counts
  exactly the caches the store keeps or lends out.
  - With the same 1 ms sleep, the peaks stayed at 3–4 in 20 runs, matching the
    code's bound: 2 kept, 1 evicted but borrowed, 1 being built.
  - Afterwards: 300 of 300 runs passed in the mutants profile, and 100 of 100 in
    the dev profile.
- **Real, transient effect.** With real 256 MiB caches, a new build can briefly
  overlap the freeing of a cache whose destructor is still running. This is bounded
  by the number of hashing threads that release at that moment. It is not a
  consensus matter (a cache never changes a hash), and it is reported for the Lead.

## Survivors and their resolution

### consensus: run A, 28 missed

| Mutant | Resolution |
|---|---|
| chain.rs 85:9 `Display for HeaderError` → `Ok(Default)` | killed: `errors_display_as_their_debug_form` |
| chain.rs 104:9 `Reorg::is_extension` → `true` | killed: `accessors_report_validity_work_and_extensions` |
| chain.rs 227:9 `is_valid` → `Some(false)` | killed: same test |
| chain.rs 236:9 `work` → `None`, `Some(0)`, `Some(1)` | killed: same test |
| chain.rs 601:23 `next_seq += 1` → `*=` (the first-seen tie-break) | killed: `invalidation_breaks_work_ties_by_first_arrival` |
| chain.rs 527:21 `<` → `<=`, 531:47 `-` → `+` in `overlay_context` | equivalent: E2 |
| difficulty.rs 35:19 `>` → `>=` in `clock_step` | equivalent: E3 |
| difficulty.rs 91:31 `*` → `+`, `*` → `/`; 91:35 `*` → `/` (the DAA floor) | equivalent: E1 (RTFP3-16) |
| genesis.rs 121:36 `\|` → `^` in `parse_display_hex` | equivalent: E4 |
| params.rs 198:31 `+` → `-`, `+` → `*` (the `N·(N + 1)·T` bound) | killed: exact edge at N = 1000 in `check_refuses_each_broken_invariant` |
| pow.rs 27:24 `E + L` → `E − L` in `seed_height` | killed: `seed_schedule_matches_the_spec_for_every_valid_small_schedule` (differs only when `L > E/2`) |
| pow.rs 125:42 `trim`'s `> 1` → `>= 1` | killed: `without_a_hot_set_the_two_most_recent_keys_stay` (nothing tracked) |
| pow.rs 191:43 `evicted_alive() > 1` → `==`, `>=` | killed: `one_borrowed_evicted_cache_does_not_block_a_build_but_two_do` |
| pow.rs 214:34 `retain(!=)` → `==` | killed: `without_a_hot_set_…` (no key left building) |
| pow.rs 241:50 `set_hot`'s `&&` → `\|\|` | killed: `a_hot_key_is_never_evicted_for_other_keys` (built keys are not missing) |
| pow.rs 309:9 `RandomXPow::resident` → `vec![]`, `vec![Default]`; 314:9 `is_resident` → `true` | killed: `tests/seed_cache.rs` (the state before and after the first hash) |
| schedule.rs 94:9 `epochs` → empty, 99:9 `len` → 1, 104:9 `is_empty` → `true` | killed: `epoch_lookup_at_boundaries`, `v3_is_one_epoch_…` |

Re-run A: 21 caught, 7 missed. The 7 are exactly the E1–E4 mutants.

### consensus: run A, 48 timeouts

- **timeoutG, 27 mutants.** 25 fail an assertion in golden, lwma_warm or the lib
  unit tests. They are in `required_difficulty`, `validate`, `accept`,
  `next_difficulty`, `H::chain`, `to_bytes` and `check_hash`. Under the full suite
  they had hung in the unit tests' nonce searches.
  - `merkle.rs` 19:23 `>` → `>=` and `>` → `==` loop forever on a one-leaf list,
    which every block has (the coinbase): real hangs.
- **timeoutS, 21 mutants.** All still hang at 120 s against a baseline of about 1 s,
  as they did at 300 s in run A before this work's tests existed. They are all in
  the RandomX cache store (`pow.rs` 102–232).
  - Each loses a release or a wake-up: a key left in `building`, `side_building`
    never decremented, dead weak references counted as alive, a side capacity of 0,
    or a hot set never installed.
  - Callers then wait forever: a real hang, which the suite catches by its timeout.

### px-core: run B, 15 missed

| Mutant | Resolution |
|---|---|
| hash.rs 116:32 and 116:49 `\|\|` → `&&` in `Sponge::absorb`'s guard | killed: `sponge_refuses_each_invalid_input_through_the_hook` |
| kernel.rs 163:20 `v >> 32` → `<<` in `Public::write` | killed: `public_words_carry_the_high_word_of_each_bridge_amount` |
| kernel.rs 472:12 `v >> 32` → `<<` in `u64w` | killed: same test (a bridge of 2^32 or more) |
| kernel.rs 205:50 `digest_eq`'s `\|` → `^` | killed: `digests_differing_in_two_words_by_the_same_bits_are_not_equal` |
| kernel.rs 388:23 `specs += 1` → `-=`, `*=` | killed: `two_functions_may_not_specify_the_same_output` |
| kernel.rs 390:21, 391:21, 392:21 `&` → `\|` in the spec comparison | killed: `a_specified_output_must_match_in_every_field` |
| call.rs 54:47 and kernel.rs 66:70 `+` → `*` (`2 + 2`) | equivalent: E5 |
| kernel.rs 192:8 `u64_word` and 217:27 `select`, `\|` → `^` | equivalent: E6 |
| kernel.rs 332:26 the approval guard's first `\|\|` → `&&` | equivalent: E7 |

Re-run B: 10 caught, 5 missed. The 5 are exactly the E5–E7 mutants.

The px-core killing tests are in `px/tests/mutation_regressions.rs`: px-core's source
is consensus-pinned through its guest build. Each kernel test compares the native
kernel with the pinned guest.

- **The sponge guard.** With either mutant, a bad input no longer reaches
  `Permutation::invalid_input`: it stops at an overflow check or at `add`'s debug
  assertion. That happens only in a build that has them. A release-built guest has
  neither, so it would absorb the input silently (R15-6).
- **The contract-function paths.** Only the proving tests ran them before; the new
  tests check them without proving.

## Limits

- **Operators.** The census covers cargo-mutants' mutation operators, not every
  possible fault. A caught mutant shows only that some test notices that change.
- **Timeouts.** They count as caught when they are real hangs. Hangs are a weaker
  oracle than failed assertions.
- **px-core oracles.** Its mutants were tested against px's non-proving tests and
  the new regression tests only. The tx, chain and wallet tests, and px's proving
  tests, were not used.
- **Transcript binding.** The guest ELF is pinned, so a px-core mutant is tested
  natively against the unmutated guest. This is the intended differential, but it
  never exercises mutated code inside the zkVM. The proof system's binding to the
  transcript is covered by the golden-proof and proving tests (CI tier 2), not by
  this census.
- **Unviable mutants.** 40 in consensus and 10 in px-core do not compile, mostly
  `Default::default()` for types without `Default`. They are not tested.
- **Scope.** The tx rules (run C) are outside this gate (decisions "Agent 42").
