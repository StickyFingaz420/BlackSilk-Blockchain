# Mutation census of the BVM-1 AIR (W4-MUTAIR; threat model round 2, TM2-1)

Internal engineering evidence, not an audit. A mutation census shows which changes of
the code the tests notice. It does not show that the AIR is sound, complete or
correct. No AIR source line was changed, so the circuit fingerprint and `CIRCUIT_ID`
are unchanged (`circuit_fingerprint` passes on the final commit).

## Soundness finding first

**No under-constrained rule was found.** No mutant, hand mutant, cell change or forged
trace showed a false execution that the constraints accept:

- every mutant of the constraint files that survived the first census is either killed
  by a new test or recorded as equivalent, with an argument (E51–E61 in
  [mutation-exemptions.md](../../reviews/mutation-exemptions.md));
- each of the 20 negative-trace tests (`zkvm/tests/air_tamper.rs`, § Negative traces)
  is rejected, and each only by the single rule it targets;
- the full cell census changed 3,858,903 cells across every row of every table. Every
  change is rejected, except cells listed as free by design.

What the census **did** find were gaps in the tests, all now closed (§ Survivors):
- true executions that no honest test produced:
  - a `HALT` on the CPU table's last row;
  - byte accesses at offset 3;
  - an odd `JALR` sum;
  - a read of the initial stack pointer;
  - code above `2^27`;
  - `POSEIDON2` pointers with nonzero low and top bytes;
- the initial register image;
- the budgeted shape and `trace::usage`;
- the constraint oracle itself: `MutationChecker` could have answered "caught" for
  every change, and no test would have noticed.

**One specification gap (Informational; § Spec-to-constraint table, note 2).** The input
and output length limits of zkvm.md §5 are enforced by the interpreter, not by the
constraints.

## Scope

- **Files:** all of `zkvm/src/air/` at `3c21afe` (3,700 lines):
  - **run A**, the constraint files (1,560 mutants): `cpu.rs`, `alu_add.rs`,
    `alu_bit.rs`, `alu_lt.rs`, `alu_mul.rs`, `alu_shift.rs`, `memory.rs`,
    `poseidon.rs`, `program.rs`, `byte.rs`, `util.rs`, `mod.rs`;
  - **run B** (417 mutants): `trace.rs` (the trace generator, and the statement layout
    the verifier also builds: `tables`, `public_values`, `image`, `Statement::shape`)
    and `check.rs` (the constraint oracle itself, and the circuit fingerprint).
- **Out of scope:**
  - `zkvm/src/prove.rs` (`CIRCUIT_ID`, the height limits, the prover wrapper);
  - the interpreter (`exec.rs`, `isa.rs`);
  - Plonky3's `Poseidon2Air`, used unchanged through `SubAirBuilder`. Its constraints
    are exercised by the POSEIDON2 tests, but they are not mutated.

## Oracle design, and why the fingerprint pins are excluded

**Why the pins are excluded.** The circuit-fingerprint pins
(`zkvm/tests/circuit_fingerprint.rs`, `zkvm/tests/circuit_id.rs`) hash an evaluation
of every constraint at random points. Almost any AIR mutant changes that hash, so the
pins would "kill" it. That only shows that the circuit *changed*, not that the change
lets a false execution through (TM2-1). The pins are therefore not part of the oracle
for the constraint files. They are used only for `check.rs`'s `fingerprint` code
(run B2), whose job is exactly that hash.

**The oracle.** It is the constraint checker (`air::check`, which runs the same `eval`
code as the prover), applied to two kinds of traces:

1. **Honest traces (completeness).** Every honest execution in `alu.rs`, `vm.rs`,
   `multi.rs`, `blinding.rs`, `air_tamper.rs` and `air_cells.rs` must satisfy every
   constraint and balance every bus. A mutant that rejects a true execution is caught
   here.
2. **Negative traces (soundness).** A mutant that accepts a false execution must meet a
   trace that only the original rule rejects:
   - the existing tests:
     - the single-cell probes (`vm.rs`, `alu.rs`, `multi.rs`);
     - the false-claim and wrong-statement tests;
     - the blinding-bus tests;
   - the new **targeted forgeries** (`air_tamper.rs`). Each keeps every other rule
     satisfied:
     - the byte table's multiplicities are recomputed (`rebalance_bytes`);
     - memory chains are re-linked;
     - ALU rows are rebuilt for the forged claim;
     - the test asserts *which* rule rejects the trace (`assert_rejected_only_by`).

     Weakening that rule therefore makes the forgery pass;
   - the **lying-generator tests** (`air_tamper.rs`; TM2-X §1.8 item 2);
   - the **cell census** (`air_cells.rs`; item 1);
   - tests of the oracle itself (`air_cells.rs`).

**Proving tests are not oracles.** They take minutes each and fall under the PX memory
rule. They are compiled out of the census copy (`strip.py` marks the 17 tests listed in
`skips.txt` with `#[cfg(any())]`). No mutant here needed a proving test to be judged.

**The census build.** cargo-mutants rebuilds the mutated crate and the oracle for each
mutant. To keep that near one minute:
- the census runs on a scratch copy of the tree, not on the worktree: a `git archive`
  of the commit plus the new test files;
- one test binary, `air_oracle.rs`, includes the six oracle files as modules
  (`air_oracle.rs.txt`; it exists only in the scratch copy), so each mutant links once;
- `blacksilk-zkvm` is built at `opt-level = 1` (`--config`). The profile's other
  settings are unchanged, and overflow checks and debug assertions stay on. At level 3
  a mutant took 119 s to build; at level 1, about 60 s.

## Setup

- **Tool:** cargo-mutants 27.1.0, as in runs A–D; rustc 1.98.1
  (x86_64-pc-windows-msvc).
- **Code:** branch `w4-mutair` on base `3c21afe` (`rebuild/core`).
- **Profile:** `[profile.mutants]` (overflow checks and debug assertions on), with
  `blacksilk-zkvm` at `opt-level = 1`. Release arithmetic is a separate pass.
- **Machine:** 4 cores / 8 threads, 16 GB, shared with run E (another cargo-mutants
  run).
  - `--jobs 2` throughout, and one census process at a time.
  - Environment: `CARGO_BUILD_JOBS=2`, `CARGO_INCREMENTAL=0`.
- **Tests used by each run:**
  - **run A:** `air_tamper.rs` and `air_cells.rs` as in `29cb162`, but without
    `the_top_memory_word_and_the_registers_have_distinct_keys` (added during the run)
    and before `air_cells.rs`'s clippy reformatting (no behaviour change);
  - **rerunA, `poseidonFull`, the hand mutants and run B:** the tests of `c28ff20`;
  - **`hand2`, rerunB and the boundary pass:** the tests of `f1ec22c` (the final ones).
- **Baselines:** checked by the tool for run A (132 s build, 64 s test) and run B
  (B1: 125 s + 96 s; B2: 91 s + 53 s). The boundary pass checks its own baseline. The
  re-runs use `--baseline skip` on the same copies.

## Results

**Run A (constraint files): 1,560 mutants in 19 h.** 1,169 caught, 21 missed,
1 timeout, 369 unviable.

| File | Mutants | Caught | Missed | Timeout | Unviable |
|---|---|---|---|---|---|
| cpu.rs | 473 | 310 | 4 | 0 | 159 |
| alu_add.rs | 51 | 39 | 0 | 0 | 12 |
| alu_bit.rs | 48 | 38 | 0 | 0 | 10 |
| alu_lt.rs | 134 | 102 | 0 | 0 | 32 |
| alu_mul.rs | 175 | 145 | 2 | 0 | 28 |
| alu_shift.rs | 217 | 177 | 1 | 0 | 39 |
| memory.rs | 91 | 59 | 7 | 0 | 25 |
| poseidon.rs | 184 | 146 | 6 | 1 | 31 |
| program.rs | 46 | 34 | 0 | 0 | 12 |
| byte.rs | 41 | 33 | 0 | 0 | 8 |
| util.rs | 48 | 38 | 1 | 0 | 9 |
| mod.rs | 52 | 48 | 0 | 0 | 4 |

- **After the new tests** (`rerunA`, 22 mutants): 13 caught, 8 missed (E51–E55),
  1 timeout.
- **The timeout** (poseidon.rs 69:32, `WIDTH = WORDS · 16 · PER_WORD`) is caught when
  run alone with a 1,800 s limit. Its filter file came out empty, so `poseidonFull`
  re-ran all of poseidon.rs with the tests of `c28ff20`: 151 caught, 2 missed (E54),
  31 unviable, no timeout.

**Run B (trace.rs, check.rs): 417 mutants in 5 h.**

| Part | Scope | Mutants | Caught | Missed | Timeout | Unviable |
|---|---|---|---|---|---|---|
| B1 (AIR oracle) | trace.rs | 254 | 198 | 14 | 2 | 40 |
| B1 (AIR oracle) | check.rs, except the fingerprint | 145 | 104 | 38 | 0 | 3 |
| B2 (AIR oracle + the fingerprint pins) | check.rs `fingerprint`, `FingerprintBuilder`, `update_values` | 18 | 14 | 2 | 0 | 2 |

- **After the new tests** (`rerunB`, 54 mutants): 33 caught, 19 missed (E58–E61),
  2 timeouts.
- **B2's 2 missed** are covered by E58.

**Constant hand mutants (±1, `hand.txt`): 62.**
- 57 caught, 5 missed.
- After the new tests (`hand2`): H03, H05 and H06 caught. H02 (E55) and H04 (E57)
  are equivalent.
- H06 (pc top byte at 5 bits) was already caught in `hand`, by the corner-case test.
  For soundness it is equivalent anyway: the program-table lookup fixes every real
  row's pc below `2^28`.

**Boundary pass** (`tools/boundary-mutants.sh`). The AIR files contain one `>=`/`<=`,
at util.rs 176:18. Its mutant was missed; it is equivalent (E56).

**Release arithmetic** (`ovfA`). Run A has 64 kills whose logs show an overflow panic.
Re-run with overflow checks and debug assertions off, all 64 are still caught.

**Timeouts.** trace.rs 462:32 (`&` to `|`) and 463:14 (`<` to `==`), both in
`uniform`, make the blinding sampler loop forever, or for about `2^31` draws: the
prover never returns. They are counted as caught by the hang, as runs A–D counted
hangs.

## Survivors and their resolution

| Mutant | What it showed | Resolution |
|---|---|---|
| cpu.rs 168:50 `real · (1 − sh)` → `real · (1 + sh)` on the last row | no honest trace halts on the CPU table's last row | killed: `honest_corner_cases_satisfy_every_constraint` |
| cpu.rs 310:32 `o3 = mem·l0·l1` → `o3 = −mem·l0·l1` | no honest access at byte offset 3 | killed: same test (LB, LBU, SB at offset 3) |
| cpu.rs 346:30 JALR target `addr − l0` → `addr + l0` | no honest `JALR` with an odd sum | killed: same test |
| memory.rs 199:5 (×5), 200:28 `register_image` | no honest test read the initial registers | killed: same test (reads sp) |
| poseidon.rs 112:34, 209:37, 210:49, 211:46 | no honest `POSEIDON2` pointer with a nonzero low or top byte | killed: same test (pointer `0x0123_4564`) |
| alu_mul.rs 109:29, 110:29; alu_shift.rs 67:29 | equivalent slice ends | E51 |
| cpu.rs 108:31 | `f::FLAGS = 0` | E52 |
| memory.rs 105:24 | `KB + 2 = KB · 2` | E53 |
| poseidon.rs 252:5 (×2) | dead function | E54 |
| util.rs 76:29; hand H02 | relabelings of the register base | E55 |
| util.rs 176:18 (boundary pass) | an assertion never reached at 8 | E56 |
| hand H03 (`BLIND_VALUES = 7`) | no non-proving test of the blinding span | killed: `a_blinding_message_spans_the_extension_field` (blinding.rs) |
| hand H04 (`BLIND_VALUES = 9`) | harmless | E57 |
| hand H05 (pc top byte at 3 bits) | no honest code at or above `2^27` | killed: `honest_corner_cases_satisfy_every_constraint` (code at `0x0fe0_0000`) |
| check.rs 72:25, 389:5 (×2), 395:95 (×2), 399:48 (×2), 415:46 `*` | `shapes` was judged only by proving tests | killed: `shapes_count_every_constraint_and_interaction` |
| check.rs 143:35, 152:29 | the oracle's shape errors were untested | killed: `the_checker_reports_every_shape_mismatch` |
| check.rs 241:16, 241:21, 260:33, 262:43 (×2), 325:9, 337:50, 342:50, 362:66, 365:66, 370:73 | `MutationChecker` was never asked about a change it must NOT catch | killed: `the_mutation_checker_agrees_with_the_full_checker` |
| check.rs 98:9, 108:9, 110:75 (×2), 206:43 (×2), 209:42, 350:62 (×2), 353:62 (×2), 356:38, 415:46 `-`; B2 528:9, 540:9 | local and exclusive interactions, which no table uses | E58 |
| check.rs 370:68 | the baseline is balanced | E59 |
| check.rs 261 (×3) | the last-row flag of single-cell probes | E60 |
| trace.rs 107:9, 121:9, 357:69 (×2), 485:49, 717:49 (×2), 734:23 (×2) | budgets, the fixed shape and `usage` were judged only by proving and px tests | killed: `a_budgeted_statement_takes_its_fixed_shape` |
| trace.rs 436:5 | `blinded` had no caller | killed: `hand_assembled_tables_are_blinded` |
| trace.rs 612:34 | the generator's cross-check of the witness was untested | killed: `the_generator_refuses_a_diverging_witness` |
| trace.rs 462:32 `^`, 463:14 `<=` | uniform up to `2^−31` | E61 |
| trace.rs 463:14 `>` | biased blinding values went unnoticed | killed: `blinding_values_cover_the_field` |

**Kill check.** Every former survivor marked "killed" was checked against its log for
the test that failed:
- rerunA: each by `honest_corner_cases_satisfy_every_constraint`;
- hand2: H03 by `a_blinding_message_spans_the_extension_field`; H05 and H06 by the
  corner-case test.

## Negative traces (`zkvm/tests/air_tamper.rs`)

Each forgery is targeted: the test asserts the single rule that rejects it.

| Test | False execution | Rejected only by |
|---|---|---|
| `a_jump_to_an_identical_copy_of_its_target_is_rejected` | JAL, JALR and all six branches (both outcomes) continue at an identical copy of their target | the next-pc rule of the jump's row |
| `an_execution_that_does_not_start_at_the_entry_is_rejected` | the whole run on a copy of the code elsewhere | `pc = entry` on the first row |
| `a_skipped_instruction_is_rejected` | an instruction skipped (two ways) | the transition rule, or the next-pc rule |
| `running_past_a_halt_is_rejected` | execution continues after a HALT | `sh · real' = 0` |
| `an_execution_that_stops_without_halting_is_rejected` | the last step dropped (mid-table and on the last row) | the halting rule (both forms) |
| `a_load_cannot_return_a_stale_value_through_a_duplicated_key` | a load after a store returns the old value, through a second history of the key | the range check of the key difference |
| `a_register_read_from_the_future_is_rejected` | x0's accesses reordered into a cycle | the timestamp-difference range check (each byte) |
| `a_signed_load_cannot_drop_its_sign` | LB and LH zero-extend | the 7-bit range check |
| `an_addition_with_non_boolean_carries_is_rejected` | a false sum or difference, its carries solved in the field | carry booleanity |
| `a_signed_comparison_cannot_hide_a_sign_bit` | SLT with the sign bit moved into the low bits | the 7-bit range check |
| `an_equality_cannot_be_claimed_for_different_operands` | `a == b` for `a ≠ b` | `s · z = 0` |
| `a_product_byte_cannot_absorb_a_carry` | MULHU's high word off by one | the product bytes' range check |
| `a_shift_cannot_claim_a_zero_amount` | SRL by 1 claimed as a shift by 0 | `z · s = 0` |
| `a_shift_cannot_use_another_power_of_two` | SLL by 1 as a product by 4 | the exponent rule |
| `a_digest_word_has_a_single_byte_encoding` | a POSEIDON2 output word written as value + p | the canonical-encoding check |
| `a_poseidon2_timestamp_difference_must_be_three_bytes` | a non-byte limb for the same difference | the difference's range check |
| `a_lying_generator_cannot_change_an_alu_result` | 14 ALU operations computed as another (TM2-X item 2) | the ALU bus |
| `a_lying_generator_cannot_change_a_loaded_value` | 7 width or sign confusions of loads | the load-value rules |
| `a_lying_generator_cannot_flip_a_branch` | 6 branches evaluated inverted | the next-pc rule |
| `a_lying_generator_cannot_change_a_poseidon2_output` | a different digest word carried through the load, the output and memory | the permutation's constraints |

**How the lying-generator tests lie.** The generator recomputes ALU results and the
permutation itself and refuses a witness that disagrees, so the interpreter cannot make
it lie. Instead, each test:
- runs the interpreter on a program that differs in one instruction;
- builds every table from that run;
- decodes the lying row as the statement's instruction.

The POSEIDON2 variant patches the columns that depend on the digest directly, since no
input produces the lie.

**Controls.** `the_forgery_machinery_preserves_honest_traces` checks that the helpers
leave honest traces valid. Also in the file:
- `the_top_memory_word_and_the_registers_have_distinct_keys`;
- `honest_corner_cases_satisfy_every_constraint`;
- the trace-generator tests: `a_budgeted_statement_takes_its_fixed_shape`,
  `the_generator_refuses_a_diverging_witness`, `blinding_values_cover_the_field`,
  `hand_assembled_tables_are_blinded`.

## Cell census (`zkvm/tests/air_cells.rs`; TM2-X §1.8 item 1)

**Method.** For every table and column, on every probed row (padding included), five
changes: `+1`, `−1`, `= 0`, `= p − 1`, and a swap with the next row's cell.
- The default test probes every real row and samples the padding rows: 87,611 changes,
  10 s.
- The `#[ignore]`d test probes every row of every table: **3,858,903 changes, none
  accepted outside the free-by-design list** (113 s; `cells-full.txt`).

**Free by design** (`free_by_design`, an explicit list):
- **Padding rows** (every rule and bus count on these columns is multiplied by the
  row's selector):
  - the ALU tables: `a`, `b`, `c`, and the inverse witnesses;
  - the CPU: `clk`, `next_pc`, the register-read columns, `out`;
  - `MEM_INIT`: the final value, the final timestamp, the key difference;
  - POSEIDON2: `clk`, the execution tag, the words.
- **Real rows:** the inverse witnesses of `ALU_LT` (when `d = 0`) and `ALU_SHIFT`
  (when the amount is 0).
- **Swaps** that exchange two whole rows of a table without transition constraints.

**Testing the oracle itself.** The census, the forgeries and the single-cell probes all
trust `air::check` and `MutationChecker`. Three tests check them:
- `the_checker_reports_every_shape_mismatch`;
- `shapes_count_every_constraint_and_interaction`;
- `the_mutation_checker_agrees_with_the_full_checker`. `MutationChecker`'s answer must
  equal a full re-check, for changes it must catch and for changes it must not (zero
  deltas, free witness cells, free padding cells), on first, middle and last rows.

## Spec-to-constraint table (TM2-X §1.8 item 3)

Each rule of zkvm.md §2–§6 that a guest relies on, mapped to the constraints that
enforce it.
- **Line numbers** are those of `zkvm/src/air/` at `3c21afe`.
- **"Test"** names the test that exercises the rule (in `air_tamper.rs` unless another
  file is named).
- **"Gap"** marks a rule that no constraint enforces.

### Control and decoding

| Rule (spec) | Enforced by | Test |
|---|---|---|
| Execution starts at `pc = entry`, `clk = 0`, with no output written (§2) | cpu.rs:152-156 (first row: real, `clk = 0`, `pc = ENTRY`, `out = 0`); `ENTRY` is a public value the verifier computes | `an_execution_that_does_not_start_at_the_entry_is_rejected` |
| Every executed instruction is an instruction of the committed program, decoded as `program::fields` (§3, §4) | cpu.rs:180-182 (PROGRAM lookup of `(exec, pc, 26 fields)`); program.rs:154-163 (one entry per code word, built by the verifier; padding rows have multiplicity 0) | `public_column_copies_are_pinned_to_the_statement` (vm.rs); `a_lying_generator_cannot_*` |
| `pc` is 4-aligned and inside the code segment (§2, §4) | implied by the PROGRAM lookup: the only provided `pc` values are `code_base + 4k` | `a_jump_to_an_identical_copy_of_its_target_is_rejected` |
| Consecutive rows: `clk' = clk + 1`, `pc' = next_pc` | cpu.rs:159-161 | `a_skipped_instruction_is_rejected` |
| Sequential instructions: `next_pc = pc + 4` | cpu.rs:348-353 | `a_skipped_instruction_is_rejected` |
| `JAL`: `next_pc = pc + imm`, `rd ← pc + 4` | cpu.rs:350, 353; the link through the ALU (cpu.rs:265-270); `pc` bytes range-checked `< 2^28` (cpu.rs:185-187) | `a_jump_to_an_identical_copy_of_its_target_is_rejected` |
| `JALR`: `next_pc = (rs1 + imm) & ~1`, the sum range-checked `< 2^28` (§2) | cpu.rs:286-291, 293-299, 346, 352 | same; `honest_corner_cases_satisfy_every_constraint` (odd sum) |
| Branches: `next_pc = pc + imm` iff the comparison (negated for BNE/BGE/BGEU) holds | cpu.rs:273-283, 351 | same (six branches, both outcomes); `a_lying_generator_cannot_flip_a_branch` |
| The last real row is a `HALT`; nothing runs after a `HALT` (§5) | cpu.rs:164-168; padding follows real rows only (cpu.rs:150-151) | `an_execution_that_stops_without_halting_is_rejected`; `running_past_a_halt_is_rejected` |
| Padding rows are inert | cpu.rs:174-177 (all instruction fields zero); every interaction count is a product with a flag or `real` | `every_cell_change_is_rejected_or_free_by_design` (air_cells.rs) |
| `MAX_CYCLES = 2^21` (§5) | **not a constraint**: the verifier's CPU height limit (`prove::limits`) | note 1 |

### Registers and memory

| Rule (spec) | Enforced by | Test |
|---|---|---|
| Initial memory: the program image, zero elsewhere; `x2 = STACK_TOP`, other registers 0 (§2) | memory.rs:121-131 (`MEM_INIT`: an image key takes its value from `IMAGE`; other keys start at 0); memory.rs:53-60 (`IMAGE`, verifier-built, each word once); `register_image` (memory.rs:197-201) | `honest_corner_cases_satisfy_every_constraint` (reads sp); `wrong_public_statement_is_caught_by_the_oracle` (vm.rs) |
| Every key has one history (unique keys) | memory.rs:98-120 (key bytes `< 2^27`, `key' = key + 1 + D`, `D < 2^27`) | `a_load_cannot_return_a_stale_value_through_a_duplicated_key` |
| A read returns the last value written (§6.3) | the memory bus: each access consumes `(exec, key, v, t_prev)` and produces `(exec, key, v', t)`. CPU reads: cpu.rs:190-207; register write: cpu.rs:210-232; memory word: cpu.rs:356-373; POSEIDON2: poseidon.rs:138-151; endpoints in `MEM_INIT`: memory.rs:133-149 | `a_lying_prover_cannot_change_a_register_value` (vm.rs); `a_load_cannot_return_a_stale_value_through_a_duplicated_key` |
| Accesses are ordered: `t − t_prev − 1 ∈ [0, 2^24)` | cpu.rs:203-206, 222-223, 361-362; poseidon.rs:148-150, 354-358 | `a_register_read_from_the_future_is_rejected`; `a_poseidon2_timestamp_difference_must_be_three_bytes` |
| Register keys and memory keys are disjoint | `REG_BASE = 2^26` (util.rs:76) is above every word key (`addr < 2^28`: cpu.rs:291, poseidon.rs:110-114) | `the_top_memory_word_and_the_registers_have_distinct_keys`; E55 |
| `x0` reads 0 and ignores writes (§2) | `x0` starts at 0 and is never written: the write count (cpu.rs:136) uses the public `rd_write = writes ∧ rd ≠ 0` (program.rs:118-122) | `every_instruction_class_satisfies_the_constraints` (vm.rs) |
| Only `rd` is written, with the computed value | cpu.rs:210-236 | single-cell probes; `a_lying_generator_cannot_change_an_alu_result` |
| Executions of one proof are isolated (§6.5) | every memory, program, image, output and syscall message starts with the execution id | `executions_are_isolated_and_satisfy_the_constraints`, `every_part_of_a_multi_execution_statement_is_bound` (multi.rs) |

### Loads and stores

| Rule (spec) | Enforced by | Test |
|---|---|---|
| Address `= rs1 + imm` (32-bit), `< MEM_SIZE = 2^28` (§2) | cpu.rs:286-291 | single-cell probes |
| Accesses below `NULL_GUARD = 0x1000` trap (§2) | cpu.rs:320-337 (`SLTU(addr, 0x1000) = 0` for loads and stores) | hand mutants H13, H14 (caught) |
| Stores below `CODE_END` trap (ZK-3b) | cpu.rs:338-343; `CODE_END` is public | single-cell probes (vm.rs) |
| Natural alignment, else trap (§4) | cpu.rs:311-313 | single-cell probes |
| The word accessed is the aligned word `addr / 4` | cpu.rs:314-318 | single-cell probes |
| LB, LBU, LH, LHU and LW extract and extend (§4) | cpu.rs:376-402 (byte select from the one-hot `o`, cpu.rs:305-310; sign byte `= 128·sgn + sr`, `sr < 128`) | `a_signed_load_cannot_drop_its_sign`; `a_lying_generator_cannot_change_a_loaded_value`; offset 3 in `honest_corner_cases_satisfy_every_constraint` |
| SB, SH and SW merge into the word (§4) | cpu.rs:404-426; the new word range-checked (cpu.rs:365) | single-cell probes; the honest stores |

### ALU (RV32I, Zmmul)

| Rule (spec) | Enforced by | Test |
|---|---|---|
| R-type and I-type results (`ADD` … `AND`, `MUL*`) | cpu.rs:246-255 (ALU lookup `(op, a, b or imm, c)`); `ALU_ADD`, `ALU_BIT` (through the byte table), `ALU_LT`, `ALU_MUL`, `ALU_SHIFT` (products through `ALU_MUL`) | `a_lying_generator_cannot_change_an_alu_result`; `a_false_alu_claim_leaves_the_bus_unbalanced` (alu.rs); the ALU forgeries of § Negative traces |
| Shifts use the low 5 bits of the amount (§4) | alu_shift.rs:56-66 | alu.rs edge values (amounts 31, 33) |
| `LUI`: `rd ← imm`; `AUIPC`: `rd ← pc + imm` | cpu.rs:256-264 | `every_instruction_class_satisfies_the_constraints` (vm.rs) |
| No division (ZK-3a) | rejected at load; the program table holds only valid instructions (program.rs:141-152) | `invalid_instructions_are_rejected_at_load_time` (interpreter.rs) |
| `FENCE` is a no-op | class flag only: no value (cpu.rs:233-236), no access, `next_pc = pc + 4` | `every_instruction_class_satisfies_the_constraints` (vm.rs) |

### System calls (§5)

| Rule (spec) | Enforced by | Test |
|---|---|---|
| `a7` selects exactly one of HALT, READ, WRITE, POSEIDON2; any other number traps | cpu.rs:429-437, 465-467 | single-cell probes (vm.rs) |
| HALT: `a0` is the public exit code | cpu.rs:169-171 | `wrong_public_statement_is_caught_by_the_oracle` (vm.rs) |
| READ: `a0 ←` a private input word | cpu.rs:136, 144, 233 (written, range-checked; the value is the witness) | `every_instruction_class_satisfies_the_constraints` (vm.rs) |
| WRITE appends `a0` to the public output, which has exactly the claimed length | cpu.rs:156, 162, 172, 468-470; memory.rs:62-79 (`OUTPUT` consumes each claimed word once) | `wrong_public_statement_is_caught_by_the_oracle` (vm.rs) |
| POSEIDON2 permutes the 16-word buffer at a 4-aligned `a0` in writable memory, in place | cpu.rs:441-464 (`a0 ≥ CODE_END`, `a0 < 2^28 − 63`, syscall lookup); poseidon.rs:100-161 | `a_poseidon2_row_cannot_claim_a_different_digest` (vm.rs); `a_lying_generator_cannot_change_a_poseidon2_output` |
| Each buffer word is a canonical field element (`< p`), else trap | poseidon.rs:84-92, 134-136, 154-158 | `a_digest_word_has_a_single_byte_encoding` |
| Input ≤ `2^16` words, output ≤ `2^12` words (§5) | **not a constraint** | note 2 (**gap**) |

### Byte-level facts every rule above relies on

| Fact | Enforced by | Test |
|---|---|---|
| A range lookup `(x, y)` holds only for bytes; `range_bits(x, k)` only for `x < 2^k` | byte.rs:43-59 (a verifier-built table of all 65,536 pairs); util.rs:168-186 | `byte_table_multiplicities_must_match` (alu.rs); every rejection by a non-byte range message above |
| Byte operations `AND`, `OR`, `XOR` | byte.rs:48-58 | alu.rs single-cell probes |
| No bus message can be absorbed by the blinding bus | util.rs:31-67 | blinding.rs |

**Note 1 (`MAX_CYCLES`).**
- It is a resource limit, enforced by the verifier's CPU height limit (`prove::limits`:
  `2^21` rows), not by a constraint.
- With it, every timestamp is below `2^24`. The access-order check needs that bound for
  completeness only.
- Soundness needs `t − t_prev − 1` to fall outside `[0, 2^24)` whenever
  `t_prev > t`, which holds for all timestamps far below `p`.

**Note 2 (input and output lengths; Informational gap).**
- **What the AIR allows.** The limits are interpreter limits; the AIR does not bound
  either length. An execution that reads more than `2^16` words, or writes more than
  `2^12`, has no interpreter run, but a valid trace may exist.
- **What it proves.** Such a statement is still a true statement about a halting RV32IM
  execution: the input is private, and the output is public and fully constrained.
- **The spec.** zkvm.md says such an execution "traps"; the circuit accepts it.
- **Open for the Lead.** Whether any consumer relies on the limits for a public
  statement (PX statements fix their output layout). Changing the AIR here is a
  consensus change; nothing was changed.

## Commands

Run from the scratch directory (`C:/bszkeval/w4-mutair-scratch`):
- **The census copy `src/`:**
  - a `git archive` of the commit;
  - the new test files copied in;
  - `air_oracle.rs` added (`air_oracle.rs.txt`);
  - `python strip.py skips.txt src/zkvm/tests/{alu,vm,multi,blinding}.rs`.
- **`src-hand/`:** the hand mutants' own copy of `src/`, with its own target directory.
- **Filter files:** `mkre.py` writes the `--re` files, one anchored filter per mutant
  name, as in run D. They are LF files.

| Step | Script | Output |
|---|---|---|
| run A | `runA.sh` | `A/` |
| rerunA, the timeout re-run (`poseidonFull`), hand mutants, run B | `chain2.sh` (uses `rerunA.args`, `hand.sh`, `hand.txt`, `runB.sh`) | `rerunA/`, `poseidonFull/`, `hand/`, `B1/`, `B2/` |
| release arithmetic | `chain3.sh` (`ovfA.args`) | `ovfA/` |
| boundary pass | `chain4.sh` (tools/boundary-mutants.sh, oracle in the worktree) | `boundary/` |
| hand re-run | `hand.sh hand2.txt` | `hand2/` |
| rerunB | `chain5.sh` (`rerunB.args`) | `rerunB/` |
| cell census | `cargo test --locked --profile mutants -p blacksilk-zkvm --test air_cells -- --ignored --nocapture` | `cells-full.txt` |

**Times (UTC):**
- run A: 2026-10-02 04:28 to 23:14;
- `chain2`: 2026-10-02 23:17 to 2026-10-03 13:07;
- release arithmetic, the boundary pass, the hand re-run and rerunB followed it one
  at a time, until 2026-10-03 15:41.

## Limits

- **What a census can and cannot find.** It finds tests that do not notice a change of
  a written constraint. It cannot find a constraint that was never written; the
  negative traces, the lying generators and the spec table address that, only for the
  cases they name.
- **Upstream code.** Plonky3's `Poseidon2Air`, the LogUp argument (`p3-lookup`) and the
  STARK itself are not mutated.
- **The oracle.** It is the constraint checker. That the prover and verifier evaluate
  the same constraints rests on the shared `eval` code, and on the existing proving
  tests (not run here).
- **Count weights.** `Count::bounded` weights (the LogUp height check) are not modelled
  by the checker. They are pinned by `the_logup_multiplicity_bound_holds_for_the_largest_statement`
  (multi.rs).
- **One machine.** The runs used one machine, under load from run E. No result depends
  on timing, except the hang classification.
