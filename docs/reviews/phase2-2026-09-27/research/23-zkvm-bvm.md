# 23 zkvm-bvm: research dossier (phase 2, phase 1)

Agent 23 (zkvm-bvm). Internal engineering research, **not an audit**. Read-only on the
repository; no builds or tests were run. Zero knowledge is claimed only as statistical and
conditional (docs/reviews/zk-coverage.md §3). Nothing here claims BVM-1 is secure.

Evidence tags: **[math]** mathematically established; **[test: name]** tested (by an
existing test, not re-run by me); **[src]** source-read; **[assumed]**; **[unknown]**;
**[est]** my estimate.

---

## 1. Scope and what I read

**Commit:** `9e422d8` (`rebuild/core`, `git rev-parse --short HEAD`).

**Code (all read in full):**
- `zkvm/src/lib.rs`, `isa.rs`, `exec.rs`, `program.rs`, `prove.rs`, `asm.rs`;
- `zkvm/src/air/{mod,util,cpu,program,memory,byte,alu_add,alu_bit,alu_lt,alu_mul,alu_shift,poseidon,trace,check}.rs`;
- `zkvm/Cargo.toml`; `fuzz/fuzz_targets` list (a `zkvm_elf` target exists).

**Tests (all read):** `zkvm/tests/{vm,interpreter,alu,fuzz,multi,circuit_id,stress}.rs` in
full; `blinding.rs` and `guest.rs` by test inventory and the parts cited; `isa.rs` unit
tests.

**Plonky3 0.7.0 sources consulted (registry copies):**
- `p3-lookup-0.7.0/src/{challenges.rs,logup.rs}` (bus separation, fraction constraint);
- `p3-batch-stark-0.7.0/src/{transcript.rs,common.rs,prover.rs,symbolic.rs}` (challenge
  sampling, per-bus width assertion, public-value absorption, quotient-chunk count, same-bus
  packing budget);
- `p3-poseidon2-air-0.7.0/src/{columns.rs,air.rs}` (column layout);
- `p3-air-0.7.0/src/symbolic/expression.rs` (selector degrees);
- `p3-uni-stark-0.7.0/src/security.rs` (buildability bound under ZK).

**Docs and reports:** `docs/zkvm.md` (full); `docs/reviews/full-review-2026-09-27.md` §3.5
and the register rows for R4; `docs/reviews/autonomous-session-2026-09-27.md` (zk items);
`full-review-2026-09-27/R4-zk.md` (full); SX1 rows on R4; `docs/reviews/terminal-blinding.md`
§2–§7; `tx/src/px.rs:755-782` (`budget_is_provable`), `px/src/prove.rs` statement
construction; roster entries 20–29, 41–47, 50.

---

## 2. Current state

### 2.1 What exists

BVM-1 is RV32I + Zmmul, with a strict decoder shared by the loader, the interpreter and
the verifier's PROGRAM table. It has:
- 13 table kinds, 9 buses and an offline memory argument;
- multi-execution tags, fixed shapes (budgets) and terminal blinding;
- a statement digest that opens with `CIRCUIT_ID` (R4-11, merged from v3);
- a concrete-value constraint oracle (`air/check.rs`) used for differential tests and
  single-cell mutation tests.

### 2.2 My independent re-derivation of the soundness of each bus and table

I re-derived the argument from the source, independently of R4 §2, before reading it. **I
agree with R4: I found no soundness defect.** The points I verified, and those I add:

| Item | Claim | Evidence |
|---|---|---|
| Bus separation | One `(α, β)` pair per batch. Each bus gets the prefix `α + (id+1)·β^W`, with W = the widest payload (28, PROGRAM). A per-bus uniform tuple width is asserted, so `[x]` and `[0,x]` cannot alias. The terminal sum is taken over all buses together, which is sound because distinct (bus, payload) pairs give distinct denominators as polynomials in (α, β). | [src] `p3-batch-stark transcript.rs:115-190`, `p3-lookup challenges.rs:8-35` [math] |
| Bus widths in BVM-1 | RANGE 2, BYTE_OP 4, ALU 13 (the CPU, ALU_SHIFT and every ALU table send op + 12), PROGRAM 28, IMAGE 6, OUTPUT 6, SYSCALL 6, MEMORY 7, BLIND 8. Each is fixed per bus. | [src] `util.rs`, `cpu.rs`, `alu_*.rs` |
| Public values | Absorbed right after the main commitment, before any lookup challenge. | [src] `transcript.rs:48-55` |
| Memory argument | Produced timestamps are 0, `4(clk+1)+slot` and the POSEIDON2 `4(CLK+1)+3`, all < 2^24. Consumed `t_prev` is forced to `t − 1 − d`, with d in 3 bytes. Keys: memory words are < 2^26 (WK·4 = s − l0 − 2l1 with s < 2^28; the POSEIDON2 KEY+15 < 2^26 via the CPU's `ptr < 0x0FFF_FFC1`), and registers are 2^26+r. MEM_INIT keys are unique and < 2^27, with no wrap because key+1+D < 2^28+1 < p. | [src] `cpu.rs:189-232,355-373`, `memory.rs:91-150`, `poseidon.rs:109-153` [math] |
| Byte induction | Every producer of a memory value range-checks its bytes: CPU `cc` (gated by `computes`, which covers every writing class including READ), store `nn`, POSEIDON2 outputs, image bytes, zeros. A minimal-timestamp argument shows that every consumed value is bytes. | [math] |
| Register-operand confusion (the class of RISC Zero CVE-2025-52484) | The rs1 and rs2 keys are `REG_BASE + fld(RS1)` and `REG_BASE + fld(RS2)`. Both fields are inside the PROGRAM lookup message, which is verifier-built, and each read is a separate memory interaction at a distinct slot (0 and 1). A prover cannot read rs2's value as rs1: the keys are pinned per pc. | [src] `cpu.rs:180-207`, `program.rs:113-121` |
| ALU determinism | ADD/SUB byte carries; LT via `b + d = a + 2^32·k3`; the signed rule and the EQ inverse; MUL with 8-byte sign extension and carries < 2^12. The maximum column sum is 520,200 + carry < 2^20. SHIFT reduces to MUL/MULHU/MULHSU of 2^e. Every result is unique given (a, b). | [src] [math], [test: `alu.rs::a_false_alu_claim_leaves_the_bus_unbalanced`, `every_single_cell_mutation_of_a_real_alu_row_is_caught`] |
| Control | The first row is real, with clk=0, pc=entry and OUT=0. Real rows form a prefix. The last real row must HALT, including on the last trace row. Nothing follows a HALT. A negative branch or JAL target wraps to ≥ 2^28 and fails the next row's `pb` range or the PROGRAM lookup. | [src] `cpu.rs:148-172,345-353` |
| Syscalls | `a7 ∈ {0..3}` via one-hot flags with `a[1..3] = 0`. READ writes x10 with a free, range-checked value. The POSEIDON2 pointer satisfies `CODE_END ≤ ptr < 2^28 − 63` and is 4-aligned (`ptr0 = 4·PH`). This matches the interpreter's per-word `check_addr(.., store)`. | [src] `cpu.rs:428-470`, `exec.rs:348-371` |
| Poseidon2 column mapping | `Poseidon2Cols` starts with `inputs[16]` and ends with the last full round's `post[16]`. So `r[k]` is input k and `P2_OUT + k` is output k. | [src] `p3-poseidon2-air columns.rs:12-31` |
| Canonicity | `x3 + 136 − 120e` is a byte, with the e-flag constraints. It is sound only because inputs come from the bus (bytes by induction) and outputs are range-checked. This is R4's fragile invariant, which I confirm. | [src] `poseidon.rs:83-92,134-136` |
| Cross-execution | MEMORY, PROGRAM, IMAGE, OUTPUT and SYSCALL messages carry the exec id. For POSEIDON2 the id is an `EX` column bound through SYSCALL. | [src] |
| Blinding bus | The selector is 1 on row 0 and every other blinding cell is 0. The BLIND provider has a boolean `real` and zero padding. A blinding message cannot stand in for a real one: the fingerprints differ by bus prefix. | [src] `util.rs:39-62`; [test: `blinding.rs::*`, `alu.rs::a_blinding_bus_message_cannot_stand_in_for_an_alu_result`] |
| Padding rows | Padding rows have free cells (CPU `A`, `B`, `PC`, `NEXT_PC`, `OUT`; MEM_INIT `VF`, `TF`). None of them touches a bus. This is harmless for soundness [src]. | R4 §2.6 agrees |

### 2.3 What the tests actually prove

- **Differential (interpreter ⇒ circuit completeness):** random programs satisfy every
  constraint [test: `fuzz.rs::random_programs_satisfy_every_constraint`, 300 iterations by
  default]. The generator (`fuzz.rs:40-131`) has limits:
  - it covers R-type, I-type, shifts, loads and stores at offsets 64–255 of a data segment,
    **forward** branches over one instruction, WRITE, READ and POSEIDON2 on one fixed buffer;
  - it never emits JAL, JALR, AUIPC (LUI only through `li`), backward branches, rd = x0, loads
    from code or read-only data, stores near CODE_END, boundary POSEIDON2 pointers,
    multi-execution statements or budgets;
  - its registers are only `{t0–t2, a1–a5}` (`fuzz.rs:32`).
- **Single-cell mutation (soundness evidence, partial):**
  - covered: real CPU and MEM_INIT rows of the kitchen-sink program; POSEIDON2 rows and
    their CPU rows; the CPU rows of extra executions; real ALU rows; public-copy cells;
    blinding cells;
  - deltas: ±1 (and +256 for the ALU);
  - **not covered:** coordinated multi-cell forgeries. This is exactly the class the
    literature finds in production zkVMs (§4, F23-5).
- **Decoder:** 43 ops × 200 round trips, 9 known encodings, 16 illegal and 4 compressed words
  [test: `isa.rs` unit tests]. There is no exhaustive or census test (R4-04, confirmed).
- **ISA semantics:** 14 R-type ops × 12×12 edge pairs against an i128 reference
  [test: `interpreter.rs::register_ops_match_the_reference_on_edge_values`], plus hand
  vectors. The reference was written by the same project, so it is not independent evidence
  of RISC-V conformance.
- **Binding:** program, exit code, outputs, binding, execution order and budgets are bound
  [test: `vm.rs::a_small_program_proves_and_verifies_and_statements_are_bound`,
  `multi.rs::three_executions_prove_and_verify_in_one_proof`,
  `budgets_are_enforced_by_prover_and_verifier`].
- **`CIRCUIT_ID`:** the tag is the first digest input [test: `circuit_id.rs`]. **Nothing
  ties the tag to the AIR it names** (F23-1).

---

## 3. Problems in scope

### 3.1 ISA conformance evidence (R4-04)

**Problem.**
- `decode` is consensus-critical: it defines the PROGRAM table the verifier builds.
- It is correct by my own field-by-field check against the Unprivileged ISA (20191213 and
  20240411) and Zmmul 1.0 [src]. I confirm R4 §2.9, including:
  - JALR requires funct3 = 0;
  - shift immediates require funct7 = 0 or 0100000;
  - FENCE ignores fm, pred, succ, rs1 and rd (a no-op);
  - FENCE.I and CBO are rejected;
  - SYSTEM must be exactly `0x00000073`;
  - encodings of 48 bits or longer are illegal.
- As R4 notes, a decoder bug is not a soundness bug: both sides share `decode`. It is a
  **RISC-V divergence**. A rustc-compiled guest (including the consensus kernel) could then
  compute something other than its Rust source says.
- **After the freeze, fixing such a bug is a consensus change.** Conformance evidence must
  therefore exist before the freeze.

**Security consequences:** a miscompiled-semantics kernel could accept or reject PX
transactions differently from the native `px-core` kernel. That is a consensus-level logic
bug, not a proof forgery.

**Class:** consensus-critical (as a specification), correctness.

**Literature and practice:**
- **zkvmBlast** (zkSecurity, 2026-08) differentially fuzzes SP1, RISC Zero, OpenVM, Pico and
  Zisk against Spike. It found:
  - x0-write completeness bugs;
  - misaligned-JALR proving failures;
  - misaligned fetches that execute silently instead of trapping;
  - wrong rounding of misaligned memory addresses.
- **ACT4** (riscv-arch-test, which replaces RISCOF) produces self-checking ELFs whose
  expected values are computed by the Sail reference model, using only
  `RVMODEL_HALT_PASS`/`FAIL` target macros. `eth-act/zkevm-test-monitor` runs it against SP1,
  OpenVM and Zisk.
- **riscv-tests** `rv32ui`/`rv32um` are self-checking with a replaceable `riscv_test.h`.
  Zero-CSR custom environments exist (for example SystemScope's).

**Assessment of BVM-1 against the zkvmBlast bug classes [src]:**
- **x0 write:** handled. `C` is still computed and range-checked, and only the write is
  gated.
- **Misaligned JALR:** `(rs1+imm) & ~1`; a target that is 2 mod 4 traps at the next fetch,
  which is consistent in both the interpreter and the circuit.
- **Misaligned fetch:** trap.
- **Misaligned data access:** trap, never rounded.

These should become regression tests (§5, W3).

**Proposed conformance plan** (details in §5 W1–W4):
1. **Decoder census (fast, default test).**
   - Loop over all 32 major opcodes with low bits `11` × funct3 × funct7 (32,768 classes),
     with rd, rs1, rs2 and immediate bits set to patterns (all-zero, all-one, alternating).
   - Assert that the accepted op equals an independently written table taken from the spec's
     opcode map.
2. **Exhaustive 2^32 sweep (`#[ignore]`, nightly).** For every word w:
   - **(a)** if `decode(w)` is `Ok` and the op is not FENCE, then `encode(decode(w)) == w`.
     That proves that no accepted bit is silently ignored. FENCE is the only op whose
     don't-care bits are allowed.
   - **(b)** Per-op accepted counts equal the closed form. In total:
     `3·2^25 + 22·2^22 + 17·2^15 + 1 = 193,495,041` accepted words. The terms are:
     - LUI, AUIPC, JAL: 3·2^25;
     - JALR, 6 branches, 5 loads, 3 stores, 6 non-shift OP-IMM ops and FENCE: 22·2^22;
     - 3 shift-immediate ops and 14 OP ops: 17·2^15;
     - ECALL: 1.

     [math]; the total must be confirmed on the first run.
   - **(c)** `w & 3 != 3` implies `Compressed`.
   - Estimated time: 4.3·10^9 iterations × about 5–10 ns ≈ 25–45 s single-threaded in release
     [est].
3. **riscv-tests port in pure Rust.**
   - Reimplement `test_macros.h` (`TEST_RR_OP`, `TEST_IMM_OP`, `TEST_LD_OP`, `TEST_ST_OP`,
     `TEST_BR2_OP_*`, `TEST_JAL*`, and the bypass variants) as Rust helpers over `asm::Asm`.
   - Transcribe the vectors of rv32ui (`add…xori`, `lui`, `auipc`, `jal`, `jalr`, `b*`, `l*`,
     `s*`, `simple`, `fence_i` excluded, `ma_data` excluded) and rv32um (`mul`, `mulh`,
     `mulhsu`, `mulhu` only).
   - Each test runs in the interpreter **and** through `air::check::check`; one per class is
     proven.
   - Upstream riscv-tests is BSD-3; keep the attribution.
4. **ACT4 fixtures (spike first).**
   - Build the rv32i and Zmmul ACT4 ELFs offline with the Sail-based ACT4 flow, a BVM
     `rvmodel_macros.h` (HALT_PASS = `li a7,0; li a0,0; ecall`) and a linker script placing
     `.text` at 0x10000.
   - Commit the ELFs plus SHA-256 values as fixtures, as is done for the guest ELFs. They run
     under `Program::from_elf`.
   - Non-Rust tools are used **only offline, as test oracles**, never in the build or at
     runtime. The coordinator must confirm that this fits the pure-Rust rule (open question
     Q2).
   - [unknown] Whether ACT4's startup code for the I tests touches CSRs. If it does, those
     lines must be stubbed in the model macros.

**Trade-offs:**
- The ported vectors are only as good as the transcription (use the upstream source verbatim
  in comments).
- ACT4 adds an offline toolchain dependency for fixture regeneration.
- The exhaustive sweep costs CI minutes.

**Invariants that must never change:** one `decode` shared by the loader, the interpreter
and the PROGRAM table; rejection of DIV/REM/CSR/compressed/FENCE.I.

### 3.2 R4-03: the interpreter/circuit exception

**Re-derivation.** I searched for every place where the circuit accepts more than the
interpreter. The complete list is [src]:
1. **More than `MAX_INPUT_WORDS` READs:** the circuit has no READ counter.
2. **`run` rejects `input.len() > 2^16` up front** (`exec.rs:433-435`), even if the program
   never reads that far. This is a strict sub-case of 1.
3. **More than `MAX_OUTPUT_WORDS` WRITEs:** the circuit bounds the OUT counter only by the
   claimed outputs and the CPU height. PX pins output lengths (R4, internal-review F1).

**Checked and consistent** [src]:
- the cycle limit (`clk ≥ max` before a step, against a CPU height ≤ 2^21);
- every address trap;
- the POSEIDON2 range;
- unknown syscalls, including a7 ≥ 256;
- x0;
- HINTs;
- loads with rd = x0, which still access memory and trap, as the spec requires;
- the JALR low bit;
- the entry point.

**Consequences:** none for security. The input is witness, and a guest cannot observe the
end of its input except by trapping.

**Class:** a specification-accuracy issue only.

**Options:**
- (a) Document the three exceptions (doc only).
- (b) Add a READ counter to the CPU: +1 column plus a public bound, which is a consensus
  change and changes the circuit id.

**Recommendation:** (a). A counter adds circuit surface for no security gain, against V6
("simple enough to review"). The V3 sentence in `zkvm.md:26` and the "exactly" claims at
`exec.rs:3-4` and `zkvm.md` §9 must be corrected.

**Test:** a test that a program performing 2^16 + 1 READs traps in the interpreter, while a
hand-built trace of the same execution satisfies `check`. This documents the exception.

### 3.3 R4-07: degree reduction, re-derived

**Facts [src], checked against p3-air 0.7 degree rules** (`IsFirstRow`/`IsLastRow` count as
degree 1 and `IsTransition` as 0; `expression.rs:44-48`):
- **CPU degree 5** comes from exactly two constraints:
  - `real·(NEXT_PC − … f_br·taken·(imm_f−4) …)` (`cpu.rs:348-353`);
  - `f_ld·sg·(kb·sel_b + kh·half_hi − 128·sgn − sr)` (`cpu.rs:380-385`).
- Every other CPU constraint is ≤ 4, including the transition constraint
  `real·(1−nr)·(1−sh)` (degree 3).
- Other tables: ALU_LT is **4** (`slt·lts`, with `lts` of degree 3); POSEIDON2 is 3; ALU_MUL
  is 3 (the two extended bytes never multiply, because k ≤ 7); ALU_SHIFT is 3.

**New observation: a zero-column reduction to degree 4.** The PROGRAM table is
verifier-built, so two public invariants hold:
- **SIGNED ⇒ LOAD:** `fields()` sets `signed` only for LB and LH.
- **BR_NEG ⇒ BRANCH**, and `COND = 0` off-branch (`cpu.rs:282`). So `taken` is already 0 on
  non-branch rows.

Replacing `f_br·taken` with `taken`, and `f_ld·sg` with `sg`, lowers both constraints to
degree 4, with no new committed column. R4's TAKEN and SEL_B columns are not needed. Each
invariant must be stated in `program.rs` and pinned by a test over all 43 ops.

**Why this may not pay (new caveat, quantified from the source):**
- Under ZK, `log_chunks = log2_ceil(d + 1 − 1)`, so d = 5 gives 3 and d = 4 gives 2. The
  **same-bus packing budget** is `2^log_chunks + 1 − is_zk` (`common.rs:341`): **8 at degree
  5, but only 4 at degree 4**.
- The CPU has about 30 interactions. Halving the packing budget will likely add LogUp
  fraction columns, each 8 base columns (the extension), plus their quotient contribution.
- Gain: fewer quotient chunks. Loss: more aux columns. **The net can be negative** [est].
- Chunk counts to measure:
  - R4 states 8 → 4 chunks. My reading of `prover.rs:203`
    (`n_chunks = 1 << (lq + is_zk)`) gives **16 → 8 committed chunks**.
  - Either way the count halves, but the absolute numbers must be measured with
    `vm.rs::proof_composition_report`.
- Buildability: `MAX_CONSTRAINT_DEGREE = 2^LOG_BLOWUP = 8` (`zk/src/params.rs:161-162`)
  matches p3's ZK bound ("blowup, not blowup+1", `security.rs:68-72`). Degree 5 is
  legitimate [src].

**Classification:** performance and architecture; a consensus change (the AIR, so
`CIRCUIT_ID` v2 and new kernel budgets). **Recommendation:** P3. Do it only if a measured
per-table breakdown shows a net win, and only if it can ride the freeze. It must never be
merged merely because it is interesting.

**Tests if done:**
- a golden per-table degree assertion (W5);
- a re-run of every mutation test;
- an invariant test that `SIGNED ⇒ LOAD` and `BR_NEG ⇒ BRANCH` for all ops;
- forgery tests for branch and signed loads (W4).

### 3.4 CIRCUIT_ID is not mechanically tied to the AIR (new, F23-1)

- `CIRCUIT_ID` is a hand-maintained string (`prove.rs:59`). Its doc says "a change to any AIR,
  bus or table order must change this tag".
- **Nothing detects an AIR edit that forgets the bump.** The consequence: two node versions
  with different AIRs under the same id. Honest proofs from one version would fail under the
  other, which is a liveness and consensus split with a confusing error. Worse, an edit that
  only *weakens* a constraint verifies old proofs and silently changes the statement.
- **Fix (test-only, no consensus impact): a *circuit fingerprint* test.**
  - For every table kind, evaluate `eval` with the existing `EvalBuilder` on K
    pseudo-random rows (a fixed seed; random main, next, periodic and public values; random
    selector values).
  - Collect the constraint values, the interaction tuples, the bus names and the counts. Hash
    them together with `width`, `num_periodic_columns`, `num_public_values`, the table order
    for 1/2/3-execution statements, `BLIND_WIDTH` and `limits()`.
  - Pin the digest next to `CIRCUIT_ID`.
  - Any constraint change alters the evaluations with overwhelming probability (a polynomial
    identity argument) [math]. The test then fails until both the pinned digest **and**
    `CIRCUIT_ID` are updated. The test asserts the pair.
- **Priority: P0** (a freeze guard; cheap).

### 3.5 Soundness evidence beyond single-cell mutation (new, F23-5)

- **Literature:**
  - Arguzz (Hochrainer, Wüstholz and Christakis, arXiv 2509.10819) combines metamorphic
    testing with **fault injection into the executor**. It found 11 bugs in 3 of 6
    production zkVMs, 3 of them soundness bugs. One RISC Zero bug earned a $50k bounty
    despite prior audits.
  - The RISC Zero rs1/rs2 confusion (CVE-2025-52484) was **multi-cell and consistent**, and
    it existed while RISC Zero had machine-checked *determinism* for 122 of its 123
    components (Picus). Determinism does not catch wrong-but-deterministic wiring.
  - ZEBRA (Takahashi, Jana and Yang, arXiv 2609.15020, 2026-09) found 11 zero-days in 5
    zkVMs by solution-set cardinality checking.
  - The SNARK vulnerability SoK (Chaliasos et al., USENIX Sec 2024) finds that
    under-constrained circuits are the dominant class.
- **BVM-1 today:**
  - R4's paper argument, plus single-cell ±1 mutation.
  - A single-cell mutation cannot express "read rs2's value as rs1 and keep every bus
    balanced", nor "execute a misaligned load consistently".
- **Fix: fault-injection tests.** A test-only feature `fault-injection` (off by default) in
  `exec.rs` lets a test perturb one step's semantics, for example:
  - the wrong source register;
  - a load that ignores alignment;
  - a store below CODE_END;
  - a skipped trap;
  - a READ into the wrong register;
  - an off-by-one POSEIDON2 pointer;
  - `next_pc` + 4 on a taken branch;
  - HALT with a different a0;
  - a WRITE with a stale value.

  The trace builder then produces a fully consistent witness of the faulty execution. The
  test asserts that `check` reports a violation, and for a sample that `prove`/`verify`
  fails (in release). This is the Arguzz method, applied at the witness level.
- The trace builder's cross-checks (`assert_eq!` against the replay) must be
  bypassable under the feature. Otherwise the fault never reaches `check`.

### 3.6 Security-envelope tests hardcode the degree (new, F23-2)

- `vm.rs:299` and `multi.rs:345` set `max_degree = 5` by hand for `params::security`.
- If a constraint of degree 6–8 were added, both tests would still compute the security
  figure for degree 5.
- **Fix:**
  - compute each table's degree with p3's `get_max_constraint_degree` (the symbolic builder,
    including the lookups after packing);
  - take the maximum;
  - assert `≤ MAX_CONSTRAINT_DEGREE`;
  - add a golden per-table degree vector: CPU 5, ALU_LT 4, every other table ≤ 3 [src; to be
    confirmed on the first run].
- Coordinate with 25 (the calculator input) and 22.

### 3.7 Blinding fail-open (terminal-blinding.md §6a; partially implemented)

- Zero-blinded traces satisfy every constraint. Only one test guards the real path
  (`every_table_of_a_real_proof_is_blinded_with_fresh_values`).
- **Hardening, no consensus change:** a type-state.
  - `build_multi` returns an `UnblindedTraces` newtype.
  - Only `randomize_blinding(UnblindedTraces, &mut impl CryptoRng) -> BlindedTraces` gives
    the `Vec<RowMajorMatrix>` that `blacksilk_zk::prove` accepts.
  - The oracle and tests use an explicit `.into_unblinded_for_tests()`.
- This touches the `blacksilk_zk::prove` call site in `prove.rs` only. **P2.**

### 3.8 Verify-path panics on malformed statements (F23-9)

- `Statement::shape` asserts that either every execution has a budget or none
  (`trace.rs:122-125`).
- `tables` asserts that the execution count is at most `MAX_EXECUTIONS` (`trace.rs:213`).
- `program::preprocessed` calls `expect` on `decode` (`program.rs:145`).
- `zkvm::prove::verify` calls these **before** `blacksilk_zk::verify`'s `catch_unwind`.
- These are **unreachable from network data today** [src]:
  - PX builds statements with all budgets;
  - `n_fn ≤ MAX_FN = 2`;
  - every consensus Program comes from `from_elf` (`tx/src/px.rs:615`) or embedded ELFs.
- Defence in depth: return `ZkError::Shape`. **P2.**

### 3.9 Documentation inaccuracies (F23-6)

- `lib.rs:5` says "strict RV32IM decoding", and `lib.rs:9-10` says the tables are "(ZK-3, in
  progress)". `Cargo.toml:5` says "(RV32IM)". The truth: RV32I + Zmmul, with no division,
  and the tables are complete.
- `exec.rs:11` gives timestamps as `4·clk + slot`. The code (`exec.rs:144`) and the spec use
  `4·(clk+1) + slot`.
- `cpu.rs:25-26` says "the witness is unique". This holds only for real rows, apart from the
  inverse witnesses; padding cells are free.
- `zkvm.md:26` (V3, "exactly one valid execution") and §9 item 3 (`zkvm.md:419`: "for each
  table, every column of a valid trace is mutated"). The actual coverage is real rows of
  CPU, MEM_INIT, POSEIDON2 and the ALU tables, plus public copies and blinding. PROGRAM
  multiplicities, IMAGE/OUTPUT dummies and all padding rows are not mutated (padding is
  free by design).
- `zkvm.md` §4/§5 lack the R4-03 exceptions.

---

## 4. New findings

| ID | Title | Severity | Status | Location | Scenario | Confidence |
|---|---|---|---|---|---|---|
| F23-1 | `CIRCUIT_ID` not bound to the actual AIR; no fingerprint test | Low | Not implemented | `zkvm/src/prove.rs:59`, `zkvm/tests/circuit_id.rs` | A post-freeze AIR edit forgets the bump. Mixed-version nodes then split on honest proofs, or a weakened constraint silently accepts old proofs. | High |
| F23-2 | Envelope and security tests hardcode `max_degree = 5`; no per-table degree assertion | Low | Partially implemented | `zkvm/tests/vm.rs:299`, `zkvm/tests/multi.rs:345` | A degree-6 constraint is added. The security figure is computed for 5 and the tests stay green. | High |
| F23-3 | Decoder conformance thin (R4-04 confirmed): no census, no exhaustive sweep, no riscv-tests/ACT4 | Low | Complete but requires further testing | `zkvm/src/isa.rs:325-565` | A latent decode divergence in a rarely emitted encoding changes kernel semantics. Found after the freeze, it is a consensus change. | High (gap) / low (a bug exists) |
| F23-4 | Differential generator misses JAL/JALR/AUIPC, backward branches, x0 destination, code/rodata loads, boundary addresses, multi-exec and budgets | Low | Partially implemented | `zkvm/tests/fuzz.rs:32,40-131` | These are the zkvmBlast bug classes (x0 writes, misaligned JALR). They are untested by the differential. | High |
| F23-5 | No fault-injection or coordinated-forgery tests; soundness evidence is a paper argument plus single-cell mutation | Low (evidence) | Not implemented | `zkvm/tests/*` | A consistent multi-cell forgery class (as in CVE-2025-52484) cannot be caught by the existing tests. None is known in BVM-1 [src]. | High (gap) |
| F23-6 | Doc and comment inaccuracies (RV32IM, "in progress", timestamp formula, "unique witness", V3, §9.3 coverage, R4-03 exceptions) | Informational | Not implemented | `zkvm/src/lib.rs:5,9-10`; `zkvm/Cargo.toml:5`; `zkvm/src/exec.rs:3-4,11`; `zkvm/src/air/cpu.rs:25-26`; `docs/zkvm.md:26,419` | A reviewer or second implementer is misled. The project policy forbids unverified claims. | High |
| F23-7 | R4-03 re-derived: exactly three exceptions (READ count, the up-front input length check, output count) | Accepted limitation | Accepted limitation (doc pending) | `zkvm/src/exec.rs:333-343,433-435` | None for security. | High |
| F23-8 | R4-07: degree 4 is reachable with zero new columns (SIGNED⇒LOAD, BR_NEG⇒BRANCH), but the packing budget halves (8→4); the net is unknown; chunk counts should be re-measured (R4 says 8→4, the source suggests 16→8 committed) | Informational (perf/arch) | Deferred | `zkvm/src/air/cpu.rs:348-353,380-386`; `p3-batch-stark common.rs:341`, `prover.rs:203` | An optimisation merged without measurement grows proofs. | Medium |
| F23-9 | Verify-path asserts and expects run outside `catch_unwind`; unreachable today | Informational | Not implemented | `zkvm/src/air/trace.rs:122-125,213`; `zkvm/src/air/program.rs:145`; `zkvm/src/prove.rs:209-211` | A future caller builds a mixed-budget statement from network data, and the node thread panics. | High (fact) / low (reach) |
| F23-10 | Blinding fail-open: zero-blinded traces are provable; only a test guards it | Low (privacy hardening) | Partially implemented | `zkvm/src/air/trace.rs:404-456`; `zkvm/src/prove.rs:181-199` | A new proving path skips `randomize_blinding`, and its proofs leak terminals. | High |
| F23-11 | Program periodic columns rebuilt on every call (R4 §3.7) | Informational (perf) | Not implemented | `zkvm/src/air/mod.rs:136-144` | Verifier CPU waste (up to 2^16 × 28 per call, at least 4 calls per program table). | High |

**No Critical, High or Medium soundness finding.** This matches R4. SX1 did not challenge
R4's soundness section.

---

## 5. Implementation plan (phase 2)

Ordered by priority. Ownership lists the exact files. None of W1–W9 changes consensus or
identity. W10 is a consensus change.

**W1: decoder census and exhaustive sweep (P0, S)**
- **Files:** new `zkvm/tests/isa_conformance.rs` (owned by 23). Optionally `pub fn` helpers
  in `zkvm/src/isa.rs` (a `#[doc(hidden)] pub const ALL_OPS`, which moves the existing
  test-local list).
- **Change type:** nothing externally visible. **Identity:** none.
- **Tests:**
  - census over opcode × funct3 × funct7 with field patterns (default);
  - the 2^32 sweep asserting `encode∘decode = id` except FENCE, per-op counts
    (193,495,041 in total), and the compressed classification (`#[ignore]`, nightly CI);
  - the invariants SIGNED⇒LOAD and BR_NEG⇒BRANCH over `program::fields`.
- **Bench:** time the sweep.
- **Docs:** `zkvm.md` §9 item 1.

**W2: circuit fingerprint bound to `CIRCUIT_ID` (P0, S)**
- **Files:** new `zkvm/tests/circuit_fingerprint.rs`, plus a small `pub fn fingerprint(...)`
  in `zkvm/src/air/check.rs` (23). `EvalBuilder`'s fields are private, so the function
  lives in `check.rs`.
- **Change type:** none. **Identity:** none (the test pins the current v1 digest).
- **Tests:**
  - the digest equals the pinned constant;
  - a mutation drill: changing one constant in a scratch copy changes the digest (the
    documented procedure).
- **Docs:**
  - `zkvm.md` §10;
  - `prove.rs:47-58` doc: the procedure "bump both together".

**W3: riscv-tests port (pure Rust) and zkvmBlast-class regressions (P1, M)**
- **Files:** new `zkvm/tests/riscv_tests.rs` and `zkvm/tests/riscv_tests/macros.rs` (23).
  If needed, small additions to `zkvm/src/asm.rs` (`la`, `j`, `nop`, `mv`), owned by 23.
- **Change type:** none.
- **Tests:**
  - rv32ui (all except `fence_i` and `ma_data`) and rv32um mul/mulh/mulhsu/mulhu;
  - each through the interpreter and `check`, one per class proven;
  - regressions: rd = x0 for every writing class; JALR to 2 mod 4 and 4k+1; a misaligned
    fetch; misaligned LW/LH/SW/SH; loads from code and from rodata below the code; x0 as
    base register.
- **Docs:** `zkvm.md` §9; an attribution note (BSD-3).

**W4: fault-injection forgery suite (P1, M)**
- **Files:**
  - `zkvm/src/exec.rs` (a `#[cfg(feature = "fault-injection")]` hook; off by default);
  - `zkvm/src/air/trace.rs` (skip the replay `assert_eq!` cross-checks under the feature);
  - `zkvm/Cargo.toml` (feature only, no new dependency);
  - new `zkvm/tests/forgery.rs`.

  All owned by 23.
- **Change type:** none (the feature is never enabled in node or wallet builds; CI checks
  that). **Identity:** none.
- **Tests:** at least 20 fault classes (§3.5). Each must be rejected by `check`; 3 are
  proven in release and must fail `verify`.
- **Docs:** the security-review §3 appendix, "tested forgeries".

**W5: derived degrees and a golden table-shape vector (P1, S)**
- **Files:** `zkvm/tests/vm.rs` and `zkvm/tests/multi.rs` (23). Coordinate with 25 on the
  `params::security` input.
- **Tests:**
  - per-table degree and constraint-count golden vector;
  - `max ≤ MAX_CONSTRAINT_DEGREE`;
  - assert the unique-decoding bound too (R4-12, shared with 25).

**W6: differential generator extension and a cargo-fuzz target (P1, M)**
- **Files:** `zkvm/tests/fuzz.rs` (23). A new `fuzz/fuzz_targets/zkvm_exec_diff.rs` plus a
  `fuzz/Cargo.toml` entry, owned by **41** with 23 as reviewer.
- **Generator additions:** all 43 ops; bounded backward loops; JAL/JALR call and return;
  rd = x0; aliasing; code and rodata loads; stores at CODE_END; POSEIDON2 at CODE_END and at
  `0x0FFF_FFC0`; 2–3 executions; budgets; `proptest` shrinking.
- **Campaign:** 10^5 programs nightly [est].

**W7: documentation corrections (P1, S)**
- **Files:**
  - `docs/zkvm.md` (§1 V3; §4/§5 R4-03 exceptions; §9 item 3 coverage wording; §6.3 note on
    the weight-0 boolean providers from R4 §2.2) (23, reviewed by 47);
  - `zkvm/src/lib.rs`, `zkvm/Cargo.toml`, `zkvm/src/exec.rs`, `zkvm/src/air/cpu.rs` (doc
    comments only).

**W8: blinding type-state (P2, S–M)**
- **Files:**
  - `zkvm/src/air/trace.rs`, `zkvm/src/prove.rs` (23);
  - the call sites in `zkvm/tests/*`;
  - `px/src/prove.rs` only if it calls `build_multi` directly (it calls `prove_shaped`
    [src]).
- **Change type:** none. **Tests:** a compile-fail doctest showing that unblinded traces
  cannot be proven.

**W9: verify-path hardening and the periodic cache (P2, S)**
- **Files:** `zkvm/src/air/trace.rs`, `zkvm/src/prove.rs`, `zkvm/src/air/program.rs`,
  `zkvm/src/air/mod.rs` (23).
- **Change type:** none (identical accept/reject on valid inputs).
- **Tests:** mixed budgets or 6 executions return `Err`, not a panic.
- **Bench:** verify time before and after (with 45).
- Optional R4-05 hardening: require `H == L` for PROGRAM, IMAGE and OUTPUT even when
  unshaped. This is consensus-neutral for PX, which is always shaped.

**W10: R4-07 degree reduction (P3, S code / M review)**
- **Files:** `zkvm/src/air/cpu.rs`, `zkvm/src/air/program.rs` (invariant docs), `CIRCUIT_ID`
  → v2, the W2 digest.
- **Change type:** **consensus.** New kernel budgets (with 20/22); new identity unless it
  rides the freeze.
- **Precondition:** a measured per-table breakdown (27/45) showing that the net committed
  width and the proving time improve despite the halved packing budget.
- **Tests:** W1 invariants, W2, W4 branch and signed-load faults, and every mutation test.

**Not recommended:** a READ counter (R4-03). Document instead.

---

## 6. Dependencies and conflicts

| Roster | Relation |
|---|---|
| **20** px-kernel | W10 changes kernel budgets. W3/W4 give conformance evidence for the kernel guest (the zmmul build). |
| **22** px-proof-system | `zkvm::prove::verify` interface (W9); the widest-proof measurement shares W5. |
| **24** plonky3-verifier-security | Confirm the quotient-chunk count (16 vs 8 committed at degree 5) and the packing-budget semantics (F23-8). |
| **25** zk-soundness | W5 supplies the correct `max_degree` to the calculator; the R4-12 assertion. |
| **26** zk-privacy | W8 blinding type-state; any AIR change (W10) re-triggers the blinding and P-5 checks. |
| **27** zk-performance, **45** benchmarks | The W10 measurement and the W9 verifier bench. |
| **41** fuzzing | Owns `fuzz/`; W6 target. |
| **42** mutation-formal | W4 is complementary to cargo-mutants. A ZEBRA/Picus-style determinism check of the ALU tables could be their formal item. |
| **43** ci-reproducibility | Nightly exhaustive sweep (W1); ACT4 fixture regeneration job; the fault-injection feature must never be enabled in release builds (a CI check). |
| **44** supply-chain | No new dependencies planned. `proptest` is already usable per roster 41. |
| **47** docs | W7 review. |
| **50** red-team | `CIRCUIT_ID` integration: W2 gives them a mechanical check. |

There are no file conflicts if 23 owns `zkvm/src/**` and `zkvm/tests/**` (except
`fuzz/`).

---

## 7. Open questions for the coordinator

1. **CIRCUIT_ID policy.** Should W2 be a P0 freeze gate, so that any AIR diff requires
   `CIRCUIT_ID` plus a new digest in the same commit?
2. **Offline non-Rust oracles.** May Sail/LLVM (ACT4) be used only to *generate* committed
   test fixtures, never in the build or at runtime? If not, W3's pure-Rust port is the
   ceiling of the conformance evidence.
3. **W10 (degree 4).** Should it be considered for the freeze at all? My recommendation: only
   with a measured net win. Otherwise defer to BVM-1.1.
4. **Nightly CI budget:** about 1 minute for the 2^32 sweep and the W6 campaign [est].
5. **R4-03:** confirm the doc-only resolution (no READ counter).

---

## 8. Sources

**Specifications:**
- RISC-V Unprivileged ISA 20191213 and 20240411 (Zmmul 1.0 ratified):
  https://docs.riscv.org/reference/isa/v20240411/unpriv/colophon.html ;
  https://courses.grainger.illinois.edu/ece391/sp2025/docs/unpriv-isa-20240411.pdf
- RISC-V ISA manual snapshot: https://riscv.github.io/riscv-isa-manual/snapshot/spec/
- Zmmul public review: https://groups.google.com/a/groups.riscv.org/g/isa-dev/c/okAISwX9usI

**Conformance suites:**
- riscv-tests: https://github.com/riscv-software-src/riscv-tests
- A zero-CSR custom env example (SystemScope PR #3):
  https://github.com/SystemScopeLabs/systemscope/pull/3
- riscv-arch-test / ACT4 (RISCOF deprecated; Sail 0.13.1 self-checking ELFs):
  https://github.com/riscv/riscv-arch-test/blob/main/README.md ;
  RISCOF docs https://riscof.readthedocs.io/en/stable/arch-tests.html
- ACT4 applied to zkVMs: https://github.com/eth-act/zkevm-test-monitor ,
  https://eth-act.github.io/zkevm-test-monitor/

**zkVM soundness literature and advisories:**
- Hochrainer, Wüstholz, Christakis, "Arguzz: Testing zkVMs for Soundness and Completeness
  Bugs", arXiv 2509.10819: https://arxiv.org/abs/2509.10819
- Takahashi, Jana, Yang, "Efficient Branch-and-Bound Testing and Verification of zkVMs"
  (ZEBRA), arXiv 2609.15020: https://arxiv.org/abs/2609.15020
- Ke, Liang, Li, "Consistency Verification for Zero-Knowledge Virtual Machine on
  Circuit-Irrelevant Representation" (ZIVER), ePrint 2025/2204:
  https://eprint.iacr.org/2025/2204
- zkSecurity, "Introducing zkvmBlast: Differential Fuzzing for Ethereum's zkVMs" (2026-08):
  https://blog.zksecurity.xyz/posts/zkvmblast/
- RISC Zero advisory GHSA-g3qg-6746-3mg9 / CVE-2025-52484 (rs1/rs2 confusion):
  https://github.com/risc0/risc0/security/advisories/GHSA-g3qg-6746-3mg9 ; related division
  CVE-2025-54873: https://app.opencve.io/cve/CVE-2025-54873
- Veridise / RISC Zero, Picus determinism verification:
  https://veridise.com/blog/zero-knowledge/risc-zeros-zk-vm-security-how-veridise-enabled-risc-zero-to-achieve-provable-continuous-zk-security/ ;
  Nethermind Lean work: https://www.nethermind.io/blog/towards-formal-verification-of-the-first-risc-v-zkvm
- Chaliasos et al., "SoK: What Don't We Know? Understanding Security Vulnerabilities in
  SNARKs", USENIX Security 2024: https://arxiv.org/pdf/2402.15293
- Kardas et al., "A Sound and Efficient AIR for 32-bit Division and Remainder", ePrint
  2025/2220 (reference for a future BVM-2 division table): https://eprint.iacr.org/2025/2220

**Memory checking and lookups:**
- Blum, Evans, Gemmell, Kannan, Naor, "Checking the correctness of memories", FOCS 1991 /
  Algorithmica 1994: https://link.springer.com/article/10.1007/BF01185212
- Setty, Angel, Gupta, Lee, "Proving the correct execution of concurrent services in
  zero-knowledge" (Spice), OSDI 2018: https://www.usenix.org/system/files/osdi18-setty.pdf
- Haböck, "Multivariate lookups based on logarithmic derivatives" (LogUp), ePrint 2022/1530:
  https://eprint.iacr.org/2022/1530 ; Papini and Haböck, ePrint 2023/1284:
  https://eprint.iacr.org/2023/1284

**Plonky3 0.7.0 source (read locally from the cargo registry):**
- p3-lookup `challenges.rs`, `logup.rs`;
- p3-batch-stark `transcript.rs:95-190`, `common.rs:308-381`, `prover.rs:131-205,340-355`,
  `symbolic.rs:53-105`;
- p3-poseidon2-air `columns.rs`;
- p3-air `symbolic/expression.rs:44-60`;
- p3-uni-stark `security.rs:47-83`.
