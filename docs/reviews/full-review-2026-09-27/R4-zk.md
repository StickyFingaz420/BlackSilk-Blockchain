# R4: ZK architecture and zkVM soundness review (internal, 2026-09-27)

> Historical record (2026-09-27). Superseded where it conflicts with the code: the ZK parameter set is BS-ZK-3 (73372e9; BS-ZK-4 pending). Current: [docs/consensus.md](../../consensus.md), [docs/STATUS.md](../../STATUS.md).

Reviewer: R4 (internal review agent). **This is an internal review, not an audit.** It is read-only: no builds were run and no repository file was changed. HEAD is `f677e55`.

**Scope:**
- `zk/src` (params BS-ZK-2, config, prove/verify);
- `third_party/p3-{fri,merkle-tree,dft}`, diffed against the registry copies;
- the Plonky3 0.7.0 crates in the cargo registry;
- `zkvm/src`: `isa.rs`, `exec.rs`, `program.rs`, `prove.rs`, and every AIR table in `air/*` (cpu, memory, alu_add, alu_bit, alu_lt, alu_shift, alu_mul, byte, program, poseidon, util/blind, trace);
- docs `zk.md`, `zkvm.md`, `reviews/{zk-coverage,terminal-blinding,zk-security-review,internal-review-log,query-policy,aggregation-study}.md`.

**Evidence tags:**
- **[math]**: mathematically established;
- **[test: name]**: tested;
- **[src]**: source-read;
- **[assumed]**;
- **[unknown]**;
- **[est]**: my estimate.

---

## 0. Executive summary

1. **No critical or high soundness defect found in BVM-1.**
   - I rebuilt the coordinated-forgery argument from the source, independently of `zk-security-review.md` §3. It covered:
     - every bus: providers, consumers, counts and weights;
     - the offline memory argument, including timestamp uniqueness across the CPU and Poseidon2 tables;
     - every range check and field-wrap point;
     - control flow;
     - the syscall and Poseidon2 binding;
     - cross-execution isolation;
     - the terminal-blinding bus.
   - The argument holds [src, math]. The periodic-repetition argument (internal-review-log F4, never written down) is written in §2.8. It is sound, and moot for consensus.
2. **`isa.rs` (first review ever): correct for RV32I + Zmmul** on every opcode, funct3/funct7 and immediate format I checked against the RISC-V specification [src].
   - A decoder bug could not break soundness relative to the interpreter: the decoder defines both sides.
   - It could make the VM deviate from RISC-V. Conformance evidence is therefore thin: there is no exhaustive table cross-check and no riscv-tests run (R4-04).
3. **The security figures (≥ 123 Johnson / ≥ 105 unique-decoding bits) are computed with a one-off domain size, by a calculator with known under-accounting bugs** (R4-01, medium).
   - `zk/src/params.rs:153` passes the pre-ZK trace height, but Plonky3 expects the post-ZK committed size.
   - Plonky3 0.8 (released 2026-09-23) fixed several 0.7 accounting bugs that *overstated* security (PR #2048).
   - My own arithmetic reproduces the unique-decoding figure: 108·log2(1/0.5625) + 16 = 105.6 bits, which is query-bound and domain-independent [math].
   - The Johnson figure must be re-derived.
4. **The FRI folding schedule is prover-chosen in 0.7** (fixed upstream in 0.8, PR #2033) and is bound to the transcript only after all folding challenges (R4-02, low). It can be closed verifier-side with no Plonky3 patch.
5. **Architecture: the proof is ~2.2 MB because of *committed width × 108 queries*, not computation.**
   - Two policy targets each force one expensive dimension:
     - the unique-decoding floor forces 108 queries;
     - the Johnson ≥ 120 target effectively forces the degree-8 extension, so every LogUp, quotient and out-of-domain column costs 8 base elements (R4-09).
   - Proving time (~45 s) is inflated by a build that uses **no SIMD** (R4-06; the cheapest large win, with no consensus impact), and by the CPU table's degree 5, which doubles its quotient work (R4-07).
6. **Plonky3 0.8 exists but is a transcript-breaking rewrite.** Stay on 0.7 for the testnet. Backport the two verifier-side hygiene checks, and plan 0.8 as a new parameter set after the trial (R4-10).

---

## 1. Findings table

| ID | Title | Class | Sev. | Conf. | Priority |
|---|---|---|---|---|---|
| R4-01 | Security calculator fed pre-ZK height; 0.7 calculator known to over-report; figures not independently re-derived | Complete but requires further testing | medium | high | P1 |
| R4-02 | FRI arity schedule chosen by the prover, bound after the betas (0.7; fixed in 0.8 #2033) | Partially implemented | low | high (fact) / medium (impact) | P2 |
| R4-03 | Circuit accepts > `MAX_INPUT_WORDS` READs and > `MAX_OUTPUT_WORDS` outputs (V3 "exactly" is false) | Accepted limitation | info/low | high | P3 (doc now) |
| R4-04 | `isa.rs`: correct, but no exhaustive or riscv-tests conformance evidence | Complete but requires further testing | low | high | P2 |
| R4-05 | Periodic-repetition argument: sound, written here; unshaped path only | Complete and verified (by argument) | info | high | P3 |
| R4-06 | Prover and verifier built without SIMD: Plonky3 falls back to scalar BabyBear on x86-64 | Not implemented | medium (perf) | high | P2 |
| R4-07 | CPU constraint degree 5 ⇒ 8 quotient chunks (the ZK maximum at blow-up 8) | Partially implemented (opt.) | low (perf/size) | high (fact) / est (gain) | P3 |
| R4-08 | Per-table fixed overhead: many thin tables (Image/Output dummies, 5 ALU tables, Blind) | Deferred | low (size) | medium | P3 |
| R4-09 | Parameter policy couples queries (UDR floor) and extension degree 8 (Johnson target) | Accepted limitation (policy) | info | high | P3 |
| R4-10 | Plonky3 0.7 pin vs 0.8: upgrade risk and backports | Deferred | medium (maintenance) | high | P1 (backports) / P3 (migration) |
| R4-11 | Transcript does not bind a circuit/AIR version | Not implemented | low | high | P2 (free at v3 reset) |
| R4-12 | Envelope tests assert only Johnson ≥ 100, use unshaped toy statements | Partially implemented | low | high | P2 |
| R4-13 | Recursion/aggregation is the only route below ~1 MB; realistic roadmap | Deferred | info | medium | P3 |

---

## 2. zkVM soundness (BVM-1 circuits)

### 2.1 Adversary model

The prover controls every main-trace cell of every table, all free multiplicities, and (for unshaped statements) all heights within the limits. The verifier fixes:
- programs, images and claimed outputs (periodic columns, bound by `statement_digest`);
- public values: entry, `CODE_END`, exit code, `N_OUT`, binding;
- the table list and exec ids;
- for PX, the exact heights (`prove.rs:192-206`).

### 2.2 Buses and LogUp accounting [src]

| Bus | Providers (weight) | Consumers (weight) | Check |
|---|---|---|---|
| RANGE / BYTE_OP | BYTE, public content, free mult. (0) | all tables, counts ∈{0,1} (1) | Every count expression was checked to be boolean or a sum of exclusive public flags: `real`, `write = rdw + f_ecall·srd`, `mem = f_ld + f_st`, `addr_use`, `computes`, `signed_load`, `real·(1−z)` in shift. The last is boolean because `z` is forced to {0,1} on real rows and 0 on padding (`alu_shift.rs:71-72`). |
| ALU | ALU tables, count `real` (0) | CPU (exclusive class flags), ALU_SHIFT→MUL (1) | Op ids are disjoint across tables. `c` is unique given `(a, b)` in every table (§2.5). |
| PROGRAM | PROGRAM, public, free mult. with `mult·(1−is_real)=0` | CPU, `real` | Program pcs are distinct, so each message is unique. |
| IMAGE | MEM_INIT, `ii` ∈ {0,1} | IMAGE periodic `is_real` (1) | Every image word must meet one `ii = 1` MEM_INIT row, and keys are unique (§2.3). |
| MEMORY | ±1 on both sides, all weight 1 | | Blum argument, §2.3. |
| OUTPUT | CPU, `swr` | OUTPUT periodic `is_real` | `OUT` starts at 0, steps by `swr`, and equals `N_OUT` at HALT (`cpu.rs:156-172`). So the outputs are exactly the claimed ones, in order. |
| SYSCALL | POSEIDON2, `real` | CPU, `sp2` | `(EX, CLK, ptr)` bijection: CPU clk is unique per exec. |
| BLIND | Blind, `real` | each table's first row, `sel` | `sel` = 1 on row 0 and 0 elsewhere (`util.rs:42-45`). |

Two further points:
- **Weight-0 providers with boolean counts** (CPU→OUTPUT, MEM_INIT→IMAGE, POSEIDON2→SYSCALL, Blind) are outside Plonky3's `Σ w·h < p` sum.
  - This is still sound. Their total is ≤ Σ heights ≈ 2^25 ≪ p, so provider − consumer ∈ (−p, p) and can vanish mod p only when it vanishes over the integers [math].
  - Please state this explicitly in the security review; §3.1 there says only that "boolean-constrained counts" make it harmless.
- Plonky3 0.7 **packs same-bus lookups** into shared columns up to each table's free quotient degree (`p3-batch-stark common.rs:318-345`, `Lookups::pack_same_bus`).
  - Packing adds the tuples' weights. The height bound is therefore unchanged, and the 63% figure [test: `the_logup_multiplicity_bound_holds_for_the_largest_statement`] still applies.

### 2.3 Memory argument [src, math]

**Produced timestamps** are only:
- 0 (MEM_INIT);
- `4·(clk+1)+slot` (CPU; `clk` chained from 0 by `nr·(n.clk − clk − 1)`);
- `4·(CLK+1)+3` (POSEIDON2, with CLK equal to a CPU clk through SYSCALL).

All are integers < 4·(2^21+1)+4 < 2^24. The CPU height is capped at `MAX_CYCLES`: `prove.rs:36` plus the exact height check.

**Consumed timestamps** `t_prev` satisfy `t − t_prev − 1 = d` with `d` in 3 bytes.
- A "negative" `t_prev` (a field element near p) is possible as a cell value.
- It can never match a producer, so it only unbalances the bus.

**Uniqueness of (exec, key, t)** among producers:
- slot 0/1: rs1/rs2 registers;
- slot 2: CPU memory word, only when `mem = 1`;
- slot 3: either the rd register (`write`) or the memory word (`f_st`). These are different key spaces.
- On a POSEIDON2 row the CPU has `mem = 0`, `write = 0` (RD_WRITE = 0 for ECALL, and `srd = 0` because the flags are one-hot).
- So the Poseidon2 accesses (16 distinct keys at slot 3; the slot-2 read is folded away) never collide with a CPU access of the same key and timestamp.
- Two Poseidon2 rows for the same `(e, clk)` would need two CPU consumptions of one message, which is impossible.

**Key spaces:**
- memory key `WK` = (s − (s mod 4))/4 with s < 2^28, so WK < 2^26 (`cpu.rs:314-318`);
- Poseidon2 keys: `KEY·4 = ptr`, with the CPU forcing `ptr < 0x0FFF_FFC1`, so KEY+15 < 2^26;
- registers: 2^26 + r, with r ≤ 31 from the public program.

The spaces are disjoint.

**MEM_INIT:**
- real rows form a prefix;
- keys are byte-decomposed and < 2^27, and strictly increasing via `D` < 2^27. There is no wrap because 2^28 < p;
- `ii = 0` forces a zero initial value;
- image keys need `ii = 1`, and uniqueness excludes a second, `ii = 0` row.

With those three facts, the per-key multiset equality forms a single chain from 0 to `t_final`, strictly increasing. So every read returns the last write (Blum et al.). Any key accessed but absent from MEM_INIT has an unmatched earliest consumption. **Holds.**

### 2.4 Values and ranges [src]

- **Every producer range-checks its bytes:**
  - CPU `cc` for every computing class, including READ (`computes`, `cpu.rs:137-144, 233`);
  - store `nn` (`cpu.rs:365`);
  - Poseidon2 outputs (`poseidon.rs:136`);
  - image values (public bytes);
  - zeros.
- Consumers (`A`, `B`, `M`, `CP`, Poseidon2 inputs) therefore hold bytes by induction over the chain. This relies on message equality being componentwise, which holds w.h.p. over the 247-bit field.
- **Canonicity in Poseidon2:** the check `x3 + 136 − 120e` is a byte. On its own it would admit `x3 ∈ [p−136, p)` for an unchecked `x3`. It is only sound because output bytes are range-checked and input bytes come from the bus. The comment at `poseidon.rs:17-20` says this; keep it as a documented invariant.
- **Addresses and targets:**
  - `s = a + imm` comes from ALU_ADD, and `s3 < 16`;
  - `s0 = l0 + 2·l1 + 4h` with h < 64;
  - the NULL guard and `CODE_END` checks are ALU SLTU lookups with constant result 0;
  - alignment: `kw·l0 = kw·l1 = kh·l0 = 0`.
- **pc:**
  - `PC = word(pb)` with pb < 2^28 on real rows;
  - branch/JAL targets use the signed field immediate. A negative wrap yields a field element ≥ 2^28, which fails the next real row's range check or the PROGRAM lookup. This is consistent with the interpreter trapping at fetch.

### 2.5 ALU determinism [src, math]

- **ADD/SUB:** byte carries are boolean and every equation is < 2^10.
- **LT:** `b + d = a + 2^32·k3`.
  - Signed: `sa(1−sb) + [sa=sb]·k3`, correct.
  - EQ: via `s = Σd_i ≤ 1020`, so zero ⇔ all zero.
- **MUL:**
  - the largest column sum is 8·255² + carry ≤ 524,295 < 2^20;
  - `carry ≤ 2,048 < 2^12`;
  - the representation is unique;
  - sign extension to 8 bytes gives the correct high word for MULH and MULHSU [math].
- **SHIFT:**
  - `s` is the low 5 bits of `b0`, with `b0 = s + 32·hb`, hb < 8, and b1..b3 range-checked;
  - `P = 2^e` as bytes, where `e = s` (SLL) or `32 − s`;
  - SRA = MULHSU(a, 2^(32−s)) = ⌊a/2^s⌋ [math];
  - `s = 0` bypasses the multiplier with `c = a`.
- **No free cell changes an output.** The only free cells are the inverse witnesses. This matches §3.3 of the security review.

### 2.6 Control and syscalls [src]

- The first row is real with clk = 0, pc = entry, OUT = 0. Real rows are contiguous, the last real row must HALT (including on the last trace row), and nothing follows a HALT.
- **ECALL:**
  - rs1 = 17 and rs2 = 10 are fixed by `program::fields`;
  - `a7 ∈ {0,1,2,3}` with one-hot flags whose sum equals `f_ecall`, and `a[1..3] = 0`;
  - exit code = x10 at HALT;
  - READ writes x10 with a *free* range-checked value. This is correct: the input is witness.
  - POSEIDON2: `CODE_END ≤ ptr < 2^28 − 63`, 4-aligned (Poseidon table `ptr0 = 4·PH`). This matches the interpreter's per-word `check_addr(.., store=true)`.
- **x0:** `RD_WRITE = writes ∧ rd ≠ 0`, the ECALL write targets x10 only, and the image sets x0 = 0. So x0 always reads 0.
- **Padding CPU rows are inert:** every INS field is 0, so the flags, counts and syscall flags are 0. Unconstrained padding cells (NEXT_PC, OUT, PB, …) touch no bus. This is harmless for soundness, and for ZK because they are committed and hidden like everything else.

### 2.7 Cross-execution isolation [src]

- MEMORY, PROGRAM, IMAGE, OUTPUT and SYSCALL messages carry the exec id: an AIR constant in the per-execution tables, and the `EX` column in POSEIDON2, bound through SYSCALL to the caller's constant.
- ALU and BYTE are pure functions.
- Timestamps restart per execution but are tag-separated.
- The binding is repeated in every CPU's public values.
- Table order and count follow from the statement (`trace::tables`); heights come from `Statement::shape`.

**Holds.**

### 2.8 The periodic-repetition argument (F4, written down) [src, math]

- Plonky3 evaluates a periodic column of length L on a trace of height H ≥ L as `col[i mod L]`. It rejects L > H (`check_periodic_column_lengths`, `p3-batch-stark verifier/mod.rs:703-704`).
- If H = k·L with k > 1, every public row repeats k times:
  - **PROGRAM:** k copies of each `(e, pc, fields)` with separate free multiplicities. Only their sum matters, so this is harmless.
  - **IMAGE:** each image word is *consumed* k times, but MEM_INIT can provide each key at most once (unique keys). So k > 1 is unsatisfiable.
  - **OUTPUT:** each output is consumed k times, but CPU `OUT` indices are unique, so this is unsatisfiable.
  - **BYTE:** fixed height 2^16 = L.
- So repetition never admits a false statement. At worst it makes a true one unprovable.
- In consensus it cannot occur: shaped statements set the Program, Image and Output heights exactly to their period (`trace.rs:128-135`, `prove.rs:194-206`).
- *Hardening (optional, P3):* reject H ≠ L for these three tables in `verify` for unshaped statements too, so the argument is no longer needed at all.

### 2.9 isa.rs (first review) [src]

**Checked against RISC-V Unprivileged ISA 20191213 plus Zmmul:**
- U, J, B, S and I immediate bit positions, and sign extension;
- JALR requires funct3 = 0;
- branch funct3 {0,1,4,5,6,7};
- loads {0,1,2,4,5}: LD and LWU rejected;
- stores {0,1,2};
- OP-IMM: shift immediates require bits 31:25 = 0, or 0100000 for SRAI, so RV64 `shamt[5]` is rejected;
- OP: all ten RV32I ops plus MUL/MULH/MULHSU/MULHU; DIV and REM rejected;
- MISC-MEM funct3 = 0 only (FENCE.I and CBO rejected);
- SYSTEM exactly `0x00000073`: EBREAK, CSR, WFI and xRET rejected;
- 16-bit and longer encodings rejected.

**Observations:**
- **FENCE with any fm/pred/succ/rd/rs1 is a no-op.** This includes FENCE.TSO and PAUSE, and the reserved rd/rs1 ≠ 0 forms that the spec asks implementations to treat as ordinary fences. Correct.
- **HINT encodings** (e.g. `addi x0, x0, imm ≠ 0`, `lui x0, …`) are accepted and computed. The write is dropped, and the CPU still range-checks the value. Correct.
- **Branch and JAL targets that are 2- but not 4-aligned** are rejected at the next fetch (interpreter) or by the PROGRAM lookup (circuit), not at the jump as the spec says. Since both "trap", this is equivalent for BVM.
- `encode` is only an inverse on valid instructions, and panics on bad registers (test-only use).

**Why a decoder bug is not a soundness bug:** the interpreter (`exec.rs:215`), the loader (`program.rs:203`) and the verifier's PROGRAM table (`air/program.rs:145`) all use `decode`. A decoding error would therefore be *consistent* between prover and verifier. It would be a divergence from RISC-V (miscompiled guests, kernel A5), not a false-statement acceptance.

**Current evidence:**
- [test: `encode_decode_round_trip_for_every_op`];
- 9 known encodings;
- 16 illegal and 4 compressed words;
- guests compiled by rustc run natively and in the VM (px kernel tests).

This is thin for a consensus-critical decoder (R4-04).

---

## 3. ZK layer: parameters, configuration, verify path

### 3.1 BS-ZK-2 soundness arithmetic [math]

| Term | Value |
|---|---|
| UDR per-query error | (1+ρ)/2 = 0.5625, i.e. 0.830 bits |
| UDR, 108 queries | 89.6 bits, + 16 grinding = **105.6** |
| Johnson per-query | ≈ √ρ = 0.354, i.e. ~1.5 bits; 108 queries give ~162 + 16 bits |

- The reported 123 Johnson bits are **not** query-bound. They come from the collision term (8-element Poseidon2 digests, ≈ 123.6 bits) and the commit-phase/batching terms, whose |D|² scaling needs the 247-bit field.
- Hence the policy picture in R4-09: in the Johnson regime, ~70 queries would suffice, as query-policy.md measured.
- **Eq. (17) couples the parameters:** 2·(8 + 108) = 232 ≤ 256 = min height. Any query count > 120, or a higher extension degree, breaks it at `MIN_LOG_HEIGHT = 8`. Keep the `const` assertion, and treat queries, extension degree and minimum height as one parameter triple.

### 3.2 R4-01: calculator inputs and calculator version (medium, P1)

**Facts [src]:**
- `zk/src/params.rs:153` calls `ProvenSecurity::compute(&p, 1 << shape.log_height)`, with `log_height ≤ MAX_LOG_HEIGHT = 22` in the envelope test (`params.rs:185`), `zkvm/tests/multi.rs:364` and `vm.rs:307`.
- Plonky3's API says the argument must be the committed-polynomial size *post-ZK* (`p3-uni-stark-0.7.0/src/security.rs`, doc of `compute_from_proof`: "`degree_bits` already reflects the committed-polynomial size (post-zk padding)").
- Under ZK the committed domain is 2H (`degree_bits = log2(H)+1`, `zk/src/lib.rs:142`). The envelope therefore analyses domains one bit too small.
- `StarkSecurityParams::new` itself warns that "This does not account for zk" (`security.rs:70-72`).
- **Plonky3 0.8 PR #2048 ("accounting and grinding hygiene fixes") lists 0.7 bugs that *overstated* security:**
  - the ZK quotient-chunk doubling was not applied;
  - `LOG2_E` was rounded down (0.7 `p3-security/src/fixed.rs:24`: `94_548`);
  - `compute_upper_m` used `ceil`;
  - `best_ldr_m` ignored grinding in the batching term;
  - a folding-coefficient overflow could drop rounds.
  - BlackSilk already avoids the headline "`num_batched_functions = 1`" bug: it passes the committed column count.
- Separately, 0.8 PR #2282 replaced the Johnson bound with DKT26, which *raises* the figures. So 0.7 is conservative in that respect only.

**Impact [est]:**
- The UDR figure is query-bound and domain-independent (§3.1), so 105 is very likely right.
- The Johnson figure (123) may move by a few bits in either direction. The documents' "≥ 123 bits" claim is therefore *not* established to the stated precision.

**Scenario:** an external reviewer recomputes with post-ZK degree bits and the corrected formulas, and finds, say, 119–121 Johnson bits at 2^23 × 6,000 columns. The "≥ 123" claim in `zk.md`, `zkvm.md` §7 and `query-policy.md` is then wrong. Soundness is unchanged; the documented margin is not.

**Recommendation:**
- pass `log_height + 1` (or call `compute_from_proof(degree_bits)`) everywhere;
- assert UDR ≥ 100 in the two shape tests (R4-12);
- cross-check the two headline numbers with an independent calculator: 0.8 `p3-security` in a scratch crate, or ethereum `soundcalc`, which 0.7 says it was checked against;
- record the calculator version next to every figure.

| Dimension | Assessment |
|---|---|
| Why | Accuracy of the headline security claims (owner policy: no unverified claims) |
| Security impact | None on the protocol; corrects the evidence |
| Privacy impact | None |
| Performance impact | None |
| Complexity | S |
| Consensus impact | None |
| Testnet identity | None |
| Difficulty | S |
| Priority | P1 |

### 3.3 R4-02: prover-chosen FRI folding schedule (low, P2)

**Facts [src]:**
- The 0.7 verifier (`third_party/p3-fri/src/verifier.rs:218-232`) reads each round's `log_arity` from the proof and checks only three things:
  - each arity is in `1..=MAX_LOG_ARITY` (4);
  - the arities sum to the global height (`:247-279`);
  - the per-query sibling count.
- The schedule is observed into the transcript **after all commit-phase betas** (`:319-322`).
- Upstream fixed this in 0.8 (PR #2033, "derive the folding schedule instead of accepting the prover's"). Its test shows that a proof with a non-configured schedule (e.g. `[3,1]` vs `[1,3]`) was accepted.

**Impact:**
- **Malleability:** the prover, not third parties, can produce structurally different valid proofs.
- **Soundness analysis:** the calculator assumes the configured schedule [assumed]. A prover that picks round i+1's arity after seeing β_i gets at most 4 choices per round. That multiplies the commit-phase error by ≤ 4^rounds. With |F| = 2^247 that is negligible [est], but it is outside the analysed protocol.

**Recommendation:** in `zk::verify`, before Plonky3, recompute the honest 0.7 prover's schedule from the claimed heights, `LOG_BLOWUP`, `LOG_FINAL_POLY_LEN` and `MAX_LOG_ARITY`, and reject any `commit_phase_openings[i].log_arity` that differs.

| Dimension | Assessment |
|---|---|
| Why | Close an upstream-acknowledged verifier gap without patching Plonky3 |
| Security impact | Removes an unanalysed degree of prover freedom |
| Privacy impact | None |
| Performance impact | None |
| Complexity | S. The only care needed is to derive the schedule exactly as the 0.7 prover does [unknown: read `p3-fri` prover's `fold_schedule` equivalent] |
| Consensus impact | CONSENSUS: a tightening that rejects only non-honest proofs |
| Testnet identity | Do it with the v3 genesis reset; no new identity by itself |
| Difficulty | S |
| Priority | P2 (P1 if it rides the reset) |

### 3.4 R4-03: circuit ⊋ interpreter on stream lengths (info/low)

**Facts [src]:**
- `exec.rs:333-336, 342-343, 433-435` trap on the input or output limit.
- The circuit has no counter for READs, and `OUT` is bounded only by the CPU height. So an execution that performs more than 2^16 READs is provable, though the interpreter rejects it.
- `zkvm.md` §4 claims "The constraint tables must accept exactly the executions this interpreter produces" (also `exec.rs:3-4`).
- **Security impact nil:** the input is private witness, and a guest cannot observe the end of input except by trapping. The output part is known (internal-review F1; PX pins output lengths).

**Recommendation (P3, doc-only now):** state the two exceptions in `zkvm.md` §5 and §9, or add a READ counter.

| Dimension | Assessment |
|---|---|
| Consensus impact | None for the doc; CONSENSUS for a counter |
| Difficulty | S |

### 3.5 R4-11: no circuit version in the transcript (low)

**Facts [src]:**
- The challenger absorbs `PARAMS_ID = "BlackSilk/zk/BS-ZK-2"` and the statement digest (`zk/src/config.rs:76-85`), but nothing identifying the BVM-1 AIR revision.
- The AIR changed at least twice under the same `PARAMS_ID`: terminal blinding, and minimum height.
- Cross-version acceptance would still require the old proof to satisfy the new constraints, so this is defence in depth, and it makes proof and transcript domain separation explicit.

**Recommendation:** add a `BVM_CIRCUIT_ID` (a tag plus a version) to `statement_digest`.

| Dimension | Assessment |
|---|---|
| Consensus impact | CONSENSUS |
| Testnet identity | Free if done with the v3 reset |
| Difficulty | S |
| Priority | P2 |

### 3.6 R4-12: envelope tests (low)

**Facts [src]:**
- `zkvm/tests/multi.rs:336-372` and `vm.rs:293-320` assert only `johnson_bits ≥ MIN_PROVEN_BITS (100)`. They do not assert `unique_decoding_bits ≥ 100`, which is the project's actual floor.
- They use unshaped `prove_multi` statements of toy programs. Width is shape-independent, so the column count is fine. The quotient-chunk count depends on the periodic/trace ratio, which the doc comment addresses.

**Recommendation:**
- assert both targets;
- add the real shaped PX two-function statement. This ties in with the known "widest two-function proof size unmeasured" item.

| Dimension | Assessment |
|---|---|
| Consensus impact | None |
| Difficulty | S |
| Priority | P2 |

### 3.7 Verify path: other observations [src]

- **Hardening is correct:**
  - table count, degree bits (per-table caps), and permutation and terminal counts are checked before Plonky3;
  - `catch_unwind`;
  - strict canonical decoding;
  - exact shapes for budgeted statements.
- **Minor verifier cost:**
  - `Table::periodic_columns()` rebuilds `program::preprocessed` (up to 2^16 × 28) on *every* call. The verifier calls it at least three times per program table: symbolic degree, length check and evaluation, plus `statement_digest`.
  - The byte table is cached (`byte.rs:28-31`); programs are not.
  - Cache per `Arc<Program>`. Perf only (P3).
- **ZK-F3** (VerifierConfig reuse) and **ZK-F4** are known; nothing new.

---

## 4. third_party patches (hiding PCS, hiding MMCS, DFT) [src]

Diffed with `--strip-trailing-cr` against `p3-*-0.7.0` in the registry:
- **`hiding_pcs.rs`:**
  - `commit` and `get_quotient_ldes` draw exactly the same values in the same order under the lock, then `widen` outside it;
  - `w` is recomputed as `evaluations[0].width() + num_random_codewords`, which equals upstream's widened width;
  - the unit test `widen_matches_with_random_cols` pins the equivalence;
  - `get_opt_randomization_poly_commitment` holds the lock only for `DenseMatrix::rand` (sequential).
- **`hiding_mmcs.rs`:** salts are drawn under the lock; tree construction happens after it.
- **`radix_2_dit_parallel.rs`:** twiddles are computed outside the write lock, first insert wins, and the tables are deterministic.

**Verdict:** the patches are minimal, preserve the values, and are correct.
- **Residual risk:** the tests of these crates are not run in CI (known).
- **Upgrade risk:** per `third_party/README.md`, 0.8 still holds the lock in the p3-fri/p3-merkle-tree sites, so the patches must be re-ported on migration.
- 0.8 also adds "require a cryptographic RNG for HVZK mask sampling" (#2260). BlackSilk already uses `StdRng` seeded from a hedged OS-RNG digest (`config.rs:128-149`), so nothing to do.

**Never change:** the rule that every `lock()` in these crates does sequential work only.

---

## 5. Architecture: proof size and proving time

### 5.1 What dominates

**Proof size** follows from `aggregation-study.md` §1 (measured) and my source reading:
- About 92% of the 2.04–2.18 MB scales with 108 queries.
- **Opened rows are 60%.** Their size is Σ over committed base columns of 4 bytes, per query.
- Three committed rounds are roughly equal (18.8–19.8% each): main, LogUp permutation, and quotient chunks. The quotient share is surprisingly large. It comes from:
  - **extension degree 8:** every aux (LogUp) column and every quotient chunk is 8 base columns;
  - **the CPU's degree-5 constraint:** under ZK, `log2_ceil(d)` = 3, i.e. **8 quotient chunks = 64 base columns**. That is the ceiling at blow-up 8 (`p3-batch-stark common.rs` budget formula; test comment `vm.rs:302` confirms degree 5);
  - **per-table fixed overhead** ×13 to 23 tables:
    - 9 blinding columns;
    - 12 `R` columns;
    - 4 random codewords per committed matrix;
    - ≥ 2 quotient chunks;
    - ≥ 1 aux column.
    - That is roughly 60–120 base columns per table even for Image/Output tables with one real column [est].
- **Hiding salts (10%) and out-of-domain openings (6.4%)** also scale with width, the latter at 32 B per column per point.

**Proving time (~45 s):**
- There are no per-phase measurements in the repository [unknown].
- Structural drivers [src, est]:
  1. **Scalar field arithmetic on x86-64 (R4-06).**
     - `p3-monty-31` selects AVX2/AVX-512 packing only under `cfg(target_feature)` (`p3-monty-31-0.7.0/src/lib.rs:24-47`).
     - The workspace has no `.cargo/config.toml` and no `rustflags`.
     - So every DFT, every Poseidon2 Merkle hash and every quotient evaluation runs on scalar BabyBear.
     - (aarch64 enables NEON by default, so ARM Macs are already packed.)
  2. **LDE size:** 2 (ZK) × 8 (blow-up) × height, for ~3,100 base columns (single execution, measured M3).
  3. **Quotient evaluation in the degree-8 extension**, over 8·2H points for the CPU (degree 5) instead of 4·2H at degree 4.
  4. **Fixed per-table and 2^16 byte-table costs.** The byte table is the tallest table of a transfer (the CPU is 2^15 for `n_fn = 0`).

### 5.2 R4-06: SIMD build for the prover (medium perf, P2)

**Recommendation:**
- Build the wallet/prover (and optionally the node) with `-C target-feature=+avx2`, or ship baseline and AVX2 binaries.
- Measure with `proof_bench` before and after. Plonky3's AVX2 BabyBear and Poseidon2 are typically several times faster than scalar [assumed; measure].

| Dimension | Assessment |
|---|---|
| Why | The largest available prover speed-up |
| Security impact | None: field arithmetic is exact, so proofs verify identically |
| Privacy impact | None |
| Performance impact | Large [est] |
| Complexity | S |
| Consensus impact | None. If applied workspace-wide, re-run the RandomX vectors under the new flags (Rust does not contract FMA, but verify) |
| Testnet identity | None |
| Difficulty | S |
| Priority | P2 |

### 5.3 R4-07: CPU degree 5 → 4 (P3, measure first)

**Facts [src]:** the degree-5 constraints are:
- `real·(NEXT_PC − …f_br·taken·(imm_f−4)…)` (`cpu.rs:348-353`), with `taken` of degree 2;
- `signed_load·(kb·sel_b + kh·half_hi − 128·sgn − sr)` (`cpu.rs:384-385`), with `sel_b` of degree 2.

**Recommendation:**
- One committed `TAKEN` column (constrained to `cond + br_neg(1−2cond)`), or dropping the redundant `real·` factor, since padding rows can satisfy `NEXT_PC = PC+4`.
- A `SEL_B` column.
- Together these bring the CPU to degree 4 ⇒ 4 quotient chunks: −32 committed base columns, and half the CPU quotient-evaluation domain.
- *Caveat:* Plonky3's same-bus lookup packing budget for the CPU drops from 8 to 4 with it, so aux columns may grow. The net effect must be measured with a per-table breakdown.

| Dimension | Assessment |
|---|---|
| Consensus impact | CONSENSUS (circuit) |
| Testnet identity | New identity unless done at the reset |
| Difficulty | S–M, including the mutation and forgery-review cycle |
| Priority | P3 |

### 5.4 R4-08: table consolidation (P3)

- Merge each execution's IMAGE and OUTPUT (both "1 dummy column + 6 periodic copies", same message layout), or all executions' public tables into one periodic table with an exec column.
- Merge the ALU tables (the study's candidate).
- Consider the exclusive-lookup API (`LookupBus::lookup_key_exclusive`, p3-lookup 0.7) for the CPU's mutually exclusive ALU requests.
- Expected: roughly 5–10% width for multi-execution proofs [est].

| Dimension | Assessment |
|---|---|
| Consensus impact | CONSENSUS |
| Difficulty | M |

### 5.5 R4-09: parameter policy insight (info)

- **UDR ≥ 100 alone** needs ~102–108 queries. Its field-dependent terms would be comfortable at a degree-5 or degree-6 extension (|F| ≈ 2^155 to 2^186) [est].
- **Johnson ≥ 120 alone** needs ~70 queries, but its |D|²-type commit and batching terms need the 247-bit field at 2^23 domains [est].
- **Requiring both** buys the worst of each:
  - 108 queries, with ~92% of bytes scaling linearly;
  - an 8-wide extension on every LogUp, quotient and OOD column, and on the blinding values (`BLIND_VALUES = 8`, which must equal the degree).
- **Options for the owner after the trial** (each a new parameter set with its own identity):
  - (a) keep both;
  - (b) UDR floor with a smaller extension (loses the Johnson target);
  - (c) Johnson target with ~70–80 queries plus 20–24 grinding bits (loses the proven-UDR floor);
  - (d) keep both and **raise grinding 16 → 20–22 bits**. That removes ~5–7 queries (−5–6% size) for ~1–4 s of prover grinding at scalar speed, less with SIMD [est]. It is the cheapest safe lever.
- Re-check eq. (17) for every option.

### 5.6 R4-13: realistic roadmap

| Stage | Items | Consensus |
|---|---|---|
| Before testnet (no identity change) | R4-06 SIMD build and a phase profile (Plonky3 `info_span`s are already there); R4-01 recomputation and doc correction; R4-12 tests | none |
| At the v3 genesis reset (if the owner approves) | R4-02 schedule check; R4-11 circuit id. Both are tiny, verifier-side, and reject only dishonest proofs | CONSENSUS |
| After the trial: BVM-1.1 / BS-ZK-3 | R4-07 degree reduction; R4-08 consolidation; the study's Poseidon2 field-element memory interface (−224 columns); grinding 20–22; kernel trimmed so `n_fn = 2` fits in 2^15 cycles (35,600 → < 32,768 halves that CPU table; kernel id change). Expected ~1.5 MB and ~2× faster proving, compounded with SIMD [est] | CONSENSUS, new identity |
| Plonky3 0.8 migration | New typed Fiat–Shamir transcript (#1603/#2090/#2091); fold-schedule and shape derivation (#2033, #2107, #2125); corrected calculator; multilinear lookups and logUp* (#1968, #2145), which could remove most LogUp aux width; WHIR (`p3-whir`) as a research PCS. Re-port the lock patches; re-review blinding (does 0.8 change how terminals are published?) | new parameter set |
| Mainnet-capacity step | Recursion/aggregation with `Plonky3-recursion` (supports p3-batch-stark and ZK FRI in-circuit; **unaudited, pre-production** per its README). One proof per block; target of the order of 10^2 KB [est]. Its own milestone and review, as `aggregation-study.md` §3.3 says | new consensus |

---

## 6. Plonky3 version pinning and upgrade risk (R4-10)

**Current pinning is good:** `=0.7.0` on every p3 crate in `zk` and `zkvm`, three `[patch]` crates copied verbatim plus reviewed diffs, and a lockfile. Missing: `--locked` in CI (known), and the third_party test suites in CI (known).

**0.8.0 (2026-09-23)** is a breaking release:
- the typed Fiat–Shamir layer changes the transcript for every protocol, so no proof is compatible;
- API changes in `p3-fri`, `p3-lookup` and `p3-batch-stark`;
- the lock bugs are still present in two of the three patched sites.

**Security-relevant 0.8 changes that 0.7 lacks:**

| PR | Change | BlackSilk exposure |
|---|---|---|
| #2033 | Fold schedule derived | R4-02 |
| #2107, #2125 | Shape fields pinned or derived from the config | BlackSilk already checks heights and counts strictly and absorbs degree bits and widths (`observe_instance_binding`) [src] |
| #2048 | Calculator fixes | R4-01 |
| #2105, #2106 | Non-canonical grinding witnesses at zero difficulty | Commit PoW bits = 0 here; the witness is still checked by `check_witness`, and the effect is malleability at most [unknown for 0.7] |
| #1947 | Public inputs bound by trace position | [unknown relevance] |

**Recommendation:**
- Do **not** migrate before the testnet.
- Backport R4-02 verifier-side now (P1 if riding the reset, else P2).
- Track 0.8.x advisories.
- Plan the migration as a new parameter set with the full review cycle (P3).

| Dimension | Assessment |
|---|---|
| Consensus impact | Backports: CONSENSUS (tightening); migration: new identity |
| Difficulty | Backports S; migration L |

---

## 7. The 13 questions, per subsystem

| # | zkVM circuits (AIR, buses, memory) | ISA and interpreter | ZK layer (params, config, verify) | Patches and Plonky3 |
|---|---|---|---|---|
| 1 Implemented | 13 table kinds, 9 buses, offline memory, multi-exec tags, fixed shapes, terminal blinding | Strict RV32I + Zmmul decoder; normative interpreter with a witness | BS-ZK-2, hiding FRI, statement digest, hardened verify | 3 lock-scope patches; 0.7 pinned |
| 2 Correct and well designed | Everything argued in §2; no free cell affects outputs; field-wrap guards complete | Decoding verified field by field (§2.9) | Strict decoding, pre-checks, catch_unwind, exact shapes | Minimal, value-preserving |
| 3 Incomplete | V3 exceptions (R4-03) | Conformance evidence (R4-04) | Calculator inputs (R4-01); schedule check (R4-02) | CI does not run the p3 tests |
| 4 Fragile | Soundness of canonicity and consumer bytes relies on the "all producers range-check" invariant: every new producer must keep it | Decoder shared by all sides: one bug moves the whole system | Eq. 17 couples queries, extension and minimum height; blinding width = extension degree | Patches must be re-ported on every upgrade |
| 5 Exploitable | Nothing found [src] | Nothing (consistency by construction) | Prover-chosen arity (R4-02): malleability; negligible soundness impact [est] | — |
| 6 Inefficient | Degree-5 CPU; thin tables; Poseidon2 memory interface | — | Program periodic columns rebuilt per call | No SIMD build (R4-06) |
| 7 Does not scale | ~2 MB per tx, about 3–4 PX tx per block | — | Linear in queries × width | — |
| 8 Missing | Written periodic argument (now §2.8); weight-0 boolean-provider note | riscv-tests; exhaustive table | Circuit id in the transcript (R4-11) | — |
| 9 Redesign | LogUp aux width (multilinear/logUp* in 0.8), table consolidation | — | Parameter policy (R4-09), after the trial | 0.8 migration |
| 10 Innovate | Field-element memory for hash buffers; precompile tables beyond Poseidon2 (e.g. a U256/limb table for kernel arithmetic) to cut cycles | — | WHIR/STIR PCS; recursion and aggregation | — |
| 11 Before testnet | — | — | R4-01 (docs and tests), R4-12 | R4-06 (optional, no consensus); R4-02 and R4-11 only if riding the reset |
| 12 Defer safely | R4-07, R4-08 | R4-04 | R4-09 | Migration to 0.8 |
| 13 Never change | Exec tags on every non-pure bus; strict key ordering in MEM_INIT; `t − t_prev − 1` 3-byte check with the `MAX_CYCLES` cap; fixed shapes; blinding selector pattern | Rejecting DIV/REM/CSR/compressed; decode shared by loader, interpreter and verifier | Statement digest before any challenge; UDR floor (unless deliberately re-decided); minimum height ≥ eq. 17; `catch_unwind` with `panic = "unwind"` | Exact pins; "no rayon work under a spin lock" |

---

## 8. Sources

- Plonky3 v0.8.0 release: https://github.com/Plonky3/Plonky3/releases/tag/v0.8.0
- PR #2033 (fold schedule derived): https://github.com/Plonky3/Plonky3/pull/2033
- PR #2048 (accounting and grinding hygiene fixes): https://github.com/Plonky3/Plonky3/pull/2048
- PR #2282 (DKT26 Johnson bound): https://github.com/Plonky3/Plonky3/pull/2282
- p3-lookup / p3-batch-stark 0.8.0 releases: https://github.com/Plonky3/Plonky3/releases/tag/p3-lookup-v0.8.0 , https://github.com/Plonky3/Plonky3/releases/tag/p3-batch-stark-v0.8.0
- Plonky3-recursion (unaudited, in development): https://github.com/Plonky3/Plonky3-recursion
- Haböck and Al Kindi, ePrint 2024/1037 (ZK for STARKs), as cited in `zk-coverage.md`.
