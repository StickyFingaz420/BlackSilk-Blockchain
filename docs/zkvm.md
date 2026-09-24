# BVM-1: the BlackSilk zero-knowledge virtual machine

Status: **specification v0.3; implemented and tested, including the Poseidon2 syscall
circuit and multi-execution proofs** (AUDIT.md R8; internal security review
`docs/reviews/zk-security-review.md`). Not consensus; not production-ready before
independent review.
This document is normative:
- the reference interpreter (`zkvm/src/exec.rs`) and the constraint tables
  (`zkvm/src/air/`) implement exactly what it says;
- the tests check both against it, and against each other.

It builds on [`zk.md`](zk.md): proof system and parameters §9, kernel §6, private
functions §7.

---

## 1. Goals

| # | Goal |
|---|---|
| V1 | Contract authors write **ordinary Rust**, compiled for `riscv32im-unknown-none-elf` with the BlackSilk SDK. No circuit knowledge is needed. |
| V2 | **One** fixed constraint system, audited once, proves *every* program. Contract code never becomes constraints (zk.md §3). |
| V3 | **Deterministic:** every program has exactly one valid execution for given inputs, fully specified here. No floating point, no undefined behavior, no host-dependent results. |
| V4 | **Zero-knowledge:** a proof reveals only the program id, the public output digest, the exit code and the padded trace sizes (§8). |
| V5 | **Bounded:** the cycle count, memory, input and output sizes are capped, so proving and verification costs are bounded. |
| V6 | **Simple enough to review.** Fewer, clearer tables are preferred over faster ones. Each table has a written invariant (§6) and a negative test per constraint (§9). |

---

## 2. Machine state

| Component | Definition |
|---|---|
| `pc` | 32-bit program counter; must be 4-byte aligned and inside the code segment |
| `x0..x31` | 32-bit registers; `x0` always reads 0, and writes to it are discarded |
| memory | byte-addressed, little-endian, `MEM_SIZE = 2^28` bytes (addresses `0 .. 2^28 − 1`); stored as aligned 32-bit words |
| input stream | private sequence of 32-bit words (the witness) |
| output stream | public sequence of 32-bit words |
| `clk` | cycle counter, starting at 0 |

**Initial state:**
- `pc = entry` (from the ELF);
- all registers 0, except `x2` (sp) `= STACK_TOP = 2^28 − 16`;
- memory holds the program image (§3) and is zero elsewhere.

**Memory regions:**
- The code segment is `[CODE_BASE, CODE_END)`. Its words are part of the initial
  memory image, so loads from it return the instruction words, as on RISC-V.
  Instructions are fetched from the committed program, never from data memory.
- **Stores must target addresses ≥ `CODE_END`** (decision ZK-3b). Code can never be
  written, and the rule costs one comparison per store in the constraint system. lld's
  default layout (read-only data, then code, then writable data and the stack)
  satisfies it, and the loader rejects writable segments below the code.
- **Computed addresses:** every computed jump target and memory address is a 32-bit
  sum. The constraint system range-checks it (`< 2^28`) before using it as a field
  element, so a sum that wraps modulo the field cannot alias a valid address.
- Any access with address ≥ `MEM_SIZE` traps.
- Addresses below `NULL_GUARD = 0x1000` trap on any access, so null pointer
  dereferences fail loudly.

---

## 3. Programs

- **Format:** a statically linked 32-bit little-endian RISC-V ELF (`EM_RISCV`, class
  32, no dynamic sections).
- **Segments:**
  - exactly one executable `PT_LOAD` segment: the code. It is 4-aligned, has no bss,
    and every word must be a valid BVM-1 instruction (checked at load);
  - up to 4 non-executable `PT_LOAD` segments: read-only data, data and bss (lld
    emits `.rodata` separately).
  - Segments must not overlap, and must lie in `[NULL_GUARD, STACK_TOP − STACK_SIZE)`,
    with `STACK_SIZE = 1 MiB`.
- **Header:** `e_flags` must not select compressed instructions, a hard-float ABI or
  RVE.
- **Program image** = the code words plus the initial data words (bss is zero).
- **Program id:**

  ```
  program_id = first 32 bytes of H64("zkvm/program",
                   LE32(entry) ‖ LE32(code_base) ‖ LE32(#words) ‖ code words ‖
                   LE32(#segments) ‖ for each non-empty data segment in address order:
                   LE32(base) ‖ LE32(len) ‖ file bytes)
  ```

  It does not depend on ELF metadata, symbol tables or section names. Builds must be
  reproducible (SDK build profile) so that anyone can check a program id against
  published source.
- **Limits:** code ≤ 2^16 instructions; data ≤ 2^20 bytes.

---

## 4. Instruction set

BVM-1 implements **RV32I** and the multiplication-only **Zmmul** extension, from *The
RISC-V Instruction Set Manual, Volume I: Unprivileged ISA* (version 20191213 plus the
ratified Zmmul extension), with the restrictions below. Semantics are exactly the
specification's; the notable cases are fixed here.

**Why no hardware division (decision ZK-3a):**
- Division and remainder are the most intricate circuit of a RISC-V zkVM: sign rules,
  the divide-by-zero and overflow special cases, and remainder bounds.
- Leaving them out removes the riskiest constraint table from the audit surface.
- Guests build for `riscv32i-unknown-none-elf` with `-C target-feature=+zmmul`, so the
  compiler uses its software division routines (`compiler_builtins`).
- **rustc lists `zmmul` as an unknown (unstable) target feature**, though LLVM
  implements it. This cannot affect consensus: the loader rejects every division
  instruction, and a miscompiled guest can only fail to load or compute a wrong
  result, never produce an accepted proof of a false statement.
- The SDK also documents a pure RV32I build (software multiplication) as the stable
  fallback.
- A division table may be added in BVM-2, after the core has been audited.

| Class | Instructions |
|---|---|
| Upper immediates | `LUI`, `AUIPC` |
| Jumps | `JAL`, `JALR` (target `(rs1 + imm) & ~1`; it must be 4-aligned and in the code segment, or execution traps) |
| Branches | `BEQ BNE BLT BGE BLTU BGEU` (the target must be 4-aligned and in the code segment) |
| Loads | `LB LH LW LBU LHU`. The address must be naturally aligned (`LH`/`LHU`: 2, `LW`: 4), **else trap** |
| Stores | `SB SH SW`, same alignment rule |
| Register–immediate | `ADDI SLTI SLTIU XORI ORI ANDI SLLI SRLI SRAI` |
| Register–register | `ADD SUB SLL SLT SLTU XOR SRL SRA OR AND` |
| Zmmul | `MUL MULH MULHSU MULHU`. `DIV DIVU REM REMU` are **not** part of BVM-1 and are rejected at load |
| System | `ECALL` (§5), `FENCE` (no-op) |

**Shifts:** only the low 5 bits of the shift amount are used.

**Division** is done in software by the guest; see above.

**Traps** (execution is invalid, so no proof exists):
- `EBREAK`, CSR instructions, compressed instructions, and any encoding not listed
  above;
- misaligned or out-of-range accesses and jumps;
- stores into the code segment;
- exceeding `MAX_CYCLES`;
- reading past the end of the input stream;
- an invalid syscall.

A program therefore either halts cleanly (§5) or has no proof.

---

## 5. System calls (`ECALL`)

The syscall number is in `x17` (a7); arguments are in `x10..x12` (a0–a2); the result
is in `x10`.

| a7 | Name | Effect |
|---|---|---|
| 0 | `HALT` | Stops. `a0` is the public **exit code**. |
| 1 | `READ` | `a0 ←` the next private input word. Traps at the end of the input stream. |
| 2 | `WRITE` | Appends `a0` to the public output stream. |
| 3 | `POSEIDON2` | `a0` is a 4-aligned pointer to 16 words holding a BabyBear state. The Poseidon2 permutation (BabyBear, width 16, standard constants) is applied in place. Each word must be a canonical field element (`< p`), **else trap**. |

**Limits:**
- `MAX_CYCLES = 2^21` per execution; a syscall counts as one cycle. With this bound
  every timestamp is `< 2^24` (§6.3).
- input ≤ 2^16 words; output ≤ 2^12 words.

---

## 6. Constraint system

The proof is one `p3-batch-stark` batch (zk.md §9.4). Tables communicate over LogUp
buses. Every column holding a byte, a 16-bit limb or a flag is range-checked by a
lookup or a boolean constraint. **No field element is ever interpreted as an integer
without such a check.**

Words are 4 bytes `[b0, b1, b2, b3]` (little-endian), because a 32-bit word does not fit
in the 31-bit field.

### 6.1 Tables

| Table | Kind | One row per | Purpose |
|---|---|---|---|
| `BYTE` | preprocessed (2^16 rows) | byte pair `(a, b)` | Range checks of byte pairs; `AND`, `OR`, `XOR` of bytes; free multiplicity column |
| `PROGRAM` | preprocessed | instruction | `(pc, decoded fields)`; free multiplicity column (execution counts) |
| `IMAGE` | preprocessed | image word | `(key, value)` of code, data and the 32 initial registers |
| `MEM_INIT` | main | key used | Initial entry `(key, v_init, 0)` and final entry of every key; keys strictly increasing (§6.3) |
| `CPU` | main | cycle | Fetch, register and memory accesses, next `pc`, syscalls; sends ALU, memory, output and syscall messages |
| `ALU_ADD` | main | ADD/SUB request | Byte-wise addition with boolean carries |
| `ALU_BIT` | main | AND/OR/XOR request | Byte-operation lookups |
| `ALU_LT` | main | SLT/SLTU/EQ request | Signed or unsigned comparison; zero test with an inverse witness |
| `ALU_SHIFT` | main | SLL/SRL/SRA request | Reduced to one multiplier request by `2^e`, with `2^e` proven as bytes |
| `ALU_MUL` | main | MUL/MULH/MULHSU/MULHU request | 8×8-byte convolution with range-checked carries |
| `OUTPUT` | preprocessed | claimed output word | `(index, value)` of the public output |
| `POSEIDON2` | main | syscall | Plonky3's `Poseidon2Air` (standard constants) unchanged, plus memory access, canonical-encoding checks and the syscall binding |

Words are held as 4 bytes. Registers are memory keys `REG_BASE + r`
(`REG_BASE = 2^26`); memory word `w` has key `w` (`< 2^26`).

### 6.2 Buses

| Bus | Message | Providers → consumers |
|---|---|---|
| `bvm/byte-range`, `bvm/byte-op` | `(x, y)`, `(op, a, b, a op b)` | BYTE → all tables |
| `bvm/alu` | `(op, a[4], b[4], c[4])` | ALU tables → CPU, ALU_SHIFT |
| `bvm/program` | `(exec, pc, fields…)` | PROGRAM → CPU |
| `bvm/image` | `(exec, key, v[4])` | MEM_INIT → IMAGE |
| `bvm/memory` | `(exec, key, v[4], ts)` | accesses and MEM_INIT, produce (+1) and consume (−1) |
| `bvm/output` | `(exec, index, v[4])` | CPU → OUTPUT |
| `bvm/syscall` | `(exec, clk, ptr[4])` | POSEIDON2 → CPU |

**Counts:**
- Providers whose message contents are witness cells have boolean counts.
- Free multiplicities occur only on preprocessed providers (`BYTE`, `PROGRAM`).
- The verifier enforces Plonky3's LogUp bound `Σ weight·height < p`; the largest
  accepted statement reaches 63% of p (tested).

### 6.3 Memory argument (offline memory checking)

Every access to key `k` at time `t` consumes `(e, k, v_prev, t_prev)` and produces
`(e, k, v, t)`, where:
- `v = v_prev` for reads;
- `t_prev < t` is enforced by a 3-byte range check on `t − t_prev − 1`.

**Endpoints:** `MEM_INIT` produces `(e, k, v_init, 0)` and consumes the final entry of
every key used.
- Its rows are strictly sorted by key, with range-checked positive differences below
  2^27, so each key appears exactly once.
- `v_init` equals the `IMAGE` value for image keys, and 0 for any other key.

**Timestamps:** `t = 4·(clk + 1) + slot`, so `t = 0` means "initial value". The slots:

| Slot | Access |
|---|---|
| 0 | `rs1` read (for `ECALL`: `a7`) |
| 1 | `rs2` read (for `ECALL`: `a0`) |
| 2 | memory read; `POSEIDON2` buffer read |
| 3 | register write, memory write, `POSEIDON2` buffer write |

**Why this is sound:**
- Timestamps increase per key, and the CPU table has at most `MAX_CYCLES = 2^21` rows,
  so every timestamp is `< 2^24`. The difference check is therefore exact.
- A balanced bus then forces each read to return the last value written (Blum et al.,
  1991).
- The full argument is in the security review, §3.2.

### 6.4 Public values (per execution's `CPU` table)

```
entry pc        1 element
CODE_END        4 bytes
exit code       4 bytes
output count    1 element
binding         16 × 16-bit limbs of the caller's 32-byte h_tx (zk.md §5.2)
```

The program (as the preprocessed `PROGRAM` and `IMAGE` tables) and the claimed outputs
(the preprocessed `OUTPUT` table) are rebuilt by the verifier from the statement. All
public values enter the Fiat–Shamir transcript, so a proof is valid for exactly one
statement and one binding.

### 6.5 Several executions in one proof

A statement may cover up to `MAX_EXECUTIONS = 5` executions: one main execution (id 0)
and further ones (ids 1…). PX uses one kernel and up to 4 functions.
- **Own tables per execution:** `PROGRAM`, `IMAGE`, `MEM_INIT`, `CPU` and `OUTPUT`,
  each with the execution id as a constant.
- **Shared tables:** `BYTE`, the ALU tables and `POSEIDON2`.
- **Tags:** every message on the memory, program, image, output and syscall buses
  begins with the id. So no execution can read another's memory, fetch its code or emit
  its outputs.
- **Shared Poseidon2 table:** each `POSEIDON2` row carries its caller's id in a column
  bound by the syscall lookup.
- The byte and ALU buses are pure functions of their operands and need no tag.
- **Binding:** every execution carries the same binding.
- **Verification:** the verifier rebuilds every execution's tables from the statement
  (program, exit code, outputs). Dropping, reordering or changing an execution fails.

---

## 7. Proof parameters

As zk.md §9.3, parameter set **BS-ZK-2**:
- BabyBear with a degree-8 extension;
- hiding FRI: blow-up 8, 108 queries, 16 grinding bits;
- over the whole shape envelope, ≥ 123 bits in the Johnson regime and ≥ 105 bits in
  the unique-decoding regime.

**Height limits:**
- `BYTE`: 2^16;
- `CPU`: 2^21 (`MAX_CYCLES`, so the circuit accepts exactly the executions the
  interpreter allows);
- every other table: 2^22.

---

## 8. Privacy

| Revealed by a proof | Hidden |
|---|---|
| Program id, exit code, output digest (and the output words, when published with the transaction) | Input stream, all registers, memory, control flow, which instructions ran |
| **Padded height of each table** (powers of two): roughly how many cycles, memory accesses and Poseidon2 calls the run used | Exact counts within a power-of-two bucket |

**The padded heights leak coarse timing.** A branch on a secret that changes the cycle
count across a power of two changes a public height.
- **Programs must do constant work** in their secrets. The PX kernel does: tests check
  identical table heights across dummy, real, bridge, user-record and contract-record
  witnesses (docs/px.md §4.4).
- Contract functions must follow the same rule for their own secrets.
- A padding helper in the SDK (spin to a declared cycle bucket) is **not implemented
  yet**; until it is, function authors must design for constant work.
- `zk.md` §12.2 lists this under metadata.

**Zero-knowledge:**
- The hiding FRI commitment scheme needs fresh CSPRNG randomness **for every proof**.
- The prover takes it from the OS RNG, hedged with the witness (transactions.md §10).
- A fixed seed would break zero-knowledge; a test checks that two proofs of the same
  statement differ.

---

## 9. Assurance (acceptance criteria)

1. **Reference interpreter:**
   - every instruction against hand-computed vectors, including all shift and
     multiplication edge cases (there is no division, decision ZK-3a);
   - every trap condition;
   - determinism (the same run twice gives identical traces).
2. **Differential testing:** the interpreter against the constraint system on random
   programs. For every accepted execution the proof verifies; the traces must satisfy
   every constraint row by row (the debug constraint checker).
3. **Constraint mutation:** for each table, every column of a valid trace is mutated
   (one cell at a time); the constraint checker or the verifier must reject. A mutation
   that is still accepted is an under-constrained column and a release blocker.
4. **Adversarial programs:**
   - infinite loops (cycle limit);
   - memory bombs (bounds);
   - misaligned and out-of-range accesses;
   - stores into code;
   - invalid syscalls and input exhaustion.
5. **Invalid proofs:**
   - every single-element mutation of a proof;
   - proofs for another program id, output or binding;
   - truncated or oversized proofs;
   - claimed table heights above the limits.

   All must be rejected **without a panic reaching the node** (§10).
6. **Cross-node determinism:** two independent verifier instances, and proofs from
   different machines, give identical results.
7. **Resource exhaustion:** verification time and memory are bounded by the height
   limits before any expensive work starts.

---

## 10. Verifier hardening

- **Before verification:**
  - the proof bytes are size-checked (≤ `MAX_PROOF_BYTES`) and strictly decoded;
  - every claimed table height is checked against its limit.
- **During verification:**
  - the Plonky3 verifier is run behind `catch_unwind`; its README warns that malformed
    proofs may panic it;
  - the node is built with `panic = "unwind"`, so such a panic becomes a rejected proof,
    not a crash;
  - the panic is returned as a distinct error (`ZkError::VerifierPanicked`); logging
    and counting it in the node is part of consensus integration.
- **Parameters:** compiled in (`zk/src/params.rs`), never taken from the proof. The
  verifier registry of zk.md §9.5 comes with consensus integration.
