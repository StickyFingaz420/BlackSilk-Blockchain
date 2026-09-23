# BVM-1: the BlackSilk zero-knowledge virtual machine

Status: **specification v0.2; core constraint system implemented and tested** (AUDIT.md
R8). The Poseidon2 syscall circuit is pending. Not consensus.
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
| `PROGRAM` | preprocessed | instruction | `(pc, decoded instruction)`. Its multiplicity column counts executions |
| `CPU` | main | cycle | Fetch, decode lookup, register and memory accesses, next `pc`. Sends ALU, memory and syscall requests |
| `ALU_ADD` | main | ADD/SUB/ADDI and address computations | Byte-wise addition with carries |
| `ALU_BIT` | main | AND/OR/XOR (and immediates) | Byte-wise, via `BYTE` lookups |
| `ALU_LT` | main | SLT/SLTU/branches | Unsigned or signed comparison by limb subtraction |
| `ALU_SHIFT` | main | SLL/SRL/SRA | Bit decomposition of the shift amount; byte and bit shifting |
| `ALU_MUL` | main | MUL/MULH/MULHSU/MULHU | 32×32→64-bit product with limb carries |
| `MEMORY` | main | access | Consistency of reads and writes (§6.3) |
| `MEM_INIT` | main | touched address | Initial value of each touched word (program image or 0), sorted |
| `IMAGE` | preprocessed | image word | `(address, value)` of the program image |
| `BYTE` | preprocessed | pair `(a, b) ∈ [0,256)²` | `a AND b`, `a OR b`, `a XOR b`; range checks of bytes |
| `U16` | preprocessed | value in `[0, 2^16)` | 16-bit range checks |
| `POSEIDON2` | main | permutation | The `POSEIDON2` syscall (the `p3-poseidon2-air` layout) |
| `IO` | main | input or output word | Private input stream; public output digest |

### 6.2 Buses

| Bus | Kind | Senders → receivers |
|---|---|---|
| `program` | lookup | CPU → PROGRAM |
| `alu` | lookup | CPU → ALU_* (tuple `(op, a, b, result)`) |
| `memory` | permutation | CPU, POSEIDON2 → MEMORY; MEM_INIT produces and consumes |
| `byte`, `u16` | lookup | all tables → BYTE, U16 |
| `syscall` | lookup | CPU → POSEIDON2, IO |

### 6.3 Memory argument (offline memory checking)

Every access to address `a` at time `t` consumes the entry `(a, v_prev, t_prev)` and
produces `(a, v, t)`:
- `v = v_prev` for reads;
- `t_prev < t` is enforced by a range check on `t − t_prev − 1`.

**Endpoints:**
- `MEM_INIT` produces `(a, v_init, 0)` and consumes `(a, v_final, t_final)` for every
  touched address.
- Its rows are **strictly sorted by address** (range-checked positive differences), so
  each address appears exactly once.
- `v_init` must equal the `IMAGE` value for image addresses, and 0 for any other
  address.
- Registers use a separate address space (a tag column), with the same argument.

**Timestamps:** `t = 4·(clk + 1) + slot`, so every real access has `t ≥ 4` and
`t = 0` means "initial value". The slots are:
- 0: first register read (`rs1`; for `ECALL`, `a7`);
- 1: second register read (`rs2`; for `ECALL`, `a0`);
- 2: memory read;
- 3: register write, or memory write.

**Every cycle reads exactly two registers.** With `clk < 2^21`, every timestamp is
`< 2^24`. The check `t − t_prev − 1 ∈ [0, 2^24)` therefore needs three byte-range
lookups, and cannot be satisfied by a wrapped (negative) difference: a negative
difference is a field element above `p − 2^24`, far outside `[0, 2^24)`.

**Why this is sound:** with every entry produced before it is consumed, the multiset
equality of the permutation bus forces each read to return the last value written.
This is the argument of Blum et al. (1991), as used by Jolt and SP1.

**Implementation risk:** this argument is the most delicate part of the VM. It is
reviewed separately (R8 review document).

### 6.4 Public values

```
program_id    8 field elements (the 32-byte program_id as 8 × 4-byte limbs)
output_digest 8 field elements: Poseidon2 sponge over the output words
exit_code     1 field element (u32 as 2 × u16)
binding       8 field elements: the caller's h_tx (zk.md §5.2), absorbed but unconstrained
```

The binding values are in the Fiat–Shamir transcript, so a proof is valid for exactly
one transaction.

---

## 7. Proof parameters

As zk.md §9.3 (parameter set `BS-ZK-1`):
- BabyBear with a degree-5 extension;
- hiding FRI;
- ≥ 100 bits in the Johnson-bound regime, with the unique-decoding bits also reported;
- table heights padded to powers of two, `≤ 2^22`.

---

## 8. Privacy

| Revealed by a proof | Hidden |
|---|---|
| Program id, exit code, output digest (and the output words, when published with the transaction) | Input stream, all registers, memory, control flow, which instructions ran |
| **Padded height of each table** (powers of two): roughly how many cycles, memory accesses and Poseidon2 calls the run used | Exact counts within a power-of-two bucket |

**The padded heights leak coarse timing.** A branch on a secret that changes the cycle
count by a factor of two changes a public height.
- The SDK provides `pad_to(cycles)`, and contract functions **must** pad to a
  per-function constant (their declared bucket).
- `zk.md` §12.2 lists this under metadata.
- Tests check that two executions with different secrets but the same bucket produce
  identically shaped proofs.

**Zero-knowledge:**
- The hiding FRI commitment scheme needs fresh CSPRNG randomness **for every proof**.
- The prover takes it from the OS RNG, hedged with the witness (transactions.md §10).
- A fixed seed would break zero-knowledge; a test checks that two proofs of the same
  statement differ.

---

## 9. Assurance (acceptance criteria)

1. **Reference interpreter:**
   - every instruction against hand-computed vectors, including all division and shift
     edge cases;
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
  - the panic is logged and counted, as evidence for an upstream fix.
- **Parameters:** they come only from the verifier registry (zk.md §9.5), never from the
  proof.
