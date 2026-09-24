# ZK layer security review (internal)

Date: 2026-09-24.
Scope: `zk/`, `zkvm/`, `px-core/`, `px/`, specifications `docs/zk.md`, `docs/zkvm.md`,
`docs/px.md`.

> **This is an internal review by the implementer. It is not an independent review.**
> It records the arguments, tests and open risks so that independent reviewers can
> check them. Nothing in the ZK layer may be used in production before the independent
> reviews in §9 are complete.

---

## 1. Method

1. **List every assumption** the soundness and privacy of a PX proof depend on (§2).
2. **Argue soundness structurally** against a prover that controls *every* witness cell
   of every table at once (§3). Single-cell mutation tests (§7) cannot show this on their
   own. The argument follows each bus from consumer to provider, down to public or
   preprocessed data.
3. **Check field-wrap hazards:** every place a 32-bit or 64-bit quantity meets a
   31-bit field (§3.5).
4. **Enumerate protocol attacks** against the kernel, contract functions, state and
   delivery (§4), and privacy leaks (§5).
5. **Audit Pure Rust and determinism** (§6).
6. **Record evidence and the findings of this review** (§7, §8).

## 2. Assumptions (complete list)

| # | Assumption | Basis | Status |
|---|---|---|---|
| A1 | Knowledge soundness of the Plonky3 0.7 batch STARK (LogUp, hiding FRI), Fiat–Shamir in the random-oracle model, at parameter set BS-ZK-2 | Proven bounds computed by `p3-security` for every shape of the envelope: ≥ 123 bits (Johnson regime), ≥ 105 bits (unique decoding), tested | Implementation unreviewed by us |
| A2 | Poseidon2 (BabyBear, width 16, standard constants) behaves as an ideal permutation: 124-bit collision and preimage resistance for the Merkle trees, the transcript and `Hk` | Designers' analysis; wide deployment | **Young primitive; first external-review item** |
| A3 | LogUp: an unbalanced bus passes with negligible probability over the 247-bit challenge field, provided multiplicities do not wrap modulo p | Plonky3's verifier enforces `Σ weight · height < p`. The largest accepted statement reaches 63% of p (test `the_logup_multiplicity_bound_holds_for_the_largest_statement`). | Holds |
| A4 | The BVM-1 tables constrain exactly the interpreter's semantics | Constraint oracle, mutation testing, differential tests, proofs (§7) | Structural argument §3; external review |
| A5 | The kernel and function programs implement their specifications | One Rust source for native and guest; per-check rejection tests | External review |
| A6 | Zero knowledge: the hiding FRI (4 random codewords) and salted Merkle leaves (4 elements) hide the witness; prover randomness is fresh | Plonky3's hiding construction; `ProverConfig` hedges the OS RNG with a witness digest | Sufficiency of the parameters is an external-review item |
| A7 | Delivery: IND-CCA of the hybrid KEM (Ristretto ECDH and ML-KEM-768) and of ChaCha20-Poly1305 | Standard assumptions; RustCrypto `ml-kem` 0.3.2 | Wallet-side only |

## 3. Coordinated (multi-cell) forgery analysis

**Adversary.** It chooses all main-trace cells of all tables, all table heights within
the verifier's limits, and all free multiplicities, simultaneously. Public data
(programs, image, claimed outputs, exit codes, binding, public values) is fixed by the
verifier.

**Goal.** Show that any accepted proof implies a genuine execution of each program, per
the interpreter, with the claimed public results. By A1 and A3, an accepted proof means
every constraint holds on every row and every bus balances as a multiset. The argument
therefore reasons about satisfying assignments.

### 3.1 Buses: who provides, who consumes

Every message on the memory, program, image, output and syscall buses starts with an
**execution id**. Per-execution tables carry it as a constant; the Poseidon2 table's
`EX` column is bound through the syscall bus.

| Bus | Provider (count) | Consumers (count) | What balance implies |
|---|---|---|---|
| `RANGE`, `BYTE_OP` | `BYTE`: preprocessed contents, **free** multiplicities | all tables, counts in {0, 1} | Every consumed pair is in the fixed table: it is a byte pair or a correct byte operation. Free multiplicities cannot create a message outside the fixed set. |
| `ALU` | ALU tables: `(op, a, b, c)`, count `real ∈ {0,1}` | CPU, `ALU_SHIFT` (to `ALU_MUL`), CPU checks of Poseidon2 pointers | Each consumed claim equals an ALU row; each ALU row's `c` is determined by `(op, a, b)` (§3.3). |
| `PROGRAM` | `PROGRAM(e)`: preprocessed decoding, **free** multiplicities | CPU of `e`, count `real` | Every executed row's decoded fields are the program's at `pc`. |
| `IMAGE` | `IMAGE(e)`: preprocessed, count 1 per real word | `MEM_INIT(e)`, count `in_image ∈ {0,1}` | Every image word appears exactly once with `in_image = 1` and its image value. Keys strictly increase, so there are no duplicates; non-image keys start at 0. |
| `MEMORY` | accesses produce `(e, key, v, t)`; `MEM_INIT` produces `(e, key, v_init, 0)` | accesses consume `(e, key, v_prev, t_prev)` with `t_prev < t`; `MEM_INIT` consumes the final entry | Offline memory checking (Blum et al.), argued in §3.2 |
| `OUTPUT` | `OUTPUT(e)`: preprocessed claimed outputs, count 1 each | CPU of `e`: `(e, OUT, value)` on `WRITE`, count `swr` | `OUT` starts at 0, increments per `WRITE`, and equals the claimed count at `HALT`, so the outputs are exactly the claimed ones, in order. |
| `SYSCALL` | Poseidon2 rows `(EX, CLK, ptr)`, count `real` | CPU of `e` on `POSEIDON2`, count `sp2` | A bijection between Poseidon2 rows and `POSEIDON2` calls. `EX` and `CLK` equal the caller's, so the row's memory accesses carry the caller's execution id and timestamps. |

**Free multiplicities appear only on providers with preprocessed contents** (`BYTE`,
`PROGRAM`). Every provider whose message contents are witness cells has a
boolean-constrained count. This is the property that makes free multiplicities
harmless: a negative or oversized multiplicity can only cancel messages the table
genuinely contains.

### 3.2 Memory consistency

- **Timestamps are unique per key:**
  - slot timestamps are `4·(clk+1)+slot`;
  - `clk` starts at 0 and increments by one per real CPU row;
  - within a row, each slot accesses at most one key: registers use slots 0, 1 and
    3; a load or store uses slots 2 and 3 on its word;
  - a Poseidon2 row accesses its 16 distinct buffer words at slots 2 and 3 of the
    caller's cycle;
  - on a `POSEIDON2` call the CPU makes no memory access and no register write (the
    syscall flags are exclusive), so no key is accessed twice with one timestamp.
  - Different keys may share a timestamp; the memory argument only needs increasing
    timestamps per key.
- **Every access consumes an entry with a strictly smaller timestamp:** `t − t_prev − 1`
  is proven to be a 3-byte value. Timestamps are below `4·(2^21+1)+4 < 2^24`, so this is
  exact, with no wrap-around.
- **The endpoints are fixed:** `MEM_INIT` produces exactly one initial entry per key at
  time 0 (unique keys, below 2^27, initial values bound to the image) and consumes one
  final entry per key.
- **Conclusion:** a multiset-balanced memory bus with these three properties forces
  every read to return the most recent write of its key (the standard offline
  memory-checking argument). A forged value would need a producer for its
  `(e, key, v, t)`; the only producers are the accesses and `MEM_INIT`, and both are
  bound as above.
- The execution id separates executions completely: an execution's memory messages
  cannot match another's.

### 3.3 Determinism of each row

**ALU tables.** Each row's result is a function of its operands.
- `ADD`/`SUB`: byte-wise with boolean carries.
- `XOR`/`OR`/`AND`: byte-operation lookups.
- `SLT`/`SLTU`/`EQ`: difference sign and zero test.
- `MUL` family: byte convolution with range-checked carries.
- Shifts: reduced to one `MUL`/`MULHU`/`MULHSU` request by `2^e`, proven as bytes.

**Free cells:** the only unconstrained witness cells are the inverse witnesses of the
two zero tests (`ALU_LT` when the difference is zero, `ALU_SHIFT` when the shift is
zero).
- In both, `z·x = 0` and `x·inv = real − z` determine `z` uniquely: `x ≠ 0` forces
  `z = 0`; `x = 0` forces `z = 1`.
- The free `inv` cannot change any output, alone or together with other cells.

**CPU.** Each row is determined by `(pc, clk)`, the fetched fields, and the memory and
ALU buses:
- register values come from the memory bus;
- results come from the ALU bus or from byte decompositions checked in-row;
- the next `pc` is constrained;
- padding rows are inert (all fetched fields zero).

**Control:**
- the first row is real, with `clk = 0`, `pc = entry` and `OUT = 0`;
- real rows are contiguous;
- `pc` chains through `next_pc`;
- the last real row executes `HALT`, and nothing follows a `HALT`;
- the exit code and output count at `HALT` equal the public values.

**`POSEIDON2`:**
- the embedded `Poseidon2Air` fixes the output from the input;
- input and output words equal the permutation's field elements, and both are
  canonical, so each value has one byte encoding;
- the CPU checks that the 64-byte buffer lies in writable memory:
  `CODE_END ≤ ptr < 2^28 − 63`.

**`MEM_INIT`:** keys strictly increase (a 27-bit difference check), so keys are unique.

### 3.4 Multi-execution statements

- Each execution's `PROGRAM`, `IMAGE`, `MEM_INIT`, `CPU` and `OUTPUT` tables use its id
  as a constant. Each has its own public values: entry, `CODE_END`, exit code, output
  count, and the shared binding.
- The byte, ALU and Poseidon2 tables are shared. The first two carry pure functions of
  their operands, so sharing cannot transfer information between executions. The
  Poseidon2 table's rows are bound to their caller's id (§3.1).
- **Tests:** isolation, per-part binding (swapped outputs, swapped programs, altered
  exit codes and outputs, a dropped or reordered execution), and 11 458 mutations over
  extra executions and the shared Poseidon2 table.

### 3.5 Field-wrap hazards

Every place a quantity of 32 bits or more meets the 31-bit field:

| Quantity | Guard |
|---|---|
| `pc`, computed addresses, jump targets | Range-checked `< 2^28` before use as field elements (finding ZK-F2). |
| Memory keys | `< 2^27` (`MEM_INIT`); Poseidon2 `4·KEY = ptr < 2^28`. |
| Timestamps | `< 2^24`; differences are 3 bytes (§3.2). |
| Word ↔ field element (Poseidon2 inputs and outputs) | Canonicity check (`x3 < 120`, or `x3 = 120` with low bytes zero), so `word(bytes)` never exceeds p. |
| Kernel values and sums | Never field elements: `u64` values and `u128` sums in guest integer arithmetic; value limbs of 16 bits in hashes. The wrap case is tested. |
| Witness elements read by the kernel | Checked `< p` (`NonCanonical`). |
| LogUp multiplicities | Verifier bound `Σ weight·height < p` (A3); CPU tables are capped at `MAX_CYCLES` (finding ZK-F9). |

**Conclusion of §3.** Under A1–A3, any accepted BVM-1 proof implies, for each execution,
a run of its program that the interpreter would perform, with the claimed exit code and
outputs.
- The argument covers coordinated changes across all cells; the tests support it but
  cannot prove it.
- The weakest links are the per-table constraint sets (A4). They are the primary target
  of the independent implementation review (§9).

## 4. Protocol attacks (kernel, functions, state)

| Attack | Defence | Evidence |
|---|---|---|
| Spend another user's record | The owner tag is recomputed from the witness `sk` | `only_the_owner_can_spend`; sk and diversifier cases |
| Double spend (chain, block, transaction) | Deterministic nullifiers; the state rejects repeats; the kernel rejects `nf_0 = nf_1` | state tests; `duplicate` case |
| Faerie Gold (shared nullifiers) | `rho` derives from a unique nullifier; `nf` covers `cm` | Construction; distinct-rho test |
| Inflation by wrap-around | Integer `u128` sums | `wrap` case |
| Value from dummies; dummy contract records | `DummyWithValue`, `DummyContract` | rejection cases |
| Burn a victim's record with a dummy nullifier | Needs the victim's `nk` (`nk = Hk(NK, sk)` of the witness) or an `Hk` collision | Construction |
| **Spend a contract record without its contract** | A function of that contract must approve the exact commitment | `no function`, `approve only dummy` cases |
| **Rogue function claiming another contract** | The verifier checks that each function's program is registered to its contract (a mandatory argument of `prove::verify`) | `Unregistered` test; **consensus must implement the registry** (§8 R-1) |
| Function approving foreign or dummy inputs | `ApprovalMismatch` | cases |
| Caller redirecting a function's payout, or changing its amount | Outputs a function specifies must match exactly | `redirect`, `amount` cases |
| Forged contract state (a contract output without its function) | `Unauthorized` | `forge contract output` |
| Function writing another contract's state | `SpecForeignContract` | case |
| Two functions claiming one output | `SpecConflict` | case |
| Function and kernel disagreeing (another blind, record or specification) | `io_hash` differs; the statement cannot be satisfied | `a_function_transcript_must_match_the_kernel` |
| Function with a wrong secret, or any failing function | Exit code ≠ 0; the verifier requires 0 | `a_wrong_secret_cannot_claim` |
| Proof replay or malleability | `h_tx` in every execution's public values; every public field bound | 10 alteration cases; multi-execution binding tests |
| Statement confusion between executions | Execution tags; per-part public values | §3.4 |
| Stale or forged anchor | 100-block root window | state tests |
| Pool drain after a proof-system break | Containment: `pool ≥ 0` | state tests |
| Malformed or oversized proofs; verifier panics | Strict decoding, 4 MiB cap, height and count checks before Plonky3, `catch_unwind` | 402 byte mutations: all rejected, no panic |
| **Denial of service by verification cost** | Each proof costs ~1.3–1.5 s to verify | **Open** (§8 R-3) |

## 5. Privacy

| Channel | Status |
|---|---|
| Proof contents | Zero knowledge (A6) |
| Trace heights (public) | Constant work. Identical heights across dummy, real and bridge witnesses, and across user and contract inputs (tests). Kernel: 25–29k cycles in a 2^15 CPU table (§8 R-5). |
| Which contract and function are called | **Public by design** (program ids, contract ids, selector outputs; zk.md §12.2) |
| Function transcripts | `io_hash` hides them only if the blind is fresh and uniform. The wallet must sample it with a CSPRNG (§8 R-6). |
| Contract-record nullifiers | `Hk(contract ‖ rcm ‖ cm)`. Anyone who knows the record's plaintext can recognize its spend. This is inherent to shared contract state; distributing plaintext is the application's job. |
| Bridge amounts | Public by design (containment); wallet policy in zk.md §12.2 |
| Record delivery | Hybrid encryption; per-address keys; uniform ciphertext length |
| Prover timing | Local only (the prover's machine) |

## 6. Pure Rust and determinism audit

- **No C/C++ in the build:** no crate in the workspace's normal or build dependency graph
  depends on `cc`, `cmake`, `bindgen` or `pkg-config` (`cargo tree -i`).
  - The only `links` keys are `rayon-core`, a marker with no native library, and
    `wasm-bindgen`, for wasm targets only.
- **`unsafe`:**
  - every workspace library and binary crate declares `#![forbid(unsafe_code)]`;
  - the single `unsafe` block is the guest SDK's `ecall`, which runs inside the VM, not
    in a node.
  - Third-party crates (Plonky3, curve25519-dalek, RustCrypto) contain `unsafe`
    internally (SIMD, zeroization). "Pure Rust" does not mean "no `unsafe` in
    dependencies".
- **Determinism:**
  - verification uses no randomness, clocks or floating point, and there is no
    floating point anywhere in `zk`, `zkvm`, `px-core` or `px`;
  - Plonky3's parallel code computes exact field sums, so results do not depend on
    thread scheduling;
  - hash maps in the zkVM are used only for lookups, or are sorted before use
    (`MEM_INIT`);
  - the kernel rebuild was byte-identical, and its program id is pinned.
- **Pinned versions:** Plonky3 `=0.7.0` (every crate), `ml-kem =0.3.2`.

## 7. Evidence (tests)

| Area | Evidence |
|---|---|
| Proof layer | Honest and false statements; 402 single-byte proof mutations (no verifier panic); strict encoding; randomized proofs; parameter envelope ≥ 123 / ≥ 105 bits |
| ALU tables | 231 120 single-cell mutations, all caught; false claims unbalance the bus |
| CPU and memory | 37 616 mutations; every instruction class; lying-prover tests |
| Poseidon2 | 2 496 mutations; consistent output forgery rejected; AIR output equals the interpreter's |
| Multi-execution | Isolation; statement binding; 11 458 mutations; 3-execution proof |
| LogUp bound | Largest accepted statement at 63% of p |
| Kernel | 20 plain and 12 contract rejection cases, identical natively and in the guest; constant trace heights |
| Proofs | Deposit, payment, LOCK and CLAIM proven and verified; rejected under statement alterations, unregistered programs, a wrong shape |
| State, tree, delivery, hash | docs/px.md §8.3 |

## 8. Findings of this review

| # | Finding | Status |
|---|---|---|
| R-1 | **Function programs must be registered to their contracts.** Without that check, anyone could write a "function" approving the spending of another contract's records. | The registry is a mandatory argument of `prove::verify` (tested). **Consensus must implement it** (contract deploy v2, zk.md §8.3). Open for integration. |
| R-2 | The CPU table height was bounded by the global 2^22 limit, not by `MAX_CYCLES` (2^21). The circuit accepted longer executions than the interpreter allows. | Fixed: CPU tables are capped at `MAX_CYCLES` (AUDIT.md ZK-F9). The LogUp bound improved from 84% to 63% of p. |
| R-3 | **Verification costs ~1.3–1.5 s per proof.** The preprocessed tables (the 2^16-row byte table) are recommitted on every verification. | Open: cache the setup commitments per program and table height; gate relay behind cheap checks, fees and rate limits. |
| R-4 | **Proof size ~2–2.5 MB** | Open (docs/px.md §7; security-policy decision on queries; aggregation) |
| R-5 | The kernel with one function uses 29.4k of 32 768 CPU rows. A future change that crosses 2^15 for some witnesses only would make heights witness-dependent. | Open: a test asserts identical heights. Before release, add a margin check, or pad the kernel to a fixed cycle count. |
| R-6 | `io_hash` hiding depends on a fresh uniform blind chosen by the caller. | Documented. Wallet code must sample it with a CSPRNG; the tests do. |
| R-7 | Poseidon2 is young and used everywhere (A2). | External cryptanalysis review required |
| R-8 | Plonky3 0.7 is a pre-1.0 library; its audit status has not been verified by us. An earlier comment called `Poseidon2Air` "audited"; the claim was unverified and has been removed. | External implementation review required |

## 9. Required independent reviews (before any production use)

1. **Cryptographic design:** `Hk` and the node compression, nullifiers, records, the
   kernel and function statements, the hybrid delivery combiner, and the BS-ZK-2
   parameters (including the zero-knowledge parameters, A6).
2. **Implementation:**
   - the BVM-1 constraint tables against the interpreter (A4);
   - the kernel and SDK;
   - the verifier hardening in `zk/src/lib.rs`;
   - the Plonky3 components as used (A1, R-8).
3. **Poseidon2 cryptanalysis** for this instance (A2, R-7).
4. **Public testnet period and bug bounty** (zk.md §13).

Until these are done, the ZK layer is **incomplete for production**. Every document and
status line says so.
