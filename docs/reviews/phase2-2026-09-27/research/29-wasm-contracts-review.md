# 29 wasm-contracts-review: research dossier (phase 2, phase 1)

- **Agent:** 29 (wasm-contracts-review). Internal engineering research, **not an audit**. Nothing here states that BlackSilk, wasmi or the `contracts/` crate is secure, audited or production-ready.
- **Commit:** `rebuild/core` @ `9e422d8` (`git rev-parse --short HEAD`).
- **Rules followed:** read-only on the repository; no cargo builds or tests; public web sources only; no repository content sent anywhere. One public PDF (the wasmi Runtime Verification report) and public upstream source files (wasmi, rs-soroban-env) were downloaded to the session scratchpad and read locally.

---

## 0. Summary and decision recommendation

**Decision (recommended, for the owner's D22): option D, implemented as "D-freeze".**

1. PX is the only contract platform, for the testnet and v1 (same as R7, R16 §8, SX1 and the 28 dossier).
2. `contracts/` becomes **frozen research, outside the root workspace.**
   - Move it from `members` to `exclude` in the root `Cargo.toml`, with its own committed `contracts/Cargo.lock`. The `fuzz/` crate already works this way.
   - Its code stays buildable and testable, and it is not deleted.
   - **Effect:** 16 crates leave the root `Cargo.lock`: `wasmi`, `wasmi_core`, `wasmi_ir`, `wasmi_collections`, `wasmparser-nostd`, `string-interner`, `multi-stash`, `downcast-rs`, `indexmap-nostd`, `wat`, `wast`, `wasm-encoder`, `wasmparser` 0.259, `leb128fmt`, `unicode-width`, and the crate itself. This was computed from `Cargo.lock` [source-read].
3. The two Wasm fuzz targets (`wasm_module`, `contract_sequence`) and their seeds leave `fuzz/`, so that `fuzz/Cargo.lock` also sheds wasmi.
4. **C-1 to C-5 are not fixed now.** They become the written **preconditions for any revival**, together with the new findings below.
5. The only admissible future door is an **Aleo-style public finalize attached to PX calls**, with no value layer (R7 §4 D; 28 ADR-28-1). This dossier adds one recommendation to it: if a finalize is ever built, run it on the **existing BVM-1 RISC-V interpreter** (safe Rust, `forbid(unsafe_code)`, already consensus-reviewed), not on wasmi. That avoids a second VM. Polkadot made the same move from wasmi to RISC-V (PolkaVM).

**Identity impact of the recommendation:** none. The Wasm system is not consensus. No node, wallet, miner or tx crate depends on `blacksilk-contracts` [source-read: grep over all manifests]. The consensus fingerprint covers constants only and does not include the `contract/*` hash tags (`node/src/fingerprint.rs:3-14`).

**Corrections to the consolidated review and to the repository's own claims (new evidence):**

- **The "0.38.0 is covered by an external audit" claim overstates the evidence.**
  - Runtime Verification's report (delivered 2024-11-27) targets tag **v0.36.0** (commit `02621ad`), plus the fix commits of 0.36.1–0.36.5. It fuzzed 0.37.x for 8 machine-days.
  - wasmi's own NEWS.md says "v0.36 and **partially** 0.37-0.38".
  - 0.38.0 (2024-10-06) contains post-audit refactors of the `unsafe` load/store executor paths (#1224).
  - The report leaves four code-review findings **unaddressed**:
    - C4 (High): raw-pointer offset bounds;
    - C2 (Low);
    - C3 (Low): truncating fuel division, **still present in 0.38.0** at `engine/config.rs:135-137`;
    - C1 (Low): addressed only on main.
- **"About 120 `unsafe` blocks" undercounts the closure.** Line counts of `unsafe` in `src/`: wasmi 120, string-interner 40, wasmi_collections 5, wasmi_ir 4, wasmparser-nostd 1, multi-stash 1 (≈171 in total).
- **wasmi is in no shipped binary today.** The consolidated P0-17 justification ("removes wasmi `unsafe` from the release supply chain") is therefore imprecise. The real gains are:
  - the lockfile and audit surface;
  - CI time;
  - reviewer and documentation confusion;
  - no temptation to wire the crate in.

**New findings: 11** (W-1 … W-11; §4). None is Critical or High, because nothing is reachable from a node. The highest are Medium-if-revived.

---

## 1. Scope and what I read

**Code (all read in full):**
- `contracts/Cargo.toml`
- `contracts/src/{lib,exec,profile,state,smt,types}.rs` (≈2,270 lines)
- `contracts/tests/exec.rs` (18 tests)
- `contracts/tests/fuzz.rs` (1 test)
- in-crate unit tests: smt 5, state 3, types 3. That makes **30 tests**, matching R7.
- `fuzz/fuzz_targets/{wasm_module,contract_sequence}.rs`
- `fuzz/Cargo.toml`, `fuzz/run_campaign.sh`, `fuzz/src/seeds.rs:190-210`
- `.github/workflows/ci.yml` (clippy `--workspace` :44, test `--workspace` :74, the overflow job `-p blacksilk-contracts` :107, audit :163-180, fuzz-smoke :182-205)
- root `Cargo.toml`, `Cargo.lock` (wasmi closure), `fuzz/Cargo.lock`
- `tx/src/params.rs:9-14` (KIND 0..3)
- `tx/src/types.rs:397-410`
- `crypto/src/lib.rs`, `crypto/src/hash.rs:55-141` (the `contract/*` tags)
- the users of `crypto::{schnorr,membership,claims}` (grep: none outside `crypto/`)
- `node/src/fingerprint.rs:1-30`
- `zkvm/src/lib.rs:12,37`

**Third-party source read locally (cargo registry):**
- wasmi 0.38.0:
  - `engine/limits/engine.rs:200-221` (`EnforcedLimits::strict`);
  - `engine/config.rs:52-137` (`FuelCosts`, `costs_per`);
  - `engine/code_map.rs:82,208-236`;
  - `memory/buffer.rs:69-76`;
  - `limits.rs:124-199` (`StoreLimitsBuilder`);
  - `store.rs:913`;
  - `engine/translator/visit.rs:3314-3333`;
  - `engine/translator/visit_register.rs`.
- `wasmi_ir-0.38.0/src/for_each_op.rs:5141-5147`.
- `wasmi_collections-0.38.0/src/arena/mod.rs` (no removal API).
- The wasmi 2.0.0 README (audit table).
- `unsafe` counts via grep.

**Documents:**
- `docs/reviews/full-review-2026-09-27.md` (§1, §3.7, register rows 846-939, P0-17, D22, §8, §9);
- `docs/reviews/autonomous-session-2026-09-27.md` §5-6;
- `R7-contracts.md` (full);
- `R16-architecture.md` §8, A7;
- `SX1` (R7 rows);
- `R13` (fuzz rows);
- `I1` (R7 references);
- `docs/contracts.md` (banner, §1-2, §5, §9, §12-13, §15-18);
- `docs/reviews/contracts-completion-assessment.md` (full; C-1..C-5, K-1);
- `AUDIT.md:670-735, 1355-1391`;
- `docs/reviews/dependency-review.md:38,121-166`;
- `README.md:41-60`;
- `docs/testnet-reset-plan.md:22`, `docs/testnet-roadmap.md:60`.

**Roster and neighbours:**
- the 28 dossier (ADR-28-1, the `contracts.md` rewrite plan §3.8, F-28-9);
- the 18 dossier (R2-C5 membership nonce, P-A);
- the 19 dossier (tag registry).

`v3-upgrade-mechanism.md` and `px-f4-f5-analysis.md` were checked only for Wasm references. There are none beyond R7-5, which is PX.

---

## 2. Current state

### 2.1 What exists

| Item | State | Evidence class |
|---|---|---|
| Crate `blacksilk-contracts`, `#![forbid(unsafe_code)]` | Exists, builds in CI as a default workspace member | source-read (`Cargo.toml:14`, `contracts/src/lib.rs:15`, `ci.yml:44,74,107`) |
| Consumers | **None** outside its tests and 2 fuzz targets | source-read (grep over all manifests and `.rs`) |
| Consensus | **Not consensus.** No tx kind, no state root, no activation; kinds 0-3 in `tx/src/params.rs:9-14` are coinbase, transfer, PX, PX deploy | source-read |
| wasmi pin | `=0.38.0`, `default-features=false, std`; parser `wasmparser-nostd =0.100.2` | source-read (`contracts/Cargo.toml:17-20`, `Cargo.lock:2787,2846`) |
| Engine config | fuel on; eager compilation; floats off; multi-value, bulk-memory and reference-types **on**; `EnforcedLimits::strict()`; stack limits 1,024 frames / 1 Mi values | source-read (`exec.rs:136-160`) |
| Profile check | wasmparser validation with the restricted features, then structural rules (imports only from `bs`, one bounded memory ≤ 32 pages, ≤ 1 bounded funcref table ≤ 1,024, no start, no passive segments, ≤ 64 KiB code, ≤ 1,024 functions, ≤ 1,024 globals, ≤ 256 locals) | source-read (`profile.rs:139-305`); **tested** `profile_rejects_everything_outside_the_profile`, `profile_accepts_minimal_and_full_modules` |
| Host API | 31 functions; list equals the linker | **tested** `host_api_table_matches_the_linker` |
| Atomic failure, abort, fuel exhaustion, storage limit | Implemented | **tested** `abort_returns_the_code_and_writes_nothing`, `infinite_loop_runs_out_of_fuel`, `too_little_fuel_for_instantiation_fails`, `storage_limit_and_key_rules_are_enforced` |
| Approve/accept model, access list | Implemented | **tested** `notes_must_be_approved_and_accepted_by_their_owner`, `contracts_see_only_their_own_notes` |
| Depth ≤ 4, reentrancy trap | Implemented | **tested** `cross_contract_calls_depth_and_reentrancy`, `a_failing_callee_fails_the_whole_call` |
| Recursion trap, memory growth cap | Implemented | **tested** `unbounded_recursion_traps_inside_the_interpreter`, `memory_cannot_grow_past_its_declared_maximum` |
| SMT (shortcut sparse tree) | Implemented, with a cached root | **tested** `matches_reference_under_random_updates`, `order_of_insertion_does_not_matter`, `adjacent_paths_are_handled` |
| Undo per block | Implemented | **tested** `commit_and_undo_restore_state_and_root`, `counter_persists_across_calls_and_undo_restores_the_root`; fuzz `contract_sequence` (rollback and replay oracles) |
| Determinism | Two `Executor`s in **one process**, plus golden fuel 1,807 for one module | **tested** `execution_is_deterministic_and_fuel_is_pinned`. This does **not** prove cross-platform or cross-version determinism. |
| Fuzzing | `wasm_module` 6 h, `contract_sequence` 4 h, 0 crashes | tested (AUDIT.md:1366-1391); not rerun by me |

### 2.2 What is correct and well designed

These points are source-read and agree with R7 §2.2:
- floats are rejected twice (by the profile and by the engine);
- compilation is eager, so there are no lazy-compilation surprises inside a call;
- the "no partial execution" rule;
- the diff-based execution against a read-only state;
- a reentrancy trap that scans the whole stack;
- pointer reads are bounded by the memory length before allocation (`exec.rs:530-541`);
- `u32` reinterpretation of `i32` lengths everywhere;
- SMT leaf and branch domain separation (`smt.rs:67-73`);
- the leaf hash includes the path, so there is no second-preimage confusion between a single-leaf subtree and a branch;
- undo restores exact roots.

The profile's intent (consensus acceptance defined by BlackSilk, not by the engine) is the right intent. W-3 shows that it is not fully achieved.

### 2.3 What the tests do not prove

- **Cross-platform execution.** There is no aarch64 or 32-bit test. The node refuses non-64-bit targets anyway.
- **Cross-version fuel.** There is one golden number. It is not a corpus.
- **Memory behaviour across many instantiations (C-1, W-2).** Every fuzz input builds a fresh `Executor`, and the fuzz fuel is ≤ 1e6 (`wasm_module.rs:8,17,32`), against the spec's `MAX_CALL_FUEL` of 20M (`contracts.md` §12).
- **Any chain-level property.** None can be tested, because there is no integration.

---

## 3. Problems in scope

### 3.1 Should Wasm be frozen outside the default workspace, or kept research-only?

**What the problem is and why it exists.** Two contract designs were started before PX reached consensus (completion assessment §0). The Wasm one is a default workspace member (`Cargo.toml:14`), so it is:
- compiled and clippy-checked by every `--workspace` run;
- tested in the release overflow job (`ci.yml:107`);
- present in the root lockfile that `cargo audit` checks (`ci.yml:179`);
- present in `fuzz/Cargo.lock` (`ci.yml:180`).

The docs still present it as "v0.2: model approved, implementation in progress" (`contracts.md:17`).

**Security consequences today.** Small and indirect.
- wasmi is in **no shipped binary**: the closure computation shows it reaches no `node`, `wallet`, `miner`, `rpc`, `chain` or `tx` crate.
- It adds about 171 `unsafe` lines to the code compiled and executed on developer and CI machines. None of these crates has a `build.rs` [source-read], so the build-time execution risk is nil.
- The real risks are:
  - **scope creep:** a developer wires `blacksilk-contracts` into `tx` or `chain` because it is "in the workspace and tested";
  - **overclaiming:** the fuzz hours are listed as testnet-readiness evidence in `testnet-reset-plan.md:22` and `testnet-roadmap.md:60`;
  - **CI noise:** advisories against an engine nobody ships.

**Classification.** Architectural and supply-chain hygiene. Not consensus-critical, not privacy-critical.

**Prior art:**
- The project already isolates non-shipped code with `exclude = ["legacy", "research", "third_party", "fuzz"]` (`Cargo.toml:22`). `fuzz/` is an out-of-workspace crate with its own lockfile that path-depends on workspace crates, which is the exact model.
- Cargo's `default-members` does **not** help:
  - CI uses `--workspace`;
  - the lockfile still contains wasmi;
  - so `default-members` changes only a bare `cargo build`.
- Polkadot retired its wasmi-based `pallet-contracts` in favour of `pallet-revive` on PolkaVM (RISC-V). It cited a large validation attack surface, non-constant-time calls, slow interpretation and no linear-time compilation to fast code [ink! docs; Polkadot forum 1084].

**Options:**

| Option | Lockfile | CI | Effort | Risk |
|---|---|---|---|---|
| (a) Keep a default member (today) | wasmi in the root lock | full | 0 | scope creep, noise |
| (b) `default-members` without contracts | unchanged | unchanged (`--workspace`) | S | cosmetic only |
| **(c) `exclude` + own `contracts/Cargo.lock` (recommended)** | shed from the root lock | optional non-blocking scheduled job | S | code can rot; mitigated by an optional scheduled job |
| (d) `git mv contracts research/contracts-wasm` | same as (c) | same as (c) | S–M (path churn, doc links) | more doc edits; clearer signal |
| (e) Delete (history keeps it) | shed | none | S | loses the only candidate engine for a finalize and the SMT; reversible via git |

**Trade-offs.**
- Option (c) keeps the code runnable, needs no doc-link churn and matches 28's plan: 28 moves `docs/contracts.md` to `docs/research/wasm-contracts.md` and does not move code.
- (d) is acceptable if the coordinator prefers all research under `research/`.
- (e) is not recommended. The SMT and the undo model are reusable, and deletion gains nothing over (c).

**What could go wrong with (c):**
- `contracts` path-depends on `crypto`. When built from `contracts/`, the root `[patch.crates-io]` (the Plonky3 patches) and the root `[profile]` do not apply. `crypto` does not use Plonky3 [source-read: `crypto/src/lib.rs` modules], so nothing changes semantically.
- The first `cargo test` inside `contracts/` must generate and commit `contracts/Cargo.lock` with the same exact pins. `=0.38.0` and `=0.100.2` are already exact.
- A scheduled job must use `--locked`.

**Tests that prove the fix:**
- the root `cargo metadata` no longer lists wasmi (a CI assertion: `! grep -q '^name = "wasmi"' Cargo.lock`);
- `cargo test --locked` inside `contracts/` still passes 30/30;
- `cargo audit --file contracts/Cargo.lock` runs in the optional job;
- `bash fuzz/run_campaign.sh` no longer lists the two Wasm targets.

**Invariants:**
- No consensus crate may depend on `blacksilk-contracts`.
- Kinds 2 and 3 stay PX (§3.3).

### 3.2 Can a deterministic Wasm layer coexist with PX without privacy loss?

**Short answer:** only in one form, and only with "privacy loss limited to what the contract author explicitly publishes". **Never** in the `contracts.md` form.

**Why the `contracts.md` form loses privacy (R7-12, confirmed) [source-read on `contracts.md` §2, §15.2]:**
- callers are 1-of-16 CLSAG, the weakest anonymity set BlackSilk ships (R3-1 coinbase-dominated rings);
- code, state, call input, access lists, fuel and storage limits, and note creation and consumption are public;
- front-running is admitted (§15.3);
- the design is Ristretto-only, not post-quantum;
- it adds a second value layer: notes, a Mimblewimble-style kernel and BP+ claims.

A user who touches it leaves the PX anonymity set and becomes linkable through public state.

**The form that can coexist:** a public finalize (Aleo) or a public-function phase (Aztec).
- A proven PX function emits declared public outputs.
- Consensus then applies a deterministic public-state transition whose inputs are exactly those outputs, bound by `io_hash`.
- Value never leaves PX records.

**Conditions for "no privacy loss beyond the explicit publication":**
1. There is no second value layer. Conservation stays one kernel statement (R7 §9).
2. There are no ring-based callers. Only PX transactions trigger a finalize, so the caller is hidden in the full PX set.
3. Finalize inputs are a typed, manifest-declared subset of the function's public outputs (28's F-28-5 `out_words` and manifest), shown by the wallet before calling.
4. The finalize cannot read private PX state and has no host call that exposes the caller, the nullifiers or the fee inputs.
5. Public state is per contract and opt-in. A contract without a finalize is exactly today's PX.
6. There is timing and ordering exposure (MEV, as in Aztec public calls and `contracts.md` §15.3). Contracts that need ordering fairness need commit-reveal or batch settlement (Penumbra).

**What still leaks, inherently:**
- the contract and program identity (already public, P-8);
- the fact that some PX transaction updated this public state at height h;
- the published values.

Joint analysis of public-state updates with PX transaction timing can shrink anonymity for low-traffic contracts. This is an unavoidable, documented limitation, not a defect.

**The engine choice for such a finalize (new recommendation):**

| Engine | `unsafe` | Determinism basis | Audit | Fit |
|---|---|---|---|---|
| wasmi 0.38 | ≈171 in its closure | IR-level fuel (W-4); pinned version | partial (W-1) | poor: a second VM, an unmaintained line (W-5) |
| wasmi ≥ 2.0 | 302 in wasmi alone | "Stable fuel metering": fuel stays the same across versions, and costs are customizable (`Config::operator_cost`) [wasmi 2.0 blog; releases] | none for 2.x | better metering; no audit; still a second VM |
| wasmtime (Cranelift or Winch JIT, Pulley) | JIT | — | — | reject: JIT and FFI-like codegen risk; April 2026 had its largest advisory batch, including a CVSS 9.0 Winch sandbox escape (RUSTSEC-2026-0095) |
| **BVM-1 reference interpreter** (`zkvm`) | **0** (`forbid(unsafe_code)`, `zkvm/src/lib.rs:12`) | own ISA (RV32I + Zmmul), already consensus-reviewed (R4) | internal | **best fit:** one VM for private and public code; Rust toolchain already exists; cycle count is a natural fuel |

This is an architectural recommendation for P3 only. Nothing should be built now (brief §3: "innovation is never merged into consensus merely because it is interesting").

### 3.3 The kinds 2/3 collision

- **What it is:** `contracts.md` §5 assigns kind 2 (call) and kind 3 (deploy). The code assigns `KIND_PX = 2` and `KIND_PX_DEPLOY = 3` (`tx/src/params.rs:12,14`).
- **Why it exists:** the spec predates PX.
- **Status:** purely a documentation conflict. The Wasm crate has **no kind constant and no codec** [source-read: `contracts/src`], and the decoder rejects every other kind (`tx/src/types.rs:405-410`).
- **Consensus impact:** none today. If ever resolved by renumbering (4/5), it would be a new consensus rule.

**Decision (recommended):**
- Do not renumber. Retire `contracts.md` §5's kind numbers with the move to `docs/research/`.
- Record in the ADR that a future finalize is **not a new transaction kind**. It is an effect of PX transactions, or a new kind only through the v3 schedule mechanism (R16-1, `v3-upgrade-mechanism.md`).

**Invariant:** kinds 0-3 keep their meaning forever. No kind number is reserved for Wasm.

### 3.4 C-1 to C-5 (re-verified at `9e422d8`)

All five are confirmed. None is reachable from a node. I recommend **not** fixing them now: under option D the code is frozen, and each fix only matters for a design that will not ship in this form. Instead, record them, with the corrections below, as preconditions for any revival.

**C-1: per-transaction instantiation memory (Medium if revived; confirmed).**
- **Where:** `exec.rs:461-474` (one `Store` per top-level call); `exec.rs:813-860` (every nested `call` instantiates into the **same** store).
- **How big:**
  - wasmi's `ByteBuffer::new` does `vec![0; initial_len]` (`memory/buffer.rs:69-70`).
  - A minimal callee (≈40 bytes) declaring `(memory 32 32)` costs `CALL_BASE` 10,000 + ≈40 fuel per call.
  - A caller can loop sequential calls. The reentrancy check forbids only callees already on the stack, and depth stays 2.
  - At `MAX_CALL_FUEL` = 20M that is ≈1,995 instances × 2 MiB ≈ **3.9 GiB of zeroed allocations** held until the store drops. Arithmetic, [math] from source constants.
  - On Windows a large zeroed allocation commits memory. On Linux, `calloc`/`mmap` is lazy, but `memory.fill` makes it real at 1 fuel per 64 bytes (32K fuel per 2 MiB).
  - Rust aborts on allocation failure, so the node dies.
- **Established fix, from prior art:** Soroban configures wasmi with a `ResourceLimiter` of **`instances: 1`, `memories: 1`, `tables: 1`, `table_elements: 1000`**, and charges module memory to its budget. Each contract invocation gets its own VM or store [rs-soroban-env `budget/wasmi_helper.rs:19-24,126-156`].
- **For BlackSilk, if revived:**
  1. a fresh `Store` per nested call (dropped on return), with an overlay diff passed down;
  2. or wasmi `StoreLimitsBuilder::instances(n).memories(n).memory_size(..)` (available in 0.38: `limits.rs:124-199`, `store.rs:913`);
  3. plus fuel per initial and grown page;
  4. plus a cap on nested calls per transaction.
- **Tests:** a test at `MAX_CALL_FUEL` that asserts peak RSS stays bounded, and that the (N+1)-th instantiation traps deterministically.

**C-2: unbounded module cache (Medium if revived; confirmed; the fix as stated is insufficient, see W-2).**
- **Where:** `exec.rs:124-173`, a `HashMap<Id, Module>` with no eviction.
- **Also:**
  - modules compiled for **rejected** deploys (for example, a deploy whose `bs_init` runs out of fuel) are cached, because `check_module` → `module()` inserts before init runs (`exec.rs:176-180, 262`);
  - compilation happens outside the lock, so two threads can compile the same code twice (benign).

**C-3: engine limits beyond the profile (Low; confirmed with exact numbers).**
- `EnforcedLimits::strict()` in 0.38.0 (`engine/limits/engine.rs:200-221`):
  - globals ≤ 1,000 (the profile allows 1,024);
  - functions ≤ 10,000;
  - tables ≤ 100;
  - memories ≤ 1;
  - data segments ≤ 1,000;
  - element segments ≤ 1,000;
  - params ≤ 32 and results ≤ 32;
  - once function bodies total ≥ 1,000 bytes, an average body of ≥ 40 bytes.
- The profile does not state the last five.
- `check_module` runs both the profile and the compile (`exec.rs:176-180`). So the consensus rule is "profile ∧ wasmi 0.38 compiles", which contradicts `profile.rs:11-12` and `contracts.md` §9.1's last paragraph (W-3).
- `contracts.md` §9.1 does list the strict limits, so the doc is self-contradictory rather than silent.

**C-4: encoders do not check lengths (Low; confirmed, with one addition).**
- `types.rs:93-94` panics if `policy.len() > 64` (slice out of range).
- `types.rs:217-218` panics if `scope.len() > 32`.
- **Addition:** `Note::encode` (`types.rs:61`) writes `policy.len() as u8`, so a policy of 256 bytes or more makes the **state-root leaf encoding non-injective** (truncated length prefix). Two different notes could produce the same leaf preimage.
- This is not reachable without a decoder, but it is exactly the class of bug that becomes consensus-critical at M3.

**C-5: `commit` panics on an inconsistent diff (Low; confirmed).**
- Where: `state.rs:220-223` (contract id reused), `:239` (consumed note missing), `:243` (note id reused), `:261` (commit outside a block).
- It is correct only under in-order execute-then-commit.

### 3.5 wasmi version, advisories and audits (the research questions)

**Releases [GitHub releases; CHANGELOG]:**
- 0.36.0: 2024-07-24; 0.36.1–0.36.5: 2024-09-20 → 2024-10-11;
- 0.37.0–0.37.2: 2024-09-30 → 2024-10-04;
- **0.38.0: 2024-10-06, with no patch release ever;**
- 0.39.0: 2024-11-04; 0.40.0: 2024-11-27;
- 1.0 later; v1.1.0: 2026-06-12;
- **v2.0.0: 2026-09-01.** Redesigned executor. Its "stable fuel metering" keeps the metered fuel per unit of execution the same across wasmi versions, and it adds customizable per-operator costs.

**Advisories (GitHub Security Advisories of wasmi-labs/wasmi):**

| Advisory | Severity | Affected | Patched | 0.38.0 |
|---|---|---|---|---|
| GHSA-75jp-vq8x-h4cq / **CVE-2024-28123**: out-of-bounds write on host→Wasm calls with more than 128 parameters | Critical | 0.15.0–0.31.0 | 0.31.1 | not affected (version range); BlackSilk's host calls `bs_call`/`bs_init` with 0 parameters, and strict limits cap params at 32 |
| GHSA-g4v2-cjqp-rfmq / **CVE-2025-66627**: use-after-free in linear memory on growth | High (CVSS 8.4) | 0.41.0–1.0.0 | 0.41.2+, 0.47.1+, 0.51.3+, 1.0.1+ | not affected (version range) |

- A RustSec search found **no 2026 wasmi advisory**. The 2026 RustSec entries in this space are wasmtime (RUSTSEC-2026-0086, -0095, -0182, -0269, …).
- CI already runs `cargo audit` (`ci.yml:179-180`).

**Maintenance.** The CVE-2025-66627 backports went only to the 0.41, 0.47, 0.51 and 1.0 lines. **No 0.38.x patch was ever published.** wasmi's SECURITY.md does not state supported versions.
- So 0.38 is effectively unsupported (W-5).
- For a consensus engine, a future advisory against 0.38 would force a consensus upgrade to a different line, with different IR fuel.

**Audits:**
- **SRLabs (2023-12-20), v0.31.0 for Parity:**
  - code review plus differential fuzzing against wasmtime, for execution and for gas;
  - "No vulnerabilities were identified";
  - it recommends periodic audits "on major changes to the core logic".
  - 0.32+ replaced the engine (the register machine), so this audit says little about 0.38.
- **Runtime Verification (delivered 2024-11-27), for the Stellar Development Foundation:**
  - target: **v0.36.0, commit `02621ad`**; fix commits 0.36.1–5 analysed; 8 weeks;
  - code review prioritised the executor, then the translator, with an `unsafe` checklist appendix;
  - fuzzing: translation 14 machine-days (0.36.0), execution 26 (0.36.x) + **8 (0.37.x)**, differential 30 (0.36.x);
  - 8 fuzz findings (F1–F8: 2 memory-corruption, 3 silent output mismatches versus wasmtime, 1 hang, 1 panic, 1 assertion). All were fixed in 0.36.x and in 0.37.x before or at 0.37.2.
  - **Code-review findings "acknowledged but not addressed":**
    - **C4 (High):** unbounded `isize`/`usize` offsets to raw-pointer `offset`/`add`;
    - **C2 (Low):** register-allocation bound inconsistency;
    - **C3 (Low):** `FuelCosts::costs_per` truncates, so bulk and table operations are under-charged.
  - C1 (Low) was fixed on main by PR #1207. I did not verify whether that is in 0.38.0.
  - The report notes that several issues needed **reference-types or multi-value, which Soroban disables**, and says such bugs indicate design risk.
- **I verified one post-audit 0.36.5 fix against 0.38.0.** Commit `82c9388` ("table.get index visitation", RV F3 class) is a hand-written visitor fix. In 0.38 that visitor is generated from `wasmi_ir` (`for_each_op.rs:5143-5147`: `index` is an input field), so the bug is structurally absent [source-read; medium-high confidence].
- **Conclusion:** 0.38.0 is **downstream of an audited base with all audit-found crashes fixed**, but it is **not itself an audited release**. The repository's wording should say exactly that (W-1).

**Deterministic-Wasm literature.**
- Wasm 3.0 (completed 2025-09-17) defines a **deterministic profile**: canonical positive NaNs, and fixed semantics for the relaxed-SIMD instructions [webassembly.org; spec numerics].
- The profile does **not** cover:
  - resource exhaustion (stack depth, memory growth failure, which are implementation-defined);
  - metering.
- BlackSilk sidesteps the float and SIMD part (both are banned) and pins stack limits.
- Metering remains engine-defined, and gas mispricing is a known chain-DoS class in production Wasm chains:
  - CosmWasm CWA-2024-004: gas off by about 10×, RUSTSEC-2024-0361;
  - CWA-2023-004: excessive function parameters, RUSTSEC-2024-0366;
  - CWA-2024-006: non-determinism leading to a chain halt.

---

## 4. New findings

| ID | Title | Severity | Status | Where | Scenario | Confidence |
|---|---|---|---|---|---|---|
| **W-1** | "0.38.0 is covered by an external audit (0.36–0.38)" overstates the evidence | **Low** (claims; the owner's no-overclaiming policy) | Not implemented (docs wrong) | `contracts/Cargo.toml:13-16`; `docs/contracts.md:546-552, 985-987`; `AUDIT.md:712`; `docs/reviews/dependency-review.md:38` | RV audited v0.36.0 (`02621ad`) and fixes 0.36.1–5; 0.37 was only partly fuzzed; NEWS.md says "partially 0.37-0.38"; 0.38 has post-audit refactors in the `unsafe` load/store paths (#1224); C2/C3/C4 remain unaddressed. A reader would believe 0.38 is audited. | High |
| **W-2** | wasmi never frees compiled code, so bounding the module cache (the C-2 fix) cannot bound memory | **Medium if revived**; Info now | Not implemented | `exec.rs:124-173`; wasmi `engine/code_map.rs:82,221-224` (append-only `Arena`; `wasmi_collections` arena has no remove); the same "never reallocate or move for the lifetime of the engine" design in 2.0 [wasmi 2.0 blog] | Every `Module::new`, including those that fail later or come from rejected deploys, appends to the Engine's code map for the process lifetime. A long-running node that compiles attacker-supplied modules (the mempool admission of deploys) grows without bound, whatever the cache policy. Fix: compile only after fee-bearing admission; recycle the `Engine` (a new `Executor`) at block boundaries when code-map growth passes a threshold; cap per-block new code. | High (source-read) |
| **W-3** | The profile claims to define acceptance independently of the engine; it does not | **Low** | Not implemented | `profile.rs:11-12`; `contracts.md:586-587` versus `:534-543`; `exec.rs:176-180` | A module with 1,001–1,024 globals, or with more than 1,000 bytes of bodies averaging under 40 bytes, or with more than 32 params, passes `profile::check` and fails `check_module`. Acceptance depends on wasmi's `strict()`, so an engine change silently changes the consensus module rule. Fix if revived: state every strict limit in the profile (globals 1,000; segments; params and results 32; the average-size rule) and test each boundary on both sides. | High |
| **W-4** | The fuel schedule inherits RV C3 (truncating division) and is IR-defined, so it is not a function of Wasm semantics | **Low if revived**; Info now | Accepted limitation (documented in part, `contracts.md` §9.5) | wasmi `engine/config.rs:135-137`; `exec.rs:103` (golden 1,807) | Bulk and table operations under 64 bytes, or under 8 copies, cost 0 extra fuel. Fuel depends on wasmi's register allocation and fusion, so no Wasm-level spec can predict it. One golden number cannot detect schedule drift in untested paths. Prior art: CosmWasm CWA-2024-004 (a 10× gas mispricing, a chain-DoS); Soroban calibrates its own `FuelCosts`. If revived, use a wasmi line with stable, operator-defined fuel (2.x) or BVM-1 cycles, plus a golden fuel **corpus**. | High |
| **W-5** | wasmi 0.38 is an unsupported line | **Accepted limitation** (moot under D) | Accepted limitation | `contracts/Cargo.toml:17` | No 0.38.x patch release exists; the 2025 CVE was backported only to 0.41, 0.47, 0.51 and 1.0. Any future advisory affecting 0.38 has no patched 0.38. For a consensus engine, that forces a fuel-changing consensus upgrade. | High |
| **W-6** | The profile enables reference types and multi-value; Soroban, the audited production configuration, disables both | **Low if revived** | Not implemented | `exec.rs:145-150`; `profile.rs:104-124` | The RV report rated bugs needing these proposals lower *because Soroban disables them*, so they received less assurance weight. The BlackSilk engine enables them, adding a lower-assurance surface (tables, `call_indirect` typing, multi-value copies). Prior art: Soroban `wasm_multi_value(false)`, `wasm_reference_types(false)` [rs-soroban-env `wasmi_helper.rs:140-156`]. Fix if revived: MVP + mutable-global + sign-extension (+ bulk-memory only if a toolchain needs it). | Medium–High |
| **W-7** | `Note::encode` length prefix is `u8`, so the leaf encoding is non-injective above 255 bytes of policy (adds to C-4) | **Low if revived** | Not implemented | `types.rs:61` | Two notes with different policies of 256 bytes or more can encode to the same `LEAF_NOTE` preimage prefix structure. It is a state-root ambiguity only once decoders exist. Fix: check `policy.len() ≤ MAX_POLICY` in every constructor and encoder, returning `Result`. | High |
| **W-8** | The fuzz harnesses cannot see cross-call or long-lived memory growth | **Low** | Not implemented | `fuzz/fuzz_targets/wasm_module.rs:8,32`; `contract_sequence.rs:124,146`; `contracts/tests/fuzz.rs:37,79` | A fresh `Executor` is built per input and fuel is ≤ 1e6 (20× below `MAX_CALL_FUEL`), so C-1, C-2 and W-2 are structurally invisible. "0 crashes in 10 h" is therefore no evidence on resource exhaustion. | High |
| **W-9** | Wasm fuzzing is listed as testnet-readiness evidence | **Low** (claims) | Not implemented | `docs/testnet-reset-plan.md:22`; `docs/testnet-roadmap.md:60`; `docs/reviews/review-package.md:112` | Readers may count 10 h of engine fuzzing as testnet evidence, but it covers no consensus path (as AUDIT.md:1366 itself says). Fix: remove or annotate "not testnet evidence; engine not integrated". | High |
| **W-10** | Consolidated review P0-17 framing: "removes wasmi `unsafe` from the release supply chain" | **Informational** (correction) | — | `full-review-2026-09-27.md:1071` | wasmi is in no release binary today. The effect of D-freeze is on the lockfile, CI, audit and review surface, and it prevents future wiring. The decision is unchanged; only the justification changes. | High |
| **W-11** | Wasm-only hash tags and crypto stay in the consensus crypto crate | **Informational** | Deferred | `crypto/src/hash.rs:55-73,68` (`CONTRACT_*`, `WALLET_CONTRACT_*`, `INPUT_CONTEXT_CALL`); `crypto/src/{schnorr,membership,claims}.rs` (1,037 lines, no consumer) | These are dead code in a consensus crate. The membership nonce (R2-C5, now 18's P-A) leaks the key after two signatures under a broken RNG. Recommendation: feature-gate the three modules (`contracts-research`, off by default), enabled only by the frozen crate. **Keep the tag strings registered in `tags::ALL` forever** (never reuse `contract/*` names for PX), for domain-separation hygiene (19). | High |

**Re-confirmed, not new:** C-1 … C-5 (§3.4), R7-12 (§3.2), R7-10 / R16-11 (W-11).

**Challenged:**
- The completion assessment says fixing C-1..C-5 "must be done before M3". I agree. Under D, M3 does not happen, so they should be marked **"revival preconditions"**, not "open", to stop them counting as testnet work.
- The C-2 fix text ("a bound or eviction") is incomplete; see W-2.

---

## 5. Implementation plan for phase 2

Ordered. None of the items changes consensus or identity. Ownership is proposed. Files marked (coord) are shared.

| # | Work item | Files (ownership) | Consensus | Identity | Tests | Bench | Docs | Diff. | Prio |
|---|---|---|---|---|---|---|---|---|---|
| **W29-1** | **ADR "Wasm contracts: frozen research (D-freeze)"**: the decision, the evidence of §3.1-3.5, the preconditions for revival (C-1..C-5, W-2..W-4, W-6..W-8), the finalize-only door, the BVM-1 engine recommendation, "no kind reserved" | new `docs/reviews/adr-wasm-contracts.md` (**29**) | none | none | — | — | the ADR itself | S | **P0** (owner sign-off on D22) |
| **W29-2** | **Move `contracts` out of the root workspace** (`members` → `exclude`); generate and commit `contracts/Cargo.lock`; drop `-p blacksilk-contracts` from the overflow job; add a CI assertion that wasmi is absent from the root `Cargo.lock`; optional scheduled, non-blocking job: `cd contracts && cargo test --locked && cargo audit` | `Cargo.toml` (**29**, coord 46); `contracts/Cargo.lock` new (**29**); `.github/workflows/ci.yml` lines 44/74/107 context and a new job (**coord 43**, which owns CI) | none (externally invisible) | none (the fingerprint covers constants only; no consumer) | CI: `cargo metadata` has no wasmi; `contracts` 30/30 pass standalone; full-workspace suite unchanged | none | README table row `contracts/` (coord 47) | S | **P1** |
| **W29-3** | **Move the Wasm fuzz targets out of `fuzz/`**: remove `wasm_module`, `contract_sequence` (and their seeds) from `fuzz/Cargo.toml`, `fuzz/run_campaign.sh:22` and `fuzz/src/seeds.rs:190-210`; re-home them as `contracts/fuzz/` (their own lock) or drop them; regenerate `fuzz/Cargo.lock` | `fuzz/Cargo.toml`, `fuzz/Cargo.lock`, `fuzz/run_campaign.sh`, `fuzz/src/seeds.rs` (**coord 41**, which owns fuzz); `contracts/fuzz/` new (**29**) | none | none | fuzz-smoke still runs the 7 remaining targets; `cargo audit --file fuzz/Cargo.lock` has no wasmi | none | AUDIT.md fuzz table note (coord 47) | S | P1 |
| **W29-4** | **Status banners and claim corrections**: banner on the moved spec ("superseded research; not consensus; not planned for v1; kinds 2/3 are PX"); fix W-1 wording in the Cargo.toml comment, AUDIT.md R7 table, dependency-review; W-3 contradiction; W-9 readiness rows; mark C-1..C-5 "revival preconditions"; `unsafe` closure count ≈171 | `contracts/Cargo.toml` comment and `contracts/src/profile.rs:11-12` comment (**29**); `docs/research/wasm-contracts.md` banner only (file move by **28**, per its §3.8); `AUDIT.md` R7 section, `docs/reviews/dependency-review.md:38,166`, `docs/reviews/contracts-completion-assessment.md` §3a/§5, `docs/testnet-reset-plan.md:22`, `docs/testnet-roadmap.md:60`, `docs/reviews/review-package.md:112` (**coord 47**) | none | none | a doc-claim grep (with 47): no "0.38 … audited" outside the corrected sentence | none | as listed | S | **P0** (claims) |
| **W29-5** | **Feature-gate the Wasm-only crypto**: `crypto` feature `contracts-research` (off by default) gating `schnorr`, `membership`, `claims`; the `contracts` crate enables it; the tags stay in `tags::ALL` | `crypto/Cargo.toml`, `crypto/src/lib.rs:30,37,40` (**coord 18/19**, which own crypto; 18's R2-C5 fix first if it lands in these files); `contracts/Cargo.toml` (**29**) | none | none (no consumer; KATs of the tag registry unchanged) | `cargo test -p blacksilk-crypto` (default) and `--features contracts-research` both pass; `tags::ALL` uniqueness test unchanged | none | `crypto` module docs; R16-11 closed | S | P2 |
| **W29-6** | **Revival-precondition tests (only if the owner keeps a research CI job)**: failing-first tests documenting C-1 (instantiation count at 20M fuel), C-4/W-7 (over-long policy and scope panics, encode injectivity), W-3 (the 1,001-globals and average-size boundary) as `#[ignore]`d regression specs | `contracts/tests/limits.rs` new (**29**) | none | none | the tests themselves | peak RSS for C-1 | ADR appendix | S | P3 |
| **W29-7** | **(Future, only with evidence of demand) the public-finalize design study on BVM-1**: effect model per R16 (a "public mapping update" effect), inputs = manifest-typed public outputs, cycles as fuel, per-contract opt-in, MEV analysis | new design doc (**28** leads; **29** reviews the engine choice; **46** for the effects model) | would be **CONSENSUS** (activation height via the v3 schedule) | new activation | full consensus discipline (brief §3) | verifier and executor cost | new spec | L | P3 |

**Nothing in this plan touches:**
- PX, the kernel ELF or `tx/`;
- the genesis or the golden vectors.

The CI edits are the only shared-file changes.

---

## 6. Dependencies and conflicts (by roster number)

| # | Relationship |
|---|---|
| 28 private-contracts-px | Same decision (ADR-28-1 = option D). **28 owns** the `docs/contracts.md` rewrite and the `git mv` to `docs/research/wasm-contracts.md`; 29 adds only the banner and the W-1/W-3 corrections inside it, after the move. 28's finalize door and `out_words` or manifest are preconditions for §3.2's coexistence conditions. |
| 18 crypto-randomness | R2-C5 / P-A edits `crypto/src/membership.rs`. W29-5 gates the same module. **Order:** 18's fix first (or 18 decides the module needs no fix because it is gated off), then W29-5. |
| 19 hash-domain-separation | The `contract/*` tags stay in `tags::ALL` (W-11). If 19 introduces `Tag` typing (19 item 7), W29-5 must follow its API. |
| 41 fuzzing | W29-3 edits `fuzz/` files that 41 owns. 41 decides whether the Wasm targets are dropped or re-homed. |
| 43 ci-reproducibility | Owns `ci.yml`. W29-2's edits (overflow `-p` list, the no-wasmi assertion, the optional research job) go through 43. |
| 44 supply-chain | wasmi, string-interner and the other crates leave the root lock (reduces 44's review list). W-1 and W-5 facts feed 44's dependency register. |
| 46 architecture-consensus-separation | R16-11 / A7 is the same item. 46 may prefer `research/contracts-wasm` (option d); either works. 29 recommends (c). |
| 47 docs-spec-consistency | W-1, W-3, W-9, W-10 doc edits; README row. |
| 23 zkvm-bvm | Only for the P3 recommendation that a future finalize run on the BVM-1 interpreter (no action now). |
| 50 red-team | No overlap: the Wasm code is not reachable from the merged v3 consensus. |

---

## 7. Open questions for the coordinator

1. **Owner sign-off on D22 (option D).** Everything above assumes it. If the owner instead wants to keep Wasm "alive", the minimum is:
   - W29-2 (out of the workspace) anyway;
   - C-1..C-5 and W-2..W-8 fixed before any integration;
   - a wasmi line change (0.38 is unsupported), which is a fresh consensus-engine decision.
2. **Placement:** `exclude` in place (c, recommended) or `git mv contracts research/contracts-wasm` (d)? This decides the doc-link edits for 28 and 47.
3. **Research CI:** keep an optional scheduled job for `contracts/` (it prevents rot and runs `cargo audit` on its lock), or let it build only on demand? My recommendation is a weekly non-blocking job. It is cheap.
4. **Wasm fuzz targets:** re-home to `contracts/fuzz/` or delete? The corpora (15,764 files) exist only on the developer machine (R13). Deleting loses nothing in git.
5. **Crypto gating (W29-5):** gate behind a feature (recommended) or move the three modules physically into `contracts/`? Moving changes more files and conflicts more with 18/19.

---

## 8. Sources

**Repository (source-read at `9e422d8`):** the files listed in §1.

**wasmi (primary):**
- Releases (v2.0.0 2026-09-01; v2.0.0-beta.10; v1.1.0 2026-06-12): https://github.com/wasmi-labs/wasmi/releases
- CHANGELOG (0.36.x–0.40.x dates and fixes): https://raw.githubusercontent.com/wasmi-labs/wasmi/main/CHANGELOG.md
- NEWS.md ("Wasmi v0.36 and partially 0.37-0.38 have been audited by Runtime Verification Inc."): https://github.com/wasmi-labs/wasmi/blob/main/NEWS.md
- README audit table: https://github.com/wasmi-labs/wasmi/blob/main/README.md (also the local `wasmi-2.0.0/README.md:36-43`; the local `wasmi-0.38.0/README.md:26` mentions only SRLabs 0.31)
- SECURITY.md (no supported-version statement): https://github.com/wasmi-labs/wasmi/blob/main/SECURITY.md
- Advisories list: https://github.com/wasmi-labs/wasmi/security/advisories
- GHSA-g4v2-cjqp-rfmq / CVE-2025-66627: https://github.com/wasmi-labs/wasmi/security/advisories/GHSA-g4v2-cjqp-rfmq
- GHSA-75jp-vq8x-h4cq / CVE-2024-28123: https://github.com/wasmi-labs/wasmi/security/advisories/GHSA-75jp-vq8x-h4cq
- Runtime Verification, *Security Audit Report: Wasmi*, delivered 2024-11-27 (scope v0.36.0 `02621ad`; findings C1–C4, CI1–CI4, F1–F8; `unsafe` checklist): https://raw.githubusercontent.com/wasmi-labs/wasmi/main/resources/audit-2024-11-27.pdf ; portal: https://amp.runtimeverification.com/public-report/wasmi (unreachable from here)
- SRLabs, *Wasmi security assurance*, v1.3, 2023-12-20 (v0.31.0): https://raw.githubusercontent.com/wasmi-labs/wasmi/main/resources/audit-2023-12-20.pdf
- Fix commit `82c9388` (table.get index visitation) and the compare v0.36.4…v0.36.5: https://github.com/wasmi-labs/wasmi/commit/82c9388f ; https://github.com/wasmi-labs/wasmi/compare/v0.36.4...v0.36.5
- Wasmi 1.0 post: https://wasmi-labs.github.io/blog/posts/wasmi-v1.0/
- Wasmi 2.0 post (stable fuel metering; append-only CodeMap): https://wasmi-labs.github.io/blog/posts/wasmi-v2.0/

**Production prior art:**
- Stellar rs-soroban-env, wasmi config and limits (`instances: 1`, `multi_value(false)`, `reference_types(false)`, calibrated `FuelCosts`): https://github.com/stellar/rs-soroban-env/blob/main/soroban-env-host/src/budget/wasmi_helper.rs ; the pin `soroban-wasmi =0.31.1-soroban.20.0.1`: https://github.com/stellar/rs-soroban-env/blob/main/Cargo.toml
- ink!/Polkadot, move from wasmi `pallet-contracts` to PolkaVM `pallet-revive`: https://use.ink/docs/v6/background/why-riscv-and-polkavm-for-smart-contracts/ ; https://use.ink/docs/v6/faq/migrating-from-ink-5-to-6/ ; https://forum.polkadot.network/t/ebpf-contracts-hackathon/1084 ; https://forum.polkadot.network/t/contracts-on-assethub-roadmap/9513
- CosmWasm advisories: CWA-2024-004 gas mispricing (RUSTSEC-2024-0361) https://rustsec.org/advisories/RUSTSEC-2024-0361.html ; CWA-2023-004 excessive params (RUSTSEC-2024-0366) https://rustsec.org/advisories/RUSTSEC-2024-0366.html ; CWA-2024-006 non-determinism and chain halt https://github.com/CosmWasm/advisories/blob/main/CWAs/CWA-2024-006.md
- wasmtime 2026 advisories (context for rejecting JIT engines): https://rustsec.org/packages/wasmtime.html ; https://rustsec.org/advisories/RUSTSEC-2026-0086.html ; https://rustsec.org/advisories/RUSTSEC-2026-0182.html

**Deterministic Wasm:**
- Wasm 3.0 completed (deterministic profile): https://webassembly.org/news/2025-09-17-wasm-3.0/
- Spec numerics (deterministic NaN): https://webassembly.github.io/spec/core/exec/numerics.html
- Relaxed SIMD overview (deterministic profile): https://github.com/WebAssembly/spec/blob/wasm-3.0/proposals/relaxed-simd/Overview.md
- Wasmtime deterministic execution guide (NaN canonicalization, fuel): https://docs.wasmtime.dev/examples-deterministic-wasm-execution.html

**Privacy-architecture prior art:** as cited in R7 §11 (Aleo finalize, Aztec public and private functions, Zexe, Penumbra batch swaps, Secret Network SGX). Not re-fetched; R7's citations stand.

**Confidence notes:**
- Code facts: [source-read].
- The C-1 figure (≈3.9 GiB): [math] from source constants and the spec's provisional `MAX_CALL_FUEL`. It was not measured.
- The `unsafe` counts are grep line counts, not audited block counts.
- Whether RV C1 (PR #1207) is in 0.38.0: [unknown].
- The Soroban configuration is main-branch source as fetched on 2026-09-27.
