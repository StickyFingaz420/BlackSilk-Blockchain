# 42 mutation-formal: mutation testing, invariants and formal-tool choice

Specialist 42, BlackSilk engineering phase 2, phase 1 (research and briefing). This is internal engineering work, not an audit. Nothing here claims that any component is secure, proven or verified. Where a formal tool is recommended, the claim it supports is "bounded model checking of property P under abstraction A", never "formally verified".

---

## 1. Scope and what I read

**Commit:** `9e422d8` (`rebuild/core`, clean tree).

**Brief, roster and decisions:**
- `C:/bszkeval/p2/brief.md`;
- `roster.md`, my entry (42) and the neighbours 01, 02, 03, 05, 11, 15, 16, 20, 40, 41, 43, 44 and 46;
- `decisions.md`, every entry;
- the dossiers that request work from 42: 01 (item 11, `validate.rs` 880–1120), 02 (`mark_complete`, `recompute_target`), 03 (the `difficulty.rs` kill set and optional Kani), 05 (`fpu.rs`, `vm.rs` decode), 11 (I1 mutation check on `px.rs` and `validate.rs`), 15 (W6 `clsag.rs`), 16 (`bulletproofs_plus.rs`) and 20 (W3, the px-core campaign).

**Reviews:**
- `docs/reviews/full-review-2026-09-27.md`: §1–§3.13, the register rows T-1…T-15, P0-10, P1-13, §8 (never-change) and §9;
- `docs/reviews/autonomous-session-2026-09-27.md`: §1–§3 and §7;
- `full-review-2026-09-27/R13-testing-supplychain.md` in full (T-1, T-3, T-4, T-5 and T-12 are the basis of my scope);
- SX2's rows for T-3 and T-12;
- R16 §2.

**Code read in full:**
- `consensus/src/{chain,difficulty,pow,timestamp,merkle,hash,lib,header}.rs`, plus the test list of `schedule.rs` and `params.rs`;
- `tx/src/validate.rs`, and `tx/src/codec.rs` 1–140;
- `px-core/src/{kernel,record,call,lib,hash}.rs`;
- `chain/src/manager.rs` 760–830.

**Tests read:**
- `consensus/tests/golden.rs` (LWMA, MTP) and `consensus/tests/randomx_end_to_end.rs`;
- the unit-test lists of `consensus/src/chain.rs`;
- `px-core/src/hash.rs` tests;
- the headers of `px/tests/kernel.rs` and `px/tests/fuzz.rs`;
- the block-rule sections of `tx/tests/adversarial.rs` (B5/B6) and `tx/tests/deploy_rules.rs` (deploy budget);
- test counts for every test file in `consensus`, `tx`, `px`, `px-core`, `chain` and `randomx`.

**Build configuration:**
- root `Cargo.toml` (profiles and dev opt-level overrides);
- `consensus`, `tx`, `px` and `px-core` `Cargo.toml`;
- `.gitignore` (what cargo-mutants would copy);
- `.github/workflows/ci.yml` (jobs, toolchain 1.98.1);
- `px/src/prove.rs` (`KERNEL_ELF = include_bytes!("../kernel.elf")`, a committed, pinned ELF).

**Machine facts:**
- 8 logical cores and 16 GB RAM (17.08 GB reported);
- Windows 10, rustc and cargo 1.98.1;
- `~/.cargo/bin` has `cargo-fuzz` and `cargo-miri`, but **no `cargo-mutants` and no Kani**;
- WSL2 is enabled but has **no installed distribution**.

**Web research:** primary sources only; see §8. Covered: cargo-mutants (book, source `config.rs`, releases, crates.io), Kani (install guide, releases, crates.io, ASE 2026 paper), Prusti, Creusot, Verus, hax and libcrux, rust-bitcoin's workflows and `mutants.toml`, eth2.0-dafny, the Cardano formal ledger specs and the OtterSec Solana/Kani case study.

**Rules followed:** read-only; no builds; no cargo invocations beyond `--version`.

---

## 2. Current state

| # | Claim | Evidence class |
|---|---|---|
| S1 | No mutation testing has been run by tool anywhere in the project. There is no `.cargo/mutants.toml`, no `mutants.out`, no workflow, and `cargo-mutants` is not installed on the machine. | source-read (repo tree, `~/.cargo/bin`) |
| S2 | The "15/15 non-equivalent mutants caught" figure (autonomous session §3; `f6c98c3`) is a **hand-selected** set of arithmetic mutants against the new golden vectors, not a tool-generated census. It shows those 15 are killed; it gives no mutation score. | source-read (commit message, test comments) |
| S3 | R13 T-3's predicted LWMA survivors are now killed by `consensus/tests/golden.rs`: `(n+1)→n` by `lwma_steady_state_is_exact` (the exact result 10 000 against the mutant's 9 836); `6*t→7*t` by `lwma_solve_time_cap_is_6t`; `/20→/19` by `lwma_increase_floor_is_n2_t_over_20`. The register row "the LWMA mutant `(n+1)→n` survived" (full review §4, R16-2/T-3) is therefore stale for that mutant. | source-read + math (hand-recomputed) |
| S4 | Consensus arithmetic is pure and deterministic, takes `now` as a parameter, and uses no unsafe code. It is ideal for mutation testing and bounded model checking. The only slow consensus test is `randomx_end_to_end` (real light-mode RandomX at difficulty 4 and 8). | source-read |
| S5 | `px-core` is `no_std`, has no dependencies, allocates nothing, and every public function is total over fixed-size arrays with bounded loops (`TREE_DEPTH = 32`, `MAX_FN = 2`). Permutations are injected through a trait. This is a near-ideal Kani target. | source-read |
| S6 | `px-core` has only **4 unit tests** (`hash.rs`, toy permutation). Its real test oracle is in `px/tests`: `kernel` (6), `fuzz` (2) and `state` (4) compare the **native** kernel against the **pinned committed ELF** run in the guest interpreter (`px/src/prove.rs:30`). A native px-core mutant is therefore compared against unmutated guest code. That is a strong differential oracle, but it catches only verdict changes on the witnesses the tests generate. | source-read |
| S7 | `tx` tests include PX proving (`px_consensus`, 431 s in release; `deploy_rules` uses kernel budgets). Its dev profile optimizes only `tx`, `crypto`, `curve25519`, `randomx`, `blake2`, `aes` and `argon2`. `zk`, `zkvm`, `px` and Plonky3 build at opt-level 0 under the default `test` profile, so any proving or zkVM-interpreting test is far slower under cargo-mutants' default profile than in CI. | source-read (root `Cargo.toml`) |
| S8 | The tree that cargo-mutants would copy per job is about 100–130 MB (400 MB minus the 385 MB fuzz corpus, which is gitignored). `.claude/` worktrees (506 MB) and `fuzz/target` are gitignored. `Cargo.lock` is tracked and re-included (`.gitignore:60 !/Cargo.lock`), so copies build with the locked graph. | source-read (`git check-ignore --no-index`) |
| S9 | Boundary coverage of block rules is thin. B6 weight is tested only far over the limit (`tx/tests/adversarial.rs:689-695`, max 1000). The deploy budget is tested with a sum strictly over the limit (`deploy_rules.rs:387`). **No test anywhere in the workspace produces `BlockError::PxBytesExceeded`** (grep over every `*.rs`). | source-read (grep) |
| S10 | Kani, hax and Creusot do not run natively on Windows. This machine has WSL2 without a distribution. | tested (`wsl --status`) + primary docs |

---

## 3. Problems in scope

### 3.1 P-A: test adequacy of consensus-critical code is unmeasured (R13 T-12)

- **What and why.** Coverage and mutation adequacy have never been measured. The consensus tests were largely self-consistent until `f6c98c3`. Golden vectors now pin the main arithmetic, but nobody knows which *rules* can be deleted or weakened without any test failing. S9 is one concrete instance.
- **Security consequence.** A refactor during phase 2 (about 50 agents editing consensus-adjacent code) can silently change validity, which forks the chain. Examples: a `>` that becomes `>=` at a byte budget, or a dropped PX byte cap.
- **Class:** consensus-critical (testing infrastructure). Not privacy-critical.
- **Literature and practice:**
  - cargo-mutants is the de facto Rust tool (27.1.0, June 2026; its CI runs on Windows, Linux and macOS).
  - rust-bitcoin runs it weekly in CI. It restricts `examine_globs` to its consensus-encoding, units and primitives crates, excludes Debug/Display/Error and infinite-loop-prone functions by regex, and files an issue on missed mutants (`cron-weekly-cargo-mutants.yml`, `.cargo/mutants.toml`).
  - R13 T-12 proposes the same: consensus first, then `--in-diff` in CI.
- **Trade-offs and risks:**
  - Cost. Every mutant is an incremental build plus a test run, and the heavy PX tests dominate (§5.2 estimates).
  - Flaky or time-sensitive suites produce false "caught" or "missed" results (cargo-mutants' limitations page: hermetic tests are required). The consensus, px and tx suites are seeded and hermetic. `p2p/tests/network.rs` is not (R13 T-5), so p2p is excluded.
  - Equivalent mutants need human triage. The risk is an "equivalent" label used to hide a real gap, so every exclusion must carry a written reason and a reviewer.
- **Tests that prove the fix.** A mutation census with zero unexplained missed mutants in the target files, and a killing test for every former survivor.
- **Invariants that must never change:**
  - never-change item 31 ("consensus pins as failing tests; extend, never loosen");
  - mutation exclusions never touch rule-bearing functions without a written equivalence argument.

### 3.2 P-B: formal statement of the invariants that the tests only sample

- **What and why.** The key consensus and PX properties are tested on examples (`transfer` rejections, LWMA vectors, varint round trips). No property is checked over all inputs, even where the input space is small enough for a bit-precise model checker: varints, header encoding, `seed_height`, BabyBear `add`, and the kernel's framing and balance under hash abstraction.
- **Security consequence.** Rare-input bugs sit exactly where random tests do not reach. An example is `lib.rs:17` (`add`) with `a + b == P`, probability about 2^-31 per addition (F42-5).
- **Class:** consensus-critical (px-core is compiled into the pinned kernel ELF).
- **Literature:**
  - Kani (AWS; ASE 2026 industry paper) compiles MIR to CBMC and checks panics, overflow, bounds and user assertions. It is used on Firecracker and s2n-quic, and by the Rust std verification effort (more than 16,000 harnesses per change).
  - rust-bitcoin runs Kani daily in CI.
  - OtterSec used Kani on Solana programs and reported path explosion, which they mitigated with a verification-friendly SDK layer.
  - Deductive tools (Prusti, Creusot, Verus) and extraction tools (hax, Aeneas) prove more, at far higher cost (§3.4).
- **Trade-offs:**
  - Bounded model checking proves properties only up to the bound and only under the stated abstraction. In particular, a nondeterministic "any canonical output" permutation over-approximates Poseidon2. That is sound for safety and balance properties, but it says nothing about hash security.
  - Wide multiplication and division (u128) are known to be very slow for SAT back-ends. A Kani PR adds a "division scalability" example to the slow-proofs guide, and third-party CI reports show u128 division harnesses timing out while cvc5 can succeed (§8). So `check_hash` equivalence at full width and LWMA at N = 60 may be infeasible. They are time-boxed with a proptest fallback.
- **Tests that prove the fix.** The harness suite in §5 (W5), run weekly, with results recorded under `docs/evidence/formal/`.
- **Invariants.** §4 lists them. They are exactly the never-change items 2, 4, 7 and 13–16, restated as checkable properties.

### 3.3 P-C: where mutation testing is feasible on this machine

- **Feasible locally:**
  - `consensus`: 1.5–2.5 h at `-j2`;
  - the `difficulty`/`timestamp`/`pow` subset: under 20 min;
  - `px-core` against the `px` differential tests, using an optimized-dependency profile: 1.5–5 h at `-j2`.
- **Not feasible locally as a full run:** `tx` (7–23 h at `-j2`). It belongs on Linux CI shards, or on `--in-diff` locally.
- **Why tx is costly:**
  - every mutant rebuilds `tx` and relinks about 10 test binaries against crypto, zk, zkvm, px and Plonky3 (link-dominated on MSVC);
  - PX statement code (`tx/src/px.rs`: `public()`, `binding()`, `h_tx`) is killed today only by **proving** tests.
- **The cheap fix is a golden PX proof** (P0-10; owners 22/01/40). A pinned proof that must verify, and must fail when any statement word changes, turns a 7–15 min proving oracle into a sub-second verification oracle. **This is the single largest speed-up available for mutation testing of PX consensus code.** It is also already a P0 item for other reasons.

### 3.4 P-D: tool choice under the pure-Rust and no-rewrite constraints

- **Kani:**
  - Harnesses are ordinary Rust under `cfg(kani)`. The `kani` crate is injected by `cargo kani`, so the manifest gains no dependency.
  - Harnesses can live in a separate crate, so the verified crates see no source change.
  - The verifier binary (CBMC, C/C++) is an **off-tree tool**, like the approved C++ RandomX oracle (decision for agent 05). It never enters a node or wallet binary.
  - Platforms: Linux x86-64 and macOS only. So it is CI-only here unless the owner installs a WSL distribution.
  - **Chosen.**
- **Prusti:**
  - It requires `prusti_contracts` annotations in the verified source and a JVM plus Viper plus Z3 toolchain.
  - It is a prototype, and its pinned old nightly lags the edition features we use.
  - Annotating `px-core` would change the crate that defines the kernel ELF.
  - **Rejected now.**
- **Creusot:**
  - Deductive verification over Why3, installed through opam and OCaml (no native Windows path).
  - Contracts and ghost code are written in the source, using the `creusot-contracts` crate.
  - Proven at scale on algorithmic cores (CreuSAT, key algorithms of a Kafka broker). It would suit a future full functional proof of `kernel::transfer` against a written spec.
  - **P3 research track.** It is not proposed before the freeze.
- **Verus:** code must be written inside `verus!` with `vstd`. Verifying a Verus copy does not verify the shipped crate, which is effectively a rewrite and violates "no rewrites". **Rejected.**
- **hax (with Lean, F\* or Rocq):**
  - It extracts ordinary Rust (with a restricted `&mut` subset). This is how libcrux's ML-KEM is verified (panic freedom, functional correctness against a spec, secret-independence at source level).
  - Linux and macOS only (WSL on Windows). Proofs need F\* or Lean expertise.
  - It is the best long-term option for a px-core functional-correctness proof and for replacing the unaudited `ml-kem` crate with a verified pure-Rust implementation (a point for 44).
  - **P3.**
- **stateright** (a pure-Rust explicit-state model checker) is right for fork choice (R13 T-5). It is owned by 02 and 41 (02 W-1: reference model plus proptest, P0), so 42 supplies invariants only (§4, C8).
- **Miri** is installed locally. BlackSilk crates are `forbid(unsafe_code)`, so Miri adds little there. It is relevant only to `third_party` Plonky3 patches (24 and 44's domain).
- **Blockchain prior art:**
  - The Ethereum phase-0 spec in Dafny (ConsenSys, eth2.0-dafny; more than 200 functions; archived April 2026) verifies a *model* of the spec, not the clients.
  - Cardano's Agda ledger spec produces Haskell for **conformance testing** of the implementation.
  - rust-bitcoin: daily Kani plus weekly cargo-mutants on its consensus-encoding crates. This is the closest match to BlackSilk's size and constraints.
  - Lesson: executable conformance vectors plus bounded checks on the real code pay off earliest. Full deductive proofs of a model come later, and prove the model, not the node.

---

## 4. Invariants to state formally

"Tool" says how each is checked: **K** = Kani harness in `tools/formal` (bounded, Linux CI); **P** = property test (proptest or seeded, owner 41 or the domain owner); **V** = pinned vector; **M** = model (stateright or reference model, owner 02/41). Each Kani harness also has a `#[test]` wrapper over exhaustive small or seeded random inputs, so the property also runs on Windows.

### 4.1 px-core (kernel ELF source; Kani with a toy or nondeterministic permutation)

| Id | Invariant | Tool | Expected Kani cost |
|---|---|---|---|
| X1 | `add(a,b)` for all `a,b < P`: the result is `< P` and equals `(a+b) mod P` | K (exhaustive over 2^62) | seconds |
| X2 | `limbs(v)`: each limb `< 2^16` (canonical), and `Σ limbs[i]·2^{16i} = v` (injective value encoding inside `cm`) | K | seconds |
| X3 | `hash(d, parts)` ≡ `Sponge::new(d, len)` + `absorb_all` + `finish`, for every split of every length 0..=24, and neither calls `invalid_input` on canonical input with a matching length | K (cheap deterministic toy permutation) | minutes |
| X4 | `Call::io_hash` never calls `invalid_input` (`IO_LEN` equals the absorbed count) for every approve/spec shape (2^4) and all canonical digests | K | seconds–minutes |
| X5 | `kernel::transfer` never panics and never overflows, for **any** word stream (nondeterministic `Source`, nondeterministic canonical permutation outputs) | K (stub `node`/`permute`) | minutes–1 h, time-boxed |
| X6 | Balance: `Ok(pub)` ⇒ `Σ value_i + bridge_in = Σ value'_j + bridge_out` over the witness fields (u128, no overflow) | K (typed `Witness`, `write` then `transfer`) | as X5 |
| X7 | `Ok` ⇒ `nf_0 ≠ nf_1`; every dummy input has value 0 and contract 0; `n_fn ≤ MAX_FN`; every called contract `≠ 0` | K | as X5 |
| X8 | PX-F5: `Ok` ⇒ every output with `contract ≠ 0` has `owner = 0` | K | as X5 |
| X9 | Authorization: `Ok` ⇒ every contract input is approved by some function of the same contract, and no function approves a dummy, a user record or a foreign record. Every contract output is specified by exactly one function of its contract. After F-20-1 this becomes "approved by **exactly one** function" | K | as X5 |
| X10 | Framing: for a well-formed `Witness w`, `transfer` reads exactly `len(write(w))` words (no ambiguity at the end of the witness) | K | minutes |
| X11 | `Public::write` emits `46 + 16·n_fn ≤ MAX_PUBLIC_WORDS` words | K | seconds |
| X12 | The same verdict natively and in the pinned guest (the differential) | P/V (20's W2, 41) | n/a (the guest interpreter is too big for Kani) |

### 4.2 consensus

| Id | Invariant | Tool |
|---|---|---|
| C1 | `check_hash(h,d) ⇔ int_le(h)·d < 2^256`, and `d = 0 ⇒ false` | V (exists) + P against a u128-limb reference. K only with a restricted width (the symbolic top limb and `d`): full-width multiplier equivalence is likely intractable |
| C2 | `seed_height(h, E, L)` for all `h` and all power-of-two `E`: `≤ h`; `≡ 0 mod E`; `h > E+L ⇒ L < h − s ≤ E+L`; non-decreasing in `h`; changes only at `h ≡ L+1 (mod E)` | K (full width) |
| C3 | LWMA: for any u64 timestamps and cumulative work built from per-block `D ≥ 1`, no panic and no overflow, and the result is in `[1, u64::MAX]`. Increase bound: `next ≤ ⌊S·T(n+1)/(2·max(1, n²T/20))⌋`. Monotone: longer solve times never raise the result | K at N ≤ 8 (time-boxed at N = 60, solver `cvc5`); P for monotonicity (relational) |
| C4 | `median(v)` for `1 ≤ len ≤ 11`: the result is an element of `v`, with at most `⌊(len−1)/2⌋` elements below it and at least `⌊(len−1)/2⌋ + 1` at or below it | K |
| C5 | Header codec: `from_bytes(to_bytes(h)) = h`; `from_bytes(b) = Some(h) ⇒ to_bytes(h) = b` for all 100-byte `b`; `None` for every other length | K |
| C6 | `Schedule`: a table that validates has strictly increasing activations starting at 0, `epoch_at` is total, and `activation_in` is half-open | K (small tables) |
| C7 | `is_permanent`: exactly `{Duplicate, UnknownParent, TimestampTooFarInFuture, UnknownUpgrade}` are non-permanent | V (table test) |
| C8 | Fork choice: verdicts do not depend on arrival order; the tip is a max-work body-complete leaf with the first-seen tie; `main` is the tip's ancestor path; a reorg reconstructs both chains; `mark_invalid(x)` ≡ a fresh chain without x's subtree | M/P (owner 02 W-1, 41) |

### 4.3 tx

| Id | Invariant | Tool |
|---|---|---|
| T1 | Varint: for all `v`, `decode(encode(v)) = v`; for all byte strings of length ≤ 11, `Ok(v)` ⇒ the consumed bytes equal `encode(v)` (unique encoding); `decode` never reaches the `unreachable!` (`codec.rs:137`) | K, tried first on the `tx` dependency closure; if Kani cannot compile the closure (Plonky3, dalek), use exhaustive P over all ≤ 3-byte strings plus random longer ones |
| T2 | Transaction codec: `decode(b) = Ok(t) ⇒ encode(t) = b`, and `validate` Ok ⇒ round trip (11 I4) | P/fuzz (41, 11) |
| T3 | `is_stateless` / `is_stateless_at` classification table | V (11) |
| T4 | `min_fee`, `weight` and `standard_fee` never overflow over all legal shapes (`n_in ≤ 64`, `n_out ≤ 16`) | P, exhaustive (64 × 15 shapes) |
| T5 | Block B3 exact equality, pool containment (`px_pool ≥ 0` in block order), B6 at the exact boundaries (weight = max accepted, max + 1 rejected; the same for the PX and deploy byte budgets) | V (10, 11, 01) |

---

## 4b. New findings

| Id | Severity | Status | Location | Scenario | Confidence |
|---|---|---|---|---|---|
| **F42-1** | Medium | Not implemented | repo-wide (no config; T-12) | Consensus test adequacy is unmeasured. The "15/15 mutants" figure is a hand-picked set (S2) and must not be quoted as a mutation score | High |
| **F42-2** | Medium (consensus test gap) | Not implemented | `consensus/src/difficulty.rs:28` (and `:31`) | **Predicted survivor:** `ts[i] > prev` → `>=`. Worked example: ts `[0,100,100,220]` with D = 1000 each. The original gives 1,568. The mutant gives 1,565: the weighted sum is 459 against 460, because the equal timestamp contributes solve time 1 instead of 0 and shifts the next one. No vector has an equal timestamp followed by a later one (`lwma_window_fill_phase` covers equal timestamps only at n = 1; `lwma_increase_floor` is floor-dominated). MTP allows equal timestamps (strictly after the *median* only), so a miner can produce this, and a refactor that changes the rule forks the chain at the first such block. Fix: one golden vector (owner 03/01) | Medium (source-read + hand arithmetic; to confirm by run A′) |
| **F42-3** | Medium (consensus test gap) | Not implemented | `tx/src/validate.rs:976-982` (PX budget), `:970` (weight), `:991` (deploy) | No test in the workspace produces `PxBytesExceeded`. A mutant `px_bytes > MAX` → `==` (effectively deleting the 8 MiB PX cap) is predicted to survive. The weight and deploy budgets are tested only away from the boundary, so `>` → `>=` survives, and a block of exactly maximum size would then be rejected by a mutated build (a chain split). This confirms 01's F-02 with a stronger instance (rule deletion, not only the boundary). Fix: exact-boundary vectors, built on 01's "structure path" without proving (owner 10/11) | High (grep); outcome predicted |
| **F42-4** | Low (planning) | Not implemented | `px-core` (4 unit tests) versus the `px` tests | cargo-mutants' default runs only the tests of the mutated package. `cargo mutants -p blacksilk-px-core` would therefore report almost every kernel mutant as missed (false alarms), while running all `px` tests (`unified` and `proof` prove) costs minutes per mutant. The run must route to `px` tests `kernel`, `fuzz` and `state` (and 20's `kernel_spec`), with an optimized-dependency profile | High |
| **F42-5** | Low (px-core consensus test gap) | Not implemented | `px-core/src/lib.rs:17` (`add`) | **Predicted survivor:** `s >= P` → `s > P`. It differs only when `a + b == P` exactly (about 2^-31 per random addition), which no test constructs. The effect is a non-canonical sponge word: `HostPerm` asserts (`px/src/perm.rs:27`), or the native and guest paths disagree in rare cases. Fix: a unit test `add(P−1, 1) == 0` in px tests (px-core source untouched), plus Kani X1 | Medium |
| **F42-6** | Low | Not implemented | `consensus/src/chain.rs:96` (`Reorg::is_extension`) | Only asserted `true` (`randomx_end_to_end.rs:55`), and there is no production caller (grep over chain, p2p, node and miner). The mutant `→ true` survives. Either test the false case or remove the dead API (01/46) | High |
| **F42-7** | Low (test architecture) | Not implemented | `tx/tests/px_consensus.rs`; P0-10 | Mutants in PX statement code (`tx/src/px.rs`) can be killed today only by proving tests (431 s in release; several times slower under the default test profile). Without the golden PX proof, a tx mutation census is about 7–23 h locally. The golden proof (P0-10) is a prerequisite for W4 | Medium (estimate) |
| **F42-8** | Accepted limitation | Accepted limitation | tooling | Kani, hax and Creusot do not run natively on Windows. WSL2 has no distribution here. Formal runs are Linux-CI-only unless the owner installs Ubuntu in WSL | High |
| **F42-9** | Informational | — | claims | Any Kani result must be worded as bounded model checking under a stated abstraction (the hash as a nondeterministic canonical function, the bounds). Never "formally verified" (brief §3 claims policy) | — |

---

## 5. Implementation plan for phase 2

### 5.1 Principles

- **No source changes to verified crates for tooling.** No `#[mutants::skip]`: it needs the `mutants` crate as a normal dependency, and px-core must stay dependency-free. No `cfg(kani)` modules inside `px-core`: any px-core edit forces a `reproduce.sh` check of the kernel id. All exclusions go in config, and all harnesses go in a separate crate.
- **Every exclusion regex carries a one-line reason** in `.cargo/mutants.toml`, and 50 (red-team) reviews the consensus-path exclusions.
- **Timing of the census.** Full censuses run only on **settled code**: after each implementation wave, with the final census on the freeze-candidate tag. During waves only `--in-diff` runs.
- **Never use `--in-place` locally.** Other agents share the tree. Copy mode is the default.
- **Local runs use `-j2`,** inside the exclusive machine windows (as decided for agent 06's benchmarks), or overnight. `-j3` is used only if nothing else runs.

### 5.2 Run specifications and expected run times (16 GB / 8 cores, Windows, MSVC)

Mutant counts are estimated from the functions and operators in non-test code (1 fn ≈ 2 mutants, 1 binary operator ≈ 1.5). **The first step of every run is `cargo mutants --list | wc -l`, which lists without building, followed by a baseline timing. These replace the estimates below, and the measured figures go into the evidence file.**

| Run | Mutated files | Tests per mutant | Mutants (est.) | Build + test per mutant (est.) | Serial | `-j2` | Peak RAM `-j2` |
|---|---|---|---|---|---|---|---|
| **A′** LWMA gate | `consensus/src/{difficulty,timestamp,pow}.rs` | consensus `--lib --test golden` (+ `randomx_end_to_end` for `pow.rs`) | 60–80 | 10–20 s | 15–25 min | **≤ 15 min** | ~3 GB |
| **A** consensus | `consensus/src/**` | the whole consensus package | 250–320 | 25–40 s, plus 10–20 timeouts × ~75 s | 2.5–4 h | **1.5–2.5 h** | 4–6 GB |
| **B** px-core | `px-core/src/**` | `--test-package blacksilk-px`: `--test kernel --test fuzz --test state` (+ `kernel_spec` after 20 W2) | 180–240 | 60–150 s (guest interpreter; deps optimized) | 3–10 h | **1.5–5 h** | 5–7 GB |
| **B′** px-core survivors | survivors of B | adds `--test unified` (proving) | ≤ 20 | 5–15 min | ≤ 5 h | ≤ 2.5 h | 8+ GB (proving is 3.8 GB) → `-j1` |
| **C** tx rules | `tx/src/{validate,px,codec,types,params,state}.rs` | tx `--lib` + every test target **except** `px_consensus` | 450–600 | 2–5 min (link-dominated) | 15–45 h | **7–23 h** (**CI shards instead**) | 6–8 GB |
| **C′** tx PX survivors | survivors in `px.rs` | adds the golden-proof test (after P0-10) or `px_consensus` | ≤ 40 | 1 s–15 min | — | — | — |
| **D1** fork choice (02) | `chain/src/manager.rs`, restricted with `--re 'mark_complete\|recompute_target\|keeps_body\|invalidate'` | chain `--test fork_choice --test manager` (+ 02's W-1 model) | 40–70 | 1–2 min | 1–2 h | ≤ 1 h | 4 GB |
| **D2** RandomX FPU (05) | `randomx/src/fpu.rs` (+ `vm.rs` decode) | randomx lib tests + 05's C2/C3/C5 corpus tests | 120–270 | 1–1.5 min (opt-3 rebuild) | 2–7 h | 1–3.5 h | 4 GB |
| **D3** crypto (15/16) | `crypto/src/{clsag,bulletproofs_plus}.rs` | crypto lib + malleability + the new vector files | 250–350 | 1–2 min | 4–12 h | 2–6 h | 4 GB |

**GitHub Linux runners** (ubuntu-latest, 4 vCPU/16 GB for public repositories, 6 h per job limit): run C as 16 shards (`--shard k/16`, slice sharding keeps incremental builds warm). The expected time is 1–3 h per shard. A, B and D run as 4–8 shards each.

### 5.3 Ordered work items

**W1. Mutation-testing configuration and runner scripts.** P0, S.
- **Files (new, owner 42):**
  - `.cargo/mutants.toml`;
  - `tools/mutants/README.md`;
  - `tools/mutants/run.ps1` and `tools/mutants/run.sh` (runs A′, A, B, C and D as named presets: `--list` count, baseline, run, then copy `outcomes.json` and `missed.txt` into evidence);
  - `docs/evidence/mutants/README.md` (method, triage rules).
- **Shared:** root `Cargo.toml`, adding `[profile.mutants]` (owner **43**, content from 42), and `.gitignore` (`mutants.out*/`, owner 43).
- **Consensus impact:** nothing externally visible. **Identity impact:** none (the release profile is untouched).
- **Draft config:**
  - `profile = "mutants"`;
  - `timeout_multiplier = 3.0`;
  - `minimum_test_timeout = 60`;
  - `cap_lints = true` (a mutated build must not fail on a `-D warnings` RUSTFLAGS);
  - `gitignore = true`, `copy_vcs = false`;
  - `exclude_re`, each entry with a reason:
    - `impl (Debug|Display) for`, `fmt` (formatting only);
    - `hex_id` (the log string);
    - `impl Default for` (behaviour-free constructors; the constructor itself remains mutated).
  - No `test_package`: it is per-run, in the scripts.
- **Draft profile:**
  - `[profile.mutants] inherits = "test"`, `debug = "none"`;
  - `[profile.mutants.package."*"] opt-level = 3` (every external dependency, Plonky3 included);
  - opt-level 3 for the workspace members `blacksilk-zk`, `blacksilk-zkvm`, `blacksilk-px`, `blacksilk-crypto` and `blacksilk-randomx`;
  - overflow checks and debug assertions stay **on** (the test profile), so an overflow-introducing mutant is caught.
- **Tests:** a smoke run of A′.
- **Docs:** the evidence README.

**W2. Census A′, then A (consensus).** P0 (the final census before the freeze tag); A′ now, as calibration.
- **Files:** evidence only (`docs/evidence/mutants/<date>-consensus.md`).
- **Killing tests:** added by the domain owners in their files:
  - 01/03: `consensus/tests/golden.rs`, the F42-2 equal-timestamp vector;
  - 01: F42-6.
- A new file, `consensus/tests/mutation_regressions.rs` (owner 42), holds only kills that fit nowhere else.
- **Consensus:** none. **Identity:** none.
- **Acceptance:** zero missed mutants without a written equivalence note. Known equivalent: `weighted.max(...).max(1)`, per R13.
- **Sequencing:** after 03's W2 (the LWMA clamp change), 04's items and 01's F-05 reorder. The final run is on the freeze candidate.

**W3. Census B (px-core), agent 20's W3.** P0 for the freeze evidence (the kernel is consensus-pinned).
- **Files:** evidence plus `px/tests/mutation_regressions.rs` (new, owner 42), for example `add(P−1, 1) == 0` for F42-5.
- **Oracle:** 20's `kernel_spec` (W2).
- **Acceptance:** no survivor in `transfer`, `io_hash`, `Record::commit`, `nullifier`, `output_rho` or `hash`/`Sponge`/`node`/`add`/`limbs`, except documented equivalent mutants.
- **Sequencing:** after the single v3 kernel rebuild (F-20-1, ABI word, validity window), because running earlier wastes triage. A calibration run of about 1 h, on `record.rs` and `call.rs` only, can happen now.
- **Identity:** none. px-core's source is never edited by 42.

**W4. Census C (tx).** P1; P0 only for the block-rule section, if the coordinator agrees with 01 item 11.
- **Prerequisites:**
  - the golden PX proof (P0-10) and 11's I1 corpus;
  - D8 (the C4 removal), R12-2 (the weight rule) and F10-2 (the reorder) merged, since each rewrites parts of `validate.rs`.
- **Files:** evidence plus `tx/tests/mutation_regressions.rs` (new, owner 42). F42-3's boundary vectors belong to 10/11 (`tx/tests/rule_vectors.rs` from 11's I1).
- **Where it runs:** CI shards (W6); local runs only with `--in-diff`.

**W5. Bounded model-checking harnesses.** P1, M.
- **Files (new, owner 42):**
  - `tools/formal/Cargo.toml`, with its own `[workspace]` so the root manifest is untouched, path dependencies on `blacksilk-px-core`, `blacksilk-consensus` and (attempted) `blacksilk-tx`, and **no crates.io dependencies**;
  - `tools/formal/src/{props_px.rs, props_consensus.rs, props_tx.rs}`, where each property is a plain `pub fn check_*(inputs)`;
  - `#[cfg(kani)]` harnesses using `kani::any`, `#[kani::unwind]`, `#[kani::stub]` for `node`/`permute`, and `#[kani::solver(cvc5)]` for the u128 division harnesses;
  - `#[cfg(test)]` wrappers (exhaustive where small, otherwise a seeded ChaCha from the existing dev-dependency set; proptest only if 41 adopts it there);
  - a `tools/formal/Cargo.lock` copied from the root lock.
- **Harness order:** X1, X2, C2, C5, T1 (varint), X11, X4, X3, C4, C6; then X10, X5–X9 (time-boxed at 2 engineer-days); then C3 at N ≤ 8 and C1 at restricted width (time-boxed at 1 day each, with the proptest fallback documented).
- **Expected Kani wall time** for the whole suite on ubuntu-latest: 20–90 min [estimate]. X5–X9 are the unknowns.
- **Consensus:** none. **Identity:** none.
- **Tests:** `cargo test --manifest-path tools/formal/Cargo.toml` runs on Windows in CI tier 0.
- **Docs:** `docs/evidence/formal/README.md`, with each property, its bound and its abstraction (F42-9 wording).

**W6. CI jobs.** P1, S.
- **Owner:** 43, in a new workflow `mutants-formal.yml`. 42 specifies the jobs.
- **(a) Weekly and manual** `cargo mutants` with presets A, B and C sharded (`--shard k/n`, `--baseline=skip` after a separate baseline job, `-j1` per runner). Upload `mutants.out`. Fail when `missed.txt` holds entries not in the reviewed equivalence list.
- **(b) On push to `rebuild/core`** touching `consensus/`, `px-core/` or `tx/src/{validate,px,codec,types,params,state}.rs`: `git diff <before>..<after> > diff`, then `cargo mutants --in-diff diff --test-package …` with a 90 min cap. Missed mutants produce annotations (cargo-mutants ≥ 25.3 emits them in GitHub Actions) and fail the job.
- **(c) Weekly Kani:** a pinned `kani-verifier = 0.68.0` via `cargo install --locked`, then `cargo kani setup` and `cargo kani --manifest-path tools/formal/Cargo.toml`. Or the pinned-SHA `model-checking/kani-github-action`, as rust-bitcoin does. The results go to SARIF or JSON as an artifact.
- **Supply chain (44):** record cargo-mutants and Kani/CBMC as **test-only, off-tree tools**, never linked into node or wallet binaries. This follows the precedent of the approved C++ RandomX oracle.

**W7. Extended runs.** P2.
- D1 (for 02, after W-1);
- D2 (for 05, after C2/C3/C5; gate C1–C3 green first);
- D3 (for 15 W6 and 16, after their vector files);
- the mempool (for 12, after W6's stateful test).
- Evidence only; killing tests go to the domain owners.

**W8. Documentation.** P2, S.
- `docs/evidence/mutants/*` and `docs/evidence/formal/*`;
- 47 updates the testing section of AUDIT.md and the review register (T-12 status, T-3's stale "survived" note, "15/15" reworded as a hand-picked set).

### 5.4 Benchmarks

The runs themselves are the benchmarks: record `--list` counts, the baseline build and test times, and the per-outcome counts (caught, missed, timeout, unviable) and wall time. They go into the evidence files, and 45 receives the build-time figures.

---

## 6. Dependencies and conflicts

- **01** (consensus-core): owns `consensus/tests/golden.rs` and the vector files, so F42-2 and F42-6 kills land there. Item 11 (mutants on `validate.rs` 880–1120) is W4.
- **02** (fork choice): W-1 is the killing oracle for D1. Invariant C8 is theirs.
- **03** (LWMA): W2 changes `difficulty.rs`, so run A waits for it. Their harness supplies C3's proptest fallback.
- **05** (RandomX): D2 waits for C1–C3.
- **10/11** (validation): F42-3 vectors; the I1 corpus; the ownership split of `validate.rs`. W4 waits for D8, R12-2 and F10-2.
- **12:** the mempool is a later D-run.
- **15/16:** D3 after their vectors.
- **20** (px-kernel): W2 `kernel_spec` is B's oracle, and B runs after the single kernel rebuild. 42 never edits `px-core`.
- **22/40/01:** the golden PX proof (P0-10) is a hard prerequisite for an affordable W4 (F42-7).
- **41** (fuzz/property): proptest adoption. X12, T2 and C8 are theirs. The property functions in `tools/formal` can be shared.
- **43** (CI): owns the root `Cargo.toml` profile, `.gitignore` and the workflows (W1, W6).
- **44** (supply chain): the tool exemption records for Kani/CBMC and cargo-mutants. hax/libcrux as a future verified ML-KEM (P3 note).
- **46:** F42-6 (dead API). A future consensus-core crate would make Kani on `tx` codecs cheap (a smaller dependency closure).
- **50** (red-team): reviews the consensus-path exclusion list and equivalence notes.

---

## 7. Open questions for the coordinator

1. **Freeze gate.** Should "zero unexplained missed mutants in `consensus` and `px-core`" be a P0 freeze gate (my recommendation, affordable at about 2 h and about 5 h), and the tx census a P1 gate that is P0 for the block-rule section?
2. **Machine windows.** Can runs A and B use the exclusive machine windows after implementation wave 1? Or should all census runs go to GitHub shards, keeping only A′ and `--in-diff` local?
3. **WSL.** Will the owner install an Ubuntu distribution in WSL2 so Kani can run locally? Otherwise Kani is CI-only.
4. **Root `Cargo.toml`.** Is `[profile.mutants]` acceptable (43 to own it)? It changes no release artifact.
5. **Off-tree tools.** Please confirm that cargo-mutants (pure Rust) and Kani (CBMC, C/C++) are acceptable as off-tree verification tools under the same policy as the C++ RandomX oracle.
6. **Golden PX proof.** Can P0-10's golden PX proof be scheduled before W4? It removes most of the tx census cost.

---

## 8. Sources

**cargo-mutants**
- cargo-mutants book: https://mutants.rs/ ; https://mutants.rs/timeouts.html ; https://mutants.rs/parallelism.html ; https://mutants.rs/workspaces.html ; https://mutants.rs/in-diff.html ; https://mutants.rs/mutants.html ; https://mutants.rs/attrs.html
- Book sources: https://raw.githubusercontent.com/sourcefrog/cargo-mutants/main/book/src/SUMMARY.md, and the pages `config-file.md`, `performance.md`, `limitations.md`, `installation.md`, `shards.md`, `cargo-args.md`, `nextest.md` and `iterate.md` under the same path.
- cargo-mutants config keys: https://raw.githubusercontent.com/sourcefrog/cargo-mutants/main/src/config.rs
- cargo-mutants releases (27.1.0, 2026-06-02; 26.0.0 deterministic order and sharding; 25.3.0 GitHub annotations): https://github.com/sourcefrog/cargo-mutants/releases ; https://crates.io/api/v1/crates/cargo-mutants
- cargo-mutants CI matrix (macOS, Ubuntu, Windows): https://raw.githubusercontent.com/sourcefrog/cargo-mutants/main/.github/workflows/tests.yml

**rust-bitcoin (prior art)**
- Workflows: https://api.github.com/repos/rust-bitcoin/rust-bitcoin/contents/.github/workflows ; https://raw.githubusercontent.com/rust-bitcoin/rust-bitcoin/master/.github/workflows/cron-weekly-cargo-mutants.yml ; https://raw.githubusercontent.com/rust-bitcoin/rust-bitcoin/master/.github/workflows/cron-daily-kani.yml
- Mutants config: https://raw.githubusercontent.com/rust-bitcoin/rust-bitcoin/master/.cargo/mutants.toml

**Kani**
- Kani install guide (platforms): https://model-checking.github.io/kani/install-guide.html
- Kani automatic checks: https://model-checking.github.io/kani/tutorial-kinds-of-failure.html
- Kani releases (0.68.0, 2026-09-16): https://github.com/model-checking/kani/releases ; https://crates.io/api/v1/crates/kani-verifier
- R. Delmas et al., "Kani: A Model Checker for Rust", arXiv:2607.01504 (ASE 2026 Industry Showcase): https://arxiv.org/abs/2607.01504
- Kani division-scalability guidance, PR #4781: https://github.com/model-checking/kani/pull/4781
- Third-party report on u128 and i128 solver cost (z3 against cvc5): https://github.com/pina-rs/pinapod/pull/26
- OtterSec, "Solana Formal Verification: A Case Study" (2023): https://osec.io/blog/2023-01-26-formally-verifying-solana-programs/

**Other verifiers**
- Prusti: https://github.com/viperproject/prusti-dev ; https://github.com/prusti/prusti ; https://viperproject.github.io/prusti-dev/user-guide/
- Creusot (v0.13.0, 2026-07-30): https://github.com/creusot-rs/creusot ; https://github.com/creusot-rs/creusot/releases
- Verus (platforms; `verus!` subset): https://github.com/verus-lang/verus ; https://raw.githubusercontent.com/verus-lang/verus/main/INSTALL.md ; https://github.com/verus-lang/verus/releases
- hax (Linux and macOS; WSL on Windows): https://github.com/cryspen/hax
- libcrux (hax-verified ML-KEM): https://github.com/cryspen/libcrux

**Formal verification in blockchain projects**
- ConsenSys eth2.0-dafny (archived 2026-04-14): https://github.com/ConsenSys/eth2.0-dafny
- Cardano formal ledger specifications (Agda, conformance testing): https://github.com/IntersectMBO/formal-ledger-specifications

**Internal inputs**
- `docs/reviews/full-review-2026-09-27.md` and `full-review-2026-09-27/R13-testing-supplychain.md` (T-1, T-3, T-4, T-5, T-12);
- commit `f6c98c3`;
- dossiers 01, 02, 03, 05, 11, 15, 16 and 20.
