# 08 randomx-determinism: dossier (phase 2, phase 1: research and briefing)

**Agent:** 08 randomx-determinism. This is internal engineering work, not an audit.
**Commit:** `9e422d8` (branch `rebuild/core`). **Date:** 2026-09-27.
**Mode:** read-only. I ran no builds and no tests. Every "tested" tag below names a test
that exists in the tree; I did not run it myself.

Evidence tags: **[math]** mathematically established; **[test: name]**; **[src]**
source-read; **[assumed]**; **[unknown]**.

---

## 1. Scope and what I read

**Code in scope (all read in full):**
- `randomx/src/fpu.rs` (266 lines, 6 unit tests), `randomx/src/vm.rs` (882),
  `randomx/src/lib.rs` (296, which holds the target guard and the vector tests),
  `randomx/src/config.rs`, `hash.rs`, `aes_gen.rs`, `argon2d.rs`, `dataset.rs`.
- `randomx/src/superscalar.rs`: read in part (lines 1–160, plus a grep of every cast and
  byte conversion). It is integer-only.
- `randomx/Cargo.toml`, `randomx/README.md`, `randomx/examples/bench.rs`.
- The target guards: `randomx/src/lib.rs:22-25` (x86 without SSE2) and
  `consensus/src/lib.rs:17-20` (non-64-bit).
- `consensus/src/pow.rs`, `consensus/tests/randomx_end_to_end.rs`,
  `node/src/fingerprint.rs:175-212` (the RandomX manifest entries).
- `.github/workflows/ci.yml` (all jobs), `.github/scripts/annotate-tests.sh`,
  `deploy/docker/Dockerfile`, the workspace `Cargo.toml` (profiles). There is no
  `rust-toolchain.toml` and no `.cargo/config.toml`.
- **Dependency source, as locked:**
  - `aes-0.8.4`: `hazmat.rs` (backend selection), `lib.rs` (cfg flags), `soft.rs`
    (fixslice32/64 selection), the fixslice64 bitslice loaders, `tests/hazmat.rs`;
  - `blake2-0.10.6`: endianness handling (`as_bytes.rs`, `macros.rs`);
  - `cpufeatures-0.2.17`: aarch64 detection.

**Docs and reports read:**
- `docs/reviews/full-review-2026-09-27.md`: §3.2, the register rows for R9 and T-8, and
  the P0/P1/P2 lists.
- `docs/reviews/autonomous-session-2026-09-27.md`: all of it.
- `full-review-2026-09-27/R9-randomx.md`: all of it.
- `R13-testing-supplychain.md` T-8; SX2 §R9 and T-8; the SX1 rows on RandomX;
  `R15-testnet-decentralization.md` C3; `R1-consensus.md` (R1-C6, the 64-bit item).
- `docs/consensus.md` §9–10; `docs/reviews/assumptions.md` K5; the RandomX rows of
  `docs/testnet.md`.
- The roster: my entry (08) and its neighbours 05, 06, 07, 09, 43, 44, 45, 46 and 47.
- The already-written dossier of 07 exists in `C:/bszkeval/p2/research/`. I did not
  rely on it.

---

## 2. Current state

### 2.1 What exists and is well designed

| Claim | Evidence |
|---|---|
| No hardware rounding-mode control. Directed rounding is emulated with RN operations plus a one-ulp correction, and the error sign comes from TwoSum (add), Dekker TwoProduct on operands rescaled to [1,2) (mul), the exact remainder (div) and the exact residual (sqrt). There is no MXCSR/FPCR state, so no per-thread FP state can leak into hashes. | [src] `fpu.rs`; [math] see §3.1 |
| The error-free transforms are sound for the operands RandomX produces. TwoSum is exact whenever `s` is finite (Knuth; Boldo–Graillat–Muller 2017: "almost immune to overflow"). The division remainder and the sqrt residual are exactly representable (Boldo–Daumas 2003). Rescaling by powers of two preserves the rounding decision when the unscaled result is normal. | [math] with citations; [test: `fpu::tests::*`, 6 tests] |
| Rust guarantees what the design relies on: IEEE 754 roundTiesToEven for `+ - * /`; `sqrt` is correctly rounded ("guaranteed to be the rounded infinite-precision result"); no FMA contraction ("strict IEEE 754 guarantees preclude … turning a*b + c into FMA"); no FTZ; moves, `to_bits` and `from_bits` preserve NaN bits. | [src] RFC 3514; `f64` std docs |
| Every byte↔word conversion in the crate is explicit little-endian: argon2d, blake2 generator, VM loads and stores, `register_file`, program entropy. AES works on bytes. The fixslice64 loader in `aes` is byte-wise, and `blake2` converts words with `to_le`/`from_le`. | [src] (R9 said the same; I re-checked the dependencies too) |
| x87 targets are refused (`randomx/src/lib.rs:24-25`), and so are all non-64-bit targets for the consensus crate (`consensus/src/lib.rs:19-20`, commit `8097f66`). Every binary depends on `blacksilk-consensus`, so the node, miner and wallet are 64-bit only. | [src] |
| The official vectors pass on x86_64 Windows (the `guests` job, Windows leg, runs `cargo test -p blacksilk-randomx`) and on x86_64 Linux (the `test` and `overflow` jobs). Full mode matches light mode on Linux (`randomx-full`, weekly and on every push). | [test: `hash_1a`–`hash_1e`, `cache_initialization`, `superscalar_generator`, `dataset_items`, `aes_generator_1r`, `reciprocals`, `full_mode_matches_light_mode`]; CI runs 78 and 79 green per the session report |
| `blake2` has no SIMD feature enabled. `aes` is `=0.8.4` with `hazmat` only. | [src] `randomx/Cargo.toml` |

### 2.2 What the tests actually prove, and what they do not

- **They prove** bit-identical results with the reference on 5 end-to-end inputs over 2
  keys, and on the component vectors, **on x86_64 with the AES-NI backend** (every
  GitHub x86 runner has AES-NI) [test].
- **They do not prove:**
  - **any non-x86 target.** There is no aarch64, big-endian or RISC-V run [src ci.yml].
  - **any AES backend other than AES-NI.** `aes 0.8.4` picks its backend *at runtime*
    through `cpufeatures` on x86/x86_64, and at build time elsewhere:
    - AES-NI (x86 when detected);
    - ARMv8 (only with `--cfg aes_armv8`);
    - fixslice64 (64-bit software);
    - fixslice32 (32-bit);
    - "compact" variants of both (`--cfg aes_compact`).

    `aes_force_soft` forces software. CI exercises only AES-NI [src `aes-0.8.4/src/hazmat.rs:16-44`, `soft.rs:11-13`].
  - **any code generation other than the default `x86-64` baseline.** No job uses
    `-C target-cpu`/`target-feature`, although miners commonly build with
    `target-cpu=native`.
  - **the rare FP paths at scale.** The fpu unit tests are hand-picked [test: 6 tests].
    The vectors reach the emulation only indirectly (R9-R6 and T-8, known).
- **The whole-chain claim** (docs/consensus.md §9) says "verified only on x86_64". That
  is accurate.

### 2.3 Answers to the roster questions

**Q1. Is determinism across x86-64 Windows/Linux, aarch64 and big-endian satisfied?**

| Target | Status | Evidence class |
|---|---|---|
| x86_64 Linux, Windows (AES-NI path) | Satisfied | tested |
| x86_64 without AES-NI (VMs that mask the flag, old CPUs): fixslice64 path | Designed to be; untested in-tree | src + upstream FIPS-197 tests of `aes` hazmat on whatever backend upstream CI ran [assumed] |
| aarch64 Linux, macOS, Windows | Designed to be; **untested** | src/math. RN arithmetic, sqrt and no-contraction are guaranteed by Rust; AES is software fixslice64 unless `aes_armv8` is set |
| Big-endian (s390x, ppc64) | The RandomX crate is designed endian-clean; **untested**. The rest of the workspace (Plonky3, zk, px-core, p2p codecs) is **unknown** for big-endian | src (randomx), unknown (workspace) |
| riscv64 | Designed to be; untested. NaN canonicalization on RISC-V is irrelevant, because no RandomX FP operation produces a NaN (§3.1) | math/src |
| 32-bit (any), x86 without SSE2 | Refused at compile time | src |

So the design satisfies determinism on every IEEE-conforming 64-bit target that Rust
supports, but the evidence exists only for x86_64 with AES-NI.

**Q2. Which targets does BlackSilk claim?**
- **Today, implicitly:** "64-bit" (the compile guard) and "x86_64 verified" (docs).
- There is **no explicit supported-target table** anywhere: README, `docs/testnet.md`,
  `docs/consensus.md`. The proposed matrix is in §5, item W1.

**Q3. How can aarch64 be tested in CI?**
- **Native hosted runners, which is better than QEMU:**
  - `ubuntu-24.04-arm` and `windows-11-arm`: 4 vCPU and 16 GB in public repositories, or
    2 vCPU and 8 GB in private ones (private availability since 2026-01-29);
  - `macos-14`/`macos-15`: M1, 3 CPU and 7 GB.
- All of them fit the ~2.3 GiB full-mode test.
- QEMU user mode (via `cross` or apt `qemu-user` plus a cross linker) is the right tool
  only for targets with no hosted runner: s390x (big-endian) and riscv64gc.

---

## 3. Problems in scope

### 3.1 The FPU emulation: is it sound on every target? (analysis; no defect found)

**Operand ranges, re-derived [math/src]:**
- **a registers:** exponent `(entropy>>59) + 1023`, so a ∈ [1, 2^32), always normal
  (`vm.rs:198-205`).
- **e registers:**
  - After `mask_e`, the exponent is `0x300 | static<<4 | dyn` ∈ [0x300, 0x3FF], so
    e ∈ [2^-255, 1).
  - FMUL (×a ≥ 1) and FDIV (÷ v < 1) only increase e. FSQRT moves e toward 1.
  - So e ≥ 2^-255 always: never subnormal, never zero. It can overflow to ±MAX or ±∞
    under directed modes (handled). ∞ only meets ×a, ÷v and √, so there is no NaN.
- **f registers:**
  - They are reloaded every iteration as i32→f64 (exact), then changed by ± a, ± memory
    int, and FSCAL.
  - **FSCAL XORs `0x80F0…`: the sign bit and the low 4 exponent bits.** It scales by
    2^±15 at most, so |f| stays around ≤ 2^48 [math].
  - **One case the docstring (`fpu.rs:10`) and R9 §3.1 omit:** FSCAL of ±0 gives an
    exponent field of 0x00F, i.e. **±2^-1008**. That is normal, but only 14 binades above
    the subnormal range. The conclusion still holds: adding ±2^-1008 to an operand ≥ 1,
    or to an integer, gives a normal result or an exact one, and the TwoSum error term
    is ±2^-1008 or 0, both normal.
- **Result:** no subnormal ever reaches `fpu.rs`, so FTZ/DAZ settings could not change a
  hash. No arithmetic NaN is ever produced, so platform NaN-propagation rules (x86 vs
  ARM vs RISC-V canonical NaN) are irrelevant [math].
- **Is this conclusion safe to build on?** It is safe for `fpu.rs` as written, because
  `add` needs no rescaling. It is a trap for performance work (06), because a scaled or
  "fast" add path that assumes |f| ≥ some bound would be wrong for the 2^-1008 case.

**Where NaN *bit patterns* do occur (new; see D-4):**
- At the end of each iteration, `f[i][lane] = f64::from_bits(f.to_bits() ^ e.to_bits())`
  (`vm.rs:682-683`).
- An f exponent near 0x41x XOR an e exponent near 0x3Ex gives 0x7FF. So **f holds
  NaN-patterned (and about half the time signaling-NaN-patterned) values often**
  [math/src].
- They are never used arithmetically: the next iteration reloads f. But the values of
  the last iteration are serialized by `register_file()` (`vm.rs:566-572`) into the Blake2
  seed of the next program and into the final hash.
- So the hash depends on **moves preserving NaN bits**. Rust guarantees this ("when a
  floating-point value is just passed around, its contents (including the bits of a NaN)
  do not change") **except on 32-bit x86, where float returns travel through x87 and
  alter NaN payloads** (RFC 3514). Those targets are already refused at compile time.
- The reference does the XOR with SIMD integer ops, so its bits are exact.

### 3.2 AES backend diversity (D-1)

**Problem:**
- The hash depends on `cipher_round`/`equiv_inv_cipher_round` giving AESENC/AESDEC
  semantics bit-exactly on every backend.
- The backend is chosen at runtime on x86 by `cpufeatures` (the CPUID `aes` bit, which
  hypervisors can mask), and at build time on aarch64 (`aes_armv8`).
- The software backends are data-independent bitsliced code (Adomnicai–Peyrin
  fixslicing, ePrint 2020/1123). Upstream tests each backend against FIPS-197 vectors
  (`aes-0.8.4/tests/hazmat.rs`: `cipher_round_fips197_vectors` and others). But
  BlackSilk's own CI never runs a non-NI backend.

**Consequence:** a backend bug, or a miscompile on one backend and target, makes every
node on that hardware compute wrong PoW hashes. It then rejects valid blocks and
isolates itself. That is not a network split, but it is a silent liveness failure for
that operator. A *miner* on such hardware would produce blocks everyone else rejects.
- Consensus-critical: yes (per node). Privacy: no.
- **Prior art:** the reference RandomX ships `randomx-tests` and a benchmark with
  `--verify`, and operators run them per machine. The RandomX v2.0.1 / v1.2.2 releases
  fixed "invalid hashes (1 out of ~268 million) on ARM/RISC-V" caused by an **ISUB_R JIT
  edge case** (immediate 0x80000000 with src = dst; PR #326). A platform-specific code
  path with a rare trigger went unnoticed until cross-platform checking caught it.

**Fix:**
- CI legs that force each backend:
  - `RUSTFLAGS="--cfg aes_force_soft"`;
  - `--cfg aes_force_soft --cfg aes_compact`;
  - on aarch64, the default (fixslice64) and `--cfg aes_armv8`.
- A **startup self-test** through the runtime-selected backend (W4).

**What could go wrong:** `RUSTFLAGS` rebuilds everything (slower CI, no cache sharing).
Use a dedicated job with `-p blacksilk-randomx` only.

**Tests:** the existing vectors plus the digest tests (W3) under each backend.

**Invariant:** AES semantics are AESENC/AESDEC exactly; the key constants in
`aes_gen.rs` never change.

### 3.3 No non-x86 evidence (D-2; known as R9-7, T-8 and P1-14, confirmed)

- **Problem:** the design argument (§3.1) is sound but untested off x86_64. The
  remaining risks are:
  - LLVM backend bugs on aarch64 in the f64 or `u128` paths (`mulh`, `smulh`, the
    superscalar `IMULH`);
  - the soft-AES path;
  - `rotate_*`;
  - `as_chunks`.
- **Solution:** native `ubuntu-24.04-arm` jobs:
  - on every push: light vectors plus the digests;
  - weekly: the full = light ignored test.
- **Trade-off:** none material. The runners are free for public repositories.

### 3.4 Big-endian and riscv64 (D-7)

- **Problem:** nothing refuses big-endian, but the workspace beyond `randomx`, `aes` and
  `blake2` has never been considered for big-endian. That includes the Plonky3 field
  crates (which use inline assembly and SIMD on some targets; `AUDIT.md:788`), px-core,
  and the p2p and tx codecs. RandomX itself is validated upstream on PPC64 big-endian
  (the tevador README's platform list).
- **Options:**
  - **(a)** Declare the node little-endian-only (`compile_error!` on
    `target_endian = "big"` next to the 64-bit guard) until a whole-workspace big-endian
    run passes. Test the `randomx` crate alone on s390x under QEMU, as cheap evidence
    that the crate is endian-clean.
  - **(b)** Try to support big-endian for everything: an XL review for no testnet
    benefit.
- **Recommendation:** (a).
- **QEMU user mode** uses softfloat emulation of the guest FPU. A QEMU bug would more
  likely cause a false failure than a false pass [assumed].
- **riscv64gc:** the same approach, as evidence only; unsupported for nodes until
  someone runs one.

### 3.5 Runtime environment faults (D-3)

**Problem:** the emulation assumes the hardware is in round-to-nearest with no FTZ.
- In pure-Rust binaries nothing changes the FP environment.
- But a foreign library loaded into the process can. The known class is GCC's
  `crtfastmath.o`, which set FTZ/DAZ for the whole process when a `-ffast-math` shared
  object was loaded, until GCC 13 (GCC bug 55522; LLVM issue 57589). An injected DLL or
  `LD_PRELOAD` can also change MXCSR.RC.
- As shown in §3.1, FTZ/DAZ cannot change RandomX results. **A changed rounding mode
  would change every hash.**
- Rust documents that it "does not support executing floating-point operations with
  alternative rounding modes" (RFC 3514). Such a process is outside the language model.

**Consequence:** the node rejects every valid block, the same failure mode as D-1.
Severity is low: it needs a non-Rust component or a hostile local environment.

**Fix:** the self-test (W4). It must use `std::hint::black_box` so that it is not
constant-folded. It should run at node and miner start, and optionally periodically in
the miner. It does not *prevent* the fault; it turns silent isolation into a loud refusal
to start.

### 3.6 Code-generation variants (D-10)

**Problem:**
- CI only builds the default target CPU. Miners will build with
  `-C target-cpu=native` (AVX2, FMA, AVX-512).
- Rust semantics forbid contraction, so results must not change [src RFC 3514]. The
  residual risk is an LLVM backend bug in a code path that only exists with those
  features.
- **06's O4 proposes `#[cfg(target_feature = "fma")]` exact-error paths.** Once that
  lands, **two FPU implementations exist per architecture**, and CI must run both.

**Fix:** a CI leg with `RUSTFLAGS="-C target-cpu=x86-64-v3"`, plus v4 if the runner's CPU
supports AVX-512 (runtime-check it and skip otherwise). Run it on vectors plus digests.
Priority: P1 if O4 lands, P2 otherwise.

### 3.7 Documentation drift (D-8, D-5, D-6)

- `docs/consensus.md` §9 says "Its CI job (`randomx-full`, Linux) has not yet run on
  GitHub". Runs 78 and 79 passed per the session report §7. The text is stale.
- R9 §1 and full-review §3.2 attribute the RandomX v2.0.1 ARM/RISC-V invalid-hash bug to
  "MXCSR/FPCR plus JIT". The release notes and PR #326 show it was an **integer ISUB_R
  JIT immediate edge case**.
  - The conclusion ("no JIT is a strength") stands.
  - The lesson for 05 is different: rare *integer immediates* such as 0x80000000,
    `imm32 == 0` and powers of two for IMUL_RCP, and shift and rotate by 0 and 63 need
    targeted program-level vectors, not just FP tests.
- `fpu.rs:9-15` omits the ±2^-1008 FSCAL-of-zero case (§3.1).
- There is no supported-target table (§2.3 Q2).

### 3.8 Invariants that must never change

1. **There is exactly one FP path, the software directed-rounding emulation over RN
   hardware ops.** Never MXCSR/FPCR control, never `unsafe` FP-environment code, never
   `-ffast-math`-style flags, never runtime-dispatched `mul_add` (it falls back to libm
   without hardware FMA).
2. **A NaN bit pattern produced by the f^e XOR reaches the hash bit-exactly.** Never
   route it through a float arithmetic operation, a float conversion or a float
   canonicalization.
3. **Every serialization is explicit little-endian**: no `to_ne_bytes`, no transmute,
   no `bytemuck` casts of `[u64]`↔`[u8]`.
4. **Refuse at compile time the targets whose float semantics deviate from IEEE, and
   the targets that are not 64-bit** (x87, i586/i686, 32-bit ARM with NEON FTZ, and
   so on).
5. **AES rounds are exactly AESENC/AESDEC** on every backend, and the constants never
   change.
6. **Every supported target runs the vectors in CI.** A target that runs no vectors in
   CI is not "supported", only "designed for".

---

## 4. New findings

| ID | Severity | Status | Where | Scenario | Confidence |
|---|---|---|---|---|---|
| **D-1** | **Medium** | Not implemented (test gap) | `randomx/src/aes_gen.rs:167-175` → `aes-0.8.4/src/hazmat.rs:16-44`; `.github/workflows/ci.yml` (all jobs on x86 with AES-NI) | A node on a VPS whose hypervisor masks CPUID.AES (or an aarch64 host) runs the never-CI-tested fixslice64 backend. Any divergence isolates it silently. | high (gap); low (that a divergence exists) |
| **D-2** | Medium | Not implemented (known R9-7/T-8/P1-14, confirmed) | ci.yml | aarch64 operators (Graviton, Apple silicon, Raspberry Pi 5) run consensus code never executed on that architecture. | high |
| **D-3** | Low | Not implemented | `node/src/main.rs`, `miner/src/main.rs` (no startup KAT); `fpu.rs` assumes an RN environment | A foreign library or a hostile environment changes MXCSR.RC; the node rejects every block with no diagnosis. A CPU erratum or backend bug does the same. | medium |
| **D-4** | Low | Complete but requires further testing | `randomx/src/vm.rs:682-683` (NaN patterns in `f`), `vm.rs:566-572` (serialized) | Correct on every non-x87 target by Rust's guarantee. It becomes a split only if a future refactor sends these values through an FP op or conversion, or a target with x87-style returns is admitted. No test pins it. | high (mechanism); low (risk today) |
| **D-5** | Informational | — | R9 §1, full-review §3.2 | Misattribution of the upstream ARM/RISC-V invalid-hash bug (integer JIT immediate, not FP state). Redirects 05's edge-vector effort. | high |
| **D-6** | Informational | — | `randomx/src/fpu.rs:9-15`; R9 §3.1 | f can be ±2^-1008 (FSCAL of ±0). A 06 fast path that assumes a magnitude floor, or a scaled add, would be wrong in that case. | high |
| **D-7** | Low | Not implemented (decision) | `consensus/src/lib.rs:17-20` (guards only pointer width) | Someone builds the node for s390x or ppc64 big-endian. `randomx` is likely fine; other crates are unknown, and an undetected byte-order bug elsewhere splits that node. | medium |
| **D-8** | Low | Not implemented (docs) | `docs/consensus.md` §9, `docs/reviews/assumptions.md` K5, README, `docs/testnet.md` | There is no supported-target table; §9 is stale about `randomx-full`. Operators cannot tell what is supported. | high |
| **D-9** | Informational | Complete and verified (for the current code) | `fpu.rs` uses no `mul_add` | Rust guarantees that `mul_add` is correctly rounded, but without hardware FMA it calls the platform libm (R9 O4 caution). Any `cfg(target_feature="fma")` path doubles the per-target code paths; see D-10. | high |
| **D-10** | Low (P1 once O4 lands) | Not implemented | ci.yml | A miner or operator builds with `target-cpu=native`; a backend bug only on the AVX2/FMA/AVX-512 codegen path goes unseen. | medium |
| **D-11** | Informational | Complete but requires further testing | `randomx/src/lib.rs:24-25`, `consensus/src/lib.rs:19-20` | The guards exist, but no CI check proves they fire. A refactor could drop them. Cheap check: `cargo check --target i586-unknown-linux-gnu -p blacksilk-randomx` and `--target i686-unknown-linux-gnu -p blacksilk-consensus` must **fail**. | high |

---

## 5. Implementation plan for phase 2

All items are **policy or tests only**. None changes consensus or the testnet identity.
Hash output is unchanged by construction.

### W1. Supported-target matrix and documentation (P0, S)

**Files:** `docs/consensus.md` §9 (rewrite), `docs/reviews/assumptions.md` K5,
`randomx/README.md` (a "Platforms" section), `docs/testnet.md` (the operator table),
`randomx/src/fpu.rs:9-15` (docstring only).

**Matrix (proposed):**

| Tier | Targets | Meaning | CI evidence |
|---|---|---|---|
| **Supported** | `x86_64-unknown-linux-gnu`, `x86_64-pc-windows-msvc`, `aarch64-unknown-linux-gnu` | Nodes and miners may run here | Vectors and digests on every push; full = light weekly (Linux x86, aarch64) |
| **Supported, weekly** | `aarch64-apple-darwin`, `aarch64-pc-windows-msvc` (both Rust Tier 1), `x86_64-unknown-linux-musl` | Expected to work | Vectors and digests weekly on `macos-15` and `windows-11-arm` |
| **Evidence only** | `s390x-unknown-linux-gnu` (big-endian), `riscv64gc-unknown-linux-gnu` | The RandomX crate is shown to be endian-clean and ISA-neutral; **nodes not supported** | Light vectors and digests under QEMU, weekly |
| **Refused at build** | every non-64-bit target; x86 without SSE2; big-endian nodes (if the coordinator accepts D-7 option (a)) | — | Expected-failure `cargo check` legs (D-11) |

**Docs to update:** also fix D-5 (the attribution in the full-review §3.2 text, if
editable, or an erratum in the session log) and D-8 (the stale §9 sentence).

**Tests:** none. **Identity impact:** none.

### W2. Determinism CI workflow (P1, M)

**File:** a new `.github/workflows/randomx-determinism.yml`. It is deliberately a separate
file, so it does not conflict with 43, who owns `ci.yml`.

| Job | Runner | What it runs | When |
|---|---|---|---|
| `rx-aarch64` | `ubuntu-24.04-arm` | `cargo test --locked --release -p blacksilk-randomx` (vectors, fpu tests, digests); then `-- --ignored` (full = light) | push (non-ignored); weekly (ignored) |
| `rx-aarch64-armv8` | `ubuntu-24.04-arm` | the same with `RUSTFLAGS="--cfg aes_armv8"` | push |
| `rx-x86-soft-aes` | `ubuntu-latest` | `RUSTFLAGS="--cfg aes_force_soft"`, then `--cfg aes_force_soft --cfg aes_compact` | push |
| `rx-x86-v3` | `ubuntu-latest` | `RUSTFLAGS="-C target-cpu=x86-64-v3"` (plus v4 if `/proc/cpuinfo` has avx512f) | push (P1 once O4 lands) |
| `rx-macos-arm`, `rx-windows-arm` | `macos-15`, `windows-11-arm` | non-ignored randomx tests | weekly |
| `rx-s390x`, `rx-riscv64` | `ubuntu-latest` + `cross` (Docker/QEMU), or apt `qemu-user` + a cross gcc linker (CI tooling, not project code) | light vectors + digests only; **skip** the ignored full test | weekly |
| `rx-guards` | `ubuntu-latest` | rustup add `i586-unknown-linux-gnu` and `i686-unknown-linux-gnu`; `cargo check` must **fail** with the guard message (grep for it) | push |

- **Pins:** the same SHA-pinned actions and toolchain 1.98.1 as `ci.yml`. Pin `cross`
  with `cargo install cross --locked --version <pinned>`.
- **Estimated time [assumed]:**
  - native aarch64 light suite: ~2–4 min;
  - full = light: ~15–30 min on 4 vCPU;
  - QEMU s390x: the Argon2 fill plus 5 light hashes at ~20–50× slowdown ≈ 5–15 min.
- **Consensus impact:** none. **Docs:** W1 matrix.
- **Difficulty:** M (mostly QEMU plumbing).

### W3. Cross-target determinism digests (P1, S–M)

**Files:** a new `randomx/src/determinism_tests.rs` (a `#[cfg(test)]` module), plus a
one-line `mod` declaration in `randomx/src/lib.rs`. The lib.rs line is shared with 05
and 06, so the coordinator should serialize those edits.

**Tests:**
1. **`fpu_digest`:**
   - About 2^22 operations: add, sub, mul, div, sqrt × 4 modes.
   - The operands are drawn by a fixed xorshift, **biased to the RandomX-reachable
     classes and to IEEE edges**:
     - integers from i32;
     - a ∈ [1, 2^32);
     - e ∈ [2^-255, 1);
     - the grown e up to overflow;
     - ±2^-1008;
     - ±0, ±MAX, ±∞;
     - 1 ± ulp;
     - exact-tie constructions;
     - values a quarter or half ulp above MAX.
   - Blake2b-256 over the result bits is compared with a committed constant.
   - It runs in well under a second natively.
   - **Correctness** of the committed constant comes from 05's `rustc_apfloat` oracle
     (add, sub, mul and div via `*_r` with `Round`; sqrt checked by the sign of the
     residual via `mul_add_r`, since apfloat has no sqrt). The oracle needs to run only
     on x86_64. The digest then proves *equality* on every other target.
2. **`vm_digest_light`:**
   - Keys `test key 000` and `test key 001` (their caches are already shared via
     `OnceLock`).
   - 16 inputs per key: lengths 0, 1, 63, 64, 65, 100 (header-sized with varied nonce
     bytes) and random.
   - One committed digest over all hashes.
   - The expected hashes are cross-checked once against 05's reference corpus. If that
     is not yet available, they are marked "self-consistency only" in the test doc.
3. **`nan_patterns_survive_register_file`** (D-4):
   - Construct a VM state whose post-XOR f lanes are a signaling-NaN pattern
     (`0x7FF0_0000_0000_0001`), a quiet NaN with payload, and `-0.0`.
   - Assert that `register_file()` reproduces those bytes exactly.
   - This needs a `#[cfg(test)]` constructor, or the test lives in `vm.rs`'s own test
     module.
4. **`fscal_of_zero_is_normal`** (D-6): FSCAL of ±0 gives ±2^-1008. Then `add` in
   every mode, with an operand ≥ 1 and with 0, gives the IEEE result (compared with the
   oracle once available).

**Benchmarks:** none (keep the digests under 2 s in release).
**Docs:** list the tests in `randomx/README.md` "Verification status".
**Difficulty:** S (3, 4), M (1, 2, including oracle wiring with 05).

### W4. Runtime known-answer self-test (P1, S–M)

**Files:**
- `randomx/src/lib.rs`: a new `pub fn self_test() -> Result<(), SelfTestError>` and
  `pub fn self_test_full() -> Result<…>`;
- `randomx/src/selftest.rs` (new);
- `node/src/main.rs` (call at start-up; refuse to start on failure, with a clear message
  naming the failed KAT);
- `miner/src/main.rs` (the same, plus a re-check after each dataset build: hash vector
  1a in full mode is not possible because of the key, so check a light hash equals a
  full hash for one input under the *new* key);
- optionally `node/src/fingerprint.rs` (record "randomx self-test: pass/backend").

**Content:**
- **`self_test()`** takes about 1 ms and allocates nothing large:
  - fpu directed-rounding KATs through `std::hint::black_box` (which detects a changed
    rounding mode or FTZ at run time);
  - the `aes_generator_1r` vector (this runs *the runtime-selected AES backend*);
  - the `reciprocals`;
  - the `superscalar_generator` program hashes for key 000 (cheap: Blake2 plus the
    generator);
  - a short `blake2b_long` KAT.
- **`self_test_full()`** takes about 1–2 s and 256 MiB:
  - a cache for `test key 000` plus vectors 1a–1c;
  - exposed as `blacksilk-node --randomx-self-test`. This **is the R15 C3 / P0-13
    per-device-class check**, reduced to one command whose output is one line per
    vector plus the digest.

**Classification:** policy only. It rejects no block and changes no hash.
**Tests:** a unit test that `self_test()` passes; a node CLI test that
`--randomx-self-test` exits 0 and prints the expected digest.
**Trade-off:** it adds ~1 ms at start-up. The full variant is opt-in.
**Difficulty:** S (library), S (CLI). Coordinate with 09 (miner) and the node owners.

### W5. Remove the NaN-move dependence (P2, S)

**File:** `randomx/src/vm.rs`. Keep the post-XOR f values as `[u64; 8]` bits (for
example a field `f_out`) used by `register_file()`, instead of storing
`f64::from_bits(v)` into `self.f`. The next iteration overwrites `self.f` anyway.
- **Consensus:** none. The hash is unchanged on every conforming target. W3 tests 1–3
  prove it.
- **Why:** it makes invariant 2 structural rather than dependent on a language
  guarantee.
- **Coordination:** fold it into 06's O3 scratchpad refactor of `vm.rs`, so that one
  owner edits `vm.rs`.

### W6. Big-endian policy (P2, S; a decision)

**File:** `consensus/src/lib.rs:17-20`. Add a
`#[cfg(target_endian = "big")] compile_error!(…)` next to the 64-bit guard, if the
coordinator and 01 accept D-7 option (a). The RandomX crate itself stays
big-endian-capable, and W2's s390x job keeps it that way.
**Tests:** the expected-failure `rx-guards` leg gains `s390x -p blacksilk-consensus`.

### W7. aarch64 hardware AES (P3, M)

`aes 0.9.x` (0.9.3, 2026-08-28) enables ARMv8 AES by default with runtime detection
(aes 0.8 needed `--cfg aes_armv8`).
- **Upgrading from `=0.8.4`** is a dependency change in a crate that defines consensus
  bytes. The API moves to the `cipher` 0.5 generation, and the cfg names change
  (`aes_backend`).
- It needs W2 (every backend) and W3 green before and after.
- **Owner:** 44 (supply chain), with 06 measuring the gain.
- **Until then:** document `RUSTFLAGS="--cfg aes_armv8"` for aarch64 builds (W1). W2's
  `rx-aarch64-armv8` job proves it gives identical hashes.

### Priority summary

| Item | Priority | Consensus | Identity | Difficulty |
|---|---|---|---|---|
| W1 matrix + docs | P0 | none (docs) | none | S |
| W2 CI workflow | P1 (aarch64 + soft-AES legs are the P1 core; QEMU/macOS/Windows-arm are P2) | none | none | M |
| W3 digests + NaN/FSCAL tests | P1 | none | none | S–M |
| W4 self-test + `--randomx-self-test` | P1 (it is the tool for P0-13 C3) | none (policy) | none | S–M |
| W5 bits-based f output | P2 | none | none | S |
| W6 big-endian guard | P2 (decision) | none | none | S |
| W7 aes 0.9 | P3 | none (same semantics; must be proven) | none | M |

---

## 6. Dependencies and conflicts

- **05 randomx-conformance:**
  - owns the reference corpus and the `rustc_apfloat` oracle. W3's committed constants
    should be validated by them;
  - D-5 redirects part of their edge-case work to integer immediates (ISUB_R with
    0x80000000, IMUL_RCP at 0 and powers of two, rotates by 0 and 63, CBRANCH with
    shift 8 and 23);
  - shared edit point: `randomx/src/lib.rs` (the `mod` lines and the test module).
- **06 randomx-performance:**
  - any FPU fast path (O4) must pass W3 on every W2 leg;
  - an `fma` cfg path triggers the `rx-x86-v3` P1 upgrade;
  - their `vm.rs` refactor (O3) should absorb W5;
  - they must not assume a magnitude floor for f (D-6).
- **07 randomx-cache-seed:** no file overlap. `consensus/src/pow.rs` is theirs.
- **09 mining-templates:** `miner/src/main.rs`. The W4 start-up and post-build self-test
  hook needs one coordinated edit.
- **43 ci-reproducibility:** owns `ci.yml`. W2 is a separate workflow file to avoid
  conflicts, but it must reuse 43's action and toolchain pins. 43's aarch64 release
  builds should run W4's `--randomx-self-test` as a smoke step.
- **44 supply-chain:** W7 (aes 0.9); the `cross` tool pin.
- **45 benchmarks:** aarch64 numbers with and without `aes_armv8` come for free from W2.
- **01 consensus-core:** W6 edits the guard block in `consensus/src/lib.rs`.
- **47 docs-spec-consistency:** W1 docs; the D-5 and D-8 corrections.

---

## 7. Open questions for the coordinator

1. **D-7 / W6:** refuse big-endian for the node now (my recommendation), or leave it
   unguarded but "unsupported" in the docs?
2. Is the GitHub repository public? That decides 4 vCPU/16 GB versus 2 vCPU/8 GB runners
   and the cost of the weekly macOS legs. Both fit the full-mode test.
3. W4: should a failed start-up self-test be fatal for the node (my recommendation), or
   a loud warning with an override flag for diagnosis?
4. Is `--randomx-self-test` the accepted instrument for the P0-13 per-device-class
   check, replacing "run `cargo test`" on operator devices, which needs a toolchain?
5. W3's committed digests: may they land as "self-consistency" before 05's oracle and
   corpus exist, with a TODO to cross-validate them? Or should they wait?

---

## 8. Sources

- Rust RFC 3514, *Floating-point semantics*:
  https://rust-lang.github.io/rfcs/3514-float-semantics.html. IEEE RN guarantee, no
  contraction, NaN bits preserved on moves, the 32-bit x86 x87-return exception, NEON
  FTZ on 32-bit ARM.
- Rust `f64` documentation (`sqrt` and `mul_add` precision; `next_up`/`next_down` stable
  in 1.86): https://doc.rust-lang.org/std/primitive.f64.html
- Rust platform support tiers: https://doc.rust-lang.org/nightly/rustc/platform-support.html
- tevador/RandomX README (validated platforms incl. PPC64 big-endian; "only operations
  that are guaranteed to give correctly rounded results"): https://github.com/tevador/RandomX
- tevador/RandomX releases (v1.2.2 and v2.0.1: "invalid hashes (1 out of ~268 million)
  on ARM/RISC-V"; v1.1.8: "preserved floating point state"):
  https://github.com/tevador/RandomX/releases
- tevador/RandomX PR #326, *ISUB_R fix for ARM/RISC-V JIT* (immediate 0x80000000 with
  src = dst): https://github.com/tevador/RandomX/pull/326
- S. Boldo, S. Graillat, J.-M. Muller, "On the robustness of the 2Sum and Fast2Sum
  algorithms", ACM TOMS 44(1), 2017. https://dl.acm.org/doi/10.1145/3054947 ; preprint
  https://inria.hal.science/ensl-01310023
- S. Boldo, M. Daumas, "Representable correcting terms for possibly underflowing
  floating point operations", ARITH-16, 2003:
  https://ieeexplore.ieee.org/document/1207663/
- S. Boldo, "Pitfalls of a full floating-point proof: example on the formal proof of the
  Veltkamp/Dekker algorithms", IJCAR 2006:
  https://link.springer.com/chapter/10.1007/11814771_6
- A. Adomnicai, T. Peyrin, "Fixslicing AES-like ciphers", ePrint 2020/1123:
  https://eprint.iacr.org/2020/1123.pdf
- RustCrypto `aes` 0.8.4 source (local registry: `hazmat.rs`, `lib.rs` cfg flags,
  `soft.rs`, `tests/hazmat.rs`); `aes` 0.9.x docs: https://docs.rs/aes/latest/src/aes/lib.rs.html
- `rustc_apfloat` (0.2.3, Apache-2.0 WITH LLVM-exception; `add_r`/`mul_r`/`div_r`/
  `mul_add_r` with `Round`; no sqrt): https://github.com/rust-lang/rustc_apfloat ,
  https://docs.rs/rustc_apfloat/latest/rustc_apfloat/trait.Float.html
- GitHub arm64 hosted runners, GA for public repositories (2025-08-07):
  https://github.blog/changelog/2025-08-07-arm64-hosted-runners-for-public-repositories-are-now-generally-available/ ;
  private repositories (2026-01-29):
  https://github.blog/changelog/2026-01-29-arm64-standard-runners-are-now-available-in-private-repositories/ ;
  runner specifications: https://docs.github.com/en/actions/reference/runners/github-hosted-runners
- cross-rs (QEMU test support for s390x, powerpc64, riscv64gc, aarch64):
  https://github.com/cross-rs/cross
- RISC-V F extension, canonical NaN: https://docs.riscv.org/reference/isa/unpriv/f-st-ext.html
- GCC `-ffast-math` / `crtfastmath.o` process-wide FTZ/DAZ (GCC 13 change); LLVM issue
  57589: https://trofi.github.io/posts/302-Ofast-and-ffast-math-non-local-effects.html ,
  https://github.com/llvm/llvm-project/issues/57589
