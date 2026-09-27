# 06 randomx-performance: research dossier (phase 2, phase 1)

**Agent:** 06 randomx-performance. This is internal engineering research, not an audit.
**Base:** branch `rebuild/core`, commit `9e422d8`. Read-only. No builds and no benchmarks
were run: the machine is shared. Every speed figure below that is not quoted from a
source is an **estimate [assumed]** and must be measured under the methodology in §5.1
before anyone relies on it.

Evidence tags: **[math]** mathematically established; **[test: name]**; **[src]**
source-read; **[assumed]**; **[unknown]**; **[ext]** external primary source (see §8).

---

## 1. Scope and what I read

**Code, read in full:**
- `randomx/src/`: `lib.rs` (vectors, x87 guard), `config.rs`, `hash.rs`,
  `argon2d.rs`, `superscalar.rs` (execute, and the generator skimmed), `dataset.rs`,
  `aes_gen.rs`, `fpu.rs`, `vm.rs`;
- `randomx/examples/bench.rs` and `randomx/README.md`;
- `miner/src/lib.rs` and `miner/src/main.rs`;
- the PoW consumers:
  - `consensus/src/pow.rs` (`RandomXPow`);
  - `chain/src/manager.rs:35-110` (`CachedPow`, `compute_parallel`);
  - `p2p/src/net.rs:1740-1775` (chunked header PoW);
  - `node/src/fingerprint.rs:188-202`.
- **Build configuration:**
  - the workspace `Cargo.toml` profiles: release `lto = "fat"`, `codegen-units = 1`,
    `opt-level = 3`, `panic = "unwind"`; dev `opt-level = 3` for randomx, blake2 and
    aes;
  - `.github/workflows/ci.yml` (toolchain 1.98.1, and the `randomx-full` job);
  - there is no `.cargo/config*`, no `RUSTFLAGS` and no `target-cpu` anywhere in the
    repository.
- **Dependency source:** `aes-0.8.4/src/hazmat.rs` (runtime AES-NI detection on x86;
  ARMv8 only with `--cfg aes_armv8`).

**Tests in scope:**
- `randomx/src/lib.rs` tests: `cache_initialization`, `superscalar_generator`,
  `reciprocals`, `dataset_items`, `aes_generator_1r`, `hash_1a`–`hash_1e`, and
  `full_mode_matches_light_mode` (ignored; run in CI job `randomx-full`, 512 random
  inputs per key);
- `randomx/src/fpu.rs` tests (6 unit tests);
- `consensus/tests/randomx_end_to_end.rs` (2 tests);
- `miner/src/lib.rs` tests (`found_nonce_verifies_with_consensus`,
  `stop_flag_and_limit_end_the_search`).

**Docs and reports:**
- `docs/reviews/full-review-2026-09-27.md`: RandomX rows, §3.2, P1-4, P1-14, P2-6 and
  the never-change list;
- `docs/reviews/autonomous-session-2026-09-27.md` §5–§7;
- `docs/reviews/full-review-2026-09-27/R9-randomx.md` (in full);
- `R12-performance.md` (RandomX parts);
- `SX1` and `SX2` (the R9 rows; SX2 corrects R9-2's asymmetry to 4–7× at D0 = 100).

**Evidence:** `C:/bszkeval/seedrun2/miner0.log`. It records light-mode cache builds of
3.1 s and 0.94 s under load, and a real seed switch at 09:57.

**Roster neighbours:**
- 05 conformance;
- 07 cache and seed;
- 08 determinism;
- 09 mining templates;
- 10 validation pipeline;
- 34 actor;
- 43 CI;
- 44 supply chain;
- 45 benchmarks;
- 49 innovation.

---

## 2. Current state

### 2.1 What exists and is correct

**Safety and dependencies [src]:**
- `randomx` and `miner` both have `#![forbid(unsafe_code)]`.
- The only dependencies are RustCrypto `blake2 =0.10.6` and `aes =0.8.4` (hazmat).
  `aes` contains `unsafe` for its AES-NI backend, and that is upstream code.
- The crate has no `cfg(target_feature)` code path except the x86 non-SSE2
  `compile_error!` (`lib.rs:24-25`). So every build of the crate runs the same
  arithmetic.

**Conformance:**
- Pinned by the official vectors [test: `hash_1a`–`hash_1e`, `dataset_items`,
  `superscalar_generator`, `cache_initialization`, `aes_generator_1r`, `reciprocals`].
- Full = light on 1,024 random inputs [test: `full_mode_matches_light_mode`, CI
  `randomx-full`].

**What the tests do NOT prove:**
- anything about performance;
- the equivalence of any *future* optimized path to the current one. There is no
  internal oracle and no pinned digest over many inputs;
- FPU correctness beyond the vectors and 6 unit tests. The oracle is 05's item.

**Already done (this corrects R9 O2's scope) [src]:**
- **Superscalar execution:**
  - `SsInstr` already stores `dst`/`src` as `u8`;
  - it already carries a precomputed reciprocal (`superscalar.rs:84-92`), used at
    `:139`.
- **VM decode:**
  - it already lowers `IMUL_RCP` to `ImulR` with a precomputed reciprocal
    (`vm.rs:370-379`);
  - it pre-sign-extends the immediates.
- R9's O2 ("precomputed reciprocal", "u8 registers") is therefore partly in place
  already, and its expected gain (1.3–2×) is overstated. I estimate the remaining O2
  scope at 1.05–1.3× [assumed].

### 2.2 Measured baseline (only what exists)

**Measured figures:**

| Quantity | Figure | Source and conditions |
|---|---|---|
| Cache build | 0.63 s | README, "development machine", conditions not recorded |
| Cache build | 0.94–3.1 s | seedrun2 miner log, labnet under load |
| Light hash | ~0.45 s | README, idle |
| Light hash | ~0.75 s | brief / R9, "under load" |
| Full hash | ~100 ms/hash/thread | brief, under load |
| Dataset build | 133 s (8 threads) | README |
| Dataset build | 179 s (8 threads) | loaded |

**Reference, tevador README [ext] (i9-9900K, JIT, large pages):**

| Mode | Hash rate | Per hash, per thread |
|---|---|---|
| Fast | 5,770 H/s on 8 threads | ≈ 1.39 ms |
| Light | 1,160 H/s on 16 threads | ≈ 14 ms |

**Current gap [math on the figures above]:**
- light ≈ **32×**;
- full ≈ **70×**.

**What the baseline lacks:**
- no recorded CPU, governor, turbo, SMT or THP state;
- no full-mode or dataset benchmark in `bench.rs`, which is light-only;
- the "under load" figures were taken while other agents were building.

**None of these numbers is a reproducible baseline** (finding F4).

### 2.3 Where the time goes

**Workload per hash [math] (R9 §4.1, rechecked):**
- **Light mode:**
  - 16,384 dataset items × 8 SuperscalarHash programs × ~450 instructions ≈ 59 M
    superscalar ops;
  - of these, ~155 per program are 64-bit multiplications [ext: design.md §6: "450
    instructions, out of which 155 are 64-bit multiplications"].
- **Full mode:**
  - 4.19 M VM instructions;
  - ≈ 2.1 M directed-rounding FP lane-ops (≈ 75% of FP lane-ops run under a
    non-nearest mode, because CFROUND randomizes the mode).

**Attribution [src + assumed]:**
- Light mode and the dataset build are superscalar-interpreter bound.
- ~0.35 s per 59 M ops ≈ 6 ns ≈ 20–25 cycles per op. That is far above the 1–3 cycles
  a simple op should cost.
- **Two competing hypotheses:**
  - (a) Indirect-branch mispredictions on the `match` dispatch. The opcode sequence is
    random within a program, but it is identical for all 16,384 items, so the pattern
    repeats every ~3,600 dispatches. Ertl & Gregg 2003 [ext] showed that switch
    dispatch is mispredict-dominated on older predictors.
  - (b) Long dependency chains plus 64-bit multiply latency. Rohou, Swamy & Seznec
    (CGO 2015) [ext] showed that modern TAGE-class predictors predict switch dispatch
    well.
- **Which one holds decides the gains of O1.** It must be measured with
  `branch-misses` per op before O1 is sized (O0).

**Full mode, the directed FPU emulation [src]:**
- Each directed `mul`, `div` or `sqrt` runs 2 Dekker splits plus a TwoProduct
  (≈ 17 flops), plus `with_exponent` bit operations (`fpu.rs:72-88, 130-175`).
- `correct()` then takes a data-dependent branch on the error sign (`fpu.rs:52-61`).
  That branch is ~50% unpredictable.
- Estimate: 10–30 ms per hash [assumed, R9].

**Memory is not the bottleneck [math]:**
- 16,384 dataset misses × ~80 ns ≈ 1.3 ms per hash;
- scratchpad AES fill and AesHash1R: 262 k AES-NI rounds ≈ 1 ms;
- a 2 MiB zeroed scratchpad allocation per `Vm` is ≈ 0.1 ms (F10).

---

## 3. Problems, one by one

### P-A. The superscalar interpreter (light verification, dataset build)

**The problem:**
- Every dataset item runs 8 programs through a 14-arm `match`, one item at a time
  (`superscalar.rs:119-142`, `dataset.rs:324-341`).
- The build expands items one after another on each thread (`dataset.rs:352-366`).

**Why it exists:** it is a faithful port of the reference *interpreter*. The reference
compiles SuperscalarHash with its JIT; we cannot, because a JIT needs W^X memory, and
so `unsafe` plus OS FFI.

**Security consequence:**
- Light-mode cost sets the node's verification cost for low-work header attacks
  (R9-2, which SX2 corrects to 4–7× at D0 = 100).
- It also sets the cost of IBD header PoW (R12 B3: ~6.9 h per chain-year on 8
  threads).
- The dataset build sets the seed-switch stall of every full-mode miner (R9-R4).

**Class:** performance, liveness-adjacent (sync time, DoS asymmetry). Not
consensus-critical as long as the output is unchanged. Not privacy-critical.

**Solution: SoA lane batching (O1).**
- The key fact: *all items under one key execute the same 8 programs*; only the
  register values differ [src, spec §7.3]. So interpret each instruction once for `K`
  independent items, with registers laid out as `[[u64; K]; 8]`.
- **Effects:**
  - the dispatch cost is amortized K×;
  - K independent multiply chains give the out-of-order core ILP (64-bit `mul` has
    latency 3 and throughput 1 per cycle on recent x86 [assumed]);
  - add, sub, xor and shift loops over K auto-vectorize under SSE2/AVX2.
- **Where it applies:**
  - (1) **the dataset build**: items `n..n+K`;
  - (2) **batched light verification**: K VMs keyed by the same seed step in
    lockstep. Every hash runs exactly 8 × 2,048 iterations, and CBRANCH only jumps
    within a program, so the iteration count is fixed [src `vm.rs:648`]. So K VMs
    each run their *own* program for iteration i, then request K item numbers
    together, and one SoA batch computes all K items. This is the "lane batching" of
    the roster;
  - (3) light-mode mining over K nonces.
- **Where it does NOT apply:** the VM programs themselves. Every hash has a different
  program, generated from its input, so VM lanes cannot be batched. It also does not
  help a single tip-block verification.

**Why SIMD adds little here [ext + math]:**
- 155 of 450 superscalar instructions (34%) are 64-bit multiplies.
- AVX2 has no 64×64→64 vector multiply (`vpmullq` needs AVX-512DQ) and no vector
  `mulh` at all.
- The gain is therefore dispatch amortization plus ILP, not vector width.

**Prior art:**
- The reference JIT's superscalar compilation.
- xmrig's dataset-init JIT.
- In interpreters generally: superinstructions and dispatch amortization
  (Ertl & Gregg).
- I found no public safe-Rust batched RandomX; this is BlackSilk-specific engineering
  [unknown beyond my search].

**Trade-offs and risks:**
- more code in consensus-critical execution;
- register pressure: K × 8 u64 values do not fit in 16 GPRs, so they live in L1. That
  is fine, but K must be tuned (4–16);
- batched light verification changes the threading model of `compute_parallel`:
  fewer threads, K headers each. That is latency-for-throughput: bad for one tip
  header, good for IBD;
- **the risk:** a lane-mixing bug gives wrong items only for some batch positions,
  which the vectors would not catch. Hence the internal differential tests below.

**Tests:**
- property test: `dataset_items_batch(ns) == [dataset_item(n) for n in ns]` over
  random item numbers, including the last items, 34,078,718 to 34,078,719;
- run it over several keys (at least 8, including 60+ byte keys) and every K;
- the full dataset equality spot-check in `randomx-full`;
- batched light hash == scalar light hash for random inputs across batch sizes 1..K,
  including partial batches;
- the official vectors.

**Invariants that must never change:**
- the item function (spec §7.3);
- the program order;
- `address_register` selection;
- the XOR with the cache line;
- `LINES - 1` masking.

### P-B. Superscalar decode and bounds checks (O2, narrowed)

**The problem [src]:**
- `r[d]` with `d = ins.dst as usize` (0..255) against `[u64; 8]`: this bounds check
  cannot be elided;
- the `IaddC7/8/9` and `IxorC7/8/9` arms re-sign-extend the immediate on every
  execution;
- `IaddRs` recomputes the shift from `mod_`.

**The fix:**
- pre-decode into an execution form with 9 canonical ops;
- index with `r[(d & 7) as usize]`;
- pre-sign-extend `u64` immediates;
- precompute the shift.

**Gain:** 1.05–1.3× on superscalar [assumed]. **Consensus:** none. **Tests:** the same
as P-A; `superscalar_generator` stays on the unchanged `SsInstr`.

### P-C. The VM interpreter (full mode, and 25% of light)

**The problem [src]:**
- The scratchpad is a `Vec<u8>` accessed through
  `self.scratchpad[addr..addr+8].try_into().unwrap()` (`vm.rs:603-618`). Each load
  pays two slice bounds checks, because the mask is a runtime field.
- `Op` uses `usize` and `Option<usize>` fields, about 40 bytes per op [assumed].
- `self.r[dst]` with `dst: usize` is bounds-checked.

**The fix:**
- Store the scratchpad as `Box<[[u8; 8]]>` (262,144 words) and index with
  `((base + imm) & mask) >> 3 & (L3/8 - 1)`. The final AND is a no-op for every
  valid mask, and it lets LLVM elide the check.
- Keep the byte layout, so the AES fill and AesHash1R stay on bytes through
  `as_flattened_mut()`. Endianness stays explicit through `u64::from_le_bytes`.
- Use `u8` registers indexed with `& 7`.
- Split variants by `Src::Reg`/`Src::Imm`, and by the L3 fixed-address form, so the
  per-op `match` inside `src_val` and `mem_addr` disappears.

**Gain:** 1.2–1.5× on the VM part [assumed, R9 O3/O5]. **Consensus:** none, if outputs
are identical. **Tests:** vectors, full = light, and a pinned digest (W2).

### P-D. The directed-rounding FPU (full mode)

**The problem [src]:**
- (1) `correct()` branches on the error sign. A data-dependent branch mispredicts
  ~50% [assumed].
- (2) Dekker's split-based TwoProduct costs ≈ 17 flops in a dependency chain.

**R9's option O4a (FMA under `cfg(target_feature = "fma")`) [ext]:**
- `f64::mul_add` is documented as correctly rounded ("guaranteed to be the rounded
  infinite-precision result").
- But without hardware FMA it lowers to a software `fma` call:
  - on Windows or no-std targets that is the platform or compiler-builtins
    implementation;
  - software FMA fallbacks have had rounding bugs (for example f32 subnormal handling
    in compiler-builtins and musl, reported in Aug 2026).
- A compile-time `cfg(target_feature)` path is safe from that. But **it splits
  consensus code into two build-dependent paths**: default builds use Dekker,
  `target-cpu=native` builds use FMA. CI would then have to test both builds forever
  (with 08 and 43).

**Recommended alternative, O4′: exact integer residuals [math].**
- For normal operands, let the significands with the hidden bit be
  `ma, mb ∈ [2^52, 2^53)`. Then `M = ma·mb` is exact in `u128` (< 2^106).
- **Multiplication.** The sign of `|a·b| − |p|` is the sign of
  `M − (mp << k)`, with `k = Ep − Ea − Eb + 52 ∈ {52, 53, 54}`:
  - 54 happens when rounding carries into a new binade;
  - all quantities are < 2^108, so they fit in `u128`.
- **Division.** The sign of `|a|/|b| − |q|` is the sign of `(ma << k) − mq·mb`.
- **Square root.** The sign of `√a − s` is the sign of `(ma << k) − ms²`, with `k`
  chosen by exponent parity.
- **Why this is better:**
  - one `u128` multiply (x86-64 `mul`, or `mulx` with BMI2; `umulh` on aarch64), a
    shift and a compare replace Dekker's chain;
  - it is portable integer arithmetic with no build-flag dependence;
  - it is easier to reason about than error-free transforms.
- **Validity:** the same precondition as today. The unscaled result is normal, which
  §3.1 of R9 establishes (subnormals are unreachable). Overflow and infinity keep
  their existing early exits.
- **Branch-light `correct`:**
  - for finite non-zero `r`, `next_up`/`next_down` are
    `bits ± 1` selected by the sign of r;
  - `MAX + 1ulp` gives the bit pattern of +∞, which is the correct IEEE directed
    overflow for Up when `RN = MAX` and `err > 0` [math];
  - so the adjustment becomes `bits + (sign-selected ±1) × need`, with `need` a
    0 or 1 computed without branches.
- Keep `add` on TwoSum: it is 6 flops and already cheap.

**Gain:** 1.3–2× on full-mode FP [assumed]. It must be measured against both the
current code and the FMA-cfg variant; adopt O4′ only if it wins or ties.

**Consensus:** none if the output is bit-identical. But `fpu.rs` is the rarest-path
consensus code, so **it must be gated on 05's independent oracle**
(`rustc_apfloat`-class). The oracle runs ≥ 10^7 random in-range operands per op per
mode, plus edge cases (exact ties, the binade carry, the MAX boundary, ±∞, signed
zero for add), and must agree three ways: old, new and oracle.

**Invariants that must never change:**
- the software rounding emulation stays the only FP path;
- no MXCSR/FPCR;
- no contraction that is not proven exact;
- NaN stays unreachable.

### P-E. SIMD options under the pure-Rust, no-`unsafe` policy

This answers the roster question directly.

**`core::simd` / `std::simd` [ext]:**
- It is **still nightly-only** (`portable_simd`, tracking issue #86656). The official
  std docs state "This is a nightly-only experimental API".
- A search-engine summary claiming it was "stabilized in 2025" is contradicted by the
  docs. A Sep 2026 third-party CI canary is still waiting for stabilization.
- It cannot be used on the pinned stable 1.98.1 toolchain.

**`std::arch` intrinsics [ext]:**
- Since **Rust 1.87**, "most `std::arch` intrinsics that are unsafe only due to
  requiring target features to be enabled are now callable in safe code that has
  those features enabled".
- Since **1.86** (target_feature 1.1), safe functions can carry
  `#[target_feature(enable = …)]`.
- **However**, the Rust Reference states that such a function "can only be safely
  called within a caller that enables all the target_features that the callee
  enables", and gives the example comment "Calling `foo_sse` here is unsafe … even if
  `sse` is enabled by default on the target platform or manually enabled as compiler
  flags".
- So the *entry* into any intrinsic-using code from ordinary code needs one `unsafe`
  block. That also covers SSE2 on x86-64, and it covers pointer-taking loads, stores
  and prefetches in any case.
- **Conclusion: `std::arch` is not usable in a crate under
  `#![forbid(unsafe_code)]`.** R9's "SIMD via safe `std::arch`?" is answered **no**.

**Safe-wrapper crates [ext]:**
- `safe_arch` 1.2.0 (Aug 2026) works purely by compile-time
  `cfg(target_feature)`, with `unsafe` inside.
- `wide` is built on `safe_arch`.
- `fearless_simd` 1.0 (released 2026-09-22) uses target_feature 1.1 plus two
  audited `unsafe` building blocks, with runtime dispatch.
- `pulp` and `multiversion` do runtime dispatch, with `unsafe` inside.
- **Assessment:**
  - these are legal under the letter of the policy, as `aes` is: `unsafe` inside a
    dependency;
  - but each adds a new supply-chain surface to consensus code, and `fearless_simd`
    1.0 is 5 days old;
  - the workload is dominated by 64-bit mul/mulh, which AVX2 does not vectorize;
  - **recommendation: do not add a SIMD crate.**

**What remains, and is safe:**
- **LLVM auto-vectorization** of SoA loops (P-A). It needs no dependencies and no
  `unsafe`, and SSE2 is baseline on x86-64 and NEON on aarch64.
- **Optional `-C target-cpu`** builds for the *miner only* (F13).

**Runtime dispatch:** not available without `unsafe` or a dispatch crate. The safe
alternative is two separately built miner binaries (baseline and x86-64-v3), selected
by the operator.

### P-F. Cache build (Argon2d) cost

**The problem [src]:**
- `read_block` copies the prev and reference blocks (2 × 1 KiB) for every one of the
  786,432 block fills (`argon2d.rs:91-94, 132-136`). That is ≈ 1.6 GB of memcpy per
  cache build.
- `fill_block` runs scalar G over a 128-word block.
- **Why it matters:**
  - the cache build runs under `RandomXPow`'s mutex (R9-2, owned by 07);
  - it runs at every seed switch;
  - seedrun2 measured 0.94–3.1 s under load.

**The fix:**
- XOR `prev ^ ref` from slice views (index arithmetic, with no whole-block copies);
- write G over row arrays `[u64; 4]` so LLVM can vectorize the 4-wide rounds (64-bit
  add, xor and rotate vectorize; the `fBlaMka` 32×32 multiply maps to `pmuludq`).

**Gain:** 1.3–2× [assumed].

**Rejected alternative:** RustCrypto `argon2` `fill_memory`. RandomX hashes
`outlen = 0` into H0, while `argon2` enforces an output length of at least 4, so it is
not a drop-in. It would also add a consensus-byte dependency.

**Priority:** P3. 07's out-of-lock build is the real fix for the lock problem.

### P-G. Miner-side performance (my part of `miner/src`)

**Findings [src]:**
- `threads` defaults to all logical CPUs, including SMT siblings (`main.rs:303-305`).
- The dataset is built with the same thread count.
- Nothing guides the operator.
- There is no offline self-test or benchmark mode. The P0-13 "per-device-class
  RandomX hash check" needs one: today an operator would have to run `cargo test`.
- `search` spawns threads and allocates a `Vm` (2 MiB) per template, every 15 s. That
  is negligible.
- `hashes.fetch_add` is contended only at ~10 H/s per thread. Negligible.

**Operator knobs that need no code [ext]:**
- **Linux THP.** With `/sys/kernel/mm/transparent_hugepage/enabled = always`, or with
  the glibc ≥ 2.35 tunable `GLIBC_TUNABLES=glibc.malloc.hugetlb=1` (makes glibc
  `madvise(MADV_HUGEPAGE)` its mmap'd chunks), the 2 GiB dataset gets 2 MiB pages with
  zero code change.
- **Windows large pages** need `VirtualAlloc` with `SeLockMemoryPrivilege`: FFI, so
  excluded.
- **Expected gain for our interpreter:** small (≤ 5% [assumed]), because memory is not
  the bottleneck (§2.3).

**Stale work and seed prebuild:** these belong to 09 and 07. Not repeated here.

### P-H. Toolchain-level optimizations

- **Miner `-C target-cpu=native` or `x86-64-v3`.**
  - This is deterministic for this crate. RFC 3514 guarantees IEEE-754 results for
    non-NaN operations and forbids automatic FMA contraction. NaN is unreachable in
    RandomX (R9 §3.1). The crate has no `cfg(target_feature)` paths.
  - It gives BMI2 `mulx`, and AVX2 for the SoA loops after O1.
  - **Node binaries stay baseline**: SIGILL risk on older CPUs.
  - **This invariant breaks if anyone later adds a `cfg(target_feature)` path**, which
    is another reason to prefer O4′ over O4a.
- **PGO** (`-Cprofile-generate`/`-Cprofile-use`) [ext].
  - The final binary does not depend on the profiler runtime.
  - Interpreters typically gain 10–20% [assumed].
  - It makes reproducible builds depend on a committed `.profdata`. P3, and only
    together with 43.
- **Guaranteed tail calls** (`become`) for threaded dispatch are unstable and
  incomplete (tracking issue #112788) [ext]. Not usable.

---

## 4. New findings

| ID | Severity | Status | Location | Scenario | Confidence |
|---|---|---|---|---|---|
| **F1** | Medium (perf, liveness/DoS-adjacent) | Not implemented | `superscalar.rs:119-142`, `dataset.rs:324-341, 352-366` | Items are expanded one at a time through a match interpreter. Light verification ~0.45–0.75 s; IBD header PoW ~6.9 h per chain-year on 8 threads (R12); dataset rebuild stalls every full-mode miner 133–179 s at each seed switch. Batching K same-key items (dataset, IBD header batches, light mining) is the largest safe-Rust lever. | high (structure); medium (gain size, pending O0) |
| **F2** | Low (perf) | Not implemented | `fpu.rs:52-61, 72-88, 130-175` | Directed mul/div/sqrt use a ~17-flop Dekker chain plus a ~50%-unpredictable branch on about 2.1 M lane-ops per hash. O4′ (u128 exact residual, branch-light correct) is portable and needs no build-flag path. | medium |
| **F3** | Low (perf) | Not implemented | `vm.rs:51-186, 603-632, 697-868` | Byte-slice scratchpad with non-elidable bounds checks; `usize`/`Option` operands; `src_val`/`mem_addr` inner matches. | high (source); medium (gain) |
| **F4** | Medium (process; blocks evidence-based decisions) | Not implemented | `randomx/examples/bench.rs`, `randomx/README.md:78-88` | The benchmark is light-only, with no machine, governor, turbo, SMT or THP record. Figures were taken on a loaded shared machine. The R9-2 asymmetry, R12 IBD and R9-R4 stall figures all rest on unreproducible numbers, and no before/after comparison of any optimization is possible. | high |
| **F5** | Informational (answers the roster question) | Accepted limitation | policy vs Rust Reference | `std::arch` cannot be used under `forbid(unsafe_code)`: even with 1.87 safe intrinsics, the entry call needs `unsafe`. `std::simd` is nightly-only. SIMD crates carry `unsafe` inside. | high |
| **F6** | Informational (challenges R9) | Complete and verified (partly) | `superscalar.rs:84-92, 139`; `vm.rs:370-379` | R9 O2's "precompute reciprocal, u8 registers" is already done. The remaining O2 is `& 7` indexing, merged C7/C8/C9 variants and a precomputed shift; realistic gain is 1.05–1.3×, not 1.3–2×. | high |
| **F7** | Low (perf, aarch64) | Complete but requires further testing | `randomx/Cargo.toml` (`aes =0.8.4`); `aes-0.8.4/src/hazmat.rs:16-47` | R9-5 has an upstream fix: aes 0.9.x (0.9.3, 2026-08-28) autodetects ARMv8 AES at runtime on Linux and macOS. The upgrade is consensus-byte-sensitive (cipher 0.5 API, exact pin), so it needs vectors, the corpus and 44's review. | medium-high |
| **F8** | Informational | — | R9 O4a | An FMA-cfg path would create two build-dependent consensus code paths. Software FMA fallbacks have had rounding bugs (2026). Prefer O4′. | medium-high |
| **F9** | Low (ops) | Not implemented | `miner/src/main.rs:303-305, 338-339` | No offline `--selftest`/`--bench`, as needed for the P0-13 per-device check. SMT threads are the default, untested for the interpreter. No THP guidance. | high |
| **F10** | Informational | Accepted limitation | `consensus/src/pow.rs:80-83`, `vm.rs:529` | A fresh 2 MiB zeroed scratchpad per verified header: ≈ 0.1 ms against 450 ms. Not worth changing. | high |
| **F11** | Low (perf, lock-hold time) | Not implemented | `argon2d.rs:91-94, 132-136, 138-202` | About 1.6 GB of block copies per cache build. The build is on the `RandomXPow` mutex path (R9-2) and at every seed switch (0.94–3.1 s measured under load). | medium |
| **F12** | Informational | Not implemented (docs) | ops | Large pages need no code on Linux (THP `always`, or the glibc 2.35+ `hugetlb=1` tunable). Windows is impossible without FFI. The gain is small for the interpreter. | medium |
| **F13** | Informational | Complete and verified (property) | `randomx/src/lib.rs:24-25`; RFC 3514 | Builds with `target-cpu` are deterministic because the crate has no `cfg(target_feature)` arithmetic paths and Rust never contracts FP. This must stay true, or be CI-tested for both builds. | high |

**Security note (no new vulnerability).** None of F1–F13 is a correctness or consensus
bug. Their security relevance is indirect: the verifier/attacker cost asymmetry (R9-2,
which SX2 corrects to 4–7× at D0 = 100) and sync liveness. The real DoS fixes are
presync, `MIN_CHAIN_WORK` and the out-of-lock cache build, owned by 31 and 07.

**Realistic speed-up [assumed; to be replaced by measurements]:**

| Path | Now | After W3–W6 | Remaining gap to JIT |
|---|---|---|---|
| Dataset build (8 threads) | 133–179 s | 25–50 s (3–5×) | JIT is seconds |
| Light, single header (tip) | 0.45 s | 0.30–0.40 s (1.1–1.5×) | ~20–30× |
| Light, batched K = 8 same-seed headers (IBD) | 0.45 s/hash·thread | 0.12–0.2 s (2.3–4×) | ~10× |
| Full hash, per thread | ~100 ms (loaded) | 35–60 ms (1.7–3×) | 25–40× |

**The gap is structural** (no JIT, no `unsafe`, no large pages on Windows). The
documentation must keep saying that the bundled miner is not competitive (full review
risk 1).

---

## 5. Implementation plan for phase 2

**Ordering rule:** W1 and W2 first. No optimization may merge without a before/after
measurement under W1 and a green W2 on the same commit.

### 5.1 Benchmark methodology (deliverable of W1; share with 45)

**1. Record the machine (in a JSON header per run):**
- CPU model, stepping, microcode, cores/threads, L2/L3;
- RAM type, speed and channels;
- OS and kernel build;
- `rustc -vV` (1.98.1);
- commit;
- profile (release, fat LTO, CGU 1);
- RUSTFLAGS (none vs `target-cpu`);
- power state:
  - Linux: `cpupower frequency-info` governor = `performance`, turbo state
    (`intel_pstate/no_turbo` or `cpufreq/boost`), SMT on/off, THP mode;
  - Windows: power plan "High performance" (`powercfg /getactivescheme`).

**2. Isolation:**
- an exclusive machine window: the coordinator stops the other agents and builds;
- pin to cores (`taskset -c` / `start /affinity`);
- ≥ 3 warm-up hashes;
- interleave A/B runs (ABAB…) so thermal drift cancels.

**3. Workloads (fixed keys `test key 000`/`001` and deterministic inputs):**

| ID | Workload | Repetitions |
|---|---|---|
| B1 | Cache build | ×5 |
| B2 | Light hash, 1 thread | ≥ 50 |
| B3 | Light hash, N threads (aggregate) | — |
| B4 | Dataset build, 1/4/8 threads | ×3 (2.3 GiB) |
| B5 | Full hash, 1 thread | ≥ 500 |
| B5 | Full hash, N threads (H/s) | — |
| B6 | Batched light, K ∈ {1, 4, 8, 16} (after W7) | — |
| B7 | Superscalar item µs, scalar vs batch | — |
| B8 | FPU ns per op per mode, on operand streams recorded from vector 1b | — |
| B9 | Node header throughput: `compute_parallel` over 2,048 headers | — |

**4. Statistics:**
- median, min and IQR; report derived ns per op;
- accept a claimed gain only if the medians differ by more than 3× the IQR.

**5. Counters:**
- Linux:
  `perf stat -e cycles,instructions,branches,branch-misses,dTLB-load-misses,LLC-load-misses`;
- a `samply` profile on Windows and Linux.
- **This decides hypothesis (a) vs (b) in §2.3.**

**6. Output:** `docs/evidence/bench-<date>/` (JSON plus machine descriptor), and the
README table regenerated from it. **No new dependencies:** `std::time::Instant` plus
`std::hint::black_box`, no criterion.

### 5.2 Work items

| # | Item | Files (ownership) | Consensus | Identity | Tests | Bench | Docs | Size | Priority |
|---|---|---|---|---|---|---|---|---|---|
| W1 | Benchmark harness plus baseline (O0), per §5.1; `bench.rs` gains `--full`, `--dataset`, `--threads`, `--json` | `randomx/examples/bench.rs`, `randomx/README.md` (Performance), `docs/evidence/bench-*/` | nothing | none | — | B1–B5, B7, B8 baseline plus perf counters | README perf table with machine record | S | **P1** (the baseline is needed before the freeze for 45's before/after) |
| W2 | Internal oracles and regression digest: keep today's scalar code as `reference` (`#[cfg(any(test, feature = "reference"))]`, unchanged code moved); new integration test dir; a pinned digest of light hashes over 64 deterministic inputs × 2 keys (normal suite, ~1 min), and over 4,096 inputs in `randomx-full` | `randomx/src/reference.rs` (new), `randomx/tests/equivalence.rs` (new), `randomx/src/lib.rs` (mod line), `.github/workflows/ci.yml` (`randomx-full` step only, with 43) | nothing | none | differential (optimized vs reference), property (random items, keys, K), regression digest | — | README "Verification status" | S–M | **P1** (a gate for W3–W7) |
| W3 | O1: SoA batched superscalar (`execute_batch::<K>`), `Cache::dataset_items_batch`, dataset build in batches; K tuned by B7 | `randomx/src/superscalar.rs` (execute only; the generator untouched), `randomx/src/dataset.rs` | nothing (output identical) | none | batch = scalar property tests (all K, edge items, 8+ keys); `dataset_items`; full = light | B4, B7 | README | M | **P1** (shortens the seed-switch stall that 09's prebuild hides; needed if the testnet runs full-mode miners at 2113) |
| W4 | O2 narrowed: compact execution form, `& 7` indexing, merged constant ops | `randomx/src/superscalar.rs` (with W3, same owner) | nothing | none | as W3 | B2, B7 | — | S | P2 |
| W5 | O3/O5: word-indexed scratchpad, `u8` registers, split operand variants | `randomx/src/vm.rs` | nothing | none | vectors, W2 digest, full = light | B2, B5 | — | M | P2 |
| W6 | O4′: u128 exact residuals and branch-light `correct` | `randomx/src/fpu.rs` | nothing, but the most sensitive code | none | **blocked on 05's FPU oracle**: three-way old/new/oracle, ≥ 10^7 per op per mode plus edges; vector 1b (overflow-heavy); W2 digest | B5, B8 | README design notes, a proof sketch of the u128 bound in a code comment | M | P2 |
| W7 | Batched light-verification API (`Vm` state split into resumable per-iteration steps; `hash_batch_light(cache, inputs) -> Vec<Hash>`); then the consumer in `compute_parallel` groups jobs by seed | `randomx/src/vm.rs`, `randomx/src/lib.rs` (API); consumer `chain/src/manager.rs::compute_parallel` (**owned by 10/34**) and `consensus/src/pow.rs` (**owned by 07**): a `PowFunction::pow_hash_batch` default method | policy (acceptance order unchanged) | none | batch = single for random inputs and batch sizes; mixed-seed batches; chain tests unchanged | B6, B9 | `docs/p2p.md` IBD note | M–L | P2 |
| W8 | Argon2 fill without block copies; row-wise G | `randomx/src/argon2d.rs` | nothing | none | `cache_initialization` plus a full-cache digest (W2) | B1 | — | S | P3 |
| W9 | Miner `--selftest` (official vectors light, optional full, prints H/s and the machine record) for the P0-13 per-device check; threads/SMT guidance after B5; THP/glibc and `target-cpu` guidance for miner builds | `miner/src/main.rs` (CLI flag only; **coordinate with 09**, who owns the template loop), `docs/testnet.md` mining section (with 47) | nothing | none | test: `--selftest` passes against the vectors | B5 via selftest | operator docs | S | **P1** (selftest, for P0-13); guidance P2 |
| W10 | `aes` 0.9.x upgrade (aarch64 hardware AES by default) | `randomx/Cargo.toml`, `randomx/src/aes_gen.rs`, `Cargo.lock` (**with 44**) | nothing if the vectors hold; consensus-byte dependency | none | `aes_generator_1r`, all vectors, W2 digest, 08's aarch64 CI | B2 on aarch64 | README | S | P3 |
| W11 | PGO for miner release builds | build scripts / CI (**43**) | nothing | none | W2 digest on the PGO binary | B5 | release docs | M | P3 |

**Not recommended:**
- adding `fearless_simd`, `pulp`, `wide`, `safe_arch` or `multiversion` (P-E);
- the FMA-cfg path (F8), unless W6's O4′ measures slower;
- any change to `config.rs`, instruction semantics, program generation or the seed
  schedule;
- a RandomX JIT, which is excluded by policy.

---

## 6. Dependencies and conflicts

| Workstream | Relationship |
|---|---|
| **05 randomx-conformance** | W6 is blocked on its FPU oracle. The reference corpus (≥ 10^5 hashes) should gate W3–W7 once it exists. W2's `reference.rs` and 05's corpus tests share `randomx/tests/`: agree on file names. |
| **07 randomx-cache-seed** | Owns `consensus/src/pow.rs` (the out-of-lock build, pinning, capacity). W7's `pow_hash_batch` touches that trait: sequence W7's consumer after 07. W8 shortens their lock-hold time but does not replace their fix. |
| **08 randomx-determinism** | F13: `target-cpu` guidance is valid only while there are no `cfg(target_feature)` paths. W10 needs their aarch64 CI. |
| **09 mining-templates** | Owns `miner/src/main.rs`' loop, the prebuild and stale work. W9 adds only a CLI subcommand. W3 cuts the prebuild's cost and memory-time window. |
| **10 / 34** | `compute_parallel` and the header path belong to them. W7's consumer must fit the actor design (verification off-lock, batch by seed). |
| **43 ci-reproducibility** | The `randomx-full` job extension (W2), PGO (W11), and whether release miners get a v3 build. |
| **44 supply-chain** | The aes 0.9 upgrade (W10); confirms "no SIMD crate". |
| **45 benchmarks-scalability** | §5.1 should become part of their suite spec. One shared evidence directory format. |
| **49 innovation** | Safe-Rust RandomX optimization overlaps: W3/W7 lane batching and W6 O4′ are my concrete proposals. |

---

## 7. Open questions for the coordinator

1. **An exclusive benchmark window.** W1 needs an idle machine (no other agents or
   builds) for about 1–2 h, including 2 dataset builds at 2.3 GiB each. When?
2. **Is W3 (O1) P1?** It is if the trial plans full-mode miners across 2113 (P0-13).
   Otherwise P2.
3. **Unsafe-in-dependency policy.** Confirm that no new dependency with internal
   `unsafe` may enter consensus crates for performance. I recommend a firm "no" for
   SIMD crates; `aes` remains the only one.
4. **Should release miner binaries have an x86-64-v3 variant?** This is 43's
   reproducibility cost against about 10–30% [assumed].
5. **Batched verification changes `compute_parallel` threading** (fewer threads, K
   headers each). Accept latency-for-throughput for IBD batches only, with a single
   tip header always verified alone?

---

## 8. Sources

**RandomX, reference implementation and specification:**
- tevador/RandomX README (performance table: i9-9900K fast 5,770 H/s at 8T, light
  1,160 H/s at 16T; "portable interpreter, which is much slower"):
  https://github.com/tevador/RandomX/blob/master/README.md
- RandomX design document §6 ("450 instructions, out of which 155 are 64-bit
  multiplications"; the light-mode verification target):
  https://github.com/tevador/RandomX/blob/master/doc/design.md
- RandomX specification (§6 SuperscalarHash, §7.3 dataset item):
  https://github.com/tevador/RandomX/blob/master/doc/specs.md

**Rust toolchain and language:**
- Rust 1.87.0 release notes (safe architecture intrinsics):
  https://blog.rust-lang.org/2025/05/15/Rust-1.87.0/
- The Rust Reference, `target_feature` safety rules and the example "unsafe … even if
  `sse` is enabled by default … or manually enabled as compiler flags":
  https://doc.rust-lang.org/reference/attributes/codegen.html
- `std::simd` docs ("nightly-only experimental API", `portable_simd` #86656):
  https://doc.rust-lang.org/std/simd/index.html
- Tracking issue #86656: https://github.com/rust-lang/rust/issues/86656
- Portable SIMD stabilization canary (third-party CI, 2026-09-14, still waiting):
  https://github.com/omnizip/omnizip-rs/pull/590
- `f64` docs (`mul_add` and `sqrt` precision guarantees; `next_up` stable 1.86):
  https://doc.rust-lang.org/std/primitive.f64.html
- RFC 3514, float semantics (IEEE results for non-NaN operations; no automatic FMA
  contraction; NaN bits non-deterministic):
  https://rust-lang.github.io/rfcs/3514-float-semantics.html
- rustc book, profile-guided optimization:
  https://doc.rust-lang.org/rustc/profile-guided-optimization.html
- Explicit tail calls, tracking issue #112788 (unstable, incomplete):
  https://github.com/rust-lang/rust/issues/112788

**SIMD crates and floating point:**
- S. Davidoff, "Implementing FMA and finding bugs in C and Rust standard libraries"
  (2026-08-20): https://shnatsel.github.io/implementing-fma-finding-bugs-in-std/
- `safe_arch` docs (compile-time `cfg` only; `unsafe` inside):
  https://docs.rs/safe_arch/latest/safe_arch/
- Linebender, "Fearless SIMD v1.0" (2026-09-22):
  https://linebender.org/blog/fearless-simd-1-0/
- pythonspeed, "Using portable SIMD in stable Rust" (pointer only):
  https://pythonspeed.com/articles/simd-stable-rust/

**Dependencies:**
- RustCrypto `aes` 0.9.3 source (ARMv8 runtime detection on Linux and macOS; hazmat
  retained): https://docs.rs/aes/latest/src/aes/lib.rs.html
- Local: `~/.cargo/registry/src/*/aes-0.8.4/src/hazmat.rs:16-47`.

**Memory and large pages:**
- Phoronix, "Glibc 2.35 … Huge Pages" (the `glibc.malloc.hugetlb` tunable), pointing
  to the glibc patch series:
  https://www.phoronix.com/news/Glibc-2.35-Huge-Pages-Madvise ;
  https://sourceware.org/pipermail/libc-alpha/2021-August/130628.html

**Interpreter performance:**
- M. A. Ertl, D. Gregg, "The Structure and Performance of Efficient Interpreters",
  JILP 5 (2003): http://www.jilp.org/vol5/v5paper12.pdf
- E. Rohou, B. N. Swamy, A. Seznec, "Branch Prediction and the Performance of
  Interpreters — Don't Trust Folklore", CGO 2015:
  https://inria.hal.science/hal-01100647

**Internal reports:**
- R9-randomx.md, R12-performance.md, SX1, SX2, full-review-2026-09-27.md,
  autonomous-session-2026-09-27.md (in the repository).
