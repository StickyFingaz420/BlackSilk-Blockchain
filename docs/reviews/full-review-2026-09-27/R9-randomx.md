# R9: RandomX and mining, internal review (2026-09-27)

**Reviewer:** R9. This is an internal review, not an audit.

**Scope:**
- `randomx/src/*`;
- `consensus/src/pow.rs`;
- `consensus/src/difficulty.rs` and `params.rs` (the PoW-related parts);
- `miner/src/{lib,main}.rs`;
- `chain/src/manager.rs` (`CachedPow`, `pow_jobs`);
- `p2p/src/net.rs` (`verify_headers`, the PoW parts only).

**Base:** HEAD `f677e55`, branch `rebuild/core`.

**Method:**
- read-only source review, with no builds or measurements of my own;
- line-by-line comparison of `vm.rs` against the reference `vm_interpreted.cpp`/`bytecode_machine.cpp` semantics (from memory of the reference);
- web research, cited inline and in the Sources section at the end.

**Evidence tags:**
- **[math]**: mathematically established;
- **[test: name]**: tested by the named test;
- **[src]**: source-read;
- **[assumed]**;
- **[unknown]**.

Performance figures not in the brief are **estimates [assumed]**, because I was not allowed to profile.

---

## 0. Executive summary

1. **Correctness is in good shape.**
   - The port matches the reference semantics everywhere I checked by hand [src]:
     - CBRANCH target and imm/mask;
     - IMUL_RCP → NOP for 0 and powers of two;
     - ISWAP with src = dst → NOP, without touching register usage;
     - FSWAP over f and e;
     - the ISTORE L3 condition;
     - the `mx`/`ma` masking order: this is AND-after-XOR, which is equivalent [math];
     - the dataset offset;
     - the rounding-mode reset per hash and its persistence across the 8 programs.
   - It is pinned by the official vectors [test: `hash_1a`–`hash_1e`, `cache_initialization`, `superscalar_generator`, `dataset_items`, `aes_generator_1r`, `reciprocals`] and by full = light agreement [test: `full_mode_matches_light_mode`, CI `randomx-full`].
   - The software rounding emulation is sound for the operand ranges RandomX produces (§3.2) [math/src].
2. **The performance gap is the main risk, and it is a security issue before it is a fairness issue.** Nodes verify in light mode at about 450–750 ms per hash (brief). A JIT miner produces a difficulty-1 header in about 1.4 ms (§4.2). That gives an attacker-to-verifier cost asymmetry of roughly **300–500×** for low-work headers:
   - A low-difficulty fork from the genesis era (no minimum chain work, K4) costs an xmrig-class attacker seconds to mine.
   - It costs every node tens of core-minutes to verify.
   - It can also force **fresh RandomX caches for attacker-chosen seeds**, built under a global mutex, and thrash the 2-entry cache (new finding R9-2).
   - This deepens the known "low-work header batches are hashed and stored" finding. The fix is a policy-only header presync (R9-R1).
3. **Where the time goes [src + assumed]:**
   - **Light mode:** about 59 M interpreted SuperscalarHash ops per hash (16,384 dataset items × 8 programs × ~450 ops), at about 8–12 ns per op.
   - **Full mode:** 4.19 M VM instructions per hash at about 24 ns each (under load). About 2.3 M of those are directed-rounding FP lane-ops done by error-free transforms.
   - Neither is dominated by memory. There are credible safe-Rust gains of about 3–8× for the dataset build and 2–5× for hashing (§4.3).
   - The gap to JIT (≥5–10× even after optimization) is **structural**: JIT needs writable-executable memory, which needs `unsafe`, so it is excluded by policy.
4. **Fairness:** third-party xmrig-derived miners will dominate pure-Rust miners by about 50–100× today. Hardware-level decentralization (commodity CPUs, ASIC resistance) is a property of the *algorithm*, not of our implementation, so it is unaffected. This is an **accepted limitation**, to document honestly. The larger and more permanent risk is **rentable Monero hashrate**: the algorithm is identical to Monero's RandomX v1, and the Qubic episode of August 2025 showed how mobile that hashrate is.
5. **Seed switch:** the full-mode miner stalls for about 3 minutes (8 threads) to 20+ minutes (1 thread) every 2,048 blocks, although the next key is known 64 blocks (~2 h) in advance. The fix is policy-only (R9-R4).
6. **Cross-platform determinism:**
   - The software-FP design is *better* than the reference here: there is no MXCSR/FPCR state and no JIT.
   - Remaining risks:
     - x87 targets (i586) would silently fork;
     - 32-bit targets cannot allocate the dataset;
     - ARM64 uses software AES single rounds unless a cfg flag is set (a performance issue, not a correctness one);
     - there is no ARM64 or big-endian CI (known).
7. **PoW choice:** keep RandomX, spec-conformant with the audited reference. RandomX v2 (merged upstream in February 2026 and planned for Monero's v17 fork) is the only credible successor. It is a consensus change and must not be adopted before the testnet. Equi-X and custom variants are not suitable as the consensus PoW (§7).

---

## 1. What is implemented (answers Q1, Q2)

| Component | Status | Evidence |
|---|---|---|
| Argon2d cache fill (256 MiB, 3 passes, 1 lane, salt `RandomX\x03`, raw memory) | **Complete and verified** | [test: `cache_initialization`] (3 words) |
| Blake2Generator, SuperscalarHash generator (CPU port model), reciprocal | **Complete and verified** | [test: `superscalar_generator`] (10 programs, key 000), [test: `reciprocals`] |
| Dataset item and parallel dataset expansion | **Complete and verified** | [test: `dataset_items`], [test: `full_mode_matches_light_mode`] |
| AesGenerator1R/4R, AesHash1R via `aes::hazmat` | **Complete and verified** | [test: `aes_generator_1r`] directly; 4R and Hash1R only through the end-to-end vectors |
| VM: program generation, bytecode decode, execution, hash chain | **Complete and verified** | [test: `hash_1a`–`hash_1e`], plus 1,024 random inputs where full = light |
| Directed rounding emulation (`fpu.rs`) | **Complete but requires further testing** | 5 unit tests plus the end-to-end vectors; no independent differential test (R9-R6) |
| `RandomXPow` (2-key LRU, light mode) | **Complete but requires further testing** | [test: `randomx_end_to_end`]; no adversarial-seed test (R9-2) |
| Seed schedule (E = 2048, L = 64, seed from the header's own branch) | **Complete and verified** | [test: `seed_schedule_matches_monero`], [test: `seed_is_taken_from_the_headers_own_branch`] |
| `check_hash` (h·d < 2^256, d = 0 invalid) | **Complete and verified** | [test: `check_hash_boundaries`]; the same rule as Monero [src] |
| LWMA-1 (N = 60, solve time capped at 6T, increase ≤ ~10×) | **Complete and verified** (unit level) | [test: `difficulty::tests::*`] |
| Miner: template polling, block build, nonce search, full/light | **Complete but requires further testing** | [test: `found_nonce_verifies_with_consensus`], [test: `stop_flag_and_limit_end_the_search`]; the binary is never run in CI (known) |
| Next-dataset pre-build at the seed switch | **Not implemented** (known) | `miner/src/main.rs:310-319` |
| Header PoW batching (`pow_jobs`, `compute_parallel`, chunked by `pow_threads`) | **Complete but requires further testing** | `p2p/src/net.rs:1053-1083` |

**What is well designed [src]:**
- **Safety and dependencies:**
  - `#![forbid(unsafe_code)]` is set in `randomx` and `miner`;
  - there is no FFI;
  - the only dependencies are RustCrypto `blake2` and `aes`.
- **Consensus constants:**
  - they live in one file (`config.rs`), with a compile-time check that the frequencies sum to 256;
  - the doc comment says they "must never change".
- **The rounding emulation is the right design choice:**
  - Rust and LLVM cannot soundly change the rounding mode;
  - the reference's reliance on MXCSR/FPCR plus JIT has produced real platform bugs. The RandomX v2.0.1 release notes say previous versions "could produce invalid hashes (1 out of ~268 million) on ARM/RISC-V systems" [cite: RandomX releases].
- **One PoW path:** the miner and the node share `check_hash`, the header layout and the crate. This closes the historic P5 mismatch.
- **Verification order:**
  - PoW is computed after the cheap header prechecks, in chunks of `pow_threads`, then accepted;
  - an invalid header is a 100-point penalty, which is an immediate ban (`p2p/src/limits.rs:13`).

---

## 2. Correctness review of the port (Q2, Q4)

I checked each point by hand against the reference [src].

**Program decode:**
- **IADD_RS:** the shift is `(mod>>2)%4`. The displacement applies only to `dst == 5`. Matches.
- **Memory operands:** with `src == dst`, the operand is `imm & L3` with base 0. Otherwise the mask is L1 when `mod%4 != 0`, else L2. Matches.
- **FADD_M/FSUB_M/FDIV_M:** always register-based, with no `src == dst` special case. Matches.
- **IMUL_RCP:** skipped (NOP, register usage untouched) when `imm32` is 0 or a power of two. Matches.
- **CBRANCH:**
  - `shift = (mod>>4)+8`;
  - `imm = sext(imm32) | 1<<shift`, with bit `shift-1` cleared;
  - `mask = 255<<shift`;
  - target = the last-modified-register index (−1 means the program start);
  - all register usages are set to `i`.
  - The executor does `pc = target; pc += 1`, which equals the reference `for (...; ++pc)`. Matches.
- **CFROUND:** `rotr(r[src], imm&63) & 3`. Matches.
- **ISTORE:** L3 when `mod>>4 >= 14`. Matches.

**Iteration loop (`vm.rs:642-690`):**
- The reference masks `mx` right after the XOR. The port masks at use instead: `(self.ma & CACHE_LINE_ALIGN_MASK)`, and `ma` was masked in `initialize`. AND distributes over XOR, and unmasked high bits never reach a masked read, so the two are equivalent [math].
- The dataset read comes before the swap, and the register store and f^e store order match.

**Hash chain:** `fprc` is reset to nearest once per hash and persists across the 8 programs, as in `randomx_calculate_hash` [src].

**Endianness:** every byte↔word conversion is explicit little-endian [src]. That covers argon2d, the VM loads and stores, `register_file` and the AES blocks. I found no host-endian dependence, but it is untested on big-endian (R9-7).

**Panics from untrusted input:**
- `Vm::hash` accepts any input length, and header bytes are a fixed 100 bytes.
- All scratchpad indices are masked to lengths ≤ 2 MiB − 8.
- I found no reachable panic [src].

**Finding R9-1 (info, Complete and verified):** I found no semantic deviation from RandomX v1. Confidence is high, given the vector coverage plus the manual check.

---

## 3. Software floating point and cross-platform determinism (focus 3)

### 3.1 Operand ranges (why the emulation is sufficient) [src + math]

**Register ranges:**
- **f registers** are reloaded each iteration from `i32 → f64` (exact), then change only by ± a-registers and FSCAL. Their magnitude stays ≲ 2^48, and they never become NaN or infinite.
- **e registers** are reloaded each iteration with exponent bits forced to 0x300–0x3FF, so they lie in [2^-255, 1).
- Within one iteration, e registers are updated by:
  - FMUL (×a, a ∈ [1, 2^32));
  - FDIV (÷ a masked e-range value);
  - FSQRT.
- The lower bound: they can never drop below about 2^-255 / 1. Subnormals (< 2^-1022) are therefore unreachable [math].
- The upper bound: they **can** overflow to ±MAX or ±∞ (the README notes vector 1b does this).

**Inf and NaN:**
- ∞·a = ∞, ∞/v = ∞ and √∞ = ∞.
- No FP instruction ever combines two e registers, so ∞ − ∞ and 0·∞ cannot occur.
- **NaN is unreachable** [math/src].

This matters because NaN payload bits are the one IEEE-754 area where platforms differ, WASM included.

### 3.2 Emulation soundness [math]

The emulation rescales operands to exponent 1023 (it keeps the sign bit), then derives the sign of the exact rounding error:

| Operation | How the error sign is computed |
|---|---|
| add | Knuth TwoSum. Exact while `s` is finite. Overflow is handled first; exact-zero sign rules are handled explicitly. |
| mul | Dekker TwoProduct on rescaled operands in [1, 2). No intermediate overflow. |
| div | Remainder `a1 − q1·b1`, exactly representable (Sterbenz + the division remainder theorem). |
| sqrt | Rescaled by an even power of two to [1, 4); the residual is exactly representable. |

**Why the rescaling is safe:**
- Rescaling preserves the rounding decision whenever the unscaled result is normal.
- The unscaled result is always normal here, because §3.1 rules out subnormals.

**Contraction:** Rust never contracts `a*b+c` into FMA, so Dekker is safe at any `-C target-cpu`.

**`f64::sqrt`:** it is correctly rounded on every IEEE target (`llvm.sqrt`).

**`next_up`/`next_down`:** these are pure bit operations (stable since 1.86; the toolchain is pinned to 1.98.1).

### 3.3 Platform risks

| ID | Risk | Severity | Class | Scenario | Confidence |
|---|---|---|---|---|---|
| **R9-3** | **x87 targets.** On `i586-*` (and any x86 build without SSE2), f64 arithmetic runs on the x87 FPU with 80-bit intermediates. Double rounding breaks both the base round-to-nearest result and the TwoSum/Dekker identities, so hashes differ silently. Nothing in the crate prevents such a build (`randomx/src/lib.rs`). | medium (latent) | Not implemented (guard) | Someone runs a node on an old 32-bit distribution or embedded x86. The node rejects valid blocks and accepts nothing: a permanent split for that node, but no network split. | high |
| **R9-4** | **32-bit targets, full mode.** `vec![0u64; 272 M]` is 2.08 GiB, above `isize::MAX` on 32-bit, so `Dataset::new` panics with a capacity overflow (`dataset.rs:533`). wasm32 is also limited to 4 GiB of linear memory. Light mode (256 MiB) works. | low | Accepted limitation (document) | A miner on armv7 or wasm32 with `--light` omitted panics at startup. | high |
| **R9-5** | **ARM64 AES.** `aes 0.8.4` uses ARMv8 intrinsics only with `--cfg aes_armv8`; otherwise it falls back to fixsliced software single rounds (`aes-0.8.4/src/hazmat.rs:16-28`). The results are identical, but it is slow: about 262 k single rounds per hash, estimated +30–100 ms per hash [assumed]. | low (performance) | Complete but requires further testing | Graviton or Apple-silicon nodes and miners are far slower than necessary. | medium |
| **R9-7** | **Big-endian and ARM64 not in CI** (ARM64 is known; big-endian is new). The code looks endian-clean [src], but that is unproven. | low | Not implemented | A future s390x or PowerPC node. | medium |
| — | Reference JIT bug class (ARM/RISC-V invalid hashes) | — | N/A | Not applicable: there is no JIT and no FP state. This is a *strength* of the design. | high |

**Recommendation R9-R5 (guards):**
- Add
  `#[cfg(all(any(target_arch="x86"), not(target_feature="sse2")))] compile_error!("RandomX requires SSE2 f64 arithmetic");`
  to `randomx/src/lib.rs`. Also consider `compile_error!` for 16-bit and 32-bit pointer widths with a documented "light-mode only" path.
- Document `RUSTFLAGS=--cfg aes_armv8` for aarch64 builds, or check whether aes ≥ 0.9 enables it by default [unknown].

| Attribute | Assessment |
|---|---|
| Why needed | Prevents a silent consensus split. |
| Security impact | + |
| Privacy impact | none |
| Performance impact | none |
| Complexity | trivial |
| Consensus impact | none (the build fails instead of producing wrong hashes) |
| Testnet identity | no new identity |
| Difficulty | S |
| Priority | **P2** (the guard); ARM64 AES P3 |

---

## 4. Performance gap (focus 1)

### 4.1 Workload per hash (exact from the constants) [math]

**Full mode, VM instructions:** 8 programs × 2,048 iterations × 256 = **4,194,304**.
- FP share: FADD_R 16 + FADD_M 5 + FSUB_R 16 + FSUB_M 5 + FMUL 32 + FDIV 4 + FSQRT 6 = 84 of 256 opcodes (33%, plus FSWAP and FSCAL).
- That gives about 1.38 M FP instructions, or **2.75 M lane-ops**.
- CFROUND has frequency 1/256, so after about the first iteration the mode is uniformly random. About 75% of lane-ops take the emulated directed path: **about 2.1 M emulated FP ops per hash**.

**Other per-hash work:**
- Dataset reads: 16,384 random 64-byte lines.
- AES single rounds: 131 k (scratchpad fill) + 131 k (AesHash1R) + about 4.4 k (program generation).
- Blake2b: 8 × 256 B + 1 × 100 B.

**Light mode:** each of the 16,384 dataset reads becomes `dataset_item`: 8 SuperscalarHash programs (≈ 450 instructions each; `SUPERSCALAR_MAX_SIZE` = 512) plus 8 random cache-line reads. That is **about 59 M interpreted superscalar ops per hash**.

**Dataset build:** 34.1 M items × 8 programs × ~450 ≈ **1.2 × 10^11 superscalar ops**.

### 4.2 Measured versus implied cost per operation

| Mode | Measured (brief/README) | Implied cost | Reference (cited) |
|---|---|---|---|
| Full hash | ~100 ms/hash/thread (under load) | ~24 ns per VM instruction | i9-9900K fast mode 5,770 H/s with 8 threads, about **1.4 ms/hash/thread**, JIT [cite: tevador/RandomX README] |
| Light hash | 450 ms (README, idle) to 750 ms (under load) | ~8–13 ns per superscalar op | light mode with JIT is roughly 10–20 ms [assumed] |
| Dataset | 133 s (README) to 179 s (8 threads, loaded) | ~9–12 ns per superscalar op·thread | seconds with JIT on 8 threads [assumed] |

**Interpretation [src + assumed]:** in light mode and in the dataset build, the time goes entirely into the superscalar interpreter. In full mode it splits into two parts:
- **Directed-rounding emulation.** My estimate is ~5–15 ns per emulated lane-op × 2.1 M ≈ **10–30 ms per hash**. Each directed `mul` or `div` costs:
  - 2 splits (4 flops);
  - a TwoProduct (7 flops);
  - rescale bit-ops;
  - 3–4 predicate checks (`is_normal`, `is_infinite`, mode);
  - a data-dependent branch in `correct` (mispredicted about 50% of the time).
- **Interpreter overhead:**
  - **Dispatch.** A 29-arm `match` on a ~40-byte `Op` with `usize` fields. The branch predictor sees a 256-long pattern repeated 2,048 times, so this is partly learnable, as in the reference interpreter.
  - **Bounds checks.** They cannot be elided:
    - `self.r[dst]` with `dst: usize`;
    - `ops[pc]`;
    - two slice checks per scratchpad access on `Vec<u8>`;
    - byte assembly of words through `try_into().unwrap()`.

Memory is **not** the bottleneck today: 16,384 DRAM misses × ~80 ns ≈ 1.3 ms. It becomes relevant only once hashing is below about 10 ms.

**Allocation is negligible [src]:**
- one 2 MiB zeroed scratchpad per `Vm` (per `pow_hash` call in the node, and per search call in the miner);
- one `Vec<Op>` per program.

### 4.3 Safe-Rust optimizations (no `unsafe`, no JIT, stable toolchain)

The ordering is by expected gain per effort. Gains are **[assumed]**; profiling must come first.

| # | Optimization | Where | Expected gain | Consensus impact |
|---|---|---|---|---|
| O0 | **Profile first.** Use `samply` (works on Windows and Linux) or `perf` on the `bench` example, extended with full-mode and dataset benches. Pin the numbers in the README. | — | enables everything else | none |
| O1 | **SoA-batched dataset build.** SuperscalarHash programs are identical for every item; only register values differ. Interpret each instruction once over `N` items (`[[u64; N]; 8]`, N = 4–16). This amortizes dispatch N×. add/sub/xor/rotate auto-vectorize; mul/mulh get ILP. | `dataset.rs`, `superscalar.rs` | dataset build **3–8×** (179 s → ~25–60 s) | none (the vector tests cover it) |
| O2 | **Superscalar decode tightening.** Pre-decode to a compact struct with `u8` registers indexed as `r[(d & 7) as usize]` (LLVM removes the check), a pre-sign-extended `u64` imm, a `u32` rotate and a precomputed reciprocal. Split `ImulRcp` into `ImulR` with an immediate. Order match arms by frequency. | `superscalar.rs:119-142` | light mode 1.3–2× | none |
| O3 | **Scratchpad as `Box<[u64; 262144]>` (or `Vec<u64>`) with index `addr >> 3`.** All 64-bit accesses are 8-aligned, because every mask is a multiple of 8. `load_f` becomes a split of one u64, and masking bounds the index so checks vanish. Registers become `r[x & 7]`. | `vm.rs:529, 603-618` | full 1.2–1.5× | none |
| O4 | **FPU fast paths.** (a) Compile-time `#[cfg(target_feature = "fma")]`: the exact product error `e = a.mul_add(b, -p)` (one op, exact, deterministic) replaces the splits, with Dekker as the fallback. Never use a runtime-dispatched `mul_add`: without hardware FMA it calls the platform libm (a C runtime dependency, slow, and historically buggy on some CRTs). (b) Branch-light `correct` via `to_bits` ± 1 arithmetic selected by masks. (c) Process both lanes as `[f64; 2]` in one function so LLVM can emit SSE2/NEON 2-lane code. (d) Hoist the `mode == Nearest` check out per instruction. | `fpu.rs` | full 1.3–2× | none, but it touches consensus-critical code, so it needs R9-R6 first |
| O5 | **Pre-decoded handler table.** For example, specialize ops by `Src::Reg`/`Src::Imm` and by mask kind into separate variants to shrink per-op work. A `Vec<fn(&mut State, &Op)>` is another option, but it is usually *not* faster than a dense `match` in Rust; measure it. | `vm.rs:274-498, 692-871` | 1.1–1.5× | none |
| O6 | **Software prefetch without intrinsics.** After computing the next `mx`, issue an early ordinary load of the next dataset line into a local that is used later (the OoO core overlaps the miss). | `vm.rs:669-675` | ≤ 1.3 ms/hash (matters only after O1–O5) | none |
| O7 | **Node full-mode verification (optional).** When the node has ≥ 2.5 GiB free, build a dataset for the current seed in the background and use light mode until it is ready. | `consensus/src/pow.rs` | verification 5–7× faster | policy |
| — | *Not possible under policy:* JIT (needs W^X page mapping, which is `unsafe` plus OS FFI), large pages (FFI), explicit `_mm_prefetch`/MXCSR (`unsafe`). `std::simd` is nightly-only, so it is not usable on the pinned stable toolchain. | | | |

**Realistic ceiling [assumed]:** O1–O6 together might reach about 10–25 ms per full hash and 100–200 ms per light hash. That is interpreter class: about 5–15× slower than JIT. **The gap cannot be closed in safe Rust.**

**Recommendation R9-R2 (performance programme O0–O6):**

| Attribute | Assessment |
|---|---|
| Why needed | Verification cost (DoS, sync time) and honest-miner competitiveness. |
| Security impact | + (reduces the asymmetry in §5) |
| Privacy impact | none |
| Performance impact | large + |
| Complexity | medium; each change must keep all vectors green, plus R9-R6 before touching `fpu.rs` |
| Consensus impact | none (the hash output is unchanged) |
| Testnet identity | no new identity |
| Difficulty | M (O1–O3), M (O4) |
| Priority | **P2** for O0/O1/O2 before the testnet (O1 cuts the seed-switch stall; O2 cuts verification cost); O3–O7 **P3** |

### 4.4 What the gap means (fairness, decentralization, ASIC resistance)

- **ASIC resistance is unaffected.** It comes from the algorithm (a random program, 2 GiB of memory, FP, branches, AES), not from any implementation. Implementation speed never changes the ASIC-to-CPU ratio [src/design].
- **Hardware decentralization is unaffected.** Any commodity CPU can run a free, open JIT miner. xmrig mines RandomX v1 with a custom seed. Correction (2026-10-04, output-root): the nonce offset is compiled into xmrig per algorithm (byte 39, 4 bytes, for RandomX), so no adapter could move it; v3 therefore hashes a 47-byte mining blob with the nonce at byte 39 (docs/consensus.md §3), and a pool needs only an algorithm entry with the BlackSilk salt.
- **Software fairness is affected.** An operator who uses the project's own miner gets about 1–2% of the blocks that the same hardware earns with a JIT miner. In practice:
  - rational miners will run third-party C/C++ miners on BlackSilk;
  - the "pure-Rust" property then holds for *verification* (nodes), but not for the mining economy.

  This is acceptable **if documented**. The node, which is the trust anchor, stays pure Rust; mining software is untrusted by design, because PoW verification does not trust the miner. It is *not* acceptable to market the bundled miner as competitive.
- **Security margin is unaffected.** It depends on the total honest hashrate. If most honest hashrate runs JIT miners anyway, the margin is the same as with any RandomX coin of equal hashrate.
- **Rentable hashrate is the real risk** (Accepted limitation, high, owner decision before mainnet):
  - Using *unmodified* RandomX v1 means any Monero pool, NiceHash-style marketplace or botnet can point a small fraction of Monero's hashrate at BlackSilk.
  - The Qubic episode (August 2025) showed how mobile that hashrate is: 6-block reorgs on Monero itself at an estimated 28–35% hashrate share, using selfish mining [cite: CoinDesk, Halborn].
  - A small RandomX chain is far more exposed.
  - Tweaking parameters (salt, sizes) does not help: xmrig adds variants in hours, and a tweak forfeits the reference audits.
  - Options: merge-mining with Monero (Tari's model) or finality/checkpoint policies. Both are large decisions that conflict with K4.
  - For the testnet: accept it.

---

## 5. Security findings: PoW verification cost as a DoS lever

### R9-2: fake-seed cache builds under a global lock and cache thrash
- **Severity:** medium.
- **Class:** Partially implemented (mitigation missing).
- **Where:** `consensus/src/pow.rs:55-70`, `chain/src/manager.rs:590-614`, `p2p/src/net.rs:1053-1083`.
- **Confidence:** medium-high [src].

**Preconditions (the known K4 gap and no minimum chain work):**
- A branch may fork from any height, including the genesis era, where difficulty can fall to ~1. The attacker spaces timestamps over the real elapsed time; LWMA caps each solve time at 6T, but the elapsed time since genesis is large.
- Testnet initial difficulty is 100 (`params.rs:61`), so a JIT attacker mines such a branch in seconds.

**Attack:**
1. The attacker mines ≥ 2,113 low-difficulty headers from near genesis. The branch crosses a seed boundary at a seed block the attacker chose, which has valid low-difficulty PoW.
2. Every node verifies all of them. At 450–750 ms per light hash that costs about 16–26 core-minutes per 2,113 headers, against about 3 s of attacker JIT time. That is the **~300–500× asymmetry**.
3. Each crossed epoch forces `Cache::new(attacker_seed)`: 256 MiB plus about 0.6–1 s single-threaded, **while holding `RandomXPow::caches`'s mutex**, which stalls every other PoW check including tip blocks.
4. The capacity-2 LRU then evicts the honest current and previous seeds, so the next honest block pays another cache build.
5. The headers are stored permanently (known).
6. The per-IP ban does not help:
   - the headers are *valid*;
   - with exact-IP bans (N-5), a different address repeats the attack with a new branch.

**What is already bounded:** because PoW runs in chunks of `pow_threads` before `accept_headers`, a seed header with *invalid* PoW cannot key later headers unless `pow_threads > 65` [src]. So the attacker must mine the seed block, which is cheap at difficulty ~1.

**Fix R9-R1:**
- **Header presync** (Bitcoin Core 24 "headers presync", PR #25717):
  - For a branch that does not extend our best chain, first run only the cheap checks (`precheck_headers`, which already verifies difficulty fields and timestamps without PoW).
  - Sum the *claimed* work from the difficulty fields.
  - Keep only a bounded per-peer commitment or ring.
  - Compute RandomX **only once the claimed cumulative work exceeds our best chain's work** (or a minimum-chain-work constant).
  - Then re-download and verify in order.
  - The first invalid PoW means a ban.
  - An attacker must then really out-work the honest chain before it costs us more than one chunk.
- Also:
  - build caches **outside** the lock, with a per-seed `OnceLock` or in-flight map so duplicate builds are still avoided;
  - raise capacity to 3 and pin the active-tip seed so a side-branch seed cannot evict it.

| Attribute | Assessment |
|---|---|
| Why needed | The single largest DoS amplification in the PoW path. |
| Security impact | high + |
| Privacy impact | none |
| Performance impact | + (no wasted RandomX) |
| Complexity | medium |
| Consensus impact | **none** (policy: the acceptance order changes, the rules do not) |
| Testnet identity | no new identity |
| Difficulty | M |
| Priority | **P1**; coordinate with A8's "low-work header batches" item |

### R9-6: `CachedPow::known` is unbounded
- **Severity:** low.
- **Class:** Partially implemented.
- **Where:** `chain/src/manager.rs:35-102`.
- **Confidence:** high [src].

**Problem:**
- Every computed PoW hash is inserted permanently: accepted, side-branch and *failed* (below-target) headers alike.
- Legitimate growth is ~26 MB/year (262,800 headers × ~100 B).
- Adversarial growth is bounded by node CPU: at 8 cores and ~0.5 s per hash, about 16 entries/s, ≈ 140 MB/day of sustained attack.
- **Fix:** insert failed hashes only into a small bounded LRU, and drop entries for headers marked invalid.
- **Assessment:** policy; no identity change; S; P2.

### R9-8: per-block verification latency and sync cost [assumed from measured numbers]
- **Severity:** low for the testnet, medium for mainnet.
- **Class:** Accepted limitation (testnet).

**Per-block latency:**
- Each relay hop verifies before forwarding: 0.5–0.75 s × ~4–6 hops ≈ 2–4 s of added propagation per block.
- At T = 120 s that means about 2–3% more stale blocks.
- It also mildly favours large, well-connected miners, which is a centralization pressure.

**Initial sync:**
- 262,800 headers/year × 0.5 s ≈ **36 CPU-hours per chain-year**, about 4.6 h on 8 threads.
- After 5 years: about 23 h per new node.
- Monero avoids this with fast-sync checkpoints, which K4 rejects.

**Mitigations:** R9-R2 O2 and O7 (all policy-only). A signed or embedded "assume-valid PoW" hash is a K4 decision for the owner.

**Priority:** P3 for the testnet, P1 before mainnet.

---

## 6. Mining system (focus 2 and miner review)

### 6.1 Seed switch (`miner/src/main.rs:309-319`)

**What happens:**
- The miner learns the seed from the template.
- When it changes, it drops the old dataset first, then builds the cache and dataset synchronously, and mines nothing meanwhile.

**Cost per switch:**
- about 179 s on 8 threads (measured, under load);
- about 20 min on 1 thread;
- after O1, an estimated 25–60 s.

**Frequency:** every 2,048 blocks, about 68 h at 120 s blocks.

**Direct loss:**
- 0.07% of the time at 8 threads;
- about 0.5% at 1 thread.

**Systemic effect:** every pure-Rust full-mode miner stalls at the **same** height, H = S + 65.
- The network's pure-Rust hashrate drops to about zero for ~3 minutes.
- LWMA-60 barely reacts: it is 1–2 slow blocks. It is harmless for consensus.
- But it is a predictable window in which a JIT or prebuilt miner (xmrig builds datasets in seconds) finds the block almost surely. A minor fairness leak [assumed].

**No pre-build, although the key is known 64 blocks (~2 h) ahead:** the seed block S = k·2048 is fixed once the tip passes S, and it is used from S + 65.

**Recommendation R9-R4:**
- **Node side:** add `next_seed_id` (and its activation height) to `/template` once the tip is at or above S.
- **Miner side:** build the next `Cache` + `Dataset` in a background thread with 1–2 threads (or `threads/4`) while mining continues. Swap atomically at activation, keeping the old context until then.
- **Memory:** the peak is 2 × 2.08 GiB + 256 MiB ≈ 4.4 GiB. Add a `--no-prebuild` flag and an automatic fallback when memory is short.
- **Node verifier:** pre-build the next light cache (0.6 s) the same way, which removes the lock-held build on the first block of each epoch.

| Attribute | Assessment |
|---|---|
| Why needed | Removes the stall; also useful for R9-2. |
| Security impact | neutral / + |
| Privacy impact | none |
| Performance impact | + |
| Complexity | low-medium |
| Consensus impact | none (RPC field and policy) |
| Testnet identity | no new identity |
| Difficulty | S–M |
| Priority | **P2** (known issue, deepened); also test with the real epoch on regtest at 10 s blocks, which is 5.7 h |

### 6.2 Other miner findings [src]

| ID | Finding | Severity | Class | Location | Recommendation |
|---|---|---|---|---|---|
| R9-9 | **Stale work.** The template is refreshed only every `--refresh` = 15 s. When another miner finds a block, this miner keeps hashing on a stale parent for 7.5 s on average: about **6% wasted hashrate**, and occasional rejected blocks. | low | Complete but requires further testing | `main.rs:245-247, 323-335` | Poll the tip cheaply (`/info`) every 1–2 s, or add a long-poll `/template?since=`. Policy; S; P2. |
| R9-10 | **Header timestamp is fixed per template.** Fine at a 15 s refresh; a long refresh would drift. No consensus risk: MTP/FTL are checked by the node. | info | Complete and verified | `lib.rs:58` | none |
| R9-11 | **Nonce search.** Thread t tries `start + i·threads + t`, and the random 64-bit start persists across templates. Collisions are irrelevant because tx_root and timestamp change. `stop` is checked every hash (~100 ms latency). Correct. | info | Complete and verified [test: `stop_flag_and_limit_end_the_search`] | `lib.rs:114-159` | none |
| R9-12 | **Two miners, one address.** Correct. Shared RNG seeding and the hedge are fine. The coinbase hedge is outside R9 scope (see crypto: HedgedRng coinbase context not yet reviewed, known). | info | — | `main.rs:290-296` | — |
| R9-13 | **Found block on a stale template is submitted anyway.** Harmless: the node rejects or orphans it. | info | — | `main.rs:348-365` | — |
| R9-14 | **Miner never verifies the node's `difficulty`/`seed_id`.** A malicious or compromised node can make the miner waste work. This is inherent to local-node mining; document "only mine against your own node". | info | Accepted limitation | `main.rs:301-321` | document |

### 6.3 Difficulty interplay [src]

- `check_hash` equals Monero's rule, and u64 difficulty is ample.
- LWMA-1 with N = 60:
  - solve time capped at 6T;
  - monotone timestamp handling;
  - per-step increase bounded by the `n²T/20` floor, about 10× per window, and ≤ 20× at n = 1 in the early chain.
- **Testnet start:** initial difficulty 100 against pure-Rust hashrate.
  - Full mode: ~10 H/s per thread, so 8 threads give ~80 H/s.
  - The equilibrium D at T = 120 is about 9,600.
  - The first blocks arrive in ~1 s, and LWMA's early short window ramps in a few dozen blocks. Harmless.
  - **But** a single xmrig-class participant at ~1,000+ H/s per core would own the testnet. Expect it and plan the trial for it.
- **Genesis-era fork (see R9-2):** difficulty collapses to 1 because solve times up to 6T per block let LWMA fall by up to 6× per window. This is correct LWMA behaviour, and it is why presync or minimum chain work matter.

---

## 7. Should the PoW or its parameters change? (focus 4)

| Option | Assessment | Recommendation |
|---|---|---|
| **Keep RandomX v1 (current)** | Audited reference design (Trail of Bits, X41, Kudelski, QuarksLab, 2019). Vectors match. Largest review surface in the ecosystem. Downside: shares hashrate with Monero (rental risk). | **Keep it for the testnet.** Never change it silently. |
| **RandomX v2** (tevador PR #317, merged 2026-02-17; release v2.0; planned for Monero hard fork v17, PR #10038, still open as of September 2026) [cite] | Changes: program 256 → 384 instructions; CFROUND fires 16× less often; F/E mixing through 16 AES rounds instead of XOR; dataset prefetch 2 iterations ahead; plus a "commitment" API (`randomx_calculate_commitment(input, hash)`). The goal is tighter CPU fit. For us: about +53% work per hash (worse for our interpreter), a new AES path, new vectors, and fresh upstream code that the Monero hard fork has not yet exercised. | **Defer (P3).** Decide before mainnet. Adopt only after Monero activates v2 and the official v2 vectors are stable. It is a CONSENSUS change and needs a new identity. |
| **Parameter tweak** (own salt or sizes, Wownero-style) | Does not stop rental (miners patch in hours). Loses reference audits and vectors. Adds consensus risk. | **Reject.** |
| **Equi-X / HashX** (Tor proposal 327; pure-Rust implementation exists in Arti) | Client puzzle: 1.8 MiB of memory, ~50 µs verification, 16-byte solutions [cite: tevador/equix]. It is not memory-hard at the RandomX level and not designed for ASIC resistance as a consensus PoW. | **Reject for consensus.** *Innovation (P3):* use it as a **P2P admission or anti-DoS puzzle** (inbound connections, unsolicited headers or blocks, tx relay under load), the way Tor uses it for onion services. |
| **"Commitment" pre-check** | In v2, `commitment = f(input, hash)` [cite: randomx.h]. **[assumed]** usefulness for cheap pre-filtering of headers is unverified: a commitment compared against the target can be ground cheaply unless the hash is recomputed. It does not solve R9-2; presync does. | Do not rely on it. |
| **Merge mining with Monero** | Shares Monero's security, but brings Monero-format aux headers, coupling, and privacy and metadata implications for miners. | Owner decision before mainnet (P3). |

### What must never change (Q13)
Changing any of the following adds consensus risk without enough benefit:
1. **Algorithm conformance to an audited reference.**
   - The `config.rs` constants;
   - the instruction semantics;
   - the Argon2d, AES and Blake2b constants.
   - Any change must be a deliberate, versioned switch to an upstream spec (v2), never a local tweak or "optimization" that changes output.
2. **The software rounding emulation as the only FP path.** Never switch to hardware rounding-mode control (MXCSR/FPCR), which needs `unsafe` and is unsound under LLVM. Never introduce FMA-contracted formulas that are not proven exact (an exact-error `mul_add` under `cfg(target_feature)` is fine; see O4).
3. **The key schedule semantics:**
   - E = 2048, L = 64;
   - the seed is the id of the block at `seed_height` **on the header's own branch**;
   - `seed_height = 0` (genesis id) for H ≤ E + L.
4. **The PoW input:** the full 100-byte header, with nonce at offset 92. Verification is RandomX light or full, which are equal.
5. **`check_hash`:** h·d < 2^256, and d = 0 is invalid.
6. **Verification order:** cheap checks first, then PoW, then the body.
7. **No wall-clock or timing-based PoW judgement** (the historic P6/P7 must never return).

---

## 8. Testing gaps and recommendations

**R9-R6: independent differential tests for `fpu.rs` (P1 before any O4 change, P2 otherwise).** The official vectors exercise the emulation only indirectly.

*Tests to add:*
- **Randomized FPU tests** (millions of cases, in-range and edge operands: overflow boundary, exact ties, zeros of both signs, ∞) comparing `fpu::{add, sub, mul, div, sqrt}` in all 4 modes against an **independent pure-Rust softfloat**, for example `rustc_apfloat` (used by rustc; supports all IEEE rounding modes) as a dev-dependency.
- **Mined corpus of real-world vectors:** Monero mainnet blocks give thousands of RandomX v1 (seed, blob, pow_hash) triples with the same algorithm. A dev-only, offline-generated corpus file of about 1,000 triples across many seeds would multiply coverage of real program diversity by orders of magnitude. Do not fetch at test time.

*Per-change assessment:*
- 4 AesGenerator4R/AesHash1R direct vectors: the reference `tests.cpp` has them.
- Why needed: the emulation is the most subtle consensus code in the crate.
- Security +, privacy none, performance none, consensus none, no new identity.
- S–M.

**R9-R7: CI matrix and other tests.**
- Add `aarch64-unknown-linux-gnu` (native ARM runner) running the vectors plus the full = light test.
- Add a big-endian cross test (`s390x` under QEMU, light vectors only).
- Add `wasm32-wasip1` light vectors under wasmtime.
- Add the x87 guard (R9-R5).
- Add a real-epoch seed-switch test on regtest (10 s blocks × 2,113 ≈ 5.9 h; nightly).
- Add an adversarial-seed test for `RandomXPow`: a concurrent build must not block a cached key once fixed.
- Assessment: known, deepened; policy; P2.

**R9-R3: benchmarks as CI artifacts.**
- Extend `examples/bench.rs` to full mode and the dataset build.
- Record numbers per release, so that performance claims in docs are evidence-backed.
- Assessment: P2, S.

---

## 9. Answers to the 13 questions (condensed)

1. **Implemented:** the full spec-conformant RandomX v1 (cache, superscalar, dataset, VM, AES, software FPU), `RandomXPow`, seed schedule, `check_hash`, LWMA, and a miner with full/light modes. See §1.
2. **Correct and well designed:** everything verified against vectors; semantics hand-checked; the software FP design is sound and more portable than the reference; one shared PoW path; cheap-first verification.
3. **Incomplete:** next-dataset pre-build; header presync or minimum work; FPU differential tests; ARM64/big-endian/wasm CI.
4. **Fragile:**
   - x87 builds (R9-3);
   - the cache build held under the global lock (R9-2);
   - future FPU optimizations without differential tests (R9-R6).
5. **Exploitable:**
   - the low-work fork verification asymmetry, ~300–500× (R9-2, deepening the known issue);
   - fake-seed cache thrash (R9-2);
   - unbounded `CachedPow` (R9-6);
   - rentable Monero hashrate (§4.4).
6. **Inefficient:**
   - the interpreter: ~24 ns per VM instruction, ~10 ns per superscalar op;
   - directed-FP emulation;
   - unbatched dataset build;
   - soft AES on ARM64;
   - the 15 s template refresh (6% stale).
7. **Does not scale:**
   - initial sync at ~36 CPU-hours per chain-year;
   - verification latency per hop;
   - the dataset build at low thread counts.
8. **Missing:** header presync; `next_seed_id` in the template; a tip-change notification to the miner; benchmarks in CI; target guards.
9. **Redesign:**
   - `RandomXPow`: build outside the lock, pin the tip seed, capacity 3;
   - batched superscalar execution;
   - a node full-mode option.
10. **Innovate:**
    - SoA-batched dataset expansion (O1);
    - an Equi-X P2P admission puzzle;
    - a Monero-block-derived vector corpus;
    - an exact-error FMA path under `cfg`.
11. **Before the testnet:**
    - R9-R1 presync or minimum work, P1 (coordinate with A8);
    - R9-R5 x87 guard, P2;
    - R9-R4 pre-build, P2;
    - R9-R6 FPU differential tests, P2 (P1 if O4 lands);
    - R9-R2 O0–O2, P2;
    - R9-9 stale-work polling, P2;
    - document the JIT-miner reality and rental risk honestly (docs; no claims of "fair mining" or "competitive miner").
12. **Can be deferred:** O3–O7; RandomX v2; merge mining; Equi-X admission; big-endian CI; ARM64 AES cfg.
13. **Never change:** see §7.

---

## 10. Recommendation index

| ID | Title | Priority | Consensus impact | New identity? | Difficulty |
|---|---|---|---|---|---|
| R9-R1 | Header presync (claimed-work gate before RandomX); cache build outside the lock; pin the tip seed | **P1** | none (policy) | no | M |
| R9-R2 | Safe-Rust performance programme O0–O7 | P2 (O0–O2) / P3 | none | no | M |
| R9-R3 | Benchmarks in CI, numbers in docs | P2 | none | no | S |
| R9-R4 | `next_seed_id` in the template; background pre-build in miner and node | P2 | none | no | S–M |
| R9-R5 | `compile_error!` on x86 without SSE2; document 32-bit light-only and the ARM64 AES cfg | P2 | none | no | S |
| R9-R6 | FPU differential tests (`rustc_apfloat`), Monero-derived vector corpus, direct AES 4R/Hash vectors | P2 (P1 before O4) | none | no | S–M |
| R9-R7 | ARM64/big-endian/wasm CI; real-epoch switch test; adversarial-seed test | P2 | none | no | M |
| R9-6 | Bound `CachedPow::known` | P2 | none | no | S |
| R9-9 | 1–2 s tip polling or long-poll in the miner | P2 | none | no | S |
| — | RandomX v2 decision | P3 (before mainnet) | **CONSENSUS** | **yes** | L |
| — | Rental-hashrate strategy (merge mining / finality) | P3 (before mainnet) | CONSENSUS (likely) | yes | XL |

## Sources
- [tevador/RandomX README](https://github.com/tevador/RandomX): fast-mode hashrates (i9-9900K 5,770 H/s with 8 threads); JIT only for x86-64/ARM64/RISCV64; "portable interpreter, which is much slower".
- [tevador/RandomX releases](https://github.com/tevador/RandomX/releases): v2.0; v2.0.1 "invalid hashes (1 out of ~268 million) on ARM/RISC-V".
- [tevador/RandomX PR #317 (RandomX v2)](https://github.com/tevador/RandomX/pull/317): program 384, CFROUND 16× rarer, AES F/E mixing, prefetch 2 ahead.
- [tevador/RandomX randomx.h](https://github.com/tevador/RandomX/blob/master/src/randomx.h): `RANDOMX_FLAG_V2`, `randomx_calculate_commitment`.
- [monero-project/monero PR #10038](https://github.com/monero-project/monero/pull/10038): RandomX V2 and commitments for v17 (open).
- [tevador/equix](https://github.com/tevador/equix): Equi-X, 1.8 MiB, ~50 µs verification.
- Tor proposal 327 (PoW over introduction circuits): https://spec.torproject.org/proposals/327-pow-over-intro.html
- Bitcoin Core PR #25717 (headers presync / anti-DoS headers sync): https://github.com/bitcoin/bitcoin/pull/25717
- [CoinDesk: Qubic and Monero, 2025-08-12](https://www.coindesk.com/business/2025/08/12/monero-s-51-attack-problem-inside-qubic-s-controversial-network-takeover); [Halborn explainer](https://www.halborn.com/blog/post/explained-the-monero-51-percent-attack-august-2025)
- Local source: `aes-0.8.4/src/hazmat.rs:16-28` (ARMv8 intrinsics only with `cfg(aes_armv8)`).
