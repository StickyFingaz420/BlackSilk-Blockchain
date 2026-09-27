# 05 randomx-conformance: research dossier (phase 2, phase 1)

**Specialist:** 05 randomx-conformance. This is internal engineering research, not an audit.
**Repository:** `rebuild/core` at **`9e422d8`** (`git rev-parse --short HEAD`). The
`randomx/` crate is unchanged since `249d4f0`. Since R9's base `f677e55`, the only change
is the SSE2 guard in `lib.rs` (`8097f66`, +5 lines).
**Reference studied:** tevador/RandomX `master` at **`7607fb2`** (this is now the v2
code base, with v1 selected by flags), the release notes for v1.2.1–v1.2.3 and v2.0/v2.0.1,
and `doc/specs.md`, `doc/design.md` and `doc/configuration.md` at the same commit.
**Method:**
- read-only;
- no builds and no tests run;
- a line-by-line comparison of the port against the *actual* reference source, which I
  downloaded (R9 compared "from memory of the reference");
- web research from primary sources (§8).

**Evidence tags:**
- **[math]**: mathematically established;
- **[test: name]**: shown by the named test;
- **[src]**: source-read;
- **[ref-src]**: read in the reference source at `7607fb2`;
- **[assumed]**;
- **[unknown]**.

---

## 1. Scope and what I read

**BlackSilk code (all of it):**
- `randomx/src/{lib,config,vm,fpu,superscalar,dataset,argon2d,aes_gen,hash}.rs`
  (2,833 lines);
- `randomx/examples/bench.rs`, `randomx/README.md`, `randomx/Cargo.toml`.
- There is **no `randomx/tests/` directory**. All tests are in-crate `#[cfg(test)]`
  modules (`lib.rs:53-296`, `fpu.rs:162-266`).
- Consumers: `consensus/src/pow.rs`, `consensus/tests/randomx_end_to_end.rs`, the
  RandomX part of `chain/tests/manager.rs` (lines 1099-1260), and `miner/src/lib.rs:80-105`.
- `.github/workflows/ci.yml`: the `test`, `overflow`, `randomx-full` and `guests`
  (Windows vector step) jobs.

**Reviews and docs:**
- `docs/reviews/full-review-2026-09-27.md` (§3.2, the register rows for R9-*/T-8,
  P1-14, and the never-change list item 3);
- `docs/reviews/autonomous-session-2026-09-27.md` (§1, §7);
- `full-review-2026-09-27/R9-randomx.md` (all);
- `SX1-core-crossreview.md` and `SX2-systems-crossreview.md` (the R9 and T-8 rows);
- `R13-testing-supplychain.md` (T-8);
- `R1-consensus.md` (R1-C2);
- `docs/consensus.md` (§3, §9);
- `docs/reviews/dependency-review.md`.

**Roster and neighbour dossiers:**
- my roster entry (05) and the neighbouring entries 06, 07, 08, 09, 41, 42, 43, 44, 45
  and 47;
- the already-written dossiers `research/06-randomx-performance.md`,
  `07-randomx-cache-seed.md` and `08-randomx-determinism.md`, read to avoid overlap.

**Reference files read in full or in the relevant parts:**
- `superscalar.cpp` (generator, scheduler, executor), `bytecode_machine.cpp`/`.hpp`
  (decode and execute);
- `vm_interpreted.cpp` (iteration loop), `virtual_machine.cpp` (`initialize`,
  `getFinalResult`), `randomx.cpp` (`randomx_calculate_hash`);
- `aes_hash.cpp`, `blake2_generator.cpp`, `reciprocal.c`, `dataset.cpp`,
  `argon2_core.c`, `instruction.hpp`, `configuration.h`;
- `tests/tests.cpp` (all 105 `runTest` cases).

**Third-party source:** `aes-0.8.4/src/hazmat.rs`, from the local registry.

---

## 2. Current state

### 2.1 Conformance of the port, re-checked against the real reference

Every row below was compared against the reference code at `7607fb2`, **not from
memory**. No semantic deviation was found. Where R9 made the same claim, it is now
**[ref-src]** instead of "hand-checked from memory".

| Component | Result | Evidence |
|---|---|---|
| Argon2d fill: H0 field order (p, T=0, m, t, v=0x13, y=0, len‖key, len‖salt, 0, 0); first two blocks via H′; `index_alpha` (pass/slice areas, `J1²>>32`, start position); `fill_block` rows then columns, `fBlaMka`, rotations 32/24/16/63; XOR-in from pass 1; `prev_offset` wrap | matches RFC 9106 and `argon2_core.c` | [ref-src] `argon2d.rs:18-231`; [test: `cache_initialization`] (3 words of 33.5 M) |
| H′ (`blake2b_long`) for 1024 bytes: V1…V30 at 32 B, then V31 at 64 B | matches RFC 9106 §3.3 | [math] `hash.rs:27-46` |
| Blake2Generator: seed truncated to 60 bytes, LE32 nonce at [60..64], rehash when `index+n > 64` | matches | [ref-src] `superscalar.rs:12-46` |
| `randomx_reciprocal` (the post-#284 optimized form) | matches; no overflow for u32 divisors that are not 0 or powers of two [math] | [test: `reciprocals`] (7 values) |
| SuperscalarHash generator: decoder buffers and their indices; `fetchNext` priority; slot tables; `create` including the carried-over `opGroupPar_`; `selectSource` r5 rule; `selectDestination` 5 conditions; `scheduleUop` P5→P0→P1; `scheduleMop` dependent/eliminated/two-uop; throw-away and abort (`Null`) paths; `cycle` not reset after a throw-away; ASIC-latency address register | matches statement for statement, including the uninitialized-but-zero `Null` fields (`superscalar.rs:341-354`) | [ref-src] `superscalar.rs:287-763` vs `superscalar.cpp:180-828`; [test: `superscalar_generator`] (10 programs, 1 key) |
| Superscalar executor (IROR_C imm 1..63, sign-extended C7/C8/C9, mulh/smulh, reciprocal) | matches | [ref-src] |
| Dataset item (`(n+1)·mul0`, `r[0]^add[i]`, mix-block index `reg & (lines-1)`, 8 programs, address register) | matches | [ref-src] `dataset.rs:58-75`; [test: `dataset_items`] (word 0 of 4 items) |
| AES generators and hash: keys, dec/enc lane pattern, 4R key schedule (k0,k4)…(k3,k7), Hash1R xkeys, state write-back of the 1R generator | matches | [ref-src] `aes_gen.rs` vs `aes_hash.cpp:46-286`; [test: `aes_generator_1r`]; 4R and Hash1R only end to end |
| VM `initialize` (a-registers, `ma` masked / `mx` not, read registers, dataset offset, e-masks) | matches | [ref-src] `vm.rs:585-600` |
| Decode of all 29 opcodes: IADD_RS displacement only for r5; memory operand `src==dst` → L3 at base 0; `mod%4` L1/L2; F-memory ops without the `src==dst` special case; IMUL_RCP NOP for 0 and 2^k; ISWAP `src==dst` NOP; IROR/IROL immediates unsigned, IMUL/ISUB/IXOR sign-extended; CBRANCH `imm`, bit b−1 cleared, mask, target, all registers marked; CFROUND `imm&63`; ISTORE L3 when `mod>>4 ≥ 14` | matches line for line | [ref-src] `vm.rs:274-498` vs `bytecode_machine.cpp:150-470` |
| Iteration loop: spMix and masks; r ^= L3 line; f and e conversion; `readPtr = offset + (ma & mask)`; `mx ^= r2^r3`; swap; stores; f ^= e | matches. Upstream master itself now masks `ma` at the point of use, as the port does, so R9's "AND-after-XOR" equivalence is also the reference's current form | [ref-src] `vm.rs:642-690` vs `vm_interpreted.cpp:60-135` |
| Hash chain: `fprc = 0` once per hash (spec §2.2 step 6, *before* the program loop), persisting across the 8 programs; register file r/f/e/a; AesHash1R into bytes 192..256; Hash256 | matches spec §2.2 steps 1–14 | [ref-src] `vm.rs:546-575`; [test: `hash_1a`–`hash_1e`] |

### 2.2 Floating point: domain and soundness (agreeing with 08 §3.1)

**What 08 already says:**
- 08 re-derived the operand ranges: a ∈ [1, 2^32); e ≥ 2^-255, possibly reaching +∞;
  f is reloaded every iteration.
- FSCAL XORs the sign and the **low 4 exponent bits** (spec §5.3.4: x ∈ odd −15..15).
- FSCAL(±0) = ∓2^-1008.
- NaN *bit patterns* arise in f after the f^e XOR and reach the hash.

I agree with all of it [math/src].

**My independent checks [math]:**
- **The directed `div` residual `(a1 − p) − e`:**
  - `a1 − p` is exact by Sterbenz, because p = RN(q1·b1) is within a factor 2 of a1.
  - The true remainder is exactly representable for a correctly rounded quotient
    (Boldo–Daumas 2003).
  - So the RN evaluation is exact, and its sign is the sign of the exact error.
- **sqrt:** the same argument with a1 ∈ [1, 4) and an even rescale.
  - For E odd, (E+1)%2 = 0, so the new exponent is 1023 (a shift of E−1023, which is
    even).
  - For E even, the new exponent is 1024 (a shift of 1024−E, also even).
- **Dekker with splitter 2^27+1 on [1, 2)-rescaled operands:** it cannot overflow, and it
  is exact for binary64 (Boldo 2006, formal proof of Veltkamp/Dekker).
- **Overflow:** when RN is finite and equal to MAX but the exact value is above MAX,
  `correct` gives `next_up(MAX) = +∞` under Up and keeps MAX under Down/Zero, which is
  IEEE 754 §7.4. Cases where RN is infinite go through `overflow()`. Both cases are
  covered, and tested at the add boundary [test: `overflow_follows_ieee`].

**The domain restriction is real and undocumented in code:**
- `mul`, `div` and `sqrt` return the **round-to-nearest** result for subnormal operands
  in every mode (`fpu.rs:133, 146, 166`: `!a.is_normal()` → return RN).
- That is *wrong IEEE* outside RandomX's reachable domain, and harmless inside it.
- An oracle test must therefore sample the reachable domain plus the IEEE edges that
  are reachable (±0, ±MAX, +∞). It must not "fail" on subnormal operands. See F-4.

### 2.3 What the existing tests actually prove

| Test | Proves | Does not prove |
|---|---|---|
| `hash_1a`–`hash_1e` (light) | end-to-end equality with the reference on **5 inputs, 2 keys**. That covers 40 VM programs, **16 superscalar programs** (8 per key) and 2 Argon2 caches | inputs of header shape (100 B); 32-byte keys (both keys are 12 B); any key other than the two; rare decode paths |
| `superscalar_generator` | 10 programs for key `test key 000` (the first 8 are the cache's own) | any other key. Total distinct generator runs: **18 programs from 2 keys** |
| `cache_initialization`, `dataset_items` | 3 cache words and word 0 of 4 items for one key | the other 7 words; other keys |
| `aes_generator_1r`, `reciprocals` | direct KATs | 4R and Hash1R directly (the reference has **no** direct 4R or Hash1R KAT either; see F-5) |
| `fpu::tests::*` (6 tests) | hand-picked directed-rounding, zero-sign, scaled-residual, overflow and ∞ cases, **self-consistency only** (for example `up == down.next_up()`) | agreement with an IEEE oracle; any random sample |
| `full_mode_matches_light_mode` (ignored; CI `randomx-full` on Linux) | full = light on 5 vectors plus 1,024 random inputs over 2 keys | a reference for the 1,024; other keys; thread-count independence of `Dataset::new` |
| `guests` job, Windows step | the vectors also pass on Windows (MSVC) | other OS/arch; the soft-AES path (every x86 CI runner has AES-NI; see 08) |
| `consensus/tests/randomx_end_to_end.rs`, `chain/tests/manager.rs` "reference" hashes | node, miner and chain use the crate consistently | agreement with tevador: the "reference" in `manager.rs:1159` is this same crate |

**Summary:** conformance rests on 5 end-to-end vectors, a handful of component KATs and a
line-by-line source comparison. There is **no evidence at scale** against the reference.
The official vector **1f is missing** (F-1).

---

## 3. Problems in scope

### 3.1 Where can semantics diverge from tevador/RandomX? (the roster Q1)

**The question that matters is who diverges from whom.**
- All BlackSilk nodes run the same crate. So a divergence *port ↔ reference* alone does
  not split nodes.
- It (a) makes blocks from reference-based miners (xmrig, stock RandomX) invalid to
  BlackSilk nodes, which is liveness and fairness, and (b) breaks any future second
  implementation.
- A **node split** needs BlackSilk to diverge **from itself**, in one of three ways:
  - across platforms (soft AES on aarch64, FP backends; 08's scope);
  - across builds (`target-cpu`, an FMA cfg path; 06/08);
  - across versions (an optimization that changes output; 06).
- **The reference corpus is therefore mainly a regression pin that makes self-divergence
  detectable.** Its secondary role is conformance with the reference. Both need the same
  artefact.

**Divergence is adversarially reachable.**
- Header bytes are free to grind. Program 0 of a hash depends only on
  `Blake2b-512(input)` → the AES 1R fill → the AES 4R program. That is about 0.1 ms per
  candidate, needing no dataset [assumed timing].
- A decode feature with probability p per program can therefore be forced with about
  1/p cheap trials. The ISUB_R edge (src = dst, imm = 0x80000000) has p ≈ 2^-31 per
  program, so about 2^31 × 0.1 ms ≈ 60 core-hours [math + assumed timing].
- At the testnet's low difficulty the resulting header can also carry valid PoW.
- **So every rare decode path must be treated as attacker-reachable** and pinned by a
  vector.
- Keys (block ids at seed heights) are grindable only at the cost of valid PoW per
  candidate, so rare **generator** paths are reachable mainly on low-work forks (R1-C1).

**Divergence surface by component:**

| Area | Divergence mechanism | Pinned today? |
|---|---|---|
| Rounding modes (`fpu.rs`) | a wrong error sign in one of about 2^20 edge classes; the overflow boundary; exact-zero sign | 6 self-consistency tests plus 5 vectors. No oracle (F-3) |
| CBRANCH | `imm`/mask/target off by one; a missing "all registers modified"; target −1 | vectors only. The reference has 4 CBRANCH decode/execute KATs, **not ported** (F-2) |
| 2 MiB scratchpad | a mask constant (L1/L2/L3/L3-64) or a `src==dst` L3 base | the constants are compile-time derived [src]; vectors only |
| Program generation | AES 4R, entropy mapping, e-mask | vectors only |
| SuperscalarHash generator | the rarest paths: throw-away (`throwAwayCount>0` → `allowChainedMul`), the 256-throw-away abort to `Null`, the IADD_RS r5 two-register rule, port saturation from `scheduleMop` returning −1 | **18 programs from 2 keys.** Whether these branches were ever taken is [unknown] (F-3) |
| Argon2d | a pass/slice boundary or `index_alpha` | 3 words of one key, plus the 5 vectors |
| Integer immediates | 0x80000000 negation (the upstream #325/#326 JIT bug class), IMUL_RCP 0/2^k, rotate by 0/63 | **vector 1f is not ported** (F-1); no instruction-level KATs (F-2) |
| NaN-patterned f after XOR | bit preservation through `f64` moves | 08 D-4/W3/W5 (not mine) |
| AES soft vs AES-NI | a backend bug in `aes` | 08 W2 (`aes_force_soft` CI leg) |

**Correction to R9 and the full review (from 08 D-5, which I confirm).**
- The RandomX v1.2.2/v2.0.1 "invalid hashes (1 out of ~268 million) on ARM/RISC-V" was
  the **ISUB_R immediate 0x80000000 JIT bug** (PR #326; #325 on the v1 branch).
- It was not an FP-state bug.
- 1/268 M ≈ 2^-28 per hash = 8 programs × 2^-31 [math]. This is exactly vector 1f.

### 3.2 A differential-testing programme without FFI (the roster Q2)

#### Design principles

1. **The in-tree check is pure Rust and reads data files only.** No C/C++ is compiled
   by `cargo test`, and there is no FFI.
2. **The reference runs elsewhere:**
   - a separate machine, or a dedicated `workflow_dispatch` CI workflow that fetches
     tevador/RandomX at a **pinned tag SHA**;
   - it produces data artefacts that maintainers commit after a two-machine agreement
     check.
   - This is the same exemption R13 T-8 proposed. The harness is test tooling, never a
     build input.
3. **Normative reference:**
   - **`v1.2.3`**, the last v1-only release line;
   - the generator also runs **`v2.0.1` with default (v1) flags**, and the two outputs
     must be identical before commit.
   - Reason: master's v1 path is now interleaved with `RANDOMX_FLAG_V2` branches
     (`vm_interpreted.cpp:88`, `bytecode_machine.hpp:263`).
4. **Reference self-agreement before commit:**
   - the generator computes every hash with `RANDOMX_FLAG_DEFAULT` (interpreter, light)
     **and** `RANDOMX_FLAG_JIT|FULL_MEM|HARD_AES`;
   - it runs on x86-64 Linux **and** on aarch64 (JIT);
   - all four outputs must match byte for byte. This exercises the reference's own
     interpreter/JIT and AES paths.
5. **Every fixture file:**
   - is immutable and versioned (`…-v1.bin`);
   - carries a provenance header (reference SHA, flags, compiler, host, date, generator
     SHA);
   - is pinned by a Blake2b-256 digest in the test source.
6. **Localization, not just detection:** a subset carries intermediate traces
   (per-program register files, superscalar program digests, cache and dataset
   digests), so a failure points at the component.

#### The five tiers

| Tier | What | Source of truth | Size | When |
|---|---|---|---|---|
| **A. Official KATs** | 1a–1f; all v1 instruction-level decode/execute KATs from `tests.cpp`; AesGenerator1R, reciprocals, cache, dataset, superscalar | reference `tests.cpp` (data transcribed) | about 80 cases | every push |
| **B. Reference hash corpus** | ≥ 100,000 `(key, input) → hash` over **64 keys**. Keys K_i = Blake2b-256("BlackSilk/rx-corpus/v1/key" ‖ LE32 i); plus 9 length-edge keys (0, 1, 12, 31, 59, 60, 61, 64, 256 B: the Blake2Generator truncation at 60); inputs derived from the same seed (50 % 100-byte header shape with nonce at [92..100], 76-byte Monero blob shape, lengths 0, 1, 63, 64, 65, 127, 128, 200, 1024, random 0..512) | refgen (§3.2 principles) | 32 B per hash ≈ 3.3 MB, plus traces for 256 hashes (8 × 256 B each ≈ 0.5 MB) | per push: a 1,024-hash subset (light); weekly/pre-release: all of it, sharded |
| **C. Monero mainnet oracle** | Sample from height 1,978,433 (RandomX activation) to now: about 870 seed epochs × 16 blocks ≈ 14k `(seed_hash, hashing_blob, difficulty₁₂₈, pow_hash)` | **the Monero chain itself** (see below) | about 14k × (32 + 76 + 16 + 32) B ≈ 2.2 MB | weekly/pre-release |
| **D. Component differential** | 4,096 keys, **generator only** (no Argon2): per program `Blake2b-256(8-byte encodings)` plus address register. 256 keys: `Blake2b-256(cache memory)` and 64 full dataset items (indices 0, 1, 2^k, 34,078,718, and random). 2 keys: `Blake2b-256(full dataset)` | refgen via internal headers, as `tests.cpp` does | about 1.3 MB | per push (generator: seconds); weekly (Argon2, dataset) |
| **E. Raw-program differential** | 10,000 synthetic programs (128 config bytes plus 256 instructions), **biased to rare features**: imm32 ∈ {0, 1, 2^k, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF}; forced `src==dst`; mod ∈ {0, 3, 4, 223, 224, 255}; all CFROUND modes; dense CBRANCH chains including never-modified targets (−1); FDIV/FMUL runs to +∞; FSCAL on zeros; ISTORE L3. Each is executed on a fixed scratchpad with a fixed light-mode key; the output is the register file (256 B) plus `Blake2b-256(scratchpad)` | refgen calls the reference `InterpretedVm` directly (initialize from the config bytes, then `execute()`), as `tests.cpp` does with its internal headers | about 2.9 MB | per push: 500; weekly: all |

#### Why tier C is valuable: a *trustless* oracle

- Each Monero block since v12 satisfies `RandomX(seed, hashing_blob) · difficulty < 2^256`
  under a 128-bit difficulty, and the network accepted it.
- A divergent implementation computes a hash that meets a difficulty of about 10^11–10^12
  with probability about 2^-37 or less per block.
- So **the check needs no trust in the tool that exported the data**: the difficulty
  rule authenticates the hash.
- The optional `pow_hash` field (monerod `get_block_header_by_height` with
  `fill_pow_hash=true`) additionally gives byte equality.
- Tier C multiplies generator coverage from 2 keys to about 870 real keys.
- It uses exactly BlackSilk's shapes: 32-byte keys that are block ids, and short
  header-like blobs.
- Vector 1f itself is such a blob (it starts `10 10`, major/minor 16), so it is very
  likely a Monero mainnet block [assumed].

**Tier C acquisition:**
- **Blob:** from each block, the hashing blob is the serialized header ‖ the Keccak tree
  root of (miner tx hash, tx hashes) ‖ varint(n+1). The Rust library `monero-oxide`
  implements this, and monerod's `get_block` returns `miner_tx_hash` and `tx_hashes`.
- **Authentication:** optionally, the block id = Keccak(varint(len) ‖ hashing_blob)
  authenticates the blob against any explorer.
- **Tool:** a small pure-Rust tool **outside the workspace** that talks only to an
  operator-run monerod and sends no repository content.
- This needs owner approval (Q4).

#### Cost, CI and resources

- Light hashes cost about 0.45–0.75 s. The full 10^5 corpus is about 12.5–21 CPU-hours
  in light mode. Sharded 4 ways on 4-vCPU runners, that is about 1 h per shard.
- In full mode it is 64 dataset builds (about 133 s each at 8 threads) plus 10^5 × 0.1 s
  / 4 ≈ 2.5–3.5 h, so split: light for most keys, full for 4 keys.
- On-push subsets stay under about 3 min.
- The local 16 GB shared machine must **not** run the full tier during phase 2. The
  weekly/pre-release jobs run on CI, which is 43's scope.

#### Programme outcome

- **Detection:** any port ↔ reference divergence on 10^5 random, about 14k chain-real
  and 10^4 adversarial programs.
- **Localization:** the traces and component digests point at the component.
- **Regression gate:** 06's optimizations and 08's platforms are all held to the same
  fixtures.

### 3.3 Can pure-Rust `rustc_apfloat` serve as an IEEE oracle? (the roster Q3)

**Answer: yes for add/sub/mul/div, no for sqrt. Use it as the second of two independent
oracles, not as the only one.**

**What it offers:**
- `rustc_apfloat` 0.2.3+llvm-462a31f5a5ab is a living port of LLVM `APFloat`.
- Licence: Apache-2.0 WITH LLVM-exception.
- `ieee::Double` has `add_r`/`sub_r`/`mul_r`/`div_r`/`mul_add_r` with
  `Round::{NearestTiesToEven, TowardNegative, TowardPositive, TowardZero}`, plus
  `from_bits`/`to_bits`.
- It has **no sqrt**.
- It is tested with the LLVM test suite, and fuzzed (cargo-afl) against the C++ APFloat
  and hardware, which found latent LLVM bugs.
- LLVM's `handleOverflow` returns ∞ or the largest finite value per mode, matching
  IEEE 754 §7.4 [ref: LLVM behaviour; assumed for the port until confirmed by test].

**Why it should not be the only oracle:** APFloat has had bugs, which is the reason the
fuzzing exists. Both oracles are pure Rust; a third is optional.

1. **An exact integer oracle** (no dependency; about 150 lines of test code). A finite
   double is ±m·2^e with m < 2^53. Every check fits in `u128`:
   - **mul:** the exact product m_a·m_b < 2^106 is compared with the candidate r and its
     neighbours (r⁻, r⁺) after aligning exponents (a shift ≤ 53).
   - **div:** the sign of a − r·b uses r_m·b_m < 2^106.
   - **sqrt:** the sign of a − r² uses r_m² < 2^106, with the exponent parity handled.
   - It checks the *defining inequalities* of each mode:
     - Down: r ≤ x < r⁺;
     - Up: r⁻ < x ≤ r;
     - Zero: by magnitude;
     - Nearest: |x − r| ≤ ½ulp, with ties to even.
   - This is independent of any float library and trivially auditable.
2. **`rustc_apfloat` as a dev-dependency** (pinned exactly; 44 to review). It is the
   **primary** oracle for add/sub, where exponent alignment exceeds u128, and a
   cross-check for mul/div.
3. **Optional:** Berkeley TestFloat 3e `testfloat_gen` vectors (C, BSD; generated
   offline as data under the same exemption as refgen) for f64_add/sub/mul/div/sqrt ×
   `-rnear_even/-rmin/-rmax/-rminMag`, filtered to the RandomX domain.

**Sampling (≥ 10^7 per op and mode in the weekly job; 10^5 per push):**
- f-domain adds: i32 ± a, a ∈ [1, 2^32), after FSCAL (×2^±odd ≤ 15), ±2^-1008,
  exact cancellations, exact halfway ties (constructed), ±0 combinations;
- e-domain mul/div/sqrt: e ∈ [2^-255, 2), grown values up to and past MAX, +∞;
- the overflow boundary: MAX·(1+k·2^-53), the MAX+½ulp tie and a quarter ulp above MAX;
- random 64-bit patterns filtered to normal operands with a normal-or-overflow result.

**Pre-existing prior art:** go-randomx (P2Pool) ships a pure-Go soft-float path
(`softfloat64`, ported from Berkeley SoftFloat 3) for RandomX's five operations, and
passes the official tests. That shows a second implementation strategy exists; it is not
a source to copy.

### 3.4 Full = light equivalence

**Current:** 5 vectors plus 1,024 random inputs over 2 keys in the weekly/push
`randomx-full` job [test: `full_mode_matches_light_mode`].

**Gaps:**
1. `Dataset::new` is never compared across **thread counts**. `dataset.rs:86-100` splits
   items into `div_ceil` chunks; the code is correct by reading [src], but untested.
2. There is no reference dataset digest.
3. Only 2 keys are used.

**Plan:**
- In the weekly job, `Blake2b-256(Dataset)` for 2 keys at threads ∈ {1, 3, 8}. This takes
  about 3 × 133 s at 8 threads and about 18 min at 1 thread [assumed from the README
  figure]. It must equal the tier D reference digest.
- Full vs light on the tier B subset for 4 keys.
- Memory: about 2.3 GiB per dataset, sequential. That fits a 16 GB runner.

### 3.5 Other conformance invariants worth testing

**VM statelessness [src]:** `hash()` resets or overwrites everything it reads:
- the scratchpad is fully refilled;
- `r` is zeroed per program;
- `f`/`e` are reloaded;
- `a`, `ma`, `mx`, the config and the offset are set in `initialize`;
- `fprc` is reset per hash (`vm.rs:546-600, 643`).

Both the miner and the ignored test reuse VMs. **Test:** 64 inputs hashed on one reused
VM equal fresh-VM hashes, in both light and full mode.

**The CBRANCH execution bound [math + ref design]:**
- Every CBRANCH sets `register_usage = [i; 8]` (`vm.rs:468`). So a later CBRANCH's
  target is never before the previous CBRANCH: **loops never nest**.
- Each segment runs at most 3 times, because design §2.6.2 says "each CBRANCH can jump up
  to twice in a row".
- So at most 3 × 256 = 768 instructions run per iteration, and an input grinder can
  inflate verification time by at most about 3× in theory. The practical effect is
  negligible, because jump conditions depend on pseudorandom register values.
- **Test:** a cfg(test) instruction counter asserts ≤ 768 per iteration over tiers B/E.

**FPU domain [math]:** a cfg(test) (or `debug_assertions`) check that every `fpu::*`
operand is normal, ±0 or +∞, and never subnormal or NaN, over tiers A/B/E. This turns
the "unreachable" claims in `fpu.rs:10-15` and 08 §3.1 into **[test]** evidence.

### 3.6 Invariants that must never change (conformance view)

1. The output equals tevador RandomX **v1** (`v1.2.3`; `v2.0.1` with default flags) for
   every key and input.
   - Official vectors are only ever added, never edited.
   - A move to v2 is a separate, versioned consensus switch (R9 §7, full review D14).
2. Fixture files are immutable. A regeneration is a new version file with provenance and
   a digest; old files stay green.
3. `Vm::hash` is a pure function of (key, input, mode ∈ {light, full}), and light = full.
4. `fprc` is reset once per hash, not per program.
5. The key handling: the first 60 bytes go to Blake2Generator; the full key goes to
   Argon2 (the reference behaviour; `lib.rs:43-44`).
6. The register-file and scratchpad serialization is explicit little-endian and
   bit-exact, NaN patterns included (08 D-4).
7. The `config.rs` constants and frequency table (a compile-time sum of 256).

---

## 4. New findings

| ID | Severity | Status | Where | Scenario | Confidence |
|---|---|---|---|---|---|
| **F-1** | **Medium** (a consensus-critical evidence gap) | Not implemented | `randomx/src/lib.rs:53-194` (vector list); `randomx/README.md` "Verification status" | Official **Hash test 1f** is absent. It was added upstream in PR #326 (2026-05, the v1.2.2/v2.0.1 security release), with a 31-byte key `77 97 37 3e … e8`, a 76-byte blob and expected `78af2a18…35a8`. It pins the ISUB_R imm = 0x80000000, src = dst path, the exact bug class that produced invalid hashes on ARM/RISC-V. The port's semantics are correct by source (`vm.rs:316-321, 287-289, 716`: `wrapping_sub(0xFFFF_FFFF_8000_0000)`), but unverified. The README claims "every applicable test vector … all pass". That overclaims. A future optimization (06 O5 specializes imm variants) could break this path unseen. | high |
| **F-2** | Low | Not implemented | `vm.rs:274-498` (decode), `fpu.rs` | About 70 reference instruction-level KATs are not ported. They are 100 % data and portable against `compile()` and a small VM state: IADD_RS/…/ISTORE decode masks and immediates; CBRANCH decode at pc 100/200 (`imm = 0xFFFFFFFFC0CB9AD2`, `mask = 0x7F800`, target) plus taken/not taken; CFROUND `imm = 18`; ISTORE L1/L2/L3; **13 FP execute KATs across rounding modes** (FADD_R ×4, FADD_M, FSCAL, FSWAP, FMUL_R ×3, FDIV_M ×3, FSQRT_R ×3). The FP KATs are the only reference-produced directed-rounding results obtainable today without a generator. | high |
| **F-3** | Medium | Not implemented (known T-8, deepened) | crate-wide | The reference evidence is 5 hashes, **18 superscalar programs from 2 keys of 12 bytes**, and no key of BlackSilk's 32-byte shape. No input has the 100-byte header shape. Whether the generator's throw-away, abort and saturation branches (`superscalar.rs:668-701, 654-657, 705-710`) have **ever executed** is unknown. The FPU has no oracle. A divergence in any of these is invisible until a JIT miner's block is rejected, or two BlackSilk builds disagree. | high |
| **F-4** | Low | Partially implemented | `fpu.rs:10-15, 108, 133, 146, 166` | The FPU is correct only on RandomX's reachable domain: it returns RN results for subnormal operands in directed modes. The precondition is prose only. There is no `debug_assert` and no test that the VM never feeds out-of-domain operands. Risks: an oracle test written naïvely "fails"; a refactor (06 O4/W6) widens the domain assumption silently. | high |
| **F-5** | Informational (a correction) | — | R9 §8 "R9-R6" | R9 says "4 AesGenerator4R/AesHash1R direct vectors: the reference `tests.cpp` has them". **False** at `7607fb2`: `tests.cpp` has only AesGenerator1R. 4R and Hash1R are pinned only end to end. Also, R9 counts 5 fpu unit tests; there are 6. | high |
| **F-6** | Informational (a correction) | — | R9 §0 item 1, §2 | R9's "hand-checked from memory of the reference" conformance claim is now **[ref-src]**: re-done against the actual source (§2.1). No deviation found. | high |
| **F-7** | Low | Complete but requires further testing | `vm.rs:546-600`; `dataset.rs:86-100` | VM reuse statelessness and `Dataset::new` thread-count independence are correct by source but untested. The miner relies on both. | high |
| **F-8** | Informational | — | upstream master | tevador master is now the v2 code base (v1 behind flags). A refgen built from master exercises v1 through `if (flags & V2)` branches. Pin `v1.2.3` as normative and cross-check against `v2.0.1` default flags. | high |
| **F-9** | Informational | Complete and verified [math] | `vm.rs:460-474` | The CBRANCH non-nesting bound (≤ 768 instructions per iteration). It is not tested (§3.5). | medium-high (it relies on design §2.6.2 for "twice in a row") |

**Not re-filed (owned elsewhere and confirmed):**
- 08 D-4: NaN-pattern bit preservation;
- 08 D-5: the misattribution of the upstream bug;
- 08 D-6: FSCAL(±0) = ∓2^-1008;
- 08 D-8: the stale `docs/consensus.md` §9 CI sentence;
- 08 W2: the soft-AES CI leg;
- 07: the cache/seed lifecycle.

---

## 5. Implementation plan for phase 2

All items **change nothing externally visible**: tests, fixtures, docs and debug-only
assertions. There is no consensus change and no identity impact.

| # | Work item | Files (ownership) | Tests to add | Bench | Docs | Size | Pri |
|---|---|---|---|---|---|---|---|
| **C1** | **Vector 1f plus README truth.** Add `hash_1f` (31-byte key, 76-byte blob). Add 1f to the full-mode test. Rewrite "Verification status" to list exactly what is pinned. | `randomx/src/lib.rs` (tests module only), `randomx/README.md` | regression KAT (light and full) | — | README | S | **P0** |
| **C2** | **Reference instruction-level KATs** (F-2): transcribe the v1 decode/execute cases of `tests.cpp` into a table-driven cfg(test) module. Needs `compile` and `Op` to be `pub(crate)` with `#[derive(Debug, PartialEq)]` on `Op`/`Src`: a 3-line, non-semantic edit to `vm.rs`. | new `randomx/src/conformance_kats.rs` (cfg(test)); `lib.rs` mod line; `vm.rs` visibility only (coordinate with 06) | unit KATs: about 70 decode/execute cases, 13 of them FP in all modes | — | README | S | **P1** |
| **C3** | **FPU oracle** (F-3/F-4): the exact u128 oracle (mul/div/sqrt), `rustc_apfloat` (add/sub/mul/div), domain samplers (§3.3), 10^5 per op and mode per push and 10^7 weekly (`#[ignore]`). Add `debug_assert!` domain preconditions in `fpu.rs`: no release change; exercised by the `overflow` CI job. | new `randomx/src/fpu_oracle.rs` (cfg(test)); `randomx/Cargo.toml` `[dev-dependencies] rustc_apfloat = "=0.2.3+llvm-462a31f5a5ab"` (44 review); `fpu.rs` debug_asserts plus a docstring fix (FSCAL range, the 2^-1008 case) | property/differential per op × mode; edge KATs; a domain assertion over the vector suite | a oracle-throughput note only | README "Design notes", `fpu.rs` doc | M | **P1**; **P0 if 06 W6 (FPU fast path) is scheduled before the freeze** (it is blocked on this) |
| **C4** | **Superscalar/Argon2/dataset differential** (tier D) plus coverage counters. cfg(test) counters in `superscalar.rs` (throw-away, abort, r5 rule, saturation) prove the fixture keys hit every branch. If not, grind keys with the port's generator (cheap) and add them to the refgen key list. | new `randomx/src/generator_conformance.rs` (cfg(test)); `superscalar.rs` (cfg(test) counters only; coordinate with 06 W3/W4); `randomx/tests/data/rx-v1-components.bin` | 4,096-key program digests (per push, seconds); 256 cache digests plus 64 items per key (weekly); a coverage assertion | — | provenance file | M | **P1** |
| **C5** | **Refgen and the reference corpus** (tiers B/E): a C++ harness (about 200 lines) against tevador `v1.2.3` (SHA-pinned) with a `v2.0.1` cross-check; interpreter and JIT; x86-64 and aarch64 runs must agree. Output tiers B, D and E plus traces. The in-tree pure-Rust tests read the files, with digests pinned in source. | harness location per Q1 (`tools/randomx-refgen/`, never built by cargo; or a separate repo; or embedded in a `workflow_dispatch` workflow owned with 43); `randomx/tests/reference_corpus.rs` (new; public API only); `randomx/tests/raw_programs.rs` needs a cfg(test)/`#[doc(hidden)]` hook to run a raw program (`vm.rs`; with 06); `randomx/tests/data/*.bin` plus `PROVENANCE.md` | differential: a 1,024-hash subset per push, 10^5 weekly (sharded, `#[ignore]`); raw programs 500 per push, 10^4 weekly; trace localization on failure | runtime per shard recorded | README, R13 T-8 status | L | **P1** (a gate for 06 W3–W7) |
| **C6** | **Monero mainnet oracle** (tier C): the acquisition tool (pure Rust, outside the workspace, operator's own monerod; `monero-oxide` or a minimal Keccak tree-hash); fixtures of about 14k blocks over about 870 epochs; the test checks `hash·diff₁₂₈ < 2^256` and `hash == pow_hash`, and optionally the block id. | `tools/monero-rx-fixtures/` (new, excluded from the workspace like `fuzz`); `randomx/tests/monero_mainnet.rs`; `randomx/tests/data/monero-mainnet-rx-v1.bin` | a trustless differential (difficulty rule) plus byte equality | — | provenance | M | **P1** (owner approval, Q4) |
| **C7** | **Full = light and dataset.** Dataset digest vs reference for 2 keys at threads {1, 3, 8}; full vs light on a tier B subset (4 keys); VM statelessness (reused vs fresh, light and full). | `randomx/src/lib.rs` (the ignored test) or `randomx/tests/full_light.rs`; the `randomx-full` step in `ci.yml` (43) | equivalence, statelessness, thread independence | dataset build time per thread count (feeds 45) | README | M | **P1** |
| **C8** | **Execution invariants:** the CBRANCH ≤ 768 per iteration counter; a no-subnormal/no-NaN FPU operand check over tiers A/B/E (cfg(test) instrumentation). | `vm.rs` (cfg(test) counter; with 06), `conformance_kats.rs` | invariant/property | — | — | S | P2 |
| **C9** | **TestFloat vectors** (optional third FPU oracle), domain-filtered | `randomx/tests/data/testfloat-f64-*.txt.gz`, `fpu_oracle.rs` | KATs | — | provenance | S | P3 |
| **C10** | **Docs:** the R9 corrections (F-5, F-6) and 08 D-5 recorded in the findings register; `docs/consensus.md` §9 states the conformance evidence precisely (vectors, corpus size, oracle), with no overclaim | `docs/consensus.md` §9 (with 47); `docs/reviews/…` register (coordinator) | — | — | as listed | S | **P0** (docs) |

**Order:**
1. C1 and C10 (hours);
2. C2 and C3 (they unblock 06 W6 and validate 08 W3's digests);
3. C4 (generator-only, fast);
4. C5 (needs the owner's Q1/Q3 answers and an external machine);
5. C6 (Q4);
6. C7;
7. C8;
8. C9.

**Merge gate for 06 W3–W7:**
- C1, C2 and C3 must be green;
- **C5's per-push subset must be green on every 08 W2 platform leg**;
- a W6 FPU change additionally needs the 10^7-per-op oracle run.

**Complete tests list (the Accept criterion):**
- **Official vectors:**
  - 1a–1f, light and full;
  - AesGenerator1R;
  - reciprocals;
  - cache words;
  - dataset items;
  - superscalar programs;
  - the instruction-level KATs.
- **Reference corpus:** ≥ 10^5 hashes, 64 + 9 keys, header and edge input shapes, traces.
- **The Monero oracle:** about 14k real blocks, about 870 keys.
- **Component differentials:** 4,096-key generator; 256 caches and items; 2 dataset
  digests.
- **The raw-program differential:** 10^4 adversarially biased programs.
- **FPU oracle:** exact-integer and apfloat, ≥ 10^7 per op × 4 modes, with edge KATs.
- **Full = light:** thread counts and statelessness.
- **Adversarial seeds/inputs:**
  - length-edge keys (0 to 256 B);
  - ground keys that hit rare generator branches;
  - ground/synthetic programs for rare decode paths (0x80000000, IMUL_RCP 0/2^k,
    rotates 0/63, CBRANCH −1, ISTORE L3, +∞ chains, all 4 modes).
- **Invariants:** the ≤ 768-instruction bound; no out-of-domain FPU operands.

---

## 6. Dependencies and conflicts

**06 randomx-performance:**
- **Heavy file overlap:** `vm.rs`, `superscalar.rs` and `fpu.rs`.
- 05's edits there are visibility or cfg(test) only. Land them **first**, then 06
  refactors.
- 06 W2 (`randomx/src/reference.rs`, `randomx/tests/equivalence.rs`) and 05's
  `randomx/tests/*`: agree on file names. 05 owns `tests/data/`.
- 06 W6 is blocked on C3. 06 W3–W7 are gated on C5's subset.

**08 randomx-determinism:**
- 08's W3 digests are validated by C3 and C5 (their open question 5: my answer is yes,
  land them as "self-consistency", then cross-validate once C3/C5 exist).
- 08 W2 platform legs run 05's per-push subset.
- The shared `lib.rs` mod lines need serialized edits.

**07 randomx-cache-seed:** `Cache::try_new`/`Dataset::try_new` in `dataset.rs` must pass
C1, C4 and C7 unchanged. There is no other overlap.

**09 mining-templates:** the miner self-test (08 W4) should reuse the C1 vectors. There
are no file conflicts.

**41 fuzzing:** a `cargo-fuzz` target that runs `fpu` vs the oracles, and one that runs
raw-program decode for panics. The corpus storage plan is to be shared.

**42 mutation-formal:** `cargo-mutants` on `randomx/src/fpu.rs` and `vm.rs` decode, with
C2/C3/C5 as the kill set. That measures the test adequacy F-3 questions.

**43 ci-reproducibility:** owns `ci.yml`. The new weekly shard jobs, the refgen workflow
(if in CI) and the `randomx-full` extension go through them.

**44 supply-chain:**
- `rustc_apfloat` (dev-only; Apache-2.0 WITH LLVM-exception);
- the refgen C++ exemption record;
- the `tools/monero-rx-fixtures` dependencies (monero-oxide or sha3).

**45 benchmarks:** C7 dataset timings.

**47 docs:** C10.

**01 consensus-core:** the rule inventory row "PoW = RandomX v1 conformance" points to
C1–C6 as its evidence.

---

## 7. Open questions for the coordinator

1. **The refgen harness (C++):** may it live in-tree under `tools/randomx-refgen/`
   (never built by cargo, documented exemption like libFuzzer), or must it be a separate
   repository or a CI-only workflow that fetches upstream at a pinned SHA? The pure-Rust
   policy covers core code; this is test tooling producing data.
2. **The normative reference:** confirm `v1.2.3`, with mandatory agreement from `v2.0.1`
   default flags (F-8).
3. **Fixture storage:** is about 7–10 MB of binary fixtures acceptable in git, or should
   they be release artefacts pinned by digest? The in-tree check needs at least the
   per-push subsets (about 150 KB).
4. **Tier C:** may an operator run a monerod to export public Monero chain data (heights,
   headers, difficulties)? No repository content leaves the machine.
5. **CI budget:** weekly full tiers cost about 15–25 CPU-hours, sharded. Acceptable?
   Otherwise, pre-release only.
6. **Is 06 W6 (the FPU fast path) planned before the freeze?** If yes, C3 becomes P0.

---

## 8. Sources

**RandomX (tevador), at master `7607fb2`:**
- repository: https://github.com/tevador/RandomX
- specification: https://github.com/tevador/RandomX/blob/master/doc/specs.md (§2.2
  steps, §4.3 fprc table, §4.3.2 E conversion, §5.3.4 FSCAL, §5.4 CFROUND/CBRANCH)
- design: https://github.com/tevador/RandomX/blob/master/doc/design.md (§2.5 FP
  domains; §2.6.2 "each CBRANCH can jump up to twice in a row"; e range 1.7e-77 to ∞)
- configuration: https://github.com/tevador/RandomX/blob/master/doc/configuration.md
  ("every implementation should choose a unique salt")
- reference sources:
  - https://github.com/tevador/RandomX/blob/master/src/superscalar.cpp
  - https://github.com/tevador/RandomX/blob/master/src/bytecode_machine.cpp
  - https://github.com/tevador/RandomX/blob/master/src/vm_interpreted.cpp
  - https://github.com/tevador/RandomX/blob/master/src/aes_hash.cpp
  - https://github.com/tevador/RandomX/blob/master/src/tests/tests.cpp (test_f; the
    instruction KATs; no AES 4R/Hash1R KAT)

**RandomX releases and PRs:**
- releases: https://github.com/tevador/RandomX/releases (v1.2.2 / v2.0.1: "invalid
  hashes (1 out of ~268 million) on ARM/RISC-V"; v1.2.3 2026-07-17)
- the ISUB_R JIT fix and vector 1f: https://github.com/tevador/RandomX/pull/326 and
  https://github.com/tevador/RandomX/pull/325
- RandomX v2: https://github.com/tevador/RandomX/pull/317

**Argon2:** RFC 9106 (Argon2), §3.2–3.4: https://www.rfc-editor.org/rfc/rfc9106

**Rust float semantics:**
- Rust RFC 3514, float semantics:
  https://rust-lang.github.io/rfcs/3514-float-semantics.html
- rust-lang/rust #115567 (x86-32 NaN payload in return values; open, affects the C ABI
  and non-SSE2 targets): https://github.com/rust-lang/rust/issues/115567

**FPU oracles:**
- `rustc_apfloat`: https://github.com/rust-lang/rustc_apfloat and
  https://docs.rs/rustc_apfloat/latest/rustc_apfloat/trait.Float.html
- `simple-soft-float`, considered and **rejected** (LGPL-2.1, last release 2019):
  https://crates.io/crates/simple-soft-float
- `dashu-float` (pure Rust, MIT/Apache; a possible sqrt oracle, not needed):
  https://docs.rs/dashu-float/latest/dashu_float/
- Berkeley TestFloat 3e: http://www.jhauser.us/arithmetic/TestFloat.html and
  http://www.jhauser.us/arithmetic/TestFloat-3/doc/testfloat_gen.html

**Floating-point literature:**
- S. Boldo, S. Graillat, J.-M. Muller, "On the Robustness of the 2Sum and Fast2Sum
  Algorithms", ACM TOMS 44(1), 2017: https://dl.acm.org/doi/10.1145/3054947 (open copy:
  https://hal.science/ensl-01310023)
- S. Boldo, M. Daumas, "Representable correcting terms for possibly underflowing
  floating point operations", ARITH-16, 2003:
  https://ieeexplore.ieee.org/document/1207663/
- S. Boldo, "Pitfalls of a Full Floating-Point Proof: Example on the Formal Proof of the
  Veltkamp/Dekker Algorithms", IJCAR 2006:
  https://link.springer.com/chapter/10.1007/11814771_6

**Prior art:**
- go-randomx (pure Go with an optional soft float): https://git.gammaspectra.live/P2Pool/go-randomx
- softfloat64: https://pkg.go.dev/git.gammaspectra.live/P2Pool/softfloat64

**Monero:**
- technical specs (RandomX from height 1,978,433): https://docs.getmonero.org/technical-specs/
- daemon RPC (`fill_pow_hash`, `pow_hash`, `wide_difficulty`, `get_block`):
  https://docs.getmonero.org/rpc-library/monerod-rpc/
- the hashing-blob structure: https://github.com/monero-project/monero/issues/9147
- monero-oxide (a Rust Monero library; hashing blob): https://github.com/monero-oxide/monero-oxide

**CI runners (for 08/43):**
- GitHub arm64 hosted runners, GA for public repositories:
  https://github.blog/changelog/2025-08-07-arm64-hosted-runners-for-public-repositories-are-now-generally-available/
- and for private repositories (2026-01-29):
  https://github.blog/changelog/2026-01-29-arm64-standard-runners-are-now-available-in-private-repositories/

**Local source:** `~/.cargo/registry/src/…/aes-0.8.4/src/hazmat.rs:14-47` (AES-NI via
cpufeatures on x86; ARMv8 only with `cfg(aes_armv8)`; `aes_force_soft`).
