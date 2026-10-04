# SKC-1 (SilkChain-1) — Research Report A: cryptography and algorithm design

- Agent: SKC-1 Research Agent A (independent; Agent B's notes not read)
- Start: 2026-10-04T09:44:21+02:00 — Finish: 2026-10-04T09:52:19+02:00
- Scope: research only. No repository file modified, no build/test/benchmark run. Repository inspected read-only on branch `rebuild/core` at `8ccc24c`.
- Evidence labels used throughout: **[E]** established (published result or primary source), **[H]** plausible hypothesis (argued, not measured), **[U]** unverified assumption. Nothing here claims SKC-1 or RandomX is "secure", "ASIC-proof" or "GPU-proof".

---

## 0. Executive summary

1. **SKC-1 as proposed is structurally a CryptoNight/Argon2d hybrid**: a per-nonce scratchpad filled by a one-pass data-dependent graph, with a 64×64 multiply, an integer division, and read-modify-write. Every one of these ideas has been deployed before, and the deployed record is not encouraging. CryptoNight (2 MiB scratchpad, 64-bit multiply, later integer division and square root) got ASICs and needed four emergency forks before Monero gave it up for RandomX [E]. Argon2d is the well-analysed version of the same graph, and it has a known ranking tradeoff (time-area reduction about 1.33×) [E].
2. **The 32 MiB size is the weakest parameter choice.** It is too large for per-core CPU cache, so CPU cores walk the dependency chain at DRAM latency. It is small enough to sit in on-die SRAM on an ASIC (about 8 mm² at TSMC N5 HD density), where each access takes about 1–2 ns [E for density; H for the consequence]. RandomX chose 2 MiB (cache-resident on CPUs) plus 2 GiB (forces DRAM on ASICs) for exactly this reason [E]. SKC-1's middle size gives up both advantages.
3. **SilkMix and the division step are invented primitives with no analysis.** Established alternatives exist and are better studied: BLAKE2b's round function with BlaMka multiplications (Argon2's G), and RandomX's reciprocal-multiply in place of division. A one-pass, uniform-parent graph is weaker against TMTO than Argon2's quadratic index mapping [E/H].
4. **The proposal leaves its most important binding unspecified: how header ‖ nonce enters the scratchpad.** If it enters through any narrow intermediate (≤128 bits), it is open to the ProgPoW "Kik" bypass class [E]. If it enters only through the seed, the scratchpad is shared across nonces and the memory hardness is void.
5. **What SKC-1 genuinely offers** [H]:
   - Verification costs one hash, with no 256 MiB cache, no seed epochs and no `SeedCache` machinery.
   - Pure safe Rust would be close to optimal, because there is no JIT gap. Today's pure-Rust RandomX is about 50–100× slower than xmrig (internal review R9).
   - The algorithm is not shared with Monero.

   The first two are engineering wins. The third is weaker than it looks (§5).
6. **On "dependence on Monero's algorithm"** (§5), the practical risk is shared, rentable hashpower, not shared code. Merge mining is impossible with the current header format, so the risk is that RandomX hashpower can be redirected with a thin adapter. That includes botnets, rental markets, Qubic-style coordinated pools and the RandomX ASICs now on sale (Antminer X5/X9). A unique algorithm raises the switching cost from "an adapter" to "a new kernel". That is days of work for a motivated attacker, and generic CPUs/GPUs remain rentable. Uniqueness does not change the basic fact that a small PoW chain can be out-mined by anyone who rents more hashpower [E: Bonneau 2016].
7. **Recommendation:** **REDESIGN REQUIRED** before any prototyping; **keep RandomX v1 for the testnet** (§8). A redesigned SKC-1 (§7) is worth a time-boxed research prototype. It must never be deployed without the measurements in §9–10 and an external cryptanalysis the owner has explicitly decided to seek. Under the current self-reliant policy, internal review is not an audit and must not be presented as one.

---

## 1. Repository integration map (read-only, `rebuild/core` @ 8ccc24c)

### 1.1 Algorithm and configuration

| What | Where | Notes |
|---|---|---|
| RandomX crate (pure Rust, `#![forbid(unsafe_code)]`, no FFI, interpreter) | `randomx/src/lib.rs:20`; modules `argon2d.rs`, `superscalar.rs`, `dataset.rs`, `aes_gen.rs`, `vm.rs`, `fpu.rs`, `config.rs` | Port of tevador/RandomX v1 (README). Deps: RustCrypto `blake2`, `aes` (hazmat). |
| Consensus constants | `randomx/src/config.rs:4-74` | `ARGON_SALT = b"RandomX\x03"` (:7) is Monero's own salt; cache 256 MiB, dataset 2080 MiB, scratchpad 2 MiB, 8 programs × 2048 iterations. **The algorithm is bit-identical to Monero's RandomX v1.** |
| VM hash entry | `randomx/src/vm.rs:546` (`Vm::hash`); `randomx/src/lib.rs:179` (`hash_light`) | |
| Self-test (vectors, full-vs-light agreement) | `randomx/src/self_test.rs:30,168,211,274` | |

### 1.2 Consensus PoW layer

| What | Where | Notes |
|---|---|---|
| Target check `check_hash` | `consensus/src/pow.rs:11-23` | `h·d < 2^256`, LE 256-bit; d=0 invalid. Algorithm-agnostic: **reusable by any PoW**. |
| Seed schedule `seed_height` | `consensus/src/pow.rs:26-33` | Monero `rx_seedheight`, E=2048, L=64; first switch at 2113. Tests `pow.rs:1311-1347`. |
| `PowFunction` trait (the swap point) | `consensus/src/pow.rs:37-46` | `pow_hash(seed, header_bytes)`. An alternative PoW plugs in here; `set_hot_seeds` becomes a no-op without epochs. |
| `SeedCache`/`MAX_CACHES` (5×256 MiB = 1.25 GiB) | `consensus/src/pow.rs:52-75, 212-570` | Exists only because of RandomX's 256 MiB per-key cache. |
| `RandomXPow` (verification = **light mode**) | `consensus/src/pow.rs:582-645` (`Vm::light` at :637) | |
| Seed lookup on own branch | `consensus/src/chain.rs:301-305` (`seed_id_for`) | |
| PoW in header validation (last, expensive) | `consensus/src/chain.rs:556-593` (`validate`, `pow_meets`) | Also the RT-1 `UnknownUpgrade` PoW gate at :566-576. |
| Chain work = sum of difficulties (u128) | `consensus/src/chain.rs:235`; spec `docs/consensus.md` §3 | Algorithm-agnostic. |
| Difficulty LWMA-1 variant | `consensus/src/difficulty.rs:23,56` | Algorithm-agnostic, but `D0` and the hashrate model assume RandomX rates. |
| Params: epoch/lag, D0 | `consensus/src/params.rs:24-34, 100-119, 210-216` | Testnet D0 = 100. |
| Header layout (100 B, nonce @92) | `consensus/src/header.rs:6,26,30-40`; spec `docs/consensus.md` §2 | Whole header = PoW input. **Pending: branch `omr` grows header to 140 B** (`output_count`, `output_root`; decision `docs/reviews/phase2-2026-09-27/decisions.md` tail, "Header output commitment"). Any PoW spec must take the header as a length-tagged opaque blob so as not to depend on this. |

### 1.3 Node, sync and mining

| What | Where | Notes |
|---|---|---|
| Node PoW memo cache / preload from store | `chain/src/manager/pow_cache.rs:33-99,366`; store record `pow_hash‖block` `chain/src/store.rs:9,175,290` | Trusts stored PoW hash at restart. |
| Hot seeds, live-key check, anti-DoS threshold, chunking | `chain/src/sync_policy.rs:37,62,94,114,129,143,243` | Epoch-specific: disappears or simplifies without seed epochs. |
| Batch seed for header sync | `p2p/src/net/headers.rs:342-350` | |
| Wallet header verification (also RandomX light) | `wallet/src/headers.rs:374,417`; `wallet/src/wallet/sync.rs:13,671` | Wallets pay 256 MiB + ~0.45 s per header (R9). |
| Miner: light/full context, nonce loop | `miner/src/lib.rs:77-128` (`PowContext`), `:640-680` (`search`, nonce patched at `NONCE_OFFSET`) | |
| Miner key-switch planner | `miner/src/lib.rs:243` (`SeedPlanner`) | Epoch-specific. |
| Node fingerprint (consensus constants incl. seed schedule, header size) | `node/src/fingerprint.rs:305,343-348,474-478` | Must change for any PoW change. |

### 1.4 Tests, CI and documentation

| What | Where |
|---|---|
| Tests | `consensus/tests/randomx_end_to_end.rs`, `seed_cache.rs`, `seed_switch_liveness.rs`, `golden.rs`; `chain/tests/seed_switch.rs`, `pow_pool*.rs`, `rt_pow_pool_stress.rs`; `p2p/tests/network.rs:4355-4398` (2113 switch). |
| CI | `.github/workflows/*.yml:220-231` job `randomx-full` (full-vs-light, ignored tests). |
| Documentation | `docs/consensus.md` §3, §3.1, §9, §10; `docs/reviews/assumptions.md` K1, K2, K5; `docs/reviews/full-review-2026-09-27/R9-randomx.md`; `docs/reviews/phase2-2026-09-27/research/05..08-randomx-*.md`. |

### 1.5 RandomX-specific assumptions recorded in the repository

- Verification is in light mode: about 0.45–0.75 s per header and 256 MiB per key (`docs/consensus.md` §10; R9 §4.2).
- Attacker-to-verifier asymmetry for low-work headers is about 300–500× (xmrig full mode at ~1.4 ms vs pure-Rust light at 450–750 ms; R9 §2).
- The key switch at 2113 has been exercised only with short epochs in tests (`docs/consensus.md` §3.1).
- Determinism is verified on x86_64 only (K5).
- Fingerprint samples include the seed schedule.
- R9 §5 already names rentable Monero hashrate (Qubic, Aug 2025) as "the larger and more permanent risk".

**Integration conclusion** [E, from code]:
- An alternative PoW is mechanically a new `PowFunction` implementation plus a fingerprint, params and spec change.
- `check_hash`, chain work and LWMA are reusable unchanged.
- The seed-epoch machinery (`seed_height`, `SeedCache`, hot seeds, `SeedPlanner`, live-key checks) exists only for RandomX. A per-nonce PoW with no per-key precomputation would delete roughly 600+ lines of concurrency-sensitive code.
- This is a consensus change and a testnet reset item. It needs owner approval per memory policy.

---

## 2. Literature review

Each entry gives what the scheme commits to, its hardness argument, known attacks or TMTOs, the hardware outcome, and the lesson for SKC-1.

### 2.1 RandomX (Monero, 2019)

- **Commits to:** Argon2d-filled 256 MiB cache (keyed by an epoch seed), expanded by SuperscalarHash into a 2080 MiB dataset. Per hash: 8 random programs × 2048 iterations over a 2 MiB scratchpad that is read and written. Integer, floating-point (4 rounding modes), branches, AES. Finalised by AES hashing of the scratchpad and Blake2b.
- **Hardness argument:** the work is *code*, so the efficient hardware is a general CPU. The 2 MiB scratchpad fits CPU L2/L3. The 2 GiB dataset forces DRAM on any chip. Light mode is about 8× slower via a constant memory-time product. Division is avoided: IMUL_RCP precomputes a reciprocal once per program. Source: design.md, https://github.com/tevador/RandomX/blob/master/doc/design.md
- **Audits:** Trail of Bits, X41 D-SEC, Kudelski and QuarksLab (2019, OSTIF). No critical findings; algorithm changes were made as a result; no significant optimisation found by the auditors [E].
  - Audits: https://github.com/tevador/RandomX (`audits/`)
  - QuarksLab report: https://blog.quarkslab.com/resources/2019-08-02-audit-monero-randomx/19-07-610-REP-monero-randomx-sec-assessment.pdf
- **Hardware outcome:** Bitmain Antminer X5 (212 kH/s, 1350 W, about 6.4 J/kH) and X9 (about 1 MH/s) are sold for RandomX. Reported CPU efficiency (Ryzen 7950X) is about 6–7.7 J/kH, so the X5's energy advantage is about 1–1.2×; the gain is density, not efficiency [E for availability; numbers are from secondary/vendor sources, not independently verified].
  - https://www.asicminervalue.com/miners/bitmain/antminer-x5
  - https://millionminer.com/news/monero-mining-guide-2026-antminer-x5-x9-pinecone-r1x-randomx
  - https://www.hashrate.no/cpus/7950x
- **RandomX v2 released 2026-03-25:** 384-instruction programs, conditional CFROUND, AES F/E mix.
  - https://github.com/tevador/RandomX/releases/tag/v2.0
  - https://github.com/tevador/RandomX/pull/274
  - Monero activation status is **[U]**, not verified here. If Monero moves to v2, BlackSilk's v1 is no longer "Monero's algorithm", and v1-only hashpower could look for a new home.
- **Lesson:** this is the best-documented CPU-oriented PoW that exists. Its ASIC margin appears small in energy terms, though that is [U] because vendor figures are not independently verified.

### 2.2 CryptoNight family (Monero 2014–2019): the closest ancestor of SKC-1

- **Commits to:** Keccak state, then a per-nonce 2 MiB scratchpad init via AES, then a read-modify-write loop with AES rounds and a 64×64→128 multiply, then a Keccak-selected final hash.
- **Variant 2 (2018)** added 64:32 integer division and integer square root "adding large and unavoidable computational latency", plus 64-byte-line shuffles.
  - https://github.com/monero-project/monero/pull/4218
  - https://github.com/SChernykh/sqrt_v2
- **CryptonightR (2019)** added random math: https://github.com/monero-project/monero/pull/5126
- **Hardware outcome** [E, historical]: CryptoNight ASICs (Bitmain X3, 2018) forced repeated forks (v7, v8/variant 2, R). Monero then adopted RandomX.
- **Lesson:**
  - A fixed, per-nonce, scratchpad-plus-multiply-plus-division design was the *failed* approach.
  - Division and square root raised ASIC latency but not ASIC throughput, which comes from many parallel instances.
  - The one-time "bricking" effect came from the *change*, not from the primitive.

### 2.3 Argon2 (RFC 9106; PHC winner)

- **Commits to:** memory blocks of 1 KiB filled with compression G, which is the BLAKE2b round with BlaMka multiplication `a+b+2·lo32(a)·lo32(b)`. Argon2d's reference index is data-dependent and uses a quadratic map `|W|(1−J1²/2^64)` that biases toward recent blocks. Later passes XOR the new value into the old block.
- **Rationale for the multiplication:** "increase the circuit depth and thus the running time of ASIC implementations, while having roughly the same running time on CPUs".
- **Known tradeoff:** the best known Argon2d attack, a ranking tradeoff, reduces the time-area product by about 1.33×. RFC 9106 names Argon2d for PoW/cryptocurrency use.
- Source: https://www.rfc-editor.org/rfc/rfc9106.html
- **Lesson:** every SKC-1 graph component has an analysed counterpart here, and that counterpart is already in the repository (`randomx/src/argon2d.rs`).

### 2.4 scrypt

- **Commits to:** ROMix: a sequential fill of n blocks, then n data-dependent reads of uniformly random earlier blocks.
- **Result:** Alwen, Chen, Pietrzak, Reyzin, Tessaro, "Scrypt is Maximally Memory-Hard" (Eurocrypt 2017). Cumulative memory complexity is Ω(n²) in the parallel random-oracle model [E]. https://eprint.iacr.org/2016/989
- **Hardware outcome:** Litecoin's scrypt (128 KiB parameter) went to ASICs in 2014 [E, historical].
- **Lesson:** a provable CMC bound does not prevent ASICs. Small memory parameters lose. The proof covers scrypt's structure (full fill, then uniform reads over the *completed* array), **not** SKC-1's one-pass "parent < i" graph.

### 2.5 Data-independent MHF theory

- Alwen–Blocki, "Efficiently Computing Data-Independent Memory-Hard Functions" (CRYPTO 2016): https://eprint.iacr.org/2016/115
- Alwen–Blocki, "Towards Practical Attacks on Argon2i and Balloon Hashing" (EuroS&P 2017): https://eprint.iacr.org/2016/759
- Alwen–Blocki–Pietrzak, "Depth-Robust Graphs and Their Cumulative Memory Complexity" (Eurocrypt 2017): https://eprint.iacr.org/2016/875
- **What they show** [E]:
  - iMHFs whose graphs are not depth-robust admit asymptotic CMC reductions.
  - Depth-robustness is the right graph property.
  - A sequential chain plus random edges is depth-robust only under specific edge distributions, and analysis is per graph.
- **Lesson:** "S[i] depends on S[i−1] and a random parent" is not automatically depth-robust or maximally hard. Proofs exist only for specific constructions (scrypt; DRSample/Argon2-like with caveats).

### 2.6 Tradeoff cryptanalysis

- Biryukov–Khovratovich, "Tradeoff Cryptanalysis of Memory-Hard Functions" (ASIACRYPT 2015): https://eprint.iacr.org/2015/227
- Ranking attacks on one-pass data-dependent designs, applied to Catena, Lyra2 and Argon2 predecessors [E].
- **Lesson:** a one-pass design must be evaluated against ranking and "store-every-k-th" attacks. Its index distribution decides the penalty.

### 2.7 Balloon hashing

- Boneh, Corrigan-Gibbs, Schechter (ASIACRYPT 2016): https://eprint.iacr.org/2016/027
- Provable space-hardness in the sequential model, from a standard hash. Later partially attacked by the depth-robustness results in 2.5 (parallel attacks, data-independent variant) [E].
- **Lesson:** build from a standard compression function and prove the graph. "Invented mixer + heuristic graph" is the opposite approach.

### 2.8 Bandwidth hardness

- Ren–Devadas, "Bandwidth Hard Functions for ASIC Resistance" (TCC 2017): https://eprint.iacr.org/2017/225
- An ASIC's *energy* advantage is bounded by memory-access energy only if the function forces off-chip bandwidth, which requires a working set larger than practical on-chip memory [E].
- **Lesson:** a 32 MiB working set does not force off-chip traffic on an ASIC (§3.2), so SKC-1 gets no bandwidth-hardness benefit.

### 2.9 Equihash (Zcash)

- Biryukov–Khovratovich, NDSS 2016: https://eprint.iacr.org/2015/946
- Asymmetric PoW: generalised birthday problem, cheap verification.
- **Hardware outcome:** Bitmain Z9 / Z9 mini (2018) reported about 20–30× more performance per watt than contemporary GPUs [E historical; vendor/secondary numbers]. https://www.asicminervalue.com/miners/bitmain/antminer-z9-mini
- **Lesson:** a memory-bound *sorting* workload with a fixed algorithm went to ASICs within about 2 years.

### 2.10 Cuckoo Cycle (Grin)

- Tromp, https://eprint.iacr.org/2014/059 and https://github.com/tromp/cuckoo
- Graph-theoretic, memory-latency-bound, instant verification.
- **Hardware outcome:** Grin ran a "GPU-friendly, ASIC-resistant" Cuckaroo variant tweaked every ~6 months next to an "ASIC-friendly" Cuckatoo31+/32. Cuckatoo ASICs (e.g. Obelisk, Innosilicon) appeared [E historical; secondary]. TSMC SRAM-density analyses were discussed in that community: https://forum.grin.mw/t/tsmc-5nm-sram-density/6395
- **Lesson:**
  - Scheduled tweak forks are the only demonstrated way a *fixed* algorithm keeps hardware general-purpose.
  - SRAM density decides which memory sizes an ASIC can hold on-die.

### 2.11 Ethash and ProgPoW

- Ethash's 1+ GiB DAG still got ASICs (Antminer E3, 2018) [E historical].
- ProgPoW (random programs tuned for GPUs; EIP-1057) had a third-party review (Least Authority, 2019):
  - Least Authority (software) and Bob Rao (hardware), 2019: https://github.com/ethcatherders/progpow-audit
  - Report: https://leastauthority.com/static/publications/LeastAuthority-ProgPow-Algorithm-Final-Audit-Report.pdf
- **Kik exploit (2020)** [E]: https://github.com/kik/progpow-exploit
  - The memory-hard part was keyed by a **64-bit seed**.
  - An ASIC fixes the seed, computes the mix once, grinds an extra-nonce to meet the difficulty, then grinds the nonce to hit the seed.
  - Result: memory hardness bypassed at 64-bit security.
- **Lesson (directly applicable to SKC-1):** every bit of the header and nonce must enter the memory-hard computation through a wide (≥256-bit, ideally 512-bit) state. No narrow intermediate may determine the expensive part.

### 2.12 Autolykos v2 (Ergo)

- Whitepaper: https://docs.ergoplatform.com/ErgoPow.pdf [citation not re-verified this session]
- Memory-hard via a large, height-growing table of k-element sums, GPU-oriented.
- **Hardware outcome:** no confirmed ASIC to my knowledge [U].
- **Lesson:** a *growing* table is a deliberate, scheduled anti-ASIC mechanism.

### 2.13 GhostRider (Raptoreum)

- Chains multiple CryptoNight variants with x16r-style randomly ordered hash functions.
- Cited from memory; not verified this session [U].
- **Lesson** [H]: composing many primitives multiplies implementation and determinism risk. The weakest or cheapest component sets the bottleneck. Mixing algorithms is not by itself evidence of hardness.

### 2.14 Hashpower rental and economics

- Bonneau, "Why Buy When You Can Rent?" (FC/BITCOIN 2016) [E]: https://jbonneau.com/doc/B16b-BITCOIN-why_buy_when_you_can_rent.pdf
  - Rented hashpower makes attacks on small chains cheap.
  - Algorithm choice changes the *rental pool*, not the principle.
- Qubic and Monero (Aug 2025) [E]:
  - Selfish mining with up to ~6-block reorgs and ~60 orphaned blocks.
  - A peer-reviewed measurement finds no *sustained* 51%.
  - https://arxiv.org/pdf/2512.01437 ; https://www.coindesk.com/business/2025/08/12/monero-s-51-attack-problem-inside-qubic-s-controversial-network-takeover
- **Lesson:** coordinated RandomX hashpower is mobile. A tiny RandomX chain is a cheap target for it.

---

## 3. Critical review of each SKC-1 component

### 3.1 Seed `BLAKE2b-256("BlackSilk/SKC1/Seed/v1" ‖ LE32 network_id ‖ LE64 height ‖ prev_id)`

- **Grinding:** `prev_id` is fixed once the parent exists, so a miner cannot grind it without mining the parent. The parent's miner chooses its own nonce, which changes the child's seed. That is harmless only if the seed creates no precomputable structure (no per-seed dataset). Under SKC-1 as specified there is none [H]. Height and network_id are fixed.
- **Manipulation:** a selfish miner who knows the parent early gets a head start, as in any PoW. Nothing specific to SKC-1.
- **Redundancy:** `height` and `prev_id` are already in the header, which also enters `Final`. The seed adds no new commitment. Its only role is domain separation, and it costs an extra hash per block template (negligible).
- **Critical gap:** the specification never states how `header ‖ nonce` initialises the scratchpad and state.
  - If initialisation depends only on the seed, all nonces share one scratchpad. An attacker computes it once and only the finaliser is per-nonce. **Total failure** of memory hardness.
  - If the nonce enters through a ≤128-bit intermediate, the ProgPoW-Kik class applies (§2.11).
  - **Requirement:** `init = BLAKE2b-512(domain ‖ seed ‖ LE32(len) ‖ full_header_with_nonce)`, expanded (Argon2-style H′) into the first blocks and the state.
- **Verdict:** **Retain**, demoted to a domain-separation prefix. **Redesign** the initialisation binding (mandatory).

### 3.2 Per-nonce 32 MiB scratchpad (262,144 × 128 B)

- **Degeneration and cross-nonce reuse:** with correct initialisation (3.1) no state is shared between nonces. Without a seed-wide dataset, however, there is also **no large shared structure** penalising small-memory parallel attackers beyond 32 MiB per instance.
- **CPU side** [H, from known hardware]:
  - Per-core cache is about 1–4 MiB L2 plus a share of L3 (e.g. 64 MiB L3 / 16 cores on a 7950X; 96–128 MiB on X3D parts).
  - With data-dependent parent reads over [0,i), the chain is mostly DRAM-latency-bound at ~70–100 ns per step. One instance would take ~262k × ~80 ns ≈ 20 ms, unless several instances are interleaved per core to hide latency, at 32 MiB each.
  - Performance becomes dependent on the L3 SKU (X3D vs non-X3D), so it is **not** evenly CPU-fair.
- **ASIC side** [E density / H consequence]:
  - TSMC N5 HD SRAM is about 31.8 Mib/mm² including assist overhead. 32 MiB = 256 Mib ≈ 8 mm².
  - A 300–400 mm² die can carry dozens of independent instances, each with ~1–2 ns random access.
  - This is the regime where Cuckatoo, scrypt and CryptoNight ASICs won. RandomX avoids it with its 2 GiB dataset.
- **GPU side** [H]: 24 GB holds about 700 instances. 128 B random reads match GPU access granularity well, and thousands of threads hide latency. This is plausibly GPU-competitive or GPU-favoured, as Ethash was.
- **16 MiB vs 64 MiB:**
  - 16 MiB fits entirely in large CPU L3, which helps some CPUs; it also halves ASIC SRAM cost.
  - 64 MiB raises the ASIC SRAM cost to ~16 mm² per instance, which is still on-die-feasible, and worsens CPU DRAM-latency exposure.
  - **No size in 16–64 MiB escapes the on-die SRAM regime.** Forcing off-chip memory needs ≥ several hundred MiB *shared* per seed, i.e. a dataset. That reintroduces RandomX's per-seed precomputation.
- **Verdict:** **Redesign.** The memory architecture must be decided on the CPU-cache vs ASIC-SRAM argument. Either:
  - (a) a small, cache-resident per-nonce scratchpad (≤2 MiB) **plus** a large per-epoch DRAM dataset (RandomX's architecture), or
  - (b) accept that a 16–64 MiB per-nonce design is ASIC-feasible and plan scheduled tweaks (Grin-style), stating that openly.

### 3.3 Dependency graph: `S[i] ← f(S[i−1], S[parent(i)])`, `parent = (state[0] ^ ROTL(state[5],19) ^ i) % i`

- **Structure:** a one-pass, single-lane, data-dependent graph. This is Argon2d with t=1, p=1 and a *uniform* index map, not Argon2's quadratic one.
- **Depth-robustness:** a path plus one uniform random back-edge per node is depth-robust with good parameters only in a probabilistic sense specific to the distribution. For data-dependent graphs the adversary also learns edges only at run time, which helps the honest side, but there is **no published CMC proof for this graph** [E: none known to me; U].
- **TMTO, store every k-th block** [H, standard analysis]:
  - A missing parent costs recomputing up to k−1 predecessors, whose own parents may also be missing (recursive penalty).
  - With a uniform index, block j is referenced about ln(n/j) times in expectation. The last half of the blocks are referenced < 0.7 times on average.
  - So an attacker keeps the early, heavily referenced blocks and drops late ones cheaply: the classic ranking attack.
  - Argon2 adopted its quadratic map toward recent blocks precisely to change this profile. Even so, its best tradeoff gains 1.33× in time-area.
  - **Expected:** SKC-1's uniform map has a *lower* TMTO penalty than Argon2d [H; must be measured by simulation, §9].
- **Modulo bias of `% i`:** for a 64-bit uniform x the bias is ≤ i/2^64 ≈ 2^−46. **Negligible.**
- **Real cost of `% i`:** a 64-bit variable-divisor division on every step: ~10–40 cycles depending on the CPU, an ASIC divider otherwise. Replace with Lemire's reduction `((x as u128 * i as u128) >> 64)`: no division, bias ≤ i/2^64.
- **Predictability:** the parent is known only after step i−1 completes. That serialises lookups (good against prefetch). The `^ i` term prevents fixed cycles. Using only two of 16 words for addressing is fine if SilkMix diffuses well (unproven, §3.4).
- **Verdict:** **Redesign.** Use the Argon2 index map (or a proven construction) and multiple passes with XOR overwrite (t ≥ 2) or a scrypt-style second phase over the completed array. Measure the TMTO penalty by simulation before any claim.

### 3.4 SilkMix (`m=(a|1)*(c|1); wide=a*b; state[k]=rotl(a,11+3k)+b+m+hi ^ lo`)

- **Precedence:** in Rust `+` binds tighter than `^`, so this is `(rotl(a)+b+m+hi) ^ lo`. The specification must state it explicitly.
- **`|1` tricks:**
  - The product of two odd numbers is odd, so `m` always has LSB = 1. This is a constant bit in every product, which shortens carry-chain analysis.
  - Forcing oddness removes one bit of entropy per operand. It avoids zero products but does not by itself create diffusion.
- **Fixed points:** an all-zero state is not a fixed point (m ≥ 1). Other weak states (e.g. a = 0 makes lo = hi = 0) leave the update affine in b and m for that step. No proof excludes short cycles or low-entropy orbits.
- **Diffusion** [E, arithmetic fact]:
  - The low k bits of `a*b mod 2^64` depend only on the low k bits of the operands, so information moves only upward in `lo`. Downward diffusion comes only from `hi` and the rotations.
  - Additions are also upward-only (carries).
  - So low bits of the state are a "triangular" function, the classic weakness exploited in ad-hoc ARX designs.
  - No differential or rotational analysis exists. Per-word updates may leave inter-word diffusion incomplete within a block step, depending on which "previous words" feed `a, b, c`; the proposal does not define the wiring.
- **Invertibility:** not required for PoW, but a non-bijective iterated map loses entropy. For a *random* function on a 1024-bit state the loss over 2^18 steps is ~log2(2^18/2) ≈ 17 bits, which is harmless. A *structured* map can lose far more (e.g. lanes forced odd, collapsing low bits) [H].
- **Better-established cores:**
  - BlaMka G, the BLAKE2b round with `2·lo32·lo32` multiplications (Argon2, RFC 9106): analysed, already implemented in the repository, and with CPU/ASIC latency reasoning in the RFC.
  - Optionally, one 64×64→128 `IMULH`-style step per block for CPU-favourable latency (as RandomX and CryptoNight do).
- **Verdict:** **Remove**, and replace with BlaMka-G (or the full Argon2 G over a 1 KiB block) plus one widening multiply. Inventing a mixing function brings unknown risk with no benefit, because hardware cost is set by the memory architecture, not by the mixer.

### 3.5 Dynamic division `q = s4/(s9|1)`, `r = s4%(s9|1)`

- **Determinism:** fine (u64, divisor never 0).
- **Effect on CPUs** [E, documented latencies]:
  - Integer division latency varies widely and is data-dependent on some cores: roughly 10–90 cycles on x86 generations, lower on recent Apple and AMD.
  - This produces **inter-CPU unfairness** rather than CPU-vs-ASIC asymmetry.
- **Effect on ASICs:** a pipelined divider adds latency per step, but throughput is recovered with parallel instances (§3.2). CryptoNight-v2's division plus square root "bricked" existing ASICs only because the algorithm *changed*; it did not stop the next generation.
- **RandomX's choice:** avoid in-loop division; precompute a reciprocal once per program (IMUL_RCP) "without giving [ASICs] a performance advantage" (design.md).
- **Verdict:** **Remove** (or replace with RandomX-style multiply-by-reciprocal). It adds latency, not CPU specificity.

### 3.6 Mutable scratchpad writes `idx = (s6 ^ ROTL(s15,37)) & MASK`

- **Write-target ambiguity:** `& MASK` targets the whole pad, including indices ≥ i not yet filled. Those writes are dead (later overwritten by the fill), and their effective rate depends on i. Writes should target `[0, i)` (Lemire reduction) or happen in a separate pass.
- **TMTO effect** [H]:
  - Overwriting earlier blocks makes stored checkpoints stale. Recomputing block j then requires its write history, which raises the TMTO penalty.
  - Argon2 v1.3's XOR-overwrite in later passes serves the same purpose and is analysed.
  - RandomX's scratchpad writes (≈2:1 read/write, design.md) serve CPU realism.
- **ASIC effect:** none if the whole pad sits in SRAM (CryptoNight was fully read-modify-write and was still ASIC'd).
- **Verdict:** **Retain the idea; redesign the mechanism.** Use defined XOR-overwrite semantics in-range, preferably as Argon2 multi-pass. Do not count it as an ASIC defence.

### 3.7 BLAKE2b-512 checkpoints every 2048 blocks

- **Value:** 128 standard-primitive diffusion barriers per hash, which cap the reach of any SilkMix differential or algebraic shortcut to ≤2048 steps [H, sound reasoning].
- **Overhead:** about 128 BLAKE2b compressions per hash, ≪1% [H].
- **Redundancy:** if the mixer itself is the BLAKE2b round (3.4), they are unnecessary.
- **Verdict:** **Retain only if an invented mixer survives.** Otherwise **remove** as redundant. They are not a security argument in themselves.

### 3.8 Finalisation `BLAKE2b-256("…Final/v1" ‖ network_id ‖ seed ‖ full_header ‖ final_state ‖ selected words)`

- **Output bias and distinguishers:** with BLAKE2b-256 as the last step, output bias against `check_hash` reduces to BLAKE2b's PRF/RO behaviour. No distinguisher is known [E, BLAKE2 cryptanalysis to date]. Low-entropy *inputs* (e.g. a degenerate state) cannot bias outputs, but they *can* create shortcuts: if final_state is cheap to obtain, the hash is cheap. Hardness lives entirely upstream.
- **Selected words:** final_state already depends on every step. Selected words add value only if they force the *whole* pad to stay live until the end (RandomX hashes the full 2 MiB with AesHash1R; Argon2 XORs the final blocks of lanes).
  - A fixed small selection adds ~nothing.
  - A full-pad BLAKE2b over 32 MiB costs about tens of ms (prohibitive).
  - A cheap full-pad fold (XOR/AES-like) could be justified only by the TMTO simulation.
- **Serialisation:**
  - Include `LE32(len(header))` and the header version, so the omr change (100 → 140 B) and any future format cannot create ambiguous concatenations.
  - The fields are otherwise fixed-length, which is unambiguous today.
  - The domain tags are good practice.
  - `network_id` is duplicated (seed and final), which is harmless.
- **Verdict:** **Retain** (domain-separated BLAKE2b-256 finaliser, length-tagged). **Remove** "selected words" unless the simulation shows a TMTO gain.

### 3.9 Cross-cutting implementation requirements (pure Rust, deterministic)

- Every arithmetic operation must be `wrapping_*`. Debug builds panic on overflow, so debug and release builds would disagree in behaviour.
- `u128` multiply, rotations, division and BLAKE2b are deterministic on x86_64 and aarch64 [E, Rust semantics].
- No floats, no `unsafe`: feasible.
- The repository already shows the hidden cost: the RandomX port needed 6 official vectors, mutation runs and full/light agreement checks. **SKC-1 would have no external reference implementation or vectors.** Its only "spec oracle" would be the project itself.

---

## 4. Threat model

- **Assets:** chain immutability and finality (K1), fair issuance, node availability (verification DoS), and decentralisation of mining hardware. Privacy is indirect: pool centralisation concentrates miner IP metadata.
- **Adversaries:**
  - **A1. Rented commodity hashpower** (cloud CPUs/GPUs, NiceHash-like markets).
  - **A2. Botnets** (CPU-heavy).
  - **A3. Coordinated large miners or pools of a sister chain** (Qubic-type, RandomX).
  - **A4. Custom hardware vendors** (FPGA/ASIC), with economic thresholds tied to market cap.
  - **A5. Cryptanalyst** seeking shortcuts (TMTO, algebraic or differential shortcut in the mixer, Kik-style binding bypass).
  - **A6. DoS peer** sending junk headers to exhaust verification.
  - **A7. Implementation-divergence attacker** exploiting consensus differences between builds, platforms or versions.
- **Mapping to the algorithm choice:**
  - A1 and A2 are not stopped by *any* algorithm on a small chain [E, Bonneau].
  - A3 is specific to sharing an algorithm with a large chain (RandomX today).
  - A4 is about the memory architecture (§3.2).
  - A5 is the main new risk of an invented design.
  - A6 favours cheap verification. SKC-1 is ~1 hash (better than pure-Rust RandomX light).
  - A7 is higher for an unreferenced novel algorithm.
- **Out of scope:** economic security sizing (Agent B).

---

## 5. Key question: what does "dependence on Monero's algorithm" mean in practice?

1. **Code dependence:** none. The port is pure Rust, owned and frozen at v1, and verified against official vectors. Monero's governance cannot change BlackSilk's rules.
2. **Merge mining:** impossible as designed. BlackSilk hashes its own 100 B (soon 140 B) header with its own seed. There is no aux-PoW commitment, so Monero work is never directly reusable [E, from code].
3. **Hashpower fungibility (the real issue)** [E/H]:
   - Every RandomX-capable machine can mine BlackSilk via a thin adapter: blob, nonce offset 92 and target format (R9 §5). (Correction, output-root: the offset is compiled into xmrig, so v3 hashes a 47-byte mining blob with the nonce at byte 39, docs/consensus.md §3.) That covers xmrig rigs, botnets, Qubic-style pools, and the X5/X9 ASICs if their firmware accepts arbitrary key and blob [U].
   - At testnet or early-mainnet difficulty, a fraction of a percent of Monero's hashrate dominates BlackSilk.
4. **Ecosystem reputation:** botnets favour RandomX because it runs on any CPU. Being on RandomX makes BlackSilk part of that target set.
5. **Benefits of sharing:**
   - Four external audits and years of cryptanalysis.
   - Mature open miners, so hardware decentralisation is real even if BlackSilk's own miner is slow.
   - Determinism and reference vectors.
6. **Tweaking RandomX parameters** (salt or sizes, as Wownero, Arweave and others did):
   - Separates the *zero-effort* path only; xmrig adds variants quickly (R9).
   - Gives up direct reuse of the audits; parameters within documented safe ranges keep most of the analysis.
   - Does not affect A1 or A2.
7. **Monero's move to RandomX v2:** if activated [U], it would by itself make BlackSilk's v1 distinct from Monero's live algorithm. This deserves to be tracked: it changes A3 without any BlackSilk action.

**Conclusion:**
- The "dependence" is a *shared-hashpower* exposure (A3), not a code or governance dependence.
- SKC-1 would trade A3 for A5 and A7 (novel-cryptanalysis and divergence risk) and a likely-worse A4 (32 MiB on-die SRAM).
- A1 and A2 remain whatever the algorithm.
- The A3 exposure is better mitigated by:
  - (a) minimum-chain-work and anti-DoS policy;
  - (b) honest documentation that a small RandomX chain is cheaply attackable;
  - (c) tracking RandomX v2;
  - (d) only if needed, a parameter-level RandomX variant within the reference's documented configuration bounds, rather than a new primitive.

---

## 6. Recommendations per component

| Component | Recommendation | Evidence |
|---|---|---|
| Seed hash | Retain, as domain separation only | §3.1 |
| Header/nonce → scratchpad binding | **Redesign (mandatory, unspecified today)**: 512-bit BLAKE2b of the length-tagged full header incl. nonce, expanded H′-style | Kik / ProgPoW [E] |
| 32 MiB per-nonce pad | **Redesign**: choose the RandomX-like split (cache-resident pad + DRAM dataset) or accept ASIC-feasibility with a tweak schedule | SRAM density [E], Ren–Devadas [E], CryptoNight history [E] |
| One-pass uniform-parent graph | **Redesign**: Argon2 index map, ≥2 passes with XOR overwrite, or a scrypt-style 2nd phase; simulate TMTO | RFC 9106, ePrint 2015/227, 2016/989 |
| `% i` | Replace with multiply-high reduction | §3.3 |
| SilkMix | **Remove**: use BlaMka-G (Argon2 G) + one 64×64→128 multiply | RFC 9106 rationale |
| Division | **Remove**, or reciprocal-multiply | RandomX design.md; CNv2 history |
| Mutable writes | Retain the concept, redesign as in-range XOR-overwrite passes; not an ASIC defence | Argon2 v1.3, CryptoNight |
| BLAKE2b checkpoints | Remove if the mixer is BLAKE2b-based; else retain as a cheap barrier | §3.7 |
| Finaliser | Retain (length-tagged, domain-separated BLAKE2b-256); drop "selected words" unless simulation shows a benefit | §3.8 |
| Pure Rust / no floats / wrapping ops | Retain (a genuine advantage: no JIT gap, simpler determinism) | R9 |

**Overall research verdict on SKC-1 as proposed: REDESIGN REQUIRED.**

---

## 7. What a defensible redesign would look like (for research only)

"SKC-1r" is essentially a parameterised Argon2d-PoW: BLAKE2b init, Argon2d G and index map, t ≥ 2, one IMULH per block, length-tagged finaliser.

**Its honest pitch:**
- No per-epoch caches, so verification costs one hash with bounded memory.
- Near-optimal in safe Rust.
- Not Monero-shared.

**Its honest weakness:** a 16–64 MiB per-nonce MHF sits in the on-die-SRAM regime, so expect FPGA/ASIC/GPU efficiency gains until measured otherwise. That is the same fate as scrypt, CryptoNight, Equihash and Cuckatoo.

**The alternative "RandomX-like" architecture:** large per-epoch dataset plus random code. It converges back on RandomX, which BlackSilk already has in pure Rust. (RandomX's design had external reviews in 2019; BlackSilk's port has not been externally audited.)

---

## 8. Overall recommendation

- **Keep RandomX v1 for the testnet.** It is the only option here with external audits, reference vectors and demonstrated, near-parity CPU/ASIC energy efficiency [E with caveats].
- **Address the actual risk (A3/A6) with policy:**
  - minimum chain work;
  - DoS penalties;
  - documented small-chain exposure;
  - monitoring of RandomX v2 adoption.
- **SKC-1 status: REDESIGN REQUIRED.** The redesigned SKC-1r variant (§7) is **INSUFFICIENT EVIDENCE** for anything beyond a time-boxed offline research prototype under the §9–10 criteria. It is **NOT RECOMMENDED** as a production replacement for RandomX on current evidence.
- Any switch is a consensus change needing owner approval. It should be decided before the final genesis freeze or deferred to a scheduled post-launch fork.

---

## 9. Assumptions requiring experimental validation

1. **[U]** TMTO penalty curve of the (re)designed graph at memory fractions 1/2…1/8, from a pebbling/ranking simulation using the actual index distribution. It should be compared with Argon2d t=1 and t=3 under the same simulator.
2. **[U]** Entropy retention of the mixer over 2^18 steps (collision and cycle statistics on reduced-size states, e.g. 16/32-bit-lane analogues). Includes bit-bias tests on the low bits of state words.
3. **[U]** Output uniformity at the `check_hash` boundary: chi-square on leading-zero distributions over ≥2^24 hashes (sanity check only; BLAKE2b finalisation makes failure unlikely).
4. **[U]** Per-hash CPU time and memory-latency profile across x86_64 (L3 SKUs incl. X3D) and aarch64. Determines CPU fairness (Agent B's domain).
5. **[U]** GPU throughput of an optimised kernel per watt versus CPU, which requires an adversarial implementation effort.
6. **[U]** Rough ASIC/FPGA estimates from SRAM area and multiplier/divider latency (paper model).
7. **[U]** Cross-platform determinism: identical hashes on x86_64/aarch64, debug/release, and different rustc versions, over ≥10^6 random headers.
8. **[U]** Kik-style binding analysis: no intermediate below 256 bits determines the memory-hard computation (design review plus a test that flipping any header bit changes the first block).
9. **[U]** Whether RandomX ASIC firmware (X5/X9) accepts arbitrary keys and blobs, i.e. whether it already applies to BlackSilk.
10. **[U]** Monero's activation status of RandomX v2.

---

## 10. Measurable success criteria for a future prototype (definitions only)

- **S1 Specification completeness:**
  - A normative spec with byte-exact serialisation, operator precedence, wrapping semantics, length tags and domain tags.
  - An independent second implementation (e.g. a stdlib Python script, as for LWMA) reproduces ≥1000 vectors bit-exactly.
- **S2 Determinism:** 0 mismatches over ≥10^6 random inputs across {x86_64, aarch64} × {debug, release} × {two rustc versions}.
- **S3 TMTO:** under the published simulator, the time × memory product at every memory fraction ≥ 1/8 is ≥ the full-memory product (no tradeoff gain >1.0×). The penalty is reported against Argon2d at equal parameters.
- **S4 Binding:** a documented proof sketch that every header bit enters a ≥256-bit state before the first memory access, plus tests showing any single-bit flip changes the first scratchpad block.
- **S5 Statistical:** the mixer passes avalanche (~50% ± 1% per output bit per input bit flip over one step). The final hash passes chi-square uniformity at α = 0.01 over ≥2^24 samples.
- **S6 Verification cost:** p99 verification time and peak RSS per header on a reference node, and the ratio of verify cost to best-known miner cost per hash. Target ≤ 10×; RandomX pure-Rust light vs xmrig is ~300–500× today.
- **S7 Hardware-efficiency estimates** (Agent B co-owns): a documented GPU and ASIC efficiency estimate relative to a reference CPU, with methodology. Acceptance thresholds are set by the owner *before* measurement.
- **S8 Review:** the multi-pass internal review log is completed, with any external cryptanalysis an explicit owner decision. Internal review is labelled as internal, never as an audit.

---

## 11. Citations

The URL and what each supports appear inline in §2. Primary:
- RFC 9106
- tevador/RandomX design.md, audits, v2 release
- QuarksLab RandomX audit
- ePrint 2016/989, 2016/115, 2016/759, 2016/875, 2015/227, 2016/027, 2017/225, 2015/946, 2014/059
- ProgPoW audit repository and Least Authority report
- Kik's progpow-exploit
- Monero PRs #4218 and #5126
- Bonneau 2016
- arXiv 2512.01437 (Qubic measurement)

Secondary or vendor (flagged where used): Antminer X5/X9 and Z9 specifications and efficiency, 7950X efficiency, Grin forum SRAM thread, CoinDesk. Not re-verified this session: Autolykos PDF URL, GhostRider details, Ethash E3 specifics, exact CPU divide latencies.

Finish: 2026-10-04T09:52:19+02:00
