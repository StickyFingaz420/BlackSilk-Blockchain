# SKC-1 (SilkChain-1) research report B: performance, hardware economics, security

> Historical record (2026-10-04). Superseded where it conflicts with the code: RandomX uses BlackSilk's Argon2 salt "BlackSilk/RandomX/v1", not Monero's rx/0 salt (RX-SALT, 3e3e9ca); the header is 172 bytes (output-root commitments, f5daa0e) and the PoW input is the 47-byte mining blob with the nonce at byte 39 (921fdd5); both were adopted after this report. Current: [docs/consensus.md](../consensus.md), [docs/STATUS.md](../STATUS.md).

- Agent: SKC-1 Research Agent B. This is internal research, not an audit, and no measurements were made. Every number is either cited or a labeled back-of-envelope estimate.
- Started: 2026-10-04T07:44:19Z. Finished: see the footer.
- Scope: theoretical modeling only. No builds, tests or benchmarks were run, and no repository file was changed. Agent A's notes were not read.
- Repository facts used (read-only):
  - BlackSilk's PoW is unmodified RandomX v1, the same variant Monero uses (`randomx/src/config.rs`: `ARGON_SALT = b"RandomX\x03"`, the stock scratchpad sizes; `randomx/README.md`). The key is the seed block id: `seed_epoch` 2048, `seed_lag` 64.
  - Block time is 120 s on mainnet and testnet (`consensus/src/params.rs`).
  - Pure-Rust light-mode verification takes 548 ms per header on 1 thread (release build) and 159 ms per header on 4 threads (`docs/evidence/pow-pool-2026-10-01/logs/after-idle.log`).
  - The pure-Rust full-mode miner does about 10 H/s per thread. A JIT miner does about 700 H/s per thread, so the gap is about 70× (`docs/reviews/full-review-2026-09-27/R12-performance.md:528`, `R9-randomx.md`).

## 0. Executive summary

1. **The rental and redirection risk under stock RandomX v1 is real and severe, and it is the strongest argument for changing the PoW.**
   - BlackSilk hashes with exactly Monero's RandomX v1. Any xmrig instance, NiceHash buyer or large RandomX pool can point at BlackSilk without code changes.
   - At launch, honest BlackSilk hashrate will be about 10⁻⁶–10⁻⁴ of the global RandomX hashrate (Monero alone is about 6 GH/s).
   - Honest participants also run a pure-Rust miner about 70× slower per core than the xmrig an attacker would use.
   - A one-day majority can be rented for **single-digit dollars** (§4). Qubic showed in August 2025 that one entity can move GH/s-scale RandomX hashrate at will.
2. **SKC-1 as specified does not fix this robustly, and it likely loses on ASIC resistance.**
   - The core problem is that per-nonce memory is *symmetric*: the verifier pays the same memory as the miner per hash. That forces the memory to stay small, and 32 MiB is small enough to hold in on-die SRAM. AMD's 64 MB V-Cache die is 36–41 mm² at 7 nm, so 32 MiB is about 18–20 mm².
   - An SRAM-resident fixed-function datapath (mul, div, ALU ops, BLAKE2b) is the textbook ASIC case. My estimated ASIC/CPU energy advantage is **~10–200×**. The commercial RandomX ASIC (Antminer X5, vendor spec 157 H/J) is only about 1–2× a modern CPU.
   - RandomX forces ASICs to use DRAM through a *shared* 2 GiB dataset with a 256 MiB light mode for verifiers. SKC-1 has no equivalent asymmetric structure.
3. **SKC-1 is memory-bandwidth-bound on CPUs unless compute per step is large.**
   - Each hash moves about 67–170 MB of DRAM traffic, about 100× RandomX's roughly 1 MiB. A 16-core desktop saturates dual-channel DDR5 with about 3–4 cores.
   - That favors 12-channel servers, GPUs (1–3 TB/s) and HBM ASICs, which is the opposite of the "CPU-fair" goal.
   - The design's best anti-GPU lever is **data-dependent 64-bit division combined with the per-nonce memory cap**. The memory cap limits GPU occupancy, so a GPU cannot hide its slow emulated 64-bit division (§2). That lever also penalizes older Intel CPUs, where 64-bit DIV takes 39–94 cycles.
4. **Real strengths:**
   - Verification would be about 15–80 ms with 32 MiB, against BlackSilk's current pure-Rust RandomX light mode at 548 ms with a 256 MiB cache and a 0.6–1.2 s cache build on every key switch.
   - Without a JIT, a safe pure-Rust miner can be within about 2× of an optimal miner. That closes the 70× honest-vs-attacker gap.
   - There is no per-epoch key cache to precompute or amortize.
5. **Likely design flaws found:**
   - A one-pass fill with uniform parents leaves late blocks rarely referenced, which weakens TMTO resistance (§3.3).
   - Checkpoint hashing could become a BLAKE2b-bound, ASIC-friendly component (§1.4).
   - The seed must absorb the nonce and the full header, or the scratchpad becomes amortizable (§4.1).
6. **Recommendation: REDESIGN REQUIRED**, with INSUFFICIENT EVIDENCE for any claimed superiority over RandomX.
   - Do not prototype SKC-1 as specified.
   - Address the rental risk first with cheaper, well-understood options: a BlackSilk-specific RandomX configuration, merge-mining, and confirmation policy (§4.5).
   - In parallel, prototype only a revised SKC-1 in isolation if the owner wants to keep that path open (§6).

## 1. Cost model per hash (CPU)

### 1.1 Assumptions

Parameters taken from the proposal:
- N = 262,144 blocks × 128 B = 32 MiB per nonce.
- Fill step i reads S[i−1] (hot in L1 or registers) and S[p], where p is data-dependent and earlier than i. It then mixes with a 64×64→128 multiply and one 64-bit division, and writes S[i].

Choices the proposal leaves open (labeled assumptions):
- **A1:** phase 2 performs W = N random read-modify-writes. W = 0 is "fill only".
- **A2:** each step's critical path is c = 30–80 core cycles, including one DIV: Zen 4 10–18 cycles, Ice Lake 14–18, Skylake 39–94; uops.info, Agner Fog.
- **A3:** a checkpoint hashes only a 64 B running state, not the 256 KiB of blocks. §1.4 covers the other case.

Hardware figures:
- DDR5 random-access latency is about 80–110 ns.
- Dual-channel DDR5 delivers about 60–80 GB/s peak, of which roughly 40–50 GB/s is usable for random 128 B accesses.
- 128 B is two 64 B cache lines; the adjacent-line prefetcher helps.

### 1.2 Traffic per hash

- **Fill:** each step does a 128 B random read plus a 128 B write, and possibly a 128 B read-for-ownership (RFO). That is 256–384 B per step, or **67–100 MB per hash**.
- **Phase 2 (W = N):** adds about 256 B per step, for **~134–170 MB per hash** in total.
- **RandomX full mode for comparison:** 8 programs × 2048 iterations × one 64 B dataset read is about 1 MiB of DRAM per hash. The scratchpad stays in L2/L3, and the dataset address is known one iteration early, so the access is prefetchable.
- SKC-1 therefore moves about **70–170× more DRAM bytes per hash**, and each parent address is known only after the previous step completes.

### 1.3 Latency-bound and bandwidth-bound regimes

**Single nonce per thread (naive reference, and how a verifier runs):**
- Step time is about L_mem + c/f = 90–130 ns when data is in DRAM. The fill takes **24–34 ms**; with phase 2, 50–70 ms. Throughput is about 15–40 H/s per thread.
- When the scratchpad is L3-resident (L3 latency about 10–15 ns), the fill takes **6–9 ms**.
  - One 32 MiB scratchpad fits on a 96 MB X3D part or on a 36 MB Intel L3 if nothing else runs there.
  - It is borderline on a 32 MB Zen 4 CCD.
  - It never fits for 8+ threads.

**Interleaved nonces per thread (what any optimized miner does; safe Rust can do it too, because out-of-order execution overlaps independent loads):**
- Throughput rises until the DRAM bandwidth limit: 45 GB/s ÷ 256 B ≈ 176 M steps/s, about **670 fills/s for the whole desktop** (about 330 H/s with phase 2).
- Compute-bound capacity is 16 cores × 4.5 GHz ÷ 50 cycles ≈ 1.4 G steps/s, which is 8× more. So **the desktop is bandwidth-bound, and roughly 3–4 cores saturate memory.**
- To make a 16-core dual-channel desktop compute-bound needs c ≥ 16 × 4.5e9 × 256 ÷ 45e9 ≈ **410 cycles per step**. That gives about 107 M cycles per fill (≈ 24 ms per hash per core, and the same verification time).

**Consequences:**
- Hashrate scales with memory channels, not cores. A 12-channel DDR5 EPYC (about 460 GB/s, of which about 300 GB/s is usable) reaches about 1.2 G steps/s, roughly 4,500 fills/s, or about 7× the desktop.
- Large-L3 parts get a qualitative boost. EPYC-X with 1,152 MB of L3 holds about 36 nonces fully in cache.
- Laptops and phones fall far behind.

### 1.4 Checkpoint ambiguity

If each BLAKE2b-512 checkpoint absorbs its 2048 blocks (256 KiB), each hash also BLAKE2b-hashes 32 MiB:
- At about 3–5 cycles per byte that is 100–170 M cycles (≈ 25–40 ms), which roughly doubles the CPU cost.
- That added cost is spent on a primitive ASICs run very efficiently (BLAKE2b ASICs exist for Sia and Decred).

Recommendation: checkpoints should absorb only a compact running state, or be dropped.

### 1.5 Verification cost (every node, every header)

| Variant | Memory per verify | Time, DRAM-resident | Time, L3-resident | 1 year of headers (262,800), 8 threads |
|---|---|---|---|---|
| SKC-1 16 MiB | 16 MiB | 12–35 ms | 3–8 ms | ~4–20 min |
| SKC-1 32 MiB | 32 MiB | 24–70 ms | 6–18 ms | ~13–40 min |
| SKC-1 64 MiB | 64 MiB | 50–140 ms | rarely resident | ~27–80 min |
| BlackSilk RandomX light (pure Rust, measured) | 256 MiB cache, shared, plus 2 MiB | 548 ms on 1 thread, 159 ms per header on 4 threads | n/a | ~1.5–5 h, plus cache builds |
| RandomX light, reference C++ | 256 MiB | ~14.8 ms (design.md) | | |

DoS:
- An invalid-PoW header costs a verifier about 25–70 ms and 32 MiB before rejection, so one core rejects about 15–40 headers per second.
- That is 10–20× cheaper per header than today's pure-Rust RandomX. The existing defenses still apply: PoW is checked only for headers that connect to a known chain, peers are scored, and the PoW pool's concurrency is bounded.
- Verifiers must reuse fixed 32 MiB buffers from a bounded pool. A per-header allocation multiplies page-fault cost (about 8,192 first-touch faults) and creates a memory-pressure vector.
- There is no seed-switch cache build, which removes a known stall source.

## 2. GPU analysis

Assumed RTX 4090 figures: 24 GB GDDR6X, about 1 TB/s, 72 MB L2 (Chips and Cheese). VRAM latency under load is assumed at about 400–600 ns (not quoted by the cited source; to be measured).

### 2.1 Capacity

- 24 GB holds about **700 concurrent nonces** at 32 MiB. With 80 GB (A100 or H100) it is about 2,400.
- 700 threads is about 22 warps across 128 SMs. A 4090 can hold about 196k resident threads, so this is **under 0.5% of maximum occupancy.**

### 2.2 Little's law

- Saturating about 750 GB/s effective at 256 B per step needs about 2.9 G steps/s. That requires 2.9e9 × 0.5 µs ≈ 1,450 nonces in flight, but only about 700 fit.
- So the GPU is **capacity- and latency-bound**: throughput ≈ 700 ÷ (L_vram + t_compute).

### 2.3 Compute per step on GPU

- There is no native 64-bit integer multiply. The 64×64→128 product needs about 4–8 32-bit IMAD.WIDE instructions.
- 64-bit division is a software routine. NVIDIA states that even 32-bit integer division and modulo compile to up to 20 instructions; my 64-bit estimate is about 70–150 instructions with branches (to be measured).
- At about 0.5% occupancy, each thread runs at dependent-instruction latency of about 4–6 cycles per instruction at about 2.5 GHz.
- With one division per step, t_compute is about 0.3–0.7 µs and a step takes about 0.8–1.3 µs. That gives **about 0.5–0.9 G steps/s, or about 2,000–3,400 fills/s at about 350–450 W.**

### 2.4 Ratios (H/J, fill only), with explicit assumptions

| Device | Estimated fills/s | Power | H/J |
|---|---|---|---|
| Desktop 16-core, DDR5 dual-channel, bandwidth-bound | ~670 | ~120–170 W | ~4–6 |
| RTX 4090, 1 division per step | ~2,000–3,400 | ~400 W | ~5–9 |
| RTX 4090 with TMTO to ½ memory (if compute is spare) | up to ~2× | | ~8–15 |
| 12-channel EPYC | ~4,500 | ~400 W | ~11 |

- **GPU:desktop-CPU energy ratio is estimated at about 1–3× for the design as specified**, up to about 4× if the GPU spends spare compute on TMTO.
- Capital efficiency: a 4090 at about $1.8k gives about 1–2 H/s/$. A desktop at about $1.2k, already owned by most miners, gives about 0.5 H/s/$.

### 2.5 Does the sequential chain limit GPUs?

Partly, and only **because of the per-nonce memory cap**:
- Massive nonce parallelism normally lets GPUs win. Ethash used the same 128 B random-access unit and was GPU-dominated.
- Here, 32 MiB per nonce caps concurrency far below what is needed to hide both VRAM latency and slow 64-bit arithmetic.
- **Making each step division-heavy turns this into an anti-GPU lever.** For example, 4 dependent 64-bit divisions per step:
  - add about 1–2.5 µs per step on GPU, which roughly halves to thirds GPU throughput;
  - add only about 40–70 cycles (about 10–15 ns) on Zen 4 or Ice Lake.
- The same lever costs Skylake-era Intel about 160–380 cycles per step, a fairness problem (§5).
- It is also weak against ASICs: a radix-16 64-bit divider is cheap.
- GPU-side tricks to model:
  - spreading one nonce's 128 B block across 16 lanes cuts per-step compute latency if the mixing has intra-block parallelism;
  - L2 residency (72 MB holds 2 nonces) is negligible.
- **Design implication:** keep mixing strictly serial within a step (no 16-way lane parallelism), so lane-splitting buys nothing.

## 3. FPGA and ASIC threat model

### 3.1 SRAM-resident ASIC (the main threat)

- 32 MiB of SRAM is about 18–20 mm² at 7 nm (V-Cache: 64 MB in 36–41 mm²). SRAM scaling has stalled at N5/N3, so it stays at about 15–20 mm².
- A 400 mm² die fits about 20 nonce engines, or about 40 with a ½-memory TMTO.
- One step takes SRAM latency of about 2–5 ns plus a 3-cycle multiply and a 16–20 cycle divide at about 1.5 GHz. That is about 10–20 ns per step, so each engine does about 200–400 H/s.
- A die therefore does about **4,000–16,000 H/s** at about 15–40 W, including SRAM leakage.
- Energy estimates:
  - Large on-chip SRAM access is about 0.5–2 pJ/bit, so 2 × 1,024 bits per step is about 1–4 nJ, plus about 0.1–0.5 nJ of arithmetic.
  - Bandwidth-bound desktop CPU: about 0.7–1 µJ per step at the package.
  - **Estimated ASIC/CPU energy ratio: about 50–200× (conservatively 10× after a 5–20× error allowance).** Horowitz's ISSCC 2014 relative energies support the order of magnitude: DRAM access ≫ SRAM ≫ integer ALU.
- Comparable examples:
  - RandomX ASIC (Antminer X5, 6.37 J/kH ≈ 157 H/J) against a modern CPU running xmrig at about 100–130 H/J: about 1.2–1.6×.
  - Equihash (about 144 MB per instance, and believed ASIC-resistant): the Antminer Z9 mini at about 33 Sol/J against a GTX 1080 Ti at about 3.6 Sol/J is about 9×.
  - Ethash Antminer E3: about 2× a GPU per joule. ProgPoW's audit gives about 1.2× for an ASIC over a GPU, against 2× on Ethash.

### 3.2 DRAM/HBM ASIC and FPGA

**HBM3 ASIC:**
- One stack is about 819 GB/s and 24 GB, about 750 nonces.
- Saturating it needs about 3.2 G steps/s × about 150 ns (an ASIC's memory controller is faster than a GPU's), about 480 nonces in flight, which fits.
- That gives about **12,000 fills/s per stack** at about 8–10 nJ per step (about 4 pJ/bit), which is about 50–100× the CPU in energy.
- Ren and Devadas' bandwidth-hard argument bounds ASIC gains only when the ASIC must use off-chip memory, and the SRAM option voids it here.

**FPGA:**
- A VU9P (as in AWS F1) has about 43 MB of on-chip memory, enough for 1–2 nonces, so it is marginal.
- An HBM FPGA (Alveo U280: 8 GB HBM2, about 460 GB/s) holds about 250 nonces and is plausible.
- The 64-bit divider is the main logic cost.
- FPGAs are a realistic threat in the early phase, at small scale, as on past "ASIC-resistant" coins.

### 3.3 Time-memory tradeoff (TMTO)

**Naive model (store every k-th block, uniform parent p in [0, i)):**
- Recomputing a missing block walks d forward from the last stored block, with E[d] ≈ k/2. Each recomputed block's parent is itself missing with probability 1 − 1/k.
- Expected recompute cost per missing block: R = (k/2)(1 + (1 − 1/k)R).
  - k = 2: R = 2, so the overhead is about 1 extra block per fill step, a **penalty of about 2× at ½ memory**.
  - k ≥ 3: the naive recursion diverges, so in practice it is huge but bounded by depth. Smarter strategies (ranking, keeping hot blocks) give finite, Argon2d-like curves.

**Structural weakness of a uniform single pass:**
- Block j's expected reference count during the fill is Σ_{i>j} 1/i ≈ ln(N/j). So:
  - the last half of the blocks average about 0.31 references each;
  - the last quarter average about 0.14;
  - the earliest blocks get about 10 or more.
- An attacker stores the early, high-rank region densely and the tail sparsely, at little cost.
- Argon2's non-uniform (recent-biased) index map and multiple passes exist precisely to close this. Argon2's 1-pass penalty table is only a lower benchmark, and RandomX uses 3 passes.
- **Fix:** a phase 2 with ≥ N uniform reads over the *final* array, or ≥ 2 fill passes, or an Argon2-style map. Data-dependent writes further raise TMTO cost because the attacker must track block versions, but they make analysis and testing harder.

**Reference curve (Argon2d 1-pass ranking attack, Argon2 spec), memory fraction α → compute penalty C(α):**
- ½ → 1.5
- ⅓ → 4
- ¼ → 20.2
- ⅕ → 344
- ⅙ → 4,660
- 1/7 → 2^18

The best area-time point is near α ≈ ½ (α·C = 0.75).

**Expected SKC-1 curve (hypothesis to be measured):**

| Memory | Uniform, 1-pass, no phase 2 | With phase 2 or 2 passes |
|---|---|---|
| 75% | 1.1–1.3× | 1.2–1.5× |
| 50% | 1.5–2× | 2–3× |
| 25% | ~3–20× (tail weakness) | 20–100× |
| 12.5% | 10²–10⁴× | ≥ 10⁴× |
| 6.25% and 3.125% | ≥ 10⁴× | infeasible (≥ 2^30) |

The ASIC conclusion holds regardless: the attacker uses about ½ memory with about 1.5–2× compute, and because the SRAM area is the large term, that improves the ASIC's AT product by about 1.3×.

### 3.4 Algorithmic versus economic resistance

- **Algorithmic:** SKC-1 is a fixed datapath. It lacks RandomX's random programs, branches, floating point and large instruction-level structures, which force an ASIC to become a CPU (the X5 is RISC-V-based). Its only barrier is memory, and that memory is SRAM-feasible. **Algorithmic ASIC resistance is weak.**
- **Economic:** only BlackSilk's market cap protects it, which is small at launch. The "unique algorithm" benefit (§4) is economic and temporary.

## 4. Consensus-level attacks

### 4.1 Precomputation via the seed

- The seed (previous block id, height, network id) changes every block. There is no epoch cache to amortize, which is good.
- **Critical requirement:** S[0] must absorb the full header *including the nonce*, the transaction and output commitments, and the timestamp.
  - If the fill depended only on the seed, one scratchpad per block would serve all nonces.
  - If the nonce entered only at finalization, PoW would collapse to roughly one BLAKE2b per nonce.
- Required tests: a KAT showing two nonces have disjoint fills, and a spec rule that no state survives across nonces.

### 4.2 Grinding, nonce partitioning, batching

- Nonce partitioning and extranonce grinding are harmless: work is proportional to nonces either way.
- Batching is exactly the GPU/ASIC parallelism already modeled.
- Stale work at block switch is at most one partial hash (about 30 ms) against a 120 s block, which is negligible.

### 4.3 Botnets and cloud

- Any CPU-friendly PoW is botnet-friendly, as Monero's cryptojacking history shows. 32 MiB per nonce does not deter that.
- Cloud CPU rental is available for both designs. For SKC-1 it is memory-channel-priced, which favors large instances.

### 4.4 The hashpower-market question (quantified)

**With RandomX (current design):**
- Monero network hashrate is about 5.8–6.4 GH/s (minerstat, coinwarz).
- NiceHash's RandomX market showed 0.12 GH/s available at 0.4732 BTC/GH/day, about $40k/GH/day (fetched 2026-10-04, a point-in-time quote). Monero mining revenue (about 432 XMR/day over about 6 GH/s) implies about $20–25k/GH/day, so the order of magnitude is consistent.
- Honest BlackSilk hashrate at launch (estimate): 50–500 hobbyists on the pure-Rust miner at about 10 H/s per thread is about 4–40 kH/s, or about 0.1–1 MH/s if they switch to xmrig.
- **Cost of a 2× honest majority for 24 h:** 80 kH/s–2 MH/s × $40k/GH/day ≈ **$3–$80 per day.**
  - One xmrig desktop (10–25 kH/s) already outmines a pure-Rust-only network.
  - The NiceHash supply is about 10²–10⁴× BlackSilk's honest hashrate. Qubic moved about 2.6 GH/s and produced a 6-block reorg on Monero (August 2025), and its stated model is redirecting its hashrate to whichever chain it chooses.
  - Profit-switching pools such as MoneroOcean also cause difficulty whiplash on small RandomX chains.
- **BlackSilk's security budget under RandomX is therefore set by the rental market, not by its own miners.** That holds until BlackSilk is a meaningful fraction of global RandomX revenue.

**With a unique algorithm (SKC-1):**
- At launch there is no off-the-shelf miner and no liquid market. An attacker must write or obtain an optimized miner (days to weeks; the reference miner is open source) and then acquire hardware.
- Attack cost is then about the cost of matching honest capacity:
  - CPU cloud is about $0.02–0.05 per vCPU-hour. For a 500-desktop-equivalent honest network that is about $10²–10³ per hour, which is **1–3 orders of magnitude more than RandomX rental.**
  - **But if the GPU ratio is ≥ 1×** (§2), the GPU cloud is a large, liquid pool (vast.ai, RunPod; a 4090 at about $0.3–0.4/hour). 100 4090s for 6 hours (about $200) give about 0.2–0.4 MH/s, which overwhelms a hobbyist CPU network.
  - Once one SKC-1 ASIC or FPGA exists, the chain is owned by its operator.
- **Net:** SKC-1 raises the attack cost from roughly $10 to roughly $10²–10⁴ and adds an engineering barrier. It does not make a small chain secure, and it trades "Monero's renters" for "GPU cloud plus a future SKC-1 ASIC vendor".
- The honest-miner efficiency gap closing (pure Rust within about 2× of optimal, against 70× today) is the largest *relative* gain.

### 4.5 Alternatives that address the same risk

1. **BlackSilk-specific RandomX configuration** (a different Argon salt and parameters, as Wownero, Arweave and others do).
   - It breaks plug-and-play NiceHash and Qubic redirection. NiceHash has no market for a new variant.
   - It keeps the RandomX design, which had external reviews in 2019 (Trail of Bits, X41, Kudelski, QuarksLab); BlackSilk's pure-Rust port has not been externally audited.
   - It does not fix the 70× pure-Rust JIT gap, and an xmrig recompile takes hours.
   - Low cost, but it is a consensus change.
2. **Merge-mining with Monero** (the Tari RxM model): Monero pools add honest hashrate. It depends on pool adoption and concentrates trust in a few pools.
3. **Multi-algorithm lanes** (Tari's 4 lanes): an attacker must dominate several markets.
4. **Confirmation policy:** depth guidance scaled to observed hashrate share, and reorg alerts. Monitoring only; no consensus-level reorg caps without separate review.

### 4.6 Attack list

| Attack | SKC-1 as specified | Realistic? |
|---|---|---|
| GPU mining dominance | 1–4× CPU (estimate) | Realistic (needs a kernel) |
| SRAM ASIC | 10–200× (estimate) | Realistic if the coin has value (12–24 months, as with Equihash) |
| HBM ASIC or FPGA | 50–100× / marginal | Realistic, ASIC needs value / early niche |
| TMTO at ½ memory | 1.5–2× penalty, ~1.3× AT gain | Realistic, part of the ASIC design |
| TMTO at ≤ ¼ | Depends on tail fix | Theoretical, or realistic if not fixed |
| Nonce-independent fill | Catastrophic if spec is wrong | Spec bug, must be tested |
| Checkpoint BLAKE2b dominance | ASIC-friendly | Spec ambiguity |
| Server and X3D unfairness | 7–36× per box | Realistic |
| Verify DoS | 25–70 ms, 32 MiB per bogus header | Realistic, mitigated as today |
| Rental and redirection | No market at launch; GPU cloud if GPU-friendly | Realistic |
| Botnet | Same as RandomX | Realistic |

## 5. Pure-Rust implementation risks and CPU fairness

Implementation risks:
- `u64 / 0` panics, so the spec must force the divisor non-zero (for example `| 1` or `| 1<<63`). Use explicit `wrapping_*` ops so debug and release builds agree.
- `u128` multiply lowers to MUL/UMULH and is fine on x86-64 and aarch64. It is slow but correct on 32-bit and wasm.
- Fix little-endian (LE) layout in the spec; test big-endian via an s390x emulator.
- Masked indexing lets bounds checks elide; expect ≤ a few percent cost otherwise.
- Prefetch intrinsics are `unsafe`. Use multi-nonce interleaving instead: safe, and out-of-order execution provides the memory-level parallelism.
- Reuse buffers. Large pages would need OS-specific code and are optional.
- RustCrypto `blake2` is portable and already a dependency.
- With no floats, no JIT and no unsafe code, determinism risk is low, much lower than the RandomX port's software-rounding machinery.

CPU fairness:
- **Division latency** spread for 64-bit DIV:
  - Skylake 39–94 cycles
  - Zen 4 10–18
  - Ice Lake 14–18
  - Neoverse 12–20
  - Apple Firestorm about 7–9 latency (reported by dougallj; throughput is about 2)
  
  With division on the critical path, older Intel is about 2–4× slower per core.
- **Memory channels and L3** dominate in the bandwidth-bound regime (§1.3): EPYC 12-channel and X3D or EPYC-X large-L3 parts gain 7–36×, while laptops with LPDDR are hurt.
- **SMT** helps a latency-bound miner.
- **NUMA:** first-touch-local scratchpads plus thread pinning avoid penalties. A remote-node scratchpad costs about 1.5–2× latency.

## 6. Benchmark plan (future isolated prototype)

Safety rules:
- Use a separate machine or VM, never this development host while tier-1 tests or agents run.
- Use a separate repository or a directory outside the BlackSilk tree, with no consensus code touched and no shared `target/`.
- Run at low priority with an explicit thread cap, a memory cap (job object or cgroup) and a wall-clock timeout. Stop processes by PID.
- Keep raw logs, toolchain and CPU microcode versions, BIOS memory settings and the governor in the evidence.
- Run each measurement at least 5 times; report the median and IQR.

Metrics:
- H/s, J/H (wall meter plus RAPL or `nvidia-smi`), H/s/$, and DRAM GB/s (perf or uProf).
- L3 miss rate; ns per step; verify p50 and p99 latency; peak RSS; page faults; cold- and warm-buffer verify.

Hardware matrix:
- Skylake (slow DIV), Ice Lake or Alder Lake, Raptor Lake; Zen 2, Zen 4, Zen 5 including X3D; EPYC Genoa 12-channel (rented).
- Apple M1 and M3; Graviton 3/4; Raspberry Pi 5.
- RTX 3090, 4090 and 5090; A100 or H100 (rented); RX 7900 XTX.
- FPGA and ASIC: modeled only, using the §3 spreadsheet with published SRAM and HBM energy figures.

Labs:
1. **Memory-reduction lab:** instrument the reference implementation to run TMTO strategies (every-k-th, ranking, tail-sparse) at α ∈ {75, 50, 25, 12.5, 6.25, 3.125}%. Count block recomputations exactly; this is deterministic and needs no timing. Plot C(α) and α·C(α).
2. **GPU cost-model validation:** an independent CUDA kernel, ideally under a public bounty. Measure VRAM pointer-chase latency, 64-bit division instruction count via SASS, occupancy, and achieved bandwidth. Compare against the §2 predictions.
3. **Verification lab:** verify p99 on the weakest supported node (4-core 2019 laptop, Raspberry Pi 5), and sync-time projection for 1 year of headers.
4. **Rust-versus-optimal:** the pure-Rust miner against a hand-optimized intrinsics or assembly miner on the same box.

Success thresholds (proposed gates; failing any gate means redesign or stop):
- Verify p99 ≤ 50 ms and ≤ 64 MiB peak on a mid-range desktop; ≤ 150 ms on a Raspberry Pi 5; 0 allocations per verify in steady state.
- Best consumer GPU ≤ 1.5× the best consumer CPU in J/H, using an independently optimized kernel.
- TMTO: C(½) ≥ 1.5; C(¼) ≥ 20; C(⅛) ≥ 1,000; max over α of 1/(α·C(α)) ≤ 1.5.
- Modeled SRAM-ASIC/CPU energy ratio ≤ 10×. The current design is predicted to fail this gate.
- Per-core throughput, normalized per memory channel, within 3× across the CPU matrix.
- Pure-Rust miner ≥ 50% of the optimized miner.
- Bit-identical KATs on x86-64, aarch64, 32-bit, big-endian and wasm.

## 7. Strengths and weaknesses

Strengths:
- Verification is 10–20× faster than the current pure-Rust RandomX light mode, uses a 32 MiB footprint, and needs no key-cache builds.
- Simple, auditable, safe Rust with no floats or JIT, so determinism is easy.
- Closes the honest-vs-attacker miner efficiency gap (from about 70× to about 2× or less).
- No existing rental market at launch.
- Division combined with the per-nonce memory cap is a real anti-GPU lever.

Weaknesses:
- Symmetric per-nonce memory is SRAM-feasible, giving weak algorithmic ASIC resistance (estimated 10–200×, against about 1–2× for RandomX's ASIC).
- Bandwidth-bound behavior favors servers, HBM, GPUs and large-L3 parts over ordinary desktops.
- Division fairness problems on older Intel.
- A one-pass uniform fill has a TMTO tail weakness.
- Checkpoint-hash ambiguity.
- A novel, unaudited primitive (RandomX had four audits).
- Small honest hashrate remains cheap to attack with GPU cloud or a first ASIC.

## 8. Assumptions that need experiments

1. VRAM pointer-chase latency under load, and SASS instruction count for 64-bit division and 64×64→128 multiply (§2).
2. Effective random-128 B DRAM bandwidth on DDR5 desktops and servers (§1.3).
3. The TMTO curve for the actual parent rule, with and without phase 2 (§3.3).
4. SRAM area and energy for 32 MiB at 5–7 nm from published macro data, and the ASIC model's error bars (§3.1).
5. Pure-Rust interleaved miner efficiency against an optimized miner (§5).
6. Real honest-hashrate projections for testnet and mainnet (§4.4).

## 9. Recommendation

**REDESIGN REQUIRED.** I found no evidence that SKC-1 as specified is superior to RandomX. My models predict worse ASIC resistance and server/GPU-favoring bandwidth behavior.

The rental-hashpower risk it targets is real and urgent for any value-bearing BlackSilk chain. Suggested order:
1. Decide on a BlackSilk-specific RandomX configuration and/or merge-mining, plus confirmation policy. This is a consensus decision, using known-good primitives.
2. If SKC-1 stays on the table, revise it before prototyping:
   - a nonce-bound S[0];
   - a phase 2 or multiple passes;
   - compact checkpoints;
   - division-heavy, lane-serial steps;
   - an explicit answer to the symmetric-memory/SRAM-ASIC problem. For example: a large *shared* per-block dataset with a light verifier mode, RandomX-style; or random-program elements.
3. Prototype the revised design only in isolation, against the §6 gates.

## Sources

- RandomX design.md (light mode ~14.8 ms; 256 MiB cache and 2080 MiB dataset; Argon2d halving-memory penalty 3,423×; IMUL_RCP and division rationale; multiply energy compared with DRAM): https://github.com/tevador/RandomX/blob/master/doc/design.md
- Argon2 specification (1-pass ranking-attack penalty table): https://www.password-hashing.net/submissions/specs/Argon-v3.pdf ; RFC/draft: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-argon2-13
- uops.info IDIV r64 (Zen 4 9–18, Ice Lake 14–18, Skylake 39–94 cycles): https://uops.info/html-instr/IDIV_R64.html ; Agner Fog's tables: https://www.agner.org/optimize/instruction_tables.pdf
- Apple Firestorm UDIV measurements: https://dougallj.github.io/applecpu/measurements/firestorm/UDIV_slow_64.html ; Arm Neoverse optimization guides: https://documentation-service.arm.com/static/6687d73a69e89f01e39c4507
- CUDA Best Practices Guide (integer division and modulo compile to up to 20 instructions): https://docs.nvidia.com/cuda/cuda-c-best-practices-guide/index.html
- Chips and Cheese, RTX 4090 (72 MB L2, ~1 TB/s): https://chipsandcheese.com/p/microbenchmarking-nvidias-rtx-4090
- AMD 3D V-Cache 64 MB die, 36–41 mm², 7 nm: https://fuse.wikichip.org/news/5531/amd-3d-stacks-sram-bumplessly/
- Antminer X5 RandomX (212 kH/s, 1,350 W): https://www.asicminervalue.com/miners/bitmain/antminer-x5
- Antminer Z9 mini Equihash (10 kSol/s, 300 W; about 13× a 1080 Ti): https://www.asicminervalue.com/miners/bitmain/antminer-z9-mini , https://coinguides.org/antminer-z9-mini-equihash-asic/
- Antminer E3 Ethash (190 MH/s, 760 W): https://asicminervalue.org/miners/bitmain/antminer-e3-190mh
- Least Authority ProgPoW audit (ASIC 1.2× over GPU against 2× on Ethash): https://leastauthority.com/static/publications/LeastAuthority-ProgPow-Algorithm-Final-Audit-Report.pdf
- Qubic and Monero, August 2025 (majority claim, 6-block reorg): https://www.coindesk.com/business/2025/08/12/qubic-claims-majority-control-of-monero-hashrate-raising-51-attack-fears , https://www.theblock.co/post/366535/monero-faces-chain-reorganization-fears-after-qubic-says-it-controls-51-of-hashrate
- Monero hashrate (~5.8–6.4 GH/s): https://minerstat.com/coin/xmr/network-hashrate , https://www.coinwarz.com/mining/monero/hashrate-chart
- NiceHash RandomX market (0.12 GH/s; 0.4732 BTC/GH/day, point-in-time): https://www.nicehash.com/algorithm/randomxmonero
- Rental-hashpower 51% attacks (ETC, BTG): https://cloudsecurityalliance.org/blog/2020/11/20/rent-to-pwn-the-blockchain-51-attacks-made-easy , https://dci.mit.edu/projects/51-percent-attacks , https://www.crypto51.app/about.html
- Tari merge-mining with Monero, 4 PoW lanes: https://rfc.tari.com/RFC-0131_Mining , https://tari.com/tokenomics

Cited from background knowledge and not re-fetched in this session (verify before relying on them):
- Ren and Devadas, "Bandwidth Hard Functions for ASIC Resistance" (TCC 2017, eprint 2017/225).
- Alwen and Blocki, "Efficiently Computing Data-Independent Memory-Hard Functions" (CRYPTO 2016). It applies to data-independent memory-hard functions; SKC-1 is data-dependent, like scrypt and Argon2d.
- Alwen et al., "Scrypt is Maximally Memory-Hard" (EUROCRYPT 2017).
- Horowitz, "Computing's Energy Problem" (ISSCC 2014), for relative DRAM, SRAM and ALU energy.
- RandomX audits (Trail of Bits, X41, Kudelski, QuarksLab, 2019).

Finished: 2026-10-04T07:53:20Z
