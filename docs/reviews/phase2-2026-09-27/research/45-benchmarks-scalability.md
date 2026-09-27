# 45 benchmarks-scalability: research dossier (phase 2, phase 1)

**Agent:** 45 benchmarks-scalability. Internal engineering research, not an audit. Nothing
here claims BlackSilk is secure, production-ready or audited.
**Base:** branch `rebuild/core`, commit `9e422d8` (`git rev-parse --short HEAD`), clean tree.
**Mode:** read-only on the repository. No builds, tests or benchmarks were run. The only
commands run were read-only machine queries (CPU, RAM, power plan, running processes). All
timings below are quoted from existing files with their provenance, or they are estimates
marked **[est]**.

Evidence tags: **[math]** established from constants; **[test: name]** a named existing test
(not run by me); **[src]** source-read at `file:line`; **[meas: file]** a measurement recorded
in a file, with its conditions as far as they are known; **[machine]** a read-only query of
this machine on 2026-09-27; **[ext]** external primary source (§8); **[assumed]**; **[unknown]**;
**[est]** an estimate.

**What this dossier delivers:** one benchmark-suite specification that covers every
measurement request in the phase-2 dossiers and R12 (§5.2). It defines:
- the workloads (§5.2);
- machine-state recording (§5.3);
- the output format under `docs/evidence/` (§5.4);
- the statistical protocol (§5.5);
- the before/after baseline plan for this phase (§5.6);
- the machine-time schedule with its exclusive windows (§5.7).

---

## 1. Scope and what I read

**Brief, roster and decisions:**
- `C:/bszkeval/p2/brief.md` (all);
- `roster.md` (all entries; my entry 45; neighbours 06, 09, 10, 22, 27, 39, 41, 43, 44);
- `decisions.md` (all);
- `status.md`.

**Phase-2 dossiers.** I read every file in `C:/bszkeval/p2/research/` that existed at
writing time: 01–22, 25, 28, 30, 31 and 36.
- Read in full: 06.
- Read in their benchmark, measurement and implementation-plan sections: 03, 07, 09, 10, 12,
  14, 15, 16, 22, 23 and 31.
- Grepped for every "bench", "measure", "timing", "RSS" and "throughput" request: all the
  others.
- **Not yet written, so not read:** 23's full plan beyond its W sections, 24, 26, 27, 29, 32,
  33–35, 37–44 and 46–50. **39 (sync bandwidth) and 27 (prover performance) are expected to
  add requests.** The catalogue in §5.2 reserves IDs for them.

**Repository reports:**
- `docs/reviews/full-review-2026-09-27.md` (grep of every benchmark, measurement, R12-*, P0-3
  and P0-13 row);
- `docs/reviews/autonomous-session-2026-09-27.md` (grep);
- `docs/reviews/full-review-2026-09-27/R12-performance.md` (**in full**).

**Code: every existing benchmark or timing path:**
- `randomx/examples/bench.rs`, `randomx/README.md` §Performance;
- `randomx/src/lib.rs:198-290` (the ignored full = light test with printed timings);
- `px/examples/proof_bench.rs` (and a directory listing of the other nine `px/examples`);
- `chain/tests/manager.rs:1010-1047` (`mempool_revalidation_cost_per_transaction`) and
  `:1230-1310` (restart and header-sync timings across switches);
- `chain/tests/fork_choice.rs:580-620` (the linearity timing test);
- `chain/src/mempool.rs:595-613`, `chain/src/store.rs:630-690`;
- `tx/tests/validation_order.rs:460-476`;
- `px/tests/proof.rs:40-65`, `px/tests/unified.rs:170-190`;
- `zkvm/tests/multi.rs:140-160`, `zkvm/tests/stress.rs`;
- `wallet/tests/e2e.rs:1295-1304`;
- `tx/tests/common/mod.rs` (fixtures); `chain/tests/fork_choice.rs:30-75` (`ZeroPow`,
  `Miner`).

**Tooling and configuration:**
- `tools/labnet/src/main.rs` (Args, Report, `rss_mb`, the metrics loop `:440-505`);
- workspace `Cargo.toml` (members, profiles);
- `.github/workflows/ci.yml` (all jobs).

**Evidence on disk:**
- `docs/evidence/*`: labnet-2026-09-23/25/26, p5-2026-09-25/26/26b, px0-2026-09-23 (with its
  out-of-tree bench crate).
- Coordinator scratch files: `C:/bszkeval/bench-{before,before-idle,after,optA-*,rc-*}.txt`,
  `timing*.log`, `stress-compare.log`, `seedrun2/metrics.csv` (tail).

**Machine [machine]:**
- CPU: Intel Core i7-6700 (Skylake), **4 cores / 8 logical CPUs**, 3.4 GHz base, L2 1 MiB,
  L3 8 MiB.
- RAM: 2 × 8 GiB at 1600 MT/s.
- OS: Windows 10 Pro 19045. A hypervisor is present. Defender real-time protection is off.
- Power scheme: **Balanced** (`381b4222-…`).
- Toolchain: rustc 1.98.1 as `stable-x86_64-pc-windows-msvc`. The gnu and nightly
  toolchains are also installed. There is **no `rust-toolchain.toml`**.
- Load at writing time: labnet seedrun2 was running (4 nodes at ≈ 534 MB each, 2 light
  miners at ≈ 265 MB each, height 2352).

---

## 2. Current state

### 2.1 What exists

| Item | What it measures | Evidence class and conditions |
|---|---|---|
| `randomx/examples/bench.rs` | One cache build; 20 light hashes; prints the mean | [src]. Light mode only. No machine record, no JSON, no statistics |
| `randomx/README.md:78-88` | Cache ~0.63 s, light ~0.45 s, dataset ~133 s | [meas], "development machine". Profile, power and load unrecorded |
| `randomx/src/lib.rs:198-290` (ignored) | Dataset build time, and full vs light time over 1,024 inputs | [test: `full_mode_matches_light_mode`]. Prints only; runs in CI `randomx-full` on a shared runner |
| `px/examples/proof_bench.rs` | Transfer and vault LOCK: mean size, prove time, verify time, table layout | [src]. Means only (no min, median or spread). No peak memory (the coordinator measured it externally: `bench-optA-summary.txt`, "peakMB=3771") |
| `px/examples/proof_length_campaign.rs` | P-5 proof-length statistics | [meas: docs/evidence/p5-*]. Byte-level, deterministic enough; time irrelevant |
| `chain/tests/manager.rs:1010` `mempool_revalidation_cost_per_transaction` | Per-transaction cost of connecting an empty block with 40 pooled transfers | [test]. Runs in the **normal suite**; prints. The printed number is the R12 "6.8 ms" anchor, but the test now measures the extension path (6.3 µs) and its comment is stale (M12-11) |
| `chain/tests/manager.rs:1241-1305` | Restart and 40-header sync across 2 switches; reference hashes | [test]. Prints only |
| Wall-clock assertions in the normal suite | `chain/src/mempool.rs:604-611` (< 2 s), `chain/src/store.rs:651, 684` (< 2 s), `wallet/tests/e2e.rs:1303` (< 5 s), `chain/tests/fork_choice.rs:609` (ratio + 5 s) | [src]. See F45-7 |
| `tools/labnet` | Heights, tips, mempools, peers, **RSS samples** per process; `max_rss_mb`; proxy bytes | [src `main.rs:126, 156-180, 448-505`]. RSS is the current working set, sampled |
| `docs/evidence/px0-2026-09-23` | PX-0 stack comparison | [meas]. Uses an out-of-tree crate (`bench-Cargo.toml`) with `p3-*` 0.7, stwo, halo2 |
| The coordinator's `bench-*.txt` | proof_bench outputs, idle and loaded | [meas]. **Not in the repository.** One file is UTF-16. No machine record beyond "idle" in the name |

**Well designed:**
- `proof_bench` and `proof_length_campaign` use fixed seeds, so their witnesses reproduce.
- The P-5 evidence READMEs state the machine, the commit, the reproduce command and the
  concurrent load. That is the right template.
- `fork_choice.rs:609` asserts a **ratio against a same-process baseline**
  (`reverse < forward × 4 + 5 s`), which is robust to machine speed.
- The release profile (fat LTO, `codegen-units = 1`) is what ships, and CI runs the tests in
  release [src `Cargo.toml`, `ci.yml:72-74`].

**What the existing measurements prove:**
- **Orders of magnitude only.**
- **The noise is large and measured [meas: `C:/bszkeval/bench-before-idle.txt` vs
  `bench-before.txt`, same code, idle vs loaded]:**

  | Proof | Prove time, idle → loaded | Verify time, idle → loaded |
  |---|---|---|
  | Transfer | 42.0 → 48.5 s (+15%) | 0.195 → 0.256 s (+31%) |
  | Vault | 50.4 → 59.3 s (+18%) | 0.234 → 0.268 s (+15%) |

- **RandomX load noise:**
  - light hash 0.45 s idle against 0.75 s loaded (+67%);
  - dataset build 133 s against 179 s (+35%) [meas: README, testnet.md §12.1].
- **These noise levels exceed every effect size the phase must decide on:**
  - 06's per-optimization gains of 1.05–1.5×;
  - 10's parallel speed-up;
  - 12's "20k entries in under 1 s";
  - the R12-2 margin between ≈ 2.7 s and 5–10 s.

### 2.2 R12's scalability model: status of each input

| Model input | Value used | Class |
|---|---|---|
| t_clsag | 2–4 ms | **[est]**, split from the single 6.8 ms anchor |
| t_bp (batched) | 0.3–1 ms | [est] |
| t_px verify | 0.207–0.265 s | [meas], one machine, idle, parallel feature on; single-thread cost [unknown] |
| Adversarial t_px (ZK-F4) | ≈ 0.45 s | [est] |
| RAM per block | 6 KB floor + 4.5 × v1 bytes + 1.0 × PX bytes | [math on struct sizes] + [est]. **Never measured** |
| Disk per block | 240 B + … | [math]. Never checked against a real `blocks.dat` |
| Restart | Σ t_block(cold) | [est] |
| IBD headers | N × t_light / p, with p = 8 | [math on meas]. **Assumes linear scaling to 8 logical CPUs on a 4-core SMT machine [unknown]** |

**Labnet cannot validate the RAM model at its scale [math + meas: seedrun2 metrics.csv]:**
- Node RSS went from ≈ 265 MB to ≈ 534 MB across height 2113. That step is the second
  256 MiB RandomX cache (07 F07-9).
- The chain-proportional term at 2,352 blocks × ≈ 6 KB ≈ 14 MB is below the sampling
  resolution and the working-set noise.
- So the model needs synthetic replays at 10^4–10^5 blocks (§5.2 SC).

---

## 3. Problems in scope

### P1. There is no reproducible baseline; the decisions of this phase need one

**Problem.** Every figure the phase will rely on lacks at least one of: the machine state,
the profile, a record of concurrent load, repetitions, a spread, the commit, or a stored raw
output. Decisions that depend on such numbers:
- R12-2 (the consensus weight rule; its final adoption waits on the worst-block benchmark,
  per the decisions log);
- P0-3 (the widest proof against `MAX_PROOF_BYTES`; ZK-F4);
- 06's optimization gates ("no optimization merges without before/after");
- 12's W1 acceptance ("20k entries < 1 s");
- 40's D0 (the measured honest hash rate).

**Why it exists:** measurements were taken ad hoc during development, on the shared labnet
host, while other agents were building.

**Security consequence (indirect):**
- A wrong t_clsag could set the R12-2 bound wrongly, leaving a block-validation DoS larger
  than believed.
- A wrong widest-proof size could leave a registered function pair uncallable.

**Class:** evidence and process. It feeds consensus decisions (R12-2, `MAX_PROOF_BYTES`,
kernel budgets) but is not itself consensus.

**Literature:**
- Mytkowicz et al. (ASPLOS 2009): innocuous set-up changes (environment size, link order)
  bias results enough to reverse conclusions.
- Curtsinger & Berger, STABILIZER (ASPLOS 2013): memory-layout effects make a single-build
  before/after comparison statistically unsound. Under layout randomization, LLVM -O3 vs
  -O2 was indistinguishable from noise.
- Kalibera & Jones (ISMM 2013): repeat at the level where the variance lives (builds,
  process invocations, iterations), and report an effect-size confidence interval.
- Chen & Revels (2016): the minimum is a robust estimator for CPU-bound microbenchmarks
  under positive-only noise.

**How established projects solve it:**
- **Bitcoin Core:** an internal bench framework (nanobench). It prints an `err%`, warns about
  frequency scaling and turbo, and recommends `pyperf system tune`. Performance PRs "may be
  rejected when a clear end-to-end performance improvement cannot be demonstrated". IBD
  benchmarking (benchcoin) uses hyperfine over a fixed block range from a dedicated peer, on
  a dedicated bare-metal machine with cores reserved for the system and for the profiler.
- **Zebra (PR #10444, merged 2026-04-21):** a criterion suite for Groth16, Halo2 and Sapling
  batch sizes and for transaction (de)serialization. It runs on GitHub runners, which show
  "10 to 20% Ubuntu CI runner variance", so the noise threshold is 10% and the alert
  threshold is 150%.
- **Monero:** a custom `performance_tests` harness with a filter, a loop multiplier, min and
  median statistics, and a timings database. It includes CLSAG and BP+ tests.

**Trade-offs:**
- A rigorous protocol costs machine time; the machine is shared (§5.7).
- A custom harness is code to maintain. Criterion is excluded anyway (F45-4).

**Tests that prove the fix:**
- the suite runs end to end in smoke mode in CI;
- an A/A calibration shows the noise floor in each window;
- deterministic metrics are asserted exactly.

**Invariants:**
- benchmarks never change consensus code paths;
- they are compiled with the shipped release profile;
- raw samples are kept.

### P2. Where the noise comes from on this machine, and how to control it

**Sources [machine, meas]:**
- **The Balanced power plan:** dynamic frequency.
- **SMT:** the "8 threads" figures are 4 cores plus Hyper-Threading.
- **Concurrent agents and the labnet:** seedrun2's two miners hash continuously.
- **The hypervisor:** QPC is then fixed at 10 MHz, a 100 ns resolution [ext: Microsoft QPC
  docs]. That is irrelevant for ≥ µs workloads.
- **Windows services:** Update, Search. Defender is already off.
- **Turbo:** single-core versus all-core turbo differ.
- **Thermal drift** during multi-hour windows.

**Mitigations (§5.5):**
- **An exclusive window** (the only way to remove agent and labnet load).
- **The High performance plan** (`powercfg /setactive SCHEME_MIN`), recorded and restored.
- **Idle pre-check.**
- **Fixed affinity and priority** for single-thread workloads.
- **Interleaved ABAB runs**, so drift and turbo affect both arms.
- **Repeated process invocations**, which sample layout and ASLR, as STABILIZER argues.
- **A/A calibration** in every window.

**Linux** (for any bare-metal trial device):
- the LLVM benchmarking guide lists the performance governor, `no_turbo`, disabling SMT
  siblings, cpuset shielding and ASLR off, and reports < 0.1% variation;
- `pyperf system tune` also stops irqbalance and lowers `perf_event_max_sample_rate`.

**What is not controllable here:**
- Hardware performance counters. There is no Linux on this host (WSL has no distribution),
  and GitHub-hosted runners are VMs [assumed: PMU events are generally unavailable]. **06's
  O0 hypothesis test (branch-misses per superscalar op) therefore needs a bare-metal Linux
  machine** (open question §7.4).

### P3. Memory measurement without `unsafe` or FFI

**Problem.** Several requests need peak memory:
- 22 W1(d): decode amplification;
- 07: RSS across a switch;
- 21-F: undo bytes;
- 30 W7: frame buffers;
- R12 §19.4: RSS against chain length.

22 proposes "a counting global allocator in the test binary". Implementing `GlobalAlloc`
requires `unsafe impl` and `unsafe fn`. That breaks the brief's "no `unsafe` in BlackSilk
crates". The CI root check (`ci.yml:45-58`) would not catch it, because it only inspects
`src/lib.rs`, `src/main.rs` and `src/bin`, not `tests/` (F45-5).

**Pure, safe alternatives:**
- **Linux:** the process reads its own `VmHWM` (the peak RSS) from `/proc/self/status`.
  proc(5) warns that the value "is inaccurate" (mm counters are batched); it is adequate at
  MB resolution.
- **Windows:** the OS maintains the peak working set (`PeakWorkingSet64`, the "Working Set
  Peak" counter), which is monotone. The runner (or the process itself, via `std::process`
  spawning PowerShell with its own pid) reads it after the workload, before exit. No FFI in
  our code.
- **Deterministic accounting where possible:** undo bytes per block, encoded bytes, and
  `size_of` × counts. These are exact and CI-assertable.

**Design rules:**
- Each memory workload runs **in its own process**. Peaks are per process, and the allocator
  does not return memory.
- The workload records a **baseline** (after fixture load) and the **peak**, and reports the
  delta.
- 22's threshold (~64 MB) is far above page granularity, so resolution is not an issue.

### P4. Where workloads live, and the harness choice

**Options examined:**
- **criterion 0.8.2** (defaults: 100 samples, 3 s warm-up, 5 s measurement, 100k bootstrap
  resamples, 1% noise threshold, 0.05 significance). It is a sound statistical design, but it
  depends on `alloca 0.4`, whose build script compiles `alloca.c` with `cc`. **That is C in
  the dependency graph**, excluded by the brief (F45-4). It also pulls plotters, rayon,
  regex, clap, ciborium and more. **Rejected.** This confirms 06 and the 10 decision.
- **divan / iai-callgrind:** not evaluated in depth. iai-callgrind needs Valgrind (C) and
  Linux. Rejected for now; a P3 Linux-only option for deterministic instruction counts.
- **`#[ignore]` timing tests** (the repository's convention; the agent 10 decision). They can
  use the per-crate test fixtures (`tx/tests/common`, `chain/tests` `Miner`/`ZeroPow`),
  which are not exported from the library crates.
  - **Catch:** CI's `randomx-full` job runs `cargo test -p blacksilk-randomx -- --ignored`
    (`ci.yml:130-131`), so an ignored bench in `randomx` would run there (F45-6).
  - Every bench test must therefore be **env-gated** (`BLACKSILK_BENCH` unset → return
    immediately with a "skipped" line) **and** named `bench_*`, so CI can `--skip bench_`.
- **The chosen design:**
  - a zero-dependency internal crate `tools/benchkit` (timing, statistics, JSON-line
    emission, peak-memory probe);
  - `#[ignore]` + env-gated `bench_*` tests in each domain crate;
  - a runner binary `tools/bench` that records the machine, checks the preflight, invokes the
    pre-built test executables one workload per process, interleaves A/B, and writes the
    evidence directory and the comparison.
  - hyperfine (pure Rust, JSON export, warm-up, `--prepare`) is the recommended **external
    operator tool** for process-level workloads (node restart, IBD). It is optional, never a
    dependency.

**Why `benchkit` has zero dependencies:** a dev-dependency can change feature unification
for the code under test when `cargo test` builds the crate. A dependency-free harness cannot
perturb the codegen of what it measures.

### P5. The before/after baseline must stay valid while implementation proceeds

**Problem.** The harness does not exist at `9e422d8`, and many phase-2 changes alter APIs or
rules. Examples:
- R12-2 (a′) makes today's worst block invalid;
- the kernel rebuild changes proof shapes;
- D8 removes the one-time-key set.

**Solution:**
- "Before" is defined as **B = `9e422d8` + H**, where H is the harness-only patch series.
  It is rebuilt at any time in a separate worktree, **independent of what has merged since**.
- "After" is the freeze candidate F.
- The binding before/after table comes from **one window (X2) running B and F interleaved**.
  This cancels drift since X0 (Windows updates, thermals).
- X0's run of B serves as early decision data and as a drift check.
- Scenarios are defined semantically ("the worst valid block under the rules at that
  commit"). Rows whose meaning changed are labelled "non-comparable: rule changed", with both
  values shown.

**Proof that H changes no behaviour:**
```
git diff --stat 9e422d8 B -- . ':!tools/bench*' ':!**/tests/bench_*' ':!docs/evidence'
```
must show only `Cargo.toml` dev-dependency lines, workspace members, `Cargo.lock` entries
for the new internal crates, and `ci.yml`. A reviewer (43) checks this.

### P6. The chain-growth and RAM-growth models are unverified

**Problem:**
- R12's per-block RAM formula, its 6 KB floor and its 4.5× decode factor are derived from
  struct sizes.
- The time-to-OOM table (147 days light use, 2.4 days full) is extrapolated.
- The disk formula is [math].
- None has been measured (§2.2).

**Consequences:**
- The testnet go/no-go for RAM (R12 "S1 safe for months on 16 GB") rests on an unmeasured
  model.
- The mainnet storage roadmap (35) needs the real coefficients.

**Fix: SC workloads (§5.2):**
- deterministic byte and undo accounting;
- RSS and restart time against N, from synthetic chains with `ZeroPow` (isolating RandomX,
  whose 256 MiB caches are measured separately under RX);
- a linear fit per scenario, with confidence intervals;
- publish the fitted coefficients against R12's.

**Invariant:** the model is re-fitted after every storage-affecting change (21-F / I1 undo
delta, 35's items).

### P7. Measurement code must not become a correctness or policy hazard

**Rules:**
- **No `unsafe`:** every bench file carries `#![forbid(unsafe_code)]` at the test-crate root.
- **No new external dependency** (benchkit is internal and dependency-free). The runner may
  use only crates already in `Cargo.lock`, with 44 confirming.
- **No bench-only code paths in library crates.** Counters for "proofs verified" and the
  like live behind `cfg(test)` or existing test hooks, as 12 and 02 propose.
- **No wall-clock pass/fail assertions in the normal suite** (F45-7). Timing verdicts belong
  to the runner.

---

## 4. New findings

| ID | Severity | Status | Location | Scenario | Confidence |
|---|---|---|---|---|---|
| **F45-1** | Medium (evidence; blocks P0 decisions) | Not implemented | `randomx/examples/bench.rs`; `px/examples/proof_bench.rs`; `chain/tests/manager.rs:1010-1047`; `randomx/README.md:78-88`; `docs/zk.md:703-712` | Every anchor that R12-2, P0-3 and 06's gates depend on lacks a machine record and a spread. The same commit measured idle vs loaded differs by 15–31% (PX) and 35–67% (RandomX). That exceeds the effects being decided, so a before/after on the shared machine without a window cannot resolve 1.05–1.5× claims | High (meas files) |
| **F45-2** | Medium (evidence) | Not implemented | machine state (§1); `p2p/src/net.rs:104` (`pow_threads = available_parallelism`); `miner/src/main.rs:303-305` | The host runs Balanced power, 4C/8T, with labnet seedrun2 live (two miners at 100% of one logical CPU each). "8 threads" in R12's IBD formulas and the dataset figures are SMT threads; the scaling from 4 to 8 threads is [unknown]. R12's T_hdr ÷ 8 may be optimistic | High (state); unknown (effect) |
| **F45-3** | Low | Not implemented | `tools/labnet/src/main.rs:156-180, 448-460` | Labnet's `max_rss_mb` is the maximum of sampled **current** working sets (`tasklist` "Mem Usage" on Windows, `VmRSS` on Linux), taken every sample period. Transient peaks (IBD frame bursts ≈ 151 MB per peer, reorg revalidation, a prebuild at 4.4 GiB) can fall between samples. Windows working set and Linux RSS are not comparable across OSes. No `blocks.dat` size, CPU seconds or stale counts are recorded (overlaps 09's M9-7) | High |
| **F45-4** | Medium (policy; prevents a wrong adoption) | Accepted limitation (decision input) | criterion 0.8.2 manifest → `alloca 0.4` (`build.rs`, `alloca.c`, build-dependency `cc`) | Adopting criterion (the Rust ecosystem default, used by Zebra) would bring C compilation into the dev-dependency graph, against the brief's "no C". It confirms the no-criterion decision with a concrete reason | High (manifests read) |
| **F45-5** | Low (policy) | Not implemented (proposal in 22 W1(d)) | 22 dossier W1(d); `ci.yml:45-58` (checks crate roots only) | A counting `GlobalAlloc` in `zk/tests/decode_memory.rs` needs `unsafe impl`, and the CI unsafe check would not see it, because tests are separate crates. Replace it with the process-peak method (P3) | High |
| **F45-6** | Low | Not implemented | `ci.yml:130-131` (`-p blacksilk-randomx -- --ignored`); future 05 ignored tiers | Any `#[ignore]` bench added to `randomx` runs inside the `randomx-full` CI job (60-minute timeout), with minutes of dataset builds and noise-meaningless timings. It could time the job out. Needs env gating plus `bench_` naming, and `--skip bench_` in that job | High |
| **F45-7** | Low (flakiness) | Not implemented | `chain/src/mempool.rs:604-611`; `chain/src/store.rs:651, 684-687`; `wallet/tests/e2e.rs:1303` | Absolute wall-clock assertions (< 2 s, < 5 s) run in the normal suite. They fail spuriously on a loaded shared machine or a slow runner, and they pass on a fast machine even after an asymptotic regression. The ratio form of `fork_choice.rs:609` and operation counters are more robust | Medium |
| **F45-8** | Low (docs accuracy; confirms 01 F-08, 07 F07-10, 12 M12-11) | Not implemented | `randomx/README.md:85-86`; `docs/consensus.md:108, 257`; `docs/blocks.md:232, 300`; `docs/p2p.md:189, 209, 565`; `chain/tests/manager.rs:1041` | Performance statements cite "development machine" or no conditions. "0.45 s" is the idle figure (0.75 s loaded). The "20,000 transfers of ~2.5 kB" comment is stale (1.56 kB; R12 §18). Docs must cite an evidence directory | High |
| **F45-9** | Informational | Not implemented | repository root (no `rust-toolchain.toml`); `Cargo.toml` `[profile.release] strip = true` | Local builds follow whatever `stable` is (1.98.1 today); CI pins 1.98.1. A silent compiler change between the X0 and X2 windows would confound before/after, so the runner must record `rustc -vV` and refuse a mismatch. `strip = true` removes symbols, so profiles (samply) need a `profiling` profile that inherits release with `debug = "line-tables-only"` and `strip = false`. Timings still come from `release` | High |
| **F45-10** | Medium (scalability claims unverified) | Not implemented | R12 §4-§6; `docs/reviews/full-review-2026-09-27.md:1388` | The RAM and disk growth models (6 KB/block floor, 4.5× v1, 16 GB in 147 days at S1) are unmeasured. Labnet cannot detect the per-block term at its scale (≈ 14 MB against a 256 MiB cache step). The testnet RAM go/no-go rests on arithmetic alone | High (fact); unknown (model error) |
| **F45-11** | Low (evidence custody) | Not implemented | `C:/bszkeval/bench-optA-*.txt`, `bench-rc-summary.txt` (UTF-16) vs `docs/zk.md:703-712` and R12 §1.2 | The only records behind the PX measured table and R12's anchors live outside the repository, partly UTF-16, without a machine record or a peak-memory method. `px0` evidence depends on an out-of-tree crate with unpinned `0.7` requirements | High |
| **F45-12** | Informational | — | chain tests: `Miner` is redefined in 7 files (`activation.rs:78`, `fork_choice.rs:55`, `manager.rs:50`, `mempool_conflicts.rs:64`, `revalidation.rs:69`, `storage_recovery.rs:47`, …) | The bench fixtures for chain-level scenarios will be an 8th copy unless a shared `chain/tests/common/` exists. Overlaps 41's fixture plan | High |

There are **no Critical or High findings, and no consensus finding.** Measurement never
changes a validity verdict. Its security relevance is that consensus limits (R12-2,
`MAX_PROOF_BYTES`, kernel budgets) and DoS budgets are **chosen from** these numbers.

---

## 5. Implementation plan for phase 2 (the benchmark-suite specification)

### 5.1 Architecture

```
tools/benchkit/   (new, lib, zero deps, #![forbid(unsafe_code)])   owner 45
    measure(id, cfg, |iter| ...)  -> samples; stats; emit JSON line
    emit_value(id, unit, value)   -> deterministic metrics
    peak_mem_probe()              -> Linux VmHWM (/proc/self/status);
                                     Windows PeakWorkingSet64 via spawned PowerShell
    gate()                        -> returns false (prints "skipped") unless BLACKSILK_BENCH set
<crate>/tests/bench_<area>.rs     (#[ignore] + gate(); fn bench_*; dev-dep benchkit)
tools/bench/      (new bin `blacksilk-bench`, #![forbid(unsafe_code)])   owner 45
    machine | preflight | build | run --suite S | interleave A B | compare | report
```

**Invocation:** one workload per process, as

```
<test-exe> --ignored --exact <name> --nocapture --test-threads=1
```

with the environment set to:
- `BLACKSILK_BENCH=<mode>` (`full` or `smoke`);
- `BLACKSILK_BENCH_OUT=<results.jsonl>`;
- `BLACKSILK_BENCH_REPS`, `BLACKSILK_BENCH_THREADS`, `RAYON_NUM_THREADS`.

The runner **clears the environment** and passes a fixed minimal set, so environment size
and bias stay constant (Mytkowicz).

**Executables:** built once per commit into `C:\bsbench\<commit12>\target` with
`cargo test --release --locked --no-run`. The runner records the SHA-256 of each executable.
Paths have equal length across commits.

### 5.2 Workload catalogue

**Legend:**
- **Class:** T = timing; M = peak memory; D = deterministic (bytes, counts, cycles; exact and
  CI-assertable); S = simulation output (seeded).
- **Req:** the dossier or report that asked for it.
- **Owner:** the author of the bench file. 45 reviews all of them for protocol compliance.
- **X0:** is it available at `9e422d8` + H? (Y / N = only after that item lands.)

#### RX: RandomX (file `randomx/tests/bench_randomx.rs`, owner 06; 45 reviews)

**Common parameters:** keys `test key 000` and `test key 001`, plus one 60-byte key.
Deterministic inputs: `LE32(i) ‖ 76 bytes` from a fixed splitmix stream.

| ID | Workload | Class | Repetitions | Req | X0 |
|---|---|---|---|---|---|
| RX-1 | Cache build (Argon2d 256 MiB) | T, M | 5 per key × 3 processes | 06 B1, 07, 05 C7 | Y |
| RX-2 | Light hash, 1 thread, pinned | T | 3 warm-up + 50 per key × 3 processes | 06 B2, R12, 01 | Y |
| RX-3 | Light hash throughput, threads ∈ {1, 2, 4, 8} (SMT scaling; F45-2) | T | 64 hashes per thread count × 3 processes | 06 B3, R12 §7 | Y |
| RX-4 | Dataset build, threads ∈ {1, 4, 8}. 1 thread: one run only (≈ 20 min) | T, M | 4 and 8 threads ×3 | 06 B4, 09 M9-4, 05 C7 | Y |
| RX-5 | Full hash: 1 thread ≥ 500; throughput at {1, 2, 4, 8}. Run in the same process as the RX-4 8-thread builds | T | ×3 processes | 06 B5, 40 D0 | Y |
| RX-6 | Superscalar item µs, scalar vs batched K ∈ {1, 4, 8, 16} | T | ≥ 10^5 items | 06 B6/B7 (W3) | N |
| RX-7 | FPU ns/op per mode, operand streams from vector 1b | T | 10^6 ops | 06 B8 (W6) | N |
| RX-8 | Node header PoW throughput: `compute_parallel` over 2,048 same-seed headers, and a 4,096-header span across a switch (cache build included) | T | ×3 | 06 B9, 31, 07 | Y |
| RX-D | Regression digest (06 W2, 08 W3) must pass before any RX timing is accepted | D | — | 06, 08 | N |

#### CR: Cryptography (file `crypto/tests/bench_crypto.rs`, owner 45; 15 and 16 review)

| ID | Workload | Class | Req |
|---|---|---|---|
| CR-1 | `clsag::sign`, ring 16 | T | 15 W8 |
| CR-2 | `clsag::verify`, ring 16: 1 pinned thread; throughput at T ∈ {1, 2, 4, 8} independent verifications | T | 15 W8/W9, 10 §5.1, R12 §19 |
| CR-3 | Key image and `Hp`, per member | T | 15 W8 |
| CR-4 | `bpp::prove`, k ∈ {2, 16} | T | 16 item 9 |
| CR-5 | `bpp::verify` single, k ∈ {2, 16} | T | 10, 16, R12 |
| CR-6 | `bpp::batch_verify`, n ∈ {1, 10, 100, 381} (k = 2); hedged vs current weights once 16 item 2 lands | T | 10, 16, R12 |
| CR-7 | Build and verify a 64-input transfer | T | 15 W8 |
| CR-8 | Wallet scan cost per output, v1 view-tag path (optional) | T | 17 |

**Repetitions:** 2 s warm-up; ≥ 200 samples (sign/verify) or ≥ 30 (batches); ×3 processes.
All CR rows are available at X0.

#### BLK: Block validation (file `tx/tests/bench_block.rs` using `tests/common`, owner 45; 10 reviews; 14 consumes)

| ID | Scenario (built with the TestNet fixtures) | Class | Req | X0 |
|---|---|---|---|---|
| BLK-0 | S0: coinbase only | T | R12 §3 | Y |
| BLK-1 | S3: 381 × 1-in/2-out | T | 10 §5.1, R12 | Y |
| BLK-2 | S5: 13 × 64-in (the v1 input maximum, ≈ 886 CLSAGs) | T | 10 | Y |
| BLK-3 | S6-now: 23 × 64-in deploys + 3 real PX + v1 fill (≈ 2,530 CLSAGs); after R12-2 (a′), "the worst valid block under that commit's rules" | T | 10, 14, R12-2 | Y |
| BLK-4 | F10-2: 183 × 64-in PX with empty proofs. The time to **reject** | T | 10 F10-2, 50 | Y |
| BLK-5 | S4: S3 + 3 PX, cold vs PX-cached | T | R12 §3 | Y |
| BLK-6 | `resolve_input_rings` per input | T | 10 §5.1, R12 §19 | Y |
| BLK-D | Per scenario: CLSAG count, BP+ count, encoded bytes, weight. A **bound checker**: the maximum CLSAGs per valid block under the rules (analytic, from params), asserted against the constructed block | D | 10 item 2 ("≤ ~890"), 14 | Y |

**Reported for each BLK row:**
- `validate_block_transactions` wall time;
- `submit_block` wall time;
- verify threads ∈ {1, default} (after 10's item 4).

**Repetitions:** 5 per scenario (BLK-4: 3) × 3 processes.

**Fixtures:** PX proofs are pre-generated **outside** the window into
`C:\bsbench\fixtures\<commit12>\` (≈ 45 s and 3.8 GB each). The fixtures are keyed by the
kernel id and invalidated when it changes.

#### MP: Mempool (file `chain/tests/bench_mempool.rs`, owner 12; 45 reviews)

| ID | Workload | Class | Req |
|---|---|---|---|
| MP-1 | Extension revalidation per entry, pool N ∈ {1k, 5k, 20k} | T | 12 W1, R12 §10 |
| MP-2 | **Reorg** revalidation (`after_reorg = true`) per entry, N ∈ {1k, 5k} plus one 20k point (W1 acceptance: < 1 s at 20k after W1) | T | 12 M12-1/W1 |
| MP-3 | Reorg that returns PX transactions: number of proofs verified (must be 0 after W2) | D | 12 W2 |
| MP-4 | Eviction under flood (the existing `eviction_under_a_flood_stays_fast`, moved to a ratio or counter) | T | 12, F45-7 |
| MP-5 | PX-lane congestion simulation: honest inclusion latency in blocks under a 64 MiB deploy flood | S | 14 item 3 |

**Availability at X0:** MP-1, MP-2 and MP-4 yes; MP-3 and MP-5 after 12 W2 and 14 item 3.

#### PX: PX and ZK (files `px/tests/bench_px.rs` and `zk/tests/decode_memory.rs`, owner 22; 20, 23, 27 and 28 contribute)

| ID | Workload | Class | Req | X0 |
|---|---|---|---|---|
| PX-1 | Transfer: prove / verify / size ×5; verify at `RAYON_NUM_THREADS` = 1 and default; peak memory | T, M | R12, 27 | Y |
| PX-2 | Vault LOCK and CLAIM, as PX-1 | T, M | R12 | Y |
| PX-3 | **Widest n_fn = 2** (CLAIM + LOCK, fixture `unified.rs:549`) ×5: size min/max, prove, verify, peak | T, M | 22 W1(a), 28 W28-3, P0-3 | N (needs 28 W28-3) |
| PX-4 | Height-scaling series, test function at 2^16 / 2^17 / 2^18 non-CPU heights, as far as RAM allows; fit the bytes per level | T, M | 22 W1(b) | Y (2^16), ? |
| PX-5 | Adversarial verify: (i) valid proof padded to ≈ 4 MiB (test-only codeword count); (ii) invalid with a corrupted last final-poly coefficient. RAYON 1 and default | T | 22 W1(c), ZK-F4, 10 §3.2 | Y |
| PX-6 | Decode peak for a crafted 4 MiB empty-vector postcard proof: **process-peak method** (F45-5), baseline vs after decode, own process | M | 22 W1(d)/F22-7 | Y |
| PX-7 | Kernel cycles and table heights per shape (n_fn ∈ {0, 1, 2}, worst branches) | D | 20 W5, 19 (option B only) | Y |
| PX-8 | Verify time per call, with and without the periodic-column cache | T | 23 W9/W11, F22-13 | N |
| PX-9 | Reserved for 27: proving time and memory per shape, SIMD build variants (prover only; the verifier stays pinned) | T, M | 27, P2-5 | N |

#### SC: Scalability model (file `chain/tests/bench_scale.rs`, owner 45; 35 and 21 review)

**Common rules:** `ZeroPow`, so RandomX is excluded (its 256 MiB caches are RX-1 and 07's
metric). Chains are pre-generated outside the window as `blocks.dat` fixtures.

| ID | Workload | Class | Req |
|---|---|---|---|
| SC-1 | `blocks.dat` bytes per block, per scenario, against R12's disk formula | D | R12 §4, roster |
| SC-2 | Replay RSS against N: S0 at N ∈ {10k, 25k, 50k, 100k}; S1 (5 v1 tx/block) at N ∈ {1k, 2k, 5k}; one process per point; baseline after `open` of an empty store. Linear fit gives KB/block ± CI; compare with 6 KB + 4.5 × v1 | M | R12 §5, §19.4, F45-10 |
| SC-3 | Undo bytes per block (PX `Frontier` + roots clone vs 21-F delta), by accounting | D | 21-F, R10-6, I1 |
| SC-4 | Restart (replay) time against N, 1 thread | T | R12 §6, 01 item 4 (startup PoW sampling at 48 samples, 1 and 8 threads, real RandomX, separate row) |
| SC-5 | PX contribution: a small chain with ≈ 20 PX transactions; RSS slope per PX byte (factor ≈ 1.0?) | M | R12 §5 |
| SC-6 | Published model: the fitted coefficients and time-to-16 GB per scenario, replacing R12's [est] rows | report | roster Q3 |

#### SY / NET / RPC / WAL: Sync, network, RPC and wallet (owners 31, 30, 36 and 39 respectively; 45 reviews)

| ID | Workload | Class | Req |
|---|---|---|---|
| SY-1 | Header sync throughput of 4,096 real-PoW headers across one switch | T | 31, R12 §7 |
| SY-2 | Tip-announcement latency under a 2,000-header batch load (`SlowCountingPow`) | T | 31 S5 |
| SY-3 | Presync IBD of a synthetic 50k-header chain: hash count (D, counting PoW) and wall time at 4,096 real headers | D, T | 31 S7 |
| SY-4 | Fork choice with 1,000 heavier leaves (linearity ratio) | T | 02 F-6 |
| SY-5 | Verifications saved by W-4 in a failed 10-block reorg | D | 02 W-4 |
| NET-1 | Handshake latency and CPU (v1; later v2 with ML-KEM) | T | 30 W6 |
| NET-2 | 9 MB frame send/receive throughput and peak memory per connection | T, M | 30 W7, T-1 |
| RPC-1 | P2P `with_chain` probe latency under 200 concurrent RPC reads | T | 36 W2/F36-3 |
| RPC-2 | `/px/commitments` latency and allocation at 10^5 records | T, M | R12 §19.6 |
| WAL-1 | Wallet sync bytes per block: full `/blocks` hex vs the compact feed | D | 39, R12-7 |
| WAL-2 | `tree_at` at 10^5 / 10^6 commitments; incremental tree after 39's fix | T | R12-8 |
| WAL-3 | PX scan per record at 21 and 1,000 addresses | T | R12-9 |

Reserved for 39: WAL-4 onwards.

#### LAB: Labnet evidence metrics (owner 09 for the labnet code; 45 specifies)

Added to `metrics.csv` and `summary.json`:
- per process: `peak_ws_mb` (the OS peak: Windows `PeakWorkingSet64` via PowerShell, Linux
  `VmHWM`) as well as the current value;
- `cpu_s` per process;
- `blocks_dat_bytes` per node;
- competing blocks per height (stale proxy);
- per miner: the seed-switch gap (s) and the hash-rate dip during prebuild;
- RSS before and after each switch (07).

These cover M9-7 and F45-3.

#### SIM: Simulations (not timing; no exclusive window)

- **03 `tools/daa-sim`:** a seeded scenario table (commit, seeds, rule id).
- **05:** the reference corpus generation.
- **26:** the P-5 re-run.

These run in low-priority slots (§5.7). Their outputs go to their owners' evidence
directories under the same `machine.json` convention.

### 5.3 Machine-state recording (`machine.json`)

Written by `blacksilk-bench machine` at the start **and** end of each window. The end
snapshot detects drift: plan changes, new processes, thermal state. Everything is collected
by `std::process` calls to OS tools, with no FFI.

| Field group | Windows source | Linux source |
|---|---|---|
| CPU model, cores, logical CPUs, base/max MHz, L2/L3 | `Get-CimInstance Win32_Processor` | `/proc/cpuinfo`, `lscpu` |
| Microcode | `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0` "Update Revision" (`reg query` via PowerShell) | `/proc/cpuinfo` microcode |
| SMT topology | assumed pairs (2k, 2k+1) [assumed; record the assumption] | `/sys/devices/system/cpu/cpu*/topology/thread_siblings_list` |
| RAM total, modules, speed | `Win32_PhysicalMemory` | `/proc/meminfo`, `dmidecode` (if permitted) |
| OS and build | `Win32_OperatingSystem` | `uname -a`, `/etc/os-release` |
| Power | `powercfg /getactivescheme` (must be High performance during windows) | governor per CPU, `intel_pstate/no_turbo` or `cpufreq/boost`, `energy_perf_bias` |
| Virtualization and security | `Win32_ComputerSystem.HypervisorPresent`; Defender RT (`Get-MpComputerStatus`) | `systemd-detect-virt` |
| Memory policy | — | THP `enabled`/`defrag`, `vm.overcommit`; ASLR `randomize_va_space` |
| Load | 30 × 1 s `\Processor(_Total)\% Processor Time`; top 10 processes by CPU; any `blacksilk-*`, `cargo`, `rustc`, `cargo-fuzz` or labnet process | `/proc/loadavg`, `mpstat` if present, `ps` top 10 |
| Frequency during runs | `\Processor Information(_Total)\% Processor Performance` sampled every 5 s [assumed counter semantics; recorded, not gated] | `scaling_cur_freq` sampled |
| Free RAM and disk | `Win32_OperatingSystem.FreePhysicalMemory`; `Get-PSDrive` | `/proc/meminfo`, `df` |
| Toolchain | `rustc -vV`, `cargo -V`, active toolchain (`rustup show active-toolchain`), target triple | same |
| Build | commit, `git status --porcelain` (must be empty), `Cargo.lock` SHA-256, profile, `RUSTFLAGS`/`CARGO_*` env (must be empty unless the run declares a variant), SHA-256 of each executable | same |
| Run protocol | runner version, window id, machine-lock holder, affinity masks, priority class, environment passed, cooldowns | same |

**Preflight gates** (`blacksilk-bench preflight`; refuses unless `--allow-noisy`, which
stamps `"noisy": true` on every result):
- the machine lock is held by this run (§5.7);
- no forbidden processes are running;
- mean CPU busy < 3% over 30 s;
- free RAM ≥ the suite's declared need (RX-4: 3 GiB; PX-4: 12 GiB);
- the power plan is High performance;
- the tree is clean;
- `rustc` equals the window's pinned version.

### 5.4 Output format under `docs/evidence/`

**Directory:**
```
docs/evidence/bench-<YYYY-MM-DD>-<label>/
```
Labels: `baseline-X0`, `gate-<topic>`, `px-freeze-X1`, `final-X2`, `labnet-full-A`, …

| File | Content |
|---|---|
| `README.md` | Purpose, window id, commits (B and/or F with full hashes), exact commands, deviations, and an interpretation limited to what the data shows. It is the P-5 README template extended |
| `machine-start.json`, `machine-end.json` | §5.3 |
| `results.jsonl` | One JSON object per (workload, commit, process invocation) |
| `summary.md` | Generated table: median [95% CI], min, p90, IQR, n per workload and commit |
| `compare.md` | Only for A/B: ratio of medians [95% bootstrap CI], verdict (`faster` / `slower` / `no detectable change` / `non-comparable: <reason>`), and the A/A noise floor of the window |
| `raw/` | Optional: stdout/stderr per invocation (compressed if > 1 MB), labnet `metrics.csv` |
| `SHA256SUMS` | Of every file in the directory |

**`results.jsonl` schema** (`"schema": "blacksilk-bench/1"`):

```json
{"schema":"blacksilk-bench/1","id":"CR-2","name":"clsag_verify_ring16","class":"timing",
 "unit":"s","commit":"<40 hex>","exe_sha256":"…","invocation":2,"order_index":7,
 "params":{"threads":1,"affinity":"0x4","ring":16},
 "warmup":{"iters":20,"secs":2.1},"n":200,
 "samples":[0.00301,0.00299, …],
 "stats":{"min":…,"median":…,"p90":…,"mean":…,"iqr":…,"mad":…},
 "peak_mem":{"method":"win-peak-ws","baseline_mb":…,"peak_mb":…},
 "started_utc":"…","duration_s":…,"noisy":false,"status":"ok","notes":""}
```

**Deterministic results** use `"class":"deterministic","value":…` with no samples. CI can
assert them exactly (§5.8 B6).

**Size budget:** < 2 MB per run in git. The raw labnet logs stay compressed or out of tree,
with their SHA-256 recorded (as for seedrun2).

**Existing evidence:** the out-of-tree anchors (`bench-optA-*`, `bench-before*`,
`bench-rc-*`) are imported **once**, converted to UTF-8, into
`docs/evidence/bench-2026-09-2x-historical/` with a README stating "provenance incomplete:
machine state unrecorded". They are then referenced instead of the scratch paths (F45-11).

### 5.5 Statistical protocol

**Repetition levels (Kalibera–Jones):**
- one build per commit (layout bias is controlled by the claim threshold below);
- **≥ 3 process invocations** per workload per commit;
- iterations within a process after warm-up (counts per §5.2).

**Warm-up:**
- time-based: ≥ 2 s, or ≥ 3 iterations for workloads ≥ 0.1 s;
- first-iteration costs (cache build, fixture load) are reported separately, never mixed in.

**Estimators:**
- median (primary);
- minimum (reported; the Chen–Revels estimator for CPU-bound microbenchmarks);
- p90 (for latency workloads: SY-2, RPC-1);
- IQR and MAD for spread.

**Comparison (A/B):**
- interleaved invocations `A B B A A B …` (≥ 3 each; randomized start arm);
- ratio of medians with a **hierarchical percentile bootstrap** 95% CI (resample
  invocations, then iterations; 10,000 resamples; fixed seed so `compare.md` reproduces).

**Noise floor:** each window starts **and** ends with an A/A run (B against B) of RX-2,
CR-2 and BLK-1. The floor is δ = max(2%, the larger A/A |ratio − 1| upper CI).

**Verdict:**
- A change is **claimed only if the CI lies entirely outside [1 − δ, 1 + δ]**.
- Otherwise the verdict is "no detectable change".
- For RandomX claims, 06's stricter screen also applies: the medians must differ by more
  than 3 × IQR.

**Layout and turbo caveat:** gains below 3% are never claimed on one build (STABILIZER,
Mytkowicz). A < 3% effect that matters must be reproduced with a second build variant or on
a second machine.

**Threads:**
- single-thread workloads are pinned to one logical CPU of a non-zero core (default
  `0x4`), with its sibling idle and priority High (`start /high /affinity`; never Realtime);
- multi-thread workloads are unpinned, with the thread count explicit.

**Cooldowns:** 60 s after each RX-4 or PX group; the frequency counter is recorded.

**Failures:** a workload that panics or errors is recorded with `"status":"failed"` and the
suite continues. Nothing is retried silently.

### 5.6 The before/after baseline plan for phase 2

1. **H (harness) lands first** (items B1–B3, B5 below). It is proven behaviour-neutral by the
   restricted diff in P5 (43 reviews).
2. **B = `9e422d8` + H** is built in a dedicated worktree `C:\bsbench\src-B` (tag
   `bench-base-p2`, local; pushing follows the git policy).
3. **X0 (baseline window):** the full X0 set on B. Outputs:
   - `docs/evidence/bench-<date>-baseline-X0/`;
   - the early decision data for R12-2 (CR-2, BLK-1..6), 06 (RX), 12 (MP-1/2), and PX-1/2/5/6
     as preliminary P0-3 data;
   - the SC model fit.
4. **Gates (G):** every merge that claims performance, or that touches a measured hot path,
   runs its affected workloads interleaved, base (the head before the merge) against the
   candidate:
   - 06 W3–W8, 07 W1;
   - 10 items 1, 4, 6 and 9;
   - 12 W1/W2;
   - 21-F / I1;
   - 22 W8; 23 W9/W11;
   - 30 W7;
   - 35's storage items.

   Each writes `bench-<date>-gate-<topic>/compare.md`. Gates are batched into shared windows.
   A correctness gate (RX-D digest, differential tests) must be green on the same commit.
5. **X1 (PX freeze window):** after the single v3 kernel rebuild (20, 43), and **before** the
   ids, fingerprints and golden vectors are pinned. It gives the binding P0-3 measurements
   (PX-3, PX-4, PX-5, PX-6, PX-7) and BLK-3 under the adopted R12-2 rule (the confirmation the
   decisions log requires before R12-2 is final).
6. **X2 (final window):** at the freeze candidate F, **B and F interleaved** for the whole X0
   set, plus F-only rows for workloads that did not exist in B. The result is the phase's
   before/after report `bench-<date>-final-X2/compare.md`. The `docs/` performance tables (the
   randomx README, `docs/zk.md` §11, `docs/testnet.md` §12, R12's model rows) are regenerated
   from it (47 edits the docs).
7. **Non-comparable rows are listed explicitly:**
   - BLK-3 (R12-2 changes validity);
   - PX-1..3 (kernel id, codeword pin, R2-C6 option A);
   - MP-* if D8 changes the conflict keys.

   For each, both values are shown with the reason, and none is presented as a speed-up.
8. **The drift check:** B at X0 against B at X2 per workload. A |Δ| outside the X2 noise floor
   is reported in the README as machine drift, and only X2's interleaved ratios are used.

### 5.7 Machine-time schedule and exclusive windows

**Machine:** one shared host (4C/8T, 16 GiB).

**The machine lock:**
- `C:/bszkeval/p2/MACHINE-LOCK` holds the holder, the window id, the start and the expected
  end. It is written by the coordinator only.
- During an exclusive window:
  - no cargo, rustc or fuzz;
  - no labnet;
  - agents are limited to Read/Grep/web;
  - the power plan is High performance (restored after).

| Window | When | Exclusive? | Duration [est] | RAM peak | Contents |
|---|---|---|---|---|---|
| **P0-prep** | After H merges; before X0 | No, but **no other heavy job** (low priority, `start /low`) | 2–3 h | ≈ 4–6 GiB | Build B's test executables (fat LTO); generate fixtures: 3 PX proofs, BLK blocks, MP pools of 20k, SC chains up to 100k/5k blocks; checksum them |
| **X0 baseline** | As soon as P0-prep is done; **seedrun2 must be stopped first** | **Yes** | **≈ 4 h** | ≈ 3 GiB (RX-4), ≤ 12 GiB (PX-4 at 2^18, [unknown]) | Preflight and A/A (15 min); RX-1..5, 8 (≈ 60 min; the 1-thread dataset once); CR (10 min); BLK (20 min); MP-1/2/4 (10 min); PX-1/2/4/5/6/7 (45 min); SC-1..5 (35 min); SY-1/4, NET-2, RPC-2, WAL-2/3 (20 min); closing A/A and machine-end (10 min) |
| **G-n gates** | Batched, e.g. nightly, ≤ 1 per day | **Yes** | ≤ 45 min each; ≈ 8 expected (≈ 6 h total) | Workload-dependent | Only the affected workloads, ABAB × 3 |
| **L-A, L-B labnet full-mode** (09's runs A and B, P0-13) | After implementation wave 1 (decisions log) | **Yes** (memory: 2 full miners with prebuild ≈ 8.8 GiB + 4 nodes ≈ 2.2 GiB) | ≈ 7–8 h each (2,400+ blocks at 10 s plus dataset builds) | ≈ 11–12 GiB | Labnet with LAB metrics; outputs `labnet-full-A/B`. Timing results from other suites are **not** taken during L |
| **X1 PX freeze** | After the v3 kernel rebuild; before the id and golden-vector pin | **Yes** | ≈ 1.5 h (+ 1 h prep for fixtures) | ≤ 12 GiB | PX-3..7, BLK-3 under the adopted rule |
| **X2 final** | At the freeze candidate, before the rc tag | **Yes** | **≈ 5 h** | as X0 | B/F interleaved X0 set; F-only rows; drift check |
| **Low-priority slots** | Outside X/G/L windows | No (low priority; one at a time) | as needed | ≤ 6 GiB | 03 daa-sim, 05 corpus (12.5–21 CPU-h, sharded), 26 P-5 re-run (≈ 4 h), fuzz campaigns (41). Never concurrent with prep for a window, since the fixtures' generation time is not measured but their RAM competes |

**Total exclusive time [est]:** 4 + 6 + 1.5 + 5 ≈ **16.5 h** of benchmark windows, plus
≈ 15 h of labnet full-mode windows (09's).

**Sequencing constraints:**
- X0 before the first G gate (the gates cite X0's noise floor);
- the R12-2 decision data (CR-2, BLK) is available at X0;
- X1 strictly after 20's rebuild and before 01's vector freeze;
- X2 last.

### 5.8 Work items

| # | Item | Files (ownership) | External effect | Identity | Tests | Bench | Docs | Size | Pri |
|---|---|---|---|---|---|---|---|---|---|
| **B1** | `tools/benchkit`: zero-dependency harness. Gate, measure, stats (median/min/p90/IQR/MAD), hierarchical bootstrap, JSON-line emit, peak-memory probe (Linux VmHWM; Windows peak working set via PowerShell), `#![forbid(unsafe_code)]` | new `tools/benchkit/**` (45); workspace `Cargo.toml` members line (43 coordinates) | none | none | unit tests of the statistics against hand-computed values; the bootstrap is deterministic under a seed; the gate returns early without the env var | — | module docs | S | **P0** |
| **B2** | `tools/bench` runner: `machine`, `preflight`, `build`, `run`, `interleave`, `compare`, `report`; the suite table as Rust constants (no TOML dependency); env clearing; affinity/priority via `cmd /c start` (Windows) or `taskset` (Linux); executable hashing | new `tools/bench/**` (45); `Cargo.toml` members (43) | none | none | compare golden files; preflight refuses a dirty tree and forbidden processes (mocked process list) | — | `docs/evidence/BENCHMARKS.md` (B5) | M | **P0** |
| **B3** | Core X0 bench files: CR (45), BLK (45; 10 reviews), SC (45; 35 reviews); RX (06); MP-1/2/4 (12); PX-1/2/4/5/6/7 (22; 20 for PX-7). All are `#[ignore]` + `gate()` + `bench_*` | `crypto/tests/bench_crypto.rs`, `tx/tests/bench_block.rs`, `chain/tests/bench_scale.rs` (45); `randomx/tests/bench_randomx.rs` (06); `chain/tests/bench_mempool.rs` (12); `px/tests/bench_px.rs`, `zk/tests/decode_memory.rs` (22); dev-dependency lines in each crate's `Cargo.toml` (crate owners) | none | none | smoke mode runs each once; the BLK-D bound checker asserts the analytic maximum | produces X0 | — | M | **P0** |
| **B4** | CI hygiene: `--skip bench_` in `randomx-full`; a weekly `bench-smoke` job (`BLACKSILK_BENCH=smoke`, no timing verdicts, deterministic metrics asserted); add `tools/benchkit` and `tools/bench` to the unsafe-root check list | `.github/workflows/ci.yml` (43) | none | none | the CI job itself | — | ci.yml comments | S | **P0** (the skip) / P1 (smoke) |
| **B5** | Methodology document: §5.1–§5.5 condensed; the evidence format; the window protocol; how to run on Linux trial devices | new `docs/evidence/BENCHMARKS.md` (45; 47 coordinates) | none | none | — | — | itself | S | **P0** |
| **B6** | LAB metrics (peak working set, CPU s, `blocks_dat_bytes`, competing blocks, switch gap, RSS around switches) | `tools/labnet/src/main.rs` (**09 owns**, I4); 45 supplies the field spec | none | none | a labnet smoke run shows the fields | L-A/L-B | labnet README | S | **P0** (with 09's I4) |
| **B7** | Run X0, commit the evidence, import the historical anchors (F45-11) | `docs/evidence/bench-*-baseline-X0/`, `bench-*-historical/` (45) | none | none | — | X0 | README of each | S (plus 4 h machine) | **P0** |
| **B8** | Scalability model report: fitted coefficients against R12, time-to-16 GB per scenario, IBD with measured thread scaling | `docs/evidence/bench-*/scale-model.md` (45); R12 correction note and `docs/testnet.md` RAM guidance (47) | none | none | SC-D assertions (bytes/block exact) in the smoke job | SC | as listed | S | **P1** |
| **B9** | X1 and X2 runs; the final before/after report; regenerate the docs perf tables | `docs/evidence/bench-*-px-freeze-X1/`, `…-final-X2/` (45); doc tables via 47 | none | none | — | X1, X2 | randomx README, zk.md §11, testnet.md §12, R12 rows | M (+ 6.5 h machine) | **P0** (X1 gates P0-3) / **P1** (X2) |
| **B10** | Replace absolute wall-clock assertions with ratios or counters (F45-7) | `chain/src/mempool.rs` tests (12), `chain/src/store.rs` tests (35), `wallet/tests/e2e.rs` (39/37) | none | none | same tests, now load-independent | — | — | S | P2 |
| **B11** | `[profile.profiling]` (inherits release, `debug = "line-tables-only"`, `strip = false`) for samply/perf; `rust-toolchain.toml` pin (1.98.1) | workspace `Cargo.toml`, new `rust-toolchain.toml` (**43** owns) | none (profiles of shipped binaries unchanged) | none | the build works | used by 06 O0 | BENCHMARKS.md | S | P2 |
| **B12** | Remaining workloads as their features land: RX-6/7/D, PX-3/8/9, MP-3/5, SY-*, NET-*, RPC-*, WAL-* | the domain owners' `tests/bench_*.rs` (06, 22/28, 12/14, 31, 30, 36, 39, 27) | none | none | smoke | G / X1 / X2 | — | S each | P1 |
| **B13** | (P3) Linux bare-metal counter runs (`perf stat`) for 06's O0 and RX-6; optionally a deterministic instruction-count lane (iai-callgrind-style) as an off-tree tool | trial device (ops); off-tree script | none | none | — | 06 O0 | BENCHMARKS.md | M | P3 |

**Order:** B1 → B2 (minimal `machine`/`preflight`/`run`) → B3 core + B4 skip + B5 → P0-prep →
**X0 (B7)** → gates as merges arrive → B6 before L-A → X1 → B8 → X2 (B9). B10–B13 run in
parallel where they fit.

---

## 6. Dependencies and conflicts (by roster number)

| # | Relationship |
|---|---|
| **06** | Its §5.1 methodology is merged into §5.1–§5.5 here (one evidence format). `randomx/tests/bench_randomx.rs` is 06's file. `examples/bench.rs` stays a quick operator tool (it may use benchkit's JSON; 06 decides). W2's digest (RX-D) gates RX timings |
| **05** | Shares `randomx/tests/`: file names `bench_randomx.rs` (06), `equivalence.rs` (06), corpus tests (05). The corpus generation runs in low-priority slots |
| **07** | RX-1 and the RSS-across-switch figures (LAB) are its before/after metrics |
| **08** | RX-D digests; aarch64 numbers come later (B13 or CI arm runners, where timings are not comparable) |
| **09** | Owns `tools/labnet` (B6) and `miner --benchmark`. The miner benchmark should emit the same JSON schema, so 40's D0 measurement is evidence-grade. L-A/L-B windows |
| **10** | BLK specification from its §5.1; item 4's `--verify-threads` is a BLK parameter; item 3 ownership moves to 45 with 10 reviewing (per its "45 owns the methodology") |
| **12** | MP file owner; W1 acceptance (< 1 s at 20k) is judged by the runner, not by an assertion in the normal suite |
| **14 / 15 / 16** | Consumers of CR and BLK; 15 W8 and 16 item 9 are implemented by 45 in `crypto/tests/bench_crypto.rs` |
| **20 / 22 / 23 / 27 / 28** | PX rows; X1 depends on 20's rebuild and 28's W28-3; F45-5 changes 22's W1(d) method |
| **21 / 35** | SC-2/SC-3 before/after for 21-F and the storage items |
| **30 / 31 / 36 / 39 / 02 / 01** | NET, SY, RPC, WAL rows; SC-4 includes 01 item 4 |
| **34** | Lock-hold histograms (10 item 5, 36 F36-3) should be emitted as benchkit JSON lines, so the actor migration has a before/after |
| **41** | Shared chain test fixtures (F45-12). Proptest is unrelated. Bench fixtures should reuse 41's `tests/common` if created |
| **43** | CI changes (B4), workspace members, `rust-toolchain.toml` and the profiling profile (B11), and the behaviour-neutral diff review of H |
| **44** | Confirms: benchkit has no dependencies; the runner uses only crates already locked; criterion rejected (F45-4) |
| **47** | Every doc performance table cites an evidence directory (F45-8) |
| **50** | BLK-4 (F10-2) doubles as a red-team reproduction |

**Conflict to avoid:** no `bench_*` file may be edited by two owners in the same wave. The
file names above are the ownership keys.

---

## 7. Open questions for the coordinator

1. **The X0 window.** It needs ≈ 4 h exclusive plus 2–3 h of low-priority prep, and
   **seedrun2 must be stopped first**. It is at height ≈ 2352: is 2400 required? When?
2. **Approve the two internal crates** `tools/benchkit` (zero deps) and `tools/bench` (runner;
   may it use `clap` and `serde_json`, already in `Cargo.lock`?) as workspace members.
3. **Power plan:** may the runner switch the shared desktop to High performance during
   windows and restore Balanced afterwards?
4. **Is a bare-metal Linux trial device available** for hardware counters (06's O0 branch-miss
   hypothesis; B13)? Without one, that hypothesis stays [unknown] and O1's gain is sized only
   by before/after timing.
5. **Accept the claim rule:** no speed-up below max(2%, the A/A floor) is claimed, and none
   below 3% without a second build or machine.
6. **Import the out-of-tree anchors** (`C:/bszkeval/bench-*.txt`) into `docs/evidence` as a
   "historical, provenance incomplete" set (F45-11)?
7. **Should `rust-toolchain.toml` (1.98.1) land now** (43)? Otherwise a `stable` bump between X0
   and X2 would force re-running B at X2 anyway. That is already planned, but the preflight
   would then refuse X0 fixtures.

---

## 8. Sources

**Benchmarking methodology (academic):**
- T. Mytkowicz, A. Diwan, M. Hauswirth, P. Sweeney, "Producing wrong data without doing
  anything obviously wrong!", ASPLOS 2009. https://dl.acm.org/doi/10.1145/1508244.1508275
- C. Curtsinger, E. Berger, "STABILIZER: statistically sound performance evaluation",
  ASPLOS 2013. https://dl.acm.org/doi/10.1145/2451116.2451141 ; PDF:
  https://people.cs.umass.edu/~emery/pubs/stabilizer-asplos13.pdf
- T. Kalibera, R. Jones, "Rigorous benchmarking in reasonable time", ISMM 2013.
  https://dl.acm.org/doi/10.1145/2464157.2464160 ; https://kar.kent.ac.uk/33611/
- J. Chen, J. Revels, "Robust benchmarking in noisy environments", arXiv:1608.04295 (HPEC
  2016). https://arxiv.org/abs/1608.04295

**Noise control:**
- LLVM, "Benchmarking tips" (ASLR, governor, cpuset shield, SMT siblings, `no_turbo`,
  `perf stat -r`, < 0.1% variation). https://llvm.org/docs/Benchmarking.html
- pyperf, "Tune the system for benchmarks" (`pyperf system tune`: governor, min frequency,
  irqbalance, `perf_event_max_sample_rate`, turbo; Windows: priority only).
  https://pyperf.readthedocs.io/en/latest/system.html
- nanobench reference (epochs, `minEpochTime`, `err%`; frequency-scaling and turbo warnings
  recommending `pyperf system tune`). https://nanobench.ankerl.com/reference.html ;
  https://github.com/martinus/nanobench/blob/master/src/docs/reference.rst
- Microsoft, "Acquiring high-resolution time stamps" (QPC; fixed 10 MHz under a hypervisor;
  invariant TSC). https://learn.microsoft.com/en-us/windows/win32/sysinfo/acquiring-high-resolution-time-stamps
- Microsoft, "Powercfg command-line options".
  https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options
- Microsoft .NET, `Process.PeakWorkingSet64` ("maximum amount of physical memory … since it
  was started"; equals the Working Set Peak counter).
  https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process.peakworkingset64
- Linux man-pages, proc_pid_status(5) (`VmHWM` peak RSS; "inaccurate" caveat).
  https://man7.org/linux/man-pages/man5/proc_pid_status.5.html

**Rust toolchain and tools:**
- Rust std, `Instant` (Windows: `QueryPerformanceCounter`; Unix: `clock_gettime(CLOCK_MONOTONIC)`).
  https://doc.rust-lang.org/std/time/struct.Instant.html
- The Cargo Book, Profiles (profile selection; `test` inherits `dev`; `bench` inherits
  `release`; `--release` selects `release`). https://doc.rust-lang.org/cargo/reference/profiles.html
- criterion 0.8.2 (defaults: 100 samples, 3 s warm-up, 5 s measurement, 100,000 resamples,
  noise 0.01, significance 0.05). https://docs.rs/criterion/latest/criterion/struct.Criterion.html ;
  its manifest (dependency `alloca 0.4`):
  https://docs.rs/crate/criterion/latest/source/Cargo.toml.orig ; analysis process:
  https://bheisler.github.io/criterion.rs/book/analysis.html
- alloca 0.4.0 (`build.rs`, `alloca.c`, build-dependency `cc`).
  https://docs.rs/crate/alloca/latest/source/ ;
  https://docs.rs/crate/alloca/latest/source/Cargo.toml.orig
- hyperfine (Rust; `--warmup`, `--runs`, `--prepare`, `--export-json`, `-N`, outlier
  detection). https://github.com/sharkdp/hyperfine
- samply (Rust sampling profiler; ETW on Windows, perf events on Linux).
  https://github.com/mstange/samply

**Blockchain projects:**
- Bitcoin Core, `doc/benchmarking.md` (bench_bitcoin; "may be rejected when a clear
  end-to-end performance improvement cannot be demonstrated").
  https://github.com/bitcoin/bitcoin/blob/master/doc/benchmarking.md
- Bitcoin Core, `src/bench/nanobench.h`.
  https://github.com/bitcoin/bitcoin/blob/master/src/bench/nanobench.h
- benchcoin (IBD blocks 840,000 → 855,000 from a dedicated peer; hyperfine; flamegraphs;
  dedicated 16-core machine with reserved cores; JSON with config, machine specs, results).
  https://github.com/bitcoin-dev-tools/benchcoin
- Bitcoin Core IBD tracking PR #32043 (hyperfine with `-reindex-chainstate`/`-stopatheight`).
  https://github.com/bitcoin/bitcoin/pull/32043
- Zebra PR #10444, "add criterion benchmark suite and CI workflow" (merged 2026-04-21;
  critcmp base vs PR; "10 to 20% Ubuntu CI runner variance"; 150% alert threshold).
  https://github.com/ZcashFoundation/zebra/pull/10444
- Monero `tests/performance_tests/main.cpp` (filter, loop multiplier, min/median stats,
  timings database; CLSAG and BP+ tests).
  https://github.com/monero-project/monero/blob/master/tests/performance_tests/main.cpp

**Internal (repository and phase-2 inputs):**
- `docs/reviews/full-review-2026-09-27/R12-performance.md`;
  `docs/reviews/full-review-2026-09-27.md`; `docs/reviews/autonomous-session-2026-09-27.md`.
- Phase-2 dossiers 01–22, 25, 28, 30, 31 and 36; `C:/bszkeval/p2/decisions.md`.
- Measurement files: `C:/bszkeval/bench-before-idle.txt`, `bench-before.txt`,
  `bench-after.txt`, `bench-optA-summary.txt`, `bench-rc-summary.txt`,
  `stress-compare.log`, `seedrun2/metrics.csv`; `docs/evidence/*`.
