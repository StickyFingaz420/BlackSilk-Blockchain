# 27 zk-performance: research dossier (phase 2, phase 1: research and briefing)

> Historical record (2026-09-27). Superseded where it conflicts with the code: the ZK parameter set is BS-ZK-3 (73372e9; BS-ZK-4 pending). Current: [docs/consensus.md](../../../consensus.md), [docs/STATUS.md](../../../STATUS.md).

**Internal engineering work, not an audit.** Nothing here claims that BlackSilk or any
part of it is secure, audited, proven or production-ready. Zero knowledge is claimed only
as statistical and conditional (docs/reviews/zk-coverage.md §3). No build, test or
benchmark was run for this dossier (brief §4). Every speed-up figure is an estimate or
unknown until the measurement plan in §5 has been run.

Evidence classes: **[math]** mathematically established; **[test: name]** covered by a
named test; **[src]** source-read; **[meas]** measured by earlier work (source named);
**[est]** my estimate; **[assumed]**; **[unknown]**.

---

## 1. Scope and what I read

**Commit:** `9e422d8` (`rebuild/core`, after the v3 merge).

**Scope (roster 27):** the prover pipeline (`px/src/prove.rs`, `zkvm/src/prove.rs`,
`zk/src/*`), SIMD packing in `p3-monty-31` (R4-06, I1-F3), table widths and degree
(R4-07/08), grinding (R4-09). Questions: speed-ups without a consensus change; whether
target features are safe for determinism; building only the wallet prover with SIMD.

**Reviews and docs read:**
- `docs/reviews/full-review-2026-09-27.md` (register rows R4-06, R4-07/08/09, R12-*,
  P2-5, §3.12, never-change list);
- `docs/reviews/autonomous-session-2026-09-27.md` (all of it);
- `full-review-2026-09-27/R4-zk.md` (§0, §1, §5, §6, §7), `R12-performance.md`
  (§1.2–1.3, §11, §19), `I1-private-computation.md` (I1-F3, A1), `SX1-core-crossreview.md`
  (R4-01, R4-02, R4-06 rows);
- `docs/zk.md` §9.3, §11; `docs/reviews/aggregation-study.md` §1–§3;
  `docs/reviews/privacy-review.md` §2 (proof-length argument);
  `docs/evidence/px0-2026-09-23/RESULTS.md`; `third_party/README.md`;
  `docs/testnet.md` rows on proving time and memory.
- Neighbouring dossiers already written: 06 (RandomX performance), 08 (RandomX
  determinism), 10 (block validation pipeline), for overlap only.

**Code read in full:** `zk/src/config.rs`, `zk/src/lib.rs`, `zk/src/params.rs`,
`px/src/prove.rs`, `zkvm/src/prove.rs`, `zkvm/src/air/mod.rs`, `zkvm/src/air/byte.rs`,
`third_party/p3-merkle-tree/src/hiding_mmcs.rs`, `third_party/p3-fri/src/periodic.rs`,
the grinding sites of `third_party/p3-fri/src/{prover,verifier}.rs`,
`px/examples/proof_bench.rs`, `px/examples/proof_breakdown.rs` (head),
`tx/src/px_builder.rs` (proof step), workspace `Cargo.toml`, `zk/zkvm/px/wallet`
manifests, `.github/workflows/ci.yml` (flags and runners), `deploy/docker/Dockerfile`
(toolchain).

**Registry crates read (Plonky3 0.7.0, the versions pinned in `Cargo.lock`):**
- `p3-monty-31-0.7.0/src/lib.rs` (backend selection by `cfg(target_feature)`),
  `monty_31.rs:431-452` (`Field::Packing` per backend), `extension.rs:1-40` (scalar
  extension multiply dispatches to a backend function), `no_packing/mod.rs`,
  `x86_64_avx2/packing.rs:1240-1330` (`octic_mul_packed`, `base_mul_packed`),
  `x86_64_avx2/poseidon2.rs` (packed-only layer impls);
- `p3-field-0.7.0/src/packed/*` (cfg sites only);
- `p3-batch-stark-0.7.0/src/common.rs:150-320` (`from_instances`,
  `from_airs_and_degrees`);
- `p3-challenger-0.7.0/src/grinding_challenger.rs:99-235` (`grind`).
- `unsafe` counts in `p3-monty-31` backends: AVX2 87 sites in 2,571 lines, AVX-512 89 in
  2,764, NEON 88 in 2,561, no-packing 0 in 170 [src].

**Tests inventoried:** `zk/tests/{proofs,pins,field_mutations}.rs`,
`zk/src/lib.rs::schedule_tests`, `zk/src/params.rs::tests`,
`px/tests/{proof,unified,fri_schedule}.rs`, `zkvm/tests/{multi,stress,circuit_id}.rs`.
**No test builds or runs any non-scalar x86 backend**, and there is no stored proof
corpus (proofs are generated at test time and are not byte-reproducible,
`third_party/README.md`).

---

## 2. Current state

### 2.1 What exists and is sound

| Claim | Evidence |
|---|---|
| One batch STARK per PX transaction (BS-ZK-2: BabyBear, degree-8 extension, blow-up 8, 108 queries, 16 query-PoW bits, 0 commit-PoW bits) | [src] `zk/src/params.rs:30-58`, `zk/src/config.rs:90-115` |
| Hiding randomness is drawn sequentially under the lock, so salts and random codewords do not depend on the packing width or on thread scheduling *within* one call | [src] `hiding_mmcs.rs` commit block; `third_party/README.md` rounds 1–3 |
| The preprocessed/public tables are periodic columns, not Plonky3 preprocessed traces, so neither prover nor verifier re-commits the 2^16-row byte table per proof (the ~76 % verifier cost removed earlier) | [src] `zkvm/src/air/mod.rs:127-144`; [meas] aggregation-study §2 (1.3–1.5 s → 188 ms) |
| Scalar Poseidon2 (the `Hk` hash for commitments, nullifiers, tree nodes; the Fiat–Shamir sponge; Merkle verification) runs the **same generic code in every backend**: the AVX2/AVX-512/NEON files implement the Poseidon2 layers only for the *packed* type | [src] `p3-monty-31/src/poseidon2.rs:69,88` vs `x86_64_avx2/poseidon2.rs:388-560`; [test: `zk/tests/pins.rs::poseidon2_is_the_pinned_permutation`] (baseline build only) |
| Release profile: `lto = "fat"`, `codegen-units = 1`, `opt-level = 3`, `panic = "unwind"` (the upstream README's own performance advice on LTO is already followed) | [src] `Cargo.toml` |
| The prover runs the witness natively before proving and refuses early | [src] `px/src/prove.rs:160-184` |

### 2.2 Performance facts

| Quantity | Value | Evidence |
|---|---|---|
| Transfer proof: prove / verify / size | 44.6–45.2 s / 0.207–0.212 s / ~2.18 MB | [meas] zk.md §11, R12 §1.2 (before the v3 changes) |
| Vault call (n_fn = 1) | 52.7–53.0 s / 0.254–0.265 s / ~2.69 MB | same |
| Prover peak memory | 3,771 MB | same; **no tool in the repository measures it** (`proof_bench` reports time and size only) |
| Widest shape (n_fn = 2) | unmeasured | zk.md §11; roster 22 |
| Per-phase split of the 45 s | unknown | R4 §5.1 |
| Field backend of every measurement so far | scalar (x86-64 baseline: no `.cargo/config*`, no `RUSTFLAGS`, no `target-cpu` anywhere) | [src] repo-wide search; R4-06, I1-F3 |

**The v3 changes** (`CIRCUIT_ID` absorbed, canonical FRI schedule, neutral kernel ids,
PX-F5) altered the kernel and the transcript, but not the parameter set. They should
move proving time by very little [est]. The published figures still predate them and
must be re-measured (F27-4).

### 2.3 What the tests prove, and what they do not

- They prove that honest proofs verify, that the canonical form and the FRI schedule are
  enforced, and that byte mutations are refused [test: `zk/tests/proofs.rs::*`,
  `field_mutations`, `px/tests/fri_schedule.rs`].
- They prove all of this **only for the scalar x86-64 backend** (CI runs
  `ubuntu-latest`/`windows-latest` without target flags) [src: ci.yml].
- **No test compares a packed backend with the scalar one**, for field operations,
  Poseidon2 lanes or the accept/reject verdicts on a proof corpus.

---

## 3. Problems in scope

### 3.1 P-A: the prover runs on scalar BabyBear on x86-64 (R4-06, I1-F3): confirmed

**What and why.** `p3-monty-31` selects `Packing = PackedMontyField31AVX2` only under
`cfg(all(target_arch="x86_64", target_feature="avx2", not(target_feature="avx512f")))`
(`monty_31.rs:436-440`). Otherwise, on x86-64, `Packing = Self` (`:443-452`). Rust's
x86-64 targets default to the baseline (SSE2), so every DFT butterfly, every packed
Merkle leaf hash and every quotient evaluation runs one lane wide [src].

**Consequences:**
- Security: none.
- Privacy: slightly negative. A long proof delays broadcast, and makes users less
  likely to prove at all.
- Consensus: none, if applied only to the prover (but see P-B).
- Class: performance and UX (45 s, "no phones").

**Literature and prior art:**
- Plonky3's README states that `-Ctarget-cpu=native` is "required to get parity with
  the published benchmark numbers". It also says rustc does not emit AVX2/AVX-512/BMI
  by default.
- A published micro-benchmark (Apple M1, NEON, 4 lanes) gives BabyBear Poseidon2
  width 16 at 1.172 µs scalar vs 267 ns per lane packed (~4.4×). AVX2 has 8 lanes.
- Hashing is only part of the prover (DFT, quotient evaluation, memory traffic), so
  the end-to-end gain is bounded by Amdahl's law. **My estimate for the whole prover
  is 1.5–3× [est].** It must be measured before any recommendation to users.

**Trade-offs and what can go wrong:**
- An x86-64-v3 binary dies with an illegal-instruction fault on CPUs without
  AVX2/BMI2/FMA. The August 2026 Steam survey shows AVX2 on 95.4 % of machines, so
  about 1 in 20 would fail.
- A process-wide `RUSTFLAGS` also reaches the riscv32 guest build, if that runs in the
  same shell, and build scripts. The flags must be target-scoped.
- The SIMD code adds `unsafe` (third-party, already compiled-in for aarch64).

**Tests that prove the fix:** P-B's differential tests, plus benchmark evidence (§5 W1).

**Invariants:**
- Proof bytes and verdicts are backend-independent.
- The default (distributed) node binary stays on one reviewed backend per architecture.

### 3.2 P-B: "SIMD for the prover only, verifier pinned" does not match the code (correction to R4-06, I1-F3 and SX1)

**What.** The reviews treat SIMD as a prover-side choice. In Plonky3 0.7.0 a target
feature changes the **verifier's own arithmetic** in the same binary.

**The scalar extension-field multiply takes a backend path.**
- `MontyField31`'s `ext_mul` for degree 8 calls `octic_mul_packed` (`extension.rs:26-33`).
  - Under AVX2 that is an 8-term `PackedMontyField31AVX2::dot_product`
    (`x86_64_avx2/packing.rs:1254-1300`).
  - Without packing it is the generic `p3_field::extension::octic_mul`
    (`no_packing/mod.rs:38-47`).
  - The same holds for `base_mul_packed`.
- The verifier does its constraint folding, OOD checks and FRI folding in the degree-8
  challenge field, so its verdict passes through this code [src].

**The Merkle and DFT types are generic over `<Val as Field>::Packing`.**
`zk/src/config.rs:46-57` defines them this way, so any prover-side code on the verifier
path (setup, periodic LDE) is also backend-specific [src].

**aarch64 already runs a different backend today.**
- NEON is part of every aarch64 target's baseline, and Plonky3 enables its NEON packing
  whenever `target_feature="neon"`.
- Disabling NEON is not an option: rustc warns that toggling `neon` on hard-float
  aarch64 is unsound, because it changes the float ABI (rust-lang/rust #131058,
  #133417).
- So an ARM node (e.g. an Apple Silicon machine in the trial) necessarily verifies with
  NEON arithmetic, while x86 nodes verify with scalar arithmetic.
- "Pin the verifier to one backend" is therefore impossible across architectures. The
  only available control is **differential evidence**.

**AVX-512 is not runtime-tested upstream.**
- Plonky3's CI runs its AVX2 leg's tests but builds the `+avx512f` leg only ("build
  only").
- A user who builds a node with `-C target-cpu=native` on a Zen 4 or Sapphire Rapids
  machine selects the AVX-512 backend (`lib.rs:37-42`). Upstream does not run that
  code in CI.

**Precedent for backend-only bugs:**
- Plonky3 PR #2157 (merged 2026-09-18, post-0.7) notes that "random and proptest sweeps
  alone do not catch the missing fold at N = 5 and 6. Only the maximum-limb test
  does". This was a bug in the PR under development, not in a release.
- #2262 (0.8) fixed wrong results in a NEON-assembly Poseidon2 for Goldilocks with
  non-canonical constants. That is not our field or our constants, but it is the same
  class of defect.

In each case a SIMD path diverged from the generic code, and random tests were not
enough to catch it.

**Security consequences:**
- A backend-specific arithmetic bug in the verifier would split nodes of different
  architectures or builds on the validity of a PX block. That makes it a
  consensus-critical, latent hazard.
- No bug is known. Field arithmetic is exact, so correct implementations agree by
  construction [math]. The risk is purely an implementation defect.

**Prior art:**
- Bitcoin Core and Monero ship one reference binary per architecture, and test
  consensus code on every supported platform in CI.
- Plonky3 itself runs packed-vs-scalar field tests (`test_packed_field!` macros in
  `p3-baby-bear/src/*/packing.rs`), but only on the backends its CI hardware exercises.

**Solutions:**
- (i) A distributed node binary on the baseline backend per architecture.
- (ii) In-binary differential tests (packed vs generic) that run under each backend
  build.
- (iii) A cross-build verdict corpus.
- (iv) A compile-time refusal of AVX-512 unless it is explicitly opted into.
- (v) The backend reported in `--version` and `/info`, next to the consensus
  fingerprint.

**Trade-offs.** (iv) blocks a `target-cpu=native` build on AVX-512 machines until the
opt-in flag is passed. That is an acceptable friction for a consensus-adjacent choice.

**Is it consensus-critical?** The *hazard* is. The mitigations change nothing
externally visible.

**Tests:** §5 W2 and W3.

**Invariants:** every node verdict on every proof is identical across all backends that
BlackSilk distributes or supports.

### 3.3 P-C: the query-grinding witness reveals the prover's thread structure (new, privacy)

**What.** The FRI prover grinds the query proof-of-work with `challenger.grind(16)`
(`third_party/p3-fri/src/prover.rs:108`). The witness is published in every proof
(`query_pow_witness`, `prover.rs:158`).

**How the search runs.** `DuplexChallenger::grind` (p3-challenger 0.7.0,
`grinding_challenger.rs:109-231`) searches
`(0..num_batches).into_par_iter().find_map_any(...)`:
- The candidate range [0, p) is split by rayon. Its `Splitter` starts with
  `current_num_threads()` splits and halves them, so "the effective number of pieces
  will be `next_power_of_two()`". Stolen jobs split again.
- Each piece is scanned sequentially from its start.
- `find_map_any` returns **any** hit, not the first. In rayon's words, it "may not be the
  first non-None value".

**What the witness reveals.** The witness is therefore, with high probability, within
roughly 2^16–2^18 of a multiple of p/2^d, where d grows with the prover's thread count
[src; est for the constant].
- An observer tests the witness against multiples of p/2^d, for d = 1…8.
- From that, the observer learns a lower bound on the prover's split depth, i.e. its
  thread-count class.

**How it arose.** The upstream comment says the search "is semantically equivalent to
serially trying witnesses". It is equivalent for validity, not for *which* witness.
BlackSilk's privacy review repeats the serial reading: "Grinding picks the first nonce
whose next output bits are zero" (`docs/reviews/privacy-review.md` §2, item 3).

**Consequences.**
- Privacy (metadata): a PX proof carries a coarse, public, persistent fingerprint of the
  proving device's thread count. It is worth about 1–2 bits across the population.
- It links PX transactions made by the same device, which is meaningful in small
  anonymity sets such as the seven-device trial.
- It is **not** a witness leak: the value depends on scheduling and on the public
  transcript, not on secrets. The proof-length argument of privacy-review §2 stays
  valid: positions are still uniform conditioned on the grinding success.
- Not consensus. Security: none.

**Literature.** I found no published treatment of fingerprinting through a PoW nonce.
This finding is novel as far as my search went. The mechanism rests on the rayon
documentation and the rayon source.

**Solutions:**
- (a) Make the witness a deterministic function of the transcript: the smallest valid
  nonce (`find_map_first` over fixed-size ordered chunks). The witness then carries
  nothing beyond the public transcript, whatever the thread count or SIMD width.
- (b) A uniformly random start per proof. This is weaker: parallel pieces still sit at
  offsets from that start, so it hides less.
- (c) Grind on one thread. That costs about 65k scalar permutations, ≈ 80 ms at 16 bits
  [est], which is negligible against 45 s. It does not scale if R4-09 raises grinding
  to 20–22 bits (≈ 1–4 M permutations).

(a) is preferred.
- It can be implemented as a **one-line change plus chunking** in a patched
  `p3-challenger`, or as a delegating challenger wrapper in `zk/src/config.rs`.
- The verifier is untouched: `check_witness` accepts any valid nonce. So this is
  prover policy only, and old proofs stay valid.

**Trade-offs.**
- A fourth patched crate in `third_party`, to be re-ported at the 0.8 migration.
- `find_map_first` must finish every chunk left of the hit. With ordered chunks of
  about 2^12 candidates, the extra work is small [est].

**Tests:**
- A demonstration test first: grind the same transcript state under rayon pools of
  1, 2, 8 and 16 threads, and show that the witnesses cluster by thread count.
- After the fix: identical witnesses across pools, equal to the minimal valid nonce
  (brute-forced in the test).
- Every existing proof test still passes, and the corpus of W3 cross-verifies.

**Invariants:** the verifier's `check_witness` logic and transcript order are unchanged.

### 3.4 P-D: measurement gaps

The following have never been measured:
- the per-phase profile (trace generation, main LDE and commit, LogUp, quotient, FRI,
  openings);
- memory by phase and by thread count;
- the n_fn = 2 shape;
- a SIMD baseline;
- single-thread verification.

`proof_bench` has no memory figure and no n_fn = 2 fixture. The 3,771 MB figure cannot
be reproduced from the repository.

Plonky3 already emits `tracing` spans (`info_span!` in `p3-batch-stark/src/prover.rs`
and `p3-fri`). `tracing` and `tracing-core` 0.1 are already in `Cargo.lock`, so a
~100-line span-timing subscriber written in the example needs no new crate [src].

### 3.5 P-E: verifier per-call recomputation (no consensus change possible, unmeasured)

Every `zkvm::prove::verify`:
- rebuilds `Table`s and their periodic columns, including the kernel's program table
  (`air/mod.rs:139`);
- hashes all periodic columns into the statement digest, including 2^16 × 5 byte-table
  values (`prove.rs:67-91`);
- builds a fresh `ZkConfig` (Poseidon2 constants);
- derives the symbolic lookups of every AIR in `ProverData::from_airs_and_degrees`
  (`zk/src/lib.rs:162-166`).

Plonky3 0.8 added "Cache AIR profiles at setup" (#2215), which shows that upstream
considers the last item a measurable cost. Caching by shape key (table kinds, execution
ids, degree bits) and memoizing the kernel program's columns cannot change a verdict,
provided the key is complete. An incomplete key would be a consensus bug, so it needs a
cached-vs-uncached differential over every consensus shape. The gain is unknown until W1
profiles verification.

### 3.6 P-F: consensus-changing levers (out of scope for no-consensus work; data only)

- **R4-07.** Degree 5 → 4 in the CPU AIR: −32 committed columns and half the CPU
  quotient domain.
- **R4-08.** Table consolidation.
- **R4-09.** Grinding 16 → 20–22 bits, trading ~5–7 queries (−5–6 % size) for
  1–4 M permutations of grinding. That is ≈ 0.15–0.6 s on 8 scalar threads or less with
  AVX2 [est]; recompute eq. (17) and both soundness targets (roster 25).

Each is a new parameter set or circuit id, so each is post-trial, at a reset or an
activation. W1 must provide the per-table and per-phase data these decisions need.

---

## 4. New findings

| ID | Title | Severity | Status | Location | Scenario | Confidence |
|---|---|---|---|---|---|---|
| **F27-1** | x86-64 prover (and verifier) built on scalar BabyBear; no SIMD baseline measured (confirms R4-06, I1-F3) | Medium (perf/UX) | Not implemented | `p3-monty-31-0.7.0/src/lib.rs:24-47`, `monty_31.rs:436-452`; no `.cargo/config*` | 45 s / 3.8 GB proving; users defer or avoid PX; the gain is [unknown] until measured | high (fact) / low (gain) |
| **F27-2** | Target features change the **verifier's** arithmetic (extension multiply, packed MMCS/DFT types). aarch64 nodes already verify through NEON code; AVX-512 is untested upstream. No cross-backend differential exists. Corrects "prover-only / pin the verifier" in R4-06, I1-F3 and SX1 | Medium (latent consensus-split hazard; no known bug) | Not implemented | `p3-monty-31-0.7.0/src/extension.rs:26-33`, `x86_64_avx2/packing.rs:1254-1330`, `no_packing/mod.rs:38-67`; `zk/src/config.rs:46-57`; ci.yml (baseline only) | An ARM trial device, or an operator building with `target-cpu=native` on an AVX-512 machine, runs verifier arithmetic that BlackSilk never tested. A backend bug of the #2157 class splits the PX chain | high (mechanism) / low (probability of a bug) |
| **F27-3** | The published query-grinding witness reveals the prover's rayon split depth (thread-count class); privacy-review §2 wrongly says "first nonce" | Low (privacy, metadata linkability) | Not implemented | `p3-challenger-0.7.0/src/grinding_challenger.rs:172-174` (`find_map_any`); `third_party/p3-fri/src/prover.rs:108,158`; `docs/reviews/privacy-review.md` §2 | An observer clusters PX transactions by witness ≈ k·p/2^d and links a device's transactions in the seven-member trial | high (mechanism) / medium (strength; to measure) |
| **F27-4** | Performance evidence is stale and incomplete: pre-v3 figures; no memory tool; n_fn = 2 unmeasured; no phase profile; no single-thread verify | Low | Partially implemented | `px/examples/proof_bench.rs`; zk.md §11; testnet.md rows at lines 435 and 486 | Operators are given 45 s / 3.8 GB figures that nobody can reproduce; the widest-proof limit stays unknown (shared with 22) | high |
| **F27-5** | Verifier recomputes shape-invariant data on every call (config, symbolic lookups, kernel program columns, byte-table digest) | Informational | Not implemented | `zkvm/src/prove.rs:209-232`, `zk/src/lib.rs:158-167`, `zkvm/src/air/mod.rs:136-144` | Up to 3 PX proofs per block, plus relay, under the chain lock; a possible several-percent verify saving [unknown] | medium |
| **F27-6** | SIMD build hygiene: a global `RUSTFLAGS` would reach the guest build and every binary; an x86-64-v3 binary faults on the ~4.6 % of CPUs without AVX2 | Low | Not implemented | build docs, ci.yml, `zkvm/guests/build.sh` (environment) | An operator exports `RUSTFLAGS=-Ctarget-cpu=native`, rebuilds node and guest, and gets an untested backend, or a broken guest reproduction | medium |
| **F27-7** | Raising grinding (R4-09) interacts with F27-3's fix: deterministic grinding must be chunk-parallel to stay cheap at 20–22 bits | Informational | Deferred | `zk/src/params.rs:41` | — | medium |

I found **no** soundness or consensus *bug* in the prover pipeline. Everything above is
performance, hazard or metadata.

---

## 5. Implementation plan for phase 2

Order: measure first (W1), make backends safe to exercise (W2–W4), fix the leak (W6),
then decide on a distributed SIMD wallet (W5) from the evidence.

| # | Work item | Files (ownership) | Externally visible? | Identity | Tests | Bench | Docs | Diff. | Prio |
|---|---|---|---|---|---|---|---|---|---|
| **W1** | **Measurement harness.** Extend `proof_bench` with:<br>• shapes n_fn = 0, 1, 2 (reuse the vault fixture twice for n_fn = 2);<br>• CSV output: prove, verify, size and per-table rows × widths, with ≥ 5 rounds reported as median and min/max;<br>• a pure-Rust `tracing-core` span-timing subscriber for the phase profile (dev-dependency on `tracing-core =0.1.36`, already in the lock: no new crate);<br>• single-thread verify via `RAYON_NUM_THREADS=1`.<br>Peak memory is measured **outside** the process: `/usr/bin/time -v` on Linux, and a PowerShell sampler of `PeakWorkingSet64` on Windows. Scripted, no `unsafe`. | `px/examples/proof_bench.rs`, `px/Cargo.toml` (dev-deps), new `px/examples/span_profile.rs` (helper module), new `tools/bench/zk-bench.{sh,ps1}` | nothing | none | none (harness) | the full matrix below | new `docs/evidence/zkperf-2026-xx/README.md`; update zk.md §11 and testnet.md (lines 435, 486) with the re-measured figures | S | **P1** (P0 for the n_fn = 2 figure, shared with 22) |
| **W2** | **In-binary backend differential tests**, runnable under every build:<br>• `Packing` ops (+, −, ×, square, dot products of lengths 1–8) vs lane-wise scalar, over boundary vectors (0, 1, p−1, (p−1)/2, 2^27, Montgomery limb maxima, the max-limb pattern of #2157) plus a seeded random sweep;<br>• `Challenge` multiply vs `p3_field::extension::octic_mul(a, b, res, W = 11)`;<br>• `base_mul`;<br>• Poseidon2 packed state vs per-lane scalar permutation.<br>Plus `pub const FIELD_BACKEND: &str` (scalar/avx2/avx512/neon, set by `cfg`). | new `zk/tests/backend_differential.rs`; `zk/src/lib.rs` (the const) | nothing | none | property and boundary unit tests (above) | — | zk.md §9 (the backend statement) | S | **P1** |
| **W3** | **Cross-build verdict corpus.** An example writes a corpus:<br>• valid proofs: transfer, n_fn = 1, n_fn = 2;<br>• mutated variants from the `field_mutations` strategy and byte flips;<br>• the statements.<br>A second example verifies a corpus and prints a verdict vector plus its digest. CI builds baseline and x86-64-v3 (and runs on an arm64 runner): each build generates a corpus, every build verifies every corpus, and the verdict digests must be equal. Corpora are CI artifacts, not committed (~3 MB per proof). | new `px/examples/proof_corpus.rs`; `.github/workflows/ci.yml` (**owned by 43**; I supply the job spec) | nothing | none | differential (cross-build, cross-arch), adversarial (mutations) | corpus verify time per backend | review-package / testnet.md §12: "supported backends" | M | **P1** (before any SIMD binary or ARM node in the trial) |
| **W4** | **AVX-512 guard:** `#[cfg(all(target_arch = "x86_64", target_feature = "avx512f", not(blacksilk_allow_avx512)))] compile_error!(…)` in `blacksilk-zk`, next to the existing `panic = "unwind"` guard. Declare the cfg in `[lints.rust] unexpected_cfgs`. Report `FIELD_BACKEND` in `--version` and `/info` beside the consensus fingerprint. | `zk/src/lib.rs`, `zk/Cargo.toml`; `node/src` version/info line (**coordinate with the owner of `f440c4b`'s code, 36/40**) | nothing (build policy) | none | a CI compile-fail check; a `/info` field test | — | build section of README / testnet.md §12 | S | **P1** |
| **W5** | **Optional x86-64-v3 wallet build** (only if W1 shows ≥ 1.3× and W2/W3 are green):<br>• build with `--target x86_64-pc-windows-msvc` (or `-unknown-linux-gnu`), `CARGO_TARGET_<TRIPLE>_RUSTFLAGS="-C target-cpu=x86-64-v3"` and `--target-dir target/x86-64-v3`, so the guest and baseline builds are untouched;<br>• ship it as a second artifact, `blacksilk-wallet-x86-64-v3`;<br>• the node and miner stay baseline for the testnet;<br>• the baseline wallet may print a one-line hint when `is_x86_feature_detected!("avx2")` (a safe macro) is true. | release scripts (**43**), docs; optionally `wallet/src/main.rs` (hint; **37/38 own the wallet**) | nothing | none | W3 on the release build; the wallet PX e2e suite under the v3 build | before/after on the same machine | testnet.md (proving time, hardware requirement), README | S | **P2** |
| **W6** | **Deterministic grinding witness** (F27-3):<br>• (a) preferred: patch `p3-challenger` 0.7.0 as a fourth `third_party` crate. `grind` scans fixed ordered chunks (e.g. 2^12 candidates) with `find_map_first`, so it returns the minimal valid nonce. Verifier code is untouched.<br>• Alternative (b): a delegating challenger wrapper in `zk/src/config.rs` (more trait surface, more risk).<br>• Also correct privacy-review §2 item 3 and report upstream. | `third_party/p3-challenger/` (new), `Cargo.toml` `[patch]`, `third_party/README.md` (**24 owns third_party**); `docs/reviews/privacy-review.md` (**26**) | nothing: the verifier accepts any valid nonce | none | demonstration (the leak exists before the fix: witnesses under pools of 1/2/8/16 threads cluster); regression (identical witness across pools, equal to the brute-forced minimum); proofs from patched provers verify under the unpatched verifier logic (W3 corpus) | grind time at 16 and 20 bits, patched vs upstream | third_party/README.md; privacy-review §2; zk-coverage "what a proof reveals" | S | **P1** |
| **W7** | **Verifier memoization** (only if W1 attributes ≥ 10 % of verify time to it): the kernel program's periodic columns in a `OnceLock`; `ProverData::common` cached by the complete shape key (table kinds, execution ids, degree bits); the byte-table digest contribution precomputed. | `zkvm/src/prove.rs`, `zkvm/src/air/mod.rs`, `zk/src/lib.rs` (**22/23 co-own; 10 plans a `verify_decoded` entry in `px/src/prove.rs`, so sequence after it**) | nothing (verdict-identical) | none | cached-vs-uncached differential over every consensus shape and the W3 corpus; key-completeness test (two shapes differing only in each key field never share an entry) | verify time, 1 and N threads | docs/zkvm.md §10 note | S–M | **P2** |
| **W8** | **Low-memory proving mode:** measure peak memory against `RAYON_NUM_THREADS` ∈ {1, 2, 4, all}; if memory falls meaningfully, add a wallet `--prove-threads N` (sets a dedicated rayon pool for proving) and document the memory/time curve. | `wallet/src/main.rs` (**37/38**), docs | nothing | none | wallet flag test | memory vs threads | testnet.md hardware table | S | **P3** |
| **W9** | **Data for BS-ZK-3** (consensus, post-trial): per-table width and phase data from W1 to size R4-07, R4-08 and R4-09. No code here. | — | — | new identity when done | — | per-table breakdown | aggregation-study update | — | **P3** |

**Benchmark methodology (W1, fixed across runs):**
- Record the CPU model and microcode, cores/threads, RAM, OS build, toolchain `1.98.1`,
  commit, and `FIELD_BACKEND`.
- Use the Windows "High performance" power plan or the Linux `performance` governor,
  on AC power, idle machine, no other agents running (the shared 16 GB box is
  unsuitable while other workstreams run).
- Do one warm-up proof, then ≥ 5 measured rounds per cell.
- Matrix: {baseline, x86-64-v3} × {n_fn 0, 1, 2} × {threads 1, 4, all} for proving,
  and the same for verification.
- Report the median and range; keep the raw CSV in `docs/evidence/`.
- Treat a speed-up as real only if the medians differ by more than the run-to-run
  range.

**Invariants that must never change (this workstream):**
- Proof verdicts are independent of backend, thread count and build.
- The verifier's `check_witness` and transcript order are unchanged.
- The hiding randomness stays drawn sequentially under the lock (patch rounds 1–3).
- No `unsafe` in BlackSilk crates: the SIMD `unsafe` stays inside Plonky3.
- No new native dependency.
- The default distributed node binary stays one reviewed backend per architecture.

---

## 6. Dependencies and conflicts

| Roster | Interaction |
|---|---|
| 22 px-proof-system | Shares W1: the widest (n_fn = 2) proof size vs `MAX_PROOF_BYTES`, and verify times. W7 touches `zk/src/lib.rs::verify` and `zkvm/src/prove.rs`, which 22 may also own. |
| 24 plonky3-verifier-security | Owns `third_party/`; W6 adds `p3-challenger`. Backend differential (W2/W3) belongs in 24's advisory coverage matrix. The 0.8 migration brings new perf work (#2015, #2148, #2215), so compare with W1. |
| 25 zk-soundness | Grinding bits (R4-09, F27-7); W6's chunked design must hold at 20–22 bits. |
| 26 zk-privacy | F27-3 is a privacy finding; 26 owns privacy-review.md and zk-coverage. The P-5 proof-length campaign is unaffected by W6 (the witness is fixed-width), but its conditioning argument text changes. |
| 08 randomx-determinism / 43 ci-reproducibility | The same CI matrix (x86-64-v3 leg, arm64 runner); W3's job goes into 43's ci.yml. 08's `rx-x86-v3` leg can share the build. |
| 06 randomx-performance | The same question of a two-binary (baseline / v3) distribution. Decide once for miner and wallet. |
| 10 block-validation-pipeline | Plans `px/src/prove.rs` changes (decoded-proof reuse); sequence W7 after it. Parallel block verification nests with Plonky3's rayon use. |
| 44 supply-chain | Record that the AVX2/NEON paths add ~87–89 `unsafe` sites each (third-party). W4's AVX-512 exclusion. |
| 45 benchmarks-scalability | Adopt W1's methodology and CSV format into the suite. |
| 36/40 (node `/info`, fingerprint) | The W4 `FIELD_BACKEND` field. |
| 37/38 wallet | W5 hint, W8 flag. |
| 47 docs | zk.md §11 and testnet.md figures after W1. |

---

## 7. Open questions for the coordinator

1. **Is aarch64 a supported node platform for the trial?** If yes, W3 on an arm64
   runner becomes a P0 gate, because NEON verification cannot be avoided (F27-2).
2. Do you accept a **fourth patched Plonky3 crate** (`p3-challenger`) for W6, or do you
   prefer the wrapper-challenger variant in `zk/src/config.rs`?
3. For the testnet, should we distribute an **x86-64-v3 wallet** (W5) if W1 shows a real
   gain, while keeping node and miner baseline? The same decision applies to 06's miner.
4. Is a compile-time refusal of AVX-512 (W4) acceptable friction for operators who build
   with `target-cpu=native`?
5. Who runs W1 on a quiet machine? The shared 16 GB box with parallel agents invalidates
   timing and memory figures.

---

## 8. Sources

- Plonky3 README (CPU features, `-Ctarget-cpu=native`, LTO advice):
  https://github.com/Plonky3/Plonky3
- Plonky3 CI workflow (AVX2 leg tested; AVX-512F "build only"):
  https://github.com/Plonky3/Plonky3/blob/main/.github/workflows/ci.yml
- Plonky3 PR #2157, x86 dot-product fold; "random and proptest sweeps alone do not catch
  the missing fold": https://github.com/Plonky3/Plonky3/pull/2157
- Plonky3 PR #2262, NEON asm Poseidon2 round-constant reduction (Goldilocks):
  https://github.com/Plonky3/Plonky3/pull/2262
- Plonky3 v0.8.0 release notes (perf PRs #2015, #2148, #2215; packed fixes #2193,
  #2262, #2264): https://github.com/Plonky3/Plonky3/releases/tag/v0.8.0
- Plonky3 main `grinding_challenger.rs` (still `find_map_any`):
  https://raw.githubusercontent.com/Plonky3/Plonky3/main/challenger/src/grinding_challenger.rs
- Plonky3 0.7.0 sources as vendored in the cargo registry: `p3-monty-31`, `p3-field`,
  `p3-challenger`, `p3-batch-stark` (paths in §1).
- Rayon `ParallelIterator::find_map_any` / `find_map_first` documentation:
  https://docs.rs/rayon/latest/rayon/iter/trait.ParallelIterator.html
- Rayon `Splitter` (pieces = `next_power_of_two()` of the thread count):
  https://raw.githubusercontent.com/rayon-rs/rayon/main/src/iter/plumbing/mod.rs
- rustc codegen options (`target-cpu`, `target-feature`; "Using this flag is unsafe"):
  https://doc.rust-lang.org/rustc/codegen-options/index.html
- rustc known issues with target features:
  https://doc.rust-lang.org/rustc/targets/known-issues.html
- rust-lang/rust #131058 (`neon` toggling unsound, changes the float ABI):
  https://github.com/rust-lang/rust/issues/131058 ; PR #133417:
  https://github.com/rust-lang/rust/pull/133417 ; forbidden features PR #129884:
  https://github.com/rust-lang/rust/pull/129884
- Rust 1.86 announcement (`#[target_feature]` on safe fns; calling from non-feature code
  still needs `unsafe`, so single-binary runtime dispatch is unavailable to
  `forbid(unsafe_code)` crates): https://blog.rust-lang.org/2025/04/03/Rust-1.86.0/
- Cargo `profile-rustflags` (unstable, so per-package rustflags need a separate build):
  https://github.com/rust-lang/cargo/issues/10271
- x86-64 psABI microarchitecture levels (x86-64-v3 = AVX, AVX2, BMI1/2, F16C, FMA,
  LZCNT, MOVBE, XSAVE): https://gitlab.com/x86-psABIs/x86-64-ABI/-/wikis/x86-64-psABI ;
  https://en.opensuse.org/X86-64_microarchitecture_levels
- Steam Hardware & Software Survey, August 2026 (AVX2 95.40 %, AVX-512F 23.90 %):
  https://store.steampowered.com/hwsurvey/Steam-Hardware-Software-Survey-Welcome-to-Steam
- Poseidon2 scalar vs packed micro-benchmark (Apple M1 NEON; a pointer only):
  https://hackmd.io/dDpkJ_srTwqzdJ745ZK9yg
- Haböck and Al Kindi, "A note on adding zero-knowledge to STARKs", ePrint 2024/1037
  (the eq. (17) randomizer bound referenced by `zk/src/params.rs`):
  https://eprint.iacr.org/2024/1037
