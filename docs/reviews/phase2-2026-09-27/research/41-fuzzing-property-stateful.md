# 41 fuzzing-property-stateful: dossier (phase 2, phase 1 research)

Agent 41. Internal engineering work, **not an audit**. Read-only on the repository, no builds run.
Evidence classes: **[math]** · **[tested: name]** · **[src]** source-read · **[web]** · **[assumed]** · **[unknown]**.

---

## 1. Scope and what I read

**Commit:** `9e422d8` (`git rev-parse --short HEAD`, branch `rebuild/core`, clean tree).

**Brief, roster, decisions:** `C:/bszkeval/p2/brief.md` (whole); `roster.md` entries 41 and the
neighbours 02, 12, 30–34, 40, 42–45, 48, 50; `decisions.md` (whole). Dossiers that request work from
41 (all read at the relevant sections): 01, 02, 04, 05, 07, 09, 10, 12, 13, 15, 16, 17, 18, 20, 21.

**Reviews:** `docs/reviews/full-review-2026-09-27.md` (fuzz/testing rows, P0-10/11, P1-13, §5),
`docs/reviews/autonomous-session-2026-09-27.md` (§2, §6, §7, §10),
`full-review-2026-09-27/R13-testing-supplychain.md` (whole; my primary source report),
`SX2-systems-crossreview.md` (T-rows, C11, P0-10), `R12-performance.md` (§1.3 verify costs),
`AUDIT.md` (fuzz campaign sections, lines 1075–1225, 1350–1392), `docs/testnet-launch-checklist.md` (G3, G9).

**Code (read in full or at the relevant parts):**
- `fuzz/`: `Cargo.toml`, `.gitignore`, `run_campaign.sh`, all 9 `fuzz_targets/*.rs`, `src/seeds.rs`;
  on-disk `corpus/` and `artifacts/` (counted, not read).
- Seeded "fuzz" tests: `chain/tests/fuzz_block.rs`, `p2p/tests/fuzz_message.rs`,
  `tx/tests/fuzz_decode.rs` (head), `px/tests/fuzz.rs`, `zkvm/tests/fuzz.rs` (head),
  `contracts/tests/fuzz.rs` (head); `zk/tests/field_mutations.rs` (head),
  `crypto/tests/malleability.rs` (index).
- Stateful surfaces: `consensus/src/chain.rs` (API, tests index), `consensus/src/pow.rs`,
  `chain/src/manager.rs` (struct, `submit_block_in_steps`, API, `missing_bodies`),
  `chain/src/mempool.rs` (API, `add`, `revalidate`, `select`), `chain/src/store.rs`
  (`BlockStore`, `MemoryStore`, `parse_record`), `chain/tests/fork_choice.rs` (harness),
  `p2p/src/net.rs` (function index, clock/RNG/spawn sites), `p2p/src/{dandelion,limits,addrman}.rs` (imports).
- ZK: `zk/src/lib.rs` (verify, catch_unwind), `zk/src/params.rs`, `px/src/prove.rs` (verify),
  `px-core/src/kernel.rs` (`Source`, `SliceSource`, `Error`), `zkvm/src/exec.rs` (`TrapKind`).
- `tools/labnet/src/{main.rs,proxy.rs}` (args, RNG, kill paths).
- CI: `.github/workflows/ci.yml` (lint, overflow, audit, fuzz-smoke).
- Toolchain sources in the local registry: `cargo-fuzz-0.13.2/src/{options.rs,project.rs}`,
  `libfuzzer-sys-0.4.13/src/lib.rs` and `libfuzzer/FuzzerLoop.cpp`, `proptest-1.11.0/{Cargo.toml,src/test_runner/config.rs}`.

**Web (primary sources, §8):** LLVM libFuzzer docs; rust-fuzz book (structure-aware fuzzing);
proptest book (state machines) and `proptest-state-machine` 0.8.0 manifest; FoundationDB testing
doc; TigerBeetle VOPR doc; turmoil; madsim / mad-turmoil; Bitcoin Core `doc/fuzzing.md`,
`process_message(s)` harness PRs, `tx_pool` target; Zebra `non_finalized_state/tests/prop.rs`;
reth `derive_arbitrary` codecs and sparse-trie proptest PRs; ClusterFuzzLite; GitHub runner specs;
Groce et al., "Swarm testing".

---

## 2. Current state

### 2.1 Coverage-guided fuzzing (`fuzz/`)

| Fact | Evidence |
|---|---|
| 9 cargo-fuzz targets: `tx_decode`, `block_decode`, `p2p_message`, `proof_decode`, `zkvm_elf`, `kernel_diff`, `delivery_open`, `wasm_module`, `contract_sequence`; own workspace and tracked lockfile (libFuzzer C++ never enters product builds) | [src] `fuzz/Cargo.toml` |
| Oracles: no panic + canonical round trip (tx, block, p2p, proof); native/guest differential (`kernel_diff`); twin-executor determinism, rollback, replay (`contract_sequence`); nothing opens without keys (`delivery_open`) | [src] targets |
| `run_campaign.sh` now builds and runs with `-O -a` (debug assertions ⇒ overflow checks), `pipefail`, fails on zero executed units or any artifact | [src] `run_campaign.sh:18-57`; cargo-fuzz `project.rs:259` adds `-Cdebug-assertions` when `-a`; rustc's `overflow-checks` defaults to `debug-assertions` [src/web] |
| **No campaign has run with `-O -a`**; the ~531 M recorded executions (AUDIT.md:1138-1225, 1371-1372) had overflow checks off; G9 still cites them | [src] AUDIT.md, launch checklist:30; autonomous-session §6 "evidence still missing" |
| CI `fuzz-smoke`: 2 min per target from freshly generated seeds, `-O -a`, pinned nightly and cargo-fuzz 0.13.2 | [src] `ci.yml:186-204` |
| Corpora and artifacts are gitignored and exist on this machine only: 9 dirs, **23,221 files, ≈385 MB** (`proof_decode` 343 MB, `wasm_module` 22 MB); `artifacts/*` empty | [src] `fuzz/.gitignore`; `du`/`ls` counts |
| libfuzzer-sys installs a panic hook that **aborts before unwinding** — panics inside `catch_unwind` (the zk verifier and decoder) also abort a fuzz target | [src] `libfuzzer-sys-0.4.13/src/lib.rs:82-96` |
| libFuzzer truncates seed files longer than `-max_len` when it loads them | [src] `FuzzerLoop.cpp:795-834` (`FileToVector(SF.File, MaxInputLen)`), `FuzzerIO.cpp:52-53` |

### 2.2 Seeded mutation tests in the normal suite (pure Rust, `BLACKSILK_FUZZ_ITERS`)

`tx/tests/fuzz_decode.rs` (8 mutation operators; 25 PX mutants validated in full),
`chain/tests/fuzz_block.rs`, `p2p/tests/fuzz_message.rs`, `zkvm/tests/fuzz.rs` (random
straight-line programs satisfy every constraint), `px/tests/fuzz.rs` (kernel differential),
`contracts/tests/fuzz.rs`. [tested: each file, listed passing in autonomous-session §7]. They
cannot shrink failures and do not persist counterexamples. Good design: fixed seeds, scalable
iteration counts, measured campaigns recorded in AUDIT.md:1078-1090.

### 2.3 Non-malleability and structure-aware tests (since `f6c98c3`)

- `crypto/tests/malleability.rs`: every CLSAG/BP+ scalar and point alteration fails; `s + ℓ`
  rejected at decoding; batch = individual verification on every subset of a mixed batch, including
  cancelling pairs. [tested: `clsag_every_*`, `bpp_every_field_alteration_fails`,
  `batch_verify_agrees_with_individual_verification`, `batch_weights_prevent_cancelling_errors`]
- `zk/tests/field_mutations.rs`: a postcard-layout recording serializer locates every field element
  of a toy proof; every stride-10 element replacement is refused (~6,750 mutations, 136 s).
  [tested: `field_mutations`] This recorder is the right building block for a verifier fuzz target.

### 2.4 Property-based / stateful / simulation

- **No `proptest` anywhere** (0 entries in `Cargo.lock`); approved as a dev-dependency by the
  coordinator (decisions: 12, 17, 20, 02), 41 owns adoption. [src]
- The consensus core is already **sans-IO**: `HeaderChain::accept(header, now)`,
  `ChainManager::submit_block(block, now)`, PoW behind `Arc<dyn PowFunction>`, a seeded ChaCha RNG
  for batch weights, `MemoryStore`. **This is exactly what stateful fuzzing and deterministic
  simulation need; it must never change.** [src] `consensus/src/chain.rs:470-539`,
  `chain/src/manager.rs:300,561-604`, `store.rs:77-104`
- Determinism of iteration: `select` and eviction sort with a `seq` tie-break; `revalidate`
  collects a set; `missing_bodies` sorts by height. I found no decision depending on `HashMap`
  iteration order in manager/mempool. [src] `mempool.rs:306-311,378-395,411-413`; `manager.rs:1087-1124`
- `p2p/src/net.rs` is **not** sans-IO and has grown to **2,934 lines** (R13 counted 1,781): 20+
  `std::time::Instant::now()` sites, `tokio::spawn` of accept/maintenance/header/block workers,
  `std::sync::Mutex<ChainManager>`. The RNG is already a single seeded `ChaCha20Rng` (seed from
  `getrandom`, `net.rs:397-398`), so randomness is injectable; time and scheduling are not. [src]
- `p2p/tests/network.rs` runs real tokio runtimes over loopback with sleeps; its flakiness is
  documented (run 80 race, `197855b`). [src; autonomous-session §7]
- `chain/src/manager.rs:282` sleeps 1 ms between sync steps in `submit_block_in_steps` (a
  mutex-fairness fix). Harnesses must use `submit_block_bounded`/`sync_step` directly. [src]
- **Test-support duplication:** `struct ZeroPow` is defined 15 times (chain tests ×7 + unit,
  node ×2, p2p ×2, tx, wallet, supply-audit), each with its own block-building helpers. [src] grep

### 2.5 Labnet

N real node/miner processes behind latency/jitter/partition proxies; checks convergence, stuck
nodes, late joiner, wallet restore, supply. Processes are killed only at the end
(`main.rs:628,731`), no skew, no adversary (R13 T-9). **The harness RNG is seeded from
`getrandom` and the seed is not written anywhere** (`main.rs:281-283`; the only other "seed"
matches are wallet seeds), so a run's transaction/partition schedule cannot be replayed. [src]

---

## 3. Problems in scope

### P1. Fuzz evidence without overflow checks (R13 T-2, P0-10/P0-11)

- **Problem:** the only long campaigns ran without `-a`. The script is fixed; no `-O -a` run exists.
- **Consequence:** integer wrap in decoders, zkVM, PX value arithmetic, fuel accounting is unobserved
  by the fuzz evidence (the `overflow` CI job covers only unit/integration tests).
- **Class:** evidence gap for consensus-adjacent code (decoders define validity).
- **Prior art:** Bitcoin Core fuzzes with UBSan integer checks; its `process_message` harness found
  a misbehaviour-score signed overflow [web: bitcoincore.reviews 18521 / chinggg summary].
- **Trade-offs:** `-a` also enables `debug_assert!` in *every* crate in the fuzz build (RUSTFLAGS are
  global), including `third_party` Plonky3 and dependencies: expect assertion hits that production
  never evaluates. Each must be triaged: a debug assertion reachable from attacker input is a real
  invariant break that production silently proceeds past, so it is a finding, not noise.
- **Test that proves the fix:** campaign E1 (§5, W41-1) with recorded counts per target, zero
  artifacts, logs retained.
- **Invariant:** campaigns and smoke runs keep `-O -a`; never go back to `--release` alone.

### P2. Corpora exist on one machine; no replay on the stable toolchain (R13 T-7)

- **Problem:** 385 MB of corpora are gitignored; CI starts from seeds every run; a crash found once
  cannot be replayed by a reviewer; nothing re-runs old inputs in `cargo test`.
- **Consequence:** fuzz evidence is not reproducible; regressions of fixed crashes go unnoticed.
- **Prior art:** Bitcoin Core keeps seed corpora in `bitcoin-core/qa-assets` and tests every PR
  against all of them [web: doc/fuzzing.md]. ClusterFuzzLite stores corpora in a storage repo
  (needs a write PAT) or workflow artifacts, with batch/prune/coverage modes [web]. Zebra and reth
  instead lean on proptest with committed regression files [web].
- **Design for BlackSilk:** (a) small **regression set committed** in the main repo
  (`fuzz/regressions/<target>/`, every crash repro minimized, each < 64 KiB, the big-proof ones
  as generated-on-demand recipes rather than bytes); (b) a **separate corpus repository**
  (qa-assets model) holding `cargo fuzz cmin`-minimized corpora for fast targets; (c) big
  corpora (proof targets) as zstd tarballs attached to releases of that repo with a SHA-256
  manifest; (d) CI **replays** (a) and (b) on stable Rust through the harness library (W41-3),
  seconds per target, no libFuzzer; (e) weekly fuzz jobs upload the grown corpus as a workflow
  artifact (90-day retention) and a human merges it into (b) after `cmin`. This keeps the
  read-only `GITHUB_TOKEN` policy (never-change item: SHA-pinned actions, read-only token): no PAT
  with write access in CI, so ClusterFuzzLite's storage-repo mode is not adopted.
- **Privacy:** corpora are generated from fixed test seeds (`seeds.rs` uses `ChaCha20Rng` seeds
  1 and 2, `Account::from_seed(&[..])`); a rule is needed that no corpus input is ever derived from
  a real wallet or node data.
- **Tests:** a stable-toolchain test that replays every committed input through the same oracle
  as the fuzz target; a manifest check (hash of the corpus set) in the weekly job.
- **Invariant:** `fuzz/` stays its own workspace; the replay path must not pull libFuzzer.

### P3. Stateful and verification surfaces are unfuzzed (R13 T-6)

Uncovered by any coverage-guided target: `HeaderChain` DAG sequences, `ChainManager`
block/reorg/restart sequences, mempool sequences, the per-peer protocol in `net.rs`, the ZK
verifier (`proof_decode` only decodes), CLSAG/BP+ verification, output scanning, store record
parsing, RandomX program decoding and the soft FPU.
- **Consequence:** interleaving, ordering and resource bugs (the class of H1, F-1, the mempool C4
  stall, reorg revalidation) are found only by hand-written examples.
- **Prior art:** Bitcoin Core `process_message(s)` (mocked time via `SetMockTime`, deterministic
  build that skips PoW), `tx_pool` (arbitrary coins/fees, packages) [web]; Zebra
  `forked_equals_pushed`, `finalized_equals_pushed`, `rejection_restores_internal_state` proptests
  over generated partial chains [web]; reth differential proptests of the sparse trie against a
  reference root computation (300 cases in CI, 4,000 soaked) [web].
- **Design:** one **harness library** (W41-3) with operation enums decoded *totally* from bytes
  (every byte string is a valid op sequence; ops address existing objects "index mod len", so
  every op is always applicable and shrinking never produces invalid sequences). The same `run(ops)`
  is driven by proptest (generated ops, shrinking, committed regressions) and by libFuzzer (bytes →
  ops, coverage guidance). Oracles: a small reference model (fork choice by body-complete work, ties
  keep the connected tip; 02's `FcModel`), **twin determinism** (two instances fed the same ops must
  have equal state digests after every op; separate `HashMap` instances have different
  `RandomState` keys, so this also catches iteration-order dependence), **replay equivalence**
  (reopen from the shared store ⇒ same digest), supply conservation, and resource bounds.
- **Trade-offs:** harness code is test code that can itself be wrong; mitigated by mutation testing
  of the harness oracles (42) and by keeping models small. Coinbase-only blocks with `ZeroPow` avoid
  proof costs but do not cover v1/PX transaction interplay; a second, slower lane adds real
  transfers (6.8 ms each, R12) at lower op counts.
- **Swarm testing:** each run randomly disables a subset of op kinds (Groce et al. 2012), which
  finds bugs that uniform op mixes starve. Cheap to add to the op decoder.

### P4. The ZK verifier target: what fuzzing can and cannot show

- **Facts:** PX verify ≈ 0.235 s wall on a multi-core machine (R12 §1.3), single-core unknown;
  the toy statement verifies at ≈ 50/s (field_mutations timing). `QUERY_POW_BITS = 16`
  (`zk/params.rs:41`), `COMMIT_POW_BITS = 0`. Verification checks shape, heights and the FRI
  schedule before any expensive work (`zk/lib.rs:126-157`).
- **Depth limit [math]:** Fiat–Shamir makes every later challenge depend on every earlier
  transcript element. A mutation placed before the query-grinding witness passes the grinding check
  with probability 2^-16, so byte- or field-level mutation almost never reaches the FRI query checks.
  Coverage-guided fuzzing of the verifier therefore finds **robustness** bugs (panics, aborts,
  non-canonical acceptance), **malleability** (accept ⇒ identical bytes) and **cost** anomalies. It
  cannot find algebraic soundness breaks; say so in any evidence text.
- **Options for depth:** (a) accept shallow coverage; (b) a `#[cfg(fuzzing)]` verifier
  configuration with query grinding off (cargo-fuzz sets `--cfg fuzzing` for every crate; zero
  production effect, but it changes code in `zk`); (c) a harness "fix-up" that re-grinds after
  mutation (checksum-fixing, standard in structure-aware fuzzing) — needs a transcript replay the
  Plonky3 API does not expose. I recommend (a) now plus (b) as a coordinator decision (Q3).
- **Time limits:** libFuzzer `-timeout` (per-input hard limit, default 1200 s) and
  `-report_slow_units`; wall-clock assertions are flaky on a shared machine, so the cost oracle runs
  only in a dedicated single-thread lane (`RAYON_NUM_THREADS=1`), records the slowest inputs and
  their times (feeds ZK-F4 evidence, owner 22/27), and CI never asserts on time.
- **Contained panics:** because libfuzzer-sys aborts on any panic, a Plonky3 panic that production
  contains as `VerifierPanicked` is a fuzz crash. Keep this strictness (R13 never-change); run long
  verifier campaigns in `-fork=N` mode (crash-resistant; `-ignore_crashes=1` only for campaigns
  whose crash class is already triaged) and report each distinct stack upstream.

### P5. Property-based framework adoption (R13 T-4)

- **Decision input:** `proptest` 1.11.0 (in the local registry; `rust-version 1.85`). Default
  features pull `fork`/`timeout` → `rusty-fork`, `tempfile`, `wait-timeout`. With
  `default-features = false, features = ["std"]` the tree is `rand 0.9`, `rand_chacha 0.9`,
  `rand_xorshift`, `regex-syntax`, `num-traits`, `bitflags`, `unarray`: pure Rust; the crate's own
  `unsafe` sits behind non-default features (`hardware-rng`, `handle-panics`) [src]. It adds a
  second `rand` major (the workspace has 0.10.3) in dev builds only. 44 must confirm.
- **`proptest-state-machine` 0.8.0** (released 2026-09-20) depends on proptest with
  `default-features = true, features = ["fork", "timeout", "bit-set"]` [web: Cargo.toml.orig], so it
  forces the fork/timeout tree back in, and it is one week old. Its value is precondition-aware
  sequential shrinking; with the "total op decoding" design of P3 every op is always applicable, so
  plain proptest over `Vec<Op>` shrinks equally well. **Recommendation: do not adopt it; write a
  ~100-line sequential runner on plain proptest** in the harness crate.
- **Conventions:** fixed `PROPTEST_RNG_SEED` in per-push CI (deterministic, no flakes), random seed
  and 20× `PROPTEST_CASES` nightly, `proptest-regressions/` files committed (proptest's default
  `FileFailurePersistence::SourceParallel`), each property ≤ 20 s release in CI. Stale docs
  (AUDIT.md:297, transactions.md:1017 "getrandom does not build") must be corrected (47).

### P6. Deterministic simulation (R13 T-5)

- **Problem:** multi-node interleavings are tested only over real sockets and wall time.
- **Options:**
  - **turmoil** (tokio-rs): simulated hosts/network/fs in one thread, seeded [web]. It virtualizes
    tokio time and `turmoil::net`, **not** `std::time::Instant`, which `net.rs` uses at 20+ sites,
    and it needs a current-thread runtime; adoption means rewriting `net.rs` I/O anyway.
  - **madsim**: `--cfg madsim` swaps tokio for `madsim-tokio` and **overrides libc symbols**
    (`clock_gettime`, `getrandom`, `getentropy`, `sysconf`) to make std deterministic [web]; the
    s2 "mad-turmoil" does the same for turmoil. Symbol interposition is FFI-level `unsafe`, platform
    specific (not Windows, our main dev platform), and patches tokio across the build.
    **Rejected** under the pure-Rust/no-unsafe principle.
  - **Sans-IO core + in-house simulator** (FoundationDB/TigerBeetle design: single thread,
    everything non-deterministic stubbed, seed + commit replays a failure [web]; `quinn-proto` is the
    Rust precedent for a sans-IO protocol core). No dependency.
- **Recommendation:** two stages. **D0 (P1, no p2p change):** `simnet`, a chain-level simulator of
  N `ChainManager`s exchanging headers/bodies/transactions through a seeded event queue with
  virtual time, partitions, delays, restarts and adversary roles (withheld bodies, invalid bodies,
  low-work header spam, selfish release). It tests fork choice, H1/F-1, reorg revalidation and
  replay under interleavings, which is where the consensus-relevant risk is. **D1 (P2, after 34's
  actor and 31's sync design):** extract a sans-IO `PeerCore` (`on_message(now, msg) -> actions`) so
  simnet drives the real protocol logic and a `p2p_peer` fuzz target becomes possible. D1 must be
  designed into 34's refactor, not bolted on later.
- **Invariants:** `now` stays a parameter in consensus/chain; no clock or OS-RNG reads added there.

### P7. Labnet reproducibility and fault coverage (R13 T-9)

Seed not recorded (new, §4 F41-4), no kill/restart, no skew, no adversary. Fix: `--seed` (default
random, always written to `summary.json` and the log), then a chaos schedule after 09's I4
instrumentation lands (kill -9 + restart during sync and during a reorg; `--clock-offset-secs` on
regtest only, per the agent 04 decision). Labnet is not deterministic even with a seed (OS
scheduling, real sockets); the seed reproduces the *schedule*, simnet reproduces *executions*.

---

## 4. New findings

| ID | Severity | Status | Location | Scenario | Confidence |
|---|---|---|---|---|---|
| **F41-1** | Low (assurance) | Not implemented | `fuzz/run_campaign.sh:27` (`-max_len=65536` for `tx_decode`); `fuzz/src/seeds.rs:313-329`; libFuzzer `FuzzerLoop.cpp:833` | The PX transaction seed is 2,183,616 bytes; libFuzzer truncates it to 64 KiB at load, so it never decodes. Coverage-guided `tx_decode` starts with **no decodable PX seed**, and `check_px_structure`/`check_px_balance`/`binding` are reached only if the fuzzer rebuilds a short PX encoding by itself. The proof is opaque bytes in `Transaction::decode` (`tx/src/px.rs:351`), so a seed with a short proof blob decodes and fixes this. `block_decode` has no PX-carrying seed at all. | High (mechanism); medium (how much coverage was lost) |
| **F41-2** | Low (assurance) | Partially implemented | `fuzz/fuzz_targets/kernel_diff.rs:26`; `px/tests/fuzz.rs:93-95`; `zkvm/src/exec.rs:68-81`; `px-core/src/kernel.rs:105-123` | The differential oracle accepts **any** (native `Err`, guest trap) pair. The comment says a trap is legitimate only where the native kernel read past the end; the code does not check `TrapKind` or whether the native source over-read. A guest `CycleLimit`, `AccessOutOfRange` or `NonCanonicalField` trap on an input the native kernel rejects with a specific code is a native/guest divergence that passes silently. Verdicts still agree (both reject), so no consensus split follows directly; it hides guest bugs that could later bite an accepting path. Fix: a counting `Source` wrapper in the harness and an allowed-trap table (InputExhausted ⇔ native over-read; others only as documented by 20). | High (code fact); medium (impact) |
| **F41-3** | Informational | Complete but requires further testing | `fuzz/fuzz_targets/proof_decode.rs:1-2`; `libfuzzer-sys-0.4.13/src/lib.rs:82-96`; `zk/src/lib.rs:158,278` | "Never panics (outside its own catch)" is inaccurate: the libFuzzer hook aborts on *any* panic, including inside `catch_unwind`. Consequence (good): the recorded decode campaigns also show no contained panic. Consequence (plan): verifier targets will stop on every contained Plonky3 panic; campaigns need fork mode and a triage rule (§3 P4). | High |
| **F41-4** | Low (evidence reproducibility) | Not implemented | `tools/labnet/src/main.rs:281-283` | The labnet RNG seed comes from `getrandom` and is never logged or written to `summary.json`; a failing run (e.g. a stuck-node incident) cannot be re-run with the same wallet/partition schedule. | High |
| **F41-5** | Informational (decision) | Not implemented | proptest-state-machine 0.8.0 manifest | The state-machine add-on forces proptest's `fork`/`timeout` features (`rusty-fork`, `tempfile`, `wait-timeout`) and is one week old; the approved plain proptest with `default-features = false, features = ["std"]` avoids them. Recommend an in-house sequential runner (§3 P5). | High |
| **F41-6** | Low (efficiency) | Not implemented | `fuzz/run_campaign.sh:15,22-33` | Every target gets the same time. In a 9-target campaign 2/9 of the budget goes to the Wasm engine, which ADR-28-1 places outside consensus, and `proof_decode` byte-fuzzes 2 MB inputs at 21 exec/s. Budgets should follow consensus exposure (§5 campaign table). | High |
| **F41-7** | Low (maintainability, blocks new harnesses) | Not implemented | 15 `struct ZeroPow` definitions (e.g. `chain/tests/fork_choice.rs:26`, `p2p/tests/network.rs:39`, `wallet/tests/e2e.rs:25`) | Every new property/stateful/fuzz harness would copy PoW stubs, block builders and store wrappers again, and 02 W-1, 12 W6 and the 41 targets would each build their own models. A shared test-support crate removes the duplication and lets the fuzz targets reuse the P0 models as oracles. | High |
| **F41-8** | Informational (design constraint) | — | `zk/src/params.rs:41`; Fiat–Shamir | Verifier fuzzing cannot go deep past the 16-bit query grinding by mutation alone (§3 P4); any evidence text must state that verifier fuzzing shows robustness, non-malleability and cost, not soundness. | High [math] |
| **F41-9** | Medium (architecture; re-confirms T-5 with new numbers) | Not implemented | `p2p/src/net.rs` (2,934 lines; `Instant::now` at 732, 750, 779, 900, 1078, 1139, 1158, 1184, 1215, 1255, 1310, 1414, 2006, 2051, 2214, 2449, 2514, 2596-2601, 2762; `tokio::spawn` at 469-473, 495, 837, 1117, 2850, 2887) | The per-peer protocol cannot be fuzzed or simulated deterministically; turmoil would not virtualize `std::time::Instant`; madsim is excluded by policy. Only a sans-IO extraction solves it, and it should ride 34's actor refactor. | High |

Re-confirmed known items (no new severity): T-2 (P0, evidence), T-6 (Medium–High), T-7 (Medium,
now quantified: 23,221 files, ≈385 MB, one machine), T-4 (Medium; proptest now approved).

---

## 5. Implementation plan for phase 2

### 5.1 Verification matrix (target state; owner of each cell in brackets)

Layers: **U** unit/KAT/golden vectors · **P** property (proptest) · **S** stateful model ·
**D** differential · **F** coverage-guided fuzz · **M** mutation (42) · **Sim** deterministic
simulation · **L** labnet/chaos.

| Component / invariant | U | P | S | D | F | M | Sim | L |
|---|---|---|---|---|---|---|---|---|
| Codecs (tx, block, p2p message) canonical & non-malleable | have | **new** generated round-trip (41) | — | — | have (F41-1 seed fix, 41) | 42 | — | — |
| LWMA, MTP/FTL, seed schedule | golden (01) | 01 item 10, 04 W6e (framework 41) | — | 03 Rust harness | — | 42 (the `(n+1)` mutant) | — | 04 skew via L |
| HeaderChain fork choice, precheck = sequential | have | 01 item 10 | **41 `header_chain` target** on 02's model | precheck vs accept | **new `header_chain`** (41) | 42 | D0 (41) | — |
| ChainManager: body-complete fork choice, reorg, replay, store failure | have | 02 W-1 (P0) | 02 W-1 model; **41 restart/store-fault lane** | replay = live | **new `chain_manager`** (41) | 42 | D0 (41) | 41 chaos |
| Mempool: no conflicts, caps, template validity, reorg revalidation | have | 13 C4-B property | **12 W6 (P0)** | vs. manager verdict | `mempool_seq` (41, P2, after 12's redesign) | 42 | D0 tx lane | have |
| Block validation parallel = sequential | — | 10 item 4 (differential proptest) | — | T ∈ {1,2,3,8} | — | — | — | — |
| CLSAG verify | have | — | — | batch/single | **new `clsag_verify`** (15 writes, 41 integrates) | 42 | — | — |
| BP+ verify, batch = single | have | 16 batch-size proptest | — | have | **new `bpp_verify`** (16 writes, 41 integrates) | 42 | — | — |
| Stealth scan / Janus | have | 17 F17-11 field mutation | — | honest rebuild | **new `scan_output`** (17 writes, 41 integrates) | — | — | — |
| ZK verifier (Plonky3) | pins | — | — | field mutation (have) | **new `zk_verify_toy`, `px_verify`** (41; 22/24/25 review) | — | — | — |
| PX kernel native = guest = spec | have | 20 W2 spec oracle (P0) | — | have | `kernel_diff` (F41-2 sharpen, 41; seeds with 20) | 20 W3 via 42 | — | L PX traffic |
| PX state apply/undo/window | have | 21-A/F properties | 21 model (could join testkit) | — | — | — | — | — |
| zkVM loader/interpreter vs constraints | have | — | — | have | have | — | — | — |
| RandomX FPU | unit | 05 C3 apfloat oracle | — | 05 C1/C5 corpus | `fpu_diff` (P2, 41 after C3) | 42 | — | — |
| RandomX program decode | 05 C2 KATs | — | — | — | `randomx_program` (P2, needs `cfg(fuzzing)` export, Q2) | 42 | — | — |
| Seed cache pin window | — | 07 T5 | 07 T6 | real RX | — | — | — | L 2113 |
| Store record parser / repair | have | — | restart lane (41) | — | `store_records` (P2, 35 exposes parser) | — | — | 41 kill -9 |
| P2P per-peer protocol | net tests | — | D1 `PeerCore` (31/34 + 41) | — | `p2p_peer` (P2, after D1) | — | D1 | have |
| Dandelion privacy | 33 regression | — | — | — | — | — | D1 spy estimator (33) | — |
| Contracts (Wasm, non-consensus) | have | — | — | twin | have (smoke-only budget) | — | — | — |

### 5.2 Campaign specifications

Measured rates are from AUDIT.md (no `-a`); `-a` typically costs 10–30% [assumed]. Rates marked *est*
are estimates to be replaced by a 10-minute calibration run before each campaign. A campaign
**passes** when every target reaches its execution count, produces zero artifacts, and its coverage
(`stat::` features/edges) is recorded; a target that still finds new features in its last 2 hours
is flagged "not plateaued" and gets more time in the next campaign.

**Common flags:** `cargo +nightly-2026-09-24 fuzz run -O -a <t> corpus/<t> -- -timeout=<T> -rss_limit_mb=<R> -max_len=<L> -print_final_stats=1 -max_total_time=<s>`; Linux runs use `-fork=N` for the
verifier targets; Windows dev runs use one process per core (fork mode on Windows is [unknown]).
`RAYON_NUM_THREADS=1` for every target that verifies proofs.

**E1 — overflow-checked evidence campaign on existing targets (P0, before the freeze).** Dev machine,
exclusive window, 4 targets in parallel (RAM: `proof_decode` ≤ 4 GB, others < 1 GB under ASan
[AUDIT peak 664 MB]).

| Target | Oracle | `-max_len` / `-timeout` / `-rss` | Rate (measured, no `-a`) | Min executions | ≈ Core-hours |
|---|---|---|---|---|---|
| `p2p_message` | no panic, canonical | 65,536 / 60 / 2048 | 120,787/s | 1×10⁹ | 2.8 |
| `block_decode` | no panic, canonical | 65,536 / 60 / 2048 | 27,709/s | 2×10⁸ | 2.5 |
| `tx_decode` (with the F41-1 short-proof PX seed) | + stateless rules | 65,536 / 60 / 2048 | 5,470/s | 5×10⁷ | 3.2 |
| `zkvm_elf` | no panic | 32,768 / 60 / 2048 | 977/s | 1×10⁷ | 3.5 |
| `kernel_diff` (F41-2 oracle) | native = guest | 8,192 / 60 / 2048 | 98/s | 1×10⁶ | 3.5 |
| `delivery_open` | nothing opens | 65,536 / 60 / 2048 | 1,808/s | 1×10⁷ | 1.9 |
| `proof_decode` | strict decode canonical | 2,200,000 / 60 / 4096 | 21/s | 2×10⁵ | 3.3 |
| `wasm_module`, `contract_sequence` | non-consensus; smoke-plus | 65,536, 4,096 / 60 / 4096 | 2,419/s, 22/s | time-boxed 1 h each | 2.0 |
| **Total** | | | | | **≈ 22.7 core-h ≈ 6–7 h wall** |

**E2 — new-target evidence campaign (P1; before the public testnet, after W41-4..7 land).**

| Target | Input model | Oracle | Rate *est* | Min executions | ≈ Core-hours |
|---|---|---|---|---|---|
| `clsag_verify` | valid signature from a fixed ring + field-level mutations (scalar ±1, negate, zero, swap ring member, point → identity/other/`s+ℓ` bytes, message byte) | no panic; `verify(m) = Ok ⇒ bytes(m) = bytes(o)` | 250/s | 5×10⁶ | 5.5 |
| `bpp_verify` | proofs for k ∈ 1..16 decoded via `read_bpp`, field mutations, batch of the mutant with honest proofs | no panic; non-malleability; `batch_verify == all(verify)` | 250/s | 5×10⁶ | 5.5 |
| `scan_output` | arbitrary canonical points/bytes, random subaddress table | no panic; `Owned ⇒` honest rebuild matches | 3,000/s | 5×10⁷ | 4.6 |
| `header_chain` | ops: extend(known idx, dt, field-fault), mark_invalid(idx), precheck batch, now-advance; ZeroPow | reference model tip/work; `main` = ancestor path of tip; Reorg consistency; precheck = sequential; twin determinism | 8,000/s | 1×10⁸ | 3.5 |
| `chain_manager` | ops over a generated block tree: header(i), body(i), invalid body(i), restart, store-fail-next, sync_step(budget), advance time | 02's `FcModel`; replay after restart = live; supply; `missing_bodies ⊆ keeps_body`; twin determinism | 80/s | 1×10⁶ | 3.5 |
| `zk_verify_toy` | toy AIR proof decoded, field-element mutations via the layout recorder of `zk/tests/field_mutations.rs` | no abort; accept ⇒ identical bytes; verify ≤ 3× honest (recorded, not asserted) | 40/s | 5×10⁵ | 3.5 |
| `px_verify` | real transfer proof + public inputs; field mutations; public-input word mutations | no abort; non-malleability; cost profile of the slowest 20 inputs (ZK-F4 evidence) | 3/s (1 thread) | 3×10⁴ | 2.8 |
| **Total** | | | | | **≈ 29 core-h** |

**Weekly continuous (CI, Linux, after W41-10/11):** 4 shards × 5 h × 3 cores (one core left for
the runner) on standard 4-vCPU/16 GB runners (6 h job cap) = **60 core-hours/week**, split by
consensus exposure: `header_chain`+`chain_manager` 30%, verifiers (`clsag`, `bpp`, `zk_*`,
`px_verify`) 30%, codecs 20%, `kernel_diff`+`zkvm_elf` 15%, others 5%. Corpus from the corpus repo,
grown corpus uploaded as artifact.

**Per push (CI):** existing 2-min smoke per target **plus** stable-toolchain replay of
`fuzz/regressions/` and the small corpus set (seconds, must pass).

**Property tests:** per push: fixed `PROPTEST_RNG_SEED`, default cases (256; stateful sequences
≤ 64 ops), each property ≤ 20 s release, whole property tier ≤ 10 min. Nightly: random seed,
`PROPTEST_CASES` ×20, sequences ≤ 256 ops; any failure is committed to `proptest-regressions/`.
Pre-freeze: ×100 cases on 3 seeds, recorded in the evidence file.

**Simnet (D0):** per push 200 seeds (≤ 2 s each); nightly 10⁴ seeds; pre-freeze 10⁵ seeds; a
failure is reported as `(commit, seed)` and must replay bit-for-bit.

### 5.3 Work items

| # | Item | Files (ownership) | Consensus? | Identity | Tests | Docs | Diff. | Prio |
|---|---|---|---|---|---|---|---|---|
| **W41-1** | **E1 campaign** with `-O -a`; per-target budgets and counts file; the F41-1 seed fix (short-proof PX tx seed in `tx_decode`, a PX-carrying block seed in `block_decode`); triage rule for dependency `debug_assert` hits; results recorded | `fuzz/run_campaign.sh`, new `fuzz/campaigns.tsv` (41); `fuzz/src/seeds.rs` (41; 20 co-edits the kernel seeds) | nothing | none | E1 itself | AUDIT.md fuzz section, launch checklist G9 wording (47 applies) | S | **P0** |
| **W41-2** | **proptest convention**: `proptest = { version = "=1.11.0", default-features = false, features = ["std"] }` per crate as dev-dep (each owner adds to their crate), CI env (fixed seed per push, nightly random), regression files committed; in-house sequential state-machine runner (no `proptest-state-machine`) | runner in `tools/testkit` (41); CI env lines via 43; crate `Cargo.toml` dev-deps by the crate owners | nothing | none | the runner's own tests (a planted bug is found and shrunk to a minimal op list) | `docs/testing.md` (new, 41) or AUDIT.md section (47 decides); fix AUDIT.md:297, transactions.md:1017 (47) | S | **P0** (02 W-1 and 12 W6 depend on it) |
| **W41-3** | **`tools/testkit` harness crate** (publish = false, no new external deps): `ZeroPow`, `SharedStore` (restart), `FaultyStore` (append failure injection), `BlockFactory` (coinbase-only blocks on any parent with claim/timestamp/nonce overrides), header-DAG builder, total `OpReader` byte decoder, state digest (tip, height, generated, output count, key-image count, PX root, mempool ids), twin runner, stable replay of `fuzz/regressions/` | new `tools/testkit/**` (41); root `Cargo.toml` members line (coordinate 43/44) | nothing | none | self-tests; replay test | crate README | M | **P0** (enables 02 W-1, 12 W6, 01 item 10) |
| **W41-4** | Integrate the requested verification targets: `clsag_verify` (15 W5), `bpp_verify` (16 item 5), `scan_output` (17 item 6); structure-aware input via decode-mutate-re-encode; non-malleability oracles | `fuzz/fuzz_targets/{clsag_verify,bpp_verify,scan_output}.rs` (target bodies from 15/16/17; 41 owns `fuzz/Cargo.toml`, seeds, script) | nothing | none | E2 rows | fuzz README | S each | **P1** |
| **W41-5** | ZK verifier targets `zk_verify_toy` and `px_verify` (layout recorder moved from `zk/tests/field_mutations.rs` into a shared test module or testkit), cost lane with `RAYON_NUM_THREADS=1`, fork-mode campaign | `fuzz/fuzz_targets/{zk_verify_toy,px_verify}.rs`, `fuzz/src/seeds.rs` (41); moving the recorder touches `zk/tests/field_mutations.rs` (coordinate 22/24) | nothing (option (b) of §3 P4 would touch `zk`; Q3) | none | E2 rows; ZK-F4 cost table to 22/27 | zk.md evidence note (47) | M | **P1** (cost lane feeds P0-3 ZK-F4 evidence) |
| **W41-6** | `header_chain` target + model (the proptest file itself is 01's `consensus/tests/properties.rs`, sharing the model from testkit) | `fuzz/fuzz_targets/header_chain.rs`, model in `tools/testkit` (41) | nothing | none | E2 row; planted-bug check (tie-break flipped ⇒ found) | — | M | **P1** |
| **W41-7** | `chain_manager` target + restart/store-fault property lane (reuses 02's `FcModel` via testkit) | `fuzz/fuzz_targets/chain_manager.rs`; new `chain/tests/manager_stateful.rs` (41; restart and store faults only — fork-choice properties stay in 02's files) | nothing | none | E2 row; proptest lane | blocks.md §6 pointer (02) | M | **P1** |
| **W41-8** | Sharpen the kernel differential oracle (F41-2): counting `Source`, allowed-trap table | `fuzz/fuzz_targets/kernel_diff.rs` (41); `px/tests/fuzz.rs` (20 applies the same change, since 20 W2 edits that file) | nothing | none | a planted guest trap is flagged | px.md §9.3 (20) | S | **P1** |
| **W41-9** | Codec generated round-trip properties: `decode(encode(x)) == x` for generated tx/block/message values, including `Version` extension areas and every tx kind | new `tx/tests/codec_props.rs`, `chain/tests/codec_props.rs`, `p2p/tests/codec_props.rs` (41) | nothing | none | property | — | S | **P1** |
| **W41-10** | Corpus storage: owner creates a corpus repo; `cmin` pipeline; release-asset tarballs with SHA-256 manifest for proof corpora; crash → `fuzz/regressions/` + named regression test rule | `fuzz/regressions/**`, `fuzz/README.md`, `fuzz/corpus-manifest.toml` (41); external repo (owner) | nothing | none | replay test (W41-3) | fuzz README; AUDIT.md (47) | S | **P1** |
| **W41-11** | CI spec: per-push replay job (stable); weekly sharded fuzz workflow; nightly property job | `.github/workflows/fuzz-weekly.yml`, `ci.yml` job lines (**43 owns**; 41 supplies the spec) | nothing | none | the jobs | — | S | **P1** |
| **W41-12** | **Simnet D0**: chain-level deterministic multi-node simulator (seeded event queue, virtual time, partitions, restarts, adversary roles: withheld bodies, invalid bodies, low-work spam, selfish release); oracles: convergence within bounded virtual time after heal, connected tip = model's best body-complete chain, supply, no invalid block connected; `(commit, seed)` replay | new `tools/simnet/**` (41) | nothing | none | 200/10⁴/10⁵ seeds; planted-bug checks (F-1 starvation reproduced on the pre-fix code) | testnet.md §7 pointer (47) | L | **P1** (P0 evidence for 02 F-1 if the coordinator wants a model-level check before the trial) |
| **W41-13** | Labnet `--seed` recorded (F41-4); chaos schedule (kill -9/restart during sync and reorg; regtest clock offset) | `tools/labnet/src/main.rs` (after 09's I4 lands; small hooks), new `tools/labnet/src/chaos.rs` (41) | nothing | none | a 1 h chaos run in evidence | labnet README | S | **P1** (seed P0-cheap: fold into 09's I4 change) |
| **W41-14** | D1: sans-IO `PeerCore` extraction, `p2p_peer` fuzz target, simnet over the real protocol | `p2p/src/net.rs` split (**31/34 own**), `fuzz/fuzz_targets/p2p_peer.rs`, `tools/simnet` (41) | policy only | none | fuzz + simnet | p2p.md (31) | L | **P2** (design in 34's ADR now) |
| **W41-15** | RandomX targets `fpu_diff` (after 05 C3) and `randomx_program` (`#[cfg(fuzzing)]` export) | `fuzz/fuzz_targets/*` (41); `randomx/src/lib.rs` cfg(fuzzing) mod line (05/06, Q2) | nothing | none | fuzz | — | S–M | **P2** |
| **W41-16** | `mempool_seq` target after 12's sub-pool redesign; `store_records` after 35 exposes the parser | `fuzz/fuzz_targets/*` (41); a `#[doc(hidden)] pub` parser entry in `chain/src/store.rs` (35) | nothing | none | fuzz | — | S | **P2** |
| **W41-17** | Swarm-testing op masks in all stateful harnesses | `tools/testkit` (41) | nothing | none | — | — | S | **P2** |

**Order:** W41-2 → W41-3 (unblocks 02/12/01 P0 work) → W41-1 (E1 in the next exclusive window) →
W41-8, W41-9, W41-4 → W41-6, W41-7, W41-5 → W41-10/11 → E2 → W41-12/13 → P2 items.

No item changes consensus or any network/genesis identity. Benchmarks: none beyond the 10-minute
calibration per campaign and the ZK-F4 cost table.

---

## 6. Dependencies and conflicts

- **02** fork choice: W-1 model and properties are 02's; 41 supplies testkit/runner and reuses the
  model as the `chain_manager` oracle. Files are disjoint (`fork_choice_{model,props}.rs` vs
  `manager_stateful.rs`).
- **12** mempool: W6 stateful test is 12's (P0); 41 provides the runner; `mempool_seq` waits for 12's redesign.
- **01 / 04**: LWMA/MTP/HeaderChain property files are theirs; framework from 41.
- **05 / 06 / 08**: FPU oracle C3 first; any `cfg(fuzzing)` export in `randomx` needs their and the
  coordinator's approval (Q2).
- **10**: the parallel-verify differential proptest is 10's file; no conflict.
- **15 / 16 / 17**: they write target bodies; 41 owns `fuzz/Cargo.toml`, `seeds.rs`, the script.
- **20**: shared edits of `fuzz/src/seeds.rs` (function-rich kernel seeds) and the F41-2 change in `px/tests/fuzz.rs`.
- **22 / 24 / 25 / 27**: verifier targets, the grinding decision (Q3), ZK-F4 cost evidence.
- **31 / 34**: D1 sans-IO shape must be part of the actor design; simnet adversary roles double as 31's "hostile peer" tests.
- **35**: parser entry point for `store_records`; kill -9 chaos informs recovery tests.
- **09 / 40**: labnet file sequencing (09's I4 first).
- **42**: mutation runs use the new properties as the kill set; the harness oracles should themselves be mutation-tested.
- **43**: owns CI files; 41 supplies job specs. **44**: confirms proptest (`std` only), no `proptest-state-machine`, and (if Q2 = yes) no new deps.
- **47**: AUDIT.md, launch checklist G9 wording, stale proptest reason.
- **50**: red-team may use simnet adversary roles and the stateful targets.

## 7. Open questions for the coordinator

1. **Corpus storage:** create a public `BlackSilk-fuzz-corpora` repository (owner action), or keep corpora only as release assets? I recommend the repository plus release assets for proof corpora, with human-merged updates (no write token in CI).
2. **`#[cfg(fuzzing)]` exports** in consensus crates (`randomx` program/FPU entry points, possibly `chain` store parser): acceptable given zero production effect?
3. **Verifier depth:** add a `cfg(fuzzing)` configuration with query grinding off in `zk`, or accept shallow verifier coverage (my default)?
4. **`tools/testkit` as a workspace member** (dev tool, publish = false, no external deps): approve, and who edits the root `Cargo.toml` members list?
5. **Exclusive machine window for E1** (≈ 6–7 h wall, 4 cores, up to ~6 GB RAM): schedule alongside the benchmark window of decision 06?
6. Confirm **`proptest-state-machine` is not adopted** (in-house runner instead).
7. Confirm the **Wasm targets are demoted** to smoke plus 1 h per campaign (ADR-28-1).
8. Is a **simnet D0 check of 02's F-1 fix** wanted as P0 evidence before the trial, or is 02's model-level proptest sufficient?

## 8. Sources

- LLVM libFuzzer documentation (flags `-runs`, `-max_total_time`, `-timeout`, `-rss_limit_mb`, `-malloc_limit_mb`, `-max_len`, `-fork`, `-ignore_crashes`, `-jobs`, `-workers`, `-merge`, `-use_value_profile`, `-dict`, `-print_final_stats`, `-seed`; fork mode "experimental"): https://llvm.org/docs/LibFuzzer.html
- libFuzzer source as vendored by libfuzzer-sys 0.4.13 (`FuzzerLoop.cpp` ReadAndExecuteSeedCorpora, `FuzzerIO.cpp` FileToVector): https://github.com/rust-fuzz/libfuzzer (local registry copy read)
- cargo-fuzz 0.13.2 (`-O`, `-a`, `--cfg fuzzing`, cmin, coverage): https://github.com/rust-fuzz/cargo-fuzz ; Rust Fuzz Book, structure-aware fuzzing (`Arbitrary`, `fuzz_mutator!`): https://rust-fuzz.github.io/book/cargo-fuzz/structure-aware-fuzzing.html
- Google fuzzing docs, structure-aware fuzzing with libFuzzer: https://github.com/google/fuzzing/blob/master/docs/structure-aware-fuzzing.md
- proptest: https://github.com/proptest-rs/proptest ; proptest book, state machine testing: https://proptest-rs.github.io/proptest/proptest/state-machine.html ; proptest-state-machine 0.8.0: https://docs.rs/proptest-state-machine/latest/proptest_state_machine/ and manifest https://docs.rs/crate/proptest-state-machine/latest/source/Cargo.toml.orig
- FoundationDB, Simulation and Testing: https://apple.github.io/foundationdb/testing.html
- TigerBeetle VOPR: https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/internals/vopr.md
- turmoil: https://github.com/tokio-rs/turmoil ; announcement https://tokio.rs/blog/2023-01-03-announcing-turmoil
- madsim: https://github.com/madsim-rs/madsim ; mad-turmoil (libc symbol overrides for determinism): https://github.com/s2-streamstore/mad-turmoil ; S2, "Deterministic simulation testing for async Rust": https://s2.dev/blog/dst (pointer)
- Sans-IO protocol design: https://sans-io.readthedocs.io/ ; quinn-proto (Rust sans-IO QUIC core): https://github.com/quinn-rs/quinn
- Bitcoin Core fuzzing doc (qa-assets, per-PR corpus replay, deterministic fuzz build skipping PoW, disabling RNG seeding and clock): https://github.com/bitcoin/bitcoin/blob/master/doc/fuzzing.md ; qa-assets: https://github.com/bitcoin-core/qa-assets ; `process_message` harness: https://github.com/bitcoin/bitcoin/blob/master/src/test/fuzz/process_message.cpp ; `process_messages` PR #18521: https://github.com/bitcoin/bitcoin/pull/18521 and review club https://bitcoincore.reviews/18521 ; mocked time PR #20437: https://github.com/bitcoin/bitcoin/pull/20437 ; `tx_pool` target review club: https://bitcoincore.reviews/21142
- Zebra non-finalized state proptests (`forked_equals_pushed_*`, `finalized_equals_pushed_*`, `rejection_restores_internal_state_genesis`; `PROPTEST_CASES` overrides): https://github.com/ZcashFoundation/zebra/blob/main/zebra-state/src/service/non_finalized_state/tests/prop.rs ; `LedgerState` arbitrary chains: https://doc.zebra.zfnd.org/zebra_chain/block/arbitrary/struct.LedgerState.html
- reth codecs (`derive_arbitrary` generating arbitrary + proptest round-trip tests): https://github.com/paradigmxyz/reth/blob/main/crates/storage/codecs ; sparse-trie differential proptests (300 CI cases, 4,000 soaked): https://github.com/paradigmxyz/reth/pull/27159
- ClusterFuzzLite (code-change, batch, prune, coverage modes; storage repo needs a PAT): https://google.github.io/clusterfuzzlite/running-clusterfuzzlite/github-actions/
- GitHub-hosted runner specs (public repos: 4 vCPU, 16 GB, 14 GB SSD): https://docs.github.com/en/actions/reference/runners/github-hosted-runners ; usage limits (6 h per job): https://docs.github.com/en/actions/administering-github-actions/usage-limits-billing-and-administration
- A. Groce, C. Zhang, E. Eide, Y. Chen, J. Regehr, "Swarm Testing", ISSTA 2012: https://dl.acm.org/doi/10.1145/2338965.2336763
- M. Böhme, V. Manès, S. K. Cha, "Boosting Fuzzer Efficiency: An Information Theoretic Perspective" (Entropic, default libFuzzer power schedule), ESEC/FSE 2020: https://dl.acm.org/doi/10.1145/3368089.3409748
- Internal: `docs/reviews/full-review-2026-09-27/R13-testing-supplychain.md` (T-1…T-15), `SX2-systems-crossreview.md`, `R12-performance.md` §1.3, AUDIT.md fuzz sections.
