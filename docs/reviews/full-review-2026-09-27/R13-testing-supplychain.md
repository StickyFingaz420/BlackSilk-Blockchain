# R13: Testing strategy, fuzzing, CI/CD, reproducibility and supply chain (program level)

Reviewer: R13 (internal review, **not an audit**). Date: 2026-09-27. Branch `rebuild/core`, HEAD `0b7bc54` (the brief says `f677e55`; two test/zk commits have landed since, `4b277cd` and `0b7bc54`, and are included).
Method: read-only source reading (Read/Grep/Glob/git), no builds. I also read the `cargo-fuzz 0.13.2` sources in the local cargo registry, and did web research (sources are listed at the end). The GitHub Actions page of the public repository was read over the web.
Scope: the program-level testing strategy. The dependency review (A14) and the CI detail fixes (A15b) are not repeated. Where I touch their items, I only add depth or correct them.

Evidence tags: **[math]** mathematically established · **[tested: name]** · **[source-read]** · **[web]** observed on the web · **[assumed]** · **[unknown]**.

---

## 0. Executive summary

BlackSilk has **more testing than most projects at this stage**:
- 731 `#[test]`/`#[tokio::test]` functions over the workspace plus `third_party`;
- 9 cargo-fuzz targets, including two strong differential ones (`kernel_diff`, `contract_sequence`);
- seeded mutation "fuzz" tests inside the normal suite;
- a multi-process lab network with partitions and supply checks;
- pins for the genesis ids, the kernel and vault program ids, and Poseidon2;
- a statistical privacy campaign (P-5);
- a pinned CI whose recent runs are all green.

The **strategy has structural gaps** that matter for a consensus-critical system:

1. **The oracles are weak where it counts** (T-1). Almost every fuzz and mutation test checks only "no panic" and "decode∘encode is the identity". No test has a **non-malleability oracle** ("if a mutated object still validates, its bytes are the original's"). The FRI-witness malleability (A14 M1) passed every one of these tests. The dependency review found it by reading upstream issues, not through testing. The 400-position byte-flip test in `zk/tests/proofs.rs:243` samples every ~N-th byte, so it never hit the witness field.
2. **The coverage-guided campaigns ran without overflow checks and debug assertions** (T-2, new). `fuzz/run_campaign.sh:19,26` passes `--release` to `cargo fuzz`. In cargo-fuzz 0.13.2 that turns off `-Cdebug-assertions`, and with it overflow checks. The "≈531 M executions, 0 crashes" cited for gate G9 therefore says nothing about integer overflow or `debug_assert!` invariants.
3. **No conformance test vectors for consensus arithmetic** (T-3). LWMA, emission, block and tx ids, the seed schedule, MTP and merkle roots are not pinned by golden vectors. The mutant `(n + 1) → n` in `consensus/src/difficulty.rs:40` changes every difficulty by −1.6%, and I predict it **survives the whole suite**. A refactor could silently hard-fork the chain.
4. **No property-based framework, model checking or deterministic simulation** (T-4, T-5). The documented reason for avoiding `proptest` ("getrandom does not build", AUDIT.md:297, transactions.md:1017) is stale: `getrandom` 0.2.17 and 0.3.3 are already in `Cargo.lock`. The fork-choice order-independence test deliberately avoids ties (`consensus/src/chain.rs:711`). P2P tests use real sockets and `sleep`.
5. **The fuzzing surface misses the stateful attack surfaces** (T-6):
   - the peer message handler (`p2p/src/net.rs`, 1,781 lines);
   - the `HeaderChain`/`ChainManager` state machines;
   - mempool sequences;
   - the **ZK verifier** (`proof_decode` only decodes);
   - CLSAG/BP+ verification and batch versus single verification.

   The corpora are gitignored and live on one developer machine (T-7).
6. **RandomX is not differentially tested against the reference at scale** (T-8). The coverage is:
   - 5 end-to-end vectors;
   - 1,024 full=light self-consistency hashes (not reference-checked);
   - no aarch64 run.

   The software FPU (`randomx/src/fpu.rs`) is the component most likely to hide a rare platform-independent divergence. An exact pure-Rust oracle exists: `rustc_apfloat`.
7. **Release engineering is absent** (T-10):
   - no tags, no signed commits or tags, no release binaries;
   - the Dockerfile uses a floating `rust:1-bookworm` base (not 1.98.1) and has no `.dockerignore`;
   - no SBOM, no `cargo-vet`/`crev`, no `cargo-deny`, no root `rust-toolchain.toml`.

   Launch checklist item "binaries are pinned" has no mechanism behind it.

**None of this is critical by itself.** Items 1–3 are the ones I would do **before the testnet (P0)**. They are small (S/M) and protect against the failure a testnet cannot tolerate: an unnoticed consensus change or a malleable transaction id during the ongoing multi-agent refactoring.

---

## 1. What exists (inventory)

**Tests per crate.** Counts are `#[test]` plus `#[tokio::test]`, from grep **[source-read]**:

| Crate | Unit+integration tests | Notes |
|---|---|---|
| randomx | 17 (1 ignored: full mode) | 5 official hash vectors + cache/superscalar/dataset/AES vectors; fpu unit tests |
| consensus | 32 | LWMA 7 tests (tolerance-based); fork choice 9; genesis pin |
| crypto | 94 | CLSAG self-generated pinned vector (`clsag.rs:979`); BP+ batch tests |
| tx | 61 | adversarial.rs (820 lines), fuzz_decode (seeded mutation), privacy.rs |
| chain | 44 | manager.rs restart/torn write/reorg; revalidation.rs |
| p2p | 20 + 27 tokio | network.rs: in-process multi-node over real loopback sockets |
| rpc | **0** | covered indirectly by wallet/tests/e2e.rs |
| node | 4 + 1 | config only; the RPC handlers are only reached through the wallet e2e tests |
| miner | 2 | nonce search agrees with consensus |
| wallet | 27 | e2e.rs (1,116 lines) spins up node+miner in process |
| zk / zkvm / px / px-core | 12 / 68 / 30 / 4 | pins, mutation, differential kernel, blinding, stress (ignored) |
| contracts | 30 | exec, seeded fuzz |
| tools/labnet | 0 | the harness itself |
| third_party | 189 | **never run in CI** (known) |

**Coverage-guided fuzzing** (`fuzz/`):
- 9 targets: `tx_decode`, `block_decode`, `p2p_message`, `proof_decode`, `zkvm_elf`, `kernel_diff`, `delivery_open`, `wasm_module`, `contract_sequence`;
- seeds from `fuzz/src/seeds.rs`;
- an own workspace with its own tracked lockfile;
- a 2-minute smoke run per target in CI.

**Recorded campaigns:**
- 144 M executions (15 min per target);
- 387 M executions (10.5 h);
- `wasm_module` for 6 h and `contract_sequence` for 4 h.

All report 0 crashes (AUDIT.md:1118–1200, 1350–1378).

**Seeded mutation tests in the normal suite:**
- `tx/tests/fuzz_decode.rs`, `chain/tests/fuzz_block.rs`, `p2p/tests/fuzz_message.rs`;
- `zkvm/tests/fuzz.rs`, `px/tests/fuzz.rs`, `contracts/tests/fuzz.rs`.

`BLACKSILK_FUZZ_ITERS` scales them.

**Labnet** (`tools/labnet`): N real node/miner processes behind latency/jitter/partition proxies, with wallet and PX traffic. It checks:
- convergence;
- stuck nodes;
- a late joiner syncing;
- wallets restored from seed;
- supply conservation.

The runs recorded so far are the 62-minute PX run, the 30-minute reset rehearsal and the 60-minute PX regtest run.

**CI** (`.github/workflows/ci.yml`) has 6 jobs:
- lint;
- release tests;
- RandomX full mode;
- guests reproduction plus RandomX on Windows;
- cargo-audit;
- fuzz-smoke.

Actions are SHA-pinned, the toolchain is pinned to 1.98.1 and the token is read-only. The public repository's Actions page shows runs #65–#74 on `rebuild/core` all green, at 35–68 min each **[web]**.

**Reproducibility:**
- `zkvm/guests/reproduce.sh` rebuilds the consensus-pinned guests to their program ids (Windows only, known);
- `Cargo.lock`, `fuzz/Cargo.lock` and `zkvm/guests/Cargo.lock` are tracked;
- the release profile uses `lto = "fat"` and `codegen-units = 1`, which helps determinism.

**Privacy testing:** the P-5 proof-length campaign (permutation and KS tests, `docs/evidence/p5-*`) is a good model of evidence-based privacy testing.

---

## 2. Findings

### T-1 Oracles: no non-malleability or cross-verdict oracle in fuzz or mutation tests
- **Class:** Partially implemented · **Severity:** high (for a system whose tx id must be non-malleable) · **Confidence:** high.
- **Where:**
  - `fuzz/fuzz_targets/proof_decode.rs:7-10` only checks the canonical round trip;
  - `zk/tests/proofs.rs:243-268` flips 1 byte at about 400 evenly spaced positions of a toy proof;
  - `tx/tests/fuzz_decode.rs` validates only 25 PX mutants in full;
  - `block_decode`, `tx_decode` and `p2p_message` check no-panic and canonical encoding.
- **Evidence:**
  - [source-read];
  - commit `4b277cd`: the M1/M2 rewrite was found by the dependency review, not by any test. Its new test shows "the 0.7.0 verifier accepting a rewritten witness" **[source-read: commit message]**.
- **Scenario:** a relayer rewrites a semantically unbound field and the verifier still accepts. Examples:
  - a FRI grinding witness;
  - an empty optional opening;
  - a non-canonical scalar or point encoding in CLSAG/BP+ if a decoder ever became lenient;
  - a padding byte in a future codec.

  The tx id changes, and so do mempool conflict or cache keys (the "PX proofs already verified on mempool admission" cache is keyed by id, `chain/src/manager.rs:560`).

  A round-trip oracle cannot see this, because the mutated bytes also round-trip. A sparse byte-flip test hits an 8-byte field in a ~2 MB proof with probability ≈ 400·8/2·10⁶ ≈ 0.16% per run **[math, approximate]**.
- **Missing oracle:** for any mutant `m` of an honest object `o`, the rule is `validate(m) == Ok ⇒ bytes(m) == bytes(o)`. For signatures and proofs, apply it to every field. It needs **structure-aware** mutation: mutate each decoded field, re-encode, verify. This beats random byte flips.
- **Also missing:** batch versus single verification agreement (`bpp::batch_verify` versus `bpp::verify`, `crypto/src/bulletproofs_plus.rs:522,529`, used in consensus at `tx/src/validate.rs:921`). The tests only check it on honest items and single bad items (`bulletproofs_plus.rs:786-814`).

### T-2 Coverage-guided campaigns ran with overflow checks and `debug_assert!` disabled (NEW)
- **Class:** Complete but requires further testing · **Severity:** medium · **Confidence:** high.
- **Where:**
  - `fuzz/run_campaign.sh:19` runs `cargo fuzz build --release`, and `:26` runs `cargo fuzz run --release`;
  - the manual commands in AUDIT.md:1357-1358 also pass `--release`.
- **Evidence:** cargo-fuzz 0.13.2:
  - `src/options.rs:62` says: "Build artifacts with debug assertions and overflow checks enabled (default if not -O)";
  - `src/project.rs:259` adds `-Cdebug-assertions` only when `!build.release || build.debug_assertions`.

  So `--release` without `-a` builds **without** debug assertions, and overflow checks follow them **[source-read]**. The seeded tests run under `cargo test --release`, whose profile sets `debug-assertions = false` (`Cargo.toml` `[profile.release]`), so they have the same gap. That part is already known as "no overflow runs"; the part about the fuzz campaigns is new.
- **Impact:** the libFuzzer campaigns (≈531 M executions cited for gate G9 in `docs/testnet-launch-checklist.md`) never checked:
  - integer overflow in decoders, length arithmetic, the zkVM interpreter, the contract engine's fuel/storage accounting or PX value arithmetic;
  - the `debug_assert!`s: consensus 2 (`chain.rs:210`, `pow.rs:25`), tx 3, zkvm 3, px-core 1, px 1, wallet 8, crypto 1.

  Wrapping overflow in release is *defined* behaviour, so ASan cannot catch it either.
- **Scenario:** a length sum in a decoder wraps, passes a bound check, and is later caught (or not) by a slice check. The campaign reports "0 crashes" either way.
- **Fix:** `cargo fuzz build -O -a` (or `--debug-assertions`), re-run at least the long campaign, and record both kinds of run. **P0** (S). It needs no code change, but it may surface intentional wrapping that must become `wrapping_*`, which is a good outcome.

### T-3 No consensus conformance vectors; a real LWMA mutant survives
- **Class:** Not implemented · **Severity:** high (silent hard fork during refactoring) · **Confidence:** medium-high for the mutant prediction.
- **What is pinned** **[source-read]**:
  - the genesis ids (`consensus/src/params.rs:124`);
  - Poseidon2 (`zk/tests/pins.rs`);
  - the kernel and vault ids (`px/tests/proof.rs:24`, `px/tests/unified.rs:59`);
  - one CLSAG alpha/signature vector (`crypto/src/clsag.rs:979`);
  - the RandomX official vectors.
- **What is not pinned:**
  - LWMA `next_difficulty` outputs;
  - the emission table (`chain/src/emission.rs` tests are relational: "monotone", "curve matches spec");
  - MTP/FTL decisions;
  - the seed-height schedule;
  - block and tx ids for fixed objects;
  - the merkle root of fixed leaves;
  - address encodings;
  - key-image, stealth-derivation and hash-to-point outputs;
  - BP+ proofs that must verify or must fail;
  - a stored PX proof that must verify for a fixed statement.
- **Predicted surviving mutant** **[math, source-read]**: in `consensus/src/difficulty.rs:40`, `(n + 1)` → `n`.
  - Steady state: the exact output is `D·n/(n+1)` = 9,836 for D = 10,000 and n = 60. `steady_state_is_stable` accepts 9,800..10,200.
  - 2× hashrate: 19,672. `responds_to_hashrate_changes` accepts 19,000..21,000.
  - The bound test asserts only `d ≤ 101,667` and `d > 10,000`.
  - The chain-level tests are tolerance-based too.
  - So a −1.6% change to every difficulty passes the suite. Other likely survivors are `6 * t` → `7 * t` (line 32) and `/ 20` → `/ 19` (line 37, only the `/ 21` direction is killed); `.max(1)` is an equivalent mutant.
- **Why it matters now:** several agents are editing consensus-adjacent code in parallel. Any node built from a tree carrying such a change would reject the chain after the first retarget that differs. The testnet cannot tell "valid" from "the code's current behaviour" without an independent source of truth.
- **Fix:** add `consensus/tests/vectors/*.json` (or `.rs` tables) generated once, reviewed by hand against the spec formulas, and checked by a test. Publish them in the spec as the **conformance suite** a second implementation must pass (the Ethereum `consensus-spec-tests` and Zcash `zcash-test-vectors` model).

### T-4 No property-based testing framework; key consensus properties are untested
- **Class:** Partially implemented (seeded loops) · **Severity:** medium · **Confidence:** high.
- **Evidence:**
  - AUDIT.md:297 and docs/transactions.md:1017 give the reason: "proptest needs getrandom, which does not build on the audit toolchain". `Cargo.lock` now contains `getrandom 0.2.17` and `0.3.3`, and labnet depends on `getrandom` directly, so the reason is **stale** **[source-read]**.
  - The seeded loops cannot **shrink** failures. They also do not persist failing cases for regression the way `proptest-regressions/` files do.
- **Missing properties** (each is small):
  - **LWMA:**
    - `next_difficulty ≥ 1`;
    - no panic for any `u64` timestamps and any monotone cumulative sequence (note the `assert_eq!` at `difficulty.rs:14` and the `cd[i] - cd[i-1]` subtraction, which is sound only if cumulative is monotone);
    - the per-block increase bound `≤ 10·(n+1)/n · avg D` [math: from `weighted ≥ n²T/20`];
    - monotonicity: longer solve times never raise difficulty;
    - scale invariance: multiplying every D by k multiplies the output by ≈k;
    - no u128 overflow at `D = u64::MAX` (the bound is 61·2⁶⁴·120·61 < 2⁸⁴, **[math]**, so it is fine today; a pin keeps it fine).
  - **Fork choice (`HeaderChain`):**
    - for a random header DAG fed in any order, the best work is equal and the tip is one of the max-work tips;
    - `main` is always the ancestor path of the tip;
    - a `Reorg` is consistent (disconnected ∪ connected reconstructs both chains);
    - `mark_invalid(x)` gives the same state as a fresh chain fed everything except x's subtree;
    - `precheck_batch` agrees with sequential `accept` (a hand-picked version exists at `chain.rs:815`).

    `verdicts_do_not_depend_on_arrival_order` (`chain.rs:705`) excludes ties by construction, so the first-seen/seq tie-break (`chain.rs:477`, `:529-531`) and replay-order issues (known, being fixed) are untested as properties.
  - **Mempool:**
    - after any sequence of add, remove_block, reorg and evict: no two entries conflict, and the byte/count limits hold;
    - the template never contains a conflict;
    - pool contents never change a block's verdict (one example exists at `chain/tests/manager.rs:911`).
  - **Codecs:** `decode(encode(x)) == x` for *generated* structured values, in addition to the decode-side round trip.
- **Fix:** add `proptest` as a dev-dependency (default features include `std` and `fork`; use `default-features = false, features = ["std"]` if needed), with a fixed seed in CI plus a nightly run with a random seed. **P1**, S–M.

### T-5 No deterministic simulation or model checking of the node
- **Class:** Not implemented · **Severity:** medium (testnet); high before mainnet · **Confidence:** high.
- **Evidence** **[source-read]**:
  - `p2p/tests/network.rs` runs real tokio runtimes over loopback sockets and waits with `tokio::time::sleep` and `wait_until` polling (lines 277-283, 593, 655, 964, 1213, 1283, 1321). It is time-sensitive, cannot be replayed from a seed, and a race seen once cannot be re-run.
  - `p2p/src/net.rs` has 24 direct uses of `Instant/SystemTime::now`, `tokio::spawn` or OS randomness; `dandelion.rs` has 3, `limits.rs` 2 and `transport.rs` 3.
  - By contrast, `consensus` and `chain` take `now: u64` as a parameter (`chain/src/manager.rs:321`, `consensus/src/chain.rs:442`). **This is the right design and should be kept.**
- **Why it matters:** most of the P2P findings in the brief are interleaving and timing bugs:
  - the header queue across reconnects;
  - concurrent handshakes bypassing limits;
  - a tip announcement racing GetHeaders;
  - re-request loops;
  - H1 (withheld bodies);
  - replay tie-breaks.

  This class of bug is exactly what deterministic simulation testing (DST) finds and makes replayable (FoundationDB, TigerBeetle VOPR, turmoil, madsim).
- **Options:**
  - (a) **turmoil**: simulated hosts, network and time within tokio, driven by a seed. It is the least invasive, because it replaces `tokio::net` with `turmoil::net` behind a small cfg or trait.
  - (b) **madsim**: a drop-in tokio replacement via `--cfg madsim`. It is more complete, but it patches tokio and has a heavier dependency footprint.
  - (c) a sans-IO refactor of `net.rs` into a pure `PeerState` machine (message in → actions out, `now` injected). It is then trivially fuzzable (T-6) and model-checkable.

  I recommend **(c) for the per-peer protocol logic plus (a) for multi-node scenarios.**
- **Model checking:** fork choice with "most-work **body-complete** chain" (the H1 fix) and restart replay is a small state space with subtle ordering. Two tools fit:
  - `stateright` (a Rust embedded model checker) can exhaustively explore header/body arrival orders, invalidation and restart for chains of depth ≤ 6 with 2–3 branches;
  - `kani` (a bounded model checker) can prove panic-freedom and the bound properties of `next_difficulty` and `median` for small windows.
- **Priority:** P2 for DST (L). P1 for a stateright model of the H1 fork-choice rule (M), because that rule is being changed now.

### T-6 Fuzzing does not cover the main attack surfaces
- **Class:** Partially implemented · **Severity:** medium-high · **Confidence:** high.

**Attack surfaces against targets:**

| Attack surface (remote unless noted) | Covered by | Gap |
|---|---|---|
| Frame decrypt/length (`p2p/src/transport.rs:92-113`) | none | Low: the length is AEAD-authenticated and checked before allocation. A handshake point-decode target is cheap |
| Message decode | `p2p_message` | covered (canonical) |
| **Per-peer protocol state machine** (`net.rs`, 1,781 lines: headers flow, GetData, inv/tx announce, Dandelion, scoring) | none | **Largest gap.** Needs sans-IO (T-5c); then fuzz sequences of `Message`s from 1–3 peers with invariants: bounded memory, no ban of honest behaviour, no panic |
| Header chain (`HeaderChain::accept`, `precheck_batch`) | unit tests | fuzz random header DAGs with a ZeroPow/cheap PoW; oracles from T-4 |
| Block connect/reorg (`ChainManager::submit_block`) | manager.rs examples | stateful fuzz: sequences of valid-ish blocks, mutated txs, reorgs, restarts; oracle: state root equals a from-scratch replay; supply conserved |
| Mempool | examples | stateful fuzz (T-4 properties); cost oracle (revalidation DoS is known) |
| Tx stateless rules | `tx_decode` | covered; only 25 PX mutants reach full validation (seeded test) |
| **ZK verifier** (`blacksilk_zk::verify` on decodable proofs) | `zk/tests/proofs.rs` byte flips (400 positions) | **no coverage-guided target runs the verifier.** Needs structure-aware mutation of decoded proofs, a non-malleability oracle (T-1) and a **cost** oracle (libFuzzer `-report_slow_units`, max verify time: the known ZK-F4) |
| CLSAG/BP+ verification | unit tests | fuzz verify on arbitrary points/scalars (no panic, non-malleability); batch==single differential |
| Store record parser (`chain/src/store.rs:250`) | torn-write tests | local attack surface (a corrupted disk): fuzz `parse_record` and replay |
| Wallet file decode (`wallet/src/wallet.rs:406`), addresses | unit tests | low: local |
| zkVM ELF/interpreter | `zkvm_elf` | covered |
| Kernel native/guest | `kernel_diff` | covered (differential, good) |
| Delivery | `delivery_open` | saturated by design |
| Contracts | `wasm_module`, `contract_sequence` | covered (determinism, rollback, replay: a good model) |

- **Throughput:** `proof_decode` runs at 21 exec/s and `kernel_diff` at 98 exec/s (AUDIT.md:1127-1130). Byte-level fuzzing of a 2 MB proof is the wrong tool. Use `arbitrary`-derived structured inputs: mutate the decoded proof and re-encode.

### T-7 Corpus management and continuous fuzzing
- **Class:** Partially implemented · **Severity:** medium · **Confidence:** high.
- **Evidence** **[source-read]**:
  - `fuzz/.gitignore` ignores `corpus`, `artifacts` and `coverage`. The corpora on disk hold 23,212 files (for example `wasm_module` 15,764 and `proof_decode` 1,559) and exist only on the developer's Windows machine.
  - The CI smoke run starts from the seeds on each run, so 2 minutes per target never reaches the depth of the 10.5 h campaign.
  - No regression replay of the corpus in the normal suite.
  - No minimization pipeline (`cargo fuzz cmin`).
  - No crash-to-regression-test workflow.
  - No coverage report of the corpora (`cargo fuzz coverage`).
- **Risk:** losing that machine loses the campaigns' only durable output. A reviewer cannot reproduce "0 crashes on this corpus".
- **Fix:**
  - keep minimized corpora in a separate repository (the Bitcoin Core `qa-assets` model) or as release assets;
  - replay them in CI on each push (fast: seconds per target, no fuzzing);
  - run a scheduled nightly job of 1–2 h across targets with the corpus cached or uploaded (ClusterFuzzLite "batch" mode, or a plain cron workflow);
  - add PR-mode fuzzing on changed code.

  **P1**, S–M.

### T-8 RandomX: differential testing against the reference at scale, FPU oracle and aarch64
- **Class:** Complete but requires further testing · **Severity:** medium-high (a consensus split is possible only across platforms, or with a second implementation; mining pools using reference-RandomX derivatives in future) · **Confidence:** high.
- **Evidence** **[source-read]**:
  - `randomx/src/lib.rs` has the official vectors 1a–1e and component vectors; the ignored test checks full=light over 1,024 random inputs. That is self-consistency, not agreement with the reference.
  - `fpu.rs` emulates the directed rounding modes with error-free transforms (README "Design notes").
  - CI runs the vectors on Linux x86 and Windows x86 only.
- **Why:** five end-to-end hashes exercise at most 5 × 8 programs × 2,048 iterations of instructions. Rare paths (directed-rounding corner cases, subnormals, `CFROUND` sequences, overflow to ±MAX/±inf) are covered by unit tests the project wrote itself, whose expected values come from the same understanding.
- **Three independent oracles:**
  1. **Offline reference vectors.** Generate N ≥ 10⁵ `(key, input, hash)` triples with the tevador/RandomX reference, spread over ≥ 16 keys. Commit a compressed file (≈ 10⁵ × 64 B ≈ 6.4 MB, or a sampled subset plus a hash-of-all digest). Check them in a scheduled job. The generator is test tooling, not core code: it is the same exemption as libFuzzer's C++, documented as such. The in-tree check stays pure Rust.
  2. **Exact FPU oracle in pure Rust.** `rustc_apfloat` (a port of LLVM APFloat) implements add, sub, mul, div and FMA with all IEEE rounding modes, with no host floating point and no unsafe code. It can serve as a property-test oracle against `fpu.rs` for each operation and rounding mode on random and edge-biased f64 inputs, including sqrt if it is emulated separately; APFloat has no sqrt, so use the `ieee-apsqrt` crate or big-rational bisection for sqrt.
  3. **aarch64 CI** (`ubuntu-24.04-arm`; the repository is public, so the runners are free). It checks the soft-AES path of `aes` against AES-NI, and it checks LLVM codegen on a second backend.
- **Priority:** 2 and 3 are **P1** (S–M); 1 is P1 (M).

### T-9 Labnet scope: honest-only, short, no fault injection beyond partitions
- **Class:** Partially implemented · **Severity:** medium · **Confidence:** high.
- **Evidence** **[source-read]**:
  - processes are killed only at the end (`tools/labnet/src/main.rs:628,731`);
  - no adversarial peer process;
  - no clock skew;
  - no disk-full or crash-restart mid-run;
  - the longest recorded run is 62 min; the default is 180 min;
  - it never runs in CI (known).
- **Missing scenarios:**
  - kill -9 and restart of a node during sync and during a reorg (checks restart replay and the store tail);
  - clock skew of ±FTL on one node (checks MTP/FTL at the edges);
  - an **adversarial node** mode built from the same codebase with a flag (withheld bodies for H1, invalid-body headers, header spam below minimum work, inv floods, stale-tip announcements);
  - a soak of ≥ 1 real RandomX seed epoch at testnet parameters in full-mode miners (the dataset-switch stall is known);
  - a resource-leak trend check (RSS slope) rather than peak only.
- **Fix:** extend labnet with a `--chaos` schedule and an `--adversary` node role. Run 6 h nightly on a self-hosted or large runner, and 72 h before launch (gate G5). **P1** for kill/restart and skew (S). P2 for the adversary role (M).

### T-10 Release engineering and build reproducibility
- **Class:** Not implemented · **Severity:** medium (testnet); high before mainnet · **Confidence:** high.
- **Evidence** **[source-read]**:
  - `git tag -l` is empty;
  - HEAD is unsigned and `commit.gpgsign` is unset;
  - no release workflow;
  - operators build from source (`deploy/scripts/install-linux.sh:24`) with whatever toolchain they have: there is no root `rust-toolchain.toml` (only the guests have one) and no `rust-version` in any manifest.
  - `deploy/docker/Dockerfile:8` uses `FROM rust:1-bookworm`, a floating tag. CI and the evidence use 1.98.1.
  - `debian:bookworm-slim` is not digest-pinned.
  - no `--remap-path-prefix`, no `SOURCE_DATE_EPOCH`, no `.dockerignore`: `COPY . .` sends `target/` (GBs), `.git`, `legacy/` and any untracked local files to the build context. The final image copies only the binaries, but the build stage and any remote builder see everything.
  - No SBOM and no `cargo auditable` metadata in the binaries.
  - `docs/testnet-launch-checklist.md` requires "the release commit and binaries are pinned", but nothing implements the binary part.
- **Consensus relevance:** the consensus-pinned guest ELF is reproducible only on Windows at the canonical path (known). The node and miner binaries are not reproducible at all today. The testnet can tolerate that, but operators cannot verify what they run.
- **Minimum for the testnet (P0, S):**
  - a root `rust-toolchain.toml` pinning 1.98.1;
  - the Dockerfile pinned to `rust:1.98.1-bookworm@sha256:…` and a digest-pinned runtime base;
  - a `.dockerignore`;
  - a **signed annotated tag** for the release commit (SSH or GPG signing, with the key fingerprint in SECURITY.md);
  - the CI run of the tag linked in the readiness report.
- **P1:**
  - a release workflow that builds Linux x86_64 and aarch64 binaries with `--locked`, `--remap-path-prefix` and `SOURCE_DATE_EPOCH`;
  - `SHA256SUMS` signed by the maintainer;
  - GitHub artifact attestations (SLSA build provenance);
  - a CycloneDX SBOM (`cargo cyclonedx`);
  - `cargo auditable` builds;
  - a second independent rebuild compared bit for bit (the Bitcoin Core Guix / Monero model is XL; two-builder comparison of the same Docker recipe is M).

### T-11 Supply-chain review depth
- **Class:** Partially implemented · **Severity:** medium · **Confidence:** high.
- **Existing controls:**
  - `cargo audit` in CI;
  - A14's manual dependency review;
  - tracked lockfiles;
  - no git dependencies (`Cargo.lock` has 0 `git+` sources, 323 packages; the fuzz lock has 177; the guests have 6) **[source-read]**.
- **Missing:**
  - `cargo-vet` or `cargo-crev`. There is no recorded audit trail per crate and version, so a lockfile bump pulls unreviewed code silently. `cargo vet` can import audits from Mozilla, Google, Bytecode Alliance and ZcashFoundation, which already cover much of RustCrypto and dalek; only the delta needs owner review.
  - `cargo-deny`: license policy, a single-registry `sources` policy, `bans` for duplicate or unwanted crates. It would also mechanically enforce "No C/FFI" by banning `cc`/`bindgen`/`*-sys` in the non-fuzz graph (today "No C/C++" is verified manually, per A14).
  - Automated verification that `third_party/p3-*` equals the crates.io 0.7.0 tarball (checksum from the index) plus exactly the documented hunks (`third_party/README.md:61-81` records it manually).
  - CI does not check the `fuzz/Cargo.lock` or `zkvm/guests/Cargo.lock` graphs with `cargo audit` (partly known).
- **Priority:** P1 for `cargo-deny` sources/bans and the third_party verification script (S). P2 for `cargo-vet` with imports (M).

### T-12 Coverage and mutation testing are not measured
- **Class:** Not implemented · **Severity:** medium · **Confidence:** high.
- **Evidence:** no `cargo-llvm-cov`, no `cargo-mutants` and no coverage artifacts anywhere (grep; `.gitignore` ignores `/coverage/`) **[source-read]**.
- **Why:**
  - T-3 shows that tolerance-based tests leave consensus arithmetic unpinned;
  - `cargo-mutants` finds such gaps mechanically;
  - line and branch coverage of `consensus`, `tx/src/validate.rs`, `chain/src/manager.rs` and `mempool.rs` would show which rejection paths no test reaches (for example, which `BlockError` and `HeaderError` variants are never produced).
- **Fix:**
  - run `cargo mutants -p blacksilk-consensus` now (a small crate with fast tests), then `tx/src/validate.rs`, `chain/src/mempool.rs` and `crypto/src/{clsag,bulletproofs_plus}.rs` with `--in-diff` in CI for changed consensus files;
  - add `cargo llvm-cov` (Rust-native instrumentation) weekly with a published report.
- **Rule:** every surviving mutant in consensus code gets a test or a written "equivalent mutant" note.
- **Priority:** P1 (S to run; M to triage).

### T-13 Suite structure and CI cadence
- **Class:** Complete but requires further testing · **Severity:** low · **Confidence:** medium.
- **Evidence:** one monolithic `cargo test --release --workspace` takes 35–68 min in CI [web] and 30–40 min locally (review-package §3). There is no fast tier, no `cargo-nextest` (process-per-test isolation, retries that expose flakiness, JUnit output, sharding), no test-time budget and no flaky-test tracking.
- **Fix:**
  - tier 0 (< 5 min: unit tests, codec, consensus vectors, fmt/clippy) on every push;
  - tier 1 (the current suite) on every push to `rebuild/core` and on PRs;
  - tier 2 nightly (fuzz corpus + campaign, labnet 1–6 h, mutants-in-diff, coverage, aarch64, overflow-checked test run);
  - tier 3 pre-release (72 h labnet, the long fuzz campaign, the reference RandomX vector file, a reproducible-build comparison).
- **Priority:** P2 (S).

### T-14 Stale or overstated statements about testing (for A16b)
- **Class:** Accepted limitation → fix the docs · **Severity:** info.
  - AUDIT.md:1186 says "**not yet run:** CI runs on GitHub after a push". It has run: #65–#74 are green [web]. The launch checklist G3 says "all four jobs"; there are six now.
  - AUDIT.md:297 and transactions.md:1017: the `getrandom` reason for avoiding proptest is stale (T-4).
  - G9 and review-package §3 cite fuzz executions without saying that overflow checks were off (T-2).
  - labnet is described as "long-duration" (`tools/labnet/Cargo.toml` description); the recorded runs are ≤ 62 min.

### T-15 Privacy testing (strategy-level)
- **Class:** Partially implemented · **Severity:** medium · **Confidence:** medium.
- **Good:** P-5 is statistical, pre-registered in its thresholds and reproducible.
- **Missing** (as automated, repeatable tests):
  - **Dandelion++ linkability simulation:** in a simulated network of 50–500 nodes (turmoil, T-5), a spy controlling a fraction f of nodes runs a first-spy or first-fluff estimator. Measure precision against the theoretical bound for the implemented stem parameters. This would also catch regressions like the known "local tx fluffed with no stem peer".
  - **Decoy-selection distribution test:** a KS test of selected ring member ages against the target distribution, over many draws.
  - **Wire-size and timing fingerprinting tests** for the node's responses.
  - A P-5-style campaign re-run automatically (small n) on every change to `zk/` or `zkvm/` layout code.
- **Priority:** P1 for the decoy KS test and the fluff-without-stem regression (S). P2 for the Dandelion simulation (M, depends on DST).

---

## 3. The 13 questions per subsystem

| # | Testing strategy | Fuzzing | CI/CD | Reproducibility | Supply chain |
|---|---|---|---|---|---|
| 1 Implemented | 731 tests, seeded mutation tests, labnet, pins, P-5 | 9 cargo-fuzz targets, seeds, ~531 M exec recorded | 6 jobs, SHA-pinned, read-only token, green | guest ELF rebuild (Windows), lockfiles tracked, fat LTO | cargo-audit, A14 manual review, no git deps |
| 2 Correct/well designed | `now` injected in consensus/chain; differential kernel; contract determinism/rollback/replay oracles; honest limits stated | `kernel_diff` and `contract_sequence` are exemplary differential/stateful targets; ASan | pinned toolchains; artifacts-based failure detection intent | the program-id pin design | patch documented with removal criteria |
| 3 Incomplete | property framework; consensus vectors | stateful targets, verifier target | nightly tier, aarch64, labnet | node/miner binaries; toolchain file | vet/deny, third_party verification |
| 4 Fragile | wall-clock P2P tests with sleeps | corpus on one machine; `--release` without `-a` | smoke from seeds only (and the known pipe-masking) | Windows path in the kernel (known); floating Docker tag | caret pins (known) |
| 5 Exploitable | malleability classes invisible to round-trip oracles (T-1) | overflow invisible (T-2) | — | an operator building with another toolchain is unverifiable | unreviewed lockfile bumps |
| 6 Inefficient | a 35–68 min monolithic suite | byte fuzzing of 2 MB proofs (21 exec/s) | no caching of target/ or corpora | — | — |
| 7 Does not scale | example-based fork-choice tests | manual campaigns | one job per concern, no sharding | — | manual review per bump |
| 8 Missing | DST, model checking, mutation, coverage | verifier, P2P state machine, mempool, header chain, batch==single | release workflow, signed tags | SBOM, attestations, second builder | cargo-vet, cargo-deny |
| 9 Redesign | `net.rs` → sans-IO core + IO shell | structure-aware (`arbitrary`) inputs | tiered pipeline | release pipeline | — |
| 10 Innovate | stateright model of H1 fork choice; apfloat FPU oracle; conformance suite as a public artifact | non-malleability oracle as a standard for every signed or proved object | mutants-in-diff gate on consensus paths | two-builder reproducibility on every tag | `cargo vet` imports from ZcashFoundation/Google/Mozilla |
| 11 Before testnet | T-2 re-run, T-3 vectors, T-1 oracles, signed tag + pinned toolchain/Docker | T-1/T-2 targets for the verifier and tx | overflow-checked nightly run | toolchain file, pinned Docker | cargo-deny sources/bans |
| 12 Deferrable | full DST, Guix-level reproducibility, cargo-vet full | OSS-Fuzz application | self-hosted soak runners | bit-for-bit multi-builder | crev |
| 13 Never change | — | — | — | — | — |

**What should never be changed** (changing it adds risk without enough benefit):
- The **sans-IO shape of `consensus` and `chain`**: `now` passed in, a PoW function behind a trait (`Arc<dyn PowFunction>`). It is what makes the consensus core testable and simulatable. Do not add clock or OS-RNG reads there.
- **Consensus pins as failing tests** (genesis ids, program ids, Poseidon2): extend them, never loosen them to "tolerance" asserts.
- **Keeping `fuzz/` in a separate workspace** with its own lock, so the libFuzzer C++ never enters product builds (the pure-Rust policy).
- **`panic = "unwind"`** in the release profile, while the verifier relies on `catch_unwind`. Note that libfuzzer-sys installs an aborting panic hook, so the fuzz targets are *stricter* than production. Keep that.
- **SHA-pinned actions and the read-only token.**

---

## 4. Target test pyramid for BlackSilk

| Layer | Purpose | Tooling (pure Rust unless noted) | State |
|---|---|---|---|
| L0 Static | fmt, clippy `-D warnings`, `forbid(unsafe_code)` grep, cargo-deny, cargo-audit | built-in, cargo-deny | mostly present |
| L1 Unit + **conformance vectors** | every consensus function pinned to spec-derived vectors | `#[test]` + JSON vectors | vectors missing (T-3) |
| L2 Property | LWMA, MTP, fork choice, mempool, codecs, batch==single | `proptest` (fixed seed in CI) | seeded loops only (T-4) |
| L3 Differential | native/guest kernel; full/light RandomX; **reference RandomX vectors**; **apfloat FPU**; batch/single BP+ | in-tree + offline generator | partial (T-8) |
| L4 Mutation / coverage | test-suite adequacy for consensus code | `cargo-mutants`, `cargo-llvm-cov` | none (T-12) |
| L5 Coverage-guided fuzz | decoders + **stateful** + **verifier**, with overflow checks and non-malleability oracles | cargo-fuzz (libFuzzer, test-only C++), `arbitrary` | decoders only (T-1, T-2, T-6) |
| L6 Model checking | fork choice / H1 / restart replay; LWMA bounds | `stateright`, `kani` | none (T-5) |
| L7 Deterministic simulation | multi-node P2P with seeds, faults, adversaries, privacy spies | turmoil (or madsim) on a sans-IO core | none (T-5) |
| L8 Multi-process lab | real binaries, partitions, **kill/restart, skew, adversary**, supply | labnet | honest-only (T-9) |
| L9 Soak / multi-machine | 72 h, ≥ 1 seed epoch, resource trends | labnet + real machines (G5) | not started |
| L10 Release | reproducible, signed, attested binaries + SBOM | cargo auditable, cyclonedx, attestations | none (T-10) |

---

## 5. Prioritized plan

For every item, the table gives: **why** · security · privacy · performance · complexity · consensus impact · testnet identity · difficulty · priority.

| # | Recommendation | Why | Security | Privacy | Perf. | Complexity | Consensus | New identity? | Diff. | Prio |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | Re-run coverage-guided fuzzing with `-O -a` (debug assertions and overflow checks); change `run_campaign.sh`; record it as a separate evidence row; add a nightly `cargo test` with `-C overflow-checks=on -C debug-assertions=on` in release | recorded fuzz evidence does not cover overflow (T-2) | high: finds wrap bugs in decoders and accounting | none | fuzz ~10–20% slower | low | none (may reveal consensus-relevant wraps: those then go through the change process) | no | S | **P0** |
| 2 | Consensus conformance vectors: LWMA, MTP/FTL, seed schedule, emission table, merkle roots, header/tx/block ids, address encodings, key image/stealth/hash-to-point, BP+/CLSAG accept/reject, one stored PX proof (verify=ok) plus its id; JSON under `consensus/tests/vectors/`, referenced by the specs | silent-hard-fork protection during parallel refactoring (T-3); a base for a second implementation | high | none | none | low | none (pins current behaviour); any change becomes explicit | no | M | **P0** |
| 3 | Non-malleability oracle: for PX proofs, CLSAG, BP+, tx and block, a structure-aware test "a mutant that validates has the original bytes", per field; plus BP+ `batch_verify == all(verify)` over random mixes | the class of M1/M2 is invisible to current oracles (T-1) | high | medium (tx-id malleability hurts wallet tracking) | none | low–medium | none (tests); any hit is a consensus fix | no | M | **P0** |
| 4 | Signed annotated release tag; root `rust-toolchain.toml` (1.98.1); Dockerfile pinned by version and digest; `.dockerignore`; SECURITY.md lists the signing-key fingerprint; readiness report links the tag's CI run | operators must be able to verify what they run (T-10) | medium | none | none | low | none | no | S | **P0** |
| 5 | Run `cargo-mutants` on `consensus`, then `tx/validate.rs`, `mempool.rs`, `clsag.rs`, `bulletproofs_plus.rs`; triage survivors; add `--in-diff` to CI for consensus paths | measures test adequacy mechanically (T-12) | high | none | CI time (+ minutes) | low | none | no | S–M | **P1** |
| 6 | `proptest` (fixed seed in CI, random nightly) for LWMA, MTP, fork choice (with ties and invalidation), mempool, codecs; fix the stale docs | shrinking and regression files; properties instead of examples (T-4) | medium–high | low | none | low | none | no | M | **P1** |
| 7 | stateright model of the H1 fork choice (most-work body-complete chain), invalidation and restart replay; `kani` harnesses for `next_difficulty`/`median` panic-freedom and bounds | the rule is being changed now; ordering bugs are the known failure mode | high | none | none | medium | none (verifies a rule) | no | M | **P1** |
| 8 | New fuzz targets: ZK verifier (structure-aware, with non-malleability and time oracles), CLSAG/BP+ verify, HeaderChain DAG, ChainManager block/reorg/restart sequences, mempool sequences, store `parse_record` | covers the remote surfaces (T-6), ZK-F4 cost | high | low | none | medium | none | no | M | **P1** |
| 9 | Corpus: minimized corpora in a separate repository or release assets; replay in CI on each push; nightly 1–2 h campaign (ClusterFuzzLite batch mode or cron) with corpus caching; crash → regression test rule | durable and reproducible fuzz evidence (T-7) | medium | none | CI minutes | low | none | no | S–M | **P1** |
| 10 | RandomX: aarch64 CI job; `rustc_apfloat` differential property tests of `fpu.rs` per op and rounding mode; an offline reference vector file (≥ 10⁵ hashes, ≥ 16 keys) checked nightly | the soft FPU is the rarest-path consensus code (T-8) | high (split avoidance) | none | none | medium | none | no | M | **P1** |
| 11 | Labnet: kill -9/restart during sync and reorg, ±FTL clock skew, RSS-trend check, a 6 h nightly on a large runner; 72 h and ≥ 1 real seed epoch before launch | recovery and time-edge coverage (T-9); gate G5 | medium | none | none | low | none | no | S–M | **P1** |
| 12 | `cargo-deny` (sources: crates.io only; bans: `cc`/`bindgen`/`*-sys` outside `fuzz/`; licenses); a script verifying `third_party/` = crates.io 0.7.0 + the documented hunks; audit the fuzz and guests locks | mechanical enforcement of pure-Rust and provenance (T-11) | medium | none | none | low | none | no | S | **P1** |
| 13 | Privacy regression tests: decoy-age KS test; "local tx never fluffs without a stem" test; small-n P-5 re-run on zk/zkvm layout changes | privacy claims backed by repeatable tests (T-15) | low | high | CI minutes | low | none | no | S | **P1** |
| 14 | Release workflow: x86_64 and aarch64 Linux binaries, `--locked`, `--remap-path-prefix`, `SOURCE_DATE_EPOCH`, signed `SHA256SUMS`, GitHub artifact attestations, CycloneDX SBOM, `cargo auditable`; a second builder compares hashes | verifiable binaries (T-10) | medium | none | none | medium | none | no | M | **P1** (before a public testnet with outside operators), else P2 |
| 15 | Tiered CI (tier 0 < 5 min, tier 1 suite, tier 2 nightly, tier 3 pre-release); `cargo-nextest` with JUnit and flaky detection; `cargo-llvm-cov` weekly report | feedback speed; visibility (T-13, T-12) | low | none | faster feedback | low | none | no | S | **P2** |
| 16 | Sans-IO refactor of the `net.rs` peer logic, and turmoil-based deterministic multi-node simulation (partitions, delays, adversaries, Dandelion spy estimator) | replayable interleaving bugs; privacy measurement (T-5, T-15) | high | high | none | high | none (policy code) | no | L | **P2** (start the design before the testnet; full use after the trial) |
| 17 | `cargo-vet` with imported audits (Mozilla, Google, ZcashFoundation, Bytecode Alliance); owner audits the remainder | a per-version audit trail for the lockfile | medium | none | none | medium | none | no | M | **P2** |
| 18 | Bit-for-bit reproducible builds across independent builders (Guix-like) and a platform-neutral guest build (known kernel-id issue: that one is CONSENSUS, v3) | the mainnet trust model | medium | none | none | high | CONSENSUS only for the guest part | yes, only if the kernel is rebuilt platform-neutrally (fold it into the planned v3) | L–XL | **P3** (fold the guest rebuild into v3 if v3 happens anyway) |
| 19 | Publish the conformance suite (item 2) as a versioned artifact with a runner a second implementation can use; apply to OSS-Fuzz once there is a user base | ecosystem, independent implementations | medium | none | none | medium | none | no | M | **P3** |

**Suggested order for the next pass:** 1 → 2 → 3 → 4 (all small, P0) · then 5, 12, 10 (aarch64 and apfloat first) · then 6, 7, 8, 9, 11, 13 · then 14 before outside operators join.

---

## 6. Residual risks this report does not resolve

- No amount of internal testing replaces independent review. **No part of BlackSilk has been externally reviewed**, per the owner policy.
- Tests encode the authors' reading of the specs. Conformance vectors (item 2) help only if at least the arithmetic vectors are **re-derived by hand from the spec formulas**, not copied from the code's output. Otherwise they pin bugs.
- My mutant predictions (T-3) are **[math, source-read]**, not run. They should be confirmed by item 5.
- The GitHub Actions results are **[web]** as read on 2026-09-27; I did not inspect the job logs. The known pipe-masking in fuzz-smoke means a green fuzz job is not evidence of fuzzing.

---

## Sources
- cargo-fuzz 0.13.2 source (local registry): `src/options.rs:62`, `src/project.rs:259`; repository https://github.com/rust-fuzz/cargo-fuzz
- turmoil, deterministic simulation for tokio: https://github.com/tokio-rs/turmoil · https://tokio.rs/blog/2023-01-03-announcing-turmoil · https://s2.dev/blog/dst · https://notes.eatonphil.com/2024-08-20-deterministic-simulation-testing.html
- madsim: https://github.com/madsim-rs/madsim
- FoundationDB simulation testing: https://apple.github.io/foundationdb/testing.html ; TigerBeetle VOPR: https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/internals/vopr.md
- stateright model checker: https://github.com/stateright/stateright · https://docs.rs/stateright/latest/stateright/
- Kani Rust model checker: https://github.com/model-checking/kani
- rustc_apfloat (pure-Rust APFloat, all IEEE rounding modes, no host FP): https://github.com/rust-lang/rustc_apfloat · https://docs.rs/rustc_apfloat ; ieee-apsqrt: https://lib.rs/crates/ieee-apsqrt
- RandomX reference and tests: https://github.com/tevador/RandomX
- GitHub arm64 hosted runners (public repositories GA; private since 2026-01): https://github.blog/changelog/2025-08-07-arm64-hosted-runners-for-public-repositories-are-now-generally-available/ · https://github.blog/changelog/2026-01-29-arm64-standard-runners-are-now-available-in-private-repositories/
- ClusterFuzzLite (continuous fuzzing in CI, PR and batch modes, Rust supported): https://github.com/google/clusterfuzzlite · https://google.github.io/clusterfuzzlite/running-clusterfuzzlite/github-actions/
- Bitcoin Core fuzz corpora repository (qa-assets): https://github.com/bitcoin-core/qa-assets ; Bitcoin Core fuzzing doc: https://github.com/bitcoin/bitcoin/blob/master/doc/fuzzing.md
- Zcash test vectors (conformance vectors used by independent implementations): https://github.com/zcash/zcash-test-vectors · https://github.com/QED-it/zcash-test-vectors ; cross-implementation conformance suite proposal: https://forum.zcashcommunity.com/t/zcg-307-cross-implementation-conformance-test-suite-for-zcash-zips/55814
- Ethereum consensus spec tests: https://github.com/ethereum/consensus-spec-tests
- cargo-mutants: https://mutants.rs · https://github.com/sourcefrog/cargo-mutants ; cargo-llvm-cov: https://github.com/taiki-e/cargo-llvm-cov ; cargo-nextest: https://nexte.st
- cargo-vet: https://mozilla.github.io/cargo-vet/ ; cargo-crev: https://github.com/crev-dev/cargo-crev ; cargo-deny: https://github.com/EmbarkStudios/cargo-deny
- cargo-auditable: https://github.com/rust-secure-code/cargo-auditable ; CycloneDX for Cargo: https://github.com/CycloneDX/cyclonedx-rust-cargo
- GitHub artifact attestations / SLSA: https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations · https://slsa.dev
- Reproducible builds, SOURCE_DATE_EPOCH: https://reproducible-builds.org/docs/source-date-epoch/ ; Bitcoin Core Guix builds: https://github.com/bitcoin/bitcoin/tree/master/contrib/guix
- proptest: https://github.com/proptest-rs/proptest
