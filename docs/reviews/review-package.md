# Review package (for internal review passes, and for a future external reviewer)

Status: **2026-09-25, updated 2026-09-27. No external review has been engaged or completed**
(docs/reviews/review-status.md). Everything referenced here is internal work. The
package serves two purposes:
- it is the brief for the project's internal review passes;
- it is kept ready in case an external review is commissioned later.

It is **not** a testnet gate: the owner decided on self-reliant review on 2026-09-25.

## 1. What to review

The scope, priorities and the claims to confirm or refute are in
`docs/reviews/external-review-scope.md`:

| # | Area | Priority |
|---|---|---|
| 1 | Poseidon2 and the `Hk` constructions | Critical |
| 2 | Plonky3 as configured (soundness, hiding/ZK, transcript) and the three local patches | Critical |
| 3 | BVM-1 zkVM circuits | Critical |
| 4 | PX kernel and the function binding | Critical |
| 5 | PX consensus rules | Critical |
| 6 | Record delivery and contract-record distribution | High |
| 7 | Privacy and metadata, including P-5 (proof length) | High |
| 8 | Wallet PX and contract code | Medium |
| 9 | K4 reorganization-depth policy (provisional, testnet) | High |

### 1.1 The five critical areas and the expertise each needs

| # | Area | Main question | Expertise | Code |
|---|---|---|---|---|
| 1 | Poseidon2 and `Hk` | Are the parameters (BabyBear, width 16, standard rounds) and our domain-separated uses sound for collision and preimage resistance at ~124 bits? | Symmetric cryptanalysis (arithmetization-oriented hashes) | `px-core/src/hash.rs`, `px-core/src/record.rs`, `zkvm/src/air/poseidon.rs` |
| 2 | Plonky3 as configured, and the three patches | Is BS-ZK-2 sound at the claimed bits across the envelope, and statistically zero-knowledge as configured (a separate FRI mask per table, 4 random codewords, 4 salt elements, terminal blinding; docs/reviews/zk-coverage.md)? Do the patches only change lock scope? | STARK/FRI proof systems; Rust concurrency for the patches | `zk/src/config.rs`, `zk/src/params.rs`, `third_party/` |
| 3 | BVM-1 zkVM circuits | Do the 13 table kinds (12 plus the `BLIND` table; 13 to 23 tables per proof) and their buses, including the terminal-blinding bus `bvm/blind`, constrain exactly the interpreter's semantics, with no under-constrained column? | Arithmetization and circuit auditing (AIR, LogUp) | `zkvm/src/air/`, docs/zkvm.md |
| 4 | PX kernel and function binding | Does the kernel conserve value, and can a function approve or specify anything outside its own contract (`io_hash`)? | Protocol design, ZK application auditing | `px-core/src/{kernel,call}.rs`, `px/src/prove.rs`, docs/px.md |
| 5 | PX consensus rules | Do the node rules (nullifiers, anchors, the fee rule, the deploy registry, reorg undo) match the kernel's statement, with no double-spend or inflation path? | Blockchain consensus and state management | `tx/src/px.rs`, `tx/src/validate.rs`, `tx/src/state.rs`, `chain/` |

Areas 6–8 need applied cryptography (the delivery KEM combiner), privacy and metadata
analysis (P-5 to P-8), and Rust wallet review.

A qualified review therefore needs at least:
- a **cryptographer** for areas 1–2 and 6;
- a **ZK circuit auditor** for areas 3–4;
- a **consensus and implementation reviewer** for area 5 and the wallet;
- **privacy** expertise for area 7.

One firm may cover several of these.

**Out of scope unless agreed:** the v1 layer (RandomX, CLSAG, Bulletproofs+, stealth
outputs, P2P), which AUDIT.md R1–R6 cover, and the transparent contract engine
(docs/contracts.md).

## 2. The version under review

- **Repository:** `https://github.com/StickyFingaz420/BlackSilk-Blockchain`, branch
  `rebuild/core`.
- **Commit:** the owner fixes the exact commit when a review starts. The newest
  internally reviewed code is `5e667bd` (internal review rounds 1–4 and the gap
  analysis of completion-readiness-2026-09-26.md; `87278ac` added only that report);
  the hardening round from `7826289` onward is under internal review (AUDIT.md R14).
- **Toolchain:** Rust stable 1.98.1 (MSVC on Windows; any tier-1 host). The fuzz crate
  uses nightly.
- **Pinned dependencies:**
  - Plonky3 `=0.7.0`, with three patched files in `third_party/` (documented in
    `third_party/README.md`);
  - `ml-kem =0.3.2`.
- **Consensus identity:** the kernel program id `px/kernel.id`; the vault program id
  `px/vault.id`; the parameter set `BlackSilk/zk/BS-ZK-2`.

## 3. Reproducing the evidence

```sh
# Everything (about 40 min on 8 threads; proofs make it slow)
cargo test --release --workspace --no-fail-fast

# The two opt-in tests
cargo test --release -p blacksilk-randomx -- --ignored          # ~2.3 GiB RAM
BLACKSILK_STRESS_ROUNDS=10 cargo test --release -p blacksilk-zkvm --test stress -- --ignored

# Security parameters over the whole envelope
cargo run --release -p blacksilk-zk --example param_study

# Proof size breakdown, and the P-5 campaign
cargo run --release -p blacksilk-px --example proof_breakdown
cargo run --release -p blacksilk-px --example proof_length_campaign -- 50 30 out.csv

# Coverage-guided fuzzing (nightly, cargo-fuzz)
cd fuzz && cargo run --release --bin seeds && ./run_campaign.sh 900

# Supply chain
cargo audit
```

**Recorded results** (2026-09-25; rows marked 2026-09-26 or 2026-09-27 were updated
then).
- **Environment** for every row unless stated: Windows 10 Pro 19045, x86_64, 8
  logical CPUs, Rust 1.98.1 MSVC, release build. Fuzzing: nightly MSVC with
  AddressSanitizer.
- **Independently verified:** no row has been.

| Evidence | Command | Duration | Result | Limitations |
|---|---|---|---|---|
| Full test suite | `cargo test --release --workspace --no-fail-fast` | 30–40 min | 2026-09-26 (AUDIT.md R13): 423 passed, 0 failed, 2 ignored (opt-in). The hardening round adds tests (about 450 in total at `7826289`) | One platform. Tests encode our own understanding of the specs |
| RandomX full mode | `cargo test --release -p blacksilk-randomx -- --ignored --nocapture` | 2026-09-27: dataset build about 179 s per key with 8 threads, under load | 2026-09-25 and 2026-09-27: all 5 official vectors in full mode, and full/light agreement on 1,024 random inputs; full mode about 100 ms per hash per thread, light about 750 ms (under load: the full suite ran at the same time; idle figures to be re-measured) | One machine. The CI job `randomx-full` has not yet run on GitHub |
| Concurrency stress | `BLACKSILK_STRESS_ROUNDS=10 … --test stress -- --ignored` | 909 s | 80 concurrent proofs, no hang | No hang observed is not proof that none can occur (ZK-F21 was not reproducible on demand) |
| Upstream Plonky3 suites with the patches | `cargo test` in the patched crates (third_party/README.md) | not recorded | 208 of 208 pass | Upstream tests were not written for concurrency hangs |
| Security parameters | `cargo run --release -p blacksilk-zk --example param_study` | < 1 min | ≥ 123 bits (Johnson), ≥ 105 (unique decoding) | Our calculator: review area 2 |
| Proof sizes and timings | `cargo run --release -p blacksilk-px --example proof_bench` | 2 × 5 proofs of each kind, idle | 2026-09-26 (AUDIT.md R13): transfer 2,178,213–2,180,408 B, 44.6–45.2 s to prove, 0.207–0.212 s to verify; vault 2,687,952–2,688,822 B, 52.7–53.0 s, 0.254–0.265 s; peak memory 3,771 MB | One machine. The widest shape (kernel plus two functions) is not measured |
| P-5 campaign | `… --example proof_length_campaign -- 50 30 out.csv` | 13,493 s (2026-09-26, docs/evidence/p5-2026-09-26b/) | 260 proofs. Non-authentication parts byte-identical per shape (1,811,565 B transfer, 2,359,622 B vault); 14 pairwise tests, p from 0.107 to 0.965, none significant | 260 proofs detect only large effects; privacy-review §3a.5 |
| Coverage-guided fuzzing, first campaign | `fuzz/run_campaign.sh 900` | 15 min per target | 144,432,805 executions, 0 crashes | Short for the slow targets |
| Coverage-guided fuzzing, long campaign | per target, AUDIT.md ZK-8 | 10.5 h total | 386,839,603 executions, 0 crashes | Slow targets reached < 0.5 M executions |
| Contract-engine fuzzing, extended | `wasm_module` 6 h and `contract_sequence` 4 h | 10 h | 0 crashes (AUDIT.md) | Determinism is checked between two executor instances in one process only. **Not testnet evidence:** the Wasm engine is frozen research, not integrated (D22; dossier 29 W-9) |
| Multi-process network with PX | `blacksilk-labnet … --px-every-mins 4` (docs/evidence/labnet-2026-09-25) | 62 min | `checks_passed`; supply conserved; restored wallets match | One machine, 5 processes, simulated latency |
| Reset rehearsal | the same, `--network testnet`, new identity | 30 min | `checks_passed`; an old-identity node is refused | No transactions (coinbase maturity) |
| Supply chain | `cargo audit` | < 1 min | 0 vulnerabilities; 1 unmaintained (`paste`) | Advisory database only; no code review of dependencies |

## 4. Evidence index (internal)

| Topic | Where |
|---|---|
| Findings and fixes, chronologically | AUDIT.md R8 to R13 (ZK-F1 to ZK-F30), R14 (hardening round, being written) |
| ZK security review, attack table | docs/reviews/zk-security-review.md |
| Privacy review, every channel; P-5 in detail (§3a); P-6, P-8, query positions, proof size (§3b) | docs/reviews/privacy-review.md |
| Every assumption, with its status | docs/reviews/assumptions.md |
| K4 policy and its analysis | docs/reviews/k4-reorg-policy.md |
| Wallet error handling; P-9 (re-spending with a new ring) | docs/reviews/wallet-review.md; privacy-review.md §3c |
| Reviewer candidates and selection criteria | docs/reviews/reviewer-candidates.md |
| Dependencies, patches, supply chain | docs/reviews/dependency-review.md, third_party/README.md |
| Query policy and the security calculator | docs/reviews/query-policy.md; `zk/src/params.rs` |
| Proof size and aggregation | docs/reviews/aggregation-study.md |
| Specifications | docs/zk.md (architecture; parts marked "design, not implemented"), docs/zkvm.md, docs/px.md |
| Constraint mutation tests | `zkvm/tests/{alu,vm,multi}.rs` (231,120 ALU; 37,616 CPU and memory; 2,500 Poseidon2; 180 public-copy) |
| Kernel rejection cases | `px/tests/kernel.rs`, `px/tests/unified.rs` |
| Consensus tests | `tx/tests/px_consensus.rs`, `tx/tests/adversarial.rs`, `chain/tests/manager.rs` |
| Network tests | `p2p/tests/network.rs` |
| Wallet end to end | `wallet/tests/e2e.rs` |
| Fuzzing | `fuzz/`, AUDIT.md ZK-7 and ZK-8 (about 531 million coverage-guided executions over both campaigns, no crash) |
| Measurements | `docs/evidence/` |

## 5. Where the project itself is least certain

These are the questions where outside judgement would matter most, if a reviewer
were engaged (none is; meanwhile they are the priorities of the internal passes):
1. **Zero knowledge of Plonky3's hiding mode as configured**, which the project claims
   only as statistical and conditional (zk-coverage.md §3: many tables of mixed
   heights, the leakage of LogUp arguments, multi-phase traces). We rely on it for
   every private property.
2. **The security calculator** behind "≥ 123 / ≥ 105 bits", and whether the envelope
   bounds (2^22 rows, 6,000 honest columns, 15,709 adversarial columns under
   `MAX_PROOF_BYTES`) are enforced everywhere the verifier sees a shape. The
   calculator counts one batched function per column; with two opening points the true
   count can reach about twice that (31,418), still inside the 65,536 the test covers
   (zk.md §9.3).
3. **Poseidon2 over BabyBear, width 16, with the standard round numbers,** used for
   both the proof system and every PX commitment and nullifier (no extra rounds,
   decision DR-4).
4. **The statement digest** (ZK-F13): that everything the verifier supplies as
   periodic columns is bound into the transcript before any commitment.
5. **The kernel's contract rules** and the `io_hash` binding: whether a function can
   approve or specify anything outside its own contract.
6. **The delivery combiner:** an X-Wing-style hybrid, with a nonce of zero under fresh
   keys.
7. **P-5:** the argument that proof-length variation carries no witness information
   (privacy review §3a).
8. **The three Plonky3 patches:** that they change nothing but lock scope.

Every assumption the project relies on, with its status, is listed in
`docs/reviews/assumptions.md`. The items marked **External** there are the ones this
review is asked to confirm or refute. The unresolved ones:
- **Z1–Z3, Z5–Z7, Z9, Z10:** proof-system, hash and circuit assumptions; no one outside
  the project has examined them.
- **P1:** P-5, supported by our measurement and reasoning only.
- **P4 and N4:** they depend on user behaviour and on untuned Dandelion++ parameters.
- **K4:** no reorg-depth limit (a documented policy): a hash-power majority can rewrite history.

## 6. Known limitations (not findings)

- Proof size is about 2.2 MB (transfer) and 2.7 MB (vault call), so 3 PX
  transactions fit per block (aggregation-study.md). The widest shape (kernel plus two
  functions) has not been measured against `MAX_PROOF_BYTES` (4 MiB); an unmeasured
  estimate is about 3.0–3.3 MB.
- The reference vault is a demonstration contract: no timeout, no refund, not
  trustless (docs/px.md §13.4).
- CI passes on GitHub (first run 2026-09-25, commit `d6534c3`; later commits through
  `87278ac`, runs #69–#74). `7826289` is unpushed, and its new jobs `guests` and
  `randomx-full` have never run on GitHub. CI is not a substitute for review.
- There is no reorg-depth limit or checkpoint, by policy (docs/consensus.md §8; assumptions.md K4).
- The P-6 and P-8 residual risks are analysed in privacy-review.md §3b and not
  mitigated further.
- The wallet keeps every commitment. Contract records addressed to a wallet before its
  restore height are not recovered from the seed.

## 7. Deliverables requested

See external-review-scope.md §4:
1. findings with severity and reproduction;
2. an explicit opinion on each critical claim;
3. an opinion on P-5 and on the query policy;
4. what was not covered.

The project will record every finding and its resolution in AUDIT.md and link the
report.
