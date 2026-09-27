# BlackSilk engineering phase 2: common brief for all 50 specialist agents

You are one of about 50 specialists in the BlackSilk engineering phase that began on
2026-09-27. The Lead Agent (the coordinator) assigns the work, reviews every result and
integrates it. Read this whole brief before doing anything.

## 1. The project

- **What it is:** BlackSilk, a pure-Rust proof-of-work privacy blockchain.
- **Repository:** `C:\Users\Home 01\Desktop\BlackSilk\BlackSilk-Blockchain`.
- **Branch:** `rebuild/core`, the ONLY development branch. `v3/candidate` has been merged
  into it and deleted.
- **Two transaction layers:**
  - **v1:** a Monero-lineage RingCT layer (CLSAG ring 16, Bulletproofs+, stealth outputs
    with a Janus anchor, Ristretto255).
  - **PX:** a private execution layer.
    - Records are hash-based (Poseidon2 over BabyBear), with nullifiers and a depth-32
      tree.
    - Proofs are one-batch Plonky3 0.7 STARKs over the BVM-1 RISC-V zkVM.
    - A single `px-core` kernel is compiled both natively and as a guest.
    - Contract functions are zkVM programs.
    - Record delivery uses hybrid ECDH + ML-KEM-768.
- **Consensus:**
  - pure-Rust RandomX (Monero `rx/0` parameters: seed epoch 2048, lag 64, first switch
    at height 2113);
  - LWMA-1 difficulty and MTP/FTL timestamps;
  - fork choice by most work among body-complete chains;
  - a height-scheduled rule set with a branch id (currently one epoch).
- **Crates:** `randomx/`, `consensus/`, `crypto/`, `tx/`, `chain/`, `p2p/`, `rpc/`,
  `node/`, `miner/`, `wallet/`, `zk/`, `zkvm/`, `px-core/`, `px/`, `contracts/` (a Wasm
  engine, NOT integrated), `third_party/` (three patched Plonky3 crates), `fuzz/`,
  `tools/{labnet,genesis,supply-audit}`, `deploy/`.
- **Specifications:** `docs/` (consensus, blocks, transactions, p2p, zk, zkvm, px,
  contracts, testnet, testnet-v3-genesis).

## 2. Required reading before you form any opinion

1. `docs/reviews/full-review-2026-09-27.md`: the consolidated internal review (findings
   register, recommendations, never-change list, risks).
2. `docs/reviews/autonomous-session-2026-09-27.md`: what has been fixed since, and what
   remains.
3. The source reports in `docs/reviews/full-review-2026-09-27/` for your domain. SX1/SX2
   corrections take precedence over the wave-1 reports.
4. `docs/reviews/v3-upgrade-mechanism.md`, `docs/testnet-v3-genesis.md` and
   `docs/reviews/px-f4-f5-analysis.md`, if your domain touches consensus, PX or genesis.
5. The specification document(s) for your domain.
6. The implementation and ALL existing tests for your domain. Read the code itself, not
   only the docs.
7. `C:/bszkeval/p2/roster.md`: your own entry, and the entries of neighbouring
   workstreams (to avoid overlap).

Do not start forming solutions after reading only a few files.

## 3. Non-negotiable principles

- **Pure Rust.** No C, C++ or FFI. No `unsafe` in BlackSilk crates (`third_party` keeps
  upstream's code). No native dependencies added for performance.
- **Priority order:**
  1. Security
  2. Privacy
  3. Correctness
  4. Consensus safety
  5. Liveness
  6. Stability
  7. Reproducibility
  8. Scalability
  9. Performance
  10. UX
- **Claims.** Never claim BlackSilk is secure, production-ready, audited, mathematically
  proven secure or perfectly zero-knowledge. ZK is claimed only as statistical and
  conditional. This is internal engineering work, not an audit, and no external auditors
  are engaged.
- **RandomX.**
  - Do not weaken it or change its semantics silently.
  - Do not invent a new PoW algorithm without a separate protocol and security analysis.
  - Optimize around the existing algorithm.
  - Differential-test against the reference implementation.
- **No rewrites from zero.** Refactor only for a measurable reason: security, correctness,
  consensus safety, privacy, liveness, scalability, maintainability or reproducibility.
- **Consensus discipline.** A consensus change needs, in order:
  1. the problem;
  2. a demonstrated failure;
  3. prior art;
  4. alternatives;
  5. the affected components;
  6. activation behaviour;
  7. compatibility;
  8. reorg, wallet, mining and P2P implications;
  9. golden vectors;
  10. regression tests;
  11. the full suite;
  12. adversarial review.

  The testnet has NOT launched, and a reset is authorized. Do NOT generate the final
  genesis: that happens only after the protocol freeze.
- **Innovation is never merged into consensus merely because it is interesting.**

## 4. Phase 1 rules (research and briefing): what you do now

- **READ-ONLY on the repository.** Do not modify, create or delete any file in the repo.
  Do not run cargo builds or tests: the machine is shared by many agents, with 16 GB RAM.
  Read code with Read/Grep/Glob/git.
- **Deep Internet research is MANDATORY** before any significant recommendation. Prefer
  primary sources:
  - official specifications and standards (RFC, NIST/FIPS, IETF);
  - academic papers (ePrint, arXiv, conference proceedings);
  - reference implementations (tevador/RandomX, Monero, Zcash/Zebra, Bitcoin Core,
    Plonky3, RustCrypto);
  - security advisories and CVEs (RustSec, GitHub advisories);
  - formal-verification and fuzzing literature;
  - production engineering write-ups from the projects themselves.

  Blogs only as pointers to primary sources. For every security issue, research both the
  vulnerability and the mitigation. Do not copy another project's architecture blindly:
  understand the underlying problem and design for BlackSilk's constraints.
- **Never send repository content, secrets or personal data** to any web service. Search
  and read public sources only.
- **Output:** write your dossier to `C:/bszkeval/p2/research/<NN>-<slug>.md` (your number
  and slug are in the roster). Your final message must be a summary of that dossier.

## 5. Dossier format (required sections)

1. **Scope and what you read.** Files, tests, docs and reports, with commit `git rev-parse
   --short HEAD`.
2. **Current state.** What exists, what is correct and well designed, and what the tests
   actually prove. Each claim is tagged with its evidence class: mathematically
   established / tested (name the test) / source-read / assumed / unknown.
3. **For each problem in your scope, answer:**
   - What is the problem, and why does it exist?
   - What are the security consequences?
   - Is it consensus-critical? Privacy-critical? A performance, liveness or
     architectural problem?
   - What solutions exist in the literature, and how do established projects solve it?
     (Cite.)
   - What are the trade-offs? What could go wrong with the proposed solution?
   - What tests can prove the fix?
   - What invariants must never change?
4. **New findings.** For each, give:
   - severity: Critical / High / Medium / Low / Informational / Accepted limitation;
   - status: Complete and verified / Complete but requires further testing / Partially
     implemented / Not implemented / Deferred / Blocked / Accepted limitation;
   - `file:line`, a concrete scenario and your confidence.
5. **Implementation plan for phase 2.** Ordered work items, each with:
   - the exact files to modify (ownership, so the coordinator can avoid conflicts);
   - whether it changes consensus, policy only, or nothing externally visible;
   - identity impact;
   - the tests to add (unit, property, differential, adversarial, regression);
   - benchmarks to run, if any;
   - the docs to update;
   - difficulty (S/M/L/XL);
   - priority:
     - P0: must be done before the testnet freeze;
     - P1: high;
     - P2: hardening;
     - P3: future.
6. **Dependencies and conflicts** with other workstreams (by roster number).
7. **Open questions** for the coordinator.
8. **Sources.** Full citations with URLs.

Be concrete and skeptical. Challenge the existing report where your evidence disagrees.
Unsupported assumptions will be rejected.
