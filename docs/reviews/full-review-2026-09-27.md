# BlackSilk full-project review, 2026-09-27: consolidated report

> Historical record (2026-09-27). Superseded where it conflicts with the code: the header is 172 bytes (output-root commitments, f5daa0e) and the PoW input is the 47-byte mining blob with the nonce at byte 39 (921fdd5); RandomX uses BlackSilk's Argon2 salt "BlackSilk/RandomX/v1", not Monero's rx/0 salt (RX-SALT, 3e3e9ca); the ZK parameter set is BS-ZK-3 (73372e9; BS-ZK-4 pending); the v3 candidate was merged into `rebuild/core` in 9e422d8. Current: [docs/consensus.md](../consensus.md), [docs/STATUS.md](../STATUS.md).

**Internal review. Not an audit.** No external auditors were engaged, and none are planned (owner policy, docs/reviews/review-status.md). Nothing in this report states or implies that BlackSilk, or any component of it, is secure, audited, proven, production-ready or perfectly zero-knowledge. Zero knowledge is claimed only as **statistical and conditional**, under the conditions in docs/reviews/zk-coverage.md §3.

- **Report writer:** consolidation agent. Read-only on the repository; no builds, no tests run by this writer.
- **Inputs:**
  - the common brief (`C:/bszkeval/review-brief.md`) and its classification scheme;
  - 16 subsystem reviews R1–R16, 4 innovation reports I1–I4 and 2 senior cross-reviews SX1–SX2 (`C:/bszkeval/review/`);
  - `C:/bszkeval/v3-plan.md` and `C:/bszkeval/coordination.md`;
  - the git history `87278ac..origin/rebuild/core` (30 commits) and `origin/rebuild/core..origin/v3/candidate` (4 commits), read commit by commit, plus a few targeted `git grep` checks of the current tree;
  - the coordinator's post-merge test logs in `C:/bszkeval/` (`after-a20-a21.log`, `after-a8.log`, `after-h1.log`, `tx-after-a4b.log`, `labnet-p2pfix.log`, `seedrun.log`).
- **Precedence rule:** where SX1 or SX2 corrects a wave-1 finding, the correction is used here.
- **Branch state when this report was written:**
  - `origin/rebuild/core` = `54c4827` (pushed). The local `rebuild/core` is one commit ahead (`e4a5634`, a Docker/doc change, unpushed). The brief's statement that nothing after `87278ac` was pushed is out of date.
  - `origin/v3/candidate` = `cc39795` (4 CONSENSUS commits). Its merge base with `rebuild/core` is `cf07324`, **24 commits behind** the current `rebuild/core`. It must be rebased before review.
  - Active agent worktrees with no commits yet beyond `54c4827`: `a24-p2p3`, `a25-pxhedge`, `a26-wallet2`, `a27-supply`, and two v3 candidate worktrees (one holds staged, uncommitted changes). Their scope is inferred from their names and the coordination log; their work is **not** counted as done anywhere in this report.

**Evidence classes used in this report** (the brief's): mathematically established / tested (named test) / source-read / assumed / unknown. Each claim cites the report that makes it (R1…R16, I1…I4, SX1, SX2). "Fixed in `<commit>`" means that the commit message states the fix and names tests; this writer did not rerun those tests. Where the coordinator's logs show the tests passing after the merge, that is noted. Where that evidence is thin, the register says "claimed fixed in `<commit>`, verify".

---

## Contents

1. Executive summary
2. Method
3. Per-subsystem assessment
4. Findings register
5. Recommendations (P0–P3)
6. v3 identity bundle
7. Innovation
8. What should never change
9. Open risks and accepted limitations
10. Next steps

---

## 1. Executive summary

### 1.1 What the system is

BlackSilk is a pure-Rust proof-of-work privacy blockchain with two transaction layers:

- **v1 (payments layer):** Monero-lineage RingCT. CLSAG rings of 16, aggregated Bulletproofs+, stealth outputs with a Janus-style anchor, and Ristretto255 throughout.
- **PX (private execution layer):** hash-based records (Poseidon2 over BabyBear), a nullifier set and a depth-32 commitment tree, proven by a one-batch Plonky3 0.7 STARK over the BVM-1 RISC-V zkVM. A single `px-core` kernel is compiled both natively and as the proven guest. Contract functions are further zkVM programs. Record delivery uses a hybrid Ristretto-ECDH + ML-KEM-768 encryption.

Supporting components:
- consensus: a pure-Rust RandomX (Monero `rx/0` parameters), LWMA-1 difficulty and MTP/FTL timestamps;
- an encrypted P2P transport with Dandelion++;
- a chain manager with an append-only block store;
- a mempool, an RPC server, a miner and a CLI wallet.

A Wasm confidential-contract engine exists but is **not integrated**, and its transaction kinds collide with PX.

### 1.2 Overall state

**Strengths.** The internal review found the core designs carefully built, with conservative choices throughout:
- **Consensus rules (R1):** no rule bug was found that accepts an invalid block or rejects a valid one on 64-bit platforms. `check_hash`, the seed schedule, emission, the implicit coinbase commitment and the Merkle construction are Monero-equivalent where intended.
- **Cryptography (R2):**
  - the primitives are faithful: canonical decoding, CLSAG, and BP+ checked by hand against ePrint 2020/735;
  - the CLSAG nonce hedge (F2) is fixed;
  - the hedged-randomness gaps R2-C1, C2 and C3 are fixed in `b7d0d3a`.
- **The zkVM (R4):** a full re-derivation found no critical or high soundness defect in BVM-1.
- **PX (R5):** no inflation, theft or double-spend path was found in the kernel, the call binding, the state or the consensus integration.
- **RandomX (R9):** the port matches the reference semantics everywhere it was checked by hand, and it is pinned by the official vectors.

**Pace of fixes.** A large hardening round landed during the review:
- P2P round 2 (`12ce4cb`, `b12b024`);
- body-complete fork choice for the withheld-body stall H1 (`9d689f0`);
- storage fail-safety (`9578517`);
- wallet hardening (`22ad441`);
- hedged randomness (`b7d0d3a`);
- consensus golden vectors and malleability tests (`f6c98c3`);
- exact dependency pins (`249d4f0`);
- a consensus fingerprint and build identity (`f440c4b`).

About 45 register rows are now fixed or partly fixed (§4).

**Weaknesses.** The system is **not yet designed for a hostile public network**, and several structural limits remain:
- one global chain lock held during expensive verification (R8-1, R16-7);
- all state, bodies and undo data in RAM, with full revalidation on every restart (R12-1, R12-4);
- no eclipse-resistant address manager (R8-3, R8-5);
- a PX layer of about 3 transactions per 8 MiB block at about 2.2 MB and about 45 s per proof (R12-10);
- no consensus upgrade mechanism outside the v3 candidate branch (R16-1).

### 1.3 Top risks

| # | Risk | Where | Status |
|---|---|---|---|
| 1 | **PoW security is nominal against stock JIT RandomX miners.** The chain uses Monero's exact rx/0. The project's safe-Rust miner is about 50–100× slower per core than JIT, and rx/0 hash power can be rented or redirected. K1 ("honest majority") is not attainable on any public network. | R1-C2, R9 §4.4, R15-2, I4-1 | Accepted limitation for the trial; mainnet decision open; **not yet documented** for operators |
| 2 | **v3 is not assembled.** The candidate has 4 of about 15 proposed CONSENSUS items. It is 24 commits behind `rebuild/core`. The owner's v3 decision table (SX2 P0-1) has not been signed. PX-F5, the platform-neutral kernel, the genesis tool, the R12-2 verification-cost bound and the P2P "future version is not a ban" integration are all missing. | v3-plan, SX1 §3, SX2 P0-1 | Open |
| 3 | **Node liveness under load.** Block bodies are validated on the peer read loop. Verification runs under the global chain lock. `sync_state` is unbounded. A block of weight-0 deploy CLSAGs can cost about 25–50 s of single-thread validation. | R8-1, R12-2, R16-7, SX2 C10 | Partly mitigated (`12ce4cb` admission order, `d374ef3`); structurally open |
| 4 | **Small anonymity sets.** On a young, quiet chain, v1 rings are dominated by coinbase outputs, and coinbase maturity removes young decoys (R3-1). The PX anonymity set equals PX usage. Dandelion++ anonymity does not grow with network size. | R3-1, R3-3 (SX2-corrected), I3 §3.1 | Accepted limitation plus open wallet fixes (R3-1, P1) |
| 5 | **The 2.2 MB PX upload reveals the transaction origin** to the origin's ISP, including over Tor. No transport fix exists at this proof size. | R8-18, R3-10, I3 §3.5 | Accepted limitation; not yet in the docs |
| 6 | **No minimum chain work during early sync.** The `12ce4cb` work gate is relative to our own best chain. A fresh node, or a chain shorter than 144 blocks, still hashes and stores low-work branches. There is no presync. | R1-C1, R9-2, `12ce4cb` docs | Partly fixed; residual accepted for the trial |
| 7 | **C4 output-key front-running.** A stem relay or a miner can permanently invalidate a victim's transaction for one fee. A PX victim must re-prove (about 45 s). | R6 MP-7, SX1 §2 | Open; owner decision (option C or B) before v3 |
| 8 | **Evidence gaps.** Not evidenced in the inputs: the full workspace suite on the current HEAD, a real seed switch at height 2113, fuzzing with overflow checks, adversarial verifier cost (ZK-F4) and the widest two-function proof size. | T-2, ZK-F4, R15 C2, SX2 P0-10/12 | Open |

### 1.4 Is it ready for the seven-device controlled trial?

**No, not today.** The plan is sound, and most remaining work is small, but the trial cannot start honestly until the items below are closed. The trial model is SX2's: trusted operators, explicit `--peer` lists, at least 96 h across seed height 2113, PX exercised, a late joiner, and an end-of-trial supply audit.

**What blocks it (P0, from SX2 §4, updated with the commits since then):**
1. **The owner's signed v3 decision table** (SX2 P0-1), then the v3 candidate completed and rebased. At minimum:
   - PX-F5;
   - the platform-neutral kernel with no embedded paths, reproduced on Windows and Linux;
   - the genesis tool and procedure (R15 §4);
   - an explicit decision on R12-2, R16-1 integration, R6 option C/B, R2-C6, R4-02 and M3.
2. **Freezing the golden vectors, the fingerprint and the golden PX proof on the final v3 rule set** (SX2 P0-2). Only part of this exists (`f6c98c3`, `f440c4b`).
3. **The P2P and node items still open:**
   - tolerance of unknown message types (R8-14);
   - chain-lock liveness for the late joiner (P0-7: bound `sync_state`, move chain-lock reads off async threads);
   - a fail-stop on the three remaining poison-recovery sites in `p2p/src/net.rs` (R10-2);
   - integration of the non-banning `UnknownUpgrade` if the schedule rides v3.
4. **Evidence:**
   - a fuzz re-run with `-O -a` (the script is fixed in `9ddaddd`; no run is recorded);
   - a labnet regtest run past height 2400 with real RandomX and full-mode miners (the run in `C:/bszkeval/seedrun` stopped near height 42 with a transient "stuck" note and no summary);
   - a per-device-class RandomX hash check;
   - a full test suite on the tagged commit.
5. **Release integrity:** signed annotated tags `testnet-v3-rc` and `testnet-v3`, with the fingerprint published through two channels. Pushing is now done up to `54c4827`.
6. **Trial tooling and procedure:**
   - the supply-audit tool (R15-7; `a27-supply` is in progress);
   - fresh data directories;
   - Windows hygiene (R15-11);
   - hardware minimums;
   - a trial end at max(96 h, height 2113 + 720) (R15-9).
7. **Documentation corrections:**
   - 3 PX per block, not 4 (still wrong in 8 places);
   - K1 cannot be met against JIT miners;
   - the PX upload size reveals the origin;
   - anonymity among 7 participants is not meaningful;
   - the false Hk node collision comment (R2-C6);
   - the share-privacy overclaim (R5-4).
8. **LICENSE decision** (R14 D-10).

**What is only a limitation for this trial (document it; do not block on it):**
- JIT miner dominance (risk 1);
- small anonymity sets (risk 4);
- PX origin visible to the ISP (risk 5);
- no presync or minimum chain work (risk 6, residual);
- RAM that grows with the chain, and restart revalidation (PX-F1/F2/F3; safe for weeks of light use on 16 GB per R12 §5);
- the eclipse weaknesses R8-3 and R8-5 (not reachable in an explicit `--peer` mesh, SX2 §5);
- the PX fixed-fee congestion lever (R5-2, I4-2);
- the lack of PX view keys (R11-W2, which SX2 C8 moved to P1);
- statistical, conditional ZK.

---

## 2. Method

### 2.1 Agents and waves

| Wave | Agents | Scope | Rules |
|---|---|---|---|
| Earlier rounds (in session) | A4, A5, A7, A10, A11, A12, A14, A15, A16, A17 | Prior reviews summarized in the brief's "already known" list | — |
| Wave 1: subsystem reviews | R1 consensus, R2 crypto, R3 privacy, R4 ZK/zkVM, R5 PX, R6 tx/mempool/economics, R7 contracts, R8 P2P, R9 RandomX/mining, R10 storage/node/RPC, R11 wallet, R12 performance, R13 testing/supply chain, R14 docs/DX, R15 testnet/decentralization, R16 architecture | Answered the brief's 13 questions per subsystem; classified every finding; gave severity, file:line, scenario and confidence | Read-only, no builds or cargo; web research allowed and cited; no repository content sent to any service |
| Wave 1: innovation | I1 private computation, I2 identity and governance, I3 network privacy, I4 sustainability, scaling and post-quantum | Worthwhile ideas, prior art, rejections with reasons | As above |
| Wave 2: senior cross-review | SX1 (R1, R2, R4–R7, I1, I2, R12-2); SX2 (R3, R8–R16, I3, I4) | Re-verified about 90 major findings against HEAD, recomputed the arithmetic, resolved contradictions, deduplicated the P0 list | Read-only |
| Implementation (parallel) | A1, A4b, A6, A7b, A8, A15b, A16b, A20, A21, A22, A23, H1, V3-A (and A24–A27 running) | Fixes in separate worktrees; merged by the coordinator after tests | Worktrees; owner approval required for CONSENSUS changes (these go to `v3/candidate` only) |

### 2.2 How findings were verified

- **Wave-1 reviewers** read the code at `f677e55` to `9578517`. They tagged each claim with its evidence class. "Tested" means that an existing named test covers the claim; the reviewers ran no tests.
- **SX1 and SX2** re-read every cited line at `58f25ec` to `f6a52ca`.
  - SX2 reports about 50 of about 70 major findings confirmed as stated, 14 confirmed with a correction, 3 overstated, 1 partly wrong (R3-7 "undocumented") and 1 partly unverifiable (R8-6).
  - SX1 confirmed its set, with corrections to R2-C6 (cost), R4-01 (severity), R4-02 (rationale), R7-5 (DoS framing), R12-2 (broader scope) and R6 option C (four required corrections).
  - **Neither cross-review found a fabricated major finding.**
- **Fixes** were verified by tests the implementation agents added (named in each commit message), then run by the coordinator after merging. The logs in `C:/bszkeval/` show, for example:
  - consensus golden 17/17 and crypto 96/96 plus malleability 9/9 (`after-a20-a21.log`);
  - p2p 28 unit, 36 network and 1 `withheld_body` (`after-a8.log`);
  - chain `fork_choice` 9/9, `storage_recovery` 8/8 and `manager` 20/20 (`after-h1.log`);
  - tx `validation_order` 10/10 (`tx-after-a4b.log`).
- `after-a8.log` also records a wallet test compile failure (a missing `Info` field) that `54c4827` says it fixes. **No log of a full-workspace run on `54c4827` or later was among the inputs.**

### 2.3 Limits

- **Same-model internal review.** Every reviewer and cross-reviewer is an instance of the same AI system working from the same brief. Correlated blind spots are likely (docs/reviews/review-status.md §3). This is not a substitute for independent review, and the owner has decided none will take place.
- **No reviewer ran builds, tests or benchmarks.** Most performance figures beyond the brief's measured anchors are estimates (R12 §1.3).
- **External facts** (Plonky3 0.8, RandomX v2, ProxyMark, the Qubic 2025 events, Neptune Cash, Arti status) are as of the pages the reviewers retrieved on 2026-09-27. Several are marked [assumed] in the source reports.
- **Unmerged work is excluded.** Work in unmerged worktrees is not treated as done. Where a wave-1 report described code that has since changed, the register uses the current commit.

---

## 3. Per-subsystem assessment

Each subsystem uses the brief's seven classifications:
- **CV**: Complete and verified;
- **CT**: Complete but requires further testing;
- **PI**: Partially implemented;
- **NI**: Not implemented;
- **Def**: Deferred;
- **Blk**: Blocked;
- **AL**: Accepted limitation.

Register IDs (§4) are given in brackets.

### 3.1 Consensus and chain

**Implemented and well designed:**
- **One rule definition.** A single `check_rules` is shared by sequential validation and the batch pre-check [R1 V7, test `precheck_agrees_with_sequential_validation_and_computes_no_pow`].
- **Monero-equivalent core:**
  - `check_hash` with the exact 2^256 boundary [R1 V1, math];
  - the seed schedule on the header's own branch [R1 V2];
  - LWMA-1, matching zawy's reference [R1 V5];
  - strict MTP, and an FTL that is never a permanent verdict [R1 V6].
- **Fork choice:** strictly-greater cumulative work, first-seen ties and invalidity propagation [R1 V8]. It now targets the **most-work body-complete** chain, so a withheld body can no longer stall the chain [H1; `9d689f0`; tests `fork_choice` 9/9, `withheld_body`].
- **Emission and coinbase:** emission depends on height only, and B3 is exact [R1 V10–V11].
- **Commitments:** the tx id covers every byte [R1 V9]; the Merkle tree has no CVE-2012-2459 duplication [R1 V4].
- **Build guard:** a `compile_error!` on non-64-bit targets [R1-C6, `8097f66`].
- **v2 retired:** `--network testnet` refuses to start until the v3 genesis is final [R15-1, `f6a52ca`].

**Fragile or exploitable:**
- **Free low-work headers.** At difficulty 1 headers are free. Before `12ce4cb`, any valid header was hashed and stored. The work gate in `12ce4cb` now drops batches below `best_work − work(last 144 blocks)`. What remains:
  - no `MIN_CHAIN_WORK`, and no presync, for fresh nodes and chains shorter than 144 blocks;
  - the RandomX cache is still built under a global mutex with 2 slots, and the best-chain seed is not pinned [R1-C1, R9-2; SX1 correction: gate on claimed work, not on difficulty].
- **LWMA timestamp shaping** by a majority miner is unquantified [R1-C8].
- **Clock skew above 360 s** stalls a node silently [R1-C9].
- **Worst-case block validation:** weight-0 v1 inputs in deploys and PX allow about 12,100 CLSAGs per block, about 25–50 s single-threaded [R12-2; SX1: any mempool user can do this, not only miners].
- **Majority rewrites are cheap** given risk 1 [R1-C2].

**Missing:**
- `MIN_CHAIN_WORK` and a presync;
- the upgrade and activation mechanism (only on `v3/candidate`) [R16-1];
- a state digest for divergence detection [R16-9];
- a finality or deep-reorg policy for mainnet [R1 §4.3];
- an LWMA adversarial simulation [R1-C8].

| Component | Class | Notes |
|---|---|---|
| Header format, id, network binding | CV | Never change (§8) |
| PoW check and seed schedule | CV | The seed switch is tested with a short epoch only [R15-9] |
| LWMA-1 | CV (arithmetic, golden vectors in `f6c98c3`); CT (adversarial) | `consensus/tests/golden.rs` (`f6c98c3`) pins LWMA outputs derived independently from the spec. It should kill the R13 T-3 mutant `(n+1)→n`. Verify with cargo-mutants (T-12) |
| Fork choice and reorgs | CT | H1 fixed; ties after restart fixed [`9578517`, `9d689f0`]; deep PX reorgs tested only shallow [R1 V12] |
| Anti-DoS work gate | PI | `12ce4cb`; no presync or minimum work |
| Upgrade mechanism | NI on `rebuild/core`; PI on `v3/candidate` (`58c7f6e`) | P2P, chain, mempool, wallet and miner integration still owed [v3-upgrade-mechanism.md §2.4] |
| Finality policy | Def | K4 kept for the testnet |

### 3.2 PoW and RandomX

**Implemented and well designed:**
- **A spec-conformant pure-Rust RandomX v1** [R9-1]:
  - no FFI, `forbid(unsafe_code)`;
  - verified by the 5 official vectors and component vectors, plus full = light agreement on 1,024 inputs.
- **Deterministic floating point.** Directed rounding is emulated with error-free transforms, with no FP state. That is more portable than the reference, which relies on MXCSR plus JIT [R9 §3].
- **One PoW path** is shared by the miner and the node [R9 §1].
- **Target guards:** x87 and non-SSE2 targets are refused [R9-3, `8097f66`].
- **Miner:** the nonce is re-randomized per template [R3-2, `f331642`].

**Fragile or exploitable:**
- **Speed:**
  - **the JIT gap:** about 100 ms per full hash and 450–750 ms per light hash, against about 1.4 ms for the JIT reference. This is structural under the no-unsafe policy [R9 §4, R1-C2];
  - **the verification asymmetry:** SX2 recomputes it as 4–7× at D0 = 100, and about 300–500× only at D ≈ 1.
- **Seed-cache thrash** from attacker-chosen seeds: caches are built under a global mutex [R9-2, residual].
- **The seed-switch stall:** every full-mode miner stops for about 179 s (8 threads) to about 20 min (1 thread) at the same height [R9-R4].
- **Stale work:** about 6% of hash power is wasted by the 15 s template refresh [R9-9].
- **Unbounded `CachedPow`** [R9-6 = R10-12 = R12-14].

**Missing:**
- an FPU differential oracle (`rustc_apfloat`) [R9-R6, T-8];
- aarch64 and big-endian CI [R9-7];
- a reference vector corpus [T-8];
- next-dataset prebuild [R9-R4];
- a safe-Rust performance programme [R9-R2];
- a documented statement that K1 fails against JIT miners [R1-C2, R15-2].

| Component | Class |
|---|---|
| Algorithm conformance (x86-64) | CV |
| Cross-platform determinism | CT (x86-64 only; aarch64 unverified) |
| `RandomXPow` cache design | PI (in-mutex build, 2 slots, no pinning) |
| Miner | CT (binary not run in CI) |
| Competitive mining with the official miner | AL |

### 3.3 Cryptography

**Implemented and well designed:**
- **Encoding and hashing:** canonical Ristretto and scalar decoding; domain-separated Blake2b [R2 §2].
- **CLSAG:** the transcript matches ePrint 2019/654. The F2 nonce hedge binds the full transcript [`f677e55`].
- **BP+:** checked by hand against the paper; strong Fiat–Shamir; batch weights of 128 bits [R2 §5].
- **Janus anchor:** Lemma 1 holds in the ROM [R2 §3.1].
- **Delivery:** the hybrid delivery key includes `ct_kem` [R2 §9].
- **Hedged randomness:** transfer, coinbase and PX contexts now bind the full statement, and PX delivery is hedged [R2-C1/C2/C3, `b7d0d3a`].
- **Wallet file:** Argon2id with AES-256-GCM, with the header authenticated as AAD [R2 §10].

**Fragile or exploitable:**
- **Hk node collision claim.** The comment claiming 124-bit collision resistance for `node(l,r) = P(l‖r)[0..8]` is **false**: standalone collisions follow trivially from inverting the permutation. Tree binding still holds at about 2^124, through leaf anchoring and fixed depth [R2-C6; SX1 re-derived it]. **The comment is still in `px-core/src/hash.rs`.**
- **Membership nonce:** two signatures leak the key. Unreachable today, because there is no consumer [R2-C5].
- **Poseidon2-BabyBear margin:** +7.5% in partial rounds, in the most actively attacked parameter class [R2-C7].
- **PX view tag:** derived from ECDH only, so it is a post-quantum recipient-linkage filter [R2-C8, R5-6, R11-W5].
- **Identity `V`:** accepted in `seal` [R2-C9].
- **ML-KEM:** the crate is unaudited, and its decapsulation timing is unknown [R2-C12].

**Missing:**
- RFC 9496, FIPS 203 and RFC 7693 known-answer vectors; a pinned BP+ proof; real-permutation Hk and node vectors [R2-C11];
- a written derivation of the Carrot delta [R2 §3.1];
- a hash-agility plan [R2-C7].

| Component | Class |
|---|---|
| Ristretto and hash primitives | CV |
| CLSAG, BP+ | CV (self-vectors, differential tests and malleability tests in `f6c98c3`; no external vectors) |
| HedgedRng call sites | CT (`b7d0d3a`; PX witness randomness is still unhedged; `a25` in progress) |
| Janus anchor | CT (own construction, no external review) |
| Hk | Sponge CV; tree node CT (argument unwritten, comment false) |
| PX delivery | CT (not X-Wing; documented as such in `22ad441`) |
| Post-quantum migration | NI (research track; I4-6 gives a cheaper recovery construction) |

### 3.4 Transactions, mempool and economics

**Implemented and well designed:**
- **Codec:** strict, with minimal varints and no trailing bytes [R6 §1.1].
- **Signatures:** bound to the network [R6 §1.1].
- **Fees:** a deterministic per-shape standard fee, and an exact PX fee (no fingerprint) [R6 §3.3].
- **Mempool:**
  - atomic eviction;
  - namespaced conflict keys, now including output keys [F1, `16659ee`];
  - revalidation after an extension [R6 §2.1].
- **Validation order:** stateless checks run before contextual ones in the mempool paths [TX-1/TX-3, `b33a1ce`].
- **Relay admission (`12ce4cb`):**
  - cheapest checks first;
  - a CLSAG signature budget per input;
  - replays of pooled transactions cost nothing;
  - contextual rejects are cached per tip;
  - invalid signatures over rings buried at least 60 blocks deep are penalized [R6 TX-2, `54c4827`].
- **Emission and tail:** correct [R6 §3.1].

**Fragile or exploitable:**
- **C4 output-key front-running:** a stem relay or a miner copies a victim's output key for one fee [R6 MP-7, confirmed by SX1].
- **Deploys:**
  - they are underpriced permanent RAM state [R5-1, R6 TX-4, R7-11];
  - they can capture the PX lane cheaply [R6 MP-5].
- **No PX fee market** under congestion [R5-2, I4-2].
- **Admission cryptography** runs under the chain lock [R6 MP-1].
- **Full revalidation after a reorg:** about 136–218 s under the lock for a full pool [R12 §10, §18].
- **No expiry** [known].

**Missing:**
- a two-phase admission [R6 R-MP1];
- a proof-verified cache [R6 MP-2, R16-8];
- a ring-keyed v1 verification cache [R12-12];
- fee tiers [R6 R-FEE1, deferred].

| Component | Class |
|---|---|
| Codec, tx ids, weight | CV |
| Validation rules T/C/B/PX | CV (for the rules as specified) |
| Mempool conflicts and eviction | CV (`16659ee`, `mempool_conflicts` 10/10) |
| Relay admission cost | CT (`12ce4cb`) |
| Deploy pricing | PI (exact fee on `v3/candidate` `cc39795`; block budget defined, not enforced) |
| C4 griefing | PI (design decision open) |
| Fee market | AL (testnet); mainnet redesign |

### 3.5 ZK and zkVM

**Implemented and well designed:**
- **Soundness argument.** R4 re-derived it independently from the source for every bus, the memory argument, range checks, control flow, syscalls, cross-execution isolation and terminal blinding [R4 §2].
- **ISA decoder:** `isa.rs` is correct for RV32I + Zmmul [R4 §2.9].
- **Third-party patches:** the three patches preserve values [R4 §4].
- **Verify path:** hardened with pre-checks, `catch_unwind` and exact shapes [R4 §3.7].
- **Canonical proofs:** rewritten proofs (non-zero FRI witnesses, empty optional openings) are rejected [M1/M2, `4b277cd`].
- **ZK-F3:** fixed [`f36b909`].
- **Build guard:** `panic = abort` is refused [`5888d4c`].

**Fragile or exploitable:**
- **Security calculator:** it is fed the pre-ZK height, and the 0.7 calculator is known to over-report. The unique-decoding figure (105.6 bits) is query-bound and stands. The Johnson figure (≥ 123) is not established to that precision [R4-01; SX1: low severity, docs only].
- **FRI folding schedule:** chosen by the prover and bound after the betas. This is not relayer malleability [R4-02, SX1 correction].
- **No circuit id** in the transcript [R4-11].
- **Unmeasured costs:**
  - adversarial verifier cost [ZK-F4];
  - the widest two-function proof against `MAX_PROOF_BYTES` [known].
- **Thin conformance evidence** for the decoder: no riscv-tests [R4-04].

**Missing:**
- a SIMD prover build: probably a large speed-up, with no consensus impact if the verifier stays pinned [R4-06, I1-F3];
- an independent security calculation [R4-01];
- envelope tests that assert the unique-decoding bound [R4-12].

| Component | Class |
|---|---|
| BVM-1 circuits | CV (by argument; R4) |
| ISA decoder | CT |
| BS-ZK-2 parameters and documented bits | CT (R4-01) |
| Proof encoding canonicity | CV (`4b277cd`; `f6c98c3` field mutations) |
| Zero knowledge | AL: statistical and conditional (zk-coverage.md §3) |
| Plonky3 0.8 | Def (hard fork; new verifier id) |
| Recursion or aggregation | Def (P3) |

### 3.6 PX

**Implemented and well designed:**
- **Kernel source:** one Rust source is both the native kernel and the proven guest [R5 §0].
- **Kernel checks:** integer (`u128`) balance, canonical witness checks, `nf` binding `cm`, and `rho` derived from `nf_0` (no Faerie Gold) [R5 §1].
- **Verification:** registry-mandatory `verify`, fixed shapes, pool containment, and `h_tx` binding over prefix, base and network [R5 §1].
- **Vault checks:** the vault lock and claim now require the program set to be exactly {vault} with its budget [P-1/P-2, `22ad441`].

**Fragile or exploitable:**
- **PX-F5:** contract outputs are not forced to `owner = 0`, so records can be burned. Planned for v3; **not on the candidate yet**.
- **PX-F4:** the caller chooses `rcm`, so a contract's openings can be withheld. Deferred and documented. Option B′ goes with the contract redesign [R5-15]; SX1 and I2-F1 require that `rcm` stays prover-choosable.
- **Shares:** they expose `cm` and `rho`, while the docs still claim they reveal nothing [R5-4].
- **Shape limits:**
  - 2 inputs, with no consolidation [R5-5, R11-W6];
  - shared state can be updated at most about once per 16 blocks [R5-9, R7-4].
- **Chain growth:** about 5.9 GB/day at capacity, with no pruning while PX-F3 re-verifies [R5-11].

**Missing:**
- a clock for functions (anchor height or validity window) [R5-3, R7-1; SX1: a capability, not a security issue];
- user-owned contract records [R5-10];
- multi-asset records [R5 §4, I1 B1];
- delegated proving [R5-13, R11-W4].

| Component | Class |
|---|---|
| Kernel and records | CV (source and argument); CT for PX-F5 |
| State, tree, nullifiers | CV |
| Bridge and fee | CV (rules); AL (public bridge amounts, R3-8) |
| Contract model | PI (demo vault only; no clock, no authorization, no composition) |
| Capacity (3 PX per block) | AL |

### 3.7 Contracts (Wasm)

**Implemented:**
- a deterministic Wasm profile on wasmi 0.38;
- an SMT, undo and the approval model;
- 30 tests [R7 §1.2].

**Not integrated.** Its transaction kinds 2 and 3 collide with PX.

**Fragile:**
- C-1 to C-5 are open [known];
- about 120 unreviewed `unsafe` blocks inside wasmi, on an unsupported release line [R7, A14];
- a weaker privacy tier: callers are 1-of-16 rings, and state is public [R7-12].

**Recommendation (R7, endorsed by R16 §8 and I1): option D.**
- PX becomes the only contract platform.
- The Wasm system is frozen out of the default workspace.
- The unused `crypto::{schnorr, membership, claims}` modules (1,037 lines) move behind a feature [R7-10, R16-11].
- This needs an owner decision.

| Component | Class |
|---|---|
| Wasm engine M1–M2 | CT (C-1 to C-5 open) |
| Chain integration M3–M6 | NI; recommend **Def** indefinitely (owner) |
| Schnorr, membership, claims | CT, no consumer (R7-10) |

### 3.8 P2P and sync

**Implemented and well designed:**
- **Codec:** bounded before allocation, and strict [R8 §1].
- **Transport:** encrypted, with `network_id` in the KDF [R8 §1].
- **Relay rules:** GetTx serves only announced transactions; local transactions always stem [R8 §1].
- **Round 2 (`12ce4cb`):**
  - a bounded header queue and a work gate;
  - handshake counting (N-4);
  - the announcement race fixed, plus loop fixes;
  - bans saved;
  - local transactions held when no stem exists;
  - stem conflicts checked before verification (R8-7);
  - unrequested unknown-header blocks dropped (R8-2, R10-1);
  - group diversity within a round (R8-4);
  - seed fallback (R8-13);
  - the InvTx stempool oracle closed (I3-1);
  - an onion address sent only over Tor (I3-2);
  - Dandelion++ set to q = 0.2 with a 39 s embargo (R3-4);
  - the PX token drain closed (SX2 §0.4).
- **Block timeouts** are not misbehaviour [R8-9, `b12b024`].

**Fragile or exploitable:**
- **Global chain lock:** held for expensive work and taken on async threads; block bodies are validated on the read loop [R8-1, R16-7; `12ce4cb` docs "M5 open"].
- **Address manager:**
  - no per-source bucket limit and no address rate limit [R8-3];
  - every onion address is its own network group [R8-5];
  - no inbound eviction and no /64 caps [N-5, N-9].
- **SOCKS:** no stream isolation [R8-6].
- **Outbox:** accounted in messages, not bytes, so about 605 MB per peer [R8-10, SX2 correction].
- **Forward compatibility:** an unknown message type bans the sender, which blocks protocol evolution [R8-14].
- **Trickle timers:** one per inbound peer [R8-16].
- **Tor inbound:** every Tor inbound connection comes from 127.0.0.1 [N-6].
- **GetAddr:** the answer fingerprints the node [R3-6].
- **PX token:** a PX transaction that conflicts with a pooled one still consumes a node-wide token [`12ce4cb` docs].

**Missing:**
- a chain actor with snapshots [R8 §3.1];
- addrman v2, feelers, anchors and block-relay-only connections [R8 §3.4];
- compact blocks, whose reconstruction must never use the stempool [I4-5];
- private broadcast [I3 §3.3];
- transport v2 [I3 §3.7].

| Component | Class |
|---|---|
| Transport | CT (fingerprintable, R8-20) |
| Codec | CV (fuzzed); PI for forward compatibility (R8-14) |
| Dandelion++ | CT (`12ce4cb`); AL for the small anonymity set (I3 §3.1) |
| Header sync | PI (work gate; no presync) |
| Body download | CT (`b12b024`, H1) |
| Addrman and eclipse resistance | PI (R8-3, R8-5, N-7/N-8/N-9) |
| Resource accounting | PI (R8-10, R8-11) |
| Concurrency | PI (R8-1) |

### 3.9 Storage, node and RPC

**Implemented and well designed:**
- **Block store:**
  - an append-only CRC log with fsync before apply [R10 §2.1];
  - a versioned `blocks.dat` header that refuses other networks [R10-3, `9d689f0`];
  - fail-safe load that truncates only the final region [R10-8a, `9578517`].
- **Fail-stop behaviour:**
  - a store failure stops the node [`9578517`];
  - a poisoned chain lock stops the node [R10-2, `35b7cb9`].
- **Side branches:** low-work side-branch bodies are not stored [R10-1, `9d689f0`].
- **RPC:**
  - `/px/commitments` is paginated, without cloning the record log [R10-5/R12-3, `d374ef3`];
  - loopback by default.
- **Identity:** the consensus fingerprint, genesis id and build commit are shown in `--version`, the log and `/info` [D-6/R15-8, `f440c4b`].
- **Deployment:** a hardened systemd unit.

**Fragile or exploitable:**
- **Poison recovery:** 3 sites in `p2p/src/net.rs` (lines 323, 442, 446) still recover instead of stopping [R10-2 residual].
- **RPC:**
  - no Host check, auth or CORS policy, so DNS rebinding is possible [R10-4];
  - handlers still take the chain lock on async workers; `/distribution` is O(height) [R10-5 residual].
- **Memory:**
  - PX undo takes about 4.2 KB per block, including empty blocks [R10-6];
  - PX ciphertexts are held twice [R10-7].
- **Shutdown:** no SIGTERM handling; no Docker `STOPSIGNAL` [R10-9].
- **Logs:** debug logs record stem routing [R10-10].

**Missing:**
- persistent state with bodies on disk (a mainnet blocker) [R10 §5, R12 I5];
- `/health` and `/metrics` [R10 §4];
- `--reindex` and snapshots [R10 §5.4].

| Component | Class |
|---|---|
| Block store | CV (crash-consistency tests `storage_recovery` 8/8) |
| Chain manager | CT |
| In-RAM state | AL (testnet); mainnet blocker |
| RPC | PI (R10-4, R10-11) |
| Node binary | CT (identity and fail-stop added) |

### 3.10 Wallet and UX

**Implemented and well designed:**
- **Sending:** reserve before send, unchanged rebroadcast, ring reuse (W-5) [R11 §3.5].
- **Receiving:**
  - download-everything scanning [R11 §0];
  - canonical PX anchors;
  - Janus-style `cm` acceptance [R11 §3.6].
- **Hardening in `22ad441`:**
  - gap limits (M-1) and gap-limit scanning (M-2);
  - vault secrets stored before a lock is sent (R11-W1);
  - RPC client caps, no redirects, no proxy environment variables;
  - 0600 file permissions;
  - secrets read from a file or a prompt.
- **Delivery-key cache** [R12-9, in part].

**Fragile or exploitable:**
- **Keys and seed:** no PX viewing-key hierarchy, and a seed with no version, birthday or network. Both change seed derivation [R11-W2/W3, I2-R1; SX2 C8: P1 for the trial, P0 before persistent users].
- **Decoys:** coinbase maturity removes young decoys [R3-1].
- **`/outputs` query:** it reveals a superset of the ring to the node. A local output index would remove it [I3 §3.9].
- **Remote nodes:** plaintext, with no SOCKS [R3-9].
- **UX gaps:**
  - no confirmation, fee preview, history or status [R11-W7];
  - misleading PX "insufficient funds" errors [R11-W6];
  - nominal accounts [R11-W10].

**Missing:**
- view-only wallets and cold signing [R11-W15];
- a compact scan [R11-W9, I1-F2];
- an incremental PX tree [R11-W8, R12-8];
- payment proofs [R11-W11, I2 §4.3];
- a PoW check [W-F6].

| Component | Class |
|---|---|
| v1 wallet core | CT |
| Seed and keys | PI (R11-W3) |
| PX wallet | PI (no view keys, no consolidation) |
| Remote-node privacy | PI (hardened client; no Tor or TLS) |
| Hardware wallet, delegated proving | NI (P3) |

### 3.11 Privacy end-to-end

**Well designed** [R3 §4]:
- no `tx_extra` or `unlock_time`;
- canonical orderings;
- a mandatory change output;
- deterministic fees;
- a minimal `Version` message;
- stempool invisibility, now including InvTx [I3-1, fixed];
- PX fixed shapes and dummies;
- hash-based user nullifiers.

**Quantified weaknesses** [R3 §2.1, simulated; SX2 corrections applied]:
- **Coinbase-dominated rings.** At 3 days and 20 transfers per day:
  - 94% of decoys are coinbase outputs;
  - 40% of rings have only coinbase decoys (the outsider "unique non-coinbase member" heuristic);
  - the effective ring of 1.9 "against miners" assumes that every miner colludes (m = 1). For one of seven equal miners it is **about 14** (SX2).
- **Young spends.** A real input spent within 60 blocks is the newest ring member in 70–100% of cases on a quiet chain [R3-1].
- **Miner clustering** is removed by `f331642` [R3-2].
- **Dandelion++.** The q/embargo pair is fixed (`12ce4cb`). The anonymity set stays small and does not grow with N [I3 §3.1].
- **Bridge amounts are public** [R3-8].
- **Contract-record nullifiers** can be computed by anyone who holds the opening. This was already documented at px.md:595-598, so SX2 marks R3-7's "undocumented" as wrong; the public-`rcm` corollary is new.
- **PX size** reveals the origin to the ISP [R3-10, R8-18].
- **Retroactive deanonymization:** a DL-capable adversary can deanonymize v1 after the fact. PX does not depend on DL (conditionally) [R3-12, R2-C14].

| Property | Class |
|---|---|
| v1 ring anonymity | AL (quantified, testnet) plus PI (R3-1 wallet fix pending) |
| PX full-set anonymity | CV (design); AL (set = usage) |
| Network-origin privacy | PI (D++ fixed; addrman, SOCKS and GetAddr open) |
| Post-quantum privacy | AL (v1); CT (PX, conditional on statistical ZK) |

### 3.12 Performance and scalability

**Measured anchors** [brief, R12 §1.2]:
- transfer proof about 2.18 MB; proving 44.6–45.2 s; verification 0.21 s;
- vault proof 2.69 MB; about 53 s;
- 3.8 GB peak;
- v1 full validation 6.8 ms per transfer; extension path 6.3 µs;
- RandomX light 0.45–0.75 s.

**Binding constraints** [R12 §13; arithmetic re-verified by SX2]:
- **Node RAM is O(chain):** about 4.5× v1 bytes, plus a floor of about 6 KB per block. A 16 GB node fills in about 147 days of light testnet use, or 2.4 days of full blocks.
- **Restart re-validates everything:** about 22 h after one moderate year.
- **Initial sync:** header PoW takes about 6.9 h per chain-year on 8 threads.
- **PX throughput:** 0.025 PX tx/s.
- **Worst-case block:** about 25–50 s (R12-2).
- **Stale rate:** about 3% (empty blocks) to about 12% (full blocks) [est].
- **Wallet sync:** full blocks as hex, about 614 GB per moderate year [R12-7].

**Levers** (none is consensus except proof-size reduction):
- persistent state;
- snapshot restart;
- parallel verification (R12-11);
- a ring-keyed v1 cache (R12-12);
- compact blocks;
- the RandomX interpreter programme;
- a compact wallet feed;
- pruning.

| Area | Class |
|---|---|
| Throughput, v1 (≈ 3.2 tx/s) | CV [math] |
| PX throughput | AL |
| RAM, restart | AL (testnet, weeks); NI fix (mainnet blocker) |
| Parallel verification | NI |

### 3.13 Testing and supply chain

**Implemented:**
- about 731 tests;
- 9 cargo-fuzz targets, including the differential `kernel_diff` and `contract_sequence`;
- a labnet with partitions and supply checks;
- pins for genesis, program ids and Poseidon2 [R13 §1].
- Commit `f6c98c3` adds:
  - consensus golden vectors derived independently from the spec;
  - non-malleability tests for CLSAG, BP+, tx, block and zk (15/15 non-equivalent mutants caught) [T-3/T-1].
- Commit `9ddaddd` adds:
  - `--locked` in CI;
  - an overflow-checks job;
  - an audit of the fuzz lockfile;
  - a fuzz smoke job that fails on zero executions;
  - a fixed-path guest build;
  - a pinned Docker toolchain and a `.dockerignore`.
- Commit `249d4f0` pins postcard, serde, blake2, aes, curve25519-dalek, p3-monty-31 and p3-poseidon2 exactly [R16-3].

**Fragile:**
- **Fuzz evidence:** the recorded evidence (about 531 M executions) had no overflow checks. The script is fixed, but no re-run is recorded [T-2].
- **Missing test methods:**
  - no property-based framework (the stated reason is stale) [T-4];
  - no deterministic simulation [T-5];
  - unfuzzed stateful surfaces [T-6];
  - no RandomX reference corpus or FPU oracle [T-8];
  - an honest-only, short labnet [T-9];
  - no mutation testing or coverage [T-12].
- **Corpora** exist on one machine only [T-7].
- **Supply chain:**
  - no signed tags or release artifacts [T-10, R15-5];
  - no cargo-deny or cargo-vet [T-11];
  - the `third_party` tests never run in CI [known].

**Dependencies** [A14]:
- the only advisory is RUSTSEC-2024-0436 (paste, unmaintained);
- wasmi 0.38 is an unsupported line;
- fs2 and env_logger are stale;
- ml-kem is unaudited;
- "no C/C++" is verified for the root lockfile only.

| Component | Class |
|---|---|
| Unit and integration tests | CT |
| Consensus golden vectors | PI (`f6c98c3`; no golden chain corpus or golden PX proof; freeze after v3) |
| Fuzzing | PI (T-2, T-6, T-7) |
| Reproducible guests | PI (fixed-path build; still dependent on the Windows path until v3) |
| Release engineering | PI (pins, Docker) / NI (tags, signing, artifacts) |

### 3.14 Documentation and operator experience

**Good:**
- the claims discipline (review-status.md);
- the v1 byte-level specs;
- the zkvm guests README, a model reproducibility document;
- SECURITY.md;
- the incident plan, which is honest about one-owner capacity [R14 §1];
- `6ed731f` added operator requirements (testnet.md §12) and one trial-authorization statement;
- `58f25ec` fixed the issue template and added Neptune Cash as prior art.

**Open:**
- **Specification:**
  - no normative PX/ZK byte spec [D-1].
- **Status and governance records:**
  - no single status source [D-3];
  - fragmented finding ids [D-4];
  - no decision log or consensus-change process in the repository [D-5];
  - no ARCHITECTURE.md [D-11];
  - evidence not bound to builds [D-12].
- **Licence:** none [D-10].
- **Stale or false statements:**
  - "about 4 PX per block", in 8 places [R12-10];
  - the false Hk node comment [R2-C6];
  - the share-privacy overclaim [R5-4].
- **Undocumented limitations:**
  - K1 against JIT miners;
  - the PX origin visible to the ISP.

| Component | Class |
|---|---|
| v1 specs | CT (golden vectors partly) |
| PX/ZK specs | PI (normative by code) |
| Operator docs | PI (`6ed731f`; upgrade and backup guides open) |
| Governance records | NI |
| Licence | NI (owner decision) |

### 3.15 Testnet readiness and decentralization

**Implemented:**
- a 14-gate checklist, a reset plan, a validation list and an incident plan;
- the v2 identity retired [`f6a52ca`];
- a consensus fingerprint [`f440c4b`];
- work pushed up to `54c4827`.

**Open** [R15 §3; SX2 §4]:
- the v3 decision table and freeze;
- the genesis procedure: a beacon-derived nonce, `T_g` fixed before the beacon, dual verification, 8 tests [R15 §4];
- genesis binding in the P2P session and the wallet [R15-3];
- the supply-audit tool [R15-7];
- a real seed-switch run [R15 C2];
- Windows hygiene [R15-11];
- signed tags [R15-5].

**Decentralization:**
- **Mining:** JIT-dominated (risk 1).
- **People:** one maintainer, one approver and one signing identity [R15-5, R15 §5.3].
- **Seeds:** none. That is correct for the trial; a public testnet needs at least 3 independent operators and at least 1 onion seed [R15 §5.2].
- **Governance:** no on-chain protocol governance is recommended [I2 §5].

| Area | Class |
|---|---|
| Trial process documents | CT |
| v3 identity | PI (candidate branch) |
| Genesis tool | NI |
| Release integrity | PI |
| Mining decentralization | AL (trial) |
| Maintainer redundancy | AL |

### 3.16 Architecture

**Good** [R16 §2, §5]:
- an acyclic crate graph;
- one definition of the header rules;
- a single-source kernel;
- typed, rule-tagged errors with a stateless/contextual split;
- `catch_unwind` containment, with the build profile guarded;
- a fail-stop store.

**Structural debt:**
- **Upgrades:** no rule schedule on `rebuild/core` (it exists only on the candidate) [R16-1].
- **No separable consensus core:** wallet and prover modules define consensus constants, for example `CIPHERTEXT_BYTES` in `px::delivery` [R16-4].
- **Rules restated in 4–6 places;** F1 was one instance [R16-5].
- **State handling:**
  - validate-then-`expect` on apply [R16-6];
  - no state digest [R16-9].
- **Concurrency:** one global mutex [R16-7].
- **Mempool as a proof cache:** sound today, but broken by planned features [R16-8].
- **Dual transaction model:** sustainable only if v1 is frozen and PX is the growth path [R16-10].
- **Repository weight:** 118.6 MB of tracked `legacy/` and `research/` [R16-12].

**Target** [R16 §11–12]:
- a consensus facade;
- a `TxKind` effects model with an infallible commit;
- a chain actor with snapshots and off-lock verification;
- frozen per-verifier crates;
- a project-owned proof codec.

| Area | Class |
|---|---|
| Crate structure | CT |
| Consensus core as a unit | PI |
| Concurrency model | PI |
| Upgrade architecture | PI (candidate) |
| State commitment | NI (P2 node-local, P3 consensus) |

---

## 4. Findings register

One table, deduplicated across all reports.

**How to read the columns:**
- **ID:** the original IDs. Where findings were merged, every original ID is listed.
- **Sev:** Crit / High / Med / Low / Info. This is the most defensible severity after cross-review.
- **Class:** the abbreviations of §3.
- **Ev (evidence):** m = mathematically established; t = tested (the named test is in the source report or in the commit); s = source-read; a = assumed; u = unknown; e = estimate.
- **SX:** the cross-review verdict. C = confirmed; CC = confirmed with correction; O = overstated; W = wrong in part; U = unverifiable; "—" = not cross-reviewed.
- **Status:**
  - "fixed `x`": the commit message states the fix and names tests;
  - "partly `x`";
  - "cand `x`": on `v3/candidate` only, not merged;
  - "open";
  - "WIP": an agent branch exists with no commits;
  - "verify": the claim needs confirmation.
- **Pri:** priority **for the seven-device trial**, using SX2's re-prioritization where it gave one. "-pub" marks a priority that applies before a public testnet.
- **Cons (consensus impact):** none / policy / **CONS**.
- **Id (testnet identity impact):** none / v3 (rides the planned reset) / new (would need an identity or activation height of its own).

| ID | Sev | Class | Subsystem | One-line description | Ev | SX | Status | Pri | Cons | Id |
|---|---|---|---|---|---|---|---|---|---|---|
| R1-C1, R9-2 (low-work part), R15-10, known "low-work headers hashed and stored" | High | PI | Consensus/P2P | Difficulty-1 forks give free valid headers; RandomX verification asymmetry; stored forever | m,s | SX1 CC (gate on claimed work, any low work); SX2 CC (4–7× at D0 = 100) | partly `12ce4cb` (work gate 144 blocks, full-batch density rule); no MIN_CHAIN_WORK or presync | P1 (presync P2) | none | none |
| R9-2 (cache part), R1-C1 item 6 | Med | PI | PoW | RandomX cache built under the global mutex, 2 slots, best-chain seed not pinned: seed thrash | s | SX2 CC | open (`12ce4cb` removes the free trigger only) | P1 | none | none |
| R1-C2, R9 §4.4, R15-2, I4-1, R12 §12 | High (security model) | AL | PoW | Stock rx/0 plus a safe-Rust interpreter miner (about 50–100× slower than JIT); rentable hash rate; K1 unattainable | s,m | SX1 C; SX2 C2 (keep rx/0 for the testnet) | open (not documented) | P0 docs; mainnet decision P3 | none (docs); CONS if the salt changes | mainnet |
| R1-C3, R12-5, R9-8 | Med | AL | Sync | Header PoW about 0.75 s per header: about 55 CPU-h per chain-year; rejected headers not remembered | m | SX1 C | open | P3 (reject LRU P2) | none | none |
| R1-C4 | Low | CV | Chain | `accept_headers` skipped `sync_state` on partial failure | s | SX1 | fixed `9578517` | done | none | none |
| R1-C5, R9-6, R10-12, R12-14, R8-22 | Low | PI | Chain | PoW cache keyed by header only and unbounded; caches rejected headers | s | SX1 (keying fixed); SX2 C9 | partly `9578517` (seed-keyed); unbounded open | P2 | none | none |
| R1-C6 | Low | CV | Consensus | 32-bit decode divergence | s | SX1 | fixed `8097f66` | done | none | none |
| R1-C7 | Info | AL | Consensus | LWMA omits the 99/100 factor (deliberate; document it) | m | — | open (docs) | P3 | none | none |
| R1-C8 | Med | CT | Consensus | LWMA weight shaping by a majority miner; net gain unknown | m,u | SX1 C | open | P2 | none | none |
| R1-C9 | Med | PI | Consensus/ops | 360 s FTL with no skew detection: silent stalls | s | SX1 C | open | P2 (NTP in the operator checklist: P0 procedure) | none | none |
| R1-C10, R16-1, R16-15, R15-12, I4 F1, R7 kernel-id schedule | High (mainnet) | NI (rebuild/core) / PI (cand) | Consensus/arch | No activation-height schedule; every change needs a new genesis; future versions get peers banned | s | SX1 C (priority raised); SX2 C (P0 decision) | cand `58c7f6e` (schedule, branch id, header version = epoch); P2P non-ban and chain, mempool, wallet, miner integration open | P0 decision | CONS | v3 |
| R1-C11 | Info | PI | Docs | Stale consensus.md statements (PoW hash stored; 0.45 s; atomic apply; clock text) | s | — | partly `6ed731f` | P2 | none | none |
| R1-C12 | Info | AL | Consensus | A verifier panic makes a block permanently invalid on that node | s | — | open | P3 (`reconsiderblock`) | none | none |
| H1 (A10-H1) | High | CV | Chain | A withheld-body header stalls chain progress | s,t | — | fixed `9d689f0` (tests `fork_choice`, `withheld_body`; `after-h1.log`) | done | policy | none |
| M1 (genesis), R15-4 | High | PI | Testnet | Pre-mining from the public v2 genesis; FTL does not stop post-reveal pre-mining | m | SX2 C | open: owner chose a fresh v3 genesis; tool and procedure not built | P0 | CONS | v3 |
| R15-1 | High | CV | Testnet | v3 rules (canonical proofs) under the v2 identity | s | SX2 C | fixed `f6a52ca`; `e4a5634` marks the v2 identity check superseded (local) | done | none | v3 |
| R15-3 | Med | PI | P2P/wallet | Chain identity bound by network id only, not genesis (session KDF, wallet check) | s | SX2 C (P0) | partly `9d689f0` (store header), `f440c4b` (/info); session and wallet open | P0 | policy | v3 (free) |
| TreeFull (known) | Low | PI | Chain | `apply_block` panics if the PX tree is full; not checked in validation (unreachable) | s | — | open | P3 | CONS if checked | none |
| R12-2 | Med (testnet) / High (mainnet) | NI | Tx/consensus | Weight-0 v1 inputs in deploys and PX: about 12,100 CLSAGs per block, about 25–50 s | m,e | SX1 C (broader: any mempool user); SX2 C (P0 decision) | open (not on candidate) | P0 decision | CONS | v3 |
| R5-1, R6 TX-4, R7-11, R12-13, known "deploys act as cheap transfers" | Med | PI | Tx/PX | Deploys are underpriced (2/byte), permanent RAM state; crowd out the PX lane | s,m | SX1 C | cand `cc39795` (exact fee; `MAX_DEPLOY_BLOCK_BYTES` defined, **not enforced**) | P1 (P2 for the closed trial) | CONS | v3 |
| R5-7, R7-6 | Low | CT | PX | Duplicate program ids in one deploy; the first budget wins | s | SX1 C | cand `79b874e` | P2 | CONS | v3 |
| R7-5 | Low | PI | PX | Deploy budgets above the proving limits were registrable (unprovable) | s | SX1 O (as DoS); valid tightening | cand `abee421` | P2 | CONS | v3 |
| R6 MP-7, known C4 front-running | Med–High | PI | Tx/mempool | Stem relay or miner copies a victim output key, invalidating it forever for one fee; PX victims re-prove | s,t (`forge_with_output_key`) | SX1 CC (option C needs 4 corrections; option B equal) | open (owner decision) | P0 decision | CONS | v3 |
| R6 TX-1 | Low | CV | Tx | Intra-transaction duplicates classed contextual | s | — | fixed `b33a1ce` | done | policy | none |
| R6 TX-2, known "invalid-CLSAG spam unpenalized", tx review H1 | Med | CV | Tx/P2P | Invalid signatures over real rings cost CPU for free | s | SX1 C | fixed `12ce4cb` (burial ≥ 10) and `54c4827` (≥ 60 blocks) | done | policy | none |
| R6 TX-3, known "stateless after contextual" | Low | CV | Tx | Range proof checked after CLSAGs in mempool paths | s | — | fixed `b33a1ce` (differential test over 42 transactions) | done | policy | none |
| R6 TX-5, R2-C1 | Low | CV | Crypto/wallet | Transfer and coinbase hedge contexts omitted payments, fee and ring | s,m | — | fixed `b7d0d3a` | done | none | none |
| R6 TX-6 | Info | PI | Tx | Repeated re-encoding of 2–4 MB PX transactions | s | — | open | P3 | none | none |
| R6 MP-1, R8-1, R16-7, known "chain lock on async threads", "block processing on read loop" | High | PI | Node/P2P | Global std mutex held for PoW, CLSAG, BP+, PX and unbounded `sync_state`; taken on tokio workers | s | SX2 CC (worst case is R12-2, not 3.4 s) | partly `12ce4cb` (admission order, budgets), `d374ef3`; bound, off-async reads and actor open | P0 (bound + off-async, "P0-7") | none | none |
| R6 MP-2 | Low–Med | PI | Mempool | PX proofs verified twice on the stem path and again after reorgs | s | — | partly `12ce4cb` (pooled replays unverified) | P2 | none | none |
| R6 MP-3, known "full revalidation after reorg" | Med | PI | Mempool | About 136–218 s of CLSAG work under the lock for a full pool after any reorg | m,e | — | open | P2 | none | none |
| R6 MP-5, R5-2, I4-2 | Med | AL | Mempool/PX | No PX fee market; fixed-price lane congestible (about 0.27 BLK/block); deploys outrank PX | m | SX1 C | open (policy FIFO part not done) | P1 policy; P3 consensus | policy / CONS | none / new |
| R6 MP-8 | Low | PI | Docs | Mempool docs stale (conflict keys, missing test file) | s | — | partly `16659ee` (blocks.md §7) | P3 | none | none |
| R6 MP-9 | Low | PI | P2P | Stem keys omit output keys and contract ids | s | — | open | P2 | policy | none |
| R6 R-FEE1 | Low | Def | Economics | v1 overpayment is a fingerprint; no priority tiers | s | SX1: not in v3 | deferred | P3 | CONS | new |
| F1 (mempool output keys) | Med | CV | Mempool | Output one-time keys missing from conflict keys could stall templates | s,t | — | fixed `16659ee` (`mempool_conflicts` 10/10) | done | policy | none |
| Known "no mempool expiry" | Low | NI | Mempool | No expiry | s | — | open | P2 | policy | none |
| R16-5 | Med | PI | Architecture | Rules restated in 4–6 places per kind (F1 was one instance) | s | — | open (effects model) | P2 | none | none |
| R10-2, R16-6 | Med | PI | Node | Poison recovery continued from a half-applied state; false comment | s | SX2 C (upgraded to P0) | partly `35b7cb9` (node lock fatal); p2p `net.rs:323,442,446` still recover | P0 | none | none |
| R16-8 | Low–Med | CT | Chain | Mempool used as PX proof cache; breaks under verifier schedules or mutable registry | s | — | open | P2 (before a second verifier) | none | none |
| R16-9 | Med | AL/Def | Architecture | No state commitment; divergence is silent | s | — | open (node-local digest proposed) | P2 / P3 | none, then CONS | none / activation |
| R16-4 | Med | PI | Architecture | No separable consensus core; wallet and prover modules define consensus constants (`CIPHERTEXT_BYTES`) | s | — | open | P2 | none | none |
| R16-2, R13 T-3, R14 D-2, R2-C11 (part) | High | PI | Testing | No golden corpus or known-answer vectors; the LWMA mutant `(n+1)→n` survived | m,s | SX2 C | partly `f6c98c3` (consensus and chain golden vectors, independent derivation), `f440c4b` (fingerprint pin); golden chain corpus, golden PX proof, Hk/node vectors open | P0 (freeze after v3) | none | none |
| R16-3 | Med–High | PI | ZK/deps | Proof wire format is the Plonky3 serde layout via caret-pinned postcard | s | SX2 C | fixed `249d4f0` (exact pins), `9ddaddd` (`--locked`); own codec P2 | done (pins) / P2 | none | none |
| R16-11, R7-10 | Low | PI | Contracts/crypto | Wasm contracts in the default workspace; 1,037 lines of unused crypto in the consensus crate | s | — | open (owner decision on R7 option D) | P2 | none | none |
| R16-12 | Med (hygiene) | NI | Repo | 118.6 MB tracked `legacy/` and `research/`, including build artifacts | s | — | open | P3 | none | none |
| R16-13, R15-6, known "kernel ELF embeds a Windows path" | Med | PI | ZK/build | Kernel id depends on the checkout path and OS; located panics embed `px-core\src\hash.rs` | s | SX1, SX2 C | partly `9ddaddd` (fixed-path build, ids unchanged); neutral rebuild open | P0 | CONS | v3 |
| R16 §5 | High (if packaged) | CV | ZK/node | A `panic = abort` build turns malformed proofs into crashes | s | SX2 | fixed `5888d4c` | done | none | none |
| R9-1 | Info | CV | PoW | No semantic deviation from RandomX v1 found | s,t | SX2 U beyond vectors | — | — | none | none |
| R9-3, R9-R5 | Med | CV | PoW | x87 targets would split silently | s | SX2 | fixed `8097f66` | done | none | none |
| R9-4 | Low | AL | PoW | 32-bit full mode cannot allocate the dataset | s | — | superseded by the 64-bit-only guard `8097f66` | done | none | none |
| R9-5 | Low | CT | PoW | ARM64 uses software AES single rounds without the cfg flag | s | — | open (docs) | P3 | none | none |
| R9-7, R9-R7, R13 T-8, known "no ARM64 CI" | Med | NI | PoW/testing | No aarch64 or big-endian CI; no reference corpus; FPU not differentially tested | s | SX2 C | open (per-device hash check P0 procedure) | P1 | none | none |
| R9-R4, known "no next-dataset prebuild" | Low | NI | Mining | Every full-mode miner stalls about 3–20 min at the same seed height | s | SX2 C | open | P2 | none | none |
| R9-R6 | Med | NI | PoW | No independent oracle for `fpu.rs` (`rustc_apfloat`) | s | — | open | P2 (P1 before FPU optimization) | none | none |
| R9-R2 | Med (perf) | NI | PoW | Safe-Rust performance programme (SoA dataset, decode, scratchpad) | e | — | open | P2 | none | none |
| R9-9 | Low | CT | Mining | 15 s template refresh wastes about 6% of hash power | m | SX2 C | open | P2 | none | none |
| R9-14 | Info | AL | Mining | Miner trusts its node's difficulty and seed | s | — | open (docs) | P3 | none | none |
| R15-9, R15 C2, known "seed switch tested with short epoch only" | Med | CT | Testnet | Real switch at height 2113 never exercised with full-mode miners | s | SX2 C | open: `C:/bszkeval/seedrun` reached about height 42, logged a transient "stuck" note, no summary | P0 | none | none |
| F2 | Low | CV | Crypto | CLSAG nonce hedge bound only part of the transcript | m,t | — | fixed `f677e55` | done | none | none |
| R2-C2 | Med | CV | Crypto | PX delivery randomness (`r`, ML-KEM coins) not hedged | s,m | SX1 C | fixed `b7d0d3a` | done | none | none |
| R2-C3 | Low | CV | Crypto | PX builder hedged with an all-zero secret | s | — | fixed `b7d0d3a` | done | none | none |
| A21 residual | Low | PI | Crypto/PX | PX witness randomness (`rcm`, dummy inputs, empty-slot owners) not hedged | s | — | WIP `a25-pxhedge` | P2 | none | none |
| R2-C4 | Low | AL | Crypto | Coinbase hedge secret is per-process OS randomness | s | — | open | P3 | none | none |
| R2-C5 | High once contracts integrate; Info now | PI | Crypto | Membership nonce: two signatures leak the key | m | SX1 C | open (no consumer) | P1 before any contract use | none | none |
| R2-C6 | Med (claim) | CT | Crypto/PX | Hk node without feed-forward; the "124-bit collision" comment is false; tree binding about 2^124 via anchoring | m | SX1 CC (guest-only change, about +2–3k cycles) | open (comment still false; v3 decision) | P1 docs; P0 decision | CONS if changed | v3 |
| R2-C7 | Med (long-term) | AL | Crypto | Poseidon2-BabyBear margin +7.5%; hash agility | s,a | SX1 C | open | P2 | CONS (future) | new/pool migration |
| R2-C8, R5-6, R11-W5 | Low | AL | Crypto/wallet | PX view tag is ECDH-only: post-quantum recipient linkage filter | m | — | open | P3 (docs P1) | none | none |
| R2-C9 | Low | CT | Crypto | Delivery combiner is not X-Wing (V and H(ek) omitted); identity `V` accepted | s | SX1 (ship with the v3 wallet) | partly `22ad441` (docs); v2 label and identity-V rejection open | P2 | none | none |
| R2-C10 | Low | PI | Crypto | Redacting `Debug` and zeroization gaps | s | — | partly `b7d0d3a` (best effort) | P2 | none | none |
| R2-C11 | Low–Med | PI | Crypto/testing | No RFC 9496, FIPS 203 or RFC 7693 known-answer vectors; no pinned BP+ proof; no Hk vectors | s | — | partly `f6c98c3` | P2 (Hk and node vectors P0 with v3) | none | none |
| R2-C12, A14 | Low | AL | Crypto/deps | `ml-kem` 0.3.2 unaudited; decapsulation timing unknown | a | — | open | P2 | none | none |
| R2-C13 | Info | AL | Crypto | Unprefixed concatenation; `len` not reduced; modulo bias | m | — | open | P3 | none | none |
| R2-C14, R3-12, I4-6 | High (strategic) | NI | Crypto | v1 fully exposed to a CRQC; latent recoverability via seed-derived keys; I4-6 gives a recovery proof without in-circuit EC | m | SX1 C | open (spec draft proposed) | P1 docs / P3 impl | CONS (future) | activation |
| Known "Janus anchor is our own construction" | Med | CT | Crypto | Carrot-like anchor, not externally reviewed; Theorem 1 scope notes | m | — | open (docs) | P2 | none | none |
| M1 (A14 dependency: FRI witness), M2 | Med | CV | ZK | Unbound FRI commit witnesses and empty optional openings made proofs, and so tx ids, relayer-malleable | s,t | SX1 | fixed `4b277cd` (a narrowing rule; part of the v3 rule set) | done | CONS | v3 |
| M3, R4-02 | Low | PI | ZK | FRI folding schedule is chosen by the prover and bound after the betas (not relayer malleability) | s | SX1 CC | open (proposed for v3) | P0 decision | CONS | v3 |
| R4-01 | Low (per SX1) | CT | ZK/docs | Security calculator fed pre-ZK height; 0.7 over-reports; the Johnson "≥ 123" is not established | s | SX1 CC (severity low; docs only) | open | P1 docs | none | none |
| R4-03 | Info | AL | ZK | Circuit accepts more READs and outputs than the interpreter ("exactly" is false) | s | — | open (docs) | P3 | none | none |
| R4-04 | Low | CT | zkVM | ISA decoder correct but no exhaustive or riscv-tests evidence | s | — | open | P2 | none | none |
| R4-06, I1-F3 | Med (perf) | NI | ZK | Prover built without SIMD (scalar BabyBear) | s | SX1 C (prover only, or a differential verifier) | open | P2 | none | none |
| R4-07, R4-08, R4-09 | Low | Def | ZK | Degree-5 CPU, thin tables, query and extension coupling | s,e | — | deferred | P3 | CONS | new |
| R4-10 | Med (maintenance) | Def | ZK | Plonky3 0.7 pinned; 0.8 is a transcript-breaking hard fork | s | SX1 C | deferred | P3 | CONS | new verifier |
| R4-11 | Low | NI | ZK | No circuit or AIR version in the transcript | s | SX1 C (free at v3) | open (proposed v3) | P0 decision | CONS | v3 |
| R4-12 | Low | PI | ZK/testing | Envelope tests assert only Johnson ≥ 100 on unshaped toys | s | — | open | P2 | none | none |
| ZK-F3 | Low | CV | ZK | Reused `VerifierConfig` could reject honest proofs (latent) | s,t | — | fixed `f36b909` | done | none | none |
| ZK-F4, R7-5 (cost part) | Med | NI | ZK | Adversarial verifier cost unmeasured | u | — | open | P0 evidence (R15 C4) | none | none |
| Known "widest two-function proof size unmeasured" | Med | NI | ZK/PX | Widest statement not measured against `MAX_PROOF_BYTES`; must precede pinning v3 ids | u | SX1 (must close before v3) | open | P0 | none | none |
| Known "statistical ZK conditional" | Info | AL | ZK | ZK holds only under zk-coverage.md §3 conditions | m,a | — | accepted | — | none | none |
| Known "PX output words: docs field-canonical, code raw u32" | Low | PI | PX | Documentation and code disagree on the function output word encoding | s | SX2 P0-1 row (f) | open (decision) | P0 decision | CONS | v3 |
| PX-F4, R5-15 (B′), I2-F1 | Med | AL/Def | PX | Caller chooses `rcm` of function-specified outputs; griefable; B must keep a private-input `rcm` | s | SX1 (defer) | deferred; docs `9a7c6bb` | P1 docs | CONS (when done) | new |
| PX-F5, R5-10 | Med | PI | PX | Contract outputs not forced to `owner = 0`: burnable records | s | SX1 (include) | open (v3 decided; not on candidate) | P0 | CONS | v3 |
| Known "approval not tied to value" | Low | AL | PX | Contract-author footgun | s | — | docs; SDK lint proposed | P2 | none | none |
| P-1/P-2 | Med | CV | Wallet/PX | Vault wallet checks (program set, budget) | s | — | fixed `22ad441` | done | none | none |
| R5-3, R7-1 | Med (capability) | NI | PX | Functions have no clock: no timeouts, refunds or HTLCs | s | SX1 CC (capability, not security; choose one mechanism) | open | P3 (docs P0) | CONS | new/activation |
| R5-4 | Med (privacy) | PI | PX | Share exposes `cm` and `rho`; docs say it "reveals nothing" | s | SX1 C | open (doc still claims it) | P0 docs; P2 fix | none | none |
| R5-5, R11-W6 | Med (UX) | PI | PX/wallet | Two inputs, no consolidation; misleading insufficient-funds error | s | SX2 C | open | P1 | none | none |
| R5-9, R7-4 | Med–High (design) | AL | PX | Shared-state contracts: at most about one update per 16 blocks | s,m | SX1 C | accepted (docs) | P0 docs | — | — |
| R5-11 | Med (mainnet) | Def | PX | About 5.9 GB/day at capacity; no pruning while PX-F3 re-verifies | m | — | deferred | P3 | none | none |
| R5-12 | Low | AL | Wallet | Expired-anchor retry republishes the same nullifiers | s | — | open | P3 | none | none |
| R5-13, R11-W4 | Med (architecture) | NI | PX/wallet | Spend authority = `sk` in the proof: no safe delegated proving, no hardware wallet | s | SX2 C | open (docs P1) | P3 | CONS | new |
| R5-14, R12-10 | Low | PI | Docs | Docs say about 4 PX per block; the true figure is 3 (1 at maximum size) | m | SX2 C (still open) | open (8 occurrences in HEAD) | P0 docs | none | none |
| R3-7 | Med | AL | PX/privacy | Holders of an opening can compute contract-record nullifiers | s,m | SX2 W (already documented at px.md:595) | public-`rcm` corollary open (docs) | P2 docs | none | none |
| PX-F1, PX-F2, PX-F3, R10-6, R10-7, R12-1, R12-4 | Med (testnet) / Crit (mainnet) | AL | Storage/PX | All bodies, undo (about 4.2 KB/block) and state in RAM (×4.5 for v1); restart re-validates all PX proofs | s,m | SX2 CC (IBD transient bounded by the 256-body window) | open | P2 (docs P0: expected RAM and replay time) | none | none |
| Known "witness `sk` buffers not zeroized" | Low | PI | PX | — | s | — | open | P3 | none | none |
| C-1 … C-5 (Wasm) | Med | PI | Contracts | Per-transaction memory, unbounded module cache, limits beyond the profile, encoder lengths, commit panics | s | — | open; moot under option D | P3 (if kept) | none | none |
| R7-2 | High (capability) | NI | PX contracts | No authorization primitive except a shared secret | s | SX1 C (capability) | open | P2 (SDK pattern) | none | none |
| R7-3 | Med | NI | PX contracts | Functions cannot communicate (no composition) | s | — | open | P3 | CONS | activation |
| R7-7 | Med | AL | PX contracts | 2×2 shape, 248 bits of state per record | s | — | accepted | P3 | CONS | new |
| R7-8 | Med | PI | PX contracts | Up to 256 free public output words: a leak channel | s | SX1 C | open | P2 | policy | none |
| R7-9 | Med | NI | PX contracts | Contracts not auditable by users (no manifest or reproducible build) | s | SX1 C | open | P2 | none | none |
| R7-12 | High (strategic) | Def | Contracts | Wasm would create a weaker second privacy tier | s | — | owner decision (option D recommended) | P0 decision (scope) | none | none |
| Known "wasmi `unsafe` unreviewed", wasmi 0.38 unsupported | Med | AL | Contracts/deps | About 120 `unsafe` blocks in wasmi | s | — | open | P2 (remove from the default build) | none | none |
| Known "header queue unbounded" | Med | CV | P2P | Batches from departed senders queued without bound | s,t | — | fixed `12ce4cb` (`the_header_queue_is_bounded_across_reconnects`) | done | policy | none |
| N-4 | Med | CV | P2P | Concurrent handshakes bypassed `max_inbound` and `max_per_ip` | s,t | — | fixed `12ce4cb` | done | policy | none |
| Known "tip announcement racing GetHeaders" | Low | CV | P2P | Honest sender charged 10 points | t | — | fixed `12ce4cb` | done | policy | none |
| Known "tx_announcers leak, known_txs unbounded" | Low | CV | P2P | — | t | — | fixed `12ce4cb` (cap 50,000; moves on disconnect) | done | policy | none |
| Known "re-request loops", R8-12 (part) | Med | PI | P2P | Non-advancing replies caused loops; scheduling trusts `Version.height` | s,t | SX2 C | partly `12ce4cb`; best-known-header scheduling open | P1 | policy | none |
| Known "bans.json save", R10-15 | Low | PI | P2P | Ban list not saved on add; no fsync before rename | s | — | partly `12ce4cb` (saved on add); fsync open | P2 | none | none |
| Known "local tx fluffed with no stem peer", R3-5 (item 2) | Med (privacy) | CV | P2P | Origin fluffed its own transaction when it had no stem peer | s,t | SX2 C | fixed `12ce4cb` (`a_local_transaction_waits_for_a_stem_peer`) | done | policy | none |
| Known "global PX relay budget exhaustible", SX2 §0.4, R3-5 (item 1), tx review M2 | Med | PI | P2P | Budget drained by junk or replayed PX before cheap checks: a black hole that forces self-fluff | s,t | SX2 (new vector) | fixed `12ce4cb` (token after cheap checks); residual: a mempool-conflicting PX still consumes a token | P1 (residual) | policy | none |
| R8-2, R10-1 | High | CV | P2P/storage | Unsolicited blocks fully processed; cheap height-1 siblings with 9 MB bodies stored forever | s,t | SX2 C | fixed `12ce4cb` (`an_unrequested_block_of_an_unknown_header_is_not_stored`), `9d689f0` (low-work body policy) | done | policy | none |
| R8-3, N-7, N-8 | High (public) | PI | P2P | One source reaches all new buckets; no address rate limit; eclipse (Monero CCS'26 precedent) | s,m | SX2 C | open | P1 (P0-pub) | none | none |
| R8-4 | Med–High | CV | P2P | Group diversity not enforced within one selection round | s,t | SX2 C | fixed `12ce4cb` | done | none | none |
| R8-5 | High (Tor) | PI | P2P | Each onion is its own group; no v3 checksum validation | s | SX2 C | open | P1 (P0-pub for Tor) | none | none |
| R8-6 | Med–High | PI | P2P | SOCKS5 without stream isolation; one exit can MITM all clearnet peers | s,a | SX2 C/U | open | P1 | none | none |
| R8-7 | High | CV | P2P | Stem conflict check after full `check_tx`: valid double-spend variants cost free CPU | s,t | SX2 CC (the mempool path was already safe) | fixed `12ce4cb` (`conflicting_stem_transactions_are_not_verified`) | done | policy | none |
| R8-8 | Med–High | PI | P2P | Invalid-PoW single headers from rotating IPs cost one hash each on the single worker | s | SX2 C (gate does not cover invalid PoW) | mitigated 2026-10-04: outbound-first header tiers and a per-class budget of failed hashes (docs/p2p.md §6; RT-HDRDOS fixes) | P1 | none | none |
| R8-9 | Med–High | CV | P2P | Block download timeouts banned honest slow peers | s,t | SX2 CC | fixed `b12b024` | done | policy | none |
| R8-10 | High (public) | PI | P2P | Outbox is 64 messages (about 605 MB); no upload budget; frame preallocation | m,s | SX2 CC (one large block suffices; receive side is lazy) | open | P1 (P0-pub) | none | none |
| R8-11 | Med | PI | P2P | Control messages queue behind bulk blocks | s | SX2 C | open | P1 | none | none |
| R8-13 | Med | PI | P2P | Seed fallback only when addrman empty; no timestamps, feelers, anchors | s | SX2 C | partly `12ce4cb` (fallback when no outbound) | P1 | none | none |
| R8-14 | Med | PI | P2P | Unknown message type = ban; `Version` not extensible | s | SX2 C (P0) | open (p2p.md:130 still says "violations") | P0 | none | none |
| R8-15 | Med | PI | P2P | Single FIFO header worker: head-of-line blocking | s | — | open | P1 | none | none |
| R8-16 | Med (privacy) | PI | P2P | Independent trickle timer per inbound peer; invs in arrival order | s | SX2 C | open | P1 | none | none |
| R8-17 | Med (privacy) | AL | P2P | The origin's embargo can fire first (conditional on a black hole; about 10–12% for slow PX stems) | m | SX2 CC | open | P2 | none | none |
| R8-18, R3-10, I3 §3.5 | Med–High (privacy) | AL | P2P/PX | Unpadded 2.2 MB upload reveals PX origin to the ISP, even over Tor | m,s | SX2 C | open (not in docs) | P0 docs | none | none |
| R8-19, I3-2 | Med | PI | P2P | `--proxy` without `--proxy-only` listens on clearnet; onion `listen` sent to clearnet | s,t | SX2 C | partly `12ce4cb` (onion only over Tor; dual-homed warning); clearnet listen default open | P1 | none | none |
| R8-20, R8-21, I3 §3.7 | Low–Med | PI | P2P | Transport fingerprintable and probe-able; no optional authentication or session id | s,m | — | open | P3 (P2 session id) | none | none |
| N-5, R8 §3.4 | Med | PI | P2P | Exact-IP bans; no /64 or /16 inbound caps | s | SX2 O for the trial | open | P1 (P0-pub) | none | none |
| N-6, I3 §3.4 | Med | PI | P2P/Tor | All Tor inbound = 127.0.0.1: shared limits; one ban blocks all | s | — | open (documented `6ed731f`) | P1 | none | none |
| N-9 | Med | NI | P2P | No inbound eviction | s | — | open | P1 (P0-pub) | none | none |
| R3-4 | Med | CV | P2P/privacy | Dandelion++ q = 0.1 paired with Monero's 39 s embargo | s | SX2 C | fixed `12ce4cb` (q = 0.2, docs) | done | policy | none |
| R3-6 | Med (Tor) | NI | P2P/privacy | GetAddr fingerprint links onion and clearnet identities | s | SX2 C | open | P1 | none | none |
| I3-1 | Med–High (privacy) | CV | P2P/privacy | InvTx probe revealed stempool membership and forced fluff | s,t | SX2 C | fixed `12ce4cb` (`announcing_a_stem_transaction_neither_reveals_nor_fluffs_it`) | done | policy | none |
| I3-3 | Low | AL | P2P/privacy | Traffic-rate freedom lets peers watermark Tor links | s,a | — | open | P3 | none | none |
| I4-5 | Info (design rule) | — | P2P | Compact blocks must never reconstruct from the stempool | m | — | rule recorded | P3 | none | none |
| I4-7 | Low | AL | P2P | Transport is exposed to harvest-now-decrypt-later | s | SX1: not v3 | open | P3 | none | none |
| R10-3 | Med | CV | Storage | `blocks.dat` had no header (network, genesis) | s,t | SX2 C | fixed `9d689f0` | done | none | none |
| R10-4 | Med (privacy) | NI | RPC | No Host check, auth or CORS: DNS rebinding reads `/info`, POSTs `/tx` and `/block` | s,a | SX2 C | open | P1 (firewall/loopback procedure P0) | none | none |
| R10-5, R12-3 | Med | PI | RPC | `/px/commitments` cloned every record under the lock; `/distribution` O(height); handlers on async workers | s | SX2 C | partly `d374ef3` (paginated slice); off-async and `/distribution` open | P1 | none | none |
| R10-8 (a) | Med | CV | Storage | Tail heuristic could silently drop valid data | s | SX2 | fixed `9578517` | done | none | none |
| R10-8 (b, c) | Low | PI | Storage | Quadratic torn-tail scan; load peak about 2× file | s | — | open | P2 | none | none |
| Known "poisoned store loops downloads", "replay order and tie-breaks" | Med | CV | Storage/chain | — | s,t | — | fixed `9578517`, `9d689f0` | done | none | none |
| R10-9 | Low | PI | Node/deploy | SIGTERM not handled; Docker lacks `STOPSIGNAL` and `HEALTHCHECK` | s | — | open | P2 | none | none |
| R10-10 | Low (privacy) | PI | Node | Debug logs record stem routing; info logs record peer IPs | s | — | open (bug template fixed `58f25ec`) | P2 (P1 Tor) | none | none |
| R10-11 | Low | PI | RPC | No RPC timeouts, concurrency or cost limits | s,a | — | open | P2 | none | none |
| R10-13 | Low | AL | Docs | Docker docs put the wallet in the node volume | s | — | open | P3 | none | none |
| R10-14, A14 | Info | AL | Deps | fs2 and env_logger stale; log strings with source indentation | s | SX2 (same class in the `f6a52ca` message) | open | P3 | none | none |
| R11-W1 | High (funds) | CV | Wallet | Generated vault secret lost on an `Uncertain` submission | s | SX2 C | fixed `22ad441` | done | none | none |
| R11-W2, R11-W3, I2-R1, I2-F3 | Med | NI | Wallet | No PX viewing-key hierarchy; seed has no version, birthday or network; range-scoped incoming-only package possible | s | SX2 C8 (P1; not in the consensus bundle) | open (WIP `a26-wallet2` inferred) | P1 (decide before persistent users) | none | none |
| R11-W7 | Med (UX) | NI | Wallet | No confirmation, fee preview, status or history | s | SX2 C | open | P1 | none | none |
| R11-W8, R12-8 | Med (scale) | PI | Wallet | PX tree rebuilt from genesis on every sync and spend; commitments stored as JSON hex | s,m | SX2 C | open | P2 | none | none |
| R11-W9, R12-7, I1-F2, I3 §3.9 (b) | Med (scale) | NI | Wallet/RPC | Wallet downloads full blocks as hex, proofs included (about 614 GB/year moderate) | s,m | SX1, SX2 C | open | P2 | none | none |
| R11-W10 | Low | PI | Wallet | v1 accounts are nominal; restore scans account 0 (W-F7) | s | — | open | P1 (remove or implement) | none | none |
| R11-W11, I2-F9 | Low | NI | Wallet | No sender records or payment proofs; proofs would be permanent | s | — | open | P2 | none | none |
| R11-W12 | Low | CT | Wallet | KDF header allows 4 GiB and t ≤ 100 (OOM on load) | s | — | open | P2 | none | none |
| R11-W13 | Low | CT | Wallet | Mnemonic entry case-sensitive and blind | s | — | open | P2 | none | none |
| R11-W14 | Info | AL | Wallet | Fixed PX address roles (0 = deposit, 1 = change) | s | — | open | P2 | none | none |
| R11-W15 | Med | NI | Wallet | No view-only, watch-only or cold signing | s | — | open | P2 | none | none |
| M-1, M-2, L-1…L-6 | Med | CV | Wallet | Huge index bricked the file; scan window did not grow; file permissions; secrets on the command line; RPC client unbounded | s | — | fixed `22ad441` | done | none | none |
| R3-9, known "RPC client plaintext, no Tor or TLS" | High (remote-node users) | PI | Wallet/RPC | Remote node or on-path observer sees the transaction, the ring superset and the birthday | s | SX2 C | partly `22ad441` (caps, schemes); SOCKS open | P1 | none | none |
| I3 §3.9 (a) | Med (privacy) | NI | Wallet | Local output index would remove the `/outputs` ring-superset query | s,m | SX2 C5 (dominates R3's rule) | open | P1 | none | none |
| W-F6, W-F7, W-F13, W-F15 | Low–Med | PI | Wallet | No PoW check; restore account 0 only; `first_output` trusted; create height falls back to 1 | s | — | open | P2 | none | none |
| R3-1 | High (privacy, early chain) | CT | Wallet/privacy | Coinbase maturity removes young decoys; young real spends stand out | s,e (simulated) | SX2 CC | open | P1 | none | none |
| R3-2 | Med | CV | Mining/privacy | Persistent nonce start clustered blocks by miner | s,m | SX2 C | fixed `f331642` | done | none | none |
| R3-3 | High early / Low later | AL | Privacy | Coinbase-dominated rings; "effective ring 1.9" needs all miners (m = 1); about 14 for 1 of 7 miners | e (simulated) | SX2 CC | open (docs P0; wallet P1) | P0 docs | none | none |
| R3-8 | Med | AL | PX/privacy | Bridge amounts public; round-trip linkage | s | SX2 C | accepted (docs exist) | P2 (wallet hygiene) | none | none |
| R3-11, I4 §5 (I4-8) | Med (strategic) | NI | Privacy/consensus | No shielded coinbase; I4 proposes delayed-insertion maturity | s,a | SX1, SX2: defer (activate later by height) | deferred | P0 decision (defer) | CONS | activation |
| R3-13 | Low–Med | PI | Wallet/privacy | No merge avoidance for co-spent outputs | s | — | open | P2 | none | none |
| R3-14 | Med (claims) | PI | Docs | P7 and N4 overclaims; "as deployed in Monero" | s | SX2 CC | partly `6ed731f`, `12ce4cb` (D++ text); simulated figures still to publish | P0 docs | none | none |
| R13 T-1 | High | PI | Testing | No non-malleability oracle in fuzz or mutation tests | s | SX2 O for P0 (instance fixed) | partly `f6c98c3` (15/15 mutants caught) | P1 | none | none |
| R13 T-2 | Med | PI | Testing | Fuzz campaigns ran without overflow checks or debug assertions | s | SX2 C (P0) | partly `9ddaddd` (script `-O -a`); re-run not recorded, verify | P0 | none | none |
| R13 T-4 | Med | PI | Testing | No property-based framework (stale reason) | s | — | open | P1 | none | none |
| R13 T-5 | Med | NI | Testing | No deterministic simulation or model checking (H1 rule) | s | — | open | P1 (stateright model) / P2 | none | none |
| R13 T-6, T-7 | Med–High | PI | Testing | Fuzzing misses stateful surfaces and the verifier; corpora on one machine | s | — | open | P1 | none | none |
| R13 T-9 | Med | PI | Testing | Labnet honest-only, at most 62 min; no kill/restart or skew | s | — | open | P1 | none | none |
| R13 T-10, R15-5, R14 D-6 (release part) | Med–High | PI | Release | No tags, no signing, no artifacts; floating Docker base; unpushed work | s | SX2 C (P0; no root toolchain file, C1) | partly `9ddaddd` (Docker pinned, `.dockerignore`), push up to `54c4827`; signed tags open | P0 | none | none |
| R13 T-11, T-12, T-13, T-15 | Med | NI | Testing/supply | No cargo-deny or vet, no mutants or coverage, no CI tiers, no privacy regression tests | s | — | open (a fluff-without-stem test now exists `12ce4cb`) | P1 / P2 | none | none |
| Known CI items | Med | PI | CI | Fuzz smoke could pass with zero fuzzing; no overflow runs; no `--locked`; fuzz lock not audited; labnet and binaries never in CI; stress test ignored; `third_party` tests not run | s | — | partly `9ddaddd` (first four); labnet, binaries, `third_party` open | P1 | none | none |
| R14 D-1 | High (mainnet) | PI | Docs/spec | PX/ZK consensus layer normative only by code | s | SX2 C | open | P1 (with v3) | none | none |
| R14 D-3, D-4, D-5 | Med | PI | Docs/governance | No single status source; fragmented ids; no decision log or change process in the repo; "AUDIT" naming | s | SX2 C | open | P1 | none | none |
| R14 D-6, R15-8 | High (operability) | CV | Node/ops | No build or rule identification (`--version` = 0.1.0) | s | SX2 C | fixed `f440c4b` (fingerprint, commit, genesis; no dirty flag) | done | none | none |
| R14 D-7 | Med | PI | Docs/ops | No operator sizing, upgrade, backup, monitoring or log-privacy guidance | s | SX2 C (subset P0) | partly `6ed731f` (testnet.md §12) | P0 (sizing, replay time) | none | none |
| R14 D-8 | Med (privacy) | CV | Docs | Legacy, privacy-unsafe issue template | s | SX2 | fixed `58f25ec` | done | none | none |
| R14 D-9 | Low–Med | PI | Docs/DX | Toolchain story, guest target inconsistency, contract onboarding | s | — | partly `9ddaddd` | P2 | none | none |
| R14 D-10 | Med (legal) | NI | Docs | No LICENSE at the root | s | SX2 C | open | P0 decision | none | none |
| R14 D-11, D-12, D-13 | Low–Med | PI | Docs | No ARCHITECTURE.md; evidence not bound to builds; normative text mixed with commentary | s | — | open | P1 / P1 / P2 | none | none |
| I1-F1 | Low (claims) | CV | Docs | Neptune Cash missing from prior art | a (web) | SX1 | fixed `58f25ec` | done | none | none |
| I1-F4 | Info | AL | ZK | Proof cost is driven by generic zkVM width, not kernel work | s,e | — | accepted (docs) | P3 | — | — |
| I2-F2 | Med (design rule) | NI | PX | Owner tags are derivable from FVK material: authority-conferring programs must derive keys from `sk` | m | SX1 C | rule not yet written | P2 | none | none |
| I2-F4 | Low | AL | Crypto | Scoped-membership anonymity is classical (1-of-16, DDH) | m | — | open (docs) | P2 | none | none |
| I2-F5 | Low | AL | PX | Contract id tied to the deployer's first key image | s | — | open (wallet warning) | P3 | none | none |
| I2-F6 | Med | AL | PX | About 2,160 PX transactions per day chain-wide bound on-chain governance | m | SX1 C | accepted | — | — | — |
| I2-F7 | Info | NI | PX | No committed nullifier accumulator; a naive reserve proof leaks spend times | s | — | open (gap-tree spec P2) | P2 | none | none |
| I4-3 | Low | AL | Economics | Fees fixed in atomic units (price-insensitive) | s | — | open | P3 | CONS | activation |
| I4-10 | Info | AL | Mining | `MAX_COINBASE_OUTPUTS` = 16 blocks P2Pool-style payouts | s | — | open | P3 | — | — |
| R15-7 | Med | NI | Testnet | No supply-audit tool; the trial is the only moment a supply audit is possible | m,s | SX2 C (P0) | WIP `a27-supply` (inferred) | P0 | none | none |
| R15-11 | Med | NI | Ops | Windows desktop hazards (updates, sleep, w32time, antivirus) | a | SX2 U | open | P0 procedure | none | none |
| R15 §5.3 | Med | AL | Governance | Single maintainer, approver and signing identity | s | — | partly (pushed) | P1 (mirror, 2FA) | none | none |
| R15 §5.2 | Med (public) | NI | P2P/ops | No independent seeds | s | — | open | P2 (P0-pub) | none | none |

---

## 5. Recommendations

Priorities follow the brief:
- **P0:** critical before the trial;
- **P1:** high security;
- **P2:** hardening;
- **P3:** after the trial, or future.

"P0-pub" marks an item that is P1 for the closed trial but P0 before any public testnet. Each row gives: why, security impact, privacy impact, performance impact, complexity, consensus impact, testnet identity impact, and difficulty (S/M/L/XL).

### 5.1 P0: before the seven-device trial

| # | Recommendation (sources) | Why | Security | Privacy | Perf. | Complexity | Consensus | Identity | Diff. |
|---|---|---|---|---|---|---|---|---|---|
| P0-1 | **Owner signs the v3 decision table** (§6.3), then the chosen items are implemented on `v3/candidate`, rebased onto current `rebuild/core` (SX2 P0-1, R15 A2, SX1 §3) | "One identity" must be true. Every undecided CONSENSUS item costs another reset later | High + | + | none | Low (decisions); M–L (implementation) | **CONS** | defines v3 | S / M–L |
| P0-2 | **PX-F5 in the kernel; platform-neutral kernel.** No located panics in kernel paths (`px-core/src/hash.rs:81,82,126,226` asserts); a guard test that the ELF has no path strings; CI reproduces `kernel.id` identically on Windows and Linux. Do the rebuild **last**, after R2-C6 and PX-F5 (PX-F5, R15-6, R16-13, SX1 §3) | Burnable records; a consensus artifact that only one machine can reproduce | + | removes a personal path from consensus data | none | M | **CONS** (kernel and vault ids) | v3 | M |
| P0-3 | **Re-measure before pinning ids:** kernel budgets after PX-F5 and R2-C6, the widest two-function proof against `MAX_PROOF_BYTES`, and the adversarial verifier cost (ZK-F4) (SX1 §3 item 4, R15 C4) | Budgets carry about 6% headroom (R5 §3.1); a proof over the cap makes a function uncallable | + | none | none | Low | none (evidence) | none | S |
| P0-4 | **Genesis tool and procedure** (R15 §4): nonce = LE64(Blake2b-256("BlackSilk/genesis-nonce/v1" ‖ LE32(net_id) ‖ LE64(H) ‖ BTC hash in display order)[0..8]); `T_g` fixed *before* the beacon; 6 confirmations; dual independent verification; D0 from the measured honest hash rate, erring low (SX1); the 8 pinned tests | Removes anyone's pre-reveal head start and randomizes the first RandomX key; makes the launch verifiable | + | none | none | Low | **CONS** (genesis) | v3 | S |
| P0-5 | **Bind the genesis id** into the P2P session KDF (or a first encrypted frame) and into the wallet file's network check (R15-3) | Stops release-candidate, rehearsal and stale nodes and wallets from mixing silently | + | + (the wallet never reconciles against a foreign chain) | none | Low | policy (P2P protocol) | v3 (free) | S |
| P0-6 | **Forward-compatible P2P:** ignore unknown message types (charge the message budget only); allow `Version` trailing bytes or a TLV area; add `HeaderError::UnknownUpgrade` to the no-score arms with a WARN (R8-14, v3-upgrade-mechanism.md §2.2) | Must be in every v3 binary, or the first upgrade bans upgraded peers | + | features leak versions (bucket them coarsely) | none | Low | none | none | S |
| P0-7 | **Chain-lock liveness:** bound `sync_state` to N blocks per call; move `inner.chain()` off async threads (`spawn_blocking` as the interim) in `on_inv_tx`, `schedule_downloads`, maintenance and the RPC readers. Test that pongs keep flowing while 256 PX-bearing blocks connect (R8-1 a/b, R16-7, R10-5; SX2 P0-7) | The late joiner syncing PX blocks would otherwise stall its whole network stack | + | + (timing) | + | M | none (identical verdicts) | none | M |
| P0-8 | **Fail-stop on the remaining poison-recovery sites** (`p2p/src/net.rs:323,442,446`) (R10-2 residual, R16-6) | Silent state divergence would invalidate trial evidence | + | none | none | Low | none | none | S |
| P0-9 | **Decide R12-2** (charge the v1 part of PX and deploy transactions against `MAX_BLOCK_WEIGHT`, SX1's option (a)) **and enforce `MAX_DEPLOY_BLOCK_BYTES`** in validation and the template (it is defined but unenforced in `cc39795`) (R12-2, R5-1, SX1 §3) | A 25–50 s block stalls every node; deploys censor the PX lane | High + | none (P-7 untouched: the PX fee exceeds the v1 minimum for 64 inputs, SX1) | worst case → ≤ 3 s | Low | **CONS** | v3 | S |
| P0-10 | **Freeze the evidence on the final v3 rule set:** regenerate the golden vectors; add a golden PX transfer proof and a vault proof (decode, re-encode, verify); real-permutation Hk and node vectors; re-pin the consensus fingerprint (R16-2, T-3, D-2, SX2 P0-2) | Detects any accidental consensus change after the freeze; operators can compare rule sets | High + | none | CI minutes | M | none | none | M |
| P0-11 | **Fuzz evidence:** re-run the long campaign with `-O -a`, or strike the overflow claims from gate G9 (T-2, SX2 P0-10) | The existing 531 M executions say nothing about overflow | + | none | none | Low | none | none | S |
| P0-12 | **Release integrity:** push `e4a5634` and any later work; mirror to a second host; sign annotated tags `testnet-v3-rc` and `testnet-v3`; publish the signing fingerprint and the consensus fingerprint through two channels; `git diff rc..final` must touch only the genesis constants (R15-5, T-10, R15 B2; no root `rust-toolchain.toml`, SX2 C1) | Operators must be able to authenticate what they run | High + | none | none | Low | none | none | S |
| P0-13 | **Trial evidence runs:** a labnet regtest run past height 2400 with real RandomX and full-mode miners (the partial `C:/bszkeval/seedrun` does not count); a RandomX hash check per device class; a full workspace suite on the tagged commit (R15 C2/C3, T-8, SX2 P0-12) | The 2113 switch has never run at real parameters; no full-suite log on HEAD is in evidence | + | none | about 7 h of machine time | Low | none | none | S |
| P0-14 | **Trial tooling and procedure:** the supply-audit tool with mandatory retention of every wallet (R15-7); a per-device sampler with local alerts (R15 §6.1); trial end at max(96 h, height 2113 + 720) (R15-9); fresh data directories; Windows hygiene (R15-11); RPC firewalled to loopback (R10-4 interim); NTP (R1-C9); at least 8 GB RAM on proving devices; the expected restart replay time documented (R12-4) | The only end-to-end inflation check that is ever possible; a trial that measures what it claims | + | − (balances shared within the trusted group) | none | Low | none | none | S |
| P0-15 | **Documentation corrections:** 3 PX per block (1 at maximum size) in all 8 places (R12-10); K1 unattainable against JIT rx/0 miners (R1-C2, R15-2); PX upload size reveals the origin, even over Tor (R8-18, I3 §3.5); anonymity among 7 participants is not meaningful (R15 D4); simulated effective-ring figures with SX2's m = 1/7 correction (R3 §8, R3-3); correct the Hk node comment (R2-C6); correct the share claim (R5-4); "functions cannot see time; shared-state contracts are unsupported" (R7-1, R7-4) | The owner's policy against overclaiming | none | + (users understand the limits) | none | Low | none | none | S |
| P0-16 | **LICENSE** decision plus `license` fields in the workspace crates, and licence texts in `third_party` (R14 D-10) | Other people run the binaries; the RandomX BSD notice | none | none | none | Low | none | none | S (decision) |
| P0-17 | **Scope decision on Wasm contracts** (R7 option D): out of v1, and out of the default build (R7, R16-11) | Removes wasmi `unsafe` from the release supply chain; avoids a second privacy tier | + | + | build time ↓ | Low | none | none | S |

### 5.2 P1: high security (before public users; most can follow the trial)

| # | Recommendation (sources) | Why | Security | Privacy | Perf. | Complexity | Consensus | Identity | Diff. |
|---|---|---|---|---|---|---|---|---|---|
| P1-1 | **Addrman v2:** per-source bucket limit (two-stage hash); addr token bucket (0.1/s, burst 1,000); timestamps and terrible-address eviction; onion grouping by network plus 4 bits with v3 checksum validation; a HashMap index; a many-groups, one-source test (R8-3, R8-5, N-7/N-8; P0-pub) | Eclipse; the Monero CCS'26 precedent (I3 §3.4) | High + | eclipse → origin deanonymization | + (index) | M | none | none (`peers.json` gets a version) | M |
| P1-2 | **Connection manager:** inbound eviction; per-/64 and per-/16 caps; a dedicated onion inbound port tagged by network class; SOCKS stream isolation with random RFC 1929 credentials; network classes as state (stems, trickle timers, GetAddr caches, limits) (N-5, N-6, N-9, R8-6, R3-6, I3 §3.4) | Join resistance; the Tor exit MITM; linking dual-homed identities | + | High + | none | M | none | none | M |
| P1-3 | **Byte-accounted send path:** a per-peer byte budget with pause-processing; lazy `GetBlocks` serving; a global upload budget; control/bulk priority; incremental receive buffers (R8-10, R8-11; P0-pub) | OOM and upload amplification | High + | none | + | M | none | none | M |
| P1-4 | **Header-path hardening:** a priority lane for announcements; a per-peer unsolicited-PoW budget; best-known-header scheduling; RandomX cache built outside the mutex with a per-seed once-cell, capacity 3, tip seed pinned (R8-8, R8-12, R8-15, R9-2, R1-C1) | Invalid-PoW rotation and seed thrash | + | none | + | M | none | none | M |
| P1-5 | **Relay privacy:** a shared inbound trickle timer, shuffled invs, delayed requests to inbound announcers (R8-16); `--proxy` implies no clearnet listen unless explicit (R8-19); **private broadcast** design for local transactions (fresh isolated Tor connection per transaction, sent as `StemTx`, never height-filtered) (I3 §3.3) | First-spy precision; ProxyMark lessons | none | High + | one Tor circuit per transaction | M | none | none | S / M |
| P1-6 | **Wallet decoys:** draw a block by gamma age, then a uniform eligible output; redraw in the same band; recent-window `average_output_time`; an optional default spend delay; coinbase-aware guidance (R3-1, R3-3, R3 #4–#6) | Young real spends stand out on a quiet chain | none | High + | negligible | M | none | none | M |
| P1-7 | **Wallet network privacy:** a local output index (drop `/outputs`); SOCKS5 with separate circuits for query and submit (I3 §3.9 a, R3-9) | Removes the ring-superset leak to remote nodes | + | High + | about 73 MB per million outputs | S–M | none | none | S–M |
| P1-8 | **Key-hierarchy decision and implementation** before persistent users: PX view keys (R11-W2); hierarchical range-scoped roots and the incoming-only package (I2-R1, I2-F3); versioned seed with birthday and network (R11-W3); room for a future authorization key (R11-W4) | Seed-derivation changes must precede real users | neutral | High + | none | M | none | none (wallet derivation) | M |
| P1-9 | **Wallet safety UX:** build, summary, confirm; `status`, history, balance lines; PX max-sendable and `px-consolidate`; remove or implement accounts (R11-W6, W7, W10) | User error; the privacy-damaging `clear-pending` reflex | + | + | none | Low–M | none | none | S–M |
| P1-10 | **RPC auth:** Host allowlist, cookie token, no CORS, refuse non-loopback binds without auth; move remaining handlers to `spawn_blocking`; paginate `/distribution` (R10-4, R10-5) | DNS rebinding from any web page | + | + (node fingerprint) | + | S–M | none | none | S–M |
| P1-11 | **Crypto hygiene before any contract use:** hedge the membership nonce over the full transcript (R2-C5); document the Hk binding argument, whatever the R2-C6 decision (R2-C6) | Two signatures leak the key; a false claim | + | none | none | Low | none | none | S |
| P1-12 | **Security-claim accuracy:** recompute the BS-ZK-2 bits with post-ZK degree bits and an independent calculator; assert the unique-decoding bound in the envelope tests (R4-01, R4-12) | The documented margins must be evidenced | none (evidence) | none | none | Low | none | none | S |
| P1-13 | **Testing programme:** `proptest` for LWMA, MTP, fork choice with ties, mempool and codecs (T-4); a stateright model of H1 fork choice and replay (T-5); fuzz targets for the ZK verifier (structure-aware, time oracle), CLSAG/BP+ verify, HeaderChain DAGs, ChainManager sequences and mempool sequences (T-6); corpora in a separate repository with CI replay (T-7); cargo-mutants on consensus with `--in-diff` in CI (T-12); cargo-deny for sources and bans, plus a `third_party` verification script (T-11) | Detect the classes of bug that the current oracles miss | High + | none | CI minutes | M | none | none | M |
| P1-14 | **RandomX differential evidence:** an aarch64 CI job; a `rustc_apfloat` oracle for `fpu.rs`; an offline reference corpus of ≥ 10⁵ hashes over ≥ 16 keys (T-8, R9-R6, R9-R7) | The soft FPU is the rarest-path consensus code | High + (split avoidance) | none | none | M | none | none | M |
| P1-15 | **Labnet chaos:** kill -9 during sync and reorg; ±FTL skew; RSS trend; a 6 h nightly run; 72 h plus one real epoch before any public launch (T-9) | Recovery and time-edge coverage | + | none | none | Low | none | none | S–M |
| P1-16 | **Governance records:** DECISIONS.md seeded from the existing owner decisions; the consensus-change pipeline in CONTRIBUTING; a consensus-critical file list with a CI trailer check; STATUS.md as the one status source; a findings register; ARCHITECTURE.md with the lock model; evidence bound to commit, fingerprint and binary hash (D-3, D-4, D-5, D-11, D-12) | Makes the owner's gate enforceable, not remembered | + | none | none | M | policy | none | M |
| P1-17 | **Normative-by-reference proof-system spec:** crates, versions and patch hashes, config, transcript order, byte grammar, every MUST (witness == 0, folding schedule) (D-1) | The M1/M2/M3 class needs a written rule to test against | + | P-5 depends on the layout | none | M | none (documents v3 rules) | none | M |
| P1-18 | **Policy on the PX lane:** PX transactions first-seen before deploys; per-source PX admission cap; mempool expiry (R6 MP-5, I4-2) | Cheap lane capture | + | none | none | Low | policy | none | S |
| P1-19 | **Freeze v1 as a feature-closed payments layer;** all new capability goes to PX (R16-10) | Sustainability; no third privacy tier | + | + | none | Low | none | none | S |
| P1-20 | **Quantum-recovery spec draft** (I4-6: a seed-preimage STARK plus native EC checks) and the never-change preconditions (R2 §11.2) | Wallets must never break the preconditions | + | + | none | Low | none (spec) | none | S |

### 5.3 P2: hardening

| # | Recommendation (sources) | Why | Security | Privacy | Perf. | Complexity | Consensus | Identity | Diff. |
|---|---|---|---|---|---|---|---|---|---|
| P2-1 | Two-phase mempool admission (cheap checks under the lock, crypto outside, re-check) plus a bounded `VerifiedProofCache` keyed by (tx id, verifier id, registry digests) (R6 MP-1, MP-2, R16-8) | Liveness under load; cache soundness under future upgrades | + | none | large + | M | none | none | M |
| P2-2 | Parallel block verification (per input, per PX transaction, split BP+) reporting the lowest failing index; a v1 cache keyed on the (tx, resolved ring) pair (R12-11, R12-12) | Initial sync, replay and reorg cost | none | none | ×cores | S–M | none | none | S–M |
| P2-3 | PX undo as deltas; PX ciphertexts out of RAM; streaming load; a snapshot for fast restart (R10-6, R10-7, R10-8c, R12-4, R10 §5.4 steps 2–3) | RAM floor; restart hours | + | none | large + | M | none | none | M |
| P2-4 | Compact wallet scan RPC (unfiltered, proofs stripped, `tx_root` checkable); incremental wallet tree with witnesses; wallet PoW check (R11-W8, W9, R12-7, R12-8, I1-F2, W-F6) | 70–700× less wallet download | + | neutral (download-all kept) | large + | S–M | none | none | S–M |
| P2-5 | SIMD prover build (x86-64-v3), with the verifier pinned or differential-tested; measure first (R4-06, I1-F3) | Proving time | none (prover) | + (faster broadcast) | large + [unknown] | S | none | none | S |
| P2-6 | RandomX safe-Rust programme O0–O2 (profile, SoA dataset build, decode tightening); next-seed prebuild in the miner and the node; 1–2 s tip polling (R9-R2, R9-R4, R9-9) | Seed-switch stall; verification cost | + | none | large + | M | none | none | M |
| P2-7 | Node-local effects digest, logged and compared across labnet nodes (R16-9 option 1) | Detect divergence immediately | + | none | negligible | S | none | none | S |
| P2-8 | LWMA adversarial simulation; clock-skew warnings; recently-rejected header LRU; `MIN_CHAIN_WORK` constant plus presync design (R1-C8, R1-C9, R1-C3, R1 §4.3) | Fairness; liveness; early-sync DoS | + | none | none | S–M | none | none | S–M |
| P2-9 | Wallet: view-only file, key-image import, unsigned-transaction format (R11-W15); KDF bounds (W12); mnemonic parsing (W13); sent-record storage and PX payment-disclosure format (W11, I2 §4.3); merge avoidance (R3-13); bridge hygiene (R3-8) | Usability and safety | + | + | none | M | none | none | M |
| P2-10 | Delivery v2: the `px/delivery-key/v2` label binding `V ‖ H(ek)`; identity `V` rejected; hedge the PX witness randomness (`a25`) (R2-C9, A21) | Combiner robustness | + | + | negligible | S | none (wallet format) | none | S |
| P2-11 | Known-answer vectors: RFC 9496, FIPS 203 ACVP, RFC 7693, a pinned BP+ proof; an independent naive CLSAG verifier (R2-C11, R2 §4) | External anchors for self-pinned primitives | + | none | none | S | none | none | S |
| P2-12 | ISA conformance (riscv-tests or an exhaustive table cross-check) (R4-04) | Consensus-critical decoder | + | none | none | S–M | none | none | S–M |
| P2-13 | SIGTERM handling, Docker `STOPSIGNAL` and `HEALTHCHECK`; log redaction (no tx id with routing, optional peer-IP suppression); RPC timeouts and concurrency limits; `/health` (R10-9, R10-10, R10-11) | Operations and privacy | + | + | none | S | none | none | S |
| P2-14 | Bound `CachedPow` and the header tree; prune side branches below the threshold (R9-6, R1-C5) | Memory | + | none | + | S | none | none | S |
| P2-15 | Contract tooling: SDK, ABI and manifest with a typed public-output schema; `px-verify-contract`; approval-record authorization pattern; author security checklist (R7 §7.2, R7-2, R7-8, R7-9) | Contract safety and auditability | + | + | none | M–L | none | none | M–L |
| P2-16 | Hash-agility plan (versioned domain constants and kernel id, a pool-migration pattern) (R2-C7, I4 §3.5) | Poseidon2 margin | + | none | none | S | none (plan) | none | S |
| P2-17 | Typed PoW configuration and offline salt-variant vectors (keep `Monero_v1` exercising the official vectors) (I4 §2.4) | Makes a later mainnet PoW choice cheap and safe | + | none | none | S–M | none | none | S–M |
| P2-18 | Nullifier gap-tree specification; the rule that authority-conferring programs derive keys from `sk` (I2 §4.2a, I2-F2) | Enables private reserve proofs and polls; prevents FVK-holder voting | + | + | none | S | none | none | S |
| P2-19 | Frame padding to size buckets; labnet first-spy simulation of Dandelion++ (R8-18 b, I3 §3.1) | Evidence for privacy claims | none | + | bandwidth | S–M | none | none | S–M |
| P2-20 | Tiered CI, cargo-nextest, weekly coverage; cargo-vet with imported audits (T-13, T-11) | Feedback speed; supply-chain trail | + | none | none | S–M | none | none | S–M |
| P2-21 | Remove `legacy/` and `research/` from the main tree (a history rewrite only with explicit owner approval) (R16-12) | Supply-chain and review hygiene | + | none | none | S | none | none | S |
| P2-22 | Independent seeds (≥ 3 operators, ≥ 1 onion), with a stale-table fallback (R15 §5.2; P0-pub) | Eclipse; privacy of joiners | + | + | none | S (code) | none | none | S |

### 5.4 P3: after the trial, or future

| # | Recommendation (sources) | Why | Security | Privacy | Perf. | Complexity | Consensus | Identity | Diff. |
|---|---|---|---|---|---|---|---|---|---|
| P3-1 | **Persistent state** (redb with 2PC behind a `StateStore` trait, differential-tested against `MemoryChain`), bodies on disk, segmented archive, pruning of the prunable part, `--reindex` (R10 §5, R12 I5, I16) | A mainnet blocker | + | none | RAM O(chain) → O(cache) | L | none | none | L |
| P3-2 | **Architecture Stage C:** consensus facade; `TxKind` effects model with an infallible commit; chain actor with snapshots and off-lock verification; split `net.rs` (R16-4, R16-5, R16-6, R16-7) | Specifiability; removes rule drift and stall vectors | + | + | large + | L | none (corpus-verified) | none | L |
| P3-3 | **Recursion milestone:** A5a proof-carrying sync (no consensus change) first; then A5c function-hiding wrapper; then A5b deferred permissionless aggregation. Never in-block miner aggregation. Couple with the Plonky3 0.8 hard fork as verifier 2 (I1 A5, I4 §4, R4-13, R16-14) | PX capacity, pruning, fast sync and function privacy | new soundness layer | + (A5c) | 10–100× | XL | none (A5a); **CONS** (A5b, A5c) | activation | XL |
| P3-4 | **Width reduction** and a measurement spike for a dedicated transfer AIR (I1 A2, A3, R4-07, R4-08) | The dominant cost is committed width | new circuit risk | none | −10% to −25% bytes; A3 3–8× [est] | M–L | **CONS** | activation | M–L |
| P3-5 | **Kernel generation** (one deliberate batch): shape classes; multi-asset with per-asset conservation (B1 needs shape classes); user-owned contract records; a clock (choose R5-3 or R7-1); B′ for PX-F4; message commitments (R5 §4, R7-3, I1 B1/B3) | Contracts beyond the demo vault | + | + | kernel rows ↑ | L | **CONS** | activation | L |
| P3-6 | **Shielded coinbase** into PX with delayed-insertion maturity (mandatory), activated by height once the schedule exists; fallback: coinbase-segregated rings (R3-11, I4 §5) | Removes coinbase outputs from v1 rings; grows the PX set by ≥ 720 per day | new surface | High + | miners: +1 proof per spend | L | **CONS** | activation | L |
| P3-7 | **Mainnet PoW decision:** a unique salt (on RandomX v2 once Monero has activated it); reject merge mining; J1 stratum bridge or J2 isolated JIT with verify-before-submit (owner) (I4 §2, R9 §7, R1-C2) | Leaves the "same algorithm, isolated" quadrant | + (friction) | none | honest miners + | S / XL | **CONS** | mainnet genesis | S–XL |
| P3-8 | **Fee reform:** anchor-indexed uniform base fee with partial burn; optional small multiplier set (owner trade-off) (I4 §6.3, R5-2, R6 R-FEE1) | Congestion pricing without fingerprints | + | ≤ 2 bits under congestion | none | M | **CONS** | activation | M |
| P3-9 | **Finality:** halt on a reorg deeper than K ≥ 720 with an operator override; finalized/non-finalized state split; End-of-Service halts (R1 §4.3, I4 §7.2) | Bounds rewrite damage and undo | + | none | + | M | policy | none | M |
| P3-10 | **Transport v2** (Elligator2 X25519, padding, optional static key or bridge mode, session id); hybrid ML-KEM step; I2P SAM client; Nym through SOCKS (docs only) (R8-20, R8-21, I3 §3.7, I4-7) | Censorship resistance; harvest-now-decrypt-later | + | + | small | L | none | none | L |
| P3-11 | **Emergency quantum rules** specified ahead: freeze CLSAG spends and `bridge_in`; v1 → PX only through the recovery proof (R2 §11.3, I4-6) | Q-day response without a reset | + | + | none | M | **CONS** | activation | M |
| P3-12 | **Off-chain snapshot statements** (polls, reserve proofs, credential shows); credential-state voting templates (I2 §4.1, §4.2) | Governance and disclosure without consensus change or block space | + | + | none | L | none | none | L |
| P3-13 | Compact blocks (mempool-only reconstruction); assume-valid PoW or fast-sync hashes signed with SLH-DSA (owner decision); ASERT evaluation (R8 §3.6, I4-5, I4 §3.3, R1 §4.1) | Propagation and sync | trust in the release (assume-valid) | none | + | M–L | none / policy | none | M–L |
| P3-14 | PQ view tag derived from `ss_ec ‖ ss_kem`; persisted miner hedge secret; CLSAG Hp cache; OMR or PIR research (R2-C8, R2-C4, R2 §4, R11 §5.2) | Long-term privacy and performance | + | + | ±scan cost | S–M | none | none | S–M |

---

## 6. The v3 identity bundle

**Rules** (v3-plan.md):
- every CONSENSUS item goes to `v3/candidate` and is never merged into `rebuild/core` without the owner's review;
- one item per commit, so each can be dropped on its own;
- the genesis is **not** generated in advance: the tool and procedure are built, and the genesis is produced at launch with the owner.

### 6.1 Already on `v3/candidate` (`origin/v3/candidate` = `cc39795`; base `cf07324`, 24 commits behind `rebuild/core`)

| Commit | Item | Sources | Scope and caveats |
|---|---|---|---|
| `58c7f6e` | **Height-scheduled rule sets and branch id** | R16-1, R1-C10, I4 F1 | Adds `consensus::schedule`, with one epoch `BSv3` from height 0. The header version must equal the epoch's version. A version above every scheduled one is `UnknownUpgrade` (not permanent). The branch id is hashed next to the network id into the transfer, deploy and PX signature messages and into `h_tx`, so there is no kernel change. `TxRules::for_chain` panics on a multi-epoch schedule (tripwire). Tests: schedule boundaries and `tx/tests/upgrade.rs`. **Still owed** (v3-upgrade-mechanism.md §2.2, §2.4): the P2P no-score arm for `UnknownUpgrade` (until then it is still banned); chain and mempool `at_height`; the mempool flush at activation; the stateless classification of `PxProof` across activations; the wallet building `at_height`; node and miner using `BlockTemplate.version`. |
| `79b874e` | **Reject duplicate program ids in one deploy** | R5-7, R7-6 | Stateless `PxDuplicateProgram`. Compares loaded ids, not bytes. |
| `abee421` | **Reject deploy budgets above the proving limits** | R7-5 (SX1-corrected) | `budget_is_provable`: cycles ≤ 2^21, shared fields within 2^22 including the kernel share. |
| `cc39795` | **Exact deploy fee**, and a `MAX_DEPLOY_BLOCK_BYTES` constant | R5-1, R6 TX-4 | Fee = `FEE_PER_WEIGHT · max_weight(n,k) + 50 · payload`, exact. **The 1 MiB block budget is defined but NOT enforced**: the validation and template rules are owed. |

**Already on `rebuild/core`, and part of the v3 rule set:**
- `4b277cd`: canonical proofs. Nonzero FRI commit witnesses and empty optional openings are rejected, a narrowing rule.
- `f6a52ca`: `--network testnet` refuses to start until the v3 genesis is final.

A v3b worktree holds staged, uncommitted changes that look like a merge of `rebuild/core` into the candidate. They are not reviewed here.

### 6.2 Proposed but not yet implemented

| Item | Sources | State |
|---|---|---|
| PX-F5: the kernel enforces `owner = 0` for contract outputs | known, R5 §2, SX1 | Decided; not implemented |
| Platform-neutral kernel: no located panics, path guard test, dual-OS CI reproduction; **done last**, so the ids are computed once | R15-6, R16-13, SX1 | Decided; not implemented (`9ddaddd` gives a fixed-path build with unchanged ids) |
| Genesis tool and procedure (beacon nonce, `T_g` before the beacon, 8 tests, D0 from measured hash rate) | R15 §4, SX1 | Decided (tool only); not implemented |
| R12-2 verification-cost bound (option (a): the v1 part of PX and deploy transactions counts toward the weight) | R12-2, SX1, SX2 | Proposed |
| Enforce the deploy block budget in validation and the template | R5-1, `cc39795` | Half done |
| R4-02 canonical folding schedule (honest-schedule test for every consensus shape) | R4-02, M3, SX1 | Proposed (rationale corrected) |
| R4-11 circuit id in the transcript | R4-11, SX1 | Proposed |
| R6 C4 change: option C (pair-keyed uniqueness, with SX1's 4 corrections, including intra-transaction uniqueness on O) or option B (drop C4) | R6 MP-7, SX1 §2 | Owner decision |
| R2-C6 feed-forward node compression (guest-only, about +2–3k cycles; include only if the budgets hold) | R2-C6, SX1 | Conditional |
| PX function output-word encoding (field-canonical vs raw u32) | known, SX2 P0-1(f) | Decision |
| M3 / `COMMIT_POW_BITS`, given the zero-witness rule of `4b277cd` | A14, SX2 P0-1(e) | Decision (the zero-witness rule makes `COMMIT_POW_BITS ≥ 1` optional) |
| Re-measure kernel budgets and the widest two-function proof before pinning ids; re-pin Hk and node vectors plus the fingerprint | SX1 §3 item 4 | Not started |
| Genesis id bound into the P2P session and the wallet (not consensus, but ships with v3) | R15-3 | Not started |
| P2P forward compatibility (unknown messages, non-banning `UnknownUpgrade`) | R8-14, v3-upgrade-mechanism.md | Not started |
| One scheduled no-op activation on the testnet, to exercise the path | I4 F2 | Proposed (SX1 did not rule on it) |
| Wallet items that freeze formats at v3: R2-C9 delivery v2 label; I2-R1 / R11-W2/W3 derivation | SX1 §3 item 5 | Not started (`a26` inferred) |

### 6.3 Owner decision table

| # | Item | Options | Recommendation | Reason |
|---|---|---|---|---|
| D1 | Upgrade mechanism: schedule plus branch id (`58c7f6e`) | include / defer to v4 | **Include**, with P2P non-ban and mempool flush integration before the freeze | The highest-value v3 item: every later change arrives by height, with no reset (R16-1, I4 F1). SX1: the branch id is not *required* at v3; including it costs only new vectors. v3-plan contradicts itself by also listing "ZIP-200 branch ids" as deferred: remove that line |
| D2 | PX-F5 | include / defer | **Include** | One constant-work check; prevents silent burns (R5, SX1) |
| D3 | Platform-neutral kernel (no located panics, dual-OS CI) | include / defer | **Include, last** | A consensus artifact must be reproducible anywhere (R16-13, R15-6) |
| D4 | Fresh genesis by beacon procedure | include | **Include** (tool now, genesis at launch) | Removes pre-reveal pre-mining; randomizes the first seed (R15 §4) |
| D5 | R12-2 cost bound, option (a) | include / defer / accept | **Include** | Otherwise a 25–50 s block is possible for about 0.17 BLK, by any mempool user (SX1) |
| D6 | Deploy economics: exact fee (`cc39795`) plus an **enforced** 1 MiB block budget; drop "≤ 2 deploy outputs" | include / defer | **Include both**; drop the output cap once D5(a) prices the v1 part (SX1) | Registry RAM DoS; PX-lane censorship |
| D7 | Duplicate program ids (`79b874e`); budget caps (`abee421`) | include | **Include** | Trivial tightenings |
| D8 | R6 C4 change | option C / option B / keep C4 | **Option C with all four SX1 corrections**, or **B** if the owner prefers removing all griefing including clear payouts. Either way keep intra-transaction O-uniqueness | Stops free griefing of hidden outputs (SX1 §2). Without correction 1, C *introduces* a burning-bug vector |
| D9 | R2-C6 feed-forward | include / accept with a written argument | **Include if the re-measured budgets hold**; otherwise accept, and correct the comment and docs | The tree hash is the hardest thing to change later (I4 F3); guest-only (SX1) |
| D10 | R4-02 folding-schedule check | include / defer | **Include** (low value, low risk), with an honest-schedule test for every shape | A canonical schedule; a mismatch would be a liveness split, so test it |
| D11 | R4-11 circuit id | include / defer | **Include** | No marginal identity cost now |
| D12 | PX output-word encoding | field-canonical / raw u32 | **Pick one and document it** (either is a rule) | Docs and code disagree today |
| D13 | M3 / `COMMIT_POW_BITS` | keep 0 with the zero-witness rule / ≥ 1 | **Keep 0** with the `4b277cd` rule; revisit with grinding (I1 A1) only after R4-01 is recomputed (SX1) | Avoids a second parameter change |
| D14 | RandomX configuration | rx/0 / unique salt | **Keep rx/0 for the testnet**; decide for mainnet (SX2 C2, I4 §2.4) | A salt does not stop a recompiled xmrig; the testnet should observe the real threat |
| D15 | Shielded coinbase | include / defer / reject | **Defer**; activate later by height through D1 (SX1, SX2) | Not ready for the full review chain before launch |
| D16 | PX-F4 option B / B′ | include / defer | **Defer** to the contract-model redesign; document it as a griefable trust assumption (R5, SX1, I2-F1) | B does not solve delivery; `rcm` must stay prover-choosable |
| D17 | Function clock (R5-3 / R7-1) | include / defer | **Defer**, unless the trial includes non-vault contracts (SX1) | A capability, not security |
| D18 | Hybrid ML-KEM P2P handshake | include / defer | **Defer** (transport; can ship anytime) (SX1) | Not an identity item |
| D19 | Fee tiers (R-FEE1) | include / defer | **Defer** (later by activation) | Not needed for the trial |
| D20 | Genesis id in the P2P session and wallet | include | **Include** (free at the reset) | R15-3 |
| D21 | Scheduled no-op activation on the testnet | include / skip | **Include if D1 is included** | The only way to exercise flush, re-signing and peer handling across a boundary (I4 F2) |
| D22 | Wasm contract scope | option D / keep | **Option D** | R7, R16 §8 |

**Order of implementation** (SX1): consensus rule changes first; then the neutral kernel rebuild, so the ids are computed once; then re-measurement; then the fingerprints and golden vectors; then the rc tag.

---

## 7. Innovation

### 7.1 Worthwhile ideas, with a realistic path

| Idea | Source | What it gives | Path | Consensus | Priority |
|---|---|---|---|---|---|
| **Upgrade mechanism in v3** (activation table, branch id, non-banning future versions, one no-op activation on the testnet) | I4 F1/F2, R16-1, R1 §4.4 | Every later change arrives by height, with no reset. It is the enabler for most items below | On the candidate (`58c7f6e`); finish the integration (§6.2) | CONS | P0 decision |
| **Quantum recoverability without in-circuit EC arithmetic** | I4-6 (refines R2 §11.2) | After Q-day, v1 owners move funds to PX by proving knowledge of the seed preimage of the now-public `k_s`, `k_v`. About 10–50k cycles [est], an ordinary PX-class proof. Consensus checks the EC relations natively | Spec draft now; pin its preconditions as never-change (seed-derived keys, no raw-key import, the PX `sk` link); emergency rule activated by height | CONS (later) | P1 spec / P3 impl |
| **Shielded coinbase with delayed-insertion maturity** | I4-8, R3-11 | Coinbase outputs leave v1 rings (fixes R3-1 and R3-3 at the root). The PX set grows by ≥ 720 records per day. Maturity by delaying tree insertion needs no kernel change | Specify now; activate by height after the full review chain | CONS | P2 decision / P3 |
| **Proof-carrying sync (recursion step A5a)** | I1 A5a | Restarting and syncing nodes verify one recursive proof instead of N PX proofs. Fixes the PX-F3 cost and enables pruning **without a consensus change** | After the trial; pin Plonky3-recursion at a reviewed commit (it is WIP and unaudited), or write a dedicated circuit | none | P3 (first recursion step) |
| **Function-hiding wrapper plus private message commitments** | I1 A5c + B3, R7-3 | Hides which contract ran (P-8), and composition then leaks no metadata. Post-quantum | After A5a; its own review | CONS | P3 |
| **Deferred, permissionless aggregation off the mining path** | I1 A5b, D3 | Chain growth drops without putting provers on the PoW critical path | After A5c | CONS | P3 |
| **Compact, unfiltered wallet feed** | I1-F2, R11-W9, R12-7, I3 §3.9 | Keeps the strongest private-sync model (download everything) at about 1/500–1/1000 of the bandwidth | RPC plus wallet | none | P2 |
| **Local output index** (drop `/outputs`) | I3 §3.9 a | Removes the ring-superset query to remote nodes | Wallet | none | P1 |
| **Private broadcast of local transactions into the stem** | I3 §3.3 | One fresh isolated Tor connection per transaction, sent as `StemTx`. Learns from ProxyMark (no height-based choice) | After the addrman fixes | none | P1 design / P2 |
| **Network classes as first-class state; dedicated onion inbound port** | I3 §3.4 | Structurally closes the onion/clearnet identity links and N-6 | P2P | none | P1 |
| **Hierarchical, range-scoped PX viewing keys; incoming-only package without `nk`** | I2-R1, I2-F3 (corrects R11-W2) | Least-privilege disclosure (time-scoped audits) without a kernel change | Wallet, before persistent users | none | P1 |
| **Off-chain snapshot statements** (polls, reserve proofs with anti-double-count tags, credential shows) against a public nullifier gap tree | I2 §4.2 | Governance and disclosure with no block space and no consensus change. The pattern matches Zcash's 2026 coinholder vote | Gap-tree spec (P2), then a statement program | none | P3 |
| **Credential-state voting** (one credential, one vote, via record state) | I2 §4.1 | Anonymous (not receipt-free) votes that fit the 2×2 shape | After the SDK | none | P3 |
| **SIMD prover build** | I1-F3, R4-06 | Probably large proving speed-ups | Measure; keep the verifier pinned or differential-tested | none | P2 |
| **Width reduction; dedicated transfer AIR (spike)** | I1 A2/A3, aggregation-study | The largest non-recursive capacity lever [est] | Measure first; its own mutation and review cycle | CONS | P3 |
| **Confidential multi-asset records via the existing `asset` field** | I1 B1, R5 §4 | Tokens without splitting anonymity sets | Only together with shape classes (a token plus BLK fee needs 3 outputs) | CONS | P3 |
| **Anchor-indexed uniform base fee with partial burn** | I4 §6.3 | Congestion pricing that keeps "same fee within a class"; makes self-stuffing costly | Mainnet design; activation | CONS | P3 |
| **Stratum bridge for stock miners; isolated JIT with verify-before-submit** | I4 §2.5 J1/J2 | Honest miners get competitive tools; a JIT bug can never produce an invalid block | Owner decision on the unsafe policy for non-consensus binaries | none | P3 |
| **Contract-scoped tags** (rate-limiting nullifiers) | R7, I1 B4 | Post-quantum, full-set-anonymous one-time actions | Only with a measured need beyond credential state (I2 §4.1) | CONS | P3 |
| **Consensus corpus as the specification of record; published conformance vectors** | R16-2, R13 T-3, R14 | Detects silent forks; enables a second implementation | Partly done (`f6c98c3`); complete after v3 | none | P0/P1 |

### 7.2 What could make BlackSilk meaningfully different (stated honestly)

No "first" claim is supported. **Neptune Cash** is prior art: a live PoW chain since February 2025 with STARKs, post-quantum-oriented primitives, hidden lock/type scripts, custom tokens and per-block recursive transaction merging (I1-F1; now cited in docs via `58f25ec`). Zexe, Aleo and Aztec are prior art for the record-plus-predicate model; Zcash (ZIP 213, ZIP 200, ZIP 2005) for shielded coinbase, upgrades and quantum recoverability; Penumbra/Namada/ZSA for multi-asset pools.

Within those constraints, three differences are defensible *if built*:

1. **Post-quantum programmable private execution with no trusted setup, committee or trusted hardware** (I1 D1): hash-based ownership and nullifiers, a transparent STARK, hybrid ML-KEM delivery, and (if kept STARK-in-STARK) a post-quantum recursion layer. Versus Neptune the difference is narrower: a general RISC-V zkVM with Rust-source functions, contract-held records with an approve-and-specify kernel, and a Monero-lineage ring layer with a consensus turnstile. **Today this is not a meaningful difference**: there is one demo contract and no SDK (R7, I1).
2. **Function-hiding private calls with private composition, post-quantum** (I1 D2) — depends entirely on the recursion milestone, the least mature part of the plan.
3. **Scaling that keeps mining CPU-only** (I1 D3): proving never on the PoW critical path; deferred permissionless aggregation; proof-carrying sync; compact download-everything wallets. Monero and Zcash also keep mining prover-free but have no aggregation; the difference is having both.

Also notable but not differentiating: the Janus-anchor-plus-C4 burning-bug defence (a Carrot relative, R2 §3.1); latent quantum recoverability of v1 without format change (R2 §11.2, I4-6); software-FP RandomX that avoids the reference's MXCSR/JIT platform bug class (R9 §3).

### 7.3 Rejected ideas, with reasons

| Idea | Reason | Source |
|---|---|---|
| Curve-based folding (Nova, HyperNova, ProtoStar, ProtoGalaxy); KZG/Groth16 wrapping | Soundness on discrete log or pairings breaks the post-quantum requirement; trusted setup | I1 A6, §6 |
| Lattice folding (LatticeFold, Neo) now | Young research, new assumption, no reviewed pure-Rust stack (watch only) | I1 A6 |
| FHE contracts; threshold-encrypted batches or mempools; fair ordering | Need a committee or TEE; a PoW chain has no validator set | I1 B2, I3 §3.8 |
| TEE confidentiality or TEE provers | No trusted hardware (Secret Network 2022 lesson) | R7 §5, I1 §6 |
| Witness-revealing delegated proving | Violates client-side proving; the prover learns everything (and today can steal, R11-W4) | I1 A8, R12 §15 |
| Miner-produced in-block aggregate proofs | Puts heavy proving on the mining path; centralizes | I1 A5d |
| Proving RandomX in a STARK for light clients | Infeasible by RandomX design | I1 §5 |
| GPU in consensus builds | Driver FFI and `unsafe` | I1 A7 |
| Merge mining with Monero | Breaks the 100-byte header, adds a Monero-seed dependency, zero-cost pool attacks, cross-chain miner linkage | I4 §2.3 |
| RandomX program or size tweaks (Wownero-style) | Leaves the audited design; only a salt change is designer-endorsed | I4 §2.2, R9 §7 |
| Equi-X or another consensus PoW; multi-algorithm lanes | Not memory-hard at RandomX level; weakest lane sets security | R9 §7, I4 §8 |
| Hybrid PoS finality (Crosslink-style); Bitcoin timestamping | Validator set as privacy/centralization surface; external dependency | I4 §7.2 |
| On-chain protocol governance (coin or miner votes); BIP9 signalling | Hands rule changes to capital or pools; leaks amounts | I2 §5, I4 |
| BBS/BBS+, CL, Coconut credentials; homomorphic-ElGamal tallies | Not post-quantum, new curve or RSA code, committees | I2 §6 |
| Mandatory auditor/escrow viewing ciphertexts; Privacy Pools at kernel level | Backdoor by design; clean/dirty tiers harm fungibility | I2 §6 |
| MACI-style coercion-resistant voting | Needs a trusted coordinator or committee; state voting as "anonymous, not receipt-free" | I2 §5 |
| PQ signatures (ML-DSA/SLH-DSA) inside PX | PX authorization is already the hash-based STARK | I4 §3.3 |
| Lattice ring signatures for v1 | Large unreviewed construction; PX is the PQ path | R2 §11.3, I4 |
| State expiry for v1 outputs or key images | Breaks rings and double-spend protection | I4 §4 |
| Dynamic block size before persistent state | Multiplies the binding RAM constraint | I4 §4, R6 §3.4 |
| Transaction expiry-height field (ZIP 203 style) | Per-wallet value is a fingerprint (like `unlock_time`) | I4 §7.1 |
| Optional (not mandatory) shielded coinbase | Keeps coinbase outputs in v1 rings | I4 §5.4 |
| Own mixnet; embedding nym-sdk or Arti | No operator set; huge unreviewed trees; Arti needs C SQLite | I3 §3.2, §3.6 |
| DHT discovery; adaptive diffusion; switching to Clover | Eclipse-prone; undeployed; no demonstrated gain | I3 §3.1, §3.4 |
| FMD; Erlay now | Weak "fuzzy" guarantees plus consensus fields; only minisketch binding is C++ FFI | I3 §3.9, §4 |
| Default constant-rate cover traffic | GB/day per link at PX sizes | I3 §3.5 |
| Height-based stem or proxy selection | Exactly the ProxyMark bias | I3 §4 |
| Hiding tx type by padding transfers to function shape | +0.5 MB and +9 s per padded function at 3 tx/block; recursion is the proper fix | I1 §6 |
| Compact blocks answered from the stempool | Stem-membership leak | I4-5 |

### 7.4 Contradictions between reports and their resolution

| # | Contradiction | Resolution (source) |
|---|---|---|
| C1 | Root `rust-toolchain.toml`: R13 for, R14 against | No root file (a Windows GNU host breaks); pin CI/Docker by version and digest, record rustc per device (SX2 C1) |
| C2 | RandomX salt tweak: R9 rejects, R15-2(b)/I4-1 propose | Keep rx/0 for the testnet; salt-only is the designer-endorsed variant; mainnet owner decision (SX2 C2). R16 §13's "no variant" is read as "no program/size tweaks" |
| C3 | v1 capacity per block (R8 400, R3 330, R12 381) | 381 × 1-in/2-out (R12; SX2 C3) |
| C4 | Stale rate (R8 17%, R12 3–12%, R9 2–3%) | Different terms; R12's combined model; all estimates; measure in the trial (SX2 C4) |
| C5 | R3 "never change the single `/outputs` query" vs I3 "stop calling it" | I3 dominates; reword to "never make per-ring queries" (SX2 C5) |
| C6 | PX undo delta P1 (R12) vs P2 (R10) | P2 for the trial, P1 before a long public testnet (SX2 C6) |
| C7 | Origin self-fluff 17% (R8-17) vs R3-4 concern | Both right under different conditions; honest v1 path ≈ 0, slow PX stem ≈ 10–12%, after a black hole 1/k (SX2 C7) |
| C8 | PX key hierarchy in the v3 consensus bundle (R11) | No: wallet-only; decide before persistent users (SX2 C8) |
| C9 | `CachedPow` unbounded priority (P2/P3/info) | One item, P2 (SX2 C9) |
| C10 | Worst block validation (R8 3.4 s vs R12-2 25–50 s) | R12-2 (SX2 C10) |
| C11 | T-1 oracle P0 | P1: the known instance is fixed (SX2 C11) |
| C12 | PX-F4 B in v3 (R7) vs defer (R5, I2-F1) | Defer (SX1) |
| C13 | "≤ 2 deploy outputs" (R6) vs charging v1 weight (R12-2 a) | Option (a) makes the cap unnecessary (SX1) |
| C14 | Branch id must be in v3 (R1 §4.4) vs can come at the upgrade | Not required at v3; acceptable to include (SX1); now on the candidate |
| C15 | R4-01 medium/P1 vs consensus reach nil | Low; P1 for documents only (SX1) |

---

## 8. What should never change

Consolidated from R1 §4.5, R2, R3 §9, R4 §7, R5 §6, R6 §4, R7 §9, R8 §7, R9 §7, R10 §6, R11 §7, R12 §17, R13 §3, R14 §5, R15 §7, R16 §13, I1–I4. Changing any of these adds consensus, security or privacy risk without enough benefit; each belongs in the golden corpus or fingerprint so it cannot change by accident. "On a launched network" items may change only at a new identity or a scheduled, reviewed activation.

**Consensus core**
1. The 100-byte header layout, nonce offset 92, the id derivation `H("BlackSilk/block-id" ‖ network_id ‖ header)`, and never reusing a network id (R1, R15, I4).
2. `check_hash` semantics (`h·d < 2^256`, d = 0 invalid), work = difficulty, cumulative work as a u128 sum, strictly-greater fork choice, invalidity propagating to descendants, validation depending only on ancestors (R1, R9).
3. RandomX conformance to the audited reference with the official vectors as the pin; the software rounding emulation as the only FP path (never MXCSR/FPCR, never unproven FMA contraction); seed schedule E = 2048, L = 64 on the header's own branch; the full header as PoW input; epoch-0 key = genesis id. Any change only as a versioned switch (salt or RandomX v2) at an identity or activation (R9, R15, R16, I4).
4. The LWMA formula including its integer operation order, N, cap, floor and the absent 99/100; strict MTP; FTL never permanent; **never adjust consensus time from peers** (R1).
5. Emission formula and constants, height-only `reward(h)`, the 0.6 BLK tail, B3 exact equality, the implicit coinbase commitment `G + a·H` (R1, R6, I4).
6. The Merkle construction and the tx-hash composition covering every byte (prefix ‖ base ‖ prunable) (R1).
7. Strict canonical encodings with exactly one valid encoding per object (sorted key images and outputs, canonical points, scalars and field elements, the proof re-encode check); malleability defences never relaxed (R6, R16).
8. The network id (and, with v3, the branch id) in every signature message and in `h_tx` (R6, R16, I4).
9. No admin, pause, kill-switch or upgrade keys; no checkpoint server signed by the maintainer (R15, R16).

**Cryptography**
10. Domain-tag scheme, `Hs`/`Hp` definitions, generator derivations, key-image definition, CLSAG verification equation, BP+ transcript and `BITS`, stealth and Janus-anchor derivations and ctx definitions — old outputs must stay spendable and scannable forever (R2, R16).
11. Spend-capable v1 keys derived by hash from a 32-byte seed (the quantum-recovery precondition); never spend-capable raw-key import without flagging; PX `sk = Hk(SK, seed)` link kept (R2 §11.2, I4-6).
12. HedgedRng seed/stream construction (extend contexts only) (R2).

**PX and ZK**
13. Hash-based ownership and `nk`-keyed user nullifiers; `rho` from `nf_0`; `nf` binding `cm`; the `asset` field inside `cm`; tree depth 32; anchors only from block-end roots; `Hk` domain constants except by a versioned upgrade (R5, R7, R16, I1).
14. Integer (u128) balance in the kernel; one kernel source for native and guest; consensus pins the kernel id (R5, R14, R16).
15. Fixed-shape privacy invariants: 2-in/2-out, dummies, fixed ciphertext length for all record kinds, exact PX fee (or any replacement that is a deterministic function of public data), fixed budgets per registered program, no variable-shape proofs (R3, R5, R6, R16).
16. Pool containment (`px_pool ≥ 0`, in order); value lives only in PX records — no second value layer (R5, R7).
17. Mandatory registry in `verify`; immutable registrations fixed by the contract id (the proof cache depends on it) (R5, R7, R16).
18. zkVM: exec tags on every non-pure bus; strict key ordering in MEM_INIT; the `t − t_prev − 1` 3-byte check with the `MAX_CYCLES` cap; decode shared by loader, interpreter and verifier; rejection of DIV/REM/CSR/compressed; statement digest before any challenge; minimum height ≥ eq. 17; `catch_unwind` with `panic = "unwind"`; "no rayon work under a spin lock" in the patched crates (R4).
19. Plonky3 never upgraded in place — only as a new verifier at an activation (R16).
20. Hash-only soundness: no curve or pairing in any consensus proof path; no committee, TEE or trusted setup; proving kept off the mining critical path (I1).

**Network and node**
21. No plaintext magic; `network_id` in the session KDF; directional AEAD keys; strict decoding *within* known message types (R8, I3).
22. Header-first sync (no body before its header's PoW and context); not penalizing contextual failures, InvalidParent, NotFound or future timestamps (R8).
23. Dandelion++: local transactions always stem; per-source fixed routes per epoch; outbound-only stem peers; stempool invisible (`GetTx` only for announced; InvTx answered as unknown); stem conflict keys include nullifiers; **no height-based stem or proxy choice** (R3, R8, I3).
24. Minimal `Version` (no user agent, no clock, per-connection nonce); no own-address advertisement by default; no local DNS in proxy-only mode; SOCKS5 (later SAM) as the only anonymity-network boundary (R3, R8, I3).
25. The lock-ordering rule (never state and chain locks together) — keep it in the actor design (R8).
26. Storage: fsync the body before applying state; atomic per-block state changes; never silently discard mid-file data; replay and reindex through the same validation code; stored PoW hashes trusted only for the node's own store (R10).
27. RPC loopback by default; no wallet or key operations in the node; bulk-only PX endpoints (never per-record or per-contract lookups); `deny_unknown_fields` (R10, R14).

**Wallet and privacy**
28. Reserve-before-send; unchanged rebroadcast; ring reuse (W-5); download-everything (or compact-but-unfiltered) scanning; never per-ring queries; canonical PX anchors; Janus-style `cm` check on received records; per-address independent PX keys (unless the PQ address-unlinkability trade-off is explicitly re-decided); the atomic authenticated wallet file (R3, R11, I3).
29. No `tx_extra`, no `unlock_time`, no transaction expiry field; canonical input and output ordering; mandatory change output (R3, I4).
30. No mandatory or escrowed viewing; disclosure stays the user's choice; no real-world identity in the protocol (I2).

**Process**
31. Consensus pins as failing tests (extend, never loosen to tolerance); `fuzz/` in its own workspace; SHA-pinned actions and read-only token; `forbid(unsafe_code)` in project crates; no C/FFI in the node closure; the owner-approval gate for consensus, crypto and protocol changes; honest "not an audit / statistical and conditional ZK" wording carried verbatim through any doc restructure (R13, R14, R16).

---

## 9. Open risks and accepted limitations

These are stated plainly; none is hidden by any classification above.

**Security model**
1. **Stock RandomX miners dominate a safe-Rust miner.** The pure-Rust interpreter is about 50–100× slower per core than JIT rx/0; the chain uses Monero's exact rx/0, so rented or redirected Monero hash power, or one desktop running xmrig behind a thin bridge, can out-mine the whole trial and rewrite history (K4 has no depth limit). K1 (honest majority) is **not attainable** on any public network; PoW security is nominal. A unique salt adds friction only. (R1-C2, R9 §4.4, R15-2, I4-1, SX1, SX2.)
2. **No minimum chain work during early sync and no presync.** The `12ce4cb` work gate is relative to our own best chain; a fresh node or a chain shorter than 144 blocks still hashes and stores low-work branches; RandomX caches for attacker seeds are still built under a global mutex. (R1-C1, R9-2, `12ce4cb` p2p.md.)
3. **Deep reorgs are unlimited** (K4) and ring references are by global index, so reorgs deeper than 10 (60 for coinbase) invalidate honest transfers. (R1, k4-reorg-policy.md.)
4. **Worst-case block validation of about 25–50 s** until R12-2 lands (R12-2).
5. **C4 front-running** permanently invalidates a victim's transaction for one fee until D8 is decided (R6 MP-7).
6. **Janus anchor, CLSAG-over-Ristretto and BP+-over-Ristretto have no external vectors or external review**; the Poseidon2-BabyBear partial-round margin is +7.5%; `ml-kem` is unaudited; wasmi internals unreviewed. (R2, A14.)
7. **Zero knowledge is statistical and conditional** (zk-coverage.md §3); the documented "≥ 123 Johnson bits" is not established to that precision (R4-01).
8. **Single maintainer, approver and signing identity**; no signed releases yet (R15-5).

**Privacy**
9. **Small anonymity sets.** v1: on a young quiet chain rings are coinbase-dominated (40% all-coinbase at 3 days / 20 tx/day), young real spends stand out, and colluding miners can eliminate their own coinbase decoys (1.9 effective only if all collude; ~14 for one of seven). PX: the set equals usage (~40 commitments/day at 20 PX/day). Network: Dandelion++ leaves a small candidate set that does not grow with N. With 7 trial participants, anonymity is not meaningful. (R3 §2, SX2, I3 §3.1, R15 D4.)
10. **The 2.2 MB PX size reveals the origin** to the origin's ISP, VPS provider or Tor guard, including over Tor; no padding or cover scheme is affordable at this size (R8-18, R3-10, I3 §3.5).
11. **Bridge amounts are public**; round-trip linkage (R3-8).
12. **Remote-node and plaintext RPC use** exposes IP, transaction, ring superset and wallet birthday (R3-9).
13. **v1 privacy is not post-quantum** (retroactive tracing; `k_v` recoverable from any address); PX view tags leak recipient linkage post-quantum (R2-C8, R2-C14, R3-12).
14. **Contract records**: every holder of an opening sees the spend; issued credentials give zero anonymity on first use without a refresh step (R3-7, I2-F1).
15. **Eclipse**: addrman lacks per-source limits and onion grouping; Tor inbound shares 127.0.0.1 (R8-3, R8-5, N-6) — not reachable in an explicit-peer trial mesh, but open for any public use.

**Scalability and operations**
16. **RAM grows with the chain** (~4.5× v1 bytes, ~6 KB/block floor incl. 4.2 KB PX undo): 16 GB lasts ~147 days of light use, ~2.4 days of full blocks; **every restart re-validates the whole chain** including PX proofs (R12-1, R12-4, PX-F1/F2/F3).
17. **PX capacity ~3 transactions per 8 MiB block** (~0.025 tx/s); proving ~45 s and 3.8 GB (no phones); no fee market (fixed price, congestible) (R12, R5-2, I4-2).
18. **Initial sync** costs ~6.9 h of header PoW per chain-year on 8 threads plus single-threaded body validation (R12 §7).
19. **Seed switch** stalls every full-mode miner at the same height; never exercised at 2113 with real parameters (R9-R4, R15-9).
20. **Contracts**: no clock, no authorization primitive, no composition; shared-state apps not viable; PX-F4 (openings can be withheld) is a documented, griefable trust assumption (R5, R7).
21. **Wallet UX** is a developer CLI (R11 §0).

**Evidence**
22. No full-suite log on current HEAD among the inputs; fuzz overflow coverage not evidenced; adversarial verifier cost (ZK-F4) and widest proof size unmeasured; cross-platform RandomX (aarch64) unverified; labnet runs ≤ 62 min, honest-only (§2.2, R13).
23. **Same-model internal review**: correlated blind spots likely; no independent review will take place (review-status.md §3).

---

## 10. Next steps (ordered)

1. **Push and mirror** the local commit `e4a5634` and all agent work as it merges; enable 2FA hardware keys and branch protection (P0-12, R15 §5.3).
2. **Merge the in-flight agents after review and tests**: `a24-p2p3` (expected: R8 P0 set remainder), `a25-pxhedge` (PX witness hedging), `a26-wallet2` (decoys R3-1, key hierarchy, SOCKS5), `a27-supply` (supply-audit tool). Check each base commit before merging (coordination.md).
3. **Close the non-consensus P0 items on `rebuild/core`**: R8-14 unknown-message tolerance and `UnknownUpgrade` non-ban (P0-6); chain-lock liveness (P0-7); p2p poison fail-stop (P0-8); genesis binding in session and wallet (P0-5).
4. **Owner signs the v3 decision table** (§6.3, P0-1).
5. **Rebase `v3/candidate` onto `rebuild/core`**, then implement the included CONSENSUS items in order: rule changes (R12-2, deploy block budget enforcement, R6 C/B, R4-02, R4-11, output-word encoding, PX-F5, R2-C6 if budgets hold) → integration of the schedule (chain/mempool `at_height`, flush, wallet, miner) → **neutral kernel rebuild last** → re-measure budgets, widest proof and ZK-F4 (P0-2, P0-3, P0-9).
6. **Build the genesis tool and its 8 tests** (P0-4); do not generate the genesis.
7. **Freeze evidence on the final v3 rule set**: golden vectors, golden PX proofs, Hk/node vectors, consensus fingerprint (P0-10); run the full workspace suite; fuzz with `-O -a` (P0-11).
8. **Documentation pass** (P0-15, P0-16, P0-17): the eight "4 PX" statements, K1/JIT, PX size vs ISP, trial anonymity, simulated ring figures with corrections, Hk comment, share claim, contract capability envelope; LICENSE; Wasm scope.
9. **Tag `testnet-v3-rc` (signed)**; run the labnet regtest past height 2400 with full-mode miners, the per-device RandomX check, and a local v3 rehearsal with a rehearsal id (P0-13, R15 C5).
10. **Trial procedure**: sampler, supply tool, Windows hygiene, fresh data directories, hardware minimums, end criterion max(96 h, 2113 + 720) (P0-14).
11. **Owner approvals**: genesis announcement ≥ 48 h before the beacon; after H + 6, compute and cross-verify the nonce; commit constants only; tag `testnet-v3` (signed); start the trial (R15 §4.2).
12. **During and after the trial**: measure stale rate, RSS slope, sync time and seed-switch behaviour; run the supply audit mid-way and at the end; report the result as a "functional trial", never as audited or secure (R15 §3 F).
13. **Post-trial P1 programme** (§5.2), in roughly this order: addrman v2 and connection manager, byte-accounted sends, header-path hardening, wallet privacy (local index, SOCKS, decoys), key hierarchy before persistent users, RPC auth, testing programme (proptest, stateright H1 model, stateful fuzzing, mutants, RandomX differential), governance records and the normative proof-system spec.
14. **Then P2/P3** (§5.3–5.4): two-phase admission and verified-proof cache, parallel verification, undo deltas and snapshot restart, compact wallet feed, SIMD prover, persistent state (mainnet blocker), architecture Stage C, and the recursion milestone starting with proof-carrying sync (A5a).
15. **Before any mainnet discussion**: the mainnet PoW decision (I4 §2), finality policy (I4 §7.2), fee reform (I4 §6.3), shielded coinbase activation (I4 §5), persistent state (R10 §5), and the quantum-emergency rule specified in advance (I4-6) — each through analysis → evidence → proposal → security review → tests → implementation → integration review, with explicit owner approval.

---

*End of report. Internal review, not an audit. No claim in this document asserts that BlackSilk or any component is secure, audited, proven, production-ready or perfectly zero-knowledge.*
