# R15: Testnet readiness, decentralization and operational risk

**Reviewer:** R15 (senior review agent). **Date:** 2026-09-27. **This is internal review, not an audit.**
**Tree read:** `rebuild/core` at `9578517`, which is 8 commits ahead of `origin/rebuild/core` (`87278ac`). It includes `f677e55`, `4b277cd` (the canonical proof rule), `f36b909` (ZK-F3) and `16659ee` (mempool F1). The brief's HEAD was `f677e55`; the extra commits are on the same branch.
**Method:** I read the code and docs with Read, Grep and git, and ran no builds. I also did web research and cite it in §10.
**Documents read:** docs/testnet.md, testnet-launch-checklist.md, testnet-reset-plan.md, testnet-roadmap.md, testnet-v2-validation.md, testnet-incident-response.md, reviews/completion-readiness-2026-09-26.md, reviews/review-status.md, reviews/px-f4-f5-analysis.md (headings), AUDIT.md R6 and R13.
**Code read:** consensus/src/{params,header,pow,difficulty,timestamp}.rs, p2p/src/transport.rs, node/src/config.rs, miner/src/{main,lib}.rs, rpc Info, wallet `check_network`, zkvm/guests/{build.sh, reproduce.sh, README.md, Cargo.toml}, .github/workflows/ci.yml, randomx/src/config.rs, SECURITY.md and deploy/.

**Evidence tags:**
- **[M]** mathematically established;
- **[T:name]** tested, with the test named;
- **[S]** source-read;
- **[A]** assumed;
- **[U]** unknown.

---

## 0. Verdict

1. **The seven-device trial is not ready to start. This is a sequencing question, not a quality verdict.**
   - The plan is sound: finish hardening, then one v3 identity, then a trial of more than 72 h across seed height 2113.
   - Three things must happen first:
     - the tree must stop presenting v3 rules under the v2 identity (R15-1);
     - every open item that affects consensus must be closed or explicitly deferred before the v3 freeze, so that "one identity" really means one (§3 A2);
     - the checklist in §3 must be satisfied with evidence.
2. **The v3 genesis is straightforward to do correctly.** §4 gives a procedure.
   - The unpredictable data goes into the 8-byte genesis `nonce`.
   - It is derived from a pre-announced Bitcoin block hash.
   - The genesis timestamp is fixed in advance and placed before the beacon.
   - One subtlety matters. An unpredictable genesis does **not** prevent mining with future timestamps between the reveal and the launch; the FTL rule does not stop it (R15-4). What it prevents is the maintainer, or anyone else, mining *before the reveal*, and it makes the launch publicly verifiable. The procedure keeps the window between reveal and start short.
3. **The largest structural decentralization risk is PoW (R15-2).**
   - BlackSilk's RandomX is byte-for-byte Monero's `rx/0` (`ARGON_SALT = b"RandomX\x03"`, randomx/src/config.rs:7).
   - The project's own pure-Rust miner is about 100× slower per core than reference RandomX. It cannot JIT without `unsafe`, which the project forbids.
   - So one ordinary desktop running a reference miner behind a small bridge, or rented `rx/0` hash rate, will out-hash every honest BlackSilk miner combined.
   - This does not block a trusted seven-device trial. It is **the** question for any public testnet, and a decision (tweak RandomX or accept it) belongs in the v3 bundle if it is to avoid another reset.
4. **Operationally, the project has a single point of failure in every role:**
   - one maintainer, one approver and one signing identity (no signatures in use);
   - one hosting provider;
   - work that exists only on one machine (8 unpushed commits plus agent worktrees);
   - no seeds, no alerting and no release artifacts.
   The incident plan says so honestly (incident-response §1b). Several low-cost mitigations are listed in §6 and §7.

---

## 1. New findings

These are not in the brief's "already known" list, or they deepen an item on it.

### R15-1: The branch carries v3 consensus rules under the v2 network identity
- **Classification:** Partially implemented. **Severity:** High for process and identity; not exploitable today. **Confidence:** high.
- **Where:**
  - `zk/src/lib.rs:186-240`: `decode_proof` now refuses non-zero FRI commit witnesses and empty optional openings. Commit `4b277cd` says "Consensus: narrows the valid proof encodings (testnet v3 rule set)".
  - `consensus/src/params.rs:55-62` still defines testnet as `0x0001_D672` with genesis `6556f92d…`.
  - docs/testnet.md §1 and docs/testnet-v2-validation.md still tell operators to run v2.
- **Scenario:**
  - An operator follows the v2 validation checklist on a build of the current HEAD.
  - A second operator builds the commit that was announced for v2 (for example `87278ac`).
  - The two nodes handshake: same network id, same genesis. They fork on the first PX proof that one accepts and the other refuses: a relayer-rewritten proof, which is exactly what M1 describes.
  - The docs say v2 was "approved; not executed", so no real network is affected today.
- **Evidence:** [S] for the rule and the id, both read. [A] that no operator has run v2, from reset-plan §0 and validation §0.
- **Recommendation:** Treat `0x0001D672` as retired now.
  - Before v3 is final, make `--network testnet` refuse to start with "testnet v3 genesis not final". The mainnet guard at `node/src/config.rs:150` is the model.
  - Mark the v2 documents as superseded.
  - Details: §8, item 1.

### R15-2: Mining centralization. Honest miners are about 100× slower than a drop-in reference miner
- **Classification:** Accepted limitation (not yet accepted by the owner). **Severity:**
  - Info for the trusted trial;
  - **High** for any public testnet;
  - Critical for a mainnet.
  **Confidence:** high on the mechanism; medium on the exact ratios.
- **Where:**
  - `randomx/src/config.rs:7` (`ARGON_SALT = b"RandomX\x03"`, the Monero parameters);
  - `consensus/src/pow.rs` (the seed is a block id, the input the 100-byte header);
  - the brief's measurements: full mode about 100 ms per hash per thread, light mode about 750 ms, against about 1 ms for reference full mode.
- **Scenario:**
  - The RandomX input is an arbitrary blob (the header), and the key is a 32-byte seed. A reference miner that accepts `(seed, blob, target)` jobs for `rx/0` can mine BlackSilk through a small template-to-job bridge.
  - The bridge needs the node's `/template`, a coinbase built with `miner::build_block`, and submission to `/block`.
  - **Example:** at about 10 H/s per thread in the pure-Rust full mode, seven devices × 8 threads give about 560 H/s. One 16-core desktop with a reference miner gives roughly 10–20 kH/s [A: typical public figures], which is more than 95% of the network.
  - Rented `rx/0` hash rate is sold on hash-rate markets [A]. In August 2025 a single pool (Qubic) held a majority of **Monero's** hash rate and caused a 6-block reorg (§10, refs 1–3). BlackSilk's network is many orders of magnitude smaller.
  - Under K4 (no reorg limit, no minimum chain work), such a miner can rewrite testnet history at will. It can also farm every block reward, which distorts the "Σ wallets = generated" check in a public setting.
- **Why the gap is structural:** reference RandomX speed comes from a JIT, which needs writable-then-executable memory and therefore `unsafe`. That is forbidden in project crates (the CI lint "No unsafe code"). A safe-Rust interpreter can get faster, but not to JIT speed [A]. The honest miner the project ships will therefore always be the slow one.
- **Recommendation:** an owner decision *before the v3 freeze* (§8, item 7):
  - **(a)** accept it for testnet, and document that PoW security on the testnet is nominal; or
  - **(b)** adopt a BlackSilk-specific RandomX parameter set: a different `ARGON_SALT`, and optionally program size or iteration tweaks, as Wownero and ArQmA did.
    - This removes the zero-effort drop-in and the direct rental markets for `rx/0`.
    - It does **not** stop someone from compiling a reference miner with the new constants.
    - The cost: new known-answer vectors are needed, generated by an off-project oracle (the reference implementation with the same constants, used only as a test oracle, never shipped), and it is a consensus change.
  - In both cases, measure the pure-Rust gap to the reference **interpreter** (not only the JIT) [U]. 100 ms per hash in full mode looks slow even for an interpreter, so safe-Rust optimization may reduce the gap by a large factor.

### R15-3: The chain identity is bound only by `network_id`, not by the genesis
- **Classification:** Partially implemented. **Severity:** Medium. **Confidence:** high.
- **Where:**
  - `p2p/src/transport.rs:161-168`: the session key is `H64("p2p/session", LE32(network_id) ‖ A ‖ B ‖ S)`, with no genesis id.
  - `wallet/src/wallet.rs:435-444`: `check_network` compares only the network **name** (`"testnet"`).
- **Scenario:**
  - The v3 procedure (§4) necessarily produces a release candidate and possibly rehearsal builds with the same network id but a placeholder genesis.
  - Any such node that is started connects to v3 nodes. It exchanges locators that never meet, and it wastes the peer's RandomX work on headers that cannot connect.
  - A v2 or rehearsal wallet file pointed at a v3 node passes `check_network` and reconciles against a foreign chain. The reset plan §4.5 relies only on user discipline here.
- **Recommendation:**
  - Add `genesis_id` to the session-key derivation, or send it as the first encrypted frame.
  - Store `genesis_id` in the wallet file and refuse a mismatch.
  - This changes the P2P protocol, not consensus. It is free to bundle with v3, because v3 breaks compatibility anyway.

### R15-4: The FTL does not prevent pre-mining with future timestamps. Only the reveal-to-start window bounds it
- **Classification:** Accepted limitation, with a design constraint for §4. **Severity:** Medium for a public launch; Low for the trusted trial. **Confidence:** high [M].
- **Mechanism:**
  - Block 1 needs a timestamp greater than `T_g` (MTP) and at most `now + 360` **at receipt** (`consensus/src/timestamp.rs`; docs/consensus.md §5: "not a permanent verdict").
  - A miner who knows the genesis at time `t_r` can mine a private chain whose timestamps lie in `(T_g, T_launch + 360]` and release it at `T_launch`.
  - Under most-work selection, its advantage is roughly its hash rate × `(T_launch − t_r)`. Packing the timestamps only raises the LWMA difficulty; the total work, which is what counts, is unchanged.
- **Consequence:** an unpredictable nonce protects against knowledge *before* `t_r`. After `t_r` everyone is equal, so the protocol must make "`t_r` → honest miners running" short and must not place `T_g` far after `t_r`.
- **What §4 does:** it fixes `T_g` **before** the beacon, so the genesis is already in the past at launch. The only remaining asymmetry is build and distribution time.

### R15-5: No release integrity chain, and the work exists on one machine
- **Classification:** Not implemented. **Severity:** Medium for the trial; High for a public testnet. **Confidence:** high [S].
- **Evidence:**
  - `git tag` is empty;
  - HEAD is unsigned (`%G? = N`);
  - there are no release binaries;
  - all 389 commits come from one identity (two e-mail aliases);
  - 8 commits are unpushed;
  - the CI tests jobs lack `--locked`, which is already known.
- **Scenario:** during the trial, "the release commit announced by the owner" (v2-validation §1) arrives over a chat channel. If the owner's account or channel is compromised, an attacker can announce a different commit, and nothing lets an operator tell the difference. If the developer machine fails, the unpushed hardening work and the agent worktrees are lost.
- **Recommendation:** §8, items 9–10.

### R15-6: A "platform-neutral kernel" needs more than a neutral `--remap-path-prefix`
- **Classification:** Not implemented (planned in v3 (c)). **Severity:** Medium. **Confidence:** medium-high.
- **Evidence:**
  - The only path string in `px/kernel.elf` is `C:\Users\Home 01\Desktop\BlackSilk\BlackSilk-Blockchain\px-core\src\hash.rs` [S: `grep -a` on the ELF]. It comes from the `assert!`s in `px-core/src/hash.rs:81,82,102`, whose `Location` data survives even though the guest `#[panic_handler]` ignores it (`zkvm/sdk/src/lib.rs:79-82`).
  - Remapping the prefix to a neutral string still leaves the *relative* part with OS-native separators (`px-core\src\hash.rs` against `px-core/src/hash.rs`), as the README already notes. So a neutral prefix alone gives *two* ids, one per OS [A: rustc's file-name formatting; the README observed it].
- **Recommendation:**
  - Remove every `Location`-carrying panic from the code reachable by the kernel. For example, route px-core's invariant failures through a guest-supplied abort hook, or make them return errors that the guest turns into `halt(1)`.
  - Add a **guard test**: the loaded segments of `kernel.elf` and `vault.elf` contain no `.rs` and no `:\` or `/home`-like substrings.
  - Require CI to reproduce `kernel.id` on **both** `windows-latest` and `ubuntu-latest`, and to get the same value.
  - Rationale: array-index bounds checks also carry a `Location` [A: rustc semantics]. Any future change could re-introduce a path, and the guard test catches that.

### R15-7: The trial is the only moment a supply audit is possible, and there is no tool for it
- **Classification:** Not implemented. **Severity:** Medium. **Confidence:** high [M]/[S].
- **Mechanism:**
  - v1 amounts are Pedersen-committed, and key images hide which outputs are spent. No one can compute the circulating v1 supply from the chain. Inflation is detected only by per-transaction validity, which is the thing under test.
  - The PX pool is ≥ 0 by rule.
  - In a closed seven-device world, V14 (Σ of all wallets, v1 and PX = `generated`) is a real end-to-end inflation check. On a public testnet it is impossible.
  - incident-response §3 says "No tool for the real testnet yet".
- **Recommendation:** before the trial:
  - write a small tool, or a documented wallet command sequence, that dumps each wallet's v1 and PX balances with the height;
  - mandate that every wallet, including every miner payout wallet, is kept and included;
  - run the audit at a fixed height on all devices at the end, and once in the middle.
  Losing one miner wallet makes V14 impossible.

### R15-8: Identity and build are not observable over RPC
- **Classification:** Partially implemented. **Severity:** Low. **Confidence:** high [S].
- **Where:** `rpc` `Info` has no `genesis_id` and no build commit or version. V1 relies on an 8-byte prefix in a log line (`node/src/main.rs:67-72`).
- **Recommendation:** add `genesis_id` (full) and `version` (crate version plus an optional commit, supplied through a build-time environment variable, so reproducibility is unaffected) to `/info`. Make `check-node.sh` print them, and make V1 compare the **full** id.

### R15-9: The seed-switch trial window, stated precisely
- **Classification:** Complete but requires further testing. **Severity:** Info. **Confidence:** high [M].
- **Mechanism:** `seed_height(h) = 0` for `h ≤ 2112` (`consensus/src/pow.rs:25-31`; [T: the chain.rs test "seed is genesis before height 2113"]).
  - The first key change happens at h = 2113, keyed by block 2048's id. At the target that is 2113 × 120 s ≈ 70.4 h after the first blocks.
  - The early LWMA ramp from D0 = 100 shortens this by minutes, not hours [M: the maximum rise per block is bounded by `n²T/20`].
- **Recommendation:** define the trial end as **height ≥ 2113 + 720 (≈ 24 h after the switch) and wall time ≥ 96 h**, whichever is later, and not "72 h".
  - Expect every full-mode miner to stall at the switch: about 179 s with 8 threads, up to about 20 min with 1 (known).
  - That is roughly one missing block, a useful LWMA observation.

### R15-10: Header verification cost scales badly for new nodes and amplifies low-work spam
- **Classification:** Accepted limitation (deepens known items). **Severity:** Medium for a public testnet. **Confidence:** medium.
- **Mechanism:**
  - Nodes verify with light mode at about 750 ms per hash in one header worker. Syncing N headers costs about 0.75·N s:
    - 2,113 headers ≈ 26 min;
    - 100 k headers (about 140 days) ≈ 21 h [M from the brief's figures; A that verification is not parallelized].
  - A reference-speed attacker (about 1 ms per hash) forking from a low-difficulty early height (D ≈ 100) pays about 0.1 s per header, while the victim pays 0.75 s. That is roughly 7× amplification in the attacker's favor, until minimum chain work or an equivalent exists (known item: "low-work header batches are hashed and stored").
- **Recommendation:**
  - Verify headers in parallel: independent per header given the seed.
  - Optionally use a full-mode verifier on nodes with 2.3 GB free RAM (about 7× faster).
  - Add a minimum-chain-work floor per identity. It is policy, not a checkpoint, and v3 can set it to 0 at launch and raise it at a release.

### R15-11: Windows desktop operations are an unlisted trial risk
- **Classification:** Not implemented (procedure). **Severity:** Medium for the trial's validity. **Confidence:** medium [A].
- **Scenario:** a 96-hour run on consumer Windows devices is at risk from:
  - automatic update reboots;
  - sleep or hibernate;
  - the w32time default sync interval: an unsynced clock with FTL = 360 s leads to blocks that others reject;
  - antivirus quarantining a miner binary (miners are commonly flagged as potentially unwanted applications) [A];
  - scanning locks on `blocks.dat`.
  Any of these produces a "crash" or "stall" that tests nothing.
- **Recommendation:** make these gates in §3 E, each with evidence.

### R15-12: Consensus governance has no activation mechanism other than a reset
- **Classification:** Deferred. **Severity:** Low now; High for mainnet. **Confidence:** high [S].
- **Evidence:** `HEADER_VERSION = 1` is the only valid version (`consensus/src/header.rs:9`). There is no signalling and no activation-height machinery; every rule change is a new identity (reset-plan §1).
- **Assessment:** fine for the testnet, and deliberately simple. For a public testnet with outside participants, a reset destroys their state each time.
- **Recommendation:** after the trial, design height-based activation (hard forks at a published height). Keep a numbered proposal record (see §5.5).

---

## 2. Scope answers: the 13 questions

The subsystems are: A = testnet readiness process and identity; B = genesis; C = decentralization (mining, seeds, maintainer, releases, governance); D = operations.

| Q | A: Readiness process / identity | B: Genesis | C: Decentralization | D: Operations |
|---|---|---|---|---|
| 1 Implemented | 14-gate checklist, reset plan, v2 validation list (V1–V16), labnet tool, isolation by network id [T: `different_networks_cannot_talk`] | Constant header, empty body, id = H(domain ‖ network_id ‖ header), pinned [T: `genesis_ids_are_pinned`] | Pure-Rust RandomX, LWMA-1, no premine, empty seed list, a documented approval process | Incident plan (roles, severities, signals, halt), systemd, Docker, `check-node.sh`, `/info` counters |
| 2 Correct and well designed | Honest status language; "never reuse an id"; evidence-before-claim | The genesis is never validated, so the nonce is a free, harmless field. The id binds network_id. The seed for epoch 0 is the genesis id, so the beacon also randomizes the first RandomX key [S] | No kill switch by design; seeds untrusted for correctness; Tor-aware seed rules | "Operators may halt on S1 without waiting"; evidence preservation; logs treated as private (IPs) |
| 3 Incomplete | G1/G2/G4–G14 open; v3 checklist not written | v3 procedure (this report §4) | Seeds, release signing, backups | Channel choice, private reporting (disabled), rehearsal, supply tool |
| 4 Fragile | v3 rules under the v2 id (R15-1); status spread over 5 documents | Placeholder builds with the real id (R15-3) | Everything depends on one person and one machine (R15-5) | Windows desktops (R15-11); clock (FTL 360 s) |
| 5 Exploitable | A stale checklist leads operators into a mixed network | Pre-mining in the reveal-to-start window (R15-4) | Reference-miner dominance and reorgs (R15-2); low-work header amplification (R15-10) | Channel compromise: a fake "release commit" (R15-5) |
| 6 Inefficient | Five documents restate gate status | — | 100× hash gap; single-thread header verification | Manual monitoring |
| 7 Does not scale | Owner as the only approver and incident lead | — | Sync cost linear at 0.75 s per header; all bodies in RAM (PX-F1) | No alerting; no metrics endpoint |
| 8 Missing | Network-id registry; a v3 validation list; a trial-end criterion tied to height | Beacon-derived nonce, pre-announcement, verification tool, tests | Signed tags, a second maintainer or backup, independent seeds, a proposal register | Supply-audit tool; per-device sampler; Windows hardening steps |
| 9 Redesign | One authoritative readiness file (fold the gate tables into the checklist; others link to it) | — | PoW parameters (R15-2 option b), if the owner wants PoW security beyond "nominal" | — |
| 10 Innovate | — | A combined beacon (Bitcoin ⊕ drand) for mainnet; OpenTimestamps on the announcement | Pooled solo mining without custodians (P2Pool-style) later; safe-Rust RandomX optimization | Labnet's sampler reused as a trial monitor |
| 11 Before testnet | §3 in full | §4 | R15-2 decision; R15-3; signed tag; off-site backup | §3 E; §6 |
| 12 Safely deferred | L4 review completion, per the owner's acceptance | Mainnet genesis design | Independent seeds (trial uses `--peer`); activation heights; decentralized pool | Public explorer, faucet |
| 13 Never change | "Never reuse an id"; the empty-body, no-premine genesis; the no-kill-switch principle | Header layout; id domain; the genesis-never-validated rule; epoch-0 key = genesis id | Most-work rule for the testnet (K4 is revisited only with data) | Halt order: miners first, then nodes |

---

## 3. Readiness gates before the seven-device trial

Every gate needs the named evidence **linked from AUDIT.md**. "Owner" means a written decision recorded in the repository.

### A. Code and identity freeze

| # | Gate | Evidence required |
|---|---|---|
| A1 | Hardening round merged. For the trial, at minimum: header queue bound; N-4 concurrent-handshake bound; H1 (connection target = most-work body-complete chain); the A6 storage revert; replay-order fix; mempool F1 tests; low-work header handling (at least bounded) | Commit ids; a named regression test per item; the CI run URL |
| A2 | **Every item that affects consensus is decided before the freeze**, so that v3 is the only identity change. Include: PX-F5 (B); neutral kernel; canonical proofs (done); **PX function output words, field-canonical vs raw u32** (docs vs code: either choice is a rule); **M3, the FRI folding schedule** (pin the arity or accept it); the RandomX parameter choice (R15-2); COMMIT_POW_BITS (0 with the zero-witness rule, or ≥ 1); PX-F4 recorded as deferred, **with the owner's acknowledgement that adopting it later means v4** | One decision table in AUDIT.md, signed off by the owner, with each item marked "in v3", "deferred to v4" or "accepted" |
| A3 | PX-F5 in the kernel: reject `contract ≠ 0 ∧ owner ≠ 0` | Tests: (i) the vault lock/claim still proves and verifies; (ii) a witness with owner ≠ 0 on a contract output makes the guest halt non-zero or the proof fail; (iii) the new `kernel.id` is pinned |
| A4 | Platform-neutral kernel (R15-6) | CI: `reproduce.sh` green on Windows **and** Linux with the same `kernel.id`; the guard test (no path strings in the loaded segments); one manual reproduction on a non-developer machine |
| A5 | Canonical proof rule (already implemented) | The existing test in `zk/tests/proofs.rs`, plus an integration test that a relayed non-canonical proof is refused and the relayer penalized (the error is stateless) |
| A6 | v3 identity: `network_id` = next unused (proposed `0x0001_D673`; ids for rehearsals and release candidates are taken from a separate, documented range); genesis per §4 | The id registry in docs/consensus.md; the §4 tests; the `node` refusal removed only in the final tag |
| A7 | Chain identity bound by genesis (R15-3) | A P2P test: same id, different genesis → handshake fails. A wallet test: wallet genesis ≠ node genesis → `WrongNetwork` |

### B. Build, CI and release

| # | Gate | Evidence required |
|---|---|---|
| B1 | CI green on the **exact tag**, all six jobs (lint, test, randomx-full, guests on both OSes, audit, fuzz-smoke). Test jobs use `--locked`; fuzz-smoke fails on zero executions | The run URL, and inspection of the job logs, not just the badge |
| B2 | Signed, annotated tag `testnet-v3`; the release-candidate tag `testnet-v3-rc` precedes it; `git diff testnet-v3-rc testnet-v3` touches only the genesis constants and tests | The tag signature verifies under a fingerprint published in the repository **and** in a second channel |
| B3 | Every device builds from the tag, records `git rev-parse HEAD` and the rustc version, and the node reports the full genesis id | The V1 record per device |
| B4 | Off-site copy of the repository, including unpushed work, before the freeze | Pushed branch or mirror; date |

### C. Pre-trial measurements with real RandomX

| # | Gate | Evidence required |
|---|---|---|
| C1 | Full-mode vectors and full = light agreement | The `randomx-full` CI job run URL |
| C2 | **The real seed switch, exercised.** Regtest uses the same E = 2048 and L = 64 with 10 s blocks, so a labnet regtest run past height ≥ 2400 with real RandomX and full-mode miners takes about 7 h and exercises the production code path at 2113 | Labnet `summary.json`; logs showing the new seed (block 2048's id) from height 2113; no rejected blocks around it |
| C3 | Cross-device hash check: every device class, ARM64 if present, runs `cargo test --release -p blacksilk-randomx` and one fixed header hash under the v3 genesis key | Output per device |
| C4 | Sync of ≥ 5,000 blocks from ≥ 3 peers; restart time and RSS with ≥ 100 PX transactions; ZK-F4 adversarial verifier cost | Numbers in the operator docs, or an accepted limitation |
| C5 | Local v3 rehearsal: 5 nodes on the release candidate with a **rehearsal id**; a v2 build and a placeholder-genesis build both refused | Labnet evidence directory |

### D. Trial design

| # | Gate | Evidence required |
|---|---|---|
| D1 | A v3 validation list replaces the v2 one. Changes: V1 compares the full genesis id; V14 uses the supply tool (R15-7); V15 states the expected memory growth (PX-F1); V10 names its tool; the end criterion is R15-9 | The document, reviewed |
| D2 | Hardware minimums published: node + full miner + PX proving ≈ 256 MiB × 2 + 2.3 GiB + 3.8 GB peak, so **≥ 8 GB RAM** on devices that prove; light mode below 3 GB | docs/testnet.md |
| D3 | Topology: ≥ 2 networks; explicit `--peer` lists; one device designated as the late joiner (H) | A plan table |
| D4 | Participants told plainly that anonymity at 7 participants is not meaningful and that coins have no value | A notice in the README and the guide |

### E. Operations

| # | Gate | Evidence required |
|---|---|---|
| E1 | Private channel chosen and members verified; backup contact | incident-response §1a filled in |
| E2 | GitHub private vulnerability reporting **enabled** | API `enabled: true` |
| E3 | Incident rehearsal (§8 of the plan): halt order, evidence collection, a rollback without a consensus change | A short record |
| E4 | Per-device sampler running (§6.1) | The first hour of CSV from every device |
| E5 | Windows hygiene: updates paused for the trial window; sleep and hibernate off; w32time resynced with skew < 10 s (`w32tm /query /status`); antivirus exclusion for the data directory and the binaries, or confirmation that the binaries are not flagged; RPC firewalled to loopback | A checklist per device |
| E6 | Fresh data directories; `peers.json` deleted; wallet files backed up; non-empty passwords | A checklist per device |

### F. Approvals
- The owner approves, separately: the v3 decision table (A2); the genesis announcement (§4 step 2); the final tag; the start of the trial.
- The trial report may call the result a "functional trial", never "audited" or "secure".

---

## 4. The v3 genesis procedure

### 4.1 Design

**The only field that carries entropy is `nonce`, a u64.**
- `version = 1`, `height = 0`, `prev_id = 0³²`, `tx_root = 0³²` (empty body; blocks.md §3), `difficulty = D0 = 100`, and `timestamp = T_g`, which is pre-announced.
- The genesis is never validated, so any nonce is legal [S: blocks.md §3; `params.rs:89-97`].
- The id is `Blake2b-256("BlackSilk/block-id" ‖ LE32(network_id) ‖ header)` (`header.rs:52-58`).
- 64 bits of unpredictability is ample: an attacker must guess the nonce exactly, with probability 2⁻⁶⁴ per guess [M].
- Because the epoch-0 RandomX key is the genesis id [T: the chain.rs test "seed is genesis before height 2113"], the first key is unpredictable too. No one can pre-build the first dataset.

**Beacon: the hash of Bitcoin mainnet block at a pre-announced height `H`.**
- Anyone can verify it against a Bitcoin node or several explorers, with no cryptography beyond comparing strings.
- Biasing it costs a Bitcoin block reward: a miner would have to withhold a found block. See Bonneau, Clark and Goldfeder 2015 (§10, ref 4), who bound manipulation cost and measure ≥ 68 bits of min-entropy per block.
- drand quicknet (BLS12-381, 3 s rounds, unchained; §10, refs 5–6) is a good alternative. Offline verification needs a pairing library, so it would need a new pure-Rust dependency or external tools. For the testnet, Bitcoin alone suffices. Combining both (`H(btc ‖ drand)`) is an option for mainnet.

**Derivation (fixed in the announcement):**
```
beacon  = 32 bytes of the block hash IN DISPLAY ORDER
          (the hex printed by `bitcoin-cli getblockhash H` and shown by explorers, decoded left to right)
d       = Blake2b-256( "BlackSilk/genesis-nonce/v1" ‖ LE32(network_id) ‖ LE64(H) ‖ beacon )
nonce   = u64::from_le_bytes(d[0..8])
```
- The domain string, network id and height make the derivation single-purpose.
- Using the display order avoids the classic reversed-byte bug. State it explicitly and test it (§4.4).

**Timestamp `T_g`:**
- Fixed in the announcement, and chosen about **2 h before H's expected time**. H's expected time is the current Bitcoin height plus the remaining blocks, × 600 s.
- The genesis is then (almost surely) already in the past when anyone can compute it. No valid block can be "saved for later" with a future timestamp beyond the normal 360 s, and the pre-mining window is only reveal → honest start (R15-4).
- **Cost:** at launch, block 1 comes ≥ 720 s after `T_g`. LWMA caps that solve time at 6T, so **block 2's difficulty is ⌊100·120·2 / (2·720)⌋ = 16** [M: difficulty.rs]. The ramp then brings it back within tens of blocks, because the rise per block is bounded by `n²T/20`. This is harmless and must be covered by a test (the "genesis-to-launch gap" test the completion report lists as missing).
- **The alternative, `T_g` after the beacon, is rejected:** it opens a window in which anyone who knows the beacon mines future-timestamped blocks until `T_g`.
- **MTP:** block 1 needs a timestamp greater than `T_g`. The miner uses `max(now, min_timestamp)` (`miner/src/lib.rs:58`), so this holds automatically.

### 4.2 Steps

1. **Freeze all non-beacon fields** (after A1–A5 and A7 are merged).
   - Tag `testnet-v3-rc`, signed. It contains:
     - `network_id` (proposed `0x0001_D673`), `D0` and `T_g` as constants;
     - `GENESIS_NONCE` as a placeholder;
     - `BTC_BEACON_HEIGHT = H`;
     - a `derive_genesis_nonce(network_id, height, beacon_display_hex) -> u64` function in `consensus` (pure, tested with the known-answer vector in §4.4);
     - **`--network testnet` refusing to start** ("v3 genesis not final").
   - CI green on the release candidate. Operators may pre-build it to warm `target/`.
2. **Announce** at least 48 h before H's expected time.
   - The announcement is a committed, pushed document (`docs/testnet-v3-genesis.md`) and a signed tag or message. It gives: `network_id`, `T_g` (Unix seconds and UTC), `D0`, `H`, the exact derivation and domain string, the confirmation rule, and the fallback rule.
   - Optionally, stamp the commit hash with OpenTimestamps. It anchors the announcement time in Bitcoin, using an external tool only.
   - **Confirmation rule:** use block H once it has **6 confirmations**, which leaves about 1 h of window.
   - **Fallback rule:** if a reorg replaces H before it is 6-deep, use the new H at that height. Nothing else moves.
3. **Wait for H + 6.** Two people, the owner and one operator, independently obtain H's hash from ≥ 2 sources (their own Bitcoin node, or two explorers run by different organizations), and compare.
4. **Compute:** `cargo run -p blacksilk-consensus --example v3_genesis -- <hex>`. It prints the nonce and the full genesis id. Both people compare.
5. **Commit the final values:**
   - `GENESIS_NONCE`, `BTC_BEACON_HASH_HEX` (kept in the source for provenance), the pinned `TESTNET_GENESIS_ID`;
   - removal of the refusal;
   - docs/testnet.md §1 and docs/consensus.md §1.
   `git diff testnet-v3-rc HEAD` must show **only** these. Tag `testnet-v3` (signed) and push. CI runs, but operators need not wait for the long test job: the change after the release candidate is constants only, and the pin test is fast. The owner must still record the full CI run before the trial report.
6. **Operators:**
   - verify the tag signature and the diff against the release candidate;
   - verify H's hash independently (step 3);
   - build and start the node;
   - V1: `/info` `genesis_id` equals the announced full id;
   - start miners.
   Target: ≤ 1 h from H + 6 to all seven running.
7. **Retire:** record the id in the registry. Never reuse it, the release-candidate id or any rehearsal id.

**Who can verify, and how, later:** anyone, with any Blake2b implementation (for example `b2sum -l 256` on the concatenated bytes) and a public Bitcoin hash. There is no trust in the maintainer. The pinned test re-derives the nonce on every CI run.

### 4.3 Bugs to avoid

- **Byte order:** use the display order versus the internal little-endian order of the Bitcoin hash consistently. Test it with a known block.
- **Hex versus bytes:** hash the 32 decoded bytes, not the ASCII hex.
- **Nonce extraction:** use little-endian `d[0..8]`, and test it.
- **Grinding after the reveal:** every field except `nonce` is frozen in the announcement. A changed `T_g`, `D0` or id after the reveal voids the procedure.
- **Ids and data:** a release candidate or rehearsal node joining with the real id is prevented by the refusal plus R15-3. Old data directories: operators use fresh directories.
- **Time zones:** give `T_g` as Unix seconds. Check it with `date -u -d @T_g`.
- **Showing only the 8-byte prefix:** V1 must compare the full id.
- **The Bitcoin block's own timestamp** plays no role. Do not use it for `T_g`: it may be up to 2 h off real time.
- **`T_g` later than the reveal:** do not let it happen (R15-4). If H arrives unusually early, earlier than `T_g`, the fallback is simply to wait. The window is then at most about 2 h of equal-access mining, which is acceptable for a trusted trial and documented.

### 4.4 Tests to pin

1. **Known-answer vector** for `derive_genesis_nonce`, using Bitcoin block 0:
   - hash `000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f`, H = 0, and a test network id;
   - expected nonce computed once and pinned;
   - plus a reversed-byte-order input asserting a **different** nonce.
2. `testnet().genesis.nonce == derive_genesis_nonce(TESTNET_ID, BTC_BEACON_HEIGHT, BTC_BEACON_HASH_HEX)`.
3. `genesis_ids_are_pinned` updated to v3.
4. **Explicit field asserts** on the testnet genesis: version 1, height 0, `prev_id` 0, `tx_root` 0, difficulty 100, timestamp `T_g`. This stops a future edit from silently moving entropy into another field.
5. **Id registry:** `network_id` differs from `{0x0001D670, D671, D672}`, from rehearsal and release-candidate ids, and from mainnet and regtest.
6. **Genesis gap:** block 1 at `T_g + 7,200` gives block-2 difficulty 16, and the difficulty reaches ≥ D0 again within the ramp. This covers the untested "genesis-to-launch gap".
7. **The refusal:** `--network testnet` errors in the release-candidate build. This is a unit test on the config, removed in the final commit.
8. **R15-3 tests:** handshake with a different genesis fails; the wallet refuses a different genesis.

---

## 5. Decentralization risks, now and at scale

### 5.1 Mining

**In the trial.** Hash rate differs by device (full mode vs light mode, core counts). One device may find most blocks.
- This is harmless, and it tests LWMA under skew.
- Record the share of blocks per miner in the trial report; the coinbase goes to known wallets.

**Public testnet.** R15-2 dominates: expect a single reference-speed miner to hold a majority.
- Combined with K4 (no depth limit, no minimum chain work), the testnet has **nominal** PoW security, and the docs should say so.

**At scale (mainnet).** A standard `rx/0` chain with a small hash rate is an obvious target for rented hash rate. Monero itself had a single-pool majority and a 6-block reorg in August 2025 (§10, refs 1–3). Options:
- a BlackSilk-specific RandomX variant;
- an optimized safe-Rust interpreter, to narrow the honest miner's gap;
- finality or checkpoint policy (K4 §5);
- merge-mining is **not** recommended: it gives a larger chain's miners control.

**Pools.** None exists, so solo mining only. That is fine for 120 s blocks at small scale. Later, a P2Pool-style decentralized pool avoids custodial pool centralization.

### 5.2 Seed nodes and bootstrap
- **Now:** the built-in list is empty (`node/src/config.rs:18-24`). The trial uses `--peer`. This is correct for the trial.
- **Risk:**
  - If the owner runs every seed, one party sees every joining IP (privacy) and controls first contact (eclipse, N-7 and N-8).
  - Stale peer tables never fall back to seeds (completion report §2).
- **Before a public testnet:**
  - ≥ 3 seeds under independent operators in different ASes, plus ≥ 1 `.onion` seed;
  - fall back to seeds when the table is stale;
  - no DNS seed under a single registrar account.

### 5.3 Maintainers (key-person risk)
- **Facts:**
  - one committer identity;
  - one decision-maker for consensus, releases, incidents and disclosure;
  - an AI assistant that acts only through the owner (incident-response §1);
  - 8 unpushed commits;
  - hardening fixes in local worktrees.
- **Mitigations, cheapest first:**
  1. Push, or mirror to a private remote, daily.
  2. GitHub account hardening: a hardware security key for 2FA; branch protection on `main` and `rebuild/core` (no force-push).
  3. A second person with repository recovery ability (org-owned repository or a documented break-glass).
  4. A mirror on a second host (for example Codeberg), with tags.
  5. A written "if the owner is unreachable" rule: operators may halt; nobody may release.

### 5.4 Release signing and supply chain
- **Now:** no tags, no signatures, no binaries. Operators build from a commit id received over chat.
- **Recommend:**
  - signed tags (git SSH or GPG signing; GitHub shows verification);
  - the signing key's fingerprint published in the repository and in a second channel;
  - later, a `SHA256SUMS` signed file for binaries, and rebuilds of the Linux binaries by ≥ 2 builders [A: needs work to be bit-reproducible].
- CI's `dtolnay/rust-toolchain` is pinned to a SHA of branch `master` [S]. That is acceptable, since it is pinned, but note the provenance.

### 5.5 Governance of consensus changes
- **Now:** a sound written process (analysis → … → owner approval), but a single approver and no public record per change except commit messages and AUDIT.md.
- **Recommend:**
  - a numbered consensus-change register (`docs/proposals/NNNN-*.md`) with its status, identity impact and tests;
  - a minimum review window before approval;
  - for testnet resets, the operators' acknowledgement.
- For mainnet: height-based activation instead of resets (R15-12), and a stated policy on who may propose, review and veto.

### 5.6 Dependence on one developer machine for the consensus kernel
- **Now:** partly mitigated. CI reproduces `kernel.id` on `windows-latest` by remapping to the developer's path [S: ci.yml job `guests`; README "Verified … C:\bszkeval\repro"]. The consensus id therefore still embeds a personal path, and reproduction requires Windows.
- **After v3 (c) and R15-6:** reproducible on 2 OSes with no path bytes.
- **Residual:** the rustc 1.98.1 codegen is a trust dependency. Accept it, and record the toolchain hash.
- **Recommend:** at least one operator, not the owner, runs `reproduce.sh` before the trial and reports the id (gate A4).

### 5.7 Hosting and communication
- GitHub is the single host for code, CI, vulnerability reports and announcements.
- If the account is suspended or compromised, all four fail together. The mirror and the backup channel (incident-response §1a) address this.

---

## 6. Operational risks

### 6.1 Seven-device trial

| Risk | Likelihood | Impact | Mitigation (gate) |
|---|---|---|---|
| Windows reboot, sleep or antivirus interrupts the run | High [A] | A false "crash"; V15 invalid | E5 |
| Clock skew > 360 s | Low–medium | Blocks rejected until the clock catches up; false-divergence alarms | E5; the sampler records `date` against the block timestamps |
| Mixed builds or identities | Medium without R15-1/3 | Silent fork | A6, A7, B2, B3 |
| Seed switch at 2113 | Unknown with real RandomX | Stall or split | C2 before the trial; watch heights 2100–2130 live |
| Memory growth (PX-F1) misread as a leak | High | V15 false failure | D1 states the expected slope (about 7 KB per block plus bodies) |
| Lost miner wallet | Medium | V14 impossible | R15-7; backups |
| The owner unavailable during an S1 | Medium over 96 h | Delayed halt | Operators halt on S1 themselves (already allowed); the second contact route |
| Private data in the evidence (IPs in logs) | Certain | Privacy | Logs stay in the private channel; redact before publishing (already in §5 of the plan) |

**Monitoring without new infrastructure:**
- On each device, a script polls every 60 s: `/info`, `/px/commitments` and the process RSS. It appends to a CSV, and it also records the **block id at height h − 6** (comparable across devices without tip races).
- Alert locally, for example with a printed "CRITICAL" line, on:
  - peers = 0;
  - height unchanged for 30 min. At 120 s blocks, P(no block in 30 min) ≈ e⁻¹⁵ if hash rate is stable, so this is a real signal;
  - `deepest_reorg ≥ 10`;
  - `misbehaving_disconnects` increased;
  - RSS slope above the expected value;
  - any `VerifierPanicked` log line.
- Twice a day, the owner compares the h − 6 ids across the seven devices.
- Labnet's sampler is the natural code base for this [S: tools/labnet samples every 15 s].

**Rollback during the trial:**
- A non-consensus bug: previous binaries, same data (incident-response §6).
- A consensus bug: halt, preserve, fix, then **v4** with the next id from the registry.
- Never "patch and continue" on a chain that contains an invalid block (incident-response §4.2 is correct).

### 6.2 Public testnet (after the trial)
- **Additional risks:**
  - reference-miner dominance and arbitrary reorgs (R15-2, K4);
  - low-work header spam amplified by the hash-speed gap (R15-10);
  - the RPC exposed by careless operators (no auth);
  - eclipse of new nodes through owner-run seeds;
  - wallet users on remote nodes (plaintext, trusted for PoW);
  - reset fatigue (R15-12).
- **Minimum additions:**
  - independent seeds;
  - minimum chain work (policy);
  - parallel header verification;
  - an RPC auth token and rate limits;
  - a metrics endpoint;
  - the published statement that PoW security is nominal;
  - an explorer is optional.
  The incident plan scales poorly beyond "operators are the owner's contacts": a public testnet needs a public status page (a pinned issue suffices) and a clear "we will reset" policy.

---

## 7. What should never change (in scope)
- **Never reuse a network id**, and never ship a binary whose testnet genesis is not final.
- **The genesis stays unvalidated**, with an empty body and no premine. Entropy goes only into `nonce`.
- **No protocol kill switch**, no admin key and no checkpoint server signed by the maintainer. Each would give the single maintainer a centralization lever that outweighs its operational convenience.
- **Seeds stay untrusted for correctness.**
- **Epoch-0 RandomX key = genesis id** (it makes the beacon also randomize the first key).

---

## 8. Recommendations

Consensus impact: none / policy / **CONSENSUS**. ID: whether a new testnet identity is needed. Diff.: implementation difficulty.

| # | Recommendation | Why | Security | Privacy | Performance | Complexity | Consensus | ID | Diff. | Prio |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | Retire `0x0001D672`: testnet refuses to start until the v3 genesis is final; mark the v2 documents superseded (R15-1) | Prevents a mixed-rule network | High (+) | none | none | low | none (it guards against a consensus mismatch) | part of v3 | S | **P0** |
| 2 | v3 genesis per §4 (beacon nonce, `T_g` before the beacon, pre-announcement, dual verification, 8 tests) | Removes the maintainer's pre-mining ability; verifiable launch | Medium (+) | none | none | low | **CONSENSUS** (genesis) | yes (the planned v3) | S | **P0** |
| 3 | A2 decision table: close or defer every consensus-affecting item before the freeze (output-word encoding, M3 folding schedule, COMMIT_POW_BITS, RandomX parameters, PX-F4 as deferred to v4) | "One identity" must be true | High | — | — | low (a decision) | decides CONSENSUS items | defines v3 | S | **P0** |
| 4 | Platform-neutral kernel: no `Location` panics in kernel paths; a path-string guard test; reproduction on Windows and Linux (R15-6) | Removes the developer-path and OS dependence of a consensus id | Medium (+) (verifiable build) | removes a personal path from consensus data | none | low–medium | **CONSENSUS** (`kernel.id`) | v3 | M | **P0** |
| 5 | Bind the genesis id in the P2P handshake and in wallet files (R15-3) | Stops release-candidate, rehearsal or stale nodes and wallets from mixing | Medium (+) | Low (+) (wallet does not reconcile against a foreign chain) | none | low | none (P2P protocol) | bundle with v3 | S | **P0** |
| 6 | Supply-audit procedure or tool, and mandatory wallet retention (R15-7) | The only end-to-end inflation check that will ever be possible on this chain | High (+) | Low (−) (balances are shared inside the trusted group) | none | low | none | no | S | **P0** |
| 7 | Owner decision on RandomX parameters: tweak (option b) or accept with docs (R15-2) | Reference-miner dominance | High for public nets | none | none for honest miners | medium (new vectors; external oracle) | **CONSENSUS** if tweaked | only if bundled in v3 | M | P0 decision; implementation P1 |
| 8 | `/info` exposes the full `genesis_id` and the version or commit; `check-node.sh` prints them (R15-8) | Operators verify identity | Low (+) | none (node-local RPC) | none | low | none | no | S | P1 (before the trial if cheap) |
| 9 | Signed tags plus a published fingerprint; `--locked`; release-candidate and final tag flow | Operators can authenticate the release | High (+) | none | none | low | none | no | S | **P0** for the trial |
| 10 | Daily off-site push or mirror; 2FA with a hardware key; branch protection; a second host mirror | Key-person and single-machine risk | Medium (+) | none | none | low | none | no | S | **P0** (push/mirror); P1 (others) |
| 11 | C2: labnet regtest past height 2400 with real RandomX and full-mode miners | Exercises the actual 2113 switch before relying on it | High (+) | none | about 7 h of machine time | low | none | no | S | **P0** |
| 12 | Trial end = max(96 h, height 2113 + 720) (R15-9) | Observes the switch and its aftermath | — | — | — | none | none | no | S | **P0** |
| 13 | Windows operations checklist (R15-11); a per-device sampler with alerts (§6.1) | Trial validity; detection | Low (+) | Logs private | Negligible | low | none | no | S | **P0** |
| 14 | Parallel header verification; optional full-mode verifier; a minimum-chain-work floor (R15-10) | Sync time at scale; spam amplification | Medium (+) | none | large (+) for sync | medium | **policy** | no | M | P2 (before a public testnet) |
| 15 | Independent seeds (≥ 3 operators, ≥ 1 onion); fall back to seeds when stale | Eclipse; privacy of joiners | Medium (+) | Medium (+) | none | low | none | no | S (code); the operators are the hard part | P2 |
| 16 | Consensus-change register and height-based activation design (R15-12, §5.5) | Governance transparency; no resets on public networks | Medium (+) | none | none | medium | **CONSENSUS** mechanism (future) | future | M–L | P3 |
| 17 | Safe-Rust RandomX interpreter optimization, with a measured gap to the reference interpreter | Narrows honest miners' disadvantage and node sync cost | Medium (+) | none | large (+) | medium–high | none (the vectors must stay identical) | no | L | P3 |
| 18 | One authoritative readiness document (the checklist); the others link to it | Five documents drift (completion report §2 "Documentation") | Low | none | none | low | none | no | S | P1 |

---

## 9. Items to deepen or correct from the brief and the documents

- **Brief, "the genesis nonce is the only free field":** confirmed [S]. It is 64 bits, not 256. It is sufficient [M], but the derivation must hash the beacon, not truncate it, so that the full beacon entropy is mixed in.
- **Completion report, "Anyone can pre-mine from the public genesis":** correct for v2. For v3, the right statement is "anyone can mine from the reveal onward; the maintainer has no head start" (R15-4).
- **v2-validation V1 "first log line (genesis 6556f92dee4df050)":** an 8-byte prefix is a weak identity check. Replace it with the full id (R15-8).
- **Reset plan §3, "Seed-node list: the same hosts":** no seed hosts exist. The completion report already flags this; still stale.
- **The completion report's P0 "no new reset is needed":** superseded by the owner's v3 decision and by `4b277cd`. Documents that still say v2 is the next network are stale (R15-1).
- **incident-response §4.3, "record it as a finding for the independent reviewer":** no independent reviewer exists (review-status §1). Reword to "record it in AUDIT.md".

---

## 10. Sources
1. Halborn, "Explained: The Monero 51% Attack (August 2025)": https://www.halborn.com/blog/post/explained-the-monero-51-percent-attack-august-2025
2. CoinDesk, "Monero's 51% attack problem: inside Qubic's controversial network takeover" (2025-08-12): https://www.coindesk.com/business/2025/08/12/monero-s-51-attack-problem-inside-qubic-s-controversial-network-takeover
3. Bitcoin.com News, "Security Experts Flag Possible 51% Attack on Monero, Citing 6-Block Reorganization": https://news.bitcoin.com/security-experts-flag-possible-51-attack-on-monero-citing-6-block-reorganization/
4. J. Bonneau, J. Clark, S. Goldfeder, "On Bitcoin as a public randomness source", IACR ePrint 2015/1015: https://eprint.iacr.org/2015/1015
5. drand, "`quicknet` is live on the League of Entropy mainnet" (2023-10-16): https://docs.drand.love/blog/2023/10/16/quicknet-is-live/
6. drand, "Verifying the `quicknet` beacons on Ethereum" (2025-08-26): https://docs.drand.love/blog/2025/08/26/verifying-bls12-on-ethereum/

**Repository references:**
- consensus/src/params.rs:55-62, 89-97;
- consensus/src/header.rs:9, 52-58;
- consensus/src/pow.rs:25-31;
- consensus/src/difficulty.rs:24-41;
- consensus/src/timestamp.rs;
- p2p/src/transport.rs:161-168;
- wallet/src/wallet.rs:435-444;
- node/src/config.rs:18-24, 150;
- node/src/main.rs:67-72;
- miner/src/lib.rs:58;
- miner/src/main.rs:86-106;
- randomx/src/config.rs:7;
- zk/src/lib.rs:186-240 (commit 4b277cd);
- px-core/src/hash.rs:81, 82, 102;
- zkvm/sdk/src/lib.rs:79-82;
- zkvm/guests/{build.sh, reproduce.sh, README.md};
- .github/workflows/ci.yml;
- SECURITY.md.
