# 47 docs-spec-consistency: research dossier (phase 2, phase 1)

**Internal engineering research, not an audit.** Read-only on the repository; no build or
test was run. Nothing here claims BlackSilk is secure, audited or production-ready. ZK is
described only as statistical and conditional.

Commit: `9e422d8` (`git rev-parse --short HEAD`), branch `rebuild/core`.

---

## 1. Scope and what I read

**Brief, roster, decisions:** `C:/bszkeval/p2/brief.md`, `roster.md` (header, 40–50),
`decisions.md` (all, incl. PX-only/ADR-28-1, R2-C6 option A, C4/D8 option B, 03 fix,
zk.md rewrite, contracts.md → research, security headline), `status.md`.

**Every dossier present in `C:/bszkeval/p2/research/` at writing time:** 01–23, 25–31,
34–37 (findings and implementation-plan sections in full; doc-related passages located by
grep in all of them). Dossiers 24, 32, 33, 38–46, 48–50 did not exist yet; see §7 Q7.

**Documentation, read in full:** `README.md`, `docs/consensus.md`, `docs/blocks.md`,
`docs/transactions.md`, `docs/p2p.md`, `docs/px.md`, `docs/zk.md`, `docs/zkvm.md`,
`docs/testnet.md`, `docs/testnet-v3-genesis.md`, `docs/testnet-launch-checklist.md`,
`docs/testnet-roadmap.md`, `randomx/README.md`, `SECURITY.md`,
`docs/reviews/full-review-2026-09-27/R14-docs-dx.md` (D-1…D-13, §3, §4),
`docs/reviews/review-status.md`.
**Read in part (status headers, claims located by grep, sections cited by dossiers):**
`AUDIT.md` (status block 1–50, R7 wasmi 700–740, R8 739–909, R13 1490–1579, register
988), `docs/contracts.md` (banner 1–40, 315–325, 540–556, 980–990), `docs/testnet-reset-plan.md`,
`docs/testnet-v2-validation.md`, `docs/testnet-incident-response.md`, and every file of
`docs/reviews/*.md` (header plus claim grep), `docs/evidence/*/README.md`,
`docs/evidence/px0-2026-09-23/RESULTS.md`, `zkvm/guests/README.md` (path independence),
`docs/reviews/full-review-2026-09-27.md` (register rows cited below, P0-15/16/17).
CSV/log evidence files were not read line by line (not claims).

**Code read to verify claims:** `consensus/src/params.rs:1-120`, `node/src/config.rs:140-175`,
`node/tests/deploy_configs.rs:236-244`, `node/src/lib.rs:157-165` (routes),
`chain/src/block.rs:10-13`, `chain/src/mempool.rs` (constants), `tx/src/params.rs:10-50`,
`p2p/src/net.rs:636-654, 938, 967-1020`, `p2p/src/message.rs:20-21`, `randomx/src/lib.rs:201-230`,
`wallet/src/file.rs` (header), `wallet/src/px.rs:88-92`, `git show 53d3b49`, test-attribute count.

**Web (only for externally cited claims):** ePrint 2025/2055, 2024/1037, Monero PR #7025,
the Monero CLSAG audit, the Quarkslab dalek audit (§8).

**Evidence classes used:** [src] source-read, [test] named test, [web] primary source,
[grep] repository-wide search, [dossier NN] finding carried from another dossier and
spot-checked unless marked (unverified).

---

## 2. Current state

**What is correct and well designed (keep):**
- The claims discipline is strong and mostly consistent: "internal, not an audit",
  "statistical and conditional" ZK, "not production-ready" appear in every spec header
  [grep]. `review-status.md` §1–3 and `SECURITY.md` are precise [src].
- v1 specs are close to second-implementation quality: transactions.md §4 byte grammar,
  §5.2 ordering, §8 rule tables, §12 Janus analysis; consensus.md §2–§7; blocks.md
  normative/policy split (§1–6 vs §7–9) [src].
- `testnet.md` status block (12–18) is the one place that correctly states the v2 identity
  is retired and the testnet disabled, matching `node/src/config.rs:144-161` [src].
- The "4 PX per block" statements named by P0-15 are already corrected to 3 in all 8
  places [grep]; what remains is the shape qualification (D47-40).
- Cited external sources checked: ePrint 2025/2055 is Ben-Sasson–Carmon–Haböck–Kopparty–Saraf
  "On Proximity Gaps for Reed–Solomon Codes" (zk.md:539 correct); ePrint 2024/1037 is
  Haböck–Al Kindi "A note on adding zero-knowledge to STARKs" (zk.md:560, zkvm.md:225 correct);
  Monero PR #7025 sets fluff 20 % and a 39 s embargo (p2p.md:324 correct); the CLSAG
  audit by Aumasson and Vennard (OSTIF, report 2020-07-29) exists (transactions.md:422-423
  correct) [web].

**What is wrong structurally (evidence):**
- **Eight status blocks disagree.** Six live documents say the v2 identity is "approved
  and fixed in code"; code and testnet.md say it is retired (D47-01). R14 D-3 predicted
  exactly this [src].
- **Normative content for PX/ZK is still split and partly false.** zk.md is a design
  document that still describes a Wasm-integrated architecture and a kernel statement
  that differs from the code (D47-20…D47-27); px.md has no normative marker and no rule ids
  (R14 D-1, 11 F11-6) [src].
- **Measured figures are copied into many files and go stale independently** (proof size
  2.04 vs 2.18 MB, verify 188 vs 207 ms, 0.45/0.6 s RandomX, 3.4 s lock hold, 450 tests,
  fingerprints) (D47-05, D47-35, D47-47, D47-60) [src].
- **Several consensus decisions of this phase invalidate existing spec text** (C4 option B,
  03 rise cap, F-20-1, R12-2 (a′), PX6 window, ABI_VERSION, D-identity, rule revisions);
  nothing today ties a rule change to its spec text or vectors (§3.3).
- **No test or CI job checks any document** (links, banned claims, pinned values) [grep of
  `.github/workflows/ci.yml` shows none].

---

## 3. Problems in scope (standard questions)

### 3.1 Docs contradict code or decisions (roster Q1)

- **What / why.** Docs are hand-maintained prose updated by whichever agent touched the
  code; status and figures are copied, not referenced. The v3 merge (9e422d8) and the
  2026-09-27 hardening changed many facts in one day.
- **Security consequence.** Operator-facing errors are the dangerous ones: a trial operator
  comparing the fingerprint in testnet.md §2.1 against a correct build sees a mismatch
  (D47-02) or, worse, trusts a stale identity statement (D47-01); a wallet user told the
  remote-node risk is "ring members" is not told the real leaks (IP, birthday, send timing;
  D47-12). Spec errors (zk.md kernel statement, Hk node claims) mislead second
  implementers and contract authors (19 F1: reusing `node()` with free leaves is an
  instant forgery).
- **Classification.** Not consensus-critical by itself; privacy-critical for D47-12,
  D47-13; security-claim accuracy for D47-06…D47-09.
- **Prior art.** Zcash keeps one protocol spec (with a changelog and "pre-activation"
  markers) plus ZIPs; Bitcoin Core keeps release notes per version and never restates
  status in design docs; Monero's research-lab separates papers from code docs.
  Diátaxis separates reference from explanation. (Sources §8.)
- **Trade-offs.** Consolidating status into one file costs one edit per file now and saves
  a class of drift; generating tables (fingerprints) from code costs a small test.
- **Tests that prove the fix.** A doc-lint job: (a) link check; (b) banned-phrase grep with
  an allowlist; (c) a test that the fingerprint table in testnet.md equals the pins in
  `node/tests/deploy_configs.rs`; (d) a rule-registry completeness test (every
  `TxError`/`BlockError`/`HeaderError` variant appears in the spec table; 11 I7).
- **Invariants.** Code (then vectors) decides; docs describe the code as the rule (R14 §5).
  Never "fix" code to match prose without the consensus pipeline.

### 3.2 Stale or overclaiming statements (roster Q2)

The roster's three named items:
- **"4 PX".** Fixed to 3 everywhere [grep]; remaining error: 3 holds for transfers only;
  vault calls fit 3, `n_fn = 2` shapes about 2 [est, 22], a maximum-size proof 1 (D47-40).
- **"Hk comment".** The code comment was corrected in `53d3b49`; the **normative docs still
  claim collision and preimage resistance of the node compression** (px.md:57-58, 483-484;
  zk.md:772-774, 809; zk-security-review.md:34) and zk.md:226 even specifies a different
  node construction, `Hk("px/node", l‖r)` (D47-08). Under R2-C6 option A the correct
  statement is the tree-binding argument of ePrint 2026/089 with the adaptation (19 item 1).
- **"audited".** Remaining overclaims: `crypto/Cargo.toml:11` "audited by Quarkslab (2019)";
  wasmi "0.38 covered by an external audit" (contracts/Cargo.toml:13-16, contracts.md:546-552,
  985-987, AUDIT.md:712,717, dependency-review.md:38); AUDIT.md's title and :45 (D47-10,
  D47-11). The Quarkslab report exists [web] but was commissioned by Tari in 2019 for the
  curve25519-dalek of that time; BlackSilk pins `=4.1.3`, which it does not cover.

### 3.3 Normative spec structure (R14 D-1) — see §5 W47-9 and the plan in §5.2

### 3.4 Coordination of many doc edits (brief deliverable 3) — see §5.3

---

## 4. Findings

### 4.1 Summary findings (this dossier)

| ID | Severity | Status | Location | Scenario | Confidence |
|---|---|---|---|---|---|
| F47-1 | **Medium** | Not implemented | D47-01 (11 files) | An operator or agent reads README/AUDIT/consensus.md/zk.md/checklist and believes the v2 identity is the approved trial identity; code refuses `--network testnet` | High [src] |
| F47-2 | **Medium** | Not implemented | `docs/testnet.md:97-98` vs `node/tests/deploy_configs.rs:236-240` | The §2.1 operator identity check publishes fingerprints `e7b89863…`/`d56ea868…`; the pinned values are `8876128f…`/`9cb0c0bf…`. Every correct build "fails" the documented check, training operators to ignore it | High [src] |
| F47-3 | **Medium** | Not implemented | D47-06…D47-09, D47-20…27 | Security figures, quantum claims and Hk/node claims in normative docs contradict the adopted headline and R2-C6; zk.md specifies a kernel statement and a Wasm integration that do not exist | High |
| F47-4 | **Medium** (privacy guidance) | Not implemented | D47-12 | Users are told the remote-node leak is "which ring members it fetches" (false since `2b0f75a`); the real leaks (IP, birthday, send timing, tx↔IP) are not listed | High [src + 36] |
| F47-5 | **Medium** (process) | Not implemented | whole `docs/` | No doc is checked by CI; every figure is copied; 20+ workstreams will edit the same 6 specs in parallel. Without the §5.3 protocol, merges will reintroduce stale text | High |
| F47-6 | Low | Not implemented | `docs/contracts.md` ~20 inbound refs (zk.md ×8, contracts/src ×7, crypto/src/hash.rs:54, crypto/src/lib.rs:4, AUDIT.md ×3, reviews ×9) | After 28's `git mv` plus a new file under the same name, every old reference silently points to "Private contracts on PX", a semantic dangling link worse than a broken one | High [grep] |
| F47-7 | Low | Not implemented | AUDIT.md (110 references in 43 files) | Renaming AUDIT.md now (R14 item 9) would collide with every workstream; retitling the heading achieves the claims fix without churn | High [grep] |
| F47-8 | Low | Not implemented | ID collisions: "ZK-F4" (AUDIT.md:988 fixed margin vs register open verifier cost; 22 F22-10), "R14" (AUDIT.md round never written vs R14 report; testnet.md:568, checklist, roadmap, completion-readiness banner), "audit finding K1/S3/S4/S5" (transactions.md:139,341,416,845), "M1" (R14 D-4) | Readers conclude open items are fixed or follow dangling references | High |
| F47-9 | Informational | — | `transactions.md:38-42` | The dalek audit is now verifiable (Quarkslab, 2019, for Tari; scope curve25519-dalek of that time); the sentence can say so precisely instead of "reported elsewhere, not verified" | High [web] |

### 4.2 Deduplicated discrepancy list

Columns: **ID · doc file:line (verified at 9e422d8) · current text (short) · correct
statement · evidence · severity · source (dossier/finding; "47" = found here) · edit owner.**
"Owner" is the content owner; 47 reviews every edit (§5.3). Items marked **[after X]**
become wrong only when item X lands and must ship in X's commit.

#### A. Identity, status and process

| ID | Location | Current | Correct | Evidence | Sev | Source | Owner |
|---|---|---|---|---|---|---|---|
| D47-01 | README.md:13-17; AUDIT.md:10-13, 22-25; consensus.md:33-37; zk.md:15-18, 724-726; testnet-launch-checklist.md:4-7, :G12; testnet-roadmap.md:4-7; testnet-reset-plan.md:3-8; testnet-v2-validation.md:5-8; contracts.md:7; consensus/src/params.rs:37-40 (doc comment) | "the v2 identity is approved and fixed in code" / "testnet v2 … first public network" | v2 (`0x0001D672`) is **retired**; the testnet is disabled (`TESTNET_GENESIS_FINAL = false`) until the v3 genesis is generated at launch (testnet-v3-genesis.md). v2 validation doc is superseded by a v3 procedure (40) | node/src/config.rs:144-161; testnet.md:12-18 | **Med** | 47 (01 F-08 partial) | 47 (params.rs comment: 01) |
| D47-02 | testnet.md:95-98 | fingerprints `e7b898…`, `d56ea8…` | `8876128f…cda9` (testnet), `9cb0c0bf…9a61` (regtest), mainnet `1ccf1942…` — or better, no copied value: point to the release announcement and the test | node/tests/deploy_configs.rs:236-244 | **Med** | 47 | 40 (+47 test) |
| D47-03 | consensus.md:266-267; testnet-v3-genesis.md:3; reviews/v3-upgrade-mechanism.md:1-4; reviews/px-f4-f5-analysis.md:3-4; px.md:602 | "v3 candidate … branch v3/candidate (v3a-candidate) … not merged" | Merged into rebuild/core in `9e422d8`; `v3/candidate` deleted; still not launched and not frozen | git log; status.md | Low | 01 F-08, 47 | 01 (consensus.md), 40 (genesis), coordinator (reviews) |
| D47-04 | AUDIT.md:1, :45; transactions.md:139, 341, 416, 845 | "Testnet Readiness Audit"; "tracks the internal review defined in Claude.md"; "fixes audit finding K1" | Title "Internal findings log (historical)"; say "internal finding K1 (AUDIT.md)"; drop the Claude.md sentence | R14 D-5; review-status.md §1 | Low | R14 D-5, 47 | 47 |
| D47-05 | AUDIT.md:14-17; testnet.md:567-568; testnet-launch-checklist.md:11-12; testnet-roadmap.md:31; reviews/completion-readiness-2026-09-26.md:3-4 | "recorded in R14 (being written)" / "see AUDIT.md R14" | No AUDIT.md R14 exists; point to reviews/full-review-2026-09-27.md and autonomous-session report | grep "R14" AUDIT.md → only :15 | Low | 47 | 47 |
| D47-06 | testnet-launch-checklist.md:G3; testnet-roadmap.md:item 3, item 14, RandomX row; testnet-reset-plan.md (CI row); consensus.md:250-251 | "`7826289` is unpushed; `guests` and `randomx-full` have never run on GitHub" | Runs 78 and 79 passed every job incl. `guests`, `overflow`, `randomx-full`; run 80 failed one racy test, fixed in `197855b`; re-run required on the release commit | autonomous-session-2026-09-27.md:305-316 | Low | 01 F-08, 08 D-8, 47 | 43 (CI facts), 47 |
| D47-07 | testnet.md:6; README.md:10 | "current readiness status is in AUDIT.md" | One status source (new docs/STATUS.md); AUDIT.md is historical | R14 D-3 | Low | R14 D-3 | 47 |

#### B. Security figures, quantum, Hk, audit claims

| ID | Location | Current | Correct | Evidence | Sev | Source | Owner |
|---|---|---|---|---|---|---|---|
| D47-08 | px.md:57-58; px.md:483-484 (§9.1 item 2); zk.md:772-774 (§12.1 item 2), :809 (§12.3 row); zk.md:226; reviews/zk-security-review.md:34 (A2); px.md:47-51 | "124-bit collision and preimage resistance"; "node compression: collision resistance, preimage resistance"; zk.md: node = `Hk("px/node", l‖r)`; separation argument "2^−186" | Sponge `Hk`: ≈123 bits generic under the ideal-permutation assumption. `node(l,r)=P(l‖r)[0..8]` alone has trivial collisions via P⁻¹ and **must never be reused with free leaves**; the **tree** is binding by ePrint 2026/089 Thm 3 (≈122.6 bits) plus 19's three-point adaptation (argued, pending 50's check). zk.md:226 must state the real construction. The separation argument assumes honest siblings; state F2 | px-core/src/hash.rs (53d3b49 comment); 19 F1, F2, F3 | **Med** | 19 F1/F2, R2-C6 | 19 (content), 47 |
| D47-09 | zk.md:568-570, :882; zkvm.md:360-361; reviews/assumptions.md:41 (Z1); reviews/query-policy.md:27-28, :56; reviews/review-package.md:107, :148; reviews/external-review-scope.md:53; reviews/zk-security-review.md:243; AUDIT.md:796 (historical, annotate) | "≥ 123 bits Johnson and ≥ 105 unique decoding" | Adopted headline: "about **105 bits proven** (89.7 statistical + 16 grinding), with a **123-bit hash-collision cap**; the Johnson-regime algebraic terms are ≥ 154 (not binding)". Figures from two calculators, not yet a Rust test (25 W1/W2) | decisions.md (Agent 25); 25 ZS-2 | **Med** | 25 ZS-2 | 25 (content), 47 |
| D47-10 | zk.md:592-594; zk.md:486 (P6); zk.md:811; zk.md:183-185; zk.md:249-250; px.md:77-78 | "Parameters are sized with the quantum bound noted separately"; "plausible post-quantum security"; "survive a quantum adversary" | No quantum bound exists. State only labelled rough estimates (≈53 bits unique-decoding, ≈82 bits hash collisions; heuristic QROM, not a theorem). Hash-based ownership "relies on no DL assumption"; do not claim survival | 25 ZS-3; decisions.md | **Med** | 25 ZS-3, 47 | 25, 47 |
| D47-11 | crypto/Cargo.toml:11 | "audited by Quarkslab (2019)" | "A 2019 Quarkslab audit (commissioned by Tari) covered curve25519-dalek of that time; the pinned 4.1.3 is not covered; no audit is claimed" | [web] Quarkslab blog/report; transactions.md:38-42 | Low | 17 F17-6 | 17 (file), 47 |
| D47-12 | contracts/Cargo.toml:13-16; contracts.md:546-552, 985-987; AUDIT.md:712, 717; reviews/dependency-review.md:38 | "0.38.0 … covered by an external audit (0.36–0.38)" | Runtime Verification audited 0.36.0 with fixes to 0.36.5; 0.37–0.38 only partly covered per wasmi NEWS; 0.38 has post-audit refactors in unsafe paths | 29 W-1 | Low | 29 W-1 | 29 (Cargo.toml, moved spec), 47 (AUDIT, dependency-review) |
| D47-13 | randomx/README.md "Verification status"; README.md:23 | "every applicable test vector … all pass"; "passes the official test vectors" | Official hash test **1f** (upstream PR #326) is absent; ~70 instruction-level KATs not ported. Say exactly what is pinned (1a–1e light; full = light on 1a–1e + 1,024 random inputs, the README understates this) | randomx/src/lib.rs:53-194, 201-230; 05 F-1, F-2 | **Med** | 05 F-1/C1 | 05 |
| D47-14 | randomx/README.md "Design notes" ("bit-identical on every platform"); consensus.md:242-247 (OK); README.md (no platform table) | "Results are therefore bit-identical on every platform" | Designed to be; verified only on x86_64 with AES-NI; add the supported-target table (08 W1) | 08 D-1, D-2, D-8 | Low | 08 D-8 | 08 |

#### C. Privacy and operator guidance

| ID | Location | Current | Correct | Evidence | Sev | Source | Owner |
|---|---|---|---|---|---|---|---|
| D47-15 | blocks.md:395-400; README.md:144-146; testnet.md:464-465 | "reveals … which ring members it fetches" | Rings are resolved from the wallet's own index (transactions.md:804-812, since `2b0f75a`). A remote node learns: the wallet's IP, its scan start (birthday), the send timing (`/distribution` then `/tx`) and the tx↔IP link | 36 F36-10, P8; transactions.md §11.3.1 | **Med** | 36 F36-10 | 36 (blocks.md §9), 47 (README, testnet.md) |
| D47-16 | blocks.md:385-393 (§9 table) | 7 endpoints | 9 routes: add `/px/commitments`, `/px/contracts` (and later `/tip`, auth, 503, limits) | node/src/lib.rs:157-165 | Low | 36 F36-10 | 36 (09 for /template, /tip) |
| D47-17 | px.md:124-125 | `IncomingViewKey` "Records received at those addresses … cannot derive further addresses" | As built it discloses the whole index range (65,536 addresses) of `ivk_k` | 37 F37-2 | **Med** (latent, library API) | 37 F37-2 | 37 |
| D47-18 | transactions.md:673-675 (§10 "Other RNG uses"); reviews/autonomous-session-2026-09-27.md:212-213 | decoys "not secret, but predictable under a broken RNG"; "three unhedged items" | Decoy unpredictability is a privacy requirement (cloned RNG ⇒ rings differ exactly at the reals). Unhedged set: membership, vault blind and rcm, vault secret, decoys, miner secret, batch weights | 18 F18-4, F18-12 | Low–Med | 18 | 18 (W9) |
| D47-19 | testnet.md:567-576; testnet-launch-checklist.md G9; testnet-roadmap.md:31 | open defects "N-4 … unbounded pre-handshake", "N-11 … not penalized" | N-4 fixed (`12ce4cb`, handshakes counted); N-11 fixed (`54c4827`, burial ≥ 60); N-5, N-6, N-9, N-12 open | full-review register :941, :851; p2p.md:404-407, 457-466 | Low | 47 (15 C5 for N-11) | 40/47 |
| D47-20a | transactions.md:1068 | invalid-signature relays "not penalized: an open defect (N-11)" | Penalized (20) when every ring member is ≥ `SIGNATURE_BURIAL` = 60 deep | p2p/src/net.rs:2325-2360; p2p.md:457-466 | Low | 15 C5 | 15 (W11) |
| D47-20b | testnet.md §12.2 (493-503); consensus.md:156-157 | no Windows time steps; "Nodes must not adjust their clocks from peer time by more than FTL/2" | Nodes never adjust from peer time (local clock only, warn-only monitor after 04 W3); add Windows STS/poll steps, chrony/NTS, skew < 10 s pre-flight | 04 F8, S17 | Low | 04 F8, 01 F-08 | 04 (W1) |
| D47-20c | px.md:636-638; testnet.md:453-454 | anchor = most recent height multiple of 16 | **[after 21-C]** `ANCHOR_MIN_DEPTH = 3`, rounded down to a multiple of 16 | decisions.md (Agent 21); wallet/src/px.rs:88-92 | Low | 21 F21-3 | 21 |

#### D. zk.md and zkvm.md vs code (decision: zk.md §6–§7 rewritten; px.md normative)

| ID | Location | Current | Correct | Evidence | Sev | Source | Owner |
|---|---|---|---|---|---|---|---|
| D47-21 | zk.md:33, 40-47, 62 (R6), 119 (diagram step 3), 132 (layer "VM integration"), 276-277, 296-297, §8 (428-472), §14 PX-2 (857), 868-872, §17 Aztec row (942), 948-953; README.md:43-45, 54, 60 | PX results enter "the v1 Wasm VM as facts"; proof facts; deploy v2 with Wasm; "contract model and proof facts shared" as the novelty | PX is the **only** consensus contract platform (ADR-28-1 / D22). Wasm is frozen research (docs/research/wasm-contracts.md). Remove R6, §8, the diagram step and the §14/§17 statements; restate novelty without "shared with the Wasm model" | decisions.md (Agent 28); 28 F-28-9 | **Med** | 28 §3.8 item 3, 29 W29-4 | 47 (zk.md), 28 |
| D47-22 | zk.md:322-324 (§6.1) | public inputs include `program_id_f` | The kernel outputs `(contract, io_hash)` per function; program ids come from the registry lookup (PX3/PX5) | px-core/src/kernel.rs; 20 F-20-7 | Low | 20 F-20-7 | 47 (with 20) |
| D47-23 | zk.md:349-350 (§6.3 item 5) | "Otherwise, as for dummies, the output is value 0 with a random owner" | User outputs carry value to any owner; contract outputs need owner 0 (PX-F5, `ContractOutputOwner`) and a spec; `DummyContract` | 20 F-20-7; px.md §7.2 | Low | 20 | 47 (with 20) |
| D47-24 | zk.md:356-357 (§6.3 item 7) | function proof "verifies (recursion, §9.4)" | One batch STARK; kernel and functions linked by the shared `io_hash`; no recursion (zk.md:598-602 itself) | px.md §7.1 | Low | 47 | 47 |
| D47-25 | zk.md:411-414 (§7.2) | "state digest updates"; `io_hash` over "(inputs digest, approved, created, public outputs)" | Real layout: `Hk(IO, C ‖ [a_i, a_i·cm_i] ‖ [s_j, s_j·(owner‖contract‖value₁₆[4]‖data)] ‖ blind)`; **[after F-20-1, F-28-1, PX6]** add `ApprovalConflict`, `ABI_VERSION`, window words | px-core/src/call.rs:14-16; px.md:389 | Low | 20 F-20-7, 28 | 47 (with 20, 28) |
| D47-26 | zk.md:390-395 (§7.1); zkvm.md:92-96 (§3) | pinned kernel "embeds one developer's absolute Windows source path"; reproduction needs the same path | Path-independent since `53d3b49`; `px/tests/elf_paths.rs` fails on any path-like string; any host with bash reproduces | zkvm/guests/README.md:42-74; git show 53d3b49 | Low | 20 F-20-7, 47 (zkvm.md) | 47, 23 |
| D47-27 | zk.md:507, :882; AUDIT.md:988; zk/src/params.rs:12; full-review register (ZK-F4) | "ZK-F4" = BS-ZK-1 margin (fixed) and = adversarial verifier cost (open) | Rename the open one (e.g. ZK-VC1) and keep an alias | 22 F22-10 | Info | 22 | coordinator (register), 47 |
| D47-28 | zk.md:628 (§9.5), :944 (§17 RISC Zero/SP1 row) | on-chain verifier "implemented in BlackSilk's own crate … independent"; RISC Zero/SP1 "used (or reproduced) as the execution layer" | Plonky3's own verifier behind `catch_unwind` (zk.md:827-829); BVM-1 is our own zkVM, nothing from RISC Zero/SP1 is used | zk.md §13 item 3; zkvm.md §10 | Low | 47 | 47 |
| D47-29 | zkvm.md:26 (V3); zkvm.md:419-421 (§9 item 3); zkvm.md §4/§5 (161-166); zkvm/src/lib.rs:5, 9-10; zkvm/Cargo.toml:5; zkvm/src/exec.rs:3-4, 11; zkvm/src/air/cpu.rs:25-26; AUDIT.md:885 | "exactly one valid execution"; "every column … mutated"; RV32IM; "(ZK-3, in progress)"; timestamp `4·clk+slot`; "witness is unique" | Three documented R4-03 exceptions (READ count, up-front input length, output count); coverage = real rows of CPU, MEM_INIT, POSEIDON2, ALU + public copies + blinding; RV32I + Zmmul; tables complete; `4·(clk+1)+slot`; unique on real rows only (padding free) | 23 F23-6, F23-7 | Info | 23 | 23 (W7) |
| D47-30 | zkvm.md §5 WRITE row (160); px.md §7.2, §11.1; transactions.md T2 row | silent on output-word encoding | Normative: function public output words are raw u32 (injective byte limbs); only POSEIDON2 buffer words are field elements. Close D12 as a misattribution | 11 F11-1, decisions.md (Agent 11) | Low | 11 I2 | 11 |
| D47-31 | zkvm.md:10-13 | "This document is normative: … the constraint tables implement exactly what it says" | Normative for ISA, syscalls, program id and table *invariants*; the AIR constraints themselves are normative-by-reference to `zkvm/src/air/` pinned by `CIRCUIT_ID` (+ 22 W4 AIR digest) | R14 D-1; 22 F22-4, 23 F23-1 | Low | R14 D-1 | 47 (with 22/23) |
| D47-32 | zk.md:561, zkvm.md, zk/src/params.rs:164-170 | eq. (17) as `2·(8+108)=232 ≤ 256` "n_F = 1 with the translate" | Upstream counts both opening points: `2·(108 + 16) = 248 ≤ 256`; query ceiling at 2^8 is 112, not 120 | 25 ZS-8 | Info | 25 | 25 |
| D47-33 | reviews/zk-coverage.md §4; reviews/assumptions.md Z7, Z12; zkvm.md V4 (27); zk.md R1 (57), 808 | "statistical zero knowledge" | Add: the deployed masks are PRG (ChaCha) outputs, so the practical guarantee is computational in the ROM + PRG; adopt 26's proposed §4 text | 26 N2, ZP-1 | Low | 26 | 26 |
| D47-34 | reviews/terminal-blinding.md §3 C1 | Byte table listed as "real sum is public" | Byte multiplicities are witness-dependent; it must stay blinded | 26 N3 | Low | 26 | 26 |
| D47-35 | reviews/privacy-review.md §2 | grinding witness is "first nonce" | `find_map_any` returns a thread-split-dependent nonce (metadata) | 27 F27-3 | Low | 27 | 27 |

#### E. px.md

| ID | Location | Current | Correct | Evidence | Sev | Source | Owner |
|---|---|---|---|---|---|---|---|
| D47-36 | px.md:32; px-core/src/lib.rs:11-12 | "no separate circuit that could disagree with the specification" | "No hand-written circuit; the proven statement is the pinned riscv32 ELF, checked against the native build by differential tests" (the compiler is in the trusted base) | 20 F-20-4 | Low | 20 | 20 (W4) |
| D47-37 | px.md:264-266; px.md:449-452 (§8 table); px.md:457-459 | "2.04 MB (2,029,768–2,046,856 B)", "verifying 188 ms", vault "~2.5 MB", encoded "~2.05 MB"; cycles 25.0–25.2k | Current: transfer 2,178,213–2,180,408 B, verify 0.207–0.212 s; vault 2,687,952–2,688,822 B, 0.254–0.265 s (AUDIT R13; zk.md:709-711); cycles predate PX-F5 and the neutral build → re-measure (P0-3) and **reference evidence instead of copying** | zk.md §11; review-package.md:108 | Low | 20 F-20-7, 22, 27 F27-4, 47 | 22/27 (figures), 47 |
| D47-38 | px.md:322; reviews/dependency-review.md:39 | ML-KEM "FIPS 203" | "ML-KEM-768 parameter set with hedged (deterministic-interface) encapsulation coins", which FIPS 203 §6 reserves for testing; sound in the ROM | px/src/delivery.rs:236; 18 F18-11 | Info | 18 | 18 (W9) |
| D47-39 | px.md:208-217 (exit table), §4.1, §7.2 | exits 2–17 | **[after F-20-1]** add 18 `ApprovalConflict` (appended); "exactly one approval per contract input" | decisions.md (Agent 20) | Low | 20 W1 | 20 |
| D47-40 | px.md:472-473, :648; testnet.md:458; zk.md:724-725; query-policy.md:50; review-package.md:178 | "3 PX transactions per block" | 3 transfers or vault calls; about 2 at `n_fn = 2` [est]; 1 at the 4 MiB proof cap. Replace with the measured widest-shape figure after 22 W1 | 22 F22-12; tx/src/params.rs:16,22 | Info | 22 | 22 (W10) |
| D47-41 | px.md:649 | "a consensus rule (§12)" | §11.3 (px.md §12 is privacy guidance). Also note `PX_STANDARD_FEE` derives from `MAX_PROOF_BYTES` (FE-7) | tx/src/params.rs:41 | Info | 14 FE-7, 47 | 14 |
| D47-42 | px.md:803-806 | a table row (`px-share …`) orphaned after a paragraph | Move the row back into the commands table | render | Info | 47 | 47 |
| D47-43 | px.md §3 (65-89), §9.2, §13.2 | "no two leaves equal" implicit; rho public not stated | State the no-duplicate-leaf invariant and its dependency on rho; rho is public ⇒ contract-nullifier secrecy rests on rcm; any new creation path needs its own domain and chain-unique input (21-G) | 21 F21-5, F21-7 | Info | 21 | 21 |
| D47-44 | px.md §11.3 (598-611); transactions.md §8 | rules without ids for PX structure and deploy; capacity rule absent | Rule-id registry PS1–PSn, D1–Dn, B8 capacity **[after I3]**; each variant ↔ one id (11 I7) | 11 F11-6 | Low | 11 | 11 |
| D47-45 | px/src/share.rs:15-17 (doc comment) | share "reveals nothing to anyone but the addressee" | R5-4 correction (P0-15): the share also reveals to every opening holder, etc. (28 content) | 28 F-28-8 | Low | 28 | 28 |
| D47-46 | px-core/src/record.rs:49-50; px-core/src/kernel.rs:26-30; px/src/tree.rs:10-11; px/src/delivery.rs:26-35 | "In v2.0 contract and asset must be zero"; check list omits PX-F5/DummyContract; tree doc overstates coverage; delivery-key statements | Correct per 20 F-20-7, 21 F21-6, 37 F37-10. Comment-only edits in px-core: verify the kernel id with reproduce.sh | 20, 21, 37 | Info | 20/21/37 | 20 / 21 / 37 |

#### F. consensus.md, blocks.md, p2p.md, transactions.md

| ID | Location | Current | Correct | Evidence | Sev | Source | Owner |
|---|---|---|---|---|---|---|---|
| D47-47 | consensus.md:98, 110; randomx/README.md "~0.6 s"; consensus.md:257; blocks.md:300; p2p.md:189, 565; testnet.md:485, 488 | cache "about 0.6 s"; light hash "0.45 s" | Measured: cache 0.91–0.94 s under load, 3.1 s at start-up; light hash ~0.45–0.75 s (idle vs load). Reference one evidence file (06 W1 baseline) | 07 F07-10, 06 F4, 01 F-08 | Info | 01/06/07 | 06 (baseline), 47 |
| D47-48 | consensus.md:111-113; testnet.md:562-565 | first switch "exercised only in a test … not at 2113 with the network parameters" | Light-mode miners crossed 2113 at network parameters (seedrun2, 4 nodes agreed at 2123); full mode still unexercised | status.md; 09 M9-10 | Info | 09 | 09 (I8) |
| D47-49 | consensus.md:117-143 (§4) | "bounds the influence of manipulated timestamps"; no note on divergences | Divergences from zawy's reference (no 99/100, `prev = t[0]`, short window vs fixed guess, no rounding, max(1)); zawy recommends N = 90 for T = 120; the rule bounds *lowering* only; **[after 03 W2]** the bounded-rise rule `next ≤ parent + max(1, parent·R)` becomes normative with vectors | 03 C2, F4, F1 | Low now; **P0 with W2** | 03 F4/W5, 01 F-08 | 03 (01 reviews table) |
| D47-50 | consensus.md:207 (§8); consensus.md:225-226 | "applies it atomically"; "honest nodes always converge" | Block-by-block in bounded steps, lock released between steps, pool updated at drain end; convergence conditional on body availability (02 F-1) | 02 F-5 | Low | 02 | 02 (W-8) |
| D47-51 | consensus.md §6 (168-180) | order: version, height, timestamps, difficulty, PoW | **[after 01 F-05]** difficulty before FTL (error class only) | 01 F-05 | Info | 01 | 01 |
| D47-52 | consensus.md §9 (240-251) | CI "has not yet run"; evidence prose | Precise conformance evidence (vectors, corpus size, oracle) and the supported-target table | 05 C10, 08 W1 | Low | 05, 08 | 05/08 |
| D47-53 | blocks.md:101 (§5 item 5); blocks.md §7 (218-219) | "fit the 8 MiB PX budget"; templates "by descending fee per weight" | Also ≤ `MAX_DEPLOY_BLOCK_BYTES` = 1 MiB of deploys (a block rule); PX lane filled by fee per byte in its own budget; deploys outrank and can evict PX in the shared 64 MiB class (until 12/14 sub-pools); **[after R12-2 (a′)]** PX/deploy v1 part counts toward `MAX_BLOCK_WEIGHT` | tx/src/params.rs:32-36; chain/src/mempool.rs:431-442; 14 FE-8, FE-2 | Low | 14 FE-8, 10 | 14/12 |
| D47-54 | blocks.md §6 (114-154) | tie wording; downloads | Document F-4 tie retention after a failed reorg; step bound does not hold during a reorg until the new branch outweighs the old tip | 02 F-4, F-2 | Info | 02 | 02 |
| D47-55 | blocks.md §8 (298-305) | stored PoW hash trusted | Add the operator rule "never copy another operator's blocks.dat; use `--verify-store-pow`" **[after 01 item 4]**; legacy headerless stores refused on testnet **[after 35 S1]** | 01 F-01, 35 F35-1 | Low (Med after S1 decision) | 01, 35 | 35 (01 reviews) |
| D47-56 | p2p.md:66-67 (§3) | "forward secrecy: recorded traffic cannot be decrypted later, even if a node is compromised" | Ephemeral keys, but no rekey within a session and AES/GHASH key schedules are not zeroized; FS holds only after session end and memory hygiene | 30 T-5 | Low | 30 | 30 (W4) |
| D47-57 | p2p.md:102 | "handshake must complete within 10 s" | Up to ~110 s today (key exchange + Version + up to 9 unknown frames of ≤ 9.45 MB, each with its own 10 s timeout) **[after 30 W1]** one deadline and a 4 KiB pre-Verack cap | 30 T-1 | Low–Med | 30 | 30 |
| D47-58 | p2p.md:90, 111-114, §4.1 | `MIN_PROTOCOL = 1`; nothing on unknown address kinds | **[after 30 W5]** min 2, transport version in the KDF, no-fallback; new NetAddr kinds need a new message type (unknown kind = 100-point ban today, addr.rs:178) | 30 T-3, T-9 | Low | 30 | 30 |
| D47-59 | p2p.md:416-418 vs 610-612 | §10 "for proxied or onion peers only the connection is dropped" vs §12 "a ban of one bans all" | §10 is true only for outbound proxied peers; hidden-service inbound (127.0.0.1) is banned as an IP (N-6) | p2p/src/net.rs:641-654, 938 | Low | 47 | 30/32 |
| D47-60 | p2p.md:534-539, 590-602; reviews/autonomous-session-2026-09-27.md:389 | pings unaffected; single block "up to ~3.4 s"; blocking waiters "bounded by the number of connections" | Pings of the holding peer's own connection stall; valid worst block ≈5–10 s, invalid F10-2 block ≈25–50 s [est], up to 8 per hold; RPC also queues on the shared blocking pool | 34 F34-1/F34-9, 10 F10-1/2 | Low | 34, 10 | 34 |
| D47-61 | p2p.md:249-250, 581-583 | bodies "only from peers whose announced height covers them"; "seed pinning … is in the consensus crate" | State the withholding-peer limitation (F31-2); no seed pinning exists anywhere (07 W1 will add it in `consensus/src/pow.rs`); density rule is a heuristic | 31 F31-7 = 07 F07-10 | Info | 31, 07 | 31 |
| D47-62 | transactions.md:181-184, 541-544 (C4), 555 (B4), 556 (B7), 1063, 1097 (Δ5); blocks.md:119, 179-200; px.md:604; p2p.md:503-506 | global one-time-key uniqueness C4; "burning bug impossible even for broken wallets" | **[after C4 option B]** C4 → "O distinct within a transaction" (stateless, all kinds); remove the state key set, OutputKey conflict namespace, `CoinbaseDuplicateOneTimeKey`; burning-bug safety = ctx binding + Janus re-derivation + intra-tx distinctness (Lemma 2); §12.5: wallets must dedupe by key image and decoy selection must not filter duplicate O | decisions.md (D8/C4); 13 F13-8; 17 F17-4 | Low now; **P0 with the change** | 13, 17 | 13 (rules), 17 (§3, §12) |
| D47-63 | transactions.md:1040 (§12.8); 180-185; §3.1 | Janus anchor attributed to "Jamtis"; ctx binding "by construction"; only transfer/coinbase contexts | The re-deriving encrypted anchor is Carrot's (§7.4, §7.7); add PX (`input-context/px`) and deploy contexts; write the Carrot-delta rationale | 17 F17-4 | Low | 17 | 17 |
| D47-64 | transactions.md:839 (§11.6) | quantum: recover r from R for known addresses | With DL, any single address gives `k_v = log_D C`, exposing the wallet's entire incoming view | 17 F17-5 | Low | 17 | 17 |
| D47-65 | transactions.md:453 (§6.1), §8.1 T11, §13, §14 | verification rejects only `I = identity` | **[after 15 W1]** also `D = identity` (stateless), `sign` refuses z = 0; §14 row: C1 parity, C6 zero-challenge not adopted | 15 C1, decisions.md | Low; **P0 with W1** | 15 | 15 |
| D47-66 | transactions.md:593-598 (§9), :1051 (§13); :422-424 | "Nothing else is assumed"; "CLSAG unforgeability under DL"; "BP+ are proven" in ROM; "follows Monero except cofactor" | CLSAG proof: κ-OMDL with gaps; Cypher Stack 2024 repair to DL is non-tight; BP+: interactive protocol proven (WEE), FS via Attema–Fehr–Klooß, non-malleability assumed; BlackSilk uses its own Blake2b transcript (not byte-compatible) | 15 C3, 16 BPP-9 | Info | 15, 16 | 15/16 |
| D47-67 | transactions.md:504-510 (§7); §16.4 (1147) | batch weights "from the verifier's CSPRNG"; "honest prover refuses out-of-range values" | **[after 16 item 2]** hedged, transcript-bound weights; u64 amounts make out-of-range unrepresentable; reference the pinned vectors | 16 BPP-9, BPP-1 | Info | 16 | 16 |
| D47-68 | transactions.md:572-576 (§8.5) | mempool conflicts "on any key image" | Conflict keys: key images, PX nullifiers, deploy contract ids (and output keys until C4 option B); refer to blocks.md §7 | chain/src/mempool.rs conflict_keys; 11 F11-6 | Low | 11 | 11/12 |
| D47-69 | transactions.md:1159-1162 (§16.6); :1130-1131 | property tests "not proptest"; "fixed KATs for Hs, Hp, generators" required | proptest is now an approved dev-dependency; KATs are still missing (`kat_matches_definition` is self-referential) → point to 15 W3/W4, 16 item 1, 17 item 1, 19 item 2 vector files | decisions.md; R14 D-2 | Info | 47 | 41 / 15–19 |
| D47-70 | transactions.md:1.2 (68-100) | "Every hash has a domain tag"; table lists v1 tags only | Fingerprint domains bypass `tags::ALL`; consensus Blake2b contexts use a separate first-byte scheme; point to the domain registry (19 item 3) | 19 F6 | Low | 19 | 19 |
| D47-71 | transactions.md:38-42 | dalek audit "reported elsewhere … not verified" | Precise: Quarkslab 2019 report (for Tari) exists; it covered the 2019 code; 4.1.3 not covered | [web] | Info | 47 (F47-9) | 17/47 |

#### G. README, testnet.md, operator docs, review docs

| ID | Location | Current | Correct | Evidence | Sev | Source | Owner |
|---|---|---|---|---|---|---|---|
| D47-72 | README.md:91 | "about 450 tests" | 745 `#[test]`/`#[tokio::test]` attributes in workspace crates (grep, incl. ignored); better: no count, or the CI summary | [grep] | Info | 47 | 47 |
| D47-73 | README.md:112; testnet.md:128 | full mode "needs 2 GiB" / "< 3 GB" | ~2.3 GiB (2080 MiB dataset + 256 MiB cache); ~4.4 GiB peak with `--prebuild auto` **[after 09 I3]** | testnet.md:224; 09 | Info | 09 | 09/47 |
| D47-74 | README.md:47-69 (layout) | omits `tools/genesis`, `tools/supply-audit`, `research/`, `legacy/`; `contracts/` row | Add; `contracts/` → "frozen research, outside the root workspace" **[after 29 W29-2]**; `crypto/` row: Wasm-only schnorr/membership/claims feature-gated **[after W29-5]** | Cargo.toml members | Info | 29, 47 | 47 |
| D47-75 | testnet.md:126 (§3 quick start) | `blacksilk-node --network testnet` | Refuses to start until the v3 genesis (status block); show regtest until launch | config.rs:155 | Info | 47 | 40 |
| D47-76 | reviews/contracts-completion-assessment.md:3-4; testnet-roadmap.md matrix row "Transparent contract engine" (L3 ✅), items 4 and 17; testnet-reset-plan.md:22; testnet-roadmap.md:60; reviews/review-package.md:112 | "BlackSilk is not complete while the Wasm system is not integrated"; Wasm fuzz hours as readiness evidence | Under ADR-28-1 Wasm is out of v1: completeness does not depend on it; C-1…C-5 are "revival preconditions"; mark fuzz rows "not testnet evidence (engine not integrated)" | 29 W-9, W29-4 | Low | 29 | 29 (+47) |
| D47-77 | full-review-2026-09-27.md register rows D12, R12-2 (:845, :1197, :1372), P0-17 (:1071) | D12 "docs and code disagree"; R12-2 "25–50 s" for valid blocks; P0-17 "removes wasmi unsafe from release supply chain" | D12 is a misattribution (close: raw u32 normative); valid worst block ≈5–10 s after the deploy budget, invalid F10-2 block still ≈25–50 s; wasmi is in no release binary (effect is lockfile/CI/scope) | 11 F11-1, 10/14 FE-1, 29 W-10 | Info | 10, 11, 14, 29 | coordinator |
| D47-78 | testnet-v3-genesis.md §4 (101-104), §5, §6 | genesis gap and D0 | **[after 03 W2]** gap re-derived under the rise cap; add 04 W11 (NTP check of the generating machine, reveal window, free-fork budget, T_g ≤ ~4 h before launch) and 09 M9-9 (measured hash rate tool) | 03, 04, 09 | Low | 03/04/09 | 40 |
| D47-79 | reviews/assumptions.md:12-20 ("External" class), K5 | "External" column; no target table | Replace "External" by "Unverified (no external review planned)" (R14 D-4); K5 → supported-target table (08) | R14 D-4; 08 D-8 | Info | R14, 08 | 47/08 |
| D47-80 | chain/tests/manager.rs:1010-1047 (comment); randomx/src/fpu.rs:9-15; third_party/upstream/issue-anonymous.md:89 | "revalidates the whole pool … in full"; FSCAL range omits ±2^-1008; "we audited the three crates" | Extension path only (M12-11); add the FSCAL(±0) case (08 D-6); "we reviewed" | 12, 08, 47 | Info | 12/08/47 | 12/05/47 |

**Duplicates merged:** 01 F-08 ⊃ {04 F8/S17, 07 F07-10, 08 D-8 (CI sentence), 05 C10}; 07 F07-10 = 31 F31-7
(seed pinning); 13 F13-8 ≈ 17 F17-4 (burning-bug credit); 10 F10-1 = 14 FE-1 (R12-2 figure);
19 F1 = R2-C6 doc part; 20 F-20-7 (zk.md §7.1 path) = zkvm.md §3 (found here); 25 ZS-2 is the
headline decision; 36 F36-10 extends to README and testnet.md (found here).

---

## 5. Implementation plan for phase 2

### 5.1 Work items (47 owns the listed files unless noted; every item: nothing externally
visible, no consensus change, no identity impact)

| # | Item | Files (ownership) | Tests / checks | Diff | Pri |
|---|---|---|---|---|---|
| **W47-1** | **One status source.** Create `docs/STATUS.md` (identity: v2 retired, testnet disabled, v3 not generated; gates; open P0s; link to the register). Replace every status block by a one-line link. Fix D47-01, D47-03 (spec files), D47-05, D47-07, D47-19, D47-75 | new `docs/STATUS.md`; README.md:5-17; AUDIT.md:1-50 (retitle, historical banner, no rename); docs/testnet-launch-checklist.md, testnet-roadmap.md, testnet-reset-plan.md, testnet-v2-validation.md (banner "superseded by the v3 procedure, owner 40"), zk.md:3-21, consensus.md:33-39 (47 edits; 01 reviews), contracts.md:3-15 (before 28's move) | doc-lint (W47-8) forbids "v2 identity is approved" outside history | S | **P0** |
| **W47-2** | **Claims pass: security headline, quantum, Hk/node, audit** (D47-08…D47-12, D47-71, F47-9). Text from 25 (headline, quantum estimates) and 19 (tree-binding argument) | zk.md §9.3, §12, P4/P6, R4; zkvm.md §7; px.md §2, §3 bullet 1, §9.1; reviews: assumptions.md Z1/Z3, query-policy.md, review-package.md, external-review-scope.md, zk-security-review.md A2 (47 edits with 25/19 content); crypto/Cargo.toml:11 (17), contracts/Cargo.toml (29) | lint rules: no "≥ 123 bits in the Johnson", no "quantum bound noted", no "collision resistance" next to `node(`, no "audited by" in manifests | S | **P0** |
| **W47-3** | **zk.md rewrite** (decided): §6–§7 to match code (D47-22…25), remove the Wasm architecture (D47-21), fix §4.5 node, §5.2 binding refs, §7.1 path (D47-26), §9.4/§9.5/§17 (D47-24, D47-28); zk.md becomes design/rationale and points to px.md for every kernel rule; mark DR records as history | docs/zk.md (47; content from 20, 28, 19, 25) | link check; lint (no `contracts.md §` in zk.md) | M | **P0** |
| **W47-4** | **RPC privacy text** (D47-15) in README and testnet.md; blocks.md §9 rewrite is 36 W9 | README.md:140-150; testnet.md §11 (47); blocks.md §9 (36) | lint: forbid "which ring members it fetches" | S | **P0** |
| **W47-5** | **Fingerprint table** (D47-02): remove copied values from testnet.md or add a test that parses the table and compares with `node/tests/deploy_configs.rs` | docs/testnet.md §2.1 (40 owns testnet.md; 47 writes the test with 43) | new `node/tests/doc_pins.rs` (or a lint script) | S | **P0** |
| **W47-6** | **contracts.md move support** (F47-6): after 28's `git mv docs/contracts.md docs/research/wasm-contracts.md` and the new file, re-point every old reference to the research path in the **same commit** | zk.md (via W47-3), AUDIT.md:41,642,731, reviews ×9, README.md:43 (47); contracts/src/*.rs, contracts/Cargo.toml, crypto/src/hash.rs:54, crypto/src/lib.rs:4 (29 and 19 own; comment-only) | `rg "contracts\.md"` must return only intended new-doc references | S | **P0** (with 28 W28-5) |
| **W47-7** | **Stale-fact sweep** of items not owned by a code workstream: D47-04, D47-06, D47-37 (link to evidence), D47-40 (after 22 W1), D47-42, D47-47 (after 06 W1), D47-72, D47-73, D47-74, D47-79 | README.md, AUDIT.md, testnet.md (with 40), px.md §8 (with 22/27), reviews/assumptions.md | lint | S | P1 |
| **W47-8** | **Doc lint in CI** (F47-5): markdown link check (relative links and `§` anchors of the form file.md §n where feasible), banned-phrase list with a reviewed allowlist (history files exempt), retired-identity strings, fingerprint pins, rule-registry completeness (11 I7's grep test) | new `tools/doc-lint/` (pure Rust, no new dependency, workspace member; 47) + a CI step (43 owns ci.yml) | the lint itself; a seeded failing fixture per rule | S–M | **P0** (before wave 2 merges) |
| **W47-9** | **Normative spec structure, stage 1 (pre-freeze, no file moves):** normativity header on every spec (normative / normative-by-reference / design / operator / history); docs/README.md index; px.md gets a "Normative" marker for §2–§7, §11 and RFC 2119 keywords only in rule tables; a **proof-system normative-by-reference section** (new `docs/proof-system.md`: exact crates, versions and third_party patch hashes, config, transcript order (PARAMS_ID, statement digest with CIRCUIT_ID, public values), proof byte grammar = `PROOF_VERSION ‖ postcard(...)` with pinned postcard version, every MUST: canonical FRI schedule, zero commit-PoW witness, hidden-codeword count **[if 22 W2/26 ZP-7]**, height limits, `MAX_PROOF_BYTES`; the AIR digest pin **[22 W4]**); consensus rule table (01 item 1) and PX/deploy rule registry (11 I7) placed in their files | docs/README.md, docs/proof-system.md (47 writes; 22/25/23 supply content and review), headers in all specs | lint: every spec has a header; registry test | M | **P1** (proof-system section **P0** if ZP-7/W2 ride the reset: it states the new rule) |
| **W47-10** | **Stage 2 (after the protocol freeze):** move to the R14 §3 tree: `docs/spec/{00-conventions (domain registry from 19), 01-consensus, 02-blocks, 03-transactions-v1, 04-px (px.md §2–7, §11 + contracts ABI from 28), 05-proof-system, 06-zkvm, 07-p2p}`, `docs/spec/vectors/` (index of the vector files owned by 01/11/15/16/17/19/22), `docs/design/` (zk.md, DR records, hash-agility), `docs/operators/` (testnet.md split), `docs/research/`, `docs/history/` (AUDIT.md renamed only here, with a stub) | whole docs tree (47; one mechanical move commit, diff-reviewed "moved text only", like 46's net.rs split) | link check green; no rule text changed (diff shows moves only) | L | P2 |
| **W47-11** | **ID hygiene** (F47-8, D47-27): alias table in the register (ZK-F4 → ZK-VC1 for the open item; AUDIT "R14" references removed; "audit finding" → "internal finding") | register (coordinator), zk.md, AUDIT.md, transactions.md | lint: ID list | S | P1 |
| **W47-12** | **Docs review gate**: 47 reviews every docs diff of waves 1–3 against the claims checklist (§5.3) and the discrepancy list above; closes each D47 item with the commit id in the dossier addendum | — | checklist | ongoing | P0 |

**Items owned by other workstreams (content), tracked by 47:** D47-13/14 (05, 08),
D47-16/15-blocks (36), D47-17 (37), D47-18/38 (18), D47-20a/63-66 (15, 16, 17), D47-20b (04),
D47-20c/43 (21), D47-29 (23), D47-30/44/68 (11), D47-32 (25), D47-33/34 (26), D47-35 (27),
D47-36/39/46 (20), D47-40 (22), D47-41/53 (14, 12), D47-45 (28), D47-48/73 (09),
D47-49 (03), D47-50/54 (02), D47-51/52 (01, 05, 08), D47-55 (35, 01), D47-56–59 (30),
D47-60 (34), D47-61 (31), D47-62 (13, 17), D47-76 (29), D47-77 (coordinator), D47-78 (40).

### 5.2 Normative spec restructuring plan (R14 D-1), in brief

1. **Principle (never change):** the code and the pinned vectors are the rule; the spec
   describes them. Where prose and code disagree today, the prose is fixed (R14 §5). The
   px-core single source is not re-described as a circuit.
2. **Normative-by-reference for the proof system** (R14 D-1 assessment, Zcash precedent):
   exact crate versions and patch hashes, config, transcript order, byte grammar, every
   MUST, golden proofs (22 W6). This is the one pre-freeze *new* normative document
   (W47-9).
3. **Rule ids everywhere:** H* (header, 01), B* (block, 01/10), T*/C* (v1, 11), PS*/D*/PX*
   (PX and deploy, 11), K* (kernel exit codes, 20), P* (proof MUSTs, 22). Every error
   variant maps to exactly one id; a test enforces it (11 I7, W47-8).
4. **Vectors are part of the spec:** `docs/spec/vectors/README.md` indexes the data files
   owned by 01 (consensus), 11 (tx), 15/16/17 (crypto), 19 (Hk), 22 (golden proofs), 30
   (transport KAT), with provenance and independent generators (non-core Python allowed by
   decisions). The fingerprint (`node/src/fingerprint.rs`) is the constants manifest: the spec
   links to it and to its pinned values instead of copying them.
5. **Stages:** stage 1 (W47-9) before the freeze adds headers, the index, rule tables and
   the proof-system document **without moving files**; stage 2 (W47-10) moves files after
   the freeze in one mechanical commit. Moving files mid-wave would collide with every
   workstream's doc edits.

### 5.3 Coordination plan (so many doc edits do not collide)

**(a) Section ownership matrix (single writer per section per wave; 47 reviews all):**

| File | Section → owner |
|---|---|
| consensus.md | §1 40 · §2–§3 01/07/09 · §3.1 07 · §4 03 · §5 04 · §6 01 · §7 01 · §8 02 · §9 05/08 · §10–§11 01 · new rule table 01 |
| blocks.md | §1–§5 01 (§5 weight: 10/14) · §6 02 · §7 12 (fees 14) · §8 35 (replay trust 01) · §9 36 (/template,/tip 09) · §10 37 |
| transactions.md | §1–§2 17/37 · §3, §11.6, §12 17 · §4 11 · §6.1, §9 CLSAG 15 · §7, §9.3 16 · §8 11 (C4 13) · §10 18 · §11.3 38 · §13–§14 15/16/17 (merge by 47) · §15–§16 47 |
| px.md | §2 19 · §3, §5 21 (§3.1 37) · §4 20 · §6 18/37 · §7 20 → then moved to contracts.md by 28 · §8 22/27 · §9 20/21 · §11 11 (fees 14, weight 10) · §12 38 · §13 28 |
| zk.md | 47 (content 20, 25, 19, 28, 22, 26) |
| zkvm.md | 23 (§7 25; §8 26) |
| p2p.md | §1–§5 30 · §6, §12 31 · §8 33 · §9 32 · §10 liveness 34, scoring 11/30 |
| contracts.md (new) | 28; research/wasm-contracts.md banner 29 |
| testnet.md, testnet-v3-genesis.md | 40 (§5 mining 09/06, §12.2 04, §11 36) |
| README.md, AUDIT.md, STATUS.md, docs index, reviews/* status lines | 47; register rows: coordinator |

**(b) Same-commit rule.** A behaviour or rule change and its spec text land in one commit by
the code owner, with the D47 id in the message. Consensus changes add the vector and the
rule-table row in the same commit. Items marked **[after X]** in §4.2 must not be edited
before X.

**(c) Merge order for contended files** (each step rebases on the previous):
- transactions.md: 13+17 (C4 option B, §3/§12) → 15 (D-identity, assumptions) → 16 (BP+)
  → 18 (§10) → 11 (rule registry, raw u32) → 14 (weight/fees).
- px.md: 19 (claims) → 20 (F-20-1, statement) → 21 (invariants) → 28 (move §7/§13 to
  contracts.md, ABI, window) → 11 (registry) → 37 (keys) → 22/27 (figures, after
  measurement).
- consensus.md: 01 (rule table, stale facts) → 03 (§4 after W2) → 04 (§5) → 02 (§8) →
  05/08 (§9) → 07/09 (§3).
- zk.md: 47 rewrite first (W47-3), then only 25/22 figure updates.
- p2p.md: 46 split has no doc effect; 30 → 31 → 34 → 32/33.

**(d) No copied volatile values.** Measured figures, pins, counts and CI states are stated
once (evidence file, test, STATUS.md) and referenced. The lint rejects new copies of the
fingerprint and of "tests pass" counts.

**(e) Claims checklist** (reviewer 47, every docs diff): no "audit(ed)" for our code or for
unpinned versions; ZK only statistical and conditional (computational in practice, 26 N2);
security figures only the adopted headline; quantum only labelled estimates; no "first";
Wasm never described as consensus or planned for v1; every measured figure has machine,
commit and evidence path; "[after X]" text only with X.

**(f) Cadence.** 47 publishes a D47 status addendum after each wave; the coordinator
closes register rows from it.

---

## 6. Dependencies and conflicts

- **01, 03, 04, 05, 07, 08, 09:** consensus.md sections (§5.3a); 01 owns the rule table and
  params.rs doc comment (D47-01).
- **11, 13, 15, 16, 17, 18:** transactions.md merge order (§5.3c); 17 asked who owns §3/§12
  (decision: 17 writes, 47 coordinates).
- **19, 20, 21, 22, 25, 26, 27, 28:** px.md/zk.md content; W47-2/W47-3 need 25's headline
  text, 19's tree-binding paragraph (after 50 verifies ePrint 2026/089), 20's statement.
- **28/29:** contracts.md move; W47-6 must be in the same commit (F47-6).
- **36, 09:** blocks.md §9 and RPC docs; W47-4.
- **40:** testnet.md, testnet-v3-genesis.md, v2-validation supersession; W47-5 test.
- **43:** CI step for W47-8; CI facts (D47-06). **44:** none. **46:** stage-2 move after its
  ADR; no overlap with the net.rs split.
- **Coordinator:** register rows (D47-77, D47-27 alias), STATUS.md content authority.
- **50:** must verify the 2026/089 citation before 19's text enters px.md (D47-08).

## 7. Open questions for the coordinator

1. Approve `docs/STATUS.md` as the single status source, with every other status block
   reduced to a link (W47-1)? Who updates it after each wave (47 proposes itself, the
   coordinator approves)?
2. Approve the doc-lint as a pure-Rust workspace tool (`tools/doc-lint`, no new dependency)
   and a blocking CI step (43)?
3. Confirm stage-2 file moves (W47-10) wait until after the protocol freeze, and that AUDIT.md
   is only retitled now (110 references in 43 files).
4. For testnet.md §2.1: remove the copied fingerprint values (announcement is the source), or
   keep them with a pin test? 47 recommends removal plus the test on the announcement template.
5. Should testnet-v2-validation.md be superseded by a v3 validation document owned by 40, or
   edited in place?
6. Is the proof-system normative-by-reference document P0 (only if a proof-format MUST is
   added at the reset, i.e. 22 W2/26 ZP-7), or P1?
7. Dossiers 24, 32, 33, 38–46, 48–50 were not available; 47 will append their doc items to
   the list in the first wave addendum. Confirm this is acceptable.

## 8. Sources

- R14 docs review: `docs/reviews/full-review-2026-09-27/R14-docs-dx.md` (D-1…D-13, §3, §4).
- Ben-Sasson, Carmon, Haböck, Kopparty, Saraf, "On Proximity Gaps for Reed–Solomon Codes",
  IACR ePrint 2025/2055: https://eprint.iacr.org/2025/2055
- Haböck, Al Kindi, "A note on adding zero-knowledge to STARKs", IACR ePrint 2024/1037:
  https://eprint.iacr.org/2024/1037
- Monero PR #7025 (Dandelion++ fluff 20 %, embargo 39 s):
  https://github.com/monero-project/monero/pull/7025
- Monero CLSAG audit results (Aumasson, Vennard; OSTIF; 2020):
  https://www.getmonero.org/2020/07/31/clsag-audit.html ;
  https://www.getmonero.org/resources/research-lab/audits/clsag.pdf
- Quarkslab, "Security Audit of dalek libraries" (2019, for Tari):
  https://blog.quarkslab.com/security-audit-of-dalek-libraries.html ;
  report: https://blog.quarkslab.com/resources/2019-08-26-audit-dalek-libraries/19-06-594-REP.pdf
- Zcash ZIP process and protocol specification: https://zips.z.cash/zip-0000 ,
  https://zips.z.cash/protocol/protocol.pdf
- Bitcoin BIP-2: https://github.com/bitcoin/bips/blob/master/bip-0002.mediawiki
- RFC 2119 / RFC 8174: https://www.rfc-editor.org/rfc/rfc2119 , https://www.rfc-editor.org/rfc/rfc8174
- Diátaxis documentation framework: https://diataxis.fr
- Carried from dossiers (their sources apply): 19 (ePrint 2026/089), 25 (Chiesa–Manohar–Spooner
  ePrint 2019/834), 15 (Cypher Stack 2024 CLSAG note), 17 (Carrot spec), 18 (FIPS 203),
  29 (wasmi NEWS, Runtime Verification report), 05 (tevador/RandomX PR #326).
