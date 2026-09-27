# SX2: Systems cross-review of the wave-1 reports (R3, R8–R16, I3, I4)

**Reviewer:** SX2, senior cross-reviewer (wave 2). This is internal review, not an audit.
**Tree judged:** the main working tree, `rebuild/core`. HEAD moved while I worked: `58f25ec` → `5888d4c` → `f6a52ca`. There are 16 commits after `87278ac` and 22 unpushed over `origin/rebuild/core`.
**Worktrees read for context only:**
- A8 P2P round 2: `.claude/worktrees/agent-ac1d74d49664dea4f`, commit `9eb90ae` plus uncommitted changes;
- A7b: `agent-adcbff0538d434fbf`.

These are unmerged. Their effect is shown as "fixed in WIP" and never as "fixed".
**Method:**
- read-only;
- no cargo and no builds;
- every cited line was re-read in HEAD;
- arithmetic was recomputed by hand.

**Evidence tags:** [src] source-read, [math] recomputed, [assumed], [unknown].

**Scope:** the major findings (medium or above, or proposed as P0/P1) in:
- R3, R8, R9, R10, R11, R12, R13 and R14;
- R15, R16, I3 and I4, which existed by the end of this review.

**Trial model.** A seven-device trial with trusted operators and explicit `--peer` lists (no seeds, per `6ed731f`). It runs at least 96 h across seed height 2113, exercises PX, and includes a late-joining device and an end-of-trial supply audit (R15 §3). "P0" below means **must be done before that trial**. Items that matter only for a public testnet are marked P0-public.

---

## 0. Essentials

1. **Most major findings hold up.**
   - I re-verified about 70 major findings against the code:
     - about 50 are confirmed as stated;
     - 14 are confirmed with a correction;
     - 3 are overstated;
     - 1 is partly wrong (R3-7: "undocumented");
     - 1 is partly unverifiable (R8-6, which depends on Tor defaults).
   - No major finding is fabricated.
   - The arithmetic in R12 (RAM, restart, IBD, per-block cost), R8 (605 MB outbox, header CPU-hours), R9 (instruction counts, JIT ratio), R10 (undo size) and R11 (PX fee) recomputes correctly, within rounding.
2. **The corrections that matter:**
   - **R8-10 (605 MB outbox).** The arithmetic is right: 64 × 9,454,144 B. The bound is really 64 × *the largest block that exists*, because one `GetBlocks` may repeat the same id (`on_get_blocks`, net.rs:1123-1144). So a single large block is enough.
     - The receive-side "slowloris pins 600 MB" is commit/virtual memory. It becomes resident only as bytes arrive, because `vec![0u8; len]` gets lazily zeroed pages.
   - **R8-17 (origin fires first about 17%).** The math is right: E[1/(L+1)] = 0.173 for q = 0.1. But it is *conditional on the transaction never reaching a diffuser*. On an honest path the diffuser fluffs within about L × 0.1 s, far below the 10 s floor.
     - Conditional on a drop at hop k, P = 1/k. So P = 1 when the first hop drops the transaction (R3-5 scenario 3).
     - R3-4's concern is real for **PX**. With hops at about 1.5 s (2.2 MB transfer plus verification) and L = 10, the origin's own timer fires before the diffuser in about 12% of cases: P(10 + Exp(39) < 15 s) [math].
   - **R8-7 (valid double-spend variants).** The mempool path is *not* affected: `Mempool::check`/`add` run `precheck` (conflicts) before validation (mempool.rs:201, 219). Only the stem path is. A8 fixes it (WIP).
   - **R8-9 (honest-peer bans).** Confirmed, and LAN addresses *are* banned (only loopback is exempt, net.rs:412-416). But manual `--peer` outbound ignores bans (`maintain_outbound`/`connect_outbound` never check `bans` for `cfg.connect`). In the trial's explicit mesh this causes reconnect churn and repeated re-downloads, not a partition. It is still P0, because it will fire with PX blocks.
   - **R9-2 (300–500× verification asymmetry).** This holds only at difficulty ≈ 1. At the testnet D0 = 100 it is about 4–7×: 0.45–0.75 s / (100 × 1.4 ms). This matches R15-10's 7×.
     - Collapsing to D ≈ 1 needs at least about 180 blocks × 6T ≈ 36 h of chain time, then about 70 h to cross height 2113. That is feasible on a multi-day testnet.
     - A8's `anti_dos_threshold` (WIP) closes it.
   - **R3-3 ("effective ring 1.9 against miners").** This needs m = 1: one party, or all miners colluding, knows every coinbase output. For one of seven equal miners (m ≈ 1/7), the figure at 3 days and 20 tx/day is about 14.
     - The outsider heuristic ("the unique non-coinbase member is real", 40%) stands without miners.
     - The simulation's assumptions match `tx/src/decoy.rs` and the wallet filter (checked below).
   - **R3-7 ("contract-record nullifiers undocumented").** Wrong: docs/px.md:595-598 has documented "spends are seen by every holder" since `bb437ad` (2026-09-25). Only the corollary for public-data `rcm` (PX-F4 option B) is new.
   - **R8/R3 v1 block capacity.** R8 uses "1 MB / 400 transfers" and R3 uses 330. The correct figure is **381** 1-in/2-out transfers: `MAX_BLOCK_WEIGHT` = 600,000, less `COINBASE_RESERVE`, at 1,563 B each (R12). R8's per-block 3.4 s is therefore about 2–3 s, **but** R8 missed R12-2: a deploy-CLSAG block costs 25–50 s, which is the real worst case.
3. **Already fixed in HEAD since the reviewers read the code:**
   - R3-2 (`f331642`);
   - R9-3/R9-R5 (`8097f66`);
   - R10-8a (`9578517`);
   - R14 D-8 (`58f25ec`);
   - R16 §5 panic=abort guard (`5888d4c`);
   - R15-1 (`f6a52ca`);
   - known items F1 (`16659ee`), F2 (`f677e55`), M1/M2 (`4b277cd`) and ZK-F3 (`f36b909`).

   **In A8 WIP only** (not merged):
   - R8-2 / R10-1 (unsolicited unknown-header blocks dropped);
   - R8-4 (group diversity within a round);
   - R8-7 (stem conflict check before verification);
   - N-4 (handshake counts);
   - local hold without a stem;
   - R9-2 (the low-work header gate).
4. **One new concrete vector (it deepens the known "global PX relay budget exhaustible").**
   - `on_stem_tx` charges `px_rate` (per peer, then global) **before** the stempool-duplicate check and before `check_tx` (net.rs:1462-1469 vs 1470-1473).
   - A contextual failure is unpenalized (net.rs:1485-1487).
   - Replaying **any already-mined PX transaction** (spent nullifiers, so a contextual failure, so no penalty) from about 10 connections at 0.2/s each keeps the node-wide 2/s PX bucket empty indefinitely. The attacker needs no proving, and neither side spends CPU. The cost is bandwidth only: about 4.4 MB/s.
   - This is the cheapest form of R3-5's black hole. The fix: charge the global bucket only after a cheap novelty/contextual pre-filter, and add `recent_rejects` for contextual PX failures within a block.
5. **Contradictions between reports** are resolved in §3. The main ones:
   - a root `rust-toolchain.toml` (R13 for it, R14 against): R14 is right about the file, R13 about the goal;
   - a RandomX salt tweak (R9 rejects it, R15/I4 propose it): all agree to keep rx/0 for the testnet;
   - the single `/outputs` query (R3 says "never change", I3 says "index locally and stop calling it"): I3 dominates.
6. **Deduplicated P0 list:** 15 items (§4).
   - Five are code (policy-only).
   - One is the v3 consensus decision table.
   - Four are tests/evidence.
   - Five are procedural or documentation.

   Items I **downgrade** for the trial, with reasons, are in §5.

---

## 1. Verdict table (major findings)

Legend:
- **C** = CONFIRMED;
- **CC** = CONFIRMED-WITH-CORRECTION;
- **O** = OVERSTATED;
- **W** = WRONG;
- **U** = UNVERIFIABLE.

Status: **fixed** = fixed in HEAD; **WIP** = fixed only in an unmerged worktree.

### R3 (privacy)

| ID | Claim (short) | Re-verification (file:line) | Verdict | Trial priority |
|---|---|---|---|---|
| R3-1 | Coinbase maturity removes young decoys; young real spends stand out | The picker draws age → output index → uniform output in the block (decoy.rs:199-224), with a whole-chain `average_output_time` (decoy.rs:193). The wallet draws a pool of `(4·need).max(32)` and keeps a random subset of the *mature* ones (wallet.rs:1069-1076, 1101-1125). That is conditioning, not redrawing within the age band. The simulation assumptions match: exp(Gamma(19.28, 1/1.61)) s; lock 10T; recent window U[0, 15T); `COINBASE_MATURITY` 60 (params.rs:49-51). | CC. The magnitudes assume the real input is non-coinbase; on a young chain many real spends are coinbase. P(all 15 decoys coinbase) = cb^15 recomputes: 0.94^15 = 0.40, 0.75^15 = 0.013, 0.87^15 = 0.12. | P1 (wallet) |
| R3-2 | Nonce start persists: miner clustering | Was `main.rs:87,129` | C, **fixed `f331642`** (fresh start per template) | done |
| R3-3 | Coinbase-dominated rings; effective ring 1.9 against miners | Formula 1 + 15(1 − cb·m) | CC. 1.9 needs m = 1 (every miner colluding). With m = 1/7 it is ≈ 14. The outsider "unique non-coinbase member" heuristic (40%) is valid. | docs P0, wallet P1 |
| R3-4 | q = 0.1 with a 39 s embargo is not Monero's pair | dandelion.rs:45-49; docs/p2p.md:203 "as deployed in Monero" | C. It matters mostly for PX stems with slow hops (≈12% origin self-fluff at 1.5 s/hop, L = 10) [math]. | P1 (1-line policy); docs P0 |
| R3-5 | Forced self-fluff (PX black hole, no stem, first-hop drop) | net.rs:1462-1469, 1493-1522; dandelion.rs:133-135 | C, plus a new cheapest vector (§0.4, replaying mined PX). "No stem" is in A8 WIP (hold). | P1 |
| R3-6 | GetAddr fingerprint across onion and clearnet | net.rs:874-897 (`sample(1000)`); addrman mixes networks | C | P1 |
| R3-7 | Contract nullifiers computable by holders, "undocumented" | kernel.rs:324, record.rs:102-112 | W on "undocumented": px.md:595-598 states it. The PX-F4-B public-`rcm` corollary is new (a docs line). | P2 docs |
| R3-8 | Bridge amounts reduce amount privacy | tx/px.rs payouts | C (accepted limitation, px.md §12 guidance exists) | docs |
| R3-9 | Remote-node plaintext RPC defeats network privacy | wallet/node.rs; rpc | C (known, A7b) | P1 |
| R3-11 | No shielded coinbase | builder.rs:352-381 | C (design). It is CONSENSUS; not ready for v3 unless the schedule (R16-1) exists. | P0 decision: defer |
| R3-14 | P7/N4 overclaim | assumptions.md:67 now says "not re-analysed"; p2p.md:203 still says "as deployed in Monero" | CC (partly addressed by `6ed731f`) | P0 docs |
| R3 §6 | PX-only is infeasible (110× capacity gap, 4.7 GB/day) | 3 × 2.18 MB × 720 = 4.7 GB; 237,600 / 2,160 = 110 | C. The v1 figure should use 381/block (R12): 274k/day, 127×. | info |

### R8 (P2P)

| ID | Claim | Re-verification | Verdict | Trial priority |
|---|---|---|---|---|
| R8-1 | The chain lock is held for unbounded work and taken on async threads | PoW of an unknown header under the lock (manager.rs:437-446 → chain.rs:464-465). `sync_state` connects everything reachable (manager.rs:497ff). `inner.chain()` is called on async paths (net.rs:1237-1240, 1206, 602). | CC. The per-block figure uses a wrong v1 budget (1 MB, 400 tx); the correct maximum is 381 × ≈3.5–6.8 ms ≈ 1.3–2.6 s. The real worst case is the R12-2 deploy block (25–50 s). | **P0** (a, b), for the late joiner with PX blocks |
| R8-2 | Unsolicited blocks are fully processed, RandomX under the lock | net.rs:1169-1175: +10, then `submit_block` anyway | C; **WIP A8** (drops unknown-header unsolicited blocks) | P0 via the A8 merge |
| R8-3 | addrman: one source reaches all new buckets; no addr rate limit | addrman.rs:48-54 (bucket = H(secret, table, group(addr), group(src)) mod 256), 83-107; on_addr net.rs:899-933. 16,384 slots at ≈500/s ≈ 33 s [math] | C | P1 (P0-public) |
| R8-4 | Group diversity is not enforced within a round | net.rs:1741-1776 (`groups` computed once) | C; **WIP A8** (`groups.insert`). It is skipped entirely when `allow_private`. | P0 via A8 (P0-public) |
| R8-5 | Every onion is its own group | addr.rs:88-92 | C | P1 (P0-public for Tor) |
| R8-6 | SOCKS5 without stream isolation | socks5.rs no-auth only | C for the code; U for the Tor default isolation flags [assumed] | P1 |
| R8-7 | Stem conflict check after the full `check_tx` | net.rs:1476 before 1498 | CC. The mempool path is safe (precheck first, mempool.rs:201, 219). **WIP A8.** | P0 via A8 |
| R8-8 | Unsolicited single headers cost one RandomX hash each | net.rs:938-1047 | C. A8's gate covers low work, not invalid PoW (a rotating-IP attacker). | P1 |
| R8-9 | Block timeout bans honest slow peers | `BLOCK_TIMEOUT` 60 s (net.rs:39); 16 per request (`BLOCKS_IN_FLIGHT`); +5 each (net.rs:1637-1649, 1662-1664); a late block is "unrequested" +10 (1169-1172) → 100 → ban | CC. LAN IPs are banned too. Manual `--peer` dials bypass bans, so the trial sees churn rather than a partition. Not in A8. | **P0** (S) |
| R8-10 | Outbox of 64 messages ≈ 605 MB; frame pre-allocation | net.rs:44, 1123-1144; transport.rs:103 | CC. 64 × 9,454,144 = 605 MB ✓ and ×64 peers = 38.7 GB ✓. But the bound is 64 × the largest existing block (duplicate ids allowed); memory is freed on the kill; the receive allocation is lazy (commit, not RSS). | P1 (P0-public) |
| R8-11 | No control/bulk priority | single FIFO | C | P1 |
| R8-12 | Scheduling trusts `Version.height` | net.rs:1220 | C [src, light] | P1 |
| R8-13 | Seed fallback only when addrman is empty | net.rs:1730 | C. N/A for a no-seed trial. | P1 |
| R8-14 | An unknown message type means a ban; `Version` is not extensible | message.rs:237-239 `UnknownKind`, `finish()`; net.rs:736-739 PROTOCOL 100 | C | **P0** (S). Mid-trial upgrades must not partition. |
| R8-16 | Per-inbound-peer trickle timers | net.rs:476-498, 1608-1616 | C | P1 |
| R8-17 | The origin's embargo fires first ≈ 17% | E[1/(L+1)], q = 0.1: 0.173 ✓ [math] | CC. Conditional on a black hole beyond every hop; on the honest path ≈ 0 for v1. See §0.2. | P2 |
| R8-18 | Unpadded PX size reveals the origin to an ISP | frame = payload + 36 | C (known class; no fix below proof size) | docs P0 |
| R8-19 | `--proxy` without `--proxy-only` listens on clearnet | config.rs:203-215 | C. I3-2 is the sharper form (`Version.listen` carries the onion to clearnet peers, net.rs:605-612). | P1; docs P0 |
| R8 §3.4 | Inbound caps per /64 and /16 as P0 | — | O for the trial (trusted mesh) | P1 (P0-public) |
| R8 §5 | IBD 32.9–54.8 CPU-h per chain-year; stale ≈17% | 262,980 × 0.45/0.75 s ✓ | CC. Stale rate: R12's model (≈12% full, ≈3% empty) is better founded; all are [est]. | info |

### R9 (RandomX)

| ID | Claim | Re-verification | Verdict | Trial priority |
|---|---|---|---|---|
| R9-1 | No semantic deviation from RandomX v1 | Rests on the official vectors plus the hand check | U beyond the vectors (I did not redo the semantic diff); consistent with the tests | — |
| R9-2 | Fake-seed cache build under a global lock; 300–500× asymmetry | pow.rs:55-70 (built under `caches` mutex, capacity 2) ✓. Arithmetic 0.45–0.75 s / 1.4 ms = 321–536 ✓ | CC. It holds only at D ≈ 1; ≈4–7× at D0 = 100; the collapse needs multi-day chain time (§0.2). A8 `anti_dos_threshold` (WIP) closes the low-work part; the in-mutex build remains. | P1 |
| R9-3 | x87 targets split silently | — | C, **fixed `8097f66`** (also a 64-bit-only guard in consensus) | done |
| §4.1 | 4,194,304 VM instructions; 59 M superscalar ops per light hash; 1.2×10¹¹ per dataset | 8 × 2048 × 256; 16,384 × 8 × ≈450; 34.08 M × 3,600 | C [math] | info |
| §4.4 | Pure-Rust miner 50–100× slower than JIT; rental risk | 1/0.1 s vs 1/1.4 ms ≈ 70× | C (accepted limitation; documentation) | P0 docs |
| R9-R4 | No next-dataset pre-build | miner main.rs | C (known) | P2 (the trial observes it) |
| R9-9 | 6% stale work (15 s refresh) | 7.5 / 120 = 6.25% | C | P2 |

### R10 (storage, node, RPC)

| ID | Claim | Re-verification | Verdict | Trial priority |
|---|---|---|---|---|
| R10-1 | Cheap height-1 siblings with 9 MB bodies stored and kept in RAM forever | difficulty.rs:18-21 (`n == 0 → initial`); params.rs:61 D0 = 100; manager.rs:437-468 (append and `bodies.insert` before validation); net.rs:1169-1175 | C in HEAD. **WIP A8** (unknown-header unsolicited blocks dropped before hashing; low-work header gate). Whether 9 MB of decodable garbage fits is [unknown], as R10 says. | P0 via A8 |
| R10-2 | Poison recovery resumes a half-applied `MemoryChain` | node/lib.rs:53-58 (the comment is false); state.rs:147-219 mutates, then `expect` at 182 and 205-208; `panic = "unwind"` (Cargo.toml:31) | C (reachability [unknown]) | **P0** (S, my upgrade): fail-stop beats silent divergence in the trial |
| R10-3 | `blocks.dat` has no header (network, genesis) | store.rs:1-6; the orphan message at manager.rs:294-298 | C | P0 procedural (fresh data directories, R15 E6); code P1 |
| R10-4 | DNS rebinding / cross-origin on the loopback RPC | lib.rs:124-134: no Host check, auth or CORS layer | C [src]; exploit class [assumed] | P1 (the trial runs on browsing desktops: do it if cheap) |
| R10-5 | `/px/commitments` clones every record under the lock on a worker | state.rs:113-119 filter + clone; handler not in `spawn_blocking` (only lines 193 and 235 are) | C | P1 |
| R10-6 | PX undo ≈4.2 KB per block, 1.1 GB/yr idle | 100 × 32 + (8 + 32 × 32) = 4,232 B ✓; × 262,800 ✓ | C | P2 (≈12 MB over 96 h) |
| R10-8a | Silent tail drop | — | C, **fixed `9578517`** | done |

### R11 (wallet)

| ID | Claim | Re-verification | Verdict | Trial priority |
|---|---|---|---|---|
| W1 | A generated vault secret is lost on `Uncertain` | wallet/main.rs:472-499 (`?` at 496 before the print at 497) | C. A7b only fixes the opt-in `--secret-out` path. | P0 procedural (mandate `--secret-out` after the A7b merge); code P1 |
| W2 | No PX viewing-key hierarchy; `d` is a free witness | kernel.rs:263-275 (`d` read as witness, not derived) ✓ | C on the facts; **O** on "P0": wallet-only, and testnet wallets are disposable | P1 decision (before public/mainnet) |
| W3 | Seed has no version, birthday or network | wallet.rs:322-344 | C | P1 |
| W4 | PX spend authority = `sk` inside the proof | px/wallet.rs:87-108 | C (design, CONSENSUS to fix) | P3; docs P1 |
| W6/W7 | Misleading PX insufficient funds; no confirmation or history | — | C | P1 |
| W8/W9 | Wallet tree rebuilt from genesis; no compact blocks | px.rs:479-492 | C | P2 |
| fee | `PX_STANDARD_FEE` = 0.089 BLK | 2 × (4,194,304 + 262,144) = 8,912,896 ✓ | C | — |

### R12 (performance)

| ID | Claim | Re-verification | Verdict | Trial priority |
|---|---|---|---|---|
| R12-1 | RAM O(chain), ≈4.5× v1 decode factor, 6 KB/block floor; 16 GB in 147 d (S1), 16 d (S2), 8 d (S3), 2.4 d (S4) | `Point` = 32 + 4 × 40 B = 192 B (point.rs:13-16) ✓. Per block: S1 6 + 4.5 × 7.8 KB + 110 KB ≈ 151 KB → 109 MB/day ✓; S2 1.42 MB → 1.02 GB/day ✓; S3 2.68 MB ✓; S4 9.3 MB → 6.7 GB/day ✓ | CC. The IBD transient is bounded by the 256-body window (≈2.4 GB worst case), not 8 × 151 MB: inbound peers are download candidates too (net.rs:1206-1228). | P2 (trial S1: safe) |
| R12-2 | Deploy/PX v1 inputs weigh 0: 12,096 CLSAGs per block, 25–50 s | types.rs:452-458 (weight 0); validate.rs:788-799 (separate budgets); 8,388,608 / 44,338 = 189 × 64 ✓; fee 0.168 BLK ✓ | C (the seconds are [est] from t_clsag 2–4 ms) | **P0 decision** (CONSENSUS; include in v3 or defer explicitly) |
| R12-3 | `/px/commitments` O(N) per call | = R10-5 | C (duplicate) | P1 |
| R12-4 | Restart = full single-thread revalidation; load 2× the file | known PX-F3; store.rs load | C | P2; docs P0 (operators must expect it) |
| R12-10 | Docs say 4 PX per block; the true figure is 3 | still in HEAD: px.md:385, 546; zk.md:719; aggregation-study.md:147 | C, **open** | P0 docs |
| §2 | v1 381/block; attacker fill 0.119 / 0.267 / 0.168 BLK | 597,000 × 20 = 11.94 M ✓ | C | info |

### R13 (testing and supply chain)

| ID | Claim | Re-verification | Verdict | Trial priority |
|---|---|---|---|---|
| T-1 | No non-malleability oracle | fuzz targets check round trips only | C on the gap; **O** on P0: the known instance (M1/M2) is fixed and tested (`4b277cd`) | P1 |
| T-2 | Fuzz campaigns ran without overflow checks or debug assertions | run_campaign.sh:9,19 `--release`; cargo-fuzz 0.13.2 project.rs:259 adds `-Cdebug-assertions` only if `!release \|\| -a`; fuzz/Cargo.toml `[profile.release]` sets no overflow checks | C | **P0** (evidence: re-run with `-O -a`, or stop citing G9 for overflow) |
| T-3 | No consensus vectors; the LWMA mutant `(n+1)→n` survives | difficulty.rs:40. Recomputed: steady state 9,836 ∈ [9,800, 10,200]; 2× 19,672 ∈ [19,000, 21,000]; ½× 4,918 ∈ [4,750, 5,250]; bound test 100,000 ≤ 101,667 and > 10,000; early-chain 300 > 100 (lines 68-128) | C [math] | **P0** |
| T-8 | RandomX not differentially tested at scale; no aarch64 | lib.rs vectors | C | P1 (C3 cross-device hash check is P0 procedural) |
| T-10 | No tags or signing; floating Docker base; no `.dockerignore` | `git tag` empty; Dockerfile:8 `rust:1-bookworm`; no `.dockerignore` | C. The "root `rust-toolchain.toml`" part conflicts with R14 (see C1). | **P0** (tag, signing, pins); root file: reject |
| T-4/5/6/7/9/11/12 | Property tests, DST, stateful fuzzing, corpora, labnet chaos, deny/vet, mutants | not re-verified line by line | C (plausible; consistent with the tree) | P1–P2 |

### R14 (documentation and developer experience)

| ID | Claim | Re-verification | Verdict | Trial priority |
|---|---|---|---|---|
| D-1 | The PX/ZK layer has no normative byte spec | zk.md:528; zk/lib.rs encode | C | P1 (write it with the v3 bundle) |
| D-2 | No frozen vectors | = T-3 | C (duplicate) | P0 (merged into P0-2) |
| D-3/4/5 | No single status source; fragmented IDs; no decision log | — | C | P1 |
| D-6 | No build or rule identification | main.rs:67-72 (8-byte genesis prefix only); clap `version` | C | **P0** |
| D-7 | No operator sizing, upgrade or backup guidance | — | C | P0 (sizing and replay-time subset) |
| D-8 | Legacy, privacy-unsafe issue template | — | C, **fixed `58f25ec`** | done |
| D-10 | No LICENSE | no root LICENSE | C | P0 decision (other people run the binaries) |

### R15 (testnet readiness and decentralization)

| ID | Claim | Re-verification | Verdict | Trial priority |
|---|---|---|---|---|
| R15-1 | v3 rules under the v2 identity | — | C, **fixed `f6a52ca`** (`TESTNET_GENESIS_FINAL`). Cosmetic: the error literal embeds source indentation (config.rs:155-157), the same defect class as R10-14. | done |
| R15-2 | JIT miners out-hash honest miners about 100× | config.rs salt `RandomX\x03` | C (info for the trusted trial) | P0 decision + docs |
| R15-3 | Genesis not bound in the P2P session or wallet | transport.rs:161-168 (`network_id` only) | C | **P0** (S, bundle with v3) |
| R15-4 | FTL does not stop pre-mining after the reveal | [math] | C | P0 (genesis procedure) |
| R15-5 | No release integrity; work on one machine | 22 commits unpushed; no tags | C | **P0** |
| R15-6 | Neutral kernel needs more than a path remap | known | C | v3 bundle |
| R15-7 | No supply-audit tool | — | C | **P0** |
| R15-11 | Windows desktop hazards | — | U (operational assumptions; reasonable) | P0 procedural |

### R16 (architecture)

| ID | Claim | Re-verification | Verdict | Trial priority |
|---|---|---|---|---|
| R16-1 | No rule schedule; every change is a new genesis | no `rules_at`; header version equality | C | **P0 decision** (in v3 or explicitly v4) |
| R16-2 | No golden corpus | = T-3 | C (duplicate) | P0 |
| R16-3 | Proof bytes = Plonky3 serde via caret-pinned postcard | zk/Cargo.toml:30-31 `postcard = "1"`, `serde = "1"`; CI test jobs lack `--locked` (only `cargo install … --locked`) | C | **P0** (S) |
| R16-6/7 | Validate-then-`expect`; one global mutex | = R10-2, R8-1 | C (duplicates) | P0 as above |

### I3 (network privacy) and I4 (sustainability)

| ID | Claim | Re-verification | Verdict | Trial priority |
|---|---|---|---|---|
| I3-1 | An `InvTx` probe reveals stempool membership and forces a fluff | net.rs:1261-1264 (stempool id → no `GetTx`, `fluff`) | C | P1 |
| I3-2 | `Version.listen` sends a configured onion to clearnet peers | net.rs:605-612 (on every connection) | C | P1 (docs P0 for Tor operators) |
| I3 7(a) | Index outputs locally and stop calling `/outputs` | the wallet already downloads every block | C (improvement) | P1 |
| I4-1 | R9's rejection of a salt tweak contradicts the RandomX guidance | — | C as a contradiction (see C2) | mainnet decision |
| I4 F1 | Upgrade table plus branch id in v3 | = R16-1 | C (duplicate) | P0 decision |

---

## 2. Checks the reviewers missed, or attacks blocked by existing code

- **PX global-budget drain by replay** (new vector for a known item). §0.4: net.rs:1462-1469 charges the global bucket before the duplicate check (1470-1473) and before the contextual verdict, which is unpenalized (1485-1487). It costs only bandwidth.
- **Mempool path protected against R8-7** by `precheck` before validation (mempool.rs:201, 219).
- **Manual peers bypass bans** (net.rs:1709-1719 for `cfg.connect`; `connect_outbound` does not consult `bans`). This softens R8-9 in the trial, but it also means a peer banned for a real violation is re-dialled every 10 s if it is listed with `--peer`. That is harmless in a trusted mesh; document it.
- **`on_get_blocks` accepts repeated ids** (net.rs:1123-1134), so R8-10 needs only one large block.
- **R10-1's attack also needs the unsolicited path.** Side-branch bodies are never *requested* (`missing_bodies` walks the best chain), so R10-1 depends only on the unsolicited-block path, which A8 closes. Worth a regression test when A8 merges: "a low-work sibling of block 1 is neither stored nor held in RAM".
- **R3's simulation is faithful** on:
  - the picker;
  - the maturity filter (`coinbase_limit` = `cumulative[next − 60]`, wallet.rs:1040-1043);
  - the 60-candidate pool with a random eligible subset.

  One simplification: SIM ignores PX `bridge_out` payouts as v1 outputs. That is negligible at testnet PX volumes.
- **R12's t_px is wall-clock with Plonky3 `parallel`.** Under a chain lock that also holds a rayon pool, contention with the node's own work is [unknown]. It would be worth measuring together with R12's measurement list.

---

## 3. Contradictions between reports, and resolutions

| # | Reports | Contradiction | Resolution |
|---|---|---|---|
| C1 | R13 T-10 vs R14 §2.3 / zkvm/guests/README.md:25-26 | Add a root `rust-toolchain.toml` / never add one | **R14 is right about the file**: a Windows GNU default host breaks the build. Keep R13's goal by other means: CI and Docker pinned to 1.98.1 by version and digest, a build-script or `rust-version` check, and the rustc version recorded in the V1 evidence. |
| C2 | R9 §7 vs R15-2(b) / I4-1 | Reject a salt tweak / adopt a unique salt | **All agree: keep rx/0 for the testnet**, and document that K1 cannot be met against JIT miners. The mainnet choice is an owner decision. R9's "loses reference audits" is weaker than stated: a salt changes no audited structure. It does lose the official vectors, which a reference oracle would then have to produce. |
| C3 | R8 (1 MB, 400 tx), R3 (330), R12 (381) | v1 capacity per block | **R12**: `MAX_BLOCK_WEIGHT` 600,000 (params.rs:56), less `COINBASE_RESERVE`, at 1,563 B |
| C4 | R8 §5 (17%), R12 §8 (12%/3%), R9-8 (2–3%) | Stale rate | Different terms. R12 is the combined model; all are [est]; measure on the trial |
| C5 | R3 §9 ("never change the single `/outputs` query") vs I3 §3.9 (stop calling it) | Wallet decoy fetching | **I3 dominates** (no query at all). Reword R3's rule to "never make per-ring queries" |
| C6 | R12 I1 (P1) vs R10-6 (P2) | PX undo delta priority | **P2 for the trial** (≈12 MB over 96 h); P1 before any long public testnet |
| C7 | R8-17 vs R3-4 | Origin self-fluff probability | Both are right under different conditions (§0.2). The v1 honest path ≈ 0; the PX slow path is ≈10%; after a black hole, 1/k |
| C8 | R11 (W2/W3 as P0) vs R15/R16 (v3 bundle) | Is the PX key hierarchy part of the v3 freeze? | **No.** It is wallet-only (`d` is a free witness), so it does not belong in the consensus bundle. Decide before a public testnet with persistent users |
| C9 | R9-6 (P2), R10-12 (P3), R12-14 (info) | `CachedPow` unbounded | One item, P2. `9578517` re-keyed it by seed; it is still unbounded |
| C10 | R8 ("worst case ≈ 3.4 s per block") vs R12-2 (25–50 s) | Worst block validation time | **R12-2.** R8 did not consider weight-0 deploy CLSAGs |
| C11 | R13 T-1 (P0) vs the fixed M1/M2 | Oracle priority | P1: the known instance is fixed and tested. Keep the structure-aware PX test in P0-2's golden-proof set |

---

## 4. P0 before the seven-device trial (deduplicated)

**Column key:**
- **Kind:** policy / CONSENSUS / test / procedure / docs.
- **Size:** S / M / L.
- **Status:** open / WIP (unmerged worktree) / fixed.

| # | Item (source findings) | Owner | Size | Kind | Status |
|---|---|---|---|---|---|
| P0-1 | **v3 consensus decision table**, signed off by the owner: each item "in v3", "deferred (v4)" or "accepted" (R15 A2, R16 Stage B, I4 F1). Minimum rows: (a) rule schedule + verifier/branch id (R16-1, I4 F1); (b) block verification-cost bound for weight-0 inputs (R12-2); (c) platform-neutral kernel + path guard test (R15-6, R16-13, known); (d) PX-F5 (known); (e) M3 FRI folding-schedule pin, and `COMMIT_POW_BITS` given the `4b277cd` zero-witness rule (A14); (f) PX output-word encoding (known); (g) RandomX: keep rx/0 (C2); (h) shielded coinbase: defer (R3-11); (i) fresh genesis per R15 §4. Every row that goes "in v3" then follows the owner's change pipeline. | owner + consensus/zk/px | S (decisions); M–L (the chosen implementations) | **CONSENSUS** | open |
| P0-2 | **Consensus golden vectors, fingerprint and build identity.** Frozen vectors (LWMA incl. the `(n+1)` mutant, emission, MTP/FTL, seed schedule, tx/block ids, `sig_message`, `tx_root`, addresses, `Hk` domains, `h_tx`, one golden PX proof, and a structure-aware rewrite-rejection test). A consensus fingerprint (manifest hash, kernel id, proof version) pinned by a test and shown with commit and dirty flag in the start-up log, `/info` and `--version`. The full genesis id in `/info` (R13 T-3, R14 D-2/D-6, R16-2, R15-8). Freeze the vectors **after** P0-1's changes, **before** the tag. | tests + consensus + node | M | test / policy (no consensus change) | open |
| P0-3 | `=` pins for `postcard`, `serde` and the other caret-pinned consensus crates (A14 list); `--locked` in the CI test jobs and the documented builds (R16-3, known A14) | build | S | policy | open |
| P0-4 | Bind the genesis id into the P2P session KDF (or a first frame) and into the wallet file (R15-3). Bundle it with the v3 release. | p2p + wallet | S | policy (P2P protocol) | open |
| P0-5 | **Review, test and merge A8 round 2.** It covers: unsolicited unknown-header blocks dropped (R8-2, R10-1); in-round group diversity (R8-4); stem conflict check before verification (R8-7); handshake counts (N-4); local hold with no stem (R3-5); low-work header gate (R9-2); plus the known header-queue, announcer and known_txs items. Add regression tests for R10-1 and R8-7 as written in the reports. | p2p (A8) | M | policy | WIP |
| P0-6 | Block-download timeouts: no score on timeout (disconnect or re-assign instead); a late requested block is not "unsolicited"; a byte-aware in-flight window (R8-9) | p2p | S | policy | open (not in A8) |
| P0-7 | Chain-lock liveness for the late joiner: bound `sync_state` to N blocks per call; move `inner.chain()` off the async threads in `on_inv_tx`, `schedule_downloads`, the maintenance tip check and the RPC readers (`spawn_blocking` as the interim step) (R8-1 a/b, R10-5, R16-7). Test: pongs keep flowing while 256 PX-bearing blocks connect. | p2p + node | M | policy | open |
| P0-8 | Ignore unknown message types (charge the message budget only); allow `Version` trailing bytes or a TLV area (R8-14) | p2p | S | policy (P2P) | open |
| P0-9 | A poisoned chain lock is fatal (log and exit; systemd or the operator restarts, and replay rebuilds the state); correct the comment at node/src/lib.rs:54-56 (R10-2, R16-6) | node + p2p | S | policy | open |
| P0-10 | Fuzz evidence: re-run the campaigns with `cargo fuzz … -O -a`, or strike overflow coverage from the G9 claims; fix `run_campaign.sh` (R13 T-2) | tests | S | test / docs | open |
| P0-11 | **Release integrity:** push or mirror the 22 unpushed commits off-site; signed annotated `testnet-v3-rc` and `testnet-v3` tags with the fingerprint published through two channels; Dockerfile pinned by version and digest; `.dockerignore` (R15-5, R13 T-10, R14 D-6/D-9) | owner + build | S | procedure | open |
| P0-12 | **Trial evidence tooling and gates:** a supply-audit procedure or tool with mandatory retention of every wallet (R15-7); a labnet regtest run past height 2400 with real RandomX and full-mode miners (R15 C2); a per-device-class RandomX hash check (R15 C3, R13 T-8); trial end = max(96 h, height 2113 + 720) (R15-9) | ops + tests | S | procedure / test | open |
| P0-13 | **Operator procedure:** fresh data directories and deleted `peers.json` (this covers R10-3 until the file header lands); Windows hygiene (R15-11); `--secret-out` mandatory for vault locks after the A7b merge (R11-W1 interim); RPC firewalled to loopback (R10-4 interim); hardware minimums (≥ 8 GB RAM on proving devices) and expected replay time after a restart (R14 D-7, R12-4) | docs / ops | S | procedure | open |
| P0-14 | **Documentation corrections:** 3 PX per block (R12-10); Dandelion "as deployed in Monero" (R3-4/R3-14); the P7 simulated effective-ring figures (R3 §8); K1 cannot be met against JIT rx/0 miners (R9, R15-2, I4); PX size reveals the origin to link-level observers (R8-18, R3-10); anonymity at 7 participants is not meaningful (R15 D4); `--public-address <onion>` without `--proxy-only` (I3-2) | docs | S | docs | open |
| P0-15 | LICENSE decision, and `license` fields in the workspace crates; licence texts for `third_party` (R14 D-10) | owner | S | docs / legal | open |

**Already fixed in HEAD (no action):**
- R3-2 (`f331642`);
- R9-3/R9-R5 (`8097f66`);
- R10-8a (`9578517`);
- R14 D-8 (`58f25ec`);
- the R16 §5 panic-abort guard (`5888d4c`);
- R15-1 (`f6a52ca`);
- F1 (`16659ee`);
- F2 (`f677e55`);
- M1/M2 (`4b277cd`);
- ZK-F3 (`f36b909`).

**Suggested order:**
1. P0-11 (push/mirror) now;
2. P0-5 and P0-6 to P0-9 (P2P and node, policy);
3. P0-1 decisions, then their implementations;
4. P0-3 and P0-4;
5. P0-2 (freeze the vectors on the final v3 rule set);
6. P0-10, P0-12 to P0-15;
7. the tag.

---

## 5. Downgraded from the reviewers' P0 for this trial (still valid for a public testnet)

| Item | Reviewer's priority | Mine | Why |
|---|---|---|---|
| R3-4 Dandelion pair | P0 | P1 | Origin privacy among 7 trusted devices is not meaningful (R15 D4). A one-line policy change that is possible at any time. The docs part stays P0. |
| R8-3, R8-5, R8-13, R8 §3.4 (addrman, onion grouping, seed fallback, /64 caps) | P0 | P1 (P0-public) | The trial uses explicit `--peer` lists, no seeds and trusted peers; `allow_private` skips group logic on a LAN. |
| R8-10 outbox bytes | P0 | P1 (P0-public) | Needs a non-reading peer; trusted peers only. The honest late joiner costs ≤ 16 blocks per request per server. |
| R10-1 | P0 | covered by P0-5 | The A8 merge closes the vector. |
| R10-3 file header | P0 | P1 code, P0 procedure | Fresh data directories (P0-13) remove the stale store. |
| R11-W1 | P0 | P0 procedure, P1 code | Test coins; `--secret-out` avoids the loss. |
| R11-W2/W3 | P0 (decision) | P1 | Wallet-only, not consensus; testnet wallets are disposable (C8). |
| R12-2 | P1 | P0 **decision** | CONSENSUS: include it in v3 or defer it explicitly, otherwise it costs another reset. |
| R13 T-1 | P0 | P1 | The known instance is fixed (C11). |
| R16-1 | P0 if v3 precedes the trial | P0 decision; implementation may be deferred to v4 by the owner | It is a mechanism, not a trial blocker. |
| R10-2 | P1 | **P0** (upgraded) | S effort. A silent state divergence would invalidate the trial's evidence. |
| R8-9 | P0 | P0 (kept) | It fires with PX blocks on home uplinks; S. |

---

## 6. Limits

- No builds or tests were run. Every "C" means that the code as read supports the claim. Performance figures stay [est] where the reviewers marked them so.
- A8's worktree was read at `9eb90ae` plus uncommitted changes. Its fixes are unreviewed; "WIP" means intent, not verification.
- I did not re-derive R3's simulation numerically. I checked its assumptions and closed-form pieces (cb^15, the effective-ring formula), and a rough gamma-mass estimate that agrees in order of magnitude (≈15–20% of raw draws land in blocks 10–59 deep).
- The Tor isolation defaults (R8-6) and the Windows hazards (R15-11) are [assumed].
- This is internal review, not an audit. Nothing here claims that any component is secure or ready.
