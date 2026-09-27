# 31 p2p-sync: research dossier (phase 2, phase 1: research and briefing)

Agent 31. This is internal engineering research, not an audit. I only read the repository: I built nothing and ran nothing. Where this dossier gives figures, they are arithmetic on unit costs that were measured before and recorded in the review reports. None of them is a new measurement.

---

## 1. Scope and what I read

**Commit:** `9e422d8` (`git rev-parse --short HEAD`), branch `rebuild/core`.

**Code in scope. I read these in full, or the complete functions named:**

- `p2p/src/net.rs`, all 2,934 lines, with particular attention to the following:
  - the constants (:69-105);
  - `Peer` and `State` (:199-302);
  - `request_headers_after` (:727-762);
  - `run_connection` (:953-1223), including the handshake height/tip and the initial `GetHeaders`;
  - `requested_by_us` (:1251);
  - `on_headers` (:1396-1471);
  - `HeaderOutcome`, `penalized` and `header_worker` (:1474-1628);
  - `sender_live` (:1631);
  - `ANTI_DOS_BLOCKS`, `anti_dos_threshold` and `worth_verifying` (:1642-1696);
  - `verify_headers` (:1701-1777);
  - `on_header_error` (:1795);
  - `on_get_blocks` (:1829);
  - `on_block` and `block_worker` (:1866-1994);
  - `schedule_downloads` and `window_has_room` (:2000-2039);
  - `maintenance_loop` (:2594-2759): tip announcement, timeouts and the "behind" re-request;
  - `maintain_outbound` (:2761);
  - the unit tests (:2854-2934).
- `p2p/src/limits.rs` (scores), and `p2p/src/message.rs` (limits: `MAX_HEADERS` = 2000, locator ≤ 64).
- `chain/src/manager.rs`:
  - `CachedPow` (:45-124);
  - `SYNC_STEP_BLOCKS` and `submit_block_in_steps` (:258-291);
  - `submit_inner` (:616-700);
  - `header_height`, `locator`, `headers_after`, `missing_bodies`, `pow_jobs`, `precheck_headers` and `accept_headers` (:1001-1200).
- `consensus/src/chain.rs`:
  - `HeaderError` and `is_permanent` (:19-75);
  - `HeaderChain` (:140-560): `work`, `main_id_at`, `ancestor_id`, `required_difficulty`, `seed_id_for`, `check_rules`, `precheck_batch`, `overlay_context`, `validate`, `accept`, `switch_to` and `mark_invalid`.
- `consensus/src/difficulty.rs` (LWMA-1; the maximum-increase clamp), and `consensus/src/params.rs` (testnet: D0 = 100, genesis time 2026-09-23, FTL 360 s, window 60, MTP 11, seed epoch 2048 / lag 64).

**Tests read:**

- `p2p/tests/network.rs`: the harness (`raw_peer_at`, `serve_branch`, `header_branch`, `CountingPow`, `SlowCountingPow`, `give_headers`) and every sync test:
  - `new_node_syncs_headers_first`;
  - `heavier_chain_wins_when_partitions_join`;
  - `invalid_header_gets_the_peer_disconnected`;
  - `junk_header_batches_cost_at_most_one_chunk_of_proof_of_work`;
  - `an_unrequested_header_batch_is_not_verified`;
  - `relaying_headers_of_a_block_with_an_invalid_body_is_not_penalized`;
  - `requested_blocks_are_not_dropped_by_the_byte_limit`;
  - `pings_are_answered_while_a_header_batch_is_verified`;
  - `a_peer_that_leaves_before_its_bad_batch_is_verified_is_still_charged`;
  - `the_header_queue_is_bounded_across_reconnects`;
  - `low_work_header_branches_are_not_hashed`;
  - `a_heavier_fork_deeper_than_one_batch_syncs`;
  - `a_tip_announcement_racing_a_headers_reply_is_not_penalized`;
  - `non_advancing_header_replies_do_not_cause_a_request_loop`;
  - `an_unrequested_block_of_an_unknown_header_is_not_stored`;
  - `pings_are_answered_while_the_chain_lock_is_held`;
  - `pings_are_answered_while_a_long_batch_of_blocks_connects`;
  - `blocks_in_flight_per_peer_are_bounded_by_bytes`.
- `p2p/tests/withheld_body.rs` (header and harness).
- The `consensus/src/chain.rs` unit tests:
  - `precheck_agrees_with_sequential_validation_and_computes_no_pow`;
  - `precheck_skips_known_headers_and_reports_breaks`;
  - `precheck_rejects_known_invalid_headers_and_their_descendants`.

**Docs and reports read:**

- `docs/p2p.md` (all of it; §6 and §12 in detail).
- `docs/reviews/full-review-2026-09-27.md`: the P2P sections, the register rows for R8-*, R1-C1 and R9-2, the P0/P1/P2 lists, and risk 6.
- `docs/reviews/autonomous-session-2026-09-27.md`: P2P rounds 2 and 3, and the open list.
- `full-review-2026-09-27/R8-p2p.md` in full, and `SX2-systems-crossreview.md` (the R8 table and the P0 list).
- `SX1-core-crossreview.md`: R1-C1 (the scope correction: any low claimed work, not only D = 1) and the genesis-timestamp note.

**Phase 2 coordination files:**

- `C:/bszkeval/p2/brief.md`, `roster.md` (entries 30-34, plus 02, 03, 04, 10, 35, 36, 41, 50) and `decisions.md`.
- `research/07-randomx-cache-seed.md` in full. Items W2, W3 and W6 land in my file, and the decisions log makes W1-W3 P0 and asks for a shared `worth_verifying` predicate in `chain`.

---

## 2. Current state (what exists, what is right, what the tests prove)

| Claim | Evidence class |
|---|---|
| Header-first sync holds: no body is requested before its header has passed every rule, including RandomX (`missing_bodies` lists only headers in the tree; `accept_headers` runs full validation). | source-read (`manager.rs:1087-1125, 1173-1200`); tested `new_node_syncs_headers_first` |
| The cheap rules are checked for the whole batch before any hash, through one shared rule function (`check_rules`), so batch and single validation cannot disagree. | source-read (`chain.rs:309-425`); tested `precheck_agrees_with_sequential_validation_and_computes_no_pow` |
| A junk batch costs at most one PoW chunk beyond its last valid header, and a batch the pre-check condemns costs no hash at all. | tested `junk_header_batches_cost_at_most_one_chunk_of_proof_of_work` |
| An unrequested batch of more than one header is not verified (+10 points). | tested `an_unrequested_header_batch_is_not_verified` |
| The header queue is bounded: at most one batch per peer, `max_per_ip` per origin, and 2 × (in + out) in total. A departed sender's batch is only pre-checked. | tested `the_header_queue_is_bounded_across_reconnects`, `a_peer_that_leaves_before_its_bad_batch_is_verified_is_still_charged` |
| **Work gate:** a batch is hashed only if its claimed tip work is at least our best header work at tip − 144, or if it is a full batch with at least half our work per height. | source-read (`net.rs:1642-1696`); tested `low_work_header_branches_are_not_hashed`, `a_heavier_fork_deeper_than_one_batch_syncs` |
| The claimed work computed by the gate is exact. The pre-check forces each header's difficulty to equal the LWMA-required one, so `Σ difficulty` is what the branch really claims. | math (the difficulty is a deterministic function of the branch's timestamps and cumulative work, `chain.rs:254-265`) |
| PoW runs outside the chain lock (`pow_jobs`, then `compute_parallel`, then `accept_headers`). | source-read (`net.rs:1756-1764`) |
| The read loop never verifies. Pings are answered during header PoW and during block connection. | tested `pings_are_answered_while_a_header_batch_is_verified`, `..._chain_lock_is_held`, `..._long_batch_of_blocks_connects` |
| **Body window:** 16 blocks and 32 MiB per peer (in practice 3 maximum-size blocks). Timeouts reassign the request without penalty, and a late answer is accepted for another 60 s. | source-read (`net.rs:74-86, 2680-2693, 1881-1890`); tested `blocks_in_flight_per_peer_are_bounded_by_bytes` |
| An unrequested body of an unknown header is dropped before it is hashed or stored. | tested `an_unrequested_block_of_an_unknown_header_is_not_stored` |
| **Non-advancing replies:** an empty reply, a solicited LowWork batch or a known batch lowers the peer's claimed height, so there is no request loop. | tested `non_advancing_header_replies_do_not_cause_a_request_loop` |
| There is **no minimum chain work and no presync.** For a node whose best header chain is at most 144 blocks (a fresh node, or any node during the first ~5 h after launch), the threshold is the genesis work, so any branch passes. | source-read (`anti_dos_threshold`: `main_id_at(0)` = genesis, work D0 = 100 on the testnet) |
| There is **no stall detection** and no per-peer "which blocks does this peer have" knowledge. The candidates are the peers with `p.height ≥ h`. | source-read (`net.rs:2013-2018`) |
| The **header worker is one FIFO**, with no priority for tip announcements. | source-read (`net.rs:1524-1628`) |
| The tests all run in `allow_private` mode, which **disables the per-origin queue cap**. So no test covers the per-IP limit that protects a public node, only the total cap. | source-read (`header_queue_room`, `net.rs:677-687`) |

**Assessment.** The sync layer is well designed for a v1:

- It is header-first.
- Its cheap checks come first, sharing one rule definition with full validation.
- Its gate uses exact claimed work.
- It has an explicit bounded queue.
- It does no verification on the read loops.

The work since R8 (the rounds 2 and 3 commits `12ce4cb`, `7d72b37` and `1c07316`) closed R8-2, R8-9 (the penalty part), R8-11, R8-14 and the P0-7 lock items. Several R8 line references are now stale: the code has moved by about 500-900 lines.

What remains open in my scope is structural:

1. the gate is *relative* to our own chain, so it protects nothing while that chain is short (R1-C1 residual, risk 6);
2. scheduling trusts self-reported height, and nothing detects a staller (R8-12);
3. the worker has one FIFO lane (R8-15);
4. the density rule is a heuristic stand-in for what Bitcoin does with presync;
5. 07's W2, W3 and W6 must land in `net.rs`.

---

## 3. Problems in scope (the brief's questions)

### P1. No `MIN_CHAIN_WORK`, and no presync: syncing from genesis next to a hostile peer

**What the problem is and why it exists.** `anti_dos_threshold` = `work(main[tip − 144])` (`net.rs:1648-1651`). While our best header chain is at most 144 blocks long, this is the genesis work (100 on the testnet), and every batch passes `worth_verifying`. The gate was designed for a synced node; a fresh node has no reference work.

**Attacker cost.** LWMA-1 floors the difficulty at 1 once timestamps are spaced more than about 60 s apart (SX1). `check_hash` with d = 1 always passes (SX1, math). So a hostile peer can produce a valid difficulty-1 chain **at no hashing cost** from any old block, including genesis.

**The timestamp budget bounds its length.** The limit is (now − fork timestamp) / ~61 s, so one year of chain age gives about 517k headers. That is about twice the honest height (263k per year at 120 s), so the free chain is *taller* than the honest one.

The testnet genesis time is `TESTNET_GENESIS_TIME = 2026-09-23` (`params.rs:41`). If that is not moved to launch time, the budget is already non-zero at launch. This is SX1's note, and a dependency on 40.

**Current behaviour on a fresh node, derived from the code:**

1. The node sends `GetHeaders` to every peer claiming a higher height, the attacker included (`run_connection:1121`, maintenance `:2716-2732`).
2. The worker processes one batch per peer at a time, in FIFO order.
3. Every attacker batch passes the gate. It costs 2000 RandomX light hashes (0.45-0.75 s each: about 125-190 s wall on 8 threads) and is stored forever. The header tree and the unbounded `CachedPow` each hold an entry.
4. Once one honest batch has been processed, the honest chain's work per header (the real difficulty) exceeds the attacker's (1 per header). The threshold jumps, and every later attacker batch is `LowWork`. The work-per-height rule also fails for the attacker.
5. **So the damage is bounded by how many attacker batches the FIFO holds before the first honest batch.** With the queue caps that is at most `2 × (64 + 8) = 144` batches in total, 2 per IP. With 32 IPs (64 inbound slots) that is about 64 batches: 128k hashes, about 2.7-4 h of an 8-core node, and about 128k junk headers stored (roughly 50-60 MB of RAM at about 400-500 B per header across `HeaderChain.entries`, `children`, `leaves` and `CachedPow`) [M/A].
6. **If no honest peer is reachable yet** (a node bootstrapping from a hostile or poisoned address set, which is 32's eclipse scope), the damage is bounded only by the timestamp budget: about 65-108 CPU-hours and about 250 MB per year of chain age, per distinct free chain.

**A second effect: F31-3.** Every stored junk branch whose work exceeds the connected tip's is walked in full by `missing_bodies` on every scheduling call. On a fresh node the connected tip is genesis, so every stored junk branch qualifies.

**Security consequences.** CPU and memory DoS of joining nodes, and delayed initial sync. There is no consensus or privacy consequence: the header tree never selects a lighter chain, and fork choice needs complete bodies (H1).

**Classification.**
- **Timing and trial impact:** the problem affects liveness and resources. It is not consensus-critical. It matters mainly for nodes joining after launch.
- **Launch window:** every node is exposed for the first 144 blocks (about 4.8 h). In the 7-device explicit mesh this is Low; for a public testnet it is Medium.
- **Classes involved:** architectural (the gate has no absolute reference) and DoS.

**Literature and prior art.**

- **Bitcoin Core before 24.0.1: checkpoints.** Hard-coded checkpoints bounded low-difficulty header spam. This eroded as the difficulty grew, which is CVE-2019-25220 (a memory DoS from headers spam; severity High; the attack cost fell from about 4 BTC in 2019 to about 0.14 BTC in 2024).
- **Bitcoin Core PR #25717 (merged 2022-08-30, shipped in 24.0.1): `HeadersSyncState`.**
  - It triggers when a peer's headers connect to a chain below `GetAntiDoSWorkThreshold()` = max(`nMinimumChainWork`, tip work − 144 blocks' work) and the message is full.
  - **PRESYNC:** headers are downloaded *without being stored*. The node checks continuity and `PermittedDifficultyTransition`, accumulates chain work, and stores a 1-bit salted commitment every `commitment_period` headers (random offset).
  - **Memory bound:** at most `6 · (now − chain_start_MTP + MAX_FUTURE_BLOCK_TIME) / commitment_period` commitments. The factor 6 is the fastest block rate the MTP rule allows.
  - **REDOWNLOAD:** once the claimed work reaches the minimum, the node re-requests the same headers from the fork point and checks them against the commitments.
  - **Release:** headers are released into the block index only while a buffer of `redownload_buffer_size` later matching headers exists, or once the redownloaded work reaches the minimum.
  - **Abort conditions:** a discontinuity, a bad difficulty transition, a commitment mismatch or overrun, the maximum commitments exceeded, and a non-full message without enough work.
  - **PoW:** it is checked for *every* header, in both phases, by `CheckHeadersPoW` in `ProcessHeadersMessage`. SHA-256d is cheap.
  - **Parameters:** they are set per release in chainparams and re-tuned at each release (e.g. PRs #31978 and #33274).
- **Bitcoin Core PR #31649 ("consensus: Remove checkpoints (take 2)", 2025).** It removed checkpoints entirely, on the grounds that presync plus `nMinimumChainWork` now provides the DoS protection. In other words, checkpoints are no longer needed to prevent header-spam DoS.
- **Monero.** It is not headers-first. It downloads block-id chain entries, then blocks in spans, verifying each block's PoW on arrival. It relies on hard-coded checkpoints (`src/checkpoints/checkpoints.cpp`), plus an embedded block-hash list that lets `--fast-block-sync` skip PoW for checkpointed history. That is a trust-in-release model that also bounds forks below a checkpoint.
- **FlyClient** (Bünz, Kiffer, Luu and Zamani, IEEE S&P 2020): sampling blocks in proportion to cumulative work makes a chain with a fraction of fake work detectable with a handful of samples.
- **Weighted reservoir sampling** (Efraimidis and Spirakis, IPL 2006) makes such sampling streamable in O(s) memory.

**Why Bitcoin's design cannot be copied verbatim.** Presync is safe in Bitcoin *because PoW is checked for every presync header* and SHA-256d is cheap. BlackSilk cannot afford that: one RandomX light hash costs about 0.5 s. Presync without PoW is spoofable at no cost.

LWMA's increase clamp (`weighted ≥ n²t/20`, `difficulty.rs:42`) lets the required difficulty grow by roughly **10× the window average per block**. So a fake branch with tight timestamps reaches any claimed work in a few hundred headers. That is Bitcoin's "compress the work into as few blocks as possible" attack, and here nothing prevents it before PoW.

The naive "presync on claimed work, then verify PoW in order" therefore lets the attacker prefix the fake tail with L free difficulty-1 headers. We would hash all L before reaching the first fake header, which is the same DoS as today.

**Proposed design: "RX-presync", a work-weighted sampled-PoW presync.**

1. **Trigger (the same shape as Bitcoin).** In `verify_headers`, after the pre-check, a batch below `T = max(MIN_CHAIN_WORK, work(tip − 144))` is handled as follows:
   - if the message is not full: `LowWork`, as today;
   - if it is full: start a presync for this peer, anchored at the batch's (stored) parent.
   The heuristic "full batch with at least half our density" rule is **retired**. It is replaced by presync, which handles both the fresh-node case and the deep-fork case, the way Bitcoin's single mechanism does. This removes F31-5.
2. **PRESYNC (cheap, off the chain lock, per peer).**
   - The node receives the peer's continuation batches (the locator starts at the last presync header).
   - It checks continuity and every rule except PoW, with a **persistent branch context**: a ring of the last 61 (timestamp, cumulative work) pairs, the height and the last id. This uses the same `check_rules` function as `precheck_batch`: one rule definition.
   - It accumulates the claimed work.
   - It stores a 64-bit SipHash-style salted commitment (keyed with local randomness) every K = 64 headers. Full-width hashes are affordable here: at most 2 × 263k headers per year gives about 66 KB per peer-year.
   - It stores the ids at seed heights: 1 per 2048 headers.
   - It keeps a **weighted reservoir of s headers**, with weight = claimed difficulty, stored with each sample's seed id.
   - **Abort without penalty** on `TimestampTooFarInFuture`, or when the height exceeds `2 × expected_height(now) + 10,000`. Here `expected_height(now) = (now − genesis_ts)/T`, the analogue of Bitcoin's MTP-based bound; honest chains track wall time through LWMA.
   - **Abort with a penalty** on a rule violation (as the pre-check does today).
   - An empty or non-full reply below T ends the presync as `LowWork`.
3. **The sampled PoW gate.** When the claimed work reaches T:
   - Verify the s samples, **sequentially with early exit**. Order them by descending difficulty (a fake tail is most likely there) and group them by seed to reuse the RandomX cache.
   - Any failure: ban (`INVALID_HEADER` 100), and discard the presync.
   - **Soundness argument (math).** Let a fraction r of the claimed work carry valid PoW. Sampling with replacement in proportion to difficulty gives P(pass) = r^s. With s = 32:
     - an attacker with half the claimed work real passes with probability 2^-32;
     - an attacker with 90 % real passes with probability 0.034, but has then spent at least 0.9·T of genuine work, which is the bound Bitcoin offers;
     - a zero-work attacker's free prefix L carries weight L/T ≪ 1, so it passes with probability about (L/T)^32 ≈ 0.
   - **Cost to us.** A zero-work attacker costs about 1 cache build plus 1 hash per identity, because of the early exit. An honest peer costs at most s hashes plus at most min(s, epochs) cache builds, **once per IBD** (about 32 × 1-3 s of CPU, against hours of header PoW).
4. **REDOWNLOAD.**
   - Re-request from the anchor. Each batch must match the commitments; a mismatch is `INVALID_HEADER`, because the peer switched chains.
   - Batches then go through the **existing** chunked-PoW path (`pow_jobs`, `compute_parallel`, `accept_headers`) and are stored as they are verified.
   - **Why storing as verified is acceptable.** Once the sample gate passes, the branch provably (with high probability) carries at least about T of genuine work. So storing its headers meets Bitcoin's invariant: "stored headers belong to a chain with at least the minimum work". An attacker who wants us to store its L free headers must also have spent about T genuine work.
   - Bitcoin's release buffer is not needed. With full-width commitments a switch is detected deterministically, and the work guarantee comes from the samples, not from the buffer. This is a deliberate simplification to review.
5. **Concurrency and budgets.**
   - At most one presync per peer, and at most 8 at a time.
   - Outbound peers first when more are waiting.
   - A presync's sample verification consumes 07's per-peer unpinned-build budget (W6).

**`MIN_CHAIN_WORK`: value and placement.**

- **Value:** per network, per release. It is 0 at the testnet launch, because presync then only replaces the density rule and covers deep forks.
- **Setting it:** each later release sets it to the honest chain's work at about release time minus one week (Bitcoin practice). The release procedure (40/43) records how it was derived.
- **Placement:** keep it **out of `ChainParams`**, which feeds the identity fingerprint. It is policy, like Bitcoin's (Bitcoin keeps it in chainparams but it is not consensus). I propose a `SyncParams` in `p2p` with a node override `--min-chain-work` (open question Q2).

**Trade-offs and what could go wrong.**

- Double header download: about 26 MB per chain-year. The cost is bandwidth only.
- The reservoir sampling needs an unbiased RNG. Use the node's ChaCha20 with fresh OS seed material: the peer must not predict which headers are sampled. Keys stay local.
- **Probabilistic soundness:** accepting an attacker with probability r^s is a *resource* risk, not a consensus risk. Headers are still fully verified before they are stored.
- **Liveness edge 1:** an honest peer whose chain is below `MIN_CHAIN_WORK` (a new testnet reset, a mis-set constant) cannot sync. Provide the `--min-chain-work 0` override and document it.
- **Liveness edge 2:** the height bound could reject an honest chain after a massive hash-rate surge. The 2× margin covers any LWMA-consistent chain [A; to be checked by 03's simulator].
- **Cache thrash:** mitigated by the early exit, the grouping by seed and 07's `SeedCache` pinning (W1).

**Tests that can prove the fix.**

- **Unit tests (sans-IO `PresyncState`, `p2p/src/presync.rs`):**
  - a commitment mismatch on redownload;
  - the height bound;
  - a future timestamp aborts without penalty;
  - the reservoir is weight-proportional (a chi-square test over 10^4 runs, deterministic RNG).
- **Property test (proptest):** for random honest branches, presync followed by redownload stores exactly the headers the old path stores, and the sampled hashes equal `CountingPow` calls.
- **Adversarial tests (`p2p/tests/sync_adversarial.rs`):**
  - **T-P1:** a fresh node, one hostile peer serving a 20k difficulty-1 branch and one honest peer. Zero hashes and zero stored headers for the hostile branch.
  - **T-P2:** an inflated fake tail after a free prefix. At most 1 hash (early exit), a ban, and nothing stored.
  - **T-P3:** an honest heavier fork deeper than 2000 still syncs (a regression of `a_heavier_fork_deeper_than_one_batch_syncs`, which is now via presync).
  - **T-P4:** a peer that switches chains between presync and redownload is caught.
  - **T-P5:** `MIN_CHAIN_WORK` = 0 behaves exactly as today for chains that pass the gate (a differential run over the existing suite).
- **Fuzz target (owner 41):** `PresyncState` fed arbitrary header sequences, with the invariant "memory ≤ bound; never emits a header whose ancestors were not emitted".

**Invariants that must never change.**

- No header enters `HeaderChain` without full rule and PoW validation.
- One rule function (`check_rules`) for pre-check, presync and full validation.
- A PoW-invalid header is always penalized, and a non-permanent failure (FTL, `UnknownUpgrade`) never is.
- The work gate never compares claimed work that the rules have not fixed. Difficulties must be the required ones.

### P2. Header-worker head-of-line blocking (R8-15)

**Problem.** There is one worker, in FIFO order (`net.rs:1524`). A single-header tip announcement waits behind every queued batch. A full batch is about 125-190 s on 8 threads; the queue holds at most 144 batches.

- **On a synced node:** attacker batches that pass the gate must carry real PoW, or they fail after one chunk (about 0.6 s wall). An identity-rotating attacker can then delay tip processing by about 0.6 s per queued identity (R8-8 is the single-header variant: 1 hash each).
- **On a syncing node:** honest tip announcements wait behind honest IBD batches, which is harmless, and behind the junk batches of P1, which is harmful.

**Consequences.** Liveness: a node lags the tip, and a miner mines on a stale tip (stale rate, miner fairness). Not consensus or privacy.

**Literature.**

- Bitcoin processes messages per peer in round-robin (`ThreadMessageHandler`). Headers are cheap there, so HOL blocking is not an issue.
- BIP 130 exists exactly so that new blocks are announced by header and processed immediately.
- BIP 152 high-bandwidth mode goes further and relays after header and PoW validation, before full validation.

**Proposed design (policy, `net.rs`).**

1. **Intake stage.** When the worker drains the channel, each batch gets a cheap classification under a short chain-lock hold (pre-check and claimed tip work):
   - **class 0:** 1-8 headers whose first parent is our best header tip or on our main chain within 8 blocks: an announcement, or a BIP 130-style short reorg;
   - **class 1:** solicited batches, ordered by *claimed tip work*, highest first;
   - **class 2:** everything else.
2. **Preemption at chunk boundaries.** `verify_headers` becomes a resumable job. After every chunk, the worker checks for a pending class-0 item and runs it first. Announcement latency is then bounded by one chunk (about 0.6 s) instead of 150 s or more.
3. **Work-ordered class 1.** An honest batch (high claimed work) overtakes junk batches. In P1 this cuts the fresh-node damage from "all attacker batches queued first" to "at most the batch in progress".
4. **Class-0 abuse bound:** one pending item per peer (as today). Invalid PoW is `INVALID_HEADER` (ban). Per-origin caps unchanged.

**Trade-offs.**

- The ordering changes *which* headers are stored first, never *whether*. `accept_headers` is order-independent for validity (`verdicts_do_not_depend_on_arrival_order`, a consensus test).
- It adds complexity to a hot path. The worker's state machine must stay sans-IO testable.

**Tests.**

- **T-H1:** a `SlowCountingPow` node verifying a 2000 batch still stores a tip announcement within 2 chunk times.
- **T-H2:** with k junk full batches queued, an honest full batch is verified before them. Assert by `CountingPow` order.
- **T-H3:** an invalid-PoW class-0 header from a rotating origin costs 1 hash and a ban per identity.

**Invariant.** Every queued batch is eventually processed or dropped by an explicit rule. No starvation of class 2: when class 0 and class 1 are empty, class 2 proceeds.

### P3. Stall detection, and scheduling that trusts `Version.height` (R8-12, deepened)

**Problem.** `schedule_downloads` (`net.rs:2013-2018`) picks uniformly among peers with `p.height ≥ h`. There are three sub-problems:

- `p.height` comes from `Version.height` or from accepted announcements. A peer that relays a *real* tip header (free: it is the honest block) becomes a candidate for its body.
- A block-request timeout (60 s) removes the request but does **not** lower `p.height` or exclude that peer (`:2680-2691`). The same staller can be picked again.
- Blocks connect in order, so a withheld lowest block stalls the whole window. A NotFound frees the slot immediately, and the next tick (250 ms) may pick another peer, or the same one, again.

**Scenario 1: a synced public node.**

1. An attacker with k of n connections relays every honest tip header promptly and never serves bodies.
2. Each new block's body goes to the attacker with probability k/n and waits 60 s.
3. After the timeout, the attacker is again a candidate with probability about k/n.

At 120 s blocks, a node with k/n = 1/2 is late by 60 s or more on about half of its blocks. That means stale mining and slow relay for its own peers.

**Scenario 2: IBD.** The same logic applied to the lowest missing block halts the connected tip for 60 s at a time.

**Scenario 3: fork branch downloads.** Peers on the main chain (height ≥ h) are asked for side-branch bodies they do not have, and answer NotFound. There is no penalty and no memory of the refusal, so the loop repeats every tick.

**Consequences.**
- **Liveness:** Medium on a public network, Low in the explicit trial mesh (7 honest devices).
- **Privacy:** none.
- **Consensus:** none.

**Literature (Bitcoin Core).**

- **Per-peer best known block:** `pindexBestKnownBlock` (and `pindexLastCommonBlock`). Blocks are requested only from peers whose known chain contains them.
- **Stall detection, `m_stalling_since`:** if the 1024-block download window cannot move because one peer holds its first block, that peer is disconnected after `BLOCK_STALLING_TIMEOUT`. The timeout is adaptive: 2 s by default, doubling per disconnected staller up to 64 s, and halving on progress (PR #25880).
- **Block download timeout:** base 1 block interval, plus 0.5 per other downloading peer.
- **Headers sync timeout:** 15 min + 1 ms per header.
- **`CHAIN_SYNC_TIMEOUT` (20 min):** evicts outbound peers that are behind.
- **`STALE_CHECK_INTERVAL` (10 min):** an extra outbound connection on a stale tip.
- **PR #32051:** protects `addnode` (manual) peers during IBD.

**Literature (Monero).** `cryptonote_protocol_handler`:

- `IDLE_PEER_KICK_TIME` = 240 s and `NON_RESPONSIVE_PEER_KICK_TIME` = 20 s;
- a span stalled beyond `REQUEST_NEXT_SCHEDULED_SPAN_THRESHOLD` (30 s; 5 s in standby) is re-requested from another peer;
- `DROP_ON_SYNC_WEDGE_THRESHOLD` = 30 s;
- `update_sync_search` drops a synced non-anchor peer to find a faster syncing one;
- peers whose claimed heights regress are penalized.

**Proposed design (policy, `net.rs`).**

1. **`Peer.best_known: Option<Hash>`.** This is the highest-work *validated* header the peer sent or announced. Set it on `Accepted` (last id) and on a class-0 announcement. `Version.height` is used only to decide whether to *ask* for headers.
2. **Candidate rule.** Block X is requested only from peers whose `best_known` has X as an ancestor. This needs `HeaderChain::is_ancestor(a, b)`: an O(1) main-chain fast path, else a bounded walk. It is added next to `ancestor_id` in `consensus/src/chain.rs` (additive).
3. **Per-block `tried` set.** A peer that timed out or answered NotFound for X is not asked for X again while another candidate exists.
4. **Staller rule.**
   - **Condition:** the lowest missing block on the download path has been in flight longer than `stall_timeout`, and at least one later block of the window has arrived. So the peer is slower than others; it is not merely that our own link is slow.
   - **Response:** disconnect it. No score and no ban (R8-9 lesson).
   - **Manual `--peer` entries:** never disconnected. They are only deprioritized (PR #32051 lesson, and the trial mesh).
   - **Timeout:** adaptive, 10 s base, doubling to 120 s, halving per connected block. The base exceeds Bitcoin's 2 s because a BlackSilk block is up to 9.45 MB against Bitcoin's about 1-4 MB.
5. **Size-aware block timeout.** Replace the fixed 60 s by `30 s + bytes_in_flight / 250 kB/s`, a 2 Mbit/s floor (R8-9 remainder, policy).
6. **Stale tip / chain-sync eviction:** the connection-manager part goes to 32. I supply the "peer behind" signal from `best_known`.

**Trade-offs.**
- Disconnecting stallers on a tiny network could drop the only peers. Hence the manual-peer protection, and "at least one later block arrived" as the condition.
- The adaptive timeout avoids the Bitcoin failure mode on slow links (#25880).

**Tests.**

- **T-S1 (block withholding):** 3 honest raw peers and 1 attacker peer that relays tip headers and ignores `GetBlocks`. The node's connected tip reaches the chain head within `stall_timeout + ε` of each block; the staller is disconnected once, not banned; honest scores are 0.
- **T-S2:** an IBD of 200 blocks with one staller holding the lowest block. The window moves after the stall timeout; the staller is never re-picked for the same block.
- **T-S3:** a fork-branch body is requested only from the peer that announced it. No NotFound loop: at most one NotFound per (peer, block).
- **T-S4:** a manual peer that stalls is deprioritized, not disconnected.
- **T-S5 (regression):** `blocks_in_flight_per_peer_are_bounded_by_bytes` and `requested_blocks_are_not_dropped_by_the_byte_limit` still pass.

**Invariants.**
- Timeouts are never misbehaviour.
- A late requested block is not unsolicited.
- The window stays bounded in bytes.
- NotFound is never penalized.

### P4. 07's W2, W3 and W6 in my file; the shared `worth_verifying` (decisions log: P0)

- **W2 (shared predicate).** The decision is: "a shared `worth_verifying` predicate in `chain`, used by both P2P (31) and RPC (36)".
  - Move `ANTI_DOS_BLOCKS`, `anti_dos_threshold` and `worth_verifying` from `net.rs` into a new `chain/src/sync_policy.rs`. They are pure functions of `&HeaderChain`, re-exported by `chain`.
  - The RPC `/block` gate (36, with 07's rule) calls the same function for a block with an unknown header. `full` = false for a single block; with presync, an RPC block below the threshold is simply rejected.
  - `MIN_CHAIN_WORK` enters the threshold there too, so both paths get one rule.
  - **Test:** the existing `low_work_header_branches_are_not_hashed` stays green, plus a direct unit test of the moved function against the three cases (extends best; near-tip rival; cheap deep branch).
- **W3 (chunk cap).** At `net.rs:1750`: `chunk = pow_threads.clamp(1, params.seed_lag as usize)`.
  - **Why:** an S + 65 header is never in the same chunk as an unverified seed header S. `compute_parallel(&jobs, chunk)` stays parallel at up to 64 threads.
  - **Test (07's T9):** `pow_threads = 128`, a seed-recording double; a garbage batch across S never requests the fake S′.
- **W6 (per-peer unpinned-build budget).**
  - **Rule:** before `compute_parallel`, compute the job seeds that are neither resident nor pinned (07's `SeedCache` query API). Such a batch consumes the peer's budget: 1 per 10 min. Over budget: `LowWork` (no penalty).
  - The presync sample gate (P1) consumes the same budget.
  - **Test:** 3 branches with distinct seeds from one peer lead to 1 cache build.
  - **Dependency:** W1 (07) must expose `is_resident_or_pinned(seed)`.

### P5. The density rule is weak while the historical difficulty is low (new; retired by P1)

**Problem.** The full-batch rule verifies a 2000-header branch whose work per height is at least half of *our historical* work over the same heights (`net.rs:1684-1695`). If our chain once had low difficulty (the launch ramp from D0 = 100, or any early low-hash-rate period), an attacker can mine one full batch forking there at half that density. Each victim then hashes 2000 headers (about 1000 CPU-s, about 2 min on 8 cores) and stores them forever.

- The attacker's headers are reusable against every node.
- Each distinct fork costs the attacker 2000 × D_early/2 hashes.
- The next batch must match our later, higher density, so the depth is limited to one batch per fork.

**Severity:** Low. Its reach depends on how low the early difficulty is (for example, at about 240k early difficulty, 7 devices, about 240M fast hashes per fork). **Fix:** P1 replaces this rule with presync. Until then, accepted as a limitation.

### P6. `missing_bodies` walks every heavier leaf back to its complete ancestor on every call (new)

**Location:** `chain/src/manager.rs:1087-1125`.

**Problem.** For each valid leaf with work above the connected tip (except the header tip), the loop walks back until it reaches a complete block, pushing every missing id. Only then does it sort and truncate to `max`. This is O(Σ depth of all heavier leaves) under the chain lock, on every `schedule_downloads` call: every 250 ms tick, after every header batch and after every block.

**Scenario:** a fresh node, where the connected tip is genesis for a long time. It has the P1 junk branches (each up to 2000 × batches deep, all heavier than genesis) and also honest stale forks. Tens of thousands to hundreds of thousands of map lookups, allocations and a sort, 4+ times per second, under the chain lock. That contends with block connection and the RPC.

**Severity:** Medium on a fresh node under P1, Low otherwise. **Confidence:** high (source).

**Fix (owner 02, since `missing_bodies` is in 02's scope; test supplied by 31):**
- stop each leaf's walk once `max` entries are collected beyond the lowest height already found, or cache a per-leaf "first missing ancestor" invalidated on body arrival;
- only consider the top-k heaviest alternative leaves (k = 8).

**Test:** 20 branches of 5,000 headers without bodies and a counting store. `missing_bodies(256)` touches O(256 · k) entries; its output equals the old function's (a differential test).

### P7. Sync from genesis with a hostile peer: the overall assessment

I traced every path a hostile peer can drive during a fresh sync:

| Path | Current behaviour | Verdict |
|---|---|---|
| Lies about height (huge) | Asked for headers. No reply: after 60 s its height is lowered. An empty reply lowers it at once. | OK (tested) |
| Serves a low-work free chain | Hashed and stored while our work is small (P1). | **Open (P1)** |
| Serves invalid PoW | Banned after ≤ 1 chunk. | OK (tested) |
| Serves unconnected single headers | No penalty. Triggers one `GetHeaders` (one outstanding per peer). | OK (bounded by the rate limit) |
| Serves an unconnected multi-header batch | +20, and `GetHeaders`. | OK |
| Withholds bodies | Fork choice uses body-complete chains (H1). The schedule re-picks the staller (P3). | **Open (P3)** |
| Rotates identities with full junk batches | Queue caps. FIFO HOL delays honest headers (P2). | **Open (P2)** |
| Serves a taller, lighter chain first | Best header = most work, so the honest chain wins as soon as one honest batch is processed. | OK after P2 (work ordering) |
| Serves a body mismatch or an invalid body | 100 points. | OK |
| Forces a RandomX cache build (unverified seed) | F07-4 on hosts with more than 65 threads. | **Open (W3)** |

**Recovery property (source-derived).** Suppose the node's header-best is a taller, lighter chain and honest peers are connected. The honest peers' next tip announcement is unconnected for us. That triggers `request_headers`; the honest reply from genesis passes the gate, and sync resumes. After a solicited `LowWork` reply from us, honest peers lower our claimed height to theirs, so they do announce to us. Recovery therefore takes at most about one honest block interval. **This deserves a regression test (T-G1)**, because it relies on three separate height-lowering rules staying in place.

---

## 4. New findings

| ID | Severity | Status | Location | Scenario | Confidence |
|---|---|---|---|---|---|
| **F31-1** (R1-C1 residual, risk 6, quantified) | **Medium** for a public testnet; **Low** for the 7-device trial | Not implemented (presync, `MIN_CHAIN_WORK`) | `p2p/src/net.rs:1648-1696` | A fresh node, or any node in its first 144 blocks: free difficulty-1 batches pass the gate. The damage is the attacker batches queued before the first honest one (≤ 144 batches in total, 2 per IP): about 2.7-4 h of 8-core RandomX and about 128k junk headers with 32 IPs. With no honest peer reachable: about 65-108 CPU-h and about 250 MB per chain-year of timestamp budget. | high (source + math); the costs are [M/A] |
| **F31-2** (R8-12 deepened) | **Medium** for a public testnet; Low for the trial | Not implemented | `net.rs:2013-2018` (candidates by `p.height`), `:2680-2691` (the timeout neither lowers height nor excludes the peer) | A block-withholding peer that relays honest tip headers is a download candidate with probability k/n and stalls each block for 60 s. It is re-picked after the timeout. IBD windows stall the same way. Side-branch bodies loop on NotFound. | high (source) |
| **F31-3** | **Medium** under F31-1, Low otherwise | Not implemented | `chain/src/manager.rs:1087-1125` | `missing_bodies` walks every heavier leaf in full, under the chain lock, at every scheduling call (≥ 4/s). Junk branches on a fresh node make this O(10^5) per call. | high (source) |
| **F31-4** (R8-15, deepened) | Medium | Not implemented | `net.rs:1524-1628` | FIFO worker: a tip announcement waits behind full batches (up to about 150 s each). Junk batches on a fresh node are processed before honest ones (this amplifies F31-1). | high (source) |
| **F31-5** | Low | Partially implemented (a heuristic) | `net.rs:1684-1695` | The density rule lets a fork at half our *historical* density through, one full batch per fork. That is cheap wherever the early difficulty was low. Each victim hashes and stores 2000 headers forever. | high (source + math) |
| **F31-6** | Low (test gap) | — | `p2p/tests/network.rs` `fast_config` (`allow_private = true`) | Every sync test disables the per-origin header-queue cap (`header_queue_room`), so the public-node configuration of the queue bound is untested. | high |
| **F31-7** | Informational (docs) | — | `docs/p2p.md:581-583`; `:249-250` | §12 says RandomX seed pinning "is in the consensus crate". It is not (it agrees with F07-10). §6 says bodies come "only from peers whose announced height covers them"; that is correct, but it should state the F31-2 limitation. §6 also describes the density rule as a design choice; it should note it as a heuristic to be replaced (F31-5). | high |
| **F31-8** (07's F07-4, owned here) | Low | Not implemented | `net.rs:1750` | `chunk = pow_threads` can exceed `seed_lag`, so a fake in-batch seed keys a cache build on hosts with more than 65 threads. | medium-high (07) |
| **F31-9** | Low | Not implemented | `net.rs:2716-2732` | During IBD, `GetHeaders` goes to every peer that is ahead, so up to 8 identical 2000-header replies arrive. Hashing is deduplicated, but bandwidth, pre-checks and queue slots are not. Bitcoin uses one headers-sync peer plus announcements. | high (source) |
| **F31-10** | Informational | — | `consensus/src/params.rs:41` | `TESTNET_GENESIS_TIME` = 2026-09-23 predates the launch. The free-fork timestamp budget (F31-1, F31-5) grows with (launch − genesis time). SX1 recommends a launch-time timestamp (owner 40). | high |

There are no Critical or High findings in my scope, and no consensus findings. Everything proposed below is policy: no testnet identity impact and no change to validity.

---

## 5. Implementation plan for phase 2

Order: P0 items (07-dependent and cheap), then the P1 structural items.

### S1 (P0, S): shared `worth_verifying` in `chain` (W2 prerequisite)

- **Files:**
  - new `chain/src/sync_policy.rs` (owner **31**);
  - `chain/src/lib.rs`: a one-line `pub mod` (coordinate with 02/35);
  - `p2p/src/net.rs`: remove the local copies and call the chain function (owner 31).
- **Externally visible:** nothing. The functions are identical.
- **Identity:** none.
- **Tests:**
  - unit tests of `anti_dos_threshold` and `worth_verifying`: the three cases, a height ≤ 144 and the genesis-only chain;
  - the existing p2p gate tests unchanged.
- **Docs:** `docs/p2p.md` §6 (where the rule lives).
- **Difficulty:** S.

### S2 (P0, S): W3 chunk cap (F31-8)

- **Files:** `p2p/src/net.rs:1750` (owner 31). The `pow_jobs` debug-assert is 07's.
- **Externally visible:** nothing.
- **Tests:** T9 (07) in `p2p/tests/network.rs` or a new `p2p/tests/sync_adversarial.rs`.
- **Difficulty:** S.

### S3 (P0, S): documentation and test-gap fixes (F31-6, F31-7)

- **Files:**
  - `docs/p2p.md` §6 and §12 (coordinate with 47);
  - a test variant with `allow_private = false` on a 127.0.0.x source spread. The harness `connect_from` already gives distinct loopback IPs. `ban_addr` exempts loopback only in `allow_private` mode, so check the ban side effects.
- **Test:** `the_header_queue_is_bounded_per_origin_on_a_public_node`.
- **Difficulty:** S.

### S4 (P0 as evidence, S): hostile-genesis-sync regression tests pinning today's behaviour

- **Files:** new `p2p/tests/sync_adversarial.rs` (owner 31).
- **Tests:**
  - **T-G1:** recovery from a taller, lighter header chain within one honest block.
  - **T-G2 (documents F31-1):** on a fresh node, a free branch *is* hashed today. Assert the current bound (≤ one batch per queued attacker identity when an honest peer is present). It is inverted when S7 lands.
  - **T-G3:** a lying-height peer causes no request loop.
- **Why P0:** the trial evidence needs to state the residual precisely, and these tests are the regression net for S5-S8.
- **Difficulty:** S-M.

### S5 (P1, M): header worker v2, with priority classes and chunk-boundary preemption (F31-4; supports F31-1)

- **Files:** `p2p/src/net.rs` (owner 31). The worker state machine goes in a new `p2p/src/header_queue.rs` (owner 31), sans-IO, so it can be unit-tested and fuzzed (41).
- **Externally visible:** ordering only. The verdicts are identical.
- **Tests:** T-H1, T-H2, T-H3; a property test "the multiset of stored headers equals the FIFO result"; the full existing p2p suite.
- **Benchmark:** tip-announcement latency under a 2000-batch load with `SlowCountingPow` (an `#[ignore]` timing test).
- **Docs:** `docs/p2p.md` §6 ("Where", "At most one batch"), and §12 (remove R8-15).
- **Difficulty:** M.

### S6 (P1, M): download scheduling v2: `best_known`, `tried`, stall detection, size-aware timeouts (F31-2)

- **Files:**
  - `p2p/src/net.rs` (owner 31);
  - `consensus/src/chain.rs`: add `pub fn is_ancestor(&self, ancestor: &Hash, of: &Hash) -> bool` (additive; owner 01/02 to review);
  - `chain/src/manager.rs`: a pass-through accessor (≤ 5 lines, coordinate with 02).
- **Externally visible:** peers that stall get disconnected (not banned). Manual peers are exempt.
- **Tests:** T-S1 through T-S5, plus a labnet chaos run with one withholding node (P1-15 of the consolidated plan).
- **Docs:** `docs/p2p.md` §6.4 and §10 (liveness), §12 (remove "fixed 60 s").
- **Difficulty:** M.

### S7 (P1 before any public testnet; P2 for the trial, M-L): RX-presync plus `MIN_CHAIN_WORK` (F31-1, F31-5)

- **Files:**
  - new `p2p/src/presync.rs` (owner 31): the `PresyncState`, sans-IO;
  - `p2p/src/net.rs` hooks in `verify_headers` and `header_worker` (owner 31);
  - `chain/src/sync_policy.rs` (from S1) gets `min_chain_work` in the threshold;
  - `consensus/src/chain.rs`: expose a `BranchContext` (the persistent LWMA/MTP overlay) and refactor `precheck_batch` to use it, so there is **one** rule path. Owner 01/02 reviews it, and the existing pre-check tests must stay green;
  - `node/src/config.rs`: `--min-chain-work` (with 36's or 40's owner of config);
  - a per-network default constant (placement: open question Q2).
- **Externally visible:** a presync progress log and RPC `/info` field ("pre-syncing headers", as Bitcoin). The double download is bandwidth only.
- **Identity:** none, provided `MIN_CHAIN_WORK` stays out of the fingerprinted `ChainParams` (Q2).
- **Tests:**
  - T-P1 to T-P5;
  - a property test (differential against the old path for honest chains);
  - the reservoir distribution test;
  - a fuzz target for `PresyncState` (41);
  - an adversarial review by 50 (the sampling argument, the RNG unpredictability, the abort paths).
- **Benchmark:** IBD of a synthetic 50k-header chain: the wall time and hash count of the old path against presync (expected overhead: s hashes plus redownload bandwidth).
- **Docs:**
  - `docs/p2p.md` §6 and §12 (the replaced "no minimum chain work" paragraph);
  - release procedure docs (how `MIN_CHAIN_WORK` is set; 40/43);
  - `docs/reviews/full-review` risk 6 status (47).
- **Difficulty:** L. The design needs 50's review before any code merges.

### S8 (P1, S): W6, the per-peer unpinned-build budget

- **Files:** `p2p/src/net.rs` (owner 31), using 07's `SeedCache` API (W1).
- **Test:** 3 branches with distinct seeds from one peer lead to 1 build.
- **Depends on** 07 W1.
- **Difficulty:** S.

### S9 (P1, S-M; owner 02, tests by 31): bound `missing_bodies` (F31-3)

- **Files:** `chain/src/manager.rs` (02).
- **Tests:** a differential test of old against new output, plus the complexity counter (above).
- **Difficulty:** S-M.

### S10 (P2, S): one headers-sync peer during IBD (F31-9)

- **Files:** `p2p/src/net.rs`.
- **Rule:** while `header_height` is more than one day behind wall-clock expectation, send `GetHeaders` to one sync peer (outbound preferred), rotating it on a headers timeout. Announcements from all peers are still processed (class 0).
- **Test:** a node with 4 serving peers receives ≤ 1 full batch per 2000 headers during IBD, and syncs when the sync peer disconnects mid-way.
- **Difficulty:** S.

### S11 (P3): compact blocks (BIP 152-like) and relay after PoW, before full validation

Out of my sync scope; a pointer for 30/33/45. A privacy constraint must be recorded: reconstruction uses the mempool only, **never the stempool** (R8 §3.6). There is no penalty for an invalid body behind a valid header in high-bandwidth mode (BIP 152 rule), and at most 3 high-bandwidth peers.

**Nothing in S1-S11 changes consensus.** S6 and S7 add additive, non-consensus accessors to `consensus/src/chain.rs`. They need 01's review, because that file is consensus code, even though validity is untouched.

---

## 6. Dependencies and conflicts

| Workstream | Relationship |
|---|---|
| **07 randomx-cache-seed** | W3 (S2) and W6 (S8) are in my file. W2 needs S1 (the shared predicate). S7's sample gate uses W1's `SeedCache` (grouping by seed; unpinned-build budget). |
| **36 rpc-security** | The `/block` handler calls `chain::sync_policy::worth_verifying` (S1). With presync, RPC blocks below the threshold are simply rejected. |
| **34 chain-actor-concurrency** | The header worker's short lock holds (intake classification, `pow_jobs`, `accept_headers`) become actor commands. S5's sans-IO queue should be designed so that it can be driven by the actor. The two designs must agree on "check, verify outside, re-check". |
| **02 fork-choice-reorgs** | Owns `missing_bodies` (S9) and reviews `is_ancestor` (S6). Presync must preserve the body-complete fork-choice semantics (headers only). |
| **01 consensus-core** | Reviews the `BranchContext` refactor (S7) and `is_ancestor` (S6). Their invariant: one rule function. |
| **03 difficulty-lwma** | Their simulator should check S7's height bound (2 × expected + 10k) against adversarial LWMA timestamp shaping and hash-rate surges, and the claimed-work inflation rate under the ~10× clamp. |
| **04 timestamps-mtp-ftl** | The presync abort on FTL, and clock skew (a node with a skewed clock aborts honest presyncs: warn). |
| **32 eclipse-addrman** | Stale-tip / chain-sync eviction (S6 part 6) is theirs, and I provide the `best_known` signal. F31-1's unbounded case (no honest peer reachable) is an eclipse problem. |
| **30 p2p-transport** | No protocol change is needed by S1-S10. A future "headers with body size" message (docs/p2p.md §6.4) would allow byte-exact windows. |
| **40 testnet-genesis** | F31-10 (the genesis timestamp). `MIN_CHAIN_WORK` release procedure. Fingerprint placement (Q2). |
| **41 fuzzing-property-stateful** | Fuzz targets for `PresyncState` and the header-queue state machine. The deterministic network simulation could host T-S1 and T-P1 at scale. |
| **47 docs-spec-consistency** | `docs/p2p.md` §6 and §12 edits (S3, S5-S7). |
| **50 red-team-integration** | Adversarial review of S7's sampling argument before merge. |

**File ownership I request:**

- owner: `p2p/src/net.rs` (sync paths: header worker, `verify_headers`, `schedule_downloads`, maintenance re-requests);
- new, owner: `p2p/src/presync.rs`, `p2p/src/header_queue.rs`, `chain/src/sync_policy.rs`, `p2p/tests/sync_adversarial.rs`.

Other agents touch `net.rs`: 32 (outbound/inbound), 33 (Dandelion and trickle) and 34 (actor). Please sequence the `net.rs` edits, or ask that each lands in separate functions and is rebased in order.

---

## 7. Open questions for the coordinator

1. **Q1 (priority):** do you accept S7 (presync) as P1 for the public testnet and P2 for the 7-device trial? At launch `MIN_CHAIN_WORK` = 0, so presync then protects only against deep forks (replacing the density rule). The fresh-node protection starts with the first release that sets a non-zero value.
2. **Q2 (placement):** where does `MIN_CHAIN_WORK` live?
   - (a) a p2p `SyncParams` per network plus `--min-chain-work` (my recommendation: no fingerprint impact); or
   - (b) `ChainParams`, which changes the fingerprint at every release that updates it.
3. **Q3 (sampling parameter):** s = 32 samples, with early exit and grouping by seed. Do you want 50 to review the probabilistic argument before implementation, or after a prototype with tests?
4. **Q4 (design choice):** after the sample gate passes, redownloaded headers are stored as they are verified, with no Bitcoin-style release buffer. Accept this, or require the buffer (more code, a stronger conservative match with Bitcoin)?
5. **Q5 (stallers):** disconnecting stallers is the only new "punishment" (no ban, manual peers exempt). Acceptable for the trial mesh, or should S6 be observe-only (log and deprioritize) during the trial?
6. **Q6:** should `net.rs` be split (R16 Stage C) before phase-2 implementation? Four workstreams edit it. A split into `sync.rs`, `relay.rs` and `conn.rs` along the lines of the current sections would reduce conflicts, at the cost of one large mechanical diff first.
7. **Q7:** assume-valid PoW for IBD (R8 §3.6, P3-13). It is out of scope here and is a trust-in-release decision. Should it stay deferred until after the trial?

---

## 8. Sources

**Primary: Bitcoin Core**

- PR #25717, "p2p: Implement anti-DoS headers sync" (merged 2022-08-30): https://github.com/bitcoin/bitcoin/pull/25717
- `src/headerssync.cpp`, the `HeadersSyncState` (commitments, max-commitments bound from MTP, REDOWNLOAD release): https://github.com/bitcoin/bitcoin/blob/master/src/headerssync.cpp
- `src/net_processing.cpp`: `CheckHeadersPoW`, `TryLowWorkHeadersSync`, `GetAntiDoSWorkThreshold`, `m_stalling_since`, `BLOCK_STALLING_TIMEOUT_DEFAULT`/`_MAX`, `BLOCK_DOWNLOAD_TIMEOUT_*`, `HEADERS_DOWNLOAD_TIMEOUT_*`, `CHAIN_SYNC_TIMEOUT`, `STALE_CHECK_INTERVAL`, `BLOCK_DOWNLOAD_WINDOW`, `MAX_BLOCKS_IN_TRANSIT_PER_PEER`: https://github.com/bitcoin/bitcoin/blob/master/src/net_processing.cpp
- `src/kernel/chainparams.cpp` (the per-release `HeadersSyncParams` and `nMinimumChainWork`): https://github.com/bitcoin/bitcoin/blob/master/src/kernel/chainparams.cpp
- PR #31978, the pre-29.x chainparams and headerssync update: https://github.com/bitcoin/bitcoin/pull/31978
- PR #33274, the chainparams and headersync updates for 30.0: https://github.com/bitcoin/bitcoin/pull/33274
- PR #31649, "consensus: Remove checkpoints (take 2)": https://github.com/bitcoin/bitcoin/pull/31649
- The same change in Bitcoin Optech Newsletter #346: https://bitcoinops.org/en/newsletters/2025/03/21/
- CVE-2019-25220, "Memory DoS due to headers spam" (disclosed 2024-09-18): https://bitcoincore.org/en/2024/09/18/disclose-headers-oom/
- PR #25880, "p2p: Make stalling timeout adaptive during IBD": https://github.com/bitcoin/bitcoin/pull/25880
- The #25880 review club notes: https://bitcoincore.reviews/25880
- PR Review Club #32051, "Protect addnode peers during IBD": https://bitcoincore.reviews/32051

**Primary: BIPs**

- BIP 130, "sendheaders message": https://github.com/bitcoin/bips/blob/master/bip-0130.mediawiki
- BIP 152, "Compact Block Relay" (high- and low-bandwidth modes; do not ban for an invalid block with a valid header; at most 3 high-bandwidth peers; SipHash short ids): https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki

**Primary: Monero**

- `src/cryptonote_protocol/cryptonote_protocol_handler.inl`: `IDLE_PEER_KICK_TIME`, `NON_RESPONSIVE_PEER_KICK_TIME`, `REQUEST_NEXT_SCHEDULED_SPAN_THRESHOLD`, `DROP_ON_SYNC_WEDGE_THRESHOLD`, `kick_idle_peers`, `update_sync_search`: https://github.com/monero-project/monero/blob/master/src/cryptonote_protocol/cryptonote_protocol_handler.inl
- `src/checkpoints/checkpoints.cpp` (hard-coded checkpoints; the fast-sync hash list): https://github.com/monero-project/monero/tree/master/src/checkpoints
- Monero issue #8834 (sync flags and checkpoint-presumed validity, context for `--fast-block-sync`): https://github.com/monero-project/monero/issues/8834
- The alt-block seed DoS fix, PR #11238, is cited via 07's dossier: https://github.com/monero-project/monero/pull/11238

**Academic**

- B. Bünz, L. Kiffer, L. Luu, M. Zamani, "FlyClient: Super-Light Clients for Cryptocurrencies", IEEE S&P 2020; IACR ePrint 2019/226: https://eprint.iacr.org/2019/226
- P. S. Efraimidis, P. G. Spirakis, "Weighted random sampling with a reservoir", Information Processing Letters 97(5), 2006: https://doi.org/10.1016/j.ipl.2005.11.003
- E. Heilman, A. Kendler, A. Zohar, S. Goldberg, "Eclipse Attacks on Bitcoin's Peer-to-Peer Network", USENIX Security 2015 (context for F31-1's no-honest-peer case; 32's scope): https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/heilman

**Internal**

- `docs/reviews/full-review-2026-09-27/R8-p2p.md` (§2.8, §2.12, §2.15, §3.6)
- `SX1-core-crossreview.md` (R1-C1)
- `SX2-systems-crossreview.md`
- `C:/bszkeval/p2/research/07-randomx-cache-seed.md`
- `C:/bszkeval/p2/decisions.md`
