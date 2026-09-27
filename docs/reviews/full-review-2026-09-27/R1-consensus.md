# R1 — Consensus review (internal review, not an audit)

- **Reviewer:** R1 (consensus)
- **Date:** 2026-09-27
- **Tree:** `rebuild/core` at `f677e55`. The WIP commit `7826289` is included.
- **Method:** read-only source reading of the files listed below, plus arithmetic on the consensus formulas. Web sources were used for comparison. No builds were run and no tests were executed by me: every "tested" tag names an existing test I read, not a run I made.
- **Scope, code:**
  - `consensus/src/*`;
  - `chain/src/{block.rs, manager.rs, emission.rs}`;
  - `tx/src/validate.rs` (the block path) and `tx/src/state.rs`;
  - `px/src/state.rs`;
  - p2p call sites where consensus verdicts are consumed (`p2p/src/net.rs` 993–1210).
- **Scope, specs:** `docs/consensus.md`, `docs/blocks.md`, `docs/reviews/k4-reorg-policy.md`, `docs/reviews/assumptions.md`.

**Evidence tags:**
- **[math]**: mathematically established;
- **[test: name]**: covered by the named existing test;
- **[src]**: source-read;
- **[assumed]**;
- **[unknown]**.

---

## 0. Executive summary

The consensus core is small, readable and mostly well built.
- One crate defines the header rules. The node and the miner both use it.
- Validation is branch-local. A single `check_rules` is shared by sequential validation and by the batch pre-check.
- The main consensus pieces are Monero-equivalent where they should be:
  - `check_hash`;
  - the seed schedule;
  - the emission formula;
  - the implicit coinbase commitment `G + a·H`.
- The Merkle tree is domain-separated and has no CVE-2012-2459 duplication.
- B3 (the coinbase amount) is exact, and the reward depends on height only.
- Tx ids commit to every byte, so a body cannot be malleated to get an honest block marked invalid.

I found **no consensus-rule bug** that would let an invalid block be accepted or a valid block be rejected on 64-bit platforms.

The serious problems are at the boundary between consensus and resource policy, and in the security model:

1. **R1-C1 (HIGH, deepens a known item).** Low-work forks are not just "cheap". Once a fork reaches difficulty 1 they cost **nothing**, because LWMA floors at 1 and `check_hash(_, 1)` accepts every hash.
   - Branches can be made arbitrarily wide by varying the nonce.
   - These headers are *valid*, so no peer is ever penalized for them.
   - Each one costs every victim one light RandomX hash (~0.75 s).
   - They also enable unlimited distinct RandomX **seeds** (256 MiB cache rebuilds under a global lock), header-worker starvation (a stall of honest sync), and persisted plus RAM-resident side-branch bodies.
   - The fix is policy only: gate on the *claimed* work, which the pre-check already computes before any PoW. This is Bitcoin Core's anti-DoS threshold ([PR #25717](https://github.com/bitcoin/bitcoin/pull/25717)).
   - Make sure the A8 fix covers all four effects.
2. **R1-C2 (HIGH for the security model).** The PoW is standard Monero RandomX (salt `RandomX\x03`).
   - Reference or JIT miners (xmrig) are ~50–100× faster per core than the project's safe-Rust miner.
   - Under the project's own policy (no unsafe code, no FFI) the official miner can never close the JIT gap.
   - So K1 ("honest majority") does not hold on the testnet against anyone who runs a stock RandomX miner, or who rents RandomX hash power.
   - Accept this explicitly for the testnet. Take a mainnet decision on it.
3. Several medium or low items: an unverified LWMA timestamp-shaping bound, silent stalls from clock skew, `accept_headers` skipping `sync_state` on partial failure, a 32-bit decode divergence, stale spec statements, and no forward-compatibility for header versions or network upgrades.

**Testnet verdict (consensus layer only):** acceptable for a controlled testnet once the in-progress items are done:
- the R1-C1 gating (A8);
- the H1 fix;
- the M1 v3 genesis.

R1-C2 must also be written down as an accepted limitation. **Not** acceptable for mainnet without decisions on R1-C2, reorg finality, upgrades, and minimum chain work (§4).

---

## 1. What I checked and found correct

| # | Item | Verdict | Evidence |
|---|---|---|---|
| V1 | `check_hash`: `h·d < 2^256`. The limb loop never overflows u128: `v·d + carry ≤ (2^64−1)^2 + 2^64−1 < 2^128`. The final carry is exactly the bits ≥ 2^256. `d = 0` is rejected. This is Monero's semantics. | Complete and verified | [math], [test: `pow::check_hash_boundaries`] |
| V2 | `seed_height` equals Monero's `rx_seedheight` (E=2048, L=64). The seed is looked up on the header's own branch (`ancestor_id`). | Complete and verified | [test: `seed_schedule_matches_monero`, `seed_is_taken_from_the_headers_own_branch`, `the_randomx_key_switch_works_across_sync_restart_and_reorg` (short epoch only)] |
| V3 | Header: fixed 100 bytes, strict length, and the id is domain-separated and bound to the network id. | Complete and verified | [test: `roundtrip_and_layout`, `strict_length`, `id_commits_to_every_field_and_network`] |
| V4 | Merkle root: leaf/node prefixes, odd node carried up, no duplication malleability. The shapes are injective under Blake2b collision resistance. | Complete and verified | [math], [test: `merkle::*`] |
| V5 | LWMA-1: matches zawy's reference loop (monotone `prev+1`, 6T cap, `L ≥ N²T/20`, short early window). Integer bounds hold: `S·T·(n+1) ≤ 61·2^64·120·61 < 2^84`. | Complete and verified (arithmetic); behaviour see R1-C8 | [math], [test: `difficulty::*`] |
| V6 | MTP (lower median of 11, strict). FTL is non-permanent and never stored. A rejected header is not cached, so it is re-evaluated later. | Complete and verified | [test: `mtp_is_strict`, `rejects_each_invalid_field`] |
| V7 | `precheck_batch` reaches the same verdict as sequential `validate` at every window position, with zero PoW. | Complete and verified | [test: `precheck_agrees_with_sequential_validation_and_computes_no_pow`] |
| V8 | Fork choice: strictly more cumulative work wins; ties go to first seen (`accept`: `>`, `mark_invalid`: `seq`). `mark_invalid` propagates to every descendant and re-selects. | Complete and verified | [test: `heavier_fork_reorgs_and_lighter_fork_does_not`, `invalidating_a_block_falls_back_to_best_remaining_branch`, `verdicts_do_not_depend_on_arrival_order`] |
| V9 | Body/header binding: the tx id is `H(prefix‖base‖prunable)`, and together these cover every encoded byte (`types.rs:432-448`). Decoding is canonical. So a matching `tx_root` fixes the body, and a failed body is an intrinsic property of the header. A peer cannot get an honest block invalidated with a malleated body. | Complete and verified | [src] `types.rs:253-274,432`; [test: `body_must_match_header`, `mempool_contents_never_change_a_blocks_verdict`] |
| V10 | Emission: `reward(h, G(h))` depends on height only, so side-branch templates are correct (`manager.rs:668`). Saturating at M; tail 0.6 BLK. | Complete and verified | [test: `first_rewards`, `curve_matches_spec`, `reward_is_monotone_non_increasing`, `emission_is_enforced_exactly`] |
| V11 | B3 exact equality (`coinbase.total() == reward + Σfee`, u128). The coinbase commitment is implicit `G + a·H`, so no coinbase commitment can hide inflation. | Complete and verified | [src] `validate.rs:802-809`, `types.rs:115`; [test: `emission_is_enforced_exactly`] |
| V12 | State undo is symmetric in `MemoryChain::undo_block` (outputs, one-time keys, key images, PX frontier/roots/pool/nullifiers, registry, logs). C4/C2 uniqueness makes set removal safe. | Complete but requires further testing (deep PX reorgs are tested shallow only; K4 §7) | [src] `tx/src/state.rs:221-243`, `px/src/state.rs:100-157`; [test: `restart_rebuilds_the_px_state_exactly`, `transactions_survive_reorgs_via_the_mempool`] |
| V13 | Block-level PX rules are consistent between validation and apply: the anchor is "end of earlier block" in both places, nullifiers are unique per block and per chain, and the pool evolves in block order. | Complete and verified except TreeFull (known) | [src] `validate.rs:414-432,843-873`, `px/src/state.rs:117-147` |
| V14 | The implicit consensus decode limits (`MAX_BLOCK_BYTES`, `MAX_BLOCK_TXS`) cannot reject a block that is valid under the weight and PX budgets. The v1 bytes are at most the weight (600 000), plus 8 MiB PX, plus ≤ 30 KB framing, which is below the cap. | Complete and verified | [math] |
| V15 | No peer-time clock adjustment exists: the local clock only (`node/src/lib.rs:60`). | As specified (see R1-C9) | [src] |
| V16 | `pow_jobs` seed derivation is sound. The header bytes (`prev_id`, `height`) determine the seed. A batch whose `first.height` is wrong fails BadHeight before its cached hash is ever consulted. | Complete and verified (fragile, see R1-C5) | [src] `manager.rs:590-614`; [test: `pow_jobs_use_seeds_from_the_batch`] |

---

## 2. Findings

### R1-C1: Difficulty-1 forks give unlimited, zero-cost, *valid* headers
- **Severity:** HIGH (remote, unauthenticated, zero-cost DoS and sync stall of every node).
- **Classification:** Partially implemented (anti-DoS policy).
- **Confidence:** high on the mechanics, [math]+[src]. The end-to-end effect is untested.
- **Relation to known items:** deepens "low-work header batches are hashed and stored (no minimum chain work)".

**Mechanics:**
1. **Descent is cheap.** From any old block, an attacker's fork uses timestamps 720 s (6T) apart, which the time elapsed since that block allows.
   - LWMA then gives `next ≈ avg_D/6` per window (`difficulty.rs:28-41`).
   - From the testnet genesis (D0 = 100, and the genesis time is already in the past) the fork reaches D = 1 within about two windows, for about 100 hashes in total.
   - From a main-chain block of difficulty D it takes about log₆(D) windows and roughly 70·D hashes.
   - With a stock RandomX miner (R1-C2) that is minutes.
2. **D = 1 is free.** `check_hash(h, 1)` is true for every h (`pow.rs:9-21`, test `check_hash_boundaries`). The clamp `next.clamp(1, …)` (`difficulty.rs:42`) keeps the fork at 1 as long as its weighted mean solve time is above T/2.
   - The derivation: `next = 219 600/L < 2` requires `L > 109 800`, which means an average spacing above 60 s.
   - **Depth budget:** about (chain age)/61 s headers.
   - **Width:** unbounded. Any nonce or `tx_root` variant at any height is a new valid header.
3. **No penalty.** These headers pass every rule, so the peer is never scored (`net.rs:1087-1122`).
   - The node even *pulls* them: after a tip announcement it asks for headers, and a full batch of 2000 triggers the next request (`net.rs:1022-1027`).
   - Messages carry heights, not work, so the node cannot gate on work before it hashes (`p2p/src/message.rs`; there is no "work" field).
4. **Cost to victims, per header:**
   - one light RandomX hash (~0.75 s per thread, measured);
   - an entry in `HeaderChain.entries`/`children` and in `CachedPow.known` (both unbounded).
   - `mark_invalid` scans every entry (`chain.rs:529-535`), so any later body failure costs O(all entries).
5. **Worker starvation.**
   - There is one global header worker (`net.rs:1001`), and one attacker batch of 2000 is about 190 s of 8-thread hashing.
   - Honest batches queue behind it. The effect is a sync and propagation **liveness** failure, not only CPU.
6. **Seed-cache thrash (amplifier).**
   - A free fork from genesis that is 2113 blocks deep costs about 36 h of timestamp budget. It can have unlimited distinct blocks at height 2048, and so unlimited distinct RandomX seeds.
   - Each header at seed height + 65 on such a branch forces `Cache::new` (Argon2d over 256 MiB).
   - The build runs *while holding the global cache mutex* (`pow.rs:55-70`) and evicts one of only 2 slots, **including the honest chain's cache**.
7. **Bodies.**
   - `submit_inner` persists a block to disk and keeps its body in the `bodies` RAM map **before** checking whether its branch has any work (`manager.rs:352-362`).
   - An unsolicited block costs the sender only 10 points (`limits.rs:17`), so each peer identity can deliver about 10 blocks of up to ~9 MB before a ban.
   - Bans are exact-IP only (N-5), and all Tor inbound peers are 127.0.0.1 (N-6).

**Scenario.**
1. An attacker on a laptop mines 100 hashes on a fork from the testnet genesis.
2. It announces the fork tip to every node.
3. Each node's header worker hashes 2000-header batches of free headers indefinitely, and honest blocks stop propagating through it.

**Recommendation R1-C1 (policy; no consensus change):**
- **Gate before hashing.** After `precheck_batch`, the cumulative work the batch *claims* is known exactly: the overlay's last `cumulative`, from checked `difficulty` fields, with no PoW. Hash and store a batch only if one of these holds:
  - (a) it extends the current best tip;
  - (b) its claimed tip work is at least `anti_dos_threshold = max(best_work − work(last 144 main blocks), MIN_CHAIN_WORK)`, as in Bitcoin Core's `GetAntiDoSWorkThreshold` ([PR #25717](https://github.com/bitcoin/bitcoin/pull/25717); [CVE-2019-25220](https://bitcoincore.org/en/2024/09/18/disclose-headers-oom/)).
- **Deeper forks** (a partition longer than about 144 blocks) need a presync: download without storing, keep a running claimed-work sum plus a commitment, then re-download once the threshold is cleared. A simpler first step: announce cumulative work in the handshake and tip messages, and presync only peers whose claim beats ours. Ban a peer whose delivered claim falls short.
- **Claimed but unproven work cannot be abused.** Every stored header still passes PoW, and the first failure bans the peer (INVALID_HEADER = 100). So the victim's cost per attacker identity is bounded by one chunk of `pow_threads` hashes.
- **Bodies:** do not persist or keep bodies of branches below the threshold. Download bodies only for the best chain, as today.
- **Seed cache:**
  - pin the best-chain seed(s) so they are never evicted by side-branch work;
  - build caches outside the mutex, with a per-seed once-cell;
  - cap cache builds per peer.
- Bound `HeaderChain` and `CachedPow` growth, by pruning or refusing side branches below the threshold.

| Field | Assessment |
|---|---|
| Why needed | Zero-cost stall of every node |
| Security impact | Removes the free-header, seed-thrash and body-fill vectors |
| Privacy impact | None directly. It reduces how easily an attacker can partition or eclipse a node. |
| Performance impact | Positive: no hashing of junk work |
| Complexity | Moderate. The threshold check is small; a presync is larger. |
| Consensus impact | none. Policy only: validity rules are unchanged, only which headers are evaluated. |
| Testnet identity impact | none |
| Implementation difficulty | M (threshold plus pinning), L (full presync) |
| Priority | **P0.** The threshold, body gating and seed pinning are needed before the testnet. A full presync is P2. |

**Tests to add:**
- a fork from genesis driven to D = 1, then 10 000 free headers: the node computes ≤ `pow_threads` hashes and keeps its honest tip;
- a seed-thrash case: the best-chain cache is never evicted.

---

### R1-C2: Standard RandomX plus a safe-Rust-only miner means the honest majority (K1) is not attainable on the testnet
- **Severity:** HIGH for the security model (mainnet decision). Accepted limitation for the testnet.
- **Classification:** Accepted limitation (testnet); decision required (mainnet).
- **Confidence:** high [src] on the parameters; the measured speed ratio comes from the brief.

**Evidence:**
- `randomx/src/config.rs:4-7` uses Monero's exact parameters (`ARGON_SALT = b"RandomX\x03"`, Argon2 256 MiB × 3). The brief confirms that the 5 official vectors pass.
- Measured: the project's miner does ~100 ms per hash per thread in full mode; reference RandomX with JIT does ~1 ms.

**Consequences:**
- A single operator running xmrig or the reference library outmines a testnet of honest official miners by 50–100× per core. Only a trivial adapter is needed: a 100-byte blob, key = seed id.
- RandomX hash power can also be rented on hash-rental markets [assumed: RandomX is listed on public rental markets], or redirected from Monero.
- K1 therefore fails trivially. This enables:
  - deep reorgs (K4 has no limit);
  - selfish mining, which is profitable above ~1/3 with first-seen ties;
  - timestamp shaping (R1-C8);
  - capture of emission before the launch (M1).
- **The structural point:** under "no unsafe, no FFI", the official miner is an interpreter. A JIT needs executable memory, and so `unsafe`. A well-optimized safe-Rust interpreter might gain around 5–10× [assumed; reference interpreter vs JIT], but the policy **guarantees a permanent disadvantage for miners who follow it**. This has to be an explicit owner decision, not an accident.

**Recommendations:**
- **Testnet:**
  - document the limitation in `assumptions.md` K1 and in `testnet.md`: anyone with a stock RandomX miner controls the chain;
  - optionally run a project-operated "anchor" miner, knowing that it is centralizing;
  - set the v3 D0 from the measured honest hash rate.
  - Consensus: none. Identity: no. Difficulty: S. Priority: P0 (documentation only).
- **Mainnet decision (P3, owner):**
  - (a) keep standard RandomX. This gives the largest pool of CPUs that can mine it, but also rentable attack power and Monero miners as attackers.
  - (b) use a project-specific RandomX variant: a different salt and/or program parameters, as Wownero and other CryptoNote coins have done. This stops direct rental and reuse of rx/0 without changes, but not a determined attacker. It also invalidates the official vectors, so new known-answer vectors must be produced with the reference implementation, in test tooling only.
  - (c) allow a separately reviewed, optional JIT miner outside the consensus crates. The policy question is whether the no-unsafe rule covers the miner.
  - Consensus: CONSENSUS for (b). Identity: yes for (b). Difficulty: M.

---

### R1-C3: The PoW verification cost limits sync, and rejected-PoW headers are not remembered
- **Severity:** MEDIUM.
- **Classification:** Partially implemented.
- **Confidence:** high. The arithmetic uses the measured 0.75 s light hash.
- **Relation to known items:** deepens "far slower than reference".

**Scaling:**
- A year of chain is 262 800 headers × 0.75 s ≈ 55 CPU-hours, or about 7 h per chain-year of initial sync on 8 threads. That is for headers alone, before PX-F3 body replay.
- A full-mode dataset does not help much. The dataset rebuild takes 179 s on 8 threads per 2048-block epoch, 128 epochs a year, about 6.4 h a year. That is about the same.
- Monero verifies with light-mode reference hashes that are ~20–40× cheaper [assumed], and it skips verification below embedded hashes (`--fast-block-sync`, on by default; [monerod reference](https://docs.getmonero.org/interacting/monerod-reference/)).

**Replay of rejected headers:** a header that fails `InsufficientWork` is not recorded (`chain.rs:442-460`; `Duplicate` covers only stored headers). The same bad header can be replayed by each new identity, at one light hash per identity.

**Recommendations:**
- (a) a bounded "recently rejected header ids" LRU, as Bitcoin's `m_recent_rejects` does. Policy, S, P2.
- (b) faster light-mode hashing (tracked).
- (c) for mainnet, a release-embedded hash list for fast sync, Monero-style. This trusts the release exactly as much as the binary is already trusted, and it can be disabled. Policy, M, P3.
- Consensus: none. Identity: no.

---

### R1-C4: `accept_headers` returns on the first error without running `sync_state`
- **Severity:** LOW.
- **Classification:** Complete but requires further testing.
- **Confidence:** high [src].
- **Location:** `chain/src/manager.rs:643`. The `?` exits before `if new > 0 { self.sync_state(); }` at 647-649.

**Scenario:**
1. A batch of which the first k headers are valid and header k+1 is invalid is accepted in part.
2. The header best chain may have switched to a stored side branch whose bodies are all present.
3. The connected state does not follow until the next unrelated event (a block, a header or a template), so the module invariant is broken in the meantime.
4. A miner meanwhile keeps building on the stale connected tip.

**Fix:** run `sync_state` whenever `new > 0`, on both paths, for example with an inner closure. Add a test: a partial batch that makes a body-complete side branch best must reorganize immediately. Consensus: none. Difficulty: S. Priority: P2.

---

### R1-C5: The PoW cache is keyed by header bytes only
- **Severity:** LOW.
- **Classification:** Complete and verified (sound today), fragile.
- **Confidence:** high.
- **Location:** `manager.rs:48-53`.

**Why it is fragile:** the cache is sound only because `pow_jobs` derives the same seed as `HeaderChain::seed_id_for` (V16).
- A future refactor that computes a seed differently, for example with a pre-built next-epoch dataset or another seed source, would poison the cache.
- `validate` would then trust a hash computed under the wrong key. That is a silent consensus divergence.
- The cache is also unbounded (R1-C1).

**Fix:** key the cache by `H(tag ‖ seed ‖ header_bytes)`, bound it, and drop entries once a header is stored. Consensus: none. Difficulty: S. Priority: P2.

---

### R1-C6: A platform-dependent block decode on 32-bit targets
- **Severity:** LOW (no 32-bit target is supported today).
- **Classification:** Accepted limitation, but undocumented.
- **Confidence:** high [src].
- **Location:** `chain/src/block.rs:66`, `let len = r.varint()? as usize;`.

**Scenario:** on a 32-bit build, a length prefix of `2^32 + k` truncates to `k`, and `Block::decode` can accept bytes that a 64-bit node rejects. That is a different verdict on the same block. RandomX full mode is impractical on 32-bit, but light-mode validation (which is what nodes use) is not.

**Fix:** use `usize::try_from(len)`, which fails as `Framing`, and add a `compile_error!` for `target_pointer_width != "64"` in the consensus, tx and chain crates, so the supported platforms are explicit. Consensus: none on 64-bit. Difficulty: S. Priority: P2.

---

### R1-C7: LWMA omits zawy's 99/100 bias factor
- **Severity:** INFO.
- **Classification:** Accepted limitation.
- **Confidence:** medium.

zawy's LWMA-1 computes `next_D = S·T·(N+1)·99 / (100·2·L)` ([zawy12 issue #3](https://github.com/zawy12/difficulty-algorithms/issues/3)). The code (`difficulty.rs:41`) and the spec (§4) omit the 99/100.
- The test `steady_state_is_stable` accepts ±2%.
- The expected effect is block times about 1% longer than T, which stretches the emission schedule by about 1%.

**Do not change this:** it is consensus, and the benefit is negligible. Record it in consensus.md §4 as a deliberate deviation. Consensus: none (docs only). Priority: P3.

---

### R1-C8: The bound on LWMA timestamp shaping is unverified for a >50% (or private-chain) miner
- **Severity:** MEDIUM (emission and fairness; needs a majority).
- **Classification:** Complete but requires further testing.
- **Confidence:** medium on the example [math]; [unknown] on sustained gain.

**What is already sound:** the monotone rule plus the 6T cap makes the sum of counted solve times at most the real span plus FTL. The Bitcoin-style timewarp, which exploits the gaps between retarget windows, does not exist in a sliding window.

**What can still be shaped:** the *linear weights*.
- Worked example: 50 blocks bunched at 1 s, then 10 blocks at 720 s. That is a 7 250 s span, which fits real time at T plus FTL.
- It gives `L = 720·555 + 1 275 = 400 875` against 219 600 for honest timestamps, so the next difficulty is **0.55·D**.
- As the bunched blocks move into the high weights, difficulty rises again (up to the 10× floor). Whether the cycle yields a *net* gain in blocks per unit of time is **unknown**.

**Fix:**
- Add an adversarial simulation test: a majority miner with strategy search (bunch/jump cycles and FTL-edge timestamps), measuring blocks per real hour against 30. Assert that the gain is ≤ 5%, or document the measured gain.
- Run the same harness for ASERT (see §4.1) before mainnet.
- Consensus: none (tests). Difficulty: M. Priority: P2.

---

### R1-C9: A 360 s FTL with no clock-skew detection lets a node stall silently
- **Severity:** MEDIUM (liveness and operations).
- **Classification:** Partially implemented.
- **Confidence:** high [src].
- **Relation to known items:** deepens K3.

**Scenario, slow clock:**
1. A node's clock is more than 6 minutes slow.
2. Every fresh tip header is `TimestampTooFarInFuture`. That is correctly non-permanent and unpenalized (`net.rs:1102,1189`).
3. But each *new* tip is also in the future for this node, so it stays behind for as long as the skew lasts.
4. Nothing in the logs says why.

**Scenario, fast clock:** a miner whose clock is more than 6 minutes fast has its blocks rejected network-wide until the network's time catches up. This wastes its work and creates short forks.
- The 360 s FTL is deliberately tight (LWMA guidance: `FTL = N·T/20`), which is 20× tighter than Monero's or Bitcoin's 2 h. That is right for LWMA, but it makes clock hygiene a liveness requirement.

**Fix (policy, never adjusting time):**
- keep a per-peer offset estimate from the handshake time;
- log a WARN when the median offset is above FTL/3, or when more than N consecutive tip headers are rejected as future;
- the miner warns when `now < template.min_timestamp − 60`;
- add NTP to the operator checklist.
- Consensus: none. Difficulty: S. Priority: P2. (Upgrade it to P1 if the testnet has many home-operated nodes.)

---

### R1-C10: No forward path for header or tx versions; unknown versions get peers banned
- **Severity:** LOW now; it matters at the first upgrade.
- **Classification:** Not implemented.
- **Confidence:** high.
- **Location:** `chain.rs:301`, `header.version != HEADER_VERSION` is `BadVersion`, which is permanent and scores INVALID_HEADER = 100, an immediate ban.

**Consequence:** after any future upgrade, un-upgraded nodes ban every upgraded peer. That speeds up the partition, and operators get no "upgrade required" signal.

**Fix:**
- A version above the current one should be non-permanent, with no ban and a prominent WARN ("peers are on a newer consensus version").
- Add an `upgrades: &[(activation_height, header_version, branch_id)]` table to `ChainParams`, and require `header.version == version_at(height)`. See §4.4.
- Consensus: CONSENSUS if the table rule is adopted (a no-op today with one entry). Identity: no, if introduced as a no-op. Difficulty: S–M. Priority: P3 (the policy half is P2).

---

### R1-C11: Spec statements that no longer match the code
- **Severity:** INFO. Pass these to A16b.
- **Classification:** Partially implemented (docs).

The stale statements:
- `consensus.md` §3 says "The PoW hash is **not** stored anywhere: every verifier recomputes it." In fact the store persists `pow_hash`, and replay trusts it (`blocks.md` §8; `manager.rs:211`).
- `consensus.md` §10 and `blocks.md` §8 say "0.45 s per header". The measured figure is ~0.75 s under load.
- `consensus.md` §8 says "The node applies it atomically to transaction state". In fact bodies are connected block by block. A mid-branch failure leaves a partly connected branch, which the next loop iteration re-selects from (`manager.rs:385-475`). This is correct but not atomic.
- `consensus.md` §5 says "Nodes must not adjust their clocks from peer time by more than FTL/2". Nodes do not adjust at all; say so.
- `consensus.md` §3.1 gives a cache cost of "about 0.6 s". This is unverified for the pure-Rust Argon2 fill. Measure it or remove it.

---

### R1-C12: A verifier panic permanently invalidates a block
- **Severity:** INFO.
- **Classification:** Accepted limitation.
- **Confidence:** medium.

`VerifierPanicked` becomes `PxProof`, which leads to `mark_invalid` (`validate.rs:456-470`, `manager.rs:462-468`).
- If a *valid* proof ever panics on one platform or build (overflow checks, a stack difference), that node permanently rejects the block, even after a restart, because replay reproduces the rejection. That is a node-local split.
- Allocation failure aborts rather than panics, so OOM is a crash, not a split.

Keep this behaviour, because treating a panic as "unknown" would let crafted proofs stall nodes. But:
- log panics at ERROR with the block id;
- add a `--reconsider-block <id>` operator command, like Bitcoin's `reconsiderblock`;
- run the PX verifier in overflow-checked CI (the CI gap is known).
- Consensus: none. Difficulty: S. Priority: P3.

---

### Confirmations of known items (nothing new)

- **H1** (withheld body):
  - Confirmed at `manager.rs:393-409`. `reachable` walks only the best header chain, so blocks on the connected branch can never be connected while a heavier body-less branch exists.
  - The fix must also cover `missing_bodies` (best chain only, `manager.rs:570`) and `mark_invalid`'s best-tip selection (`chain.rs:529`). Both still choose among body-less tips.
- **Deep reorgs and ring references:** outputs are referenced by global index, so a reorg deeper than `SPENDABLE_AGE = 10` (and than `COINBASE_MATURITY = 60` for coinbase outputs) can invalidate honest transfers. This is covered by k4-reorg-policy.md §2 and is the same in Monero.
- **TreeFull:** `MemoryChain::apply_block` panics (`tx/src/state.rs:205-207`) if it is ever reached. The effect would be *every* node crashing at the same height, a global halt. Unreachable at this tree depth; keep it on the list.
- **Replay tie-breaks and `seq`** after a restart: known, being fixed.

---

## 3. The 13 questions per subsystem

### 3.1 Header format and serialization
1. **Implemented:** a 100-byte LE header, a strict decode, the id `H("BlackSilk/block-id"‖nid‖bytes)`, and `NONCE_OFFSET` = 92.
2. **Correct:** everything consensus-relevant is committed (height, difficulty). Network separation is in the id.
3. **Incomplete:** there is no upgrade or activation mechanism (R1-C10).
4. **Fragile:** the version check bans peers on a future version.
5. **Exploitable:** nothing found.
6. **Inefficient:** no.
7. **Does not scale:** the nonce is u64 and there is no extra-nonce. Pools must vary coinbase keys. That is fine, and better for privacy, because there are no pool tags.
8. **Missing:** an `upgrades` table.
9. **Redesign:** none.
10. **Innovate:** a branch id in the signature message (ZIP-200 style), §4.4.
11. **Before testnet:** nothing.
12. **Defer:** R1-C10.
13. **Never change:** the layout, the offsets, the id domain tag, and the network-id binding.

### 3.2 PoW verification and seed schedule
1. **Implemented:** RandomX light verify, a 2-slot cache, the Monero seed schedule on the header's own branch, the `CachedPow` precompute, and replay trusting stored hashes.
2. **Correct:** V1, V2, V16.
3. **Incomplete:** seed switching is tested only with a short epoch (known). There is no ARM64 cross-check (known).
4. **Fragile:**
   - the cache build under the global mutex, with capacity 2 (R1-C1 item 6);
   - the cache key (R1-C5).
5. **Exploitable:** seed thrash through free forks (R1-C1).
6. **Inefficient:** a 0.75 s light hash (R1-C3).
7. **Does not scale:** initial sync (R1-C3).
8. **Missing:** best-chain seed pinning, and next-epoch cache prebuild in the node (the miner gap is known).
9. **Redesign:** the cache design (a once-cell per seed, outside the lock).
10. **Innovate:** fast-sync with embedded hashes (P3).
11. **Before testnet:** seed pinning (part of R1-C1).
12. **Defer:** fast-sync, light-mode speed.
13. **Never change:** `check_hash` semantics, the E/L schedule, "seed on own branch", and "the input is the full 100-byte header".

### 3.3 LWMA difficulty
1. **Implemented:** LWMA-1, N = 60, a monotone `prev+1`, a 6T cap, an `N²T/20` floor, a u128 intermediate, and a clamp to [1, u64::MAX].
2. **Correct:** V5.
3. **Incomplete:** the adversarial analysis (R1-C8).
4. **Fragile:** the floor of 1 makes fork blocks free (R1-C1). This is a policy problem, not a rule problem.
5. **Exploitable:** by a majority miner through weight shaping, with unverified gain (R1-C8).
6. **Inefficient:** O(N) per header. That is fine.
7. **Does not scale:** no issue.
8. **Missing:** the 99/100 factor (R1-C7, deliberate).
9. **Redesign:** not for the testnet. Evaluate ASERT for mainnet (§4.1).
10. **Innovate:** a simulation harness shared by LWMA and ASERT.
11. **Before testnet:** nothing in the rule itself.
12. **Defer:** R1-C8 simulation (P2); the ASERT decision (P3).
13. **Never change** (for a live network): the loop, the integer order of operations, the cap, the floor, N, and cumulative work defined as the sum of header difficulties.

### 3.4 Timestamps (MTP and FTL)
1. **Implemented:** MTP-11 (lower median, strict), FTL 360 s against the local clock, non-permanent, with no peer adjustment.
2. **Correct:** V6.
3. **Incomplete:** skew detection (R1-C9).
4. **Fragile:** a tight FTL makes clock skew a liveness risk.
5. **Exploitable:** R1-C8 shaping, within FTL.
6. **Inefficient:** no.
7. **Does not scale:** no issue.
8. **Missing:** skew warnings.
9. **Redesign:** no.
10. **Innovate:** a peer-offset monitor (warn only).
11. **Before testnet:** NTP in the operator checklist (S).
12. **Defer:** the monitor (P2).
13. **Never change:** MTP strictness and window, "FTL is never permanent", and "never adjust consensus time from peers".

### 3.5 Chain selection, reorganization, undo
1. **Implemented:**
   - most cumulative work with first-seen ties;
   - a header tree with invalid propagation;
   - the connected chain as most-work body-complete (H1 pending);
   - full undo in RAM;
   - no depth limit (K4);
   - a warning at 10 blocks.
2. **Correct:** V8, V12.
3. **Incomplete:**
   - H1;
   - the partial-batch sync (R1-C4);
   - minimum chain work and anti-DoS (R1-C1).
4. **Fragile:**
   - `mark_invalid` is O(entries);
   - entries are unbounded;
   - tie-breaks after a restart (known).
5. **Exploitable:**
   - R1-C1;
   - majority rewrites (R1-C2 makes these cheap).
6. **Inefficient:** reconnecting after a failed reorg re-verifies PX proofs, because they left the mempool. Acceptable.
7. **Does not scale:** undo and bodies in RAM (PX-F1 and PX-F2, known).
8. **Missing:**
   - the anti-DoS work threshold;
   - `MIN_CHAIN_WORK`;
   - finality policy for mainnet (§4.3).
9. **Redesign:** finalize state below depth K on disk for mainnet (§4.3).
10. **Innovate:** Zebra-style "finalized vs non-finalized" state split ([Zebra state RFC](https://zebra.zfnd.org/dev/rfcs/0005-state-updates.html)).
11. **Before testnet:** R1-C1, H1.
12. **Defer:** finality and pruning (P3).
13. **Never change:** "valid only by own ancestors", strictly-greater work, and descendants of invalid blocks being invalid.

### 3.6 Block validation (B rules), emission and fees
1. **Implemented:**
   - B1–B7 (coinbase first and unique, height, exact amount, tx_root, weight, PX budget);
   - T and C rules with block-wide sets;
   - batched BP+ proofs;
   - PX5 last, with a sound cache;
   - height-only emission with a tail.
2. **Correct:** V9–V11, V13, V14.
3. **Incomplete:** TreeFull (known). Stateless checks come before contextual ones only partially in mempool paths (known).
4. **Fragile:** R1-C12 (panic leads to permanent invalid).
5. **Exploitable:** nothing new at block level. The C4 front-running griefing is known.
6. **Inefficient:** the order is cheap-first, which is good. `Transaction::hash` re-encodes each time: `ids` in B5, `tx_hashes` in apply, and `mempool.contains` (minor).
7. **Does not scale:**
   - about 3 PX transactions per block (known);
   - a fixed 600 k weight, with no dynamic block size.
8. **Missing:** nothing needed for the testnet.
9. **Redesign:** none.
10. **Innovate:**
    - a consensus minimum fee (`FEE_PER_WEIGHT = 20`) plus a fixed PX fee is good for privacy (uniform fees) but freezes fee economics. Consider a dynamic minimum based on the median of the chain for mainnet (Monero-style), P3;
    - if fees are ever *burned*, do it by consensus, not by the coinbase `≤` Monero allows. The exact-equality rule here is the better choice.
11. **Before testnet:** nothing.
12. **Defer:** fee and block-size dynamics.
13. **Never change:**
    - B3 exactness;
    - `reward(h)` depending on height only;
    - the M/S/TAIL constants;
    - the implicit coinbase commitment `G + a·H`;
    - the tx-hash composition (prefix ‖ base ‖ prunable, which covers every byte);
    - the Merkle construction.

### 3.7 Genesis and network parameters
1. **Implemented:**
   - per-network constants;
   - an empty genesis with no premine;
   - pinned testnet and regtest ids;
   - distinct network ids, never reused.
2. **Correct:** the identity discipline (the id history in the comments).
3. **Incomplete:**
   - the mainnet genesis time is provisional (by design);
   - there is no mainnet id pin (fine until it is fixed).
4. **Fragile:**
   - the genesis timestamp being far in the past lets free forks be generated (R1-C1) and shapes the difficulty at block 2 (`D0/6`);
   - the public v2 genesis (M1, known).
5. **Exploitable:** M1 (known).
6. **Inefficient:** —
7. **Does not scale:** —
8. **Missing:** a consensus fingerprint (known CI item).
9. **Redesign:** no.
10. **Innovate:**
    - v3 genesis: timestamp = launch time minus a few minutes, published with the binary only at launch;
    - D0 set from the measured honest hash rate.
11. **Before testnet:** the v3 genesis (M1, planned). Consider folding in the §4.4 branch-id binding, because the identity changes anyway.
12. **Defer:** mainnet parameters.
13. **Never change** (per network, once launched): the network id, the genesis header, T, N, the MTP window, FTL, E and L.

### 3.8 Determinism across platforms
1. **Implemented:** integer arithmetic everywhere; RandomX FP emulated in software.
2. **Correct:** no floats outside RandomX; u128 where needed; tie-breaks do not depend on HashMap order (`seq` is unique).
3. **Incomplete:**
   - no ARM64 or cross-platform identical-output comparison (known);
   - 32-bit not excluded (R1-C6).
4. **Fragile:** R1-C5 and R1-C12.
5. **Exploitable:** only if a platform divergence exists [unknown without cross-platform runs].
6. **Inefficient:** —
7. **Does not scale:** —
8. **Missing:**
   - the `compile_error!` for 32-bit;
   - consensus vectors: header id, LWMA sequences, the emission table, `tx_root`, and RandomX seeds across an epoch. Run them on x86_64 and aarch64 in CI.
9. **Redesign:** —
10. **Innovate:** a published consensus-vector file that other implementations can check against.
11. **Before testnet:** nothing blocking.
12. **Defer:** ARM64 CI (P2).
13. **Never change:** "integers only, LE everywhere".

---

## 4. Long-term protocol questions

### 4.1 Is LWMA-60 the right choice?
- **For T = 120 s, LWMA-1 with N = 60 is the widely deployed CryptoNote choice** and zawy's standard recommendation, and the implementation matches it (V5). Keep it for the testnet.
- **For mainnet, compare with ASERT** (Bitcoin Cash `aserti3-2d`, 2020).
  - ASERT is an absolutely scheduled exponential rule anchored to one reference block. It needs O(1) state, and it has no window whose weights can be shaped (R1-C8).
  - Its difficulty depends only on the parent's timestamp and height relative to the anchor, which makes it very easy to analyze and test.
  - Trade-off: LWMA has more deployed experience in small CryptoNote coins, while ASERT has the stronger analysis.
- **Recommendation:** a simulation harness (honest variable hash rate, hash-and-flee, majority timestamp strategies) for both rules, and a decision before the mainnet genesis. Consensus: CONSENSUS if changed. Identity: new. Difficulty: M. Priority: P3.

### 4.2 Timewarp and selfish mining
- **Classic timewarp:** not applicable, because the window slides and solve times are monotone and capped. The residual weight shaping is R1-C8.
- **Selfish mining:** first-seen ties give the Bitcoin/Monero exposure, where the profitability threshold depends on γ (up to 1/3 at γ = 0).
  - Randomized tie-breaking (Eyal–Sirer) lowers γ but makes behaviour less predictable. I do not recommend it now.
  - The real risk is R1-C2: attackers far above 1/3 are cheap to get.
- **Do not add "freshness" or timestamp-based fork choice.** It reintroduces a dependency on local clocks into consensus.

### 4.3 Minimum chain work, checkpoints, reorg depth
- **Minimum chain work (policy):**
  - adopt a `MIN_CHAIN_WORK` constant per network, updated each release;
  - a node below it reports "syncing" and does not serve templates, which protects eclipsed fresh nodes and miners;
  - together with the R1-C1 threshold, this is Bitcoin Core's model.
  - Consensus: none. Difficulty: S. Priority: P2 (testnet v3 starts at genesis work).
- **Checkpoints:**
  - keep "none" as the testnet policy;
  - for mainnet prefer an *assumed-valid / fast-sync hash list* (a sync shortcut, overridable) to hard checkpoints (a validity rule). Monero ships both kinds, and its fast sync is on by default.
- **Reorg depth for mainnet:** there is a third option beyond the two in k4-reorg-policy.md: **halt on deep reorg**.
  - zcashd refuses reorganizations deeper than `MAX_REORG_LENGTH = 99` and requires operator action ([zcash PR #2463](https://github.com/zcash/zcash/pull/2463)).
  - Zebra finalizes state below 99 blocks and is discussing raising the limit to 1000 ([zebra #11403](https://github.com/ZcashFoundation/zebra/issues/11403)).
  - This caps the undo data kept in RAM (it fixes PX-F2 structurally) and bounds the rewrite damage.
  - It pays with the partition risk k4 describes, which the halt, needing a human decision instead of silently following, makes visible rather than silent.
  - **Recommendation for mainnet:** K on the order of 1–2 days of blocks (≥ 720), with a halt plus an operator override rather than a silent refusal. Decide with testnet data. Consensus: policy, but it behaves like consensus under partition. Difficulty: M. Priority: P3.

### 4.4 Future upgrades without splits
- **Use scheduled, height-activated network upgrades** (Monero's hard-fork table; Zcash [ZIP 200](https://zips.z.cash/zip-0200)). **Do not use version-bits soft forks.**
  - In a privacy chain, un-upgraded nodes that accept blocks they cannot fully check weaken the soundness of the supply and nullifier rules.
  - Upgrades should be explicit hard forks with an activation height known long in advance.
- **Mechanism:**
  - add `ChainParams.upgrades` = [(name, activation_height, header_version, branch_id)];
  - require `header.version == version_at(h)`;
  - bind `branch_id` into every signature message and the PX binding, as Zcash does with branch-id sighashes (ZIP 143/244). This gives two-way replay protection across an upgrade or a contentious split;
  - make R1-C10's "unknown future version" handling non-banning.
- **Privacy note:** in ring-signature chains, a split that shares history lets the same key image be spent on both chains with different rings. Ring intersection then exposes the real input.
  - Wallets must reuse the stored ring on both chains (the reference wallet does; W-5).
  - A branch id alone does not prevent this. Document it in the upgrade guide.
- **When:** the table as a no-op now (S). Branch-id binding is best folded into the **v3 identity reset** already planned for M1, where it adds no extra identity cost. Consensus: CONSENSUS. Identity: fold into v3. Difficulty: M. Priority: P2, if the v3 reset timing allows, otherwise P3.

### 4.5 What must NEVER change (on a launched network)
Changing any of these rewrites history or forks every existing node, and brings no benefit that could not be had by a new identity or a scheduled upgrade:
1. The header layout, the id hashing (tag, network id, bytes) and the network id.
2. `check_hash` semantics, "work = difficulty", cumulative work as a u128 sum, and strictly-greater fork choice.
3. The RandomX parameters and the seed schedule (E, L, "own branch", "the whole header is the input"). A variant (R1-C2 option b) is only acceptable at a new identity.
4. The LWMA formula, including its integer operation order, N, the cap, the floor, the early-window behaviour, and the absent 99/100 factor.
5. MTP rules. Never add peer-adjusted time to consensus.
6. The Merkle construction, and the tx-hash composition covering every byte.
7. The emission formula and constants, height-only `reward(h)`, B3 exactness, and the implicit coinbase commitment.
8. Genesis constants per network, and never reusing a network id.
9. "Validation depends only on ancestors", and propagation of invalidity to descendants.

---

## 5. Priority list

| Pri | Item | Consensus | Identity | Difficulty |
|---|---|---|---|---|
| P0 | R1-C1: claimed-work gate before PoW (threshold `max(best − 144 blocks, MIN_CHAIN_WORK)`), no bodies for sub-threshold branches, best-chain seed pinning with cache builds outside the lock. **Check that A8's scope covers all four effects.** | none | no | M |
| P0 | H1 (in progress). Also cover `missing_bodies` and `mark_invalid` selection. | policy | no | M |
| P0 | M1 v3 genesis near launch, with D0 from the measured honest hash rate | CONSENSUS | new (planned) | S |
| P0 | R1-C2: document K1 as not attainable against stock RandomX miners (testnet) | none | no | S |
| P2 | R1-C4 `sync_state` on partial batch; R1-C5 seed-keyed bounded PoW cache; R1-C6 64-bit only | none | no | S |
| P2 | R1-C3 reject cache; R1-C9 skew detection plus NTP checklist; R1-C8 adversarial LWMA simulation; `MIN_CHAIN_WORK` constant | none | no | S–M |
| P2/P3 | §4.4 upgrade table (no-op) plus branch-id binding (best folded into v3) | CONSENSUS | fold into v3 | M |
| P3 | R1-C2 mainnet PoW decision; §4.1 ASERT vs LWMA; §4.3 finality (halt-on-deep-reorg with finalized state); fast-sync hash list; dynamic fees and block size; R1-C10 policy half; R1-C12 `reconsiderblock` | mixed | mixed | M–L |
| docs | R1-C7, R1-C11 (to A16b) | none | no | S |

**Tests to add (named proposals):**
- `free_low_work_fork_is_not_hashed_or_stored`
- `side_branch_seed_cannot_evict_best_chain_cache`
- `partial_header_batch_still_syncs_state`
- `lwma_adversarial_timestamp_strategies_bound_gain`
- `unknown_future_header_version_is_not_banned`
- cross-platform `consensus_vectors` (x86_64 and aarch64)

## Sources
- [Bitcoin Core PR #25717: anti-DoS headers sync](https://github.com/bitcoin/bitcoin/pull/25717)
- [Bitcoin Core CVE-2019-25220: memory DoS from headers spam](https://bitcoincore.org/en/2024/09/18/disclose-headers-oom/)
- [zawy12 LWMA (difficulty-algorithms issue #3)](https://github.com/zawy12/difficulty-algorithms/issues/3)
- [zcash PR #2463: roll-back limit for reorganisation](https://github.com/zcash/zcash/pull/2463)
- [Zebra issue #11403: raise the reorg limit to 1000](https://github.com/ZcashFoundation/zebra/issues/11403)
- [Zebra state-updates RFC](https://zebra.zfnd.org/dev/rfcs/0005-state-updates.html)
- [ZIP 200: network upgrade mechanism](https://zips.z.cash/zip-0200)
- [ZIP 143](https://zips.z.cash/zip-0143)
- [monerod reference (`--fast-block-sync`)](https://docs.getmonero.org/interacting/monerod-reference/)
- Bitcoin Cash `aserti3-2d` (Nov 2020 upgrade): cited from memory, not re-fetched [assumed].
