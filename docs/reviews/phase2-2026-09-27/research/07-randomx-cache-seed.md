# 07 randomx-cache-seed: research dossier (phase 2, phase 1: research and briefing)

Agent 07. This is internal engineering research, not an audit. The repository was read only, and nothing was built or run.

---

## 1. Scope and what I read

**Commit:** `9e422d8` (`git rev-parse --short HEAD`), branch `rebuild/core`.

**Code in scope (read in full or at the relevant functions):**

- `consensus/src/pow.rs`: `check_hash`, `seed_height`, the `PowFunction` trait, and `RandomXPow` (capacity-2 LRU, one global `Mutex`).
- `consensus/src/chain.rs`:
  - `seed_id_for` (:277);
  - `template_on` (:287-303);
  - `check_rules`, `validate` (:469-489; PoW last);
  - `precheck_batch`, `overlay_context`;
  - `accept`, `switch_to`, `mark_invalid`.
- `chain/src/manager.rs`:
  - `CachedPow` (:45-124);
  - `replay`, `replay_one` (:376-466; stored-hash preload);
  - `submit_inner` (:616-700; PoW hash recomputed or looked up at store append);
  - `keeps_body` (:773);
  - `sync_state` (:879);
  - `pow_jobs` (:1127-1157);
  - `template`, `template_on` (:1231-1270);
  - `submit_block_in_steps` (:266).
- `p2p/src/net.rs`:
  - `header_worker`;
  - `ANTI_DOS_BLOCKS`, `anti_dos_threshold`, `worth_verifying`, `verify_headers` (:1510-1790);
  - `block_worker` (:1917-1990);
  - `NetConfig::pow_threads` (:135, :160).
- `node/src/lib.rs`: `/template` (:199-222) and `/block` (:230-268). `node/src/main.rs:103` (`RandomXPow::new()`). `node/src/config.rs` (the RPC binds to loopback by default and has no authentication).
- `miner/src/lib.rs`: `PowContext`, `search`, `build_block`. `miner/src/main.rs`: the seed-change loop, which drops the old dataset and then builds the new one synchronously.
- `randomx/src/lib.rs` (the x87 `compile_error!` guard is now present), `randomx/src/dataset.rs` (`Cache::new` and `Dataset::new` allocate with `vec!`), `randomx/examples/bench.rs`.
- `rpc/src/lib.rs`: `Template` (no `next_seed_id`).
- `Cargo.toml` profiles (randomx, blake2 and aes run at opt-level 3 in dev, so real-RandomX tests are affordable).

**Tests read:**

- `consensus/src/pow.rs` tests: `check_hash_boundaries`, `seed_schedule_matches_monero`.
- `consensus/tests/golden.rs`: `seed_height_schedule_golden`, and the seeds taken from templates.
- `consensus/tests/randomx_end_to_end.rs`.
- `consensus/src/chain.rs` tests: `seed_is_taken_from_the_headers_own_branch` (:932-939).
- `chain/tests/manager.rs`:
  - `pow_jobs_use_seeds_from_the_batch`;
  - `pow_jobs_reject_a_height_gap`;
  - `the_pow_cache_key_includes_the_seed`;
  - `the_randomx_key_switch_works_across_sync_restart_and_reorg` (short epoch 16/4, real RandomX).
- `p2p/tests/network.rs`: the `CountingPow`, `SlowCountingPow` and `SlowPow` doubles and the header-gate tests.
- `miner/src/lib.rs` tests: `found_nonce_verifies_with_consensus`, `stop_flag_and_limit_end_the_search`.
- `randomx/src/lib.rs` vectors, and `full_mode_matches_light_mode` (ignored; CI `randomx-full`).

**Docs and reports read:**

- `docs/reviews/full-review-2026-09-27.md`: the register rows for R1-C1, R9-2, R9-6/C9, R9-R4 and R15-9, P1-4, P2-6, P2-14, never-change item 3, and risks 2 and 19.
- `docs/reviews/autonomous-session-2026-09-27.md`: `12ce4cb` work gate; "RandomX: the seed cache built outside the lock, and next-seed prebuild in the miner" is listed as remaining.
- `full-review-2026-09-27/R9-randomx.md` (all of it).
- `R1-consensus.md`: R1-C1, R1-C5, R1-C11, and the §3.2 answers.
- `SX1-core-crossreview.md`: the R1-C1 correction, "gate on claimed work, not on a difficulty floor".
- `SX2-systems-crossreview.md`: R9-2 is "4–7× at D0 = 100", "A8 closes the low-work part; the in-mutex build remains", P1; C9.
- `R8-p2p.md`: the relevant `0.6 s` passages.
- `R12-performance.md:143, :357`.
- `docs/consensus.md` §3 and §3.1.
- `docs/p2p.md` §6 (:176-192) and §12 limitations (:572-590).

**Local evidence (outside the repo, read only):**

- `C:/bszkeval/seedrun2/` (4-node labnet with light-mode miners, which crossed height 2113):
  - `miner0.log` and `miner1.log`: "RandomX ready in 3.1s" at start-up, and "944.6ms" and "910.2ms" at the 2113 switch (light mode, so the cache build only, under labnet load);
  - `metrics.csv`: node RSS was about 262–268 MB before the switch and 531–532 MB after (2113–2153);
  - `node0.log`: block 2112 at 09:57:48, 2113 at 09:57:53.

**Roster neighbours read:** 05, 06, 08, 09 (overlap: next-seed prebuild), 31, 34, 36, 01 and 35.

---

## 2. Current state

### 2.1 What exists and is correct

| Item | Evidence class |
|---|---|
| `seed_height` equals Monero `rx_seedheight` (E = 2048, L = 64; first switch at 2113). The key is always ≥ L + 1 blocks old and changes once per epoch. | tested (`seed_schedule_matches_monero`, `seed_height_schedule_golden`) |
| The seed is looked up on the header's **own branch** (`seed_id_for` → `ancestor_id`). | tested (`seed_is_taken_from_the_headers_own_branch`; `the_randomx_key_switch_works_across_sync_restart_and_reorg` checks every cached hash against a reference hash under the expected key, including a heavier branch that forks below the seed block) |
| PoW runs last, after `check_rules` (difficulty, MTP, FTL, height, version). | source-read (`chain.rs:469-489`) |
| `CachedPow` is keyed by `H("BlackSilk/pow-cache/v2" ‖ seed ‖ header_bytes)`, so a hash computed under one seed is never reused under another (closes the keying half of R1-C5). | tested (`the_pow_cache_key_includes_the_seed`) |
| Header PoW is computed **outside the chain lock** (`pow_jobs` then `compute_parallel`, then `accept_headers` under the lock). | source-read (`net.rs:1750-1765`) |
| Anti-DoS claimed-work gate (`12ce4cb`): a batch is hashed only if its claimed tip work reaches `work(main[tip-144])`, or if it is a full batch whose claimed work per height is at least half of ours. Unrequested bodies with unknown headers are dropped before hashing. | source-read (`net.rs:1641-1692, 1936-1942`); p2p tests exist for the gate (not re-derived here) |
| `RandomXPow::cache`: one mutex over a `Vec<(seed, Arc<Cache>)>`, capacity 2, MRU last. The build (`Cache::new`) runs **while the mutex is held**. Hashing itself runs outside the mutex (on an `Arc` clone). | source-read (`pow.rs:41-84`) |
| No duplicate builds of the same seed (a side effect of the in-lock build). | source-read |
| Replay trusts the stored PoW hash under the seed derived from the stored parent. No RandomX runs on restart. | source-read (`manager.rs:436-466`); tested indirectly by the restart leg of the key-switch test |
| Miner: `PowContext::{Light, Full}`. On a seed change it drops the old context **before** building the new one (the peak is about 2.3 GiB in full mode), and mines nothing meanwhile. | source-read (`main.rs:117-127`) |
| x87 guard `compile_error!` present (R9-R5 part closed). | source-read (`randomx/src/lib.rs:22-25`) |

### 2.2 What the tests actually prove

- **Seed correctness** (which key) is well covered, including reorgs across a switch. The coverage uses a short epoch; the real epoch only ran in the labnet `seedrun2` in **light** mode.
- **Nothing tests the cache policy:**
  - no eviction test;
  - no pinning (it does not exist);
  - no concurrency or blocking test;
  - no adversarial-seed test;
  - no memory-bound test;
  - no test of the miner seed switch in full mode (R15-9, P0-13, owned by 09).

  Evidence class: **unknown / untested**.
- **Cache build cost:**
  - `docs/consensus.md:98,110` says "about 0.6 s", which was never measured (R1-C11).
  - The only local evidence is the light-mode miner log: 0.91–0.94 s at the switch and 3.1 s at start-up, under labnet load, on this machine. This is tested evidence, but on one machine only.
- **Node memory:** measured from about 265 MB to about 532 MB RSS after the first switch (seedrun2 `metrics.csv`). That equals two resident 256 MiB caches. With capacity 2 and no pinning, the genesis-era cache stays resident until a third seed appears, which is about 2048 blocks later.

---

## 3. Problems in scope (roster questions plus the standard analysis)

### 3.1 Q: Can adversarial seeds from low-work forks force cache builds and evict the honest cache (R1-C1)?

**Before `12ce4cb`:** yes, for free (R1-C1 item 6, R9-2).

**Now:** re-derived, with the evidence class noted for each path.

1. **P2P header path.** A header at height h ≥ S + 65 on a branch whose block at height S differs from ours needs an unpinned cache. To be hashed, the batch must pass `worth_verifying`.
   - **(a) Near-tip branches.** The parent is within 144 blocks of our tip, so the gate passes on *claims*. But to reach a different seed, the branch must fork below S and carry headers up to S + 65. Every header before the one keyed by the new seed is verified in earlier chunks, so the attacker must **really mine** at least 66 headers at LWMA difficulty. Timestamps cannot drop the difficulty much: the fork is recent, so there is little elapsed time to spread out, and FTL is 360 s.
     - **Cost per forced build:** about 66 × D_honest hashes.
     - This is cheap only for an attacker who could already out-mine the pure-Rust testnet. With the R9 figures (JIT about 50–100× the pure-Rust miner; D about 9,600 at about 80 H/s of honest hashrate), 66 × 9,600 ≈ 0.63 M hashes, or about 2 min for one xmrig desktop.
     - That attacker class can 51%-attack the trial anyway, so the incremental DoS is small.
     - [src + math, assumed hashrates]
   - **(b) Deep branches.** These pass only as full batches with at least half our work per height. That is real work of the same order.
   - **(c) Exception, F07-4.** When `pow_threads > 65`, a single chunk can contain both an **unverified** seed header S and a header at S + 65 or above. `pow_jobs` then keys a cache build on an attacker-chosen, PoW-less seed.
     - `pow_threads` defaults to `available_parallelism`, so a 96- or 128-thread host is affected by default.
     - The window is when our tip is within about 63 blocks *below* S. The attacker extends our tip (the gate passes trivially) with garbage PoW.
     - Victim cost per identity: 1 chunk of hashes, plus 1 cache build (about 1 s, 256 MiB), plus possibly one honest eviction. Then the ban follows.
     - [src]
2. **RPC `/block` path, F07-3.** `submit_block` leads to `submit_inner`, then `headers.accept`, then `validate`, then `pow_hash`. This path runs **under the chain lock**, with no work gate and no seed restriction.
   - Anyone who can reach the RPC can therefore replay the full R1-C1 free-fork attack, including arbitrary seeds, directly into the header tree and the store.
   - The default bind is loopback. There is no authentication, and a non-loopback bind is only warned about (`node/src/main.rs:125-128`).
   - This is exactly the class Monero fixed in **PR #11238** ("rpc: reject deep block submissions on restricted RPC", merged 2026-09-20). That fix rejects a submitted block whose `rx_seedheight(parent_height + 1) != rx_seedheight(chain_height)`, because Monero computes alt-block PoW before other validation and the "slowest path" re-inits the secondary cache under a write lock.
   - [src + primary source]
3. **Eviction.**
   - With capacity 2 and plain LRU, any cache build for a third seed evicts the least recently used honest seed.
   - Around a switch (tip between S + 65 and about S + 209), both honest seeds are live. A single side-seed build then forces an honest rebuild of about 1 s on the next honest header.
   - **No pinning exists.** `docs/p2p.md:581` wording suggests that it lives "in the consensus crate", but it does not (F07-10).

**Security consequences.**

- **Liveness.** A build stalls every PoW caller, including the chain-lock holder in the RPC path and the header worker, for 1–3 s.
- **Memory churn.** 256 MiB per build.
- **Not safety.** The cache contents are a deterministic function of the seed, so a thrash can never change a verdict.
  - Invariant: `hash(seed, blob)` is independent of cache state.
  - Evidence: [math] (a cache is a pure function of the key) plus the reference-hash checks in the key-switch test.

**Classification.** Liveness and DoS; policy only; not consensus-critical and not privacy-critical.

**Prior art.**

- **Monero `rx-slow-hash.c`:**
  - A **main** seed is set by the blockchain (`rx_set_main_seedhash`, which inits the cache and then the dataset in a background thread, releasing the cache lock before the dataset build so that light hashing can proceed).
  - A **single secondary** cache serves every other seed. An unknown seed reinitializes the secondary under an exclusive write lock ("only one thread runs at a time").
  - The main seed is thus effectively **pinned**, and attacker seeds thrash only the secondary.
- **p2pool (`pow_hash.cpp`):**
  - two caches (current and previous seed);
  - `set_seed_async`;
  - hashing tries dataset, then current cache, then previous cache, and falls back to `calc_pow` RPC to monerod for unknown seeds;
  - cache and dataset init take write locks that block hashers (a known cost p2pool accepts).
- **Bitcoin Core PR #25717:** headers presync and the anti-DoS work threshold (already adopted in part by `12ce4cb`).

**Trade-offs.**

- Pinning needs the chain layer to tell the PoW layer which seeds are "hot", and a bug could leak memory. This is mitigated by a hard cap.
- Building outside the lock allows *parallel* builds of different seeds, which is a memory hazard. It needs an explicit build semaphore and a live-cache bound.
- A per-peer build budget could delay a legitimate deep-reorg branch. It must drop, not ban, and it must never apply to pinned seeds.

**Tests that can prove the fix:** see §5 (T1–T9).

**Invariants that must never change:**

- the seed schedule;
- "seed on the header's own branch";
- the full 100-byte header as input;
- `check_hash`;
- PoW last;
- cache state never affects a verdict (never-change list item 3; R9 §7).

### 3.2 Q: Can the cache be built outside the lock?

**Yes**, in pure safe `std`. I recommend a `Mutex<State>` plus a `Condvar` with an explicit `building` set, rather than a `OnceLock` per seed:

- `OnceLock::get_or_init` guarantees a single initializer for one cell (Rust std docs). But eviction, pinning priority, a bound on concurrent builds, and a live-memory bound all need state across cells.
- A single mutex with a condvar is easier to reason about and to model-test.

Algorithm (`SeedCache<C>`, generic over the cache type so that tests can inject a cheap counting fake):

```
get(seed):
  lock
  loop:
    if resident(seed): touch LRU; return Arc clone
    if building(seed): wait(condvar); continue
    if !pinned(seed) && (unpinned_builds_in_flight >= 1 || evicted_unpinned_alive() > 1):
        wait(condvar); continue
    break
  building.insert(seed); unlock
  let guard = BuildGuard(seed)   // Drop: lock, building.remove, notify_all (panic-safe)
  let c = Arc::new(build(seed))  // outside the lock
  lock; insert; evict unpinned beyond SIDE_CAP (never a pinned one),
        remember evicted as Weak; drop guard; return
set_hot(seeds: [Hash; ≤2])        // replaces the pinned set; prebuild spawns for missing
```

- `evicted_unpinned_alive()` counts `Weak`s whose strong count is above 0. These are evicted caches still in use by a hashing thread.
- A pinned request never waits for an unpinned build. It waits only for its own seed's build.

### 3.3 Q: Can the best-chain seed be pinned?

**Yes.** Pin set = `{ seed_id_for(tip, h) : h ∈ [tip+1−144, tip+1+L] }` on the **connected** chain.

- **Why the pin set holds at most 2 seeds [math]:**
  - For h > 2112, the seed changes only at heights h ≡ 65 (mod 2048).
  - The window holds 144 + 1 + 64 = 209 < 2048 consecutive heights, so it contains at most one change point.
  - Therefore the set holds **≤ 2 seeds**, so `PINNED_CAP = 2` is exact.
- **What the window covers:**
  - the next block's seed;
  - every seed a competing branch within the anti-DoS window can use without forking below a seed block;
  - the **next** seed, 64 blocks ahead. This is what enables the node prebuild (§3.4).
- **Memory:**
  - The old seed is released automatically once tip + 1 − 144 > S + 64.
  - Steady state is 1 cache for about 1,839 of every 2,048 blocks, and 2 caches for 209 blocks.
  - Today it is 2 caches permanently (seedrun2 RSS 532 MB).
- **Capacity:** `PINNED_CAP 2 + SIDE_CAP 1 = 3`. This matches R9-R1, P1-4 and Monero's main-plus-secondary layout.
- **Hard memory bound:** resident 3, plus 1 unpinned in flight, plus at most 1 evicted-but-borrowed, which is **≤ 5 × 256 MiB ≈ 1.25 GiB** worst case. Typical is 256–512 MiB.
- **Plumbing:**
  - Add a default no-op trait method `PowFunction::set_hot_seeds(&self, &[Hash])`, so the ~15 `ZeroPow` test doubles are untouched.
  - `CachedPow` forwards it.
  - `ChainManager` calls it after every connected-tip change (end of `sync_state` and `finish_sync`) and after `open`/replay.
- **Header-best tip:** the header-best tip may differ from the connected tip (withheld bodies). Its seeds use the side slot, which is acceptable because that branch passed the work gate.

### 3.4 Q: Next-seed prebuild (node and miner)

**Node.** When the pin set gains a seed that is not resident (the next seed, from the moment block S is connected, about 64 blocks or 2 h ahead), spawn one background build thread with `std::thread::Builder`.

- Result: the first block of each epoch (S + 65) no longer pays about 1–3 s on the critical path.
- Today it pays that cost either in the header worker or, for the local miner's own block, **under the chain lock** via `/block` (F07-7).

**Template RPC.**

- Add `next_seed_id: Option<String>` and `next_seed_height: Option<u64>` to `rpc::Template` with `#[serde(default)]`.
- Also add `next_seed: Option<(Hash, u64)>` to the consensus `BlockTemplate`, computed by a `HeaderChain::next_seed_for(parent, height)` that returns `seed_id_for(parent, height+L)` when it differs from `seed_id_for(parent, height)`, with activation height `seed_height(height+L) + L + 1`.
- `seed_height(height+L) = (height−1) & !(E−1) ≤ parent height`, so the seed is always already known [math].
- This mirrors Monero `get_block_template`, which sets `next_seed_hash` only when it differs from `seed_hash`.

**Miner (full mode).** When `next_seed_id` appears, build the next `Cache` and `Dataset` in a background thread with `prebuild_threads` (default `max(1, threads/4)`) while mining continues. Then swap when the template's `seed_id` equals the prebuilt one.

- **Peak memory:** about 2.08 + 0.25 + 2.08 ≈ 4.4 GiB (R9-R4).
- **Fallback:**
  - use fallible allocation (`Vec::try_reserve_exact`, stable) through new `Cache::try_new` and `Dataset::try_new`;
  - on failure, or with `--no-prebuild`, fall back to today's behaviour;
  - better still, a **light-mode bridge**: build the new cache (about 1 s), mine in light mode while the dataset builds in the background, then switch to full. The bridge is Monero's own pattern: `rx_set_main_seedhash` releases the cache lock before the dataset build, so light hashing proceeds.
- **Windows:** try_reserve fails reliably under commit-charge limits. On Linux with overcommit it may succeed and the OOM killer strikes later, so document `--no-prebuild`.
- **Reorg of block S before activation:** `next_seed_id` changes, so the prebuild is discarded and restarted.
- **Reorg back below the switch after activation:** the template seed returns to the old seed, so the miner keeps the previous context until `next_seed_height + 144` and drops it after that (policy).

**Classification.** Performance and liveness (the R9-R4 stall: 179 s at 8 threads, 1,217 s at 1 thread, on the same height for every pure-Rust miner). No consensus change. The miner already trusts its node's seed (R9-14, accepted).

### 3.5 Q: Memory bounds

| Component | Today | Proposed |
|---|---|---|
| Node RandomX caches | 2 × 256 MiB resident forever after the first switch (measured: RSS +267 MB), plus borrowed evicted Arcs (unbounded in principle, small in practice) | 1–2 pinned plus ≤ 1 side, hard-bounded ≤ 5 × 256 MiB transient |
| `CachedPow::known` | unbounded; includes failed hashes (R9-6/C9): about 26 MB per year legitimately, about 140 MB per day under attack (R9) | see F07-5: move accepted headers' PoW hashes to a per-id map dropped at store append; keep only transient per-chunk entries; never insert failures |
| Miner | 2.08 GiB dataset (+0.25 GiB cache while building) | + prebuild 4.4 GiB peak, fallible, optional |
| Allocation failure | `vec!` then process abort (`dataset.rs:32, :89`) | `try_new` returns `Err`; the node refuses the side build (drop, no ban); the miner falls back |

**Caution on bounding `CachedPow` naively (new observation).** `submit_inner` needs the PoW hash again at **store append** (`manager.rs:666-671`), possibly thousands of blocks after the header was accepted (headers-first sync). A plain LRU would force a light RandomX recompute of about 0.5–0.75 s **under the chain lock** per evicted block. The bound must therefore key on "header accepted, body not yet stored", not on recency.

---

## 4. New findings

| ID | Severity | Status | Location | Scenario | Confidence |
|---|---|---|---|---|---|
| **F07-1** (refines R9-2, cache part) | **Low** (was Medium in R9-2; downgraded because `12ce4cb` removed the free P2P trigger) | Partially implemented | `consensus/src/pow.rs:55-70` | Any cache build blocks **every** `pow_hash` caller for any seed for 0.9–3.1 s (measured cache build: seedrun2 miner logs). Triggers today: (1) every honest epoch switch; (2) the local miner's first block of an epoch, via `/block` **under the chain lock**, so RPC and P2P readers convoy behind it; (3) F07-3; (4) F07-4; (5) work-backed side branches. | high |
| **F07-2** | Low | Not implemented | `pow.rs:46-70` | No pinning, capacity-2 LRU. One side-seed build near a switch evicts an honest seed; the next honest header rebuilds (+1–3 s). The old genesis-era seed also stays resident about 2048 blocks longer than needed (+256 MiB RSS; seedrun2). | high |
| **F07-3** | **Low** (loopback default); **Medium** if `rpc_bind` is non-loopback or DNS rebinding reaches it (see 36) | Not implemented | `node/src/lib.rs:230-241` then `chain/src/manager.rs:616-650`, `consensus/src/chain.rs:469-489` | `/block` bypasses `worth_verifying`: a deep free fork (R1-C1, difficulty collapsed to 1) can be submitted block by block. PoW runs under the chain lock; attacker-chosen seeds force cache builds and evictions; headers and bodies are stored. This is Monero's alt-block seed DoS, fixed by PR #11238 (2026-09). | high (src) |
| **F07-4** | Low | Not implemented | `p2p/src/net.rs:1750` (chunk = `pow_threads`, default = `available_parallelism`); `chain/src/manager.rs:1146-1152` | On a host with more than 65 threads, a garbage-PoW batch that extends our tip across S (tip within about 63 blocks below S) makes `compute_parallel` build a cache for the unverified in-chunk seed S before the header's PoW fails. Per identity: 1 chunk + 1 build + possibly 1 honest eviction. | medium-high |
| **F07-5** (R9-6/C9 deepened) | Low | Partially implemented | `chain/src/manager.rs:53-124, 666-671` | Unbounded; stores failed hashes. **New:** a naive LRU bound would move RandomX recomputes under the chain lock at body-store time during headers-first sync. | high |
| **F07-6** (R9-R4, known) | Low | Not implemented | `miner/src/main.rs:117-127`, `rpc/src/lib.rs:65-79` | No `next_seed_id` in the template; every full-mode pure-Rust miner stalls 3–20 min at S + 65. | high |
| **F07-7** | Low | Not implemented | `pow.rs` (no prebuild API) | The node builds the next-epoch cache on the first S + 65 header or block (critical path; under the chain lock for the local miner's block). | high |
| **F07-8** | Low | Not implemented | `randomx/src/dataset.rs:32, :89` | `vec!` allocation failure aborts the process (node or miner). No fallible path for the prebuild's 4.4 GiB peak. | high |
| **F07-9** | Informational | — | seedrun2 `metrics.csv` | Measured memory baseline: node RSS 265 to 532 MB across the first switch. Useful as the before/after figure for pinning (1 cache for about 90% of each epoch). | high (measured, 1 machine) |
| **F07-10** | Informational (docs) | — | `docs/consensus.md:98,110`; `docs/p2p.md:581-583` | "About 0.6 s" is unmeasured (measured 0.91–0.94 s under load, 3.1 s at start-up); p2p.md implies seed pinning exists in the consensus crate, but it does not. | high |

There are no Critical, High or consensus findings. Cache policy can never change a validity verdict [math: `Cache` is a pure function of the key; tested indirectly by the reference-hash checks].

---

## 5. Implementation plan for phase 2

Ordered by priority. **None of these items changes consensus**, and **none has a testnet identity impact**. All are policy or internal.

### W1 (P1, M): `SeedCache` with pinning, out-of-lock builds and hard memory bound (F07-1, F07-2, F07-7 node part)

- **Files (owner 07):**
  - `consensus/src/pow.rs`: `SeedCache<C>`, `RandomXPow` built on it; the trait method `set_hot_seeds` (default no-op); `prebuild`; stats (`builds()`, `resident()`) for tests and diagnostics.
  - `consensus/src/lib.rs`: exports.
  - `chain/src/manager.rs`: **only** the call sites that compute the pin window and call `set_hot_seeds` at the end of `sync_state`/`finish_sync` and after `open`. About 15 lines; coordinate with 02, 10, 34 and 35.
- **Externally visible:** nothing. Memory and latency only.
- **Tests:**
  - **T1 unit, fake builder:** a pinned seed is never rebuilt after 100 side seeds (build count = 1).
  - **T2 concurrency:** a pinned `get` completes while an unpinned build is blocked. The fake builder waits on a channel, so the test is deterministic with no timing.
  - **T3 memory exhaustion:** 32 threads × 200 distinct random seeds. The live-instance counter (Drop-counted fake) never exceeds 5, and never exceeds 3 when idle.
  - **T4 panic safety:** a builder that panics once leaves no waiter stuck, and a retry succeeds.
  - **T5 pin window property (proptest):** for random tip heights and E/L = 2048/64 and 16/4, the window holds ≤ 2 distinct seeds, and it contains the seed of tip + 1 and of tip + 1 + L.
  - **T6 differential, real RandomX:** under a random sequence of `set_hot_seeds` and `get` calls over 4 keys, every `pow_hash` equals `hash_light(seed, blob)`. About 5 real cache builds; affordable at dev opt-level 3.
  - **T7 chain adversarial (short epoch 16/4, real `RandomXPow`):** a side branch forking below seed block 16 with 5 distinct block-16 variants. Assert that the connected tip's seed build count stays 1, and that `resident() ≤ 3` after each.
- **Benchmarks:** extend `randomx/examples/bench.rs` to report cache build time (median of 5). Record the RSS before and after on a labnet run across 2113.
- **Docs:** `docs/consensus.md` §3.1 (the cache policy and the measured cost); `docs/p2p.md:581` (fix the wording).

### W2 (P1, S): gate the RPC `/block` path (F07-3)

- **Files:** `node/src/lib.rs` (`submit_block`). This is shared with 36 rpc-security; I suggest 36 owns the endpoint and 07 supplies the predicate. The predicate itself goes in `chain/src/manager.rs` as `ChainManager::rpc_block_admissible(&Block) -> Result<(), Reject>`.
- **Rule:**
  - Before any PoW, reject a block with an unknown header whose seed (`seed_id_for(prev, height)`) is not in the hot (pinned) set.
  - Or equivalently, reject when its parent is below `anti_dos_threshold`. Moving `anti_dos_threshold` and `worth_verifying` from `net.rs` into `chain` (a `HeaderChain` method) lets P2P and RPC share one definition. That move is 31's file, so coordinate.
  - The local miner always mines on `template()`, so it is never affected.
  - Prior art: Monero PR #11238.
- **Externally visible:** an RPC error string only. This is policy.
- **Tests:**
  - **T8:** submit a 2,200-block free fork (short epoch) via the router. The node rejects it at the first header whose seed is not pinned. `RandomXPow::builds()` does not grow, and the tip is unchanged.
  - A regression: the miner's normal submission is accepted across a switch.
- **Docs:** `docs/p2p.md` §12, and the RPC docs.

### W3 (P1, S): cap the PoW chunk so an unverified in-batch seed never keys a build (F07-4)

- **Files:** `p2p/src/net.rs:1750` (owner 31). The change is `chunk = pow_threads.clamp(1, params.seed_lag as usize)`, which keeps every S + 65 header in a later chunk than S. As defence in depth, `chain/src/manager.rs::pow_jobs` also debug-asserts or skips in-part seeds (owner 07).
- **Tests:**
  - **T9 (p2p):** `pow_threads = 128` and a seed-recording `PowFunction` double. A garbage-PoW batch across S never requests the seed S′ = id(fake header S).
- **Priority:** P1 because it is trivial; the impact is Low.

### W4 (P2, S–M): `CachedPow` bound without chain-lock recomputes (F07-5)

- **Files:** move `CachedPow` from `chain/src/manager.rs` into a new `chain/src/pow_cache.rs` (owner 07) to take it out of the most contended file.
- **Design:**
  - A `pending` map for jobs computed but not yet accepted, cleared after `accept_headers` of each chunk.
  - An `accepted_unstored: HashMap<BlockId, Hash>` filled at header accept and removed at store append.
  - Failures go only to a 256-entry LRU.
  - Keep the seed in the key (the R1-C5 invariant).
- **Tests:**
  - growth bounded under 10,000 failing headers;
  - headers-first sync of 3,000 headers then bodies performs **zero** RandomX under the lock (a counting double);
  - replay still performs zero RandomX.
- **Docs:** `docs/blocks.md` §8.

### W5 (P2, M): miner next-seed prebuild and fallible allocation (F07-6, F07-8)

- **Files:**
  - `consensus/src/chain.rs`: `next_seed_for` and `BlockTemplate.next_seed`. This is 01's file, but additive; coordinate.
  - `chain/src/manager.rs` `Template`: `next_seed`.
  - `rpc/src/lib.rs`: `next_seed_id` and `next_seed_height` with serde default.
  - `node/src/lib.rs`: `/template` fills them.
  - `randomx/src/dataset.rs`: `Cache::try_new` and `Dataset::try_new` with `try_reserve_exact`; the existing `new` becomes `try_new(..).expect(..)`. The outputs are unchanged, and the vectors guard this. Coordinate with 05.
  - `miner/src/lib.rs`: a `SeedPlanner` state machine (pure) plus a background builder.
  - `miner/src/main.rs`: wiring and the `--no-prebuild` and `--prebuild-threads` flags. 09 also touches `main.rs` for the R9-9 polling, so assign `main.rs` to a single owner (see §6).
- **Tests:**
  - `SeedPlanner` unit tests for:
    - switch with the prebuild ready;
    - switch while it is still building (light bridge);
    - reorg of S before activation (discard and restart);
    - reorg back after activation (keep the old context);
    - allocation failure (injected) falling back;
  - a template golden: `next_seed` is present exactly for heights in [S + 1, S + 64] (Monero semantics), and absent otherwise;
  - a labnet `--miner-full` run across 2113 (09 / P0-13): hashrate never drops to zero.
- **Benchmarks:** stall time at the switch, before and after, and peak RSS.
- **Docs:** `docs/consensus.md` §3.1 ("as implemented" paragraph); miner README and `--help`.

### W6 (P2, S): per-peer unpinned-build budget

- **Files:** `p2p/src/net.rs` (owner 31).
- **Rule:** before `compute_parallel`, a batch that would need a non-resident, unpinned seed consumes the peer's budget (1 per 10 min). Over budget, the batch is `LowWork`: dropped, not banned.
- **Test:** 3 successive branches with distinct seeds from one peer lead to 1 build.

### W7 (P3): node full-mode dataset (R9 O7)

Owned by 06. It reuses `SeedCache` with a `Dataset` payload.

---

## 6. Dependencies and conflicts

| Workstream | Relationship |
|---|---|
| **05 randomx-conformance** | `Cache::try_new` and `Dataset::try_new` in `randomx/src/dataset.rs` must not change outputs; all vectors and `full_mode_matches_light_mode` must pass. 05 owns the crate; 07 needs only the additive constructors. |
| **06 randomx-performance** | Dataset build speed (O1) shrinks the prebuild window and the bridge time. O7 (node full mode) should build on `SeedCache`. |
| **09 mining-templates** | Direct overlap on the next-seed prebuild and the template RPC. Proposal: 07 owns `SeedPlanner`/`PowContext` (`miner/src/lib.rs`) plus the template `next_seed` plumbing (consensus, chain, rpc, node `/template`); 09 owns the `miner/src/main.rs` loop (tip polling R9-9, stale work) and wires the planner in. The coordinator should assign `main.rs` to one of us. |
| **31 p2p-sync** | W3 (chunk cap) and W6 (per-peer build budget) are in `net.rs`; the `anti_dos_threshold` move into `chain` for W2. |
| **34 chain-actor-concurrency** | The `/block` PoW under the chain lock (F07-1 trigger 2) disappears if 34 moves PoW off-lock for RPC submissions ("check, verify outside, re-check"). W1 must not assume the chain lock. The pin update is a cheap call from the single writer. |
| **36 rpc-security** | W2 lives in the `/block` handler; DNS-rebinding and auth decide F07-3's real severity. |
| **01 consensus-core** | `next_seed_for` added to `consensus/src/chain.rs`; the stored-PoW trust on replay (unchanged by W4). |
| **02, 10, 35** | Share `chain/src/manager.rs`. W1 needs about 15 lines there; W4 moves `CachedPow` out to `pow_cache.rs` (replay preload call sites touch 35's area). |
| **41 fuzz/stateful** | A `SeedCache` stateful model (T3–T6) could join their harness. |
| **45 benchmarks** | Cache build time and RSS-across-switch are baseline metrics. |
| **47 docs** | F07-10. |

---

## 7. Open questions for the coordinator

1. **`miner/src/main.rs` ownership:** 07 or 09 (see §6)?
2. **Prebuild default:** should it be on by default in the miner (4.4 GiB peak), or off, with the light bridge as the default? Trial devices with < 6 GiB RAM would need `--no-prebuild`. Which device classes are in the trial (R15)?
3. **W2 rule:** "seed pinned" (a Monero-like, simple rule), or a shared `worth_verifying` predicate (more general; needs 31's move)? I recommend pinned-seed for the RPC, because only the local miner should use it.
4. **P1 vs P0:** is P1 acceptable for W1–W3, given that after `12ce4cb` none of these is exploitable for free over P2P? My view is P1 before the trial, because W1 is also the base for the node prebuild and removes a 1–3 s chain-lock convoy at every epoch switch that the 96-hour trial will hit at 2113.
5. **Pin window:** should it also include the header-best tip's seed when it differs (withheld-body branches)? I propose no: the side slot covers it.

---

## 8. Sources

- **Monero `src/crypto/rx-slow-hash.c`:** main vs secondary cache, `rx_set_main_seedhash` background init (cache lock released before the dataset build), the "slowest path" secondary re-init under a write lock. https://github.com/monero-project/monero/blob/master/src/crypto/rx-slow-hash.c
- **Monero PR #11238**, "rpc: reject deep block submissions on restricted RPC" (selsta, opened 2026-09-04, merged 2026-09-20). https://github.com/monero-project/monero/pull/11238
  - The code in `core_rpc_server.cpp` `on_submitblock`: reject if `rx_seedheight(parent_height+1) != rx_seedheight(chain_height)`. https://github.com/monero-project/monero/blob/master/src/rpc/core_rpc_server.cpp
  - Third-party review describing the alt-block seed-cache DoS (used as a pointer only): https://github.com/xmrack/monero-review/issues/451
- **Monero `get_block_template`:** `seed_hash`, `seed_height`, and `next_seed_hash` (set only when it differs from `seed_hash`). Daemon RPC docs: https://www.getmonero.org/resources/developer-guides/daemon-rpc.html ; the code in `core_rpc_server.cpp` (above).
- **Monero RandomX integration PR #5549** (hyc): https://github.com/monero-project/monero/pull/5549
- **p2pool `src/pow_hash.cpp`:** two caches, `set_seed_async`, old-seed precalc, `calc_pow` RPC fallback. https://github.com/SChernykh/p2pool/blob/master/src/pow_hash.cpp
- **tevador/RandomX:** README and specs (cache 256 MiB, dataset about 2 GiB, light vs fast mode). https://github.com/tevador/RandomX ; https://github.com/tevador/RandomX/blob/master/doc/specs.md
- **Bitcoin Core PR #25717** (headers presync / anti-DoS work threshold): https://github.com/bitcoin/bitcoin/pull/25717
- **Rust std:**
  - `OnceLock::get_or_init` (single initializer; a panic leaves the cell uninitialized): https://doc.rust-lang.org/std/sync/struct.OnceLock.html
  - `Vec::try_reserve_exact` (fallible allocation): https://doc.rust-lang.org/std/vec/struct.Vec.html#method.try_reserve_exact
  - `Condvar`: https://doc.rust-lang.org/std/sync/struct.Condvar.html
- **Pointer only (non-primary):** c2pool PRs #1813 and #1814 (next-seed announcement to miners; a seed-switch share-rejection bug when a cache slot was re-keyed without re-binding the VM): https://github.com/frstrtr/c2pool/pull/1814
- **Internal:**
  - R9-randomx.md (R9-2, R9-6, R9-R4);
  - R1-consensus.md (R1-C1, R1-C5, R1-C11);
  - SX1 and SX2 cross-reviews;
  - full-review-2026-09-27.md (P1-4, P2-6, P2-14);
  - `C:/bszkeval/seedrun2/` logs and `metrics.csv`.
