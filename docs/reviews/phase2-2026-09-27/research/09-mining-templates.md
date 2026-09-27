# 09 mining-templates: research dossier (phase 2, phase 1)

Agent 09. Internal engineering work, not an audit. Read-only on the repository; no builds
or tests run by me. The one "measurement" below is a re-analysis of the log files of the
coordinator's labnet run that is still in progress (`C:/bszkeval/seedrun2`), not a new run.

---

## 1. Scope and what I read

**Commit:** `9e422d8` (`rebuild/core`, `git rev-parse --short HEAD`).

**Code (all read in full unless noted):**
- `miner/src/lib.rs` (214 lines: `build_block`, `PowContext`, `search`, 2 unit tests);
- `miner/src/main.rs` (179 lines: CLI, template loop, seed switch, refresh timer, submit);
- `miner/Cargo.toml`;
- `node/src/lib.rs` (554 lines: `/template`, `/block`, `/info`, `with_chain`, locking);
- `rpc/src/lib.rs` (`Template`, `SubmitResult`, client limits and timeouts; relevant parts);
- `chain/src/manager.rs`: `CachedPow`, `Template`, `submit_block_in_steps`, `submit_inner`,
  `drain_ready`, `sync_state`, `finish_sync`, `keeps_body`, `template`, `template_on`,
  `generated_before`, and the in-file tests;
- `chain/src/mempool.rs` lines 1–480 (`select`, `remove_block`, `revalidate`,
  `enter_rules`, `COINBASE_RESERVE`);
- `consensus/src/pow.rs` (all), `consensus/src/chain.rs` (`BlockTemplate`, `template_on`,
  `seed_id_for`), `consensus/src/params.rs` (`base`, `regtest`);
- `randomx/src/dataset.rs` (`Cache::new`, `Dataset::new`), `randomx/src/vm.rs` (API);
- `tx/src/builder.rs` `build_coinbase`; `tx/src/types.rs` `weight`, `px_bytes`;
  `tx/src/validate.rs` `BlockError` and `validate_block_transactions_cached` (B1–B7);
- `chain/src/block.rs` (`MAX_BLOCK_BYTES`, `MAX_BLOCK_TXS`);
- `p2p/src/net.rs` tip-announcement tick (lines 2600–2645) and the `tick` default (250 ms);
- `tools/labnet/src/main.rs` (774 lines, all).

**Tests read:** `miner/src/lib.rs` tests (`found_nonce_verifies_with_consensus`,
`stop_flag_and_limit_end_the_search`); `chain/tests/manager.rs` short-epoch seed switch
(`short_epoch_params`, `mine_real`, `expected_seed`, `pow_jobs_use_seeds_from_the_batch`);
`chain/tests/activation.rs` (template version and pool flush); the uses of
`blacksilk_miner::build_block` in `wallet/tests/e2e.rs` and
`tools/supply-audit/tests/regtest.rs`; `consensus/src/pow.rs` tests
(`check_hash_boundaries`, `seed_schedule_matches_monero`); `chain/src/mempool.rs`
template-selection tests (by grep).

**Docs and reports:** `docs/reviews/full-review-2026-09-27.md` (all mining/PoW/template
rows, §1.3, §1.4, §3.2, P0-13, P1-4, P2-6, P2-14); `docs/reviews/autonomous-session-2026-09-27.md`
(all); `full-review-2026-09-27/R9-randomx.md` (all); SX1 and SX2 (every R9/R15/mining
row); `docs/reviews/v3-upgrade-mechanism.md` (miner/template rows); `docs/testnet-v3-genesis.md`
§4–§6; `docs/consensus.md` §3 (seed schedule); `docs/blocks.md` §7, §9;
`docs/testnet.md` §5, §8, §12.1, §12.6. Roster entries 05–08, 10–12, 31, 33–36, 40, 45.

**Evidence files:** `C:/bszkeval/seedrun2/{journal.log, metrics.csv, miner0.log,
miner1.log}` (read on 2026-09-27 12:09 local, while the run was still going; last sample
at height 2166).

---

## 2. Current state

### 2.1 What exists

| Component | What it does | Evidence class |
|---|---|---|
| Template (node) | `ChainManager::template()` = consensus `template_on(tip)` + `block_reward(h, generated)` + `mempool.select(max_block_weight − 3000, px_pool)`; transactions only when the pool's signature domain equals the template height's (activation-safe) | source-read; tested `chain/tests/activation.rs` (template version, no old-rule txs), mempool select unit tests (PX and deploy budgets) |
| `/template` RPC | Builds under the chain lock on a blocking thread, hex-encodes outside it; no readiness gate; no auth (loopback bind) | source-read |
| Coinbase construction | Done **in the miner**, not the node: one output to `--address`, amount `reward + fees`, hedged anchor randomness (`coinbase/v2` context, per-process OS hedge secret), outputs sorted | source-read; `build_block` exercised by `wallet/tests/e2e.rs`, `supply-audit/tests/regtest.rs` |
| Header | `version = template.version` (epoch), `timestamp = max(min_timestamp, now)` fixed per template, `nonce` from a fresh 64-bit random start per template (`f331642`) | source-read; R3-2 fix |
| Nonce search | `threads` scoped threads, thread `t` tries `start + i·threads + t`; `stop` checked each hash; first found wins | tested `found_nonce_verifies_with_consensus` (light mode, difficulty 3, hash equals `hash_light`), `stop_flag_and_limit_end_the_search` |
| PoW check | Miner uses `consensus::check_hash` and the same header layout (`NONCE_OFFSET` 92) as the node | source-read; same crate |
| Template freshness | Timer thread stops the search after `--refresh` (default 15 s; labnet uses 5 s); no tip notification | source-read |
| Seed switch | When `template.seed_id` changes: `drop(old)`, then `Cache::new` + `Dataset::new(threads)` synchronously; no hashing meanwhile | source-read; measured stall in docs/testnet.md §12.1 (179 s at 8 threads, 1 217–1 219 s at 1 thread) |
| Submission | `POST /block`; `submit_block_in_steps` (8 blocks per lock hold); the P2P tick (250 ms) announces the new tip as a `Headers` message to peers with a lower height | source-read |
| Labnet | N regtest nodes (real RandomX, epoch 2048/lag 64, 10 s target), 2 miners (light by default, `--miner-full` for both), wallets, partitions, late joiner, supply check | source-read; run logs in `C:/bszkeval/seedrun2` |

### 2.2 What is correct and well designed

- **One PoW path.** The miner cannot disagree with the node on `check_hash` or the header
  bytes [source-read]; `found_nonce_verifies_with_consensus` pins it end to end in light
  mode [tested]. Full = light is pinned by CI `randomx-full` [tested, per R9].
- **The payout address never reaches the node.** Unlike Monero's
  `get_block_template(wallet_address)`, BlackSilk's node serves an address-free template
  and the miner builds the coinbase. A remote or compromised node learns the payout only
  from the submitted block (which becomes public anyway) and cannot redirect the reward:
  the coinbase is under `tx_root`, which is under the PoW [source-read]. This is a good
  privacy/security property and should be kept (§3.8, never-change list).
- **Nonce privacy.** A fresh random start per template closes R3-2 [source-read].
- **Activation safety of templates.** Templates carry the epoch's header version and
  offer transactions only under the matching signature domain [tested:
  `chain/tests/activation.rs`].
- **Template budgets.** v1 weight ≤ `600 000 − 3 000`, PX bytes ≤ 8 MiB, deploy bytes
  ≤ 1 MiB, PX pool non-negative in block order, conflict keys unique within the template
  (defence in depth after F1) [source-read; mempool unit tests].
- **Seed schedule.** `seed_height` equals Monero's `rx_seedheight`
  [tested `seed_schedule_matches_monero`]; the seed is taken on the header's own branch
  [tested, per R9].

### 2.3 What the tests actually prove, and what they do not

- **Proven:** a nonce found by `search` verifies under the consensus light-mode hash at a
  tiny difficulty; the stop flag and hash limit end the search; blocks built by
  `build_block` from `/template` connect on a regtest node (e2e and supply-audit tests,
  with `ZeroPow`-style or regtest difficulty); a short-epoch (16/4) seed switch works in
  the chain manager with real RandomX.
- **Not proven by any test:**
  - the **miner binary**'s loop (refresh, seed switch, error handling, submit) — no test
    runs `main.rs` logic; CI builds but does not run the binary [source-read; known];
  - **full-mode mining across a real seed switch** (2113) — never run (see §2.4);
  - that **every template the node serves validates** as a block (no template→validate
    property test; see M9-3);
  - behaviour of `/template` **while the node is syncing** or mid-drain (M9-2);
  - **stale-work rate** — only modelled (R9-9) until the log analysis in §2.4.

### 2.4 New evidence from `seedrun2` (re-analysis of running-run logs)

Setup (from `autonomous-session` §7 and the logs): 4 regtest nodes, **light-mode** miners
(`--refresh 5`, 1 thread), binaries at `83fceee`, partitions every 25 min for 4 min.

- **The real switch at 2113 has now been crossed** with network parameters, by light
  miners: both miners logged `initializing RandomX for seed 273fcf33…` at 09:57:48/51Z and
  `ready in 944.6 ms / 910.2 ms` [measured, log]. All 4 nodes agreed on the tip within
  ~15 s at heights 2113–2135 (metrics.csv). **Node RSS rose 285 → 541 MB at 2113** (the
  2-slot RandomXPow keeps both 256 MiB caches) [measured]. This is relevant to 07.
- **No full-mode miner has crossed 2113.** The P0-13 gate (full-mode miners past 2400) is
  still open.
- **Stale work is large at regtest parameters.** From the two miner logs, 2 199 heights
  were found; **836 heights (38%) had competing blocks from both miners**; excluding
  heights found within a partition window (217), **≈ 28% of heights outside partitions
  had two competing blocks** [measured from logs; my script, not a harness metric]. This is
  consistent with R9-9's model: each miner learns a new tip only at its next refresh (mean
  2.5 s at `--refresh 5`) plus ~1 s propagation and light verification, against a 10 s
  block target. At testnet parameters (T = 120 s, refresh 15 s) the same model gives
  ~6–8% (R9-9 said ~6%). It also means **most labnet reorganizations are stale-work races,
  not partition healing**, which inflates the reorg statistics that labnet reports.
- The journal shows **every wallet sync hitting "still synchronizing (N of N+1)"**: the
  node's `header_height` routinely runs one ahead of `height` for a moment after each
  block. Any "syncing" gate on `/template` must tolerate this (M9-2).

---

## 3. Problems in scope

### 3.1 Stale work (R9-9) — now measured

- **Problem and cause.** The miner has no tip notification; it polls a full template every
  `--refresh` seconds and hashes the old parent meanwhile. The P2P layer learns the new tip
  within 250 ms (tick), but nothing pushes it to the miner.
- **Consequences.** Wasted hash power (≈6–8% at testnet parameters, measured ≈28% at
  regtest), more forks and short reorgs, a slight advantage to the miner whose node hears
  first (centralization pressure, Gervais et al. 2016 model stale rate as a function of
  interval and propagation). Not consensus-critical; liveness/efficiency and evidence
  quality (labnet reorg counts).
- **Prior art.**
  - Bitcoin BIP 22 long polling: the server "SHOULD NOT" answer a `longpollid` request
    until it wants to replace the current work; Bitcoin Core's `getblocktemplate` waits for
    a tip change or mempool update and releases `cs_main` while waiting.
  - Monero: miners poll `get_block_template`; p2pool uses the ZMQ `miner_data` feed and
    `get_miner_data`.
- **Options.** (a) poll `/template` every 1–2 s: **rejected**: a PX-full template is up to
  ~8 MiB of transactions, ~16–18 MB of hex JSON (`MAX_TEMPLATE_RESPONSE_BYTES`), selected
  and cloned under the chain lock each time; (b) poll a tiny tip endpoint every ~0.5–1 s
  from a watcher thread and refetch the template only on change; (c) long-poll
  `/template?wait=<prev_id>` held ≤ 30 s. (b) is the smallest change with no new
  plumbing; (c) is better once the chain actor (34) gives a tip `watch` channel.
- **Trade-offs.** Polling adds a lock acquisition per poll (trivial work, but the global
  lock is contended; 34). Long-poll holds an HTTP connection per miner (the client timeout
  is 120 s; server cap must be well below). Both are policy-only.
- **Tests.** Node: the tip endpoint changes exactly when `tip_id` changes; a long-poll
  returns within the tick after a `submit_block`. Miner: a watcher sets `stop` when the
  mock node's tip changes (needs the loop refactor, I1). Labnet: stale-race rate reported
  (I4); acceptance: at regtest with the watcher, competing heights outside partitions drop
  from ≈28% to the propagation floor (expect < 10%).
- **Invariants.** The miner still refetches a template periodically (new transactions,
  timestamp freshness); the node remains authoritative for template content.

### 3.2 Seed-switch stall and next-seed prebuild (R9-R4)

- **Problem.** On the first template with the new key, the miner frees the old dataset and
  builds the new one synchronously: 3 min (8 threads) to 20 min (1 thread) of zero
  hashing, at the same height `S+65` for every full-mode BlackSilk miner. The key is known
  64 blocks earlier (RandomX README: key change every 2048 blocks with a 64-block delay).
- **Consequences.** Liveness/fairness only: a predictable window where only light-mode or
  JIT miners produce blocks; on regtest (10 s blocks) a 20-min stall is 120 target
  intervals. LWMA caps each solve time at 6T, so it recovers in a few blocks (03). Not
  consensus-critical.
- **Prior art.** Monero's `get_block_template` returns `seed_hash`, `seed_height` and
  `next_seed_hash`, computed with `rx_seedheights(height, &seed, &next)` and set only when
  next ≠ current. Monero's node updates its "main" dataset **in a background thread**
  (`rx_set_main_seedhash`: "Update main cache and dataset in the background") and falls
  back to light mode while the dataset is initializing ("use the light mode"). Pool
  software announces the next seed in the 64-block window (c2pool PR #1814). Whether xmrig
  itself prebuilds from `next_seed_hash` I could not confirm [unknown].
- **Design (policy only, no consensus change).**
  - **Pure function** (consensus crate, no rule change): `next_seed_height(h, E, L) =
    seed_height(h + L)` if it differs from `seed_height(h)`, else `None`. For
    `h > E+L`, `seed_height(h+L) = (h−1) & !(E−1) ≤ h−1`, so the next seed block is always
    at or below the parent: it exists on the template's branch. Check: h = 2049 → 2048;
    h = 2112 → 2048; h = 2113 → none; h = 4097 → 4096.
  - **Node:** `chain::Template` and `rpc::Template` gain `next_seed_id: Option<…>`
    (`#[serde(default)]`, so old miners and nodes interoperate) =
    `ancestor(prev_id, next_seed_height)`.
  - **Miner:** when `next_seed_id` is `Some` and differs from the current and pending
    seeds, spawn one background thread that builds `Cache` then `Dataset` with
    `--prebuild-threads` (default `max(1, threads/4)`), while mining continues. When a
    template's `seed_id` equals the prebuilt seed, swap in O(1) and drop the old context.
    If the prebuild is still running at the switch, wait for it (never start a second
    build). If the template's `seed_id` matches neither (a reorg across the seed block),
    discard and build synchronously as today. **The template's `seed_id` stays the only
    authority** (R9-14: a malicious node can only waste the miner's work, as today).
  - **Memory:** peak = 2 datasets + 1 cache ≈ 4.4 GiB per full-mode miner (the `Dataset`
    does not keep the `Cache`). `--prebuild off` restores today's behaviour. A fallible
    `Dataset::try_new` (with `Vec::try_reserve_exact`) lets the miner fall back instead of
    aborting on allocation failure on Windows/macOS; on Linux with overcommit the failure
    can still surface later as an OOM kill (documented, not solvable in safe portable Rust).
- **Honest trade-off.** Prebuild does **not** save CPU: the dataset costs the same
  core-seconds. It removes the synchronized network-wide drop and keeps block production
  continuous; hash rate during the ~64-block window is reduced by roughly
  `prebuild_threads / cores`. On regtest the window is ~640 s, shorter than a 1–2 thread
  build (~10–20 min), so labnet must use ≥ 4 build threads to show the benefit. Speeding up
  `Dataset::new` (06, R9-R2 O1) shrinks both the stall and the prebuild.
- **Tests.** Unit: `next_seed_height` against an independent transcription of Monero's
  `rx_seedheights` for every height in `0..20_000` and the edge heights; short-epoch
  (16/4) chain test: `next_seed_id` appears exactly for template heights in the lag window,
  equals the `seed_id` of the first template after the switch, and changes after a reorg
  that replaces the seed block; miner: the prebuilt context is used iff seeds match
  (light-mode `PowContext` so the test is fast); labnet (I5).
- **Invariants.** `seed_height`, E = 2048, L = 64, the seed from the header's own branch,
  and "template `seed_id` is authoritative" never change.

### 3.3 Template served while syncing or mid-drain (new, M9-2)

- **Problem.** `/template` always answers from the connected tip. Two cases:
  1. **Catch-up/IBD** (restart, late joiner, header sync ahead of bodies): the miner hashes
     on a tip the network has long passed; every block it finds is an orphan. Bitcoin Core
     refuses (`RPC_CLIENT_IN_INITIAL_DOWNLOAD`, and `RPC_CLIENT_NOT_CONNECTED` with no
     peers, both skipped on test chains); Monero returns "Core is busy" when
     `check_core_ready()` fails, for `get_block_template`, `submit_block` and
     `get_miner_data`.
  2. **Mid-drain** (`sync_pending()`, a bounded connect of > 8 blocks with the lock released
     between steps): the mempool is only partly updated — `remove_block` runs per block,
     but `revalidate` runs once in `finish_sync`. Pooled transactions that became invalid
     during the drain (a PX anchor that left the window after several extensions; after a
     disconnect, rings that now resolve to different outputs) can be selected, so the
     miner's block is invalid (`Body` error, logged as an invalid block).
- **Consequences.** Wasted work and misleading "block … is invalid" warnings on the
  operator's own node; no consensus or safety impact (the block is rejected by the same
  rules). Liveness/operability, Low.
- **Fix (policy).** `ChainManager::template_ready()` = `!sync_pending() &&
  header_height − height ≤ SYNC_SLACK` (slack ≥ 2: the labnet shows `header_height =
  height + 1` constantly). `/template` returns 503 "syncing" otherwise; the miner treats
  it as retry. **No "no peers" rule by default:** the trial's first node mines from genesis
  with no peers; a regtest/solo exemption is needed anyway (Bitcoin's is by chain type).
- **Tests.** Manager: `template_ready` false during a bounded drain and with a header gap;
  node: 503 in both states; a regression that a template taken mid-drain in an
  anchor-expiry scenario would have been invalid (documents why the gate exists).

### 3.4 No template self-validation (M9-3)

- **Problem.** Nothing checks that a served template forms a valid block. Correctness rests
  on mempool invariants plus unasserted arithmetic: `MAX_BLOCK_TXS = 10 000` and
  `MAX_BLOCK_BYTES` (decode limits) are not enforced by `select`; they hold because v1
  weight ≥ encoded size (≤ 597 000 bytes), PX ≤ 8 MiB, and minimal transaction sizes keep
  the count far below 10 000 [source-read, my arithmetic]. `COINBASE_RESERVE = 3 000`
  exceeds a 16-output coinbase prefix (~1.5 KB) but has no const assertion.
- **Prior art.** Bitcoin Core's `CreateNewBlock` runs `TestBlockValidity(…, check_pow =
  false, check_merkle_root = false)` on every template when `test_block_validity` is set,
  and throws if it fails.
- **Recommendation.** Not a runtime full validation (CLSAG/BP+/PX verification per
  template would be a DoS lever under the lock). Instead: const assertions for the three
  bounds; a defensive tx-count cap in `select`; a property test that fills a pool with
  random valid transactions (ZeroPow chain) and validates the template's block with
  `validate_block_transactions`, over reorgs and activations. Cheap runtime checks only
  (B6 sums, byte and count bounds) if at all.

### 3.5 Coinbase construction privacy

- **What is right.** Address-free template (§2.2); one output per block for every
  BlackSilk miner (uniform; P2Pool-style multi-output payouts would be distinguishable,
  I4-10); fresh random nonce start (R3-2); hedged output randomness; no extra/tag field
  (no pool or software tag in the coinbase).
- **Residual metadata (Informational / accepted):**
  - **Block origin IP.** The mining node is the first to announce the block to all its
    peers (`Headers` to every lower peer at the next tick). A well-connected observer can
    link IP ↔ block ↔ coinbase outputs, which feeds the coinbase-decoy heuristics of R3-3
    (knowing which coinbase outputs belong to whom). Monero and Bitcoin share this; there is
    no Dandelion for blocks. Cross-ref 33; accepted for the trial.
  - **Timestamps.** `timestamp = max(MTP+1, now)` at template time, fixed for the refresh
    period. Clock offsets are a known device fingerprint (Kohno, Broido, claffy 2005); per
    miner, the offset between the header timestamp and the network's first-seen time can
    cluster blocks by miner and by miner software. Weak, speculative for 7 participants;
    Informational. A long-poll design keeps the timestamp at template time; do not add
    sub-second or per-software-distinctive timestamp behaviour.
  - **Local logs.** `found block <height>` at info level ties the operator to those
    coinbases if logs leak in bug reports (same class as R10-10).
  - **Hedge secret** per process (R2-C4, accepted); `hedge` is not zeroized at exit
    (Informational).

### 3.6 Nonce search

Correct as R9-11 says [source-read, tested]. No extranonce is needed: 2^64 nonces per
template at ≤ 10^2 H/s per thread. Stop latency = one hash (~0.1 s full, ~0.5–0.75 s
light). No finding.

### 3.7 Running and measuring full-mode mining across 2113

See I4/I5 in §5. Current labnet gaps (M9-7): `--miner-full` switches **both** miners (2 ×
2.3 GiB, or 2 × 4.4 GiB with prebuild; with 4 nodes at up to ~550 MB after 2113, ~7–11 GB
on the shared 16 GB machine); duration-based only (no `--until-height`); no summary field
proves the switch was crossed; miner events (rebuild time, hash rate, found/stale blocks)
are not collected; the miner logs hash rate only at debug level.

### 3.8 Invariants that must never change

1. The miner computes PoW only through `consensus::check_hash` and the consensus header
   bytes; never a miner-local target formula.
2. The template's `seed_id` is authoritative; prebuilt contexts are used only on an exact
   seed match.
3. The payout address never goes to the node; the coinbase is built by the miner.
4. The nonce start is random per template (R3-2).
5. Seed schedule E = 2048, L = 64, seed on the header's own branch; `check_hash` rule.
6. Templates for height h use `rules_at(h)` and the epoch's header version; no mixed rule
   sets.
7. All of I1–I7 are policy: they must not change which blocks are valid.

---

## 4. New findings

| ID | Severity | Status | Where | Scenario | Confidence |
|---|---|---|---|---|---|
| **M9-1** | **Medium** (liveness/efficiency; evidence quality) | Complete but requires further testing (R9-9, now measured) | `miner/src/main.rs:33-35, 136-151`; `tools/labnet/src/main.rs:356-357` | seedrun2: ≈28% of heights outside partitions had two competing blocks (836 of 2 199 overall), consistent with refresh-based staleness at T = 10 s. Testnet model ≈6–8% wasted hash rate; labnet reorg counts are dominated by stale races | high (log counts); medium (attribution) |
| **M9-2** | Low | Not implemented | `node/src/lib.rs:199-219`; `chain/src/manager.rs:1247-1277`, `592-600`, `979-995` | A late joiner or restarted node serves templates on an old tip (every found block an orphan); mid-drain templates can include transactions invalidated during the drain (PX anchor expiry, reorg ring resolution) → own block invalid | high (code); scenario frequency medium |
| **M9-3** | Low | Partially implemented | `chain/src/mempool.rs:411-459`, `:43`; `chain/src/block.rs:10-13` | No template self-check; `MAX_BLOCK_TXS`/`MAX_BLOCK_BYTES`/`COINBASE_RESERVE` hold only by unasserted arithmetic; a future change (a smaller tx kind, a larger coinbase) could make templates invalid silently | medium |
| **M9-4** | Low (P1 for the trial evidence) | Not implemented | `miner/src/main.rs:118-127`; `chain/src/manager.rs:163-177`; `rpc/src/lib.rs:65-80` | R9-R4 unchanged: synchronized 3–20 min full-mode stall at S+65; no `next_seed_id` in the template. Light-mode switch measured fine (0.9 s) | high |
| **M9-5** | Low | Complete but requires further testing | `miner/src/main.rs:117, 128-129` | The miner process exits on one undecodable template transaction or a bad seed id (e.g. an old miner binary after an activation adding a tx kind). Fail-stop is defensible for an outdated binary, but the message does not say "upgrade", and a transient bad response kills an unattended miner | medium |
| **M9-6** | Informational (privacy) | Accepted limitation | `p2p/src/net.rs:2626-2643`; `miner/src/lib.rs:60`; `miner/src/main.rs:164-169` | Block origin IP visible to peers; header timestamp = miner clock (clock-skew fingerprint); `found block` logs link operator to coinbases | medium |
| **M9-7** | Low (evidence tooling) | Partially implemented | `tools/labnet/src/main.rs:78-81, 349-370, 103-141` | Labnet cannot run a mixed full/light pair, stop at a height, or prove the switch was crossed; miner rebuild times, hash rate and stale counts are not in `summary.json`; P0-13 evidence cannot be produced mechanically | high |
| **M9-8** | Informational | — | `rpc/src/lib.rs:229`; `chain/src/manager.rs:1257-1262` | A full template is up to ~16–18 MB of hex and is selected/cloned under the chain lock: naive fast polling (R9-9's "1–2 s") must not use `/template` | high |
| **M9-9** | Informational | Not implemented | `miner/src/main.rs:154-158` | Hash rate is logged only at debug; `docs/testnet-v3-genesis.md` §5 requires a **measured** honest hash rate for D0; there is no `--benchmark` mode | high |
| **M9-10** | Informational (docs) | — | `docs/testnet.md` §12.6 ("never at 2113 with the network's parameters"); `docs/consensus.md` §3 | Outdated once seedrun2 finishes: light miners crossed 2113 at network parameters. Update only with the finished summary, and state that full mode is still unexercised | high |

Challenge to existing reports: R9-9/SX2 accept "poll `/info` or `/template` every 1–2 s";
polling `/template` is not acceptable at PX block sizes (M9-8). R9-R4's "Priority P2 (the
trial observes it)" is fine for the stall itself, but the **evidence** gate P0-13 needs the
labnet changes (I4) to be mechanical, so I4 is P0.

---

## 5. Implementation plan for phase 2

Ordered; all items are **policy / not externally visible to consensus**, no identity
impact, no golden-vector change.

**I1 — Tip watcher and cheap tip endpoint (P1, S–M).**
- Files: `node/src/lib.rs` (new `GET /tip` → `{height, tip, header_height, template_ready}`,
  or `GET /template?wait=<prev_id>&max_secs≤30`), `rpc/src/lib.rs` (struct + client
  method, response cap `MAX_SMALL_RESPONSE_BYTES`), `miner/src/main.rs` (watcher thread
  polling `/tip` every 500 ms–1 s that sets `stop` on change; keep `--refresh` (default
  30 s) for new transactions), `miner/src/lib.rs` (move the loop into a testable
  `run_loop<C: NodeApi>` with a trait over `template/tip/submit`).
- Tests: node unit (tip changes exactly with `submit_block`); miner loop with a mock node
  (stop within one poll of a tip change; resubmits nothing stale; retries on 503).
- Docs: `docs/blocks.md` §9 table; `docs/testnet.md` §5.
- Coordinate with 36 (endpoint exposure, auth) and 34 (later: a `watch` channel replaces
  polling).

**I2 — Template readiness gate (P1, S).**
- Files: `chain/src/manager.rs` (`pub fn template_ready(&self) -> bool`; `SYNC_SLACK`
  const), `node/src/lib.rs` (503 "syncing"), `miner/src/main.rs` (backoff on 503).
- Tests: manager (false during a bounded drain, false with header gap > slack, true at
  gap 1); node 503; miner retry.
- Docs: `docs/blocks.md` §9, `docs/testnet.md` §5 ("the miner waits while the node syncs").
- Coordinate with 02/34 (manager ownership) and 31 (definition of "syncing").

**I3 — `next_seed_id` and miner prebuild (P1 for the trial, S–M).**
- Files: `consensus/src/pow.rs` (pure `next_seed_height`; owner 07/01 — no rule change),
  `consensus/src/chain.rs` (`BlockTemplate.next_seed_id`), `chain/src/manager.rs`
  (`Template` field in `template`/`template_on`), `rpc/src/lib.rs`
  (`#[serde(default)] next_seed_id: Option<String>`), `node/src/lib.rs` (map field),
  `miner/src/lib.rs` (`Prebuild` state: pending seed, `JoinHandle<PowContext>`; swap rule),
  `miner/src/main.rs` (`--prebuild auto|off`, `--prebuild-threads`),
  `randomx/src/dataset.rs` (`Dataset::try_new` with `try_reserve_exact`; owner 05/06).
- Tests: `next_seed_height` vs an independent transcription of Monero `rx_seedheights`
  over heights 0..20 000 plus edges (2112, 2113, 4160, 4161); short-epoch chain test
  (window, equality with the post-switch `seed_id`, reorg of the seed block); miner
  prebuild unit tests in light mode (match → swap, mismatch → discard, never two builds);
  CI stays within memory (tests use light contexts).
- Bench: the labnet run I5 (switch gap, hash-rate dip during prebuild).
- Docs: `docs/consensus.md` §3 ("As implemented…"), `docs/testnet.md` §5, §12.1 (4.4 GiB
  peak with prebuild), §12.6.
- Coordinate with 07 (node-side next-cache prebuild in `RandomXPow` uses the same
  `next_seed_height`), 06 (dataset build speed).

**I4 — Labnet instrumentation for the seed switch (P0, S).**
- Files: `tools/labnet/src/main.rs`, `miner/src/main.rs` (log lines).
- Changes: `--full-miners K` (0, 1 or 2; `--miner-full` = 2); `--until-height H`
  (run until every node ≥ H or duration expires, then final checks); `--require-height H`
  (`checks_passed` requires `final_height ≥ H`); miner logs at info: `RandomX ready in …
  (seed …, prebuilt|built)`, `found block <h> <id8> best=<bool>`, a hash-rate line every
  60 s; labnet parses them into `summary.json`: `seed_switches_crossed`,
  `miner_rebuild_secs`, `max_block_gap_secs` in [2100, 2200], `competing_heights`
  (partition and non-partition), `miner_hashrate`, `node_rss_at_switch`.
- Tests: parser unit tests on sample log lines.
- Docs: `docs/testnet.md` §8.

**I5 — The full-mode run across 2113 (P0 evidence, S effort / ~7 h machine time).**
- Run A (today's code, after I4): `blacksilk-labnet --network regtest --nodes 4
  --full-miners 1 --miner-threads 4 --until-height 2400 --require-height 2400
  --duration-mins 600 --partition-every-mins 25 --partition-mins 4 --tx-every-secs 20
  --px-every-mins 30`. Budget: 1 full miner (2.3 GiB) + 1 light (0.3) + 4 nodes (≤ 0.6
  each) ≈ 5 GiB; start dataset ~5 min; 2 400 blocks × 10 s ≈ 6.7 h. Records the baseline
  stall (expected ~5 min at 4 threads, zero full-mode blocks during it).
- Run B (after I1–I3): same with `--full-miners 2` if memory allows (≈ 11 GiB with
  prebuild), else 1. Pass criteria: converged, supply conserved, late joiner synced, both
  switches' `max_block_gap_secs` ≤ 3 × T, full miner's rebuild at switch ≤ 1 s (prebuilt),
  non-partition competing heights < 10%.
- Schedule when no PX proving (3.8 GB peaks) or other heavy agent jobs run. Per-device
  RandomX hash check (P0-13) is separate (08/45).
- Docs: `docs/evidence/labnet-<date>/` summary + `docs/testnet.md` §12.6 update.

**I6 — Template correctness assertions and property test (P2, S–M).**
- Files: `chain/src/mempool.rs` (tx-count cap in `select`; const assertions
  `COINBASE_RESERVE ≥ max coinbase prefix`, bytes bound ≤ `MAX_BLOCK_BYTES`),
  `chain/tests/template.rs` (new: random pool → template → `validate_block_transactions`
  on ZeroPow, across extension, reorg and activation).
- Owner: 12 owns `mempool.rs`; I propose the test file and the asserts.

**I7 — Miner robustness and measurement (P2, S).**
- Files: `miner/src/main.rs`, `miner/src/lib.rs`.
- Changes: a bad template or seed is logged and retried with backoff (exit only on a
  network/address mismatch or a header version the miner does not know, with an "upgrade
  the miner" message); `--benchmark <secs>` (hash rate without a node, full/light; feeds
  genesis D0, 40); zeroize `hedge` on exit; info-level hash rate.
- Tests: mock-node loop tests from I1.

**I8 — Docs (P0 for the wording, S).** `docs/testnet.md` §5, §8, §12.1, §12.6;
`docs/consensus.md` §3; `docs/blocks.md` §9 (template fields, 503, `next_seed_id`);
operator note: "mine only against your own loopback node" (R9-14), and at genesis launch
the dataset build starts only after the reveal (genesis id = first seed), so use ≥ 4 build
threads.

---

## 6. Dependencies and conflicts

- **05 randomx-conformance / 06 randomx-performance:** `Dataset::try_new`; dataset build
  speed-ups (O1) change stall and prebuild times; any `randomx/` edit must keep vectors.
- **07 randomx-cache-seed:** shares `next_seed_height`; node-side next-cache prebuild;
  the 285 → 541 MB node RSS at 2113 (two caches) is 07's data point. Agree on who owns
  `consensus/src/pow.rs`.
- **01 consensus-core:** `BlockTemplate` in `consensus/src/chain.rs` (field addition only).
- **02 fork-choice / 34 chain-actor:** `chain/src/manager.rs` ownership; `template_ready`
  and the tip `watch` channel fit the actor design.
- **12 mempool-architecture:** `select` changes and the template property test.
- **31 p2p-sync:** the node's notion of "syncing" for I2.
- **33 dandelion-network-privacy:** block-origin privacy (M9-6).
- **36 rpc-security:** new `/tip` endpoint or long-poll, 503 semantics, response caps.
- **40 testnet-genesis:** D0 from `--benchmark`; launch-time dataset build.
- **45 benchmarks:** hash-rate methodology; labnet metrics format.
- **41 fuzzing/property:** template property test style.
- **03 difficulty-lwma:** LWMA response to the synchronized stall (regtest 120 T gap).

## 7. Open questions for the coordinator

1. May the ~7 h labnet runs (I5 A and B) get exclusive machine time, and is one full-mode
   miner acceptable for run A given the 16 GB limit?
2. Should `/template` refuse when the node has **no peers** on testnet (Bitcoin does, off
   test chains)? My recommendation: no, because the trial's first node mines from genesis;
   gate only on sync state.
3. Default for `--prebuild`: on (4.4 GiB peak) or off with an operator opt-in? I recommend
   `auto` = on in full mode, documented in §12.1.
4. Tip endpoint vs long-poll: accept the polling `/tip` now and long-poll after 34?
5. Should the seedrun2 summary (light miners across 2113) be committed as evidence once it
   finishes, with the stale-race figure, so docs can drop "never at 2113"?

## 8. Sources

- Monero daemon RPC, `get_block_template` (`seed_hash`, `seed_height`, `next_seed_hash`)
  and `get_miner_data`: https://docs.getmonero.org/rpc-library/monerod-rpc/
- Monero `core_rpc_server.cpp` (`check_core_ready` → "Core is busy" in
  `on_getblocktemplate`, `on_submitblock`, `on_getminerdata`; `rx_seedheights` for
  `next_seed_hash`): https://github.com/monero-project/monero/blob/master/src/rpc/core_rpc_server.cpp
- Monero `rx-slow-hash.c` (`rx_set_main_seedhash`: background dataset update; light-mode
  fallback while initializing): https://github.com/monero-project/monero/blob/master/src/crypto/rx-slow-hash.c
- Monero RandomX integration PR #5549: https://github.com/monero-project/monero/pull/5549
- tevador/RandomX README (key change every 2048 blocks with a 64-block delay; 2080 MiB
  fast mode, 256 MiB light; interpreter much slower): https://github.com/tevador/RandomX
- RandomX specification ("The whole Dataset needs to be recalculated every time the key
  value changes"): https://github.com/tevador/RandomX/blob/master/doc/specs.md
- Bitcoin Core `src/rpc/mining.cpp` (`getblocktemplate`: `RPC_CLIENT_NOT_CONNECTED`,
  `RPC_CLIENT_IN_INITIAL_DOWNLOAD` unless `IsTestChain()`; long polling):
  https://github.com/bitcoin/bitcoin/blob/master/src/rpc/mining.cpp
- Bitcoin Core `src/node/miner.cpp` (`CreateNewBlock` → `TestBlockValidity`, option
  `test_block_validity`): https://github.com/bitcoin/bitcoin/blob/master/src/node/miner.cpp
- BIP 22, getblocktemplate, long polling: https://github.com/bitcoin/bips/blob/master/bip-0022.mediawiki
- c2pool PR #1814 (announcing the next RandomX seed to miners in the 64-block window):
  https://github.com/frstrtr/c2pool/pull/1814
- A. Gervais et al., "On the Security and Performance of Proof of Work Blockchains",
  ACM CCS 2016 (stale rate vs block interval and propagation): https://eprint.iacr.org/2016/555
- C. Decker, R. Wattenhofer, "Information Propagation in the Bitcoin Network", IEEE P2P
  2013: https://tik-db.ee.ethz.ch/file/49318d3f56c1d525aabf7fda78b23fc0/P2P2013_041.pdf
- T. Kohno, A. Broido, k. claffy, "Remote Physical Device Fingerprinting", IEEE S&P 2005
  (clock skew as a fingerprint): https://homes.cs.washington.edu/~yoshi/papers/PDF/KoBrCl2005PDF-Extended-lowres.pdf
- Rust std `Vec::try_reserve_exact` (fallible allocation): https://doc.rust-lang.org/std/vec/struct.Vec.html#method.try_reserve_exact
- Local evidence: `C:/bszkeval/seedrun2/{journal.log, metrics.csv, miner0.log, miner1.log}`
  (run in progress on 2026-09-27; figures from my log analysis).
