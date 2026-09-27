# 38 wallet-privacy: research dossier (phase 2, phase 1)

This is internal engineering research, **not an audit**. The repository was read-only: no
builds, no cargo tests. The one computation (§2.4) is a Python Monte Carlo of the picker
as it is written in `tx/src/decoy.rs`. It ran in the agent's scratchpad, outside the
repository, and is marked **[sim]**.

Evidence classes:
- **[math]** mathematically established;
- **[test: name]** tested (the named test exists; I did not run it);
- **[src]** source-read;
- **[sim]** simulated;
- **[assumed]**;
- **[unknown]**.

---

## 1. Scope and what I read

**Commit:** `9e422d8` (`rebuild/core`, after the merge of `v3/candidate`).

**Scope (roster 38):**
- decoy selection;
- input selection;
- rebroadcast;
- remote-node privacy;
- SOCKS/Tor for the wallet;
- PX transaction timing;
- the metadata-leakage inventory.

**Code read in full or in the relevant parts:**
- `tx/src/decoy.rs` (all, including the tests);
- `wallet/src/wallet.rs`:
  - constants 50-85;
  - `sync` 999-1084;
  - `apply_block` 1086-1166;
  - `spendable_at` 1168;
  - `submit`/`forget` 1333-1412;
  - `refresh_pending` 1424-1551;
  - `gather`/`select_inputs` 1578-1664;
  - `transfer` 1672;
  - `v1_plans` 1768;
  - `complete_index` 1809-1867;
  - `plans_for` 1881-1980;
  - `px_deposit` 1988;
- `wallet/src/index.rs` (all);
- `wallet/src/node.rs` (all);
- `wallet/src/main.rs` (CLI, RNG);
- `wallet/src/px.rs::anchor_height`;
- `rpc/src/lib.rs`: `Client`, `http_client` 357-364, `already_pooled` 106, caps;
- `rpc/Cargo.toml`, `wallet/Cargo.toml`;
- `node/src/lib.rs`: routes 157-165, `submit_tx` 270-294;
- `p2p/src/net.rs`:
  - `Network::submit_tx` 482-491;
  - `on_stem_tx` 2446-2498;
  - `stem_or_fluff` 2502-2550;
  - `send_held_local_txs`;
  - `fluff` 2575-2592;
- `p2p/src/socks5.rs` (all);
- `chain/src/mempool.rs`: `precheck` 227-240, `check`, `add`;
- `chain/src/manager.rs`: `check_tx`, `submit_tx`;
- `tx/src/validate.rs`: C1 `resolve_input_rings` 398-432, T8 350-360;
- `tx/src/builder.rs`: `max_weight`, `standard_fee` 119-148;
- `tx/src/params.rs`;
- `tx/src/types.rs` (`weight`);
- `px/src/state.rs` (`ROOT_WINDOW`).

**Tests read:**
- all tests in `tx/src/decoy.rs`, especially `young_decoys_survive_coinbase_maturity`,
  `no_pile_up_at_the_maturity_boundary`,
  `an_ineligible_block_is_replaced_from_its_neighbourhood` and
  `kept_members_survive_and_only_the_rest_is_drawn`;
- `tx/tests/privacy.rs` (names and bodies of the ring-position and broken-RNG tests);
- `wallet/tests/e2e.rs` (names), especially:
  - `an_unconfirmed_transaction_keeps_its_inputs_and_is_rebroadcast_unchanged`;
  - `an_output_spent_again_reuses_its_ring`;
  - `rings_are_built_without_asking_the_node_about_outputs`;
  - `a_late_restore_backfills_older_outputs_once`;
  - `a_transfer_built_before_an_activation_is_not_rebroadcast_after_it`;
- the `wallet.rs` unit test `outputs_of_one_transaction_are_not_spent_together_unless_needed`;
- `index.rs` tests.

**Docs:**
- the brief, the roster (entries 12-14, 17, 18, 33, 36, 37, 38, 39) and `decisions.md`;
- `docs/reviews/full-review-2026-09-27.md`: all of it, concentrating on §3.10, §3.11, the
  register rows R3-*, R11-*, I3 §3.9, P1-5/6/7 and never-change items 24 and 27-29;
- `docs/reviews/autonomous-session-2026-09-27.md`;
- source reports R3 (all), R11 §3.5-3.7, I3 §3.3 and §3.9, and the SX2 rows for R3/R11/I3;
- `docs/transactions.md` §10 (end), §11 (all);
- phase-2 dossiers 12 (P3 expiry, P4), 13 (F13-2, step 9, F13-7), 14 (all, esp. §3.4),
  17 (item 2), 18 (P-D/F18-4, W2/W3, dependencies).

---

## 2. Current state

### 2.1 What exists and is well designed

| Item | Assessment | Evidence |
|---|---|---|
| Gamma picker = Monero master `gamma_picker` | Same shape and scale (19.28, 1/1.61), subtract `10·T` or uniform `[0, 15·T)`, age → output index via the average output time, then a uniform output in the block. This matches Monero after PRs #7821/#7993 | [src] `decoy.rs:37-40, 200-214`; Monero `wallet2.cpp` |
| Eligibility inside the draw (R3-1 fix) | The immature-coinbase mass is re-served from the same age neighbourhood instead of being discarded | [test: `young_decoys_survive_coinbase_maturity`, `no_pile_up_at_the_maturity_boundary`] |
| Outputs exactly 10 blocks deep can be decoys | `last_block = height − 10` equals the C1 rule `height − rec.height ≥ 10` (`validate.rs:414-420`) and the wallet's `spendable_at`. So the picker and the spend rule agree. This is the Monero 2023 off-by-one bug class (#8872), **absent here** | [src]; no test pins it (F38-10) |
| Local output index; no per-ring `/outputs` | The ring-superset leak (I3 §3.9) is closed. Backfill takes the whole range `0..start` in fixed pages | [test: `rings_are_built_without_asking_the_node_about_outputs`, `a_late_restore_backfills_older_outputs_once`] |
| Ring reuse W-5 (`select_ring_keeping`) | Correct: kept members are re-validated against the index | [test: `kept_members_survive_…`, e2e `an_output_spent_again_reuses_its_ring`] |
| Reserve-before-send, unchanged rebroadcast | Correct and should never change | [test: e2e rebroadcast, uncertain, save-before-send] |
| Merge avoidance (R3-13) | One output per source transaction first; warns otherwise | [test: `outputs_of_one_transaction_are_not_spent_together_unless_needed`] |
| Standard fee | The wallet always pays `20·max_weight(n,k)`; `max_weight ≥ weight` by construction (varints at 10 bytes) | [src] `builder.rs:121-148`, `wallet.rs:1640-1656` |
| Duplicate-`O` outputs are not excluded from decoys (F13-7) | Eligibility is maturity only | [src] `wallet.rs:1905-1910`; untested |
| RPC client hygiene | No implicit proxy, no redirects, body caps, `https` refused | [src] `rpc/src/lib.rs:357-364` |
| Epoch safety | No rebroadcast across an activation | [test: `a_transfer_built_before_an_activation_is_not_rebroadcast_after_it`] |

### 2.2 What the tests prove, and what they do not

**What the tests prove:**
- On one synthetic young chain (2,160 blocks), the young-decoy fraction matches the target
  within 0.05.
- On that chain, the real input spent 12 blocks after receipt is the newest ring member
  in 51.5 % of rings, against a 62.4 % target (docs/transactions.md §11.3.1).

**What the tests do not prove:**
- **The distribution on a mature chain.** There is no test of the distribution against a
  reference on a steady chain, and no guess-newest regression there. See F38-4: the 52 %
  figure is **not** the steady-state figure.
- **Selection of exactly-10-block decoys** (the Monero #8872 regression class).
- **Behaviour under a malicious node** (a manipulated distribution or backfill).
- **Behaviour under RNG failure** for decoys (F18-4).
- **What the node receives during a spend.** The e2e test proves only that there is no
  `/outputs` call. It does not prove "no spend-time query" (`/distribution` is still
  called).
- **Rebroadcast privacy.** No test covers what a stem peer observes on a re-injection.

### 2.3 Spend path, message by message (what a remote node sees) [src]

A `transfer` makes these calls:
1. `sync`: `/info`, then `/blocks?from=synced` (1 block for the reorg check, then batches),
   `/px/commitments?from=…` and `/px/contracts?from=…`;
2. `plans_for`: **`/distribution?to=synced_height`**, plus the one-time backfill with
   `/outputs` pages if the index is not complete;
3. `submit`: `/info` (tip), then `POST /tx`;
4. `refresh_pending`: on every later sync, `POST /tx` again for each unconfirmed stored
   transaction once `synced ≥ relayed_height + 20`.

A remote node therefore learns:
- the wallet's IP;
- the restore height (the first `/blocks` and the backfill extent) and the PX sync start;
- sync times;
- **the moment the wallet starts to build a spend** (`/distribution`);
- the transaction and its IP;
- a resubmission every 20 blocks while it is unconfirmed.

### 2.4 Quantification: the picker on a mature, steady chain [sim]

The simulation: 400,000 draws of `decoy.rs`'s age draw, on a chain with a constant output
rate, T = 120 s. On such a chain, depth in blocks ≈ 10 + x/T. The attacker guesses the
newest member; the probability that the real input is strictly the newest is
(1 − F(≤d))^15.

| Real depth d (blocks) | F_decoy(< d) | P(real is the newest member) |
|---|---|---|
| 10 | 0.000 | 0.94 |
| 12 | 0.008 | **0.84** |
| 15 | 0.020 | 0.70 |
| 20 | 0.039 | 0.52 |
| 30 | 0.068 | 0.34 |
| 40 | 0.087 | 0.25 |
| 60 | 0.120 | 0.14 |
| 90 | 0.160 | 0.07 |
| 120 | 0.192 | 0.04 |
| 180 | 0.242 | 0.015 |
| 360 | 0.337 | 0.002 |

Decoy-depth quantiles:

| Quantile | Depth (blocks) | Age |
|---|---|---|
| 5 % | 23 | 0.8 h |
| 10 % | 47 | 1.6 h |
| 25 % | 191 | 6.4 h |
| 50 % | 1,078 | 36 h |
| 75 % | 7,297 | 10 days |

Why the young-chain test shows only 52-62 %: on a 3-day chain every draw older than the
chain is discarded (`draw_block` returns `None`, `decoy.rs:209-211`). That discards about
60 % of the gamma mass and inflates the relative young mass about 2.5×. **As the chain
ages, the guess-newest rate for a 12-block spend rises towards about 84-89 %** [math: this
follows from the code; sim for the magnitudes].

---

## 3. Problems in scope

### 3.1 Guess-newest and spend age (roster Q1: "can gamma fitting or spend-delay defaults help?")

**The problem.** For a real input of depth d, guess-newest succeeds with
(1 − F_D(d))^15, where F_D is the decoy CDF. It exists because F_D (Monero's 2017-fitted
gamma) puts about 0.4 % of the mass per block at depths 10-25. It is not a bug; it is the
decoy-model mismatch that OSPEAD measures.
- **OSPEAD** (Rucknium, 2025): with Monero's current distribution, a MAP decoder succeeds
  23.5 % of the time on average (effective ring 4.2). A re-fitted log-GB2 distribution
  (scale 20.62, shape1 4.462, shape2 0.5553, shape3 7.957) would give 7.6 % (13.2).

**Classification.** Privacy-critical (v1 sender anonymity). Not consensus. Not a liveness
problem.

**Can gamma fitting help?**
- **Not now.** OSPEAD-style fitting needs a large corpus of real rings, with the real-spend
  distribution recovered by the Patra-Sen inversion and the BJR mixture estimator.
  Testnet spends by a handful of testers are not representative of anyone.
- **Adopting OSPEAD's Monero fit** would mis-fit BlackSilk users as much as the 2017 fit
  does, with no evidence either way.
- **A distribution that differs between BlackSilk wallets is itself a fingerprint.** The
  BJR estimator separates wallet decoy distributions.
- **Recommendation:**
  - keep Monero master's picker as the single network-wide distribution;
  - version it (`decoy/v1`) in the spec;
  - plan a re-estimation only with mainnet-scale data (P3).
- **Only matching the real-spend distribution reduces the MAP decoder's advantage.** For a
  fixed young age, no decoy distribution reduces guess-newest without mis-serving older
  spends.

**Can spend-delay defaults help?** Yes. This is R3's "make the real spends match the
decoys". But the gain needs hours of waiting, and a naïve fixed minimum creates a spike
that a MAP decoder exploits.
- **A fixed minimum age** puts every young real spend at exactly D. Decoy mass at exactly
  D is small, so a policy-aware attacker gains.
- **Recommended form:** when the user spends an output of depth a < D_lo, draw a target
  depth t from the **picker's own distribution restricted to [max(a, D_lo), D_hi]**, and
  wait until the output reaches t. Within the window the real depth is then distributed
  like a decoy's.
- **The residual advantage** of an attacker who knows that "the real input is in the
  window" is E[1/(1+K)], with K ~ Bin(15, F_D(D_hi) − F_D(D_lo)) [sim]:

| Window (blocks) | Longest wait | Decoy mass in window | Success of an attacker who knows the policy |
|---|---|---|---|
| none (spend at 12) | 0 | — | ≈ 0.84 (guess-newest) |
| 60-120 | 4 h | 0.073 | 0.60 |
| 60-240 | 8 h | 0.161 | 0.37 |
| 60-360 | 12 h | 0.217 | 0.28 |
| 60-720 | 24 h | 0.320 | 0.20 |
| 40-1440 | 48 h | 0.456 | 0.14 |
| full distribution (median 36 h) | days | — | → 1/16 (the ideal) |

This is an upper bound. It assumes the attacker knows that the real input went through the
window. Users who spend late anyway are unaffected.

**Trade-offs:**
- UX latency of hours;
- a user in a hurry overrides it, and the override population is itself young;
- on a young chain (testnet) the table is more favourable, because the chain-length
  truncation shifts decoy mass younger (§2.4).

**Recommendation:**
- **P1:** a young-spend warning. The build step reports "this input is d blocks old; on a
  mature chain the newest-member heuristic identifies such spends in about X % of rings".
- **P2:** an opt-in `--spend-delay {short|long}`, with windows 60-360 and 60-720 and the
  restricted-picker target described above. The default is off for the testnet (UX, R3
  open question 2), and the owner decides it for mainnet.

**Tests:**
- a steady-chain regression of the §2.4 table, with seeded bounds, e.g.
  P(newest | d = 12) ∈ [0.80, 0.90] and P(newest | d = 120) ≤ 0.06;
- delay mode: the target depths drawn are KS-equivalent (seeded) to the picker restricted
  to the window;
- the window table reproduced within ±0.03.

**Invariants:**
- one picker for all wallets;
- decoy eligibility equals the C1 rule;
- exactly-10-block decoys stay possible.

### 3.2 Decoy selection inputs come from the node (remote-node attack on ring quality)

**The problem.** `plans_for` builds the picker from `node.distribution(synced_height)`
(`wallet.rs:1888-1894`). It also derives `coinbase_limit` from it (1900-1903). The only
cross-check is the total at the synced height (`complete_index`, 1814). The local index
already holds a height for **every** output `0..total`, so the wallet does not need the
node's per-block boundaries at all.

**Consequences:**
- **(a)** A malicious remote node can return a monotone but distorted `cumulative`. For
  example, it can compress recent blocks into few outputs and inflate old ones. The age →
  output mapping then shifts, the decoys skew old, and the victim's young real input
  becomes the newest member with near certainty. The same node then receives the
  transaction by `/tx` and learns the real input and the IP together (A4 in R3's threat
  model). Monero's wallet2 has only sanity checks on `rct_offsets` (PR #4691); the
  literature treats a malicious remote node as able to bias decoys.
- **(b)** The `/distribution` request is made only when a spend starts, so it marks "this
  IP is about to spend". It also links a query circuit to a submit circuit by timing, even
  when they are separate Tor circuits (§3.5).
- **(c)** `/distribution` is O(height) per spend in bandwidth and in node CPU (R10-5).

**Classification:** privacy-critical for remote-node users; nothing otherwise.

**Fix:**
- compute `cumulative` from the local index (`OutputIndex::cumulative_through(h)`: a
  partition point per height; O(outputs), cached per sync);
- use it for both the picker and `coinbase_limit`;
- drop the spend-time `/distribution`;
- optionally, fetch `/distribution` during `sync` (the same request for every wallet at
  every sync) and **compare**, refusing on a mismatch (`BadNodeData`).

**Trade-off.** Memory is none beyond the index. For the backfilled range the heights still
come from the node (see §3.3).

**Tests:**
- a mock node serving a skewed distribution: before the fix, the ring age statistics
  shift (the demonstration); after it, they are identical to an honest node;
- a call-recording mock proving that a `transfer` makes only `/info`, `/blocks`,
  `/px/*` and `/tx` calls.

### 3.3 The backfill is trusted (black marbles injected by a remote node)

**The problem.** `complete_index` accepts the keys, commitments, heights and coinbase flags
of every output below the restore height from `/outputs`. It checks only that they are
points and in height order (1841-1860). Nothing binds them to the chain: the wallet has no
blocks and no headers below its restore height.

**The attack.** A malicious node serves forged keys for the backfill range. Every decoy
drawn from that range is then a black marble known to the node, and the real input (always
above the restore height) stands out. The transaction is invalid everywhere else (the
CLSAG is over the wrong keys), but the node sees it. The wallet reuses the same ring
(W-5), because the forged index entries still "match", so the spend is stuck until
`clear-pending`.

**Severity.** Medium, for remote-node users with a late restore height. The effect is
DoS plus deanonymization of that attempt.

**Fix options:**
1. Verify the backfill against a compact, verifiable block feed. That feed is 39's design:
   compact blocks with a `tx_root` check and a header chain, plus a header PoW check
   (W-F6). **P2.**
2. **Rejected:** drawing decoys only from scanned outputs. That truncates the distribution
   at the restore height, and every ring then reveals the restore height.
3. Now: document it; the default and recommended setup is the user's own node.

**Invariant.** Backfill requests depend only on the restore height.

### 3.4 Rebroadcast, expiry and origin re-injection (coordinator question; with 12 and 33)

**Current behaviour [src]:**
- **Wallet.** Every sync with `synced ≥ relayed_height + 20` re-POSTs the unchanged
  transaction (`wallet.rs:1490-1505`).
- **Node, transaction pooled.** `precheck` returns `AlreadyKnown`, so nothing is relayed
  (`mempool.rs:231-234`).
- **Node, transaction not pooled** (restart: the mempool is RAM-only, with no persistence
  anywhere in `chain`, `node` or `p2p`; or a policy expiry): `Network::submit_tx` →
  `check_tx` passes → `stem_or_fluff(Source::Local)` → **`StemTx` to a stem peer**
  (`net.rs:482-491, 2502-2550`).
- **Stem peer that still pools it.** `on_stem_tx` → `check_tx` → `AlreadyKnown` → silently
  dropped (`net.rs:2470-2498`).
- **No node re-announces pool transactions.** `announce_tx` is called only on fluff
  (`net.rs:2431, 2586`). There is no mempool sync on connect.

**The problem.**
- An honest relay never emits a `StemTx` for a transaction that has long been fluffed.
  Only an origin whose wallet resubmitted does that.
- So a first-hop stem spy that still pools the transaction learns "this peer is the
  origin" with near certainty. That is an origin oracle outside Dandelion++'s model,
  which assumes one broadcast per transaction.
- It fires in two cases:
  - **(i)** the origin node restarts while the transaction is pending for 20 or more
    blocks;
  - **(ii)** the origin's pool expires the transaction while others still hold it.
- **Under 12's proposal (expiry counted from each node's own admission height, applied in
  `finish_sync`),** case (ii) is likely:
  - 2160 = 108 × 20, and the wallet's `relayed_height` equals the height at which the
    network admitted the transaction (propagation takes seconds, blocks take 120 s);
  - so the wallet's rebroadcast lands on the very block at which its own node expires the
    transaction;
  - the transaction is re-stemmed at once, while peers that connect that block a few
    seconds later still pool it.
- **Even with no oracle,** each re-injection after network-wide expiry is a new, linkable
  sample of the same origin (the same tx id). This is Dandelion++'s intersection concern,
  and F13-2 raises it for griefing.

**Classification.** Privacy-critical (network origin). Policy only. It becomes live as soon
as W5 (expiry) of 12 lands.

**Prior art:**
- **Bitcoin Core:**
  - "only the source wallet rebroadcasts … quite frequently" was identified as a privacy
    leak (PR #16698);
  - PR #18038 (in 0.21) moved initial-broadcast retries into the node's *unbroadcast set*
    (retried every 10-15 min until a peer sends GETDATA) and cut wallet rebroadcast to
    once per 12-36 h;
  - node-level rebroadcast of "should-have-been-mined" transactions (PR #21061) gives
    cover to the origin.
- **Monero `tx_pool.cpp`:**
  - **every node** re-relays **every** fluffed pool transaction with a backoff
    (`MIN_RELAY_TIME` 300 s, growing to `MAX_RELAY_TIME` 4 h);
  - it stops after half the lifetime;
  - expired transactions go to `m_timed_out_transactions`, which prevents their
    re-acceptance;
  - lifetime `CRYPTONOTE_MEMPOOL_TX_LIVETIME` = 3 days.
- **Private broadcast** (Bitcoin Core 31, PR #29415): re-sends go over a fresh Tor
  connection.

**Recommendation (answer to 12's open question and to decisions.md "pending agent 38"):**
1. **Expiry value: 2160 blocks for all classes is acceptable** (Monero parity). Privacy
   favours a long expiry, because re-injections for a stuck transaction number about
   (stuck time)/E. Keep one value for all classes, deploys included (their deployer is
   privacy-relevant, I2-F5). The 8 MiB deploy sub-pool (14) bounds memory. If 12/14 still
   want 720 for deploys, the wallet logic below takes the value per class.
2. **Node, a recently-expired set** (owner 12): for R = 30 blocks after expiring a
   transaction, the node refuses it on `/tx` and on relay, with a new `Expired` answer,
   and does not stem it. This is Monero's `m_timed_out_transactions`. Every honest node
   then drops it within the same window, before anyone re-injects it. This removes case
   (ii).
3. **Node, pool re-announcement** (owner 33, with 30):
   - every node re-announces (fluff `InvTx`, trickled) each pool transaction that has
     been pooled for at least 10 blocks and would have fitted the last template;
   - exponential backoff: 10, 20, 40 … blocks, capped at 360, stopping after E/2;
   - peers that lost it (restart) re-fetch it through the existing `GetTx`, which heals
     pools with no origin signal;
   - bandwidth is 32 B per inv.

   This removes most of case (i), because the restarted origin node gets the transaction
   back from its peers before its wallet's next probe.
4. **Node, persistence (P2, owner 35):** save the mempool, including the stempool's local
   entries, across restarts, as Bitcoin Core's `mempool.dat` and Monero's LMDB pool do.
   This removes case (i) entirely.
5. **Wallet (owner 38):**
   - **(a)** make the 20-block resubmission a **probe**: if the node answers
     `AlreadyKnown`/`Conflict`, do nothing, as today;
   - **(b)** if the node lacks the transaction, do **not** re-inject before
     `relayed_height + E + R` (network-wide expiry plus the guard), unless the original
     submission was `Uncertain` and has never been confirmed as received;
   - **(c)** after that point, re-inject once, at a random extra delay (uniform 0-20
     blocks), through private broadcast or a fresh isolated SOCKS circuit when available
     (§3.5, I3 §3.3);
   - **(d)** retry an `Uncertain` submission at the **next** sync, not after 20 blocks
     (liveness: the submission most likely never arrived);
   - **(e)** rename `PENDING_EXPIRY_BLOCKS` to `REBROADCAST_PROBE_BLOCKS` and add
     `NETWORK_EXPIRY_BLOCKS = 2160 + 30`, taken from `chain` constants so that wallet and
     node cannot drift.
6. **Optional RPC** (owner 36): `GET /tx/status?id=` → `{pooled | stem | expired | unknown}`.
   The wallet then never POSTs the full transaction to probe. It reveals nothing new to a
   node that already has the transaction.

**Trade-offs:**
- A genuinely lost transaction (every pool restarted, no persistence) waits up to
  E + R ≈ 3 days before re-injection. That is acceptable while persistence (item 4) is
  pending, and the user can force it with `rebroadcast --now`, with a warning.
- Re-announcement costs a little bandwidth, and its trickle timers must be the shared
  inbound timers (R8-16).

**Tests:**
- **p2p:**
  - a node restarted with an empty pool gets a pending transaction back from peers
    through re-announcement, and **no `StemTx` for it is ever sent** (a counter);
  - an expired transaction resubmitted within R returns `Expired` and emits nothing;
  - after R it is stemmed once.
- **wallet e2e (mock node):**
  - a node lacking the transaction before E + R gets no POST;
  - an `Uncertain` submission is retried at the next sync;
  - a re-injection happens at most once per E.
- **chain:** expiry at exactly N; the recently-expired set is evicted after R.

**Invariants (never change):**
- unchanged rebroadcast;
- never rebuild with a new ring;
- reserve-before-send;
- no transaction expiry *field* (never-change 29).

### 3.5 Wallet SOCKS5 in pure Rust (roster Q3; R3-9, P1-7)

**The problem.** The wallet speaks plaintext HTTP. It cannot reach a node over Tor except
through an external forwarder.

**Options, researched:**

| Option | Pure Rust / unsafe | New crates | Notes |
|---|---|---|---|
| **reqwest 0.12.28 feature `socks`** | the implementation is `hyper_util::client::legacy::connect::proxy::socks::v5`; `grep unsafe` over hyper-util 0.1.20's `connect/proxy` tree gives **0** hits | **none**: `socks = []` in reqwest's Cargo.toml, and hyper-util's `client-proxy` is already in our lock through reqwest | supports RFC 1929 user/pass (`with_auth`). **Pitfall:** reqwest maps `socks5://` to **local DNS** and only `socks5h://` to proxy DNS (`reqwest-0.12.28/src/connect.rs:540-541`). The wallet must force `socks5h` |
| Reuse `p2p/src/socks5.rs` | our own code, forbid-unsafe, async tokio; no auth | none | would need a custom blocking connector and RFC 1929 support; more code to own |
| `tokio-socks`, `socks` 0.2.3 | third-party; not reviewed here | adds crates | unnecessary |

**Recommendation (P1, owner 38 for the wallet, rpc client shared with 36):**
- `Client::with_proxy(base, proxy: SocketAddr, isolation: &str)`. It builds a reqwest
  client with `Proxy::all("socks5h://…")` and `basic_auth(random_user, random_pass)`.
- Tor's `IsolateSOCKSAuth` is on by default (tor manual), so distinct credentials give
  distinct circuits.
- **Two clients, two credential sets:**
  - one for sync and queries;
  - a **fresh** one per submission (and per re-injection).
- Allow `.onion` node addresses (passed to the proxy as domain names).
- **Refuse** plain `socks5://` and any clearnet host when `--proxy` is set, with no
  fallback.
- Keep `.no_proxy()` (no environment proxies). Keep `https` refused (no TLS stack; Tor
  onion services authenticate the endpoint).
- **Crucial:** with §3.2's fix there is no spend-time query, so the submit circuit is not
  timing-linked to a query.
- **Tests:**
  - a mock SOCKS5 server (pattern of `socks5.rs` tests) checks that the greeting offers
    method 2, credentials are sent, and ATYP = 3 (domain) for onion and DNS names;
  - two submissions use different credentials;
  - `socks5://` is refused;
  - no DNS lookup happens (the target is a name).
- **Docs:** the wallet threat model for remote nodes (§5 in the plan).

**Dependency check:** 44 must confirm that enabling the reqwest `socks` feature changes no
lockfile entries (expected: only the feature set).

### 3.6 Hedged decoy selection (F18-4, owned here with 18's derivation spec)

**The problem** (18 P-D). Decoys come from the wallet's raw ChaCha20 (`wallet.rs:1960`).
Two wallet instances with a cloned RNG state spend different outputs, so their decoys
largely coincide and the rings differ exactly at the real inputs.

**Classification.** Medium, privacy-critical, conditional on an RNG failure.

**Design (confirms 18, with two additions):**
- **The stream:** one `HedgedStream` per input (18's W2), with:
  - key = the derived hedge key (decisions: domain-separated from `k_s`, final form with
    37);
  - context: `wallet/decoys/v1`, network id, **genesis id**, branch id, `next`, the real
    input's `(global_index, one_time_key)`, and the sorted `keep` list with its count;
  - fresh 32 bytes from the wallet RNG.
- **Addition 1:** the genesis and branch ids, so rehearsal and release chains never share
  streams.
- **Addition 2:** a **per-input** stream, so the inputs of one transaction draw
  independently.
- **Floating point:** the picker uses `exp`, `ln` and `cos` (libm). Bitwise ring vectors
  are therefore **not portable** across platforms. Pin the *stream* bytes, not rings.
  Statistical equivalence is tested by KS (below).

**Tests:**
- `cloned_rng_state_spending_different_outputs_gives_unrelated_decoys`: shared decoys at
  most the independent baseline + 3σ;
- `broken_rng_same_output_same_height_same_ring`;
- a two-sample KS between hedged and unhedged depths, 50k draws, seeded, D below the
  α = 0.001 critical value;
- the stream-bytes vector.

### 3.7 Exact v1 fee (coordinator open decision, with 14 §3.4 and 11)

**Question:** should T8 become `fee == FEE_PER_WEIGHT × max_weight(n_in, n_out)`?

**Evidence:**
- **Rucknium, Monero non-standard fees:**
  - after the 2022 fork, about 10 % of transactions carry non-standard fees, in at least
    five clusters that single out wallet implementations;
  - the positive predictive value of guessing the ring member created by a
    same-fingerprint transaction reaches **62 %** (29-32 nanoneros/byte cluster), against
    6.25 % by chance;
  - a fee fingerprint therefore marks both the transaction and, through its change output,
    later **real inputs**.
- **Monero research-lab #70:** high-precision dynamic fees leak the creation-to-mining
  time.
- **Hammad & Victor (IEEE ICBC 2024):** wallet-application bugs are among the most
  effective traceability heuristics.
- **BlackSilk already makes the PX and deploy fees exact.** v1 is the only kind whose fee
  is a free field.

**Assessment:**
- **Privacy:** positive. It removes an entire class of wallet fingerprint (third-party
  wallets, "priority" users, buggy fee code) and any timing channel through fees.
- **Cost:**
  - there is no priority escape. But the official wallet is already exact, so honest
    users cannot outbid today either (12 P4);
  - congestion is then handled by policy (12's ZIP-401-style random eviction and the
    expiry).
- **Consensus surface:**
  - `max_weight` becomes validity-defining for transfers. It is already so for deploys
    (`deploy_fee`);
  - pin it with golden vectors for (1,2), (2,2), (16,2), (64,16) and (1,16);
  - a property test that `max_weight(n,k) ≥ weight(tx)` for all valid shapes (so that
    T8-min is implied);
  - route it through `TxRules` (14 FE-5) so that a later activation can relax it to
    tiers (R-FEE1), which the schedule allows.
- **Identity:** it rides the v3 reset (free now).

**Recommendation: adopt T8-exact at the v3 genesis.** It needs the full consensus record:
- a demonstration test (a +1 overpayment is accepted today);
- a golden vector;
- `validate.rs` owned by 11;
- a wallet e2e check (unchanged fees);
- 50's review.

Severity of the status quo: Low on the testnet (the official wallet is exact), Medium for
mainnet (third-party wallets).

### 3.8 PX transaction timing

**Items [src]:**
- **The anchor** is the synced height rounded down to 16 (`px.rs:91-93`). It reveals the
  wallet's sync time to 16-block precision, and any lag between sync and submission
  (stale wallets stand out). Low.
- **Proving signature:** about 45 s of CPU, then a 2.2 MB upload. This origin signal is
  R3-10/R8-18, an accepted limitation.
- **Anchor expiry (100 blocks) → `Invalid` → a re-prove republishes the same nullifiers**
  (R5-12). That is a linkable second broadcast, like §3.4.
- **Bridge timing:** deposit → spend → withdraw (R3-8).

**Recommendations:**
- sync immediately before proving (it does, through `self.sync` in each operation [src]);
- document the anchor granularity;
- route re-proves through §3.4's re-injection rules;
- bridge hygiene with random delays is P2 (R3 #11).

No consensus change.

### 3.9 Coinbase-dominated rings (R3-3), black-marble floods

**Status.** Accepted limitation for the testnet, with the documentation owed.

**New quantification:**
- a black-marble flood is cheap: about 0.000345 BLK per 1-in/2-out transaction, and fees
  are recycled to miners (14 FE-9);
- on a quiet chain a flooder can own most non-coinbase outputs for a few BLK a day;
- Rucknium's 2024 Monero flood analysis found a measurable fall in effective ring size,
  and that ring size, not fees, is the cost-effective defence.

**For BlackSilk:**
- ring size is consensus-fixed at 16;
- the real remedy is PX (full-set) or shielded coinbase (P3, R3-11);
- coinbase-segregated decoys (I3/I4 fallback) are **not** recommended now: on a young
  chain the non-coinbase pool is too small, and segregation reveals the input type;
- revisit it with the statistical suite once non-coinbase outputs are ≥ 10⁵ (P3).

### 3.10 Metadata leakage inventory (roster Q4)

| # | Channel | Observer | What leaks | Status / fix |
|---|---|---|---|---|
| 1 | IP ↔ transaction | remote node, on-path | the whole transaction | SOCKS (§3.5), own node |
| 2 | Restore height (`/blocks` start, backfill extent, `/px/*?from`) | remote node | wallet birthday | inherent to download-from-birthday; the versioned seed with birthday (37) makes it coarse by design (round birthdays to 720 blocks) |
| 3 | Spend start (`/distribution`) | remote node | spend intent, circuit link | **fix §3.2** |
| 4 | Decoy distribution from the node | malicious remote node | ring quality degraded | **fix §3.2** |
| 5 | Backfill contents | malicious remote node | black-marble decoys | §3.3 (P2 via 39) |
| 6 | Rebroadcast / re-injection | stem peers | origin oracle, repeated samples | **§3.4** |
| 7 | Sync cadence | remote node, ISP | online times | document; randomize the auto-sync interval if a daemon mode is added |
| 8 | Fee | chain | wallet implementation, creation time | exact fee §3.7 |
| 9 | Shape (n_in, n_out) | chain | consolidations; default 2 outputs | document |
| 10 | Ring ages | chain | guess-newest | §3.1 |
| 11 | Co-spent sources | chain | real inputs | merge avoidance (done) |
| 12 | Co-spent accounts (`select_inputs` over all accounts) | chain | account linkage | R11-W10 (accounts nominal) |
| 13 | PX anchor | chain | sync lag | §3.8, document |
| 14 | PX size and CPU | ISP | origin | accepted (R3-10) |
| 15 | Bridge amounts | chain | round trips | R3-8 |
| 16 | Key image on a re-spend after `clear-pending` | chain | links two spends | warned (`wallet.rs:1251-1256`) |
| 17 | Restore loses rings (W-5 residual) | chain | ring intersection | document; the seed cannot restore rings |
| 18 | RNG failure | chain | decoys (F18-4) | §3.6 |
| 19 | Logs, wallet file | local | history | 0600, encrypted (done) |

---

## 4. New findings

| ID | Severity | Status | Location | Scenario | Confidence |
|---|---|---|---|---|---|
| **F38-1** | **Medium** (remote-node users) | Not implemented | `wallet/src/wallet.rs:1888-1903` | A malicious remote node returns a distorted but monotone `/distribution` with the correct total. The decoys skew old, the young real input becomes the newest member, and the same node receives the transaction by `/tx`. The local index already has every height, so the node's distribution is unnecessary | High (mechanism, [src]); magnitude [unknown] |
| **F38-2** | Medium (remote-node users, late restore) | Accepted limitation until 39's verified feed | `wallet/src/wallet.rs:1809-1866`, `index.rs:123-141` | Forged backfill keys make every pre-restore decoy a black marble. The node identifies the real input from the (invalid) transaction, and W-5 keeps reusing the poisoned ring | High [src] |
| **F38-3** | **Medium** (origin privacy) | Not implemented | `wallet.rs:1490-1505`; `p2p/src/net.rs:482-491, 2470-2498`; no mempool persistence; no pool re-announce | A node restart, or 12's admission-based expiry (2160 = 108 × 20 makes the origin's own expiry and its wallet's rebroadcast coincide), makes the origin re-stem a transaction that its stem peer still pools: an origin oracle. Every re-injection is also another linkable Dandelion++ sample | High [src] for the mechanism; likelihood depends on 12's final expiry rule |
| **F38-4** | Low (claims) | Not implemented (docs) | `docs/transactions.md` §11.3.1; `autonomous-session-2026-09-27.md` §3 ("90 % → 52 %") | The 52 % guess-newest figure holds for a 3-day chain only. Chain-length truncation (`decoy.rs:209-211`) inflates young mass. On a mature steady chain a 12-block spend is the newest member in about 84-89 % of rings | High [math + sim] |
| **F38-5** (= F18-4) | Medium (conditional) | Not implemented | `wallet.rs:1960`, `decoy.rs:119-150` | A cloned RNG gives shared decoys, and the rings differ at the real inputs | High (mechanism) |
| **F38-6** | Low | Not implemented | `wallet.rs:1888` | The spend-time `/distribution` marks spend intent and links Tor query and submit circuits by timing | High |
| **F38-7** | Low (liveness/UX) | Not implemented | `wallet.rs:1490`, `submit` 1382-1383 | An `Uncertain` submission (most likely never received) waits 20 blocks (about 40 min) before its first retry | High |
| **F38-8** | Informational | Not implemented | `rpc/Cargo.toml`; `reqwest-0.12.28/src/connect.rs:540-541` | Wallet SOCKS is available at no dependency cost. A `socks5://` URL would do **local DNS** (a leak); only `socks5h://` is safe | High (local registry read) |
| **F38-9** | Low | Not implemented | `decoy.rs:183-187` | `average_output_time` is computed over the whole chain; Monero uses at most one year. It diverges once the chain is over one year old or its usage changes; parity is needed before mainnet | High [src] |
| **F38-10** | Informational (regression guard) | Complete but requires further testing | `decoy.rs:175-179` vs `validate.rs:414-420` | Exactly-10-block decoys are drawable (no Monero #8872 bug), but no test pins it | High [src] |
| **F38-11** | Low (testnet) / Medium (mainnet) | Accepted limitation unless the owner adopts §3.7 | `tx/src/validate.rs:353-359` | T8 "≥" lets any non-standard fee fingerprint a wallet and, through change outputs, its later real inputs (Rucknium: 62 % PPV) | High |
| **F38-12** | Informational | — | `decoy.rs:59-84` | The picker uses f64 libm transcendentals, so cross-platform bitwise ring vectors are not possible. Conformance for third-party wallets needs a distributional spec and tests | High |
| **F38-13** | Accepted limitation | Accepted (testnet) | chain economics | Black-marble floods are cheap on a quiet chain (about 0.000345 BLK per transaction, fees recycled to miners). Ring size is fixed | Medium [math] |

---

## 5. Implementation plan for phase 2

| # | Work item | Files (ownership) | Consensus? | Identity | Tests | Bench | Docs | Size | Pri |
|---|---|---|---|---|---|---|---|---|---|
| W1 | **Local distribution; no spend-time query** (F38-1, F38-6): `OutputIndex::cumulative()` (cached per sync); `plans_for` and `coinbase_limit` use it; drop `/distribution` from `plans_for`; optional compare at sync | `wallet/src/index.rs`, `wallet/src/wallet.rs` (`plans_for` only) | nothing visible | none | skewed-distribution mock (demo, then fixed); a call-recording mock asserting the endpoints during `transfer`; index cumulative unit tests incl. reorg rewind | spend latency on 10⁶ outputs (a `#[ignore]` timing test) | transactions.md §11.3.1 ("the node serves no spend-time data") | S | **P1** (P0-pub) |
| W2 | **Statistical decoy suite** (gates W3, W6, W7): steady-chain CDF vs reference (seeded, KS); §2.4 guess-newest table bounds; exactly-10-block frequency > 0 and within tolerance; recent-window mass; young-chain (existing); F13-7 (duplicate-`O` outputs remain eligible); coinbase share on a mixed chain | `tx/tests/decoy_statistics.rs` (new, owner 38); small additions to `tx/src/decoy.rs` tests | none | none | itself; bounded case counts (< 30 s in release) | — | §11.3.1 figures replaced by the suite's output | M | **P1** (the suite is the roster's acceptance item) |
| W3 | **Hedged decoys** (F18-4) with 18's `HedgedStream`, per input, context incl. genesis and branch ids | `wallet/src/wallet.rs` (`plans_for` only); consumes `crypto/src/nonce.rs` (18 W2) and the derived hedge key (37) | none | none | cloned-RNG, same-output-same-ring, KS equivalence, stream-bytes vector | — | transactions.md §10 table row, "Other RNG uses" | S | P1 |
| W4 | **Rebroadcast redesign, wallet side** (F38-3, F38-7): probe semantics; no re-injection before `relayed + E + R`; a single random-delayed re-injection over a fresh circuit; `Uncertain` retried next sync; constants from `chain` | `wallet/src/wallet.rs` (`refresh_pending`, `submit`, constants) | policy (wallet) | none | e2e with a mock node (see §3.4) | — | transactions.md §11 new "rebroadcast" paragraph; wallet-review.md W-6 | S–M | **P1** (lands with 12 W5) |
| W4n | **Node side** of §3.4: recently-expired set R = 30 and the `Expired` answer (**owner 12**, `chain/src/mempool.rs`); pool re-announcement with backoff (**owner 33/30**, `p2p/src/net.rs`); optional `/tx/status` (**owner 36**); mempool persistence (**owner 35**, P2) | as listed | policy | none | as in §3.4 | inv bandwidth in labnet | p2p.md §8, blocks.md §7 | M | **P1** (the expired set is **P0 if 12's W5 expiry lands before the trial**) |
| W5 | **Wallet SOCKS5**: reqwest `socks` feature; `socks5h` forced; random RFC 1929 credentials; a separate client per submission; `.onion` allowed; no clearnet fallback | `rpc/Cargo.toml`, `rpc/src/lib.rs` (`Client::with_proxy`; coordinate with 36), `wallet/src/main.rs` (`--proxy`), `wallet/src/node.rs` (a submit client) | none | none | mock SOCKS5 server tests (method 2, ATYP 3, distinct credentials, `socks5://` refused) | — | wallet README / transactions.md §11.2 ("the wallet has no Tor" → how to use `--proxy`), remote-node threat model | S–M | **P1** |
| W6 | **Young-spend warning** (P1) and **opt-in `--spend-delay short|long`** (P2), with the restricted-picker target | `wallet/src/wallet.rs` (`select_inputs` / a new `spend_policy`), `wallet/src/main.rs`; `tx/src/decoy.rs` (`sample_depth_in(range)`, a public helper) | none | none | KS: the delay targets match the restricted picker; the window table reproduced ±0.03 | — | §11.3.1 table (§3.1 of this dossier) | S (warn) / M (delay) | P1 / P2 |
| W7 | **One-year `average_output_time` window** (Monero parity) | `tx/src/decoy.rs` (`Picker::new`) | none | none | W2 suite unchanged on chains < 1 year; a new > 1-year chain case | — | §11.3.1 | S | P2 (before mainnet) |
| W8 | **T8-exact v1 fee** (if the owner approves) | `tx/src/validate.rs` (**owner 11**), `tx/src/builder.rs` (`max_weight` vectors), `tx/src/params.rs` (via `TxRules`, 14 FE-5); wallet test by 38 | **CONSENSUS** | v3 (free) | demo (fee + 1 accepted today → rejected); golden `max_weight` vectors; property `max_weight ≥ weight`; wallet e2e unchanged | — | transactions.md T8, §11.3 table | S | **P0 decision** / P1 impl |
| W9 | **Docs**: F38-4 figure correction (mature-chain numbers); remote-node trust (F38-1/2); rebroadcast behaviour; SOCKS usage; the leak inventory (§3.10); PX anchor granularity | `docs/transactions.md` §11 (content 38, edits coordinated by **47**), `docs/reviews/assumptions.md` P7 | none | none | — | — | as listed | S | **P0** (claims) |
| W10 | **Picker spec for third-party wallets** (normative pseudocode, `decoy/v1`, distributional conformance test with published tolerances) | `docs/transactions.md` §11.3.1 (47), `tx/tests/decoy_statistics.rs` | none | none | the conformance test | — | yes | S | P2 |
| W11 | **Verified backfill** (F38-2) through 39's compact feed plus a header PoW check | `wallet/src/wallet.rs` (`complete_index`), with **39** | none | none | forged-backfill mock refused | — | yes | M | P2 |

**Ordering:**
1. W9 (docs, P0).
2. W2 (the suite), then W1.
3. W3 after 18 W2 and 37's hedge key.
4. W4 together with 12's W5 and W4n.
5. W5.
6. W6, W7, W10, W11.

W8 follows the owner's decision.

**`wallet/src/wallet.rs` is shared with 37, 39, 17 and 18 (W4).** W1, W3 and W6 touch only
`plans_for`/`select_inputs`; W4 touches only `refresh_pending`/`submit`. The coordinator
should serialize them.

---

## 6. Dependencies and conflicts

| # | Workstream | Dependency or conflict |
|---|---|---|
| 12 | mempool-architecture | expiry value and reference (2160 confirmed; the recently-expired set R = 30 is required); `Expired` error variant |
| 14 | fee-economics | T8-exact (§3.7); `TxRules` routing (FE-5) |
| 11 | tx-validation | owns `validate.rs` T8 |
| 18 | crypto-randomness | `HedgedStream` (W2), derivation spec; W3 statistics validated by my W2 |
| 37 | wallet-keys | derived hedge key; seed birthday granularity (leak 2); `wallet.rs` edits |
| 39 | wallet-sync-scanning | compact verified feed for the backfill (W11); `index.rs` ownership overlap (W1 adds a method); a sync-time distribution compare |
| 33 / 30 | dandelion / p2p | pool re-announcement; private broadcast for re-injections; shared trickle timers (R8-16) |
| 36 | rpc-security | `/tx/status`; `Client::with_proxy` in `rpc/src/lib.rs`; remote-node threat model |
| 35 | storage | mempool persistence (P2) |
| 13 / 17 | C4 / stealth | F13-7: decoys never exclude duplicate `O` (my W2 test); `apply_block` dedupe (17) touches the same file |
| 41 | fuzzing-property | statistical test conventions (seeded, bounded) |
| 44 | supply-chain | confirm the reqwest `socks` feature adds no crate or unsafe |
| 47 | docs | §11 edits |
| 50 | red-team | review of W4/W4n (oracle closure) and W8 |

---

## 7. Open questions for the coordinator

1. **Expiry reference.** Is 12's admission-height expiry kept? Then the recently-expired
   guard (R = 30) is mandatory in the same change. Alternatively, it could be counted from
   the transaction's first sighting by any honest node, but that is not uniform. I
   recommend admission height plus the guard.
2. **Deploy expiry.** Uniform 2160 (my preference, for privacy uniformity) or 720 (14)?
3. **T8-exact at the v3 genesis:** recommended yes; the owner decides.
4. **Spend-delay default:** off for the testnet with the warning on, and the mainnet
   default for the owner?
5. **Mempool persistence (35):** P2 as proposed, or P1 given F38-3?
6. **`/tx/status` RPC (36):** acceptable, or keep the POST-as-probe?

---

## 8. Sources

**Decoy selection:**
- Rucknium, *OSPEAD*: repository https://github.com/Rucknium/OSPEAD ; Monero blog
  2025-04-05 https://www.getmonero.org/2025/04/05/ospead-optimal-ring-signature-research.html ;
  documentation https://rucknium.github.io/OSPEAD/CCS-milestone-2/OSPEAD-docs/_book/
- Möser et al., "An Empirical Analysis of Traceability in the Monero Blockchain", PoPETs
  2018(3): https://petsymposium.org/popets/2018/popets-2018-0025.php
- Kumar, Fischer, Tople, Saxena, "A Traceability Analysis of Monero's Blockchain",
  ESORICS 2017: https://eprint.iacr.org/2017/338
- Ronge, Egger, Lai, Schröder, Yin, "Foundations of Ring Sampling", PoPETs 2021:
  https://petsymposium.org/popets/2021/popets-2021-0055.php
- Monero `wallet2.cpp` `gamma_picker` (1-year window, `RECENT_SPEND_WINDOW` = 15·T):
  https://github.com/monero-project/monero/blob/master/src/wallet/wallet2.cpp
- Monero issue #7807 (recent outputs never selected):
  https://github.com/monero-project/monero/issues/7807 ; PR #7821 (gamma from tip):
  https://github.com/monero-project/monero/pull/7821
- Monero issue #8872, post-mortem of the 10-block-old decoy bug (fixed in PR #8794):
  https://github.com/monero-project/monero/issues/8872
- Monero PR #4691, sanity-check of the daemon's rct distribution:
  https://github.com/monero-project/monero/pull/4691

**Wallet fingerprinting and floods:**
- Rucknium, Monero non-standard fees:
  https://github.com/Rucknium/misc-research/tree/main/Monero-Nonstandard-Fees
- Monero research-lab #70 (fee timing leak):
  https://github.com/monero-project/research-lab/issues/70 ; monero #5711:
  https://github.com/monero-project/monero/issues/5711
- Hammad and Victor, "Monero Traceability Heuristics: Wallet Application Bugs and the
  Mordinal-P2Pool Perspective", IEEE ICBC 2024: https://arxiv.org/abs/2408.05332
- Rucknium, black-marble flood analysis:
  https://github.com/Rucknium/misc-research/blob/main/Monero-Black-Marble-Flood/pdf/monero-black-marble-flood.pdf ;
  research-lab #119: https://github.com/monero-project/research-lab/issues/119

**Rebroadcast and expiry:**
- Bitcoin Core PR #16698 (rebroadcast privacy rationale):
  https://github.com/bitcoin/bitcoin/pull/16698 ; PR #18038 (unbroadcast set, wallet
  rebroadcast every 12-36 h): https://github.com/bitcoin/bitcoin/pull/18038 ; PR #21061
  (node rebroadcast module): https://github.com/bitcoin/bitcoin/pull/21061 ; review club:
  https://bitcoincore.reviews/18038 ; 0.21.0 notes:
  https://bitcoincore.org/en/releases/0.21.0/
- Monero `tx_pool.cpp` (`get_relayable_transactions`, `get_relay_delay`,
  `m_timed_out_transactions`):
  https://github.com/monero-project/monero/blob/master/src/cryptonote_core/tx_pool.cpp ;
  PR #8326 (re-relay backoff fix): https://github.com/monero-project/monero/pull/8326
- Fanti et al., "Dandelion++: Lightweight Cryptocurrency Networking with Formal Anonymity
  Guarantees", SIGMETRICS 2018: https://arxiv.org/abs/1805.11060

**Remote nodes and Tor:**
- Monero `docs/ANONYMITY_NETWORKS.md`:
  https://github.com/monero-project/monero/blob/master/docs/ANONYMITY_NETWORKS.md
- Shi et al., "Deanonymizing Monero Transactions in Tor Network" (ProxyMark),
  arXiv:2607.07062: https://arxiv.org/abs/2607.07062
- Bitcoin Core private broadcast, PR #29415: https://github.com/bitcoin/bitcoin/pull/29415
- Tor manual, SocksPort flags (`IsolateSOCKSAuth` on by default):
  https://2019.www.torproject.org/docs/tor-manual.html.en
- RFC 1928 (SOCKS5): https://www.rfc-editor.org/rfc/rfc1928 ; RFC 1929 (username/password):
  https://www.rfc-editor.org/rfc/rfc1929
- reqwest 0.12.28 (`socks = []`; `src/connect.rs` DNS mapping) and hyper-util 0.1.20
  (`client/legacy/connect/proxy/socks/v5`, no `unsafe`): read from the local cargo
  registry; upstream https://github.com/seanmonstar/reqwest ,
  https://github.com/hyperium/hyper-util

**Zcash:**
- Kappos, Yousaf, Maller, Meiklejohn, "An Empirical Analysis of Anonymity in Zcash",
  USENIX Security 2018:
  https://www.usenix.org/conference/usenixsecurity18/presentation/kappos
- ZIP 203 (expiry field, rejected here as a fingerprint): https://zips.z.cash/zip-0203 ;
  ZIP 401: https://zips.z.cash/zip-0401
