# 33 dandelion-network-privacy: research dossier (phase 2, phase 1)

Internal engineering research, not an audit. Nothing here claims that BlackSilk's network
layer is secure or private. Every anonymity figure below is a **simulation or calculation
under a stated model**, not a measurement of a deployed network.

Evidence tags: **[M]** mathematically established or a calculation; **[S]** simulation
(reproducible script, described in §2.5); **[T]** tested (test named); **[SR]** source-read;
**[A]** assumed or taken from an external source; **[U]** unknown.

---

## 1. Scope and what I read

**Commit:** `rebuild/core` = `9e422d8` (`git rev-parse --short HEAD`). Read-only; no build,
no cargo, no repository file changed.

**Code (read in full or in the relevant ranges):**
- `p2p/src/dandelion.rs` (all 233 lines, including its 4 unit tests);
- `p2p/src/net.rs`: config and state (90-300), `submit_tx` (480-491), `announce_tx`
  (775-800), `connect_outbound`/`advertised_listen` (900-940), handshake and registration
  (953-1130), read loop and cleanup (1180-1225), `handle` (1270-1326), `on_get_addr` /
  `on_addr` (1328-1385), `on_inv_tx` / `on_get_tx` / `retry_tx` (2041-2135), `stem_keys`
  (2146-2153), `admit_tx` (2186-2320), `on_tx` (2386-2438), `on_stem_tx` (2446-2498),
  `stem_or_fluff` (2501-2542), `send_held_local_txs` (2546-2569), `fluff` (2572-2591),
  `maintenance_loop` (2594-2760);
- `p2p/src/lib.rs` (`#![forbid(unsafe_code)]`), `p2p/src/addrman.rs` (`sample`),
  `node/src/config.rs` (listen/proxy/public address), `node/src/lib.rs` (`/tx` handler,
  260-295), `chain/src/manager.rs` (`check_tx`/`submit_tx`, 1203-1214),
  `chain/src/mempool.rs` (no persistence, no expiry today), `wallet/src/wallet.rs`
  (`PENDING_EXPIRY_BLOCKS`, `submit`, `refresh_pending`: 60-82, 245-262, 1330-1560).

**Tests read:** `p2p/tests/network.rs`: `transactions_travel_the_stem_then_fluff_everywhere`,
`mempool_cannot_be_probed_with_gettx`, `px_transactions_travel_the_stem_and_confirm_everywhere`,
`a_local_transaction_waits_for_a_stem_peer`, `conflicting_stem_transactions_are_not_verified`,
`announcing_a_stem_transaction_neither_reveals_nor_fluffs_it`,
`an_onion_address_is_not_advertised_over_clearnet`,
`replaying_a_pooled_transaction_costs_no_verification`,
`pings_are_answered_while_the_chain_lock_is_held` (and its `pong_latency` helper);
`dandelion.rs` unit tests (`routes_are_stable_within_an_epoch`,
`diffuser_fraction_and_epoch_rotation`, `no_outbound_means_fluff_and_lost_stems_are_replaced`,
`embargo_distribution`).

**Docs and reports:** `docs/p2p.md` (§1, §4, §7, §8, §9, §11, §12);
`docs/reviews/full-review-2026-09-27.md` (register rows for R3-4/5/6/10, R8-5/6/7/16/17/18/19,
I3-1/2/3, R10-10, P1-5, P2-19); `docs/reviews/autonomous-session-2026-09-27.md`;
`full-review-2026-09-27/I3-network-privacy.md` (whole), `R3-privacy.md` (§2.3, R3-5, R3-6,
R3-9, R3-10), `R8-p2p.md` (R8-16 … R8-19), `SX2-systems-crossreview.md` (§0, C7).
Phase-2 inputs: `C:/bszkeval/p2/brief.md`, `roster.md` (30-34, 12, 13, 38),
`decisions.md` (D8 = option B), `research/13-mempool-frontrunning-c4.md` (F13-2),
`research/12-mempool-architecture.md` (expiry 2160 blocks, rebroadcast note),
`research/10-block-validation-pipeline.md` §3.6 (the planned `VerifiedCache`).

---

## 2. Current state

### 2.1 What exists and is well designed

| Property | Evidence |
|---|---|
| Dandelion++ per Fanti et al.: epochs 9–11 min, 2 stems drawn from outbound peers, diffuser with q = 0.2, per-source fixed routes, embargo 10 s + Exp(39 s) | [SR] `dandelion.rs:40-53, 97-148`; [T] `routes_are_stable_within_an_epoch`, `diffuser_fraction_and_epoch_rotation`, `embargo_distribution` |
| The node's own transactions always stem, also in a diffuser epoch | [SR] `dandelion.rs:132`; [T] unit test only (no network-level test in a diffuser epoch) |
| Local transactions are held, not fluffed, while no stem peer exists | [SR] `net.rs:2520-2532, 2546-2569`; [T] `a_local_transaction_waits_for_a_stem_peer` |
| `InvTx` for a stempool id is answered like an unknown id (`GetTx`) and does not end the stem (I3-1 fix) | [SR] `net.rs:2065-2078`; [T] `announcing_a_stem_transaction_neither_reveals_nor_fluffs_it` |
| `GetTx` served only for transactions announced to that peer; uniform `NotFound` | [SR] `net.rs:2086-2115`; [T] `mempool_cannot_be_probed_with_gettx` |
| Stem conflicts dropped before verification (R8-7) | [SR] `net.rs:2466-2476`; [T] `conflicting_stem_transactions_are_not_verified` |
| Stem choice ignores peer-claimed height (the ProxyMark proxy-selection bias does not exist here) | [SR] `net.rs:2606-2611` (filter is `!inbound && relay_txs` only) |
| Onion `listen` only over Tor connections (I3-2 fix) | [SR] `net.rs:931-940`; [T] `an_onion_address_is_not_advertised_over_clearnet` |
| No user agent, clock or service bits in `Version` | [SR] `net.rs:983-991` |
| `#![forbid(unsafe_code)]`, no FFI; SOCKS5 is the only anonymity-network boundary | [SR] `p2p/src/lib.rs:14` |

### 2.2 What the tests actually prove

- The unit tests prove the **routing state machine** (stable routes per epoch, diffuser
  fraction ≈ q, embargo mean ≈ 49 s). They say nothing about anonymity.
- The network tests prove **three specific oracles are closed** (InvTx membership, GetTx
  probing, local fluff without stem) and one DoS property (conflict pre-check).
- **No test** covers: timing side channels; the trickle timer structure; GetAddr
  behaviour; re-submission of a transaction the network already holds; a diffuser-epoch
  origin; a black-holed local stem; or any statistical first-spy property. The roster's
  required "no oracle" regression suite does not exist yet [SR].

### 2.3 Open items inherited from the review (status at `9e422d8`)

| Item | Status [SR] |
|---|---|
| R8-16 per-peer inbound trickle timers, invs in arrival order | open: `net.rs:785-797` draws a fresh Exp per peer; `net.rs:2655-2659` sends the queue in insertion order |
| R3-6 / R8-19 GetAddr: fresh `sample(1000)` per connection, networks mixed, no cache | open: `net.rs:1328-1348`, `addrman.rs:195-210` |
| R8-17 origin embargo can fire first | open (quantified in §3.4) |
| R8-18 / R3-10 PX size reveals origin to the ISP | accepted limitation; docs still missing (p2p.md §1 lists "traffic analysis" as not protected but does not name PX) |
| R8-6 SOCKS stream isolation | open (32/30 scope) |
| R10-10 stem routing in debug logs | open: `net.rs:2530, 2538, 2566, 2585, 2622` |
| R6 MP-9 stem keys omit output keys and contract ids | output keys moot under D8 option B; contract ids still omitted (`net.rs:2147-2153`) |

### 2.4 The embargo parameters, recomputed

- Dandelion++ Proposition 3 (fail-safe timers, each Exp with mean `T_base`): to reach k hops
  without premature diffusion with probability ≥ 1 − ε,
  `T_base ≥ −k(k−1)·δ_hop / (2·ln(1−ε))` [A, arXiv:1805.11060].
- Monero's `tx_pool.cpp` states that its 39 s comes from k = 5, ε = 0.10, δ_hop = 175 ms
  [A, source comment]. With the natural logarithm that gives **16.6 s**; 39 s is what the
  formula gives with **log₁₀** (38.2 s) [M]. The error is in the conservative direction:
  with ln, 39 s corresponds to ε ≈ 4.4 % for 175 ms hops [M].
- BlackSilk's per-hop latency is not Monero's:
  - v1 transfer: a few kB plus about 3 ms per CLSAG input [A, R12] → δ ≈ 0.1–0.2 s. The 10 s
    base alone protects stems up to about 50–100 hops, so premature diffusion on an honest
    path is negligible [M].
  - PX: 2.2 MB transfer plus about 0.235 s verification [A, R12; SX2's 1.5 s/hop]. The paper's
    formula at δ = 1.5 s, k = 5, ε = 0.1 asks for a **142 s** mean [M]. BlackSilk's 10 s base
    covers about 6 PX hops; beyond that the Exp(39) part races the stem.
- Conclusion: the (q = 0.2, 39 s) pair was right to fix for v1 (R3-4), but it is **not
  tuned for PX**. §3.4 quantifies the effect.

### 2.5 Simulation model (for §3.3 and §3.4)

A 200-line Python script in my scratchpad (not repository code; the repository stays pure
Rust; W9 ports it to a Rust `#[ignore]` test). It mirrors the code at `9e422d8`:
- N nodes, each with 8 random outbound peers that **persist across broadcasts** (connections
  are long-lived); per epoch every node redraws 2 stems from its outbound peers and its
  diffuser flag (q = 0.2); per-source routes; the origin always stems.
- Fluff: every node announces to its outbound peers after Exp(2 s) and to its inbound peers
  after Exp(5 s), independent per peer (the current code), plus a fetch latency δ per hop.
- Adversary A: a fraction p of nodes are spies. Per broadcast, the first spy to see the
  transaction names its sender (the StemTx sender in stem phase; the first InvTx sender in
  fluff). Over k **linked** broadcasts (same key images or id, in different epochs): a
  plurality vote. This is a weak estimator; a maximum-likelihood adversary does better.
- Adversary B: a passive supernode connected inbound to every node, knowing the outbound
  graph, seeing only which node announces first; maximum likelihood under a random-walk
  stem model, over k linked broadcasts.
- Embargo model: honest path, origin timer 10 s + Exp(39 s), stem δ per hop, fluff back to
  the origin through the graph.

---

## 3. Problems in scope

### 3.1 Re-origination of a transaction the network already holds (NEW, F33-1)

**What and why.**
- The wallet rebroadcasts every unconfirmed transaction unchanged every 20 blocks (about
  40 min, `wallet.rs:1490-1494`). The node answers `AlreadyKnown` while it still pools the
  transaction, and nothing is relayed. That part is sound.
- The node **forgets** a pooled transaction on restart (the mempool is not persisted), and
  whenever its own pool evicts it (fee eviction, `mempool.rs:296`), or when agent 12's policy
  expiry (2160 blocks, counted from **this node's** admission) removes it first. The origin
  admitted it earliest, so it also expires it first.
- The wallet's next rebroadcast then passes `check_tx` and enters the stem as
  `Source::Local` (`net.rs:483-491`).
- Every relay that still pools it drops the `StemTx` silently (`admit_tx`, `net.rs:2257`):
  **the first hop is a black hole**. The origin's embargo fires (10 s + Exp(39 s)) and the
  origin announces an `InvTx` for an old transaction to every peer that does not "know" it
  (`fluff` → `announce_tx`, `net.rs:2572-2590, 777-800`). After a restart that is every peer.
- No other node re-announces old transactions (there is no mempool sync on connect [SR]).
  So an `InvTx` for a transaction first fluffed tens of minutes ago comes **only from its
  origin**, and every spy connected to the origin sees it. A spy that is the first stem hop
  also sees a `StemTx` for a transaction it already pools, which only the origin sends.

**Consequence.** Deterministic origin identification (probability ≈ 1 for any spy peer),
whenever the trigger occurs [M, SR]. Triggers are realistic for **PX**: 3 PX per block and
2.2 MB proofs mean PX transactions can wait many blocks; node restarts are routine (updates,
the poisoned-lock exit 70). This is the Bitcoin "only the source wallet rebroadcasts"
problem (Koshy et al. FC 2014 used relay anomalies of exactly this kind; Bitcoin Core PR
#18038 introduced the unbroadcast set because "the current rebroadcast logic is terrible for
privacy") [A].

**Classification.** Privacy-critical; policy only; no consensus impact.

**Solutions in the literature.**
- Bitcoin Core: mempool persistence (`mempool.dat`) plus the **unbroadcast set**: locally
  submitted transactions are re-announced only until a peer requests them; wallet
  rebroadcast reduced to about once a day [A, PR #18038].
- Bitcoin Core 31 **private broadcast**: each originated transaction goes over fresh
  short-lived Tor/I2P connections (3 peers each, `NUM_PRIVATE_BROADCAST_PER_TX = 3`), and
  it enters the local mempool only when it comes back from the network [A, PR #29415,
  `net_processing.cpp`]. A re-send then reveals nothing about the IP.
- Monero: `--tx-proxy` sends local transactions only over anonymity networks [A].

**Proposal for BlackSilk (W2).**
1. An **originated set** in the node: `(tx id, stem keys, first-origination height)` for
   every `Source::Local` transaction, persisted in the data directory (`local_txs.json`,
   bounded, pruned when mined and buried or after the expiry horizon).
2. **Persist the node's own pooled transactions** across restarts and re-admit them on start
   **without announcing** them (full revalidation on load).
3. On `submit_tx` for a transaction in the originated set that is not pooled:
   - with private broadcast available (W8), send it that way;
   - otherwise, if fewer than `MEMPOOL_EXPIRY_BLOCKS` have passed since first origination,
     **do not re-originate**: re-admit it to the local pool silently and answer "pending"
     (the network most likely still has it);
   - after the horizon, re-stem as a fresh transaction (the network has dropped it).
4. A re-originated local transaction never takes the embargo fluff path at the origin
   (W3's re-stem instead).
5. Exempt originated transactions from local fee eviction only if that is not itself a
   fingerprint (it is not externally visible; decide with 12).

**Trade-offs.** A transaction that the whole network really dropped (for example after a
fee-eviction wave) is re-sent only after the horizon, unless private broadcast is on. That is
the correct side of the trade for a privacy chain; `--force-rebroadcast` can override with a
logged warning. Persistence adds a small file and a revalidation pass at start.

**Tests.** `a_restarted_origin_does_not_reannounce_a_transaction_the_network_holds` (two nodes,
restart the origin with its data dir, resubmit, assert no `InvTx` for the id reaches a raw
spy peer within 2 × the embargo); `a_resubmitted_pooled_transaction_is_not_relayed`
(regression of today's AlreadyKnown behaviour); unit tests of the originated set.

**Invariants.** A node never announces in fluff, as origin, a transaction whose first
fluff it did not itself observe **in this origination**; local transactions never skip the
stem.

### 3.2 Stempool membership through `StemTx` replay timing (NEW, F33-2)

**What and why.**
- The read loop handles one message at a time (`handle(...).await`, `net.rs:1194`), and a
  `Ping` after a `StemTx` is answered only once that `StemTx` has been handled.
- A `StemTx` whose id is already in the stempool, or whose keys conflict with it, returns
  **before any verification** (`net.rs:2466-2476`, the R8-7 fix); one already pooled returns
  in `admit_tx` (`net.rs:2257`). An unknown one is fully verified under the chain lock
  (`check_tx`, `net.rs:2480-2488`): about 0.235 s for PX, about 3 ms per CLSAG input plus
  BP+ for v1 [A, R12].
- So `StemTx(bytes) + Ping` → Pong latency tells the prober whether the target already holds
  the transaction. Before fluff, only stem-path nodes do.

**Who can do it.** Anyone holding the bytes, which is every stem hop downstream of the
target, i.e. exactly the attacker of I3-1. I3-1's fix made the `InvTx` answer uniform, but a
downstream spy can run this probe instead against every node it is connected to (spies
typically connect inbound to every reachable node). **The I3-1 oracle is therefore only
partly closed.** For PX the timing gap is two orders of magnitude above network jitter
[M]; for v1 it is milliseconds and needs repeated baselines [A].

**Side effect.** The probe injects the transaction into non-path targets (it is verified and
stemmed onward), so each target can be probed once; that is enough.

**Classification.** Privacy-critical (D++'s main guarantee); policy; no consensus impact.

**Solutions.**
- Uniform processing time is not affordable (the R8-7 fix exists to avoid verifying
  duplicates).
- **Decouple verification from the connection's read loop**: `on_stem_tx` and `on_tx` hand the
  transaction to a verification worker (bounded per peer, e.g. 2 in flight, the rest dropped
  unverified as a rate excess) and return at once. Pongs then no longer carry verification
  time. This is the same direction as 34's actor design (off-lock verification) and must be
  designed with it.
- Residual: global load observed through other requests (for example `GetHeaders` latency
  while the chain lock is held for verification). 34's off-lock verification reduces it;
  document it.
- **Invariant for agent 10's `VerifiedCache` (§3.6 of dossier 10):** it must be populated
  only on mempool admission and block validation (as 10 proposes), **never from stem-phase
  `check_tx`**. Otherwise a `Tx` delivered through `InvTx`/`GetTx` (the I3-1 path) is
  verified faster by stem-path nodes and the oracle reappears on the `Tx` path. The price is
  R6 MP-2 (a stem node verifies a PX proof twice), which privacy outranks.

**Tests.** `stem_replay_does_not_change_pong_latency` (a slow test verifier or a PX
transaction; compare Pong latency after `StemTx` of a held vs an unknown transaction, with
a tolerance far below the verification time); a unit test that `VerifiedCache` is not written
by `check_tx`.

### 3.3 Linked repeated broadcasts (F13-2, quantified: F33-3)

**Status of the trigger.** F13-2's trigger was C4 griefing. D8 chose option B, which removes
cross-transaction output-key uniqueness, so the **forced** rebroadcasts disappear. Linked
repeated broadcasts remain possible through:
- re-origination after the node forgot the transaction (F33-1, which is far worse than a
  fresh sample because the first hop black-holes it);
- a transaction dropped at an upgrade: the wallet asks the user to "send the payment
  again", which reuses rings (W-5) and key images (`wallet.rs:1414-1480`);
- a user re-sending, or a double spend variant;
- any future rule that invalidates pending transactions.

**Why it degrades anonymity.** Dandelion++'s intersection-attack guarantee (Theorem 2,
precision Θ(p²·log(1/p))) holds because transactions from one source follow the same path
**within an epoch** [A, arXiv:1805.11060: "the intersection attack analysis assumes
single-epoch conditions"]. A re-broadcast after 20 blocks (≈ 40 min ≈ 4 epochs) is a fresh
sample: new stems, new diffuser flags. The outbound connections, however, stay the same,
so the origin's neighbourhood is the common factor, and each sample adds evidence.

**Quantification [S] (§2.5 model; weak plurality estimator for A, ML for B).** Probability
that the adversary names the true origin after k linked broadcasts:

| Adversary | N | spy fraction / δ | k = 1 | k = 2 | k = 4 | k = 8 | k = 16 |
|---|---|---|---|---|---|---|---|
| A: in-graph spies | 200 | p = 0.05, δ = 0.15 s | 0.046 | 0.043 | 0.083 | 0.124 | 0.207 |
| A: in-graph spies | 200 | p = 0.10, δ = 0.15 s | 0.103 | 0.088 | 0.135 | 0.251 | 0.383 |
| A: in-graph spies | 200 | p = 0.20, δ = 0.15 s | 0.216 | 0.216 | 0.306 | 0.456 | 0.606 |
| A: in-graph spies | 200 | p = 0.10, δ = 1.5 s (PX) | 0.108 | 0.110 | 0.151 | 0.271 | 0.362 |
| A: in-graph spies | 1000 | p = 0.10, δ = 0.15 s | 0.150 | 0.123 | 0.200 | 0.293 | 0.443 |
| B: supernode, knows graph, sees exact diffuser | 60 | — | 0.03 | 0.105 | 0.105 | 0.18 | 0.31 |
| B: supernode, first announcer with trickle noise | 60 | — | 0.005 | 0.010 | 0.015 | 0.025 | 0.050 |

(1,000 trials per A row with N = 200, 300 for N = 1000, 200 per B row; standard error ≈ 1.5
percentage points at 0.1 and ≈ 3 at 0.5. k = 2 is not above k = 1 because a two-way tie
is broken at random.)

**Reading.**
- A single broadcast gives the in-graph adversary recall ≈ p (it catches the origin whenever
  a spy is the first stem hop). This matches Sharma et al.'s point that D++ anonymity sets
  are small and do not grow with N [A, NDSS 2023].
- **Each doubling of k after k = 2 adds roughly 5–15 percentage points**; 8 linked broadcasts
  roughly double to triple the single-broadcast recall. Even the weak estimator converges
  on the origin; an ML estimator converges faster.
- The realistic k after D8 is 1–3 per transaction, so the amplification is modest **if and
  only if** F33-1 is fixed: F33-1 turns one re-broadcast into certainty.
- N = 1000 gives no better protection than N = 200 (0.15 vs 0.10 at k = 1, within about two
  standard errors), consistent with "anonymity does not grow with N" [A, Sharma et al.].
- The passive supernode that sees only fluff timing is weak **with the current trickle
  noise** (0.5 % → 5 % at k = 16, near the 1/60 chance level at k = 1); with the exact diffuser
  it reaches 31 % at k = 16. That gap is what the trickle delays buy, and why W5 must keep
  the noise while removing the per-connection advantage (R8-16).
- Analytic check [M]: with m spies among the origin's 8 outbound peers, the chance that at
  least one of k epochs routes the origin's own transaction straight to a spy is
  1 − (1 − m/8)^k (m = 1: 12.5 % for k = 1, 41 % for k = 4, 66 % for k = 8).

**Mitigations (in order of value).**
1. Fix F33-1 (W2). It removes the dominant case.
2. Private broadcast (W8): each re-send goes over a fresh Tor circuit, so linked samples say
   nothing about the IP.
3. Keep repeated broadcasts rare by design: no forced rebuild (D8 already), the wallet's
   20-block cadence harmless once the node persists its own transactions (W2), expiry long
   (12's 2160 blocks).
4. Document: "each independent broadcast of the same spend is another sample for a spy".

### 3.4 The origin's embargo on PX paths (R8-17 refined: F33-4)

**What and why.** Every stem node, the origin included, arms 10 s + Exp(39 s). If the origin's
timer fires before the fluff reaches it, the origin announces its own transaction.
SX2 showed that on an honest v1 path this is negligible and after a black hole at hop k it is
about 1/k (1 for a first-hop drop). Nobody has quantified the honest PX path end to end.

**Quantification [S] (N = 200, honest path, 3,000 trials each):**

| Hop latency δ | Embargo | P(origin's own timer fires before the fluff reaches it) | P(a supernode's first announcer is the origin) |
|---|---|---|---|
| 0.15 s (v1) | 10 s + Exp(39 s) | 0.015 | 0.021 |
| 1.5 s (PX) | 10 s + Exp(39 s) | **0.123** | **0.076** |
| 3.0 s (PX, slow link) | 10 s + Exp(39 s) | 0.277 | 0.152 |
| 1.5 s (PX) | 10 s + Exp(150 s) | 0.059 | 0.048 |
| 1.5 s (PX) | 60 s + Exp(39 s) | 0.038 | 0.048 |

- The baseline for "first announcer is the origin" on this graph is set by D++ itself (0.021
  for v1). **PX origins are named 3.6× more often (7.6 %)**, and on slow links 7×. The
  SX2 estimate (about 12 %) is confirmed as the self-fire rate.
- A longer base or mean roughly halves the excess but does not remove the structural part
  (the origin is adjacent to its first hop, and the fluff comes back late).
- Adding the black-hole cases (R3-5, the node-wide PX budget, a malicious first hop), the
  origin fires first with probability 1/k after a drop at hop k [M, SX2].

**Solutions.**
- Kind-aware embargo: a PX base long enough for PX hops (for example 40–60 s, to be chosen
  from labnet data; the table suggests the gain saturates near 60 s).
  The kind is public, so this adds no fingerprint.
- **Local re-stem on first expiry** (R8-17's alternative): when a *local* transaction's
  embargo fires, send it once through the *other* stem peer with a fresh embargo; fluff only
  at the second expiry. A first-hop black hole then needs both stem peers to be adversarial.
- In a dual-homed node (`--proxy` plus clearnet listening), the origin's fallback fluff must
  go first to proxied/onion peers only; otherwise the fallback shows the transaction to
  clearnet inbound spies despite the Tor stem (F33-7).
- Trade-off: extra delay only when the stem black-holes; PX latency is dominated by proving
  (≈ 45 s) and block space (3 per block), so 30–50 s more in the failure case is acceptable.

**Tests.** `a_black_holed_local_transaction_is_restemmed_before_the_origin_fluffs` (two raw
outbound peers as stems, the first drops; assert the second receives `StemTx` and the
inbound raw spy sees no `InvTx` before the second expiry); unit tests for the per-kind
embargo distribution.

### 3.5 Trickle timers (R8-16, open) and per-network state

- Independent Exp(5 s) per inbound peer: a spy with c inbound connections sees the minimum of
  c exponentials (mean 5/c s) [M]. Bitcoin Core uses **one timer for all inbound peers with the
  same network key** (`NextInvToInbounds`: "a single … timer for all peers with the same
  network key") and 2 s per outbound peer [A, `net_processing.cpp`].
- Invs are sent in arrival order (`net.rs:2655-2659`); Core randomizes the order.
- **Proposal (W5):** one inbound timer per network class (clearnet IPv4, IPv6, onion);
  per-peer outbound timers stay; shuffle every batch. Test:
  `inbound_peers_of_one_network_share_one_trickle_timer` (three raw inbound peers receive the
  announcement in the same tick) and `inv_batches_are_shuffled`.

### 3.6 GetAddr (R3-6/R8-19 extended: F33-5)

- The node answers `GetAddr` from **any** peer, once per connection, with a fresh random
  sample of up to 1000 addresses from one table that mixes networks (`net.rs:1328-1348`).
- R3-6 described the dual-homed link. A further case: **unreachable nodes**, which only dial
  out, answer the peers they dial. A spy plants cookie addresses through `Addr` (≤ 10 per
  message, `net.rs:1352-1385`) and reads them back whenever the victim dials it again: after
  an IP change, or over Tor. On a small network one answer is the whole table.
- Bitcoin Core ignores `getaddr` on outbound connections for exactly this reason ("a node
  behind NAT can be fingerprinted"), and caches the answer per (network, local socket) for
  about 24 h ("prevent cross-network node identification") [A, PR #18991, `net.h`].
- **Proposal (W6):** answer inbound only; one cached answer per network class, refreshed after
  21–27 h (randomized), at most 23 % of the table and ≤ 1000; an onion-class answer contains
  only onion addresses. Tests: `getaddr_on_an_outbound_connection_is_ignored`,
  `getaddr_answers_are_cached_per_network`, `an_onion_getaddr_answer_holds_no_clearnet_address`.

### 3.7 PX size origin leakage (R3-10/R8-18/I3 §3.5: accepted limitation)

I agree with I3: no transport hides a 2.2 MB upload from the origin's ISP or Tor guard. Two
policy items remain in my scope:
- **Docs (P0):** state it in p2p.md §1 and §12 and px.md §12.
- **Padding buckets (P2, owner 30):** hide v1 fan-in/out and PX function counts; not the
  PX-vs-v1 distinction. The root fix is smaller proofs (P3, 49).

### 3.8 Private broadcast (design, W8)

Keep I3 §3.3's design with three adjustments from the primary sources:
- **Peers per transaction:** Core sends each transaction to 3 peers over separate
  connections [A]. In BlackSilk a private-broadcast transaction enters the receiver's
  **stem** (`StemTx`), so sending to several peers starts several stems. Send to **one**
  random peer, and re-send through a new one after a timeout if the transaction has not come
  back in fluff; over Tor a re-send reveals nothing about the IP (unlike §3.3's clearnet
  case).
- **Mempool entry:** as in Core, the transaction enters the local pool only when it comes back
  from the network; this also removes the origin's embargo (F33-4) and F33-1.
- **ProxyMark lessons [A, arXiv:2607.07062]:** never filter candidate peers by claimed height
  (BlackSilk does not); run D++ inside the anonymity network, so that a transaction from a Tor
  inbound connection may be relayed (BlackSilk already treats all sources alike); fixed
  cadence for keep-alives on proxied connections (I3-3, P3).
- Prerequisites: 32's addrman fixes (peer draws from a poisoned table are worthless) and
  stream isolation (R8-6).

### 3.9 Invariants that must never change

- Local transactions always stem, and are never fluffed by the origin while a stem path
  exists; they are held when none exists.
- One uniform answer to `InvTx`/`GetTx`/`StemTx` whether or not the id is in the stempool,
  **including in timing** (F33-2).
- Stem and proxy selection independent of peer-claimed height.
- Per-source fixed routes within an epoch.
- `GetTx` served only for ids announced to that peer.
- The origin never re-announces, in fluff, a transaction the network already holds (F33-1).
- The verification cache is never populated from stem-phase checks (F33-2).
- SOCKS5 (later SAM) is the only anonymity-network boundary; no embedded C Tor.

---

## 4. New findings

| ID | Severity | Status | Where | Scenario | Confidence |
|---|---|---|---|---|---|
| **F33-1** | **Medium–High** (privacy) | Not implemented | `net.rs:483-491, 2257, 2572-2590, 2604-2624`; `wallet.rs:1490-1494`; `chain/src/mempool.rs` (no persistence) | The origin restarts (or its pool evicts/expires the transaction first); the wallet's 20-block rebroadcast re-stems it; the first hop drops it as pooled; the origin's embargo fires and it announces a transaction the network has held for tens of minutes. Only the origin does that: any spy peer identifies it with probability ≈ 1 | High [SR, M]; not tested |
| **F33-2** | **Medium** (privacy; High for PX) | Not implemented | `net.rs:1194` (sequential read loop); `:2466-2476`, `:2257` (fast paths); `:2480-2488` (verification) | A downstream stem hop replays `StemTx` + `Ping` to each node it reaches; a fast Pong means "already holds it", i.e. on the stem path. The I3-1 fix is bypassed for the same attacker | High for PX [SR, M]; medium for v1 (ms-level) |
| **F33-3** (= F13-2 quantified) | Medium (privacy) | Accepted limitation with mitigations; trigger removed by D8 | `wallet.rs:1414-1480` (stale-epoch re-send), F33-1 sites | Linked broadcasts in different epochs are independent D++ samples: in-graph recall 0.10 → 0.25 → 0.38 for k = 1, 8, 16 at p = 0.1 (N = 200) | Medium [S], model-dependent |
| **F33-4** (refines R8-17 / SX2 C7) | Medium (privacy, PX) | Not implemented | `dandelion.rs:40-53, 146-148`; `net.rs:2604-2624` | Honest PX path: the origin's timer fires before the fluff returns in 12 % of cases; a supernode's first announcer is the origin 7.6 % vs 2.1 % for v1 | Medium [S]; high on direction |
| **F33-5** (extends R3-6) | Medium for Tor/NAT users; Low otherwise | Not implemented | `net.rs:1328-1348`; `addrman.rs:195-210` | Unreachable nodes answer `GetAddr` on connections they dialled; planted cookie addresses link the node across IP changes and Tor sessions | High [SR] |
| **F33-6** | Low (docs vs code) | Not implemented | `docs/p2p.md` §8 ("announced by a peer, or included in a block" ends the embargo) vs `net.rs:2065-2078, 2427-2429` | After I3-1 only a received `Tx` ends a stem; a mined stem transaction stays in the stempool until its embargo (its fluff then fails silently). §7 and §8 contradict each other; §8 also claims the embargo is "tuned" (§2.4) | High |
| **F33-7** | Medium for dual-homed Tor nodes | Not implemented | `net.rs:2572-2590, 777-800` | With `--proxy` and clearnet listening, the origin's fallback fluff goes to clearnet inbound spies too; a Tor stem does not protect the fallback | High [SR] |
| **F33-8** (= Monero note) | Informational | — | `dandelion.rs:45-46` comment; `docs/p2p.md` §8 | Monero's 39 s derivation appears to use log₁₀ (ln gives 16.6 s); BlackSilk's comment "tuned for this q" inherits an unverified derivation | Medium [M] |

Carried open items (not new): R8-16 (W5), R10-10 stem logs (W12), MP-9 contract ids (W11),
R8-18/R3-10 docs (W10).

---

## 5. Implementation plan for phase 2

All items are **policy only**: no consensus change and no testnet identity impact.

| # | Item | Files (ownership) | Visibility | Tests | Bench | Docs | Diff. | Pri. |
|---|---|---|---|---|---|---|---|---|
| **W1** | Privacy regression suite (the roster's "never fluffed first, no oracle"): diffuser-epoch origin still stems; InvTx uniformity (exists); `StemTx`-replay Pong timing; GetAddr outbound; held local tx never announced; restarted origin does not re-announce | new `p2p/tests/privacy.rs` (**33**) | none | adversarial, regression | — | p2p.md §13 test list | M | **P0** |
| **W2** | Originated set + own-transaction persistence + no re-origination inside the expiry horizon (F33-1) | new `p2p/src/local.rs` (**33**); `p2p/src/net.rs` `submit_tx`/`fluff` (**33**, coordinate 34); `chain/src/mempool.rs` load/save of local entries (**12** owns, 33 specifies); `node/src/lib.rs` `/tx` "pending" answer (**36**) | none on the wire (fewer announcements) | `a_restarted_origin_does_not_reannounce_a_transaction_the_network_holds`; originated-set unit tests; restart/revalidation test | — | p2p.md §8, wallet docs | M | **P0** (P1 if the trial has no PX backlog) |
| **W3** | Local re-stem on first embargo expiry; origin fallback fluff to proxied/onion peers first (F33-4, F33-7) | `p2p/src/dandelion.rs` (**33**); `p2p/src/net.rs` `stem_or_fluff`/maintenance (**33**) | none | `a_black_holed_local_transaction_is_restemmed_before_the_origin_fluffs`; dual-homed fallback test | — | p2p.md §8 | S | **P1** |
| **W4** | Kind-aware embargo base (PX 40–60 s, chosen from labnet) (F33-4) | `p2p/src/dandelion.rs`, `net.rs` (**33**) | none | per-kind distribution unit test; W9 sim | labnet stem latency of PX (with 09's I4 instrumentation) | p2p.md §8 table | S | **P1** |
| **W5** | Shared inbound trickle timer per network class; shuffled inv batches (R8-16) | `p2p/src/net.rs` `announce_tx`, maintenance (**33**) | none | `inbound_peers_of_one_network_share_one_trickle_timer`; `inv_batches_are_shuffled` | — | p2p.md §7 | S | **P1** |
| **W6** | GetAddr inbound-only, per-network 21–27 h cache, 23 % cap (F33-5, R3-6, R8-19) | `p2p/src/net.rs` `on_get_addr` (**33**); `p2p/src/addrman.rs` network-filtered `sample` (**32** owns) | none | the three GetAddr tests of §3.6 | — | p2p.md §9 | S | **P1** (P0-public for Tor) |
| **W7** | Verification off the read loop, bounded per peer (F33-2) | `p2p/src/net.rs` read loop, `on_stem_tx`, `on_tx` (**34** owns the architecture; 33 writes the privacy test and reviews) | none | `stem_replay_does_not_change_pong_latency`; existing liveness tests | pong latency under PX verification | p2p.md §10 | M | **P1** |
| **W8** | Private broadcast (Tor, one peer per attempt, `StemTx`, pool entry on return) | new `p2p/src/private_broadcast.rs` (**33**); `socks5.rs` stream isolation (**30**/**32**); `node/src/config.rs` flag (**36**) | none | local SOCKS test double; no-clearnet-fallback test; re-send uses a new peer | — | p2p.md §11 | M | P1 design / **P2** build (after 32's addrman) |
| **W9** | Rust port of the first-spy simulator (`#[ignore]` statistical test or `tools/labnet` mode), used for every parameter change | `tools/labnet` (**40**/labnet owner) or `p2p/tests/dandelion_sim.rs` (**33**) | none | reproduces §3.3/§3.4 tables within CI noise | runtime ≤ 1 min | evidence file under `docs/evidence/` | M | **P2** |
| **W10** | Docs: quantified anonymity statements (§3.3/§3.4 tables with their model), "small anonymity set, does not grow with N", PX origin visible to the ISP even over Tor, repeated-broadcast caveat, embargo semantics fix (F33-6), Monero-derivation note (F33-8) | `docs/p2p.md` §1, §7, §8, §12; `docs/px.md` §12 (**47** coordinates, content 33) | none | — | — | yes | S | **P0** |
| **W11** | Stem keys include deploy contract ids (MP-9 residual) | `p2p/src/net.rs` `stem_keys` (**33**) | none | conflicting-deploy stem test | — | p2p.md §8 | S | P2 |
| **W12** | Stem routing out of default debug logs (R10-10) | `p2p/src/net.rs` log lines (**33**) | none | — | — | node ops docs | S | P2 (P1 for Tor) |
| **W13** | Frame padding buckets | `p2p/src/transport.rs` (**30**) | wire (protocol version) | codec tests | bandwidth | p2p.md §3 | S–M | P2 |

**Order:** W10 and W1 first (docs and tests of what holds today), then W2, W3, W5, W6, W4
(needs labnet numbers), W7 (with 34), W8 (after 32), then P2 items.

---

## 6. Dependencies and conflicts

- **12 mempool-architecture:** W2 needs own-transaction persistence in `mempool.rs` and the
  expiry horizon (2160 blocks). The expiry must count from admission everywhere; F33-1 shows
  the origin expires first. MP-9 is mine (W11).
- **10 block-validation (VerifiedCache):** never populated by stem-phase `check_tx` (F33-2
  invariant). This keeps R6 MP-2 (double PX verification on stem nodes) open by design.
- **34 chain-actor-concurrency:** owns W7's architecture; the read loop and the handlers in
  `net.rs` are shared ground. My edits to `stem_or_fluff`, `fluff`, `announce_tx`,
  `on_get_addr` and the maintenance loop must be sequenced with 34's refactor.
- **31 p2p-sync:** also edits the read loop and maintenance loop in `net.rs`; sequence.
- **32 eclipse-addrman:** owns `addrman.rs` (W6 needs a network-filtered sample), onion
  grouping, anchors; W8 depends on its fixes.
- **30 p2p-transport:** padding (W13), transport v2; stream isolation with 32.
- **36 rpc-security:** `/tx` answer for "held/pending" (W2); `--private-broadcast` flag.
- **38 wallet-privacy:** wallet rebroadcast cadence (keep 20 blocks only if W2 lands;
  otherwise lengthen); "send the payment again" after an upgrade reuses key images (F33-3);
  remote-node submission bypasses D++ (R3-9).
- **13 / 17:** F13-2 is closed as a forced trigger by D8; F33-3 records the residual.
- **40 testnet-genesis / labnet, 09 (I4 instrumentation):** stem latency data for W4.
- **41 fuzzing-property:** hosts W9's statistical test if it becomes a property test.
- **47 docs:** W10. **48 / 50:** adversarial review of W2, W3, W7.

---

## 7. Open questions for the coordinator

1. **F33-1 policy:** before the expiry horizon, should a forgotten local transaction be held
   silently (my recommendation), or re-stemmed with a warning? It changes the `/tx` answer (36).
2. **Ownership of W7:** 34 or 33? I recommend 34 owns the read-loop change and 33 owns the
   privacy test that gates it.
3. **Trial vs public testnet:** with 7 trusted devices and `--peer` lists, D++ anonymity is
   not meaningful (R15 D4). Should W2–W6 be P0 for the trial or P0-public? I rate W1, W2
   (if PX backlogs are expected) and W10 as trial-P0, the rest P0-public.
4. **PX embargo:** may the labnet evidence runs include a stem-latency measurement (09's I4
   instrumentation) so that W4's base is chosen from data, not from my model?
5. May W9 add a statistical `#[ignore]` test to `p2p/tests` (pure Rust, no new dependency)?

---

## 8. Sources

**Dandelion and Dandelion++**
- G. Fanti, S. B. Venkatakrishnan, S. Bakshi, B. Denby, S. Bhargava, A. Miller, P. Viswanath,
  "Dandelion++: Lightweight Cryptocurrency Networking with Formal Anonymity Guarantees",
  SIGMETRICS 2018 / POMACS 2(2). https://arxiv.org/abs/1805.11060 (HTML:
  https://arxiv.org/html/1805.11060) — Proposition 3 (fail-safe timers), Theorem 2
  (one-to-one routing, Θ(p² log(1/p))), q ≤ 0.2, single-epoch intersection analysis.
- S. Bojja Venkatakrishnan, G. Fanti, P. Viswanath, "Dandelion: Redesigning the Bitcoin
  Network for Anonymity", SIGMETRICS 2017. https://arxiv.org/abs/1701.04439
- BIP 156 (Dandelion). https://github.com/bitcoin/bips/blob/master/bip-0156.mediawiki
- P. K. Sharma, D. Gosain, C. Diaz, "On the Anonymity of Peer-To-Peer Network Anonymity
  Schemes Used by Cryptocurrencies", NDSS 2023. https://arxiv.org/abs/2201.11860
- E. Franzoni, V. Daza, "Clover: an Anonymous Transaction Relay Protocol for the Bitcoin P2P
  Network". https://arxiv.org/abs/2109.00376

**Monero**
- `cryptonote_config.h` (`CRYPTONOTE_DANDELIONPP_*`, `CRYPTONOTE_NOISE_*`,
  `CRYPTONOTE_MEMPOOL_TX_LIVETIME`).
  https://github.com/monero-project/monero/blob/master/src/cryptonote_config.h
- `tx_pool.cpp` embargo derivation comment (k = 5, ε = 0.10, hop = 175 ms, 39 s).
  https://github.com/monero-project/monero/blob/master/src/cryptonote_core/tx_pool.cpp
- PR #7025 (q = 20 %, 39 s). https://github.com/monero-project/monero/pull/7025
- Commit a12a817 (skip desynced peers in stem phase: height filtering).
  https://github.com/monero-project/monero/commit/a12a8174e06588be33e0790548873f6e8b160b23
- `levin_notify.cpp`. https://github.com/monero-project/monero/blob/master/src/cryptonote_protocol/levin_notify.cpp
- Anonymity networks. https://github.com/monero-project/monero/blob/master/docs/ANONYMITY_NETWORKS.md

**Bitcoin Core**
- PR #29415 private broadcast. https://github.com/bitcoin/bitcoin/pull/29415
- PR #36309 private broadcast marked experimental, claims clarified.
  https://github.com/bitcoin/bitcoin/pull/36309
- Bitcoin Core 31.0 release notes. https://bitcoincore.org/en/releases/31.0/
- Optech #388. https://bitcoinops.org/en/newsletters/2026/01/16/
- `net_processing.cpp` (`NUM_PRIVATE_BROADCAST_PER_TX = 3`,
  `PRIVATE_BROADCAST_MAX_CONNECTION_LIFETIME`, `INBOUND/OUTBOUND_INVENTORY_BROADCAST_INTERVAL`,
  `NextInvToInbounds`, outbound `getaddr` ignored).
  https://github.com/bitcoin/bitcoin/blob/master/src/net_processing.cpp
- `net.h` (`m_addr_response_caches` per (network, local socket)).
  https://github.com/bitcoin/bitcoin/blob/master/src/net.h
- PR #18991 (cache GETADDR responses). https://github.com/bitcoin/bitcoin/pull/18991
- PR #18038 (unbroadcast set; wallet rebroadcast privacy).
  https://github.com/bitcoin/bitcoin/pull/18038
- PR #13298 (shared inbound trickle timer), cited via R8-16.
  https://github.com/bitcoin/bitcoin/pull/13298
- Outbound-getaddr fingerprinting: D. Abrozzoni, "Fingerprinting nodes via addr requests"
  (pointer to Core's rationale). https://danielabrozzoni.com/posts/addr_fingerprinting/

**Network deanonymization**
- ProxyMark: Deanonymizing Monero Transactions in Tor Network, arXiv:2607.07062.
  https://arxiv.org/abs/2607.07062
- Are Unreachable Nodes Truly Safe? Fully Eclipsing Monero's P2P Network (CCS'26),
  arXiv:2609.10260. https://arxiv.org/abs/2609.10260
- P. Koshy, D. Koshy, P. McDaniel, "An Analysis of Anonymity in Bitcoin Using P2P Network
  Traffic", FC 2014. https://patrickmcdaniel.org/pubs/klm14.pdf
- A. Biryukov, D. Khovratovich, I. Pustogarov, "Deanonymisation of Clients in Bitcoin P2P
  Network", CCS 2014. https://arxiv.org/abs/1405.7418
- A. Biryukov, I. Pustogarov, "Bitcoin over Tor isn't a Good Idea", IEEE S&P 2015.
  https://arxiv.org/abs/1410.6079
- G. Fanti, P. Viswanath, "Deanonymization in the Bitcoin P2P Network", NeurIPS 2017
  [A, background, not re-fetched].
