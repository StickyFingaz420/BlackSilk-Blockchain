# R3: End-to-end privacy review (BlackSilk, 2026-09-27)

**Reviewer:** R3 (internal review, not an audit).
**Tree:** worktree at `f677e55`. Read-only. No builds were run.
**Scratch evidence:** one pure-Python re-implementation of `tx/src/decoy.rs::Picker` plus the wallet's coinbase-maturity filter, run in the reviewer's scratchpad (not in the repository). It is called **SIM** below.
**Evidence tags:**
- **[math]** mathematically established;
- **[test: name]** tested;
- **[src]** source-read;
- **[sim]** simulated with SIM;
- **[assumed]**;
- **[unknown]**.

Items in the brief's "already known" list are only deepened here, and marked **(known)**.

---

## 0. Executive summary

1. **The v1 ring layer gives much less anonymity than "ring of 16" suggests on a young, quiet chain, and testnet will be one.**
   - SIM uses the real picker, T = 120 s, 1 coinbase per block and 2 outputs per transfer. After 3 days at 20 transfers/day:
     - 94% of decoys are coinbase outputs;
     - 40% of rings have **only** coinbase decoys, so a non-coinbase real input is the unique non-coinbase member;
     - against the miners (on testnet, a handful of people) the expected effective ring is about 1.9.
   - With 500 transfers/day it only reaches about 10 after a week.
   - A new interaction makes it worse (R3-1). The picker's "recent" probability mass falls on immature coinbase outputs, which the wallet then rejects. So decoys younger than 60 blocks almost never occur (0.6–5% of decoys on a young chain). A real input spent within 60 blocks of receipt is then the youngest ring member with high probability (≥ 91% in the quietest scenario).
   - This is the Möser et al. / Kumar et al. "guess-newest" heuristic, re-created by coinbase maturity.
2. **The miner leaks its identity through the nonce (new, R3-2).**
   - `miner/src/main.rs:87,129` draws one random `nonce_start` per process and advances it by the hashes done. Every block a miner process finds therefore has a nonce inside a narrow window of the 2^64 space.
   - Anyone can cluster blocks, and therefore coinbase outputs, by miner (the "Patoshi pattern").
   - This undoes the stealth-address unlinkability of coinbase outputs, and it lets outsiders, not only miners, run the coinbase-elimination of item 1.
   - The fix is one line of policy.
3. **Dandelion++ parameters are a mismatched pair (new, R3-4).** The code uses fluff probability 0.1 with a 39 s mean embargo, and docs/p2p.md says "as deployed in Monero". Monero chose 39 s *because* it raised the fluff probability to 20% (expected stem 5). With q = 0.1 it had used a longer embargo (Monero PR #7025).
4. **Three known P2P problems become origin-revealing black holes (deepened):**
   - the global PX relay budget can be exhausted;
   - a local tx is fluffed when there is no stem peer;
   - the embargo fallback always fires at the origin first when the first hop drops the tx.

   Together they let an adversary force a node to fluff its own transactions (R3-5).
5. **GetAddr leaks a node fingerprint (new, R3-6).** It returns up to 1,000 addresses, which is the whole address manager on a small network. It has no per-network cache and no onion/clearnet separation. This is the Biryukov–Pustogarov address-cookie fingerprint: a dual-homed (clearnet plus onion) node can be linked across identities.
6. **PX is the strongest part of the design, but:**
   - its anonymity set is the size of its usage;
   - bridge amounts are public, and they actually *reduce* amount privacy compared with staying in v1 (R3-8);
   - contract-record nullifiers can be computed by anyone who knows the record's opening (R3-7, not documented as such). A contract that derives `rcm` from public data (PX-F4 option B) makes its records' spends public.
7. **PX-only is not feasible now.**
   - Capacity: about 3 PX per 8 MiB block, about 2,160 per day, against about 237,000 v1 transfers per day by weight.
   - Proving takes about 45 s and 3.8 GB of RAM.
   - Proofs would add about 4.7 GB of chain per day at full use.

   The recommended path is a staged migration:
   - fix the v1 decoy and coinbase handling now (policy);
   - move coinbase into the PX pool at the v3 genesis if the owner accepts a consensus change (ZIP 213-style shielded coinbase, R3-11);
   - make PX the default store of value;
   - retire v1 only when a membership proof is cheap enough. Monero's FCMP++ reports proofs of a few KB; PX is 2.18 MB.
8. **Plain-HTTP remote-node use makes Dandelion++ irrelevant (known; deepened in R3-9).** Anyone on the path sees the submitted transaction, and the `/outputs` query, which is a superset of the ring. v1 privacy is also **not post-quantum** (retroactive ring deanonymization through the discrete log), whereas PX ownership and nullifiers are hash-based (R3-12).

**Testnet verdict (privacy):**
- Nothing here blocks a *controlled* testnet, provided the limitations in §8 are published.
- P0 before testnet:
  - R3-2 (nonce clustering fix);
  - R3-4 (parameter pair);
  - the documentation items (§8).
- R3-1 and R3-3 wallet mitigations are P1.

---

## 1. Threat model used

| Adversary | Capabilities | Main relevance |
|---|---|---|
| A1 chain analyst | Reads the whole chain | Rings, amounts at bridges, PX metadata, nonces, timing |
| A2 miner coalition | A1, plus knows its own coinbase outputs | Decoy elimination (coinbase-heavy rings) |
| A3 spy nodes | Many P2P connections, possibly stem peers, can drop and relay | Dandelion++ origin inference, black holes, address fingerprinting |
| A4 remote RPC node, or an on-path observer of wallet RPC | Sees wallet queries and submissions, plaintext today | IP ↔ transaction, ring superset, wallet birthday |
| A5 recipient or counterparty | Knows the outputs it created or received | EAE-style tracing, contract-record nullifiers |
| A6 ISP / global passive | Sees link-level traffic sizes and timing | Explicit non-goal (N2), but PX sizes make it trivial (R3-10) |
| A7 future quantum | Discrete logs | Retroactive v1 deanonymization (R3-12) |

---

## 2. Quantified anonymity sets

### 2.1 v1 rings on testnet-like chains [sim]

SIM is faithful to the source:
- `decoy.rs` Picker: gamma(19.28, 1/1.61) in seconds, lock 10·T, recent window uniform in [0, 15·T);
- `average_output_time` over the whole usable chain;
- a uniform output within the chosen block;
- the wallet's filter for coinbase outputs younger than 60 blocks (`wallet.rs:1101`).

Per block: 1 coinbase output, plus Poisson(tx/day ÷ 720) transfers of 2 outputs each. The real input is assumed to be a non-coinbase output.

Column meanings:
- **cb share of decoys:** fraction of decoys that are coinbase outputs;
- **E[non-cb decoys]:** expected non-coinbase decoys per ring;
- **all 15 decoys cb:** probability that every decoy is a coinbase output;
- **decoy < 60 blocks:** probability that a decoy is younger than 60 blocks;
- **newest = real:** probability that the newest member is the real one, if the real input is 10–12 blocks old;
- **Eff. ring:** effective ring size against miners that know a fraction m of the coinbase outputs, computed as 1 + 15·(1 − cb·m).

| Chain | cb share of decoys | E[non-cb decoys] | all 15 decoys cb | decoy < 60 blocks | newest = real (real 10–12 blocks old) | Eff. ring vs miners, m = 0.5 | Eff. ring vs miners, m = 1 |
|---|---|---|---|---|---|---|---|
| 3 d, 20 tx/d | 0.94 | 0.9 | 0.40 | 0.006 | 1.00 | 8.9 | **1.9** |
| 3 d, 100 tx/d | 0.75 | 3.7 | 0.014 | 0.032 | 0.70 | 10.4 | 4.7 |
| 7 d, 50 tx/d | 0.87 | 1.9 | 0.13 | 0.054 | 1.00 | 9.5 | 2.9 |
| 7 d, 500 tx/d | 0.38 | 9.3 | ~0 | 0.084 | 0.86 | 13.2 | 10.3 |
| 30 d, 200 tx/d | 0.63 | 5.6 | 0.001 | 0.093 | 0.81 | 11.3 | 6.6 |
| 30 d, 2,000 tx/d | 0.13 | 13.0 | 0 | 0.126 | 0.88 | 15.0 | 14.0 |
| 180 d, 5,000 tx/d | 0.06 | 14.1 | 0 | 0.121 | 0.77 | 15.6 | 15.1 |

**Reading:**
- On a quiet chain, 14–20% of raw picker draws land on immature coinbase outputs and are rejected [sim].
- The recent-age mass is therefore **removed**, not redistributed. A ring member aged 10–59 blocks is almost always the real one.
- Even on a busy chain, "guess newest" wins 77–88% of the time when the real input is spent at the minimum age. That is Monero's known weakness, inherited.

**Comparison:**
- Rucknium's OSPEAD work estimates Monero's mean effective ring size at about **4.2** (attack success 23.5%) since the 2022 fork. A re-fitted distribution would raise it to about 13.2 ([OSPEAD CCS](https://ccs.getmonero.org/proposals/Rucknium-Statistical-Research.html), [OSPEAD repo](https://github.com/Rucknium/OSPEAD)).
- BlackSilk uses the same distribution, fitted on 2017 Monero spends (Möser et al., PoPETs 2018). It has **no** evidence that BlackSilk users spend like Monero users in 2017. On testnet, testers will spend much faster.

### 2.2 PX

- **Anonymity set of a spend:** every commitment in the tree at the anchor (dummies included, because they are indistinguishable) [src: docs/px.md §3–4].
- **Size:** about 2 commitments per PX transaction. At most 3 PX transactions per block (8 MiB ÷ 2.18 MB), so at most about 4,300 commitments per day, and in practice far fewer.
  - A testnet with 20 PX/day has about 40 new commitments per day. After a month, a spend hides among about 1,200 commitments.
- **This is effectively reduced by:**
  - A2/A5 knowledge of their own records;
  - timing: deposit → spend → withdraw, with anchors at 16-block granularity;
  - public bridge amounts (R3-8);
  - public contract and program per call (P-8, known);
  - contract-record nullifiers (R3-7).
- **Comparison with Zcash:**
  - Kappos et al. (USENIX Security 2018) showed that most shielded-pool activity was linkable through round-trip amount and timing heuristics, and through the behaviour of founders and miners.
  - BlackSilk's bridge has the same shape: public amounts on both sides.

### 2.3 Network

- **Model:** Dandelion++ with q = 0.1, 2 stem peers, embargo 10 s + Exp(39 s) [src: `p2p/src/dandelion.rs:45-49`].
- **Expected stem length:** 1/q = 10 hops [math].
- **Precision:** Fanti et al. give a first-spy precision bound of about O(p²·log(1/p)) for a spy fraction p, *assuming a 4-regular stem graph and honest timers*. The black-hole paths of R3-5 break that assumption.
- **No measurement exists** on BlackSilk's network size (N4, known).

---

## 3. Findings

Format:
- **ID, title.** Class; severity; location.
- **Scenario.**
- **Evidence.** With a confidence level.

### R3-1: Coinbase maturity removes young decoys; young real spends stand out (NEW)

- **Class:** Complete but requires further testing (the picker works as specified; the combination is flawed).
- **Severity:** high (privacy, v1), during the testnet's early months.
- **Location:**
  - `tx/src/decoy.rs:199-222` (pick);
  - `tx/src/decoy.rs:193` (whole-chain `average_output_time`);
  - `wallet/src/wallet.rs:1101-1125` (maturity filter after drawing).
- **Scenario:**
  1. Alice receives a payment and spends it 12 blocks later.
  2. The chain is 3–7 days old, with 20–50 transfers per day.
  3. Her real input is 12 blocks old. P(any of the 15 decoys < 60 blocks) is 8.6% to 56% [sim]. With 20 transfers per day, the newest member is hers in essentially 100% of the draws.
- **Root cause:** the picker maps age → output index, using a whole-chain average output time. It then picks a uniform output in the block. In blocks 10–59 deep, most outputs are immature coinbase outputs, and the wallet rejects them rather than redrawing *within the same age*.
- **Evidence:** [src] [sim]. **Confidence:** high for the mechanism; medium for the magnitudes (the real spend distribution is [unknown]).

### R3-2: Miner nonce sequence clusters every block of a miner process (NEW)

- **Class:** Not implemented (the privacy property is missing).
- **Severity:** medium (high on testnet, combined with R3-1 and R3-3).
- **Location:** `miner/src/main.rs:87` (`nonce_start` drawn once), `:129` (`nonce_start += hashes`), `miner/src/lib.rs:111-145`.
- **Scenario:**
  1. A miner at ~100 H/s runs for a month and performs about 2.6·10^8 hashes.
  2. All its winning nonces lie in a window of width about 2^28 starting at a uniform 64-bit point.
  3. Two miners' windows overlap with probability about 2^-36.
  4. Sorting all block nonces yields exact per-process clusters. This gives:
     - the number of miners and their hashrate shares;
     - restarts;
     - **all coinbase outputs belonging to one miner.**
- **Consequences:**
  - Coinbase outputs are meant to be unlinkable (stealth keys).
  - An outside analyst (A1, not only A2) can now use the "known-owner" structure. For example, a multi-input transaction whose rings each contain a coinbase output of the same cluster is probably spending those.
  - This is the "Patoshi pattern" (S. D. Lerner, 2013) in a new form.
- **Evidence:** [src] [math]. **Confidence:** high.

### R3-3: Coinbase-dominated decoy sets, and miner elimination (DEEPENED; P7 "resists known heuristics" is not supported on a young chain)

- **Class:** Accepted limitation today, but undocumented.
- **Severity:** high on early testnet, falling to low as volume grows (§2.1 table).
- **Location:** `tx/src/decoy.rs` (no type-awareness); `tx/src/params.rs:47-50`; assumption P7 in docs/reviews/assumptions.md.
- **Scenario:**
  - Testnet will have few transfers per block, so every ring is mostly coinbase outputs.
  - The heuristic "the real input is the non-coinbase member" succeeds whenever the ring has one non-coinbase member: 40% of rings at 3 days and 20 transfers per day.
  - A single testnet miner (A2) eliminates every coinbase decoy it owns; with m = 1 the effective ring is 1.9.
- **Evidence:** [sim]. **Confidence:** high.

### R3-4: Dandelion++ fluff probability and embargo are not a consistent pair (NEW)

- **Class:** Partially implemented.
- **Severity:** medium.
- **Location:** `p2p/src/dandelion.rs:45-49`; docs/p2p.md §8 ("as deployed in Monero").
- **What Monero did:** it moved q from 0.1 to 0.2, and *therefore* lowered the embargo to 39 s. The expected stem is 5, and the 5th node has about a 90% chance of being the first to time out (vtnerd, [monero PR #7025](https://github.com/monero-project/monero/pull/7025)).
- **What BlackSilk has:**
  - q = 0.1 (expected stem 10) with a 39 s mean;
  - a 10 s base, not in Monero;
  - the timer is drawn per transaction, not per node;
  - the timer applies at the origin too.
- **Effect:**
  - Longer stems give a larger chance that an upstream timer, including the origin's, fires before the transaction is seen in fluff. That happens when any hop is slow: PX stem hops each carry 2.2 MB and a 0.21 s verification, over Tor possibly seconds.
  - An origin that fluffs its own transaction is exactly what a spy wants.
  - Also, 20% fluff gives better precision in the Fanti et al. analysis (the PR says +10% on average for a spy connected to every node).
- **Evidence:** [src] and published rationale. **Confidence:** medium (no BlackSilk measurement).

### R3-5: Forced self-fluff, from three known items combined (DEEPENED)

- **Class:** Partially implemented.
- **Severity:** medium-high (origin privacy).
- **Location:**
  - `p2p/src/net.rs:1463-1468` (`PxRate::GlobalExceeded => return`, a silent drop);
  - `:1493-1522` (`stem_or_fluff`);
  - `dandelion.rs:133-135` (no stems → Fluff);
  - maintenance embargo at `net.rs:1569-1579`.
- **Scenarios:**
  1. **PX black hole.** A3 floods valid-looking PX stem traffic, or any traffic that consumes the global 2/s PX budget, into the victim's stem peers. They silently drop the victim's PX stem transaction. Nobody downstream has it, so the *origin's* embargo (10 s + Exp(39)) fires first with high probability, and the origin fluffs its own transaction to all peers with trickle delays. A spy connected to the origin sees the first INV from it.
  2. **No stem peer.** After startup, or after both stem peers disconnect (A3 can cause that by misbehaving so that it is disconnected, or by eclipsing), a transaction submitted by RPC is fluffed at once (**known**; Monero has the same behaviour, PR #6973).
  3. **A malicious first hop drops the transaction.** The first-hop adversary then watches who fluffs it. The origin's timer started first, so it has the highest chance to fire. This is inherent to D++ embargo, but it is more exploitable with the 10 s floor and per-transaction timers.
- **Evidence:** [src]. **Confidence:** high for 1 and 2, medium for 3.

### R3-6: GetAddr responses fingerprint nodes and link onion and clearnet identities (NEW)

- **Class:** Not implemented (no mitigation).
- **Severity:** medium for Tor users; low otherwise.
- **Location:**
  - `p2p/src/net.rs:874-897` (answers `addrman.sample(1000)`);
  - `p2p/src/addrman.rs:195-210` (a random subset of *all* entries, onion and IP mixed);
  - `net.rs:899-930` (addresses from any peer are stored and relayed).
- **Scenario:**
  1. On a network with fewer than 1,000 addresses, every GetAddr answer is the node's full address manager.
  2. A3 plants a unique fake address via connection X (the address-cookie attack: Biryukov, Khovratovich and Pustogarov, CCS 2014; Biryukov and Pustogarov, IEEE S&P 2015).
  3. It then connects over the node's onion service and requests GetAddr. The cookie identifies the same node, and the same holds across IP changes.
- **Mitigation precedent:** Bitcoin Core caches the addr response per network for about 24 h and caps it at 23% of the address manager.
- **Evidence:** [src]. **Confidence:** high.

### R3-7: Contract-record nullifiers can be computed by anyone who holds the opening (NEW in this form)

- **Class:** Accepted limitation (design), but undocumented.
- **Severity:** medium (contract privacy).
- **Location:** `px-core/src/kernel.rs:23`, `px-core/src/hash.rs:52,223`: `nf = Hk(NULLIFIER_CONTRACT, contract ‖ rcm ‖ cm)`.
- **Scenario:**
  - The creator of a vault LOCK record, and every recipient of a share (`px_share`), knows `rcm` and `cm`. They can therefore watch the nullifier set and learn exactly *which* transaction spent the record, and when.
  - The pool anonymity of that spend is zero toward them.
  - Under PX-F4 option B, if a contract derives `rcm` from **public** data, *everyone* can compute the nullifiers of its records.
  - User records do not have this problem: their nullifier needs `nk`.
- **Evidence:** [src] [math]. **Confidence:** high.

### R3-8: Bridge amounts reduce amount privacy relative to v1 (DEEPENED from "Inherent")

- **Class:** Accepted limitation.
- **Severity:** medium.
- **Location:** `tx/src/px.rs:52-70` (`bridge_in`, `bridge_out`, payouts with clear amounts).
- **Scenario:**
  - A v1 user's amounts are hidden. Moving through PX publishes `bridge_in` and each payout amount.
  - On a small pool, a withdrawal of X after a deposit of X + fee is uniquely linkable. This is Zcash's round-trip heuristic (Kappos et al. 2018).
  - The wallet only prints guidance (docs/px.md §12); P4 is marked "unverified: depends on users".
  - `px_vault_claim` paying its fee from v1 (`wallet.rs:1563-1600`) adds a further class: a PX call with v1 inputs and `bridge_in` = 0.
- **Evidence:** [src]. **Confidence:** high.

### R3-9: The remote-node and plaintext RPC path defeats network privacy (known; deepened)

- **Class:** Partially implemented (A7b in progress).
- **Severity:** high for remote-node users.
- **Location:** `wallet/src/node.rs`; `rpc/src/lib.rs:260-305`; `wallet.rs:1064-1090` (the `/outputs` query holds the real output + stored members + (4·need).max(32) candidates, shuffled, which is good design).
- **What a remote node or path observer learns:**
  - the IP, and the whole transaction via `/tx` (Dandelion++ is bypassed, because the observer sees the submission);
  - a query that is a superset of each ring (61 indices for a fresh input);
  - the wallet's birthday, from the first `/blocks?from=restore_height`;
  - sync times;
  - rebroadcasts after 20 blocks, which link repeated submissions (W-6).
- **Stays hidden:** which ring member is real. The design of `plans_for` gives the node nothing beyond the ring itself [src].
- **Evidence:** [src]. **Confidence:** high.

### R3-10: PX transaction size is a link-level origin signal (NEW, but out of the N2 scope)

- **Class:** Accepted limitation (to document).
- **Severity:** low under the stated model; high against A6.
- **Scenario:**
  - A 2.2 MB encrypted flow leaves a node that received no similar flow just before, after about 45 s of CPU at 100%.
  - The transport hides content, not size.
  - A Tor guard, an ISP or a VPS provider identifies the origin of every PX transaction. v1 transactions (about 1.8 KB) are also distinguishable, but they blend with other traffic.
- **Evidence:** [src] [math]. **Confidence:** high.

### R3-11: No shielded coinbase; the coinbase design shapes the whole v1 set (design observation)

- **Class:** Not implemented.
- **Severity:** medium (strategic).
- **Location:** `tx/src/builder.rs:355-381`; `tx/src/types.rs:33-40`.
- Coinbase outputs are stealth outputs with clear amounts that enter the v1 ring set. That is the source of R3-1, R3-2 (partly) and R3-3.
- **Zcash precedent:** ZIP 213 (Heartwood, 2020) allows coinbase outputs directly into the shielded pool, with the note plaintext decryptable with a zero key so that nodes can check the value. The analogous PX construction:
  - the coinbase publishes the record opening (`owner`, value, `rho` derived from the height, `rcm`);
  - nodes recompute `cm` and append it;
  - no STARK is needed;
  - spends are later hidden by the nullifier.
  - The owner hash is revealed, so a fresh diversified PX address per block is required (the wallet can do this).
- **Evidence:** [src] and published precedent. **Confidence:** medium (feasibility needs a proper design review).

### R3-12: v1 privacy is not post-quantum; PX mostly is (NEW, documentation)

- **Class:** Accepted limitation (to document).
- **Severity:** info now; strategic.
- **v1:** a discrete-log adversary computes `x` from `P = xG` for each ring member, recomputes `I = x·Hp(P)` and identifies the real spend retroactively. It can also recompute ECDH shared secrets from public view keys, which reveals amounts and recipients. All of this is harvestable today.
- **PX:** ownership, nullifiers and commitments are Poseidon2-based (docs/px.md §3). Delivery is an ML-KEM hybrid. ZK is statistical. So PX privacy does not rely on discrete logs, subject to the conditions in zk-coverage.md.
- **Evidence:** [math] [src]. **Confidence:** high for v1; medium for "PX is PQ" (no formal analysis).

### R3-13: Multi-input merging (Monero "output merging" heuristic) (NEW for BlackSilk)

- **Class:** Partially implemented.
- **Severity:** low-medium.
- **Location:** `wallet.rs:891-930` (`select_inputs`: largest-first when no single output covers).
- **Scenario:** two outputs created by one transaction (payment + change, or two payments from a counterparty) are later spent together. Their rings then share a source transaction only at the real members (Kumar et al., ESORICS 2017; Möser et al. 2018).
- **What the wallet does not do:**
  - it does not avoid co-spending outputs of the same source transaction, or of the same block;
  - it does not warn about it.
- **Evidence:** [src]. **Confidence:** high for the mechanism; the magnitude is [unknown].

### R3-14: Assumptions P7 and N4 are stated too weakly or too optimistically (documentation)

- P7 says the decoy selection "resists the known heuristics … standard practice". §2.1 contradicts this for the testnet regime, and OSPEAD contradicts it even for Monero.
- p2p.md §8 claims Monero parity, which R3-4 contradicts.
- **Class:** Partially implemented (docs). **Severity:** medium (the owner's policy against overclaiming).

---

## 4. Per-subsystem answers (the 13 questions)

### 4.1 Chain, v1 layer

1. **Implemented:**
   - CLSAG rings of 16;
   - BP+ confidential amounts;
   - stealth/Janus outputs with 1-byte view tags;
   - canonical ordering of inputs by key image and of outputs by one-time key (`builder.rs:223,238`);
   - a change output always present (`builder.rs:150`);
   - a deterministic `standard_fee(shape)` (`builder.rs:126`);
   - no `unlock_time` and no `tx_extra`;
   - gamma decoys; ring reuse (W-5).
2. **Correct and well designed:**
   - there are no free-form fingerprint fields (better than legacy Monero `tx_extra`/`unlock_time`);
   - fee standardisation;
   - the single `/outputs` query with an oversized shuffled pool;
   - ring reuse;
   - network id bound into signatures.
3. **Incomplete:**
   - the decoy/maturity interaction (R3-1);
   - no type-aware selection (R3-3);
   - no merge avoidance (R3-13).
4. **Fragile:** Monero's 2017 parameters, used without any BlackSilk data (P7).
5. **Exploitable:** guess-newest; coinbase elimination; nonce clustering (R3-1, R3-2, R3-3).
6. **Inefficient:** nothing significant for privacy.
7. **Does not scale:** ring size 16 is fixed; effective anonymity is bounded by it even when the picker is ideal.
8. **Missing:**
   - a spend-delay policy;
   - a v1 fee rule that is exact in consensus (other wallets may overpay and fingerprint themselves; low);
   - shielded coinbase.
9. **Redesign:** in the long term, a full-set membership proof (§6).
10. **Innovate:** coinbase into PX (R3-11); a BlackSilk-specific, re-estimated decoy distribution fitted on testnet data (OSPEAD-style).
11. **Before testnet:** R3-2 fix; documentation of the effective ring figures (§8).
12. **Deferred:** decoy re-estimation, which needs testnet data.
13. **Never change:**
    - ring members as global indices checked by consensus;
    - the canonical orderings;
    - the absence of an extra field.

### 4.2 PX

1. **Implemented:**
   - a fixed 2-in/2-out shape;
   - dummies;
   - fixed 1,241-byte ciphertexts;
   - an exact consensus fee;
   - fixed trace shapes (budgets);
   - terminal blinding;
   - the canonical anchor (16 blocks);
   - one proof-error variant;
   - wallet full-download scanning.
2. **Correct:** the items above, with tests cited in privacy-review.md §2. P-5 is well argued (the length is a function of public query positions).
3. **Incomplete:**
   - no PX view/spend separation (known);
   - no wallet-enforced denominations or delays (R3-8).
4. **Fragile:** P-5 depends on the Plonky3 layout (guarded by a regression test); statistical ZK is conditional (known).
5. **Exploitable:** contract-record nullifier tracking (R3-7); round trips (R3-8); call timing (P-8, known).
6. **Inefficient:** 2.18 MB proofs and 45 s proving (known). This is the binding constraint on PX anonymity, because it limits usage.
7. **Does not scale:** about 2,160 PX per day at most, so the anonymity set grows by at most about 4,300 commitments per day.
8. **Missing:**
   - automatic denomination splitting;
   - random submission delay;
   - documentation of R3-7 for contract authors.
9. **Redesign:** hide bridge amounts. Proving a Ristretto Pedersen opening inside BabyBear is non-native and XL; defer.
10. **Innovate:** shielded coinbase (R3-11); a program-hiding proof through recursion (aggregation-study.md §3.3).
11. **Before testnet:** documentation of R3-7 and R3-8 (P0 docs).
12. **Deferred:** constant proof length (P-5 option 1), bridge hiding, recursion.
13. **Never change:**
    - fixed shape and dummies;
    - the exact PX fee;
    - fixed ciphertext length;
    - the canonical anchor;
    - hash-based nullifiers for user records (`nk`-keyed).

### 4.3 Network

1. **Implemented:**
   - D++ with per-epoch routes and outbound-only stem peers;
   - local transactions stemmed even by a diffuser (`dandelion.rs:129-131`, correct per D++);
   - the stempool never served (`GetTx` answers `NotFound` alike);
   - trickled fluff (exponential 2 s outbound, 5 s inbound, `net.rs:476-498`);
   - an encrypted transport with no cleartext magic;
   - a minimal `Version`: no user agent, no timestamp, a per-connection random nonce (`net.rs:595-613`);
   - SOCKS5, proxy-only mode, onion addresses.
2. **Correct:**
   - the minimal handshake is better than Bitcoin's and Monero's (no clock-skew fingerprint);
   - the stem conflict keys include nullifiers;
   - the node's clearnet address is not advertised in proxy-only mode.
3. **Incomplete:** R3-4, R3-5; no I2P.
4. **Fragile:** the global PX budget as a black-hole lever (R3-5).
5. **Exploitable:** R3-5, R3-6, and N-6 (Tor inbound all from 127.0.0.1, so one ban blocks all Tor inbound; known).
6. **Inefficient:** —
7. **Does not scale:** parameters are not tuned for the network size (N4).
8. **Missing:**
   - address-response caching;
   - network separation of the address manager;
   - a "keep in stempool until a stem exists" policy.
9. **Redesign:**
   - on embargo expiry for `Source::Local`, re-stem once through the other stem peer before fluffing (needs analysis first, as privacy-review §3b notes);
   - exempt the node's own transactions from the global PX budget, and do not drop but queue stem PX transactions.
10. **Innovate:**
    - Tor-only transaction broadcast in the style of Monero's `--tx-proxy`. Note the July 2026 ProxyMark attack on exactly that design (Shi et al., [arXiv:2607.07062](https://arxiv.org/abs/2607.07062)): do not copy it blindly.
    - Cover traffic or padding for PX (R3-10), research only.
11. **Before testnet:** R3-4 parameter pair (policy); R3-6 cache (S).
12. **Deferred:** I2P; cover traffic.
13. **Never change:** the minimal `Version` message; no `GetTx` for the stem; per-epoch fixed routes.

### 4.4 Node and RPC

1. **Implemented:**
   - RPC on loopback by default, with a warning otherwise (`node/src/main.rs:93-97`);
   - rejection reasons only to the submitter;
   - RPC submissions enter the stem (`node/src/lib.rs:198-203`).
2. **Correct:** the above; the logs carry no tx origin at info level.
3. **Incomplete:** no authentication, no TLS, no restricted public mode.
4. **Fragile:** an operator exposing RPC for wallets turns the node into A4.
5. **Exploitable:** R3-9.
6. **Missing:** a "public restricted RPC" mode (read-only plus submit, rate-limited) for community remote nodes, served as an onion service.
7. **Before testnet:** documentation. **Deferred:** TLS or authentication, or RPC over the P2P transport.

### 4.5 Wallet

1. **Implemented:**
   - full block download;
   - local trial decryption;
   - a single oversized `/outputs` query;
   - ring reuse;
   - pending-transaction persistence;
   - canonical PX anchor;
   - deterministic fee.
2. **Correct:** strong query hygiene for its model (§R3-9).
3. **Incomplete:**
   - no SOCKS or Tor, no TLS (known);
   - no spend-delay or merge avoidance (R3-1, R3-13);
   - no denominations (R3-8);
   - the restore scan limits (M-2, W-F7, known).
4. **Fragile:** rings are lost on a restore from seed (W-5 residual).
5. **Exploitable:** R3-9; wallet birthday; rebroadcast linkage.
6. **Innovate:** a default spend delay drawn to match the decoy distribution. Instead of forcing the decoys to match real spends, make real spends match the decoys: the wallet waits a random age sampled from the same gamma before spending (opt-out). This addresses guess-newest without consensus changes, at a usability cost.
7. **Before testnet:** the R3-2 fix is in the miner, not the wallet. For the wallet, P1 items R3-1 and R3-3 (below).

### 4.6 Miner

1. **Implemented:** local coinbase construction (the payout address is never sent to the node, `miner/src/lib.rs:38-46`), a hedged RNG, a random nonce start.
2. **Correct:** the address stays local.
3. **Exploitable:** R3-2.
4. **Missing:** fresh-subaddress payouts per block (weak mitigation, since coinbase outputs are already stealth); shielded coinbase (R3-11).
5. **Before testnet:** R3-2.

### 4.7 Operational metadata

- Node logs at info level include peer addresses and the reasons for bans. Debug logs include transaction ids with stem/fluff routing. Operators sharing debug logs reveal routing; this should be documented.
- `bans.json` and the peer table on disk reveal the node's peer history. It is local, but should be documented for seized-machine threat models.
- Wallet file permissions on Unix (known).

---

## 5. Comparison with Monero, Zcash, FCMP++ and Seraphis

| Aspect | BlackSilk v1 | Monero (2022+) | Monero FCMP++ | Zcash shielded | BlackSilk PX |
|---|---|---|---|---|---|
| Anonymity set per input | 16 nominal; §2.1: about 2–10 on early testnet | 16 nominal, about 4.2 effective (OSPEAD) | the whole output set (about 1.5·10^8 per press reports; unverified) | the whole pool | the whole PX tree (usage-bound) |
| Decoy dependence | yes (gamma fitted on 2017 data) | yes | none | none | none |
| Amounts | hidden | hidden | hidden | hidden in-pool, public at t↔z | hidden in-pool, public at the bridge |
| Proof size | about 1.8 KB per 1-in/2-out tx | similar | reported about 2.7 KB membership proof (secondary sources) | about 2–10 KB (Orchard) | 2.18 MB |
| Post-quantum privacy | no | no | no (Carrot/FCMP++ are DL-based; forward-secrecy work is ongoing) | partial | hash-based ownership; conditional |

**Notes and sources:**
- **FCMP++ + Carrot:**
  - the stressnet forked on 2025-10-03 ([Monero Observer](https://monero.observer/fcmp++-carrot-alpha-stressnet-v1-released/));
  - mainnet activation status could not be verified from primary sources in this review (secondary sources conflict);
  - background: [getmonero.org 2024-04-27](https://www.getmonero.org/2024/04/27/fcmps.html), [Carrot spec](https://github.com/jeffro256/carrot/blob/master/carrot.md).
- **Seraphis/Jamtis** was superseded in Monero's roadmap by FCMP++ with Carrot, which keeps RingCT outputs.
- **Lesson for BlackSilk:** the field is moving from decoy rings to full-set membership proofs. BlackSilk already *has* a full-set membership proof (the PX kernel); its problem is cost, not concept.
- **Zcash:** optional privacy with public boundary amounts led to heavy linkability (Kappos et al. 2018). BlackSilk's v1 is not transparent, so its boundary is weaker than Zcash's t↔z, but the amounts at the boundary are equally public.

---

## 6. Should v1 be phased out in favour of PX-only?

**Not now.** The consequences are measured or computed from the repository's own figures [src: brief performance figures, `tx/src/params.rs`]:

| Consequence of PX-only today | Value |
|---|---|
| Capacity | about 3 PX per block, about 2,160 per day (0.025 tx/s), against v1 about 330 transfers per block by weight (600,000 ÷ about 1.8 KB), about 237,000 per day: **about 110× less** [math, estimate] |
| Chain growth at full PX use | about 4.7 GB per day, about 1.7 TB per year [math] |
| Wallet requirements | about 45 s and 3.8 GB peak per spend: no phones, no low-end devices |
| Coinbase | there is no PX coinbase path today; miners would still need v1, or R3-11 |
| Deploys | kind 3 pays through v1 inputs |
| Consensus | new rules; new testnet identity |
| Fee market | PX fee = `PX_STANDARD_FEE` for the maximum size (about 2·MAX_PX_TX_SIZE atomic units); every payment would pay it |

**Recommended staged path:**

1. **Testnet v3 (now; policy only):**
   - R3-2 fix;
   - R3-4 parameter pair;
   - wallet mitigations for R3-1, R3-3 and R3-13;
   - honest documentation (§8).
2. **Owner decision at the v3 genesis (CONSENSUS; new identity anyway, M1):**
   - consider **shielded coinbase** (R3-11). It removes coinbase outputs from v1 rings entirely, fixes R3-3 and R3-1 at the root, makes R3-2 irrelevant for linkage, and seeds the PX pool with every block's reward, growing the PX anonymity set by at least 720 records per day for free.
   - **Cost:** v1 gets outputs only from PX withdrawals and v1 transfers. Early rings would then be drawn from a very small non-coinbase set, and v1 would need a minimum-set guard: the wallet refuses v1 spends while usable non-coinbase outputs are below some N, and directs users to PX.
   - **Needs** the full review → proposal → tests chain.
3. **Mainnet horizon:** make PX the default wallet store of value; v1 becomes a "fast lane" with documented weaker privacy.
4. **Retire v1** only when a membership proof reaches roughly tens of KB and a few seconds (recursion or aggregation, or a dedicated membership STARK over the output tree). Then v1 outputs can migrate into the PX tree.

---

## 7. Recommendations

**Columns:**
- **Consensus:** none / policy / CONSENSUS;
- **Id:** testnet identity change (new identity or not);
- **Diff:** implementation difficulty (S/M/L/XL);
- **Pri:** priority (P0 critical before testnet; P1 high security; P2 hardening; P3 after the trial, or future).

| # | Recommendation | Why | Security | Privacy | Perf. | Complexity | Consensus | Id | Diff | Pri |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | Re-randomize `nonce_start` per template (or per block), `miner/src/main.rs:87,129` | R3-2 | none | removes miner clustering | none | trivial | none | no | S | **P0** |
| 2 | Adopt Monero's pair: q = 0.2 with a 39 s embargo (or keep q = 0.1 with a longer embargo). Drop or justify the 10 s base. Fix the "as in Monero" text | R3-4 | none | better precision; less self-fluff | slightly faster fluff | low | policy (P2P) | no | S | **P0** |
| 3 | Documentation (§8), including correcting P7 and N4 in assumptions.md | owner policy on claims | — | honest | — | low | none | no | S | **P0** |
| 4 | Decoys: draw a **block** by gamma age, then a uniform output among the *eligible* outputs of that block; redraw in the same age band if none. Compute `average_output_time` over a recent window (Monero uses up to 1 year) | R3-1 | none | restores the young-decoy mass | negligible | medium (wallet and node must expose per-block eligibility; the RPC already gives the `coinbase` flag) | none | no | M | P1 |
| 5 | Default spend delay: the wallet refuses to spend outputs younger than a random age from the picker's own distribution (or at least 60 blocks), with an explicit override | R3-1 on a quiet chain, where #4 cannot help (no young non-coinbase outputs exist) | none | large for young spends | UX latency | low | none | no | S | P1 |
| 6 | Coinbase-aware policy: miners sweep coinbase outputs into PX (wallet command `sweep-coinbase-to-px`); document the coinbase-heavy ring effect; publish effective-ring estimates per testnet week (measured, not assumed) | R3-3 | none | medium | PX cost for miners | medium | none | no | M | P1 |
| 7 | Keep local transactions in the stempool until a stem peer exists (with a long fallback). Exempt `Source::Local` from the global PX budget. Queue rather than drop over-budget stem PX transactions. Analyse local-origin re-stem on embargo expiry | R3-5 | DoS trade-off (queue bounds) | high | small | medium | policy | no | M | P1 |
| 8 | Cache the GetAddr response per network for about 24 h; cap it at about 23% of the address manager; never serve onion addresses to clearnet peers or the reverse unless dual-homing is configured; document "onion-only nodes must bind to 127.0.0.1" | R3-6 | none | medium | none | low | policy | no | S | P1 |
| 9 | Wallet: SOCKS5 (reuse `p2p/src/socks5.rs`), separate circuits for query and submit, optional delayed submit (known item A7b; deepened) | R3-9 | TLS or onion also authenticates | high | latency | medium | none | no | M | P1 |
| 10 | Document R3-7 in docs/px.md and the contract guide. Add a lint or test in the contract tooling that `rcm` is not derived from public data (ties to PX-F4 option B) | R3-7 | none | medium | none | low | none | no | S | P1 (docs P0) |
| 11 | Wallet bridge hygiene: optional automatic denominations (1-2-5 series), split deposits, random delays, refusal of an exact round-trip amount unless overridden | R3-8 | none | medium | more PX transactions (capacity!) | medium | none | no | M | P2 |
| 12 | Merge avoidance: do not co-spend outputs from the same transaction or block without a warning | R3-13 | none | low-medium | none | low | none | no | S | P2 |
| 13 | Shielded coinbase into PX (ZIP 213-style opening, `rho` from the height, a fresh diversified address per block) | R3-11, R3-3, R3-1 at the root | new consensus surface (value check without a proof) | high | none for nodes | high | **CONSENSUS** | **new** (fits v3) | L | P2 (decide at v3 genesis) |
| 14 | Consider making the v1 fee exact in consensus (as PX) | fee fingerprint from third-party wallets | none | low | none | low | **CONSENSUS** | new | S | P3 |
| 15 | PX size padding or cover traffic research; I2P | R3-10 | — | against A6 | bandwidth | high | none | no | L | P3 |
| 16 | Long term: a cheap full-set membership proof for v1, then retire rings (§6) | ceiling of ring privacy; PQ | high | very high | major | XL | **CONSENSUS** | new | XL | P3 |
| 17 | Restricted public RPC mode as an onion service for community remote nodes | R3-9 ecosystem | reduces exposure | medium | none | medium | none | no | M | P2 |

---

## 8. Must be documented as limitations (user-facing)

1. **"Ring of 16" is not an anonymity set of 16.** Publish the §2.1 figures (clearly as simulations). Early-testnet effective rings can be about 2 against miners, and young spends are identifiable. Correct assumptions.md P7.
2. **Spend delay:** spending an output soon after receiving it (under about 60 blocks) is likely to be identifiable on a quiet chain.
3. **Coinbase outputs** dominate early rings. Miners can eliminate their own; until R3-2 is fixed, anyone can cluster them by miner.
4. **Dandelion++** is tuned by analogy, not by measurement (N4). Local transactions can be fluffed directly when no stem peer exists, or when an adversary black-holes the stem (R3-5).
5. **Tor:** a node reachable over both clearnet and onion can be linked (R3-6). Use onion-only binding.
6. **Remote nodes and RPC** are plaintext today. A remote node or on-path observer sees your transactions, your ring candidates and your wallet's birthday.
7. **PX:**
   - bridge amounts are public, and entering and leaving PX reveals amounts that v1 would hide;
   - the anonymity set equals PX usage (small on testnet);
   - contract records can be tracked by anyone who holds their opening (R3-7);
   - PX transaction size identifies the origin to link-level observers (R3-10).
8. **Post-quantum:** v1 privacy can be broken retroactively by a quantum adversary; PX's does not rest on discrete logs (conditional).
9. **Restore from seed** loses stored rings (known, W-5).

## 9. Never change (without strong new evidence)

- PX: the fixed 2/2 shape and dummies, the fixed ciphertext length, the exact consensus fee, the fixed trace budgets, terminal blinding, the canonical anchor, and `nk`-keyed user nullifiers.
- v1: the absence of `tx_extra` and `unlock_time`, canonical input and output ordering, the mandatory change output, and the network id bound into signatures.
- P2P: the minimal `Version` (no user agent, no timestamp, a per-connection nonce), stempool invisibility, per-epoch fixed stem routes, and outbound-only stem peers.
- Wallet: the single oversized shuffled `/outputs` query per input, full-block scanning (no view-key delegation), and rebroadcasting unchanged with ring reuse.

## 10. Open questions for the owner

1. Is shielded coinbase (R3-11) acceptable for v3, given it makes v1 dependent on PX withdrawals for new outputs?
2. Is a default spend delay (recommendation #5) acceptable for testnet UX?
3. Should testnet collect opt-in, anonymized spend-age data to fit a BlackSilk decoy distribution (OSPEAD-style)? This must be designed so that it does not itself leak.

## Sources

- Fanti, Venkatakrishnan, Bakshi, Denby, Bhargava, Miller, Viswanath, "Dandelion++", ACM SIGMETRICS 2018.
- Monero PR #7025 (Dandelion++ 20% / 39 s): https://github.com/monero-project/monero/pull/7025
- Monero PR #6973 (fluff without outbound): https://github.com/monero-project/monero/pull/6973
- Möser et al., "An Empirical Analysis of Traceability in the Monero Blockchain", PoPETs 2018(3).
- Kumar, Fischer, Tople, Saxena, "A Traceability Analysis of Monero's Blockchain", ESORICS 2017.
- Ronge, Egger, Lai, Schröder, Yin, "Foundations of Ring Sampling", PoPETs 2021.
- Rucknium, OSPEAD: https://github.com/Rucknium/OSPEAD ; CCS: https://ccs.getmonero.org/proposals/Rucknium-Statistical-Research.html ; black-marble analysis: https://github.com/monero-project/research-lab/issues/119
- Kappos, Yousaf, Maller, Meiklejohn, "An Empirical Analysis of Anonymity in Zcash", USENIX Security 2018.
- Zcash ZIP 213, "Shielded Coinbase".
- Biryukov, Khovratovich, Pustogarov, "Deanonymisation of Clients in Bitcoin P2P Network", ACM CCS 2014; Biryukov, Pustogarov, "Bitcoin over Tor isn't a Good Idea", IEEE S&P 2015.
- Shi et al., "Deanonymizing Monero Transactions in Tor Network" (ProxyMark), arXiv:2607.07062, July 2026.
- "Eclipse Attacks on Monero's Peer-to-Peer Network", NDSS 2025: https://www.ndss-symposium.org/wp-content/uploads/2025-95-paper.pdf
- Hinteregger, Haslhofer, "An Empirical Analysis of Monero Cross-Chain Traceability", FC 2019 (relevant only if a chain were ever forked with shared history; the fresh v3 genesis avoids this).
- FCMP++: https://www.getmonero.org/2024/04/27/fcmps.html ; Carrot: https://github.com/jeffro256/carrot/blob/master/carrot.md ; stressnet: https://monero.observer/fcmp++-carrot-alpha-stressnet-v1-released/
- S. D. Lerner, "The Well Deserved Fortune of Satoshi Nakamoto" (2013), the nonce/extranonce "Patoshi pattern".
