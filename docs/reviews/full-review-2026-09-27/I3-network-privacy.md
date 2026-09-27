# I3: Network-level privacy and censorship resistance, innovation research (BlackSilk, 2026-09-27)

Internal review and innovation research, not an audit. It is read-only: no repository file was changed and nothing was built. The repository was read at `rebuild/core` `9578517`, and the p2p crate matches the brief's scope. Web sources are listed at the end, and no repository content was sent to any service.

**Scope.** This report covers:
- metadata-resistant networking;
- Dandelion++ and alternatives;
- peer discovery and eclipse resistance;
- transport obfuscation and anti-censorship;
- Tor, I2P and Arti;
- private mempools and MEV;
- light-wallet privacy;
- miner and transaction censorship.

**Inputs:**
- `docs/p2p.md`;
- `p2p/src/{transport,dandelion,addrman,socks5,net}.rs`;
- `node/src/config.rs`;
- `wallet/src/wallet.rs`;
- `rpc/src/lib.rs`;
- `docs/reviews/privacy-review.md` §2.5 and §3b;
- the sibling reviews `R8-p2p.md` and `R3-privacy.md`. They already cover most P2P defects, so this report cites their items instead of re-reporting them.

**Evidence tags:**
- [M] mathematically established or a simple calculation;
- [T] tested (named test);
- [SR] source-read;
- [A] assumed or taken from external documentation;
- [U] unknown.

---

## 0. Executive summary

1. **New, medium-high: an `InvTx` probe reveals which nodes hold a transaction in the stempool.**
   - Where: `net.rs:1261-1264` and `:1266-1276`.
   - The mechanism: a node that receives `InvTx(id)` for an id in its stempool fluffs it and sends no `GetTx`. For an unknown id it sends `GetTx`.
   - Any peer that knows a stem transaction's id can therefore test every node it is connected to for stem-path membership, the origin included. Being a stem hop anywhere downstream is enough to learn the id.
   - The probe also forces the probed node to fluff at once.
   - This contradicts privacy-review §3b, which lists "no reply that differs between have and have not" as a mitigation. It is a third probe form, cheaper than the conflict and replay probes documented as P-6.
   - The fix is policy-only and S effort: treat a stempool id as unknown on `InvTx`, and leave the stem only when the full transaction arrives. **P1.** §2.1.
2. **New, medium: `--public-address <x>.onion` without `--proxy-only` hands the onion address to every clearnet peer.**
   - Where: `config.rs:203-219`, `net.rs:605-612`.
   - The node listens on `0.0.0.0` and sends `Version.listen` on every connection, so any clearnet peer links the onion identity to the IP at once.
   - This is the most direct form of the identity link that R8-19 and R3-6 approach through GetAddr.
   - The fix is policy-only and S effort: send `listen` only on connections of the same network class, and refuse the risky combination at config time. **P1.** §2.2.
3. **Tor through Monero's `--tx-proxy` design is not enough.** For local transactions, adopt the 2026 Bitcoin Core *private broadcast* pattern instead: one fresh isolated Tor connection per transaction, to a peer drawn at random, with the transaction sent as `StemTx`.
   - The July 2026 ProxyMark attack (arXiv:2607.07062) breaks Monero's fixed-proxy design at 100 % precision for onion-ID identification. It works through connection occupation, a height-biased proxy choice and Tor-cell watermarks.
   - BlackSilk already avoids the height bias, because its stem choice ignores `Version.height`. Keep it that way.
   - Private broadcast still depends on R8-3/R8-5 (addrman poisoning) being fixed first. **P1 design, P2 implementation.** §3.3.
4. **No transport or anonymity network hides a 2.2 MB PX upload from the origin's ISP**, and that includes Tor, Nym and I2P (R8-18, R3-10 extended).
   - Monero-style noise (3 KiB every 10–15 s, at most 60 KiB per payload) would take hours per PX transaction [M].
   - Poisson PX-sized cover traffic costs about 300 MB per day per node at a 10-minute slot [M].
   - The only root fix is **smaller PX transactions** (recursion or aggregation). That makes proof size a network-privacy problem as well as a throughput problem. Document it now; research it at **P3**. §3.5.
5. **Arti (Tor in Rust) is mature enough to run out of process, but not to embed.**
   - Status: Arti 2.5.0 (June 2026) has a stable client and onion services. `arti-client` 0.46 is still pre-1.0.
   - Blockers for embedding: `tor-dirmgr` depends on `rusqlite` (C SQLite) unconditionally, and the default features pull in xz and zstd (C) and native-tls.
   - Embedding would therefore break the project's no-C/no-FFI rule.
   - Recommendation: keep the SOCKS5 boundary (it already works with an external `arti proxy` or C tor); add stream isolation (R8-6) and a dedicated onion inbound port. §3.6.
6. **Encrypted mempools, threshold decryption, commit-reveal and fair ordering: rejected** for this PoW chain.
   - They need a committee or a trusted beacon, or they break validate-before-include.
   - The chain has little MEV: confidential amounts, a fixed PX fee, no public AMM state.
   - The real censorship levers are the visible *contract/program id* of PX calls (P-8) and v1 ring members (taint censorship). They are fixed by uniformity and program hiding, and mitigated by solo mining and P2Pool, not by mempool encryption. §3.8.
7. **Light-wallet privacy has two cheap policy wins.**
   - **(a) Local output index (P1).** The wallet already downloads every block, so it can index every output locally and stop calling `/outputs`. That call hands the node a superset of the future ring, the real input included. Bucketed fetching would *not* be enough (§3.9).
   - **(b) Compact scan blocks (P2).** The same data for every wallet, with proofs and signatures stripped: roughly 99 % less download for PX blocks [estimate].
   - PIR and OMR are P3 research; FMD is rejected.
8. **Peer discovery.** R8's Bitcoin-parity addrman plan is the right P0/P1 base. Beyond it:
   - asmap-style AS grouping (P2);
   - a dedicated onion inbound listener with network-class tagging (P1, extends N-6);
   - per-network GetAddr caches (R8-19);
   - optional PoW-stamped onion adverts (P3, weak Sybil cost).

   DHT-based discovery is rejected. The 2026 Monero eclipse paper (CCS'26: peer-list poisoning through reachable relays) confirms that R8-3 is urgent.

**Nothing in this report needs a consensus change.** Everything is node, wallet or RPC policy, except two rejected items (commit-reveal, FMD) and one future item (program hiding through recursion). None of the recommended items needs a new testnet identity.

---

## 1. Subsystem answers (the 13 questions), network-privacy lens

| # | Question | Answer (evidence) |
|---|---|---|
| 1 | Implemented | Ephemeral Ristretto DH transport with AES-256-GCM and `network_id` bound into the KDF [SR `transport.rs:116-187`; T `different_networks_cannot_talk`]. D++ with 2 stems, q = 0.1 and per-source epoch routes [SR `dandelion.rs`; T `routes_are_stable_within_an_epoch`]. GetTx serves only announced transactions [T `mempool_cannot_be_probed_with_gettx`]. Secret-keyed addrman. SOCKS5 with onion names resolved by the proxy [T `onion_names_go_to_the_proxy`]. Proxy-only mode refuses local DNS [SR `config.rs:263-273`]. No user agent, clock or service bits in `Version` [SR `net.rs:605-613`] |
| 2 | Correct and well designed | Local transactions always stem, even on a diffuser [SR `dandelion.rs:130`]. Stem peers are chosen **without regard to the peer-claimed height** [SR `net.rs:1565`, `dandelion.rs:95-126`], which avoids ProxyMark's proxy-selection bias. No plaintext magic. Proxy-only mode binds no clearnet listener by default [SR `config.rs:209-211`] |
| 3 | Incomplete | tx-proxy / private broadcast; stream isolation (R8-6); I2P; network-class separation (stems, trickle, GetAddr, `listen`); padding |
| 4 | Fragile | Stem privacy depends on no node ever answering differently for stempool ids. It does today (§2.1). Tor inbound (N-6). The addrman (R8-3/4/5) |
| 5 | Exploitable | §2.1 InvTx stempool oracle; §2.2 onion↔IP link through `Version.listen`; R8-18 size-based origin; R3-5 forced self-fluff; R3-6 addr cookies; R8-3/5 eclipse |
| 6 | Inefficient | The wallet downloads full blocks with 2.2 MB proofs it never uses (§3.9) |
| 7 | Does not scale | D++ anonymity does not grow with network size (Sharma et al., NDSS 2023); PX size makes cover traffic and mixnet transport expensive (§3.5) |
| 8 | Missing | Private broadcast; per-network state; a local output index; compact scan blocks; transport v2 (obfuscation and optional authentication) |
| 9 | Redesign | The stem-ingress rule for `InvTx` (§2.1). How the local-transaction first hop is chosen (§3.3). Network classes as a first-class concept in `net.rs` (§3.4) |
| 10 | Innovate | A unified *transport v2*: Noise NK-style with an Elligator-encoded ephemeral and an optional responder static key taken from the address. It gives probe resistance, optional authentication and bridge mode in one (§3.7). PoW-stamped onion adverts (§3.4). Per-transaction isolated private broadcast into the D++ stem (§3.3) |
| 11 | Before testnet | §2.1 and §2.2 fixes; the R8 P0/P1 addrman items; R8-6 stream isolation; documentation of the PX-size limitation |
| 12 | Defer | Transport v2; I2P (emissary or SAM); Nym; PIR/OMR; cover traffic; P2Pool/SV2-style pool protocol; asmap |
| 13 | Never change | No plaintext magic; `network_id` in the KDF; local-always-stem; per-source fixed routes; GetTx-only-announced; **no height-based stem or proxy choice**; SOCKS5 as the only anonymity-network boundary (no embedded C Tor) |

---

## 2. New findings

### 2.1 I3-1: An `InvTx` probe reveals stempool membership and forces fluff (NEW)

- **Class:** Partially implemented (a design defect in the stem ingress rules).
- **Severity:** **Medium-high** (privacy: this is D++'s main guarantee).
- **Location:**
  - `p2p/src/net.rs:1254-1276` (`on_inv_tx`: `known_txs.insert`, then for a stempool id `to_fluff.push(id); continue`, which sends no `GetTx`);
  - `:1279-1281` (immediate `fluff`);
  - `:1526-1546` (the fluff announces to every peer except those that "know" the id, prober included);
  - spec: `docs/p2p.md:220-223` ("seen in fluff (announced by a peer …)").
- **Evidence:** [SR]; not tested; impact estimate [M, model below].
- **Confidence:** high that the oracle exists; medium on real-world impact, because it depends on how many nodes spies are connected to.

**Oracle.** A peer P sends `InvTx(id)` to a node X it is connected to:

| State of X | X's visible reaction to P |
|---|---|
| id unknown | `GetTx(id)` to P, unless another peer's request is in flight |
| id in stempool | **no `GetTx`**; X fluffs immediately. Every other peer of X receives `InvTx(id)` after the trickle, P does not |
| id in mempool or recent rejects | no `GetTx` |

Before the transaction is fluffed, only stem-path nodes have ever seen its id, so "no `GetTx`" means "X is on the stem path". Colluders connected to X also see X start announcing an id that was never fluffed, which is a second observation.

**Attack:**
1. A spy S receives `StemTx(id)`: it is some stem hop, or a colluder of one.
2. S immediately sends `InvTx(id)` over every connection it has. Spies typically connect inbound to every reachable node and are often among unreachable nodes' outbound peers.
3. Every reachable node that stays silent is on the upstream stem path: the origin, the relays and S's predecessor.
4. With a stem length beyond the origin that is geometric with q = 0.1, the expected path has about 10 hops [M]. The spy therefore narrows the origin from N nodes to the few path members it can reach, typically ≤ 5 when it sits mid-path.
5. It needs only one spy on the path. With a 10 % spy fraction and about 10 hops, P(at least one spy on the path) ≈ 1 − 0.9^10 ≈ 0.65 [M].
6. The probe also *fluffs the transaction at every probed path node*. That destroys the embargo structure and turns the origin (if probed) into a fluff source that other colluders observe.

**Why it is not P-6:**
- P-6 conflict probing needs a valid double spend (only the owner can build one).
- P-6 replay probing needs colluders downstream of the probed node.
- This probe needs only the id and one connection.
- The claim in privacy-review.md:389 ("silent drops, with no reply that differs between have and have not") holds for `StemTx` and `GetTx`, but **not for `InvTx`**.

**Recommendation** (policy; a change to docs/p2p.md §8):
- On `InvTx` for an id in the stempool, behave **exactly as for an unknown id**: record the announcer and send `GetTx`.
- Leave the stem only when the full transaction arrives as a requested `Tx`. `on_tx` already moves a stempool entry to the mempool (`net.rs:1412-1418`), so the existing fluff trigger remains, but it now needs the prober to deliver the bytes. Anyone holding the bytes could fluff them anyway.
- Keep the embargo timer as the only other exit.
- Also make `recent_rejects` handling identical in both branches. It is already silent.
- **Test:** add `inv_for_a_stem_transaction_is_answered_like_an_unknown_one` in `p2p/tests/network.rs`. It asserts that a `GetTx` is sent and that no fluff happens before `Tx` arrives.

**Residual:**
- Timing. X re-validates on `Tx` whether or not it held the transaction, so the cost is the same. Verify that no fast path skips validation for stempool entries.
- Replay probing (P-6) remains.

| Field | Assessment |
|---|---|
| Why | Closes a cheap, single-spy origin-narrowing oracle and a forced-fluff trigger |
| Security | Neutral. One `GetTx` per inv, already bounded by the inv rate |
| Privacy | High |
| Performance | Negligible. A few extra `GetTx`/`Tx` round trips, only in a rare race |
| Complexity | Low |
| Consensus | None (policy) |
| Testnet identity | No |
| Difficulty | S |
| Priority | **P1**. It is P0 if D++ origin privacy is advertised as a testnet property |

### 2.2 I3-2: `Version.listen` leaks a configured onion address to every clearnet peer (NEW)

- **Class:** Partially implemented.
- **Severity:** **Medium** (privacy, a configuration footgun).
- **Location:**
  - `node/src/config.rs:203-219`: `public_address` is accepted whatever the proxy mode, and without `--proxy-only` the listener defaults to `0.0.0.0`;
  - `p2p/src/net.rs:611`: `listen: inner.cfg.public_address.clone()` is sent in **every** `Version`, inbound and outbound, whatever the network class of the connection.
- **Evidence:** [SR].
- **Confidence:** high.

**Scenario.** The operator runs an onion service and sets `--proxy 127.0.0.1:9050 --public-address abc….onion`, but not `--proxy-only`, because they still want clearnet inbound peers.
- Any spy that connects to the node's clearnet IP receives `Version.listen = abc….onion` in the handshake. The onion identity and the IP are linked with certainty, in one connection.
- The same happens on direct clearnet outbound connections when no proxy is set.
- R8-19 and R3-6 describe the statistical versions of this link (clearnet listening under `--proxy`, GetAddr cookies). This one is deterministic.

**Recommendation:**
- Send `listen` only on connections of the **same network class** as the address:
  - an onion address only on proxied or onion connections;
  - a clearnet address only on clearnet connections.
- Allow one `public_address` per class.
- At config time, refuse or loudly warn about `public_address = *.onion` together with clearnet listening, unless `--allow-dual-homed` is set, and document that dual-homing is linkable.
- Test: a clearnet inbound handshake to a node configured with an onion `public_address` carries `listen = None`.

| Field | Assessment |
|---|---|
| Consensus | None |
| Testnet identity | No |
| Difficulty | S |
| Priority | **P1** |

### 2.3 I3-3: Traffic-rate freedom gives a Tor watermark channel (NEW, low)

- **Class:** Accepted limitation, improvable.
- **Severity:** Low.
- **Location:** rate limits of 50 messages/s with a burst of 500 (`docs/p2p.md` §10); pings are allowed at any rate under that.
- **Evidence:** [SR], plus [A] from ProxyMark §3.

ProxyMark encodes a node-level identifier into the number of messages per time window. Malicious Tor *guards* then read it back from the cell timing. A BlackSilk peer may send Ping, GetAddr-free Addr (≤ 10 entries), InvTx and similar messages at any cadence under 50/s. A malicious peer can therefore modulate its traffic *towards* a proxied node and confirm the node's guard or IP with malicious guards.

The authors' countermeasure is strict fixed cadences for keep-alives, with violators disconnected. For BlackSilk that means:
- on proxied or onion connections, at most 1 unsolicited Ping per 30 s;
- batch outbound writes to a fixed flush interval (for example 1 s ticks);
- disconnect peers whose control-message cadence deviates.

This only raises the watermark's cost. Inbound shaping at the victim cannot stop an attacker's traffic from entering its guard. **P3.** Consensus: none.

### 2.4 Design note: local transactions share one stem route per epoch (info)

`Source::Local` gets one route per epoch (`dandelion.rs:136-141`). All of a node's own transactions in about 10 minutes therefore go to the same stem peer, which can see that they share a source. D++ uses this deliberately against intersection attacks.

Bitcoin Core's private broadcast (§3.3) takes the opposite view for *originated* transactions: one isolated connection per transaction, so that transactions cannot be linked. Private broadcast would replace the local first hop, so this becomes moot if §3.3 is adopted. No separate action.

---

## 3. Innovation evaluations

Each subsection gives: what exists, the idea, its benefit, pure-Rust feasibility, consensus impact, cost, complexity, and a verdict.

### 3.1 Dandelion++ weaknesses and alternatives

**What the literature says:**
- **Sharma, Gosain, Diaz (NDSS 2023):** Bayesian analysis. With 15 % adversarial nodes, Dandelion leaves on average **about 8 candidate originators**. For both Dandelion and D++, **the anonymity set does not grow with network size** [A, paper]. BlackSilk's docs should present D++ as "a small anonymity set against spy nodes", not as network-wide anonymity.
- **Monero parameters (current master):** 2 stems, fluff probability **20 %**, 10 min + 30 s epochs, flush average 5 s, embargo average 39 s [A, `cryptonote_config.h`]. This confirms R3-4: BlackSilk's q = 0.1 together with a 39 s embargo is an unmatched pair.
- **Clover (Franzoni and Daza, 2022):** a stem/fluff design that treats inbound and outbound peers differently, needs no propagation graph, and cuts an eavesdropper's precision by up to 10× compared with diffusion [A]. BlackSilk's D++ already maps inbound sources to outbound stems. Clover's gain over D++ is not established and would need its own analysis. **Verdict: do not switch; cite Clover as an alternative in the docs.**
- **Adaptive diffusion (Fanti et al. 2015):** it needs knowledge of the graph structure and assumes a regular-tree-like topology. It has not been deployed and is fragile under active adversaries. **Rejected.**

**Actionable D++ hardening** (all policy; each needs analysis first under owner policy):

| Item | Source | Priority |
|---|---|---|
| InvTx stempool oracle | §2.1 | P1 |
| Consistent q/embargo pair; tune with the labnet | R3-4 (known) | P1 |
| Origin-fires-first mitigation: a longer local embargo, or re-stem through the other stem | R8-17 (known) | P2 |
| Hold local transactions when no stem peer exists (Monero behaviour) | known (A8) | P0/P1 |
| Stem conflict check before `check_tx` | R8-7 (known) | P1 |
| Shared inbound trickle timer; shuffled invs | R8-16 (known) | P1 |
| Measure: a labnet simulation of first-spy precision under 5/10/20 % spies, as the evidence for any claim | new | P2 |

### 3.2 Mixnets (Nym and Loopix) and cover traffic for the whole network

**What Loopix/Nym offer:**
- Poisson mixing with sender and loop cover traffic, which resists a global passive adversary (Piotrowska et al., USENIX Security 2017).
- Nym runs it as a network. Its mixnet is live in Zcash wallets such as Zingo and Zkool as of 2026 [A, Nym blog].

**Feasibility for BlackSilk:**
- **Build our own mixnet.** Rejected (XL). A mixnet's anonymity comes from its independent operator set and traffic volume; a small testnet has neither.
- **Embed `nym-sdk`.** Rust (1.21.6, Apache-2.0). It is a very large dependency tree (about 3 M SLoC by lib.rs's count) with bandwidth-credential machinery. Its C and unsafe content has not been reviewed [U]. It also ties users to Nym's token economics. **Rejected for project crates.**
- **Out-of-process.** The wallet or node talks SOCKS5 to a local Nym SOCKS client, exactly as it does with Tor. This needs **no new dependency**: only the SOCKS5 client (`socks5.rs`) and wallet SOCKS support (the known A7b work). **Accept as P3, documentation only.**
- **Cost for PX.** Sphinx packets are about 2 KB, so 2.2 MB means about 1,100 packets plus cover. That is feasible for occasional submissions, with latency in minutes [estimate].

**Consensus impact:** none. **Recommendation:** keep SOCKS5 as the single anonymity-network boundary (never change) and document Nym as a tested option once someone verifies it on labnet.

### 3.3 Private broadcast of local transactions (tx-proxy done right)

**Prior art:**
- **Monero `--tx-proxy`:**
  - local transactions go only over anonymity networks and are queued if none is available [A, ANONYMITY_NETWORKS.md];
  - 3 KiB noise frames every 10–15 s on at most 2 channels, at most 20 fragments [A, `cryptonote_config.h`, `levin_notify.cpp`];
  - clearnet transaction messages are padded to 1 KiB granularity [A, `levin_notify.cpp:173-199`].
- **ProxyMark (July 2026)** broke Monero's design [A, arXiv:2607.07062]. The two proxies are fixed per epoch and filtered by unverified peer height. Adversarial onion nodes that advertise height + 5 get chosen. About 5,000 onion addresses saturate a whitelist in about 2 hours. A Tor-cell timing watermark maps the onion to an IP through malicious guards: 179 relays give 12 %, 1,000 relays give 27–46 %.
- **Bitcoin Core 31 `privatebroadcast`:** each own transaction goes over a **short-lived** Tor or I2P connection, a separate one per transaction, and the node does not add it to its own mempool until it comes back from the network [A, PR #29415, Core 31.0 notes]. Since PR #36309 it is marked experimental, with "best-effort" claims.

**Proposal for BlackSilk** (policy; P1 to design, P2 to implement after the addrman fixes):
1. `--private-broadcast` (requires `--proxy`). For each *local* transaction:
   - draw a peer uniformly from the *tried* table, preferring onion addresses and falling back to clearnet over Tor;
   - open a fresh SOCKS connection with **random RFC 1929 credentials**, so Tor isolates the stream (R8-6);
   - complete the handshake and send `Version` with `listen = None` and a fresh nonce;
   - send the transaction as **`StemTx`**, so it enters the receiver's D++ stem as an inbound source instead of being fluffed;
   - close the connection after a short random linger.
2. Do not put the transaction in our own stempool or mempool until it comes back in fluff. This removes the origin-fires-first issue (R8-17) and the §2.1 oracle *at the origin*.
3. Re-broadcast unchanged through a *different* random peer after a timeout (W-6 rule: never rebuild).
4. Do **not** filter by peer-claimed height (ProxyMark §4). If a filter is ever needed, use verified header work.
5. Queue, never fall back to clearnet, when Tor is unavailable (the Monero rule).

**What it buys:**
- Stem spies and first-hop peers no longer learn the origin IP.
- Two transactions of one user cannot be linked by connection.

**What it does not buy:**
- It does nothing against the origin's ISP for PX: a 2.2 MB Tor upload is still visible (§3.5).
- It does nothing against a poisoned addrman, because the random peer is drawn from it. **The addrman fixes (R8-3/4/5) are a prerequisite.**

| Field | Assessment |
|---|---|
| Why | The strongest practical origin protection, with a 2026 negative precedent to learn from |
| Security | Low risk. Short-lived connections are rate-limited like any outbound |
| Privacy | High against spy nodes; none against the ISP for PX |
| Performance | One Tor circuit per transaction; PX takes seconds to a minute over Tor |
| Complexity | M |
| Consensus | None |
| Testnet identity | No |
| Difficulty | M |
| Priority | P1 design, P2 implementation |

### 3.4 Peer discovery and eclipse resistance beyond R8

**Base (known, R8-3/4/5/13):**
- per-source bucket limits;
- an addr rate limit;
- timestamps and terrible-address eviction;
- feelers and test-before-evict;
- anchors;
- block-relay-only connections;
- inbound eviction;
- stale-tip recovery;
- onion grouping.

**Monero precedent (CCS'26, arXiv:2609.10260):** "Nyx/Moros" poison reachable nodes' peer lists. Those nodes then relay the poison into unreachable nodes' white lists, and the attacker exploits connection refresh to evict benign neighbours [A]. BlackSilk's `on_addr` relays fresh small batches (`net.rs:924-932`) with no rate limit (R8-3). It has the same propagation path. **This strengthens R8-3's P0/P1 rating.**

**Beyond parity:**

| Idea | Benefit | Pure Rust | Cost | Verdict |
|---|---|---|---|---|
| **Network classes as first-class state** (clearnet, onion, later I2P): separate stem peers, trickle timers, GetAddr caches, `listen` values and inbound limits per class | Closes §2.2, R8-19 and R3-6 structurally, not item by item | Trivial | Low | **P1** |
| **Dedicated onion inbound listener** (a `--onion-inbound 127.0.0.1:P` port, as in Monero's `--anonymous-inbound`): connections on that port are tagged onion, never IP-banned, and limited as a class | Fixes N-6 (all Tor inbound = 127.0.0.1, one ban blocks all), and tells the node which class a peer is in | Trivial | Low | **P1** (extends known N-6) |
| **asmap-style AS grouping** for IPv4/IPv6 groups (Bitcoin Core `-asmap`; defends against Erebus-style AS-level attacks) | Cloud attackers across many /16s share few ASes | A small pure-Rust interpreter for the compressed map; the data file is an operational burden | Map maintenance | **P2**, after the R8 parity items |
| **PoW-stamped onion adverts**: an onion address in `Addr` carries a hashcash stamp over (onion pubkey, network id), costing for example about 1 CPU-minute to mint | Raises the cost of minting 5,000 onions (the ProxyMark scale) to about 3.5 CPU-days. A weak Sybil barrier, not a defence | Trivial (Blake2) | Honest nodes pay once per onion | **P3**, optional; honest about weakness |
| **Verified onion checksum and version** (R8-5 notes these are missing) | Stops junk onions | Trivial | — | P1 (part of R8-5) |
| **DHT discovery** (Kademlia/S-Kademlia, rust-libp2p) | Scales lookup | Available in Rust, but a large dependency tree | Eclipse-prone by construction; adds dependencies | **Rejected**: a gossip addrman with Core's defences is better studied and suits a small network |
| **DNS seeds** | Bootstrapping | — | Local DNS leaks, and seeds centralize trust | Keep literal IP and onion seeds. Never resolve in proxy mode (already enforced, `config.rs:270-273`). Ensure seed-operator diversity at launch |

### 3.5 Cover traffic, padding and constant-rate links

**The PX problem in numbers [M]:**
- PX transfer about 2.18 MB, vault about 2.69 MB (measured, brief).
- **Monero noise mode** carries at most 20 × 3 KiB = 60 KiB per covert payload, one fragment per 10–15 s per channel. One PX transaction would need about 730 fragments, about 2.5 hours on one channel. **Not viable for PX.**
- **Constant-rate stem link** sized to carry one PX per 40 s: about 68 KB/s per link, about 5.9 GB per day per link. **Not viable** as a default.
- **Poisson PX-sized cover** (Loopix-style: a node emits one 2.7 MB cell to a random peer at Exp(10 min) intervals, and a real PX transaction replaces the next dummy): about 4.5 KB/s, about 390 MB per day per node, with a mean added latency of 5–10 min.
  - Stem relays would also need to replace their own dummies with forwarded real cells, or their ISPs see in-then-out.
  - Feasible only as an **opt-in privacy mode**.
- **Size buckets / padding** (R8-18b): cheap. They separate classes (v1 vs PX) no further than the kind already does, but they hide v1 fan-in/out and PX function counts. **P2.**

**Root fix:** the ISP signal is the *size* of PX transactions. Smaller proofs, through recursion (aggregation-study §3.3, a separate milestone), would also let PX transactions blend into cover traffic at acceptable cost. **Record "network privacy" as a second motivation for proof compression (P3 research).** Until then, docs/p2p.md §1 and px.md §12 should say plainly: *PX origin is visible to the origin's ISP, including over Tor, by upload volume and timing*.

### 3.6 Tor, I2P and Arti in pure Rust

**Arti status (as of September 2026):**
- Arti 2.4.0 (June 2026) made flow and congestion control stable and fixed onion-service client bugs [A].
- Arti 2.5.0 (June 2026) made Counter Galois Onion stable and fixed TROVE-2026-024 and TROVE-2026-027 (DoS) [A].
- Relay and directory-authority support is still in progress [A].
- The `arti-client` crate is **0.46.0** (2 September 2026). It is still pre-1.0 ("expect a certain amount of breakage"), and its experimental features have no semver guarantees [A, docs.rs].

**Dependency facts that break the project's pure-Rust / no-C policy if embedded [A, lib.rs and docs.rs]:**
- `tor-dirmgr` depends on `rusqlite` **unconditionally**, and so on C SQLite (static or system).
- `tor-dirclient` enables **xz** and **zstd** by default. Their Rust bindings wrap C libraries (liblzma and zstd). They can be disabled at a bandwidth cost.
- The default TLS is **native-tls** (OpenSSL, SChannel or Security.framework). A `rustls` feature exists.
- `mmap` is on by default (unsafe memory mapping).
- Even with rustls and compression disabled, **SQLite remains**.

**Verdict:**
- **Do not embed Arti in project crates** while SQLite is mandatory. Re-evaluate when `tor-dirmgr` has a pure-Rust store.
- Using **Arti out of process** (`arti proxy` on a SOCKS port) already works with `--proxy`. Recommend it in the docs as the pure-Rust Tor option.
- Add stream isolation (R8-6), because Arti also isolates streams by SOCKS credentials [A].
- For running an onion service: Arti's onion-service support exists, and the node needs only the dedicated inbound port (§3.4).

**I2P:**
- **emissary** is a pure-Rust I2P router: SAMv3/I2CP, NTCP2/SSU2, hybrid ML-KEM handshakes. It embeds, but is marked **experimental, not for production** [A].
- A SAM client is a small text protocol, and one exists in `legacy/` [SR, docs/p2p.md §11].
- **Verdict:** add a SAMv3 client (S–M) that talks to an external router (i2pd or emissary). Do not embed. **P3.** I2P's unidirectional tunnels resist some of Tor's guard-side correlation, and Monero's docs note it "should provide better protection" against bandwidth shaping [A].

### 3.7 Transport obfuscation and anti-censorship: a proposed transport v2

**The current transport is fingerprintable** (R8-20): Ristretto encodings have fixed bits, the flow shape is fixed, and the responder answers any 32 bytes. No censor is known to block BlackSilk. A privacy chain should nevertheless assume a DPI adversary later.

**Proposal (one design that closes R8-20 and R8-21 and adds bridge mode):**
- **Pattern:** Noise-NK-like (the responder is optionally authenticated) or NN (anonymous), X25519, ChaCha20-Poly1305 or AES-GCM, with the key schedule bound to the `network_id` (keep this).
- **Uniform keys:** ephemeral X25519 keys encoded with **Elligator2 "randomized" representatives**:
  - `curve25519-elligator2` is the Tor Project's fork of curve25519-dalek used by the Rust obfs4 work. It is alpha 0.1.0-alpha.2. Its `Randomized` variant fixes RFC 9380's computational distinguisher [A].
  - The `elligator2` crate is differentially tested against it [A].
  - Both are pure Rust. Their maturity is **alpha**, so this needs internal review and known-answer tests.
  - Ristretto has no deployed uniform encoding. Switching the transport DH to X25519 is simplest, because the transport keys never touch consensus.
- **Shape:** random-length pre-handshake padding with a garbage terminator (the BIP324 pattern), and decoy frames.
- **Probe resistance / bridge mode:**
  - A listener *may* publish a static key with its address (for example `ip:port#key`, in a future addrv2 with timestamps).
  - Initiators that know the key include a MAC under DH(e, S) in their first flight. Without it the responder stays **silent**, as obfs4 does.
  - Unpublished "bridge" listeners serve only holders of the key.
  - The same static key gives the **optional authentication** R8-21 asks for (MITM detection on `--peer` links).
  - Nodes without a static key still work as today (NN), so unreachable nodes stay anonymous.
- **Privacy cost:** a static key identifies a listener across IP changes. Make it opt-in and rotatable. Never use one on the initiator side.
- **Pure Rust:** `snow` (Noise) is pure Rust but adds a dependency. Hand-rolling on the existing `blake2`/`aes-gcm` primitives plus X25519 from `curve25519-dalek` is small. **Prefer hand-rolled with a Noise-compatible transcript and test vectors.**
- **Pluggable transports:** Tor bridges with lyrebird (Go) or WebTunnel run out of process. BlackSilk inherits them for free through `--proxy` into a Tor with bridges. **No PT code in project crates.**
- **Consensus:** none. **Identity:** none. It is a P2P protocol upgrade and needs R8-14 (feature negotiation) first.
- **Difficulty:** L. **Priority:** P3. It becomes P2 if deployment in censoring jurisdictions is a stated goal.

### 3.8 Private mempools, MEV and miner censorship

**Threat reality for BlackSilk** [SR plus reasoning]:
- Amounts are confidential, the PX fee is a consensus constant (P-7), and there is no public AMM or DeFi state. **Extractable value is near zero.**
- The one concrete ordering attack, the front-running grief that copies a pooled output key (C4, known), is a consensus-rule matter. It has a direct fix and needs no mempool encryption.
- **Censorship levers** a miner or relayer actually has:
  1. the **contract and program id** of PX calls (P-8, inherent today);
  2. the **transaction kind and size**;
  3. **v1 ring members**, which allow *taint censorship*: refuse transactions whose ring includes flagged outputs;
  4. PX nullifiers, only for someone who knows the record (R3-7).

**Ideas evaluated:**

| Idea | Fit with PoW | Verdict |
|---|---|---|
| Threshold-encrypted mempool (Shutter/Ferveo-style) | Needs a keyper committee and an honest-threshold assumption, which is foreign to permissionless PoW. Adds liveness dependencies | **Rejected** |
| Time-lock encryption (tlock/drand, VDF puzzles) | Needs an external beacon or sequential work. Blocks would include undecryptable payloads, so validation happens after inclusion, which opens free DoS and fee problems | **Rejected** |
| Commit-reveal inclusion | Consensus change, two-phase latency, and invalid reveals must be paid for. Complex for little gain | **Rejected** |
| Fair ordering (Aequitas/Themis) | Needs BFT committees | **Rejected** (not applicable) |
| **Uniformity:** one PX shape, dummy function slots, and program hiding by recursion | Removes levers 1–2 at the root | **P3** (aggregation study; consensus when adopted) |
| **Shielded coinbase / PX-only direction** | Removes lever 3 over time | R3 recommendation; owner decision |
| **Decentralized template choice:** solo mining over your own node (the current design: the miner takes `/template` from its node, `rpc/src/lib.rs:264`), P2Pool-style share chains (Monero P2Pool for RandomX), or a Stratum-V2-style protocol where miners declare their own jobs, over an encrypted Noise channel | Pools emerge on any RandomX chain. When they do, template control should stay with the miners | **P3.** Document now that solo mining keeps censorship power with the miner. Evaluate a P2Pool port after launch |
| **Miner↔node transport:** `/template` over plaintext HTTP | Exposes miner IP and payout if remote | Recommend loopback-only (it already defaults to loopback, `config.rs:38`), otherwise SOCKS. P2 docs |

### 3.9 Light-wallet and RPC privacy (decentralized RPC)

**Current state [SR]:**
- The wallet downloads **whole blocks** (`/blocks`, up to 100 per request), the full PX commitment list and the full contract list. It trial-decrypts locally. This is good: the node learns only the sync height.
- **But** for v1 spends it calls `POST /outputs` with a shuffled set: a pool of about 4 × need, plus stored ring members, plus **the real input** (`wallet/src/wallet.rs:1079-1084`).
- The node, or anyone on the plaintext HTTP path, later sees the transaction's ring. The ring is a subset of the query, so the node **links the requester's IP to the transaction**. It also narrows the real input to the ring ∩ query, which is at most the ring itself. This is R3-9, known; the new point concerns which fix works.

**Why bucketing is not enough [M]:**
- Suppose the wallet fetched fixed 256-output pages instead of exact indices.
- The node would still check "is this transaction's ring contained in the pages this IP fetched?"
- For an unrelated transaction, the probability that 16 ring members all fall in the same k pages is about (k·256/N)^16, which is negligible.
- The link survives. Only fetching *everything* or PIR breaks it.

**Options:**

| Idea | Benefit | Pure Rust | Cost | Consensus | Verdict |
|---|---|---|---|---|---|
| **Local output index.** While scanning full blocks (which the wallet already downloads), store `(index, one_time_key, commitment, height, coinbase)`, about 73 B per output (the `OutputEntry` fields, `rpc/src/lib.rs:119-125`); drop `/outputs` | Removes the ring-linking channel completely, for self-hosted *and* remote nodes | Trivial | About 73 MB per million outputs; must stay consistent across reorgs (undo by height) | None | **P1** (with A7b's wallet work) |
| **Compact scan blocks** (a new RPC): per block, the header, and per transaction the outputs (key, commitment, encrypted amount and ciphertexts), key images, nullifiers and the kind; **no BP+, CLSAG or PX proofs**. Served identically to every wallet | Scanning bandwidth: PX blocks shrink from about 8 MiB to KBs; v1 transfers by roughly 60–80 % (proofs and signatures dominate) [estimate, not measured] | Trivial | Server CPU to strip, or cache | None | **P2**. The wallet trusts the node for validity anyway (W-F6). Pair with a header PoW check |
| **Wallet over SOCKS/Tor** | Hides the wallet IP from a remote node | Existing `socks5.rs` | — | None | Known (A7b), P1 |
| **PIR** (SimplePIR/YPIR: single-server, lattice-based) for fetching outputs or records without full download | Lets truly light wallets fetch ring members privately | `simplepir` crate (Rust); YPIR's reference implementation is Rust with SIMD intrinsics (unsafe) | Server cost linear in database size per query; offline hint download | None | **P3**; only if a no-full-download light client is wanted |
| **OMR** (Liu and Tromer, CRYPTO 2022; PerfOMR, USENIX Security 2024): the server finds your messages obliviously under FHE | Delegated detection without leaking to the server | Heavy FHE; no mature pure-Rust stack [U] | Very high server CPU | New per-output clue fields (**CONSENSUS**) | **P3 research** |
| **FMD** (Beck et al., CCS 2021; Penumbra) | Tunable false-positive detection | Pure Rust possible | New output fields | **CONSENSUS** | **Rejected**: the anonymity is weak and leaks under repeated queries and relationship analysis (Seres et al., "fuzzy privacy guarantees"), and it adds consensus surface |
| **Tachyon-style oblivious sync** (Zcash research, key-hierarchy redesign) | Removes scanning entirely | — | Protocol redesign | CONSENSUS | Watch only |

---

## 4. Rejected ideas (summary)

| Idea | Reason |
|---|---|
| Own mixnet | A small operator set and small traffic volume give no anonymity; XL effort |
| Embedding `nym-sdk` | Huge unreviewed dependency tree and token-credential coupling; the SOCKS boundary gives the same benefit |
| Embedding Arti | Mandatory C SQLite; C compression by default; pre-1.0 API |
| Adaptive diffusion | Needs knowledge of the global graph; undeployed; fragile |
| Switching D++ to Clover | No demonstrated gain over D++ as implemented; migration cost |
| DHT discovery | Eclipse-prone; heavy dependencies |
| Threshold or time-lock encrypted mempool, commit-reveal, fair ordering | Committees, beacons or validation-after-inclusion; negligible MEV |
| FMD | Consensus surface with weak guarantees |
| Erlay (BIP330) | Transaction volume is tiny; the only minisketch Rust crate is bindings to C++ (FFI); reconciliation also changes D++'s fluff analysis |
| Default constant-rate cover | GB/day per link at PX sizes (§3.5) |
| Height-based proxy or stem selection | Exactly the ProxyMark bias. Never add it |

---

## 5. Prioritized roadmap (all policy; none needs a new testnet identity)

| Priority | Item | Section | Difficulty |
|---|---|---|---|
| P0/P1 | R8 addrman parity (per-source limit, addr rate limit, onion grouping, diversity-in-round). Prerequisite for everything peer-drawn | R8-3/4/5 (known) | M |
| P1 | InvTx stempool oracle fix and test | §2.1 | S |
| P1 | `listen` per network class; refuse or warn on dual-homed onion configs | §2.2 | S |
| P1 | Network classes as state (stems, trickle, GetAddr cache, limits); dedicated onion inbound port | §3.4 | M |
| P1 | SOCKS stream isolation | R8-6 (known) | S |
| P1 | Wallet local output index; remove `/outputs` | §3.9 | S–M |
| P1 | Documentation: D++ anonymity sets are small and do not grow with N; PX origin is visible to the ISP even over Tor; the Arti-out-of-process recipe | §3.1, §3.5, §3.6 | S |
| P1 design / P2 build | Private broadcast of local transactions into the stem | §3.3 | M |
| P2 | Compact scan blocks; padding size buckets; asmap; labnet first-spy simulations | §3.9, §3.5, §3.4, §3.1 | M |
| P3 | Transport v2 (Elligator2 + optional static key + bridge mode); I2P SAM; Nym via SOCKS docs; Poisson PX cover mode; PoW onion stamps; PIR; P2Pool/SV2; Tor cadence shaping | §3.7, §3.6, §3.2, §3.5, §3.4, §3.9, §3.8, §2.3 | L |
| P3 (CONSENSUS when adopted) | PX size reduction and program hiding by recursion: the root fix for R8-18 and P-8 | §3.5, §3.8 | XL |

## 6. Never change (without strong new evidence)

- No plaintext magic or version on the wire; `network_id` bound into the session KDF.
- Local transactions always stem, and are never fluffed directly while a stem or anonymity path exists.
- Per-source fixed stem routes within an epoch (for relayed traffic).
- `GetTx` serves only announced transactions; one uniform `NotFound`.
- Stem and proxy selection independent of peer-claimed heights.
- SOCKS5 (plus, later, SAM) as the only boundary to anonymity networks: no FFI to C tor, and no embedded router with C dependencies.
- The wallet downloads data that is identical for every wallet (full or compact blocks, full commitment lists), and never sends the node addresses, keys, records or targeted indices.

## 7. Sources

**Monero and Tor attacks:**
- ProxyMark: Deanonymizing Monero Transactions in Tor Network — https://arxiv.org/abs/2607.07062 (HTML: https://arxiv.org/html/2607.07062)
- Are Unreachable Nodes Truly Safe? Fully Eclipsing Monero's P2P Network! (CCS'26) — https://arxiv.org/abs/2609.10260

**Dandelion++ and alternatives:**
- Sharma, Gosain, Diaz, On the Anonymity of Peer-To-Peer Network Anonymity Schemes Used by Cryptocurrencies (NDSS 2023) — https://arxiv.org/abs/2201.11860 ; https://www.ndss-symposium.org/wp-content/uploads/2023-241-paper.pdf
- Fanti et al., Dandelion++ — https://arxiv.org/abs/1805.11060
- Franzoni and Daza, Clover — https://arxiv.org/abs/2109.00376

**Monero implementation:**
- Monero anonymity networks (tx-proxy) — https://github.com/monero-project/monero/blob/master/docs/ANONYMITY_NETWORKS.md
- Monero parameters (`CRYPTONOTE_DANDELIONPP_*`, `CRYPTONOTE_NOISE_*`) — https://github.com/monero-project/monero/blob/master/src/cryptonote_config.h
- Monero noise and padding (`levin_notify.cpp`) — https://github.com/monero-project/monero/blob/master/src/cryptonote_protocol/levin_notify.cpp

**Bitcoin Core:**
- Private broadcast, PR #29415 — https://github.com/bitcoin/bitcoin/pull/29415 ; Core 31.0 notes — https://bitcoincore.org/en/releases/31.0/ ; "clarify claims, mark as experimental", PR #36309 — https://github.com/bitcoin/bitcoin/pull/36309 ; Optech #388 — https://bitcoinops.org/en/newsletters/2026/01/16/
- BIP324 (v2 encrypted transport, ElligatorSwift) — https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki
- BIP330 / Erlay — https://bitcoinops.org/en/topics/erlay/ ; minisketch-rs (C bindings) — https://github.com/eupn/minisketch-rs

**Tor, Arti and I2P:**
- Arti 2.5.0 release — https://blog.torproject.org/arti_2_5_0_released/ ; Arti 2.4.0 — https://forum.torproject.org/t/arti-2-4-0-released-relay-and-directory-authority-development-flowctl-cc-stable/21670
- arti-client 0.46 features — https://docs.rs/arti-client/latest/arti_client/ ; tor-dirmgr (rusqlite mandatory) — https://lib.rs/crates/tor-dirmgr ; tor-dirclient (xz/zstd default) — https://lib.rs/crates/tor-dirclient
- emissary (Rust I2P) — https://github.com/eepnet/emissary

**Elligator2:**
- curve25519-elligator2 `Randomized` — https://docs.rs/curve25519-elligator2/latest/curve25519_elligator2/elligator2/struct.Randomized.html
- elligator2 crate — https://docs.rs/elligator2/latest/elligator2/
- dalek issue #533 — https://github.com/dalek-cryptography/curve25519-dalek/issues/533

**Nym:**
- Nym in Zcash wallets — https://nym.com/blog/nym-mixnet-zcash-wallets
- nym-sdk — https://lib.rs/crates/nym-sdk

**Wallet scanning (OMR, FMD, Tachyon):**
- OMR (Liu and Tromer, CRYPTO 2022) — https://crypto.iacr.org/2022/papers/530630_1_En_26_Chapter_OnlinePDF.pdf ; PerfOMR — https://www.usenix.org/system/files/usenixsecurity24-liu-zeyu.pdf
- Penumbra FMD — https://protocol.penumbra.zone/main/crypto/fmd.html ; FMD privacy analysis — https://github.com/seresistvanandras/FMD-analysis
- Tachyon — https://seanbowe.com/blog/tachyon-scaling-zcash-oblivious-synchronization/

**PIR:**
- SimplePIR (Rust) — https://lib.rs/crates/simplepir ; YPIR — https://github.com/menonsamir/ypir

**Background, cited from general knowledge** (not re-fetched in this session; evidence class [A]):
- Heilman et al., Eclipse Attacks on Bitcoin's P2P Network (USENIX Security 2015);
- Biryukov, Khovratovich, Pustogarov (CCS 2014);
- Tran et al., Erebus (IEEE S&P 2020);
- Piotrowska et al., Loopix (USENIX Security 2017);
- Beck et al., FMD (CCS 2021);
- Stratum V2 job declaration;
- Monero P2Pool;
- Bitcoin Core `-asmap`, anchors and block-relay-only connections.
