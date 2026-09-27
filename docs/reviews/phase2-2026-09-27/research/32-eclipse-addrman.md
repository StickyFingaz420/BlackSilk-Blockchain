# 32 eclipse-addrman: research dossier (phase 2, phase 1)

**Agent:** 32 eclipse-addrman. This is internal engineering research, not an audit.
**Date:** 2026-09-27.
**Commit:** `9e422d8` (`rebuild/core`).
**Mode:** read-only; no builds or tests run. Every claim below is from reading source, docs and primary literature.

**Evidence tags:**
- **[SR]** source-read;
- **[T: name]** tested by the named test;
- **[M]** mathematically established, or computed under a stated model;
- **[A]** assumed;
- **[U]** unknown.

---

## 1. Scope and what I read

### 1.1 Code (full reads unless noted)

- `p2p/src/addrman.rs`: all 407 lines, including the `BanList` and 6 unit tests.
- `p2p/src/addr.rs`: all 254 lines, including 4 unit tests.
- `p2p/src/net.rs`, the parts in my scope:
  - `NetConfig` and `Peer`/`State` (`:95-340`);
  - `Network::start` (`:382-475`);
  - `save`, `send`, `penalize`, `ban_addr` (`:574-660`);
  - `accept_loop`, `inbound_count`, `same_ip_count`, `HandshakeSlot` (`:804-892`);
  - `connect_outbound` (`:894-924`);
  - `advertised_listen` (`:926-940`);
  - `run_connection`: handshake and registration (`:953-1125`);
  - `handle`, `on_get_addr`, `on_addr` (`:1276-1387`);
  - `sender_live` (`:1631`);
  - `maintenance_loop` (`:2594-2758`) and `maintain_outbound` (`:2761-2852`);
  - the unit tests (`:2855-2934`).
- `p2p/src/limits.rs` (scores, token buckets, ban constants); `p2p/src/message.rs` (the `Addr` codec, `MAX_ADDRS`, `Version`).
- `node/src/config.rs` (`builtin_seeds`, the listen/proxy flags, `resolve_seeds`).
- `p2p/Cargo.toml`, and `Cargo.lock` for `sha3`.
- `fuzz/fuzz_targets/*`: no addrman or `NetAddr` target exists.

### 1.2 Tests

- `p2p/tests/network.rs`, the relevant ones:
  - `peers_are_discovered_through_addr_exchange`;
  - `concurrent_handshakes_respect_the_inbound_limits`;
  - `a_ban_disconnects_every_connection_from_the_ip_and_is_saved`;
  - `connect_only_nodes_do_not_dial_discovered_addresses`;
  - `an_onion_address_is_not_advertised_over_clearnet`;
  - the helpers `connect_from` and `raw_peer_from`, which bind 127.x source addresses.
- I searched `p2p/` for tests of group diversity, seed fallback, onion grouping, the addr rate and GetAddr: **none exist** (§2.3).

### 1.3 Docs and reports

- `docs/p2p.md` §1 (threat model), §4, §9 (discovery and addrman), §10 (bans), §11 (Tor), §12 (limitations).
- `docs/reviews/full-review-2026-09-27.md`: §3.8, the register rows for R8-3/4/5/13/19, N-5/6/9 and R3-6, P1-1, P1-2, P2-22, and risk 15.
- `docs/reviews/autonomous-session-2026-09-27.md`: the addrman items are still listed as open (`:44`, `:262`).
- `docs/reviews/full-review-2026-09-27/R8-p2p.md`, in full.
- `SX2-systems-crossreview.md`, the R8 rows and P0-5.
- `I3-network-privacy.md` §2.2, §3.3, §3.4.
- `R15-testnet-decentralization.md` (seeds).
- `docs/reviews/assumptions.md` N1.
- `docs/reviews/completion-readiness-2026-09-26.md` (the N-items).
- The phase-2 dossiers of my neighbours: `30-p2p-transport.md` (P-10, T-2, W10) and `31-p2p-sync.md` (`best_known`, and the stale-tip hand-off to 32).

### 1.4 N-7 and N-8

Their original definitions are **not present** anywhere in the repository. `completion-readiness` lists "N-4 to N-9" as a block. The consolidated register maps them onto R8-3: "one source reaches all new buckets; no address rate limit; eclipse" (`full-review…md:949`). I treat them as: N-7 = the addr flood / rate limit, and N-8 = the per-source bucket limit / eclipse. See open question Q1.

---

## 2. Current state

### 2.1 What exists and is well designed

| Property | Evidence |
|---|---|
| **Secret-keyed bucketing.** `H32("p2p/addrman", secret ‖ table ‖ group(addr) ‖ group(source)) mod N`. The secret is random per node and persisted in `peers.json`, so an attacker cannot predict bucket placement. | [SR `addrman.rs:48-54`]; [T `different_secrets_give_different_buckets`] |
| **Only outbound successes enter *tried*.** `mark_good` is called only when `!inbound` (`net.rs:1068-1070`). Inbound peers' `listen` goes to *new*. This is the single most important post-Heilman fix: Erebus §II-C calls it "the most notable" deployed countermeasure. | [SR] |
| **Outbound group diversity, including within one selection round (R8-4 fix).** `groups.insert(a.group())` runs after each pick (`net.rs:2839-2843`). | [SR] only: **no test** (§4, F32-11) |
| **Seed fallback** when no outbound connection is registered (R8-13, partial). | [SR `net.rs:2789-2806`]; no test |
| **Handshake counting (N-4 fixed).** In-progress handshakes count against `max_inbound`/`max_per_ip`, and the limits are re-checked at registration. | [T `concurrent_handshakes_respect_the_inbound_limits`] |
| **Proxied peers are never IP-banned.** One bad Tor exit cannot get every Tor user's exit banned. This avoids the Biryukov–Pustogarov "ban Tor exits" attack. | [SR `net.rs:641-653`] |
| **Onion `listen` goes only over Tor**, and a clearnet `listen` only over clearnet (I3-2 fixed). | [T `an_onion_address_is_not_advertised_over_clearnet`] |
| **Routability filter** on received and served addresses (loopback, RFC 1918, link-local, CGNAT, ULA, documentation). There is one gap: F32-7. | [SR `addr.rs:98-130`]; [T `routability`] |
| **GetAddr** is answered once per connection with ≤ 1000 entries. Banned IPs are filtered out. | [SR `net.rs:1328-1351`] |
| **Atomic save** of `peers.json` and `bans.json`. `load` checks the table shape. | [T `persistence`, `a_ban_disconnects_every_connection_from_the_ip_and_is_saved`] |
| **`connect_only` mode** for fixed topologies. | [T `connect_only_nodes_do_not_dial_discovered_addresses`] |
| **Port diversity is contained by grouping.** The bucket depends only on groups, and outbound diversity is per group. The Monero CCS'26 "port-diversity" amplification (one IP, many ports) therefore lands in one bucket per (group, source-group) pair, not across the table. | [SR]+[M]; F32-9 notes the residual |

### 2.2 What is missing or wrong (summary; details in §3 and §4)

- **No per-source limit (R8-3).** One source group reaches all 256 *new* buckets.
- **Random eviction** on a full *new* bucket, with no deterministic slot. An attacker can therefore evict honest entries at will.
- **No addr rate limit.** In addition, an **unsolicited 1000-address batch is accepted from every inbound connection** (F32-1, new).
- **Onion group = the whole host (R8-5).** The onion v3 checksum and version are not validated.
- **No timestamps**, no `IsTerrible`, no test-before-evict, no feelers, no anchors, no block-relay-only connections.
- **No stale-tip / chain-sync outbound eviction.** A fully eclipsed node never self-recovers (F32-3, new).
- **No inbound eviction (N-9).** Per-IP limits and bans are on the exact IP (N-5), so one IPv6 /64 fills 64 inbound slots.
- **Tor inbound all arrives from 127.0.0.1 (N-6).** That means 2 onion inbound peers in total, and one ban blocks the hidden service for 24 h.
- **Privacy oracles (new):**
  - `GetAddr` is answered to *outbound* peers, which enables addr-cookie fingerprinting (F32-4);
  - relaying only *fresh* addresses is an addrman-membership oracle (F32-5).

### 2.3 What the tests actually prove

**`one_group_cannot_flood_the_table`** proves only that 10,000 addresses from **one addr /16** announced by **one source /16** fill ≤ 1 bucket. It does not test the attack that matters: many addr groups from one source group. The docstring ("Eclipse resistance") and docs/p2p.md §9 ("An attacker from a few network groups can therefore fill only a few buckets") are **false** as stated. [SR]+[M]

**Not tested at all:**
- the R8-4 within-round diversity;
- seed fallback;
- IPv6 grouping;
- GetAddr from outbound;
- the addr rate;
- eviction behaviour;
- the tried-collision policy;
- restart behaviour;
- any eclipse scenario.

**Test environment.** All integration tests run with `allow_private = true` except the one handshake test. That mode **skips the group rule and the per-IP rule entirely** (`net.rs:824`, `:2831`), so the public-network policy paths have almost no integration coverage.

---

## 3. Problems in scope

For each problem, the notes that follow list, where relevant:
- what the problem is, and why it exists;
- consequences;
- class;
- prior art;
- the fix and its trade-offs;
- tests;
- invariants.

### 3.1 R8-3 / N-7 / N-8: new-table flooding (per-source limit, eviction discipline, rate limit)

**Why it exists.** The bucket function has one stage: `H(secret, table, group(addr), group(src))`. For a fixed source group, varying `group(addr)` makes the index uniform over all 256 buckets. Bitcoin Core uses two stages:

```
hash1 = H(nKey, group(addr), group(src))
bucket = H(nKey, group(src), hash1 % 64) % 1024
```

This confines one source group to **64 of 1024** buckets (`ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP{8→64}`, Bitcoin `addrman.cpp` v23). Separately, BlackSilk's `add` **appends or random-evicts** (`addrman.rs:96-105`). Bitcoin's `AddSingle`:
- computes a **deterministic slot** (`GetBucketPosition`, Heilman CM1);
- overwrites an occupied slot only if the occupant `IsTerrible()`.

So in Bitcoin, honest entries already in place **cannot be pushed out by flooding**. In BlackSilk they can.

**Flood rates [SR+M]:**
- **Small `Addr` messages** (≤ 10 each) are limited only by the 50 msg/s message bucket (burst 500): about 500 addresses/s sustained and a 5,000 burst per connection.
- **Unsolicited 1000-address batch (F32-1).** One is allowed on *every* connection, including inbound, with no penalty and no requirement that we asked (`net.rs:1358-1366`). A reconnecting inbound attacker (`max_per_ip = 2`, reconnects not rate-limited) delivers 1000 addresses per handshake. At about 20 handshakes/s that is about 20,000 addresses/s.
- **Time to flush honest entries.** With random eviction, displacing essentially all honest entries from a 64-slot bucket takes on the order of 64·ln 64 ≈ 270 inserts per bucket (coupon collector). That is about 69k inserts, or **≈ 3–4 s** for the whole *new* table.

This contradicts Heilman countermeasure 8 ("Ban unsolicited ADDR messages … with > 10 addresses from incoming peers").

**Consequences:**
- **Security, eclipse.** A restarted node, or one with a small *tried* table, draws ~50 % of its outbound picks from *new* (`select` is 50/50, `addrman.rs:173`). The attacker owns that table.
- **Liveness, join denial.** Dead junk costs 10 s connect timeouts per slot.
- **Propagation.** Fresh small batches are relayed to 2 random peers (`net.rs:1381-1386`), so pollution spreads network-wide. This is the propagation path of the Monero CCS'26 attacks (Nyx: poison reachable nodes, which then poison unreachable ones; Moros: poison the seeds, which then poison every newborn node in about 8 s).

**Class:** not consensus. Privacy-critical: an eclipse gives transaction-origin deanonymization, because every stem is an outbound peer. Security, liveness.

**Fix (addrman v2, §5 W1–W3):**
- a two-stage per-source hash;
- a deterministic slot position;
- never evict a non-terrible occupant;
- a per-peer address token bucket (Bitcoin PR #22387: 0.1 addr/s, burst 1000, start at 1 token), with our own `GetAddr` answer exempt;
- **drop and penalize** any > 10-address `Addr` we did not solicit;
- a HashMap index instead of the O(20k) linear `position()` (`addrman.rs:56-65`).

**Trade-offs:**
- Deterministic slots make honest newcomers lose collisions against old non-terrible entries. That is intended, and `IsTerrible` plus feelers recycle dead ones.
- 0.1 addr/s slows honest gossip. At testnet scale (tens to hundreds of nodes) it is negligible: a node self-advertises about once per 24 h.

**What could go wrong:**
- If `IsTerrible` is too lax, the table fills with stale honest entries. That is a liveness risk, mitigated by feelers.
- Changing the table geometry invalidates `peers.json`. Handle it with a version field, and start fresh on mismatch.

**Invariants:**
- secret-keyed placement;
- only outbound success enters *tried*;
- bucket placement depends on (group(addr), group(src)), never on attacker-chosen ports;
- no attacker input can evict a non-terrible entry.

### 3.2 R8-5: onion grouping and validation

`group()` for an onion is the host itself (`addr.rs:88-92`). Onions are free to mint, so:
- the addr-group dimension of the bucket hash is unbounded;
- the outbound "one per group" rule is satisfied by 8 attacker onions.

`valid_onion_host` checks only the charset (`addr.rs:33-38`). It does not check the v3 structure:
- `base32(PUBKEY(32) ‖ CHECKSUM(2) ‖ VERSION(1))`;
- `CHECKSUM = SHA3-256(".onion checksum" ‖ PUBKEY ‖ VERSION)[:2]`;
- `VERSION = 0x03` (Tor rend-spec-v3, "Encoding onion addresses").

About 1 − 2^-16·(1/256) of random 56-char strings are invalid, yet they are stored, relayed and dialled.

**Prior art:**
- Bitcoin Core groups Tor and I2P by network plus the **first 4 bits** (`nBits = 4`), giving 16 groups (`netgroup.cpp`). CJDNS gets 12 bits after its constant byte.
- Marcus, Heilman and Goldberg (2018) show the same problem for Ethereum, where node IDs are free: two hosts sufficed to eclipse.
- ProxyMark (arXiv 2607.07062, via I3): about 5,000 onions saturate Monero's whitelist in about 2 h.

**Important nuance (skeptical of the R8 recommendation).** 4-bit grouping does **not** create Sybil cost for onions. Grinding an onion into any of 16 groups is free. It only bounds the *bucket spread* in combination with the per-source limit.

For a `--proxy-only` node, eclipse resistance must therefore come from:
- a *tried* table with test-before-evict;
- anchors;
- a mixed outbound policy: at least 2 outbound to **clearnet IPs via Tor**, whose /16 groups cost real resources, unless the operator sets onion-only;
- manual `--peer` entries.

**Fix (W2):**
- `group() = [10, host_pubkey[0] >> 4]`;
- validate the checksum and version at parse and decode (`sha3` 0.11 is already in `Cargo.lock` through `ml-kem`, so no new crate; needs 44's sign-off);
- encode onions in the new address format as the 32-byte pubkey, BIP155-style, so they are canonical by construction.

**Invariant:** onion names are never resolved locally.

### 3.3 No recovery once eclipsed: stale tip, chain-sync eviction, extra peers (F32-3, new, deepens R8-13)

**The mechanism gap.** Outbound peers are disconnected only for:
- misbehaviour;
- a pong timeout;
- 180 s idle;
- a full outbox.

There is no rotation. The seed fallback fires only when `registered_outbound == 0` (`net.rs:2792`). So an attacker who occupies all 8 outbound slots and simply answers pings, withholding blocks, holds the node **forever**. Even one attacker outbound peer suppresses the seed fallback.

**Prior art:**
- **Bitcoin Core:**
  - `STALE_CHECK_INTERVAL` 10 min: if the tip is older than 3× the target spacing, add one extra outbound connection;
  - `CHAIN_SYNC_TIMEOUT` 20 min: an outbound peer whose best known work stays below our tip after a `getheaders` challenge is disconnected (4 outbound are protected);
  - `EXTRA_PEER_CHECK_INTERVAL` 45 s;
  - **extra block-relay-only peers** about every 5 min, kept only if they deliver a new block (PR #19858, rationale: eclipse and partition).
- **Erebus** countermeasure C4: "protect peers providing fresher block data".
- **Monero** rotates outbound (`update_sync_search`, one peer about every 101 s). CCS'26 shows that rotation **into a poisoned gray list** accelerates eclipse. So rotation must draw from *tried* (or be tested) and must not evict good peers.

**Fix (W5):**
- stale-tip detection at 3 × 120 s = 6 min, checked every 10 min, adds one extra full outbound;
- chain-sync eviction of outbound peers that are behind, using 31's `Peer.best_known`;
- an extra block-relay-only probe every 5 min (Poisson), kept only if it supplies a new header with more work than ours;
- the seed fallback also on a stale tip.

**Class:** security and liveness. Consensus-adjacent, because an eclipse enables N-confirmation double spends against a victim, but no consensus change.

### 3.4 Restart eclipse: anchors and block-relay-only connections (R8-13)

Heilman's main attack exploits restarts. BlackSilk has no anchors, so after a restart all 8 outbound connections are fresh draws from a possibly poisoned table.

**Prior art:**
- Heilman CM5 (anchor connections);
- Bitcoin PR #15759 (2 block-relay-only outbound, v0.19);
- Bitcoin PR #17428 (`anchors.dat`: the block-relay-only peers saved at shutdown and re-dialled first at startup, v0.21);
- Monero `P2P_DEFAULT_ANCHOR_CONNECTIONS_COUNT 2`. CCS'26 notes that anchors do **not** help newborn nodes (Moros) or a node that is never restarted (Nyx), hence §3.3 and §3.1 as well.

**Privacy bonus.** Block-relay-only links carry no `InvTx` and no `Addr`, so TxProbe-style topology inference (Delgado-Segura et al., FC 2019) cannot see them. BlackSilk's `Version.relay_txs` already exists on the wire (`message.rs:62`) and is honoured for sending (`net.rs:791`), but the node always sends `true` (`net.rs:991`). docs/p2p.md §4 claims block-relay-only connections exist. **They do not.**

**Fix (W4):**
- 2 block-relay-only outbound connections (`relay_txs = false`; no `GetAddr` or `Addr` on them; never Dandelion stems);
- `anchors.json` written at shutdown and deleted on read (a crash does not re-anchor an attacker from an old file);
- anchors dialled first at startup;
- for proxy-only nodes, anchors must be Tor-reachable.

### 3.5 Inbound: eviction, per-/64 identity, per-group pressure, onion inbound (N-5, N-6, N-9)

**What goes wrong today:**
- **Exact-IP limits and bans.** `same_ip_count` (`net.rs:853-858`) and `BanList` (`addrman.rs:232-248`) key on the exact `IpAddr`.
- **No eviction.** When inbound is full, new sockets are silently dropped (`net.rs:822-826`).

**Consequences [M]:**
- **Inbound slot exhaustion.** One VPS with a routed IPv6 /64 opens 64 connections from 32 addresses and **fills every listening node's inbound slots**. At testnet scale (say 10–50 listeners × 64 slots) that is a few thousand connections from one machine.
- **Joiners reach only the attacker.** Every newcomer's outbound attempts then fail, except to attacker listeners. Combined with a poisoned addrman, this eclipses **all joiners**.
- **Bans do not stick.** Banning one /128 evicts nothing.
- **Tor inbound: two connections, one shared ban.** All Tor inbound arrives from 127.0.0.1 (N-6), and `max_per_ip = 2` applies because `allow_private` is off. So a hidden-service node accepts **2** onion inbound connections in total, and an attacker holding both makes the onion unreachable. A single misbehaving onion peer gets 127.0.0.1 banned for 24 h (`ban_addr` bans unless `proxied` or `allow_private`), which disables the hidden service.

**Prior art:**
- Bitcoin `SelectNodeToEvict` (`node/eviction.cpp`), which protects, in order:
  1. 4 peers by keyed netgroup;
  2. 8 by lowest minimum ping;
  3. 4 recent transaction relayers;
  4. 8 block-relay-only peers that relayed blocks;
  5. 4 recent block relayers;
  6. up to 25 % of the candidates from disadvantaged networks (onion, localhost, I2P, CJDNS);
  7. then half by uptime.
  It then evicts the youngest peer of the netgroup with the most connections.
- Heilman CM9 (diversify incoming connections).
- Monero `--anonymous-inbound` (a dedicated Tor or I2P inbound port, as I3 §3.4 recommends).

**Fix (W6):**
- A peer identity key: IPv4 /32; IPv6 **/64** (BIP-style `IpKey`); onion inbound = a per-connection key.
- `max_per_ip` and bans on that key.
- Bitcoin-style eviction when full.
- A dedicated `--onion-inbound 127.0.0.1:P` listener whose peers are tagged `NetClass::Onion`, never IP-banned (connection-only drops, as for proxied peers), capped as a class (e.g. 25 % of `max_inbound`), and evicted within the class.
- Loopback inbound on the *clearnet* port is no longer assumed to be Tor.

**Trade-off:** eviction lets an attacker churn honest inbound peers that are unprotected. Bitcoin's protection classes bound that.

### 3.6 Timestamps, horizon, `IsTerrible`, and the address wire format (R8-13, 30's P-10)

`NetAddr` has no timestamp, so:
- dead entries never age out;
- relay freshness cannot be judged;
- self-advertisement cannot be refreshed.

`Addr` entries are also not length-prefixed. An unknown kind is a 100-point ban (30's P-10/T-9).

**Prior art:**
- Bitcoin `IsTerrible`: never if tried in the last minute; a timestamp > 10 min in the future; not seen for `ADDRMAN_HORIZON` (30 days); never succeeded after `ADDRMAN_RETRIES` (3); ≥ `ADDRMAN_MAX_FAILURES` (10) failures within `ADDRMAN_MIN_FAIL` (7 days).
- Bitcoin `GetChance`: 0.01 for a try in the last 10 min, and 0.66^min(attempts, 8).
- BIP155 addrv2: network id plus a length-prefixed address, with Tor v3 as a 32-byte key.

**Fix (W1, W3):**
- **Local** timestamps: `first_heard`, `last_try`, `last_success`, `attempts`, `last_count_attempt`, used for `IsTerrible` and `GetChance`. These are never trusted from peers for security decisions.
- A **pre-launch** wire change, while it is still free (a testnet reset is authorized): `Addr` entries become `(u32 unix_time, u8 net_id, varint len, bytes, u16 port)`.
  - An unknown `net_id` is skipped, not banned.
  - A peer timestamp is clamped (future → now − 5 days, as Core does) and used **only** for relay freshness (relay if it is within 10 min) and as a weak horizon hint.
- Periodic self-advertisement of `public_address` (Poisson, mean 24 h), per network class.
- **Identity:** P2P protocol version only (`PROTOCOL_VERSION` 3). No chain identity or genesis impact.

### 3.7 Privacy: GetAddr fingerprinting and the relay membership oracle (F32-4, F32-5, new)

**F32-4, fingerprinting through GetAddr answers to outbound peers.** `on_get_addr` answers any peer (`net.rs:1328-1351`), including peers the victim itself dialled.

*Attack (Biryukov and Pustogarov, IEEE S&P 2015, "Bitcoin over Tor isn't a good idea"):*
1. The attacker plants unique fake "cookie" addresses into a non-listening or Tor node's addrman, via `Addr` whenever the victim connects to an attacker node.
2. Later, when the victim dials another attacker node (a different session, IP or Tor circuit), the attacker asks `GetAddr` and recognises the cookies. That links the sessions.

*Mitigation in Core:* Bitcoin ignores `getaddr` from non-inbound connections precisely for this. A node that only dials out then cannot be fingerprinted this way. BlackSilk's privacy audience (proxy-only, non-listening) is exactly the target.

*Residual after the fix:* dual-homed listening nodes also need the per-network 24 h GetAddr cache (Bitcoin PR #18991, `MAX_PCT_ADDR_TO_SEND = 23`). That is 33's scope, and I supply the addrman API for it.

**F32-5, the "relay only if fresh" addrman-membership oracle.** `on_addr` relays only the addresses that `addrman.add` reported as new (`net.rs:1370-1386`).
- *Probe:* a spy sends a 1-address `Addr` with X, and watches (from other connections) whether the victim relays X.
  - Relayed ⇒ X was not in the table.
  - Not relayed ⇒ it was.
- *Consequence:* this reveals which addresses the victim knows: a fingerprint and a topology hint.
- *Bitcoin's approach:* relay is **not** conditioned on the `Add` result. An address is relayed if its timestamp is < 10 min old, the message has ≤ 10 entries and the address is routable. Loops are controlled by a per-peer known-address filter (`m_addr_known`). Targets are chosen deterministically per (address, 24 h window) (`ROTATE_ADDR_RELAY_DEST_INTERVAL = 24h`). [SR of Core constants; the loop body is from my knowledge of `ProcessAddrs`, since the fetched source was truncated: tag [A] for the exact ordering.]

**Fix (W3):** requires timestamps (§3.6). Relay on freshness, not on novelty; keep a per-peer bounded known-address set; use deterministic targets per (address, day).

### 3.8 Seeds (R8-13, R15, P2-22)

- Seeds are dialled as **full, permanent outbound peers** (`net.rs:2792-2806`). They count as `tried` (`mark_good`) and never leave.
- A seed operator therefore holds long-lived outbound slots of every joiner, which is exactly the Moros (CCS'26) bootstrap leverage.
- Bitcoin uses **ADDR_FETCH** (one-shot) connections for seed nodes: connect, `getaddr`, disconnect.
- Seed hosts are resolved once at startup by local DNS unless `--proxy-only` (`config.rs:280-307`).

**Fix (W7):**
- seed connections are one-shot addr-fetch (no `mark_good`; disconnect after the `Addr` reply or 30 s; never counted as a stem or anchor);
- fall back to seeds when outbound < 2 for 60 s, or on a stale tip, not only at 0;
- ≥ 3 independent operators and ≥ 1 onion seed (R15; operational).

**Seeds are also poisoning amplifiers (Moros).** Addr rate limits on seed nodes and deterministic slots matter most there.

### 3.9 Outbound selection in a small network (design analysis)

**This is the most important framing point for BlackSilk, and the reports do not state it.** Bitcoin's addrman gives *proportional* protection: attacker share ≈ attacker entries / all entries. On a testnet with **N_h ≈ 20–100 honest reachable nodes**, the honest *new* population is tiny and the tables are mostly empty.

**Model [M]:**
- Even after W1, an attacker announcing from g source groups fills up to `min(256, 16g) × 64` *empty* slots, i.e. 1,024·g fake entries.
- The *new* table is sampled uniformly over filled entries. So P(a new pick is honest) ≈ N_h / (N_h + 1024·g) ≈ **5 %** for N_h = 50, g = 1.
- In a small network, new-table picks are therefore nearly worthless under attack, whatever the bucket geometry.
- Security must come from *tried* (real, reachable, tested) plus anchors plus rotation.

**Heilman's restart model** with 50/50 selection:
- Per-pick attacker-or-dead probability: q = 0.5·f + 0.5·0.95, where f is the attacker fraction of *tried*.
- For h = 40 live honest tried entries and a attacker nodes in *tried*:

| a (attacker nodes in *tried*) | f | q | P(all 8 outbound bad) = q^8 |
|---|---|---|---|
| 40 | 0.5 | 0.725 | ≈ 0.08 |
| 120 | 0.75 | 0.85 | ≈ 0.27 |

- Attackers enter *tried* only by being dialled, i.e. they need real reachable IPs in distinct groups. So the cost is (number of /16s) × (a tried presence), bounded per group by `TRIED_BUCKETS_PER_GROUP × 64` slots.
- **Port-diversity residual (F32-9):** one IP with many ports gets up to 64 *tried* slots in its group's bucket. Hence a one-entry-per-IP rule in *tried*, and Core's "avoid non-default ports for the first 50 tries" rule.

**Design choices:**
- **Tried bias:** full-relay outbound picks come from *tried* with probability 0.7 (Monero's `P2P_DEFAULT_WHITELIST_CONNECTIONS_PERCENT = 70`) once *tried* holds ≥ 2 × max_outbound entries in distinct groups; otherwise 0.5.
- **Feelers:** new → tried promotion only through feelers (Heilman CM4: one short connection about every 2 min), so junk never occupies a full slot.
- **Table size:** keep the current sizes (256×64 new, 64×64 tried), which are smaller than Core's. Erebus §VII-C C1 shows that *smaller* tables resist network-level adversaries better, and larger tables help them.
- **Outbound count:** 8 full-relay + 2 block-relay-only + 1 feeler, as in Core. Erebus C2 and Heilman CM7 favour more; Monero uses 12. With 9.45 MB PX blocks, more full-relay outbound costs bandwidth. The 2 block-relay-only connections are the cheap increment.
- **Tunable:** the 0.7 bias must be validated in the eclipse simulator (W8) before being fixed.

**Stated honestly (accepted limitation).** Against an attacker with real reachable nodes in about N_h distinct /16s (cheap on clouds) and a long attack window, **no addrman design gives strong eclipse resistance on a network of tens of nodes**. The practical defences are:
- anchors;
- manual `--peer` links to known operators;
- independent seeds;
- stale-tip rotation;
- operator monitoring.

The testnet threat model (docs/p2p.md §1, docs/reviews/assumptions.md N1) must say this with numbers.

### 3.10 AS-level adversaries: asmap and Erebus

**Erebus** (Tran et al., IEEE S&P 2020):
- A Tier-1 or large Tier-2 AS spoofs "shadow IPs" whose victim-bound paths cross it. That is millions of IPs in more than 100 /16 groups, at about 520 bit/s per victim, taking 5–6 weeks.
- /16 grouping gives no protection.
- The paper's countermeasures:
  - C1: smaller tables;
  - C2: more outbound connections;
  - **C3: AS-based grouping (asmap)**;
  - C4: protect fresher-block peers.

**Bitcoin Core `-asmap`** (since v0.20, PR #16702) groups by ASN. The data is generated by Kartograf, with collaborative launches in the `bitcoin-core/asmap-data` repository.

**BlackSilk:**
- the unauthenticated transport (30) makes an on-path AS an even easier man in the middle;
- asmap is a pure-Rust-feasible interpreter (a bit-packed decision trie, about 200 lines, safe code), but needs a data pipeline and trust in the map.

**Recommendation:**
- abstract grouping behind a `NetGroupManager` now (W2), so that asmap can be plugged in;
- implementation P3;
- recommend Tor or a multi-homed operator setup for miners and pools in the docs.

---

## 4. Findings

All the findings below are policy-only, with no consensus change and no chain identity impact.

| ID | Severity | Status | Location | Scenario | Confidence |
|---|---|---|---|---|---|
| **R8-3 / N-7 / N-8** (re-confirmed, open) | **High** (public testnet) | Not implemented | `addrman.rs:48-54, 83-107`; `net.rs:1353-1387` | One source group spreads over all 256 *new* buckets; random eviction displaces honest entries; no rate limit. With F32-1 the whole *new* table is flushed in seconds. | High [SR+M] |
| **F32-1** (new; sharper form of R8-3) | **High** | Not implemented | `net.rs:1358-1366` | Every connection, **including inbound and unsolicited**, may deliver one 1000-address batch, with no penalty. Reconnect loops give about 20k addresses/s from one IP. That violates Heilman CM8. | High [SR]; rate [A] |
| **R8-5** (re-confirmed, open) | **High** for Tor-only nodes; Medium overall | Not implemented | `addr.rs:33-38, 88-92` | 8 free onions satisfy "one per group". Invalid v3 onions (bad checksum or version) are stored, relayed and dialled. 4-bit grouping alone does *not* add Sybil cost (§3.2). | High |
| **F32-2** (N-5 + N-9 deepened) | **High** (public testnet); Low (explicit-peer trial) | Not implemented | `net.rs:804-858`; `addrman.rs:232-248` | One IPv6 /64 fills 64 inbound slots of every listening node, with no eviction. On a small testnet, all joiners can reach only attacker listeners; that is network-wide join denial and an eclipse of newcomers. Bans per /128 are useless. | High [SR+M] |
| **F32-3** (new) | **High** (public) | Not implemented | `net.rs:2761-2852` (no rotation); `:2792` (seed fallback only at 0 outbound) | Once all outbound slots are attacker peers that answer pings and withhold blocks, the node never recovers. One attacker outbound peer also suppresses the seed fallback. There is no stale-tip detection or chain-sync eviction. | High [SR] |
| **N-6** (re-confirmed; mechanism quantified) | **Medium-High** for onion listeners | Not implemented (documented) | `net.rs:641-653, 822-826, 853-858` | A hidden-service node accepts exactly 2 onion inbound connections (all from 127.0.0.1, `max_per_ip = 2`). One misbehaving onion peer bans 127.0.0.1 for 24 h and disables the onion service. | High [SR] |
| **F32-4** (new; related to R3-6) | **Medium** (privacy) | Not implemented | `net.rs:1328-1351` | GetAddr is answered to *outbound* peers, which enables addr-cookie fingerprinting of non-listening and Tor nodes across sessions (Biryukov and Pustogarov 2015). Bitcoin ignores getaddr from outbound connections for this reason. | High [SR]; literature |
| **F32-5** (new) | **Low-Medium** (privacy) | Not implemented | `net.rs:1370-1386` | Relaying only addresses new to addrman is a membership oracle: the spy learns which addresses the victim knows. | Medium-High [SR] (needs a relay target to be the spy; likely with several connections) |
| **R8-13** (partly fixed; remainder open) | Medium | Partially implemented | `net.rs:2789-2806`; `addrman.rs` (no timestamps) | No timestamps, horizon or `IsTerrible`; no feelers, anchors or block-relay-only connections. docs/p2p.md §4 claims block-relay-only connections exist; they do not. | High |
| **F32-6** (new) | Medium | Not implemented | `net.rs:2792-2806`; `config.rs:280-307` | Seeds become permanent outbound and *tried* peers rather than one-shot addr-fetch connections, which gives the seed operator long-lived slots in every joiner (the Moros bootstrap lever). | High [SR] |
| **F32-7** (new) | Low | Not implemented | `addr.rs:118-126`, `:80-86` | IPv4-mapped (`::ffff:127.0.0.1`, `::ffff:10.x`) and other special IPv6 ranges pass `is_routable`. So do 6to4 and NAT64 with embedded private v4, site-local `fec0::/10`, ORCHID and `100::/64`; on the IPv4 side, 198.18/15, 240/4 and 192.0.0/24 also pass. Peers can make every node relay these and dial local or LAN services with 32 random bytes; a dual-stack connect works on Linux, not on Windows' default V6ONLY. Mapped and v4 forms of one host also get different ban and per-IP keys. | High [SR] |
| **F32-8** (new) | Low | Not implemented | `net.rs:1071-1077` | An inbound peer's `Version.listen` is stored without checking that it matches the connection's IP. Any peer injects arbitrary third-party addresses, bypassing the (future) addr rate limit. | High [SR] |
| **F32-9** (new) | Low | Not implemented | `addrman.rs` (dedupe on IP:port); `net.rs:2825-2837` | Port diversity: one IP with many ports takes up to 64 *tried* slots in its group bucket, or 64 *new* slots per source group. Bounded by grouping, but it inflates attacker *tried* share in a small network (§3.9). | High [SR+M] |
| **F32-10** (new) | Low | Not implemented | `net.rs:275, 900` | `last_attempt` is never pruned, so it grows with every junk address dialled (about 70k entries a day under a junk flood). | High [SR] |
| **F32-11** (new) | Informational | — | `full-review…md:950` (R8-4 "CV", "s,t"); p2p tests | The R8-4 fix and the R8-13 seed fallback have **no regression test**, so "Complete and verified" is overclaimed; the correct class is CT. `one_group_cannot_flood_the_table`'s docstring and docs/p2p.md §9 claim eclipse resistance the code lacks. docs/p2p.md §9 says a *new* collision "evicts the older entry"; the code evicts a random one. | High |
| **F32-12** (new) | Informational | — | `net.rs:2792-2806` | Seeds are added to `to_connect` without being inserted into `groups`, so a seed and an addrman pick can share a group in one round. | High |
| **F32-13** | Informational (accepted limitation, to document) | Accepted limitation | docs/p2p.md §1; assumptions.md N1 | On a network of tens of nodes, no addrman gives strong eclipse resistance against an attacker with about N_h real /16s; the practical defences are anchors, manual peers, independent seeds and rotation (§3.9). AS-level adversaries (Erebus) are out of reach without asmap. | Medium [M under the stated model] |

---

## 5. Implementation plan for phase 2

All items are **policy / P2P only**: no consensus change and no chain identity change. W3 bumps `PROTOCOL_VERSION`; it must land before the v3 testnet launch, where it costs nothing.

**Sequencing:** W0 → W1 → W2 → W3 in order. W4–W7 are parallelizable after W1 and W2. W8 starts with W1 (the simulator drives the design constants).

### W0 (P0, S): immediate hardening, landable in hours

- **Changes:**
  - `on_addr`: drop and penalize (+10) any > 10-address `Addr` that we did not solicit. Solicited = we sent `GetAddr` on this *outbound* connection and it was not yet answered.
  - `on_get_addr`: ignore it from outbound peers, with no penalty (F32-4).
  - `is_routable`: canonicalize IPv4-mapped addresses, and add the missing IANA special ranges (F32-7).
  - Insert seed groups into `groups` (F32-12).
  - Prune `last_attempt` by age (F32-10).
  - Accept an inbound `listen` only if it is an onion (over Tor) or its IP equals the connection IP (F32-8).
- **Files:** `p2p/src/net.rs` (`on_addr`, `on_get_addr`, `maintain_outbound`, the registration block); `p2p/src/addr.rs` (`is_routable`, a new `canonical()`).
- **Tests:**
  - `unsolicited_large_addr_batch_is_penalized`;
  - `getaddr_from_outbound_is_ignored`;
  - `mapped_and_special_ranges_are_not_routable` (a table of about 25 vectors);
  - `inbound_listen_must_match_source_ip`.
- **Docs:** docs/p2p.md §9.

### W1 (P0 before a public testnet, M): addrman v2 core (R8-3, N-7/N-8, F32-9)

- **Changes in `p2p/src/addrman.rs`:**
  - **New bucket:** two stages. `h1 = H(secret, 0, group(addr), group(src))`; `bucket = H(secret, 2, group(src), h1 mod NEW_BUCKETS_PER_SOURCE_GROUP) mod 256`, with `NEW_BUCKETS_PER_SOURCE_GROUP = 16` (Core's 64/1024 ratio).
  - **Tried bucket:** `h1 = H(secret, 1, addr_key)`; `bucket = H(secret, 3, group(addr), h1 mod 2) mod 64` (Core's 8/256 ratio → 2).
  - **Position:** `pos = H(secret, 4 + table, bucket, addr_key) mod 64`.
  - **Domain tags:** keep the single tag `P2P_ADDRMAN` with the first-byte discriminators 0–5, so no `crypto/src/hash.rs` change is needed (no dependency on 19).
  - **Entry fields:** `first_heard`, `last_try`, `last_count_attempt`, `last_success`, `attempts`, `peer_time` (u32; W3).
  - **`IsTerrible`** as in Core (30 days, 3 retries, 10 failures / 7 days, 1-minute grace).
  - **`GetChance`** (0.01 within 10 min; 0.66^min(attempts, 8)).
  - **Insert:** never evict a non-terrible occupant.
  - **Tried collisions:** `tried_collisions` (≤ 10) plus `resolve_collisions` (test-before-evict; replacement after 4 h; a 40-minute window).
  - **One *tried* entry per IP** (F32-9).
  - **Index:** `HashMap<NetAddr, (Table, bucket, pos)>`.
  - **Persistence:** a `peers.json` version field; a mismatch means a fresh table.
  - **API** for W3/W5/33: `select(new_only, net_filter)`, `select_tried_collision()`, `good()`, `attempt(count_failure)`, `connected()`, and a `get_addr(max_pct, max, net_filter)` that excludes terrible entries.
- **Files:** `p2p/src/addrman.rs` (owner 32). `BanList` moves to `p2p/src/banlist.rs` (owner 32), which keeps `addrman.rs` focused.
- **Tests:**
  - unit tests;
  - **property** (proptest or the existing seeded-RNG style), each checked over random operation sequences:
    - the index is consistent with the tables;
    - `len` equals the sum of the buckets;
    - no duplicates;
    - a non-terrible entry is never evicted by `add`;
    - one source group occupies ≤ 16 *new* buckets;
    - *tried* holds ≤ 1 entry per IP;
    - save/load round-trips;
  - **regression** `many_addr_groups_from_one_source_fill_at_most_16_buckets` (replacing the misleading test);
  - a fuzz target `fuzz/fuzz_targets/addrman_ops.rs` (coordinate with 41).
- **Bench:** `add` of a 1000-address batch, and `select` × 10k, before and after (the linear scan is removed).
- **Docs:** docs/p2p.md §9 rewritten, with exact constants.
- **Difficulty:** M.

### W2 (P0 for Tor users, S): grouping, onion validation, `NetGroupManager` (R8-5)

- **Changes in `p2p/src/addr.rs`:**
  - `NetGroup` abstraction: IPv4 /16; IPv6 /32 (HE.net 2001:470::/32 at /36); 6to4, Teredo and NAT64 grouped by the embedded IPv4 /16; onion `[10, key[0] >> 4]`; local and unroutable in their own groups; an asmap hook (unimplemented).
  - `valid_onion_host` decodes base32 and checks the version (0x03) and the SHA3-256 checksum.
- **Dependency:** `sha3 = "=0.11.0"` added to `p2p/Cargo.toml`. It is already locked through `ml-kem`; 44 must sign off.
- **Files:** `p2p/src/addr.rs`, `p2p/Cargo.toml` (owner 32).
- **Tests:**
  - a Tor spec vector (a known-valid v3 address), plus bit-flipped checksum and version vectors;
  - `onion_group_has_16_values`;
  - `6to4_groups_as_embedded_v4`;
  - `he_net_groups_at_36`.
- **Difficulty:** S.

### W3 (P0 — pre-launch wire change, M): address format v2, timestamps, rate limit, relay (N-7, F32-5, 30's P-10)

- **Wire format:**
  - `Addr` entries become `LE32 time ‖ u8 net ‖ varint len ‖ bytes ‖ LE16 port`.
  - Nets: 1 = IPv4 (4 bytes), 2 = IPv6 (16), 4 = TorV3 (32-byte key); 5 and 6 are reserved for I2P and CJDNS.
  - An unknown net is skipped, not banned.
  - `PROTOCOL_VERSION` 3. Agree with 30 whether to re-type the message or replace type 5 outright before launch; the latter is simpler because no deployed nodes exist.
- **Rate limit:** a per-peer `addr_tokens` bucket (0.1/s, cap 1000, start 1; +1000 when we send `GetAddr`), with drops counted and not penalized.
- **Relay:**
  - relay if the peer timestamp is ≤ 10 min old, the message has ≤ 10 entries and the address is routable, **independent of `add`'s result**;
  - targets: 2 peers chosen by a keyed hash of (address, day), from the full-relay peers only;
  - a per-peer bounded known-address set.
- **Self-advertisement:** Poisson with a 24 h mean, per network class (reuses `advertised_listen`).
- **Files:**
  - `p2p/src/message.rs`, the `Addr` arm and `PROTOCOL_VERSION` (**shared with 30**; request a narrow window);
  - `p2p/src/addr.rs` (the encoding);
  - `p2p/src/net.rs` (`on_addr`, relay, the per-peer token).
- **Tests:**
  - codec round-trip and fuzz (41);
  - `addr_rate_limit_drops_excess`;
  - `getaddr_answer_is_exempt_once`;
  - `relay_does_not_reveal_membership`: the same relay behaviour for a known and an unknown address;
  - `unknown_net_kind_is_skipped_not_banned`.
- **Docs:** docs/p2p.md §5 and §9; the protocol history in §4.1.
- **Difficulty:** M.

### W4 (P1, M): block-relay-only connections and anchors

- **Changes:**
  - `ConnType {FullRelay, BlockRelayOnly, Feeler, AddrFetch, Manual, Inbound}` on `Peer`.
  - 2 block-relay-only outbound connections: send `relay_txs = false`; no `GetAddr` or `Addr`; ignore `InvTx`/`Tx`/`StemTx` from them (+10); exclude them from Dandelion stems.
  - `anchors.json`, written at shutdown with the current block-relay-only peers and deleted after reading; dialled first.
- **Files:**
  - `p2p/src/connman.rs` (**new**, owner 32): pure policy functions `select_outbound`, `select_feeler`, `select_evict_inbound` and `should_evict_outbound`;
  - `p2p/src/net.rs`: the `maintain_outbound` and `run_connection` wiring; the Dandelion stem filter (**touches 33's filter; one line**);
  - `node/src/lib.rs`: the shutdown save.
- **Tests:**
  - `anchors_are_redialed_first_after_restart`;
  - `block_relay_only_peers_get_no_addr_or_tx`;
  - `anchors_file_is_deleted_after_load`.
- **Difficulty:** M.

### W5 (P1, M): feelers, test-before-evict, stale tip, chain-sync eviction, extra block-relay-only probe (F32-3)

- **Feelers:** one feeler about every 2 min (Poisson). It picks from *new*, in a group distinct from the current outbound, or a tried-collision candidate. It disconnects after `Verack`, then calls `good()` or `attempt()`.
- **Stale tip:** checked every 10 min; stale if there is no new tip for 3 × target spacing (6 min on the testnet). A stale tip triggers one extra full outbound connection and the seed fallback.
- **Chain-sync eviction:** an outbound full-relay peer whose `best_known` work (from 31) stays below our tip after a 20-minute challenge (`GetHeaders`, then a 2-minute response window) is disconnected. 4 outbound peers are protected.
- **Extra block-relay-only probe:** every 5 min; kept only if it delivered a new most-work header, in which case the youngest block-relay-only peer is evicted.
- **Files:** `p2p/src/connman.rs`, `p2p/src/net.rs` (maintenance). This **depends on 31's `Peer.best_known`**.
- **Tests (labnet or in-process):**
  - `feeler_promotes_live_new_address_to_tried`;
  - `test_before_evict_keeps_live_tried_entry`;
  - `stale_tip_opens_extra_outbound`;
  - `withholding_outbound_peers_are_rotated_out`;
  - `eclipsed_node_recovers_via_block_relay_probe`.
- **Difficulty:** M.

### W6 (P0 before a public testnet for the /64 key and eviction; P1 for onion inbound; M): inbound (N-5, N-6, N-9, F32-2)

- **Changes:**
  - `PeerKey`: IPv4 /32, IPv6 /64, onion per connection. Use it in `same_ip_count`, `handshaking_ip` and `BanList`.
  - `select_evict_inbound`: Core's protection order (§3.5). Keyed netgroup protection uses the addrman secret-keyed group hash.
  - `--onion-inbound <addr>`: a second listener; `NetClass::Onion` peers, never IP-banned, class cap 25 % of `max_inbound`; `advertised_listen` uses the class, not the loopback heuristic.
- **Files:**
  - `p2p/src/net.rs` (`accept_loop`, `ban_addr`, registration; **30 also edits `ban_addr` and `accept_loop` (T-2, W1/W2)**, so sequence with 30);
  - `p2p/src/connman.rs`;
  - `p2p/src/banlist.rs`;
  - `node/src/config.rs` (the flag; shared with 33 and 36).
- **Tests:**
  - `ipv6_slash64_counts_as_one_ip`: a pure unit test of `PeerKey` (IPv6 loopback is a single address, so it cannot be an integration test). Eviction is covered by `connman` unit tests and by integration runs from 127.x IPv4 sources, as `connect_from` already does;
  - `full_inbound_evicts_from_largest_netgroup`;
  - `protected_peers_survive_eviction`;
  - `onion_inbound_is_never_ip_banned`;
  - `onion_inbound_class_cap`.
- **Docs:** docs/p2p.md §9–§11; `deploy/` torrc example.
- **Difficulty:** M.

### W7 (P1, S): seeds as addr-fetch (F32-6, R8-13)

- **Changes:** `ConnType::AddrFetch` for seeds: send `GetAddr`, disconnect on reply or after 30 s, never `good()`. Fall back when outbound < 2 for 60 s, or on a stale tip. Warn at startup if fewer than 3 seeds are configured on a public network.
- **Files:** `p2p/src/net.rs`, `p2p/src/connman.rs`, `node/src/config.rs`.
- **Tests:**
  - `seed_is_disconnected_after_addr_reply`;
  - `seed_fallback_when_outbound_below_two`.
- **Difficulty:** S.

### W8 (P0 in parallel with W1, M): eclipse simulator plus adversarial tests (roster "Tests: eclipse simulations")

- **Simulator:** `p2p/tests/eclipse_sim.rs` (new, owner 32). It is deterministic (ChaCha20), in-process and network-free, driving `AddrMan` plus `connman::select_outbound` / feelers / anchors.
- **Model:**
  - N_h honest nodes with a churn probability p;
  - an attacker with g source groups, R real reachable IPs in distinct groups, and a flood rate r;
  - events: flood, restart, feeler ticks, stale-tip rotation.
- **Measured:** P(all full-relay outbound are attacker), P(at least one honest outbound), and the time to recover after flood stops.
- **Scenarios:**
  1. Heilman botnet and infrastructure;
  2. Monero Nyx-style network poisoning (a reachable intermediary relays poison);
  3. Moros-style seed poisoning of a newborn;
  4. an onion-only node;
  5. port diversity.
- **Assertions (targets to be fixed after the first runs):**
  - at N_h = 50, g = 4, with R = 0: P(eclipse) < 1e-3, and newborn P(eclipse) < 1 %;
  - with R = N_h: report the numbers and document them (no assertion).
- **Also:**
  - run the same simulator on the *current* addrman to record the baseline;
  - labnet adversarial scenarios (`tools/labnet`, coordinate with 50): a flooding raw peer; a /64-style inbound squat using 127.0.0.0/8 sources; a withholding outbound peer.
- **Bench:** simulator runtime ≤ 60 s in CI (the budget is set with 43).
- **Difficulty:** M.

### W9 (P3, L): asmap

A pure-Rust asmap interpreter (safe code), an optional `--asmap <file>`, and `NetGroupManager` selection by ASN. Defer until mainnet planning. Document the Erebus threat now.

### W10 (P0, S, docs): documentation corrections

- docs/p2p.md §1: the eclipse row states the limitation (F32-13).
- docs/p2p.md §4: remove the block-relay-only claim until W4 lands.
- docs/p2p.md §9: the collision wording and the grouping.
- Register: R8-4 and R8-13 evidence classes → CT until tests exist (F32-11).
- docs/reviews/assumptions.md N1: add the quantified small-network bound.
- **Owner:** 32 for the p2p.md sections; 47 for the register and assumptions.

---

## 6. Dependencies and conflicts

**30 p2p-transport:**
- `message.rs` (W3's `Addr` format and `PROTOCOL_VERSION`); 30's P-10 wants the length-prefixed `NetAddr` that W3 delivers.
- 30's W10 static keys in addr records can reuse W3's net-id scheme.
- `ban_addr` / `accept_loop` are edited by both (30's T-2 transport-error bans; my W6 `PeerKey`). I propose that 32 owns `accept_loop`, `ban_addr` and `BanList`, and that 30 lands its read-loop error-arm change first.

**31 p2p-sync:**
- W5 needs `Peer.best_known` and an "outbound peer behind" signal. 31 explicitly hands stale-tip / chain-sync eviction to 32 (31 §S6 item 6).
- `maintenance_loop` is shared; I own only the outbound and feeler sections.

**33 dandelion-network-privacy:**
- GetAddr per-network cache (R3-6) uses my `get_addr(net_filter)` API.
- W4 excludes block-relay-only peers from stems (a one-line filter in their code).
- `NetClass` (W6) is the shared per-network state type. Agree on one definition; I propose it lives in `connman.rs`.
- SOCKS stream isolation (R8-6) complements onion policy; theirs.

**34 chain-actor-concurrency:** no lock interaction. Addrman stays under the network state lock, and W1's index removes the O(20k) scan under that lock.

**19 hash-domain-separation:** none if the single `P2P_ADDRMAN` tag with internal discriminators is accepted. Otherwise, new tags.

**41 fuzzing:** the `addrman_ops` and addr-codec targets.

**43 CI:** the simulator's runtime budget.

**44 supply-chain:** `sha3` as a direct dependency of `p2p`.

**47 docs:** register corrections. **48 threat-model:** the eclipse attack tree. **50 red-team:** labnet eclipse scenarios.

**40 testnet-genesis / R15:** seed operators, and the `builtin_seeds` list is empty (operational).

---

## 7. Open questions for the coordinator

1. **N-7/N-8 definitions** are not in the repository. Is my mapping (addr flood / per-source limit, both within R8-3) correct, or is there an original source?
2. **Wire change timing.** May W3 replace `Addr` (type 5) outright before the v3 launch (no deployed nodes), or must it be a new type for hygiene? Either is fine for me; 30 must agree.
3. **Launch topology.** Is the public testnet expected to launch with open discovery (seeds plus addrman), or with operator `--peer` meshes first? This decides whether W1/W3/W6 are hard P0 blockers (open discovery) or P0-pub (the register's current rating).
4. **Tried bias (0.7) and feeler rate.** Acceptable to fix these by the W8 simulator results rather than a priori?
5. **Mixed outbound for proxy-only nodes** (≥ 2 clearnet-over-Tor outbound unless `--onion-only`): an owner privacy trade-off. Clearnet-over-Tor exposes the connection to exit relays, and R8-6 stream isolation is required first.
6. **asmap:** confirm P3, not before mainnet planning.
7. **Ownership.** Confirm 32's ownership of:
   - `addrman.rs`, `addr.rs`, and the new `banlist.rs`, `connman.rs` and `tests/eclipse_sim.rs`;
   - the `net.rs` regions `accept_loop`, `ban_addr`, `on_addr`, `on_get_addr`, `maintain_outbound`, `connect_outbound`, and the registration block of `run_connection`.

---

## 8. Sources

**Primary papers:**
- Ethan Heilman, Alison Kendler, Aviv Zohar, Sharon Goldberg. "Eclipse Attacks on Bitcoin's Peer-to-Peer Network." USENIX Security 2015. https://eprint.iacr.org/2015/263 (PDF read: §7 countermeasures 1–10, eq. (10), Table 2); https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/heilman
- Muoi Tran, Inho Choi, Gi Jun Moon, Anh V. Vu, Min Suk Kang. "A Stealthier Partitioning Attack against Bitcoin Peer-to-Peer Network" (Erebus). IEEE S&P 2020. https://ihchoi12.github.io/assets/tran2020stealthier.pdf (PDF read: §VII countermeasures C1–C4); https://ieeexplore.ieee.org/document/9152616/
- Ruisheng Shi et al. "Are Unreachable Nodes Truly Safe? Fully Eclipsing Monero's P2P Network!" ACM CCS 2026. https://arxiv.org/abs/2609.10260 ; https://arxiv.org/html/2609.10260 (Nyx and Moros mechanisms, resources, countermeasures read)
- Alex Biryukov, Ivan Pustogarov. "Bitcoin over Tor isn't a Good Idea." IEEE S&P 2015. https://arxiv.org/pdf/1410.6079 (address-cookie fingerprinting; Tor-exit banning)
- Alex Biryukov, Dmitry Khovratovich, Ivan Pustogarov. "Deanonymisation of Clients in Bitcoin P2P Network." ACM CCS 2014.
- Yuval Marcus, Ethan Heilman, Sharon Goldberg. "Low-Resource Eclipse Attacks on Ethereum's Peer-to-Peer Network." IACR ePrint 2018/236. https://eprint.iacr.org/2018/236 (free identities, the analogue of onions) [cited from knowledge; not re-fetched]
- Maria Apostolaki, Aviv Zohar, Laurent Vanbever. "Hijacking Bitcoin: Routing Attacks on Cryptocurrencies." IEEE S&P 2017. [context; not re-fetched]
- S. Delgado-Segura et al. "TxProbe: Discovering Bitcoin's Network Topology Using Orphan Transactions." FC 2019. [context]
- "Deanonymizing Monero Transactions in Tor Network" (ProxyMark). arXiv 2607.07062. https://arxiv.org/pdf/2607.07062 [via I3; abstract-level]
- "Security Analysis of Bitcoin's V2 Transport Protocol: Exploiting Design Implications for Sustained Eclipse and Downgrade Attacks." arXiv 2605.19715. https://arxiv.org/abs/2605.19715 [abstract only; pointer for 30]

**Bitcoin Core source and PRs:**
- `src/addrman_impl.h` (bucket counts: tried 256, new 1024, bucket size 64). https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/addrman_impl.h
- `src/addrman.cpp`: two-stage bucket hashes, `IsTerrible`, `GetChance`, 50/50 `Select_`, test-before-evict, multiplicity. https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/addrman.cpp ; constants at v23.0: https://github.com/bitcoin/bitcoin/blob/v23.0/src/addrman.cpp
- `src/net_processing.cpp`: `MAX_ADDR_RATE_PER_SECOND 0.1`, `MAX_PCT_ADDR_TO_SEND 23`, `MAX_ADDR_TO_SEND 1000`, `STALE_CHECK_INTERVAL 10min`, `CHAIN_SYNC_TIMEOUT 20min`, `EXTRA_PEER_CHECK_INTERVAL 45s`, `ROTATE_ADDR_RELAY_DEST_INTERVAL 24h`. https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/net_processing.cpp ; https://github.com/bitcoin/bitcoin/blob/v27.0/src/net_processing.cpp
- `src/node/eviction.cpp` (`SelectNodeToEvict`). https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/node/eviction.cpp
- `src/netgroup.cpp` (`GetGroup`: Tor/I2P 4 bits, CJDNS 12, IPv6 /32, HE /36, asmap first). https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/netgroup.cpp
- PR #22387 (addr rate limiting). https://github.com/bitcoin/bitcoin/pull/22387
- PR #17428 (anchors). https://github.com/bitcoin/bitcoin/pull/17428
- PR #19858 (extra block-relay-only peers). https://github.com/bitcoin/bitcoin/pull/19858
- PR #15759 (block-relay-only), PR #8282 (feelers), PR #9037 (test-before-evict), PR #18991 (GetAddr cache), PR #16702 (asmap). [PR numbers from knowledge; behaviour confirmed through the source files above]
- The getaddr-from-outbound fingerprinting rationale, as discussed with Core references: https://github.com/btclib-org/btclib-node/issues/1177
- Asmap data and Kartograf: https://github.com/bitcoin-core/asmap-data/issues/75 ; https://opensats.org/projects/asmap ; https://gist.github.com/fjahr/bf0ff0917e03a4e49fac0617b2b35747

**Monero:**
- `src/cryptonote_config.h` (white 1000, gray 5000, 12 connections, whitelist 70 %, 2 anchors, 250 peers per handshake, IP block 24 h). https://raw.githubusercontent.com/monero-project/monero/master/src/cryptonote_config.h

**Tor:**
- Tor rend-spec-v3, "Encoding onion addresses" (checksum, version 0x03). https://spec.torproject.org/rend-spec/encoding-onion-addresses.html

**BIP155** (addrv2): https://github.com/bitcoin/bips/blob/master/bip-0155.mediawiki [format from knowledge]
