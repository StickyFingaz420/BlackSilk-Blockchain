# R8: P2P networking and synchronization architecture review

**Reviewer:** R8 (internal review, not an audit).
**Date:** 2026-09-27.
**Tree:** `f677e55` (includes WIP `7826289`). Read-only. No builds run.

**Scope:**
- `p2p/src/*`: transport, message, addr, addrman, dandelion, limits, socks5, net;
- `p2p/tests/*`;
- node wiring (`node/src/{main,lib,config}.rs`);
- the `chain/src/manager.rs` and `consensus/src/chain.rs` entry points that the network calls.

**Evidence tags:**
- **[SR]** source-read;
- **[T: name]** tested by the named test;
- **[M]** mathematically established or estimated under a stated model;
- **[A]** assumed;
- **[U]** unknown.

**Line references:** `net.rs` = `p2p/src/net.rs`. Other files are named in full.

---

## 0. Executive summary

The P2P layer is a compact, readable, well-bounded v1. Its codec and transport discipline are better than Monero's levin. It has several privacy details many projects miss:
- GetTx serves only announced transactions;
- local transactions always stem;
- stem conflict keys include PX nullifiers;
- network-bound session keys;
- no user agent or clock.

At the architecture level, however, it is **not yet designed for a hostile public network**. Bitcoin Core has 10+ years of adversarial hardening; measured against that, five structural gaps dominate. Most known N-items are symptoms of them.

1. **One global `std::sync::Mutex<ChainManager>`.**
   - It is held for arbitrarily long CPU work:
     - RandomX PoW inside `submit_block` for an unknown header;
     - CLSAG, BP+ and PX verification in `check_tx` and `submit_tx`;
     - `sync_state` connecting up to 256 downloaded bodies in one call.
   - It is also taken directly on tokio async worker threads.
   - Result: one expensive operation freezes the whole network stack, and an attacker can trigger such operations cheaply.
   - Redesign: a chain actor with published read snapshots and off-lock verification (§3.1).
2. **The address manager and connection manager lack Bitcoin's anti-eclipse machinery.** Missing:
   - a per-source-group bucket limit;
   - an addr rate limit;
   - timestamps and a terrible-address policy;
   - feelers and test-before-evict;
   - anchors and block-relay-only connections;
   - inbound eviction and stale-tip recovery.
   - Two new bugs make it worse:
     - outbound group diversity is not enforced within one selection round;
     - every onion address is its own "group".
   - A single inbound peer can repopulate the whole *new* table in about 30 s.
   - A Tor-only node can be fully eclipsed with 8 free onion services (§2.3–2.6).
3. **Resource accounting counts messages, not bytes or CPU.**
   - The outbox holds 64 *messages*, which can be 64 blocks of 9.45 MB.
   - `GetBlocks` has no upload budget.
   - Frames pre-allocate up to MAX_FRAME before any data arrives.
   - Unsolicited blocks and headers buy RandomX hashes (0.45–0.75 s each) for the cost of a TCP connection.
   - IPv6 makes per-IP limits meaningless.
4. **Initial sync and propagation are CPU-bound, not network-bound.**
   - One year of chain costs 33–55 CPU-hours of light-mode header PoW (4–7 h wall on 8 cores).
   - Worst-case full blocks cost ~250 single-threaded hours per year of body verification, done under the chain lock.
   - Per-hop propagation of full blocks is ~5–6 s. That implies a stale rate in the ~10–18 % range at 120 s blocks (§5), which harms mining decentralization.
5. **Privacy against network-level observers is weaker than the Dandelion++ story suggests.**
   - An unpadded ~2.2 MB outbound frame with no matching inbound frame identifies the origin of a PX transaction to the node's ISP.
   - Per-peer (not shared) inbound trickle timers help spies with many connections.
   - GetAddr answers are not cached per network, so clearnet and onion identities can be linked.
   - SOCKS5 without stream isolation lets one Tor exit see or MITM every clearnet peer of a proxied node.

**Before the public testnet (P0/P1), I recommend:**
- the stem-conflict ordering fix;
- chain-lock hold-time bounds;
- dropping unsolicited blocks and headers before PoW;
- a byte-accounted send path;
- the addrman per-source limit and addr rate limit;
- the outbound-group-diversity fix;
- onion grouping;
- SOCKS stream isolation;
- the block-timeout penalty fix;
- unknown-message tolerance.

All are **policy-only** (no consensus change, no new testnet identity). Each is S–M effort.

---

## 1. Subsystem matrix (the brief's 13 questions)

Legend for column 1 (status):
- **CV** = Complete and verified;
- **CT** = Complete but requires further testing;
- **PI** = Partially implemented;
- **NI** = Not implemented.

| Subsystem | Status | Implemented / well designed | Incomplete / fragile / exploitable | Never change |
|---|---|---|---|---|
| Transport (`transport.rs`) | CT | Ephemeral Ristretto DH; directional AES-256-GCM keys; `network_id` bound into the KDF; length AEAD-protected and checked before the payload is read; identity and non-canonical keys rejected [T: `bad_keys_and_silence_are_rejected`, `different_networks_cannot_talk`, `ciphertext_hides_content_and_tampering_is_detected`] | Fingerprintable (2 fixed bits per key); the responder answers any 32 bytes (no probe resistance); no padding; no rekey; no optional authentication or session id; full MAX_FRAME allocation before data (§2.10) | No-plaintext-magic; `network_id` in the KDF; directional keys; strict AEAD failure → disconnect |
| Codec (`message.rs`) | CV (fuzzed) | Every count bounded before allocation; strict trailing-byte rejection; truncation tests [T: `strictness`, `limits_are_enforced_before_allocation`, `fuzz_message`] | Unknown type = protocol violation (score 100, ban); Version cannot be extended → upgrade partitions (§2.14) | Bounded-before-allocate; strict payloads *within* known types |
| Peer lifecycle (`net.rs:577-776`) | PI | Handshake with timeouts; self-connection nonce; bounded outbox with slow-peer kill; cleanup of requests | Pre-handshake unbounded (N-4, known); no inbound eviction (N-9); control messages queue behind blocks (§2.11); scores never decay | — |
| Scoring and bans (`limits.rs`, `net.rs:393-441`) | PI | Contextual failures and InvalidParent not penalized; departed-peer ban; per-peer and global PX buckets | Exact-IP bans (N-5); honest slow peers banned via block timeouts (§2.9); Tor inbound (N-6) | Not penalizing contextual or InvalidParent failures |
| Address manager (`addrman.rs`) | PI | Secret-keyed buckets; tried/new tables; atomic save | No per-source bucket limit (§2.3); no addr rate limit; no timestamps or terrible policy; onion group = host (§2.5); linear scans | Secret-keyed bucketing |
| Outbound selection (`net.rs:1703-1781`) | PI | One-per-group intent; backoff; manual peers | Diversity not enforced within a round (§2.4); no feelers, anchors or block-relay-only; seeds only when addrman is empty (§2.13) | — |
| Dandelion++ (`dandelion.rs`, `net.rs:1444-1546`) | CT | Per-source fixed routes per epoch; local always stems; stem validated before relay; conflict keys include nullifiers; embargo with exponential tail; "seen in fluff" stops the embargo [T: `transactions_travel_the_stem_then_fluff_everywhere`, `px_transactions_travel_the_stem...`] | Conflict check after the expensive `check_tx` (§2.7); origin fires the embargo first ~17 % (§2.17); no stem peers → fluff (known); stempool unbounded in bytes | Local-always-stem; per-source routes; GetTx-only-announced |
| Fluff relay | PI | Trickle with exponential delays; `announced_to` gate | Per-inbound-peer independent timers (§2.16); inv order = arrival order; one in-flight announcer with a 30 s timeout (inv-withholding) | — |
| Tor/SOCKS (`socks5.rs`, config) | PI | No local DNS in proxy-only mode; onion via the domain-name type [T: `onion_names_go_to_the_proxy`] | No stream isolation (§2.6); `--proxy` without `--proxy-only` still listens on clearnet (§2.19); inbound onion = 127.0.0.1 (N-6); no I2P; onion checksum not validated | No local DNS for onions |
| Header-first sync | PI | Cheap precheck before PoW; chunked PoW; one worker dedups work [T: `junk_header_batches_cost_at_most_one_chunk_of_proof_of_work`, `pings_are_answered_while_a_header_batch_is_verified`] | Single FIFO: a tip announcement waits behind a 150 s batch (§2.15); unsolicited single headers cost a RandomX hash each (§2.8); no minimum chain work (known) | PoW before any body request |
| Body download | PI | Window of 256 bodies, 16 per peer, requested-block byte exemption | Trusts the peer's *claimed* height (§2.12); fixed 60 s timeout for 16 × 9.45 MB (§2.9); no stall detection; re-request loops (known) | — |
| Block serving / relay | PI | Header announcement then pull (no push duplication) | Upload not accounted (§2.10); no compact blocks; announcement only after full validation (§5) | — |
| Node wiring | PI | spawn_blocking for RPC `submit_block` | The same lock design as §3.1; RPC readers take the chain lock on async threads | — |

---

## 2. Findings

Format for each finding:
- **Class** (brief taxonomy);
- **Severity**;
- **Location**;
- **Scenario**;
- **Confidence**;
- **Evidence** tag;
- **Recommendation**, with the fields in the order why / security / privacy / performance / complexity / consensus / identity / difficulty / priority.

Known items are marked **(known: X)**; for those I add only depth or correction.

### 2.1 R8-1: The chain lock is held for unbounded CPU work and is taken on async threads (known in part: "chain lock taken on async threads", "block processing on read loop"; deepened)

- **Class:** Partially implemented (architecture).
- **Severity:** **High**.
- **Confidence:** high.
- **Evidence:** [SR].

**Where the chain lock is held during expensive work:**
- `chain/src/manager.rs` `submit_inner` calls `self.headers.accept(block.header, now)` for an *unknown* header. `consensus/src/chain.rs:452-458` then computes RandomX **under the chain lock**. That is 0.45–0.75 s light mode per call.
- `sync_state` (called from `submit_block` *and* from `accept_headers`) connects **every** reachable body in one call.
  - The download window is 256 bodies (`net.rs:1206`), and bodies arrive out of order from random peers.
  - The one block that fills a gap therefore triggers connecting up to 256 blocks while the lock is held.
  - Per-block validation is single-threaded (no threads in `tx/src/validate.rs`).
  - Worst case, a full block (1 MB v1 + 8 MiB PX) is ≈ 400 transfers × 6.8 ms + 3 PX × 0.21 s ≈ 3.4 s [A: 2.5 kB/transfer]. 256 such blocks hold the lock for ≈ 14 min.
- `check_tx` / `submit_tx` hold the lock during CLSAG, BP+ and PX verification (`net.rs:303, 1409, 1476, 1537`). A PX transaction takes 0.2 s.

**Where async threads take the lock (they block a tokio worker while another thread verifies):**
- `run_connection` (`net.rs:602`);
- `locator` (`:444`, from `request_headers`, which also runs on `header_worker` and the maintenance loop);
- the `GetHeaders` handler (`:845`);
- `on_get_blocks` (`:1126`, clones up to 16 bodies of ≤ 9.45 MB under the lock);
- `schedule_downloads` (`:1206`);
- `on_inv_tx` (`:1238`);
- `on_get_tx` (`:1298`);
- the maintenance tip check (`:1583`, `:1668`);
- every RPC handler in `node/src/lib.rs` (`info`, `template`, `blocks`, `outputs`, …).

**Scenario:**
1. During IBD, the gap-filling block arrives and `sync_state` starts connecting 200 PX-heavy blocks.
2. Within milliseconds, the tokio workers (one per core by default, `node/src/main.rs:100`) are each blocked in `inner.chain()` from `on_inv_tx`, `schedule_downloads` or the maintenance loop.
3. No pongs are sent, no frames are read, and the accept loop stops.
4. Peers drop us after `PONG_TIMEOUT` (30 s), and in-flight requests time out.
5. When the lock is released, we charge *them* timeout points (`net.rs:1663`).

The same freeze can be triggered on demand by an attacker; see R8-2 and R8-5.

**Recommendation.** See the redesign in §3.1. Short term:
- (a) Never lock the chain on an async thread. Route every access through `spawn_blocking`, or better, a read snapshot.
- (b) Bound `sync_state` to N blocks per call, re-queueing the rest.
- (c) Verify the PoW of block headers outside the lock (reuse `pow_jobs`/`compute_parallel`, as the header path already does).
- (d) Run stateless tx verification (signatures, range proofs, PX proofs) outside the lock against immutable ring-member data, then commit under the lock.

| Field | Assessment |
|---|---|
| Why | The whole node's liveness depends on the slowest lock holder |
| Security | Removes a node-wide freeze primitive |
| Privacy | None |
| Performance | Large gain (parallel verification) |
| Complexity | M (short term) to L (actor) |
| Consensus | None; validation results must stay identical (differential tests) |
| Identity | No |
| Difficulty | M/L |
| Priority | **P0** for (a)(b)(c), P1 for (d) |

### 2.2 R8-2: Unsolicited blocks are fully processed, including RandomX under the chain lock

- **Class:** Partially implemented.
- **Severity:** **High**.
- **Location:** `net.rs:1159-1175`.
- **Confidence:** high.
- **Evidence:** [SR].

An unrequested `Block` costs the sender +10 (`UNSOLICITED`) and is **then submitted anyway**. For an unknown header, that is:
- a merkle root;
- one RandomX light hash under the chain lock (R8-1);
- if the PoW is valid, full body validation.

With invalid PoW the sender is banned only after that hash. Because bans are per exact IP (N-5), an IPv6 attacker with one /64 can rotate addresses indefinitely. Each connection costs ~30 ms of TCP and Ristretto work plus 20 bytes. Each one buys ~0.6 s of **global** chain-lock time. That is about 2 connections/s to keep the node permanently frozen.

**Recommendation:**
- Accept a `Block` only if its id is in `block_requests` for that peer, or its header is already known valid and its body is wanted.
- Otherwise drop it before decode-heavy or PoW work (score +10, no processing).
- Blocks from our own miner go through RPC, not P2P, so nothing legitimate is lost.

| Field | Assessment |
|---|---|
| Why | Cheapest global DoS in the code |
| Security | High |
| Privacy | None |
| Performance | Positive |
| Complexity | S |
| Consensus | None |
| Identity | No |
| Difficulty | S |
| Priority | **P0** |

### 2.3 R8-3: Address manager: one source group can reach all *new* buckets; there is no addr rate limit

- **Class:** Partially implemented.
- **Severity:** **High** (eclipse, join denial).
- **Location:**
  - `addrman.rs:48-54, 83-107`;
  - `net.rs:899-933`.
- **Confidence:** high.
- **Evidence:** [SR]; [M] for the bucket argument.

**How bucketing works here.** The bucket is `H(secret, table, group(addr), group(source)) mod 256`. For a fixed attacker source group, varying `group(addr)` spreads entries uniformly over **all 256 buckets**. Announced addresses need not be real.

**How Bitcoin Core bounds it.** Core bounds a source group to 64 of its 1024 buckets (`ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP`), using a two-stage hash.

**Why the existing test misses it.** The test `one_group_cannot_flood_the_table` (`addrman.rs:305`) varies addresses only *within one /16*. It therefore misses this; the doc claim in docs/p2p.md §9 ("an attacker from a few network groups can therefore fill only a few buckets") is incorrect as written.

**Flooding rate:**
- `on_addr` accepts unlimited ≤ 10-address `Addr` messages (only the 50 msg/s bucket applies). That is ~500 addresses/s per connection, plus one 1000-address batch.
- The whole 16,384-slot *new* table is overwritten in ~30 s by one inbound peer.
- Eviction on a full bucket is random unless `attempts ≥ 3`, so honest entries are evicted.
- Fresh small batches are then relayed to 2 random peers, so the pollution spreads network-wide. Each node relays only *fresh* entries, which bounds the spread per address but not the total volume.

**Consequences:**
- A new or restarted node with an empty or small *tried* table draws ≥ 50 % (100 % if *tried* is empty) of its outbound candidates from attacker-chosen addresses. They are either dead (join denial: 10 s connect timeouts, 60 s backoff) or attacker nodes (eclipse; see Heilman et al., USENIX Security 2015).
- Combined with R8-4 and R8-5, this is a practical eclipse.

**Recommendation.** Bitcoin-parity addrman v2:
- per-source bucket limit (two-stage hash);
- a per-peer token bucket for unsolicited addresses (Core: 0.1 addr/s, burst 1000; GetAddr answers exempt; PR #22387);
- address timestamps with a horizon and `IsTerrible` eviction;
- multiplicity (up to 8 *new* buckets per address);
- test-before-evict for *tried* collisions;
- a HashMap index instead of linear `position()` scans (`addrman.rs:56-65`, O(20k) per add under the state lock).

Add a regression test with many address groups from one source group.

| Field | Assessment |
|---|---|
| Why | Eclipse resistance is claimed but not provided |
| Security | High |
| Privacy | Eclipse enables full transaction-origin deanonymization |
| Performance | Positive (index) |
| Complexity | M |
| Consensus | None |
| Identity | No; the `peers.json` format changes, so add a version field |
| Difficulty | M |
| Priority | **P1** (the rate limit and per-source limit are **P0**, S) |

### 2.4 R8-4: Outbound network-group diversity is not enforced within one selection round (new bug)

- **Class:** Partially implemented.
- **Severity:** **Medium-High**.
- **Location:** `net.rs:1741-1776`.
- **Confidence:** high.
- **Evidence:** [SR].

`groups` is computed once, before the `for _ in 0..free` loop. Picked candidates are pushed to `to_connect` but their groups are never added. The skip closure checks only `to_connect.contains(a)` (the exact address).

**Scenario:** at startup (`free = 8`), all 8 outbound connections can be made to one /16. That is exactly when a node is most vulnerable, and with R8-3 it is the attacker's /16. Later rounds exclude that group only for *new* picks; the existing 8 stay.

**Recommendation:**
- Insert each pick's group into `groups` inside the loop.
- Add a test asserting ≤ 1 pick per group per round.
- Consider an AS-based group (Bitcoin's asmap) later (Tran et al., "A Stealthier Partitioning Attack against Bitcoin Peer-to-Peer Network" / Erebus, IEEE S&P 2020).

| Field | Assessment |
|---|---|
| Why | Violates the documented invariant "at most one per group" |
| Security | High for new nodes |
| Privacy | Eclipse → origin |
| Performance | None |
| Complexity | S |
| Consensus | None |
| Identity | No |
| Difficulty | S |
| Priority | **P0** |

### 2.5 R8-5: Every onion address is its own network group

- **Class:** Partially implemented.
- **Severity:** **High** for Tor-only nodes, Medium overall.
- **Location:** `p2p/src/addr.rs:88-92`.
- **Confidence:** high.
- **Evidence:** [SR].

`group()` for an onion address returns the whole host, and onion addresses are free to mint. Consequences:
- **addrman:** an attacker's onion addresses land in arbitrarily many buckets, even with a per-source limit, because the addr-group dimension is unbounded.
- **Outbound diversity:** a `--proxy-only` node's "one per group" rule is satisfied by 8 attacker onion services. That costs nothing, so a full eclipse of the most privacy-conscious users is trivial.
- Onion hosts are checked only for charset (`addr.rs:33-38`). The v3 checksum and version byte are not validated, so garbage onions pollute the table as well.

Bitcoin Core groups Tor addresses by network plus the first 4 bits (16 groups). This is weak, but it bounds the damage together with per-source limits.

**Recommendation:**
- Group onions as `{onion-net, first 4 bits}`.
- Validate the v3 checksum.
- For Tor-only nodes, add anchors and manual `--peer` pinning guidance.
- Consider a mixed-network outbound policy: at least one clearnet-via-Tor peer and one onion peer.

| Field | Assessment |
|---|---|
| Why | Tor users are the primary privacy audience |
| Security | High |
| Privacy | High |
| Performance | None |
| Complexity | S |
| Consensus | None |
| Identity | No |
| Difficulty | S |
| Priority | **P0/P1** |

### 2.6 R8-6: SOCKS5 without stream isolation; the unauthenticated transport makes one exit a MITM of all clearnet peers

- **Class:** Partially implemented.
- **Severity:** **Medium-High** (Tor users who dial clearnet peers).
- **Location:** `p2p/src/socks5.rs:14`.
- **Confidence:** medium-high.
- **Evidence:** [SR] for the code; [A] for Tor's default isolation flags (IsolateSOCKSAuth on, IsolateDestAddr off).

Only the no-auth method is offered, so Tor may carry many clearnet peer connections over the same circuit and exit. The transport is unauthenticated (docs/p2p.md §1). A single malicious exit relay can therefore:
- read (by MITM) and drop every clearnet peer connection of the node;
- see its stem transactions in the clear;
- eclipse it.

Bitcoin Core defaults to `-proxyrandomize`: random SOCKS credentials per connection.

**Recommendation:** RFC 1929 username/password with random credentials per connection. Prefer onion peers when running `--proxy-only`.

| Field | Assessment |
|---|---|
| Why | Closes the single-exit observer |
| Security | Medium |
| Privacy | High |
| Performance | Negligible |
| Complexity | S |
| Consensus | None |
| Identity | No |
| Difficulty | S |
| Priority | **P1** |

### 2.7 R8-7: The stem conflict check runs *after* full `check_tx`, so there is free CPU DoS with valid double-spend variants (new)

- **Class:** Partially implemented.
- **Severity:** **High** (DoS).
- **Location:** `net.rs:1476` (`check_tx`, full CLSAG/BP+/PX verification under the chain lock) precedes the `stem_key_images` check at `net.rs:1498`.
- **Confidence:** high on the ordering. The CPU figures use the brief's measurements.
- **Evidence:** [SR].

**Scenario:**
1. An attacker owns one output.
2. It builds unlimited *distinct, valid* transactions spending it: different ring decoys, outputs and fees. These pass every stateless check, and none is in the mempool.
3. Each costs the victim ~6.8 ms of verification under the chain lock (0.2 s if PX-shaped, though the PX buckets bound that).
4. Each is then silently dropped as a stem conflict, with **no penalty**.
5. At 20 tx/s per peer (burst 100) × 64 inbound, that is ~8.7 CPU-s/s: the chain lock is saturated and blocks and headers starve.

This is distinct from the known "invalid-CLSAG spam unpenalized": these transactions are *valid*. The mempool path (`on_tx`) has the same shape if the mempool's key-image conflict test runs after verification [U: depends on `Mempool::check` ordering, being fixed per the brief].

**Recommendation:**
- Check `stem_key_images` and mempool key images **before** `check_tx`: cheap hash lookups.
- Count conflicting variants per peer. Repeated conflicts on the same key image from one peer mean deliberate spam; charge UNSOLICITED.
- Cap stempool bytes.

| Field | Assessment |
|---|---|
| Why | Cheapest sustained DoS using valid data |
| Security | High |
| Privacy | Neutral: the conflict check is local; do not reply differently |
| Performance | Positive |
| Complexity | S |
| Consensus | None |
| Identity | No |
| Difficulty | S |
| Priority | **P0** |

### 2.8 R8-8: Unsolicited single-header announcements cost one RandomX hash each on the single header worker

- **Class:** Partially implemented.
- **Severity:** **Medium-High**.
- **Location:** `net.rs:938-979`, `1001-1047`.
- **Confidence:** high.
- **Evidence:** [SR]; [T: `junk_header_batches_cost_at_most_one_chunk_of_proof_of_work`] covers batches, not rotation.

A one-header unsolicited `Headers` is allowed at any time and passes the cheap precheck if its fields are plausible. It then costs one light hash (0.45–0.75 s) on the **only** header worker before the invalid PoW is found. The ban is per exact IP (N-5), so rotation (IPv6 /64, or Tor inbound per N-6) makes this ≈ 1.5 bad headers/s to occupy the worker permanently. Honest tip announcements queue behind them, and the node falls behind the network.

This deepens the known "low-work headers" item: here the headers are *invalid*, and the attack works regardless of a minimum-chain-work rule.

**Recommendation:**
- (a) A separate priority lane for announcements from outbound peers.
- (b) Per-peer and global budgets for unsolicited-header PoW (e.g., one pending per peer, and inbound-only unsolicited headers verified only when the claimed cumulative work exceeds our tip's).
- (c) Bans keyed by /64 for IPv6 and by /24 after repeated offences (N-5).
- (d) Keep a full-mode RandomX dataset when ≥ 2.5 GiB RAM is available: 0.1 s instead of 0.6 s per verification, i.e. 6× less amplification.

| Field | Assessment |
|---|---|
| Why | RandomX makes header validation expensive; Bitcoin's SHA-256d assumptions do not transfer |
| Security | Medium-High |
| Privacy | None |
| Performance | Positive |
| Complexity | S–M |
| Consensus | None |
| Identity | No |
| Difficulty | S/M |
| Priority | **P1** |

### 2.9 R8-9: The block download timeout bans honest slow peers during large-block sync (new)

- **Class:** Partially implemented.
- **Severity:** **Medium-High** (testnet reliability and partition risk).
- **Location:**
  - `net.rs:39` (`BLOCK_TIMEOUT` 60 s);
  - `:1220-1228` (16 blocks per peer requested at once);
  - `:1637-1649` (+5 per timed-out block);
  - `:1170-1172` (a late arrival is then "unrequested", +10).
- **Confidence:** high on the mechanics; the bandwidth figures are [A].
- **Evidence:** [SR].

**Scenario:**
1. PX-era blocks are ~9.45 MB, and 16 requested together means 151 MB. Delivering that in 60 s needs ≥ 2.5 MB/s (20 Mbit/s) of upload from the server to us alone, and the server may be serving several peers.
2. A home node serving IBD misses the deadline: +80 at the first timeout sweep.
3. Late blocks arrive as "unrequested", +10 each, so the score reaches 100 immediately.
4. That is a **24 h IP ban of an honest peer**.
5. Several such bans on a small testnet fragment the network. The known "requested blocks exempt from byte budget" fix addressed only the byte limit.

**Recommendation:**
- A per-block timeout that starts when the block reaches the head of that peer's queue, scaled by size and in-flight count (Bitcoin: base 10 min + per-peer scaling; stall detection when the window cannot move).
- Timeouts cause disconnection and re-assignment, **never** a score.
- A late requested block is not "unsolicited" if it was requested within the last N minutes.
- Fewer in flight when blocks are large (byte-based window).

| Field | Assessment |
|---|---|
| Why | False bans between honest nodes (a repeat of the R6 class) |
| Security | Medium |
| Privacy | None |
| Performance | Positive |
| Complexity | S |
| Consensus | None |
| Identity | No |
| Difficulty | S |
| Priority | **P0** for the testnet with PX blocks |

### 2.10 R8-10: No byte accounting on the send side or at frame allocation (memory and upload amplification)

- **Class:** Partially implemented.
- **Severity:** **High** (memory DoS once large blocks exist).
- **Confidence:** high.
- **Evidence:** [SR].

**Where the unaccounted bytes come from:**
- **Outbox:** `OUTBOX = 64` *messages* (`net.rs:44`). `on_get_blocks` (`:1124-1144`) enqueues up to 16 full blocks per request, and `GetBlocks` costs one message token (50/s).
  - A peer that requests and does not read accumulates up to 64 × 9.45 MB ≈ **605 MB** before the kill.
  - 64 inbound peers can pin ~38 GB. Bodies are already in RAM (PX-F1), and each serve clones and encodes them under the chain lock.
- **Upload amplification:** a ~550-byte `GetBlocks` yields ~151 MB of upload. There is no upload target, and a killed peer reconnects (max_per_ip = 2; IPv6 unlimited).
- **Receive side:** `FrameReader::recv` allocates `len + 16` (up to MAX_FRAME ≈ 9.5 MB) right after the length decrypts (`transport.rs:103`), before any payload arrives.
  - The per-frame timeout is the 180 s idle timeout.
  - 64 inbound peers plus unbounded pre-registration connections (N-4) can pin ~600 MB+ with slowloris frames.
  - The byte budget is charged only after the whole frame has been read.

**Recommendation:**
- A per-peer send queue accounted in bytes (e.g., 16 MB). Stop *processing that peer's requests* while it is over the limit (Bitcoin's `fPauseSend`) instead of pre-materializing 16 blocks: serve `GetBlocks` lazily, one block at a time as the writer drains.
- A global upload budget with priority for recent blocks (`-maxuploadtarget` analogue).
- Grow the receive buffer incrementally as bytes arrive.
- Allow MAX_FRAME only while a block request to that peer is outstanding; otherwise cap at MAX_ANY_TX_SIZE. This needs the type or a size class authenticated with the length; a transport v2 change (§3.5), which can also be done by a policy check after the first chunk.

| Field | Assessment |
|---|---|
| Why | OOM of every listening node |
| Security | High |
| Privacy | None |
| Performance | Positive |
| Complexity | M |
| Consensus | None |
| Identity | No |
| Difficulty | M |
| Priority | **P0** (outbox bytes, lazy serving), P1 (upload target, incremental receive) |

### 2.11 R8-11: No priority between control and bulk messages

- **Class:** Partially implemented.
- **Severity:** Medium.
- **Location:** `net.rs:778-787`; single FIFO outbox.
- **Confidence:** high.
- **Evidence:** [SR].

A `Pong`, a `Headers` tip announcement or a `StemTx` queues behind up to 16 × 9.45 MB of blocks. At 2 MB/s that is 75 s, past the peer's 30 s pong timeout, so the peer disconnects us. It also delays stem relay, which widens the timing signal.

**Recommendation:** two queues (control/announcement vs bulk) with strict priority. Block frames can additionally be chunked (a transport v2 feature).

| Field | Assessment |
|---|---|
| Consensus | None |
| Identity | No |
| Difficulty | S/M |
| Priority | **P1** |

### 2.12 R8-12: Download scheduling trusts self-reported `Version.height`; there is no stall detection (known in part: "re-request loops")

- **Class:** Partially implemented.
- **Severity:** Medium.
- **Location:** `net.rs:1220`, `:1669-1680`.
- **Confidence:** high.
- **Evidence:** [SR].

A peer claiming a huge height:
- is a download candidate for every missing body;
- answers `NotFound` (no penalty) or lets requests time out (+5);
- receives `GetHeaders` every tick while it returns nothing: `headers_requested` is cleared on an empty reply, and it is re-requested at 250 ms intervals, each call taking the chain lock for `locator()`.

A few such peers slow IBD severely.

**Recommendation:**
- Track `best_known_header` per peer: the highest header that peer *sent us* and that we validated. Request bodies only from peers whose known chain contains them (Bitcoin's `pindexBestKnownBlock`).
- Detect a stalled window and evict the staller.
- Back off `GetHeaders` to peers that returned empty.

| Field | Assessment |
|---|---|
| Consensus | None |
| Identity | No |
| Difficulty | M |
| Priority | **P1** |

### 2.13 R8-13: Discovery liveness: seeds only when addrman is empty; no timestamps, no self-announcement refresh, no feelers, anchors, block-relay-only or stale-tip logic

- **Class:** Not implemented.
- **Severity:** Medium.
- **Location:** `net.rs:1730`; `addrman.rs`.
- **Confidence:** high.
- **Evidence:** [SR].

**What goes wrong:**
- A node offline for weeks whose `peers.json` holds only dead addresses never falls back to seeds: `st.addrman.is_empty()` is false. It cycles 10 s connect timeouts.
- `NetAddr` has no timestamp, so dead addresses never age out.
- A listening node's `Version.listen` reaches only its direct inbound peers. It is never re-advertised, so it spreads only through random GetAddr samples. At thousands of nodes, new listeners are discovered slowly and stale entries dominate.
- docs/p2p.md §4 says `relay_txs = false` means "block-relay-only connection". The code always sends `true` and never makes such connections.

**Recommendation:**
- Fall back to seeds if there is no outbound connection within 60 s.
- Addresses with timestamps (addrv2-like; a protocol version bump) and periodic self-advertisement for configured public addresses.
- Feeler connections every ~2 min, plus test-before-evict.
- 2 block-relay-only outbound connections persisted as anchors across restarts.
- Stale-tip detection: no new tip for 30 min → one extra outbound; rotate outbound peers that are behind.

| Field | Assessment |
|---|---|
| Security | High for eclipse resistance |
| Privacy | Block-relay-only connections hide transaction topology (TxProbe, Delgado-Segura et al., FC 2019) |
| Consensus | None |
| Identity | No |
| Difficulty | M |
| Priority | Seed fallback **P0** (S); the rest **P1–P2** |

### 2.14 R8-14: Forward compatibility: an unknown message type or an extended Version is a bannable protocol violation

- **Class:** Partially implemented.
- **Severity:** Medium (testnet upgrade risk).
- **Location:**
  - `message.rs:237` and `:239` (`finish()` on Version);
  - `net.rs:736-739` (malformed message → PROTOCOL 100 → IP ban);
  - docs/p2p.md §5: "Unknown message types are violations".
- **Confidence:** high.
- **Evidence:** [SR].

**Scenario:**
1. Testnet v3 ships compact blocks or addrv2 as a new message type 15.
2. Old nodes ban upgraded peers for 24 h on first use.
3. A new optional field in `Version` fails old nodes' strict decode, so they refuse handshakes.

Rolling upgrades then partition the network.

**Recommendation:**
- Ignore unknown message types; count them against the message budget only.
- Allow `Version` trailing bytes, or use a TLV extension area.
- Negotiate features by `protocol` number (and, if accepted despite the fingerprint concern, a small feature bitfield).
- Keep strictness *inside* known types.

| Field | Assessment |
|---|---|
| Why | Upgrades must not split the network |
| Security | Neutral |
| Privacy | Features leak versions: bucket them coarsely |
| Consensus | None |
| Identity | No; do it *before* the v3 launch so every v3 node tolerates future messages |
| Difficulty | S |
| Priority | **P0** (cheap now, impossible to retrofit into deployed nodes) |

### 2.15 R8-15: Header worker: a single FIFO causes head-of-line blocking

- **Class:** Partially implemented.
- **Severity:** Medium.
- **Location:** `net.rs:1001-1047`.
- **Confidence:** high.
- **Evidence:** [SR].

A full 2000-header batch takes 2000 × 0.6 s / 8 threads ≈ 150 s. A new tip announced meanwhile waits the full 150 s. On a synced node, any peer's deep side-branch batch has the same effect. Separately, the node sends `GetHeaders` to **every** peer that is ahead (`:1669-1680`), receiving up to 8 identical 2000-header batches. PoW is deduplicated, but bandwidth and prechecks are not.

**Recommendation:**
- A priority lane for single-header announcements.
- Sync headers from one peer at a time during IBD (plus announcers).
- Pipeline: request the next batch as soon as the precheck passes, not after PoW.

| Field | Assessment |
|---|---|
| Consensus | None |
| Identity | No |
| Difficulty | S/M |
| Priority | **P1** |

### 2.16 R8-16: Fluff-phase trickle timers are independent per inbound peer (privacy)

- **Class:** Partially implemented.
- **Severity:** Medium (privacy).
- **Location:** `net.rs:485-496`.
- **Confidence:** high.
- **Evidence:** [SR]; [M] for the order-statistics argument.

Each peer draws its own `Exp(5 s)` delay. A spy with *k* inbound connections sees the minimum of *k* exponentials, with mean 5/k s, so first-spy estimation of the diffuser becomes easy again. Bitcoin Core fixed exactly this by using one shared Poisson timer for all inbound peers (PR #13298, 2018).

Two further signals:
- Inventory is sent in arrival order, which leaks relative ordering.
- One in-flight announcer with a 30 s timeout lets an inbound attacker that announces first and never answers delay propagation by 30 s per slot (inv-blocking).

**Recommendation:**
- A shared inbound timer (per network class).
- Shuffle each inv batch.
- Prefer outbound announcers and delay requests to inbound announcers by ~2 s (Bitcoin `TxRequestTracker`).

| Field | Assessment |
|---|---|
| Consensus | None |
| Identity | No |
| Difficulty | S |
| Priority | **P1** |

### 2.17 R8-17: Dandelion++: the origin's embargo fires first with non-trivial probability

- **Class:** Accepted limitation of Dandelion++ as specified; improvable.
- **Severity:** Medium (privacy).
- **Location:** `dandelion.rs:40-51`, `net.rs:1506`, `:1576-1579`.
- **Confidence:** medium.
- **Evidence:** [M] under the stated model; not measured.

**Model:**
- Every stem node, *including the origin*, arms `10 s + Exp(39 s)` when it first sees the transaction.
- Stem hops forward within ~0.1 s, far below the timer scale.
- The path length L beyond the origin is geometric with q = 0.1 (L ≥ 1).

**Estimate:**
- The origin is one of L+1 nearly simultaneous memoryless timers, so P(origin fires first) ≈ E[1/(L+1)] ≈ **0.17**.
- It is slightly higher in practice, because the origin arms earliest.
- When it fires, the origin diffuses to all its peers, and spies connected to it see the fluff from it.
- Monero has the same structure. The Dandelion++ paper analyses the timers' fail-safe role but does not claim the source never fires.

**Recommendation:**
- Give **locally originated** transactions a longer embargo (e.g., base 10 s + Exp(39 s) + an extra 30–60 s), so the origin is almost never first. The cost is extra delay only when the stem black-holes.
- Alternatively, on local-embargo expiry, *re-stem* through the other stem peer before fluffing.
- Either is a design change; per the owner policy it needs analysis and review first.
- Also add a "no stem peers → hold local transactions (bounded) instead of fluffing" rule (known item; supports the A8 fix).

| Field | Assessment |
|---|---|
| Consensus | None |
| Identity | No |
| Difficulty | S |
| Priority | **P2** (P1 if the owner rates origin privacy above latency) |

### 2.18 R8-18: Traffic analysis: an unpadded local PX transaction reveals its origin to a passive network observer

- **Class:** Not implemented. Documented as a non-goal in docs/p2p.md §1, but it undermines Dandelion++ for PX.
- **Severity:** **Medium-High** (privacy).
- **Location:** `transport.rs` (no padding); `node/src/lib.rs:192-216` (local transactions go to a clearnet stem peer).
- **Confidence:** high.
- **Evidence:** [SR] + [M] (frame sizes are exact: payload + 36 bytes).

**Scenario:**
1. The ISP of a clearnet node sees an outbound encrypted frame of ~2.18 MB (a PX transfer; a 2.69 MB vault).
2. There was no inbound frame of that size shortly before.
3. So this node *originated* a PX transaction.
4. Dandelion++ protects only against spy *nodes*.
5. PX transactions are rare and huge, so this signal is near-perfect. Size classes also separate PX transfer, vault, v1 transfer, stem vs inv, and so on.

**Recommendation (comparison with Monero):** a Monero-style anonymity-network mode, where Monero uses `--tx-proxy tor,…` and a "noise" mode with fixed-size, fixed-interval fragments:
- **(a)** `--tx-proxy`: locally originated transactions are sent *only* over Tor or onion connections, never over clearnet stems. This is the highest-value, lowest-cost step.
- **(b)** Frame padding to size buckets (e.g., powers of two, or 64 KiB granularity for large frames).
- **(c)** Optional constant-rate cover traffic on stem links (research-grade).

Also document clearly that `--proxy` without `--proxy-only` still listens on clearnet (R8-19).

| Field | Assessment |
|---|---|
| Consensus | None |
| Identity | No |
| Difficulty | (a) M, (b) S–M, (c) L |
| Priority | **P1** for (a) and documentation, P2 for (b), P3 for (c) |

### 2.19 R8-19: `--proxy` without `--proxy-only` listens on clearnet; the clearnet and onion identities of one node are linkable

- **Class:** Partially implemented.
- **Severity:** Medium (privacy footgun).
- **Location:** `node/src/config.rs:203-215`; `net.rs:874-897`.
- **Confidence:** high.
- **Evidence:** [SR].

**Two problems:**
- With `--proxy` alone, outbound goes over Tor but the node listens on `0.0.0.0`. A spy connects inbound on clearnet and receives the node's fluff invs and tip timing, linking the "Tor" node to its IP.
- For dual-homed nodes (clearnet plus an onion service), `GetAddr` answers come from one addrman with fresh random samples per connection. An attacker can scrape both identities repeatedly and correlate the tables (Biryukov, Khovratovich and Pustogarov, CCS 2014; Bitcoin Core's per-network 24 h addr-response cache, v0.21).

**Recommendation:**
- `--proxy` implies no clearnet listening unless `--listen` is explicit, with a warning.
- Cache the GetAddr answer per (network, ~24 h).
- Keep a separate stem and trickle context per network class.

| Field | Assessment |
|---|---|
| Consensus | None |
| Identity | No |
| Difficulty | S |
| Priority | **P1** |

### 2.20 R8-20: Transport fingerprintability and active probing

- **Class:** Partially implemented.
- **Severity:** Low-Medium (censorship resistance, fingerprint).
- **Location:** `transport.rs:131-147`.
- **Confidence:** high.
- **Evidence:** [SR]; the Ristretto encoding facts are [M].

**What identifies the protocol:**
- Canonical Ristretto encodings have bit 0 of byte 0 = 0 ("non-negative") and bit 7 of byte 31 = 0. Four known bits per connection (two per direction) identify the protocol after a few flows.
- Flow shape: exactly 32 bytes, 32 bytes, then two ~90–110-byte Version frames, then 36-byte Veracks.
- **Active probing:** the responder writes its key after reading *any* 32 bytes (`transport.rs:138-140`), before validating them. A censor confirms a BlackSilk listener with one probe.

**Comparison:**
- BIP324 uses ElligatorSwift (64 uniform bytes), garbage padding up to 4 KiB and decoy packets. Its content is indistinguishable from random, though its shape is still detectable.
- obfs4 requires a server-specific secret for any response.
- Monero's levin is plaintext with a fixed magic. Opportunistic TLS for P2P is in development: an open PR, not in the release as of this review [A per web search].

**Recommendation (transport v2, version-negotiated):**
- Elligator2-encoded X25519 or ristretto-elligator-inverse keys. A pure-Rust implementation is needed; FFI is not allowed.
- Random-length handshake padding and a garbage terminator (BIP324 pattern).
- Decoy frames.
- Optionally a "bridge mode" requiring a pre-shared server key.

This depends on R8-14 so that v1 nodes can be dropped cleanly.

| Field | Assessment |
|---|---|
| Consensus | None |
| Identity | No (P2P only), but all nodes must upgrade |
| Difficulty | M/L |
| Priority | **P3** (P2 if censorship-resistant deployment is a goal) |

### 2.21 R8-21: No optional peer authentication and no exposed session id

- **Class:** Not implemented.
- **Severity:** Low.
- **Evidence:** [SR].

A MITM can read and drop traffic (documented). There is no way for operators to detect a MITM on their manual `--peer` links.

**Recommendation:**
- Expose `H(session key)` as a session id in peer info (BIP324 practice) for out-of-band comparison.
- Optional static-key authentication for `--peer` entries (Noise IK pattern; `--peer <addr>#<pubkey>`), leaving normal peers anonymous.

| Field | Assessment |
|---|---|
| Consensus | None |
| Identity | No |
| Difficulty | S (session id), M (auth) |
| Priority | **P2** |

### 2.22 R8-22: Smaller items

**Low severity:**

| Item | Location | Status | Priority | Evidence |
|---|---|---|---|---|
| `CachedPow::known` grows without bound and also caches hashes of *invalid* headers (~100 B each) | `chain/src/manager.rs:37` | PI | P2 | [SR] |
| addrman linear scans (see R8-3) | — | PI | P2 | [SR] |
| Misbehavior scores never decay; +1 per rate excess accumulates over days of an honest connection | — | PI | P2 | [SR] |
| No per-message-type CPU accounting | — | PI | P2 | [SR] |

**Medium and informational:**
- **Unbounded stempool size in bytes** (`net.rs:174`, `:1507`). Medium; P1; [SR].
  - PX entries are bounded by the PX buckets, but v1 entries are bounded only by 20/s/peer × embargo (~49 s): ≈ 70k entries at 64+8 peers.
- **The unit test comment asserts properties the code lacks.** Info; [SR].
  - `one_group_cannot_flood_the_table` asserts eclipse resistance in a narrower sense than docs/p2p.md §9 claims.
  - Docs should be corrected by A16b.

---

## 3. What should be redesigned (target architecture)

### 3.1 The chain as an actor with snapshots; verification off-lock

**Proposal:**
- **Chain actor:** one dedicated OS thread owns `ChainManager`. It takes commands over a bounded channel with priority classes: tip headers > requested blocks > header batches > transactions > RPC reads.
- **Read snapshot:** published after each mutation as `Arc<ChainView>` (height, tip, locator, header index, mempool id set), swapped atomically. std `RwLock<Arc<_>>` suffices; the `arc-swap` crate is optional. Network tasks and RPC readers never block on the actor.
- **Verification pool:** a fixed thread pool with `std::thread::scope` workers, like `compute_parallel`, runs every stateless and signature check **before** a command reaches the actor:
  - PoW;
  - CLSAG (ring members fetched from the snapshot; ring outputs are immutable once confirmed);
  - BP+;
  - PX proofs.
  The actor then re-checks only cheap contextual facts: key images, ring-member existence on the current branch, anchors.
- **Bodies:** verify in parallel per transaction, and pre-verify across blocks during IBD. `sync_state` connects a bounded number of blocks per actor turn.

**Assessment:**
- **Why:** R8-1 and R8-2, and the known "lock on async threads".
- **Performance:** IBD body verification scales with cores (≈ 8× on 8 cores [A]); block propagation per hop drops by the validation time.
- **Security:** removes the global-freeze primitive.
- **Consensus:** none, *if* results are identical. Require differential tests: old path vs new path over the labnet chain and fuzzed blocks.
- **Identity:** no.
- **Difficulty:** L.
- **Priority:** P1 for the design, with the P0 short-term steps in R8-1.

### 3.2 Per-peer work queues and a fair scheduler

**Proposal:**
- Read loops only decrypt, decode, apply rate limits and push into a per-peer bounded queue, measured in bytes and CPU-cost units.
- A message-handler task round-robins across peers, one message per peer per round, as Bitcoin's `ThreadMessageHandler` does.
- A peer whose queue is full stops being read, giving TCP backpressure instead of a kill.
- Expensive work carries a per-peer CPU budget (RandomX hashes/min, CLSAG verifications/s, PX/s). Exceeding it pauses the peer; it is not banned.

**Assessment:**
- **Why:** fairness; no peer can monopolize the chain or verifier; a slow peer cannot stall anything.
- **Consensus:** none.
- **Identity:** no.
- **Difficulty:** M.
- **Priority:** P1.

### 3.3 Bandwidth accounting

**Proposal:**
- A per-peer send buffer in bytes with pause-processing.
- A global upload budget: serve recent blocks first; historical block serving is rate-limited.
- Two-level priority (control vs bulk).
- Incremental receive buffers.
- Metrics (bytes in/out per message type) exposed through RPC for testnet observability.

**Assessment:** R8-10 and R8-11. Difficulty M. Priority P0/P1.

### 3.4 Connection manager v2 (Bitcoin-parity, adapted)

**Outbound classes:**
- 8 full-relay;
- 2 block-relay-only (persisted as anchors);
- 1 feeler every ~2 min;
- 1 extra on a stale tip.

**Inbound eviction** (N-9), à la `AttemptToEvictConnection`:
- protect by netgroup (4), lowest ping (8), recent tx (4) and recent block (4) relayers, and the longest-lived half;
- reserve a share for onion inbound;
- evict from the netgroup with the most connections;
- treat IPv6 by **/64 for per-IP limits and bans and /32 for grouping**; IPv4 by /32 per IP and /16 per group.

**Per-/64 and per-/16 inbound caps**, not just exact-IP `max_per_ip`. Today one IPv6 /64 can fill all 64 inbound slots of every listening node. With no eviction, new nodes cannot join; that deepens N-5/N-9.

**Discovery:** addrman v2 (R8-3), onion grouping (R8-5), seed fallback (R8-13).

**Assessment:**
- **Why:** eclipse resistance and join resistance at thousands of nodes.
- **Consensus:** none.
- **Identity:** no.
- **Difficulty:** M/L.
- **Priority:** P1; the inbound caps by /64 are **P0**.

### 3.5 Transport v2

**Proposal:** negotiated by protocol version, after R8-14:
- Elligator-encoded keys;
- padding and decoys;
- length and size-class authenticated together so the receive cap depends on the solicitation state;
- rekey every 2^20 frames or 1 GiB (hygiene);
- session id;
- optional authenticated manual peers.

**Assessment:** R8-20/21. Difficulty M/L. Priority P2/P3.

### 3.6 Sync v2

**Minimum chain work** (known K4/A8; policy): update it each release. It stops low-work header storage and can drive a Bitcoin-style **headers presync**:
1. First download headers keeping only a rolling commitment and the running *claimed* work, checked cheaply by recomputing LWMA without PoW.
2. Once the claimed work exceeds `minimum_chain_work`, re-download and verify PoW.
3. Memory stays bounded against low-work spam.
4. The double download costs bandwidth only, about 26 MB/yr of headers.

**Assume-valid PoW checkpoint** (policy, Monero-fast-sync-like; Monero ships embedded block hashes for fast sync):
- Headers that hash-link to a release-embedded block id cannot be forged; that is a preimage argument [M].
- Their RandomX can therefore be skipped.
- Signature and proof verification of bodies stays on by default. A second, opt-in tier could skip CLSAG/BP+/PX for ancestors of the checkpoint, but for a hidden-amount chain that trusts the release for **inflation soundness**. It should never be the default, and needs owner approval.

**Other sync changes:**
- Per-peer best-known header, stall detection and byte-based download windows (R8-12, R8-9).
- **Compact blocks (BIP152-like), with a privacy caveat.**
  - Reconstruction must use only the mempool, *never* the stempool. Otherwise the set of short ids a node must request reveals which stem transactions it holds, i.e. that it is on a stem path.
  - Relay the compact block after PoW and before full validation (high-bandwidth mode), with no penalty if the body later proves invalid (as in Bitcoin).
  - Gains: PX blocks drop from ~9.45 MB to kilobytes per hop when the mempool is warm, removing most propagation delay (§5).
- **Erlay** (Naumenko et al., CCS 2019): not needed below a few thousand nodes. It requires a pure-Rust minisketch; no pure-Rust implementation is known, and bindings would be FFI. Defer (P3).

**Assessment:**
- **Consensus:** none for any of these; all are policy or P2P.
- **Identity:** minimum chain work and checkpoints are per-release constants, not a new identity.
- **Difficulty:** M (minimum work and presync), M (assume-valid PoW), L (compact blocks).
- **Priority:** minimum chain work and assume-valid PoW **P1**; compact blocks **P2**.

---

## 4. Scalability to thousands of nodes

| Aspect | Current behaviour | At 1,000–5,000 nodes | Evidence |
|---|---|---|---|
| Inbound capacity | 64 slots, no eviction | Fine if ≥ 1/8 of nodes listen. But exhaustible by one IPv6 /64 per node (§3.4) → new nodes cannot join | [SR]+[M] |
| Addr propagation | No timestamps; `listen` is never re-advertised; only fresh addresses are relayed | New listeners are found slowly; stale entries accumulate; floods propagate (R8-3) | [SR] |
| addrman CPU | O(20k) linear scan per add under the state lock | 1000-address batch ≈ 2×10^7 comparisons, tens of ms per batch [A] | [SR] |
| Tx announcements | Inv to every peer (≤ 72) | ~2.3 kB per tx per node: fine; Erlay only at larger degree | [M] |
| Block relay | Header announce → pull from a random peer | No push duplication (good); full body per hop (no compact blocks) | [SR] |
| Header worker | One FIFO | Head-of-line blocking (R8-15) | [SR] |
| Dandelion | 2 outbound stems per epoch | Approximates the paper's 4-regular graph; fine | [SR] |
| State lock | One process-wide `Mutex<State>` | Held briefly (µs–ms); OK to hundreds of peers; addrman scans are the main outlier | [SR] |

---

## 5. Initial sync time and propagation estimates

**Assumptions:**
- testnet 120 s blocks, so **262,980 blocks/year**;
- light RandomX 0.45–0.75 s per hash per thread;
- PX verification 0.21 s;
- v1 full verification 6.8 ms per transfer;
- a full block is ≈ 400 transfers (1 MB v1 budget at ~2.5 kB [A]) plus 3 PX (8 MiB PX budget / 2.18 MB);
- linear thread scaling [A].

All figures are **[M]** (arithmetic on measured unit costs) **plus [A]** (scaling and load); none is measured end to end.

| Component | Per year of chain | 2 threads | 4 threads | 8 threads |
|---|---|---|---|---|
| Header PoW (light) | 32.9–54.8 CPU-h | 16–27 h | 8–14 h | 4.1–6.8 h |
| Header PoW with an assume-valid checkpoint | ~0 (hash-linking only) | — | — | — |
| Body verification, empty blocks | negligible | — | — | — |
| Body verification, 100 % full blocks (today: **single-threaded, under the chain lock**) | ≈ 3.4 s × 262,980 ≈ **248 h** | 248 h | 248 h | 248 h |
| Same after parallel per-tx verification (§3.1) | 248 CPU-h | ~124 h | ~62 h | ~31 h |
| Same at 10 % average fill | ~25 h today | | | ~3 h after §3.1 |
| Download, 100 % full blocks | 9.45 MB × 262,980 ≈ **2.5 TB** | | | |
| Restart re-validation (PX-F3, known) | repeats the body cost on every restart | | | |

**Full-mode vs light-mode RandomX for IBD** with this implementation:
- The dataset takes ~179 s per epoch on 8 threads.
- Per 2048-block epoch:
  - full ≈ 179 s + 2048 × 0.1 / 8 ≈ 205 s;
  - light ≈ 2048 × 0.6 / 8 ≈ 154 s.
- Light mode is therefore as good or better for IBD.
- The full dataset pays off only at the tip: 0.1 s vs 0.6 s per hop of propagation, and 6× less DoS amplification (R8-8).
- Recommendation: build the dataset only once synced, when RAM allows.

**Block propagation per hop (worst case, full PX block):**

| Step | Time |
|---|---|
| Maintenance tick | ≤ 0.25 s |
| Header PoW | 0.6 s |
| `GetBlocks` round trip | 0.1–0.3 s |
| Transfer (9.45 MB at ~50 Mbit/s) | ~1.5 s |
| Full body validation before re-announcement | ~3.4 s |
| **Total** | **≈ 5.8 s** |

Small blocks take ≈ 1 s per hop.

With ~4 average hops at 1,000–5,000 nodes [A], latency is ≈ 23 s for full blocks, giving a stale rate of ≈ 1 − e^(−23/120) ≈ **17 %**. For small blocks it is ≈ 4 s and ≈ 3 %. High stale rates favour large, well-connected miners, a decentralization concern.

The levers, in order:
1. compact blocks with a mempool-only reconstruction;
2. relay after PoW, before validation;
3. parallel verification;
4. a full dataset at the tip.

---

## 6. Comparison summary

| Feature | BlackSilk v1 | Bitcoin Core (≥ 27) | Monero (0.18) |
|---|---|---|---|
| Transport encryption | Yes, unauthenticated, fingerprintable | BIP324 v2 (ElligatorSwift, garbage, decoys) | Plaintext levin; opportunistic TLS in development [A: web] |
| Addrman | 256/64 buckets, no per-source limit, no timestamps | 1024/256 buckets, per-source 64, timestamps, test-before-evict, asmap | Gray/white peerlists, anchors |
| Addr rate limit | None | 0.1/s, burst 1000 (v22) | Limited |
| Feelers / anchors / block-relay-only | No / No / No | Yes / Yes / Yes | Anchors partial |
| Inbound eviction | No | Yes | Limited |
| Header sync | Header-first, PoW per header (0.6 s) | Header presync + minimum chain work | Block-based; checkpoints + fast-sync hashes |
| Compact blocks | No | BIP152 | Fluffy blocks |
| Tx origin privacy | Dandelion++ (Monero parameters) | Diffusion + shared inbound timer (no Dandelion) | Dandelion++, `--tx-proxy` over Tor/I2P with noise |
| Tor | SOCKS5 no-auth, onion addresses; no I2P | Tor/I2P/CJDNS, stream isolation | Tor/I2P anonymity networks |

**Research notes:**
- **Dandelion++** (Fanti et al., SIGMETRICS 2018) is correctly adopted in its key features: per-source routes, epochs, local-always-stem.
- **Clover** (Franzoni & Daza, 2022): a lighter alternative that distinguishes inbound and outbound sources. Worth evaluating if Dandelion's embargo latency proves costly.
- **Erlay:** defer.
- **Recent work:** "Are Unreachable Nodes Truly Safe? Fully Eclipsing Monero's P2P Network!" (arXiv 2609.10260) was seen in search and not read in depth. It is relevant because BlackSilk's discovery is weaker than Monero's.

---

## 7. What should never be changed

These are sound; changing them adds risk without benefit:
- Strict, bounded-before-allocation decoding *within* known message types.
- `network_id` in the session KDF, with no plaintext magic.
- Directional AEAD keys; a counter nonce that never wraps.
- Header-first sync: no body is requested before its header's PoW and context are verified.
- Not penalizing contextual transaction failures, InvalidParent relays, NotFound, or the future-time rule. These fixed real false-ban partitions (R6).
- GetTx serves only what was announced to that peer (anti-probing).
- Local transactions always stem; fixed per-source routes per epoch.
- Stem conflict keys include PX nullifiers.
- No user agent, no clock, no own-address advertisement by default.
- No local DNS in proxy-only mode.
- The lock-ordering rule: never hold the state and chain locks together. Keep it in the actor design.

## 8. Before the testnet vs deferrable

**P0 (before the public testnet; all policy, no new identity, S–M effort):**
- R8-1 (a)(b)(c): no chain lock on async threads; bounded `sync_state`; PoW off-lock.
- R8-2: drop unsolicited blocks before PoW.
- R8-7: stem and mempool conflict checks before verification.
- R8-9: block-timeout handling.
- R8-10: byte-accounted outbox and lazy block serving.
- R8-3: addr rate limit and per-source bucket limit.
- R8-4: group-diversity fix.
- R8-5: onion grouping.
- R8-13: seed fallback.
- R8-14: unknown-message and Version-extension tolerance.
- §3.4: inbound caps per /64 and per /16.

**P1:**
- R8-6: SOCKS isolation.
- R8-8: header-announcement budget and lanes.
- R8-11: message priority.
- R8-12: best-known-header scheduling.
- R8-15: header lanes.
- R8-16: shared trickle timer.
- R8-18 (a): `--tx-proxy`, plus documentation.
- R8-19: proxy listen default and addr cache.
- Addrman v2.
- Inbound eviction.
- Stempool byte cap.
- The chain-actor design (§3.1).
- Minimum chain work plus assume-valid PoW.

**P2:**
- R8-17: origin embargo.
- R8-18 (b): padding.
- R8-21: session id.
- Compact blocks.
- Feelers, anchors and block-relay-only connections, if not done in P1.
- Score decay.
- `CachedPow` bound.

**P3:**
- Transport v2 obfuscation.
- Cover traffic.
- Erlay.
- I2P.
- asmap.

**Tests to add** (each finding needs a regression test before its fix is claimed):
- many-group, single-source addr flood;
- one-group-per-round outbound selection;
- onion-group flood;
- stem double-spend variants cost ≤ 1 verification;
- unsolicited block costs no PoW;
- a slow honest server is never banned during large-block IBD;
- a GetBlocks-without-reading peer stays within a memory bound;
- a new message type from an upgraded peer is ignored, not banned;
- a pong arrives while 16 large blocks are queued;
- chain-lock hold time stays bounded while 256 blocks connect;
- a labnet run with ~9 MB PX blocks and throttled links.
