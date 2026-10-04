# TM2-NET: second threat-model round, network, denial of service, operations and supply chain

> Historical record (2026-10-02). Superseded where it conflicts with the code: `blocks.dat` is format 3 (524b9c0). Current: [docs/consensus.md](../../../consensus.md), [docs/STATUS.md](../../../STATUS.md).

Agent TM2-NET, phase 2. Internal engineering review, **not an audit**. Nothing here claims
that BlackSilk is secure, audited or production-ready. Read-only on the repository; no
cargo build or test was run for this report (the machine was running a mutation
campaign, and every question below could be answered from source, tests and committed
evidence). External content was treated as data.

Evidence tags: **[src]** read in the source at the cited `file:line` (commit `3c21afe`);
**[test: name]** a named test exists that exercises the property (not re-run here);
**[evid]** committed evidence under `docs/evidence/`; **[doc]** a project document;
**[inf]** my inference; **[R1]** round-1 dossier 48.

---

## 0. Scope, method and what I read

- **Commit:** local `rebuild/core` at `3c21afe` (clean). `docs/STATUS.md` declares itself
  "as of `e986250`", 218 commits earlier, with later rows edited piecemeal (§9 F-OPS-9).
- **Read in full:** `C:/bszkeval/p2/brief.md`, `impl-brief.md`, `decisions.md` (all 1,099
  lines), round-1 `48-threat-model-adversarial.md`; `p2p/src/transport.rs`,
  `p2p/src/net/conn.rs` (handshake, registration), `p2p/src/net/peers.rs` (bans, accept
  loop, handshake caps, manual-peer redial), `node/src/{main,serve,guard,cookie}.rs`,
  `node/src/config.rs` (RPC/P2P flags), `p2p/src/originated.rs`, `p2p/src/clock.rs`
  (header), `node/src/lib.rs::clock_check`; every file in `deploy/`;
  `.github/workflows/ci.yml`, `.github/scripts/{gate-range,consensus-gate}.sh`, `deny.toml`,
  `tools/release-build.sh`, `.cargo/config.toml`, `.dockerignore`, root `Cargo.toml`
  profiles; `docs/STATUS.md`, `docs/testnet.md` §2, §2.1, §11, §12, `docs/p2p.md` §1, §10
  (start), §12, `docs/testnet-v3-genesis.md` §1–§6, `docs/testnet-launch-checklist.md`,
  `docs/testnet-incident-response.md`, `SECURITY.md`, `third_party/README.md`; the
  evidence READMEs `fuzz-w4-2026-09-29`, `fuzz-stateful-2026-10-01`,
  `labnet-w4-2026-09-30`.
- **Delegated read-only inventories** (three sub-agents, each told to quote constants and
  `file:line`; I spot-checked their load-bearing claims against the source and corrected
  nothing material): (a) addrman/eclipse (`p2p/src/addrman.rs`, `addrman_gate.rs`,
  `addr.rs`, `connman.rs`, `net/addr_relay.rs`, `net/maintenance.rs`, labnet-peers
  evidence); (b) DoS and sync (`limits.rs`, `message.rs`, `net/{admission,dispatch,headers,
  blocks,relay,stem}.rs`, `chain/src/actor.rs`, `sync_policy.rs`, `manager/{header_sync,
  submission,pow_cache,fork_choice}.rs`, `mempool.rs`); (c) store and operations
  (`chain/src/store.rs`, `manager/replay.rs`, exit codes, persistence files, logs).
- **Repository metadata:** `git tag` is empty; no `.github/CODEOWNERS`; the last 20
  commits are all signature status `N` (unsigned); 795 commits in total.

---

## 1. System model and assets

| Asset | Why it matters | Primary threats |
|---|---|---|
| A1 Liveness of each node and of the network | a stalled or crashed node cannot follow or mine | DoS, crash loops, stalls |
| A2 The node's view of the best chain | eclipse lets an attacker feed a private chain (double spend, wallet poisoning, time dilation) | eclipse, sybil, MITM |
| A3 Transaction-origin privacy | the project's first goal; Dandelion++ and `originated.json` | MITM, spy nodes, logs, data at rest |
| A4 The RPC credential and the RPC's chain access | cookie = full RPC; `/block` and `/tx` cost CPU | local attackers, DNS rebinding, slot exhaustion |
| A5 Integrity of the data directory | `blocks.dat` replay trusts stored PoW hashes; operator verdicts live there | disk-full, crash, tampering |
| A6 Integrity of the shipped code | operators run what the owner says is the release | supply chain, CI, unsigned releases, social engineering |
| A7 The genesis identity | one ceremony fixes the chain | beacon handling, unsigned commit, D0 |

**Deployment models assessed.** (T) the seven-device trial: explicit `--peer` mesh,
`connect_only`, closed to outsider inbound (decision "Agent 40"), a network PSK (decision
"Agent 48" F48-1), mostly Windows desktops, one owner. (P) a later public testnet: open
inbound, seeds, Tor users, unknown operators. Severity is given for (T) and, where it
differs, (P).

**Severity scale** (same as round 1): Critical / High / Medium / Low / Informational.
Reasoning is given per finding; "P0" in §11 means it blocks the genesis or the trial
launch, "P1" before a public testnet or mainnet, "P2" hardening.

---

## 2. Network adversaries

### 2.1 Eclipse and sybil

**Assets:** A2, A3, A1.

**Mitigations in place [src, via inventory (a), spot-checked]:**
- addrman v2 (`p2p/src/addrman.rs`): 256 new × 64 tried buckets of 64 slots; keyed
  bucketing with a 32-byte RNG key persisted in `peers.json` (`AddrMan::new` :199, `save`
  :917); a source group reaches at most `NEW_BUCKETS_PER_SOURCE_GROUP = 16` new buckets;
  one slot per address, a newcomer never displaces a non-terrible entry (`add` :464);
  one tried entry per IP (`make_tried` :607), `TRIED_PER_ONION_GROUP = 1`,
  `TRIED_PER_SOURCE_GROUP = 16`; test-before-evict with the stricter RTW3-9 rule
  (`resolve_collisions` :687); adaptive tried bias 0.7 / 0.9 at ≥ 64 tried entries.
- Peer-supplied address timestamps never enter the table (`addrman_gate::clamp_time`
  :103); unsolicited `Addr` > 10 entries is dropped and scored 10; small `Addr` messages
  pass a 0.1/s token bucket (burst 1000, one token per new connection).
- Outbound diversity: one outbound per netgroup (IPv4 /16, IPv6 /32, onion = 16 groups by
  the first base32 character) across live, pending, manual and anchor connections
  (`peers.rs:562-574`), 8 full-relay + 2 block-relay-only (`connman.rs:22`), 2 anchors from
  block-relay peers (`anchors.json`, deleted on read), Poisson feelers (mean 120 s), seeds
  as one-shot `AddrFetch` that are never promoted (`conn.rs:286`).
- Inbound: 64 slots, 2 per IP or IPv6 /64, handshake caps 16 total and 4 per group with
  oldest-first eviction that never evicts a registered peer (`peers.rs:109-219`, RTW3-3);
  Bitcoin-style eviction protection by keyed group, ping, recent tx, recent block, and a
  quarter for onion peers (`connman.rs:175`); `--onion-inbound` caps onion peers at a
  quarter (16).
- Stale-tip rotation after 3·T·2 (720 s on testnet): one extra peer every 600 s; the
  outbound peer with the oldest *validated* new tip leaves (`connman.rs:280-333`,
  RTW3-4).
- Trial: `connect_only` disables table dials, feelers, seeds and anchors; the PSK closes
  the port to outsiders (§2.4).

**Evidence:** `p2p/tests/eclipse_sim.rs` drives the real `AddrMan`/`AddrGate`
([evid] `labnet-peers-2026-09-29/tests/eclipse-sim-output.txt`: IPv4 g=1 v2 attacker slot
share 10.0 %; empty tried table 61.3 %, P(all 8 outbound) = 0.018); [test]
`connection_policy.rs` cases; W4-LAB late-joiner and RT's E2 relay run (decisions
"W4-LAB"). No live adversarial address scenario has run (labnet README §8.3: "group caps
and bans cannot be tested on one machine").

**Attacks that remain, by cost:**

| # | Attack | Mechanism | Residual |
|---|---|---|---|
| E1 | Fresh-node capture (P) | built-in seeds are empty for every network (`node/src/config.rs:18-24`); a joiner depends on the `--seed`/`--peer` its operator copied from somewhere; with an empty tried table the simulator gives the attacker 61 % of slots | **High (P)** until seeds exist and their addresses come with the signed release; N/A (T) |
| E2 | Inbound self-advertisement poisoning (P) | each attacker /16 is a new source group with 16 new buckets and up to 16 tried entries, one IP per entry (`conn.rs:300-313`); not modelled in the simulator (p2p.md §9 says so) | Medium (P) |
| E3 | Laundering through honest relays (P) | fresh addresses are relayed to 2 random peers whether or not stored; laundered entries carry honest source groups, defeating the per-source cap | Medium (P), unmeasured |
| E4 | Onion sybils (P, Tor nodes) | onion names are free and their 16 groups can be ground; tried is capped at 1 per onion group, but new-table and 16 onion inbound slots are open | Medium (P, Tor-only nodes) |
| E5 | Anchor inheritance | anchors come from the block-relay peers of the last session with no cross-check; a poisoned session persists | Low |
| E6 | AS-level (Erebus) and BGP | no asmap (P3 decision) | Accepted (P) |
| E7 | Keep-alive of dead or attacker entries | `add` on a known address refreshes `time = max(time, now)` (`addrman.rs:467`): any peer re-announcing keeps entries past the 30-day horizon | Low |
| E8 | "Progressing" eclipse | stale-tip rotation only fires on a stale tip; outbound peers that keep relaying *valid* tips of a lower-work view are never rotated; there is no Bitcoin-style "outbound peer with insufficient chain work" timeout | Medium (P); see SY2 in §2.3 |
| E9 | Docker / SIGTERM loses anchors | anchors are written only by `Network::save` at a clean shutdown (`node/src/main.rs:427-429`, `p2p/src/net.rs:373-375`); the node handles only Ctrl-C (`main.rs:419`); `deploy/docker/Dockerfile` has no `STOPSIGNAL`, so `docker stop`'s SIGTERM to PID 1 is ignored and SIGKILL follows after 10 s; a plain `kill <pid>` also ends the process unsaved | Low–Medium (P): the eclipse defence of anchors silently never works in the Docker deployment; systemd is correct (`KillSignal=SIGINT`) |
| E10 | Proxy nodes never ban outbound misbehavers | with any `--proxy`, every outbound connection is `proxied = true`, and `ban_addr` returns early (`peers.rs:69-71`); a misbehaving outbound address stays dialable after the 60 s backoff | Low (by design: the IP is the proxy's) |
| E11 | Ban list unbounded | `bans: HashMap<IpAddr,u64>` has no cap; IPv6 /48 holders mint 65,536 /64 keys | Low |
| E12 | No per-netgroup cap on registered inbound | only eviction favours the largest group | Low (P) |

**Single-machine limits of the labnet (inventory a, confirmed in the README):** all nodes
on 127.0.0.1 with `allow_private`, which turns off grouping by netgroup (whole-address
groups), the one-outbound-per-group rule, per-IP and accept limits, and loopback bans;
nodes are `connect_only`. So **none** of: netgroup diversity, /64 limits, handshake caps
per group, bans and their persistence, keyed-group eviction, ping protection (20 ± 10 ms
synthetic jitter only), NAT, Tor, feelers/anchors/stale rotation against a hostile table,
or tables above 8 entries, has ever been exercised live. §10 proposes the tests.

### 2.2 Denial of service (CPU, memory, disk, bandwidth)

**Assets:** A1 (CPU, memory, disk, bandwidth of every node), and through them A2.

**Mitigations in place [src, inventory (b), the load-bearing items re-read by me]:**
- **Framing.** `MAX_FRAME` = `MAX_BLOCK_BYTES` (9,454,144) + 64 KiB; per-message counts
  checked before allocation (`message.rs:39-43, 233-275`: Addr 1000, locator 64, Headers
  2000, GetBlocks 128, Inv/GetTx 500); a frame's authenticated length is checked before
  its payload is read (`transport.rs:276-286`); malformed known messages score 100.
- **Per-peer token buckets** (`limits.rs:118-127`): messages 50/s (burst 500), bytes
  4 MB/s (16 MB), txs 20/s, v1 inputs 50/s, PX 0.2/s per peer and 2/s node-wide; relay
  excess dropped unscored (RTW2A-4), message/byte excess scored 1. Slow lane 64 places
  (32 relay, 6.55 MB of relay bytes) (`dispatch.rs:22-50`). Control outbox 64 messages,
  bulk outbox 32 blocks; a full outbox disconnects without a ban (`state.rs:478-494`).
- **Headers.** Count and linkage on the read loop; precheck of every non-PoW rule on the
  actor (required difficulty included) before any hash; `worth_verifying` work gate
  (`sync_policy.rs:62-88`, anti-DoS window 144 blocks); queue room 2 batches per origin
  and 144 in total (`headers.rs:49-59`); PoW hashed off the actor on the persistent pool
  (W4-POWPOOL), chunk by chunk, each chunk accepted before the next is hashed
  (`verify_headers`, `headers.rs:599-756`); FTL and unknown-upgrade unscored.
- **RandomX caches.** At most `MAX_CACHES = 5` × 256 MiB, keys only from stored (PoW
  verified) headers, hot keys pinned (`consensus/src/pow.rs:52-75`; RT-POW measured a
  1,298 MB peak) [evid `mutation-2026-09-29`, decisions "RT-POW"].
- **PX proofs.** Decode capped before allocation at limits implied by the shape check
  (W4-PXDOS): ≈ 16 MB / ≈ 40 ms worst case, off the actor under a 2-permit semaphore
  (`admission.rs:245`); RT-PXDOS found no parser differential over 1.15 M inputs; run D
  confirmed every cap at its boundary [evid `mutation-runD-2026-10-01`].
- **Mempool.** 50 MB v1 + 64 MiB PX/deploy, expiry 2,160 blocks; `recent_rejects` 10,000
  FIFO keyed by the full tx hash (covers proofs and signatures); `ctx_rejects` per tip.
- **Chain actor.** One writer with lanes Headers > Blocks > Query > Tx (capacities 64,
  256, 1024, 64), `STARVATION_LIMIT = 16`, one command between drain steps of 8 blocks;
  relayed transactions use `try_call` and are dropped when the lane is full; ping/pong on
  the read loop, never behind the chain (`chain/src/actor.rs:77, 141`) [test: liveness
  L1–L8, ordering g1–g7, `docs/reviews/chain-actor-stage2.md`].
- **Fuzz/mutation evidence:** decode targets (`p2p_message` 45 M execs, `block_decode`,
  `tx_decode`, `proof_decode`, `addr_v2`, `transport_*`), stateful `peer_protocol` and
  `px_admission`; mutation runs C and D on admission and decode caps.

**Residual DoS (new or re-rated this round):**

| # | Attack (cost to attacker) | Mechanism [src] | Severity |
|---|---|---|---|
| **D1** | **Junk-PoW header batches, PoW-free, one identity each.** The attacker claims a high `Version` height, we send `GetHeaders`, it answers 2,000 headers that extend our tip with the right difficulty field and junk nonces. They pass precheck and the work gate (claimed work), and the **whole first chunk** of `pow_chunk` = clamp(`pow_threads`, 1, 64) headers is hashed (`headers.rs:665-677`, `pow.compute_parallel(&j, chunk)`) before the first `InsufficientWork` scores 100. Light-mode RandomX ≈ 0.45 s per hash (p2p.md §12): ≈ 3.6 CPU-s on 8 threads, ≈ 29 CPU-s on 64. The single header worker is busy meanwhile, so honest tip headers queue behind it (R8-15). Identities: one IPv4 or one IPv6 /64 per 24 h ban (a free tunnel-broker /48 holds 65,536 /64s); **unlimited through Tor** where the node accepts onion inbound, and through any `--proxy` outbound, because proxied and onion peers are never banned (`peers.rs:69-71`). | **High (P)**: two cheap connections per second keep every core busy and delay honest headers. (T): closed by the PSK |
| **D2** | **Withholding bodies; staller detection not implemented.** `schedule_downloads` picks uniformly among peers with `p.height >= height` (`blocks.rs:238-272`); `p.height` comes from `Version` and is only ever lowered to *our header height* (`headers.rs:226, 429-440`; `maintenance.rs:151`), and every missing body is at or below it, so a peer that inflated its height stays a candidate forever. A withheld request times out after `BLOCK_TIMEOUT` = 60 s and is only logged at debug: "A timeout is not misbehavior … The request moves to another peer" (`maintenance.rs:154-191`), but the next random pick may be the same peer. Bodies connect in parent order, so one withheld low height stalls the drain above it. A peer with blocks in flight is also exempt from stale-tip rotation (`connman.rs:263-276`). Decision "Agent 31" said "Staller disconnects: enforced (disconnect, never ban)"; there is no such code. With k attacker inbound peers against 8 honest outbound, a fraction k/(k+8) of body requests (up to 89 % with 64 inbound) stalls 60 s each, during initial sync **and at the tip**. | **High (P)** for sync and tip liveness; Low (T) |
| **D3** | **Serve-side memory without a byte bound.** Outboxes are counted in messages, not bytes: the bulk outbox holds 32 encoded blocks (≈ 302 MB at max size), the control outbox 64 frames (`GetTx` answers of up to 4.46 MB each). A peer that requests and then reads slowly pins them until the pong timeout (60 + 30 s) or the overflow disconnect, then reconnects. × 72 peers this is multi-GB (docs/p2p.md:1374 acknowledges the outboxes are outside the lane bound). Large blocks are cheap to create on a testnet with free coins; even 1 MB v1 blocks give ≈ 32 MB per peer. Bitcoin pauses processing a peer's requests while its send buffer is full; this node keeps serving until the queue overflows. | **Medium (P)**; OOM on 8 GB trial-class devices if reachable |
| **D4** | **Honest peers disconnect each other on a `GetTx` over 64 ids** (likely; no test). `on_inv_tx` requests every unknown id of an `InvTx` (≤ 500) in **one** `GetTx` (`relay.rs:130-172`); `on_get_tx` pushes one `Tx` per id into the 64-slot control outbox in a tight loop under the state lock (`relay.rs:201-204`); `try_send` failure disconnects the requester (`state.rs:478-490`). Announcements are chunked by 500 (`maintenance.rs:122`). Any burst of more than 64 new transactions (a reconnect, re-announcement, a spam test) can drop honest links. | **Medium** (T and P liveness of tx relay; a trial stress test would hit it) |
| **D5** | **Young-ring CLSAG spam on the actor, PoW-free.** An invalid signature is penalized only if every ring member is ≥ `SIGNATURE_BURIAL` = 60 blocks deep (`admission.rs:341`); otherwise it is contextual, unscored, and cached only in `ctx_rejects`, keyed by tx id and cleared at every tip change, so re-randomized bytes bypass it. Each peer may demand 50 CLSAG verifications/s (`inputs` bucket) on the **single actor thread** (Tx lane). ~72 peers × 50 × ≈ 3 ms ≈ 10 actor-s per second: the Tx lane saturates, honest relay is dropped (`tx_lane_drops`), blocks keep priority. | Medium (P): relay liveness and mempool privacy (honest txs stuck in stem); Low (T) |
| **D6** | **Read buffer allocated before the payload arrives.** After `Verack`, `recv_limited` allocates `len + 16` bytes as soon as the length decrypts (`transport.rs:287`); the only bound on trickling is the 180 s idle timeout per `recv` (`conn.rs:46, 404`), so ≈ 53 KB/s holds 9.5 MB per registered connection (≈ 600 MB across 64 inbound). | Low–Medium (P) |
| D7 | Upload amplification: `GetHeaders` (≈ 2 KB) returns ≤ 200 KB; at 50 msgs/s ≈ 10 MB/s of upload per peer, no upload budget; `GetBlocks` clones and encodes ≤ 16 blocks inside one actor Query command. | Low–Medium (P) |
| D8 | Unbounded maps keyed by attacker data: `CachedPow::known` (every computed hash, including junk ones, never evicted, `pow_cache.rs:32-63`); `BanList` (§2.1 E11); stempool count; `ChainManager::invalid` and stored side headers (need PoW). | Low |
| D9 | Low-work header floods on a fresh node (R1 B4): no `MIN_CHAIN_WORK`/presync (p2p.md §12, decided P1 for a public testnet, decision "Agent 31"). | Medium (P) |
| D10 | `missing_bodies` walks every heavier non-main leaf back to a complete block on every summary publish (`header_sync.rs:63-101`, `summary.rs:233`); with a large header/body gap and many side leaves (1 PoW block each) this is O(gap × leaves) per actor command [unverified magnitude]. | Low (needs a measurement) |
| D11 | Block and tx decoding (≤ 9.45 MB / 4.46 MB) on tokio workers, not `spawn_blocking`; only PX proofs are offloaded. | Low |
| D12 | Invalid-body storage amplifier (§3.2 S2). | Medium (P) |

**What a PoW-free attacker can no longer do** (closed since round 1 or never possible):
pre-`Verack` memory or slot holding (4 KiB frames, 20 s deadline, handshake caps that
never evict registered peers); forcing RandomX cache builds (keys only from stored
headers); writing anything to `blocks.dat` (only the true body of a PoW-gated header can be
stored); PX decode amplification (W4-PXDOS); getting honest relayers banned by an
invalid-body block (body sender only) or by decryption failures; banning honest stem
forwarders by rate (RTW2A-4).

### 2.3 Stalling and sync attacks

**In place:** header sync by work and tip id (W4-SYNC, RT-SYNC fixes F-A to F-C:
announcements event-driven, a best-chain epoch for stale known-work) [test: the W4-SYNC
failing-first tests; run D pins "the W4-SYNC rules"]; stale-tip rotation by validated
deliveries (RTW3-4); invalid-body relays penalize only the body's sender, header relayers
of its descendants get the unscored `InvalidParent` and are not asked again until they
announce a new tip (p2p.md §10) [test
`relaying_headers_of_a_block_with_an_invalid_body_is_not_penalized`, de-flaked by INV-PEN];
fair per-candidate `missing_bodies` (F-1: the bodies of a withheld best branch and a
competing heavier branch interleave by height, `SUMMARY_MISSING_BODIES` = 256);
UnknownUpgrade disconnect after 3 without a ban (RT-1).

**Residual:**
- SY1 = D2 (no staller detection; withholding peers never lose candidacy and block their
  own rotation). **High (P).**
- SY2 = E8: no "insufficient chain work" outbound eviction; a set of outbound peers that
  keeps delivering valid tips of a lower-work view is never rotated. Medium (P).
- SY3 = D9: no presync / `MIN_CHAIN_WORK`. Medium (P), decided P1.
- SY4 Head-of-line blocking in the single header worker (R8-15), made exploitable by D1.
  Medium (P).
- SY5 Block-download timeout fixed at 60 s regardless of size (R8-9, documented). Low.
- SY6 Header-first relay is not implemented; per-hop cost ≈ 0.6 s (RT-LAB F2); no
  multi-hop measurement. Low (performance; stale-rate fairness).

### 2.4 The transport (KDF, PSK, key exchange, pre-Verack input)

**Assets:** A3 (stem origins), A2, A1.

**Mitigations [src `p2p/src/transport.rs`, `p2p/src/net/conn.rs`]:**
- Ephemeral Ristretto255 ECDH; `k = H64("p2p/session", LE32 nid ‖ genesis_id ‖ LE32
  TRANSPORT_VERSION ‖ psk_flag ‖ psk ‖ A ‖ B ‖ S)` (`session_key` :194-219); AES-256-GCM per
  direction with a counter nonce, length and payload as separate AEAD messages
  (`FrameWriter::send` :243). Identity and non-canonical keys refused (:415-429); a zero
  shared secret refused. Ephemeral secret, shared point and key are `Zeroizing`.
- Transport version and genesis id are bound in the KDF (dossier 30 W5, R15-3):
  [test `mismatching_transport_versions_derive_different_keys_and_fail`,
  `different_genesis_ids_cannot_talk`], plus an independent KDF known answer
  (`the_session_key_matches_its_known_answer`, Python blake2b).
- Optional network PSK (F48-1): `NetworkPsk` from a 64-hex file, all-zero refused, file
  read capped at 4 KiB, wiped buffers, Unix mode warning (RTW3-12) [test
  `a_psk_session_talks_and_a_missing_or_wrong_psk_fails`; `p2p/tests/transport_adversarial.rs`
  `a_man_in_the_middle_reads_the_traffic_unless_a_psk_is_set`,
  `only_nodes_with_the_network_psk_connect_and_others_are_not_banned`].
- Pre-Verack: key exchange 5 s clearnet / 10 s Tor; one 20 s deadline for the whole
  handshake; every frame ≤ `MAX_HANDSHAKE_FRAME = 4096` refused after its length decrypts
  and before allocation (`recv_limited` :276-295); only `Version`, ≤ 8 unknown frames, then
  `Verack`; any failure closes unscored (`conn.rs:58-75, 180-237`). Decryption failures are
  counted (`transport_failures`) and never scored, before and after `Verack`
  (`conn.rs:66-67, 411-412`), closing R1's "flip one bit to get both ends banned".
- Fuzz: `transport_recv`, `transport_handshake`, stateful `peer_protocol` ([evid]
  fuzz-w4 and fuzz-stateful READMEs: 0 findings; `transport_recv` was still finding new
  units at 99 % of its 30 min, i.e. not saturated).

**Residual:**

| # | Issue | Severity |
|---|---|---|
| T1 | **No peer authentication without a PSK** (documented, p2p.md §1). An on-path attacker terminating both legs reads every `StemTx` the victim originates (deterministic origin) and can forge well-formed invalid messages under a peer's address, getting that peer's IP banned for 24 h (`docs/testnet.md` §11). | High (P, privacy-critical); closed for (T) **only if** the trial actually uses the PSK (T2) |
| T2 | **The trial procedure never tells operators to use the PSK.** The flag is documented in the config table (`docs/testnet.md:260`), but §12.3 "Network configuration", the v3 genesis steps and the launch checklist do not require it, say how to generate it (`openssl rand -hex 32` appears only in a code comment) or how to distribute it (the E2E operators' channel of incident-response §1a). Decision "Agent 48" made the PSK **P0 for the trial**. | **Medium (T), P0 docs** |
| T3 | Distinguishable handshake: 32 bytes each way, responder answers any 32-byte valid encoding, Ristretto encodings are not uniform; frames have a fixed 20-byte length prefix. Active probing and DPI can identify BlackSilk; transport v2 (Elligator, garbage) is design notes only (`docs/p2p.md` §3.1). | Low (censorship resistance is not a v3 goal, decision "Agent 30") |
| T4 | No rekeying and no PQ step (documented p2p.md §12). AES-GCM with 2^64 nonces per direction and per-connection keys is far from its data limits for realistic connection lifetimes [inf]; harvest-now-decrypt-later exposes stem origins recorded today. | Low (now); Medium for mainnet (privacy) |
| T5 | A responder sends its `Version` (height, best header, tip, optional listen address) to any peer that completes the ECDH, before learning anything about it (`conn.rs:171-188`). Without a PSK, a scanner learns the chain view and an advertised address. | Low |
| T6 | `STATUS.md` still lists "Transport hardening (30: pre-Verack cap, transport version in the KDF): Not implemented" although both are in the code (`conn.rs:44-56`, `transport.rs:40, 206-218`). | Low (docs; see F-OPS-9) |

### 2.5 Time and clock

**Mitigations [src]:** FTL 360 s on every network (`consensus/src/params.rs:117`);
`HeaderError::TimestampTooFarInFuture` is non-permanent and never penalized
(`consensus/src/chain.rs:68-79`, `p2p/src/net/headers.rs:300-310, 835`); the node never
takes time from peers and `Version` carries no clock; the start-up check refuses a clock
before genesis or unreadable and warns when the stored tip is beyond the FTL
(`node/src/lib.rs:318`, called at `node/src/main.rs:302-315`, exit 2) [test
`the_start_up_clock_check`]; the clock monitor estimates the offset from PoW-verified live
headers and retro-confirmed FTL refusals, warn-only (`p2p/src/clock.rs`: ≥ 5 samples from
≥ 3 peers; WARN > FTL/3, ERROR > FTL); operator guidance for NTP, Windows W32Time poll
interval and Secure Time Seeding (`docs/testnet.md` §12.2).

**Residual:**
- C1 Time dilation of an eclipsed node (it can only delay, not forge, samples) — inherits
  §2.1's residual; the monitor names delay as a cause. Low.
- C2 Clock jump on the majority-hash device (dossier 04 P4): documented, not prevented.
  Medium (T: 7 devices, one may hold most hash rate); mitigated by the operator checklist.
- C3 Miner clock safety (refuse to mine on skew > FTL/2, `--allow-clock-skew`, decision
  "Agent 04") is not implemented [src: no such flag in `miner/` or `node/`], and the monitor
  has no `/info` field or test on an injectable clock (STATUS §3 row "Clock sanity
  monitor"). Low–Medium (T).
- C4 The WARN thresholds rely on operators reading logs; there is no alerting
  (incident-response §1b). Low.

---

## 3. Operational adversaries and failures

### 3.1 The RPC

**Mitigations [src `node/src/{serve,guard,cookie}.rs`]:**
- Loopback bind by default (`config.rs:270-272`); a non-loopback bind logs a WARN
  (`main.rs:336-342`); the RPC is never served without the cookie (`serve::run` :146-176).
- Cookie: 32 bytes from the OS RNG, hex, written `create_new` to a temporary file with
  mode 0600 on Unix, `sync_all`, renamed; removed on clean shutdown; never logged (`Token`
  Debug is redacted) [test `a_cookie_is_fresh_private_and_removed`,
  `node_binary::a_restart_after_a_crash_replaces_the_cookie`]. Windows relies on the
  profile ACL, with a warning outside `%USERPROFILE%` (accepted limitation, decision
  "Agent 36").
- Guard order: exactly one `Host`, which must be loopback, the exact non-loopback bound IP
  or an allowed name (DNS rebinding); any `Origin`/`Sec-Fetch-*` refused (browsers);
  exactly one `Bearer` compared with `subtle` (length public), 250 ms delay on failure;
  POST must be JSON, no body elsewhere; per-class slots (reads 4, bulk 2, submits 2,
  blocks 1, long polls 16) taken **before** the body is read, body read with a route
  limit and a 60 s deadline (`guard.rs:280-373`) [test
  `hosts_are_loopback_the_bound_address_or_allowed_names` with 19 refused forms].
- Connection layer: 64 sockets, 10 s header-read timeout (also the idle keep-alive
  timeout), 16 KiB head (`serve.rs:42-53`). Per-request result bounds: `/headers` ≤ 2,000,
  `/blocks` ≤ 100.
- Evidence: [evid] `rpc-security-2026-09-27/after-suite.log`, `rpc-wire-2026-09-27`.

**Residual:**

| # | Issue | Severity |
|---|---|---|
| R1 | **Pre-authentication slot exhaustion.** The 64-socket cap is shared by everyone and checked before any authentication; a client that opens sockets and sends nothing holds each for 10 s, and failed authentications also wait 250 ms while holding the socket. Any local user (on a multi-user host) or anyone who can reach a non-loopback bind can keep the miner and wallet out of the RPC indefinitely. Not a confidentiality problem. | Low (T, loopback, single-user desktops); Medium on shared hosts or non-loopback binds |
| R2 | Plaintext HTTP on non-loopback binds exposes the cookie; mitigated only by a WARN and docs (SSH/VPN/Tor). | Low (documented) |
| R3 | Windows cookie protection is the directory ACL only (accepted, decision "Agent 36"). Same-user malware reads it on every OS (documented, `cookie.rs:18-19`). | Accepted |
| R4 | No restricted/public RPC mode (P3, decision "Agent 36"); `/block` and `/tx` with the cookie are full chain access by design. | Accepted |
| R5 | No runtime invalidate/reconsider RPC (STATUS row "Operator block invalidation": open). This is **good** for the threat model (an RPC thief cannot invalidate), but it means operator recovery requires a restart (§3.4). | Info |

### 3.2 The data directory and the store

**Mitigations [src, inventory (c), spot-checked]:**
- `blocks.dat` format 2: 48-byte header binding magic, version, network id, genesis id and
  a CRC; records `"BSR2" ‖ len ‖ crc32(len ‖ body) ‖ body`; types 0x01 block, 0x02 invalid
  (origin 1 verdict / 2 operator), 0x03 reconsider, 0x81 checkpoint (advisory), 0x82
  quarantine **reserved** (`chain/src/store.rs:3-94`). Legacy and foreign stores refused
  (F35-1) (`FileStore::bind` :715-798).
- Every append is `write_all` + `sync_data`; a failed append is undone with `set_len`;
  an undo failure poisons the store until restart (`store.rs:594-637`). A torn tail is
  truncated at load; damage followed by valid data refuses to start and points to
  `--repair-store`, which moves the damaged region aside (`create_new` + `sync_all`) and
  re-appends intact operator records (RTW3-7) (`store.rs:510-591`).
- Disk full on `blocks.dat`: after 3 consecutive failures (`STORE_FAILURE_LIMIT`) or one
  failed undo, the manager refuses every block before any state change and the node exits
  1 within 2 s (`submission.rs:82-150`, `watch_store`).
- Tests (all fault-injected, no real kill -9 or power loss):
  `a_crash_at_every_byte_keeps_every_complete_record`,
  `a_write_failing_at_every_byte_loses_no_earlier_record`,
  `every_single_bit_flip_is_refused_or_cut_to_an_exact_prefix`,
  `chain/tests/storage_recovery.rs::a_full_disk_fails_the_store_without_changing_state`,
  `store_format.rs::a_crash_at_every_write_boundary_loses_no_confirmed_block`,
  `replay_reaches_the_state_of_a_fresh_sync`; fuzz `store_records` (0 findings, still
  finding units at 100 % of 30 min).

**Residual:**

| # | Issue | Severity |
|---|---|---|
| S1 | **Crash loop on a deterministic panic (R1 F48-5) is still open.** The quarantine marker (0x82) is reserved only; nothing writes or reads it. A panic in the chain actor exits 70 (`actor.rs:611-619`), a panic during replay on the main thread exits 101 [inf: Rust default; no panic hook is installed]. The systemd unit prevents restarts only for 2 and 65 (`deploy/systemd/blacksilk-node.service`), so 70 and 101 restart every 10 s forever, each restart replaying the whole chain (every PX proof re-verified). With `RestartSec=10` the default `StartLimitBurst=5` per 10 s never trips [inf]. | **Medium** (liveness of every node, persistent); decided P1 (35 S5) |
| S2 | **Store-before-validate keeps invalid bodies forever, in RAM and on disk.** A block whose header passes PoW, the operator refusal and the low-work keep policy is appended before body validation (`submission.rs:75-168`); verdict markers (origin 1) are never written (`append_marker` has only operator callers), so the invalid body is re-validated at every start; bodies and undo data are held in memory (accepted limitation PX-F1/F2, STATUS §6). Each such block costs the attacker one header of real PoW near the tip, up to `MAX_BLOCK_BYTES` ≈ 9.45 MB (`chain/src/block.rs:10`). Under K1 (rented `rx/0` hash rate exceeds the testnet's), this is a cheap, permanent memory and disk amplifier, and it makes start-up time grow. | Medium (P); Low (T) |
| S3 | **Stored PoW hashes are trusted at replay.** `replay_one` preloads the stored `pow_hash` without recomputation (`replay.rs:313-319`); the decided "48 sampled PoW checks at start-up, `--verify-store-pow`, `--verify-store`" (decisions "Agent 01", "Agent 35") are not implemented. Anyone who can write the data directory (a backup restored from an untrusted source, a shared copy of a synced data dir to speed up a trial device) can plant a CRC-valid chain of headers with fake PoW. | Medium (T: trial operators may copy data dirs between devices); the decided fix is cheap |
| S4 | No fsync on `peers.json`, `bans.json`, `anchors.json` (write tmp + rename only) and never on the parent directory (inventory c). Power loss can leave an empty file: a fresh address table (re-randomized key) and **bans lifted**. | Low |
| S5 | Data directory created with the process umask (`main.rs:218`). Under systemd `UMask=0077` gives 0700/0600; a manual Linux/macOS run with umask 022 leaves `blocks.dat`, `peers.json` (with the bucketing key), `anchors.json` and **`originated.json`** world-readable. | Medium (privacy, see L1) |
| S6 | `peers.json` and `bans.json` are read whole with no size bound (`fs::read`). Only a data-dir writer can exploit it. | Info |

### 3.3 systemd, Docker and deploy scripts

**Mitigations [src `deploy/`]:** the node unit runs as `blacksilk` with `NoNewPrivileges`,
`ProtectSystem=strict`, `ProtectHome`, `PrivateTmp/Devices`, kernel/clock/hostname
protections, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `MemoryDenyWriteExecute`,
`SystemCallFilter=@system-service`, empty capability sets, `UMask=0077`,
`KillSignal=SIGINT`, `TimeoutStopSec=60`, `RestartPreventExitStatus=2 65`. The miner unit
is similar with `RestartPreventExitStatus=78`. `install-linux.sh` builds as the invoking
user with `tools/release-build.sh` and runs `check-build-flags.sh --strings` as that user
(RT-GUARD), installs root-owned binaries, data dir 0750. Docker runs as a system user
with RPC on in-container loopback.

**Residual:**

| # | Issue | Severity |
|---|---|---|
| D1 | Exit 70 (fail-stop) and 101 (panic) are not in `RestartPreventExitStatus`, and no `StartLimitIntervalSec`/`StartLimitBurst` is set: see S1. A transient 70 (a poisoned lock from a one-off bug) deserves a restart, a repeated one does not. | Medium (with S1) |
| D2 | `install-linux.sh` builds whatever the checkout holds: no `git verify-tag`/`verify-commit`, no comparison of the binary hash with an announcement. | Medium (T): it is the trial operators' install path once tags exist |
| D3 | The Dockerfile does not use `tools/release-build.sh` (no path remap; `/src` and `/usr/local/cargo` are embedded, harmless but not the reproducible recipe), does not run `check-build-flags.sh`, pins base images by tag not digest (`rust:1.98.1-bookworm`, `debian:bookworm-slim`), and has no `STOPSIGNAL SIGINT` (E9). Without `.git`, there is no dirty check and the commit is whatever `BLACKSILK_BUILD_COMMIT` says. (`docs/testnet.md` §2.1 also says the Dockerfile does not forward the variable; it now does: stale text.) | Low (Docker is not the trial path) |
| D4 | `/etc/blacksilk/miner.env` is installed 0644 with the payout address: any local user links the machine to the address. | Low (privacy) |
| D5 | The miner unit lacks `ProtectKernelLogs`, `ProtectClock`, `SystemCallFilter` that the node unit has. | Info |

### 3.4 Operator invalidation and reconsider

**Mitigations [src]:** CLI only (`--invalidate-block`, `--reconsider-block`, 64 hex,
`main.rs:142-208`), appended to the store before the chain loads, so a block that halts the
node is never re-validated; persistent; kept by repair; refused at header time after PoW
(S5b, `submission.rs:241-255`), returning the unpenalized `InvalidParent`; a 10 s WARN
while a heavier chain is refused only by an operator verdict and template refusal unless
`--mine-despite-operator-fork` (`node/src/lib.rs:226-262, 573-601`) [tests
`chain/tests/operator_invalidation.rs`, `rt_w3_regressions.rs`].

**Residual:**
- O1 Social engineering (R1 G3/F48-9): "run with `--invalidate-block <id>`" from a chat is a
  one-line partition of a victim from the honest chain. The node warns loudly, but `/info`
  does not expose active verdicts or overrides (`--mine-despite-operator-fork`,
  `--mine-from-stale-tip`, `--repair-store`), so `check-node.sh` and the identity check
  cannot catch it (the `Info` struct in `rpc/src/lib.rs:69-127` has no such field). Medium
  (T), Low (P).
- O2 The trust model of S5 has not had its red-team pass (STATUS row; decisions "W3-35b").
  Low.
- O3 Without the F48-5 quarantine, operator invalidation is the only crash-loop escape and
  requires the operator to read the full block id from the halt message — which exists
  for apply failures (exit 65) but not for panics (exit 70/101). Covered by S1.

### 3.5 Logs and data at rest (privacy)

| # | Issue | Severity |
|---|---|---|
| L1 | **`originated.json` is a plaintext list of the transactions this node originated** (hex ids and relay heights, up to 10,000 entries, ~3 days each; `p2p/src/originated.rs:1-30, 64-68`). It exists for a privacy reason (no re-origination, F33-1), but anyone who reads the data directory gets deterministic origin attribution: a stolen or seized device, malware, a synced backup folder, another local user under S5's umask, and **the incident procedure itself**, which asks operators to send "the node's data directory" to the owner (`docs/testnet-incident-response.md` §5), who is also the trial's supply auditor. | **Medium** (privacy-first project; T) |
| L2 | At `debug`, stem logs name local transactions (`stem.rs:70, 107`: "local tx … held", "held local tx … -> stem peer"); W4 evidence runs use `RUST_LOG=info,blacksilk_p2p::net=debug`, and incident-response §5 asks for logs "at their original level". At `info`, `/block` RPC acceptance logs identify locally mined blocks (`node/src/lib.rs:816`). | Low–Medium (T) |
| L3 | Peer IPs at `info` on every connect/disconnect/ban (`conn.rs:366, 519`, `peers.rs:56`); documented ("treat logs as private"). | Low (documented) |
| L4 | **No log rate limiting (R1 F48-8 open).** Per-connection INFO lines are unthrottled; with a PSK, outsiders never reach registration, so (T) is bounded; on (P), inbound churn from many IPs grows journald/Docker logs without bound (no rotation in `deploy/`). | Low (T), Medium (P) |
| L5 | `peers.json` holds the addrman key: a reader learns bucket placement and can target buckets. | Low |

---

## 4. Supply chain, build, CI, release and genesis

### 4.1 Dependencies

**In place [src]:** `deny.toml` (advisories incl. unmaintained/unsound/yanked, crates.io
only, exact licence set, `multiple-versions = "deny"` incl. dev, an explicit ban list of
C/C++/FFI crates, `curve25519-dalek >= 5` banned until transport v2, build-script allowlist
by exact version per decisions "W3-44"); `sys-crates.sh` (no `-sys` or C per release
target); `hazmat-policy.sh`; `lockfile-gate.sh` (a Cargo.lock change names its crates);
`--locked` everywhere; `cargo audit` and `cargo deny` weekly; unsafe inventory as a
warning. Patched Plonky3 (`third_party/p3-{dft,fri,merkle-tree}`) with a written diff
rationale and patches under `third_party/upstream/`.

**Residual:**
- SC1 Build-time code execution (R1 F48-4: ~54 build scripts, 16 proc macros) on the
  owner's workstation, which also runs the agent swarm and holds push credentials. The
  allowlist constrains *which* versions run, not *what they do*. `cargo vet` not adopted
  (S9, P2). Medium (process).
- SC2 No CI check that `third_party/` equals upstream 0.7.0 plus the recorded patches
  (dossier 24 I6, P1 open). A tampered vendored file is visible only in review; the
  consensus-path gate covers `third_party/*` but is self-attested. Low–Medium.
- SC3 `RUSTSEC-2024-0436` (paste, unmaintained, compile-time) ignored with a reason. Info.

### 4.2 Build and reproducibility

**In place:** `tools/release-build.sh` (path remap of CARGO_HOME, sysroot, checkout;
`-Brepro` on MSVC), dirty-tree refusal in `node/build.rs` (RTFP3-9), test-hooks guard
(W4-GUARD: markers, refusal off regtest, `--require-clean-build`, CI `build-guard` job,
`check-test-features.sh`). [evid] `repro-windows-2026-10-01`: two builds on one machine
are byte-identical.

**Residual:**
- B1 Cross-machine and Linux reproducibility of the node binary not shown (STATUS row,
  "Partially implemented"). The operator binary-hash check of `docs/testnet.md` §2.1 is
  therefore only a same-machine check; across devices operators fall back to
  fingerprints, which "identify rules, not code". Medium (T): it is the only code-identity
  check the trial has.
- B2 Dirty check misses untracked and staged-only files; miner and wallet have no build
  script and report `unknown` unless `BLACKSILK_BUILD_COMMIT` is set; a non-empty
  `BLACKSILK_BUILD_COMMIT` always wins (self-reported). Low.
- B3 No RandomX start-up self-test (decision "Agent 08": stop on failure,
  `--skip-randomx-self-test`) [src: no such code]. A miscompiled or platform-divergent
  RandomX build would only show as a fork. Low–Medium (T: Windows devices, one toolchain;
  aarch64 excluded).

### 4.3 CI

**In place [src `.github/workflows/ci.yml`]:** top-level `permissions: contents: read`;
every checkout `persist-credentials: false`; actions pinned by full SHA (checkout v5.1.0,
dtolnay/rust-toolchain master SHA); toolchain 1.98.1 pinned; no secrets used; no
`pull_request_target`; no caches (no cache poisoning); `cargo install --locked` with
pinned versions for cargo-audit/deny; concurrency never cancels `main`, `rebuild/core` or
tags; gates job (consensus trailer, lockfile, Unicode, test-feature markers) over every
commit after the cut-over `55f110e` (`gate-range.sh`), robust to force pushes and zero
SHAs; guests reproduced on three OSes.

**Residual:**
- CI1 **The gates are advisory**: without branch protection, a direct push lands first and
  turns CI red afterwards; the trailer is self-attested. Known OWNER task. Medium.
- CI2 `dtolnay/rust-toolchain` pinned to a `master` commit (fine), but toolchain bytes
  come from `static.rust-lang.org` per run; the guests job checks `toolchain.sha256`, the
  others do not. Low.
- CI3 No release job: no build provenance, SBOM, attestation or signed artifacts. Known
  (release process). Low now; P1 before a public testnet.
- CI4 Default branch is still `main` (owner task), so scheduled jobs (`audit`, `deny`,
  `randomx-full` weekly) do not run on `rebuild/core` unless dispatched manually
  (decision "Agent 43"). Low–Medium: new advisories go unnoticed between pushes.

### 4.4 Release and signing

**What exists:** the identity check (fingerprints, genesis id, commit, build flags, binary
hash), `--print-manifest`, the emergency-release procedure (incident-response §4.11: "Tag
the commit", tell operators over the private channel).

**What is missing (all known owner tasks; their consequences in this threat model):**
- RS1 **No signing key, no tags, unsigned commits** (`git tag` empty; last 20 commits `N`).
  Decision "Agent 43": "Trial operators build from the signed tag" — impossible today.
  Every trial instruction ("upgrade to tag X", "restart with `--invalidate-block`") is
  authenticated only by the chat channel. **High (T) — blocks launch.**
- RS2 **No second fingerprint channel.** The release announcement (fingerprints, binary
  hash, genesis id) is the reference every device compares against; one channel means one
  compromise point. **High (T) — blocks launch.**
- RS3 No branch protection, no CODEOWNERS (R1 F48-3, owner task). Medium.
- RS4 The private-vulnerability-reporting setting is disabled (SECURITY.md, checked
  2026-09-27); the operators' E2E channel and backup channel are undecided (incident
  response §1a); the incident plan is not rehearsed (§8, G14). Medium (T).

### 4.5 The genesis ceremony

**In place [doc/src]:** beacon-derived nonce in consensus (`consensus/src/genesis.rs`);
`T_g` fixed before the beacon; reserved ids and `--final`/`--rehearsal` (RTFP3-13/14); two
people compute independently from a guarded release build and compare the full id;
aborted launches retire the id (decision "Agent 40").

**Residual:**
- G1 D0 not measured on reference hardware (genesis gate F40-12; STATUS "Not
  implemented"). **P0** (already a decided gate).
- G2 The step-5 commit with the final values is unsigned (RS1) and its announcement single
  channel (RS2): an attacker who controls the announcement can hand operators another
  genesis. Mitigated by every operator recomputing the genesis from the public beacon and
  the stage-1 announcement; the doc says two people compare, it should say **every
  operator** recomputes (the tool is public and cheap). Medium (T).
- G3 The second computer "must be an operator's machine" (owner task) — and cross-machine
  binary reproducibility is not shown (B1), so the two computations agree on the id but
  the doc correctly treats a binary-hash difference as non-fatal. Low.
- G4 PSK generation and distribution are not part of the ceremony (T2). Medium (T).
- G5 Between `H+6` and the operators' start, whoever starts first mines alone (by design,
  ≤ 1 h target). Accepted.

---

## 5. Re-check of round-1 network and operations findings

| R1 item | Round-1 claim | Status at `3c21afe` | Evidence |
|---|---|---|---|
| **F48-1** MITM of the explicit-peer mesh; PSK | Medium (T) | **Partially closed.** The PSK exists, is bound into the KDF, and failures are unscored; the AT-1 test exists. Open: the trial procedure does not require it (T2), and without it T1 stands. | `transport.rs:68-219`; `p2p/tests/transport_adversarial.rs` AT-1; `docs/testnet.md:260` only |
| B2 (tree) bit-flip → mutual 24 h bans | — | **Closed** for decryption failures (never scored, before and after `Verack`) | `conn.rs:66-67, 411-412`; p2p.md §10 |
| **F48-3** pipeline / consensus gates | High | **Partially closed.** Trailer gate, Unicode scan, lockfile gate, test-feature gate live in CI; untrusted-input rule in impl-brief. Open: CODEOWNERS, branch protection, signed commits (owner); gates advisory (CI1). | `ci.yml` gates job; `gate-range.sh` |
| **F48-4** build-time execution and credential co-location | Medium | **Open** (owner: key placement; `cargo vet` P2). Build-script allowlist narrows versions only. | `deny.toml` `[bans.build]` |
| **F48-5** panic-to-global-halt | Medium | **Partially closed.** Apply failures halt with 65 and are restart-prevented; the tree-capacity rule moved into validation (STATUS §2). Open: quarantine marker reserved only; exit 70/101 crash loop (S1, D1); AT-3/AT-4 not found [src grep]. | `store.rs:29-33`; `actor.rs:611-619`; systemd unit |
| **F48-7** Windows endpoint leakage | Low–Medium | Out of my lens except logs: L1/L2 add two new data-at-rest channels. | — |
| **F48-8** log fill | Low | **Open** (no limiter, no rotation). | grep: no rate-limited logging |
| **F48-9** override flags visible | Low | **Open.** No override or operator verdict in `/info`; `--skip-randomx-self-test` and `--allow-clock-skew` do not exist at all (their features are missing, B3, C3). | `rpc/src/lib.rs:69-127` |
| B1 (tree) addrman poisoning / eclipse (P) | 16 (rank) | **Partially closed.** addrman v2, anchors, feelers, block-relay-only, eviction, onion caps, seeds as fetches are implemented; the simulator bounds slot share; open: E1–E8, no live test. | §2.1 |
| B3 chain-lock convoy | 12 | **Largely closed** by the chain actor (stages 1–2): lanes, starvation limit, PoW off-lock; open: stages 3–4 (verification in the writer) | §2.2; STATUS §3 |
| B4 low-work header floods | 8 | **Partially closed** (work gate; no MIN_CHAIN_WORK/presync) | §2.2 |
| B5 pre-Verack frames, outbox, OOM | 12 | **Closed** for pre-Verack (4 KiB frames, 20 s deadline, ≤ 8 unknown frames, handshake caps); outboxes bounded (64 control, 2× blocks per request) | `conn.rs:44-56, 247-248`; `peers.rs:109` |
| B6 log disk fill | 6 | **Open** = F48-8 | L4 |
| E (tree) RPC DNS rebinding, cross-site GET, slowloris | 12 | **Closed** for rebinding and browser requests (Host allowlist, `Origin`/`Sec-Fetch` refusal, cookie); slowloris bounded by 10 s head timeout and 64 sockets; residual R1 (pre-auth slot exhaustion) | `guard.rs`, `serve.rs` |
| F1 build-time crate compromise | 10 | Open (= F48-4) | SC1 |
| F2 compromised Action | 4 | **Closed as far as CI can be**: SHA pins, read-only token, no secrets, no credentials persisted | `ci.yml` |
| F3 ELF swap with id pin | 5 | **Closed** (guests reproduced byte-identically on 3 OSes, CI run 102) | decisions "CI-1 CLOSED" |
| G2 single maintainer, unsigned, no tags, no CODEOWNERS | 10 | **Open** (owner tasks) | RS1–RS3 |
| G3 social engineering of operators | 9 | **Open**, worse than R1 assumed: operator invalidation now exists as a lever and is invisible in `/info` (O1) | §3.4 |
| H4 clock jump on the majority device | 9 | Documented, not prevented; start-up check added; miner skew refusal missing (C3) | §2.5 |
| A10 timestamp/clock | 4 | Closed as far as designed (FTL non-permanent, unscored) | §2.5 |

---

## 6. New findings of this round (summary)

| ID | Title | Severity | Status | Location |
|---|---|---|---|---|
| **TM2-1** | No signing key, no tags, no second fingerprint channel: the trial cannot follow its own "build from the signed tag" rule; every operational instruction is authenticated by chat only | **High (T)** | Not implemented (owner) | `git tag` empty; decisions "Agent 43" |
| **TM2-2** | The trial procedure does not require or distribute the network PSK (decided P0); without it an on-path attacker reads stem origins and can get honest peers banned | **Medium (T)** | Docs not implemented | `docs/testnet.md` §12.3, v3 genesis §6 |
| **TM2-3** | `originated.json` is a plaintext origin list; the incident procedure ships it, and debug logs, to the owner; manual runs leave the data dir world-readable | **Medium** (privacy) | Not implemented | `p2p/src/originated.rs`; incident-response §5; `node/src/main.rs:218` |
| **TM2-4** | Crash loop on exit 70/101: F48-5 quarantine unimplemented and systemd restarts these codes forever with full replays | **Medium** | Partially implemented | `store.rs:29-33`; `blacksilk-node.service` |
| **TM2-5** | Stored PoW hashes trusted at replay; decided sampling and `--verify-store(-pow)` missing; trial operators copying data dirs is a realistic path | **Medium (T)** | Not implemented | `replay.rs:313-319` |
| **TM2-6** | Invalid and side-branch bodies stored before validation are kept forever in RAM and on disk and re-validated each start (memory/disk amplifier under K1) | **Medium (P)** / Low (T) | Partially implemented | `submission.rs:75-168` |
| **TM2-7** | Operator verdicts and overrides are invisible in `/info`; `--invalidate-block` from chat is a one-line partition lever | Medium (T) | Not implemented | `rpc/src/lib.rs:69-127` |
| **TM2-8** | Anchors are never saved under Docker or SIGTERM (no SIGTERM handler, no `STOPSIGNAL`) | Low–Medium (P) | Not implemented | `main.rs:419`; Dockerfile |
| **TM2-9** | `install-linux.sh` builds the checkout without verifying a tag or the announced hash | Medium (T) once tags exist | Not implemented | `deploy/scripts/install-linux.sh` |
| **TM2-10** | RPC pre-auth socket exhaustion (64 shared sockets, 10 s idle, 250 ms auth delay held) | Low (T) | Accepted? not recorded | `serve.rs:42-88`, `guard.rs:308-320` |
| **TM2-11** | `STATUS.md` (the single status source) is stale in rows operators and reviewers rely on (transport hardening, clock check, address manager open items; p2p.md §12's eclipse list too) | Low (process), but it misleads launch decisions | Not implemented | `docs/STATUS.md` §3; `docs/p2p.md` §12 |
| **TM2-12** | No fsync on `peers.json`/`bans.json`/`anchors.json`; power loss lifts bans and re-keys the table | Low | Not implemented | `addrman.rs:917-935`, `connman.rs:350` |
| **TM2-13** | No live test of any eclipse/sybil/ban/netgroup mechanism; the labnet cannot exercise them | Medium (P) — evidence gap | Not implemented | §10 |

| **TM2-14 (D1)** | Junk-PoW header batches cost the node a whole first chunk (8–64 light RandomX hashes) per PoW-free identity; Tor/proxied identities are never banned | **High (P)** | Not implemented | `p2p/src/net/headers.rs:665-677`; `peers.rs:69-71` |
| **TM2-15 (D2)** | Staller detection decided ("Agent 31") but absent: withholding peers keep body candidacy forever and stall each request 60 s, at sync and at the tip | **High (P)** | Not implemented | `blocks.rs:238-272`; `maintenance.rs:154-191` |
| **TM2-16 (D3)** | Outboxes bounded in messages, not bytes: hundreds of MB per slow-reading peer | Medium (P) | Not implemented | `conn.rs:49-52`; `state.rs:478-490` |
| **TM2-17 (D4)** | A `GetTx` for more than 64 ids overflows the 64-slot outbox and disconnects an honest requester | Medium | Likely (no test) | `relay.rs:130-204` |
| **TM2-18 (D5)** | Young-ring invalid CLSAGs are unscored and bypass `ctx_rejects` by re-randomization: ~10 actor-s/s of verification from 72 peers | Medium (P) | Accepted design without a budget | `admission.rs:341`; `limits.rs` `inputs` |

(The lower-severity DoS items D6–D12 are in §2.2.)

---

## 7. Attacks the single-machine labnet cannot exercise

| Area | Why one machine cannot | Needed |
|---|---|---|
| Netgroup diversity, one-outbound-per-group, keyed-group eviction | all nodes are 127.0.0.1 with `allow_private`, which disables grouping | ≥ 20 nodes on distinct /16s |
| Per-IP and /64 limits, handshake caps per group, bans and their persistence, ban lifting at power loss | `allow_private` skips them; loopback is never banned | distinct IPs, real restarts |
| Eclipse by address poisoning, laundering, fresh-node capture, anchors from a poisoned session, stale-tip rotation against a hostile table | lab nodes are `connect_only`; tables ≤ 8 entries | attacker-controlled address sources at scale |
| Real latency heterogeneity (ping-protection), loss, bandwidth asymmetry, NAT, unreachable nodes | synthetic 20 ± 10 ms only | tc netem per link; NAT namespaces |
| On-path MITM with and without PSK at the network layer | AT-1 is in-process | a router namespace that terminates TCP |
| Tor/onion paths, `--onion-inbound`, SOCKS isolation | no Tor daemon | a private Tor network (chutney) |
| Bandwidth exhaustion, multi-peer flood interaction with the token buckets and the chain actor | one CPU shared by all nodes and the attacker | separate hosts or CPU-pinned namespaces |
| Multi-hop propagation and stale-rate at realistic topology | ring option exists, not run | ≥ 10-hop topologies |
| Disk-full, power loss, clock jumps on one node | the host is shared | per-node filesystems (loop devices), `faketime`/`clock_settime` in a namespace |

---

## 8. Proposed multi-machine / network-namespace tests (before a public testnet; the
trial-critical subset before the trial)

All of these run on Linux (GitHub `ubuntu-24.04` runners have passwordless sudo, so
`ip netns` works in CI) and drive the real release binaries, guarded by
`--require-clean-build`.

1. **NS-1 netns labnet harness (P1; the base for the rest).** A script that creates N
   namespaces joined by a bridge, assigns addresses from distinct /16s (and a few sharing
   one /16, and IPv6 /64s), applies `tc netem` delay/jitter/loss per link, and runs one node
   per namespace with `allow_private` OFF. Acceptance: the existing labnet scenarios pass
   with grouping on.
2. **NS-2 eclipse campaign (P1).** 30 honest + attacker namespaces holding many /16s:
   (a) fresh joiner with an attacker-supplied seed list (E1), (b) inbound self-ad flood
   from k /16s (E2), (c) laundering via honest relays (E3), (d) anchors after a poisoned
   session (E5), (e) a "progressing" lower-work eclipse (E8). Metric: attacker share of
   the victim's outbound slots over time, against `eclipse_sim` predictions; pass/fail
   thresholds set from the simulator.
3. **NS-3 MITM router (P0 for the trial if any device is on an untrusted network;
   otherwise P1).** A middle namespace that terminates TCP and runs the BlackSilk
   handshake toward both sides (reuse AT-1's relay). Assert: without PSK it reads
   `StemTx` and can get the impersonated peer banned; with PSK both ends see only
   `transport_failures`, no bans, no decoded message.
4. **NS-4 ban and limit semantics (P1).** Per-IP, per-/64 and handshake-per-group caps;
   ban persistence across restart; a ban of one IP behind a NAT namespace; manual peers
   redialed despite bans (confirm intent).
5. **NS-5 flood and starvation (P1).** One namespace floods (connection churn, `Addr`,
   `InvTx`, max frames, low-work headers, invalid PX at the PX share rate) while an honest
   miner extends the chain; measure tip lag, ping RTT, CPU and RSS of the victim; assert
   bounds derived from §2.2's constants and no honest-peer penalty.
6. **NS-6 disk-full and power loss (P1).** Node data dir on a small loop filesystem; fill
   it; assert exit 1 within 2 s and no state change; `kill -9` at random points and
   `echo b > /proc/sysrq-trigger`-equivalent VM resets (or `dm-flakey`) to check
   `peers.json`/`bans.json` survival (TM2-12).
7. **NS-7 clock (P1).** One namespace's node and miner under `faketime` at ±(FTL/3, FTL,
   2·FTL): assert monitor WARN/ERROR, FTL refusals unscored, recovery after correction;
   the majority-hash device scenario (C2).
8. **NS-8 Tor (P2).** chutney private Tor network; onion-only nodes; `--onion-inbound` cap;
   onion sybil grinding (E4).
9. **NS-9 72-hour multi-machine run** (already required by `docs/testnet.md` §7 / G5):
   real devices, real NAT, including the supply audit.
10. **Large-scale (P2):** Shadow (the discrete-event network simulator that runs real Linux
    binaries) for 200–1,000-node eclipse and propagation studies, if the tokio runtime runs
    under it; otherwise the namespace harness on a large VM.

---

## 9. Process and documentation findings

- **F-OPS-9 (TM2-11).** STATUS.md says "as of `e986250`" and has stale rows (transport
  hardening, clock check called by the binary, address-manager "open" items such as
  block-relay-only and onion caps that have landed). p2p.md §12 still lists "no
  block-relay-only connections", "seeds are full outbound peers" and Tor inbound sharing
  per-IP limits, all changed by W3-32c (`ConnKind::BlockRelay`, `AddrFetch`,
  `OnionInbound`). doc-lint cannot catch semantic staleness. Fix: a STATUS refresh against
  the code before the freeze, plus a rule that a merge closing a STATUS row edits it
  (already the rule; not followed).
- `docs/testnet-launch-checklist.md` is a historical v2 snapshot; there is no current
  launch checklist other than STATUS, so the trial gates of this report have no home.
  Propose a v3 trial launch checklist (owner 40/47) that lists the P0 items of §11.

---

## 10. Severity reasoning for the top items

- **TM2-1 High (T):** the impact is total (operators run attacker code or join a fake
  genesis), the feasibility is social (a chat account takeover or an impersonation), and
  there is no technical control at all today. It is listed as an owner task in decisions,
  but its *consequence* — that the trial's identity check has no authenticated reference —
  is not stated anywhere as a launch blocker.
- **TM2-2 Medium (T):** cheap to fix, privacy-critical (stem origin), and the trial's
  premise ("eclipse unreachable in an explicit mesh") is false without it. Not High,
  because trial devices on home networks need an on-path attacker.
- **TM2-3 Medium:** deterministic origin attribution, the project's top asset, from a file
  that the project's own procedure asks operators to hand over.
- **TM2-4 Medium:** no trigger is known (fuzz and mutation found none), but the impact is
  every node, persistently; the fix is small (unit change today, quarantine P1).
- **TM2-14 / TM2-15 High (P):** both are PoW-free, need only ordinary connections, and
  hit liveness of every reachable node (CPU saturation and header delay; sync and tip
  stalls). They are not trial blockers only because the PSK keeps outsiders off the
  trial's ports; on a public testnet they are the cheapest attacks in this report.
- **TM2-5 Medium (T):** realistic in a trial (copying a synced data dir), the decided fix
  exists on paper, and its absence silently voids the PoW of everything replayed.

---

## 11. Ranked list

**P0 — blocks the genesis or the trial launch**

| # | Item | Concrete fix or measurement |
|---|---|---|
| P0-1 | TM2-1 signing and second channel | Owner creates an ed25519-sk (FIDO2) SSH signing key on a machine that never builds third-party crates (F48-4); publishes its public key in the repo and on a second channel; signs the release-candidate and final tags; the announcement (fingerprints, binary hashes, genesis inputs) is signed and posted on two channels; operators run `git verify-tag` before building. Acceptance: a rehearsal operator rejects a tag signed by another key. |
| P0-2 | TM2-2 PSK in the trial procedure | `docs/testnet.md` §12.3 and testnet-v3-genesis §6: the trial **requires** `network_psk_file`; generation (`openssl rand -hex 32` or the node's own generator), distribution only over the E2E operators' channel, mode 0600, rotation after any device loss; `check-node.sh` prints whether a PSK is loaded (`/info` field). Acceptance: NS-3 (or AT-1 re-run) on the release commit. |
| P0-3 | G1 D0 measured | Already a decided gate (F40-12): measure light/full hash rate of every trial device with the release build; record in evidence; compute D0 with the tool. |
| P0-4 | TM2-3 origin data at rest | (a) incident-response §5: never send `originated.json` or debug logs; send `blocks.dat` and info logs only, with stem lines scrubbed; (b) `create_dir_all` followed by a 0700 mode on Unix for the data dir, and 0600 for every file the node writes (cookie already); (c) store keyed hashes `H32(tag, node_secret ‖ txid)` in `originated.json` with the secret in a 0600 file, so a copied file alone (backups, evidence) reveals nothing; a test that the file contains no transaction id. |
| P0-5 | TM2-4 crash-loop containment (unit part) | Add `StartLimitIntervalSec=900`, `StartLimitBurst=3` to `[Unit]` of both services, so repeated 70/101 exits stop the node for the operator; keep 70 restartable once. Docs: the incident plan's S1 step for exit 70/101 (read the last "validating" log line, use `--invalidate-block`). The quarantine marker itself stays P1 (35 S5). |
| P0-6 | TM2-7 overrides and verdicts visible | `/info` gains `operator_verdicts` (ids) and `overrides` (`mine_despite_operator_fork`, `mine_from_stale_tip`, `repair_store`, PSK loaded yes/no); `check-node.sh` fails on any; incident plan: no flag or binary is accepted from chat without a signed tag. |
| P0-7 | TM2-5 replay PoW sampling | Implement the decided 48-sample PoW check at start-up (uniform over the stored main chain plus the last 48) and `--verify-store-pow`; docs: never copy a data directory between trial devices without `--verify-store-pow`. Test: a store with one forged `pow_hash` is refused when sampled, and always with the flag. |
| P0-8 | TM2-17 (D4) honest `GetTx` disconnects | It would disturb the trial's own transaction-relay evidence. Fix: cap a `GetTx` at 64 ids on the requesting side (split larger requests), or serve a `GetTx` through a byte-bounded queue that yields; test: announce 200 transactions between two nodes and assert no `slow_disconnects`. Small. |

No other DoS item blocks the trial **provided P0-2 (PSK) is in force**: every remaining
DoS in §2.2 needs a connection that the PSK refuses. If any trial device listens
without a PSK, D1, D2 and D3 become P0.

**P1 — before a public testnet or mainnet**

| # | Item | Fix or measurement |
|---|---|---|
| P1-1 | F48-5 quarantine marker (35 S5) | write 0x82 "validating <id>" before body validation, clear after; on start with a pending marker, halt naming the block; never auto-invalidate; AT-3 fault-injection test. |
| P1-2 | TM2-6 invalid/side bodies | write origin-1 verdict markers for invalid bodies (skip re-validation, keep the record for diagnosis), move bodies out of RAM (35 S6), prune stored side branches deeper than the K4 window; measure RSS growth under NS-5 with PoW-valid invalid blocks. |
| P1-3 | Eclipse residuals E1–E8 | built-in seeds with signed release lists; model E2/E3 in `eclipse_sim`; an outbound "insufficient chain work" timeout (Bitcoin's `ConsiderEviction`) for E8; NS-2 campaign. |
| P1-4 | TM2-13 live network tests | NS-1, NS-2, NS-4, NS-5, NS-6, NS-7 in CI or on a Linux VM. |
| P1-5 | TM2-9 install verification | `install-linux.sh --tag <t>`: `git verify-tag`, checkout, build, compare the binary hash with the signed announcement (when cross-host reproducibility is shown), refuse otherwise. |
| P1-6 | B1 cross-host reproducibility | Linux reproducible build of the node in CI (two runners, compare hashes), then Windows-to-Windows across machines. |
| P1-7 | TM2-8 SIGTERM | handle SIGTERM like SIGINT in the node; `STOPSIGNAL SIGINT` in the Dockerfile; Docker build via `release-build.sh` and `check-build-flags.sh`, base images by digest. |
| P1-8 | F48-8 log limiting | per-category token bucket with "N suppressed" lines for connect/disconnect/ban/invalid-block lines; `journald` limits or logrotate in `deploy/`; AT-10. |
| P1-9 | CI3/RS release pipeline | release job building artifacts from the signed tag with provenance and SHA256SUMS signed by the release key. |
| P1-10 | SC2 third_party check | CI script that downloads the published 0.7.0 crates (checksums from crates.io index) and checks `third_party/*` = upstream + `third_party/upstream/*.patch`. |
| P1-11 | C3/B3 self-tests | RandomX start-up self-test (decision 08) and miner clock-skew refusal (decision 04), both visible as overrides in `/info`. |
| P1-12 | T4 transport v2 | per decision "Agent 30": Elligator encoding, hybrid ML-KEM, rekeying, or ship v1+W5 and say so. |
| P1-13 | TM2-14 (D1) header-hash budget | Slow start per peer: the first chunk of any peer that has not yet delivered an accepted header is **one** header, doubling after each accepted chunk; a node-wide token bucket for hashes spent on peers without delivered work (e.g. 2 hashes/s), excess batches deferred, not dropped; per-onion-connection and per-proxy-session counting so Tor identities share one budget. Measure with NS-5: CPU of the victim and honest-tip delay while an attacker opens 2 connections/s. |
| P1-14 | TM2-15 (D2) staller detection | Implement decision "Agent 31": when the lowest missing body has been in flight for > T_stall (Bitcoin: 2 s, doubling up to 64 s) and other peers could serve it, disconnect (no ban) the holder; never re-request a timed-out body from the same peer while another candidate exists; lower `p.height` to the highest body it actually delivered after a timeout; let rotation evict a peer whose only in-flight requests have timed out. Test failing first: one inflated-height withholding peer among 3 honest peers, assert sync completes within a bound. |
| P1-15 | TM2-16 (D3) send-buffer bound | Byte-count the outboxes; stop reading a peer's requests while its queued bytes exceed e.g. 2 × `MAX_BLOCK_BYTES` (Bitcoin's `fPauseSend`); a node-wide cap on queued outbound bytes. Measure RSS with 64 slow readers in NS-5. |
| P1-16 | TM2-18 (D5) contextual-signature budget | A per-peer budget of unscored contextual failures (e.g. 20 per minute) after which further young-ring transactions from that peer are dropped unverified for a while; a node-wide CPU budget for the Tx lane. Measure actor latency under NS-5. |
| P1-17 | D6, D7 | Grow the read buffer as bytes arrive (or require > 64 KiB frames only after a request of ours); an upload budget per peer for `Headers`/`Block` answers. |
| P1-18 | SY2 / E8 | Bitcoin-style outbound chain-work eviction (`ConsiderEviction`): an outbound peer whose best known work stays below our tip's for 20 min after a `GetHeaders` is disconnected (not banned). |

**P2 — hardening**

| # | Item | Fix |
|---|---|---|
| P2-1 | TM2-10 RPC pre-auth | per-source-IP socket cap (e.g. 16) and a separate small pool for unauthenticated sockets; auth-failure delay without holding a slot beyond it. |
| P2-2 | TM2-12 fsync | `sync_all` the tmp file and the directory for `peers.json`, `bans.json`, `anchors.json` (reuse `write_atomic` from `originated.rs`). |
| P2-3 | E11 ban list cap | cap at e.g. 10,000 entries with oldest-expiry eviction; ban /48s when many /64s of it are banned. |
| P2-4 | L5, D4, D5 | `peers.json` 0600 (with P0-4), `miner.env` 0600, miner unit hardening parity. |
| P2-5 | TM2-11 docs | STATUS refresh and p2p.md §12 correction (should be done with P0 work, cheap). |
| P2-6 | CI4 | default branch to `rebuild/core` (owner) so weekly `audit`/`deny` run. |

---

## 12. Sources

Internal: the files cited inline; `C:/bszkeval/p2/decisions.md` sections named in the text;
round-1 dossier `48-threat-model-adversarial.md`. External prior art referred to (not
re-fetched for this round; see dossier 48 §11 and dossiers 30, 32, 36, 43, 44 for the
citations): Bitcoin Core addrman/anchors/feelers/eviction and `ConsiderEviction` (net
processing), BIP 324, WireGuard PSK, Heilman et al. "Eclipse Attacks on Bitcoin's
Peer-to-Peer Network" (USENIX Security 2015), Tran et al. "A Stealthier Partitioning
Attack against Bitcoin Peer-to-Peer Network" (Erebus, IEEE S&P 2020), Bitcoin Core
CVE-2025-54604/54605 (log fill), Zebra CVE-2026-52738 (panic crash loop), systemd.unit(5)
(`StartLimitIntervalSec`, `StartLimitBurst`), docker stop / PID 1 signal semantics,
Shadow network simulator (shadow.github.io), Tor chutney.
