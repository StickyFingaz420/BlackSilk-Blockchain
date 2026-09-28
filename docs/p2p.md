# BlackSilk Peer-to-Peer Protocol

Status: **v1**, implemented by `blacksilk-p2p` (`p2p/`) and wired into `blacksilk-node`.

This protocol is not consensus. Nodes agree on validity through
[`consensus.md`](consensus.md), [`transactions.md`](transactions.md) and
[`blocks.md`](blocks.md); the network only moves data. Every rule here has one of three
purposes: move data reliably, keep a node available under attack, or leak as little as
possible about who sends what.

All integers are little-endian unless stated otherwise. Encoding primitives
(minimal varints, bounded counts) are those of transactions.md §4.1.

---

## 1. Goals and threat model

**Adversaries considered:**
- **Passive network observers.** ISPs, or anyone on the path, who watch traffic.
- **Spy nodes.** They connect to many nodes to find which node first broadcast a
  transaction, and so which IP a transaction came from.
- **Malicious peers.** They send invalid data, flood messages, lie about their chain,
  or try to monopolize a node's connections (eclipse).

| Goal | Mechanism |
|---|---|
| Content confidentiality against passive observers | Encrypted transport (§3) |
| Transaction origin privacy against spy nodes | Dandelion++ (§8) and randomized relay delays (§7) |
| Minimal fingerprint | No user agent, no clock, no services flags; own address not announced unless configured (§4) |
| Availability | Strict size and count limits, rate limits, misbehavior scoring, bans (§10) |
| Eclipse resistance (limited, §9) | Bucketed address manager with a secret key; per-peer address admission limits; outbound diversity by network group (§9) |
| Correct sync under a lying peer | Header-first sync: every header is PoW-checked before any body is requested (§6) |
| Tor/I2P users | SOCKS5 proxy for outbound connections, proxy-only mode, onion addresses (§11) |

**Not protected in v1:**
- **An active man in the middle** can read and modify a connection. Peers are not
  authenticated; the encryption is opportunistic, like Bitcoin's BIP 324. The
  consequences are limited: a MITM cannot forge valid blocks or transactions, only drop
  or observe traffic.
- **Traffic analysis** of sizes and timing.
- **A global passive adversary** watching all links.

## 2. Transport

Plain TCP. The default port is **19334 on mainnet, 29334 on testnet and 39334 on
regtest**. The RPC ports are one below (blocks.md §9).

## 3. Encrypted transport

Handshake, directly after the TCP connect. There are no magic bytes and no version in
the clear:

```
initiator → responder:  A = a·G     32 bytes, Ristretto255, a random
responder → initiator:  B = b·G
S       = a·B = b·A                 (reject non-canonical encodings and the identity)
k       = H64("p2p/session", LE32(network_id) ‖ genesis_id ‖ A ‖ B ‖ S)
k_i→r   = k[0..32],  k_r→i = k[32..64]
```

- `network_id` and the 32-byte `genesis_id` are bound into the keys (the genesis since
  testnet v3, R15-3: a release candidate or rehearsal with the same id but another
  genesis cannot join). Nodes of different networks or chains derive different keys,
  and the first frame fails to decrypt: a cross-network connection is detected without
  any plaintext network marker.
- Ephemeral keys give **forward secrecy**: recorded traffic cannot be decrypted later,
  even if a node is compromised.

**Frames:**

```
frame = AEAD(k_dir, n,   LE32(len))      4 + 16 bytes
        AEAD(k_dir, n+1, payload)        len + 16 bytes
```

- AEAD is AES-256-GCM. The nonce `n` is a 96-bit little-endian message counter that
  starts at 0 and increases by 2 per frame, separately for each direction.
- `len ≤ MAX_FRAME = MAX_BLOCK_BYTES + 64 KiB` is checked right after the length decrypts, before
  any payload is read.
- Any decryption failure ends the connection.
- The counter never wraps: 2^64 frames are unreachable.

## 4. Handshake and version negotiation

Both sides send `Version` as their first frame and answer the other's `Version` with
`Verack`.

```
Version {
  protocol:  u32        currently 3 (below); peers below MIN_PROTOCOL (3) are disconnected
  network:   u32        must equal ours (defence in depth; §3 already separates networks)
  nonce:     u64        random per connection; equal to one of our own nonces = self-connection
  height:    u64        best header height (a hint for sync, not trusted)
  tip:       [u8; 32]   best header id (a hint)
  listen:    optional NetAddr   our reachable address, only if the operator configured one
  relay_txs: bool       false = block-relay-only connection
}
```

- There is deliberately **no user agent, no timestamp and no service bits**. Each would
  fingerprint software versions or clocks.
- The handshake must complete within **10 s**, or the connection is closed.

### 4.1 Protocol versions and extensibility (P0-8, R8-14)

| `protocol` | Meaning |
|---|---|
| 1 | Original protocol: an unknown message type or extra bytes after `relay_txs` were protocol violations (100 points, a ban). |
| 2 | Unknown message types are ignored (§5), and `Version` may carry **extension bytes** after `relay_txs`, which are ignored. Every known message's wire format is unchanged. |
| 3 | `Addr` (type 5) carries timestamped, length-prefixed entries (§5) instead of bare `NetAddr`s. `MIN_PROTOCOL_VERSION` is 3. |

Changed on 2026-09-27, before any launch: `PROTOCOL_VERSION` went from 1 to 2, and a
v2 node accepts a v1 node's `Version` unchanged (`MIN_PROTOCOL_VERSION` stays 1). A v1
node would reject a v2 node's `Version` only if it carried extension bytes; v2 sends
none.

Changed again before the v3 testnet launch (32 W3, agreed with 30 in the decisions
log): the `Addr` format was **replaced in place** (type 5), not added as a new type,
since no node was deployed. A v2 node cannot decode a v3 `Addr` and would ban its
sender, so `MIN_PROTOCOL_VERSION` rose to 3 with it: v2 and v3 nodes refuse each other
at the handshake instead. Old `peers.json` files stay readable (the table format did
not change).

How a later version (v3) adds a feature without splitting the network:
- **New `Version` fields** are appended after `relay_txs`, in order. A decoder reads the
  fields it knows and ignores the rest, so old nodes still complete the handshake.
- **New message types** are sent only to peers whose `protocol` is at least the version
  that defines them. Older v2 peers ignore them anyway (§5), so a mistake costs
  bandwidth, not a ban.
- **Negotiation** may use messages of new types between `Version` and `Verack`: a v2
  node skips up to 8 frames of unknown types there.
- No feature bitfield was added: with nothing to negotiate yet it would only be a
  constant, and each bit set later would fingerprint software versions. The protocol
  number carries the same information for features every node of a version supports.
  A v3 that needs optional per-node features can append one; that is the fingerprint
  trade-off to decide then.

## 5. Messages

A payload is `u8 type ‖ body`. Every list is bounded **before** anything is allocated;
an oversized list is a protocol violation.

| Type | Message | Body | Limit |
|---|---|---|---|
| 0 | `Version` | §4 | |
| 1 | `Verack` | — | |
| 2 | `Ping` | `u64` nonce | |
| 3 | `Pong` | `u64` nonce | must answer our ping |
| 4 | `GetAddr` | — | answered once per connection, to inbound peers only (§9) |
| 5 | `Addr` | `varint n`, `n × AddrEntry` | n ≤ 1000; each address ≤ 512 bytes |
| 6 | `GetHeaders` | `varint n`, `n × id` (locator), `stop id` | n ≤ 64 |
| 7 | `Headers` | `varint n`, `n × 100-byte header` | n ≤ 2000 |
| 8 | `GetBlocks` | `varint n`, `n × id` | n ≤ 128 |
| 9 | `Block` | `varint len`, block bytes | len ≤ `MAX_BLOCK_BYTES` (blocks.md §4) |
| 10 | `NotFound` | `varint n`, `n × id` | n ≤ 128 |
| 11 | `InvTx` | `varint n`, `n × tx hash` | n ≤ 500 |
| 12 | `GetTx` | `varint n`, `n × tx hash` | n ≤ 500 |
| 13 | `Tx` | `varint len`, tx bytes | len ≤ the cap of the transaction's kind: 100 kB for transfers, `MAX_PX_TX_SIZE` / `MAX_DEPLOY_TX_SIZE` for kinds 2 and 3 (px.md §11.5) |
| 14 | `StemTx` | `varint len`, tx bytes | as `Tx` (§8) |

`NetAddr` (only in `Version.listen`) is one of:
- `0x04 ‖ 4-byte IPv4 ‖ LE16 port`
- `0x06 ‖ 16-byte IPv6 ‖ LE16 port`
- `0x0a ‖ 56-byte Tor v3 host (base32, without ".onion") ‖ LE16 port`

`AddrEntry` (the entries of `Addr`, since protocol 3; BIP155's network numbering):

```
AddrEntry = LE32 time ‖ u8 network ‖ varint len ‖ len bytes of address ‖ LE16 port
network 1 = IPv4 (len 4), 2 = IPv6 (len 16), 4 = Tor v3 (len 32: the service's public key)
```

- `len ≤ 512` for every network, checked before the bytes are read.
- A **known network with another length**, or an IPv4-mapped IPv6 address (it must be
  sent as IPv4), makes the message malformed (100 points, §10).
- An entry of an **unknown network** decodes and is skipped: never stored, dialed or
  relayed. A later version can add networks (I2P, CJDNS) without old nodes banning it.
- A Tor v3 entry is the 32-byte key; the receiver derives the name with its checksum
  and version (§9), so an onion entry is valid by construction.
- `time` is the sender's claim of when the address was last seen, in Unix seconds, and
  0 = unknown. It is never trusted for a security decision: the receiver uses it only
  to decide whether the address is fresh enough to relay (§9).

Every address is used in **canonical form**: an IPv4-mapped IPv6 address
(`::ffff:a.b.c.d`) is the IPv4 address, whether it comes from the wire, the
configuration or a dual-stack listener, so bans, per-IP limits, deduplication and
groups see one form per host. The encoders write the IPv4 form; the decoders refuse
the mapped one.

**Unknown message types** (above 14) are ignored, not penalized, since protocol 2
(§4.1). They still count against the peer's message and byte budgets (§10), so a flood
of them is cut off like any other. Inside a known type, decoding stays strict:
a malformed known message (bad length, bad flag, a list over its limit, trailing bytes)
is a violation (100 points). The only exception is `Version`'s extension area (§4.1).

## 6. Header-first synchronization

1. **Start.** After the handshake, if the peer's `height` exceeds our best header height,
   send `GetHeaders(locator)`.
   - The locator holds ids of our best header chain: the tip, then 10 predecessors one
     by one, then exponentially sparser ones back to genesis (at most 64).
2. **Answering.** The responder finds the first locator id on its best chain and returns
   the following headers, at most 2000, ending at `stop` if it meets it.
3. **Processing headers.** They must form a chain. Each header is fully validated
   (consensus.md §6), including RandomX PoW, *before* it enters the header tree.
   - **Where.** A batch is handed to a single header worker; the peer's read loop only
     checks that the headers form a chain. The loop keeps answering pings however
     long the proof of work takes. The worker verifies one batch at a time, so
     batches from several peers covering the same headers are hashed once.
   - **Cheap rules first.** The worker checks every rule except proof of work (parent,
     version, height, median-time-past, future-time limit, difficulty) for the
     **whole batch** before any RandomX hash (`HeaderChain::precheck_batch`). It uses
     the branch context the batch itself forms, with the same rule function as
     single-header validation, so the two cannot disagree.
   - **Then proof of work, in chunks** of `pow_threads` headers, at most `seed_lag`
     (64; `sync_policy::pow_chunk`), hashed in parallel (the seeds come from ids in
     the batch or the existing chain). Each chunk is accepted before the next is
     hashed. A header's RandomX key is at least `seed_lag + 1` blocks below it, so
     its key block is never an unverified header of its own chunk: a batch with junk
     proof of work at a key block cannot make the node build that key's cache (on
     hosts with more than 65 threads it could before, F07-4;
     `p2p/tests/sync_policy.rs`).
   - **Cost bound.** A batch that breaks a cheap rule costs no RandomX hash. One that
     fails the proof of work costs at most one chunk of hashes beyond its last valid
     header, and the sender is banned. Before 2026-09-27 every header of a batch was
     hashed first: up to 2000 × 0.45 s ≈ 900 CPU-seconds per junk message.
   - **No hash for a sender about to be banned.** If the pre-check finds a violation
     the sender is penalized for, the batch is rejected before any hash, and nothing
     of it is stored. Only failures that are not the sender's fault (a future
     timestamp, a descendant of an invalid body) keep the valid prefix.
   - **Known headers are skipped.** Headers already stored cost nothing more: a peer
     replaying known headers causes no hashing.
   - **Work gate (anti-DoS, R1-C1).** After the pre-check, the cumulative work the
     batch *claims* is exact: the difficulties are the required ones. The gate is
     `blacksilk_chain::sync_policy::worth_verifying`, the one rule shared with the
     RPC `/block` gate (blocks.md §9.2), which charges a submitted block the
     required difficulty too. RandomX hashes are spent only if one of these holds:
     - the batch's claimed tip work is at least
       `threshold = best_work − work(our last 144 blocks)`, i.e. the work of our best
       chain 144 blocks below its tip. Every extension of our best chain and every
       near-tip competitor passes;
     - the message is a **full** batch (2000) whose work per height is at least half
       of our best chain's over the same heights (our tip difficulty above our tip).
       This lets a heavier fork deeper than one batch sync, batch by batch.
     - Otherwise the batch is dropped: no hash, nothing stored, no penalty, and the
       peer is not asked again because of it.
     - Why: once LWMA is driven to difficulty 1 (timestamps 6T apart from an old
       block), valid headers cost an attacker nothing, but each cost ~0.45 s of
       RandomX to verify and would be stored forever. Such a branch claims ~1 work
       per header, far below the threshold once our difficulty is above ~2.
   - **Headers of an unknown version (RT-1, RTW1-1).** A header whose version is above
     every version of this node's schedule (`HeaderError::UnknownUpgrade`) passes the
     pre-check unconfirmed: its difficulty is never checked, since a newer release
     may change that rule. So:
     - **Charged the required difficulty.** The work gate counts it at the difficulty
       this node requires at its position (`HeaderChain::required_difficulty_after`),
       never the difficulty it claims. Before this rule a header anchored at genesis
       and claiming `u64::MAX` passed the gate and was hashed.
     - **Live RandomX keys only.** It is hashed only if its RandomX key (on its own
       branch) is the key of our next block or the next key after it
       (`sync_policy::seed_is_live`). Under any other key it is dropped unhashed, so
       it cannot make the node build a RandomX cache.
     - **Classified by its proof of work.** Otherwise it is hashed after the batch's
       valid prefix and checked against the required difficulty: junk proof of work
       is `InsufficientWork` (penalized); real work is `UnknownUpgrade`, not scored.
       A peer is disconnected, never banned, after 3 of them on one connection.
       Either way nothing past it is usable: the peer's claimed height is lowered to
       ours.
     - **Operator warning.** The node warns once per run that it may need an upgrade.
       A report counts toward the warning only if it comes from an **outbound** peer
       and the header's branch reaches the anti-DoS threshold at the required
       difficulty. The warning needs 2 such reporters, or one whose header reaches
       our best chain's work. Reporters are counted by network group (by whole
       address in `allow_private` mode), not by connection, so reconnecting does not
       count twice; at most 2 are remembered. Inbound peers never trigger it.
   - **Unrequested headers** must be a single tip announcement. A longer unrequested
     batch is not verified at all, and costs the sender 10 points.
     - A single header that arrives while our `GetHeaders` is outstanding may be a
       tip announcement that crossed our request. It answers the request, but one
       multi-header batch arriving within 60 s of the request still counts as
       solicited (the real reply). Before 2026-09-27 that reply cost the honest
       sender 10 points and was dropped.
   - **At most one batch per peer** is queued or being verified. The peer is not asked
     for more headers meanwhile; headers arriving from it in that time are dropped,
     and the node asks again once the batch is done (whatever its outcome, unless the
     peer was penalized).
   - **Bounded queue.** At most `max_per_ip` batches per sender IP (onion peers: per
     address; not enforced in `allow_private` mode, like the connection limit) and
     `2 × (max_inbound + max_outbound)` in total are queued. When full, the headers
     are dropped and the peer is asked again once there is room. Before 2026-09-27
     the batches of departed senders stayed queued without bound: an attacker
     reconnecting (or rotating IPs) could queue batch after batch and starve honest
     header sync behind the single worker.
   - **Departed or banned senders.** A batch whose sender left is only pre-checked:
     a violation worth a ban still bans its address, but no RandomX hash is spent on
     it. A batch whose sender's IP is banned is skipped. A sender that leaves while
     its batch is being hashed stops the hashing at the next chunk.
   - **Asking for more.** If a full batch (2000) added headers, or ended on a stored
     branch that is not our best chain, the node asks the same peer for more, with a
     locator that starts at the batch's last header (then our best chain). A fork
     deeper than one batch therefore continues where it stopped; a locator of our
     best chain alone would return the same first batch forever.
   - **Non-advancing replies.** An empty answer, or a solicited batch that adds
     nothing, lowers the peer's claimed height to ours, so it is not asked again
     every tick (it is asked again when it announces a new tip). Before 2026-09-27 a
     peer claiming a higher chain and replaying known headers caused a request loop.
4. **Bodies.** The node requests `GetBlocks` for best-chain blocks whose body it lacks,
   starting just above the connected tip.
   - An **unrequested** block costs its sender 10 points and is stored only if its
     header is already in our header tree (it passed the work gate), e.g. a requested
     block that arrives after its timeout. Any other unrequested body is dropped
     before it is hashed or written: a free low-work branch cannot fill the disk.
   - **Window per peer (R8-9):** at most **16** blocks and **32 MiB** in flight, and
     only from peers whose announced height covers them. Headers carry no body size,
     so each request is charged the maximum block size (`MAX_BLOCK_BYTES`, about
     9.45 MB): **3 blocks** per peer in practice (at least one is always allowed).
     Before 2026-09-27 the window was 16 blocks, up to 151 MB, which a peer on a
     home connection could not deliver within the 60 s timeout. The cost is a lower
     download rate for small blocks (3 per round trip per peer); a v3 inventory
     message with body sizes would lift it.
   - A block counts in its peer's window from the request until it has been
     **processed** (connected or rejected), not merely received, so the block
     worker's queue is bounded by the windows.
   - A node serves at most 16 blocks per `GetBlocks`; the rest are answered with
     `NotFound`.
   - A request unanswered within **60 s** is reassigned to another peer. It is not
     penalized (before 2026-09-27: 5 points), and the block arriving late from the
     peer we asked is accepted as an answer, not as an unsolicited block, for another
     60 s (R8-9).
5. **Connecting.** Bodies go through the chain manager (blocks.md §5–§6). It connects
   them in order, validates each, and reorganizes when a heavier branch completes. The
   network layer never decides validity.
   - **Where.** The peer's read loop only decodes the block and matches it against our
     requests; a single **block worker** hands bodies to the chain actor (§10), one at
     a time, in arrival order, and waits for each verdict. The read loop keeps
     answering pings however long a block takes. Unrequested blocks (penalized, §10)
     wait there too, at most 8 node-wide; beyond that they are dropped unread.
   - **Bounded steps (P0-7, R8-1, dossier 34 Stage 2).** The body that fills a gap
     can release hundreds of downloaded descendants at once. The chain actor connects
     them in steps of at most **8** block validations (`ChainManager::sync_step`)
     and serves one waiting command between two steps (§10), so header sync, queries
     and the RPC are not held up by the whole drain. Results are unchanged: blocks
     complete in the same order (lowest body arrival first), a body arriving during a
     drain waits for it, and a reorganization is never paused on a tip lighter than
     the one it replaces. The mempool receives the drain's effects once, at its end.
     Tested: `bounded_submission_reaches_the_unbounded_result_in_bounded_steps`,
     `a_bounded_reorganization_never_stops_on_a_lighter_tip`, the equivalence tests
     E1-E4 (`chain/tests/actor_equivalence.rs`) and
     `pings_are_answered_while_a_long_batch_of_blocks_connects` (p2p).
   - Between steps, readers see intermediate tips of the drain (each a valid,
     heavier-or-equal connected chain). Node policy that depends on the tip (the
     low-work body rule, blocks.md §8) sees them too; it can only keep more bodies,
     never fewer.

**New blocks** are announced with a `Headers` message holding the one new header, sent
to every peer that does not already have it. A peer that lacks the body asks for it with
`GetBlocks`.

## 7. Transaction relay (fluff phase)

- **Announcing.** A transaction in the mempool is announced with `InvTx`.
  - Announcements to each peer are batched and sent after an independent random delay
    (exponential, mean 2 s for outbound peers and 5 s for inbound peers).
  - This makes the first announcer hard to find by timing (the "diffusion" of
    Dandelion++).
- **Requesting.** A peer asks for unknown hashes with `GetTx`, from one announcer at a
  time.
  - A `NotFound` answer, no answer within 30 s, or the peer disconnecting moves the
    request to the next announcer (on disconnect at once).
  - Neither is penalized: transaction relay is best effort.
  - The per-peer sets of announced and known transaction ids are capped (50 000;
    cleared when exceeded: forgetting only costs a redundant announcement).
- **Stem transactions stay private.** An `InvTx` for a transaction in our stempool
  is answered exactly like one for an unknown transaction (a `GetTx`), and does not
  end its stem. Before 2026-09-27 the node sent no request and fluffed at once: a
  stempool-membership oracle that also let a spy end any stem at will (I3-1). If
  the transaction really is in fluff, it arrives and enters the mempool, which ends
  its embargo.
- **Serving.** A node serves `GetTx` **only for transactions it has already announced to
  that peer and still has**.
  - Every other requested hash gets the same `NotFound`, whether the transaction was
    mined, dropped or never known.
  - A spy therefore cannot probe the stempool or the mempool for transactions it was
    never offered.
- **Pool re-announcement** (dossier 38 §3.4 item 3, `net/maintenance.rs`). Every node
  announces again, with `InvTx` like any announcement above, each pooled transaction
  that is still in its next block template, at fixed pool ages: 10, 20, 40, 80, 160,
  320, 640 and 1 000 blocks (the gap doubles from 10 and is capped at 360), and never
  after 1 080 blocks (half the pool expiry, blocks.md §7).
  - The age counts from the height the node pooled the transaction for; for a
    transaction this node originated, from the height it was relayed for (§8.1), if
    that is earlier. Honest nodes pool a transaction within seconds of each other,
    so they all re-announce it at the same heights: the origin re-announces its own
    transaction exactly as every other node does, and never with a `StemTx`.
  - Only peers not known to have the transaction get the announcement (the per-peer
    sets above), so in practice it reaches connections opened since: a peer that
    restarted fetches it back with `GetTx`, without its origin doing anything.
  - Cost: 32 bytes per transaction and peer at each point. Announcements use the
    per-peer trickle delays of this section (a shared inbound timer, R8-16, is open).
  - Tested: `pooled_transactions_are_reannounced_on_the_common_schedule` (not before
    age 10, once at age 10, not again at 11; `InvTx` only) and the schedule's unit
    test (`reannouncement_follows_the_backoff_schedule`).

## 8. Dandelion++ (stem phase)

Following Fanti et al., "Dandelion++" (SIGMETRICS 2018), with Monero's parameters
(fluff probability 20 % with a 39 s mean embargo, Monero PR #7025):

- **Epochs.** Time is divided into epochs of about 10 minutes (random length, 9–11
  minutes). In each epoch a node:
  - picks **2 stem peers** at random among its outbound peers;
  - maps each inbound peer, and itself, to one of the two stem peers at random, so each
    source's stem route stays fixed for the epoch;
  - is a *diffuser* with probability **20 %**, otherwise a *relayer* (expected stem
    length 5). Before 2026-09-27 it was 10 %, which Monero pairs with a longer
    embargo (R3-4). The embargo's 10 s base is ours, not Monero's: it keeps a stem
    peer's first forward from racing the embargo.
- **Transactions the node creates or receives by RPC** enter the stem: they are sent as
  `StemTx` to the stem peer mapped to "self".
  - If there is no stem peer yet (no outbound connection, e.g. right after startup),
    the transaction is **held** in the stempool, not broadcast, and sent into the
    stem as soon as an outbound peer exists. If none appears before its embargo
    fires, it is fluffed then. Before 2026-09-27 it was fluffed at once, showing
    every connected (inbound) spy where it came from.
  - A transaction this node expired from its mempool fewer than 30 blocks ago is
    refused here (`Expired`, the recently-expired guard, blocks.md §7). This is the
    only place the guard applies: a `StemTx` or relayed `Tx` from a peer is admitted
    whether or not this node expired it recently, so a stem peer whose window is
    later than the origin's does not drop the origin's stem (RTW1B-1).
  - A transaction this node originated before is never originated again while other
    nodes may still hold it (§8.1).
- **Receiving a `StemTx`.**
  - One that conflicts with a stem transaction (a shared key image or nullifier) is
    dropped first, before any verification: first seen wins, and valid
    double-spend variants cost nothing (R8-7).
  - The transaction goes through the relay admission checks (§10), then is
    validated fully against the current state.
  - Only a proven failure is a violation (§10).
  - It is stored in the **stempool**. The stempool is never announced, never served and
    never mined.
  - A relayer forwards it to the stem peer mapped to the sender. A diffuser fluffs it:
    it moves the transaction to the mempool and starts §7.
- **Embargo.** Every stem transaction gets a random embargo timer (exponential, mean
  **39 s**, plus 10 s).
  - If the transaction has not been seen in fluff (announced by a peer, or included in a
    block) before the timer fires, the node fluffs it itself.
  - This guarantees delivery if a stem peer is malicious or offline.
- **Stem failures.** A relayed stem transaction with no stem peer to forward it to is
  fluffed immediately (the node's own transactions are held instead, see above).

### 8.1 The originated set: no re-origination

An honest relay never stems, or announces as new, a transaction the network has held
for a while. Only its origin does that, when its wallet resubmits a transaction the
origin forgot: a restart empties the pool (it is not persisted), and the pool's own
expiry comes first at the origin, which admitted the transaction first. A spy that
still pools it then learns the origin with near certainty (dossier 33 F33-1, dossier
38 F38-3). So the node keeps an **originated set** (`p2p/src/originated.rs`):

- **What.** The id of every transaction originated here (`Network::submit_tx`, which
  serves the RPC `/tx`), with the next-block height it was relayed for. Recorded and
  written to disk before the transaction leaves the node.
- **Resubmission** of a transaction in the set, for inclusion at next height `h`
  (relayed for `r`):
  - already in this node's stempool: nothing is sent, and `/tx` accepts it;
  - `h < r + 2 160` (the pool expiry, blocks.md §7): other nodes most likely still
    pool it. It is **held**: pooled here, never stemmed and never announced, and `/tx`
    accepts it (or answers what the pool answers, e.g. `AlreadyKnown`). It is then
    re-announced only on the common schedule of §7, from `r`;
  - `r + 2 160 ≤ h < r + 2 190`: other nodes expired it recently and refuse it from
    their own wallets. It is refused here too, as `Expired`, also after a restart,
    when the pool's in-memory guard is gone;
  - `h ≥ r + 2 190` (`NETWORK_EXPIRY_BLOCKS`, 2 160 + 30, derived from the pool's
    constants): the network has dropped it, the entry is gone, and the transaction is
    originated again as a new one, through the stem.
- **Only local origination.** A peer's `StemTx` or `Tx` is admitted and relayed
  whether or not its transaction is in the set (as for the guard, RTW1B-1).
- **Persistence.** `originated.json` in the data directory: written to a temporary
  file, synced and renamed (a crash leaves the old or the new set), whenever the set
  changes. Entries are dropped when their window ends; at most 10 000 are kept, oldest
  dropped first (logged). A missing file is an empty set; an unreadable one is logged
  as an error and an empty set is used, so the node may then originate one of its old
  transactions again.
- **The wallet side** (wallet `sync`) asks `/tx/status` instead of re-posting, and
  re-originates at most once, after `relayed + 2 190` (px.md §12).
- Tested (`p2p/tests/network.rs`, over TCP):
  `a_restarted_origin_does_not_reoriginate_a_transaction_the_network_holds` (no
  `StemTx` and no `InvTx` after a restart), `an_expired_local_transaction_is_not_reoriginated_inside_the_window_even_after_a_restart`
  (`Expired` up to the window's last block after a restart, then one `StemTx`),
  `a_peers_stem_of_a_transaction_this_node_originated_is_relayed`, and the unit tests
  of `originated.rs`.
- **Limits.** The set protects against re-origination by this node only. A wallet
  that submits the same transaction to another node, or a node without this set,
  still re-originates it. A transaction the whole network dropped early (a full-pool
  eviction wave) is still not originated again before `r + 2 190`. The node's own
  miner may include a held transaction in its templates. Every independent re-origination is
  another sample for a spy (dossier 33 F33-3).

**Limitations.**
- Dandelion++ gives statistical origin privacy against spy nodes that control a fraction
  of the network. It does not help against an adversary who observes a node's own
  network link.
- For that, run the node over Tor (§11).

## 9. Peer discovery and the address manager

- **Seeds.** Seed nodes come from `--seed` or a built-in list. The built-in list is empty
  until the testnet is launched.
- **Address exchange.** After each outbound handshake the node sends `GetAddr`. A peer
  answers with at most 1000 random known addresses, at most once per connection, and
  **only to inbound peers**: a `GetAddr` from a peer the node dialed is ignored
  (unpenalized). Answering it would let a peer plant unique addresses in a node's
  table and recognize them later from another session, IP or Tor circuit, linking the
  node's sessions (Biryukov and Pustogarov, "Bitcoin over Tor isn't a good idea",
  IEEE S&P 2015; Bitcoin Core does the same, F32-4). The table keeps no per-address
  times yet, so the answer's entries carry time 0 ("unknown").
- **What a peer may add to the table** (`p2p/src/addrman_gate.rs`, per connection):
  - **The answer to our `GetAddr`**: up to 1000 addresses in total within 60 s,
    ending with its first message of more than 10 entries. Stored, never relayed.
  - **An unsolicited `Addr` of more than 10 entries** is dropped whole and costs 10
    points (Heilman et al., "Eclipse Attacks on Bitcoin's Peer-to-Peer Network",
    USENIX Security 2015, countermeasure 8). Before this change one such batch of
    1000 was accepted from every connection, inbound ones included, so reconnecting
    delivered 1000 addresses per handshake (F32-1).
  - **Unsolicited small `Addr` messages** are rate limited by address: 0.1 per second,
    burst 1000, starting with 1 token per connection (Bitcoin Core PR #22387). The
    excess is dropped, not penalized. Each new connection starts with one token, so
    connection churn is the remaining flood rate (bounded by the inbound limits).
  - **An inbound peer's `Version.listen`** is stored only if it is the peer's own
    address: its IP must be the connection's IP, or it is an onion address arriving
    through our hidden service (from loopback). Before this change any address was
    accepted there, one per handshake, around every other limit (F32-8).
  - Addresses of unknown networks, and addresses that are not routable (unless
    `allow_private`), are skipped.
- **Relaying addresses.** An address from an unsolicited `Addr` of at most 10 entries
  is relayed to 2 random peers (other than the sender) if it is routable, it passed
  the rate limit, and its time is **fresh**: at most 10 minutes old and at most 10
  minutes in the future (times further in the future, or 0, count as 5 days old).
  - Relay does **not** depend on whether the address was new to our table. Before this
    change only addresses new to the table were relayed, so a spy could learn which
    addresses the table held by sending one and watching whether it came back (F32-5).
  - Each connection remembers the addresses the peer sent or was sent (up to 5000,
    then the set restarts), and an address is not relayed to a peer that has it. With
    the freshness window this bounds how long one address circulates.
  - The relayed entry keeps its original time, so relaying reveals nothing about the
    relayer's clock.
- **Own address.** A node advertises its own address (`Version.listen`) only when the
  operator sets `--public-address`, so private nodes are not revealed.
  - An onion address is advertised only over Tor (proxied outbound connections, and
    inbound ones from loopback, i.e. through the hidden service); a clearnet address
    only over clearnet. A dual-homed configuration logs a warning at startup. Before
    2026-09-27 an onion address was sent to clearnet peers too, linking the node's
    two identities (I3-2).
  - After each handshake the node also sends the same address to the peer as a
    one-entry `Addr`, timed now rounded down to 5 minutes (so the peer relays it, and
    the time reveals the node's clock no finer than that).
- **Address manager.** Addresses live in two tables, *new* (heard of) and *tried*
  (successfully connected).
  - Each table is split into buckets. The bucket is
    `H32("p2p/addrman", secret ‖ table ‖ group(addr) ‖ group(source)) mod N`, where
    `secret` is local and random, so an attacker cannot predict which buckets it
    reaches.
  - The bucket depends on the address's group and the source's group together.
    Addresses from **many groups** announced by **one** source therefore spread over
    all of *new*: one source group bounds nothing (R8-3, open; the per-source limit is
    addrman v2, 32 W1). What bounds a flood today is what a peer may add (above).
  - *new* has 256 buckets × 64 slots; *tried* has 64 × 64. A full *new* bucket
    evicts an entry that failed 3 or more attempts, else a **random** entry; *tried*
    keeps the entry that connected more recently and moves the other back to *new*.
- **Groups** (`NetAddr::group`, as Bitcoin Core's without asmap):
  - IPv4: the /16. IPv6: the /32, except Hurricane Electric's `2001:470::/32` at /36.
  - IPv6 forms embedding an IPv4 address (IPv4-mapped, 6to4 `2002::/16`, NAT64
    `64:ff9b::/96`, Teredo `2001::/32`): the embedded IPv4 /16, the group of that
    IPv4 address.
  - Onion: the first 4 bits of the service key, so **16 groups** for all onions.
    Before this change every onion address was its own group, and onion names cost
    nothing to create: 8 of them satisfied "one per group" (R8-5). Four bits do not
    make onion addresses costly either (a name can be ground into any group); they
    bound how many buckets onion addresses from one source can reach.
- **Tor v3 names** are checked in full wherever one is parsed or decoded:
  `base32(key ‖ checksum ‖ version)`, version 3,
  `checksum = SHA3-256(".onion checksum" ‖ key ‖ version)[..2]` (Tor rend-spec-v3,
  "Encoding onion addresses"). A name with a wrong checksum or version is refused,
  never stored, relayed or dialed. The key itself is not checked to be a valid
  ed25519 point (as in Bitcoin Core); such a name is unreachable, like any dead
  address.
- **Routability.** Stored, relayed and dialed addresses are routable: not loopback,
  private, link-local, unspecified, multicast, broadcast, shared (100.64/10),
  benchmarking (198.18/15), reserved (240/4), IETF (192.0.0/24) or documentation,
  nor IPv6 `::/96`, unique-local, link-local, site-local, ORCHID, discard-only
  (`100::/64`) or documentation; an IPv6 address embedding an IPv4 address
  (mapped, 6to4, NAT64, Teredo) is routable only if that IPv4 address is.
- **Outbound connections.** The node keeps **8 outbound connections**, at most **one per
  group**, also among the addresses picked in the same round (before 2026-09-27 two
  picks of one round could share a group, R8-4). The groups of manual peers and seeds
  being dialed count too (F32-12). Candidates are drawn 50/50 from *tried* and *new*.
- **Seeds** are dialed when the address table is empty, and also when no outbound
  connection is up (every known address may be stale or hostile), each seed at most
  every 30 s (R8-13). Dial attempt times are kept 10 minutes (longer than every
  backoff), so dialing junk addresses does not grow memory (F32-10).
- **Eclipse resistance is limited** (F32-13). The eclipse simulator
  (`p2p/tests/eclipse_sim.rs`, run with `--nocapture`) models one node's table under a
  Sybil address flood with the real address manager and admission code, and prints the
  attacker's share of the outbound slots after a restart. Its results: the admission
  limits above cut what a flood gets into the table by orders of magnitude, but on a
  network of tens of honest nodes the attacker's addresses still outnumber the honest
  ones in *new*, so roughly half the outbound picks (the *new* half) go to the attacker,
  and a node whose *tried* table is empty (a new node) can have all 8 slots taken. The
  practical defences for the testnet are manual `--peer` links to known operators,
  independent seeds and operator monitoring; addrman v2, anchors, feelers and
  stale-tip rotation (32 W1, W4–W7) are open. An AS-level attacker (Erebus, IEEE S&P
  2020) is outside what /16 grouping can resist.
- **Connect-only mode.** With `--connect-only`, outbound connections go only to the
  configured `--peer` entries: no seeds and no discovered addresses. Inbound
  connections and address exchange still work. It suits fixed private topologies and
  lab tests.
- **Inbound.** At most 64 inbound connections, and at most 2 from any one IP.
  - Connections still in their handshake count against both limits when a new one
    is accepted, and the limits (and bans) are checked again, atomically, when the
    peer is registered. Before 2026-09-27 only registered peers were counted, so
    concurrent handshakes bypassed both limits.
- **Persistence.** The tables and the ban list are saved in the data directory
  (`peers.json`, `bans.json`) within a minute of changing, and on shutdown. The ban
  list is saved whenever a ban was added (not only when its size changed). An
  existing `bans.json` that cannot be read or parsed is logged as a warning.

## 10. Misbehavior, limits and bans

Each connection has a misbehavior score. At **100** the peer is disconnected and its IP
banned for **24 h**. Every other live connection from that IP is disconnected too.
Tor peers all share one exit IP, so for proxied or onion peers only the connection is
dropped.

| Violation | Score |
|---|---|
| Undecryptable frame, malformed known message, list over its limit | 100 |
| Header with invalid PoW, bad difficulty, bad version or height, a timestamp not after the median-time-past | 100 |
| Block whose body is invalid or does not match its header | 100 |
| `Headers` that do not connect or are not a chain | 20 |
| Unrequested `Headers` with more than one header | 10 |
| Transaction invalid by a **stateless** rule (`Tx`/`StemTx`; transactions.md T1–T11), or with an invalid ring signature over ring members all ≥ 60 blocks deep | 20 |
| A `StemTx` already proven invalid, sent again | 20 |
| Unrequested `Block`/`Tx`, `Pong` without a ping, second `GetAddr` from an inbound peer, or an unsolicited `Addr` of more than 10 entries (§9) | 10 |
| Rate limit exceeded | 1 per excess message; the message is dropped |

**Not penalized** (honest peers can trigger these):
- a header rejected only by the future-time rule;
- a header that descends from a block whose **body** we found invalid (including
  that block's own header), whether it is relayed in `Headers` or arrives as a
  block.
  - An honest peer relaying headers cannot know a body is invalid before it has
    downloaded and checked it, and an attacker can withhold the body from it.
  - Penalizing such relays let one invalid-body block get honest peers banned, which
    could split the network (fixed 2026-09-27).
  - The peer that sends the invalid **body** itself is penalized (100). Headers that
    break the header rules are penalized as before.
  - After such a relay we stop asking that peer for headers until it announces a new
    tip;
- a header whose version is above every version of this node's schedule
  (`HeaderError::UnknownUpgrade`, docs/consensus.md §11): the peer probably runs a
  newer release. It is not penalized; the operator warning follows the rules of §6
  ("Headers of an unknown version": outbound reporters only, required-difficulty work
  gate, 2 distinct network groups);
- within `ACTIVATION_GRACE_BLOCKS` (60) of an activation height, on either side, a
  transaction whose PX proof or ring signature fails: it may be bound to the
  neighbouring rule set's branch id (`TxError::is_stateless_at`);
- a duplicate;
- an already-known transaction;
- a transaction that conflicts with the mempool (dropped before verification, step 3
  below);
- a message of an unknown type (§5; it still counts against the rate limits);
- a transaction invalid only against **our chain state** (contextual rules C1–C3). Its
  key image may have been spent in a block we saw first, or its ring members may
  resolve differently on our branch. This is not proof of misbehavior. Exception:
  an invalid signature whose ring members are all at least **60 blocks** below our
  tip (`SIGNATURE_BURIAL`, the coinbase maturity). Those members resolve to the same
  outputs on every branch we could plausibly reorganize to, so the signature fails
  for every honest node: it is penalized (20) and remembered. Before 2026-09-27 it
  was never penalized nor cached, so garbage CLSAGs over real rings cost ~3 ms of CPU
  per input, under the chain lock, for free and forever (tx review H1). A node on a
  fork deeper than 60 blocks may penalize an honest relayer (20 points, not a ban);
- `NotFound`, or a slow answer to a request for a transaction, a block or headers
  (a peer whose headers request timed out is not asked again until it announces a
  new tip).

The lab network found the last two cases as false bans between honest nodes (AUDIT.md
R6).

A peer that does not read its messages fast enough is disconnected, not banned, when
its bounded outbox fills up. Each peer has two outboxes (R8-11): **control** (64
messages: pongs, headers, addresses, transaction relay, requests) and **bulk** (32
`Block` frames). The writer sends every queued control message before the next block
frame, so a pong or a stem transaction never waits behind a batch of blocks (a frame
already being written is finished first).

**Rate limits** (per peer, token buckets):
- **Messages:** 50 per second, burst 500.
- **Bytes:** 4 MB per second, burst 16 MB, for what a peer sends **on its own
  initiative**.
  - Answers to our own requests are exempt: a block we requested from that peer and
    are still waiting for, and headers while our `GetHeaders` is outstanding.
  - Their volume is already bounded by our requests: the block window (§6: 32 MiB
    per peer) and one header batch (at most 200 kB).
  - Before 2026-09-27 requested blocks were charged too. During a sync of large (PX)
    blocks the node dropped the blocks it had asked for, penalized the honest sender,
    and re-requested them after a timeout.
- **Transactions accepted into the relay path:** 20 per second, burst 100.
- **Ring signatures:** 50 per second, burst 500. A relayed transaction (`Tx` or
  `StemTx`) costs one token per v1 input (one CLSAG verification each): a 64-input
  transaction costs 64, not 1. Charged before any verification; a `StemTx` over
  the budget costs 1 point, a requested `Tx` over it is dropped unverified.
- **Admission order** of a relayed transaction, cheapest first:
  1. an id already proven invalid is dropped;
  2. the signature budget and, for PX, the peer's PX share are charged;
  3. an id already in our mempool (a replay, SX2), or one that failed a
     contextual rule **at our current tip**, is dropped unverified: the same bytes are verified again only after the tip changes
     (the cache holds at most 10 000 ids and is emptied when the tip changes).
     `InvTx` announcements of such ids are not requested either. A transaction that
     **conflicts** with a pooled one (same key image, PX nullifier or contract id,
     `Mempool::conflicts`; output keys never conflict) is dropped here too, unpenalized: the pool
     keeps the first seen, so it would be refused after verification anyway. Before
     2026-09-27 such a PX transaction passed the cheap checks and took a node-wide PX
     token (step 5) first;
  4. cheap checks: the stateless structure and balance rules and, for PX, the
     proof's strict decoding (penalized), then the contextual rules a chain
     extension can change: key images, PX anchor, nullifiers, registry, pool,
     contract id (not penalized, cached as in 3), then, for PX, the proof's table
     shape against its registered functions (penalized as `PxProof`);
  5. for PX and deploys, the node-wide PX token (below);
  6. full verification: ring signatures, range proofs, PX proof. The PX proof is
     decoded and shape-checked again there, before any ring (transactions.md §8.5).
- **PX and deploy transactions** (each costs ~0.2 s to verify): 0.2 per second,
  burst 4, per peer, **and** 2 per second, burst 10, over all peers together. Excess
  ones are dropped unverified.
  - The node-wide token is taken only after the cheap checks (step 5 above). Before
    2026-09-27 it was taken first, so ~10 connections sending PX transactions with a
    random anchor (rejected cheaply, contextual, unpenalized) drained it and
    censored honest PX relay for free (tx review M2).
  - A peer is penalized (1 point) only for exceeding **its own** share with unsolicited
    `StemTx` messages.
  - It is never penalized for the node-wide limit, which an attacker can drain, nor
    for a `Tx` we requested.
  - A malformed proof (one that fails decoding or shape) is caught in step 4, so it
    never takes the node-wide token. Before red team RTW1-2 the proof was not
    looked at until step 6: a PX transaction with a garbage proof and a garbage
    ring signature over young ring members passed step 4, took the token, cost the
    ring lookups, the range proof and a CLSAG, and was rejected with the contextual
    (unpenalized) `InvalidSignature`; the red team estimated that about 10 Sybil
    peers could starve honest PX relay that way, unpenalized.
  - Tested: `px_transactions_travel_the_stem_and_confirm_everywhere`,
    `junk_anchor_px_floods_do_not_drain_the_px_relay_budget`,
    `a_garbage_px_proof_is_penalized_before_the_px_token_and_any_signature`.
- An invalid PX proof counts as a stateless violation (20). Once the anchor and
  registry checks pass, the proof's statement does not depend on our pool state, so
  an honest peer never relays one. Exception: within `ACTIVATION_GRACE_BLOCKS` of a
  scheduled activation, a proof failure (in step 4 or 6) is contextual
  (`TxError::is_stateless_at`).
- A well-formed proof that does not verify (for instance a valid proof replayed in
  another transaction) passes step 4, takes the node-wide token and costs every
  check up to the proof verification before it is penalized: the per-peer PX share
  and the penalty bound that cost, not the cheap stage.

**Liveness:**
- The node pings every 60 s.
- A connection is closed after 180 s without any message, or when a pong is 30 s late.
- **The chain actor** (dossier 34 Stage 2; `chain/src/actor.rs`). One dedicated
  thread owns the chain manager and runs every chain operation, one at a time; no
  other thread can reach the manager, so nothing waits on a chain lock. P2P and RPC
  send it **commands** (one former lock closure each: the same manager calls with
  the same arguments) on four bounded **lanes**, served in priority order:
  - **Headers** (the header worker's pre-checks, PoW jobs and acceptance),
    **Blocks** (the block worker and RPC `/block`: local mining), **Query** (reads
    the snapshot does not answer: `GetHeaders`, `GetBlocks`, mempool lookups,
    transaction pre-checks, `/template` and the RPC state pages), **Tx**
    (verification of relayed transactions, fluff, local submission).
  - A lower lane's command is served after at most `STARVATION_LIMIT` (16) higher
    ones. During a drain, one command runs between two steps, and a Tx command only
    once starved: blocks, headers and queries go first (F34-5).
  - Producers never block: a full lane refuses at once. Relayed transactions are
    then dropped, counted (`NetStats::tx_lane_drops`) and never penalized (relay is
    best effort); every other caller waits asynchronously and offers the command
    again. The Blocks lane holds at least every block the node can have in flight
    ((64 + 8) × 3 + 8), and the block worker submits one at a time, so a requested
    block is never dropped.
  - Replies come back through oneshot channels: no async worker and no blocking
    thread waits for chain work (P0-7, R8-1, R10-5). The actor never takes the
    network-state lock, and no command is sent with it held.
  - Each command of the header worker (a batch of `k` PoW chunks costs `k + 1`:
    the pre-check with the first chunk's jobs, then each acceptance with the next
    chunk's jobs) waits for at most one step (F34-7). RandomX runs outside the
    actor.
  - **Equivalence.** Every actor schedule is one the old mutex allowed (the same
    closures, one at a time), and the connected chain, state, invalid marks and
    store bytes depend only on the sequence of submitted bodies and headers, so
    consensus results are unchanged (docs/reviews/chain-actor-stage2.md §4). Tested:
    E1 (four drivers, including the actor, reach the oracle's chain, state, store
    bytes and every verdict), E2 (four concurrent producers: replaying the actor's
    command log gives every reply and the final state), E3 (every published
    snapshot equals the one recomputed on the replay), E4 (a restart from the
    actor's store gives the oracle's state), and the ordering guarantees
    `chain/tests/actor_order.rs` g1-g7.
- **No read loop and no maintenance tick waits for the chain** (dossier 34
  Stage 1; F34-1 to F34-3). Before this, a peer whose own request waited for the
  chain lock stopped reading its socket, so its pings went unanswered and it dropped
  the node after the 30 s pong timeout, and the handshake and the maintenance loop
  stopped with it. A long command (a heavy block step, a reorganization, a slow
  disk) now delays only the chain work itself:
  - **Per-peer slow lane.** Messages whose handling needs a chain command
    (`GetHeaders`, `GetBlocks`, `InvTx`, `GetTx`, `Tx`, `StemTx`) go to a bounded
    per-peer queue, handled by the peer's own task one at a time in arrival order.
    Every other message (pings, pongs, addresses, `NotFound`, headers, blocks) is
    handled on the read loop, which never waits for the chain. A lane message may
    be handled after a later non-lane message of the same peer; no handler depends
    on that order. The bounds (`dispatch.rs`):
    - relay (`InvTx`, `Tx`, `StemTx`): at most `SLOW_LANE_RELAY` messages and
      `SLOW_LANE_BYTES` bytes (but always one message, so the largest transaction
      passes); beyond them relay is dropped without penalty (relay is best effort;
      a request is retried with the next announcer);
    - requests (`GetHeaders`, `GetBlocks`, `GetTx`): the rest of the lane's
      `SLOW_LANE` places, which relay never takes; queued relay bytes never drop
      a request. A request is dropped and charged as a message-rate excess
      (`score::RATE`) only when the lane holds `SLOW_LANE` messages. Before this
      split (a Stage 1 defect, found by the PX relay test), one queued PX
      transaction of about 3 MB made every later message of its peer dropped,
      and its requests charged;
    - memory: at most `SLOW_LANE_BYTES` plus one maximum-size transaction of
      relay, plus `SLOW_LANE` requests of at most 16 KiB each (about 11.5 MB per
      peer).

    The per-peer PX share (`PeerLimits::px`) is charged on the read loop when a
    PX `Tx` or `StemTx` arrives, before the lane: a peer stemming PX
    transactions over its share is penalized (one point each) however busy its
    lane is; a requested `Tx` over the share is dropped. At a disconnect the lane
    task stops before its next message, never in the middle of one.
  - **Published chain snapshot** (`ChainHandle::summary_cell`,
    `chain/src/manager/summary.rs`): the tip (id, header, height), the best header
    chain (height, id, locator), the bodies to download (at most 256), the next
    block's header fields, rule domain and epoch, the PX record count and root, the
    mempool counts, and the drain and halt flags. The actor republishes it after
    every command and step, before it replies and before it takes the next command,
    in a `std::sync::RwLock<Arc<_>>` whose critical sections are a pointer copy;
    `seq` never decreases. The handshake's `Version`, the locator of every
    `GetHeaders` we send, the handling of an empty `Headers`, tip announcements,
    download scheduling, the next height of a local transaction, RPC `/info` and
    the halt watcher read it. A reader sees the state of the last publication: at
    most one command or step old, and consistent (one publication is one point in
    the actor's order); a command's reply is never older than its snapshot. Nothing
    consensus-relevant reads it.
  - **Two maintenance loops.** Pings, timeouts, Dandelion epochs, held local
    transactions, tip announcements, header re-requests, outbound dialing and
    saving never wait for the chain. Embargo fluff (a mempool submission), pool
    re-announcement and download scheduling run on a second task. A long command
    delays only the first two, by at most its length: an embargo that expires
    during one is fluffed when it ends.

  Tested with real long commands (a stalled block append in a block submitted to
  the actor, 15-40 s): `p2p/tests/liveness.rs` L1 and L6 (a peer's own pongs flow
  while its `GetHeaders` and `InvTx` wait, and the replies come in arrival order
  afterwards), L2 (outbound dialing continues), L3 (a handshake completes), L7 (a
  header announcement is accepted during a body drain of heavy steps);
  `node/tests/rpc_liveness.rs` L4 (`/info` within 100 ms) and L5 (an RPC burst
  stays within the admission classes, docs/blocks.md §9.1); `p2p/tests/network.rs`
  L8 (a full Tx lane drops a relayed transaction without penalty while a requested
  block connects). `chain/tests/actor_order.rs` `l7_...` measures the header
  acceptance of L7 against the pre-Stage 2 mutex under transaction-verification
  load (printed; the actor's bound is asserted).
- **A panic in the chain actor stops the node** (P0-9, R10-2). A panic while running
  a chain operation can leave the manager half-updated. The node then exits with
  status 70 (`POISONED_EXIT_CODE`, the same in the chain actor, the P2P layer and
  the RPC) instead of relaying and building on that state; systemd
  (`Restart=on-failure`) or the operator restarts it, and the replay of the
  append-only block store rebuilds a consistent state (tested:
  `f1_a_panic_in_the_actor_exits_with_70_and_the_store_replays`). The same holds for
  a poisoned network state lock. At shutdown the actor stops between two steps; a
  drain in progress is finished by the replay at the next start.


## 11. Tor, I2P and proxies

- **Outbound proxy.** `--proxy <host:port>` sends all outbound connections through a
  SOCKS5 proxy (RFC 1928, no authentication), for example Tor at `127.0.0.1:9050`.
  - Onion addresses are resolved by the proxy (SOCKS5 domain-name type), never by local
    DNS.
- **Proxy-only mode.** `--proxy-only` makes the node connect *only* through the proxy
  and refuse clearnet connections.
  - Addresses are still exchanged, but the node's own clearnet address is never
    revealed.
- **Inbound over Tor.** The operator runs a Tor hidden service that forwards to the P2P
  port, and passes `--public-address <host>.onion:port` so the node advertises it.
- I2P is not implemented in v1; the I2P SAM client from the old code is in `legacy/`.

## 12. Known limitations

- Peers are not authenticated (§1). A MITM can read or drop a connection's traffic.
- PoW verification of headers costs about 0.45 s per header in RandomX light mode.
  Parallel verification divides this by the number of cores. Initial sync of a long
  chain is still slow until RandomX gets faster (AUDIT.md R1).
- **Cheap valid-PoW headers (R1-C1), partly closed.** The work gate (§6) keeps
  free low-work branches from being hashed or stored, and unrequested bodies of
  unknown headers are dropped (§6.4). Open:
  - **No minimum chain work.** While our own best work is small (initial sync, or
    a chain shorter than 144 blocks) the threshold is small too, and a peer can
    feed a low-work branch that is hashed and stored. A hard-coded
    `MIN_CHAIN_WORK` would need a headers *presync* (download without storing,
    count the claimed work, re-download once it clears the minimum, as Bitcoin
    Core since PR #25717): not implemented.
  - The full-batch density rule lets a peer whose hash rate per header is at least
    half of ours feed side branches deeper than one batch; that costs real work.
  - No pruning of stored side branches (consensus.md §8, policy K4); `HeaderChain`
    and the PoW cache still grow with every stored header.
  - **RandomX caches** (`consensus::pow::SeedCache`, under `RandomXPow`): a cache
    is built outside the lock other PoW callers need, so a key switch no longer
    stalls hashing under the other key (`consensus/tests/seed_switch_liveness.rs`).
    The chain manager pins and prebuilds the best header chain's keys: whenever
    that chain changes (a new header, an invalidated block, start-up) it passes
    `sync_policy::hot_seeds` to `PowFunction::set_hot_seeds` through `CachedPow`,
    and the next key's cache is built on a background thread during the lag
    (`ChainManager::refresh_hot_seeds`). Hot keys are never evicted for a
    side-branch key, and the first block of a key epoch builds no cache under the
    chain lock (`chain/tests/seed_switch.rs`: both switches cost an ordinary
    block's hash). The work gate removes the free trigger (headers of free branches
    are not hashed).
  - Bodies of stored side branches can still be stored before they are validated
    (the completion report's N-2), by an unrequested block whose header passed the
    gate.
  - A batch whose sender left before verification is only pre-checked: a sender
    whose batch would fail only the proof of work is not banned (it paid the real
    work of every header before the failing one).
- **One chain writer.** Every chain operation runs on the chain actor (§10), which
  serves commands by priority and one command between two drain steps, but still
  one at a time. Open (dossier 34 Stages 3 and 4):
  - Commands and steps are bounded in blocks, not in time: a step of
    `SYNC_STEP_BLOCKS` heavy blocks, a reorganization (never paused before its new
    branch outweighs the old tip) or the pool revalidation after it can take many
    seconds (research dossiers 10 and 12 estimate several seconds per heavy block).
    What waits for them is only chain work: lane messages, embargo fluff, header
    acceptance (each header-worker command waits for at most one step) and RPC
    chain calls. The main-chain header index and the mempool outside the writer
    (Stage 3) would let `GetHeaders`, pre-checks and mempool lookups skip the
    actor.
  - Relayed transactions are verified in the actor, below blocks, headers and
    queries (Tx lane; R8-1d: verification outside the writer is dossier 34
    Stage 4). They no longer delay block connection by more than one command per
    `STARVATION_LIMIT` slots during a drain, but each still costs the actor its
    verification time.
  - PoW of an RPC `/block` is computed outside the lock (docs/blocks.md §9.2); a
    P2P block whose header we never saw is dropped unhashed (§6.4).
  - Requests that need the chain wait for the lock on a blocking thread: at most
    one per peer lane, the workers' and the second maintenance loop's, plus the RPC
    admission classes (docs/blocks.md §9.1). Tokio's blocking pool (512 threads) is
    shared by all of them.
- **Block worker.** Bodies of all peers are connected by one worker, in arrival
  order: a peer's large valid blocks delay other peers' blocks, not their pings.
  Block-download timeouts still use a fixed 60 s (no per-size or head-of-queue
  timer, R8-9); they are not penalized.
- **Header worker head-of-line blocking** (R8-15): a single-header tip announcement
  waits behind a full 2000-header batch; no priority lane yet.

- **Address manager and eclipse** (§9, dossier 32). Open: no per-source bucket limit
  and random eviction in *new* (R8-3), no per-address times, `IsTerrible` or feelers,
  no anchors or block-relay-only connections, no stale-tip rotation (an outbound set
  of withholding peers is never replaced), per-IP limits and bans on the exact IPv6
  address rather than its /64, no inbound eviction, and the admission rate restarts
  with every connection.
- **Tor inbound.** Every inbound connection through a hidden service comes from
  127.0.0.1, so they share the per-IP limits (2 connections, 2 queued header
  batches) and a ban of one bans all of them.
- There is no compact-block relay; a full block is sent once per peer that lacks it.
- Dandelion++'s parameters follow Monero (q = 0.2, 39 s mean embargo), plus a 10 s
  embargo base. They have not been re-tuned for BlackSilk's network size.
