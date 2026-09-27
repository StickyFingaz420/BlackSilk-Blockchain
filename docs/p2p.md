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
| Eclipse resistance | Bucketed address manager with a secret key; outbound diversity by network group (§9) |
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
  protocol:  u32        currently 2 (below); peers below MIN_PROTOCOL (1) are disconnected
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

Changed on 2026-09-27, before any launch: `PROTOCOL_VERSION` went from 1 to 2, and a
v2 node accepts a v1 node's `Version` unchanged (`MIN_PROTOCOL_VERSION` stays 1). A v1
node would reject a v2 node's `Version` only if it carried extension bytes; v2 sends
none.

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
| 4 | `GetAddr` | — | answered once per connection |
| 5 | `Addr` | `varint n`, `n × NetAddr` | n ≤ 1000 |
| 6 | `GetHeaders` | `varint n`, `n × id` (locator), `stop id` | n ≤ 64 |
| 7 | `Headers` | `varint n`, `n × 100-byte header` | n ≤ 2000 |
| 8 | `GetBlocks` | `varint n`, `n × id` | n ≤ 128 |
| 9 | `Block` | `varint len`, block bytes | len ≤ `MAX_BLOCK_BYTES` (blocks.md §4) |
| 10 | `NotFound` | `varint n`, `n × id` | n ≤ 128 |
| 11 | `InvTx` | `varint n`, `n × tx hash` | n ≤ 500 |
| 12 | `GetTx` | `varint n`, `n × tx hash` | n ≤ 500 |
| 13 | `Tx` | `varint len`, tx bytes | len ≤ the cap of the transaction's kind: 100 kB for transfers, `MAX_PX_TX_SIZE` / `MAX_DEPLOY_TX_SIZE` for kinds 2 and 3 (px.md §11.5) |
| 14 | `StemTx` | `varint len`, tx bytes | as `Tx` (§8) |

`NetAddr` is one of:
- `0x04 ‖ 4-byte IPv4 ‖ LE16 port`
- `0x06 ‖ 16-byte IPv6 ‖ LE16 port`
- `0x0a ‖ 56-byte Tor v3 host (base32, without ".onion") ‖ LE16 port`

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
   - **Then proof of work, in chunks** of `pow_threads` headers, hashed in parallel
     (the seeds come from ids in the batch or the existing chain). Each chunk is
     accepted before the next is hashed.
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
     batch *claims* is exact: the difficulties are the required ones. RandomX hashes
     are spent only if one of these holds:
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
       branch) is the key of our next block or the next key after it, the two keys
       the node keeps built. Under any other key it is dropped unhashed, so it cannot
       make the node build and evict a RandomX cache.
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
     requests; a single **block worker** validates and connects bodies, one at a time,
     in arrival order. The read loop keeps answering pings however long a block
     takes. Unrequested blocks (penalized, §10) wait there too, at most 8 node-wide;
     beyond that they are dropped unread.
   - **Bounded lock holds (P0-7, R8-1).** The body that fills a gap can release
     hundreds of downloaded descendants at once. The worker connects them in steps of
     at most **8** block validations per chain-lock hold
     (`ChainManager::submit_block_in_steps`), releasing the lock in between, so the
     header worker, transaction relay and the RPC get it. Results are unchanged:
     blocks complete in the same order (lowest body arrival first), a body arriving
     during a drain waits for it, and a reorganization is never paused on a tip
     lighter than the one it replaces. The mempool receives the drain's effects once,
     at its end. Tested: `bounded_submission_reaches_the_unbounded_result_in_bounded_steps`,
     `a_bounded_reorganization_never_stops_on_a_lighter_tip` (chain) and
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

**Limitations.**
- Dandelion++ gives statistical origin privacy against spy nodes that control a fraction
  of the network. It does not help against an adversary who observes a node's own
  network link.
- For that, run the node over Tor (§11).

## 9. Peer discovery and the address manager

- **Seeds.** Seed nodes come from `--seed` or a built-in list. The built-in list is empty
  until the testnet is launched.
- **Address exchange.** After each outbound handshake the node sends `GetAddr`. A peer
  answers with at most 1000 random known addresses, and at most once per connection.
- **Relaying addresses.** Received addresses are relayed to 2 random peers when they are
  few (≤ 10) and routable.
- **Own address.** A node advertises its own address (`Version.listen`) only when the
  operator sets `--public-address`, so private nodes are not revealed.
  - An onion address is advertised only over Tor (proxied outbound connections, and
    inbound ones from loopback, i.e. through the hidden service); a clearnet address
    only over clearnet. A dual-homed configuration logs a warning at startup. Before
    2026-09-27 an onion address was sent to clearnet peers too, linking the node's
    two identities (I3-2).
- **Address manager.** Addresses live in two tables, *new* (heard of) and *tried*
  (successfully connected).
  - Each table is split into buckets. The bucket is
    `H32("p2p/addrman", secret ‖ group(addr) ‖ group(source)) mod N`, where `secret`
    is local and random.
  - An attacker from a few network groups can therefore fill only a few buckets, and
    cannot predict which ones.
  - *new* has 256 buckets × 64 slots; *tried* has 64 × 64. A collision evicts the
    older entry in *new*, and in *tried* keeps the entry that connected more recently.
- **Groups.** An IPv4 /16, an IPv6 /32, or a single onion address.
- **Outbound connections.** The node keeps **8 outbound connections**, at most **one per
  group**, also among the addresses picked in the same round (before 2026-09-27 two
  picks of one round could share a group, R8-4). Candidates are drawn 50/50 from
  *tried* and *new*.
- **Seeds** are dialed when the address table is empty, and also when no outbound
  connection is up (every known address may be stale or hostile), each seed at most
  every 30 s (R8-13).
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
| Unrequested `Block`/`Tx`, `Pong` without a ping, second `GetAddr` or oversized `Addr` | 10 |
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
  newer release. The first per peer is logged at WARN ("this node may need an
  upgrade");
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
  4. cheap checks: the stateless structure and balance rules (penalized), then the
     contextual rules a chain extension can change: key images, PX
     anchor, nullifiers, registry, pool, contract id (not penalized, cached as in 3);
  5. for PX and deploys, the node-wide PX token (below);
  6. full verification: ring signatures, range proofs, PX proof.
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
  - Tested: `px_transactions_travel_the_stem_and_confirm_everywhere`,
    `junk_anchor_px_floods_do_not_drain_the_px_relay_budget`.
- An invalid PX proof counts as a stateless violation (20). Once the anchor and
  registry checks pass, the proof's statement does not depend on our pool state, so
  an honest peer never relays one.

**Liveness:**
- The node pings every 60 s.
- A connection is closed after 180 s without any message, or when a pong is 30 s late.
- **The chain lock is never taken on an async worker thread** (P0-7, R8-1, R10-5).
  Every P2P handler and every RPC handler that reads or changes the chain runs that
  part on a blocking thread (`spawn_blocking`); the async workers only wait for the
  result. A long lock hold (a reorganization, a block with PX proofs, a drain step)
  delays only the requests that need the chain; pings, reads, accepts and handshakes
  of other peers keep flowing. Tested: `pings_are_answered_while_the_chain_lock_is_held`.
- **A poisoned lock stops the node** (P0-9, R10-2). A panic while holding the chain
  lock can leave the manager half-updated. The node then exits with status 70
  (`POISONED_EXIT_CODE`, the same in the P2P layer and the RPC) instead of relaying
  and building on that state; systemd (`Restart=on-failure`) or the operator restarts
  it, and the replay of the append-only block store rebuilds a consistent state. The
  same holds for the network state lock, and for a panic inside a blocking chain task.


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
  - **RandomX seed pinning** (the best chain's cache never evicted by side-branch
    seeds) is in the consensus crate, not here; the work gate removes the free
    trigger (headers of free branches are no longer hashed).
  - Bodies of stored side branches can still be stored before they are validated
    (the completion report's N-2), by an unrequested block whose header passed the
    gate.
  - A batch whose sender left before verification is only pre-checked: a sender
    whose batch would fail only the proof of work is not banned (it paid the real
    work of every header before the failing one).
- **One global chain lock.** Handlers no longer take it on async workers (§10), and
  block connection is bounded per hold (§6), but every chain access still
  serializes on it. Open:
  - A *single* block still holds the lock for its whole validation (up to ~3.4 s
    for a full block with 3 PX proofs not seen in the mempool), and a
    reorganization is not paused before its new branch outweighs the old tip.
  - PoW of a block whose header we never saw is computed under the lock (R8-1c),
    and relayed transactions are verified under it, one per connection at a time
    (R8-1d: stateless verification outside the lock is open).
  - Requests that need the chain (headers, blocks, transactions of a peer) wait
    for the lock on a blocking thread. Tokio's blocking pool is large (512
    threads), and each connection has at most one such request at a time, so the
    waiters are bounded by the number of connections.
- **Block worker.** Bodies of all peers are connected by one worker, in arrival
  order: a peer's large valid blocks delay other peers' blocks, not their pings.
  Block-download timeouts still use a fixed 60 s (no per-size or head-of-queue
  timer, R8-9); they are not penalized.
- **Header worker head-of-line blocking** (R8-15): a single-header tip announcement
  waits behind a full 2000-header batch; no priority lane yet.

- **Tor inbound.** Every inbound connection through a hidden service comes from
  127.0.0.1, so they share the per-IP limits (2 connections, 2 queued header
  batches) and a ban of one bans all of them.
- There is no compact-block relay; a full block is sent once per peer that lacks it.
- Dandelion++'s parameters follow Monero (q = 0.2, 39 s mean embargo), plus a 10 s
  embargo base. They have not been re-tuned for BlackSilk's network size.
