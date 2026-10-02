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
| Content confidentiality against passive observers (contents only, not sizes or timing) | Encrypted transport (§3) |
| Transaction origin privacy against spy nodes | Dandelion++ (§8) and randomized relay delays (§7) |
| Minimal fingerprint | No user agent, no clock, no services flags; own address not announced unless configured (§4) |
| Availability | Strict size and count limits, rate limits, misbehavior scoring, bans (§10) |
| Eclipse resistance (limited, §9) | Keyed *new*/*tried* address tables with a per-source bucket limit and test-before-evict; per-peer address admission limits; outbound diversity by network group; anchors, feelers and stale-tip rotation; inbound eviction (§9) |
| Correct sync under a lying peer | Header-first sync: every header is PoW-checked before any body is requested (§6) |
| Tor/I2P users | SOCKS5 proxy for outbound connections, proxy-only mode, onion addresses (§11) |

**Not protected in v1:**
- **An active man in the middle** can read and modify a connection. Peers are not
  authenticated; the encryption is opportunistic, like Bitcoin's BIP 324. A MITM cannot
  forge valid blocks or transactions, but he can observe and drop traffic: he reads the
  transactions a node originates (its stem, §8, so origin privacy is lost against him),
  and he can eclipse a node whose connections he controls (F48-1). An explicit `--peer`
  list does not stop him. A closed network can close this with a pre-shared key (§3);
  a public network cannot.
- **Traffic analysis** of sizes and timing. Frames are not padded
  (`FrameWriter::send`, §3), so **an observer of a node's own link** (its ISP, or
  its Tor guard) sees when the node sends a transaction-sized message that no peer
  sent it first: it learns that the node **originated** a transaction, **v1 as well
  as PX**. A PX transaction (about 2.2 MB) is unmistakable even over Tor; a v1
  transaction (a few kB, a few Tor cells) is a weaker signal over Tor, not a hidden
  one. Dandelion++ (§8) does not help against this observer; only padding or a
  private broadcast design would (transport v2, §3.1, design only).
- **Identification as a BlackSilk node.** The handshake is recognizable: the first
  32 bytes each way are canonical Ristretto encodings (about 8 bits distinguishable
  per connection, §3.1), and Ping/Pong are fixed-size frames every 60 s. A responder
  sends its encrypted `Version` right after the key exchange, before it can tell
  whether the initiator holds the network key, so an active prober recognizes a
  BlackSilk node even on a pre-shared-key network. Censorship resistance is not a
  goal of this version.
- **A global passive adversary** watching all links.
- **Block origin** (the IP of the node that mines). A node announces a block it mined
  as soon as it connects it (§6), before any relay could, so peers can tell which node
  found it. A miner that wants origin privacy runs its mining node proxy-only or over
  Tor (§11). Announcements get no random delay, on purpose: the per-hop cost is
  dominated by header verification and the body round trip (§12), so jitter large
  enough to hide the origin would add much more; any delay raises the stale-block rate,
  which favours large miners; and Monero and Bitcoin Core relay blocks without delay
  too.

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
k       = H64("p2p/session", LE32(network_id) ‖ genesis_id ‖ LE32(TRANSPORT_VERSION)
                             ‖ psk_flag ‖ psk ‖ A ‖ B ‖ S)
k_i→r   = k[0..32],  k_r→i = k[32..64]
```

- Every input has a fixed length: `network_id` 4 bytes, `genesis_id` 32,
  `TRANSPORT_VERSION` 4, `psk_flag` 1 (1 with a pre-shared key, else 0), `psk` 32 (zero
  without a key), `A`, `B` and `S` 32 each. A known-answer vector, computed outside
  the code, is the test `transport::tests::the_session_key_matches_its_known_answer`
  (`p2p/src/transport.rs`).
- `network_id` and the 32-byte `genesis_id` are bound into the keys (the genesis since
  testnet v3, R15-3: a release candidate or rehearsal with the same id but another
  genesis cannot join). Nodes of different networks or chains derive different keys,
  and the first frame fails to decrypt: a cross-network connection is detected without
  any plaintext network marker.
- **`TRANSPORT_VERSION` = 1** (`p2p/src/transport.rs`) is bound into the keys too
  (dossier 30 W5, changed before the v3 testnet launch). It is not negotiated. A node of
  another transport version derives other keys and fails at the first frame, so two
  transports never talk. **No fallback:** a later transport is either a flag day or an
  in-band extension negotiated inside this one; a node never falls back silently to a
  weaker transport. The message protocol version (§4.1) is deliberately *not* in the
  keys: it is negotiated in `Version`, and a peer below `MIN_PROTOCOL_VERSION` is refused
  there with a clear reason.
- **Closed-network pre-shared key** (optional, F48-1). A private test network can give
  every member the same 32 secret bytes (`NetConfig::network_psk`; a file of 64
  hexadecimal characters, for example from `openssl rand -hex 32`, read by
  `NetworkPsk::load`). The key is mixed into `k`, so a node without it, or with another
  key, fails at the first frame, and so does a man in the middle: without a key he can
  run the handshake with both ends and read everything (`p2p/tests/transport_adversarial.rs`,
  `a_man_in_the_middle_reads_the_traffic_unless_a_psk_is_set`). Limits: one leaked key
  reopens the hole for everyone; members are not authenticated to one another; the key
  is never printed (its `Debug` is redacted). It must never be required on a public
  network.
  - **Key hygiene** (RTW3-12). The file is read into a buffer wiped on drop (at most
    4 KiB) and decoded straight into the key's own wiped storage, with no copy in a
    temporary. On Unix a key file its group or other users can read is logged as a
    warning (the node still starts). The shared point `S`, its encoding and the session
    key `k` are held in wiped buffers. Residuals: the BLAKE2b state inside the key
    derivation is not wiped (the `blake2` 0.10 crate has no zeroizing state), and
    temporary copies the compiler makes are outside the program's control.
- Ephemeral keys protect a *finished* session against a later compromise of either
  node's long-term state: nothing long-term exists to steal. They do **not** give more
  than that:
  - There is no rekeying. Whoever obtains a session key while the session runs (for
    example from the memory of a running node) can decrypt the whole session, including
    what was sent before.
  - The AES key schedules are wiped when a session ends (`aes`/`aes-gcm`/`polyval`
    `zeroize` features, W3-44). Residuals: polyval's aarch64 PMULL backend and ghash's
    temporary copies of H are not wiped upstream.
  - A future attacker able to compute discrete logarithms in Ristretto255 can decrypt
    recorded sessions (harvest now, decrypt later; the hybrid ML-KEM step of transport
    v2 below addresses it).

**Frames:**

```
frame = AEAD(k_dir, n,   LE32(len))      4 + 16 bytes
        AEAD(k_dir, n+1, payload)        len + 16 bytes
```

- AEAD is AES-256-GCM. The nonce `n` is a 96-bit little-endian message counter that
  starts at 0 and increases by 2 per frame, separately for each direction. A replayed,
  reordered, reflected or truncated frame fails (tests in `p2p/src/transport.rs`).
- `len ≤ MAX_FRAME = MAX_BLOCK_BYTES + 64 KiB` is checked right after the length decrypts, before
  any payload is read. Before `Verack` the limit is `MAX_HANDSHAKE_FRAME` = 4096 bytes
  (§4).
- Any decryption failure ends the connection. It is **never scored and never bans**
  (§10): anyone on the path can cause one by flipping a bit, and a node of another
  network, genesis, transport version or pre-shared key causes one at the first frame.
  It is counted in `NetStats::transport_failures`. Both ends send their first frame at
  once, and the end that reads first fails and closes, so a refused connection is
  counted on at least one side, not necessarily on both.
- The counter never wraps: 2^64 frames are unreachable.

### 3.1 Transport v2 (design notes; not implemented)

Decided for the v3 genesis if it is complete and adversarially tested by the protocol
freeze (decisions log, agent 30 W6); otherwise v3 ships the transport above and v2
comes later through `TRANSPORT_VERSION`, as a flag day. There is no partial v2. The
design (dossier 30 §5 W6):

- **Keys:** ephemeral Ristretto255 keys sent as 64-byte Elligator-Squared encodings, so
  the first bytes are uniform. Today a passive observer who decodes the first 32 bytes
  of each direction recognizes a BlackSilk handshake with about 8 bits of confidence per
  connection.
- **Garbage:** 0 to 4095 random bytes and a derived 16-byte terminator (BIP 324
  pattern); the garbage is authenticated as the first frame's associated data.
- **Key schedule:** the same inputs as above with `TRANSPORT_VERSION = 2`, over the exact
  encodings sent.
- **Hybrid post-quantum step:** an ML-KEM-768 exchange inside the encrypted channel,
  then a switch to `k' = H64("p2p/session-pq", k ‖ ss_pq ‖ H(transcript))` at a defined
  frame in each direction. The encapsulation key is checked (FIPS 203) before use.
- **Length block with flags:** a decoy bit, and a size class checked against the message
  type (a block-size frame only while a block request to that peer is outstanding).
- **Rekeying** every 224 frames per direction; a **session id** shown to operators for
  comparing manual links out of band.
- **Tests owed before activation:** encoding uniformity statistics and round trips,
  known answers, the terminator search bound, the PQ switch point, `ek` validation,
  fuzzing of the ML-KEM inputs, and v1-against-v2 failing cleanly with no fallback.
- New dependencies (curve25519-dalek 5 with `lizard`, in `p2p` only; `ml-kem`) are
  conditional on the supply-chain review (agent 44).

## 4. Handshake and version negotiation

Both sides send `Version` as their first frame and answer the other's `Version` with
`Verack`.

```
Version {
  protocol:  u32        currently 3 (below); peers below MIN_PROTOCOL (3) are disconnected
  network:   u32        must equal ours (defence in depth; §3 already separates networks)
  nonce:     u64        random per connection; equal to one of our own nonces = self-connection
  height:    u64        best header height (a hint for sync, not trusted)
  tip:       [u8; 32]   best header id (a hint: an id we cannot place makes us ask
                        for headers once, §6)
  listen:    optional NetAddr   our reachable address, only if the operator configured one
  relay_txs: bool       false = block-relay-only connection
}
```

- There is deliberately **no user agent, no timestamp and no service bits**. Each would
  fingerprint software versions or clocks.
- **Before `Verack`** (dossier 30 W1) the peer is unregistered, so no message or byte
  budget applies to it yet. The handshake therefore has its own limits:
  - only `Version`, then at most 8 frames of unknown types (§4.1), then `Verack`. Any
    other message, a malformed one or a ninth unknown frame closes the connection;
  - every frame is at most **`MAX_HANDSHAKE_FRAME` = 4096 bytes** (`p2p/src/message.rs`),
    refused as soon as its length decrypts;
  - the key exchange must finish within **5 s** on clearnet and 10 s over Tor (a proxied
    outbound connection, or an inbound one through our hidden service), and the whole
    handshake, from the TCP connection to the peer's `Verack`, within **20 s** (one
    deadline, not one per frame; the margin is for Tor round trips). The 5 s bound
    (RTW3-3) makes a connection that sends nothing leave after one key-exchange round
    trip's allowance, not after the whole deadline.

  A failure only closes the connection. Nothing is **scored or banned** before
  registration: the peer is unauthenticated, and its address may be a proxy's, a hidden
  service's loopback, or spoofed by whoever is on the path. At most about 40 KiB can
  arrive per handshaking connection (10 frames of 4 KiB). Handshaking inbound connections
  have their own bounds and are the first to be evicted (§9, "Inbound").

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
  node skips up to 8 frames of unknown types there. Each must fit in
  `MAX_HANDSHAKE_FRAME` (4096 bytes), and the whole negotiation in the 20 s handshake
  deadline: deployed nodes enforce both, so a later version cannot relax them without a
  flag day.
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

1. **Start.** After the handshake, send `GetHeaders(locator)` if the peer's `height`
   exceeds our best header height, **or** its `tip` is not one we can place on our best
   header chain from the published snapshot (our best header, our connected tip or a
   locator entry; genesis is always one). Address fetches are never asked.
   - The locator holds ids of our best header chain: the tip, then 10 predecessors one
     by one, then exponentially sparser ones back to genesis (at most 64).
   - **Why the tip, not only the height (W4-SYNC, RT-LAB F1).** Fork choice is by work,
     not height. Before 2026-09-30 only a greater height triggered the request, so two
     nodes meeting on branches of **equal height** (a healed partition) asked each other
     nothing until the next block (12.5 s in labnet run 4), and a node on a **longer but
     lighter** branch never asked a shorter, heavier peer at all. Now the lighter side
     asks, gets the heavier branch and reorganizes without waiting for a block
     (`equal_height_branches_converge_on_the_heavier_without_a_new_block`,
     `a_shorter_heavier_branch_wins_over_a_longer_lighter_one`).
   - **Bounded.** It is one request per connection: an empty or non-advancing answer
     lowers the peer's claimed height to ours ("Non-advancing replies" below), and a
     branch below the work gate's threshold is dropped unhashed. A peer naming a fake
     tip costs one `GetHeaders` and the checks of one answer
     (`a_fake_version_tip_costs_one_header_request`,
     `rt_sync_fake_tip_churn_with_stored_headers_hashes_nothing`). A lighter branch that
     still reaches `anti_dos_threshold` (a near-tip competitor) **is** hashed, so the
     answer can cost one proof-of-work chunk (`pow_threads` headers) before a junk header
     gets the sender banned; the old height claim allowed the same. This is what Bitcoin
     Core does
     once its best header is less than a day old: it sends `getheaders` to every new
     peer that can serve blocks, whatever its claimed start height
     (`net_processing.cpp`, `fSyncStarted`). We skip a peer whose tip we can place. A
     peer behind us on our own chain answers with headers we have (skipped
     unhashed).
   - Nothing new is sent or revealed: the `Version` already carries our best header id
     and height, and the locator is public chain data. Block-relay-only connections
     keep their restrictions (no addresses, no transactions); header sync is theirs.
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
     the batch or the existing chain). With one thread a chunk is hashed inline on
     the worker's blocking thread; with more, the worker's thread hashes alongside
     up to `pow_threads - 1` helper threads of a persistent pool owned by the PoW
     cache (`CachedPow::compute_parallel`), started once, not per chunk: under CPU
     contention a thread started per chunk waited 13-130 ms for the scheduler
     (W4-POWPOOL, docs/evidence/pow-pool-2026-10-01/). The worker never waits for a
     busy helper, and each thread holds one RandomX cache at a time (the cache
     store's caller rule). Each chunk is accepted before the next is
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
       tip announcement that crossed our request. It answers the request, but the
       request's reply is still **owed**: one later batch of other than one header,
       arriving within 60 s of the request, still counts as solicited (the real
       reply). Before 2026-09-27 that reply cost the honest sender 10 points and was
       dropped.
     - A request that times out (60 s) is owed the same way for another 60 s: its
       late reply is accepted, unpenalized.
     - The node asks again as soon as nothing is outstanding, so a slow peer can owe
       several replies; each one owed (at most 8 remembered) excuses exactly one
       batch. Every `GetHeaders` still buys at most one batch. Before P2P-FIX2 a new
       request cancelled the owed reply, whose arrival then cost the honest sender 10
       points. Under CPU load this happened while syncing from a peer that was itself
       syncing and announcing every new tip (the flake of
       `px_transactions_travel_the_stem_and_confirm_everywhere`; regression test
       `a_headers_reply_overtaken_by_a_second_request_is_not_penalized`).
   - **At most one batch per peer** is queued or being verified. The peer is not asked
     for more headers meanwhile; headers arriving from it in that time are dropped,
     and the node asks again once the batch is done (whatever its outcome, unless the
     peer was penalized). A dropped header is neither verified nor scored, so whether
     a rule-breaking announcement is penalized at once depends on whether the
     sender's batch is still in flight; what the peer sends in answer to the new
     request is verified and scored as usual (test
     `a_header_announced_during_a_batch_is_asked_for_again_and_scored`).
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
to every peer (address fetches excepted) that is not known to have it. A peer that lacks
the body asks for it with `GetBlocks`.
- **Known to have it** (`Peer::wants_tip`): the peer has the new tip itself, or our
  current best header while the new tip is on the best header chain (the tip is then an
  ancestor of it). "Has" means it named that header as its `Version` tip, or it is the
  last header of the heaviest batch from the peer that we accepted. Both are compared
  with the **current** snapshot (`best_header_id`, `ChainSummary::tip_on_best_chain`),
  never with a flag recorded earlier: after a branch is invalidated the best header
  changes, and the relayer of that branch gets our next tips
  (`rt_sync_tips_after_an_invalidated_branch_are_announced_to_its_relayer`). While the
  tip is not on the best header chain (a heavier branch's bodies are missing, or
  withheld) only the exact-tip rule applies.
  - Before W4-SYNC (2026-09-30) the announcement went only to peers whose claimed height
    was below the new tip's, so a peer on a longer but lighter branch never heard of our
    heavier tip (`a_new_tip_is_announced_to_a_peer_on_a_longer_lighter_branch`).
  - A node draining bodies behind the best header a peer gave or named does not announce
    the intermediate tips to that peer
    (`rt_sync_a_draining_node_does_not_echo_tips_to_a_peer_ahead`).
  - Bitcoin Core announces a new tip to every peer that does not have it
    (`PeerHasHeader`), by ancestry of each peer's best known block. The snapshot cannot
    answer ancestry without a chain command, so a peer whose best header lies on our
    best chain between our connected tip and our best header (a peer slightly behind
    the network while we catch up) may still get redundant headers until our best
    header reaches its tip: each is one stored header (no hash), at the rate below.
  - Each peer is considered once per tip (`Peer::announced`). At registration it is set
    to the connected tip of the snapshot our `Version` came from, and the announcer runs
    once more, so a tip connected during the handshake is announced
    (`rt_sync_a_tip_found_during_the_handshake_is_announced`; before, a global "last
    tip announced" blocked it).
- **When** (RT-LAB F2): as soon as the chain publishes the new tip. The summary cell
  calls its tip listeners after every publication that changes the connected tip
  (`SummaryCell::on_tip_change`); the P2P layer's listener wakes the announcer
  (`maintenance::announce_loop`), which announces at once and then waits at least
  `ANNOUNCE_MIN_GAP` (100 ms) before the next announcement. The maintenance tick still
  announces a tip the announcer has not (fallback), so a burst of tips (a body drain,
  initial sync) costs a peer at most about 14 announcements per second with the default
  250 ms tick (10 from the announcer, 4 from the tick), the tips in between skipped. Before, only the tick announced: half a tick (125 ms by default) per hop
  on average. The delay from publication to a peer's receipt is measured by
  `announcement_latency_with_the_default_tick` (`--ignored --nocapture`); a test with a
  5 s tick checks that announcements do not wait for it
  (`tip_announcements_do_not_wait_for_the_maintenance_tick`). A hop is still dominated
  by the light-mode RandomX verification of the header and the body round trip
  (§12).

### 6.1 The local clock and the clock-offset monitor

The future time limit (consensus.md §5, `FTL` = 360 s) is checked against the local
clock only. Nothing corrects that clock: there is no peer time, and `Version` carries
no clock (§4), since a clock's skew identifies a device (Kohno, Broido and claffy 2005;
Murdoch 2006).

- **A slow clock** (more than `FTL` behind) refuses every new tip as too far in the
  future. That refusal is not permanent and not penalized (§10); the header is not
  stored, and it is accepted once the clock reaches it, from the next header request
  or announcement. Until then the node falls behind the network.
- **A fast clock** accepts blocks normally, but a miner on the same machine stamps its
  blocks from it (the miner reads its own clock), so they can exceed the other nodes'
  limit and be refused there (not penalized). A fast clock also makes the connected tip look old to
  the template gate's catch-up latch (blocks.md §9.4); a slow one makes it look recent.
  The wallet's tip-age check (blocks.md §10, RTW3-6) reads the wallet machine's clock
  and is tripped by a wrong one too.

**Monitor** (`blacksilk_p2p::clock`, dossier 04 P2; warn-only). It estimates the local
clock's offset against recent blocks, logs a warning when the offset is large, and is
never used in any check or sent to a peer:

- **Samples.** (1) A header batch that is not a bulk-sync batch (fewer than
  `MAX_HEADERS` headers) and extends the best header chain gives the offset
  `timestamp − arrival` of its last header, once its proof of work is verified. An
  honest sample is a few to a few tens of seconds below zero (template age plus
  propagation). (2) A header refused only by the FTL is remembered (at most 64, first
  sighting kept); if the same header is later accepted with its proof of work verified,
  `timestamp − first sighting` is a sample. This is what a slow clock produces. An
  unverified refusal is never a sample: the FTL is checked before the proof of work, so
  it costs a forger nothing.
- **Estimate.** The lower median of the last 25 samples (one per block), reported once
  5 samples from 3 distinct peers are held (`Network::clock_estimate`). Every sample
  needs a header with valid proof of work at the chain's difficulty. A peer that delays
  blocks (an eclipse) pushes the estimate below zero, which the warning names as a
  possible cause; it cannot make the clock look slow without mining.
- **Warnings.** WARN above `FTL/3` (120 s), ERROR above `FTL`, repeated at most every
  10 minutes while they last, and one INFO line when the estimate is back below `FTL/6`.
- **Tested** by the unit tests of `p2p/src/clock.rs` (the median, the sample and peer
  minimums, the one-sample-per-block window, retro-confirmed refusals, the refusal list
  bound, levels, the repeat limit and the hysteresis). No network-level test injects a
  clock skew yet: the clock is not injectable (dossier 04 W2, open).

## 7. Transaction relay (fluff phase)

- **Announcing.** A transaction in the mempool is announced with `InvTx`.
  - Announcements to each peer are batched and sent after an independent random delay
    (exponential, mean 2 s for outbound peers and 5 s for inbound peers).
  - This makes the first announcer hard to find by timing (the "diffusion" of
    Dandelion++).
- **Requesting: the transaction request tracker** (`net/tx_requests.rs`, RT2-TM2P2P
  redesign, 2026-10-02; prior art: Bitcoin Core's `TxRequestTracker`, txrequest.cpp).
  - **State.** One record per (transaction id, announcing peer): *candidate* (with
    the time it may be asked), *requested* (with its expiry) or *done* (answered
    without the transaction, timed out, or refused). One record per id holds its
    hard deadline, its count of timeouts and an optional node-wide pause. Every
    tracked id has a timer: the earliest of its deadline, its requests' expiries,
    its candidates' ready times and its pause. There is no queue in which an id
    waits without a request and a timer (RT2 F1). Due timers run in time order,
    each as of its own time, and before any event (an announcement, an answer):
    what happens never depends on when the maintenance tick comes.
  - **Who is asked.** A candidate is ready at once if its peer is outbound
    (*preferred*), 2 s after its announcement if inbound (Core's
    `NONPREF_PEER_TX_DELAY`). Among the ready candidates whose peer has room, the
    node asks preferred ones first, then by a per-node random priority of (id, peer)
    (a salted hash): announcing first, or many times, buys no place in the order.
  - **How many at once.** One request per id is outstanding until the first one
    times out (30 s); from then on up to 4, to 4 different announcers, each replaced
    as it ends. A `NotFound` or a disconnect ends a request at once and the next
    candidate is asked. A request that timed out is asked once more of the same
    peer, as a last resort after every fresh candidate (its answer may have been
    dropped by this node's own slow lane); never a third time.
  - **Per-peer caps.** A peer may have at most 2 000 ids tracked (its announcements
    beyond are ignored) and at most 16 requests in flight, and at most
    `SLOW_LANE_BYTES` of expected answers in flight (each request counted at the
    size of that peer's last answer, at least 8 KiB, and at half that budget before
    its first answer; a PX answer is about 2.2 MB, so two PX requests at once). A candidate whose peer is at a cap is skipped, not
    queued: junk from one peer consumes only that peer's own allowance (RT2 F1,
    F4).
  - **Busy.** An answer this node drops for the peer's relay share or a full
    transaction lane is not the transaction's fault: that record goes back to
    candidate behind the others, and the next candidate is asked now; after 2 such
    drops for one (id, peer) the record is done (RT2 F2: an announcer could keep its
    own answers Busy forever). An answer dropped for the node-wide PX share pauses
    the id (not the peer) for 1 s, then it is asked again. The per-peer relay share
    is charged only after the already-pooled, known-rejected and conflict checks.
  - **Deadline.** An id is dropped, with all its records, 20 minutes after its first
    announcement, or as soon as every record is done. It comes back with a later
    announcement (pool re-announcement, §7 below).
  - **Worst-case delay bound.** Let `k` announcers of an id never answer, and one
    honest announcer answer. The honest one is asked within
    `2 s + 30 s × (1 + ⌈k / 4⌉)` of its announcement: at most 2 s of delay, one
    first request that may time out, then 4 at a time. If it is outbound and the
    attackers inbound, within 32 s. The deadline holds that bound up to `k = 152`
    (more than the 64 inbound slots). With the random priority the expected delay is
    about half the bound. Before the redesign: about 30 s per silent announcer in
    arrival order (`rt_eight_silent_first_announcers_do_not_suppress_an_honest_one`:
    240 s for 8; about 58 minutes with 117), and without bound behind one announcer's
    junk queue (`rt2_a_timed_out_request_is_not_parked_behind_a_junk_queue`).
  - **Late answers.** The answer to a request that timed out is still accepted from
    the peer asked for another 30 s, unpenalized, as a late block is (at most 10 000
    such requests remembered). Before P2P-FIX2 it was an unrequested `Tx` (10 points)
    and was dropped, so a node or link slow for 30 s penalized honest peers
    (`a_late_transaction_answer_is_not_penalized`).
  - Neither a timeout nor a `NotFound` is penalized: transaction relay is best
    effort.
  - Tested: the tracker's property test (random announce, answer, `NotFound`, Busy,
    timeout and disconnect sequences; invariants: every id has a request or a timer,
    no cap is exceeded, at most one request per id before its first timeout and 4
    after, an honest announcer is asked within the bound) and the network tests named
    above, `rt_a_px_burst_from_one_announcer_is_relayed_in_full` and
    `rt2_an_announcer_kept_busy_does_not_hold_a_transaction` (PX-proving).
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
  - The answer is **paced** (TM2-17; `net/serve_tx.rs`): at most `SERVE_TX_BYTES`
    (`MAX_RELAY_FRAME`, at least one transaction) per step, and each `Tx` is queued
    only while the peer has fewer than `SERVE_TX_FRAMES` (32, half its control
    outbox) answers queued or being written. The rest of the outbox stays free for
    pongs and announcements. Meanwhile that peer's slow lane waits, as Bitcoin Core
    stops processing a peer's messages while its send buffer is full. The
    `NotFound` comes last and ends the answer. An id named twice in one `GetTx` is
    answered once.
  - **Budget** (RT-TM2P2P, RT2-TM2P2P F3): `GetTx` answers hold at most
    `SERVE_TX_TOTAL` (64 MiB) node-wide, whatever the number of peers. A step holds
    exactly its transactions' sizes (measured before they are encoded for sending),
    from the peer's own share (`SERVE_TX_PEER`, 8 MiB) and then from a pool:
    outbound peers use a slice of their own (16 MiB), inbound peers the rest. Both
    are waited for in arrival order (FIFO semaphores). Each byte comes back when its
    frame is written, or when its peer disconnects. A step that finds no room for
    `SERVE_TX_STALL` (60 s) ends with `NotFound` for the rest, and the requester asks
    another announcer. Before RT2-TM2P2P every step reserved a full
    `SERVE_TX_BYTES` (4.5 MB) however small its transactions, without fairness, so
    about eight slow readers held the whole budget.
  - **Slow readers.** A peer holding more than `SLOW_SHARE` (4 MiB) of the budget
    whose oldest queued answer is not written within `SLOW_BASE` (10 s) plus its
    size at `SLOW_RATE` (64 KiB/s) is disconnected (no ban). So is one that lets no
    answer be written for `SERVE_TX_STALL` while more wait, as when its outbox
    overflows. One that reads slowly otherwise is bounded by the pong timeout
    (§10): its pings queue behind its answers.
  - Before TM2-17 every answer was queued at once, and the first that found the
    64-message outbox full disconnected the requester as a slow reader: one `GetTx`
    for more than 64 transactions, which an honest node sent for any burst, cut the
    link, and with it a Dandelion stem route, which the requester then re-drew
    mid-epoch (`a_gettx_for_more_transactions_than_an_outbox_is_served_in_full`, the
    burst test above; repeated ids, `a_repeated_id_in_one_gettx_is_answered_once`).

- **Pool re-announcement** (dossier 38 §3.4 item 3, `net/maintenance.rs`). Every node
  announces again, with `InvTx` like any announcement above, each pooled transaction
  that is still in its next block template, at fixed pool ages: 10, 20, 40, 80, 160,
  320, 640 and 1 000 blocks (the gap doubles from 10 and is capped at 360), and never
  after 1 080 blocks (half the pool expiry, blocks.md §7).
  - The age counts from the height the node pooled the transaction for: at or after
    its fluff, or the readmission after a reorganization returned it. Honest nodes
    pool a transaction within seconds of each other, so they re-announce it at the
    same heights, and the origin counts exactly as they do, never with a `StemTx`.
  - A restarted origin whose wallet resubmits its transaction does not pool it
    (§8.1): like a restarted relay, it has the transaction only once a peer
    announces it and it fetches it, and it re-announces it from that pool height
    (`rt_a_restarted_origin_answers_an_inv_probe_like_a_restarted_relay`,
    `a_restarted_origin_never_reannounces_its_held_copy`).
  - Before TM2-P1 (2026-10-02) the origin counted from the height it relayed the
    transaction for when that was earlier. That height is fixed at submission,
    before the stem, so a block found during the stem made the origin alone
    re-announce one block (about 2 minutes) before every other node, and a
    reorganization that returned the transaction made it re-announce early or at
    once, while every other node counted from the readmission: a spy opening fresh
    connections identified the origin with certainty
    (`a_block_found_during_the_stem_does_not_make_the_origin_reannounce_first`,
    `after_a_reorganization_the_origin_reannounces_with_everyone`). A restarted
    origin re-announced the copy it pooled for its wallet from its relay height
    too.
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
  - The embargo ends only when the transaction arrives fluffed (a peer's `Tx`, which
    moves it to the mempool), or when the node fluffs it itself. An `InvTx` alone does
    not end it, and neither does the transaction's inclusion in a block: a mined stem
    transaction stays in the stempool until its timer fires, and its fluff then fails
    harmlessly (logged at debug level). When the timer fires first, the node fluffs it
    itself.
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
  written to disk before the transaction leaves the node. The relay height decides
  only the windows below, never the re-announcement schedule (§7).
- **Resubmission** of a transaction in the set, for inclusion at next height `h`
  (relayed for `r`):
  - already in this node's stempool: nothing is sent, and `/tx` accepts it;
  - `h < r + 2 160` (the pool expiry, blocks.md §7): other nodes most likely still
    pool it. It is **held**: checked as any submission is, and `/tx` accepts it (or
    answers what the pool answers, e.g. `AlreadyKnown`), but it is neither stemmed,
    announced nor pooled. The node then holds it exactly as a restarted relay does:
    not at all, until a peer announces it; then it requests it with `GetTx`, pools
    it, and re-announces it from that pool height, like any node (§7). Before
    RT-TM2P2P (2026-10-02) a held copy was pooled: an `InvTx` probe for it got no
    `GetTx` where a restarted relay asks, and it expired at its own height, later
    than the network's copies;
  - `r + 2 160 ≤ h < r + 2 190`: other nodes expired it recently and refuse it from
    their own wallets. It is refused here too, as `Expired`, also after a restart,
    when the pool's in-memory guard is gone;
  - `h ≥ r + 2 190` (`NETWORK_EXPIRY_BLOCKS`, 2 160 + 30, derived from the pool's
    constants): the network has dropped it, the entry is gone, and the transaction is
    originated again as a new one, through the stem.
- **Only local origination.** A peer's `StemTx` or `Tx` is admitted and relayed
  whether or not its transaction is in the set (as for the guard, RTW1B-1).
- **Persistence.** `originated.json` in the data directory, owner-only (0600 on Unix
  whatever the umask; `p2p::private_file`, RT-NODEOPS) (format 1: id and relay
  height; a format 2 file, written by an unmerged development version with a pool
  height per entry, is read with that field ignored): written to a temporary file,
  synced and renamed (a crash leaves the old or the new set), whenever the set
  changes. Entries are dropped when their window ends; at most 10 000 are kept, oldest
  dropped first (logged). A missing file is an empty set; one that cannot be read is
  logged as an error and an empty set is used, so the node may then originate one of
  its old transactions again. A damaged file fails closed (RT-TM2P2P): each entry is
  parsed on its own and a malformed one is dropped alone, a duplicate id keeps its
  highest height, a missing or unknown version does not stop the entries from being
  read, a file that is not JSON (torn) is scanned for the entries it still holds, and
  every damage is logged as an error and the set written back clean. Before, one bad
  entry or a version mismatch discarded the whole set. A height counts only if the
  entry's `]` follows it: a height cut by a tear (`81234` torn to `81`) would end the
  window about 81 000 blocks early, so such an entry keeps its id with the next
  height at start-up instead (a window starting late, never early;
  `rt2_a_torn_height_is_not_salvaged_short`). On Unix the directory is synced after
  the rename, so the rename itself survives a power loss.
- **The wallet side** (wallet `sync`) asks `/tx/status` instead of re-posting, and
  re-originates at most once, after `relayed + 2 190` (px.md §12).
- Tested (`p2p/tests/network.rs`, over TCP):
  `a_restarted_origin_does_not_reoriginate_a_transaction_the_network_holds` (no
  `StemTx` and no `InvTx` after a restart), `an_expired_local_transaction_is_not_reoriginated_inside_the_window_even_after_a_restart`
  (`Expired` up to the window's last block after a restart, then one `StemTx`),
  `a_peers_stem_of_a_transaction_this_node_originated_is_relayed`,
  `a_restarted_origin_never_reannounces_its_held_copy` (silent while a relay
  re-announces it), `rt_a_restarted_origin_answers_an_inv_probe_like_a_restarted_relay`,
  the unit tests of `originated.rs` and `p2p/tests/rt_originated.rs`.
- **Limits.** The set protects against re-origination by this node only. A wallet
  that submits the same transaction to another node, or a node without this set,
  still re-originates it. A held transaction is not pooled, so this node's own
  miner does not include it until it is learned back from a peer. A transaction the
  whole network dropped early (a full-pool eviction wave) is still not originated
  again before `r + 2 190`. Every independent re-origination is another sample for a
  spy (dossier 33 F33-3).

**Limitations.**
- Dandelion++ gives statistical origin privacy against spy nodes that control a fraction
  of the network. It does not help against an adversary who observes a node's own
  network link (§1: frames are not padded).
- Over Tor (§11) that observer is the Tor guard, which still sees a PX transaction's
  size, and a v1 transaction as a weaker signal.
- A spy can make stems fail: a relayer drops a relayed `StemTx` silently when its PX
  relay budget is exhausted (§10), which spies can cause, and the origin's own
  embargo then fluffs the transaction first, naming the origin to its peers. There is
  no local re-stem on the first embargo expiry and no separate PX embargo (dossier 33
  W3, W4: not implemented).
- No privacy regression suite tests these properties (docs/STATUS.md §3).

## 9. Peer discovery and the address manager

- **Seeds.** Seed nodes come from `--seed` or a built-in list. The built-in list is empty
  until the testnet is launched. They are asked for addresses in one-shot connections
  (below), never kept as peers.
- **Address exchange.** After each full-relay outbound handshake, and on a seed's address
  fetch, the node sends `GetAddr`. No address is exchanged on a block-relay-only
  connection (below), either way. A peer
  answers with at most 1000 random known addresses, at most once per connection, and
  **only to inbound peers**: a `GetAddr` from a peer the node dialed is ignored
  (unpenalized). Answering it would let a peer plant unique addresses in a node's
  table and recognize them later from another session, IP or Tor circuit, linking the
  node's sessions (Biryukov and Pustogarov, "Bitcoin over Tor isn't a good idea",
  IEEE S&P 2015; Bitcoin Core does the same, F32-4). The answer holds at most 23 % of
  the table (rounded up; Bitcoin Core's `MAX_PCT_ADDR_TO_SEND`) but at least
  min(table size, 8) addresses (`addrman::GETADDR_MIN`), and no terrible entry (below).
  Its entries carry time 0 ("unknown"): the table's times stay local, so the answer
  reveals nothing about them or the node's clock.
  - **The floor of 8** (P2P-FIX2, Lead decision after INV-PEERS). With 23 % alone a
    table of up to 4 entries answered 1 address, so a joiner on a small network
    stopped below its outbound target: a joiner with one seed and a target of 4, on
    a network of 4 advertised nodes, often did not fill it
    (`a_joiner_with_one_seed_fills_its_outbound_target`).
  - **Privacy cost.** A table of at most 8 entries is revealed whole to one
    `GetAddr`, and tables up to 34 entries answer more than 23 %. Above 34 entries
    the 23 % cap governs, as before. A spy could already sample a small table fully
    by reconnecting (one answer per connection); an attacker's own table is large,
    so the floor gives it nothing (the eclipse simulator's output is unchanged).
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
  - The node's own address (`--public-address`) is relayed like any other but not
    stored. It is never dialed, and in a small table it could take the one entry a
    `GetAddr` answer carries. Before INV-PEERS a 4-node labnet's joiner that knew one
    node learned only that node's own address in 7 of 32 runs, and stayed with one
    peer (`a_node_does_not_store_its_own_address`).
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
  operator sets `--public-address`, so private nodes are not revealed, and never on a
  block-relay-only connection (ours, or an inbound peer's that sent `relay_txs =
  false`).
  - An onion address is advertised only over Tor (proxied outbound connections, and
    inbound ones through the hidden service: on the onion listener, §11, or from loopback
    when there is none and `allow_private` is off); a clearnet address only over
    clearnet. A dual-homed configuration logs a warning at startup. Before
    2026-09-27 an onion address was sent to clearnet peers too, linking the node's
    two identities (I3-2).
  - After each handshake the node also sends the same address to the peer as a
    one-entry `Addr`, timed now rounded down to 5 minutes (so the peer relays it, and
    the time reveals the node's clock no finer than that).
  - **Discovery depends on it.** A node that does not set `--public-address` never
    enters another node's table: a successful outbound connection promotes only an
    address the table already holds (`AddrMan::good`), so the addresses a node dials,
    manual peers included, are not learned from it either. A network whose nodes all
    run without it gives a joiner nothing to discover (INV-PEERS: the W4-RX labnet,
    `nodes_that_do_not_advertise_are_not_discovered`). Before addrman v2 (W3-32) every
    successful dial inserted its address into *tried*, so a node's `GetAddr` answer
    revealed the addresses it had dialed.
- **Address manager** (`p2p/src/addrman.rs`; v2 since W3-32, after Bitcoin Core's).
  Two tables of fixed slots: *new* (256 buckets × 64 slots: heard of) and *tried*
  (64 × 64: this node connected to it).
  - **Placement** is a keyed hash. The `key` is random, local to the node and saved with
    the table, so an attacker cannot predict placement. `H(d, parts…)` below is
    `H32("p2p/addrman", key ‖ d ‖ (len ‖ part)…)`, first 8 bytes:
    - *new* bucket: `h1 = H(0, group(addr), group(src)) mod 16`, then
      `H(2, group(src), h1) mod 256`. **One source group reaches at most 16 of the 256
      buckets**, whatever addresses it announces. Before v2 the bucket was
      `H32(secret ‖ table ‖ group(addr) ‖ group(src)) mod 256`, so one source reached
      all of them (R8-3; `one_source_group_reaches_at_most_16_new_buckets` fails on
      bff3a62 with 256 of 256).
    - *tried* bucket: `h1 = H(1, addr) mod 2`, then `H(3, group(addr), h1) mod 64`: one
      group reaches at most 2 buckets.
    - Slot: `H(4 + table, bucket, addr) mod 64`. An address has exactly one slot.
  - **Flooding evicts nothing that works.** A new address whose slot is taken is
    dropped, unless the occupant is *terrible*. Before v2 a full bucket evicted a random
    entry. Terrible follows Bitcoin Core's `IsTerrible`, and never applies within a
    minute of an attempt. An entry is terrible if:
    - it was not heard of or connected to for 30 days;
    - it failed 3 attempts and never connected;
    - it failed 10 attempts and had no success for 7 days.
  - **Promotion and test-before-evict.** An address moves to *tried* when an outbound
    connection to it (full-relay, block-relay-only or a feeler) completes its handshake.
    Inbound connections and seeds' address fetches never promote. If its *tried* slot
    holds another address, or its class is full (below):
    - the newcomer waits in *new* (at most 10 wait), and a feeler tests the occupant;
    - the occupant stays if it connected in the last 4 hours (an outbound peer this
      node is connected to counts as connected now);
    - the newcomer replaces it if an attempt on it failed, at least a minute ago;
    - if it was not tested within 40 minutes, the collision is dropped and the occupant
      stays (RTW3-9). Bitcoin Core replaces it then; an occupant this node could not
      test has shown nothing wrong, and an answering attacker address must not displace
      a working entry by default;
    - a replaced *tried* entry goes back to *new*.

    *tried* holds **one address per IP**: another port of that IP that connects
    replaces it (F32-9). It also holds at most **16 addresses per source group** (the
    group of the peer an address was first heard from; `TRIED_PER_SOURCE_GROUP`,
    W3-32c): feelers and regular dials promote whatever answers, so without the cap an
    attacker's answering addresses, announced from its few source groups, filled
    *tried* in proportion to their number. It holds **one onion address per onion group**
    (`TRIED_PER_ONION_GROUP`, W3-32c): onion names cost nothing, so before this cap every
    answering onion an attacker announced could reach *tried*. A newly connected onion
    whose group already has its entry waits as a collision with that entry, tested as
    above (it is replaced only if it stops answering). Outbound picks are one per group
    anyway, so a second entry per group adds nothing to diversity; the cap was chosen
    from the simulator (below).
  - **Selection.** A table is drawn: *tried* with probability 0.7 (`TRIED_BIAS`), or
    0.9 once *tried* holds at least 64 entries (`RICH_TRIED_BIAS`, `RICH_TRIED`;
    W3-32c), else *new*; both set from the simulator below (Bitcoin Core uses 0.5,
    Monero 70 %). Then a
    **non-empty bucket is drawn uniformly**, then an entry of it. The entry is accepted
    with Bitcoin Core's `GetChance` (0.01 if tried in the last 10 minutes, × 0.66 per
    failed attempt up to 8), raised 1.2× per draw. A source's entries, crowded into its
    16 buckets, are therefore drawn no more often than 16 buckets' worth. When nothing
    eligible is left in the drawn table, the other one is used.
  - **Times are local:** when this node heard of or connected to an address. Peers'
    claimed times are used only for relay freshness (above).
  - With `allow_private` (local and lab networks), unroutable addresses are grouped by
    the whole address. A LAN's nodes then spread over buckets instead of sharing one
    /16's.
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
- **Outbound connections** (`maintain_outbound`, every 2 s). The node keeps **8
  full-relay** outbound connections (`--max-outbound`, manual peers included) and **2
  block-relay-only** ones (`NetConfig::block_relay_only`; none with `--connect-only`), at
  most **one per group** across both, also among the addresses picked in the same round
  (before 2026-09-27 two picks of one round could share a group, R8-4). The groups of
  manual peers and anchors being dialed count too (F32-12); seeds' address fetches do
  not (they are short).
  - **Block-relay-only connections** (W3-32c, dossier 32 W4; Bitcoin Core PR #15759).
    The node sends `relay_txs = false` and no address of its own in `Version`; no
    `GetAddr` and no `Addr` go either way (an `Addr` from the peer is ignored); no
    transaction is announced or stemmed to it; a transaction message from it (`InvTx`,
    `GetTx`, `Tx`, `StemTx`) costs 10 points. Headers and blocks flow as on any
    connection. Transaction and address relay therefore reveal nothing about these
    links (TxProbe-style topology inference, Delgado-Segura et al., FC 2019). The
    receiving side treats an inbound peer that sent `relay_txs = false` the same way for
    addresses. Full-relay slots are filled first, then these, from the same table.
  - A registered outbound peer counts **once** against the target (RTW3-2). Its address
    stays in the dialing set for its whole session (so it is never dialed twice), and
    before the fix it was counted there and as a registered peer: a node refilled a lost
    outbound slot only once fewer than half its target were left, never reached the
    feeler condition after churn, and could not dial the stale-tip extra peer
    (`p2p/tests/outbound_policy.rs`, `lost_outbound_peers_are_replaced`).
  - **Anchors** (dossier 32 W4, as Bitcoin Core since PR #17428):
    - At shutdown the node writes up to 2 of its **block-relay-only** peers to
      `anchors.json`, longest connected first, never manual peers or seeds.
    - At the next start it dials them, block-relay-only, before anything else.
    - The file is deleted when read, so a node that crashes later does not re-anchor to
      an old file.
    - Not used with `--connect-only` or without block-relay-only connections.
  - **Feelers** (W5). When every full-relay slot is taken, the node opens a short
    connection about every 2 minutes (exponentially distributed; `NetConfig::
    feeler_interval`). It goes to a waiting *tried* collision's occupant, else to a *new*
    address in a group with no outbound peer. A collision test ignores the group and
    one-minute backoff filters (RTW3-9): the occupant may share a group with an
    outbound peer, and a repeated attempt is what the test needs. A completed handshake
    moves the address to *tried* (or settles the collision). The connection is then
    closed unregistered: no message is exchanged (`feelers_move_an_answering_new_address_to_tried`).
  - **Stale tip** (W7). If the connected tip has not changed for `3 × T × 2` (Bitcoin
    Core uses 3 × T), the node allows one extra full-relay connection, at most once per
    10 minutes, and also asks seeds for addresses. With more full-relay peers than the
    target, one discovered full-relay peer (never a manual peer) is disconnected, not
    banned, after
    Bitcoin Core's `EvictExtraOutboundPeers` (RTW3-4):
    - the worst of **all** of them: the one whose last **validated new tip** is oldest
      (a header batch that stored new headers on our best header chain, or a block that
      joined our best chain; never delivered is worst), ties broken by the youngest
      connection. The height a peer claims in `Version` is never used: it costs nothing
      to inflate;
    - if that peer is younger than 30 s (`MIN_CONNECT_TIME`) or has blocks in flight,
      the rotation waits for it, rather than evicting a better peer.

    So an extra peer that brings nothing goes once it is 30 s old, and one that brings a
    new tip stays while an established peer that brought none goes. Before RTW3-4 the
    peer with the lowest claimed height went, and among equal heights an established
    peer was evicted two seconds after the newcomer arrived. A node whose outbound peers
    all withhold blocks rotates one of them every 10 minutes; before W7 it kept them
    forever (F32-3). The thresholds are `NetConfig` fields (`stale_tip_after`,
    `stale_check_interval`, `min_connect_time`) so tests can shorten them
    (`p2p/tests/outbound_policy.rs`).
- **Seeds are one-shot address fetches** (W3-32c, dossier 32 W7, F32-6; Bitcoin Core's
  `ADDR_FETCH`): the node connects, sends `GetAddr`, stores the answer and closes the
  connection on it, or after 30 s without one (`NetConfig::addr_fetch_timeout`). Any
  `Addr` closes it except the seed's self-advertisement: one entry equal to the
  listen address its `Version` carried, sent before the answer. Before P2P-FIX2 any
  single-entry `Addr` was taken for the self-advertisement, so a seed whose answer
  was one address was held for the whole timeout
  (`a_seed_answering_one_address_is_left_at_once`). The seed is never
  promoted in the table, never counted as an outbound peer, never a stem or an anchor;
  no transaction is taken from it and no header or block is requested from it. Before,
  a seed was dialed as a full outbound peer, promoted to *tried* and kept: a seed
  operator held a long-lived slot in every joiner (the Moros bootstrap lever, CCS'26). A seed that also advertises its own
  address (`--public-address`) is learned from that fetch and dialed later like any
  address. Seeds are asked in three cases, each seed at most every 30 s (R8-13):
  - the address table is empty;
  - fewer than 2 full-relay outbound peers have been up for 60 s
    (`NetConfig::seed_fallback_after`; every known address may be stale or hostile).
    Before, only when none was up, so one attacker peer suppressed the seeds;
  - the tip is stale.

  Dial attempt times are kept 10 minutes (longer than every backoff), so dialing junk
  addresses does not grow memory (F32-10).
- **Eclipse resistance is limited** (F32-13). The eclipse simulator
  (`p2p/tests/eclipse_sim.rs`, run with `--nocapture`) is the regression metric. It
  models one node's table under a Sybil address flood with the real address manager and
  admission code, and prints for each scenario:
  - the attacker's share of *new* entries and buckets;
  - the most buckets one attacker source reached;
  - its share of the outbound slots after a restart;
  - the probability that all 8 slots are its.

  It compares the admission before W2-32, the address manager before v2 (kept in the
  simulator as the baseline) and v2. It asserts that v2 is never worse than the
  baseline, that one source reaches at most 16 *new* buckets, and that with one or four
  attacker sources the attacker's outbound share at least halves.
  - A second model (RTW3-10, `eclipse_simulation_with_feelers_rederives_the_tried_bias`)
    adds a day and a week of feelers after the flood. Attacker addresses that accept
    connections reach *tried* through them (one per IP; the attacker's own source IPs,
    or 32 or 128 addresses in distinct groups), and so do the honest *new* addresses.
    It prints the *tried* make-up and the outbound share for biases 0.5 to 0.9, and
    asserts that the chosen bias is never worse than 0.5. Findings: 0.7 is never worse
    than 0.5; 0.8 and 0.9 lower the share further where the attacker holds few *tried*
    entries, but raise P(all 8) where it holds most of them, so `TRIED_BIAS` stays 0.7.
    Feelers drain honest addresses out of *new* into *tried*, so after them *new* is
    almost all the attacker's and a *new* draw almost always picks it. An attacker with
    more answering addresses than the honest *tried* entries keeps most of the slots at
    every bias tested (run the simulator for the figures); onion addresses have no
    per-IP limit, and their names are free. This model has no honest address inflow
    after the flood and no promotions by regular outbound connections (the third model
    has both).
  - **Onion *tried* cap** (W3-32c, `eclipse_simulation_onion_tried_cap`): the feeler
    model's onion rows for caps of none, 1, 2, 4 and 8 per onion group. One per group is
    lowest in every row, including a 100-node honest onion network with no answering
    attacker address (where fewer honest entries in *tried* leave more of them in *new*
    for its draws), so the cap is 1. The test asserts that the cap bounds the attacker's
    *tried* entries to 16 × cap, that it cuts the attacker's outbound share by at least a
    third with 32 and with 128 answering onions, and that it costs the honest-only
    network at most 5 points.
  - **Realistic model** (W3-32c, `eclipse_simulation_realistic_model`): the flood, then a
    week in 2-minute steps with a feeler each step, a regular outbound redial every 30
    minutes (promoting what answers), a new honest node every hour and every honest
    address heard again once a day (both relayed by honest peers), the attacker still
    flooding 100 addresses per source per hour, and the honest addresses known before
    the flood learned from 8 peers. It prints, per day, the honest share of *new*, the
    *tried* make-up, the attacker's share of the live outbound slots and of the slots
    after a restart, for W3-32's policy, source-group caps of 8, 16 and 32, bias 0.9
    alone, and the chosen policy. Findings:
    - feelers still drain honest addresses out of *new*: within a day *new* is at most
      2 % honest in every IPv4 scenario, despite the inflow, and the draws that go to
      *new* then carry most of the attacker's share;
    - the source-group cap bounds the attacker's *tried* entries where its answering
      addresses come from few sources;
    - a higher *tried* bias removes most of the *new* draws, but helps only where the
      attacker cannot hold much of *tried* (with the cap), and not with a small *tried*
      table: an onion node's (at most 16 entries) did worse at 0.9. Hence 0.9 only from
      64 *tried* entries.

    The test asserts that the drain happens under W3-32's policy, and that the chosen
    policy never raises the attacker's share after a restart (2 points of sampling noise
    allowed) or P(all 8) in any scenario, and cuts the share by at least a third where the
    attacker answers from its own IPs (run the simulator for the figures). The live
    share after a week can be a little higher (one empty-*tried* scenario). Not modelled:
    honest churn, an attacker laundering its addresses through honest relays (they then
    carry honest source groups), and inbound self-advertisements from many attacker IPs
    (each is its own source group).
  - The admission limits cut what a flood gets into the table by orders of magnitude.
  - Addrman v2 confines what gets in to 16 buckets per source.
  - On a network of tens of honest nodes, the attacker's addresses still outnumber the
    honest ones in *new*. A node whose *tried* table is empty (a new node) still gives
    the attacker most of its *new* draws.

  The practical defences for the testnet are manual `--peer` links to known operators,
  anchors, independent seeds and operator monitoring. An AS-level attacker (Erebus,
  IEEE S&P 2020) is outside what /16 grouping can resist (asmap is not implemented).
- **Connect-only mode.** With `--connect-only`, outbound connections go only to the
  configured `--peer` entries: no seeds and no discovered addresses. Inbound
  connections and address exchange still work. It suits fixed private topologies and
  lab tests.
- **Inbound.** At most 64 inbound connections, and at most 2 per IPv4 address or
  **IPv6 /64** (`addr::peer_key`). One IPv6 host is routinely given a whole /64. Before
  W3-32 the limit applied per exact address, so one /64 could fill every inbound slot
  (F32-2).
  - Connections still in their handshake count against the per-IP limit when a new one
    is accepted, and the limits (and bans) are checked again, atomically, when the
    peer is registered. Before 2026-09-27 only registered peers were counted, so
    concurrent handshakes bypassed both limits.
  - **Handshaking connections** (RTW3-3, `peers::handshake_caps`) are bounded on their
    own: at most a quarter of `max_inbound` at once (16 of 64), and a quarter of that
    per group (4 per IPv4 /16 or IPv6 /32). A new connection past either bound closes
    the **oldest** handshaking connection (of its group first): handshaking
    connections are the first eviction candidates, before any registered peer. They
    never count against `max_inbound`. Before RTW3-3 they did, and room was made at
    accept by evicting registered peers, so TCP connections that never sent a byte
    pushed honest registered peers out and held the slots
    (`silent_handshakes_do_not_evict_registered_peers`).
  - **Eviction** (W6; `connman::select_inbound_to_evict`, after Bitcoin Core's
    `SelectNodeToEvict`). When inbound is full, a peer that completed its handshake is
    still registered if a registered inbound peer can give way; the choice is made at
    registration, not at accept (RTW3-3). Protected, in order:
    1. the oldest peer of each of the 4 groups with the highest keyed group hash (keyed
       with the address table's key, so peers cannot tell which groups);
    2. the 8 peers with the lowest **minimum ping** measured (the round trip of a ping
       nonce the peer cannot know before it is sent, so it cannot answer faster than
       its real distance; W3-32c);
    3. the 4 peers that most recently delivered a **new transaction that passed
       verification** (accepted to the pool, or a valid stem transaction);
    4. the 8 block-relay-only peers (`relay_txs = false`) that most recently delivered a
       **new block that joined our best chain**;
    5. the 4 peers that most recently delivered such a block;
    6. up to a quarter of the candidates arriving through our hidden service, oldest
       first;
    7. the older half of the rest.

    Classes 2 to 5 protect only peers that earned it: a measured ping or a delivery.
    Of the others, the youngest peer of the group with the most connections is
    disconnected, not banned. If every peer is protected, the new peer is refused at
    registration. Before W3-32 it always was. Classes 2 to 5 are W3-32c; before, a peer
    that relayed blocks or answered pings fastest had no more protection than any other
    (`low_ping_inbound_peers_survive_eviction`).
  - **Onion peers** through the onion listener (§11) are a class capped at a quarter of
    `max_inbound`; a new one past the cap evicts within the class.
- **Persistence.** The tables and the ban list are saved in the data directory
  (`peers.json`, `bans.json`) within a minute of changing, and on shutdown. The ban
  list is saved whenever a ban was added (not only when its size changed). An
  existing `bans.json` that cannot be read or parsed is logged as a warning.
  - `peers.json` holds the table's key, a format version (2) and the entries. A file of
    another version, such as the format before v2, starts a fresh table (logged).
  - Slots are recomputed from the key at load. A damaged or edited file therefore
    cannot break the tables' invariants: duplicates, a second *tried* entry of an IP
    and non-canonical addresses are dropped.
  - `anchors.json` is written only at shutdown (above).

## 10. Misbehavior, limits and bans

Each connection has a misbehavior score. At **100** the peer is disconnected and its IP
banned for **24 h** (an IPv6 address's whole /64, §9). Every other live connection from
that IP (or /64) is disconnected too.
Tor peers all share one exit IP, so for proxied or onion peers only the connection is
dropped.

| Violation | Score |
|---|---|
| Frame over `MAX_FRAME` (its length is authenticated), malformed known message, list over its limit | 100 |
| Header with invalid PoW, bad difficulty, bad version or height, a timestamp not after the median-time-past | 100 |
| Block whose body is invalid or does not match its header | 100 |
| `Headers` that do not connect or are not a chain | 20 |
| Unrequested `Headers` with more than one header | 10 |
| Transaction invalid by a **stateless** rule (`Tx`/`StemTx`; transactions.md T1–T11), or with an invalid ring signature over ring members all ≥ 60 blocks deep | 20 |
| A `StemTx` already proven invalid, sent again | 20 |
| Unrequested `Block`/`Tx`, `Pong` without a ping, second `GetAddr` from an inbound peer, or an unsolicited `Addr` of more than 10 entries (§9). The late answer to a request of ours that timed out is not unrequested (§6, §7) | 10 |
| Message or byte rate exceeded (read loop), `InvTx` rate, a request dropped by a full slow lane | 1 per excess message; the message is dropped |

**Not penalized** (honest peers can trigger these):
- a frame that fails to decrypt, at any time (§3). It closes the connection and is
  counted in `NetStats::transport_failures`, never scored. It is not attributable: an
  on-path party can flip one bit, and a ban would let it cut two honest nodes apart for
  24 h in both directions (dossier 30 T-2; before 2026-09-28 it scored 100 and banned).
  An active man in the middle who runs the handshake with both ends can still send
  well-formed invalid messages under a peer's address; only a pre-shared key (§3) or
  authenticated transports prevent that;
- anything before `Verack` (§4): the connection is closed, unscored;
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
- a relayed transaction (`Tx` or `StemTx`) over one of the peer's relay budgets
  (transactions, ring signatures, PX share; below): dropped unverified. A `StemTx`
  is not fluffed either (a forced fluff helps locate its origin; the origin's
  embargo ends the stem). An honest node forwarding many peers' stems exceeds these
  rates without misbehaving; before 2026-09-28 each excess `StemTx` cost 1 point, so
  such a forwarder could be banned (RTW2A-4). Floods stay bounded, and scored, by
  the message and byte rates and by the slow lane's bounds;
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
its bounded outbox fills up (`GetTx` answers wait for room instead, §7). Each peer has two outboxes (R8-11): **control** (64
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
- **Transactions accepted into the relay path:** 20 per second, burst 100 (one per
  `StemTx`; an `InvTx` costs 0.1 per id).
- **Ring signatures:** 50 per second, burst 500. A relayed transaction (`Tx` or
  `StemTx`) costs one token per v1 input (one CLSAG verification each): a 64-input
  transaction costs 64, not 1. Charged before any verification.
- A relayed transaction's budgets (a transaction token for a `StemTx`, its ring
  signatures, the PX share below) are charged together, all or nothing
  (`PeerLimits::charge_relay`), on the peer's slow lane, never for a message the
  lane dropped. Over any of them it is dropped unverified and not penalized
  (RTW2A-4).
- **Admission order** of a relayed transaction, cheapest first:
  0. for a `StemTx`: one that does not decode is penalized (20); one already in
     our stempool, or conflicting with a stem transaction, is dropped for free;
  1. an id already proven invalid is dropped (a `StemTx` of it is penalized);
  2. the relay budgets are charged (above);
  3. an id already in our mempool (a replay, SX2), or one that failed a
     contextual rule **at our current tip**, is dropped unverified: the same bytes are verified again only after the tip changes
     (the cache holds at most 10 000 ids and is emptied when the tip changes; a
     failure is cached under the tip its cheap checks ran at, returned by the same
     chain command, RTW2A-7).
     `InvTx` announcements of such ids are not requested either. A transaction that
     **conflicts** with a pooled one (same key image, PX nullifier or contract id,
     `Mempool::conflicts`; output keys never conflict) is dropped here too, unpenalized: the pool
     keeps the first seen, so it would be refused after verification anyway. Before
     2026-09-27 such a PX transaction passed the cheap checks and took a node-wide PX
     token (step 5) first;
  4. cheap checks: first, a PX transaction whose window ends fewer than
     `PX_EXPIRING_SOON_BLOCKS` (3) blocks after the next block is refused
     (RTW1C-4, `validate::px_expires_soon`): contextual, never scored, cached as
     in 3, before its proof is decoded; then the stateless structure and balance rules and, for PX, the
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
  - A peer over **its own** share has its excess dropped, unpenalized (RTW2A-4;
    before 2026-09-28 an unsolicited `StemTx` over it cost 1 point). A peer is
    never penalized for the node-wide limit either, which an attacker can drain.
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
  and the penalty (20, once verified) bound that cost, not the cheap stage.

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
      `SLOW_LANE_BYTES` = `MAX_RELAY_FRAME` + `SMALL_RELAY_BYTES` (2 MiB) bytes,
      queued or being handled; `MAX_RELAY_FRAME` is the largest relay frame (a
      transaction of `MAX_ANY_TX_SIZE` and its framing), so a maximum-size
      transaction always fits behind 2 MiB of other relay. Beyond them relay is
      dropped without penalty (relay is best effort; a request is retried with the
      next announcer). Before RTW2A-1 (2026-09-28) the bound was 2 MiB, and a
      message over it entered only a lane with no relay bytes: every PX transfer
      is larger (docs/zk.md), so one queued 40-byte `InvTx` dropped a requested PX
      `Tx` (its PX share already charged) or a PX `StemTx` (a stem black hole,
      which the origin then ends by fluffing its own transaction). Two PX
      transfers and small relay now fit together (`dispatch.rs`,
      `a_px_transaction_behind_small_queued_relay_is_queued`);
    - requests (`GetHeaders`, `GetBlocks`, `GetTx`): the rest of the lane's
      `SLOW_LANE` places, which relay never takes; queued relay bytes never drop
      a request. A request is dropped and charged as a message-rate excess
      (`score::RATE`) only when the lane holds `SLOW_LANE` messages. Before this
      split (a Stage 1 defect, found by the PX relay test), one queued PX
      transaction of about 3 MB made every later message of its peer dropped,
      and its requests charged;
    - memory of one peer's lane, what the code bounds: the relay frames counted
      above (at most `SLOW_LANE_BYTES`; a frame stays counted until its handler
      returns, although the handler frees it once decoded), plus at most
      `SLOW_LANE` requests of at most 16 KiB each (`MAX_INV` ids; a lane without
      relay can hold 64 requests), plus the one message being handled: a relayed
      transaction is decoded once, into one shared copy of about its encoded
      size (at most `MAX_ANY_TX_SIZE`; RTW2A-5, before it was copied twice more).
      Together about `MAX_RELAY_FRAME` × 2 + 3 MiB per peer. Not in this bound:
      the frame the read loop is receiving (the transport, §3), the outboxes, the
      stempool and the mempool (their own bounds), and the answer a `GetTx`
      handler builds (§7: at most `SERVE_TX_TOTAL`, 64 MiB, node-wide since
      RT-TM2P2P; before TM2-17, an encoded copy of every requested transaction,
      once per repetition of its id).
    - requests and relay share one queue with separate bounds; separate queues
      would lose the per-peer order across kinds that the handlers keep, and were
      not made (RTW2A-5).

    A relayed transaction's budgets, the per-peer PX share (`PeerLimits::px`)
    included, are charged when the lane handles it (admission order above), so a
    message the lane dropped costs nothing (RTW2A-1). Until 2026-09-28 the PX
    share was charged on the read loop, before the lane: a PX transaction the
    lane then dropped had burned it, and a `StemTx` over it cost 1 point. At a
    disconnect the lane task stops before its next message, never in the middle
    of one.
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
  - **Two maintenance loops and the announcer.** Pings, timeouts, Dandelion epochs,
    held local transactions, tip announcements (a fallback of the announcer, §6),
    header re-requests, outbound dialing and saving never wait for the chain. The
    announcer is woken by the summary cell's tip listener, which the actor calls
    after a publication that changed the tip; the listener only wakes a task.
    Download scheduling (from the snapshot, first), embargo fluffs and pool
    re-announcement run on a second task; each fluff (a mempool submission) runs on
    a task of its own, so that loop never waits for one (RTW2A-3). A long command
    delays only the fluffs and the re-announcement, by at most its length (during a
    drain a fluff waits about `STARVATION_LIMIT` steps): an embargo that expires during one is fluffed when it ends. Tested:
    `p2p/tests/network.rs`
    `downloads_are_scheduled_during_a_drain_while_a_fluff_waits`.

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
  - **`--proxy` alone is dual-homed.** Without `--proxy-only` the node keeps its
    clearnet listener (`0.0.0.0` by default), resolves seed host names with the
    system DNS, and serves its Tor and clearnet identities from one address table,
    mempool and stempool; a held local transaction is fluffed at its embargo to
    clearnet inbound peers as well (dossier 33 F33-7). Answers to `GetAddr` come
    from the one table that mixes onion and clearnet entries, with no per-network
    cache, so a spy can link the two identities.
  - **No stream isolation.** The SOCKS5 greeting offers "no authentication" only, so
    Tor may carry several of the node's connections over one circuit and one exit
    (Bitcoin Core sends random credentials per connection for this reason).
- **Proxy-only mode.** `--proxy-only` makes every connection go through the proxy:
  no direct clearnet connection, no clearnet listener unless one is bound
  explicitly, and no local DNS lookup (seeds and peers must be IP or `.onion`
  addresses).
  - Addresses are still exchanged, but the node's own clearnet address is never
    revealed.
  - **It still dials clearnet addresses, through Tor exits.** The outbound filter
    skips onion addresses only when there is no proxy; with a proxy, every known
    address is dialable (`Dialable::skip_test`, `p2p/src/net/peers.rs`). An exit
    relay terminates such a connection, and the transport is unauthenticated (§1),
    so the exit can read and alter it: it sees the transactions this node originates
    and can eclipse that link. There is no onion-only setting yet (the decided
    "onion-only by default" for Tor nodes, decisions "Agent 32", is not
    implemented). To stay among onion peers, list only `.onion` peers and use
    `--connect-only`.
- **Inbound over Tor.** The operator runs a Tor hidden service and passes
  `--public-address <host>.onion:port` so the node advertises it. The service should
  forward to a dedicated **onion listener**, `--onion-inbound 127.0.0.1:<port>` (`[p2p]
  onion_inbound`; loopback only, not the P2P port; W3-32c, N-6):
  - every connection on it is an onion peer (`ConnKind::OnionInbound`), whatever its
    source IP (the Tor daemon's). No ban and no per-IP limit applies to it; misbehaviour
    disconnects it without banning the shared address;
  - onion peers are capped as a class at a quarter of `--max-inbound` (16 of 64), inside
    `--max-inbound`. A new onion peer past the cap evicts one within the class (by the
    eviction rules of §9, "Inbound"); their pending handshakes are bounded as one group;
  - their header batches are queued per connection, not per IP;
  - with an onion listener set, loopback connections on the P2P port are no longer taken
    for Tor.

  Without `--onion-inbound` a hidden service forwarding to the P2P port still works as
  before: its peers arrive from loopback, count as one IP (`max_per_ip` = 2, so **2 onion
  peers at most**) and one misbehaving onion peer gets loopback banned for 24 h, which
  closes the service (N-6). The onion listener exists to remove those limits.
- I2P is not implemented in v1; the I2P SAM client from the old code is in `legacy/`.

## 12. Known limitations

- Peers are not authenticated (§1). A MITM can read or drop a connection's traffic,
  except on a closed network with a pre-shared key (§3). The transport has no rekeying
  and no post-quantum step, and its first bytes are recognizable (§3.1). Frames are
  not padded, so a link observer sees when a node originates a transaction, v1 or
  PX (§1).
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
    are not hashed). The store never holds more than `consensus::pow::MAX_CACHES`
    caches in memory (kept, being built, evicted but still borrowed, or being
    freed), hot builds and hot-set changes included; a build at the bound first
    evicts an idle side cache, otherwise waits for a hashing thread to release one
    (RT-MUT; `pow::tests`).
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
    What waits for them is only chain work: lane messages, embargo fluffs (each on
    a task of its own: the chain-maintenance loop schedules body downloads first
    and never waits for a fluff, RTW2A-3; before, each expired embargo parked
    download scheduling for about `STARVATION_LIMIT` drain steps), header
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
- **Per-hop block latency** (RT-LAB F2). A node announces a block only after it has
  connected it: it verifies the header's RandomX proof of work in light mode (about
  0.45 s per header, above), then downloads and connects the body. Relaying the
  header before the body connects, and a faster light-mode verifier, are design
  notes, not implemented; the announcement itself no longer waits for the maintenance
  tick (§6). No multi-hop figure is measured yet.

- **Address manager and eclipse** (§9, dossier 32). Implemented since dossier 32:
  two block-relay-only outbound connections, which are also the anchors; inbound
  eviction that protects peers by network group, ping, and recent transaction and
  block relay; seeds used as one-shot address fetches; a cap of one tried entry per
  onion group. Open:
  - no chain-sync eviction of outbound peers that stay behind (an outbound peer that
    keeps delivering valid tips of a lower-work view is never rotated), only the
    stale-tip rotation;
  - no built-in seeds yet, so a fresh node depends on the addresses its operator
    gives it; with an empty tried table an attacker gets about 61 % of the slots in
    the simulator's small-network scenario (`eclipse_sim`, F32-13);
  - no asmap;
  - the admission rate restarts with every connection;
  - none of these mechanisms has run against a live adversary: the labnet runs on
    one machine with `allow_private`, which turns off network grouping, per-IP
    limits and bans.

  On a network of tens of honest nodes, the address manager bounds an eclipse by an
  attacker with many real addresses but cannot prevent it (§9).
- **Tor inbound.** With the onion listener (`--onion-inbound`, §11) each onion peer
  stands alone: no per-IP limit and no ban of the shared loopback address. A hidden
  service forwarded to the P2P port instead still shares the per-IP limits
  (2 connections, 2 queued header batches) and one ban (N-6). Tor outbound has no
  onion-only mode and no stream isolation (§11).
- **Download stalls.** A block request that times out (60 s) is moved to a random
  candidate peer, which may be the same one; a peer that withholds bodies is never
  disconnected or demoted (the decided staller detection, decisions "Agent 31", is
  not implemented). A peer that announced a high `Version` height stays a download
  candidate.
- **Header PoW per identity.** A peer can send headers with junk proof of work; the
  first chunk of a batch (`pow_threads` headers) is hashed before the first failure
  is scored. Peers reached through a proxy and onion inbound peers are never banned,
  so over Tor this costs the attacker nothing per identity.
- **Send buffers are bounded in messages, not bytes** (64 control frames, 32 blocks
  per peer), so a slow-reading peer can pin hundreds of megabytes; and a `GetTx` for
  more than 64 transactions may overflow the 64-slot control outbox and disconnect
  the honest requester (not yet reproduced by a test).
- There is no compact-block relay; a full block is sent once per peer that lacks it.
- Dandelion++'s parameters follow Monero (q = 0.2, 39 s mean embargo), plus a 10 s
  embargo base. They have not been re-tuned for BlackSilk's network size.
