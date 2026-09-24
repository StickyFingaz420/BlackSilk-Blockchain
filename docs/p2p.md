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
k       = H64("p2p/session", LE32(network_id) ‖ A ‖ B ‖ S)
k_i→r   = k[0..32],  k_r→i = k[32..64]
```

- `network_id` is bound into the keys. Nodes of different networks derive different keys,
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
  protocol:  u32        currently 1; peers below MIN_PROTOCOL (1) are disconnected
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

Unknown message types are violations.

## 6. Header-first synchronization

1. **Start.** After the handshake, if the peer's `height` exceeds our best header height,
   send `GetHeaders(locator)`.
   - The locator holds ids of our best header chain: the tip, then 10 predecessors one
     by one, then exponentially sparser ones back to genesis (at most 64).
2. **Answering.** The responder finds the first locator id on its best chain and returns
   the following headers, at most 2000, ending at `stop` if it meets it.
3. **Processing headers.** They must form a chain. Each header is fully validated
   (consensus.md §6), including RandomX PoW, *before* it enters the header tree.
   - The PoW hashes of a batch are computed in parallel first; the seeds come from ids
     in the batch or the existing chain. Accepting the batch is then cheap.
   - If a full batch (2000) arrived, the node asks the same peer for more.
4. **Bodies.** The node requests `GetBlocks` for best-chain blocks whose body it lacks,
   starting just above the connected tip.
   - At most **16** are in flight per peer, and only from peers whose announced height
     covers them.
   - A node serves at most 16 blocks per `GetBlocks`; the rest are answered with
     `NotFound`.
   - A request unanswered within **60 s** is reassigned to another peer and counts as a
     minor violation.
5. **Connecting.** Bodies go through the chain manager (blocks.md §5–§6). It connects
   them in order, validates each, and reorganizes when a heavier branch completes. The
   network layer never decides validity.

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
  - A `NotFound` answer, or no answer within 30 s, moves the request to the next
    announcer.
  - Neither is penalized: transaction relay is best effort.
- **Serving.** A node serves `GetTx` **only for transactions it has already announced to
  that peer and still has**.
  - Every other requested hash gets the same `NotFound`, whether the transaction was
    mined, dropped or never known.
  - A spy therefore cannot probe the stempool or the mempool for transactions it was
    never offered.

## 8. Dandelion++ (stem phase)

Following Fanti et al., "Dandelion++" (SIGMETRICS 2018), as deployed in Monero:

- **Epochs.** Time is divided into epochs of about 10 minutes (random length, 9–11
  minutes). In each epoch a node:
  - picks **2 stem peers** at random among its outbound peers;
  - maps each inbound peer, and itself, to one of the two stem peers at random, so each
    source's stem route stays fixed for the epoch;
  - is a *diffuser* with probability **10 %**, otherwise a *relayer*.
- **Transactions the node creates or receives by RPC** enter the stem: they are sent as
  `StemTx` to the stem peer mapped to "self".
- **Receiving a `StemTx`.**
  - The transaction is validated fully against the current state.
  - Only a stateless failure is a violation (§10).
  - It is stored in the **stempool**. The stempool is never announced, never served and
    never mined.
  - A relayer forwards it to the stem peer mapped to the sender. A diffuser fluffs it:
    it moves the transaction to the mempool and starts §7.
- **Embargo.** Every stem transaction gets a random embargo timer (exponential, mean
  **39 s**, plus 10 s).
  - If the transaction has not been seen in fluff (announced by a peer, or included in a
    block) before the timer fires, the node fluffs it itself.
  - This guarantees delivery if a stem peer is malicious or offline.
- **Stem failures.** If the stem peer is missing or has no connection, the transaction is
  fluffed immediately.

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
  group**. Candidates are drawn 50/50 from *tried* and *new*.
- **Connect-only mode.** With `--connect-only`, outbound connections go only to the
  configured `--peer` entries: no seeds and no discovered addresses. Inbound
  connections and address exchange still work. It suits fixed private topologies and
  lab tests.
- **Inbound.** At most 64 inbound connections, and at most 2 from any one IP.
- **Persistence.** The tables and the ban list are saved in the data directory
  (`peers.json`, `bans.json`) within a minute of changing, and on shutdown.

## 10. Misbehavior, limits and bans

Each connection has a misbehavior score. At **100** the peer is disconnected and its IP
banned for **24 h**. Tor peers all share one exit IP, so for proxied or onion peers only
the connection is dropped.

| Violation | Score |
|---|---|
| Undecryptable or malformed frame, unknown type, list over its limit | 100 |
| Header with invalid PoW, bad difficulty, bad version or height, invalid parent | 100 |
| Block whose body is invalid or does not match its header | 100 |
| `Headers` that do not connect or are not a chain | 20 |
| Transaction invalid by a **stateless** rule (`Tx`/`StemTx`; transactions.md T1–T11) | 20 |
| Unrequested `Block`/`Tx`, `Pong` without a ping, second `GetAddr` or oversized `Addr` | 10 |
| Timeout on a requested block or headers | 5 |
| Rate limit exceeded | 1 per excess message; the message is dropped |

**Not penalized** (honest peers can trigger these):
- a header rejected only by the future-time rule;
- a duplicate;
- an already-known transaction;
- a transaction that conflicts with the mempool;
- a transaction invalid only against **our chain state** (contextual rules C1–C4). Its
  key image may have been spent in a block we saw first, or its ring members may
  resolve differently on our branch. This is not proof of misbehavior;
- `NotFound`, or a slow transaction answer.

The lab network found the last two cases as false bans between honest nodes (AUDIT.md
R6).

A peer that does not read its messages fast enough is disconnected, not banned, when
its bounded outbox (64 messages) fills up.

**Rate limits** (per peer, token buckets):
- **Messages:** 50 per second, burst 500.
- **Bytes:** 4 MB per second, burst 16 MB.
- **Transactions accepted into the relay path:** 20 per second, burst 100.
- **PX and deploy transactions** (each costs ~0.2 s to verify): 0.2 per second,
  burst 4, per peer, **and** 2 per second, burst 10, over all peers together. Excess
  ones are dropped unverified.
  - A peer is penalized (1 point) only for exceeding **its own** share with unsolicited
    `StemTx` messages.
  - It is never penalized for the node-wide limit, which an attacker can drain, nor
    for a `Tx` we requested.
  - Tested: `px_transactions_travel_the_stem_and_confirm_everywhere`.
- An invalid PX proof counts as a stateless violation (20). Once the anchor and
  registry checks pass, the proof's statement does not depend on our pool state, so
  an honest peer never relays one.

**Liveness:**
- The node pings every 60 s.
- A connection is closed after 180 s without any message, or when a pong is 30 s late.

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
- There is no compact-block relay; a full block is sent once per peer that lacks it.
- Dandelion++'s parameters follow Monero. They have not been re-tuned for BlackSilk's
  network size.
