# TM2-PRIV: second threat-model round, privacy and deanonymization lens

Agent TM2-PRIV, phase 2. This is an internal engineering review, not an audit. It does
not claim that BlackSilk is secure, private "by proof", production-ready or audited.
Zero knowledge is described only as statistical and conditional (computational in
practice, because the masks are ChaCha PRG outputs).

- **Code under review:** local `rebuild/core` at **`3c21afe`**, read-only. No file in the
  repository was changed.
- **Builds and tests:** none. No worktree was created and no cargo command was run.
  - Every code claim is source-read [src], or it names an existing test [test: name] or an
    evidence folder [ev].
  - Probabilities are either reasoned [r] or quoted from a dossier simulation [sim, dossier N].
- **How the work was done:** four read-only sub-searches mapped the wallet and node, P2P,
  chain and operator surfaces. I re-read every load-bearing claim in the code myself
  before using it here: the re-announcement anchor, the originated-set file, decoy
  distribution and RNG, GetAddr, the SOCKS greeting, proxy dialling, stem admission and
  the handshake order.
- **Inputs read:**
  - brief.md, impl-brief.md, decisions.md (all 1,099 lines)
  - round 1: dossier 48
  - dossiers 26, 32, 33, 38 and 39 (findings and plans)
  - docs: p2p.md (sections 1-4, 7, 8, 8.1, 11, 12), px.md (sections 1, 3.1, 4.4, 6, 7, 11, 12), transactions.md (sections 4.1, 11, 12.7-15), zk.md section 12, contracts.md section 8, testnet.md (sections 2, 4.3, 4.5, 7.1, 11, 12.7), STATUS.md, README.md, privacy-review.md (index)

Severity is **likelihood (L, 1-5) x impact (I, 1-5)**:

| Score | Severity |
|---|---|
| 15 or more | High |
| 8-14 | Medium |
| 7 or less | Low |

Two deployment models are scored:
- **Trial:** 7 trusted devices, explicit `--peer` mesh, closed-network PSK, own nodes.
- **Public:** a public testnet, with remote-node and Tor users.

---

## 0. Top findings in one table

| ID | Finding | New? | Severity (trial / public) | Priority |
|---|---|---|---|---|
| **TM2-P1** | Pool re-announcement is anchored on the origin's *relay* height, so a block found while the tx is still in the stem makes the origin re-announce one block before every other node: a deterministic origin oracle. It sits inside the mechanism built to prevent exactly that (33 W2), and the docs claim the opposite | NEW | Medium (L2 x I4 = 8) / Medium (L3 x I4 = 12) | **P0** (small fix) |
| **TM2-P2** | `originated.json` is a plaintext list of every transaction the operator sent in the last ~2,190 blocks. It is written with default permissions and is missing from the data-dir docs | NEW (side effect of 33 W2) | Medium (L3 x I3 = 9) | **P0** docs + perms, P1 design |
| **TM2-P3** | The wallet still takes the node's `/distribution` unchecked to place decoys (F38-1) and fetches it only at spend time (F38-6). The decoy RNG is not hedged (F38-5) | carried over, open | Low (own node) / **High** (remote node, L4 x I4 = 16) | P1 (P0 before a public testnet, as decided) |
| **TM2-P4** | PX origin under an active spy: one embargo for v1 and PX, no local re-stem, and spies can drain the node-wide PX relay bucket, which black-holes PX stems at relayers so the origin's own timer fires first | composition of F33-4 and RTW2A-4; open | Medium (L2 x I4) / **High** (L4 x I4 = 16) | P1 |
| **TM2-P5** | Tor mode is weaker than the decisions and docs suggest. There is no onion-only outbound: proxy-only nodes dial clearnet peers through Tor exits, which can MITM the unauthenticated transport. Other gaps: no SOCKS stream isolation; `--proxy` without `--proxy-only` stays clearnet-listening with system DNS; F33-7 fallback fluff to clearnet; GetAddr answers are network-mixed and uncached; the shipped Tor config has the N-6 2-peer cap | partly new | n/a (trial) / Medium-High | P1 |
| **TM2-P6** | Stempool timing oracle survives on the per-peer slow lane (F33-2 residual): `StemTx(X)` then `GetHeaders` shows whether X is held, by up to 0.2 s for PX | carried over, partly closed | Low / Medium (L3 x I3) | P1 |
| **TM2-P7** | Decided docs corrections not landed: guess-newest is about 84-89 % on a mature chain (W9, decided P0); supply-audit custody (F48-2); Windows endpoint checklist (F48-7). Plus a dozen overclaims and stale rows (section 10) | open | Medium (claims) | **P0** (docs) |
| **TM2-P8** | Build channel: path remap exists only in `tools/release-build.sh`. README, Docker, CI build-guard and the genesis procedure use a plain build, and no automated check scans binaries for home paths. No signed tags; cross-host reproducibility not shown | partly new | Medium (L2 x I5) / High before any binary release | P1 (P0 before publishing any binary) |
| **TM2-P9** | Passive link observer: unpadded frames reveal local origination of v1 *and* PX transactions to the node's ISP. The handshake is about 8 bits distinguishable, and the active-probe response identifies a node even with a PSK | accepted limitation, under-documented for v1 | Medium / High (accepted) | P2 (transport v2, private broadcast) |
| **TM2-P10** | No privacy regression suite (33 W1, decided trial P0). The STATUS row says Not implemented. TM2-P1 and TM2-P6 would both have been caught by it | open | process | **P0** |

Round 1 privacy findings, in brief:
- **Closed:** F48-1 (PSK, tested).
- **Partly closed:** F48-7 (only the `seed` confirmation landed).
- **Open:**
  - F48-2: the decided custody procedure is not in the docs.
  - F48-8: no log rate limit, and peer IPs are logged at INFO.
  - D3: decoy RNG not hedged.
  - The "I" leaf is accepted and documented (for PX only).
- **Round 1 missed:** TM2-P1, TM2-P2, TM2-P5 (exit MITM) and TM2-P8. Three of these are side effects of fixes made after round 1. Details are in section 9.

---

## 1. Assets

| Asset | Where it lives | Who must not learn it |
|---|---|---|
| A1. Transaction origin (IP, Tor session) | the node's link, its stem, its pool re-announcements, its logs and files | spies, ISPs, remote nodes, anyone with the data dir |
| A2. Which ring member is real (v1) | rings, decoy distribution, wallet RNG, spend timing | chain analysts, malicious nodes |
| A3. Amounts and recipients (v1 commitments and stealth; PX records) | chain | chain analysts |
| A4. Links between transactions, addresses and identities (change, subaddresses, PX deposit and withdraw, contract calls) | chain, wallet behaviour | analysts, counterparties |
| A5. Block origin (miner IP) | announcements, logs | spies (documented as not protected) |
| A6. The node's contact graph and its Tor/clearnet identity link | addrman, anchors, GetAddr answers, logs | spies, dual-homed linkers |
| A7. Keys and wallet history | wallet file, process memory, swap, terminal, build channel | local attackers, a compromised binary |
| A8. The fact of running BlackSilk | handshake bytes, ports, DNS, frame sizes | ISP, censors (censorship resistance is not a goal, decisions "Agent 30") |

---

## 2. Adversary 1: passive network observer (ISP or AS level)

**Attacks and current state**

1. **Origin by size and timing on the node's own link.** Frames are
   `AEAD(LE32(len)) ‖ AEAD(payload)` with no padding (`p2p/src/transport.rs` `FrameWriter::send`, about lines 243-264).
   - A `StemTx` leaving the node with no inbound frame of the same size before it, and no `GetTx` round trip, is a transaction this node originated. That holds for v1 (a few kB) as well as PX (about 2.2 MB).
   - Dandelion++ does not help against this adversary. p2p.md section 8 "Limitations" says so in general terms.
   - STATUS section 6 and testnet.md section 12.7 state it only for PX ("visible to its ISP and Tor guard").
   - **Residual:** deterministic origin for every clearnet node. Over Tor, a v1 tx is a few cells (weak signal), while a PX tx is unmistakable to the guard.
2. **Protocol identification.**
   - The first 32 bytes each way are canonical Ristretto encodings, about 8 bits distinguishable per connection (p2p.md section 3.1).
   - Ping and Pong are fixed 45-byte frames every 60 s.
   - The responder sends its encrypted `Version` (about 90 bytes) right after the key exchange, before learning whether the initiator holds the PSK (`p2p/src/net/conn.rs` `run_connection`, about lines 185-188). So an active scanner identifies a BlackSilk node even on a PSK network.
   - Censorship resistance is not a stated goal; transport v2 (design only, p2p.md section 3.1) would fix the first-bytes part.
3. **Block origin.**
   - The miner announces before anyone else could: relays pay about 0.45-0.6 s of light-mode PoW verification per hop (RT-LAB F2).
   - It announces to *every* peer at once (`p2p/src/net/maintenance.rs` `announce_tip`; relayed blocks skip the sender, `net/state.rs` around lines 142-145).
   - It then uploads the body to each of them.
   - This is documented as "not protected" (p2p.md section 1). The no-jitter decision is recorded (decisions "RT-POW, RT-PXDOS, RT-SYNC").
4. **Wallet to remote node.**
   - Plain HTTP; `https://` is refused (`rpc/src/lib.rs` `normalize_base`, `http_client`).
   - The observer sees the full transaction on `POST /tx`, the bearer cookie, the scan start and the spend burst (`/info`, `/distribution`, `/tx`).
   - Documented in testnet.md section 11 and px.md section 12: "use your own node or a tunnel".
5. **DNS.** With `--proxy` but not `--proxy-only`, seed host names go to system DNS (`node/src/config.rs` `resolve_seeds`). Only proxy-only refuses them.
6. **Harvest now, decrypt later.** The Ristretto ECDH transport has no PQ step. A future DL break reads recorded stems, and so origins, of sessions that were not on Tor. Documented (p2p.md section 3); ML-KEM inside transport v2 is "targeted", not implemented.

**Mitigations (files)**
- Encrypted transport (`transport.rs` `session_key`, `handshake`).
- `--proxy`, `--proxy-only` and onion support (`p2p/src/socks5.rs`, `net/peers.rs` dial).
- No local DNS in proxy-only mode.
- PSK for closed networks.

**Evidence**
- [test: `transport::tests::the_session_key_matches_its_known_answer`]
- [test: `a_man_in_the_middle_reads_the_traffic_unless_a_psk_is_set`] (an active MITM, not a passive observer)
- None for traffic analysis, padding or handshake uniformity.

**Severity**
- Trial: L4 x I3 = **12, Medium**. Operators are trusted and the PSK hides content from MITMs, but size and timing still give origin.
- Public: L4 x I4 = **16, High**, accepted limitation.
- The decisions treat it as accepted. The gap I flag is the **documentation**: STATUS lists only PX origin as visible to the ISP, which implies v1 origin is safe against a link observer. It is not (section 10, C-7).

---

## 3. Adversary 2: spy nodes and sybil sets

### 3.1 First-spy and Dandelion++ inference

**State**
- **Parameters** (`p2p/src/dandelion.rs` `DandelionParams::default`): epochs of 9-11 min, q = 0.2, 2 stem peers, embargo 10 s + Exp(39 s).
- **Routing:**
  - Routes are per source and fixed for the epoch.
  - The node's own transaction is always stemmed, never diffused by the origin (`Dandelion::route`, lines 131-144).
  - A local transaction with no stem peer is held (`p2p/src/net/stem.rs` `stem_or_fluff`, `send_held_local_txs`).
- **Probing:**
  - An `InvTx` for a stem transaction is answered like an unknown one (I3-1).
  - `GetTx` is served only for transactions announced to that peer.
- **Not protected:**
  - **Trickle:** every peer has its own exponential timer (mean 2 s outbound, 5 s inbound; `net/relay.rs` `announce_tx`). There is no shared inbound timer (R8-16 open), and inv batches go out in arrival order, unshuffled. A spy with k inbound connections sees the minimum of k exponentials.
  - **PX embargo:** the embargo is the same for PX and v1. There is no local re-stem on first expiry (dossier 33 W3 and W4 not implemented; grep finds no re-stem or PX embargo). 33's simulation names a PX origin as first announcer 7.6 % of the time against 2.1 % for v1 [sim, dossier 33 section 3.4].

**Evidence**
- [test: `transactions_travel_the_stem_then_fluff_everywhere`]
- [test: `a_local_transaction_waits_for_a_stem_peer`]
- [test: `announcing_a_stem_transaction_neither_reveals_nor_fluffs_it`]
- [test: `px_transactions_travel_the_stem_and_confirm_everywhere`]
- dandelion.rs unit tests
- **No privacy regression suite** (STATUS row "Privacy regression suite with the timing oracle (33 W1, trial P0)": Not implemented).

### 3.2 TM2-P1 (NEW): the re-announcement schedule leaks the origin

**Code [src]**
- `p2p/src/net/relay.rs` `reannounce_pool` (about lines 81-129) re-announces a pooled tx at pool ages 10, 20, 40, ... blocks, counted from
  `anchor = originated.relayed(id).map_or(admitted, |r| r.min(admitted))`.
- `submit_local` (`stem.rs`, about lines 188-250) records `relayed = c.height() + 1` *at submission*, before the stem.
- Every other node's `admitted` is the next height *when it pooled the tx*. Stem hops keep it in the stempool, not the mempool. Nodes pool it only at or after the fluff.

**Attack**
- Suppose a block is found between the origin's submission and the network-wide fluff:
  - window: stem latency, or the whole embargo when the stem black-holes;
  - probability: about E[stem delay]/120 s [r], roughly 1 % for v1, 5-10 % for PX, and up to about 30 % after a black hole.
- Then every node anchors at r+1, and only the origin anchors at r.
- At r+10 the origin, and only the origin, sends `InvTx` to every peer that lacks the tx. Every other node sends it one block (about 2 min) later.
- **Who sees it:** a spy that opens a fresh connection to the origin each block, or that resets its per-peer known set, which is cleared at 50,000 entries. From that peer it gets an announcement that no relay could have produced.
- **Impact:** deterministic origin identification (impact 4) for any tx still unmined 10 blocks after submission. That is exactly the case the schedule exists for: PX congestion (3 per block) or a tx missing from miners' pools.

**Doc claim contradicted**
- p2p.md section 7, lines 638-641: "Honest nodes pool a transaction within seconds of each other, so they all re-announce it at the same heights: the origin re-announces its own transaction exactly as every other node does".
- The same sentence appears in the code comment and in the wallet sub-search's summary. Nobody checked the block-boundary case.

**Evidence**
- [test: `pooled_transactions_are_reannounced_on_the_common_schedule`] covers a single node's schedule only. No test puts a block between submission and fluff.

**Fix (policy, about 20 lines)**
- Anchor the origin on the height at which *it* first saw the tx in fluff: a peer's `InvTx` or `Tx`, or its own embargo fluff.
- Persist that height in the originated set, so a restarted origin still has it.
- Never anchor on the submission height.
- Alternative: derive the schedule from a per-node random offset of plus or minus 2 blocks. This is weaker: it adds noise, not equality.

**Test:** `a_block_found_during_the_stem_does_not_make_the_origin_reannounce_first` (raw spy connections opened at each height; assert the origin's first `InvTx` height is at least the relays').

**Severity**
- Trial: L2 x I4 = **8, Medium** (low PX volume).
- Public: L3 x I4 = **12, Medium**.
- **P0** because the fix is small and the docs claim the opposite at genesis.

### 3.3 TM2-P4: black-holing PX stems by draining relay budgets

**Code [src]**
- PX relay is rate-limited per peer (0.2/s, burst 4) and node-wide (2/s, burst 10) (docs/px.md section 11.5; `p2p/src/limits.rs`; charged in `net/admission.rs` after dedupe).
- A rate excess on a relayed `StemTx` is **dropped, not fluffed** (RTW2A-4, `admission.rs` about lines 134-144). That decision was correct in isolation: a forced fluff helps a spy.

**Attack**
1. About 10 spy connections, each sending distinct PX transactions that pass the cheap checks, keep a relayer's node-wide bucket empty.
   - Hollow-proof txs pass decode and shape (see Run D's "hollow proof").
   - Onion-inbound peers are never IP-banned (p2p.md section 11), so scoring does not stop it.
2. Every honest PX stem that reaches that relayer is silently dropped.
3. The origin is adjacent to its first hop, so its own embargo (10 s + Exp(39 s)) fires first with probability of about 1/k after a drop at hop k (SX2, dossier 33 section 3.4), and the origin then fluffs to everyone.
4. A first-hop black hole names the origin with probability of about 1.

**Mitigations:** none specific. 33 W3 (local re-stem through the other stem peer on first expiry) and W4 (kind-aware PX embargo) would both bound it. A per-source share of the node-wide bucket would raise the cost.

**Severity:** trial L2 x I4 = 8; public L4 x I4 = **16, High**. P1, and P0 for any public-testnet privacy claim about PX.

### 3.4 TM2-P6: stempool timing oracle on the slow lane (F33-2 residual)

**Partly closed**
- Pings are answered on the read loop. The heavy messages (`StemTx`, `Tx`, `InvTx`, `GetTx`, `GetHeaders`, `GetBlocks`) run on a per-peer FIFO slow lane (`net/dispatch.rs`).
- [test: `l6_a_peers_own_pongs_flow_while_its_inv_tx_waits_and_order_is_kept`] shows the Pong path is unaffected.

**Still open**
- `on_stem_tx` (`net/admission.rs` lines 502-552) returns at once if the id or any key image is already in the stempool. Otherwise it waits for `verify_on_tx_lane`: milliseconds for v1, about 0.2 s for PX.
- So `StemTx(X)` followed by `GetHeaders` from the same peer gives a `Headers` latency that tests stempool membership. Every downstream stem hop holds X's bytes.
- Side effect: the probe injects X into non-path nodes, so each target can be probed only once. That is enough.
- **Fix:** hand the verification off the per-peer lane (spawned with a per-peer in-flight bound) so later messages do not queue behind it. This is 34's Stage 4 direction.
- **Test:** `stem_replay_does_not_change_reply_latency` (dossier 33's test, with `GetHeaders` in place of `Ping`).

**Severity:** trial L2 x I3 = 6, Low; public L3 x I3 = **9, Medium**.

### 3.5 Address relay and node identity

**Closed**
- GetAddr from outbound peers is ignored (F32-4 / F33-5 part 1; `net/addr_relay.rs` `on_get_addr` lines 22-60) [test: `getaddr_from_outbound_is_ignored`].
- Relay does not depend on whether the table knew the address (F32-5) [test: `relay_does_not_reveal_whether_an_address_was_known`].
- Entry times in answers are forced to 0. The node's own entry time is rounded to 300 s.

**Open (dual-homed nodes)**
- GetAddr answers come from one table mixing onion and clearnet entries (`addrman.rs` `get_addr` lines 843-859). They are fresh random samples on every connection, with no per-network cache (33 W6, second half).
- A spy plants unique addresses over a clearnet inbound connection, then asks over the onion listener (or the reverse). Repeated connections scrape the whole table. Either way it can link a hidden service to its clearnet IP.
- Addresses we receive in answers to our own GetAddr are stored and may later be dialled from another identity (dial-back cookies).
- Anchors (`anchors.json`, two block-relay-only peers re-dialled first) let an anchor operator recognize the node across restarts and IP changes. Bitcoin Core accepts the same trade-off.

**Severity:** Low for single-homed nodes; **Medium** (L3 x I3) for dual-homed Tor nodes.

### 3.6 Other spy observations (Low)

- **Diffuser role:** a diffuser fluffs a peer's stem with `except = None` (`stem.rs` line 76), so the upstream stem peer gets an `InvTx` and learns that this node is the diffuser for that route. Dandelion++'s analysis already lets the adversary learn this in most cases. Informational.
- **Repeated broadcasts (F33-3):** a wallet's single re-send after `relayed + 2190` is a fresh origination, which is another independent sample. Accepted and documented (px.md section 12).
- **Embargo semantics (F33-6):** a stem entry is not removed when its tx is mined, only when a fluffed copy arrives. The later fluff just fails at debug level. There is no leak, but p2p.md line 692 says "or included in a block" ends the embargo (section 10, C-11).

---

## 4. Adversary 3: a malicious peer in direct connection

**Fingerprinting by `Version`** (`p2p/src/message.rs` `Version`; built in `net/conn.rs`):
- The message has no user agent, timestamp or service bits.
- `nonce` is fresh per connection and ChaCha seeded from getrandom at each start.
- `height` and `tip` are the best header, the same on all of a node's connections at one moment. They correlate sessions only while the node is syncing or forked.
- `listen` is sent only with `--public-address`: an onion only over Tor, clearnet only over clearnet (`net/peers.rs` `advertised_listen`).
- `relay_txs` is false only on our block-relay-only connections.
- Result: one constant protocol number, 3. Good. **Evidence:** p2p.md section 4 (doc); no "two nodes' Version bytes are equal" test.

**Fingerprinting by behaviour**
- There is no Reject message (the `Message` enum has none). Disconnects are silent TCP closes, and scores are identical across nodes of one version (`p2p/src/limits.rs`).
- Configuration does show:
  - `--public-address` (self `Addr`);
  - PSK (decryption failure at the first frame);
  - proxied peers (never banned);
  - fixed timers (ping 60 s, idle 180 s, key exchange 5 s / 10 s over Tor).
- No privacy issue beyond configuration classes.

**Active MITM**
- The transport is unauthenticated. A MITM reads `StemTx`, which gives origin, and can eclipse.
- **Closed for the trial:** PSK in the KDF (`transport.rs` `NetworkPsk`, `session_key`) [test: `a_man_in_the_middle_reads_the_traffic_unless_a_psk_is_set`]. This closes round 1 F48-1.
- **Public networks:** unchanged and documented (p2p.md section 1).

**TM2-P5 (partly NEW): Tor exits as MITMs, and Tor mode is weaker than recorded**
- **No onion-only outbound.** With a proxy, every outbound dial goes through SOCKS (`net/peers.rs` lines 343-353). The candidate filter skips onions only when there is *no* proxy (`skip_test`, line 440). So a `--proxy-only` node dials clearnet addresses through Tor exits.
  - decisions.md "Agent 32" says "Tor-only nodes: stay onion-only by default (no clearnet-over-Tor outbound mix)". **The code does not do that.**
  - An exit that carries one of these connections terminates the unauthenticated handshake. It reads the node's `StemTx`, which is first-hop origin information about a Tor client, and it can eclipse that link.
- **No SOCKS stream isolation.** `socks5::connect` offers "no authentication" only (`p2p/src/socks5.rs` lines 11-22). Tor's IsolateSOCKSAuth never separates the node's peer streams, so several clearnet links can share one circuit and one exit. Bitcoin Core's `-proxyrandomize` (default on) sends random credentials per connection for this reason.
- **`--proxy` without `--proxy-only`:**
  - the node still listens on `0.0.0.0` (`node/src/config.rs` lines 295-309);
  - it resolves seeds with system DNS;
  - it shares one mempool, stempool and addrman between both identities.
  - A held or black-holed local tx is fluffed at embargo to clearnet inbound peers too (F33-7 open; `net/maintenance.rs` embargo loop and `stem.rs` `fluff_entry`).
  - p2p.md section 11 does not warn that `--proxy` alone is dual-homed.
- **The shipped Tor config has the N-6 defect.** `deploy/config/testnet-tor.toml` forwards the hidden service to the P2P port and does not use `--onion-inbound`. So the N-6 defect applies: 2 inbound Tor peers at most, and one ban shuts out all of them (testnet.md section 4.3, which still calls it open even though `--onion-inbound` exists).
- **Severity:** not applicable in the trial (no Tor). Public, for Tor users: L3 x I4 = **12, Medium** (exit MITM plus dual-homed linking).

---

## 5. Adversary 4: a malicious remote node serving a wallet

The wallet's request map (all [src], `wallet/src/node.rs`, `rpc/src/lib.rs`, `wallet/src/wallet/*.rs`):

| Request | When | What the node learns or controls |
|---|---|---|
| `/info` | every sync, before every `/tx` | liveness; a submit is imminent |
| `/headers?from=H&count=1` | every sync (reorg walk) | synced height |
| `/headers` (pages) | restore or `--verify-headers` | restore height |
| `/blocks` (bulk, 100 per page) | every sync | scan range only (good: no per-output queries) |
| `/px/commitments`, `/px/contracts` | first sync or rescan, whole lists | nothing record-specific |
| **`/distribution?to=synced`** | **spend time only** (`px_flows.rs` `plans_for` lines 214-236) | **spend intent (F38-6) and the decoy distribution itself (F38-1)** |
| `/outputs` (consecutive pages `0..start`) | first spend after a restore | restore point; never ring members (good) |
| `/tx/status?id=` | every 20 blocks per pending tx | the tx ids of pending txs |
| `/tx` | submit and the single re-send | the transaction and the sender's IP (inherent) |

**What holds**
- Ring members are resolved from the wallet's own output index, so the node is never asked about members [src: `plans_for`, `member` closure].
- The wallet builds its own PX tree from verified blocks and checks anchors against its own root window (F39-1 closed; STATUS row "Wallet sync").
- Restores check headers from genesis, with dense PoW on the last 720 [ev: `docs/evidence/wallet-header-feed-2026-09-28/`].
- The wallet never re-posts before `relayed + 2190` and asks `/tx/status` instead (F38-3 closed) [test: `a_pooled_transaction_is_checked_not_posted_again`, `a_transaction_the_node_lacks_is_sent_again_once_only_after_the_network_expiry`].
- `/tx/status` never reveals stem state (`node/src/lib.rs` `tx_status` reads the mempool and blocks only) [test file: `node/tests/tx_status.rs`].

**What is open**

1. **TM2-P3 / F38-1: distribution poisoning.**
   - `plans_for` passes the node's `cumulative` straight into `usable_outputs`, the coinbase-maturity limit and `select_ring_keeping`.
   - The only checks are monotonicity (`tx/src/decoy.rs` `Picker::new`) and that the total equals the local index's end (`complete_index`).
   - The local index already holds every output's height (`IndexedOutput.height`), so a local distribution costs nothing. Decided P1, and P0 before a public testnet (decisions "Agent 38" W1). **Not implemented.**
   - **Attack:** skew decoy ages old, so the real young input is the newest member. The same node then receives the `/tx`.
   - **Severity:** L4 x I4 = **16, High** for remote-node users. Low with an own node (the trial).
2. **F38-6:** the spend-time `/distribution` marks spend intent and, with Tor, links the query and the submission. Removing it is part of the same fix.
3. **F38-5 / D3: decoys come from a plain RNG.** The CLI seeds a `ChaCha20Rng` from getrandom (`wallet/src/main.rs` lines 653-656, `os_rng` lines 367-373). The hedged stream covers only anchors, masks, nonces and PX blinds. A cloned VM or a broken OS RNG gives two wallets the same decoys, and their rings then differ exactly at the real inputs. Decided W3 (owner 38, keyed with `k_s`); **not implemented**. Medium (conditional).
4. **F38-2: the `/outputs` backfill below the restore height is not checked against blocks.** Accepted limitation until a verified feed exists.
5. **No SOCKS or TLS in the wallet (F38-8 / W5, decided P1).** The bearer cookie travels in clear over a direct remote HTTP connection. Documented in px.md section 12 and testnet.md section 11.
6. **NEW, Low:** `/tx/status` and the single re-send go to whatever `--node` is current. A user who switches nodes hands the new node the ids of transactions submitted elsewhere (`wallet/src/wallet/rebroadcast.rs` `check_pending`, `resend`). **Fix:** store the node identity per pending tx and skip status probes on a different node, or warn.
7. **Header PoW is not checked on routine syncs** of a created (non-restored) wallet; it runs only on restore or with `--verify-headers`. This is an accepted design (decisions "Agent 39" W5) and mostly an integrity question. The privacy consequence (F39-10, hidden spends leading to a new ring) is bounded by stored-ring reuse (W-5).
8. **Young-spend warning and spend delay: not implemented** (decided P1, "Agent 38").

---

## 6. Adversary 5: a chain analyst with full chain data

| Channel | What is public | Mitigation (file) | Evidence | Residual / severity |
|---|---|---|---|---|
| **v1 rings** | 16 members per input; their global indices, hence their ages | gamma picker, eligibility inside the draw (`tx/src/decoy.rs`), 10-block spendable age, 60-block coinbase maturity (`tx/src/params.rs`) | [test: `young_decoys_survive_coinbase_maturity`, `no_pile_up_at_the_maturity_boundary`] | Guess-newest ≈ 84-89 % for a spend 12 blocks after receipt on a mature chain [math+sim, dossier 38 F38-4]. The docs quote only the young-chain 51.5 % (section 10, C-1). `average_output_time` is computed over the whole chain (F38-9; Monero uses at most one year). Coinbase-dominated rings on small networks (documented). **Medium** (inherent to rings; the docs understate it) |
| **Fees** | the exact fee | T8: `fee == FEE_PER_WEIGHT x max_weight(n, k)`; PX fee constant | STATUS "Exact v1 fee (T8)" | **Closed** (an advantage over Monero's fee tiers). The PX *fee source* (v1 inputs vs `bridge_out = fee`) still marks the tx type |
| **Counts and shapes** | v1 input and output counts; PX v1-input, hidden-output, payout and function counts | the wallet always uses 2 outputs, change always present (`transfer.rs`, `builder.rs`) | — | Consolidations visible. PX tx type (deposit, send, withdraw, vault call) is readable from public fields. Inherent. **Low** |
| **Output order, extra, unlock time** | none | sorted outputs and key images (`validate.rs` `OutputsNotSorted`), no `extra` | [doc: transactions.md section 4.1] | **Closed.** However the encrypted fields (`enc_amount`, `enc_anchor`, `view_tag`, about 25 B per output) and the PX ciphertexts (2 x 1,241 B, `R` not validated) are unvalidated: covert channels or wallet fingerprints for non-reference wallets (section 10, C-6). **Low** |
| **View tags** | 1 byte per output (v1 and PX) | per-output `R` | — | Standard (Monero has the same). Informational |
| **Amounts** | v1 hidden; coinbase and PX payouts in clear; `bridge_in` and `bridge_out` in clear; the PX pool computable | containment by design (zk.md section 12.2) | — | Deposit-withdraw amount matching. The wallet only prints a reminder (`wallet/src/main.rs` lines 688, 725); it neither enforces nor suggests denominations, though zk.md calls them "wallet policy" (C-5). **Medium**, a design choice |
| **PX spends** | 2 nullifiers, 2 commitments, an anchor | Poseidon2 PRF nullifiers; anchor `round_down16(synced - 3)` (`wallet/src/px.rs` `anchor_height`) | [test in `wallet/src/px.rs` anchor-depth loop] | The anchor gives the build time to 16 blocks. Contract nullifiers are computable by anyone holding the opening (vault parties). **Low** |
| **PX proof length** | about 0.84 % spread (FRI path pruning) | fixed table shapes (budgets), canonical shape, 8 random codewords | [ev: `docs/evidence/p5-2026-09-26b/`, pre-v3]; [test: `kernel_budget.rs`] | **P-5 not re-run on the frozen v3 kernel** (STATUS section 5; 26 ZP-2). ZP-4 and ZP-5 (blinding tied to the extension degree; fail-closed blinding) are not implemented (`zkvm/src/air/util.rs` line 31 has no assertion). Evidence gap. **Low-Medium** |
| **Grinding witness** | the PoW nonce | deterministic smallest nonce (`zk/src/config.rs` `smallest_pow_witness`) | per 27 W6 | **Closed** (F27-3) |
| **Contracts and vault** | contract id, program, selector, window (non-zero only for timed vault claims and refunds), lock-to-claim timing | windows rounded to 16, timeouts multiples of 16 (`wallet/src/wallet/contracts.rs`) | RTW1C-2 tests | Documented (px.md section 12, contracts.md section 8). The refund window reveals *less* than the docs say (it always starts at `round_down16(next)`). **Low** |
| **Deploys** | ELF, salt; contract id bound to the first key image | — | — | Links a contract to the deployer's v1 inputs (documented I2-F5). The deploy path uses largest-first input selection **without** merge avoidance (`contracts.rs` lines 62-77). **Low** |
| **Coinbase** | amount and height; one output to the payout address | stealth one-time keys; the miner builds the coinbase locally, so the node never sees the payout address | — | Block origin by IP (section 2). The miner's own node logs "block ... accepted" at INFO only for its own blocks (`node/src/lib.rs` around line 816). **Low** |
| **Quantum** | v1 key images and outputs | — | transactions.md section 11.6 | Retroactive v1 deanonymization, including the v1 side of PX deposits and withdrawals. Documented |

---

## 7. Adversary 6: a malicious recipient or sender

- **Eve-Alice-Eve and black marbles (v1).** A sender knows the outputs it created and recognizes them in later rings. Black-marble floods are cheap on a quiet chain (F38-13, accepted). Documented in transactions.md section 11.3. **Medium on small networks**, inherent.
- **Merge linkage.**
  - Input selection avoids spending two outputs of one source transaction (R3-13; `transfer.rs` `gather`).
  - A dust sender can still force multi-input spends later, and two rings that each contain an attacker-known output reveal both real inputs.
  - The wallet warns only on the fallback. The deploy path has no merge avoidance.
- **Subaddress linkage (Janus).** The encrypted 16-byte anchor defeats it with the view key alone [test: `enc_anchor_is_uniform_to_observers`, `output_encoding_does_not_depend_on_recipient_type`]. It is a novel construction, reviewed internally only (transactions.md section 12.8). Good.
- **PX delivery.**
  - Hybrid ECDH plus ML-KEM-768, `cm`-bound acceptance (`px/src/delivery.rs`).
  - A recipient knows the fixed slot policy (send: recipient in slot 0, change in slot 1), so it knows which commitment is the payer's change. It cannot compute that change's nullifier without `nk`. **Low.**
  - The KEM combiner does not bind `V` or `H(ek)`. The hardening is recorded as "best done at a testnet reset" (px.md section 6), and this reset is the cheapest point. **P1-at-reset.**
- **View packages.** `IncomingViewKey` is range-wide; the address-scoped package (K4, P1) does not exist. The docs say so (F37-2 docs fixed). A range-view holder who learns another record's opening sees its spend (F37-3, documented).
- **Payment proofs, tx keys, view-only v1 wallet: none.** This is a design gap, not a leak: there are fewer artefacts to coerce, but disputes need disclosure of the whole view key. Monero has all three.

---

## 8. Adversaries 7 and 8: build or update channel, and the operator's own machine

### 8.1 TM2-P8: build and update channel

- **Remap.** Path remapping (`--remap-path-prefix` for CARGO_HOME, the sysroot and the checkout) exists only in `tools/release-build.sh` (about lines 184-190), which `docs/testnet.md` section 2 and `deploy/scripts/install-linux.sh` use.
  - Plain `cargo build --release` keeps the builder's home path in panic locations. These all use a plain build:
    - README.md line 98
    - `deploy/docker/Dockerfile` (container paths only, harmless)
    - `.github/scripts/build-guard.sh`
    - `docs/testnet-v3-genesis.md` around line 180
  - testnet.md lines 61-62 calls a plain build "still a valid build".
  - **No automated check scans a binary for home paths.** `tools/check-build-flags.sh --strings` and build-guard look for hook markers only. The only evidence is a manual grep in `docs/evidence/repro-windows-2026-10-01/README.md`.
  - RT-GUARD's decision "No binary built before this fix may be published" has no mechanical guard.
- **Signing and reproducibility.** There are no signed tags, which is an owner task (F48-4, decisions 43). Reproducibility is shown on one Windows machine only (STATUS "Reproducible node binary": Partially implemented). Miner and wallet report commit `unknown` unless the builder exports it.
- **Why it matters for privacy:** a trojaned wallet or node binary defeats every mechanism in this report: keys, origin, decoys. Trial operators build from source (decisions 43), which keeps the trial at **L2 x I5 = 10, Medium**. Any published binary raises it to **High** until signed and reproducible.
- **Fix:**
  - add a home-path string check (`$HOME`, `C:\Users\`, `/home/`, the username) to `check-build-flags.sh --strings` and build-guard;
  - point README and the genesis procedure at `release-build.sh`;
  - sign tags and publish hashes before any binary.

### 8.2 The operator's own machine

| Artefact | What it reveals | State | Severity |
|---|---|---|---|
| **TM2-P2: `originated.json`** (`p2p/src/originated.rs` `encode`, `write_atomic` lines 224-232: plain `File::create`) | Full hex id and relay height of every tx the operator originated, kept until about `relayed + 2190` (cap 10,000) | NEW (from 33 W2). Default umask (usually 0644) outside systemd (`UMask=0077`) and install-linux.sh (dir 0750). Missing from testnet.md section 4.5 | L3 x I3 = **9, Medium** |
| `peers.json` (with the addrman bucketing key), `anchors.json`, `bans.json` | Contact graph and stable contacts; the bucketing key helps target addrman | default permissions (`addrman.rs` `save` via `std::fs::write`; `connman.rs` `save_anchors`) | Low-Medium |
| INFO logs (default level `info`, stderr or journald) | every peer IP and connection kind (`net/conn.rs` around lines 366, 519; `peers.rs`); the data-dir path (user name); "block accepted" for own mined blocks | no rate limit (F48-8 open); no option to redact IPs | Medium (a persistent contact record) |
| DEBUG logs | "local tx <id> held / -> stem peer", "originated here before" (`stem.rs` lines 70, 78, 107, 217-228) | debug only; dossier 33 W12 (R10-10) not done. Evidence runs that turn on p2p debug logging record origins (labnet only) | Low (Medium if operators enable debug) |
| Wallet file | everything | Argon2id 64 MiB, t = 3, AES-256-GCM, 0600 on Unix, atomic writes (`wallet/src/file.rs`); no plaintext sidecars | good; size reveals index coverage (Informational) |
| Password via `BLACKSILK_WALLET_PASSWORD` | the password, visible to same-user processes, never wiped | supported (`wallet/src/main.rs`) | Low |
| Vault secrets via `--secret` or `--secret-out` | the secret on the command line or in a plaintext file | warned in help and at runtime | Low |
| Seed display | 27 words on stdout (terminal scrollback, screen capture) | `seed` requires typing `show` (part of F37-11) | Low-Medium |
| Swap, hibernation, core dumps, Windows Recall, clipboard | secrets in memory | no `mlock` (forbidden by policy); no `LimitCORE`; **no operator guidance anywhere** (F48-7 open) | **Medium** for the trial (Windows desktops) |
| `rpc.cookie` | RPC access | 0600 `create_new` on Unix; inherited ACL on Windows (documented limitation) | Low |

---

## 9. Re-check of round-1 (and other earlier) privacy findings

| Finding | Round-1 status | Now | Evidence |
|---|---|---|---|
| **F48-1** MITM of the explicit-peer mesh (stem origin) | Medium, not implemented | **Closed for closed networks** (PSK in the KDF, decryption failure unscored). Public networks unchanged (documented) | `transport.rs` `NetworkPsk`, `session_key`; [test: `a_man_in_the_middle_reads_the_traffic_unless_a_psk_is_set`]; p2p.md section 3 |
| **F48-2** supply-audit custody | Medium, not implemented | **Still open in the docs.** decisions.md (F48-2) decided "trial-only seeds; mid-trial audits per-operator and locally; the central run only at the END". testnet.md section 7.1 still says "at the end, and once in the middle", "Collect every wallet file on one machine". There is no custody banner in `tools/supply-audit` | testnet.md lines 492-505 |
| **F48-7** Windows endpoint leakage | Low-Medium | **Partly closed:** `seed` requires typing `show`. The endpoint checklist (Recall, clipboard, disk encryption, swap and hibernation, WER and core dumps) is absent from every doc | grep over docs, README, SECURITY.md |
| **F48-8** log fill (privacy side: peer IPs at INFO) | Low | **Open:** no rate limit; IPs still at INFO | section 8.2 |
| **Leaf I** (PX size reveals origin; small Dandelion++ sets; ProxyMark) | accepted | **Accepted and documented for PX** (STATUS section 6, testnet.md section 12.7). Not stated for v1 against a link observer (C-7) | — |
| **Leaf D1** (malicious remote node) | owned by 38 and 39 | **Partly closed:** F39-1 closed (own tree); F39-10 bounded; **F38-1, F38-2, F38-6 open** | section 5 |
| **Leaf D2** (seed not bound to network) | owned by 37 | **Closed in code:** seed v1 binds the network into `master` (px.md section 3.1). px.md section 6 still says "No network separation" (stale; C-9) | `wallet/src/seed.rs`; seed vectors [test: `wallet/tests/seed_vectors.rs`] |
| **Leaf D3** (broken or cloned RNG) | owned by 18 | **Open for decoys** (F38-5); hedged elsewhere | section 5 |
| F33-1 re-origination | Medium-High | **Closed** (originated set, persisted). It introduced TM2-P1 and TM2-P2 | [test: `a_restarted_origin_does_not_reoriginate_a_transaction_the_network_holds`, `an_expired_local_transaction_is_not_reoriginated_inside_the_window_even_after_a_restart`] |
| F33-2 stem replay timing | Medium | **Partly closed:** Pong off the slow lane; the slow-lane FIFO oracle remains (TM2-P6) | [test: `l6_...`] (liveness, not privacy) |
| F33-4 PX origin embargo | Medium | **Open**, and worse when composed with RTW2A-4 (TM2-P4) | dandelion.rs defaults |
| F33-5 / F32-4 GetAddr cookies | Medium | **Outbound part closed;** per-network cache and dual-homed linking open | [test: `getaddr_from_outbound_is_ignored`] |
| F32-5 membership oracle | Low-Medium | **Closed** | [test: `relay_does_not_reveal_whether_an_address_was_known`] |
| F33-6 embargo docs | Low | **Open** (docs) | p2p.md line 692 |
| F33-7 dual-homed fallback | Medium (Tor) | **Open** | section 4 |
| R8-16 shared inbound trickle | open | **Open** | `relay.rs` `announce_tx` |
| F38-3 rebroadcast origin oracle | Medium | **Closed** | rebroadcast e2e tests |
| F38-4 guess-newest docs | Low (claims); docs fix decided P0 | **Open** | transactions.md line 917 |
| F38-7 uncertain retry delay | Low | **Closed** (re-checked at the next sync) | px.md section 12 |
| F38-9 whole-chain average | Low (parity before mainnet) | **Open** | `decoy.rs` `Picker::new` |
| F38-11 fee fingerprint | Low / Medium | **Closed** (T8) | STATUS |
| F27-3 grinding nonce linkage | P0 privacy | **Closed** | `zk/src/config.rs` |
| 26 N7 / ZP-2 P-5 on v3 | P0 after the freeze | **Open** (evidence) | STATUS section 5 |
| 26 ZP-4 / ZP-5 / ZP-6 | P1 | **Open** | `zkvm/src/air/util.rs` |
| 37 K4 address-scoped view package | P1 | **Open** (documented) | px.md section 3.1 |

**What round 1 missed, and why.**
- TM2-P1 and TM2-P2 are side effects of the 33 W2 fix, which landed after round 1.
- TM2-P4 is a composition of two separately correct decisions (RTW2A-4 "drop, never fluff" and the single embargo).
- TM2-P5 contradicts a decision text ("onion-only by default") that the code never implemented.
- TM2-P8 extends RT-GUARD's finding: the remap landed, but only on one of five build paths, with no mechanical check.

Lesson: privacy fixes need their own adversarial test at merge. The 33 W1 suite (TM2-P10) is that gate.

---

## 10. Claims checklist: where the docs claim more privacy than the code or evidence supports

| # | Doc and line | Claim | Reality | Fix |
|---|---|---|---|---|
| C-1 | transactions.md lines 905-920 (section 11.3.1) | the real input is "still the newest member in about half the rings" | true only for a 3-day chain; ≈ 84-89 % on a mature chain (dossier 38 F38-4; decided P0 docs correction W9, not landed) | add the mature-chain figure and the model |
| C-2 | transactions.md line 935 | the node's distribution "reveals nothing about the ring" | it *controls* where decoys land (F38-1) | add: "it is trusted for decoy placement; a malicious node can skew it" until W1 lands |
| C-3 | px.md line 811 | the node "learns nothing from your scanning" | it learns the scan start (birthday), the restore point (`/outputs` pages), sync times, and spend intent (`/distribution`); testnet.md section 11 says so itself | align with testnet.md section 11 |
| C-4 | p2p.md lines 638-641 and the `relay.rs` comment | "the origin re-announces its own transaction exactly as every other node does" | false when a block lands during the stem (TM2-P1) | fix the code, or qualify the claim |
| C-5 | zk.md lines 895-899 | wallet policy: "bridge in standard denominations; bridge out after delays" | the wallet uses exact amounts and only prints a reminder | say "user guidance", or implement a helper |
| C-6 | transactions.md lines 274-276 | "Everything that can vary between wallets is either fixed by consensus or absent" | `enc_amount`, `enc_anchor`, `view_tag` and the PX ciphertexts (`R` unvalidated) are free bytes for non-reference wallets | qualify: "absent as fields; encrypted fields are unvalidated and must be random" |
| C-7 | STATUS section 6, testnet.md section 12.7 | only *PX* origin is listed as visible to the ISP | v1 origin is equally visible to a link observer through unpadded frame sizes and timing (Tor makes it harder for v1) | state it for v1, with the Tor nuance |
| C-8 | px.md line 828 | the PX fee "reveals nothing" | the fee *amount* is uniform, but its *source* (v1 inputs vs `bridge_out = fee`) marks the tx type | qualify |
| C-9 | px.md lines 368-381 (section 6, "Key separation: limits"); `px/src/delivery.rs` lines 26-35 comment | "No view/spend separation ... No network separation" | stale (V1 derivation): V2 has `ivk_k` and range views, and seed v1 binds the network | rewrite to match section 3.1 (an understatement, but contradictory) |
| C-10 | testnet.md line 485 | "spends are unlinkable" | statistically hidden among 16 ring members, not unlinkable | reword |
| C-11 | p2p.md line 692 | inclusion in a block ends the embargo | only a received fluffed copy ends it (F33-6) | reword |
| C-12 | p2p.md section 11 | `--proxy` "sends all outbound connections through a SOCKS5 proxy" | true, but the node stays clearnet-listening, uses system DNS and is dual-homed (F33-7) unless `--proxy-only`; and proxy-only dials clearnet peers through exits | add the warnings; recommend proxy-only plus `--onion-inbound` |
| C-13 | decisions.md "Agent 32" | "Tor-only nodes: stay onion-only by default" | not implemented (`net/peers.rs` `skip_test`) | implement `--onion-only` (default on under proxy-only), or amend the decision |
| C-14 | px.md line 285 | a deposit and a payment "have identical shapes" | proof shape only; the public statements differ trivially | qualify "proof shape" |
| C-15 | stale status (understatements, but they misdirect reviewers) | STATUS line 85 "Transport hardening: Not implemented" (done in e9ec2ff); line 95 "`ANCHOR_MIN_DEPTH`: Not implemented" (done); line 84 "Open: ... block-relay-only connections"; p2p.md lines 1552-1556 (no block-relay-only, seeds as full peers, Tor inbound shared limits); testnet.md section 4.3 "N-6 open" without mentioning `--onion-inbound`; testnet.md section 4.5 lists no `originated.json`, `anchors.json` or `rpc.cookie` | update; add a privacy note for `originated.json` and logs |

Claims that **hold**:
- ring 16;
- the T8 exact fee and the uniform PX fee amount;
- sorted outputs and no extra field;
- 1,241-byte uniform ciphertexts;
- `(0,0)` as the default window;
- no user agent, clock or service bits;
- GetAddr only for inbound peers;
- `/tx/status` never shows stem state;
- ring members resolved locally;
- the ZK wording in README and STATUS (statistical and conditional, computational in practice).

---

## 11. Missing protections compared with prior art

| Protection | Who has it | BlackSilk | Matters for |
|---|---|---|---|
| Uniform-looking transport (Elligator Swift, garbage, size classes) | Bitcoin BIP 324 | design notes only (p2p.md section 3.1, transport v2) | mainnet (P1); testnet: design choice (censorship is not a goal) |
| Post-quantum step in transport (against harvest now, decrypt later of stems) | — (Bitcoin none; this is BlackSilk's own v2 plan) | not implemented | mainnet P1 |
| Stream isolation per peer (`-proxyrandomize`) | Bitcoin Core (default on) | **missing** (no SOCKS auth) | public testnet with Tor: P1 |
| Onion-only or network-restricted outbound (`-onlynet`) | Bitcoin Core | **missing** (contradicts decision 32) | public testnet: P1 |
| Transactions only over an anonymity network, blocks over clearnet (`--tx-proxy`) | Monero | missing | mainnet P1/P2 (with W8) |
| Private broadcast (own txs through short-lived Tor connections) | Bitcoin Core 30.x private broadcast; Monero's anonymity-network relay | W8, P2 | mainnet P1 |
| Per-network cached `getaddr` answers | Bitcoin Core (PR #18991) | missing | public (Tor users) P1 |
| Shared inbound trickle timer, shuffled invs | Bitcoin Core | missing (R8-16) | public P1 |
| I2P | Monero, Bitcoin | not implemented (legacy only) | design choice; mainnet P2 |
| Wallet SOCKS and TLS | Monero (`--proxy`, `--daemon-ssl`), Zcash light wallets (TLS) | missing (W5, P1) | public testnet P1 |
| Restricted public RPC for remote-node service | Monero `--restricted-rpc` | P3 (decided) | design choice |
| Decoy distribution from local data | (Monero wallet2 *also* trusts the daemon's distribution) | BlackSilk is ahead on ring members (local index) and behind its own plan on the distribution | P0 before a public testnet |
| Full-chain anonymity set for spends | Zcash (shielded), Monero FCMP++ (research) | PX has it (all records); v1 is ring-16 | v1 long-term P3 (transactions.md section 11.7) |
| Shielded coinbase | Zcash (since Heartwood) | not in v3 (21-G) | design choice; P3 |
| Outgoing viewing key, payment proofs, view-only wallets with key-image export | Zcash (ovk), Monero (tx key, out proofs, reserve proofs, key images) | none in the CLI (PX view packages are a library API) | mainnet P2 (UX and audit), design choice |
| Transaction expiry by default | Zcash ZIP-203 (40 blocks) | PX6 default unbounded `(0,0)`, chosen for uniformity | design choice (fine as long as every wallet uses `(0,0)`) |
| Janus mitigation | Monero Carrot/Jamtis (planned) | **has** the encrypted anchor (novel, internally reviewed) | — |
| Fee fingerprint removal | (Monero fee tiers leak) | **has** (T8 exact fee) | — |
| Blocks-only or no-tx-relay mode | Bitcoin `-blocksonly` | missing | Low; P2 |
| Memory hygiene (`mlock`, no core dumps) | Monero (mlock of key pages) | forbidden by the no-`unsafe` policy; documentation is the only mitigation | trial P0 (docs), design choice |

---

## 12. Ranked work list

### P0: before genesis or trial launch (all cheap; none is a consensus change)

1. **TM2-P1 fix.**
   - What: anchor the origin's re-announcement on the height at which it first saw its tx in fluff (persisted in the originated set). Never anchor on the submission height.
   - Files: `p2p/src/net/relay.rs`, `p2p/src/originated.rs`, `p2p/src/net/stem.rs`.
   - Test: `a_block_found_during_the_stem_does_not_make_the_origin_reannounce_first`.
   - If not fixed in time: correct p2p.md section 7 and the code comment (C-4).
2. **Privacy regression suite (33 W1, TM2-P10)**, `p2p/tests/privacy.rs`, with:
   - the TM2-P1 test;
   - the slow-lane oracle test of TM2-P6 (marked `#[ignore]` with a reason if the fix lags);
   - "a held local tx is never announced";
   - "a diffuser still stems its own tx";
   - InvTx uniformity;
   - GetAddr only for inbound peers.
3. **`originated.json` and the other node files (TM2-P2).**
   - Create `originated.json`, `peers.json`, `anchors.json` and `bans.json` with 0600 on Unix (as `rpc.cookie` already is) and the data dir with 0700.
   - Document all of them in testnet.md section 4.5, with what each reveals and an "erase before sharing a data dir" note.
   - Design option, P1: keep only the ids still inside the window (already done). Consider re-deriving the set from the wallet's pending list instead of a node-side file.
4. **Docs corrections C-1 to C-15**, through the 47 claims checklist and doc-lint. C-1 is an already-decided P0 (W9).
5. **Supply-audit custody (F48-2):** bring testnet.md section 7.1 in line with the decision (per-operator local runs mid-trial; one central run at the end under the custody procedure). Add a custody banner to `tools/supply-audit`.
6. **Trial endpoint checklist (F48-7):**
   - Recall off;
   - clipboard history and sync off;
   - full-disk encryption;
   - encrypted swap and no hibernation (or accept the risk);
   - WER and core dumps disabled for the wallet;
   - logs at `info` (never debug on a trial device) and not in synced folders;
   - the `BLACKSILK_WALLET_PASSWORD` caveat.
7. **Before publishing any binary (TM2-P8):**
   - a home-path string check in `tools/check-build-flags.sh --strings` and `.github/scripts/build-guard.sh`;
   - README and the genesis procedure pointed at `tools/release-build.sh`.

   (P1 if no binary is published for the trial, as decided.)

### P1: before a public testnet or mainnet (those marked "public" are P0 for a public testnet)

8. **F38-1 and F38-6** (public): compute the distribution from the local index and drop the spend-time `/distribution`. Test: a node that serves a skewed but monotone distribution with the correct total cannot change the rings.
9. **F38-5:** hedged decoy RNG keyed with the derived hedge key. Test: two wallets with the same OS RNG but different keys draw different decoys.
10. **TM2-P4** (public, for any PX privacy claim):
    - local re-stem through the other stem peer on the first embargo expiry (33 W3);
    - a kind-aware PX embargo base taken from labnet PX hop latency (33 W4);
    - a per-source fair share of the node-wide PX bucket.
    - Measurement: a Rust first-spy simulator (33 W9) and a labnet PX stem-latency run.
11. **TM2-P6:** verification off the per-peer slow lane (34 Stage 4 direction).
12. **TM2-P5** (public, for Tor users):
    - `--onion-only` (default under `--proxy-only`), or amend decision 32;
    - random SOCKS credentials per connection;
    - a start-up warning that `--proxy` without `--proxy-only` is dual-homed;
    - origin fallback fluff to proxied and onion peers first (F33-7);
    - per-network cached GetAddr answers (33 W6);
    - `deploy/config/testnet-tor.toml` switched to `onion_inbound`.
13. **Wallet SOCKS5 (W5):**
    - `socks5h` forced, with random credentials;
    - a fresh client per submit;
    - `/tx/status` only to the node that received the tx (section 5 item 6).
14. **Trickle:** a shared inbound timer per network class, and shuffled inv batches (R8-16).
15. **Young-spend warning** (decided P1); F38-9 window parity before mainnet.
16. **PX evidence:** the P-5 re-run on the frozen v3 kernel (ZP-2, decided P0 after the freeze); ZP-4, ZP-5 and ZP-6 blinding hardening.
17. **Delivery combiner:** bind `V` and `H(ek)`. Do it at this reset, since a later change would need a coordinated upgrade.
18. **Logs:** a rate limit (F48-8); an option to log peer IPs at debug only; 33 W12 (stem routing out of debug logs, or behind its own target).
19. **Signed tags and cross-host reproducible builds** before any public binary (owner tasks).

### P2: hardening

20. Transport v2: Elligator Squared, garbage, size classes or padding buckets, rekeying, ML-KEM. This is decided "targeted" for v3; if it slips, it arrives as a flag day through `TRANSPORT_VERSION`.
21. Private broadcast (W8) and a `--tx-proxy` style split (transactions only over Tor).
22. Consensus checks at a future reset: the PX ciphertext `R` must be a canonical point. Consider requiring wallets' encrypted fields to be uniformly random (not checkable) and documenting this as the conformance rule for third-party wallets.
23. Denomination helper for PX deposits and withdrawals; merge avoidance in the deploy path.
24. View-only v1 audit with key-image export (also F48-2's P2); payment proofs; the address-scoped PX incoming package K4.
25. Diffuser `except` for the stem predecessor; an anchors-over-Tor policy.

### Measurements requested (no claim should rest on reasoning alone)

- **M1 (TM2-P1):** a labnet run with PX congestion, logging per-node re-announcement heights. Expect the origin at least one block early in a share of cases close to P(a block during the stem).
- **M2 (TM2-P4):** a labnet spy that drains a relayer's PX bucket. Measure P(first announcer = origin) against the honest baseline (7.6 % in 33's model).
- **M3 (TM2-P6):** `GetHeaders` reply latency after `StemTx` for a held vs an unknown PX tx.
- **M4 (F38-4):** guess-newest on a synthetic mature chain, as a committed test with its model, to back C-1.
- **M5 (TM2-P8):** a `strings` scan of `tools/release-build.sh` binaries on Linux and Windows for the build user's name.

---

## 13. Sources

Internal:
- `C:/bszkeval/p2/decisions.md`
- research dossiers 26, 27, 30, 32, 33, 37, 38, 39 and 48 in `C:/bszkeval/p2/research/`
- repository docs and code at `3c21afe`, cited inline

External, primary (cited by the dossiers, not re-fetched for this round):
- Fanti et al., "Dandelion++", SIGMETRICS 2018; Monero PR #7025 (q and embargo)
- Bitcoin Core: BIP 324; `net_processing.cpp` (shared inbound trickle, `NextInvToInbounds`); PR #18991 (per-network addr cache); `-proxyrandomize` (SOCKS stream isolation)
- Biryukov and Pustogarov, "Bitcoin over Tor isn't a good idea" (IEEE S&P 2015)
- Shi et al., "Deanonymizing Monero Transactions in Tor Network" (ProxyMark), arXiv 2607.07062
- Monero issue #3404 (untrusted remote node); Monero `--tx-proxy` anonymity networks
- Zcash ZIP-203 (expiry), ZIP-317 (fees), the outgoing viewing key (Sapling spec)
- Rucknium, Monero fee and decoy analyses (via dossier 38)

No web content was fetched in this round. No repository content was sent anywhere. No injected instructions were met.
