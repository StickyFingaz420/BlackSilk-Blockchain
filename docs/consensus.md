# BlackSilk Consensus Specification: Header Chain

Status: **draft v1**, implemented by the `blacksilk-consensus` crate (`consensus/`).
This document is normative: the node and the miner must implement exactly these
rules, and they do so by sharing one crate.

Scope: block headers, proof-of-work, difficulty, timestamps, chain selection and
reorganization. Transaction and block-body rules (coinbase, emission, balances, ring
signatures, size limits) are specified separately and are applied on top of the
header chain described here.

All integers are unsigned and little-endian unless stated otherwise.
`H(x)` is Blake2b-256.

---

## 1. Network parameters

| Parameter | Mainnet | Testnet | Regtest |
|---|---|---|---|
| `network_id` (u32) | `0x000B1A6C` | `0x0001D672` | `0x00DEB06E` |
| Target block time `T` | 120 s | 120 s | 10 s |
| Initial difficulty `D0` | 100 000 | 100 | 1 |
| Difficulty window `N` (LWMA) | 60 | 60 | 60 |
| Median-time-past window | 11 | 11 | 11 |
| Future time limit `FTL` | 360 s | 360 s | 360 s |
| RandomX epoch `E` | 2048 | 2048 | 2048 |
| RandomX lag `L` | 64 | 64 | 64 |

The genesis header of each network is a constant in `params.rs`.
- The genesis body is **empty**: no coinbase, no premine, `tx_root` = 32 zero bytes
  (blocks.md §3).
- **Testnet v2 genesis** (the planned reset, identity fixed 2026-09-26: PX rules from height 0, parameter set
  BS-ZK-2 with terminal blinding): timestamp `1790380800` (2026-09-26 00:00:00 UTC), network id `0x0001D672`,
  genesis id `6556f92dee4df050cfb113a2b4ba234794274854b69f7c8a39755ec7a66b037d`.
  Testnet v1 was `0x0001D670` at `1790121600`, genesis id `bbeb1a9f…`. The id
  `0x0001D671` was used only by the 2026-09-25 local reset rehearsal.
- The mainnet genesis timestamp is provisional until its launch date.
- A test pins the testnet and regtest genesis ids.

Regtest uses 10-second blocks so that local tests cover hours of chain activity
quickly. Every other rule is the same on all networks.

## 2. Block header

Serialized form: exactly **100 bytes**, fields in this order, no padding:

| Offset | Size | Field | Meaning |
|---|---|---|---|
| 0 | 4 | `version` | header version; must be the version of the epoch at `height` (§11); `1` in every epoch of the built-in schedules |
| 4 | 8 | `height` | distance from genesis (genesis = 0) |
| 12 | 32 | `prev_id` | block id of the parent (all zero for genesis) |
| 44 | 8 | `timestamp` | seconds since the Unix epoch (miner-chosen) |
| 52 | 8 | `difficulty` | the block's difficulty, must equal §4 |
| 60 | 32 | `tx_root` | Merkle root of the block's transaction ids (§7) |
| 92 | 8 | `nonce` | miner-controlled |

Decoding is strict: any length other than 100 bytes is invalid.

**Block id:** `id = H("BlackSilk/block-id" ‖ LE32(network_id) ‖ header_bytes)`.
The network id makes headers, and therefore whole chains, unique to one network.

The header commits to `height` so that a header can be checked in context without
the block body, and to `difficulty` so that a block's work is explicit.

## 3. Proof of work

**Algorithm:** RandomX v1 (spec: tevador/RandomX `doc/specs.md`), computed with the
`blacksilk-randomx` crate. This is the only PoW implementation in the project.

**Input:** `pow_hash = RandomX(key = seed_id(height), input = header_bytes)`.
The whole 100-byte header, including the nonce, is the input. The PoW hash is not
part of the header or of any block data sent to peers: every node recomputes it for
headers it receives. The node does cache it in its **local** block store and, at
restart, trusts the stored value for blocks read from its own file instead of
recomputing RandomX (blocks.md §8). The PoW hash and the block id are different
values.

**Validity:** interpret `pow_hash` as a 256-bit little-endian integer `h`. The block
satisfies difficulty `d` iff `h × d < 2^256` (Monero's `check_hash`). A difficulty of
`d` means an expected `d` hashes per block. Difficulty 0 is invalid.

**Work:** a block's work is its difficulty. A chain's cumulative work is the sum of
the difficulties of all its blocks, genesis included (u128).

### 3.1 RandomX key schedule (seed)

The RandomX key changes once per epoch of `E = 2048` blocks, with a lag of `L = 64`
blocks. This is the schedule Monero uses (`rx_seedheight`):

```
seed_height(h) = 0                                   if h <= E + L
               = (h - L - 1) & !(E - 1)              otherwise
seed_id(h)     = id of the block at seed_height(h) on the same branch
```

Why:
- Building a RandomX cache costs about 0.6 s and 256 MiB (plus ~2 GiB and minutes for
  a mining dataset). A per-block key, which the pre-rebuild code used, would force
  that cost on every block.
- An epoch of 2048 blocks (~2.8 days) keeps the key changing often enough that no
  precomputation or ASIC dataset can be reused for long.
- The lag of 64 blocks means the next key is known about 2 hours before it takes
  effect, so miners and nodes *could* prepare the new dataset in time, and a shallow
  reorg cannot change the key under active miners.
  - **As implemented, the miner does not prepare ahead:** it frees the old dataset and
    builds the new one when the node's template shows the new key, and does not hash
    meanwhile. Measured (2026-09-27, one machine): about 179 s with 8 threads under
    load, 1,217–1,219 s with 1 thread. Nodes verify in light mode and only need a new
    256 MiB cache (about 0.6 s).
  - The first switch is at height 2113 (then 4161, …). The switch has been exercised
    only in a test with a short epoch (16 blocks, lag 4, `chain/tests/manager.rs`),
    not at 2113 with the network parameters.
- The seed block must be looked up **on the header's own branch**. On a fork deeper
  than the lag, the two branches can use different keys.

## 4. Difficulty: LWMA-1

The difficulty of block `h` is computed from its ancestors on its own branch using
zawy12's Linearly Weighted Moving Average (LWMA-1), chosen because it:
- responds quickly to hashrate swings (important for a young network),
- bounds the influence of manipulated timestamps,
- has been deployed widely by CryptoNote-family coins.

Let `A` be the list of the up to `N+1` most recent ancestors (oldest first, ending with
the parent), with timestamps `t[i]` and cumulative difficulties `C[i]`, and `n = |A| - 1`.

```
if n < 1: return D0                         # block 1 (only genesis precedes it)
prev = t[0]; L = 0; S = 0
for i in 1..=n:
    this = t[i] if t[i] > prev else prev + 1      # out-of-order timestamps
    st   = min(6·T, this - prev)                  # cap a single solve time
    prev = this
    L   += i · st                                 # linear weights: newest counts most
    S   += C[i] - C[i-1]                          # sum of difficulties
L = max(L, n·n·T / 20)                            # bound the maximum increase
next = S · T · (n + 1) / (2 · L)                  # integer arithmetic, u128
return clamp(next, 1, u64::MAX)
```

During the first `N` blocks the window is shorter (`n < N`), which lets the
difficulty leave `D0` quickly.

## 5. Timestamps

A header with parent `P` is valid only if:

1. **Median-time-past:** `timestamp > median(timestamps of the last 11 blocks ending at P)`
   (fewer near genesis; the median of an even count is the lower middle element).
2. **Future limit:** `timestamp ≤ local_time + FTL` with `FTL = 360 s`.

Rule 2 depends on the local clock, so it is **not** a permanent verdict. A header
rejected only by rule 2 must not be marked invalid; it may be accepted later. `FTL`
is deliberately much shorter than Bitcoin's or Monero's 2 hours, because LWMA reacts
to timestamps within a few blocks: `FTL ≤ N·T/20` as recommended for LWMA. Nodes
must not adjust their clocks from peer time by more than `FTL/2`.

On regtest (`T` = 10 s) the recommendation gives `N·T/20` = 30 s, but regtest keeps
`FTL` = 360 s like the other networks. Regtest is a local test network, so this is
accepted; its difficulty is more sensitive to manipulated timestamps than the
testnet's.

Operators must keep their clocks synchronised (NTP): a node more than about 6 minutes
behind refuses honest blocks for that long, and a miner more than about 6 minutes
ahead mines blocks the others refuse (docs/testnet.md §12.2).

## 6. Header validation

A header `B` whose parent `P` is known and not invalid is valid iff, in this order
(cheap checks first, the expensive RandomX check last):

1. `B.version == epoch_at(P.height + 1).header_version` (§11). A version above every
   version of the schedule is `UnknownUpgrade`, which is **not permanent** (the sender
   probably runs a newer release). Any other mismatch is `BadVersion`, permanent.
2. `B.height == P.height + 1`
3. Timestamp rules (§5)
4. `B.difficulty == next_difficulty(P's branch)` (§4)
5. PoW: `check_hash(RandomX(seed_id(B.height), bytes(B)), B.difficulty)` (§3)

Headers whose parent is unknown are not stored (the network layer requests
the missing ancestors). Descendants of an invalid block are invalid.

## 7. Transaction Merkle root

`tx_root` commits to the ordered list of transaction ids (coinbase first):

```
leaf(x)    = H(0x00 ‖ x)
node(l, r) = H(0x01 ‖ l ‖ r)
root([])   = 32 zero bytes
level:     pair adjacent nodes; an odd last node is carried up unchanged
```

The leaf/node prefixes prevent second-preimage confusion between leaves and inner
nodes. Carrying odd nodes up (instead of duplicating them as Bitcoin does) removes
the CVE-2012-2459 class of duplicate-transaction malleability.

## 8. Chain selection and reorganization

- The **best chain** is the valid chain with the greatest cumulative work. On a tie
  the chain whose tip was accepted first is kept (no switching on equal work).
- When a newly accepted header gives another branch strictly more work, the node
  reorganizes. It computes the fork point, **disconnects** the old blocks
  from the tip down to the fork point, and **connects** the new blocks upward.
  The consensus crate returns this as an ordered `Reorg { disconnected, connected }`.
  The node applies it atomically to transaction state (undo old, apply new).
- Every header of the new branch has been fully validated (§6) before it can become
  part of the best chain. Header validation never depends on the current best chain,
  only on the header's own ancestors, so the result is the same on every machine
  and in any arrival order.
- If a block is later found invalid by body or transaction validation, the node marks it
  invalid. That block and all its descendants are excluded, and the best chain is
  re-selected among the remaining valid tips (possibly a reorg).
- **Header-best chain vs. connected chain.** The rules above select the best *header*
  chain. The node's transaction state follows the most-work valid chain whose bodies
  are all available (blocks.md §6): a header chain whose bodies are missing or withheld
  cannot hold it back, and between equal-work body-complete tips the connected one
  stays (else the one completed first). The two agree whenever the header-best chain's
  bodies are available. This is node behaviour, not a validity rule: which blocks are
  valid and which chain has the most work are unchanged (A10-H1, 2026-09-27).
- **Reorganization depth: PROVISIONAL testnet policy** (accepted by the owner for the
  experimental testnet on 2026-09-25; not a mainnet decision; analysis in
  docs/reviews/k4-reorg-policy.md). **No limit and no checkpoints.** The
  chain with the most work wins at any depth, so honest nodes always converge. The
  cost is that an attacker with more hash power can rewrite any amount of history
  (assumptions.md K1, K4). Reorganizations of `DEEP_REORG_WARN_DEPTH` = 10 blocks or
  more are logged as warnings, and the node keeps the deepest one seen
  (`ChainManager::deepest_reorg`) for monitoring.
- **Options not adopted:**
  - a hard depth limit: nodes that saw different branches could split permanently,
    and an attacker could partition the network deliberately;
  - release checkpoints: central trust in the release process.

  Both remain open for mainnet, after testnet measurements.
- Undo data is kept for every block in memory, so a reorganization of any depth can
  be carried out. Memory grows with the chain; a bound belongs with the storage
  work.

## 9. Determinism

- All consensus arithmetic uses integers, except inside RandomX. RandomX's
  floating-point rounding modes are emulated exactly in software, so its output is
  **designed** to be bit-identical on every CPU and compiler. **Verified** only on
  x86_64: the official vectors pass on Windows (locally) and the test suite on Linux
  (CI). There is no ARM64 run and no cross-platform comparison of identical chain
  hashes (assumptions.md K5).
- **RandomX conformance evidence** (`randomx/README.md`, "Verification status"): the
  official hash vectors 1a–1f of the reference (tevador/RandomX v1.2.3, including 1f,
  the ISUB_R immediate edge case of upstream PR #326) and its cache, dataset,
  superscalar, reciprocal and AesGenerator1R vectors. That is 6 end-to-end hashes
  under 3 keys. There is no comparison against the reference at scale (no reference
  corpus, no oracle for the software rounding emulation), and no vector has
  BlackSilk's 32-byte-key, 100-byte-header shape.
- **RandomX full mode** (what the miner uses) must reproduce the official hash vectors
  and agree with light mode (what nodes verify with) on 512 random inputs per key. The
  CI job `randomx-full` (Linux x86_64) checks this and passed in GitHub Actions CI runs
  78, 79 and 83 (2026-09-27), before vector 1f was added to it.
- The only input not derived from chain data is the local clock (§5 rule 2), which is
  treated as non-final.

## 10. Known limitations / open items

- The header-level PoW check costs about 0.45 s per header (light mode). Peers that
  send headers with invalid PoW must be penalized by the network layer to limit this
  DoS vector. Faster light-mode hashing is tracked in `AUDIT.md`.
- The mainnet genesis timestamp is provisional until launch (§1).
- Emission, block format and block limits: [`blocks.md`](blocks.md). Transaction
  rules and coinbase maturity: [`transactions.md`](transactions.md).

## 11. Upgrades: the rule-set schedule

*v3 candidate. Design, alternatives and the integration still owed by other
components: [`reviews/v3-upgrade-mechanism.md`](reviews/v3-upgrade-mechanism.md).*

`ChainParams.schedule` is a table of epochs (`consensus/src/schedule.rs`). Each epoch
has an activation height, a header version, a branch id and a PX verifier id. The
epoch of a block at height `h` is the last one whose activation height is at most `h`.

| Epoch | Activation | Header version | Branch id | Verifier id |
|---|---|---|---|---|
| `v3` (every built-in network) | 0 | 1 | `0x42537633` (`"BSv3"`) | 1 |

A table must be non-empty and start at 0. Its activation heights must increase, its
header versions must not decrease, and its branch ids must be nonzero and distinct.
`Schedule::new` checks this, at compile time for a constant table.

What the epoch fixes:
- **Header version** (§6 rule 1). The genesis header carries the version of epoch 0,
  so the genesis ids of §1 are unchanged.
- **Branch id.** Every transaction signature message and the PX proof binding `h_tx`
  commit to `LE32(network_id) ‖ LE32(branch_id) ‖ genesis_id` (transactions.md §4.4,
  px.md §11.1).
  A transaction signed or proved in one epoch is invalid in every other.
- **Verifier id.** It names the PX verifier (kernel, parameter set and kernel budgets).
  Only `1` exists. A test checks that every scheduled id is implemented.

**Rules for the network layer and the pool:**
- `UnknownUpgrade` is not the peer's fault: warn the operator ("a newer consensus
  version is in use") and do not penalize the peer.
- Validate a block at height `h` with the transaction rules of `epoch_at(h)`
  (`TxRules::at_height`).
- When the next height crosses an activation (`Schedule::activation_in`), flush the
  mempool: pooled transactions are bound to the old branch.
- `TxRules::for_chain` panics on a schedule with more than one epoch, so no caller
  can keep the first epoch's rules by accident.

**Privacy note.** After a contentious split with shared history, key images can be
spent on both chains with different rings. The branch id prevents replay; it does not
prevent ring intersection. Wallets must reuse stored rings.
