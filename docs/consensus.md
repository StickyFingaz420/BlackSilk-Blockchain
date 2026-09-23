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
| `network_id` (u32) | `0x000B1A6C` | `0x0001D670` | `0x00DEB06E` |
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
- **Testnet genesis is final**: timestamp `1790121600` (2026-09-23 00:00:00 UTC), id
  `bbeb1a9fdb16cf416ddb505e8468a16b4308d15307d0a12d9ef4ecfefed12909`.
- The mainnet genesis timestamp is provisional until its launch date.
- A test pins the testnet and regtest genesis ids.

Regtest uses 10-second blocks so that local tests cover hours of chain activity
quickly. Every other rule is the same on all networks.

## 2. Block header

Serialized form: exactly **100 bytes**, fields in this order, no padding:

| Offset | Size | Field | Meaning |
|---|---|---|---|
| 0 | 4 | `version` | header version; must be `1` |
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
The whole 100-byte header, including the nonce, is the input. The PoW hash is
**not** stored anywhere: every verifier recomputes it. The PoW hash and the block id
are different values.

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
  effect. Miners and nodes can prepare the new dataset in time, and a shallow reorg
  cannot change the key under active miners.
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

## 6. Header validation

A header `B` whose parent `P` is known and not invalid is valid iff, in this order
(cheap checks first, the expensive RandomX check last):

1. `B.version == 1`
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
- Reorg-depth limits and checkpoints are **node policy**, not consensus, and are
  documented with the node.

## 9. Determinism

- All consensus arithmetic uses integers, except inside RandomX. RandomX's
  floating-point rounding modes are emulated exactly in software, so its output is
  bit-identical on every CPU and compiler.
- The only input not derived from chain data is the local clock (§5 rule 2), which is
  treated as non-final.

## 10. Known limitations / open items

- The header-level PoW check costs about 0.45 s per header (light mode). Peers that
  send headers with invalid PoW must be penalized by the network layer to limit this
  DoS vector. Faster light-mode hashing is tracked in `AUDIT.md`.
- The mainnet genesis timestamp is provisional until launch (§1).
- Emission, block format and block limits: [`blocks.md`](blocks.md). Transaction
  rules and coinbase maturity: [`transactions.md`](transactions.md).
