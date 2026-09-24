# BlackSilk Block, Emission and Node Specification

Status: **v1**, implemented by `blacksilk-chain` (`chain/`) and `blacksilk-node` (`node/`).

This document is normative for §1–§6. Those sections complete the consensus rules of
[`consensus.md`](consensus.md) (header chain) and [`transactions.md`](transactions.md)
(transactions). §7–§9 describe node policy and interfaces, which are not consensus.

All integers are unsigned and little-endian unless stated otherwise.

---

## 1. Units

`1 BLK = 10^8` atomic units. Every amount on chain is a `u64` count of atomic units.

- The whole emission curve fits comfortably in `u64` (§2).
- 64-bit range proofs cover any single amount.

## 2. Emission

Smooth emission with a permanent tail, in the style of Monero:

```
M    = 21 000 000 · 10^8   (2.1·10^15)      main emission asymptote
S    = 20                                   emission speed (for T = 120 s)
TAIL = 60 000 000          (0.6 BLK)        minimum reward, forever

G(h)      = Σ reward(i) for 0 < i < h       coins generated before block h (fees excluded)
reward(0) = 0                               genesis has no transactions (§3)
reward(h) = max(TAIL, (M − G(h)) >> S)      if G(h) < M
          = TAIL                            otherwise
```

- The coinbase of block `h` must pay exactly `reward(h)` plus the block's fees
  (transactions.md §8.3, B3).
- Every reward is a function of the height alone: `G(h)` is determined by the
  rewards of heights `1..h`, and fees are excluded. So `reward(h)` is the same on every
  branch, and a template for a side branch needs no branch-specific state.

**Curve.** Values computed with the formula above, 262 800 blocks per year:

| | Block | Reward / total emitted | Share of M |
|---|---|---|---|
| First reward | 1 | 20.027 160 64 BLK | |
| After 1 year | 262 800 | 4.66 M BLK | 22.2 % |
| After 2 years | 525 600 | 8.28 M BLK | 39.4 % |
| After 4 years | 1 051 200 | 13.29 M BLK | 63.3 % |
| After 8 years | 2 102 400 | 18.17 M BLK | 86.5 % |
| Tail starts | 3 678 315 (~14.0 years) | 20.37 M BLK emitted | 97.0 % |

From then on, emission is 0.6 BLK per block, which is 157 680 BLK per year: 0.77 % in
the first tail year, falling every year after.

**Why a tail.**
- Miner revenue must not depend on fees alone. A fee-only security budget is volatile
  and invites fee sniping and selfish mining.
- On a chain with hidden amounts, supply integrity rests on cryptography (balance and
  range proofs), not on an auditable sum. A hard cap therefore adds no verifiable
  guarantee.
- The tail also offsets coins lost over time.

Monero adopted the same reasoning in 2022.

## 3. Genesis

Each network's genesis header is the constant in `consensus/src/params.rs`.
- **Its body is empty:** no transactions and `tx_root` = 32 zero bytes, the Merkle root
  of the empty list.
- **There is no premine and no founder reward.** The first coins are created by block 1.
- The genesis block is never validated; it is the root of the chain.

## 4. Block format

```
header      100 bytes                          consensus.md §2
tx_count    varint, 1 ≤ n ≤ 10 000
txs[n]:     varint length ‖ transaction bytes  transactions.md §4 (strict decoding)
```

- Decoding is strict:
  - the whole block is at most `MAX_BLOCK_BYTES = 1 000 000 + 8 MiB + 64 KiB`: the v1
    weight limit, the PX byte budget (px.md §11.5), and framing headroom;
  - each transaction's length prefix matches its strict decoding exactly;
  - there are no trailing bytes.
- The block id is the header id (consensus.md §2). Because the header commits to
  `tx_root` over the transaction hashes, the id commits to the whole block.

## 5. Block validity

A block `B` at height `h` with parent `P` is valid iff all of the following hold:

1. its header is valid (consensus.md §6);
2. `P` is valid;
3. its transactions are valid against the transaction state after `P`, with
   `BlockContext { height: h, reward: reward(h), tx_root: B.header.tx_root }`
   (transactions.md §8, rules T, C and B1–B7);
4. with block weight limit `MAX_BLOCK_WEIGHT = 600 000` and
   `FEE_PER_WEIGHT = 20 atomic units` (transactions.md §8.4);
5. its PX and deploy transactions satisfy px.md §11.3 (PX1–PX5, the pool stays ≥ 0 in
   block order, contract ids unique) and fit the 8 MiB PX budget.

The v1 limits are fixed values; a dynamic block size is future work.

**Header-first processing.**
- A header is accepted into the header tree as soon as it is valid (item 1). Its body is
  validated when the block is about to be connected to the best chain.
- If the body is invalid, the block is marked invalid, along with all its descendants
  (consensus.md §8). The node then re-selects the best valid chain, possibly
  reorganizing.
- A body that does not match its header's `tx_root` is simply discarded. The header
  stays valid, because anyone can pair a valid header with garbage.

## 6. Reorganization and transaction state

The transaction state is:
- the ordered global output set;
- the set of spent key images;
- the set of used one-time keys;
- the running `G`;
- the PX state (px.md §5): commitment tree, root window, nullifier set, containment
  pool, the contract registry, and the logs wallets download. Every block's changes
  have an exact undo.

It is always the result of applying, in order, the bodies of the connected chain's
blocks `1..tip`.

The **connected chain** is the most-work chain whose bodies are all available.
- During header-first sync (p2p.md §6) the best *header* chain can be ahead of it, or on
  another branch.
- The node leaves its current chain only when the other branch, as far as its bodies
  have arrived, has strictly more work. A heavier branch whose bodies are still
  downloading therefore never rolls the state back early.

On a reorganization the node:
1. disconnects blocks back to the fork point, undoing their state changes in reverse
   order;
2. connects the new branch block by block, validating each body against the state
   before it.

Transactions from disconnected blocks return to the mempool if they are still valid
(§7).

## 7. Mempool (policy, not consensus)

- The mempool accepts a transfer if it is valid for inclusion at `tip + 1`
  (transactions.md `validate_transfer`) and none of its key images appears in another
  pooled transaction (first seen wins; no replacement in v1).
- PX and deploy transactions are validated in full, proof included, on admission. They
  conflict on key images, nullifiers and contract ids. They live in a separate class of
  at most `MEMPOOL_MAX_PX_BYTES = 64 MiB` with the same fee-per-byte eviction.
  - Their proofs are not re-verified when the pool is revalidated, nor when a block
    containing them is validated: a sound cache, because the transaction id commits to
    the proof (`validate_block_transactions_cached`).
  - Templates add them in fee-per-byte order within the PX budget, simulating the pool
    so that it never goes negative.
- It holds at most `MEMPOOL_MAX_BYTES = 50 MB`. When full, a new transaction is accepted
  only if its fee per weight beats the lowest one in the pool, which is evicted.
- **Block templates** take transactions by descending fee per weight, up to
  `MAX_BLOCK_WEIGHT − COINBASE_RESERVE` with `COINBASE_RESERVE = 3 000`.
- After every change of the connected chain, the pool:
  - removes confirmed transactions;
  - re-adds transactions from disconnected blocks;
  - re-validates everything against the new tip, dropping what no longer validates
    (spent key images, ring members now too young).

## 8. Storage (node)

Blocks are stored in an append-only file `blocks.dat` in the node's data directory.

```
record = magic "BSB1" ‖ LE32 length ‖ LE32 crc32(payload) ‖ payload
payload = pow_hash (32) ‖ block bytes
```

- **What is stored:** every block whose header was accepted (main chain and side
  branches). The record is written and flushed (`fsync`) *before* the block is applied,
  so a crash cannot lose an applied block.
- **Startup:** the node replays the file through the same code path as live blocks. For
  headers from its own file it uses the stored PoW hash instead of recomputing RandomX
  (about 0.45 s per header). Records are written only for headers that passed full
  header validation, including PoW, and the CRC detects corruption. Bodies are fully
  re-validated during replay, so a stored block with an invalid body is rejected again
  deterministically.
- **Corruption:** a truncated or corrupt tail record, for example from a crash
  mid-write, is truncated away with a warning. Corruption before the tail stops startup
  with an error rather than silently dropping blocks.

## 9. Node RPC (interface, not consensus)

JSON over HTTP/1.1, **bound to `127.0.0.1` by default**. Binary objects are hex strings.

| Method | Path | Purpose |
|---|---|---|
| GET | `/info` | network, height, tip id, difficulty, generated supply, mempool size |
| GET | `/template` | mining template: height, prev id, difficulty, seed id, min timestamp, reward, fees, transactions |
| POST | `/block` | submit a mined block (`{"hex": …}`) |
| POST | `/tx` | submit a transaction (`{"hex": …}`); with P2P enabled it enters the Dandelion++ stem (p2p.md §8), otherwise the local mempool |
| GET | `/blocks?from=h&count=n` | connected blocks with the global index of their first output (n ≤ 100), for wallet scanning |
| GET | `/distribution?to=h` | cumulative output counts per block, for decoy selection |
| POST | `/outputs` | output keys and commitments for up to 1 024 global indices, for building rings |

**Privacy of the RPC.** A wallet that uses someone else's node reveals to that node:
- which block ranges it scans (weak);
- **which ring members it fetches**. The real input is among them, so an operator who
  sees the same wallet fetch the same ring twice, or fetch a ring and then relay the
  transaction, can narrow down the real input.

Wallets should use their own node. Where they cannot, they should fetch decoys in larger
randomized batches (future work). The RPC must never be exposed publicly without
authentication, because `/block` and `/tx` accept arbitrary input and validation costs
CPU.

## 10. Wallet formats (interface, not consensus)

**Address strings** (`chain/src/address.rs`):

```
payload  = tag (1) ‖ D (32) ‖ C (32) ‖ H32("address/checksum", tag ‖ D ‖ C)[0..4]
string   = base58(payload)
tag      = 0x1b mainnet, 0x5a testnet, 0x7e regtest
```

- Decoding checks the checksum, the network tag, and that `D` and `C` are canonical,
  non-identity points.
- Primary and subaddresses share the format, so a string does not reveal which kind it
  is.

**Seed words:**
- The 32-byte wallet seed (transactions.md §2.1) is shown as 24 BIP-39 English words.
- The words encode the seed bytes directly. This is **not** BIP-39's PBKDF2 seed
  derivation, and there is no passphrase.

**Wallet file** (`wallet/src/file.rs`):

```
"BSW1" ‖ LE32 m_kib ‖ LE32 t ‖ LE32 p ‖ salt (16) ‖ nonce (12) ‖ AES-256-GCM ciphertext
key = Argon2id(password, salt; m_kib = 65536, t = 3, p = 1 by default)
```

- The header is authenticated as associated data.
- Salt and nonce are fresh from the OS RNG on every save.
- The file is replaced atomically.
- The plaintext holds the seed and the scanned outputs; both are secret.
