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
   `FEE_PER_WEIGHT = 20 atomic units` (transactions.md §8.4); the v1 part of a PX or
   deploy transaction with `n > 0` inputs weighs `max_weight(n, k)` against it
   (transactions.md B6, R12-2);
5. its PX and deploy transactions satisfy px.md §11.3 (PX1–PX5, the pool stays ≥ 0 in
   block order, contract ids unique) and fit the 8 MiB PX budget.

The v1 limits are fixed values; a dynamic block size is future work.

Body validation runs its checks cheap-first (transactions.md §8.3, "Evaluation order"):
malformed PX proofs are found before any ring is resolved or any CLSAG verified, and
the range-proof batch runs before the CLSAGs. The order changes only which error an
invalid block reports, never its validity.

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
- the running `G`;
- the PX state (px.md §5): commitment tree, root window, nullifier set, containment
  pool, the contract registry, and the logs wallets download. Every block's changes
  have an exact undo.

There is no set of used one-time keys: output one-time keys may repeat across
transactions (transactions.md §8.2; removed for the v3 genesis,
reviews/v3-consensus-changes.md §1). Outputs are records by global index, so two
outputs with the same key are two records.

It is always the result of applying, in order, the bodies of the connected chain's
blocks `1..tip`.

The **connected chain** is the most-work chain whose bodies are all available. Its tip
is the *connection target*: the most-work valid header whose own body and every
ancestor's body have been kept ("body-complete"; `chain/src/manager.rs`).
- During header-first sync (p2p.md §6) the best *header* chain can be ahead of it, or on
  another branch. The header-best chain only guides downloads and the block locator;
  it never decides the connected chain.
- The node leaves its current chain only for a body-complete block with strictly more
  work. A heavier branch whose bodies are still downloading therefore never rolls the
  state back early, and one whose bodies are **withheld** never holds the chain back.
- **Ties.** Between equal-work candidates the connected tip stays (no flapping).
  Otherwise the candidate that became body-complete first wins. A block becomes
  complete when its body is kept and its parent is complete; blocks waiting for a
  parent complete, when it arrives, in body arrival order. The choice therefore depends
  only on the order in which bodies were kept, which is the storage order, so a restart
  reproduces it exactly (§8).
- Fixed 2026-09-27 (A10-H1). Before, the state only followed the header-best chain,
  where a tie keeps the first header seen. An attacker who announced a header B1 on
  the tip and withheld its body tied the local miner's next block A1; A1 was never
  connected, templates stayed on the old tip, and block production stalled for good
  (more generally: any bodiless branch with at least the tip's work plus one block).
  Tested by `chain/tests/fork_choice.rs` and, over TCP with an attacker peer that
  announces a header and never serves the body, `p2p/tests/withheld_body.rs` (which
  fails on the old code).
- Downloads (`ChainManager::missing_bodies`) cover the path to every valid header tip
  with strictly more work than the connected tip, not only the header-best one, so a
  competing heavier branch is fetched while the header-best one's bodies are withheld.
  Equal-work tips are not fetched: they cannot replace the connected tip.

On a reorganization the node:
1. finds the fork point (the target's last ancestor on the connected chain);
2. disconnects blocks back to it, undoing their state changes in reverse order;
3. connects the target's branch block by block, validating each body against the state
   before it.

If a body fails, the block and its descendants are marked invalid (header chain
included) and dropped from the candidates; the target is recomputed (the most work
among the remaining complete blocks, the connected tip on a tie) and the loop repeats,
reconnecting the old chain if it is again the best. The state is synced after every
single block that becomes complete, live and on replay alike.

Transactions from disconnected blocks return to the mempool if they are still valid
(§7).

## 7. Mempool (policy, not consensus)

- The mempool accepts a transfer if it is valid for inclusion at `tip + 1`
  (transactions.md `validate_transfer`) and none of its conflict keys appears in another
  pooled transaction (first seen wins, whatever the fee; no replacement in v1).
- **Conflict keys** (`mempool::conflict_keys`), each kind in its own namespace, so equal
  bytes of two kinds never conflict:
  - key images (C2), PX nullifiers (PX2), deploy contract ids.
  - **Output one-time keys are not conflict keys.** Consensus does not require them to
    be unique across transactions (transactions.md §8.2; the former rule C4 was removed
    for the v3 genesis, reviews/v3-consensus-changes.md §1). A key is public once its
    transaction is relayed; under C4 anyone who saw a pending transaction could get a
    copy of one of its keys mined or pooled first, for one fee, and the victim's
    transaction was invalid on that branch for good. A first-seen rule on output keys
    in the pool would keep that veto as policy, so there is none: a copy and its victim
    are both pooled, both selected, and both valid in one block.
  - A connected block removes every pooled transaction sharing any conflict key with
    it.
  - Templates skip a transaction sharing a conflict key with one already selected, and
    log it. Admission already prevents it; this only keeps a broken invariant from
    making every template invalid.
  - Tested with forged, fully valid transactions with chosen output keys, including
    verbatim copies mined before their victim, across fees, arrival orders,
    reorganizations and restarts (`chain/tests/mempool_conflicts.rs`), and with
    synthetic transactions of every kind plus a randomized invariant test
    (`mempool.rs` unit tests).
- PX and deploy transactions are validated in full, proof included, on admission. They
  live in a separate class of at most `MEMPOOL_MAX_PX_BYTES = 64 MiB` with the same
  fee-per-byte eviction.
  - Their proofs are not re-verified when the pool is revalidated, nor when a block
    containing them is validated: a sound cache, because the transaction id commits to
    the proof (`validate_block_transactions_cached`).
  - Templates add PX transactions first, in fee-per-byte order within the PX budget,
    simulating the pool so that it never goes negative.
- It holds at most `MEMPOOL_MAX_BYTES = 50 MB`. When a class is full, a new transaction
  is accepted only by evicting **strictly** cheaper entries of its class (fee per
  weight, or per byte for PX), cheapest and then newest first.
  - The victims are chosen before anything is removed. If strictly cheaper entries
    cannot free enough room, the transaction is refused and the pool is unchanged.
  - Before 2026-09-27 the cheaper entries were evicted one by one even when the new
    transaction was refused in the end.
  - One sort per admission, not one scan per victim: a flood of small entries cannot
    make admission quadratic (`eviction_under_a_flood_stays_fast`).
- **Block templates** charge every transaction against the weight budget
  `MAX_BLOCK_WEIGHT − COINBASE_RESERVE` (`COINBASE_RESERVE = 3 000`), including the v1
  part of PX and deploy transactions (R12-2), and PX and deploy transactions also
  against the PX budget and deploys against the deploy sub-budget, so a template never
  breaks B6. Order: PX transactions first (their fee is uniform; v1 congestion cannot
  keep one with v1 inputs out), then transfers and deploys by descending fee per weight
  (one unit for both; no fee per byte is compared with a fee per weight). Tested with
  randomized pools of every kind (`templates_respect_both_budgets_for_every_kind`).
- **Expiry** (`MEMPOOL_EXPIRY_BLOCKS = 2 160`, about 3 days at 120 s, Monero's pool
  lifetime). A transaction leaves the pool once the next block's height reaches the
  height it was admitted for plus 2 160, whatever its kind, deploys included (one value
  for every kind, so the expiry tells no kinds apart; PX transactions leave earlier when
  their anchor leaves the 100-block root window). It is counted from this node's
  admission height: there is no expiry field in transactions (a per-wallet value would
  fingerprint the wallet; Zcash's ZIP 203 field is rejected for that reason).
  - **Recently-expired guard** (`RECENTLY_EXPIRED_BLOCKS = 30`). For 30 blocks after
    expiring a transaction, the node refuses that transaction (by id) on `/tx`, on
    relay and on the stem, with `MempoolError::Expired`, and does not stem or relay it
    (no peer is penalized: the transaction may be valid). Honest nodes admitted it
    within seconds of each other, so they expire it within the same few blocks; while
    any of them still pools it, none re-injects it. Without the guard, a wallet
    resubmitting its pending transaction at the block its own node expires it would
    re-stem it to a peer that still pools it, marking the node as the origin (dossier
    38 §3.4; Monero's `m_timed_out_transactions`). Another transaction spending the
    same inputs is not refused by the guard.
  - After a reorganization to a lower height, expiry and the guard count against the
    new height: nothing expires early, and the guard lasts longer, never shorter.
  - A transaction returned by a disconnected block is pooled again even inside the
    guard window, with a fresh admission height (`Mempool::readmit`): it was on the
    best chain, so this is no re-injection by its origin.
  - Tested: `chain/src/mempool.rs` unit tests (expiry at exactly 2 160 for every kind,
    the guard window at both ends, reorganizations) and
    `chain/tests/mempool_expiry.rs` (through the chain manager, with a real transfer:
    expiry, `Expired` on the fluff and stem paths, and the return by a reorganization).
- After every change of the connected chain, the pool:
  - removes confirmed transactions and every pooled transaction conflicting with them;
  - expires transactions pooled for 2 160 blocks (above);
  - re-adds transactions from disconnected blocks;
  - re-validates against the new tip, dropping what no longer validates:
    - **after a reorganization** (any block disconnected), every rule except PX proofs,
      because ring members may now resolve to different outputs;
    - **after a plain extension**, only the rules an extension can change
      (`revalidate_after_extension`): key images, the PX anchor window,
      nullifiers, the registry and the pool, and deploy contract ids.
      - Structure, balance and proofs belong to the transaction alone.
      - Outputs are only appended, so rings resolve to the same outputs and signatures
        stay valid; maturity only improves.
      - Measured: 6.3 µs instead of 6.8 ms per pooled transfer. A full v1 pool (about
        20 000 transfers) costs about 0.13 s per block instead of about 136 s under the
        chain lock (`mempool_revalidation_cost_per_transaction`).
      - Its verdicts match full validation
        (`revalidation_after_an_extension_agrees_with_full_validation`).
- **The mempool is not persisted.** After a restart it is empty; wallets rebroadcast
  their stored transactions (px.md §12).
- **No consensus effect.** Blocks are always validated in full, whatever the pool
  holds.
  - The only use of pool contents in block validation is the PX proof cache, keyed by
    the transaction id, which commits to every byte.
  - Tested: two nodes, one with the transactions pooled and one without, reach the same
    state from the same block, and both reject a tampered copy
    (`mempool_contents_never_change_a_blocks_verdict`).
- **Not implemented:** per-peer or per-source limits beyond the byte caps and the P2P
  rate limits; pool re-announcement with backoff and the wallet-side rebroadcast
  redesign (dossier 38 W4, W4n; owners 33/30 and 38).

## 8. Storage (node)

Blocks are stored in an append-only file `blocks.dat` in the node's data directory.

```
file    = file header ‖ record*
header  = magic "BSBH" ‖ LE32 version (1) ‖ LE32 network_id ‖ genesis_id (32)
          ‖ LE32 crc32(the 44 bytes before)                          (48 bytes)
record  = magic "BSB1" ‖ LE32 length ‖ LE32 crc32(payload) ‖ payload
payload = pow_hash (32) ‖ block bytes
```

- **Network identity** (added 2026-09-27, R10-3). A new store is created with the file
  header. At startup (`BlockStore::bind`, before any record is read) a store naming
  another network id or genesis is refused with "wrong network data directory", so a
  store left over from an earlier testnet (for example a v2 store after the v3 reset)
  is detected instead of being replayed into a new genesis and silently orphaned. A
  damaged header or an unknown format version is refused too (fail safe); a header torn
  while the store was being created (no record after it) is written again.
  - **Legacy stores** written before 2026-09-27 have no header (format 0: records from
    offset 0). They are accepted as they are, with a warning that their network cannot
    be verified, and stay headerless: nothing is rewritten, appends continue in the
    legacy layout. Only new stores get the header. Tested in `store.rs`
    (`a_new_store_is_bound_to_its_network`, `a_legacy_headerless_store_is_accepted_unchanged`,
    `damaged_and_torn_file_headers`) and `fork_choice.rs::a_store_of_another_network_is_refused`.
- **What is stored:** every block whose header was accepted and whose body passes the
  low-work policy below (main chain and side branches). The record is written and
  flushed (`fsync`) *before* the block is applied, so a crash cannot lose an applied
  block.
- **Low-work bodies (node policy, not consensus; added 2026-09-27, R10-1).** A body is
  stored and kept only if its block's cumulative work is at least the connected tip's
  minus `LOW_WORK_MARGIN_BLOCKS` = 100 blocks at the tip's difficulty, or if the block
  is on the path to a header tip with more work than the connected tip (exactly the
  bodies `missing_bodies` requests). Otherwise the header is accepted but the body is
  neither stored nor kept (`Submitted::body_kept == false`). Before, every side-branch
  body was appended before any validation, so cheap children of early, low-difficulty
  blocks (testnet: difficulty 100) could be stored forever.
  - Honest reorganizations of any depth arrive header-first from the network and are
    candidates, so they are never refused, including a heavier branch that is not the
    header-best one. The margin covers locally mined side branches (a miner extending a
    fork up to 100 blocks deep, block by block). Near the tip the difficulty is about
    the current one, so each junk body the policy still keeps costs about one real
    block of work. (The margin was meant to be about 6 blocks; existing tests mine
    locally side branches up to 60 blocks deep block by block, which a 6-block margin
    would refuse. 100 keeps them working; a smaller margin is a later tuning decision.)
  - The refusal is reported as `Ok` with `body_kept: false`, not as a new
    `SubmitError` variant: the P2P layer's exhaustive match on `SubmitError` would
    otherwise need a change in `p2p/src/net.rs`. The P2P layer only accepts requested
    blocks without penalty, and requested ones are always kept.
- **Startup:** the node replays the file through the same code path as live blocks. For
  headers from its own file it uses the stored PoW hash instead of recomputing RandomX
  (about 0.45 s per header). The stored hash is trusted only under the RandomX key
  derived from the stored parent, exactly as header validation derives it: the PoW
  cache is keyed by (seed, header bytes). Records are written only for headers that
  passed full header validation, including PoW, and the CRC detects corruption. Bodies
  are fully re-validated during replay, so a stored block with an invalid body is
  rejected again deterministically.
- **Replay order.** Records are in arrival order, and bodies arrive in any order during
  header-first sync (up to 16 in flight, from several peers). A block is replayed once
  its parent is known; one stored before its parent waits for it. Blocks released
  together (the waiting children of the block just replayed) replay in storage order.
  - A stored block whose parent was never stored (the parent's write failed) is not
    replayed. It stays in the file, and the node downloads it again.
  - Descendants of a block found invalid are refused again on replay, including ones
    stored before it (header-first sync). Fixed 2026-09-27: before, such a grandchild
    stopped the node from starting (`UnknownParent`), and the log counted such blocks
    as orphans to download again.
  - **Replay equals live processing** (since 2026-09-27). Each replayed block becomes
    body-complete as it is replayed, and the state is synced after each one, exactly as
    live processing syncs after each completion; blocks released together complete in
    storage order in both. Headers that arrived without bodies are not replayed, and
    they never influence the connected chain (§6). So the tip, including every
    equal-work tie, the state, `G`, the PX state and the nullifiers are the same after
    a restart as before it (`fork_choice.rs::replay_reproduces_live_fork_choice_exactly`:
    16 random delivery orders of a tree with five equal-work tips, two restarts each).
    Before, the live node broke ties by first *header* seen and a restart by first
    *body* stored, so it could come back on the other tip.
  - Remaining exception: a stored block whose parent was never stored in the same
    session (a failed write) is dropped after a restart and completes live only when
    downloaded again, while a later replay releases the older copy as soon as the
    parent is replayed. This can only change which of two equal-work tips is kept.
  - Fixed 2026-09-27. Before, a node that had received bodies out of order refused to
    restart (`chain/tests/manager.rs::restart_after_out_of_order_body_arrival_replays_the_store`).
- **A failed write** (disk full, I/O error) is undone: the file is truncated back to
  its previous length. The block is refused (`SubmitError::Store`), is not kept in
  memory as if stored, and is downloaded again.
  - If the truncation itself fails, the store refuses further writes until the node
    restarts. The damaged bytes are then the file's tail, which the restart truncates.
  - So no record ever follows damaged bytes, and a node is never left unable to restart
    by a failed write. Before 2026-09-27 the partial record stayed in place, and the
    next block written after it made the whole store refuse to load.
  - **Fail safe.** When a write fails and cannot be undone, or 3 writes in a row fail
    (`STORE_FAILURE_LIMIT`: a full or failing disk), the chain manager marks the store
    failed (`ChainManager::store_failed`) and refuses every further block before
    looking at it: no header or state change. The node checks this every 2 s and exits
    with `block store write failed: free disk space / check the disk, then restart the
    node`, instead of staying up while re-downloading bodies it cannot store. A restart
    truncates any torn tail and resumes from the last stored block.
  - Tested with injected failures (`store.rs` tests, `chain/tests/storage_recovery.rs`:
    a crash at every byte of the last record, a full disk, a failure during a
    reorganization, restarts after each). A real full disk has not been tested.
- **Corruption:**
  - **Damaged tail** (a crash mid-write): truncated away with a warning. Damage counts
    as the tail only if **no** valid record starts anywhere after it.
  - **Damage followed by any valid record** is real corruption, not a crash. The node
    refuses to start rather than silently drop blocks (fail safe). The check is linear:
    each later position holding the magic is parsed at most once.
  - A torn last block whose data happens to contain a complete record-shaped byte
    string (block data is partly user-chosen) is also refused, since it cannot be told
    apart from corruption; the repair below recovers it without losing any valid
    record. Accepted trade-off: it needs a crash during exactly that block's write.
    (From 2026-09-27 until the fix the same day, a rule that required valid records to
    reach the end of the file accepted this case, but a mid-file bit flip plus a torn
    tail then silently truncated every block after the flip, in quadratic time.)
  - The operator repairs it with `blacksilk-node --repair-store` (one run; logged as a
    warning). Everything from the first damaged record on is moved to
    `blocks.dat.damaged-<unix time>` (synced to disk before the store is truncated),
    the store is truncated there, and the node downloads the dropped blocks again.
    Valid records after the damage are not salvaged (they are in the set-aside file).
    A missing store (fresh data directory) is "nothing to repair".
- **Known limitations** (acceptable for a controlled testnet; to be measured in the
  trial):
  - every block body and every block's undo data stays in memory (PX-F1, PX-F2);
  - startup reads the whole file into memory, then replays every block through full
    body validation, including every PX proof (about 0.2 s each; PX-F3). Only RandomX
    is skipped;
  - there are no indexes and no pruning;
  - side-branch blocks within the low-work margin, candidates' blocks, and blocks with
    invalid bodies stay in the file.
  - Startup time and memory therefore grow with the chain. A store with bodies on disk,
    indexes and a verified-state checkpoint is post-trial work.

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
