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

Applying a block (`MemoryChain::apply_block`) is atomic and returns an error instead of
panicking; block validation rejects every block that would fail to apply (for example
B8, the PX tree capacity). A block that passed validation and still fails to apply is
therefore a bug in this node: the manager halts (`ChainManager::halted`), logs the
block, does **not** mark it invalid, connects nothing more and refuses every further
block (`SubmitError::Halted`), and the node stops with exit status 65
(`HALT_EXIT_CODE`, node/src/lib.rs; other failures exit 1). A restart replays the store
and tries the block again; a real apply bug fails the same way again, so the systemd
unit does not restart on status 65 (`RestartPreventExitStatus`, docs/testnet.md §4.2)
(docs/reviews/v3-consensus-changes.md#tree-capacity; dossier 48 F48-5: never
auto-invalidate).

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
  keep one with v1 inputs out), then transfers and deploys by descending fee of their v1
  part per weight: a transfer's fee, a deploy's `standard_fee(n_in, n_out)`. A deploy's
  payload fee (`DEPLOY_FEE_PER_BYTE` per payload byte) pays for permanent registration
  state and buys no priority: ranked by its whole fee per weight, every deploy with a
  large program outranked every standard-fee transfer, which cannot pay more (T8), and
  displaced transfers from blocks (RTW1B-3). Tested with randomized pools of every kind
  (`templates_respect_both_budgets_for_every_kind`) and with vault-sized 64-input deploys
  against standard-fee transfers (`rtw1b_deploys_do_not_displace_standard_fee_transfers`).
- **Expiry** (`MEMPOOL_EXPIRY_BLOCKS = 2 160`, about 3 days at 120 s, Monero's pool
  lifetime). A transaction leaves the pool once the next block's height reaches the
  height it was admitted for plus 2 160, whatever its kind, deploys included (one value
  for every kind, so the expiry tells no kinds apart; PX transactions leave earlier when
  their anchor leaves the 100-block root window). It is counted from this node's
  admission height: there is no expiry field in transactions (a per-wallet value would
  fingerprint the wallet; Zcash's ZIP 203 field is rejected for that reason).
  - **Recently-expired guard** (`RECENTLY_EXPIRED_BLOCKS = 30`). For 30 blocks after
    expiring a transaction, the node refuses that transaction (by id) when it would
    originate it: on `/tx` (with P2P, before it enters the stem; without, before the
    pool), with `MempoolError::Expired` (`mempool::Origin::Local`). Without the guard, a
    wallet resubmitting its pending transaction at the block its own node expires it
    would re-stem it to a peer that still pools it, marking the node as the origin
    (dossier 38 §3.4; Monero's `m_timed_out_transactions`). Another transaction
    spending the same inputs is not refused by the guard.
  - Relay and stem admission do **not** apply the guard (`Origin::Peer`): a node
    admits a peer's transaction it expired recently like any valid transaction. Nodes
    expire a transaction up to the spread of their admission heights apart, so a stem
    peer that admitted it later than the origin is still inside its own window when
    the origin's ends; refusing it there would drop the origin's stem silently (a
    Dandelion black hole), and the origin would fluff its own transaction when its
    embargo fires (RTW1B-1, `rtw1b_a_later_stem_peer_admits_the_origins_reinjection`,
    `a_recently_expired_transaction_is_stemmed_for_a_peer_but_not_originated`). What
    the guard does not cover: the entries are not persisted, so a node restarted inside
    the window can re-originate the transaction to a peer that still pools it; the
    originated set (dossier 33 W2) and the wallet rebroadcast redesign (dossier 38 W4)
    are the planned remedies, and no privacy claim about expiry and resubmission rests
    on this guard alone.
  - After a reorganization to a lower height, expiry and the guard count against the
    new height: nothing expires early, and the guard lasts longer, never shorter.
  - A transaction returned by a disconnected block is pooled again even inside the
    guard window, with a fresh admission height (`Mempool::readmit`): it was on the
    best chain, so this is no re-injection by its origin. Its guard entry is cleared
    only if it is pooled; if it is refused, the entry stays (RTW1B-5).
  - Tested: `chain/src/mempool.rs` unit tests (expiry at exactly 2 160 for every kind,
    the guard window at both ends and on the local path only, reorganizations),
    `chain/tests/mempool_expiry.rs` (through the chain manager, with a real transfer:
    expiry, `Expired` on the local paths, admission on the stem path, and the return by
    a reorganization) and `p2p/tests/network.rs` (a peer's stem is relayed while the
    node's own `/tx` path refuses the transaction).
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
The route list is `blacksilk_node::ROUTES` (`node/src/lib.rs`).

| Method | Path | Purpose | Class | Body limit |
|---|---|---|---|---|
| GET | `/info` | network, height, tip id, difficulty, generated supply, mempool size, identity (genesis id, consensus fingerprint, commit, version) | read | none |
| GET | `/template` | mining template: height, prev id, difficulty, seed id, min timestamp, reward, fees, transactions | bulk | none |
| POST | `/block` | submit a mined block (`{"hex": …}`); admission rule §9.2 | block | `rpc::MAX_REQUEST_BYTES` (a maximum-size block in hex) |
| POST | `/tx` | submit a transaction (`{"hex": …}`); with P2P enabled it enters the Dandelion++ stem (p2p.md §8), otherwise the local mempool | submit | `guard::MAX_TX_BODY_BYTES` (the largest transaction of any kind in hex) |
| GET | `/blocks?from=h&count=n` | connected blocks with the global index of their first output (n ≤ 100, at most 64 MiB of hex), for wallet scanning | bulk | none |
| GET | `/distribution?to=h` | cumulative output counts per block, for decoy selection | read | none |
| POST | `/outputs` | output keys and commitments for up to 1 024 global indices | read | `guard::MAX_OUTPUTS_BODY_BYTES` |
| GET | `/px/commitments?from=f&limit=l` | a page of PX commitments in tree order (px.md §11.4) | read | none |
| GET | `/px/contracts?from=f` | contract registrations in block order (at most 1 024 per page) | read | none |
| GET | `/tx/status?id=<hex>` | `{"status":"pooled"}` (in this node's mempool), `{"status":"confirmed","height":h}` (in a connected block) or `{"status":"unknown"}`. A transaction still in this node's Dandelion++ stem answers `unknown`: the stem state is never reported (F36-11) | read | none |

The PX endpoints are bulk-only: there is no lookup of a single record, contract or ring.

### 9.1 Access control and limits (policy)

A guard (`node/src/guard.rs`) runs in front of every route, and in front of unknown paths,
before routing. In order:

1. **Host.** The `Host` header, and the authority of an absolute-form request target,
   must name `localhost`, an address in `127.0.0.0/8`, `[::1]`, the exact non-loopback
   address the RPC is bound to, or a name listed by the operator (for example an onion
   service name). Anything else, including `0.0.0.0`, `[::]` and every other name, is
   refused with `403`; a missing or repeated `Host` with `400`. This refuses DNS
   rebinding: a rebinding page always sends its own host name.
2. **Browsers.** A request with an `Origin` or any `Sec-Fetch-*` header is refused with
   `403`. The node's clients (miner, wallet, curl) send none of them; browsers send at
   least one on requests to loopback (W3C Fetch Metadata). There is no CORS support. This
   also stops cross-site no-cors GETs, which need no rebinding.
3. **Credential.** The node's RPC (`blacksilk_node::serve::run`) writes 32 random bytes as
   64 lowercase hex digits to `<data dir>/rpc.cookie` at every start (written to a
   temporary file and renamed; a stale file is replaced) and removes it at a clean
   shutdown. Every request, `/info` included, must carry
   `Authorization: Bearer <cookie>`; there is no unauthenticated endpoint. The comparison
   is constant-time (`subtle`). A failure is answered `401` after 250 ms. Clients take
   `--rpc-cookie <path>` or the `BLACKSILK_RPC_COOKIE` environment variable
   (`rpc::Client::with_cookie_file`, `with_cookie_option`). Routers built with
   `blacksilk_node::router` or `router_with` (tests, embedded use) have no credential but
   all other checks. The `blacksilk-node` binary serves its RPC only through `serve::run`
   (`node/tests/node_binary.rs`); extra host names come from `--rpc-allow-host` or
   `rpc_allow_hosts`.
   - **Unix:** the cookie is created with mode 0600.
   - **Windows:** the cookie inherits its directory's permissions. The default data
     directory is under the user's `%APPDATA%`, readable only by that user and
     administrators. Setting an ACL would need FFI, so a data directory outside the user
     profile only gets a warning. This is an accepted limitation.
   - The cookie keeps out other local users and web pages. It does not keep out malware
     running as the same user.
4. **Content type and body.** A `POST` must be `application/json` (`415` otherwise). Its
   body is read by the guard, up to the route's limit (`413`) and within 60 s (`408`).
   Other methods carry no body (`413`).
5. **Admission.** Each class has a fixed number of concurrent requests: read 4, bulk 2,
   submit 2, block 1, long poll 16 (`guard::Limits`). A request that finds its class full
   is answered `503` with `Retry-After: 1` at once, instead of waiting on a blocking thread
   for the chain lock. Clients retry with backoff.

The serve loop (`node/src/serve.rs`) adds connection limits: at most 64 open
connections (a connection beyond them is closed at once), a 10 s limit to receive a
request head, which also closes idle kept-alive connections, and a 16 KiB request head
(`431` beyond it). Shutdown lets in-flight requests finish within 10 s.

All of this is policy. It is not a claim that the RPC is safe to expose: keep it on
loopback, or reach it over SSH, a VPN or Tor. The connection is plaintext HTTP, so on
any other path the cookie and every request are visible.

### 9.2 `/block` admission

`/block` is for the local miner. Before any proof of work or storage, under a brief
chain lock, a block is refused (`accepted: false`, no PoW computed, nothing stored)
unless:
- its parent is the connected tip or one of its last `RPC_BLOCK_MAX_DEPTH` = 8
  ancestors, and its height follows the parent's (`NotNearTip`);
- its RandomX seed is the tip's or the next block's (`StaleSeed`), so an RPC client
  cannot make the node build the cache of another seed.

Within that depth the seed block lies on the connected chain and the parent is above the
P2P low-work threshold (p2p.md §6), so the rule is stricter than the P2P header gate.
Blocks of any other shape arrive over P2P, under that gate. The block's RandomX hash is
then computed outside the chain lock, and the submission hits the PoW cache.

### 9.3 Privacy of the RPC

A wallet that uses someone else's node reveals to that node, and over plaintext HTTP to
anyone on the path:
- its IP address;
- where it starts scanning (`/blocks?from=`), which approximates its birthday;
- that a send is imminent: `/distribution` is fetched just before `/tx`;
- the transaction itself, together with its IP address. The node stems it, so the
  network does not learn the origin, but that node's operator does.

Ring members come from the wallet's own output index; `/outputs` is used once, to fill
the missing range of that index in fixed pages, not per ring. Wallets should use their
own node.

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
