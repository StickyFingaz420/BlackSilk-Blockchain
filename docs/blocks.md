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
  of the empty list; no outputs (`output_count` 0, `output_root` 32 zero bytes, the
  root of the empty range) and the empty PX tree's root as `px_root`
  (`consensus::genesis::EMPTY_PX_ROOT`).
- **There is no premine and no founder reward.** The first coins are created by block 1.
- The genesis block is never validated; it is the root of the chain.

## 4. Block format

```
header      172 bytes                          consensus.md §2
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
   `BlockContext::of(B.header, reward(h))` (height, reward, and the header's `tx_root`,
   `output_count`, `output_root` and `px_root`; transactions.md §8, rules T, C, B1–B8,
   B-OMR and B-PXR);
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
- A body that matches `tx_root` but not the header's `output_count`, `output_root` or
  `px_root` (B-OMR, B-PXR) is the block's own body: the header commits to a false
  state, so the **block** is invalid and marked invalid with its descendants, like any
  other body failure. Only the block's miner can produce such a pair (the header
  commits to the body through `tx_root`).

## 6. Reorganization and transaction state

The transaction state is:
- the ordered global output set, with every node of its Merkle mountain range
  (consensus.md §7.1), so the range after any connected block is a lookup (undo
  truncates it);
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
(`HALT_EXIT_CODE`, node/src/lib.rs; the other exit statuses, 1, 2, 66, 70 and 71, are
listed in docs/testnet.md §4.2). A restart replays the store and tries the block again; a real apply bug fails the same way again, so the systemd
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

**Reference model.** `chain/tests/model` is an independent, brute-force executable
form of this section and of §7's pool rules; it shares no code with the manager.
`chain/tests/reference_model.rs` drives the real `ChainManager`, `MemoryChain` and
`Mempool` against it:
- every body arrival order, with and without headers first, of small trees with
  invalid bodies (explicit-state search);
- proptest over random trees, deliveries (orphans, duplicates, headers first, bounded
  drains paused across later arrivals), blocks with real transfers (double spends,
  blocks invalid by C2), and pool submissions;
- the mempool alone at explicit heights (conflicts, expiry, the guard, readmission).

After every step it compares the verdict, the connected chain, header validity, kept
bodies, `missing_bodies`, the pool and the deepest reorganization. It also checks:
- the tip has the most work among blocks whose whole branch has valid bodies;
- the state equals a fresh replay of the connected bodies;
- a paused drain never rests on a lighter tip;
- a restart reproduces the tip.

The model tests the rules as written here; it proves nothing beyond the cases it
runs. The known difference is listed in the test file (W2-02-I1, informational); the
model also found W2-02-F1, which was fixed (§7).

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
  - Their proofs are not re-verified when the pool is revalidated or readmits them,
    nor when a block containing them is validated: a sound cache, because the
    transaction id commits to the proof (`validate_block_transactions_cached`). A
    readmitted one was verified when its block connected, under the same rules.
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
    `a_recently_expired_transaction_is_stemmed_for_a_peer_but_not_originated`). The
    guard's entries are not persisted; the node's originated set (p2p.md §8.1) is,
    and keeps a restarted node from originating its own transaction again inside the
    window, and the wallet does not send a transaction its node lacks before
    `relayed + 2 190` (px.md §12). Neither covers a transaction submitted through
    another node.
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
  - re-validates against the new tip, dropping what no longer validates, without
    verifying any signature, range proof or PX proof again:
    - **after a plain extension**, only the rules an extension can change
      (`revalidate_after_extension`): key images, the PX window, anchor, nullifiers,
      registry, pool and tree capacity, and deploy contract ids.
      - Structure, balance and proofs belong to the transaction alone.
      - Outputs are only appended, so rings resolve to the same outputs and signatures
        stay valid; maturity only improves.
      - Measured: 6.3 µs instead of 6.8 ms per pooled transfer. A full v1 pool (about
        20 000 transfers) costs about 0.13 s per block instead of about 136 s under the
        chain lock (`mempool_revalidation_cost_per_transaction`).
      - Its verdicts match full validation
        (`revalidation_after_an_extension_agrees_with_full_validation`).
    - **after a reorganization** (any block disconnected), ring members may resolve to
      other outputs, or be immature at a lower height. The same checks, plus C1 at the
      new next height (`resolve_input_rings`, the function blocks use) and the entry's
      **ring digest**: a hash of the resolved `(one_time_key, commitment)` of every ring
      member of every v1 input, kept from when its signatures were verified
      (`mempool::ring_digest`, tag `mempool/ring-digest`, in memory only).
      - Unchanged digest: the CLSAG verdict is unchanged, exactly (`clsag::verify` is
        a function of the message, ring, pseudo-output, key image and signature; the
        rest is the transaction and the rules, which the pool fixes).
      - Changed digest: dropped without verification (the ring is hashed into the
        CLSAG aggregation coefficients and every round challenge, so a signature valid
        over one ring verifies over another only with negligible probability). The
        only error is dropping a transaction that would still verify; its wallet
        rebroadcasts it.
      - Before 2026-09-28 this path validated every entry in full, CLSAGs and range
        proofs included (dossier 12 M12-1): after any reorganization, minutes under
        the chain lock with a full pool.
  - then pools again the transactions of the disconnected blocks
    (`Mempool::readmit_returned`), each captured with its ring digest and its block's
    rules while the block was connected (`mempool::Returned::capture`; outputs are only
    appended, so the rings then resolve as when the block was validated). One is
    readmitted if its block's rules are the pool's (otherwise it would fail: dropped
    unverified), no pooled transaction holds one of its conflict keys (both would be
    the same owner's spends; the pooled one stays), the reorganization checks above
    pass and the class has room, with a fresh admission height and no signature or
    proof verified. Revalidation comes first, so stale entries neither take the room
    nor hold the keys. At most one class cap of returned bytes per class is captured
    and examined per reorganization (`READMIT_MAX_BYTES`, like Bitcoin Core's
    `MAX_DISCONNECTED_TX_POOL_BYTES`); the rest is dropped. The manager stops
    capturing, tip first, once a class's budget is reached
    (`Returned::capture_within`; each transaction is encoded once, and its size and
    id are kept for readmission), so a reorganization of any depth holds at most
    that much for readmission (RTW2A-6; before 2026-09-28 capture was unbounded
    and only readmission was bounded).
  - **Reservation during a bounded drain** (RTW2A-2). The manager captures a
    disconnected block's transactions when it undoes the block, but the pool
    receives them only when the whole drain ends, and between two drain steps the
    chain actor serves other commands. The conflict keys of every captured
    transaction are therefore reserved (`Mempool::reserve`) until readmission
    releases them: meanwhile admission, `check` and `Mempool::conflicts` refuse a
    transaction using one of them (`MempoolError::ReorgPending`, contextual, never
    scored), before any validation, and the returned transaction wins, as it does
    when the same reorganization is connected in one command. Before, a double
    spend admitted between two steps held the keys and the returned transaction was
    refused as a conflict (`chain/tests/revalidation.rs`, the `rtw2a_` pair: the
    bounded drain against its atomic control).
  - `Mempool::update_after_chain_change` does all of this and reports it;
    `Mempool::full_validations` counts every full validation the pool runs (none on
    these paths). The manager captures the transactions before it undoes their block
    (`chain/src/manager/fork_choice.rs`).
  - The pool is flushed when any transaction rule changes (`Mempool::enter_rules`),
    not only the signature domain: the paths above skip every stateless rule, which
    is exact only under the same rules.
  - Tested: `chain/src/mempool.rs` unit tests (an unchanged ring kept without
    verification; a changed ring and an immature member dropped; readmission without
    verification, of PX transactions without their proof, with conflicts, other rules
    and changed rings refused; returned transactions taking the room of stale entries;
    the byte bounds of readmission and of capture; reserved keys refusing a double
    spend until readmission); `chain/tests/revalidation.rs` (the two reorganizations above with
    real transfers, through the manager); `chain/tests/mempool_stateful.rs` (proptest:
    random submissions, extensions, reorganizations up to 69 blocks deep, expiry and
    templates; after every step the pool equals what full validation decides, no
    chain update verifies anything, templates are within budget and are accepted as
    blocks, and the manager's own pool agrees).
- **The mempool is not persisted.** After a restart it is empty; peers' pool
  re-announcement (p2p.md §7) brings pending transactions back, and a transaction this
  node originated is held, not originated again, if its wallet sends it (p2p.md §8.1,
  px.md §12).
  - This holds also when the replay itself reorganizes (for example through a heavier
    branch whose body fails): `open` empties the pool after the replay (finding
    W2-02-F1, `a_restart_that_replays_a_failed_reorganization_starts_with_an_empty_pool`).
- **No consensus effect.** Blocks are always validated in full, whatever the pool
  holds.
  - The only use of pool contents in block validation is the PX proof cache, keyed by
    the transaction id, which commits to every byte.
  - Tested: two nodes, one with the transactions pooled and one without, reach the same
    state from the same block, and both reject a tampered copy
    (`mempool_contents_never_change_a_blocks_verdict`).
- **Not implemented:** per-peer or per-source limits beyond the byte caps and the P2P
  rate limits; mempool persistence (dossiers 35/12; P1, designed in dossier 12 §9).
  Pool re-announcement is in p2p.md §7, the wallet rebroadcast in px.md §12.

## 8. Storage (node)

Blocks are stored in an append-only log of typed records, `blocks.dat` in the node's
data directory (format 3, `chain/src/store.rs`). Formats 1 and 2 are refused on every
network with resync advice (format 2 since output-root); format 0 is refused on testnet
and mainnet and still read on regtest (below).

```
file    = file header ‖ record*
header  = magic "BSBH" ‖ LE32 version (3) ‖ LE32 network_id ‖ genesis_id (32)
          ‖ LE32 crc32(the 44 bytes before)                          (48 bytes)
record  = magic "BSR2" ‖ LE32 n ‖ LE32 crc32(LE32 n ‖ body) ‖ body   (n = |body|)
body    = type (1) ‖ payload
  0x01 block       payload = pow_hash (32) ‖ block bytes
                   (pow_hash: RandomX of the header's mining blob, consensus.md §3)
  0x02 invalid     payload = block id (32) ‖ origin (1: verdict, 2: operator)
                             ‖ LE16 k ‖ reason (k ≤ 256 bytes, UTF-8)
  0x03 reconsider  payload = block id (32)
  0x81 checkpoint  payload = tip id (32) ‖ LE64 height ‖ state digest (32)
                             ‖ consensus fingerprint (32) ‖ LE16 k ‖ build commit (k ≤ 64, UTF-8)
  0x82 (reserved)  F48-5 quarantine marker ("validating <block id>"); not written, skipped
```

- **Record types.** A type with bit 7 set is *advisory*: ignoring it never changes the
  chain a replay reaches, so a build that does not know it skips it. Any other unknown
  type is refused (the store was written by a newer build whose records this one cannot
  honour). A record whose checksum holds but whose body is not a valid record of its
  type is refused too, wherever it is; it is never skipped and never truncated as a
  torn tail. The format was fixed before the v3 freeze so that v3 stores never migrate;
  new record types are added with new type codes.
  - **What this build writes:** block records, and the operator's `invalid`
    (origin 2) and `reconsider` records (below). Verdict markers (origin 1) and
    checkpoints are defined for the own-store trust work (S5 tombstones, S7), which is
    not implemented yet. On replay a checkpoint is not trusted (every stored block is
    validated in full), and a verdict marker is redundant (the block is validated again
    and gets the same deterministic verdict) (`chain/src/manager/replay.rs::scan`).
  - **Reserved:** type `0x82`, the F48-5 quarantine marker (written before a body is
    validated and cleared after, so that a start after a crash during validation halts
    naming the suspect block instead of looping). It is advisory and not implemented:
    this build writes none and skips it when read.
- **Operator invalidation** (node policy, not consensus; added 2026-09-28, S5).
  `blacksilk-node --invalidate-block <block id>` appends an `invalid` record of origin
  2 (operator) before the chain loads (`ChainManager::mark_stored_block`), and
  `ChainManager::invalidate_block` does the same on a running manager (not exposed
  through the chain actor or the RPC). The block and its descendants are never
  connected, whatever their bodies, and the node follows the best remaining
  body-complete branch: invalidating a block of the connected chain reorganizes to
  the best other branch, or down to the block's parent. It is Bitcoin Core's
  `invalidateblock`: a branch built on the block is not followed however much work it
  has, so a node whose operator invalidates a block the network accepts stays on its
  own chain until the verdict is cancelled.
  - **Where it applies.** On a block the store holds: when the block would become
    body-complete (`ChainManager::mark_complete`), on replay before its body is
    validated or applied (so the flag gets the node past a block that halts it at
    start-up, below). The verdict may name a block whose header the node does not know
    yet; it then applies **when the header arrives** (S5b, 2026-09-29;
    `ChainManager::refuse_operator_invalidated`), from a header batch or with a whole
    block: the header passes every header rule, proof of work included, and is then
    marked invalid at once and refused as a descendant of an invalid block is
    (`HeaderError::InvalidParent`, which the P2P layer does not penalize: the peer
    follows the network's rules). No body of it or of a descendant is requested or
    stored, and a descendant's header is refused by the pre-check before any proof of
    work. The header stays known, so a heavier chain refused only because of the
    verdict is still reported (§9.4, operator fork). In every case the block's header is
    marked invalid, so the block and every descendant sent again are refused
    (`HeaderError::InvalidParent`). `invalid_reason` stays empty for it (no rule was
    broken); `operator_invalidated` reports it.
  - **At start-up** (RTW3-11) the node logs each verdict in force, with the full block id
    and the block's height (or that the block has not arrived yet), and whether a heavier
    chain is refused only because of them (§9.4, operator fork).
  - **Reconsider.** `--reconsider-block <block id>` appends a `reconsider` record that
    cancels the operator's earlier verdict on that id; the last operator record for an
    id wins, wherever it is in the log. It takes effect at that start (a running
    manager cannot reconsider). It does not cancel an operator verdict on an ancestor,
    and a block that breaks a rule stays invalid.
  - **Refused:** genesis (`InvalidInput`, nothing written; the node exits with status
    2), and a malformed id (status 2). A verdict already in force (invalidating an
    invalidated block, reconsidering one that is not) writes nothing.
  - **Durability.** The record is appended with `sync_data` before the verdict takes
    effect. A crash while writing it loses only that record (a torn tail); a crash
    while writing a later record keeps it.
  - **Compatibility.** Both record types are critical: a build that does not know them
    refuses the store rather than connect a block the operator ruled out. (The build
    before this one refused any store holding an operator `invalid` record.)
  - Tested in `chain/tests/operator_invalidation.rs` (the tip and a buried block, live
    and through the flag, with restarts; descendants arriving later; a block marked
    before it arrives; its header and its descendants' headers refused at header time
    with no body requested or stored (S5b); reconsider; genesis; a torn tail right
    after a marker; the apply-halt escape), `store_format.rs::replay_reaches_the_state_of_a_fresh_sync`,
    the `store.rs` record tests, `node/tests/node_binary.rs::
    the_node_binary_invalidates_and_reconsiders_a_block` (the binary end to end) and
    `node/src/config.rs::operator_block_flags`.
- **Network identity** (added 2026-09-27, R10-3). A new store is created with the file
  header. At startup (`BlockStore::bind`, before any record is read) a store naming
  another network id or genesis is refused with "wrong network data directory", so a
  store left over from an earlier testnet (for example a v2 store after the v3 reset)
  is detected instead of being replayed into a new genesis and silently orphaned. A
  damaged header, a file that is not a block store, or an unknown format version is
  refused too (fail safe), with nothing changed; a header torn while the store was
  being created (no record after it) is written again.
  - **Older formats are never migrated.** Format 0 (no file header; every store written
    before 2026-09-27, so every one belongs to a network from before the v3 reset) is
    refused on testnet and mainnet (F35-1): its network cannot be verified, and
    accepting it would append the v3 chain after an old network's orphaned blocks. The
    error says to move `blocks.dat` aside and resync. Since 2026-10-05 regtest refuses it
    too, with the same advice (before, regtest read it and appended to it in its own
    `"BSB1"` layout; its blocks and stored proof-of-work hashes predate the 172-byte
    header and the mining blob). Format 1 (file header, untyped `"BSB1"` records; stores
    of pre-freeze labnet runs) and format 2 (the 100-byte header, or an intermediate
    build whose stored proof-of-work hashes are of another input than the mining blob)
    are refused on every network with the same advice.
  - Tested in `store.rs` (`a_new_store_is_bound_to_its_network`,
    `a_legacy_headerless_store_is_refused_on_every_network`,
    `damaged_torn_and_foreign_file_headers`, which also refuses format versions 1, 2
    and an unknown one, `unknown_and_malformed_records`) and
    `chain/tests/store_format.rs` (`a_legacy_headerless_store_is_refused_on_every_network`,
    `a_format_1_store_is_refused_with_resync_advice`,
    `a_store_of_another_network_or_genesis_is_refused`: the chain manager refuses format
    0 and format 1 on every network, and another network or genesis).
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
  cache is keyed by (seed, mining blob), domain `BlackSilk/pow-cache/v3`. Records are
  written only for headers that passed full header validation, including PoW, and the CRC detects corruption. Bodies
  are fully re-validated during replay, so a stored block with an invalid body is
  rejected again deterministically.
  - **Stored hashes are re-checked** (decisions "Agent 01", TM2-5): the CRC does not
    stop someone who can write the file. After the replay the node recomputes the
    stored hash of the 16 highest connected blocks and of 48 connected heights drawn
    uniformly below them from the start-up's OS randomness
    (`StorePowCheck::NODE_DEFAULT`; by height on the replayed chain, never by record
    order, which the file's writer controls), or of every stored block with
    `--verify-store-pow` (`StorePowCheck::All`), and refuses the store if one differs
    (`StorePowMismatch`, node exit status 66). The first record of a block is the one
    validation uses; a later record of the same block with another hash is refused.
    A forged block below the tip region is found with probability at least
    1 - (1 - k/N)^48 per start (k forged of N heights; table in docs/testnet.md
    §4.5); side branches the node does not follow are not sampled. Node policy, not consensus:
    the verdicts on blocks do not change. `ChainManager::open` itself trusts every
    stored hash (`StorePowCheck::Trust`); the node opens with `open_checked`.
  - **Halts persist across restarts without a record.** A block that passed validation
    but fails to apply (for example the PX tree-capacity check; a bug by §6's rule)
    halts the node and is not marked invalid. Nothing about it is written to the store:
    the block record is already there, and replay rebuilds exactly the state the node
    had, so applying it fails again and `ChainManager::open` refuses to start, naming
    the block. A halt caused by a transient fault (tested with an injected one-shot
    failure, `an_apply_failure_after_validation_halts_without_invalidating`) connects on
    the next start. A persistent halt needs an operator decision: report the block,
    then restart once with `--invalidate-block <block id>` (the halt message names the
    full id), and the node starts on the block's parent without validating or applying
    it again (moving the store aside only resyncs to the same block). The block passed
    validation, so it is consensus-valid by the node's own rules and the rest of the
    network follows it: invalidating it forks this node off the network's chain (§9.4,
    operator fork) until the operator reconsiders it, presumably with a fixed build. The
    halt message says so (RTW3-8).
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
    16 random delivery orders of a tree with five equal-work tips, two restarts each;
    `store_format.rs::replay_reaches_the_state_of_a_fresh_sync`: a fresh sync, a
    restart after every block and a store holding markers reach one identical state,
    PX state included, over a reorganization and an invalid body; coinbase-only blocks,
    so the PX record and nullifier logs stay empty there and PX transactions are covered
    by `manager.rs::restart_rebuilds_the_px_state_exactly`).
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
  - Tested with injected failures (`store.rs` tests, `chain/tests/storage_recovery.rs`,
    `chain/tests/store_format.rs`): a crash at every byte of the whole store, file
    header and markers included (store level and chain-manager level), a write failing
    after every byte count of every record type with and without a working undo, a
    full disk, a failure during a reorganization, restarts after each. A real full
    disk has not been tested.
- **Corruption:**
  - **Damaged tail** (a crash mid-write): truncated away with a warning. Damage counts
    as the tail only if **no** valid record starts anywhere after it.
  - **Damage followed by any valid record** is real corruption, not a crash. The node
    refuses to start rather than silently drop blocks (fail safe). The check is linear:
    each later position holding the magic is parsed at most once. Every single-bit
    flip anywhere in a store is either refused or, inside the last record, cut back to
    an exact prefix of the records written (`store.rs::every_single_bit_flip_is_refused_or_cut_to_an_exact_prefix`);
    the checksum covers the record length too. The record decoder is exercised with
    random bytes (`random_bytes_never_panic_and_allocate_within_the_input`): no panic,
    and nothing is allocated beyond the bytes read.
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
    Valid block records after the damage are not salvaged (they are in the set-aside
    file). The operator's records are (RTW3-7, 2026-09-28): every intact `invalid`
    record of origin 2 and every `reconsider` record of the moved region is written back
    after the kept prefix, in its order, before the store is cut behind them, and each is
    logged with its block id. Before, a verdict written after the damage was moved aside
    with it, and the node connected the block the operator had invalidated. The region is
    walked record by record (the bytes of an intact record are never read as records);
    past a damaged record the walk resumes where its length field says it ends if a valid
    record starts there, otherwise at the next valid record. Only that last search can
    take a record-shaped byte string inside a damaged block for a record, so the operator
    compares the logged ids with the verdicts they gave. Tested:
    `store.rs::repair_keeps_the_operator_records_of_the_moved_region`,
    `chain/tests/rt_w3_regressions.rs::repair_keeps_operator_verdicts_written_after_the_damage`.
    A missing store (fresh data directory) is "nothing to repair". Repair handles the
    current format (3) only; it refuses a store without a file header (format 0), a
    damaged file header or another format version and changes nothing (the operator
    moves the store aside and resyncs).
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
| GET | `/info` | network and `network_id`, height, tip id, difficulty, generated supply, mempool size (`mempool_txs`, `mempool_bytes`), `outputs`, `peers`, `header_height`, `deepest_reorg`, `misbehaving_disconnects`, identity (genesis id, consensus, rules and identity fingerprints, commit, version, `build_flags`), `template_ready`, `template_latched` and, during an operator fork, `operator_fork` (§9.4); `network_psk_loaded` (whether a pre-shared key is loaded, never the key), `overrides` (the operator flags of this run that change a default, e.g. `--invalidate-block <id>`, `--skip-randomx-self-test`) and `operator_verdicts` (`block`, `height` or `null`: the operator invalidations in force) | read | none |
| GET | `/template` | mining template: height, prev id, header `version` (the epoch's), difficulty, seed id, min timestamp, reward, fees, transactions, the parent's output range (`output_count`, `output_peaks`: the miner appends its coinbase's and the transactions' outputs and puts the count and root in the header, B-OMR), the block's `px_root` for exactly these transactions (B-PXR), and `next_seed_id` inside the key-switch window; `503` until the node has caught up, during a drain, and during an operator fork (§9.4) | bulk | none |
| GET | `/tip?after=<id>&wait=<s>` | the connected tip (height, id, header height, `template_ready`); with `after`, held until the tip differs from it, at most `wait` ≤ 30 s (§9.4) | long poll | none |
| POST | `/block` | submit a mined block (`{"hex": …}`); admission rule §9.2 | block | `rpc::MAX_REQUEST_BYTES` (a maximum-size block in hex) |
| POST | `/tx` | submit a transaction (`{"hex": …}`); with P2P enabled it enters the Dandelion++ stem (p2p.md §8), otherwise the local mempool | submit | `guard::MAX_TX_BODY_BYTES` (the largest transaction of any kind in hex) |
| GET | `/blocks?from=h&count=n` | connected blocks with the global index of their first output (n ≤ 100, at most 64 MiB of hex), for wallet scanning | bulk | none |
| GET | `/headers?from=h&count=n` | the headers of connected blocks `h…h+n−1` (fewer at the tip, none above it), 172 bytes each, concatenated as hex, with the tip height (`1 ≤ n ≤ rpc::MAX_HEADERS_PER_REQUEST`); the wallet's header check reads the chain from the genesis with it (§10) | read | none |
| GET | `/distribution?to=h` | cumulative output counts per block, at most `h + 1` entries; kept for external tools (no wallet spend path uses it: the wallet derives its decoy distribution from its own output index, transactions.md §11.3.1). The client caps the answer's bytes by `h` (`rpc::DISTRIBUTION_ENTRY_RESPONSE_BYTES` per entry) | read | none |
| POST | `/outputs` | output keys and commitments for up to 1 024 global indices | read | `guard::MAX_OUTPUTS_BODY_BYTES` |
| GET | `/px/commitments?from=f&limit=l` | a page of PX commitments in tree order (px.md §11.4) | read | none |
| GET | `/px/contracts?from=f` | contract registrations in block order (at most 1 024 per page) | read | none |
| GET | `/tx/status?id=<hex>` | `{"status":"pooled"}` (in this node's mempool), `{"status":"confirmed","height":h}` (in a connected block) or `{"status":"unknown"}`. A transaction still in this node's Dandelion++ stem answers `unknown`: the stem state is never reported (F36-11) | read | none |

The PX endpoints are bulk-only: there is no lookup of a single record, contract or ring.

**Concurrency (node, not consensus).** One chain actor runs every chain operation of
the node, one command at a time, from priority lanes (p2p.md §10; `chain/src/actor.rs`).
`/info`, `/tip` and the halt watcher answer from the chain's published snapshot
(`ChainHandle::summary_cell`), never a command, so they stay prompt during a block
step, a reorganization or a slow disk. Their chain fields are those of the last
publication: at most one command or drain step old, and mutually consistent. Every
other route that reads the chain is one command on the actor's Query lane (`/block`:
its admission check on the Blocks lane; a local `/tx` without P2P: the Tx lane),
within its admission class (§9.1); it may wait for the command or drain step in
progress, and its answer describes the chain at one point of the actor's order (the
state may already be one command further when it arrives). No RPC request occupies a
thread while it waits.

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
   is answered `503` with `Retry-After: 1` at once, instead of waiting for the chain.
   Clients retry with backoff.

The serve loop (`node/src/serve.rs`) adds connection limits: at most 64 open
connections (a connection beyond them is closed at once), a 10 s limit to receive a
request head, which also closes idle kept-alive connections, and a 16 KiB request head
(`431` beyond it). Shutdown lets in-flight requests finish within 10 s.

All of this is policy. It is not a claim that the RPC is safe to expose: keep it on
loopback, or reach it over SSH, a VPN or Tor. The connection is plaintext HTTP, so on
any other path the cookie and every request are visible.

### 9.2 `/block` admission

`/block` is for the local miner. Before any proof of work or storage, in one brief
chain command, a block is refused (`accepted: false`, no PoW computed, nothing stored)
unless:
- its parent is the connected tip or one of its last `RPC_BLOCK_MAX_DEPTH` = 8
  ancestors, and its height follows the parent's (`NotNearTip`);
- its RandomX seed is the tip's or the next block's (`StaleSeed`), so an RPC client
  cannot make the node build the cache of another seed.

Within that depth the seed block lies on the connected chain and the parent is above the
P2P low-work threshold (p2p.md §6), so the rule is stricter than the P2P header gate.
Blocks of any other shape arrive over P2P, under that gate. The block's RandomX hash is
then computed outside the chain actor, and the submission hits the PoW cache.

### 9.3 Privacy of the RPC

A wallet that uses someone else's node reveals to that node, and over plaintext HTTP to
anyone on the path:
- its IP address;
- where it starts scanning (`/blocks?from=`), which approximates its birthday;
- when it sends, from `/tx` itself. The wallet does not fetch `/distribution` (its decoy
  distribution comes from its own output index), and the one-time `/outputs` backfill
  of a restored wallet is made by the `sync` that catches up, not by the spend, unless
  the wallet spends straight after the restore without a `sync` (transactions.md
  §11.3.1);
- the transaction itself, together with its IP address. The node stems it, so the
  network does not learn the origin, but that node's operator does.

Ring members come from the wallet's own output index; `/outputs` is used once, to fill
the missing range of that index in fixed pages, not per ring. The filled index is
checked against the synced block's header (`output_count`, `output_root`; B-OMR), and
every scanned block's `first_output` against its header's `output_count`, so neither
is the node's word (output-root; closes F38-2, 38 W11). The PX commitment tree is
built from the scanned blocks; `/px/commitments` is fetched whole, once, for the part
below the restore height, and never after it: an imported contract record is placed
from the commitments of the recent blocks the wallet keeps, or at a rescan (px.md
§11.4; RTW3-15: a download made for an import told the node that the wallet holds a
record whose position it does not know). Below the restore height the wallet also fetches `/px/contracts` whole, and the
blocks both lists name (the block of the last commitment, every block with a deploy),
one height each: the same requests for every wallet with that restore height. The
header check reads `/headers` from height 1. None of this depends on what the wallet
owns or uses. Wallets should use their own node.

### 9.4 Mining endpoints (policy)

- **Readiness gate** (RTW3-1, 2026-09-28; replaces the W2-09b gate). `/template` answers
  `503` with a body starting `syncing:` unless the node is *template-ready*
  (`blacksilk_chain::sync_policy::template_ready`, checked in the same chain command
  that builds the template, after the catch-up latch is updated with the node's clock):
  - **never mid-drain** (`sync_pending`): between the steps of a bounded drain the
    mempool is not yet revalidated, so a template could offer transactions the next
    block cannot carry. A drain connects bodies the node holds and always ends;
  - **catch-up latch**, as Bitcoin Core's initial-download latch. Until the node is
    first *caught up* (`sync_policy::caught_up`), templates are refused, since a block
    mined on a tip the network has passed is an orphan. Caught up means: no drain in
    progress, the best valid header at most `TEMPLATE_SYNC_SLACK` = 2 blocks above the
    connected tip (a header usually arrives just before its body), and the connected
    tip's timestamp at most `MAX_TIP_AGE_BLOCKS` = 24 target block times (48 minutes on
    testnet) before the node's clock. The bound, and why 24 is enough, is documented on
    `sync_policy::MAX_TIP_AGE_BLOCKS`. Regtest has no clock rule: its tests and lab
    networks mine at synthetic timestamps (Bitcoin Core skips this check for templates
    on test chains too), so a regtest node latches at its first input.
  - The latch is judged whenever the node is given a clock reading: before each block
    submission and header batch is processed, and at each `/template` request. Once
    set, it stays set until the process exits (it is not stored). **No header lead
    closes the gate again**: the W2-09b gate recomputed the header gap on every request,
    so three bodiless headers on a synced node's tip (a 3-block private branch, at any
    minority hash rate) stopped its mining until the bodies came or its chain outworked
    them (RT-W3 demonstration; `chain/tests/rt_w3_regressions.rs`).
  - **Restart after a network-wide stall.** A node that restarts while the whole
    network's tip is older than the bound (every miner gone for 48 minutes, or the first
    blocks of a network on an old genesis) is not caught up and would wait. The operator
    of the first miner starts its node once with `--mine-from-stale-tip`, which sets the
    latch at start (`ChainManager::set_template_latch`); the 503 body names the flag.

  There is no peer-count rule: the first node of a network mines alone from genesis once
  its genesis is recent or the latch is set. `/info` and `/tip` report `template_ready`
  from the published snapshot at the node's clock, and `/info` reports
  `template_latched`. The miner treats `503` as "retry later".

  **Risk.** Before the latch sets, a node that knows a heavier header chain whose bodies
  are withheld refuses templates until the bodies arrive or its connected chain outweighs
  those headers. This needs no majority: three withheld headers on the network's tip, a
  3-block private branch at any hash rate, delay a node that has not latched yet (the
  catch-up refusal is tested in `a_node_in_its_initial_catch_up_refuses_templates`). The
  delay lasts until the rest of the network's chain outweighs the withheld headers;
  keeping it up longer takes a branch that stays ahead of the network. It affects only
  nodes that started or restarted recently and have not caught up since. A node that has
  latched is not affected, whatever headers it is sent. The operator can release a
  delayed node by restarting it with `--mine-from-stale-tip`.
- **Operator fork** (RTW3-8, 2026-09-28). When a heavier chain is refused only because of
  an operator verdict (`--invalidate-block`, §8; `ChainManager::operator_fork`: the
  heaviest known header in the subtree of an operator-invalidated block, bodies found
  invalid excluded, has more work than the connected tip), a block mined on this node
  extends a chain the rest of the network does not follow. Then:
  - `/template` answers `503` with a body starting `operator fork:` that names the block,
    asks the operator to verify the incident through a second channel, and names
    `--reconsider-block` and the override. The override is
    `--mine-despite-operator-fork` (command line only).
  - `/info` carries `operator_fork` (`block`, `height`, `branch_height`,
    `templates_refused`), and `template_ready` is false unless overridden.
  - The node logs a warning when the fork starts, every 10 minutes while it lasts, and a
    notice when it ends (`blacksilk_node::watch_operator_fork`), and one at start-up.
  - **Limitation.** Headers built on an invalidated block after the verdict are refused
    unverified (`InvalidParent`), and on restart the stored descendants of the block are
    not replayed, so the refused chain's known work is a lower bound: after a restart only
    the invalidated block itself counts. The report ends when the node's own chain
    outweighs that known work, not the network's.
- **Next RandomX key.** During the `seed_lag` (64) template heights before a key switch,
  `/template` carries `next_seed_id`: the id of the block whose id becomes the key
  (`sync_policy::next_seed_height`, Monero's `next_seed_hash`), taken on the template's
  own branch. A miner builds that key's context in advance. The template's `seed_id`
  remains the only key its block is hashed with. The field is absent outside the window,
  and clients that do not know it ignore it.
- **Tip notification.** `GET /tip?after=<tip id>&wait=<s>` is answered at once when
  `after` is absent or differs from the connected tip. Otherwise the request is held
  until the tip changes, re-reading the published snapshot every
  `TIP_POLL_INTERVAL` = 20 ms, and at most `min(wait, rpc::MAX_TIP_WAIT_SECS = 30)`
  seconds; then it answers with the tip either way. It runs no chain command and has
  its own admission class (long poll, §9.1). The miner holds one such poll open and
  drops its work as soon as the tip moves off the template's parent (stale work,
  dossier 09 R9-9).

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

**Seed words (seed format v1, `wallet/src/seed.rs`):** 27 words from the BIP-39
English list (only the list: the format, the checksum and the derivation are not
BIP-39's). The list is vendored in `crypto/src/wordlist.rs`, and a test pins its digest.

```
data   = entropy (256 bits) ‖ version (5) ‖ network (2) ‖ birthday (10) ‖ features (2)
         275 bits, big-endian, cut into 25 symbols of 11 bits d_0 .. d_24
code   = Reed–Solomon over GF(2^11) (modulus x^11 + x^2 + 1, α = x), n = 27, k = 25:
         C(x) = Σ c_i·x^(26-i), c_i = d_i for i < 25, check symbols c_25, c_26 such
         that C(α) = C(α²) = 0
words  = list[c_0] … list[c_24], list[c_25 XOR 0x253], list[c_26]
master = H32("seed/master/v1", u8 version ‖ u8 network ‖ u8 features ‖ entropy)
```

- `entropy` comes from the OS CSPRNG. `master` replaces the former "32-byte seed":
  every wallet key derives from it (transactions.md §2.1, px.md §3.1).
- `version` is 1. Any other value is refused, so a wallet never guesses a derivation.
- `network`: 0 mainnet, 1 testnet, 2 regtest; 3 is reserved and refused. It enters
  `master`, so one entropy gives unrelated keys and addresses on each network. A seed
  restored for another network than its own is refused.
- `birthday = min(creation height >> 14, 1023)`, the 2^14-block epoch of the tip when
  the wallet was created. Restore scans from `max(1, birthday · 2^14)` unless told
  otherwise. It is not part of `master`: a wrong birthday moves the scan start, never
  the keys.
- `features`: bit 0 is reserved for a passphrase, bit 1 is reserved. Both must be 0.
- The two check words detect any one or two wrong words, a swap of two words included.
  A single wrong word can be located: the wallet names its position and asks for the
  seed again. It never applies a correction itself, because two wrong words can look
  like a different single one. The tweak `0x253` (the low 11 bits of ASCII "BS") makes
  other codes with the same field and roots fail the check.
- 27 is not a BIP-39 length: BIP-39 wallets refuse these words, and the wallet refuses
  BIP-39 phrases, the former 24-word format included (removed at the v3 reset).
- Entry is case-insensitive, and a word may be given by its first four or more letters.
- Vectors: `wallet/tests/data/seed_v1_vectors.txt`, generated by the independent script
  `tools/vectors/seed_v1.py` and checked by `wallet/tests/seed_vectors.rs`.

**Wallet file** (`wallet/src/file.rs`):

```
"BSW1" ‖ LE32 m_kib ‖ LE32 t ‖ LE32 p ‖ salt (16) ‖ nonce (12) ‖ AES-256-GCM ciphertext
key = Argon2id(password, salt; m_kib = 65536, t = 3, p = 1 by default)
```

- The header is authenticated as associated data.
- Salt and nonce are fresh from the OS RNG on every save.
- The file is replaced atomically.
- The plaintext holds the seed and the scanned outputs; both are secret.
- The plaintext is JSON, format version 3: the seed's entropy, version, birthday and
  features (so the words can be shown again), the network and genesis id, and the
  scan state. Files of versions 1 and 2 (24-word seeds, PX derivation 1) are refused.
- The scan state includes the wallet's own PX tree (frontier, root window, recent
  blocks' commitments, checkpoints, witnesses; px.md §11.4), the contract
  registrations derived from deploys (px.md §13.4), the headers of the last `N + 1 + 11`
  scanned blocks (the context of a header check), the height up to which the header
  chain was checked from the genesis, and the ids of the last RandomX key blocks among
  the checked headers. A version 3 file written before the wallet built its own tree
  holds the node's commitment list instead, and one written before registrations were
  derived holds the node's registrations: either loads with a warning, and the next
  sync rescans from the restore height.
- `seed` shows the words only after the user types `show` at a warning prompt
  (F37-11); `create` prints them once.

**What a wallet checks of its node** (dossier 39 W5, F39-10; `wallet/src/headers.rs`).
Blocks are decoded strictly; each block's id is recomputed from its header, its
`tx_root` from its transactions, and it must extend the previous block. Every PX
anchor must be in the wallet's own root window (px.md §11.4). The header chain is
checked by the first sync of a restored wallet, until it reaches the node's tip, and
at every sync with `--verify-headers` (opt-in: it builds a RandomX cache per key epoch
and hashes the sampled headers in light mode):
- each header's version, height and link; its difficulty recomputed with the LWMA
  rule over its own ancestors; its timestamp after the median time past and within the
  future time limit of the local clock;
- the RandomX proof of work (light mode) of every one of the node's last
  `wallet::DENSE_POW_TAIL` (720) headers and of the first scanned one (RTW3-5), and of a
  random sample of the others (`headers::HEADER_SAMPLES` expected), drawn from the OS
  RNG as the headers arrive, so the node cannot tell which are checked. A header of
  difficulty 1 is met by every hash and is not hashed. A forged header forces the node
  to forge every header after it, so a forgery is a suffix of its chain: within the last
  720 headers it is always caught; a deeper one is caught by the sample with a
  probability that grows with its length. (With uniform sampling alone, the red team's
  4-header forged suffix passed 25 of 30 restores.)

A header that fails is refused, with every block from it on. Every check starts at the
genesis (W3-39b): the headers below the first block the wallet scans come from
`/headers` (172 bytes each, `rpc::MAX_HEADERS_PER_REQUEST` per request) and are
checked first, so at any restore height every header's difficulty follows from the
genesis by the LWMA rule, and the work sample is drawn from the whole chain. A later
check continues from the wallet's own last headers when an earlier one checked them
from the genesis (the height is kept in the wallet file); a sync without the check ends
that, and the next check starts from the genesis again. The check then proves that the
chain follows the difficulty rule from the genesis and that the sampled headers carry
that work; it does not prove that the chain is the network's heaviest (a node that
mines its own chain from the genesis under the rule passes), which only other nodes can
show. Cost: a restore hashes the whole dense tail in light mode, which dominates the
check. The cheap checks run in order. The hashes they call for are computed in batches
of up to `headers::POW_BATCH` on every available thread (W3-39c), which share one light
cache per RandomX key. The verdict is that of checking header by header: the first
header refused in chain order, with the blocks before it applied. Figures in
[evidence/wallet-parallel-pow-2026-09-29](evidence/wallet-parallel-pow-2026-09-29/README.md)
and, before W3-39c,
[evidence/wallet-header-feed-2026-09-28](evidence/wallet-header-feed-2026-09-28/README.md)
(`wallet::tests_sync::header_feed_cost_for_3000_headers`, `--ignored`). Without
the check a wallet trusts its node for proof of work.

**Tip age** (RTW3-6). Every sync records the age of the synced tip by the local clock
(`sync` and `balance` print it). Past `STALE_TIP_WARN_BLOCKS` = 10 target block times
plus the future time limit the wallet warns; past `STALE_TIP_REFUSE_BLOCKS` = 60 of them
plus the future time limit (`wallet::stale_tip_limits`; about 2 h on the testnet) it
refuses to build any transaction, unless run with `--allow-stale-tip` for a network that
has really stalled. With a steady hash rate the chance of no block for `k` target times
is `e^-k`; a wrong local clock also trips it.

**What this bounds (F39-10).** A node that hides a spend from a restored wallet (which
would then spend the output again, and the two rings would intersect at the real
input) must either forge blocks or withhold them. Forged blocks: within the last 720
headers they fail the dense check; deeper forged suffixes pass only if the random
sample misses them, and only below that tail. Withheld blocks: the tip then goes stale,
and within at most 60 target times plus the future time limit the wallet refuses to
transact; a node that withholds less than that can still hide a spend made in the
withheld blocks. A node that mines a chain of its own from the genesis under the rule
passes all of this. F39-10 is bounded by these checks, not closed; a wallet's own node
remains the recommendation.

Below the restore height the wallet checks the node's lists against the blocks they
name, each bound to that header chain (px.md §11.4, §13.4): the block of the last
commitment listed must hold exactly the commitments listed at its height, and every
block the registration list names is read and its deploys give the registrations. The
first scanned block must extend the header at the restore height minus one.
