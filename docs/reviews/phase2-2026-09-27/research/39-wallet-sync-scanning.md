# 39 wallet-sync-scanning: research dossier (phase 2, phase 1)

> Historical record (2026-09-27). Superseded where it conflicts with the code: the header is 172 bytes (output-root commitments, f5daa0e) and the PoW input is the 47-byte mining blob with the nonce at byte 39 (921fdd5); the wallet derives the decoy distribution from its own output index and makes no spend-time `/distribution` request (1902761). Current: [docs/consensus.md](../../../consensus.md), [docs/STATUS.md](../../../STATUS.md).

**Internal engineering work, not an audit.** Nothing here claims that BlackSilk, its
wallet or any sync protocol is secure, audited or production-ready. Performance figures
marked [estimate] are arithmetic, not measurements. No build, test or benchmark was run
(phase 1 rules).

---

## 1. Scope and what I read

**Commit:** `9e422d8` (`rebuild/core`, `git rev-parse --short HEAD`).

**Scope (roster 39):** wallet sync (full blocks as hex), the local output index, the PX
tree rebuild (R12-8), PX scanning cost (R12-9), compact feeds (I1-F2, I3 §3.9),
`/px/commitments` pagination.

**Code read in full:**
- `wallet/src/px.rs` (944 lines: `PxStore`, `AddressKeys`, `apply_block`, `rewind`,
  `sync_commitments`, `tree_at`, selection, tests);
- `wallet/src/index.rs` (local output index and its tests);
- `wallet/src/node.rs` (the `NodeApi` trait);
- `wallet/src/wallet.rs`: constants and errors (40–180), constructors (517–572),
  persistence (830–956), `check_network`, `rewind`, `sync`, `apply_block` (958–1175),
  `for_each_input`/`submit` head (1284–1340), `complete_index`, `plans_for`,
  `px_deposit`, `px_inputs` (1800–2067); test names;
- `wallet/src/file.rs` (header, KDF), `wallet/src/lib.rs` (`load`, `save`);
- `rpc/src/lib.rs` (all 769 lines: types, caps, client, tests);
- `node/src/lib.rs` 120–530 (router, `/blocks`, `/px/commitments`, `/px/contracts`,
  `/distribution`, `/outputs`);
- `tx/src/state.rs` (all: `MemoryChain`, `PxRecordEntry`, record/nullifier logs, undo);
- `tx/src/scan.rs` (all); `tx/src/types.rs` 150–525 (prefix/base/prunable encodings,
  `Transaction::hash`, accessors); `tx/src/px.rs` 180–560 (PX and deploy
  prefix/base/prunable encodings, `decode_body`, `output_context`);
- `px/src/tree.rs` (all), `px/src/state.rs` (all), `px/src/delivery.rs` 1–340;
- `consensus/src/header.rs` 1–60, `chain/src/block.rs` 1–80,
  `chain/src/manager.rs` `block_at`.

**Tests read:** `wallet/src/px.rs` tests (8), `wallet/src/index.rs` tests (2), wallet.rs
test list, `wallet/tests/e2e.rs` (test list; bodies of `px_records_follow_a_reorganization`,
`rings_are_built_without_asking_the_node_about_outputs`,
`a_late_restore_backfills_older_outputs_once`,
`a_reorganization_deeper_than_the_kept_window_rescans`), `node/tests/px_commitments.rs`
(test list), `rpc` unit tests, `tx/src/state.rs` tests, `px/src/tree.rs` test.

**Docs and reports:** `C:/bszkeval/p2/brief.md`; roster (entries 20–50, mine is 39);
`decisions.md` (all); `docs/reviews/full-review-2026-09-27.md` (§1–§4 in full, wallet and
never-change sections of §5–§9); `docs/reviews/autonomous-session-2026-09-27.md` (full);
source reports R11 (§0, §1, W8, W9, §3.4, §5, §8, §9), R12 (§11, R12-3, R12-7, R12-8,
R12-9), I1 (I1-F2), I3 (§3.9), SX2 (R11 table, C5, C8); `docs/px.md` §3.1, §11.4, §11.5;
`docs/blocks.md` §9–§10; `docs/reviews/wallet-review.md` (rounds 2–3);
`docs/reviews/query-policy.md`. Neighbour dossiers checked for overlap: 21, 34, 35, 36, 37.

---

## 2. Current state

### 2.1 What exists

| Item | State | Evidence |
|---|---|---|
| v1 scan: download every block via `/blocks` (≤ 100 blocks, ≤ 64 MiB hex per response), decode strictly, recompute block id and `tx_root`, check `prev_id` linkage, scan with view keys and a subaddress table | Implemented | [src] `wallet.rs:1035-1078`; [test] e2e `funds_move_between_wallets_over_rpc` |
| Reorg detection: walk back from the synced height comparing stored block ids with the node's; 720 ids kept; deeper forks rescan from the restore height | Implemented | [src] `wallet.rs:1008-1033`; [test] `wallet_follows_a_reorganization`, `a_reorganization_deeper_than_the_kept_window_rescans` |
| Gap-limit scanning (v1 and PX) | Implemented | [test] `a_restored_wallet_follows_payments_beyond_its_first_window` |
| Local output index (73 B/output), rings built locally, backfill below the restore height in fixed 1,024-index pages | Implemented (`2b0f75a`) | [test] `rings_are_built_without_asking_the_node_about_outputs`, `a_late_restore_backfills_older_outputs_once`, `the_backfill_fetches_the_whole_missing_range_in_fixed_pages` |
| PX scan: per PX output and per address index `0..=issued+20`, `delivery::open` (tag check after one scalar multiplication; ML-KEM decapsulation only on a tag match; Janus-style `cm` recomputation) | Implemented | [src] `px.rs:452-494`, `delivery.rs:279-332` |
| PX delivery keys and owner tags cached per session (`AddressKeys`) | Implemented (the R12-9 short-term fix) | [test] `cached_address_keys_match_fresh_derivation` |
| PX commitment list: downloaded in full from `/px/commitments` (default page 1,024), stored as `(height, hex)` in the wallet JSON; tree rebuilt from scratch (`tree_at`) for the root check and for every PX spend | Implemented, does not scale (R12-8 open) | [src] `px.rs:541-611`, `wallet.rs:2005-2008, 2048, 2421` |
| Node `/px/commitments`: paginated slice, no clone of the record log | Implemented (`d374ef3`) | [test] `node/tests/px_commitments.rs` (7 tests incl. `pages_follow_undo`, `wallet_style_sync_completes`) |
| Canonical PX anchor (multiple of 16) | Implemented | [test] `the_anchor_is_the_last_multiple_of_the_interval` |
| Genesis binding of wallet file and node check | Implemented | [test] `the_wallet_is_bound_to_its_genesis` |
| Compact / pruned scan feed | **Not implemented** (R11-W9, R12-7, I1-F2) | [src] no endpoint in `node/src/lib.rs:155-168` |
| Incremental PX tree with witnesses | **Not implemented** (R11-W8, R12-8) | [src] |
| Wallet PoW check | **Not implemented** (W-F6) | [src] comment `wallet.rs:1060-1061` |

### 2.2 What is correct and well designed

- **The privacy model is the strongest available:** every wallet downloads identical
  data (whole blocks, whole commitment and contract lists) and never asks about a
  record, position, nullifier or ring member [src; the I1 and I3 analyses agree]. The
  node learns the scanned ranges, the timing and the IP only.
- **The v1 part of scanning is Monero-lineage and cheap:** one scalar multiplication per
  output, independent of the number of subaddresses, and a 1-byte view tag [src
  `stealth.rs` via R11 §3.4]. Monero adopted the same 1-byte tag in v15 for a measured
  30–40 % sync saving (MRL #73, PR #8061).
- **The transaction hash already separates what a scanner needs from what it does
  not:** `tx_hash = H32(TX_HASH, prefix_hash ‖ base_hash ‖ prunable_hash)`
  (`types.rs:432-450`). Everything scanning needs is in the **prefix**: key images and
  ring offsets, outputs (key, ephemeral, view tag, commitment, encrypted amount and
  anchor), PX anchor, nullifiers, commitments, **both full ciphertexts**, function
  outputs, and the deploy payload (`types.rs:217-237`, `px.rs:228-263`, `px.rs:487-496`)
  [src]. `output_context()` and `key_images()` read prefix fields only
  (`px.rs:444-448`, `types.rs:480-488`) [src]. The prunable part holds only BP+, CLSAGs
  and the PX proof. **So a compact block made of `(prefix bytes, base_hash,
  prunable_hash)` per transaction lets the client recompute every transaction id and
  the header's `tx_root`: exactly the integrity it has with full blocks.** This is
  better than Zcash's ZIP-307, whose compact blocks cannot verify the transaction
  tree (ZIP-307 §"Client verification"). Monero is only now adding the same thing
  (`verifiable` pruned blobs with a prunable hash, PR #11397) [mathematically
  established from the hash definition + collision resistance of H32].
- **The PX tree definition is simple to mirror in a wallet:** append-only, depth 32,
  commitments of PX transactions only, 2 per PX transaction, in block order
  (`state.rs:172-188`, `px/src/state.rs:135-139`) [src]. A wallet that sees every
  block can build the tree itself.

### 2.3 What the tests actually prove

- They prove functional sync, reorg rewind, deep-reorg rescan, gap-limit growth,
  the absence of `/outputs` queries for rings, and that pages reassemble the node's
  list [test names above].
- They do **not** prove anything against a *lying* node: there is no test where the
  node serves inconsistent commitments, heights, `first_output`, `total` or `root`
  [src: no such test in `e2e.rs` or `px.rs`]. `the_wallet_is_bound_to_its_genesis`
  covers identity only.
- No test measures sync bandwidth or time (roster Bench requirement) [src].

---

## 3. Problems in scope

### 3.1 P1: the PX commitment list is not bound to the scanned blocks (new finding F39-1)

**What and why.** The wallet takes its PX tree from `/px/commitments`, a list of
`(height, commitment)` pairs whose **heights and contents are node-supplied and never
checked against the blocks the wallet verified** (`px.rs:541-596`). The only check
compares the rebuilt root with `resp.root`, and only if `complete && resp.height ==
synced` (`px.rs:560-567`). The node controls `total`, `height` and `root`, so it can
always skip the check (R11 §3.4 already noted this, rating it "only DoS"). The same
data is already present, verified, in the blocks the wallet downloads, but
`PxStore::apply_block` uses the block's commitments only for trial decryption
(`px.rs:452-494`) and discards them.

**Security consequence: the anchor can be chosen by the node, and it becomes a
fingerprint.** `tree_at(anchor)` filters by the node-supplied heights (`px.rs:603-611`).
A malicious sync node can:
1. relabel the heights of the last commitments so that `tree_at(A)` (A = the canonical
   anchor, a multiple of 16) contains exactly the commitments up to some real height
   X ≠ A, with X inside the 100-block root window;
2. report a `height` ≠ `synced`, so no root check runs.

The wallet then builds a **valid** PX transaction (its records at positions ≤ X have
correct paths) whose anchor is the real root at height X. Honest wallets always anchor
at multiples of 16 (`docs/px.md` §11.4), so this transaction stands out on chain, and
the node can give each client wallet a different X to recognize which of its clients
made which PX transaction, even if the wallet broadcasts through another node or Tor.
This defeats the purpose of the canonical anchor. [source-read; not tested; confidence
medium-high. The attack needs a malicious sync node, which the docs already advise
against (`docs/blocks.md` §9), but remote-node use is a stated use case (R3-9, I3 §3.9).]

A reorg between two page requests can also produce a mixed list that is not caught
unless the heights match (liveness only).

**Class.** Privacy-critical (remote-node users), liveness. Not consensus.

**Prior art.** ZIP-307 light clients append every output commitment to a local tree as
compact blocks arrive and keep incremental witnesses (ZIP-307 "witness and tree state");
lightwalletd serves `GetTreeState` only as a **starting frontier** at the birthday.
Zcash's `shardtree`/`bridgetree` (incrementalmerkletree repo) implement this with
checkpoints for rewinds. None of them take commitment positions from the server for the
scanned range.

**Fix (W1).** Derive the tree from the scanned (tx_root-verified, prev-linked) blocks:
- append each PX transaction's two commitments to a wallet frontier in block order,
  recording block boundaries;
- use `/px/commitments` only for the part **below the restore height** (a one-time
  replay), or, later, a frontier (`/px/tree_state`, W7);
- keep a local **root window** that mirrors `px::state` (the roots after each of the
  last 100 blocks, initial root included) and **check every scanned PX transaction's
  anchor against it**. Consensus enforces exactly this rule
  (`px/src/state.rs:120-124`), so an honest node never fails it. A failure means the
  node's tree data (the backfilled part) or blocks are inconsistent: `BadNodeData`.
  This check costs no bandwidth and also validates the backfilled pre-restore part as
  soon as any PX transaction anchors after it. Anchors that could refer to roots older
  than the restore height (first 100 blocks after it) are skipped only if the wallet
  has no backfill;
- assert when building: `anchor == locally computed root at anchor_height(synced)`.

**Trade-offs.** The wallet must mirror the root-window rule exactly; a mismatch would
make the wallet refuse an honest node (a DoS on ourselves). Mitigation: a differential
test against `px::state::State` on random chains. Cost: about 64 Poseidon2 permutations
per block (one root plus appends), ≈ 30–130 µs per block at the 0.5–2 µs per
permutation implied by R12's figures [estimate], ≈ 10–35 s per chain-year of restore.

**Tests.** Adversarial node: relabelled heights → refused (or ignored, since heights no
longer come from the node); omitted or altered commitment in the backfill → anchor
check fails at the next PX transaction; reorg between pages → consistent result.
Differential: wallet root window vs `px::state::State` over random block sequences
with PX transactions anchored at random window positions. Regression: every built
PX transaction's anchor equals the root at `anchor_height(synced)`.

**Invariants.** Canonical anchors; no per-record or per-position query; the tree
definition (`px/src/tree.rs`, depth 32, node hash, zero leaves) is consensus.

### 3.2 P2: full-block hex download (R12-7, R11-W9, I1-F2; confirmed)

**What.** `/blocks` returns full blocks, hex in JSON (2× the bytes), proofs and
signatures included (`node/src/lib.rs:302-334`, `rpc/src/lib.rs:116-127`). A 2.18 MB PX
proof is useless to a wallet. R12 estimates ≈ 614 GB per moderate chain-year of wallet
download [estimate, R12 §11]; I confirm the mechanism [src].

**Additional cost found (F39-2):** every `sync`, including the implicit sync before each
spend, downloads the **full block at the synced height** only to compare its id
(`wallet.rs:1019-1027`); a reorg walk back downloads up to 720 full blocks, one request
each, to compare ids. With PX-heavy blocks that is up to ≈ 9 MB per sync and ≈ 6.5 GB
for a deep walk [estimate].

**Consequences.** Scale, liveness of remote-node use, mobile infeasibility. Not
privacy (everyone downloads everything), not consensus.

**Prior art.**
- **Zcash ZIP-307 / lightwalletd `CompactBlock`:** per transaction, nullifiers,
  commitments, ephemeral keys and the first 52 bytes of each note ciphertext; the
  client cannot verify the transaction tree; the server is "honest but curious";
  omission of transactions is undetectable (ZIP-307 security considerations).
- **Monero `get_blocks.bin` with `prune=true`**, and the recent `verifiable` flag
  (PR #11397) that returns pruned v2 transactions **with their prunable hash** so the
  client can recompute the transaction hash.
- **Lesson from lightwalletd `GetTransaction`:** any per-transaction follow-up fetch tells
  the server which transactions the wallet cares about; ZIP-307 says clients SHOULD
  download all transactions of a block if they fetch one, and wallets have removed such
  lookups (e.g. vizor-wallet PR #748).

**Design (W2): the BlackSilk compact scan feed.**

```
GET /compact_blocks?from=h&count=n        (n ≤ 100; response byte-capped)
Content-Type: application/octet-stream    (project codec, strict, no JSON/hex)

response  = varint(count) ‖ block*
block     = header (100 bytes) ‖ varint(first_output) ‖ varint(tx_count) ‖ ctx*
ctx       = varint(len) ‖ prefix_bytes (exactly Transaction::prefix_bytes)
            ‖ base_hash (32) ‖ prunable_hash (32)       -- omitted for a coinbase:
                                                          the client uses the constant
                                                          hashes of the empty strings
```

Client rules:
1. Decode each prefix with a strict **prefix-only decoder** that shares its field
   readers with `Transaction::decode` (W2a); require `encode(decoded) == bytes`.
2. `tx_hash = H32(TX_HASH, H32(TX_PREFIX, bytes) ‖ base_hash ‖ prunable_hash)`; require
   `tx_root(ids) == header.tx_root`, `header.id == expected`, `prev_id` linkage — the
   same checks as today (`wallet.rs:1054-1068`).
3. Require `first_output(h+1) == first_output(h) + outputs(h)` (fixes F39-6), and
   check the first one against the backfill or `/distribution`.
4. Scan with the **same** code as full blocks: full blocks are converted to the compact
   view first, so there is one scan path (differential-tested).
5. The reorg check uses the header of the compact block at the synced height (100
   bytes, not 9 MB).

Properties:
- **Privacy: identical to today.** Unfiltered, the same bytes for every client asking
  for a range; no key, tag, index or address parameter; ciphertexts **not** truncated
  (a tag-first then fetch-the-rest design leaks a candidate set, R11 §5.2 option 2, and
  would recreate the `GetTransaction` leak).
- **Integrity: identical to full blocks** (tx_root binding, §2.2). As today, the node
  is trusted for PoW and for omission of whole blocks it forges (W5 reduces this).
- **Size [estimate from the encodings]:** PX transaction ≈ 2.7–3.1 KB (2 ciphertexts of
  1,241 B dominate) vs ≈ 2.2 MB: ≈ 700× smaller. A 2-in/2-out transfer ≈ 0.45 KB vs
  ≈ 2.2 KB: ≈ 5×. Binary instead of hex: another 2×. Overall ≈ 70× (S2) to ≈ 700×
  (PX-heavy), in line with R12 §11 and I1-F2. Deploy prefixes carry their payload
  (≤ 1 MiB per block by the v3 deploy budget) and stay large; that is acceptable.
- **Node cost.** Must not clone bodies or hash 2 MB proofs under the chain lock (the
  current `/blocks` already clones and hex-encodes up to 64 MiB under the lock:
  F36-2 in dossier 36). The PX `prunable_hash` is computed once (at connect or first
  request) and memoized per transaction (≈ 64 B per PX transaction, ≈ 50 MB per
  saturated chain-year [estimate]); prefix bytes are a few KB per transaction. After
  34's snapshots land, the handler builds from an immutable snapshot off-lock.

**Trade-offs and what could go wrong.**
- A prefix-only decoder that diverges from the consensus decoder would mis-scan. The
  hash is computed over the raw received bytes, so a divergence can cause a missed or
  wrong scan result but can never make the wallet accept bytes that are not in the
  block [math: collision resistance]. Mitigation: split `decode_body` so the prefix
  readers are literally shared (W2a), plus a differential property test.
- Any future consensus change that moves scan-relevant data into `base` or `prunable`
  breaks verifiable compaction. This becomes a never-change invariant (§3.7).

**Tests.** Differential: for random blocks with every transaction kind (coinbase,
transfer, PX with and without v1 inputs and payouts, PX with functions, deploy),
`scan(compact(b)) == scan(b)`, `tx_hash` equal, `tx_root` equal. Adversarial: a
corrupted prefix byte, a wrong `prunable_hash`, a wrong `first_output`, a truncated
response, an over-cap response → refused. Privacy regression: the endpoint takes no
parameter except `from`/`count`; two clients get byte-identical responses; the wallet's
recorded requests contain only ranges (existing `Flaky` harness). Fuzz: the compact
decoder (41).

### 3.3 P3: PX tree rebuilt from scratch; commitments stored as JSON hex (R12-8, R11-W8; confirmed)

**What.** `tree_at` rebuilds every node from every commitment on each sync root check
and each PX spend; `px_deposit` rebuilds the whole tree only to read its root
(`wallet.rs:2005-2008`). Commitments are stored as `(u64, String)` JSON (~80–120 B
each) inside the single encrypted wallet file, re-encrypted with Argon2id (64 MiB,
t = 3) on every save (`file.rs:26-41`, `lib.rs:27-37`) [src]. R12's 4–100 s per call at
scale is arithmetic I agree with [estimate].

**Prior art.** Zcash `IncrementalWitness` (incrementalmerkletree `witness`
module: the frontier's "ommers" at insertion plus the right-hand subtree roots as they
fill), `bridgetree` (marked leaves, checkpoints, rewind), `shardtree` (shards, subtree
roots for spend-before-sync, checkpoints). ZIP-307 suggests about 100 cached states for
reorgs.

**Design (W1, same work item as §3.1).** A new `px/src/witness.rs`, generic over
`Permutation`, pure safe Rust, **not** touching the consensus `Frontier`:
- `WalletTree`: its own frontier whose `append` reports every completed subtree root
  `(level, index, digest)` (the `cur` values of the frontier loop); per-16-block
  frontier checkpoints (anchors are multiples of 16, so the checkpoint at the anchor is
  exact), the commitments of the last 720 blocks, and the root window (§3.1).
- `Witness` for each owned leaf q: left ommers taken from the frontier when q is
  appended; right-sibling roots recorded, with the block height, when the frontier
  completes them; the one partially filled right sibling at anchor size S is computed
  at spend time from the checkpoint frontier (O(depth)); higher empty ones are
  `empty[h]`. `path_at(anchor)` uses only fills with height ≤ anchor.
- Rewind to height H: restore the checkpoint ≤ H, re-append the kept commitments up to
  H, truncate fill logs, drop witnesses created above H.
- Spent witnesses are dropped once the spend is deeper than the wallet's 720-block window.

Cost per append: the frontier's ≤ 32 permutations plus O(#witnesses) comparisons, no
extra hashing. Memory: O(depth × owned records) + 720 blocks of commitments
(≤ 6 per block → ≤ 138 KB) + 45 checkpoints (≈ 1 KB each). No per-chain-growth storage.

**Why in-tree and not `bridgetree` now.** `bridgetree` 0.7.1 (Sept 2026, MIT/Apache,
Zcash-maintained; its `lib.rs` has no `unsafe` blocks, source-read of one file only)
is the right reference design, but (a) the `Hashable` trait is stateless
(`combine(level, a, b)`), while BlackSilk's Poseidon2 uses an explicit `&mut perm`;
(b) a new dependency needs 44's review. About 300 lines, differential-tested against
the existing reference `px::tree::Tree`, is less supply-chain risk. Revisit if the
wallet later needs out-of-order insertion (spend-before-sync, i.e. shardtree).

**Tests.** Property tests (proptest is approved for px): for random append sequences,
random owned positions and random anchor sizes, `Witness::path_at == Tree::path`
truncated at that size, and `root_from_path` equals the tree root; rewind at random
depths equals rebuilding from scratch; migration: an old wallet file with a
commitment list loads and yields identical roots and paths.

### 3.4 P4: PX scanning cost (R12-9; partly fixed)

**What remains.** `AddressKeys` removed the per-output ML-KEM key generation. Per PX
output the wallet still does, for each of `issued + 21` addresses: a Ristretto
decompression of the same `R` (`delivery.rs:289-290`, repeated per address), one
variable-base scalar multiplication, one hash; ML-KEM decapsulation only on the ≈
k/256 tag matches [src]. This O(addresses) cost is a deliberate consequence of
**per-address independent keys**, which keep a wallet's addresses unlinkable even to a
DL-capable adversary (R11 §5.1). Do not remove it silently.

**Options, in order of risk.**
1. Hoist the decompression of `R` out of the address loop (`open_with_point`): free.
2. For one `R` and k secret scalars `v_i`, build a precomputed table for `R` once and
   multiply by each `v_i` with a constant-time fixed-base path (curve25519-dalek
   supports tables for arbitrary points): expected ≈ 2–3× for k ≈ 21 [estimate;
   benchmark first; must stay constant-time in `v_i`].
3. Parallel trial decryption of a block's outputs with `std::thread::scope` (pure std,
   no new dependency), v1 and PX.
4. **Structural (P3, owner 37):** a shared incoming key with diversified bases makes the
   EC check O(1) per output (R12-9 structural); it changes the address format and the
   post-quantum address-unlinkability trade-off. It is an explicit decision, not an
   optimization.

**Consensus:** none. **Privacy:** none for 1–3.

### 3.5 P5: `/px/commitments` pagination (in scope)

The slice-based pagination is correct and tested (`d374ef3`, 7 tests) [test]. Residuals:
the pages are not snapshot-consistent across requests (a reorg between pages yields a
mixed list, §3.1); the wallet uses the default 1,024 page (≈ 1,500 requests per
saturated chain-year [estimate]; the 4,096 maximum would divide that by 4). After W1 the
wallet uses the endpoint only for the pre-restore backfill, so the residuals lose most
of their weight. Keep the endpoint (bulk-only, whole list) for backfill and tools.

### 3.6 P6: trust in the node (accepted limitation, with a privacy angle; F39-10)

With full or compact blocks, the wallet trusts its node not to forge blocks: no PoW is
checked (W-F6). ZIP-307 lists the same limitation (omission of transactions). There is
one privacy consequence I have not seen recorded: a malicious sync node can **hide a
spend** from a **restored** wallet (one without its stored rings or pending
transactions) by serving a forged block. The wallet then sees the output as unspent and
builds a **new ring for an already-used key image**; the node receives that transaction
(or sees it relayed), intersects the two rings, and learns the real input of the old
spend. The W-5 ring reuse protects only a wallet that still has its history. A forged
block needs a forged header chain, so a header PoW check closes this.

**Option (W5):** verify the header chain the wallet already receives:
- LWMA recomputation over all headers (cheap arithmetic);
- RandomX **light-mode** verification of the tip and of k random headers chosen after
  the chain is received (an attacker that forged a fraction f of the chain is detected
  with probability 1 − (1 − f)^k);
- verification of the headers of blocks whose spends the wallet acts on.

Cost: ≈ 0.45–0.75 s per light hash plus one 256 MiB cache build per distinct seed
epoch [R9/R12 anchors]. Opt-in first, measured, then decided. A cheaper immediate
mitigation: before building a new ring for an output of a restored wallet, warn when the
output's receiving block is older than the restore-time history.

### 3.7 Invariants that must never change

1. Download-everything (full or compact, **unfiltered**) scanning; the same bytes for
   every client that asks for a range; never per-record, per-position, per-nullifier,
   per-output or per-transaction queries (the never-change list #27–#28;
   lightwalletd `GetTransaction` lesson).
2. Every field a scanner needs stays in the transaction **prefix**; `tx_hash =
   H(prefix_hash ‖ base_hash ‖ prunable_hash)`. This makes compact blocks verifiable.
3. Ciphertexts are delivered whole in the feed (no tag-first fetching).
4. Canonical PX anchors; the anchor must equal the locally computed root.
5. Per-address independent PX keys, unless explicitly re-decided (R11 §5.1).
6. Janus-style `cm` check on received records; rejected outputs are never shown or spent.
7. The PX tree definition (depth 32, node hash, zero leaves, 2 commitments per PX
   transaction in block order) and `ROOT_WINDOW = 100` (consensus).

---

## 4. New findings

| ID | Severity | Status | Where | Scenario | Confidence |
|---|---|---|---|---|---|
| **F39-1** | **Medium** (privacy for remote-node users; liveness) | Not implemented | `wallet/src/px.rs:541-596` (heights, total, height, root from the node; root check only at 560-567), `px.rs:603-611` (`tree_at` filters by node heights), `wallet.rs:2005-2008, 2046-2048` | A malicious sync node relabels commitment heights so that `tree_at(A)` equals the real root at a non-canonical height X in the root window, and reports another height to skip the check. The wallet's PX transaction is valid but carries a unique anchor, which tags it on chain as coming from that node's client (per-client X). A reorg between pages gives a mixed list (failed spends). | Medium-high (source-read; not tested) |
| **F39-2** | Low (bandwidth, liveness) | Not implemented | `wallet/src/wallet.rs:1008-1033` (1019-1027) | Every sync downloads the full block at the synced height (up to ≈ 9 MB) only to compare ids; a reorg walk makes one full-block request per height, up to 720. | High |
| F39-3 (= R12-7/R11-W9/I1-F2) | Medium (scale) | Not implemented | `node/src/lib.rs:302-334`, `wallet.rs:1035-1078` | ≈ 614 GB per moderate chain-year of wallet download [R12 estimate]. Confirmed; design in §3.2. | High |
| F39-4 (= R12-8/R11-W8) | Medium (scale) | Partially implemented | `wallet/src/px.rs:259-273, 598-611`; `wallet.rs:2005-2008` | Tree rebuild per sync and per spend; the deposit rebuilds the whole tree for the root only; commitments as JSON hex in a file re-encrypted with Argon2id on every save. Confirmed. | High |
| F39-5 (R12-9 residual) | Low (performance) | Partially implemented | `px/src/delivery.rs:289-290`; `wallet/src/px.rs:456-458` | `R` decompressed once per address instead of once per output; O(addresses) per output remains (by design). | High |
| **F39-6** | Low (integrity; DoS only) | Not implemented | `wallet/src/index.rs:100-103`; `wallet/src/wallet.rs:1069, 1088-1097` | `first_output` is node-supplied per block; a discontinuity silently **restarts** the local index instead of failing, and owned outputs get wrong global indices; the spend is later rejected. Refines W-F13. Continuity is checkable for free. | High |
| F39-7 | Low (liveness, node) | Not implemented | `node/src/lib.rs:312-331` | `/blocks` clones bodies and hex-encodes up to 64 MiB inside the chain-lock closure. **Already F36-2 in dossier 36**; listed here because the compact endpoint must not repeat it. | High |
| F39-8 | Low (docs) | Not implemented | `docs/blocks.md` §9; `docs/px.md` §11.4 | §9 omits the `/px/*` endpoints and says wallets fetch ring members (false since `2b0f75a`; also F36-10). px.md §11.4 describes the node-supplied commitment list as the source of the tree. | High |
| **F39-10** | Low–Medium (privacy; needs a malicious node and a restored wallet) | Accepted limitation today, not documented | `wallet.rs:1060-1061` (no PoW check); `wallet.rs:1154-1165` (spends learned only from blocks) | A node that forges a block to hide an old spend makes a restored wallet re-spend the output with a new ring; the two rings intersect at the real input. | Medium (reasoned; the ring-intersection effect is well known from Monero) |
| F39-11 | Info | — | `node/tests/px_commitments.rs`, `wallet/tests/e2e.rs` | No adversarial-node tests and no sync bandwidth or time measurement exist. | High |

---

## 5. Implementation plan for phase 2

All items are **wallet/RPC policy: no consensus change, no identity impact.**

| # | Work item | Files (ownership) | Visibility | Tests | Bench | Docs | Diff. | Pri. |
|---|---|---|---|---|---|---|---|---|
| **W0** | **Baseline measurement harness**: `#[ignore]` timing tests that sync a labnet-style regtest chain (v1-heavy and PX-heavy synthetic chains) and record bytes downloaded, requests, wall time and CPU for sync, restore and one PX spend | new `wallet/tests/sync_bench.rs` (39) | nothing | — | the baseline (before W1/W2) and after each item; figures go to 45's report | `docs/evidence/` note (45) | S | P1 |
| **W1** | **Block-derived PX tree with witnesses and a root-window anchor check** (fixes F39-1, F39-4): `WalletTree`, `Witness`, `RootWindow` in px; the wallet appends commitments from scanned blocks; `/px/commitments` only for the pre-restore backfill (replayed once); anchor check on every scanned PX transaction; anchor == local root assertion; checkpoints for rewind; the wallet file stores the tree state instead of the commitment list (old files migrate by replay) | new `px/src/witness.rs` (39), `px/src/lib.rs` (one `pub mod` line; 21 informed); `wallet/src/px.rs` (39: `PxStore` tree state, `apply_block`, `rewind`, `sync_commitments` → `backfill_commitments`); `wallet/src/wallet.rs` (39: `sync`, `px_deposit`, `px_inputs`, vault claim path lines ~2005, 2046-2066, 2421; **serialize with 37/38**); `Persisted` field (coordinate with 37's K1) | nothing externally (anchors stay canonical) | property: witness vs `Tree`; differential: `RootWindow` vs `px::state::State`; adversarial node (relabelled heights, altered backfill, reorg between pages); regression: anchor equals local root; migration of an old file; e2e `px_records_follow_a_reorganization` still passes | W0: sync and spend time at 10^5 / 10^6 commitments | `docs/px.md` §11.4 (39 content, 47 edits) | M | **P1** (before any public/remote-node use; not needed for the 7-device own-node trial) |
| **W2a** | **Prefix-only decoder** sharing the field readers with `Transaction::decode` (split `decode_body` into prefix + rest, no behaviour change) and a `TxView` for scanning | `tx/src/types.rs`, `tx/src/px.rs` decode functions (**co-owned with 11**, one reviewed commit); new `tx/src/compact.rs` (39); `tx/src/scan.rs` generalized to the view (**coordinate with 17**) | nothing (decode results identical) | differential: `decode` unchanged on the tx fuzz corpus and golden vectors; `decode_prefix(prefix_bytes(t))` equals `t`'s fields for every kind; `scan(view(t)) == scan(t)`; fuzz target `compact_prefix` (41) | — | `docs/transactions.md` (prefix is scan data; invariant 2) | M | P2 |
| **W2b** | **`/compact_blocks` endpoint and client** (binary, bulk-only, byte-capped, behind 36's guard and bulk class); PX `prunable_hash` memo; built off-lock once 34's snapshots exist | `node/src/lib.rs` route + handler (**36 owns the router file; 39 adds one route + handler module** `node/src/compact.rs` (39)); `rpc/src/lib.rs` (types, cap, client method; with 36); `chain/src/manager.rs` accessor for borrowed bodies (**34/35**) | new RPC (policy) | node tests: pages reassemble, caps, reorg between pages detected by the client; privacy regression (only `from`/`count`; identical bytes) | response time and lock-hold time per 100 blocks (with 34) | `docs/blocks.md` §9 (36 writes the section; 39 supplies the endpoint text) | M | P2 |
| **W2c** | **Wallet sync over compact blocks**: `NodeApi::compact_blocks`; one scan path (full blocks converted to the view); header-only reorg check (fixes F39-2); `first_output` continuity (fixes F39-6); fallback to `/blocks` for older nodes | `wallet/src/node.rs`, `wallet/src/wallet.rs` `sync`/`apply_block`, `wallet/src/index.rs` (`push_block` returns an error on discontinuity) (39) | nothing | e2e: a compact-synced and a full-synced wallet end identical (balances, records, index, tree); adversarial: wrong `prunable_hash`, wrong `first_output`, altered prefix → `BadNodeData` | W0 before/after: bytes and time | wallet README | M | P2 |
| **W3** | **Wallet bulk state out of the JSON**: the output index and the tree state in an encrypted, append-only side file (binary), so a save does not rewrite 150 MB per million outputs | `wallet/src/index.rs` (39), `wallet/src/file.rs` / `lib.rs` (**37** owns the file format) | wallet file format | crash-consistency (side file vs main file), migration from the JSON index, tamper → refused | save time at 10^6 outputs | `docs/blocks.md` §10 | M | P2 |
| **W4** | **Scan performance**: hoist `R` decompression (`delivery::open_with_point`); benchmark the table-based `v_i·R`; parallel trial decryption per block with `std::thread::scope` | `px/src/delivery.rs` (new function only; 39, **R2-C9 delivery-v2 owner informed**), `wallet/src/px.rs`, `wallet/src/wallet.rs` scan loop (39) | nothing | equality of results single- vs multi-threaded; constant-time argument recorded for the table path | per-output PX scan cost at 21 and 1,021 addresses (the R12 plan item 5) | — | S–M | P2 |
| **W5** | **Optional header verification**: LWMA recomputation, RandomX light-mode check of the tip and k random headers, and of blocks the wallet acts on; a restored-wallet warning before a new ring is built for an old output (F39-10) | `wallet/src/verify.rs` (new, 39); uses `consensus` APIs (05/07 own RandomX light-mode API) | nothing | forged-chain test (fake difficulty, bad PoW on sampled headers → refused); LWMA mismatch → refused | cost per sampled header and per seed cache | `docs/blocks.md` §9 trust statement | M | P2 (decision: opt-in or default) |
| **W6** | **Range bucketing**: start each sync at `synced+1` rounded down to a multiple of 16 (re-downloading ≤ 15 compact blocks) so the request does not reveal the exact last-sync height; compute the decoy distribution from the local index instead of calling `/distribution` at spend time (removes 36's P8 "about to send" signal; coordinate with 38) | `wallet/src/wallet.rs` `sync`, `plans_for` (39 with 38) | nothing | request log shows aligned starts; decoy selection identical with local vs node distribution | — | `docs/px.md` §12 privacy guidance | S | P2 |
| **W7** | Research/future: `/px/tree_state?height=` frontier for restores (needs the node's frontier at past heights from PX undo: 21/35); OMR evaluation against the PX output format; shared-ivk scanning (37); header or coinbase commitment to the PX root (46's state commitment) | — | — | — | — | — | — | P3 |

**Order.** W0 → W1 (privacy fix, standalone, no node change) → W2a → W2b/W2c → W3 →
W4/W6 → W5. W1 does not depend on W2: with full blocks the wallet already has every
commitment.

---

## 6. Dependencies and conflicts

- **11 (tx-validation):** W2a splits `decode_body` in `tx/src/types.rs` and
  `tx/src/px.rs`; 11 owns those functions. One commit, reviewed by 11, with the
  golden and fuzz corpora re-run.
- **17 (stealth-janus):** `tx/src/scan.rs` generalized to a view; the D8 wallet
  one-output-per-key-image rule lands in the same scanner. Serialize.
- **21 (px-nullifiers-commitments):** `RootWindow` must mirror `px::state` exactly; 21's
  window-undo and anchor-reorg tests are the reference. No edit to `px/src/tree.rs` or
  `px/src/state.rs`.
- **34 (chain actor):** off-lock compact building from snapshots; until then, the memo
  plus a borrowed-body accessor.
- **35 (storage):** a disk-backed body store (its S6) can serve the compact feed; the
  `/px/tree_state` idea needs frontier retention.
- **36 (rpc-security):** router ownership, guard and bulk class for the new route
  (36's stated condition), response caps, F36-2/F36-10 overlap with F39-7/F39-8.
- **37 (wallet-keys):** wallet file format (`Persisted`, side file), seed birthday
  (restore start), watch-only scanner mode (K9: 39 owns the scanner), shared-ivk
  decision. `wallet/src/wallet.rs` and `wallet/src/px.rs` are shared by 37/38/39: the
  coordinator must serialize edits.
- **38 (wallet-privacy):** local decoy distribution (W6), rebroadcast semantics,
  F39-10 (ring intersection after a hidden spend), SOCKS for sync.
- **05/07:** RandomX light-mode verification API for W5.
- **41:** fuzz target for the compact decoder; proptest adoption.
- **44:** only if `bridgetree` is ever proposed (not now).
- **45:** W0 figures in the baseline.
- **47:** docs edits (blocks.md §9, px.md §11.4, transactions.md invariant).
- **49:** compact private sync / OMR research alignment.

---

## 7. Open questions for the coordinator

1. **Priority of W1.** I rate F39-1 Medium (privacy) and W1 P1. For the 7-device trial
   (own nodes) it is not a blocker. Agree?
2. **Compact encoding.** Project codec (`Writer`, strict) as `application/octet-stream`,
   rather than postcard or JSON/hex. Agree? Keep `/blocks` (hex) for tools and older
   wallets?
3. **Wallet PoW check (W5):** opt-in at first, or default for restores only?
4. **A header commitment to the PX root:** I recommend **not** adding it to v3 (a
   header-format and RandomX-input change for a benefit only light wallets without PoW
   checks would see). The anchor-consistency check gives most of the benefit for free.
   Record as P3 with 46.
5. **proptest in `wallet` tests** (it is approved for px, chain and crypto): may W1's
   wallet-side tests use it too?
6. **Shared files:** confirm 39 as owner of `px/src/witness.rs`, `tx/src/compact.rs`,
   `node/src/compact.rs`, `wallet/tests/sync_bench.rs`, `wallet/src/verify.rs`, and
   co-owner (serialized) of `wallet/src/{wallet,px,index}.rs`.

---

## 8. Sources

Zcash:
- ZIP 307, *Light Client Protocol for Payment Detection*: https://zips.z.cash/zip-0307
- lightwallet-protocol `compact_formats.proto`: https://github.com/zcash/lightwallet-protocol/blob/main/walletrpc/compact_formats.proto
- lightwallet-protocol `service.proto` (GetBlockRange, GetTreeState, GetSubtreeRoots): https://github.com/zcash/lightwallet-protocol/blob/main/walletrpc/service.proto
- ZIP 314 discussion (light-client privacy upgrades): https://forum.zcashcommunity.com/t/zip-314-privacy-upgrades-to-the-zcash-light-client-protocol/38868
- Removal of per-txid `GetTransaction` lookups (privacy): https://github.com/chainapsis/vizor-wallet/pull/748
- `incrementalmerkletree` 0.8.2: https://docs.rs/incrementalmerkletree/latest/incrementalmerkletree/
- `bridgetree` 0.7.1: https://docs.rs/bridgetree/latest/bridgetree/ ; source https://github.com/zcash/incrementalmerkletree/blob/main/bridgetree/src/lib.rs
- `shardtree` 0.7.1: https://docs.rs/shardtree/latest/shardtree/

Monero:
- View tags proposal, MRL issue #73: https://github.com/monero-project/research-lab/issues/73
- View tags implementation, PR #8061: https://github.com/monero-project/monero/pull/8061
- Daemon RPC (`get_blocks.bin`, `prune`): https://www.getmonero.org/resources/developer-guides/daemon-rpc.html
- `verifiable` pruned transactions with prunable hash, PR #11397 (review summary): https://github.com/xmrack/monero-review/issues/795
- Carrot specification (3-byte view tag, view-received tier): https://github.com/jeffro256/carrot/blob/master/carrot.md
- monero-lws (view key given to the server): https://github.com/vtnerd/monero-lws

Detection and retrieval research:
- Beck, Len, Miers, Green, *Fuzzy Message Detection*, ACM CCS 2021: https://eprint.iacr.org/2021/089
- Seres, Pejó, Burcsi, *The Effect of False Positives: Why Fuzzy Message Detection Leads to Fuzzy Privacy Guarantees?*, FC 2022: https://eprint.iacr.org/2021/1180
- Penumbra S-FMD design: https://protocol.penumbra.zone/main/crypto/fmd.html
- Liu, Tromer, *Oblivious Message Retrieval*, CRYPTO 2022: https://eprint.iacr.org/2021/1256
- Liu, Tromer, Wang, *PerfOMR*, USENIX Security 2024: https://eprint.iacr.org/2024/204
- Menon, Wu, *YPIR: High-Throughput Single-Server PIR with Silent Preprocessing*, USENIX Security 2024: https://eprint.iacr.org/2024/270

Internal:
- `docs/reviews/full-review-2026-09-27.md` and its R11, R12, I1, I3, SX2 reports;
  `docs/reviews/wallet-review.md`; dossiers 21, 34, 35, 36, 37 in `C:/bszkeval/p2/research/`.

Assessment of research claims: the OMR/PerfOMR cost figures are the papers' own and were
not reproduced. FMD's constructions are DH-based per the paper body as summarized by R11
(the abstract does not say so); FMD stays rejected as in R11/I3 (not post-quantum, fuzzy
privacy, consensus fields). OMR stays P3 research: it needs a per-output clue (a consensus
field or sidecar) and has no mature pure-Rust stack.
