# 35 storage-recovery: research dossier (phase 2, phase 1)

**Agent:** 35 (storage-recovery). Internal engineering research, not an audit.
**Repository:** `rebuild/core` at `9e422d8` (`git rev-parse --short HEAD`). Read-only; no builds or tests were run.

Evidence tags: **[math]** established by arithmetic from source constants; **[test: name]** an existing named test; **[src]** source-read; **[ext]** external primary source (see §8); **[assumed]**; **[unknown]**.

---

## 1. Scope and what I read

**Code (all read in full unless noted):**
- `chain/src/store.rs` (876 lines: format, `bind`, `append`/undo, `load`, `repair`, 14 unit tests).
- `chain/src/manager.rs` (1459 lines: `CachedPow`, `open`, `replay`, `replay_one`, `submit_inner`, `drain_ready`, `keeps_body`, `invalidate`, `sync_state`, `finish_sync`, bounded API and its tests).
- `tx/src/state.rs` (`MemoryChain`, `BlockUndo`, `apply_block`, `undo_block`, `ChainView` impl, tests).
- `px/src/state.rs` (PX `State`, `Undo`, `apply_block`/`apply_inner`/`undo`) and `px/src/tree.rs` (`Frontier::append`, `root`).
- `tx/src/validate.rs` (`ChainView`, `OutputRecord`, `validate_block_transactions_cached` signature), `tx/src/types.rs` and `tx/src/px.rs` (prefix/base/prunable split of the tx hash).
- `node/src/main.rs` (data dir, `LOCK` via fs2, `--repair-store`, open/replay, error hints, shutdown), `node/src/lib.rs` (fatal `lock`, `watch_store`), `node/src/config.rs` (default data dir, `TESTNET_GENESIS_FINAL`), `p2p/src/net.rs` (`lock_or_exit`, block serving at :1836).
- `Cargo.toml` workspace members/excludes; `node/Cargo.toml` (`fs2`); `chain/Cargo.toml` (`crc32fast`).

**Tests read:** `chain/tests/storage_recovery.rs` (all 8), `chain/tests/manager.rs` restart tests (`restart_replays_the_store_without_recomputing_pow`, `restart_after_torn_write_recovers_previous_block`, `restart_rebuilds_the_px_state_exactly`, `restart_after_out_of_order_body_arrival_replays_the_store`, `a_failed_block_write_during_sync_is_recoverable`), the names of `chain/tests/fork_choice.rs` (`replay_reproduces_live_fork_choice_exactly`, `low_work_side_branch_bodies_are_not_kept_but_candidates_always_are`, `a_store_of_another_network_is_refused`), the `store.rs` unit tests.

**Docs and reports:** `C:/bszkeval/p2/brief.md`; roster entries 30–39 (mine is 35); `decisions.md` (all); dossiers 01, 02, 10, 12 (storage-related sections in full); `docs/blocks.md` §8 (full); `docs/reviews/full-review-2026-09-27.md` (§3.9, register rows, never-change #26, risks); `docs/reviews/autonomous-session-2026-09-27.md` (full); `full-review-2026-09-27/R10-storage-node.md` (full); R12 (§5, §6, R12-1, R12-4); SX2 (R10 table, C6, C9); `internal-review-log.md` PX-F1 row; `testnet.md` references to PX-F1/F2/F3.

**Not read in depth (outside scope):** RPC handlers other than the storage-facing ones (36), p2p sync (31), the mempool (12).

---

## 2. Current state

### 2.1 What exists and is well designed

| Claim | Evidence |
|---|---|
| `blocks.dat` is an append-only log: 48-byte file header (`BSBH`, version 1, network id, genesis id, CRC) then records `BSB1 ‖ len ‖ crc32 ‖ pow_hash ‖ block`. | [src] `store.rs:1-9, 219-228, 390-400` |
| A new store is bound to network and genesis; an existing store naming another network/genesis, a damaged header, or an unknown version is refused before any record is read. | [src] `store.rs:256-308`, `manager.rs:315`; [test: `a_new_store_is_bound_to_its_network`, `damaged_and_torn_file_headers`, `a_store_of_another_network_is_refused`] |
| Each append is durable on return (`sync_data`); a failed append is undone by truncation; if the undo fails the store is poisoned and refuses writes, so no record ever follows damaged bytes. | [src] `store.rs:186-205, 310-333`; [test: `a_failed_append_is_undone`, `a_failed_append_that_cannot_be_undone_stops_writes_until_restart`, `a_poisoned_store_reports_failure`] |
| Body fsync precedes state application ("fsync before apply"). | [src] `manager.rs:664-687` then `drain_ready` at `:703` |
| Load truncates only a damaged tail and refuses damage followed by any valid record, in linear time; repair is operator-only and moves the damaged region aside (synced) before truncating. | [src] `store.rs:342-383, 152-184, 417-428`; [test: `torn_tail_is_truncated`, `corruption_in_the_middle_is_an_error`, `mid_file_corruption_and_a_torn_tail_are_refused_fast`, `a_long_damaged_tail_of_record_candidates_is_truncated_fast`, `corruption_in_the_middle_is_repaired_only_on_request`, `mid_file_corruption_is_refused_then_repaired`] |
| A crash at any byte of the last record keeps all earlier blocks. | [test: `a_crash_at_any_byte_of_the_last_record_keeps_every_earlier_block`] |
| Repeated write failures (3) or a poisoned store mark the manager failed; no header/state change after that; the node exits within 2 s. | [src] `manager.rs:623-627, 672-686`, `node/src/lib.rs:82-88`, `main.rs:174-196`; [test: `a_full_disk_fails_the_store_without_changing_state`, `a_write_that_cannot_be_undone_fails_the_store_at_once`] |
| A poisoned chain lock is fatal everywhere (node and p2p); the store is replayed on restart. R10-2's residual p2p sites are closed at HEAD. | [src] `node/src/lib.rs:63-75`, `p2p/src/net.rs:54-67` |
| Replay goes through the same `submit_inner` → `sync_state` → full body validation as live processing, releases blocks in storage order, and reproduces live fork choice including ties. | [src] `manager.rs:376-463`; [test: `replay_reproduces_live_fork_choice_exactly` (16 orders × 2 restarts), `siblings_stored_before_their_parent_replay_in_storage_order`, `replay_skips_descendants_of_an_invalid_block_stored_before_it`] |
| Stored PoW hashes are trusted only under the seed re-derived from the replayed tree (cache keyed by seed and header bytes). | [src] `manager.rs:66-72, 441-451`; [test: `restart_replays_the_store_without_recomputing_pow`] |
| PX state (root, pool, nullifiers, registry, registration log) is rebuilt exactly by replay. | [test: `restart_rebuilds_the_px_state_exactly`] |
| PX `apply_block` is atomic on error. | [src] `px/src/state.rs:100-114` |
| Low-work side-branch bodies are neither stored nor kept (policy). | [src] `manager.rs:652-663, 773-789`; [test: `low_work_side_branch_bodies_are_not_kept_but_candidates_always_are`] |
| The mempool is never persisted (good for privacy). | [test: `after_a_restart_the_mempool_is_rebuilt_by_resubmission`] (per dossier 12) |
| The tx hash is `H(prefix_hash ‖ base_hash ‖ prunable_hash)`, and the prunable part holds BP+, CLSAGs and the PX STARK proof. So Monero-style pruning of proofs and signatures is structurally possible later without a consensus change. | [src] `tx/src/types.rs:253-271, 431-444`; `tx/src/px.rs:281-288, 506-511` |

### 2.2 What the tests prove, and what they do not

- **Proven:** prefix-preservation under a torn last record at every byte offset; refusal of mid-file damage; undo of failed appends; network binding; replay equivalence for small trees (ZeroPow, coinbase-only); exact PX state after one restart; the stored PoW is not recomputed.
- **Not proven:**
  - behaviour under random multi-fault sequences (bit flips plus tears plus failed appends): there is no property test;
  - a real full disk (docs say untested);
  - directory durability after creation;
  - restart cost and RSS at scale: no benchmark (only R12 arithmetic);
  - deep PX reorgs against a fresh replay (02 W-6c);
  - memory per block: nothing measures it.

### 2.3 What is missing (confirmed at HEAD)

- Positive evidence of validation in the store: no "validated" marker, no invalid tombstone, no state digest.
- Bodies are all in RAM (`manager.rs:217`), including side branches within the 100-block margin; there is no read-by-id and no index.
- Undo for every block forever, with a full PX snapshot of about 4.2 KB per block (R10-6).
- `load` reads the whole file, then copies every payload (peak about 2× the file) (`store.rs:343-353`).
- No `--reindex`/`--verify-store`, no operator tool to invalidate or pop blocks, no directory fsync.

---

## 3. Problems in scope

### 3.1 Restart costs a full re-verification, and the store has no positive evidence of validation (PX-F3, R12-4)

**What and why.** `open` → `replay` → `replay_one` → `submit_inner(persist=false)` → `sync_state` → `validate_block_transactions_cached` with an empty mempool, so every CLSAG, BP+ and PX proof (about 0.21 s each) is re-verified on one thread [src `manager.rs:434-463, 944-953`]. R12 estimates about 22 h per restart after one year of moderate use [R12 §6].

**The key design fact (new).** The absence of an "invalid" mark does **not** mean "valid". Bodies are fsynced *before* validation (`manager.rs:672`, `:703`). A crash between the append and `sync_state` leaves a never-validated body in the store, indistinguishable from a validated one. Side-branch bodies within the margin are also stored but never validated unless they become the target. So an assume-valid replay needs **positive** evidence written *after* validation. Tombstones alone (F10-3) cannot provide it. [src]

**Security consequences.** Liveness: restart time grows without bound. If assume-valid is done wrong (for example "no tombstone ⇒ valid"), a crash lets an invalid block be connected on replay without verification. That is a local consensus failure: the node follows an invalid chain and mines on it.

**Classification:** liveness/performance, with a consensus-safety pitfall in the fix. Not privacy-critical.

**Prior art.**
- Bitcoin Core `assumevalid` (0.14) skips *script* checks only for ancestors of a known-good block. Every other rule still runs, and "other chains are still accepted if they'd otherwise be chosen as best" [ext: 0.14.0 release notes].
- Core's crash recovery is `DB_HEAD_BLOCKS` plus `ReplayBlocks`: the block files are the journal, and the chainstate records which transition was in flight (PR #10148) [ext].
- Dash issue #7703 shows the failure mode of two stores committed non-atomically (coins DB vs EvoDB): nodes crash-loop until a full reindex [ext].
- AssumeUTXO loads a snapshot whose hash is compiled into the binary and validates it in the background [ext].
- Zebra commits each finalized block in one RocksDB write batch and keeps the non-finalized tip in memory [ext].

**Options.**
1. **Own-store validation watermarks** (recommended first). After a block connects, the node periodically appends a small typed record: `Checkpoint { tip_id, height, state_digest, fingerprint, build_commit }`, at every N = 720 connected blocks and at a clean shutdown.
   - On replay, blocks on the ancestor path of the newest checkpoint whose binding matches skip **cryptographic** verification (CLSAG, BP+, PX proof) but still run every contextual check (rings resolve, key images, nullifiers, anchors, amounts, coinbase, weight).
   - At the checkpoint height the recomputed state digest must equal the stored one. On a mismatch, full verification restarts from genesis automatically.
   - Cost: O(chain) cheap work with no proofs. This is `assumevalid` with the node's own verdict as the trust anchor.
2. **State snapshot** (serialized `MemoryChain` plus undo window plus digest, tmp + fsync + rename + directory fsync). Restart is O(tail). It needs a stable serialization of every state component and undo, and more format surface.
3. **Persistent state DB** (redb) (§3.6). Restart is O(1); it is the largest change.

**Trade-offs and risks of option 1.**
- **Trust model** (same class as stored PoW, never-change #26): the watermark is trusted only for the node's own store. A copied or forged store gets its crypto skipped. The mitigations are:
  - 01's startup PoW sampling (decided: 48 samples);
  - a single `--verify-store` flag that disables **all** own-store trust (stored PoW, tombstones, checkpoints) for imported stores;
  - documentation.
- **Code-version drift:** a release that fixes a validation bug must not inherit old verdicts. So the checkpoint binds the consensus fingerprint **and** the build commit, and any upgrade causes one full replay. Builds with an unknown commit never trust checkpoints.
- **State digest definition:** it must be deterministic and cheap. Proposal: a chained per-block delta digest
  `d_h = H("BlackSilk/state-delta/v1", d_{h-1}, id_h, first_output_h, n_outputs_h, H(sorted key images_h), px_root_h, px_pool_h, n_nullifiers_h, H(registrations_h))`.
  It is O(1) per block, computed in `apply_block`, never consensus, and its tag is registered with 19.
- Mempool trust (dossier 12, W2): "connected ⇒ verified" becomes "connected ⇒ verified now or in an earlier session under the same build". This must be written in blocks.md §8.

**Tests that prove it:**
- a counting test hook: a restart after N blocks with a checkpoint verifies 0 PX proofs and 0 CLSAGs below it, and the tail above it is fully verified;
- the digest equals a fresh full replay;
- a checkpoint with another fingerprint or commit is ignored;
- a crash after the append and before validation (injected) is fully validated on replay and never skipped;
- a forged checkpoint over an invalid block is caught by `--verify-store`;
- restart-equivalence: restarting after every block gives the same digest sequence as never restarting.

**Invariants that must never change:**
- replay runs the same code path, with only the crypto sub-checks gated;
- positive evidence only ("no tombstone" never means valid);
- own-store trust only, with a flag to disable it;
- no consensus effect.

### 3.2 Invalid bodies are re-validated at every start (F10-3)

Agreed with dossier 10. Invalid bodies stay in the file (`invalidate` drops them only from RAM, `manager.rs:820-851`), and `replay_one` re-validates them (`:453-456`).

**Fix:** a typed `Invalid { id, code }` record appended after the verdict. It needs no fsync of its own: the next append's `sync_data` covers it, and a lost or torn tombstone only means one re-validation. Replay marks the block invalid without validation, and descendants follow through the existing `InvalidParent` path.

**Conditions:**
- tombstone only deterministic body verdicts (`SubmitError::Body`);
- the body is bound to its header by `tx_root` before storage (`manager.rs:639-649`), so the CVE-2012-2459 class (a valid id marked invalid through a mutated body) cannot arise. Keep that order as an invariant;
- ignored under `--verify-store`.

**Bonus:** the same record type gives operators an `--invalidate-block <id>` escape hatch (§3.5).

**Tests:** a restart after an invalid block performs zero body validations (counter) and gives the same `invalid_reason` code; a torn tombstone at the tail is truncated and the block is re-validated.

### 3.3 PX undo snapshots and slim undo (R10-6, PX-F2)

`px::State::apply_block` clones the whole frontier (8 + 32×32 = 1,032 B) and root window (100 × 32 = 3,200 B) into every `Undo`, including empty blocks; `MemoryChain` keeps an undo for every block forever [src `px/src/state.rs:100-106`, `tx/src/state.rs:46, 221-229`]. That is about 4.2 KB per block, about 1.1 GB/year idle [math, confirmed by SX2].

**New exactness argument.**
- `Frontier::append` writes **exactly one** branch slot per leaf: `branch[h]` for the lowest zero bit `h` of `pos`. Positions are below 2^32, so such an `h` always exists [src `tree.rs` `append`].
- The root window changes by one push plus at most one pop per block.

So an exact delta is:
`Undo { size_before: u64, slots: Vec<(u8, Digest)> (old values, in write order), popped_root: Option<Digest>, pushed: bool, pool_before: u128, nullifiers: Vec<Digest> }`.
Undo reverses the slot writes in reverse order, sets `size`, pops the pushed root, restores the popped one, restores the pool, and removes the nullifiers. It is about 100 B for an empty block and about 33 B per commitment. The mid-block error path (`apply_inner` failing after some appends) must use the same reversal, so slots are recorded *before* each write.

**Also:**
- `BlockUndo.tx_hashes` (32 B per tx per block, forever) has no caller outside its own getter (`tx/src/state.rs:100, 224`; no use in node, p2p, wallet or tests) [src, grep]. Drop it.
- Removing the key set per D8 option B shrinks `BlockUndo` further.

**Classification:** memory DoS resistance and scalability. No consensus impact if undo restores exactly.

**Tests:**
- a proptest (approved for chain; for px via decision 20): random blocks with 0–6 commitments, random nullifiers and pool moves, apply/undo sequences; compare every step with a reference implementation that keeps the old snapshot undo; include forced mid-block failures (DoubleSpend after appends; TreeFull with a test-only frontier near capacity);
- a byte-accounting test: `undo_heap_bytes()` for 1,000 empty blocks is at most 200 B per block (structural accounting, not an allocator hook, so no `unsafe`).

**Invariant:** undo restores bit-exactly, and the root window semantics (roots after each block, including empty ones) never change.

### 3.4 Bodies in RAM, startup load 2× the file (PX-F1, R10-8c, R12-1)

`bodies: HashMap<Hash, Vec<Transaction>>` holds every stored body, main chain and side branches, forever [src `manager.rs:217, 690`]. `load` reads the whole file, then copies each payload [src `store.rs:343-353`]. R12: about 6 KB per block floor plus 4.5× v1 bytes in RAM.

**Fix (R10 step 1, refined):**
- `BlockStore::read(loc) -> io::Result<Vec<u8>>` with the CRC re-checked on read. For `FileStore`, a separate read handle using positional reads (`std::os::unix::fs::FileExt::read_at` / `std::os::windows::fs::FileExt::seek_read`: safe std APIs; no new dependency, no `unsafe`).
- A streaming `load` that yields `(offset, len, pow_hash, bytes)` one record at a time.
- `bodies` becomes `HashMap<Hash, BodyLoc>` plus a byte-bounded LRU of decoded bodies (the tip window and blocks being connected).
- A read error or CRC mismatch on read is a **store failure** (fail-stop, restart, `load` decides).

**Users of bodies to migrate:**
- `sync_state` (validate, disconnect returns);
- `block_at` (RPC `/blocks`, `node/src/lib.rs:317`);
- `block` (p2p serving, `net.rs:1836`);
- `has_body`, `missing_bodies`, `keeps_body`, `invalidate`.

**Risk:** disk I/O under the chain lock (about 1 ms per body). This is acceptable interim; 34's actor removes it.

**Tests:**
- RSS proxy: `bodies_cached_bytes()` stays at most the LRU cap while 2,000 blocks connect;
- read-after-restart equals the original bytes;
- an on-read CRC flip stops the node (store failed) and the next start refuses with mid-file damage;
- a p2p `GetBlocks` served from disk.

**Bench (45):** restart time and peak RSS on a 20k-block regtest chain, before and after.

### 3.5 Deterministic crash loops and operator escape (new)

- A validator/apply mismatch panics in `MemoryChain::apply_block` (`expect` at `tx/src/state.rs:193, 220`) after the body was fsynced. With fail-stop the node exits (correct), but replay re-hits the same block and panics again: a permanent crash loop.
- A decode tightening in a future release makes `replay` refuse the store (`manager.rs:388-393`).
- In both cases `main.rs:106-113` suggests `--repair-store`, which finds "no damage" because the CRCs are valid.
- There is no `--invalidate-block`/`--pop-blocks` (Monero `--pop-blocks`, Core `invalidateblock`) and no `--reindex`.

**Fix:**
- an operator `--invalidate-block <id>` that appends an `Invalid` record (§3.2);
- `--resync` guidance (move the store aside);
- a precise error message per error class.

**Tests:** a test hook forces an apply panic at height h; the node exits with 70; a restart with `--invalidate-block` starts on the parent.

### 3.6 Persistent state engine: redb, fjall, sled (roadmap only)

| | redb | fjall | sled |
|---|---|---|---|
| Model | CoW B+tree, ACID, 1 writer and MVCC readers | LSM, keyspaces with cross-keyspace atomic batches | lock-free B-link, log-structured |
| Maturity | "Stable and maintained… file format is stable"; releases 4.1.0 (2026-04-19), 4.2.0 (2026-08-17), 4.3.0 (2026-09-14) [ext: README, CHANGELOG] | 3.0 with a new disk format "made for longevity" (the blog is dated 2026-09-15 as fetched; R10 cited 2026-01-02, a discrepancy to check before relying on it) [ext] | "quite young… unstable… if reliability is your primary constraint, use SQLite. sled is beta"; the on-disk format will change before 1.0; a rewrite is under way [ext] |
| Crash consistency | 1PC+C (default): one fsync, an XXH3-128 checksum Merkle tree, a "god byte" primary flip. 2PC: two fsyncs. The design doc: "Users who need to accept malicious input are encouraged to use 2PC". Repair on open; `set_quick_repair` [ext: design.md, CHANGELOG 2.3.0] | Default writes reach **OS buffers only** ("matches RocksDB's default"); durability needs `persist(PersistMode::SyncAll)` per commit [ext README] | periodic flush every 500 ms by default [ext] |
| `unsafe` | mmap backend removed in 0.14.0 because its soundness "was infeasible to prove"; there is **no** `#![forbid(unsafe_code)]` in `src/lib.rs`; the internal count is unknown [ext] | claims "100% safe & stable Rust" (`forbid(unsafe_code)`), but its storage layer uses `unsafe` in `byteview` for non-zeroed buffers (fjall 3.0 post) [ext] | 159 occurrences of `unsafe` in `sled-0.34.7/src` (counted locally in the cargo registry); optional `zstd` (C) [src-local] |
| Fuzzing | `fuzz/` directory; "extensive fuzz testing" before 1.0 [ext] | "core components… fuzz- and mutation tested" (3.0) [ext] | `fuzz/`, crash-testing topic [ext] |
| History of corruption bugs | several fixed data-corruption bugs (0.13.0 >4 GB overflow; 1.0.4 `drain`; 2.1.2 savepoint/I/O error; 4.0.0 `AccessGuardMut`) [ext CHANGELOG] | — | — |
| RustSec | none found by search [unknown; agent 44 must run `cargo audit`/`cargo deny`] | none found [unknown] | none found for sled itself; stale dependencies [assumed] |
| Verdict | **preferred candidate** if a DB is adopted, with 2PC and quick-repair, behind a `StateStore` trait | viable, but opt-in durability is error-prone and background compaction adds nondeterministic I/O | **reject** (`legacy/gui-wallet` still names it; that crate is excluded from the workspace) |

**Prior-art layouts:**
- **Monero LMDB:** `blocks`, `block_info`, `block_heights`, `txs_pruned`, `txs_prunable`, `txs_prunable_hash`, `txs_prunable_tip`, `tx_indices`, `tx_outputs`, `output_txs`, `output_amounts`, `spent_keys`, `alt_blocks`, `txpool_*`; schema `VERSION 5` [ext]. Monero has no undo table: it pops blocks by recomputing.
- **Zebra:** RocksDB column families, semantic `DATABASE_FORMAT_VERSION` (major 28: a new empty state and re-sync; minor/patch: in-place upgrades that run concurrently and must be valid after every transaction); note-commitment trees stored per height; nullifiers and anchors create-only; `MAX_NON_FINALIZED_CHAIN_FORKS = 10` [ext].

**BlackSilk decision.** Do **not** adopt a DB before the trial.
- The in-house log plus watermarks plus body index removes the trial-relevant costs with no new dependency.
- Adopting redb is P3, and only after:
  - 44's dependency review (unsafe count via `cargo geiger`, platform FFI for locking, RustSec);
  - a differential property test against `MemoryChain`.
- The unit of atomicity must be **one transaction per connected or disconnected block** covering v1 state, PX state, undo, tip and invalid flags. Two stores committed separately is exactly Dash #7703.

### 3.7 Pruning and privacy (rings need old outputs)

**Never prunable** (on any node that validates or serves wallets):
- the output set `(one_time_key, commitment, height, coinbase)`: every output is a potential CLSAG ring member, and decoy selection samples over the whole distribution [ext: Möser et al. PETS 2018; Ronge et al. ePrint 2020/1550]. A node or wallet that knew only recent outputs would produce age-distinguishable rings;
- key images; PX nullifiers;
- PX commitments and positions (wallets rebuild authentication paths; R12-8);
- the contract registry.

Monero likewise prunes only the *prunable* tx data (signatures and range proofs) of 7/8 of blocks and keeps the last 5,500 blocks in full [ext: PR #4843, 2019 announcement]. FCMP++ moves Monero to a whole-chain anonymity set [ext], which makes "never prune outputs" permanent.

**Prunable later** (non-archival nodes only): v1 BP+ and CLSAGs, and the PX STARK proofs (the bulk of PX bytes), after validation and a depth. The tx hash keeps `prunable_hash`, so `tx_root` stays checkable [src]. Base parts (ECDH amounts, PX ciphertexts) must stay, because wallets scan them.

**Privacy hazards of pruning:**
- advertising a pruning seed or stripe in P2P is a node fingerprint (Monero sends it in its handshake) [assumed from Monero's design];
- a pruned node serving `/blocks` with stripped data is distinguishable;
- a pruned node cannot re-validate its own history, so it depends on §3.1's trust.

**Recommendation:** archival-only for the testnet; pruning is P3 and requires the snapshot (option 2).

### 3.8 Legacy headerless stores reopen R10-3 at the v3 launch (new)

`bind` accepts any headerless (format 0) store "as it is, with a warning", and it stays headerless forever [src `store.rs:272-280`; test `a_legacy_headerless_store_is_accepted_unchanged`]. Every store written before 2026-09-27 is headerless, and every one of them belongs to a **pre-v3** network. The default data directory is the same for every testnet generation (`node/src/config.rs:201-204`).

**Scenario.** At the v3 launch an operator keeps the default directory:
1. the v2 store is accepted;
2. every v2 block becomes an unreplayable orphan, re-read and re-decoded at every start (the log says "they will be downloaded again", which is wrong);
3. the v3 chain is appended into a file whose network can never be verified.

That is exactly R10-3, which the header was meant to close. It is mitigated today only by procedure (P0-13: fresh data directories) and by `TESTNET_GENESIS_FINAL = false`.

**Fix:** refuse format 0 on testnet and mainnet ("block store from before the v3 reset; move it aside"). Regtest may keep accepting it. No v3 store can be headerless, because the header shipped before any v3 genesis. Cheap, P0.

### 3.9 Smaller items

- **Directory durability.** No directory fsync after `blocks.dat` is created (`store.rs:122-131, 256-270`). Today that is only a resync after a power loss. Any future snapshot, checkpoint sidecar or rename **must** fsync the directory. Pillai et al. (OSDI 2014, ALICE) show that applications routinely get this wrong. On Windows, use `OpenOptionsExt::custom_flags(FILE_FLAG_BACKUP_SEMANTICS)` from safe std.
- **fsync errors.** The design already follows the lesson of PostgreSQL's "fsyncgate": the failed record is truncated and never assumed durable. For extra margin, treat a `sync_data` error (as opposed to a `write` error) as an immediate store failure, as PostgreSQL does (it PANICs) [ext].
- **Torn tail with an embedded record** is refused and needs a manual repair (an accepted trade-off, `store.rs:566-609`). Optional P3: when the damaged record reports "short payload" and starts within `MAX_PAYLOAD + 12` bytes of EOF, automatically move the region aside (as `repair` does) instead of refusing. The data is never silently lost, and availability improves.
- **Side-branch bodies in RAM forever**, including after replay (R10-1(d) not implemented). The cost is bounded by work within the 100-block margin. After §3.4 this becomes index-only, so eviction is trivial.
- **Local forensic metadata.** `blocks.dat` keeps arrival order and locally mined blocks that never propagated. A seized store can link an operator to mining a stale block. Informational; document it next to R10-10's log advice.
- **D8 interaction.** Set-based undo of `one_time_keys` (`tx/src/state.rs:208, 239`) is sound only under uniqueness. D8 option B removes the set together with the rule; the removal must be total (no leftover insert/remove), or `has_one_time_key` becomes wrong after an undo. Owners 13 and 17; I review.

---

## 4. New findings

| ID | Severity | Status | Location | Scenario | Confidence |
|---|---|---|---|---|---|
| **F35-1** Legacy headerless stores are accepted, reopening R10-3 at the v3 launch | **Medium** | Not implemented | `chain/src/store.rs:272-280`; `node/src/config.rs:201-204` | An operator keeps the default data dir at the v3 launch: the v2 store is accepted, all old blocks are orphaned and re-read at every start, and the v3 chain is appended into an unverifiable file | High |
| **F35-2** No positive validation evidence in the store: assume-valid replay cannot be built on tombstones | **Medium** (design pitfall; liveness today) | Not implemented | `manager.rs:672` (append) before `:703` (validate); `:434-463` | The naive "no tombstone ⇒ valid" skip would connect a crash-interrupted invalid body without verification | High |
| **F35-3** Restart = full crypto re-verification (PX-F3/R12-4, sharpened with the watermark design) | Medium (testnet) / High (mainnet) | Accepted limitation → P1 | `manager.rs:434-463, 944-953` | About 22 h restart after a year of moderate use (R12); crash loops amplify it | High |
| **F35-4** Invalid bodies re-validated at every start (= F10-3; owner 35) | Low–Medium | Not implemented | `manager.rs:820-851, 453-456` | Each attack block costs its full validation at every restart | High |
| **F35-5** PX undo snapshot of about 4.2 KB per block; an exact delta is possible because one frontier slot changes per append | Medium (scaling) | Accepted limitation → P1 | `px/src/state.rs:100-106, 150-157`; `px/src/tree.rs` `append` | 1.1 GB/year of RAM idle | High [math] |
| **F35-6** Deterministic apply panic or decode tightening ⇒ permanent crash loop, with a misleading `--repair-store` hint and no invalidate/pop tool | Low | Not implemented | `tx/src/state.rs:193, 220`; `manager.rs:388-393, 458-461`; `node/src/main.rs:106-113` | A validator/apply mismatch block, once stored, stops every restart | Medium (trigger reachability [unknown]) |
| **F35-7** `BlockUndo.tx_hashes` is dead per-block memory | Low | Not implemented | `tx/src/state.rs:100, 224` | 32 B × txs per block forever, never read | High |
| **F35-8** No directory fsync after store creation; required for any future rename-based file | Informational (Low for future snapshots) | Not implemented | `store.rs:122-131, 256-270` | A power loss right after the first start loses the new file (resync only) | High |
| **F35-9** A `sync_data` failure is retried up to 3 times instead of failing at once | Low | Partially implemented | `manager.rs:672-686`, `store.rs:310-333` | Conservative practice (PostgreSQL) treats fsync failure as fatal; the current undo makes it safe, but the margin is thin | Medium |
| **F35-10** Side-branch bodies kept in RAM forever; replay keeps them all | Low | Partially implemented (R10-1 a/b done; d open) | `manager.rs:651, 690` | Junk within the margin costs about one block of work each and stays forever | High |
| **F35-11** Torn tail with an embedded record-shaped string needs a manual repair | Low (accepted) | Accepted limitation | `store.rs:356-369` | A crash during a user-shaped block write blocks the restart until the operator acts | High |
| **F35-12** `blocks.dat` retains local stale mined blocks and arrival order (forensic) | Informational (privacy) | Accepted limitation (document) | `manager.rs:664-686` | A seized store links the operator to mining | Medium |
| **F35-13** Load peak about 2× the file | Low | Not implemented (R10-8c) | `store.rs:343-353` | OOM at start on large stores | High |

**Challenges to existing reports.**
- R10 §5.4 step 3 (a snapshot as the interim fast start) is heavier than needed for the trial. Watermarks (option 1) give most of the restart gain with far less format surface.
- R12-4 (b) ("trust own validated store… mark blocks validated") is right, but it must be positive evidence written after validation (F35-2), bound to the build commit.
- The legacy acceptance in `9d689f0` partly undoes R10-3 for exactly the population it targeted (F35-1).

---

## 5. Implementation plan for phase 2

| # | Item | Files (ownership) | Externally visible | Identity | Tests | Bench | Docs | Size | Prio |
|---|---|---|---|---|---|---|---|---|---|
| S1 | Refuse format-0 (legacy) stores on testnet/mainnet; precise message; regtest keeps accepting (F35-1) | `chain/src/store.rs` (35); `chain/src/manager.rs` `open` call site only (35); `node/src/main.rs` error text (35, 36 reviews) | Node policy | none | unit: legacy refused on testnet, accepted on regtest, file untouched; `fork_choice.rs` extension | — | blocks.md §8, testnet.md §9/§12 | S | **P0** |
| S2 | Store format v2: typed records (`Block`, `Invalid`, `Checkpoint`), a version bump before the freeze so v3 stores never need migration; v1 (pre-freeze labnet) stores refused with "resync" | `chain/src/store.rs` (35) | Storage format only | none | round-trip per type; unknown type refused; torn typed record truncated; proptest crash/bit-flip model (below) | — | blocks.md §8 | S–M | **P0** (the format; the logic below is P1) |
| S3 | Store proptest: random appends, failed appends, tear at a random byte, random bit flips ⇒ `load` returns an exact prefix of the committed records or refuses; never truncates when a later valid record exists; repair keeps every valid prefix record | `chain/src/store.rs` tests (35); proptest dev-dependency (41 adopts) | none | none | property | — | — | S | P1 |
| S4 | PX undo delta, and `BlockUndo` slimming (drop `tx_hashes`) (F35-5, F35-7) | `px/src/state.rs`, `px/src/tree.rs` (35 writes; 21 reviews, owner of px state semantics); `tx/src/state.rs` `BlockUndo` (35; sequence after 13/17's D8 removal in the same file) | none (exact undo) | none | proptest vs reference snapshot undo including mid-block failures; byte-accounting test; all existing reorg/restart suites; 02's W-6c deep PX reorg | memory per 1k empty blocks | blocks.md §8 limits; R10-6 closed | S–M | **P1** (P0 if the trial runs longer than about 4 weeks) |
| S5 | Invalid tombstones and `--invalidate-block` (F35-4, F35-6) | `chain/src/manager.rs` `invalidate` (append) and `replay_one` (35); `chain/src/store.rs` (35); `node/src/config.rs`, `main.rs` flag (35; 36 reviews CLI) | Policy | none | a restart after an invalid block does 0 validations (counter); invalidate-block escapes a forced apply-panic loop; tombstones ignored under `--verify-store` | restart with N invalid blocks | blocks.md §8, testnet.md operator | S–M | P1 |
| S6 | Body index: bodies out of RAM, positional reads with CRC check, byte-bounded LRU, streaming `load` (F35-10, F35-13, PX-F1) | `chain/src/store.rs` (35); `chain/src/manager.rs` body accessors (35; 34 reviews lock/I/O; 10 reviews `sync_state` read) | none | none | read-after-restart; on-read CRC ⇒ store failed; cache bound; p2p serving from disk; all suites | restart time and RSS, 20k blocks (45) | blocks.md §8 | M | **P1** |
| S7 | Own-store validation checkpoints (assume-valid of own data) plus the state-delta digest; `--verify-store` unifies with 01's `--verify-store-pow` (F35-2, F35-3) | `chain/src/manager.rs` replay (35) plus 01's sampling in the same path (01 writes sampling, 35 integrates); `tx/src/state.rs` digest (35); a `VerifyMode::ContextualOnly` in `tx/src/validate.rs` block path (**10 writes**, 35 specifies); digest tag in `crypto/src/hash.rs` registry (19); `node/src/fingerprint.rs` read-only use (40) | Policy | none | skip counters; digest equals full replay; binding mismatch ⇒ full verify; crash-before-validate never skipped; forged checkpoint caught by `--verify-store`; restart-after-every-block equivalence | restart time vs chain length (45) | blocks.md §8 trust model (also 12's W2 note), testnet.md | M | **P1** |
| S8 | Durability hygiene: directory fsync on create (Unix and Windows); `sync_data` failure ⇒ immediate store failure; precise startup error hints per class | `chain/src/store.rs`, `node/src/main.rs` (35) | none | none | injected sync failure ⇒ failed at once; message tests | — | blocks.md §8 | S | P2 |
| S9 | Side-branch body eviction below the low-work threshold as the tip advances (index-only after S6) | `chain/src/manager.rs` (35; 02 reviews) | Policy | none | memory stays flat under junk siblings; a heavier branch is still fetched | — | blocks.md §8 | S | P2 |
| S10 | State snapshot for O(tail) restart, only if S7's measurements miss the target | new `chain/src/snapshot.rs` (35) | none | none | crash at every snapshot write step; equivalence | restart | blocks.md §8 | M–L | P2 |
| S11 | Persistent `StateStore` trait; redb (2PC) implementation; differential proptest against `MemoryChain`; one transaction per block; `--reindex` | `tx/src/state.rs` trait (35, 46 reviews), new crate or module (35) | none | none | differential, crash injection between archive fsync and DB commit, real disk-full on a size-limited tmpfs (CI Linux) | RSS, restart | ADR | L | P3 |
| S12 | Pruning of prunable parts on non-archival nodes (never outputs, key images, nullifiers, commitments or base parts); no pruning-seed advertisement | chain, p2p (31/33 review) | Policy | none | pruned node refuses `/blocks` below the prune height; privacy regression: no pruning signal on the wire | disk | blocks.md, px.md | L | P3 |

**First safe steps (wave 1): S1, S2, S4, then S5 and S6.** They touch only storage and undo internals and are verdict-neutral. S7 follows once 10's `VerifyMode` lands.

---

## 6. Dependencies and conflicts

- **01:** F-01 PoW sampling lives in my replay path. I propose one `--verify-store` flag covering PoW, tombstones and checkpoints. 01 writes the sampling; I integrate it. `blocks.md` §8 edits go through 47.
- **02:** INV-4 (replay = live) must hold after S5–S7; W-1's model test should include restarts with tombstones and checkpoints. W-7 park: undo is never pruned on its strength (agreed). W-4 (in-memory skip of re-verification on reconnect) is the in-session analogue of S7; share the "validated" notion.
- **10:** F10-3 is S5 (mine). `VerifyMode::ContextualOnly` for S7 is 10's file; the verified-proof cache must not be persisted without the same binding.
- **12:** W2's trust note ("verified now or in an earlier session under the same build") goes into blocks.md §8 with S7.
- **13/17:** the D8 removal of the key set touches `tx/src/state.rs` before S4. Sequence: D8 first, then S4.
- **19:** register the `state-delta/v1` tag (policy-only).
- **20/21:** px state and tree semantics review for S4.
- **34:** S6 does disk reads under the lock (interim); the actor design should expose the store read path off-lock; MVCC readers come later with S11.
- **36:** `/blocks` reads bodies from disk after S6; CLI flags; error texts.
- **39:** a compact feed can be served from the S6 index.
- **40:** fingerprint semantics used in the S7 binding; the store format is not part of the consensus fingerprint.
- **41:** proptest adoption, and a store fuzz target (`parse_record`, `load` over arbitrary bytes).
- **43:** `BUILD_COMMIT` must be reliable for the S7 binding (an unknown commit ⇒ no trust).
- **44:** review of any DB dependency (S11).
- **45:** restart and RSS benchmarks.
- **47:** docs.
- **50:** red-team review of S5/S7 (the trust model).

---

## 7. Open questions for the coordinator

1. Accept F35-1's fix (refuse legacy stores on testnet and mainnet) as P0?
2. Typed records inside `blocks.dat` (format v2, one ordered log) vs a sidecar file? I recommend in-log, now, before the freeze.
3. S7 binding: the build commit (one full replay after every upgrade; simple, conservative) vs a manually bumped "validation epoch" (faster upgrades, error-prone)? I recommend the build commit.
4. Should S7 still run contextual checks (my recommendation), or apply covered blocks directly and rely on the digest (faster, less defensive)?
5. Confirm archival-only for the testnet and a DB (redb) deferred to P3.
6. PX undo delta priority: P1 (my view: cheap and exact), or P0 given the trial length?

---

## 8. Sources

- redb README: https://github.com/cberner/redb
- redb design (1PC+C, 2PC, god byte, malicious-input note): https://github.com/cberner/redb/blob/master/docs/design.md
- redb CHANGELOG (releases 4.1–4.3, mmap removal 0.14.0, quick repair 2.3.0, corruption fixes): https://raw.githubusercontent.com/cberner/redb/master/CHANGELOG.md
- redb `src/lib.rs` (crate attributes; no `forbid(unsafe_code)`): https://raw.githubusercontent.com/cberner/redb/master/src/lib.rs
- fjall README: https://github.com/fjall-rs/fjall
- fjall 3.0 announcement: https://fjall-rs.github.io/post/fjall-3/
- sled README: https://github.com/spacejam/sled
- Bitcoin Core assumeutxo design: https://github.com/bitcoin/bitcoin/blob/master/doc/design/assumeutxo.md ; user doc: https://github.com/bitcoin/bitcoin/blob/master/doc/assumeutxo.md
- Bitcoin Core PR #10148 (non-atomic flush with block replay, `DB_HEAD_BLOCKS`): https://github.com/bitcoin/bitcoin/commit/d4e551a
- Bitcoin Core 0.14.0 release notes (assumevalid): https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-0.14.0.md ; https://bitcoincore.org/en/2017/03/08/release-0.14.0/
- Bitcoin Core block storage (PoW re-check on read; undo files): https://github.com/bitcoin/bitcoin/blob/master/src/node/blockstorage.cpp
- Dash issue #7703 (coins DB / EvoDB non-atomic commit ⇒ reindex loop): https://github.com/dashpay/dash/issues/7703
- Zebra state DB upgrades: https://zebra.zfnd.org/dev/state-db-upgrades.html ; constants: https://github.com/ZcashFoundation/zebra/blob/main/zebra-state/src/constants.rs
- Monero LMDB schema (`db_lmdb.cpp`): https://raw.githubusercontent.com/monero-project/monero/master/src/blockchain_db/lmdb/db_lmdb.cpp
- Monero pruning PR #4843: https://github.com/monero-project/monero/pull/4843 ; announcement: https://web.getmonero.org/2019/02/01/pruning.html
- Möser et al., "An Empirical Analysis of Traceability in the Monero Blockchain", PoPETs 2018: https://petsymposium.org/popets/2018/popets-2018-0025.php (arXiv 1704.04299)
- Ronge et al., "Foundations of Ring Sampling", ePrint 2020/1550: https://eprint.iacr.org/2020/1550.pdf
- Monero FCMP++: https://www.getmonero.org/2024/04/27/fcmps.html
- Pillai et al., "All File Systems Are Not Created Equal", OSDI 2014: https://www.usenix.org/conference/osdi14/technical-sessions/presentation/pillai
- PostgreSQL "Fsync Errors": https://wiki.postgresql.org/wiki/Fsync_Errors
- Local measurement: `unsafe` occurrences in `~/.cargo/registry/src/.../sled-0.34.7/src` (159) and `crc32fast-1.5.2/src` (15), by grep.
