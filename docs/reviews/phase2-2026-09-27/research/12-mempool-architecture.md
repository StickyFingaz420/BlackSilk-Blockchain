# 12 mempool-architecture: research dossier (phase 2, phase 1)

Author: specialist agent 12. This is internal engineering research, not an audit. The
repository was only read. Nothing was built or run, and no repository content was sent to
any web service.

## 1. Scope and what I read

**Commit:** `9e422d8` (`rebuild/core`, `git rev-parse --short HEAD`).

**Code, read in full:**
- `chain/src/mempool.rs` (1,254 lines, including the 15 unit tests).
- `chain/src/manager.rs`, these parts:
  - `SyncOutcome` (196-205) and `submit_block_in_steps` (266-288);
  - `drain_ready` (711-741) and `sync_state` (879-967), covering disconnection, the returned transactions and the proof cache;
  - `finish_sync` (979-995), `check_tx` and `submit_tx` (1203-1214), and `template` (1247-1277).
- `tx/src/validate.rs` (1,132 lines, all of it), in particular:
  - `validate_mempool_tx`, `validate_px_without_proof`, `revalidate_after_extension` and `revalidate_between`;
  - `resolve_input_rings`, the `is_stateless` table and `validate_block_transactions_cached`.
- `tx/src/params.rs`: `TxRules`, `at_height` and `domain`. `tx/src/types.rs`: `weight`, `px_bytes` and `fee`. `consensus/src/schedule.rs`: branch-id uniqueness (line 83).
- `p2p/src/net.rs` 2041-2600: `on_inv_tx`, `on_get_tx`, `admit_tx`, `on_tx`, `on_stem_tx`, `stem_or_fluff`, `fluff`, and the reject caches.
- `node/src/lib.rs`: `/template` and `/tx`. `wallet/src/wallet.rs` 60-85 and 1414-1560: `PENDING_EXPIRY_BLOCKS` and rebroadcast. `crypto/src/clsag.rs` 60-110 and 262-290: the ring is hashed into `mu_P` and `mu_C`.

**Tests read:**
- `chain/src/mempool.rs` unit tests (15);
- `chain/tests/revalidation.rs` (4);
- `chain/tests/mempool_conflicts.rs` (10, test list and harness);
- `chain/tests/manager.rs` 858-1097 (mempool section, 5 tests);
- `chain/tests/activation.rs` (mempool flush cases).

**Docs and reports:**
- `docs/blocks.md` §7.
- `docs/reviews/full-review-2026-09-27.md`: the register rows for MP-1 to MP-9, F1, "no expiry", R16-8 and R12-2, plus P1-18, P2-1, D5 and the never-change list.
- `docs/reviews/autonomous-session-2026-09-27.md`.
- R6 (full), R12 §1, §10 and R12-12, R16-8, R13 T-4/T-5, SX1 and SX2 (mempool rows), and I4 (expiry and compact-block rows).
- `docs/reviews/v3-upgrade-mechanism.md` §2.5.
- The roster entries for 10, 11, 13, 14, 33, 34, 35, 38 and 41.

## 2. Current state

### 2.1 What exists and is well designed

1. **Two classes, separate caps and units.**
   - v1: 50 MB, fee per weight. PX and deploys: 64 MiB, fee per byte (`mempool.rs:38-41, 97-102, 284-287`). [source-read]
2. **Atomic eviction.** Victims are chosen before any removal. Only strictly cheaper entries are evicted, and the pool is unchanged if that cannot make room (`mempool.rs:296-327`).
   - [tested: `a_full_pool_evicts_only_strictly_cheaper_entries_and_only_if_that_suffices`, `eviction_under_a_flood_stays_fast`]
3. **Four conflict namespaces** (key image, nullifier, contract id, output key), checked in `precheck` before any validation (`mempool.rs:227-240`).
   - [tested: `a_shared_output_key_is_a_conflict_across_all_kinds`, `equal_bytes_in_different_namespaces_do_not_conflict`, `randomized_operations_keep_the_conflict_invariants` (2,000 seeded operations, full invariant check after each), and the 10 `mempool_conflicts` integration tests with forged valid transactions]
4. **`select` re-checks conflicts** as defence in depth. It also simulates the PX pool in block order and respects the deploy sub-budget.
   - [tested: `select_skips_a_conflicting_entry_when_the_invariant_is_broken`, `selection_orders_by_fee_rate_and_respects_budgets_and_the_pool`, `selection_respects_the_deploy_sub_budget`]
5. **Budgets in `select` match the block rules:**
   - B6 counts `weight()` of every transaction, but PX and deploys have weight 0 (`types.rs:452-458`), so the v1-only weight in `select` is exact;
   - `COINBASE_RESERVE = 3000` exceeds the largest coinbase (1,469 B, R6).
   - [source-read; math]
6. **Extension-only revalidation** (`validate.rs:712-746`).
   - The argument holds: outputs are append-only, so rings resolve identically, and maturity only improves.
   - [tested: `revalidation_after_an_extension_agrees_with_full_validation`, `a_plain_extension_keeps_valid_transactions`, `an_output_key_created_by_another_transaction_is_caught_by_the_extension_check`; measured 6.3 µs per transaction]
7. **The reorg path needs more than the extension check.**
   - [tested: `replacing_coinbase_only_blocks_changes_a_ring_and_needs_full_validation`, `a_shorter_heavier_reorg_makes_a_ring_member_immature`]
   - Both tests show the extension check alone would keep an invalid transaction. **Any faster reorg path must keep both tests green.**
8. **Activation flush.** `enter_rules` drops everything when the signature domain changes, in either direction. `template` refuses a pool of another domain (`manager.rs:1257`), and the proof cache is gated on `same_rules` (`manager.rs:945`).
   - [tested: `a_new_signature_domain_flushes_the_pool`, `chain/tests/activation.rs`]
9. **P2P admission order.** Replays, pooled conflicts and contextual rejects at this tip are dropped before verification (`net.rs:2246-2266`), and the PX node-wide token is taken only after the cheap checks. [source-read; SX2]
10. **The pool is not persisted** [tested: `after_a_restart_the_mempool_is_rebuilt_by_resubmission`]. This is good for privacy, because nothing about local transactions is written to disk.
11. **Pool contents never change a block verdict** [tested: `mempool_contents_never_change_a_blocks_verdict`].

### 2.2 What the tests do not prove

- No test runs `revalidate(after_reorg = true)` or the returned-transaction path at scale, or measures its cost. `mempool_revalidation_cost_per_transaction` measures an **extension**: its comment says "revalidates the whole pool", which predates the extension path. The 6.8 ms figure is from before the extension path existed.
- No test checks the invariant **"every template is a valid block body at tip + 1"**. The conflict tests check only disjointness.
- No test covers a template requested mid-drain (between `sync_step` calls).
- No stateful test mixes admission, extension, reorg, activation and eviction against a real `ChainManager` with a full-validation oracle. The randomized unit test uses synthetic transactions and no chain.
- `proptest` is **not** in `Cargo.lock` (0 entries), and no workspace crate declares it. The existing randomized tests use seeded ChaCha. [source-read]

## 3. Problems in scope

### P1: post-reorg revalidation is unbounded under the chain lock

**Problem and why it exists.**
- After any disconnection, `finish_sync` runs two things (`manager.rs:990-994`):
  - `mempool.add` for every returned transaction;
  - `revalidate(after_reorg = true)`, which runs `validate_mempool_tx` for every v1 transaction and deploy, and `validate_px_without_proof` for PX (`mempool.rs:382-397`).
- That re-runs **every stateless check**: structure, balance and a non-batched BP+ verification (about 3 ms). It also re-runs every CLSAG (about 3 ms per input [est, R12 §1.3]).
- It runs at the end of the drain, inside one lock hold, with no budget. `sync_state` is bounded (`SYNC_STEP_BLOCKS`), but `finish_sync` is not.
- It exists because ring members are global indices. After a reorg an index may resolve to another output, which changes C1 and C3. The code chose full validation as the simple correct answer.

**Cost (my recomputation) [math over measured and estimated unit costs]:**

| Pool content | Transactions | CLSAGs | BP+ | Time under the lock |
|---|---|---|---|---|
| v1, 1-in/2-out (about 1.6 kB) | about 31,000 | 31,000 | 31,000 | about 136-211 s (6.8 ms each) |
| v1, 64-input (about 44 kB) | about 1,130 | 72,500 | 1,130 | about 218 s |
| **PX class, 64-input deploys with a tiny program (about 45 kB)** (new: not in the register) | about 1,490 | about 95,000 | 1,490 | **about 290 s** |
| Returned transactions of a d-block reorg | up to d × (about 380 v1 + 3 PX) | | | adds d × (about 1.3 s + 0.63 s of PX proofs) |

- **Worst case with a full pool: about 500 s under the lock** after *any* reorg, plus the returned transactions.
- **Trigger:** a natural one-block orphan race is enough. The stale rate is 3-12 % per R12, which is 20 to 80 reorgs a day at 720 blocks a day.
- **Filling the pool:**
  - The pool needs valid transactions. On a testnet the UTXOs are free, and fees are paid only for what gets mined: about 0.12 BLK per block of v1 lane, plus the deploy sub-budget.
  - Blocks drain about 1.2 % of a full v1 pool per block, so one fill gives about 85 blocks of exposure.
- **Consequences:**
  - While the lock is held, P2P, RPC and block connection stall.
  - The node falls behind, which raises its own stale rate: a feedback loop.

**Classification.** Liveness and DoS. Not consensus-critical and not privacy-critical, because blocks are always fully validated.

**Prior art.**
- **Monero** keeps per-transaction `max_used_block_height` and `max_used_block_id`, plus a `valid_input_verification_id`. Per the `blockchain.h` documentation, this lets `check_tx_inputs` skip input (ring) verification when the chain state it depends on is unchanged. It also caches failures per tip (`last_failed_id`) and clears its input cache on `on_blockchain_inc` and `on_blockchain_dec` [monero-txpool], [monero-bch]. The underlying idea: re-verify the ring only if what the ring resolves to changed.
- **Bitcoin Core** re-adds disconnected transactions through `AcceptToMemoryPool(bypass_limits = true)`, then `LimitMempoolSize`. The disconnected pool is capped at `MAX_DISCONNECTED_TX_POOL_BYTES = 20 MB`, and the most recent transactions are trimmed first [core-validation], [core-disconnected]. Script checks have their own cache, keyed by the script-execution inputs.
- **Zebra** clears tip-specific rejections on a chain reset and retries all transactions [zebra-spec].

**Proposed solution (policy only): ring-digest reorg revalidation.**
- For each pool entry, store `ring_digest`: a 32-byte hash over the resolved `(one_time_key, commitment)` of every ring member of every input.
  - It is computed at admission, after `validate_mempool_tx` succeeds, with the public `resolve_input_rings` against the same state.
  - Cost: 16 vector lookups plus hashing about 1 kB per input, a few µs.
- After a reorg, for each entry:
  1. `revalidate_after_extension` (C2, C4, PX1-PX4, contract id);
  2. `resolve_input_rings` at the new next height (C1: existence **and maturity**);
  3. recompute the digest.
     - **Equal:** the CLSAG verdict is unchanged. **Exact** [math]: `clsag::verify` is a deterministic function of (message, ring, pseudo-outs, key image, signature). The message depends only on the transaction and the domain, and the domain is unchanged, or `enter_rules` has flushed.
     - **Different:** drop the entry without verifying. A CLSAG that verified over ring R verifies over R′ ≠ R only with negligible probability, because every member is hashed into `mu_P` and `mu_C` (`clsag.rs:85-101`) and into every round challenge.
- **Safety direction.** The pool never keeps an invalid transaction: unchanged digest means the same verdict. The only error mode is dropping a transaction that would still verify. That needs a CLSAG valid over two different rings, and even then it is policy only: the wallet rebroadcasts.
- **Stateless checks** (structure, balance, BP+, PX proof) are **not** re-run. They are functions of the transaction and the rule set, and within one `SigDomain` the rule set is fixed (see M12-8).
- **Resulting cost:** about 5-20 µs per entry, so a full pool takes about 0.2-0.6 s instead of about 500 s.
- **Returned transactions (see P2) must use the same path.**

**Alternatives considered.**
- (a) **Max-index test.** Record the output count at the lowest fork height of the drain. An entry whose maximum ring index is below it is unaffected.
  - O(1) and no hash, but it needs manager plumbing.
  - It is also coarser: honest rings are at least `SPENDABLE_AGE = 10` deep, so reorgs shallower than 10 blocks never touch them. That is the common case, and it makes (a) cheap.
  - Good as a pre-filter inside the digest design, not as a replacement: the digest is self-contained and exact for any depth.
- (b) **Parallel full revalidation** (R12: about 17 s on 8 cores). It is still minutes of CPU and needs a thread pool under the lock. Rejected.
- (c) **Flush the pool on every reorg** (the Zebra-like extreme). Simple, but honest transactions vanish on every orphan race, and every wallet re-stems its transactions, which is a privacy cost (P5).
- (d) **Chunked revalidation with lock releases.** Still minutes of CPU, and templates must stay coinbase-only meanwhile. Rejected as the primary design; the budget idea is kept only as a safety net (W1.4).

**Trade-offs and risks.**
- Memory: 32 B per entry, negligible.
- Correctness depends on "same domain ⇒ same rules" (M12-8) and on `resolve_input_rings` being exactly the C1 used by blocks. It is: blocks call the same function (`validate.rs:1095`).
- If R6 option C (13) changes C4 to a pair key, nothing here changes except the conflict key.

**Tests that prove it.**
- Both existing reorg tests (`revalidation.rs:487, 549`) pass unchanged through the new path.
- New differential test over random reorg sequences: for every entry before and after, `fast_keep(tx) == validate_mempool_tx(tx).is_ok()`.
- Unit tests:
  - a digest change drops the entry;
  - an unchanged digest keeps it without calling `clsag::verify` (counted with a test-only verification counter, or by timing);
  - a cost test with a synthetic pool of 20,000 entries after a reorg stays under 1 s.

**Invariants that must never change.**
- A pooled transaction is valid at tip + 1 whenever no drain is pending.
- Blocks are fully validated regardless of the pool.
- The reorg path checks C1 maturity at the *new* height.

### P2: returned transactions are re-verified in full, and in the wrong order

- `finish_sync` calls `mempool.add` for each returned transaction (`manager.rs:990-992`). That is full `validate_mempool_tx`: BP+, CLSAGs and the **PX proof** (about 0.21 s each).
- **The block already verified all of this under its own rules.** When the block's domain equals the pool's, the stateless checks and the proof are the same (the argument of `validate_block_transactions_cached`, `validate.rs:894-905`).
- When the domains differ, every returned transaction's signature fails. It is verified anyway, to be refused.
- **Order:**
  - Returned transactions are admitted **before** `revalidate` removes stale entries. With a full class they can be refused with `FeeTooLowForFullPool` although room is about to be freed.
  - Bitcoin Core does the reverse: re-add bypassing limits, then trim [core-validation].
- **Fix:**
  - capture `(tx, ring_digest, block domain)` at disconnection in `sync_state`, **before** `undo_block`, while the ring members are still in the state;
  - in `finish_sync`: `enter_rules`, then `revalidate` via the P1 fast path, then drop returned transactions whose block domain is not the pool's (exact, since the signature message binds the branch id), then `readmit`;
  - `readmit` is precheck + the P1 contextual checks + the digest comparison + `insert` with normal eviction.
- The proof of a readmitted PX transaction is then vouched for by `mempool.contains`, which stays sound: it was verified in a connected block under the same domain.
  - Dependency on 35: if replay later trusts the node's own store ("assume-valid"), "connected ⇒ verified" becomes "connected ⇒ verified now or in an earlier session". That is the same trust model, but it must be written down.
  - Dependency on 10: if a `VerifiedProofCache` (R16-8) replaces `mempool.contains`, readmission must insert into that cache.
- **Tests:**
  - a reorg returning PX transactions verifies zero proofs (counter);
  - returned transactions are readmitted into a class that is full of stale entries;
  - returned transactions of another domain are dropped without verification (activation test extended).

### P3: no expiry

- Nothing ever expires. The only exits are mining, conflict, a revalidation failure, eviction, an activation flush or a restart.
- PX transactions have an **implicit** expiry: `ROOT_WINDOW = 100` blocks (`px/src/state.rs:26`) makes PX1 fail within 100 blocks.
- v1 transfers and deploys have none.
- **Consequences:**
  - A standard-fee transfer that never gets selected, for example behind a full pool of equal-rate transactions, keeps its key images locked in every pool until those nodes restart.
  - There is no RBF, so the owner cannot replace it.
  - Diverging pools, where one node holds A and another holds a rival A′ with the same key image, never re-converge.
- **Prior art:**
  - Monero: `CRYPTONOTE_MEMPOOL_TX_LIVETIME = 86400*3` s (3 days), and 1 week for transactions from alternative blocks [monero-config];
  - Bitcoin Core: `DEFAULT_MEMPOOL_EXPIRY_HOURS = 336` [core-options];
  - Zcash: a consensus expiry height (ZIP 203), which BlackSilk has **rejected** because a per-wallet value is a fingerprint (full review, never-change row 29 and I4 §7.1). A policy expiry has no such problem: it is node-local and uniform.
- **Proposal:** a height-based policy expiry `MEMPOOL_EXPIRY_BLOCKS = 2160` (3 days at 120 s blocks, Monero parity), counted from the node's admission height and applied in `finish_sync`.
  - Height rather than time: deterministic, testable, and no clock dependency. The rest of `chain` already takes `now` as a parameter (R13 T-5).
  - Apply it to all classes, for uniformity. PX never reaches it.
- **Privacy interaction** (for 38 and 33): the wallet rebroadcasts unchanged every `PENDING_EXPIRY_BLOCKS = 20` blocks (`wallet.rs:1490`).
  - While a node holds the transaction, the rebroadcast returns AlreadyKnown and nothing is relayed.
  - After expiry network-wide, the origin re-injects it through the stem. Each re-injection is a fresh sample of the same transaction's origin for a stem adversary, the "multiple observations" weakness Dandelion++ discusses [dandelionpp].
  - A long expiry (days) keeps re-injections rare. A short one (hours) would multiply them.
  - I recommend 3 days and ask 38 to confirm the wallet's rebroadcast cadence against it.

### P4: the fee floor is decided only after full verification, with no rolling minimum

- `insert` decides `FeeTooLowForFullPool` (`mempool.rs:302-323`) **after** `validate_mempool_tx` (`mempool.rs:272`) has verified everything, the PX proof included.
- `on_tx` caches nothing for this error (`net.rs:2436`: `(_, Err(_), _) => {}`), so the same refused transaction is fully verified again for every peer that announces it. Up to 72 peers can.
- The fee is public, so the floor can be checked before verification. Bitcoin Core does exactly that: PreChecks → `CheckFeeRate` against the mempool minimum, before script checks [core-validation].
- **No rolling minimum and no incremental fee.**
  - An entry is evicted by any transaction with a strictly higher rate, and 1 atomic unit more is enough.
  - An attacker with K UTXOs can cycle two sets of transactions, each evicting the other at +1 unit, relaying about 50 MB network-wide per round for a negligible fee increase ("free relay").
  - Bitcoin Core raises `rollingMinimumFeeRate` to the evicted rate plus the incremental relay fee, decaying with `ROLLING_FEE_HALFLIFE`, and requires the incremental fee [core-txmempool].
- **Complication specific to BlackSilk.**
  - Honest v1 wallets pay the **exact** standard fee (privacy, R6 §3.3), and PX fees are exact by consensus. So honest users cannot outbid.
  - Under a flood at the standard rate, "strictly cheaper" eviction makes the pool first-come-keeps.
  - **ZIP 401** is the prior art for this regime, where conventional fees replace an auction:
    - cost = max(size, 10,000);
    - a penalty below the conventional fee;
    - **random eviction weighted by cost**;
    - a 60-minute, 40,000-entry recently-evicted set [zip401].
  - This is fee policy (14). I list it as an option, not a decision.
- **Fix now:**
  - a read-only `Mempool::fee_admissible(&tx) -> bool`, the same arithmetic as `insert` without mutation, called in `admit_tx` after the conflict check;
  - `FeeTooLowForFullPool` recorded in a bounded "fee-rejects" set, cleared on every tip change;
  - an incremental margin (policy constant) on eviction.

### P5: templates built mid-drain can hold transactions invalid at that tip

- `submit_block_in_steps` releases the lock between `sync_step`s (`manager.rs:276-287`). `finish_sync` (revalidation and returned transactions) runs only at the end of the drain (`manager.rs:739`).
- Between steps, `template()` (`manager.rs:1247`, reachable by RPC `/template`) selects from a pool that `remove_block` has cleaned of key conflicts, but **not** revalidated for:
  - the PX anchor window (PX1), which moved up to 8 blocks per step;
  - the PX pool (PX4);
  - after a reorg, ring resolution (C1/C3), anchors of the old branch, and deploys of disconnected contracts (PX3).
- The node does not validate its own template (no `TestBlockValidity` equivalent). A miner that finds a block on such a template has it rejected: a lost reward.
- Short windows; low severity. **Fix:** `template()` offers pool transactions only when `!self.sync_pending()`, otherwise coinbase-only. Mining on a mid-drain tip is stale work anyway.
- **Test:**
  - drive `submit_block_bounded` with budget 1 over a reorg;
  - call `template()` between steps;
  - assert that `validate_block_transactions` accepts the template body, or that the template is coinbase-only.

### P6: cluster mempool and package relay

- **Cluster mempool** (Bitcoin Core 31.0, April 2026) linearizes connected components of the parent-child graph: clusters of at most 64 transactions and 101 kvB [core-31]. **Package relay** (BIP 331) exists so that low-fee parents can be carried by a child (CPFP) and to fight pinning [bip331].
- **In BlackSilk every pooled transaction is a singleton cluster** [source-read; math]:
  - v1 rings may reference only chain outputs at least `SPENDABLE_AGE = 10` deep (`validate.rs:416-422`);
  - PX spends need an anchor that is a chain tree root (PX1), and pooled PX outputs are not in the tree;
  - so no pooled transaction depends on another pooled one.
- The single cross-transaction coupling is the PX pool balance (bridge-out against bridge-in), and `select` already simulates it.
- Linearization therefore reduces to a feerate sort, which is what `select` does. RBF pinning does not arise, because there is no RBF.
- **Conclusion:** not relevant now. It becomes relevant only if a future PX design allows spending pooled outputs, and then as a design input, not a copy.

### P7: C4 griefing and conflict keys (owned by 13)

- R6 MP-7 (front-running output keys) is 13's decision. What the mempool needs from it:
  - if option C is adopted, `ConflictKind::OutputKey` becomes a pair key `H(O ‖ Cm)`;
  - the extension and reorg revalidation code needs no change.
- MP-9 (`stem_keys` omits output keys and contract ids) is 33's.

## 4. New findings

| id | Severity | Status | Location | Scenario | Confidence |
|---|---|---|---|---|---|
| **M12-1** (re-rates MP-3, Med → **High for testnet liveness**) | High | Partially implemented (extension path only) | `chain/src/mempool.rs:374-398`; `chain/src/manager.rs:979-995` | Pool filled (testnet coins free) with 64-input v1 transfers and 64-input tiny deploys. The **deploy half is new**: about 95k CLSAGs in the 64 MiB PX class, not counted in the register. Any natural one-block orphan then gives about 500 s under the chain lock. Stateless BP+ is needlessly re-run too. | Medium-high: arithmetic sound; CLSAG unit cost estimated (3 ms/input) from the measured 6.8 ms |
| **M12-2** (extends MP-2 and MP-3) | Medium | Not implemented | `chain/src/manager.rs:913-921, 990-994` | A 20-block reorg with 3 PX transactions per block re-verifies 60 proofs (about 13 s) plus about 7,600 CLSAG/BP+ pairs under the lock. Returned transactions are admitted before stale entries leave, so they are spuriously refused from a full class. Old-domain returned transactions are fully verified only to fail. | High [source-read] |
| **M12-3** | Medium | Not implemented | `chain/src/mempool.rs:272, 302-323`; `p2p/src/net.rs:2410-2437` | Pool full. A valid low-rate transaction, announced by N peers, is fully verified N times and refused each time: no pre-verification floor check, no cache. Separately, eviction needs only a 1-unit higher fee, with no rolling minimum, which allows free relay churn. | High (floor/cache) [source-read]; medium (churn economics) |
| **M12-4** | Low | Not implemented | `chain/src/manager.rs:1247-1264` vs `709-741` | A miner asks for `/template` between drain steps after a reorg. The template holds a PX transaction whose anchor left the window, or a transfer whose ring changed. The found block is rejected. | Medium (source-read, needs the test in P5) |
| **M12-5** (known, "no expiry") | Low | Not implemented | `chain/src/mempool.rs` (no expiry) | A standard-fee transfer behind a full equal-rate pool locks its key images network-wide until restarts. Diverging pools never re-converge. | High |
| **M12-6** | Informational | Complete and verified (by construction) | `tx/src/validate.rs:399-432`; `px/src/state.rs:26` | No in-pool dependencies, so cluster mempool, CPFP and package relay are not applicable (P6). | High [math, source-read] |
| **M12-7** | Low / accepted limitation | Accepted limitation | `chain/src/mempool.rs:306-311` | With exact (privacy) fees, fee-rate eviction degenerates to first-come-keeps under a standard-rate flood. The ZIP 401 random weighted eviction is the prior art (for 14). | Medium |
| **M12-8** | Low | Complete but requires further testing | `chain/src/mempool.rs:183-199`; `tx/src/params.rs:127-135` | `validated_under` compares only `SigDomain`. That equals "same `TxRules`" today, because `fee_per_weight` and `max_block_weight` are constants and branch ids are unique per epoch (`schedule.rs:83`). A future per-epoch fee or weight change would silently keep entries validated under the old limits (T8) and the old template weight. No test or assert pins the equivalence. | High |
| **M12-9** | Low | Not implemented | `chain/src/manager.rs:991` (`let _ = ...`), `revalidate` | No metrics: revalidation time, drops by reason, returned-transaction outcomes and expiries are invisible to operators. A multi-minute stall (M12-1) would appear only as lag. | High |
| **M12-10** (confirms MP-4) | Informational | Accepted limitation | `chain/src/mempool.rs:283` | Caps count encoded bytes; the decoded size is 2-4.5× (R12: 190-225 MB for 50 MB). Bounded, so it is informational. | Medium |
| **M12-11** | Low | Not implemented | `chain/tests/manager.rs:1010-1047` | The test called "revalidation cost" measures the extension path, and its comment ("revalidates the whole pool ... in full") is stale. The only 6.8 ms anchor is from before the extension path, and the reorg-path cost has never been measured. | High |

I checked for a mempool-induced consensus split and found none: every block is validated in full. I also checked the proof-cache soundness (`mempool.contains` gated on `same_rules`) and agree with R12 and R16-8 that it is sound today.

## 5. Implementation plan for phase 2

All items are **policy only**: no consensus change and no identity impact.

**W1 (P0): ring-digest reorg revalidation** (M12-1). Difficulty M.
- **Files:** `chain/src/mempool.rs` (owner 12). It needs a policy-only hash tag in `crypto/src/hash.rs`, for example `mempool/ring-digest`, one line (owner 19, coordinate).
- **Steps:**
  1. Add `Entry { ring_digest: [u8; 32], admitted_height: u64 }`, filled in `add` after validation, via `resolve_input_rings` over `Transfer`, `PxTx` or `PxDeploy` inputs.
  2. Add `revalidate(.., after_reorg = true)`: `revalidate_after_extension` + C1 re-resolution at `height` + digest comparison. Drop on mismatch.
  3. Optional pre-filter: skip resolution when the maximum ring index is below the fork output count (needs one field from the manager).
  4. Safety net: if more than `REORG_REVALIDATE_MAX` entries changed (for example 5,000), drop the excess instead of verifying. No CLSAG runs in this path at all.
- **Tests:**
  - the existing `revalidation.rs` reorg tests unchanged;
  - new unit tests (digest change drops, unchanged keeps, activation still flushes);
  - differential test W6;
  - cost test: 20k synthetic entries in under 1 s.
- **Bench:** a reorg-revalidation timing test (prints µs per entry).
- **Docs:** `docs/blocks.md` §7 (revalidation bullets); the `mempool.rs` module docs.

**W2 (P0): returned-transaction readmission** (M12-2). Difficulty S-M.
- **Files:** `chain/src/manager.rs`: `SyncOutcome.returned` becomes `(tx, digest, domain)`, computed in the disconnect loop at 913-921 before `undo_block`; `finish_sync` reordered. `chain/src/mempool.rs`: `readmit`.
- **Ownership:** `manager.rs` is shared with 02, 34 and 35. The edits are confined to `SyncOutcome`, the disconnect loop body and `finish_sync`.
- **Tests:**
  - a reorg returning PX transactions verifies no proof (a counter behind `cfg(test)`, or timing);
  - readmission into a full stale class;
  - old-domain returned transactions dropped unverified (extend `chain/tests/activation.rs`);
  - `transactions_survive_reorgs_via_the_mempool` stays green.
- **Docs:** `blocks.md` §7.

**W3 (P1): fee-floor pre-check, fee-reject cache, incremental eviction margin** (M12-3). Difficulty S.
- **Files:** `chain/src/mempool.rs` (`fee_admissible`, `MEMPOOL_INCREMENTAL_RATE`); `p2p/src/net.rs` `admit_tx`, `on_tx` (owner 33/31, a small insertion after the conflict check, plus a `fee_rejects` set cleared on tip change).
- **Tests:**
  - unit: `fee_admissible == insert would succeed` over random full pools (property);
  - p2p: a refused-for-fee transaction announced by 3 peers is verified once.
- **Docs:** `docs/p2p.md` §10, `blocks.md` §7.

**W4 (P1): no pool transactions in templates while a drain is pending** (M12-4). Difficulty S.
- **Files:** `chain/src/manager.rs` `template()`.
- **Test:** bounded drain over a reorg, with the template validated between steps.
- **Docs:** `blocks.md` §7.

**W5 (P1): height expiry** (M12-5). Difficulty S.
- **Files:** `chain/src/mempool.rs` (`MEMPOOL_EXPIRY_BLOCKS = 2160`, `expire(height)`); `manager.rs` `finish_sync` (one call).
- **Tests:** expiry at exactly N; readmission after expiry; PX unaffected.
- **Docs:** `blocks.md` §7 ("Not implemented" line). Coordinate the value with 38.

**W6 (P0, with 41): stateful differential test against a real manager.** Difficulty M.
- **Files:** new `chain/tests/mempool_stateful.rs` (owner 12). Seeded ChaCha, following the existing style; `proptest` only if 41 and 44 approve the new dev-dependency.
- **Operations:** submit (valid, conflicting, low fee), mine on tip, mine a rival branch (reorg of depth 1 to 15, including a shorter-heavier one), `template()`, activation (regtest two-epoch), restart.
- **Oracles after each operation:**
  - every pooled transaction passes `validate_mempool_tx` at tip + 1;
  - the template body passes `validate_block_transactions`;
  - conflict and byte invariants hold (reuse `assert_invariants`);
  - the fast-path verdict equals full validation for every entry.
- **Budget:** runtime under 60 s in CI (regtest ZeroPow).

**W7 (P2): observability** (M12-9). Difficulty S.
- **Files:** `chain/src/mempool.rs` (a `RevalidationReport` returned by `revalidate` and `readmit`); `manager.rs` logs it at `info` when anything is dropped or the pass takes more than 100 ms.
- Exposure in `/info` belongs to 36 (`rpc` struct change).

**W8 (P2): M12-8 pin.** Difficulty S.
- **Files:** `chain/src/mempool.rs`: store the full `TxRules` (or a digest of it), not only `SigDomain`, in `validated_under`. Alternatively a unit test asserting `at_height` differs across epochs only in `branch_id`.

**W9 (P2): fix the stale cost test** (M12-11). Difficulty S.
- **Files:** `chain/tests/manager.rs` 1010-1047 (comment and name); the reorg timing moves into W1.

**W10 (P3): eviction policy research** with 14.
- ZIP 401-style random cost-weighted eviction versus the rate floor under exact fees. An ordered per-class index to make eviction and `select` O(k log n).
- Decoded-size accounting (M12-10).

**Order:** W1 → W2 → W6 (it gates W1 and W2) → W4 → W3 → W5 → the rest.

## 6. Dependencies and conflicts

- **02** (fork choice): W2 touches the `sync_state` disconnect loop. Behaviour is identical apart from computing digests.
- **10** (validation pipeline and proof cache): readmission relies on "connected ⇒ proof verified". If `VerifiedProofCache` replaces `mempool.contains`, W2 inserts into it.
- **11** (`tx/src/validate.rs` owner): W1 uses only public functions; I propose no change to `validate.rs`. If 11 prefers, a `revalidate_after_reorg` helper can live there instead.
- **13** (C4): option C changes `ConflictKind::OutputKey` to a pair key. Independent of W1-W5.
- **14** (fees): R12-2 (deploy/PX v1-input cost) directly bounds the M12-1 worst case. The W3 margin and W10 eviction policy are fee policy.
- **19** (hash domains): one policy tag for the ring digest.
- **33** (Dandelion): stem keys (MP-9); the rebroadcast-after-expiry privacy note; W3's edits in `net.rs`.
- **34** (actor): W1 makes the post-reorg pass cheap enough to stay in the writer. Two-phase admission (R-MP1) is 34's. The mempool API should keep `check` pure (it is).
- **35** (storage): assume-valid replay changes the "connected ⇒ verified" premise of W2 (same trust model; document it).
- **36** (RPC): metrics in `/info`.
- **38** (wallet privacy): expiry versus the 20-block rebroadcast cadence.
- **41** (stateful testing): W6 is a stateful test they may want to generalize; `proptest` adoption.

## 7. Open questions for the coordinator

1. Do you accept re-rating MP-3 to **High (testnet liveness)** and W1/W2 as **P0**? The fix is policy-only and small; the exposure is any orphan race with a full pool.
2. On a ring-digest mismatch: drop without verifying (my recommendation, sound and O(1)), or re-verify (exact, but restores the CPU lever)?
3. Expiry: 3 days (Monero parity) or something else? Should it apply to all classes?
4. Is `proptest` allowed as a new dev-dependency, or do we stay with seeded ChaCha loops?
5. Should the ring-digest tag go in `crypto/src/hash.rs` (19's registry), or use a local constant in `chain` (not consensus)?
6. Should eviction under exact fees move toward ZIP 401 (randomized)? That is a 14 / owner decision.

## 8. Sources

- [monero-txpool] Monero `src/cryptonote_core/tx_pool.cpp` (`is_transaction_ready_to_go`, `check_tx_inputs` with `valid_input_verification_id`, `m_input_cache`, `on_blockchain_inc/dec`, `remove_stuck_transactions`): https://github.com/monero-project/monero/blob/master/src/cryptonote_core/tx_pool.cpp
- [monero-bch] Monero `src/cryptonote_core/blockchain.h` (`check_tx_inputs` documentation: `max_used_block_id`, `valid_input_verification_id_inout`): https://github.com/monero-project/monero/blob/master/src/cryptonote_core/blockchain.h
- [monero-config] Monero `src/cryptonote_config.h` (`CRYPTONOTE_MEMPOOL_TX_LIVETIME` = 3 days, the alt-block livetime of 1 week, `DEFAULT_TXPOOL_MAX_WEIGHT`, `CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE = 10`): https://github.com/monero-project/monero/blob/master/src/cryptonote_config.h
- [core-options] Bitcoin Core `src/kernel/mempool_options.h` (`DEFAULT_MAX_MEMPOOL_SIZE_MB = 300`, `DEFAULT_MEMPOOL_EXPIRY_HOURS = 336`, incremental relay fee): https://github.com/bitcoin/bitcoin/blob/master/src/kernel/mempool_options.h
- [core-txmempool] Bitcoin Core `src/txmempool.cpp` (`GetMinFee`, `ROLLING_FEE_HALFLIFE`, `TrimToSize`/`trackPackageRemoved`, `Expire`): https://github.com/bitcoin/bitcoin/blob/master/src/txmempool.cpp
- [core-validation] Bitcoin Core `src/validation.cpp` (`MaybeUpdateMempoolForReorg` with `bypass_limits = true` then `LimitMempoolSize`; PreChecks fee-rate check before script checks): https://github.com/bitcoin/bitcoin/blob/master/src/validation.cpp
- [core-disconnected] Bitcoin Core `src/kernel/disconnected_transactions.h` (`MAX_DISCONNECTED_TX_POOL_BYTES = 20 MB`, trimming policy): https://github.com/bitcoin/bitcoin/blob/master/src/kernel/disconnected_transactions.h
- [core-31] Bitcoin Core 31.0 release notes (cluster mempool: clusters of at most 64 transactions and 101 kvB, ancestor/descendant limits removed; 19 April 2026): https://bitcoincore.org/en/releases/31.0/
- [bip331] BIP 331, Ancestor Package Relay: https://github.com/bitcoin/bips/blob/master/bip-0331.mediawiki
- [zip401] ZIP 401, Addressing Mempool Denial-of-Service (cost function, random weighted eviction, recently-evicted set): https://zips.z.cash/zip-0401
- [zip203] ZIP 203, Transaction Expiry: https://zips.z.cash/zip-0203
- [zebra-spec] The Zebra Book, Mempool Specification (reset handling, eviction memory, rejection lists): https://zebra.zfnd.org/dev/mempool-specification.html
- [dandelionpp] G. Fanti et al., "Dandelion++: Lightweight Cryptocurrency Networking with Formal Anonymity Guarantees", SIGMETRICS 2018, arXiv:1805.11060: https://arxiv.org/abs/1805.11060
- [clsag] B. Goodell, S. Noether, A. Blue (RandomRun), "Concise Linkable Ring Signatures and Forgery Against Adversarial Keys", ePrint 2019/654: https://eprint.iacr.org/2019/654 (for the argument that the ring is bound into the aggregation coefficients and challenges)
