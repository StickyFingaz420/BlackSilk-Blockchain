# 02 fork-choice-reorgs: research dossier (phase 2, phase 1)

Internal engineering research, not an audit. Read-only on the repository. No builds or
tests were run by this agent. Every "tested" claim names an existing test that I read
but did not run.

Commit: `9e422d8` (`rebuild/core`, `git rev-parse --short HEAD`).

---

## 1. Scope and what I read

**Code (read in full):**
- `chain/src/manager.rs` (1,459 lines): `CachedPow`, `submit_block_in_steps`,
  `open`/`replay`/`replay_one`, `submit_inner`, `drain_ready`, `header_added`,
  `keeps_body`, `mark_complete`, `recompute_target`, `invalidate`, `fork_height`,
  `sync_state`, `finish_sync`, `accept_headers`, `missing_bodies`, `template`,
  `template_on`, and the two in-file tests on the bounded API.
- `consensus/src/chain.rs` (`HeaderChain`: `accept`, `switch_to`, `mark_invalid`,
  `check_rules`, `precheck_batch`, `seed_id_for`, `ancestor_id`).
- `tx/src/validate.rs` lines 880–1130 (`validate_block_transactions_cached`, PX5 skip
  and its soundness argument), 505–600 (`check_px_state`, `check_px_proof`).
- `tx/src/state.rs` 150–260 (`apply_block`, `undo_block`); `px/src/state.rs::undo`.
- `chain/src/mempool.rs` (`validated_under`, `enter_rules`, `add`).
- `p2p/src/net.rs`: module docs, `lock_or_exit`, `on_get_blocks`, the `NotFound`
  handler, `block_worker` (1918–1996), `schedule_downloads` (2000–2031),
  maintenance timeouts (2670–2715), tip announcement (2641).
- `node/src/lib.rs` `/template`, `/block` handlers (grep-level).

**Tests (read):** `chain/tests/fork_choice.rs` (all 9), `chain/src/manager.rs` tests (2),
`chain/tests/activation.rs` (2), `chain/tests/manager.rs` (list + `mempool_contents_never_change_a_blocks_verdict`),
`chain/tests/storage_recovery.rs` and `revalidation.rs` (test list), `p2p/tests/withheld_body.rs`,
`consensus/src/chain.rs` tests (list).

**Docs and reports:** `docs/reviews/full-review-2026-09-27.md` (§1, §3.1, register rows
R1-C1/C4/C5/C12/H1, §5 P0-7/P1-13/P3-9, §8), `docs/reviews/autonomous-session-2026-09-27.md`,
`docs/reviews/k4-reorg-policy.md`, R1 (§3.5, §4.2–4.5, V8, V12), SX2 (R8-1, R10-1 notes),
R10, R12 (§10, reorg revalidation, CLSAG cache caveat), R13 (T-4/T-5 model checking),
R16 (R16-7 scenario), `docs/blocks.md` §6 and §8, `docs/consensus.md` §8–§9, the roster
entries 01, 03, 07, 10, 31, 34, 35, 41, 42, 50.

---

## 2. Current state

### 2.1 What exists

| Mechanism | Where | Evidence class |
|---|---|---|
| Header tree with first-seen ties, strictly-greater switch, invalidity propagated to descendants | `consensus/src/chain.rs:492-565` | tested: `heavier_fork_reorgs_and_lighter_fork_does_not`, `invalidating_a_block_falls_back_to_best_remaining_branch`, `verdicts_do_not_depend_on_arrival_order` |
| Header validity depends only on ancestors | `chain.rs:309-358, 470-488` | source-read; tested: `precheck_agrees_with_sequential_validation_and_computes_no_pow` |
| Connection target = most-work **body-complete** valid block; strictly greater to move; ties keep the connected tip, else earliest completion | `manager.rs:794-815` | tested: `a_late_equal_work_body_does_not_reorg`, `waiting_siblings_complete_in_body_arrival_order` |
| Completion order = body arrival order (min-heap on `body_seq`), sync after each completion | `manager.rs:700-741` | tested: `replay_reproduces_live_fork_choice_exactly` (16 random delivery orders, headers-first or not, 2 restarts) |
| Replay = live (storage order), except documented orphan case | `manager.rs:376-463` | tested: same, plus `siblings_stored_before_their_parent_replay_in_storage_order`, `replay_skips_descendants_of_an_invalid_block_stored_before_it` |
| Withheld body can no longer stall (H1) | `manager.rs:1-24, 1087-1120` | tested: `a_withheld_body_cannot_stall_block_production`, `p2p/tests/withheld_body.rs` |
| Invalid body → block and descendants dropped, target recomputed, old chain reconnected | `manager.rs:820-851, 960-963` | tested: `candidates_by_complete_work_with_invalid_bodies_on_both_sides`, `invalid_side_branch_body_is_rejected_when_it_would_win` |
| Bounded drain: at most `budget` validations per call, never stops at a lighter tip, same final chain | `manager.rs:255-288, 580-600, 879-926` | tested: `bounded_submission_reaches_the_unbounded_result_in_bounded_steps`, `a_bounded_reorganization_never_stops_on_a_lighter_tip` |
| Low-work body policy (margin 100 blocks at tip difficulty, or on path to a heavier header tip) | `manager.rs:184-194, 773-789` | tested: `low_work_side_branch_bodies_are_not_kept_but_candidates_always_are` |
| No depth limit (K4), WARN at depth ≥ 10, `deepest_reorg` counter | `manager.rs:179-182, 902-912` | source-read |
| Mempool effects applied once per drain; flush on rule-domain change | `manager.rs:969-995`, `mempool.rs:183, 261` | tested: `transactions_return_to_the_mempool_across_a_body_complete_reorg`, `transactions_returned_across_the_activation_are_revalidated_under_the_new_rules` |
| PX5 skipped for pooled transactions only under the same rule domain | `manager.rs:939-953`, `validate.rs:894-1129` | tested: `mempool_contents_never_change_a_blocks_verdict` (v1 only); PX-proof skip under reorg not tested |
| Full undo in RAM; symmetric `undo_block` | `tx/src/state.rs:159-256`, `px/src/state.rs:150-157` | source-read; shallow reorg tests only (R1 V12) |

### 2.2 What is correct and well designed (my assessment)

1. **The body-complete rule is Bitcoin Core's rule.** Core's `setBlockIndexCandidates`
   only contains blocks whose whole ancestry has data (`HaveNumChainTxs`), and
   `nSequenceId` is assigned when a block becomes linkable (in `ReceivedBlockTransactions`),
   so ties go to the first *completed* block, as here. BlackSilk's rule is the
   established one, not a novelty [source-read here; Core code recalled from
   `validation.cpp`, the commit history cited in §8].
2. **Restart determinism is stronger than Core's.** Core kept `nSequenceId` in memory only,
   so equal-work ties could flip on restart until PR #29640 (merged 2025-10-27) gave the
   previous best chain `SEQ_ID_BEST_CHAIN_FROM_DISK`. BlackSilk reproduces the whole
   completion order from the append-only storage order, and tests it with random
   delivery orders. [tested: `replay_reproduces_live_fork_choice_exactly`]
3. **"Never release the lock at a lighter tip"** is exactly Core's `ActivateBestChainStep`
   invariant (sipa, commit `4e0eed8`: "We're in a better position than we were. Return
   temporarily to release the lock"). BlackSilk uses `>= floor` where Core uses `>`; both
   are safe (readers never see a lighter tip). [source-read]
4. **PX5 cache soundness.** The skip covers only the proof (not PX1–PX4, rings, BP+),
   is keyed by the full tx id, and is gated on the pool's rule domain, so a reorg or
   activation cannot turn a stale pool verdict into acceptance. R12's warning (do not
   extend the mempool shortcut to CLSAGs, whose rings resolve differently per branch) is
   correct and is respected by the code. [source-read; argument in `validate.rs:894-905`]
5. **Invalid-marking cannot be triggered by body malleation**, because the header's
   `tx_root` commits to tx ids that cover every byte, with no CVE-2012-2459 duplication
   (R1 V4, V9; `chain/tests/block_malleability.rs`). A store I/O failure returns before
   any validation, so it never marks a block invalid. [source-read]

### 2.3 What the tests do NOT prove

- No property or model test over *arbitrary* trees: `replay_reproduces_live_fork_choice_exactly`
  uses one fixed tree with 16 orders. Nothing checks the target invariant after every
  step. [unknown beyond that tree]
- No test of a reorg across an activation **downward** (from above to below the
  activation height), and no test of the PX5 cache during a reorg. [not tested]
- No deep reorg with PX transactions (R1 V12, K4 §7). [not tested]
- No test of download scheduling with a withheld *deep* heavier branch (F-1). [not tested]
- No test of how many verifications a failed reorg costs (F-2). [not tested]

---

## 3. Problems in scope (the roster's questions)

### 3.1 Edge cases of the body-complete most-work rule

**Ties.** Correct and deterministic. One deviation from "earliest completion wins":
after a failed reorg, `recompute_target` keeps the current tip if it has the maximum work,
even when it is the attacker's equal-work prefix and not the first-completed block (F-4).
Bitcoin Core would return to the earliest `nSequenceId`. Impact: nil in practice (the
attacker pays a full PoW block for the invalid child and would do better publishing a
valid one), but the spec wording is inexact. Zebra instead breaks ties by tip hash
(RFC 0005). That is deterministic across nodes, but it gives the lowest-hash block the
win, which changes the selfish-mining γ. The literature (Eyal–Sirer; "The Power of Random
Symmetry-Breaking in Nakamoto Consensus") shows that the tie rule is a γ lever.
**Keep first-seen** (never-change list §8 item 2).

**Invalid bodies.** Correct. Two costs:
- **Unbounded lock hold during a reorg.** The "never lighter" rule means that a reorg of
  depth D validates at least about D blocks in one lock hold, whatever the budget
  (`manager.rs:923`).
- **Full re-validation on reconnect.** If the new branch fails, the old chain is
  reconnected with full verification. Validity depends only on ancestors, so this repeat
  is provably unnecessary (F-2).

**Deep reorgs.** Functionally supported (undo for every block in RAM). Only shallow PX
reorgs are tested. The undo stores the PX frontier and the root window per block
(`px/src/state.rs:150-157`), so a deep reorg is O(D) with small constants. The concern is
memory (PX-F2), not correctness.

**Replay order.** Correct by construction and tested. The one divergence is documented:
a stored block whose parent was never stored in the same session. Second-order effect:
such a child is appended twice, so the store grows slightly. Harmless.

**Low-work margin of 100.** Policy only; it cannot refuse an honest candidate. The code
keeps every block on the path to *any* valid leaf with more work than the tip, not only
the header-best leaf. Useful invariant, not yet asserted: **everything `missing_bodies`
returns, `keeps_body` keeps** (the doc states it, and the test implies it only for the
tested tree). The margin's only real function is supporting locally mined deep side
branches in tests; docs/blocks.md §8 already says a smaller margin is a later tuning
decision. Compare Core's `AcceptBlock`: an *unrequested* block is processed only if it has
at least the tip's work, is not more than 288 blocks ahead, and is above
`MinimumChainWork`. BlackSilk's P2P drops unrequested unknown-header bodies before this
point (`net.rs:1933-1941`), so the margin matters only for RPC `/block` submissions and
requested blocks. No change needed.

**Download completeness (new).** `missing_bodies` lists the heavier candidates, but the
list is **sorted by height and truncated to 256**. `schedule_downloads` then assigns ids
to *any* peer whose claimed height is high enough, not to peers that announced that
branch. A deep withheld heavier branch therefore crowds out an honest candidate
completely (F-1). Bitcoin Core avoids this by construction: `FindNextBlocksToDownload`
asks a peer only for blocks on *its own* `pindexBestKnownBlock` chain, and stalling peers
are disconnected. The same flaw is documented in another node implementation
(btclib-node #1179).

### 3.2 Should deep-reorg finality (a halt flag) exist?

**Prior art:**

| Project | Mechanism | Behaviour past the limit | Criticism |
|---|---|---|---|
| Bitcoin Core | none (historic checkpoints; `assumevalid` and `minimumchainwork` are sync shortcuts, not finality) | follows most work | — |
| zcashd | `MAX_REORG_LENGTH = 99` (= coinbase maturity − 1), PR #2463 | **shuts down** with a fork report; the override flag was deliberately removed, so the fix is a new release | turns a majority attack into a network-wide halt; ties fork resolution to releases |
| Zebra | finalized/non-finalized split; `MAX_BLOCK_REORG_HEIGHT` raised 99 → 1000 in 5.2.0 (2026-06-19) "to respond to a sustained consensus split" | blocks below the window are committed to RocksDB; deeper reorgs are impossible for that node | a long partition becomes permanent without operator action |
| Bitcoin ABC 0.18.5 | `-maxreorgdepth=10` rolling finalization; `parkblock`/`finalizeblock` RPCs; a penalty on deep forks | refuses (parks) | classic split-by-partition criticism; nodes offline during the attack follow a different chain |
| Monero | no limit; emergency DNS checkpoints since 2014; after the 18-block Qubic reorg (2025-09-14), issue #10064 proposes *temporary rolling DNS checkpoints* (3 of 4 records must agree) | checkpointed history is fixed | "nodes would temporarily no longer follow the chain with the most proof of work"; trust in the DNS publishers |
| Academic | Karakostas & Kiayias, ePrint 2020/173: checkpointing protects against majorities but needs a trusted or federated checkpointer | — | the trust assumption |

**Analysis for BlackSilk:**
- K1 is unattainable against JIT rx/0 miners (R1-C2). A depth limit is the only thing
  that bounds rewrite damage for nodes that stay online.
- Its costs:
  - a permanent split under partition (K4 §2);
  - a halt DoS: a majority burst stops every online node;
  - history dependence: a node's verdict depends on when it was online, which breaks
    "validation depends only on ancestors" as a *node* property (not a validity rule).
- It also enables a bounded undo window (PX-F2 structurally, R1 §4.3).

**Recommendation:**
1. Implement a **policy-only "park" (halt-to-operator) mode**, not a silent refusal and
   not a shutdown. Past `max_reorg_depth` the node:
   - keeps its current chain;
   - stops serving templates (the miner stops);
   - raises an ERROR plus a `/info` field;
   - accepts the reorg only on an explicit operator action (`--accept-reorg <block id>`
     or an RPC).

   This is ABC's park/finalize idea without automatic finalization, and zcashd's report
   without its forced release.
2. **Default: disabled for the seven-device trial**, which keeps the owner-accepted K4.
   **K = 720** is the proposed default for a public testnet, matching the wallet's
   720-id window and R1 §4.3.
3. **Do not prune undo on the strength of the flag.** An override must remain possible,
   so an override deeper than the kept undo re-replays from `blocks.dat` (storage
   workstream 35).
4. Owner decision required (open question Q1).

### 3.3 How Bitcoin Core, Zebra and Monero handle the rest

- **Bitcoin Core:** see above.
  - `ActivateBestChainStep` disconnects everything to the fork at once, then connects in
    batches of 32 (`nTargetHeight = std::min(nHeight + 32, …)`), releasing `cs_main`
    only once the tip has more work than the old tip.
  - On failure: `InvalidChainFound`, `BLOCK_FAILED_CHILD` on descendants,
    re-select by (work, `nSequenceId`).
  - Reconnect cost is cut by the signature and script-execution caches.
  - The operator has `invalidateblock`, `reconsiderblock` and `preciousblock`.
- **Zebra:** each non-finalized fork is a `Chain` holding its own UTXO, nullifier and
  tree state. Switching to an already-verified fork needs **no re-validation and no
  undo**. Ties are broken by hash.
- **Monero:** `Blockchain::switch_to_alternative_blockchain` pops blocks and validates
  the alternative chain. If the alternative fails, it rolls back and re-adds the
  original blocks. Alternative blocks are kept in the DB. (This point comes from my
  knowledge of the monerod source; I did not fetch it this session, so it counts as
  assumed.)

### 3.4 Per-problem answers (brief's template)

For F-1…F-5 in §4: problem and root cause, consequence, class, literature, trade-offs,
tests and invariants are given inline there. Invariants that must never change (all
problems):
- **INV-1:** strictly-greater cumulative work (u128 sum of header difficulties) moves the
  chain; ties never move it.
- **INV-2:** validity depends only on the block and its ancestors; invalidity propagates
  to all descendants.
- **INV-3:** the state equals the ordered application of `connected[1..]`.
- **INV-4:** replay of the store reproduces the live tip, state and tie decisions.
- **INV-5:** the lock is never released at a tip lighter than the one held when the
  operation began.
- **INV-6:** no depth limit is a *validity* rule; any limit is node policy (docs must say
  so).
- **INV-7:** the PX5 skip is gated by the full tx id **and** the rule domain; never
  extend it to CLSAG or BP+ without a (tx, resolved ring) key (R12-12).

---

## 4. Findings

### F-1: Download starvation by a deep withheld heavier branch
- **Severity:** Medium (liveness, public network). Low for the 7-device explicit-peer
  trial.
- **Status:** Not implemented.
- **Where:** `chain/src/manager.rs:1087-1120` (`missing_bodies`: main-chain scan from
  the fork first, then other heavier leaves, `sort_by_key(height)`, `truncate(max)`);
  `p2p/src/net.rs:2000-2031` (`schedule_downloads(…missing_bodies(256))`, peers chosen by
  `p.height >= height`, `break` when no candidate); `NotFound` handler at `net.rs:1308-1320`
  (no memory of "peer lacks it").
- **Scenario:**
  1. An attacker mines a branch B forking about 300 blocks below the tip, with slightly
     more cumulative work than the honest chain. Only headers are published; bodies are
     withheld and can be anything.
  2. B becomes header-best. `missing_bodies(256)` returns B's 256 lowest missing blocks,
     all below the honest candidate C (a new honest block at tip+1, heavier than the
     connected tip).
  3. C is truncated away and never requested. Honest peers asked for B's bodies answer
     `NotFound` and are asked again. The attacker's peer times out after 60 s.
  4. Each honest node now only connects the blocks of its own local miner (H1 keeps that
     working), so honest hash power fragments into per-node chains.
  5. To keep B heavier than every node's view, the attacker only has to out-mine the
     **largest single honest miner**, not the whole network.
- **Precondition:** a one-time majority-work burst of about 256 blocks, cheap on a
  young testnet per R1-C2.
- **Confidence:** high on the mechanism (code read line by line); medium on
  practicality. Not reproduced: no builds in phase 1.
- **Class:** policy/P2P liveness. Not consensus-critical and not privacy-critical.
- **Prior art:** Core's per-peer `FindNextBlocksToDownload` (ask a peer only for its own
  announced chain), plus stalling-peer disconnection; btclib-node #1179 documents the
  same flaw.
- **Fix:**
  - (a) `missing_bodies` reserves slots per candidate leaf: round-robin over candidates
    ordered by work, lowest missing height first within each, so no candidate is starved.
  - (b) A new `missing_bodies_toward(tip, max)` lets P2P request only blocks on the
    chain a peer announced (31 owns per-peer `best_known`).
  - (c) Optionally, deprioritize a candidate whose bodies drew `NotFound` from every
    announcing peer.
- **Trade-offs:** more bookkeeping in P2P, and slightly slower IBD if the per-peer
  targeting is too strict (a fallback to any peer is needed for IBD).
- **Tests:**
  - chain unit: a deep heavier withheld B (300) plus honest C at tip+1 →
    `missing_bodies(256)` contains C's block;
  - property: every heavier candidate is represented;
  - p2p integration: a withholding peer with a deep branch; honest nodes still converge
    on each other's blocks.

### F-2: The reorg lock hold is bounded only by reorg depth; a failed reorg re-verifies the old chain
- **Severity:** Low. Medium while R12-2 (about 25–50 s per worst-case block) is open.
- **Status:** Partially implemented (the bounded API exists but does not bound reorgs).
- **Where:** `manager.rs:923-926` (the budget is ignored while `work(tip) < floor`),
  913-921 (disconnects), 960-963 plus loop (reconnection validates in full); `p2p` module
  docs at `net.rs:10-11` claim bounded steps.
- **Scenario:**
  1. The attacker publishes B1..BD, expensive to verify, then B(D+1) with valid PoW and
     an invalid body at PX5, the last check.
  2. The victim disconnects D blocks and validates D+1 new blocks in **one** lock hold.
  3. It then re-validates D old blocks to reconnect, still in the same hold.
  4. Cost: about 2D+1 full validations per attack, where an honest reorg costs D.
- **Confidence:** high (source-read).
- **Class:** liveness and architecture.
- **Prior art:**
  - Core has the same lock rule but cheap reconnects (the signature and script
    caches);
  - Zebra keeps verified forks' state, so a switch needs no re-validation.
- **Fix (non-consensus, not externally visible):**
  - keep `validated: HashSet<Hash>` of blocks that passed body validation once;
  - in `sync_state`, a block in the set is applied without re-verification (sound by
    INV-2: same block id ⇒ same header ⇒ same ancestors ⇒ same parent state ⇒ same
    verdict);
  - clear it for invalidated blocks.

  This removes the reconnect half and also speeds reorgs back to a previously seen
  branch (flip-flop partitions). Longer term, off-lock pre-verification belongs to
  34/10.
- **Trade-offs:**
  - 32 B per block;
  - a bug in apply-without-validate would be a consensus divergence, hence the
    differential tests below;
  - `apply_block` panics on PX rule violations, which gives a fail-stop backstop.
- **Tests:**
  - a counting verifier (a wrapper PowFunction is not enough; count through a test hook
    or measure `validate` calls): reconnect after a failed reorg performs 0 body
    validations;
  - differential: random trees with and without the cache reach identical
    `connected`, state digest and `invalid` sets.
- **Docs:** state in `docs/p2p.md` §6 and `blocks.md` §6 that the step bound does not
  hold during a reorg until the new branch outweighs the old tip (Core-equivalent).

### F-3: Templates are served from an unrevalidated pool mid-drain, and during IBD
- **Severity:** Low. **Status:** Not implemented.
- **Where:** `manager.rs:1247-1277` (`template` uses the pool when the rule domain
  matches); `finish_sync` (979-995) runs only when the drain ends; `node/src/lib.rs:199-203`
  serves `/template` unconditionally.
- **Scenario:** between bounded steps of a reorg, the pool still holds transactions that
  spend outputs of disconnected blocks, or reference PX anchors only on the old branch.
  A miner template contains them, so the miner hashes an invalid block, which is
  rejected on submit. The pause is short (1 ms sleeps plus steps), so the impact is
  wasted work. During IBD, templates on a stale tip create low-work forks.
- **Fix:**
  - `template()` offers `txs = []` while `sync_pending()`;
  - optionally, the node reports "syncing" and withholds templates below a
    minimum-work or header-lag threshold (owned by 09/31; R1 §4.3 `MIN_CHAIN_WORK`).
- **Tests:** a unit test that a template taken mid-drain is valid when mined.
- **Confidence:** high.

### F-4: Tie retention after a failed reorg
- **Severity:** Informational. **Status:** Accepted limitation (document it).
- **Where:** `manager.rs:808-815`.
- **Scenario:** tip A1 (first seen). The attacker sends B1 (valid, equal work) and B2
  (invalid body, valid PoW). The reorg to B2 fails at B2, the tip rests at B1, and
  `recompute_target` keeps B1 (the tip, tied) instead of A1. This is deterministic and
  replays identically. It deviates from Core's earliest-`nSequenceId` choice, but it
  gives the attacker nothing beyond publishing a valid B2.
- **Fix:** documentation only (blocks.md §6: "after a body failure, the connected tip
  stays if it ties the maximum").
- **Test:** pin the behaviour in `fork_choice.rs` so any future change is deliberate.

### F-5: Stale or over-strong statements in the specifications
- **Severity:** Low (docs). **Status:** Not implemented.
- **Where:**
  - `docs/consensus.md` §8: "The node applies it atomically to transaction state". Not
    true since the bounded drain: the lock is released between steps, and the mempool
    is updated at the end of the drain.
  - Same section: "honest nodes always converge". Conditional on F-1.
  - blocks.md §6 tie wording (F-4).
  - `net.rs` module docs: "bounded steps" (F-2).
- **Fix:** doc edits (coordinate with 47).

### F-6: Candidate walks are O(leaves × depth) and not memoized
- **Severity:** Low. **Status:** Not implemented.
- **Where:** `manager.rs:1104-1116` (the `seen.insert` check does not stop the walk
  through shared ancestors) and 785-788 (`keeps_body` walks every heavier leaf for every
  arriving body).
- **Scenario:** K heavier leaves sharing a withheld branch of length L cost K·L per call.
  `missing_bodies` runs after every processed block. Each leaf costs the attacker a real
  block of PoW, so this is bounded by attacker work.
- **Fix:** stop the walk once `cur` is in `seen`, or at a node already visited
  (`HashSet` of visited ids); in `keeps_body`, check "is `id` an ancestor of a heavier
  leaf" by walking **up** from `id` through `children` restricted to valid headers, or
  cache the candidate path set per tip change.
- **Test:** timing test with 1,000 heavier leaves (linear bound, in the style of
  `ten_thousand_bodies_in_reverse_order_stay_linear`).
- **Confidence:** high.

### F-7: Bounded ≡ unbounded holds modulo `keeps_body` decisions
- **Severity:** Informational. **Status:** Accepted limitation.
- **Where:** `manager.rs:652` evaluates the policy against the intermediate tip during a
  drain. The chain result can differ only in which low-work side bodies were kept. It is
  never a candidate, because candidates are always kept. Worth one sentence in the
  doc comment at `manager.rs:260-265`.

### F-8: A mid-drain `submit_tx` across an activation flushes the pool
- **Severity:** Informational. **Status:** Accepted limitation.
- **Where:** `mempool.rs:268-270` (`add` → `enter_rules`) with an intermediate
  `next_rules()` during a paused drain that crosses an activation. The final
  `finish_sync` would have flushed anyway in the crossing direction. In the other
  direction (a reorg that ends back on the pool's side), valid pooled transactions are
  lost and must be rebroadcast. Wallets rebroadcast.
- **Possible fix:** `submit_tx`/`check_tx` return a "busy, retry" error while
  `sync_pending()`. Overlaps with 12/34.

### F-9: No operator `reconsiderblock` for non-intrinsic invalidity (R1-C12)
- **Severity:** Low. **Status:** Deferred (R1 P3).
- The only non-intrinsic body failure I found is a contained verifier panic
  (`validate.rs:552-566`). It is deterministic in practice. An operator reconsider fits
  the park/override RPC of §3.2 and should be designed with it.

### F-10: Test gaps
- **Severity:** Medium (evidence). **Status:** Not implemented.
- **Missing:**
  - the property/model tests of §5 W-1;
  - a downward activation reorg;
  - the PX5 cache under reorg;
  - a deep PX reorg (≥ 30 blocks, ≥ 3 PX blocks disconnected) against a from-scratch
    replay;
  - F-1 and F-2 regressions.

**Challenge to the existing reports:**
- The consolidated report classes fork choice as CT and notes only "deep PX reorgs
  shallow". I add F-1, a liveness gap left by the H1 fix: H1 made the *connection* rule
  body-complete, but *download* is still driven by a height-sorted, truncated list with
  height-based peer choice.
- R1 §3.5 called the reconnect re-verification "acceptable". Given R12-2, and that the
  lock is held throughout, I rate it Low→Medium, with a cheap sound fix (F-2).

---

## 5. Implementation plan (phase 2)

| # | Item | Files (ownership) | Consensus? | Identity | Tests | Docs | Size | Pri |
|---|---|---|---|---|---|---|---|---|
| W-1 | **Fork-choice model and properties.** (a) A pure-Rust reference model `FcModel`: a tree of abstract blocks (id, parent, difficulty, valid flag), fed a delivery sequence of `Header(id)`/`Body(id)`, computing the expected connected tip by the spec (earliest completion, tip retention on ties, invalid propagation). (b) An exhaustive enumerator of every delivery order for trees of ≤ 6 blocks (a small in-house explicit-state search; `stateright` 0.31 was last released about 3 years ago, so I do not recommend adding it). (c) `proptest` (fixed seed in CI) over random trees of ≤ 40 blocks with random invalid bodies, random header-first/withheld deliveries, random bounded budgets and restarts, driving the real `ChainManager` (ZeroPow, coinbase-only blocks, invalid = over-claimed coinbase). Invariants: INV-1…5; bounded = unbounded (the in-file `same_chain`); `missing_bodies ⊆ keeps_body`; every heavier candidate is represented in `missing_bodies` (after W-2); the state proxy (output count, generated, key-image count, PX root) equals a fresh node fed only `connected` in order; with pairwise distinct cumulative works, the final tip is order-independent | new `chain/tests/fork_choice_model.rs`, `chain/tests/fork_choice_props.rs` (02); `chain/Cargo.toml` dev-dep `proptest` if absent (coordinate with 41/44) | none | none | property, model, regression files | `blocks.md` §6 (point to the model) | M | **P0** (evidence for the freeze; R13 T-4/T-5) |
| W-2 | **F-1 fix, chain side:** fair `missing_bodies` (round-robin per candidate, ordered by work) and `missing_bodies_toward(tip, max)`; memoized walks (F-6) | `chain/src/manager.rs` `missing_bodies`, `keeps_body` (02) | policy | none | unit (deep withheld B + honest C), property (W-1), linear-time test with 1,000 leaves | `blocks.md` §6 "Downloads" | S | **P1** (P0 if the public testnet precedes 31's work) |
| W-3 | **F-1 fix, P2P side:** per-peer best-known header from `Headers`/announcements; request only blocks on that chain (IBD fallback); remember `NotFound` per (peer, id) for a period; stalling-peer handling | `p2p/src/net.rs` `schedule_downloads`, `on_headers`, the `NotFound` handler (**31 owns**; 02 reviews) | policy | none | `p2p/tests/withheld_body.rs`: a new case with a deep withheld heavier branch; simulation harness (41) | `p2p.md` §6 | M | P1 |
| W-4 | **F-2 fix:** `validated` set; skip re-verification on reconnect; clear on invalidate | `chain/src/manager.rs` `sync_state`, `invalidate`, struct field (02; coordinate with 34, which restructures the same function, and 10) | none (not externally visible) | none | differential property (cache vs no cache: identical `connected`, state, `invalid`); a counting test through a `#[cfg(test)]` counter or a `validate_calls()` diagnostic | `blocks.md` §6; `p2p.md` §6 bound statement | S | P1 |
| W-5 | **F-3:** empty template txs while `sync_pending()` | `chain/src/manager.rs` `template` (02); node "syncing" gate by 09/31 | policy | none | unit: a mid-drain template mines a valid block | `blocks.md` §9 | S | P1 |
| W-6 | **Activation and PX reorg tests:** (a) a downward-crossing reorg (tip above activation → heavier, shorter branch ending below): the pool is flushed, returned txs are admitted only under the old domain, and PX5 is never skipped for below-activation blocks; (b) a PX5 cache during reorg: a pooled PX tx included in the new branch's block is accepted without re-proof, while the same tx under a different domain is fully verified (use a counting hook); (c) a deep PX reorg (nightly; reuse proofs from `restart_rebuilds_the_px_state_exactly` fixtures) vs from-scratch replay | `chain/tests/activation.rs` (02 adds cases; coordinate with 50), new `chain/tests/deep_reorg_px.rs` (02) | none | none | regression, nightly | K4 §7 update | M | P1 (a, b); P2 (c) |
| W-7 | **Park-on-deep-reorg policy** (§3.2): config `max_reorg_depth: Option<u64>` (default `None`); in `sync_state`, a target whose fork depth exceeds it is *parked* (no switch, ERROR log, `/info` field, templates withheld); operator accept by block id (RPC/CLI); the park state is not persisted (replay follows most work; document it); pairs with F-9 reconsider | `chain/src/manager.rs` (02), `node/src/config.rs` + `/info` (36/40 review), `rpc` types | policy (behaves like consensus under partition) | none | unit: park at K+1, accept override; labnet partition drill | `consensus.md` §8, `k4-reorg-policy.md` §5, `testnet-incident-response.md` | M | P2 (owner decision Q1) |
| W-8 | **Docs:** F-4 tie wording, F-5 stale statements, F-7 note | `docs/consensus.md` §8, `docs/blocks.md` §6/§8, `manager.rs` doc comments (02; 47 reviews) | none | none | — | — | S | P1 |
| W-9 | `HeaderChain::mark_invalid` O(entries) → maintain valid leaves | `consensus/src/chain.rs` (**01 owns**) | none | none | the existing `invalidating_*` tests plus a property | — | S | P2 |
| W-10 | Speculative branch validation without disconnect (a Zebra-style per-fork overlay), so that a failed reorg never touches the connected state | `chain/src/manager.rs`, `tx/src/state.rs` (34/35 lead) | none | none | differential against the current path | ADR | L | P3 |

Benchmarks: none new. W-4 should report the verifications saved in a failed 10-block
reorg. W-2 and F-6 need a timing assertion only.

---

## 6. Dependencies and conflicts

- **34 chain-actor-concurrency:** the same functions (`sync_state`, `drain_ready`,
  `submit_block_in_steps`). W-4 and W-5 are small and should land before or inside the
  actor refactor. The actor must preserve INV-5 and the bounded ≡ unbounded equivalence;
  W-1's properties are its determinism oracle.
- **31 p2p-sync:** owns W-3. `MIN_CHAIN_WORK` and presync interact with `keeps_body` and
  `missing_bodies` (candidates below minimum work should not be downloaded during IBD).
- **10 block-validation-pipeline:** R12-2 bounds F-2's severity; the PX5 cache design
  (tx id + verifier id + registry digest) must keep INV-7.
- **07 randomx-cache-seed:** `CachedPow` lives in `manager.rs:45-126`; no overlap with
  fork-choice functions, but the same file (merge coordination).
- **35 storage-recovery:** replay semantics (INV-4); undo bounds if W-7 is adopted;
  the orphan-duplicate note.
- **01 consensus-core:** W-9; the tie rule on the never-change list.
- **41 fuzzing/property:** W-1 is a property/model deliverable (share the harness;
  proptest dependency).
- **42 mutation-formal:** mutants on `mark_complete`, `recompute_target` and the budget
  condition should be killed by W-1.
- **50 red-team:** W-6 (activation grace, PX5 domain gating).
- **09 mining-templates:** F-3 and the IBD template gate.
- **47 docs:** W-8.

---

## 7. Open questions for the coordinator

1. **Q1 (owner):** adopt the park-on-deep-reorg policy (W-7) at all? If yes, which
   default for the public testnet (my proposal: disabled for the 7-device trial, 720 for
   a public testnet)?
2. **Q2:** should `missing_bodies` stay a single global list (W-2 fair version) or be
   replaced outright by per-peer targeting (W-3)? I recommend both: fair list for IBD
   fallback, targeted for tips.
3. **Q3:** is `proptest` already an approved dev-dependency for `chain` (44 supply
   chain)? W-1 needs it. The fallback is a seeded ChaCha loop.
4. **Q4:** should the F-4 tie behaviour be changed to Core's (return to the
   earliest-completed block) or only documented? I recommend documenting it; a change
   costs an extra reorg and gains nothing.
5. **Q5:** should `LOW_WORK_MARGIN_BLOCKS` be reduced (docs say "meant to be about 6")
   once the tests that mine deep local side branches are adapted? Policy only; low value.

---

## 8. Sources

- Bitcoin Core PR #29640, "Fix tiebreak when loading blocks from disk" (merged
  2025-10-27): https://github.com/bitcoin/bitcoin/pull/29640
- Bitcoin Core commit 4e0eed8 (sipa), "Allow ActivateBestChain to release its lock on
  cs_main": https://github.com/bitcoin/bitcoin/commit/4e0eed8
- Bitcoin Core `validation.cpp` (`ActivateBestChainStep`, the 32-block batch,
  `ReceivedBlockTransactions`, `AcceptBlock`):
  https://github.com/bitcoin/bitcoin/blob/master/src/validation.cpp ; batch commit
  pointer https://github.com/bitcoin/bitcoin/commit/2ef5ffa
- Bitcoin Core `net_processing.cpp` (`FindNextBlocksToDownload`, stalling):
  https://github.com/bitcoin/bitcoin/blob/master/src/net_processing.cpp ; issue #32179
  https://github.com/bitcoin/bitcoin/issues/32179 ; PR review club #25880
  https://bitcoincore.reviews/25880
- btclib-node issue #1179 (block download from peers that never announced the block):
  https://github.com/btclib-org/btclib-node/issues/1179
- zcashd PR #2463, "rollback limit for reorganisation" (MAX_REORG_LENGTH, shutdown):
  https://github.com/zcash/zcash/pull/2463
- Zebra RFC 0005, State Updates (non-finalized chains, tie by hash, finalization):
  https://zebra.zfnd.org/dev/rfcs/0005-state-updates.html
- Zebra 5.2.0, "Wider Rollback Window" (99 → 1000, 2026-06-19):
  https://zfnd.org/zebra-5-2-0-wider-rollback-window/ ; Zebra issue #11403:
  https://github.com/ZcashFoundation/zebra/issues/11403 ; constants:
  https://github.com/ZcashFoundation/zebra/blob/main/zebra-state/src/constants.rs
- Monero issue #10064, "Temporary rolling DNS checkpoints":
  https://github.com/monero-project/monero/issues/10064
- CoinDesk, the Monero 18-block reorg of 2025-09-14 (pointer only):
  https://www.coindesk.com/web3/2025/09/15/monero-suffers-deepest-ever-blockchain-reorganization-invalidating-118-transactions
- Bitcoin ABC 0.18.5 release (finalization, `-maxreorgdepth`, `parkblock`):
  https://github.com/Bitcoin-ABC/bitcoin-abc/releases/tag/v0.18.5 ; finalization tests
  https://github.com/Bitcoin-ABC/bitcoin-abc/blob/master/src/test/finalization_tests.cpp
- Karakostas & Kiayias, "Securing Proof-of-Work Ledgers via Checkpointing", ePrint
  2020/173: https://eprint.iacr.org/2020/173
- Garay, Kiayias & Leonardos, "The Bitcoin Backbone Protocol with Chains of Variable
  Difficulty", ePrint 2016/1048 (CRYPTO 2017): https://eprint.iacr.org/2016/1048
- Eyal & Sirer, "Majority is not Enough: Bitcoin Mining is Vulnerable", arXiv
  1311.0243: https://arxiv.org/abs/1311.0243
- "The Power of Random Symmetry-Breaking in Nakamoto Consensus", arXiv 2108.09604:
  https://arxiv.org/abs/2108.09604
- stateright (maintenance status): https://github.com/stateright/stateright ,
  https://lib.rs/crates/stateright
- Internal: `docs/reviews/k4-reorg-policy.md`, `docs/reviews/full-review-2026-09-27.md`
  (R1 §3.5/§4.3, SX2 P0-7, R12 §10), `docs/blocks.md` §6/§8, `docs/consensus.md` §8.
