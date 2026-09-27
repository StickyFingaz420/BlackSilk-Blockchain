# 34 chain-actor-concurrency: research dossier (phase 2, phase 1)

**P0-A: the global chain lock and node liveness.** This is internal engineering research,
not an audit. Nothing here claims that BlackSilk is secure or production-ready.

## 1. Scope and what I read

**Commit:** `9e422d8` (`rebuild/core`), from `git rev-parse --short HEAD`. I stayed read-only
and ran no builds.

**Code (read in full or at every relevant site):**
- `chain/src/manager.rs` (1,459 lines, all of it):
  - `CachedPow`, `submit_block_in_steps` (:266-288), `submit_inner`, `drain_ready`,
    `sync_state` (:879-967), `finish_sync` (:979-995);
  - the header-sync API, `template`;
  - the two bounded-API unit tests (:1370-1458).
- `chain/src/mempool.rs` :112-460 (`enter_rules`, `conflicts`, `check`, `add`,
  `remove_block`, `revalidate`, `select`).
- `p2p/src/net.rs`:
  - the module concurrency rules (:4-12), `lock_or_exit`/`fatal` (:54-67), constants
    (:69-105), `NetConfig` defaults (:142-162);
  - `Network::start`/`submit_tx` (:383-492), `Inner::chain`/`with_chain` (:551-572),
    `request_headers_after` (:727-762);
  - `run_connection` (the read loop, :953-1223), `handle` (:1276-1326), `on_headers`,
    `header_worker`, `verify_headers` (:1396-1777);
  - `on_get_blocks`, `on_block`, `block_worker`, `schedule_downloads`, `on_inv_tx`,
    `on_get_tx` (:1829-2118);
  - `admit_tx`, `on_tx`, `on_stem_tx`, `fluff`, `maintenance_loop` (:2207-2759).
  - I grepped every `.chain()` / `with_chain` / `spawn_blocking` site in `p2p/src/net.rs`.
- `p2p/src/limits.rs` (all).
- `node/src/lib.rs` (all: `lock`, `with_chain`, every handler) and `node/src/main.rs` (all).
- `tx/src/validate.rs`:
  - :380-720 (C1/C3, PX5, `validate_*`, `revalidate_after_extension`);
  - :840-1132 (`validate_block_transactions_cached`).
- `tx/src/state.rs` :1-140 (the `MemoryChain` layout).
- `consensus/src/chain.rs` (the `HeaderChain` struct, `validate`/`accept` PoW site :470-492).
- The rpc client timeout (`rpc/src/lib.rs:359`, 120 s) and the miner refresh loop
  (`miner/src/main.rs`).

**Tests read:**
- `p2p/tests/network.rs`: `pings_are_answered_while_the_chain_lock_is_held` (:2262-2307) and
  `pings_are_answered_while_a_long_batch_of_blocks_connects` (:2309-2448). I also read the
  helper list and the list of all test names.
- `chain/src/manager.rs` unit tests:
  - `bounded_submission_reaches_the_unbounded_result_in_bounded_steps`;
  - `a_bounded_reorganization_never_stops_on_a_lighter_tip`.
- `chain/tests/manager.rs` and `fork_choice.rs`: test names, and the custom failing
  `BlockStore` at `chain/tests/manager.rs:771`, which is precedent for a slow-store
  injection.
- `node/src/lib.rs::tests`.

**Docs and reports:**
- `docs/p2p.md` §6 (:265-285), §10 liveness (:528-545) and open items (:590-608);
- `docs/blocks.md` :225-240;
- `full-review-2026-09-27.md`: rows R6 MP-1, R8-1, R16-7, P0-7, P3-2 and never-change item
  25;
- `autonomous-session-2026-09-27.md` §1, §2, §4, §6;
- R8 §2.1-2.2;
- R16 §4 (R16-6, R16-7, R16-8);
- SX2: rows R8-1, R8-2, R16-6/7, C10, and P0-5 to P0-9.

**Roster and coordination:**
- `C:/bszkeval/p2/roster.md`: my entry (34) and neighbours 30-33, 35, 36 and 46-50.
- `C:/bszkeval/p2/decisions.md`: all of it, especially 07 (W1-W3 are P0 and coordinated with
  34), 09 (/tip long-poll after 34), 10 (VerifiedCache, verify threads) and 02 (W-4).
- Dossiers 02, 07, 09, 10 and 12, at every lock and 34 reference.

**Internet research (primary sources, §8):**
- Bitcoin Core: `net.h` timeouts, `Chainstate::ActivateBestChain`, the cs_main release
  commit, PR #11824, PR #35561 and draft PR #36244;
- Zebra `zebra-state/src/service.rs`;
- reth: the stages doc, `CanonicalInMemoryState`, the MDBX freelist issue;
- Monero `blockchain.h`/`.cpp`;
- arc-swap: docs and soundness issues;
- RustSec: RUSTSEC-2026-0251 and RUSTSEC-2026-0292 (`sized-chunks` / `imbl-sized-chunks`);
- std `RwLock` docs; the tokio runtime `Builder`;
- the actor model (Hewitt 1973) and linearizability (Herlihy-Wing 1990).

## 2. Current state

### 2.1 What exists

| Item | Detail | Evidence |
|---|---|---|
| **One lock** | `SharedChain = Arc<std::sync::Mutex<ChainManager>>` (`net.rs:42`, `node/src/lib.rs:32`). It guards the header tree, `MemoryChain`, all bodies, `invalid`, the mempool, the block-store handle and the batch RNG. | source-read |
| **No lock on async workers** | Every P2P and RPC access runs the closure on a tokio blocking thread (`Inner::with_chain` `net.rs:562-572`, `node/src/lib.rs:135-142`), so tokio workers never park on the mutex. | tested: `pings_are_answered_while_the_chain_lock_is_held` |
| **Bounded body connection** | `submit_block_in_steps` makes ≤ 8 block validations per hold, sleeps 1 ms between steps, and gives the same final chain. | tested: `bounded_submission_reaches_the_unbounded_result_in_bounded_steps`, `a_bounded_reorganization_never_stops_on_a_lighter_tip`, `pings_are_answered_while_a_long_batch_of_blocks_connects` |
| **Header PoW outside the lock** | `pow_jobs` → `compute_parallel` → `accept_headers` (`net.rs:1756-1761`). | source-read; tested indirectly (`junk_header_batches_cost_at_most_one_chunk_of_proof_of_work`) |
| **Unrequested unknown-header blocks** | Dropped before any lock-held work (`net.rs:1940`). | tested: `an_unrequested_block_of_an_unknown_header_is_not_stored` |
| **Fail-stop** | A poisoned lock or a panicking chain task exits with status 70 (`lock_or_exit`, `fatal`, `node::lock`). | source-read (no subprocess test) |
| **Lock-ordering rule** | The chain lock and the network-state lock are never held together, and never across `.await` (`net.rs:4-6`). | source-read; I found no violation |
| **Workers** | One header worker and one block worker (`net.rs:1524`, `:1923`). | source-read |

### 2.2 What is correct and well designed

1. **The bounded drain keeps consensus results identical**, a mathematically-argued and
   tested property. `sync_state` stops only at a tip with work ≥ `floor` (the tip's work at
   entry), and continuation resumes from the connected prefix. The chain tests prove
   bounded equals unbounded for gap-fill and reorg shapes.
   - This mirrors Bitcoin Core: "ActivateBestChain is split into steps (see
     ActivateBestChainStep) so that we avoid holding cs_main for an extended period of
     time", with `m_chainstate_mutex` making sure that "only one caller may execute this
     function at a time" [btc-chainstate].
   - **BlackSilk has no equivalent of `m_chainstate_mutex`.** The RPC `/block` handler and
     the block worker can both drive `submit_block_in_steps`. They interleave safely,
     because the drain is global state inside the manager and either driver advances it.
     The verdicts stay correct, because `verdict()` is read only once the drain is empty.
     [source-read]
2. **Determinism is anchored in body storage order.** The fork-choice target depends only
   on the sequence of kept bodies (`manager.rs:17-24`). This is the property that makes any
   *scheduler* change consensus-neutral (§3.6). [source-read; tested:
   `replay_reproduces_live_fork_choice_exactly`]
3. **Fsync before apply.** A crash mid-hold replays deterministically. This must stay in the
   actor design. [source-read]
4. **The expensive checks read the chain through few, well-understood accessors.** They use
   only `ChainView::output` (ring resolution, append-only) and `px_function` (content-addressed,
   immutable per contract id). This is what makes "resolve on a view, verify outside, re-check
   and commit" exact (§3.5). [source-read: `validate.rs:399-432`, `:538-572`, `:1071-1130`]

### 2.3 What the tests actually prove, and what they do not

- The P0-7 test proves that a **third, idle** peer's pings are answered while the lock is
  held for 3 s.
  - It deliberately does **not** check the peers whose `GetHeaders` waits (`r1`, `w2`). Their
    read loops are blocked (F34-1).
- The long-batch test uses coinbase-only blocks, so every step is milliseconds long.
  - It proves the lock is *released* between steps, not that a *step* is short.
  - No test holds the lock longer than 3 s, and none crosses `PONG_TIMEOUT` (30 s) or
    `HANDSHAKE_TIMEOUT` (10 s).
- No test covers:
  - the handshake during a hold;
  - the maintenance loop during a hold;
  - RPC latency during a hold;
  - the blocking-pool size under an RPC flood;
  - fail-stop on a panic, as a subprocess exit-code test.

## 3. Problems in scope

### 3.1 The P0-7 fix moved the stall from tokio workers into the per-peer read loops

**Problem.** `run_connection` handles every decoded message inline: `handle(&inner, id,
msg).await` (`net.rs:1194`).
- Seven message kinds await the chain lock inside `handle`:
  - `GetHeaders` (:1300), `GetBlocks` (:1831), `InvTx` (:2042) and `GetTx` (:2097);
  - `Tx`/`StemTx` (`admit_tx` :2246, :2267; then :2414 / :2483);
  - an empty `Headers` (:1401).
- While the closure waits for the mutex, that connection's read loop reads nothing. The
  peer's `Ping` sits unread in the socket, so the peer kills us after `PONG_TIMEOUT` = 30 s
  (`net.rs:73`, :2661-2663 on its side).
- The pong to our own ping is also unread. This is symmetric, but our maintenance loop is
  stalled too (§3.2).

**Why it exists.** The R8-1 remediation targeted "no tokio worker parks on the mutex". It
did not target "no read loop depends on the writer". The doc (`p2p.md:534-539`) correctly
says "pings … of *other* peers keep flowing", and the test mirrors that wording.

**Is a hold over 30 s reachable?** Yes, on several paths (F34-4):
- a step of 8 heavy valid blocks, at ≈ 5-10 s each per 10 §3.1: **40-80 s**;
- the F10-2 invalid block: ≈ 25-50 s for one block;
- a reorg of depth D: at least about D validations in one hold (the "never lighter" rule,
  02);
- post-reorg `finish_sync` with a full pool: ≈ 500 s (M12-1).

Every syncing peer sends `GetHeaders` and `InvTx` routinely. So in the late-joiner
PX-block scenario (SX2 P0-7), the peers that matter most are exactly the ones exposed.

**Consequences.**
- **Liveness and partition.** A node connecting a heavy step loses its active peers. It
  also cannot gain new ones: the handshake needs the lock (§3.3).
- **Security.** An attacker who can create long holds (F10-2 needs one PoW-valid block; M12-1
  needs a pool fill plus a natural orphan) turns each hold into a network-wide disconnect
  wave.
- **Class.** Not consensus-critical, not privacy-critical. Liveness (priority 5), with an
  eclipse-assist aspect (32).

**Prior art.**
- Bitcoin Core has the same structural issue: `msghand` blocks while a block is processed.
  - It tolerates this through a very long `TIMEOUT_INTERVAL` of **20 minutes**
    [btc-net-h].
  - Draft PR #36244 (opened 2026-09-14, not merged) moves block processing to a dedicated
    worker "to keep peers responsive". It measures PING/PONG latency dropping from
    41.8 ms to 0.77 ms during IBD [btc-36244].
- Zebra keeps readers off the write path entirely. `ReadStateService` requests "are
  processed in parallel, ignoring any blocks queued by the read-write StateService", served
  from "a watch channel with a cached copy of the NonFinalizedState" [zebra-service].

**Fixes (trade-offs in §5):**
- **Interim, Stage 1.** Split each connection's traffic into a **fast lane**, handled inline
  (Ping, Pong, Addr, GetAddr, NotFound, non-empty Headers, Block), and a per-peer bounded
  **slow lane** task for the chain-touching kinds, which keeps the per-peer order.
  - The read loop never awaits the chain.
  - A full slow lane counts as a message-rate excess: drop and charge `score::RATE`, as the
    message budget does today.
- **Structural, Stage 2.** Most slow-lane work becomes snapshot reads, which answer
  immediately.
- **Not recommended alone:** raising `PONG_TIMEOUT` (Bitcoin-style). It hides the symptom and
  weakens dead-peer detection. It is an optional belt-and-braces item (open question Q2).

**Tests that prove the fix.**
- **L1:** peer P sends `GetHeaders` while the lock (or the actor) is stalled for 40 s by a
  `SlowStore` whose `append` sleeps. Every one of **P's own** pings is answered in < 1 s, and
  the `Headers` reply arrives after the stall. Today this test fails.
- **L2:** the same, with `InvTx` and a requested `Tx`.

**Invariant.** Per-peer message order within the slow lane equals arrival order. Relay
semantics (`tx_requests`, `known_txs`) depend on it.

### 3.2 The maintenance loop awaits the chain every tick

`maintenance_loop` awaits `with_chain` for the tip at every 250 ms tick (`net.rs:2627`),
then again via `request_headers` per behind-peer and `schedule_downloads`.

During a hold, the whole loop stops:
- no pings are sent and no timeouts are evaluated;
- no Dandelion epoch roll, embargo fluff or held-local-tx release;
- no tip announcement and no outbound dialing;
- no address saving.

After the hold, stale timers fire together.

- **Privacy.** Embargo fluffs are delayed. This is not a leak, but the embargo guarantee
  ("fluff by T") becomes "fluff by T + hold". The origin's local-tx hold (I3-1 fix) also
  extends.
- **Fix.** Read the tip and header height from the published snapshot (Stage 1 already
  provides a summary cell). Send the per-peer `request_headers` and `schedule_downloads` to
  their own tasks, or have them read the snapshot's precomputed `locator` and
  `missing_bodies` (Stage 2).
- **Test L3.** During a 40 s stall, tip announcements for a block connected by *another* path
  still go out, pings still go out every `PING_INTERVAL`, and an embargo expiring inside the
  stall fluffs within one tick of expiry. Fluff needs `submit_tx` (a write), so in Stage 1
  assert only that the embargo is *detected*. In Stage 2 the fluff is queued to the actor's
  tx lane.

### 3.3 The handshake needs the chain lock

`run_connection` reads `(header_height, best_header_id)` through `with_chain` *before*
sending `Version` (`net.rs:981-983`). The remote's `HANDSHAKE_TIMEOUT` is 10 s. During any
hold longer than 10 s, **no inbound or outbound connection completes**.

Combined with §3.1, a node in a long hold both loses peers and cannot replace them.
- **Fix.** Read the snapshot (Stage 1 summary cell).
- **Test L4.** A fresh raw peer completes the handshake in < 1 s during a 40 s stall, and its
  `Version.height` equals the snapshot's header height.

### 3.4 Lock-hold durations are still unbounded on several paths (consolidation)

| Path | Hold | Source |
|---|---|---|
| Block step | ≤ 8 validations, counted in blocks not cost: ≈ 8 × (5-10 s) for valid blocks | `manager.rs:258, 922-926`; 10 F10-4 |
| Reorg | "Never lighter" means depth D costs ≥ D validations in one hold | `manager.rs:923`; 02 |
| `finish_sync` after a reorg | Full revalidation of the pool, unbounded, ≈ 500 s worst | `manager.rs:979-995`, `mempool.rs:374-398`; 12 M12-1 |
| RPC `/block` | Unknown header, so RandomX runs under the lock (0.45-0.75 s light), plus a seed-cache build of 1-3 s at an epoch switch | `consensus/src/chain.rs:483`; `node/src/lib.rs:239-241`; 07 F07-1/F07-3 |
| Relayed tx admission | Full `validate_mempool_tx` under the lock: PX 0.2-0.26 s, a 64-input transfer ≈ 0.2 s | `net.rs:2414, 2483, 2582` |
| Store append | `fsync` under the lock, per kept body (slow SD cards on trial devices: unknown latency) | `manager.rs:672` |

The doc understates this: "A *single* block still holds the lock … up to ~3.4 s"
(`p2p.md:593-594`). 10 recomputed about 5-10 s per valid block, and a step is 8 blocks.

### 3.5 Transaction verification and block connection share one serial resource

The per-peer input budget is 50 CLSAG/s with a burst of 500 (`limits.rs:76`).
- With 64 inbound and 8 outbound peers at `max_per_ip` 2 (32+ IPs), the demand is up to
  ≈ 3,600 CLSAG/s ≈ 10 CPU-s/s. It all serializes on the **one** lock.
- It is not penalized when the signature fails over a ring younger than
  `SIGNATURE_BURIAL` = 60, and fresh ids are free to make (`ctx_reject` caches per id only).
- The block worker and the header worker then wait in a convoy of up to about 72 waiters
  on an unfair `std::sync::Mutex`.
- Throughput for blocks drops roughly in proportion. R8 anticipated this (R8-7: "the chain
  lock is saturated and blocks and headers starve").

Existing mitigations reduce the *free* variants, but not honest-looking load:
- conflicts dropped;
- `ctx_rejects`;
- the PX global bucket.

**Fix.** Verification outside the writer (Stage 4). CPU is still spent, but on a bounded
verifier pool, never blocking connection. Add a **node-wide CLSAG budget** (like
`px_global`), sized to the verifier pool, plus priority lanes in the actor: blocks and
headers over transactions.

**Test.** Adversarial A1 (§5, Stage 4).

### 3.6 The target design, and the equivalence argument

#### Design (single writer, snapshots, off-writer verification)

```
          +------------------------ ChainHandle (Clone, Send, Sync) -----------------------+
 P2P ---> | snapshot() -> Arc<ChainSnapshot>   (std RwLock<Arc<_>>; clone under read lock) |
 RPC ---> | bodies.get(id) -> Arc<BlockBytes>  (short-hold index; O(1) critical section)   |
 miner    | mempool.contains/get/conflicts      (Stage 3: own short-hold mutex)            |
          | send(Command) -> Result<(), Full>   (bounded lanes; reply via callback)        |
          +---------------------------------------------------------------------------------+
                                        |
                                        v  (one OS thread, owns ChainManager exclusively)
                             ChainActor loop:
                               pick next command by lane priority:
                                 0 Stop  1 Headers  2 Block/Step  3 Query  4 Tx
                               run it (one ChainManager method = one former lock closure)
                               if drain pending: run ONE sync_step, then yield to lanes
                               publish snapshot (after every mutating command)
                             panic => fatal exit(70) (drop guard; same as poisoned lock)
```

**Details:**
- **Actor.** A dedicated `std::thread` owns `ChainManager` by value. No mutex around it
  exists any more, so nobody can wait on it.
  - Commands arrive on bounded `std::sync::mpsc::sync_channel` lanes. Producers use
    `try_send`, so an async thread never blocks, and back-pressure is explicit: a full lane
    is an error to the caller.
  - Replies go through a `Box<dyn FnOnce(R) + Send>` callback. The async side wraps a
    `tokio::sync::oneshot::Sender` in it, so `chain` stays std-only with no tokio dependency.
- **Scheduling.** The actor runs one `sync_step(budget)` at a time and services higher lanes
  between steps. This replaces `submit_block_in_steps` and its 1 ms fairness sleep. The drain
  and its "never lighter" rule are unchanged, because they live inside `ChainManager`.
- **Snapshot contents:** plain owned data, rebuilt by the actor from `&ChainManager` after
  each mutating command:
  - `seq`, the linearization index;
  - the tip (id, header, height, work, generated);
  - the header tip (id, height, work);
  - the next-block rule domain and epoch name;
  - the precomputed `locator` (≤ 64 ids) and `missing_bodies(256)`;
  - the header-template base on the tip (difficulty, seed, min timestamp, version, reward);
  - mempool counters (len, bytes, domain);
  - output count, PX record count and root;
  - `deepest_reorg`, `store_failed`, `sync_pending`.

  The cost per publish is O(256 + 64), microseconds, far below one block validation.
  [assumed; bench B2]
- **Indexes read with O(1) critical sections** (the actor is the sole writer):
  - **Bodies:** `HashMap<Hash, Arc<Block>>`. `ChainManager.bodies` becomes `Arc`-shared so
    the index does not duplicate memory. Serving encodes outside any lock.
  - **Main-chain header index** (Stage 3), for `GetHeaders`, `headers_after` and `locator`:
    per-height ids plus an id→height map, updated by the actor only on header-best changes.
- **Mempool out of `ChainManager`** (Stage 3, R16-7 item 4, with 12).
  - `Arc<Mutex<Mempool>>` whose critical sections are only insert, remove, lookup and select.
  - Validation happens outside the mempool lock: in the actor during Stage 3, and in the
    verifier pool during Stage 4.
- **Off-writer verification** (Stage 4):
  - **Transactions:** the "check, verify outside, re-check and commit" scheme below.
  - **Blocks:** 10's phase A / phase B split. During phase B (pure jobs on scoped threads)
    the actor may serve **only the Query lane**, which is read-only. State cannot change, so
    the verdict is the sequential verdict.

**Primitive choice.**
- `std::sync::RwLock<Arc<ChainSnapshot>>`:
  - Read: take the read lock, clone the `Arc`, drop the guard. Never nested; that is a lint
    or review rule, because std documents that "a writer which is waiting … might or might
    not block concurrent calls to read" [std-rwlock], so a nested read can deadlock.
  - Write: swap under the write lock. The critical sections are nanoseconds.
  - arc-swap's own docs note that `RwLock<Arc<T>>` "suffers from CPU-level contention"
    [arcswap-docs]. At our read rates (≤ thousands/s) that is irrelevant. [assumed; bench B3]
- **Rejected:**
  - **`arc-swap`.** Internal `unsafe` debt/hazard-pointer scheme, with open 2026 soundness
    reports: #208 (panics in `Clone` can double-decrement, giving use-after-free) and #210
    (a guard observing a freed-and-reused inner under memory pressure) [arcswap-208],
    [arcswap-210]. Earlier issues: #45, dangling `MapGuard`; #76, Miri data race.
  - **Persistent collections (`im`, `imbl`, `rpds`).** `sized-chunks` is unmaintained
    (RUSTSEC-2026-0251), and `imbl-sized-chunks` 0.1.x had a double-free / use-after-free
    (RUSTSEC-2026-0292) [rustsec-251], [rustsec-292]. Putting such a dependency *inside
    consensus state* is exactly what the brief forbids.
  - `left-right`, `evmap` and `crossbeam-epoch` all rely on internal `unsafe`, and none is
    needed. [assumed from their design; not re-audited here]
- **Async notification** (09's `/tip` long-poll): the actor calls a registered
  `on_publish(Arc<ChainSnapshot>)` hook. The node forwards it into a `tokio::sync::watch`,
  which tokio already provides as a dependency.

#### Equivalence argument (why consensus results stay identical)

1. **Current system.** Every chain access is a closure run under one mutex. Every execution
   is therefore equivalent to a sequential execution of those closures in lock-acquisition
   order: the mutex is the linearization point [herlihy-wing].
2. **Actor.** Every command is exactly one of those closures (the same `ChainManager` method
   with the same arguments), run sequentially. The actor's schedules are a **subset** of the
   schedules the mutex already allows. So every actor execution is an execution the current
   code can produce. [mathematically established, given the one-command-per-closure mapping,
   which review must check]
3. **Consensus outputs** (connected chain, state, `invalid`, store bytes) are a function of
   the body/header submission sequence alone: body-complete determinism (`manager.rs:17-24`)
   and replay equal to live.
   - So for the same arrival sequence the actor gives identical results.
   - The *scheduler* may change arrival order between peers, which the mutex also allowed
     (unfair lock). That is not a consensus-rule change: every node already sees an
     arbitrary network order.
4. **Snapshots.** A snapshot is a pure function of `&ChainManager` at a linearization
   point. A reader holding it acts like a reader that took the lock just before the next
   command.
   - Composite read-then-write flows in P2P are *already* non-atomic today: `admit_tx` takes
     three separate holds.
   - Flows that rely on atomicity within one hold stay one command: `on_tx`'s
     `tip + submit_tx + proven_invalid`, and `verify_headers`' `accept_headers`.
5. **Tx off-writer verification** (Stage 4) keeps the verdict exactly equal to
   `validate_mempool_tx(tx, state_at_commit, next_height, rules_at_commit)`:
   - (a) Stateless checks (structure, balance, BP+, PX5) are functions of the tx, plus
     registry entries that are content-addressed and immutable. PX3 re-checks existence at
     commit (the argument at `validate.rs:899-905`).
   - (b) C3 is a function of (message(domain), resolved ring members, pseudo-outs, key image,
     signature). The worker records `ring_digest = H(resolved members)` and the domain.
   - (c) At commit, the actor re-runs every contextual rule in the sequential order: C2/C4,
     PX1-PX4, contract id, then C1 (re-resolve against current state, including maturity at
     the commit height). It compares the ring digest and the domain.
     - If both are equal, the recorded C3/PX5/T10 verdicts are the verdicts at commit.
     - If either differs, it treats the tx as contextual-retry: re-verify or drop, never
       penalize. This matches 12's W1 decision (drop on mismatch).
   - (d) **Reported errors.** The actor reports the first failing rule in
     `validate_mempool_tx` order, using commit-time contextual results and pre-verified
     stateless results. So `proven_invalid` / penalty classification is unchanged. (A
     contextual failure at commit outranks a snapshot-time signature failure, exactly as the
     sequential order puts C2/C4 before C3.)
6. **Block phase B** (Stage 4) changes nothing semantically: the same jobs, the same
   state, and 10's lowest-index error rule.

**Invariants that must never change:**
- fsync before apply;
- replay equals live;
- a drain never pauses on a lighter tip;
- the mempool never changes a block verdict (the PX5 cache remains gated on
  `same_rules`, and 10's `VerifiedCache` replaces it);
- fail-stop on a writer panic;
- the lock-ordering rule (full review never-change item 25), now reformulated: the actor
  never takes the network-state lock or awaits P2P, and P2P never calls the actor while
  holding the state lock;
- one-command-per-former-closure atomicity where the code relies on it;
- the BP+ batch RNG is consumed only by the writer, in validation order. Its values affect
  verdicts only with probability ≤ 2^-128 (16's decision).

**What could go wrong:**
- **A snapshot missing a field** that some code path needs forces a new command round-trip.
  Mitigation: the Stage 2 read-site table (§5) enumerates every current site.
- **Latency.** Commands waiting behind one heavy step (seconds). This is acceptable because
  no read loop waits for them. The mitigation is Stage 4, plus 10's cost-weighted step
  budget.
- **Queue sizing.** A lane that can fill with requested blocks would drop honest data.
  - Size the block lane at ≥ Σ per-peer windows + `UNREQUESTED_QUEUE`, so it cannot fill.
    Today that is (64 + 8) × 3 + 8 = 224 by the byte window.
  - The tx lane *may* drop: relay is best-effort and uncharged.
- **Memory.** A slow reader holding an old snapshot keeps it alive. That costs only the
  small snapshot plus `Arc` bodies, never the state. Compare reth's MDBX lesson: long read
  transactions pin freed pages [reth-5228].
- **Shutdown.** The actor must accept `Stop` between steps. A mid-drain stop is safe
  (fsync before apply, replay).

## 4. New findings

| ID | Severity | Status | Location | Scenario | Confidence |
|---|---|---|---|---|---|
| **F34-1** | **High** (liveness; eclipse-assist) | Not implemented | `p2p/src/net.rs:1194` (inline `handle().await`); :1300, :1401, :1831, :2042, :2097, :2246, :2267, :2414, :2483 | A late joiner connects a step of 8 PX-heavy blocks (40-80 s), or an F10-2 block, or a post-reorg `finish_sync`. Each syncing peer's read loop is parked in `GetHeaders`/`InvTx`, so its pings go unanswered and it drops us after 30 s. The P0-7 test checks only an idle third peer. | High on the mechanism (source-read); medium on the hold magnitudes (10/12 estimates) |
| **F34-2** | Medium | Not implemented | `net.rs:2627-2629`, :2730-2733 | During a hold the maintenance loop stops: no pings, timeouts, Dandelion epochs or embargo fluff, tip announcements or outbound dials. Timers fire in a burst afterwards. Embargo is delayed by the hold. | High |
| **F34-3** | Medium | Not implemented | `net.rs:981-983` | The handshake reads the chain before `Version`. During a hold longer than 10 s every new connection fails the remote's `HANDSHAKE_TIMEOUT`. Together with F34-1, the node cannot replace dropped peers. | High |
| **F34-4** | Medium | Partially implemented | `manager.rs:258, 672, 923, 979-995`; `node/src/lib.rs:239-241`; `consensus/src/chain.rs:483` | Consolidated: holds are bounded in *blocks*, not time. Unbounded cases: reorgs, `finish_sync`, RPC `/block` PoW and cache build, relayed-tx verification, fsync. `p2p.md:593` states "~3.4 s". | High |
| **F34-5** | Medium | Partially implemented | `limits.rs:76`; `net.rs:2414, 2483`; `SIGNATURE_BURIAL` :2325 | 64+8 peers at a 50 CLSAG/s budget demand ≈ 10 CPU-s/s, all under one unfair mutex. Young-ring signature failures are unpenalized. Block and header connection convoy behind about 72 tx verifiers. | Medium (the arithmetic is sound; the contention was not measured) |
| **F34-6** | Low | Not implemented | `node/src/lib.rs:135-142, 239, 280` | RPC chain calls take tokio blocking threads without bound, and the pool (512) is shared with P2P. During a long hold, re-polling clients (120 s client timeout) accumulate waiters. Past 512, P2P `with_chain` and the worker tasks queue behind them. The loopback default limits it. | Medium |
| **F34-7** | Low-Medium | Not implemented | `net.rs:1719, 1756, 1761, 1771` | `verify_headers` takes the lock 3+ times per chunk, each waiting behind a block step. During body connection, header sync (including a competing tip) stalls. This extends R8-15 head-of-line blocking. | High |
| **F34-8** | Informational | — | `net.rs:562-565` | Read closures get `&mut ChainManager`; there is no type-level separation of readers from writers. The actor/snapshot split makes it structural. | High |
| **F34-9** | Low (docs) | Not implemented | `docs/p2p.md:534-539, 590-602` | The docs imply that pings are unaffected, which holds only for *other* peers. The "~3.4 s" figure is stale. The blocking-pool bound argument ("bounded by connections") ignores RPC. | High |
| **F34-10** | Low | Not implemented | `manager.rs:711-741` | `finish_sync` runs only when the ready queue empties. During continuous IBD arrivals a drain can span many steps, so pool revalidation and `/template` (M12-4) lag. There is no consensus effect. | Medium |
| **F34-11** | Informational | — | `node/src/main.rs:132-200` | On shutdown during a hold, the runtime drop waits for the running blocking task (the rest of the step). This is safe, because of fsync before apply. | Medium (tokio drop semantics assumed, not re-read) |

**Challenges to existing reports.**
- **The autonomous-session report (§2, round 3)** says "chain work runs off the async
  workers" and treats R8-1(a) as done. That is true for tokio workers but not for liveness
  (F34-1). R8's scenario step 3 ("No pongs are sent") still occurs, just per connection
  instead of per runtime.
- **SX2's P0-7 acceptance** ("pongs keep flowing while 256 PX-bearing blocks connect")
  has not been demonstrated. The existing test uses coinbase-only blocks and an idle pinger.

## 5. Implementation plan (phase 2)

Stage ordering follows R16-7 (Stage A, then Stage C) and SX2 P0-7. It is refined so that the
**P0 liveness items land first as small patches on the current mutex**, and the actor lands as
a pure scheduler change behind the equivalence harness. Nothing below changes consensus or
the node's identity.

### Stage 0: harness first (P0, S-M)

**Work items:**
- `SlowStore` test fixture: a `BlockStore` whose `append` sleeps a configurable time. It
  gives deterministic long holds with no production hook, following the precedent at
  `chain/tests/manager.rs:771`.
- Liveness tests L1-L6 (below), written against the **current** code. L1, L3 and L4 are
  expected to FAIL and are committed `#[ignore]`d with the finding id, then un-ignored by
  Stage 1.
- The differential/linearization harness **E1** (below), usable against both the mutex and
  the actor.

**Files:**
- new `chain/tests/support/slow_store.rs` (or inline);
- new `p2p/tests/liveness.rs`;
- new `chain/tests/actor_equivalence.rs`, which starts as a manager-only oracle.

Owner: 34 (all new files).

**Tests:**
- **L1:** same-peer pongs during a `GetHeaders` wait.
- **L2:** the same for `InvTx`/`Tx`.
- **L3:** the maintenance tick continues.
- **L4:** the handshake during a hold.
- **L5:** RPC `/info` answers in < 100 ms during a 40 s hold (node test through the router).
- **L6:** the blocking-thread count stays ≤ cap under a 1,000-request RPC burst during a hold
  (count via a semaphore probe, not tokio internals).

**Other fields:**
- Difficulty: S-M.
- Docs: none yet.

### Stage 1: liveness on the current mutex (P0, M)

All items are policy only, with no visible protocol change. Identity: none.

| Item | Change | Files (ownership) | Tests |
|---|---|---|---|
| 1a | Fast/slow lanes per connection. A per-peer slow-lane task (bounded mpsc, e.g. 32) runs `handle` for GetHeaders, GetBlocks, InvTx, GetTx, Tx, StemTx and empty Headers, in order. A full lane gives `score::RATE` and a drop. | `p2p/src/net.rs` `run_connection`, `handle` (**34**, in a window coordinated with 30/31/33) | L1, L2; all existing p2p tests |
| 1b | **Summary snapshot cell** (`RwLock<Arc<ChainSummary>>`), published by writers just before they release the mutex: `submit_block_in_steps` per step, `accept_headers`, `submit_tx`. The handshake, the maintenance tip and header height, `on_headers` empty replies and RPC `/info` read it. | new `chain/src/snapshot.rs` (**34**); `chain/src/manager.rs` adds only `summary(&self)` (**34**, append-only); `p2p/src/net.rs`; `node/src/lib.rs` `/info` (**36** reviews) | L3, L4, L5; a unit test: the summary equals the recomputed fields after each bounded-API step (reuses the `same_chain` helper) |
| 1c | RPC `/block`: `pow_jobs(&[header])` under a brief lock, then `compute_parallel` outside, then submit (the cache hits). Combined with 07's W2 seed gate. | `node/src/lib.rs` `submit_block` (**36** owns the handler; 34 supplies the pattern); `chain/src/manager.rs` gains no new logic (`pow_jobs` exists) | A counting `PowFunction`: 0 PoW calls under the lock (assert `CachedPow` hit on submit) |
| 1d | An RPC concurrency cap: `tokio::sync::Semaphore` (e.g. 16) around chain calls; beyond it → 503. | `node/src/lib.rs` (**36**) | L6 |
| 1e | Requires 12's W1/W2 (ring-digest fast revalidation) and 10's item 5 (cost-weighted step budget). 34 does not implement them. | owners 12, 10 | their tests, plus L1 with a heavy step |

- **Stage 1 docs:** `docs/p2p.md` §6 and §10 (correct F34-9; state the per-peer slow lane and
  the snapshot); `docs/blocks.md` §6 (the step-cost wording, with 10).
- **Bench:** pong-latency p50/p99 and the lock-hold histogram in labnet (**45** methodology;
  I4 instrumentation per decisions/09).
- **Difficulty:** M. **Priority: P0.** It closes F34-1/2/3/6 and most of the user-visible
  liveness problem even before the actor lands.

### Stage 2: the chain actor (P0 before the public testnet; P1 for the seven-device trial). L

**Change.** `ChainActor` plus `ChainHandle` (§3.6), in `chain/src/actor.rs`:
- lanes: 0 Stop, 1 Headers, 2 Blocks (drives `sync_step` itself), 3 Query, 4 Tx;
- `SharedChain` is removed from `p2p` and `node`;
- the actor publishes the full `ChainSnapshot`, which extends 1b's cell;
- the actor owns `submit_block_in_steps` semantics; RPC `/block` and the P2P block worker
  both send `SubmitBlock`;
- fail-stop: a drop guard in the actor thread calls `fatal` (exit 70) if
  `std::thread::panicking()`.

**Read-site migration table** (every current site):

| Site | Stage 2 source |
|---|---|
| `start` (tip, genesis); `run_connection`; maintenance tip; `on_headers` (empty); `/info` | snapshot |
| `request_headers_after` locator | snapshot `locator` |
| `schedule_downloads` | snapshot `missing_bodies` |
| `GetHeaders` (`headers_after`) | Query lane (index in Stage 3) |
| `on_get_blocks` | body index |
| `on_inv_tx`, `on_get_tx`, `admit_tx` pre-checks | Query lane (mempool in Stage 3) |
| `on_tx`, `on_stem_tx`, `fluff`, local `submit_tx` | Tx lane, one command each, keeping the in-hold atomicity |
| header worker | precheck/`pow_jobs` via Query; `accept_headers` via the Headers lane |
| block worker | Blocks lane |
| `/template` | Query lane (consistent with the pool; 09's 503 while `sync_pending`) |
| `/blocks`, `/outputs`, `/distribution`, `/px/*` | Query lane |
| `watch_store` | snapshot `store_failed` |

**Files:**
- new `chain/src/actor.rs`, `chain/src/snapshot.rs` (**34**);
- `chain/src/lib.rs` (a mod line);
- `chain/src/manager.rs`: `bodies: HashMap<Hash, Arc<Vec<Transaction>>>` (type only), plus
  `snapshot(&self)`. **34**, coordinated with 02/07/10/12/35, which edit the same file; the
  merge window goes in the order 02 W-4 → 10 items 1/5 → 34.
- `p2p/src/net.rs`: all chain sites, via a new `p2p/src/chain_access.rs` facade so later
  edits stay local (**34**);
- `node/src/lib.rs` (the handler bodies' chain calls only; **36** reviews);
- `node/src/main.rs` (spawn the actor; **34**, a small edit coordinated with 07/08/09 startup
  items).

**Tests:**
- **E1 differential.** A seeded random command script (bodies in random arrival order with
  gaps, header batches, reorgs, tx submits, templates) is run on (a) a bare `ChainManager`
  and (b) an actor with one producer. Compare tip, `connected`, `generated`, the state
  counters plus a digest of the output keys, `invalid`, mempool ids, the store bytes, and
  every `verdict`.
- **E2 linearization replay.** Four producer threads, random interleaving. The actor logs its
  applied command sequence (a test-only feature). Replaying the log on a bare manager gives
  identical final state and identical per-command replies. This is the linearizability check
  [herlihy-wing]. Use proptest where 41 adopts it (approved for chain); seeded ChaCha until
  then.
- **E3 snapshot consistency.** Every published snapshot equals `snapshot()` recomputed on the
  replayed manager at the same `seq`.
- **E4 replay equals live under the actor.** Restart from the store gives the same state as
  E1(a).
- **L1-L6 green**, with `SlowStore` stalls of 40 s, plus:
  - **L7:** header announcements are accepted within one step during a body drain (F34-7);
  - **L8:** a lane-full condition drops txs without penalty and never drops a requested
    block.
- **F1 fail-stop.** A subprocess test injects a panic in a command (a test-only command). The
  process exits with 70 and the store replays.
- **All existing** `p2p/tests/network.rs`, `chain/tests/*` and `node/tests/*` pass unchanged
  in verdict.

**Other fields:**
- Bench: actor step-duration histogram; snapshot publish cost (B2); read latency (B3); IBD
  throughput must not regress (±5 %) on a 2k-block regtest chain (**45**).
- Docs: `docs/p2p.md` §6 and §10 (the concurrency model rewritten); `docs/blocks.md` §5
  (a non-normative node-architecture note); an ADR under `docs/reviews/`, with **46**.
- **Difficulty: L.**

### Stage 3: header index, serving and the mempool out of the writer (P1, M-L)

- **Main-chain header index** read by `GetHeaders`, `locator`, precheck and `pow_jobs`
  without the actor.
  - Files: `chain/src/snapshot.rs`, `manager.rs` (an index update hook at header-best
    changes). It does **not** touch `consensus/src/chain.rs` semantics; the index mirrors
    `main_id_at`/`is_on_main`.
  - Test: the index equals `HeaderChain::main_id_at` after every command of E1, including
    header reorgs.
- **Mempool as its own component** (`Arc<Mutex<Mempool>>`, O(1)/O(k) critical sections),
  with validation outside the mempool lock.
  - Files: `chain/src/mempool.rs` (**12** owns; 34 does the plumbing), `manager.rs`.
  - Test: E1/E2 extended with mempool ids and the `select` output; 12's W6 stateful test.
- **Body serving from the store** where 35 lands an offset index (optional).

### Stage 4: verification outside the writer (P1, L)

1. **Tx check, verify outside, re-check and commit** (§3.6 item 5):
   - a verifier pool (`std::thread::scope` or a fixed pool of `min(4, cores − 1)` threads,
     the 10 decision);
   - a node-wide CLSAG token bucket sized to the pool (F34-5).
   - Files: new `chain/src/verify_pool.rs` (**34**), `tx/src/validate.rs` (a split
     `stateless_part` / `contextual_part` API: **11** owns the single-tx functions, 34
     consumes), `p2p/src/net.rs` (the Tx lane).
   - **Tests:**
     - **D1:** a differential over random txs, each with 0-2 injected faults per rule class.
       The (verdict, reported error) of snapshot-verify plus commit equals
       `validate_mempool_tx` on the commit state, including a reorg injected between verify
       and commit (ring-digest mismatch leads to a retry, not a penalty).
     - **A1 adversarial:** 72 peers flood young-ring invalid-signature transactions. The
       block-connection throughput of a concurrent 50-block drain stays ≥ 80 % of baseline,
       and verification never exceeds the node-wide budget.
2. **Block phase A/B inside the actor** (10's item 4). During phase B the actor serves the
   Query lane only.
   - Test: E1 with `--verify-threads` ∈ {1, 2, 8} gives identical results, and a Query issued
     during phase B is answered before phase B ends.
3. **PX proof pre-verification** of downloaded blocks through 10's `VerifiedCache` (item 6),
   keyed by the full tx id plus the domain plus the program ids. This happens before the
   block reaches the actor.
   - Test: 10's F10-6 tamper test; activation-boundary cache miss.

### Stage 5: later (P2/P3)

- A chunked append-only output/PX log in the snapshot, so RPC state pages bypass the actor.
- `/tip` long-poll via `on_publish` → `watch` (09).
- Actor metrics exported (**45**, I4).
- A Zebra-style per-fork validation overlay (02 W-10).

### Priority summary

| Stage | Priority | Size | Consensus | Identity |
|---|---|---|---|---|
| 0 (harness) | P0 | S-M | none | none |
| 1 (liveness patches) | **P0** | M | none (policy) | none |
| 2 (actor + snapshots) | **P0 public testnet** / P1 trial | L | none (scheduler only, proven by E1-E4) | none |
| 3 | P1 | M-L | none | none |
| 4 | P1 | L | none (verdict-equal, D1) | none |
| 5 | P2/P3 | M | none | none |

## 6. Dependencies and conflicts

| # | Workstream | Relation to 34 |
|---|---|---|
| **02** | fork-choice-reorgs | W-4 (skip reconnect re-verification) and the "never lighter" rule live in `sync_state`/`drain_ready`, the same functions the actor drives. W-4 lands **before** Stage 2. The actor must not alter the drain invariants. |
| **07** | randomx-cache-seed | W1 (out-of-lock cache builds) and W2 (the `/block` gate) are P0 and pair with Stage 1c. The `accepted_unstored` bound (W4) must stay compatible with "PoW never recomputed on the writer". |
| **09** | mining-templates | `/template` moves to the Query lane (a 503 while `sync_pending`). `/tip` long-poll needs Stage 2's `on_publish` hook. |
| **10** | block-validation-pipeline | Items 4 (phase A/B), 5 (cost budget, interim) and 6 (`VerifiedCache`) are Stage 4 building blocks. Item 5 is part of Stage 1e. |
| **11** | tx-validation | A split stateless/contextual API for Stage 4 (11 owns the single-tx functions). |
| **12** | mempool-architecture | W1/W2 (the bounded `finish_sync`) are prerequisites of Stage 1e. Mempool extraction (Stage 3) is co-owned. W6 stateful test. |
| **30, 31, 32, 33** | p2p | All edit `p2p/src/net.rs`. Proposal: 34 gets an **exclusive window** for 1a and for Stage 2's `chain_access.rs` facade; afterwards others edit only their logic, not chain calls. 31's presync and header-worker HOL (R8-15) interact with F34-7. 33's embargo timing depends on F34-2. |
| **35** | storage-recovery | Bodies as `Arc` and body serving from the store; replay stays outside the actor (at open, before the network starts). |
| **36** | rpc-security | Owns `node/src/lib.rs` handlers. Items 1c and 1d land through 36; the auth layer stays orthogonal. |
| **41** | fuzzing-property-stateful | proptest adoption for E2/D1; a stateful model. |
| **45** | benchmarks-scalability | Bench methodology for B1-B3 and pong latency. |
| **46** | architecture-consensus-separation | ADR placement; `chain_access.rs` and the actor as part of R16 Stage C. |
| **50** | red-team-integration | Adversarial review of the Stage 2 diff and of the D1 equivalence. |

## 7. Open questions for the coordinator

1. **Q1 (priority of Stage 2).** Is the actor P0 for the seven-device trial, or is Stage 1
   (lanes plus the summary cell) enough for the trial, with the actor P0 before any public
   testnet? My recommendation: Stage 0+1 P0 now, Stage 2 P0 for public.
2. **Q2 (`PONG_TIMEOUT`).** Should we raise it (e.g. 30 → 120 s) as belt-and-braces? Bitcoin
   uses 20 min [btc-net-h]. I lean *no* once Stage 1 lands. It hides stalls and slows
   dead-peer detection.
3. **Q3 (location).** Put the actor in `chain` (std-only, callback replies), which I
   recommend, or in a new `chain-service` crate between `chain` and `p2p`?
4. **Q4 (`net.rs` window).** Will you grant 34 an exclusive `p2p/src/net.rs` edit window for
   1a and the facade, ordered after 31's and 33's P0 edits or before them?
5. **Q5 (RPC semantics).** May RPC state queries (`/outputs`, `/blocks`, `/px/*`) be answered
   up to one step late (the Query lane), rather than in lock-step with the writer? Today they
   also wait a step, just blocked.
6. **Q6 (test-only command).** Is a test-only actor command (`#[cfg(any(test, feature =
   "test-hooks"))]`) for panic injection (F1) and log capture (E2) acceptable, or must these
   use external injection only (`SlowStore`, panicking `PowFunction`)?

## 8. Sources

**Bitcoin Core:**
- [btc-net-h] Bitcoin Core `src/net.h`, `TIMEOUT_INTERVAL{20}` minutes.
  https://github.com/bitcoin/bitcoin/blob/master/src/net.h
- [btc-chainstate] Bitcoin Core Doxygen, `Chainstate` / `ChainstateManager`
  (`ActivateBestChain` steps, `m_chainstate_mutex`).
  https://doxygen.bitcoincore.org/class_chainstate.html ;
  https://doxygen.bitcoincore.org/class_chainstate_manager.html
- Bitcoin Core commit 4e0eed8, "Allow ActivateBestChain to release its lock on cs_main".
  https://github.com/bitcoin/bitcoin/commit/4e0eed8
- Bitcoin Core PR #11824, "Block ActivateBestChain to empty validationinterface queue".
  https://github.com/bitcoin/bitcoin/pull/11824
- [btc-36244] Bitcoin Core PR #36244 (draft, 2026-09-14), "validation, net: Process blocks
  asynchronously and reduce cs_main contention" (PING/PONG 41.8 → 0.77 ms).
  https://github.com/bitcoin/bitcoin/pull/36244
- Bitcoin Core PR #35561, "net: move some CNodeState fields to Peer" (less cs_main).
  https://github.com/bitcoin/bitcoin/pull/35561 ; background:
  https://bitcoincore.academy/peer-state.html

**Zebra, reth and Monero:**
- [zebra-service] Zebra `zebra-state/src/service.rs` (`StateService`, `ReadStateService`: a
  watch channel of `NonFinalizedState`; reads ignore queued writes).
  https://github.com/ZcashFoundation/zebra/blob/main/zebra-state/src/service.rs
- reth staged sync: https://github.com/paradigmxyz/reth/blob/main/docs/crates/stages.md
- reth `CanonicalInMemoryState` (`Arc`-shared in-memory canonical state).
  https://reth.rs/docs/reth_chain_state/struct.CanonicalInMemoryState.html
- [reth-5228] reth issue #5228, MDBX freelist growth from long read transactions.
  https://github.com/paradigmxyz/reth/issues/5228
- Monero `blockchain.h`:
  - `mutable epee::critical_section m_blockchain_lock; // TODO: add here reader/writer lock`;
  - `prepare_handle_incoming_blocks` / `cleanup_handle_incoming_blocks`.

  https://github.com/monero-project/monero/blob/master/src/cryptonote_core/blockchain.h ;
  `blockchain.cpp` (threadpool `block_longhash_worker`; not fully re-read in this session):
  https://github.com/monero-project/monero/blob/master/src/cryptonote_core/blockchain.cpp

**Rust crates and advisories:**
- [arcswap-docs] arc-swap documentation. https://docs.rs/arc-swap/latest/arc_swap/
- [arcswap-208] arc-swap issue #208 (unwind-safety / double-decrement soundness).
  https://github.com/vorner/arc-swap/issues/208
- [arcswap-210] arc-swap issue #210 (a guard observing a freed-and-reused inner, 1.9.1).
  https://github.com/vorner/arc-swap/issues/210
- arc-swap issues #45 and #76. https://github.com/vorner/arc-swap/issues/45 ;
  https://github.com/vorner/arc-swap/issues/76
- [rustsec-251] RUSTSEC-2026-0251, `sized-chunks` is unmaintained.
  https://osv.dev/vulnerability/RUSTSEC-2026-0251
- [rustsec-292] RUSTSEC-2026-0292, `imbl-sized-chunks` double-free / use-after-free
  (advisory-db PR #3198). https://github.com/rustsec/advisory-db/pull/3198 ;
  index: https://rustsec.org/advisories/
- [std-rwlock] Rust std `RwLock` (the priority policy is OS-dependent; poisoning).
  https://doc.rust-lang.org/std/sync/struct.RwLock.html
- tokio runtime `Builder` (`max_blocking_threads` default 512).
  https://docs.rs/tokio/latest/tokio/runtime/struct.Builder.html

**Theory and background:**
- C. Hewitt, P. Bishop, R. Steiger, "A Universal Modular ACTOR Formalism for Artificial
  Intelligence", IJCAI 1973. https://www.ijcai.org/Proceedings/73/Papers/027B.pdf (not
  re-fetched)
- [herlihy-wing] M. Herlihy, J. Wing, "Linearizability: A Correctness Condition for
  Concurrent Objects", ACM TOPLAS 12(3), 1990. https://doi.org/10.1145/78969.78972 (not
  re-fetched)
- A. Ryhl (tokio maintainer), "Actors with Tokio", a pointer only.
  https://ryhl.io/blog/actors-with-tokio/
