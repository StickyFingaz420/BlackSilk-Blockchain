# Chain actor, Stage 2: design addendum (not implemented)

Internal engineering design for P0-A (research dossier 34, `C:/bszkeval/p2/research/
34-chain-actor-concurrency.md` §3.6 and §5; decisions "Agent 34"). It builds on Stage 1
(per-peer slow lane, published chain summary, chain-free maintenance loop; docs/p2p.md
§10). Nothing here is implemented yet, and nothing here changes consensus: the actor is a
scheduler for the same `ChainManager` methods. This is not an audit and claims no security
property that the tests below do not demonstrate.

## 1. Why Stage 1 is not the end

Stage 1 removed every *reader* that did not need the chain lock from the lock's path (read
loops, handshakes, locators, tip announcements, `/info`). What remains:

- Every chain *write* and most chain *reads* (`GetHeaders`, `GetBlocks`, mempool lookups,
  `/template`, `/blocks`, `/outputs`, `/px/*`) still wait on one unfair `std::sync::Mutex`.
  A hold is bounded in blocks, not time (F34-4).
- The header worker takes the lock three or more times per batch, each behind a block step
  (F34-7): header sync, including a competing tip, stalls during body connection.
- Relayed transaction verification (up to about 72 lanes) convoys with the block and header
  workers on the same mutex (F34-5).
- Nothing gives priority: a block step and a stream of transaction admissions are served in
  whatever order the OS wakes the waiters.

## 2. Design

One dedicated OS thread owns `ChainManager` by value. Nothing else can reach it, so no one
can wait on a mutex for it.

```
ChainHandle (Clone + Send + Sync)
  summary()  -> Arc<ChainSummary>     Stage 1 cell, extended into the Stage 2 snapshot
  send(cmd)  -> Result<(), Full>      bounded lanes, try_send only (never blocks a caller)
        |
        v
ChainActor thread (std::thread, owns ChainManager)
  loop:
    pick the next command by lane priority: 0 Stop, 1 Headers, 2 Blocks, 3 Query, 4 Tx
    run it: exactly one former lock closure, i.e. one ChainManager method call
    if a drain is pending: run ONE sync_step(budget), then look at the lanes again
    publish the snapshot (ChainManager::publish_summary, extended)
  panic => drop guard exits with POISONED_EXIT_CODE (70), as a poisoned lock does today
```

- **Location:** `chain/src/actor.rs`, std-only (decisions: the actor lives in `chain`;
  no `arc-swap`, no persistent collections). Lanes are `std::sync::mpsc::sync_channel`s.
  Replies go through a `Box<dyn FnOnce(R) + Send>` callback; the async side wraps a
  `tokio::sync::oneshot::Sender` in it, so `chain` gains no tokio dependency.
- **Commands** mirror the current closures one-to-one (the equivalence argument depends
  on it):
  - Headers lane: `PowJobs`/`Precheck` (read), `AcceptHeaders(batch)`;
  - Blocks lane: `SubmitBlock(block)` (P2P block worker and RPC `/block`); the actor
    itself continues a pending drain with `sync_step`, replacing `submit_block_in_steps`
    and its 1 ms fairness sleep;
  - Query lane: `HeadersAfter`, `Blocks(ids)`, `MempoolContains`, `MempoolGet`,
    `Template`, the RPC state pages;
  - Tx lane: `AdmitTx` (the current `on_tx`/`on_stem_tx` hold: tip check, `submit_tx`,
    `proven_invalid`, as ONE command), `Fluff`, `SubmitLocalTx`.
- **Sizing:** the Blocks lane holds at least the sum of all per-peer request windows plus
  `UNREQUESTED_QUEUE`, so a requested block is never dropped (today (64 + 8) × 3 + 8 =
  224). The Tx lane may drop (relay is best effort, never penalized). The Query lane is
  sized to the P2P slow lanes plus the RPC admission slots.
- **Snapshot:** Stage 1's `ChainSummary` grows the fields the read-site table below needs:
  `missing_bodies(256)`, the header-template base on the tip (difficulty, seed, minimum
  timestamp, version, reward), the next block's rule domain and epoch name, the PX record
  count and root. Published after every mutating command, in the same
  `RwLock<Arc<_>>` cell.
- **`SharedChain` goes away** from `p2p` and `node`: every chain site calls the handle,
  through a `p2p/src/chain_access.rs` facade so that later edits stay local.

### Read-site migration (every current site)

| Site | Stage 2 source |
|---|---|
| handshake, locator, empty `Headers`, maintenance tip, `/info`, `watch_store` | snapshot (done in Stage 1) |
| `schedule_downloads` | snapshot `missing_bodies` |
| `GetHeaders` (`headers_after`) | Query lane (header index in Stage 3) |
| `on_get_blocks` | Query lane (body index in Stage 3) |
| `on_inv_tx`, `on_get_tx`, `admit_tx` pre-checks | Query lane (mempool component in Stage 3) |
| `on_tx`, `on_stem_tx`, `fluff`, local `submit_tx` | Tx lane, one command each |
| header worker | `PowJobs` via the Headers lane, PoW outside, `AcceptHeaders` via the Headers lane |
| block worker, RPC `/block` | Blocks lane |
| `/template`, `/blocks`, `/outputs`, `/distribution`, `/px/*`, `/tx/status` | Query lane |

## 3. Ordering guarantees

1. **One writer, total order.** Commands run one at a time; the actor's execution order is
   the linearization order. Every command sees the effects of every command before it.
2. **Per-producer FIFO within a lane.** A producer's commands on one lane run in the order
   sent (`sync_channel` is FIFO). The P2P slow lane already serializes a peer's messages,
   so a peer's `GetHeaders` → `InvTx` order (test L6) is kept.
3. **No order across lanes beyond priority.** A higher lane's command may overtake an
   earlier lower-lane command. This is an order the mutex already allows (it is unfair),
   so it is not a new behaviour.
4. **Drain continuation.** Between two `sync_step`s the actor serves Headers, Blocks and
   Query commands. A body submitted mid-drain waits for the drain, exactly as
   `submit_block_bounded` defines today ("as if it had arrived after it"); the drain never
   pauses on a lighter tip (the rule lives in `ChainManager::sync_state`, unchanged).
5. **Snapshot monotonicity.** `seq` strictly increases; a snapshot is published after
   the command that produced it and before the actor takes the next one. A reader holding
   snapshot `k` sees the state after some prefix of the linearization, never a mix.
6. **Atomic compound operations stay single commands**: `AdmitTx` (tip + `submit_tx` +
   `proven_invalid`), `AcceptHeaders` for one chunk, `SubmitBlock`'s first bounded call.
   Flows that are already split over several holds today (`admit_tx`'s pre-checks, the
   header worker's precheck / jobs / accept) stay split; none of them relies on atomicity
   across holds today.
7. **Stop** is served between steps; a stop mid-drain is safe because every kept body is
   fsynced before it is applied and replay equals live.

## 4. Equivalence argument (summary of dossier 34 §3.6)

- Today every chain access is a closure under one mutex: every execution equals a
  sequential run of those closures in lock order.
- Every actor command is one of those closures with the same arguments, run
  sequentially. The actor's schedules are a subset of the schedules the mutex allows, so
  every actor execution is one the current code can produce.
- Consensus outputs (connected chain, state, invalid marks, store bytes) depend only on the
  sequence of submitted bodies and headers (body-complete determinism, replay equals live).
  For the same sequence the actor gives the same result.

Invariants that must not change: fsync before apply; replay equals live; a drain never
pauses on a lighter tip; the mempool never changes a block verdict; fail-stop on a writer
panic; the batch RNG is consumed only by the writer, in validation order; the actor never
takes the network-state lock or awaits P2P, and P2P never calls the actor while holding it.

## 5. Test plan

- **E1 (exists, `chain/tests/actor_equivalence.rs`).** Add the actor as a fourth driver:
  the same seeded scripts (bodies in random order with duplicates, header batches along
  random branch prefixes, a reorganization, an invalid body on a heavier branch) are sent
  from one producer through the handle. It must equal the oracle in every per-call result
  (as `stepped` must) and in final state: connected chain, header tip, outputs, PX root,
  invalid marks, kept bodies, mempool, exact store bytes, and every final verdict. Stage 1
  already checks that every driver's published summary describes its final state; the
  actor driver's snapshot must too.
- **E2 linearization replay.** Four producer threads send random interleavings; a
  test-only feature (decisions: never enabled in release; 43 adds the CI check) logs the
  applied command sequence. Replaying the log on a bare manager gives identical final
  state and identical per-command replies.
- **E3 snapshot consistency.** Every published snapshot equals the snapshot recomputed on
  the replayed manager at the same `seq`.
- **E4 replay equals live.** Restart from the actor's store gives E1's oracle state.
- **Liveness:** L1-L6 stay green; add L7 (a header announcement is accepted within one
  step during a body drain, F34-7) and L8 (a full Tx lane drops transactions without
  penalty and never drops a requested block).
- **F1 fail-stop.** A subprocess test injects a panic through the test-only command; the
  process exits with 70 and the store replays.
- **All existing** chain, p2p and node tests pass unchanged in verdict.
- **Bench:** actor step-duration histogram, snapshot publish cost, read latency; IBD
  throughput on a 2k-block regtest chain within ±5 % (methodology of dossier 45).

## 6. Order of work and ownership

Stage 2 lands after 02 W-4, 10 items 1/5 and 12 W1/W2 in `chain/src/manager*`
(decisions "Agent 34"). `chain/src/mempool.rs` and `chain/src/manager/template.rs` are
edited by CB-B2 at the time of writing; the actor needs no change in either (it calls
their existing methods), but the Query lane's `Template` command must wait for their
release. `node/src/lib.rs` handler bodies change only at their chain calls (36 reviews);
`node/src/main.rs` spawns the actor (a small, coordinated edit).
