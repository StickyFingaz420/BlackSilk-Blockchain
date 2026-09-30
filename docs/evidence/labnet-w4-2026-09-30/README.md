# Wave 4 labnet campaign (W4-LAB)

Internal engineering evidence, not an audit. One Windows machine, regtest, loopback,
light-mode miners with one thread each. Nothing here shows behaviour on a real
multi-machine network (docs/testnet.md §7), and nothing here is a claim that the
network is secure. No privacy claim is made about the labnet (decisions "RTW1B-2").

The campaign re-checks peer discovery after the P2P-FIX2 `GetAddr` floor, runs a long
honest network to difficulty equilibrium, partitions the network into unequal halves,
and runs a withholding miner. The adversarial part is an assessment of what the
tests already cover plus one live scenario (run 4); the adversary processes the labnet
still lacks are designed as follow-ups (§6).

## 1. Binaries, commands, machine

| Runs | Commit | Built as | Hashes |
|---|---|---|---|
| run1, run2 | `64d89d4` (rebuild/core) | release, clean tree (the node prints `commit 64d89d4a…`, no `-dirty`) | `runs/SHA256SUMS-64d89d4` |
| run3, run4 | `9b04827` (branch w4-lab) | release, clean tree (`commit 9b048275…`) | `runs/SHA256SUMS-9b04827` |

- `9b04827` changes only `tools/labnet` and `docs/testnet.md` against `64d89d4`: the
  node and miner sources are the same. Their binary hashes differ because the build
  commit is compiled into them.
- Toolchain: rustc 1.98.1, x86_64-pc-windows-msvc.
- `blacksilk-labnet-report` (added here) computed every propagation, stale-block and
  heal figure from the run files (`runs/<run>/report.json`), at commit `0af835f`.

**Common command** (each run's `--out`, `--base-port` and the differences below):
```
RUST_LOG="info,blacksilk_p2p::net=debug" blacksilk-labnet --bin-dir <bin> --out <dir> \
  --nodes 5 --latency-ms 20 --jitter-ms 10 --tx-every-secs 20 --miner-threads 1 --evidence
```

| Run | Differences | Partition groups | Started (UTC) | Duration |
|---|---|---|---|---|
| run1 | `--duration-mins 16 --partition-every-mins 7 --partition-mins 3 --base-port 51000` | {0,1} vs {2,3,4} | 2026-09-29 21:01 | 1734 s |
| run2 | as run1, `--base-port 52000` | {0,1} vs {2,3,4} | 2026-09-29 21:31 | 1788 s |
| run3 | `--duration-mins 50 --partition-every-mins 0 --base-port 53000` (no partitions) | none | 2026-09-29 22:11 | 4235 s |
| run4 | `--duration-mins 20 --partition-every-mins 4 --partition-mins 3 --partition-split 1 --base-port 54000` | {0} vs {1,2,3,4} | 2026-09-29 23:22 | 2189 s |

Every run: `summary.json` has `checks_passed: true`, `evidence: true`,
`evidence_notes: []`.

**Machine load (timing figures depend on it).** 4 cores, 16 GB, shared with a
single-core fuzzer and other agents' builds and tests. `load.csv` (a sample every 30 s):
run 3 CPU mean 55 % (7 to 100 %), another agent's `rustc` among the four busiest
processes in most samples; run 4 CPU mean 83 % (37 to 100 %). Runs 1 and 2 were not
sampled; the fuzzer and other agents were active then too. My own release and test builds
overlapped the warm-up of run 3 (release build before it, then a debug build and tests
of the report tool with one job). The CSV's first
column comes from PowerShell's `Get-Date -UFormat %s`, which here is about 7150 s ahead
of the system's Unix time: use it for order, not to align with the logs. Propagation
and stale-block figures below are from this loaded machine and are not a benchmark.

## 2. Late joiner after the GetAddr floor (task 1)

Each run ends with a fresh node that knows only node 0 (`--peer`, not connect-only,
`--max-outbound 4`), after the lab nodes stopped mining. The timeline is from
`node-late.log` (report field `late_joiner`).

| Run | First peer (node 0) | Node 0's `GetAddr` answer | All peers | Peers at the check |
|---|---|---|---|---|
| run1 | 0.27 s | 5 entries | 5 at 2.46 s | 5 |
| run2 | 0.27 s | 5 entries | 5 at 2.37 s | 5 |
| run3 | 0.27 s | 5 entries | 5 at 2.44 s | 5 |
| run4 | 0.27 s | 5 entries | 5 at 2.41 s | 5 |

- Every joiner learned all 5 lab nodes from node 0's single answer (the floor:
  `min(table, 8)` entries), then dialed within about 2.2 s: its 4 full-relay
  slots (node 0 and 3 others) and one block-relay-only connection, 5 peers in all.
- No joiner lost a peer before the harness stopped it (no `disconnected peer` line).
- Before the floor, INV-PEERS measured 1 entry per answer (23 % of a 4-entry table)
  and a joiner stuck at one peer in 7 of 32 runs, and at 2 peers in the evidence run.
- 4 of 4 joiners reached 5 peers within 2.5 s.
- Limits: 4 runs on one machine. The lab nodes are connect-only and advertise
  themselves (`--public-address`); a network whose reachable nodes do not advertise is
  not discovered (docs/p2p.md §9, by design).

## 3. Long honest run to difficulty equilibrium (task 2): run3

50 measured minutes with two miners and no partitions.

| Item | Value |
|---|---|
| Warm-up | 864 s, height 210, difficulty 14 |
| Measured phase | 3000 s, heights 210 to 544 (334 blocks) |
| Block interval, first / middle / last third | 8.0 s / 9.5 s / 9.7 s (target 10 s) |
| Tip difficulty, mean of first / middle / last third | 23.3 / 25.3 / 27.5 (range 14 to 32) |
| Miners' logged hash rate | 1.19 and 1.56 H/s in the first third, 1.66 and 1.66 H/s in the last |
| Reorganizations (all nodes) | 38: depth 1 × 37, depth 2 × 1 |
| Stale blocks | 43 of 377 found (11.4 %) |
| Templates abandoned on a new tip | 268 |
| Propagation (origin accept to last of 5 nodes, 289 uncontested blocks) | median 1028 ms, p90 1213 ms, max 1663 ms |
| Contested heights (two blocks seen) | 43 |
| Crashes, stuck incidents, misbehaviour disconnects | 0, 0, 0 |
| Transactions | 99 of 99 submitted; mempools drained at the end |
| Peak RSS per node | about 272 MB |

- **Equilibrium reached.** The last two thirds ran within 5 % of the target
  interval. The logged hash rate (about 3.3 H/s together) puts the exact equilibrium
  near D = 33. D was 27.5 in the last third and still rising slowly, following a
  hash rate that rose as the machine's load changed. The earlier finding (decisions
  "W2-09": D 9 to 12 against about 20, still rising after 16 minutes) is superseded
  for run lengths of about an hour.
- **Reorganizations at equilibrium are shallow:** 37 of 38 are one block, one is two.
- **Why blocks go stale (11 to 25 %):** propagation takes about 1 s at 20 ms per link.
  In run1, node 1 accepted the header of block 250 766 ms after its origin and the
  body 66 ms later. Most of that hop is the light-mode RandomX check of the header
  on a loaded CPU (the miners hash at about 1.7 H/s, so one light hash takes about
  0.6 s). A second hop doubles it. A race window of about 1 s against a 10 s target
  gives stale rates of about 10 to 25 %. On testnet (120 s) the same delay is a 12 times
  smaller share of the interval; that is arithmetic, not a measurement. A
  multi-machine run must measure it (docs/testnet.md §7).

## 4. Partitions with unequal halves (task 3): run1, run2

3-minute partitions of {0,1} (miner 0) against {2,3,4} (miner 1). Each half keeps one
miner, so both halves extend their own branch, and the heal must reorganize one of
them.

| Run | Heights just before the heal | Reorganizations at the heal (node: depth, s after the heal) | One tip everywhere |
|---|---|---|---|
| run1 | 280/280/277/277/277 | nodes 2, 3, 4: 8, 7, 8 (10.8 to 12.1 s) | first sample 20 s after the heal |
| run2 | 272/272/272/272/272 (equal heights, two tips) | nodes 0, 1: 15, 15 (5.5, 6.5 s); then all 4 other nodes 1 deep at 32 s (an ordinary race) | first sample 17 s after the heal |

- In run1 the smaller half's branch was heavier and the three-node half
  reorganized; in run2 both halves stood at height 272 and the two-node half, whose
  branch had less work, reorganized 15 blocks. Node count does not decide the winner;
  work does.
- Convergence is measured at the 15 s sampling interval: the first all-equal sample
  came 17 to 20 s after the heal, and the heal reorganizations themselves 5.5 to 12 s
  after it.
- No node got stuck and no peer was penalized. The about 100 `transport handshake
  failed` lines in runs 1 and 2 (none in run 3) all fall inside the partition windows:
  nodes redialing across a cut proxy link (connection reset). They are not scored.
- The node's warning `A reorganization this deep suggests a network partition` fired
  for the 15-block reorganizations (run2), as designed.
- Outside the heal windows every reorganization in runs 1 and 2 was 1 block deep.

## 5. Withholding miner (task 4d): run4

`--partition-split 1`: node 0 and miner 0 alone against nodes 1 to 4 and miner 1, three
3-minute partitions every 4 minutes. During each partition node 0's miner builds a
private branch, with the same hash rate as the rest of the network, and releases it
at the heal. The third partition was still up when the traffic phase ended; the end
checks healed it.

| Heal | Heights just before (node 0 / others) | Reorganizations (node: depth, s after the heal) | One tip everywhere |
|---|---|---|---|
| 1 | 258 / 254 | nodes 1 to 4: 11 each (8.6 to 10.6 s) | first sample 24 s after |
| 2 | 302 / 300 | nodes 1, 2, 3: 19, node 4: 18 (7.0 to 15.4 s); node 0: 1 at 33 s (a race) | first sample 36 s after |
| 3 (end checks) | 339 / 339 | node 0: 8, 8, 9 within 0.5 s (below) | converged 42 s after the end checks began |

- The released private branch won twice and lost once. Each time the losing side
  reorganized to the heavier branch, up to 19 blocks, the deepest of the campaign,
  and every node converged. No stuck incident, no crash, no penalty.
- **Heal 3, three reorganizations on node 0 in 0.5 s** (`runs/run4/node0.log`,
  23:55:24.967 to 23:55:25.472 UTC):
  1. node 0 received the other branch's blocks 333 to 340 and moved to them (8 deep);
  2. miner 0's block 341, found on node 0's old tip, came in by RPC and made the old
     branch heavier: back, 8 deep;
  3. the other branch's own block 341 arrived carrying more work: over again, 9 deep.

  Each step is fork choice by most work on the blocks known at that moment, not a
  flap between equal branches. The miner learns of a new tip only through its `/tip`
  long poll, so a block on the old tip can arrive after a reorganization.
- Found blocks: 187 after the warm-up, 128 on the final chain; 59 left it (32 %,
  mostly the losing branches of the three partitions).
- Transactions: 16 of 16 submitted; mempools drained, supply conserved.

This is the node side of block withholding: a released private branch is handled by
the fork-choice and reorganization paths. It is not a selfish-mining strategy (the
release time is the harness's, not the miner's), and it says nothing about the
incentives.

## 6. Adversarial campaign (task 4)

### 6.1 What the live runs show
- Across runs 1 to 4: **no penalty of any size** against an honest peer (0 `misbehaved (+`
  debug lines, 0 disconnects), on a machine loaded by other agents' builds. This is
  live evidence for the P2P-FIX2 fixes (an honest peer is not penalized because a node
  or link is slow), not proof.
- Partition heals are block-withholding events: each half withholds its branch from
  the other and releases it at the heal. Run 4 isolates one miner for that (§5).

### 6.2 What the tests already cover
The adversarial behaviours of the assignment are already tested in-process, on real
TCP, by `blacksilk-p2p` tests (names are test functions):

| Category | Tests |
|---|---|
| (a) Address flooding, eclipse | `eclipse_sim.rs` (the addrman v2 model: attacker share of *new*, *tried* and outbound slots under a Sybil flood, with feelers); `unsolicited_large_addr_batch_is_penalized`; `connection_policy.rs`: `full_inbound_evicts_an_unprotected_peer`, `low_ping_inbound_peers_survive_eviction`, `anchors_are_redialed_first_after_restart`, `block_relay_only_peers_get_no_addr_or_tx` |
| (b) Invalid, stale and oversized headers and blocks; malformed messages | `invalid_header_gets_the_peer_disconnected`, `malformed_messages_and_floods_are_cut_off`, `low_work_header_branches_are_not_hashed`, `a_deep_fork_unknown_version_header_claiming_max_difficulty_is_not_hashed`, `junk_header_batches_cost_at_most_one_chunk_of_proof_of_work`, `withheld_body.rs`, `transport_adversarial.rs` (oversized, drip-fed and undecryptable frames), `sync_policy.rs` (RandomX key abuse) |
| (c) A slow or stalling peer during sync | `liveness.rs` L1 to L7; `a_headers_reply_overtaken_by_a_second_request_is_not_penalized`; `a_late_transaction_answer_is_not_penalized`; `a_transaction_request_moves_on_when_its_peer_leaves` |
| (d) Withholding, a released private branch | `heavier_chain_wins_when_partitions_join`, `withheld_body.rs`, and the labnet heals (§4, §5) |

These run one node against a scripted peer. What the labnet does not have is an
adversary among real node processes over time.

### 6.3 Not built here, with a design (follow-ups, ranked)
Not built in this assignment: the machine was shared, and each scenario needs its own
evidence runs. A protocol-speaking adversary would link `blacksilk-p2p` into
`tools/labnet` (a workspace crate, no new dependency).

1. **Stalling sync peer (c), P1.** A labnet adversary that completes the handshake,
   claims a height above the tip, answers pings and never answers `GetHeaders` or
   `GetBlocks`. Start the late joiner with it as its first `--peer`, beside node 0.
   Measure the joiner's time to sync against a control joiner, and check the rotation
   away from it. Expected: sync from node 0, no penalty to node 0.
2. **Address flood against a discovering node (a), P1.** A victim node that is not
   connect-only (seeded by node 0), an adversary sending unsolicited `Addr` of
   addresses it listens on, then a victim restart. Measure the adversary's share of the
   victim's outbound slots against `eclipse_sim.rs`. Loopback limits it: with
   `--allow-private` the table groups unroutable addresses by the whole address, and
   loopback addresses are never banned (`ban_addr`), so group caps and bans cannot be
   tested on one machine. This needs several machines or network namespaces.
3. **Invalid data against a lab node (b), P2.** An adversary reconnecting and sending
   invalid-PoW header batches, undecodable messages and unrequested bodies, while the
   honest network runs. Measure the victim's CPU and memory, and check that honest
   peers are not disconnected. The same loopback limit applies: the adversary is
   disconnected but never banned, so it tests the per-connection cost only.
4. **Selfish miner (d), P3.** A miner controller that keeps its found blocks and
   releases them when the public chain catches up. It exercises the same node paths as
   the withholding run (§5); it matters for the incentive analysis (decisions,
   difficulty studies), not for node correctness.

## 7. Findings

- **No bug found** in the node, miner or P2P code across the four runs.
- **Labnet metric (fixed in the new report tool):** a propagation computed naively
  counted two kinds of block that were not relay delay: 194 s for a block mined 2 s
  before the partition and delivered at the heal, and 21 s for a block that lost a
  same-height race (node 1 fetched its body only when a child made it heavier; a
  1-block reorganization, correct fork choice). The report leaves out blocks whose
  delivery crosses a partition and heights with rival blocks (`contested_heights`).
- **Operational note:** propagation per hop is dominated by the light-mode header
  check on a loaded CPU (about 0.6 to 0.8 s here). Stale rates of 11 to 25 % on regtest
  follow from it.

## 8. Files
- `runs/<run>/`: `summary.json`, `metrics.csv` (every 15 s), `journal.log`, every node,
  miner and late-joiner log (info, p2p net at debug), `report.json`
  (`blacksilk-labnet-report`). Runs 3 and 4 also have `load.csv`.
- Node data directories are not included: `peers.json` holds the address table's
  secret key.
- `runs/SHA256SUMS-64d89d4`, `runs/SHA256SUMS-9b04827`: the binaries.
