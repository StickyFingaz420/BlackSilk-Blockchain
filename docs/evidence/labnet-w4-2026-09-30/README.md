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

The red-team review (RT-LAB) accepted this as honest-network and partition/withholding
evidence, with fixes. This revision makes every figure regenerable from the files
here (F3), adds the metrics RT-LAB asked for (F5), corrects three statements (F6) and
describes the stronger checks added to the labnet (F4, §7), which have not been run
yet. RT-LAB's two product findings, F1 (height-gated sync) and F2 (the announce tick),
are owned by another workstream (W4-SYNC) and are not discussed here.

## 1. Binaries, commands, machine

| Runs | Commit | Built as | Hashes |
|---|---|---|---|
| run1, run2 | `64d89d4` (rebuild/core) | release, clean tree (the node prints `commit 64d89d4a…`, no `-dirty`) | `runs/SHA256SUMS-64d89d4` |
| run3, run4 | `9b04827` (branch w4-lab) | release, clean tree (`commit 9b048275…`) | `runs/SHA256SUMS-9b04827` |

- `9b04827` changes only `tools/labnet` and `docs/testnet.md` against `64d89d4`: the
  node and miner sources are the same.
  - The miner binary is byte-identical in both builds (same hash in both files).
  - The node's hash differs: `node/build.rs` compiles the build commit into it.
  - The labnet's hash differs because its source changed.
- Toolchain: rustc 1.98.1, x86_64-pc-windows-msvc.

**The report.** Every propagation, arrival, stale-block, side-branch and heal figure
below comes from `runs/<run>/report.json`, produced by `blacksilk-labnet-report`:
- built in release mode from commit `7c44051` (clean tree; the tool has no build
  script, so the binary does not name its commit);
- SHA-256 of the binary used: `runs/SHA256SUMS-report-7c44051`;
- command, from the repository root, per run:
  ```
  blacksilk-labnet-report docs/evidence/labnet-w4-2026-09-30/runs/<run> \
    --store docs/evidence/labnet-w4-2026-09-30/runs/<run>/node0-blocks.dat \
    --json docs/evidence/labnet-w4-2026-09-30/runs/<run>/report.json
  ```
  These runs predate `final-chain.txt` in the labnet, so the first invocation
  derived `runs/<run>/final-chain.txt` from node 0's block store: the block with the
  most work, checked against the run's final height. Later invocations read the
  file.

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
`evidence_notes: []`. The topology is the default ring with chords, which with 5
nodes links every pair: each block reached every node over one direct link, and no
multi-hop propagation was measured.

**Machine load (timing figures depend on it).** 4 cores, 16 GB, shared with a
single-core fuzzer and other agents' builds and tests.
- `load.csv` (a sample every 30 s):
  - run 3: CPU mean 55 % (7 to 100 %); another agent's `rustc` was among the four
    busiest processes in most samples;
  - run 4: CPU mean 83 % (37 to 100 %);
  - runs 1 and 2 were not sampled; the fuzzer and other agents were active then too.
- My own builds overlapped the warm-up of run 3: a release build before it, then a
  debug build and the report tool's tests, with one job.
- The CSV's first column comes from PowerShell's `Get-Date -UFormat %s`, which here is
  about 7150 s ahead of the system's Unix time. Use it for order, not to align with
  the logs.
- The propagation and stale-block figures below are from this loaded machine and are
  not a benchmark.

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
  `min(table, 8)` entries). Within about 2.2 s it had 5 peers: its 4 full-relay
  slots (node 0 and 3 others) and one block-relay-only connection.
- No joiner lost a peer before the harness stopped it (no `disconnected peer` line).
- Before the floor, INV-PEERS measured 1 entry per answer (23 % of a 4-entry table).
  A joiner stayed at one peer in 7 of 32 runs, and had 2 peers in the evidence run.
- **What these runs do and do not show (RT-LAB F4).** The labnet's check then was
  "2 peers", which also passes without the floor. RT-LAB's discrimination runs
  (`C:/bszkeval/rt-lab-scratch/exp`, a 5-node replica, outside the repository) found:
  - with the floor reverted, the first answer had 2 entries instead of 5;
  - even so, 3 of 4 joiners still reached 5 peers, in 4.8 to 7.0 s, because the
    other peers' answers fill the table.

  So the answer size (the report's `late_joiner_getaddr_answer`) is the direct signal
  of the floor, and the peer count is not. In these four runs the answer size was 5,
  every entry of node 0's 5-entry table.
- The stronger checks now in the labnet (§7) have not been run.
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
| Found blocks after the warm-up, by id | 377: 375 in the connected phase (332 kept, **43 stale, 11.5 %**), 2 in the end checks (kept) |
| Side branches in node 0's store | 25, at most 2 blocks long |
| Templates abandoned on a new tip | 268 |
| Crashes, stuck incidents, misbehaviour disconnects | 0, 0, 0 |
| Transactions | 99 of 99 submitted; mempools drained at the end |
| Peak RSS per node | about 272 MB |

- **Equilibrium reached.**
  - The last two thirds ran within 5 % of the target interval.
  - The logged hash rate (about 3.3 H/s together) puts the exact equilibrium near
    D = 33. D was 27.5 in the last third and still rising slowly, following a hash
    rate that rose as the machine's load changed.
  - This supersedes, for runs of about an hour, the earlier finding (decisions
    "W2-09": D 9 to 12 against about 20, still rising after 16 minutes).
- **Reorganizations at equilibrium are shallow:** 37 of 38 are one block, one is two.
- **Stale blocks.** Propagation takes about 1 s over one 20 ms link (§5 has the
  figures).
  - In run1, node 1 accepted the header of block 250 766 ms after its origin, and the
    body 66 ms later. Most of that is the light-mode RandomX check of the header on a
    loaded CPU: the miners hash at about 1.7 H/s, so one light hash takes about 0.6 s.
  - With a race window of about 1 s against a 10 s target, 11 to 19 % of the blocks
    found in connected phases went stale (§5).
  - How the delay grows over more than one hop was not measured: every block here
    crossed one link. The ring topology (§7) is for that.
  - On testnet (120 s) the same delay would be a 12 times smaller share of the
    interval; that is arithmetic, not a measurement. A multi-machine run must measure
    it (docs/testnet.md §7).
- **A wallet sync refused once** (`runs/run3/journal.log`): `sync miner-b via node3:
  … the node is still synchronizing (346 of 347 blocks); try again later`. The
  harness's wallet asked node 3 while its connected chain was one block behind its
  best header (a body in flight). The wallet refuses to scan then. The harness skips
  that transaction slot, and the run's 99 transactions all went through.

## 4. Partitions with unequal halves (task 3): run1, run2

3-minute partitions of {0,1} (miner 0) against {2,3,4} (miner 1). Each half keeps one
miner, so both halves extend their own branch, and the heal must reorganize one of
them.

| Run | Heights just before the heal | Reorganizations at the heal (node: depth, s after the heal) | One tip everywhere |
|---|---|---|---|
| run1 | 280/280/277/277/277 | nodes 2, 3, 4: 8, 7, 8 (10.8 to 12.1 s) | first sample 20 s after the heal |
| run2 | 272/272/272/272/272 (equal heights, two tips) | nodes 0, 1: 15, 15 (5.5, 6.5 s); then all 4 other nodes 1 deep at 32 s (an ordinary race) | first sample 17 s after the heal |

- **The winner.** In run1 the smaller half's branch was heavier and the three-node
  half reorganized. In run2 both halves stood at height 272, and the two-node half,
  whose branch had less work, reorganized 15 blocks. Node count does not decide the
  winner; work does.
- **Convergence** is measured at the 15 s sampling interval: the first all-equal sample
  came 17 to 20 s after the heal, and the heal reorganizations themselves 5.5 to 12 s
  after it.
- **Run2, a 16-block side branch for a 15-block reorganization.**
  - Node 0 reorganized at 21:51:35.5.
  - 1 s later its miner's block 274, built on the old tip, arrived by RPC and was
    stored on the losing branch: work 216 against the final chain's 218 over the same
    heights (report `side_branches`).
  - The node stayed on the heavier chain. The miner learns of a new tip only through
    its `/tip` long poll.
- **No node got stuck and no peer was penalized.**
  - Runs 1 and 2 each have about 100 `transport handshake failed` lines (run 3 has
    none). All fall inside the partition windows: nodes redialing across a cut proxy
    link (connection reset). They are not scored.
  - The node's warning `A reorganization this deep suggests a network partition`
    fired for the 15-block reorganizations (run2), as designed.
  - Outside the heal windows every reorganization in runs 1 and 2 was 1 block deep.

## 5. Found blocks, propagation and arrivals, all runs (RT-LAB F5)

**Found blocks after the warm-up, by the phase in which they were mined** (report
`found_by_phase`, by block id against `final-chain.txt`; kept / stale):

| Run | connected | partition | heal | end checks | Stale, all phases |
|---|---|---|---|---|---|
| run1 | 102 / 13 (11.3 %) | 8 / 6 | 10 / 1 | 1 / 0 | 20 |
| run2 | 96 / 23 (19.3 %) | 16 / 15 | 11 / 3 | none | 41 |
| run3 | 332 / 43 (11.5 %) | none | none | 2 / 0 | 43 |
| run4 | 71 / 15 (17.4 %) | 42 / 38 | 13 / 5 | 2 / 1 | 59 |

- The per-run totals equal the earlier count-based figure: found blocks minus the
  final chain's blocks above the warm-up height (report `stale_after_warmup`).
- Partition-phase stale blocks are the losing partition branch.

**Propagation** (first to last sighting of a block every lab node logged, whole
delivery in a connected phase; median / p90 / max, ms):

| Run | Without contested heights | With contested heights | Contested heights |
|---|---|---|---|
| run1 | 88 blocks: 898 / 1031 / 1133 | 100 blocks: 908 / 1068 / 21144 | 20 |
| run2 | 73 blocks: 1039 / 1930 / 2283 | 96 blocks: 1599 / 2157 / 15427 | 41 |
| run3 | 289 blocks: 1028 / 1213 / 1663 | 332 blocks: 1035 / 1283 / 28937 | 43 |
| run4 | 54 blocks: 1345 / 1932 / 2465 | 70 blocks: 1364 / 2465 / 15435 | 59 |

**Arrivals** (per receiving node, from the origin's accept to the node's first
sighting; every block accepted in a connected phase, contested or not; report
`arrivals`):

| Run | Blocks | Seen by every node | All receivers: median / p90 / max (ms) |
|---|---|---|---|
| run1 | 115 | 102 | 896 / 1015 / 194041 |
| run2 | 119 | 96 | 1124 / 2000 / 15427 |
| run3 | 375 | 332 | 985 / 1199 / 28937 |
| run4 | 86 | 71 | 1225 / 1946 / 15435 |

- **The blocks some node never saw are exactly the stale ones.** In every run, the set
  of connected-phase blocks that at least one lab node never logged equals the set of
  connected-phase stale blocks, compared by id (13, 23, 43 and 15 blocks). A node that
  took the rival block first never fetches the loser's body, unless a child makes the
  loser's branch heavier.
- The per-node figures are in each `report.json` (`arrivals.receivers`). The origin
  nodes (node 0, and node `--partition-split`) receive only the other miner's blocks.
- **Long arrivals** are the ones the propagation table leaves out:
  - a rival body fetched only when its branch won (for example run1's block 303,
    21 s);
  - run1's 194 s arrival: block 272, mined 2 s before the partition and delivered at
    the heal. Arrivals filter only on the origin's phase, not on the delivery.

## 6. Withholding miner (task 4d): run4

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

- **Outcome.** The released private branch won twice and lost once. Each time the
  losing side reorganized to the heavier branch, up to 19 blocks, the deepest of the
  campaign, and every node converged. No stuck incident, no crash, no penalty.
- **Heal 2, a block refused at the RPC** (`runs/run4/node1.log`, `miner1.log`,
  23:49:19.580 UTC):
  - node 1 reorganized 19 blocks at 23:49:19.073;
  - 0.5 s later miner 1 submitted block 303, built on node 1's old tip;
  - node 1 refused it: `NotNearTip: the parent must be the tip (305) or one of its
    last 8 ancestors on the connected chain`. The miner logged `block 303 rejected`
    and continued on the new tip.

  It is the one RPC refusal of the campaign (report `refused_at_rpc`).
- **Heal 3, three reorganizations on node 0 in 0.5 s** (`runs/run4/node0.log`,
  23:55:24.967 to 23:55:25.472 UTC). Node 0's branch and the other branch fork above
  height 332. The work above 332, from node 0's store (report `side_branches`, the
  branch with tip `f6179eb2…`; RT-LAB derived the same four figures from the same store
  with its own parser), was:
  1. node 0 received the other branch's blocks 333 to 340 (work 139 against its own
     134) and moved to them: 8 deep;
  2. miner 0's block 341, found on node 0's old tip, came in by RPC. It made the old
     branch heavier (150 against 139): back, 8 deep;
  3. the other branch's own block 341 arrived (154 against 150): over again, 9 deep.

  Each switch went to the branch with more work among the blocks known at that
  moment: 134 < 139 < 150 < 154. The miner learns of a new tip only through its `/tip`
  long poll, so a block on the old tip can arrive after a reorganization.
- **Found blocks:** 187 after the warm-up; 59 stale, 38 of them the losing partition
  branches (§5).
- **Transactions:** 16 of 16 submitted; mempools drained, supply conserved.

This is the node side of block withholding: a released private branch is handled by
the fork-choice and reorganization paths. It is not a selfish-mining strategy (the
release time is the harness's, not the miner's), and it says nothing about the
incentives.

## 7. The labnet's stronger checks (RT-LAB F4), not yet run

Added to `tools/labnet` in `7c44051` and unit-tested. The runs are scheduled by the
Lead in a quiet window, the relay run with W4-SYNC's fix.
- **Late joiner:** it must reach min(`--late-max-outbound` + 1, nodes) peers (default
  5) within `--late-peers-secs` (default 120) of its start: its outbound slots plus a
  block-relay-only connection, or every node. The four runs above would pass it (5
  peers in under 2.5 s). By RT-LAB's data it still separates the floor weakly (§2),
  so the report prints the answer size.
- **Address relay, RT-LAB E2 (`--relay-joiners K`):**
  - A second joiner starts, knowing only node 0, with room for every node.
  - Once it has asked the lab nodes for addresses, K relay nodes join, dialing only
    node 0. The joiner can learn them only by address relay.
  - The check: it connects to every relay node within `--relay-wait-secs`.
  - RT-LAB's runs of the same design: with relay, the joiner reached 5 peers in about
    40 s; with relay switched off, it stayed at 2.
- **Multi-hop propagation:** `--topology ring` (node i dials i+1 only; a block crosses
  up to n/2 hops).
- **A table larger than 8 entries:** `--nodes 10` or more (up to 40), so the late
  joiner's answer is the 23 %-or-at-least-8 sample.
- `final-chain.txt` is written by every run from now on.

## 8. Adversarial campaign (task 4)

### 8.1 What the live runs show
- Across runs 1 to 4: **no penalty of any size** against an honest peer (0 `misbehaved (+`
  debug lines, 0 disconnects), on a machine loaded by other agents' builds. This is
  live evidence for the P2P-FIX2 fixes (an honest peer is not penalized because a node
  or link is slow), not proof.
- Partition heals are block-withholding events: each half withholds its branch from
  the other and releases it at the heal. Run 4 isolates one miner for that (§6).

### 8.2 What the tests already cover
The adversarial behaviours of the assignment are already tested in-process, on real
TCP, by `blacksilk-p2p` tests (names are test functions):

| Category | Tests |
|---|---|
| (a) Address flooding, eclipse | `eclipse_sim.rs` (the addrman v2 model: attacker share of *new*, *tried* and outbound slots under a Sybil flood, with feelers); `unsolicited_large_addr_batch_is_penalized`; `connection_policy.rs`: `full_inbound_evicts_an_unprotected_peer`, `low_ping_inbound_peers_survive_eviction`, `anchors_are_redialed_first_after_restart`, `block_relay_only_peers_get_no_addr_or_tx` |
| (b) Invalid, stale and oversized headers and blocks; malformed messages | `invalid_header_gets_the_peer_disconnected`, `malformed_messages_and_floods_are_cut_off`, `low_work_header_branches_are_not_hashed`, `a_deep_fork_unknown_version_header_claiming_max_difficulty_is_not_hashed`, `junk_header_batches_cost_at_most_one_chunk_of_proof_of_work`, `withheld_body.rs`, `transport_adversarial.rs` (oversized, drip-fed and undecryptable frames), `sync_policy.rs` (RandomX key abuse) |
| (c) A slow or stalling peer during sync | `liveness.rs` L1 to L7; `a_headers_reply_overtaken_by_a_second_request_is_not_penalized`; `a_late_transaction_answer_is_not_penalized`; `a_transaction_request_moves_on_when_its_peer_leaves` |
| (d) Withholding, a released private branch | `heavier_chain_wins_when_partitions_join`, `withheld_body.rs`, and the labnet heals (§4, §6) |

These run one node against a scripted peer. What the labnet does not have is an
adversary among real node processes over time.

### 8.3 Not built here, with a design (follow-ups, ranked)
Not built in this assignment: the machine was shared, and each scenario needs its own
evidence runs. A protocol-speaking adversary would link `blacksilk-p2p` into
`tools/labnet` (a workspace crate, no new dependency).

1. **Stalling sync peer (c), P1.**
   - The adversary completes the handshake, claims a height above the tip, answers
     pings and never answers `GetHeaders` or `GetBlocks`.
   - Start the late joiner with it as its first `--peer`, beside node 0.
   - Measure the joiner's time to sync against a control joiner, and check the
     rotation away from it.
   - Expected: sync from node 0, no penalty to node 0.
2. **Address flood against a discovering node (a), P1.**
   - A victim node that is not connect-only (seeded by node 0), and an adversary
     sending unsolicited `Addr` of addresses it listens on; then a victim restart.
   - Measure the adversary's share of the victim's outbound slots against
     `eclipse_sim.rs`.
   - Loopback limits it: with `--allow-private` the table groups unroutable addresses
     by the whole address, and loopback addresses are never banned (`ban_addr`). Group
     caps and bans cannot be tested on one machine; this needs several machines or
     network namespaces.
3. **Invalid data against a lab node (b), P2.**
   - An adversary reconnecting and sending invalid-PoW header batches, undecodable
     messages and unrequested bodies, while the honest network runs.
   - Measure the victim's CPU and memory, and check that honest peers are not
     disconnected.
   - The same loopback limit applies: the adversary is disconnected but never banned,
     so this tests the per-connection cost only.
4. **Selfish miner (d), P3.**
   - A miner controller that keeps its found blocks and releases them when the public
     chain catches up.
   - It exercises the same node paths as the withholding run (§6). It matters for the
     incentive analysis (decisions, difficulty studies), not for node correctness.

## 9. Findings

- **In node, miner and P2P code:** none by W4-LAB in the four runs. RT-LAB's review
  of the same logs found F1 and F2 (owned by W4-SYNC).
- **Labnet metric (fixed in the report tool):** a propagation computed naively counted
  two kinds of block that were not relay delay:
  - 194 s for a block mined 2 s before the partition and delivered at the heal;
  - 21 s for a block that lost a same-height race (node 1 fetched its body only when a
    child made it heavier; a 1-block reorganization, correct fork choice).

  The report now shows both variants and the arrivals (§5).
- **Operational note:** propagation over one link is dominated by the light-mode
  header check on a loaded CPU (about 0.6 to 0.8 s here). Connected-phase stale rates
  of 11 to 19 % on regtest follow from it.

## 10. Files
- `runs/<run>/`:
  - `summary.json`, `metrics.csv` (every 15 s), `journal.log`;
  - every node, miner and late-joiner log (info level, `blacksilk_p2p::net` at debug);
  - `node0-blocks.dat`: node 0's block store, the source of `final-chain.txt` and
    `side_branches`;
  - `final-chain.txt`: `height id` of the final chain;
  - `report.json`: `blacksilk-labnet-report` output (§1);
  - runs 3 and 4 also have `load.csv`.
- **Not included:** the other files of the node data directories. `peers.json` holds
  the address table's secret key.
- **Binary hashes:** `runs/SHA256SUMS-64d89d4` and `runs/SHA256SUMS-9b04827` (the run
  binaries), `runs/SHA256SUMS-report-7c44051` (the report tool).
