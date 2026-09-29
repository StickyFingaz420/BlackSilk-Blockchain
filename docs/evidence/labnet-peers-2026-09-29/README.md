# Late joiner peer discovery (INV-PEERS)

Internal engineering evidence, not an audit. One machine, regtest, light-mode miners,
loopback. It shows why the W4-RX labnet's late joiner stayed with one peer, what was
changed, and a labnet run after the change. It does not show discovery on a real,
multi-machine network (docs/testnet.md §7).

## The observation (W4-RX, docs/evidence/rx-fullmode-seedswitch-2026-09-29)
- The late joiner (`--peer` node 0 only) synced all 2835 blocks from node 0 but never
  opened a second connection in 900 s, so `checks_passed` was false.
- Its log has no dial attempts. (That build logged no line for address messages, so
  the log could not show whether one arrived.)
- Earlier labnets reached 3 peers.

## Root cause
Found in the run's data directories (`C:/bszkeval/w4-rx/run2`) and in the code.

1. **No labnet node advertised itself.**
   - `tools/labnet` never passed `--public-address`.
   - A node without it is never advertised (docs/p2p.md §9, by design: private nodes
     are not revealed). No node ever entered another node's address table.
2. **Addrman v2 no longer learns dialed addresses** (W3-32, d45ccbd).
   - Before v2, `mark_good` inserted every address the node dialed successfully into
     *tried*. Node 0 held its three proxy links, answered the joiner's `GetAddr` with
     them, and the joiner dialed them. That is how earlier labnets reached 3 peers.
   - Since v2, `AddrMan::good` promotes only an address the table already holds, as in
     Bitcoin Core. It is also a privacy gain: a `GetAddr` answer no longer reveals the
     addresses a node dialed.
3. **Node 0's table stayed empty for the whole 7-hour run.**
   - No data directory of that run has a `peers.json`. The table is saved only when its
     size changes (`maintenance_loop`), so none of the five tables ever held an entry.
   - So node 0's answer to the joiner can only have been an empty `Addr` (inferred:
     that build did not log it), and the joiner had nothing to dial.
   - Neither the seeds nor feelers apply: labnet passes `--no-builtin-seeds` and no
     `--seed`, and feelers need a full set of outbound slots.

**Found while testing the fix: a second fault, in the p2p code.**
- A node stored its own address when a peer relayed it back.
- A `GetAddr` answer holds at most 23 % of the table, rounded up: 1 entry of a 3- or
  4-entry table. On a small network that one entry was often the node's own address,
  which is useless to the asker.
- With advertised addresses, a joiner that knew one node of a 4-node mesh still stayed
  with one peer in **7 of 32 runs** on the base code (`tests/base-onepeer-12x.log`: 3 of
  12; `tests/base-onepeer-20x-stale-build.log`: 4 of 20).
- The second file's name marks a build accident: the fix had been restored with an old
  timestamp, so cargo tested the base build.

**Candidates from the assignment that were ruled out:**
- The joiner's connection to node 0 is full-relay (`--peer`): `GetAddr` is sent, and
  node 0 answers because the joiner is inbound to it.
- `maintain_outbound` does not think it is full. The RTW3-2 count is correct; its
  existing test passes.
- One-shot seeds do not apply: labnet uses no seeds.
- Loopback grouping does not apply. With `allow_private`, the table groups unroutable
  addresses by the whole address, and dials skip the group filter.
- The one-*tried*-entry-per-IP rule costs nothing here: it moves the previous
  127.0.0.1 entry back to *new*, and the connection stays up.

## Labnet-only or real-network?
- **The empty table is a labnet configuration fault.** A real network's reachable
  nodes must set `--public-address` to be discovered. docs/testnet.md now says so for
  every node that accepts inbound connections, not only seeds.
- **The own-address fault is real-network behaviour.** It hurt small networks (few
  table entries), such as an early testnet.
- **Remaining limitation, not fixed here: small networks.**
  - Each answer carries 23 % of the answering table.
  - Each outbound peer is asked once.
  - Seeds are asked only while fewer than 2 full-relay peers are up (or the table is
    empty, or the tip is stale).
  - So on a small network a joiner can stop below its outbound target. In a trial
    (4 advertised nodes, joiner with one seed, target 4), it filled its 4 slots in only
    3 of 6 base runs within 60 s. That trial test was not kept; its runs are not
    evidence, only the reason for this section.
  - A trial change that asked the seeds again, while a free slot found no address, did
    not solve it: the seed itself becomes a full-relay peer (it advertises itself) and
    is not fetched again while connected. The change was withdrawn.
  - Options for the Lead: a floor on the answer size for small tables, a periodic
    self-advertisement, or a periodic address fetch. Each has privacy trade-offs.

## Changes (commit a4caa1c, branch `inv-peers`)
- `tools/labnet`: every node passes `--public-address 127.0.0.1:<its P2P port>`. The
  lab nodes stay connect-only, so their links still go only through the proxies, and
  partitions stay complete. The late joiner dials the direct ports after the run.
- `p2p/src/net/addr_relay.rs`:
  - `on_addr` relays the node's own address like any other entry, but does not store
    it.
  - New debug lines: `peer N: addr with K entries` and `peer N: getaddr answered with K
    addresses`.
- `docs/p2p.md` §9: the own-address rule, and "discovery depends on
  `--public-address`". `docs/testnet.md`: the operator note on `--public-address`.

## Tests
| Test | Base 693dd95 | After |
|---|---|---|
| labnet `every_node_advertises_its_own_port` | fails: no `--public-address` (`tests/base-labnet.log`) | passes |
| p2p `a_node_does_not_store_its_own_address` | fails: table (2, 0), own address stored (`tests/base-own-addr.log`) | passes |
| p2p `a_joiner_with_one_peer_reaches_the_advertised_nodes` | fails 7 of 32 runs | passes 25 of 25 (`tests/fixed-onepeer-25x.log`) |
| p2p `nodes_that_do_not_advertise_are_not_discovered` | passes (documents the design) | passes |

**Eclipse simulator (`p2p/tests/eclipse_sim.rs`, release build, `--nocapture`).**
- Its printed output is byte-identical before and after (`tests/eclipse-sim-output.txt`).
  Its 4 tests pass.
- It drives `AddrMan` and the address gate directly, so the change cannot reach it.
- The W3-32, W3-32c and RT-W3 protections are untouched: bucketing, caps, bias, the
  gate, relay and the answer size.

## The labnet run (`run/`)
**Binaries:**
- Built from a4caa1c with `BLACKSILK_BUILD_COMMIT=a4caa1c` (the node log prints it).
- Hashes are in `run/SHA256SUMS`.
- Toolchain: rustc 1.98.1, x86_64-pc-windows-msvc, release profile.

**Command:**
```
RUST_LOG="info,blacksilk_p2p::net=debug" blacksilk-labnet --bin-dir <bin> --out <dir> \
  --nodes 4 --duration-mins 16 --latency-ms 20 --jitter-ms 10 \
  --partition-every-mins 7 --partition-mins 3 --tx-every-secs 20 \
  --base-port 49000 --miner-threads 1 --evidence
```

**Machine:** shared with a release build of the eclipse simulator during the warm-up.

**Result:** `summary.json`: `checks_passed: true`, `evidence: true`, `evidence_notes: []`.

| Item | Value |
|---|---|
| Warm-up | 702 s, ended at height 219, difficulty 17, mean interval 8.6 s |
| Measured phase | 960 s, one 3-minute partition |
| Final height | 347; converged, mempools drained |
| **Late joiner** | **synced, 2 peers** |
| Wallet restores against the late joiner; supply | all 5 match; conserved |
| Crashes, stuck incidents, misbehaviour disconnects | 0, 0, 0 |
| Reorganizations after the warm-up | 17: depth 1 × 15 (connected), depth 18 × 2 (partition heal) |

**Late joiner timeline** (`run/node-late.log`):
| Time (UTC) | Event |
|---|---|
| 09:55:07.386 | starts, knowing only node 0 (127.0.0.1:49001) |
| 09:55:07.646 | connected to node 0 |
| 09:55:07.646 | two one-entry `Addr` messages arrive: node 0's `GetAddr` answer and its self-advertisement |
| 09:55:09.785 | connected outbound to node 3 (127.0.0.1:49061), a direct port it learned: 2 peers, 2.4 s after start |

- The labnet's check ends as soon as the joiner has 2 peers, so the run does not show
  how many more it would reach.
- At the end of the run, node 0's table held node 1, node 2, node 3 and the late joiner
  (`run/node0-table.txt`, taken from its `peers.json`). Its own address was not in it.
- The file keeps only the addresses: `peers.json` also holds the table's secret key.

## Files
- `run/`:
  - the run's summary, journal, metrics, every node and miner log (info level, p2p net
    at debug);
  - `node0-table.txt`;
  - `SHA256SUMS`.
- `tests/`: the base-failure logs, the repeated-run logs, and the eclipse simulator
  output.
