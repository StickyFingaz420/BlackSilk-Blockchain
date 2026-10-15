# Labnet reruns A and B on v3 code (freeze-gate step 6)

Internal engineering evidence, not an audit. One Windows machine, regtest, loopback,
light-mode miners with one thread each. Nothing here shows behaviour on a real
multi-machine network (docs/testnet.md §7), and nothing here is a claim that the
network is secure. No privacy claim is made about the labnet (decisions "RTW1B-2").

Commit `66f12f0761c80f13c493f2c752d2f511511f3303` (rebuild/core). These runs are the
quiet-window reruns that decisions "W4-GUARD" schedules to supersede W4-LAB runs 3–4
(ring topology, address relay, the stronger late-joiner check, guarded binaries).

## 0. Acceptance bounds (fixed by the Lead before the runs; recorded here before run A started)

A run passes only if all of the following hold. Anything outside them is reported as
a finding; no run is repeated to make it pass. Environmental failures (a port bind
before any node starts; a start timeout tied by load.csv to outside load) may be
rerun once with a new `--out` and base port, recorded and labelled.

- labnet exit status 0 with `--evidence`;
- `summary.json`: `checks_passed`, `evidence: true`, `evidence_notes: []`,
  `crashes: []`, `stuck_incidents: 0`, `misbehavior_disconnects: 0`,
  `converged_at_end`, `mempools_drained_at_end`, `late_joiner_synced`,
  `late_joiner_peers >= late_joiner_required_peers` (5),
  `late_joiner_secs_to_required <= 120`, `relay_discovery.all_reached`,
  `fresh_wallet_balances_match`, `fresh_wallet_px_balances_match`,
  `supply_conserved`, `warmup.reached`;
- `binaries.*.version` names `66f12f0` without `-dirty`, says `build flags: none`, and
  each `sha256` equals `SHA256SUMS-66f12f0`;
- `report.json`: ~~`late_joiner_getaddr_answer >= 8`~~ (**superseded**, see 0.1); every
  final-chain block reached all 12 lab nodes;
- log greps: `RandomX self-test passed` in every node log; zero honest-block
  `is invalid`, zero `misbehaved (+`, zero `inbound limit reached`, zero
  panic / `ERROR` / halt;
- reorganization depth, connected phase: run B ≤ 2 deep (as W4); run A (12-node
  ring, up to 6 hops) ≤ 4 deep (Lead's pre-set bound; the actual distribution is
  recorded);
- propagation and heal: per-hop arrival figures recorded (A, against ring distance
  from the miners) and heal seconds (B). Sanity bounds: median block arrival at the
  farthest node ≤ 30 s (A); every heal reaches one tip within 120 s of the partition
  ending (B); side-branch work strictly increasing at each switch; no reorganization
  to a lower-work branch.

### 0.1 Bound change (Lead decision received 2026-10-15 between 06:55 and 07:11 UTC; recorded here before run A started at 07:14:01 UTC)

- **Superseded:** `late_joiner_getaddr_answer >= 8`.
- **Reason:** the smoke run (§3) answered 3, which was node 0's whole table. On the
  `ring` topology node 0 learns only a few lab addresses, so ≥ 8 tests the topology,
  not the protocol rule.
- **New bound:** the answer equals the protocol rule applied to node 0's table at the
  time of the request. The rule is `AddrMan::get_addr` (p2p/src/addrman.rs:843-846,
  constants :103 and :110):
  ```
  let total = self.entries.len();
  let pct = (total * GETADDR_MAX_PCT).div_ceil(100);      // GETADDR_MAX_PCT = 23
  let n = max.min(pct.max(GETADDR_MIN.min(total)));       // GETADDR_MIN = 8, max = 1000 (addr_relay.rs:51)
  let n = n.min(all.len());                               // all = entries not "terrible"
  ```
  So the expected answer is `min(1000, max(ceil(0.23 T), min(8, T)))`, capped by the
  non-terrible entries. For T ≤ 34 that is `min(8, T)`. The answer is then filtered by
  routability (every entry passes with `--allow-private`) and bans (loopback is never
  banned).
- **How T is measured:** node 0's table size T is taken from its `peers.json` entry
  count. The node saves the file within 60 s of any change in table size
  (p2p/src/net/maintenance.rs:101, :269-278). A poller reads only the count every 5 s
  into `node0-table.csv`; the file itself, which holds the table's secret key, is not
  copied. T at the request is the count from the entries' first-seen times up to the
  request, cross-checked against the poller.
- **If T never exceeds 8 in a run,** the "table larger than 8 entries" check is
  recorded as NOT EXERCISED for that run: not passed, not failed.
- All other bounds are unchanged.

## 1. First prerequisite check (06:49 UTC): runs NOT started (superseded by §5)

Phase 2 prerequisites, checked after CI completed:

| Prerequisite | Result |
|---|---|
| CI run 38683469356 at `66f12f0` | PASS: every job success, `zkvm-stress` skipped (`build/ci-38683469356.txt`; `test` finished about 06:49 UTC) |
| No cargo / rustc / rust-analyzer / clippy / cargo-mutants | PASS (none) |
| CPU < 10 % over 2 min | PASS: 1.6 % (06:18–06:20 UTC) |
| Available memory ≥ 10 GB | **FAIL: 6,466 MB (06:10), 6,485 MB (06:20), 6,330 MB (06:49)** |
| No Chrome processes | **FAIL: 37 (06:20), 36 (06:49)** |
| Sleep | PASS: AC standby 0 (never), hibernate 0, no battery; Balanced scheme `381b4222-…` |
| Windows Update | `wuauserv` Stopped/Disabled, `WaaSMedicSvc` Disabled, `UsoSvc` Running/Manual; CBS RebootPending and WU RebootRequired absent; `PendingFileRenameOperations` present |
| Defender | `WinDefend` Stopped/Disabled; RealTimeProtectionEnabled False, AntivirusEnabled False, AMServiceEnabled False; ScanScheduleDay 0, ScanScheduleTime 02:00 local (inactive with the service off) |
| Other scheduled load | `\Microsoft\VisualStudio\Updates\BackgroundDownload` every 3 h (05:01, 08:01, 11:01 … local, UTC+2); it used about 100 CPU-seconds at 06:01 UTC, during the smoke |
| Firewall | Domain, Private, Public profiles enabled |
| Time | `w32tm /query /status`: Leap 3 (not synchronized), Source Free-running System Clock, before and after |
| TCP port exclusions | 5357, 50000–50059 only; the planned ranges 34000–36451 and 38000–40451 are free |

The memory and Chrome failures are outside load this agent did not start and may not
stop. The runs wait until the owner frees the machine.

## 2. Build

- Worktree `C:/bszkeval/labnet-v3/src`, detached at `66f12f0761c80f13c493f2c752d2f511511f3303`,
  `git status --porcelain` empty before and after the build.
- `bash tools/release-build.sh -p blacksilk-node -p blacksilk-miner -p blacksilk-labnet`,
  `CARGO_TARGET_DIR=C:/bszkeval/labnet-v3/target` (own, empty), `CARGO_BUILD_JOBS=2`,
  `CARGO_INCREMENTAL=0`, `BLACKSILK_BUILD_COMMIT=66f12f0…` (no `-dirty`), no
  `RUSTFLAGS` / `BLACKSILK_ALLOW_DIRTY`. 05:52:30–05:58:28 UTC, 238 crates compiled,
  neither `tempfile` nor `proptest` (`build/build.log`). No `cargo test` into this target.
- rustc 1.98.1 (48a229cea 2026-09-01), host x86_64-pc-windows-msvc, LLVM 22.1.8;
  cargo 1.98.1 (797e8a9bc 2026-08-05).
- `tools/check-build-flags.sh --strings bin/*.exe`: exit 0, every binary "no test-only code".
- `build/SHA256SUMS-66f12f0`:
  - node `c04129f93691c330000487230304ea596ea08be0d79a50733ea04a4832dcc669`
  - miner `1330886d7c3546850ca539306c2a9a485f4f75d6f7eab67966b0efb69066149b`
  - labnet `6148dc2d76e772b3d3efc37c41f4690d69f480cf0c0e0173933d80081077ee55`
  - labnet-report `ab7ca197b8faebc8755434a3b01c58fd668597661d925eaccbc8c47a5a82d332`
  - rx-verify `97cc54505de475be5affb125b9d86ce2b3e88334e84a060f5339fac5d80c4a85`
- `--version` of each: commit `66f12f0761c8…` and `build flags: none` (`build/versions.txt`);
  regtest fingerprint `f90fef2537cd3d0a…`, rules `6ef53705…`, identity `bc72c2dc…`,
  genesis `3dbdba2a…`. `--print-manifest regtest`: `build/manifest-regtest.txt`.
- `blacksilk-node --randomx-self-test`: passed, 9 known answers, 4.3 s;
  `blacksilk-miner --randomx-self-test --light`: passed, 9 known answers, 4.2 s
  (`build/self-tests.txt`).
- Machine: Intel i7-6700 (4 cores, 8 threads, 3.4 GHz), 16 GB, Windows 10 Pro 22H2
  build 19045.3996, last boot 2026-10-09.
- Scripts used: `build/run.sh` (wrapper; console and load outside `--out`),
  `build/load-sampler.ps1` (30 s load sampling, 2 GB memory guard by PID).

## 3. Smoke run (NOT evidence): `smoke-S1-ring12/`

`--nodes 12 --topology ring --duration-mins 3 --warmup-max-mins 3 --partition-every-mins 0
--relay-joiners 1 --latency-ms 20 --jitter-ms 10 --tx-every-secs 20 --miner-threads 1
--base-port 44000`, no `--evidence`, 05:59:09–06:07:14 UTC, exit 0, `checks_passed: true`,
`evidence: false` (warm-up cut at 3 min, difficulty 3; no prebuild; 180 s measured).

- 12 nodes up 17 s after start (12 simultaneous RandomX self-tests), no port failure.
- Late joiner: 5 required peers after 9.9 s (6 max); relay node reached after 8.2 s.
- 0 crashes, 0 stuck, 0 misbehaviour disconnects.
- **`late_joiner_getaddr_answer` = 3 (bound ≥ 8).** Node 0's answer was its whole
  table: on the `ring` topology node 0 received 7 address messages of 1 entry each
  (its ring neighbours' self-advertisements and the joiners'), so its table held 2–3
  lab addresses, not 12. This predicts run A fails the ≥ 8 bound by
  topology, not by a product change; for the Lead to decide before run A.
- Reorganizations up to 7 deep, at difficulty 3–8 (below equilibrium, as INV-REORG
  expects of an unwarmed run); not comparable with the bounds.
- Peak RSS: nodes about 275 MB each, miners about 265 MB; available memory fell from
  about 6.4 GB to 2.8 GB with 12 nodes, 2 miners and joiners running. With the
  present baseline, runs A and B would run within about 1 GB of the 2 GB guard.

## 4. Reproducibility limits

Seeds are not settable: wallets come from the OS RNG and the transaction schedule from
`getrandom` (ChaCha20 seeded at start), and neither seed is logged. A rerun repeats
the configuration, not the event sequence. The Windows build is linked with `-Brepro`
by `tools/release-build.sh`; byte-reproducibility of these binaries was not re-checked here.

## 5. Resumed: prerequisites before each run

The owner closed Chrome. This agent ran the full check itself immediately before each run
(`build/prereqs.txt`). "≥ 10 GB" is read as ≥ 10,000 MB, as in the Lead's own 07:10 measurement.

| Check | Before A (07:11:52–07:13:54 UTC) | Before B (08:16:57–08:18:59 UTC) |
|---|---|---|
| Chrome processes | 0 | 0 |
| cargo / rustc / rust-analyzer / clippy / mutants / link | none | none |
| BlackSilk processes left over | 0 | 0 |
| CPU, mean of 24 × 5 s samples | 8.2 % (max 23.3) | 0.5 % (max 2.9) |
| Available memory | 10,182 MB | 10,168 MB |

Sleep, Update, Defender, firewall and port state are as in §1, unchanged.
`w32tm /query /status` after the runs (09:00:54 UTC) is also unchanged: not
synchronized, free-running clock.

The Visual Studio `BackgroundDownload` task runs every 3 h, at :01 past 05, 08, 11 …
local time (UTC+2). It ran at 06:01 and 09:01 UTC, so neither run overlaps it (A
07:14–08:16, B 08:19–08:59 UTC). Outside processes using more than 5 CPU-seconds in a
30 s sample: one `RuntimeBroker` sample in run A (13 s, unix 1792051816) and one
`explorer` sample in run B (5.4 s, during the end checks). None other in either run.

## 6. Run A: `runs/A-ring12/` (12-node ring, no partitions)

```
cd C:/bszkeval/labnet-v3
RUST_LOG="info,blacksilk_p2p::net=debug" BLACKSILK_REQUIRE_CLEAN_BUILD=1 \
bin/blacksilk-labnet.exe --bin-dir C:/bszkeval/labnet-v3/bin --out runs/A-ring12 \
  --nodes 12 --topology ring --duration-mins 45 --partition-every-mins 0 --relay-joiners 3 \
  --relay-gap-secs 15 --relay-wait-secs 120 --late-max-outbound 4 --late-peers-secs 120 \
  --base-port 34000 --latency-ms 20 --jitter-ms 10 --tx-every-secs 20 --miner-threads 1 --evidence
```

**Run**
- 07:14:01 to 08:16:33 UTC (3,734 s), exit status 0. Miners on nodes 0 and 6.
- Warm-up: 700 s, criterion reached at height 232 (difficulty 21, mean interval 7.8 s).
- Measured phase: 2,700 s. Final height 528.
- Difficulty 21–36; first-third mean 26.7, last-third mean 32.6.
- Transactions: 63 of 63 submitted.

**Resources**
- Peak RSS: 280 MB (a node).
- CPU: mean 40.6 %, max 99.5 %. The peak is in the end checks: fresh-wallet scans in
  the labnet process and relay nodes syncing.
- Available memory: min 6,658 MB (at node start), max 10,076 MB. The memory guard was
  not triggered.

**Reorganizations and stale blocks**
- 378 reorganizations over the 12 nodes, all in the connected phase: depth 1 × 239,
  2 × 118, 3 × 21. Max depth 3 (bound ≤ 4).
- Found blocks after warm-up:
  - connected phase: 373, of which 296 are on the final chain and 77 stale (20.6 %);
  - end checks: 2, of which 1 stale.
- One RPC refusal (`miner0.log`, 07:35:13): block 300 refused with `NotNearTip`. The
  block was built on a tip its node had already left, and the miner continued.
- Node 0's store has 30 side branches, at most 3 blocks long. None is heavier than the
  final chain over the same heights; 28 are equal-work ties, lost on first-seen.

**Per-hop arrivals** (`acceptance.json` `arrivals_by_hop_*`)
- Time from the origin node's `accepted` line to the receiver's first `received`
  line, for every block accepted in the connected phase, in ms.
- Hop is the ring distance from the origin miner. Hop 6 is only the other miner's node.

  | Hop | All blocks: n / median / p90 / max | Final-chain blocks: n / median / p90 / max |
  |---|---|---|
  | 1 | 705 / 624 / 687 / 39,854 | 592 / 622 / 686 / 28,948 |
  | 2 | 689 / 1,251 / 1,419 / 40,912 | 592 / 1,243 / 1,392 / 29,689 |
  | 3 | 670 / 1,878 / 3,702 / 42,223 | 592 / 1,870 / 2,848 / 34,218 |
  | 4 | 651 / 2,507 / 8,417 / 42,998 | 592 / 2,500 / 6,574 / 35,556 |
  | 5 | 632 / 3,143 / 10,022 / 43,804 | 592 / 3,138 / 9,234 / 36,291 |
  | 6 | 296 / 3,714 / 12,261 / 52,190 | 296 / 3,714 / 12,261 / 52,190 |

- The median grows by about 625 ms per hop, linearly in the hop count.
- The tail grows with contested heights: a rival block's body is fetched only when its
  branch wins.
- Report `propagation`:
  - uncontested, all 12 nodes: 219 blocks, median 3,660 / p90 4,194 / max 5,930 ms;
  - with contested heights: 296 blocks, 3,715 / 12,604 / 52,190 ms.

**Late joiner and address relay**
- The late joiner reached its 5 required peers after 9.9 s (max 6).
- GetAddr: node 0 answered with 3 addresses at 08:11:32.379.
  - Node 0's `peers.json` count went from 2 to 3 at 08:11:32: the joiner's own
    address. So T = 3, and the rule gives min(8, 3) = 3: **equal**.
  - Node 0's table peaked at 6 entries in this run, so the "table larger than 8
    entries" check is **NOT EXERCISED**.
- Relay discovery: the joiner had 12 peers before and 15 at the end. The relay nodes
  were reached after 70.8, 47.0 and 17.7 s.
- All 528 final-chain blocks appear (`accepted` or `received`) in every one of the 12
  lab node logs.

## 7. Run B: `runs/B-chords12-withhold/` (12 nodes, ring with chords, withholding node 0)

```
cd C:/bszkeval/labnet-v3
RUST_LOG="info,blacksilk_p2p::net=debug" BLACKSILK_REQUIRE_CLEAN_BUILD=1 \
bin/blacksilk-labnet.exe --bin-dir C:/bszkeval/labnet-v3/bin --out runs/B-chords12-withhold \
  --nodes 12 --topology ring-chords --duration-mins 25 --partition-every-mins 6 --partition-mins 3 \
  --partition-split 1 --relay-joiners 3 --base-port 38000 --latency-ms 20 --jitter-ms 10 \
  --tx-every-secs 20 --miner-threads 1 --evidence
```

**Run**
- 08:19:03 to 08:59:40 UTC (2,418 s), exit status 0.
- Miners on nodes 0 and 1. Partition groups: {0} against {1..11}.
- Warm-up: 632 s, criterion reached at height 231 (difficulty 24, mean interval 7.8 s).
- Measured phase: 1,500 s. Final height 395.
- Difficulty 24–41; first-third mean 31.3, last-third mean 31.4.
- Three partitions:
  1. 08:35:53–08:38:53;
  2. 08:44:54–08:47:54;
  3. from 08:53:54 until the end checks healed it at 08:54:53 UTC.
- Transactions: 31 of 31 submitted.

**Resources**
- Peak RSS: 277 MB.
- CPU: mean 42.5 %, max 100 % (end checks).
- Available memory: min 6,385 MB (warm-up start), max 9,849 MB. The guard was not
  triggered.

**Reorganizations by phase**
- Connected phase: 12, all 1 deep (bound ≤ 2).
- Partition phase: 8, each 1 deep.
- Heal phase: 22. Heal 1: 11 reorganizations of 8 blocks; heal 2: 11 of 12 blocks.
- End checks: 11 reorganizations of 3 blocks (heal 3).

**Heals** (report `heals`; seconds after the heal; one tip everywhere is sampled every 15 s)

| Heal | Heights before (node 0 / others) | Reorganizations | One tip everywhere |
|---|---|---|---|
| 1 (08:38:53) | 298 / 293 | nodes 1–11: 8 deep, 14.4–22.4 s | 36 s |
| 2 (08:47:54) | 344 / 344 | nodes 1–11: 12 deep, 15.0–23.0 s | 54 s |
| 3 (end checks, 08:54:53) | — | nodes: 11 × 3 deep | ≤ 22 s (see below) |

- Heal 3 timing: the journal's `converged=true` line is at 08:55:35, logged 20 s after
  the convergence loop ended.
- Node 0's withheld branch won all three heals. Every other node reorganized once per
  heal; no node switched back and forth.

**Work at each switch** (`report-node1-store.json`, from `node1-blocks.dat`; node 1's
store holds both sides)

| Heal | Losing branch (fork → tip) | Its work | Final chain's work over the same heights |
|---|---|---|---|
| 1 | 285 → 293 | 273 | 308 |
| 2 | 333 → 345 | 364 | 370 |
| 3 | 387 → 390 | 94 | 97 |

- The other three side branches are 1-block equal-work ties.
- No branch in node 0's or node 1's store is heavier than the final chain over the same
  heights. Each switch went to strictly more work, and no node reorganized to a
  lower-work branch.

**Found blocks after warm-up**
- Connected phase: 127, of which 120 kept and 7 stale (5.5 %).
- Partition phase: 49, of which 21 stale (the losing side).
- Heal phase: 16, of which 2 stale.
- End checks: 3.
- No RPC refusal.

**Propagation** (ring with chords, at most 3 hops)
- Uncontested: 113 blocks, median 1,961 / p90 2,031 / max 2,183 ms.
- With contested heights: 119 blocks, max 33,231 ms.
- Arrivals, all receivers: 1,340, median 1,298 / p90 1,960 / max 204,465 ms. The max is
  a block mined just before a partition and delivered at the heal.

**Late joiner and address relay**
- The late joiner reached its 5 required peers after 7.9 s (max 6).
- GetAddr: node 0 answered with 8 addresses at 08:55:40.026.
  - Node 0's `peers.json` count went from 7 to 8 at 08:55:40: the joiner's own
    address. So T = 8, and the rule gives min(8, 8) = 8: **equal**.
  - The table was not larger than 8 at the late joiner's request, so the "table larger
    than 8 entries" check is **NOT EXERCISED by the bound**.
  - Supplementary, outside the bound: from 08:58:17 to 08:59:36 node 0 answered the
    relay nodes' requests with 8 addresses while its table held 9–11 entries
    (`node0-table.csv`). For those sizes the rule max(ceil(0.23 T), min(8, T)) also
    gives 8.
- Relay discovery: the joiner had 12 peers before and 15 at the end. The relay nodes
  were reached after 74.0, 49.5 and 19.0 s.
- All 395 final-chain blocks appear in every one of the 12 lab node logs.

## 8. Acceptance table

| Criterion | A | B |
|---|---|---|
| Exit status 0 with `--evidence` | PASS (0) | PASS (0) |
| `checks_passed`, `evidence: true`, `evidence_notes: []` | PASS | PASS |
| `crashes: []`, `stuck_incidents` 0, `misbehavior_disconnects` 0 | PASS | PASS |
| `converged_at_end`, `mempools_drained_at_end` | PASS | PASS |
| `late_joiner_synced`; peers ≥ 5 | PASS (6) | PASS (6) |
| `late_joiner_secs_to_required` ≤ 120 | PASS (9.9 s) | PASS (7.9 s) |
| `relay_discovery.all_reached` | PASS (3/3) | PASS (3/3) |
| Fresh-wallet balances, v1 and private | PASS | PASS |
| `supply_conserved` | PASS (10,571.68400220) | PASS (7,909.24241932) |
| `warmup.reached` | PASS (700 s) | PASS (632 s) |
| Binaries: 66f12f0, no `-dirty`, `build flags: none`, SHA-256 = SHA256SUMS | PASS (labnet, node, miner) | PASS |
| GetAddr answer = rule(T at request) (§0.1) | PASS (3 = min(8, 3)) | PASS (8 = min(8, 8)) |
| Table larger than 8 at the request | NOT EXERCISED (T = 3; max 6) | NOT EXERCISED (T = 8) |
| Every final-chain block reached all 12 nodes | PASS (528) | PASS (395) |
| `RandomX self-test passed` in every node log | PASS (12 lab nodes + late, e2, 3 relay) | PASS (same) |
| `is invalid`, `misbehaved (+`, `inbound limit reached`, panic, `ERROR`, halt | PASS (0 each) | PASS (0 each) |
| Connected-phase reorganization depth | PASS (max 3, bound 4) | PASS (max 1, bound 2) |
| Median arrival at the farthest node ≤ 30 s | PASS (hop 6: 3.7 s) | n/a |
| Every heal one tip within 120 s | n/a | PASS (36 s, 54 s, ≤ 22 s) |
| Switches to strictly more work; none to lower work | PASS (node 0's store: no heavier side branch) | PASS (node 1's store, §7) |

WARN lines (`acceptance.json` `warn_lines`), and nothing else:
- every node's RPC-cookie notice (its data directory is outside the user profile);
- run A's one `block 300 rejected: NotNearTip` in `miner0.log`;
- run B's deep-reorganization warnings at heal 2 (by design).

## 9. Not done

- `blacksilk-rx-verify` (optional) was not run: it reads live nodes' `/headers`, and the
  harness stops every node at the end of a run.
- Run C was not started (not in scope).

## 10. Files

- `build/`:
  - SHA256SUMS, versions, manifest, self-tests;
  - build log and environment, CI job list, prerequisite log;
  - the scripts used: `run.sh`, `load-sampler.ps1`, `table-poller.sh`, `analyze.py`.
- `runs/<run>/`:
  - `summary.json`, `metrics.csv`, `journal.log`, `late-peers.csv`, `final-chain.txt`;
  - every node, miner, late, e2 and relay log, and `node0-blocks.dat`;
  - `report.json` and `report.txt`, from
    `blacksilk-labnet-report <run> --store <run>/node0/blocks.dat --json <run>/report.json`;
  - `acceptance.json` (from `build/analyze.py`), `load.csv`, `node0-table.csv`;
  - the console log, `meta` (command, environment, UTC start and end, PIDs) and exit
    status;
  - run B only: `node1-blocks.dat` and `report-node1-store.json`/`.txt`.
- Not included: the node data directories. `peers.json` holds the address table's secret
  key; `rpc.cookie` and `bans.json` are left out too. `node0-table.csv` records only
  entry counts.
- `load.csv`'s first column is `[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()`: true
  Unix time, unlike W4's `Get-Date -UFormat %s`.
- Line ends: git stores the text files here with LF. Eight files were written with CRLF
  (`load.csv` ×3, `acceptance.json` and `*.analyze.txt` of runs A and B, `build/run.sh`);
  a Windows checkout with `core.autocrlf=true` gives them back CRLF, a Linux checkout LF.
- One change made when committing this record to the repository (2026-10-15): the three
  `load.csv` files were written by PowerShell 5.1 `Out-File -Encoding utf8`, which puts
  a UTF-8 byte order mark (U+FEFF) before the header. The repository's invisible-Unicode
  scan (`.github/scripts/unicode-scan.sh`) rejects U+FEFF, so those three leading bytes
  (`EF BB BF`) were removed; nothing else in any file was changed. SHA-256 of the
  files as written by the sampler, with the mark (prepend `EF BB BF` to the committed
  working-tree file to check; the sampler wrote CRLF line ends, and git stores this
  directory's text files with LF, so check a Windows checkout with `core.autocrlf=true`
  or convert LF to CRLF first):
  - `runs/A-ring12/load.csv` `2b0962f26c4f1097ea571f86bda36d817a8a321220e9309f8d5c0a21867109dd`
  - `runs/B-chords12-withhold/load.csv` `7abf4aa1fed634564bd447dfe5594599166c6eccf592d0dd5170dfe47e615f5e`
  - `smoke-S1-ring12/load.csv` `bc813cf6c04e6ed0ea4bcf16627d535e8633d0598a46ebef468b1013b3e4e801`
