# Labnet with a warm-up phase (INV-REORG follow-up, 09 W2)

Internal engineering evidence, not an audit. One machine, regtest, light-mode
miners. It shows the labnet warm-up and the phase-split reorganization metrics
working. It does not measure full-mode mining or a RandomX key switch: the run ends
near height 300, far below the first switch at 2113.

## Why a warm-up
docs/evidence/labnet-reorg-2026-09-27 found that two miners starting at the regtest
genesis difficulty (1) mine in lockstep and split into deep equal-work branches (up to
76 blocks). The coordinator decided (decisions "Labnet deep reorgs (INV-REORG)"):
- a single miner runs first, until the difficulty nears equilibrium;
- reorganization metrics count only after the warm-up, and the warm-up's are reported
  apart;
- runs shorter than about 10 minutes are not evidence;
- `--prebuild` is on in evidence runs.

## What the labnet now does (tools/labnet, docs/testnet.md §8)
- **Warm-up criterion:** miner0 alone until the mean interval of the last 30 blocks,
  timed by when node 0 first reports each height (sampled every second), is at least
  0.75 × T (T = 10 s on regtest), or 60 minutes pass. Then miner1 starts and
  `--duration-mins` begins. With 30 exponential solve times the window's standard
  deviation is about T/√30 ≈ 0.18 T, so 0.75 T separates "still ramping" (blocks
  every 1 to 5 s) from "near equilibrium" without waiting for the noise to settle.
- **Phases:** at each phase change the harness records the size of every node and
  miner log. Each log line is attributed to the phase in which it was written:
  `warmup`, `connected`, `partition`, `heal` (the first 60 s after a heal) and
  `final` (end checks).
- **Summary fields:** `reorganizations`, `max_reorg_depth` and `reorg_depths` exclude
  the warm-up. `warmup_reorganizations` and `warmup_max_reorg_depth` report the
  warm-up. `reorgs_by_phase` and `blocks_found_by_phase` split everything.
  `evidence` and `evidence_notes` say whether the run may be cited.
- **`--evidence`:** refuses `--duration-mins` below 10 and `--no-warmup`, turns on
  `--prebuild`, and exits with status 1 unless `evidence` is true.

## Command
Binaries from branch `w2-mine`: the node at fd848fb (its log prints the commit); the
miner and labnet with the changes of 36e0456; for run 2 also 43df9bb (labnet).

```
blacksilk-labnet --bin-dir <bin> --out <dir> --nodes 4 --duration-mins 16 \
    --latency-ms 20 --jitter-ms 10 --partition-every-mins 7 --partition-mins 3 \
    --tx-every-secs 20 --base-port 47600 --miner-threads 1 --evidence
```
Run 1 used `--base-port 47500`; otherwise the same. The machine was Windows 10 with 8
logical CPUs, shared with other agents' work. Run 1 overlapped this branch's `cargo test` run
for part of its warm-up.

## Run 2 (the evidence run): `run2/`
`summary.json`: `checks_passed: true`, `evidence: true`, `evidence_notes: []`.

| Item | Value |
|---|---|
| Warm-up | 587 s, ended at height 185, difficulty 9, mean interval 7.8 s (criterion met) |
| Measured phase | 960 s (16 min), one partition of 3 min (03:04:43 to 03:07:47 UTC) |
| Final height | 298 |
| Crashes, stuck incidents, misbehaviour disconnects | 0, 0, 0 |
| Converged, mempools drained, late joiner synced, wallets restored, supply conserved | all true |
| Transactions | 11 of 11 attempts submitted |

**Reorganizations (log lines summed over nodes 0 to 3 and the late joiner):**

| Phase | Count | Depths (depth: count) |
|---|---|---|
| warmup | 0 | none |
| connected | 10 | 1: 9, 2: 1 |
| partition | 0 | none |
| heal | 3 | 1: 1, 13: 2 |
| final | 0 | none |
| **after the warm-up (headline)** | **13** | 1: 10, 2: 1, 13: 2 (max 13) |

- The two 13-deep reorganizations are nodes 3 and 2 (one partition side) switching to
  the other group's branch 5 and 8 s after the heal (`run2/logs/node3.log`,
  `node2.log`, 03:07:52 and 03:07:55 UTC). That is the partition, as designed.
- Outside the partition window every reorganization was 1 or 2 blocks deep. No deep
  equal-work split of the kind in labnet-reorg-2026-09-27 occurred.

**Found blocks (`blocks_found_by_phase`, from the miner logs):**

| Phase | Found (accepted by the miner's node) | Of those, not adopted at submission |
|---|---|---|
| warmup | 185 | 0 |
| connected | 122 | 26 |
| partition | 27 | 0 |
| heal | 11 | 1 |
| final | 1 | 0 |

"Not adopted" counts the miner's `not on the node's best chain` lines: its node already
had a rival block of equal work. About 21 % of the connected-phase finds were such
races. This is the stale-work effect of dossier 09 M9-1 (the miner learns of a new tip
only at its 5 s refresh) plus relay delay; the tip notification (09 I1) is not
implemented.

**Difficulty.** The tip difficulty (column `difficulties` of `metrics.csv`) was 1 to 9
during the warm-up and 9 to 12 in the measured phase. With the second miner the hash
rate doubled (each light-mode miner logged about 0.9 to 1.1 H/s), so the two-miner
equilibrium is about 20. The difficulty was still rising when the run ended, and the
blocks came faster than T (113 blocks in 960 s including the partition). A run long
enough to settle at the two-miner equilibrium would lower the race rate; this run does
not show that.

## Run 1: `run1/` (metrics misattributed; kept as the record of the bug)
Same flags. `checks_passed: true` and `evidence: true`, but the phase split was wrong:
every reorganization and most found blocks were put in `final`. Cause: the harness
read log sizes from the directory listing, and on Windows a directory entry's size
does not follow a file that another process is appending to. Measured during run 2 on
`miner0.log`: 0 bytes from the directory entry, 624 bytes through an open handle. The
fix (43df9bb) reads the size through an open handle. Its totals are still valid as
all-phase counts: 21 reorganizations, depths 1: 17, 2: 2, 12: 2, with the two
12-deep ones on nodes 2 and 3, 8 to 10 s after the heal (02:37:23 UTC). Its warm-up took 636 s and ended at
height 197, difficulty 12.

## Limits
- One machine, loopback, light mode, one thread per miner. Not multi-machine evidence
  (docs/testnet.md §7).
- The miners ran with `--prebuild`, but no key switch happens below height 2113, so
  the prebuild itself is not exercised here. It is tested with a short key epoch in
  the `miner` tests (`prebuild_crosses_a_key_switch_without_building_on_the_mining_thread`).
- Two runs; the reorganization counts are single samples, not a distribution across
  seeds.

## Files
- `run2/summary.json`, `run2/metrics.csv` (every 15 s; the last column is the phase),
  `run2/journal.log`.
- `run2/logs/`: every node, miner and late-joiner log of run 2 (info level).
- `run1/summary.json`, `run1/journal.log`.
