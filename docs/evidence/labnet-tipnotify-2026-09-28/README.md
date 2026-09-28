# Labnet with tip notification (09 I1, W2-09b)

Internal engineering evidence, not an audit. One machine, regtest, light-mode
miners, two runs. It measures how often a miner's found block was not adopted by its
own node (a rival of equal work was there first) after the miners started using the
node's `/tip` long poll to drop stale work. The baseline is
[labnet-warmup-2026-09-28](../labnet-warmup-2026-09-28/README.md) run 2, where about
21 % of the connected-phase finds were such races (dossier 09 M9-1).

## What changed (branch `w2-mine2`, commit bec93ff)
- The node serves `GET /tip?after=<id>&wait=<s>` from its published chain snapshot. A
  request is held until the tip differs from `after` (docs/blocks.md §9.4).
- The miner keeps one such poll open (`blacksilk_miner::TipWatcher`). It stops its
  nonce search as soon as its node's tip is no longer the template's parent, logs
  `new tip at height h: work on template t abandoned after …`, and fetches a new
  template. Before, it noticed only at its `--refresh` (5 s in the labnet).
- `/template` answers `503` while the node syncs (not triggered in these runs as far
  as the logs show; the miners logged no retry).
- The labnet passes `--prebuild on` in evidence runs and counts the abandoned
  templates (`blocks_found_by_phase.*.abandoned`).

## Command
Binaries built at bec93ff (`BLACKSILK_BUILD_COMMIT=bec93ff`; the node log prints it).
The flags are the baseline's, except `--nodes 4` (the baseline also ran 4 nodes) and
the ports:

```
blacksilk-labnet --bin-dir <bin> --out <dir> --nodes 4 --duration-mins 16 \
    --latency-ms 20 --jitter-ms 10 --partition-every-mins 7 --partition-mins 3 \
    --tx-every-secs 20 --base-port 47700 --miner-threads 1 --evidence
```
Run 2 used `--base-port 47800`. The machine was Windows 10 with 8 logical CPUs,
shared with other agents' work. No test suite of this branch ran during the runs.

## Results
Both runs: `checks_passed: true`, `evidence: true`, `evidence_notes: []`. Converged,
mempools drained, late joiner synced, wallets restored, supply conserved; 0 crashes,
0 stuck incidents, 0 misbehaviour disconnects.

| | Baseline (warmup run 2) | Run 1 | Run 2 |
|---|---|---|---|
| Warm-up | 587 s, height 185, D 9 | 742 s, height 188, D 8 | 564 s, height 193, D 11 |
| Measured phase difficulty (`metrics.csv`) | 9 to 12 | 8 to 21 | 11 to 21 |
| Connected-phase finds | 122 | 123 | 119 |
| Of those, not adopted at submission | 26 (21.3 %) | 16 (13.0 %) | 9 (7.6 %) |
| Templates abandoned on a new tip (connected) | not measured | 58 | 75 |
| Reorganizations after warm-up, depths | 1: 10, 2: 1, 13: 2 | 1: 28, 24: 2 | 1: 15, 2: 2, 3: 1, 12: 2 |
| Deepest outside the heal | 2 | 1 | 3 |

Source: `run*/summary.json` (`blocks_found_by_phase`, `reorgs_by_phase`). The two
deep reorganizations in each run are the two nodes of one partition side switching
branches just after the heal, as in the baseline.

**Confounder: difficulty.** The two runs reached a higher difficulty than the
baseline (the miners logged 0.5 to 1.7 H/s here against about 0.9 to 1.1 H/s there,
a less loaded machine). Longer block intervals alone lower the race rate. To
compare like with like, `analysis/stratify.py` attributes each connected-phase find
to the tip difficulty of the preceding 15 s metrics sample:

```
python analysis/stratify.py ../labnet-warmup-2026-09-28/run2 run1 run2
../labnet-warmup-2026-09-28/run2 {'<=12': (121, 26, 21.5)}
run1 {'13-16': (8, 0, 0.0), '<=12': (82, 12, 14.6), '>=17': (40, 4, 10.0)}
run2 {'13-16': (31, 3, 9.7), '<=12': (27, 4, 14.8), '>=17': (59, 2, 3.4)}
```
(found, not adopted, %). At difficulty 12 or below, the range of the baseline, 16 of
109 finds (14.7 %) were not adopted, against 26 of 121 (21.5 %) in the baseline.
The totals differ slightly from `summary.json`, which attributes by log position.

**Rejected at the heal.** Each run has one `block … rejected: NotNearTip` in a miner
log (run 1 `miner0` 16:18:17, run 2 `miner1` 16:51:47 UTC), 5 to 16 s after its partition
healed: the miner's node had just reorganized to the other side's branch, and a
block found on the old branch's tip no longer had a parent among the node's last 8
connected blocks (docs/blocks.md §9.2). That is the `/block` admission rule working
as designed; the block could not have won.

**Reading.** The tip notification removed part of the stale-work races. The rest
has two causes the notification cannot remove:
- A light-mode hash here takes about 0.6 to 2 s, and the search checks its stop flag
  between hashes, so a miner may finish a hash on the old parent after the tip moved.
  Full-mode hashing is much faster per hash (docs/testnet.md §12.1).
- Blocks found by the two miners within the relay delay of each other (proxy latency
  20 ms ± 10 ms per hop, plus header-first relay and validation) race whatever the
  miner does.

## Limits
- Two runs of 16 minutes each; the counts are small samples (a binomial standard
  error of about 3 percentage points at these sizes). The difference to the baseline
  at comparable difficulty is about two standard errors: an indication, not a
  precise figure.
- One machine, loopback, light mode, one thread per miner. Not multi-machine evidence
  (docs/testnet.md §7).
- No key switch happens below height 2113, so `next_seed_id` and the prebuild are
  not exercised here. They are tested with a short key epoch: node
  `tip_notify::the_template_announces_the_next_key_in_the_lag_window`, chain
  `manager::template::tests::the_next_key_is_announced_in_the_lag_window`, miner
  `prebuild_crosses_a_key_switch_without_building_on_the_mining_thread`.
- The `503` readiness gate was not observed to fire; it is covered by
  `node/tests/template_gate.rs` and the chain unit tests.

## Files
- `run1/`, `run2/`: `summary.json`, `metrics.csv` (every 15 s, phase in the last
  column), `journal.log`, and `logs/` with every node, miner and late-joiner log
  (info level).
- `analysis/stratify.py`: the difficulty-stratified count above.
