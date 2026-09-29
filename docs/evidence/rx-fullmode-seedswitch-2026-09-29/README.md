# A full-mode RandomX miner across the first key switch (height 2113)

Internal engineering evidence, not an audit.

The earlier seed-switch run (labnet-seedswitch-2026-09-27) crossed height 2113 with
light-mode miners only. This run crosses it with the real full-mode miner:
`blacksilk-miner` without `--light`, its 2 GiB dataset, and `--prebuild auto` (the
default). Every node's chain is then re-checked in a separate process, in light and
full mode.

**Scope.** This shows one crossing of one key switch, on one machine, on regtest
(10 s blocks). It is not a claim of production readiness, and not multi-machine
evidence (docs/testnet.md §7). On the testnet the blocks are 12 times longer (§ Timing).

## Result in brief
- **Prebuild and switch.**
  - The miner built the next key's dataset in the background from template 2049. The
    build finished at height 2070, 338 s before the first template at 2113.
  - At 2113 it logged `RandomX key 3bbf6fb874d645fc: prebuilt context in use` and
    found block 2113 **2.9 s** later.
  - It never mined in light mode: all of its hash-rate lines say `full mode`, and it
    logged no warning.
- **Hash rate.** 27.1 H/s before the prebuild, 19.7 H/s during it, 27.3 H/s after it,
  and 27.3 H/s in the first 10 minutes under the new key.
- **Nodes.**
  - Submitting block 2113 took 0.58 s (median over the run: 0.59 s).
  - Nodes 1–3 accepted its header 0.94 s after node 0. The neighbouring blocks took
    0.69–0.93 s.
  - No reorganization touched the switch.
- **Chain.** The run reached height 2835, 722 blocks past the switch.
  - All five nodes, including the late joiner, hold byte-identical headers 1–2835.
  - Every header passes a fresh light-mode RandomX check and consensus header
    validation.
  - 61 blocks around and after the switch hash identically in full and light mode,
    bit for bit.
  - A corrupted-nonce negative control fails as it should.
- **Labnet verdict: `checks_passed: false`.**
  - One check failed: the late joiner stayed with one peer; the labnet requires two.
  - It did have the whole chain: it synced to the same tip in about 7 minutes, and
    the fresh wallets restored against it matched.
  - This is a peer-discovery issue, not a RandomX one (§ What failed).

## Setup
- **Code:**
  - Node, miner and labnet binaries were built from branch `w4-rx` at commit
    `17ba8b1`: `rebuild/core` c496627 plus two labnet commits, 2cea0aa and 17ba8b1.
  - The node and miner sources are those of c496627. The node log prints
    `commit 17ba8b1`; the miner was built with `BLACKSILK_BUILD_COMMIT=17ba8b1`.
  - Toolchain: rustc 1.98.1 (x86_64-pc-windows-msvc), release profile.
  - SHA-256 of each binary is in `summary.json`.
- **Machine:**
  - Hardware: Intel Core i7-6700 (4 cores, 8 threads, 3.4 GHz), 16 GB RAM, Windows 10
    Pro 19045.
  - It was shared with other work during the run, including a process of about 7.9 GB
    at times.
  - Free memory fell to 362 MB at 03:26 UTC. The memory watcher then suspended the
    light miner twice, for 44 s and 55 s (02:17:46 and 03:25:53 UTC), following the
    rule "pause the light miner below 1.5 GB free".
  - The full-mode miner was never touched.
- **Network:** 4 regtest nodes plus a late joiner, on loopback, behind proxies.
  - Links: 20 ms ± 10 ms latency.
  - Partitions: a 3-minute partition every 45 minutes, 8 in total, none during the
    switch.
  - Traffic: a v1 transaction every 20 s.
- **Miners:**
  - `miner0` on node 0: full mode, 2 mining threads, `--prebuild auto --build-threads 4`.
  - `miner1` on node 2: light mode, 1 thread, `--prebuild on`.
  - The labnet records both in `labnet-summary.json` (`miner_modes`).

### Commands
Build (worktree at 17ba8b1):
```
CARGO_TARGET_DIR=C:/bszkeval/t-w4-rx CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 \
BLACKSILK_BUILD_COMMIT=17ba8b1 \
cargo build --locked --release -p blacksilk-node -p blacksilk-miner -p blacksilk-labnet
```
Run (binaries copied to `C:/bszkeval/w4-rx/bin`):
```
RUST_LOG="info,blacksilk_miner=debug,blacksilk_p2p::net=debug" \
blacksilk-labnet --bin-dir C:/bszkeval/w4-rx/bin --out C:/bszkeval/w4-rx/run2 \
  --nodes 4 --duration-mins 420 --latency-ms 20 --jitter-ms 10 \
  --partition-every-mins 45 --partition-mins 3 --tx-every-secs 20 --base-port 48200 \
  --miner-threads 2 --miner-full --light-second-miner --full-prebuild auto \
  --miner-build-threads 4 --evidence
```
Independent check:
- After the labnet exited, each node (node0–3 and the late joiner) was restarted on
  its data directory, offline:

  ```
  --network regtest --allow-private --connect-only --peer 127.0.0.1:9
  ```

  plus its own RPC and P2P ports (48500 + 20·i).
- Then:

  ```
  blacksilk-rx-verify --network regtest --threads 4 \
    --node 127.0.0.1:48500 --cookie <node0>/rpc.cookie  ... (all five nodes) \
    --full 2100-2130,2300-2313,2820-2835 --record 2040-2140,2300-2313,2820-2835 \
    --out rx-verify.json
  ```

- Controls, against node 0:
  - negative: `--up-to 2113 --corrupt-nonce 2113`;
  - positive: `--up-to 2113`.

Log analysis:
```
python analysis/analyze.py <run dir> <monitor csv> > analysis.json
python analysis/attribute.py verify/rx-verify.json <run dir> > attribution.json
```
- **Full logs needed:** both scripts read the full logs (about 9 MB, kept locally at
  `C:/bszkeval/w4-rx/`). This directory has the info-level logs and every line from
  03:50 to 04:10 UTC (§ Files).
- **Monitor:** `analysis/monitor.ps1` sampled every 10 s:
  - free memory;
  - each run process's working set, private bytes and CPU time.

## The labnet changes this run needed (branch `w4-rx`)
- **2cea0aa:**
  - `--light-second-miner`: one full-mode miner plus one light miner, instead of two
    2 GiB datasets on a 16 GB machine.
  - `--full-prebuild on|auto`: `--evidence` otherwise passes `--prebuild on`, and the
    requirement here is the default `auto`.
  - `--miner-build-threads`.
  - `miner_modes` in the summary.
  - `blacksilk-rx-verify` (tools/labnet/src/bin/rx_verify.rs).
- **17ba8b1, a labnet warm-up bug found by this work:**
  - Aborted run 1 (`run1-aborted/`) ended its warm-up after 314 s, at height 30 and
    difficulty 1.
  - Cause: the harness timed the genesis from when it first looked, so the miner's
    286 s dataset build counted as the first block interval, and the 30-block mean
    came out at 10.4 s.
  - The starting tip is no longer counted. Regression test:
    `the_miners_start_is_not_a_block_interval`.
  - Light-mode runs start in about 1 s and were barely affected.
- **The evidence commit:** `--up-to` and `--corrupt-nonce` for the controls.

## Timing: why `--build-threads 4`
- **The window is short on regtest.** The prebuild window is the 64 blocks between
  the key block (2048) and the switch (2113): about 640 s at regtest's 10 s blocks
  (7,680 s on the testnet).
- **The default is too slow here.** With `--threads 2` the default is 1 build thread,
  and docs/testnet.md §12.1 measured about 1,220 s for a 1-thread build. That default
  would not finish on regtest; the miner would reach the switch still building and
  bridge in light mode.
- **So this run passed `--build-threads 4`.** The build took 314–335 s while mining;
  the bounds come from 10 s sampling.
- **Not exercised:** the default build-thread count on regtest, and the light-mode
  bridge at a switch.
- **On the testnet,** a 1-thread build (about 20 minutes) fits the 128-minute window
  about six times over. This run does not measure that.

## Results in detail

### Dataset builds (miner0)
| Build | Start (UTC) | End (UTC) | Duration | Threads | Source |
|---|---|---|---|---|---|
| First (genesis key), before any hashing | 22:49:01.9 | 22:54:04.6 | 302.6 s | 4 (`max(--threads, --build-threads)`) | miner log |
| Prebuild (block-2048 key) | 03:52:35 (allocation seen) | 03:58:00 (its cache freed) | 314–335 s | 4, beside 2 mining threads | `analysis/monitor-miner-full.csv` |

- **The miner logs no line for a background build**, so the prebuild is timed from
  outside:
  - At its start, private bytes rose from 2,092 MB to 4,433 MB (the next cache and
    dataset).
  - At its end, they fell by 257 MB to 4,176 MB: the 256 MiB cache is freed once the
    dataset is built.
  - The miner's CPU use agrees: 1.86 cores busy before, 4.93 during, 1.85 after.
- **Template 2049** (the first to announce the next key) was fetched at 03:52:30.9.
  The allocation was seen at the next sample, 4 s later.
- **Two datasets were kept after the switch,** for a reorganization back across it
  (`KEEP_PREVIOUS_BLOCKS` = 144). The previous dataset was released with template
  2258 at 04:27:31, and private bytes returned to about 2,090 MB.
- **Peak working set:** 4,425 MB, matching docs/testnet.md §5 ("about 4.4 GiB").

### The switch (miner0 log, node0 log)
| Time (UTC) | Event |
|---|---|
| 04:03:38.155 | block 2112 accepted; template 2113 fetched; `RandomX key 3bbf6fb874d645fc: prebuilt context in use` (same millisecond) |
| 04:03:41.064 | block 2113 found and accepted by node 0 (2.909 s after the switch; submission round trip 0.582 s) |
| 04:03:42.00–.01 | nodes 1–3 accept header 2113 (0.94 s after node 0) |
| 04:03:46.457 | block 2114 |

- **Block intervals at node 0:** mean 10.43 s over 2049–2112 and 10.49 s over
  2113–2176.
- **Submissions 2113–2123:** round trip median 0.576 s, max 0.608 s, against a run
  median of 0.594 s (p95 0.983 s).
- **Neither side showed a stall.** A node building the new key's cache on the chain
  lock at the switch would add about 1–3 s to that round trip (dossier 07 W1). Here
  the node's hot-seed prebuild had the cache ready.
- **What the node does not log:** its hot-seed build itself. The absence of a delay
  is the evidence.

### Hash rate (miner0 debug lines, search time only)
| Window | H/s |
|---|---|
| 10 min before the prebuild | 27.09 |
| During the prebuild (4 build threads beside 2 mining threads on 4 cores) | 19.71 |
| Prebuild end to the switch | 27.33 |
| First 10 min after the switch | 27.25 |
| Heights 2177–2400 / 2401–2835 | 27.64 / 26.42 |

- **The machine was shared.** Heights 1500–2048 averaged 23.0 H/s, including the
  low-memory period.
- **The prebuild costs hash rate.** It took about 27 % of the hash rate while it ran,
  because of CPU contention. The switch itself cost none.
- **Light miner:** `miner1` ran at about 1 H/s in light mode. It crossed the switch
  with its own prebuilt light cache (`prebuilt context in use` at 04:03:39.3).

### Who mined the checked blocks (`analysis/attribution.json`)
| Heights | Blocks | miner0 (full) | miner1 (light) |
|---|---|---|---|
| 2040–2112 | 73 | 73 | 0 |
| 2113–2140 | 28 | 27 | 2136 |
| 2300–2313 | 14 | 14 | 0 |
| 2820–2835 | 16 | 15 | 2832 |

### Chain agreement and supply (`labnet-summary.json`)
| Item | Value |
|---|---|
| Final height | 2835 |
| End state | converged, mempools drained |
| Transactions | 1,099 submitted of 1,099 attempts |
| Fresh-wallet restores | match |
| Supply | conserved (generated 5,670,034,349,581 = wallet total) |
| Crashes, misbehaviour disconnects, stuck incidents | 0, 0, 0 |
| Reorganizations after the warm-up | 72: depth 1 × 70, depth 2 × 2 |

### Independent verification (`verify/rx-verify.json`)
`blacksilk-rx-verify` runs in a fresh process and reads only `/headers`.

| Check | Result |
|---|---|
| Headers 1–2835 from node0, node1, node2, node3 and the late joiner | byte-identical |
| Light-mode RandomX hash of every header (fresh caches; own copy of the rx/0 key schedule; own 32-bit-limb target check against the header's difficulty) | 2,835 checked, 0 failures |
| The same headers through `HeaderChain::accept` (difficulty, timestamps, links; PoW answered from the light hashes, refusing any key but the one derived independently) | 2,835 accepted, 0 key mismatches, same tip |
| Full mode (fresh 2 GiB dataset per key, 275 s and 281 s on 4 threads) against light mode, heights 2100–2130, 2300–2313, 2820–2835 | 61 compared (13 under the genesis key, 48 under the block-2048 key), **0 mismatches, bit for bit** |
| Negative control: nonce of 2113 changed | target failure at 2113, consensus `InsufficientWork`, exit 1 |
| Positive control: same range, unchanged | PASS, exit 0 |

- **Keys:** block 2113's key is the id of block 2048,
  `3bbf6fb874d645fc228566f7b266431a52afbef23afa1c89230c281389b63d0b`, the key the
  miner logged.
- **The limit of this check:**
  - The verifier uses the same `blacksilk-randomx` crate as the node, so it is not a
    second implementation.
  - It checks the run's real blocks outside the processes that made and accepted them,
    and it checks that the full-mode path (dataset) and the light-mode path (cache)
    agree on them.
  - Conformance to the reference RandomX is shown by the crate's vectors, not here.

## What failed or surprised
1. **Late joiner: one peer, so `checks_passed: false`.**
   - The late joiner connected to node 0 and synced all 2835 blocks by 06:13:46, 6.7
     minutes after it started.
   - It never opened a second connection within the labnet's 900 s. Its debug log
     shows no address messages, dial attempts or feelers. The labnet requires at least
     2 peers.
   - Earlier labnets had 3 peers (labnet-tipnotify-2026-09-28), before the addrman v2
     and RT-W3 peer changes (d45ccbd, 5bb7dc8). That may be the cause; this run does
     not establish it.
   - The same node's chain is byte-identical to the others', and the five fresh
     wallets restored against it matched.
   - For the P2P owner (W3-32 / RT-W3); not a RandomX issue.
2. **The labnet warm-up bug with a full-mode miner** (run 1, fixed in 17ba8b1, above).
3. **Hash rate during the prebuild** fell by about 27 % with 4 build threads on a
   4-core machine. On the testnet, the default of 1 build thread and the longer window
   trade build time for less contention. Not measured here.
4. **The miner logs no background-build lines** (start, end, duration). Operators
   cannot see from the log whether the prebuild finished before a switch; this run
   inferred it from memory and CPU. A small miner logging change would fix it (outside
   this assignment's files).
5. **Regtest-only behaviour:** the late joiner logged `caught up at height 0` 2 s after
   start. Regtest has no tip-age rule in `sync_policy::caught_up`, so the template latch
   set before headers arrived. This is expected on regtest; testnet nodes apply the
   tip-age rule.
6. **Memory pressure from other work** (362 MB free at worst) suspended the light miner
   twice for under a minute. The full-mode miner's second dataset (+2.3 GB) was
   allocated at 03:52, when about 5.9 GB was free (3.0 GB after). No allocation failed, and the
   `--prebuild auto` fallback did not trigger.

## Not demonstrated
- The default build-thread count on regtest, and the light-mode bridge at a switch.
- The `--prebuild auto` fallback after a failed allocation (the miner unit tests cover
  it).
- A reorganization back across the switch (no reorganization touched it).
- Testnet timing (120 s blocks), several machines, several full-mode miners, the
  second switch (4161).
- The machine was shared, so the hash rates are indications.

## Files
- `summary.json`: the numbers above, with their sources.
- `labnet-summary.json`, `metrics.csv` (every 15 s), `journal.log`: the labnet's own
  output.
- `analysis/`:
  - `analyze.py`, `analysis.json`: log analysis;
  - `attribute.py`, `attribution.json`: who mined each checked block;
  - `monitor.ps1`, `monitor-miner-full.csv`: the full-mode miner's memory and CPU, and
    the suspensions.
- `verify/`: `rx-verify.json` and `.log` (main check), and the negative and positive
  controls.
- `logs/info/`: every process's info-level log. `logs/switch-window/`: every line,
  debug included, from 03:50 to 04:10 UTC. `logs/node-late-full.log`: the late joiner's
  full log.
- `run1-aborted/`: the warm-up bug run's journal and miner log.
