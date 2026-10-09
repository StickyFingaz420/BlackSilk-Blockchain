# xmrig compatibility gate: real xmrig mining BlackSilk regtest blocks (2026-10-09)

Internal engineering evidence, not an audit. One machine, one CPU.

A locally patched xmrig v6.26.0 (`rx/blacksilk`: RandomX v1 with BlackSilk's Argon2
salt) mined regtest blocks through `tools/stratum-bridge` into a `blacksilk-node`.
The bridge compared every xmrig result byte for byte with the node's own
`RandomXPow::pow_hash`. Every submission was recomputed offline afterwards, and
the chain was rechecked in a fresh process. A negative control (xmrig hashing
with Monero's `rx/0` salt) shows that the comparison does catch a wrong salt.

**Gate verdict for runs A, L and NC (steps 1 to 6 of the plan): PASS.** No
`GATE-MISMATCH` on a BlackSilk job, no `GATE-INTERNAL`, no job rejected by xmrig,
no node rejection of a bridge-verified block, and no invalid share accepted. The
negative control identified every result as Monero `rx/0`, and the offline
recompute found 0 mismatches.

**Run B (seed switch): PASS.** xmrig mined on from height 557 to 2134 across the
first RandomX key switch at height 2113, re-keying from `seed_hash` alone, with
the same criteria met (see "Run B" below). In all, 2,133 xmrig blocks are on the
best chain at height 2134 (A 542, L 13, B 1,578; the remaining block is the
probe's).

## Scope and limits

- **One machine, one CPU code path.** Intel Core i7-6700 (AVX2, AES), Windows 10
  Pro 10.0.19045, 16 GB. xmrig picks its Argon2 (`AVX2` here) and AES code paths by
  CPU, so only this machine's paths were exercised.
- **Light-mode verification.** The bridge and the node verify with
  `blacksilk-randomx` light mode. xmrig mined in fast mode (its own 2 GiB dataset
  and JIT) in runs A and NC, and in light mode in run L.
- **xmrig's fast mode is supporting evidence, not the full-mode reference gate.**
  Byte-equal results from xmrig's dataset and JIT agree with BlackSilk's light
  mode, and `rx-verify --full` adds BlackSilk's own full dataset for 77 heights.
  Neither is the comparison against the RandomX reference implementation.
- **One key switch.** Runs A and L use the genesis key (key height 0). Run B
  crossed the first key switch on regtest (height 2113, key height 2048) once, on
  this one machine; 22 best-chain blocks (2113 to 2134) use the new key. Later
  switches and a switch during a reorganization are not covered.
- **RandomX v1 versus v2.** xmrig 6.26.0 also ships RandomX v2 (`rx/2`).
  BlackSilk is v1; the patch derives `rx/blacksilk` from the v1 base
  configuration. A future xmrig refactor of that base could break the patch.
- **xmrig low-nonce fingerprint (privacy).** xmrig writes only the low 32 bits of
  the 64-bit header nonce and counts them up from a small per-thread start. In
  run A the largest low-32 value submitted was 105,345, in run B 113,939. The bridge randomizes
  the high 32 bits per job, but blocks mined with xmrig remain distinguishable
  from `blacksilk-miner` blocks, which start at a random 64-bit nonce.
- **Hashes filtered out locally are lost by design.** While the block difficulty
  is below the share floor (3600), xmrig only submits hashes that meet the floor;
  a hash that meets the block difficulty but not the floor is a valid block that
  is never submitted. That is acceptable for a regtest gate and does not apply
  once the block difficulty exceeds the floor.
- **Sibling blocks.** 200 of run A's 744 xmrig submissions were valid blocks the
  node accepted off the best chain (`OK_OFF_BEST_CHAIN`): xmrig found them on a
  job whose tip had already been extended by an earlier share still being
  verified (about 1 s per share at the bridge plus the node). They are counted
  separately from best-chain blocks. `rx-verify` reads the best chain only, so it
  does not recheck these 200; the offline recompute does cover their results.
- **Regtest only, loopback only.** The bridge is an evidence tool, not part of the
  release package and not a pool.

## Build and versions

| Item | Value |
|---|---|
| Date | 2026-10-09 |
| Repository HEAD | `65d5a70` (rebuild/core, "Merge xmrig-gate/bridge"), checked out clean in a worktree |
| Build commit of the gate binaries | `65d5a70d0b86668ff8662163d3bfe59809e81d1d` (the node prints it; the bridge, probe, rx-verify and wallet print `commit unknown` because only the node embeds its commit; all five were built in the same invocation from the same worktree) |
| Build command | `CARGO_TARGET_DIR='C:\bsgate\target' bash tools/release-build.sh -p blacksilk-node -p blacksilk-stratum-bridge -p blacksilk-labnet -p blacksilk-wallet` (3 min 31 s; `build/build.log`) |
| `--version` | every binary prints `build flags: none` (`build/versions.txt`) |
| `tools/check-build-flags.sh --strings` | all five clean (`build/check-build-flags.txt`) |
| Binary SHA-256 | `build/bin-sha256.txt` |
| xmrig | v6.26.0, tag commit `b2ca72480c58d197e18c885d9fc1a0c8d517e60a` (lightweight tag; cloned with `git clone --branch v6.26.0 --depth 1`) |
| xmrig binary | `xmrig-notls.exe`, SHA-256 `c7bb8a3da51e77ad0aa7b84d9d82beec593b78eb29e99c797f7844635e8de00e`, re-hashed before the run (matches the build record) |
| xmrig build | MSVC 19.44 (VS 2022), CMake 3.31.6-msvc6, `-DWITH_TLS=OFF -DWITH_HWLOC=OFF -DWITH_OPENCL=OFF -DWITH_CUDA=OFF -DWITH_KAWPOW=OFF -DWITH_GHOSTRIDER=OFF -DWITH_MSR=OFF -DWITH_HTTP=OFF` |
| xmrig-deps | v25.06.16, commit `24c64e8ccdc532bcd396bf1da908ddc70cd2afbc`, zip SHA-256 `a0b75254340def5c5615297b9f08b7a0eb9c24450fd220a9411fb7b8074c8756` |
| Patch | `xmrig-rx-blacksilk.diff`, SHA-256 `63d3e16e638553ae4f233cd766f6885b0863d7f6b7a5ec21458b0b1de374b4ea`, 6 files, 20 insertions, 3 deletions. Kept off-tree (see below) |
| `gate.json` | SHA-256 `c66274bbfa46bee349ea3428f475731d9a6d2932c9e3c24659da60c39fb6ab2f` (`config/gate.json`) |

xmrig source, binaries and the GPL-derived patch text are not in this repository.

### The patch, in prose

The diff itself is GPLv3-derived and the repository has no licence yet, so only
its hash and this description are recorded.

1. `src/base/crypto/Algorithm.h`: a new enum value `RX_BLACKSILK = 0x72151262`
   (RandomX family 0x72, L3 2 MiB, L2 256 KiB as `rx/0`, coin byte 0x62, unused by
   any other variant) and the name declaration `kRX_BLACKSILK`.
2. `src/base/crypto/Algorithm.cpp`: the name `"rx/blacksilk"`, its entry in the
   name table, an automatic alias (no extra aliases) and its place in the
   `Algorithm::all()` list.
3. `src/crypto/randomx/randomx.h`: `struct RandomX_ConfigurationBlackSilk`,
   derived from `RandomX_ConfigurationBase` (RandomX v1, every `Tweak_V2_*` flag 0),
   not from the Monero v2 configuration, and its global instance declaration.
4. `src/crypto/randomx/randomx.cpp`: the constructor, whose only statement sets
   `ArgonSalt = "BlackSilk/RandomX/v1"` (20 bytes); every other parameter keeps
   the `rx/0` value. Plus the global instance.
5. `src/crypto/rx/RxAlgo.cpp`: `RxAlgo::base()` maps `RX_BLACKSILK` to that
   configuration. Without it the switch default would return the `rx/0`
   configuration (the wrong salt) silently.
6. `src/donate.h` (not PoW): default and minimum donate level 1 to 0. xmrig then
   creates no `DonateStrategy` (`Network.cpp`), so no donation-pool connection can
   be made.

### RX_SFX grep check and the rx/0 known-answer test (from the build record)

- `grep -rn "RX_SFX\|RX_BLACKSILK\|BlackSilk" src/` after patching: every switch
  or list that names `RX_SFX` either has an `RX_BLACKSILK` arm or does not matter
  in this build (`RxAlgo::id()` and `RxAlgo::version()` are used only by the CUDA
  and OpenCL backends, both compiled out; the OpenCL `.cl` file is not built;
  `Coin.cpp` is coin mode only; the CPU profile falls back to `rx`, confirmed by
  `use profile rx` in the logs). `RxSeed::isEqualSeedAlgo` keeps `rx/blacksilk`
  distinct from `rx/0`, so switching algorithms rebuilds the dataset.
- The patched build's own benchmark `--bench=1M --algo=rx/0` (4 threads, fast
  mode) gave hash sum `898B6E0431C28A6B`, equal to xmrig's reference table entry
  for `{RX_0, 1000000}`. The shared RandomX v1 code path is intact after the
  patch. `--bench=250K --algo=rx/blacksilk` gave a different sum
  (`017D8A83D6C55AA2`), showing the salt took effect; xmrig has no BlackSilk
  reference value, which is what this gate supplies.
- Program output, copied here: `xmrig-build/bench-results.txt` (the two bench
  result lines) and `xmrig-build/rx-sfx-grep-summary.txt` (file, line and matched
  identifier of every grep hit). The raw grep output quotes xmrig source lines, so
  only that summary is committed. The raw output, the bench logs and the build
  record (`BUILD-RECORD.md` of the local xmrig build) stay off-tree with the xmrig
  build.

## Runs and command lines

Runtime data was in `C:\bsgate\` (outside the repository). The node's data
directory was `C:\bsgate\node`. Each process ran in its own hidden console and was
stopped with Ctrl-C delivered by PID (a small `AttachConsole` and
`GenerateConsoleCtrlEvent` helper), which also delivered xmrig's console keys
`p` (pause) and `r` (resume).

```
blacksilk-node --network regtest --data-dir C:\bsgate\node --no-p2p        (RPC 127.0.0.1:39333)
blacksilk-wallet -w C:\bsgate\wallet\gate.wallet --node 127.0.0.1:39333 --rpc-cookie C:\bsgate\node\rpc.cookie create --network regtest
blacksilk-wallet -w C:\bsgate\wallet\gate.wallet --node 127.0.0.1:39333 --rpc-cookie C:\bsgate\node\rpc.cookie address

# run A (fast mode) and run L (light mode): one bridge each, same flags apart from the log names
blacksilk-stratum-bridge serve --node 127.0.0.1:39333 --rpc-cookie C:\bsgate\node\rpc.cookie --listen 127.0.0.1:3334 --payout <regtest address> --min-share-diff 3600 --allow-session-diff --log-stratum runA-stratum.log --log-submits runA-submits.jsonl
xmrig-notls.exe -c C:\bsxmrig\gate.json --donate-level 0 --log-file C:/bsgate/logs/runA-xmrig.log
xmrig-notls.exe -c C:\bsgate\gate-light.json --donate-level 0          (gate.json with "mode":"light" and its own log file)

# probe (xmrig paused with 'p'; resumed with 'r' afterwards)
blacksilk-stratum-probe cases --bridge 127.0.0.1:3334 --diff 1 --node 127.0.0.1:39333 --rpc-cookie C:\bsgate\node\rpc.cookie
blacksilk-stratum-probe replay --bridge 127.0.0.1:3334 --diff 1 --node 127.0.0.1:39333 --rpc-cookie C:\bsgate\node\rpc.cookie --job-id 9 --nonce 13000000 --result <xmrig's result for that share>
blacksilk-stratum-probe direct-to-node --node 127.0.0.1:39333 --rpc-cookie C:\bsgate\node\rpc.cookie --payout <regtest address>

# negative control
blacksilk-stratum-bridge serve ... --min-share-diff 3600 --negative-control-algo rx/0 --log-stratum runNC-stratum.log --log-submits runNC-submits.jsonl
xmrig-notls.exe -c C:\bsgate\gate-nc.json --donate-level 0            (gate.json with "algo":"rx/0" and its own log file)

# offline recompute
blacksilk-stratum-bridge recompute --log runA-submits.jsonl --only-agent XMRig/
blacksilk-stratum-bridge recompute --log runL-submits.jsonl --only-agent XMRig/
blacksilk-stratum-bridge recompute --log runNC-submits.jsonl --only-agent XMRig/ --expect-negative-control

# recheck
blacksilk-rx-verify --node 127.0.0.1:39333 --cookie C:\bsgate\node\rpc.cookie --network regtest --full 480-556 --threads 4 --out rx-verify.json
```

The share floor 3600 is about 3 times xmrig's measured hash rate. In run A (fast
mode, 4 threads) xmrig's 10 s `speed` readings outside the two pauses were 1,112
to 1,206 H/s, with a logged maximum of 1,211.8 H/s; in light mode about 228 H/s.

## Results

| Run | xmrig mode | Heights | xmrig submissions | Best-chain blocks | Off-best-chain blocks | Stale | Other rejections | Blocks at block_diff > 3600 | block_diff range |
|---|---|---|---|---|---|---|---|---|---|
| A | fast (dataset verified) | 1 to 543 | 744 | 542 | 200 | 2 | 0 | 59 (heights 485 to 543) | 1 to 8,671 |
| L | light | 544 to 556 | 13 | 13 | 0 | 0 | 0 | 13 | 4,197 to 7,258 |
| NC | fast, `rx/0` | none (tip stayed 556) | 33 | 0 | 0 | 0 | 33 `Invalid result`, all `nc_rx0_match` | n/a | 4,058 |
| probe | n/a | 10 | 7 probe submissions (not xmrig) | 1 (case d, labelled `A-probe` in `blocks.tsv`) | 0 | 2 | 4 | 0 | 1 |

- Plan (D) asked for "all on the best chain". That was replaced by the bridge
  critique's L7 accounting: best-chain blocks (`OK`) and blocks the node accepted
  off the best chain (`OK_OFF_BEST_CHAIN`) are counted separately, and neither is
  a rejection.
- Height 543 includes one block per height from 1 to 543: 542 xmrig blocks and
  the probe's case (d) at height 10.
- Run A: LWMA reached the floor at height 485 (difficulty 3605) and 8,671 at most.
  The condition "at least 50 xmrig blocks at `block_diff > min_share_diff`" was met
  with 59 in run A alone (72 with run L). The climb took 485 blocks, inside the
  600-block limit, so the floor was not lowered.
- Every hashed xmrig submission in runs A and L has `result == bridge_hash`
  (`blocks.tsv` column `equal` is `Y` on all 755 xmrig rows).
- The node logged no rejection of any bridge-submitted block. Its only rejection
  in the whole run is the probe's direct-to-node block.
- The 2 stale shares in run A (jobs 66 and 200) were superseded jobs; the bridge
  does not hash those live, and the offline recompute matched both.

### H1: fast mode was really fast mode

From `logs/h1-dataset-grep.txt` (run A):

```
randomx  init dataset algo rx/blacksilk (4 threads) seed 3dbdba2aca8842cd...
randomx  allocated 2336 MB (2080+256) huge pages 0% 0/1168 +JIT (0 ms)
randomx  dataset ready (7525 ms)
count slow mode/failed to allocate: 0
```

Run L logs `fast RandomX mode disabled by config` and `switching to slow mode`, as
light mode should.

### Probe cases (exact replies)

`logs/probe-cases.txt`, `logs/probe-replay.txt`, `logs/probe-direct-to-node.txt`.
Cases a to e2 ran on one probe session at difficulty 1 (job 11, height 10) while
xmrig was paused but still connected; xmrig's session kept mining after `r`.

| Case | Submission | Expected | Got | Tip unchanged |
|---|---|---|---|---|
| c | 7-hex nonce | `Invalid nonce` | `Invalid nonce` | yes |
| a | nonce n+1 with the true hash of n | `Invalid result` | `Invalid result` | yes |
| b | true hash with one bit flipped | `Invalid result` | `Invalid result` | yes |
| e | (b) again on the still-current job | `Duplicate share` | `Duplicate share` | yes |
| d | a valid share | `OK` | `OK` (block height 10) | moved, as expected |
| e2 | (d) again after the new job | `Stale job` | `Stale job` | yes |
| f | job 9 / nonce `13000000` (xmrig's accepted share) submitted on a new probe session; see the note below | `Stale job` | `Stale job` | yes |
| direct-to-node | a node-template block whose hash fails the block difficulty (226, height 352), sent straight to `/block` | `InsufficientWork` | `InsufficientWork`; node log: `block rejected: Header(InsufficientWork)` | yes |

Note on case f: the replayed `result` carried a trailing carriage return
(`logs/runA-stratum.log` line 60), an artefact of the shell that passed xmrig's
result to the probe. The `Stale job` reply still shows that jobs are
session-scoped, because the bridge checks the job before it parses the result;
but the case is best read as "job 9 / nonce `13000000` submitted on a new
session", not as a byte-exact replay of xmrig's share.

### Negative control

`logs/runNC-*`, `logs/recompute-NC.txt`: 33 xmrig results on `rx/0`-labelled jobs;
33 classified `nc_rx0_match` (xmrig's result equals Monero's `rx/0` hash of the same
blob and differs from BlackSilk's); 0 `nc_blacksilk_match`, 0 `nc_unidentified`;
`blocks_submitted` 0; every reply `Invalid result`; node tip `5e0ea890f7196a1a`
(height 556) before and after. Recompute: `records 33, recomputed 33, negative
control 33 (rx/0 33, blacksilk 0)`: PASS.

### Offline recompute (H3)

`logs/recompute-A.txt`, `logs/recompute-L.txt`, with `--only-agent XMRig/`:

| Log | Records | Skipped (probe) | Hashed live | Recomputed | Matches | Mismatches | Inconsistent | Verdict |
|---|---|---|---|---|---|---|---|---|
| run A | 744 | 7 | 742 | 744 | 744 | 0 | 0 | PASS |
| run L | 13 | 0 | 13 | 13 | 13 | 0 | 0 | PASS |
| run B | 1,767 | 0 | 1,766 | 1,767 | 1,767 | 0 | 0 | PASS |

Every xmrig submission of runs A, L and B is covered, including the 3 stale ones
that were not hashed live (`logs/recompute-B.txt` for run B).

### Counter cross-check

`logs/analysis.txt`:

| Run | xmrig `accepted/rejected` (last line) | Bridge OK-status replies | Bridge error replies |
|---|---|---|---|
| A | 741 / 2 | 742 | 2 |
| L | 13 / 0 | 13 | 0 |
| NC | 0 / 33 | 0 | 33 |
| B | 1,765 / 1 | 1,766 | 1 |

Run A's one-share difference: submit id 745 (job 546, block height 543) reached
the bridge at 04:16:06.820 UTC; the node accepted the block, and the bridge wrote
`OK` to its stratum log at 04:16:07.888. xmrig was stopped with Ctrl-C in that
second, and xmrig's connection closed before the reply was written: the bridge
logged `session 0c3be847 closed` at 04:16:07 before its `BLOCK height 543` line
(`logs/runA-bridge.log` line 1295), so the `OK` was probably never delivered.
xmrig's last log line is at 06:16:00.414 local time (04:16:00 UTC).
xmrig's 2 rejections are the 2 `Stale job` replies.

### Job difficulty as xmrig decoded it (M4, L1)

For every job notification sent to an xmrig session, the difficulty xmrig logged
(`new job ... diff D ... height H`) was compared with `floor((2^64-1)/target64)`
and with the bridge's share difficulty minus one, `max(block_diff, 3600) - 1`.

| Run | Jobs | xmrig `new job` lines | Mismatches |
|---|---|---|---|
| A | 543 | 543 | 0 |
| L | 18 | 18 | 0 |
| NC | 3 | 3 | 0 |
| B | 1,581 | 1,581 | 0 |

The logged value is exactly `d - 1` (3599 in the floor regime, `block_diff - 1`
above it), as the ceiling target predicts, and height and algorithm agree on
every job. No job had d = 1 for xmrig (its floor was 3600).

### Recheck with rx-verify

`rx-verify.txt`, `rx-verify.json`. A fresh-process recheck with the same crate
(`blacksilk-randomx`, not a second implementation):

```
127.0.0.1:39333: 556 headers
key height 0: 556 light hashes in 62.4 s (cache 0.6 s)
key height 0: dataset built in 194.0 s
nodes agree true (1..=556), light 556 checked / 0 failed, consensus accepted 556, full 77 compared / 0 mismatched: PASS
```

The full-mode range 480 to 556 covers run A's above-floor blocks and all of run
L. The node was then stopped with Ctrl-C and restarted: it loaded `height 556,
tip 5e0ea890f7196a1a`, the same tip (`logs/node-restart.log`, the first 10
lines; it also re-verified 64 of 756 stored proof-of-work hashes at load).

### xmrig network posture

`logs/donate-pool-grep.txt`. In all three xmrig logs the only donate line is
`* DONATE 0%`, and the only address is `127.0.0.1:3334` (545, 20 and 5 occurrences),
plus the bare `127.0.0.1` of the `use pool` line. The control is the patched
`donate.h` together with `--donate-level 0` and `"donate-level": 0`.

Firewall:
- The owner said the firewall was disabled for this work.
- `netsh advfirewall show allprofiles` showed all three profiles `ON`, each with
  the policy `BlockInbound,AllowOutbound` (`firewall-netsh.txt`; captured after
  runs A, L and NC, during run B).
- No firewall rule targeted the gate's xmrig binary, so the planned outbound-block
  guard was absent.
- The only controls were the patched `donate.h`, `--donate-level 0` and the log
  grep above. No netstat sampling was done.

## Run B (seed switch)

Run B continued on the same node from height 556 with a new bridge (same flags,
`runB-*` logs) and xmrig in fast mode with the unchanged `gate.json`:
`xmrig-notls.exe -c C:\bsxmrig\gate.json --donate-level 0 --log-file C:/bsgate/logs/runB-xmrig.log`.
It ran from 06:39 to 10:58 local time (04:39 to 08:58 UTC) and was stopped with
Ctrl-C by PID: xmrig, then the bridge, then the node.

| Criterion | Result |
|---|---|
| Blocks | 1,767 xmrig submissions: 1,578 best-chain blocks (heights 557 to 2134), 188 off the best chain, 1 stale share (job 1250); block difficulty 3,720 to 14,663, all above the 3600 floor |
| Per key | key `3dbdba2aca8842cd` (genesis): 1,556 best-chain and 186 off-chain blocks, 1 stale; key `b2835265be38b157` (height 2048): 22 best-chain blocks (2113 to 2134) and 2 off-chain |
| `GATE-MISMATCH`, `GATE-INTERNAL`, other errors | 0 (`runB-bridge.log` has no `GATE-` or `ERROR` line) |
| Node rejections | 0 (`logs/node-runB.log` has no `rejected` line) |
| Offline recompute | 1,767 recomputed, 1,767 match, 0 mismatches: PASS (`logs/recompute-B.txt`) |
| Counters | xmrig 1,765 accepted / 1 rejected (the stale share); bridge 1,766 OK / 1 error. The one-share difference is submit id 1771 (block 2134): the bridge logged `session b2baee9a closed` at 08:58:17 before its `BLOCK height 2134` line (`runB-bridge.log` line 3350), the same shutdown race as in run A |
| Job difficulty (d - 1) | 1,581 jobs, 1,581 xmrig `new job` lines, 0 mismatches (`logs/analysis-B.txt`) |
| Fast mode | `dataset ready` at start; 0 `slow mode` or `failed to allocate` lines |
| Restart | the node reloaded `height 2134, tip a1f9517742fa4d5b`, the tip it had at shutdown (`logs/node-restart-after-runB.log`) |
| Network posture | the only donate line is `* DONATE 0%`; the only address is `127.0.0.1:3334` (`logs/donate-pool-grep-B.txt`) |

**xmrig re-keyed by itself from `seed_hash`** (`logs/h1-seedswitch-grep-B.txt`).
The bridge's job for height 2113 (job 1560) carried the new key in `seed_hash`;
jobs 1558 and 1559 for heights 2111 and 2112 carried the genesis key. Nothing else
told xmrig to switch. xmrig logged:

```
3577: new job from 127.0.0.1:3334 diff 12038 algo rx/blacksilk height 2113
3578: randomx  init dataset algo rx/blacksilk (4 threads) seed b2835265be38b157...
3579: randomx  dataset ready (7102 ms)
```

It found block 2113 thirteen seconds after that job (`BLOCK height 2113` at
08:54:55 UTC), and the node accepted it on the best chain.

**Recheck with rx-verify (run B).** A fresh-process recheck with the same crate,
over the whole chain, with full mode across the switch (`rx-verify-B.txt`,
`rx-verify-B.json`):

```
blacksilk-rx-verify --node 127.0.0.1:39333 --cookie C:\bsgate\node\rpc.cookie --network regtest --full 2100-2134 --threads 4 --out rx-verify-B.json
127.0.0.1:39333: 2134 headers
key height 0: 2112 light hashes in 271.3 s (cache 0.6 s)
key height 2048: 22 light hashes in 3.1 s (cache 0.6 s)
key height 0: dataset built in 226.4 s
key height 2048: dataset built in 226.7 s
nodes agree true (1..=2134), light 2134 checked / 0 failed, consensus accepted 2134, full 35 compared / 0 mismatched: PASS
```

The node was restarted for this recheck (rx-verify reads `/headers`) and stopped
again afterwards. In run B xmrig's 10 s hash-rate readings were 885 to 1,221 H/s.

## Files

| File | Content |
|---|---|
| `blocks.tsv` | every block the node accepted from the bridge in runs A, L and B (on and off the best chain), with block id, difficulties, job, header nonce, xmrig result, bridge hash, equality and reply |
| `logs/runA-*`, `logs/runL-*`, `logs/runNC-*`, `logs/runB-*` | xmrig log, bridge log, stratum log (every line in and out) and submit log (one JSON line per submit) for each run |
| `logs/node.log`, `logs/node-restart.log`, `logs/node-runB.log`, `logs/node-restart-after-runB.log` | node log of runs A, L and NC; the first lines after the first restart; the node log of run B (it starts with that restart); the restart after run B |
| `logs/probe-*.txt` | probe output |
| `logs/recompute-*.txt`, `logs/analysis.txt`, `logs/analysis-B.txt` | offline recompute, counts, counter and job-difficulty checks |
| `logs/h1-dataset-grep.txt`, `logs/h1-seedswitch-grep-B.txt`, `logs/donate-pool-grep*.txt` | the H1, re-keying and network-posture greps |
| `rx-verify.txt`, `rx-verify.json`, `rx-verify-B.*` | the chain rechecks after runs A/L/NC and after run B |
| `build/` | build log, `--version` output, build-flag check, binary SHA-256 |
| `config/` | `gate.json` and the two copies used for runs L and NC |
| `xmrig-build/` | the two xmrig bench result lines and the RX_SFX grep summary (program output) |
| `firewall-netsh.txt` | `netsh advfirewall show allprofiles`, captured during run B |
| `SHA256SUMS` | SHA-256 of every other file here |

**Redaction.** No file here contains a path under the user profile (checked with
`grep -iE 'c:[\/]users|home 01|home01|/c/users'`), and none contains the RPC
cookie value. The cookie used during runs A, L and NC was overwritten when the
node restarted, so it could not be grepped for directly; the restart's cookie was
grepped for and is absent. The node removes its cookie at a clean shutdown, so
the cookies of run B and of the last restart could not be grepped for either, and every 64-hex value in these files was accounted
for: block ids, xmrig results and bridge hashes, the RandomX seed, SHA-256 values
of files and binaries, and the digests the node prints in `--version` (plus three
SHA-256 values from the xmrig build record in this README). The paths that remain are `C:\bsgate\...` (runtime data),
`C:\bsxmrig\...` (the xmrig build) and the build worktree `C:\bszkeval\...`. The
wallet's seed words, password and the regtest payout address are not recorded.
The submit logs record the block ids and the session ids only.
xmrig's hash-rate lines were kept (run A's xmrig log is 114 KiB, run B's 320 KiB).
With run B the folder is about 6 MB, most of it run B's stratum, submit and bridge
logs; they are kept whole because the offline recompute and the job-difficulty
check read them.
