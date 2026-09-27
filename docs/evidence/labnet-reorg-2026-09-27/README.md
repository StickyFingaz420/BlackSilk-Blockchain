# Labnet: deep reorganizations without a partition (INV-REORG)

Internal engineering evidence, not an audit.

## Observation
A 4-minute regtest labnet on `w2-rpc-wire` (base 2985a50) ended with final height 141 and `checks_passed: true`, but reported 20 reorganizations, the deepest 22 blocks, with no partition in the window:
```
blacksilk-labnet --nodes 4 --duration-mins 4 --latency-ms 20 --jitter-ms 10 --partition-every-mins 60 --partition-mins 1 --tx-every-secs 20 --base-port 47100 --miner-threads 1
```
That run directory was later deleted. Before that, its node0 chain was copied and its main-chain headers dumped: `analysis/run1-headers.txt`, with columns height, timestamp, delta and difficulty. The observation was then reproduced with the same flags (below).

## Verdict
- **Classification:** expected at these parameters. It is not a P2P, sync, chain-lock, RPC-gate or template bug.
- **Why it is new:** it is a new consequence of the v3 difficulty rule (163bfa0, merged in 4cd343e) combined with the regtest genesis difficulty D0 = 1.
- **Fixing it:** needs a parameter or design decision (see Recommendations), not a code fix in the sync path.

### Mechanism
1. **Difficulty 1 for the first 76 blocks.**
   - The first block of a labnet comes years after the regtest genesis stamp (1 700 000 000). Its solve time is capped at 6T = 60 s and counts in the window for 75 blocks.
   - With every other solve counted at the step T/2 = 5 s, the v3 formula gives `2·n(n+1)/(n(n+1)+22) < 2` at D = 1. The integer result truncates to 1.
   - Blocks 1 to 76 all have difficulty 1, and block 77 gets 2.
   - Test: `consensus/src/difficulty.rs` `a_genesis_gap_holds_difficulty_one_for_the_first_window`.
   - Observed: `analysis/run1-headers.txt` and `analysis/cur2-headers.txt` (D = 1 through height 76, then 2, 3, 4), and the `difficulties` column of `runs/c180-*/metrics.csv`.
2. **At D = 1, every RandomX hash meets the target, so there is no lottery.**
   - Each miner runs a fixed-latency loop:
     - one light-mode hash, about 0.6 s ("1 hashes in 601 ms" in the miner logs);
     - the `/block` submission, whose light-mode PoW check takes about 0.6 s more;
     - one block about every 1.2 s in total.
   - Both miners start together and stay in lockstep.
   - Measured by `analysis/delta.py`:

     | Run | Same-height finds, A vs B | Rival header reaches the other mining node |
     |---|---|---|
     | c180-dbg1 | median 0.26 s, p90 0.83 s | median 0.85 s, p90 0.98 s |
     | cur-dbg1 | median 0.16 s, p90 0.39 s | median 0.80 s, p90 0.92 s |

     About 0.6 s of the header relay time is the receiver's light-mode PoW.
3. **Equal work, first seen: each mining node keeps its own branch** (docs/p2p.md fork choice).
   - The rival's block at height h arrives after the node's own miner has already delivered its own block at h. The rival's h+1 then arrives after the own h+1.
   - The branches stay at equal work for as long as the offset between the miners stays below the relay delay.
   - The non-mining nodes flip whenever one branch briefly leads (c180-dbg1 node1/node3: 8, 12, 14, 18, 20, 21, 28 and 36-deep reorganizations above genesis).
4. **The split ends when the lockstep breaks.** Either timing noise pushes the offset above the relay delay, or D reaches 2 and hash counts become geometric.
   - c180-dbg1 (D = 1 still):
     - miner0's block 72 took an 872 ms hash, then its block 73 led by 0.9 s;
     - node2 accepted header 73 at 18:58:03.492 and reorganized 72 blocks at 03.543;
     - its tip was 73 at 03.553, and miner1's own block 73 was "not on the node's best chain" at 03.707.
   - cur-dbg1:
     - at template 77 (difficulty 2), miner1 needed 5 hashes (3.0 s) against miner0's 2;
     - node2 accepted rival header 77 at 18:21:43.056 and started downloading bodies 1 to 76 at 43.115;
     - the 76-deep reorganization is logged at 43.612, and the tip was 77 at 43.627.
5. **After height 76 the difficulty stays far below equilibrium.**
   - The v3 rise bound, at most 2 times the window average, gives D = 2, 3, 4 by height 145. The pre-v3 rule reached D ≈ 18 by height 16 (`analysis/base1-headers.txt`).
   - Blocks keep coming every 1.2 to 2 s against the 0.8 to 0.9 s relay delay. About 46 to 48 % of the blocks the miners found are not in the final chain.
   - Reorganizations continue, but shallow ones: every reorganization deeper than 8 blocks forked below height 76.

### What was ruled out, from the debug logs of cur-dbg1 and c180-dbg1
- **Chain lock, sync or body download:**
  - no request timeouts, no "do not beat our best chain" drops, no misbehaviour, no dropped bodies;
  - the whole 76-deep switch took 0.57 s, from the rival's decisive header to the new tip, including 76 bodies downloaded and validated.
- **Refusal of a peer's branch:**
  - equal-work rival headers were verified and stored ("headers ... accepted (new: true)"). Their bodies are fetched once that branch has the most work, as specified;
  - `worth_verifying` and the anti-DoS threshold never dropped a batch;
  - the RT-1 gating saw no unknown versions;
  - the `/block` gate refused 2 to 4 miner blocks per run, all built on a parent that had just left the connected chain. The message now says so (it used to read like a height rule).
- **Stale templates:**
  - at D = 1 the miner fetches a new template after every block (at most about 1.3 s old), so the 5 s refresh never applied;
  - at D ≥ 2 the lack of a tip notification (09 M9-1) adds stale work, but it is not what makes the deep splits.

## Is it new? Identical flags, current code against the pre-v3 base
Labnet has no seed option, so several runs were made of each. Reorganization counts are per node log line, summed over nodes 0 to 3.

| Run | Code | Final height | Reorgs | Max depth | Fork < 76: count (max) | Fork ≥ 76: count (max) | Found blocks not in final chain |
|---|---|---|---|---|---|---|---|
| cur-dbg1 | c3bd12c + instrumentation, debug logs | 149 | 24 | 76 | 9 (76) | 15 (4) | 46 % |
| cur-2 | c3bd12c + instrumentation | 149 | 27 | 25 | 12 (25) | 15 (8) | 47 % |
| cur-3 | c3bd12c + instrumentation | 102 | 17 | 38 | 5 (38) | 12 (4) | 48 % |
| c180-dbg1 | 180d1ca + this branch, debug logs | 142 | 41 | 72 | 17 (72) | 24 (6) | 48 % |
| c180-2 | 180d1ca + this branch | 147 | 21 | 20 | 9 (20) | 12 (3) | 46 % |
| base-1 | d915be4 (pre-v3 DAA) | 42 | 4 | 6 | all above genesis, 3 (6) | 1 (1) | 30 % |
| base-2 | d915be4 | 41 | 10 | 10 | 7 (10) above genesis; 3 later (1) | | 34 % |
| base-3 | d915be4 | 54 | 25 | 7 | 5 (7) above genesis; 20 later (2) | | 39 % |

For the base runs, the fork-point split is "above genesis" against "later", because the pre-v3 rule leaves D = 1 after about 7 blocks.

- **The v3 DAA is the contributor.** At the pre-v3 base the D = 1 phase lasts about 7 blocks: deep reorganizations appear only above genesis and stay at most 10 deep, and the chain reaches about 5 to 6 s blocks within the run.
- **No Wave 1 sync change contributes.** The later-phase depths (8 or less) are the ordinary orphan races of 1.2 to 2 s blocks.
- **The original 22-deep observation fits the same pattern.** It is node2's switch above genesis at height 22, while D was 1.

## Expected distribution (model)
Two miners, each finding blocks at rate λ = 1/cycle, with relay delay δ ≈ 0.85 s (measured).

**D = 1:** the depth of a split is not geometric. It lasts until the drift of two nearly equal fixed cycles exceeds δ: tens of blocks, up to the whole 76-block window, as observed.

**D ≥ 2:** the chance that the rival finds a competing block within δ is about `1 − e^(−λδ)`.

| D | Cycle | P(competing block) | Depth ≥ 3 |
|---|---|---|---|
| 2 | ≈ 1.8 s | ≈ 0.37 | a few per hundred blocks |
| 4 | ≈ 3 s | ≈ 0.25 | |

At regtest equilibrium (10 s blocks; the pre-v3 base runs settled at D ≈ 18 to 20 with these two miners), the pure relay term is about 4 %. The miner's refresh staleness (09 M9-1) comes on top of it; seedrun2 measured about 28 % of heights with two blocks.

## The seedrun2 "stuck node" (labnet-seedswitch-2026-09-27): a detector false positive, a different cause
In `seedrun2/metrics-window.csv`, node1 trailed the best height by one block at the samples 1790507835, …867, …888 and …911. Its height went 2556, 2559, 2564, 2566 over that window, so it was advancing. The miner's node was simply one block ahead at each sampled instant.

The labnet detector counted "behind at every sample for more than 90 s" as stuck, even though the node was progressing. This is a labnet bug, now fixed:
- `StuckDetector` counts a stall only while the tip does not move;
- unit test `trailing_by_one_while_advancing_is_not_stuck` reproduces the seedrun2 shape.

It is unrelated to the deep reorganizations: those are equal-height splits, which the height-based detector never sees.

## Testnet relevance
- **No freeze at 1 on testnet.** With D0 = 100 the integer truncation is not binding.
- **Slower ramp from a low D0.** The rise bound makes the ramp from a low D0 slower than before (`analysis/ramp2.py`, 5 seeds, single chain, genesis gap 2 h):

  | D0 | v3 rule | Pre-v3 rule |
  |---|---|---|
  | 10 times too low | 88 blocks to 80 % of equilibrium | 14 to 81 |
  | 100 times too low | 197 blocks | 15 to 81 |

- **The same regime at launch if D0 is far too low.** During the ramp, block intervals are about T·D/D_eq. With a D0 100 times too low they start near 1.2 s, and light-mode verification alone costs about 0.6 s per hop.

## Recommendations (not implemented here)
1. **Regtest D0 (consensus parameter, needs approval).**
   - Raising the regtest D0 (for example 16 to 32, near light-mode equilibrium at T = 10) removes the D = 1 lockstep phase.
   - It changes the regtest genesis id, the fingerprint vectors and `REGTEST_GENESIS_ID`.
   - Alternative: set the regtest genesis stamp at node start. This is not recommended, because it gives each run a different genesis.
2. **Labnet (tools/labnet).**
   - Either start with one miner until the tip difficulty is within 2 times of the miners' equilibrium, or report reorganizations separately for the warm-up.
   - Do not read reorganization counts from runs shorter than about 10 minutes at regtest.
   - The new `difficulties` metrics column makes the phase visible.
3. **Testnet launch.** Measuring D0 (dossier 40 P7 / F40-12, and the miner `--benchmark` from 09) matters more under v3.
4. **Tip notification for the miner (09 M9-1)** and **faster light-mode verification (06 F1)**. The relay delay per hop is dominated by one light-mode hash.

## Reproduce
- **Build:**
  - `CARGO_TARGET_DIR=C:/bszkeval/t-inv-reorg cargo build --locked --release -p blacksilk-node -p blacksilk-miner -p blacksilk-labnet`, on branch `inv-reorg`;
  - for the base, the same command on a `git archive d915be4` tree with its own target directory.
- **Runs:** `analysis/runs.sh` and `analysis/runs2.sh`. The debug runs add `RUST_LOG=info,blacksilk_p2p=debug,blacksilk_chain=debug,blacksilk_miner=debug`.
- **Summaries:** `python analysis/summ.py <run dirs>`, `python analysis/delta.py <debug run dir>`, `python analysis/hdr.py <blocks json>` (from `/blocks` of a node restarted on a copy of a run's data directory), and `python analysis/ramp.py` / `ramp2.py`.
- **Machine:** Windows 10, 8 logical CPUs, 4 nodes and 2 one-thread light-mode miners on one host.

## Files
- `runs/<run>/`: `summary.json`, `metrics.csv` and `journal.log` of every run.
- `logs/c180-dbg1/`: debug logs of all nodes and miners at 180d1ca.
- `logs/cur-dbg1/`: node2 and the miners at c3bd12c.
- `logs/base-1/`: info-level logs at d915be4.
- `seedrun2/`: the stuck-incident journal line and its metrics window.
