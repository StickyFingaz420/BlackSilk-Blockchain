# Red-team study of the recommended difficulty rule (RT-DAA), 2026-09-27

Internal engineering evidence for the "DAA DECIDED" entry of the coordinator's decision log.
This is not an audit. It attacks the rule that the W0-03b selection study chose
(`selection.md`): LWMA-1 with N = 75 and the counted clock `this = max(ts, prev + max(1, T/2))`.
Consensus code is unchanged. The candidate rules and the fix exist only in the harness
`tools/daa-sim`.

- **Branch:** `rt-daa`, based on `rebuild/core` at `b02ac91`.
- **Machine:** Intel Core i7-6700 (4 cores, 8 threads), Windows 10, rustc 1.98.1.
- **Main command:** `cargo run --release -p blacksilk-daa-sim -- --redteam`. It uses base seed
  `0x0daa7ea3` and 6 threads, and takes about 10 min. Its output is at the end of this file,
  unedited. It covers three subjects: the rule under attack, the candidate fix, and the current
  consensus rule (LWMA-60, step 1) as a reference. It ends with the selection study's own
  runner (`selection::run`, main seed `0x5e1ec7ed`) applied to the rule under attack and the fix.
- **Consistency check:** in that last section, the rule under attack reproduces its row of
  `selection.md` exactly (+3.8%, +0.15%, +0.69%, +2.4, +1.01%, 113/113, 130/133, 2, 12).
- **Supporting commands** (examples in `tools/daa-sim/examples/`):
  - `--example anchor_ablation`: the rollout attacker against warm-up lengths 0, 1, 11 and 75.
    Warm-up 1 needs `-- 3000 1000 76 6 o`.
  - `--example rollout_trace`: which stamps the rollout attacker chooses.
  - `--example hop_ahead`: forward-stamping hoppers, by how far ahead they stamp.
- **Pinning tests:** `tools/daa-sim/tests/redteam.rs`. `cargo test --release -p blacksilk-daa-sim`
  takes about 40 s.
- Results depend only on the seeds. Floating-point `ln` comes from the platform libm, so other
  platforms may differ in the last digits.

## Verdict: ACCEPT WITH CHANGES

The counted clock with step T/2 does what the selection study claimed for the race: the
difficulty-raising attack stays bounded, and the genesis-fork rewrite drops to zero. But the
rule as specified **breaks the emission criterion (≤ +1%)**. The cause is a window-boundary
flaw: the counted clock restarts at the raw stamp of the window's oldest block. A one-line
change removes it (RT-1).

The **hopper criterion (±3 points) is also broken** under a wider hopper search, both by the
rule and by the fix (RT-2). No DAA change tested repairs it without giving up the race bound.
The coordinator must either accept it as a residual or relax the criterion. Everything else
passes.

**Required change** (RT-1): warm the counted clock over the 11 blocks before the window.

```text
  // After `take`, `n` and `step` as in selection.md:
  w0   = len - take                      // index of the window's oldest block
  from = w0.saturating_sub(11)           // NEW: the warm-up start (11 = MTP window)
  prev = ts[from]
  for j in from+1 ..= w0:                // NEW: warm the counted clock
      prev = max(ts[j], prev + step)
  // unchanged from here: for i in 1..=n (block w0+i):
  //   this = max(ts[w0+i], prev + step); st = min(this - prev, 6T); prev = this; ...
```

- The window's anchor becomes `c0 = max(ts[w0], ts[w0-j] + j·step for j = 1..11)`, instead of
  `ts[w0]`.
- Near genesis the warm-up simply uses the blocks that exist (`saturating_sub`).
- Every counted solve time is still at least `step`, so the rise bound `next ≤ floor(sumD·T/(step·n))`
  is unchanged. The property test checks it for the fix too, on extreme inputs.
- The callers need `N + 1 + 11 = 87` ancestors instead of 76, in `required_difficulty` and in
  `overlay_context`.
- The fingerprint's DAA identifier should name the warm-up, for example
  `lwma1-n75-step-t/2-warm11-cap6t-floor20`.
- Golden vector (from `window_start_lag_vector`): an on-target window at `D = 10^6` whose oldest
  stamp is 1 300 s low gives 998 248 under the rule and 999 824 with the fix.
- It passes every selection criterion on the selection's own seed, with the same or better
  margins as the rule under attack:

  | Criterion | Rule under attack | Fix |
  |---|---|---|
  | Race q = 0.4 | +3.8% | +3.5% |
  | Race q ≤ 0.35 | +0.15% | +0.10% |
  | Emission, selection families | +0.69% | +0.46% |
  | Threshold hopper | +2.4 | +2.3 |
  | Bias | +1.01% | +1.03% |
  | 10× up | 113/113 | 113/113 |
  | 10× down | 130/133 | 130/133 |
  | 0.5×D0 | 2 | 2 |
  | Gap | 12 | 12 |

## Findings

| ID | Attack (goal) | Rule under attack | Fix (warm 11) | Current rule | Criterion | Proposed action |
|---|---|---|---|---|---|---|
| **RT-1** | Anchor lag: window-boundary repayment evasion (goals 1, 2, 3) | **+1.90%** emission (static period-12 policy); **+1.31%** sustained (rollout controller) | +0.25% static; +0.35% rollout H = 76; +0.66% rollout H = 150 | +1.80% static (period 10); +1.02% rollout | **Emission ≤ +1%: broken** | **Required:** warm-up 11 |
| **RT-2** | Hoppers beyond the threshold family (goal 4) | honest 100×: +3.36; FTL-edge stamping: +4.50 | +3.02 / +4.18 | +1.10 / +2.54 | **Hopper ±3 points: broken** | Coordinator decision (see RT-2) |
| RT-3 | Bahack race, 24 adaptive policies, q up to 0.45 (goal 7) | q = 0.4: +3.7%; q = 0.45: +28.4% | +3.5%; +27.4% | +36.0%; +60.7% | q = 0.4 passes; q = 0.45 has no criterion | Residual to park-on-deep-reorg (02) |
| RT-4 | Inherited difficulty after a won race | median 2.4–2.7×, max 17.6× DEQ | max 18.0× | median 14–104×, max 193× | none | Document (liveness after an attack) |
| RT-5 | Selfish mining + stamps (goal 5) | FTL-edge stamps add +0.6 to +1.8 share points to SM1 | same | +1.4 to +3.0 | none | None in the DAA (fork-choice matter) |
| RT-6 | Large upward steps and D = 1 (goal 6) | 100×: 224 blocks; 1000×: 334; from D = 1: 737 blocks (694 excess) | same | 105 / 114 / 160 | none (only 10× is a criterion) | Document; set D0 with care |
| RT-7 | Low-difficulty truncation (goal 6) | D_eq = 1.5–3: blocks 18–35% fast; no freeze; no oscillation beyond 1↔2 | same | same | none | Document (regtest-only scale) |
| RT-8 | Integer paths (goal 6) | no overflow for T < 2^51; saturates at u64::MAX | same | — | criterion 8 passes | ChainParams range invariant for T (03-F6) |
| RT-9 | Genesis era (goal 6) | genesis-fork rewrite 0/300 at q = 0.2, 0.3, 0.4 | 0/300 | 25, 59, 104 of 300 | informational | None |

### RT-1: anchor lag (window-boundary repayment evasion). Breaks the emission criterion.

**Mechanism.**
- The consensus loop starts the counted clock at `prev = ts[w0]`, the raw stamp of the
  window's oldest block. MTP-11 allows that stamp to lie 1 000–2 000 s below its neighbours.
- Every window that starts at such a low stamp restarts its clock that far back.
- The next stamps then count their full gaps from the low anchor, up to 6T each, until the clock
  catches up. The window therefore counts real time that its predecessor window did not.
- In the global view, a low stamp borrows counted time: the clock runs ahead of the stamps, and
  later stamps would have to repay it. The repayment is forgiven when the borrowing block
  becomes a window's anchor.
- Golden vector: one oldest stamp 1 300 s low turns a 120 s first solve time into 720 s (the
  6T cap) and lowers the child difficulty by 0.18%.
- The attacker zig-zags. `rollout_trace` shows the rollout controller alternating FTL-edge
  stamps with `MTP + 1` (1 100–1 800 s back), `prev + 720` and `now − 600`, so that a large
  share of windows start at a lagging anchor.

**Why the step makes it worse than the current rule.**
- A low stamp costs `step` counted seconds where an honest stamp would count its real gap. That
  is 60 s here, against 1 s under the current rule, so zig-zagging is much cheaper.
- The current rule is exposed to the same mechanism: +1.80% static and +1.02% rollout. The
  selection study's +0.68% for the current rule was an underestimate too. Its families never
  put a low stamp under a window anchor on purpose.

**Evidence** (all figures reproducible from the commands above).
- **The periodic search** (14 periods, 6 restarts × 600 hill-climbing steps; about 44 000
  deterministic evaluations per rule) found the period-12 policy
  `[mtp+1 prev+417 prev+420 mtp+1 prev+482 prev+840 prev+839 now-1083 prev+955 clk+720 mtp+1 mtp+1]`.
  - On fresh seeds it gains +1.99%, +1.88% and +1.84%, each over 10 000 stochastic blocks.
  - The one-shot FTL gain over 10 000 blocks is at most 0.03%, so this gain is sustained.
  - Periods 5 and 6 give +0.83% and +0.87%.
- **The rollout controller** is a one-step policy improvement over honest stamping. It picks
  from 14 candidate stamps by simulating the next 76 or 150 blocks.
  - Gain: +1.31% sustained, counting blocks 1 000–3 000 only (6 seeds, minimum +1.11%).
  - A controller that stamps only 50% or 80% of the blocks gains +0.61% and +0.85%.
- **Causal test** (`anchor_ablation`, 6 seeds × 3 000 blocks, sustained rollout gain):

  | Rule | Sustained gain | Honest bias |
  |---|---|---|
  | Rule under attack | +1.19% | +0.89% |
  | Warm-up 1 | +0.67% | +0.90% |
  | Warm-up 11 | +0.28% | +0.92% |
  | Warm-up 75 | +0.27% | +0.92% |
  | Current rule | +0.91% | +1.21% |

  - Only the anchor changes, and the gain goes. 11 is enough: 75 buys nothing more.
- **The fix under the same search:**
  - best static policy +0.25% (period 1, `clk+428`, the one-shot kind);
  - rollout +0.35% (H = 76) and +0.66% (H = 150, maximum seed +0.99%);
  - table search: no gain (its best policies lose 9–10% on fresh seeds).

**Why the fix is sound.**
- The warm-up takes the anchor to the running maximum of `ts[w0-j] + j·step`. A low stamp
  therefore cannot be an anchor unless the 11 stamps before it are low too, which is sustained
  compression. Each compressed block counts only `step` in every window that contains it.
- The rise bound, race behaviour and all follow metrics are unchanged (table above).

### RT-2: hoppers. Breaks the hopper criterion; no DAA fix found.

**Search.** 825 configurations:
- hash multiples 1, 3, 10, 30 and 100;
- thresholds on D/DEQ or on D relative to the window mean;
- fixed-duration hops;
- honest, FTL-edge or last-3-edge stamping of the hopper's own blocks.

Each ran 10 000 blocks. The top 6 were re-run on 3 fresh seeds × 20 000 blocks.

**Results.** Excess over fair share (the share of hashes spent), 3 seeds × 20 000 blocks,
`hop_ahead`:

| Hopper (abs on < 1.2 off > 1.7) | Rule | Fix | Current |
|---|---|---|---|
| 100×, honest stamps | +3.36 | +3.02 | +1.10 |
| 100×, 120 s ahead | +3.49 | +3.31 | +1.60 |
| 100×, 360 s ahead (FTL edge) | **+4.50** | **+4.18** | +2.54 |
| 10×, FTL edge | +3.83 | +3.55 | +2.33 |

- **Two causes.** The step bounds the rise per block at 2× the window average, so a large
  hopper's cheap phase lasts longer: honest stamps alone exceed ±3 at 100×. On top of that,
  forward stamps borrow counted time while the hopper mines. The dedicated miners repay it after
  the hopper leaves, which is a second form of repayment evasion.
- **The trade-off is structural.** The selection study found the same direction: larger steps
  cut the race but raise hopper gains, because the hopper profits from the same slow rise that
  protects the race.
- **A smaller FTL is not a fix.** The forward-stamp component scales with the offset, but at
  120 s ahead the 100× hopper still gets +3.3 to +3.5.
- **For the coordinator.** Hop-in/hop-out is a fairness loss for dedicated miners (about 12%
  more blocks per hash for a hopper with about a third of the blocks). It is not a consensus-safety
  failure. It needs a large external hash multiple, 10–100× the network, which is realistic on a
  small testnet. Options:
  - (a) accept a limit of ±5 points with this evidence;
  - (b) revisit N (N = 90 lowers the threshold hopper to +2.1 but fails 10× down at 156 blocks);
  - (c) keep ±3 and reopen the selection.

  I recommend (a) for the testnet, with the question reopened before mainnet.

### RT-3: the race, with adaptive release timing and state-dependent policies

**Policies.** 24 policies, screened at q = 0.30, 0.35, 0.40 and 0.45 with 1 000 trials each,
then confirmed at 4 000 trials on a disjoint seed set:
- compress only when behind by x blocks of work;
- cap the private difficulty at x times the public one;
- honest for the first j private blocks, then compressed (j = 10, 38, 75, 76, 100: the window
  boundaries);
- the first j blocks at the FTL edge, then compressed;
- compressed only early;
- compressed until z confirmations, then only while behind;
- aligned to the counted clock.

The release rule is optimal by construction: the attacker publishes the first moment its
branch has more work after z confirmations.

**Results.**
- **No policy beats full compression beyond noise.** The best confirmed excess at q = 0.4 is
  +3.72% on the rule and +3.50% on the fix, both under +5%.
- **q = 0.45** (no criterion): +28.4%, against +60.7% for the current rule.
- **The window-timed policies are worse than compression, not better.** At q = 0.4, "honest 75
  then compressed" got 6 hits against 50 for the best policy in screening. Compression pays
  best when it starts at the fork.

**Branch switches and private branches published only when favourable** are what the race
model already measures (optimal release). A reorg that discards repaying blocks gives a single
miner nothing: the state at the fork point is the same on both branches, so the alternative is
just another stamp policy, and the searches above cover those.

### RT-4: difficulty inherited after a won race

- **What it is.** On a win, the chain adopts the private branch's difficulty.
- **Rule under attack.** Median 2.4–2.7× DEQ and maximum 17.6× over all q. The honest chain
  then recovers like a 10× drop (about 130 blocks, about 9.6 h).
- **Current rule.** Median 14–104× and maximum 193×.
- **Assessment.** This is a liveness cost after a successful attack, not an attack path. The
  bounded rise makes it much smaller than today.

### RT-5: selfish mining with timestamp manipulation

- **Model.** Eyal–Sirer SM1 with work-based fork choice, α = 0.25, 0.33 and 0.40, γ = 0 and 0.5,
  3 seeds × 20 000 blocks. The harness is validated against Eyal–Sirer: at α = 0.4, γ = 0 with
  honest stamps the attacker share is 0.466 (theory 0.484).
- **Forward stamps help a little.** FTL-edge stamps on the private blocks raise the share by
  +0.6 to +1.8 points: the attacker's own next private block is the one that gets the cheaper
  difficulty. Compressed stamps lower the share.
- **This is a fork-choice issue, not a DAA one.** The effect is smaller than under the current
  rule (+1.4 to +3.0), and the fix does not change it.

### RT-6 and RT-7: low difficulty and large steps

**Large steps** (deterministic, both the rule and the fix):
- A 100× hash-rate jump takes 224 blocks to reach ±10%, against 105 today.
- A 1000× jump takes 334 blocks, against 114.
- A chain at D = 1 whose hash rate returns takes 737 blocks, against 160. That is 694 excess
  blocks within 1.45 h.
- Start-up from D0 = DEQ/1000 takes 192 blocks, against 37.
- This is the direct price of the rise bound (about 2.1% per block), the same parameter that
  bounds the race. Only 10× is a criterion.
- On the testnet it matters when a much larger miner joins, or when D0 is mis-set by far more
  than the genesis tool's margin of 2.

**Low difficulty** (honest miners, 20 000 blocks):
- No freeze: D = 1 still rises to 2 under fast blocks.
- No oscillation beyond the unavoidable 1↔2 alternation at D_eq ≈ 2.
- Truncation makes blocks up to 35% fast at D_eq = 1.5–3. The current rule behaves the same
  (28–33%). This only matters at hash rates of about 1/60 H/s, that is regtest scale.

### RT-8: integer paths

- **Independent port.** `reference_next` is a port of the pseudocode with checked `u128`
  arithmetic, in which any overflow or underflow panics. It equals the harness rule on 320
  random histories (out-of-order stamps, windows 1–200), each at T = 120 and T = 10.
- **Extremes, run in debug with overflow checks.** Stamps near `u64::MAX`, difficulties near
  `u64::MAX`, and T from 1 to 2^40 raise no panic, and the rise bound holds for the rule and the
  fix.
- **Saturation.** At `u64::MAX` difficulties, the output clamps to `u64::MAX`.
- **Overflow bounds.** The largest intermediate is `sumD·T·(n+1) < 76·2^64·T·76`, which fits in
  `u128` for T < 2^51. The counted clock stays below `ts_max + (N+11)·T/2`.
- **Recommendation.** Add the ChainParams range invariant for T and N (03-F6, W6).

## Search effort (per rule; three rules unless stated)

- **Emission:**
  - periodic hill-climbing, about 44 000 deterministic evaluations of 1 950 blocks;
  - table-policy hill-climbing (100 states), about 21 800 evaluations;
  - stochastic confirmation of 18 policies on 3 fresh seeds × 10 000 blocks;
  - 3 rollout controllers on 6 seeds × 3 000 blocks;
  - large miners (50% and 80%), 2 policies × 6 seeds × 3 000 blocks.
- **Race:** 24 policies × 4 q × 1 000 screening trials, and 3 × 4 × 4 000 confirmation trials.
- **Selfish mining:** 24 cells × 3 seeds × 20 000 blocks.
- **Hoppers:**
  - 825 configurations × 10 000 blocks, with the top 7 × 3 × 20 000 re-run;
  - `hop_ahead`: 4 configurations × 6 offsets × 3 × 20 000 blocks.
- **Low difficulty:** 9 × 20 000 blocks.
- **Ramps:** 6 deterministic scenarios.
- **Genesis fork:** 6 × 300 trials.
- **Selection criteria:** the full selection run for the rule and the fix.

## Model limits and honesty notes

- **Model.** There is no network latency, no orphans (except in SM1) and no clock skew. The
  model is the one the selection study used.
- **Deterministic gains are not results.** The deterministic model overstates some static
  policies: period 76 is +10.7% deterministic but −5.8% stochastic. Only the stochastic
  fresh-seed figures are results.
- **The search is finite.** It is evidence, not a proof. The fix's +0.66% worst case comes from
  the stronger (H = 150) controller, and stronger controllers may exist. The margin to +1% is
  about 0.3 points.
- **Selection bias.** The static policies were selected on the deterministic model and
  confirmed on fresh stochastic seeds. The rollout controllers were not selected at all.
- **Untrusted input.** No external text was used in this study, and no instruction was found in
  any input.

---

Generated tables (unedited output of the main command):

# Red-team study of the recommended difficulty rule (generated)

Generated by `cargo run --release -p blacksilk-daa-sim -- --redteam` (full mode, 371 s on 6 threads).

## Configuration

- Base seed `0xdaa7ea3`, 6 threads. Every job seeds from the base seed and its coordinates only (never the rule), so both rules see the same draws.
- Emission search (deterministic model, expected solve times, honest = exactly 0): periods [1, 2, 3, 4, 5, 6, 10, 12, 15, 25, 38, 75, 76, 150], 6 restarts x 600 hill-climbing steps each; table policy 8 restarts x 3000 steps; each evaluation 450 burn-in + 1500 measured blocks. Confirmation: 3 fresh seeds x 10000 blocks, stochastic, gain over honest on the same draws. Rollout controllers: 6 seeds x 3000 blocks.
- Race: z = 100, q in [0.3, 0.35, 0.4, 0.45]; screening 1000 trials per policy (24 policies) on seed set A; confirmation 4000 trials each of honest, compressed and the screened best on seed set B. Excess = max(compressed, best) - honest on B.
- Selfish mining: 3 seeds x 20000 main-chain blocks. Hoppers: 825 configurations x 10000 blocks, top 6 by hopper gain (excess) re-run on 3 fresh seeds x 20000 blocks. Low difficulty: 20000 blocks after 1 000 burn-in. Genesis fork: 300 trials per cell, age 720, 10-day horizon.

## LWMA-75 step T/2 (under attack)

### Emission (100% miner unless stated)

| Family | Evaluations | Deterministic gain | Stochastic gain per fresh seed | Mean | Best policy |
|---|---|---|---|---|---|
| periodic, period 1 | 3492 | +0.00% | +0.22%, +0.25%, +0.28% | +0.25% | `periodic 1: [clk+428]` |
| periodic, period 2 | 3325 | +0.38% | +0.24%, +0.32%, +0.27% | +0.28% | `periodic 2: [now-594 clk+180]` |
| periodic, period 3 | 3143 | +0.57% | +0.30%, +0.40%, +0.33% | +0.34% | `periodic 3: [mtp+1 now-607 clk+240]` |
| periodic, period 4 | 3166 | +0.77% | +0.42%, +0.47%, +0.40% | +0.43% | `periodic 4: [mtp+1 prev+423 now-714 clk+300]` |
| periodic, period 5 | 3164 | +1.23% | +0.78%, +0.89%, +0.83% | +0.83% | `periodic 5: [mtp+1 prev+65 prev+485 now-2400 clk+359]` |
| periodic, period 6 | 3164 | +1.48% | +0.90%, +0.80%, +0.91% | +0.87% | `periodic 6: [mtp+1 prev+539 prev+240 now-2101 clk+417 mtp+1]` |
| periodic, period 10 | 3103 | +2.02% | -1.66%, -1.27%, -1.66% | -1.53% | `periodic 10: [now-1321 now-659 mtp+1 mtp+1 mtp+1 prev+301 mtp+1 prev+1080 prev+960 prev+901]` |
| periodic, period 12 | 3192 | +2.81% | +1.99%, +1.88%, +1.84% | +1.90% | `periodic 12: [mtp+1 prev+417 prev+420 mtp+1 prev+482 prev+840 prev+839 now-1083 prev+955 clk+720 mtp+1 mtp+1]` |
| periodic, period 15 | 3145 | +3.29% | -7.31%, -7.62%, -7.20% | -7.38% | `periodic 15: [now+238 mtp+1 prev+1 prev+362 prev+60 prev+64 prev+181 prev+241 mtp+1 prev+1021 mtp+1 now-2160 prev+602 now-901 clk+296]` |
| periodic, period 25 | 3098 | +2.26% | -0.81%, -0.51%, -0.35% | -0.56% | `periodic 25` |
| periodic, period 38 | 3060 | +2.57% | +0.80%, +0.81%, +0.34% | +0.65% | `periodic 38` |
| periodic, period 75 | 3090 | +1.48% | -1.36%, -0.72%, -0.50% | -0.86% | `periodic 75` |
| periodic, period 76 | 3038 | +10.70% | -6.40%, -5.58%, -5.30% | -5.76% | `periodic 76` |
| periodic, period 150 | 3116 | +1.14% | -0.55%, -0.36%, -0.39% | -0.43% | `periodic 150` |
| state table (clock offset x D/avg) | 21787 | +2.10% | -10.12%, -10.80%, -9.75% | -10.22% | `table` |
| hand-made reference | 1 | +0.00% | +0.03%, +0.03%, +0.03% | +0.03% | `always now+360` |
| hand-made reference | 1 | -11.45% | -12.41%, -13.27%, -13.26% | -12.98% | `periodic 76` |
| hand-made reference | 1 | -0.10% | -0.56%, -0.38%, -0.40% | -0.45% | `periodic 75` |
| miner stamps 50% of blocks (6 seeds x 3000 blocks) | - | - | - | -0.09% | `periodic 12` |
| miner stamps 80% of blocks (6 seeds x 3000 blocks) | - | - | - | -0.45% | `periodic 12` |
| miner stamps 50% of blocks (6 seeds x 3000 blocks) | - | - | - | +0.61% | `rollout H=76 over honest` |
| miner stamps 80% of blocks (6 seeds x 3000 blocks) | - | - | - | +0.85% | `rollout H=76 over honest` |

Rollout controllers (6 seeds x 3000 blocks; sustained = blocks 1000..3000 only, without the one-shot gain):

| Controller | total gain per seed | mean | sustained gain per seed | mean | min |
|---|---|---|---|---|---|
| `rollout H=76 over honest` | +1.16%, +1.25%, +1.12%, +1.50%, +1.24%, +1.52% | +1.30% | +1.18%, +1.23%, +1.11%, +1.53%, +1.22%, +1.59% | +1.31% | +1.11% |
| `rollout H=150 over honest` | +0.99%, +0.92%, +0.89%, +1.22%, +0.84%, +1.27% | +1.02% | +1.09%, +0.80%, +1.02%, +1.32%, +1.03%, +1.48% | +1.12% | +0.80% |
| `rollout H=76 over always now+360` | +0.80%, +0.80%, +0.75%, +1.04%, +0.80%, +1.10% | +0.88% | +0.82%, +0.73%, +0.73%, +1.05%, +0.77%, +1.21% | +0.88% | +0.73% |

### Race (z = 100)

| q | honest | compressed | screened best | P(best) | excess | inherited D/DEQ on compressed wins (median, max) |
|---|---|---|---|---|---|---|
| 0.3 | 0.0000 | 0.0000 | compressed to z, then behind>3 | 0.0000 | +0.00% | 0.00, 0.00 |
| 0.35 | 0.0000 | 0.0008 | D-cap 5x | 0.0010 | +0.10% | 2.67, 2.73 |
| 0.4 | 0.0030 | 0.0403 | compressed until 0.6 of horizon | 0.0365 | +3.72% | 2.44, 16.90 |
| 0.45 | 0.1263 | 0.4105 | compressed to z, then behind>3 | 0.4105 | +28.43% | 2.55, 17.62 |

Screening hits at q = 0.3 (seed set A): aligned (clock + step) 0; behind>-3 0; behind>0 0; behind>2 0; behind>5 0; behind>10 0; D-cap 1.5x 0; D-cap 2x 0; D-cap 3x 0; D-cap 5x 0; honest 10 then compressed 0; honest 38 then compressed 0; honest 75 then compressed 0; honest 76 then compressed 0; honest 100 then compressed 0; FTL edge 5 then compressed 0; FTL edge 20 then compressed 0; FTL edge 75 then compressed 0; compressed until 0.3 of horizon 0; compressed until 0.6 of horizon 0; behind>2 or after 0.5 0; behind>5 or after 0.3 0; compressed to z, then behind>0 0; compressed to z, then behind>3 0

Screening hits at q = 0.35 (seed set A): aligned (clock + step) 0; behind>-3 1; behind>0 0; behind>2 0; behind>5 0; behind>10 0; D-cap 1.5x 0; D-cap 2x 1; D-cap 3x 2; D-cap 5x 2; honest 10 then compressed 0; honest 38 then compressed 1; honest 75 then compressed 0; honest 76 then compressed 0; honest 100 then compressed 0; FTL edge 5 then compressed 1; FTL edge 20 then compressed 0; FTL edge 75 then compressed 0; compressed until 0.3 of horizon 1; compressed until 0.6 of horizon 1; behind>2 or after 0.5 0; behind>5 or after 0.3 0; compressed to z, then behind>0 0; compressed to z, then behind>3 0

Screening hits at q = 0.4 (seed set A): aligned (clock + step) 41; behind>-3 29; behind>0 20; behind>2 28; behind>5 19; behind>10 9; D-cap 1.5x 7; D-cap 2x 18; D-cap 3x 25; D-cap 5x 39; honest 10 then compressed 23; honest 38 then compressed 9; honest 75 then compressed 6; honest 76 then compressed 8; honest 100 then compressed 4; FTL edge 5 then compressed 37; FTL edge 20 then compressed 12; FTL edge 75 then compressed 6; compressed until 0.3 of horizon 38; compressed until 0.6 of horizon 50; behind>2 or after 0.5 28; behind>5 or after 0.3 19; compressed to z, then behind>0 41; compressed to z, then behind>3 41

Screening hits at q = 0.45 (seed set A): aligned (clock + step) 424; behind>-3 378; behind>0 359; behind>2 382; behind>5 310; behind>10 262; D-cap 1.5x 178; D-cap 2x 212; D-cap 3x 247; D-cap 5x 295; honest 10 then compressed 340; honest 38 then compressed 339; honest 75 then compressed 275; honest 76 then compressed 301; honest 100 then compressed 261; FTL edge 5 then compressed 361; FTL edge 20 then compressed 361; FTL edge 75 then compressed 265; compressed until 0.3 of horizon 327; compressed until 0.6 of horizon 407; behind>2 or after 0.5 382; behind>5 or after 0.3 310; compressed to z, then behind>0 424; compressed to z, then behind>3 424

### Selfish mining (work-based fork choice)

| alpha | gamma | attacker stamps | attacker share of main chain | main-chain rate vs target |
|---|---|---|---|---|
| 0.25 | 0 | honest | 0.1911 | -0.91% |
| 0.25 | 0 | always mtp+1 | 0.1882 | -2.15% |
| 0.25 | 0 | always now+360 | 0.1997 | -0.87% |
| 0.25 | 0 | always clk+60 | 0.1881 | -2.19% |
| 0.25 | 0.5 | honest | 0.2482 | -0.94% |
| 0.25 | 0.5 | always mtp+1 | 0.2461 | -2.32% |
| 0.25 | 0.5 | always now+360 | 0.2541 | -0.96% |
| 0.25 | 0.5 | always clk+60 | 0.2461 | -2.37% |
| 0.33 | 0 | honest | 0.3268 | -0.94% |
| 0.33 | 0 | always mtp+1 | 0.3204 | -4.27% |
| 0.33 | 0 | always now+360 | 0.3379 | -0.94% |
| 0.33 | 0 | always clk+60 | 0.3204 | -4.37% |
| 0.33 | 0.5 | honest | 0.3749 | -0.91% |
| 0.33 | 0.5 | always mtp+1 | 0.3690 | -4.43% |
| 0.33 | 0.5 | always now+360 | 0.3835 | -0.86% |
| 0.33 | 0.5 | always clk+60 | 0.3692 | -4.53% |
| 0.4 | 0 | honest | 0.4656 | -1.13% |
| 0.4 | 0 | always mtp+1 | 0.4482 | -9.46% |
| 0.4 | 0 | always now+360 | 0.4833 | -1.06% |
| 0.4 | 0 | always clk+60 | 0.4483 | -9.56% |
| 0.4 | 0.5 | honest | 0.5150 | -1.03% |
| 0.4 | 0.5 | always mtp+1 | 0.4998 | -10.56% |
| 0.4 | 0.5 | always now+360 | 0.5253 | -0.96% |
| 0.4 | 0.5 | always clk+60 | 0.4999 | -10.67% |

### Hoppers (825 configurations searched)

| Hopper | screening excess (points) | confirmed excess (points) |
|---|---|---|
| 30x, abs on<1.2 off>1.7, edge | +4.60 | +4.28 |
| 100x, abs on<1.2 off>1.7, edge | +4.60 | +4.50 |
| 10x, abs on<1.2 off>1.7, edge | +3.85 | +3.78 |
| 100x, abs on<1.2 off>2.2, edge | +3.83 | +3.98 |
| 100x, abs on<1.1 off>1.6, edge | +3.66 | +3.86 |
| 100x, abs on<1.2 off>1.4, edge | +3.44 | +3.43 |
| selection study's reference hopper (10x, abs on<1.2 off>2) | - | +2.47 |

The six largest hopper gains of the screening, confirmed on fresh seeds. The most negative screening excess was -8.20 points (a hopper that overpays; not an attack).

### Low difficulty (honest miners)

| D_eq | mean solve time / T | mean D / D_eq | blocks at D = 1 | CV of D | min D | max D |
|---|---|---|---|---|---|---|
| 0.3 | 3.368 | 3.333 | 1.000 | 0.000 | 1 | 1 |
| 0.7 | 1.432 | 1.429 | 1.000 | 0.000 | 1 | 1 |
| 1 | 1.004 | 1.000 | 1.000 | 0.000 | 1 | 1 |
| 1.5 | 0.669 | 0.667 | 0.999 | 0.025 | 1 | 2 |
| 2 | 0.653 | 0.650 | 0.699 | 0.353 | 1 | 2 |
| 3 | 0.817 | 0.824 | 0.001 | 0.212 | 1 | 4 |
| 5 | 0.903 | 0.906 | 0.000 | 0.145 | 3 | 7 |
| 10 | 0.960 | 0.959 | 0.000 | 0.129 | 6 | 16 |
| 100 | 1.006 | 1.013 | 0.000 | 0.118 | 68 | 160 |

### Large upward steps (deterministic)

| Scenario | blocks to within 10% | hours | excess blocks (blocks - hours x 30) |
|---|---|---|---|
| hash rate x10 | 113 | 1.29 | 74 |
| hash rate x100 | 224 | 1.43 | 181 |
| hash rate x1000 | 334 | 1.44 | 291 |
| start-up from D0 = 0.01 DEQ | 83 | 1.14 | 49 |
| start-up from D0 = 0.001 DEQ | 192 | 1.40 | 150 |
| chain at D = 1, hash rate returns to DEQ | 737 | 1.45 | 694 |

### Genesis-fork rewrite (age 720, 10-day horizon)

| q | stamps | wins / trials |
|---|---|---|
| 0.2 | honest | 0/300 |
| 0.2 | compressed | 0/300 |
| 0.3 | honest | 0/300 |
| 0.3 | compressed | 0/300 |
| 0.4 | honest | 0/300 |
| 0.4 | compressed | 0/300 |

## Candidate fix: LWMA-75 step T/2, clock warmed over 11 blocks

### Emission (100% miner unless stated)

| Family | Evaluations | Deterministic gain | Stochastic gain per fresh seed | Mean | Best policy |
|---|---|---|---|---|---|
| periodic, period 1 | 3492 | +0.00% | +0.22%, +0.25%, +0.28% | +0.25% | `periodic 1: [clk+428]` |
| periodic, period 2 | 3532 | +0.00% | +0.12%, +0.16%, +0.13% | +0.14% | `periodic 2: [clk+428 now+360]` |
| periodic, period 3 | 3481 | +0.01% | -0.01%, -1.87%, -1.61% | -1.16% | `periodic 3: [clk+59 clk+119 prev+182]` |
| periodic, period 4 | 3515 | +0.20% | -0.99%, -1.10%, +0.71% | -0.46% | `periodic 4: [prev+1 clk+121 prev+2 clk+240]` |
| periodic, period 5 | 3528 | +0.63% | +0.04%, +0.14%, +0.17% | +0.12% | `periodic 5: [prev+539 now-1260 mtp+1 prev+600 prev+601]` |
| periodic, period 6 | 3562 | +0.00% | +0.12%, +0.14%, +0.17% | +0.14% | `periodic 6: [prev+180 clk+120 clk+780 prev+119 prev+659 prev+540]` |
| periodic, period 10 | 3547 | +0.48% | +0.01%, +0.11%, +0.22% | +0.11% | `periodic 10: [prev+1 mtp+1 prev+839 prev+361 prev+1 clk+303 now-1441 clk+1 prev+424 now-842]` |
| periodic, period 12 | 3549 | +0.00% | -0.11%, -0.05%, -0.03% | -0.07% | `periodic 12: [clk+361 clk+720 clk+362 prev+119 prev+181 clk+1020 clk+1019 prev+241 clk+179 clk+120 clk+959 clk+181]` |
| periodic, period 15 | 3549 | +0.00% | +0.16%, +0.22%, +0.15% | +0.17% | `periodic 15: [clk+419 clk+422 prev+780 clk+121 prev+538 clk+122 clk+119 prev+541 clk+121 prev+1080 prev+479 clk+360 prev+300 prev+663 clk+720]` |
| periodic, period 25 | 3468 | +0.00% | +0.20%, +0.23%, +0.23% | +0.22% | `periodic 25` |
| periodic, period 38 | 3392 | +0.00% | -0.23%, -0.25%, -0.20% | -0.23% | `periodic 38` |
| periodic, period 75 | 3283 | +0.00% | -0.02%, -0.00%, +0.00% | -0.01% | `periodic 75` |
| periodic, period 76 | 3204 | +9.16% | -6.34%, -6.29%, -6.38% | -6.34% | `periodic 76` |
| periodic, period 150 | 3228 | +0.00% | -0.00%, -0.01%, +0.00% | -0.00% | `periodic 150` |
| state table (clock offset x D/avg) | 21906 | +0.71% | -9.98%, -9.39%, -9.45% | -9.61% | `table` |
| hand-made reference | 1 | +0.00% | +0.03%, +0.03%, +0.03% | +0.03% | `always now+360` |
| hand-made reference | 1 | -11.45% | -12.40%, -13.25%, -13.24% | -12.96% | `periodic 76` |
| hand-made reference | 1 | -0.10% | -0.59%, -0.42%, -0.44% | -0.48% | `periodic 75` |
| miner stamps 50% of blocks (6 seeds x 3000 blocks) | - | - | - | +0.26% | `periodic 1` |
| miner stamps 80% of blocks (6 seeds x 3000 blocks) | - | - | - | +0.30% | `periodic 1` |
| miner stamps 50% of blocks (6 seeds x 3000 blocks) | - | - | - | +0.32% | `rollout H=76 over honest` |
| miner stamps 80% of blocks (6 seeds x 3000 blocks) | - | - | - | +0.36% | `rollout H=76 over honest` |

Rollout controllers (6 seeds x 3000 blocks; sustained = blocks 1000..3000 only, without the one-shot gain):

| Controller | total gain per seed | mean | sustained gain per seed | mean | min |
|---|---|---|---|---|---|
| `rollout H=76 over honest` | +0.28%, +0.29%, +0.28%, +0.52%, +0.26%, +0.60% | +0.37% | +0.26%, +0.20%, +0.22%, +0.50%, +0.19%, +0.70% | +0.35% | +0.19% |
| `rollout H=150 over honest` | +0.56%, +0.49%, +0.50%, +0.78%, +0.56%, +0.82% | +0.62% | +0.62%, +0.40%, +0.57%, +0.75%, +0.63%, +0.99% | +0.66% | +0.40% |
| `rollout H=76 over always now+360` | +0.28%, +0.28%, +0.27%, +0.51%, +0.27%, +0.58% | +0.36% | +0.28%, +0.18%, +0.20%, +0.49%, +0.19%, +0.68% | +0.34% | +0.18% |

### Race (z = 100)

| q | honest | compressed | screened best | P(best) | excess | inherited D/DEQ on compressed wins (median, max) |
|---|---|---|---|---|---|---|
| 0.3 | 0.0000 | 0.0000 | compressed to z, then behind>3 | 0.0000 | +0.00% | 0.00, 0.00 |
| 0.35 | 0.0000 | 0.0013 | D-cap 5x | 0.0022 | +0.22% | 2.29, 2.39 |
| 0.4 | 0.0040 | 0.0390 | compressed to z, then behind>3 | 0.0390 | +3.50% | 2.44, 11.36 |
| 0.45 | 0.1325 | 0.4062 | behind>-3 | 0.3790 | +27.38% | 2.61, 17.99 |

Screening hits at q = 0.3 (seed set A): aligned (clock + step) 0; behind>-3 0; behind>0 0; behind>2 0; behind>5 0; behind>10 0; D-cap 1.5x 0; D-cap 2x 0; D-cap 3x 0; D-cap 5x 0; honest 10 then compressed 0; honest 38 then compressed 0; honest 75 then compressed 0; honest 76 then compressed 0; honest 100 then compressed 0; FTL edge 5 then compressed 0; FTL edge 20 then compressed 0; FTL edge 75 then compressed 0; compressed until 0.3 of horizon 0; compressed until 0.6 of horizon 0; behind>2 or after 0.5 0; behind>5 or after 0.3 0; compressed to z, then behind>0 0; compressed to z, then behind>3 0

Screening hits at q = 0.35 (seed set A): aligned (clock + step) 0; behind>-3 0; behind>0 0; behind>2 0; behind>5 0; behind>10 0; D-cap 1.5x 0; D-cap 2x 2; D-cap 3x 0; D-cap 5x 2; honest 10 then compressed 0; honest 38 then compressed 0; honest 75 then compressed 0; honest 76 then compressed 0; honest 100 then compressed 0; FTL edge 5 then compressed 1; FTL edge 20 then compressed 0; FTL edge 75 then compressed 0; compressed until 0.3 of horizon 1; compressed until 0.6 of horizon 1; behind>2 or after 0.5 0; behind>5 or after 0.3 0; compressed to z, then behind>0 0; compressed to z, then behind>3 0

Screening hits at q = 0.4 (seed set A): aligned (clock + step) 45; behind>-3 32; behind>0 26; behind>2 23; behind>5 10; behind>10 9; D-cap 1.5x 10; D-cap 2x 24; D-cap 3x 26; D-cap 5x 34; honest 10 then compressed 25; honest 38 then compressed 9; honest 75 then compressed 4; honest 76 then compressed 3; honest 100 then compressed 8; FTL edge 5 then compressed 30; FTL edge 20 then compressed 13; FTL edge 75 then compressed 3; compressed until 0.3 of horizon 32; compressed until 0.6 of horizon 34; behind>2 or after 0.5 23; behind>5 or after 0.3 10; compressed to z, then behind>0 45; compressed to z, then behind>3 45

Screening hits at q = 0.45 (seed set A): aligned (clock + step) 384; behind>-3 411; behind>0 396; behind>2 351; behind>5 338; behind>10 293; D-cap 1.5x 166; D-cap 2x 211; D-cap 3x 259; D-cap 5x 332; honest 10 then compressed 379; honest 38 then compressed 325; honest 75 then compressed 284; honest 76 then compressed 254; honest 100 then compressed 268; FTL edge 5 then compressed 399; FTL edge 20 then compressed 360; FTL edge 75 then compressed 301; compressed until 0.3 of horizon 300; compressed until 0.6 of horizon 375; behind>2 or after 0.5 351; behind>5 or after 0.3 338; compressed to z, then behind>0 384; compressed to z, then behind>3 384

### Selfish mining (work-based fork choice)

| alpha | gamma | attacker stamps | attacker share of main chain | main-chain rate vs target |
|---|---|---|---|---|
| 0.25 | 0 | honest | 0.1911 | -0.93% |
| 0.25 | 0 | always mtp+1 | 0.1881 | -2.19% |
| 0.25 | 0 | always now+360 | 0.1996 | -0.97% |
| 0.25 | 0 | always clk+60 | 0.1881 | -2.21% |
| 0.25 | 0.5 | honest | 0.2482 | -0.96% |
| 0.25 | 0.5 | always mtp+1 | 0.2461 | -2.40% |
| 0.25 | 0.5 | always now+360 | 0.2541 | -1.07% |
| 0.25 | 0.5 | always clk+60 | 0.2461 | -2.40% |
| 0.33 | 0 | honest | 0.3268 | -0.96% |
| 0.33 | 0 | always mtp+1 | 0.3204 | -4.35% |
| 0.33 | 0 | always now+360 | 0.3379 | -1.03% |
| 0.33 | 0 | always clk+60 | 0.3204 | -4.38% |
| 0.33 | 0.5 | honest | 0.3747 | -0.93% |
| 0.33 | 0.5 | always mtp+1 | 0.3690 | -4.53% |
| 0.33 | 0.5 | always now+360 | 0.3836 | -0.96% |
| 0.33 | 0.5 | always clk+60 | 0.3690 | -4.55% |
| 0.4 | 0 | honest | 0.4657 | -1.15% |
| 0.4 | 0 | always mtp+1 | 0.4483 | -9.54% |
| 0.4 | 0 | always now+360 | 0.4833 | -1.15% |
| 0.4 | 0 | always clk+60 | 0.4483 | -9.57% |
| 0.4 | 0.5 | honest | 0.5149 | -1.05% |
| 0.4 | 0.5 | always mtp+1 | 0.4999 | -10.64% |
| 0.4 | 0.5 | always now+360 | 0.5254 | -1.06% |
| 0.4 | 0.5 | always clk+60 | 0.4999 | -10.68% |

### Hoppers (825 configurations searched)

| Hopper | screening excess (points) | confirmed excess (points) |
|---|---|---|
| 100x, abs on<1.2 off>1.7, edge | +4.45 | +4.17 |
| 30x, abs on<1.2 off>1.7, edge | +4.06 | +4.02 |
| 10x, abs on<1.2 off>1.7, edge | +3.90 | +3.52 |
| 100x, abs on<1.2 off>2.2, edge | +3.84 | +3.95 |
| 30x, abs on<1.2 off>2.2, edge | +3.64 | +3.66 |
| 100x, abs on<1.1 off>1.6, edge | +3.55 | +3.63 |
| selection study's reference hopper (10x, abs on<1.2 off>2) | - | +2.29 |

The six largest hopper gains of the screening, confirmed on fresh seeds. The most negative screening excess was -8.10 points (a hopper that overpays; not an attack).

### Low difficulty (honest miners)

| D_eq | mean solve time / T | mean D / D_eq | blocks at D = 1 | CV of D | min D | max D |
|---|---|---|---|---|---|---|
| 0.3 | 3.368 | 3.333 | 1.000 | 0.000 | 1 | 1 |
| 0.7 | 1.432 | 1.429 | 1.000 | 0.000 | 1 | 1 |
| 1 | 1.004 | 1.000 | 1.000 | 0.000 | 1 | 1 |
| 1.5 | 0.670 | 0.667 | 0.999 | 0.030 | 1 | 2 |
| 2 | 0.666 | 0.663 | 0.675 | 0.353 | 1 | 2 |
| 3 | 0.818 | 0.825 | 0.001 | 0.212 | 1 | 4 |
| 5 | 0.903 | 0.906 | 0.000 | 0.145 | 3 | 7 |
| 10 | 0.960 | 0.960 | 0.000 | 0.129 | 6 | 16 |
| 100 | 1.006 | 1.014 | 0.000 | 0.118 | 68 | 160 |

### Large upward steps (deterministic)

| Scenario | blocks to within 10% | hours | excess blocks (blocks - hours x 30) |
|---|---|---|---|
| hash rate x10 | 113 | 1.29 | 74 |
| hash rate x100 | 224 | 1.43 | 181 |
| hash rate x1000 | 334 | 1.44 | 291 |
| start-up from D0 = 0.01 DEQ | 83 | 1.14 | 49 |
| start-up from D0 = 0.001 DEQ | 192 | 1.40 | 150 |
| chain at D = 1, hash rate returns to DEQ | 737 | 1.45 | 694 |

### Genesis-fork rewrite (age 720, 10-day horizon)

| q | stamps | wins / trials |
|---|---|---|
| 0.2 | honest | 0/300 |
| 0.2 | compressed | 0/300 |
| 0.3 | honest | 0/300 |
| 0.3 | compressed | 0/300 |
| 0.4 | honest | 0/300 |
| 0.4 | compressed | 0/300 |

## LWMA-60 step 1 (current consensus)

### Emission (100% miner unless stated)

| Family | Evaluations | Deterministic gain | Stochastic gain per fresh seed | Mean | Best policy |
|---|---|---|---|---|---|
| periodic, period 1 | 3491 | +0.00% | +0.33%, +0.38%, +0.42% | +0.38% | `periodic 1: [clk+431]` |
| periodic, period 2 | 3097 | +0.63% | +0.65%, +0.73%, +0.69% | +0.69% | `periodic 2: [now-1320 clk+239]` |
| periodic, period 3 | 3140 | +1.11% | -6.74%, -3.23%, +1.24% | -2.91% | `periodic 3: [mtp+1 prev+187 clk+358]` |
| periodic, period 4 | 3150 | +1.27% | -6.79%, -2.59%, -7.24% | -5.54% | `periodic 4: [mtp+1 clk+1 mtp+1 clk+478]` |
| periodic, period 5 | 3250 | +1.30% | -0.23%, +0.69%, -1.32% | -0.29% | `periodic 5: [mtp+1 prev+599 clk+58 prev+181 prev+360]` |
| periodic, period 6 | 3037 | +1.49% | -1.54%, -3.02%, -0.49% | -1.68% | `periodic 6: [mtp+1 mtp+1 mtp+1 mtp+1 mtp+1 clk+720]` |
| periodic, period 10 | 3161 | +1.96% | +1.83%, +1.72%, +1.84% | +1.80% | `periodic 10: [prev+358 mtp+1 prev+361 mtp+1 prev+779 prev+1020 now-1619 clk+470 clk+719 mtp+1]` |
| periodic, period 12 | 3164 | +2.41% | -3.57%, -3.60%, -3.17% | -3.45% | `periodic 12: [mtp+1 prev+721 now-2161 now-1562 prev+898 prev+719 clk+1080 mtp+1 mtp+1 mtp+1 prev+2 prev+665]` |
| periodic, period 15 | 3180 | +0.78% | +0.45%, +0.37%, +0.48% | +0.43% | `periodic 15: [clk+117 clk+540 prev+175 prev+356 mtp+1 prev+182 prev+478 prev+660 clk+597 now-1564 mtp+1 mtp+1 mtp+1 now-1561 now-961]` |
| periodic, period 25 | 3156 | +0.71% | -2.03%, -1.84%, -1.59% | -1.82% | `periodic 25` |
| periodic, period 38 | 3215 | +0.92% | -2.43%, -2.28%, -2.63% | -2.44% | `periodic 38` |
| periodic, period 75 | 3197 | +0.44% | -0.84%, -0.52%, -0.82% | -0.73% | `periodic 75` |
| periodic, period 76 | 3210 | +0.40% | -3.26%, -3.02%, -3.47% | -3.25% | `periodic 76` |
| periodic, period 150 | 3177 | +0.25% | -2.36%, -2.57%, -2.88% | -2.60% | `periodic 150` |
| state table (clock offset x D/avg) | 21866 | +58.27% | -4.82%, -13.31%, -29.55% | -15.89% | `table` |
| hand-made reference | 1 | +0.00% | +0.03%, +0.03%, +0.03% | +0.03% | `always now+360` |
| hand-made reference | 1 | -67.72% | -70.00%, -70.27%, -70.48% | -70.25% | `periodic 76` |
| hand-made reference | 1 | -3.77% | -5.50%, -4.33%, -4.78% | -4.87% | `periodic 75` |
| miner stamps 50% of blocks (6 seeds x 3000 blocks) | - | - | - | -1.05% | `periodic 10` |
| miner stamps 80% of blocks (6 seeds x 3000 blocks) | - | - | - | -3.27% | `periodic 10` |
| miner stamps 50% of blocks (6 seeds x 3000 blocks) | - | - | - | +0.62% | `rollout H=76 over honest` |
| miner stamps 80% of blocks (6 seeds x 3000 blocks) | - | - | - | +0.81% | `rollout H=76 over honest` |

Rollout controllers (6 seeds x 3000 blocks; sustained = blocks 1000..3000 only, without the one-shot gain):

| Controller | total gain per seed | mean | sustained gain per seed | mean | min |
|---|---|---|---|---|---|
| `rollout H=76 over honest` | +0.91%, +0.88%, +0.81%, +1.18%, +0.90%, +1.17% | +0.98% | +1.00%, +0.78%, +0.86%, +1.17%, +0.95%, +1.34% | +1.02% | +0.78% |
| `rollout H=150 over honest` | +0.93%, +0.87%, +0.86%, +1.22%, +0.86%, +1.17% | +0.98% | +1.02%, +0.72%, +0.98%, +1.30%, +1.00%, +1.41% | +1.07% | +0.72% |
| `rollout H=76 over always now+360` | +0.68%, +0.68%, +0.68%, +0.94%, +0.68%, +0.96% | +0.77% | +0.73%, +0.58%, +0.67%, +0.90%, +0.65%, +1.08% | +0.77% | +0.58% |

### Race (z = 100)

| q | honest | compressed | screened best | P(best) | excess | inherited D/DEQ on compressed wins (median, max) |
|---|---|---|---|---|---|---|
| 0.3 | 0.0000 | 0.0085 | behind>-3 | 0.0112 | +1.12% | 103.87, 193.41 |
| 0.35 | 0.0000 | 0.0783 | compressed to z, then behind>3 | 0.0783 | +7.83% | 65.32, 165.53 |
| 0.4 | 0.0045 | 0.3645 | compressed to z, then behind>3 | 0.3645 | +36.00% | 37.19, 165.53 |
| 0.45 | 0.1328 | 0.7395 | behind>-3 | 0.7252 | +60.68% | 14.37, 141.69 |

Screening hits at q = 0.3 (seed set A): aligned (clock + step) 11; behind>-3 15; behind>0 11; behind>2 12; behind>5 9; behind>10 8; D-cap 1.5x 0; D-cap 2x 0; D-cap 3x 0; D-cap 5x 0; honest 10 then compressed 10; honest 38 then compressed 6; honest 75 then compressed 4; honest 76 then compressed 3; honest 100 then compressed 2; FTL edge 5 then compressed 9; FTL edge 20 then compressed 10; FTL edge 75 then compressed 3; compressed until 0.3 of horizon 0; compressed until 0.6 of horizon 4; behind>2 or after 0.5 12; behind>5 or after 0.3 9; compressed to z, then behind>0 11; compressed to z, then behind>3 11

Screening hits at q = 0.35 (seed set A): aligned (clock + step) 81; behind>-3 74; behind>0 70; behind>2 76; behind>5 79; behind>10 70; D-cap 1.5x 1; D-cap 2x 1; D-cap 3x 2; D-cap 5x 7; honest 10 then compressed 78; honest 38 then compressed 53; honest 75 then compressed 55; honest 76 then compressed 57; honest 100 then compressed 52; FTL edge 5 then compressed 71; FTL edge 20 then compressed 80; FTL edge 75 then compressed 45; compressed until 0.3 of horizon 35; compressed until 0.6 of horizon 61; behind>2 or after 0.5 76; behind>5 or after 0.3 79; compressed to z, then behind>0 81; compressed to z, then behind>3 81

Screening hits at q = 0.4 (seed set A): aligned (clock + step) 363; behind>-3 313; behind>0 296; behind>2 328; behind>5 321; behind>10 314; D-cap 1.5x 7; D-cap 2x 24; D-cap 3x 35; D-cap 5x 56; honest 10 then compressed 297; honest 38 then compressed 301; honest 75 then compressed 244; honest 76 then compressed 259; honest 100 then compressed 230; FTL edge 5 then compressed 327; FTL edge 20 then compressed 318; FTL edge 75 then compressed 260; compressed until 0.3 of horizon 204; compressed until 0.6 of horizon 311; behind>2 or after 0.5 328; behind>5 or after 0.3 321; compressed to z, then behind>0 363; compressed to z, then behind>3 363

Screening hits at q = 0.45 (seed set A): aligned (clock + step) 743; behind>-3 753; behind>0 729; behind>2 720; behind>5 686; behind>10 711; D-cap 1.5x 184; D-cap 2x 203; D-cap 3x 277; D-cap 5x 320; honest 10 then compressed 729; honest 38 then compressed 710; honest 75 then compressed 690; honest 76 then compressed 681; honest 100 then compressed 666; FTL edge 5 then compressed 730; FTL edge 20 then compressed 734; FTL edge 75 then compressed 684; compressed until 0.3 of horizon 564; compressed until 0.6 of horizon 698; behind>2 or after 0.5 720; behind>5 or after 0.3 686; compressed to z, then behind>0 743; compressed to z, then behind>3 743

### Selfish mining (work-based fork choice)

| alpha | gamma | attacker stamps | attacker share of main chain | main-chain rate vs target |
|---|---|---|---|---|
| 0.25 | 0 | honest | 0.1902 | -1.17% |
| 0.25 | 0 | always mtp+1 | 0.1835 | -4.81% |
| 0.25 | 0 | always now+360 | 0.2039 | -1.28% |
| 0.25 | 0 | always clk+60 | 0.1865 | -2.56% |
| 0.25 | 0.5 | honest | 0.2476 | -1.19% |
| 0.25 | 0.5 | always mtp+1 | 0.2421 | -5.40% |
| 0.25 | 0.5 | always now+360 | 0.2566 | -1.41% |
| 0.25 | 0.5 | always clk+60 | 0.2453 | -2.80% |
| 0.33 | 0 | honest | 0.3251 | -1.19% |
| 0.33 | 0 | always mtp+1 | 0.3100 | -10.85% |
| 0.33 | 0 | always now+360 | 0.3435 | -1.31% |
| 0.33 | 0 | always clk+60 | 0.3174 | -4.77% |
| 0.33 | 0.5 | honest | 0.3735 | -1.16% |
| 0.33 | 0.5 | always mtp+1 | 0.3610 | -11.67% |
| 0.33 | 0.5 | always now+360 | 0.3894 | -1.28% |
| 0.33 | 0.5 | always clk+60 | 0.3669 | -5.08% |
| 0.4 | 0 | honest | 0.4618 | -1.37% |
| 0.4 | 0 | always mtp+1 | 0.4289 | -22.83% |
| 0.4 | 0 | always now+360 | 0.4912 | -1.46% |
| 0.4 | 0 | always clk+60 | 0.4429 | -9.80% |
| 0.4 | 0.5 | honest | 0.5131 | -1.27% |
| 0.4 | 0.5 | always mtp+1 | 0.4810 | -24.80% |
| 0.4 | 0.5 | always now+360 | 0.5331 | -1.39% |
| 0.4 | 0.5 | always clk+60 | 0.4948 | -10.94% |

### Hoppers (825 configurations searched)

| Hopper | screening excess (points) | confirmed excess (points) |
|---|---|---|
| 100x, abs on<1.2 off>1.4, edge | +2.99 | +2.83 |
| 30x, rel on<0.9 off>1.1, edge | +2.96 | +2.90 |
| 30x, abs on<1.2 off>1.4, edge | +2.93 | +2.80 |
| 100x, rel on<0.9 off>1.1, edge | +2.89 | +3.01 |
| 30x, abs on<1.2 off>1.3, edge | +2.85 | +2.76 |
| 100x, abs on<1.2 off>1.3, edge | +2.81 | +2.80 |
| selection study's reference hopper (10x, abs on<1.2 off>2) | - | +0.30 |

The six largest hopper gains of the screening, confirmed on fresh seeds. The most negative screening excess was -41.64 points (a hopper that overpays; not an attack).

### Low difficulty (honest miners)

| D_eq | mean solve time / T | mean D / D_eq | blocks at D = 1 | CV of D | min D | max D |
|---|---|---|---|---|---|---|
| 0.3 | 3.368 | 3.333 | 1.000 | 0.000 | 1 | 1 |
| 0.7 | 1.432 | 1.429 | 1.000 | 0.000 | 1 | 1 |
| 1 | 1.004 | 1.000 | 1.000 | 0.000 | 1 | 1 |
| 1.5 | 0.675 | 0.673 | 0.991 | 0.096 | 1 | 2 |
| 2 | 0.720 | 0.718 | 0.564 | 0.346 | 1 | 3 |
| 3 | 0.826 | 0.832 | 0.002 | 0.218 | 1 | 5 |
| 5 | 0.908 | 0.911 | 0.000 | 0.158 | 3 | 8 |
| 10 | 0.963 | 0.963 | 0.000 | 0.144 | 6 | 17 |
| 100 | 1.009 | 1.017 | 0.000 | 0.133 | 64 | 166 |

### Large upward steps (deterministic)

| Scenario | blocks to within 10% | hours | excess blocks (blocks - hours x 30) |
|---|---|---|---|
| hash rate x10 | 92 | 1.63 | 43 |
| hash rate x100 | 105 | 1.47 | 61 |
| hash rate x1000 | 114 | 1.41 | 72 |
| start-up from D0 = 0.01 DEQ | 21 | 0.51 | 6 |
| start-up from D0 = 0.001 DEQ | 37 | 0.92 | 9 |
| chain at D = 1, hash rate returns to DEQ | 160 | 1.41 | 118 |

### Genesis-fork rewrite (age 720, 10-day horizon)

| q | stamps | wins / trials |
|---|---|---|
| 0.2 | honest | 0/300 |
| 0.2 | compressed | 25/300 |
| 0.3 | honest | 0/300 |
| 0.3 | compressed | 59/300 |
| 0.4 | honest | 0/300 |
| 0.4 | compressed | 104/300 |

# Selection criteria: rule under attack and candidate fix (generated)

The selection study's runner (`selection::run`) on its main seed `0x5e1ec7ed`, for the two rules only.

## Configuration

- Base seed `0x5e1ec7ed`; every job derives its seed from the base seed and its scenario coordinates, not from the rule, so all rules and policies run on common random numbers. 6 threads.
- Race: z = 100, q in [0.3, 0.35, 0.4]. Screening: 1000 trials per (rule, q, policy) on seed set A over the policies compressed + late(0.5), late(0.8), late(1), ratio(0.1), ratio(0.3), ratio(0.6). Confirmation: 4000 trials each of honest, compressed and the screened-best adaptive policy on the disjoint seed set B. Excess = max(compressed, best adaptive) - honest, all on B.
- Lowering (100% miner): dossier 04's fixed families on 3 seeds x 3000 blocks, 120 random patterns selected on 1500 blocks and the best re-run on 3 fresh seeds. Emission gain = blocks/h over honest stamping on the same draws.
- Hopper: configurations (on < x DEQ, off > y DEQ, hash multiple) [(1.2, 2.0, 10.0), (1.05, 1.5, 10.0), (1.1, 1.3, 3.0), (1.0, 1.2, 1.0)], 3 seeds x 20000 blocks each; reported: the largest |share - fair share| in points, where fair share = the hopper's share of hashes spent.
- Bias: 4 seeds x 50000 blocks. Medians: 101 seeds. Follow criteria use the slower of the deterministic run and the stochastic median; 0.5xD0 and the gap use the stochastic median. Genesis fork (informational): q = 0.2, age 720, compressed, 300 trials.

## Every candidate against every criterion

| # | Rule | Race q=0.4 (<= +5%) | Race q<=0.35 (<= +1%) | Emission gain (<= +1%) | Hopper vs fair (+-3 pts) | Bias (+-1.5%) | 10x up (<= 150) | 10x down (<= 150) | 0.5xD0 median (<= 60) | Gap median (<= 120) | Fails |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | (a') LWMA-75, virtual clock step T/2 [RECOMMENDED] | pass +3.8% | pass +0.15% | pass +0.69% | pass +2.4 | pass +1.01% | pass 113/113 | pass 130/133 | pass 2 | pass 12 | 0 |
| 2 | LWMA-75 step T/2, clock warmed over 11 blocks | pass +3.5% | pass +0.10% | pass +0.46% | pass +2.3 | pass +1.03% | pass 113/113 | pass 130/133 | pass 2 | pass 12 | 0 |

Follow cells: deterministic / median blocks. All rules are exact integer arithmetic (criterion 8); see the rule definitions.

## Race detail (z = 100, confirmation pass, 4000 trials per cell)

Cells: honest / compressed / best adaptive (policy) -> excess. Standard error of a difference near p = 0.05: about 0.007.

| Rule | q = 0.3 | q = 0.35 | q = 0.4 |
|---|---|---|---|
| (a') LWMA-75, virtual clock step T/2 [RECOMMENDED] | 0.000 / 0.000 / 0.000 (ratio(0.6)) -> +0.0% | 0.000 / 0.002 / 0.001 (ratio(0.1)) -> +0.1% | 0.003 / 0.041 / 0.032 (ratio(0.1)) -> +3.8% |
| LWMA-75 step T/2, clock warmed over 11 blocks | 0.000 / 0.000 / 0.000 (ratio(0.6)) -> +0.0% | 0.000 / 0.001 / 0.001 (ratio(0.1)) -> +0.1% | 0.003 / 0.038 / 0.038 (ratio(0.1)) -> +3.5% |

### Screening pass at q = 0.4 (seed set A, 1000 trials per policy; hits)

| Rule | compressed | late(0.5) | late(0.8) | late(1) | ratio(0.1) | ratio(0.3) | ratio(0.6) |
|---|---|---|---|---|---|---|---|
| (a') LWMA-75, virtual clock step T/2 [RECOMMENDED] | 38 | 12 | 7 | 4 | 32 | 23 | 9 |
| LWMA-75 step T/2, clock warmed over 11 blocks | 33 | 14 | 12 | 5 | 43 | 20 | 15 |

## Timestamp lowering by a 100% miner (best member per family, blocks/h gain)

| Rule | all at FTL edge | all at MTP+1 | myopic greedy | two-step greedy | b-of-c cycles | one FTL edge every c | threshold | random periodic patterns |
|---|---|---|---|---|---|---|---|---|
| (a') LWMA-75, virtual clock step T/2 [RECOMMENDED] | +0.10% (all at FTL edge) | -100.00% (all at MTP+1) | +0.39% (myopic greedy) | +0.57% (two-step greedy) | +0.09% (1-of-120 Mtp) | +0.08% (edge every 2) | +0.69% (threshold 720) | +0.32% (pattern period 6) |
| LWMA-75 step T/2, clock warmed over 11 blocks | +0.10% (all at FTL edge) | -100.00% (all at MTP+1) | +0.24% (myopic greedy) | +0.42% (two-step greedy) | +0.09% (1-of-120 Mtp) | +0.05% (edge every 60) | +0.46% (threshold 1) | +0.21% (pattern period 2) |

## Hoppers (share / fair share of blocks)

| Rule | on<1.2 off>2 x10 | on<1.05 off>1.5 x10 | on<1.1 off>1.3 x3 | on<1 off>1.2 x1 |
|---|---|---|---|---|
| (a') LWMA-75, virtual clock step T/2 [RECOMMENDED] | 0.366 / 0.342 (+2.4) | 0.250 / 0.230 (+2.0) | 0.206 / 0.193 (+1.3) | 0.116 / 0.109 (+0.8) |
| LWMA-75 step T/2, clock warmed over 11 blocks | 0.362 / 0.339 (+2.3) | 0.244 / 0.225 (+1.8) | 0.205 / 0.192 (+1.3) | 0.116 / 0.108 (+0.8) |

## Liveness and start-up (informational columns included)

| Rule | 10x down: hours (det) | 100x drop: blocks, hours (det) | 0.5xD0 det | Gap det | Gap: extra blocks in first 6 h (median) | Gap at D0 = 100 (det) | Genesis fork q=0.2 age 720 (compressed) |
|---|---|---|---|---|---|---|---|
| (a') LWMA-75, virtual clock step T/2 [RECOMMENDED] | 9.6 | 184, 62.0 | 2 | 11 | +9 | 12 | 0/300 |
| LWMA-75 step T/2, clock warmed over 11 blocks | 9.6 | 184, 62.0 | 2 | 11 | +9 | 12 | 0/300 |

## Automated verdict

- Candidates meeting every criterion: (a') LWMA-75, virtual clock step T/2 [RECOMMENDED]; LWMA-75 step T/2, clock warmed over 11 blocks.

## Correction 2026-10-02: the RT-3 residual is not covered by park-on-deep-reorg

The RT-3 row above, `results.md` ("pair the cap with defence in depth (02's
park-on-deep-reorg)") and `selection.md` (the criteria "assign the q ≈ 0.4 residual to
02's park-on-deep-reorg") assign the race residual to park-on-deep-reorg. That does not
hold (threat-model round 2 cross-check, §1.7):
- the RT-3 figures are measured at z = 100 confirmations, while the decided park depth
  is 720 for a public testnet and park is off for the trial (decisions "Agent 02" W-7),
  so park would never act on such a race; park is also not implemented;
- RT-4 (the inherited difficulty) arises after the attacker's branch is accepted, which
  park does not touch.

The residual (+3.5% at q = 0.4, +27.4% at q = 0.45 on the adopted rule) is accepted
under the majority-hash assumption (K1), and the RT-4 liveness cost goes to the incident
procedure (docs/testnet-incident-response.md §4.4). The figures and the rule are
unchanged; the record of the decision is in docs/reviews/v3-consensus-changes.md
(`daa-lwma75-warm`, item 8).
