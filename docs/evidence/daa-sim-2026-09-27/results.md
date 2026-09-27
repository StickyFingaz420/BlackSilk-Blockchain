# Difficulty-rule simulation (daa-sim), 2026-09-27

Internal engineering evidence for decision 03-F1 (difficulty-raising attack), produced by the
pure-Rust harness `tools/daa-sim`. This is not an audit. The candidate rules exist only in the
harness; consensus code is unchanged.

- **Base commit:** `9e422d8` (rebuild/core). Branch `w0-daa-sim`.
- **Command:** `cargo run --release -p blacksilk-daa-sim -- --out <file>` (default base seed
  `0xb1ac0511c03`, full mode, about 400 s on 4 threads). Everything below the "Generated
  tables" line is the unedited output of that command. Results do not depend on the thread
  count. Floating-point `ln` comes from the platform libm, so other platforms may differ in the
  last digits.
- **Trial counts:** race 2 000 trials per (rule, q, z, stamping) cell; genesis fork 1 000 trials
  per cell (300 at age 7 200); honest bias 4 x 50 000 blocks; hopper 3 x 20 000 blocks;
  stochastic medians over 101 seeds; lowering 3 x 3 000 blocks per strategy plus 120 random
  patterns (best re-run on 3 fresh seeds).
- **What is real consensus code:** LWMA-60 is `blacksilk_consensus::difficulty::next_difficulty`
  called exactly as `HeaderChain::required_difficulty` calls it. Every block goes through
  `blacksilk_consensus::timestamp::{after_median_time_past, within_future_limit}` (MTP-11,
  FTL 360 s). The harness panics on any invalid stamp.
- **Scale:** equilibrium difficulty 10^6, so integer rounding does not distort the percentage
  caps. At the current testnet placeholder `D0 = 100`, a 2% cap degenerates to +1 per block
  below difficulty 50. See the gap table's `D0 = 100` column.

## Conclusion

**No candidate meets all four acceptance criteria of decisions.md.** The race criterion
(excess <= +2% at q <= 0.4, z = 100) and the liveness criteria (10x up <= 150 blocks, from
0.5xD0 <= 40 blocks) conflict. This is the GKL dampening trade-off that dossier 03 predicted.

**F1 is reproduced on the current rule.**
- At q = 0.4 and z = 100, a compressed-stamp attacker wins 0.332 of trials, against 0.005 for
  the honest-stamp baseline.
- At q = 0.35 it wins 0.103, against 0.000.
- In the genesis fork at q = 0.2 and chain age 720, it wins 0.077, against 0.000.
- The reduced test `tools/daa-sim/tests/f1.rs` pins this with 1 000 trials and prints:
  `q = 0.4, z = 100, 1000 trials: compressed 0.368 (368), honest baseline 0.007 (7)`.

**The rise cap.** Race excess at q = 0.4, z = 100, by cap R:

| R | Race excess |
|---|---|
| 1.75% | +3.8% |
| 2% | +4.2% |
| 2.25% | +5.3% |
| 2.5% | +5.0% |
| 3% | +6.6% |
| 5% | +13.9% |

- Between 1.75% and 2.5% the excess is flat within noise (one se of the difference is about 0.5
  points). The residual is the variance of a branch whose difficulty compounds at 1+R per
  block. The +2% target would need roughly R <= 1% (extrapolated, not simulated), which fails
  the 10x-up and 0.5xD0 criteria by a wide margin: 1.75% already needs 149 blocks for 10x up.
- At every R, the cap removes the genesis-fork rewrite: 0/1 000 trials in every cell.
- At every R, the cap cuts q <= 0.35 to <= 0.4% excess.

**ASERT.**
- A 6 h half-life meets the race criterion (+0.3%) and has zero bias.
- It needs 1 142 blocks (19 h) to follow a 10x rise and 571 blocks from 0.5xD0.
- A 2 h half-life misses the race criterion narrowly (+2.25%) and needs 381 and 191 blocks.
- Neither meets the liveness criteria.

**The bias criterion fails on the current rule itself (+1.36%).** A cap lowers the bias
(2%: +0.86%; 1.75%: +0.60%), because it trims upward overshoot.

**New finding (for W2 and red-team 50).** A rise cap makes timestamp lowering profitable for a
majority miner. The best 100%-miner strategy gains, in blocks per hour over honest stamping on
common random numbers (the threshold-720 policy, sustained over 3 x 3 000 blocks):

| Rule | Gain |
|---|---|
| Current rule | +0.65% |
| 3% cap | +1.46% |
| 2.5% cap | +2.58% |
| 2% cap | +3.82% |
| 1.75% cap | +4.41% |

The cause is an asymmetry: forward stamps lower the difficulty at LWMA speed, while the
compensating rise is capped. The effect is emission speed only. A minority miner cannot raise
its own share this way (dossier 04's argument, not re-simulated here), but this weakens the
03-F3 downgrade for any capped rule.

**Other costs of a 2% cap versus the current rule:**
- 2 h genesis gap: 112 blocks to recover instead of 29, and +54 extra blocks in the first 6 h
  instead of +10.
- The same gap at `D0 = 100`: 91 blocks to recover.
- Hopper share: 0.363 instead of 0.316.
- Start-up from 0.5xD0: 31 blocks deterministic, but a stochastic median of 47 (above 40).
- D0 set 100x too low: 253 blocks.
- 10x down: unchanged (104 blocks, 7.7 h).

### Recommendation

- **Candidate: R = 2% (`next <= parent + max(1, parent/50)`).** The coordinator must first
  either amend the race criterion or accept the residual.
- **Why 2%:**
  - It is the largest R that passes the three non-race criteria (bias +0.86%, 10x up in 137
    blocks, 0.5xD0 in 31 blocks deterministic).
  - Its race excess is statistically indistinguishable from 1.75% and 2.5%.
  - 2.25% and above fail the bias criterion.
- **Effect at q = 0.4, z = 100:** a 2% cap cuts F1 from +32.7% to +4.2%. At q <= 0.35 it
  removes F1 in practice (<= +0.2%), and it removes the genesis-era rewrite (03-F2).
- **What it does not meet:**
  - the +2% race target at q = 0.4;
  - the stochastic start-up target.
- **Costs to accept:**
  - slower gap recovery, unless T_g moves closer to launch (40);
  - majority-miner lowering gains of about 4%.
- **Why not ASERT:** it is the only rule family that reaches the race target (6 h half-life),
  and it fails liveness by an order of magnitude, so it is not recommended for a small, volatile
  testnet.
- **For a stricter bound at q = 0.4**, pair the cap with defence in depth (02's
  park-on-deep-reorg), not with a smaller R.

**Discrepancy with dossier 03.** Its scratch run gave 0.020 at q = 0.4 for a 2% cap (600 trials,
difficulty about 120). This harness measures 0.044 (2 000 trials, difficulty 10^6). A plausible
cause, not verified here, is integer truncation in the scratch port: at difficulty about 120,
`parent*2/100` truncates to 2, an effective cap of <= 1.7%.

**Limitations.**
- The attacker models are fixed strategies: honest stamps and all-MTP+1 stamps. An adaptive
  attacker (for example, compress late) was not searched, so the excess figures are lower
  bounds for the rise-cap candidates.
- The lowering families are not exhaustive either.
- The honest chain in the race uses honest stamps only.
- The model has no network latency, orphans or clock skew.
- A private block whose lowest valid stamp is beyond the FTL is held until the clock allows it
  (`held_back`). This matters only at difficulties far below the hash rate.

---

Generated tables (unedited output):


Generated by `cargo run --release -p blacksilk-daa-sim --` (full mode, 394 s on 4 threads). Rules: LWMA-60 (current); LWMA-90; LWMA-60 + rise <= 1.75%; LWMA-60 + rise <= 2%; LWMA-60 + rise <= 2.25%; LWMA-60 + rise <= 2.5%; LWMA-60 + rise <= 3%; LWMA-60 + rise <= 5%; ASERT half-life 2 h; ASERT half-life 6 h.

## Configuration

- Base seed: `0xb1ac0511c03`. Every job derives its own seed from the base seed and its scenario coordinates (`rng::derive`), so results do not depend on the thread count (4 threads used).
- T = 120 s, FTL = 360 s, MTP window 11, equilibrium difficulty DEQ = 1000000 (reference hash rate DEQ/T). Solve times are exponential with mean D/H.
- Race: 2000 trials per (rule, q, z, stamping) cell; q in [0.2, 0.3, 0.35, 0.4, 0.45]; z in [6, 20, 100]; horizon 12z + 240 block times; the private branch starts from a 121-block equilibrium chain.
- Genesis fork: (q, chain age, trials) = [(0.1, 720, 1000), (0.2, 720, 1000), (0.3, 720, 1000), (0.2, 7200, 300)]; horizon 10 days after the fork.
- Honest bias: 4 seeds x 50000 blocks (after 1 000 burn-in). Hopper: 3 seeds x 20000 blocks. Stochastic medians: 101 seeds. Lowering: 3 seeds x 3000 blocks per strategy; 120 random patterns selected on 1500 blocks and the best re-run on 3 fresh seeds.

## Summary

| Rule | Race q=0.4 z=100: compressed / honest | Max excess q<=0.4 z=100 (+3 se) | Honest bias | 10x up: blocks (h) | 10x down: blocks (h) | From 0.5xD0: blocks | 2 h gap: recovery blocks | Genesis fork q=0.2 age 720 | Hopper share | Best lowering gain |
|---|---|---|---|---|---|---|---|---|---|---|
| LWMA-60 (current) | 0.332 / 0.005 | +32.65% (+35.85%) | +1.36% | 92 (1.6) | 104 (7.7) | 2 | 29 | 0.077 (honest 0.000) | 0.316 | +0.65% |
| LWMA-90 | 0.194 / 0.005 | +18.80% (+21.50%) | +0.99% | 137 (2.4) | 156 (11.5) | 2 | 29 | 0.077 (honest 0.000) | 0.305 | +0.54% |
| LWMA-60 + rise <= 1.75% | 0.043 / 0.005 | +3.80% (+5.24%) | +0.60% | 149 (2.1) | 104 (7.7) | 35 | 121 | 0.000 (honest 0.000) | 0.384 | +4.41% |
| LWMA-60 + rise <= 2% | 0.044 / 0.002 | +4.20% (+5.61%) | +0.86% | 137 (2.1) | 104 (7.7) | 31 | 112 | 0.000 (honest 0.000) | 0.363 | +3.82% |
| LWMA-60 + rise <= 2.25% | 0.056 / 0.003 | +5.25% (+6.83%) | +1.05% | 127 (2.0) | 104 (7.7) | 28 | 105 | 0.000 (honest 0.000) | 0.345 | +3.23% |
| LWMA-60 + rise <= 2.5% | 0.054 / 0.004 | +4.95% (+6.53%) | +1.17% | 119 (1.9) | 104 (7.7) | 25 | 100 | 0.000 (honest 0.000) | 0.331 | +2.58% |
| LWMA-60 + rise <= 3% | 0.071 / 0.005 | +6.60% (+8.39%) | +1.31% | 108 (1.8) | 104 (7.7) | 21 | 91 | 0.000 (honest 0.000) | 0.321 | +1.46% |
| LWMA-60 + rise <= 5% | 0.143 / 0.005 | +13.85% (+16.25%) | +1.36% | 92 (1.6) | 104 (7.7) | 14 | 76 | 0.000 (honest 0.000) | 0.316 | +0.65% |
| ASERT half-life 2 h | 0.025 / 0.003 | +2.25% (+3.37%) | -0.00% | 381 (6.3) | 198 (12.9) | 191 | 192 | 0.000 (honest 0.000) | 0.339 | +0.10% |
| ASERT half-life 6 h | 0.008 / 0.005 | +0.30% (+1.06%) | -0.00% | 1142 (19.0) | 595 (38.9) | 571 | 223 | 0.000 (honest 0.000) | 0.332 | +0.10% |

## Acceptance criteria (decisions.md, Agent 03)

Race excess <= +2% at q <= 0.4, z = 100 (point estimate); |honest bias| <= 1%; 10x up in <= 150 blocks; from 0.5xD0 in <= 40 blocks (deterministic runs).

| Rule | Race | Bias | 10x up | 0.5xD0 | All | All but bias | Race also passes at +3 se |
|---|---|---|---|---|---|---|---|
| LWMA-60 (current) | FAIL (+32.65%) | FAIL (+1.36%) | pass | pass | **FAIL** | FAIL | no |
| LWMA-90 | FAIL (+18.80%) | pass (+0.99%) | pass | pass | **FAIL** | FAIL | no |
| LWMA-60 + rise <= 1.75% | FAIL (+3.80%) | pass (+0.60%) | pass | pass | **FAIL** | FAIL | no |
| LWMA-60 + rise <= 2% | FAIL (+4.20%) | pass (+0.86%) | pass | pass | **FAIL** | FAIL | no |
| LWMA-60 + rise <= 2.25% | FAIL (+5.25%) | FAIL (+1.05%) | pass | pass | **FAIL** | FAIL | no |
| LWMA-60 + rise <= 2.5% | FAIL (+4.95%) | FAIL (+1.17%) | pass | pass | **FAIL** | FAIL | no |
| LWMA-60 + rise <= 3% | FAIL (+6.60%) | FAIL (+1.31%) | pass | pass | **FAIL** | FAIL | no |
| LWMA-60 + rise <= 5% | FAIL (+13.85%) | FAIL (+1.36%) | pass | pass | **FAIL** | FAIL | no |
| ASERT half-life 2 h | FAIL (+2.25%) | pass (-0.00%) | FAIL | FAIL | **FAIL** | FAIL | no |
| ASERT half-life 6 h | pass (+0.30%) | pass (-0.00%) | FAIL | FAIL | **FAIL** | FAIL | yes |

## Difficulty-raising race (P(attacker wins))

Each cell: compressed-stamp attacker / honest-stamp attacker (baseline). Standard error at p = 0.02 and 2000 trials: 0.003.

### z = 6 confirmations

| Rule | q = 0.2 | q = 0.3 | q = 0.35 | q = 0.4 | q = 0.45 |
|---|---|---|---|---|---|
| LWMA-60 (current) | 0.019 / 0.016 | 0.144 / 0.110 | 0.275 / 0.216 | 0.517 / 0.405 | 0.774 / 0.650 |
| LWMA-90 | 0.013 / 0.013 | 0.127 / 0.111 | 0.259 / 0.227 | 0.465 / 0.411 | 0.749 / 0.645 |
| LWMA-60 + rise <= 1.75% | 0.018 / 0.017 | 0.127 / 0.108 | 0.245 / 0.229 | 0.458 / 0.414 | 0.715 / 0.640 |
| LWMA-60 + rise <= 2% | 0.023 / 0.015 | 0.154 / 0.112 | 0.249 / 0.241 | 0.445 / 0.408 | 0.711 / 0.642 |
| LWMA-60 + rise <= 2.25% | 0.016 / 0.017 | 0.134 / 0.106 | 0.263 / 0.239 | 0.455 / 0.397 | 0.737 / 0.641 |
| LWMA-60 + rise <= 2.5% | 0.017 / 0.017 | 0.126 / 0.106 | 0.270 / 0.230 | 0.469 / 0.400 | 0.750 / 0.633 |
| LWMA-60 + rise <= 3% | 0.017 / 0.011 | 0.132 / 0.102 | 0.249 / 0.236 | 0.470 / 0.410 | 0.752 / 0.641 |
| LWMA-60 + rise <= 5% | 0.019 / 0.016 | 0.138 / 0.110 | 0.281 / 0.216 | 0.490 / 0.405 | 0.771 / 0.650 |
| ASERT half-life 2 h | 0.018 / 0.015 | 0.131 / 0.127 | 0.254 / 0.240 | 0.451 / 0.405 | 0.698 / 0.637 |
| ASERT half-life 6 h | 0.022 / 0.015 | 0.141 / 0.100 | 0.283 / 0.235 | 0.480 / 0.421 | 0.701 / 0.647 |

### z = 20 confirmations

| Rule | q = 0.2 | q = 0.3 | q = 0.35 | q = 0.4 | q = 0.45 |
|---|---|---|---|---|---|
| LWMA-60 (current) | 0.000 / 0.000 | 0.025 / 0.005 | 0.118 / 0.039 | 0.363 / 0.173 | 0.737 / 0.450 |
| LWMA-90 | 0.000 / 0.000 | 0.018 / 0.006 | 0.087 / 0.041 | 0.283 / 0.174 | 0.664 / 0.465 |
| LWMA-60 + rise <= 1.75% | 0.000 / 0.000 | 0.015 / 0.005 | 0.065 / 0.039 | 0.237 / 0.161 | 0.567 / 0.446 |
| LWMA-60 + rise <= 2% | 0.000 / 0.000 | 0.020 / 0.004 | 0.064 / 0.040 | 0.240 / 0.175 | 0.597 / 0.435 |
| LWMA-60 + rise <= 2.25% | 0.000 / 0.000 | 0.017 / 0.006 | 0.073 / 0.046 | 0.244 / 0.165 | 0.610 / 0.429 |
| LWMA-60 + rise <= 2.5% | 0.000 / 0.000 | 0.017 / 0.006 | 0.076 / 0.037 | 0.237 / 0.159 | 0.610 / 0.452 |
| LWMA-60 + rise <= 3% | 0.000 / 0.000 | 0.013 / 0.006 | 0.073 / 0.048 | 0.239 / 0.175 | 0.633 / 0.441 |
| LWMA-60 + rise <= 5% | 0.001 / 0.000 | 0.025 / 0.005 | 0.090 / 0.039 | 0.308 / 0.173 | 0.671 / 0.450 |
| ASERT half-life 2 h | 0.000 / 0.000 | 0.013 / 0.004 | 0.057 / 0.037 | 0.228 / 0.173 | 0.552 / 0.462 |
| ASERT half-life 6 h | 0.000 / 0.000 | 0.007 / 0.006 | 0.053 / 0.041 | 0.188 / 0.164 | 0.519 / 0.460 |

### z = 100 confirmations

| Rule | q = 0.2 | q = 0.3 | q = 0.35 | q = 0.4 | q = 0.45 |
|---|---|---|---|---|---|
| LWMA-60 (current) | 0.000 / 0.000 | 0.011 / 0.000 | 0.103 / 0.000 | 0.332 / 0.005 | 0.747 / 0.135 |
| LWMA-90 | 0.000 / 0.000 | 0.001 / 0.000 | 0.017 / 0.000 | 0.194 / 0.005 | 0.650 / 0.128 |
| LWMA-60 + rise <= 1.75% | 0.000 / 0.000 | 0.000 / 0.000 | 0.003 / 0.000 | 0.043 / 0.005 | 0.394 / 0.144 |
| LWMA-60 + rise <= 2% | 0.000 / 0.000 | 0.000 / 0.000 | 0.002 / 0.000 | 0.044 / 0.002 | 0.420 / 0.138 |
| LWMA-60 + rise <= 2.25% | 0.000 / 0.000 | 0.000 / 0.000 | 0.002 / 0.000 | 0.056 / 0.003 | 0.443 / 0.141 |
| LWMA-60 + rise <= 2.5% | 0.000 / 0.000 | 0.000 / 0.000 | 0.002 / 0.000 | 0.054 / 0.004 | 0.456 / 0.148 |
| LWMA-60 + rise <= 3% | 0.000 / 0.000 | 0.000 / 0.000 | 0.004 / 0.000 | 0.071 / 0.005 | 0.489 / 0.128 |
| LWMA-60 + rise <= 5% | 0.000 / 0.000 | 0.001 / 0.000 | 0.013 / 0.000 | 0.143 / 0.005 | 0.576 / 0.135 |
| ASERT half-life 2 h | 0.000 / 0.000 | 0.000 / 0.000 | 0.000 / 0.000 | 0.025 / 0.003 | 0.298 / 0.135 |
| ASERT half-life 6 h | 0.000 / 0.000 | 0.000 / 0.000 | 0.000 / 0.000 | 0.008 / 0.005 | 0.182 / 0.131 |

## Genesis-fork rewrite (P(private branch from genesis overtakes))

The chain runs `age` blocks at the full hash rate; then a miner with share q mines a branch from genesis for 10 days. Cells: compressed / honest stamps (trials; capped trials count as losses).

| Rule | q = 0.1, age 720 (1000) | q = 0.2, age 720 (1000) | q = 0.3, age 720 (1000) | q = 0.2, age 7200 (300) |
|---|---|---|---|---|
| LWMA-60 (current) | 0.016 / 0.000 | 0.077 / 0.000 | 0.189 / 0.000 | 0.010 / 0.000 |
| LWMA-90 | 0.008 / 0.000 | 0.077 / 0.000 | 0.226 / 0.000 | 0.017 / 0.000 |
| LWMA-60 + rise <= 1.75% | 0.000 / 0.000 | 0.000 / 0.000 | 0.000 / 0.000 | 0.000 / 0.000 |
| LWMA-60 + rise <= 2% | 0.000 / 0.000 | 0.000 / 0.000 | 0.000 / 0.000 | 0.000 / 0.000 |
| LWMA-60 + rise <= 2.25% | 0.000 / 0.000 | 0.000 / 0.000 | 0.000 / 0.000 | 0.000 / 0.000 |
| LWMA-60 + rise <= 2.5% | 0.000 / 0.000 | 0.000 / 0.000 | 0.000 / 0.000 | 0.000 / 0.000 |
| LWMA-60 + rise <= 3% | 0.000 / 0.000 | 0.000 / 0.000 | 0.000 / 0.000 | 0.000 / 0.000 |
| LWMA-60 + rise <= 5% | 0.000 / 0.000 | 0.000 / 0.000 | 0.000 / 0.000 | 0.000 / 0.000 |
| ASERT half-life 2 h | 0.000 / 0.000 | 0.000 / 0.000 | 0.000 / 0.000 | 0.000 / 0.000 |
| ASERT half-life 6 h | 0.000 / 0.000 | 0.000 / 0.000 | 0.000 / 0.000 | 0.000 / 0.000 |

## Honest operation

| Rule | Mean solve time / T - 1 (se) | 10x up: det blocks (h) / median | 10x down: det blocks (h) / median |
|---|---|---|---|
| LWMA-60 (current) | +1.36% (0.01%) | 92 (1.6) / 73 | 104 (7.7) / 105 |
| LWMA-90 | +0.99% (0.01%) | 137 (2.4) / 114 | 156 (11.5) / 155 |
| LWMA-60 + rise <= 1.75% | +0.60% (0.01%) | 149 (2.1) / 132 | 104 (7.7) / 105 |
| LWMA-60 + rise <= 2% | +0.86% (0.01%) | 137 (2.1) / 119 | 104 (7.7) / 105 |
| LWMA-60 + rise <= 2.25% | +1.05% (0.01%) | 127 (2.0) / 107 | 104 (7.7) / 105 |
| LWMA-60 + rise <= 2.5% | +1.17% (0.01%) | 119 (1.9) / 97 | 104 (7.7) / 105 |
| LWMA-60 + rise <= 3% | +1.31% (0.01%) | 108 (1.8) / 90 | 104 (7.7) / 105 |
| LWMA-60 + rise <= 5% | +1.36% (0.01%) | 92 (1.6) / 73 | 104 (7.7) / 105 |
| ASERT half-life 2 h | -0.00% (0.00%) | 381 (6.3) / 371 | 198 (12.9) / 171 |
| ASERT half-life 6 h | -0.00% (0.01%) | 1142 (19.0) / 1116 | 595 (38.9) / 549 |

"Blocks" counts blocks after the change until a block's difficulty is within +/-10% of the new equilibrium; "det" uses expected solve times, "median" is over 101 stochastic seeds.

## Start-up from a mis-set D0

Cells: first height whose difficulty is within +/-10% of equilibrium, deterministic / stochastic median; and the expected time to block 1.

| Rule | D0 = 0.01x | D0 = 0.1x | D0 = 0.5x | D0 = 2x | D0 = 10x |
|---|---|---|---|---|---|
| LWMA-60 (current) | 21 / 8 (block 1: 1 s) | 2 / 8 (block 1: 12 s) | 2 / 8 (block 1: 60 s) | 2 / 6 (block 1: 240 s) | 62 / 36 (block 1: 1200 s) |
| LWMA-90 | 21 / 8 (block 1: 1 s) | 2 / 8 (block 1: 12 s) | 2 / 8 (block 1: 60 s) | 2 / 6 (block 1: 240 s) | 92 / 36 (block 1: 1200 s) |
| LWMA-60 + rise <= 1.75% | 282 / 265 (block 1: 1 s) | 149 / 134 (block 1: 12 s) | 35 / 54 (block 1: 60 s) | 2 / 17 (block 1: 240 s) | 62 / 35 (block 1: 1200 s) |
| LWMA-60 + rise <= 2% | 253 / 238 (block 1: 1 s) | 137 / 122 (block 1: 12 s) | 31 / 47 (block 1: 60 s) | 2 / 16 (block 1: 240 s) | 62 / 35 (block 1: 1200 s) |
| LWMA-60 + rise <= 2.25% | 231 / 218 (block 1: 1 s) | 127 / 110 (block 1: 12 s) | 28 / 42 (block 1: 60 s) | 2 / 15 (block 1: 240 s) | 62 / 35 (block 1: 1200 s) |
| LWMA-60 + rise <= 2.5% | 213 / 199 (block 1: 1 s) | 119 / 103 (block 1: 12 s) | 25 / 39 (block 1: 60 s) | 2 / 13 (block 1: 240 s) | 62 / 35 (block 1: 1200 s) |
| LWMA-60 + rise <= 3% | 186 / 171 (block 1: 1 s) | 108 / 88 (block 1: 12 s) | 21 / 32 (block 1: 60 s) | 2 / 12 (block 1: 240 s) | 62 / 35 (block 1: 1200 s) |
| LWMA-60 + rise <= 5% | 133 / 119 (block 1: 1 s) | 86 / 72 (block 1: 12 s) | 14 / 21 (block 1: 60 s) | 2 / 10 (block 1: 240 s) | 62 / 34 (block 1: 1200 s) |
| ASERT half-life 2 h | 588 / 578 (block 1: 1 s) | 381 / 359 (block 1: 12 s) | 191 / 169 (block 1: 60 s) | 148 / 124 (block 1: 240 s) | 198 / 171 (block 1: 1200 s) |
| ASERT half-life 6 h | 1764 / 1740 (block 1: 1 s) | 1142 / 1121 (block 1: 12 s) | 571 / 564 (block 1: 60 s) | 443 / 423 (block 1: 240 s) | 595 / 574 (block 1: 1200 s) |

## Genesis-to-launch gap (2 h)

Genesis stamped 2 h before mining starts, D0 correct. Minimum difficulty reached (x equilibrium), first height back at >= 90%, and extra blocks in the first 6 h of mining (180 expected). The D0 = 100 column repeats the deterministic run at the current testnet placeholder, where integer rounding matters.

| Rule | Min ratio | Recovery: det / median | Extra blocks in 6 h: det / median | D0 = 100: min, recovery |
|---|---|---|---|---|
| LWMA-60 (current) | 0.167 | 29 / 11 | 10 / 7 | 0.16, 29 |
| LWMA-90 | 0.167 | 29 / 11 | 11 / 8 | 0.16, 29 |
| LWMA-60 + rise <= 1.75% | 0.167 | 121 / 104 | 60 / 61 | 0.16, 91 |
| LWMA-60 + rise <= 2% | 0.167 | 112 / 97 | 54 / 54 | 0.16, 91 |
| LWMA-60 + rise <= 2.25% | 0.167 | 105 / 90 | 49 / 49 | 0.16, 91 |
| LWMA-60 + rise <= 2.5% | 0.167 | 100 / 80 | 46 / 45 | 0.16, 91 |
| LWMA-60 + rise <= 3% | 0.167 | 91 / 70 | 40 / 39 | 0.16, 91 |
| LWMA-60 + rise <= 5% | 0.167 | 76 / 39 | 29 / 27 | 0.16, 82 |
| ASERT half-life 2 h | 0.500 | 192 / 179 | 54 / 53 | 0.50, 188 |
| ASERT half-life 6 h | 0.794 | 223 / 206 | 31 / 30 | 0.79, 215 |

## Hop-in/hop-out mining

A hopper with 10x the dedicated hash rate mines while D < 1.2 DEQ and leaves above 2 DEQ.

| Rule | Hopper share of blocks | Mean solve time / T | Blocks slower than 6T |
|---|---|---|---|
| LWMA-60 (current) | 0.316 | 1.050 | 1.47% |
| LWMA-90 | 0.305 | 1.043 | 1.31% |
| LWMA-60 + rise <= 1.75% | 0.384 | 0.998 | 1.59% |
| LWMA-60 + rise <= 2% | 0.363 | 1.019 | 1.61% |
| LWMA-60 + rise <= 2.25% | 0.345 | 1.033 | 1.59% |
| LWMA-60 + rise <= 2.5% | 0.331 | 1.042 | 1.50% |
| LWMA-60 + rise <= 3% | 0.321 | 1.048 | 1.45% |
| LWMA-60 + rise <= 5% | 0.316 | 1.050 | 1.47% |
| ASERT half-life 2 h | 0.339 | 0.999 | 1.31% |
| ASERT half-life 6 h | 0.332 | 0.994 | 1.17% |

## Timestamp lowering by a 100% miner (dossier 04's families)

Gain in blocks per hour over honest stamping on the same solve-time draws (positive = the strategy lowers the difficulty). Best member of each family.

| Rule | all at FTL edge | all at MTP+1 | myopic greedy | two-step greedy | b-of-c cycles | one FTL edge every c | threshold | random periodic patterns |
|---|---|---|---|---|---|---|---|---|
| LWMA-60 (current) | +0.11% (all at FTL edge) | -100.00% (all at MTP+1) | +0.21% (myopic greedy) | +0.52% (two-step greedy) | +0.09% (1-of-60 Mtp) | -0.09% (edge every 60) | +0.65% (threshold 240) | +0.61% (pattern period 5) |
| LWMA-90 | +0.11% (all at FTL edge) | -100.00% (all at MTP+1) | +0.18% (myopic greedy) | +0.49% (two-step greedy) | +0.09% (1-of-30 Mtp) | -0.08% (edge every 60) | +0.54% (threshold 120) | +0.47% (pattern period 5) |
| LWMA-60 + rise <= 1.75% | +0.11% (all at FTL edge) | -100.00% (all at MTP+1) | +1.20% (myopic greedy) | +1.57% (two-step greedy) | +0.13% (1-of-30 Mtp) | +1.20% (edge every 10) | +4.41% (threshold 720) | +0.90% (pattern period 5) |
| LWMA-60 + rise <= 2% | +0.11% (all at FTL edge) | -100.00% (all at MTP+1) | +0.86% (myopic greedy) | +1.20% (two-step greedy) | +0.12% (1-of-30 Mtp) | +0.87% (edge every 10) | +3.82% (threshold 720) | +0.87% (pattern period 5) |
| LWMA-60 + rise <= 2.25% | +0.11% (all at FTL edge) | -100.00% (all at MTP+1) | +0.59% (myopic greedy) | +0.87% (two-step greedy) | +0.12% (1-of-30 Mtp) | +0.56% (edge every 10) | +3.23% (threshold 720) | +0.83% (pattern period 5) |
| LWMA-60 + rise <= 2.5% | +0.11% (all at FTL edge) | -100.00% (all at MTP+1) | +0.44% (myopic greedy) | +0.70% (two-step greedy) | +0.11% (1-of-30 PrevPlusOne) | +0.27% (edge every 10) | +2.58% (threshold 720) | +0.77% (pattern period 5) |
| LWMA-60 + rise <= 3% | +0.11% (all at FTL edge) | -100.00% (all at MTP+1) | +0.28% (myopic greedy) | +0.55% (two-step greedy) | +0.10% (1-of-30 Mtp) | -0.04% (edge every 60) | +1.46% (threshold 720) | +0.68% (pattern period 5) |
| LWMA-60 + rise <= 5% | +0.11% (all at FTL edge) | -100.00% (all at MTP+1) | +0.21% (myopic greedy) | +0.52% (two-step greedy) | +0.09% (1-of-60 Mtp) | -0.09% (edge every 60) | +0.65% (threshold 240) | +0.61% (pattern period 5) |
| ASERT half-life 2 h | +0.10% (all at FTL edge) | -100.00% (all at MTP+1) | +0.10% (myopic greedy) | +0.10% (two-step greedy) | +0.10% (1-of-120 PrevPlusOne) | +0.05% (edge every 2) | +0.10% (threshold 1) | +0.09% (pattern period 3) |
| ASERT half-life 6 h | +0.10% (all at FTL edge) | -99.99% (all at MTP+1) | +0.10% (myopic greedy) | +0.10% (two-step greedy) | +0.10% (1-of-120 PrevPlusOne) | +0.05% (edge every 2) | +0.10% (threshold 1) | +0.09% (pattern period 3) |

## Automated verdict

- Candidates meeting every criterion: none.
- Candidates meeting every criterion except the honest-bias one: none.
- No candidate meets every criterion (nor every criterion but the bias).
