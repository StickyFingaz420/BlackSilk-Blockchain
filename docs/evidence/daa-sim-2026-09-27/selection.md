# Difficulty-rule selection study (W0-03b), 2026-09-27

Internal engineering evidence for decision 03-F1 ("DAA update" in the coordinator's decision
log). This is not an audit. The candidate rules exist only in the harness `tools/daa-sim`;
consensus code is unchanged. CB-A implements the chosen rule only after coordinator and
red-team review.

- **Branch:** `w0-daa-select`, based on `rebuild/core` at `2d46ac4`.
- **Main command:** `cargo run --release -p blacksilk-daa-sim -- --selection`. It uses base seed
  `0x5e1ec7ed` and 4 threads, and takes about 20 min.
- **Confirmation command:** `cargo run --release -p blacksilk-daa-sim -- --selection --seed
  0xc0ffee03b --only 'LWMA-60 (current)~RECOMMENDED~LWMA-60, virtual clock step T/2~c = 1.5'`.
  It takes about 3 min.
- **Output:** everything below the "Generated tables" lines is the unedited output of these
  two commands. Results do not depend on the thread count. Floating-point `ln` comes from the
  platform libm, so other platforms may differ in the last digits.
- **Pinning test:** `tools/daa-sim/tests/selection.rs` pins the recommended rule's key metrics
  with reduced sizes. `cargo test --release -p blacksilk-daa-sim` takes about 15 s.

## Trial counts and seeds

**Races** (difficulty raising, Bahack):
- Settings: z = 100, q in {0.30, 0.35, 0.40}.
- **Screening:** 1 000 trials per (rule, q, policy) on seed set A, over seven attacker
  policies:
  - compressed (always MTP+1);
  - late(0.5), late(0.8), late(1.0): honest stamps until the public chain has that fraction
    of z blocks after the fork, then compressed;
  - ratio(0.1), ratio(0.3), ratio(0.6): the branch clock runs at that fraction of real time,
    which is partial compression. Together these are the search over compress ratios.
- **Confirmation:** 4 000 trials each of honest, compressed and the screened-best adaptive
  policy, on the disjoint seed set B.
- **Excess:** max(compressed, best adaptive) minus honest, all measured on set B. This removes
  the selection bias of choosing the best policy.
- **Common random numbers:** seeds depend only on scenario coordinates, never on the rule, so
  every rule and policy sees the same draws.

**Lowering** (100% miner, dossier 04's families):
- The fixed families: FTL edge, MTP+1, myopic greedy, two-step greedy, b-of-c cycles, one edge
  every c, threshold.
- Runs: 3 seeds × 3 000 blocks. 120 random periodic patterns are selected on 1 500 blocks, and
  the best is re-run on 3 fresh seeds.
- Every candidate faces every family.

**Hoppers:** four configurations (on/off thresholds and hash multiple), 3 seeds × 20 000 blocks
each.
- **Fair share** is the hopper's share of the hashes spent: per block, `D` hashes on average,
  and the hopper spends the fraction `big/(1+big)` of them while it is on.
- **Reported:** the largest |share − fair| in points.

**Other measurements:**
- Bias: 4 seeds × 50 000 blocks.
- Stochastic medians: 101 seeds.
- Genesis-fork rewrite (informational): q = 0.2, chain age 720, 300 trials.
- The criteria in the table:
  - **10× follow:** the slower of the deterministic run and the stochastic median;
  - **start-up from 0.5×D0 and the 2 h genesis gap:** the stochastic median.

## Candidates (all exact integer arithmetic)

The notation throughout: `T` = 120, `n` = the window length in use, and `L` = Σ i·st_i (the
weighted solve-time sum).

**References:**
- the current LWMA-60, calling `blacksilk_consensus::difficulty::next_difficulty` itself;
- LWMA-60 plus the 2% rise cap (the previous recommendation);
- ASERT with a 2 h half-life.

**(a) Symmetric per-block solve-time clamp.**
- Each solve time is clamped to `[T/k, 6T]` with the counted clock `prev` following the stamps,
  for k in {2, 3, 4, 6}.
- The current lower bound is `prev + 1` (`consensus/src/difficulty.rs`: `this = if ts > prev
  { ts } else { prev + 1 }`, so every counted solve time is at least 1 s).

**(a') The same lower bound as a virtual clock.**
- `this = max(ts_i, prev + step)`, `st = min(this − prev, 6T)`, `prev = this`.
- This is the current rule with the monotone step 1 replaced by `step`.
- Values: step in {T/3, 2T/5, T/2, 3T/5, 2T/3} at N = 60, and step T/2 at N = 75 and N = 90.

**(b) Matched rise and fall caps.**
- `parent·den/(den+num) ≤ next ≤ parent + max(1, parent·num/den)`.
- Rates: 2%, 2.5% and 3%.

**(c) Rise bounds applied to the weighted sum instead of the output:**
- **(c1)** a tightened absolute floor `L ≥ n²T/(2c)`, which bounds `next ≤ c·avg_D·(n+1)/n`.
  The current floor is c = 10. Values: c in {1.5, 1.75, 2, 2.5} at N = 60, and c = 2 at N = 75
  and N = 90.
- **(c2)** a parent-relative cap on the weighted sum:
  - `L ≥ L_eff(parent)·100/102`;
  - `L_eff(parent) = sumD_p·T·(n_p+1)/(2·D_parent)`, derived from the parent's stored
    difficulty.

**(d) ASERT and a hybrid:**
- ASERT with half-lives of 1 h and 45 min: aserti3-2d in difficulty form, anchored at the
  branch start, with the same radix-2^16 cubic.
- A hybrid: LWMA-60 kept inside a relative-ASERT band around the parent (H = 1 h). With `st`
  the parent's solve time, the band is `[parent, parent·2^((T−st)/H)]` after a fast block and
  `[parent·2^((T−st)/H), parent]` after a slow one.

**(e) Other literature-motivated rules:**
- LWMA-60 with signed solve times clamped to `[−6T, 6T]`: zawy #13 and #30 recommend allowing
  negative solve times for symmetry. Tested with the c = 2 floor.
- The c = 2 floor plus a loose 5% output rise cap, aimed at the genesis-era ramp (03-F2).

## Result

**Exactly one candidate meets every criterion on both seeds:** (a') LWMA-75 with virtual clock
step T/2.

| Criterion | Main seed | Fresh seed |
|---|---|---|
| Race excess, q = 0.4 (≤ +5%) | +3.8% | +4.0% |
| Race excess, q ≤ 0.35 (≤ +1%) | +0.15% | +0.20% |
| Best 100%-miner emission gain (≤ +1%) | +0.69% | +0.57% |
| Hopper vs fair share (±3 points) | +2.4 points | +2.5 points |
| Bias (±1.5%) | +1.01% | +1.01% |
| 10× up, deterministic / median (≤ 150) | 113 / 113 | 113 / 113 |
| 10× down, deterministic / median (≤ 150) | 130 / 133 | 130 / 133 |
| From 0.5×D0, median (≤ 60) | 2 | 2 |
| Genesis-gap recovery, median (≤ 120) | 12 | 12 |
| Genesis-fork rewrite (informational) | 0/300 (current rule: 22/300) | not run |

The full comparison of all 29 candidates against every criterion is in the generated tables
below. The findings per family follow.

- **(a) The literal symmetric per-block clamp is exploitable, and it is rejected.**
  - A lower clamp on each solve time creates counted time from nothing. A 100% miner stamps
    blocks at `prev + 1` (each counts T/k) while real time accumulates, then spends the
    accumulated real time on one forward stamp.
  - Emission gains: +57% at k = 2 and +14% at k = 6 (threshold and b-of-c families).
  - The clamp also biases honest block times: −11% at k = 2.
- **(a') The virtual clock removes that flaw.**
  - The counted clock never falls behind `prev + step`, so a compressed block borrows counted
    time that later stamps must repay. Counted time over a window is the real stamp span plus
    at most one FTL shift, as in the current rule.
  - Emission gains stay at the level of the current rule (+0.57% to +0.88%, against +0.68%).
  - The rise bound becomes exact and simple: `next ≤ (T/step)·avg_D`, which is 2× the window
    average at step T/2. The derivation is in the rule section.
  - Under sustained compression the difficulty compounds at about 2.6% per block at N = 60 and
    about 2.1% per block at N = 75 (roots of `r − 1 = (2/N)(1 − r^−N)`). It is not 17% as on
    the current rule.
  - The race excess at q = 0.4 (main seed, then fresh seed):

    | Rule | Excess |
    |---|---|
    | step T/3 | +11.3% |
    | step 2T/5 | +7.6% |
    | step T/2, N = 60 | +5.1% / +5.1% |
    | step T/2, N = 75 | +3.8% / +4.0% |
    | step T/2, N = 90 | +2.8% |

  - Larger steps at N = 60 (3T/5, 2T/3) cut the race further, but they fail the hopper
    criterion (+3.5 and +3.8 points). The slower rise gives a hopper longer cheap phases.
    2T/3 also fails 10× up (158 blocks).
  - N = 90 fails the 10×-down criterion (156 blocks).
- **(b) Matched rise and fall caps are rejected.**
  - They remove most of the lowering gain (+3.9% for a rise-only 2% cap becomes +1.5%), but
    not below +1%.
  - They bias block times by +2.3% to +2.6%.
  - They are a stall hazard: after a 100× hash-rate drop, a 2% fall cap needs 260 blocks and
    169 h. The current rule needs 50 h.
- **(c1) A tightened floor is symmetric** (lowering gain +0.68%, the same as the current rule),
  but it trades race against 10× up with no passing point:

  | c | Race q = 0.4 | 10× up (det / median) |
  |---|---|---|
  | 1.5 | +4.1% (fresh seed +3.9%) | 153 / 139 (fail) |
  | 1.75 | +5.4% (fail) | 121 / 104 |
  | 2 | +7.8% (fail) | 107 / 90 |
  | 2.5 | +11.4% (fail) | 93 / 81 |

  - The c = 1.5 floor is the runner-up: a one-constant change, `/20` → `/3`, which fails only
    10× up and only in the deterministic run.
  - It is worse than the virtual clock under late compression. The floor binds only on the
    whole weighted sum, so a few compressed blocks in the heaviest positions still move the
    difficulty. Under the virtual clock every compressed block counts T/2.
- **(c2) The parent-relative weighted-sum cap is ineffective and asymmetric:** race +11.8%,
  emission +4.0%.
  - The window's difficulty sum itself compounds, so bounding `L` relative to the parent does
    not bound the output.
  - It remains path-dependent, like the output cap.
- **(d) ASERT is rejected at both half-lives:**
  - **1 h** fails 10× up (191 blocks), start-up (86), gap (132) and the race (+5.1%).
  - **45 min** fails the race (+7.9%).
  - This is structural. ASERT's per-block rise under compression is `2^(T/H)`, and its approach
    to a 10× step needs about `4.4·H/(T·ln 2)` blocks, so a 10× rise within 150 blocks needs
    H ≤ about 47 min. The harness already measures +7.9% race excess at H = 45 min and +5.1% at
    H = 1 h, so no half-life meets both criteria.
  - The hybrid is rejected: +7.4% emission (it is still a path-dependent clamp) and 190 blocks
    for 10× up.
  - **No literature support was found for LWMA/ASERT hybrids.** zawy12 issue #61 is sceptical
    of merging them. It was simulated as a harness-only data point.
- **(e) Signed solve times are rejected.**
  - They are catastrophically exploitable here: +99% emission (patterns and threshold
    families).
  - Our reading (not analysed further): the ±6T clamps break the telescoping of signed solve
    times, and MTP allows backward stamps far below the tip.
  - zawy #13's symmetry argument therefore does not carry over to this rule set.
  - The floor plus a 5% cap fails the race (+6.5%).
- **The previous recommendation (2% output rise cap) is confirmed to fail emission:** +3.9%.
  The adaptive attackers do not raise its race excess (+4.0%).
- **Adaptive attackers.**
  - Across all rules and q, no late-compress or ratio policy beat full compression in the
    confirmation pass by more than noise. Against the current rule, late(0.5) was 0.292 against
    0.341 compressed.
  - This is consistent with the mechanism: the attacker lives on variance, and full compression
    maximizes it. Forward stamping is never useful in the race, because expected work equals
    hashes whatever the difficulty.
  - The q = 0.4 excess figures are therefore the compressed-attacker figures.
- **The literature agrees with the root cause.**
  - zawy12 issue #30 (Timestamp Attacks): "The only necessary condition to increase emission
    rate is a limit on how high the difficulty can rise in a block". It also states that
    Digishield's asymmetric 16%/32% limits let a majority miner gain about 50% more blocks.
  - zawy12 issue #13: limits must be symmetric so the difficulty "comes back" when honest
    stamps resume.
  - The virtual clock bounds the rise without a path-dependent limit: the bound is a function
    of the current window only, so a dip caused by a forward stamp is undone by the same
    window arithmetic that caused it.
  - BCH aserti3-2d (upgradespecs.bitcoincashnode.org, 2020-11-15-asert): the ASERT candidates
    and the hybrid use its fixed-point form (radix 2^16, truncating exponent division, cubic
    `195766423245049·x + 971821376·x² + 5127·x³`). BCH uses a 2-day half-life, far too slow
    for this network.
  - All literature text was treated as data (untrusted-input rule), and no instruction was
    found in it.

## Recommendation: LWMA-75 with virtual clock step T/2

**The rule.** This is the pseudocode for `consensus/src/difficulty.rs`. Only two things change:
- the window parameter, `ChainParams::difficulty_window`, goes from 60 to 75 on all networks;
- the monotone step `prev + 1` becomes `prev + max(1, T/2)`.

```text
next_difficulty(timestamps, cumulative, T, N = 75, initial) -> u64
  // timestamps / cumulative: the last up to N+1 ancestors, oldest first, ending
  // with the parent; cumulative[i] includes block i. All arithmetic in u128.
  take = min(len, N + 1); ts = last take timestamps; cd = last take cumulatives
  n = take - 1
  if n == 0: return initial
  step = max(1, T / 2)                      // NEW. Integer division, truncating.
                                            // T = 120 -> 60; regtest T = 10 -> 5.
  prev = ts[0]; weighted = 0; sum_d = 0
  for i in 1..=n:
      this = max(ts[i], prev + step)        // CHANGED: was max(ts[i], prev + 1)
      st   = min(this - prev, 6 * T)        // unchanged 6T cap
      prev = this                           // unchanged: prev follows the capped-from
                                            // value `this`, not prev + st
      weighted += i * st
      sum_d    += cd[i] - cd[i-1]
  weighted = max(weighted, n*n*T/20, 1)     // unchanged; provably inactive now
                                            // (weighted >= step*n(n+1)/2 > n*n*T/20)
  next = (sum_d * T * (n + 1)) / (2 * weighted)   // truncating division
  return clamp(next, 1, u64::MAX)
```

**Rounding and bounds** (exact, for the property tests):
- Every division truncates, and the result is clamped to `[1, u64::MAX]`.
- **Rise.** `weighted ≥ step·n(n+1)/2`, so `next ≤ floor(sum_d·T/(step·n))`. With T even, that
  is `next ≤ floor(2·avg_D)`.
  - In the genesis window this caps the ramp at `D_{k+1} ≤ 2·mean(D_1..D_k)`. The ramp is
    therefore at most linear in k (≤ (k+1)·D_1), not 5–20× per block (03-F2).
- **Fall.** Unchanged: `next ≥ floor(avg_D/6)` in steady state.
- **Low difficulty.** At `D = 1` with the fastest possible stamps, `next = 2`: `sum_d = n` and
  `weighted = step·n(n+1)/2` give exactly 2. The rule never freezes at 1, and the regtest
  "1-second blocks raise the difficulty" behaviour survives (1 → 2). Truncation costs less
  than one unit per block, a downward bias below 1% only when D < 100.
- **Overflow.** `prev ≤ ts_max + N·T/2`. `sum_d·T·(n+1) < 2^64·120·76 < 2^78`. No new overflow
  cases.

**Parameters that stay as they are:**
- FTL 360 s, which is now below `N·T/20 = 450`, so zawy's FTL guidance still holds;
- MTP-11;
- the 6T cap;
- work = declared difficulty;
- the no-99/100 choice.

**Implementation notes for CB-A:**
- The fingerprint's DAA entry should name the rule, for example
  `lwma1-n75-step-t/2-cap6t-floor20`.
- The live and batch paths (`required_difficulty`, `overlay_context`) both call
  `next_difficulty`. The only caller-visible change is `difficulty_window + 1 = 76` entries.
- **Vectors:**
  - every LWMA golden vector changes;
  - new vectors must come from an independent script (decision log);
  - suggested vectors: the fully compressed window (exactly 2× the average), the D = 1 → 2
    step, `[0, 7200]/[100, 200] → 16` (unchanged), a window that straddles n = 75, and the
    step boundary `ts_i = prev + step ± 1`.
- **Tests that need re-derivation:**
  - `genesis_to_launch_gap_is_absorbed_by_lwma`: from 16, recovery at D0 = 100 now takes 12
    blocks (deterministic), against 29 before;
  - any p2p or chain test that relies on the size of the difficulty jump from 1-second blocks.

**Why this rule:**
1. **It is the only candidate that meets all eight criteria,** on two independent seeds.
2. **It treats the cause.** F1 exists because a compressed stamp counts 1 s, and the current
   floor lets the difficulty reach 10× the window average and compound about 17% per block.
   The virtual clock counts every block as at least T/2, which bounds the output at 2× the
   window average.
3. **It adds no path-dependent limit,** so it does not reopen the emission asymmetry that sank
   the rise cap (zawy #30). The difficulty remains a function of the window only, as today.
4. **It is the smallest change to reviewed code:** one constant, `1` → `max(1, T/2)`, and one
   parameter, 60 → 75. It needs no new state, no new header field and no exponential
   arithmetic.
5. **It fixes 03-F2 as a side effect:** the genesis-fork rewrite drops from 22/300 to 0/300,
   and the genesis-era ramp becomes at most linear.
6. **It keeps start-up and gap behaviour at the current rule's level:** 0.5×D0 in 2 blocks,
   and gap recovery at median 12.

**Why N = 75 and not the decision log's default N = 60:**
- At N = 60 the same step gives +5.1% race excess on both seeds. That is consistently just over
  the +5% criterion, and it is the rule's only failure.
- N = 75 buys margin: +3.8% and +4.0%, about 3 standard errors below the line.
- The cost is liveness after a hash-rate drop:

  | | 10× down | 100× drop (det) |
  |---|---|---|
  | N = 60 | 104 blocks / 7.7 h | 50 h |
  | N = 75 | 130 blocks / 9.6 h | 62 h |

- zawy #3 recommends N = 90 for T = 120, so 75 lies inside the published range.
- **If the coordinator prefers to keep N = 60,** the relaxed option is LWMA-60 with step T/2. It
  relaxes the q = 0.4 race criterion by 0.1 point (+5.1%), and everything else passes with the
  same margins or better (10× down 104).

**The residual risks, stated honestly:**
- **The q = 0.4 race is not solved, only bounded.**
  - A 40% miner still overturns 100 confirmations about 4% of the time (honest-stamp baseline
    0.3–0.4%).
  - At q ≤ 0.35 the excess is ≤ 0.2%.
  - The coordinator's criteria assign the q ≈ 0.4 residual to 02's park-on-deep-reorg.
- **The hopper margin is small.** The excess is +2.4 to +2.5 points against the ±3 limit
  (current rule +1.2). The hopper model is a threshold hopper, and cleverer hoppers were not
  searched.
- **The emission-gain evidence comes from a finite search.** It covers dossier 04's families,
  greedy lookahead and random patterns; optimal control over the window state was not searched.
  It is evidence, not proof.
- **Bias is +1.0%,** with no 99/100 factor. That is inside the ±1.5% criterion, and the
  correction is still the separate P3 question.
- **Novelty.**
  - Monotone timestamps with step 1 are zawy's reference mechanism.
  - A step of T/2 is our parametrization; no prior art for a step above 1 was found.
  - Red team 50 should attack it specifically, for example strategies that align stamps with
    the virtual clock, and window-boundary effects when the window's first stamp lags the
    virtual clock.
- **Model limits.**
  - There is no network latency, no orphans and no clock skew.
  - Races use z = 100 and a 12z + 240 block horizon.
  - A block whose lowest valid stamp is past the FTL is held until the clock allows it. The
    held-back rule was added to the lowering scenario in this change; it had previously
    panicked under the per-block-clamp candidates.
- **Selection bias.** One passing candidate out of 29 on the main seed could be a fluke. It was
  re-run on a fresh seed with 4 000-trial confirmation cells, and it passes again.

## Harness changes (tools/daa-sim only)

- **`src/family.rs`:**
  - `GenLwma`, a parametrised LWMA-1 (solve-time mode, floor, window, output caps). With
    default parameters it equals `next_difficulty` exactly. The test
    `generalised_default_equals_consensus` checks this on 350 random histories, including
    out-of-order stamps and short windows.
  - `SumCap`, `Hybrid`, `scale_pow2` (aserti3-2d fixed point), `selection_candidates()` and
    `recommended()`.
- **`src/adaptive.rs`:** the adaptive race policies (late, ratio), hoppers with a fair-share
  reference, and the drop-time helper.
- **`src/selection.rs`:** the screening and confirmation runner, the criteria checks and the
  report.
- **`src/main.rs`:** the `--selection` and `--only` flags. The original `results.md` run is
  unchanged.
- **`src/scenarios.rs`:** `lowering_run` holds a block whose lowest valid stamp is beyond the
  FTL, instead of panicking. It is inert for every rule of `results.md`, which never reached
  that state.
- **`tests/selection.rs`:** pins the recommended rule:
  - integer vectors;
  - exact deterministic follow metrics: 10× up 113, 10× down 130, 0.5×D0 2, gap 11;
  - the race at q = 0.4 over 2 000 trials, with the worst of compressed, late(1.0) and
    ratio(0.1) at most +6.5 points over honest;
  - no fixed lowering family above +1%;
  - bias within ±1.5%;
  - every hopper within ±3 points.

---

Generated tables, main run (unedited output):

# Difficulty-rule selection study (generated)

Generated by `cargo run --release -p blacksilk-daa-sim -- --selection` (full mode, 1306 s on 4 threads).

## Configuration

- Base seed `0x5e1ec7ed`; every job derives its seed from the base seed and its scenario coordinates, not from the rule, so all rules and policies run on common random numbers. 4 threads.
- Race: z = 100, q in [0.3, 0.35, 0.4]. Screening: 1000 trials per (rule, q, policy) on seed set A over the policies compressed + late(0.5), late(0.8), late(1), ratio(0.1), ratio(0.3), ratio(0.6). Confirmation: 4000 trials each of honest, compressed and the screened-best adaptive policy on the disjoint seed set B. Excess = max(compressed, best adaptive) - honest, all on B.
- Lowering (100% miner): dossier 04's fixed families on 3 seeds x 3000 blocks, 120 random patterns selected on 1500 blocks and the best re-run on 3 fresh seeds. Emission gain = blocks/h over honest stamping on the same draws.
- Hopper: configurations (on < x DEQ, off > y DEQ, hash multiple) [(1.2, 2.0, 10.0), (1.05, 1.5, 10.0), (1.1, 1.3, 3.0), (1.0, 1.2, 1.0)], 3 seeds x 20000 blocks each; reported: the largest |share - fair share| in points, where fair share = the hopper's share of hashes spent.
- Bias: 4 seeds x 50000 blocks. Medians: 101 seeds. Follow criteria use the slower of the deterministic run and the stochastic median; 0.5xD0 and the gap use the stochastic median. Genesis fork (informational): q = 0.2, age 720, compressed, 300 trials.

## Every candidate against every criterion

| # | Rule | Race q=0.4 (<= +5%) | Race q<=0.35 (<= +1%) | Emission gain (<= +1%) | Hopper vs fair (+-3 pts) | Bias (+-1.5%) | 10x up (<= 150) | 10x down (<= 150) | 0.5xD0 median (<= 60) | Gap median (<= 120) | Fails |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | LWMA-60 (current) | **FAIL** +33.6% | **FAIL** +8.75% | pass +0.68% | pass +1.2 | pass +1.33% | pass 92/81 | pass 104/104 | pass 7 | pass 10 | 2 |
| 2 | LWMA-60 + rise <= 2% | pass +4.0% | pass +0.18% | **FAIL** +3.91% | pass +1.3 | pass +0.85% | pass 137/123 | pass 104/104 | pass 43 | pass 96 | 1 |
| 3 | ASERT half-life 2 h | pass +1.5% | pass +0.15% | pass +0.10% | pass -0.7 | pass -0.00% | **FAIL** 381/357 | **FAIL** 198/175 | **FAIL** 176 | **FAIL** 177 | 4 |
| 4 | (a) LWMA-60, st in [T/2, 6T] | **FAIL** +5.5% | pass +0.20% | **FAIL** +57.32% | pass +1.2 | **FAIL** -11.01% | **FAIL** 122/173 | pass 104/98 | pass 2 | pass 58 | 4 |
| 5 | (a) LWMA-60, st in [T/3, 6T] | **FAIL** +9.8% | pass +0.47% | **FAIL** +32.43% | pass +1.2 | **FAIL** -4.13% | pass 101/115 | pass 104/101 | pass 7 | pass 16 | 3 |
| 6 | (a) LWMA-60, st in [T/4, 6T] | **FAIL** +13.7% | pass +0.95% | **FAIL** +22.69% | pass +1.2 | **FAIL** -1.76% | pass 96/98 | pass 104/103 | pass 6 | pass 13 | 3 |
| 7 | (a) LWMA-60, st in [T/6, 6T] | **FAIL** +20.3% | **FAIL** +2.17% | **FAIL** +14.33% | pass +1.2 | pass -0.06% | pass 93/90 | pass 104/103 | pass 6 | pass 11 | 3 |
| 8 | (a') LWMA-60, virtual clock step T/3 (40 s at T = 120) | **FAIL** +11.3% | pass +0.68% | pass +0.79% | pass +1.6 | pass +1.29% | pass 58/58 | pass 104/104 | pass 7 | pass 10 | 1 |
| 9 | (a') LWMA-60, virtual clock step 2T/5 (48 s at T = 120) | **FAIL** +7.6% | pass +0.30% | pass +0.83% | pass +2.1 | pass +1.27% | pass 69/69 | pass 104/104 | pass 6 | pass 11 | 1 |
| 10 | (a') LWMA-60, virtual clock step T/2 (60 s at T = 120) | **FAIL** +5.1% | pass +0.22% | pass +0.88% | pass +2.8 | pass +1.21% | pass 91/91 | pass 104/104 | pass 2 | pass 12 | 1 |
| 11 | (a') LWMA-60, virtual clock step 3T/5 (72 s at T = 120) | pass +3.6% | pass +0.07% | pass +0.86% | **FAIL** +3.5 | pass +1.11% | pass 125/125 | pass 104/104 | pass 9 | pass 18 | 1 |
| 12 | (a') LWMA-60, virtual clock step 2T/3 (80 s at T = 120) | pass +2.6% | pass +0.07% | pass +0.87% | **FAIL** +3.8 | pass +0.98% | **FAIL** 158/158 | pass 104/104 | pass 3 | pass 25 | 2 |
| 13 | (a') LWMA-75, virtual clock step T/2 [RECOMMENDED] | pass +3.8% | pass +0.15% | pass +0.69% | pass +2.4 | pass +1.01% | pass 113/113 | pass 130/133 | pass 2 | pass 12 | 0 |
| 14 | (a') LWMA-90, virtual clock step T/2 | pass +2.8% | pass +0.05% | pass +0.57% | pass +2.1 | pass +0.88% | pass 135/135 | **FAIL** 156/159 | pass 2 | pass 12 | 1 |
| 15 | (b) LWMA-60, rise and fall <= 2% | pass +4.1% | pass +0.12% | **FAIL** +1.52% | pass +2.2 | **FAIL** +2.61% | pass 137/123 | pass 144/142 | pass 39 | pass 18 | 2 |
| 16 | (b) LWMA-60, rise and fall <= 2.5% | **FAIL** +5.3% | pass +0.22% | **FAIL** +1.31% | pass +1.6 | **FAIL** +2.47% | pass 119/104 | pass 125/128 | pass 31 | pass 15 | 3 |
| 17 | (b) LWMA-60, rise and fall <= 3% | **FAIL** +6.4% | pass +0.53% | **FAIL** +1.16% | pass +1.3 | **FAIL** +2.29% | pass 108/97 | pass 114/117 | pass 25 | pass 12 | 3 |
| 18 | (c) LWMA-60, floor n^2 T/(2c), c = 1.5 | pass +4.1% | pass +0.10% | pass +0.68% | pass +1.2 | pass +1.33% | **FAIL** 153/139 | pass 104/104 | pass 7 | pass 11 | 1 |
| 19 | (c) LWMA-60, floor n^2 T/(2c), c = 1.75 | **FAIL** +5.4% | pass +0.33% | pass +0.68% | pass +1.2 | pass +1.33% | pass 121/104 | pass 104/104 | pass 7 | pass 10 | 1 |
| 20 | (c) LWMA-60, floor n^2 T/(2c), c = 2 | **FAIL** +7.8% | pass +0.50% | pass +0.68% | pass +1.2 | pass +1.33% | pass 107/90 | pass 104/104 | pass 7 | pass 10 | 1 |
| 21 | (c) LWMA-60, floor n^2 T/(2c), c = 2.5 | **FAIL** +11.4% | pass +0.97% | pass +0.68% | pass +1.2 | pass +1.33% | pass 93/81 | pass 104/104 | pass 6 | pass 10 | 1 |
| 22 | (c) LWMA-75, floor n^2 T/(2c), c = 2 | **FAIL** +5.2% | pass +0.27% | pass +0.60% | pass +1.0 | pass +1.11% | pass 133/115 | pass 130/133 | pass 7 | pass 10 | 1 |
| 23 | (c) LWMA-90, floor n^2 T/(2c), c = 2 | pass +4.7% | pass +0.20% | pass +0.55% | pass +0.8 | pass +0.97% | **FAIL** 160/136 | **FAIL** 156/158 | pass 7 | pass 10 | 2 |
| 24 | LWMA-60 + weighted-sum rise cap 2% | **FAIL** +11.8% | pass +0.68% | **FAIL** +4.01% | pass +1.6 | pass +0.83% | pass 101/88 | pass 104/104 | pass 7 | pass 10 | 2 |
| 25 | ASERT half-life 1 h | **FAIL** +5.1% | pass +0.38% | pass +0.10% | pass +0.9 | pass -0.00% | **FAIL** 191/179 | pass 98/78 | **FAIL** 86 | **FAIL** 132 | 4 |
| 26 | ASERT half-life 0.75 h | **FAIL** +7.9% | pass +0.55% | pass +0.10% | pass +1.2 | pass -0.00% | pass 143/134 | pass 74/58 | pass 60 | pass 116 | 1 |
| 27 | Hybrid LWMA-60 in relative-ASERT band (H = 1 h) | **FAIL** +5.2% | pass +0.15% | **FAIL** +7.44% | pass +1.3 | pass +0.62% | **FAIL** 190/153 | pass 116/106 | pass 58 | pass 9 | 3 |
| 28 | (e) LWMA-60, signed st in [-6T, 6T], floor c = 2 | **FAIL** +8.5% | pass +0.70% | **FAIL** +99.21% | pass +1.2 | pass +1.33% | pass 107/90 | pass 104/104 | pass 7 | pass 10 | 2 |
| 29 | (e) LWMA-60, floor c = 2, + rise <= 5% | **FAIL** +6.5% | pass +0.50% | pass +0.68% | pass +1.2 | pass +1.33% | pass 107/90 | pass 104/104 | pass 20 | pass 44 | 1 |

Follow cells: deterministic / median blocks. All rules are exact integer arithmetic (criterion 8); see the rule definitions.

## Race detail (z = 100, confirmation pass, 4000 trials per cell)

Cells: honest / compressed / best adaptive (policy) -> excess. Standard error of a difference near p = 0.05: about 0.007.

| Rule | q = 0.3 | q = 0.35 | q = 0.4 |
|---|---|---|---|
| LWMA-60 (current) | 0.000 / 0.008 / 0.006 (late(0.5)) -> +0.8% | 0.000 / 0.087 / 0.068 (late(0.5)) -> +8.8% | 0.005 / 0.341 / 0.296 (late(0.5)) -> +33.6% |
| LWMA-60 + rise <= 2% | 0.000 / 0.000 / 0.000 (ratio(0.6)) -> +0.0% | 0.000 / 0.002 / 0.001 (ratio(0.1)) -> +0.2% | 0.003 / 0.043 / 0.042 (ratio(0.1)) -> +4.0% |
| ASERT half-life 2 h | 0.000 / 0.000 / 0.000 (ratio(0.6)) -> +0.0% | 0.000 / 0.002 / 0.000 (ratio(0.6)) -> +0.1% | 0.004 / 0.019 / 0.017 (ratio(0.1)) -> +1.5% |
| (a) LWMA-60, st in [T/2, 6T] | 0.000 / 0.000 / 0.000 (ratio(0.6)) -> +0.0% | 0.000 / 0.002 / 0.001 (ratio(0.1)) -> +0.2% | 0.004 / 0.059 / 0.044 (ratio(0.1)) -> +5.5% |
| (a) LWMA-60, st in [T/3, 6T] | 0.000 / 0.000 / 0.000 (ratio(0.6)) -> +0.0% | 0.000 / 0.005 / 0.000 (ratio(0.6)) -> +0.5% | 0.004 / 0.102 / 0.053 (ratio(0.1)) -> +9.8% |
| (a) LWMA-60, st in [T/4, 6T] | 0.000 / 0.000 / 0.000 (ratio(0.6)) -> +0.0% | 0.000 / 0.009 / 0.003 (ratio(0.1)) -> +0.9% | 0.006 / 0.142 / 0.090 (late(0.5)) -> +13.7% |
| (a) LWMA-60, st in [T/6, 6T] | 0.000 / 0.002 / 0.000 (late(0.5)) -> +0.2% | 0.000 / 0.022 / 0.011 (late(0.5)) -> +2.2% | 0.006 / 0.209 / 0.166 (late(0.5)) -> +20.3% |
| (a') LWMA-60, virtual clock step T/3 (40 s at T = 120) | 0.000 / 0.000 / 0.000 (ratio(0.6)) -> +0.0% | 0.000 / 0.007 / 0.003 (ratio(0.1)) -> +0.7% | 0.003 / 0.116 / 0.060 (ratio(0.1)) -> +11.3% |
| (a') LWMA-60, virtual clock step 2T/5 (48 s at T = 120) | 0.000 / 0.000 / 0.000 (ratio(0.6)) -> +0.0% | 0.000 / 0.003 / 0.003 (ratio(0.1)) -> +0.3% | 0.004 / 0.081 / 0.060 (ratio(0.1)) -> +7.6% |
| (a') LWMA-60, virtual clock step T/2 (60 s at T = 120) | 0.000 / 0.000 / 0.000 (ratio(0.6)) -> +0.0% | 0.000 / 0.002 / 0.002 (ratio(0.1)) -> +0.2% | 0.003 / 0.054 / 0.050 (ratio(0.1)) -> +5.1% |
| (a') LWMA-60, virtual clock step 3T/5 (72 s at T = 120) | 0.000 / 0.000 / 0.000 (ratio(0.6)) -> +0.0% | 0.000 / 0.001 / 0.000 (ratio(0.6)) -> +0.1% | 0.004 / 0.040 / 0.038 (ratio(0.1)) -> +3.6% |
| (a') LWMA-60, virtual clock step 2T/3 (80 s at T = 120) | 0.000 / 0.000 / 0.000 (ratio(0.6)) -> +0.0% | 0.000 / 0.001 / 0.000 (ratio(0.1)) -> +0.1% | 0.004 / 0.028 / 0.030 (ratio(0.1)) -> +2.6% |
| (a') LWMA-75, virtual clock step T/2 [RECOMMENDED] | 0.000 / 0.000 / 0.000 (ratio(0.6)) -> +0.0% | 0.000 / 0.002 / 0.001 (ratio(0.1)) -> +0.1% | 0.003 / 0.041 / 0.032 (ratio(0.1)) -> +3.8% |
| (a') LWMA-90, virtual clock step T/2 | 0.000 / 0.000 / 0.000 (ratio(0.6)) -> +0.0% | 0.000 / 0.001 / 0.000 (ratio(0.3)) -> +0.1% | 0.004 / 0.032 / 0.027 (ratio(0.1)) -> +2.8% |
| (b) LWMA-60, rise and fall <= 2% | 0.000 / 0.000 / 0.000 (ratio(0.6)) -> +0.0% | 0.000 / 0.001 / 0.000 (ratio(0.6)) -> +0.1% | 0.005 / 0.046 / 0.043 (ratio(0.1)) -> +4.1% |
| (b) LWMA-60, rise and fall <= 2.5% | 0.000 / 0.000 / 0.000 (ratio(0.6)) -> +0.0% | 0.000 / 0.002 / 0.002 (ratio(0.1)) -> +0.2% | 0.005 / 0.058 / 0.051 (ratio(0.1)) -> +5.3% |
| (b) LWMA-60, rise and fall <= 3% | 0.000 / 0.000 / 0.000 (ratio(0.6)) -> +0.0% | 0.000 / 0.005 / 0.003 (ratio(0.1)) -> +0.5% | 0.006 / 0.070 / 0.063 (ratio(0.1)) -> +6.4% |
| (c) LWMA-60, floor n^2 T/(2c), c = 1.5 | 0.000 / 0.000 / 0.000 (ratio(0.6)) -> +0.0% | 0.000 / 0.001 / 0.001 (ratio(0.3)) -> +0.1% | 0.005 / 0.046 / 0.044 (ratio(0.1)) -> +4.1% |
| (c) LWMA-60, floor n^2 T/(2c), c = 1.75 | 0.000 / 0.000 / 0.000 (ratio(0.6)) -> +0.0% | 0.000 / 0.002 / 0.003 (ratio(0.1)) -> +0.3% | 0.005 / 0.059 / 0.058 (ratio(0.1)) -> +5.4% |
| (c) LWMA-60, floor n^2 T/(2c), c = 2 | 0.000 / 0.001 / 0.000 (ratio(0.6)) -> +0.1% | 0.000 / 0.005 / 0.004 (ratio(0.1)) -> +0.5% | 0.005 / 0.083 / 0.062 (ratio(0.1)) -> +7.8% |
| (c) LWMA-60, floor n^2 T/(2c), c = 2.5 | 0.000 / 0.001 / 0.000 (ratio(0.6)) -> +0.1% | 0.000 / 0.010 / 0.003 (ratio(0.1)) -> +1.0% | 0.005 / 0.119 / 0.067 (ratio(0.1)) -> +11.4% |
| (c) LWMA-75, floor n^2 T/(2c), c = 2 | 0.000 / 0.000 / 0.000 (ratio(0.1)) -> +0.0% | 0.000 / 0.003 / 0.002 (ratio(0.1)) -> +0.3% | 0.005 / 0.058 / 0.047 (ratio(0.1)) -> +5.2% |
| (c) LWMA-90, floor n^2 T/(2c), c = 2 | 0.000 / 0.000 / 0.000 (ratio(0.6)) -> +0.0% | 0.000 / 0.002 / 0.000 (ratio(0.6)) -> +0.2% | 0.003 / 0.050 / 0.041 (ratio(0.1)) -> +4.7% |
| LWMA-60 + weighted-sum rise cap 2% | 0.000 / 0.000 / 0.000 (ratio(0.6)) -> +0.0% | 0.000 / 0.007 / 0.003 (late(1)) -> +0.7% | 0.003 / 0.120 / 0.064 (late(1)) -> +11.8% |
| ASERT half-life 1 h | 0.000 / 0.000 / 0.000 (ratio(0.6)) -> +0.0% | 0.000 / 0.004 / 0.001 (ratio(0.1)) -> +0.4% | 0.005 / 0.057 / 0.032 (ratio(0.1)) -> +5.1% |
| ASERT half-life 0.75 h | 0.000 / 0.000 / 0.000 (ratio(0.6)) -> +0.0% | 0.000 / 0.005 / 0.001 (ratio(0.6)) -> +0.5% | 0.005 / 0.084 / 0.044 (ratio(0.1)) -> +7.9% |
| Hybrid LWMA-60 in relative-ASERT band (H = 1 h) | 0.000 / 0.000 / 0.000 (ratio(0.6)) -> +0.0% | 0.000 / 0.001 / 0.002 (ratio(0.1)) -> +0.1% | 0.005 / 0.057 / 0.036 (ratio(0.1)) -> +5.2% |
| (e) LWMA-60, signed st in [-6T, 6T], floor c = 2 | 0.000 / 0.000 / 0.000 (ratio(0.6)) -> +0.0% | 0.000 / 0.007 / 0.003 (ratio(0.1)) -> +0.7% | 0.004 / 0.089 / 0.065 (ratio(0.1)) -> +8.5% |
| (e) LWMA-60, floor c = 2, + rise <= 5% | 0.000 / 0.000 / 0.000 (ratio(0.1)) -> +0.0% | 0.000 / 0.005 / 0.002 (ratio(0.1)) -> +0.5% | 0.005 / 0.070 / 0.063 (ratio(0.1)) -> +6.5% |

### Screening pass at q = 0.4 (seed set A, 1000 trials per policy; hits)

| Rule | compressed | late(0.5) | late(0.8) | late(1) | ratio(0.1) | ratio(0.3) | ratio(0.6) |
|---|---|---|---|---|---|---|---|
| LWMA-60 (current) | 362 | 281 | 280 | 238 | 68 | 22 | 9 |
| LWMA-60 + rise <= 2% | 43 | 13 | 6 | 8 | 46 | 25 | 7 |
| ASERT half-life 2 h | 21 | 8 | 6 | 4 | 17 | 6 | 6 |
| (a) LWMA-60, st in [T/2, 6T] | 63 | 25 | 8 | 9 | 53 | 23 | 9 |
| (a) LWMA-60, st in [T/3, 6T] | 110 | 43 | 37 | 30 | 50 | 22 | 13 |
| (a) LWMA-60, st in [T/4, 6T] | 156 | 83 | 76 | 59 | 61 | 27 | 12 |
| (a) LWMA-60, st in [T/6, 6T] | 242 | 160 | 157 | 122 | 65 | 18 | 5 |
| (a') LWMA-60, virtual clock step T/3 (40 s at T = 120) | 123 | 37 | 37 | 26 | 54 | 15 | 13 |
| (a') LWMA-60, virtual clock step 2T/5 (48 s at T = 120) | 97 | 32 | 13 | 14 | 53 | 17 | 10 |
| (a') LWMA-60, virtual clock step T/2 (60 s at T = 120) | 63 | 15 | 11 | 6 | 38 | 26 | 8 |
| (a') LWMA-60, virtual clock step 3T/5 (72 s at T = 120) | 31 | 10 | 8 | 3 | 43 | 21 | 6 |
| (a') LWMA-60, virtual clock step 2T/3 (80 s at T = 120) | 35 | 5 | 6 | 5 | 42 | 23 | 12 |
| (a') LWMA-75, virtual clock step T/2 [RECOMMENDED] | 38 | 12 | 7 | 4 | 32 | 23 | 9 |
| (a') LWMA-90, virtual clock step T/2 | 24 | 7 | 7 | 10 | 30 | 14 | 5 |
| (b) LWMA-60, rise and fall <= 2% | 59 | 11 | 2 | 9 | 41 | 25 | 6 |
| (b) LWMA-60, rise and fall <= 2.5% | 56 | 12 | 7 | 10 | 50 | 28 | 8 |
| (b) LWMA-60, rise and fall <= 3% | 76 | 25 | 15 | 11 | 51 | 16 | 8 |
| (c) LWMA-60, floor n^2 T/(2c), c = 1.5 | 35 | 6 | 8 | 7 | 42 | 26 | 9 |
| (c) LWMA-60, floor n^2 T/(2c), c = 1.75 | 63 | 14 | 5 | 7 | 58 | 22 | 9 |
| (c) LWMA-60, floor n^2 T/(2c), c = 2 | 87 | 16 | 14 | 9 | 54 | 22 | 9 |
| (c) LWMA-60, floor n^2 T/(2c), c = 2.5 | 123 | 42 | 27 | 15 | 68 | 22 | 9 |
| (c) LWMA-75, floor n^2 T/(2c), c = 2 | 52 | 18 | 10 | 7 | 49 | 18 | 10 |
| (c) LWMA-90, floor n^2 T/(2c), c = 2 | 65 | 10 | 9 | 6 | 35 | 20 | 6 |
| LWMA-60 + weighted-sum rise cap 2% | 131 | 70 | 70 | 72 | 47 | 16 | 9 |
| ASERT half-life 1 h | 55 | 14 | 11 | 10 | 32 | 14 | 10 |
| ASERT half-life 0.75 h | 93 | 22 | 15 | 11 | 41 | 33 | 9 |
| Hybrid LWMA-60 in relative-ASERT band (H = 1 h) | 65 | 12 | 6 | 6 | 40 | 18 | 9 |
| (e) LWMA-60, signed st in [-6T, 6T], floor c = 2 | 67 | 27 | 13 | 11 | 67 | 31 | 10 |
| (e) LWMA-60, floor c = 2, + rise <= 5% | 72 | 23 | 11 | 11 | 73 | 22 | 11 |

## Timestamp lowering by a 100% miner (best member per family, blocks/h gain)

| Rule | all at FTL edge | all at MTP+1 | myopic greedy | two-step greedy | b-of-c cycles | one FTL edge every c | threshold | random periodic patterns |
|---|---|---|---|---|---|---|---|---|
| LWMA-60 (current) | +0.10% (all at FTL edge) | -100.00% (all at MTP+1) | +0.28% (myopic greedy) | +0.54% (two-step greedy) | +0.08% (1-of-120 Mtp) | -0.00% (edge every 60) | +0.68% (threshold 240) | +0.34% (pattern period 6) |
| LWMA-60 + rise <= 2% | +0.10% (all at FTL edge) | -100.00% (all at MTP+1) | +0.91% (myopic greedy) | +1.25% (two-step greedy) | +0.09% (1-of-120 Mtp) | +0.96% (edge every 10) | +3.91% (threshold 720) | +1.01% (pattern period 6) |
| ASERT half-life 2 h | +0.10% (all at FTL edge) | -100.00% (all at MTP+1) | +0.10% (myopic greedy) | +0.10% (two-step greedy) | +0.10% (1-of-120 PrevPlusOne) | +0.05% (edge every 2) | +0.10% (threshold 1) | +0.05% (pattern period 2) |
| (a) LWMA-60, st in [T/2, 6T] | +0.12% (all at FTL edge) | -100.00% (all at MTP+1) | +9.40% (myopic greedy) | +24.05% (two-step greedy) | +46.09% (5-of-6 Mtp) | +37.14% (edge every 5) | +57.32% (threshold 720) | +22.58% (pattern period 3) |
| (a) LWMA-60, st in [T/3, 6T] | +0.11% (all at FTL edge) | -100.00% (all at MTP+1) | +4.30% (myopic greedy) | +11.23% (two-step greedy) | +22.78% (3-of-4 Mtp) | +20.48% (edge every 5) | +32.43% (threshold 720) | +19.18% (pattern period 3) |
| (a) LWMA-60, st in [T/4, 6T] | +0.10% (all at FTL edge) | -100.00% (all at MTP+1) | +2.61% (myopic greedy) | +6.77% (two-step greedy) | +14.92% (3-of-4 Mtp) | +14.15% (edge every 5) | +22.69% (threshold 720) | +10.73% (pattern period 2) |
| (a) LWMA-60, st in [T/6, 6T] | +0.10% (all at FTL edge) | -100.00% (all at MTP+1) | +1.35% (myopic greedy) | +3.42% (two-step greedy) | +8.53% (2-of-3 Mtp) | +9.08% (edge every 3) | +14.33% (threshold 720) | +7.39% (pattern period 2) |
| (a') LWMA-60, virtual clock step T/3 (40 s at T = 120) | +0.10% (all at FTL edge) | -100.00% (all at MTP+1) | +0.37% (myopic greedy) | +0.58% (two-step greedy) | +0.09% (1-of-120 Mtp) | +0.02% (edge every 60) | +0.79% (threshold 720) | +0.40% (pattern period 6) |
| (a') LWMA-60, virtual clock step 2T/5 (48 s at T = 120) | +0.10% (all at FTL edge) | -100.00% (all at MTP+1) | +0.45% (myopic greedy) | +0.60% (two-step greedy) | +0.09% (1-of-120 Mtp) | +0.05% (edge every 2) | +0.83% (threshold 720) | +0.41% (pattern period 6) |
| (a') LWMA-60, virtual clock step T/2 (60 s at T = 120) | +0.10% (all at FTL edge) | -100.00% (all at MTP+1) | +0.51% (myopic greedy) | +0.66% (two-step greedy) | +0.09% (1-of-120 Mtp) | +0.11% (edge every 2) | +0.88% (threshold 720) | +0.40% (pattern period 6) |
| (a') LWMA-60, virtual clock step 3T/5 (72 s at T = 120) | +0.10% (all at FTL edge) | -100.00% (all at MTP+1) | +0.65% (myopic greedy) | +0.69% (two-step greedy) | +0.09% (1-of-120 Mtp) | +0.20% (edge every 20) | +0.86% (threshold 720) | +0.39% (pattern period 6) |
| (a') LWMA-60, virtual clock step 2T/3 (80 s at T = 120) | +0.10% (all at FTL edge) | -100.00% (all at MTP+1) | +0.82% (myopic greedy) | +0.86% (two-step greedy) | +0.10% (1-of-120 Mtp) | +0.29% (edge every 20) | +0.87% (threshold 720) | +0.36% (pattern period 6) |
| (a') LWMA-75, virtual clock step T/2 [RECOMMENDED] | +0.10% (all at FTL edge) | -100.00% (all at MTP+1) | +0.39% (myopic greedy) | +0.57% (two-step greedy) | +0.09% (1-of-120 Mtp) | +0.08% (edge every 2) | +0.69% (threshold 720) | +0.32% (pattern period 6) |
| (a') LWMA-90, virtual clock step T/2 | +0.10% (all at FTL edge) | -100.00% (all at MTP+1) | +0.31% (myopic greedy) | +0.49% (two-step greedy) | +0.09% (1-of-120 Mtp) | +0.07% (edge every 2) | +0.57% (threshold 720) | +0.27% (pattern period 6) |
| (b) LWMA-60, rise and fall <= 2% | +0.11% (all at FTL edge) | -100.00% (all at MTP+1) | +1.45% (myopic greedy) | +1.45% (two-step greedy) | +0.09% (1-of-120 Mtp) | -0.04% (edge every 60) | +0.56% (threshold 60) | +1.52% (pattern period 2) |
| (b) LWMA-60, rise and fall <= 2.5% | +0.10% (all at FTL edge) | -100.00% (all at MTP+1) | +1.00% (myopic greedy) | +1.01% (two-step greedy) | +0.08% (1-of-120 Mtp) | -0.06% (edge every 60) | +0.52% (threshold 60) | +1.31% (pattern period 2) |
| (b) LWMA-60, rise and fall <= 3% | +0.10% (all at FTL edge) | -100.00% (all at MTP+1) | +0.76% (myopic greedy) | +0.76% (two-step greedy) | +0.08% (1-of-120 Mtp) | -0.08% (edge every 60) | +0.48% (threshold 1) | +1.16% (pattern period 2) |
| (c) LWMA-60, floor n^2 T/(2c), c = 1.5 | +0.10% (all at FTL edge) | -100.00% (all at MTP+1) | +0.28% (myopic greedy) | +0.54% (two-step greedy) | +0.08% (1-of-120 Mtp) | -0.00% (edge every 60) | +0.68% (threshold 240) | +0.34% (pattern period 6) |
| (c) LWMA-60, floor n^2 T/(2c), c = 1.75 | +0.10% (all at FTL edge) | -100.00% (all at MTP+1) | +0.28% (myopic greedy) | +0.54% (two-step greedy) | +0.08% (1-of-120 Mtp) | -0.00% (edge every 60) | +0.68% (threshold 240) | +0.34% (pattern period 6) |
| (c) LWMA-60, floor n^2 T/(2c), c = 2 | +0.10% (all at FTL edge) | -100.00% (all at MTP+1) | +0.28% (myopic greedy) | +0.54% (two-step greedy) | +0.08% (1-of-120 Mtp) | -0.00% (edge every 60) | +0.68% (threshold 240) | +0.34% (pattern period 6) |
| (c) LWMA-60, floor n^2 T/(2c), c = 2.5 | +0.10% (all at FTL edge) | -100.00% (all at MTP+1) | +0.28% (myopic greedy) | +0.54% (two-step greedy) | +0.08% (1-of-120 Mtp) | -0.00% (edge every 60) | +0.68% (threshold 240) | +0.34% (pattern period 6) |
| (c) LWMA-75, floor n^2 T/(2c), c = 2 | +0.10% (all at FTL edge) | -100.00% (all at MTP+1) | +0.24% (myopic greedy) | +0.52% (two-step greedy) | +0.08% (1-of-120 Mtp) | +0.01% (edge every 60) | +0.60% (threshold 240) | +0.29% (pattern period 6) |
| (c) LWMA-90, floor n^2 T/(2c), c = 2 | +0.10% (all at FTL edge) | -100.00% (all at MTP+1) | +0.24% (myopic greedy) | +0.50% (two-step greedy) | +0.08% (1-of-120 Mtp) | +0.01% (edge every 60) | +0.55% (threshold 120) | +0.25% (pattern period 6) |
| LWMA-60 + weighted-sum rise cap 2% | +0.10% (all at FTL edge) | -100.00% (all at MTP+1) | +1.02% (myopic greedy) | +1.29% (two-step greedy) | +0.09% (1-of-120 Mtp) | +0.98% (edge every 10) | +4.01% (threshold 720) | +1.03% (pattern period 6) |
| ASERT half-life 1 h | +0.10% (all at FTL edge) | -100.00% (all at MTP+1) | +0.10% (myopic greedy) | +0.10% (two-step greedy) | +0.10% (1-of-120 PrevPlusOne) | +0.05% (edge every 2) | +0.10% (threshold 1) | +0.05% (pattern period 2) |
| ASERT half-life 0.75 h | +0.10% (all at FTL edge) | -100.00% (all at MTP+1) | +0.10% (myopic greedy) | +0.10% (two-step greedy) | +0.10% (1-of-120 PrevPlusOne) | +0.05% (edge every 2) | +0.10% (threshold 1) | +0.05% (pattern period 2) |
| Hybrid LWMA-60 in relative-ASERT band (H = 1 h) | +0.10% (all at FTL edge) | -100.00% (all at MTP+1) | +0.44% (myopic greedy) | +1.04% (two-step greedy) | +0.63% (1-of-2 Mtp) | +2.25% (edge every 10) | +7.44% (threshold 720) | +2.83% (pattern period 6) |
| (e) LWMA-60, signed st in [-6T, 6T], floor c = 2 | +0.10% (all at FTL edge) | -100.00% (all at MTP+1) | +0.27% (myopic greedy) | +0.54% (two-step greedy) | +0.08% (1-of-120 PrevPlusOne) | -0.03% (edge every 60) | +52.13% (threshold 480) | +99.21% (pattern period 12) |
| (e) LWMA-60, floor c = 2, + rise <= 5% | +0.10% (all at FTL edge) | -100.00% (all at MTP+1) | +0.28% (myopic greedy) | +0.54% (two-step greedy) | +0.08% (1-of-120 Mtp) | -0.00% (edge every 60) | +0.68% (threshold 240) | +0.34% (pattern period 6) |

## Hoppers (share / fair share of blocks)

| Rule | on<1.2 off>2 x10 | on<1.05 off>1.5 x10 | on<1.1 off>1.3 x3 | on<1 off>1.2 x1 |
|---|---|---|---|---|
| LWMA-60 (current) | 0.313 / 0.309 (+0.4) | 0.205 / 0.197 (+0.8) | 0.199 / 0.187 (+1.2) | 0.120 / 0.112 (+0.9) |
| LWMA-60 + rise <= 2% | 0.367 / 0.357 (+1.0) | 0.245 / 0.233 (+1.2) | 0.208 / 0.195 (+1.3) | 0.124 / 0.115 (+0.9) |
| ASERT half-life 2 h | 0.338 / 0.345 (-0.7) | 0.195 / 0.196 (-0.2) | 0.183 / 0.179 (+0.4) | 0.099 / 0.096 (+0.3) |
| (a) LWMA-60, st in [T/2, 6T] | 0.462 / 0.459 (+0.3) | 0.359 / 0.351 (+0.8) | 0.311 / 0.300 (+1.2) | 0.212 / 0.203 (+0.8) |
| (a) LWMA-60, st in [T/3, 6T] | 0.384 / 0.380 (+0.4) | 0.277 / 0.269 (+0.8) | 0.249 / 0.236 (+1.2) | 0.159 / 0.151 (+0.9) |
| (a) LWMA-60, st in [T/4, 6T] | 0.358 / 0.354 (+0.4) | 0.249 / 0.241 (+0.8) | 0.228 / 0.216 (+1.2) | 0.143 / 0.134 (+0.9) |
| (a) LWMA-60, st in [T/6, 6T] | 0.336 / 0.332 (+0.4) | 0.227 / 0.219 (+0.9) | 0.211 / 0.199 (+1.2) | 0.130 / 0.121 (+0.9) |
| (a') LWMA-60, virtual clock step T/3 (40 s at T = 120) | 0.344 / 0.329 (+1.6) | 0.228 / 0.214 (+1.4) | 0.202 / 0.189 (+1.3) | 0.121 / 0.112 (+0.9) |
| (a') LWMA-60, virtual clock step 2T/5 (48 s at T = 120) | 0.356 / 0.336 (+2.1) | 0.238 / 0.221 (+1.7) | 0.205 / 0.191 (+1.4) | 0.122 / 0.113 (+0.9) |
| (a') LWMA-60, virtual clock step T/2 (60 s at T = 120) | 0.375 / 0.347 (+2.8) | 0.254 / 0.232 (+2.2) | 0.213 / 0.198 (+1.6) | 0.124 / 0.115 (+1.0) |
| (a') LWMA-60, virtual clock step 3T/5 (72 s at T = 120) | 0.403 / 0.368 (+3.5) | 0.283 / 0.253 (+3.0) | 0.228 / 0.209 (+1.9) | 0.130 / 0.119 (+1.1) |
| (a') LWMA-60, virtual clock step 2T/3 (80 s at T = 120) | 0.434 / 0.397 (+3.8) | 0.303 / 0.271 (+3.2) | 0.243 / 0.221 (+2.2) | 0.135 / 0.124 (+1.1) |
| (a') LWMA-75, virtual clock step T/2 [RECOMMENDED] | 0.366 / 0.342 (+2.4) | 0.250 / 0.230 (+2.0) | 0.206 / 0.193 (+1.3) | 0.116 / 0.109 (+0.8) |
| (a') LWMA-90, virtual clock step T/2 | 0.364 / 0.343 (+2.1) | 0.242 / 0.226 (+1.6) | 0.203 / 0.192 (+1.2) | 0.112 / 0.106 (+0.6) |
| (b) LWMA-60, rise and fall <= 2% | 0.334 / 0.312 (+2.2) | 0.224 / 0.209 (+1.5) | 0.186 / 0.173 (+1.4) | 0.108 / 0.099 (+0.9) |
| (b) LWMA-60, rise and fall <= 2.5% | 0.323 / 0.307 (+1.6) | 0.206 / 0.194 (+1.2) | 0.185 / 0.172 (+1.3) | 0.109 / 0.100 (+0.9) |
| (b) LWMA-60, rise and fall <= 3% | 0.312 / 0.300 (+1.2) | 0.198 / 0.188 (+1.0) | 0.186 / 0.173 (+1.3) | 0.111 / 0.102 (+0.9) |
| (c) LWMA-60, floor n^2 T/(2c), c = 1.5 | 0.314 / 0.310 (+0.4) | 0.205 / 0.197 (+0.8) | 0.199 / 0.187 (+1.2) | 0.120 / 0.112 (+0.9) |
| (c) LWMA-60, floor n^2 T/(2c), c = 1.75 | 0.313 / 0.309 (+0.4) | 0.205 / 0.197 (+0.8) | 0.199 / 0.187 (+1.2) | 0.120 / 0.112 (+0.9) |
| (c) LWMA-60, floor n^2 T/(2c), c = 2 | 0.313 / 0.309 (+0.4) | 0.205 / 0.197 (+0.8) | 0.199 / 0.187 (+1.2) | 0.120 / 0.112 (+0.9) |
| (c) LWMA-60, floor n^2 T/(2c), c = 2.5 | 0.313 / 0.309 (+0.4) | 0.205 / 0.197 (+0.8) | 0.199 / 0.187 (+1.2) | 0.120 / 0.112 (+0.9) |
| (c) LWMA-75, floor n^2 T/(2c), c = 2 | 0.312 / 0.311 (+0.1) | 0.195 / 0.190 (+0.5) | 0.191 / 0.182 (+1.0) | 0.113 / 0.106 (+0.7) |
| (c) LWMA-90, floor n^2 T/(2c), c = 2 | 0.306 / 0.307 (-0.1) | 0.190 / 0.186 (+0.3) | 0.185 / 0.177 (+0.8) | 0.108 / 0.103 (+0.6) |
| LWMA-60 + weighted-sum rise cap 2% | 0.381 / 0.366 (+1.5) | 0.254 / 0.239 (+1.6) | 0.211 / 0.198 (+1.4) | 0.125 / 0.115 (+0.9) |
| ASERT half-life 1 h | 0.353 / 0.354 (-0.0) | 0.217 / 0.213 (+0.4) | 0.199 / 0.190 (+0.9) | 0.119 / 0.113 (+0.6) |
| ASERT half-life 0.75 h | 0.359 / 0.355 (+0.4) | 0.231 / 0.222 (+0.9) | 0.208 / 0.196 (+1.2) | 0.131 / 0.122 (+0.9) |
| Hybrid LWMA-60 in relative-ASERT band (H = 1 h) | 0.356 / 0.346 (+1.0) | 0.231 / 0.221 (+1.0) | 0.206 / 0.193 (+1.3) | 0.124 / 0.115 (+0.9) |
| (e) LWMA-60, signed st in [-6T, 6T], floor c = 2 | 0.314 / 0.310 (+0.4) | 0.205 / 0.197 (+0.8) | 0.199 / 0.187 (+1.2) | 0.120 / 0.112 (+0.9) |
| (e) LWMA-60, floor c = 2, + rise <= 5% | 0.314 / 0.310 (+0.4) | 0.205 / 0.197 (+0.8) | 0.199 / 0.187 (+1.2) | 0.120 / 0.112 (+0.9) |

## Liveness and start-up (informational columns included)

| Rule | 10x down: hours (det) | 100x drop: blocks, hours (det) | 0.5xD0 det | Gap det | Gap: extra blocks in first 6 h (median) | Gap at D0 = 100 (det) | Genesis fork q=0.2 age 720 (compressed) |
|---|---|---|---|---|---|---|---|
| LWMA-60 (current) | 7.7 | 147, 50.0 | 2 | 29 | +6 | 29 | 22/300 |
| LWMA-60 + rise <= 2% | 7.7 | 147, 50.0 | 31 | 112 | +53 | 91 | 0/300 |
| ASERT half-life 2 h | 12.9 | 204, 19.8 | 191 | 192 | +52 | 188 | 0/300 |
| (a) LWMA-60, st in [T/2, 6T] | 7.7 | 147, 50.0 | 2 | 39 | +37 | 41 | 0/300 |
| (a) LWMA-60, st in [T/3, 6T] | 7.7 | 147, 50.0 | 2 | 32 | +18 | 32 | 0/300 |
| (a) LWMA-60, st in [T/4, 6T] | 7.7 | 147, 50.0 | 2 | 30 | +13 | 30 | 0/300 |
| (a) LWMA-60, st in [T/6, 6T] | 7.7 | 147, 50.0 | 2 | 29 | +9 | 29 | 2/300 |
| (a') LWMA-60, virtual clock step T/3 (40 s at T = 120) | 7.7 | 147, 50.0 | 2 | 28 | +6 | 28 | 0/300 |
| (a') LWMA-60, virtual clock step 2T/5 (48 s at T = 120) | 7.7 | 147, 50.0 | 2 | 28 | +7 | 28 | 0/300 |
| (a') LWMA-60, virtual clock step T/2 (60 s at T = 120) | 7.7 | 147, 50.0 | 2 | 11 | +8 | 12 | 0/300 |
| (a') LWMA-60, virtual clock step 3T/5 (72 s at T = 120) | 7.7 | 147, 50.0 | 3 | 17 | +9 | 17 | 0/300 |
| (a') LWMA-60, virtual clock step 2T/3 (80 s at T = 120) | 7.7 | 147, 50.0 | 3 | 25 | +11 | 27 | 0/300 |
| (a') LWMA-75, virtual clock step T/2 [RECOMMENDED] | 9.6 | 184, 62.0 | 2 | 11 | +9 | 12 | 0/300 |
| (a') LWMA-90, virtual clock step T/2 | 11.5 | 220, 73.9 | 2 | 11 | +10 | 12 | 0/300 |
| (b) LWMA-60, rise and fall <= 2% | 16.4 | 260, 169.4 | 31 | 10 | -3 | 12 | 0/300 |
| (b) LWMA-60, rise and fall <= 2.5% | 13.6 | 219, 136.6 | 25 | 10 | -2 | 11 | 0/300 |
| (b) LWMA-60, rise and fall <= 3% | 11.8 | 192, 114.8 | 21 | 10 | -2 | 11 | 0/300 |
| (c) LWMA-60, floor n^2 T/(2c), c = 1.5 | 7.7 | 147, 50.0 | 2 | 29 | +6 | 29 | 0/300 |
| (c) LWMA-60, floor n^2 T/(2c), c = 1.75 | 7.7 | 147, 50.0 | 2 | 29 | +6 | 29 | 0/300 |
| (c) LWMA-60, floor n^2 T/(2c), c = 2 | 7.7 | 147, 50.0 | 2 | 29 | +6 | 29 | 0/300 |
| (c) LWMA-60, floor n^2 T/(2c), c = 2.5 | 7.7 | 147, 50.0 | 2 | 29 | +6 | 29 | 0/300 |
| (c) LWMA-75, floor n^2 T/(2c), c = 2 | 9.6 | 184, 62.0 | 2 | 29 | +7 | 29 | 0/300 |
| (c) LWMA-90, floor n^2 T/(2c), c = 2 | 11.5 | 220, 73.9 | 2 | 29 | +8 | 29 | 0/300 |
| LWMA-60 + weighted-sum rise cap 2% | 7.7 | 114, 48.6 | 2 | 29 | +6 | 29 | 25/300 |
| ASERT half-life 1 h | 6.4 | 100, 9.8 | 96 | 144 | +58 | 142 | 0/300 |
| ASERT half-life 0.75 h | 4.8 | 71, 7.2 | 72 | 127 | +58 | 125 | 0/300 |
| Hybrid LWMA-60 in relative-ASERT band (H = 1 h) | 8.4 | 158, 51.1 | 96 | 14 | +3 | > 3000 | 0/300 |
| (e) LWMA-60, signed st in [-6T, 6T], floor c = 2 | 7.7 | 147, 50.0 | 2 | 29 | +6 | 29 | 0/300 |
| (e) LWMA-60, floor c = 2, + rise <= 5% | 7.7 | 147, 50.0 | 14 | 76 | +26 | 82 | 0/300 |

## Automated verdict

- Candidates meeting every criterion: (a') LWMA-75, virtual clock step T/2 [RECOMMENDED].
- LWMA-60 + rise <= 2% fails 1: emission.
- (a') LWMA-60, virtual clock step T/3 (40 s at T = 120) fails 1: race q=0.4.
- (a') LWMA-60, virtual clock step 2T/5 (48 s at T = 120) fails 1: race q=0.4.
- (a') LWMA-60, virtual clock step T/2 (60 s at T = 120) fails 1: race q=0.4.
- (a') LWMA-60, virtual clock step 3T/5 (72 s at T = 120) fails 1: hopper.
- (a') LWMA-90, virtual clock step T/2 fails 1: 10x down.
- (c) LWMA-60, floor n^2 T/(2c), c = 1.5 fails 1: 10x up.
- (c) LWMA-60, floor n^2 T/(2c), c = 1.75 fails 1: race q=0.4.
- (c) LWMA-60, floor n^2 T/(2c), c = 2 fails 1: race q=0.4.
- (c) LWMA-60, floor n^2 T/(2c), c = 2.5 fails 1: race q=0.4.
- (c) LWMA-75, floor n^2 T/(2c), c = 2 fails 1: race q=0.4.
- ASERT half-life 0.75 h fails 1: race q=0.4.
- (e) LWMA-60, floor c = 2, + rise <= 5% fails 1: race q=0.4.

---

Generated tables, fresh-seed confirmation run (unedited output):

# Difficulty-rule selection study (generated)

Generated by `cargo run --release -p blacksilk-daa-sim -- --selection --seed 0xc0ffee03b --only 'LWMA-60 (current)~RECOMMENDED~LWMA-60, virtual clock step T/2~c = 1.5'` (full mode, 192 s on 4 threads).

## Configuration

- Base seed `0xc0ffee03b`; every job derives its seed from the base seed and its scenario coordinates, not from the rule, so all rules and policies run on common random numbers. 4 threads.
- Race: z = 100, q in [0.3, 0.35, 0.4]. Screening: 1000 trials per (rule, q, policy) on seed set A over the policies compressed + late(0.5), late(0.8), late(1), ratio(0.1), ratio(0.3), ratio(0.6). Confirmation: 4000 trials each of honest, compressed and the screened-best adaptive policy on the disjoint seed set B. Excess = max(compressed, best adaptive) - honest, all on B.
- Lowering (100% miner): dossier 04's fixed families on 3 seeds x 3000 blocks, 120 random patterns selected on 1500 blocks and the best re-run on 3 fresh seeds. Emission gain = blocks/h over honest stamping on the same draws.
- Hopper: configurations (on < x DEQ, off > y DEQ, hash multiple) [(1.2, 2.0, 10.0), (1.05, 1.5, 10.0), (1.1, 1.3, 3.0), (1.0, 1.2, 1.0)], 3 seeds x 20000 blocks each; reported: the largest |share - fair share| in points, where fair share = the hopper's share of hashes spent.
- Bias: 4 seeds x 50000 blocks. Medians: 101 seeds. Follow criteria use the slower of the deterministic run and the stochastic median; 0.5xD0 and the gap use the stochastic median. Genesis fork (informational): q = 0.2, age 720, compressed, 300 trials.

## Every candidate against every criterion

| # | Rule | Race q=0.4 (<= +5%) | Race q<=0.35 (<= +1%) | Emission gain (<= +1%) | Hopper vs fair (+-3 pts) | Bias (+-1.5%) | 10x up (<= 150) | 10x down (<= 150) | 0.5xD0 median (<= 60) | Gap median (<= 120) | Fails |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | LWMA-60 (current) | **FAIL** +34.8% | **FAIL** +8.03% | pass +0.64% | pass +1.3 | pass +1.32% | pass 92/76 | pass 104/105 | pass 8 | pass 10 | 2 |
| 2 | (a') LWMA-60, virtual clock step T/2 (60 s at T = 120) | **FAIL** +5.1% | pass +0.12% | pass +0.77% | pass +2.7 | pass +1.21% | pass 91/91 | pass 104/105 | pass 2 | pass 12 | 1 |
| 3 | (a') LWMA-75, virtual clock step T/2 [RECOMMENDED] | pass +4.0% | pass +0.20% | pass +0.57% | pass +2.5 | pass +1.01% | pass 113/113 | pass 130/133 | pass 2 | pass 12 | 0 |
| 4 | (c) LWMA-60, floor n^2 T/(2c), c = 1.5 | pass +3.9% | pass +0.30% | pass +0.64% | pass +1.3 | pass +1.32% | **FAIL** 153/141 | pass 104/105 | pass 6 | pass 10 | 1 |

Follow cells: deterministic / median blocks. All rules are exact integer arithmetic (criterion 8); see the rule definitions.

## Race detail (z = 100, confirmation pass, 4000 trials per cell)

Cells: honest / compressed / best adaptive (policy) -> excess. Standard error of a difference near p = 0.05: about 0.007.

| Rule | q = 0.3 | q = 0.35 | q = 0.4 |
|---|---|---|---|
| LWMA-60 (current) | 0.000 / 0.009 / 0.006 (late(1)) -> +0.9% | 0.000 / 0.080 / 0.067 (late(0.5)) -> +8.0% | 0.004 / 0.351 / 0.292 (late(0.5)) -> +34.8% |
| (a') LWMA-60, virtual clock step T/2 (60 s at T = 120) | 0.000 / 0.000 / 0.000 (ratio(0.6)) -> +0.0% | 0.000 / 0.001 / 0.001 (ratio(0.3)) -> +0.1% | 0.005 / 0.056 / 0.045 (ratio(0.1)) -> +5.1% |
| (a') LWMA-75, virtual clock step T/2 [RECOMMENDED] | 0.000 / 0.000 / 0.000 (ratio(0.6)) -> +0.0% | 0.000 / 0.002 / 0.001 (ratio(0.1)) -> +0.2% | 0.004 / 0.043 / 0.034 (ratio(0.1)) -> +4.0% |
| (c) LWMA-60, floor n^2 T/(2c), c = 1.5 | 0.000 / 0.000 / 0.000 (ratio(0.6)) -> +0.0% | 0.000 / 0.003 / 0.003 (ratio(0.1)) -> +0.3% | 0.004 / 0.043 / 0.041 (ratio(0.1)) -> +3.9% |

### Screening pass at q = 0.4 (seed set A, 1000 trials per policy; hits)

| Rule | compressed | late(0.5) | late(0.8) | late(1) | ratio(0.1) | ratio(0.3) | ratio(0.6) |
|---|---|---|---|---|---|---|---|
| LWMA-60 (current) | 368 | 306 | 266 | 252 | 52 | 23 | 7 |
| (a') LWMA-60, virtual clock step T/2 (60 s at T = 120) | 48 | 16 | 13 | 5 | 50 | 32 | 7 |
| (a') LWMA-75, virtual clock step T/2 [RECOMMENDED] | 40 | 14 | 9 | 4 | 40 | 19 | 5 |
| (c) LWMA-60, floor n^2 T/(2c), c = 1.5 | 38 | 8 | 8 | 4 | 44 | 26 | 9 |

## Timestamp lowering by a 100% miner (best member per family, blocks/h gain)

| Rule | all at FTL edge | all at MTP+1 | myopic greedy | two-step greedy | b-of-c cycles | one FTL edge every c | threshold | random periodic patterns |
|---|---|---|---|---|---|---|---|---|
| LWMA-60 (current) | +0.11% (all at FTL edge) | -100.00% (all at MTP+1) | +0.20% (myopic greedy) | +0.48% (two-step greedy) | +0.09% (1-of-120 Mtp) | -0.08% (edge every 60) | +0.64% (threshold 240) | +0.55% (pattern period 6) |
| (a') LWMA-60, virtual clock step T/2 (60 s at T = 120) | +0.11% (all at FTL edge) | -100.00% (all at MTP+1) | +0.42% (myopic greedy) | +0.51% (two-step greedy) | +0.10% (1-of-60 Mtp) | +0.03% (edge every 2) | +0.77% (threshold 720) | +0.57% (pattern period 6) |
| (a') LWMA-75, virtual clock step T/2 [RECOMMENDED] | +0.10% (all at FTL edge) | -100.00% (all at MTP+1) | +0.34% (myopic greedy) | +0.42% (two-step greedy) | +0.10% (1-of-60 Mtp) | +0.01% (edge every 2) | +0.57% (threshold 720) | +0.50% (pattern period 5) |
| (c) LWMA-60, floor n^2 T/(2c), c = 1.5 | +0.11% (all at FTL edge) | -100.00% (all at MTP+1) | +0.20% (myopic greedy) | +0.48% (two-step greedy) | +0.09% (1-of-120 Mtp) | -0.08% (edge every 60) | +0.64% (threshold 240) | +0.55% (pattern period 6) |

## Hoppers (share / fair share of blocks)

| Rule | on<1.2 off>2 x10 | on<1.05 off>1.5 x10 | on<1.1 off>1.3 x3 | on<1 off>1.2 x1 |
|---|---|---|---|---|
| LWMA-60 (current) | 0.316 / 0.312 (+0.3) | 0.204 / 0.197 (+0.8) | 0.199 / 0.187 (+1.3) | 0.129 / 0.120 (+0.9) |
| (a') LWMA-60, virtual clock step T/2 (60 s at T = 120) | 0.374 / 0.346 (+2.7) | 0.256 / 0.234 (+2.2) | 0.215 / 0.199 (+1.6) | 0.132 / 0.123 (+1.0) |
| (a') LWMA-75, virtual clock step T/2 [RECOMMENDED] | 0.369 / 0.345 (+2.5) | 0.245 / 0.228 (+1.8) | 0.206 / 0.192 (+1.3) | 0.125 / 0.117 (+0.8) |
| (c) LWMA-60, floor n^2 T/(2c), c = 1.5 | 0.315 / 0.312 (+0.3) | 0.204 / 0.197 (+0.8) | 0.199 / 0.187 (+1.3) | 0.129 / 0.120 (+0.9) |

## Liveness and start-up (informational columns included)

| Rule | 10x down: hours (det) | 100x drop: blocks, hours (det) | 0.5xD0 det | Gap det | Gap: extra blocks in first 6 h (median) | Gap at D0 = 100 (det) | Genesis fork q=0.2 age 720 (compressed) |
|---|---|---|---|---|---|---|---|
| LWMA-60 (current) | 7.7 | 147, 50.0 | 2 | 29 | +7 | 29 | 25/300 |
| (a') LWMA-60, virtual clock step T/2 (60 s at T = 120) | 7.7 | 147, 50.0 | 2 | 11 | +8 | 12 | 0/300 |
| (a') LWMA-75, virtual clock step T/2 [RECOMMENDED] | 9.6 | 184, 62.0 | 2 | 11 | +10 | 12 | 0/300 |
| (c) LWMA-60, floor n^2 T/(2c), c = 1.5 | 7.7 | 147, 50.0 | 2 | 29 | +7 | 29 | 0/300 |

## Automated verdict

- Candidates meeting every criterion: (a') LWMA-75, virtual clock step T/2 [RECOMMENDED].
- (a') LWMA-60, virtual clock step T/2 (60 s at T = 120) fails 1: race q=0.4.
- (c) LWMA-60, floor n^2 T/(2c), c = 1.5 fails 1: 10x up.
