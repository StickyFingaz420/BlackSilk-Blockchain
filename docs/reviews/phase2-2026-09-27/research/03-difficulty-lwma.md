# 03 difficulty-lwma: research dossier (phase 1)

Agent 03, 2026-09-27. Repository read-only at `rebuild/core` **9e422d8**. No cargo builds were run.
All simulations are throwaway Python scripts in the session scratchpad (not in the repository):
`scratchpad/a03/{sim.py, race.py, race2.py, bias2.py, flee2.py, genfork.py}`. The integer
LWMA port reproduces the repository's golden vectors exactly (914, 844, 5 083, 101 666, and the
first 12 of `CHAIN_DIFFICULTIES`), so the simulated rule is the implemented rule.

This is internal engineering work, not an audit.

---

## 1. Scope and what I read

- **Code:**
  - `consensus/src/difficulty.rs` (all)
  - `consensus/src/params.rs`, `consensus/src/timestamp.rs` (all)
  - `consensus/src/chain.rs`: `recent`, `required_difficulty`, `stored_context`, `overlay_context`, `precheck_batch`, and the in-file test `precheck_agrees_with_sequential_validation_and_computes_no_pow`
  - `consensus/src/schedule.rs` (head)
  - `node/src/fingerprint.rs` (`chain_entries`)
  - `p2p/src/net.rs` (`anti_dos_threshold`, `worth_verifying`)
  - `chain/src/manager.rs` (`LOW_WORK_MARGIN_BLOCKS`, `keeps_body`)
  - `tools/genesis/src/lib.rs` (`starting_difficulty`, `STARTING_DIFFICULTY_MARGIN`)
- **Tests:**
  - `difficulty::tests::*` (7)
  - `consensus/tests/golden.rs` (10 `lwma_*` vectors plus `header_chain_difficulty_and_mtp_golden`)
  - `tools/genesis/tests/genesis.rs` (`genesis_to_launch_gap_is_absorbed_by_lwma`, `starting_difficulty`)
  - the difficulty-related parts of `p2p/tests/network.rs` (≈1155–1213, 1608–1633) and `chain/tests/revalidation.rs:545–566`
- **Docs:**
  - `docs/consensus.md` (all)
  - `docs/testnet-v3-genesis.md` §4–§5
  - `docs/reviews/full-review-2026-09-27.md` (LWMA, R1-C1/C7/C8 rows, never-change list)
  - `docs/reviews/autonomous-session-2026-09-27.md`
  - `full-review-2026-09-27/R1-consensus.md` (C1, C7, C8, §3.3, §3.7, §4.1–4.5)
  - SX1 and SX2 (the R1-C1, R1-C8, R9-2 and T-3 rows)
  - the R9, R12, R13 and R15 LWMA passages
- **Roster:** my entry and 01, 02, 04, 09, 40, 41 and 42. **Peer dossiers:** 01, 02 and 04 (for overlap; 04 hands the LWMA harness and the R1-C8 re-rating to 03).

## 2. Current state

| # | Claim | Evidence |
|---|---|---|
| C1 | `next_difficulty` implements zawy LWMA-1's loop: monotone `prev+1`, a 6T cap, the floor `L ≥ n²T/20`, u128 arithmetic, and a clamp to [1, u64::MAX]. | source-read; tested (10 golden vectors derived independently from the spec) |
| C2 | Deliberate divergences from zawy's current reference code (issue #3), none documented as such in `consensus.md` §4 except the short early window: (a) no 99/100 factor; (b) `prev = t[0]`, not `t[0] − T`; (c) no fixed `difficulty_guess` for the first N blocks, but a shortened window from block 2; (d) no rounding to significant digits; (e) S·T·(n+1)/(2L) without first truncating avg_D, which is more precise. | source-read vs [zawy #3] |
| C3 | N = 60 at T = 120. **zawy's current text recommends N = 90 for T = 120** ("N=60, 90, and 150 for T=600, 120, 60"). R1 §4.1's "N = 60 is zawy's standard recommendation" is outdated. | web (zawy #3) |
| C4 | The live path (`required_difficulty`) and the batch path (`overlay_context`) compute the same value. | tested: `precheck_agrees_with_sequential_validation_and_computes_no_pow` (150 headers, across the window) |
| C5 | Arithmetic is overflow-free for the built-in parameters: S·T·(n+1) < 2^84. It is not overflow-free for an arbitrary `T`: overflow needs T ≳ 2^57. No param invariant is checked (01 F-06). | math |
| C6 | Stochastic bias without the 99/100: mean solve time +0.8 % to +1.3 % above T (two seeds, 40 000 blocks, exponential solve times). With 99/100: +0.25 %. N = 90: +0.45 % to +0.9 %. This confirms R1-C7 (≈1 %). | tested (simulation, `sim.py bias`, `bias2.py`) |
| C7 | **R1-C8 (timestamp shaping to lower difficulty)** has no sustained gain. A 100 % miner publishing live under MTP-11 and FTL 360 gets, over honest stamping: FTL-forward +0.10 %, myopic greedy +0.10 %, best threshold policy +0.27 %, and best of 120 random periodic bunch/jump patterns +0.17 % (+0.05 % on re-run). Even at FTL 7 200 the greedy gain is +0.45 %. The only gain is the one-time FTL shift, amortised. This agrees with 04's independent result (+0.15 %). | tested (simulation, `sim.py attack`) |
| C8 | Start-up behaviour (shortened window, T = 120, H = 10 H/s). D0 at 0.001–2× the equilibrium reaches ±20 % within 1–12 blocks (≤ 15 min). D0 10× too high: block 1 alone takes 20 min, and ±20 % comes after 48 blocks (2.5 h). D0 100× too high: block 1 takes 3.3 h. **D0 is needed and must be measured**; erring low is right. | tested (simulation, `sim.py startup`) |
| C9 | **Maximum rise.** In steady state it is `10·avg_D·(n+1)/n` per block, i.e. ≈10.17× the window average. Under sustained timestamp compression it **compounds at ≈1.169× per block** (measured 1.1694). In the short early window it is far steeper: from genesis with compressed stamps, the sequence is 100, 2 000, 15 750, 79 333, 303 696, … 1.18·10^8 after 12 blocks. | math; tested (`genesis compressed ramp`) |
| C10 | The difficulty is never below 1, and at d = 1 PoW is free (R1-C1, SX1). The `12ce4cb` claimed-work gate (`net.rs:1648-1700`) plus the density rule address the zero-cost header flood relative to our own best chain; there is no minimum chain work and no presync. | source-read |

## 3. Problems in scope

### P1. Difficulty-raising attack: compressed timestamps concentrate work into few blocks (NEW; see F-1)

**The problem.**
- Fork choice is by most cumulative work = Σ difficulty (consensus.md §3, §8), and a block's work is its declared difficulty.
- LWMA-1 lets a private branch raise its own difficulty quickly. With every timestamp at MTP+1, all counted solve times are 1 s. The floor then binds, and the difficulty compounds ≈17 % per block (C9); near genesis, 5–20× per block.
- The branch's work is then concentrated in its last few blocks: the last block holds 14.5 % of a 120-block compressed branch and 50 % of a 12-block genesis branch.
- The attacker's time to accumulate a given amount of work therefore has **bounded variance that does not shrink with the confirmation depth z**. By contrast, an honest-difficulty race has a Gamma(z) shape whose relative spread shrinks as 1/√z. This is Bahack's *Difficulty Raising Attack* [Bahack 2013].
- Garay, Kiayias and Leonardos show that Bitcoin's security with variable difficulty relies on the target-recalculation "dampening filter" τ (the 4× clamp per 2016-block epoch) [GKL 2016/2017]. LWMA-60 has an effective per-block ramp factor of ~1.17 with no epoch structure.
- **Why it exists:** LWMA was designed for fast response and against *lowering* manipulation (the 6T cap, monotone stamps, a tight FTL). The raising direction is only bounded per window (10×), and that bound compounds block by block.
- No consensus rule constrains how *old* a timestamp may be relative to real time, and none should (it would put the local clock into validity).

**Demonstrated (Monte Carlo, 600 trials per cell unless noted).**
- Setup: attacker share q forks at the tip and mines privately. It wins if, once the public chain has z blocks after the fork, its branch has strictly more work. Horizon 12z + 240 blocks. Honest miners use real-time stamps.

| q | z | honest-stamp attacker | compressed-stamp attacker |
|---|---|---|---|
| 0.30 | 30 | 0.000 | 0.012 |
| 0.30 | 100 | 0.000 | 0.007 |
| 0.35 | 100 | 0.000 | **0.080** |
| 0.35 | 300 (300 trials) | 0.000 | **0.100** |
| 0.40 | 30 | 0.105 | 0.353 |
| 0.40 | 100 | 0.008 | **0.338** |

- **Fork from genesis** (a full-history rewrite). The chain is 720 blocks old (1 day), and the attacker mines a compressed fork from genesis for up to 10 days:
  - q = 0.20: P = 0.083;
  - q = 0.30: P = 0.212;
  - q = 0.10: P = 0.007.
  - At 7 200 blocks of age: q = 0.20 gives 0.017.
  - With honest stamps, P is effectively 0 for all of these.
- **The node accepts such a branch.** It passes `worth_verifying`, because the claimed work is high. The PoW is real, and there is no reorg-depth limit (consensus.md §8, K4).

**Security consequences.**
- Confirmation depth stops being a reliable safety margin against a 30–45 % miner. This covers double spends at any depth inside the horizon, and a full-chain rewrite during the young-chain period.
- Privacy-relevant: a rewritten chain re-orders spends and invalidates ring members and PX records built on the replaced history (wallet churn, possible ring intersection on re-spend, consensus.md §11 note).
- **Consensus-critical: yes** (the difficulty rule and the fork-choice security model).
- For the *closed testnet* the practical exposure is lower. R1-C2 already concedes that anyone with a reference RandomX miner has more than 50 %. But the rule freezes with the protocol, so the decision belongs **before the freeze**.

**Prior art.**
- **Bahack (2013):** the attack, and a proposal to bound difficulty changes.
- **GKL (CRYPTO 2017):** proves the backbone properties with a bounded target-change filter τ over epochs of length m. Their remark: without dampening "an attack still holds but it will take exponential time to mount" under Bitcoin's epoch structure. LWMA has no epochs.
- **Bitcoin:** the 4× clamp and a 2016-block epoch.
- **Zcash (protocol spec §7.7.3):** a 17-block averaging window of MTP-based spans, damping factor 4, max adjust up 16 % / down 32 %, applied to the *averaged* span.
- **BCH aserti3-2d:** the difficulty rises by at most 2^(T/halflife) per block under compressed stamps (halflife 2 days, so ≈0.24 % per block). It uses no clamps because the absolute schedule bounds it.
- **Monero:** window 720, lag 15, cut 60 on sorted timestamps, with `time_span` floored at 1. That rule is also unclamped. But compression only bites after the attacker's stamps fill the uncut middle of a 720-block window (~600 blocks), which is itself a strong dampener [source-read, not simulated].

**Alternatives (simulated at q = 0.40 and z = 100; honest-stamp baseline 0.008).**

| Rule | P(win) with compression | q = 0.35, z = 100 | Honest mean st/T | 10× hashrate jump: blocks to 90 % | 2× jump | Hopper share† |
|---|---|---|---|---|---|---|
| LWMA-60 (current) | 0.338 | 0.080 | 1.008 | 91 | 56 | 0.317 |
| LWMA-90 | 0.197 | 0.027 | 1.005 | 136 | 84 | 0.298 |
| LWMA-60, floor N²T/4 (F4) | 0.082 | 0.007 | 1.008 | 106 | 56 | 0.317 |
| LWMA-60 + rise ≤ +5 %/block | 0.157 | 0.000 (q 0.30) | 1.008 | 91 | 56 | — |
| LWMA-60 + rise ≤ +3 %/block | 0.075 | 0.002 | 1.007 | 111 | 56 | 0.331 |
| LWMA-60 + F4 + rise ≤ +3 % | 0.065 | 0.002 | 1.007 | 113 | 56 | — |
| LWMA-60 + rise ≤ +2 %/block | 0.020 | 0.000 (q 0.30) | 0.998 | 146 | 56 | 0.393 |
| ASERT, half-life 2 h (60 blocks) | 0.022 | 0.000 | 1.000 | > 400 | 271 | 0.335 |
| ASERT, half-life 6 h | 0.003 | 0.000 | 1.000 | > 400 | > 400 | — |

†A hash-and-flee miner at 10× the base rate that mines while D < 1.2·D_eq and leaves above 2·D_eq. Its share of blocks; lower is better.

Observations:
- A +5 % per-block rise clamp is invisible to honest operation: LWMA-60's own maximum honest per-block rise is 5.5 % on a 10× jump and 2.2 % on 2×. But it only halves the attack.
- Real protection needs a compounding rise rate r_max ≲ 1.02 per block. The attacker's effective sample count is ≈(r+1)/(r−1): 13 today, ≈100 at 1.02, ≈170 for ASERT-2h.
- Every such bound slows the honest ramp from a too-low D0 and after hashrate jumps, and raises hash-and-flee gains. **Resistance to difficulty raising and fast upward response are the same parameter.** This is the GKL τ trade-off.
- ASERT has no bias and the strongest analysis, but it is much slower after large hashrate swings. That is a real liveness cost on a small, volatile testnet: after a 10× drop, each block is slow until the exponential catches up.

**The candidate I recommend evaluating first** (smallest change to reviewed code):
- LWMA-1 as is, plus one line: `next = min(next, parent_D + max(1, parent_D · R_num / R_den))`, with R ≈ 1/50 to 3/100.
- It also tames the genesis-window ramp (20× per block today).
- The `max(1, …)` is essential: without it the difficulty would freeze at 1 on regtest and on any chain that reaches 1. Several tests rely on "1-second blocks raise the difficulty" (`p2p/tests/network.rs:1188-1194`, `chain/tests/revalidation.rs:545`).
- **The alternative** is aserti3-2d-style integer ASERT anchored at genesis with half-life ≈ 1–2 h.
- The decision should come from the Rust harness (W1), not from these scratch runs.

**What could go wrong.**
- A rise clamp adds a slight downward bias (−0.2 % at 2 %) and more hopper profit.
- A too-low D0 then takes longer to correct, and the extra fast blocks mean emission capture at launch. From 0.5× (the genesis tool's margin 2), a 2 % clamp needs ~35 blocks.
- `genesis_to_launch_gap_is_absorbed_by_lwma` assumes recovery from 16 to ≥ 50 within 60 blocks. At +2 % per block from 16 that takes ≈58 blocks, which is borderline; re-derive it.
- Any change alters every golden vector and the whole difficulty history, so it needs a new testnet identity. The v3 reset is authorized and still pending, so this is the right window.

**Tests that prove a fix.**
- A harness race at q ∈ {0.30, 0.35, 0.40} and z ∈ {30, 100, 300}: P_compress ≤ P_honest + 2 % (3σ at 600 trials).
- Genesis-fork rewrite: P ≤ 1 % at q = 0.2, age 720.
- A rise-bound property: `next ≤ parent + max(1, parent·R)` for all inputs.
- Honest bias within ±1 %, 10× recovery ≤ 150 blocks, and the start-up table.

**Invariants that must never change:**
- work = declared difficulty;
- most-work fork choice, strictly greater;
- validation depends only on ancestors;
- no clock in validity beyond the non-permanent FTL.

### P2. Timestamp shaping to lower difficulty (R1-C8)

- **Result:** negligible. The sustained gain is ≤ 0.3 % for a 100 % miner, and the one-shot gain is ≈ FTL/(blocks·T) (C7).
- **Why:** with monotone accounting, Σ counted st ≤ span + FTL (+ ≈ 6T of MTP slack at the window start). Varying the weights makes L vary, and because 1/L is convex, variation raises the average difficulty rather than lowering it.
- zawy's own timestamp-attack survey says: "I can't find a vulnerability in LWMA" [zawy #30]. The April 2018 LWMA incidents (Niobio, Intense, Karbo, Sumo) occurred with the CryptoNote default FTL of 7 200 s, and FTL = N·T/20 is the mitigation already adopted here.
- **Re-rating:** R1-C8 goes from Medium to **Low**, status "Complete but requires further testing" (the Rust harness must reproduce it). **The real timestamp risk is the raising direction (P1), not lowering.**

### P3. The difficulty-1 floor and low-work forks (R1-C1)

- The consensus floor of 1 is correct. Any higher floor either stalls the chain when hashrate is below `floor/T` or is too small to matter. SX1's correction stands: gate on *claimed* work, which is policy (`12ce4cb`; owned by 30/31).
- **LWMA contribution:** a descent costs at most a ÷6 step per block when the timestamps are paid for with real elapsed time. The free-fork depth budget is chain age / 61 s. The v3 genesis procedure (T_g about 2 h before the beacon) gives an attacker about 10 blocks at 6T, enough for a fork to reach D ≈ 1 from D0 = 100 at launch.
- **Interaction with P1:** the anti-DoS gate cannot distinguish a compressed high-difficulty branch (real PoW) from an honest one. It correctly verifies it. So P1 needs a rule fix, not a policy fix.

### P4. The 99/100 factor (R1-C7)

- The bias is confirmed at ≈ +1 % (C6): the emission is ~1 % slower in wall-clock time, and the amounts are unchanged.
- If the DAA is changed for P1 anyway (same identity event), optionally fold in the correction (×99/100, or better an exact bias correction fitted with the harness).
- Otherwise document it as a deliberate deviation.

### P5. The start-up window (the roster question)

- **The shortened window is better than zawy's fixed guess for a genesis launch.** A fixed guess for 60 blocks stalls the chain if D0 is too high, and hands out 60 cheap blocks if it is too low.
- **The cost:** a per-block rise of up to 20× (n = 1) makes the genesis era the most exposed to P1 (C9, the genesis-fork numbers). A per-block rise clamp (P1) removes this without losing the shortened window.
- **Is a starting difficulty needed?** Yes: `D0` is the only lever for block 1, and D0 = 100 on the testnet is a placeholder. Keep `starting_difficulty = rate·T/2` (the genesis tool), measured with the real miner.
  - Too high by 10× costs about 20 min for block 1 and 2.5 h to settle.
  - With a rise clamp, too low costs more cheap blocks. Keep the "err low by 2", and **do not** let it drift to "err low by 100".

### P6. Code-level robustness (minor)

- `assert_eq!(timestamps.len(), cumulative.len())` and `cd[i] - cd[i-1]` (u128) rely on caller invariants (cumulative is monotone), which the only callers guarantee.
- `S·T·(n+1)` overflows only for T ≳ 2^57.
- `window = 0` yields D0 forever.
- **Fix:** `ChainParams` invariants (01 F-06: `1 ≤ N ≤ 2^16`, `1 ≤ T ≤ 2^32`), plus a property test for panic-freedom. Nothing exploitable.

## 4. New findings

| ID | Title | Severity | Status | Location | Scenario | Confidence |
|---|---|---|---|---|---|---|
| **03-F1** | Difficulty-raising (Bahack) attack on LWMA-60 + most-work: compressed timestamps concentrate the branch's work, so reorg success stops decaying with depth | **High** (consensus security model; mainnet-critical; testnet exposure bounded by R1-C2) | Not implemented (no mitigation) | `consensus/src/difficulty.rs:38-42` (floor `n²T/20` only bounds the rise per window and compounds per block); consensus.md §3/§4/§8 | A 35 % miner double-spends against 100 confirmations with P ≈ 8 % (40 %: ≈ 34 %). A 20 % miner rewrites a 1-day-old chain from genesis with P ≈ 8 %. Honest-stamp baselines are ≈ 0. | High on the mechanism (math + simulation of the exact rule); medium on the exact probabilities (±2–3 %, horizon-dependent) |
| **03-F2** | Genesis-era short window allows 5–20× rise per block, the strongest form of F1 | Medium (part of F1; fix together) | Not implemented | `difficulty.rs:15-21,39` (n < N ⇒ floor n²T/20) | The genesis fork above; the ramp 100 → 1.2·10^8 in 12 blocks | High |
| **03-F3** | R1-C8 re-rated: no sustained gain from lowering-direction timestamp shaping | Low (downgrade from Medium) | Complete but requires further testing (the Rust harness) | `difficulty.rs:24-37` | Best strategy +0.27 % (one-shot FTL shift) | High |
| **03-F4** | The spec does not document the divergences from the zawy reference (99/100, `prev` init, fixed guess vs short window, rounding) or zawy's current N = 90 for T = 120. It claims "bounds the influence of manipulated timestamps", which is true only for lowering. | Low (docs) | Not implemented | `docs/consensus.md:117-143` | A second implementer copying zawy's reference forks off (the `prev = t0 − T` init changes the output) | High |
| **03-F5** | Stochastic bias of +0.8–1.3 % in block time (R1-C7 quantified) | Informational | Accepted limitation (unless folded into F1) | `difficulty.rs:41` | Emission 1 % slower in wall-clock time | High |
| **03-F6** | Parameter overflow/degenerate ranges unchecked (T, N) | Informational | Not implemented | `difficulty.rs:14,36,41`; `params.rs` | Only via a mis-set constant | High |
| **03-F7** | The fingerprint covers DAA *parameters* only, not a DAA rule id. A rule change such as a rise clamp would not show in the manifest unless it adds a field. | Low | Not implemented | `node/src/fingerprint.rs:50-76` | Two builds with different rules and the same manifest | High |

## 5. Implementation plan for phase 2

| # | Work item | Files (ownership) | Consensus | Identity | Tests | Bench | Docs | Size | Pri |
|---|---|---|---|---|---|---|---|---|---|
| W1 | **Pure-Rust DAA simulation harness** (`blacksilk-daa-sim`), described below | new `tools/daa-sim/**` (03); workspace `Cargo.toml` members line (coordinate with 43/44) | none | none | the harness *is* the adversarial test; a `#[test]` reduced mode (fixed seeds, ≤ 60 s) asserting the F3 bound (≤ +1 %) and reporting the F1 table | none | `docs/reviews/daa-simulation.md` (results table) | M | **P0** (evidence for the freeze decision) |
| W2 | **Decision and implementation of the bounded-rise rule** (F1/F2), described below | `consensus/src/difficulty.rs`, `consensus/src/params.rs` (new field, e.g. `difficulty_max_rise: (u64, u64)` so the fingerprint destructuring forces W4), `consensus/tests/golden.rs` (new vectors from an independent script), `tools/genesis/tests/genesis.rs` (gap test re-derived) (03); `docs/consensus.md` §1/§4 (03, coordinate with 47) | **CONSENSUS** | **new testnet identity** (fold into the pending v3 reset; regtest genesis id unchanged, since the DAA is not in the header) | golden (clamp boundary ±1, D = 1 → 2 path, genesis ramp), property (rise bound), W1 race regression, full suite; the regtest-dependent tests in p2p/chain must still pass | W1 only | consensus.md §4 plus a v3 genesis note | M | **P0 decision / P0 implementation if adopted** |
| W3 | LWMA property tests: never panics for arbitrary u64 timestamps and monotone cumulative; ≥ 1; longer solve times never raise; scale invariance (D×k ⇒ next×k ± 1); rise ≤ 10·avg·(n+1)/n (or the W2 bound); fall ≤ 6× per window; equals the exact integer formula | `consensus/tests/difficulty_props.rs` (03) (or inside 01's `properties.rs` if the coordinator prefers one file); proptest dev-dep via 41 | none | none | property | — | — | S | P1 |
| W4 | Fingerprint: add the new DAA field(s) and a `chain.daa_rule` text entry, e.g. "lwma1-n60-cap6-floor20-rise1/50" | `node/src/fingerprint.rs` (01/43 own; 03 supplies the entry) | none (a manifest pin changes) | fingerprint pin | fingerprint pin test | — | — | S | P1 (with W2) |
| W5 | Spec text (F3, F4, F5), described below | `docs/consensus.md` §4 (03, with 47), register rows R1-C7/C8 | none | none | — | — | as stated | S | P1 |
| W6 | `ChainParams` range invariants for T and N (F6) | `consensus/src/params.rs` (01 owns F-06; 03 supplies the bounds) | none | none | unit | — | — | S | P2 |
| W7 | 99/100 or a fitted bias correction, only if W2 changes the rule anyway | `difficulty.rs`, golden | CONSENSUS | same event as W2 | harness bias ≤ 0.3 % | — | §4 | S | P3 (P0 only if bundled) |
| W8 | ASERT full evaluation for mainnet (if W2 keeps LWMA): an integer aserti3-2d port inside the harness only, with half-life sweep | `tools/daa-sim` (03) | none | none | harness | — | review note | M | P3 |

**W1 details.**
- It calls `blacksilk_consensus::difficulty::next_difficulty` directly, so there is no re-implementation drift. Candidate rules (the W2 options, ASERT with integer 2^x, LWMA-90) go behind a trait.
- MTP-11 and FTL use `blacksilk_consensus::timestamp`.
- A deterministic in-crate PRNG (xoshiro/splitmix, about 20 lines), with no new dependency.
- Scenarios:
  - honest bias;
  - hashrate steps (0.1×, 0.5×, 2×, 10×);
  - hash-and-flee;
  - lowering strategies: FTL-forward, greedy, threshold, random periodic patterns, from 04's families;
  - raising race (q × z) and the genesis-fork rewrite;
  - D0 mis-set start-up;
  - the genesis gap.

**W2 details.**
- **Recommended candidate:** `next ≤ parent + max(1, parent·R)` with R ∈ [2 %, 3 %], chosen by W1 against these acceptance criteria:
  - P1 race within +2 % of the honest baseline at q ≤ 0.4, z = 100;
  - honest bias |b| ≤ 1 %;
  - 10× recovery ≤ 150 blocks;
  - the start-up table from 0.5× D0 ≤ 40 blocks.
- **Alternative:** ASERT with half-life 1–2 h.
- Follow all 12 steps of the consensus discipline. The demonstrated failure is §3 P1.

**W5 details.**
- Document the divergences from zawy's reference code, and zawy's N = 90 note with the reason for keeping 60 (or changing).
- The measured +1 % bias.
- The F3 result (lowering: no sustained gain).
- The F1 analysis and the chosen bound, or F1 as an accepted limitation.
- Correct "bounds the influence of manipulated timestamps".

## 6. Dependencies and conflicts

- **01 consensus-core:**
  - Their never-change list includes "the LWMA loop, … floor". F1 challenges this *before the freeze*.
  - Their `properties.rs` (LWMA bounds) overlaps W3: agree on one file.
  - F-06 (param invariants) covers W6.
  - They freeze golden vectors after P0-1 changes, so W2 must land first.
- **02 fork-choice-reorgs:** F1 is a fork-choice security issue. Their model and properties should include a "declared work concentrated in few blocks" case. A deep-reorg halt (R1 §4.3, P3) would cap z but does not fix F1 below the cap.
- **04 timestamps-mtp-ftl:** supplies the lowering strategies (their W8 lives in my W1). Their S9/S12 agree with me. **Do not** add a "timestamp not older than now − X" validity rule as an F1 fix: it violates "no clock in validity".
- **09 mining-templates:** the miner uses the template difficulty, so there is no change. Labnet runs after W2 should record the difficulty series.
- **14 fee-economics:** the block-time bias (+1 %) affects the emission timeline.
- **30/31 p2p:** the claimed-work gate stays as it is. A compressed high-difficulty branch legitimately passes it. There is no interaction problem, but the p2p tests that rely on "1-second blocks raise the difficulty from 1" must keep passing (hence `max(1, …)`).
- **40 testnet-genesis:** D0 measurement; the gap test re-derivation under W2; the identity reset carries W2.
- **41/42:** proptest harness, cargo-mutants on `difficulty.rs` (killing `(n+1)→n`, `6*t→7*t`, `/20→/19`, and the new clamp constants), and optional Kani for panic-freedom.
- **43:** the workspace member for `tools/daa-sim`; the reduced harness test in CI.
- **48/50:** adversarial review of W2.

## 7. Open questions for the coordinator

1. **The owner decision on F1 before the freeze:**
   - (a) a rise clamp on LWMA-60 (recommended to evaluate first);
   - (b) ASERT;
   - (c) accept F1 for the testnet (justified by R1-C2) and decide for mainnet.
   - With (c), the testnet should still record it in `assumptions.md` K1/K4.
2. Keep N = 60 or move to zawy's current N = 90? N = 90 alone halves F1 and lowers bias, at 1.5× slower response. I lean to keeping 60 plus a clamp, pending W1.
3. Bundle the 99/100 (W7) into the same identity event, if W2 is adopted?
4. May 03 add a new crate (`tools/daa-sim`) to the workspace, or should the harness live under `consensus/tests/` as an `#[ignore]`d long test? A crate is cleaner and keeps consensus test time down.
5. The genesis procedure places T_g about 2 h before the beacon. With a rise clamp, the post-gap recovery (from D0/6) is slower; acceptable?

## 8. Sources

- zawy12, "LWMA difficulty algorithm" (issue #3): reference code, N per T, FTL = N·T/20, `difficulty_guess`, 99/100. https://github.com/zawy12/difficulty-algorithms/issues/3
- zawy12, "Timestamp Attacks" (issue #30): the timespan-limit attack, the April 2018 LWMA incidents, and "I can't find a vulnerability in LWMA". https://github.com/zawy12/difficulty-algorithms/issues/30
- zawy12, "LWMA's history" (issue #24): https://github.com/zawy12/difficulty-algorithms/issues/24
- zawy12, "Summary of Difficulty Algorithms" (issue #50): https://github.com/zawy12/difficulty-algorithms/issues/50
- L. Bahack, "Theoretical Bitcoin Attacks with less than Half of the Computational Power (draft)", arXiv:1312.7013 / IACR ePrint 2013/868: the Difficulty Raising Attack. https://arxiv.org/abs/1312.7013v1 , https://eprint.iacr.org/2013/868
- J. Garay, A. Kiayias, N. Leonardos, "The Bitcoin Backbone Protocol with Chains of Variable Difficulty", CRYPTO 2017, ePrint 2016/1048: the dampening filter τ and the remark on attacks without it. https://eprint.iacr.org/2016/1048
- Bitcoin Cash Node, "ASERT difficulty adjustment algorithm (aserti3-2d)", 2020-11-15 upgrade spec. https://upgradespecs.bitcoincashnode.org/2020-11-15-asert/
- Monero, `src/cryptonote_basic/difficulty.cpp` (`next_difficulty`: sort, cut, `time_span` = 0 → 1). https://github.com/monero-project/monero/blob/master/src/cryptonote_basic/difficulty.cpp
- Monero, `src/cryptonote_config.h` (DIFFICULTY_WINDOW 720, LAG 15, CUT 60, FTL 7 200, timestamp window 60). https://github.com/monero-project/monero/blob/master/src/cryptonote_config.h
- Zcash Protocol Specification §7.7.3 (PoWAveragingWindow 17, PoWDampingFactor 4, MaxAdjustUp 16 %, MaxAdjustDown 32 %). https://zips.z.cash/protocol/protocol.pdf
- Zebra RFC 0006, "Contextual Difficulty Validation". https://zebra.zfnd.org/dev/rfcs/0006-contextual-difficulty.html
- Bitcoin Core PR #25717 (headers presync / anti-DoS work threshold), context for R1-C1. https://github.com/bitcoin/bitcoin/pull/25717
- Monero PR #2887 (the LWMA proposal for Monero, not merged), for context. https://github.com/monero-project/monero/pull/2887
