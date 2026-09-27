# 04 timestamps-mtp-ftl: research dossier (phase 2, phase 1)

Internal engineering work, not an audit. Nothing here claims that BlackSilk is secure or
production-ready. Read-only on the repository; no cargo builds or tests were run. One
scratch simulation (Python, outside the repository) was run and is labelled as such.

## 1. Scope and what I read

- **Commit:** `9e422d8` (`rebuild/core`).
- **Code:**
  - `consensus/src/timestamp.rs`, `chain.rs`, `difficulty.rs`, `params.rs`, `lib.rs`
  - `chain/src/manager.rs`: `submit_inner`, `replay_one`, `accept_headers`, `precheck_headers`
  - `p2p/src/net.rs`: `unix_now`, `on_headers`, `header_worker`, `verify_headers`,
    `penalized`, `on_header_error`, `block_worker`, bans
  - `p2p/src/message.rs` (`Version`), `p2p/src/addrman.rs` (`BanList`)
  - `node/src/lib.rs` (`now()`), `node/src/main.rs`, `node/src/fingerprint.rs`
  - `miner/src/lib.rs` (`build_block`), `miner/src/main.rs`
  - `rpc/src/lib.rs` (`Info`)
  - `tx/src/decoy.rs`: time use only
  - `tools/genesis/tests/genesis.rs`
  - `deploy/systemd/blacksilk-node.service`
- **Tests:**
  - `consensus/src/timestamp.rs` tests: `median_odd_even`, `mtp_is_strict`, `future_limit`
  - `consensus/src/chain.rs` tests: `rejects_each_invalid_field`,
    `precheck_agrees_with_sequential_validation_and_computes_no_pow`
  - `consensus/src/difficulty.rs` tests
  - `consensus/tests/golden.rs`: `median_time_past_golden`,
    `header_chain_difficulty_and_mtp_golden` and the LWMA vectors
  - `tools/genesis/tests/genesis.rs`: `generate_and_verify`,
    `genesis_to_launch_gap_is_absorbed_by_lwma`
  - a grep of `p2p/tests`, `chain/tests` and `tools/labnet`: **no FTL or clock-skew test exists at
    the network or labnet level**
- **Docs:**
  - `docs/reviews/full-review-2026-09-27.md`: the register, never-change §8 #4 and P2-8
  - `docs/reviews/autonomous-session-2026-09-27.md`
  - the source reports: R1 (V5, V6, V15, C1, C8, C9, C11, §3.4, §3.7, §4.1–4.2), SX1
    (C1/C8/C9 rows, genesis rows), SX2 (R15-4 row), R15 (R15-4, R15-11, §4), R13 (T-3, T-4,
    T-9), R3 (minimal `Version`), R8, R9 (R9-10)
  - `docs/testnet-v3-genesis.md` and `docs/consensus.md` §4–§5, §9–§10
  - `docs/p2p.md`: time and clock lines
  - `docs/testnet.md` §12.2
- **Roster neighbours:** 01, 02, 03, 09, 30, 31, 40, 41.

## 2. Current state (with evidence classes)

| # | Claim | Evidence |
|---|---|---|
| S1 | MTP is the lower median of up to 11 ancestors ending at the parent, on the header's own branch. It is strict (`>`). With fewer ancestors near genesis, all of them are used. | tested: `mtp_is_strict`, `median_time_past_golden`, `header_chain_difficulty_and_mtp_golden` (heights 1, 2, 3, 6, 11, 12, 21, 150) |
| S2 | FTL: `timestamp ≤ now + 360` (saturating). It is non-permanent: `is_permanent() == false`. It is not penalized in `penalized()` (`net.rs:1500-1509`), in `on_header_error` (`net.rs:1804`) or in `block_worker` (`net.rs:1975`). | tested: `rejects_each_invalid_field` (`chain.rs:802-805`), `future_limit`; the p2p part is source-read only |
| S3 | One rule definition. `check_rules` (`chain.rs:309-358`) serves both `validate` and `precheck_batch`. FTL is checked **before** the difficulty check and before PoW, so a future-stamped header costs no RandomX hash. | tested: `precheck_agrees_with_sequential_validation...` (including an FTL break mid-batch at index ≤ 70) |
| S4 | **Replay is independent of the clock.** `replay_one` passes `now = block.header.timestamp` (`manager.rs:452`), so a restart with a wrong clock cannot reject stored blocks. | source-read (no dedicated test) |
| S5 | A body whose header is already stored is never re-checked against FTL (`submit_inner` skips `accept` for known headers, `manager.rs:629-645`). | source-read |
| S6 | **No peer-adjusted time.** The only consensus clock is `SystemTime` (`node/src/lib.rs:110-115`, `p2p/src/net.rs:370-375`). `Version` carries no clock (`message.rs:55-63`), which avoids clock-skew fingerprinting (Kohno 2005; Murdoch 2006). | source-read |
| S7 | Timers use `Instant`, which is monotonic: Dandelion epochs and embargo, header and block timeouts, rate limits. Only ban expiry, addrman `mark_good` and the store-repair file name use wall-clock time. | source-read |
| S8 | **The miner stamps `max(now, template.min_timestamp)`** (`miner/src/lib.rs:58`). This is the template protection against the "Jagerman MTP attack", in which templates without MTP+1 let a lucky 25% miner lock honest miners out (zawy #30). The timestamp is fixed per template, with a default refresh of 15 s (R9-10). | source-read |
| S9 | **LWMA-1 is monotone** (`prev+1`) with a 6T per-block cap and an increase floor of `n²T/20`. So the sum of counted solve times over a window is at most the real span plus FTL. The Bitcoin timewarp does not exist here, because there are no retarget-period boundaries. | math (R1 V5, SX1 ✓); tested by the golden LWMA vectors, including out-of-order and cap cases |
| S10 | `FTL = 360 = N·T/20` on testnet and mainnet, which matches zawy's LWMA guidance. On regtest `N·T/20 = 30`, but FTL stays 360; this is documented in consensus.md §5. | source-read (`params.rs:118`) |
| S11 | MTP window, FTL and T are in the consensus fingerprint (`fingerprint.rs:59-73`). | source-read |
| S12 | The genesis gap: block 1 at `T_g + 7200` gives a block-2 difficulty of 16, and the difficulty recovers within one window. | tested: `genesis_to_launch_gap_is_absorbed_by_lwma` |
| S13 | `generate` refuses a future `T_g`. `verify` is independent of the clock. | tested: `generate_and_verify` |
| S14 | **Decoy selection uses heights × T, not block timestamps** (`tx/src/decoy.rs:98-188`), so timestamp shaping cannot skew ring selection. No transaction-level time or unlock field was found by grep. | source-read |
| S15 | The node binary refuses nothing and warns about nothing concerning the clock. `now()` falls back to `0` if the clock is before 1970 (`node/src/lib.rs:114`, `net.rs:374`, `miner/src/main.rs:42`), which silently makes every block "future". | source-read |
| S16 | Nothing detects or reports clock skew: no log, metric or RPC field (R1-C9 is confirmed at HEAD). | source-read |
| S17 | `docs/consensus.md:157` still says "Nodes must not adjust their clocks from peer time by more than FTL/2". This is stale: nodes never adjust (R1-C11, open). | source-read |

**What the tests prove:**
- The MTP and FTL arithmetic at the rule level.
- The integration of the rules into the header chain (strictness, the even-count median near genesis, branch-local context in pre-check).
- FTL's non-permanence at the `HeaderError` level.

**What the tests do not prove:**
- The p2p handling of FTL (no penalty, retry and eventual acceptance).
- Replay's independence of the clock.
- Any behaviour under real clock skew. There is no injectable clock, so labnet cannot even express skew.
- The LWMA strategy bound.

## 3. Problems in scope

### P1. Is FTL = 360 s combined with LWMA exploitable? (R1-C8; roster Q1)

**The problem.** Timestamps are miner-chosen within the window (MTP, now+FTL]. LWMA weights
recent solve times linearly, so a forward stamp on the newest block has weight N.

**Single-block bound (math).** One block stamped at the FTL edge adds at most N·FTL =
21,600 to L. The honest L is T·N(N+1)/2 = 219,600, so the next difficulty is lower by about
2·FTL/(T(N+1)) ≈ 9%.
- The next honest block then counts `prev+1`, which moves time mass to a higher weight and
  raises the difficulty again.
- zawy's rule of thumb is `next ≈ avg·1/(1+FTL/(T·N))`, about 5% for an SMA-like weighting.
  FTL < N·T/10 keeps single-block manipulation under 10% (zawy #30).
- **The transient helps every miner equally.** The difficulty at a height is the same for
  all miners, so a **minority cannot raise its share** by timestamp choice.

**Scratch simulation** (Python, outside the repository; tagged *tested (scratch)*, not a repository test):
- **Setup:** an exact integer port of `difficulty.rs`; MTP-11 lower median; FTL checked
  against real time; exponential solve times; 5 seeds × 6k–20k blocks after a 200-block
  honest warm-up.
- **Honest baseline:** 29.62 blocks/h (target 30). This is LWMA's known stochastic bias of
  about −1.3%. A deterministic run gives 30.00.
- **Majority (100%) miner** (the strategy families listed below): best found **29.67 blocks/h (+0.15%, within seed noise)**, from the two-step greedy strategy.
  - Every bunch or back-stamp strategy **loses**. For example, stamping at MTP+1 drives the
    difficulty up (down to about 0 blocks/h), because monotone `prev+1` solve times of 1 s
    count as extreme hash rate.
  - The R1-C8 worked example (0.55·D) is real but transient. Its net over a cycle was ≤ 0 in every cycle tried.
- **Minority α ∈ {0.1, 0.3, 0.45}:** the share equals α exactly, as the argument predicts. The
  chain-wide rate falls slightly: back-stamping hurts everyone.
- **Strategy families tried:**
  - all stamps at the FTL edge;
  - all stamps at MTP+1;
  - b-of-c cycles (MTP+1 or prev+1, then the FTL edge) with c ∈ {2…120};
  - one FTL-edge stamp every c blocks;
  - a myopic greedy and a two-step lookahead greedy over {MTP+1, prev+1, real, FTL edge}.

**Conclusion.** No exploitable net gain was found. **This is not a proof**: the strategy
space is not exhaustive (optimal control over a 61-block state is not searched). The
evidence supports downgrading R1-C8 from Medium to **Low**, pending a pure-Rust version of
this harness (owned by 03). The structural reason is that a constant forward offset is
invisible to LWMA, and any varying offset must be paid back within the bound of real span
plus FTL.

- **Consensus-critical?** Only if the rule changes; no change is proposed. **Privacy:** no.
- **Prior art:**
  - zawy LWMA (#3), timestamp attacks (#30);
  - the Bitcoin timewarp fix, BIP 54 (the first-block rule, 7200 s; the Murch–Zawy rule), not applicable here;
  - BCH ASERT, anchored and with no window to shape (R1 §4.1).
- **What could go wrong:** tightening FTL further (for example to 120 s) buys little against
  shaping and raises the clock-skew liveness risk (P2). **Do not tighten it.**
- **Tests:** port the strategy families into a Rust test that asserts ≤ +1% blocks/h over
  honest with fixed seeds (a long version `#[ignore]`d), plus pinned vectors for the −9%
  single-stamp transient and its recovery.
- **Invariants:** strict MTP-11; FTL 360; monotone `prev+1`; the 6T cap; the `n²T/20` floor;
  the operation order; never peer time (never-change #4).

### P2. Clock skew: silent stalls, and no detection (R1-C9; roster Q2)

**The problem.** The FTL is 20× tighter than Bitcoin's or Monero's 2 h. The effects of skew:
- a node more than 360 s slow refuses every fresh tip for as long as the skew lasts;
- a miner more than 360 s fast mines blocks everyone refuses;
- nothing is logged.

Windows makes this likely on consumer trial devices:
- w32time on stand-alone machines polls every 604,800 s (7 days) by default (Microsoft Learn);
- Secure Time Seeding has produced documented jumps of days to years (Microsoft Learn STS
  recommendations; it is disabled by default only from Server 2025).

**Recovery path (source-read).** A future header is dropped without penalty and is not
stored. Recovery then depends on the peer's claimed height staying above ours:
- the maintenance loop keeps asking for headers;
- or the next tip announcement brings `UnknownParent`, then `request_headers`.

So a node recovers within about one tick of its clock becoming correct. This is good, but untested.

**How the others do it (primary sources):**
- **Bitcoin Core:**
  - adjusted time was removed from validation in PR #28956 (merged 2024-01-31, released in 27.0), so validation uses the local clock;
  - PR #29623 (merged 2024-04-30) replaced it with a **warn-only** `TimeOffsets`: the last 50 outbound peers' `Version.nTime` offsets, a median over at least 5 samples, a warning above 10 minutes, shown in `getnetworkinfo` warnings and the GUI (`src/node/timeoffsets.{h,cpp}`).
- **Monero:**
  - the FTL check is `b.timestamp > time(NULL) + 2h` against the local clock only (`blockchain.cpp` `check_block_timestamp`);
  - `get_adjusted_time` is a chain-median projection used for unlock times, not peer time;
  - a future-timestamp block is reported as `m_verifivation_failed`, the same as an MTP failure. BlackSilk's non-permanent handling is better.
- **zawy:** remove peer time; if it is kept, limit it to FTL/2 and only warn.

**BlackSilk's constraint.** `Version` deliberately carries no clock (privacy). So the
Bitcoin mechanism (peer `nTime`) is not available, and **must not be added**:
- clock skew is a device fingerprint (Kohno, Broido and claffy 2005);
- it has been used to deanonymize Tor hidden services (Murdoch, CCS 2006).

**Proposed design: a warn-only `ClockMonitor` in p2p. It never changes consensus time.**

1. **Block-arrival samples (PoW-backed).**
   - When a header is accepted after its PoW is verified, it extends our best tip, and it arrived as a live announcement (not during bulk sync: its height is at least our header height at arrival), record `o = header.timestamp − local_arrival_time`.
   - Keep the last 25 samples, at most one per block id, and require at least 3 distinct announcing peers.
   - Honest `o` is about −(0…refresh+propagation), that is −1 to −30 s.
   - **Why this is Sybil-resistant:** forging a sample requires a valid-PoW header at the current difficulty. An eclipsing attacker can only *delay* blocks, which makes `o` more negative. It cannot make our clock look slow for free.
2. **Retro-confirmed future rejections.**
   - Keep a bounded LRU (64 entries) of `id → first_seen` for headers rejected *only* by FTL.
   - When the same id is later accepted with its PoW verified, add a sample with `o = timestamp − first_seen`.
   - Do **not** count unverified future rejections: FTL is checked before PoW, so they are free to forge. At most they are logged at DEBUG.
3. **Thresholds, with hysteresis:**
   - `|median o| > FTL/3 = 120 s`: WARN "local clock appears N s slow/fast versus recent blocks; FTL = 360 s; check NTP" (at most once per 10 min);
   - `> FTL`: ERROR-level log.
   - Median `o` below −120 s can also mean miners' clocks are slow or our peers are delaying blocks. The message says so; it can also serve as a stale-tip indicator for 31.
4. **Start-up checks:**
   - a `SystemTime` before the epoch, or `now < genesis.timestamp`: refuse to start with a clear message (policy);
   - `now + FTL < stored best tip timestamp`: WARN (our own chain is in our future).
5. **Exposure:**
   - `/info.clock_offset_estimate: Option<i64>` and `clock_offset_samples`, local RPC only;
   - the start-up log;
   - **never** sent over P2P, and **never** used in any validation.
6. **Miner (09's area, see §6):**
   - WARN when `now + 60 < template.min_timestamp`;
   - log clearly when a submit fails with `TimestampTooFarInFuture`;
   - optional: `Template.curtime` (node time, like Bitcoin's `getblocktemplate`), with the miner refusing to mine when `|miner_now − curtime| > FTL/2`.

**Trade-offs and what could go wrong:**
- **False warnings** during sync or low hash rate. Mitigations: live announcements only, at least 3 peers, a minimum of 5 samples.
- **A warn-only monitor cannot fix the clock.** That is deliberate: auto-adjusting would reintroduce a peer-time attack surface (timejacking; NTP attacks, Malhotra et al., NDSS 2016).

**Operator procedure (P0 docs):**
- chrony or ntpd, with NTS (RFC 8915) where available;
- on Windows: `w32tm /resync`, a `SpecialPollInterval` of at most 3600, and `UtilizeSslTimeData=0` (STS off);
- check before starting: skew under 10 s (R15 E5).

**Tests:**
- unit tests of `ClockMonitor`: the median, hysteresis, rejection of unverified samples, the LRU bound;
- p2p tests with an injectable clock: a node with a −400 s offset stalls, warns, and recovers when the offset is removed; a miner at +400 s has blocks refused, and the peer is not banned;
- a labnet `--clock-offset` chaos run (R13 T-9).

**Invariants:** local clock only; no clock in `Version`; FTL never permanent and never penalized.

### P3. The genesis timestamp rules (R15-4; roster Q3)

**Assessment.** I agree with R15, SX1, SX2 and `docs/testnet-v3-genesis.md` §4:
- fixing `T_g` about 2 h *before* the beacon's expected time makes the genesis past-dated when it becomes computable;
- the only pre-mining window is reveal → honest start, which FTL cannot bound: a private chain can be stamped up to launch + 360 s;
- total work is what counts, so packing timestamps gains nothing.

`generate` refuses a future `T_g` [tested]. The genesis gap (block-2 D = 16) is tested.

**Residuals I add:**
- **(a) The free low-work fork budget at launch.** With `T_g` 3–4 h before block 1, an
  attacker can build a fork from genesis about (launch − `T_g`)/61 s ≈ 180–240 headers deep, and
  arbitrarily wide, at D → 1 (R1-C1 mechanics).
  - While our chain is shorter than 144 blocks, `anti_dos_threshold` is 0 (`net.rs:1647-1651`), so
    **every such header passes the work gate** for the first about 4.8 h of the trial.
  - This is covered for the trusted trial by the explicit `--peer` mesh. It is a public-testnet concern and belongs to 31/03 (`MIN_CHAIN_WORK`/presync). Do not "fix" it by moving `T_g` later: that reopens the pre-mining window.
- **(b) If `H` arrives early (before `T_g`):**
  - the procedure says wait;
  - `generate` refuses until `T_g` on the generating machine's clock, so that clock must be NTP-checked;
  - add this to the steps.
- **(c) Keep the gap bounded:**
  - do not let `T_g` precede the launch by much more than 2–4 h;
  - the tool could print the implied free-fork depth budget and the reveal window as a sanity line (40's tool).

**Tests:** the existing ones. Add a field assert that `T_g < expected(H) − 1 h` as a documented
procedural check, not code. **Invariant:** `T_g` is announced before the beacon, never after.

### P4. Clock jumps turn an honest majority miner into an accidental private chain (new, F2)

**Scenario (source-read reasoning, not tested):**
1. On a 7-device trial where one device has most of the hash rate (R15 §5.1 expects this),
   Windows STS jumps that device's clock forward by days.
2. Its node accepts its own future-stamped blocks, which pass FTL against its own clock.
   Every other node refuses them (non-permanent, not banned).
3. Two partitions form. When the clock is corrected, the majority node's best chain is its
   own future branch, which cannot be extended (MTP+1 > now + FTL). Its miner produces blocks
   that its own node refuses, so it idles until the honest branch overtakes it in work.
4. When real time reaches the stamps, the future branch becomes valid for everyone. If it
   still has more work, which depends on the hash split and the timing, the others **reorg
   deeply**.

**Assessment:**
- It is not a new adversarial capability: withholding does the same.
- It is an accidental liveness and reorg hazard that NTP plus P2's monitor and miner refusal remove.
- **Mitigation:**
  - the miner refuses to mine when the node's offset estimate or `curtime` differ by more than FTL/2;
  - the node WARNs when its best tip is more than FTL ahead of `now` in the network estimate;
  - the operator checklist disables STS.

### P5. Miner timestamps as a weak fingerprint (new, F3)

- **Mechanism:** the header timestamp is the miner's wall clock when the template is built.
  Across many blocks, `arrival − timestamp` estimates a miner's clock offset and refresh
  interval. This can cluster blocks, and so coinbase outputs, by miner: the class of leak
  that R3-2 fixed for nonces.
- **Magnitude:** at 1 s resolution with NTP-synced miners (skew in milliseconds) the signal is
  weak. It is strong for unsynced miners (skew of many seconds, stable) and for non-default
  `--refresh` values.
- **No protocol fix is worth it:** jitter only adds noise that averaging removes.
- **Mitigation:** NTP (the same fix as P2), keep the default refresh, document it.
- Privacy: Low.

### P6. Smaller items

- **F4 (Info).** `verify_headers` reads `now` once per batch (`net.rs:1707`), and hashing a
  2000-header batch can take minutes. Tip headers at the FTL edge can then be refused against
  a stale `now`. The consequence is a retry only. Refresh `now` per chunk: a policy change
  with no consensus effect.
- **F5 (Info).** `BlockTemplate.min_timestamp = MTP + 1` (`chain.rs:302`) is unchecked
  addition. It is unreachable in production: it needs a stored timestamp near `u64::MAX`,
  which FTL forbids for a real clock. Tests use `now = u64::MAX`. Use `saturating_add`; this is
  robustness, not a rule change.
- **F6 (Low).** Failing to read the clock gives `now = 0` silently in the node, p2p and miner
  (`lib.rs:114`, `net.rs:374`, `miner/main.rs:42`). Fail loud at start-up (P2 item 4).
- **F7 (Info).** Ban expiry uses wall-clock Unix time, persisted. A forward jump lifts every
  ban, and a backward jump extends them. This is acceptable; document it, or store remaining
  durations.
- **F8 (Low, docs).** `docs/consensus.md:157` is stale: "must not adjust … by more than FTL/2"
  (R1-C11). §10's "0.45 s" is stale too (47's area). docs/testnet.md §12.2 lacks the Windows
  STS and poll-interval steps.
- **F9 (Info, test gap).** There is no network-level FTL test, no replay-independence test and
  no injectable clock. `unix_now()` and `now()` are hard-wired, so labnet cannot express skew (R13 T-9).
- **Future function clock (R5-3/R7-1, owned by 28).** If functions ever get a clock, it should
  be height-based. Block timestamps carry ±(MTP lag, about 11 min) to +FTL manipulation by
  miners.

## 4. New findings

| ID | Title | Severity | Status | Location | Scenario | Confidence |
|---|---|---|---|---|---|---|
| 04-F1 (= R1-C9, reconfirmed) | No clock-skew detection; stalls are silent | Medium (trial liveness) | Not implemented | `node/src/lib.rs:110-115`, `p2p/src/net.rs:370-375, 1804` | A node 7 min slow refuses every tip indefinitely, with no log line explaining it | High |
| 04-F2 | A clock jump makes an honest majority miner an accidental private chain, then a deep reorg | Medium (trial) / Low (public) | Not implemented | `miner/src/lib.rs:58`, `chain.rs:345` | Windows STS jumps the majority device's clock forward (§3 P4) | Medium (reasoned, untested) |
| 04-F3 | Miner timestamps leak the clock offset and refresh interval (clustering of coinbases) | Low (privacy) | Accepted limitation (docs) | `miner/src/lib.rs:58`, `main.rs:128` | Unsynced miners are linkable across blocks | Medium |
| 04-F4 | Stale `now` over a long header batch | Informational | Not implemented | `p2p/src/net.rs:1707, 1744` | An edge header is refused and retried | High |
| 04-F5 | `min_timestamp` addition is not saturating | Informational | Not implemented | `consensus/src/chain.rs:302` | Unreachable with a real clock | High |
| 04-F6 | A clock-read failure silently becomes `now = 0` | Low | Not implemented | `node/src/lib.rs:114`, `net.rs:374`, `miner/src/main.rs:42` | A clock before 1970 makes every block "future" | High |
| 04-F7 | Ban expiry depends on wall-clock jumps | Informational | Accepted limitation | `p2p/src/net.rs:647`, `addrman.rs:238-248` | STS jump lifts or extends bans | High |
| 04-F8 | Stale clock text in the specification; missing Windows steps | Low (docs) | Partially implemented | `docs/consensus.md:157`, `docs/testnet.md` §12.2 | Operators misread the guarantees | High |
| 04-F9 | No network, replay or labnet time-edge tests; no injectable clock | Medium (evidence gap) | Not implemented | `p2p/tests`, `chain/tests`, `tools/labnet` | Regressions in FTL non-penalty or retry go unnoticed | High |
| 04-F10 (= R1-C8, re-rated) | LWMA timestamp shaping: no net gain found | Low (proposed downgrade from Medium) | Complete but requires further testing | `consensus/src/difficulty.rs` | The best strategy found gave +0.15% blocks/h (noise) | Medium |
| 04-F11 (R15-4 residual) | The free-fork depth budget at launch is (launch − `T_g`)/61 s, and the work gate is 0 below height 144 | Low (trial) / Medium (public) | Accepted limitation (trial) | `p2p/src/net.rs:1647-1651`, `docs/testnet-v3-genesis.md` §4 | About 200 free headers deep, arbitrarily wide, in the first hours | High (math) |

## 5. Implementation plan for phase 2

| # | Work item | Files (ownership) | Consensus | Identity | Tests | Docs | Size | Pri |
|---|---|---|---|---|---|---|---|---|
| W1 | Operator and specification text: remove the "FTL/2 adjust" sentence; state "local clock only, warn-only monitor"; the Windows steps (w32tm resync, SpecialPollInterval, `UtilizeSslTimeData=0`), chrony/NTS, skew < 10 s pre-flight; the LWMA single-stamp bound (about −9%, transient, no share gain) and the simulation result | `docs/consensus.md` §5, `docs/testnet.md` §12.2 (coordinate with 47) | none | none | — | these | S | **P0** |
| W2 | **Injectable clock:** a `Clock` handle (the system clock plus an offset); replace `unix_now()` and `now()`; `--clock-offset-secs` accepted **only on regtest**; labnet flag | new `p2p/src/clock.rs` (04); single-line call-site edits in `p2p/src/net.rs` (coordinate with 30, 31, 34); `node/src/lib.rs`, `node/src/config.rs`; `tools/labnet/src/*` (coordinate with 43, 50) | none | none | unit tests: the offset clock; config rejects the flag on testnet and mainnet | `docs/testnet.md` (labnet) | S | **P1** |
| W3 | **`ClockMonitor`** (warn-only): PoW-backed arrival samples; LRU of retro-confirmed future rejections; median and hysteresis; WARN at 120 s, ERROR at 360 s; `/info.clock_offset_estimate` and `clock_offset_samples` | `p2p/src/clock.rs` (04); hooks in `net.rs` `verify_headers`, `on_header_error` (coordinate with 31); `rpc/src/lib.rs` `Info` (additive `#[serde(default)]`; coordinate with 36); `node/src/lib.rs` `/info` | none (policy/observability) | none | unit tests: median, hysteresis, unverified samples ignored, LRU ≤ 64, at least 3 peers; p2p: node at −400 s warns, stalls, recovers after the offset is cleared; the peer is never penalized | `docs/p2p.md`, `docs/consensus.md` §5 | M | **P1** |
| W4 | **Start-up clock sanity:** refuse on a failed clock read or `now < genesis.timestamp`; WARN on `now + FTL < tip.timestamp`; the miner and p2p stop using `unwrap_or(0)` | `node/src/main.rs`, `node/src/lib.rs`, `miner/src/main.rs` | none | none | unit tests on a sanity function taking `now` | `docs/testnet.md` | S | **P1** |
| W5 | **Miner clock safety:** WARN on `now + 60 < min_timestamp`; clear log on `TimestampTooFarInFuture`; `Template.curtime` (node time, additive); refuse to mine when \|miner − node\| > FTL/2 (prevents F2) | `miner/src/lib.rs`, `miner/src/main.rs` (09 co-owns); `rpc/src/lib.rs` `Template`; `node/src/lib.rs` template handler | none (RPC additive) | none | miner unit tests: clamping, refusal; the template carries `curtime` | `docs/blocks.md` RPC table | S | P1 |
| W6 | **Time-edge vectors:** (a) `now + 360` accepted, `+361` refused and not stored, the same header accepted later with `now + 1`; (b) MTP on two branches with different timestamps (branch-local); (c) an FTL break mid-batch in pre-check with a stored prefix; (d) a pinned single-FTL-stamp transient (about −9%) and its recovery; (e) proptests: `median` and `next_difficulty` never panic on arbitrary `u64` sequences, and MTP is invariant to input order | new `consensus/tests/time_edges.rs` (04, no conflict with `golden.rs`); proptest harness shared with 41 | none (tests pin current behaviour) | none | these | `docs/consensus.md` §5 references | M | **P1** (vectors frozen with P0-2 by 01) |
| W7 | **p2p and replay regressions:** a future header is not penalized and is retried and accepted after the clock advances (injectable clock); replay with a clock 1 h behind the stored tip succeeds (`replay_ignores_the_local_clock`) | `p2p/tests/time.rs` (new, 04); `chain/tests/manager.rs` (one test; coordinate with 35) | none | none | these | — | S–M | P1 |
| W8 | **LWMA timestamp-strategy harness in Rust:** the strategy families of §3 P1 with fixed seeds; assert ≤ +1% blocks/h over honest; long mode `#[ignore]`d | owned by **03** (difficulty harness); 04 supplies the strategies and the scratch results | none | none | simulation | R1-C8 re-rating in the register | M | P2 |
| W9 | Stale-`now` refresh per PoW chunk in `verify_headers` (F4) | `p2p/src/net.rs` (31 owns; one line) | none | none | covered by W7 | — | S | P3 |
| W10 | `saturating_add` for `min_timestamp` (F5) | `consensus/src/chain.rs:302` (01 owns) | none for reachable inputs; review as consensus-adjacent | none | a unit test with `u64::MAX` timestamps | — | S | P3 |
| W11 | Genesis procedure additions: the generating machine's clock is NTP-checked (`generate` compares against it); the tool prints the reveal window and the free-fork depth budget; `T_g` no more than about 4 h before the expected launch | `docs/testnet-v3-genesis.md` §4/§6; `tools/genesis/src/*` (**40** owns) | none | v3 (procedure only) | tool test for the printed budget | that document | S | P1 |

**Benchmarks:** none. The `ClockMonitor` costs O(25) per accepted live header.

## 6. Dependencies and conflicts

- **01 consensus-core:** the rule table rows for MTP and FTL; `chain.rs:302` (W10); freezing the W6 vectors with P0-2.
- **03 difficulty-lwma:** owns the LWMA simulation (W8) and the R1-C8 re-rating. My scratch results are an input.
- **09 mining-templates:** W5 touches `miner/src/*` and the template RPC. Co-own it, or 09 implements it to my specification.
- **30, 31, 34:** `p2p/src/net.rs` is contended. W2 and W3 keep the logic in a new `p2p/src/clock.rs` and add only small hooks in `net.rs`, so merge ordering matters. 31's stale-tip detection could consume the monitor's negative-offset signal.
- **35 storage-recovery:** the replay-independence test (W7).
- **36 rpc-security:** the additive `Info` and `Template` fields; they are local RPC only.
- **40 testnet-genesis:** W11; the residual in F11.
- **41 fuzzing-property-stateful:** proptests (W6e).
- **43, 50:** labnet `--clock-offset` chaos (W2) for the P1-15 ±FTL runs.
- **47 docs-spec-consistency:** W1 overlaps with the R1-C11 cleanup.
- **28 private-contracts-px:** any function clock must be height-based, not timestamp-based.

## 7. Open questions for the coordinator

1. **Should the start-up check refuse, or only WARN, when `now < genesis.timestamp`?** I recommend refuse: a node with such a clock can validate nothing live.
2. **Should the miner refusing to mine at more than FTL/2 skew be the default, or opt-in?** I recommend the default, with an override flag.
3. **Should R1-C8 be downgraded to Low on the simulation evidence now, or only after 03's Rust harness?**
4. **Should the `--clock-offset-secs` debug flag be regtest-only?** I recommend yes; it must never be offered as a way to "fix" a clock on testnet.
5. **Is W3 wanted before the seven-device trial (P1), or is NTP plus the checklist (W1) enough for trusted operators?** SX2 put NTP at P0 procedure and the detection at P2. Given Windows STS and the 7-day poll, I recommend P1.

## 8. Sources

- Bitcoin Core PR #28956, "Nuke adjusted time from validation": https://github.com/bitcoin/bitcoin/pull/28956
- Bitcoin Core PR #29623, "Simplify network-adjusted time warning logic": https://github.com/bitcoin/bitcoin/pull/29623
- Bitcoin Core `src/node/timeoffsets.h` and `.cpp` (MAX_SIZE 50, WARN_THRESHOLD 10 min): https://github.com/bitcoin/bitcoin/blob/master/src/node/timeoffsets.h
- Bitcoin Core 27.0 release notes (adjusted time removed from consensus; warning kept): https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-27.0.md
- BIP 54, Consensus Cleanup (timewarp and Murch–Zawy rules): https://github.com/bitcoin/bips/blob/master/bip-0054.md
- Monero `src/cryptonote_config.h` (FTL 2 h, timestamp window 60): https://github.com/monero-project/monero/blob/master/src/cryptonote_config.h
- Monero `src/cryptonote_core/blockchain.cpp` (`check_block_timestamp`, `get_adjusted_time`): https://github.com/monero-project/monero/blob/master/src/cryptonote_core/blockchain.cpp
- zawy12, LWMA difficulty algorithm (#3): https://github.com/zawy12/difficulty-algorithms/issues/3
- zawy12, Timestamp Attacks (#30): https://github.com/zawy12/difficulty-algorithms/issues/30
- zawy12, Best difficulty algorithm, timestamp rules, selecting N (#76): https://github.com/zawy12/difficulty-algorithms/issues/76
- T. Kohno, A. Broido, K. Claffy, "Remote Physical Device Fingerprinting", IEEE S&P 2005 / IEEE TDSC: https://www.caida.org/catalog/papers/2005_fingerprinting/KohnoBroidoClaffy05-devicefingerprinting.pdf
- S. J. Murdoch, "Hot or Not: Revealing Hidden Services by their Clock Skew", ACM CCS 2006: https://murdoch.is/papers/ccs06hotornot.pdf
- A. Malhotra, I. Cohen, E. Brakke, S. Goldberg, "Attacking the Network Time Protocol", NDSS 2016: https://eprint.iacr.org/2015/1020
- RFC 8915, Network Time Security for NTP: https://www.rfc-editor.org/rfc/rfc8915
- A. Riard, G. Naumenko, "Time-Dilation Attacks on the Lightning Network", 2020 (eclipse-based delay, relevant to the monitor's threat model): https://arxiv.org/abs/2006.01418
- Microsoft Learn, "Secure Time Seeding recommendations for Windows Server": https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/sts-recommendations-for-windows-server
- Microsoft Learn, "Time service does not correct the time" (SpecialPollInterval 604,800 s default): https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/specialpollinterval-polling-interval-time-service-not-correct
- S. Lee, H. Kim, "Inside Qubic's Selfish Mining Campaign on Monero", arXiv 2512.01437 (block attribution context): https://arxiv.org/abs/2512.01437
- The scratch simulation (not in the repository): `lwma_sim.py` and `lwma_sim2.py` in the agent's scratchpad. The coordinator can request them for 03.
