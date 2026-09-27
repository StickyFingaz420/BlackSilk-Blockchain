# v3 consensus changes (phase 2 record)

One section per consensus change of the testnet v3 rule set (phase 2, from 2026-09-27).
Each section follows the consensus-change record of the phase-2 implementation brief:
problem; demonstrated failure; prior art; alternatives; affected components; activation;
compatibility; reorg, wallet, mining and P2P implications; vectors; tests; suite results;
open review points; plus identity impact, documentation and review status (15 steps).
Internal engineering record, not an audit.

The testnet has not launched; every change here activates as a v3 genesis base rule
(the v3 reset), not at a height.

---

## daa-lwma75-warm: LWMA-75 with a counted clock of step T/2, warmed over 11 blocks

Owner: W1-CB-A (consensus bundle). Decisions: "Agent 03", "DAA update", "DAA DECIDED",
"DAA FINAL (after RT-DAA)". Rule id `lwma1-n75-step-t/2-warm11-cap6t-floor20`
(`consensus::difficulty::DIFFICULTY_RULE_ID`).

1. **Problem.** The pre-v3 rule (LWMA-60, counted clock `prev + 1`) lets a private branch
   with compressed timestamps raise its own difficulty by about 17% per block (5–20× per
   block near genesis), concentrating the branch's work in a few very hard blocks. Under
   most-work fork choice, the probability that such a branch overturns `z` confirmations
   stops shrinking with `z` (Bahack's difficulty-raising attack; dossier 03-F1, High). The
   first replacement candidate (LWMA-75 with a counted-clock step of `T/2`, W0-03b) then
   failed the emission criterion under the red team (RT-DAA RT-1): the clock restarted at
   the raw stamp of each window's oldest block, so a low stamp there let a window count
   real time its predecessor had not counted.
2. **Demonstrated failure.**
   - 03-F1 on the pre-v3 rule: `tools/daa-sim/tests/f1.rs`
     (`f1_difficulty_raising_attack_reproduces_on_the_current_rule`) and the tables in
     `docs/evidence/daa-sim-2026-09-27/`.
   - RT-1 on the unwarmed candidate: `tools/daa-sim/tests/redteam.rs`
     (`anchor_lag_attack_and_fix`, `periodic_attack_and_fix`).
   - On the consensus code at base `32054d4`, the red-team golden case (87 on-target
     blocks at D = 10^6, the window's oldest stamp 1 300 s low) evaluated with N = 75
     returns the unwarmed value: `consensus/tests/lwma_warm.rs`
     `window_start_lag_golden_case` failed with `left: 998248, right: 999824`.
3. **Prior art.** Bahack 2013 (arXiv:1312.7013); Garay–Kiayias–Leonardos, CRYPTO 2017
   (the dampening filter τ); zawy12 LWMA-1 (issue #3) and timestamp attacks (issue #30);
   BCH aserti3-2d; Zcash §7.7.3 (averaging window with damping); Monero's sorted and cut
   window. Full citations in dossier 03 §8.
4. **Alternatives.** 29 candidates in the selection study (`selection.md`): symmetric
   solve-time clamps, rise and fall caps of 2–3%, weighted-sum floors, ASERT with
   half-lives of 45 min to 6 h, an LWMA/ASERT hybrid, signed solve times, and the counted
   clock with steps T/3 to 2T/3 at N = 60, 75, 90. Only LWMA-75 with step T/2 met every
   criterion on two seeds. The red team compared warm-up lengths 0, 1, 11 and 75
   (`anchor_ablation`): 11 removes the anchor-lag gain, 75 buys nothing more.
5. **Affected components.**
   - `consensus/src/difficulty.rs`: the rule, `DIFFICULTY_WINDOW` (75),
     `DIFFICULTY_WARMUP` (11), `difficulty_ancestors(N)` (N + 1 + 11 = 87),
     `clock_step`, `DIFFICULTY_RULE_ID`.
   - `consensus/src/params.rs`: `difficulty_window = DIFFICULTY_WINDOW` on every network;
     `ChainParams::difficulty_ancestors()`, the one ancestor count.
   - `consensus/src/chain.rs`: both callers, `required_difficulty` (validation, templates,
     replay and submission all go through `HeaderChain`) and `overlay_context` (the batch
     pre-check of header sync), fetch `difficulty_ancestors()`. No other crate computes a
     difficulty (repository-wide grep for `next_difficulty` and `difficulty_window`).
   - `tools/daa-sim`: the pre-v3 rule is frozen as `rules::legacy_next`, so the committed
     evidence stays reproducible; `ConsensusV3` calls the new consensus rule.
6. **Activation.** A v3 genesis base rule from height 1 on every network. No height
   switch.
7. **Compatibility.** Every difficulty after block 1 differs from the pre-v3 rule, so
   no pre-v3 chain validates under v3. The testnet v2 identity is retired and the v3
   genesis is not yet generated; regtest chains are local and are recreated. Genesis ids
   are unchanged (the rule is not in the header).
8. **Reorg, wallet, mining and P2P implications.**
   - Reorg: the rise per block is bounded at `⌊S·T/(step·n)⌋` (2× the window average), so
     a compressed branch cannot concentrate work; the residual race excess at q = 0.4 is
     left to the park-on-deep-reorg policy (02).
   - Mining: the template difficulty comes from the same function; miners need no change.
   - P2P: the claimed-work gate is unchanged. The presync bound (31) must be re-derived
     with a rise of at most 2× the window average per block.
   - Wallet: none (no wallet code computes a difficulty).
   - Liveness: after a genesis gap the difficulty recovers additively at low difficulty
     (+8 per block from 16 in `genesis_to_launch_gap_is_absorbed_by_lwma`). Settling after
     100× or 1000× hash-rate increases takes a few hundred blocks (`redteam.md`, RT-6).
9. **Vectors.**
   - `consensus/tests/data/lwma_vectors.txt`: 159 vectors from
     `tools/vectors/lwma_warm.py`, a standard-library Python script written from the spec
     text (docs/consensus.md §4), not from the Rust. It covers steady state (7
     difficulties, 4 targets), 2×/10× up and down (whole window and step changes of 1–75
     blocks), genesis-near windows of 1–89 ancestors, the 1-second-block run on regtest
     and testnet timing (including a chain grown from D = 1), the genesis gap (4 gaps and a
     40-block recovery), warm-up edge cases (low and high stamps at positions 0–20, the
     88th ancestor ignored, partial warm-ups of 77–86), the 6T cap and step boundaries,
     u128 extremes (difficulties and stamps at u64::MAX, T = 2^51 − 1, T = 1, 2, 3), and 40
     random adversarial histories. `--check` regenerates and compares.
   - The red-team golden case: this exact configuration (87 ancestors) takes the warm-up,
     so **999 824** applies; the unwarmed value 998 248 applies only when the 11 warm-up
     ancestors are absent (vector `redteam_lag_1300_nowarm`, 76 ancestors). Note: the
     stamp sequence is a function vector; in a steady chain the MTP rule would refuse a
     stamp that low (lowest valid: `ts[5] + 1`), and an attacker reaches the same lag with
     earlier forward stamps.
10. **Tests.**
    - `consensus/tests/lwma_warm.rs`: `window_start_lag_golden_case`,
      `independent_vectors` (all 159).
    - `tools/daa-sim/tests/consensus_differential.rs`:
      `consensus_equals_the_warmed_redteam_rule`: consensus `next_difficulty` (on the whole
      history and on exactly the 87 fetched ancestors) and `ConsensusV3` equal
      `redteam::Anchored { window: 75, warm: 11 }` on 12 000 random histories (lengths
      1–200, 76–88 and 1–88 emphasized; T from 1 s to 2^40 s; stamps at the MTP and FTL
      edges, equal, backwards, and near u64::MAX; difficulties up to u64::MAX). 2 059 of
      them differ from the unwarmed rule, so the test discriminates.
      `every_network_uses_the_measured_window`.
    - `consensus/src/difficulty.rs` unit tests (exact steady state, 2× and ½×, the step
      bound, ancestor count, rule id names the constants).
    - `consensus/src/chain.rs`: `precheck_agrees_with_sequential_validation_and_computes_no_pow`
      now mutates at positions 11, 12, 74–77 and 86–88 (the window and warm-up edges).
    - Re-derived expected values (each changed value explained):
      - `consensus/tests/golden.rs`: N = 60 → 75 throughout. Steady state and 2×/½× stay
        exact (hand derivations with Σi = 2 850). `lwma_only_the_last_window_counts`: the
        warm-up now reads 11 blocks before the window, so the steady case needs 86 steady
        blocks, and a new assertion pins 10 092 for 7 s blocks just before the window
        (clock 583 s ahead). `lwma_window_fill_phase`: 400 → 200 and 2 000 → 200 (a 30 s
        or 0 s solve time counts one step of 60 s); 844 unchanged (every solve time ≥ 60).
        `lwma_out_of_order_timestamps`: 131 → 141 (hand derivation in the test) and
        5 083 → 1 000 (every solve time counts one step). The floor test becomes
        `lwma_increase_is_bounded_by_the_step`: 101 666 → 20 000 (the floor no longer binds;
        the step does). Clamps unchanged. `lwma_mixed_window` (now 75 blocks): 914 from the
        script. `header_chain_difficulty_and_mtp_golden`: all 150 difficulties and the total
        work (242 100 → 153 943) from the script; the MTP values are unchanged, which
        cross-checks the script's chain model.
      - `tools/genesis/tests/genesis.rs` (`genesis_to_launch_gap_is_absorbed_by_lwma`): block 2
        stays 16 (the 6T cap); the climb is now pinned exactly (24, 32, 40, 48, 56; D0/2 at
        k = 4) instead of "within the window".
      - `tools/daa-sim`: `lwma60_is_the_pre_v3_rule` (was `lwma60_is_the_consensus_call`),
        `generalised_default_equals_the_pre_v3_rule`, the new `consensus_v3_is_the_consensus_call`,
        and `constants_match_consensus` (window 75).
11. **Suite results** (this change, release, `--locked`, Windows x86_64, rustc 1.98.1):
    - `-p blacksilk-consensus`: 59 passed (lib 38, golden 17, lwma_warm 2,
      randomx_end_to_end 2).
    - `-p blacksilk-daa-sim`: 37 passed (lib 23, consensus_differential 2, f1 2, redteam 5,
      selection 5).
    - `-p blacksilk-genesis`: 10 passed.
    - `-p blacksilk-node`: 40 passed, 2 ignored (after re-pinning the fingerprints).
    - `-p blacksilk-p2p` (skipping the two PX-proving tests): 80 passed, 4 ignored.
    - `-p blacksilk-chain -- --skip restart_rebuilds_the_px_state_exactly`: 111 passed,
      **1 failed**, 2 ignored: `chain/tests/revalidation.rs`
      `a_shorter_heavier_reorg_makes_a_ring_member_immature`. Its construction (80
      one-second blocks, then three 60 s blocks against a two-block fast rival) no longer
      lowers the difficulty: the one-second blocks put the counted clock about 320 s ahead
      of the stamps, and 60 s gaps only repay that lag (difficulties `[84, 86, 88, 90]`),
      which is the rule working as intended. The file belongs to branch w1-tx-a, so it is
      not edited here. A re-derived construction (four 1 000 s blocks against a
      three-block one-second rival, deepest reorg 4; work 260 against 264, found with
      `lwma_warm.py`) passes all 4 tests of the file when applied locally; it is handed
      to the coordinator.
12. **Open review points.**
    - The floor `n²T/20` cannot bind under this rule (`L ≥ step·n(n+1)/2`), so mutants of
      the floor survive by construction: to be justified in 42's mutation run.
    - The hopper criterion is relaxed to ±5 points for the testnet only (decision "DAA
      FINAL"); reopen before any mainnet.
    - 31 must re-derive the presync bound under the 2× per-block rise.
    - Fingerprint: `DIFFICULTY_RULE_ID` is not yet in the manifest (see step 13).
13. **Identity impact.** The consensus fingerprint's `chain.difficulty_window` entry
    changes (60 → 75) on every network, so the pinned fingerprints in
    `node/tests/deploy_configs.rs` are re-pinned in this change. The rule id is **not**
    wired into `node/src/fingerprint.rs` (owner 40, the single fingerprint-v3 commit): it
    belongs in `chain_entries` next to `chain.difficulty_window`, as a text entry
    `chain.difficulty_rule = DIFFICULTY_RULE_ID` (with `DIFFICULTY_WARMUP` if the
    manifest keeps numeric entries), and `lwma_warm.rs`'s golden case is a candidate
    `rules.samples` entry.
14. **Documentation.** `docs/consensus.md` §1 (N = 75), §4 (rewritten: the rule, exact
    semantics, deviations from zawy's reference, known limits, vectors) and §5 (the
    regtest `N·T/20` figure), in this change.
15. **Review status.** Selection (W0-03b) and red team (RT-DAA) done on the harness
    rule; this change is shown equal to the red team's `Anchored` rule by the differential
    test. The consensus implementation has not had a separate adversarial review.

---

## f05-header-check-order: permanent header rules before the future time limit

Owner: W1-CB-A. Decisions: "Agent 01" (F-05 reorder accepted before the freeze).

1. **Problem.** `check_rules` checked the future time limit (FTL, not permanent: it
   depends on the local clock) before the difficulty rule (permanent). A header with a
   wrong difficulty and a far-future timestamp was reported as
   `TimestampTooFarInFuture`: unpenalized and re-evaluated later. A peer could wrap any
   permanently invalid header this way to avoid scoring (dossier 01 F-05, Low).
2. **Demonstrated failure.** On base `32054d4`, the new vector test
   `chain::tests::header_check_order_vectors` failed at its first row:
   `difficulty + future: TimestampTooFarInFuture { limit: 1700000680, got: 1700010320 }`.
3. **Prior art.** Bitcoin Core `ContextualCheckBlockHeader`: `bad-diffbits`,
   `time-too-old` and the time-warp checks are `BLOCK_INVALID_HEADER` first, then
   `time-too-new` as `BLOCK_TIME_FUTURE`.
4. **Alternatives.** Keep the order and document it (a second implementation must copy it
   to score identically); or return every failing rule (a larger API change). Rejected:
   the reorder is smaller and makes the scoring order-independent of clock skew.
5. **Affected components.** `consensus/src/chain.rs::check_rules` (the single definition
   used by `validate` and `precheck_batch`). New order: version, height, difficulty, MTP,
   FTL, then PoW in `validate`.
6. **Activation.** v3 genesis base rule set (policy-visible only).
7. **Compatibility.** Validity is unchanged: a header is valid iff every rule holds, and
   the conjunction does not depend on the order. Only the reported error, and so P2P
   scoring, changes for headers that break both a permanent rule and the FTL.
8. **Reorg, wallet, mining and P2P implications.** P2P: such headers are now penalized
   (`BadDifficulty` and `TimestampTooOld` are permanent). A header that is only too far in
   the future is still unpenalized. No reorg, wallet or mining effect.
9. **Vectors.** `header_check_order_vectors`: 7 rows of mutation sets and their
   first-failing error (difficulty + future, difficulty + too old, height + difficulty,
   height + future, too old, future, difficulty) plus the FTL-before-PoW case, each
   checked for `validate` and `precheck_batch` and for permanence.
10. **Tests.** The vector test above; the existing
    `precheck_agrees_with_sequential_validation_and_computes_no_pow` and
    `rejects_each_invalid_field` still pass unchanged.
11. **Suite results.** `-p blacksilk-consensus`: 63 passed (lib 42, golden 17, lwma_warm 2,
    randomx_end_to_end 2). Wider suites: see the RT-1 section (run once on the final
    branch).
12. **Open review points.** 30/31: scoring of the new first errors is the existing
    `penalized()` classification; no p2p change was needed.
13. **Identity impact.** None (no constant or genesis change).
14. **Documentation.** `docs/consensus.md` §6 (the order and why it does not change
    validity), in this change.
15. **Review status.** Internal; the validity-invariance argument is the conjunction.

---

## genesis-beacon: the genesis nonce is derived in consensus from a committed beacon

Owner: W1-CB-A. Decisions: "Agent 40" (nonce derived in consensus from the committed
beacon; `GenesisSpec`/`Beacon`; `genesis_is_final()`; no pasted nonce, no runtime
override). Dossier 40 F40-2 (Medium).

1. **Problem.** `ChainParams::base` hard-coded `nonce: 0`, and the ceremony tool printed
   a `TESTNET_GENESIS_NONCE` constant to paste into consensus code at launch: the final
   commit would have been a structural consensus edit under time pressure, and nothing
   tied a pasted nonce to its announced beacon (F40-2).
2. **Demonstrated failure.** Source-level: `params.rs` had no place for a beacon, and
   `tools/genesis::rust_constants` emitted a nonce constant. No test could assert
   "testnet nonce == derive(beacon)" (R15 §4.4 test 2 did not exist).
3. **Prior art.** Zcash's genesis carries public not-before data and `chainparams.cpp`
   asserts the genesis hash; Ethereum Frontier derived its genesis from an announced
   script plus a public block hash (dossier 40 §3 P1).
4. **Alternatives.** Paste the nonce plus a test that recomputes it (two values that can
   disagree until the test runs); a runtime `--genesis-beacon` flag (rejected by the
   decision: any operator could run a private genesis under the real id).
5. **Affected components.**
   - New `consensus/src/genesis.rs`: `NONCE_DOMAIN`, `nonce_preimage`,
     `nonce_preimage_digest`, `derive_genesis_nonce`, `parse_display_hex`, `Beacon`,
     `GenesisSpec` (`nonce`, `is_final`, `header`).
   - `consensus/src/params.rs`: `TESTNET_BEACON = None`, `MAINNET_BEACON = None`;
     `base()` builds the genesis from the spec; `ChainParams::genesis_spec()`,
     `genesis_is_final()`; `check()` refuses a nonce that disagrees with the beacon.
   - `tools/genesis`: re-exports the consensus derivation (its own copy removed), builds
     its header through `GenesisSpec`, and `rust_constants` now prints the
     `TESTNET_BEACON` value to commit, never a nonce constant.
6. **Activation.** Genesis construction only; no validity rule.
7. **Compatibility.** No beacon is committed on any network, so every nonce stays 0 and
   the testnet (v2, retired), regtest and mainnet genesis ids are byte-identical
   (`genesis_ids_are_pinned`, `genesis_ids_golden` unchanged).
8. **Reorg, wallet, mining and P2P implications.** None now. At launch the final commit
   changes `TESTNET_BEACON` (and the network id, genesis time and D0 per
   docs/testnet-v3-genesis.md) and the pinned ids and fingerprints.
9. **Vectors.** The tool's known answer (Bitcoin block 0, H = 0, id `0x0001D673`: digest
   `3c437d97…`, nonce `0x351e3bcf977d433c`, independently recomputed in Python by
   dossier 40) now also pinned in consensus (`genesis::tests::known_answer_bitcoin_block_0`).
10. **Tests.** `genesis::tests`: known answer, preimage layout, strict display hex, nonce
    from a dummy beacon (every input moves it; finality follows the beacon; a local
    network needs none). `params::tests`: `genesis_finality_follows_the_committed_beacon`,
    `a_committed_beacon_derives_the_nonce` (dummy beacon, test only),
    `check_refuses_each_broken_invariant` (a pasted nonce). `tools/genesis`: all 10
    existing tests pass through the consensus derivation; `rust_constants` emits a beacon,
    no nonce constant, and the tool's header equals `GenesisSpec::header`.
11. **Suite results.** `-p blacksilk-consensus` lib 49 passed; `-p blacksilk-genesis` 10
    passed. Wider suites: see the RT-1 section.
12. **Open review points.**
    - Not wired in this branch (outside the "consensus and tools/genesis" scope of the
      assignment): `node/src/config.rs` still gates the testnet on its own
      `TESTNET_GENESIS_FINAL = false`; it should call `ChainParams::genesis_is_final()`
      (40 item 3), as should the wallet, miner, supply-audit and labnet (F40-5).
    - The tool's registry semantics, the reserved test-vector id and the rehearsal range
      (F40-1, F40-11) are 40's item 2 and unchanged here.
    - No final genesis is generated; the dummy beacon exists only in tests.
13. **Identity impact.** None now (ids unchanged). The final commit is data-only:
    `TESTNET_BEACON: None -> Some(..)` plus the announced constants and pins.
14. **Documentation.** `docs/consensus.md` §1 (genesis construction and finality), in
    this change.
15. **Review status.** Internal; the derivation is the tool's, moved and cross-checked by
    the unchanged tool tests.

---

## rt1-unknown-upgrade-pow: UnknownUpgrade only for headers with real proof of work

Owner: W1-CB-A. Decisions: "Agent 50" RT-1 (adopted: `UnknownUpgrade` only for PoW-valid
headers; disconnect without a ban after N; operator warning only past a peer or work
threshold).

1. **Problem.** `check_rules` returned `UnknownUpgrade` for any header whose version
   exceeded the schedule's maximum, before proof of work. P2P does not penalize it and
   warned the operator once per peer. So a peer could stream unknown-version headers at
   zero hash cost, never be scored, keep its slot, and make any single inbound connection
   raise an "upgrade needed" warning (a social-engineering lever) (dossier 50 RT-1,
   Medium).
2. **Demonstrated failure.** On base `32054d4`, `chain::tests::unknown_upgrade_needs_valid_proof_of_work`
   failed: a newer-version header with junk proof of work returned
   `left: UnknownUpgrade { version: 7 }, right: InsufficientWork`.
3. **Prior art.** Bitcoin Core warns about unknown rules only from PoW-valid blocks of its
   own chain and only past a signalling threshold (`WarningBitsConditionChecker`, PR
   #16713); it never warns from one peer's unverified header.
4. **Alternatives.** Penalize every unknown version (breaks the upgrade signal of honest
   newer peers); keep it free but rate-limit (still free spam and a single-peer warning).
5. **Affected components.**
   - `consensus/src/chain.rs`: an unknown version is `BadHeight` if the height is wrong,
     else `UnknownUpgrade` from `check_rules` (unconfirmed); `validate` then checks the
     RandomX hash against the difficulty this node requires at that position (not the
     header's claimed difficulty) and returns `InsufficientWork` if it fails.
     `precheck_batch` (no PoW) reports it unconfirmed; the doc of
     `HeaderError::UnknownUpgrade` says so.
   - `p2p/src/net/headers.rs` (`verify_headers`): the unconfirmed header is included in
     the `worth_verifying` gate, hashed off the chain lock after its prefix, and
     classified by `validate`; `note_unknown_upgrade` replaces the per-peer warning.
   - `p2p/src/net/state.rs`: `Peer::unknown_upgrades`, `State::upgrades`
     (`UpgradeReports`), `UNKNOWN_UPGRADE_DISCONNECT = 3`, `UNKNOWN_UPGRADE_WARN_PEERS = 2`.
   - `p2p/src/net/blocks.rs`: the block path uses `note_unknown_upgrade` (its header is
     already PoW-confirmed by `validate`). `p2p/src/net.rs`, `conn.rs`: field init.
6. **Activation.** Node policy with the v3 rule set; the final verdict (header rejected)
   is unchanged.
7. **Compatibility.** No validity change: every such header was and is rejected. Only the
   error class of an unknown-version header with junk PoW (now permanent), and scoring,
   change. If a future upgrade changes the proof of work, old nodes see
   `InsufficientWork` for the new headers; they must upgrade then anyway.
8. **Reorg, wallet, mining and P2P implications.**
   - P2P: an unknown-version header costs the sender real work at our difficulty. A peer
     sending 3 of them is disconnected, never banned. The operator is warned once, when
     2 distinct peers reported one or one extends a branch reaching our best work. An
     unknown-version header on a low-work branch fails `worth_verifying` first (no hash,
     no warning).
   - Cost to us: one RandomX hash per unknown-version header that passes the work gate,
     the same as any other well-formed header.
   - No reorg, wallet or mining effect.
9. **Vectors.** `header_check_order_vectors` (F-05 section) and the RT-1 tests below.
10. **Tests.**
    - `consensus/src/chain.rs`: `unknown_upgrade_needs_valid_proof_of_work` (junk PoW:
      `InsufficientWork`, permanent; real PoW: `UnknownUpgrade`, not permanent; a header
      claiming difficulty 1 still needs the required work; a known wrong version stays
      `BadVersion`; a wrong height is `BadHeight`). `rejects_each_invalid_field` now grinds
      its unknown-version header to real work. `precheck_agrees_with_sequential_validation_and_computes_no_pow`
      states the confirmation: the pre-check's `UnknownUpgrade` is confirmed by `validate`
      to `UnknownUpgrade` or `InsufficientWork` exactly as the PoW decides.
    - `p2p/src/net/state.rs`: `upgrade_reports_warn_past_a_threshold_and_disconnect_after_n`.
    - `p2p/tests/network.rs`: `unknown_version_headers_need_real_proof_of_work` (junk PoW
      at the end of a requested batch: the peer is penalized and disconnected, the prefix
      stored; real PoW as tip announcements: score 0, still connected after 2, disconnected
      at the 3rd without a penalty or a ban).
11. **Suite results.** Final branch state (all six items), release, `--locked`, Windows x86_64,
    rustc 1.98.1, PX-proving tests skipped (`restart_rebuilds_the_px_state_exactly`,
    `px_transactions_travel_the_stem_and_confirm_everywhere`,
    `invalid_px_transactions_get_the_relaying_peer_penalized`):
    - `blacksilk-consensus`: 71 passed (lib 50, golden 17, lwma_warm 2, randomx 2).
    - `blacksilk-daa-sim`: 37 passed. `blacksilk-genesis`: 10 passed.
    - `blacksilk-node`: 40 passed, 2 ignored.
    - `blacksilk-p2p`: 82 passed, 4 ignored, 2 skipped (PX).
    - `blacksilk-chain`: 111 passed, **1 failed** (`revalidation.rs`
      `a_shorter_heavier_reorg_makes_a_ring_member_immature`, the DAA-dependent
      construction explained in the daa-lwma75-warm section, step 11), 2 ignored,
      1 skipped (PX).
    - `cargo clippy --locked -p blacksilk-{consensus,daa-sim,genesis,node,p2p,chain}
      --all-targets -- -D warnings`: clean. `cargo fmt --all -- --check`: clean.
12. **Open review points.**
    - `docs/p2p.md` §6 still describes the per-peer warning; it was on branch w1-tx-a's
      file list, so it is not edited here (one paragraph for the coordinator: the §11
      rules of docs/consensus.md, as updated here).
    - The thresholds (3 reports, 2 peers) are policy constants; 30/31 may tune them.
    - The warning is not rate-limited beyond "once per run".
13. **Identity impact.** None.
14. **Documentation.** `docs/consensus.md` §6 item 1 and §11 (network-layer rules), in
    this change.
15. **Review status.** Internal; implements the red team's fix (a)–(c).
