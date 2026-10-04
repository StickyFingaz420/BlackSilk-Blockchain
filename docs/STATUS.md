# BlackSilk status

**This file is the single status source of the project** (decision "Agent 47",
[phase-2 decisions](reviews/phase2-2026-09-27/decisions.md)). Other documents link here
instead of stating status themselves; a status line anywhere else is historical.

- **As of:** `rebuild/core` at `a144d94`, reconciled row by row against the code and
  the decisions after the second threat-model round (2026-10-02), plus the branch
  that last edited this file (see `git log -- docs/STATUS.md`). Every entry names its
  evidence; an entry without evidence in the repository says so.
- **What this is:** internal engineering work. BlackSilk has had **no external audit
  and no independent review**, none is engaged, and none is planned (owner decision
  2026-09-25, [review-status.md](reviews/review-status.md)). This file does not claim
  that BlackSilk is secure, nor that it is ready for anything of value. Zero knowledge
  is claimed only
  as statistical and conditional, and computational in practice, because the masks
  are PRG (ChaCha) outputs ([zk-coverage.md](reviews/zk-coverage.md)).
- **How to update:** change a row in the same commit as the work it describes, with
  its evidence (a commit, a test name, a file under `docs/evidence/`, or a section of
  [v3-consensus-changes.md](reviews/v3-consensus-changes.md)). Do not copy measured
  values, fingerprints or test counts here; link their source. `doc-lint`
  (`.github/scripts/doc-lint.sh`) checks the claims, links and copied digests; it
  cannot see a row that has gone stale, so a merge that closes or changes a row
  edits it in the same commit.

**Status classes** (phase-2 brief): Complete and verified · Complete but requires
further testing · Partially implemented · Not implemented · Deferred · Blocked ·
Accepted limitation. "Complete but requires further testing" is the highest class any
v3 item has before the protocol freeze: the freeze gates (§5) and the red-team rounds
are still open ([waves.md](reviews/phase2-2026-09-27/waves.md)). "Decided" in a row
means recorded in the decisions log; it says nothing about code.

## 1. Network identity and launch

| Item | Status | Evidence |
|---|---|---|
| Testnet v2 identity (`0x0001D672`) | **Retired** (2026-09-27): this tree enforces rules v2 builds do not | [testnet.md](testnet.md) status block; `node/src/config.rs` (`retired_testnet_identity_is_refused_until_v3`) |
| Testnet | **Disabled**: `blacksilk-node --network testnet` refuses to start until the v3 genesis is final (no beacon committed: `TESTNET_BEACON` is `None`) | `ChainParams::genesis_is_final` (`consensus/src/params.rs`); W2-36b merge `a2c4d1f` |
| Seven-device trial | **Blocked**: not authorized. Needs the protocol freeze, the v3 genesis, the owner's approval and the preconditions of [testnet-v3-genesis.md](testnet-v3-genesis.md) §6 step 0 (D0, the two-channel commit id, the network pre-shared key, the endpoint checklist) | [testnet-v3-genesis.md](testnet-v3-genesis.md) §6 |
| Fingerprint v3 (rules and identity split, rule samples, rule revisions) and the testnet v3 network id `0x0001D673` (agent 40, one commit) | Complete but requires further testing. Red team RT-FP3: construction sound, coverage not; its P0 and P1 items are implemented and accepted (FX-RTFP3): RandomX configuration read from the crate with a pinned known answer, consensus hash tags, crypto, tree, transcript and FTL/clamp samples, verdict samples on a pinned fixture transfer, `Revision:` lines tied to `REVISIONS`. Each of the seven red-team mutations changes the rules fingerprint (`tools/fingerprint-mutations.sh`). Eligible for the freeze subject to the freeze gates (§5). The golden PX fixture (merge `5d3d96f`) adds PX and deploy samples: ids, binding, signature message, weight, size and the stateless PX verdicts, `R` rule included. PX5 (full verification, kept out of the manifest for startup cost) is pinned by `node/tests/px_fixture.rs` instead. Rules that only a later PX stage or a full block reaches (PX6, the pool, B1–B8) are still covered by revision and commit only, not by a verdict sample | [v3-consensus-changes.md](reviews/v3-consensus-changes.md) `fingerprint-v3`, Follow-up (RT-FP3); `node/src/fingerprint.rs` tests; decisions "FX-RTFP3" |
| Consensus fingerprint pins (`px/tests/consensus_fingerprint.rs`, `node/tests/deploy_configs.rs`) | Re-pinned after each reviewed consensus merge. Operators compare `blacksilk-node --version` and `/info` against the release announcement; values are not copied into docs | decisions, "Fingerprint pins during the pre-freeze v3 window"; `fingerprint-v3` (re-pin procedure) |
| `blacksilk-node --print-manifest` (decisions "Agent 47") | Complete but requires further testing: prints both manifests, their encodings and the three fingerprints. An independent recompute script is not in the repository (dossier 40 item 5): Not implemented | `fingerprint::tests::manifest_text_recomputes`; `fingerprint-v3` |
| Dirty-tree mark on the build commit (RTFP3-9) | Complete but requires further testing: `node/build.rs` compares tracked build inputs with the git index (pure Rust, no `git` process); a modified file gives `<commit>-dirty`, and a release build of a dirty tree fails unless `BLACKSILK_ALLOW_DIRTY=1`. Not detected: untracked files and staged-only changes. The miner and wallet have no build script | `node/tests/build_id.rs`; [testnet.md](testnet.md) §2.1 |
| Reproducible node binary (the binary-hash operator check, RTFP3-15) | Partially implemented: on Windows (MSVC) two release builds of one commit on one machine give identical node, miner, wallet and genesis binaries, from different checkout paths and target directories (`-Brepro` in `.cargo/config.toml`). Not shown: across machines, users or toolchain installs, and on Linux or macOS | [repro-windows evidence](evidence/repro-windows-2026-10-01/README.md); [testnet.md](testnet.md) §2, §2.1 |
| Build-path remap (RT-GUARD privacy fix: no build user's home path in a shared binary) | Partially implemented: `tools/release-build.sh` remaps CARGO_HOME, the sysroot and the checkout, and `install-linux.sh` and every procedure in the docs use it. Not done: the Dockerfile and `.github/scripts/build-guard.sh` build without it, and no automated check scans a binary for home paths (`tools/check-build-flags.sh --strings` looks for test-code markers only; the docs give a manual check) | `tools/release-build.sh`; [testnet.md](testnet.md) §2; [repro-windows evidence](evidence/repro-windows-2026-10-01/README.md) |
| Test-only code in shipped binaries (W4-GUARD, RT-STATEFUL, RT-GUARD) | Complete but requires further testing: each crate with a `test-hooks` feature (chain, tx, px and p2p) and chain and p2p for `cfg(fuzzing)` export a marker compiled in only with that code; every BlackSilk binary prints a `build flags:` line in `--version` (the node also in `--print-manifest`, its start-up log and `/info`); the node, miner, wallet and supply audit refuse every network but regtest with a marker, and regtest too with `--require-clean-build`; the genesis tool and the labnet tools refuse to run with one; the node, miner, wallet and genesis builds refuse `cfg(fuzzing)`; the labnet passes `--require-clean-build` and records each binary's hash and version. A test-only feature added later is covered only once its crate exports a marker (`tools/check-test-features.sh`) | `node/tests/build_guard.rs`, `miner/tests/build_flags.rs`, `chain/src/build_flags.rs` tests, `wallet/tests/cli.rs`; CI `test` job, `.github/scripts/build-guard.sh`; CI `gates`, `tools/check-test-features.sh`; [testnet.md](testnet.md) §2 |
| Genesis tool reserved ids and `verify` of the launched id (RTFP3-13, RTFP3-14; F40-1) | Complete but requires further testing: `generate --final` only for `0x0001D673`, `--rehearsal` only for `0x0001D6E0`–`EF`, the test-vector id never; `verify` accepts a registered id only for a built-in network's compiled genesis | `tools/genesis/tests/genesis.rs`; [testnet-v3-genesis.md](testnet-v3-genesis.md) §3 |
| Testnet `D0` measured on reference hardware (genesis gate, F40-12); `T_g` by the two-stage announcement | Not implemented: `D0` and `TESTNET_GENESIS_TIME` in `consensus/src/params.rs` are placeholders | decisions, "Labnet deep reorgs (INV-REORG)", "Agent 40"; [testnet-v3-genesis.md](testnet-v3-genesis.md) §4, §5 |
| Release signing: the owner's signing key, signed tags, a second channel for the release announcement (decisions "Agent 43", F48-4) | Trial uses the two-channel commit id (owner decision 2026-10-02): the exact commit id and the consensus fingerprints on two separate channels, compared by every operator, who builds that commit with `tools/release-build.sh` and recomputes the genesis. Signed tags before a public testnet: Not implemented (the repository has no tags and no signing key) | decisions "Agent 43", "Agent 48", "Threat model round 2"; [testnet.md](testnet.md) §2.1; [testnet-v3-genesis.md](testnet-v3-genesis.md) §6 |
| CODEOWNERS and branch protection (F48-3) | Not implemented (owner tasks): the CI gates are advisory, since a direct push lands before CI runs | decisions "Agent 48"; `.github/workflows/ci.yml` |
| Closed-network pre-shared key (F48-1, W2-30) | Complete but requires further testing: `--network-psk-file` / `[p2p] network_psk_file` mixes a 32-byte key into the session key; a missing or wrong key fails the handshake, unscored. The trial procedure requires it, with generation, distribution and rotation ([testnet.md](testnet.md) §12.3). Not implemented: a "key loaded" field in `/info` (only a start-up log line shows it) | `e9ec2ff`; `p2p/tests/transport_adversarial.rs` (`a_man_in_the_middle_reads_the_traffic_unless_a_psk_is_set`, `only_nodes_with_the_network_psk_connect_and_others_are_not_banned`); `transport::tests::a_psk_session_talks_and_a_missing_or_wrong_psk_fails` |
| Final genesis | **Blocked** until the protocol freeze (never generated before it) | [testnet-v3-genesis.md](testnet-v3-genesis.md) |
| Protocol freeze | Not reached: the freeze gates of §5 are open | [waves.md](reviews/phase2-2026-09-27/waves.md); decisions "Threat model round 2" |

## 2. v3 consensus rule set

Every row is a v3 genesis base rule (no activation height), recorded with the 15-step
discipline in [v3-consensus-changes.md](reviews/v3-consensus-changes.md) under the
section named in the row.

| Item | Status | Evidence |
|---|---|---|
| D8 option B: no cross-transaction one-time-key uniqueness | Complete but requires further testing | §1; `dd8623b` |
| CLSAG auxiliary image `D ≠ identity` | Complete but requires further testing | §2; `f655827` |
| RT-14: genesis id in every signature domain | Complete but requires further testing | §3; `205499c` |
| BS-ZK-3: eight random codewords per committed matrix | Complete but requires further testing; not re-measured on PX proofs (§5, P-5) | "BS-ZK-3"; `73372e9` |
| Canonical proof shape | Complete but requires further testing | "Canonical proof shape"; `43ef877` |
| Soundness figures, `COLLISION_BITS = 122`; circuit digest (RTW1-3/6/8) | Complete but requires further testing. The ePrint 2026/089 adaptation is argued, not proven, and the property claimed is extractability | "Soundness figures"; `0535347`, `be93f71` |
| Difficulty: LWMA-75, counted-clock step T/2, warmed over 11 blocks | Complete but requires further testing. The remaining raising-race excess and the inherited difficulty after a won race are accepted under the majority-hash assumption, not covered by park-on-deep-reorg (correction 2026-10-02 in the record) | `daa-lwma75-warm` (item 8); `163bfa0`; [daa-sim evidence](evidence/daa-sim-2026-09-27/results.md), [redteam.md](evidence/daa-sim-2026-09-27/redteam.md) |
| `ChainParams::check`, F-05 header check order, big-endian refusal | Complete but requires further testing | `f05-header-check-order`; `67c9f69`, `3b2d0dd`, `4040edd` |
| Genesis nonce derived from a committed beacon | Complete but requires further testing; no beacon committed on any network | `genesis-beacon`; `becd6e4` |
| RT-1: `UnknownUpgrade` only for headers with real PoW | Complete but requires further testing | `rt1-unknown-upgrade-pow`; `d30f537`, `2affc89` |
| Exact v1 fee (T8) | Complete but requires further testing | `exact-v1-fee`; `6b1d2d0` |
| R12-2 (a′): PX and deploy v1 parts count toward the block weight | Complete but requires further testing | `r12-2`; `af5418c` |
| PX tree capacity (B8) with 21-D, halting apply, 21-F | Complete but requires further testing | `tree-capacity`; `c40dcca` |
| One approval per contract input (F-20-1) | Complete but requires further testing | `approval-conflict`; `66640ff` |
| Call ABI version and output-word registry (F-28-1) | Complete but requires further testing | `px-call-abi`; `66640ff` |
| PX6 validity window, PX6 before the range proof, expiring-soon policy (RTW1C-4, -5) | Complete but requires further testing | `px6-validity-window` and its Follow-up; `66640ff`, `7281128`; `tx/tests/px_window.rs` |
| Vault v3 (contract-bound locks, hedged blinds, timeout and refund; RTW1C-2, -3, -6, -7) | Complete but requires further testing: rounded windows, a seed-recoverable refund, the docs say it is not an HTLC | `vault-v3` and its Follow-up; `wallet/src/wallet/contracts.rs` tests (`vault_windows_do_not_reveal_the_timeout`, `a_restored_locker_recovers_its_timed_lock_and_can_refund`) |
| Kernel budgets cover every honest shape (RTW1C-1, -8) | Complete but requires further testing: every shape at most 95 % of every table, `prove` refuses an over-budget execution | `kernel-budget-shapes`; `px/tests/kernel_budget.rs` |
| Single v3 kernel and vault rebuild, guest link layout (CI-1) | Complete but requires further testing: byte-identical on windows-latest, ubuntu-24.04 and ubuntu-24.04-arm in CI (run 102); an operator build at the reveal is still owed | `guest-rebuild`; `9fa558f`; `zkvm/guests/README.md` |
| PX proof decode bounds (RT-FUZZ-1, W4-PXDOS) | Complete but requires further testing: every vector capped before allocation, no change to the valid set | `px-proof-decode-bounds` and its Follow-up; merge `8e0d86e`; `zk/tests/decode_bounds.rs` |

## 3. Node, network, wallet and mining

| Item | Status | Evidence |
|---|---|---|
| Authenticated RPC (cookie, limits, `--rpc-allow-host`, `/tx/status`) served by the binary | Complete but requires further testing. Open: a client that holds sockets without authenticating can occupy the 64 shared sockets (TM2-NET R1, not recorded as accepted) | `539ba30`, `9270c6a`; [rpc-security evidence](evidence/rpc-security-2026-09-27/after-suite.log) |
| Mempool expiry (2 160) and the recently-expired guard, local origination only | Complete but requires further testing | `expiry-guard`; `87c83ff`, `00afb79` |
| Originated set (no re-origination) and wallet rebroadcast via `/tx/status` (33 W2, 38 W4) | Complete but requires further testing for re-origination. Open privacy defect: `originated.json` is a plaintext list of the node's own transaction ids (TM2-P2; since `06663f0` written 0600 on Unix through `private_file::write_atomic`; documented in [testnet.md](testnet.md) §4.5). Fixed: the origin re-announces at the same heights as every other node, also after a block during the stem, a reorganization or a restart (TM2-P1, merged with TM2-P2P `1c42b82`; [p2p.md](p2p.md) §7) | `0943ea4`; [p2p.md](p2p.md) §8.1; `p2p/tests/network.rs` (`a_restarted_origin_does_not_reoriginate_a_transaction_the_network_holds`); `p2p/tests/privacy.rs` (`a_block_found_during_the_stem_does_not_make_the_origin_reannounce_first`, `after_a_reorganization_the_origin_reannounces_with_everyone`, `a_restarted_origin_never_reannounces_its_held_copy`) |
| Privacy regression suite with the timing oracle (33 W1, trial P0) | Partial: the suite exists and is the gate for relay changes ([p2p.md](p2p.md) §8.2), but the timing oracle it is named for is open. Passing: held local transactions, a diffuser stems its own transaction, the TM2-P1 cases, uniform `InvTx` order (statistical), `GetAddr` inbound-only. Open, as ignored tests that fail today: the slow-lane timing oracle (TM2-P6) and the full-Tx-lane stem black hole (X1). Not covered: per-network trickle timers, Tor mode, per-network `GetAddr` caches (not implemented) | merge `186e614`; `p2p/tests/privacy.rs` (`a_held_local_transaction_is_never_announced`, `a_diffuser_still_stems_its_own_transaction`, `inv_batches_list_ids_in_a_uniformly_random_order`, `getaddr_is_answered_only_to_inbound_peers`; ignored: `stem_membership_does_not_change_reply_latency`, `a_black_holed_local_transaction_is_restemmed_before_the_origin_fluffs`); decisions, "Agent 33", "RES-FREEZE verified" |
| Decoy distribution from the wallet's own output index; no spend-time `/distribution` (D1; 38 W1, F38-1, F38-6) | Complete but requires further testing. The picker and the ring-member age rule use `OutputIndex::cumulative`; no spend path (transfer, deploy, PX deposit, contract-call fee) requests `/distribution`, which stays for tools. Open: below the restore height the index is the node's unverified `/outputs` backfill, checked only for shape (every block present with a coinbase output), so a node serving a restore still controls that part (F38-2; verified backfill 38 W11 is P1) | branch `wdist`; [transactions.md](transactions.md) §11.3.1; `wallet/src/wallet/tests_sync.rs` (`rings_do_not_depend_on_the_nodes_distribution`, `no_spend_path_requests_the_distribution`, `an_empty_index_takes_its_extent_from_the_wallets_own_tip_block`); `wallet/src/index.rs` (`cumulative_*`); `wallet/tests/e2e.rs` (request counts) |
| Transport hardening (30 W1, W2, W5: pre-`Verack` frame cap and handshake deadline, unscored decryption failures, transport version and genesis id in the key derivation; `PROTOCOL_VERSION = MIN_PROTOCOL_VERSION = 3`) | Complete but requires further testing | `e9ec2ff` (merge `04723c7`); `p2p/tests/transport_adversarial.rs`; `transport::tests` (`mismatching_transport_versions_derive_different_keys_and_fail`, `the_session_key_matches_its_known_answer`) |
| Transport v2 (30 W6: uniform key encoding, hybrid ML-KEM, padding, rekeying) | Not implemented (design notes, [p2p.md](p2p.md) §3.1). Without it frames are unpadded and the handshake is recognizable ([p2p.md](p2p.md) §1) | decisions, "Agent 30" |
| Address manager and connection policy (32 W0–W7, W3-32b, W3-32c) | Complete but requires further testing: quick hardening, onion validation, timestamped `Addr`, addrman v2 (keyed buckets; a source reaches at most 16 of 256 new buckets), one tried entry per onion group, anchors, feelers, /64 limits, inbound eviction protected by group, ping and recent relay, two block-relay-only connections, seeds as one-shot address fetches, `--onion-inbound`, stale-tip rotation by delivered tips; RT-W3 fixes. Open: no chain-sync eviction of lagging outbound peers, no built-in seeds, no live adversarial test (the labnet cannot exercise grouping, limits or bans) | `5836a7a`, `9eec1ae`, merges `c8b770a`, `d3d8e38`, `34ccf60`; `p2p/tests/eclipse_sim.rs`, `p2p/tests/connection_policy.rs`; decisions "W3-32", "RT-W3", "W3-32c" |
| Tor mode: onion-only outbound under `--proxy-only` (decisions "Agent 32"), SOCKS stream isolation, per-network `GetAddr` answers | Not implemented: proxy-only nodes dial clearnet addresses through Tor exits; SOCKS5 without authentication; one mixed address table answers `GetAddr` (documented, [p2p.md](p2p.md) §11, [testnet.md](testnet.md) §4.3) | `p2p/src/net/peers.rs` (`Dialable::skip_test`), `p2p/src/socks5.rs` |
| `deploy/config/testnet-tor.toml` uses the onion listener (N-6) | Complete but requires further testing: the hidden service forwards to `onion_inbound`, no clearnet listener (2026-10-02) | `node/tests/deploy_configs.rs` (`every_deploy_config_parses_and_is_set_up_as_named`); [testnet.md](testnet.md) §4.3 |
| Block store format 2, pre-v3 stores refused (F35-1) | Complete but requires further testing | `6efe6ac` |
| RandomX caches outside the lock, hot keys pinned and prebuilt, cache store bounded (07 W1–W3, 31 S1–S2, W4-MUT part 2) | Complete but requires further testing | `99819cd`, `90efa17`, `73cd752`, merge `6a2b3b7`; `consensus::pow` tests; decisions "RT-POW, RT-PXDOS, RT-SYNC" |
| Persistent PoW hashing pool (W4-POWPOOL) | Complete but requires further testing; the default `pow_threads` is not tuned on a multi-core host | merge `3c21afe`; `chain/tests/pow_pool.rs`, `chain/tests/rt_pow_pool_stress.rs`; [pow-pool evidence](evidence/pow-pool-2026-10-01/README.md) |
| Header sync and tip announcements by work and tip id (W4-SYNC, RT-SYNC) | Complete but requires further testing | merge `12f69e5`; `p2p/tests/network.rs` (`a_shorter_heavier_branch_wins_over_a_longer_lighter_one`, the `rt_sync_*` tests) |
| Miner seed planner, `--prebuild auto`, light-mode bridge; labnet warm-up (09 W2) | Complete but requires further testing | `26408a6`, `36e0456`; [labnet warm-up evidence](evidence/labnet-warmup-2026-09-28/README.md) |
| Full-mode miner across the first RandomX key switch (height 2113) | Complete but requires further testing: one crossing with `--prebuild auto`, one machine, regtest (10 s blocks); not at the testnet's 120 s blocks | [rx-fullmode evidence](evidence/rx-fullmode-seedswitch-2026-09-29/README.md); decisions "W4-RX evidence" |
| Template readiness gate and tip notification (W2-09b) | Complete but requires further testing: a latched catch-up gate (RTW3-1), `/tip` long poll from the snapshot, `next_seed_id`; stale blocks about 21 % to about 15 % in two short labnet runs (an indication) | docs/evidence/labnet-tipnotify-2026-09-28/; decisions, "W2-09" |
| Wallet sync: own PX tree and anchor checks, header checks (39 W1, W5, W3-39b, W3-39c) | Complete but requires further testing: the wallet builds the PX tree from verified blocks and anchors at its own roots (F39-1); registrations derived from deploys; restores check headers from genesis via `/headers` with dense proof of work on the last 720 headers (RTW3-5), in parallel; tip-age warning and transaction refusal (RTW3-6). F39-10 is bounded, not closed | merges of w3-wsync and w3-wsync2; docs/evidence/wallet-header-feed-2026-09-28/; docs/evidence/wallet-parallel-pow-2026-09-29/; decisions "W3-39", "W3-39b" |
| `ANCHOR_MIN_DEPTH = 3`, rounded down to 16 (21, W2-02/21) | Complete but requires further testing | `bf95d18`; `wallet/src/px.rs` (`the_anchor_is_the_last_multiple_of_the_interval_three_blocks_deep`) |
| Operator block invalidation (35 S5, S5b) | Complete but requires further testing: `--invalidate-block` / `--reconsider-block`, persistent store markers, repair keeps them (RTW3-7), operator-fork warning and template refusal (RTW3-8), refusal at header time. Open: a runtime RPC or actor command, a mempool-return test for operator reorgs, a red-team review of the trust model, verdicts in `/info` (below) | merges of w3-inval and fx-rtw3-node; `chain/tests/operator_invalidation.rs`; decisions "W3-35b", "RT-W3" |
| Chain-actor liveness (P0-A): stages 0–2 | Complete but requires further testing: stage 1 (per-peer slow lane, summary snapshot) and stage 2 (single-writer actor with priority lanes). Stages 3–4 (header index, mempool and verification outside the writer) are not implemented | merges f220ceb, fc1274b; docs/reviews/chain-actor-stage2.md |
| Seed format v1 (27 words, check words, network, birthday), derived hedge keys | Complete but requires further testing; open: F37-11, K7, K8 | `ed82f30`, `7a6fe53`; decisions, "W2-37" |
| Clock: start-up check and offset monitor (04) | Partially implemented: the node refuses an unreadable clock or one before genesis and warns about a stored tip beyond the FTL (`clock_check`, called by the binary since `680f9f9`); a warn-only estimate of the clock's offset from PoW-verified live blocks (p2p.md §6.1; unit-tested only). Not implemented: `/info` fields, an injectable clock and network-level skew tests, the miner's clock-skew refusal (below) | `node/src/lib.rs` (`the_start_up_clock_check`); `p2p/src/clock.rs` tests; decisions, "Agent 04" |
| RandomX official vectors including hash test 1f | Complete but requires further testing: the transcribed reference vectors are pinned by tests (light and full mode, `randomx-full` CI job); the reference's instruction-level tests are not ported, and other platforms than x86_64 are untested (no soft-AES or aarch64 leg) | `1319a8d`; [randomx/README.md](../randomx/README.md) |
| RandomX start-up self-test in node and miner, `--skip-randomx-self-test`, per-device `--randomx-self-test` (08, TM2-3) | Complete but requires further testing: vectors 1a–1f in light mode at every node and miner start (exit 71 on a mismatch, not restarted by the units); every miner dataset checked against its cache before use; full-mode vectors only on request (`blacksilk-miner --randomx-self-test`). Only the passing case runs end to end: no diverging build or platform was available to show a real mismatch (the refusal is shown with altered vectors and items) | `randomx/src/self_test.rs`; `node/tests/node_binary.rs` (`the_node_binary_runs_the_randomx_self_test`); miner tests (`a_dataset_self_test_failure_stops_the_planner`); [testnet.md](testnet.md) §4.2, §5 |
| Stored proof-of-work check at start-up: the 16 highest connected blocks plus 48 connected heights drawn below them, `--verify-store-pow` for all (01, TM2-5, RT-NODEOPS) | Complete but requires further testing: a forged older block is found only with probability 1 - (1 - k/N)^48 per start ([testnet.md](testnet.md) §4.5 has the table); side branches the node does not follow are not sampled; the start-up cost grows with the number of RandomX keys sampled (up to 48 cache builds on a chain of more than about 100 000 blocks); `--verify-store` (full re-validation, decision "Agent 35") is not built | `chain/src/manager/replay.rs` (`StorePowCheck`); `chain/tests/manager.rs` (`the_stored_pow_check_refuses_a_forged_hash`, `rt_a_forged_tip_stored_first_is_refused_at_every_seed`); `node/tests/node_binary.rs` (`a_store_with_forged_pow_hashes_is_refused`); [testnet.md](testnet.md) §4.5 |
| Origin data at rest: data directory 0700 and node files 0600 on Unix, too-open ones tightened at start (TM2-3) | Partially implemented: `originated.json` is still written with the process umask while the node runs; its writer (`p2p/src/originated.rs`) is owned by the TM2-P2P work item, and the change to `p2p::private_file::write_atomic` is pending on that branch, so only the directory's 0700 protects it until the next start; the Unix tests run in CI only; Windows relies on the folder's ACL (documented) | `node/src/datadir.rs`; `p2p/src/private_file.rs`; `node/tests/node_binary.rs` (`the_data_directory_and_its_files_are_owner_only`, Unix); [testnet.md](testnet.md) §4.5 |
| `/info`: network pre-shared key loaded (never the key), operator overrides of the run and verdicts in force; `check-node.sh` warns on them and, with `BLACKSILK_REQUIRE_PSK=1`, on a missing key (F48-9, TM2-2) | Complete but requires further testing | `node/src/lib.rs` (`NodeInfo`); `node/tests/node_binary.rs` (`info_shows_the_psk_state_overrides_and_verdicts`); [testnet.md](testnet.md) §12.3 |
| Clean stop on SIGTERM, Docker `STOPSIGNAL SIGINT`, systemd start limit (5 starts in 15 minutes, 30 s apart) for crash loops (TM2-4, TM2-8) | Complete but requires further testing: the SIGTERM test is Unix-only (CI); the start limit is checked in the unit file, not on a running systemd | `node/src/lib.rs` (`shutdown_signal`); `node/tests/node_binary.rs` (`sigterm_is_a_clean_shutdown`); `node/tests/halt_exit.rs`; [testnet.md](testnet.md) §4.2, §4.4 |
| Wallet: empty password refused at create, restore and `change-password`, weak (fewer than 12 characters) warned about; existing empty-password wallets open with a warning and `change-password` (TM2 cross-check) | Complete but requires further testing | `wallet/src/file.rs` (`check_new_password`); `wallet/tests/cli.rs`; [testnet.md](testnet.md) §12.8 |

### 3.1 Decided but not built

Each item below is recorded in the decisions log and has **no implementation** at the
commit in the header (checked in the code; the second threat-model round's register,
TM2-CONS §8, plus the network and privacy lenses). Status: Not implemented, unless the
row says otherwise.

| Item | Decision | Note |
|---|---|---|
| `--verify-store` (full re-validation of the stored chain on request) | "Agent 35" | the sampled PoW check and `--verify-store-pow` are built (§3) |
| Template self-check with a coinbase-only fallback | "Agent 01" | |
| Miner refuses to mine on a clock skew above FTL/2, `--allow-clock-skew` | "Agent 04" | |
| Park-on-deep-reorg (off for the trial, 720 for a public testnet) | "Agent 02" W-7 | P0 for a public testnet; only a WARN at depth 10 exists. It would not cover the DAA race residual (§2) |
| F48-5 "validating" quarantine marker, halt naming the block | "Agent 48" | store record type 0x82 reserved only; exit 70 and panics (101) are restarted at most 5 times in 15 minutes under systemd, nothing names the block ([testnet.md](testnet.md) §4.2) |
| AVX-512 refusal at compile time, Plonky3 backend in `--version` and `/info` | "Agent 27" W4 | |
| Independent BP+ verifier by a different author | "Agent 16" | `crypto/src/bulletproofs_plus.rs` has an in-module naive verifier (`verify_naive`) that shares the challenge code, so it is not independent |
| Monero CLSAG conformance harness (`tools/clsag-conformance`) | "Agent 15" W10 | |
| Golden PX proof fixture | "Agent 22", "Run C and RT-MUTC" | Done: `node/src/px_fixture.bin` (merge `5d3d96f`). Open: the prover is not bit-reproducible, so the fixture is pinned and never regenerated in CI (P-5, under investigation) |
| Supply-audit PX test (F40-9) | "Agent 40" | the audit's PX half is tested only with an empty pool |
| Verifier-only grinding switch for deeper ZK fuzzing | "RT-STATEFUL" | P1 |
| Staller detection for block downloads (disconnect, never ban) | "Agent 31" | a timed-out request moves to a random candidate, possibly the same peer |
| `MIN_CHAIN_WORK` and headers presync (RX-presync) | "Agent 31", "Agent 50" | P1 for a public testnet |
| Fair per-candidate `missing_bodies` and per-peer targeted download (02 F-1) | "Agent 02" | P0 for a public testnet |
| `verifier_id` in `TxRules`; `recent_rejects` keyed by or flushed on the rule domain (RT-3, TM2-5) | "Agent 50", "Threat model round 2" | needed before any second epoch |
| Log rate limiting (F48-8) | "Agent 48" | peer IPs are logged at `info` |
| Verified output backfill below the restore height (38 W11, F38-2) | "Decoy and relay plan (2026-10-04)" | P1; the decoy distribution below the restore height depends on it ([transactions.md](transactions.md) §11.3.1) |
| Hedged decoy RNG keyed with the derived hedge key (F38-5, 18 W3) | "Agent 18" | |
| Wallet SOCKS5 (38 W5) | "Agent 38" | |
| Young-spend warning (38) | "Agent 38" | the opt-in spend delay is P2 |
| Wasm-only crypto behind a `contracts-research` feature (W29-5) | "Agent 29" | `crypto/src/lib.rs` declares the modules ungated |
| `CachedPow` bound (F07-5) | "Agent 07" | P2 |
| Per-peer header-hash slow start (D1); a `GetTx` of more than 64 ids disconnecting honest peers (reproduce first) | "Threat model round 2" (queued) | |

## 4. Contracts

| Item | Status | Evidence |
|---|---|---|
| PX as the only consensus contract platform (ADR-28-1, owner decision D22) | Decided | decisions, "Agent 28"; [contracts.md](contracts.md) |
| Wasm contract engine frozen outside the root workspace (D22 "D-freeze") | Complete but requires further testing: CI assertion added; the crate's tests pass from `contracts/` | root `Cargo.toml` `exclude`; [contracts/README.md](../contracts/README.md); [research/wasm-contracts.md](research/wasm-contracts.md) |
| Wasm-only crypto (`schnorr`, `membership`, `claims`) behind an off-by-default feature (W29-5) | Not implemented (§3.1) | decisions, "Agent 29" |

## 5. Evidence and assurance (the freeze gates)

| Item | Status | Evidence |
|---|---|---|
| Full test suite on the freeze commit, including the PX-proving tests | Not implemented (per-merge suites are recorded in the merge commits) | `git log --merges` |
| Fuzz campaign (W4-FUZZ, `-O -a`) and stateful harnesses (W4-STATEFUL) | Complete but requires further testing: 12 targets for 30 minutes each, no finding; robustness evidence only ("no panic on the reached surface"), and shallow (several targets still found new units at the end). Stateful `peer_protocol`, `px_admission` and `scan_outputs` harnesses, no product bug found | [fuzz-w4 evidence](evidence/fuzz-w4-2026-09-29/README.md); [fuzz-stateful evidence](evidence/fuzz-stateful-2026-10-01/README.md); decisions "W4-FUZZ and RT-FUZZ" |
| Mutation-testing freeze gate (zero unexplained survivors) | Partially implemented: runs A (`consensus`) and B (`px-core`), C (transaction rules, fork choice, crypto, blocks) and D (decode bounds, admission, header sync, cache store) done, every survivor killed or exempted. Not done: run E (tx types, codec and state; px prove, state and tree; chain submission and header sync; p2p headers, connections, maintenance and admission; wallet checks); `replay.rs`, `store.rs`, the zk verify path, `randomx/`, the fingerprint modules and the supply audit are in no run | [run A/B](evidence/mutation-2026-09-29/README.md), [run C](evidence/mutation-runC-2026-09-30/README.md), [run D](evidence/mutation-runD-2026-10-01/README.md); [mutation-exemptions.md](reviews/mutation-exemptions.md) |
| BVM-1 AIR soundness evidence (TM2-1: the AIR has had no mutation census) | Not implemented: W4-MUTAIR started 2026-10-02 | decisions "Threat model round 2" |
| P-5 re-run on the frozen kernel; widest-proof and verifier-cost measurement | Not implemented | decisions, "Agent 26", "Agent 22" |
| Labnet campaign | Partially implemented: W4-LAB (honest network to equilibrium, unequal partitions, a withholding miner, late-joiner discovery and address relay) on one machine; runs 3–4 have an undetermined build and are superseded by the quiet-window reruns, not yet run (ring topology, address relay, late joiner) | [labnet-w4 evidence](evidence/labnet-w4-2026-09-30/README.md); decisions "W4-LAB and RT-LAB", "W4-GUARD" |
| Supply audit with a PX pool, a multi-machine 72-hour run | Not implemented | [testnet.md](testnet.md) §7, §7.1 |
| Second threat-model round (consensus, network and operations, privacy; cross-check) | Partially implemented: the four internal reports are written; no consensus-rule bug was found; their P0 items are the open rows of this file | decisions "Threat model round 2" |
| Genesis rehearsal | Not implemented | [waves.md](reviews/phase2-2026-09-27/waves.md) |
| CI on the release commit, all jobs green on GitHub | Not verified here: CI results live on GitHub, not in the repository | `.github/workflows/ci.yml` |

## 6. Accepted limitations

These are known and documented; the testnet runs with them.

| Limitation | Where documented |
|---|---|
| **PoW honest majority is nominal (K1).** The PoW is Monero's `rx/0`; stock JIT miners and rented `rx/0` hash rate are far faster than the safe-Rust miner, and the no-`unsafe` policy rules out a JIT here. Anyone pointing such hash power at the testnet can out-mine it and reorganize the chain. The DAA's remaining raising-race excess (+3.5 % at q = 0.4, +27.4 % at q = 0.45) and the slow blocks after a won race are accepted under the same assumption | [testnet.md](testnet.md) §12.6; [assumptions.md](reviews/assumptions.md) K1; [redteam.md](evidence/daa-sim-2026-09-27/redteam.md) RT-3, RT-4 |
| No reorg-depth limit or checkpoint (K4, provisional testnet policy) | [assumptions.md](reviews/assumptions.md) K4; [k4-reorg-policy.md](reviews/k4-reorg-policy.md) |
| **A link observer sees which transactions a node originates, v1 and PX.** Frames are not padded, so the node's ISP (or its Tor guard) sees a transaction-sized message that no peer sent first. A PX transaction (2.2 MB or more) is unmistakable even over Tor; a v1 transaction is a weaker signal over Tor, not a hidden one. Dandelion++ protects against spy nodes only, and PX origins less than v1 origins | [p2p.md](p2p.md) §1; [testnet.md](testnet.md) §12.7; dossier 33 §3.4, §3.7 |
| A BlackSilk node is recognizable by its handshake, also on a pre-shared-key network; censorship resistance is not a goal of this version | [p2p.md](p2p.md) §1, §3.1; decisions "Agent 30" |
| **Block origin** (the mining node's IP) is not protected: blocks are announced without delay | [p2p.md](p2p.md) §1; decisions "RT-POW, RT-PXDOS, RT-SYNC" |
| Small anonymity sets on a trial network: the trial cannot demonstrate privacy, only function and liveness | [testnet.md](testnet.md) §12.7 |
| Guess-newest on v1 rings: on a mature chain a real input spent 12 blocks after receipt is the newest ring member in about 84–89 % of rings (a simulation estimate) | [transactions.md](transactions.md) §11.3.1 |
| Zero knowledge is statistical and conditional, computational in practice (PRG masks); soundness figures rest on the adopted headline and an argued, not proven, tree-extractability adaptation | [zk-coverage.md](reviews/zk-coverage.md); [zk.md](zk.md) §9.3 |
| DAA hopper criterion relaxed to ±5 points for the testnet; slow settling after very large hash-rate increases | decisions, "DAA FINAL"; [daa-sim evidence](evidence/daa-sim-2026-09-27/results.md) |
| Unauthenticated P2P encryption: it hides contents from passive observers, and from an outsider in the middle only on a pre-shared-key network; no I2P | [p2p.md](p2p.md) §1 |
| A fresh node with an empty tried table gives an attacker about 61 % of its slots in the simulator's small-network scenario (F32-13) | decisions "W3-32"; [p2p.md](p2p.md) §9, §12 |
| Not post-quantum: no part of the v1 layer resists a quantum adversary | [transactions.md](transactions.md) §11.6 |
| PX proofs of about 2.2 to 2.7 MB; a few PX transactions per block | [px.md](px.md) §8; [aggregation-study.md](reviews/aggregation-study.md) |
| Block bodies and undo data stay in memory; every restart re-validates every block and PX proof (PX-F1 to PX-F3) | [testnet.md](testnet.md) §12.6 |
| The RPC cookie on Windows is protected only by the directory's permissions | decisions "Agent 36"; [testnet.md](testnet.md) §4.2 |
| No memory locking (it would need `unsafe`): keys can reach swap, hibernation files and crash dumps; the operators' endpoint checklist is the only mitigation | [testnet.md](testnet.md) §12.8 |
| The toolchain identification strings are part of the guest build inputs (CI-7) | decisions, "Agent 43" |

## 7. Documentation findings left open

`doc-lint` has a temporary exclusion list (`TEMP_EXCLUDE` in
`.github/scripts/doc-lint.sh`) for files other workstreams were editing when the lint
landed. Each entry is cleared by the coordinator when its owner fixes the finding.

- Code comments that the docs now contradict: `px/src/delivery.rs` still describes
  the removed key derivation 1 ("no view/spend separation", "the derivation does not
  include the network"; [px.md](px.md) §6 is corrected), and the `reannounce_pool`
  comment in `p2p/src/net/relay.rs` repeats the claim of [p2p.md](p2p.md) §7 that
  TM2-P1 refutes (owned by TM2-P2P).
- The decisions log still assigns the DAA race residual to park-on-deep-reorg
  ("Agent 03", "DAA DECIDED"); the record and the evidence carry the correction
  (§2).
