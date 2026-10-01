# BlackSilk status

**This file is the single status source of the project** (decision "Agent 47",
[phase-2 decisions](reviews/phase2-2026-09-27/decisions.md)). Other documents link here
instead of stating status themselves; a status line anywhere else is historical.

- **As of:** `rebuild/core` at `e986250` plus the branch that last edited this file
  (see `git log -- docs/STATUS.md`). Every entry names its evidence; an entry without
  evidence in the repository says so.
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
  (`.github/scripts/doc-lint.sh`) checks the claims, links and copied digests.

**Status classes** (phase-2 brief): Complete and verified · Complete but requires
further testing · Partially implemented · Not implemented · Deferred · Blocked ·
Accepted limitation. "Complete but requires further testing" is the highest class any
v3 item has before the protocol freeze: the full suite, the fuzz, mutation and labnet
evidence runs and the red-team rounds of waves 4 and 5 are still to come
([waves.md](reviews/phase2-2026-09-27/waves.md)).

## 1. Network identity and launch

| Item | Status | Evidence |
|---|---|---|
| Testnet v2 identity (`0x0001D672`) | **Retired** (2026-09-27): this tree enforces rules v2 builds do not | [testnet.md](testnet.md) status block; `node/src/config.rs` (`retired_testnet_identity_is_refused_until_v3`) |
| Testnet | **Disabled**: `blacksilk-node --network testnet` refuses to start until the v3 genesis is final | `ChainParams::genesis_is_final` (`consensus/src/params.rs`); W2-36b merge `a2c4d1f` |
| Seven-device trial | **Blocked**: not authorized; needs the protocol freeze, the v3 genesis and the owner's approval | [testnet-v3-genesis.md](testnet-v3-genesis.md) |
| Fingerprint v3 (rules and identity split, rule samples, rule revisions) and the testnet v3 network id `0x0001D673` (agent 40, one commit) | Complete but requires further testing. Red team RT-FP3: construction sound, coverage not; its P0 and P1 items are implemented (FX-RTFP3): RandomX configuration read from the crate with a pinned known answer, consensus hash tags, crypto, tree, transcript and FTL/clamp samples, verdict samples on a pinned fixture transfer, `Revision:` lines tied to `REVISIONS`. Each of the seven red-team mutations now changes the rules fingerprint (`tools/fingerprint-mutations.sh`). Rules that only a PX proof or a full block reaches stay covered by revision and commit only. Review of the fix pending | [v3-consensus-changes.md](reviews/v3-consensus-changes.md) `fingerprint-v3`, Follow-up (RT-FP3); `node/src/fingerprint.rs` tests |
| Consensus fingerprint pins (`px/tests/consensus_fingerprint.rs`, `node/tests/deploy_configs.rs`) | Re-pinned after each reviewed consensus merge, last by RT-FP3 (rules and consensus per network; identity unchanged). Operators compare `blacksilk-node --version` and `/info` against the release announcement; values are not copied into docs | decisions, "Fingerprint pins during the pre-freeze v3 window"; `fingerprint-v3` (re-pin procedure) |
| `blacksilk-node --print-manifest` (decisions "Agent 47") | Complete but requires further testing: prints both manifests, their encodings and the three fingerprints; an independent recompute script is not yet in the repository (dossier 40 item 5) | `fingerprint::tests::manifest_text_recomputes`; `fingerprint-v3` |
| Dirty-tree mark on the build commit (RTFP3-9) | Complete but requires further testing: `node/build.rs` compares tracked build inputs with the git index (pure Rust, no `git` process); a modified file gives `<commit>-dirty`, and a release build of a dirty tree fails unless `BLACKSILK_ALLOW_DIRTY=1`. Untracked files and staged-only changes are not detected; the miner and wallet have no build script | `node/tests/build_id.rs`; [testnet.md](testnet.md) §2.1 |
| Reproducible node binary (the binary-hash operator check, RTFP3-15) | Not implemented: only the guest programs are shown reproducible (CI `guests`); the node binary's cross-host reproducibility is untested. On Windows (MSVC) two builds of one commit on one machine differ, only in the PE time stamps and the PDB GUID the linker writes (W4-GUARD) | [testnet.md](testnet.md) §2.1; [labnet-w4 README](evidence/labnet-w4-2026-09-30/README.md) §1.1 |
| Test-only code in shipped binaries (W4-GUARD, RT-STATEFUL: `cargo test --release` writes a node with the chain, tx, px and p2p test hooks to `target/release`) | Complete but requires further testing: each crate with a `test-hooks` feature (and chain and p2p for `cfg(fuzzing)`) exports a marker compiled in only with that code; the node, miner and wallet print it in `--version` (and the node in `--print-manifest` and its start-up log) and refuse every network but regtest with it; the genesis tool refuses to run with it; the node, miner, wallet and genesis builds refuse `cfg(fuzzing)`; the labnet refuses marked binaries. A test-only feature added later is covered only once its crate exports a marker | `node/tests/build_guard.rs`, `chain/src/build_flags.rs` tests, `wallet/tests/cli.rs` (`a_wallet_with_test_code_works_only_on_regtest`); CI `test` job, `.github/scripts/build-guard.sh` (dependency tree, `--version`, binary contents, with a control); [testnet.md](testnet.md) §2 |
| Genesis tool reserved ids and `verify` of the launched id (RTFP3-13, RTFP3-14; F40-1) | Complete but requires further testing: `generate --final` only for `0x0001D673`, `--rehearsal` only for `0x0001D6E0`–`EF`, the test-vector id never; `verify` accepts a registered id only for a built-in network's compiled genesis | `tools/genesis/tests/genesis.rs`; [testnet-v3-genesis.md](testnet-v3-genesis.md) §3 |
| Testnet `D0` measured on reference hardware (genesis gate, F40-12) | Not implemented | decisions, "Labnet deep reorgs (INV-REORG)" |
| Final genesis | **Blocked** until the protocol freeze (never generated before it) | [testnet-v3-genesis.md](testnet-v3-genesis.md) |
| Protocol freeze | Not reached | [waves.md](reviews/phase2-2026-09-27/waves.md) wave 4 |

## 2. v3 consensus rule set (wave 1)

Every row is a v3 genesis base rule (no activation height), recorded with the 15-step
discipline in [v3-consensus-changes.md](reviews/v3-consensus-changes.md) under the
section named in the row.

| Item | Status | Evidence |
|---|---|---|
| D8 option B: no cross-transaction one-time-key uniqueness | Complete but requires further testing | §1; `dd8623b` |
| CLSAG auxiliary image `D ≠ identity` | Complete but requires further testing | §2; `f655827` |
| RT-14: genesis id in every signature domain | Complete but requires further testing | §3; `205499c` |
| BS-ZK-3: eight random codewords per committed matrix | Complete but requires further testing; not re-measured on PX proofs | "BS-ZK-3"; `73372e9` |
| Canonical proof shape | Complete but requires further testing | "Canonical proof shape"; `43ef877` |
| Soundness figures, `COLLISION_BITS = 122`; circuit digest (RTW1-3/6/8) | Complete but requires further testing. The ePrint 2026/089 adaptation is argued, not proven, and the property claimed is extractability | "Soundness figures"; `0535347`, `be93f71` |
| Difficulty: LWMA-75, counted-clock step T/2, warmed over 11 blocks | Complete but requires further testing | `daa-lwma75-warm`; `163bfa0`; [daa-sim evidence](evidence/daa-sim-2026-09-27/results.md) |
| `ChainParams::check`, F-05 header check order, big-endian refusal | Complete but requires further testing | `f05-header-check-order`; `67c9f69`, `3b2d0dd`, `4040edd` |
| Genesis nonce derived from a committed beacon | Complete but requires further testing; no beacon committed on any network | `genesis-beacon`; `becd6e4` |
| RT-1: `UnknownUpgrade` only for headers with real PoW | Complete but requires further testing | `rt1-unknown-upgrade-pow`; `d30f537`, `2affc89` |
| Exact v1 fee (T8) | Complete but requires further testing | `exact-v1-fee`; `6b1d2d0` |
| R12-2 (a′): PX and deploy v1 parts count toward the block weight | Complete but requires further testing | `r12-2`; `af5418c` |
| PX tree capacity (B8) with 21-D, halting apply, 21-F | Complete but requires further testing | `tree-capacity`; `c40dcca` |
| One approval per contract input (F-20-1) | Complete but requires further testing | `approval-conflict`; `66640ff` |
| Call ABI version and output-word registry (F-28-1) | Complete but requires further testing | `px-call-abi`; `66640ff` |
| PX6 validity window | Complete but requires further testing | `px6-validity-window`; `66640ff` |
| Vault v3 (contract-bound locks, hedged blinds, timeout and refund) | Complete but requires further testing. The wallet does not yet expose the timeout or the refund | `vault-v3`; `66640ff` |
| Single v3 kernel and vault rebuild, guest link layout (CI-1) | Complete but requires further testing: byte-identical on windows-latest, ubuntu-24.04 and ubuntu-24.04-arm in CI (run 102, after the build.sh SIGPIPE fix); an operator build at the reveal is still owed | `guest-rebuild`; `9fa558f`; `zkvm/guests/README.md` |
| RT-W1c follow-ups (RTW1C-1 kernel budgets ≤ 95 % of every table, must land before the freeze; RTW1C-2 to -8) | Not implemented (owner FX-RTW1C) | decisions, "RT-W1c" |

## 3. Node, network, wallet and mining (wave 2 and earlier)

| Item | Status | Evidence |
|---|---|---|
| Authenticated RPC (cookie, limits, `--rpc-allow-host`, `/tx/status`) served by the binary | Complete but requires further testing | `539ba30`, `9270c6a`; [rpc-security evidence](evidence/rpc-security-2026-09-27/after-suite.log) |
| Mempool expiry (2 160) and the recently-expired guard, local origination only | Complete but requires further testing | `expiry-guard`; `87c83ff`, `00afb79` |
| Originated set (no re-origination) and wallet rebroadcast via `/tx/status` (33 W2, 38 W4) | Complete but requires further testing | `0943ea4`; [p2p.md](p2p.md) §8.1 |
| Privacy regression suite with the timing oracle (33 W1, trial P0) | Not implemented (no such suite on `rebuild/core` at `e986250`) | decisions, "Agent 33" |
| Address manager (32 W0-W7) | Complete but requires further testing: quick hardening, onion validation, timestamped `Addr`, addrman v2 (keyed buckets; a source reaches at most 16 of 256 new buckets), anchors, feelers, /64 limits, inbound eviction, stale-tip rotation by delivered tips; RT-W3 fixes (outbound refill, handshake caps). Open: onion tried cap, honest-inflow modelling, ping/relay eviction protection, block-relay-only connections | `5836a7a`, merges of w3-addrman and fx-rtw3-p2p; p2p/tests/eclipse_sim.rs; decisions "W3-32", "RT-W3" |
| Transport hardening (30: pre-`Verack` cap, transport version in the KDF) | Not implemented | decisions, "Agent 30" |
| Block store format 2, pre-v3 stores refused (F35-1) | Complete but requires further testing | `6efe6ac` |
| RandomX caches outside the lock, hot keys pinned and prebuilt; shared sync policy (07 W1-W3, 31 S1-S2) | Complete but requires further testing | `99819cd`, `90efa17`, `73cd752` |
| Miner seed planner, `--prebuild auto`, light-mode bridge; labnet warm-up (09 W2) | Complete but requires further testing | `26408a6`, `36e0456`; [labnet warm-up evidence](evidence/labnet-warmup-2026-09-28/README.md) |
| Template readiness gate and tip notification (W2-09b) | Complete but requires further testing: a LATCHED catch-up gate (RTW3-1; the first design was rejected by the red team), `/tip` long poll from the snapshot, `next_seed_id`, `--prebuild auto`; stale blocks about 21% to about 15% in two short labnet runs (an indication); full-mode prebuild across a key switch not yet run | docs/evidence/labnet-tipnotify-2026-09-28/; decisions, "W2-09" |
| Wallet sync: own PX tree and anchor checks, header checks (39 W1, W5, W3-39b) | Complete but requires further testing: the wallet builds the PX tree from verified blocks and anchors at its own roots (F39-1); registrations derived from deploys; restores check headers from genesis via `/headers` with dense proof of work on the last 720 headers (RTW3-5); tip-age warning and transaction refusal (RTW3-6). F39-10 is bounded, not closed. The proof of work of the check runs in parallel on every available thread with the verdicts of the one-by-one check (W3-39c) | merges of w3-wsync and w3-wsync2; docs/evidence/wallet-header-feed-2026-09-28/; docs/evidence/wallet-parallel-pow-2026-09-29/; decisions "W3-39", "W3-39b" |
| Operator block invalidation (35 S5) | Complete but requires further testing: `--invalidate-block` / `--reconsider-block`, persistent store markers, repair keeps them (RTW3-7), operator-fork warning and template refusal (RTW3-8), refusal at header time with no body requested or stored (S5b). Open: a runtime RPC or actor command, a mempool-return test for operator reorgs, a red-team review of the trust model | merges of w3-inval and fx-rtw3-node; decisions "W3-35b", "RT-W3" |
| Full-mode miner across the first RandomX key switch (height 2113) at network parameters | Not implemented (light-mode miners crossed it) | [seed-switch evidence](evidence/labnet-seedswitch-2026-09-27/README.md) |
| Chain-actor liveness (P0-A): stages 0-2 | Complete but requires further testing: stage 1 (per-peer slow lane, summary snapshot) and stage 2 (single-writer actor with priority lanes; E1-E4 equivalence, g1-g7 ordering, L1-L8 liveness all pass). Stages 3-4 (header index, mempool and verification outside the writer) are not implemented | merges f220ceb, fc1274b; docs/reviews/chain-actor-stage2.md |
| Seed format v1 (27 words, check words, network, birthday), derived hedge keys | Complete but requires further testing; open: F37-11, K7, K8 | `ed82f30`, `7a6fe53`; decisions, "W2-37" |
| `ANCHOR_MIN_DEPTH` (21) | Not implemented | decisions, "Agent 21" |
| Clock sanity monitor (04) | Partially implemented: a warn-only estimate of the local clock's offset from PoW-verified live blocks and retro-confirmed FTL refusals, with WARN/ERROR logs (p2p.md §6.1; unit-tested only); a start-up clock check function (`blacksilk_node::clock_check`) not yet called by the node binary. Open: the binary call, the `/info` fields, an injectable clock and network-level skew tests, miner clock safety (04 W5) | decisions, "Agent 04"; dossier 04 |
| RandomX official vectors including hash test 1f | Complete but requires further testing: the transcribed reference vectors are pinned by tests (light and full mode, `randomx-full` CI job); the reference's instruction-level tests are not ported, and other platforms than x86_64 are untested | `1319a8d`; [randomx/README.md](../randomx/README.md) |

## 4. Contracts

| Item | Status | Evidence |
|---|---|---|
| PX as the only consensus contract platform (ADR-28-1, owner decision D22) | Decided | decisions, "Agent 28"; [contracts.md](contracts.md) |
| Wasm contract engine frozen outside the root workspace (D22 "D-freeze") | Complete but requires further testing: CI assertion added; the crate's 30 tests pass from `contracts/` | root `Cargo.toml` `exclude`; [contracts/README.md](../contracts/README.md); [research/wasm-contracts.md](research/wasm-contracts.md) |
| Wasm-only crypto (`schnorr`, `membership`, `claims`) behind an off-by-default feature (W29-5) | Not implemented (a `crypto` item, after 18's membership nonce fix) | decisions, "Agent 29" |

## 5. Evidence and assurance still to come (waves 3 to 5)

| Item | Status | Evidence |
|---|---|---|
| Full test suite on the freeze commit, including the PX-proving tests | Not implemented (per-merge suites are recorded in the merge commits) | `git log --merges` |
| Fuzz campaign E1 (`-O -a`) | Not implemented (wave 4) | decisions, "Agent 41" |
| Mutation-testing freeze gate (zero unexplained survivors in `consensus`, `px-core`) | Not implemented; the exemption register exists (first entry: the LWMA floor, equivalent by proof, RTFP3-16) | decisions, "Agent 42"; [mutation-exemptions.md](reviews/mutation-exemptions.md) |
| P-5 re-run on the frozen kernel; widest-proof and verifier-cost measurement | Not implemented | decisions, "Agent 26", "Agent 22" |
| Labnet adversarial runs, supply audit with a PX pool, a multi-machine 72-hour run | Not implemented | [testnet.md](testnet.md) §7 |
| Second threat-model round, genesis rehearsal | Not implemented (wave 5) | [waves.md](reviews/phase2-2026-09-27/waves.md) |
| CI on the release commit, all jobs green on GitHub | Not verified here: CI results live on GitHub, not in the repository | `.github/workflows/ci.yml` |

## 6. Accepted limitations

These are known and documented; the testnet runs with them.

| Limitation | Where documented |
|---|---|
| **PoW honest majority is nominal (K1).** The PoW is Monero's `rx/0`; stock JIT miners and rented `rx/0` hash rate are far faster than the safe-Rust miner, and the no-`unsafe` policy rules out a JIT here. Anyone pointing such hash power at the testnet can out-mine it and reorganize the chain | [testnet.md](testnet.md) §12.6; [assumptions.md](reviews/assumptions.md) K1 |
| No reorg-depth limit or checkpoint (K4, provisional testnet policy) | [assumptions.md](reviews/assumptions.md) K4; [k4-reorg-policy.md](reviews/k4-reorg-policy.md) |
| **The origin of a PX transaction is visible to its ISP and Tor guard** (a 2.2 MB upload), and Dandelion++ protects PX origins less than v1 origins | [testnet.md](testnet.md) §12.7; dossier 33 §3.4, §3.7 |
| Small anonymity sets on a trial network (ring anonymity among few miners; the PX pool holds only the trial's records) | [testnet.md](testnet.md) §12.7 |
| Zero knowledge is statistical and conditional, computational in practice (PRG masks); soundness figures rest on the adopted headline and an argued, not proven, tree-extractability adaptation | [zk-coverage.md](reviews/zk-coverage.md); [zk.md](zk.md) §9.3 |
| DAA hopper criterion relaxed to ±5 points for the testnet; slow settling after very large hash-rate increases | decisions, "DAA FINAL"; [daa-sim evidence](evidence/daa-sim-2026-09-27/results.md) |
| Unauthenticated P2P encryption (passive observers only); no I2P | [p2p.md](p2p.md) §1 |
| Not post-quantum: no part of the v1 layer resists a quantum adversary | [transactions.md](transactions.md) §11.6 |
| PX proofs of about 2.2 to 2.7 MB; a few PX transactions per block | [px.md](px.md) §8; [aggregation-study.md](reviews/aggregation-study.md) |
| Block bodies and undo data stay in memory; every restart re-validates every block and PX proof (PX-F1 to PX-F3) | [testnet.md](testnet.md) §12.6 |
| The toolchain identification strings are part of the guest build inputs (CI-7) | decisions, "Agent 43" |

## 7. Documentation findings left open

`doc-lint` has a temporary exclusion list (`TEMP_EXCLUDE` in
`.github/scripts/doc-lint.sh`) for files other workstreams were editing when the lint
landed. Each entry is cleared by the coordinator when its owner fixes the finding.
