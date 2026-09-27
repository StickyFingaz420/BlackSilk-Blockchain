# 01 consensus-core: phase-1 research dossier

Internal engineering research, not an audit. Read-only on the repository; no builds or tests were run by
this agent. Nothing here claims BlackSilk is secure, audited or production-ready.

- **Agent:** 01 (consensus-core), BlackSilk engineering phase 2, phase 1.
- **Commit:** `rebuild/core` @ `9e422d8` (`git rev-parse --short HEAD`), working tree clean.
- **Evidence tags:** [math] mathematically established; [test: name] an existing named test covers it
  (read, not run by me); [src] source-read by me; [assumed]; [unknown]; [web] primary source cited in §8.

---

## 1. Scope and what I read

**Reviews (required reading):** `docs/reviews/full-review-2026-09-27.md` (whole), `docs/reviews/autonomous-session-2026-09-27.md`,
`docs/reviews/full-review-2026-09-27/R1-consensus.md`, `SX1-core-crossreview.md` (SX1 precedence applied),
`docs/reviews/v3-upgrade-mechanism.md`, `docs/testnet-v3-genesis.md`, `docs/reviews/px-f4-f5-analysis.md` (§1–2 only; PX not in scope),
roster entries 01 and the neighbours 02, 03, 04, 05, 07, 09, 10, 11, 12, 40–47, 50.

**Specifications:** `docs/consensus.md` (whole), `docs/blocks.md` (whole), `docs/transactions.md` §8 (rule numbering).

**Code (read in full):**
- `consensus/src/{lib,header,params,chain,pow,schedule,difficulty,timestamp,merkle,hash}.rs`, `consensus/Cargo.toml`
- `chain/src/{block,emission,lib}.rs`, `chain/src/manager.rs` (all 1459 lines)
- `tx/src/validate.rs` 826–1120 (block rules B1–B7), `tx/src/params.rs` (TxRules), `tx/src/types.rs` weight/px_bytes
- `node/src/fingerprint.rs`, `node/src/main.rs` (open path), `miner/src/lib.rs` (header build), `tools/genesis/src/lib.rs` (grep level)
- p2p call sites only by grep (`MAX_FRAME`, `precheck_headers`, `UnknownUpgrade` arms).

**Tests (read):** `consensus/tests/golden.rs` (17 tests), `consensus/tests/randomx_end_to_end.rs`, unit tests in every
consensus module, `chain/tests/golden.rs`, `chain/tests/manager.rs` (key-switch and replay tests), `chain/tests/block_malleability.rs`,
`chain/tests/fuzz_block.rs`, test-name inventory of `chain/tests/*`, grep of `tx/tests/*` for every `BlockError` variant.

---

## 2. Current state

### 2.1 What exists and is well designed

| Claim | Evidence |
|---|---|
| One definition of the header rules (`check_rules`) shared by sequential `validate` and `precheck_batch`; the batch pre-check computes zero PoW and agrees with sequential validation at every window position. | [src] `consensus/src/chain.rs:309-358`; [test: `precheck_agrees_with_sequential_validation_and_computes_no_pow`, `precheck_skips_known_headers_and_reports_breaks`, `precheck_rejects_known_invalid_headers_and_their_descendants`] |
| `check_hash` is Monero's `h·d < 2^256` with d = 0 invalid; limb loop cannot overflow u128. | [math] (R1 V1 re-derived: `v·d + carry ≤ (2^64−1)^2 + 2^64−1 < 2^128`); [web] Monero `check_hash_128`; [test: `check_hash_boundaries`, `check_hash_boundaries_golden`] |
| Seed schedule equals Monero `rx_seedheight` (E = 2048, L = 64), seed looked up on the header's own branch, key = 32-byte seed block id (Monero passes the 32-byte seed hash, `HASH_SIZE`). | [web] monero `rx-slow-hash.c`; [src] `pow.rs:153-160`, `chain.rs:277-280`; [test: `seed_height_schedule_golden`, `header_chain_uses_the_spec_seed_block`, `seed_is_taken_from_the_headers_own_branch`, `the_randomx_key_switch_works_across_sync_restart_and_reorg` (real RandomX, short epoch 16/4, cached hashes compared with reference hashes under expected keys)] |
| LWMA-1 matches zawy's loop (monotone `prev+1`, 6T cap, `L ≥ n²T/20`) without the 99/100 factor; arithmetic bounded (`S·T·(n+1) < 2^84`). The code's extra `.max(1)` is redundant (every solve time ≥ 1). | [web] zawy12 #3; [math]; [test: 10 `lwma_*` golden tests incl. exact steady state, 6T cap boundary, floor, clamps, out-of-order; `header_chain_difficulty_and_mtp_golden` over 150 blocks] |
| MTP strict (lower median of 11), FTL non-permanent, never stored, no peer time. | [src] `timestamp.rs`, `chain.rs:339-350`; [test: `mtp_is_strict`, `median_time_past_golden`, `rejects_each_invalid_field`] |
| Header 100 bytes strict; id = `H("BlackSilk/block-id" ‖ LE32(nid) ‖ header)`. | [test: `roundtrip_and_layout`, `strict_length`, `header_bytes_and_id_golden`, `genesis_ids_golden`] |
| Merkle root with leaf/node prefixes, odd node carried up (no CVE-2012-2459). | [math] (a collision between lists of different shape needs a Blake2b collision across the 0x00/0x01 prefixes); [test: `merkle_root_golden`, `no_duplicate_malleability`] |
| Emission height-only, B3 exact (u128). | [test: `reward_at_pinned_points`, `cumulative_emission_matches_the_script` (4 M blocks), `emission_is_enforced_exactly`] |
| Schedule (v3 merged): const-validated table, version rule keyed on `parent.height + 1` (a lying height cannot select an epoch), `UnknownUpgrade` non-permanent, blocks validated with `rules_at(h)`, pool flushed across a domain change, PX proof cache gated on the pool's domain. | [src] `schedule.rs`, `chain.rs:318-332`, `manager.rs:937-953, 979-995`; [test: `header_version_follows_the_schedule`, `malformed_tables_are_rejected`, `epoch_lookup_at_boundaries`, `activation_in_is_half_open`, `chain/tests/activation.rs` (2 tests)] |
| Decode limits cannot reject a block valid under weight/PX budgets (v1 bytes ≤ weight ≤ 600 000; PX ≤ 8 MiB; ≤ 10 000 tx; framing < 64 KiB); P2P `MAX_FRAME = MAX_BLOCK_BYTES + 64 KiB`; RPC request cap asserted ≥ 2·MAX_BLOCK_BYTES. | [math] re-checked with the v3 deploy budget (deploys have weight 0 but ≤ 1 MiB); [src] `p2p/src/message.rs:41`, `node/src/lib.rs:153` |
| Build guard: `compile_error!` on non-64-bit. | [src] `consensus/src/lib.rs:19-20` |
| Consensus fingerprint destructures `ChainParams` and `TxRules` so a new field fails to compile until it is fingerprinted. | [src] `node/src/fingerprint.rs:52-64, 104-113`; [test: `consensus_fingerprints_are_pinned`] |

### 2.2 What the tests actually prove, and do not

- **Prove:** exact LWMA/MTP arithmetic against an independent derivation; seed selection on branch, across restart and reorg (short epoch); header/id/Merkle/emission byte-exactness; that the pre-check and sequential validation agree; that stored PoW hashes are reused only under the right seed (`the_pow_cache_key_includes_the_seed`).
- **Do not prove:**
  - that the "independent Python script" exists or can be re-run: it is **not in the repository** (`git ls-files` has no `.py` outside `legacy/`/`research/`) [src]. The independence claim is unverifiable by a third party.
  - the RandomX key/input binding end to end against the reference implementation for a BlackSilk header (only the official RandomX vectors, and a same-implementation reference in `manager.rs:1161`).
  - four block-rule rejections (§4 F-02) and the decode boundaries (`MAX_BLOCK_BYTES + 1`, `tx_count = 0`, `10 001`) [src grep].
  - the real seed switch at 2113 (evidence item owned by 09/40).

### 2.3 Rule inventory (normative rule → spec → code → tests)

`V` = validity rule (consensus). `N` = node behaviour that decides which valid chain is followed or trusted (not validity, but divergence-relevant).

| ID | Kind | Rule | Spec | Code | Tests | Gap |
|---|---|---|---|---|---|---|
| NP-1 | V | Per-network constants (nid, T, D0, N=60, MTP 11, FTL 360, E 2048, L 64) | consensus §1 | `params.rs:198-268` | `networks_are_distinct`, `genesis_ids_are_pinned`, `consensus_fingerprints_are_pinned` | No `ChainParams` invariant check (F-06) |
| G-1 | V | Genesis header constant, never validated, empty body, work = D0 | consensus §1, blocks §3 | `params.rs:236-268`, `chain.rs:151-172`, `manager.rs:312` | `genesis_ids_golden` | Nonce hard-coded 0; v3 beacon nonce has no field yet (40) |
| H-0 | V | 100-byte strict header encoding | consensus §2 | `header.rs:67-92` | `strict_length`, `header_bytes_and_id_golden` | — |
| H-ID | V | Block id derivation | consensus §2 | `header.rs:95-101` | `id_commits_to_every_field_and_network`, golden | — |
| H-1 | V | `version == epoch_at(P.height+1).header_version`; above max ⇒ `UnknownUpgrade` (non-permanent) else `BadVersion` | consensus §6.1, §11 | `chain.rs:318-332` | `header_version_follows_the_schedule`, `rejects_each_invalid_field` | — |
| H-2 | V | `height == P.height + 1` | §6.2 | `chain.rs:333-338` | `rejects_each_invalid_field`, precheck mutation test | — |
| H-3 | V | `timestamp > MTP11` (lower median) | §5.1 | `chain.rs:339-344`, `timestamp.rs` | `median_time_past_golden`, chain golden | — |
| H-4 | V (local, non-final) | `timestamp ≤ now + 360` | §5.2 | `chain.rs:345-350` | `rejects_each_invalid_field`, `future_limit` | Checked **before** H-5 (F-05) |
| H-5 | V | `difficulty == LWMA(P's branch)` | §4, §6.4 | `difficulty.rs`, `chain.rs:351-356` | 10 `lwma_*`, chain golden | 99/100 omission undocumented (R1-C7) |
| H-6 | V | `check_hash(RandomX(seed_id, header), difficulty)` | §3, §6.5 | `chain.rs:481-486`, `pow.rs:138-150` | `check_hash_boundaries_golden`, `insufficient_work_is_rejected` | No reference PoW vector for a BlackSilk header (V-1) |
| H-7 | V | Seed schedule on own branch | §3.1 | `pow.rs:153-160`, `chain.rs:277-280` | 5 tests (§2.1) | Real 2113 switch unexercised |
| H-8 | V | Descendants of invalid are invalid; unknown parent not stored | §6, §8 | `chain.rs:470-479, 539-565` | `invalidating_a_block_falls_back_to_best_remaining_branch`, precheck invalid test | — |
| W-1 | V | Work = difficulty; cumulative u128 incl. genesis | §3 | `chain.rs:494-503` | chain golden total 242 100 | — |
| FC-1 | N | Header-best: strictly more work, first-seen ties | §8 | `chain.rs:508-512, 556-564` | `heavier_fork_reorgs_and_lighter_fork_does_not`, `verdicts_do_not_depend_on_arrival_order` | (02) |
| FC-2 | N | Connected chain = most-work body-complete; ties keep tip | §8, blocks §6 | `manager.rs:794-815, 879-967` | `fork_choice.rs` (9) | (02) |
| MR-1 | V | `tx_root` Merkle | §7 | `merkle.rs` | `merkle_root_golden` | — |
| BF-1 | V | Block encoding: header ‖ count 1..10 000 ‖ (len ‖ tx)*, ≤ MAX_BLOCK_BYTES, no trailing bytes | blocks §4 | `block.rs:54-80` | `mutated_blocks_never_panic_and_decode_canonically`, `decodable_block_mutants_change_the_id_or_break_the_body` | No boundary vectors (F-02) |
| BV-1 | V | Body valid against state after P, ctx {h, reward(h), tx_root} | blocks §5 | `manager.rs:927-964` | `emission_is_enforced_exactly`, `invalid_side_branch_body_is_rejected_when_it_would_win` | — |
| BV-2 | V | Body validated with the rules (branch id) of its own height | consensus §11 | `manager.rs:938, 493-499` | `activation.rs` | fee/weight come from caller (F-07) |
| B1 | V | Coinbase first and only | tx §8.3 | `validate.rs:914-916, 944` | adversarial (Missing/UnexpectedCoinbase) | — |
| B2 | V | Coinbase height | tx §8.3 | `validate.rs:917-922` | adversarial | — |
| B3 | V | Coinbase total == reward + fees (u128) | tx §8.3 | `validate.rs:998-1005` | adversarial, manager | — |
| B4 | V | KI/one-time keys unique in block | tx §8.3 | `validate.rs:1030-1057` | via C2/C4 tests | coinbase C4 variant untested (F-02) |
| B5 | V | tx_root matches | tx §8.3 | `validate.rs:962-966` | adversarial, chain_integration | — |
| B6 | V | weight ≤ 600 000; PX bytes ≤ 8 MiB; deploy bytes ≤ 1 MiB | tx §8.3 | `validate.rs:968-994` | `WeightExceeded` adversarial, `deploy_rules.rs` | **PxBytesExceeded untested** (F-02) |
| B7 | V | Coinbase 1–16 outputs, no identity O/R, sorted, unique | tx §8.3 | `validate.rs:923-940, 1032-1037` | identity O, sorted | **count, identity R, duplicate untested** (F-02) |
| T/C/PX | V | Transaction rules | tx §8.1–8.2, px §11 | `tx/src/*`, `px` | (11, 10, 20–24) | out of scope |
| E-1 | V | `reward(h) = max(TAIL, (M−G(h))>>20)`; G tracked per connected chain | blocks §2 | `emission.rs:100-106`, `manager.rs:930-957, 1218-1227` | 5 tests | — |
| SCH-1 | V | Schedule table validity; `epoch_at`; `activation_in` | consensus §11 | `schedule.rs` | 4 tests | — |
| POOL-X | N (consensus-coupled) | PX5 skipped only for pooled tx verified under the block's domain | blocks §7, consensus §11 | `manager.rs:944-953` | `mempool_contents_never_change_a_blocks_verdict`, activation | (10) |
| TRUST-1 | N (trust boundary) | Stored PoW hash trusted on replay under the re-derived seed; FTL skipped on replay | blocks §8 | `manager.rs:441-452` | `restart_replays_the_store_without_recomputing_pow` | **No re-verification path (F-01)** |
| DET-1 | build | 64-bit only | consensus §9 | `lib.rs:19-20` | build | — |

### 2.4 Answers to the roster questions

1. **Is every rule written once and applied identically in live, replay and mempool paths?**
   - Header rules: yes, one `check_rules` [src, test]. PoW: one `validate` path; the miner uses the same `check_hash` [src `miner/src/lib.rs:55-60`].
   - Body rules: live and replay share `submit_inner` → `sync_state` → `validate_block_transactions_cached` [src]. Replay differs only in (a) trusting stored PoW, (b) `now = header.timestamp` (FTL bypassed; correct only if the store is the node's own), (c) skipping the low-work body policy. (a)+(b) are the same trust assumption (F-01).
   - Mempool: **not** identical by design: admission uses `validate_transfer` / `check` at `tip+1`, and `revalidate_after_extension` / `revalidate_between` restate a subset of the rules (R16-5; owners 10/11/12). The template re-states the block budgets in `Mempool::select` (PX 8 MiB, deploy 1 MiB, weight minus `COINBASE_RESERVE`) without ever validating the result (F-04). F1 (the `DuplicateOneTimeKey` template stall) was exactly this failure class.
   - Consensus-critical values (`max_block_weight`, `fee_per_weight`) enter block validation through a caller-supplied `TxRules` (F-07).
2. **Is the rule set complete and canonical?** Header and block encodings are canonical (strict length, strict varints, no trailing bytes; mutation test proves canonical re-encode) [test]. The rule set is complete relative to the spec; I found no missing validity rule on 64-bit [src]. Canonical gaps are in *error classification* (F-05) and *documentation* (F-08), not in validity.
3. **Does any code path trust unverified data?** Yes, one: the replay trusts `pow_hash` from `blocks.dat`, protected only by CRC32 (not a MAC), with no option or sampling to re-verify (F-01). Everything else found is sound: the PoW cache is keyed by (seed, header) [test], `pow_jobs` derives seeds from the batch and cannot poison validation [test], bodies are always re-validated on replay [src]. The PX proof cache (POOL-X) is sound per R16-8 and gated per domain (owner 10).
4. **What does a second implementation need?** See §3.6.

---

## 3. Problems in scope (standard questions)

### 3.1 Stored PoW trusted on replay (F-01)
- **Problem / why:** `replay_one` preloads the stored `pow_hash` under the seed derived from the stored parent (`manager.rs:441-452`) and uses `now = header.timestamp` (`:452`). It exists because light RandomX costs ~0.75 s per header (restart would cost hours). Integrity is CRC32 per record plus the file header binding network and genesis (`blocks.md §8`).
- **Security consequence:** the store is trusted input. If an operator copies `blocks.dat` from another machine (a "bootstrap" shortcut, common in Monero practice) or a store is fabricated, every header rule except PoW (and FTL) is checked, but PoW is not. An attacker can craft a chain with arbitrary claimed difficulties (LWMA-consistent), fake `pow_hash` values, valid coinbase-only bodies and far-future timestamps. The victim then holds a tip with more claimed work than the honest chain and **never reorganizes back** (fork choice is most work), i.e. a permanent node-local split and eclipse until the data directory is wiped. Bodies are re-validated, so no invalid transaction is accepted; the damage is chain capture of that node (wallet sees a fake chain; a miner mines on it).
- **Class:** consensus-adjacent trust boundary (node-local divergence), not a validity-rule change. Not privacy-critical.
- **Prior art:** Bitcoin Core re-runs `CheckProofOfWork` on every block read from disk (`ReadBlock`: "Errors in block header … while reading block") [web]; it is cheap for SHA-256d. Monero's `monero-blockchain-import` verifies by default and needs `--dangerous-unverified-import` to skip [web]. BlackSilk's cost profile is between: full re-verification is too slow for every restart, sampling is cheap.
- **Solution (policy, no consensus change):**
  1. At startup, re-verify the PoW of a random sample of stored headers (e.g. 32 uniformly drawn with the OS RNG, plus the last 16 of the replayed best chain); any mismatch ⇒ refuse to start with a clear message. A wholesale fabricated store is detected with certainty; a single forged header among thousands is not (accepted: the store is local).
  2. `--verify-store-pow`: full re-verification on replay (parallel, `CachedPow::compute_parallel` pattern) for imported stores.
  3. Documentation (blocks.md §8, testnet.md operator section): never copy `blocks.dat` from another operator without `--verify-store-pow`.
  - *Rejected:* a keyed MAC with a node-local key: a copied data directory copies the key, so it adds complexity without covering the real case.
- **Trade-offs / risks:** ~48 × 0.75 s ≈ 36 s single-thread at startup (≈ 5 s on 8 threads, plus up to two cache builds if the sample spans seeds). Sampling must use seeds re-derived from the replayed tree, never from the store.
- **Tests:** `a_store_with_a_fabricated_pow_hash_is_refused_at_startup` (FileStore with one flipped byte in a stored `pow_hash`, CRC recomputed; with `--verify-store-pow` it must fail deterministically; with sampling, a store whose every hash is fabricated must fail); `sampling_uses_seeds_from_the_replayed_tree`.
- **Invariants never to change:** "stored PoW hashes trusted only for the node's own store" (never-change #26); replay through the same validation code.

### 3.2 Block-rule negative tests and decode boundaries missing (F-02)
- **Problem:** no test anywhere constructs `CoinbaseOutputCount`, `CoinbaseEphemeralIdentity`, `CoinbaseDuplicateOneTimeKey` or `PxBytesExceeded` [src grep over the workspace, excluding legacy]; no boundary test for `MAX_BLOCK_BYTES + 1`, `tx_count ∈ {0, 10 001}`. `transactions.md §16` itself requires "one negative test per rule … B1–B7".
- **Consequence:** a refactor that drops or loosens one of these (the Zebra #11383 and CVE-2026-41583 class: rules silently lost in a refactor) would pass CI. `CoinbaseDuplicateOneTimeKey` is load-bearing: C4 uniqueness is what makes set-based undo safe (R1 V12).
- **Class:** consensus-critical evidence gap.
- **Prior art:** Zebra's regression after moving parse-time checks into a dependency (issue #11383, 2026) and the sighash split CVE-2026-41583 / GHSA-8m29-fpq5-89jj [web]; Zcash maintains external test vectors; Bitcoin Core `test/functional/feature_block.py` enumerates one case per rule.
- **Solution:** one negative test per variant at the boundary (16 → 17 outputs, identity R, coinbase key equal to a chain key and to an in-block key, PX bytes = 8 MiB + 1 built from real-size PX-shaped bytes where proving is avoidable via the structure path, decode at exactly MAX and MAX+1). Then `cargo-mutants` on `validate.rs` 880–1120 (42).
- **Tests:** listed above; all regression.
- **Invariants:** rule semantics unchanged; tests only.

### 3.3 No template self-validation (F-04)
- **Problem:** `ChainManager::template` returns `Mempool::select` output (`manager.rs:1247-1277`) without checking it against the block rules. The block budgets are restated in `select`.
- **Consequence:** any mismatch between `select` and `validate_block_transactions` makes **every** locally mined block invalid (wasted work, a mining stall), exactly F1's history. Liveness, not safety (other nodes reject the block).
- **Prior art:** Bitcoin Core `BlockAssembler::CreateNewBlock` runs `TestBlockValidity(..., check_pow=false, check_merkle_root=false)` and throws on failure (`src/node/miner.cpp:231-233`) [web].
- **Solution:** a cheap self-check in `template()`: run the non-cryptographic block rules (B1–B7 structure, budgets, uniqueness, PX pool evolution, B3 with a placeholder coinbase total) on the selected set; on failure log ERROR and fall back to a coinbase-only template. Full validation (with crypto) as a property test. Needs a `validate.rs` entry point that skips C3/T10/PX5 (owner 10).
- **Tests:** property test `every_template_is_a_valid_block` (random pools of every kind including conflicting output keys and deploys at the sub-budget edge); regression for F1.
- **Invariants:** template content policy unchanged when valid.

### 3.4 Header-check order classifies permanently invalid headers as non-permanent (F-05)
- **Problem:** `check_rules` checks FTL (non-permanent) before difficulty (permanent) (`chain.rs:345-356`; spec §6 lists the same order). A header with a wrong difficulty *and* a future timestamp is reported `TimestampTooFarInFuture`: unpenalized, uncached, re-evaluated.
- **Consequence:** low: the check is pre-PoW and cheap, but it hands a peer a free "never penalized" wrapper for permanently invalid headers and makes error classes order-dependent (a second implementation must match the order to score identically).
- **Prior art:** Bitcoin Core `ContextualCheckBlockHeader` checks `bad-diffbits`, `time-too-old`, timewarp as `BLOCK_INVALID_HEADER` first, then `time-too-new` as `BLOCK_TIME_FUTURE` [web].
- **Solution:** order version → height → difficulty → MTP → FTL → PoW. **Not a validity change** (valid iff all checks pass; proof: conjunction is order-independent); changes only which error is reported, hence P2P scoring (policy). Coordinate with 04 (FTL) and 30/31 (scoring).
- **Tests:** property test that `validate(h).is_ok()` is unchanged over random mutations; `a_header_with_bad_difficulty_and_future_time_is_permanent`; adjust `precheck_agrees…`.
- **Invariants:** "FTL never permanent"; precheck = sequential.

### 3.5 Consensus parameters outside the schedule (F-06, F-07, F-09)
- **F-06:** `ChainParams` has public fields and no invariant check; `genesis.difficulty == initial_difficulty`, `genesis.version == epoch_at(0).header_version`, `seed_epoch.is_power_of_two()` (only a `debug_assert!` in `seed_height`), `seed_lag < seed_epoch`, window ≥ 1 are assumed. Tests mutate `initial_difficulty` and `genesis.difficulty` separately (`golden.rs:174-179`). The v3 genesis nonce has no plumbing (`params.rs:253` hard-codes `nonce: 0`; the tool prints `TESTNET_GENESIS_NONCE`).
- **F-07:** `rules_at` copies `fee_per_weight` and `max_block_weight` from the `TxRules` passed to `ChainManager::open` (`manager.rs:493-499`). Production passes `TxRules::at_height(&params, 0)` (`node/src/main.rs:102`), so it is correct today, but (a) a consensus limit is caller-supplied, and (b) a future epoch cannot change the weight limit, because `rules_at` freezes it at open-time values. Architectural, feeds 46.
- **F-09:** the fingerprint's RandomX section is a hand copy of the reference constants (`fingerprint.rs:175-212`), explicitly not read from `blacksilk-randomx`; a RandomX parameter change inside the crate leaves the fingerprint unchanged. Only the official vectors pin it.
- **Solution:** `ChainParams::check()` asserted in `HeaderChain::new` (and a unit test per built-in network); a genesis `nonce` parameter in `base()` (with 40); `rules_at` = `TxRules::at_height` only, overrides behind a test-only constructor; public `blacksilk_randomx::config` accessor read by the fingerprint (owner 05).

### 3.6 What a second implementation needs (roster question)
1. A **normative rule table** (the §2.3 inventory, turned into spec text with MUSTs; today spec content is spread over consensus.md, blocks.md, transactions.md, px.md, and "normative by code" for PX/ZK per R14 D-1).
2. **Committed vectors with their generator**: the golden values exist, but their Python oracle is not in the repo. Zcash's model: `zcash-test-vectors` (Python generators, Rust and JSON outputs checked in) [web].
3. Missing vectors (V-1 … V-7 below).
4. Exact integer semantics written down: u128 intermediates in LWMA (`prev + 1` may exceed u64 in an implementation using u64 only at unreachable timestamps near `u64::MAX`; the FTL makes it unreachable, say so), the redundant `max(1)`, the absent 99/100, lower median, cumulative work including genesis, error-class order (F-05).
5. RandomX v1 with key = 32-byte seed block id, input = 100-byte header (tevador spec) and a reference PoW vector.
6. PX/ZK: the Plonky3 transcript and proof byte grammar (R14 D-1, owners 22/24). This is the dominant blocker; the header chain itself is small.

**Proposed vectors:**
- **V-1** RandomX PoW of a BlackSilk header: `RandomX(key = testnet genesis id, input = fixed 100-byte header)` and one under a non-genesis seed, generated **offline with tevador/RandomX** (coordinate 05's reference corpus).
- **V-2** Full block bytes (header + coinbase) → block id, tx_root, weight; decode-rejection vectors (non-minimal count varint, trailing byte, count 0 / 10 001, length prefix past end, size MAX+1).
- **V-3** Golden header chain corpus (e.g. 300 regtest headers with TestPow-free fixed pow values, a fork, an invalid block): expected tip, cumulative work, per-block difficulty, MTP, and connected tip given a body arrival order (with 02).
- **V-4** Error-class table: for each header mutation, expected `HeaderError` and `is_permanent`.
- **V-5** Schedule vectors for a test 3-epoch table: version verdicts at A−1, A, A+1 and above max.
- **V-6** Emission table (exists; move data to the shared vector file).
- **V-7** v3 genesis vector after the freeze (owner 40).

### 3.7 Invariants that must never change (my scope)
Header layout, nonce offset 92, id derivation and network binding; `check_hash` semantics and d = 0 invalid; work = difficulty, u128 sum incl. genesis; strictly-greater fork choice; descendants of invalid are invalid; validation depends only on ancestors; seed E/L on own branch, key = seed id, input = whole header; LWMA loop, integer order, N, cap, floor, absent 99/100; MTP strict, FTL never permanent, no peer time; Merkle construction; emission constants and height-only reward, B3 exactness; version rule keyed on `P.height + 1`; stored PoW trusted only for the node's own store.

---

## 4. New findings

| ID | Severity | Status | Location | Scenario | Confidence |
|---|---|---|---|---|---|
| **F-01** Stored PoW hashes trusted on replay with no re-verification path | **Medium** | Not implemented | `chain/src/manager.rs:441-452` (preload, `now = timestamp`), `:82-85`; `blocks.md §8` | Operator copies a fabricated `blocks.dat` (bootstrap); node replays a chain of fake work and far-future timestamps, never reorgs back to the honest chain. | High (mechanics [src]); impact requires operator action |
| **F-02** Four block-rule rejections and all decode boundaries have no negative test | **Medium** (evidence, consensus-critical) | Not implemented | `tx/src/validate.rs:926, 933, 978, 1034`; `chain/src/block.rs:55, 62` | A refactor drops B7-count, B7-identity-R, coinbase C4 or the PX byte budget; CI stays green (Zebra #11383 class). | High ([src] workspace grep) |
| **F-03** The "independent Python script" behind the golden vectors is not in the repository | **Low–Medium** (reproducibility; second implementation) | Not implemented | `consensus/tests/golden.rs:3-8`, `chain/tests/golden.rs:1-5` | Vectors cannot be regenerated or audited for independence after the v3 freeze; a regenerated set could silently copy crate output. | High |
| **F-04** Templates are never validated before being served | **Medium** (liveness; F1 precedent) | Not implemented | `chain/src/manager.rs:1247-1277` | `select` and block validation drift (budget, conflict key); every mined block invalid until noticed. | High ([src]; F1 history) |
| **F-05** FTL checked before difficulty: permanently invalid headers classified non-permanent | **Low** | Not implemented | `consensus/src/chain.rs:345-356`; consensus.md §6 | Peer wraps bad-difficulty headers with future timestamps; never penalized or cached. | High |
| **F-06** `ChainParams` invariants unchecked; no genesis-nonce parameter | **Low** | Not implemented | `consensus/src/params.rs:168-189, 236-268`; `pow.rs:154` (debug only) | Tool or test builds inconsistent params (genesis difficulty ≠ D0, non-power-of-two epoch in release); v3 nonce needs an ad-hoc edit. | High |
| **F-07** Consensus limits (`max_block_weight`, `fee_per_weight`) caller-supplied and frozen across epochs | **Low** (architectural) | Partially implemented | `chain/src/manager.rs:493-499`; `node/src/main.rs:100-102` | A future epoch cannot change the weight limit; a tool passing other values validates with other limits. | High |
| **F-08** Spec drift in my scope | **Low / Info** | Partially implemented | consensus.md:98,110 ("0.6 s" cache, unmeasured), :157 ("adjust … by more than FTL/2": nodes never adjust), :207 ("applies it atomically": block-by-block, bounded steps), :250 (`randomx-full` "has not yet run": runs 78–79 passed per the session report), :257 and blocks.md:300 ("0.45 s"; measured ~0.75 s), :266 ("v3 candidate": merged in `9e422d8`), §4 (no 99/100 note, no `max(1)`), §6 order; testnet-v3-genesis.md and v3-upgrade-mechanism.md still say "candidate / not merged" | Operators and second implementers read stale facts. | High |
| **F-09** Fingerprint RandomX constants are hand copies | **Low** | Not implemented | `node/src/fingerprint.rs:175-212` | A parameter change inside `blacksilk-randomx` does not move the fingerprint. | High |
| **F-10** N = 60 vs zawy's current recommendation (N = 90 for T = 120) | **Informational** (pass to 03) | Accepted limitation (document) | `params.rs:260` | Faster response, more noise and more exposure to timestamp shaping than the reference recommends. | Medium [web] |
| R1-C12 (existing) verifier panic ⇒ permanent invalid, no `reconsider` | Info | Not implemented | `manager.rs:946-963` | Node-local split after a platform-specific panic. | Medium |

Challenge to the existing report: the consolidated review lists "stored PoW hashes trusted only for the node's own store" as a never-change item and treats replay as sound. It is sound **only** under that assumption, and the code offers no way to enforce or check it; F-01 turns the assumption into a check.

---

## 5. Implementation plan for phase 2

| # | Item | Files (ownership) | Consensus? | Identity | Tests | Docs | Diff. | Pri |
|---|---|---|---|---|---|---|---|---|
| 1 | Normative consensus rule table (§2.3) as a new section of consensus.md; fix every F-08 statement; record 99/100 omission, `max(1)`, u128 semantics, check order | `docs/consensus.md`, `docs/blocks.md` §8 (shared with 47, 35) | Nothing | None | — | as listed | S–M | **P0** |
| 2 | Negative test per B-rule variant + decode boundaries (F-02) | new `chain/tests/block_rules.rs` (01) | Nothing (tests) | None | regression, boundary | transactions.md §16 checklist | S | **P0** |
| 3 | Consensus vector file + committed generator (F-03, V-1…V-6); RandomX V-1 from tevador reference offline | new `consensus/tests/vectors/` data, new `tools/consensus-vectors/` (generator; test-only, flagged non-core), `consensus/tests/golden.rs`, `chain/tests/golden.rs` (01); V-1 with 05 | Nothing | None (regenerate after freeze) | differential (independent oracle), golden | docs/consensus.md vector section | M | **P0** (freeze) |
| 4 | Stored-PoW sampling at startup + `--verify-store-pow` (F-01) | `chain/src/manager.rs` replay path (01, coordinate 35), `node/src/config.rs`, `node/src/main.rs` (flag) | Policy | None | adversarial (fabricated store), regression | blocks.md §8, testnet.md operator section | M | **P1** |
| 5 | Template self-check (F-04) + property test | `chain/src/manager.rs::template` (01/09/12 shared), `tx/src/validate.rs` crypto-free entry point (owner 10) | Policy | None | property `every_template_is_a_valid_block`, F1 regression | blocks.md §7 | S–M | **P1** |
| 6 | Reorder header checks (F-05) | `consensus/src/chain.rs::check_rules` (01), coordinate 04, 31 | Error classes only (validity unchanged; proven by conjunction + property test) | None | property: validity unchanged; new permanence test | consensus.md §6 | S | P2 (before freeze if accepted: changes vectors V-4) |
| 7 | `ChainParams::check()`; genesis nonce parameter | `consensus/src/params.rs`, `chain.rs::new` (01; nonce jointly with 40) | Nothing today; nonce is part of the v3 genesis (CONS, owned by 40's procedure) | v3 (nonce) | unit per network | consensus.md §1 | S | P1 (nonce P0 with 40) |
| 8 | `rules_at` from params only; test-only override (F-07) | `chain/src/manager.rs`, `node/src/main.rs`, `tools/supply-audit/tests/regtest.rs`, tests (01, coordinate 46, 14) | Nothing externally visible | None | activation tests unchanged | — | M | P2 |
| 9 | Fingerprint reads RandomX config from the crate (F-09) | `randomx/src/config.rs` accessor (05), `node/src/fingerprint.rs` (43/40) | Nothing (fingerprint value unchanged if constants equal) | None | fingerprint pin unchanged | — | S | P2 |
| 10 | Proptest suites: arrival-order independence of `HeaderChain` over random DAGs; precheck = sequential over random batches; LWMA bounds | `consensus/tests/properties.rs` (01; framework from 41) | Nothing | None | property | — | M | P1 |
| 11 | cargo-mutants on `consensus/` and `validate.rs` block section | CI (42/43) | Nothing | None | mutation | — | S | P2 |
| 12 | `reconsider-block` operator command (R1-C12) | `chain/src/manager.rs`, `node` | Policy | None | regression | — | S | P3 |

Benchmarks: item 4 only (startup time with sampling, 1 and 8 threads, light mode).

---

## 6. Dependencies and conflicts

- **02 fork-choice:** V-3 connected-tip vectors; shares `manager.rs` (sync_state untouched by me).
- **03 difficulty / 04 timestamps:** F-05 reorder touches the FTL check; F-10 and 99/100 documentation; LWMA property tests.
- **05 randomx-conformance:** V-1 reference PoW vector; F-09 accessor in `randomx/src/config.rs`.
- **07 randomx-cache-seed:** `pow.rs` (`RandomXPow`) is theirs; I do not touch it. Sampling (item 4) must use their cache API.
- **09 mining-templates / 12 mempool:** item 5 touches `template()`; `Mempool::select` is theirs.
- **10 / 11:** B-rule semantics and a crypto-free validation entry point in `validate.rs`.
- **35 storage-recovery:** item 4 replay path and blocks.md §8.
- **40 testnet-genesis:** genesis nonce in `params.rs` (ownership to decide); V-7.
- **41 / 42 / 43:** proptest framework, mutants, CI jobs for vectors.
- **46 architecture:** F-07 and a future consensus-core crate; do not move files in phase 2 without 46's ADR.
- **47 docs:** item 1 overlaps; I propose to own consensus.md, 47 reviews.
- **50 red-team:** F-01 and F-04 are attack/test candidates.

## 7. Open questions for the coordinator

1. May the vector generator be committed as a test-only Python script (Zcash precedent), or must the independent oracle be a clean-room Rust crate (Pure-Rust policy)? I recommend Python for independence, marked non-core, data files as the pinned artifact.
2. Who owns `consensus/src/params.rs` for the v3 genesis constants (01 or 40)?
3. Is the F-05 reorder acceptable before the freeze? It changes no validity but changes error vectors and P2P scoring.
4. Should startup PoW sampling (item 4) be on by default (≈5–36 s extra startup)?
5. Template self-check: acceptable to fall back silently to a coinbase-only template on failure (with ERROR log), or should the node refuse to serve templates?

## 8. Sources

- Monero `rx_seedheight`, `randomx_init_cache(..., seedhash, HASH_SIZE)`: https://github.com/monero-project/monero/blob/master/src/crypto/rx-slow-hash.c
- Monero `check_hash_64/128`: https://github.com/monero-project/monero/blob/master/src/cryptonote_basic/difficulty.cpp
- zawy12, LWMA-1 reference (99/100, `N·N·T/20` floor, 6T cap, N = 90 for T = 120, FTL = N·T/20, MTP 11): https://github.com/zawy12/difficulty-algorithms/issues/3
- RandomX specification (tevador): https://github.com/tevador/RandomX/blob/master/doc/specs.md
- Bitcoin Core `ReadBlock` re-checks PoW on disk read: https://github.com/bitcoin/bitcoin/blob/master/src/node/blockstorage.cpp
- Bitcoin Core `ContextualCheckBlockHeader` order (bad-diffbits, time-too-old, timewarp, then time-too-new as BLOCK_TIME_FUTURE): https://github.com/bitcoin/bitcoin/blob/master/src/validation.cpp
- Bitcoin Core `CreateNewBlock` → `TestBlockValidity`: https://github.com/bitcoin/bitcoin/blob/master/src/node/miner.cpp
- Bitcoin Core anti-DoS headers sync (PR #25717): https://github.com/bitcoin/bitcoin/pull/25717
- Monero blockchain import, `--dangerous-unverified-import`: https://github.com/monero-project/monero/issues/5901 and monerod reference https://docs.getmonero.org/interacting/monerod-reference/
- Zebra regression: parse-time consensus checks dropped by a refactor (#11383): https://github.com/ZcashFoundation/zebra/issues/11383
- Zebra CVE-2026-41583, GHSA-8m29-fpq5-89jj (consensus divergence after refactor): https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-8m29-fpq5-89jj
- Zcash test vectors (Python generators, checked-in Rust/JSON vectors): https://github.com/zcash-hackworks/zcash-test-vectors
- ZIP 200 network upgrade mechanism: https://zips.z.cash/zip-0200 ; ZIP 244: https://zips.z.cash/zip-0244
- Zcash protocol specification (normative rule numbering model): https://zips.z.cash/protocol/protocol.pdf
