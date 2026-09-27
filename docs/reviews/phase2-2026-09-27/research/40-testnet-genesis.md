# 40 testnet-genesis: the v3 genesis procedure, independent verification and reset gates

**Agent:** 40 (testnet-genesis), phase 2, phase 1 (research and briefing). **Date:** 2026-09-27.
**Commit read:** `rebuild/core` at `9e422d8` (`git rev-parse --short HEAD`), working tree clean.
**Method:** read-only on the repository, with no cargo builds or tests. Code, tests and docs
were read with Read, Grep and git. I wrote two small independent Python scripts in my
session scratchpad (outside the repository): one recomputes the genesis derivation, the
other computes the beacon-timing probabilities and simulates the launch ramp. Public web
sources are cited in §8. **This is internal engineering work, not an audit.**

Evidence tags:
- **[M]** mathematically established;
- **[T:name]** tested (the named test);
- **[R]** recomputed by me in Python (scratchpad, §2.4);
- **[S]** source-read;
- **[A]** assumed;
- **[U]** unknown.

---

## 1. Scope and what I read

**Code (all of it, line by line unless stated otherwise):**
- `tools/genesis/{Cargo.toml, src/lib.rs, src/main.rs, tests/genesis.rs}`;
- `consensus/src/{params.rs, header.rs, hash.rs, difficulty.rs}`;
- `node/src/{fingerprint.rs, config.rs}`, `node/build.rs`,
  `node/tests/{deploy_configs.rs, build_id.rs, info_identity.rs}`;
- `px/src/fingerprint.rs`, `px/tests/consensus_fingerprint.rs`;
- `tools/supply-audit/{src/lib.rs, src/main.rs, tests/regtest.rs}`;
- `tools/labnet/src/main.rs` (Args, Report, network selection, the end-of-run checks, the
  summary);
- grep level: `p2p/src/transport.rs` (the genesis in the session KDF), `wallet/src/wallet.rs`
  (the genesis binding, `parse_network`), `chain/src/store.rs` (the file header),
  `crypto/src/hash.rs` (`Hasher64`, `DOMAIN_PREFIX`), `consensus/tests/golden.rs`
  (`genesis_ids_golden`), `.github/workflows/ci.yml` (the toolchain pin).

**Docs:**
- `docs/testnet-v3-genesis.md` (all);
- `docs/testnet.md` §1, §2.1, §7, §7.1, §8;
- `docs/testnet-launch-checklist.md`, and the `docs/testnet-reset-plan.md` headings.

**Reviews:**
- `docs/reviews/full-review-2026-09-27.md`: every genesis, R15, supply and fingerprint row,
  the P0 list, and the never-change list;
- `docs/reviews/autonomous-session-2026-09-27.md` (all);
- `docs/reviews/v3-upgrade-mechanism.md` (grep);
- `full-review-2026-09-27/R15-testnet-decentralization.md` (all);
- SX1 and SX2 (the genesis, R15 and fingerprint rows);
- `v3-plan.md`.

**Phase 2 files:**
- `C:/bszkeval/p2/brief.md` and `roster.md` (entry 40 and its neighbours 41–50, and
  01–09);
- `decisions.md` (all);
- dossiers 01, 04 and 09 in full on the genesis topics;
- grep over dossiers 02, 05–08 and 10–21 for genesis, fingerprint, labnet and supply
  items.

**Tests that exist in my scope:**
- `tools/genesis/tests/genesis.rs`: 8 tests, plus 2 unit tests in `lib.rs`;
- `consensus/src/params.rs`: `genesis_ids_are_pinned`, `networks_are_distinct`;
- `consensus/tests/golden.rs::genesis_ids_golden`;
- `node/tests/deploy_configs.rs::consensus_fingerprints_are_pinned`;
- `px/tests/consensus_fingerprint.rs`;
- `node/src/fingerprint.rs`: 4 unit tests;
- `node/tests/info_identity.rs`;
- `node/src/config.rs::retired_testnet_identity_is_refused_until_v3`;
- `tools/supply-audit`: 4 integration tests and 2 unit tests;
- `p2p` `different_genesis_ids_cannot_talk`;
- `wallet` `the_wallet_is_bound_to_its_genesis`, `files_without_a_genesis_id_are_refused`.

---

## 2. Current state

### 2.1 What exists and is well designed

| Claim | Evidence |
|---|---|
| The genesis nonce is `LE64(Blake2b-256("BlackSilk/genesis-nonce/v1" ‖ LE32(nid) ‖ LE64(H) ‖ beacon_display)[0..8])`. It is single-purpose, domain-separated and hashes the full beacon (it does not truncate it). | [S] `tools/genesis/src/lib.rs:147-170`; [T:`preimage_layout`, `every_input_changes_the_nonce`] |
| The display-order byte-order pitfall is covered. | [T:`reversed_byte_order_gives_another_nonce`]; [R] the reversed input gives nonce `0xe053c34b01ea3951` |
| KAT: Bitcoin block 0, H = 0, id `0x0001D673` → digest `3c437d97…7e19`, nonce `0x351e3bcf977d433c`, genesis id `f35c4e2b…714e`. | [T:`known_answer_bitcoin_block_0`]; **[R] reproduced exactly with Python `hashlib.blake2b(digest_size=32)`** |
| Every genesis field except the nonce is fixed (version 1, height 0, zero parent and root, the given timestamp and difficulty). | [T:`all_genesis_fields_are_fixed`] (on the tool's output, not on `ChainParams::testnet()`) |
| `generate` refuses a future `T_g`. `verify` is clock-free and refuses a wrong id. | [T:`generate_and_verify`] |
| `D0 = max(1, ⌊rate·T/2⌋)`, monotone. | [T:`starting_difficulty_from_measured_hash_rate`] |
| The genesis gap: block 1 at `T_g + 7200` gives block-2 difficulty 16 (for D0 = 100), and the difficulty recovers within one window. | [T:`genesis_to_launch_gap_is_absorbed_by_lwma`]; [M] the 6T solve-time cap gives ⌊D0/6⌋ whatever the gap is |
| The v2 identity is retired: `--network testnet` refuses to start. | [S] `node/src/config.rs:150-161`, `node/src/main.rs:38`; [T:`retired_testnet_identity_is_refused_until_v3`] |
| The genesis id is bound into the P2P session KDF, the wallet file (refusing a mismatch or a missing id) and the block-store header (R15-3). | [S] `p2p/src/transport.rs:5-10,121-172`, `wallet/src/wallet.rs:880-897,970`, `chain/src/store.rs:5-15`; [T:`different_genesis_ids_cannot_talk`, `the_wallet_is_bound_to_its_genesis`, `files_without_a_genesis_id_are_refused`] |
| The consensus fingerprint is `Blake2b-512(len ‖ "BlackSilk/v1/node/consensus-fingerprint/v1" ‖ manifest)[..32]` over a length-prefixed, typed, injective manifest. It destructures `ChainParams` and `TxRules`, so a new field fails to compile until it is fingerprinted. It is shown in `--version`, the start-up log and `/info`, and it is pinned per network. | [S] `node/src/fingerprint.rs:35-113`, `px/src/fingerprint.rs:95-155`, `crypto/src/hash.rs:164-181`; [T:`consensus_fingerprints_are_pinned`, `px_side_consensus_constants_are_pinned`, `encoding_is_injective_on_boundaries`, `info_carries_the_node_identity`] |
| The v2 testnet id `6556f92d…037d` and the regtest id `087d6fd4…69b7` follow from the spec. | [T:`genesis_ids_are_pinned`, `genesis_ids_golden`]; **[R] both recomputed exactly in Python from the 100-byte header layout** |
| The supply audit: a closed-set equation `generated = V1 + PX`, with a node pinned at H. It is read-only (it never submits or saves unless `--save`). It rechecks the id and `tx_root` linkage from genesis, `Σ coinbase = generated + fees`, a PX pool that stays ≥ 0 per block, and that the audit block is still on chain after the run. It deduplicates by global index and by commitment. Its exit codes are 0/1/2/3. | [S] `tools/supply-audit/src/lib.rs`; [T:`complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount`, `audit_at_an_earlier_height_rewinds_the_wallets_to_it`, `a_wallet_that_cannot_reach_the_audit_block_is_refused`, `the_binary_is_read_only_and_reports_json_and_exit_codes`] |

### 2.2 What the tests do NOT prove

- **No link between the tool and the compiled chain parameters.**
  - `ChainParams::base` hard-codes `nonce: 0` (`consensus/src/params.rs:100`).
  - Nothing asserts `ChainParams::testnet().genesis == blacksilk_genesis::build(announced
    inputs)`. R15 §4.4 test 2 does not exist [S].
- **The tool's registry test forces a contradiction at the final commit** (F40-1).
- **The PX half of the supply audit has never run on a non-zero pool** [S]
  `tools/supply-audit/tests/regtest.rs:1-3`; docs/testnet.md §7.1 "Limitations".
- **The fingerprint covers constants only.** Rule code (C4 option B, CLSAG D ≠ identity,
  R12-2 weight, F-20-1, the tree capacity) is invisible to it [S]
  `node/src/fingerprint.rs:8-10`.
- **No ceremony has ever been rehearsed end to end with a real, recent Bitcoin block.**

### 2.3 The beacon soundness question (R15 §4)

**What the beacon must provide:** unpredictability of the genesis id before the reveal
time `t_r`, and public verifiability after it. It does not need unbiasability: any nonce
is valid, because the genesis is never validated (docs/blocks.md §3).

**Unpredictability.**
- Bonneau, Clark and Goldfeder show at least 68 bits of min-entropy per Bitcoin block.
  Manipulating the beacon requires withholding found blocks, at a cost of one block
  reward each [ePrint 2015/1015]. Today the reward is 3.125 BTC plus fees [A: the 2024
  subsidy].
- The only party who learns the beacon before `t_r` is the miner of block H, and only
  for its propagation time (seconds). A miner who withholds H to mine BlackSilk
  privately risks losing H to a competitor, and then the beacon changes.
- Predicting 64 bits of a hash of a future Bitcoin block hash is infeasible [M, under
  standard Blake2b assumptions].

**Verifiability.** Anyone can check the block hash against several independent sources.
Better, they can check the 80-byte header themselves: `sha256d(header)` in display order
equals the hash, and it is ≤ the target encoded in `bits` [M]. Neither check needs any
BlackSilk code.

**drand quicknet** [drand docs] is a weaker fit for the testnet:
- it is unchained BLS12-381 with 3 s rounds, and its randomness is `sha256(sig)`;
- verification needs a pairing check, so a new dependency (a pure-Rust `bls12_381`) or
  external tools;
- it adds a trust assumption (the League of Entropy threshold).

Conclusion: **Bitcoin alone suffices for the testnet** [agree with R15]. `H(btc ‖
drand_round)` remains a P3 mainnet option.

**Weak point: not the beacon, but the reveal-to-start window** (F40-3, F40-4).

### 2.4 Independent recompute (done now)

`genesis_recompute.py` (scratchpad) was written from the spec text only (docs §2, the
header layout in docs/blocks.md). It uses Python's standard `hashlib.blake2b(digest_size=32)`
(RFC 7693) and reproduces:
- the KAT digest, the nonce and the genesis id;
- the reversed-order nonce;
- the v2 testnet and regtest genesis ids.

All values match the Rust pins. This proves:
- the tool implements its specification;
- the spec is complete enough for a second implementation.

It does not prove anything about the not-yet-existing v3 values.

---

## 3. Problems in scope

### P1. The ceremony tool and the compiled constants are disconnected (F40-1, F40-2, F40-11)

**Problem.** `tools/genesis` computes the genesis, but `consensus/src/params.rs` has no
place to put the result:
- there is no nonce parameter;
- there are no beacon constants;
- the finality flag lives in the node binary (`node/src/config.rs:150`).

`rust_constants()` prints `TESTNET_NETWORK_ID`, `TESTNET_INITIAL_DIFFICULTY`,
`BTC_BEACON_HEIGHT`, `BTC_BEACON_HASH_HEX` and `TESTNET_GENESIS_NONCE`
(`lib.rs:305-323`). None of them exists in params.rs. So the "final, values-only commit"
of docs §6 step 5 would in fact be a structural edit of consensus code, made during the
ceremony.

On top of this, the registry semantics break the final state (F40-1):
- `build()` refuses any registered id (`lib.rs:219`);
- the test requires every built-in network's id to be registered (`tests/genesis.rs:124-130`);
- the KAT uses the placeholder `0x0001D673`, which is also the proposed final id.

So once the final id is committed, one of these must be true:
- the test fails; or
- the id is registered, and then `verify` (docs §6 step 6, and "anyone, later") and the KAT
  both fail.

**Security consequence.**
- A rushed, unreviewed edit of consensus code at the most time-critical moment.
- The dual-verification step, which is the procedure's main integrity control, cannot be
  run as documented.
- It is not exploitable remotely.

**Class.** Identity and consensus construction (genesis), plus procedure. It is not a
validity rule.

**Prior art.**
- Ethereum's Frontier genesis: an announced script plus a public input (the Olympic
  testnet block 1028201's hash). The genesis hash was published only after community
  consensus on block 1028201, in case of reorgs [Ethereum blog 2015-07-27].
- Zcash: the committed genesis carries public "not-before" data (BTC#436254, ETH#2521903,
  the DJIA close), and `chainparams.cpp` asserts the genesis hash [zcash chainparams].
- Grin: a finalized genesis commit whose `prev_root` has the form of a Bitcoin block hash
  [A: I did not independently confirm its height], with a pinned hash assertion.

The common pattern: **the input structure exists before the event, and the final change
is data plus an assertion.**

**Solution (recommended).**
1. Move the derivation into consensus: a new `consensus/src/genesis.rs` with
   `nonce_preimage`, `derive_genesis_nonce` and `parse_display_hex` (pure, about 40 lines,
   Blake2b already a dependency). R15 §4.2 already proposed this.
2. Add a `GenesisSpec { network_id, timestamp, difficulty, beacon: Option<Beacon { btc_height, btc_hash_display: [u8; 32] }> }`
   and `const TESTNET_V3: GenesisSpec`. `ChainParams::testnet()` derives the nonce from
   `beacon`: `None` means nonce 0 and "not final".
   - The final commit then changes exactly one `None` to `Some(Beacon{…})` and the pinned
     ids and fingerprints.
   - A nonce can never disagree with its beacon, because there is no pasted nonce.
3. `ChainParams::genesis_is_final()` replaces `TESTNET_GENESIS_FINAL`. Every binary reads
   it: the node, the wallet, the miner, supply-audit and labnet (F40-5).
4. Registry semantics:
   - `generate` refuses a registered id;
   - `verify` accepts an id iff it is unregistered **or** equals a built-in network's id
     with that network's announced inputs (`verify --network testnet` recomputes against
     `ChainParams::testnet()`);
   - the KAT uses a dedicated id reserved "test vectors only" (e.g. `0xFFFF_FF00`),
     never a real candidate;
   - reserve a documented rehearsal range (e.g. `0x0001_D6E0..=0x0001_D6EF`); the tool
     refuses rehearsal-range ids unless `--rehearsal` is given.

**Trade-offs.**
- The consensus crate gains a genesis-only function. The hash is already there, so there
  is no new dependency and no validity-path change.
- Deriving at start-up costs one Blake2b: negligible.
- Risk: a derivation bug would give a wrong genesis on every node consistently. The
  pinned-id test plus the Python recompute catch it.

**Tests.**
- `genesis_spec_final_nonce_matches_beacon` (all networks);
- `testnet_genesis_fields_explicit` (R15 §4.4 test 4 on `ChainParams::testnet()`);
- `verify_accepts_the_built_in_final_id`;
- the KAT on the reserved test id (new pinned values, recomputed in Python);
- `rehearsal_range_needs_flag`;
- `not_final_is_refused_by_node_wallet_miner` (per binary).

**Invariants.**
- Entropy only in `nonce`.
- The header layout and the id domain.
- Epoch-0 RandomX key = genesis id.
- Never reuse an id.
- The v2 and regtest ids stay byte-identical (the regtest nonce stays 0).

### P2. Beacon timing: `T_g` fixed 48 h ahead is before H only about 55–76 % of the time (F40-3)

**Problem.** Docs §4 fixes `T_g` at "about 2 h before block H's expected time
(remaining blocks × 600 s)" and calls H arriving earlier "unusual". But:
- the time to H is a sum of about 288 exponential intervals, whose standard deviation is
  √288 · 600 s ≈ 2.8 h [M];
- Bitcoin's mean interval is below 600 s whenever hash rate grows between retargets [A,
  typical].

The exact Gamma CDF [R] (`early.py`) gives P(H mined before `T_g`):

| Mean interval | Margin 2 h | Margin 4 h | Margin 8 h |
|---|---|---|---|
| 600 s | **0.24** | 0.08 | 0.001 |
| 580 s | **0.45** | 0.19 | 0.007 |
| 560 s | **0.68** | 0.39 | 0.03 |

**Consequences** when H comes first:
- the genesis is computable before `T_g`, but `generate` refuses until `T_g`;
- nodes refuse to start while `now < T_g` (the 04 decision);
- honest miners cannot produce block 1 with a timestamp > `T_g` until `now ≥ T_g − 360`.

So the reveal-to-start window (R15-4) stretches by up to `T_g − t_r`, which can be hours.
Anyone watching Bitcoin can mine privately from `t_r`, stamping blocks after `T_g`. The
trusted trial tolerates this. A public launch does not.

**Solutions.**
- **(a) Two-stage announcement (recommended).**
  - Stage 1, at least 48 h ahead, fixes everything except `T_g`: the network id, D0, H,
    the derivation, the confirmation and fallback rules, and the stage-2 rule.
  - Stage 2 is published when Bitcoin's tip reaches `H − 12` (about 2 h ahead).
    - It sets `T_g` = the stage-2 publication time, rounded down to the minute.
    - It quotes the hash of the tip at that moment (a proof of "not before").
    - It is acknowledged by at least 2 witnesses (the operators) before H (a proof of
      "before H").
  - `T_g` then precedes H with certainty.
  - The gap `t_H − T_g` has mean about 2 h and a standard deviation of about 35 min [M],
    which bounds the free-fork depth budget to about 120 headers (04-F11).
  - If H is mined before stage 2 is out, a pre-announced deterministic fallback applies:
    H' = H + 36, and stage 2 is redone. Nothing else moves, so there is nothing to grind.
- **(b) Single stage with a 3σ margin:** `T_g = E[t_H] − max(2 h, 3·600·√N)`, which is
  about 8.5 h for N = 288.
  - Simpler, but the gap is larger (up to about 11 h, a free-fork budget of about 650
    headers).
  - P(H before `T_g`) is still 3 % at a 560 s interval.

**Trade-offs.**
- (a) adds one signed message and a witness step, plus a rule the operators must follow.
- (b) is simpler but weakens R1-C1's start-up margin.
- Both keep the R15 invariant "`T_g` is fixed before the beacon, never after".
- `T_g` must never be chosen after the beacon: that allows grinding the id and future
  stamps.

**Tests.**
- The tool: `announce --stage 2 --btc-tip-height --btc-tip-hash` prints `T_g` and the
  implied window and budget (04 W11).
- A unit test that `generate` refuses `T_g` > now.
- A rehearsal (C5b) that runs stage 2 against a live Bitcoin tip.

**Invariant.** `T_g` < `t_r`. It is announced before the beacon and never edited after.

### P3. The reveal-to-start window and the trial's open door (F40-4)

**Problem.**
- The beacon becomes public at `t_H`, not at H + 6. Docs §6 has operators wait for H + 6
  (about 1 h), then compute, verify, start nodes and build the full-mode dataset.
  - The epoch-0 key is the genesis id, so the 2 GiB dataset can only be built after the
    reveal: 3–20 min in pure Rust (09).
  - A reference JIT miner builds it in seconds to minutes.
- So an outsider with automation starts about 1–2 h before the honest operators.
- Meanwhile:
  - the default config listens on `0.0.0.0` (`node/src/config.rs:229`);
  - the network id and genesis are public;
  - the session KDF admits anyone who knows both;
  - K4 has no reorg limit.

  An outsider can therefore deliver a heavier private chain to the "trusted" trial. R15's
  "trusted trial" assumes `--peer` lists, but `--peer` does not stop inbound connections.

**Consequence.** Medium for a public launch (a pre-mined majority chain; rewards farmed).
For a closed trial it is Low only if the nodes are closed to inbound strangers.

**Class.** Consensus-adjacent (fork choice by work), plus operations. There is no code
bug.

**Prior art.**
- Ethereum's Frontier released the software before the starting-gun block, so everyone
  was ready at t_r [Ethereum blog].
- Zcash used a slow-start mining ramp. It is not applicable here: it is a consensus
  change.

**Solution (procedure, no consensus change).**
1. Pre-stage the verified release-candidate binaries on every device. Make the post-reveal
   step a "fill in one hash" script.
2. Speculative start at H + 1:
   - compute and cross-check from 2 sources;
   - start nodes and miners;
   - at H + 6, re-check.
   - If H was replaced, halt, delete the data directories and restart with the new H. The
     trusted trial loses at most about 1 h.
   - The final tag still follows H + 6.
3. Trial nodes run `connect_only = true` with explicit peers, `listen = false` or a
   firewall allow-list, and no public seeds, until the owner opens the network.
4. Miners use `--prebuild auto` / the light bridge (09) so hashing starts at once.

**Tests.** A rehearsal (C5) that measures reveal → first honest block. Target: ≤ 15 min
from H + 1.

**Invariant.** No maintainer head start: the maintainer follows the same script and the
same timing.

### P4. The fingerprint cannot tell rule-code differences apart, and the rc and final fingerprints are not comparable (F40-6, F40-7)

**Problem.**
- Most v3 changes are rule code, not constants: D8/C4 option B, CLSAG D ≠ identity,
  F-20-1 `ApprovalConflict`, the R12-2 weight, the tree capacity, F-05's reorder.
- Mixed builds then have equal fingerprints. Only the commit differs, and operators
  compare the fingerprint first (13's F13-3).
- The manifest also includes the genesis bytes and id, so the rc fingerprint must differ
  from the final one. Operators have no digest that proves "rules unchanged between rc and
  final".

**Solutions.**
1. **`rules.revision`**: an ordered list of short, versioned rule identifiers, one per
   consensus decision, e.g.:
   - `D8-B:ota-unique-within-tx`
   - `CLSAG:D-not-identity`
   - `R12-2:a-prime`
   - `PX-F5`
   - `F-20-1:approval-conflict`
   - `I3:tree-capacity`
   - `FRI:canonical-schedule`
   - `CIRCUIT_ID-in-transcript`
   - `branch-id-in-sigmsg`

   These are hand-maintained. The decision log requires the owner of each rule change to
   add its entry in the same commit, with a checklist item in the consensus-change
   template.
2. **`rules.samples`**: outputs of rule functions on fixed inputs. This mechanically
   catches code changes that alter results:
   - `weight(n_in, n_out)` and the standard v1 fee for 5 shapes; `PX_STANDARD_FEE`;
     `deploy_fee` at 3 sizes;
   - `next_difficulty` on one fixed 61-block vector;
   - `median_time_past` on one fixed vector;
   - `check_hash` at the boundary (d = 1, d = 2^32 against fixed hashes);
   - the Merkle root of a 3-leaf list;
   - `sig_message` domain bytes (`SigDomain` at height 0);
   - the block id of a fixed header;
   - the genesis-nonce KAT;
   - `block_reward` (exists);
   - `seed_height` (exists).

   The PX side (the Poseidon2 instance digest, `Hk` samples) is owned by 19/21 in
   `px/src/fingerprint.rs`.
3. **Split the digest.**
   - `rules_fingerprint` = the manifest without `chain.genesis`, `chain.genesis_id` and
     `chain.network_id`.
   - `identity` = `(network_id, genesis_id)`.
   - The published `consensus_fingerprint` = H(rules_fingerprint ‖ identity), so it keeps
     one value to compare.
   - `rules_fingerprint` is published at the rc tag, 48 h ahead, and must be byte-equal
     at the final tag.
4. **`blacksilk-node --print-manifest <network>`**: the canonical encoding (hex) plus the
   render. The independent Python script (§5, item 5) recomputes the digest.

**Trade-offs.**
- Samples can change for legitimate reasons, which forces a re-pin (intended).
- The revision list is manual and could be forgotten. Samples partly backstop it, and the
  red team (50) checks it.
- The fingerprint value changes once, before the freeze.

**Tests.**
- The re-pinned `consensus_fingerprints_are_pinned`.
- `rules_fingerprint_excludes_identity`: changing only the genesis changes the identity,
  not the rules fingerprint.
- A mutation check: flipping one sample rule (e.g. the LWMA `(n+1) → n` mutant) changes
  the fingerprint.

**Invariant.** The manifest encoding stays injective. The fingerprint is never loosened
to a tolerance.

### P5. The supply audit (R15-7) is untested on its PX half; labnet has a second implementation (F40-9)

**Problem.**
- `tools/supply-audit/tests/regtest.rs` explicitly exercises only an empty PX pool.
- The trial's V14 check is the only end-to-end inflation check that will ever exist for
  v1 plus PX (R15-7, [M]). The branches for `bridge_in`/`bridge_out`, contract-record
  deduplication by commitment and PX reserved records have never produced a non-zero
  number.
- Labnet computes supply conservation separately: Σ `balance().total` + PX balance
  (`tools/labnet/src/main.rs:690-720`). `balance().total` excludes reserved outputs
  (`supply-audit/tests/regtest.rs:191`), so labnet's equality can be false while the audit
  is correct, or the reverse.

**Consequence.**
- A defect in the audit's PX arithmetic could produce a false COMPLETE; worse, a false
  ALARM, which halts the trial.
- Medium: evidence integrity for a P0 trial gate.

**Prior art.** Zcash's turnstile accounting (ZIP 209: pool balances must stay ≥ 0) is the
chain-level analogue. The audit adds the wallet side.

**Solution.**
1. A proving-tier `#[ignore]` test that performs a deposit, a PX payment, a withdrawal and
   a vault lock, then audits: `px_difference == 0`, with contract-record deduplication
   across the two vault wallets, and one wallet omitted giving its exact PX amount.
2. Labnet calls `blacksilk_supply_audit::audit` at the end instead of its own sum, and
   writes the report into `summary.json`.

**Tests.** As listed. Cost: about 5–10 min of proving (the tier used by `px_consensus`).

**Invariant.** The audit stays read-only and never submits.

### P6. Evidence is not bound to what was run (F40-10)

**Problem.** `summary.json` (labnet `Report`, `main.rs:102-143`) does not record any
node's `build_commit`, `consensus_fingerprint`, `genesis_id` or binary sha256. The
evidence directories therefore cannot be tied to a build (R14 D-12). This is a Low
evidence-hygiene issue.

**Solution.** Read `/info` once per node at start and record the identity fields, plus
the sha256 of the node and miner binaries (`--bin-dir`).

### P7. D0 and the launch ramp (F40-12, Informational)

`ramp.py` [R] implements LWMA-1 as in `consensus/src/difficulty.rs`, with a Poisson
process at a constant honest rate R, a 7,200 s genesis gap and miners stamping
`max(now, MTP+1)`. It gives:

| R | D0 | Blocks in the first hour (steady: 30) | Time to D ≥ RT/2 |
|---|---|---|---|
| 12 H/s (7 light devices) | 100 | 47.5 | 213 s |
| 12 H/s | 714 (= RT/2) | 39.5 | 45 s |
| 560 H/s (7 × 8 full threads) | 100 | 58 | 293 s |
| 560 H/s | 33,600 (= RT/2) | 39 | 45 s |

- The gap forces block 2 to ⌊D0/6⌋ whatever D0 is [M], so D0 matters mostly for block 1
  and the first few minutes.
- A badly low D0 costs about 10–28 extra blocks (≈ 200–560 BLK) in the first hour. They
  go to whoever hashes first.
- The err-low rule (÷2) is correct.
- The missing piece is the measurement: the miner has no `--benchmark` mode (09 M9-9).

**Recommendation.** D0 = `starting_difficulty(Σ measured per-device benchmark rate)`. It
is measured on the trial devices in the mode they will use at launch (light or full),
within 7 days of stage 1.

---

## 4. New findings

| ID | Severity | Status | Location | Scenario | Confidence |
|---|---|---|---|---|---|
| **F40-1** | **Medium** | Not implemented | `tools/genesis/src/lib.rs:117-125, 219, 256-257`; `tools/genesis/tests/genesis.rs:8-16, 110, 124-130` | The final commit sets testnet to the new id. `used_network_ids_are_refused` requires it registered, and then `build`/`verify` refuse it (`NetworkIdReused`). Docs §6 step 6 ("operators re-run `verify`") and "anyone, later" fail on the final tag. The KAT uses the placeholder, which is the proposed final id, so it also breaks once that id is registered | High |
| **F40-2** | **Medium** | Not implemented | `consensus/src/params.rs:83-101` (`nonce: 0`, no beacon constants); `tools/genesis/src/lib.rs:305-323`; `node/src/config.rs:150` | The "values-only" final diff is impossible: the ceremony requires a structural consensus edit (a new constants API and nonce plumbing, in two crates) under time pressure. R15 §4.4 test 2 (`testnet nonce == derive(beacon)`) is absent, so a pasted nonce that disagrees with its announced beacon would ship with a self-consistent pinned id | High |
| **F40-3** | **Medium** (public) / Low (trial) | Design defect (docs only) | `docs/testnet-v3-genesis.md` §4 items 1 and 4 | `T_g = E[t_H] − 2 h` fixed ≥ 48 h ahead is after the actual `t_H` with probability 0.24 (600 s blocks) to 0.45 (580 s) [R]. The docs call this "unusual". The reveal-to-start window then grows by `T_g − t_H` | High (math) |
| **F40-4** | **Medium** (public) / Low (closed trial) | Not implemented (procedure) | docs §6 steps 3–6; `node/src/config.rs:229` (listens on 0.0.0.0) | The beacon is public at `t_H`. Honest operators start after H + 6 + compute + dataset build (≥ 1–2 h). An outsider with the public id and genesis can connect inbound and deliver a heavier privately mined chain (K4 has no depth limit) | High |
| **F40-5** | Low | Not implemented | `node/src/config.rs:150-161` (node only); `wallet/src/wallet.rs:438-445, 520-537` | The wallet, miner, supply-audit and labnet do not refuse a non-final testnet. A testnet wallet created on the rc build is bound to the placeholder or retired genesis and is later refused by the final node (fail-safe; the seed restores). The wallet accepts `mainnet`. Labnet `--network testnet` dies at node start | High |
| **F40-6** | **Medium** | Not implemented (decided: rule-revision and rule samples) | `node/src/fingerprint.rs:8-10, 50-175` | Two v3 builds that differ in a rule-code decision (C4-B, CLSAG D, F-20-1, R12-2) have equal fingerprints and fork on the first differing transaction | High |
| **F40-7** | Low | Not implemented | `node/src/fingerprint.rs:76-77` (the genesis is inside the one digest) | No genesis-independent rules digest, so operators cannot mechanically prove that rc → final changed only the identity. A reviewer must trust `git diff` reading | High |
| **F40-8** | Low | Docs drift | `docs/testnet-v3-genesis.md:3` ("candidate", `v3/candidate`), `:124` (`GENESIS_NONCE` name), `:134` (builds the tool during the ceremony); `docs/testnet.md:96-99` (fingerprints `e7b89863…`/`d56ea868…` vs pinned `8876128f…`/`9cb0c0bf…` in `node/tests/deploy_configs.rs`); `docs/testnet.md` §1 (v2 values); `docs/testnet-launch-checklist.md` (G1–G14 vs R15 A–F, two gate systems) | Operators compare against stale published values | High |
| **F40-9** | **Medium** | Partially implemented | `tools/supply-audit/tests/regtest.rs:1-3`; `tools/labnet/src/main.rs:690-720` | The PX half of the only end-to-end inflation check has never run on non-zero values. Labnet uses a second, differently defined sum (it excludes reserved outputs) | High |
| **F40-10** | Low | Not implemented | `tools/labnet/src/main.rs:102-143` | Evidence directories cannot be tied to a build, fingerprint or genesis | High |
| **F40-11** | Low | Not implemented | `tools/genesis/src/lib.rs:36-51` | No reserved rehearsal or test-vector id ranges. C5's rehearsal needs a hand-edited constant set with an ad-hoc id | High |
| **F40-12** | Informational | — | `tools/genesis/src/lib.rs:172-181`; `miner` (no benchmark) | D0 has no measurement tool. The effect of a low D0 is bounded (§3 P7) | High ([R]) |
| **F40-13** | Low (trial) / **High** (public) | Not implemented | `git tag` (empty); no root `rust-toolchain.toml`; `node/build.rs` (no dirty flag); CI `dtolnay/rust-toolchain@…master` | The release-integrity gates B1–B3 cannot be met yet (owner 43; listed for the gate checklist). This deepens nothing new, but no ceremony step may start before them | High |
| **F40-14** | Informational | Complete and verified | `tools/genesis` KAT; pinned v2 and regtest ids | An independent Python recompute from the spec reproduces every pinned genesis value [R] | High |
| **F40-15** | Low | Not implemented | `tools/genesis/src/lib.rs:226` | The tool takes the header version from `V3.epoch_at(0)`, not from `ChainParams::for_network(n).schedule`. It is the same today and would diverge silently if a network ever got its own schedule. Fixed by P1 (build from `ChainParams`) | Medium |

I do **not** challenge the R15 design: Bitcoin block hash, display order, Blake2b,
64-bit nonce, `T_g` before the beacon. My corrections concern timing (F40-3, F40-4) and
the tool and constants plumbing (F40-1, F40-2).

---

## 5. Implementation plan for phase 2

**Order:**
1. Items 1 and 2 (plumbing).
2. Item 4 (fingerprint), after every rule decision has landed.
3. Items 5 and 6.
4. The rehearsal (§5B).
5. The rc tag.

| # | Item | Files (ownership) | External effect | Identity impact | Tests | Docs | Diff. | Prio |
|---|---|---|---|---|---|---|---|---|
| 1 | Genesis plumbing in consensus: `genesis.rs` (derivation moved from the tool), `GenesisSpec`/`Beacon`, the `TESTNET_V3` spec, the nonce derived in `ChainParams::testnet()`, `genesis_is_final()`, and `ChainParams::check()` for the genesis (difficulty = D0, version = epoch 0; with 01's F-06) | `consensus/src/genesis.rs` (new, **40**), `consensus/src/params.rs` (**40**, 01 reviews), `consensus/src/lib.rs` (export; 01) | Identity only (the genesis construction); no validity rule | Testnet: a new id at launch. Regtest and v2 byte-identical | `genesis_spec_final_nonce_matches_beacon`; `testnet_genesis_fields_explicit`; `regtest_id_unchanged`; the KAT moved into consensus | consensus.md §1, testnet-v3-genesis.md §2 | S | **P0** |
| 2 | The tool: registry semantics (F40-1), a test-vector-only KAT id (re-pinned and recomputed in Python), reserved rehearsal and test ranges, `verify --network <n>` against the compiled `ChainParams`, `announce` (stage 1 and stage 2 → canonical JSON), and printing the reveal window and free-fork budget (04 W11) | `tools/genesis/src/{lib,main}.rs`, `tools/genesis/tests/genesis.rs` (**40**) | None (tool) | None | `verify_accepts_the_built_in_final_id`, `generate_refuses_registered`, `rehearsal_range_needs_flag`, `announce_stage2_sets_tg_before_h`, the re-pinned KAT | testnet-v3-genesis.md §3, §6 | S | **P0** |
| 3 | Finality gate in every binary (F40-5): the node uses `genesis_is_final()`; the wallet refuses to create or restore a testnet wallet on a non-final build and refuses `mainnet`; the miner refuses a non-final network; supply-audit and labnet refuse | `node/src/config.rs` (**40**), `wallet/src/*` CLI (37), `miner/src/main.rs` (09), `tools/supply-audit/src/main.rs`, `tools/labnet/src/main.rs` (**40**) | Policy | None | One refusal test per binary | testnet.md | S | P1 |
| 4 | Fingerprint v3 (F40-6, F40-7): the `rules.revision` list; `rules.samples` (the chain side, §3 P4); the `rules_fingerprint`/identity split; `--print-manifest`; re-pin all networks; read the RandomX config from the crate accessor when 05 provides it (01 F-09) | `node/src/fingerprint.rs` (**40**), `node/tests/deploy_configs.rs` (**40**), `node/src/main.rs` (flag; **40**, coordinate with 36 on `/info` fields); the PX samples in `px/src/fingerprint.rs` (19/21 own their entries; one merge) | None externally; the fingerprint value changes before the freeze | The published fingerprint changes (pre-freeze, intended) | Re-pinned values; `rules_fingerprint_excludes_identity`; a mutation check (the LWMA `(n+1)` mutant moves the digest); every revision id is unique | testnet.md §2.1 (new values, what is covered), consensus-change template | M | **P0** (last before the rc) |
| 5 | Independent verification scripts (test tooling, non-core, allowed by the R2-C6 and 01 decisions): `verify_genesis.py` (a Bitcoin header PoW check from 80 raw bytes, the nonce, the header, the id; stdlib only) and `verify_manifest.py` (recomputes the fingerprint from `--print-manifest`) | `tools/genesis/scripts/` (**40**) | None | None | CI job: runs both against the KAT and the regtest manifest (with 43) | testnet-v3-genesis.md §7 | S | **P0** |
| 6 | Supply audit PX coverage (F40-9); labnet reuses the audit library; labnet identity in `summary.json` (F40-10) | `tools/supply-audit/tests/px.rs` (new, **40**), `tools/labnet/src/main.rs` (**40** for these hunks; 09 owns the I4 seed-switch instrumentation; one merge order: 09 first) | None | None | An `#[ignore]` PX proving test; a labnet smoke run | testnet.md §7.1 (remove the limitation), §8 | S–M | **P0** (trial evidence) |
| 7 | Docs: rewrite `docs/testnet-v3-genesis.md` as the final procedure (§5A) and the operator runbook; merge the checklist gate systems into one "v3 launch gates" table (§5C) in `docs/testnet-launch-checklist.md`; fix testnet.md §1/§2.1 (F40-8) | docs (**40** writes; 47 coordinates) | None | None | — | as listed | S | **P0** |
| 8 | A rehearsal ceremony (§5B) with a rehearsal id | a throwaway branch; evidence under `docs/evidence/genesis-rehearsal-<date>/` | None | The rehearsal id is registered and retired | The rehearsal record | evidence README | S (about 1 day) | **P0** |

**Benchmarks:** none of my own. D0 needs the miner `--benchmark` from 09. The rehearsal
measures reveal → first block.

### 5A. The final genesis procedure (for adoption in `docs/testnet-v3-genesis.md`)

**Pre-conditions (all must hold before stage 1).** Gates FZ1–FZ6, B1–B4 and C1–C5
(§5C) are Passed or explicitly Accepted by the owner.

**T − 7 d: release candidate.**
1. `git tag -s testnet-v3-rc`. It contains:
   - `TESTNET_V3.beacon = None`, so every binary refuses testnet;
   - the final network id (proposed `0x0001D673`, confirmed unused);
   - `D0`, `H` and the stage-1 values in `docs/testnet-v3-genesis.md` §0 "Announcement";
   - `T_g` = TBD (stage 2).
2. CI green on the tag (all jobs, `--locked`).
3. Publish, in the repo and in a second channel (§5.4 of R15):
   - the tag's signing-key fingerprint;
   - the rc `rules_fingerprint`;
   - the kernel and vault ids.
4. At least 2 operators, one on Windows and one on Linux, build the rc from a clean
   checkout. They record:
   - `blacksilk-node --version` (the rules fingerprint);
   - `sha256` of the binaries;
   - `reproduce.sh` `kernel.id`.

   Identical rules fingerprints and kernel ids are required. Binary hashes are recorded,
   and compared across same-OS builders.
5. D0 = `starting_difficulty(Σ measured benchmark rate)`, measured on the trial devices in
   their launch mode (light or full).

**T − 48 h or more: stage 1 announcement.** A signed commit (docs only) plus a signed
message in the second channel. It fixes:
- the network id and D0;
- H, chosen with an expected time about T − 0;
- the derivation (domain string, byte order, LE64 of d[0..8]);
- the confirmation rule;
- the fallback rules:
  - H is replaced by a reorg before H + 6: use the block at height H on the most-work
    Bitcoin chain;
  - H is mined before stage 2 is published: H' = H + 36, and repeat stage 2;
- the stage-2 rule;
- the start protocol.

Optionally, stamp the commit with OpenTimestamps (an external tool, not a dependency).

**When Bitcoin's tip reaches H − 12: stage 2.**
- The owner publishes a signed message with:
  - `T_g` = now, rounded down to the minute (Unix seconds and UTC);
  - the quoted tip height and hash (not-before evidence).
- At least 2 operators acknowledge it in the channel before H (before-H evidence).
- `blacksilk-genesis announce --stage 2 …` prints `T_g`, the expected gap and the
  free-fork budget.

**`t_H`: the reveal.** Each of 2 people (the owner and one operator) independently:
1. obtains H's hash and 80-byte header from 2 independent sources (their own Bitcoin Core
   `getblockhash`/`getblockheader`, or two explorers run by different organizations);
2. runs `verify_genesis.py` (the PoW check of the header, then the derivation);
3. runs `blacksilk-genesis generate …` from the rc build.

Both compare the **full** 64-hex genesis id.

**H + 1: speculative start (trusted trial only).**
- There is deliberately **no** runtime genesis override (such as a `--genesis-beacon-hex`
  flag): it would let any operator run a private genesis under the real network id.
- Instead:
  1. the owner commits `beacon = Some(…)` and the re-pinned ids and fingerprints, and tags
     `testnet-v3` (signed);
  2. operators fetch the tag, run `git diff testnet-v3-rc testnet-v3 --stat` (the
     allow-list: `consensus/src/params.rs`, `node/tests/deploy_configs.rs`, `docs/*`,
     `tools/genesis/src/lib.rs` registry line only), build, check that `--version` shows
     the **same `rules_fingerprint` as the rc** and the announced genesis id, and start
     nodes with the closed-mesh config (`connect_only`, no inbound) and miners (`--prebuild
     auto`).
- Target: ≤ 30 min from `t_H` to all devices mining.

**H + 6: confirmation.** If H is unchanged, nothing happens. If H was replaced:
1. halt;
2. retire the id (it becomes a registered "aborted launch" id);
3. restart from stage 1 with the next id.

A re-launch under the same id is never done, because data directories and wallets of the
aborted chain would otherwise mix. R15-3 would refuse them, but a fresh id is cleaner.

**After launch.**
- Each device checks `/info` `genesis_id` (full), `consensus_fingerprint` and
  `build_commit` against the announcement.
- The id is registered as "testnet v3 (date)" in the next commit.
- The owner records the CI run of the final tag.

**Anyone, later:**
- `verify_genesis.py` from the announcement and public Bitcoin data; or
- `blacksilk-genesis verify --network testnet`; or
- `b2sum -l 256` by hand (docs §6).

### 5B. Rehearsal (gate C5, before stage 1)

Run the full ceremony on a throwaway branch:
- a rehearsal id from the reserved range;
- a real, recent Bitcoin block as H;
- stage 2 simulated against the live tip, with 5 labnet nodes.

Pass criteria:
- the two independent computations agree;
- the diff allow-list check passes;
- the rc build (beacon `None`) refuses testnet;
- a v2 build and a build on another genesis are refused at the handshake (the existing
  test, re-observed);
- reveal → first block ≤ 30 min;
- the rehearsal id is registered afterwards.

### 5C. Gate checklist for the reset (one table; it replaces the G1–G14 / R15 A–F duplication)

**States:** Passed / Open / Accepted (owner). The states below are as of `9e422d8`.

| # | Gate | Evidence | State now |
|---|---|---|---|
| FZ1 | Every consensus decision in decisions.md implemented, or deferred with the owner's note (D8-B, CLSAG W1, R12-2, F-20-1, the I3 capacity, R2-C6 option A, F-05) | Commits plus the red-team (50) review | Open |
| FZ2 | The single kernel rebuild; the kernel and vault ids reproduced on Windows and Linux (R15-6) | CI `guests` both OSes; one operator reproduction | Open (Windows only) |
| FZ3 | Genesis plumbing and the tool fixed (items 1–2); the Python recompute in CI | Tests named in §5 | Open |
| FZ4 | Fingerprint v3 (revisions, samples, rules/identity split) pinned **after** FZ1–FZ2 | `consensus_fingerprints_are_pinned` | Open |
| FZ5 | Golden vectors frozen on the final rule set (01, 11, 19; golden PX proof) | Vector files plus the independent generators | Open |
| FZ6 | The finality gate in every binary (item 3) | Refusal tests | Open (node only) |
| B1 | CI green on the exact rc and final tags, all jobs, `--locked` | Run URLs, logs inspected | Open (runs 78–79 green on older commits) |
| B2 | Signed annotated `testnet-v3-rc` and `testnet-v3` tags; the key fingerprint in 2 channels; the diff allow-list | `git tag -v`; the allow-list output | Open (no tags) |
| B3 | Every device builds from the tag and records the commit, rustc version and binary sha256; `rules_fingerprint` equal rc → final | V1 record per device | Open |
| B4 | Off-site push or mirror; a root `rust-toolchain.toml` (43) | Remote refs | Partial (pushed) |
| C1 | RandomX full-mode vectors; full = light | `randomx-full` CI | Passed on older commits; re-run on the rc |
| C2 | Seed switch at 2113 exercised: light (seedrun2) **and** full mode (09 I5) | `summary.json` + logs | Partial (light only) |
| C3 | Per-device-class RandomX self-test (08 `--randomx-self-test`) | Output per device | Open |
| C4 | Sync ≥ 5,000 blocks from ≥ 3 peers; restart time and RSS with ≥ 100 PX; ZK-F4 adversarial verifier cost | Numbers or an owner acceptance | Open |
| C5 | Genesis rehearsal (§5B) | Evidence directory | Open |
| C6 | Supply-audit PX test green (item 6); labnet audit report in its summary | Test log | Open |
| D1 | A v3 validation list (full id; V14 = the supply tool; the expected RSS slope; end = max(96 h, 2113 + 720)) | Document | Open |
| D2 | Hardware minimums (≥ 8 GB on proving devices); D0 benchmark per device | testnet.md §12.1; benchmark table | Partial (docs) |
| D3 | Topology: ≥ 2 networks, explicit peers, **`connect_only`, no inbound from outside**, a designated late joiner | Plan table; configs | Open |
| D4 | The notice: coins valueless, anonymity at 7 not meaningful, PoW nominal against JIT rx/0 | README/guide | Partial |
| E1–E6 | The R15 operations gates (channel, private reporting, incident rehearsal, sampler, Windows hygiene, fresh data directories and wallets **created only after the final tag**) | Per-device checklists | Open |
| G1 | Stage 1 announced ≥ 48 h ahead; stage 2 witnessed before H | Signed messages; acknowledgements | — |
| G2 | Dual independent computation matches (full id) | Two transcripts | — |
| F | Owner approvals, separately: the decision table, stage 1, the final tag, the trial start. The report says "functional trial", never "audited" or "secure" | Written approvals | Open |

---

## 6. Dependencies and conflicts

| Roster | Interaction |
|---|---|
| 01 consensus-core | Reviews `params.rs`/`genesis.rs` (the decision says 40 owns, 01 reviews); `ChainParams::check()` (F-06) is shared, so I do the genesis part and 01 the rest; vector V-7 (the v3 genesis) comes after the ceremony; RandomX accessor (F-09) via 05 |
| 04 timestamps | W11 (the tool prints the window and budget: in my item 2); the clock-before-genesis refusal interacts with F40-3; the stage-2 design removes the early-H case |
| 05 / 08 | The RandomX config accessor for the fingerprint; the per-device self-test (C3) |
| 09 mining-templates | `--benchmark` (D0), `--prebuild auto` at launch, labnet I4/I5; **labnet merge order: 09 first**, then my identity and audit hunks; the miner finality refusal is in 09's `main.rs` |
| 13, 14, 15, 20, 21, 19 | Each rule change adds its `rules.revision` entry; 14's weight samples and 19's Poseidon2 instance digest go into the manifest (px side 19/21) |
| 30 / 32 | The closed-mesh trial config (`connect_only`, no inbound) is a config use, not a code change; confirm there is no hidden inbound path |
| 36 rpc-security | `/info` fields (`rules_fingerprint`) |
| 37–39 wallet | Wallet finality refusal and `mainnet` refusal; the "create wallets only after the final tag" operator rule |
| 41 | The proptest/fuzz inventory: none needed for the tool beyond unit tests |
| 43 ci-reproducibility | Signed tags, `rust-toolchain.toml`, the CI job for the Python scripts, dual-OS kernel reproduction, binary-hash recording; `trim-paths` status on 1.98.1 [U] |
| 44 supply-chain | Confirm that stdlib-only Python test scripts are acceptable (no packages) |
| 47 docs | Coordinates the edits to testnet.md and the checklist |
| 50 red-team | Attacks the ceremony: the genesis-id binding bypass, the diff allow-list, stage-2 witness forgery, `verify` semantics |

**Conflicts.** `node/src/fingerprint.rs` has a single owner (40), and several dossiers
want entries (13, 14, 16, 19). I propose they send entry specs and I land them in one
commit after FZ1. 16's BP+ entries are accepted as P2 samples.

---

## 7. Open questions for the coordinator

1. **The stage-2 `T_g` (two-stage announcement) or a single stage with a 3σ margin
   (about 8.5 h)?** I recommend two-stage (F40-3).
2. **Derive the nonce in consensus from a committed beacon** (my item 1), rather than
   pasting a nonce? I recommend deriving: the final diff is then one `Some(Beacon)`.
3. **The trial network closed to inbound strangers** (`connect_only`, no listen/firewall)
   until the owner opens it? I recommend yes (F40-4).
4. **Final network id:** `0x0001D673` (the current placeholder), with the KAT moved to a
   reserved test id? Reserve `0x0001D6E0..EF` for rehearsals?
5. **An aborted launch** (H reorged after the speculative start): retire the id and start
   fresh (my recommendation), or allow a same-id relaunch?
6. **Who is the second independent computer at the reveal?** An operator, not the owner's
   own second machine.
7. **Is `rules_fingerprint` added to `/info`** (36), or only to `--version` and the log?

---

## 8. Sources

**Primary and external:**
1. J. Bonneau, J. Clark, S. Goldfeder, "On Bitcoin as a public randomness source", IACR
   ePrint 2015/1015. https://eprint.iacr.org/2015/1015
2. drand, "quicknet is live on the League of Entropy mainnet" (chain hash `52db9ba7…`, 3 s
   period, `bls-unchained-g1-rfc9380`). https://docs.drand.love/blog/2023/10/16/quicknet-is-live/
3. drand protocol specification and cryptography (randomness = sha256(signature);
   unchained message = sha256(round)). https://docs.drand.love/docs/specification/ ,
   https://docs.drand.love/docs/cryptography/
4. Ethereum Foundation, "Final Steps" (2015-07-27): the Frontier genesis from an announced
   script plus the hash of testnet block 1028201. https://blog.ethereum.org/2015/07/27/final-steps
5. Ethereum community forum, "Frontier is launching at testnet block #1028201".
   https://forum.ethereum.org/discussion/2536/final-steps-frontier-is-launching-at-testnet-block-1028201
6. Zcash `src/chainparams.cpp`: the genesis pszTimestamp quoting BTC#436254, ETH#2521903
   and the DJIA close; the genesis-hash assertion. https://github.com/zcash/zcash/blob/master/src/chainparams.cpp
7. Grin, "Finalized mainnet genesis block", commit 8fc489a.
   https://github.com/mimblewimble/grin/commit/8fc489a80868fcf12fcdbc0551528bb73fc891a0
8. Bitcoin Core, `contrib/guix/README.md`: multi-builder attestations (`guix.sigs`),
   `SHA256SUMS`, `SOURCE_DATE_EPOCH`, the pinned time-machine.
   https://github.com/bitcoin/bitcoin/blob/master/contrib/guix/README.md
9. Rust RFC 3127 (trim-paths), and the cargo stabilization PR #17488.
   https://rust-lang.github.io/rfcs/3127-trim-paths.html ,
   https://github.com/rust-lang/cargo/pull/17488
10. Reproducible Builds, the definition and `SOURCE_DATE_EPOCH`.
    https://reproducible-builds.org/docs/definition/ ,
    https://reproducible-builds.org/docs/source-date-epoch/
11. OpenTimestamps (optional timestamping of the announcement). https://opentimestamps.org/
12. RFC 7693, "The BLAKE2 Cryptographic Hash and MAC" (the parameterized digest length
    used by `b2sum -l 256` and `hashlib.blake2b(digest_size=32)`).
    https://www.rfc-editor.org/rfc/rfc7693
13. Zcash ZIP 209 (shielded pool balance ≥ 0, the turnstile analogue).
    https://zips.z.cash/zip-0209
14. The Bytecoin premine and back-dated timestamps (a pointer only; secondary source),
    the historical motivation for verifiable launches.
    https://blockonomi.com/mysterious-history-of-bytecoin/

**Repository:**
- `tools/genesis/src/lib.rs:34-51, 117-125, 147-181, 218-262, 305-323`;
- `tools/genesis/tests/genesis.rs:8-24, 106-132, 179-207`;
- `consensus/src/params.rs:38-125`, `consensus/src/header.rs:52-60`,
  `consensus/src/difficulty.rs:7-43`;
- `node/src/config.rs:146-161, 229`;
- `node/src/fingerprint.rs:8-113, 177-216`;
- `node/tests/deploy_configs.rs` (the fingerprint pins);
- `px/src/fingerprint.rs:95-155`;
- `crypto/src/hash.rs:15, 164-181`;
- `tools/supply-audit/src/lib.rs:351-620`, `tools/supply-audit/tests/regtest.rs:1-3,
  187-191`;
- `tools/labnet/src/main.rs:69-72, 102-143, 337-343, 690-770`;
- `wallet/src/wallet.rs:438-445, 520-537, 880-897`;
- `p2p/src/transport.rs:5-10`;
- `docs/testnet-v3-genesis.md`, `docs/testnet.md:12-99, 298-368`,
  `docs/testnet-launch-checklist.md`;
- R15 §3–§4; SX1 (the genesis rows); decisions.md (items 07, 14, 16, D8, R2-C6, 01, 04,
  09).

**Scratchpad scripts** (not in the repository):
- `genesis_recompute.py`: the spec-only recompute of the KAT and the v2 and regtest ids;
- `early.py`: the Gamma-CDF of the beacon arrival;
- `ramp.py`: the LWMA-1 launch-ramp Monte Carlo.
