# TM2-CONS: second threat-model round, consensus, cryptography and economics lens

> Historical record (2026-10-02). Superseded where it conflicts with the code: the header is 172 bytes (output-root commitments, f5daa0e) and the PoW input is the 47-byte mining blob with the nonce at byte 39 (921fdd5). Current: [docs/consensus.md](../../../consensus.md), [docs/STATUS.md](../../../STATUS.md).

Agent TM2-CONS, phase 2, 2026-10-02. Internal engineering review, not an audit. Nothing
here claims that BlackSilk is secure, production-ready, audited or mathematically
proven. Zero knowledge is "statistical and conditional (computational in practice)".

## 0. Scope, method and limits

- **Code:** `rebuild/core` at **3c21afe** (clean tree), read-only. No file in the
  repository was changed. No cargo build or test was run (a mutation run shares the
  machine). No worktree was needed.
- **One experiment:** an independent Python port of `next_difficulty`
  (`C:/bszkeval/tm2-cons-scratch/daa_probe.py`), used to size the timestamp attacks in
  §3.1. Command and output are in §9.
- **Read in full:** brief.md, impl-brief.md, decisions.md (all 1,099 lines),
  48-threat-model-adversarial.md (round 1), docs/STATUS.md, docs/reviews/mutation-exemptions.md
  (E7, E18 and the index), the consensus code paths named below.
- **Read through five read-only sub-agents and then spot-checked:** dossiers 01–05, 07,
  08, 11, 14–16, 20–25, 40–42; the mutation READMEs of runs A–D; the fuzz READMEs;
  docs/consensus.md, zk.md, px.md, proof-system.md, blocks.md, transactions.md,
  testnet-v3-genesis.md; v3-consensus-changes.md.
  - Every claim this report relies on was re-checked in the code.
  - One sub-agent claim was wrong and is corrected here: the cross-activation PX-cache
    test is run by CI (`.github/workflows/ci.yml:127`).
- **Evidence tags:**
  - **[src]**: read in the code at 3c21afe;
  - **[test: name]**: a test exists (named; not run by me);
  - **[ev]**: committed evidence under docs/evidence;
  - **[probe]**: my Python probe;
  - **[dec]**: decisions.md;
  - **[assumed]** and **[unknown]**: as named.

## 1. Summary of the top findings

| ID | Finding | Severity | Pri |
|---|---|---|---|
| TM2-1 | The BVM-1 AIR (`zkvm/src/air/*`, 3,700 lines) is the soundness core of PX and has had **no mutation census**. There is no golden proof, and fuzzing exercises only completeness. A missing constraint found after the freeze forces a new CIRCUIT_ID and a genesis reset. A naive cargo-mutants run would also be meaningless, because the `CIRCUIT_DIGEST` pin test kills every AIR mutant. | High (impact: PX theft and counterfeiting inside the pool; likelihood unknown) | **P0** (measurement) |
| TM2-2 | The golden PX proof fixture is still absent. It has been decided P0 since run C. Without it, no non-proving test verifies a real proof, PX/block verdicts cannot be fingerprint samples, and four proving-only oracles stay expensive. | Medium (evidence gap) | **P0** |
| TM2-3 | Decided safety items that do not exist in code: the RandomX start-up self-test (08), store PoW sampling (01), template self-check (01 F-04), miner clock-skew refusal (04 F2), park-on-deep-reorg (02 W-7), the F48-5 quarantine marker, and the AVX-512 refusal and backend banner (27 W4). Several are not listed in STATUS.md, which is itself stale (as of e986250, 218 commits ago). | Medium (process; each item Low to Medium) | P0 for the RandomX self-test; the rest P1/P2 |
| TM2-4 | The DAA's remaining raising-race excess (+3.5% at q = 0.4, +27% at q = 0.45) and the "inherited difficulty after a won race" liveness hazard (up to 18× equilibrium) are both handed to a park policy that does not exist. The only backstop is a WARN at depth 10. | Medium (testnet); High for mainnet | P1 (P0 for a public testnet per [dec] 02) |
| TM2-5 | The `recent_rejects` blacklist (p2p) is keyed by tx id only and never flushed on a rule change, while the mempool is. The fee guard test is vacuous today (`TxRules::at_height` hard-codes the fee). It covers neither `PxFeeNotStandard` nor any other stateless rule an epoch might change. | Low now; Medium at the first activation | P1 |
| TM2-6 | The rules fingerprint does not cover block-level or PX verdicts (by design). Binary reproducibility is shown only on one Windows machine, and untracked files do not mark a build dirty. Together: a build differing in a block or PX rule is undetectable by operators until it splits. | Medium | P1 (cheap part before the trial) |
| TM2-7 | Platform determinism is evidenced on x86_64 only, for RandomX (6 reference hashes; no soft-AES, aarch64 or target-cpu leg) and for the Plonky3 verifier arithmetic (no backend differential, F27-2 W2/W3). | Medium (split vector conditional on a backend bug) | P1 |
| TM2-8 | v1 inflation detection rests on CLSAG and BP+ verifiers that have mutation evidence (run C) but no verifier fuzzing and no cross-implementation vectors. The BP+ accept proofs were produced by the project's own prover, and no independent verifier exists. The only end-to-end check, the closed-set supply audit, has an untested PX half (F40-9). | Medium (impact Critical, likelihood low) | P0 (F40-9) / P1 |
| TM2-9 | Run E is pending: tx types/codec/state, px prove/state/tree, chain submission/header_sync, p2p headers/conn/maintenance/admission, wallet checks. `replay.rs`, `store.rs`, `zk` verify/config/params, `randomx/`, both fingerprint modules and supply-audit are in no run and not in run E. | Medium (evidence gap) | P0 for run E; P1 for the rest |
| TM2-10 | Testnet D0 is unmeasured (placeholder 100) and T_g is a placeholder already in the past. Below height 144 the anti-DoS gate equals genesis work. | Medium (launch) | **P0** (genesis gate F40-12) |

No consensus-rule bug was found in this round: no path where two honest nodes on the
supported platform (x86_64, little-endian, 64-bit) reach different verdicts, and no
inflation path that holds while the cryptographic assumptions hold. Every finding above
is an evidence gap, a latent upgrade hazard, a liveness hazard, or a decided item not yet
built.

## 2. Assets and trust assumptions

- **Assets:**
  - A1: agreement on the valid chain (consensus);
  - A2: the money supply (emission, v1 hidden amounts, the PX pool);
  - A3: ownership (no spend without keys; no double spend);
  - A4: liveness (blocks keep coming; nodes keep up);
  - A5: launch integrity (genesis, identity, binaries).
- **Assumptions:**
  - DL in Ristretto255;
  - Blake2b and Poseidon2 behave as random oracles in their roles;
  - the FRI/STARK soundness of the configured Plonky3 0.7 stack with the BVM-1 AIR (§3.3);
  - an honest majority of hash power. This is **nominal** (K1, accepted): stock rx/0 JIT
    miners or rented Monero hash power outrun the safe-Rust miner by orders of magnitude.
  - every node runs a build from the same source on x86_64.

## 3. Adversaries

### 3.1 Miner (minority and majority)

**Assets:** A1, A2 (emission), A3 (double spends by reorg), A4.

**Mitigations in force [src]:**
- `HeaderChain::check_rules` (`consensus/src/chain.rs:379-441`): version, height, exact
  difficulty, MTP strict, FTL last.
- `validate` (`:556-587`): PoW last, `UnknownUpgrade` only with real PoW (RT-1).
- `next_difficulty` (`consensus/src/difficulty.rs:56-95`): LWMA N = 75, counted clock with
  step T/2, warm-up 11, solve cap 6T, defensive floor, clamp [1, u64::MAX], u128 throughout.
- `ChainParams::check` (`consensus/src/params.rs:186-233`): T, N, MTP, FTL ≤ 7,200, seed
  schedule, genesis.
- FTL is 360 s = 3T (`params.rs:117`).
- Fork choice by strictly more work: `accept` `:613`; body-complete target
  `fork_choice.rs:89-129`.
- `DEEP_REORG_WARN_DEPTH = 10` (warn only).
- Seed from the candidate's own branch: `seed_id_for` → `ancestor_id`, `chain.rs:246-305`.

| Attack | Mitigation and evidence | Residual | Severity |
|---|---|---|---|
| **M1 Majority rewrite** (rented rx/0, an insider with an xmrig bridge) | None by design: no depth limit, no checkpoints (K4). WARN at depth ≥ 10 | Any depth, at will, on the trial. Park-on-deep-reorg is decided ([dec] 02 W-7: OFF for the trial, 720 for public) but **not implemented** (grep for park/max_reorg: none) | **Accepted limitation** (K1); High for any network that holds value |
| **M2 Selfish mining** | First-seen ties (`recompute_target` keeps the connected tip, `fork_choice.rs:118-129`); blocks relayed without jitter ([dec] RT-SYNC privacy decision) | Standard Eyal–Sirer thresholds. FTL-edge stamps add +0.6 to +1.8 share points to SM1 [ev] daa-sim redteam RT-5. No labnet selfish-mining run exists | Low (testnet); P2 measurement |
| **M3 Difficulty raising** (Bahack, private compressed branch) | Counted clock: the rise is ≤ 2× the window average per block. Race excess at q = 0.4 is +3.5% (was +33.6%) [ev] daa-sim results.md, redteam RT-3; [test] `tools/daa-sim/tests/f1.rs`, `selection.rs::raising_race_is_bounded` | +3.5% at q = 0.4 and **+27.4% at q = 0.45**, "left to park" (v3-consensus-changes.md `daa-lwma75-warm` §8), and park does not exist (TM2-4) | Medium |
| **M4 Hash-and-leave after a won race** (RT-4) | None | The honest chain inherits up to 18× equilibrium difficulty [ev] redteam RT-4. Recovery is bounded by the 6T cap per counted solve, so a stall of hours. Documented only | Medium (liveness) |
| **M5 Lowering by timestamps within FTL** | One FTL-edge stamp counts ≤ min(gap, 6T); later honest stamps count one step until real time catches up. [probe]: one block stamped +360 s drops the next difficulty to **0.927×** | Repaid within the window; harness bound +≤1% [test] `f1.rs::f3_timestamp_lowering_gains_at_most_one_percent` | Low |
| **M6 Stamp redistribution** (a miner controlling all 75 stamps puts the elapsed time on the last ~7 blocks at 6T) | Same as M5 | [probe]: next difficulty **0.690×** for one block, same total elapsed time. It needs ~100% of the window's blocks. Emission worst case +0.66% (search) [ev] results.md | Low (covered by the emission criterion) |
| **M7 Time-warp** | No period boundary. The clock is monotone and its anchor is warmed over 11 blocks, so lagging stamps raise difficulty, not lower it. RT-1 anchor-lag fixed by warm-up [test] `redteam.rs::anchor_lag_attack_and_fix` | MTP has no lower bound against real time (stamps may lag arbitrarily), which only raises difficulty | Low |
| **M8 Hopper** | Criterion relaxed to ±5 points for the testnet ([dec] DAA FINAL); 100× FTL-edge hopper measures +4.2 | Must be reopened before mainnet | Accepted (testnet); P1 mainnet |
| **M9 Reorg across the RandomX key switch** (2113, 4161, …) | The seed is the candidate branch's ancestor [test] `seed_is_taken_from_the_headers_own_branch`, `chain/tests/manager.rs::the_randomx_key_switch_works_across_sync_restart_and_reorg`. `CachedPow` stores hashes, not verdicts, keyed by H(seed ‖ header) (`pow_cache.rs:38-44`); `check_hash` recomputed. Batch chunks ≤ seed_lag (`sync_policy.rs:143-146`). The cache store is bounded (MAX_CACHES = 5; RT-POW) | Liveness: a side-branch key costs a 256 MiB cache build (seconds). Real full-mode crossing evidenced once [ev] rx-fullmode-seedswitch-2026-09-29 (one machine, regtest) | Low |
| **M10 Withholding a deep heavier branch** (download starvation, 02 F-1) | None: `header_sync.rs:93-94` still sorts by height and truncates to 256; peers are picked by height | Open | Medium (P1; P0 public testnet [dec]) |
| **M11 Failed deep reorg re-validates the old chain under the actor** (02 F-2) | None | Open; liveness | Low–Medium (P1) |
| **M12 Invalid-body blocks** (expensive CLSAG/PX bodies) | F10-2 order: decode, shape, rings before any CLSAG, PX5 last (`validate.rs:1126-1409`); R12-2 weight; decode bounds (RT-FUZZ-1) | Each costs a PoW at the current difficulty, cheap at testnet D. Bounded by 8 MiB of PX bytes per block (about 3 proofs) | Low |
| **M13 Launch window** | Beacon-derived genesis id, so no precomputation before BTC block H (`consensus/src/genesis.rs`) | D0 is a placeholder (100). Below height 144 the anti-DoS threshold is genesis work (`sync_policy.rs:37-40`). T_g is a placeholder in the past, which gives a large genesis gap (block 2 = 16, +8/block [test] `tools/genesis/tests/genesis.rs::genesis_to_launch_gap_is_absorbed_by_lwma`) | Medium (P0 gate, TM2-10) |
| **M14 Clock attacks on nodes** | FTL non-permanent; warn-only `ClockMonitor` (p2p/src/clock.rs) | Miner skew refusal not implemented (04 F2); `now` read once per header batch (04 F4); `unwrap_or(0)` on clock read failures in node, p2p and miner (04 F6) | Low |

**Arithmetic and overflow [src]:**
- `check_hash` multiplies limb by limb in u128 with a carry-out test (`pow.rs:11-23`);
  [test] `check_hash_boundaries`, golden.
- Work: Σ difficulty in u128.
- `min_timestamp = MTP + 1` (`chain.rs:327`) is an unchecked add. It is reachable only
  through a crafted store, because replay passes `now = header.timestamp`. Low.

### 3.2 Forger of v1 transactions

**Assets:** A2, A3.

**Mitigations [src]:**
- **Group and encoding:**
  - Ristretto255 (prime order, no torsion class); canonical-only point decoding
    (`crypto/src/point.rs:22-28`);
  - canonical scalars (`from_canonical_bytes`, `:86-88`).
- **Stateless (`check_shape`, `check_fee`; `tx/src/validate.rs:368-450`):**
  - T4: key image ≠ identity, inputs strictly sorted by key image;
  - T5: ring indices strictly increasing;
  - T6: output keys and ephemerals ≠ identity, strictly sorted;
  - T7, T10: counts and BP+ round shape;
  - T11: `D ≠ identity`;
  - T1: size;
  - T8: exact fee `FEE_PER_WEIGHT × max_weight(n, k)`;
  - T9: balance `Σ C' − Σ C − fee·H = 0`.
- **Contextual:**
  - C1 ring resolution with ages 10 (60 for coinbase) (`resolve_input_rings :486-519`);
  - C2 key image unspent on chain and within the block (`check_key_images :567-585`);
  - C3 CLSAG over `H32(tx/sig-message, SigDomain ‖ prefix ‖ base ‖ H(bp))`, with
    SigDomain = network ‖ branch ‖ genesis id (RT-14).
- **Block:**
  - B3: coinbase total == reward + Σ fees, an exact u128 equality (`:1255-1262`);
  - B6: Σ weight (u128) ≤ 600,000;
  - BP+ batch with random 128-bit weights (`bulletproofs_plus.rs:537-551`).

| Attack | Mitigation and evidence | Residual | Severity |
|---|---|---|---|
| **V1 Double spend by key-image malleation** | Canonical encodings and a prime-order group give one key image per output. [test] `crypto/tests/malleability.rs`; run C on clsag.rs: 97 mutants, 0 missed [ev] | None found | Low |
| **V2 CLSAG forgery** | Monero CLSAG with a Ristretto port, D ≠ identity, domain-bound message. Vectors from a spec-derived reference signer and verifier in Rust (`crypto/tests/clsag_vectors.rs`) | No Monero conformance harness (W10 absent, `tools/clsag-conformance` missing); no verifier fuzz target (15 W5); no RFC 9496 A.1–A.3 vectors (15 W4) | Low likelihood; Critical impact (hidden spend) |
| **V3 BP+ forgery** (hidden inflation, the Monero 2017 class) | BP+ with 64 bits, ≤ 16 outputs, zero-challenge refusal (run C killed E13). Vectors: generators and transcripts independently derived, but **accept-proof bytes produced by the project's own prover** (`crypto/tests/bpp_vectors.rs` header). Run C: 314 mutants, 6 missed → E14 | No independent verifier ([dec] 16 required one by a different author: not in the repo). No fuzz. BPP-5 (multi-commitment malicious-prover test) open | Medium (impact Critical, likelihood low) |
| **V4 Latent BP+ panic** | `verify_weighted` zips items with weights unchecked (`:524`, BPP-6). No const assert `BITS × MAX_OUTPUTS ≤ BP_MAX_GENERATORS` (BPP-10) | Not reachable today: constants are consistent and weights are generated per item | Low (P2, a one-line const assert before the freeze) |
| **V5 Batch-weight prediction** | ChaCha20 seeded once from getrandom (`chain/src/manager.rs:199`). Hedging with block data (BPP-1) decided as policy, not done | Requires reading node memory or breaking getrandom | Low (P2) |
| **V6 Fee and balance games** | Exact fee for transfers, PX and deploys; u128 sums; `standard_fee` uses `checked_mul`; [test] `tx/tests/exact_fee.rs`, `max_weight_vectors.rs` (Python-generated `tools/vectors/max_weight.py`) | None | Low |
| **V7 Coinbase overpay or maturity bypass** | B3 exact (burning is impossible too); B2 height; maturity via C1 age 60; amounts public (`G + a·H`). [test] `chain/tests/block_rules.rs`; run C emission 19/19, block.rs all killed | `generated + reward` unchecked u64 add (`fork_choice.rs:388`), unreachable (G < 2^61 for millennia) | Low |
| **V8 Emission** | `block_reward = max((M − G) >> 20, 0.6 BLK)`, saturating (`chain/src/emission.rs:14-20`); tail emission, uncapped by design. Golden curve `chain/tests/golden.rs` | **Its Python generator is not committed** (same for consensus/tests/golden.rs) | Low (P1 reproducibility) |
| **V9 D8-B duplicate one-time keys** | Consensus allows the same `P` in different transactions (no burning-bug rule); the wallet keeps one output per key image, the largest amount (RT-10). [test] `tx/tests/output_key_uniqueness.rs` | Consensus-safe: two indices with the same P share one key image, so only one is spendable. A griefer can copy a key to "burn" a recipient's smaller duplicate, which is wallet-mitigated. Dossier 15 §2.3's "C4 ⇒ distinct ring members" is stale | Low |
| **V10 Ring reference after a reorg** | Global indices are per branch; `InvalidSignature` is contextual; mempool ring-digest revalidation (12 W1) | Liveness and linkability on deep reorgs (k4-reorg-policy.md §2) | Accepted |

### 3.3 Forger of PX proofs

**Assets:** A2 (pool), A3 (PX records), A1 (verdict agreement).

**Statement and binding [src]:**
- The kernel proves, in RV32 integer semantics, the following (`px-core/src/kernel.rs`;
  docs/px.md §4.1):
  - ownership (`owner = Hk(ak ‖ nk ‖ d)` from `sk`), or contract approval by exactly
    one function (F-20-1, exit 18);
  - membership at depth 32;
  - nullifier `Hk(NULLIFIER, nk ‖ ρ ‖ cm)` (contract: `Hk(NULLIFIER_CONTRACT, contract ‖ rcm ‖ cm)`);
  - `nf0 ≠ nf1`;
  - `ρ'_j = Hk(RHO, nf0 ‖ j)` (Faerie Gold);
  - balance over u128: `Σv + bridge_in = Σv' + bridge_out`.
- Public words: anchor, nullifiers, commitments, bridge amounts as 2 u32 words each,
  n_fn, `(contract, io_hash)`.
- Function prefixes carry ABI_VERSION, io_hash, contract and the PX6 window.
- Every execution must exit with code 0 and the exact outputs.
- `h_tx` binds every CPU table's public values; it covers the domain, prefix and base,
  so the window too (`tx/src/px.rs:423-430`).
- **Transcript order:** PARAMS_ID → statement digest (CIRCUIT_ID, programs, images,
  claimed outputs; `zkvm/src/prove.rs:82-106`) → instance count, degree bits, widths,
  quotient chunks → main commitment and public values → permutation and LogUp
  terminals → alpha → quotient and mask commitments → zeta. No value is observed after
  a challenge that depends on it (sub-agent reading of p3-batch-stark 0.7.0, plus mine
  of `zk/src/lib.rs`).

**Parameters (BS-ZK-3, `zk/src/params.rs`):**
- BabyBear with a degree-8 extension (247-bit challenges);
- LOG_BLOWUP 3, 108 queries, arity ≤ 2^4, final poly 2^6;
- query grinding 16 bits, commit grinding 0 (its witnesses must be zero);
- 8 random codewords per matrix, salted leaves (4);
- COLLISION_BITS 122;
- heights 2^8..2^22, ≤ 6,000 committed columns, proof ≤ 4 MiB.

**Soundness claim:**
- About 105 bits in unique decoding: 89.7 statistical plus 16 grinding. This needs no
  list-decoding theorem.
- About 122 bits in the Johnson regime, capped by COLLISION_BITS.
- COLLISION_BITS is the project's own evaluation of ePrint 2026/089 Theorem 3. Its
  adaptation is **argued, not proven**, and the property is extractability.
- Mixed-height FRI has no published bound. LogUp and the DEEP union are not modelled in
  `p3-security`; the independent calculator bounds them at ≥ 200.
- Evidence: [test] `params::tests::every_shape_within_limits_meets_both_security_targets`,
  `zk/tests/soundness_calc.rs` (an independent calculator).

| Attack | Mitigation and evidence | Residual | Severity |
|---|---|---|---|
| **P1 Statistical or grinding forgery** | 2^105 work at the headline (unique decoding) | Mixed-height FRI unanalysed; extractability adaptation argued only | Low (stated assumption) |
| **P2 Under-constrained AIR** (RISC Zero CVE-2025-52484 class; the dominant realistic class) | `zkvm/src/air/check.rs` constraint oracle with single-cell trace-mutation tests; `zkvm/tests/fuzz.rs::random_programs_satisfy_every_constraint` (completeness); `CIRCUIT_DIGEST` pin; kernel native = guest [test] `kernel_diff` fuzz | **No mutation census of any AIR file** (TM2-1). No golden proof. No Kani. The digest pin makes any naive mutant "caught" | **High** (impact: forged PX spends and counterfeit up to the pool; likelihood unknown) |
| **P3 Fiat–Shamir omission** (OtterSec "unfaithful claims", SP1 GHSA-c873) | Transcript order above; [test] `zk/tests/upstream_advisories.rs` (PR 2106/2256/2033/2277), `every_merkle_cap_root_count_mutation_is_refused`, `every_hidden_opening_count_mutation_is_refused` | No per-field transcript-mutation sweep over a real proof (it needs the golden proof, TM2-2) | Low |
| **P4 Proof padding and shape games** | Canonical form: exact hidden openings, one cap root (I2); decode caps before allocation (`zk/src/bounds.rs`, RT-PXDOS: 1.15 M inputs with no parser differential); shape check from degree bits (`px/src/prove.rs::check_shape_bits`); run D boundary pass, 38/39 cap ±1 mutants caught | Margins thin: widest proof about 3.8 MB against 4 MiB (4.5%); MAX_COMMITTED_COLUMNS "thin". These are liveness, not soundness | Low |
| **P5 Kernel budgets** | Exhaustive 1,766 shapes ≤ 94.3% [test] `px/tests/kernel_budget.rs`; `prove` refuses over-budget; budgets in the fingerprint | Two large registered functions can overflow a shared table, so the contract cannot be called (liveness) | Low |
| **P6 PX6 window** | `check_px_window` runs for every PX transaction, cached or not (`validate.rs:1323`); the window enters h_tx and every function prefix. [test] `tx/tests/px_window.rs`, `px_consensus.rs` (AT-5), `chain/tests/activation.rs` (CI line 127) | None found | Low |
| **P7 Nullifier double spend** | PX2 against the chain set and a block-wide set (`check_px_state`); apply re-checks (`px/src/state.rs:163-167`); `nf0 ≠ nf1` statelessly and in the kernel. Nullifiers are position-independent and fixed by (key, ρ, cm) | Mutation of `px/src/state.rs`: **none (run E pending)** | Low (evidence pending) |
| **P8 Anchor games** | Root window: the last 100 block-end roots; an anchor inside the current block is impossible (`state.rs:158-186`); compact undo [test] `compact_undo_equals_the_full_clone_reference`, `deep_reorg_across_capacity_is_exact` | Run E pending | Low |
| **P9 Registry and contract confusion** | Contract id = h64(first key image ‖ salt ‖ h32(payload incl. ELF, budget, ABI, out_words)) (`tx/src/px.rs:651-665`); duplicate ids refused on chain and in block; PX3 exact out_words; ABI must equal 1; distinct program ids | Contract-record nullifiers computable by anyone holding the opening (F21-7, accepted); owner-0 user outputs burnable (F-20-6); approvals do not bind values (F-20-2, the author's duty) | Low (accepted) |
| **P10 PX proof cache** (CVE-2026-34377/40880 class) | Cache = `same_rules && mempool.contains(full id)` (`fork_choice.rs:376-384`); the id covers the proof bytes; PX3 and PX6 are always rechecked; the pool flushes on rule change (`mempool.rs:444-459`). RT-MUTC: 9 of 10 targeted mutants caught, 1 unviable | `TxRules::domain()` omits `verifier_id` (RT-3, P1), harmless while branch ids are distinct per epoch (`Schedule::new` enforces this) | Low |
| **P11 Verifier panic or abort** | Plonky3 verify inside `catch_unwind` (`zk/src/lib.rs:182, 318`) | `check_canonical_form`, `check_fri_schedule`, `trace::shape()` asserts (`trace.rs:122, 213`) and `statement_digest` run outside the guard (F23-9; length comparisons, unreachable on the PX path). Stack depth on 1 MiB threads untested (AT-7) | Low |

### 3.4 Consensus-split attacker

| Vector | Status [src/test] | Residual | Severity |
|---|---|---|---|
| **S1 Integer width, endianness** | `compile_error!` for non-64-bit and big-endian (`consensus/src/lib.rs:19-28`); x86 without SSE2 refused (`randomx/src/lib.rs:24-25`) | No CI job proves the guards fire (08 D-11) | Low |
| **S2 Floating point in RandomX** | Native f64 in round-to-nearest; the other modes emulated exactly (TwoSum/Dekker; `randomx/src/fpu.rs:50-175`); no `mul_add` | NaN patterns held as f64 (D-4); the subnormal round-to-nearest shortcut is unasserted (05 F-4); no FPU oracle (C3); 6 reference hashes, none in BlackSilk's 32-byte-key / 100-byte-header shape | Medium (with S3) |
| **S3 Build and backend variance** | x86_64 CI only for RandomX vectors; `aes` 0.8.4 picks AES-NI or soft at runtime | **Never run:** soft-AES leg, aarch64, target-cpu=native. **No runtime self-test** in node or miner ([dec] 08 requires one; grep finds none). Plonky3 SIMD backends: no backend differential, no AVX-512 refusal and no backend in `--version` ([dec] 27 W2-W4; grep finds none) | Medium (TM2-7) |
| **S4 Local clock** | FTL only, non-permanent; replay uses the block's own stamp | By design | Accepted |
| **S5 Proof cache across activations** | Gated on `rules.domain()`; flushed at an activation; AT-5 tests in CI | None while the domain differs per epoch | Low |
| **S6 Fee rule (and any stateless rule) per epoch** | `TxError::is_stateless_at` relaxes only `PxProof` near an activation (`validate.rs:1037-1042`); the guard test is `tx/tests/upgrade.rs::fee_rules_are_the_same_in_every_epoch_while_fee_errors_are_stateless` | **TM2-5:** (a) vacuous today, because `at_height` hard-codes `FEE_PER_WEIGHT`; (b) omits `PxFeeNotStandard` (a function of `MAX_PROOF_BYTES`), `TooLarge`, `PxShape` and the count rules; (c) `recent_rejects` (`p2p/src/net/admission.rs:18-30`) is keyed by id alone and never cleared, unlike the mempool. Effect at the first rule-changing activation: valid transactions are blacklisted (FIFO of 10,000) and their relayers penalized | Low now; Medium at activation |
| **S7 Build identity** | Rules and identity fingerprints with REVISIONS and samples (`node/src/fingerprint.rs`); 7 RT mutations change the rules digest [test] `tools/fingerprint-mutations.sh` | **TM2-6:** verdict samples only for `validate_transfer` (21 cases); none for B1–B8, the pool, PX6 or PX5. Same-machine Windows reproducibility only. The dirty check misses untracked and staged-only files | Medium |
| **S8 Validation order** | Every rule is pure, and order changes only the error reported (F-05, F10-2); `verdicts_do_not_depend_on_arrival_order` | None | Low |
| **S9 Replay trust** | Replay preloads stored PoW hashes and uses `now` = stamp (`replay.rs:285-296`); store PoW sampling decided ([dec] 01) but absent | Local integrity only (needs write access to the data directory) | Low |

### 3.5 Supply-inflation attacker

- **v1 layer.** Hidden amounts, so inflation is invisible unless BP+, CLSAG or T9 fails.
  - Containment: none on chain (as in Monero).
  - Detection: the closed-set supply audit (`tools/supply-audit`).
    - It recomputes every coinbase and `generated` and `px_pool`, then compares them with
      the listed wallets' holdings.
    - It needs every wallet and password (custody F48-2: trial-only seeds, local
      mid-trial runs, a central run at the end).
    - It uses the product's own scanning code, so it is not independent.
    - **Its PX half is tested only as zero (F40-9, P0 [dec], open).**
- **PX layer.** The pool is a turnstile.
  - `pool + bridge_in − bridge_out`, checked_sub in u128, in block order, both in
    validation (`validate.rs:1325-1330`) and in apply (`px/src/state.rs:169-172`), and for
    the mempool (`:839`).
  - So a full proof-system break withdraws at most `px_pool` to v1; counterfeit value
    inside PX dilutes or steals from other PX holders.
  - The kernel balance is integer u128, with no field wrap (docs/px.md §4.1; a test tries
    the wrap).
  - Bridge words are two u32 limbs [test]
    `mutation_regressions.rs::public_words_carry_the_high_word_of_each_bridge_amount`.
- **The v1 side of PX.**
  - `check_px_balance` (`tx/src/px.rs:798-820`): `v = fee + bridge_in + Σ payouts − bridge_out`
    in i128, mapped to a scalar.
  - A zero-input PX transaction must have no hidden outputs and v = 0.
  - Payout commitments are `G + a·H` with public amounts.
- **Coinbase:** exact (V7). **Deploys:** exact fee, counted in Σ fees.
- **Residual:** v1 soundness evidence (TM2-8); the PX AIR (TM2-1); and the audit's PX half
  (F40-9). Severity Medium overall; impact Critical.

### 3.6 Attacker on the genesis and fingerprint process

| Attack | Mitigation | Residual | Severity |
|---|---|---|---|
| **G1 Premine or precomputation** | The nonce is derived in consensus from BTC block H (`consensus/src/genesis.rs:89-110`; `check` refuses a pasted nonce); two-stage announcement; empty genesis body, no premine; the first RandomX key is the genesis id | The owner and any party reading BTC H start together. An orphaned H is handled by retiring the id and restarting ([dec] 40) | Low |
| **G2 Wrong D0 or T_g** | `starting_difficulty` tool exists | D0 is unmeasured (STATUS: Not implemented). A 100× under-estimate takes about 197 blocks to ramp ([dec] INV-REORG); an over-estimate stalls | Medium (**P0**) |
| **G3 Tampered or divergent operator binary** | `--print-manifest`; build flags and test-hook markers refuse non-regtest (W4-GUARD); dirty-tree refusal; guest ELFs byte-identical on three CI hosts | TM2-6; no signed tag; no CODEOWNERS; unsigned commits; the independent manifest recompute script is absent (STATUS); the operator kernel build at the reveal is still owed | Medium |
| **G4 Agent-pipeline injection into consensus code** (F48-3) | CI gates live: consensus-path trailer (paths extended, RTFP3-10), lockfile diff, unicode scan, cargo-deny; untrusted-input rule | Owner tasks open: CODEOWNERS, branch protection, signing (`git tag` empty; `%G?` = N) | Medium (process) |
| **G5 Identity reuse** | Reserved and rehearsal ids, `--final` only for 0x0001D673, KAT id 0xFFFFFF00; genesis id in every signature domain (RT-14) | None found | Low |

## 4. Round-1 consensus findings re-checked

| Round 1 | Now | Evidence |
|---|---|---|
| A1 rented majority (K1) | **Open / accepted.** Park policy decided, not built | grep: no park code; k4-reorg-policy.md |
| A2 difficulty raising | **Partially closed**: +33.6% → +3.5% at q = 0.4; q = 0.45 +27% left to the missing park | `difficulty.rs`; daa-sim RT-3 |
| A3 withheld heavier branch | **Open** (02 F-1) | `header_sync.rs:93-94` |
| A4 invalid-body cost | **Closed** (F10-2 order, R12-2, decode bounds) | `validate.rs:1126-1409`; RT-PXDOS |
| A5 / F48-5 panic → global halt | **Partially closed.** Apply failure halts without invalidating, with its own exit code (RTW1B-4; `fork_choice.rs:389-401`); `--invalidate-block` / `--reconsider-block`. The quarantine marker is only reserved (`store.rs:90-92`, type 0x82). A validation panic still exits with 101 and re-panics on replay. AT-4 (validate ⇒ apply property) and AT-7 (stack) not found | grep |
| A6 build-variant split | **Partially closed** (big-endian and 32-bit refused). Soft-AES, aarch64, target-cpu, Plonky3 backend differential and runtime self-test open | §3.4 S2/S3 |
| A7 / F48-3 silent rule drop | **Partially closed**: CI gates, REVISIONS and `Revision:` lines, fingerprint mutations, mutation runs A–D. Owner controls open | §3.6 G4 |
| A8 / F48-6 cache vs height and registry | **Closed** for v3: PX6 outside the skip, AT-5 tests in CI, RT-MUTC | §3.3 P6/P10 |
| A9 seed thrash, `/block` bypass | **Closed** (07 F07-1..4, 7; RPC gate). F07-5 `CachedPow` unbounded remains | `pow_cache.rs:34-63` |
| A10 timestamp and clock | **Closed** for the DAA (harness bounds); miner-side 04 F2/F4/F6 open | §3.1 M5–M7, M14 |
| C1 double approval | **Closed** (F-20-1) | `kernel.rs:326-344`; `unified.rs::an_input_approved_by_two_functions_is_rejected` |
| C2 FS binding | **Closed** on reading; a transcript-mutation sweep on a real proof is pending TM2-2 | §3.3 P3 |
| C3 zkVM under-constraint | **Open**: TM2-1 | §3.3 P2 |
| C4 proof padding | **Closed** (exact hidden openings; 8 codewords) | F22-1, F24-1 |
| C5 Poseidon2 break | **Accepted**; agility plan required by [dec] R2-C6 (not re-verified here) | — |
| C6 compiler in the TCB | **Accepted and mitigated** for tampering: byte-identical guests on three hosts (CI-1 closed); operator build at the reveal owed | [dec] CI-1 CLOSED |
| AT-1..AT-11 (consensus ones) | AT-5 done; AT-6 partial (`tx/tests/output_key_uniqueness.rs`; no chain-level reorg across a shared O found); AT-3 partial (`fail_next_apply_for_tests`); AT-4, AT-7 absent | grep |

## 5. Consensus-critical code without independent evidence

**Independent** means one of: a mutation census, vectors from a script written from the
spec, or a cross-implementation, fuzz or adversarial oracle that does not reuse the code
under test. Mutation run E is **pending**: tx/src/types.rs, codec.rs and state.rs;
px/src/prove.rs, state.rs and tree.rs; chain submission.rs and header_sync.rs; p2p
net/headers.rs, conn.rs, maintenance.rs and the rest of admission.rs; the wallet checks.

| Code / parameter | What exists | Missing | In run E? |
|---|---|---|---|
| `zkvm/src/air/*.rs`, `zkvm/src/prove.rs` (CIRCUIT_ID, digest, statement) | check oracle, single-cell mutation tests, completeness fuzz, digest pin | mutation census; golden proof; Kani; executor-vs-AIR differential (P1 research [dec]) | **No** |
| `zk/src/lib.rs` verify path, `config.rs`, `params.rs` | decode/analysis mutated (run D); advisories tests; soundness calculator | mutation of verify/config/params; verifier fuzz with grinding (switch decided, not built); golden proof | No |
| `randomx/src/*` (consensus PoW) | 6 reference hashes (3 keys), component KATs, 1,536 full-vs-light self-checks | mutation; reference corpus at BlackSilk shapes; FPU/IEEE oracle; soft-AES and aarch64 legs; runtime self-test | No |
| `tx/src/types.rs`, `codec.rs` (ids, hashes, encodings) | round-trip fuzz (`tx_decode`, `px_tx_struct`); fingerprint fixture id and sig message (implementation-generated) | mutation (E); **standalone tx-id / h_tx / sig-message / contract-id vectors from a spec script** (F11-5) | Yes |
| `tx/src/state.rs` (key images, outputs, registry apply/undo) | tests | mutation (E); AT-4 property | Yes |
| `px/src/state.rs`, `tree.rs`, `prove.rs` (rest) | Python Hk/tree vectors; state tests | mutation (E) | Yes |
| `chain/src/manager/submission.rs`, `header_sync.rs` | manager tests, peer_protocol fuzz | mutation (E) | Yes |
| `chain/src/manager/replay.rs`, `chain/src/store.rs` | storage tests, store fuzz | mutation | **No** |
| `crypto` CLSAG / BP+ | run C; spec-derived vectors (BP+ accept proofs self-generated) | verifier fuzz; independent BP+ verifier; Monero CLSAG conformance | No (done in C) |
| `consensus/tests/golden.rs`, `chain/tests/golden.rs` | Python-derived values | the generator scripts (not committed) | n/a |
| `node/src/fingerprint.rs`, `px/src/fingerprint.rs` | pins, RT mutation script | mutation; independent manifest recompute script; PX/block verdict samples | No |
| `tools/supply-audit` | v1 regtest test | PX test (F40-9); mutation | No |
| Formal | none (no Kani anywhere; [dec] 42 W5 X1–X11 not done) | — | — |

## 6. Consensus freeze

### 6.1 Must be frozen (the v3 rule set)

- **Header chain (`consensus/`):**
  - header layout and id hashing;
  - `check_hash` (LE, limb-wise);
  - T = 120; DAA rule `lwma1-n75-step-t/2-warm11-cap6t-floor20` (N, warm-up, step, cap,
    floor, clamp, 87 ancestors);
  - MTP 11 (strict, lower median); FTL 360;
  - RandomX rx/0 configuration and the seed schedule 2048/64;
  - the header check order classes (F-05, RT-1);
  - Merkle tx_root;
  - schedule V3 (one epoch, branch `BSv3`, verifier 1, header version);
  - network ids;
  - the genesis construction (nonce domain, beacon format).
- **Transactions (`tx/`):**
  - TX_VERSION and kinds 0–3; the codec (varints, delta rings, canonical points and
    scalars); hash tags and the prefix/base/prunable split; the SigDomain layout;
  - every T, C, B and PX rule:
    - ring 16; ages 10/60;
    - MAX_TX_SIZE, input/output caps, coinbase 1–16;
    - FEE_PER_WEIGHT 20 and `max_weight`; MAX_BLOCK_WEIGHT 600,000;
    - MAX_PX_TX_SIZE, PX_STANDARD_FEE, PX and deploy block budgets;
    - DEPLOY_FEE_PER_BYTE 50, deploy limits;
    - MAX_PAYOUTS 16, MAX_FN_OUTPUT_WORDS 256;
    - B8;
  - contract-id derivation; MAX_BLOCK_BYTES and MAX_BLOCK_TXS (decode-level).
- **Emission:** COIN, M, S = 20, tail 0.6.
- **Crypto:** generators; consensus tags (`tags::CONSENSUS`); CLSAG and BP+ transcripts;
  the 128-bit batch-weight rule.
- **zk:**
  - BS-ZK-3, every constant in `zk/src/params.rs`;
  - canonical-form rules (hidden openings, one cap root, zero commit-PoW witnesses);
  - decode caps (`PROOF_LIMITS`, `bounds.rs`);
  - transcript layout;
  - Plonky3 0.7.0 plus the three `third_party` crates (digest-pinned).
- **zkvm / px-core / px:**
  - CIRCUIT_ID and CIRCUIT_DIGEST; program-id definition and the ELF loader;
  - kernel and vault ELFs and ids; kernel budgets per n_fn;
  - ABI_VERSION 1, MAX_FN 2, prefix layout;
  - record, nullifier, ρ and owner hash domains; the Poseidon2 instance;
  - tree depth 32, ROOT_WINDOW 100;
  - the exit-code table (append-only).
- **Fingerprint:** manifest format, REVISIONS, rules/identity split.

### 6.2 Not ready to freeze

| Item | Why |
|---|---|
| zkvm AIR (CIRCUIT_DIGEST) | No mutation census (TM2-1). A survivor that reveals a missing constraint after the freeze forces a new circuit id and a reset |
| PX proof format and size envelope | Golden proof absent (TM2-2). P-5 re-run and widest-proof measurement on the frozen BS-ZK-3 kernel not done (STATUS §5). A 4.5% size margin and "thin" column margin are measured only once |
| tx encoding, PX state, tree, chain submission | Run E pending. A survivor may show an untested rule that must be fixed or pinned before freezing |
| Testnet D0 and T_g | Launch values by design, but D0 must be measured before the beacon is committed (P0 gate) |
| RandomX conformance claim | Not a freeze blocker (the algorithm is fixed upstream), but the runtime self-test is a decided P0 for genesis |
| Fingerprint coverage | Eligible ([dec] FX-RTFP3) "subject to the Wave 4 gate and this round". This round finds no blocker, but the PX/block verdict samples become possible once TM2-2 lands, and should be added before the identity is announced |
| Two cheap compile-time guards | BPP-10 and F11-10 should land before the freeze. They change no rule |
| Upgrade-mechanism hazards (TM2-5) | Not a v3 rule, so they do not block the v3 freeze. They must be fixed before any second epoch |

## 7. Ranked recommendations

### P0: blocks the freeze or the genesis

1. **TM2-1: AIR mutation census (run F).**
   - **Scope:** cargo-mutants over `zkvm/src/air/{cpu,alu_*,memory,program,poseidon,byte,util}.rs`
     and `trace.rs`.
   - **Oracle:** the `air::check` constraint oracle, the single-cell mutation tests, a new
     negative-trace corpus (one wrong value per constraint family), and the completeness
     tests.
   - **Exclude** `circuit_fingerprint.rs` and `circuit_id.rs` from the oracle, or every
     mutant is trivially caught by the digest.
   - **Pass:** the boundary pass plus a release-arithmetic pass.
   - Non-proving, so no 7 GB window is needed.
   - **Gate:** zero unexplained survivors. A survivor in a constraint is either killed by
     a new negative trace or fixed before the freeze, with a new CIRCUIT_ID.
2. **TM2-2: golden PX proof fixtures.**
   - One transfer (n_fn 0) and one two-function vault proof, generated on the frozen
     kernel and pinned by digest.
   - A non-proving CI test verifies them.
   - Single-byte tamper sweeps over every transcript-observed field must fail.
   - Then add PX5, PX6, pool and B8 verdict samples to the fingerprint (closes part of
     TM2-6).
3. **Run E to completion** with the boundary pass and the ±1 cap mutants (pending).
   Append `chain/src/manager/replay.rs` and `store.rs` record decoding, or record why
   they are excluded.
4. **TM2-10: measure testnet D0** on reference hardware against the expected launch
   hash rate (F40-12). Fix T_g by the two-stage procedure. Document the ramp.
5. **RandomX start-up self-test** ([dec] 08, not built).
   - At node and miner start, compute the KAT hashes (1a–1f, light mode) on the running
     binary.
   - Refuse to run on a mismatch, with a `--skip-randomx-self-test` override shown in
     `/info`.
   - This catches a soft-AES, FTZ or miscompiled build before it forks.
6. **F40-9: supply-audit PX test.** A regtest chain with bridge-in, PX transfers and
   bridge-out, audited to an exact match. A negative control with an injected extra PX
   record must alarm.
7. **P-5 re-run and widest-proof measurement on the frozen kernel** ([dec] 22 W1, 26).
   This confirms the 4 MiB and 6,000-column envelopes hold, with margin, for n_fn = 0, 1
   and 2.

### P1: before mainnet (and, where noted, before a public testnet or the trial)

1. **TM2-4: implement park-on-deep-reorg** (02 W-7: OFF on the trial, 720 for public).
   - Re-run daa-sim RT-3 at q = 0.4 and 0.45 against park-enabled fork choice.
   - For RT-4 (hash-and-leave), measure the stall time from 18× in daa-sim and decide
     between documenting it and an emergency rule.
   - Reopen the hopper criterion (±5) for mainnet.
2. **02 F-1 / F-2: download starvation and failed-reorg re-validation.**
   - Per-candidate `missing_bodies` and per-peer targeted download; a validated set.
   - Labnet withholding scenario as the measurement.
3. **TM2-5: rejects keyed by rule domain.**
   - Key `recent_rejects` by (id, rules domain), or clear it where the mempool's
     `enter_rules` flushes.
   - Make the guard test non-vacuous: a synthetic two-epoch schedule with a different
     fee. Extend it to `PxFeeNotStandard` and every stateless error whose parameters
     could change.
   - Carry `verifier_id` in `TxRules::domain` (RT-3).
4. **TM2-6: build identity.**
   - Cross-host reproducible node builds (Linux, with remapped paths).
   - A dirty check for untracked and staged files.
   - The independent manifest recompute script.
   - Signed tag, CODEOWNERS and branch protection (owner).
5. **TM2-7: determinism legs.**
   - CI legs: `aes_force_soft`, `ubuntu-24.04-arm` RandomX vectors, `target-cpu=native`.
   - A RandomX reference corpus at 32-byte keys and 100-byte headers (off-tree oracle
     [dec] 05).
   - The Plonky3 backend differential and verdict corpus, AVX-512 refusal and backend
     banner ([dec] 27 W2–W4).
   - Mutation census of `randomx/src/{fpu,vm}.rs`.
6. **TM2-8: v1 verifier assurance.**
   - Fuzz targets `clsag_verify` and `bpp_verify`.
   - An independent BP+ verifier by a different author ([dec] 16), checked against
     accept proofs from an independent prover.
   - The Monero CLSAG conformance harness (15 W10).
   - BPP-5 multi-commitment malicious-prover tests.
7. **F48-5 remainder.** The quarantine marker (0x82), the AT-4 property test (every
   block `validate_block_transactions` accepts applies), and AT-7 (widest proof verified
   on a 1 MiB stack).
8. **01 F-04 template self-check** (coinbase-only fallback with an ERROR log and a
   metric). Measurement: an inject-invalid-pool test.
9. **Reproducibility of the golden values.** Commit the Python generators behind
   `consensus/tests/golden.rs` and `chain/tests/golden.rs`. Add spec-script vectors for
   tx id, h_tx, sig message and contract id (F11-5).
10. **docs/STATUS.md refresh.** It is stale (as of e986250). Examples:
    - RTW1C-1 says "Not implemented" although it was accepted in FX-RTW1C;
    - the mutation gate and fuzz E1 say "Not implemented" although runs A–D and W4-FUZZ
      exist;
    - the full-mode miner across 2113 says "Not implemented" although it is in W4-RX
      evidence.

    Also add a "decided but not built" register (TM2-3).
11. **K1 / K4: the mainnet finality decision** (owner).

### P2: hardening

- `CachedPow` bound (F07-5).
- Store PoW sampling on start-up ([dec] 01).
- Miner clock-skew refusal and clock read failures (04 F2, F4, F6).
- `min_timestamp` and `generated + reward` checked adds.
- BPP-1 hedged batch weights; BPP-6 length assert.
- F11-4 total structure checks on in-memory PX objects.
- ZS-7: real-proof tests assert both security floors, not Johnson ≥ 100 with degree 5.
- F23-9: move `shape()` and `statement_digest` under the panic guard.
- A selfish-mining labnet scenario (M2).
- Docs drift: consensus.md "0.6 s"/"atomically"/"always converge"; blocks.md "B1–B7" and
  the deploy sub-budget; testnet-v3-genesis.md "GENESIS_NONCE"; zk.md:553 "≥ 100 bits
  Johnson".
- The stale dossier-15 claim about distinct ring members after D8-B.

## 8. Decided but not built (TM2-3 register)

| Decision | Source | Found in code |
|---|---|---|
| RandomX start-up self-test, stop on failure | [dec] Agent 08 | No (grep node/miner) |
| Store PoW sampling (48) + `--verify-store-pow` | [dec] Agent 01 | No (`replay.rs:285-296`) |
| Template self-check, coinbase-only fallback | [dec] Agent 01 | No (`template.rs:83-115`) |
| Miner refuses on clock skew > FTL/2 | [dec] Agent 04 | No |
| Park-on-deep-reorg | [dec] Agent 02, DAA FINAL | No |
| F48-5 quarantine marker | [dec] Agent 48 | Reserved type only |
| AVX-512 refusal, backend in `--version` | [dec] Agent 27 W4 | No |
| Independent BP+ verifier | [dec] Agent 16 | No |
| Golden PX proof fixture | [dec] 22, 42, run C | No |
| Supply-audit PX test | [dec] Agent 40 (F40-9) | No |
| Verifier-only grinding switch for fuzzing | [dec] RT-STATEFUL (P1, with RT pass) | No (P1, not overdue) |

## 9. Reproducibility of my own figures

- **Command:** `python C:/bszkeval/tm2-cons-scratch/daa_probe.py`.
- **What it is:** an independent port of `next_difficulty` at 3c21afe; D = 10^6, T = 120,
  N = 75.
- **Output:**
  `base 1000000 one FTL block 926829 0.9268 redistributed 690406 0.6904 redistrib+FTL 690406 0.6904 k 7`.
- **Meaning:**
  - One last block stamped 360 s late lowers the next difficulty by 7.3%.
  - Putting a window's elapsed time on its last 7 blocks at 6T (needs control of all 75
    stamps) lowers it by 31% for one block.
  - The 6T cap makes an extra FTL on top irrelevant.
  - Both are one-shot. The harness's emission search (+0.66% worst) is the sustained
    figure.
- **Other figures:** every other figure in this report is quoted from committed evidence
  or decisions, with its source named.
