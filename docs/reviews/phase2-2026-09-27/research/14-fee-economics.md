# 14 fee-economics: research dossier (phase 2, phase 1)

Internal engineering research, not an audit. Repository read-only; no builds or tests
were run. Seconds are estimates unless a test is named.

Evidence classes: **[math]** mathematically established (arithmetic from the constants in
the source), **[test: name]** tested, **[src]** source-read, **[assumed]**, **[unknown]**.

---

## 1. Scope and what I read

**Commit:** `9e422d8` (`rebuild/core`, after the merge of `v3/candidate`).

**Code:**
- `tx/src/params.rs` (all fee, weight and budget constants; `TxRules`)
- `tx/src/types.rs` (`Transfer::weight`, `Transaction::weight`/`px_bytes`/`fee`)
- `tx/src/builder.rs` (`max_weight`, `standard_fee`)
- `tx/src/px.rs` (`deploy_fee`, `check_px_structure`, `check_px_balance`,
  `check_deploy_structure`)
- `tx/src/px_builder.rs` (fee plumbing for PX and deploys)
- `tx/src/validate.rs` (`check_structure` T8, `validate_block_transactions_cached`
  B3/B6, the PX and deploy budgets)
- `chain/src/mempool.rs` (classes, `rate_cmp`, `insert` eviction, `select`)
- `chain/src/manager.rs` (`submit_tx`, the templates)
- `p2p/src/net.rs` (`admit_tx`, `on_tx`, `on_stem_tx`), `p2p/src/limits.rs`
- `wallet/src/wallet.rs` (fee selection for transfers, PX and deploys)
- `consensus/src/schedule.rs` (`Epoch` fields)
- `node/src/fingerprint.rs`

**Tests read:**
- `tx/tests/deploy_rules.rs`: fee formula, exactness, block deploy budget
- `tx/tests/px_consensus.rs` (the PX fee exactness block, around line 243)
- `tx/tests/adversarial.rs` (`t8_fee`, B6)
- `tx/tests/validation_order.rs` (fee error classes)
- the `chain/src/mempool.rs` unit tests (eviction, selection, deploy sub-budget)
- `chain/tests/golden.rs` (names)

**Docs:**
- the brief and the roster (entries 10–14 and their neighbours)
- `docs/reviews/full-review-2026-09-27.md` (registers R12-2, R5-1, R6 MP-5/MP-6/R-FEE1,
  I4-2, P0-9, P1-18, P3-8, D5/D6/D19)
- `docs/reviews/autonomous-session-2026-09-27.md`
- source reports: R6 (§1–3), R12 (§2, §3, R12-2, R12-13), I4 §6, SX1 (R12-2 rows),
  SX2 (R12-2, C10)
- `docs/reviews/v3-upgrade-mechanism.md` §7
- `docs/blocks.md` §1–2, §5, §7; `docs/transactions.md` §8.4, T8, B3, B6, §11.3
- `docs/px.md` §11.3–11.5; `docs/zk.md` (the proof-size table)

---

## 2. Current state

### 2.1 What exists

| Item | Value / behaviour | Evidence |
|---|---|---|
| Unit | 1 BLK = 10^8 atomic | [src] `docs/blocks.md` §1 |
| v1 fee rule T8 | `fee ≥ FEE_PER_WEIGHT(20) × weight`; weight = size plus BP+ clawback | [src] `validate.rs:353-361`, `types.rs:323-332`; [test: `t8_fee`] |
| v1 wallet fee | exactly `standard_fee(n,k) = 20 × max_weight(n,k)` (varints at their maximum); 1-in/2-out = 34,460 | [src] `builder.rs:121-148`, `wallet.rs:1640-1661`; [math] R6 |
| PX fee | **exactly** `PX_STANDARD_FEE = 2 × MAX_PX_TX_SIZE = 8,912,896` (0.0891 BLK) | [src] `px.rs:723-727`; [test] `px_consensus.rs` ±delta block |
| Deploy fee | **exactly** `20 × max_weight(n,k) + 50 × payload_len` | [src] `px.rs:475-480, 799-806`; [test: `the_deploy_fee_is_the_standard_transfer_fee_plus_the_payload_rate`, `only_the_exact_deploy_fee_is_valid`, `the_payload_pays_per_byte_and_the_shape_pays_the_v1_rate`] |
| Block v1 weight | `Σ weight ≤ 600,000`. **PX and deploy weigh 0** | [src] `types.rs:450-458`, `validate.rs:968-975` |
| PX byte budget | `Σ px_bytes ≤ 8 MiB` | [src] `validate.rs:976-982` |
| Deploy sub-budget | `Σ deploy bytes ≤ 1 MiB`, **now enforced** (block rule and template) | [src] `validate.rs:986-996`, `mempool.rs:438-446`; [test: `a_block_over_the_deploy_budget_is_invalid`, `selection_respects_the_deploy_sub_budget`] |
| B3 | coinbase = reward + Σ fees, exact, u128 | [src] `validate.rs:998-1004`; [test] adversarial B3 |
| Mempool | two classes (v1: fee/weight, 50 MB; PX + deploys together: fee/px_bytes, 64 MiB); eviction of strictly cheaper entries of the **same class** only | [src] `mempool.rs:276-335`; [test: `a_full_pool_evicts_only_strictly_cheaper_entries_and_only_if_that_suffices`] |
| Relay | per-peer `inputs` bucket (one token per key image), per-peer `px` bucket 0.2/s, node-wide `px_global` 2/s burst 10, **shared by PX and deploys** | [src] `limits.rs:65-78`, `net.rs:430, 2207-2311` |
| Fingerprint | covers every fee constant, `PX_STANDARD_FEE` included; constants only, not rule code | [src] `node/src/fingerprint.rs:141-152` |
| Emission | smooth curve plus a 0.6 BLK tail | [test: `curve_matches_spec`], R6 §3.1 |

### 2.2 What is correct and well designed

- **Deterministic, exact fees for PX and deploys.** The fee is a function of public data
  only (the shape, and a payload that is public anyway). No fixed-point problem: the
  required fee does not depend on the fee. [test: `only_the_exact_deploy_fee_is_valid`]
- **The v1 part of a deploy pays exactly a standard transfer's fee** for its shape,
  which closes R6's "deploy as a cheap batch payment" gap for *fees*.
  [test: `the_deploy_fee_is_the_standard_transfer_fee_plus_the_payload_rate`]
- **B3 exactness and a height-only reward.** The supply is computable. Keep both.
- **The deploy sub-budget** now bounds how far deploys crowd PX transactions out of
  **blocks**. Every block keeps ≥ 7 MiB of PX lane.
- **The fee constants are in the consensus fingerprint.** So a change to
  `MAX_PROOF_BYTES` (which feeds `PX_STANDARD_FEE`) cannot silently change the fee
  without changing the pinned fingerprint.

### 2.3 What the tests do NOT prove

- **Nothing tests mempool *admission/eviction* between deploys and PX.**
  `selection_respects_the_deploy_sub_budget` only tests template selection from a pool
  that already holds both kinds.
- **Nothing bounds or measures the CLSAG count per block.** No test exercises a block
  whose weight-0 inputs exceed the v1 input bound.
- **No test shows that fee-rate ordering among PX transactions is harmless.**

---

## 3. Problems in scope

### 3.1 R12-2: weight-0 v1 inputs in PX and deploy transactions (CONSENSUS)

**The problem.** `Transaction::weight()` returns 0 for PX and deploy transactions
(`types.rs:452-458`). Their v1 inputs (≤ 64 each, `MAX_INPUTS`) are metered only by the
PX byte budget. A CLSAG over a 16-member ring costs about 2–4 ms [est, R12 §3; the only
measurement is 6.8 ms for a full 1-in/2-out transfer, `mempool_revalidation_cost_per_transaction`].

**The worst case, recomputed at `9e422d8`.** This corrects the review's 25–50 s figure,
which predates the enforced deploy cap. [math]
- **v1 lane:** about 886 inputs (R12 S5).
- **Deploy sub-budget:**
  - a 64-in/2-out deploy with a tiny program is about 44,338 B (R12/SX2);
  - ⌊1,048,576 / 44,338⌋ = 23 deploys, which gives **1,472 CLSAGs**.
- **PX lane (7 MiB left):**
  - one PX transaction with 64 inputs is about 2.18 MB + 44 KB;
  - 3 of them fit, which gives **192 CLSAGs** and 3 proofs.
- **Total:** about **2,550 CLSAGs**, about **5–10 s** single-threaded (plus about
  0.6 s for 3 uncached proofs). The v1 bound alone is about 1.8–3.5 s.
- **Result:** the deploy cap reduced the amplification from about 14× to **about
  2.9×**. It did **not** remove it. Before the cap, 8 MiB of deploys gave 12,096 CLSAGs.
- **Who can do it:**
  - any mempool user who holds about 1,664 spendable outputs per stall block and has
    3 PX proofs prepared;
  - fees are about 23 × 1.045 M + 3 × 8.9 M ≈ 0.51 BLK per block, and for a miner who
    stuffs its own block they are recycled, so they cost it nothing.

**Security consequence.** Block validation runs under the chain lock (bounded steps, but
one block is one step), so:
- every node stalls for about 5–10 s per such block;
- the block's producer gets a stale-rate advantage;
- IBD and replay slow down.

This is liveness and DoS, not safety.

**Classification:**
- consensus-critical (a block-validity rule);
- liveness/DoS;
- not privacy-critical, **provided the PX fee stays fixed**, which holds (below).

**Prior art:**
- **Bitcoin (BIP141).** Weight = base × 3 + total. Separately, a block
  "sigop cost ≤ 80,000", with legacy sigops scaled ×4. Bitcoin meters signature
  verification in its own dimension because bytes do not track its cost.
- **Monero.** No separate lane: every transaction byte counts toward block weight
  (penalty-free zone 300,000, `CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5`). So CLSAG
  cost is bounded by weight.
- **Zcash (ZIP-317).** Prices "logical actions" (spends/outputs/actions, transparent
  bytes / 150 or 34), not bytes, because proof and verification cost scales with
  actions. Blocks limit unpaid actions (50).
- **Ethereum.** Gas: one metered dimension covers compute and data.
- **The common principle:** every verification resource must fall under *some*
  consensus-limited meter. The v1 CLSAG work of PX and deploy transactions is the only
  unmetered resource in BlackSilk.

**Alternatives:**

| Option | Rule | Pros | Cons |
|---|---|---|---|
| (a) SX1: charge the v1 part against `MAX_BLOCK_WEIGHT`, and count only the PX-specific bytes against the PX budget | new split of encoded bytes | exact accounting | the "PX-specific bytes" split is a new byte-partition definition to specify, test and keep in sync; more surface |
| **(a′) recommended:** `weight(PX or deploy) = max_weight(n_in, n_out)` if `n_in > 0`, else 0, charged against `MAX_BLOCK_WEIGHT`; `px_bytes` unchanged (full encoded length, so a slight double count) | shape-only formula already in consensus (`builder::max_weight`) | one line of consensus logic. For a deploy, charged weight × 20 = **exactly** the v1 part of its fee (a clean invariant: "resource consumed = resource paid"). Deterministic from public counts. No encoding subtleties. The wallet can compute it before building | overestimates ring varints (10 B max against about 3 B actual), about 15 % per input; the double count costs ≤ 3 × 57 KB of the 8 MiB lane (negligible) |
| (b) Sigops-style `MAX_BLOCK_INPUTS` (Σ v1 inputs of all kinds ≤ about 900) | new constant and dimension | directly bounds CLSAG count; simple | a third packing dimension for templates; not tied to fees; v1 bytes already track CLSAG cost, so it duplicates weight |
| (c) Lower `MAX_INPUTS` for PX/deploy | per-tx | trivial | does not bound the block: smaller deploys, more of them (1 MiB / 3.7 KB ≈ 283 × 4 = 1,132). **Rejected** |
| (d) Defer / accept | none | none | 5–10 s blocks by any mempool user; another reset later |

**Recommendation: (a′).**

**Trade-offs and what could go wrong:**

1. **A new weight competition.**
   - PX transactions *with* v1 inputs (bridge-in, or a fee paid from v1) now need v1
     weight. v1 spam (0.12 BLK/block) could then crowd them out of templates.
   - The current `select` sorts every entry by rate across classes with incomparable
     units (fee/weight against fee/byte, `mempool.rs:411-413`). That is harmless today,
     because the budgets are disjoint, but not after (a′).
   - **Template policy:** first pass, the PX-proof transactions (≤ 3 per block,
     ≤ 3 × 57,449 weight); then everything else by rate. Deploys may still take v1
     weight, but at the v1 price (20 per weight unit), so this is no cheaper than v1
     spam.
2. **PX fee uniformity (P-7) must stay intact.**
   - `20 × max_weight(64,16) = 20 × 57,449 = 1,148,980 < 8,912,896` [math].
   - So the fixed PX fee covers any PX v1 part.
   - Add a `const` assertion: `FEE_PER_WEIGHT * max_weight(MAX_INPUTS, MAX_OUTPUTS) <= PX_STANDARD_FEE`.
     This needs `max_weight` to be a `const fn`, or the check goes in a test.
   - (SX1 wrote about 0.87 M; the conclusion stands.)
3. **The fingerprint covers constants only** (`fingerprint.rs:8-10`). This rule change
   would **not** change it.
   - Add a weight sample list to the manifest, as the emission samples do (`weight` of
     synthetic PX/deploy shapes, `max_weight(1,2)`, `max_weight(64,16)`), so the
     fingerprint moves with the rule.
4. **`max_weight(n, 0)` for a PX transaction with inputs and no hidden outputs** is
   defined: `bpp::proof_len(0) = None`, so it contributes 0, and `m = 1`, so there is no
   clawback. Pin it with a vector.

**Tests that prove the fix:**
- **Demonstration (write it first; it passes before the fix and fails after):** a block
  with one deploy whose v1 inputs exceed a small `rules.max_block_weight` (the pattern of
  the B6 test in `adversarial.rs:686-694`) is **accepted** today. After the fix it
  fails with `WeightExceeded`.
- **Golden vectors:**
  - `Transaction::weight` for PX 0-in, PX 1-in/0-out, PX 64-in/16-out, deploy 1-in/2-out
    and deploy 64-in/2-out;
  - a block at exactly `MAX_BLOCK_WEIGHT` is valid, and at +1 invalid (with a deploy
    contributing).
- **Invariant tests:**
  - for every deploy shape, `deploy_fee − 50 × payload == FEE_PER_WEIGHT × weight`;
  - the PX fee is ≥ the v1 fee of the largest PX v1 part.
- **Template tests:**
  - PX transactions with v1 inputs are selected under v1 congestion;
  - a template never exceeds either budget (extend the randomized test at
    `mempool.rs:1239`).
- **Adversarial:** a block assembled with 23 × 64-input deploys plus full v1 is
  rejected; a count assertion that Σ inputs ≤ ⌊597,000 / 688⌋ across all kinds.
- **Benchmark (hand to 10/45):** measure `t_clsag` and the worst block after the fix.

**Invariants that must never change:**
- the PX fee is exact and uniform;
- the deploy fee is exact and a function of public data;
- B3 exactness;
- `reward(h)` depends on the height only;
- every verification resource is under a consensus meter.

### 3.2 PX-lane mempool crowding by deploys (I4-2 / R6 MP-5, sharpened; POLICY)

**The problem.** PX transactions and deploys share one mempool class with one 64 MiB cap,
ordered and evicted by fee per byte (`mempool.rs:97-102, 276-335`). With the exact v3
fees:

| Kind | Rate (atomic/B) | Evidence |
|---|---|---|
| PX transfer, ~2.18 MB | 8,912,896 / 2,178,213 ≈ **4.09** | [math], zk.md sizes |
| Vault call, ~2.69 MB | ≈ **3.31** | [math] |
| Vault deploy (13.5 KB ELF, 1-in/2-out) | ≈ 709,460 / 15.1 KB ≈ **47** | [math] |
| Maximal deploy (1 MiB) | ≈ **50** | [math] |
| Cheapest-rate deploy (64-in/2-out, tiny program) | ≈ 1.045 M / 44.3 KB ≈ **23.6** | [math] |

**Every deploy outranks every PX transaction.** The deploy block cap keeps PX room in
*blocks*, but not in the *pool*:
- in a full pool, deploys evict PX transactions (their 45 s, 3.8 GB proofs are
  wasted);
- a PX transaction cannot enter while free space is below its size, because it can
  never evict a deploy.

**Attack scenario.**
1. The attacker fills the PX class with about 64 MiB of deploys: 64 maximal deploys,
   64 key images. This is **free until mined**.
2. Honest templates mine at most 1 MiB of deploys per block.
3. The attacker tops up about 1 MiB per block, so that free space stays below about
   2.1 MB.

**Cost of the attack:**
- about 0.25–0.52 BLK per block (1.2–2.6 % of the 20 BLK reward), paid only on what is
  mined;
- zero net for blocks the attacker mines itself.

**Effect:** private payments stop entering pools, which is censorship of the privacy
lane.

**Classification:** policy, not consensus. It is a liveness and censorship problem, and
privacy-relevant: PX is the privacy feature, and forcing users back to v1 shrinks the
PX anonymity set.

**Prior art:**
- **ZIP-401 (Zcash):**
  - mempool cost = max(size, 10,000);
  - eviction is **random**, weighted by cost + `low_fee_penalty` (40,000 when the fee
    is below the conventional fee), so an attacker cannot predict or lock the
    survivors;
  - a recently-evicted list (40,000 entries).
- **ZIP-317:** fees by logical action and weighted-random block selection, with
  weight_ratio capped at 4.
- **Bitcoin Core:** fee-rate eviction and a minimum fee that rises when the pool is
  full. Not suitable for a uniform-fee class.

**Recommendation (policy, P1; owner: 12):**
1. **Sub-pools inside the PX class:** PX-proof transactions (cap about 56 MiB) and
   deploys (cap about 8 MiB, 8 blocks of the deploy budget). **Eviction only within a
   sub-pool.** A deploy never evicts a PX transaction.
2. **PX-proof transactions are ordered first seen (seq)**, not by rate. Their fee is
   identical by consensus, so rate order is an artifact that starves contract calls
   (R6 MP-5).
   - When the sub-pool is full, refuse the newest.
   - Natural expiry: the anchor window (`ROOT_WINDOW = 100`) already drops old PX
     transactions at revalidation.
   - Optionally, ZIP-401-style random eviction weighted by size.
3. **Deploys get a policy expiry** (for example 720 blocks), since they have no anchor.
4. **Template:** PX-proof transactions first, then deploys within 1 MiB (this already
   holds).

**Tests:**
- `deploys_never_evict_px_transactions`
- `px_subpool_is_first_seen_ordered`
- `px_lane_congestion_simulation` (I4's proposed name): a deterministic pure-Rust
  simulation with synthetic transactions (no proofs; the `mempool.rs` test fixtures
  suffice). It measures honest PX inclusion latency under a 64 MiB deploy flood, before
  and after the change. Acceptance: honest PX inclusion within ≤ 3 blocks of arrival
  while the flood lasts.

**Invariants:**
- the pool has no consensus effect;
- the only use of pool contents in block validation is the proof cache keyed by tx id.

### 3.3 Deploys consume the node-wide PX *proof* relay token; refused variants are not cached (POLICY)

**The problem.**
- `admit_tx` charges `px_global` (2/s, burst 10) for any `is_px` transaction, **deploys
  included** (`net.rs:2155-2157, 2300-2311`), although a deploy carries no proof.
- `MempoolError::FeeTooLowForFullPool` after verification is ignored silently
  (`net.rs:2439`, `(_, Err(_), _) => {}`): no ctx-reject, no penalty.

**Scenario.**
1. Once the PX class is full of higher-rate entries (for example, §3.2), the attacker
   re-sends deploy variants of **one** unpooled key image with fresh salts (new ids, no
   pooled conflict).
2. Each variant passes the cheap checks and takes a global PX token.
3. Each variant is verified (1 CLSAG plus an ELF load) and then refused.
4. At 2/s across a few peers, honest PX relay starves.

**Cost:** close to zero.

**Confidence:** medium. [src] only; P2P ownership.

**Severity:** Low–Medium.

**Fix (owners 30/12):**
- give deploys their own bucket, or charge them only the `inputs` bucket;
- add pool-refusals to the per-tip `ctx_rejects` (a ZIP-401 "recently evicted"
  analogue);
- optionally, a pre-verification capacity check (`Mempool::would_admit(rate, size)`)
  before the token.

### 3.4 v1 fee "≥ minimum": fingerprint channel (CONSENSUS option)

**The problem.** T8 accepts any fee ≥ min. The official wallet pays exactly
`standard_fee`, so there is no fingerprint today. But any other wallet, or any
"priority" overpayment, is a unique fingerprint, and rate ordering rewards it (R6 §3.3).

**Evidence from Monero:**
- Rucknium's measurements found clusters of non-standard fees that single out wallet
  implementations;
- monero#5711 proposes consensus fee discretization (powers of two);
- research-lab#70 shows that high-precision dynamic fees leak the creation-to-mining
  time.

**Options:**
1. Keep "≥" (status quo, D19 defers tiers).
2. **T8-exact:** `fee == standard_fee(n,k)`. This aligns v1 with PX and deploys: every
   fee on chain becomes a deterministic function of public shape. The same cost as today
   for the official wallet.
3. R-FEE1 tiers `{1, 4, 20} × standard`: ≤ 1.6 bits, with a priority escape.

**Trade-offs:**
- (2) removes the priority escape. On the testnet, v1 capacity (about 381 tx/block) far
  exceeds the load, and today's escape is itself a fingerprint.
- (2) → (3) later is a relaxation, done by activation (the schedule exists).

**Severity:** Low (testnet). **Accepted limitation** unless the owner includes (2).

**Recommendation:**
- put (2) to the owner as a v3 option (S). A reset is free now.
- otherwise, document that non-standard fees fingerprint.

### 3.5 Fee parameters are not part of the epoch rule set (ARCHITECTURE)

**The problem.**
- `TxRules::at_height` hard-codes `fee_per_weight: FEE_PER_WEIGHT` and
  `max_block_weight: MAX_BLOCK_WEIGHT` (`params.rs:127-135`).
- `px::deploy_fee` uses the global `FEE_PER_WEIGHT`, not `rules.fee_per_weight`
  (`px.rs:477`), while `check_structure` uses `rules`.
- `PX_STANDARD_FEE`, `MAX_PX_BLOCK_BYTES` and `MAX_DEPLOY_BLOCK_BYTES` are globals, used
  directly by validation and the mempool.

**Consequences.**
- Any future fee reform (I4 §6.3, R-FEE1, a price-scaled fee) needs these as per-epoch
  values.
- Today's code would silently keep deploy and PX fees fixed across an activation that
  changed `fee_per_weight`: a latent inconsistency.

**Classification:** no consensus change now (one epoch). Informational/Low.

**Fix (P2):**
- route every fee and budget constant through `TxRules` (from the `Epoch` or a per-epoch
  economics table);
- make `deploy_fee` take `&TxRules`;
- add a test that a two-epoch schedule with different fee values validates each height
  under its own values.

### 3.6 Atomic-unit fees against price, and the security budget (ACCEPTED for testnet)

- **Fixed fees:**
  - Fees are fixed atomic amounts (20/weight, 0.089 BLK per PX, 50/B deploy
    payload).
  - A 100× price move makes spam free or use prohibitive (R6 §3.2, I4-3).
  - Monero ties its minimum fee to the base reward and the median block weight
    (`DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT = 3000`,
    `CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 = 300000`, 2021-scaling fee levels,
    fee rounding), activated in v15 (PR #7819).
- **Security budget** [math, R6 §3.2]:
  - the maximum fees per full block at standard fees are about 0.39 BLK, which is
    ≤ 2 % of today's reward and ≤ about 39–64 % of the tail;
  - the tail avoids the fee-only instability of Carlsten et al. (CCS 2016).
- **Self-stuffing:**
  - B3 pays every fee to the miner, so **no fee deters a miner from stuffing its own
    blocks**: the bound must be structural (§3.1).
  - EIP-1559's burn exists for this reason ("the miner … does not receive the base
    fee").
  - A partial burn plus an anchor-indexed uniform base fee (I4 §6.3, P3-8) is the right
    mainnet direction.
  - Its privacy constraint: the fee must be a function of the **anchor**, never of
    creation time (research-lab#70).
- **Recommendation:** accept for the testnet; P3 mainnet design; §3.5 is the enabling
  refactor.

### 3.7 Fee ordering among PX transactions (covered by §3.2)

Uniform fee plus rate ordering means the smallest PX transaction goes first
(transfers 4.09 against vault calls 3.31). Under congestion this systematically delays
contract calls, which are a public class anyway (program ids are public), so there is no
new privacy leak. §3.2(2) fixes it.

---

## 4. New findings

| ID | Severity | Status | Location | Scenario | Confidence |
|---|---|---|---|---|---|
| **FE-1** (refines R12-2) | **Medium** (testnet) / High (mainnet) | Partially implemented (the deploy cap bounds it; not closed) | `tx/src/types.rs:452-458`; `validate.rs:968-996` | 23 × 64-in deploys (1 MiB) + 3 × 64-in PX + a full v1 lane gives about 2,550 CLSAGs, about 5–10 s [est] against the v1 bound of about 886 (≈ 2.9×). The review's 25–50 s predates the enforced cap and is now **overstated** | high on the counts [math], medium on seconds |
| **FE-2** | **Medium** | Not implemented (P1-18 open) | `chain/src/mempool.rs:97-102, 296-325` | Deploys (≥ 23.6/B) always outrank PX (≤ 4.1/B) in the **shared** 64 MiB class. A deploy flood evicts pooled PX transactions and locks PX out of admission for about 0.25–0.52 BLK/block (0 net for a miner in its own blocks). The block deploy cap does not help at the pool level | high [src + math]; untested |
| **FE-3** | Low–Medium | Not implemented | `p2p/src/net.rs:2155-2157, 2300-2311, 2439` | Deploys consume the node-wide PX *proof* token (2/s); `FeeTooLowForFullPool` is not cached, so salt variants of one key image drain PX relay at about zero cost once the class is full | medium [src] |
| **FE-4** | Low | Accepted limitation (D19 deferred) | `tx/src/validate.rs:353-361` | T8 "≥" allows any overpayment, a per-wallet fingerprint (Monero precedent). The official wallet is exact | high |
| **FE-5** | Low / Informational | Not implemented | `tx/src/params.rs:127-135`; `tx/src/px.rs:477` | Fee and budget constants are not per-epoch; `deploy_fee` ignores `rules.fee_per_weight`. A future fee activation would be silently inconsistent | high [src] |
| **FE-6** | Informational | — | `chain/src/mempool.rs:411-413` | `select` sorts v1 (fee/weight) and PX (fee/byte) entries in one order with incomparable units. Harmless while the budgets are disjoint; it must be fixed together with FE-1 | high |
| **FE-7** | Informational | Complete and verified (by the fingerprint pin) | `params.rs:17, 41` | `PX_STANDARD_FEE` derives from `MAX_PROOF_BYTES`; re-sizing the proof cap changes the fee. The pinned fingerprint catches it; say so in docs/px.md | high |
| **FE-8** | Informational (docs) | Partially implemented | `docs/blocks.md` §5 item 5, §7 | §5 omits the 1 MiB deploy sub-budget; §7 does not state that deploys outrank and evict PX in the pool | high |
| **FE-9** | Accepted limitation | Accepted (testnet) | B3, `emission.rs` | Fees recycle to miners: fees cannot deter self-stuffing. The bounds must be structural. Burn is P3 | high |

---

## 5. Implementation plan for phase 2

| # | Work item | Files (ownership) | Consensus? | Identity impact | Tests | Bench | Docs | Size | Priority |
|---|---|---|---|---|---|---|---|---|---|
| 1 | **R12-2 (a′):** `Transaction::weight()` = `max_weight(n,k)` for PX/deploy with n > 0 (else 0). A `const`/test assertion that the PX fee is ≥ the v1 fee of the largest PX v1 part. Fingerprint weight samples | `tx/src/types.rs` (weight), `tx/src/builder.rs` (`max_weight` → `const fn` if feasible), `tx/src/params.rs` (assert), `node/src/fingerprint.rs` + `node/tests/deploy_configs.rs` (re-pin) | **CONSENSUS** | yes: v3 genesis (not launched; single epoch, no activation height) | demo test first (a deploy over a small `max_block_weight` is accepted before, rejected after); golden weights (5 shapes); block at the limit ±1; the fee/weight invariant for deploys; adversarial 23-deploy block; full suite | worst-block timing before/after (with 10/45) | transactions.md B6 and §8.4, blocks.md §5, px.md §11.5, full-review register | S | **P0** |
| 2 | **Template for item 1:** PX-proof transactions first (their weight counted), then all others by in-class rate; v1 weight shared; no cross-class rate comparison | `chain/src/mempool.rs` (`select`) (owner 12; coordinate with 09) | policy | none | PX with v1 inputs selected under v1 congestion; randomized budget test extended to weight from PX/deploy | — | blocks.md §7 | S | **P0** (with item 1) |
| 3 | **PX-lane sub-pools:** deploy sub-pool cap (about 8 MiB), eviction only within sub-pools, PX ordered first seen, deploy expiry (about 720 blocks) | `chain/src/mempool.rs` (owner 12) | policy | none | `deploys_never_evict_px_transactions`, `px_subpool_is_first_seen_ordered`, `px_lane_congestion_simulation`, deploy expiry | the simulation reports latency | blocks.md §7, px.md §11.5 (MP-5/I4-2 status) | S–M | **P1** |
| 4 | **Relay:** deploys off the global PX proof token (own bucket, or inputs only); cache pool refusals per tip | `p2p/src/net.rs`, `p2p/src/limits.rs` (owner 30) | policy | none | salt-variant flood test (p2p/tests/network.rs) shows PX relay unaffected | — | p2p.md §10 | S | P1 |
| 5 | **Fee parameters per epoch:** route `PX_STANDARD_FEE`, `DEPLOY_FEE_PER_BYTE`, `MAX_PX_BLOCK_BYTES`, `MAX_DEPLOY_BLOCK_BYTES` and fee-per-weight through `TxRules`; `deploy_fee(&TxRules, …)` | `tx/src/params.rs`, `tx/src/px.rs`, `tx/src/px_builder.rs`, `tx/src/validate.rs`, `chain/src/mempool.rs`, `wallet/src/wallet.rs` (call sites) | none now (same values) | none (fingerprint unchanged if values are equal) | two-epoch schedule with different fees; each height validated under its own | — | consensus.md §11, v3-upgrade-mechanism.md | M | P2 |
| 6 | **Owner decision: T8-exact v1 fee** (or keep "≥" and document) | `tx/src/validate.rs` (`check_structure`), tests (owner 11) | **CONSENSUS** if chosen | v3 | `fee = standard ± 1` rejected; wallet e2e unchanged | — | transactions.md T8, §11.3 | S | P2 (decision before freeze) |
| 7 | **Docs:** FE-7, FE-8; R12-2 figure corrected (5–10 s, not 25–50 s, until item 1); I4-2 status | `docs/blocks.md`, `docs/px.md`, the full-review register (owner 47) | none | none | — | — | as listed | S | P1 |
| 8 | **Mainnet fee reform** (anchor-indexed uniform base fee plus partial burn, optional tiers) | design only | CONSENSUS (future activation) | new epoch | simulation | — | new design doc | M | P3 |

Suggested ordering: 1 + 2 together (one reviewed consensus diff), then 3, 4, 7; 5 before any
fee activation; 6 at the owner's discretion before the freeze.

---

## 6. Dependencies and conflicts

- **10 block-validation-pipeline:**
  - shares the R12-2 decision data;
  - measures `t_clsag` and the worst block;
  - owns parallel CLSAG verification, which is complementary: it reduces seconds, not
    the count;
  - agree who edits `validate.rs` (item 1 needs no `validate.rs` change if
    `Transaction::weight` carries it).
- **11 tx-validation:** T8 and B6 rule text; item 6 lives in `check_structure`.
- **12 mempool-architecture:** owns `chain/src/mempool.rs` (items 2, 3). Its expiry and
  bounded revalidation must include the deploy expiry.
- **13 mempool-frontrunning-c4:** conflict keys are shared; no fee interaction, except
  that C4 griefing costs one standard fee (R6).
- **09 mining-templates:** the template order (item 2).
- **30 p2p-transport / 33 dandelion:** item 4 (relay tokens).
- **01 consensus-core / 40 testnet-genesis:** the fingerprint and golden vectors
  (item 1); the v3 freeze.
- **45 benchmarks:** the worst-block benchmark.
- **47 docs:** item 7.
- **28 private-contracts-px:** deploy sizes and payload pricing.
- **38 wallet-privacy:** fee uniformity (item 6).

---

## 7. Open questions for the coordinator

1. Confirm **(a′)** (shape-bound weight, px_bytes unchanged) against SX1's (a) (byte
   split) or (b) (an input-count cap). My recommendation is (a′), for its simplicity and
   the exact fee/weight invariant.
2. Should item 1 land before the next labnet run, so that the worst-block benchmark
   measures the final rule?
3. Owner decision on T8-exact (item 6) versus keeping "≥" until tiers.
4. The sub-pool caps in item 3 (56/8 MiB) are proposals. Does 12 prefer ZIP-401 random
   eviction for the PX sub-pool?
5. Should the fingerprint gain rule-sample entries generally (weights, fees of fixed
   shapes), since it is blind to rule-code changes?

---

## 8. Sources

- ZIP 317, Proportional Transfer Fee Mechanism: https://zips.z.cash/zip-0317
- ZIP 401, Addressing Mempool Denial-of-Service: https://zips.z.cash/zip-0401
- BIP 141, Segregated Witness (block weight; sigop cost ≤ 80,000):
  https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
- Monero `cryptonote_config.h` (fee constants, full reward zone, fee rounding):
  https://github.com/monero-project/monero/blob/master/src/cryptonote_config.h
- Monero PR #7819, "Fee changes from ArticMine" (2021 scaling, v15):
  https://github.com/monero-project/monero/pull/7819
- Monero PR #1079, wallet fee priority multipliers:
  https://github.com/monero-project/monero/pull/1079
- Monero issue #5711, "High-precision fees leak information":
  https://github.com/monero-project/monero/issues/5711
- Monero research-lab #70, "Reduce minimum fee variability" (fee timing leak):
  https://github.com/monero-project/research-lab/issues/70
- Rucknium, Monero non-standard fees:
  https://github.com/Rucknium/misc-research/tree/main/Monero-Nonstandard-Fees
- JollyMort, Monero dynamic block size and dynamic minimum fee:
  https://github.com/JollyMort/monero-research/blob/master/Monero%20Dynamic%20Block%20Size%20and%20Dynamic%20Minimum%20Fee/Monero%20Dynamic%20Block%20Size%20and%20Dynamic%20Minimum%20Fee%20-%20DRAFT.md
- EIP-1559 (base fee, burn rationale): https://eips.ethereum.org/EIPS/eip-1559
- T. Roughgarden, "Transaction Fee Mechanism Design for the Ethereum Blockchain: An
  Economic Analysis of EIP-1559", arXiv:2012.00854: https://arxiv.org/abs/2012.00854
- M. Carlsten, H. Kalodner, S. M. Weinberg, A. Narayanan, "On the Instability of Bitcoin
  Without the Block Reward", ACM CCS 2016:
  https://www.cs.princeton.edu/~arvindn/publications/mining_CCS.pdf
