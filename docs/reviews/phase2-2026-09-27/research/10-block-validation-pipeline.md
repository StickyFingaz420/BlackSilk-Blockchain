# 10 block-validation-pipeline: research dossier (phase 2, phase 1)

Internal engineering research, not an audit. No claim here states or implies that BlackSilk is
secure, audited or production-ready. Every timing below is an estimate unless it cites a
measurement, and nothing was built or run for this dossier (brief §4: read-only, no cargo).

## 1. Scope and what I read

- **Commit:** `9e422d8` (`git rev-parse --short HEAD` on `rebuild/core`).
- **Code, read in full:**
  - `tx/src/validate.rs` (1,132 lines): every rule, `validate_block_transactions(_cached)`,
    `revalidate_*`, the activation grace;
  - `chain/src/manager.rs` (1,459 lines): `submit_inner`, `drain_ready`, `sync_state`,
    `invalidate`, `keeps_body`, `replay`, `CachedPow`, the bounded API;
  - `tx/src/params.rs`, `tx/src/types.rs` (`hash`, `weight`, `px_bytes`), the `tx/src/px.rs`
    structure, balance, codec and `contract_id`, `chain/src/block.rs`;
  - `crypto/src/clsag.rs::verify`, `crypto/src/bulletproofs_plus.rs` (`batch_verify`,
    `verify_weighted`, `Msm`);
  - `zk/src/lib.rs::decode_proof`, `px/src/prove.rs::verify`, `consensus/src/schedule.rs`;
  - `chain/src/mempool.rs` (`contains`, `validated_under`, `enter_rules`, `add`, `revalidate`,
    `select`);
  - `p2p/src/net.rs` `block_worker` (lines 1900–1980), `node/src/main.rs` (the open call).
- **Tests read (names and bodies where relevant):**
  - `tx/tests/validation_order.rs`, `adversarial.rs` (`block_rules`), `deploy_rules.rs`
    (`a_block_over_the_deploy_budget_is_invalid`), `upgrade.rs`, `px_consensus.rs`;
  - `chain/tests/manager.rs` (`mempool_contents_never_change_a_blocks_verdict`,
    `mempool_revalidation_cost_per_transaction`, `revalidation_after_an_extension_*`),
    `chain/tests/activation.rs`, `revalidation.rs`, `block_malleability.rs`;
  - the unit tests of `manager.rs` (the bounded submission).
- **Docs and reports:**
  - `docs/reviews/full-review-2026-09-27.md` (all of it, focusing on §3.1, §3.4, §3.12 and the
    register rows R12-2, R12-11, R12-12, R16-8, R6 MP-1/MP-2, R1-C12);
  - `docs/reviews/autonomous-session-2026-09-27.md`;
  - R12 (§1–§3, §14, §18, §19), SX1 (the R12-2 row and §3), SX2 (C10, the R8-1 row, P0-1,
    P0-7), R16 (R16-8);
  - `docs/reviews/v3-upgrade-mechanism.md` §7 (the deploy budget);
  - `docs/blocks.md` §5 and §8;
  - the roster entries 09–14, 34, 35, 41, 45 and 50.

## 2. Current state (with evidence class)

### 2.1 The pipeline as implemented

**Node path** (`p2p/src/net.rs:1925` → `chain/src/manager.rs`):
1. One block worker processes received blocks one at a time [source-read].
2. `submit_inner` checks `tx_root`, then accepts the header (PoW, through `HeaderChain::accept`),
   then applies the low-work body policy. It then **appends the body to `blocks.dat` and fsyncs
   it before any body validation** (`manager.rs:664-690`) [source-read].
3. Validation happens in `sync_state` only when the block is on the path to the most-work
   body-complete target (`manager.rs:922-965`) [source-read].
4. The work is bounded to `SYNC_STEP_BLOCKS = 8` block validations per chain-lock hold
   (`manager.rs:258`) [source-read].

**Order inside `validate_block_transactions_cached`** (`tx/src/validate.rs:906-1131`):

| # | Phase | Lines | Cost class |
|---|---|---|---|
| 1 | B1/B2 and coinbase structure | 915-938 | trivial |
| 2 | Per-kind structure (`check_structure`, `check_px_structure`, `check_deploy_structure`) | 940-961 | cheap (it re-encodes each tx for its size) |
| 3 | B5 `tx_root` (hashes every tx again) | 964-967 | hashing ~9 MB |
| 4 | B6: v1 weight ≤ 600,000; PX bytes ≤ 8 MiB; deploy bytes ≤ 1 MiB | 968-996 | cheap |
| 5 | B3: coinbase = reward + fees | 997-1005 | trivial |
| 6 | T9 balance for all kinds | 1007-1025 | 1 MSM-lite per tx |
| 7 | C2/C4 uniqueness; PX1–PX4; contract-id uniqueness | 1027-1069 | hash-set lookups |
| 8 | **C1 ring resolution interleaved with C3 CLSAG, tx by tx** | 1071-1097 | **2–4 ms per input [est]** |
| 9 | T10: one BP+ batch over all txs (128-bit random weights) | 1099-1119 | ~0.3–1 ms marginal per proof [est] |
| 10 | PX5: `decode_proof` + FRI verify, skipped if `proof_verified(id)` | 1121-1130 | 0.21 s per proof [measured, R12 §1.2] |

### 2.2 What is correct and well designed

- **The verdict is a conjunction of pure predicates over `(txs, ctx, parent state, rules)`.**
  The only non-pure input is the batch RNG, and it can only turn a valid-looking batch with an
  invalid proof into a rejection, with probability ≤ ~2^-128; a valid batch always passes
  [source-read `bulletproofs_plus.rs:530-543`; mathematically established by the weighted
  linear-combination argument]. So the evaluation order and any parallel schedule change only
  *which* error is reported, never *whether* the block is valid. That is the foundation of
  every item in §5.
- **The BP+ batch weights come from an unpredictable source:** `ChaCha20Rng` seeded from the
  OS at `ChainManager::open` (`manager.rs:337`, `node/src/main.rs:100-105`) [source-read].
  Tests use fixed seeds, which is fine for tests.
- **The PX proof cache is sound today.** Three facts make it so:
  - the tx id commits to every byte, including the proof: `Transaction::hash` =
    H(prefix, base, prunable), and the prunable part includes the proof bytes
    (`types.rs:432-448`, `px.rs:281-288`) [source-read];
  - registry entries are content-addressed: `contract_id` hashes the payload (ELFs and
    budgets) together with the first key image (`px.rs:593-607`) [source-read];
  - the cache is gated by the signature domain (`manager.rs:945`), and branch ids are
    pairwise distinct per epoch (`schedule.rs:59-90`, `malformed_tables_are_rejected`)
    [tested], so an epoch change always misses the cache.

  **This matters: Zebra's CVE-2026-34377 (March 2026)** was a verification cache keyed by a
  txid that *excluded* the authorization data, which let a miner split consensus. BlackSilk's
  id is the analogue of a wtxid, so it is not exposed to that class. It must stay that way (§3.6).
- **Contextual rules are never cached.** C1, C2, C4 and PX1–PX4 are re-run for every block,
  including pooled transactions [source-read]. So the Bitcoin CVE-2018-17144 pattern (a
  "redundant" check removed for speed) is absent.
- **The deploy sub-budget `MAX_DEPLOY_BLOCK_BYTES` = 1 MiB is enforced** in B6
  (`validate.rs:983-996`) [tested: `a_block_over_the_deploy_budget_is_invalid`].
- **The bounded drain never stops on a lighter tip**
  [tested: `a_bounded_reorganization_never_stops_on_a_lighter_tip`,
  `bounded_submission_reaches_the_unbounded_result_in_bounded_steps`].
- **The error classification is exhaustive, and stateless errors precede contextual ones in
  the mempool paths** [tested: `every_error_variant_is_classified`,
  `a_stateless_error_never_follows_a_contextual_check`,
  `verdicts_are_unchanged_over_a_corpus_on_two_chain_states`].

### 2.3 What the tests do not prove

- **No test measures or bounds block validation cost.** The only v1 crypto measurement is
  6.8 ms per 1-in/2-out transfer (`mempool_revalidation_cost_per_transaction`). The CLSAG / BP+
  split is [estimated].
- **No test covers a block with many-input PX or deploy transactions,** or a PX transaction
  with an empty or garbage proof inside a block [unknown behaviour cost; the verdict is
  source-read as "invalid"].
- **`mempool_contents_never_change_a_blocks_verdict` tampers with a transfer's fee** (a prefix
  field), not with a pooled PX transaction's **proof bytes**. The PX5-skip path is therefore
  not covered by a tamper test.
- **No test covers parallel or sequential equivalence.** No parallel code exists.

## 3. Problems in scope

### 3.1 The worst-case block validation cost after the deploy budget (R12-2: decision data)

**Problem.** PX and deploy transactions have `weight() = 0` (`types.rs:456`), but each can
carry up to 64 v1 inputs (`MAX_INPUTS`), and every input costs one 16-member CLSAG. Cost is
bounded per byte class, not per verification unit. The deploy budget that landed caps the
deploy share at 1 MiB, but the PX lane still admits weight-0 inputs.

**Recomputed per-block CLSAG bound at `9e422d8`** [math from source constants; seconds est. at
2–4 ms per CLSAG]:
- per v1 input ≈ 674 B: key image 32 + ring ~34 + pseudo-out 32 + CLSAG 576;
- ML-KEM-768 ciphertexts make a PX tx's fixed part ≈ 2.7 KB.

| Block (all transactions valid) | CLSAGs | Time, 1 thread |
|---|---|---|
| v1 only (597,000 weight, 64-input transfers) | ~870 | ~2–3.5 s |
| + deploys (1 MiB, 23 deploys of 64 inputs, ≈ 44.3 KB each) | +~1,470 | |
| + 3 valid PX (≥ 2.18 MB proof each) × 64 inputs | +192 | |
| **Valid-block worst case now** | **≈ 2,530** | **≈ 5–10 s, + 3 × 0.21 s PX** |
| Same, before the deploy budget (R12-2's S6) | ≈ 12,100 | ≈ 25–50 s |

So the deploy budget cut the valid-block worst case by about 4.8×. It is still about 2.9× the
v1 bound, and so **R12-2 is only partly mitigated**. For the invalid-block case the deploy
budget changes nothing: see §3.2 / F10-2.

**Consequences.**
- **Liveness:** the one block worker and the chain lock are held for up to 8 such blocks per
  step (§3.4).
- **Propagation:** the stale-rate advantage for the producer grows.
- **Sync:** IBD and replay slow down.
- **Classification:** consensus-critical (the fix is a validity rule). A liveness problem, not
  privacy.

**Prior art.**
- Bitcoin bounds verification per block by a separate counter, not by bytes:
  `MAX_BLOCK_SIGOPS_COST = 80,000` (BIP 141).
- BIP 54 (Consensus Cleanup, 2025–26) adds a per-transaction limit of 2,500 legacy sigops.
  The measured motivation: a crafted block took 120 s on a laptop, and 10 s with the limit
  ("reduces the worst case block validation time by a factor of 40"). The threshold is "the
  tightest value that did not make any non-pathological standard transaction invalid".
- Monero has no sigops counter. Its ring signatures sit inside the weighted transaction bytes,
  and its weight adds a Bulletproof clawback, so verification cost is always paid in weight.
- Zcash's ZIP-317 prices by "logical actions" (policy, not consensus), motivated by the
  bloat/DoS of many-action shielded transactions.

**Options.**

| | Rule | Worst case | Economics | Complexity |
|---|---|---|---|---|
| **(a) (SX1's choice)** | The v1 part of PX and deploy transactions counts toward `MAX_BLOCK_WEIGHT` | ≤ ~890 CLSAGs + 3 PX ≈ 3–4 s (1 thread), ≈ 0.5–1 s (8 threads) [est] | v1 bytes pay v1 space wherever they are | One dimension more in the template (v1 weight + PX bytes) |
| **(b)** | A `MAX_BLOCK_CLSAG` counter (e.g. 1,024) over all kinds | chosen directly | Fee unchanged; a new resource dimension | Three-dimensional template |
| **(c)** | Keep the status quo, document ~2.5k (valid) / ~11.7k (invalid) | 5–10 s / 25–50 s | none | none |

**Recommendation: (a), in its simplest form.**
- **Rule:** `weight(Px | Deploy) = v1_weight(v1 part)`, with the same clawback formula as
  `Transfer::weight`, while `px_bytes` stays the full encoded length.
- **Double counting.** The v1 bytes of a PX tx then count in both budgets. It costs
  ≤ 43 KB of PX lane per 64-input PX tx, and ~1.4 KB for a normal 1–2 input one. That buys a
  one-line spec with no "PX-specific bytes" definition and no change to `MAX_BLOCK_BYTES`.
- **B6 needs no change:** it already sums `Transaction::weight`. The change sits in
  `types.rs::weight` plus the template.
- **An invariant test** asserts the implied bound: `max inputs per block ≤ 600,000 /
  min_input_bytes` (≈ 890). A future constant change that silently lifts it then fails CI.

**Trade-offs and what could go wrong.**
- **The template becomes a two-budget knapsack.** A PX tx must fit both budgets. The current
  greedy `select` takes PX entries by fee per PX byte and never checks weight
  (`mempool.rs:427-436`). Without a fix, a node would build invalid templates. That is a
  miner-liveness bug, not a safety one, but it must be tested.
- **The PX fee stays exactly `PX_STANDARD_FEE`** (8.9 M atomic). It already exceeds the v1
  fee of 64 inputs (≈ 0.87 M, SX1), so P-7 fee uniformity is untouched. A per-shape v1
  component must **not** be added to the PX fee: it would fingerprint the input count
  (privacy).
- **The deploy fee already pays the v1 rate for its shape** (v3-upgrade-mechanism §7.2), so
  (a) changes deploy capacity, not deploy pricing.
- **Identity:** a consensus change. It rides the v3 reset with no extra identity cost, and must
  land before the protocol freeze and the golden-vector freeze.

**Tests that prove the fix.**
- **Unit:** `weight(Px)` against a hand-computed weight for shapes (0, 1, 2, 64 inputs; with
  and without hidden outputs).
- **Block rule, both sides of the boundary:**
  - a block at exactly 600,000 weight, mixing transfers and PX v1 parts, is valid;
  - one more input makes it invalid;
  - the S6-style deploy block is now rejected at B6 before any CLSAG, which a counting
    `ChainView` or a CLSAG-call counter must prove.
- **Template property test:** random pools; every template validates, and respects both
  budgets and the deploy sub-budget.
- **Golden:** the new weight vectors are added to `chain/tests/golden.rs` / the fingerprint.

**Invariants that must never change.**
- B6 runs before any cryptography.
- The PX fee is uniform.
- Every CLSAG in a block is paid for in some bounded resource.

### 3.2 Cost ordering: late detection of costless faults (new, F10-2)

**Problem.** A PX tx's proof is decoded only in PX5, the last phase (`validate.rs:1121-1130`,
via `check_px_proof`). The codec accepts a zero-length proof (`px.rs:348`,
`read_bytes(.., 0..=MAX_PROOF_BYTES)`), and `check_px_structure` does not look at the proof
(`px.rs:644-729`).

**Attack.** A miner builds a block with valid PoW whose PX lane holds ~183 PX transactions.
Each has:
- 64 valid inputs of the attacker's own, so the CLSAGs verify;
- zero outputs, which is allowed when inputs > 0;
- the standard fee, balanced (T9 passes; `bridge_out` or input value);
- an **empty proof**.

Each tx is ≈ 45.8 KB, and 8 MiB / 45.8 KB ≈ 183.

**What each node does.** B6 passes: weight 0, px_bytes ≤ 8 MiB, no deploys. The node then
verifies ≈ 11,700 CLSAGs (≈ 25–50 s [est]) before PX5 rejects the first empty proof.

**What it costs the attacker.**
- One block solution at the tip difficulty (a forfeited reward) per stall.
- ~11.7k owned outputs (≈ 1 BLK of fees to create, once).
- ~17 BLK of value or pool, **never spent**: the block is invalid, so the key images stay
  unspent and the same UTXOs serve every attack block.
- Each node bans the sender only *after* the work, and the attacker can deliver to every node
  directly.

**The mempool paths are not affected.** Relay admission runs cheap checks, budgets per input
and the proof last, but one tx has at most 64 inputs.

**Classification.** Liveness / DoS, not consensus-critical in itself. Moving a check earlier
changes the reported error, not the verdict (§2.2).

**Fix (consensus-neutral).**
1. Decode every PX proof in the stateless phase 2 (a few ms per 2 MB: postcard decode,
   re-encode and canonical check, `zk/src/lib.rs:266-294`).
2. Add a statement-shape precheck there (`statement(...)` shape against the proof's degree
   bits), where it is cheap and needs no state.
3. Keep the decoded `Proof` for PX5 so it is not decoded twice.

With (a) from §3.1 as well, the tiny-proof block also fails at B6.

**Residual after the fix.** To survive the early checks, each PX tx needs a correctly shaped
~2.18 MB proof, which leaves ≤ 3 per block. The worst invalid block is then ≈ the valid worst
case of §3.1, plus up to 3 garbage-but-shaped proofs at ≤ ~0.45 s each (ZK-F4, unmeasured).

**Also move:**
- ring resolution for *all* transactions into a pass before the first CLSAG (cheap lookups);
- the BP+ batch before the CLSAGs. Its marginal cost per proof is below one CLSAG input, it is
  stateless, and a bad range proof is then found before the most expensive v1 work.

Prior art: Bitcoin runs `CheckBlock` (context-free) and then `ContextualCheckBlock` before
`ConnectBlock`'s script checks. Monero `ver_non_input_consensus` runs all non-input and
semantic checks (batched BP) before `ver_input_proofs_rings`.

**Tests.**
- **Adversarial:**
  - a block with N empty-proof PX transactions of 64 inputs is rejected with **zero** CLSAG
    verifications, shown by an instrumented `ChainView` / call counter (a
    `#[cfg(test)]` counter in `check_ring_signatures`);
  - the same with a truncated proof, and with a proof of the wrong shape.
- **Differential:** for a corpus of invalid blocks (every rule broken once, and pairs of rules
  broken), the old and new orders give the same `is_err()`. The expected error variants are
  recorded in a table test.

**Invariant.** The block verdict is independent of the check order.

### 3.3 Deterministic parallel verification (R12-11)

**Problem.** Validation is single-threaded while it holds the chain lock and the only block
worker.

**Design** (pure safe Rust, no new dependency):
1. **Sequential preparation (phase A)**, under the lock as today:
   - phases 1–7;
   - `decode_proof` for every PX tx;
   - ring resolution for every input, collecting `[RingMember; 16]`;
   - registry lookups for every PX function (`Arc<Program>`, `Budget`);
   - draw the BP+ batch weights from `self.rng`, in a fixed order.
2. **Jobs (phase B).** The job list is ordered by (tx index, sub-index):
   - `Clsag(tx, input)`;
   - `BppChunk(k)`: the batch split into ≤ T chunks, each with its pre-drawn weights;
   - `Px(tx)`, unless the cache vouches for it.

   Every job is a pure function of owned or `Sync` data (`MemoryChain`, `Program` and the points
   are plain data) [source-read].
3. **Execution.** `std::thread::scope`, with T workers pulling from an `AtomicUsize`: the same
   pattern as `CachedPow::compute_parallel` (`manager.rs:93-114`). The first failure sets an
   atomic "lowest failing job index". Workers skip jobs above it but still finish jobs below
   it, so **the reported error is the lowest-index failure and is deterministic**. Bitcoin's
   `CCheckQueue` stops at the first error but reports an arbitrary one ("one of the other
   results"). BlackSilk wants stable logs and stable test expectations.
4. **BP+ chunking keeps batch soundness.** Each chunk has independent 128-bit weights. The
   probability that an invalid proof passes is ≤ ~2^-128 per chunk, so ≤ T·2^-128 by the union
   bound [mathematically established]. Zebra verifies in batches and falls back to
   per-item verification to name the failing item. BlackSilk can do the same: on a chunk
   failure, verify each of its proofs singly to report the lowest failing tx.
5. **Thread budget.** `min(available_parallelism − 1, --verify-threads)`, with 1 as a
   supported value. Plonky3's own rayon use inside PX verification is independent. Scoped OS
   threads do not touch the rayon global pool, which avoids the p3 lock issue documented in
   `Cargo.toml:57-60`.

**Gain [est]:** CLSAG work is embarrassingly parallel, so ≈ T×. Monero's
`verRctNonSemanticsSimple` already verifies each input's CLSAG on its threadpool.

**Risks.**
- Nondeterministic error selection if the lowest-index rule is implemented wrongly.
- Oversubscription at the tip while the P2P runtime needs CPU: keep one core free.
- Memory: ring copies of 890 × 16 × 2 points ≈ 1 MB, negligible.

**Tests.**
- A differential property test (proptest): random valid blocks, and blocks with 1–3 random
  faults at random positions. `parallel(T)` for T ∈ {1, 2, 3, 8} equals sequential in both
  verdict and error.
- A repeat-run determinism test: the same block 50× gives the same error.
- The existing suites (`block_rules`, `px_consensus`, `manager`, `fork_choice`) must pass
  unchanged in verdict.

**Invariant.** The verdict equals the AND of the predicates, and the error is the minimum
failing job.

### 3.4 The per-lock-hold budget counts blocks, not cost (F10-4)

`SYNC_STEP_BLOCKS = 8` bounds blocks, not work. With the §3.1 figures, one hold can be
8 × (5–10 s) today, or 8 × (25–50 s) for the invalid-block variant.

**Fix:** a cost-weighted budget, for example 1 unit per CLSAG input, 50 per uncached PX proof
and 0.2 per BP+ output, with a per-step budget of about 1–2 s of work. The unit table is
computed from phase A before phase B runs.

This overlaps workstream 34 (actor, verification outside the lock), which is the structural
answer. Until then the cost budget is a cheap interim step. Policy only.

### 3.5 Invalid bodies are persisted and re-validated on every restart (F10-3)

**Problem.** `submit_inner` appends and fsyncs the body before validation (`manager.rs:664-690`,
by design: "fsync before apply"). An invalid body stays in `blocks.dat`. `replay_one` then
re-validates it at every start (`Err(SubmitError::Body(_)) => Ok(Replayed::Done)`,
`manager.rs:453-456`).

**Consequence.** Each attack block from §3.2 costs up to 9.45 MB of disk forever, and
25–50 s (today) of work at every restart.

**Options:**
1. Write a small "invalid: id, rule" tombstone record after the verdict. Replay then marks the
   block invalid without validating it. This is the same trust model as the already accepted
   stored PoW hashes: data the node wrote itself.
2. Validate before persisting. This conflicts with the crash-consistency design and is not
   recommended.
3. Compaction that drops invalid bodies (with workstream 35's storage roadmap).

**Recommendation:** option 1 as policy, owned by 35. My dossier only supplies the scenario.

### 3.6 A verified-proof cache that stays correct under upgrades (R16-8, R12-12, R6 MP-2)

**Today.** `&|id| same_rules && mempool.contains(id)` (`manager.rs:945-952`) is sound (§2.2),
but three things are wrong with it:
- it caches only PX5;
- it depends on the mempool's eviction;
- it keys implicitly on "domain equal".

**Design: a node-owned `VerifiedCache` (bounded, in RAM).** It holds *only verdicts that are
pure functions of their key*:

| Entry | Key (Blake2b, domain-tagged, per-process random salt) | Why each component |
|---|---|---|
| PX5 | `tx_id ‖ network_id ‖ branch_id ‖ verifier_id ‖ H(for each function: contract, program_id, program hash, budget)` | `tx_id` covers the proof bytes (a wtxid analogue: **never** a prefix-only id, per Zebra CVE-2026-34377). `verifier_id` is explicit even though branch ids are distinct today. The registry digest makes the key survive a future mutable registry (R16-8 b). |
| T10 (BP+) | `tx_id` | Stateless and domain-independent: BP+ binds only commitments and proof bytes. |
| C3 (CLSAGs of one tx) | `tx_id ‖ network_id ‖ branch_id ‖ H(resolved ring members of every input, in order)` | Global indices resolve differently across branches. This is exactly Monero's `make_input_verification_id` (tx hash + serialized mix ring): "if the input verification ID for the (transaction, mixring) pair match, the result … will also match". |

**Rules.**
- **Writers:** entries are written only after this node's own successful verification (mempool
  admission, or block validation), never from peer data.
- **Readers:** only the three pure checks read it. C1 existence and age, C2, C4 and PX1–PX4
  are always re-run (the CVE-2018-17144 lesson).
- **Bounds:** a fixed capacity, with FIFO or clock eviction, of e.g. 64k v1 entries and 256
  PX entries (~32 B keys). A miss only costs time.
- **Salt:** the per-process salt stops an adversary from pre-computing hash-table collisions
  (Bitcoin's script-execution cache keys SHA256(nonce ‖ wtxid ‖ flags)).
- **Gains [est]:**
  - at the tip, blocks made of pooled transactions cost ring resolution plus lookups instead of
    ~1.3–2.6 s for a full v1 block;
  - post-reorg mempool revalidation (R6 MP-3, 136–218 s) drops to C1/C2/C4 plus cache hits
    for every tx whose rings resolve identically.
- **Classification:** consensus none, identity none. It must be done **before any second
  verifier or mutable registry** (R16-8), and it is a prerequisite for 34's off-lock
  verification.

**Tests.**
- **PX tamper (CVE-2026-34377 class):** a pooled PX tx; a block carries the same prefix and
  base with different proof bytes. It gets a new id, so it is verified and rejected. Nodes with
  and without the pool agree.
- **Ring change:** a reorg changes one ring member's resolution (as in
  `replacing_coinbase_only_blocks_changes_a_ring_and_needs_full_validation`). The C3 cache
  misses, and the verdict equals a fresh node's.
- **Activation:** across a two-epoch schedule, no hit crosses the boundary.
- **Eviction:** under a full cache every verdict is unchanged. A property test runs random
  sequences of admit, block, reorg and evict, and compares against a cache-less oracle.

### 3.7 Minor inefficiencies (Info)

- **Repeated hashing:**
  - `compute_tx_root` runs twice in `submit_inner` (`manager.rs:639,647`);
  - `Transaction::hash` runs again in B5 (`validate.rs:964`) and again per PX tx for the cache
    lookup (`:1123`).
- **Repeated encoding:** `px_bytes` and `encoded_len` re-encode 2 MB transactions two or three
  times (`types.rs:461-466`, `validate.rs:976,986`, `px.rs:719`).

That is roughly 4–5 × 9 MB of Blake2b and encoding per full block: tens of ms [est]. The fix
is to compute ids and lengths once in phase A (as part of the §3.3 work). R6 TX-6 already
records the encoding part.

**CLSAG micro-optimizations (hand to workstream 15 / 45; not consensus):**
- `key_image_base(member)` (a hash-to-point) is recomputed per member per input. Decoys repeat
  heavily on a young chain (R3-1), so a per-block memo is cheap.
- The `G` term could use a precomputed-base variable-time MSM.

Measure both before doing anything.

## 4. New findings

| ID | Severity | Status | Location | Scenario | Confidence |
|---|---|---|---|---|---|
| **F10-1** | Medium (testnet) / High (mainnet) | Partially implemented | `tx/src/types.rs:456`; `validate.rs:968-996, 1071-1097` | The deploy budget reduces R12-2 from ~12.1k to ~2.5k CLSAGs per *valid* block (≈ 5–10 s, 1 thread [est]), which is still ~2.9× the v1 bound. The R12-2 decision is still owed. | High on counts [math]; medium on seconds |
| **F10-2** | Medium | Not implemented (the fix) | `validate.rs:1121-1130` (PX5 last); `px.rs:348` (0-byte proof decodes); `px.rs:644-729` (no proof check) | One PoW-valid block with ~183 empty-proof PX txs × 64 owned inputs forces ~11.7k CLSAGs (≈ 25–50 s [est]) before rejection. UTXOs are reusable, since the block is invalid. **Not closed by the deploy budget; closed by R12-2 (a) or by early proof decoding.** | High (source-read, untested) |
| **F10-3** | Low–Medium | Not implemented | `chain/src/manager.rs:664-690, 453-456` | Invalid bodies are fsynced before validation and fully re-validated at every restart. Each F10-2 block costs ≤ 9.45 MB of disk forever and its full validation time at every start. | High |
| **F10-4** | Low (liveness) | Partially implemented | `manager.rs:258, 922-926`; `p2p/src/net.rs:1925-1947` | The lock-hold budget counts blocks (8), not cost: one hold can be 8 × the worst block. The single block worker serializes everything behind it. | High |
| **F10-5** | Low | Not implemented | `validate.rs:1071-1119` | C1 is interleaved with C3, the BP+ batch comes after all CLSAGs, and proof decoding comes last: costless faults are detected after the most expensive work. | High |
| **F10-6** | Low (test gap) | Complete but requires further testing | `chain/tests/manager.rs:960-1012` | The PX5-skip path has no tamper test on proof bytes. A future change of the id to a prefix-only hash would pass every test and reproduce Zebra CVE-2026-34377. | High |
| **F10-7** | Informational | Complete but requires further testing | `consensus/src/schedule.rs:28`; `tx/src/params.rs:76`; `validate.rs:538-572` | `Epoch::verifier_id` is not threaded into validation or into the cache key. It is sound only because branch ids are distinct and there is exactly one verifier; a second verifier must add dispatch and a keyed cache. | High |
| **F10-8** | Informational (performance) | Not implemented | see §3.7 | Hashing and encoding are repeated 4–5× per block. | Medium on magnitude |
| **F10-9** | Informational | Not implemented | `manager.rs:945-952` | R12-12 confirmed: at the tip every pooled v1 tx's CLSAGs and BP+ are verified again. | High |
| **F10-10** | Informational | Not implemented | `validate.rs:906-1131` | R12-11 confirmed: single-threaded validation. | High |

**Challenges to existing reports.**
- **R12 and SX2** give "25–50 s" as the current worst case. For *valid* blocks at `9e422d8`
  that figure is stale (≈ 5–10 s after the deploy budget). For *invalid* blocks it still stands
  (F10-2). The R12-2 decision should be taken on both numbers.
- **The autonomous-session report** says "one block's validation, up to about 3.4 s with 3 PX
  proofs, still holds the lock". That understates the lock hold: up to 8 blocks per hold, each
  up to ≈ 5–10 s valid or 25–50 s invalid.

## 5. Implementation plan for phase 2

Ownership warning: `tx/src/validate.rs` is shared with **11 tx-validation**, and
`chain/src/manager.rs` with **02, 07, 09, 34, 35**. I propose that 10 owns the block-level
functions (`validate_block_transactions*`, the new job module) and 11 owns the single-tx rules.

| # | Item | Files (ownership) | Consensus? | Identity | Tests | Bench | Docs | Size | Pri |
|---|---|---|---|---|---|---|---|---|---|
| 1 | **Early PX proof decoding + shape precheck in block phase 2; the decoded proof is reused in PX5; rings resolved for all inputs before the first CLSAG; BP+ batch before CLSAGs** (F10-2, F10-5) | `tx/src/validate.rs` (block fns), `px/src/prove.rs` (a `verify_decoded` / `precheck_shape` entry), `zk/src/lib.rs` (read-only use) | None (verdict-identical; reported errors change) | none | Adversarial zero-CLSAG test for empty, truncated and wrong-shape proofs; a differential corpus old vs new order (verdict equality); updated error expectations in `block_rules` / `px_consensus` | CLSAG-call counter; timing of an 183×64 invalid block before and after | `docs/transactions.md` §8 order table; `docs/blocks.md` §5 | S | **P0** |
| 2 | **R12-2 option (a)**: `weight(Px/Deploy) = v1 weight of the v1 part` (double-counted in px_bytes); two-budget template; an invariant test "max inputs per block ≤ ~890" (F10-1) | `tx/src/types.rs` (weight), `tx/src/px.rs` (a `v1_weight` helper), `chain/src/mempool.rs::select` (**owner 12**, coordinate), `tx/tests/deploy_rules.rs`, `chain/tests/golden.rs`, fingerprint (**40/01**) | **CONSENSUS** | v3 (rides the reset) | Boundary blocks at 600,000 weight; the S6 deploy block rejected at B6 with zero CLSAGs; a template property test (every template valid); golden weight vectors | Worst valid block before and after (S3, S4, S6) | `docs/transactions.md` §8.4, `docs/blocks.md` §5, px.md §11.5; the owner decision table (SX2 P0-1 b) | S–M | **P0 (owner decision)** |
| 3 | **Worst-case block benchmark harness**: synthetic S3/S4/S6 and F10-2 blocks through `validate_block_transactions` and `submit_block` wall time; the CLSAG / BP+ (1, 10, 381) / ring-resolution split | new `tx/benches/block_validation.rs` (or `#[ignore]` timing tests, as the repository does today); **45** owns the methodology | None | none | — | See §5.1 | `docs/evidence/` numbers | S | **P0** (evidence for the R12-2 decision) |
| 4 | **Deterministic parallel verification** (phase A / phase B, scoped threads, lowest-index error, chunked BP+ with single-proof fallback) (F10-10) | new `tx/src/block_verify.rs`; `tx/src/validate.rs` (call site); `chain/src/manager.rs` (thread count only; **34** coordinates); `node/src/config.rs` `--verify-threads` | None | none | A proptest differential over T ∈ {1, 2, 3, 8} with random fault injection; a 50× determinism repeat; all existing suites | Scaling at 1/2/4/8 threads on S3/S6; replay of a 2k-block regtest chain | `docs/blocks.md` §5 (non-normative note), node flags | M | P1 |
| 5 | **Cost-weighted sync-step budget** (F10-4), interim until 34's actor | `chain/src/manager.rs` (`drain_ready`, `sync_state` budget type), `p2p/src/net.rs` constant use (**30/34**) | None | none | A bounded-step test where 3 heavy blocks give ≥ 3 steps; the existing bounded-submission tests unchanged; the pings-during-sync test | Lock-hold histogram | docs/p2p.md §6 | S | P1 |
| 6 | **`VerifiedCache`** (PX5, BP+, ring-keyed C3), node-owned, bounded, salted; it replaces `mempool.contains` (R16-8, R12-12, R6 MP-2) | new `chain/src/verify_cache.rs`; `chain/src/manager.rs`; `chain/src/mempool.rs` (populate on admit; **12**); `tx/src/validate.rs` (a cache trait parameter) | None | none | PX proof-byte tamper (F10-6); ring-change reorg; activation boundary; eviction property test against a cache-less oracle | Tip block of pooled txs; post-reorg revalidation (R6 MP-3) | `docs/blocks.md` §7, a new §"verification cache invariants" (the key must cover every input of the verdict) | M | P2 (P0 before any second verifier or mutable registry) |
| 7 | **PX proof-byte tamper regression test now**, independent of item 6 (F10-6) | `chain/tests/manager.rs` (append one test) | None | none | As described | — | — | S | **P0** (cheap insurance) |
| 8 | **Invalid-body tombstones** so replay skips re-validation (F10-3) | `chain/src/store.rs`, `manager.rs::replay_one` (**35 owns**) | None (policy; trust in own data) | none | A restart after an invalid block does no body validation (counter), and the verdict is preserved | Restart time with N invalid blocks | `docs/blocks.md` §8 | S–M | P2 |
| 9 | **Compute tx ids and encoded lengths once per block** and pass them to B5, B6, PX5 and the cache (F10-8) | `tx/src/validate.rs`, `chain/src/manager.rs` | None | none | Existing suites | Before/after on a 3-PX block | — | S | P2 |
| 10 | **Thread `verifier_id` into `TxRules`** (or a `VerifierSet`), with PX5 dispatch and a hard error on an unsupported id at open (F10-7) | `tx/src/params.rs`, `tx/src/validate.rs`, `consensus/src/schedule.rs` (read) — **01/46** coordinate | None today (one verifier) | none | Schedule with an unknown verifier → refuses to open; cache key includes it | — | docs/consensus.md §11 | S | P2 |

### 5.1 Measurement plan (R12-2 decision data; for 45 to run)

1. **Micro-benchmarks** (release, one pinned thread, then 8):
   - `clsag::verify` over 16 members;
   - `bpp::verify` at k = 2 and 16;
   - `bpp::batch_verify` at 1, 10, 100 and 381 proofs;
   - `resolve_input_rings` per input;
   - `decode_proof` on a 2.18 MB proof.
2. **Synthetic blocks, built with the `TestNet` fixtures of `tx/tests/common`:**
   - S3: 381 × 1-in/2-out;
   - S5: 13 × 64-in;
   - S6-now: 23 deploys of 64 inputs + 3 real PX + v1 fill;
   - F10-2: 183 × 64-in empty-proof PX.
   
   Report `validate_block_transactions` wall time, CLSAG count, and `submit_block` wall time.
3. **Repeat** after items 1, 2 and 4, and publish the before/after table in `docs/evidence/`.
4. **Machine note:** the shared 16 GB machine is enough (a block is < 10 MB). PX proofs need
   pre-generated fixtures (~45 s each to prove). Reuse the `px_consensus` fixtures.

## 6. Dependencies and conflicts

| Roster # | Workstream | Dependency or conflict |
|---|---|---|
| 11 | tx-validation | Shares `tx/src/validate.rs`; split ownership as above. Also: output-word encoding and `TreeFull` are 11's. |
| 12 | mempool-architecture | `select` must become a two-budget knapsack for item 2. The cache population in item 6. Post-reorg revalidation uses item 6. |
| 14 | fee-economics | The R12-2 decision data, and confirmation that the PX fee stays uniform under (a). |
| 34 | chain-actor-concurrency | Items 4–6 are the "verify outside the lock" building blocks. Phase A (reads a snapshot) and phase B (pure jobs) map directly onto check → verify outside → re-check and commit. Item 5 is interim only. |
| 35 | storage-recovery | Item 8 (tombstones) and the replay cost of invalid blocks. |
| 45 | benchmarks-scalability | Item 3 / §5.1. |
| 01, 40, 47 | consensus-core, testnet-genesis, docs-spec-consistency | Golden vectors and the fingerprint for item 2; the docs order table. |
| 15, 16 | clsag, bulletproofs-plus | CLSAG micro-optimizations; BP+ chunked batch soundness (the weights must stay 128-bit CSPRNG, per A20). |
| 24 | plonky3-verifier-security | ZK-F4 (the adversarial PX verify cost) sets the residual in §3.2. |
| 02 | fork-choice-reorgs | `sync_state` edits (the item-5 budget type) touch the same function. |
| 41 | fuzzing-property-stateful | Hosts the differential and stateful cache property tests. |
| 50 | red-team-integration | F10-2 is a candidate for a red-team reproduction test. |

## 7. Open questions for the coordinator

1. **R12-2 (owner).** Option (a) double-counted (recommended), (a) with a split byte
   definition, (b) a `MAX_BLOCK_CLSAG` counter, or accept (c) with the ~2.5k / ~11.7k figures
   documented? Items 1 and 2 are needed in any case unless (c) is chosen.
2. **May item 1 change which `BlockError` is reported?** Verdicts are unchanged. Some test
   expectations and log lines change.
3. **Ownership split of `tx/src/validate.rs` between 10 and 11:** block-level vs single-tx.
4. **Verification threads by default:** `available_parallelism − 1`, or a conservative 2 for
   the seven-device trial (Windows desktops also run miners)?
5. **Should the benchmark harness be `cargo bench` (a new dev-dependency)** or `#[ignore]`
   timing tests, as the repository does today (`mempool_revalidation_cost_per_transaction`)?
   I recommend the latter: no new dependency.

## 8. Sources

- **Bitcoin Core**
  - CVE-2018-17144 notice (a duplicate-input check removed for performance; DoS and
    inflation): https://bitcoincore.org/en/2018/09/20/notice/
  - `CCheckQueue` (parallel script checks; the result is "one of the other results" on
    failure; workers stop once a result is set):
    https://github.com/bitcoin/bitcoin/blob/master/src/checkqueue.h
  - Script execution cache keyed by SHA256(nonce ‖ wtxid ‖ flags), in `validation.cpp`:
    https://github.com/bitcoin/bitcoin/blob/master/src/validation.cpp
  - Script validation performance tracking issue #32042:
    https://github.com/bitcoin/bitcoin/issues/32042
- **Bitcoin BIPs**
  - BIP 54, Consensus Cleanup (the worst-case validation time, the 2,500 sigops per
    transaction limit and its rationale): https://github.com/bitcoin/bips/blob/master/bip-0054.md
    and https://bip54.org/
  - BIP 141 (`MAX_BLOCK_SIGOPS_COST`): https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
- **Monero**
  - `tx_verification_utils.h` / `.cpp` (`make_input_verification_id`: tx hash + mix ring;
    `ver_input_proofs_rings`; `ver_non_input_consensus` with the batched RingCT semantics):
    https://github.com/monero-project/monero/blob/master/src/cryptonote_core/tx_verification_utils.h
    and https://github.com/monero-project/monero/blob/master/src/cryptonote_core/tx_verification_utils.cpp
  - `rctSigs.cpp` (`verRctNonSemanticsSimple` verifies CLSAGs in parallel on a threadpool):
    https://github.com/monero-project/monero/blob/master/src/ringct/rctSigs.cpp
- **Zcash / Zebra**
  - Zebra CVE-2026-34377 / GHSA-3vmh-33xr-9cqh (a verification cache keyed by a txid
    excluding authorization data → consensus split):
    https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-3vmh-33xr-9cqh
  - Zebra issue #11381 (reuse shielded verification between the mempool and blocks; the key
    is the witnessed id + sighash + pool; height-dependent checks are always re-run):
    https://github.com/ZcashFoundation/zebra/issues/11381
  - Zebra RFC 0002, Parallel Verification: https://zebra.zfnd.org/dev/rfcs/0002-parallel-verification.html
  - "Zebra: Zcash Zero-Knowledge Proofs at Scale" (batch verification with per-item fallback):
    https://zkproof.org/2021/06/03/zebra-zcash-zero-knowledge-proofs-at-scale/
  - ZIP-317, Proportional Transfer Fee Mechanism (logical actions; policy, not consensus):
    https://zips.z.cash/zip-0317
- **Libraries**
  - curve25519-dalek 4.1.3 documentation (backend selection; the AVX2 backend is chosen at
    runtime on x86-64): https://docs.rs/curve25519-dalek/4.1.3/curve25519_dalek/
- **Papers**
  - Bulletproofs+ (ePrint 2020/735) and CLSAG (ePrint 2019/654): for the batch-weight
    argument, as already cited in R2 and R16.
