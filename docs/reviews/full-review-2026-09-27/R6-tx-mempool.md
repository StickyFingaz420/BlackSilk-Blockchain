# R6: transactions, mempool and economics (internal review, 2026-09-27)

**Reviewer:** R6. This is an internal review, not an audit. The repository was only read; nothing was built or run.

**Baseline:** `rebuild/core`. The review started at `f677e55`. During the review HEAD moved to `0b7bc54`, which adds `chain/tests/revalidation.rs`, `tx/tests/revalidate_after_extension.rs` and the zk commit `4b277cd`. There are no source changes in `tx/` or `chain/src/`.

**Scope:**
- `tx/src`: codec, types, validate, builder, px, `px_builder` fees;
- `chain/src/mempool.rs`, `chain/src/emission.rs`, and the template and reorg paths in `chain/src/manager.rs`;
- the fee, weight and budget constants;
- the P2P admission call sites, only where they decide the cost of mempool admission.

**Evidence tags:** [math] mathematically established · [test: name] · [src] source-read · [assumed] · [unknown].

---

## 0. Executive summary

1. **C4 output-key front-running is cheaper and more deterministic than AUDIT.md records.**
   - **How the attack works:** a Dandelion stem relay sees a transaction before anyone else. It can fluff its own transaction T′, which copies a victim output's one-time key, before the victim's transaction T leaves the stem. The mempool rule is first-seen-wins on output keys, so T′ wins in almost every pool. Once T′ is mined, T is invalid forever.
   - **Cost to the attacker:** about 0.00034 BLK (one standard 1-in/2-out fee), and one T′ can copy up to 16 victims' keys.
   - **Cost to a PX victim:** a new 45 s, 3.8 GB proof.
   - **What binding at consensus can and cannot do:** consensus cannot cheaply bind a one-time key to its transaction's inputs, because the key hides the recipient. The wallet layer already binds it: the Janus anchor check is keyed to `ctx`. Keying the consensus uniqueness rule on the pair **(one-time key, commitment)** instead of the key alone removes free griefing:
     - a copy of a hidden-amount output is impossible without the victim's mask;
     - a copy of a clear-amount payout costs the attacker the full payout amount, and the copy is spendable by the real recipient.
   - **Status:** consensus change. It should be decided before the v3 genesis.
2. **The PX byte lane can be censored cheaply by deploys.**
   - The PX fee is fixed (0.0891 BLK), so an honest PX transfer pays about 4.08 atomic units per byte.
   - Deploys pay any fee of at least 2 per byte, so a deploy paying about 4.1 per byte outranks every PX transaction in selection and eviction.
   - Filling the 8 MiB lane then costs about 0.34 BLK per block. PX users cannot outbid, because their fee is fixed by consensus.
3. **Deploys are underpriced permanent RAM state.**
   - A deploy costs 2 atomic units per byte, 10 times less per byte than a v1 transfer.
   - Each registered program is loaded and kept in RAM forever (`MemoryChain::registry`, `tx/src/state.rs:48`).
   - Registry growth is bounded only by the 8 MiB PX lane: at most about 6 GB/day, at about 21.5 BLK per GiB at the minimum fee.
   - A 16-output deploy is about 18 times cheaper than the equivalent 16-output transfer.
4. **Mempool admission does all expensive cryptography while holding the ChainManager mutex.** This includes PX proofs (about 0.21 s each) and up to 64 CLSAGs per transfer. `submit_tx` and `check_tx` are called inside `inner.chain()` (`p2p/src/net.rs:1408`, `1463`, `1537`).
   - A stem transaction's proof is verified twice at the fluffing node.
   - Every PX transaction returned by a reorg is verified again, although the block it came from already verified it.
5. **The v1 fee rule is "at least the minimum", with no priority mechanism.**
   - Wallets pay an exact per-shape standard fee, so there is no fingerprint today.
   - Under congestion, the only way to get priority is to overpay, and any overpayment is a unique fingerprint.
   - Proposal (CONSENSUS, P2): quantized fee tiers, where the fee is `standard_fee(shape) × m` with m in a small fixed set.
6. **Emission and tail are correct and match the spec.**
   - Tail: 0.6 BLK per block from height 3,678,315, about 0.77 %/yr and falling [test: `curve_matches_spec`].
   - At standard fees, a saturated block earns at most about 0.39 BLK in fees, so the tail-era security budget is at least 60 % subsidy.
   - All fees are hard-coded in atomic units and do not scale with price. That is acceptable for testnet but not a long-term design.

---

## 1. Transactions (tx/src)

### 1.1 What is implemented, and correct
- **Codec** (`tx/src/codec.rs`): minimal LEB128 varints, canonical points and scalars, bounded counts checked before allocation, no trailing bytes. `encode(decode(b)) == b`.
  - Classification: complete and verified [test: `varint_exhaustive_small_values_are_unique`, `varint_rejects_non_minimal_and_overflow`, `tx/tests/fuzz_decode.rs`].
- **Size caps** are enforced before decoding the body (`types.rs:386-403`). PX proofs are re-encoded and compared, so non-canonical proof bytes are rejected (`zk/src/lib.rs:203`). Commit `4b277cd` adds rejection of rewritten proofs [src].
  - Transaction-id malleability of PX transactions without v1 inputs now depends only on the STARK encoding being canonical. Status: [unknown] beyond `4b277cd`'s tests.
- **Signature messages:**
  - a transfer's CLSAG signs the prefix, base and range-proof hash, and the network id (`types.rs:276`);
  - a PX transaction's CLSAG also signs the PX proof (`px.rs:400`);
  - a deploy's CLSAG signs its payload (`px.rs:552`).
  - Cross-network replay is excluded [src]. Complete and verified [test: `tx/tests/adversarial.rs`].
- **Weight** follows Monero's formula: size plus the Bulletproofs+ clawback (`types.rs:324`). Complete and verified [src; math].
- **Standard fee** (`builder.rs:103-130`): `standard_fee(n, k) = 20 · max_weight(n, k)`, with every varint at its maximum length. It is a pure function of the public shape, so it carries no fingerprint beyond the shape.
  - Worked value: `standard_fee(1, 2) = 20 × 1 723 = 34 460` atomic units = 0.00034460 BLK [math: prefix 475 + pseudo-out 32 + BP+ 640 + CLSAG 576].
- **The wallet always uses the standard fee** (`wallet.rs:902-925`), the PX standard fee (`px_standard_fee`), or `deploy_fee` [src].
- **PX fee exactness:** `check_px_structure` requires `fee == PX_STANDARD_FEE = 2 × (4 MiB + 256 KiB) = 8 912 896` atomic units = 0.0891 BLK (`px.rs:681`). Complete and verified [test: `tx/tests/px_consensus.rs:243`].
- **PX balance** (`px.rs:688`): without v1 inputs, `v = fee + bridge_in + payouts − bridge_out = 0` exactly. The fee then leaves the PX pool through `bridge_out`, and the kernel proves the PX side. Correct [src].

### 1.2 `is_stateless` classification (`validate.rs:169`)
Correctly classified:
- **Contextual:** C1–C4, PX1–PX4 and `DuplicateContract`.
- **Stateless:** `PxProof`. The registry entry is fixed by the contract id, which hashes the payload, including the budgets [src].

Remaining issues:

**TX-1: intra-transaction duplicates are classified as contextual.**
- Examples:
  - a PX transaction whose two nullifiers are equal fails as `PxNullifierSpent`, from the insertion into the block set at `validate.rs:423`;
  - a PX hidden output and a payout with the same key fail as `DuplicateOneTimeKey`, from `check_uniqueness_of`.
- Both are misbehaviour, but neither earns a penalty.
- The failure is cheap (before the proof), so it is not a DoS.
- Severity low; confidence high. Partially implemented; a fix is in progress per the brief.

**TX-2: `InvalidSignature` is always contextual.**
- This is part of the known item "invalid-CLSAG spam unpenalized". My quantification:
  - a 64-input transfer is about 45 KB, within `MAX_TX_SIZE`, and forces 64 16-member CLSAG verifications;
  - at about 3 ms each [assumed, from the measured 6.8 ms per full 1–2 input transfer], that is about 0.2 s per transaction;
  - it costs the attacker nothing: no funds, and a valid range proof reused across every spam transaction.
- **Proposed refinement (policy, S):** classify `InvalidSignature` as stateless when every ring member is buried at least `K_DEPTH` blocks below the tip (for example 60, which is `COINBASE_MATURITY`).
  - Ring indices resolve to the same outputs on any branch that forks above that depth, so a failure there is almost certainly the sender's fault.
  - An honest race needs a reorg deeper than K. Ring members are already at least 10 blocks deep (`SPENDABLE_AGE`), so honest wallets rarely use very young rings.
  - Recommendation attributes:

    | Attribute | Assessment |
    |---|---|
    | Security | + |
    | Privacy | none |
    | Performance | none |
    | Consensus impact | policy |
    | Testnet identity | no new identity |
    | Difficulty | S |
    | Priority | P1 |

**TX-3: validation order.** In `validate_transfer`, the stateless range proof runs after the contextual CLSAGs, and `check_deploy_structure` loads the ELF programs before any signature. This is known ("being fixed"). The ELF loading is bounded (1 MiB) and cheap, so its severity is low.

### 1.3 Findings in tx/src

**TX-4: deploys are priced below v1 transfers and below PX transactions, yet they create permanent RAM state.**
- Severity: medium (testnet), high (mainnet). Accepted today, but must be redesigned. Confidence high [src; math].
- **Where:** `PX_FEE_PER_BYTE = 2` (`params.rs:24`); `PxDeploy::min_fee` (`px.rs:595`); `check_deploy_structure` sets `fee_per_weight: 0` (`px.rs:717`), so there is no BP+ clawback.
- **Scenario 1 (cheap batch payments):**
  - A 16-output payment made as a deploy with a tiny program costs about 2 × 3.9 KB ≈ 7.8 k atomic units.
  - The same payment as a transfer has weight ≈ 3 609 + clawback 3 430 = 7 039, so it costs 140 k atomic units: about 18 times more.
  - The deploy also uses none of the v1 weight; it uses the 8 MiB PX lane instead.
- **Scenario 2 (state bloat):**
  - An attacker fills the PX lane with 1 MiB deploys for about 0.168 BLK per block.
  - Every program is parsed and held in `MemoryChain::registry` as `Arc<Program>` (`state.rs:48`, `apply_block` at `state.rs:184-189`). This state is not prunable, unlike bodies (PX-F1).
  - At most about 6 GB/day. At the minimum fee, about 21.5 BLK per GiB of RAM, which is trivial on a testnet where coins are mined freely.
- Duplicate program ids inside one deploy are accepted. Only the first is reachable (`state.rs:281`), so the rest are dead bytes (low; a contract-author footgun).
- **Recommendation R-TX4:**
  1. **Policy now:** template selection puts PX transactions before deploys and caps deploy bytes per template (for example 1 MiB).
  2. **Consensus:**
     - a per-block deploy byte sub-budget (for example 1 MiB);
     - a deploy fee equal to the v1 `min_fee` of its transfer part plus the payload at least at the v1 rate (20 per byte) or higher, fixed exactly (see §3.3);
     - at most 2 outputs (payment and change);
     - reject duplicate program ids.
  3. **Registry storage:** keep the ELF on disk and hold only an LRU of loaded programs.
- Recommendation attributes:

  | Attribute | Assessment |
  |---|---|
  | Why needed | stops the cheapest permanent-state vector and removes the cheap-transfer loophole |
  | Security | + |
  | Privacy | + (deploy used as a payment channel is a fingerprint) |
  | Performance | + (smaller RAM growth) |
  | Complexity | S (policy), M (consensus) |
  | Consensus impact | policy, then CONSENSUS |
  | Testnet identity | the consensus part needs a new identity; fold it into v3 |
  | Difficulty | policy S, consensus M |
  | Priority | P1 |

**TX-5: the transfer and coinbase hedges bind only the input context.**
- This deepens the known item "HedgedRng users not reviewed". `HedgedRng::new(&[secret], &[b"transfer", &ctx], rng)` (`builder.rs:228`) binds the key images, but not the payments, amounts or an attempt counter.
- **Scenario:** under a full RNG failure, a wallet that rebuilds the same spend (for example after C4 griefing, §2.4) derives the same anchors. It therefore produces the same one-time keys for the same recipient, which collide again with the attacker's copy under C4. The transaction can never be rebuilt successfully until the RNG recovers.
- The coinbase hedge binds only the height, so templates at the same height with a failed RNG reuse the same ephemeral secrets. This is harmless, because only one block per height lands on a chain.
- Severity low. Complete but requires further testing.
- **Recommendation:** bind the hedge to `(ctx, payments, change, fee, attempt counter)`.
  - Security +; privacy +; consensus impact none; difficulty S; P2.

**TX-6: repeated serialization.**
- `encoded_len()` re-encodes the whole transaction. For PX transactions this copies the 2–4 MB proof several times per admission and per block: in `check_px_structure`, `insert`, `px_bytes`, and each `hash`.
- Info; inefficient but not exploitable. P3.

---

## 2. Mempool (chain/src/mempool.rs)

### 2.1 Implemented and correct
- **Two classes with separate caps:** v1 at most 50 MB, PX at most 64 MiB. Each class has its own rate unit. Complete and verified [test: `a_full_pool_evicts_only_strictly_cheaper_entries_and_only_if_that_suffices`].
- **Atomic eviction:** only strictly cheaper entries are evicted, and the victims are chosen before anything is removed. Complete and verified [test: same; `eviction_under_a_flood_stays_fast`].
- **Conflict keys in namespaces:**
  - kinds: key image, nullifier, contract id, output key;
  - output keys cover transfer outputs, PX outputs and payouts, deploy outputs and coinbase outputs, the last in `remove_block`;
  - Classification: complete but requires further testing. The unit tests cover nullifier conflicts only. There is no mempool unit test for an output-key conflict, or for "a template never holds two sharers". `chain/tests/revalidation.rs::an_output_key_created_by_another_transaction_is_caught_by_the_extension_check` covers the extension path [test].
- **`select`:** a second-line conflict filter, and a simulation of the PX pool in block order [test: `selection_orders_by_fee_rate_and_respects_budgets_and_the_pool`]. `COINBASE_RESERVE = 3 000` is at least the largest possible coinbase, 16 × 91 + 13 = 1 469 bytes [math].
- **Revalidation after an extension:** only the rules an extension can change are re-checked. The argument is sound [src] and tested [test: `revalidation_after_an_extension_agrees_with_full_validation`, `tx/tests/revalidate_after_extension.rs`].
- **The proof cache `|id| mempool.contains(id)` is sound.** `insert` is private and reachable only through `add`, which verifies in full. The contract id fixes the registry entries [src].

### 2.2 DoS resistance of admission

**MP-1: all admission cryptography runs under the ChainManager mutex.**
- Severity medium–high; complete (as designed), must be redesigned; confidence high [src].
- **Where:**
  - `on_tx`: `spawn_blocking(move || inner2.chain().submit_tx(tx))` (`net.rs:1408`);
  - `on_stem_tx`: `chain().check_tx` (`net.rs:1463`);
  - `fluff`: `chain().submit_tx` (`net.rs:1537`).
  - Under the lock, `Mempool::add → validate_mempool_tx` runs CLSAGs, BP+ and the PX proof.
- **Scenario:**
  - The global PX bucket allows 2 transactions per second (`net.rs:263`), and each costs about 0.21 s honest; the adversarial cost is unknown (ZK-F4). The attacker can therefore keep the chain lock busy about 42 % of the time or more.
  - A PX transaction without v1 inputs needs no funds to reach PX5. Only the anchor must be recent (public), the nullifiers fresh (random), and `pool ≥ fee`.
  - With `INVALID_TX = 20` and `BAN_THRESHOLD = 100`, each identity gets 5 proofs before a ban, and bans are exact-IP (N-5).
  - Meanwhile block connection, templates and RPC wait.
- **Recommendation R-MP1 (policy, M): two-phase admission.**
  1. Under the lock: the cheap checks, the conflict precheck, and a snapshot of what the expensive checks need (resolved ring members, the `Arc<Program>` and budget per function, the network id).
  2. Without the lock: CLSAG, BP+ and the PX proof.
  3. Under the lock again: re-run `revalidate_after_extension` plus the conflict precheck against the current tip. If a reorg happened in between, run full validation without the proof.
- Recommendation attributes:

  | Attribute | Assessment |
  |---|---|
  | Security | + (liveness) |
  | Privacy | none |
  | Performance | large improvement under load |
  | Consensus impact | policy |
  | Testnet identity | no new identity |
  | Difficulty | M |
  | Priority | P1 |

**MP-2: redundant proof verification.**
- The stem path verifies the PX proof in `check_tx`, and `fluff` verifies it again in `submit_tx` at the same node (`net.rs:1463`, `1537`).
- After a reorg, `returned` transactions go through `mempool.add`, which verifies the proof again (`manager.rs:479-481`), although the disconnected block already verified them. `revalidate(after_reorg = true)` then validates them a third time without the proof.
- **Example:** a 10-block reorg with 3 PX transactions per block re-verifies 30 proofs, about 6.3 s under the lock, on top of the full v1 revalidation (known).
- **Recommendation:** keep a bounded "proof verified" id cache, shared by the stempool, the returned-transaction path and the mempool, keyed by tx id. It is sound for the same reason as `validate_block_transactions_cached`.
  - Severity low–medium; policy; S; P2.

**MP-3: the full revalidation after a reorg** is known. It has one more cost: returned transactions are validated before `revalidate` and then again inside it (`manager.rs:479-483`). This is covered by R-MP2.

**MP-4: pool memory is accounted by encoded size only.** In-memory `Transaction` structs, conflict-key vectors and hash-map overhead add a constant factor, estimated at 2–3 times [assumed]. The pool stays bounded; this is info.

### 2.3 Fairness and censorship resistance of selection

**MP-5: the PX lane has no fee market, and "fee rate" ordering means smallest first.**
- Severity medium; accepted limitation that should be redesigned; confidence high [math].
- **Rates at the fixed fee:**
  - honest PX transfer: 8 912 896 / 2.18 MB ≈ 4.08 per byte;
  - vault call: 2.69 MB, ≈ 3.31 per byte;
  - a deploy: any fee of at least 2 per byte.
- **Consequences:**
  - A deploy at about 4.1 per byte outranks every PX transaction. Filling 8 MiB costs about 34.4 M atomic units ≈ 0.34 BLK per block, or about 0.285 BLK to outrank only vault calls.
  - PX senders cannot respond, because their fee is fixed by consensus.
  - The class is small: the 64 MiB PX pool holds about 29 PX transactions, about 10 blocks' worth. When it is full, new PX transactions of equal size are refused outright (`FeeTooLowForFullPool`).
  - Their proofs (45 s, 3.8 GB) are wasted. The anchor window (`ROOT_WINDOW = 100` blocks) is not the binding limit here; the pool cap is.
  - Among PX transactions, selection by rate systematically starves larger contract calls in favour of plain transfers.
- **Recommendation R-MP5:**
  - **Policy:** order the PX class as PX transactions first-seen (FIFO), deploys after; plus the deploy cap from R-TX4.
  - **Consensus (P3):** make the PX fee a deterministic function of public data, namely the registered budgets of the called functions. That fixes the proof-size upper bound before proving, avoiding the fee↔proof circularity that forced the max-size fee.
  - Such a fee leaks nothing beyond what is already public (contract and program ids are public in `PxFunction`), so it keeps privacy fix P-7, and it prices verification fairly.
- Recommendation attributes:

  | Attribute | Policy part | Consensus part |
  |---|---|---|
  | Security | + | + |
  | Privacy | neutral | neutral |
  | Difficulty | S | M |
  | Consensus impact | policy | CONSENSUS |
  | Testnet identity | no new identity | new identity |
  | Priority | P1 | P3 |

**MP-6: v1 ordering at standard fees is shape-biased noise.**
- `standard_fee` is computed from maximum varint lengths. The effective rate (fee / actual weight) is therefore higher for many-input transactions and varies with how well ring offsets compress.
- Inclusion order under congestion is thus correlated with shape and ring composition, not with sender intent. Info (neutral for privacy; shape is public).
- There is no transaction expiry (known) and no RBF, so a stuck transfer cannot be bumped. The wallet re-spends after `PENDING_EXPIRY_BLOCKS = 20` with the same ring (W-5, `wallet.rs:1024`), so there is no privacy loss. Pools that still hold the old version stay split until restart. Covered by the known "no expiry" item.

### 2.4 Front-running, MEV, and the C4 griefing (consensus analysis)

**MP-7: output-key front-running (C4) is deterministic for Dandelion stem relays.**
- Severity medium–high (censorship of any transaction; about 5 orders of magnitude cost amplification against PX); complete (as designed), must be redesigned; confidence high [src; test: `chain/tests/revalidation.rs::forge_with_output_key` builds exactly the griefing transaction at `standard_fee(1, 2)` and consensus accepts it].
- **Mechanism:**
  1. T is relayed in stem phase: `check_tx` only, not pooled (`net.rs:1463`), with an embargo before fluff.
  2. A malicious stem hop learns T's output keys before anyone else.
  3. It immediately fluffs its own T′: 1 input, outputs sorted, one of them carrying T's key with amount 0 and the attacker's own mask. T′ can copy up to 15 more keys from other victims.
  4. Mempools see T′ first. When T fluffs, it hits `MempoolError::Conflict` on the `OutputKey` namespace. The stem pool's `stem_keys` has no output keys, so the conflict is only caught at fluff.
  5. T′ is mined, and T is invalid forever under C4.
- A miner does not even need the race: it includes T′ in its next block.
- **Costs:**
  - attacker: one fee (≈ 0.00034 BLK), or less per victim when batched;
  - v1 victim: a rebuild after 20 blocks. The ring is reused, so no privacy loss (W-5).
  - PX victim: the payout keys and change keys are in the prefix, so `h_tx` changes and the victim must **re-prove** (about 45 s, 3.8 GB).
- **Can consensus bind one-time keys to the transaction's inputs?**
  - `O = Hs(S)·G + D` with `S = r·C`. Checking that O was derived from this transaction's `ctx` requires `r` or the recipient's `(D, C)`.
    - A Schnorr proof of knowledge of `r` is impossible, because `R = r·D` has a hidden base.
    - A proof relating `(O, R, ctx)` to hidden recipient keys is a new zero-knowledge statement per output: XL difficulty, hundreds of bytes per output, new cryptography, and no external review.
    - Not recommended [math, src: `crypto/src/stealth.rs:1-13`].
  - **The binding already exists at the wallet layer.** `r = Hs(anchor ‖ ctx ‖ D ‖ C)`, and the receiver's Janus check (`scan_output`, `stealth.rs`, step 5) recomputes it with the *including* transaction's ctx. A copied output in another transaction is therefore rejected (`JanusAnchorMismatch`), even when the copier is the original sender, who knows S. This is stronger than Monero's post-2018 wallet fix [Monero burning-bug post-mortem][mb]; compare [research-lab #103][rl103].
- **Options:**

  | Option | Griefing | Burning-bug backstop | State | Privacy cost | Consensus |
  |---|---|---|---|---|---|
  | A. Keep C4 on O (status quo) | free (fee only), deterministic for stem relays and miners | full, even for wallets that skip Janus | 32 B × all outputs | none | none |
  | B. Drop C4 (Monero parity) | none | wallet-only (Janus plus key-image dedupe); third-party wallets must implement it | removes the index | none | CONSENSUS |
  | **C. Unique on (O, commitment)** | **hidden outputs: impossible**; clear payouts: costs the attacker the full amount, paid into an output the true recipient can spend | exact duplicates blocked; different-amount duplicates by the sender need Janus | same size (hash of the pair) | none | CONSENSUS |
  | D. Keep C4, policy mitigations (keep both sharers, prefer the earlier stem) | reduced only; the attacker still wins as a miner | full | same | none | policy |

- **Why C resists copying** [math: DL, and BP+ as a proof of knowledge of openings]:
  - A non-owner cannot place `(O, Cm_victim)` in its own transfer, PX transaction or deploy. The balance equation forces the attacker to know the sum of its output masks, and BP+ forces knowledge of each opening, including `y_victim = Hs(S)`.
  - Copying the victim's whole output set plus its BP+ would require the attacker's pseudo-output masks (known to it through the CLSAG z values) to sum to `Σ y_victim`.
  - For clear payouts, `Cm = G + a·H`: the attacker must commit a real `a` of its own. The recipient knows `x` and mask 1, so it could recover that output, given a wallet recovery path.
- **Recommendation R-MP7:**
  - Adopt option C in the v3 genesis, with tests:
    - the forge test inverted: T stays valid when T′ copies O with a different commitment;
    - a clear-payout copy is accepted only with the attacker funding `a`;
    - scanning of two outputs with the same O keeps only the Janus-valid one.
  - Mempool `ConflictKind::OutputKey` changes to the pair key.
  - Document that wallets **must** run the Janus check and deduplicate by key image.
  - Until then (policy, P2): the wallet detects `DuplicateOneTimeKey` invalidation and rebuilds immediately with the same ring and fresh hedging (TX-5), instead of waiting 20 blocks.
- Recommendation attributes:

  | Attribute | Assessment |
  |---|---|
  | Security | + (censorship) |
  | Privacy | none |
  | Performance | neutral |
  | Complexity | S–M |
  | Consensus impact | CONSENSUS |
  | Testnet identity | new identity (combine with v3) |
  | Difficulty | M |
  | Priority | P1; decide before the v3 genesis |

**MEV surface otherwise:**
- v1 amounts are hidden, so there is no value-based MEV.
- PX has no global mutable public contract state, only records and nullifiers, so contract-level MEV is limited to:
  - ordering bridge-outs against the pool (a miner can delay withdrawals; `select` skips them when the pool is short);
  - censorship.
- Nullifier and key-image front-running needs secrets.
- A deploy contract id binds the first key image, so it cannot be squatted.

[src] Accepted limitation (low).

### 2.5 Other mempool notes
- **MP-8: stale documentation.**
  - The `mempool.rs` module docs point to `chain/tests/mempool.rs`, which does not exist.
  - docs/blocks.md §7 and transactions.md §8.5 list conflicts on key images, nullifiers and contract ids, but not output keys.
  - Low; A16b.
- **MP-9: a stem-pool gap.** `stem_keys` omits output keys and contract ids, so two stem transactions that share an output key both route, and one fails at fluff. Low; policy S.

---

## 3. Economics

### 3.1 Emission (chain/src/emission.rs)
- **Formula:** `reward = max((M − G) >> 20, 0.6 BLK)`, with M = 21 M BLK at 8 decimals. The first reward is 20.02716064 BLK; the tail starts at height 3 678 315 (about 14.0 years), when 20.37 M BLK have been emitted.
  - Complete and verified [test: `first_rewards`, `curve_matches_spec`, `reward_is_monotone_non_increasing`].
- **Exact coinbase claim (B3, `==`, u128):** the supply is computable. G is the same on every branch, because the reward depends only on height [test: `chain/tests/manager.rs::emission_is_enforced_exactly`].
- **Tail inflation:** 157 680 BLK/yr, which is 0.774 % in the first tail year and about 0.56 % after 50 tail years [math]. This is parity with Monero's 0.6 XMR per 2 minutes, which is slightly more inflationary relative to its smaller supply.
- **No overflow:** G grows by 6·10⁷ per block, so u64 overflows only after about 3·10¹¹ blocks [math].

### 3.2 Security budget
- **Maximum fees per block at standard fees:**
  - v1: 600 000 × 20 = 0.12 BLK;
  - PX: 3 × 0.0891 = 0.267 BLK;
  - total ≈ 0.39 BLK [math].
  - Today that is at most 2 % of revenue; in the tail era, at most about 39 %.
  - The subsidy therefore dominates: fee sniping is weak and selfish-mining gains from fees are small. The tail is adequate in structure; its real-terms value depends on price and hashrate [unknown].
- **Fees are fixed in atomic units** (`FEE_PER_WEIGHT = 20`, `PX_FEE_PER_BYTE = 2`, both constants in `params.rs`) and do not scale with price.
  - A 100-fold price move makes spam either free or transacting prohibitive.
  - Monero ties the minimum fee to the base reward and the median block weight [Monero dynamic fee research][jm].
  - Deferred, P3, CONSENSUS.

### 3.3 Fee market and fee fingerprinting
- **PX:** exact fee. No fingerprint. Complete and verified.
- **v1:** consensus allows any fee at or above the minimum. The official wallet pays exactly `standard_fee(shape)`. Any other fee, including a priority overpayment, is a unique wallet fingerprint, and the mempool rewards it through rate ordering.
  - **Recommendation R-FEE1:** consensus rule T8′: `fee ∈ { m · standard_fee(n, k) : m ∈ {1, 4, 20} }`. This is comparable to Monero's priority multipliers [Monero fee tiers PR][pr1079], but enforced by consensus rather than by the wallet. It leaks at most 1.6 bits and gives a real priority lane.
  - Recommendation attributes:

    | Attribute | Assessment |
    |---|---|
    | Security | neutral |
    | Privacy | + |
    | Performance | none |
    | Consensus impact | CONSENSUS |
    | Testnet identity | new identity (v3) |
    | Difficulty | S |
    | Priority | P2 |
- **Deploy:** the fee is at least the minimum, with any amount above it allowed. Apply the same exactness to deploys (R-TX4).

### 3.4 Block weight, PX budget, dynamic size

| Quantity | Value | Evidence |
|---|---|---|
| v1 lane | about 300 transfers/block ≈ 2.5 TPS | [math] |
| PX lane | 3 PX/block ≈ 0.025 TPS, about 8.4 MB per 2 min | [math, from measured proof sizes] |
| Maximum chain growth | about 6.5 GB/day ≈ 2.3 TB/year | [math] |

- **Does not scale.** The limit is the proof size (about 2.18 MB). The root fix is proof aggregation or recursion (future).
- The 8 MiB PX budget also raises block-propagation time and orphan-driven centralization pressure, especially over Tor. That is for P2P reviewers.
- **Dynamic block size:** keep the fixed limits through testnet. They give simple, auditable DoS bounds. A Monero-style penalty scheme [jm] on top of a separate PX lane adds consensus complexity without testnet benefit. Deferred, P3.

---

## 4. Answers to the 13 questions (condensed)

1. **What is implemented:** strict codec; T1–T11 and C1–C4; PX1–PX5; B1–B7; weight with clawback; exact PX fee; per-shape standard fee; two-class mempool with atomic eviction and four conflict namespaces; proof-once cache; extension-only revalidation; smooth emission with a tail.
2. **What is correct and well designed:** canonical encodings; network-bound signatures; exact coinbase claim; ctx-bound Janus outputs; exact PX fee; atomic eviction; `select`'s pool simulation; the proof-cache soundness argument.
3. **What is incomplete:**
   - mempool output-key conflict tests;
   - intra-transaction error classification (TX-1);
   - validation order (TX-3);
   - stale docs (MP-8).
4. **What is fragile:**
   - all admission cryptography under the chain mutex (MP-1);
   - PX lane pricing (MP-5);
   - hedge binding (TX-5).
5. **What can be exploited:**
   - C4 front-running (MP-7);
   - deploy lane capture (MP-5);
   - deploy RAM bloat (TX-4);
   - no-funds proof and CLSAG spam under the lock (MP-1, TX-2).
6. **What is inefficient:** repeated proof verification (MP-2); repeated serialization (TX-6).
7. **What does not scale:**
   - PX throughput (0.025 TPS);
   - chain growth of up to 2.3 TB/year;
   - fixed atomic-unit fees;
   - an in-RAM registry.
8. **What is missing:**
   - priority tiers;
   - transaction expiry (known);
   - deploy sub-budget;
   - proof-verified cache;
   - two-phase admission.
9. **What should be redesigned:**
   - C4, towards (O, commitment);
   - deploy pricing and budget;
   - PX fee as a function of public budgets.
10. **What could be innovated:**
    - depth-based stateless classification of `InvalidSignature`;
    - a budget-derived exact PX fee;
    - (O, Cm) uniqueness, which makes griefing self-funding for the recipient.
11. **What to do before the testnet:**
    - **P1 policy:** R-MP1, TX-2 refinement, R-TX4 policy part, R-MP5 policy part.
    - **Decide before the v3 genesis:** R-MP7 (C4 → option C), R-TX4 consensus part, R-FEE1.
    - **P2:** R-MP2, TX-5, MP-8, and output-key conflict tests.
12. **What can be deferred:** dynamic block size; price-scaled fees; RBF; the budget-derived PX fee; proof recursion; compact block relay.
13. **What should never change:**
    - B3 exact coinbase claim;
    - strict canonical encoding and no trailing bytes;
    - network id in every signature message and proof binding;
    - ctx-bound output derivation with a mandatory Janus check;
    - exact PX fee, or any replacement that is a deterministic function of public data;
    - the emission curve and the 0.6 BLK tail once launched;
    - a separate, bounded PX lane;
    - PX proofs verified before their state is trusted, and the registry immutable per contract id (the proof cache depends on it).

## Sources
- [mb]: https://web.getmonero.org/2018/09/25/a-post-mortum-of-the-burning-bug.html
- [rl103]: https://github.com/monero-project/research-lab/issues/103
- [pr1079]: https://github.com/monero-project/monero/pull/1079
- [jm]: https://github.com/JollyMort/monero-research/blob/master/Monero%20Dynamic%20Block%20Size%20and%20Dynamic%20Minimum%20Fee/Monero%20Dynamic%20Block%20Size%20and%20Dynamic%20Minimum%20Fee%20-%20DRAFT.md

[mb]: https://web.getmonero.org/2018/09/25/a-post-mortum-of-the-burning-bug.html
[rl103]: https://github.com/monero-project/research-lab/issues/103
[pr1079]: https://github.com/monero-project/monero/pull/1079
[jm]: https://github.com/JollyMort/monero-research/blob/master/Monero%20Dynamic%20Block%20Size%20and%20Dynamic%20Minimum%20Fee/Monero%20Dynamic%20Block%20Size%20and%20Dynamic%20Minimum%20Fee%20-%20DRAFT.md
