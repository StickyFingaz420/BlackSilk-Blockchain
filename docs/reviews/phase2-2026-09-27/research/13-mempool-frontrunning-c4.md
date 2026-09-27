# 13 mempool-frontrunning-c4: dossier (phase 2, research and briefing)

Specialist 13. Internal engineering work, **not an audit**. I only read the repository: no
file was changed, and no build or test was run. Every "tested" tag below names an existing
test that I read. I did not run it.

- **Commit:** `rebuild/core` @ `9e422d8` (`git rev-parse --short HEAD`).
- **Scope (roster):** rule C4 (one-time-key uniqueness), the mempool conflict keys, the
  wallet Janus checks. Options C (pair-keyed, with SX1's corrections), B (drop C4) and
  "keep", taken through the 15-step consensus discipline.
- **Evidence tags:** [math] re-derived by me · [test: name] · [src] file:line read by me ·
  [web] primary source I fetched on 2026-09-27 · [assumed] · [unknown].

---

## 1. Scope and what I read

**Brief, roster and reviews**
- `C:/bszkeval/p2/brief.md`, `C:/bszkeval/p2/roster.md`: entry 13 and its neighbours 10,
  11, 12, 17, 33, 38, 46, 47 and 50.
- `docs/reviews/full-review-2026-09-27.md`: risk 7; the register row "R6 MP-7"; §3.4;
  §6.2–6.3 (D8); §7.2; §8 never-change list items 7, 10 and 28; §9 item 5.
- `docs/reviews/autonomous-session-2026-09-27.md` §8 (R6 is still an owner decision).
- `docs/reviews/full-review-2026-09-27/R6-tx-mempool.md` (MP-7, TX-1, TX-5, MP-9 and the
  options table).
- `SX1-core-crossreview.md`: the verdict rows and all of §2, "Option C … four
  corrections". **SX1 takes precedence over R6.**
- R2 §3.1 (the "anchor + C4 covers the burning bug" claim), R1 V12 (undo relies on C4),
  R16 (the F1 history) and `v3-plan.md` (the C/B line).
- The memory note defining the 15 steps: problem · demonstrated failure · prior art ·
  alternatives · affected components · activation · compatibility · reorg · wallet ·
  mining · P2P · golden vectors · regression tests · full suite · adversarial review.

**Specifications**
- `docs/transactions.md`: §3.1–3.4 (ctx, sending, scanning, key images), §8.2 C4
  (lines 541–544), B4 and B7 (553, 556), §12 Janus (whole section, including Lemma 1 and
  Theorem 1), and §13 tables (1063, 1097).
- `docs/blocks.md` §7 (lines 170–205).
- `docs/px.md`: 562–571 (payouts, v1 balance) and 604 (the C1–C4 row).
- `docs/p2p.md`: 457 and 505–510.

**Code**
- `tx/src/validate.rs`: 1–1100, in particular `check_structure` 301–362,
  `check_uniqueness(_of)` 470–508, the PX, deploy and transfer mempool paths 580–688,
  `revalidate_after_extension` 712–746, and block validation 906–1097 (the coinbase C4 at
  1029–1036, the per-tx C4 at 1040–1050).
- `tx/src/px.rs`: 427–448 (`output_keys`, `output_context`), 643–729
  (`check_px_structure`, including `PxDuplicateOutputKey` at 684–694) and 787–799
  (`check_deploy_structure` → `check_structure`).
- `tx/src/state.rs`: 40–75, 180–300 (the `one_time_keys` set, apply and undo).
- `tx/src/scan.rs` (whole file).
- `tx/src/builder.rs` 195–232 (the hedge context).
- `tx/src/params.rs` 99–130 (`TxRules`).
- `crypto/src/stealth.rs`: 1–100 (contexts) and 170–320 (`scan_output`).
- `chain/src/mempool.rs` 60–260 (`ConflictKind::OutputKey`, `conflict_keys`, `precheck`,
  `enter_rules`).
- `p2p/src/net.rs` 2140–2160 and 2425–2530 (`stem_keys`, `on_stem_tx`, `stem_or_fluff`).
- `wallet/src/wallet.rs`: 240–262, 1085–1170 (`apply_block`: dedupe and spent marking)
  and 1414–1560 (`refresh_pending`, release after `PENDING_EXPIRY_BLOCKS = 20`).
- `wallet/src/index.rs` (keyed by global index only).
- `consensus/src/schedule.rs` 19–55.
- `node/src/fingerprint.rs` 1–80.

**Tests read**
- `chain/tests/revalidation.rs`: header, and 230–430 (`forge_with_output_key`,
  `an_output_key_created_by_another_transaction_is_caught_by_the_extension_check`).
- `chain/tests/mempool_conflicts.rs`: header; the list of tests; 380–440, 660–780.
- `chain/src/mempool.rs` unit tests at 850–1000 (by grep).
- `tx/tests/adversarial.rs` 300–360 (`KeyExists`, `c4_one_time_keys_are_unique`).
- `tx/tests/validation_order.rs` 89, 313 and 520–700 (`PxDuplicateOutputKey`).
- `tx/tests/transfers.rs` 142–147; `tx/tests/chain_integration.rs` 144.
- `p2p/tests/network.rs` 529, 825, 2110–2150 (stem harness, `px_deposit`).

---

## 2. Current state

### 2.1 What C4 is, and where it lives

C4 says that no output's `O` may already exist on the chain or earlier in the same block
(transactions.md:541). It is implemented as follows:

| Place | What | Evidence |
|---|---|---|
| `tx/src/validate.rs:502-505` | `chain.has_one_time_key(k) \|\| !block_one_time_keys.insert(k)` → `DuplicateOneTimeKey` | [src] |
| `tx/src/validate.rs:1029-1036` | Coinbase outputs against the chain and the block set → `CoinbaseDuplicateOneTimeKey` | [src] |
| `tx/src/validate.rs:1040-1050` | Every other tx: the block-wide `one_time_keys` set over `tx.output_keys()` | [src] |
| `tx/src/validate.rs:57` | `ChainView::has_one_time_key` (trait method; implemented in 4 test files) | [src] |
| `tx/src/state.rs:45,207-209,239` | `MemoryChain.one_time_keys: HashSet<[u8;32]>`; insert on apply, remove on undo | [src] |
| `chain/src/mempool.rs:84,126-130` | `ConflictKind::OutputKey` namespace (F1, `16659ee`), first seen wins | [src] |
| `tx/src/validate.rs:223,277` | `DuplicateOneTimeKey` is **contextual**, so relaying it is never penalized | [src] |

**Intra-transaction uniqueness already exists as stateless structure rules,**
independently of C4:
- **transfer and deploy outputs:** strictly sorted by `O` (`validate.rs:334`; deploys go
  through `check_structure` at `px.rs:794`);
- **coinbase outputs:** strictly sorted (`validate.rs:936`);
- **PX:** hidden outputs and payouts are sorted separately (`px.rs:679-680`), and the
  shared key between the two lists is caught by `PxDuplicateOutputKey` (`px.rs:684-694`,
  added in `b33a1ce`) [src; test: `validation_order.rs:532-560`].

The comment at `px.rs:684-688` says this check "changes no verdict" because C4 would
catch the duplicate anyway. **Under B or C that stops being true.** It becomes the only
guard, which is exactly SX1's mandatory correction 1.

### 2.2 The wallet-side binding (why the burning bug is already prevented without C4)

- `r = Hs("ephemeral", anchor ‖ ctx ‖ D ‖ C)`, `R = r·D`, `S = r·C`,
  `O = Hs("output-key", S)·G + D` (`stealth.rs:1-13`).
- `scan_output` recomputes `r'` with the **including** transaction's ctx and rejects the
  output unless `r'·D' = R` (`stealth.rs:255-262`) [src]. It also rejects an output whose
  amount does not open `Cm` (`stealth.rs:264-280`).
- The contexts are domain-separated and unique per transaction on one chain:
  - transfer and deploy: `H32("input-context", key images)`;
  - PX: `H32("input-context/px", nullifiers ‖ key images)`;
  - coinbase: `H32("input-context/coinbase", height)` (`stealth.rs:46-63`).
  - Uniqueness follows from C2 (key images), PX2 (nullifiers) and one coinbase per
    height [src].

**Lemma 2 (burning-bug resistance without C4)** [math, ROM].

*Claim.* On a valid chain, a conforming wallet (§12.5) accepts at most one output per
one-time key `O`, except with probability about q²/2^252 for q hash queries.

*Proof sketch.*
1. Suppose the wallet accepts outputs o₁ and o₂ with the same `O`, in transactions with
   contexts ctx₁ and ctx₂.
2. Acceptance means `D'` is the same owned subaddress, so `x₁ = x₂`.
   - `x = Hs(S)` with S = k_v·R. Equal x with S₁ ≠ S₂ would be an Hs collision.
   - So S₁ = S₂, hence R₁ = R₂. Because C is not the identity and the group has prime
     order, r₁ = r₂.
3. So `Hs(anchor₁‖ctx₁‖D‖C) = Hs(anchor₂‖ctx₂‖D‖C)`.
4. If ctx₁ ≠ ctx₂, that is an Hs collision (about 2^126 work even for a sender who
   chooses both anchors).
5. If ctx₁ = ctx₂, both outputs are in the same transaction (ctx is unique per tx on a
   chain), and that is excluded by the intra-transaction rules in §2.1. ∎

This is the same argument Carrot gives for its burning-bug property (§9.1.4 there; the
Cypher Stack audit §3.1.4), with BlackSilk's anchor re-derivation in place of Carrot's
view-tag binding. It needs **no ledger uniqueness rule**. It does rely on the
intra-transaction rule, on C2/PX2 (which make ctx unique), and on the wallet running §3.3
step 5.

**Wallet storage.**
- Outputs are deduplicated by `global_index` only (`wallet.rs:1113-1119`) [src].
- Spends are recognized by key image (`wallet.rs:1154-1166`).
- **SX1's statement that the wallet "tolerates duplicates" is only half right.** If two
  credited outputs shared a key image, `balance()` would count both. Under Lemma 2 this
  cannot happen with the official wallet. See finding F13-6 (defence in depth).

### 2.3 What the tests actually prove

- **The attack itself is already demonstrated, in its miner form, at the consensus
  level** [test: `chain/tests/revalidation.rs::an_output_key_created_by_another_transaction_is_caught_by_the_extension_check`].
  - `forge_with_output_key` builds a fully valid 1-in/2-out transfer at
    `standard_fee(1,2)` that copies the victim's output key (amount 1 000, the attacker's
    own mask).
  - The attacker mines it; the victim's valid transaction then fails
    `DuplicateOneTimeKey` in full validation and is dropped from the pool.
- **The same effect across a reorg and a restart:**
  - `mempool_conflicts.rs::reorganizations_never_leave_conflicting_transactions_pooled`:
    `h` returns from A1, but the attacker's `x` is on branch B, so `h` is invalid;
  - `after_a_restart_the_first_seen_of_a_conflicting_pair_wins`: `x` is mined, and `h`
    is invalid for good.
- **First seen wins whatever the fee:**
  [test: `copying_a_pending_output_key_is_refused_whatever_the_fee`] and
  `first_seen_wins_in_both_orders_deterministically`.
  - This is what makes the stem-relay race decisive: nothing lets the victim outbid the
    copy.
- **Intra-transaction PX duplicates are stateless-rejected** [test:
  `validation_order.rs:532-560`].
- **Not demonstrated by any test:**
  - the stem-relay variant end to end (a relay learning T in stem phase, then fluffing
    T′ first);
  - a PX victim (re-proving);
  - repeated griefing of the victim's rebuild;
  - under any alternative rule, that a wallet credits exactly one of two same-`O`
    outputs (**Lemma 2 is untested**).

### 2.4 What is correct and well designed

- **The Janus anchor bound to ctx** is stronger than Monero's post-2018 wallet heuristics
  (the Cypher Stack audit §1.3.1 calls those "rather delicate", needing all past scans).
  It is equivalent in purpose to Carrot's `input_context` [src, web].
- **Namespaced conflict keys:** an output key cannot block a key image
  [test: `an_output_key_equal_to_a_pooled_key_image_does_not_conflict`].
- **The F1 pool invariant (no two sharers pooled)** correctly prevented template stalls
  **while C4 exists** [test: `a_conflicting_pair_cannot_stall_block_production`].

---

## 3. Problems in scope

### P1: C4 turns output-key knowledge into a veto (R6 MP-7, confirmed)

**What it is, and why it exists.**
- C4 was added as a backstop against the burning bug (transactions.md:183-184, 543-544).
- `O` is public from the moment a transaction is relayed. It is not bound to the
  transaction at consensus level: R6 showed that such a binding needs a new ZK statement
  per output.
- So anyone who sees a pending transaction T can put `O` into a transaction T′ of their
  own and get T′ mined first. T is then invalid under C4 on that branch forever.

**Security consequences.**
- **Targeted censorship of any transaction, for one fee.** One fee is about
  0.00034 BLK at `standard_fee(1,2)` [R6, math]. One T′ can carry up to 16 copied keys:
  1 real change output plus 15 copies of other victims' keys.
- **Who can do it:**
  - **stem relays:** every Dandelion stem hop sees T before diffusion, so the relay
    always wins the race;
  - **miners:** they include T′ directly;
  - **any well-connected observer after fluff:** it wins the pools, and so the hash
    power, that see T′ first.
- **Unlike plain dropping, the embargo timer does not help.** Dandelion++'s fail-safe
  recovers from a relay that drops T. It cannot recover from a relay that invalidates T.
- **The effect is repeatable (F13-2).**
  - The rebuilt transaction spends the same inputs (ring reuse, W-5). It passes through
    the network again and can be copied again for one more fee.
  - A PX victim re-proves each time: about 45 s and 3.8 GB [R6].
  - The wallet notices only after 20 blocks: `PENDING_EXPIRY_BLOCKS`, then an "Invalid"
    reply releases the inputs (`wallet.rs:1490-1500`). It does not rebuild automatically.

**Privacy consequences (F13-2).**
- Each forced rebroadcast of the same key images is one more Dandelion++ stem sample of
  the same origin.
- Anonymity against a spy that controls some relays degrades with the number of
  independent broadcasts linked by a common identifier. Fanti et al. analyse the
  one-broadcast case, so repeated broadcasts are a known intersection lever [assumed; not
  quantified here].
- Griefing is therefore also a **deanonymization amplifier**.

**Classification:**
- consensus-critical: it is a consensus rule;
- privacy-relevant: see above;
- liveness: targeted censorship.

**Prior art.** See §3.4. No surveyed project enforces ledger-wide output-key uniqueness:
- Monero master has no rule of any kind on duplicate output keys [web: `check_tx_outputs`,
  `check_outs_valid`];
- Carrot requires uniqueness within a transaction only (§4.3) and relies on
  `input_context` binding;
- Zcash's ZIP 227 considered a ledger uniqueness rule for issued-note ρ and chose
  derivation from a unique transaction element instead. The design discussion (zips#955)
  names "road-blocking" as the risk of copyable unique values.

**What could go wrong with a fix:** see the per-option analysis in §4.

**Tests that prove the fix:** §5 items 1 and 3.

**Invariants that must never change** (whatever the option):
1. **Intra-transaction uniqueness of `O`** over every output a transaction adds
   (`output_keys()`): stateless, penalizable, for every kind including coinbase.
2. **ctx uniqueness per transaction on a chain,** from C2, PX2 and the coinbase height,
   and the ctx derivations themselves (never-change item 10).
3. **The mandatory Janus and amount checks** before any output is credited; a rejected
   output is treated as not owned (§12.5; never-change item 28).
4. **The key image is a function of `O` only,** `I = p·Hp(O)`, and C2 applies to key
   images: at most one spend per `O`, whatever the number of copies.
5. **CLSAG non-frameability:** a copy of `O` cannot be spent by the copier (it needs `p`),
   so it can never block the owner's real output.

### P2: The burning-bug claim attributed to C4 is overstated in the docs (F13-8)

- transactions.md:543-544 says C4 makes the burning bug impossible "even for broken
  wallets". The §13 table (1063) and Δ5 (1097) say the same.
- **C4 blocks only exact-`O` duplicates.** A non-Janus wallet facing a sender who copies
  `O` in the same transaction is protected by the intra-transaction rule, not by C4.
- In practice the only realistic cross-transaction duplicate is one the Janus check
  already rejects (Lemma 2).
- The doc must attribute the property to "ctx binding + Janus + intra-transaction
  uniqueness", whatever D8 decides.
- **Classification:** documentation, P1.

### P3: The rule identity is not visible (F13-3)

- `consensus_fingerprint` covers constants only (`node/src/fingerprint.rs:8-10`).
- Dropping or re-keying C4 is a rule-code change with no constant, so two builds that
  differ on C4 have **equal fingerprints and fork** on the first block holding a
  cross-transaction duplicate.
- The build commit tells the builds apart, but operators compare fingerprints first.
- **Fix:** add a manifest entry `tx.rule.output_key_uniqueness = "within-tx"` (or
  `"pair"` / `"global"`), so that a rule-set change moves the fingerprint.
- Not consensus in itself. It changes the pinned fingerprint value
  (`node/tests/deploy_configs.rs:206`), which is expected at the v3 reset.

---

## 4. The 15-step consensus discipline, applied to keep, C and B

### Step 1: the problem
P1 above: a copyable public value is made a ledger-unique key, which gives every
observer a permanent veto over pending transactions.

### Step 2: the demonstrated failure

| Aspect | Evidence |
|---|---|
| Miner variant: T′ with T's key is mined, and T is invalid forever | [test: `revalidation.rs` extension test; `mempool_conflicts.rs` reorg and restart tests] |
| Copy costs exactly one standard fee, and the fee is irrelevant to winning | [test: `forge_with_output_key` uses `standard_fee(1,2)`; `…_whatever_the_fee`] |
| Stem relay variant | [src only: `net.rs:2147-2153` stem keys omit output keys; `on_stem_tx` passes T to the relay's `check_tx`; the relay can fluff T′ at once] |
| PX victim | [src: payouts and hidden outputs are in the prefix → `h_tx` changes → re-prove] |
| Repeated griefing | [src: `wallet.rs:1490-1500`; rebuild = same inputs, new outputs] |

**Phase 2 must add the missing demonstrations first (§5 item 1)**, as the roster
requires. Each must pass on today's code: it shows the attack succeeding. Each must then
be inverted by the fix.

### Step 3: prior art [web]

| Project | Rule on output keys | How the burning bug is handled | Relevance |
|---|---|---|---|
| **Monero (2018 – today, master)** | **None.** `check_tx_outputs` checks versions and types, and `check_outs_valid` checks `check_key` only. No duplicate check, within a transaction or on the ledger. | Wallet-only: first a warning (PR #4438), later "discard duplicate enotes unless they correspond to the greatest amount" (Cypher Stack audit §1.3.1). "The bug did not affect the protocol." | Parity with B, minus the intra-transaction rule. Monero never needed a ledger rule. |
| **research-lab #103 (kayabaNerve, koe)** | Discussed "enforce unique output keys … when saving to disk, paired with offset binding to prevent denial-of-service". Not adopted. | Proposes binding the shared key to a unique element (the first key image). | koe's caveat is exactly MP-7: a uniqueness rule needs a binding, or it becomes a DoS. |
| **Carrot (the FCMP++ addressing spec)** | §4.3: "all output pubkeys must be unique **within a transaction**." §4.4: the ledger model requires only unique key images. | `input_context = "R" ‖ first key image` or `"C" ‖ height`. §9.1.4: "for any Ko, it is computationally intractable to find two unique values of input_context such that an honest receiver will determine both enotes to be spendable." | **Option B is Carrot parity.** BlackSilk's ctx (all key images, or nullifiers, or height) is at least as strong. |
| **Cypher Stack audit of Carrot (22 Nov 2024)** | — | Endorses burning-bug resistance via input_context: "uniqueness then follows from consensus rules in the chain, so inspecting previous enote scanning history is not required." Seraphis instead required unique ephemeral keys. | An external review of the same approach (for Carrot, **not for Janus-BlackSilk**). |
| **Zcash (Faerie Gold → Orchard; ZIP 227 issuance)** | No note-commitment uniqueness rule. ρ is derived from the transaction's nullifiers. For ZSA issuance, zips#955 weighed "treat ρ as a nullifier" (a ledger rule) against deriving it from the txid; the final ZIP 227 derives ρ from the first nullifier `nf₀,₀`. | Uniqueness by construction, not by a ledger index of copyable values. | The same design lesson, independently. |
| **Bitcoin BIP 30 / BIP 34** | BIP 30 forbids duplicate txids of unspent outputs. BIP 34 made them unique by construction (the height in the coinbase). | — | [assumed; not re-fetched] General lesson: prefer uniqueness by construction. |

### Step 4: alternatives

| | **Keep (A)** | **C: unique `(O, Cm)` + SX1 corrections** | **B: drop cross-transaction C4; keep intra-transaction uniqueness** | D: keep + policy |
|---|---|---|---|---|
| Hidden-output griefing (transfers, deploys, PX change) | free, deterministic for stem relays and miners | impossible (the copy needs `y`, because balance plus the BP+ proof of knowledge force it) [math, SX1] | impossible (no rule to trip) | reduced; miners still win |
| Clear-payout griefing (PX withdrawals) | free | **costs `a` + fee.** It is also possible **by a miner through its own coinbase output**, since a coinbase output's `Cm = G + a·H` is exactly the payout's pair (F13-5). `a` is burnt: the recipient's wallet Janus-rejects the copy. | impossible | reduced |
| Burning-bug backstop for **non-Janus** wallets | exact-`O` duplicates across transactions | exact-pair duplicates only; a different-amount copy by the sender still burns | none across transactions (Janus required, as it already is for Janus-attack safety) | same as keep |
| Burning-bug safety for **conforming** wallets | Lemma 2 | Lemma 2 | Lemma 2 | Lemma 2 |
| Consensus state | 32 B+ per output, forever, in RAM | same (pair hash) | removed | same |
| Code touched | — | re-key 4 sets and the mempool namespace; a new pair type in the `ChainView` trait | delete the set, the trait method and the namespace; generalize the intra-transaction check | P2P and wallet |
| Consensus change | none | CONS (a relaxation) | CONS (a relaxation) | policy |

**Variants considered and rejected:**
- **Key uniqueness on `(O, R)` or on `(O, enc_anchor)`:** both are copyable. No gain.
- **Uniqueness on `(O, ctx)`:** ctx is unique per transaction, so this is exactly B.
- **Hidden payouts with secret masks, to complete C:** PX transactions without v1 inputs
  have no pseudo-output to balance a secret mask. That needs a format and kernel redesign.
  Rejected.
- **A ZK proof binding `O` to the inputs:** XL difficulty and new cryptography (R6).
  Rejected.

### Step 5: affected components

| Component | Keep | C | B |
|---|---|---|---|
| `tx/src/validate.rs`: `check_uniqueness_of`, the coinbase path 1029–1036, the block loop 1040–1050, the `TxError` / `BlockError` variants and the `is_stateless` table, `revalidate_after_extension` | — | re-key to the pair; keep a separate intra-transaction set on `O` | remove the cross-transaction check; add one stateless `check_output_keys_distinct(tx.output_keys())` for every kind (subsumes `PxDuplicateOutputKey`; sorted kinds already satisfy it) |
| `tx/src/validate.rs:57`, the `ChainView` trait | — | `has_output(O, Cm)` | remove `has_one_time_key` |
| `tx/src/state.rs:45,207-209,239` | — | pair set; undo by pair | remove the set |
| `tx/src/px.rs:684-694` | — | comment: the rule becomes load-bearing | the same, or moved into the generic check |
| `chain/src/mempool.rs:84,126-130` and unit tests | — | `OutputKey` → pair key | remove the `OutputKey` namespace (keeping it would re-create delay-griefing as policy) |
| `p2p/src/net.rs` `stem_keys` | — | no change (MP-9 becomes moot) | no change |
| Wallet | optional immediate rebuild | key-image dedupe (SX1 corr. 4) | key-image dedupe (defence in depth); **no** decoy filtering (F13-7) |
| Tests implementing `ChainView` | — | `adversarial.rs`, `validation_order.rs`, `revalidate_after_extension.rs` | the same, plus `transfers.rs:142-147` and `chain_integration.rs:144` (the `has_one_time_key` asserts) |
| Docs | P2 fix | transactions.md §3.1, §8.2, B4, B7, §13, Δ5; blocks.md §7; px.md:604; p2p.md:505-510 | the same |
| Fingerprint | — | rule-revision entry | rule-revision entry |
| PX kernel, proof, `CIRCUIT_ID`, encodings, key derivations | none | none | none |

### Step 6: activation behaviour

- The testnet has not launched, and a reset is authorized. The change goes into the
  **v3 base rule set, unconditionally from genesis**.
- It needs no new `Epoch` field. `TxRules` (`params.rs:99-107`) holds only
  network/branch/fee/weight, and adding a per-epoch flag would be complexity for a rule
  that never had a public life.
- **If it were done after launch:**
  - B and C are both **relaxations**: blocks that were invalid become valid. Old nodes
    would reject new blocks, so this is a hard fork and needs an activation height
    through `Schedule`.
  - The mempool would flush at the boundary (`enter_rules`), which is harmless here.

### Step 7: compatibility

- **Encodings, ids and signatures:** no transaction or block encoding changes. The tx
  id, the signature message and `h_tx` are unchanged, so all existing tx vectors stay
  valid.
- **Block validity:** only blocks holding a cross-transaction duplicate change verdict,
  from invalid to valid. None exist on any live chain, so the change is replay-safe for
  labnet data.
- **Kernel id and PX proofs:** unaffected.
- **Fingerprint:** unchanged unless P3 is done, and P3 should be done.
- **Third-party wallets:** under B or C they **must** run §3.3 step 5 (Janus). That is
  already normative (§12.5), because without it they are open to the Janus linking
  attack anyway.

### Step 8: reorg implications

- **Keep:** a reorg can permanently invalidate a mined T, if T′ is on the winning branch
  [test: `reorganizations_never_leave_conflicting_transactions_pooled`].
- **B:**
  - T and T′ are valid on both branches, and a returned T re-enters the pool.
  - `undo_block` no longer maintains an `O` set. R1 V12's "C4 makes set removal safe"
    becomes moot.
- **C:**
  - Undo must remove by pair. That is safe only because pairs are unique; SX1 correction
    3 notes that undo by `O` alone would be wrong once duplicates exist.
  - `revalidate_after_extension` must check pairs.

### Step 9: wallet implications

- **Scanning:** under B, Lemma 2 means the wallet credits only the honest output.
  - A copy lands in `ScanReport::rejected` (`JanusAnchorMismatch`, or
    `CommitmentMismatch` when only `O` is copied), is never shown, and triggers no
    action (§12.5).
- **Balance (defence in depth):** credit at most one output per key image. Keep the
  lowest global index, log the duplicate privately, and add a test.
- **Decoys (F13-7):** do **not** exclude duplicate-`O` outputs from decoy selection.
  - The wallet cannot tell which one is the copy. Excluding both would make the victim's
    genuine output a never-decoy, so its later spend would be identified.
  - Without filtering, a copy is simply a black-marble decoy known to the attacker. That
    is the same cost to the attacker, and the same leakage, as an attacker-owned output
    [math/argument].
- **Rebuilds:** under B, griefing rebuilds are no longer needed.
- **Under keep:**
  - the wallet should detect `DuplicateOneTimeKey` at submit or refresh and rebuild at
    once with fresh anchors, instead of waiting 20 blocks;
  - TX-5 hedging (`b7d0d3a`) makes rebuilt anchors fresh even under RNG failure
    [src: `builder.rs:199-224` binds payments; the attempt counter is unverified,
    **unknown**].
- **Wallet file format:** unaffected.

### Step 10: mining implications

- **B:** a template may contain T and T′ together; both are valid. Template selection
  loses nothing: key-image, nullifier and contract conflicts still apply.
- **Coinbase:** the miner's own outputs are unique by ctx(height). Under C, a miner can
  still grief payouts with a coinbase copy (F13-5).
- **Keep:** any miner has a free veto.
- **Weight and fees:** unaffected.

### Step 11: P2P implications

- **B:**
  - the pool admits T and T′ both, and both relay;
  - `Mempool::conflicts` no longer drops a copy before verification. A copy is a valid
    fee-paying transaction, so verifying it is ordinary relay cost, not a new DoS;
  - no ban or score change: `DuplicateOneTimeKey` disappears;
  - the Dandelion stem is unaffected.
- **C:** the stem relay can still front-run clear payouts (at cost `a`).
- **Keep:**
  - MP-9 (stem keys without output keys) is a second-order gap only;
  - policy option D cannot stop a relay that fluffs first.

### Step 12: golden vectors

Pin these as tx/block vectors for the v3 rule set:
- **(i)** a block holding two transactions whose outputs share `O` with different `Cm`:
  valid under B, valid under C, invalid under keep;
- **(ii)** the same with an identical `(O, Cm)`: valid under B, invalid under C;
- **(iii)** an intra-transaction duplicate, for each kind (PX output/payout; the transfer,
  deploy and coinbase sort rules): invalid under all options, stateless;
- **(iv)** a fingerprint vector with the new rule-revision entry.

These belong in the R14 conformance set (P3) when it exists. Until then, add them as
Rust tests in `tx/tests/`.

### Step 13: regression tests

See §5 item 3, including the inverted versions of every existing test that currently
proves C4.

### Step 14: full suite

The whole workspace, after the change, on Windows and Linux CI. Particularly `chain`
(mempool_conflicts, revalidation, fork_choice, storage_recovery), `tx` (all),
`p2p` network, `wallet`, and `node` deploy_configs (fingerprint pin).

### Step 15: adversarial review

Here is what I attacked under B, and what I found:

1. **Can a copy of `O` be spent to burn the owner's real output?**
   No. Spending needs `p` (CLSAG unforgeability) and the copy's mask. Only the `p`-holder
   can produce `I = p·Hp(O)`.
2. **Can the sender burn a recipient (exchange) by paying the same `O` twice?**
   - In one transaction: rejected by the stateless intra-transaction rule.
   - Across transactions: needs an Hs collision under Janus (Lemma 2).
   - Non-Janus third-party wallets are exposed. The same wallets are already exposed to
     Janus linking. Document it.
3. **Can duplicates corrupt consensus state?**
   - The output list is indexed by global index, so duplicates are distinct records.
   - Key images, nullifiers and the PX tree do not depend on `O` uniqueness.
   - The `one_time_keys` set disappears.
4. **Can duplicates hurt ring privacy?**
   - Only as black marbles (F13-7).
   - Observers can see that two outputs share `O`, and so that at most one of them is
     ever spendable. For a ring containing one of them, this is the same as the attacker
     knowing that its own output is a decoy.
5. **Can a copy be used to probe a subaddress (Janus)?**
   - A copy is not an honest construction for ctx′, so it is rejected (Theorem 1).
   - The copier learns nothing new: it does not know which address `O` pays.
6. **Coinbase:** the miner's ctx is its height, so no two honest coinbases collide, and
   copies of a coinbase `O` are black marbles.
7. **ctx uniqueness under mempool conditions:** double-spend variants share ctx, but only
   one can be mined (C2/PX2). Lemma 2 is a statement about the chain.
8. **Relaxation hazard:** is any rule's soundness argument silently built on C4?
   - `revalidate_after_extension` lists C4 among the rules to re-check. Under B it is
     removed, and the argument ("an extension can only change C2, C4, PX1–PX4, contract
     id") holds with fewer items.
   - `validate_block_transactions_cached`'s proof-cache argument does not use C4.
   - R1 V12's undo argument becomes moot.
   - I found no other dependency (grep of `has_one_time_key` and `DuplicateOneTimeKey`
     across the workspace) [src].

The same attacks under C, and what they add:
- the clear-payout grief by a transfer output or a coinbase output (F13-5);
- the undo and extension checks must be exactly pair-based (SX1 correction 3).

Under keep: the attack succeeds [test].

### Recommendation

**Option B.** Drop the cross-transaction (ledger and block) C4, and replace it with one
explicit stateless rule, **"output keys distinct within a transaction"**, over
`output_keys()` for every kind.

Also:
- key-image dedupe in the wallet;
- documentation corrected to Lemma 2;
- a rule-revision fingerprint entry;
- all of it riding the v3 genesis.

Reasons:
- **C is strictly dominated.** It keeps the state and the complexity. It leaves the main
  PX exit path (clear payouts) griefable, even by a miner through its coinbase. Its only
  extra backstop covers exact duplicates made by the original sender against wallets
  that skip a normative check.
- **B is exactly Carrot's model** (within-transaction uniqueness plus a bound derivation
  context). It matches Monero's ledger (which has no rule at all), and it follows the
  Zcash ZIP 227 choice of uniqueness by construction over a copyable ledger index.
- **B removes an attack surface and code** instead of adding any.
- **Keep is not acceptable for a privacy chain.** It gives every stem relay a
  one-fee, repeatable veto that the Dandelion embargo cannot repair, and each forced
  retry leaks origin information.

**The owner decides (D8).** Nothing in this dossier claims that B makes BlackSilk secure.
Lemma 2 is an internal ROM argument over BlackSilk's own Janus construction, which has
had no external review (transactions.md §12.8).

---

## 5. New findings

| ID | Severity | Status | Where | Scenario | Confidence |
|---|---|---|---|---|---|
| **F13-1** (= R6 MP-7, re-confirmed at `9e422d8`) | Medium–High | Not implemented (owner decision D8) | `tx/src/validate.rs:502-505,1029-1050`; `tx/src/state.rs:207-209`; `chain/src/mempool.rs:126-130`; `p2p/src/net.rs:2147-2153` | A stem relay or miner copies `O` from a pending T into T′ for one fee; T is invalid forever | High [test + src] |
| **F13-2** | Medium | Not implemented | `wallet/src/wallet.rs:1490-1500`; the C4 sites above | Griefing is repeatable against each rebuild (one fee each). Every forced rebroadcast of the same key images is another Dandelion++ stem sample of the same origin: censorship and a deanonymization amplifier. The wallet notices only after 20 blocks and does not rebuild | High (mechanism); Medium (privacy magnitude, unquantified) |
| **F13-3** | Low | Not implemented | `node/src/fingerprint.rs:8-10,35-47` | Any C4 change (B or C) is rule code, not a constant: mixed builds keep equal fingerprints and fork on the first cross-transaction duplicate | High |
| **F13-4** | Informational (correction to SX1 corr. 1 and R6) | Partially implemented | `tx/src/px.rs:684-694`; `validate.rs:334,936`; `px.rs:794` | Intra-transaction `O` uniqueness **already exists** as stateless rules (sort order; `PxDuplicateOutputKey` since `b33a1ce`, tested at `validation_order.rs:532-560`). Its comment says it "changes no verdict"; under B or C it becomes the sole guard and must be pinned by a test that does not rely on C4 | High |
| **F13-5** | Low–Medium (only if C is chosen) | — | `tx/src/px.rs:427-441` (payout `Cm = G + a·H`); the coinbase `Cm` form | Under C, a clear payout (the whole of a no-input PX withdrawal) is griefable for `a` + fee by a transfer output with mask 1, **or by a miner through its own coinbase output**, which already has the payout's exact commitment form. `a` is burnt (Janus rejects the copy). Refines SX1 corr. 2 | High [math] |
| **F13-6** | Low | Not implemented | `wallet/src/wallet.rs:1113-1119,1154-1166` | The wallet dedupes by global index only; two credited outputs sharing a key image would both count in `balance()`. Unreachable for conforming scans (Lemma 2), so this is defence in depth. SX1's "tolerates duplicates" is only half right | High |
| **F13-7** | Informational (design constraint) | — | `tx/src/decoy.rs` (future change) | Under B, filtering duplicate-`O` outputs out of decoy selection would make the victim's genuine output a never-decoy and identify its spend. Do not filter | Medium–High [argument] |
| **F13-8** | Low (docs overclaim) | Not implemented | `docs/transactions.md:183-184,543-544,1063,1097`; `docs/blocks.md:193-200`; R2 §3.1 | The docs credit C4 with making the burning bug impossible "even for broken wallets". C4 only blocks exact-`O` duplicates across transactions; the property rests on ctx + Janus + the intra-transaction rules. Monero never had a rule (the R2 comparison implies otherwise) | High |

---

## 6. Implementation plan for phase 2

The order is: attack tests first, then the owner decision, then the change.

### 1. Attack demonstrations (tests only; pass today, inverted later)
- **Priority:** P0 (the roster requires it).
- **Consensus impact:** nothing externally visible.
- **Identity impact:** none.
- **Files:** new `chain/tests/c4_frontrunning.rs`, reusing the helpers of
  `revalidation.rs` and `mempool_conflicts.rs` (it could share a
  `chain/tests/common/forge.rs` module).
- **Tests:**
  - `stem_relay_copy_wins_every_pool_and_the_victim_never_confirms`: two managers. The
    "relay" manager receives T through `check_tx` only (the stem path); the test forges
    T′ from T's `O` and submits T′ to the other pools first; T hits `Conflict`; T′ is
    mined; T fails `DuplicateOneTimeKey` for 100 more blocks.
  - `griefing_repeats_against_every_rebuild`: 3 rebuilds, 3 copies, 3 fees; the victim
    never confirms.
  - `a_copy_with_a_different_commitment_is_janus_rejected_by_the_recipient`: scan both,
    and only the original is `owned` (it also documents Lemma 2).
  - Optional P2P end to end in a new file `p2p/tests/frontrun.rs`. It needs a read-only
    test accessor for a stempool transaction (a one-line change in `p2p/src/net.rs`),
    which must be coordinated with 31/33/34.
  - Optional PX: `px_withdrawal_payout_copy` with the `px_deposit` or withdraw harness
    (heavy: one real proof).
- **Difficulty:** M.

### 2. Consensus change B (after D8)
- **Priority:** P0 (before the v3 freeze).
- **Consensus impact:** CONSENSUS (v3 base rule set; a relaxation). Identity: rides v3,
  no new network id beyond the planned reset.
- **Files:**
  - `tx/src/validate.rs`:
    - remove the cross-transaction C4 in `check_uniqueness_of` and in the block loop,
      and `CoinbaseDuplicateOneTimeKey`;
    - add a stateless `check_output_keys_distinct` for every kind (`TxError::DuplicateOutputKey`,
      stateless), or keep `PxDuplicateOutputKey` and rely on sorting for the others;
    - update the `is_stateless` table and the `revalidate_after_extension` docs;
    - remove `ChainView::has_one_time_key`.
  - `tx/src/state.rs`: remove `one_time_keys`.
  - `tx/src/px.rs`: the comment at 684–688.
  - `chain/src/mempool.rs`: remove `ConflictKind::OutputKey` and its unit tests
    (850–1000).
  - The test `ChainView` implementers: `tx/tests/adversarial.rs`,
    `tx/tests/validation_order.rs`, `tx/tests/revalidate_after_extension.rs`,
    `tx/tests/transfers.rs`, `tx/tests/chain_integration.rs`.
  - `chain/tests/mempool_conflicts.rs`: rewrite. Its premise (the F1 stall) no longer
    exists; keep the key-image and nullifier conflict cases.
  - `chain/tests/revalidation.rs`: invert the extension test and keep its reorg cases.
- **Tests:**
  - unit: the distinct-keys rule for every kind;
  - property (proptest): a random block with arbitrary cross-transaction `O` collisions
    is valid iff there is no intra-transaction collision; the model against
    `validate_block_transactions`;
  - adversarial: the §5 item 1 tests inverted (T and T′ both confirm);
  - regression: a reorg with T on A and T′ on B keeps both valid; restart replay of a
    chain with duplicates;
  - golden vectors (i)–(iii) of step 12.
- **Benchmarks:** none. B removes a hash-set lookup per output and the set's RAM.
- **Docs:** see item 5.
- **Difficulty:** M.

### 3. Wallet defence in depth
- **Priority:** P1.
- **Consensus impact:** none.
- **Files:** `wallet/src/wallet.rs` (`apply_block`: credit at most one output per key
  image; a private log), plus a test in the wallet tests.
- **Tests:**
  - `two_chain_outputs_with_the_same_key_are_credited_once`, where the second is
    synthetic and bypasses Janus;
  - a balance test.
- **Also required:** a statement in `docs/transactions.md` §12.5 that decoy selection must
  **not** filter duplicates (F13-7).
- **Difficulty:** S.

### 4. Rule-revision entry in the fingerprint
- **Priority:** P1.
- **Consensus impact:** none (identification), but it changes the pinned value, together
  with v3.
- **Files:** `node/src/fingerprint.rs`, and the pins in `node/tests/deploy_configs.rs`.
- **Test:** the fingerprint pin.
- **Difficulty:** S.

### 5. Documentation
- **Priority:** P0 for the D8 record; P1 otherwise.
- **Files:**
  - `docs/transactions.md`: §3.1, §8.2 (C4 → "O distinct within a transaction", with
    Lemma 2 and its assumptions), B4, B7, §13 (1063), Δ5 (1097), and a §12.5 addition
    on third-party wallets and decoys;
  - `docs/blocks.md` §7;
  - `docs/px.md:604`;
  - `docs/p2p.md:505-510`;
  - the D8 row in `full-review-2026-09-27.md` (via the coordinator).
- **Difficulty:** S.

### 6. If the owner chooses keep (fallback)
- **Priority:** P1.
- **Consensus impact:** policy only.
- **Changes:**
  - the wallet detects `DuplicateOneTimeKey` at submit or refresh and rebuilds at once
    with fresh anchors (`wallet/src/wallet.rs`);
  - the stem pool adds output keys to `stem_keys` (MP-9; `p2p/src/net.rs`);
  - document F13-1 and F13-2 as accepted limitations, including the privacy
    amplification.
- **Difficulty:** S–M.

### 7. If the owner chooses C
Item 2 becomes:
- re-key the four sites to the pair, and keep an explicit intra-transaction set on `O`;
- `ChainView::has_output(O, Cm)`;
- undo by pair;
- the mempool pair namespace.

Additional tests:
- a clear-payout copy by a transfer output and by a coinbase output (F13-5), accepted
  only with `a` funded;
- an identical-pair copy rejected.

**Difficulty:** M–L.

---

## 7. Dependencies and conflicts (roster numbers)

- **11 tx-validation and 10 block-validation-pipeline:** both edit `tx/src/validate.rs`
  (error classification, validation order, the block loop). Sequence item 2 with them,
  or give 13 the uniqueness functions and the `TxError` rows only.
- **12 mempool-architecture:** `chain/src/mempool.rs` (the `OutputKey` namespace
  removal). Its bounded-revalidation design must drop C4 from the extension rule list.
- **17 stealth-janus:** Lemma 2 depends on the Janus argument and ctx uniqueness. 17
  should co-sign the written lemma and the §12.5 wording.
- **33 dandelion-network-privacy:** F13-2 (repeated broadcasts); the optional P2P test
  and the stempool accessor in `p2p/src/net.rs`.
- **38 wallet-privacy:** F13-7 (no decoy filtering); the key-image dedupe touches the
  same `apply_block` code as 39 wallet-sync-scanning.
- **46 architecture:** the `ChainView` trait change and the effects model (it removes
  one effect: "insert O").
- **01 consensus-core:** the rule inventory (C4's row changes); 47 docs; 40 testnet
  genesis (fingerprint pin and v3 freeze order).
- **50 red-team:** should attack the final B diff, especially the claim that no rule
  depends on C4.
- **14 fee-economics:** none directly. B makes fee level irrelevant to this attack.

---

## 8. Open questions for the coordinator

1. **D8 owner decision:** B (recommended), C or keep. If B: may the error variant be
   renamed (`DuplicateOutputKey`, stateless, all kinds), or should `PxDuplicateOutputKey`
   stay and the sorted kinds rely on their sort rules?
2. **Is third-party (non-Janus) wallet compatibility a goal?** If yes, the owner should
   know that neither B nor C protects such wallets against a sender's different-amount
   copy. Only Janus does.
3. **May item 1's optional P2P test add a test-only stempool accessor to `p2p/src/net.rs`**,
   or should the stem-relay demonstration stay at the chain level?
4. **Should the fingerprint gain a general "rule revision" list** (one entry per
   non-constant rule change: C4, the deploy rules, PX-F5 …) rather than a C4-only entry?
   That is 01/40's call.
5. **Should F13-2's privacy amplification be quantified** (a Dandelion++ simulation with
   k forced rebroadcasts), under 33?

---

## 9. Sources

- Monero, "A Post-Mortem of the Burning Bug" (2018-09-25):
  https://web.getmonero.org/2018/09/25/a-post-mortum-of-the-burning-bug.html [web]
- Monero research-lab issue #103, "Remove the burning bug as a class of attack with a
  modified shared key definition" (kayabaNerve, koe):
  https://github.com/monero-project/research-lab/issues/103 [web]
- Monero source (master, fetched 2026-09-27):
  - `Blockchain::check_tx_outputs`:
    https://github.com/monero-project/monero/blob/master/src/cryptonote_core/blockchain.cpp
  - `check_outs_valid`:
    https://github.com/monero-project/monero/blob/master/src/cryptonote_basic/cryptonote_format_utils.cpp
  - [web; no duplicate-output-key rule found]
- Monero PR #4438 (wallet burning-bug warning), as cited by the post-mortem:
  https://github.com/monero-project/monero/pull/4438 [not fetched directly]
- jeffro256, Carrot specification:
  - §4.3 Transaction Model, §4.4 Ledger Model, §7.2 Input Context, §9.1.4 Burning Bug
    Resistance;
  - https://github.com/jeffro256/carrot/blob/master/carrot.md [web]
- F. Slaughter, B. Goodell, R. Salazar (Cypher Stack), "An Audit of the FCMP++
  Addressing Protocol: CARROT", 22 Nov 2024, §1.3.1 and §3.1.4:
  https://moneroresearch.info/index.php?action=attachments_ATTACHMENTS_CORE&method=downloadAttachment&id=235&resourceId=242&filename=bbec3ae84b7fd65f1594068e102eaa83dfd58b4a
  [web, PDF read locally]
- tevador, Jamtis specification (input-context binding; Seraphis unique-output rule):
  https://gist.github.com/tevador/50160d160d24cfc6c52ae02eb3d17024 [pointer; not read
  in full]
- Zcash:
  - ZIP 227 (issued-note ρ from `nf₀,₀`): https://zips.z.cash/zip-0227 [web]
  - zips issue #955 (ρ uniqueness: a ledger rule vs derivation; road-blocking):
    https://github.com/zcash/zips/issues/955 [web]
  - zcash issue #98 (Faerie Gold mitigation): https://github.com/zcash/zcash/issues/98
    [pointer]
  - ECC, "Fixing Vulnerabilities in the Zcash Protocol":
    https://electriccoin.co/blog/fixing-zcash-vulns/ [pointer]
- Bitcoin:
  - BIP 30: https://github.com/bitcoin/bips/blob/master/bip-0030.mediawiki
  - BIP 34: https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki
  - [assumed from prior knowledge; not re-fetched]
- G. Fanti et al., "Dandelion++: Lightweight Cryptocurrency Networking with Formal
  Anonymity Guarantees", 2018: https://arxiv.org/abs/1805.11060 [pointer; the
  repeated-broadcast point is my inference, not a result quoted from the paper]
- Internal:
  - R6 (§2.4 MP-7), SX1 (§1 rows, §2), R2 §3.1, R1 V12;
  - `docs/transactions.md` §3, §8.2, §12, §13;
  - `docs/blocks.md` §7.
