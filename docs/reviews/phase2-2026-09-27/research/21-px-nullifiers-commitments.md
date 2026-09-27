# 21 px-nullifiers-commitments: research dossier (phase 2, phase 1)

Agent 21. Internal engineering work, **not an audit**. Read-only on the repository, with no builds or
tests run. Nothing here claims that PX or BlackSilk is secure, and zero knowledge is claimed only as
statistical and conditional.

Commit read: **`9e422d8`** (`rebuild/core`, "Merge v3/candidate into rebuild/core").

---

## 1. Scope and what I read

**Scope (roster 21):**
- nullifier and `rho` derivation;
- the commitment tree (depth 32);
- anchors (`ROOT_WINDOW`);
- the PX state in `tx/src/state.rs`;
- R3-7.

The roster questions: Faerie-Gold-style attacks, who can compute a nullifier, the anchor window
against reorgs, tree-full behaviour, and a comparison with Orchard and Sapling.

**Code read in full:**
- `px-core/src/record.rs` (117 lines), `px-core/src/hash.rs` (275), `px-core/src/kernel.rs` (513);
- `px/src/state.rs` (158), `px/src/tree.rs` (216);
- `tx/src/state.rs` (427);
- `px/src/wallet.rs` (keys, `dummy_input`, `hedge_witness`, `witness_statement`: lines 1–130 and
  355–700);
- `wallet/src/px.rs` (lines 1–700: anchor policy, scanning, rewind, commitment sync, selection).

**Code read in part:**
- `tx/src/validate.rs`: error classes 130–285, PX state and proof 510–690, revalidation 690–813,
  block validation 881–1131;
- `tx/src/px.rs`: `read_digest` 110–119, binding and `public()` 370–450, structure checks 660–720;
- `tx/src/px_builder.rs` 140–290 (hedging, output `rho`);
- `chain/src/manager.rs` 880–990 (the reorg loop);
- the mempool and stem conflict keys (`chain/src/mempool.rs:105-121`, `p2p/src/net.rs:2146-2150`);
- `zkvm/src/air/memory.rs:62-79` (how output words are bound);
- `px/src/fingerprint.rs:240-270`.

**Tests read:**
- `px/tests/state.rs` (all);
- `px/src/tree.rs` tests;
- `px/tests/kernel.rs` 150–320 (`every_check_rejects_its_violation`, `only_the_owner_can_spend`,
  `nullifiers_are_unique_and_key_dependent`);
- `tx/tests/px_consensus.rs` 170–430 (`private_payments_through_consensus`,
  `value_cannot_be_created_and_anchors_must_be_recent`);
- `tx/src/state.rs` tests;
- the test lists of `chain/tests/{fork_choice,manager}.rs`, `px/tests/{unified,proof}.rs`,
  `tx/tests/adversarial.rs`, and the `wallet/src/px.rs` anchor tests.

**Docs and reports read:**
- the brief;
- the roster (entries 11, 19, 20, 22, 26, 28, 37–42);
- `docs/reviews/full-review-2026-09-27.md` (§1, §3.1–3.6, §3.11, and every register row on nullifiers,
  anchors, the tree and R3-7);
- `docs/reviews/autonomous-session-2026-09-27.md` (all);
- R5-px (all);
- the R3-7 section of R3-privacy;
- SX1 (R2-C6, R5-4, I2-F1 rows) and SX2 (R3-7 correction);
- `docs/px.md` §1–§5, §9–§13;
- `docs/reviews/px-f4-f5-analysis.md` (option B/C rows).

**Neighbouring dossiers checked for overlap:** `11-tx-validation.md` (§3.3 TreeFull, F11-2) and
`02-fork-choice-reorgs.md` (W-6, the deep PX reorg).

**Primary sources:** see §8. They are the Zcash protocol specification (NU6.2), the Orchard book
(nullifiers, commitment tree), ZIP 315, ZIP 227 issue #955, the Zerocash paper and ECC's Faerie Gold
disclosure, the design-of-Sapling book, and the keyed-sponge PRF literature.

---

## 2. Current state

Evidence classes: **[math]** mathematically established, **[test: name]**, **[src]** source-read,
**[assumed]**, **[unknown]**.

### 2.1 Constructions (as implemented)

```text
nk  = Hk(NK, sk)            ak = Hk(AK, sk)            owner = Hk(OWNER, ak ‖ nk ‖ d)
cm  = Hk(RECORD, owner ‖ contract ‖ asset ‖ value[4×16b] ‖ data ‖ rho ‖ rcm)
nf  = Hk(NULLIFIER, nk ‖ rho ‖ cm)                        user record
nf  = Hk(NULLIFIER_CONTRACT, contract ‖ rcm ‖ cm)         contract record
rho'_j = Hk(RHO, nf_0 ‖ j)                                output j (kernel-derived, never a witness)
node(l, r) = P(l ‖ r)[0..8]; depth 32; empty leaf 0; anchors = block-end roots of the last 100 blocks
```

Sources: `px-core/src/record.rs:98-117` and `kernel.rs:277-363` [src].

### 2.2 What is correct, and why

1. **Faerie Gold resistance** [math, conditional on Hk collision resistance].
   - Output `rho` is computed in the kernel from `nf_0` (`kernel.rs:353`); the prover cannot supply
     it.
   - `nf_0` is inserted into the nullifier set, dummies included (`px/src/state.rs:125-130`,
     `tx/src/validate.rs:523-527`), so no `nf_0` repeats on a valid chain. The slot index `j`
     separates the two outputs.
   - So every leaf ever appended has a distinct `rho`, and because `cm` commits to `rho`, **no two
     tree leaves are equal**.
   - Nullifiers do not include the position (unlike Sapling, which mixes `pos` into ρ). This is the
     Orchard design choice, and it is sound **only because** of that no-duplicate-leaf invariant.
   - This is the same argument as Orchard's `ρ = nf_old`, and as Zerocash's fix (ρ derived from
     `h_Sig`, itself derived from the unique input serial numbers) [ECC 2019; Zerocash §;
     Orchard book].

2. **Balance and uniqueness of the nullifier per record** [math].
   - For a fixed `cm`, a different user nullifier would need a different `nk`. Since
     `owner = Hk(OWNER, ak ‖ nk ‖ d)` is inside `cm`, that needs a second `(sk', d')` with the same
     owner: an Hk collision or second preimage.
   - `nk` is derived **in the kernel** from `sk`, never taken as a free witness.
   - A contract nullifier's inputs (`contract`, `rcm`) are both inside `cm`.
   - Record kind is bound by `cm`: `owner` is forced to 0 for contract inputs (`kernel.rs:280`), and
     `contract ≠ 0` selects the form.

3. **Roadblock resistance** [math, conditional].
   - To insert a victim's nullifier into the set, an attacker must produce it from a valid input.
   - A user or dummy input produces `Hk(NULLIFIER, Hk(NK, sk) ‖ …)` with the attacker's own `sk`.
     Hitting a victim's value needs the victim's `sk` (a preimage of NK) or an Hk collision.
   - A contract input produces a value in another domain.
   - This holds even against a `RangeViewKey` holder, who knows `nk` but cannot obtain an `sk` that
     derives it.
   - Compare ZIP 227 #955, where an attacker-choosable ρ in issuance enabled exactly this attack.

4. **Nullifier privacy** [assumed: Hk is a PRF keyed by `nk`; keyed-sponge bounds, Andreeva et al.
   FSE 2015].
   - User nullifiers are computable only with `nk`: by the owner and by `RangeViewKey` holders
     (documented in `docs/px.md` §3.1).
   - They are **not** computable by the sender, by `IncomingViewKey` holders, by nodes or by
     observers.
   - They are hash-based, with no discrete-log component, so unlinkability is not lost to a
     DL-breaking adversary. This differs from Orchard, whose nullifier uses a Pallas scalar
     multiplication [Orchard book].

5. **The anchor rule is consistent between validation and apply** [src].
   - Validation checks against the state after the parent block (`validate.rs:520`), and apply
     checks the same window before pushing the block's own root (`state.rs:122`).
   - Anchors never refer to a state inside the current block, which is the same rule as Orchard
     ("block boundaries").
   - Tested: [test: `anchors_must_be_recent_block_roots`,
     `value_cannot_be_created_and_anchors_must_be_recent`].

6. **Atomic apply and exact undo of nullifiers** [src], [test: `blocks_apply_and_undo_exactly`,
   `double_spends_are_rejected_and_leave_no_trace`].
   - Undo removes only the nullifiers this block inserted (the push happens after a successful
     insert), so a failed insert never removes a pre-existing nullifier.

7. **Double spends are caught at every level** [test: `double_spends_are_rejected_and_leave_no_trace`,
   `private_payments_through_consensus`, `every_check_rejects_its_violation` "duplicate"]:
   - within a transfer: the kernel's `DuplicateNullifier`, and the stateless `PxNullifierRepeated`;
   - within a block: the `block_nullifiers` set;
   - across the chain: the state;
   - in the mempool and stempool: nullifiers are conflict keys (`mempool.rs:121`, `net.rs:2150`)
     [src].

8. **Nullifier words are canonical** [src].
   - `read_digest` rejects words ≥ p (`tx/src/px.rs:110-119`).
   - Independently, output words are byte-decomposed in the zkVM output table
     (`zkvm/src/air/memory.rs:62-79`). So `x` and `x + p` are different claimed outputs and PX5 would
     fail. Two layers stop a "same nullifier, two encodings" double spend.
   - No test pins the decode layer (F21-6).

9. **The wallet re-derives `rho`** from the on-chain `nf_0` and slot, and accepts a record only if
   it recomputes `cm` (`wallet/src/px.rs:442-448`, `delivery::open`) [src]. A sender cannot give a
   recipient a record whose `rho` differs from the kernel's.

10. **Dummies.** Every dummy field comes from a hedged stream bound to the whole statement
    (`px/src/wallet.rs:663-699`) [src]. Dummy nullifiers are therefore unpredictable and
    indistinguishable from real ones under the PRF assumption.

11. **Mempool.** Anchor expiry evicts pooled PX transactions on extension, through
    `revalidate_after_extension` → `check_px_state` [src].

12. **Fingerprint.** `ROOT_WINDOW` and `CAPACITY` are in the consensus fingerprint
    (`px/src/fingerprint.rs:266-268`) [src].

### 2.3 What the tests do **not** prove

- No test that two outputs with identical `(owner, value, data, rcm)` get distinct `cm` and `nf` (a
  Faerie Gold regression).
- No test that `undo` restores the **root window**. The `Snapshot` in `px/tests/state.rs:25-39`
  compares only root, size, pool and spent flags. For example: apply 100 blocks until an anchor
  expires, then undo one block, and the anchor must be valid again.
- No reorg test in which a pooled or relayed PX transaction's anchor exists only on the orphaned
  branch.
- No test at or near tree capacity, and no `Frontier` test beyond size 300. The module doc at
  `tree.rs:10-11` claims coverage of "sparse sizes near powers of two"; only 255/256 are covered.
- No decode test for a non-canonical nullifier or anchor word.
- No test of cross-kind nullifier separation (it holds by domain constants alone, [test:
  `domains_are_distinct_and_canonical`]).

---

## 3. Problems in scope

### 3.1 Faerie Gold and the "no duplicate leaf" invariant (roster Q1)

**What the problem is.** Faerie Gold [ECC 2019; Zcash spec] means an attacker gives a victim several
notes that all look spendable, but only one can be spent, because they share a nullifier.

**Status in BlackSilk:**
- Prevented today (§2.2 item 1).
- The invariant it rests on, *no two leaves are equal*, is **not enforced by consensus**. It follows
  from the derivation.
- Zcash went through three generations of this:
  - Sprout: ρ derived from `h_Sig`;
  - Sapling: ρ mixed with the position;
  - Orchard: ρ = `nf_old`.
- It **re-broke** in 2024: ZIP 227 issuance let ρ be chosen, and issue #955 fixed it by deriving ρ
  from the txid and index.

**Future paths that must preserve the invariant (P3 design constraints; none exists today):**
- shielded coinbase (R3-13, with "ρ from the height");
- asset issuance (multi-asset, R5 §4);
- shape classes (N_OUT > 2);
- aggregation or recursion;
- any bridge that creates records outside the kernel.

**Consequences.** If broken: burnable funds (liveness and value loss for the recipient). There is no
inflation. It is consensus-critical in design.

**Invariants (never change):**
- `rho` is kernel-derived from a chain-unique value;
- `nf` covers `cm`;
- every record-creating path uses **its own** Hk domain, or the RHO domain with a chain-unique
  prefix.

A height-derived coinbase `rho` must use a new domain (e.g. `RHO_COINBASE`). It must never be
`Hk(RHO, ·)` with a caller-influenced input.

**Alternatives:**
- Add a consensus uniqueness set over commitments (the PX analogue of C4). This is defence in depth,
  but costs about 40 B RAM per leaf and a consensus rule. Zcash does not do it. **Not recommended**:
  the derivation argument is simple and testable.

**Tests:** a Faerie Gold regression (identical output witnesses in two transactions, and in both
slots of one transaction, give distinct `cm` and `nf`), plus a property test that `output_rho` is
injective over `(nf_0, j)` across random `nf_0`.

### 3.2 Nullifier privacy: who can compute a nullifier? (roster Q2, R3-7)

| Party | User record `nf` | Contract record `nf` |
|---|---|---|
| Owner (`sk`) | yes | n/a |
| `RangeViewKey` (`ak, nk, dk_k, ivk_k`) | yes (documented) | only if it holds the opening |
| `IncomingViewKey` | no | only if it holds the opening |
| Sender / creator | **no** (lacks `nk`) | **yes** (it chose `rcm`) |
| Ciphertext addressee, share recipients | no | **yes** |
| Anyone, if the contract derives `rcm` from public data (PX-F4 option B) | — | **yes** |
| DL-breaking or quantum adversary | no (hash-based) [assumed PRF] | only as above |

**A point missing from R3-7 and SX2.** `rho` is publicly computable for every record: it is
`Hk(RHO, nf_0 ‖ j)` of public values.
- So the whole secrecy of a contract nullifier rests on **`rcm` alone**. `contract` is public
  whenever a function of that contract is called.
- This makes the public-`rcm` corollary stronger than stated. Under B (or R5-15 B′ with a public
  seed), every observer can link a contract record's creation to its spend. Under B′,
  `rcm = Hk(RCM, seed ‖ rho'_j)`, and the `rho'_j` term adds **no** secrecy.

**Root cause.** A contract record has no key: spend authority is "opening plus function approval".
Anyone who could spend it must know the opening, and so can compute its nullifier. This cannot be
removed without a keyed record kind.

**The structural fix: R5-10 user-owned contract records.** Their nullifier is `nk`-keyed, so the
issuer does not see the spend. This mirrors Zcash, where the sender knows the note but not `nk`.

**Status.** SX2 is right that the base fact is documented (`docs/px.md` §13.2, "Spends are seen by
every holder"). **Accepted limitation** for the trial. Docs P2: add the public-`rho`/`rcm` point to
§13.2 and to px-f4-f5-analysis row B.

**Privacy-critical:** yes. Consensus: no (docs now; kernel generation later).

### 3.3 Anchor window against reorgs (roster Q3)

**Facts:**
- The consensus window is 100 block-end roots [src; test].
- The wallet anchors at `synced − synced mod 16` (`wallet/src/px.rs:85-88`). So the anchor lies
  0–15 blocks below the wallet's tip, and **is the tip itself once in every 16 heights**.
- A record is spendable once `record.height ≤ anchor` (`wallet/src/px.rs:614-616`). So a record can
  be spent with **one confirmation** when its block height is a multiple of 16 and is the tip.

**The failure.** Take a transaction anchored at height a and a reorg forking below a.
- The anchor root survives on the new branch only if the new branch's commitment sequence up to a is
  identical, which is unlikely if any PX transaction moved.
- Otherwise the transaction becomes `PxUnknownAnchor` on the new branch. That is contextual, so no
  one is penalized. The wallet must rebuild, and the rebuild **republishes the same nullifiers**
  (R5-12), linking both attempts. It also costs about 45 s of proving.
- If a spent input record was itself created in an orphaned block, its position may change.
- ZIP 315 recommends the anchor at `H − 3` (trusted confirmations), stating that this "prevents chain
  rollbacks from invalidating anchors and revealing nullifiers". It also recommends 10
  confirmations for untrusted notes.

**Consequences.** This is liveness plus a privacy linkage, **not** a safety issue: the state undo is
exact. A seven-device trial with scripted partitions (labnet partitions every 25 minutes) will
produce such reorgs.

**The fix (wallet policy, not consensus):**
- `anchor_height(synced) = s − s mod 16` with `s = synced.saturating_sub(ANCHOR_MIN_DEPTH)`.
- Use `ANCHOR_MIN_DEPTH = 3` (the ZIP 315 trusted depth), optionally with a separate spendability
  depth of 10 for received (untrusted) records.

**Trade-offs:**
- Spendability is delayed by up to 16 + 3 blocks (about 38 min at 120 s).
- The minimum transaction lifetime drops from 85 to 82 blocks: still ample.
- **Every wallet must switch together.** The anchor depth is a fingerprint (R5 §3.4), so ship it as
  one policy version before the trial, not mid-trial.

**Consensus alternative.** Make "anchor height ≡ 0 mod 16" a consensus rule (R5 §3.4). Defer it with
R5-3 (the clock). It needs an anchor-to-height map, because empty-PX blocks repeat roots.

**Undo of the window** is exact (the `Undo` clones the deque) [src], but untested (§2.3).

**Tests:**
- state level: undo re-validates an expired anchor;
- chain level, without proofs: a synthetic PX transaction whose anchor exists only on branch A.
  `revalidate_after_extension` returns `Ok` on A and `PxUnknownAnchor` on B after a manager reorg,
  and `Ok` again after reorging back. This needs no prover: `check_px_state` precedes PX5, and a
  `PxTx` with no v1 inputs, `fee = PX_STANDARD_FEE` and `bridge_out = fee` passes
  `check_px_balance`;
- wallet: `anchor_height` never exceeds `synced − ANCHOR_MIN_DEPTH`.

### 3.4 Tree-full behaviour (roster Q4)

1. **Missing consensus rule.** Validation does not check capacity, and `MemoryChain::apply_block`
   `expect`s success (`tx/src/state.rs:217-220`), so an overflowing block would halt every node.
   - It is unreachable at the current proof size: at most about 4 PX per 8 MiB gives 8 leaves per
     block, so 2^29 blocks, about 2,000 years.
   - It becomes reachable in years with proof-size reductions or aggregation.
   - Zcash has the explicit rule ("a block MUST NOT add … note commitments that would result in the
     … tree exceeding its capacity").
   - **Owned by agent 11 (F11-2)**, which proposes `size + 2·n_px ≤ CAPACITY` (BlockError) plus a
     contextual mempool error. I concur.

2. **New: `Frontier::root` is wrong at exactly `CAPACITY`** (F21-1).
   - At `size == 2^32`, every bit `(size >> h) & 1` for h < 32 is 0, so `root()`
     (`tree.rs:72-82`) folds zeros with empty siblings and returns **the empty-tree root** (the
     genesis anchor).
   - The last `append` (`tree.rs:61-67`) computes the full root in `cur` and discards it.
   - Under F11-2's rule, which allows `size + 2 = CAPACITY` exactly, the final block's recorded root
     would be wrong. The records in the last subtree could never be spent, and 11's proposed tests at
     `CAPACITY − 2 … CAPACITY` would expose the bug.
   - It is not a theft vector: membership against the empty root needs an Hk collision or preimage
     (the R2-C6 argument).
   - The `Tree` (the wallet's full tree) is correct at capacity. Only the consensus `Frontier` is
     wrong, so the two would disagree.
   - **Fix:**
     - either store the full root when `pos == CAPACITY − 1`, or special-case `size == CAPACITY` in
       `root()`;
     - or make the capacity rule `size + 2·n_px < CAPACITY`, leaving one leaf unused, and assert it.
   - The behaviour is unchanged for every size below 2^32, so there is no identity change.
   - **Test:** a uniform-leaf frontier. For all leaves equal to L, `full[h+1] = node(full[h], full[h])`.
     Build a frontier at size `2^32 − 1` with `branch[h] = full[h]`, append L, and assert
     `root == full[32]`. That is O(32) permutations. It needs a `#[cfg(test)]` constructor in
     `tree.rs`.

3. **Empty leaf.** The empty leaf is 0; Orchard uses a value that cannot be an output. A real
   `cm = 0` needs an Hk preimage (about 2^248) [math]. Accept as is, and document it.

### 3.5 Orchard and Sapling comparison (roster Q5)

| Property | Sapling | Orchard | BlackSilk PX |
|---|---|---|---|
| ρ | `cm` mixed with position | `nf_old` of the same action | `Hk(RHO, nf_0 ‖ j)` (kernel) |
| nf | `PRF_nk(ρ)` (BLAKE2s) | `Extract([(F_nk(ρ)+ψ) mod p]G + cm)` | `Hk(NF, nk ‖ ρ ‖ cm)` |
| nf privacy against DL break | hash PRF | relies on DL for some properties | hash PRF [assumed] |
| Sender sees spend | no | no | no (user); **yes** (contract) |
| Anchor | any earlier block's final root | any earlier block's final root | **last 100** block-end roots |
| Expiry | `nExpiryHeight` (ZIP 203, default 40) | same | implicit via the anchor window (≤ 100 blocks) |
| Capacity rule | explicit | explicit | **missing** (F11-2) |
| Empty leaf | not an x-coordinate | 2 (not an x-coordinate) | 0 (computational) |
| Wallet anchor depth | ZIP 315: H−3 | same | **H − (H mod 16)**, can be 0 deep |

**Assessment.**
- BlackSilk's windowed anchor is stricter than Zcash's. It bounds the set of roots and doubles as
  expiry: a good choice.
- The **wallet anchor depth** is the gap (§3.3).
- Nullifier design is Orchard-like in structure and more conservative post-quantum.

### 3.6 Nullifier and root-window storage (engineering)

**Undo size (F21-4):**
- `Undo` clones the full root deque (100 × 32 B) and the frontier (about 1 KB) for **every block,
  forever** (`px/src/state.rs:101-106`; `tx/src/state.rs:221-229`). This is most of R12's
  "4.2 KB/block PX undo" RAM floor.
- Storing only the evicted root (`Option<Digest>`), plus the frontier only when the block has PX
  transactions, gives about 80 B for empty blocks, about 50× less.
- It is not consensus, and it is behaviour-identical: prove that with a property test that compares
  the old and new undo over random apply/undo sequences.
- Coordinate with 35 (storage) and 12 (RAM).

**Position hard-coding (F21-8).** `MemoryChain::apply_block` hard-codes 2 leaves per transaction
(`tx/src/state.rs:173`). Use `t.commitments.len()` and the running size before shape classes land.

---

## 4. New findings

| ID | Severity | Status | Location | Scenario | Confidence |
|---|---|---|---|---|---|
| **F21-1** | Low (latent; consensus code) | Not implemented | `px/src/tree.rs:61-82` | At `size == 2^32`, `Frontier::root()` returns the empty-tree root; the last append drops the full root. With the capacity rule F11-2 allowing an exact fill, the final block's root is wrong and the last leaves are unspendable; the node `Frontier` and the wallet `Tree` disagree | High (read by hand; the bit arithmetic is exact) |
| **F21-2** | Low → Medium once PX shrinks | Not implemented (owned by 11, F11-2) | `px/src/state.rs:135-139`, `tx/src/state.rs:217-220`, `tx/src/validate.rs:1037-1069` | An overflowing block passes validation and panics every node. Concur with 11 | High |
| **F21-3** | Medium (liveness plus privacy linkage; wallet policy) | Not implemented | `wallet/src/px.rs:85-88, 614-616`; `wallet/src/wallet.rs:2007, 2046, 2400` | One height in 16, the anchor is the wallet's tip and 1-confirmation records are spendable. A 1-block reorg invalidates the transaction (`PxUnknownAnchor`); the rebuild republishes the same nullifiers (R5-12). ZIP 315: anchor at H−3 | High (mechanism) / medium (frequency on the trial) |
| **F21-4** | Low (RAM) | Not implemented | `px/src/state.rs:50-55, 101-106` | About 4.2 KB of undo per block kept forever; about 3 MB/day even for empty blocks | High |
| **F21-5** | Informational (design invariant) | Complete but requires documentation | `px-core/src/kernel.rs:353`; `docs/px.md` §3 | "No two leaves equal" is unenforced and rests on the `rho` derivation. Future creation paths (coinbase, issuance, shapes) must preserve it (ZIP 227 #955 precedent). `rho` is publicly computable, so contract-nullifier secrecy rests on `rcm` alone | High |
| **F21-6** | Low (evidence gap) | Partially implemented | `px/tests/state.rs:25-39`; `px/src/tree.rs:10-11,180-215`; `tx/src/px.rs:110-119` | No Faerie Gold regression, window-undo, anchor-reorg, capacity-edge, non-canonical-nullifier decode or cross-kind test; the `tree.rs` doc overstates coverage | High |
| **F21-7** (= R3-7, re-assessed) | Medium (privacy) | Accepted limitation | `px-core/src/record.rs:105-112`, `kernel.rs:329` | Every opening holder sees contract-record spends. Under PX-F4 B/B′ with public derivation, everyone does; the B′ `rho` term adds no secrecy. Structural fix: R5-10 | High |
| **F21-8** | Informational (maintainability) | Not implemented | `tx/src/state.rs:173` | The record-log position assumes 2 leaves per PX transaction; it breaks silently with shape classes | High |
| **F21-9** | Accepted limitation | Accepted | `px/src/tree.rs:23-30` | Empty leaf 0 is excluded computationally (2^−248), not structurally as in Orchard | High |

No Critical or High finding. The core nullifier and commitment design holds under the stated
assumptions.

---

## 5. Implementation plan (phase 2)

| # | Item | Files (ownership) | Consensus? | Identity | Tests | Docs | Diff. | Prio |
|---|---|---|---|---|---|---|---|---|
| 21-A | **Nullifier and commitment test pack** | `px/tests/state.rs`; `px/tests/kernel.rs` (a new test fn only; coordinate with 20); new `tx/tests/px_nullifier_rules.rs` | none | none | Faerie Gold regression (identical outputs across two transactions and two slots; `output_rho` injectivity proptest); window restored by undo (Snapshot gains `is_recent_root` of past roots); cross-kind nf (user `nf` ≠ contract `nf` for the same cm/rcm fields); decode rejects `nf`/anchor/cm word = p and = `u32::MAX` (`NonCanonicalField`); duplicate nullifier: same tx, same block, across blocks, in the mempool (conflict) | `px.md` §9.3 list | S | **P1** |
| 21-B | **Anchor-window reorg test** (no prover) | new `chain/tests/px_anchor_reorg.rs` (coordinate with 02's W-6 and `deep_reorg_px.rs`) | none | none | Synthetic PX transaction, as in §3.3: valid on A, `PxUnknownAnchor` after a reorg to B, valid after reorging back; the anchor at the fork point survives; the mempool drops and re-admits it | — | S–M | **P1** |
| 21-C | **Wallet anchor minimum depth** | `wallet/src/px.rs` (`anchor_height`, `ANCHOR_MIN_DEPTH`), call sites in `wallet/src/wallet.rs` (~2007, 2046, 2400); coordinate with 38/39 | policy (wallet) | none | Unit tests of `anchor_height`; selection refuses records above the anchor; an e2e test that a 1-block reorg of a 16-multiple tip does not invalidate a fresh transaction | `px.md` §11.4, §12; `testnet.md` (spendability delay) | S | **P0** (before the trial: a uniform policy for all wallets) |
| 21-D | **Frontier capacity fix** | `px/src/tree.rs` | consensus code, behaviour unchanged below 2^32 | none (fingerprint unchanged) | Uniform-leaf capacity test (§3.4): `CAPACITY − 1` → append → root equals `full[32]`; the next append gives `TreeFull`; `Frontier` equals `Tree` at small sizes (existing) | `tree.rs` doc (also fix the "sparse sizes" claim) | S | **P1** (must land with or before F11-2) |
| 21-E | Capacity rule (F11-2) | owned by **11** (`tx/src/validate.rs`, `px/src/state.rs` accessor) | **CONS** (tightening; never triggers) | v3 bundle | 11's off-by-one tests (need 21-D) | — | S | P2 (11's call) |
| 21-F | **Undo compaction** | `px/src/state.rs` (Undo), `tx/src/state.rs` (unchanged API) | none | none | Property test: a random apply/undo sequence (including failed blocks) equals the reference clone-undo; memory measured per block | `px.md` §5; R12 RAM figures | S | P2 |
| 21-G | **Docs: invariants and R3-7** | `docs/px.md` §3 (the no-duplicate-leaf invariant and its dependencies; `rho` is public; the future-path rule for `rho`), §9.2 (roadblock row already present; add the reorg/anchor row), §13.2 (public-`rcm` corollary; B′ adds no secrecy); `docs/reviews/px-f4-f5-analysis.md` row B/B′; `px-core/src/record.rs` doc | none | none | — | as listed | S | P1 |
| 21-H | Record-log positions from the actual commitment count | `tx/src/state.rs:173` | none | none | The existing `record_slice` tests | — | S | P3 (before shape classes) |
| 21-I | User-owned contract records (the R5-10 `nk`-keyed nullifier), fixing R3-7 structurally | kernel generation (20/28) | **CONS** | new kernel id | Native/guest differential; issuer cannot compute `nf` | `px.md` §7, §13 | M | P3 |
| 21-J | Consensus canonical anchor (height ≡ 0 mod 16) | with R5-3 (28) | **CONS** | new | — | — | M | P3 |

**Benchmarks:** only for 21-F (bytes of undo per block, before and after; RSS after replaying a
10k-block chain).

**Never change:**
- `rho` is kernel-derived from `nf_0`, and every new creation path uses a chain-unique derivation in
  its own domain;
- `nf` covers `cm`;
- `nk` is derived in-kernel from `sk`, never a free witness;
- user nullifiers are hash-based and `nk`-keyed;
- dummy nullifiers enter the set;
- anchors are block-end roots only, from a bounded window;
- nullifiers are conflict keys in the mempool and stempool;
- digest words are canonical at decode;
- tree depth 32 and the `node` domain separation;
- undo removes only the nullifiers it inserted.

---

## 6. Dependencies and conflicts

- **11 tx-validation:** owns the capacity rule (F11-2). **21-D must merge first**, or together;
  otherwise 11's `CAPACITY` edge tests fail or, worse, are written to the buggy root. Shared files:
  `px/src/state.rs` (11 adds a size accessor; 21-F changes `Undo`), so sequence the two.
- **02 fork-choice-reorgs:** W-6 deep PX reorg (with proofs). 21-B is the cheap, prover-free anchor
  case. Agree the file names (`chain/tests/px_anchor_reorg.rs` against 02's `deep_reorg_px.rs`).
- **20 px-kernel:** `px-core/src/kernel.rs` and `record.rs`. 21 adds only tests and a doc comment;
  kernel edits belong to 20.
- **19 hash-domain-separation:** the Hk domains and the R2-C6 `node` feed-forward. A feed-forward
  change alters `empty_roots` and every root; 21-D's test must be written against `node()`
  generically.
- **38 / 39 wallet:** `wallet/src/px.rs` anchor policy (21-C) against 39's incremental tree and sync
  work. 21-C touches only `anchor_height` and its callers.
- **28 private-contracts:** R3-7, B′, R5-10 and the clock (21-I, 21-J).
- **35 storage / 12 mempool:** undo size (21-F); anchor expiry in revalidation.
- **41 fuzzing:** a stateful property model of `State` (apply/undo/window) could absorb 21-A/21-F's
  property tests.
- **47 docs:** 21-G.

---

## 7. Open questions for the coordinator

1. **Anchor depth:** `ANCHOR_MIN_DEPTH = 3` (ZIP 315 trusted) for all records, or 3 for own change
   and 10 for received records? The latter leaks nothing on chain but delays receipt usability. I
   recommend 3 uniformly for the trial.
2. Should 21-D choose "store the full root at the last append" (exact Zcash semantics) or "leave one
   leaf unused" (a simpler rule)? I recommend the former, with 11's rule `size + 2·n ≤ CAPACITY`.
3. Is a shielded coinbase (R3-13) or issuance on the v3/v4 path? If so, the `rho` derivation must be
   specified now (a new domain, from a chain-unique prefix such as block id plus index).
4. Should 21-F wait for 35's persistent-state redesign? It is small and independent, so I suggest
   doing it now.

---

## 8. Sources

- Zcash Protocol Specification, v2026.7.0 [NU6.2]: note commitment tree capacity rule; anchors
  "MUST refer to some earlier block's final … treestate"; Sapling/Orchard nullifier and ρ
  derivations; Faerie Gold. https://zips.z.cash/protocol/protocol.pdf
- The Orchard Book, "Nullifiers" (design goals: Balance, Note Privacy, Spend Unlinkability, Faerie
  Resistance; `nf = Extract([(F_nk(ρ)+ψ) mod p]G + cm)`; ρ = `nf_old`).
  https://zcash.github.io/orchard/design/nullifiers.html
- The Orchard Book, "Commitment tree" (depth 32; anchors at block boundaries; uncommitted leaf value).
  https://zcash.github.io/orchard/design/commitment-tree.html
- ZIP 315, Best Practices for Wallet Implementations (3 trusted / 10 untrusted confirmations; anchor
  at the trusted depth "prevents chain rollbacks from invalidating anchors and revealing nullifiers";
  40-block default expiry via ZIP 203). https://zips.z.cash/zip-0315
- ZIP 203, Transaction Expiry. https://zips.z.cash/zip-0203
- zcash/zips issue #955, "[ZIP 227] Attack against Spendability due to ρ potentially not being unique
  in an issuance action" (D. Hopwood, 2024-11-11; fix: derive ρ from the txid and action index).
  https://github.com/zcash/zips/issues/955
- Electric Coin Company, "Fixing Vulnerabilities in the Zcash Protocol" (Faerie Gold and InternalH
  collision). https://electriccoin.co/blog/fixing-zcash-vulns/
- Design of Sapling book, Zerocash chapter (the Faerie Gold fix via `h_Sig`).
  https://github.com/zcash-hackworks/design-of-sapling-book/blob/master/zerocash.md
- E. Ben-Sasson et al., "Zerocash: Decentralized Anonymous Payments from Bitcoin", IEEE S&P 2014.
  http://zerocash-project.org/media/pdf/zerocash-extended-20140518.pdf
- Informal Systems, Quint model of the Faerie-Gold vulnerability. https://quint.sh/posts/zerocash
- E. Andreeva, J. Daemen, B. Mennink, G. Van Assche, "Security of Keyed Sponge Constructions Using a
  Modular Proof Approach", FSE 2015, LNCS 9054 (the basis for treating `Hk(nk ‖ …)` as a PRF).
  https://link.springer.com/chapter/10.1007/978-3-662-48116-5_18
- B. Mennink, R. Reyhanitabar, D. Vizár, "Security of Full-State Keyed Sponge and Duplex", ASIACRYPT
  2015. https://eprint.iacr.org/2015/541.pdf
- L. Grassi, D. Khovratovich, M. Schofnegger, "Poseidon2: A Faster Version of the Poseidon Hash
  Function", ePrint 2023/323 (the permutation under the PRF and collision assumptions; margin
  analysis is agent 19's). https://eprint.iacr.org/2023/323
- Internal: `docs/reviews/full-review-2026-09-27/R5-px.md`, `R3-privacy.md` (R3-7),
  `SX1-core-crossreview.md`, `SX2-systems-crossreview.md`; `C:/bszkeval/p2/research/11-tx-validation.md`
  §3.3; `02-fork-choice-reorgs.md` W-6.
