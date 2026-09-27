# 50 red-team-integration: dossier (phase 2, research)

Agent 50. Adversarial review of the v3 merge and of the decided consensus changes. This
is internal engineering work, not an audit. Nothing here claims that BlackSilk is secure.

## 1. Scope and what I read

**Commit:** `9e422d8` (`git rev-parse --short HEAD`), branch `rebuild/core`. The merged
range is `65bcec1..9e422d8`: 17 commits plus the merge.

**Diffs read in full (`git show`):**
- `58c7f6e`: schedule and branch id;
- `79b874e`, `abee421`, `cc39795`: deploy rules;
- `d4494e0`: upgrade integration (grace window, proof-cache gating, `revalidate_between`,
  mempool `enter_rules`, deploy block budget);
- `25eecad`: genesis binding in P2P and the wallet;
- `c280928`: PX-F5;
- `147fb06`: canonical FRI schedule;
- `de824a4`: `CIRCUIT_ID`;
- `53d3b49`: platform-neutral kernel;
- `9654d42`: wallet per-height rules;
- `a9edbf3`: node opens the chain with base rules.

The `3d6c624` genesis tool and the `07afd9f` data commit were read at the stat and
summary level only.

**Current code read:**
- `consensus/src/{schedule.rs, chain.rs (check_rules, validate), difficulty.rs}`;
- `tx/src/validate.rs` (lines 230–300 and 700–1200);
- `tx/src/px.rs` (deploy fee, `budget_is_provable`, `check_deploy_structure`, `contract_id`);
- `tx/src/types.rs` (`hash`, `px_bytes`);
- `tx/src/params.rs`;
- `chain/src/mempool.rs` (`insert`, `select`, `enter_rules`);
- `chain/src/manager.rs` call sites;
- `p2p/src/net.rs` (`admit_tx`, `proven_invalid`, `on_invalid_tx`, header-error paths);
- `px-core/src/{hash.rs, kernel.rs}`;
- `zkvm/guests/kernel/src/main.rs`;
- `zk/src/lib.rs` (`verify`, `honest_fri_schedule`, `check_fri_schedule`);
- `third_party/p3-fri/src/{config.rs, verifier.rs}` (shape checks);
- `wallet/src/wallet.rs` (genesis check, stale-transaction logic).

**Tests inspected (names and structure):**
- `chain/tests/activation.rs`;
- `tx/tests/upgrade.rs`;
- `consensus/src/schedule.rs` unit tests;
- the `zk` schedule tests;
- the wallet genesis tests.

**Research inputs:** `C:/bszkeval/p2/{brief,roster,decisions,status}.md`, and dossiers 03, 11,
13, 15, 19, 20, 21, 22, 28 and 31 (the relevant sections), with 10 and 14 for R12-2.

**Rules followed:** no repository file was modified and no build was run. The ePrint
2026/089 text was checked from the primary source (§4.2).

## 2. Current state (merged items)

| Item | Assessment | Evidence |
|---|---|---|
| Schedule and branch id | Correct as designed. The table is validated at construction (start at 0, strictly increasing heights, non-decreasing versions, distinct nonzero branch ids). The epoch is chosen by `parent.height + 1`, not by the claimed height. `SigDomain` is fixed-width and prepended to all three signature messages and to `h_tx`. | tested (`header_version_follows_the_schedule`, `malformed_tables_are_rejected`, `tx/tests/upgrade.rs`); source-read |
| `for_chain` tripwire | Every production caller now uses `at_height` or `rules_at` (no `.rules()` callers remain in p2p, node, rpc, miner or wallet). `for_chain` remains only in tests, fuzz and labnet (single epoch). | source-read (grep) |
| Deploy rules (R5-7, R7-5, R5-1, exact fee) | No integration bug found. The fee is a pure function of public shape and payload length. Budgets are checked before ELF loading, and duplicates are compared by loaded program id. Template `select` accounts deploys with the same `px_bytes` metric as the block rule. | source-read; tested (`deploy_rules.rs`, `selection_respects_the_deploy_sub_budget`) |
| PX-F5 | Correct. `contract ≠ 0 ∧ owner ≠ 0 ⇒ ContractOutputOwner` (exit 17 = 2 + index 15, appended). Contract outputs still need a same-contract specifier, so unregistered contract ids cannot be minted. | source-read; tested (native/guest agreement) |
| Canonical FRI schedule | Correct and DoS-safe: `degree_bits` is bounded before `check_fri_schedule`, and the loop is bounded. `log_arity` is also absorbed into the transcript upstream (verifier.rs:320). Equality with the prover is tested for 8 proven combinations, and well-formedness for all 2^15 degree-bit sets. | tested; source-read |
| `CIRCUIT_ID` | Absorbed first, length-prefixed. Correct as domain separation, but only if bumped (RT-11). | tested (`circuit_id.rs`) |
| Platform-neutral kernel | `invalid_input` → `halt(1)`, so exit code 1 cannot collide with an `Error` (codes start at 2). Guests are stripped. | source-read; tested (`elf_paths.rs`) |
| Genesis binding (P2P) | Correct. The genesis id is in the session KDF. | tested (`different_genesis_ids_cannot_talk`) |
| Genesis binding (wallet) | Correct against misconfiguration, but it trusts the node's self-reported `/info` (RT-15). | tested; source-read |
| Activation grace window | Correct arithmetic: `[A−60, A+60)`. It affects scoring only (`PxProof` is contextual, and buried-ring `InvalidSignature` is not treated as proof). It is keyed on the local height. | tested (`px_proof_failures_are_contextual_near_an_activation`) |
| Proof-cache domain gating | Logically correct: the cache is used only if `mempool.validated_under() == rules_at(h).domain()`, `add` flushes on a domain change, and the tx id covers the proof. **Untested with a PX transaction** (RT-2). | source-read |
| `revalidate_between` | Unused in production; its contract is incomplete (RT-4). | source-read |
| Wallet per-height rules | Builds use `synced+1`, `submit` checks the node tip's epoch, and stale-branch transactions are released. Release is unsafe under a reorg back below the activation (RT-5). | tested (e2e two-epoch); source-read |

## 3. Problems in scope: part A (the merged items)

### RT-1 (Medium): `UnknownUpgrade` is decided before PoW, so it is free, unpenalized and spoofs the upgrade warning

**Mechanism.**
- `HeaderChain::validate` calls `check_rules` (the version test at `consensus/src/chain.rs:322-327`) before the RandomX check (`chain.rs:481-486`).
- Any header whose version exceeds `max_header_version()` returns `UnknownUpgrade`, with no PoW verified.
- P2P treats it as not penalized, in both header batches and blocks (`p2p/src/net.rs` `penalized`, `on_header_error`, `on_block`), and logs "this node may need an upgrade" once per peer.

**Attack.**
1. A peer streams headers or full blocks carrying `version = u32::MAX`, at zero hash cost. Each is rejected cheaply, but the peer is never scored. It can keep a slot (eclipse help), stall header sync from itself, and repeat without end within the per-message rate limits.
2. Any single inbound peer makes the operator believe that an upgrade is needed. This is a social-engineering lever ("download the new release") on a privacy chain.

**Prior art.** Bitcoin Core warns about unknown rules only from blocks on its own, PoW-valid chain, and only when a threshold of a signalling window is reached (the `WarningBitsConditionChecker`; see PR #16713). It never warns from an unverified header of one peer.

**Fix (P2P policy, not consensus).**
- (a) In `validate`, compute PoW before the version classification whenever the header is otherwise well formed, and return `UnknownUpgrade` only for a PoW-valid header. A PoW-invalid header with an unknown version is `InsufficientWork` (penalized).
  - A future PoW change would make old nodes see `InsufficientWork`. They must upgrade in that case anyway. Document it.
- (b) Disconnect without a ban after `N` `UnknownUpgrade` responses from one peer.
- (c) Raise the operator warning only when at least 2 distinct outbound peers report it with PoW-valid headers, or when their work reaches `anti_dos_threshold`.

**Tests.**
- A peer sending 10^4 unknown-version headers with junk PoW is penalized (after the fix), with zero RandomX calls (`CountingPow`).
- A PoW-valid unknown-version header is not penalized and warns only at the threshold.
- A single inbound peer never triggers the warning.
- A regression that `BadVersion` (a known lower or higher version) stays penalized.

**Consensus-critical:** no (scoring and ordering of the verdict only). The final verdict (header rejected) is unchanged.

### RT-2 (Medium, test gap on a split-sensitive path): proof-cache gating across an activation is untested for PX

- `chain/src/manager.rs:938-945` gates `validate_block_transactions_cached` on `same_rules`.
- The failure it prevents is a consensus split: a pooled old-branch PX transaction without v1 inputs would skip PX5 on nodes that had pooled it and fail on nodes that had not. The commit message says exactly this.
- `chain/tests/activation.rs` exercises only transfers. Transfers have CLSAGs, which are always re-verified, so the gate's failure mode is invisible to the existing suite.

**Tests to add.**
1. A unit test of the predicate, factored into `fn cache_applies(pool_domain, block_rules)`.
2. A manager-level test with a regtest two-epoch schedule. A PX transaction with no v1 inputs is proven once, and a fixture may be reused. It is pooled under epoch A and mined in a block at the activation height. Assert `BlockError::Tx{PxProof}`, and assert that PX5 was actually called: add a counter behind `cfg(test)`, or use a closure spy through `validate_block_transactions_cached`.
3. The mirror case: a reorg back below A, the same transaction re-mined at A−1 is accepted, and the cache is not consulted after the flush.

### RT-3 (Low): `verifier_id` is carried but never dispatched

- `Epoch::verifier_id` feeds only the fingerprint (`node/src/fingerprint.rs:99`).
- `check_px_proof` always uses the single pinned kernel.
- `SUPPORTED_VERIFIERS` is checked only in `tx/tests/upgrade.rs:82-90`.
- **Consequence:** a future schedule entry with `verifier_id = 2` on a build that lacks it would silently verify with verifier 1.

**Fix:**
- a `const` assertion in `tx` (or a check in `node` at startup) that every epoch's `verifier_id ∈ SUPPORTED_VERIFIERS`;
- `TxRules` should carry `verifier_id` so that the cache key and dispatch use it (F-28-1, W28-9).

**Test:** a schedule with an unsupported id refuses to start or build.

### RT-4 (Low): `revalidate_between` has an incomplete contract and is unused

`tx/src/validate.rs:757-767` chooses extension-only revalidation whenever the domains are
equal. That ignores whether a **reorganization** happened between the two heights: the
doc of `revalidate_after_extension` itself requires a full check after a reorg. No
production caller exists; the mempool flushes instead.

**Fix:** either delete it (preferred: dead consensus-adjacent code is a trap), or add an
`after_reorg: bool` and fall back to `validate_mempool_tx`.

**Test:** a same-domain reorg that re-points a ring index must give a full-validation
verdict.

### RT-5 (Low, wallet): releasing a "stale" transaction's inputs can double-pay after a reorg across the activation

**Mechanism.** `refresh_pending` (9654d42) releases the inputs of a transaction built for
branch A as soon as `epoch_at(synced+1)` is B. It also releases them when "a
reorganization went back across one".

**Attack.**
1. A reorganization to a heavier branch below A makes the old transaction valid again. It can be mined there by any relayer who kept it.
2. Meanwhile the user has "sent the payment again". The new transaction reuses the released inputs only if coin selection picks them. With other inputs, both payments can confirm.

**Prior art.** zcashd caps a transaction's expiry at the next activation, so that it
"drop[s] out of the mempool automatically on the pre-upgrade branch" (Zcash expiry
discussion, zcash/zcash#4132 and PR #2874; ZIP 203). The mempool side is flushed.

**Fix (wallet policy).**
- A rebuild of a stale payment must spend the **same key images** (reuse the stored inputs and rings, W-5), so the two payments conflict by construction.
- Alternatively, keep the inputs reserved until the activation block is buried by `ACTIVATION_GRACE_BLOCKS`.
- When PX6 lands, PX wallet transactions built within `ACTIVATION_GRACE_BLOCKS` of A should set `not_after = A − 1` (the Zcash model).

**Tests:** an e2e two-epoch run with a reorg below A after the release. Assert that at most
one of {old, rebuilt} can be mined, whatever inputs coin selection would pick.

### RT-6 (Info, docs): the `hash.rs` separation comment is wrong for multi-block inputs

`px-core/src/hash.rs:37-40` says "every sponge call has a nonzero domain constant in word
8". Only the **first** permutation call has `(domain, len, 0⁶)` in the capacity. Later
calls carry the previous output's capacity. A 52-element `RECORD` hash is 7
permutations, the last of which is literally `node(r₆ + m₇, c₆)`.

- The security argument (2026/089 Thm 3) does not need this separation. The paper's own sponge is not separated either.
- The comment should say so instead of claiming a 2^−186 separation.
- Comment-only change: verify that the ELF id is unchanged with `reproduce.sh`.

### RT-11 (Info): `CIRCUIT_ID` is a manual string

A constraint-only AIR change that forgets the bump keeps every transcript. This is
already covered by the decided P0 freeze gate (22 W4, 23 W2: an AIR digest in the same
commit). I only confirm that the gate is necessary and that `CIRCUIT_ID` alone gives no
drift protection.

### RT-12 (Low): verifier-specific constants inside "stateless" rules

- `budget_is_provable` (`tx/src/px.rs:767`) uses `px::prove::kernel_budget(1)` and `zk::params`.
- `is_stateless` classifies `PxProof` as stateless.
- Both are properties of verifier 1. When a second verifier exists (W28-9), both must take the epoch. Otherwise a deploy that is valid under one kernel is rejected statelessly (and penalized) under another.
- Record this in the G2 design. There is no action for v3.

### RT-14 (Info): signatures bind the network and branch, but not the genesis

- A rehearsal chain and the final chain can share `network_id` and branch `BSv3`.
- Transaction replay between them is blocked only by chain state (ring indices and PX anchors almost surely differ).
- Adding `genesis_id` to `SigDomain` would cost nothing at the v3 reset and make this explicit, in the manner of EIP-155 chain ids.
- **Owner call.** I do not rate it above Info, because ring and anchor mismatch makes replay practically impossible.

### RT-15 (Info): the wallet genesis check is advisory

`check_network` compares the node's self-reported `/info.genesis_id`. A dishonest node can
report anything, and the wallet does not verify header chaining back to genesis. It is a
correct guard against misconfiguration. The docs should call it that (not a trust
boundary).

### Items attacked with no finding

- **The schedule table's validation:** strictly increasing heights and distinct branch ids mean domains never repeat, so domain equality ⇔ same epoch. This is the basis of the cache gating and of `enter_rules`.
- **Grace-window bounds:** `saturating_add` at both ends; the window only removes penalties.
- **Deploy fee and budgets:** checked against `u64::MAX` and at ±1. The payload length does not depend on the salt value.
- **FRI rule:** no panic path outside `catch_unwind`, and no unbounded loop.
- **PX-F5 bypass via dummies:** dummies cannot carry a contract (`DummyContract`).
- **Kernel exit code 1:** it cannot be forged into a success (the verifier requires exit 0).

## 4. Part B: the R2-C6 option-A basis

### 4.1 The claim under test

Decision R2-C6 option A rests on four claims:
1. ePrint 2026/089 exists and proves binding and extractability of Plonky3-style truncated-permutation trees at about 122.6 bits.
2. Theorem 3 applies to BlackSilk.
3. Dossier 19's adaptation (F3) holds: add-into-rate absorption, a (domain, len) start state and zero empty leaves.
4. The STARK's own Merkle commitments use the same construction.

### 4.2 Primary-source verification (ePrint 2026/089, revision of 2026-07-22)

**Existence and venue: VERIFIED.**
- Coratger, Khovratovich, Wagner (Ethereum Foundation) and Mennink (Maastricht), *The Billion Dollar Merkle Tree*.
- The landing page says "Published in ACM CCS 2026 (minor revision)". The PDF says it is the full version of the CCS 2026 paper.
- Received 2026-01-20 and revised 2026-07-22. I could not diff v1 against v2.

**Construction.** Leaves are `H(ck, x_i)`. Nodes are `Trunc(P(h₀, h₁))`. There is no
feed-forward and no domain separation, the depth is fixed, and `P` is two digests wide.

**Theorems.** All three are in the ideal-permutation model, with `P⁻¹` queries allowed.
- **Thm 1 (strong position-binding):** requires H to be collision and preimage resistant. Remark 4 gives "(8·31 − log 4)/2 = 123 bits" with H a random oracle.
- **Thm 2 (strong extractability):** H is an **independent** random oracle. Remark 6 gives "(8·31 − log 6)/2 ≈ 122.71 bits".
- **Thm 3 (strong extractability, H = the overwrite sponge `oSponge_P` over the same P):**
  - Bound: `Adv ≤ (4q² + 2q)/(|H| − 1)`.
  - The sponge has rate = capacity = one digest, **zero initial state**, **overwrite** absorption and messages of an integral number of blocks (Remark 1: otherwise "an injective padding must be applied").
  - **The paper gives no bit figure for Thm 3.**
- **§6:** "The proofs of strong position-binding (Section 4) and strong extractability (Section 5) require independence between H and P". A contrived H built from P⁻¹ makes the tree "completely insecure".
- **The paper explicitly excludes** "the sponge that adds the message into the outer part".
- **Plonky3's usual instantiation** (a width-24 leaf sponge and a width-16 node, Remark 2) falls under Thms 1–2 because it treats H as independent. **BlackSilk uses width 16 for both**, so only Thm 3 is relevant.

### 4.3 Where dossier 19 is right, and where it overstates

| 19's statement | Verdict |
|---|---|
| The paper exists; CCS 2026; analyses this tree without feed-forward | Correct |
| "Thm 3 … gives about 122.6 bits" | **Arithmetically correct but not the paper's number.** With `|H| = p⁸`, `log₂ p⁸ ≈ 247.26`, the bound gives `(247.26 − 2)/2 ≈ 122.6`. The paper's printed 122.71 is Thm 2 (independent H), which does not apply. Cite it as "our evaluation of Thm 3". |
| Thm 1 (position-binding) supports BlackSilk | **Not applicable as stated.** Thm 1 needs H independent of P (§6). For BlackSilk only Thm 3 is available. Whether strong extractability implies position-binding in the paper's framework must be confirmed from its definitions before the docs cite "binding" (open question Q1). |
| Quote "the Plonky3 approach is, in fact, sound" | **Not verified.** The wording I found says the tree is sound "if instantiated with appropriate permutation and leaf hash". Quote exactly or paraphrase. |
| "A published proof now covers the construction" (decision reason 1) | **Overstated.** A published proof covers a *closely related* construction. The adaptation to `Hk` is unwritten. |

### 4.4 Independent check of the three adaptations, plus one 19 did not list

**(a) Add-into-rate: HOLDS, by an exact reduction** [math, mine].
- Let `s_{i−1} = (r_{i−1} ‖ c_{i−1})`. The additive sponge feeds `P(r_{i−1} + m_i ‖ c_{i−1})`. Define `φ(m)_i = r_{i−1} + m_i`, where `r_{i−1}` comes from the previous `P` output.
- Then `Hk_add(IV; m) = Hk_ow(IV; φ(m))` for the overwrite sponge started from `(0 ‖ IV)`.
  - For block 1, `r₀ = 0`, so the two sponges coincide.
  - For each fixed prefix, `φ` is a bijection that is efficiently computable forwards and backwards from the query transcript.
  - By induction, `φ` is injective on equal-length messages.
- **Extractability transfers:** the extractor for the overwrite sponge recovers the sequence of `P` inputs, and `m_i = x_i − r_{i−1}` is read from the previous query's output.
- This is stronger than 19's "bijective relabelling per state" and can be written in a paragraph.

**(b) A (domain, len, 0⁶) start state instead of 0: PLAUSIBLE, NOT PROVEN.**
- In Thm 3's proof, 0 is the distinguished node where the extractor stops ("h₂ = 0"; Lemma 16 needs "a directed path from 0 to com"), and a backward query hitting 0 is a bad event.
- For the PX tree only **one** start state matters, `IV = (RECORD, 52, 0⁶)`, because the kernel always hashes leaves as `Hk(RECORD, 52)`.
- Replacing the constant 0 by another fixed constant should change only the label of the termination node. The bad-event probability stays `q/|H|` per query, with a factor `|IV-set|` if all domains are counted, which is negligible next to `q²/|H|`.
- **But** in BlackSilk the value 0 *also* appears as tree data (empty leaves). The paper's proof never has 0 in two roles, so the proof must be re-read with 0 as data and `IV_RECORD` as the termination label.
- I see no attack. It needs a written proof delta (see (c)).

**(c) Zero empty leaves: PLAUSIBLE, NOT PROVEN.**
- An opening of an empty position needs `Hk(RECORD, x) = 0`, a preimage event (`q/|H|`).
- The empty subtree roots `E_k = node(E_{k−1}, E_{k−1})` are public constants. A forged path through them is the generic meet-in-the-middle claw that the bound already covers.
- **The paper does not model leaves that are not H-outputs.** Treat empty leaves as the sparse-tree Remark 3 ("leafs … generated as hashes of pre-leafs") only after arguing that the constant 0 behaves like an unqueryable H-output, whose preimage probability is `q/|H|`.

**(d) Not listed by 19: partial final blocks.**
- `Hk` zero-fills a partial last block (52 = 6·8 + 4). The paper requires integral blocks or an injective padding.
- The length in the IV makes zero-fill injective, so it holds. It must still be stated in the adaptation.

### 4.5 The STARK side

`zk/src/config.rs` uses `PaddingFreeSponge<Perm,16,8,8>` (overwrite, zero IV) with
`TruncatedPermutation<Perm,2,8,16>` over **the same width-16 P**. That is **Thm 3's exact
setting**, modulo MMCS salts and row-width handling (App. C). So 19's point 2 ("the STARK
depends on the construction anyway") is correct, and it is on firmer ground than the
PX-tree adaptation.

### 4.6 Verdict on R2-C6 option A: ACCEPT WITH CHANGES

The engineering decision (no feed-forward in v3) is sound. Feed-forward does not raise
the birthday-capped level, costs +2,631 cycles on the only contract shape, and the STARK
depends on the construction regardless. The **stated basis** must be corrected before
it enters docs:

1. Cite Thm 3 only, and say that its 122.6-bit figure is our evaluation.
2. Drop Thm 1 and Thm 2 for `Hk`.
3. Label (b), (c) and (d) as an argued adaptation, not a proof. Write (a) as the reduction above.
4. `COLLISION_BITS` = 122, not 123 (agrees with 19 F10).
5. Keep 19's invariants 1–5, and add: "no `Hk` domain may ever have an all-zero start capacity" and "`IV_RECORD` must never equal a tree value" (both hold today because `domain::BASE ≠ 0`).
6. Fix the RT-6 comment.

## 5. Part C: pre-review of the decided consensus changes

For each: attacks, the exact adversarial tests, and a verdict.

### 5.1 C4 option B (13, 17): ACCEPT WITH CHANGES

**Attacks considered.**
- **A copy of `O` in another transaction.** It is Janus-rejected, because ctx (all key images, nullifiers or height) differs. It cannot be spent by the copier (no `x`), and it does not burn the victim's output unless the victim's wallet credits the copy.
- **A copy mined *before* the genuine output** (a front-running miner). The wallet must credit by Janus, never by first-seen.
- **A ring containing both `O` and its copy.** Harmless (CLSAG does not need distinct keys; the copy is a black marble).
- **Wallet dedupe (13 §3.3 step 9) "keeps the lowest global index".** This diverges from Monero's burning-bug mitigation: Monero spends the largest denomination and treats the rest as unusable (Monero post-mortem 2018-09-25; PR #3985). If an attacker ever gets two outputs past the wallet's checks, "lowest index" lets a small early copy displace a large genuine output. **Change to "largest amount, then lowest index" (RT-10, Low).**

**Tests.**
1. Attack-first, flipped after:
   - `T` and a copy `T′` (same `O`, `R`, encrypted amount and Janus anchor, copied verbatim) in the pool and in one block;
   - `T′` in block h and `T` in h+1;
   - both are accepted.
2. Intra-transaction duplicates stay stateless errors for transfer, PX (`PxDuplicateOutputKey`), deploy and coinbase (sort). A pinned test must not rely on C4.
3. Wallet: the copy-first ordering credits only the genuine output; `balance()` counts one output per key image.
4. Wallet dedupe with two forged-credited outputs keeps the larger amount.
5. Decoy selection over a distribution containing duplicate-`O` outputs selects them at the unfiltered rate (F13-7): a chi-square test against the gamma selector.
6. `undo_block` and a reorg with duplicates on both branches.
7. A fingerprint rule-revision entry changes.
8. The P2P stempool: `T` and `T′` both stem and fluff with no conflict drop.

### 5.2 Difficulty rise cap versus ASERT (03): ACCEPT WITH CHANGES (the cap)

**Attacks and concerns.**
- The cap `next ≤ parent + max(1, ⌊parent·R⌋)` bounds compounding per block regardless of timestamps. Because validation recomputes the required difficulty, the cap is self-enforcing.
- **Hop-in/hop-out:** the cap makes the rule **asymmetric** (slow up, LWMA-fast down). 03's own table shows hopper share rising 0.317 → 0.393 at 2 %.
  - An on/off hopper exploits the asymmetry: it mines cheap blocks while the capped difficulty lags, then leaves, and honest miners then pay the long blocks.
  - The decided acceptance criteria have **no hopper or emission criterion**. Add:
    - the emission deviation over 10^4 blocks under an on/off 10× hopper stays within +2 %;
    - the honest miners' worst 60-block mean block time stays ≤ 2T;
    - the hopper share stays ≤ that of LWMA-60 + 5 points.
- **Start-up (03-F2):**
  - At low D the cap degenerates to +1 per block: from D0 = 100, +2 per block.
  - The genesis-gap test (recovery 16 → 50) becomes additive. Re-derive it.
  - Specify the integer arithmetic exactly (floor and u128), because vectors depend on it.
- **ASERT with the same effective rise** (half-life ≈ 15 blocks ⇒ 2^(1/15) ≈ 4.7 %/block) is equivalent to a ~5 % cap, which 03 shows only halves the attack. ASERT-2h fails the 150-block recovery criterion (>400). The cap is the simpler rule that can meet the criteria.

**Tests.**
1. `tools/daa-sim` race at q ∈ {0.30, 0.35, 0.40} and z ∈ {30, 100, 300}, compressed against honest stamps.
2. The genesis-fork rewrite at q = 0.2, age 720.
3. Three hopper strategies:
   - threshold (1.2/2.0·D_eq);
   - a fixed 50/50 duty cycle;
   - "mine whenever the cap binds".
4. A 10× drop immediately after a capped rise (worst stall).
5. Launch with D0 = true/2 and true×10.
6. A property test: `next ≤ parent + max(1, parent·R)` for all inputs, including `u64::MAX` difficulties and non-monotone stamps.
7. Golden vectors from an independent script at the cap boundary ±1 and on the 1 → 2 path.
8. A header whose difficulty exceeds the cap by 1 gives `BadDifficulty`.
9. 31 re-derives the presync bound under the cap.

### 5.3 F-20-1 exactly-one-approval (20): ACCEPT

**Attacks.**
- Double approval by two executions of one program, and by two programs of one contract.
- Triple approval, if `MAX_FN > 2`.
- Crossed approvals (f₀ approves input 1 and f₁ approves input 0) must stay accepted.
- A dummy or user input approved: `ApprovalMismatch` must keep precedence. Pin the order.
- Constant work on success is required for privacy (a counter, not an early exit on the first approval).
- **The fix does not close F-20-2** (an approved value may flow to unspecified user outputs; only global balance holds). This must stay in the author checklist.

**Tests.**
1. Native and guest reject with exit 18 for each double-approval form.
2. The Cardano-style "unique item duplicated" scenario (20 §F-20-1) as a regression.
3. Positive: two functions approving different inputs; crossed approvals.
4. An exit-code table test (0, 1 and 2..=18 distinct, append-only).
5. The F-20-2 footgun still demonstrable (documented limitation).
6. A differential corpus seed.
7. The kernel id re-pinned in the single rebuild, and cycles re-measured.

### 5.4 PX6 validity window and ABI version (28): ACCEPT WITH CHANGES

**Required changes and attacks.**
- **The mempool must refuse a *premature* transaction** (`not_before > tip+1`) as contextual. Otherwise pool stuffing becomes free: transactions that cannot be mined for a long time occupy PX slots and pay nothing until mined.
- **`revalidate_after_extension` needs the height,** or expired transactions survive in the pool. Templates must filter by window, or the miner's self-check falls back to coinbase-only (a liveness hit).
- **PX6 is never skipped by the proof cache.** The cache vouches only for PX5. Test a cached transaction that has expired.
- **Reorg:**
  - a transaction mined at h ≤ `not_after` and re-mined at h′ > `not_after` after a reorg is invalid;
  - wallets must treat expiry as "released only when buried", as in RT-5.
- **`(0, 0)` default** for plain transactions. Non-default windows are bucketed to 16 (wallet policy).
  - With RT-5, near an activation a PX wallet may set `not_after = A − 1`.
  - This reveals "built near activation", which every wallet does at that time anyway.
- **ABI:**
  - `check_deploy_structure` must reject an `abi` not in the epoch's supported set. Otherwise a deployer can pre-register a future ABI whose semantics are not yet defined ("squatting").
  - `abi` and `out_words` must be inside the payload hashed into `contract_id` (immutable registration).
  - The verifier, not the caller, writes the ABI word and the window into the function prefix.

**Tests.**
1. Boundaries at `h = not_before−1, not_before, not_after, not_after+1`, in the mempool (`tip+1`) and in the block.
2. Premature transactions refused and not scored.
3. Expiry by extension removed from the pool.
4. A template never contains an out-of-window transaction (property test).
5. A reorg that expires a mined transaction.
6. A cached-proof transaction that has expired is rejected.
7. The structure rule `not_after ≠ 0 ∧ not_before > not_after` is stateless.
8. `u64::MAX` bounds.
9. Vault refund before and after T, native = guest.
10. A function echoing a wrong window yields no proof.
11. An unknown `abi` is rejected at deploy.
12. `outputs.len() ≠ out_words` gives `PxShape`.
13. A registry round-trip, and undo.

### 5.5 Tree-capacity rule (11 I3, 21-D): ACCEPT WITH CHANGES

- 21-D (store the full root at the last append) must merge **with or before** the rule. Otherwise `root()` returns the empty root at exactly `CAPACITY`, which is also the genesis anchor.
- Count leaves from each transaction's commitments (`N_OUT`), not from a literal 2.
- The mempool and **template selection** must enforce the cumulative leaf budget within a block.
- If `apply_block` fails after validation passed, the node must **fail-stop**, not mark the block invalid. Marking it would silently fork this node over a local bug.

**Tests.**
1. A frontier at `2^32 − 3` via a test constructor; apply 1, 2, then 3 PX transactions: exact accept and reject.
2. `root == full[32]` at capacity (the uniform-leaf method).
3. Undo at the boundary, and a reorg from full to non-full.
4. Template property near capacity.
5. The mempool contextual error is not scored.
6. A property test: `validate ⇒ apply Ok`.
7. Wallet `Tree` equals node `Frontier` at capacity.

### 5.6 CLSAG `D ≠ identity` (15 W1): ACCEPT

- On Ristretto255 there is no torsion, so `is_identity()` is the exact analogue of Monero's `8·D ≠ 0` ("Bad auxiliary key image"). 15 source-read this in Monero and monero-oxide.
- Honest `z = 0` has probability about 2^−252.

**Tests.**
1. A test-only signer with `z = 0` verifies before the change and fails after it (attack-first).
2. The stateless error for transfer, PX with v1 inputs and deploy, at input index k > 0.
3. `sign` refuses `z = 0`.
4. Checked in structure, before ring resolution, so it cannot be masked by a contextual error.
5. The block path, including `validate_block_transactions_cached`, rejects it.
6. The only 32-byte encoding that decodes to the identity is all zeros.
7. The P2P penalty is applied.
8. A golden reject vector.
9. Every existing vector is unchanged.

### 5.7 R12-2 (a′) (14, 10): ACCEPT WITH CHANGES

- Verified: `PX_STANDARD_FEE = 2·MAX_PX_TX_SIZE ≈ 8.9·10^6`, while `20·max_weight(64, 2) ≈ 1.0·10^6`. So a PX transaction always pays at least the v1 fee of its v1 part. Add this as a `const` assertion.
- **The same commit must change `Mempool::select`** to charge PX and deploy entries against *both* budgets. Today the PX class never checks `weight` (`chain/src/mempool.rs:427-449`), so templates would violate B6, and the self-check would fall back to coinbase-only.
- B6 must stay before T9 and C3, so that F10-2 blocks die with zero CLSAG verifications.

**Tests.**
1. Demo first: a deploy over a small `max_block_weight` is accepted before the change and rejected after.
2. A block at `600,000` ±1 with mixed classes.
3. The F10-2 block (183 empty-proof PX × 64 inputs) is rejected at B6 with a CLSAG counter of 0.
4. A template property over random mixed pools.
5. The fee/weight invariant for deploys.
6. Golden weights for 5 shapes.
7. A worst valid block timing (10/45).

### 5.8 Exact random-codeword count (22 W2; 4 versus 8 decided by 26): ACCEPT WITH CHANGES

- The per-(round, matrix, point) rule must derive any preprocessed-round exception **from the proof structure exactly as the 0.7 prover does**, not from a hard-coded "PX has none". The `zk::prove` path does build preprocessed data (`ProverData::from_instances`), and the FRI commit says preprocessed inputs exist. Settle this with a test.
- If 26 chooses 8, it is a new parameter set: `PARAMS_ID`, the fingerprint and P-5 all change. The decision must precede the kernel freeze and the golden proofs.

**Tests.**
1. Positive on every PX shape and on toy statements with and without a preprocessed table.
2. Mutation at **every** position: count ±1 and 0 in the first entry, the last matrix of the last round, and a multi-point entry. Rejected at decode, before any hashing.
3. The upstream-0.7-alone acceptance is asserted, so that an upstream change is noticed.
4. Decode-memory measurement (F22-7).

### 5.9 RX-presync sampling (31 S7): ACCEPT WITH CHANGES (two design gaps)

**The sampling argument itself holds** [math].
- With samples weighted by claimed difficulty and drawn with a local CSPRNG *after* the whole branch is committed, P(pass) ≤ r^s.
- Efraimidis–Spirakis A-Res samples **without** replacement. Successive draws only lower the conditional probability of hitting real work, so the bound holds (and is exact when fewer than s real headers exist).
- Under the 03 cap, work cannot concentrate faster than 1.02^k, which helps coverage.

**RT-8 (Medium, design): no protection for a fresh node at `MIN_CHAIN_WORK = 0`.**
- The threshold is `T = max(MIN_CHAIN_WORK, work(tip − 144))`. On a fresh node that is the genesis work.
- A free difficulty-1 branch exceeds T at once, so it never enters presync, and **d = 1 PoW is always valid** (`check_hash(·, 1)`). Sampling could not catch it even if it did.
- So 31's T-P1 ("a fresh node … zero hashes and zero stored headers for the hostile branch") cannot pass under the stated design with the planned launch value `MIN_CHAIN_WORK = 0`.
- **Fix:** on a fresh node (header tip below `MIN_CHAIN_WORK` or height ≤ 144), presync **every** peer's chain without PoW. Sample-verify, and redownload only the branch with the greatest claimed work. A free chain has little claimed work, and inflated claimed work fails sampling.
- Also set `MIN_CHAIN_WORK > 0` in every release after launch.

**RT-9 (Medium, design): dropping Bitcoin's redownload buffer is not justified.**
- Bitcoin's own rationale for the buffer is to stop "an attacker from using (eg) the honest chain to convince us that they have a high-work chain, but then feeding us an alternate set of low-difficulty headers" (`src/headerssync.h`).
- In RX-presync the attacker presyncs a **copy of the honest chain** at no cost of its own, so the sample gate passes. On redownload it then serves an alternate branch.
- With a keyed commitment only every K = 64 headers and "store as verified", up to K − 1 alternate headers are **RandomX-hashed and stored** per identity before the mismatch.
- The claim "the gate proves the attacker spent ≈T" is false in this scenario.
- **Fix, either of:**
  - a keyed 64-bit commitment **per header** (8 B/header, ≈2 MB per peer-year), checked **before** PoW, so zero hashes are wasted;
  - or keep a release buffer of ≥ 1 commitment period.

**Tests.**
1. T-P1 under the fresh-node fix.
2. "Honest-copy then switch": the switch at offsets 1, K−1, K, K+1 and within the final partial period. Assert 0 RandomX calls and 0 stored headers (per-header commitments), or ≤ the buffer bound.
3. r = 0.9 real work passes at ≈ 0.9^32 over 10^4 trials (`CountingPow`).
4. A single giant fake header carrying 50 % of the work is caught with probability ≥ 1 − 2^−32.
5. RNG independence: the sample set is unchanged if the peer alters unsampled bytes before commitment, and not predictable from peer-visible data.
6. The height bound is re-derived under the cap.
7. Fuzz of `PresyncState`.

## 6. New findings (summary table)

| ID | Severity | Status | Location | Scenario | Confidence |
|---|---|---|---|---|---|
| RT-1 | Medium | Not implemented | `consensus/src/chain.rs:322-327, 479-486`; `p2p/src/net.rs` `penalized`/`on_header_error`/`on_block`/`warn_unknown_upgrade` | Free unpenalized unknown-version spam; any peer triggers an "upgrade needed" warning | High |
| RT-2 | Medium (test gap, split-sensitive) | Complete but requires further testing | `chain/src/manager.rs:938-945`; `chain/tests/activation.rs` | Gate regression undetectable by the suite (transfers only) | High |
| RT-3 | Low | Not implemented | `consensus/src/schedule.rs:28`; `tx/src/params.rs:76` | An unsupported `verifier_id` is silently verified with verifier 1 | High |
| RT-4 | Low | Partially implemented | `tx/src/validate.rs:757-767` | Extension-only revalidation after a same-domain reorg; unused | High |
| RT-5 | Low | Not implemented | `wallet/src/wallet.rs` `refresh_pending` (9654d42) | A reorg below A after release gives a double payment if the rebuild uses other inputs | Medium |
| RT-6 | Info | Not implemented | `px-core/src/hash.rs:37-40` | False separation claim for multi-block sponge calls | High |
| RT-7 | Medium (evidence basis) | Complete but requires further analysis | dossier 19 §3.1; decisions R2-C6 | Basis overstated: Thm 1/2 inapplicable; Thm 3 adaptation (b)(c)(d) unproven; 122.6 is our evaluation | High |
| RT-8 | Medium | Not implemented (design) | dossier 31 S7 | A fresh node with `MIN_CHAIN_WORK = 0` hashes a free d = 1 branch; T-P1 unattainable | High |
| RT-9 | Medium | Not implemented (design) | dossier 31 S7 step 4 | Honest-copy presync then switch: ≤ 63 hashed and stored junk headers per identity | High |
| RT-10 | Low | Not implemented (design) | dossier 13 §3.3 step 9 | Dedupe by lowest index lets a small copy displace a large genuine output (Monero keeps the largest) | Medium |
| RT-11 | Info | Covered by 22 W4 / 23 W2 | `zkvm/src/prove.rs` `CIRCUIT_ID` | A forgotten bump gives no drift protection | High |
| RT-12 | Low (future) | Deferred | `tx/src/px.rs:767`; `validate.rs:245` | Verifier-1 constants in stateless rules at G2 | High |
| RT-14 | Info | Owner call | `tx/src/params.rs` `SigDomain` | No genesis in signatures; replay blocked only by state | Medium |
| RT-15 | Info | Docs | `wallet/src/wallet.rs` `check_network` | The genesis check trusts self-reported `/info` | High |

## 7. Implementation plan for phase 2

| # | Work | Files (owner) | Consensus? | Identity | Tests | Size | Priority |
|---|---|---|---|---|---|---|---|
| 1 | RT-2 PX cache-gating tests (predicate factored out) | `chain/src/manager.rs` (34/10), `chain/tests/activation.rs` | none | none | §3 RT-2 | S | **P0** |
| 2 | RT-1 PoW-before-benign `UnknownUpgrade`; disconnect count; warning threshold | `consensus/src/chain.rs` (01), `p2p/src/net.rs` modules (30/31 after the split) | policy (verdict unchanged) | none | §3 RT-1 | S–M | P1 (P0 for a public testnet) |
| 3 | RT-3 supported-verifier assertion; `verifier_id` in `TxRules` | `tx/src/params.rs` (11), `node/src/main.rs` (node owner) | none | none | unsupported-id refusal | S | P1 |
| 4 | RT-4 delete `revalidate_between` (or add a reorg flag) | `tx/src/validate.rs` (11), `tx/tests/upgrade.rs` | none | none | reorg case if kept | S | P2 |
| 5 | RT-5 stale rebuild spends the same key images, or reservation until A + 60 | `wallet/src/wallet.rs` (37/38) | none | none | e2e reorg below A | M | P1 |
| 6 | RT-6 and RT-7 docs corrections (hash.rs comment, px.md/zk.md tree argument per §4.6) | `px-core/src/hash.rs` (comments only; verify ELF id), `docs/px.md`, `docs/zk.md` (19/47) | none | none (reproduce.sh) | ELF id unchanged | S | **P0** (before the freeze text) |
| 7 | Written Thm-3 adaptation note (a) reduction; (b)(c)(d) proof delta | `docs/reviews/` new note (19 with 50 review) | none | none | — | M | P1 |
| 8 | RX-presync redesign items RT-8/RT-9 before implementation | dossier 31 design, `p2p/src/presync.rs` (31) | policy | none | §5.9 | M | P1 (public testnet) |
| 9 | Adversarial test sets §5.1–5.8 attached to each owner's work item | per owner (13, 03, 20, 28, 11/21, 15, 14/10, 22) | as decided | as decided | as listed | — | with each item |
| 10 | RT-10 dedupe rule "largest amount" | `wallet/src/wallet.rs` (17/13) | none | none | §5.1 test 4 | S | P1 |

- **Benchmarks:** none of my own. 5.2 needs `tools/daa-sim` runs, and 5.7 needs the worst-block timing.
- **Docs:** `docs/p2p.md` (the `UnknownUpgrade` policy) and `docs/reviews/v3-upgrade-mechanism.md` (RT-3, RT-4, RT-5 notes).

## 8. Dependencies and conflicts

- **01:** `chain.rs` validate order (RT-1); golden vectors after 5.2 and 5.6.
- **03:** hopper criteria (5.2).
- **10, 11, 12, 14:** `validate.rs`, `mempool.rs` select (5.7, 5.5, 5.4).
- **13 and 17:** dedupe rule (5.1).
- **19:** §4.6 corrections.
- **20 and 43:** the single kernel rebuild (5.3).
- **22, 25 and 26:** codeword count and `COLLISION_BITS` (5.8, §4.6).
- **28:** PX6 and ABI (5.4).
- **30 and 31:** RT-1, RT-8, RT-9.
- **34:** manager predicate (RT-2).
- **37 and 38:** RT-5.
- **40:** fingerprint rule revisions.
- **46:** the `net.rs` split precedes RT-1.

## 9. Open questions for the coordinator

1. Does strong extractability imply position-binding in 2026/089's definitions? If not, the docs must claim "extractable" and not "binding" for `Hk` trees until the adaptation is written.
2. Should RT-14 (genesis id in `SigDomain`) ride the v3 reset? It costs nothing now, and a change later needs an activation.
3. RT-9: per-header commitments (my preference: zero wasted hashes) or Bitcoin's buffer?
4. RT-1 (a): accept that old nodes see `InsufficientWork` rather than `UnknownUpgrade` for a future PoW change?

## 10. Sources

- Coratger, Khovratovich, Mennink, Wagner. *The Billion Dollar Merkle Tree.* IACR ePrint 2026/089 (rev. 2026-07-22), ACM CCS 2026. https://eprint.iacr.org/2026/089 ; PDF https://eprint.iacr.org/2026/089.pdf ; versions https://eprint.iacr.org/archive/versions/2026/089 . Thms 1–3, Remarks 1–6, §6, App. C.
- Bitcoin Core `src/headerssync.h` (redownload buffer rationale). https://github.com/bitcoin/bitcoin/blob/master/src/headerssync.h ; PR #25717 (headers presync).
- Bitcoin Core unknown-versionbits warning: PR #16713. https://github.com/bitcoin/bitcoin/pull/16713 ; `src/validation.cpp`. https://github.com/bitcoin/bitcoin/blob/master/src/validation.cpp
- Monero, "A Post Mortem of The Burning Bug" (2018-09-25). https://web.getmonero.org/2018/09/25/a-post-mortum-of-the-burning-bug.html ; wallet2 fix PR #3985. https://github.com/monero-project/monero/pull/3985
- ZIP 203, Transaction Expiry. https://zips.z.cash/zip-0203 ; zcashd expiry and activation discussion: https://github.com/zcash/zcash/issues/4132 , https://github.com/zcash/zcash/pull/2874 ; Zcash Network Upgrade Guide (branch id in signatures). https://zcash.readthedocs.io/en/latest/rtd_pages/nu_dev_guide.html
- Efraimidis, Spirakis. *Weighted random sampling with a reservoir.* IPL 97(5), 2006 (A-Res, without replacement).
- Bitcoin Cash Node, aserti3-2d specification. https://upgradespecs.bitcoincashnode.org/2020-11-15-asert/ (via dossier 03).
- Dossiers 03, 10, 11, 13, 14, 15, 19, 20, 21, 22, 28 and 31 (C:/bszkeval/p2/research), for the proposals under review.
