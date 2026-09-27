# 17 stealth-janus: research dossier (phase 2, phase 1)

Agent 17, 2026-09-27. This is read-only research. No files in the repository were changed, and no builds or tests were run.
This is internal engineering work, not an audit. Nothing here claims that BlackSilk is secure.

---

## 1. Scope and what I read

**Commit:** `9e422d8` on `rebuild/core`.

**Code, read in full:**
- `crypto/src/stealth.rs` (536 lines), including the tests
- `crypto/src/janus.rs` (474 lines), including the attack tests A1–A9
- `crypto/src/keys.rs` (328 lines)
- `crypto/src/hash.rs`: the tags, the helpers and the KAT test
- `tx/src/scan.rs`

**Code, the relevant parts:**
- `tx/src/builder.rs`: `make_output`, the transfer and coinbase hedges, `build_coinbase`
- `tx/src/px_builder.rs`: `make_output`
- `tx/src/px.rs`: `output_context`, `check_px_structure`, `check_px_balance`
- `tx/src/validate.rs`: T6, C4 (`check_uniqueness_of`), the coinbase rules at 918–937, and the block-wide sets at 1027–1049
- `wallet/src/wallet.rs`: `rebuild_table`, `extend_window`, `note_used`, `try_address` and `apply_block` (1086–1170)
- `px/src/delivery.rs`: the module docs and key derivation, for the PX side of the Janus principle
- `crypto/Cargo.toml`

**Tests read:**
- `crypto/src/stealth.rs::tests`: 7 tests
- `crypto/src/janus.rs::tests`: 12 tests
- `crypto/src/keys.rs::tests`: 6 tests
- `tx/tests/adversarial.rs::janus_probe_on_chain_is_refused_by_the_victim` (A10)
- `tx/tests/privacy.rs`: the view-only equivalence test, `repeated_payments_are_unlinkable_on_chain`, and the broken-RNG hedge test
- `fuzz/fuzz_targets/*`: there is no scan target

**Docs read:**
- `docs/transactions.md` §1–3, §9, §11–16 (the whole of §12)
- `docs/px.md` §11
- `docs/contracts.md` ctx lines
- `docs/reviews/full-review-2026-09-27.md`: the Janus, C4, D8 and never-change entries
- `docs/reviews/autonomous-session-2026-09-27.md`: status of R2-C1, C3, C4, C10, C13, C14
- `full-review-2026-09-27/R2-crypto.md` §3 and the Q table
- `SX1-core-crossreview.md` §2 (the C4 options and their corrections)
- `R6-tx-mempool.md` MP-7
- The `R11-wallet.md` Janus and view-tag parts
- `R3-privacy.md`, the Carrot references
- Roster entries 13, 15–19, 37–39 and 41

**Primary sources studied** (full list in §8):
- The Carrot specification (jeffro256/carrot, `carrot.md`)
- The full LaTeX source of the Cypher Stack review "An Audit of the FCMP++ Addressing Protocol: CARROT" (Goodell, Salazar, Slaughter), `cypherstack/carrot-audit/latex/main.tex`
- The Jamtis specification (tevador)
- The Monero burning-bug post-mortem (2018)
- The Monero Janus disclosure (2019)
- MRL issue #73 (view tags)
- The status of the FCMP++/Carrot stressnet

---

## 2. Current state

### 2.1 What exists

**Addresses** (`keys.rs`):
- Formulas: `m(a,i) = Hs("subaddress", k_v ‖ LE32 a ‖ LE32 i)` (0 for the primary address), `D = K_s + m·G`, `C = k_v·D`.
- Every address, the primary one included, has the uniform form `(D, k_v·D)`.
- `ViewKeys = (k_v, K_s)` can derive every address.

**Outputs** (`stealth.rs`, `janus.rs`). Each output gets its own anchor and its own `R`:
- `r = Hs("ephemeral", anchor ‖ ctx ‖ D ‖ C)`, `R = r·D`, `S = r·C = k_v·R`
- `x = Hs("output-key", S)`, `O = x·G + D`
- `view_tag = H32("view-tag", S)[0]`
- `y = Hs("mask", S)`
- `enc_amount` and `enc_anchor` are XOR pads from `H64(·, S)`

**Scan** (`scan_output`), in order:
1. `S = k_v·R`
2. view tag
3. `D' = O − xG`
4. table lookup
5. Janus check `Hs(anchor' ‖ ctx ‖ D' ‖ C')·D' == R` (constant-time `ct_eq`, identity refused)
6. amount/commitment check (hidden amounts only)

**Contexts:**

| Kind | Context |
|---|---|
| Transfer | `H32("input-context", key images)` |
| Deploy (kind 3) | the same function as a transfer (`scan.rs:69-75`) |
| PX | `H32("input-context/px", nullifiers ‖ key images)` |
| Coinbase | `H32("input-context/coinbase", LE64 height)` |

**Wallet:**
- `scan_block` sorts outputs into `owned` and `rejected` (`scan.rs:32-37,80-94`).
- `apply_block` stores only `owned`, deduplicated by `global_index` (`wallet.rs:1113-1117`).
- `rejected` is never read (`wallet.rs:1150`).
- The gap-limit window moves on owned outputs only (`note_used`).

### 2.2 What is correct and well designed

1. **Lemma 1 holds unconditionally:** an accepted output is byte-for-byte the honest construction for the recognised address.
   - Evidence: mathematically established (re-derived below, §3.1). Tested by `janus::tests::accepted_outputs_are_honest_constructions`, over 64 random honest and adversarial rounds.
2. **Janus resistance.** A probe built through address `a` and aimed at `b` is refused.
   - Tested:
     - A1 `classic_janus_is_detected`: the legacy recogniser accepts the probe, and the Janus scan refuses it
     - A2, A3, and A4 (all 12 ordered pairs of primary, same-account and cross-account addresses)
     - A5 `outcome_is_independent_of_address_linkage`
     - A6 view-only
     - A7: every one of the 128 anchor bits
     - A9 coinbase
     - A10 on chain (`tx/tests/adversarial.rs:569`)
   - The reduction to DL is established mathematically (§3.1).
3. **Cross-transaction copies are refused.** A copied `(R, O, enc_anchor, …)` in another transaction fails step 5, because `ctx` differs. Tested by `wrong_context_is_rejected`, and A8 `recipient_recovers_ephemeral_secret`.
4. **Contexts are unique on chain.** Every context is unique per transaction:
   - transfers and deploys: key images are globally unique under C2, across all transaction kinds;
   - PX: two nullifiers, unique under PX2, plus an explicit `nullifiers[0] != nullifiers[1]` check (`px.rs`);
   - coinbase: consensus enforces `coinbase.height == ctx.height` (`validate.rs:918`).

   Evidence: source-read.
5. **Uniform addresses and a per-output `R`.**
   - No transaction reveals whether it pays a primary address or a subaddress. Tested by `privacy.rs::output_encoding_does_not_depend_on_recipient_type`.
   - This is strictly better than Monero, where the additional tx keys flag a subaddress payment. Carrot uses `D_e = d_e·G` for main addresses and `d_e·K_s^j` for subaddresses, and relies on X25519 indistinguishability instead.
   - Evidence: source-read, and the Carrot spec §7.5.
6. **Observer privacy of the anchor.**
   - `enc_anchor` is uniform to observers, even with a constant anchor. Tested by `enc_anchor_is_uniform_to_observers`, a bit balance over 2,048 outputs.
   - It depends on CDH in the ROM (assumed; standard).
7. **Hedged anchors.** Anchors come from a hedged stream bound to the whole statement (R2-C1 and C3 were fixed in `b7d0d3a`). Tested by `privacy.rs::broken_rng_transfers_over_the_same_inputs_share_no_output_secrets`.
8. **Constant-time handling and redaction.**
   - `S = k_v·R` uses dalek's constant-time variable-base multiplication (source-read).
   - The early exits on the view tag and the table lookup leak only local timing (source-read).
   - `Debug` redacts the mask and the offset. Tested by `debug_output_redacts_secrets`.
9. **Rejected outputs have no effect on the wallet.** They are ignored, and they move no window, fetch nothing and change no balance.
   - Evidence: source-read of `apply_block`.
   - No test asserts that the wallet state is identical to the state after receiving a foreign output (gap F17-3).

### 2.3 What the tests do NOT prove

- **Nothing pins the derivations to fixed bytes.**
  - Every stealth test is a round trip: sender and receiver in the same build. A consistent change to both sides passes every test.
  - `hash.rs::kat_matches_definition` pins only the hash helper.
  - `clsag.rs` has pinned hex vectors. Keys, subaddresses, contexts, outputs, view tags and anchors have none (F17-1).
- **No property or fuzz test mutates every output field.** The A-tests mutate `enc_anchor`, `R`/`r` and `ctx` in structured ways. `O`, `Cm`, `view_tag`, `enc_amount` and the amount kind are not mutated in general (F17-11).
- **"Scan binding" is untested.** No test checks that two different wallets never both accept one output.
- **No test covers duplicate `O` in the wallet.** No test gives the wallet two outputs with the same `O`. Consensus C4 hides the gap today (F17-2).

---

## 3. Problems in scope

### 3.1 Written security argument (the roster's "Accept" item)

**Model.**
- **Adversary:** knows any set of public addresses and can put any consensus-valid outputs on chain. It knows neither `k_v` nor `k_s`.
- **Assumptions:** hashes are random oracles, and DL/CDH is hard in Ristretto255, a prime-order group, so no torsion is possible.
- **Wallet:** conforms to §12.5, so rejected outputs behave exactly like foreign ones.

**(A) Correctness.** Honest outputs to owned `j` pass steps 1–6. Tested by the round-trip tests.

**(B) Lemma 1 (unconditional).**
- Acceptance at `j` means `R = r'·D_j` with `r' = Hs(anchor' ‖ ctx ‖ D_j ‖ C_j)`.
- So `S = k_v·R = r'·C_j`.
- The fields `O` (step 4), `view_tag` (step 2), `Cm` (step 6, with `y = Hs("mask", S)`; for clear amounts `Cm = G + aH` is fixed by consensus), `enc_amount` and `enc_anchor` then all equal the output of `Construct(D_j, C_j, a, ctx, anchor')`.
- Canonical Ristretto encodings make "equal" mean "equal as bytes".

**(C) Janus resistance.**
- Suppose a probe routed through address `a` (the adversary knows `S = r·C_a` only via `R = r·D_a`) is accepted at `b ≠ a`.
- By (B), `R = r_b·D_b` with `r_b = Hs(anchor' ‖ ctx ‖ D_b ‖ C_b)`.
- So `r·D_a = r_b·D_b`, i.e. `D_b = (r/r_b)·D_a`.
- The adversary knows `r`, and fixes `r_b` by choosing `anchor'` (each choice is one RO query). It therefore finds a known scalar `t` with `D_b = t·D_a`, i.e. `m_b − m_a = (t − 1)(k_s + m_a)`.
- That is a discrete-log relation between two keys whose offsets are secret RO outputs. Each query succeeds with probability `1/ℓ`, so total success is at most `q/ℓ` in the ROM, and otherwise requires DL.
- Unlike Carrot's special-anchor path, the check here is a group equation, not a XOR-of-hashes equality. The Wagner/generalised-birthday caveat that Cypher Stack raised against Carrot (audit §4, "Janus (or Pordo) Attack Resistance", aside) therefore does not arise, because BlackSilk has no special anchor.
- **Conclusion.** Acceptance happens iff `o` is an honest construction for an owned `j`. Theorem 1 as stated in `docs/transactions.md` §12.4 follows, within the reaction model.

**(D) Burning-bug resistance at wallet level, independent of C4.** This is new here. The docs attribute it to "ctx binding + C4".
- Let `o_1`, `o_2` be two on-chain outputs with the same `O`, both accepted by one wallet at `j_1`, `j_2`, in contexts `ctx_1`, `ctx_2`.
- **Case `j_1 = j_2 = j`:**
  1. `x_1 = x_2`, so `S_1 = S_2` (except for an `Hs` collision), so `R_1 = R_2` (`k_v` is invertible), so `r_1 = r_2` (`D_j ≠ 0`, prime order).
  2. Therefore `(anchor_1, ctx_1) = (anchor_2, ctx_2)` (except for an `Hs` collision).
  3. Equal contexts mean the same transaction (§2.2 item 4).
  4. So both outputs sit in one transaction with the same `O`. T6 (`validate.rs:334`), the coinbase rule (`validate.rs:936`) and `PxDuplicateOutputKey` (`px.rs:684-693`) reject that statelessly.
- **Case `j_1 ≠ j_2`:**
  1. `x_1·G + D_1 = x_2·G + D_2` means `x_1 − x_2 = m_2 − m_1`.
  2. Here `x_i` are RO outputs the adversary learns only as sender, and `m_2 − m_1` is secret. The probability is at most `q²/ℓ`.
- **Conclusion:**
  - A wallet that runs the Janus check is burning-bug-safe with **intra-transaction** `O` uniqueness alone.
  - Global C4 is a backstop only for wallets that skip the check.
  - This formally supports SX1's "correction 1 is mandatory; B and C are otherwise equal" for roster 13. Once C4 is relaxed, the intra-transaction rule is the **only** consensus rule the argument needs. It must never be dropped.
- **Carrot comparison.** Carrot obtains the same property differently:
  - the view tag binds `input_context ‖ K_o`;
  - `k_o` binds `s_sr_ctx ‖ C_a`;
  - `k_a` binds `a ‖ K_s^j ‖ enote_type`.

  Cypher Stack's proof (audit, "Burning Bug Resistance") uses the view-tag mismatch plus the `C_a` re-derivation.

**(E) Why keying `x`, `y` and `view_tag` on `S` alone is acceptable here but was not in Carrot.**
- **Carrot:** a 2-out transaction shares one `D_e`, hence one `s_sr`, between two enotes, and has an internal/special self-send path. Carrot must therefore bind per-enote data (`K_o`, `C_a`, `enote_type`, `K_s^j`) into each derivation to keep enotes distinct.
- **BlackSilk:** every output has its own `R`. Honest outputs never share `S`. A dishonest shared `R` to a different address fails (C), and to the same address yields the same `O`, which T6 rejects.
- The only cost of the `S`-only view tag: a *copy* of an owned output passes the view tag and the lookup, and is refused one scalar multiplication later. In Carrot it would be dropped at the tag. The copier pays a fee per copied output, so this is a bounded, local cost (F17-9).
- Evidence: mathematically established, together with the Carrot spec §7.3.4/§7.4.1 and the audit "Enote Scan Binding"/"Burning Bug Resistance" sections.

**(F) Scan binding.**
- For two wallets to accept the same output, the sender needs `D_2 − D_1 = (x_1 − x_2)·G` and `r_1·D_1 = r_2·D_2`. Both are DL relations between unrelated wallets' keys, so this is infeasible.
- This matches the audit's "Enote Scan Binding". There is no test (F17-11).

**(G) Limits of the argument (the gaps).**
1. **Reaction model.** Theorem 1 fails the moment anything observable depends on `Rejected` versus `NotOwned`: a UI badge, a log shipped off-box, an RPC field, a webhook, or a window move.
   - Today nothing does, but only by convention. `ScanReport::rejected` is `pub` and `Debug`, and `ScanOutcome::Rejected` even carries the matched `subaddress` (F17-3).
2. **Window scope.** "Owned `j`" means "`j` is in the current lookahead window". A probe to an index beyond the window is `NotOwned`, which is consistent: it reveals nothing, and honest payments there are not seen either.
3. **Uniqueness of `D` in the table.** Collisions between table entries have probability about 2^-252 (hash collision of `m`). `insert` silently overwrites on collision (F17-7).
4. **Post-quantum.** With DL, any single address gives `k_v = log_D C`, which exposes the whole wallet's incoming view. The Janus question then becomes moot (R2 §11). `docs/transactions.md:839` still understates this (F17-5).
5. **Scope.** This is an internal argument, not peer-reviewed. The Carrot review does not transfer, because the construction differs in (C), (D) and (E).

### 3.2 Problem: no pinned vectors for v1 derivations (F17-1)

- **Why it exists.** Tests were written as round trips, and CLSAG received vectors but the stealth layer did not.
- **Consequence.** A refactor can change a derivation consistently on both sides, for example:
  - the part order in `ephemeral_secret`;
  - a tag spelling;
  - `h32` versus `h64` for the view tag;
  - the LE32 order in `subaddress_offset`.

  Every test would pass. After the testnet launches, every existing output would become unscannable by new wallets, and every restored seed would produce different addresses. Funds would not be lost cryptographically, but they would be invisible without the old build.
- **Classification.** Consensus-adjacent (it is wallet-interoperability- and never-change-critical, item 10 of the never-change list), not consensus.
- **Prior art.**
  - Zcash specifies test vectors for every key and note derivation (the zcash-test-vectors repository, used by ZIP 32/316 implementations).
  - Monero's `tests/crypto` carries fixed vectors for `derive_public_key`, `generate_key_derivation` and `derive_subaddress_public_key`.
  - Carrot's reference implementation (`carrot_core`) ships unit vectors.
- **Fix and trade-offs.**
  - Pin vectors generated from the current code, and in the same test re-derive them independently from the spec formulas using raw `blake2` + dalek, in the style of `kat_matches_definition`.
  - Pinned bytes alone would only freeze today's behaviour, bugs included. The independent re-derivation cross-checks it against the spec.
  - Risk: none externally visible.
- **Tests that prove it.** The new vector file fails on any change to a derivation.
- **Invariant.** The derivation formulas and tags must never change after the testnet launches without a seed/format version.

### 3.3 Problem: the wallet has no duplicate-`O` rule (F17-2)

- **What.** `apply_block` deduplicates by `global_index` only (`wallet.rs:1113-1117`). Two outputs with the same `O` at different indices would both be credited, and share one key image.
- **Why it has not bitten.** C4 forbids a duplicate `O` chain-wide, and the node is trusted.
- **Consequences:**
  - If D8 chooses option B (drop C4) or C (pair-keyed), the wallet becomes the only line besides intra-transaction uniqueness. §3.1(D) shows that the Janus check already prevents crediting both unless they are in one transaction, and consensus blocks that case.
  - The residual risks are a regression in the intra-transaction rule, or a malicious or buggy node serving an invalid block. The wallet does not verify blocks.
  - Monero's post-2018 wallet keeps only one output per key image, the largest amount (post-mortem; Cypher Stack audit §2 "Burning Bug").
- **Classification.** Privacy- and funds-safety defence in depth. The change is wallet policy only.
- **Fix.** Credit at most one stored output per `one_time_key`, which equals one per key image. On a duplicate, keep the existing one, never add a second, and log it locally only.
- **Test.** A wallet unit test that feeds a synthetic `Block` (built without validation) with two outputs sharing `O`: the balance counts one.
- **Invariant.** There is exactly one credited output per key image.

### 3.4 Problem: Theorem 1 relies on convention (F17-3)

- **What.** The public API exposes `ScanReport::rejected`, and `ScanOutcome::Rejected { subaddress, .. }`. The subaddress field is the linkage bit itself: "the probe matched my index `j`".
- **Consequence.** A third-party wallet, a future GUI or a debug log shipped to telemetry voids Theorem 1. The Monero Janus disclosure's attack precondition is exactly "the entity confirms off-chain".
- **Classification.** Privacy-critical, but only through misuse.
- **Fix options:**
  - (a) Drop `subaddress` from `Rejected`, and make `rejected` a count or keep it behind an explicit `diagnostics()` accessor documented as local-only.
  - (b) Put the diagnostics behind a cargo feature.
  - (c) Keep the API and add tests only.

  Recommendation: (a) plus tests. This is cheap and internal; the only consumers are two tests.
- **Test.** Observational equivalence:
  - Apply block X, containing a Janus probe at `b` via `a`, and block Y, identical except that the probe goes to a stranger.
  - Assert that the serialised wallet state (outputs, balance, `issued`, table length, history, pending) is identical.
  - Also assert that a probe aimed at the window edge does not extend the window.

### 3.5 Problem: documentation that disagrees with the implementation or with prior art (F17-4, F17-5, F17-6)

- `transactions.md:1040` credits the idea to "the Jamtis 'Janus anchor'".
  - Jamtis defends by an encrypted address tag and `j` in the secondary secret (Jamtis spec §2.5; Cypher Stack audit §2 "Janus Attack").
  - The encrypted anchor that re-derives the ephemeral key is **Carrot's** (Carrot §7.4, §7.7).
- `transactions.md:180-185` says ctx binding prevents the burning bug "by construction". Against a malicious sender, the protection is the §12 check re-deriving `r` with the *including* transaction's ctx, plus intra-transaction `O` uniqueness (§3.1 D). The R2 §3.1 item 3 request for a written Carrot-delta rationale is still open.
- §3.1 lists only the transfer and coinbase contexts. It should also give PX and deploy. The deploy uses the transfer function, and `contracts.md:322`'s `input-context/deploy` belongs to the non-integrated Wasm engine, which is a source of confusion.
- `transactions.md:839` (§11.6): see §3.1 G4 above.
- `crypto/Cargo.toml:11`, "audited by Quarkslab (2019)", contradicts `transactions.md` §1.1, which deliberately does not claim an audit. This is claim hygiene.

### 3.6 Deviation: view tag size (1 byte, from `S`)

- **Carrot** uses 3 bytes, "because of Jamtis requirements" (Carrot §7.3.4), i.e. indistinguishability from Jamtis. That is not a security need.
- **Monero** uses 1 byte (MRL #73).
- **In BlackSilk** the tag is keyed on `S`, which only the sender and the `k_v` holder know, so it leaks nothing further.
- **Conclusion.** Keep it. A change is a format change with a negligible gain: `k_v·R` dominates the scan.
- Status: Accepted limitation (F17-9).

### 3.7 Deviation: a single view secret, no tiers

- **Carrot** separates:
  - `s_ga` (generate addresses);
  - `k_v` (view received);
  - `s_vb` (view all, internal enotes).
- **BlackSilk** uses `k_v` for both address generation and ECDH. Change outputs are ordinary outputs, so a view-key holder sees change, and with it the fact and approximate size of outgoing payments.
- This is a design limitation, not a bug. It belongs to roster 37 (key hierarchy). Status: Accepted limitation (F17-10).

---

## 4. New findings

| ID | Severity | Status | Location | Scenario | Confidence |
|---|---|---|---|---|---|
| F17-1 | **Medium** | Not implemented | `crypto/src/{keys,stealth,janus}.rs` (no vector tests); `docs/transactions.md` §16 | A refactor reorders `ephemeral_secret` parts. All round-trip tests pass. Post-launch wallets can no longer scan earlier outputs or restore earlier addresses. | High |
| F17-2 | **Low** (becomes a **P0 companion** if D8 picks B or C) | Not implemented | `wallet/src/wallet.rs:1113-1117` | A block (from a malicious node, or on a chain where C4 was relaxed and the intra-transaction rule regressed) carries two outputs with the same `O`. Both are credited, the balance is overstated, and the key image is shared, so one output is burned. | High |
| F17-3 | **Low** | Partially implemented (the wallet ignores it; no guard) | `tx/src/scan.rs:32-37,83`; `crypto/src/stealth.rs:224-227` (`Rejected{subaddress}`) | An integrator or GUI shows "suspicious output at subaddress j". The Janus linkage bit returns and Theorem 1 is void. | High |
| F17-4 | **Low** (docs) | Not implemented | `docs/transactions.md:180-185`, `:1040`, §3.1 missing PX/deploy, §12.4 D-uniqueness | Reviewers are misled about prior art and the source of burning-bug safety. The Carrot-delta rationale (R2 §3.1) is still unwritten. | High |
| F17-5 | **Low** (docs, carried from R2-C14) | Not implemented | `docs/transactions.md:839` | Understates DL impact: `k_v = log_D C` from any address. | High |
| F17-6 | **Informational** | Not implemented | `crypto/Cargo.toml:11` | Audit claim in a manifest comment contradicts the no-claim policy. | High |
| F17-7 | **Informational** | Not implemented | `crypto/src/keys.rs:231-234` | `insert` overwrites silently on a `D` collision (about 2^-252, or a bug in `m`). There is no assertion. | High |
| F17-8 | **Informational** (= R2-C13) | Accepted limitation | `crypto/src/stealth.rs:55-59` | Unprefixed nullifier/key-image split in `px_context`, about 2^-248. | High |
| F17-9 | **Accepted limitation** | Accepted limitation | `crypto/src/stealth.rs:66-68,248` | A copied owned output passes the tag and lookup and costs the victim one extra scalar multiplication. The copier pays a fee per output. | High |
| F17-10 | **Accepted limitation** | Deferred (to 37) | `crypto/src/keys.rs` | No generate-address, view-received or view-all tiers. A view key reveals change. | High |
| F17-11 | **Low** (test gap) | Not implemented | `crypto/src/janus.rs` tests; `fuzz/fuzz_targets/` | No general field-mutation property test, no scan-binding test, no scan fuzz target. Lemma 1 is tested only on structured probes. | High |

**Challenges to existing reports:**
- **R2 §3.1 item 3 and SX1 §2.** They credit burning-bug safety to "anchor plus C4". §3.1(D) shows that C4 is not needed for Janus-checking wallets: only intra-transaction `O` uniqueness is. This strengthens option B and makes correction 1 the single non-negotiable piece.
- **`docs/transactions.md` §12.8.** It attributes the construction to Jamtis. Primary sources show it is Carrot's mechanism.
- **R2's "Janus anchor matches Carrot's".** It matches in idea but not in derivation structure: BlackSilk has no special or internal anchor and uses a per-output `R`. The Cypher Stack proofs therefore do not carry over verbatim. The aside in (C) shows that BlackSilk avoids one weakness the audit noted in Carrot.

---

## 5. Implementation plan for phase 2

| # | Item | Files (ownership) | Visibility | Identity impact | Tests | Docs | Diff. | Prio |
|---|---|---|---|---|---|---|---|---|
| 1 | **Pinned v1 derivation vectors plus an independent spec re-derivation.** Seeds → `k_s`, `k_v`, `K_s`; `m`, `D`, `C` for (0,0), (0,1), (1,0), (7,3); the transfer, PX and coinbase contexts; `create_output` for a fixed anchor (every field); view tag; scan result; one-time secret; key image of that output. | new `crypto/tests/stealth_vectors.rs` | Nothing external | None (pins existing behaviour) | Vector test; spec-formula re-derivation with raw `blake2`/dalek | `transactions.md` §16 item 2: list the vectors | S | **P0** (before seeds exist in users' hands) |
| 2 | **Wallet: one credited output per `one_time_key`/key image.** Keep the first, never add a duplicate, log locally only. | `wallet/src/wallet.rs` (`apply_block` plus a unit test) | Wallet policy | None | Synthetic block with a duplicated `O`: balance counted once; spend marks both | `transactions.md` §12.5 (normative "must dedupe by key image") | S | **P0 if D8 = B or C**, otherwise P1 |
| 3 | **Enforce the Theorem 1 reaction model in the API.** Remove `subaddress` from `ScanOutcome::Rejected`; turn `ScanReport::rejected` into a documented local-only diagnostic (count, or accessor). | `crypto/src/stealth.rs` (enum), `tx/src/scan.rs`, fix-ups in `tx/tests/adversarial.rs` | Nothing external (internal API) | None | Wallet observational-equivalence test (probe versus stranger output: identical serialised state); window-edge probe does not extend the window | §12.5 | S | P1 |
| 4 | **Property tests for Lemma 1, scan binding and burning-bug resistance.** Seeded loops, per project style. (a) Mutate each field (`O`, `R`, `view_tag`, `Cm`, `enc_amount`, `enc_anchor`, ctx, amount kind) of random honest outputs: never `Owned` unless the rebuild equals the output. (b) Two random wallets never both accept an output, including cross-built probes. (c) A copy into another ctx is never `Owned`; the same-ctx duplicate is rejected by T6 and by `PxDuplicateOutputKey` (tx-level). (d) Table uniqueness over 2×1,050 entries including primary. | `crypto/src/janus.rs` (tests module) or new `crypto/tests/janus_properties.rs`; `tx/tests/adversarial.rs` | Nothing | None | As listed | §12.6 table rows A11–A14 | M | P1 |
| 5 | **Docs: written security argument and Carrot delta.** Replace the §12.8 attribution; add §3.1(D)/(E) as §12.4 additions; fix §3.1 wording and add the PX/deploy contexts; correct §11.6 (`k_v` from any address); remove the Cargo.toml audit claim. | `docs/transactions.md` §3.1, §11.6, §12.4, §12.8, §14; `crypto/Cargo.toml:11` | Nothing | None | — | as listed | S | P1 |
| 6 | **Fuzz target `scan_output`.** Arbitrary canonical points and bytes, random table: no panic, and `Owned` implies an honest rebuild. | new `fuzz/fuzz_targets/scan_output.rs`, `fuzz/Cargo.toml` (coordinate with 41) | Nothing | None | Fuzz | fuzz README | S | P2 |
| 7 | **`SubaddressTable::insert` collision assertion.** Assert (debug and release) if an existing entry maps to a different index. | `crypto/src/keys.rs` | Nothing | None | Unit test | — | S | P2 |
| 8 | **Carrot-style tiers, 3-byte tag, internal/self-send enotes.** Research only; **not** for the testnet. | — | Would be a format and consensus change | Would change addresses | — | §15 | XL | P3 |

- **Benchmarks:** none required. Optionally, measure the per-output scan time before and after item 3 to confirm it is unchanged.
- **Consensus:** none of items 1–7 changes consensus. The derivations, contexts, anchor size and check order must stay exactly as they are.

**Invariants that must never change:**
- the derivation formulas and tags, and the four ctx definitions;
- the 16-byte anchor;
- the Janus check before the amount check;
- `Rejected ≡ NotOwned` in every externally observable behaviour;
- intra-transaction `O` uniqueness across outputs ∪ payouts (T6, the coinbase rule, `PxDuplicateOutputKey`), whatever D8 decides;
- the uniform `(D, k_v·D)` address form;
- the per-output `R`;
- the identity checks on `R` and `O`.

---

## 6. Dependencies and conflicts

- **13 mempool-frontrunning-c4.** §3.1(D) is direct input to the D8 decision, and item 2 must land in the same change if B or C is chosen. 13 owns `tx/src/validate.rs` and `chain/src/mempool.rs`; I touch neither.
- **18 crypto-randomness.** Anchor hedging (`make_output` in `builder.rs`/`px_builder.rs`) is theirs. My argument assumes independent anchors only for honest-sender properties.
- **19 hash-domain-separation.** They own the tag registry. My vectors (item 1) pin tags from the other side. The `px_context` split (F17-8) is theirs to record.
- **37 wallet-keys.** Tiered keys (F17-10) and the seed format. Vectors from item 1 must be regenerated if 37 introduces a seed version. Coordinate so that item 1 lands after 37's derivation decision, or pins the v1 derivation explicitly as "seed version 1".
- **38 and 39 wallet-privacy / wallet-sync-scanning.** Both touch `wallet/src/wallet.rs`. Items 2 and 3 edit `apply_block`: serialise with them.
- **41 fuzzing-property-stateful.** Item 6, and the property style (seeded loops versus proptest).
- **47 docs-spec-consistency.** Owns `docs/transactions.md` overall. Item 5 needs a merge order.
- **48 threat-model-adversarial.** The reaction-model gap belongs in the attack tree.
- **49 innovation.** A Carrot-style tier redesign, if ever considered.

---

## 7. Open questions for the coordinator

1. **D8 (C4):** which option? It decides whether item 2 is P0.
2. May phase 2 change the internal API `ScanOutcome::Rejected` and `ScanReport::rejected` (item 3)? No external consumers exist.
3. **Test style:** add `proptest` as a dev-dependency of `crypto`, or keep seeded loops (the current convention, `transactions.md` §16.6)?
4. **Vector timing:** pin the v1 derivations now? They are on the never-change list, so pinning now is safe. Or wait for 37's seed-version decision?
5. **Ownership of `docs/transactions.md` §3/§12:** 17 or 47?

---

## 8. Sources

- J. Berman (jeffro256), *Carrot (Cryptonote Address For Rerandomizable-RingCT-Output Transactions)*, specification: https://github.com/jeffro256/carrot/blob/master/carrot.md. Sections used: §5.2 key hierarchy, §6.1.3 subaddresses, §7.2 input_context, §7.3.4 view tag (24-bit rationale), §7.4.1–7.4.2 derivations, §7.5 `D_e`, §7.6 `s_sr`/`s_sr_ctx`, §7.7 Janus, §8.1 scan, §9 security properties.
- B. Goodell, R. Salazar, F. Slaughter (Cypher Stack), *An Audit of the FCMP++ Addressing Protocol: CARROT*:
  - LaTeX source: https://github.com/cypherstack/carrot-audit (`latex/main.tex`, `latex/Carrot-final.pdf`)
  - moneroresearch.info entry: https://moneroresearch.info/index.php?action=resource_RESOURCEVIEW_CORE&id=242
  - CCS proposal: https://ccs.getmonero.org/proposals/cypherstack-carrot-spec-review.html
  - Sections used: Executive Summary, §2 Burning Bug / Janus Attack, Recommended Action (HMAC/MAC note, view-tag truncation, clamping, master-secret KDF), Security Proofs (Enote Scan Binding, Burning Bug Resistance, Janus Attack Resistance and its XOR/Wagner aside).
- tevador, *Jamtis* specification: https://gist.github.com/tevador/50160d160d24cfc6c52ae02eb3d17024 (§2.5 Janus via address tag; 1-byte primary view tag; find-received key).
- Monero Project, *A Post-Mortem of the Burning Bug* (2018-09-25): https://www.getmonero.org/2018/09/25/a-post-mortum-of-the-burning-bug.html
- Monero Project, *Janus attack on subaddresses* disclosure (2019-10-18): https://www.getmonero.org/2019/10/18/subaddress-janus.html
- Monero Research Lab issue #73, *View tags*: https://github.com/monero-project/research-lab/issues/73
- FCMP++ and Carrot beta stressnet v3.0 release (seraphis-migration/monero): https://github.com/seraphis-migration/monero/releases/tag/v0.19.0.0-beta.3.0. It shows that Carrot is in stressnet with no mainnet date, so it is not yet mainnet-proven.
- H. de Valence et al., RFC 9496, *The ristretto255 and decaf448 Groups*: https://www.rfc-editor.org/rfc/rfc9496
- D. Wagner, *A Generalized Birthday Problem*, CRYPTO 2002 (the audit's XOR-of-hashes caveat): https://www.iacr.org/archive/crypto2002/24420288/24420288.pdf
- Internal: `docs/reviews/full-review-2026-09-27/R2-crypto.md` §3, `SX1-core-crossreview.md` §2, `R6-tx-mempool.md` MP-7.
