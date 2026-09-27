# R2: Cryptography review (internal, not an audit)

- **Reviewer:** R2 (cryptography)
- **Date:** 2026-09-27
- **Tree:** `f677e55`, read-only. Nothing was built or run.
- **Scope:**
  - `crypto/src/*`;
  - `tx/src/builder.rs` and `tx/src/px_builder.rs` (HedgedRng call sites);
  - `px-core/src/hash.rs` (Hk, Poseidon2);
  - `px/src/delivery.rs`;
  - `wallet/src/file.rs`.
- **Method:**
  - I read every file in scope in full, and checked call sites with grep.
  - I checked the BP+ algebra by hand against ePrint 2020/735 (Fig. 1 and Fig. 3), and the CLSAG transcript against ePrint 2019/654 and Monero.
  - I checked Poseidon2 parameters against the Poseidon2 paper (ePrint 2023/323, which I downloaded and read) and against `p3-baby-bear-0.7.0` in the local cargo registry.
  - I did web research on 2025–2026 cryptanalysis and on Carrot. Sources are listed at the end.
- **Evidence tags:**
  - **[math]**: mathematically established;
  - **[test: name]**: covered by the named existing test (I did not run it);
  - **[src]**: source-read;
  - **[assumed]**;
  - **[unknown]**.

---

## 0. Executive summary

- **No crypto-level P0 blocker found for a controlled testnet.** The core v1 primitives are implemented faithfully and conservatively:
  - canonical Ristretto and scalar decoding;
  - domain-separated Blake2b;
  - CLSAG;
  - aggregated BP+ with a correct single-MSM batch verifier;
  - Pedersen commitments;
  - stealth outputs with the Janus anchor.
- **The F2 fix is correct.** The CLSAG hedged nonce now binds the full transcript [src, test: `nonce_stream_binds_every_transcript_input`, `pre_f2_derivation_leaks_the_spend_key_and_fix_prevents_it`].
- **HedgedRng call sites** (the open item in the brief):
  - **CLSAG** (post-F2), **BP+** and **Schnorr** bind their full statement.
  - **The transfer context does not.** It binds only `"transfer" ‖ H(key images)`. Under a broken RNG, re-signing the same inputs repeats Janus anchors and pseudo-output masks. That leaks **amount deltas** between the two versions. No key leaks, because CLSAG and BP+ are hedged separately (**R2-C1**).
  - **PX record delivery is not hedged at all.** The ECDH scalar `r` and the ML-KEM coins `m` come straight from the caller's RNG. Under a broken RNG, anyone who knows the recipient address can decrypt the record (**R2-C2**).
  - **The PX builder** hedges with an all-zero secret when it has no v1 keys (**R2-C3**).
  - So the claim in `docs/transactions.md` §10 and `nonce.rs` that "every secret random value comes from a hedged stream whose context binds the whole statement" is **not true today**.
- **Hk tree nodes use a truncated permutation without feed-forward.** The node is `P(l‖r)[0..8]`. The comment claims "124-bit collision resistance in the same model", and that is **false** for a public, invertible permutation. Trivial node collisions exist by inversion. The PX commitment tree is still, by my argument, ~2^124-binding, because its leaves are capacity-anchored sponge outputs and the depth is fixed. But that is a different, unwritten argument. The Poseidon2 paper's own compression mode uses feed-forward (**R2-C6**). Changing it is **CONSENSUS**, and the owner already plans a fresh v3 genesis, so this is the cheapest moment to decide.
- **Poseidon2/BabyBear margin:** R_F = 8, R_P = 13, and the partial-round margin is only +7.5% over the Gröbner bound. 31-bit Poseidon instances are the most actively attacked parameter class in 2026 (Poseidon Initiative bounties, the "Skipping Class" paper). No full-round attack is known. Hash agility and monitoring are recommended (**R2-C7**).
- **The Janus anchor argument is sound in the ROM.** It matches Carrot's Janus anchor, which Cypher Stack has reviewed. My main comments are about the scope of Theorem 1, not about its correctness (§3).
- **Post-quantum:**
  - v1 is fully exposed: theft, inflation, and retroactive tracing of every ring spend via key images.
  - PX is plausibly PQ for soundness and ownership.
  - PX delivery is PQ-confidential. Its 1-byte view tag is not (**R2-C8**).
  - The key hierarchy already makes v1 outputs **quantum-recoverable**: `k_s = Hs(seed)` and `PX sk = Hk(seed)` are hash preimages. A post-Q-day migration rule can be built on that without changing v1 today (§11).

---

## 1. Findings list

| ID | Title | Class | Severity | Confidence |
|---|---|---|---|---|
| R2-C1 | Transfer HedgedRng context omits payments, fee and ring | Partially implemented | Low (conditional on RNG failure) + doc overclaim | High |
| R2-C2 | PX delivery randomness (`r`, ML-KEM `m`) not hedged | Partially implemented | Medium (conditional on RNG failure; breaks PX confidentiality) | High |
| R2-C3 | PX builder hedge secret defaults to zeros | Partially implemented | Low | High |
| R2-C4 | Coinbase hedge secret is per-process OS randomness | Accepted limitation | Low | High |
| R2-C5 | Membership nonce: two signatures leak the key (deepens known item) | Partially implemented (unreachable today) | High once contracts integrate; Info now | High |
| R2-C6 | Hk node compression without feed-forward; false collision claim | Complete but requires further analysis | Medium (claim-level; no exploit found) | High (standalone collision); Medium (tree bound) |
| R2-C7 | Poseidon2-BabyBear security margin and hash agility | Accepted limitation / Deferred | Medium (long-term) | Medium |
| R2-C8 | PX view tag from ECDH only: PQ linkage filter | Accepted limitation | Low | High |
| R2-C9 | Delivery combiner vs X-Wing; identity `V` not rejected | Complete but requires further testing | Low | High |
| R2-C10 | Zeroization and `Debug` leaks of masks and offsets | Partially implemented | Low | High |
| R2-C11 | KAT coverage: self-pinned only; no RFC/FIPS vectors in-tree | Partially implemented | Low–Medium | High |
| R2-C12 | Third-party crypto crate status (ml-kem unaudited; dalek 4.1.3) | Accepted limitation | Low | Medium |
| R2-C13 | Minor hygiene (unprefixed concatenation, `len` not reduced, modulo bias) | Accepted limitation | Info | High |
| R2-C14 | Post-quantum exposure and migration path | Not implemented (research track) | High (long-term, strategic) | High |

---

## 2. Primitives: `point.rs`, `hash.rs`, `generators.rs`, `commitment.rs`

**What is implemented, correct and well designed**

- **Points** are decoded only through `CompressedRistretto::decompress` [src, `crypto/src/point.rs:88-94`]. RFC 9496 decoding rejects non-canonical encodings. Equality, `Hash` and `Ord` are defined on the canonical bytes, which is sound because Ristretto encodings are unique [math].
- **Scalars** are decoded with `from_canonical_bytes`, which rejects values ≥ ℓ [`point.rs:152-154`, test: `non_canonical_scalars_rejected`].
- **Domain tags** are `u8(len) ‖ "BlackSilk/v1/" ‖ name` [`hash.rs:387-393`], so the tag/data split is unambiguous [math]. There is a distinctness test over `tags::ALL` [test: `tags_are_distinct_and_short`].
- **`Hs`** reduces a 512-bit Blake2b output modulo ℓ (bias ≈ 2^-259) [math].
- **`Hp`** uses `RistrettoPoint::from_uniform_bytes` on 64 bytes. That is the RFC 9496 §4.3.4 one-way map (two Elligator applications), which is a proper element derivation; no hash-and-increment [src].
- **`H` and the BP+ vector generators** are `Hp` outputs, so nobody knows a DL relation between them [src, `generators.rs:542-572`].
- **`commit`** uses the constant-time basepoint tables for both `y·G` and `a·H` [`commitment.rs:604-606`].
- **The dependency** is curve25519-dalek 4.1.3. That version contains the fix for RUSTSEC-2024-0344 (timing variability in `Scalar29/Scalar52::sub`). Cargo.lock pins 4.1.3 [src].

**Fragile**

- `h32`/`h64` concatenate `parts` with no length prefixes [`hash.rs:435-461`].
  - Every current call site uses fixed-size items, or items whose count is fixed by context, so there is no practical ambiguity.
  - One theoretical case is `px_context(nullifiers ‖ key images)` [`stealth.rs:55-59`]. There the split between the two lists is not encoded, so a nullifier-list/key-image-list pair could collide with a different split. That needs a 32-byte string that is both a canonical digest encoding and a valid Ristretto key image and that equals a chain-unique value. The probability is ≈ 2^-248 [math]. See R2-C13.

**Q13: never change.** Keep the tag scheme, the `Hs`/`Hp` definitions, the generator derivations and the canonical-decoding rules. Every consensus hash and every key image depends on them.

---

## 3. Keys, stealth outputs and the Janus anchor (`keys.rs`, `stealth.rs`, `janus.rs`)

**Implemented and correct**

- The key hierarchy is Monero-style:
  - `k_s = Hs("wallet/spend-key", seed)` and `k_v = Hs("wallet/view-key", seed)` [`keys.rs:156-163`];
  - subaddress offset `m(a,i) = Hs(k_v ‖ a ‖ i)`, with `D = K_s + m·G` and `C = k_v·D`.
- Address decoding is strict: canonical and non-identity [`keys.rs:74-78`, test: `address_encoding_is_strict`].
- **Output construction** follows spec §3.2 [`stealth.rs:114-148`]. Scanning follows §3.3, including the anchor check before the amount check [`stealth.rs:212-263`].
- **Rejected outputs** are reported separately and ignored by the wallet [`tx/src/scan.rs:83`, `wallet/src/wallet.rs:589-590`]. That is exactly what Theorem 1 requires.

### 3.1 Analysis of the Janus anchor security argument

**Construction:**
- `r = Hs("ephemeral", anchor ‖ ctx ‖ D ‖ C)`, `R = r·D`;
- `enc_anchor = anchor ⊕ H64("anchor", S)[..16]`;
- the recipient accepts only if `Hs(anchor' ‖ ctx ‖ D' ‖ C')·D' = R`, compared in constant time [`janus.rs:53-98`].

**Lemma 1 (an accepted output is the honest construction for `j`) holds** [math].
- If acceptance holds, then `R = r'·D_j`, so `S = k_v·R = r'·C_j`.
- `O`, the view tag, `Cm` (checked against the decrypted amount) and both ciphertexts are then functions of `(S, D_j, amount, anchor')` only.
- I verified each step against the code:
  - view tag at `stealth.rs:220`;
  - table lookup at `:226`;
  - anchor at `:232`;
  - commitment at `:246-247`.
- Canonical encodings make "byte-for-byte" meaningful.

**Theorem 1 holds under its stated model.** Its scope should be stated more precisely:

1. **Reaction model.** The theorem assumes the wallet's externally visible behaviour is a function of the accepted set only. Two other channels have to be included explicitly: (a) the timing of the wallet's own later spends, which depends only on accepted outputs, so it is fine; (b) a UI or log that surfaces `ScanReport::rejected`. Code today only keeps rejected outputs in a local report [src]. Recommendation: add a lint-level test that `rejected` never reaches RPC or UI (P2, S).
2. **Uniqueness.** "At most one `j` matches" relies on `D` values being distinct in the subaddress table. Collisions have probability ≈ 2^-252 [math]. It is fine but should be said.
3. **Why `x`, `y` and the tags are keyed on `S` only.** Carrot keys them on a *contextualized* secret `s_sr_ctx = H(s_sr, D_e, input_context)`. BlackSilk keys everything on `S` alone.
   - I find no attack. `S` is already a function of `(anchor, ctx, D, C)` through `r`.
   - A copied `R` in another transaction fails the anchor check, because `ctx` differs [test: `wrong_context_is_rejected`].
   - An identical `O` is barred by consensus C4 (`docs/transactions.md:527`).
   - So the anchor plus C4 also covers Monero's "burning bug".
   - This deviation from the reviewed Carrot design should be written down with this reasoning [src + math].
4. **Anchor entropy.** A guessed anchor costs 2^128 per output, with at most a ×16 multi-target gain inside one transaction (as in §12.7).
   - Under a *broken RNG*, the anchor's unpredictability rests entirely on the hedge secret.
   - For transfers that is `k_s`: fine.
   - For coinbases it is a per-process OS-random value (R2-C4).
   - For PX payouts without v1 keys it is zeros (R2-C3).
   - In those two cases, a broken RNG lets anyone who knows the recipient address recompute `r`, and so recognize the output. That is a privacy regression that Theorem 1 does not cover.
5. **Comparison with prior art.** Carrot's Janus anchor (jeffro256; Cypher Stack audit, "An Audit of the FCMP++ Addressing Protocol: CARROT") uses the same idea: re-derive the ephemeral secret from an encrypted 16-byte anchor, bound to the input context and the recipient spend key.
   - BlackSilk's design is a close relative, **not** Carrot itself.
   - Carrot additionally has special self-send enotes (a MAC under a view-balance secret) and 3-byte view tags.
   - The Carrot review does not transfer automatically. BlackSilk's §12.8 honesty statement ("not peer-reviewed") remains correct.

**Constant time.**
- `S = k_v·R` uses dalek's constant-time variable-base multiplication.
- The anchor comparison uses `ct_eq`.
- Early exits on the view tag or lookup miss leak only local timing (§12.7 is correct) [src].

**Classification:** Complete and verified for the construction and tests [test: `janus::tests::*` A1–A9, `tx/tests/adversarial.rs:569` A10]. Complete but requires further (external) review for the security argument.

**Q9: redesign?** No. **Q13:** do not change the anchor derivation or the ctx definitions. They are wallet-interoperability-critical, and nothing is to be gained.

---

## 4. CLSAG (`clsag.rs`)

**Correct**

- **Transcript** [`clsag.rs:75-115`]:
  - `μP` and `μC` hash the ring (P then Cr), I, D and C';
  - round challenges hash the ring, C', m, L and R.
  - This matches ePrint 2019/654 and Monero's deployed variant. `I` and `D` enter the round chain through `W = μP·I + μC·D` [math].
- **No cofactor handling is needed.** Ristretto is prime-order. The identity key image is rejected [`clsag.rs:269-271`]. `D` is decoded canonically.
- **Signer:**
  - it checks `p·G = P[π]` and `z·G = Cr[π] − C'` before signing [`clsag.rs:221-228`];
  - `α` is zeroized;
  - the loop always runs 15 iterations, whatever `π` is.
- **Verifier:** variable-time MSMs on public data only, and a constant-time final compare.
- **Hedged nonces (F2):**
  - secrets `(p, z)`;
  - context: label, `m`, `C'`, `I`, `D`, `LE64(π)`, all `P[i]`, all `Cr[i]` [`clsag.rs:130-169`].
  - Every input of the signing transcript is bound. Under a constant RNG, the same statement gives an identical signature, which is safe, and any change changes every nonce [math, test: `broken_rng_ring_change_alone_changes_nonces`, `broken_rng_message_key_image_and_d_change_nonces`].
  - `π` never leaves the hash.
- **The message** is `tx/sig-message`: network id, prefix hash (inputs with global ring indices, outputs), base hash, and BP hash [`tx/src/types.rs:276-287`]. The ring *keys* are bound by the CLSAG transcript itself.

**Fragile or inefficient**

- **Secret-indexed memory access.** `c[i]`, `s[i]` and `ring[real_index]` are indexed by the secret `π`. This is a cache-timing channel only for a co-resident attacker, and it is standard in all ring-signature implementations [src]. Info.
- **Verification cost.** Each verification recomputes 16 `Hp("key-image", P[i])` per input [`clsag.rs:283`]. A per-output cache in chain state would cut this (P3, policy, S).

**Missing**

- There are no external vectors for Ristretto-CLSAG (known). The pinned vector `nonce_and_signature_test_vector` is self-generated.
- **Recommendation:** add a differential test against an independently written naive verifier (like BP+'s `verify_naive`), written from the paper by a different author (P2, S).

**Q13:** never change the verification equation, the tags, or `Hp` for key images.

---

## 5. Bulletproofs+ (`bulletproofs_plus.rs`)

**Verified against ePrint 2020/735 Fig. 1 and Fig. 3 (by hand)** [math]:

- **The prover's WIP round** matches the paper:
  - `L = ⟨a1·y^(−h), G2⟩ + ⟨b2, H1⟩ + ⟨a1,b2⟩_y·H + d_L·G`;
  - `R = ⟨a2·y^h, G1⟩ + ⟨b1, H2⟩ + ⟨y^h·a2, b1⟩_y·H + d_R·G`;
  - fold `a' = e·a1 + e⁻¹·y^h·a2`, `b' = e⁻¹·b1 + e·b2`, `G' = e⁻¹G1 + e·y^(−h)G2`, `H' = e·H1 + e⁻¹H2`.
- **`Â`** uses `d_(64j+b) = z^(2(j+1))·2^b` and `←y = y^(N−i)`. The value constant `(z − z²)·Σ_(i=1..N) y^i − z·y^(N+1)·⟨1,d⟩` with `⟨1,d⟩ = (2^64−1)·Σ_j z^(2(j+1))` is correct [`:464-467`].
- **Padding slots** (M > k) have zero bits and implicit identity commitments on both sides. Prover and verifier agree, because both iterate only over the `k` real `V_j` for the `α̂` and point terms [`:271-273`, `:481-483`].
- **The single-MSM verifier:**
  - it derives the folded exponents `s_i` from the challenge bits, with G weighted by `y^(−i)·s_i` and H by `s_(n−1−i) = s_i^(−1)`;
  - all RHS−LHS terms carry the correct signs [`:433-484`].
  - It is cross-checked against a round-by-round verifier [test: `optimized_verifier_matches_naive_verifier`].
- **Fiat–Shamir is strong:**
  - `t0 = H32("bp+/init", BITS ‖ M ‖ k ‖ V_0..V_(k−1))` binds the whole statement;
  - `y`, `z`, then chained `e_t = H(e_(t−1), L_t, R_t)`, then `e = H(e_last, A1, B)`.
  - The commitments are hashed, so the "weak Fiat–Shamir" class of attacks on Bulletproofs (Dao, Miller, Wright, Grubbs, IEEE S&P 2023) does not apply [src].
- **Zero challenges** are rejected on both sides.
- **Batch verification:**
  - independent 128-bit weights;
  - the chain uses a `ChaCha20Rng` seeded from the OS [`chain/src/manager.rs:169-196`, `node/src/main.rs:62`];
  - so an attacker cannot craft cancelling proofs (≈ 2^-128) [test: `batch_weights_prevent_cancellation`].
- **Soundness tests** cover non-binary bit vectors, 2^64, and "negative" amounts [test: `forged_out_of_range_proofs_fail`].

**Hedge (open item in the brief)** [`:214-222`]

- The secret is every `(amount ‖ mask)`. The context is `"bp+"` followed by every commitment.
- The statement is fully bound: the transcript depends only on the commitments (and on constants).
- Under a constant RNG the proof is a deterministic function of the witness. Since the statement is a function of the witness, two different statements never share nonces [math]. **Correct.**
- One observation: anyone who knows *all* openings (for example a recipient of every output) could recompute the blinders under a broken RNG. They learn nothing they did not already know [math].

**Fragile**

- The final-round nonces `r_, s_, δ, η` and `a0, b0` are not zeroized [`:336-340`]. Knowing `r_` together with `r1` reveals the folded witness `a0`. The risk is memory hygiene only (R2-C10).

**Inefficient or scaling**

- The prover's `new_g`/`new_h` folding is O(n) vartime MSMs per round. That is normal.
- Verification is one MSM of size 2N + 2 + 3 + 2·rounds + k per proof, merged across the block. Good.

**Missing**

- There is no pinned BP+ proof vector. Add one with `ZeroRng` so that serialization and transcript changes are caught (P2, S).

**Q13:** never change the transcript layout, the generators or `BITS`.

---

## 6. HedgedRng (`nonce.rs`) and every call site

**The construction is sound** [math]:
- `seed = H64("nonce", LE64(#s) ‖ (LE64(len) ‖ s)… ‖ LE64(#c) ‖ (LE64(len) ‖ c)… ‖ 32 fresh bytes)`;
- `value_i = H64("nonce/stream", seed ‖ i)`.
- It is length-prefixed and unambiguous [test: `list_boundaries_are_unambiguous`].
- The seed is zeroized on drop.
- `scalar()` rejects zero, uses wide reduction, and zeroizes the block.

| Call site | Secrets | Context | Full statement bound? | Verdict |
|---|---|---|---|---|
| CLSAG `clsag.rs:151` | p, z | label, m, C', I, D, π, all P, all Cr | **Yes** | OK (F2) |
| BP+ `bulletproofs_plus.rs:221` | amounts ‖ masks | "bp+", all V | **Yes** (statement = f(witness)) | OK |
| Schnorr `schnorr.rs:91` | k | "schnorr", tag, K, m | **Yes** | OK |
| Membership `membership.rs:165` | x | "membership", m, B, P[π] | **No**: ring and tag missing | R2-C5 (known) |
| Transfer `tx/src/builder.rs:228` | k_s | "transfer", ctx = H(key images) | **No**: payments, change address, fee and ring missing | **R2-C1** |
| Coinbase `builder.rs:365` | miner-supplied (`miner/src/main.rs:82-83`: 32 OS bytes per process) | "coinbase", H(height) | Payout not bound; secret per process | R2-C4 |
| PX `px_builder.rs:240` | `k_s` **or `[0;32]` if no v1 keys** | "px", output_context | Payouts and change not bound; secret may be empty | **R2-C3** |
| PX delivery `px/src/delivery.rs:145-152` | none | none (raw `rng`) | **Not hedged** | **R2-C2** |
| ZK prover `zkvm/src/prove.rs:149-180`, `zk/src/config.rs:128-149` | witness digest | (statement via witness and binding) | Yes, via the witness | OK for R2 purposes (R-ZK owns it) |

### R2-C1: the transfer context omits payments, fee and ring

- **Severity:** Low (needs a failed RNG). **Confidence:** High.
- **Class:** Partially implemented.
- **Location:** `tx/src/builder.rs:227-228`, `:252`.
- **What happens.** With a constant RNG, the anchor stream is `f(k_s, key images)`. Suppose a wallet rebuilds a transfer over the **same inputs** after a failed broadcast, a fee bump, or an edited amount. Then:
  - output *i* reuses anchor *i*;
  - for the same recipient address (always the case for the change address), `r`, `R`, `S` and `O` repeat;
  - so `enc_amount₁ ⊕ enc_amount₂ = a₁ ⊕ a₂` (a two-time pad), and `Cm₁ − Cm₂ = (a₁ − a₂)·H` can be brute-forced;
  - **every observer of both versions learns the amount delta per output**;
  - pseudo-output masks `z_0..z_(n−2)` repeat, so the pseudo-outs are identical.
- **What does not happen.** No key leaks: the CLSAG and BP+ nonces are separately and fully hedged [math].
- **The documentation overclaims:**
  - `nonce.rs:1-24` and `docs/transactions.md` §10 say every context "must contain every public input of the statement … never repeat for two different statements". The code does not do that for transfers.
- **Fix.** Add the following to the transfer context:
  - network id;
  - each payment `(address bytes, amount)` in order;
  - change address;
  - fee;
  - each input's ring global indices.
- **Recommendation attributes:**
  - *Why:* restores the §10 guarantee.
  - *Security:* none adverse.
  - *Privacy:* removes the delta leak.
  - *Performance:* negligible.
  - *Complexity:* S.
  - *Consensus:* none (wallet-side).
  - *Identity:* no.
  - *Difficulty:* S.
  - *Priority:* **P2** (fix the doc statement now, as part of P1 doc accuracy).

### R2-C2: PX delivery randomness is not hedged

- **Severity:** Medium. **Confidence:** High.
- **Class:** Partially implemented.
- **Location:** `px/src/delivery.rs:145-152`.
- **What happens.** `r` (64 wide bytes) and the ML-KEM coins `m` come from the caller's `rng`. If that RNG is broken or constant:
  - anyone who knows the recipient address `(V, ek)` computes `ss_ec = r·V` and `(ct, ss_kem) = Encaps_det(ek, m)`, and so the AEAD key;
  - they read `value`, `data` and `rcm`, and confirm the recipient;
  - the hybrid PQ protection is voided.
- **Why it matters.** This is exactly the threat model the hedge exists for. PX delivery is the project's strongest privacy claim ("confidential unless both DL and ML-KEM are broken").
- **What does not happen.** The zero AEAD nonce stays safe even then: the key also binds `cm`, which is unique per output [math].
- **Fix.** Derive `r` and `m` from a `HedgedRng`:
  - secret: the sender's PX `sk` digest, or the v1 `k_s`;
  - context: label, `cm`, `V`, `H(ek)`, output index.
  - This also covers the throwaway-address path (`px_builder.rs:172-178`).
- **Recommendation attributes:**
  - *Security/privacy:* restores confidentiality under RNG failure.
  - *Performance:* negligible.
  - *Consensus:* none (ciphertext format unchanged).
  - *Identity:* no.
  - *Difficulty:* S.
  - *Priority:* **P1**.

### R2-C3: PX builder hedge secret defaults to zeros

- **Location:** `tx/src/px_builder.rs:239`: `plan.keys.map(|k| k.hedge_secret()).unwrap_or_default()`.
- **What happens.** A PX transaction without v1 inputs hedges payout anchors only with the RNG. Under RNG failure, the anchor is predictable, so `r` can be computed from the public payout address, and the payout output is linkable to that address.
- **Fix.** Use the PX spend-secret bytes (and bind the payout list).
- **Attributes:** Low; consensus none; S; **P2**.

### R2-C4: coinbase hedge secret

- **What happens.** The miner draws the hedge secret once per process from `getrandom` [`miner/src/main.rs:82-83`], the same source as the RNG. If the OS RNG fails, both fail, and coinbase outputs become linkable to a known payout address.
- **Class:** Accepted limitation (Low).
- **Option.** An optional persisted miner secret file (P3, S, consensus none).

### R2-C5: membership nonce (deepens a known item)

- **Location:** `membership.rs:165-174`.
- **What happens.** With a constant RNG, the same `(m, scope, P[π])` over two **different rings** reuses `α` while `c[π]` changes. Membership has a single secret, so **two** signatures suffice: `x = (s₁[π] − s₂[π]) / (c₂[π] − c₁[π])` [math]. That is worse than pre-F2 CLSAG, which needed three.
- **Reachability.** Unreachable today: contracts are not integrated.
- **Fix.** Bind the label, `m`, `B`, `I`, `r`, `π` and all `P[i]` (mirror F2).
- **Attributes:** P1 **before** any contract integration; consensus none; S.

---

## 7. Schnorr, membership, claims

- **Schnorr** [`schnorr.rs`]:
  - key-prefixed challenge `Hs(tag, K ‖ R ‖ m)`;
  - identity key rejected on both sides;
  - strict 64-byte decoding;
  - fully hedged.
  - **Correct** [src, math].
- **Membership** [`membership.rs`]:
  - bLSAG with a scope base `B = Hp(owner ‖ set_id ‖ len ‖ scope)`;
  - the transcript binds `r`, the ring, `B`, `I` and `m`;
  - identity tag and identity members are rejected.
  - **Correct** apart from R2-C5.
  - Tags in different scopes are unlinkable only under DDH, so they are **not PQ** (R2-C14).
- **Claims** [`claims.rs`]:
  - the range claim (`V0 = C − min·H`, `V1 = max·H − C`) and its integer argument (`a0 + a1 = max − min < 2^65 ≪ ℓ`) are correct [math];
  - equality and reveal are Schnorr proofs of knowledge of the G-discrete log of `C_a − C_b` or `C − v·H`, sound under DL [math].
  - One observation: range claims are not message-bound, so they are replayable. That is harmless because they are statements about public commitments, but contract authors must not treat a range proof as authorization.
- **Missing:** known-answer vectors for all three (known item).

---

## 8. Hk and Poseidon2 (`px-core/src/hash.rs`)

**Implemented**

- A sponge over Poseidon2-BabyBear-16:
  - rate 8, capacity 8;
  - capacity initialized to `[domain, len, 0…]`;
  - additive absorption;
  - output = rate after the last permutation (8 elements, ≈ 247.7 bits).
- Tree nodes are `P(l‖r)[0..8]`, with depth fixed at 32.
- The permutation is pinned to the Plonky3 0.7.0 test vector [test: `zk/tests/pins.rs::poseidon2_is_the_pinned_permutation`].
- The parameters in `p3-baby-bear-0.7.0/src/poseidon2.rs:33-47` are:
  - S-box x^7;
  - R_F = 8;
  - R_P = 13, where R_GB = 11.68 × 1.075 gives 12.56, rounded up to 13.
  - The Poseidon2 paper's Table 1 lists (n = 31, t = 16) only for d = 5 (R_P = 14). d = 5 is not usable for BabyBear, because 5 | p−1. So the d = 7 instance's rounds come from Plonky3's application of Eq. (1).

**Correct**

- The **sponge** part is sound. The capacity preset carries domain and length, so there is no padding ambiguity. The sponge vs node domain-separation argument in the header comment is right [math].
- **Generic sponge bound** (Poseidon2 paper §3.1): collision ≈ p^(c/2) ≈ 2^123.9 for c = 8. This matches the project's "≈124-bit" [math].

### R2-C6: Hk node compression without feed-forward

- **Severity:** Medium (claim-level). **Class:** Complete but requires further analysis.
- **Location:** `px-core/src/hash.rs:15-21` (claim), `:144-152` (code).
- **The comment is false.** It says: "node(l, r) = P(l‖r)[0..8] … with 124-bit collision resistance in the same model".
  - Poseidon2 is efficiently invertible: x^(1/7) exists since gcd(7, p−1) = 1, and the linear layers are invertible.
  - So for any target `d` and any two tails `u₁ ≠ u₂`, `P⁻¹(d‖u₁)` and `P⁻¹(d‖u₂)` are distinct inputs with the same node value. These are trivial collisions and preimages of the standalone node function [math].
- **What the paper says.** The Poseidon2 paper (§3.1, "Cryptographic Compression Functions") defines its compression function as `C(x) = Tr_n(P(x) + x)`. It states that this "crucially relies on a feed-forward operation for one-wayness" (a Davies–Meyer analogue; also the Jive mode). Plonky3's `TruncatedPermutation`, which BlackSilk mirrors, omits the feed-forward.
- **Why the PX tree is still, in my assessment, ≈2^124-binding** [math sketch, not a proof; needs writing up]:
  - A forged membership needs a path from an accepted root to a leaf `cm` that the kernel recomputes in-circuit from a record opening. `cm` is a sponge output whose capacity is fixed to `(RECORD, len, 0…)`.
  - Inversion from the root yields only uniformly random children, so the top-down tree gives random 248-bit nodes.
  - Bottom-up from the attacker's candidate records also gives random nodes.
  - A match needs a meet-in-the-middle over a 2^247.7 space, ≈ 2^124 work, with at most multi-target gains that are logarithmic in the number of accepted roots.
  - Reaching an anchored leaf top-down would instead need a sponge preimage, which is a CICO problem with 8 constrained capacity words.
  - Empty leaves are `ZERO_DIGEST`. Opening one would need a sponge preimage of zero.
  - So security stays at the generic level. It rests on *leaf anchoring and fixed depth*, not on the compression function, and the argument is fragile under future reuse of `node` (for example, a contract state tree whose leaves are not sponge outputs).
- **Plonky3's own Merkle trees** (inside the STARK/FRI commitments) use the same construction. The same anchoring argument applies there (leaves are sponge-hashed rows), so this is common practice [assumed: I did not review the p3 MMCS proof].
- **Recommendations:**
  1. **P1, docs, now.** Correct the claim in `hash.rs` and in zk.md/px.md: "node is not collision-resistant as a standalone function; tree binding holds because leaves are capacity-anchored sponge outputs and depth is fixed", with the MITM bound.
     - Consensus none; S.
  2. **P1, decision before the v3 genesis.** Either adopt feed-forward compression `node(l,r) = (P(l‖r) + (l‖r))[0..8]`, or formally accept the truncated form with the written argument.
     - The change is **CONSENSUS**: new kernel ELF and program ids.
     - It needs a **new identity**, but M1 already requires a fresh v3 genesis, so the marginal cost is lowest now.
     - Performance: +8 additions per node, and one extra AIR constraint or syscall change. Negligible.
     - Security: removes a structural caveat; no known exploit either way.
     - Privacy: none.
     - Difficulty: M (guest, host, AIR, pinned ids).
     - It follows the owner's analysis → evidence → proposal procedure.
  3. **Rule (P2).** `node()` may only be used where leaves are anchored sponge outputs. Enforce it by visibility or type (a `Leaf` newtype).

### R2-C7: Poseidon2-BabyBear margin, cryptanalysis and hash agility

**Evidence:**
- The partial-round margin is +7.5% over the Gröbner bound (Plonky3's own comment), and full rounds carry +2.
- 2025–2026 results:
  - Grassi–Koschatko–Rechberger (TOSC 2025, ePrint 2025/954) found inaccuracies in Poseidon's original round-number model, "under- or over-estimating" depending on the instance. They confirm security of the analysed instances.
  - Zhao–Sanso–Vitto–Ding (ePrint 2025/1916), Graeffe-based interpolation attacks: 2^13 speed-up, reduced-round only.
  - Merz–Rodríguez García, "Skipping Class" (ePrint 2026/306): algebraic attacks exploiting weak matrices and compression and sponge **modes** of Poseidon2. Up to 2^106 improvement over prior attacks on one recommended 128-bit parameter set. The authors state the primitive still meets its claim, thanks to the algebraic margin.
  - Poseidon Cryptanalysis Initiative (2026): reduced-round Poseidon-31 (KoalaBear, t = 16, d = 3, R_F = 6) CICO solved up to R_P = 10, and "zero-test" claims up to R_P = 12, in June–July 2026. The 2029 collision prize program is paused from 1 Aug 2026.
- None of this touches full-round BabyBear-16 with d = 7, R_F = 8, R_P = 13 [unknown whether any unpublished result does]. But 31-bit fields are where progress is fastest, and "Skipping Class" specifically targets modes.

**Recommendations:**
- *P2, S, consensus none:* add a documented hash-agility plan. Version the domain constants (`BASE`) and the kernel id, so that a round-count increase (for example R_P = 13 → 16–21) is a planned new-identity upgrade, not an emergency.
- *P3:* track the Poseidon Initiative. Re-evaluate before any mainnet.
- If the owner wants extra margin at v3 at low cost, width-24 or +R_P is a CONSENSUS change with a proving-time cost. Not recommended without measurements.

**Quantum.**
- Grover preimage ≈ 2^124.
- BHT collision ≈ 2^83. That is theoretical: it needs a quantum RAM of 2^83, and Bernstein's cost analysis argues it is no better than parallel classical rho.
- Adequate [math/assumed].

**Other items:** R2-C13 hygiene: `s[9] = len as u32` is not reduced mod p [`hash.rs:67,122`]; unreachable (< 2^31 elements). Add a `debug_assert!(len < P)`.

---

## 9. PX delivery (`px/src/delivery.rs`)

**Correct**

- **Hybrid KEM.** Ristretto ECDH (`ss_ec = r·V`) plus ML-KEM-768.
  - The key is `H32("px/delivery-key", ss_ec ‖ ss_kem ‖ R ‖ ct_kem ‖ cm)`.
  - Every item is fixed-length, so the hash input is unambiguous.
  - Including `ct_kem` is *stronger* than X-Wing, which omits it by relying on ML-KEM's ciphertext collision resistance.
  - IND-CCA of the combined KEM holds if either component holds, when both keys and both ciphertexts are hashed (Giacon–Heuer–Poettering, PKC 2018, KEM combiners) [assumed, standard].
- **AEAD.** ChaCha20-Poly1305 with a zero nonce. This is safe because every key is single-use: fresh `r`/`m` and a unique `cm` [math].
  - After R2-C2 is fixed, uniqueness holds even under RNG failure, because `cm` is in the key.
- **Acceptance** requires recomputing `cm` with the recipient's own owner tag [`:245-246`]. That gives key-commitment-like robustness: ChaCha20-Poly1305 is not key-committing, but a multi-key ciphertext cannot produce two records both matching `cm`. `cm` is binding [math].
- **Key handling.** `DeliveryKeys` zeroize `v`. The ML-KEM `dk` zeroizes itself (feature `zeroize`). Ephemeral values use `Zeroizing`.

### R2-C9: combiner vs X-Wing; identity `V`

- **Combiner.** X-Wing (draft-connolly-cfrg-xwing-kem) hashes `ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ label`. BlackSilk omits `pk_X = V` and has no `H(ek)` (known).
  - In X-Wing's proof, including `pk_X` is what makes the DH half robust in the multi-user setting and gives binding properties.
  - Adding `V ‖ H32(ek)` costs one hash of 64 bytes.
  - Recommendation: do it together with R2-C2 under a new label `px/delivery-key/v2`.
  - Wallet format only, not consensus: P2, S.
  - Then describe it as "X-Wing-style combiner with additional binding", not "X-Wing".
- **Identity `V`.** `seal` accepts `V` = identity [`:137-139`]. `ss_ec` is then the constant encoding of the identity, so a malformed or malicious address silently degrades delivery to ML-KEM-only.
  - Fix: reject identity in `seal` and in address decoding (P2, S).

### R2-C8: view tag from ECDH only

- **Location:** `:113-115`.
- **What happens.** A quantum adversary (or a DL-breaking one) who knows an address `V` computes `ss_ec` for every output. It gets a 1-in-256 filter for "is this output addressed to V", harvested now and applied later.
- **Impact is modest.** Per-output `R` is fresh, so outputs are not mutually linked. But for a well-known address receiving many records, candidate sets shrink by 256×. This contradicts the §4.6 goal that record *contents* stay PQ-confidential only mildly (contents do stay confidential), but it is a **recipient-linkage** leak.
- **Option (P3).** Derive the view tag from `H(ss_ec ‖ ss_kem …)`. That costs one ML-KEM decapsulation per output and address, which is about the cost of the scalar multiplication it replaces [assumed; not measured].
  - Consensus none; privacy +; performance about 2× scan cost.

**Not scaling (Q7).** Per-address view keys mean scanning cost is outputs × addresses (documented). That is acceptable for a testnet.

---

## 10. Wallet file (`wallet/src/file.rs`)

**Correct**

- Argon2id v1.3, default 64 MiB, t = 3, p = 1 (RFC 9106 second recommendation).
- 16-byte OS-random salt and a 96-bit OS-random nonce per save; the key is fresh per save because the salt is fresh.
- AES-256-GCM with the full header as AAD, so the KDF parameters are authenticated.
- Absurd parameters are refused before the KDF (DoS guard).
- Atomic write.
- **PQ:** Argon2id + AES-256 have ≈128-bit Grover security [math].

**Fragile**

- There is no *minimum* KDF parameter check on load. That is not exploitable: an attacker who can replace the file already controls it. But a tampered-and-rewritten file with weak parameters would be accepted if the user re-saves. Low.
- **Zeroization** (R2-C10):
  - the decrypted plaintext `Vec` (JSON containing the seed) is returned without `Zeroizing` [`:124-132`];
  - the `GenericArray` copy made by `key.into()` is not wiped.
- Unix file permissions are a known item.

---

## 11. Post-quantum exposure (R2-C14) and migration path

### 11.1 What a CRQC breaks

| Primitive | Classical assumption | Under a quantum adversary | Retroactive (harvest now)? |
|---|---|---|---|
| v1 CLSAG unforgeability | DL | **Forged spends / theft**: `p = log_G O` | n/a (live) |
| v1 CLSAG anonymity (key images) | DDH / ROM | **Every historical real spend revealed**: for each ring member compute `p_i = log O_i`, test `I = p_i·Hp(O_i)` | **Yes**: full transaction-graph tracing |
| Stealth addresses, given a known address `(D, C)` | CDH | `k_v = log_D C` recovers the **whole wallet's view key** (all subaddresses, incoming amounts). The docs (§11.6) understate this: they say "recover `r` for outputs to known addresses". | **Yes** |
| Stealth, on-chain data only | CDH | `S` still needs `k_v`. Amounts are hidden (Pedersen hiding is perfect), but spend tracing (above) reveals flows | Partially |
| Pedersen binding | DL(G, H) | **Broken**: silent v1 inflation. v1 supply is not auditable because amounts are hidden | n/a |
| BP+ soundness | DL | Broken (inflation). ZK does not rest on DL [assumed per paper] | n/a |
| Janus anchor | CDH / ROM | Moot: the adversary gets `k_v` from any address | — |
| Schnorr / claims | DL | Forgeable | n/a |
| Membership tags | DDH | Cross-scope linkage of votes/actions | **Yes** |
| PX ownership (`sk` → nk, ak, owner via Hk) | Poseidon2 preimage | Plausibly secure (Grover ≈ 2^124) [assumed] | No |
| PX STARK soundness and ZK | FRI + ROM/QROM | Plausibly secure: BCS in the QROM, Chiesa–Manohar–Spooner 2019, as cited in zk.md [assumed] | ZK is statistical and conditional (zk.md) |
| PX delivery contents | DL **and** ML-KEM-768 | Confidential under ML-KEM [assumed]. The view tag leaks (R2-C8) | View tag: yes |
| PX bridge | v1 side | Fake v1 value can be **bridged into PX**. The turnstile (`px_pool`, `tx/src/validate.rs:508,619`) only stops PX→v1 over-withdrawal, so it does not stop dilution of PX | Live |
| Hk / Blake2b / AES / Argon2 | hash / symmetric | Grover halves security: ≥ 124 bits preimage | No |

### 11.2 Latent quantum recoverability (positive finding)

- `k_s = Hs("wallet/spend-key", seed)` and `k_v = Hs("wallet/view-key", seed)` [`keys.rs:156-158`]. The PX `sk` is `Hk(SK, seed limbs)` [`px/src/wallet.rs:53-61`].
- So a quantum adversary who computes `p` or `k_s` by DL still **cannot produce the seed**.
- A post-Q-day consensus rule could therefore allow v1 outputs to move only via a STARK proving:
  1. knowledge of `seed` with `k_s`, `k_v` derived from it;
  2. `O = (Hs(k_v·R) + k_s + m(a,i))·G`;
  3. the key image `I = p·Hp(O)` is fresh.
- This is the same idea as Zcash ZIP 2005 ("Quantum Recoverability"), but BlackSilk gets it **without any format change**, because keys are already hash-derived from a seed. The cost is non-native Ristretto arithmetic in-circuit: expensive, but emergency-only [assumed; not estimated].
- **Q13:** never introduce a way to create v1 keys that are not derived from a seed through a hash (for example raw-key import as a *spend-capable* wallet) without flagging such outputs as non-recoverable.

### 11.3 Recommended migration path

- **Phase 0, now / v3 testnet** (no new v1 consensus rules):
  - (a) Fix the §11.6 docs: include `k_v` recovery from any address, PX-bridge dilution, and the PX view tag.
  - (b) R2-C2 and R2-C9: hedge the delivery and use an X-Wing-style combiner including `V` and `H(ek)`.
  - (c) R2-C6 decision and R2-C7 hash agility, so that PX's PQ foundation (Hk) can be upgraded on schedule.
  - (d) Write the quantum-recoverability rule of §11.2 as a spec draft, so wallets never break its preconditions.
  - Consensus: none (only (c) may be CONSENSUS at v3). **P1/P2.**
- **Phase 1** (post-testnet): make PX the default store of value (PX-5), and keep v1 for compatibility. Add a per-block cap or rate limit on `bridge_in` as a governance-settable policy. It limits how fast undetectable v1 inflation could leak into PX. **P3**, CONSENSUS.
- **Phase 2** (emergency switch, specified in advance): at a flag height, freeze v1 spends and `bridge_in`, and allow v1 → PX only through the §11.2 seed-preimage STARK. **P3**, CONSENSUS, new rules, no new identity.
- **Phase 3:** v1 sunset. A lattice-based linkable ring signature is **not** recommended. The PX STARK path is already PQ-plausible, and lattice ring signatures would add a large unreviewed construction (consistent with §11.6).

---

## 12. Constant-time, zeroization, randomness (cross-cutting)

- **Constant time** [src]:
  - All secret × point operations use dalek's constant-time paths: `mul_base`, `Scalar * RistrettoPoint`, and `multiscalar_mul` in the BP+ prover.
  - Vartime MSMs are used only in verifiers and on public BP+ generator folding.
  - Secret comparisons use `ct_eq`: anchor, CLSAG/Schnorr/membership key checks, commitment check in scan.
  - `Point: PartialEq` compares bytes non-constant-time. It is only used on public values (for example `builder.rs:217` compares a derived public key with a public key). OK.
  - The CLSAG and membership secret index is used for array indexing (Info).
  - ML-KEM decapsulation constant-time behaviour is **[unknown]** for `ml-kem 0.3.2`: the crate README states it "has never been independently audited". KyberSlash-class division timing was not checked by me (R2-C12, P2: review or add a timing smoke test).
- **Zeroization (R2-C10, Low, P2, S, consensus none):**
  - `stealth::CreatedOutput` (`mask`), `stealth::ReceivedOutput` (`mask`, `output_key_offset`) and `tx::builder::SpendableOutput` all `#[derive(Debug)]`, so a `{:?}` log line prints spend-relevant secrets [`stealth.rs:96,172`, `builder.rs:24`]. Implement a redacting `Debug`.
  - Not zeroized: BP+ `r_, s_, δ, η, a0, b0` [`bulletproofs_plus.rs:336-340`], builder `masks`/`mask_sum`/`partial` [`builder.rs:242-253`], and the wallet plaintext.
  - `Scalar: Copy` makes zeroization best-effort in any case. The docs should say "best effort", not "zeroized on drop".
- **Randomness sources** [src]:
  - Wallets use `ChaCha20Rng::from_seed(getrandom)`.
  - The node batch-verification RNG is seeded from getrandom.
  - The wallet file uses getrandom directly.
  - No `thread_rng`, time seeds or `SmallRng` in non-test code (grep over node, miner, wallet, rpc, chain, tx, p2p, px).
  - The throwaway delivery `sk` uses `next_u32() % P` [`px_builder.rs:173-175`]. The modulo bias makes it slightly non-uniform, which is irrelevant for a throwaway key (Info).

---

## 13. Known-answer vector coverage (R2-C11)

| Primitive | In-tree vectors | External standard vectors available? | Recommendation |
|---|---|---|---|
| Blake2b / tags | definition check (`kat_matches_definition`) | RFC 7693 | add the RFC vector (P2, S) |
| Ristretto encode/decode, `from_uniform_bytes` | negative cases only | **RFC 9496 Appendix A** | add (P2, S) |
| HedgedRng | pinned (`stream_test_vector`) | n/a | OK |
| CLSAG | self-pinned (`nonce_and_signature_test_vector`) | none for Ristretto | independent naive verifier (P2) |
| BP+ | naive-vs-MSM differential; no pinned proof | none for Ristretto | pin a `ZeroRng` proof (P2, S) |
| Schnorr / membership / claims | none | none | pin vectors (P2, S; known) |
| Poseidon2 | Plonky3's vector (`pins.rs`) | HorizenLabs reference | cross-check the constants' provenance (P3) |
| Hk sponge / node | toy-permutation bookkeeping only | n/a | pin real-permutation Hk and node vectors (P2, S). Currently only program ids indirectly pin them |
| ML-KEM-768 | none in-tree | **NIST ACVP / FIPS 203 KATs** | add encaps/decaps and implicit-rejection KATs (P2, S) |
| ChaCha20-Poly1305 | none | RFC 8439 | optional (P3) |
| Argon2id / AES-GCM | round trip | RFC 9106 / NIST CAVP | optional (P3) |

---

## 14. Per-subsystem answers to the 13 questions (condensed)

| Q | Primitives / hash | Keys, stealth, Janus | CLSAG | BP+ | HedgedRng | Hk / Poseidon2 | Delivery | Wallet file |
|---|---|---|---|---|---|---|---|---|
| 1 Implemented | full | full | full | full, aggregated to 16, batch | full | full | full | full |
| 2 Correct | yes | yes (Lemma 1 holds) | yes (F2 correct) | yes (checked vs paper) | construction yes | sponge yes | yes | yes |
| 3 Incomplete | vectors | Theorem 1 scope notes | external vectors | pinned proof | C1, C2, C3, C5 | node argument unwritten | C2, C9 | min-param policy |
| 4 Fragile | unprefixed concatenation | anchor under RNG failure (C3, C4) | secret indexing | nonce zeroization | contexts depend on each caller | 7.5% R_P margin | identity `V` | plaintext zeroization |
| 5 Exploitable | none found | none found (RNG-failure privacy only) | none found | none found | C1 deltas, C2 decryption (RNG failure) | none known | C2 (RNG failure) | none |
| 6 Inefficient | — | — | Hp recompute per verify | — | — | — | per-address scan | — |
| 7 Not scaling | — | table size (wallet M-1/M-2, known) | — | — | — | — | outputs × addresses | — |
| 8 Missing | RFC 9496 vectors | written Carrot-delta rationale | differential verifier | vector | full contexts | agility plan | hedge, X-Wing-style binding | — |
| 9 Redesign | no | no | no | no | a context builder API taking the full statement | feed-forward node (decision) | view tag (optional) | no |
| 10 Innovate | — | 3-byte view tag option; quantum recoverability (§11.2) | — | — | typed `Statement` contexts | versioned Hk | PQ view tag | — |
| 11 Before testnet | — | — | — | — | C2 (P1), doc fix; C1/C3 (P2) | C6 doc fix + decision at v3 (P1) | C2 (P1), C9 (P2) | — |
| 12 Defer | — | Carrot-style self-send | Hp cache | — | C4 | C7 round increase | C8 | KDF minimums |
| 13 Never change | tags, Hs/Hp, generators | anchor derivation, ctx defs, seed→key hashing | verification equation | transcript | seed/stream construction (extend contexts only) | domain constants (except by a versioned upgrade) | — | format magic/AAD |

---

## 15. Recommendations by priority

- **P0:** none from the crypto scope.
- **P1:**
  - **R2-C2:** hedge the delivery. Wallet-only, S.
  - **R2-C6 (a):** correct the Hk node claim in code comments and docs. S.
  - **R2-C6 (b):** make a decision on feed-forward compression before the v3 genesis. CONSENSUS, new identity (already planned), M.
  - **R2-C5:** fix the membership nonce before any contract integration. S.
  - **Docs:** §10 "every secret random value … full statement" and "zeroized on drop" overclaim; §11.6 PQ exposure understated (`k_v` from an address, bridge dilution).
- **P2:**
  - R2-C1: full transfer context.
  - R2-C3: PX hedge secret.
  - R2-C9: X-Wing-style binding, reject identity `V`.
  - R2-C10: redacting `Debug`, zeroization.
  - R2-C11: RFC 9496 and ML-KEM KATs, pinned BP+, Hk and node vectors.
  - R2-C7: hash-agility plan.
  - R2-C12: ml-kem timing review.
- **P3:**
  - R2-C8: PQ view tag.
  - R2-C4: persisted miner hedge secret.
  - CLSAG Hp cache.
  - PQ migration phases 1–3 (§11.3).

---

## Sources

- Poseidon2: Grassi, Khovratovich, Schofnegger, ePrint 2023/323, §3.1 (compression function with feed-forward), Eq. (1) and Table 1. https://eprint.iacr.org/2023/323.pdf
- Plonky3 `p3-baby-bear` 0.7.0, `src/poseidon2.rs` (R_F = 8, R_P = 13 derivation). Local cargo registry.
- Grassi, Koschatko, Rechberger, "Poseidon and Neptune: Gröbner Basis Cryptanalysis Exploiting Subspace Trails", TOSC 2025. https://eprint.iacr.org/2025/954
- Zhao, Sanso, Vitto, Ding, "Graeffe-Based Attacks on Poseidon and NTT Lower Bounds". https://eprint.iacr.org/2025/1916
- Merz, Rodríguez García, "Skipping Class: Algebraic Attacks exploiting weak matrices and operation modes of Poseidon2(b)". https://eprint.iacr.org/2026/306
- Poseidon Cryptanalysis Initiative (bounty status 2025–2026). https://www.poseidon-initiative.info/
- Chung, Han, Ju, Kim, Seo, "Bulletproofs+", ePrint 2020/735.
- Goodell, Noether, Blue, "CLSAG", ePrint 2019/654.
- Dao, Miller, Wright, Grubbs, "Weak Fiat–Shamir Attacks on Modern Proof Systems", IEEE S&P 2023 (ePrint 2023/691).
- Carrot specification. https://github.com/jeffro256/carrot/blob/master/carrot.md
- Cypher Stack Carrot review. https://github.com/cypherstack/carrot-audit and https://ccs.getmonero.org/proposals/cypherstack-carrot-spec-review.html
- X-Wing KEM, draft-connolly-cfrg-xwing-kem (IETF CFRG). https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/
- Giacon, Heuer, Poettering, "KEM Combiners", PKC 2018.
- Zcash ZIP 2005, Quantum Recoverability. https://github.com/zcash/zips/blob/main/zips/zip-2005.md
- RUSTSEC-2024-0344 (curve25519-dalek < 4.1.3 timing). https://rustsec.org/advisories/RUSTSEC-2024-0344.html
- RustCrypto `ml-kem` 0.3.2 README ("never been independently audited"). Local cargo registry.
- RFC 9496 (ristretto255), RFC 7693 (BLAKE2), RFC 8439 (ChaCha20-Poly1305), RFC 9106 (Argon2), FIPS 203 (ML-KEM).
