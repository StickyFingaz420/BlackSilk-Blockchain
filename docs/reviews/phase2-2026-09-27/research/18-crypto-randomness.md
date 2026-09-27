# 18 crypto-randomness: research dossier (phase 2, phase 1 research)

Agent 18, 2026-09-27. Read-only. Nothing in the repository was modified and nothing was built or run.
This is internal engineering work, not an audit.

---

## 1. Scope and what I read

**Commit:** `9e422d8` (branch `rebuild/core`; `crypto/src/nonce.rs` and `px/src/wallet.rs` last touched by `fe6b180`).

**Required reading:**
- `docs/reviews/full-review-2026-09-27.md`: §3.3 crypto, the findings register rows (F2, R2-C1 to R2-C5, A21), P1-11, P2-10, P3-14, and never-change item 12.
- `docs/reviews/autonomous-session-2026-09-27.md`: §3, §4, §6 ("remaining hedging items").
- `docs/reviews/full-review-2026-09-27/R2-crypto.md`: §5 BP+ hedge and batch weights, §6 HedgedRng and every call site, §7, §12, §13.
- `SX1-core-crossreview.md`: R2-C2 and R2-C5 were confirmed there.
- Grep of `R3-privacy.md`, `R4-zk.md`, `R11-wallet.md`, `R13-testing-supplychain.md`, `dependency-review.md` for RNG material.
- `docs/transactions.md` §10 (full) and `docs/px.md:322` (the FIPS 203 claim).
- `C:/bszkeval/p2/roster.md`: entries 09, 15, 16, 17, 18, 19, 26, 28, 37, 38.

**Code read in full, or at every randomness-relevant site:**

| Area | Files and lines |
|---|---|
| Hedge core | `crypto/src/nonce.rs` (all); `crypto/src/hash.rs:49-50, 163-208` (tags, `absorb_tag`, `Hasher64`) |
| Signatures and proofs | `crypto/src/clsag.rs:125-240` (`nonce_stream`, `sign_with`); `crypto/src/schnorr.rs:66-120`; `crypto/src/membership.rs:52-260, 420-470`; `crypto/src/bulletproofs_plus.rs:200-260, 527-545, 740-830` (hedge, `batch_verify`, tests); `crypto/src/claims.rs` (RNG paths); `crypto/src/keys.rs:180-200` (`hedge_secret`) |
| v1 builders | `tx/src/builder.rs:1-30, 140-500` (`HedgeContext`, `build_transfer_signing`, `build_coinbase`); `tx/src/px_builder.rs:60-320, 380-530, 610-760` |
| PX side | `px/src/delivery.rs:30-300` (hedge, `seal`, `open`); `px/src/wallet.rs:10-35, 300-470, 510-705` (samplers, `HedgedWords`, `witness_statement`, `hedge_witness`); `px/src/share.rs:47-74` |
| Wallet | `wallet/src/main.rs:255-270, 445-470, 620-660`; `wallet/src/wallet.rs:550-600, 1768-1980` (`v1_plans`, `plans_for`), `2220-2550` (deploy, vault lock/claim, share); `wallet/src/file.rs:60-110` |
| Decoys | `tx/src/decoy.rs:55-250` |
| Miner | `miner/src/main.rs:60-165`; `miner/src/lib.rs:25-160` |
| Node, chain, P2P | `node/src/main.rs:75-100`; `chain/src/manager.rs:290-340, 935-960, 1295-1345`; `tx/src/validate.rs:1095-1120`; `p2p/src/net.rs:385-410`; `p2p/src/transport.rs:120-145`; RNG uses in `p2p/src/addrman.rs` and `dandelion.rs` |
| ZK (for the interface only) | `zk/src/config.rs:60-160`; `zkvm/src/prove.rs:120-200` |
| Dependencies | `crypto/Cargo.toml`; `Cargo.lock` (getrandom 0.2.17/0.3.3, rand_core 0.6.4/0.10.1, rand 0.10.3, blake2 0.10.6); registry sources `getrandom-0.2.17/src/{lib.rs, windows.rs, linux_android_with_fallback.rs}`; `blake2-0.10.6/Cargo.toml` |

**Existing tests read:**
- `nonce.rs`: `stream_values_differ`, `broken_rng_still_separates_contexts_and_secrets`, `fresh_randomness_is_used`, `list_boundaries_are_unambiguous`, `purpose_labels_separate_streams`, `fill_bytes_uses_one_fresh_block_per_64_bytes`, `stream_test_vector`.
- `clsag.rs`: `broken_rng_does_not_reuse_nonces`, `broken_rng_ring_change_alone_changes_nonces`, `broken_rng_message_key_image_and_d_change_nonces`, `pre_f2_derivation_leaks_the_spend_key_and_fix_prevents_it`, `nonce_and_signature_test_vector`.
- `schnorr.rs::broken_rng_does_not_reuse_nonces`.
- `membership.rs::broken_rng_does_not_reuse_nonces`.
- `bulletproofs_plus.rs`: `batch_weights_prevent_cancellation`, `batch_verification`.
- `tx/tests/privacy.rs::broken_rng_transfers_over_the_same_inputs_share_no_output_secrets`.
- `px_builder.rs`: `a_missing_hedge_secret_is_refused`, `broken_rng_witness_randomness_is_bound_to_the_whole_transaction`, `working_rng_witness_randomness_is_fresh`.
- `delivery.rs`: `broken_rng_different_openings_get_different_ephemeral_secrets`, `broken_rng_ephemeral_secrets_depend_on_the_sender_secret`, `working_rng_randomizes_and_opens`, `a_missing_hedge_secret_is_refused`.
- `px/src/wallet.rs`: `broken_rng_values_differ_when_value_or_recipient_differ`, `broken_rng_values_differ_with_the_caller_context_and_secret`, `working_rng_values_are_fresh`, `contract_outputs_keep_their_rcm_and_contract_inputs_get_hedged_keys`, `the_kernel_accepts_a_hedged_witness`, `hedged_rcm_is_uniform_over_the_field`.
- `zkvm/tests/blinding.rs`: the two freshness tests.

---

## 2. Current state

### 2.1 The construction (`crypto/src/nonce.rs:35-104`)

```
seed    = BLAKE2b-512( tag("nonce") ‖ LE64(#s) ‖ (LE64(len)‖s)… ‖ LE64(#c) ‖ (LE64(len)‖c)… ‖ fresh32 )
value_i = BLAKE2b-512( tag("nonce/stream") ‖ seed ‖ LE64(i) )
```

- **The encoding is injective.** Every list has a count, and every item has a length prefix. The tag carries its own length byte (`hash.rs:163-169`).
  - [mathematically established; tested: `list_boundaries_are_unambiguous`, `purpose_labels_separate_streams`]
- **Good RNG.** The output is uniform in the random-oracle model: `fresh32` carries 256 bits of entropy into the hashed input.
  - [math, ROM assumption]
- **Constant RNG.** The output is a PRF of the secrets over the context. Different contexts give independent values, and identical contexts repeat the value (an RFC 6979 §3.6-style deterministic fallback).
  - [math; tested: `broken_rng_still_separates_contexts_and_secrets`]
- **Scalars.** `scalar()` reduces 64 bytes wide (bias below 2^-259) and rejects zero.
  - [source-read]
- **Blocks are not shared between calls.** `fill_bytes` and `bytes16` never share a block.
  - [tested: `fill_bytes_uses_one_fresh_block_per_64_bytes`]
- **The construction is pinned.**
  - [tested: `stream_test_vector`]
- **`HedgedRng` is deliberately not `RngCore`.** It cannot be passed by accident where a real CSPRNG is expected. `px/src/wallet.rs:517-557` wraps it privately as `HedgedWords: RngCore + CryptoRng` so that the rejection samplers can be reused.
  - [source-read]
- **Only `seed` is zeroized on drop.**
  - The `Hasher64` (BLAKE2b) state that absorbed the secret and `fresh32` is not wiped: `blake2 0.10.6` has no zeroize feature (its `Cargo.toml` features are `std`, `reset`, `simd`, `simd_asm`, `simd_opt`, `size_opt`).
  - [source-read, see F18-8]

### 2.2 Call-site inventory (verified against the code, not only against §10)

| # | Call site | Secrets | Context bound | Full statement? | Evidence |
|---|---|---|---|---|---|
| 1 | CLSAG `clsag.rs:151` | `p`, `z` | `clsag/nonce/v2`, m, C′, I, D, π, all P, all Cr | **Yes** | tested (3 broken-RNG tests plus the pre-F2 key-recovery regression), pinned vector |
| 2 | BP+ `bulletproofs_plus.rs:221` | every amount ‖ mask | `bp+`, every V | Yes (statement = f(witness)) | math; no broken-RNG test, no pinned proof (owned by 16) |
| 3 | Schnorr `schnorr.rs:91` | k | `schnorr`, tag, K, m | Yes | tested |
| 4 | **Membership `membership.rs:165-174`** | x | `membership`, m, B, P[π] | **No**: ring, n, π and tag missing | **R2-C5 still open** [source-read; math] |
| 5 | Transfer anchors and pseudo-masks `builder.rs:329-339` | k_s | `transfer/v2`: net, ctx, fee, rings, payments, change, payload | Yes | tested (amount, recipient, fee; the ring change alone is **not** tested) |
| 6 | Coinbase anchors `builder.rs:480-483` | miner secret (per process) | `coinbase/v2`: ctx(height), payouts | Yes for the statement; no network id or parent id; the secret is per process | source-read; no broken-RNG coinbase test |
| 7 | PX v1 part `px_builder.rs:394-410` | PX sk (+ k_s) | `px/v2`: net, ctx, fee, bridge, commitments, rings, payouts, change | Yes | source-read |
| 8 | PX throwaway key `px_builder.rs:287-290` | PX sk | `px/throwaway/v1`, cm, slot | Yes | source-read |
| 9 | PX delivery `delivery.rs:174-200, 230` | PX sk (all-zero refused) | label, owner, V, ek, cm, contract, value, data, rcm, rho | Yes | tested (4) |
| 10 | PX witness `px/src/wallet.rs:663-700` | PX sk (+ k_s) | label, slot, witness statement, caller context | Yes, except contract rcm and function blinds | tested (6 + 3) |
| 11 | **Vault flows** `wallet/src/wallet.rs:2294, 2296, 2427` | none | none (raw `rng`) | **Not hedged** (known) | source-read |
| 12 | **Vault secret** `wallet/src/main.rs:641` | none | raw `os_rng` | **Not hedged (new)** | source-read |
| 13 | **Decoy selection** `wallet/src/wallet.rs:1960` → `tx/src/decoy.rs:119-150` | none | raw `rng` | **Not hedged (new as a finding; §10 calls it "not secret")** | source-read |
| 14 | ZK hiding randomness `zkvm/src/prove.rs:166-198`, `zk/src/config.rs:128-149` | witness digest (unkeyed) | inputs of runs, binding | via the witness | source-read (owned by 26) |
| 15 | BP+ batch weights `bulletproofs_plus.rs:530-543` ← `chain/src/manager.rs:337` | n/a | raw per-process ChaCha20 | independent of the batch content | source-read (owned by 16) |
| 16 | Miner nonce start `miner/src/main.rs:134` | n/a | raw ChaCha20 | privacy only | source-read |
| 17 | Wallet file salt and nonce `wallet/src/file.rs:82-83` | n/a | getrandom direct, fail-closed | fine (key fresh per save) | source-read |
| 18 | P2P handshake DH `p2p/src/transport.rs:133` | n/a | getrandom direct, fail-closed | fine | source-read |

### 2.3 Entropy sources and `getrandom` failure modes

- **Every OS read uses `getrandom 0.2.17`, and every caller propagates the error.**
  - The node (`node/src/main.rs:85`), miner (`:101-104`), wallet (`main.rs:266, 459`; `wallet.rs:567`; `file.rs:82-83`) and P2P (`net.rs:397`; `transport.rs:133`) all do this.
  - None falls back to a weak source.
  - `tools/labnet` uses `unwrap()`, which is acceptable for a tool.
  - [source-read]
- **getrandom 0.2.17 backends** [source-read: registry source]:
  - **Linux:** the `getrandom(2)` syscall, which blocks until the CRNG is initialised. On `ENOSYS` or seccomp `EPERM` it falls back to `/dev/urandom`, but only after polling `/dev/random`. The crate's policy is "we always choose failure over returning known insecure 'random' bytes" [docs.rs].
  - **Windows:** `BCryptGenRandom(BCRYPT_USE_SYSTEM_PREFERRED_RNG)` with an `RtlGenRandom` fallback, and otherwise `Err`. `BCryptGenRandom` has a history of failing with "Access is denied" in some environments (getrandom #314/#414). Rust std, Go, Chromium and BoringSSL moved to `ProcessPrng`, and getrandom 0.3 uses `ProcessPrng`. **For BlackSilk the failure mode is fail-closed: the process refuses to run, it does not weaken.**
- **The residual real-world failure is duplicated state, not an error return.**
  - The OS generators reseed on a VM snapshot restore: Linux vmgenid since 5.18, and Windows 10 on Hyper-V via VM-Generation-ID (Ferguson 2019).
  - **User-space `ChaCha20Rng` state does not reseed.** Seeding happens once per wallet command, and once per process for the node, miner and P2P.
  - So a snapshot of a running process, restored twice, replays the same stream (Ristenpart–Yilek NDSS 2010).
  - This is exactly the threat hedging addresses, and it is the model used in §3 below. "Constant RNG" in the tests is the worst case of it.
  - [assumed for hypervisor behaviour; source-read for BlackSilk seeding]
- `rand_core 0.6.4` is used without its `getrandom` feature, so there is no `OsRng` in the build.
  - A grep of the non-legacy code finds no `thread_rng`, `SmallRng`, `StdRng::from_entropy` or time seeds. `StdRng` appears only in `zk/src/config.rs`, seeded from the hedged digest.
  - [source-read]
- **Pure Rust.** getrandom reaches the OS through `extern "system"` (Windows) and libc syscalls (Linux). This is unavoidable OS FFI and not a C library. It should be documented as the one permitted native boundary for randomness.
  - [source-read]

### 2.4 What the tests prove, and what they do not

**Proved:**
- deterministic fallback and context separation for CLSAG, Schnorr, delivery, the PX witness and transfers (amount, recipient, fee);
- a real key-recovery regression for the pre-F2 CLSAG derivation;
- uniformity of the hedged `rcm`.

**Not proved:**
- **membership reuse across rings** (the existing test only varies `m`);
- a transfer rebuilt with only a ring member changed;
- coinbase under a broken RNG;
- vault flows;
- decoy selection under duplicated RNG state;
- any *cloned-state* scenario (two different statements from the same ChaCha state), as opposed to a constant RNG;
- verify-after-sign for Schnorr and membership.

---

## 3. Problems in scope

### P-A. Membership (bLSAG) nonce context incomplete (R2-C5): still open

- **What and why.** The context `["membership", m, B, P[π]]` (`membership.rs:167-172`) omits the other ring members, the ring size, π and the tag. The code predates F2, and F2 fixed only CLSAG.
- **The consequence** [math]. With a constant or cloned RNG, sign the same `(m, scope, P[π])` over two rings that differ in any decoy. Then α repeats, while `c[π]` changes, because the transcript hashes the whole ring (`membership.rs:101-111`). Since `s[π] = α − c[π]·x`, we get `x = (s₁[π] − s₂[π]) / (c₂[π] − c₁[π])`. **Two signatures give the secret key.** That is worse than pre-F2 CLSAG, which needed three.
- **Class.** Security-critical once any consumer exists. Today it is unreachable: grep shows no caller outside `crypto` and the unintegrated `contracts` crate. Not consensus-critical: the verifier is unchanged.
- **Literature.**
  - Hedged nonces must bind every input of the Fiat–Shamir transcript. See RFC 6979 §3.6 (additional data k′), BIP-340 (the nonce binds `P` and `m`), draft-irtf-cfrg-det-sigs-with-noise-05, and Aranha–Orlandi–Takahashi–Zaverucha (EUROCRYPT 2020), whose hedged analysis assumes that the nonce input binds (sk, msg).
  - For ring signatures the "message" is the whole ring plus m.
  - Monero draws fresh randomness only, with no hedge. BlackSilk's CLSAG F2 fix is the in-tree precedent.
- **Fix.** The label `membership/nonce/v2`, then m, B, I (tag), LE64(n), LE64(π), and `P[0] ‖ … ‖ P[n−1]`, mirroring `clsag::nonce_stream`.
  - The format and verifier are unchanged, so it is wallet-side only.
- **Trade-offs.**
  - None for security.
  - π enters only the hash, as in CLSAG.
  - The cost is one hash of at most 32·n bytes.
- **Tests.**
  1. First, an attack test that reproduces key recovery on the *current* derivation (in the style of `pre_f2_…`).
  2. After the fix, broken-RNG tests varying a decoy, n, π (a reordered ring) and m.
  3. A pinned `ZeroRng` vector.
- **Invariants.** The verification equation, the transcript tag `CONTRACT_MEMBER_ROUND`, the tag `x·B`.

### P-B. Vault-flow values drawn from the raw RNG (known open item)

- **What.**
  - `blind` for `lock_call` and `claim_call` (`wallet.rs:2294, 2427`).
  - The `rcm` of the contract output (`wallet.rs:2296`, via `pxw::contract_output`).
  - `build_px` deliberately keeps both (`px_builder.rs:72`; `px/src/wallet.rs:655-660`), because the caller must know the contract record's opening, and because `blind` is inside the function's private input *and* in the witness statement.
- **The consequence** (under a broken or cloned RNG only):
  - Knowing `rcm` lets an observer test guesses of a contract record's `(value, data=lock)` against `cm`. The value is low-entropy.
  - Knowing `blind` lets an observer test guesses of a function's I/O against `io_hash`. For a lock, the I/O is (contract, amount, lock), so the amount leaks to anyone who knows the lock, such as the counterparty.
  - Privacy-critical (confidentiality of PX contract state). Not consensus-critical.
- **Literature.** Hedged commitment and encryption randomness: Bellare et al., Hedged PKE (ASIACRYPT 2009); Ristenpart–Yilek (NDSS 2010); RFC 8937 (wrap the CSPRNG with a long-term secret).
- **Fix options:**
  - (a) **Recommended.** A wallet-side helper `blacksilk_px::wallet::hedged_digest(secrets, label, context, rng) -> Digest`, built on `HedgedWords` and `random_digest`, so the output is uniform and canonical. The wallet derives `blind` and the contract `rcm` *before* it assembles the witness:
    - labels `px/wallet/vault-blind/v1` and `px/wallet/contract-rcm/v1`;
    - context: network id, contract, amount, lock (or the claimed record's cm), each chosen PX input's `(rho, rcm, position)`, the fee and the anchor root;
    - secret: `Account::hedge_secret`.
    - `build_px`'s contract ("contract outputs keep caller rcm") is unchanged.
  - (b) Move contract-output `rcm` into `hedge_witness` and return the final openings from `build_px`. This changes the API and is circular for `blind`, which is part of the statement.
- **Trade-offs.**
  - With (a), a caller that forgets to use the helper regresses silently.
  - Mitigation: make `pxw::contract_output` take the hedged `rcm` as a parameter, not an RNG, so there is no RNG path left.
  - The wallet already re-checks `record.commit() == cm` (`wallet.rs:2340-2345`), which catches mismatches.
- **Tests.**
  - `ZeroRng` lock twice with different amounts: blind and rcm differ.
  - An identical statement gives identical values.
  - A seeded working RNG gives fresh values.
  - The kernel accepts the result.
  - A uniformity check over the field (reuse `hedged_rcm_is_uniform_over_the_field`).
- **Invariants.** The record commitment and the function I/O hash definitions (consensus); the vault program id.

### P-C. The vault lock secret is plain RNG output (new)

- **What.** `wallet/src/main.rs:641`: `random_digest(&mut os_rng())` generates the claim secret. Whoever knows it can claim the funds (the lock is `Hk(LOCK, secret)`).
- **The consequence.** Under duplicated RNG state (a VM clone between seeding and use), two clones generate the same secret. Under a known-state RNG, the funds are stealable.
- **Class.** Key generation, so in principle it cannot be protected by hedging, which needs *some* secret. The wallet does have one, however: the PX spend secret.
- **Fix.** `secret = hedged_digest([px sk], "px/wallet/vault-secret/v1", [net, contract, amount, fresh counter], rng)`.
  - With a good RNG it stays uniformly random.
  - With a bad RNG it is unpredictable without `sk`.
  - The derivation is one-way, so sharing the secret with the claimer reveals nothing about `sk` [math, ROM].
- **Trade-off.** A user-supplied secret path is unchanged.
- **Severity.** Low (conditional). This is a demonstration contract, and the CLI already warns about it.

### P-D. Decoy selection is not hedged: a real-input identification risk under a cloned or known RNG (new finding; the §10 wording understates it)

- **What.**
  - `plans_for` calls `select_ring_keeping(rng, …)` with the wallet's ChaCha20 stream (`wallet.rs:1960`).
  - The draws (`decoy.rs:200-248`) depend on the RNG stream, the chain distribution and the exclusion set (`ring.contains`), which is nearly independent of which output is real.
- **Scenario 1: cloned state** [math/source-read].
  - Two wallet instances start from the same ChaCha20 state, for example a VM snapshot restored twice while the wallet is running `transfer`, or one process repeating a stream.
  - They spend *different* outputs at the same height.
  - They draw the same gamma samples, so their 15 decoys largely coincide. The members that differ between the two rings are exactly the two real inputs.
  - Any observer of both transactions de-anonymises both spends.
- **Scenario 2: known state.** An attacker who knows the seed re-simulates the picker. The one ring member it did not predict is the real one.
- **Class.** Privacy-critical: it breaks sender anonymity, the core v1 guarantee. Not consensus-critical. Conditional on an RNG failure.
- **Understatement.** `docs/transactions.md` §10 ("decoy selection (not secret, but predictable under a broken RNG)") and the autonomous-session §4 claim ("every wallet-side secret draw … apart from three items") understate this. Unpredictability of decoys is a privacy requirement, even though the decoys are public.
- **Literature.**
  - Monero's decoy selection relies on its CSPRNG (wallet2's gamma picker). Möser et al. (PETS 2018) and later analyses treat predictable or biased selection as an anonymity loss.
  - The hedging principle (Ristenpart–Yilek; RFC 8937) says to mix a long-term secret into every security-relevant random draw.
- **Fix.** A per-input hedged stream as the picker's RNG:
  - secret: `k_s` (`WalletKeys::hedge_secret`). **Not the view key**: under a broken RNG, a view-key holder (an auditor) could recompute the decoys and find the spend. `k_s` holders can link spends through key images anyway, so nothing is lost.
  - context: `wallet/decoys/v1`, network id, the real output's `(global index, one-time key)`, `next` (the height), the kept members.
- **Consequences of the fix.**
  - A good RNG gives the same distribution as today.
  - A broken RNG gives, for the same output and height, the same ring. That is consistent with W-5 ring reuse and harmless.
  - A broken RNG gives, for different outputs, independent decoys.
- **Needs** an `RngCore` adaptor. Move `HedgedWords` into `crypto::nonce` as `pub struct HedgedStream` (`RngCore + CryptoRng`), used only for derived draws. This relaxes R2's "HedgedRng is not RngCore" slightly, but in a named, auditable type.
- **Trade-offs.**
  - The draw count per input stays bounded (`MAX_ATTEMPTS`).
  - Statistical behaviour is unchanged. Verify with the roster-38 decoy suite.
- **Tests.**
  - `cloned_rng_state_spending_different_outputs_gives_unrelated_decoys`: the fraction of shared decoys is at most the baseline expected for independent draws.
  - `broken_rng_same_output_same_height_same_ring`.
  - Distribution equivalence against the unhedged picker (a KS test over many draws, seeded).
- **Invariants.** The gamma parameters, coinbase-maturity eligibility, the 16 sorted global indices and the W-5 keep logic.

### P-E. Coinbase hedge: per-process miner secret (R2-C4), and a context without network or parent

- **What.** `miner/src/main.rs:103-104`: `hedge = getrandom` per process. The coinbase context (`builder.rs:480-483`) binds `ctx(height)` and the payouts, but not the network id or `prev_id`.
- **The consequence.** If getrandom were predictable, both the stream and the secret fail together. The anchor is then computable from (height, payout address, amount), so coinbases become linkable to a known payout address. For a VM clone of a *running* miner, both clones produce identical coinbases per (height, amount), which is harmless because only one chain keeps each.
- **Fix, RFC 8937-style.** An optional persisted miner secret, `--hedge-file` (created with mode 0600 on first run), mixed with the per-process randomness: `hedge = H64("miner/hedge/v1", file_secret ‖ getrandom)`. Also add the network id and the parent id to the hedge context.
  - This changes nothing on the wire.
- **Trade-off.** One more file to protect. If the file leaks, the protection reverts to today's.
- **Severity.** Low. It remains an accepted limitation without the file.

### P-F. HedgedRng absorbs fresh randomness *last*: a first-order DPA surface (new, hardening)

- **What.** The order is `secret ‖ context (attacker-influenced m, ring…) ‖ fresh32`. The BLAKE2b compression that first mixes the secret with message-dependent words therefore runs on a deterministic, secret-dependent state.
- **Literature.**
  - Samwel et al. (CT-RSA 2018) recover Ed25519 keys by DPA on SHA-512 exactly at this point.
  - draft-irtf-cfrg-det-sigs-with-noise-05 fixes it by "mixing prefix with Z before mixing it with any public variable data".
  - BIP-340 XORs `H_aux(a)` into the key for the same reason.
- **Applicability.** This needs physical side-channel access (power or EM), which is relevant to hardware wallets or embedded signers and much less to desktop wallets.
- **Fix.** Absorb `fresh32` right after the tag, and pad secrets and fresh to a 128-byte block boundary.
- **Conflict.** This changes `stream_test_vector` and the pinned CLSAG vector, and it **conflicts with never-change item 12** ("HedgedRng seed/stream construction (extend contexts only)"). The change is wallet-only (no validator re-derives it), so the constraint is about reproducibility, not consensus.
- **Recommendation.** Do **not** change it for the testnet. Document the side-channel assumption in §10. Revisit (P3) if a hardware-signer spec (R11 §(d)) is started, as a `v2` construction that the device and the host share.

### P-G. No verify-after-sign in Schnorr and membership (new, hardening)

- **What.** The builders self-verify CLSAG and BP+ before returning (`builder.rs:454-467`), which is a good fault countermeasure. `schnorr::sign` and `membership::sign` do not.
- **Literature.**
  - Under a broken RNG the hedge degrades to deterministic signing, which is vulnerable to differential fault attacks (Poddebniak et al., EuroS&P 2018, including Rowhammer).
  - Even hedged signing leaves some fault classes open (Aranha et al., EUROCRYPT 2020).
  - Verify-before-release is the standard mitigation.
- **Fix.** Verify inside `sign`. The cost is one verification.
- **Severity.** Low, P3 (no consumer today).

### P-H. BP+ batch weights independent of batch content (Info; owned by 16)

- **What.** The weights come from a per-process ChaCha20 stream (`manager.rs:337`, `bulletproofs_plus.rs:530-543`). Soundness rests on the stream being secret. That holds, because getrandom is fail-closed.
- **Hardening.** Use the ed25519-dalek approach: derive the weights from a transcript of all proofs and commitments, keyed with node randomness (a hedged batch). Then a leaked or duplicated node state still cannot be used to pre-compute cancelling proofs.
- **Class.** Consensus-adjacent: a wrong acceptance would be a consensus split, although the verifier result is still deterministic up to 2^-128.
- **Priority.** P2. I defer to roster 16.

### P-I. ZK prover randomness (Info; owned by 26)

- **What.** The witness digest (`zkvm/src/prove.rs:166-178`) hashes the inputs of the runs and the binding, but not the program ids. It is unkeyed.
  - For PX, the kernel input contains the hedged `sk` and dummies, so it is unpredictable.
  - A function-only proof with a low-entropy input would have predictable hiding randomness under a broken RNG, but that input is then guessable anyway.
- **Suggestion to roster 26.** Add the program ids and, where one is available, the PX hedge secret.

---

## 4. New findings

| ID | Severity | Status | Location | Scenario | Confidence |
|---|---|---|---|---|---|
| **F18-1** (= R2-C5, re-verified) | Info now; **High** on any contract integration | Not implemented | `crypto/src/membership.rs:165-174` | constant or cloned RNG; two signatures over rings that differ in one decoy → `x = (s₁−s₂)/(c₂−c₁)` | High (math) |
| **F18-2** (known open item) | Low (conditional) | Not implemented | `wallet/src/wallet.rs:2294, 2296, 2427`; `px/src/wallet.rs:423-436` | broken RNG → the vault amount is brute-forced from `cm` or `io_hash` | High |
| **F18-3** (new) | Low (conditional; theft for a known-state RNG) | Not implemented | `wallet/src/main.rs:641` | two VM clones generate the same vault secret; a known seed → claim | High |
| **F18-4** (new) | **Medium** (conditional; privacy-critical) | Not implemented; the docs understate it | `wallet/src/wallet.rs:1960`, `tx/src/decoy.rs:119-150`; `docs/transactions.md` §10 "Other RNG uses" | cloned ChaCha state: two spends of different outputs share decoys, and the rings differ exactly at the reals | High on the mechanism, Medium on the likelihood |
| **F18-5** (= R2-C4, extended) | Low | Accepted limitation | `miner/src/main.rs:103-104`; `tx/src/builder.rs:480-483` | predictable getrandom → coinbases linkable to the payout address; the context lacks network and parent | High |
| **F18-6** (new) | Low (physical side channel) | Accepted limitation for the testnet | `crypto/src/nonce.rs:44-52` | DPA on the BLAKE2b compression mixing the secret with an attacker-chosen m (Samwel 2018) | Medium |
| **F18-7** (new) | Low | Not implemented | `crypto/src/schnorr.rs:73-100`, `crypto/src/membership.rs:127-150` | fault injection on deterministic fallback | Medium |
| **F18-8** (new) | Informational | Accepted limitation (the docs say "best effort") | `crypto/src/nonce.rs:44-57`; blake2 0.10.6 | the hasher state and the buffer holding `fresh32` and the secret-derived chaining value are not wiped | High |
| **F18-9** | Informational | Not implemented (hardening) | `crypto/src/bulletproofs_plus.rs:530-543`; `chain/src/manager.rs:337` | weights depend only on the process stream; a leaked state allows cancelling proofs | High |
| **F18-10** | Informational | Complete (fail-closed); consolidation open | `Cargo.lock` getrandom 0.2.17 + 0.3.3 | `BCryptGenRandom` "Access denied" → the node or wallet refuses to start (a liveness issue, not a security one) | High |
| **F18-11** (new) | Informational (documentation) | Not implemented | `px/src/delivery.rs:236` (`encapsulate_deterministic`); `docs/px.md:322` "FIPS 203" | hedged coins are sound in the ROM but deviate from FIPS 203 §6, which reserves the internal or deterministic interfaces for testing, so a "FIPS 203" claim should say "ML-KEM-768 parameter set, hedged encapsulation coins" | High |
| **F18-12** | Low (documentation) | Not implemented | `docs/reviews/autonomous-session-2026-09-27.md:212-213`; `docs/transactions.md` §10 | the documents list three unhedged items; the real set is membership, vault blind and rcm, the vault secret, decoys, the miner secret, and (per process) batch weights | High |
| **F18-13** (to 26) | Informational | — | `zkvm/src/prove.rs:166-178` | the witness digest omits program ids and is unkeyed | Medium |

---

## 5. Implementation plan for phase 2

All items are wallet-side, crypto-internal or documentation only. **No consensus change and no identity impact** in any item.

| # | Work item | Files (ownership) | Externally visible | Tests | Docs | Diff. | Prio |
|---|---|---|---|---|---|---|---|
| W1 | Membership nonce binds the full transcript (F18-1) | `crypto/src/membership.rs` | no (signatures still verify; nonces change) | attack test on the old derivation (recover x from 2 sigs); broken-RNG: decoy, n, π, m, tag each change α; `ZeroRng` pinned vector | §10 row → "full"; `nonce.rs` header | S | **P1** |
| W2 | Public `HedgedStream: RngCore + CryptoRng` in `crypto::nonce` (move `HedgedWords`); `px::wallet` uses it | `crypto/src/nonce.rs`, `px/src/wallet.rs` (the `HedgedWords` block only) | no | the existing px wallet tests unchanged; a unit test that a stream equals the concatenated `HedgedRng::fill_bytes` blocks | `nonce.rs` doc | S | P1 (enabler) |
| W3 | Hedged decoy selection (F18-4) | `wallet/src/wallet.rs` (`plans_for` only); `tx/src/decoy.rs` untouched | no | cloned-state test; same output → same ring; distribution equivalence (seeded KS) | §10 table: new row; "Other RNG uses" rewritten | S–M | **P1** |
| W4 | `hedged_digest` helper plus hedged vault `blind`, contract `rcm` and vault secret (F18-2, F18-3); `contract_output` takes `rcm` rather than an RNG | `px/src/wallet.rs` (the samplers), `wallet/src/wallet.rs` (`px_vault_lock`, `px_vault_claim`), `wallet/src/main.rs:630-645` | no | broken RNG: differ when amount, contract, lock or inputs differ; equal for an identical statement; working RNG fresh; the kernel accepts; the existing vault lock/claim tests pass | §10 "Not hedged" list shrinks; px.md §13.4 | S | P2 |
| W5 | Miner: optional `--hedge-file` mixed with getrandom; network id and prev id in the coinbase hedge context (F18-5) | `miner/src/main.rs`, `miner/src/lib.rs` (`build_block` passes extra context), `tx/src/builder.rs` (`build_coinbase` takes an extra context slice) | no (wire unchanged) | `ZeroRng` coinbase tests: height, payout, network and parent each change the anchor; a file-secret test | §10 R2-C4 paragraph; miner README | S | P2 |
| W6 | Verify-after-sign in `schnorr::sign` and `membership::sign` (F18-7) | `crypto/src/schnorr.rs`, `crypto/src/membership.rs` | no | a fault-model test: a corrupted intermediate (test hook) → `Err`, no signature released | §10 | S | P3 |
| W7 | Transfer broken-RNG completeness test: a ring change alone, the payload alone (deploy) | `tx/tests/privacy.rs` | no | the new tests | — | S | P2 |
| W8 | Cloned-state harness: `CloneRng` (two identical ChaCha20 states) run through every builder (transfer, coinbase, PX, delivery, vault, decoys), asserting that no secret-derived public value repeats across different statements | new `tx/tests/rng_failure.rs`; `px/src/wallet.rs` tests | no | itself | §16 test plan | M | P2 |
| W9 | Documentation corrections (F18-11, F18-12, F18-6 assumption, F18-8 best effort, getrandom as the one native boundary) | `docs/transactions.md` §10; `docs/px.md:322`; `crypto/src/nonce.rs` header | no | — | as listed | S | **P1** (doc accuracy) |
| W10 | (Coordinate with 16) hedged transcript-derived batch weights (F18-9) | `crypto/src/bulletproofs_plus.rs` (`batch_verify`) — **16 owns** | no (probabilistic result unchanged) | the cancellation test with a *known* RNG state now fails to cancel | — | S | P2 |
| W11 | (Coordinate with 44) consolidate on getrandom 0.3.x (ProcessPrng on Windows) | the `Cargo.toml` files of node, miner, wallet, p2p, labnet — **44 owns** | no | build matrix | dependency-review.md | S | P3 |
| W12 | (Future) HedgedRng v2 layout (fresh first, padded) for a hardware-signer profile (F18-6) | `crypto/src/nonce.rs` | no (wallet-only, but the pinned vectors change) | new vectors; v1 vectors kept for regression | §10 | S | P3 — needs a never-change #12 exception |

**Benchmarks.** None needed. Each item adds at most a few BLAKE2b calls per transaction. For W3, check the wallet `transfer` latency against the RandomX-free test net: the picker makes about 16 × 3 draws per input, now from BLAKE2b blocks, which is negligible.

**Ordering.** W9 and W1 first (independent). Then W2, then W3 and W4. W5, W7 and W8 can run in parallel.

---

## 6. Dependencies and conflicts

- **15 clsag.** `nonce_stream` is shared precedent. W1 mirrors it. No file overlap.
- **16 bulletproofs-plus.** Owns `bulletproofs_plus.rs`: the batch weights (W10), the BP+ broken-RNG test, and a pinned `ZeroRng` proof. I only coordinate.
- **17 stealth-janus.** Anchor unpredictability under RNG failure depends on W5 (coinbase) and on the transfer/PX hedges. No file overlap.
- **19 hash-domain-separation.** The new labels must enter the domain registry: `membership/nonce/v2`, `wallet/decoys/v1`, `px/wallet/{vault-blind,contract-rcm,vault-secret}/v1`, `miner/hedge/v1`. Note that labels are HedgedRng *context items*, not `hash.rs` tags.
- **26 zk-privacy.** F18-13 (witness digest). They own `zkvm/src/prove.rs`.
- **28 private-contracts-px.** The vault flows (W4) touch the vault UX. Membership (W1) is a prerequisite for any contract integration.
- **37 wallet-keys.** `hedge_secret()` is the raw `k_s` or PX `sk`. If the key hierarchy introduces a derived "hedge key" (for example `H("hedge", k_s)`, and for a spend/prove split, R11-W4), W1–W5 should consume it. Pinned vectors would move.
- **38 wallet-privacy.** Owns decoy statistics. W3 edits `wallet.rs::plans_for` only, and 38's statistical suite should validate distribution equivalence. **File conflict risk:** `wallet/src/wallet.rs` is shared by 37, 38, 39 and W3/W4, so the coordinator should serialise edits.
- **09 mining-templates.** Owns `miner/src/*`. W5 needs agreement on the `--hedge-file` flag and the `build_block` signature.
- **44 supply-chain.** W11 (getrandom consolidation) and the blake2 zeroize question.
- **41 fuzzing-property-stateful.** W8 harness style (proptest is now possible, per R13).
- **47 docs-spec-consistency.** W9.

---

## 7. Open questions for the coordinator

1. **Never-change item 12.** Is a future HedgedRng v2 (fresh-first layout, F18-6) acceptable as a versioned, wallet-only change, or is the rule absolute? I recommend documenting only, for the testnet.
2. **W3 ownership.** Hedged decoys: 18 or 38? I recommend that 18 implements the stream plumbing and 38 validates the statistics.
3. **W2.** Is a public `HedgedStream: RngCore + CryptoRng` acceptable? It deliberately gives a deterministic keyed stream the `CryptoRng` marker, as `HedgedWords` already does privately.
4. **W4 vault secret.** Deriving it from the PX secret makes it one-way-linked to the wallet. Is that acceptable, given that the demonstration vault shares the secret with a counterparty?
5. **W5.** Is a persisted miner secret file acceptable for operators (the seven-device trial)? Or should it stay an accepted limitation?
6. **Hedge secret.** Should the hedge secret remain the raw spend key (RFC 6979 and EdDSA style), or become a derived hedge key (37's hierarchy)? Deciding before the testnet avoids moving the pinned vectors twice.

---

## 8. Sources

- RFC 6979, *Deterministic Usage of DSA and ECDSA*, §3.6 (additional data): https://www.rfc-editor.org/rfc/rfc6979
- RFC 8937, *Randomness Improvements for Security Protocols* (wrapping the CSPRNG with a long-term key; the VM-snapshot caveat): https://www.rfc-editor.org/rfc/rfc8937.html
- draft-irtf-cfrg-det-sigs-with-noise-05, *Hedged ECDSA and EdDSA Signatures* (Z mixed before public data; fault and DPA rationale): https://datatracker.ietf.org/doc/draft-irtf-cfrg-det-sigs-with-noise/ ; text: https://www.ietf.org/archive/id/draft-irtf-cfrg-det-sigs-with-noise-05.txt
- BIP-340, *Schnorr Signatures for secp256k1* (aux_rand XORed into the key; the synthetic-nonce rationale): https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
- D. F. Aranha, C. Orlandi, A. Takahashi, G. Zaverucha, *Security of Hedged Fiat–Shamir Signatures under Fault Attacks*, EUROCRYPT 2020, ePrint 2019/956: https://eprint.iacr.org/2019/956
- D. Poddebniak, J. Somorovsky, S. Schinzel, M. Lochter, P. Rösler, *Attacking Deterministic Signature Schemes using Fault Attacks*, IEEE EuroS&P 2018, ePrint 2017/1014: https://eprint.iacr.org/2017/1014
- N. Samwel, L. Batina, G. Bertoni, J. Daemen, R. Susella, *Breaking Ed25519 in WolfSSL*, CT-RSA 2018, ePrint 2017/985: https://eprint.iacr.org/2017/985
- T. Ristenpart, S. Yilek, *When Good Randomness Goes Bad: Virtual Machine Reset Vulnerabilities and Hedging Deployed Cryptography*, NDSS 2010: https://www.ndss-symposium.org/ndss2010/when-good-randomness-goes-bad-virtual-machine-reset-vulnerabilities-and-hedging-deployed/
- M. Bellare, Z. Brakerski, M. Naor, T. Ristenpart, G. Segev, H. Shacham, S. Yilek, *Hedged Public-Key Encryption: How to Protect against Bad Randomness*, ASIACRYPT 2009: https://cseweb.ucsd.edu/~syilek/ac09.html
- J. Breitner, N. Heninger, *Biased Nonce Sense: Lattice Attacks against Weak ECDSA Signatures in Cryptocurrencies*, FC 2019, ePrint 2019/023: https://eprint.iacr.org/2019/023
- Milk Sad (CVE-2023-39910, libbitcoin `bx seed`, mt19937): https://milksad.info/disclosure.html ; https://nvd.nist.gov/vuln/detail/CVE-2023-39910
- Unciphered, *Randstorm* (BitcoinJS weak SecureRandom, 2011–2015): https://www.unciphered.com/disclosure-of-vulnerable-bitcoin-wallet-library-2/
- getrandom 0.2.17 documentation (backends; "we always choose failure over returning known insecure 'random' bytes"): https://docs.rs/getrandom/0.2.17/getrandom/
- getrandom issue #414 (Windows: switch to ProcessPrng) and #314 (BCryptGenRandom failures): https://github.com/rust-random/getrandom/issues/414 ; https://github.com/rust-random/getrandom/issues/314
- LWN, *Random numbers and virtual-machine forks* (Linux vmgenid, 5.18): https://lwn.net/Articles/887207/ ; J. Donenfeld, *Random number generator enhancements for Linux 5.17 and 5.18*: https://www.zx2c4.com/projects/linux-rng-5.17-5.18/
- N. Ferguson, *The Windows 10 random number generation infrastructure* (Microsoft whitepaper, 2019; VM-Generation-ID reseed): https://download.microsoft.com/download/1/c/9/1c9813b8-089c-4fef-b2ad-ad80e79403ba/Whitepaper%20-%20The%20Windows%2010%20random%20number%20generation%20infrastructure.pdf
- ed25519-dalek `batch.rs` (transcript-derived, optionally hedged batch weights): https://github.com/dalek-cryptography/curve25519-dalek/blob/main/ed25519-dalek/src/batch.rs
- NIST FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard* (§6 internal functions for testing; approved RBG): https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf
- M. Möser et al., *An Empirical Analysis of Traceability in the Monero Blockchain*, PETS 2018 (predictable or biased decoy selection as an anonymity loss): https://petsymposium.org/popets/2018/popets-2018-0025.php [assumed URL; the paper itself is well known]
- In-tree: `docs/reviews/full-review-2026-09-27/R2-crypto.md` §6, `SX1-core-crossreview.md`, `docs/transactions.md` §10.
