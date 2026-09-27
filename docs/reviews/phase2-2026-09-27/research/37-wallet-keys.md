# 37 wallet-keys: research dossier (phase 2, phase 1)

Agent 37, 2026-09-27. Read-only research. No file in the repository was changed, and nothing was built or run.
This is internal engineering work, not an audit. Nothing here claims that BlackSilk or its wallet is secure.

Evidence tags: **[math]** mathematically established; **[test: name]**; **[src]** source-read; **[assumed]**; **[unknown]**; **[web]** primary external source (cited in §8).

---

## 1. Scope and what I read

**Commit:** `9e422d8` on `rebuild/core` (`git rev-parse --short HEAD`).

**Code read in full:**
- `crypto/src/keys.rs` (328 lines, with its 6 tests)
- `px/src/wallet.rs` lines 1–520 (key domains, `Derivation`, `Account`, `RangeViewKey`, `IncomingViewKey`, `hedge_secret`, witness helpers) and `derivation_tests` (lines 963–1120)
- `px/src/delivery.rs` lines 1–320 (module docs, `DeliveryKeys::derive`, `seal`, `open`)
- `px-core/src/record.rs` lines 1–80 (`Keys`, `diversifier`)
- `wallet/src/file.rs` (all, 4 tests), `wallet/src/lib.rs`, `wallet/Cargo.toml`
- `wallet/src/wallet.rs` lines 1–960 (errors, `SecretString`, `Persisted`, `file_version`, `Wallet`, constructors, `mnemonic`, `from_mnemonic_with`, windows, `to_json`/`from_json`, `repair_windows`)
- `wallet/src/main.rs` lines 1–480 and 600–700 (CLI, `password`, `os_rng`, `read_secret`, create/restore, vault lock), 756–777 (`seed`)

**Code read in part:** `wallet/src/px.rs` (grep of the key cache, the index window and `ContractRecord.secret`); `px-core/src/kernel.rs` (per-input `sk`, lines 14, 270–278, 412); `tx/src/builder.rs:320–340, 465–485`; `tx/src/px_builder.rs:80–100, 205–220`; `crypto/src/hash.rs` (tags); `chain/src/manager.rs:1315–1340`; every `hedge_secret()` and `from_seed(` call site (grep).

**Dependency sources read** (registry, pinned by `Cargo.lock`): `argon2-0.5.3` (`Cargo.toml` features, `lib.rs` 229–330, 480–510, `block.rs`), `aes-gcm-0.10.3` (features, `lib.rs` 225–245), `bip39-2.2.2` (features, `lib.rs` 190–540, 611), `chacha20poly1305-0.10.1` (features).

**Tests read:** `crypto/src/keys.rs::tests` (6); `px/src/wallet.rs::derivation_tests` (4); `wallet/src/file.rs::tests` (4); `wallet/src/wallet.rs` tests `secrets_stay_out_of_error_messages`, `the_mnemonic_round_trips_without_reallocating`, `wallet_files_keep_their_px_key_derivation`, `the_wallet_is_bound_to_its_genesis`, `files_without_a_genesis_id_are_refused`, `a_stored_vault_secret_survives_a_save_and_load`; the e2e list in `wallet/tests/e2e.rs`.

**Docs and reports read:**
- `docs/reviews/full-review-2026-09-27.md` (wallet rows, never-change items 11, 12, 28, P1-8, C8, D20)
- `docs/reviews/autonomous-session-2026-09-27.md` (wallet and randomness items)
- `full-review-2026-09-27/R11-wallet.md` (in full), `R2-crypto.md` §10–§13, `I2-identity-governance.md` (I2-F2, I2-F3, I2-R1), `I4-sustainability-scaling-pq.md` §3.2 (I4-6), `SX2-systems-crossreview.md` (C8)
- `docs/reviews/wallet-review.md` §1c (round 3: derivation 2, seed-format design)
- `docs/px.md` §3, §3.1; `docs/transactions.md` §2; `docs/blocks.md` §10 (seed words, wallet file)
- `C:/bszkeval/p2/brief.md`, `roster.md` (37 and neighbours 13, 17–19, 28, 36, 38–41, 44, 47–49), `decisions.md`
- Dossiers `17-stealth-janus.md` and `18-crypto-randomness.md` (in full)

**Primary external sources studied:** ZIP 32, ZIP 316, the Carrot spec (key hierarchy §5–§6), the Jamtis spec, BIP-39, SLIP-39, Polyseed, the Electrum seed-version document, RFC 9106 §4 and security considerations, the `zeroize` crate documentation, and the RustSec/GHSA advisory for `aes-gcm` (CVE-2023-42811). Full list in §8.

---

## 2. Current state

### 2.1 Key hierarchy as implemented

```text
seed (32 bytes, getrandom)                                   wallet.rs:565-570
 ├─ v1:  k_s = Hs("wallet/spend-key", seed)   k_v = Hs("wallet/view-key", seed)   keys.rs:156-163
 │        m(a,i) = Hs("subaddress", k_v ‖ LE32 a ‖ LE32 i),  D = K_s + mG,  C = k_v·D
 │        hedge secret = k_s bytes                               keys.rs:193-195
 └─ PX:  sk = Hk(SK, seed as 16×16-bit limbs);  nk = Hk(NK, sk), ak = Hk(AK, sk)   (kernel-fixed)
          Derivation V1 (flat):  d_i = Hk(DIVERSIFIER, sk ‖ i),   delivery = derive(sk, i)
          Derivation V2 (default): dk = Hk(DIV_KEY, sk), ivk = Hk(IVK, sk)
                                  k = i >> 16; dk_k = Hk(DIV_RANGE, dk ‖ k), ivk_k = Hk(IVK_RANGE, ivk ‖ k)
                                  d_i = Hk(DIVERSIFIER_V2, dk_k ‖ i),  delivery = derive(ivk_k, i)
          owner_i = Hk(OWNER, ak ‖ nk ‖ d_i);  delivery: v_i = H64("px/delivery-view", root ‖ i) mod ℓ,
          kem_seed_i = H64("px/delivery-kem", root ‖ i)         delivery.rs:125-133
          hedge secret = sk bytes                                px/src/wallet.rs:319-325
```

- Seed words: 24 BIP-39 English words that encode the 32 raw seed bytes (not BIP-39's PBKDF2; no passphrase) [src: `wallet.rs:574-624`; `docs/blocks.md` §10].
- The wallet file records `network`, `genesis_id` (required), `derivation` and `version` (1 ↔ derivation V1, 2 ↔ V2) [src: `wallet.rs:322-371, 857-897`; test: `wallet_files_keep_their_px_key_derivation`, `the_wallet_is_bound_to_its_genesis`, `files_without_a_genesis_id_are_refused`].
- Wallet file: `"BSW1" ‖ m ‖ t ‖ p ‖ salt ‖ nonce ‖ AES-256-GCM(JSON)`, header as AAD, Argon2id 64 MiB / t=3 / p=1, fresh salt and nonce per save, atomic replace, 0600 on Unix [src: `file.rs`; test: `round_trip`, `wrong_password_and_tampering_are_rejected`, `atomic_write`, `wallet_files_are_owner_only`].

### 2.2 What is correct and well designed

1. **Domain separation and independence of `k_s`, `k_v`.** Both are independent hash outputs of the seed (not Monero's `k_v = H(k_s)`) [src]. Degenerate keys are refused [test: `view_keys_reject_degenerate_values`]; strict address decoding [test: `address_encoding_is_strict`].
2. **Quantum-recovery precondition holds.** Every spend-capable v1 key is `Hs(tag, 32-byte seed)` and PX `sk = Hk(SK, seed)` (never-change item 11; I4-6) [src].
3. **PX V2 hierarchy is wallet-only.** The kernel takes `sk` and `d` as witnesses and never recomputes `d` [src: `kernel.rs:270-278`], so V2 needs no consensus change [test: `the_kernel_accepts_v2_spends` (native kernel, no proof), which also shows the wrong derivation's `d` is refused].
4. **V2 keeps `sk`, `ak`, `nk`, changes every address**, and range roots are unrelated [test: `v2_keeps_the_spend_key_and_changes_the_addresses`, `range_views_see_their_range_only`].
5. **Versioned wallet file.** Inconsistent `(version, derivation)` pairs are refused, older wallets refuse version 2 instead of deriving wrong addresses [test: `wallet_files_keep_their_px_key_derivation`].
6. **Genesis binding (R15-3)** in the file and at every sync [test: `the_wallet_is_bound_to_its_genesis`].
7. **Wallet file construction is standard** (Argon2id + AES-GCM, header AAD, no nonce reuse because the key is fresh per save) [math; tests above]. `aes-gcm 0.10.3` is the release that fixed CVE-2023-42811 (plaintext exposure in `decrypt_in_place_detached` on tag failure) [web; `Cargo.lock`]; the wallet uses the allocating `decrypt`, which was never affected [src].
8. **Redaction.** `Account`, `RangeViewKey`, `IncomingViewKey` have redacting `Debug`; `h32` never echoes a secret field [test: `secrets_stay_out_of_error_messages`].
9. **Mnemonic output** is written into a preallocated `Zeroizing<String>` [test: `the_mnemonic_round_trips_without_reallocating`].

### 2.3 What the tests do NOT prove

- **No derivation is pinned to fixed bytes** on the key side: neither `seed → k_s, k_v`, nor `seed → sk, ak, nk`, nor any V2 root, diversifier, owner tag, delivery key or address. `derivation_tests` are relational (V1 = the flat formula computed by the same code; V2 ≠ V1). A consistent refactor would pass every test and silently change every restored wallet (the PX analogue of F17-1).
- **No test of what a disclosed key can see beyond its intended scope** (§3.3, §3.4).
- **No test of seed entry robustness** (case, prefixes, a wrong word) and no test of cross-network restore.
- **No zeroization test** is possible in safe Rust; claims are "best effort" (the docs agree).

---

## 3. Problems in scope

### 3.1 Seed format: no version, network or birthday (R11-W3, re-verified)

**What and why.** The 24 words encode the raw 32-byte seed with BIP-39's 8-bit checksum [src: `wallet.rs:581-624`]. The format predates versioned derivation. Consequences today:
1. **Silent PX loss on restore.** `restore` defaults to derivation 2 [src: `main.rs:55-60`]; a seed of a V1 wallet restores with no error and finds no PX records. The CLI prints a hint, but the words cannot tell.
2. **No birthday.** `--restore-height` defaults to 1 (`main.rs:52-53`); `create` silently falls back to 1 when the node is unreachable (`main.rs:366`, W-F15). A too-high height silently misses funds.
3. **No network binding (new consequence).** The same seed gives the same `k_s, k_v, sk, dk, ivk` on every network [src: `keys.rs:156`, `px/src/wallet.rs:258`; `delivery.rs:26-35` says so]. Only the address *encoding* differs. So a v1 or PX address posted from the testnet (bug reports, faucets, logs) decodes to the **same keys** as the user's mainnet address at the same index: anyone can link the two. This is a cross-network privacy leak, not only a "careless reuse" risk as R11 framed it.
4. **BIP-39 confusion.** A Bitcoin BIP-39 24-word seed is accepted and derives unrelated keys; a BlackSilk seed typed into a BIP-39 wallet is accepted likewise.

**Security consequences.** Funds invisibility (not loss) after restore; cross-network address linkage (privacy); support load. Not consensus-critical. Privacy-critical (item 3).

**Prior art [web]:**
- **Polyseed** (Monero): 16 words, 150-bit secret, 10-bit birthday at ~1-month resolution from Nov 2021, 5 feature bits (passphrase flag, KDF-update bit, 3 user bits), one Reed–Solomon check word over GF(2048); the coin is bound by XOR-ing a coin flag into the second word after the checksum, so a seed of another coin fails the checksum; key = PBKDF2-HMAC-SHA256 (10,000 iterations) with the birthday, features and coin in the domain separation. Its 150-bit secret targets 128-bit classical security (ed25519), which is too small for PX's post-quantum claims (Grover) — R11's point stands.
- **ZIP 32**: seeds MUST be 32–252 bytes with ≥ 256 bits of entropy; the path `m/32'/coin_type'/account'`, and "all cryptocurrency testnets share coin_type index 1", so testnet and mainnet keys differ.
- **BIP-39**: `CS = ENT/32`, no version; "first four letters" identify a word uniquely. The spec itself acknowledges the missing version.
- **Electrum**: a version encoded in `HMAC-SHA512("Seed version", phrase)` prefixes, at a cost of ~8 bits; it rejects BIP-39 because it lacks a version.
- **SLIP-39**: 10-bit words, RS1024 checksum (30 bits), iteration exponent, passphrase without validity check.

**Design (proposal: BlackSilk seed v1).**

```text
27 words from the BIP-39 English list (11 bits each) = 297 bits
  25 data words (275 bits):  entropy 256 ‖ version 5 ‖ network 2 ‖ birthday 10 ‖ features 2
   2 check words (22 bits):  Reed–Solomon over GF(2^11), systematic, distance 3;
                             a fixed "BlackSilk seed" tweak XOR-ed into check word 1 (Polyseed-style)
master = H32("blacksilk/seed/master/v1", LE8 version ‖ LE8 network ‖ LE8 features ‖ entropy)
then:  k_s = Hs("wallet/spend-key", master), k_v = ..., PX sk = Hk(SK, master limbs)  (unchanged formulas)
birthday = floor(creation tip height / 2^14)   (2^14 blocks ≈ 22.8 days; 10 bits ≈ 64 years at 120 s)
network: 0 mainnet, 1 testnet, 2 regtest, 3 reserved.  features: bit 0 passphrase (reserved, must be 0), bit 1 reserved.
```

Why these choices:
- **27 words** is not a BIP-39 length (12/15/18/21/24), so BIP-39 wallets refuse it and BlackSilk refuses BIP-39 phrases [math].
- **Two RS check words** detect every error of up to two words (including a transposition of two words) and correct one unknown wrong word, or two words at known positions; one check word (Polyseed) only detects one [math: MDS code, `d = n−k+1 = 3`]. Cost: one extra word over wallet-review.md's 26-word hash-checksum design, which misses 1/8192 random errors and corrects none.
- **The 32-byte `master` stays the interface.** Every existing formula keeps "a 32-byte seed", so never-change item 11 and the I4-6 recovery statement hold with witness = `master`; 17's v1 vectors (from the 32-byte seed onward) are unaffected [math].
- **Version and network enter the derivation; the birthday does not.** A wrong or edited birthday then changes only the scan start, never the keys (Polyseed binds the birthday; the gain is small and it prevents a user correcting it) [design choice].
- **Height, not time, for the birthday**: the network is in the words, so heights are unambiguous, and no time→height lookup is needed (a lookup would be another query revealing the birthday to a remote node, R3-9). Restore starts at `birthday·2^14`.
- **No PBKDF2 stretching.** 256-bit entropy needs none. Stretching belongs to a future passphrase feature (Argon2id of the passphrase mixed into `master`), reserved now.

**Legacy.** The testnet has not launched, pre-binding files are already refused, and pre-v3 chains are retired. The 24-word format and PX derivation V1 therefore have no users on the v3 chain. Recommendation: remove both at the v3 reset (keep V1 only as a `#[cfg(test)]` regression helper if 20/22 need it), so the seed version implies exactly one derivation and restore can never guess wrong.

**Trade-offs and risks.** A new word count and a custom checksum are non-standard (no hardware wallet or third-party tool support; acceptable, none exists). RS code must be implemented in pure Rust (~150 lines over GF(2048), no dependency). The wordlist is reused from `bip39::Language::English.word_list()` [src: `language/mod.rs:103`], so the `bip39` crate stays only as a wordlist provider.

**Tests.** Pinned vectors (words ↔ fields ↔ master ↔ every key, §3.6); exhaustive single-word substitution detected and corrected; all two-word transpositions detected; network mismatch refused with a clear error; 24-word BIP-39 phrases refused; upper-case and 4-letter prefixes accepted; reserved bits non-zero refused; a fuzz target for the parser (41).

**Invariants.** 256-bit entropy from the OS CSPRNG only (no brain wallets, I4-6 precondition 3); `master` is 32 bytes; every spend-capable key is a hash of `master`; the network enters the key derivation.

### 3.2 Derived hedge keys (decision item with 18)

**What.** `WalletKeys::hedge_secret()` returns the raw `k_s` bytes and `Account::hedge_secret()` the raw PX `sk` [src: `keys.rs:193`, `px/src/wallet.rs:319`]. They key every wallet `HedgedRng` stream (transfer anchors and masks, PX builder, delivery, witness hedge).

**Why change.** (i) The raw spend key is then absorbed next to attacker-influenced context in BLAKE2b (18's F18-6 DPA surface); a derived key confines any leak to the hedge key. (ii) Ed25519 is the precedent: RFC 8032 derives the nonce "prefix" from the private key separately from the signing scalar; the hedged-signature draft mixes a separate secret likewise [web]. (iii) Deciding now avoids moving 18's pinned hedge vectors twice.

**Proposal.**
```text
hk_v1 = H32("wallet/hedge-key/v1", k_s)          WalletKeys::hedge_secret()
hk_px = H32("px/wallet/hedge-key/v1", bytes(sk))   Account::hedge_secret()   (BLAKE2b, not Hk: it only feeds HedgedRng)
```
Derived **from the spend secret, not from the seed**, so any signer that holds only `k_s` (a future hardware signer, R11 §4.1) can compute it, and never from view material (a view-key holder must not predict decoys or anchors under a broken RNG, 18's F18-4 reasoning).

**Consequences.** No wire, consensus or address change. Outputs built under a broken RNG change (18's broken-RNG tests are relational and keep passing; pinned `ZeroRng` builder vectors, if any, move once). CLSAG's own nonce stream uses `p` and `z`, not the hedge secret, so the pinned CLSAG vector is unchanged [src: 18 §2.2].

**Tests.** `hedge_key_is_not_the_spend_key`; a pinned vector for each; the existing broken-RNG suites unchanged.

### 3.3 `IncomingViewKey` discloses the whole range, not the listed addresses (new)

**What.** `IncomingViewKey = (ivk_k, [(i, owner_i)])` [src: `px/src/wallet.rs:215-245`]. Its docs and `docs/px.md:124-129` say it "finds and opens the records received at those addresses" and "cannot derive further addresses". But `DeliveryKeys::derive(ivk_k, i)` works for **every** `i` of the range (65,536 addresses) [src: `delivery.rs:125-133`]. With it the holder:
- decrypts every record sent to any address of the range: `open` first performs ECDH, ML-KEM decapsulation and the authenticated AEAD decryption, and only then recomputes `cm` [src: `delivery.rs:278-310`]. The AEAD tag already authenticates the plaintext `(contract, value, data, rcm)`; the missing owner tag only stops "acceptance", not disclosure;
- fully accepts **contract records** at undisclosed indices, because `open` substitutes owner 0 for them and needs no owner tag [src: `delivery.rs:311-315`];
- recognises the undisclosed PX addresses of the range if it sees them (their `V_i` and `ek_i` are derivable).

**Consequence.** Over-disclosure of amounts and contract state for up to 65,536 addresses, against the documented least-privilege property (I2-F3's purpose). Privacy-critical once exported; today there is no CLI export, so it is latent.

**Prior art.** Zcash's IVK is honestly scoped to the whole account (all diversified addresses) [web: ZIP 32/316]; a per-address disclosure in Zcash is a payment disclosure, not a key. So either scope the key honestly or disclose per-address secrets.

**Fix options.**
- (a) **Per-address incoming package**: for each disclosed `i`, export `(v_i, kem_seed_i, owner_i)` (32 + 64 + 32 bytes) and never `ivk_k`. Exactly the listed addresses, nothing else. Recommended.
- (b) Keep `ivk_k` but rename the type to a range incoming key and document that it discloses the whole range; drop the owners list (useful only to accept user records).
- Both are wallet-only. (a) needs `DeliveryKeys` to expose a constructor from `(v, kem_seed)` or a per-address derive.

**Tests.** "An incoming package for addresses {3,5} cannot decrypt a record sent to address 4 or to a contract record addressed to 4" (fails today, passes after (a)).

### 3.4 Range scoping is nominal: all addresses in range 0, and `nk` is wallet-global (new, design)

**What.**
1. PX addresses are issued contiguously from 0 with at most 2,000 ahead [src: `wallet/src/px.rs:46-59, 456`], so every address in use lies in range 0 (`RANGE_BITS = 16`, `px/src/wallet.rs:88`); `range_view(0)` is the whole wallet. wallet-review.md §1c admits the allocation policy is unwritten.
2. `RangeViewKey` contains `nk`, which is **account-wide** (`nk = Hk(NK, sk)`, kernel-fixed). The docs say "receipts and spends in range k; nk yields nullifiers only for records the holder can open". True, but the holder can "open" any record whose opening it learns elsewhere: a payer knows the full opening of the record it created (value, `rcm`, `rho` from its own `nf_0`, `cm`). A range-2 auditor colluding with a merchant who paid the user in range 0 learns when that payment was spent.

**Consequence.** Spend visibility is not range-scoped. Low (design/documentation); matters for "time-scoped audit" claims.

**Solutions.** (i) Document it (FVK spend visibility is account-wide, as in Zcash where `nk` is per account). (ii) True scoping by **hardened accounts**: `sk_k = Hk(SK_ACCOUNT, sk ‖ k)` per range/account, as ZIP 32 hardens `account'`. The kernel reads a separate `sk` per input [src: `kernel.rs:270-278, 412`], so a transaction may still spend records of two accounts together — **no consensus change**. Cost: `sk` is no longer the single PX key (hedge keys per account; the never-change "PX `sk = Hk(SK, seed)`" link becomes "`sk_0 = Hk(SK, master)`, accounts from it"); scanning cost unchanged per address. (iii) Allocation policy: range `k = birthday epoch of issuance` (reuse the seed's 2^14-block epoch), change on an internal branch inside each range (R11-W14), so restore can enumerate ranges from the birthday.

Recommendation: (i) now (P1 docs); decide (ii) versus the status quo before the seed version is frozen, because (ii) changes which addresses a seed derives (P0 decision, P2 implementation).

### 3.5 Vault secret derivation: the decision log is internally inconsistent (new)

**What.** `decisions.md` (agent 18): "Vault secret: derived from the wallet's PX secret via `hedged_digest` (W4). Accepted, and recoverable from the seed, which is a plus." A hedged digest mixes fresh OS randomness (`fresh32`) into the output [18 §2.1], so it is **not** recoverable from the seed. Today the secret is plain `random_digest(os_rng)` [src: `main.rs:641`], stored in the file (R11-W1 fix) but not seed-recoverable.

**Proposal (deterministic, unique, seed-recoverable).**
```text
secret = H32("px/wallet/vault-secret/v1", hk_px, network_id, contract, rho_vault)
rho_vault = Hk(RHO, nf_0 ‖ j)   (the vault record's own rho; nf_0 is the nullifier of the lock's first input,
                                  a real funding record, so it is known before proving)
```
- **Unique**: `rho` is unique on chain because nullifiers are unique [src: `docs/px.md` §3]. Two builds with the same secret must spend the same input, so at most one is mined [math].
- **Unpredictable** without `hk_px`; **one-way**, so sharing the secret with a claimer reveals nothing about `hk_px` [math, ROM].
- **Recoverable**: after a restore, the wallet re-derives the candidate from any vault record it holds the opening for (records delivered to itself) and checks `Hk(LOCK, secret) == data`.
- Needs the builder to put a real input in slot 0 for vault locks (true for every funded lock) and a check that refuses otherwise.
- The vault `blind` and contract `rcm` keep 18's hedged helper (they must be fresh per build).

### 3.6 No pinned vectors for key derivations (new; PX analogue of F17-1)

Same failure mode as F17-1, larger blast radius: a reordered limb split in `from_seed_with`, a changed `split()` or a swapped tag would silently change every PX address and delivery key. Fix: a vector file that pins, for fixed seeds: words → fields → `master`; `k_s, k_v, K_s, hk_v1`; `sk, ak, nk, hk_px`; `dk, ivk, dk_k, ivk_k` for k ∈ {0, 1, 2^16−1}; `d_i, owner_i, V_i, H(ek_i)` for i ∈ {0, 1, 65,535, 65,536, 70,001}; plus an independent re-derivation from the spec formulas (raw `blake2` and the `px-core` Poseidon2 permutation called directly), in the style of `kat_matches_definition`. 17 pins the v1 part from the 32-byte seed; I pin the seed layer, the hedge keys and PX.

### 3.7 View-only wallets (R11-W15)

- **v1.** `ViewKeys (k_v, K_s)` detects incoming outputs and amounts [src: `keys.rs:81-137`]. It cannot compute key images (`I = p·Hp(O)` needs `k_s`), so a view-only balance never sees spends, and it sees change as income (F17-10). This is inherent to the CLSAG key-image definition, which is consensus and never-change. Monero's answer is key-image export from the signer and import into the view wallet; Carrot's answer (a separate generate-image key `k_gi` with `K_s = k_gi·G + k_ps·T`, a view-all tier holding `s_vb`) needs a second generator in the output key, i.e. a consensus change [web: Carrot §5.2–5.3]. Recommendation: a view-only file type plus key-image import (P2, wallet-only); document the limitation.
- **PX.** `RangeViewKey` is a real full viewing key (receipts and spends) [test: `range_views_see_their_range_only`]. Missing: a CLI export/import and a watch-only scanner mode that holds no `sk` (P2; scanner is 39's).
- **Tiers compared.** Carrot and Jamtis separate generate-address, find-received, view-received and view-all [web]. BlackSilk v1 has one view tier (`k_v` does address generation and ECDH). PX V2 has two (full range view, incoming). A generate-address-only tier for PX would be `(ak, nk, dk_k, ivk_k)` minus decryption, which does not exist as a separate secret; not worth adding for the testnet.

### 3.8 Spend/prove split (R11-W4)

Unchanged: the proof is the authorization and needs `sk`. Fixing it is a kernel (consensus) redesign: a hash-based signature (WOTS+/XMSS/SPHINCS+-like with Poseidon2) verified in-circuit against a key committed in a new `ak`, which means a new owner-tag domain and new addresses. **Correction to R11-W2's "leave room now":** with a versioned `master` seed (§3.1), a future authorization secret simply gets its own domain under `master` and a new seed/derivation version; restore can derive both. Nothing needs reserving in today's keys. Warn that XMSS-style state cannot be recovered from a seed (R11 §6.3). P3; P1 doc: "never share `sk` or delegate PX proving".

### 3.9 Zeroization (R2-C10, deepened with dependency evidence)

| # | Gap | Evidence | Fix |
|---|---|---|---|
| Z1 | Argon2 memory (64 MiB of password-derived blocks) is freed without wiping. `argon2 0.5.3` is built without its `zeroize` feature; even with it, the crate wipes only the initial hash and final block, not the memory blocks. RFC 9106: "enable the memory-wiping option" when side channels are uncertain. | [src: `wallet/Cargo.toml:31`; `argon2-0.5.3/src/lib.rs:229-231, 322, 501`; `block.rs:151`] | enable `argon2/zeroize`; call `hash_password_into_with_memory` with a `Zeroizing<Vec<Block>>` |
| Z2 | AES-256 key schedule and GHASH key not wiped: `aes-gcm` built without `zeroize` | [src: `wallet/Cargo.toml:32`; `aes-gcm-0.10.3/src/lib.rs:239`; `aes-0.8.4/Cargo.toml:58-70`] | enable `aes-gcm/zeroize` (turns on `aes/zeroize`) |
| Z3 | `bip39::Mnemonic` and its parse buffers not wiped (feature off); the docs admit it | [src: `wallet.rs:578-580`; `bip39-2.2.2/Cargo.toml:108-112`] | moot after §3.1 (own parser over the word list with `Zeroizing` buffers); else enable `bip39/zeroize` |
| Z4 | `file::decrypt` returns a plain `Vec`; `lib::load` wipes it afterwards, fine, but the type does not enforce it | [src: `file.rs:107`, `lib.rs:17-23`] | return `Zeroizing<Vec<u8>>` |
| Z5 | Password: `password()` returns a plain `Vec`; on "passwords differ" `p` is dropped unwiped; every `?` between `password()` and `pw.zeroize()` leaks the copy (`load(...)?`, `save(...)?`) | [src: `main.rs:220-233, 364-375, 392-394, 406-407, 771-772`] | `Zeroizing<Vec<u8>>` end to end |
| Z6 | `ContractRecord.secret: Option<String>` (vault secret hex) is not a `SecretString` | [src: `wallet/src/px.rs:214`] | reuse `SecretString` |
| Z7 | `px_core::record::Keys` is `Copy`: `range_view` copies `nk`, `ak` | [src: `record.rs:19`, `px/src/wallet.rs:291`] | accepted (best effort); `nk`/`ak` are view material |
| Z8 | Witness `sk` buffers (known item) and BLAKE2b state in `HedgedRng` (F18-8) | known | owners 20/22 and 18 |

Rust practice [web: `zeroize` docs]: volatile writes plus a fence; no guarantee against copies from moves, `Copy`, stack spills or `Vec` reallocation; registers, `mlock` and swap are out of scope. `mlock` needs `unsafe` (policy forbids it in BlackSilk crates), so OS-level exposure (swap, hibernation, core dumps) should be documented as the operator's responsibility (encrypted swap, core dumps off), and the docs must keep saying "best effort".

### 3.10 KDF parameters (R11-W12, re-verified) and minor corrections

- `decrypt` still accepts `m ≤ 4 GiB`, `t ≤ 100`, `p ≤ 64` and has no minimum [src: `file.rs:118`]. Recommend: cap at 1 GiB / t ≤ 10 on load; refuse to **write** below the default.
- R2 §10 calls 64 MiB / t=3 / p=1 "RFC 9106 second recommendation"; the RFC's second option is t=3, **p=4**, 64 MiB [web]. With the single-threaded RustCrypto implementation the defender's cost is the same for p=1 and p=4, so this is a documentation correction only (Info).
- R11-W13 is partly inaccurate: `bip39`'s `std` feature does pull in `unicode-normalization` [src: `bip39-2.2.2/Cargo.toml` `std = ["alloc", ...]`, `alloc = ["unicode-normalization"]`], but `parse_normalized` never normalizes, and the error already names the word index (`UnknownWord(i)`, 0-based). Case-sensitivity and missing prefix entry remain.
- `px/src/delivery.rs:26-35` module docs ("no view/spend separation... delivery keys derive from `sk`") are stale under V2 (Info).
- `Account::from_seed` defaults to V1 while `Wallet::from_seed` defaults to V2 [src: `px/src/wallet.rs:252-254`, `wallet.rs:521-523`]; every fuzz target and example exercises V1 only (Info).

---

## 4. New findings

| ID | Severity | Status | Location | Scenario | Confidence |
|---|---|---|---|---|---|
| F37-1 | **Medium** (privacy + funds visibility) | Partially implemented (file records the derivation; words do not) | `wallet/src/wallet.rs:574-624`; `wallet/src/main.rs:47-60, 366`; `crypto/src/keys.rs:156`; `px/src/wallet.rs:258` | (a) A user posts a testnet address in a bug report; the same seed's mainnet address at that index has identical keys, so anyone links them. (b) A V1-era seed restored with the default finds no PX records, with no error. (c) A too-high `--restore-height` silently misses funds. | High |
| F37-2 | **Medium** (privacy; latent: library API only) | Not implemented | `px/src/wallet.rs:208-245`; `px/src/delivery.rs:278-315`; `docs/px.md:124-129` | An auditor given an `IncomingViewKey` for addresses {0..8} derives delivery keys for all 65,536 addresses of the range and decrypts every incoming amount, and fully accepts contract records at undisclosed addresses. | High |
| F37-3 | Low (design/docs) | Accepted limitation, undocumented | `px/src/wallet.rs:88, 128-205`; `wallet/src/px.rs:456` | A range-2 full viewer colluding with a payer who paid range 0 computes that record's nullifier (global `nk`) and sees its spend; and since all addresses sit in range 0, `range_view(0)` is the whole wallet. | High |
| F37-4 | Low (hardening; decision item) | Not implemented | `crypto/src/keys.rs:193-195`; `px/src/wallet.rs:319-325` | The raw spend secrets key every hedge stream next to attacker-influenced data (F18-6 surface); a hedge-key change after 18 pins vectors moves them twice. | High |
| F37-5 | Low (decision correctness) | Not implemented | `decisions.md` (agent 18, vault secret); `wallet/src/main.rs:636-643` | The accepted "hedged_digest, recoverable from the seed" cannot be both; implemented as hedged, a restored wallet cannot recover a vault secret. | High |
| F37-6 | Low | Partially implemented (best effort) | Z1–Z6 in §3.9 | A memory disclosure after unlock (swap, crash dump) yields Argon2 blocks from which the file key follows, or the AES key schedule, or a password copy left by an error path. | High (source), Medium (exploitability) |
| F37-7 | Low (= R11-W12, re-verified) | Not implemented | `wallet/src/file.rs:118` | A corrupted header makes load allocate up to 4 GiB; a re-save can keep weak parameters. | High |
| F37-8 | Informational | Not implemented | `px/src/wallet.rs::derivation_tests`; no key vector file | A consistent refactor of limb splitting or a tag changes every PX address; all tests pass. | High |
| F37-9 | Informational | Not implemented | `px/src/wallet.rs:252-254`; `fuzz/fuzz_targets/delivery_open.rs:12`; `px/examples/*` | Legacy V1 is the library default and the only fuzzed derivation. | High |
| F37-10 | Informational (docs) | Not implemented | `px/src/delivery.rs:26-35`; R2 §10 "second recommendation"; R11-W13 | Stale or inaccurate statements. | High |
| F37-11 | Low (UX/safety) | Not implemented | `wallet/src/main.rs:756-759, 366` | `seed` prints the words with no confirmation; `create` silently uses height 1 without a node (W-F15). | High |
| F37-12 | Accepted limitation | Accepted limitation | `crypto/src/keys.rs` (key image needs `k_s`) | A v1 view-only wallet cannot see spends and counts change as income; fixing it needs Carrot-style generators (consensus). | High |
| F37-13 | Accepted limitation (= R11-W4) | Not implemented (P3, CONSENSUS) | `px/src/wallet.rs:357-381`; `px-core/src/kernel.rs:270-278` | Delegated proving hands over permanent PX spend authority. | High |

**Challenges to existing reports:**
- **R11-W3 framing**: missing network binding is a *linkage* leak across networks, not only a reuse risk (F37-1a).
- **I2-F3 / docs/px.md §3.1**: the incoming package as built is range-scoped, not address-scoped (F37-2).
- **I2-R1**: "range = time scope" does not hold without per-range `nk` or an allocation policy (F37-3).
- **R11-W2 "leave room for an authorization key"**: unnecessary once `master` is versioned (§3.8).
- **decisions.md (vault secret)**: hedged ≠ seed-recoverable (F37-5).
- **R2 §10 and R11-W13**: minor inaccuracies (§3.10).

---

## 5. Implementation plan for phase 2

None of these items changes consensus. "Identity" = testnet identity; none needs a new one. Addresses derived from a seed change for K1/K5, which the v3 reset makes free.

| # | Item | Files (ownership) | Visibility | Tests | Docs | Diff. | Prio |
|---|---|---|---|---|---|---|---|
| K1 | **Seed format v1** (§3.1): 27 words, RS(GF(2^11)) with 2 check words, version/network/birthday/features, `master` derivation; remove the 24-word format and PX derivation V1 (test-only helper if needed); `create` requires a birthday (node height or `--birthday-height`); restore starts at the birthday; case-insensitive, 4-letter-prefix entry, visible-entry option; `seed` asks for confirmation | new `wallet/src/seed.rs` (37); `wallet/src/wallet.rs` constructors/`mnemonic`/`from_mnemonic*`/`Persisted` block, lines 300–630 and 830–900 (37; serialize with 17/18/38/39); `wallet/src/main.rs` create/restore/seed/`password` (37); `px/src/wallet.rs` `Derivation` (37) | wallet policy only; changes addresses of new wallets | vectors; RS detect-2/correct-1 exhaustive over single substitutions and transpositions; network mismatch refused; BIP-39 phrase refused; reserved bits refused; restore-from-birthday e2e | `docs/blocks.md` §10, `docs/transactions.md` §2.1, `docs/px.md` §3.1, wallet README | M | **P0** (decision now; implementation before any persistent testnet user and before 18's vector pin) |
| K2 | **Derived hedge keys** (§3.2) | `crypto/src/keys.rs` `hedge_secret` (37; 17 edits tests in the same file); `px/src/wallet.rs` `hedge_secret` (37); tags in `crypto/src/hash.rs` (registry owner 19) | nothing external | `hedge_key_is_not_the_spend_key`; pinned values; 18's broken-RNG suites unchanged | `docs/transactions.md` §10 | S | **P0** (must precede 18 W1–W5 vector pins) |
| K3 | **Key-derivation vectors** (§3.6) with independent re-derivation | new `wallet/tests/key_vectors.rs`, new `px/tests/key_vectors.rs` (37); 17 owns `crypto/tests/stealth_vectors.rs` | nothing | the vector tests themselves | `docs/px.md` §3.1 test list | S | **P0** (with K1/K2) |
| K4 | **Address-scoped incoming package** (§3.3 option a), and doc correction | `px/src/wallet.rs` `IncomingViewKey`; `px/src/delivery.rs` (a `DeliveryKeys` constructor from `(v, kem_seed)`) (37) | nothing (no export yet) | the over-disclosure test (fails today) | `docs/px.md` §3.1 table | S | P1 |
| K5 | **Scoping decision** (§3.4): document global `nk` now; decide hardened accounts vs status quo; range allocation by birthday epoch plus an internal change branch (R11-W14) | `px/src/wallet.rs`; `wallet/src/px.rs` issuance (37; 39 owns scanning loops) | changes addresses if accounts are adopted | colluding-payer test (documents the limit); account isolation test if adopted | `docs/px.md` §3.1, §12 | S (docs) / M | P0 decision, P1 docs, P2 impl. |
| K6 | **Deterministic vault secret** (§3.5) plus recovery on restore | `px/src/wallet.rs` helper; `wallet/src/wallet.rs` `px_vault_lock` and PX record apply (with 18 W4 and 28); `wallet/src/main.rs:630-645` | nothing external | same input ⇒ same secret; different inputs ⇒ different; restore recovers the secret of a self-delivered lock; refused when input 0 is a dummy | `docs/px.md` §13.4 | S | P1 |
| K7 | **Zeroization bundle** Z1–Z6 | `wallet/Cargo.toml` features (37; **44 must approve**); `wallet/src/file.rs`, `wallet/src/lib.rs`, `wallet/src/main.rs` `password`, `wallet/src/px.rs:214` (37) | nothing | compile-level; existing file tests | `docs/blocks.md` "best effort"; operator note on swap/core dumps | S | P1 |
| K8 | **KDF bounds** (1 GiB / t ≤ 10 on load; no weaker-than-default write) | `wallet/src/file.rs` (37) | nothing | header with m = 2 GiB refused before allocation; weak params refused on save | `docs/blocks.md` §10 | S | P2 |
| K9 | **View-only**: v1 view-only file type plus key-image import; PX range-view export/import and watch-only mode without `sk` | `wallet/src/wallet.rs` (new mode), `wallet/src/main.rs` (37); scanner paths with 39 | nothing | view-only balance equals full balance minus spends; key-image import restores it; PX watch-only sees receipts and spends, cannot build | wallet README, `docs/transactions.md` §2 | M–L | P2 |
| K10 | **Docs**: F37-10 corrections; "never share `sk` / delegate PX proving"; what the seed recovers (R11 §3.1 table, updated) | `px/src/delivery.rs` docs; `docs/px.md`; `docs/transactions.md` (47 coordinates) | nothing | — | as listed | S | P1 |
| K11 | **Spend/prove split** research spec (hash-based in-circuit authorization) | docs only | would be CONSENSUS | — | new section in `docs/px.md` §10 | M | P3 |

**Benchmarks.** None required. Optional: restore time from a birthday vs from height 1 on a labnet chain (with 39).

**Order.** K2 and the K1 *decision* first (they unblock 17/18 vectors); then K3; K1 implementation; K7, K4, K6 in parallel; K5 after the decision; K8–K11 later.

**Invariants that must never change:**
- every spend-capable key is a hash of the 32-byte `master` (never raw-key spend import without flagging); `k_s`, `k_v`, `m(a,i)` formulas; PX `sk = Hk(SK, master limbs)` (or `sk_0` if accounts are adopted);
- 256-bit OS-CSPRNG entropy only; network and version in the `master` derivation once K1 lands;
- hedge keys derived from spend material only, never from view material;
- the authenticated, atomically replaced wallet file (AEAD with header AAD);
- per-address independent PX delivery keys (PQ address unlinkability);
- a disclosed viewing package never contains `sk`, and incoming packages never contain `nk`.

---

## 6. Dependencies and conflicts

- **17 stealth-janus:** vectors from the 32-byte seed onward are unaffected by K1 (the `master` stays 32 bytes), so 17 can pin now. `crypto/src/keys.rs` is shared (17: tests and the `insert` assertion; 37: `hedge_secret`).
- **18 crypto-randomness:** K2 feeds W1–W5; K6 replaces W4's vault-secret part (`blind`/`rcm` stay 18's). Agree the order: K2 before 18's pins.
- **19 hash-domain-separation:** register `blacksilk/seed/master/v1`, `wallet/hedge-key/v1`, `px/wallet/hedge-key/v1`, `px/wallet/vault-secret/v1`, any account domain (`0x0050_5A06+`), and the RS tweak.
- **20/22:** witness `sk` zeroization in the prover (Z8); V1 test helper if needed.
- **28 private-contracts-px:** K6 changes the vault UX (secret recoverable).
- **36 rpc-security / 38 wallet-privacy:** the birthday is still revealed to a remote node by the scan start (R3-9); K1 does not worsen it.
- **38, 39:** `wallet/src/wallet.rs` and `wallet/src/px.rs` are shared; the coordinator must serialise edits. 39 owns the scanner (watch-only mode in K9, restore-from-birthday speed).
- **40 testnet-genesis:** the network codes of the seed must match `consensus::Network`; K1 must land before public wallets exist.
- **41 fuzzing:** a fuzz target for the seed parser; switch `delivery_open` to V2.
- **44 supply-chain:** approve the feature changes (K7); `bip39` shrinks to a wordlist source (or the list is vendored as data).
- **47 docs:** `docs/blocks.md`, `docs/transactions.md`, `docs/px.md` edits.
- **48 threat-model:** F37-1a and F37-2 belong in the attack tree. **49 innovation:** K11.

---

## 7. Open questions for the coordinator

1. May the 24-word format and PX derivation V1 be **removed** at the v3 reset (no v3-chain users exist)?
2. **Seed layout:** 27 words with two RS check words (my recommendation) or wallet-review.md's 26 words with a 13-bit hash checksum?
3. **Birthday:** height-based (2^14-block epochs, network-specific) or Polyseed-style time-based?
4. **Hedge key:** derived from the spend secret (my recommendation, hardware-signer friendly) or from the seed?
5. **Vault secret:** replace the accepted hedged derivation by the deterministic `rho`-bound one (seed-recoverable)? The current decision text cannot hold as written.
6. **PX scoping:** hardened per-account `sk` (true range/time scoping, changes addresses) or document the account-wide `nk`? This must be decided with Q1–Q3, before freezing seed version 1.
7. **Passphrase feature:** reserve the bit only (my recommendation), or implement Argon2id-stretched passphrases now?
8. Is enabling the `zeroize` features of `argon2`, `aes-gcm` (and `bip39`, if kept) acceptable to 44?

---

## 8. Sources

- Zcash, ZIP 32 *Shielded Hierarchical Deterministic Wallets* (seed 32–252 bytes, ≥ 256-bit entropy; `m/32'/coin_type'/account'`; testnets share coin_type 1; internal FVK; FF1 diversifiers): https://zips.z.cash/zip-0032
- Zcash, ZIP 316 *Unified Addresses and Unified Viewing Keys* (UFVK/UIVK, F4Jumble, network HRPs, expiry metadata): https://zips.z.cash/zip-0316
- Zcash Protocol Specification (Sapling/Orchard key components, spend authorization): https://zips.z.cash/protocol/protocol.pdf
- J. Berman (jeffro256), *Carrot* specification, §5.2–5.3 key hierarchy (`s_m`, `k_ps`, `s_vb`, `k_gi`, `k_v`, `s_ga`; `K_s = k_gi·G + k_ps·T`), §6.1.3 subaddresses, wallet tiers: https://github.com/jeffro256/carrot/blob/master/carrot.md
- tevador, *Jamtis* specification (key hierarchy `k_m`, `k_vb`, `k_fr`, `k_id`, `s_ga`; five tiers; Polyseed for new wallets): https://gist.github.com/tevador/50160d160d24cfc6c52ae02eb3d17024
- tevador, *Polyseed* (16 words, 150-bit secret, 10-bit monthly birthday, 5 feature bits, RS check word over GF(2048), coin flag XOR, PBKDF2-HMAC-SHA256 10,000 iterations): https://github.com/tevador/polyseed ; Monero docs: https://docs.getmonero.org/mnemonics/polyseed/
- BIP-39 *Mnemonic code for generating deterministic keys*: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
- SLIP-0039 *Shamir's Secret-Sharing for Mnemonic Codes*: https://github.com/satoshilabs/slips/blob/master/slip-0039.md
- Electrum, *Seed Version System*: https://electrum.readthedocs.io/en/latest/seedphrase.html
- RFC 9106, *Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications*, §4 parameter choice, §7 security considerations: https://www.rfc-editor.org/rfc/rfc9106.html
- RFC 8032, *Edwards-Curve Digital Signature Algorithm* (§5.1.5–5.1.6: the nonce prefix derived separately from the secret scalar): https://www.rfc-editor.org/rfc/rfc8032
- draft-irtf-cfrg-det-sigs-with-noise (hedged signatures): https://datatracker.ietf.org/doc/draft-irtf-cfrg-det-sigs-with-noise/
- `zeroize` crate documentation (guarantees and limits: moves, copies, `Vec` reallocation, registers, `mlock` out of scope): https://docs.rs/zeroize/latest/zeroize/
- RustCrypto advisory GHSA-423w-p2w9-r7vq / CVE-2023-42811 (`aes-gcm` < 0.10.3): https://github.com/RustCrypto/AEADs/security/advisories/GHSA-423w-p2w9-r7vq ; https://nvd.nist.gov/vuln/detail/CVE-2023-42811
- Monero, *Janus attack on subaddresses* and cold-signing/key-image export practice (via 17's sources): https://www.getmonero.org/2019/10/18/subaddress-janus.html
- Dependency sources read locally (crates.io registry, versions pinned by `Cargo.lock`): `argon2 0.5.3`, `aes-gcm 0.10.3`, `aes 0.8.4`, `bip39 2.2.2`, `chacha20poly1305 0.10.1`.
- Internal: `docs/reviews/full-review-2026-09-27/{R11-wallet, R2-crypto, I2-identity-governance, I4-sustainability-scaling-pq, SX2-systems-crossreview}.md`; `docs/reviews/wallet-review.md` §1c; dossiers 17 and 18; `C:/bszkeval/p2/decisions.md`.
