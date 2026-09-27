# R11: wallet, key management and user experience

**Reviewer:** R11 (internal review, 2026-09-27). This is internal review, not an audit.

**Commit:** `f677e55` on `rebuild/core`. I also read the uncommitted A7b wallet work in
`.claude/worktrees/agent-adcbff0538d434fbf` so that I do not re-report what it already fixes.
That work is unmerged and I have not reviewed it.

**Scope:**
- `wallet/src/*`: CLI, file format, scanning, restore, pending transactions and rebroadcast, rings, PX wallet side, contract records.
- `crypto/src/keys.rs`.
- `px/src/{wallet.rs, delivery.rs, share.rs}`.
- `rpc/src/lib.rs` (client side).
- Where needed to follow the key hierarchy: `px-core/src/{record.rs, kernel.rs}`, `chain/src/address.rs`, `tx/src/{builder.rs, px.rs, params.rs, scan.rs}`.

**Method:** I read the source. I ran no builds or tests; the brief forbids them. Web research was used only for comparison, and the sources are cited in §9.

**Evidence tags:**
- **[math]**: mathematically established.
- **[test: name]**: covered by the named test.
- **[source]**: established by reading the source.
- **[assumed]**: an estimate or assumption, not measured.
- **[unknown]**: not established either way.

---

## 0. Executive summary

The v1 wallet core is careful about the problems that usually hurt privacy wallets:
- ring reuse (W-5);
- inputs reserved before sending;
- crash-safe autosave;
- a single shuffled `/outputs` query per input;
- canonical PX anchors;
- "download everything" scanning, so the node learns nothing about which outputs are the wallet's.

**This is a developer CLI, not yet a wallet for real users.** The gaps are structural, not cosmetic:

1. **Funds-loss bug (new, R11-W1).** A vault lock with a generated secret whose submission ends `Uncertain` loses the secret. The funds may already be on chain, and the vault has no timeout or refund. A7b only fixes this when the user opts into `--secret-out`.

2. **No PX viewing-key hierarchy, and it cannot be retrofitted cheaply after launch (deepens a known item).** Every PX derivation hangs off `sk`: the owner tags, the diversifiers and the delivery keys. The kernel does **not** constrain how the diversifier `d` is derived; `d` is a free witness [source]. So a Zcash-style hierarchy can be introduced **wallet-side, with no consensus change**:

   `sk → (ak, nk)`, plus a separate diversifier key and a delivery root derived from `sk`.

   It changes the addresses that a seed derives. It must therefore be decided **before the v3 genesis and the public testnet**, together with a versioned seed format (R11-W3).

3. **The seed format has no version and no birthday (new, R11-W3).** Once the PX derivation changes, old seeds silently derive different keys. Restore also defaults to a full scan from block 1.

4. **PX spend authority equals proving capability (new, design, R11-W4).** The prover needs `sk` in the witness (`px/src/wallet.rs:96-107`). Three consequences:
   - delegated proving hands over full, permanent spend authority for every PX address;
   - no hardware wallet can protect PX funds;
   - mobile users (3.8 GB and about 45 s per proof on a desktop) have no safe path.

   Fixing this is a kernel (CONSENSUS) redesign. Options are in §7.

5. **Light and mobile wallets are not possible with today's RPC.** The wallet downloads whole blocks, including about 2.2 MB of proof per PX transaction. At saturation that is about 6 GiB per day [assumed].

   The transaction hash already separates the prunable part (`tx/src/types.rs:432-447`). A **verifiable compact-block RPC** (ZIP-307 style) is therefore cheap to add and cuts PX bandwidth by about 850 times [assumed]. It is also the privacy-preserving baseline for any light client.

6. **Quantum-era recipient linkability through the PX view tag (new, low, R11-W5).** The view tag is derived only from the ECDH secret (`px/src/delivery.rs:113-115`). An adversary that can compute discrete logarithms and holds a PX address can filter that address's outputs down to about 1/256 of the others.

   The docs claim post-quantum confidentiality of record contents (true) but say nothing about unlinkability. This can be fixed wallet-side (the delivery format is not consensus), at a scanning cost that should be measured first.

7. **UX gaps that will generate support load and user error on a public testnet:**
   - no history;
   - no pending list;
   - no fee shown before sending;
   - no confirmation step;
   - no sweep or consolidation;
   - misleading PX "insufficient funds" errors;
   - balances that drop by whole inputs while change is pending;
   - no view-only mode;
   - no rescan;
   - no backup of state that cannot be recovered from the seed.

**Recommendation.** P0 before a public testnet:
- R11-W1;
- the decisions on R11-W2 and R11-W3 (because they change seed derivation);
- merging A7b.

P1 before a public testnet:
- R11-W6/W7 (UX safety);
- the compact-block RPC design decision.

Everything about hardware wallets, delegated proving and oblivious scanning is P3 research. The design decisions it depends on (W2, W3, W4) should, however, be recorded now.

---

## 1. Findings table (new in this review)

| # | Finding | Class | Sev. | Conf. |
|---|---|---|---|---|
| R11-W1 | Generated vault secret lost when the lock ends `Uncertain` (funds possibly locked for good) | Partially implemented (A7b: only with `--secret-out`) | **High** (funds; demo contract, test coins) | High |
| R11-W2 | No PX viewing-key hierarchy. Wallet-side fix possible, but it changes seed→address derivation | Not implemented | Medium (privacy, UX); **decision is P0 because of the derivation change** | High |
| R11-W3 | Seed format: no version, no birthday, no network; BIP-39 wordlist for a non-BIP-39 derivation | Accepted limitation today → should change | Medium | High |
| R11-W4 | PX spend authority equals possession of `sk` inside the proof. No authorization/proving split, so no safe delegated proving and no hardware wallet for PX | Not implemented (design) | Medium (architecture; CONSENSUS to fix) | High |
| R11-W5 | PX view tag depends only on ECDH, so a DL-capable adversary can link outputs to a known PX address (8 bits per output) | Accepted limitation (undocumented) | Low (future) | High |
| R11-W6 | PX `InsufficientFunds` reports the sum of all records although only two can be spent. No consolidation | Complete but misleading | Medium (UX, stuck funds) | High |
| R11-W7 | No fee or total shown before sending; no confirmation, dry-run, history or pending list; balance hides pending change | Not implemented | Medium (user error) | High |
| R11-W8 | The wallet stores every PX commitment in the JSON and rebuilds the full node tree for every spend and sync (O(N) memory, CPU and file rewrite, several times per command) | Complete but does not scale | Medium (scale) | High |
| R11-W9 | No compact-block or pruned RPC: light and mobile wallets must download proofs | Not implemented | Medium (scale, mobile) | High |
| R11-W10 | v1 "accounts" are nominal: selection mixes accounts, change goes to account 0, balances are not per account | Partially implemented | Low (privacy hygiene, UX) | High |
| R11-W11 | No sender-side record of PX payments (no outgoing viewing key, no payment proof); PX history not recoverable from the seed | Not implemented | Low (UX, audit) | High |
| R11-W12 | Wallet-file KDF header accepts `m_kib` up to 4 GiB and `t` up to 100: a tampered or corrupted file makes load allocate 4 GiB (OOM on phones and small VMs) | Complete but requires hardening | Low | High |
| R11-W13 | Mnemonic parsing is case-sensitive and not normalized (`parse_normalized`), and entry is hidden (`rpassword`): blind 24-word entry fails on capitals | Complete but fragile | Low (UX) | Medium |
| R11-W14 | PX sends always use address 0 (deposit) and address 1 (change), with only one PX "account" | Accepted limitation | Info | High |
| R11-W15 | No view-only or watch-only wallet, although `ViewKeys` exists in the crypto layer; no cold-signing flow | Not implemented | Medium (UX, security for real users) | High |

Deepened or corrected known items are in §8.

---

## 2. Detailed findings

### R11-W1: a generated vault secret is lost on an uncertain submission (High, funds)

**Where:**
- `wallet/src/main.rs:472-475`: the secret is generated.
- `wallet/src/main.rs:486-496`: `px_vault_lock(...)?` returns early on any error.
- `wallet/src/main.rs:497-499`: the secret is printed only after success.
- `wallet/src/wallet.rs:1495-1514`: on error, the vault record's opening is kept (W-4), but the secret never enters the wallet. Only `data = lock_of(secret)` is stored (`wallet/src/px.rs:155-174`).

**Scenario:**
1. The user runs `px-vault-lock` without `--secret`.
2. Proving takes about 45 s. The `/tx` POST then times out after the node has received the transaction (the case W-1 was about).
3. `submit` returns `WalletError::Uncertain`, and `main` returns early with the error text.
4. The transaction is mined. The vault record exists, and this wallet holds its opening (W-4).
5. Nobody knows the secret, and the demo vault has no timeout or refund. The value is locked forever.

The same happens if the process is killed between the node's acceptance and the `println!`.

**A7b status:** the worktree adds `--secret-out` and writes the secret to a file **before** sending (`main.rs` diff, lines 564-577 of the worktree). The default path (no `--secret-out`) still prints only after success.

**Evidence:** [source]. The e2e test `an_uncertain_vault_lock_keeps_the_record_opening` covers the opening, not the secret.

**Recommendation:** store the secret, encrypted in the wallet file, next to the created contract record, before `persist()` in `submit`. Print it before submission, and also print it inside the `Uncertain` error. Simplest variant: add `secret: Option<SecretString>` to `ContractRecord` for `RecordSource::Created`. Add a `px-records --show-secrets` command.
- **Why:** funds loss, triggered by an ordinary network failure.
- **Security impact:** positive (no loss).
- **Privacy impact:** the secret now lives in the encrypted wallet file, which already holds the seed. Neutral.
- **Performance, complexity:** negligible; S.
- **Consensus:** none. **Testnet identity:** no new identity.
- **Priority:** **P0** (a public-testnet user will hit it with the demo vault).
- **Test:** extend `an_uncertain_vault_lock_keeps_the_record_opening` to assert that the secret is recoverable from the saved file.

### R11-W2: no PX viewing-key hierarchy; the fix is wallet-side but changes derivation (Medium; decision P0)

**Where:**
- `px/src/wallet.rs:53-62`: `sk = Hk(SK, seed limbs)`, then `(nk, ak)`.
- `px/src/wallet.rs:69-71`: delivery keys are `DeliveryKeys::derive(&self.sk, index)`.
- `px/src/delivery.rs:93-100`: the view scalar and the ML-KEM seed are `H(sk ‖ index)`.
- `px-core/src/record.rs:40-47`: `d_i = Hk(DIVERSIFIER, sk ‖ i)`.
- `px-core/src/kernel.rs:263-275`: the kernel takes `sk` and `d` as witnesses, derives `nk, ak` from `sk`, and computes `owner = Hk(OWNER, ak ‖ nk ‖ d)`. **Nothing constrains how `d` was derived** [source].

**Consequence today:** detecting incoming PX records needs `sk`. So does detecting spends (`nk = H(sk)`, fine by itself) and even deriving one's own addresses. Every capability short of spending (view-only, audit, watch-only, light-wallet scanning service, hardware wallet with host-side scanning) requires handing over full spend authority. This is the known "no PX view/spend separation" item. It is deepened here because the fix is **not** a consensus change.

**Proposed hierarchy** (wallet-only; the kernel is unchanged):

```text
sk                                  spend authority (proof witness)
ak = Hk(AK, sk), nk = Hk(NK, sk)    unchanged (kernel)
dk  = H("px/div-key", sk)           diversifier key
d_i = Hk(DIVERSIFIER', dk ‖ i)      replaces Hk(DIVERSIFIER, sk ‖ i)
ivk_root = H("px/ivk", sk)          delivery root
(v_i, kem_seed_i) = H(ivk_root ‖ i)  replaces H(sk ‖ i)

Incoming viewing key (IVK)  = (ak, nk, dk, ivk_root) minus nk → detects receipts, cannot detect spends
Full viewing key (FVK)      = (ak, nk, dk, ivk_root)        → receipts + spends (nullifiers)
```

`owner_i = Hk(OWNER, ak ‖ nk ‖ d_i)` needs `ak` and `nk`. Hence IVK = `(ak, nk, dk, ivk_root)`, and in this design IVK equals FVK. Separating "can see spends" from "can see receipts" would require the owner tag not to depend on `nk`, which is a kernel change. For an auditor, IVK = FVK is acceptable (Zcash's FVK also reveals spends).

Neither `ak` nor `nk` permits spending: spending needs `sk` with `Hk(AK, sk) = ak`, a preimage. This rests on the same Poseidon2 assumptions as the rest of PX [math, under the PRF and preimage assumptions of `Hk`].

**Why now:**
- It changes which addresses a seed derives.
- Before the v3 genesis, there is nothing to migrate.
- After a public testnet with real users' records, it needs dual-derivation restore logic forever.

- **Security impact:** it creates new key material (FVK) that must be handled as sensitive. Spend security is unchanged.
- **Privacy impact:** strongly positive. It enables watch-only wallets, auditors, and a light-wallet design that keeps `sk` on the device.
- **Performance:** none.
- **Complexity:** M.
- **Consensus:** none (verify with a test that the kernel accepts witnesses whose `d` comes from `dk`).
- **Testnet identity:** no new identity. Addresses change, which the v3 reset makes free.
- **Difficulty:** M.
- **Priority:** P0 as a **decision**; P1 as implementation before public testnet.

### R11-W3: the seed format has no version, no birthday and no network (Medium)

**Where:**
- `wallet/src/wallet.rs:322-344`: 24 BIP-39 words encoding the raw 32-byte seed.
- `docs/blocks.md` §10: "not BIP-39's PBKDF2 derivation, no passphrase".
- `wallet/src/main.rs:52-54`: restore defaults to `--restore-height 1`.

**Problems:**
1. **No version.** Any derivation change (R11-W2, a PX account index, a fix to `Account::from_seed`) cannot be distinguished from the old one when restoring. Wallets would have to try every historical derivation.
2. **No birthday.** The user must remember a height. The default (1) scans the whole chain, including every PX output against 21 or more addresses (R11-W8/W9 costs). Giving a height that is too high **silently** misses funds, with no warning.
3. **BIP-39 wordlist with non-BIP-39 semantics.** A BlackSilk seed typed into a BIP-39 wallet, or a Bitcoin BIP-39 seed typed into BlackSilk, is accepted (the checksum is valid) and derives unrelated keys. That is a user-error trap.
4. **No network binding.** A testnet seed restored on mainnet derives the same keys. Testnet seeds are handled carelessly (posted in bug reports and logs), so reuse is a real risk [assumed].

**Comparison:**
- Polyseed (Monero) encodes a birthday, feature bits, and a passphrase flag in 16 words.
- But its 150-bit secret targets the 128-bit classical level of ed25519, which is too small for a project that claims post-quantum properties for PX. Grover reduces a 150-bit secret to about 75 bits.

**Recommendation:** a BlackSilk seed format v1 with:
- 256 bits of entropy;
- a version (about 5 bits);
- a network (2 bits);
- a birthday (about 10 bits, monthly, as in Polyseed);
- a checksum.

That is about 26 words from a BlackSilk-specific or tagged wordlist (for example 11 bits per word, 286 bits total). As an alternative, keep 24 words but reserve some bits and stay above 224 bits of entropy.

The key derivation should include the version and network: `seed_key = H("blacksilk/seed/v1" ‖ network ‖ entropy)`.

- **Why:** recovery completeness and future-proofing.
- **Security:** positive (no cross-network or cross-wallet confusion).
- **Privacy:** positive (faster restore, fewer full rescans through remote nodes).
- **Performance:** positive.
- **Complexity:** M.
- **Consensus:** none. **Testnet identity:** none (wallet only).
- **Difficulty:** M.
- **Priority:** P0 decision / P1 implementation, bundled with R11-W2.

### R11-W4: PX spend authority equals proving; no safe delegation and no hardware wallet (Medium, design; CONSENSUS)

**Where:**
- `px/src/wallet.rs:87-108`: `spend()` puts `sk` in the `InputWitness`.
- `px-core/src/kernel.rs:263-275`: ownership is "knows `sk` with `Hk(AK, sk) = ak`".
- There is no spend-authorization signature. The proof *is* the authorization, and it is bound to the transaction through `h_tx` (`tx/src/px.rs:387-397`).

**Consequences:**
- **Delegated proving:** a remote prover must receive `sk`. That is permanent spend authority over every past and future PX record of the wallet (every address shares `sk`), plus full knowledge of the transaction.
- **Hardware wallet:** the device cannot keep PX funds safe. The host that proves needs `sk`, and a device cannot prove (3.8 GB).
- **Contrast:**
  - In Zcash Sapling and Orchard, the prover gets a *proof generation key* `(ak, nsk)`, and spend authority is a separate RedDSA signature by `ask` over the sighash, under a re-randomized `rk` (Zcash protocol spec §4.2.2, §4.15).
  - Aleo separates a signed *authorization* from proving, so a delegated prover cannot change the transaction. It still sees the inputs, which Aleo protects with a "secure environment".

The design options, with their costs, are in §7.3. **No change is recommended before the testnet.** The point to record now is that R11-W2's hierarchy should leave room for an authorization key. For example, derive `ak` from a separate `ask_seed`, so that a future kernel can require "a proof of knowledge of an authorization secret" without changing addresses again.

- **Priority:** P3 (research), with a P1 documentation note: "PX delegated proving is unsafe; never share `sk`".
- **Consensus:** **CONSENSUS** if implemented. **Testnet identity:** a new identity if implemented.

### R11-W5: PX view tag is classical-only, so outputs can be linked to addresses post-quantum (Low)

**Where:**
- `px/src/delivery.rs:113-115, 205-209`: `tag = H32(PX_VIEW_TAG, ss_ec ‖ R)[0]`, with `ss_ec = r·V`.
- `docs/px.md` §6 and `docs/zk.md` §4.6 claim that contents stay confidential against a quantum adversary (correct: that needs ML-KEM too). They say nothing about **recipient unlinkability**.

**Scenario:** an adversary that can compute discrete logarithms learns `v` from a published PX address `V = v·G`. For every PX output it computes `ss_ec = v·R` and checks the tag. The address's true outputs always match; foreign outputs match with probability 1/256.

Combined with timing or amount side channels, that is strong linkage. Harvest-now-link-later applies: the chain is public forever. The per-address ML-KEM keys still stop decryption, so contents and values stay safe [math, under ML-KEM IND-CCA].

**Options:**
- **(a) Document it.** P1, S.
- **(b) Derive the tag from both secrets**, `H(ss_ec ‖ ss_kem ‖ R)`. Recipient unlinkability then becomes hybrid as well. The cost is an ML-KEM decapsulation per (output, address) instead of 1/256 of them. That is roughly one more operation of the same order as the scalar multiplication [assumed; ML-KEM-768 decapsulation and a Ristretto scalar multiplication are both in the tens of µs on desktop x86; **measure before deciding**]. Mikić et al. (2025) evaluate exactly ML-KEM-based view tags for stealth addresses.

  The delivery format is wallet-side ("consensus only fixes the ciphertext length", `px/src/delivery.rs:33`), so (b) needs no consensus change. It does change the wire format that every wallet must agree on, so it should land before the public testnet or never.
- **Consensus:** none. **Testnet identity:** none. **Difficulty:** S (code), M (measurement and review).
- **Priority:** P2 decision (document now; decide on (b) with measurements).

### R11-W6: misleading PX insufficient-funds error; no consolidation (Medium, UX)

**Where:** `wallet/src/px.rs:523-547`. `select` can use at most two records (the kernel has 2 inputs), but the error reports `available = Σ all spendable records`.

**Scenario:** the wallet holds five PX records of 2 BLK. `px-send --amount 5` fails with "insufficient unlocked funds: 10 available, 5.089 needed". The user has no command to consolidate. Each manual consolidation is a 45 s proof plus a fixed fee of 0.089 BLK (`PX_STANDARD_FEE = 2 × (4 MiB + 256 KiB)` atomic units, `tx/src/params.rs:29`) [source; arithmetic].

**Recommendation:**
- A distinct error: "largest amount sendable in one transaction: X (sum of the two largest records minus the fee); run `px-consolidate`".
- A `px-consolidate` command (2→1 merges, each a normal PX transfer to oneself).
- Show "max sendable" in `px-balance`.
- Make consolidation timing random or user-driven: automatic consolidation right before a payment links the two in time.
- **Consensus:** none. **Difficulty:** S–M. **Priority:** P1.

### R11-W7: no pre-send confirmation, fee display, pending list or history (Medium, UX and user error)

**Where:**
- `wallet/src/main.rs:309-328` and the PX commands: the transaction is built and submitted in one step. The fee is printed only after submission.
- There is no `--dry-run` or `--yes`, no "history", "pending" or "tx" command. `Wallet::has_pending` (`wallet.rs:633`) is unused by the CLI.
- `Wallet::balance` (`wallet.rs:616-630`) excludes pending outputs, but change from a pending transaction is not counted until it is mined. A 1 BLK payment from a 100 BLK output shows the balance dropping to 0 until confirmation.

**Consequences:** users cannot:
- check the fee;
- confirm the destination (a long base58 string);
- see that a transaction is still pending, and why their balance dropped;
- see incoming payments by address.

The likely user reaction to "my money disappeared" is `clear-pending`, which is precisely the privacy-damaging action W-8 warns about.

**Recommendation** (all wallet-only, **P1**, S–M):
1. Build → show a summary (destination, amount, fee, total, inputs used, a PX proving-time estimate) → confirm (`--yes` for scripts).
2. Show the fee in the `--help` text and `balance`: v1 fees depend on shape; PX fees are a fixed 0.089 BLK.
3. A `status` command listing stored transactions: id, age, last rebroadcast, and outcome (pooled, invalid, confirmed at height h, confirmations).
4. Local history: record incoming outputs and records (height, subaddress, amount), and outgoing transactions (id, destination, amount, fee). Stored in the encrypted file.
5. Balance lines: "unlocked", "locked (maturing)", "pending outgoing", "pending change".
6. Replace `Debug` error forms (`BuildError`, `AddressError`, node reasons) with user text (known remaining weakness in wallet-review.md §3; still present).

### R11-W8: PX commitment storage and tree rebuilds do not scale (Medium, scale)

**Where:**
- `wallet/src/px.rs:219-231`: `commitments: Vec<(u64, String)>`, every commitment of the chain as JSON hex.
- `wallet/src/px.rs:479-492`: `tree_at` rebuilds a full `Tree` (every node) from scratch.
- Rebuilds are called from `sync_commitments` (`px.rs:444`), `px_deposit` (`wallet.rs:1171-1174`), `px_inputs` (`wallet.rs:1213`) and `px_vault_claim` (`wallet.rs:1553`).

**Cost model** at the documented saturation (about 3 PX transactions per 120 s block, 2 commitments each) [assumed]:
- about 4,300 commitments per day, 1.6 M per year;
- about 120 MB per year of JSON inside the wallet file;
- that file is fully re-serialized and Argon2id-encrypted, plus written and fsynced, at least 3 times per spend command (autosave before and after sending, final save) and once per sync;
- the full tree holds about 2N digests (about 100 MB of RAM after a year) and is rebuilt with about N Poseidon2 compressions per rebuild, several times per command.

The wallet only needs:
- the frontier;
- authentication paths for its own records;
- the ability to rewind about 720 blocks.

Zcash wallets use incremental witnesses or `ShardTree`, with checkpoints for rewinds.

**Recommendation:**
- Persist the frontier.
- Keep an incremental witness for each owned record, updated on append.
- Keep per-block checkpoints for the rewind window.
- Store commitments only for the rewind window, in a binary form.
- Move bulk state out of the single encrypted JSON: an encrypted, append-only store, or at least a binary `postcard` encoding.
- **Consensus:** none. **Difficulty:** M–L. **Priority:** P2 (needed before load testing a public testnet with PX traffic).
- **Performance:** large improvement. **Privacy:** none.

### R11-W9: no compact-block RPC (Medium, scale and mobile)

**Where:** `wallet/src/wallet.rs:497-540` downloads full blocks. `rpc/src/lib.rs` has no pruned endpoint.

**Numbers** [assumed; derived from the measured 2.18 MB transfer proof]:
- A full-block wallet at saturation downloads about 8–9 MiB per 120 s block, which is about 6 GiB per day.
- The wallet needs, per PX transaction: 2 nullifiers (64 B), 2 commitments (64 B), 2 ciphertexts (2 × 1,241 B), the payouts, and the prunable hash (32 B). That is about 2.6 KB, against about 2.2 MB of proof: roughly 850 times less.

**Verifiability:** the transaction hash is `H(prefix, base, prunable)` (`tx/src/types.rs:432-447`), and PX `prefix_bytes` holds the inputs, outputs and payouts (`tx/src/px.rs:228-263`). So a compact block (header, per-transaction prefix and base, prunable hash) lets the client recompute every transaction id, `tx_root` and the block id. That gives exactly the integrity guarantees the wallet has today. It still has no PoW check (W-F6).

**Recommendation:** a `/compact_blocks` endpoint that returns the prefix, the base and `prunable_hash` per transaction, with the wallet verifying `tx_root`. This is the ZIP-307 approach.
- **Privacy:** identical to today (everyone downloads everything).
- **Consensus:** none (RPC). **Difficulty:** M. **Priority:** P2 (P1 if mobile or light clients are in the testnet scope).

### R11-W10: v1 accounts are nominal (Low)

**Where:**
- `wallet/src/wallet.rs:889-931`: `select_inputs` draws from all accounts.
- `wallet.rs:953`: change goes to `primary()`, which is (0,0).
- `Balance` is global.
- Restore scans account 0 only (W-F7).

**Scenario:** a user separates "savings" (account 1) and "shop" (account 2). A payment from the shop combines outputs of both accounts, and the change lands in account 0.

On chain, ring signatures hide which outputs were spent, so this is **not** a public leak [source; CLSAG hides the real input]. But:
- the multi-input transaction's recipient and timing analysis see one merged transaction;
- the user's mental model of separated funds is broken;
- a restore (account 0 only) will not find later account-1 funds, even though the user thinks accounts are "in the seed".

**Recommendation:**
- Either remove `--account` from the CLI until it is real, or implement it properly: per-account balances; `--from-account` selection that never mixes accounts; change to the account's own subaddress (a,0); and restore with a configurable account count.
- **Consensus:** none. **Difficulty:** S (remove) / M (implement). **Priority:** P1 (remove or implement; do not ship a half-feature).

### R11-W11: no sender-side PX records or payment proofs (Low)

**Where:**
- `wallet/src/wallet.rs:1235-1276`: `px_send` creates the recipient's record with `rcm` chosen locally (`pxw::output`) and discards it.
- There is one ciphertext per output, and it goes to the recipient only (`delivery.rs`). There is no out-ciphertext as in Zcash, where an OVK lets the sender recover sent notes from the seed.

**Consequences:**
- The sender cannot prove a payment.
- The sender cannot show what they sent after a restore.
- A dispute has no evidence.

For v1 there is also no stored transaction secret, so no Monero-style `tx_key` or payment proof.

**Recommendation:**
- Store sent-record openings and v1 output secrets in the encrypted file (wallet-only, P2, S).
- Add a `prove-payment` export that uses `px_share` (sealing the opening to an auditor's PX address) or a v1 transaction key.
- Seed-recoverable outgoing data would need an extra ciphertext per output (**CONSENSUS**, because the length is fixed; P3).

### R11-W12: KDF parameter bound is too high (Low)

**Where:** `wallet/src/file.rs:116`: `m_kib ≤ 4 GiB`, `t ≤ 100`, `p ≤ 64`.

**Scenario:** a corrupted header (disk error, a bad sync tool, an attacker with write access to the file) makes the next load try to allocate up to 4 GiB before the MAC can fail. That is an OOM on phones and small VMs. The attacker gains nothing (they do not know the password), so this is DoS or UX only.

**Recommendation:** cap at about 1 GiB and t ≤ 10 (well above the 64 MiB/3 default). Also keep a minimum for **writing**: refuse to save with parameters below the default unless explicitly configured.
- **Consensus:** none. **Difficulty:** S. **Priority:** P2.

### R11-W13: mnemonic entry is fragile (Low)

**Where:**
- `wallet/src/wallet.rs:335`: `bip39::Mnemonic::parse_normalized(words.trim())`, built without the `unicode-normalization` feature (`wallet/Cargo.toml`), so input is not lowercased or normalized [source; behaviour of the bip39 2.x API assumed from its documentation].
- `wallet/src/main.rs:279-280`: the 24 words are typed blind (`rpassword`).

**Scenario:** a user who wrote the words in capitals, or who mistypes one word, retypes all 24 words blind with only "mnemonic: ..." as feedback.

**Recommendation:**
- Lowercase and collapse whitespace before parsing.
- Accept 4-letter prefixes (the BIP-39 list is prefix-unique).
- Report *which* word is not in the list.
- Offer visible entry, with a warning.
- **Consensus:** none. **Difficulty:** S. **Priority:** P2 (P1 if R11-W3 introduces a new format anyway).

### R11-W14: fixed PX address roles (Info)

- PX deposits go to address 0 (`wallet.rs:1175`); change and self-payments go to address 1 (`wallet.rs:1254, 1299, 1450`).
- Address 0 is also the default `px-address` shown to users.
- On chain this reveals nothing: owners are hidden in commitments and every ciphertext is freshly encrypted [source].
- It does mean that a user who publishes address 1 publishes their change address. PX has one "account" only.

**Recommendation:** reserve a documented internal branch, for example indices ≥ 2^31 for change, never shown by `px-address`. Do it together with R11-W2 (derivation change). P2.

### R11-W15: no view-only or watch-only wallet and no cold signing (Medium, UX and security)

**Where:**
- `crypto/src/keys.rs:81-137`: `ViewKeys` supports detection.
- `transactions.md:222, 688, 783` document view-only detection and the key-image limitation.
- `wallet::Wallet` always holds the seed (`wallet.rs:207-229`), and `apply_block` computes key images with the spend key during every sync (`wallet.rs:557-558`).
- There is no CLI or file mode without the seed. PX has no viewing key at all (R11-W2).

**Consequence:** every machine that syncs holds the spend key and decrypts it into memory on every command. There is no merchant or watch-only deployment, and no air-gapped signing.

**Recommendation** (in order):
1. A v1 view-only wallet file type: `(k_v, K_s)`, balances computed without spend detection, clearly labelled "spends not visible".
2. Key-image import from a signer.
3. An unsigned-transaction format (inputs with rings, outputs, fee), signed offline, as in Monero's cold-signing flow.
4. PX view-only after R11-W2.

- **Consensus:** none. **Difficulty:** M (1–2), L (3).
- **Priority:** P2 (1 before a public testnet is desirable but not blocking).

---

## 3. Subsystem answers (the 13 questions)

### 3.1 Seed, key derivation and recovery

**Implemented:**
- a 32-byte seed from `getrandom`, shown as 24 BIP-39 words;
- `k_s` and `k_v` hashed independently from the seed (`keys.rs:156-163`);
- Monero-style subaddresses `m(a,i) = Hs(k_v ‖ a ‖ i)`;
- PX `sk` from the same seed (`px/src/wallet.rs:53-62`).

**Correct and well-designed:**
- domain separation;
- strict address decoding (`keys.rs:74-78` [test: `address_encoding_is_strict`]);
- degenerate keys refused [test: `view_keys_reject_degenerate_values`];
- regression for the hard-coded-seed bug K1 [test: `generated_wallets_are_unique`];
- `Account` and `DeliveryKeys` zeroized on drop.

**Incomplete:**
- recovery completeness. What the seed recovers and what it does not:

| State | Recovered from seed? |
|---|---|
| v1 outputs, account 0, indices ≤ highest-found + 50 (A7b grows the window) | yes |
| v1 outputs in accounts ≥ 1 | **no** (W-F7) |
| PX user records at indices ≤ highest-found + 20 | yes |
| PX contract records received | yes |
| PX contract records created or imported | **no** (file only; warned in the CLI) |
| Vault secrets | **no, not even in the file** (R11-W1) |
| Rings of relayed, unmined spends (W-5) | **no** |
| Pending or stored transactions | **no** |
| Sent-payment details and history | **no** (R11-W11) |
| Restore height | **no** (R11-W3) |

**Fragile:**
- the seed format (R11-W3);
- blind entry (R11-W13);
- the create path takes its start height from the node, falling back silently to 1 (W-F15, known).

**Exploitable:** nothing new beyond W-F15.

**Redesign:** R11-W2 and R11-W3, together, before v3.

**Never change:** the uniform subaddress format and strict decoding, and domain-separated hashing. After the public testnet, also never change the v1 derivation without a seed version (R11-W3).

### 3.2 Multi-account, view-only, watch-only and audit keys

- **Implemented:** `ViewKeys` (v1, crypto layer only); `(account, index)` addressing.
- **Missing:**
  - view-only and watch-only files (R11-W15);
  - accounts as a real feature (R11-W10);
  - PX viewing keys (R11-W2);
  - audit keys.
- **For audit today:**
  - v1: the view key reveals incoming outputs only; spends need key images.
  - PX: the only selective disclosure is `px_share` of a single contract record. User records cannot be shared through the CLI (`px_import` refuses non-contract records, `wallet.rs:1665-1669`; the check is correct for its purpose).
- **Recommendation:**
  - PX FVK per R11-W2;
  - a per-record disclosure package for audits (the record opening plus a Merkle path to a public root);
  - both wallet-only.

### 3.3 Wallet file and backups

**Implemented:**
- Argon2id (64 MiB, t=3) with AES-256-GCM;
- the header as AAD;
- fresh salt and nonce on every save;
- atomic write;
- a lock file.
- A7b adds 0600 permissions, a directory fsync, a stale-tmp cleanup and zeroizing seed strings.

**Correct:**
- the construction is standard;
- nonce reuse is impossible (fresh key per save via the fresh salt) [math];
- tamper tests on every byte [test: `wrong_password_and_tampering_are_rejected`].

**Fragile:**
- the KDF bound (R11-W12);
- empty passwords accepted (known);
- `BLACKSILK_WALLET_PASSWORD` (documented);
- the whole wallet is one JSON blob rewritten several times per command (R11-W8).

**Missing:**
- a backup command (export an encrypted copy, with a warning that the file holds non-seed-recoverable state);
- rotating automatic backups;
- a password change;
- a KDF upgrade path when re-saving with stronger parameters (the header supports it; no CLI).

**Never change:** the AEAD-with-header-AAD design and the atomic replace.

### 3.4 Scanning and synchronization

**Implemented:**
- block id and `tx_root` recomputation;
- prev-id linkage;
- reorg rewind with 720 kept ids;
- deep-reorg rescan;
- PX full commitment and contract lists;
- a root check against the node.

**Correct:**
- "download everything" gives the node no information about ownership [source];
- v1 scanning costs one scalar multiplication per output, independent of the subaddress count (table lookup, `stealth.rs:212-226`);
- the PX canonical anchor (`px.rs:49-59`) hides sync time [test: `the_anchor_is_the_last_multiple_of_the_interval`].

**Fragile:**
- the PX root check runs only when `resp.height == synced` (`px.rs:443`), so a node can always skip it by reporting another height. The impact is only DoS: a wrong root gives an anchor that consensus rejects [source]. Recommendation: check the node's root at the wallet's height, which needs a `root_at(height)` RPC, or check against a header commitment if one exists. P3.
- W-F13 (`first_output` trusted, known).
- No PoW check (W-F6, known).

**Inefficient:**
- PX trial decryption per (output, address) re-derived ML-KEM keys and owner tags on every output. A7b caches them.
- The whole-tree rebuilds (R11-W8).
- Full-block download (R11-W9).

**Does not scale:**
- PX scanning is O(N_out × k_addresses). This is inherent to per-address independent keys (§6.1).

### 3.5 Pending transactions, rebroadcast and rings

**Implemented and well-designed:**
- reserve and store before sending;
- `Uncertain` handling;
- unchanged rebroadcast;
- release only on `Invalid`;
- confirmed spends kept 720 blocks;
- ring reuse (W-5);
- tests: `an_uncertain_submission_keeps_the_inputs_reserved_across_a_restart`, `an_output_spent_again_reuses_its_ring`, `the_wallet_is_saved_before_a_transaction_leaves_it`.

This is better than many production wallets.

**Fragile:**
- An `Invalid` verdict can be transient (F12, known).
- For PX transactions, an anchor that falls out of the 100-block window while pooled (full blocks, fixed fee, no priority) turns the next rebroadcast into `Invalid`. The records are released, and the user must re-prove manually with no notice (R11-W7 `status`).
- The reservation checks are `debug_assert!` only (known).

**UX:** there is no way to see any of this state (R11-W7).

**Never change:** reserve-before-send, unchanged rebroadcast, and ring reuse.

### 3.6 PX wallet side and contract records

**Implemented:**
- deposit, send and withdraw;
- deploy;
- vault lock and claim;
- share and import;
- contract records kept apart from the balance [test: `contract_records_are_never_counted_or_selected_as_funds`];
- openings never deleted by `clear-pending` [test: `clearing_pending_keeps_every_contract_record_opening`].

**Correct:**
- the Janus-style acceptance (a record is accepted only if it recomputes `cm`) [test: `a_record_inconsistent_with_its_commitment_is_refused`, `the_record_kind_cannot_be_misrepresented`];
- a uniform PX fee (no fee fingerprint);
- fixed 2×2 shape with dummies.

**Exploitable or fund-risking:**
- R11-W1;
- PX-F4 and PX-F5 (known).

**Inefficient or does not scale:** R11-W6, R11-W8.

**Missing:**
- consolidation;
- PX history;
- PX view keys;
- sender records.

### 3.7 RPC client

- **Main branch:** plaintext HTTP, unbounded bodies, proxies from the environment honoured implicitly, redirects followed.
- **A7b fixes:** refuses `https://` (no TLS stack), turns off implicit proxies and redirects, and caps bodies per endpoint. These tests exist in the worktree: `an_endless_body_without_a_length_is_cut_at_the_cap`, `caps_cover_the_largest_honest_responses`.
- **Remaining:**
  - No transport privacy for remote nodes: the only options are an SSH tunnel, a VPN or Tor through a local forwarder.
  - A network observer between the wallet and a remote node sees the `/tx` submission and every `/outputs` query in clear. That links the IP to the transaction and to the input's candidate pool.

  **Recommendation (P2):**
  - built-in SOCKS5 (Tor) support in the client;
  - a documented "remote node" threat model in the CLI help;
  - submit through a different circuit than the queries (as Monero wallets do with Tor).

  A pure-Rust TLS (`rustls`) would be acceptable under the project's pure-Rust rule. Its crypto provider (`ring` or `aws-lc`) contains C and assembly. The pure-Rust provider options should be reviewed before adding it; Tor through a local SOCKS forwarder avoids the question.

### 3.8 CLI UX: fees, errors, pending, safety against user error

**Good:**
- network-tagged addresses with checksums;
- separate v1 and PX address tags;
- warnings on deposit and withdrawal amount privacy;
- demo-vault warnings;
- the `clear-pending` warning;
- one indistinguishable wrong-password message.

**Missing or wrong:**
- confirmations, fee preview, history, status (R11-W7);
- PX error semantics (R11-W6);
- `Debug` errors (known);
- no `sweep`, `rescan` or `consolidate` (known and R11-W6);
- no multi-recipient transfer;
- no labels or address book;
- no warning when `--restore-height` is above the height where the seed's first funds appeared (a birthday would give this; R11-W3);
- the `seed` command prints the words with no "are you sure / clear the screen" guard.

The addresses are hard to use:
- a PX address is 1,253 bytes, about 1,711 base58 characters (`chain/src/address.rs:66-67`);
- in QR byte mode it fits only at error-correction levels L or M of version 40, a very dense code that is hard to scan with phone cameras [math: QR v40 byte capacity L 2,953 / M 2,331 / Q 1,663 bytes];
- the v1 address is 69 bytes, about 95 characters.

Recommendations for addresses:
- a versioned PX address format (there is no version byte today, only a network tag);
- a short "payment request" alternative: a 32-byte content hash of the address, resolved out of band, verified by the wallet after fetching the full address.

---

## 4. Hardware-wallet readiness

### 4.1 v1 (CLSAG): feasible, not implemented

What a device would need, modelled on Monero's Ledger protocol:

1. **The device holds `k_s`.** The host holds `k_v`. Monero also optionally exports the view key to the host for scanning speed.
2. **Key images:** the device computes `KI = p·Hp(P)` from `p = x + d(a,i)` (`scan.rs:24-28`). Today `apply_block` computes key images during every sync with the spend key (`wallet.rs:557-558`). A device wallet must defer this: compute key images in a batch on request, or store the outputs "unimaged" and ask the device when needed.
3. **Signing API boundary:** `build_transfer_signing` (`tx/src/builder.rs:172-...`) takes `&WalletKeys` and does everything:
   - one-time secrets;
   - output construction with the hedge from the spend secret (`builder.rs:227-229`);
   - BP+;
   - pseudo-outputs;
   - CLSAG.

   A device split needs:
   - **(a)** a host-side "unsigned transaction" (inputs, rings, outputs, amounts, fee);
   - **(b)** the device recomputes and **displays** each destination and amount, and the fee, which requires deriving output keys and encrypted amounts on the device or verifying them;
   - **(c)** the device produces the pseudo-output masks and CLSAG responses;
   - **(d)** the hedge secret stays on the device. The F2 hedge fix binds the full CLSAG transcript, so the device must hash the same transcript. The transcript must be specified as a byte format, not just as code.
4. **BP+ proving** can stay on the host if the host gets the output masks. The masks are derived from shared secrets and reveal amounts, which the host knows anyway.
5. **An unsigned-transaction format and a cold-signing flow** (R11-W15, step 3) is the practical first step. It needs no hardware and gives air-gapped signing.

- **Classification:** Not implemented. **Consensus:** none. **Difficulty:** L (device integration XL). **Priority:** P3; the unsigned-transaction format is P2.

### 4.2 PX: not possible with the current kernel

As R11-W4 explains, holding `sk` equals full authority, and the device cannot prove. The only secure PX-with-hardware design needs an authorization key verified inside the proof (§7.3 option B), which is a kernel change.

**Interim guidance:** hardware-wallet users keep funds in v1 and use PX from a hot wallet with small balances. Document this (P1).

---

## 5. Light-wallet architecture

### 5.1 Today's cost model

| Item | v1 | PX |
|---|---|---|
| Per-output data needed | one-time key, ephemeral, view tag, commitment, enc_amount, enc_anchor (about 140 B) [assumed from field sizes] | nullifiers, commitment, ciphertext: 1,241 B per output plus about 64 B per transaction |
| Trial cost per output | 1 scalar multiplication + table lookup, independent of address count | k scalar multiplications (k = issued + 21 addresses) + 1/256·k ML-KEM decapsulations |
| Download today | full blocks | full blocks including about 2.2 MB proofs |

The PX per-output scan cost is proportional to the number of addresses because every address has independent keys. This is a **deliberate post-quantum privacy property**:
- addresses of one wallet are unlinkable even to a quantum adversary, apart from the view-tag leak R11-W5;
- a Sapling-style diversified design (`pk_d = ivk·g_d`, one scalar multiplication per output for all addresses) would make every address of a wallet linkable to anyone who can compute discrete logarithms.

**Do not "optimize" this away** without deciding that trade-off explicitly.

Rough per-day scan cost at saturation, after the A7b cache [assumed]:
- 4,300 PX outputs × 21 addresses × about 50 µs (desktop) ≈ 4.5 s per day of chain;
- about 3–4 times that on a phone.

A full restore after a year is about 30 minutes of desktop CPU for PX, before bandwidth. That is acceptable for a desktop and marginal for a phone. It should be measured with `px/examples` before any claim.

### 5.2 Server-assisted options and their privacy cost

**1. Compact blocks, client-side scanning** (ZIP-307 style; R11-W9):
- The server learns nothing beyond the client's IP and sync timing.
- Bandwidth for PX is about 2.6 KB per transaction.
- **Recommended baseline.** Wallet-only; no consensus change.

**2. View-tag-assisted fetching:**
- The client downloads only `(R, tag)` (33 B per PX output), then fetches full ciphertexts for tag hits.
- The hits leak a candidate set: k/256 of all outputs plus the true ones.
- To hide them, fetch ciphertexts in whole-block or fixed-size buckets, or with PIR.
- Low value, because a ciphertext (1.2 KB) is small next to what a client downloads anyway once proofs are pruned. **Not recommended** unless bandwidth measurements show a need.

**3. Handing a viewing key to a server** (Monero light-wallet-server model):
- It needs R11-W2 first.
- The server learns every incoming record and, with an FVK, every spend. That is total privacy loss to the server.
- **Only acceptable for self-hosted servers.** Document it that way if ever offered.

**4. Fuzzy Message Detection** (Beck, Len, Miers, Green, CCS 2021; used as S-FMD by Penumbra):
- The recipient gives the server a detection key with false-positive rate p, and the server returns matches plus cover traffic.
- Privacy is "fuzzy": Seres, Pejó and Burcsi (FC 2022) show that recipient unlinkability and relationship anonymity degrade with traffic volume and the choice of p.
- FMD is based on discrete logarithms, so it is not post-quantum.
- It needs a per-output clue (a consensus field).
- **Not recommended** for a project that positions PX as post-quantum.

**5. Oblivious Message Retrieval** (Liu and Tromer, CRYPTO 2022; PerfOMR, Liu, Tromer and Wang, USENIX Security 2024; HomeRun, CCS 2024):
- The server homomorphically computes an encrypted digest; it learns nothing.
- Lattice-based, so post-quantum.
- The original costs were about 0.1 s of server computation per message scanned, about 1 KB of per-message clue, and about 132 KB public keys. PerfOMR reports large improvements (15 times faster detection, or 235 times smaller keys) [cited; not reproduced].
- Needs a per-output clue (consensus field, or a sidecar gossip channel).
- **The right long-term research direction** for mobile PX. P3.

**6. Private signaling** (Madathil, Scafuro, Seres, Shlomovits, Varlakov, USENIX Security 2022):
- TEE- or 2-server-based signaling with sublinear recipient work.
- It trusts hardware, or non-collusion between servers.
- P3 at most.

**Recommendation:** do (1) now (P2). Keep the per-address independent-key property. Evaluate OMR against the PX output format before mainnet (P3). Do not adopt FMD.

---

## 6. Mobile feasibility

### 6.1 Scanning and storage

Feasible with R11-W8 (incremental witnesses) and R11-W9 (compact blocks).

- Storage: kilobytes per owned record plus the frontier.
- CPU: seconds to minutes per day of chain [assumed, see §5.1].
- Memory: without R11-W8, a year of PX commitments (about 100 MB tree, about 120 MB JSON re-encrypted per save) is not viable on a phone.

### 6.2 Proving: not feasible on phones in the current form

- **Measured:** 3.8 GB peak and 44.6–45.2 s per transfer proof on the desktop test machine.
- **Assumed:**
  - mobile operating systems kill foreground apps well below the device RAM (typical per-app limits are 1.5–3 GB on 4–8 GB phones);
  - phone CPU throughput for this workload is several times lower than a desktop, and thermal throttling applies over a 45 s+ run.

**Conclusion:** on-device PX proving is not feasible without at least a 3–4 times memory reduction and a large time reduction. That needs prover-side work:
- streaming or low-memory FRI;
- smaller tables for the pure-transfer shape;
- possibly a different blowup or security split.

Any of these must preserve the ZK conditions in zk-coverage.md §3. **[assumed; must be measured on real ARM64 hardware, which CI does not have yet]**

### 6.3 Delegated proving: options and privacy cost

| Option | What the prover learns | Can the prover steal? | Consensus change | Maturity |
|---|---|---|---|---|
| **A. Hand the full witness to a trusted prover** (possible today) | everything: amounts, counterparties, records, positions, **`sk`** | **yes, forever, for all PX funds** (R11-W4) | none | available, **unacceptable** |
| **B. Authorization split** (Sapling/Orchard or Aleo model): prover gets `(ak, nk, d, record, path)`; user signs `h_tx` with a key verified **inside** the proof | the full transaction (amounts, counterparties, which records) | no | **CONSENSUS**, kernel | L–XL |
| **C. Private delegation by MPC** (EOS, USENIX Security 2023; zkSaaS, USENIX Security 2023; collaborative zk-SNARKs, Ozdemir and Boneh 2022) | nothing, if one worker is honest or workers do not collude | no, if combined with B | none by itself, but needs an MPC-friendly prover | research: these works target pairing- or KZG-based SNARKs; MPC for FRI/STARK provers is much less mature [assumed] |
| **D. TEE prover** (SGX, TDX, Nitro) | nothing if the TEE holds; everything on a side-channel break | only on a TEE break (unless B) | none | available; trusts hardware vendors (conflicts with "strong decentralization") |
| **E. Reduce proving cost to fit phones** (§6.2) | nothing | no | none (prover-side), unless the shapes change | M–XL; best for privacy |

**Notes on B for this proof system:**
- The Sapling approach (re-randomized EC key `rk` plus an outside signature) needs EC arithmetic in-circuit. Over BabyBear with a non-native curve that is expensive.
- The PQ-consistent alternative is a **hash-based signature verified inside the proof**: WOTS+ or XMSS with Poseidon2, whose public-key root is committed in `ak`. The signature is a private witness, so it adds no on-chain linkability.
  - WOTS+ verification is about 1,000 Poseidon2 calls [assumed], cheap relative to the kernel.
  - XMSS is **stateful**: key reuse is forgery, and state loss on restore (seed-only recovery) is a real operational hazard.
  - A stateless SPHINCS+-like scheme avoids the state at about 10–100 times more hashing [assumed].
- Either way the delegated prover still sees the full transaction. B protects funds, not privacy.

**Recommendation:**
- For the testnet, **state plainly that PX requires desktop-class hardware** and that PX proving must never be delegated (P1 documentation).
- Invest in E (prover memory and time) as the privacy-preserving path.
- Record B as a candidate kernel v3 feature, with R11-W2's hierarchy leaving room for an authorization key.
- C and D stay research.

---

## 7. What must be implemented before a public testnet

### P0: blocking
1. **R11-W1:** persist vault secrets before sending (S).
2. **Decide R11-W2 and R11-W3** (PX viewing-key hierarchy; versioned seed with birthday and network). Both change seed→key derivation, so they must precede the v3 genesis. Implementation can follow (P1), but no public user should create a wallet under the old derivation.
3. **Merge and review A7b:**
   - M-1 and M-2 limits and window growth;
   - PX key cache;
   - RPC caps and scheme checks;
   - 0600 permissions and directory fsync;
   - vault checks P-1/P-2;
   - secret input.

   Review needed: the new `address()` panics where it used to extend (`unwrap_or_else(|e| panic!)` in the worktree's `Wallet::address`), and callers of the library API should use `try_address`.

### P1: before public users
4. **R11-W7:** confirmation with a fee preview, `status` (pending), history, clearer balance lines, user-facing errors.
5. **R11-W6:** PX max-sendable and a consolidation command.
6. **R11-W10:** either remove `--account` or make accounts real.
7. Documentation:
   - what the seed does and does not recover (the §3.1 table);
   - "PX needs a desktop-class machine";
   - "never delegate PX proving";
   - the view-tag quantum caveat (R11-W5);
   - remote-node privacy.
8. **R11-W13:** robust mnemonic entry (if the seed format changes anyway).

### P2: hardening, before load tests
- R11-W8 (incremental witnesses, binary store);
- R11-W9 (compact blocks);
- R11-W12 (KDF bounds);
- R11-W15 (v1 view-only);
- R11-W11 (store sent openings);
- R11-W14 (internal change branch);
- SOCKS5/Tor in the RPC client;
- a backup/export command;
- a password change;
- a KDF upgrade.

### P3: after the trial, or research
- hardware-wallet signing;
- PX authorization split (CONSENSUS);
- OMR;
- PQ view tags (R11-W5 b) if not taken earlier;
- seed-recoverable outgoing ciphertexts (CONSENSUS);
- root-at-height RPC.

### Can safely be deferred
Hardware wallets, OMR, delegated proving and multi-recipient transfers.

### Should never be changed
- reserve-before-send;
- the unchanged rebroadcast;
- W-5 ring reuse;
- the single shuffled `/outputs` query;
- "download everything" scanning (or compact blocks with the same property);
- canonical anchors;
- the uniform PX fee;
- the Janus-style commitment check on received records;
- per-address independent PX keys, unless the post-quantum address-unlinkability trade-off is explicitly re-decided;
- the atomic, authenticated wallet file.

---

## 8. Known items: deepened or corrected

- **"No PX view/spend separation":** deepened. It is fixable **without consensus change**, because `d` is an unconstrained witness (R11-W2), but it changes address derivation. This is a timing-critical decision, not a deferrable hardening item.
- **M-1 (huge address index):** it also applies to PX (`px_address` sets `issued = index`, `wallet.rs:967-970`), with a far larger cost per index: an ML-KEM key generation per index per PX output on main. The A7b worktree covers both (`PX_MAX_INDEX_AHEAD = 2000`, cache). I confirm that its fix targets the right paths.
- **"Vault secret on the command line":** the more serious issue is R11-W1 (the secret is *lost*), which A7b fixes only on the opt-in path.
- **"Delivery combiner X-Wing-like":** agreed, with one addition. X-Wing's post-quantum guarantee concerns confidentiality. The view tag (R11-W5) is outside any combiner, so recipient unlinkability is classical regardless of the combiner.
- **"Zeroization gaps":** A7b's `SecretString` covers the persisted seed. Remaining:
  - `password()` does not zeroize `p` on mismatch (`main.rs:175-184`);
  - the mnemonic `String` from `Mnemonic::to_string()` on main (A7b wraps it);
  - `Persisted` clones of rings and outputs are not secret.
- **Empty passwords and directory fsync** (from completion-readiness): the directory fsync is fixed by A7b on Unix. On Windows, `rename` durability without `FlushFileBuffers` on the directory is not addressed. It matters for the W-1 guarantee (the save before sending must survive a power loss) [unknown for NTFS semantics; low].
- **W-F7 (restore scans account 0):** see R11-W10. Removing accounts from the CLI is a valid, cheaper resolution.

---

## 9. Sources

- Liu, Tromer. *Oblivious Message Retrieval.* CRYPTO 2022. https://www.semanticscholar.org/paper/Oblivious-Message-Retrieval-Liu-Tromer/834a0e6c435658d724bd39dae5cd28eda36c13fb
- Liu, Tromer, Wang. *PerfOMR: Oblivious Message Retrieval with Reduced Communication and Computation.* USENIX Security 2024. https://eprint.iacr.org/2024/204 ; https://www.usenix.org/conference/usenixsecurity24/presentation/liu-zeyu
- *HomeRun: High-efficiency Oblivious Message Retrieval, Unrestricted.* ACM CCS 2024. https://dl.acm.org/doi/10.1145/3658644.3670381
- Beck, Len, Miers, Green. *Fuzzy Message Detection.* ACM CCS 2021. https://eprint.iacr.org/2021/089
- Seres, Pejó, Burcsi. *The Effect of False Positives: Why Fuzzy Message Detection Leads to Fuzzy Privacy Guarantees?* FC 2022. https://eprint.iacr.org/2021/1180
- Penumbra S-FMD. https://protocol.penumbra.zone/main/crypto/fmd.html
- Madathil, Scafuro, Seres, Shlomovits, Varlakov. *Private Signaling.* USENIX Security 2022. https://www.usenix.org/conference/usenixsecurity22/presentation/madathil
- Mikić et al. *Post-Quantum Stealth Address Protocols* (ML-KEM-based, view tags). 2025. https://arxiv.org/abs/2501.13733 ; https://eprint.iacr.org/2025/112.pdf
- Zcash ZIP-307, *Light Client Protocol for Payment Detection.* https://zips.z.cash/zip-0307 ; https://github.com/zcash/lightwallet-protocol
- Zcash Protocol Specification (Sapling/Orchard key components, spend authorization). https://zips.z.cash/protocol/protocol.pdf
- tevador, *Polyseed.* https://github.com/tevador/polyseed ; https://docs.getmonero.org/mnemonics/polyseed/
- Chiesa, Lehmkuhl, Mishra, Zhang. *EOS: Efficient Private Delegation of zkSNARK Provers.* USENIX Security 2023. https://www.usenix.org/conference/usenixsecurity23/presentation/chiesa
- Garg, Goel, Jain, Policharla, Sekar. *zkSaaS: Zero-Knowledge SNARKs as a Service.* USENIX Security 2023. https://eprint.iacr.org/2023/905
- Aleo, *Delegated Proving.* https://developer.aleo.org/sdk/delegate-proving/delegate_proving/

Uncited industry references from my own knowledge:
- Monero view tags (hard fork v15, 2022);
- the Monero Ledger/Trezor signing protocol;
- Monero cold signing;
- Ozdemir and Boneh, collaborative zk-SNARKs (USENIX Security 2022).

These should be checked before being quoted externally.
