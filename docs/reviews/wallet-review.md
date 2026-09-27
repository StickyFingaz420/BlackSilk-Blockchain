# Wallet error-handling review

Status: **internal, 2026-09-25; round 2 2026-09-27 (§1b). Not independently reviewed.**

**Scope:** `wallet/src/` (about 2,900 lines: CLI, wallet state, PX store, file format,
node interface) and the RPC client it uses.

**Method:** every path by which the wallet talks to the node, the disk or the user was
read, asking three questions:
1. Can a failure here corrupt the wallet or lose funds?
2. Can it weaken privacy?
3. Does the user get an accurate message?

## 1. Findings

| # | Finding | Severity | Resolution |
|---|---|---|---|
| W-1 | **An uncertain submission released the inputs.** If `submit_tx` failed in transport (a reset connection, the 120 s timeout) after the node had received the transaction, the wallet did not reserve the inputs. A retry built a new transaction spending the same v1 output with a **new ring**; both could reach the network, sharing a key image. Intersecting the two rings reveals the real input | **High (privacy)** | Fixed. Inputs are reserved and the transaction stored *before* the request. A transport error returns `WalletError::Uncertain`, which explains the risk; the inputs stay reserved |
| W-2 | **Reserved inputs were released after 20 blocks, even if the transaction was still pooled.** The old expiry freed them; the next spend used new rings. The old test showed exactly that: the transaction was still in the mempool when the inputs were released | **High (privacy)** | Fixed. Stored transactions are **rebroadcast unchanged** every 20 blocks. The inputs are released only when the node answers `Invalid`, meaning the transaction can never be mined on this chain. "Already pooled", a full pool and transport errors keep them reserved |
| W-3 | **A reorganization released the inputs of a confirmed spend.** A rewind cleared `spent_height`, so the outputs became spendable again while the transaction went back to the pool | **Medium (privacy)** | Fixed. A stored transaction is kept until its spend is 20 blocks deep, and a sync re-reserves its inputs after a rewind |
| W-4 | **A vault lock with an uncertain outcome lost the record's opening.** The creator's copy of the vault record was stored only after a successful submission. If the transaction reached the chain anyway, the funds were locked in a record the wallet could not open (unless it was delivered elsewhere) | **Medium (funds)** | Fixed. The copy is stored before submitting and removed only on a definite refusal |
| W-5 | **After an `Invalid` verdict or `clear-pending`, a new spend used new rings.** A relayed transaction that later became invalid (for example, a ring member was reorganized away) still shares its key image with the new spend, so observers of both could intersect the rings | Medium (privacy) | **Fixed, with residuals (§1a).** The wallet keeps the ring of every submitted spend and reuses it, as far as its members survive |
| W-6 | **Rebroadcasting gives spy nodes another look at the origin.** A stored transaction is resubmitted through the wallet's node every 20 blocks while it is unconfirmed. If the node's pool already holds it, the node answers "already known" and relays nothing; if the node lost it, it enters the Dandelion++ stem again | Low | Accepted. The alternative is funds stuck indefinitely. Documented in privacy-review.md §3c |
| W-7 | Wallets written before this change may hold reservations without a stored transaction | — | These keep the old 20-block expiry. Recommendation: before the testnet reset, create new wallets rather than migrating old files |
| W-8 | `clear-pending` could be used casually | Low | Its help text and the `Uncertain` message now warn that it is only for a transaction that never left the wallet |

## 1b. Round 2 (internal, 2026-09-27)

A second internal pass over the wallet and its RPC client, plus the contract review.
Every finding was reproduced or confirmed in the code before it was fixed. Internal
work, not an independent audit.

| # | Finding | Severity | Status |
|---|---|---|---|
| M-1 | **A large address index bricked the wallet file.** `address` stored any index as `issued`, and every load derived `issued + 50` subaddresses; `px-address --index 4000000000` did the same for PX, where scanning derived ML-KEM keys for every index up to `issued + 20`, per PX output | Medium (availability) | **Fixed.** An index more than 1,000 beyond the highest one that has received funds is refused without `--force`; with it, the ceiling is 10,000 (v1) and 2,000 (PX). Files from older versions with larger windows are clamped on load, with a warning. The window is extended incrementally, and PX delivery keys are derived once per session and cached in memory |
| M-2 | **The v1 scan window never grew.** Scanning found outputs but did not raise `issued`, so a wallet restored from its seed never saw subaddresses beyond 50, even after finding a payment at 45 | Medium (funds not found) | **Fixed.** Gap-limit scan: an output at `(account, i)` raises `issued` to `i`, the window is extended and the block is scanned again, so later outputs of the same block are found. Old files with funds above their window are repaired on load |
| L-1 | The first address of a new account was not scanned until the next load (`or_insert(0)` without extending the table) | Low | **Fixed** |
| L-2 | **RPC client:** accepted `https://` addresses although no TLS stack is compiled in; honoured proxy environment variables implicitly; followed redirects; read response bodies without limit | Low (privacy, memory) | **Fixed.** `https://` and other schemes are refused with a clear message (`Client::try_new`). Proxies and redirects are disabled. Every body is capped per endpoint, above the largest honest response (derived from the node's own limits; tested) |
| L-4 | **Secret copies:** the hex seed in the serialized form was a plain `String`; `mnemonic()` returned a plain `String`; a malformed field's value was echoed in errors | Low | **Fixed** for the wallet's own copies: the seed is a `Zeroizing` string, `mnemonic()` returns `Zeroizing<String>` written into a preallocated buffer, and no error echoes a field's value. **Not coverable:** `serde_json` may reallocate its output buffer while writing the JSON (earlier copies stay in freed memory); `bip39::Mnemonic` keeps word indices without zeroizing (its `zeroize` feature is off); clap keeps its own copy of any secret given on the command line; the OS may swap or dump memory |
| L-5 | Wallet and lock files were created with the default permissions; the directory was not fsynced after the rename; the `atomic_write` test checked for `w.tmp`, a name never used (the real one is `w.tmp<pid>`) | Low | **Fixed.** On Unix both files are created 0600 and the directory is fsynced. A stale temporary file is removed first. The test now checks the real name and that only the wallet file remains. On Windows the files inherit the directory's ACL |
| L-6 | Vault secrets could only be given on the command line (shell history, process list) | Low | **Fixed.** `--secret-file`, `--secret-prompt` (lock) and a prompt by default (claim). `--secret` still works, with a warning. `--secret-out` writes a generated secret to a new owner-only file |
| P-1 | **Vault operations accepted a contract that registers other programs next to the vault.** Any program of a contract can spend its records, so a claimer could deploy `{vault, backdoor}` and take locked funds without the secret | Medium (funds) | **Fixed.** Lock and claim require the registered program set to be exactly `{vault}`. `px-deploy --vault` cannot be combined with `--program`; the library refuses such a deploy; `px-contracts` warns. docs/px.md §13.4 states the trust boundary |
| P-2 | The wallet used whatever vault budget was registered. A budget that fits LOCK but not CLAIM would lock funds for good; an odd one fingerprints proofs | Low (funds) | **Fixed.** The budget must equal `vault::BUDGET` |
| R11-W1 | **A vault lock with a generated secret lost the secret when the submission ended "uncertain".** The error returned before the secret was printed, and the wallet stored only `Hk(LOCK, secret)`. The lock could still be mined; the demonstration vault has no refund | High (funds) | **Fixed.** The secret is stored with the record's opening before `submit` saves and sends. `px-vault-secret` shows it; `px-records` marks it; the uncertain path prints a generated secret too |
| D-1 | docs/px.md §6 and `px/src/delivery.rs` called the delivery key combiner "as in X-Wing". It hashes `ss_ec ‖ ss_kem ‖ R ‖ ct_kem ‖ cm`, without the recipient's `V` or `H(ek)` | Documentation | **Corrected.** Adding `V` and `H(ek)` is recorded as a non-blocking hardening (a wire-format change). Also documented: PX has no view/spend separation, and keys are not network-separated |

**Residuals of round 2:**
- **Restore scope.** A wallet restored from its seed scans account 0 only, and 50
  subaddresses (20 PX addresses) beyond the highest one found. `address` and
  `px-address` print a note when an address is outside what a restore would find.
- **`Wallet::address` and `Wallet::px_address` panic** beyond the gap limit (library
  convenience for tests and tools). The CLI uses `try_address` and `try_px_address`
  only. Callers checked: the CLI's `create` (index 0), the e2e tests (small indexes)
  and `tools/labnet` (indexes below 4 and 3). No path passes user input to them.
- **The gap limit counts funds found, not addresses handed out.** Handing out more
  than 1,000 unused addresses needs `--force`.
- **No wallet Tor/SOCKS support.** Reach a remote node over an SSH tunnel, a VPN or a
  local Tor forwarder.

## 1c. Round 3 (internal, 2026-09-27): decoys, ring queries, merging, PX keys

Internal work, not an independent audit. No consensus change.

| # | Finding | Status |
|---|---|---|
| R3-1 | Coinbase maturity was applied after the decoy draw, so young decoys almost vanished on a young chain | **Fixed.** Eligibility is applied inside the picker: a uniform eligible output of the drawn block, else of an age-proportional window around it (`w = clamp(depth/4, 9, 720)`), else a new draw. Measured on a synthetic 3-day chain: decoys younger than 60 blocks went from 3.4 % to 17.8 % (target 20.6 %). The real input spent at 12 blocks was the newest member in 89.8 % of rings before and 51.5 % after (target 62.4 %). Cost: on a coinbase-only chain, decoys 60–69 blocks deep are 12.9 % instead of 6.0 %. docs/transactions.md §11.3.1 |
| I3 §3.9 / F2 | `/outputs` requests carried a superset of every ring, the real input included | **Fixed.** Local output index (`wallet/src/index.rs`), stored in the wallet file. Rings make no node request. Outputs below the restore height are backfilled once, as the whole range in consecutive pages of 1,024. Tests: `rings_are_built_without_asking_the_node_about_outputs`, `a_late_restore_backfills_older_outputs_once` (e2e), `the_backfill_fetches_the_whole_missing_range_in_fixed_pages` |
| R3-13 | Outputs of one transaction could be spent together | **Fixed.** Selection takes one output per source transaction first; it co-spends only when necessary, and then warns. Test `outputs_of_one_transaction_are_not_spent_together_unless_needed` |
| R11-W2 / I2-R1 | No PX viewing hierarchy | **Implemented as PX key derivation 2** (docs/px.md §3.1): per-range `dk_k` and `ivk_k`, a `RangeViewKey` (full view of one range) and an `IncomingViewKey` (receipts only, no `nk`). This is library API only: no CLI export and no watch-only scanner |
| R11-W3 | Seed and file have no version | **Partly done.** The wallet file records the PX derivation (file version 2; version-1 files migrate as derivation 1, unchanged). **Not done:** the 24 words still carry no version, network or birthday. `restore --px-derivation 1` is needed for pre-2026-09-27 seeds that hold PX funds |

**Residuals of round 3:**
- **Guess-newest is reduced, not removed.** A real input spent 12 blocks after receipt
  is still the newest member in about half the rings on the test chain. The gamma
  target itself gives about 62 %. Sparse young transfers attract many young draws. Coinbase-dominated
  rings (R3-3) are unchanged.
- **Index size and trust.** The index takes 146 hex characters per output in the
  wallet JSON, about 150 MB per million outputs, rewritten on every save. It should
  move to an append-only side file before large chains. Backfilled entries come from
  the node unverified (as `/outputs` answers did before). A reorganization below the
  restore height, which the wallet cannot see, would make them stale, and the node
  would then reject the transaction.
- **Seed format v1 (design, not implemented).** 26 words from the BIP-39 list, 11 bits
  each: 256-bit entropy, a 5-bit version, a 2-bit network, a 10-bit monthly birthday
  and a 13-bit checksum over all of them. Keys derive from
  `H("blacksilk/seed/v1" ‖ network ‖ entropy)`. The different word count stops
  BIP-39 wallets accepting it. Changing it needs docs/blocks.md §10 and the restore
  UX, so it is left for a separate change before a public testnet.
- **Range allocation.** Every address in use lies in range 0. Allocating one range per
  period, with the change branch inside it, is policy still to write.
- **R11-W4** (spend authority equals proving) is unchanged. `ak` stays `Hk(AK, sk)`,
  because the kernel fixes it.

## 1a. W-5 in detail: ring reuse

**Precedent:** Monero's wallet ring database (`ringdb`), introduced so that an output
spent on two forks uses the same ring on both.

**Design** (`wallet/src/wallet.rs`: `rings`, `plans_for`, `surviving`, `submit`):
1. **What is stored.** For every v1 input of a submitted transaction, the wallet stores
   the ring's 15 decoys (index, one-time key, commitment) under the input's key image,
   in the encrypted wallet file.
2. **When it is stored.** When the transaction may have become public: the node
   accepted it, answered "already known", or the outcome is uncertain. A definite
   refusal by the wallet's own node discards it: that transaction never left, and
   fresh decoys fit the current chain better.
3. **When it is reused.** Whenever the output is spent again, after `clear-pending`,
   after an `Invalid` verdict, or after a restart.
4. **Which members are kept.** Each stored member is fetched again from the node. It
   is kept only if:
   - the same index still holds the same keys (after a reorganization an index can
     hold another output, or none);
   - it satisfies the age rule;
   - if it is a coinbase output, it is still mature (a reorganization can shorten the
     chain).
5. **The rest is drawn fresh** (`tx::decoy::select_ring_keeping`), and the new ring is
   stored in place of the old one.
6. **When it is pruned.** Once the output's spend is 20 blocks deep and no stored
   transaction spends it.

**Privacy analysis.** Let k be the number of surviving decoys.
- **k = 15** (the usual case: no reorganization touched the ring). The second ring is
  identical to the first; an observer of both learns nothing beyond the fact that the
  two transactions spend the same output, which the key image already reveals.
- **k < 15.** The intersection holds k + 1 candidates instead of about 1 with fresh
  rings. Reuse never does worse than fresh rings.
- **Decoy age.** A reused ring looks old for the new transaction's height. That could
  hint that a ring is recycled, but reuse happens only after a transaction with the
  same key image may already have been seen, so it reveals nothing new.
- **Node queries.** Re-fetching the old members shows them to the wallet's node. That
  node saw them in the first transaction (under the "use your own node" assumption);
  a remote node would learn the ring. The same holds for all decoy fetches.

**Residuals:**
- **Restore from seed.** Rings live in the wallet file, not in the seed. After a
  restore, a spend of an output whose earlier transaction was relayed but never mined
  uses fresh rings. Mitigation: keep wallet-file backups. The rings cannot be
  reconstructed from the chain, because that transaction is not on it.
- **Linkability remains.** Two spends of one output are always linkable through the
  key image. Reuse only prevents them from revealing the real input.
- **Wallets written before this change** have no stored rings.

**Tests** (`wallet/tests/e2e.rs`):
- `an_output_spent_again_reuses_its_ring`: an identical ring after `clear-pending`,
  after an `Invalid` verdict, and after a save and load;
- `a_refused_transaction_does_not_pin_its_rings`: a refused spend's rings are not
  kept;
- the unit test `tx::decoy::tests::kept_members_survive_and_only_the_rest_is_drawn`:
  partial survival.

**Not tested end to end:** partial survival after a real deep reorganization (it needs
a reorganization deeper than the 10-block age of every ring member). It is covered by
the unit test and by review only.

## 2. Checked and found adequate

| Area | Behaviour | Evidence |
|---|---|---|
| Wallet file writes | Encrypt to `*.tmp<pid>` (0600 on Unix), fsync, rename, fsync the directory (Unix): a crash leaves the old or the new file, never a partial one | `wallet/src/file.rs::write_atomic`; tests `atomic_write`, `wallet_files_are_owner_only` (Unix only) |
| Wrong password, damaged file | One message: "wrong password or damaged wallet file" (indistinguishable by design) | `file.rs::wrong_password_and_tampering_are_rejected` |
| Truncated or tampered header | Length checked before parsing; absurd Argon2 parameters refused (memory exhaustion) | `file::decrypt` |
| State saved after an error | The CLI saves after every command, even a failed one, so reservations and sync progress are kept | `main.rs` |
| Node inconsistencies | Block ids recomputed and compared; `BadNodeData` on mismatch | `Wallet::sync` |
| Wrong network | Refused with both network names | `e2e.rs::wrong_network_is_refused` |
| Insufficient funds | Available and needed amounts shown (amount plus fee) | `WalletError::InsufficientFunds` |
| Panics on external input | The 11 `expect` calls outside tests all follow from local invariants (checked lengths, the wallet's own data), not from node or file input | This review |

## 3. Remaining weaknesses (not fixed)

- **Error text for developers:** some messages print Rust `Debug` forms, such as
  address decode errors, `BuildError` and node rejection reasons (`Invalid(...)`).
  They are accurate but not friendly.
- **Password memory:** the password is not zeroized when loading fails (the process
  exits immediately afterwards).
- **Legacy contract-record reservations:** a contract record reserved by a wallet
  version older than this change stays reserved until `clear-pending`.
- **W-5 residuals** (§1a): restore from seed loses the rings; spends of one output remain linkable.

## 4. Tests

In `wallet/tests/e2e.rs`, over the real RPC server with a wrapper that fakes transport
failures and verdicts:
- `an_unconfirmed_transaction_keeps_its_inputs_and_is_rebroadcast_unchanged`: W-2.
  Also pins the node's "already pooled" answer that the wallet relies on.
- `an_uncertain_submission_keeps_the_inputs_reserved_across_a_restart`: W-1,
  including a save and load.
- `a_stored_transaction_the_node_finds_invalid_releases_its_inputs`: the only
  automatic release, after a transport failure that must not release.
- `wallet_follows_a_reorganization` (extended): W-3.
- `an_uncertain_vault_lock_keeps_the_record_opening`: W-4. The lock reaches the node,
  the wallet sees a transport failure, keeps the opening, and holds a confirmed
  record after mining.
- **Limitation:** the reservation checks inside the wallet are `debug_assert!`s, which
  do not run in the release-mode test runs.

Round 2 (§1b):
- `wallet/src/wallet.rs` unit tests: `subaddress_indexes_beyond_the_gap_limit_need_the_override`,
  `the_limit_follows_the_highest_index_that_received_funds`,
  `a_new_account_is_scanned_from_index_zero_at_once` (L-1),
  `finding_funds_moves_the_window`, `absurd_scan_windows_in_old_files_are_clamped_on_load`
  (a file with two accounts at `u32::MAX`-sized windows, clamped to 10,000 each, loads
  in about 1.7 s on the test machine), `old_files_with_funds_above_the_window_raise_it_on_load`,
  `px_address_indexes_beyond_the_gap_limit_need_the_override`,
  `secrets_stay_out_of_error_messages`, `the_mnemonic_round_trips_without_reallocating`,
  `deploys_mixing_the_vault_with_other_programs_are_refused`,
  `vault_lock_and_claim_refuse_unsafe_contracts_before_proving` (P-1, P-2, with a fake
  node), `a_stored_vault_secret_survives_a_save_and_load` (R11-W1).
- `wallet/src/px.rs`: `vault_operations_need_the_vault_alone_with_the_reference_budget`,
  `the_used_index_counts_payments_and_contract_records_received`,
  `cached_address_keys_match_fresh_derivation`.
- `wallet/src/file.rs`: `atomic_write` (corrected), `wallet_files_are_owner_only` (Unix).
- `rpc/src/lib.rs`: `https_and_unknown_schemes_are_refused`,
  `an_oversized_body_with_a_length_is_refused_before_reading`,
  `an_endless_body_without_a_length_is_cut_at_the_cap`, `error_bodies_are_capped_too`,
  `a_body_within_the_cap_is_parsed_and_redirects_are_not_followed`,
  `caps_cover_the_largest_honest_responses`.
- `wallet/tests/e2e.rs`: `a_restored_wallet_follows_payments_beyond_its_first_window`
  (M-2: payments at 45 and 90 in one block, then 140; fails without the fix, checked),
  `out_of_range_address_indexes_are_refused` (M-1), and
  `an_uncertain_vault_lock_keeps_the_record_opening` extended to recover the secret
  from the autosaved file (R11-W1; it builds PX proofs).
- Not tested: proxy environment variables being ignored (setting them in a
  multi-threaded test process is racy); `.no_proxy()` is checked by review.
