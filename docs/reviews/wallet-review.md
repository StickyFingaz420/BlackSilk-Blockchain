# Wallet error-handling review

Status: **internal, 2026-09-25. Not independently reviewed.**

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
| Wallet file writes | Encrypt to `*.tmp`, fsync, rename: a crash leaves the old or the new file, never a partial one | `wallet/src/file.rs::write_atomic`; test `atomic_write` |
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
