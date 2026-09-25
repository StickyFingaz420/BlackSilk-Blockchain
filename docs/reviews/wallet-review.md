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
| W-5 | **After an `Invalid` verdict, a new spend still links by key image.** If a relayed transaction later becomes invalid (for example, a ring member was reorganized away), spending the same output again with new rings lets observers who saw both transactions intersect the rings | Low (rare) | **Open, documented.** A full fix reuses the old ring for that input where its members still exist. Not implemented |
| W-6 | **Rebroadcasting gives spy nodes another look at the origin.** A stored transaction is resubmitted through the wallet's node every 20 blocks while it is unconfirmed. If the node's pool already holds it, the node answers "already known" and relays nothing; if the node lost it, it enters the Dandelion++ stem again | Low | Accepted. The alternative is funds stuck indefinitely. Documented in privacy-review.md §3c |
| W-7 | Wallets written before this change may hold reservations without a stored transaction | — | These keep the old 20-block expiry. Recommendation: before the testnet reset, create new wallets rather than migrating old files |
| W-8 | `clear-pending` could be used casually | Low | Its help text and the `Uncertain` message now warn that it is only for a transaction that never left the wallet |

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
- **W-5:** ring reuse, above.

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
