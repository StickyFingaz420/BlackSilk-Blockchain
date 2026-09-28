# Private contracts on PX

Status: **the contract layer of PX, as implemented for the testnet v3 rule set; a
demonstration platform, not production-ready.** Normative where marked; the kernel,
the proof and the transaction formats are specified in [`px.md`](px.md), which this
document does not repeat. The consensus changes behind §4–§5 are recorded in
[`reviews/v3-consensus-changes.md`](reviews/v3-consensus-changes.md) (sections
`approval-conflict`, `px-call-abi`, `px6-validity-window`, `vault-v3`). This is
internal engineering work, not an audit.

The former Wasm contract specification, which used this file name, is superseded
research: [`research/wasm-contracts.md`](research/wasm-contracts.md). References of the
form "contracts.md §N" in the `contracts/` crate, the `crypto` Wasm modules, zk.md's v1
contract sections and AUDIT.md R7 mean that file.

---

## 1. Scope and the platform decision

**PX is the only consensus contract platform** (ADR-28-1, owner decision D22).
- A private contract is a set of BVM-1 programs (RISC-V) registered by a deploy (kind
  3). A **call** is a PX transaction (kind 2) that runs up to `MAX_FN = 2` of them in
  the same batch proof as the kernel (px.md §7).
- Value lives only in PX records. A function never moves value: it **approves**
  records of its contract for consumption and **specifies** outputs; the kernel alone
  enforces the balance, over the integers (px.md §4.1).
- There is no second value layer, no public contract state and no committee. The only
  admissible future door for public state is a "finalize" phase attached to PX calls,
  with no value of its own, and only with evidence of demand (§9).
- The Wasm engine is not part of any network.

## 2. Capability envelope

What a contract can do today, and what it cannot:
- **Shapes.** Two inputs and two outputs per transaction in total, two functions at
  most, 248 bits of `data` per record (8 field elements). Larger state goes into a
  hash, with the preimage delivered off chain.
- **Bilateral and UTXO-style contracts only.** No shared state between users, so no
  pooled DeFi: every record is consumed whole by one transaction.
- **Time.** A transaction may carry a validity window (§4.3), which every called
  function reads. Timeouts, refunds and deadlines are expressible; there is no other
  clock.
- **Throughput.** A PX transaction is about 2 MB with its proof, so a block holds a
  few (px.md §8, §11.5). Aggregation is research (§9).
- **Always public** for a call (privacy review P-8): the contract id and the program id
  of every called function, the functions' public output words (a fixed number per
  program, §5), the transaction's validity window, and the bridge amounts. Private:
  records, owners, amounts, which records were consumed, and everything the functions
  read.

## 3. The model

(Normative text: px.md §4.1 and §7.2.) A function of contract `C`:
- reads private input only it is given (for example a record's opening and a secret);
- **approves** kernel inputs, each a record of `C` identified by its exact commitment;
- **specifies** kernel outputs `(owner, contract, value, data)`: new records of `C`
  (owner 0) or payouts to users; the kernel adds `rho`, the caller chooses `rcm`;
- commits to all of that in `io_hash`, a hiding commitment (a random blind), which the
  kernel recomputes from the **actual** inputs and outputs.

The kernel enforces, for every call (exit codes in px.md §4.2):
- a contract input is approved by **exactly one** function of its contract
  (`Unauthorized` if none, `ApprovalMismatch` for an approval by another contract or
  of a dummy or user record, **`ApprovalConflict`** for a second approval, testnet v3,
  F-20-1);
- a contract output is specified by a function of its contract and has owner 0
  (`Unauthorized`, `ContractOutputOwner`);
- a specified output matches exactly, and at most one function specifies it
  (`SpecMismatch`, `SpecConflict`); a function specifies only its own contract's
  records or user payouts (`SpecForeignContract`).

So one consumed record authorizes one transition: two functions of a contract in one
transaction can never both act on the same record (the input-side form of Cardano's
"double satisfaction").

The **registry** (px.md §7.3, §11.2) maps `(contract, program id)` to the program, its
row budget, its call ABI and its output-word count. It is immutable: a contract is
exactly the programs its deploy registered.

## 4. The function ABI (normative)

### 4.1 The function prefix

Every function writes, as the first `PREFIX_WORDS = 21` words of its public output
(`px_core::call::function_prefix`):

```text
abi ‖ io_hash[8] ‖ contract[8] ‖ not_before(lo, hi) ‖ not_after(lo, hi)
```

followed by exactly `out_words` words of its own public output (§5). The verifier
builds the same prefix from public values only:
- `abi`: the program's **registered** call ABI;
- `io_hash`, `contract`: the transaction's function entry (checked against the kernel's
  statement);
- the window: the transaction's own (§4.3).

A proof exists only if the function wrote exactly this prefix, so a function can rely
on each of these values.

### 4.2 ABI versioning (F-28-1)

`ABI_VERSION = 1` (`px_core::call::ABI_VERSION`) is the only ABI this kernel
generation verifies. A deploy registering any other ABI is invalid
(`PxUnsupportedAbi`, stateless). The ABI and the output-word count are in the deploy
payload, so the contract id commits to them.

**Why.** Programs are compiled against the call format (`Call`, `OutSpec`, `N_IN`,
`N_OUT`, the prefix). A later kernel generation that changes it would otherwise make
every deployed contract uncallable and strand the value in its records. With the ABI
recorded per program, a later verifier can tell old-ABI programs from new ones.

**Verifier selection by (epoch, ABI): designed, not implemented (W28-9).** When a
second kernel generation activates at a height (consensus.md §11), the verifier for a
call is chosen from the pair (the epoch's verifier generation, the ABI registered for
each called program):
- a call whose functions all have the old ABI is verified by the old generation's
  kernel and statement, at least until a published sunset height, so records of
  old-ABI contracts stay spendable;
- a call mixing ABIs is invalid;
- in the style of ZIP 211, old-ABI calls may be restricted to outputs that are user
  records or records of new-ABI contracts, so value can leave old contracts but not
  enter them;
- the verified-proof cache is keyed by the verifier generation (R16-8);
- `TxRules` carries the verifier id, with a start-up assertion (RT-3).
None of this exists in code; there is one generation. Its review and tests (a regtest
two-epoch activation in which an old-ABI vault record is still claimable after the
activation, and a new-ABI call is refused before it) come with the second generation.

### 4.3 The validity window, PX6 (normative)

A PX transaction carries `[not_before, not_after]` in its prefix (px.md §11.1), covered
by `h_tx`, and every called function receives it in its prefix. A block at height `h`
may include the transaction only if

```text
not_before ≤ h   and   (not_after = 0  or  h ≤ not_after)
```

- `(0, 0)`, the default, is unbounded. Every wallet uses it unless a contract needs a
  window, so the window does not set transactions apart.
- An inverted window (`not_after ≠ 0`, `not_before > not_after`) is invalid
  (`PxWindowInverted`, stateless).
- Outside the window the transaction is invalid with `PxWindow`: **contextual, never
  penalized**, because the same transaction is valid at another height and heights
  race at the edges. The mempool admits for the next block's height (a premature
  transaction is refused; the wallet keeps it), drops a transaction whose window has
  passed at every revalidation, after a reorganization too, and templates take only
  transactions whose window contains their height. The block path checks the window
  for every PX transaction, including those whose proof the node verified before: a
  verified proof says nothing about the height. In the mempool path the window is
  checked before the range proof (RTW1C-5).
- **Expiring soon (policy, RTW1C-4).** Pools and relays refuse a PX transaction whose
  window ends within three blocks, `not_after ≠ 0 ∧ not_after < next + 3`
  (`tx::validate::px_expires_soon`; Zcash's threshold): it is still valid in a block
  inside its window, but would likely expire while it propagates. A pooled
  transaction stays until its window ends, and one a reorganization returns is
  readmitted. Build windows that end at least three blocks ahead.
- A function **asserts** on the window it reads: `not_after ≠ 0 ∧ not_after < T`
  shows that the transaction is included before `T`; `not_before ≥ T` shows that it is
  included at `T` or later. This is the CLTV model (BIP 65; Zcash ZIP 203 expiry,
  Aztec's `expiration_timestamp`), with no clock inside the proof.

## 5. Deploy rules (normative; px.md §11.2, §11.3)

- A deploy is a v1 transfer (it pays the fee from v1 funds, so the deployer is hidden
  behind ring signatures) plus a salt and 1–16 programs, each with its ELF, row
  budget, call ABI and **`out_words`**, the exact number of public output words each
  call publishes after its prefix (at most `MAX_FN_OUTPUT_WORDS`).
- Every call must publish exactly `out_words` words (`PxOutputWords`, checked with PX3),
  so the length of a function's output never varies between calls of one program
  (F-28-5).
- The fee is exact: the standard fee of the transfer's shape plus a per-byte payload
  fee (`px::deploy_fee`).
- Budgets must be provable, programs must load and be pairwise distinct, the ABI must be
  `ABI_VERSION`.
- The contract id is `H64("px/contract-id", first key image ‖ salt ‖ H32(payload))`
  reduced to 8 field elements; the payload covers every program's ELF, budget, ABI and
  `out_words`. Registrations are immutable and usable from the next block.
- **Privacy note (I2-F5).** The deploy's first key image is public, and so is the
  contract id derived from it: a deploy is linkable to its v1 inputs' rings, like any
  v1 spend.

## 6. Contract-author security checklist

Each item cites the finding it comes from. Check every item before deploying.

1. **"Self" is a checked input.** Read the contract id from the input and bind it
   through the prefix (the verifier fills it). Wallets and verifiers pin the
   **contract id**, never only the program id: one ELF can be registered under many
   contracts (R5-8).
2. **A contract is its whole program set.** Any registered program can approve any
   record of the contract (P-1). Tag every record's `data` with a type and version,
   and check it in every function (F-28-6).
3. **Account for approved value.** For every approved input, specify outputs that cover
   its value, or document where it goes: the kernel enforces only the global balance,
   never per contract (px-f4-f5-analysis §4a, F-20-2).
4. **One approval per record.** Since testnet v3 the kernel refuses a second approval of
   an input (`ApprovalConflict`, F-20-1), so linear state (unique items, sequence
   numbers, approval records) cannot fork within a transaction. Two functions of your
   contract in one transaction can still act on *different* records: design for it.
5. **Contract outputs have owner 0** (PX-F5, enforced). A user payout to an owner tag
   nobody can open burns its value (F-20-6): specify payouts only to derivable address
   tags.
6. **Delivery (PX-F4).** The caller chooses `rcm` and writes the ciphertext of every
   output. Any multi-party state is griefable (lock or burn) by a caller who withholds
   the opening. Let the party who needs a record create it, or accept that risk
   explicitly.
7. **Contract nullifiers are visible to every holder of the opening** (R3-7, I2-F1): a
   credential issued as a contract record gives no anonymity on first use without a
   holder-refresh step.
8. **Authority from `sk`, not viewing material.** Programs that confer authority
   (votes, reserves) must derive `ak`/`nk` from `sk` (I2-F2).
9. **Public outputs.** Publish a fixed number of words (`out_words`, enforced), with no
   amounts, owners or secret-derived values (R7-8, F-28-5).
10. **Application hashes.** Use your own domain constants outside PX's `0x0050_58xx`
    range, and **include the contract id**, so a secret reused across instances opens
    only its own (F-28-7; the reference vault does, §8).
11. **Randomness.** Derive the `io_hash` blind and every `rcm` you choose from a CSPRNG,
    hedged with a wallet secret (R-6, W28-4; `blacksilk_px::wallet::hedged_digest`).
12. **Budget.** Measure the worst case of **every** valid path, not a sample, and keep
    headroom in every table (5%, as `px/tests/unified.rs::budgets_leave_headroom` does
    for the vault; the kernel's own budgets are checked against every shape it
    accepts, `px/tests/kernel_budget.rs`). A path over budget cannot be proven: funds
    under it are stuck (P-2). The prover refuses any execution over its own budget in
    any table (`TransferError::OverBudget`), even when the padded shared tables would
    have had room, so provability never depends on the other calls (RTW1C-1).
13. **Canonical input.** Check every field element you read (`canonical`); halt with
    codes, never with located panics (R15-6; `px/tests/elf_paths.rs`).
14. **Time.** Assert on the echoed window (§4.3); a function that reads the window but
    never checks it gets no protection. Size margins for censorship: a miner can
    delay a claim until a deadline passes.
15. **Shapes.** 2 inputs, 2 outputs and 248 bits of `data` in total (§2).
16. **Immutability.** Registrations never change. Build against `ABI_VERSION`, and
    include a migration path if the contract must outlive a kernel generation (§4.2).
17. **Reproducibility.** Pin the ELF and its program id (like `px/vault.id`), build
    path-neutrally with the pinned toolchain and link layout (zkvm/guests/README.md),
    and publish the source hash (R7-9).
18. **Anonymity set.** A call reveals the contract and program (P-8). A contract with
    few users gives little anonymity; show the set size in the interface (I2 §4.5).
19. **Front-running.** Whoever holds a record's opening and the function's secret can
    race you.
20. **Tests before deploying.** Every rule violation natively and in the guest, an end-
    to-end proof, budget headroom, window boundaries if you use a window, and
    two-function interactions if the contract allows them (W28-3).
21. **Dry-run every way out before locking funds (RTW1C-8).** Before value goes into a
    record of a contract (yours or a third party's), run each function that can
    release it, with the record's real opening, and check that it halts with 0, writes
    the prefix the kernel requires, publishes exactly the registered `out_words`, and
    fits the registered budget in every table. A registration whose release path fails
    any of these locks the value for good. The wallet does this for the vault before
    every lock (CLAIM, and REFUND with a timeout; §8); other contracts need the same
    check in their host-side helper.

## 7. Delivery and sharing

Record delivery and off-chain sharing are specified in px.md §13.1–§13.3 (normative):
every output carries one ciphertext, addressed for a contract record to the party that
will act on it; the creator keeps a copy; a holder can share an opening off chain, and
a recipient accepts it only if it recomputes the commitment and the commitment is on
chain. A share reveals the record to its addressee; like any ciphertext it is
confidential only while the hybrid encryption holds (px.md §9.1).

## 8. The reference vault and its limits

`zkvm/guests/vault` (host side `px/src/vault.rs`, pinned as `px/vault.elf`, id in
`px/vault.id`, registered budget `vault::BUDGET`, `out_words = 1`) is a
**demonstration contract**. A vault record of contract `C` stores its terms:

```text
data        = Hk(TERMS,  C ‖ claim_lock ‖ refund_lock ‖ timeout₁₆[4])
claim_lock  = Hk(LOCK,   C ‖ secret)
refund_lock = Hk(REFUND, C ‖ refund_secret)          (0 when timeout = 0)
```

| Entry (public selector) | Rule |
|---|---|
| LOCK (0) | Creates the record under the terms; without a timeout the refund lock must be 0 |
| CLAIM (1) | With the claim secret; with a timeout `T`, only in a transaction whose window ends before `T` (`not_after ≠ 0`, `not_after < T`) |
| REFUND (2) | With the refund secret; only with a timeout, in a transaction whose window starts at `T` or later (`not_before ≥ T`) |

- A claim and a refund of one record can never both be valid at one height.
- Both locks bind the contract id, so a lock copied into another vault instance does
  not open with the secret (F-28-7).
- A wrong secret yields a transcript the kernel never matches: no proof exists.
- **The vault is not an HTLC (RTW1C-6).** A CLAIM proves knowledge of the secret
  inside the proof and never publishes it: the claim transaction reveals nothing a
  counterparty could use to claim a second, linked vault (on this chain or another).
  So two vaults do **not** make an atomic swap. A swap needs a preimage-revealing
  claim (a function that publishes the secret as its output, giving up that privacy),
  or another design (adaptor signatures, a joint contract); none exists yet (§9).

**The wallet** (`wallet/src/wallet/contracts.rs`):
- It locks with a derived or given claim secret and an optional timeout. It derives
  the refund secret from its keys and the record's `rho` under its own tag,
  `px/wallet/vault-refund/v1` (RTW1C-7; px.md §13.4), and hedges the function blind
  with its PX hedge key (W28-4).
- **Timeouts are multiples of 16** (`VAULT_TIMEOUT_GRANULE`), more than 3 blocks above
  the next block (so a claim can be built outside the expiring-soon margin, §4.3) and
  at most `MAX_VAULT_TIMEOUT_AHEAD` = 2^20 blocks ahead (RTW1C-2).
- **Windows are rounded, not the timeout (RTW1C-2).** A claim built for the next block
  `n` uses `[0, min(T − 1, round_up16(n + 3) + 31)]`; a refund uses
  `[max(T, round_down16(n)), ∞)`. A claim window always ends one below a multiple of
  16, a refund window always starts at a multiple of 16, so a window reveals `T` only
  when the claim is made within about 50 blocks before it or the refund within 16
  blocks after it, where the rounded bound is `T − 1` or `T` itself. The wallet refuses
  to build a claim whose window would end within 3 blocks (RTW1C-4).
- **Before every lock it dry-runs every way out** (RTW1C-8, §6 item 21): CLAIM with
  the secret and, with a timeout, REFUND with its refund secret, on the record's real
  opening, each checked for exit code, prefix, output words and budget.
- **The refund is recoverable from the seed (RTW1C-3).** The terms (claim lock and
  timeout) are stored in the wallet file before the lock is sent, and a refund takes
  them from there (`px_vault_refund_stored`). A wallet restored from its seed rebuilds
  them from the chain even when the record was delivered to the counterparty and the
  claim secret was the counterparty's: the record's `rcm` is derived,
  `H32("px/wallet/vault-rcm/v1", hk_px ‖ u8 network ‖ C ‖ rho)`; the lock's change
  output (to the locker's own address 1, encrypted to it) carries the claim lock in its
  data; the value follows from the lock's inputs, fee and change; and the timeout is
  found by trying every multiple of 16 in a bounded range until the record's
  commitment appears in the lock's block (`Wallet::recover_vault_locks`, run at load
  and before a refund; the range is bounded by `MAX_VAULT_TIMEOUT_AHEAD`, and the test
  `a_restored_locker_recovers_its_timed_lock_and_can_refund` prints the cost of a
  full search). None of this is visible on chain: the change's data is
  inside its commitment and its ciphertext. A record claimed or refunded before the
  restore is recovered as well; its refund is refused by the node (spent nullifier).
- A wallet restored from its seed recovers the claim secret of a vault without a
  timeout that it holds (px.md §13.4).

**Limits** (it remains a demonstration):
- whoever made the claim secret can claim; a swap needs the counterparty to choose the
  secret and hand over only its lock (`vault::lock_call` takes the terms, not the
  secret), and even then two vaults are no atomic swap (above);
- a miner can delay a claim until the timeout passes; leave a margin;
- the caller chooses the new record's `rcm` and writes its ciphertext (PX-F4);
- a claim or refund reveals its window, rounded to 16 blocks; the timeout is revealed
  only near it (above).

## 9. Roadmap

| Phase | Content | Consensus impact |
|---|---|---|
| Tooling (after the trial starts) | A contract SDK (typed `Call` builder that makes foreign approvals and specs unrepresentable, window assertions, a conservation lint, type-tagged data, hedged blinds); a manifest (ABI, output schema, budgets, source hash) and a verifier tool; reference escrow and HTLC contracts with abuse tests (an HTLC needs a preimage-revealing claim, which the vault is not, §8) | None (new deploys only) |
| Second kernel generation, by height | Verifier selection by (epoch, ABI) (§4.2); PX-F4 option B′ (`rcm` derived from a seed and `rho'`); message commitments between the two functions of a call; contract-scoped tags in the nullifier set; user-owned contract records; shape classes | New verifier generation, activated at a height |
| Scale | Recursion (aggregation); a public finalize phase over PX only with evidence of demand | New proof system |

## 10. Prior art

The design follows established private-execution systems where they apply, and
differs where BlackSilk's constraints differ; no claim of novelty is made.
- **Zexe** (Bowe et al., IEEE S&P 2020): records with birth and death predicates over
  the transaction's local data. PX functions see only their own input; the kernel
  enforces the transaction-level rules instead (one approval per input, one specifier
  per output).
- **Aleo**: private transitions proven client-side; `block.height` available only in
  a public finalize scope.
- **Aztec**: private functions on the user's device, a private kernel folding the call
  stack, `expiration_timestamp` bounding inclusion.
- **Zcash**: `nExpiryHeight` (ZIP 203); per-pool turnstiles (ZIP 209); old pools stay
  spendable out (ZIP 211), the model for ABI coexistence.
- **Bitcoin**: `OP_CHECKLOCKTIMEVERIFY` (BIP 65), a script reading a transaction-level
  time bound that consensus checks against the block.
- **Cardano**: "double satisfaction", the output-side mirror of the input-side rule
  (§3).
- **Neptune Cash, Penumbra**: scripts reading a transaction kernel's timestamp through
  its hash; fixed-function actions instead of general contracts.

Sources and the full comparison: dossier 28 (private-contracts-px) §3 and §8,
dossier 20 (px-kernel) §3–§4.
