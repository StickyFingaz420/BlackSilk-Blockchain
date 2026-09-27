# PX-F4 and PX-F5: analysis for the owner's decision

Status: **analysis only, 2026-09-27. Nothing has been changed.**
- Both findings concern the PX kernel, whose program id is pinned in consensus
  (`px/kernel.id`). Changing either one changes that id, which is a **consensus
  change** needing a new testnet identity.
- Internal analysis only; no external audit.

**Sources** (verified in the code on 2026-09-27):
- `px-core/src/kernel.rs` (input checks around line 264, output checks around 336);
- `px-core/src/call.rs` (`OutSpec`, `io_hash`);
- `px-core/src/record.rs`;
- docs/px.md §3, §7, §13.

## 1. Background: how contract functions shape outputs

A PX transaction has two outputs. A called contract function may **specify** an
output slot as `(owner, contract, value, data)`, and the kernel checks that the output
has exactly those fields.

The rest of the output's opening is not specified by the function:
- `rho` is derived by the kernel: `Hk(RHO, nf_0 ‖ j)`;
- `rcm`, the commitment randomness, is chosen by the **caller**, the party that builds
  and proves the transaction;
- the output's ciphertext (docs/px.md §6), which delivers the opening to its
  recipient, is also written by the caller. It is not proven to be correct.

Spending a record requires its full opening (`rcm` included): the spender rebuilds
`cm` inside the proof.

There are two kinds of output:
- **User records** (`contract = 0`) are spent with the owner's key.
- **Contract records** (`contract ≠ 0`) have no key: they are spent by calling a
  function of the contract that approves them. Anyone with the opening can make that
  call.

## 2. PX-F4: who determines the randomness (`rcm`) of contract outputs?

### Current design
The caller chooses `rcm` for every output, including outputs a function specified. The
function neither sees nor fixes it: `io_hash` covers `(owner, contract, value, data)`
only.

### The concern
Only the caller then knows the opening of a function-specified output, unless it
delivers it (a correct ciphertext or an off-chain share, docs/px.md §13).
- **Contract state:** a caller that creates a new state record of a shared contract
  can keep its opening secret, or deliver garbage.
  - No other party can then open the record, so no other party can spend or update
    it.
  - The contract's state, and any value it holds, is **locked**.
  - This is a denial of service against every other participant, at the cost of one
    transaction.
- **Payouts to third parties:** if a function pays a user who is not the caller, the
  caller can make that payout unopenable. The value is then lost to everyone,
  including the caller.
- **Not affected:**
  - soundness: no value is created or stolen, and the balance and the function's
    authorization are enforced;
  - privacy: `rcm` stays random and secret, which keeps commitments hiding.

### Impact on what exists today
- The only contract is the demonstration vault. In it, the locker creates the record
  for a claimer, and the claimer pays itself.
- A locker who withholds the opening only fails to pay the claimer, which it could
  equally do by not locking at all. The vault's other limitations (no timeout, no
  refund, the locker can claim too) are larger.
- So on today's testnet PX-F4 is a **trust assumption of multi-party contracts that do
  not exist yet**, not an exploitable flaw.

### Alternatives

| Option | What changes | Advantages | Disadvantages |
|---|---|---|---|
| **A. Keep; document** | Nothing (docs) | No consensus change; privacy unchanged | Multi-party contracts cannot be safe against a griefing caller; contract authors must know it |
| **B. The function fixes `rcm`** | `OutSpec` gains `rcm`; `io_hash` covers it; the kernel checks it; function programs output it (the vault too) | The function can derive `rcm` from data every authorized party knows (for the vault, from the secret), so openings need no delivery, and a caller cannot make state unopenable. Privacy is kept if the function derives `rcm` from secret material | Kernel, call format, vault program, wallet and prover change; new kernel and vault ids; a contract that derives `rcm` from **public** data would make its records' commitments guessable (a privacy trap for contract authors, to be documented and linted) |
| **C. The kernel derives `rcm`** (e.g. `Hk(RCM, nf_0 ‖ j ‖ spec)`) | Kernel only | No delivery needed | **Rejected: breaks privacy.** `nf_0` is public, so `cm` becomes a deterministic function of `(owner, contract, value, data)`, and low-entropy values can be brute-forced from `cm` |
| **D. Prove the ciphertext** (verifiable encryption of the opening to a specified key) | Kernel proves the delivery encryption | Delivery guaranteed | ML-KEM and ChaCha20 inside the zkVM: very large proofs and proving time; research-level; not feasible now |

### Implications of B, the only candidate fix
- **Consensus:** new kernel id; new `io_hash` layout; new vault id (the vault's
  registration would be redeployed on the new network).
- **Privacy:** unchanged if functions derive `rcm` from secret data.
  - Needs a documented rule, and a tooling check, that `rcm` must never be derived
    only from public values.
  - P-5 (proof-length campaign) must be re-run on the new layout.
- **Wallet:** the builder takes `rcm` from the function's output instead of drawing
  it. Recovery gets easier for contract records whose `rcm` is derivable.
- **Contracts:** functions gain one output field; existing function programs must be
  rebuilt.
- **Testnet identity:** yes, a new one (v3).
- **Effort, estimated:**
  - kernel, call and prover changes plus tests: about a day;
  - vault and wallet: about a day;
  - then the full suite, proofs, P-5, a review pass and a reset rehearsal.

### Can it remain a documented v1 limitation?
**Yes, for the controlled trial**, where the vault is the only contract. It must be
documented as a trust assumption for any multi-party contract before third-party
contracts are encouraged (docs/px.md §12, docs/contracts.md).

### Recommendation
- **Keep A for the seven-device trial.**
- **Implement B together with the transparent-contract work**, before contracts
  beyond the demonstration are supported. At that point the contract call format
  changes anyway.
- If you prefer one network-identity change only, B can be bundled with PX-F5 and the
  platform-neutral kernel build (§4) into a single v3 before the trial.
  - That delays the trial by roughly the effort above plus re-validation.

## 3. PX-F5: should contract outputs be forced to have no owner?

### Current design
- **Spending a contract record** (input, `contract ≠ 0`): the kernel rebuilds it with
  `owner = 0`, whatever the witness says (`kernel.rs`: `owner = select(is_contract, 0,
  user_owner)`).
- **Creating one** (output, `contract ≠ 0`): the kernel requires a function of that
  contract to specify it, and checks the fields match that specification. It does
  **not** require `owner = 0`.

### The concern
- A contract output with `owner ≠ 0` has a commitment that no spend can ever reproduce:
  - as a contract input it is rebuilt with `owner = 0`, giving a different `cm`;
  - as a user input it is rebuilt with `contract = 0`, also a different `cm`.
- The record, and its value, are therefore **permanently unspendable: burned**.
- **Who can cause it:**
  - only a function of the contract, which specifies the output, can create such a
    record;
  - so it happens only if a contract's code has a bug, or deliberately lets a caller
    choose the owner of its state records;
  - a third party cannot make a correct contract do it.
- **Not affected:** soundness and privacy. No inflation (burned value stays counted in
  the PX pool as backing and can never be withdrawn), no theft, and no information
  leak.
- **Today:** the vault specifies `owner = 0` for its contract records (its tests spend
  them).

### Alternatives

| Option | What changes | Advantages | Disadvantages |
|---|---|---|---|
| **A. Keep; document** | Docs: contract authors must set `owner = 0` for contract records | No consensus change | A footgun for contract authors: a bug burns user funds silently |
| **B. The kernel enforces `owner = 0` for contract outputs** | One check in the output loop (reject `contract ≠ 0 ∧ owner ≠ 0`) | Removes the footgun at the root; states the invariant the input side already assumes; tiny change, constant work kept | New kernel id; new testnet identity |
| **C. Tooling check only** (wallet or deploy lints the function's specs) | Wallet/host code | No consensus change | Does not protect against another client; a lint, not a rule |

### Implications of B
- **Consensus:** new kernel id (v3 identity).
- **Privacy:** none. The check is on private witness data and does not change the
  constant-work shape, but P-5 is re-run as a routine check.
- **Wallet:** none (it never builds such outputs).
- **Contracts:** a buggy contract's transaction fails instead of burning funds.
- **Effort:** small: one kernel check, tests (mutation and a native/guest
  differential), a rebuilt and reproduced kernel, then the usual re-validation.

### Can it remain a documented v1 limitation?
**Yes.** The only contract is correct in this respect, and the consequence is limited to
funds entrusted to a buggy contract.

### Recommendation
- **B**, bundled with any other kernel change so the network identity changes once.
- If no other kernel change is approved before the trial, keep A for the trial and do
  B with the next kernel change.

## 4. Related: the kernel binary embeds a build path

- The consensus-pinned `px/kernel.elf` contains an absolute Windows source path from
  its panic messages (zkvm/guests/README.md).
- It is reproducible today, on a Windows host with path remapping, and CI checks it.
- A platform-neutral kernel changes the data segment and so the id: also a kernel
  change.

## 5. Summary for the decision

| | Current state | Exploitable today? | Fix | Consensus / new identity | Recommendation |
|---|---|---|---|---|---|
| PX-F4 (caller-chosen `rcm`) | Caller picks `rcm` of function-specified outputs | No (only the demonstration vault; affects future multi-party contracts) | B: the function fixes `rcm` | Yes / yes | Document for the trial; implement B with the contract work (or bundle into one v3) |
| PX-F5 (contract outputs may have an owner) | Not enforced; such records are burned | No (vault is correct); a contract bug could burn funds | B: the kernel enforces `owner = 0` | Yes / yes | Bundle with the next kernel change |
| Kernel build path | Reproducible on Windows only | No | Neutral rebuild | Yes / yes | Bundle with the next kernel change |

**Your options:**
1. **No kernel change before the trial:**
   - document PX-F4 and PX-F5 as v1 limitations;
   - the trial runs on the current v2 identity;
   - one kernel change later bundles PX-F4 B, PX-F5 B and the neutral build.
2. **One kernel change before the trial:** PX-F5 B plus the neutral build (small);
   PX-F4 later.
   - Needs a v3 identity now and v4 later.
3. **One complete kernel change before the trial:** PX-F4 B, PX-F5 B and the neutral
   build together (v3).
   - The largest delay, but the trial then tests the kernel intended for v1.

**My recommendation is option 3 if the trial should test the kernel that v1 will
ship.** Option 1 if the trial should start soon and mainly test the node, P2P, mining
and operations. I will not change the kernel until you decide.
