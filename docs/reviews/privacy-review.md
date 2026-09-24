# Privacy review: private execution (PX) and its integration

Status: **internal review (2026-09-24), not an independent audit.**

**Scope.** Every channel through which a PX transaction, a contract call or a wallet
could reveal more than the protocol intends:
- transaction structure and metadata;
- proofs and execution traces;
- timing;
- contract execution;
- network propagation;
- wallet scanning;
- errors and rejection behaviour.

**Grading.** Each channel is marked:
- **Closed** (by construction, with the test that shows it);
- **Inherent** (public by design, documented to users);
- **Open** (a known residual risk).

The v1 layer (ring signatures, stealth addresses, Dandelion++) is reviewed in AUDIT.md
R3 and R5; only its interaction with PX is covered here.

## 1. What an observer is meant to learn

From a PX transaction, an observer learns exactly:
- **The kind of operation:**
  - deposit (v1 inputs, `bridge_in > 0`);
  - private payment (no v1 inputs, no payouts);
  - withdrawal (clear-amount payouts);
  - contract call (function entries).
- **The public amounts:** `bridge_in`, the payouts, and the fee.
- **For each called function:** its contract, its program and its declared public
  outputs.
- **Two nullifiers, two commitments and two record ciphertexts, always.**

It must **not** learn:
- any private amount;
- which records were spent;
- who received what;
- whether an input or output is a dummy;
- whether a record is a user or a contract record;
- a function's inputs, path or running time;
- which wallet built the transaction.

## 2. Channel-by-channel analysis

### 2.1 Transaction structure and metadata

| Item | Status | Evidence |
|---|---|---|
| Input and output counts | **Closed.** Always 2 nullifiers, 2 commitments, 2 ciphertexts; dummies are indistinguishable (a dummy input has a random nullifier; an empty output goes to a throwaway address with a real ciphertext) | `check_px_structure` requires exactly 2 of each; `px_builder` seals every output (`None` recipients get a random address); `px/tests/kernel.rs` |
| Ciphertext length | **Closed.** Fixed 1,209 bytes | `delivery::CIPHERTEXT_BYTES`, enforced at decode |
| Fee | **Closed for the reference wallet.** Every PX transaction pays `px_standard_fee()`, the fee for the *maximum* PX size, so the fee reveals neither the proof size nor the wallet. Consensus only sets a minimum: other wallets choosing other fees would fingerprint themselves | `px_builder::px_standard_fee`, used by every wallet path |
| Deposit / withdrawal amounts | **Inherent** (containment: the pool must be auditable). Users are told to use round amounts and to wait between deposit and withdrawal; the CLI prints the reminder | docs/px.md §12 |
| v1 inputs of a deposit | Same guarantees as a v1 transfer: ring of 16, gamma decoy selection | AUDIT.md R3 |
| Anchor | **Closed for the reference wallet** (fixed 2026-09-24, see §3 P-2). The wallet anchors at the last multiple-of-16 height, so all wallets in the same 16-block window use the same root | `wallet/src/px.rs::anchor_height`; e2e test |
| Payout outputs | One-time stealth keys with context `H(nullifiers ‖ key images)` (unique): unlinkable to the recipient's address | `crypto::stealth::px_context`; `tx/tests/px_consensus.rs` |
| Contract ids | **Inherent.** A call reveals which contract and program ran (the verifier needs the program). The deployer is hidden behind a v1 ring signature | docs/px.md §11.2 |

### 2.2 Proof size and execution traces

| Item | Status | Evidence |
|---|---|---|
| Table heights (the proof's shape) | **Closed.** The kernel and every registered function have public budgets; the prover pads to them and the verifier accepts exactly that shape. Before this change, heights leaked a function's execution length (for example, how many loop rounds a secret took) | `zkvm/tests/multi.rs::a_budget_fixes_the_shape_whatever_the_secret` (the shapes differ unbudgeted and are identical budgeted); `budgets_are_enforced_by_prover_and_verifier`; `px/tests/unified.rs::record_kinds_are_not_revealed_by_trace_heights`; `px/tests/kernel.rs::successful_executions_have_identical_trace_heights` |
| Budget exhaustion | **Closed.** An over-budget execution cannot be proven: the prover returns `BudgetExceeded` and nothing is broadcast. The kernel budgets exceed measured use by about 6%; a test requires ≤ 95% use for every tested witness | `px/tests/unified.rs::budgets_leave_headroom` |
| Proof byte length | **Closed in theory, not bit-exact.** The proof encoding (`postcard`) writes field elements as varints, so the byte length varies by a few KB between proofs of one shape. The length is a function of the proof, and the proof is zero knowledge (hiding FRI and Merkle commitments), so it is simulatable and carries no witness information. It is not constant, however: a fixed-width encoding would remove the argument's dependence on zero knowledge (open item P-5) | analysis only |
| Opened values | Zero knowledge of Plonky3's hiding FRI (`HidingFriPcs`, `MerkleTreeHidingMmcs`) | assumption A-ZK, docs/reviews/zk-security-review.md §2; independent review required |
| Public outputs of functions | **Inherent**, and chosen by the contract author: whatever a function writes to its public output is public. Transcripts bound to the kernel (`io_hash`) are hiding (a random blind) | docs/px.md §7.2 |
| Kernel control flow | Constant work: both nullifier forms, both record kinds and every output check run for every input | `successful_executions_have_identical_trace_heights` |

### 2.3 Timing

| Item | Status | Notes |
|---|---|---|
| Proving time | Local to the wallet; proportional to the fixed shape (about 42 s transfer, 51 s with a function) | Not observable remotely, except through the submission time (below) |
| Verification time at nodes | No secrets are involved: the verifier's inputs are public | A remote timing probe learns nothing private |
| Submission time vs. receipt time | **Open (user behaviour).** Spending a record right after receiving it links the two in time. The canonical anchor makes a record spendable only after the next multiple-of-16 height, which blurs this slightly but does not prevent it | docs/px.md §12 |
| Wallet sync timing | Every wallet downloads the same data (all blocks, all commitments) | §2.6 |

### 2.4 Contract execution

- **Function inputs and paths:** hidden by zero knowledge and the fixed shape (§2.2).
- **Contract records:**
  - owned by the contract id, indistinguishable from user records on chain (same
    commitment form, same ciphertext);
  - spent only with the approval of one of its contract's functions.
- **Registry lookups:** public and identical for everyone; the node learns nothing from
  a verification that it would not learn from the transaction itself.
- **Open (P-4):** contract-record plaintexts must reach the parties that act on them,
  and no distribution protocol exists yet (docs/px.md §10). A contract whose parties
  exchange plaintexts off chain inherits that channel's privacy.

### 2.5 Network propagation

| Item | Status | Evidence |
|---|---|---|
| Origin of a transaction | PX and deploy transactions take the same Dandelion++ stem as v1 transfers (stem conflicts keyed by key images **and** nullifiers) | `p2p/src/net.rs::stem_keys`; `p2p/tests/network.rs` |
| Relay volume | PX relays are rate-limited per peer (0.2/s, burst 4) and globally (2/s, burst 10). Honest traffic is below both. Under a flood, a node delays PX relays, which does not reveal an origin | `p2p/src/net.rs::px_within` |
| Submission through a remote node | **Inherent.** The node sees the submitter's IP. Users are told to run their own node or use Tor | docs/px.md §12 |
| Stem probing | **Open, low (P-6).** A peer that already knows a nullifier (its own transaction) can test whether a node holds a conflicting stem transaction. This is the known Dandelion++ property and needs knowledge of the spent record | docs/p2p.md §8 |

### 2.6 Wallet scanning

- **Closed.** The wallet:
  - downloads whole blocks (`/blocks`) and the complete, ordered commitment list
    (`/px/commitments`, paged from its current count);
  - trial-decrypts every ciphertext locally;
  - resolves positions locally.
- It never sends the node a record, position, nullifier, key or address. The only
  wallet-specific values the node sees are its sync height and commitment count,
  which every wallet at the same height sends alike.
- **Evidence:**
  - `wallet/src/px.rs` (no other node calls);
  - `wallet/src/node.rs` (the whole `NodeApi` surface);
  - `wallet/tests/e2e.rs::private_funds_move_over_rpc`.
- The wallet checks the node's tree root against its own. A lying node can stall the
  wallet but cannot make it build a transaction against a false root, which consensus
  would reject anyway (PX1).

### 2.7 Error messages and rejection behaviour

| Item | Status |
|---|---|
| Kernel exit codes (2–16) | Only in the prover's interpreter, before proving. They are never broadcast; an invalid witness produces no transaction (`px/tests/proof.rs::an_invalid_witness_is_refused_before_proving`) |
| Node RPC rejection reasons | Returned only to the submitter, over a connection it opened. Every rule is a function of public data (chain state, the transaction) |
| Proof failure | One variant, `TxError::PxProof`, for decode and verification failures alike (no oracle on which check failed) |
| Peer scoring | Invalid proofs are scored as stateless misbehaviour: once the anchor (PX1) and registry (PX3) checks pass, the statement does not depend on the receiver's pool, so an honest peer never relays one. Stateful failures (a nullifier spent meanwhile, an anchor expired) are not penalised, so peers cannot be tricked into disconnecting honest relayers |

## 3. Findings of this review

| # | Finding | Resolution |
|---|---|---|
| P-1 | **Trace heights leaked execution length.** Table heights were the next power of two above each execution's use. A function's secret-dependent loop, or a kernel path, could change the shape and so the proof size (shown by the unbudgeted half of `a_budget_fixes_the_shape_whatever_the_secret`) | Fixed shapes: public budgets for the kernel and every registered function, enforced by prover and verifier (ZK-F14) |
| P-2 | **The anchor revealed the wallet's sync time.** The wallet used the tip root at its sync height, so the anchor told observers how recent the wallet's view was, a per-wallet fingerprint | Canonical anchor: the last multiple-of-16 height. Wallets in the same window share one anchor |
| P-3 | **Wallets marked spent v1 key images only for transfers**, so a v1 output spent by a PX deposit or a deploy stayed "unspent" in the wallet and could be selected again. The result was a rejected transaction and a correctness bug, with a privacy side effect: a retry reveals the same ring member twice | Key images are collected from every transaction kind (`Transaction::key_images`) in wallets and test harnesses |
| P-4 | No contract-record distribution protocol | Open (docs/px.md §10) |
| P-5 | Proof length is not constant (varint encoding) | Open, low: covered by zero knowledge (§2.2). A fixed-width encoding is a recommended hardening before production |
| P-6 | Dandelion++ stem probing with known nullifiers | Open, low; inherent to the design |
| P-7 | Uniform fees are a wallet convention, not a consensus rule | Open, low. Making the standard fee exact in consensus would remove the fingerprint and needs an owner decision |

## 4. What is not claimed

- Anonymity sets are as large as the PX pool's *usage*; on a small testnet they are
  small, and timing analysis is correspondingly strong.
- The zero-knowledge property of Plonky3's hiding mode, and the delivery combiner, have
  not been reviewed independently.
- Network-level adversaries (ISP, global passive) are outside what Dandelion++
  protects against.
