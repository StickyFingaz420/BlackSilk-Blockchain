# Privacy review: private execution (PX) and its integration

Status: **internal review (2026-09-24, updated 2026-09-25 for contract tooling, record
distribution and the fee rule), not an independent audit.**

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
| Input and output counts | **Closed.** Always 2 nullifiers, 2 commitments, 2 ciphertexts; dummies are indistinguishable (a dummy input has a random nullifier; an empty output goes to a throwaway address with a real ciphertext) | the transaction format fixes exactly 2 of each (`PxTx`'s arrays, enforced by the strict decoder); `px_builder` seals every output (`None` recipients get a random address); `px/tests/kernel.rs` |
| Ciphertext length | **Closed.** Fixed 1,241 bytes, the same for user and contract records (the plaintext always carries the contract field) | `delivery::CIPHERTEXT_BYTES`, enforced at decode; `px/tests/delivery.rs::contract_records_reach_the_addressed_party` |
| Fee | **Closed (consensus).** Every PX transaction must pay exactly `PX_STANDARD_FEE`, the per-byte fee of the *maximum* PX size. A different fee is invalid, so no wallet can fingerprint itself through its fee (P-7) | `check_px_structure` (`TxError::PxFeeNotStandard`); `tx/tests/px_consensus.rs` (±1 refused) |
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
| Proof byte length | **Closed; measured; not constant.** Field elements are written fixed-width (Plonky3 serializes them as 4-byte arrays in binary formats), so values never change the length. The length varies only in the Merkle opening proof, whose pruned query paths contain fewer nodes where queries share ancestors. The query positions are public (every verifier recomputes them from the proof), drawn by Fiat–Shamir over hiding commitments, so their distribution is the same for every witness. See P-5 | `px/examples/proof_lengths.rs`: 6 transfer proofs with different witnesses, 2,029,768–2,046,856 bytes (0.84% spread); the non-opening part was 129,898 bytes in all six |
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
- **Contract-record distribution (P-4, resolved; docs/px.md §13):**
  - **On chain:** the creator addresses each contract output's ciphertext to the party
    that will act on it. The ciphertext is indistinguishable from any other.
  - **Off chain:** shares are sealed to the recipient's PX address, so the channel
    carrying them learns nothing but their existence.
  - **What a recipient learns:** the record's opening. For the vault this lets anyone
    who also knows the secret claim it. Choosing whom to tell is part of the contract's
    trust model, not a leak.
- **Function calls:** a call reveals the contract, the program and the function's
  public outputs (for the vault, the selector: LOCK or CLAIM). The time between a LOCK
  and a CLAIM of the same contract is visible to anyone watching it (inherent, P-8).
- **Unsolicited records:** anyone can deliver real contract records to an address.
  - They cost the sender a full PX transaction each.
  - They can never move the recipient's funds; contract records are not counted as
    funds.
  - The recipient's wallet only lists them, and acts on none unless the user does.

### 2.5 Network propagation

| Item | Status | Evidence |
|---|---|---|
| Origin of a transaction | PX and deploy transactions take the same Dandelion++ stem as v1 transfers (stem conflicts keyed by key images **and** nullifiers) | `p2p/src/net.rs::stem_keys`; `p2p/tests/network.rs` |
| Relay volume | PX relays are rate-limited per peer (0.2/s, burst 4) and globally (2/s, burst 10). Honest traffic is below both. Under a flood, a node delays PX relays, which does not reveal an origin | `p2p/src/net.rs::px_rate` |
| Submission through a remote node | **Inherent.** The node sees the submitter's IP. Users are told to run their own node or use Tor | docs/px.md §12 |
| Stem probing | **Open, low (P-6).** A peer that already knows a nullifier (its own transaction) can test whether a node holds a conflicting stem transaction. This is the known Dandelion++ property and needs knowledge of the spent record | docs/p2p.md §8 |

### 2.6 Wallet scanning

- **Closed.** The wallet:
  - downloads whole blocks (`/blocks`), the complete, ordered commitment list
    (`/px/commitments`) and the complete registration list (`/px/contracts`), each
    paged from its current count;
  - trial-decrypts every ciphertext locally;
  - resolves positions locally.
- It never sends the node a record, position, nullifier, key or address. The only
  wallet-specific values the node sees are its sync height and its commitment and
  registration counts, which every wallet at the same height sends alike.
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
| P-4 | No contract-record distribution protocol | **Resolved** (2026-09-25): designated on-chain delivery, the creator's copy, off-chain sealed shares; wallet commands and an end-to-end test (docs/px.md §13) |
| P-5 | Proof length is not constant | **Supported by measurement and reasoning; independent review pending** (§3a, 2026-09-25). The earlier text blamed a varint encoding of field elements. That was wrong: they are fixed-width. A fixed-width codec was built and measured: it gained nothing and made proofs 4% larger, so it was reverted. The remaining variation (0.84% measured) comes only from pruned Merkle paths, a function of the public query positions, distributed identically for every witness. A constant length would need padding each proof to a per-shape worst case computed from Plonky3's pruned format, which costs size and is fragile across upgrades, for no privacy gain. Not done; reconsider if a reviewer disagrees |
| P-6 | Dandelion++ stem probing with known nullifiers | Open, low; inherent to the design. It needs a nullifier the prober already knows, which means its own transaction or one it relayed on the stem |
| P-7 | Uniform fees are a wallet convention, not a consensus rule | **Resolved** (2026-09-25): the fee of every PX transaction is exactly `PX_STANDARD_FEE` in consensus. Side effect: fee-per-byte ordering ranks larger PX transactions (contract calls) lower under congestion (docs/px.md §11.5) |
| P-8 | Contract calls reveal which contract and function ran, and so the timing between related calls (such as a LOCK and its CLAIM) | Inherent: the verifier needs the program. Documented to users (docs/px.md §12) |

## 3a. P-5 in detail: why proof-length variation carries no witness information

Status: **supported by measurement and reasoning; not independently verified.** The
claim is kept open for external review (§4).

### Claim

For a fixed statement shape (the same programs and budgets), the encoded length of a
PX proof is a deterministic function of the shape and of the FRI query positions
`Q`. `Q` has the same distribution whatever the witness. So the length has the same
distribution for every witness, and observing it tells nothing about the witness.

### 1. Measured (this machine, BS-ZK-2, Plonky3 0.7.0)

- **Everything but the Merkle authentication data has a fixed length.**
  `px/tests/proof.rs::a_private_transfer_proves_verifies_and_applies_once` splits a
  deposit proof and a payment proof into every component and asserts that all
  components except the Merkle authentication data (pruned input paths, and the FRI
  layers' openings) have identical encoded lengths. Both were 1,663,016 bytes; the
  authentication data was 369,024 and 378,752 bytes. A Plonky3 change that made any
  other part variable would fail this test.
- **The spread is small:** 6 transfer proofs with different witnesses were
  2,029,768–2,046,856 bytes (0.84%; `px/examples/proof_lengths.rs`).
- **Campaign across witness classes and execution paths (2026-09-25; raw data in
  `docs/evidence/p5-2026-09-25/`):** 260 proofs, the classes interleaved.

  | Shape | Class | n | Mean bytes | sd | Min | Max |
  |---|---|---|---|---|---|---|
  | transfer | deposit (two dummy inputs, bridge-in) | 50 | 2,037,703 | 4,349 | 2,026,696 | 2,046,600 |
  | transfer | payment, two real inputs | 50 | 2,037,612 | 4,132 | 2,028,872 | 2,045,384 |
  | transfer | payment, one real input and a dummy | 50 | 2,038,051 | 4,587 | 2,026,696 | 2,046,120 |
  | transfer | withdrawal (bridge-out) | 50 | 2,037,433 | 4,369 | 2,028,072 | 2,049,384 |
  | vault | LOCK (a user record into a contract record) | 30 | 2,487,709 | 4,559 | 2,479,254 | 2,495,030 |
  | vault | CLAIM (a contract record paid out) | 30 | 2,488,396 | 4,240 | 2,479,990 | 2,496,278 |

  - **Pairwise tests** (20,000 permutations each, all pairs within a shape): every
    difference of means is between 91 and 687 bytes, with p = 0.49–0.92. The
    Kolmogorov–Smirnov p is 0.55–0.97.
  - **No test indicates a dependence** of length on the class.
  - **Every** non-authentication part was byte-identical across all 200 transfer
    proofs and across all 60 vault proofs (asserted by the tool).
- **Earlier, smaller check (superseded by the campaign):**
  `px/examples/proof_length_distribution.rs`, 10 deposits and 10 payments,
  interleaved: deposits mean 2,037,998 bytes (sd 4,821, range
  2,033,288–2,045,544), payments mean 2,037,218 bytes (sd 4,168, range
  2,030,984–2,041,928). The difference of means is 781 bytes, well inside one standard
  deviation. A permutation test (20,000 relabellings) gives **p = 0.70**: no evidence
  that length depends on the class. This is consistent with the claim, but with 10
  proofs per class it could not detect a dependence much smaller than the spread
  (§5).
- **Field elements are always 4 bytes.** Plonky3's `MontyField31` serializes as a
  4-byte array in binary formats (`p3-monty-31` `Serialize`), so values never change
  the length.

### 2. Reasoning (from the Plonky3 0.7.0 source)

1. **Where positions come from** (`p3-fri/src/prover.rs`, lines 95–160):
   - after every commitment and the FRI commit phase, the prover grinds a
     proof-of-work nonce (`challenger.grind(query_pow_bits)`);
   - it then draws `num_queries` = 108 positions, each as the low bits of a field
     element squeezed from the Fiat–Shamir challenger (`sample_bits`);
   - nothing is observed between the draws.
2. **How positions become lengths:**
   - each committed tree is opened at the positions shifted right by the height
     difference (`open_inputs`);
   - each FRI layer is opened at the positions shifted by its folding
     (`answer_queries`);
   - `open_multi_batch` sends each distinct authentication node once, so its size is
     the number of distinct nodes in the union of the paths. That depends only on the
     set of shifted positions and the tree heights, not on the values stored;
   - every other part (opened rows, salts, sibling values, commitments,
     out-of-domain values, final polynomial, grinding nonces) has a size fixed by the
     shape (measured above).
3. **Why `Q` does not depend on the witness:**
   - The challenger is a duplex sponge over the Poseidon2 permutation. Model it as a
     random oracle (A1 below).
   - Its outputs are then uniform and independent of what it absorbed, even though
     the absorbed transcript (commitments, opened values) differs between witnesses.
   - Grinding picks the first nonce whose next output bits are zero. Conditioned on
     that event, the following outputs, the positions, are still uniform.
   - So `Q` is drawn from one fixed distribution, the same for every witness and
     every statement of the shape.
4. **Bias of `sample_bits` does not matter.** It takes the low bits of an element of
   BabyBear (p = 2^31 − 2^27 + 1). Since p is not a power of two, the low bits are
   very slightly non-uniform. The bias is a property of the field only, the same for
   every witness, so it creates no dependence on the witness.
5. **This argument does not need zero knowledge.** It needs only the random-oracle
   behaviour of the challenger, which soundness already assumes. It is stronger than
   the earlier argument ("the proof is zero knowledge, so its length is simulatable"),
   which also holds.

### 3. Assumptions

| # | Assumption | Also needed for |
|---|---|---|
| A1 | The Poseidon2 duplex challenger behaves as a random oracle (Fiat–Shamir) | Soundness of every proof |
| A2 | The honest prover publishes the first proof it computes. A **malicious** prover can re-prove until the length encodes chosen bits: a covert channel from its own wallet, which could leak its user's data by any other means anyway | — |
| A3 | Plonky3's proof layout is as in 0.7.0: only pruned paths vary | Pinned by the regression test above |

### 4. What could invalidate it

- **A Plonky3 change** that makes some part's size depend on values: for example,
  compressing zero columns, variable-length encodings of opened values, or pruning
  that depends on digest values. **Guard:** the regression test fails if any
  non-authentication part differs between the two witnesses. It must be re-run on
  every upgrade, together with the distribution measurement.
- **A change of query sampling**, for example positions derived partly from
  witness-dependent data outside the challenger. **Guard:** only by code review on
  upgrade.
- **The serialization format** (postcard): vector lengths are varints, but they count
  elements whose number is fixed by the shape or by `Q`. Switching formats needs the
  regression test again.
- **Different shapes have different lengths.** Calls with different functions or
  budgets produce different proof sizes. That is not a leak: the functions and budgets
  are public in the transaction.

### 5. Limitations

- **Statistical power.** With 50 proofs per class and a spread of about 4.4 KB, the
  tests would detect a class difference in mean length of about 2.5 KB (0.57 standard
  deviations; 80% power, 5% level). A smaller, systematic dependence would go
  undetected. The regression test's check, that every non-authentication part is
  identical, is exact rather than statistical, and it covers everything but the
  authentication data.
- **The classes tested:** four transfer paths and two vault functions. Other
  contracts' functions have other shapes; the argument applies to them by the same
  reasoning, but they are not measured.
- **The reasoning is internal:** it has not been independently reviewed (see below).
- **The length is not constant.** The claim is that it is uninformative, not that it
  is fixed.

### 5a. What proof-length variation could reveal

- **Within one shape, nothing about the witness.**
  - The varying part is the authentication data, whose size is a function of the
    query positions.
  - The positions are recomputable by anyone from the proof itself, so the length
    reveals nothing that the public proof does not already contain.
  - Under A1, they are distributed identically for every witness.
- **Across shapes, which shape was used,** and that is public anyway: the called
  functions (and so the budgets) are listed in the transaction. A plain transfer
  (about 2.04 MB) and a vault call (about 2.49 MB) differ by design.
- **Under a malicious prover (A2):** up to a few bits chosen by the prover, by
  re-proving until the length matches. That is a covert channel from the prover's own
  wallet, not a leak of anyone else's data.

### 5b. Stronger mitigations considered

| Option | Effect | Cost | Assessment |
|---|---|---|---|
| **Pad to a fixed per-shape length, re-proving on overflow** | Constant length. The target is set above the observed spread (for example mean + 6 sd, about 26 KB or 1.3% above the mean); a proof over it is re-proved with fresh randomness | ~1.3% size (*estimate*); a rare extra proof (probability negligible at 6 sd if the tail is Gaussian, not measured); **a new consensus rule** fixing the proof field's length per shape; a target for every shape, including every contract function's budgets | Practical for the fixed kernel shapes. For arbitrary contracts it needs a per-shape formula, or a target registered with each function |
| **Pad to the guaranteed worst case** | Constant length, no re-proving | A per-shape bound on distinct authentication nodes, derived from Plonky3's pruning, tree heights and folding schedule, to recheck on every upgrade. Size cost not measured (the worst case is well above typical) | Strongest, but ties consensus to Plonky3 internals |
| **Unpruned Merkle openings** | Constant structure | Much larger proofs: pruning saves the shared path prefixes of 108 queries | Rejected: proof size is the main open problem |
| **Pad to fixed buckets** (for example multiples of 64 KB) | Hides most of the spread | Proofs near a bucket edge still vary | Weaker; not recommended |

**Decision for now:** no padding. **Deferred, with this reason:**
- the evidence (exact identity of every non-authentication part, reasoning from the
  source, a 260-proof campaign) shows no information in the length;
- every constant-length option adds a consensus rule and a size cost.

The owner may choose the first option after the independent review.

### 6. What would increase confidence

1. **An exact per-proof check:** replay the verifier's transcript to recover `Q`,
   compute the expected number of distinct authentication nodes, and compare with the
   actual size, proving length = f(shape, Q) proof by proof. Not implemented (it
   needs hooks into Plonky3's verifier).
2. **A larger campaign:** the 260-proof campaign above covers six classes. Thousands
   of proofs per class would detect differences below 1 KB.
3. **Independent review** of this argument by someone familiar with Plonky3's FRI,
   together with the zero-knowledge review (security review §9).
4. **A constant length**, if a reviewer requires it: pad every proof to a per-shape
   worst case. That costs about 1–2% of the proof (*estimate*: roughly the measured spread) and a bound derived from Plonky3's
   pruned format.

## 4. What is not claimed

- Anonymity sets are as large as the PX pool's *usage*; on a small testnet they are
  small, and timing analysis is correspondingly strong.
- The zero-knowledge property of Plonky3's hiding mode, and the delivery combiner, have
  not been reviewed independently.
- Network-level adversaries (ISP, global passive) are outside what Dandelion++
  protects against.
