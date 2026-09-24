# BlackSilk Private Execution (PX): Zero-Knowledge Architecture

Status: **v0.3.**
- PX-0 (evaluation) is complete, and the proof system is **decided**: §9.2, §15.
- The zkVM, the kernel with private records and nullifiers, and the unified proof of
  contract functions and kernel are implemented and tested ([`px.md`](px.md); AUDIT.md
  R8). The internal security review is `reviews/zk-security-review.md`. Nothing is
  production-ready before independent review.
- The zkVM is specified in [`zkvm.md`](zkvm.md).
- Nothing here is consensus until activated.

This document fixes the architecture, interfaces and security requirements of private
contract execution.

Choices that depend on measurements are recorded as **decision records (DR)**. Each
has alternatives, a recommendation, and a decision gate in Phase PX-0 (§15), where
candidates are benchmarked and reviewed before any consensus code is written. Numbers
marked *target* are requirements to be measured, not claims.

It builds on:
- [`transactions.md`](transactions.md): the payment layer;
- [`contracts.md`](contracts.md): v1 confidential contracts;
- [`reviews/contracts-crypto-review.md`](reviews/contracts-crypto-review.md).

---

## 1. Problem and goals

**What v1 cannot do.** v1 confidential contracts (contracts.md) hide *who* acts and
*how much* moves, but their logic and state are public. A contract can reason about
hidden amounts only through predicates the caller proves: ranges, equalities, reveals.
It cannot, for example:
- compute an auction winner from sealed bids without revealing them;
- keep a private order book;
- evaluate a hidden credit score;
- hold private state.

**Goal.** Contracts whose functions run over **hidden inputs, hidden state and hidden
amounts**. The chain verifies a zero-knowledge proof that the function ran correctly,
and learns only what the function deliberately makes public.

**Requirements:**

| # | Requirement |
|---|---|
| R1 | **Privacy:** proofs are zero-knowledge. Nothing about private inputs, records or amounts leaks beyond the declared public outputs. |
| R2 | **Soundness:** no one can create value, spend a record twice, spend without authorization, or claim a false function result, except with negligible probability under stated assumptions. |
| R3 | **Transparent setup:** no trusted setup ceremony and no toxic waste. |
| R4 | **Long-term security:** privacy should survive a future quantum adversary wherever technically possible. Soundness should not rest on DL alone. |
| R5 | **Pure Rust:** prover, verifier, circuits and SDK are Rust. No C/C++, no FFI. GPU acceleration, if ever used, is optional and outside consensus. |
| R6 | **Integration:** private functions are part of the same contracts as v1 public code. Their results enter the v1 VM as verified *facts*, exactly like v1 claims. |
| R7 | **Containment:** a soundness failure in the ZK system must not be able to inflate BLK beyond a publicly known bound. |
| R8 | **Client-side proving:** users prove on their own device. Private witnesses are never sent to a third party. |
| R9 | **Upgradeability:** proof systems and parameters can be replaced at activation heights without migrating records. |
| R10 | **Assurance:** a formal statement of every circuit, constraint-level negative testing, independent verifier implementation, and at least two external audits before mainnet. |

**Non-goals:**
- Hiding which contract a transaction interacts with. This may come later, through
  private contract identities (§14, PX-3+).
- Hiding transaction timing or network origin; that is the P2P layer's job.
- Trusted hardware (TEE / SGX) of any kind.

---

## 2. Threat model

**Adversary.**
- It controls any number of users, contracts, miners and network peers.
- It sees every transaction, block and mempool message.
- It can submit arbitrary transactions and proofs.
- It may later gain a large quantum computer ("harvest now, decrypt later").

**Honest parties:** a user's device is honest for that user.

**Properties:**

| Property | Definition |
|---|---|
| Knowledge soundness | From any accepted proof, a witness satisfying the statement can be extracted |
| Zero-knowledge | A simulator without the witness produces proofs indistinguishable from real ones |
| Balance | For every accepted transaction: Σ inputs + bridge-in = Σ outputs + bridge-out (over the integers) |
| No double spend | Each record has exactly one nullifier, and consensus accepts each nullifier once |
| Spend authorization | Spending a user record needs the owner's key; spending a contract record needs that contract's function to approve it |
| Unlinkability | A spent record's nullifier cannot be linked to its commitment, except by the owner |
| Non-malleability | A proof is bound to its transaction; it cannot be moved or altered to change effects |
| Record confidentiality | Only the recipient (and view-key holders) can read a record's contents |
| Containment | The total value that can leave PX is at most the total that entered (R7) |

---

## 3. Architecture overview

```
┌──────────────────────────────── user device ────────────────────────────────────┐
│  private inputs, records, secret keys                                           │
│        │                                                                         │
│        ▼                                                                         │
│  function program(s) (Rust → RISC-V)  ──proof πf──┐                              │
│  kernel program (fixed by consensus)  ──proof πk──┼─► recursive aggregation ─► π │
│   · records exist (Merkle), nullifiers, authorization, balance, new records      │
└──────────────────────────────────────────────────┴───────────────────────────────┘
                                                        │ PX transaction
                                                        ▼
┌─────────────────────────────── consensus (node) ────────────────────────────────┐
│ 1. verify π with the registered verifier  (public inputs: root, nullifiers,      │
│    commitments, bridge amounts, function public outputs, tx binding hash)        │
│ 2. nullifiers unseen · root recent · pool balance stays ≥ 0 (containment)        │
│ 3. optional public part: v1 Wasm call, with π's public outputs as FACTS          │
│ 4. append commitments to the tree, add nullifiers, update the pool balance       │
└──────────────────────────────────────────────────────────────────────────────────┘
```

**Layers:**

| Layer | Content | Sections |
|---|---|---|
| Shielded state | Records, the commitment tree, nullifiers, the pool balance | §4 |
| Transactions | PX transaction format, binding, bridge | §5 |
| Kernel | The fixed statement that enforces protocol invariants | §6 |
| Private functions | Contract programs proven in a zkVM; composition with the kernel | §7 |
| VM integration | Facts for v1 public code; atomicity; deploy v2 | §8 |
| Proof system | Proof family, parameters, transcript, recursion, verifier registry | §9 |
| Circuit approach | zkVM ISA, precompiles, determinism, user-code isolation | §10 |

**The central security principle: protocol invariants never live in user code.**
- Balance, nullifiers, record existence, and the authorization of *user* records are
  enforced by one fixed **kernel**. It is written once, specified formally, and
  audited.
- Contract authors' programs can only *approve or produce* records that belong to
  their own contract. They cannot touch another contract's or a user's value.
- v1 follows the same principle: contracts approve declared value movements but
  cannot move value themselves.
- Under-constrained circuits are the most common catastrophic bug in deployed ZK
  systems. This split confines that risk to one audited component, instead of
  spreading it across every contract.

---

## 4. Shielded state

**DR-1 (decided): records and nullifiers.**
- Private state is held in UTXO-style records, as in Zcash, Zexe and Aleo, not in
  encrypted accounts.
- Spending a record reveals only its nullifier, and every spend's anonymity set is the
  whole tree.
- Records need no global ordering of private updates, so there is no shared account
  for provers to contend over.
- Encrypted accounts, as in Zether, reveal which account is touched, unless they are
  hidden in a ring.

### 4.1 Field and hash (see DR-2, DR-4)

`F` is the proof system's base field. `Hk(domain, …)` is the arithmetization-friendly
hash, with a distinct domain constant per use. A **digest** is 4 elements of `F`
(≥ 124 bits) or more, as fixed by DR-4; a 256-bit digest is the default target.

### 4.2 Keys and addresses (PX)

All PX keys derive from the existing wallet seed (transactions.md §2.1), so one set of
24 words recovers everything:

```
sk      = Hk("px/sk", seed)                            spend secret (digest)
nk      = Hk("px/nk", sk)                              nullifier key
ak      = Hk("px/ak", sk)                              authorization key (public inside proofs only)
owner_d = Hk("px/owner", ak, nk, d)                    per-address owner tag, diversifier d
ivk     = view-key material for record delivery (§4.6)
address = (owner_d, delivery public keys_d)
```

- Ownership is **hash-based**: spending proves knowledge of `sk`. So spend
  authorization and nullifier unlinkability do not depend on discrete logarithms, and
  survive a quantum adversary (R4).
- Different diversifiers give unlinkable `owner_d` (hash output), and the delivery keys
  are per-address (§4.6). So one wallet's addresses cannot be linked. This matches the
  subaddress property of v1.

### 4.3 Records

```
record = ( owner    digest      owner_d of a user address, or 0 for contract-owned
           contract digest      0 = plain BLK record; else the owning contract's id (§8)
           asset    digest      0 = BLK (v2.0: only 0 is valid; tokens: PX-3)
           value    u64         amount in atomic units
           data     [F; 8]      contract-defined private data (zero for plain records)
           rho      digest      uniqueness seed (§4.4)
           rcm      digest      commitment randomness, uniformly random )
cm = Hk("px/record", owner ‖ contract ‖ asset ‖ value ‖ data ‖ rho ‖ rcm)
```

`value` is carried as 64 bits with limb range checks (§6.4). It is never a single
field element in a small field.

### 4.4 Nullifiers, and the Faerie Gold attack

```
user record:      nf = Hk("px/nf",          nk ‖ rho ‖ cm)
contract record:  nf = Hk("px/nf-contract", contract ‖ psi ‖ cm)       psi: secret seed in data[0..2]
rho of output j  = Hk("px/rho", nf_0 ‖ j)                             nf_0: first nullifier of the tx
```

- `rho` is derived from a nullifier spent in the same transaction. Every transaction
  spends at least one record, real or dummy (§6.3). So `rho`s are globally unique, and
  two records can never share a nullifier.
- A shared nullifier is the Zcash "Faerie Gold" attack: a sender makes two payments
  with the same `rho`, and the recipient can spend only one of them.
- Including `cm` in the nullifier makes it unique even if `rho` were reused.
- Without `nk` (users) or `psi` (contract records), a nullifier cannot be linked to its
  commitment (PRF security of `Hk`).

### 4.5 Commitment tree and roots

- An append-only binary Merkle tree of depth 32 with `Hk("px/node", l ‖ r)`.
  Commitments are appended in block order.
- Consensus keeps the roots of the last `ROOT_WINDOW = 100` blocks. A transaction
  proves membership against one of them (its *anchor*), so a proof survives while
  other blocks arrive.
- A reorganization deeper than the window invalidates pending transactions, which
  must be re-proven. This is the same trade-off as v1's spendable age (transactions.md
  §5.3).
- The anonymity set of a PX spend is **every record ever created**, not 16 ring
  members.

### 4.6 Record delivery (DR-7)

- Each output carries a ciphertext of its record for the recipient.
- The recipient decrypts, recomputes `cm`, and **accepts the record only if it equals
  the on-chain commitment**. A probe with inconsistent contents is therefore never
  acted upon. This carries the Janus-anchor principle (transactions.md §12) into PX.
- Recommended construction (DR-7): hybrid encryption, both parts needed to decrypt:
  - **ECDH on Ristretto255.** This is the v1 stealth derivation, giving view tags and
    subaddress identification.
  - **ML-KEM-768** (FIPS 203) to a per-address key.
  - The symmetric key is `Hk`-derived from both shared secrets. The AEAD is
    ChaCha20-Poly1305.
- Consequence: record contents stay confidential against a future quantum adversary,
  who would have to break ML-KEM as well.

### 4.7 Pool balance (containment, R7)

- Consensus keeps a public `px_pool: u128`: the BLK value inside PX.
- Bridge-in adds to it; bridge-out subtracts; it must never go below 0.
- Even if the ZK system were completely broken, an attacker could withdraw at most the
  BLK that users deposited. **The v1 supply and every v1 output stay safe.**
- The pool balance is public by design (§12.2).

---

## 5. PX transaction

### 5.1 Format (kind 4; sketch, fixed in PX-1)

```
Prefix
  v1 part          as a call (contracts.md §5.2): ring inputs, outputs, fee, optional
                   public call; kernel over the v1 terms and ±bridge (§5.3)
  px_version       varint (selects the verifier, §9.5)
  anchor           digest               a recent tree root
  nullifiers[n]    digest               n = N_IN (fixed shape, §6.3)
  commitments[m]   digest               m = N_OUT
  ciphertexts[m]   fixed length         §4.6
  bridge_in        u64                  BLK moved from v1 into PX (public)
  bridge_out       u64                  BLK moved from PX to v1 outputs (public)
  functions[f]     (contract, program_id, public_outputs)      f ≤ 4
Prunable
  proof            the aggregated proof π (§9)
```

### 5.2 Binding (non-malleability)

- The statement's public inputs include
  `h_tx = H32("px/tx-binding", everything in the prefix except the proof)`.
- The proof commits to `h_tx` in its transcript, so it is valid for exactly this
  transaction.
- The v1 kernel signature (contracts.md §6.2) signs a message that covers
  `H32(proof)`.
- A third party can therefore neither move the proof nor alter any field.

### 5.3 Bridge (DR-5)

The v1 side sees bridge amounts as public values:

```
v1 excess:  E = Σ C'_k + Σ N_i − Σ Cm_j − Σ M_j − fee·H − bridge_in·H + bridge_out·H
PX side:    Σ value(inputs) + bridge_in = Σ value(outputs) + bridge_out          (kernel, §6)
pool:       px_pool' = px_pool + bridge_in − bridge_out ≥ 0                      (consensus)
```

- Fees are paid on the v1 side only.
- A transaction that only moves value inside PX still needs a fee source. Recommended:
  a PX-internal fee, i.e. `bridge_out` to the miner as a public v1 output,
  indistinguishable in amount from the standard fee bucket. The exact design is fixed
  in PX-1.

---

## 6. The kernel statement (normative target; formalized in PX-0)

### 6.1 Public inputs

```
anchor, nf[N_IN], cm'[N_OUT], bridge_in, bridge_out, h_tx,
fn[f] = (contract_f, program_id_f, io_hash_f)
```

### 6.2 Witness

```
input records r_i with Merkle paths and position, sk (per user input) or psi (per
contract input), output records r'_j, dummy flags, function IO transcripts
```

### 6.3 Constraints

For every input `i`:
1. **Existence.** If `dummy_i = 0`: `cm_i = Commit(r_i)` and `MerkleVerify(anchor,
   cm_i, path_i)`. If `dummy_i = 1`: `value_i = 0`, and no membership is required.
2. **Nullifier.** `nf_i` is computed per §4.4. For a dummy it is computed from a
   random `sk`/`rho`, so dummies are indistinguishable from real spends.
3. **Authorization.**
   - If `contract_i = 0`: `owner_i = Hk("px/owner", ak, nk, d)` for the prover's
     `sk`-derived `ak`, `nk` and some `d`.
   - If `contract_i ≠ 0`: `cm_i` appears in the *approved inputs* of the IO transcript
     of a function `fn_k` with `contract_k = contract_i`.

For every output `j`:
4. **Well-formed.** `cm'_j = Commit(r'_j)`, and `rho'_j = Hk("px/rho", nf_0 ‖ j)`.
5. **Contract records.** If `contract'_j ≠ 0`, `cm'_j` appears in the *created
   outputs* of a function of that contract. Otherwise, as for dummies, the output is
   value 0 with a random owner.

Globally:
6. **Balance.** `Σ value_i + bridge_in = Σ value'_j + bridge_out` over the integers,
   using 16-bit limb decomposition with range checks and carries (§6.4). `asset = 0`
   everywhere (v2.0).
7. **Function binding.** For each `k`, `io_hash_k = Hk("px/io", transcript_k)`, and the
   function proof for `(program_id_k, io_hash_k)` verifies (recursion, §9.4).
8. **Binding.** `h_tx` is a public input of the final proof (§5.2).

**Fixed shape:** `N_IN = N_OUT = 2` for plain transfers; a 4×4 variant is allowed for
function calls. Every transaction of one shape looks identical apart from its public
inputs.

### 6.4 Arithmetic safety (the most error-prone part)

- In a 31-bit or 64-bit field, a sum of 64-bit values wraps modulo `p`. Wrap-around is
  the classic ZK inflation bug.
- Every `value` is therefore decomposed into four 16-bit limbs, each range-checked by
  lookup.
- Sums are computed limb-wise with explicit carries, and each carry is range-checked.
  The final comparison is limb-by-limb.
- For **every** constraint in the kernel, a negative test builds a witness that
  violates only that constraint and asserts that proving fails or verification
  rejects (§13).

---

## 7. Private functions

### 7.1 Programs

- A private function is a Rust program (`no_std`, SDK-provided entry points),
  compiled to the zkVM ISA (§10).
- Its identity is `program_id = H32("px/program", canonical ELF image)`.
- Programs are registered in the contract at deploy (§8.3) and are immutable.
- Builds must be reproducible (pinned toolchain, SDK build profile), so anyone can
  check that `program_id` matches the published source.

### 7.2 Execution and IO transcript

A function receives, as private inputs:
- consumed records of *its own contract* (plaintexts);
- the caller's secret arguments;
- optionally, records of the caller that the caller chooses to reveal *to the function
  only*. The kernel still authorizes those; the function merely reads them.

It produces:
- **approved inputs:** commitments of its own contract's records that it allows to be
  consumed;
- **created outputs:** records of its own contract, or new user records, e.g. payouts.
  Payouts are ordinary user records; their value is covered by the kernel's balance;
- **public outputs:** bytes that become facts for the public part (§8.1);
- **state digest updates** for private contract state (PX-3).

The transcript `(inputs digest, approved, created, public outputs)` is hashed into
`io_hash`.

### 7.3 What a function cannot do

- It cannot create or destroy value: the kernel balances all records.
- It cannot touch records of another contract or a user's records without the user's
  authorization.
- It cannot choose nullifiers.
- It cannot see the chain beyond the anchor-committed state it is given.
- Whatever a function's code does, the protocol invariants hold. A contract bug can
  only harm that contract's own records and logic.

---

## 8. Integration with the contract VM

### 8.1 Proof facts (v1 claim kinds 128–255)

- contracts.md §8 reserves claim kinds 128–255 for proof systems. Kind `128` is
  **ProofFact**: `(verifier_id, contract, program_id, public_outputs)`. It is valid
  only if the transaction's proof verified with that function in its `functions[]`.
- The v1 Wasm host exposes proof facts through the existing `claim_count` and `claim`
  functions, extended with a record that carries the public outputs (≤ 1 KB).
- Public contract code therefore handles private results exactly as it handles v1
  range claims: it decides over verified facts, never over secrets.

### 8.2 Atomicity and ordering

A PX transaction with a public part is atomic. The order of checks is:
1. proof verification;
2. nullifier, anchor and pool checks;
3. Wasm execution with the facts;
4. state commit.

Any failure invalidates the whole transaction (contracts.md §9.2). Private and public
state of one contract therefore change together or not at all.

### 8.3 Contract deploy v2

A deploy transaction version 2 adds `programs[]: (program_id, verifier_id)`, up to 16.
- Program images are **not** stored on chain; only their ids are. Code is published
  off-chain with reproducible builds.
- Wasm public code and private programs share the contract id, so one contract has
  both public and private functions.
- v1 contracts are unchanged; they simply have no private functions.

### 8.4 From v1 notes to PX records

- **Value** moves between v1 and PX through the bridge (§5.3).
- **Contract data** does not migrate automatically. A contract that wants private
  state deploys a v2 version and migrates through its own logic, as for any v1
  upgrade (contracts.md §4.1).

---

## 9. Proof system

### 9.1 Requirements

| # | Requirement |
|---|---|
| P1 | Transparent (R3). |
| P2 | Zero-knowledge (hiding) mode, not just succinctness. Many STARK stacks optimize for succinctness only, so hiding must be verified per candidate. |
| P3 | Composition of kernel and function proofs (§9.4): by cross-table lookups in one batch proof (chosen), or by recursion. |
| P4 | Soundness ≥ 100 bits by **proven** bounds for the chosen parameters (§9.3), plus ≥ 128-bit collision resistance of the hash. |
| P5 | Pure-Rust prover and verifier, with a small, specifiable verifier. |
| P6 | Plausible post-quantum security for both soundness and zero-knowledge (R4). |

### 9.2 Candidates (DR-2)

| Family | Setup | PQ | Proof size | Verify | Recursion | Maturity notes |
|---|---|---|---|---|---|---|
| **STARK / FRI (AIR or PLONKish over small fields)**, e.g. built on Plonky3 components | transparent | yes (hash-based) | largest (tens to hundreds of KB) | fast | yes | Several production zkVMs; hiding support and audit status to be verified per library |
| Halo2 (IPA over the Pasta cycle) | transparent | **no** (DL) | small (a few KB) | moderate (linear IPA part) | yes (accumulation) | In production in Zcash Orchard since 2022 |
| Generalized Bulletproofs over a curve cycle tied to Curve25519 (Monero FCMP++ research) | transparent | no | medium | linear in circuit size | limited | Native to our curve; suited to membership, not general computation |
| Groth16 / KZG-PLONK | **trusted setup** | no | smallest | fastest | yes | Rejected: violates R3 |

**Decision (2026-09-23, after the PX-0 measurements; approved by the project
owner): a STARK on Plonky3 0.7.**

| Component | Choice |
|---|---|
| Multi-table STARK | `p3-batch-stark` |
| Lookups | LogUp (`p3-lookup`) |
| Hiding FRI and Merkle commitments | `HidingFriPcs` and `MerkleTreeHidingMmcs` |
| Security calculator | `p3-security` |
| Base field | BabyBear |
| Challenge field | degree-8 extension of BabyBear (247 bits; parameter set BS-ZK-2, which replaced the degree-5 BS-ZK-1, AUDIT.md ZK-F4) |
| Hashing (Merkle, Fiat–Shamir) | Poseidon2 with the standard constants |

- Only this family meets R3 and R4 together: soundness and zero-knowledge rest on hash
  functions, not on discrete logarithms.
- **Measured costs (evidence in `docs/evidence/px0-2026-09-23/`):**
  - proofs of 130–230 KB at the chosen parameters (§9.3);
  - verification in 11–64 ms;
  - proving from 0.1 s for small circuits to minutes for 2^20-row traces.
  - These were single-table benchmark circuits at BS-ZK-1. The complete zkVM at
    BS-ZK-2 is much larger; see §11 for its measured costs.
- **Rejected, with reasons:**

  | Candidate | Reason |
  |---|---|
  | BabyBear with a degree-4 extension | never reaches 100 provable bits |
  | Winterfell | cannot be unpacked on Windows |
  | Stwo | no zero-knowledge mode |
  | SP1 | core proofs are not zero-knowledge |
  | RISC Zero | C++ kernels |
  | Goldilocks | inline assembly in its x86-64 reduction, and larger proofs |
  | Halo2 | not post-quantum sound; the owner chose post-quantum |

### 9.3 Parameters and soundness (normative requirements)

- **Soundness is computed from proven bounds only.** Some deployments set FRI
  parameters by conjectured "up-to-capacity" proximity bounds; those conjectures have
  been challenged by recent research. BlackSilk sets parameters (blow-up, number of
  queries, extension degree, grinding bits) so that the **provable** bound, Johnson
  radius or better, gives ≥ 100 bits.
- **Chosen regime (decision B):** ≥ 100 bits in the Johnson-bound (list-decoding)
  regime of `p3-security`. That regime rests on the proximity-gap theorems of
  Ben-Sasson et al. (FOCS 2020) and their 2025 improvement (ePrint 2025/2055). The
  unique-decoding bits (no list-decoding theorem at all) are also computed and reported
  for every parameter set.
- **If those theorems come into doubt:** the verifier registry (§9.5) can move to
  unique-decoding parameters, ≥ 100 bits with about 128 queries and 2–3× larger
  proofs, without migrating records.
- **The parameter set is code** (`zk/src/params.rs`). A test recomputes its proven
  security for every registered table shape and fails the build below 100 bits.
- **Current set: BS-ZK-2.**
  - degree-8 extension, blow-up 8, 108 queries, 16 grinding bits;
  - over the whole shape envelope (2^22 rows, 4 000 columns): ≥ 123 bits in the
    Johnson regime (the target is 120, the approved floor 100) **and** ≥ 105 bits in
    the unique-decoding regime.
  - The second target is extra conservatism beyond decision B. Dropping it would cut
    queries by 35–55% (`zk/examples/param_study.rs`). That is an open
    security-policy decision for the owner.
- Proof-of-work grinding may contribute at most 20 bits and is counted explicitly.
- Challenges are drawn from an extension field of ≥ 124 bits.
- **Fiat–Shamir:** the transcript absorbs the full statement, i.e. all public inputs
  (including `h_tx`), the verifier id, the parameters and every prover message, before
  any challenge. This is the lesson of Frozen Heart (2022), as for BP+ in
  transactions.md §7.
- **Quantum ROM:** security of BCS-compiled IOPs in the QROM is known in principle
  (Chiesa, Manohar and Spooner, 2019). Parameters are sized with the quantum bound
  noted separately.

### 9.4 Composition and recursion

- A transaction proof is **one batch STARK** produced on the user's device. It contains
  the tables of every function execution (zkVM, zkvm.md) and of the kernel.
- They are connected by LogUp buses:
  - function IO flows to the kernel over an IO bus;
  - no recursion is needed.
- The verifier reconstructs each program's preprocessed commitment from the program
  image registered on chain, cached by program id.
- The chain sees one proof per transaction.
- Recursion (verifying proofs inside proofs) stays available for later aggregation, but
  is not on the critical path.
- Per-block aggregation of transaction proofs by miners is an optimization for later
  (PX-4). It changes nothing in the transaction format.

### 9.5 Verifier registry (R9)

```
verifier_id → { proof system version, parameters, kernel program id,
                activation height, sunset height (optional) }
```

- Consensus contains a fixed table; entries are added only by height-activated
  upgrades.
- After a sunset height, new transactions with that verifier are invalid. Existing
  records stay spendable with the new verifier, because records, nullifiers and the
  tree do not depend on the proof system (only `Hk` must stay; §9.6).
- The on-chain verifier is implemented in BlackSilk's own crate, from this
  specification. It is kept independent of the prover library and cross-tested against
  it (R10).

### 9.6 Hash `Hk` (DR-4)

| Option | Pros | Cons |
|---|---|---|
| **Poseidon2** (Grassi, Khovratovich, Schofnegger, 2023) | Cheapest in circuits; widely deployed | Young algebraic design; active cryptanalysis of reduced-round and specific instances |
| Rescue-Prime Optimized | Conservative algebraic margins | Slower |
| Blake3 / Blake2 in-circuit | Conservative, well studied | 10–50× more constraints |

**Recommendation:** Poseidon2 with the designers' 128-bit parameters plus extra rounds
as a safety margin (to be fixed in PX-0 after reviewing current cryptanalysis). `Hk` is
what makes records, nullifiers and the tree binding, so it is **the hardest-to-change
component**. A later `Hk` change means a new tree with a migration (records spent from
the old tree and re-created in the new one). Choosing conservatively matters more here
than prover speed.

---

## 10. Circuit design approach (DR-3)

**Options:**

| Option | Author experience | Assurance | Prover cost |
|---|---|---|---|
| Hand-written circuits (AIR/PLONKish gadgets) per contract | Expert-only | Every contract is a new circuit to audit; under-constraint risk everywhere | Best |
| Circuit DSL | Specialist | Better, but every contract still compiles to new constraints | Good |
| **zkVM**: contracts are ordinary Rust compiled to a fixed ISA | Normal Rust | **One** circuit (the VM) to audit, whatever contracts do | 10–100× of a custom circuit |

**Recommendation:** a **zkVM for contract functions, plus a fixed kernel.**
- Contract authors write ordinary Rust, and the soundness-critical surface is a single
  audited VM circuit. This is R10 and §3's central principle applied to computation.
- The kernel runs in the same zkVM as a consensus-fixed program. It may later be
  replaced by a hand-optimized circuit with an identical statement, once that circuit
  can be audited against the program.

**Decision:** our own zkVM, BVM-1, specified in [`zkvm.md`](zkvm.md), built on the
Plonky3 components above. No existing pure-Rust RISC-V zkVM met P2 (zero-knowledge)
and R5 (pure Rust) together (§15).

**zkVM profile, as originally targeted (superseded by zkvm.md):**
- ISA: **RV32IM**, a small, stable, well-specified integer ISA with no floating point
  (as in v1's Wasm profile).
- Memory: bounded, 16–64 MiB. A cycle limit per function.
- Precompiles (fixed-function circuits, each specified and audited like the kernel):
  - `Hk` permutation;
  - Merkle path verification;
  - 256-bit arithmetic;
  - recursive proof verification.
  A **Ristretto255 point-arithmetic precompile** is considered only for the
  confidential-bridge upgrade (DR-5).
- IO: only through the SDK channel. No host syscalls, no clock, no randomness except
  witness input.
- **Candidates for PX-0:**
  - (a) our own minimal zkVM on established STARK components (their audit status must
    be verified, not assumed), with small verifier and full control, but the largest
    effort;
  - (b) adopting an existing pure-Rust RISC-V zkVM, pinned and reviewed, with its
    hiding mode verified.

  The decision criteria are listed in §15.

---

## 11. Performance model

The targets below were set before PX-0. The PX-0 measurements are in
`docs/evidence/px0-2026-09-23/RESULTS.md`.

**Measured on the complete system (BS-ZK-2, this machine; docs/px.md §8): the targets
are missed by a wide margin.**

| Item | Target | Measured |
|---|---|---|
| Private transfer proving | ≤ 15 s | ~40 s |
| Proof size | ≤ 150 KB | ~2.0 MB (transfer), ~2.5 MB (with one function) |
| Verification | ≤ 30 ms | ~1.3–1.5 s |

Per-transaction proofs of this size are not viable for a chain. The paths are:
- the query-policy decision (§9.3);
- caching setup commitments, for verification;
- per-block aggregation (PX-4).

Until then, §11.1 is normative, and PX cannot be activated on a public network.

| Item | Target | Why |
|---|---|---|
| Private transfer (2×2), proving | ≤ 15 s, ≤ 4 GB RAM on a 4-core laptop | Client-side proving (R8) must be practical |
| Function of 10⁶ cycles, proving | ≤ 120 s | Interactive contract use |
| Final proof size | ≤ 150 KB | 1 MB blocks (§11.1) |
| Verification | ≤ 30 ms per proof on one core | Block validation and mempool DoS resistance |
| Recursion overhead | ≤ 2× the inner proving time | Composition must not dominate |

### 11.1 Chain capacity

- At 150 KB per proof, a 1 MB block holds at most 6 PX transactions: about 3 per
  minute at T = 120 s.
- Mitigations, in order of safety:
  1. a larger PX weight budget with a separate, higher per-byte fee;
  2. smaller final proofs (more FRI queries traded for a larger blow-up; §9.3 bounds
     still apply);
  3. per-block aggregation (PX-4).
- The block weight rule change is a consensus decision taken in PX-1, with measured
  sizes.

### 11.2 State growth

- Per output: commitment (32 B) plus ciphertext (~1.2 KB with ML-KEM-768).
- Per input: nullifier (32 B).
- The tree needs O(32) nodes of storage per append.
- Nodes keep the nullifier set and the tree frontier plus the recent roots; the full
  tree is needed only for wallets' Merkle paths. Wallets can fetch paths privately
  from their own node.

### 11.3 Proving privacy

- **Delegated proving is not supported:** it would reveal the witness (R8).
- Weak devices can use the plain v1 layer, or pre-compute proofs while idle.
- GPU acceleration may exist outside consensus, but never as a remote service
  receiving witnesses.

---

## 12. Security analysis

### 12.1 Assumptions (complete list)

1. **Proof system:** knowledge soundness and zero-knowledge of the chosen IOP, compiled
   with Fiat–Shamir in the (Q)ROM, with the parameters of §9.3.
2. **`Hk`:** collision resistance, preimage resistance, and PRF security when keyed
   (nullifiers). This is the key PX assumption.
3. **Encryption:** IND-CCA security of the hybrid KEM (secure if either ECDH/DDH or
   ML-KEM holds) and of ChaCha20-Poly1305.
4. **The v1 side** (bridge and fees): transactions.md §9, plus the kernel analysis in
   the crypto review.
5. **Correct implementation of the kernel and zkVM circuits:** the largest *practical*
   risk. It is addressed by R10 (§13), not by any assumption.

### 12.2 Privacy analysis

| Hidden | Public |
|---|---|
| Which records are spent (anonymity set: all records) | Nullifiers (unlinkable to commitments) |
| Record owners, contents, amounts | New commitments; ciphertexts (uniform length) |
| Function inputs and private state | Which contract and function were called; public outputs |
| Links between one wallet's addresses | Bridge amounts and the pool total (containment) |
| | Transaction time, size, shape; fees (standard buckets) |

**Bridge amounts are a linking vector:** an unusual deposit amount followed by an equal
withdrawal. Wallet policy:
- bridge in standard denominations;
- bridge out after delays;
- never bridge in and out the same amount.

The alternative, a confidential bridge (DR-5), would hide the amounts but give up
containment (R7) at the moment the ZK system is youngest. The recommendation is to keep
containment until the system has years of operation and audits behind it, then
reconsider.

### 12.3 Failure scenarios and responses

| Scenario | Impact | Response |
|---|---|---|
| Soundness bug in kernel or zkVM | Forged PX value or spends | Loss bounded by `px_pool` (R7). Emergency upgrade: activate a fixed verifier and sunset the old one. **There is no admin key and no pause key**; responses are consensus upgrades adopted by node operators. |
| Zero-knowledge bug | Private data leaks from proofs | Cannot be undone for published proofs. Hence the ZK-mode verification in PX-0, and tests that proofs are simulatable (statistical tests on proof elements plus a review of the hiding construction). |
| `Hk` weakness | Collisions: double spends or fake records | Containment; migration to a new tree with a new `Hk` (§9.6) |
| KEM break | Contents readable | Hybrid: both ECDH and ML-KEM must fail |
| Quantum adversary | v1 layer broken (transactions.md §11.6) | PX soundness and zero-knowledge are hash-based; record contents stay protected by ML-KEM; the bridge's v1 side is exposed like all of v1 |

---

## 13. Assurance plan (R10)

1. **Formal statements.** The kernel (§6) and every precompile get a mathematical
   specification, the relation `R(x, w)`, before implementation. The circuit must
   implement exactly that relation.
2. **Constraint mutation testing:**
   - for every constraint, a witness that violates only that constraint must be
     rejected;
   - for every witness field, an automatic check that changing it changes some
     constraint's satisfaction.
   This detects under-constrained witnesses.
3. **Independent verifier:** the consensus verifier is written from the spec and
   cross-tested against the prover library's verifier on random and adversarial
   proofs.
4. **Differential execution:** zkVM traces against a reference RV32IM interpreter, on
   the official RISC-V compliance tests plus fuzzed programs.
5. **Adversarial proofs:** mutated proofs, transcripts with a missing public input,
   wrong parameters, proof reuse across transactions. All must be rejected.
6. **Fuzzing:** decoders, verifier inputs, zkVM programs.
7. **Soundness parameter calculator** in the repository, with tests: it recomputes the
   proven security bits from the parameters in the verifier registry, and the build
   fails below 100.
8. **External review:**
   - two independent audits (cryptographic design, and implementation) before mainnet
     activation;
   - a public testnet period of at least 6 months;
   - a bug bounty.

---

## 14. Upgrade path from v1

| Phase | Scope | Unlocks |
|---|---|---|
| **PX-0** | Evaluation, parameter selection and formal kernel spec; no consensus code | Decisions DR-2 to DR-7 (§15) |
| **PX-1** | Shielded pool: records, tree, nullifiers, kernel, bridge, hybrid delivery; plain BLK only | Full-set anonymity (instead of 1 of 16) and PQ-private transfers |
| **PX-2** | Private functions: zkVM programs, proof facts to v1 Wasm, deploy v2 | Private computation over hidden inputs and amounts |
| **PX-3** | Contract-owned records and private contract state; confidential tokens (asset ≠ 0) | Private DeFi primitives, private registries |
| **PX-4** | Per-block proof aggregation; light-client proofs | Throughput, lighter nodes |
| **PX-5** | Long-term: PX as the default home of BLK, with the ring layer kept for compatibility | A post-quantum-private chain |

**Rules for every phase:**
- The order is spec → implementation → internal review → external audit → testnet →
  activation height.
- No phase is activated on mainnet without its external audit.

**Compatibility with v1:**
- v1 contracts, notes and claims keep working unchanged.
- Claim kinds 128–255, reserved since v1, carry proof facts.
- The contract id and the fact-based host API are shared, so a contract can gain
  private functions through a v2 deployment without changing its public ABI.

---

## 15. PX-0: evaluation and decision gates

**Outcome (2026-09-23):**

| Decision | Result | Evidence |
|---|---|---|
| DR-2 proof family | STARK on Plonky3 0.7, BabyBear^5, Johnson-bound ≥ 100 bits | `docs/evidence/px0-2026-09-23/RESULTS.md` §1–2 |
| DR-3 zkVM | Our own BVM-1 (zkvm.md): adopted zkVMs failed zero-knowledge (SP1) or pure Rust (RISC Zero) | RESULTS.md §3 |
| DR-4 `Hk` | Poseidon2 over BabyBear, width 16, standard constants. The same permutation is used for Merkle hashing and Fiat–Shamir. Whether to add safety rounds is an open question for the external review. | §9.6 |
| DR-5 bridge | Public amounts with containment (unchanged) | §12.2 |
| DR-6 client proving | Small circuits prove in 0.1–3 s; 2^16-row traces take 10–45 s. Further tuning in PX-1 | RESULTS.md §2 |
| DR-7 delivery | Unchanged (hybrid ML-KEM); decided in PX-1 | |

The criteria below are the original gates, kept for the record.

**Deliverables:**
- **Prototypes:** a 2×2 kernel and a 10⁶-cycle function, in every candidate stack.
- **Measurements:** the §11 targets on the reference machine (4-core x86-64,
  16 GB RAM).
- **Review:**
  - hiding mode;
  - the soundness calculation under proven bounds;
  - dependency audit status, maintenance, license, and pure-Rust status (no C, no FFI,
    and no `unsafe` outside reviewed hot paths);
  - current `Hk` cryptanalysis.

| Decision | Criteria (all must hold) | Fallback |
|---|---|---|
| DR-2 proof family | P1–P6; §11 size and verify targets within 2× | Halo2-IPA; R4 dropped and documented |
| DR-3 zkVM (own vs adopted) | Hiding verified; verifier specifiable in ≤ ~5 kLOC; audited or auditable; pinned | Own minimal zkVM on established components (audit status to be verified) |
| DR-4 `Hk` | No known attack within the security margin; parameters from the designers | Rescue-Prime Optimized |
| DR-5 bridge | Default: public amounts with containment | Confidential bridge only after ≥ 2 years of PX operation and audits |
| DR-6 client proving | 2×2 proving ≤ 15 s on the reference laptop | Smaller circuits or a relaxed target; never delegated proving |
| DR-7 delivery | ML-KEM-768 hybrid; address size acceptable (options: long addresses, an on-chain key registry, or interactive exchange) | ECDH only, documented as not PQ-confidential |

Each decision is recorded in this document, with the measurements as evidence in
`docs/evidence/`, before PX-1 begins.

---

## 16. Open questions

1. **Fees for purely internal PX transactions** without revealing the payer (§5.3).
2. **Address format with ML-KEM keys:** 1 184-byte public keys make addresses long
   (DR-7).
3. **Private contract state** (PX-3): record-based state (UTXO-style, concurrency by
   design) versus an encrypted state tree with a public root (simpler logic, but
   contention).
4. **Concurrency:** two users proving against the same contract record race, and the
   loser must re-prove. PX-3 needs a design that avoids hot records, e.g. batching or
   per-user records.
5. **Viewing keys and compliance disclosures:**
   - an incoming view key per address;
   - a full view key per wallet;
   - optional proofs of specific facts (e.g. "I received X from contract C") without a
     full disclosure.

---

## 17. Prior art

| System | Relevant idea | Difference here |
|---|---|---|
| Zcash Sapling/Orchard | Notes, nullifiers, commitment tree, Faerie Gold defenses, turnstiles | Contract records and functions; hash-based ownership; hybrid PQ delivery; consensus-enforced containment |
| Zexe / Aleo | Records with birth/death predicates, private functions | Protocol invariants in a fixed kernel separate from user programs; transparent setup |
| Aztec | Private/public function split, public calls from private | Public side is the v1 fact-based Wasm VM; contract callers are ring-anonymous on the v1 side too |
| Penumbra | Shielded pool plus public batch execution | General private functions |
| RISC Zero, SP1 | RISC-V zkVMs in Rust on STARKs | Used (or reproduced) as the execution layer, with a kernel on top and a spec-derived verifier |
| Monero FCMP++ | Full-chain membership on Curve25519 cycles | PX reaches full-set anonymity with hash-based proofs instead |

**What we believe is new** is the combination:
- a Monero-lineage ring layer whose contract model and proof facts are shared with a
  hash-based private execution layer;
- consensus-enforced containment between the two;
- kernel/user separation for all value invariants;
- hybrid post-quantum record delivery with Janus-style commitment checks.

As in contracts.md §3, "new" is our belief, pending the external prior-art check.
