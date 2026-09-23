# BlackSilk Confidential Contracts Specification

Status: **draft v0.1, for approval. Not implemented.** Nothing in this document is
consensus until it is implemented, tested and activated at a height (§18). Where this
document states a security property, it is a design goal that the implementation must
demonstrate with tests; none is verified yet.

Scope:
- the contract model: code, state, notes and key sets;
- the deploy and call transaction formats;
- the value model: notes, the balance kernel and range-proof claims;
- authorization: one-time auth keys and scoped anonymous membership;
- execution: the WebAssembly profile, host API, fuel, limits and determinism;
- the state commitment, validation rules, fees, mempool policy and wallet integration;
- the privacy model, security analysis, prior art, roadmap, milestones and test plan.

It extends [`transactions.md`](transactions.md): its primitives (§1), stealth outputs
(§3), CLSAG (§6.1), Bulletproofs+ (§7) and randomness rules (§10) are used unchanged.
Tags below are prefixed with `BlackSilk/v1/` as in transactions.md §1.2.

---

## 1. Goals and principles

**The problem.** On Ethereum-style platforms every call reveals its sender, and every
balance and transfer inside a contract is public. On BlackSilk, where senders, recipients
and amounts are hidden, such contracts would unmask every user who touches them. That is
why the old WASM contracts were parked in `legacy/`.

**Goals, in priority order:**
1. **Privacy of the people using contracts.** A call reveals no sender, no recipient
   and, by default, no amounts. Value leaving a contract becomes ordinary stealth outputs,
   indistinguishable from payments.
2. **Soundness of value.** No contract, bug or caller can create coins, move value it is
   not entitled to, or break the supply accounting.
3. **Deterministic, bounded execution.** Every node computes the same result with
   bounded CPU, memory and storage.
4. **No new cryptographic assumptions.** Only discrete log, DDH and the random-oracle
   model on Ristretto255, exactly as the transaction layer. No trusted setup, no trusted
   hardware.
5. **Pure Rust end to end.** The node, the engine and the contracts themselves (compiled
   to WebAssembly) are Rust.
6. **Room to grow.** Zero-knowledge proof verification, confidential tokens and private
   state can be added later without migrating notes or state (§17).

**Non-goals for v1:**
- Hiding contract code, contract state, or which contract was called. They are public.
- Arbitrary computation on hidden amounts. Contracts see hidden amounts only through
  the facts callers prove about them: ranges, equalities, revealed values (§8).
- Upgradable code, self-destruct, events/logs, or wall-clock time.

---

## 2. The model in one page

**Three principles define the design:**

1. **Callers are anonymous. There is no `msg.sender`.**
   - A call's inputs are ring-signed like a payment: 1 of 16.
   - A contract never learns who called it. It learns only facts the caller proves:
     - "I hold the key registered as K" (auth keys, §7.1);
     - "I am one of these members, and this is my one tag for this vote" (scoped
       membership, §7.2);
     - "this hidden amount is at least 5 BLK" (claims, §8).
2. **Value effects are declared; contracts approve them.**
   - A call transaction lists every value movement up front: normal inputs, notes it
     consumes from contracts, normal outputs, and notes it creates in contracts.
   - A single balance kernel proves that the value balances (§6).
   - The contract's code does not move value. It *approves or rejects* the declared
     movement, against its public state and the proven facts.
   - Data effects (the contract's key–value state) are computed by the code.
3. **Contracts hold value as notes.**
   - A note is a commitment owned by a contract, with policy bytes that the contract
     interprets.
   - A **private note** is a full stealth output construction toward a beneficiary
     address: amount hidden, beneficiary hidden, Janus-protected, found by wallet
     scanning.
   - A **public note** has its amount in the clear, for contracts that must compute on
     amounts (pools, treasuries).

**Anatomy of a call:**

```
            ┌────────────────────────── call transaction ─────────────────────────────┐
 inputs     │ ring-signed outputs (CLSAG, 1 of 16)    notes consumed from contracts   │
            │                          \                  /                           │
            │              kernel: Σ in − Σ out − fee·H = e·G, signed with e          │
            │                          /                  \                           │
 outputs    │ ordinary stealth outputs              new notes (private or public)     │
            │                                                                         │
 facts      │ auth signatures · membership proofs · range / equality / reveal claims  │
 call       │ target contract · access list · input bytes · fuel and storage limits  │
            └─────────────────────────────────────────────────────────────────────────┘
                     │ all proofs verified first, then:
                     ▼
            Wasm code of the target (and of the contracts it calls) runs
            deterministically; it reads its state and the verified facts, writes state,
            and must approve every consumed note and accept every created note.
            Any failure: the transaction is invalid. There are no partial or reverted calls.
```

---

## 3. Prior art, and what is new

Each ingredient has prior art. The design combines them on a RingCT chain.

| Ingredient | Prior art | Use here |
|---|---|---|
| Ring-signed inputs, stealth outputs, BP+ | Monero (CLSAG 2020, BP+ 2022) | Unchanged from transactions.md. |
| Balance kernel: Schnorr signature by the commitment excess | Mimblewimble (2016). Security: Fuchsbauer, Orrù, Seurin, *Aggregate Cash Systems*, EUROCRYPT 2019 | Makes calls non-malleable, and proves knowledge of consumed notes' openings (§6.3). |
| Declared transition checked by a validator script | Cardano eUTXO; Zexe/Aleo "records + predicates" | Contracts approve declared value effects instead of executing transfers. |
| Linkable ring signature with an event/scope tag | Tsang & Wei 2004 (e-voting); Liu & Wong 2005 (event-oriented linkable ring signatures) | Scoped membership (§7.2): one tag per member per scope. |
| Confidential contract payments with anonymity | Zether (Bünz et al., FC 2020) | Different mechanism: notes and rings instead of ElGamal accounts. |
| Private execution with ZK proofs | Aleo, Aztec, Zcash | **Not in v1**; the claim framework is designed to add it (§17). |
| Public pool, private users | Penumbra | Public notes (§4.3). |
| Declared access lists | Solana, EIP-2930 | Access list (§5.2), for conflict detection and future parallel execution. |
| Deterministic Wasm interpreter with fuel | Substrate `pallet-contracts` (wasmi) | Execution engine (§9). |

**What we believe is new is the combination.** As far as we know, no deployed system
has all of the following:
- contract callers anonymous in the *same* ring anonymity set as ordinary payments;
- contract payouts indistinguishable from payments, and reusable as decoys;
- Janus-protected contract notes;
- public contract logic over hidden amounts, through range, equality and reveal claims;
- scoped anonymous membership;
- no trusted setup, no trusted hardware, and no assumptions beyond those of the payment
  layer.

"As far as we know" is not proof. The external review (§16.4) should include a
prior-art check. We make no claim to being "first", and we will not until that check is
done.

---

## 4. Objects

### 4.1 Contract

```
contract_id  32 bytes   H32("contract/id", ctx ‖ code_hash)        (ctx: §5.4)
code_hash    32 bytes   H32("contract/code", code)
```

Code is immutable: there is no upgrade or self-destruct. Several contracts may share one
code blob, which is stored once. A contract upgrades by deploying a new contract and
migrating through its own logic.

### 4.2 Key–value state

Each contract has a private namespace of byte keys (1–64 bytes) mapping to byte values
(0–4 096 bytes). Only the contract's own code can write it. Everyone can read it: it is
public.

### 4.3 Notes

A note is value held by a contract.

```
note_id   = H32("contract/note-id", ctx ‖ LE32(j))       j: index among the tx's new notes
owner     = contract id
policy    = 0–64 bytes, chosen by the creator, checked by the owner's code on acceptance
height    = creation height

private note:   O, R, view_tag, Cm, enc_amount, enc_anchor   (transactions.md §3.2, context ctx)
public note:    amount (u64, clear);  Cm := 1·G + amount·H   (like a coinbase output)
```

- **Private notes** are built exactly like stealth outputs, toward a *beneficiary
  address* chosen by the creator.
  - The beneficiary finds them by scanning, with the same view tag, Janus anchor and
    amount checks (transactions.md §3.3).
  - The creator knows the opening (it built the note), and so does the beneficiary.
  - The beneficiary also holds the one-time secret `p` for `O`. It can therefore prove
    "I am this note's beneficiary" with an auth signature under `O` (§7.1), without
    revealing its address.
- **Public notes** have a public opening. Anyone can build a transaction that consumes
  one; the owner contract's logic decides whether it is allowed.
- A note is consumed at most once. Consumption removes it from the state. One-time keys
  `O` are unique across outputs *and* private notes, so rule C4 of transactions.md is
  extended to notes.

### 4.4 Key sets

Each contract may keep append-only key sets, `set_id: u32 → [point]`, for scoped
membership proofs (§7.2).
- Members are added by the contract's code. The keys must be valid, non-identity
  Ristretto points.
- Sets are append-only because membership proofs reference members by index. To
  remove members, a contract starts a new set.

---

## 5. Transaction formats

Encoding primitives, strict decoding and the no-optional-fields rule are those of
transactions.md §4.1. Two new kinds are valid after activation (§18):
- `kind = 2`: **call**;
- `kind = 3`: **deploy**.

### 5.1 Common elements

```
ref        u8 tag ‖ varint index     tag 0 = pseudo-output, 1 = output, 2 = new note, 3 = consumed note
sig        R point ‖ s scalar        Schnorr signature (§6.2, §7.1)
```

### 5.2 Call transaction (kind 2)

```
Prefix
  version          varint   = 1
  kind             u8       = 2
  input_count      varint   0 ≤ n ≤ 64            inputs as in a transfer (key image, ring[16])
  inputs[n]
  output_count     varint   0 ≤ k_o ≤ 16          outputs as in a transfer, sorted by O
  outputs[k_o]
  fee              varint
  contract         32 bytes                       target contract
  access_count     varint   0 ≤ a ≤ 4
  access[a]        32 bytes each, strictly increasing, none equal to `contract`
  fuel_limit       varint   1 ≤ f ≤ MAX_CALL_FUEL
  storage_limit    varint   0 ≤ s ≤ MAX_CALL_STORAGE      bytes
  input_len        varint   ≤ 16 384
  input            bytes                          opaque to consensus; read by the contract
  consumed_count   varint   0 ≤ c ≤ 16
  consumed[c]      32-byte note ids, strictly increasing
  note_count       varint   0 ≤ m ≤ 16
  new_notes[m]:
    owner          32 bytes, ∈ {contract} ∪ access
    type           u8: 0 private, 1 public
    policy_len     varint ≤ 64;  policy bytes
    private: O, R, view_tag, Cm, enc_amount, enc_anchor
    public:  amount varint
  auth_count       varint   0 ≤ u ≤ 8
  auth_keys[u]     points, strictly increasing, not identity
  claim_count      varint   0 ≤ q ≤ 8
  claims[q]        statements (§8)
  member_count     varint   0 ≤ w ≤ 4
  members[w]:      statements (§7.2): owner, set_id, scope, ring indices, tag

Base
  pseudo_outs[n]

Prunable
  bp_plus          one BP+ over all private commitments: outputs, then private new notes
                   in order (absent if there are none; 1 ≤ total ≤ 16)
  clsag[n]
  kernel           sig                            (§6.2)
  auth_sigs[u]     sig, same order as auth_keys
  claim_proofs[q]  (§8)
  member_sigs[w]   (§7.2)
```

**Structural rules:**
- `n + c ≥ 1`: every call spends something, so its context is unique (§5.4).
- `n ≥ 1` or `k_o ≥ 1`: a call has a ring input or at least one private output. Either
  way, the kernel secret `e` contains a mask that only the builder knows, which
  non-malleability requires (§6.3 Claim 3).
  - A call whose terms are all public notes would have a publicly computable `e`, and
    anyone could re-sign it.
  - With equal counts of public notes on both sides, `E` would even be the identity.
- `k_o + (private notes) ≤ 16`: one aggregated BP+ covers them.
- A wallet should still produce at least 2 outputs where it can (§14.3).

### 5.3 Deploy transaction (kind 3)

```
Prefix
  version, kind = 3
  input_count      varint   1 ≤ n ≤ 64
  inputs[n]
  output_count     varint   0 ≤ k_o ≤ 16
  outputs[k_o]
  fee              varint
  code_len         varint   ≤ MAX_CODE = 65 536
  code             Wasm module (§9.1)
  fuel_limit, storage_limit                        as in a call
  input_len, input                                 passed to `bs_init`
Base:     pseudo_outs[n]
Prunable: bp_plus (outputs), clsag[n], kernel
```

A deploy validates the module (§9.1), stores the code, creates the contract, and runs
`bs_init` if the module exports it. A failure makes the transaction invalid.

### 5.4 Context and hashes

```
call:    ctx = H32("input-context/call",   I_0 ‖ … ‖ I_{n-1} ‖ note_id_0 ‖ … ‖ note_id_{c-1})
deploy:  ctx = H32("input-context/deploy", I_0 ‖ … ‖ I_{n-1})
```

- Key images and consumed note ids are each unique on chain, so `ctx` is unique per
  transaction. The burning-bug argument of transactions.md §3.1 carries over to call
  outputs, private notes, note ids and contract ids.
- Outputs and private notes of a call or deploy use this `ctx` in their stealth
  derivation.

```
prefix_hash, base_hash, prunable_hash, tx_hash, bp_hash     as transactions.md §4.4
claims_hash  = H32("tx/claims", claim_proofs bytes ‖ member_sigs bytes)
sig_message  = H32("tx/call-sig-message",
                   LE32(network_id) ‖ prefix_hash ‖ base_hash ‖ bp_hash ‖ claims_hash)
```

Every signature in the transaction (CLSAGs, kernel, auth, membership) signs this
`sig_message`. It covers every byte except the signatures themselves, and it binds to
the network (transactions.md §4.4).

---

## 6. Value model

### 6.1 Balance

Let:
- `C'_k` be the pseudo-outputs;
- `N_i` the commitments of the consumed notes (public notes: `1·G + a·H`);
- `Cm_j` the output commitments;
- `M_j` the commitments of the new notes (public: `1·G + a·H`).

The **excess** is

```
E = Σ C'_k + Σ N_i − Σ Cm_j − Σ M_j − fee·H
```

and the transaction is balanced iff `E = e·G` for an `e` the builder knows (§6.2).

- Unlike a transfer, masks need not sum to zero; the kernel absorbs the difference.
  Private note masks are derived from the stealth secret (`y = Hs("mask", S)`), so an
  exact zero sum is not always reachable without inputs.
- Deploys have no notes: `E = Σ C'_k − Σ Cm_j − fee·H`.

**Ranges:**
- Consumed notes and pseudo-outputs commit to amounts in `[0, 2^64)`. Consumed notes
  were range-proven or public at creation; pseudo-outputs are tied to range-proven
  outputs by CLSAG.
- New private commitments are range-proven by the BP+.
- Public amounts are `u64` by encoding.
- With at most 64 + 16 terms on each side, both sides stay below `2^71 ≪ ℓ`, so no
  wrap-around (transactions.md §6).

### 6.2 Kernel signature

```
E ≠ identity                                   (else anyone could sign: rejected)
t    ← hedged nonce (transactions.md §10) over secret e and message sig_message
R_k  = t·G
c    = Hs("contract/kernel", E ‖ R_k ‖ sig_message)
s    = t + c·e
verify:  s·G = R_k + c·E
```

`E` is not transmitted. The verifier computes it, which requires the consumed notes'
commitments from the state. The kernel check is therefore contextual (§11.2).

### 6.3 What the kernel guarantees (to be reviewed)

**Claim 1 (no inflation).** Suppose:
- all range proofs are sound;
- each CLSAG proves `Cm_π − C'_k ∈ ⟨G⟩`;
- the kernel proves knowledge of `e` with `E = e·G`.

Then `E` has no `H` component, so `Σ amounts_in = Σ amounts_out + fee` over the
integers. Otherwise the prover would know a discrete-log relation between `G` and `H`.
This is the Mimblewimble argument; it is proven for aggregate cash systems in the
FOS19 model.

**Claim 2 (only openers consume).** The builder must know `e`. For consumed notes,
extracting `e` together with the openings of every other term in `E` yields a
representation of `Σ N_i` in `(G, H)`. That representation matches the true openings
unless DL is broken. So a note can be consumed only by someone who knows its opening
(amount and mask), or when the opening is public (public notes).
- This is **a property, not an authorization rule**. Both the creator and the
  beneficiary of a private note know its opening.
- Contracts must still check authorization (§7).

**Claim 3 (non-malleability).**
- `sig_message` covers every non-signature byte.
- The kernel and every CLSAG and auth signature sign it.
- A third party cannot produce any of these signatures:
  - A CLSAG needs a spend key.
  - The kernel needs `e`, and K2 guarantees that `e` includes a pseudo-output mask or
    a private-output mask known only to the builder.
- So a third party cannot change outputs, notes, fee, call input or claims, e.g. to
  burn a payout by replacing `O`.
- **Caveat (to be reviewed):** in a call without ring inputs, someone who knows the
  opening of *every* term could re-sign it. For example: a note consumed back to its
  creator, whose only output pays the creator. Such a party could only redirect value
  it can already open.
- Wallet rule: a call without ring inputs always includes an output to the builder's
  own address, so that `e` contains a mask only the builder knows.

These claims are arguments, not proofs. The formal reduction for Claim 2 must go
through FOS19's knowledge-soundness framework with BP+ extractability. It is listed for
the external review (§16.4).

---

## 7. Authorization without identity

### 7.1 Auth keys

An auth key is any point `K` the caller lists in `auth_keys`. The caller signs with it:

```
R = t·G;   c = Hs("contract/auth", K ‖ R ‖ sig_message);   s = t + c·k;   verify s·G = R + c·K
```

Contracts see the set of verified keys and decide what they mean:
- A **beneficiary** signs with the one-time key `O` of a private note (secret
  `p = x + d`, transactions.md §3.3). This proves "the beneficiary of this note acts".
  It does not reveal the beneficiary's address.
- **Registered keys:** a contract stores keys in its state, e.g. escrow parties or
  multisig signers. Wallets derive one fresh key per contract and role (§14.2), so auth
  keys never link a user's contracts.
- Using the same auth key twice links those two calls to each other. Contracts that
  need repeated anonymous action should use membership proofs instead.

### 7.2 Scoped membership proofs

A membership proof shows "I own one of these keys from key set `set_id` of contract
`owner`", and publishes a tag that is **unique per member per scope**. The tag is
unlinkable across scopes and to the member's key.

```
statement:  owner (32) ‖ set_id (u32) ‖ scope_len (u8 ≤ 32) ‖ scope ‖
            ring_size r (u8, 1..16) ‖ indices[r] (strictly increasing varints) ‖ tag I
B    = Hp("contract/scope", owner ‖ LE32(set_id) ‖ u8(len) ‖ scope)
ring = P[0..r) = key_set[owner][set_id][indices]                     (from pre-state)
I    = x·B                                                            (x: member's secret)

sign (bLSAG with a fixed tag base):
  α ← hedged nonce
  c[π+1] = Hs("contract/member-round", ring ‖ B ‖ I ‖ sig_message ‖ α·G ‖ α·B)
  for i ≠ π:  s[i] ← hedged;  L = s[i]·G + c[i]·P[i];  R = s[i]·B + c[i]·I;
              c[i+1] = Hs("contract/member-round", ring ‖ B ‖ I ‖ sig_message ‖ L ‖ R)
  s[π] = α − c[π]·x
signature:  c0 ‖ s[0..r)
verify:  I ≠ identity; recompute the loop from c0; valid iff c[r] = c0
```

**What each party learns:**
- The contract sees `(owner, set_id, scope, I, r)`.
- Consensus does **not** enforce tag uniqueness. The contract does, e.g. an anonymous
  vote stores used tags for the scope `"proposal-17"`.
- Anonymity: 1 of `r`. Contracts should require `r = 16`, or `r = |set|` if the set is
  smaller.

**Properties:**
- This is the event-oriented linkable ring signature of the literature (§3).
- Linkability: the same `x` and `B` always give the same `I`.
- Anonymity under DDH.
- Unforgeability and non-frameability under DL in the ROM.

**Differences from our CLSAG, for review:** a common tag base `B` instead of
`Hp(P[i])`, and no commitment component.

**Known limitation:** because all members share the base `B`, a member who knows
another member's secret can compute that member's tag for the scope. This follows from
key compromise; there is no attack without it.

---

## 8. Confidential claims

A claim is a statement about a commitment in the transaction, proven by the caller and
verified before execution. The contract sees only verified statements.

| Kind | Statement | Proof |
|---|---|---|
| `0` Range | `ref` commits to `v` with `min ≤ v ≤ max` | BP+ (k = 2) over `V0 = C − min·H` and `V1 = max·H − C`; masks `y` and `−y` |
| `1` Equal | `ref_a` and `ref_b` commit to the same amount | Schnorr under tag `contract/claim-eq` over `C_a − C_b` (a `G`-multiple) |
| `2` Reveal | `ref` commits to exactly `v` | Schnorr under tag `contract/claim-val` over `C − v·H` |
| `3–127` | reserved for later versions (invalid in v1) | |
| `128–255` | reserved for proof-system claims (§17) (invalid in v1) | |

- Encoding: `kind u8 ‖ ref ‖ fields` (`min`, `max`, `v`: varint; `ref_b`: ref).
  `min ≤ max`, and refs must point at existing elements.
- Every Schnorr claim signs `sig_message`. BP+ claim proofs are covered by
  `claims_hash`. So claims cannot be moved to another transaction.
- Refs to consumed notes resolve to state, which makes the claim contextual.

**Examples:**
- "the deposit note is at least the reserve price", without revealing the bid;
- "the payout equals the escrowed note" (Equal);
- "this bid, revealed after the auction closes, was 12.5 BLK" (Reveal).

---

## 9. Execution

### 9.1 Module profile (validated at deploy; consensus)

**Engine:** `wasmi` **2.0.0**, pinned exactly (`=2.0.0`), with:
- `default-features = false`;
- features `std`, `validate` and `deterministic`;
- fuel metering on;
- no `wat`, `simd` or `memory64`.

**Allowed Wasm features:** WebAssembly 1.0 (MVP) plus:
- mutable globals;
- sign-extension operators;
- multi-value;
- bulk-memory (`memory.copy`, `memory.fill` only);
- reference types, limited to one funcref table of ≤ 1 024 entries.

**Forbidden, and rejected at deploy:**
- every `f32`/`f64` type and instruction, including in signatures, globals and locals;
- SIMD, threads, atomics, memory64, multi-memory, tail calls, exceptions, GC;
- a start function;
- passive data or element segments.

**Imports and exports:**
- Imports are allowed only from module `"bs"`, only with names and signatures in the
  host API (§9.3).
- Required exports: memory `"memory"` and a function `"bs_call"` of type `[] → []`.
- Optional export: `"bs_init"` of type `[] → []`.

**Size limits:**
- The module is at most `MAX_CODE` = 65 536 bytes.
- Memory is at most 32 pages (2 MiB); its initial size is ≤ its maximum, and the
  maximum is declared.
- ≤ 1 024 functions, ≤ 1 024 globals, and ≤ 256 locals per function.

The deploy check is our own pass over `wasmparser` output, run *before* wasmi's
validator. The consensus rule is therefore defined by this list, not by whatever a
wasmi version happens to accept.

### 9.2 Calling convention

- A contract reads its call input with `input_len`/`input_read`, and returns data to a
  calling contract with `return_write`.
- To fail, it calls `abort(code)` or traps. Any trap, any failure, running out of fuel,
  or exceeding the storage limit anywhere in the call tree makes the **whole
  transaction invalid**. There is no partial execution and no revert-with-fee, so failed
  calls leave no trace on chain.
- Every function the call tree touches runs in fresh instances. No Wasm memory or
  global persists between calls; only the key–value state, notes and key sets persist.

### 9.3 Host API (module `"bs"`)

Pointers and lengths are `i32` into the calling contract's memory. An out-of-bounds
access traps. All functions are deterministic.

| Group | Function | Semantics |
|---|---|---|
| Input and output | `input_len() → i32`, `input_read(ptr)` | Call input bytes. |
| | `return_write(ptr, len)` | Result returned to the calling contract (≤ 4 096 bytes). |
| | `abort(code: i32)` | Fails the transaction. |
| Context | `height() → i64` | Height of the block containing the call. **Height is the only clock.** |
| | `self_id(ptr)`, `caller(ptr) → i32` | This contract's id; the calling contract's id, or 0 if top level. |
| | `network_id() → i32` | |
| State | `get(kp, kl, vp, cap) → i32` | Value length, or −1 if absent. |
| | `set(kp, kl, vp, vl)`, `del(kp, kl)` | Only in the own namespace. |
| Notes | `consumed_count() → i32`, `consumed(i, ptr)` | Consumed notes owned by *this* contract (record, §9.4). |
| | `created_count() → i32`, `created(i, ptr)` | New notes owned by *this* contract. |
| | `approve(i)`, `accept(i)` | Approves consumed note `i` or accepts new note `i`. |
| Facts | `auth_count()`, `auth_key(i, ptr)`, `auth_has(ptr) → i32` | Verified auth keys. |
| | `claim_count()`, `claim(i, ptr)` | Verified claims (record, §9.4). |
| | `member_count()`, `member(i, ptr)` | Verified membership proofs whose `owner` is this contract. |
| Key sets | `keyset_add(set, ptr) → i32`, `keyset_len(set) → i32`, `keyset_get(set, i, ptr)` | Append-only; `keyset_add` traps on invalid or identity points. |
| Utilities | `hash(ptr, len, out)` | `H32("contract/user-hash", data)`. |
| | `point_valid(ptr) → i32` | Canonical, non-identity Ristretto point. |
| Calls | `call(id_ptr, in_ptr, in_len) → i32` | Calls a contract in the access list. It returns only on success, with the result length; the result is read with `result_read(ptr)`. |

**Call rules:**
- Call depth is at most 4.
- **Reentrancy is impossible:** calling a contract that is already on the call stack
  traps, so the reentrancy class of bugs (e.g. the 2016 DAO) cannot occur.

**After the top-level call returns, the host checks:**
- every consumed note was approved by its owner;
- every new note was accepted by its owner;
- every owner of a consumed or new note was executed in this call tree.

Otherwise the transaction is invalid. Value cannot enter or leave a contract that did
not explicitly agree.

### 9.4 Records passed to contracts (fixed layouts)

```
note record (200 bytes): id 32 ‖ type u8 ‖ policy_len u8 ‖ policy 64 (zero-padded) ‖
                         height u64 ‖ amount u64 (public; 0 for private) ‖
                         O 32 (private; zero for public) ‖ Cm 32 ‖ index-in-tx u16 ‖ pad 6
claim record (96 bytes): kind u8 ‖ ref_tag u8 ‖ ref_index u16 ‖ ref2_tag u8 ‖ pad 1 ‖
                         ref2_index u16 ‖ min u64 ‖ max u64 ‖ value u64 ‖ C 32 ‖ pad 16
member record (80 bytes): set_id u32 ‖ ring_size u8 ‖ scope_len u8 ‖ pad 2 ‖ scope 32 ‖ tag 32 ‖ pad 8
```

The implementation freezes the exact layouts, with SDK types and golden tests, before
activation.

### 9.5 Fuel

**Instructions:**
- Wasm instructions cost wasmi 2.0.0's default fuel schedule (`FuelCosts` defaults),
  which is part of consensus through the exact version pin (§16.3).
- Memory growth costs 4 096 fuel per page.

**Host calls:** each costs `100 + 1 per byte copied`, except:
- `hash`: `2 000 + 10/byte`;
- `set`: `1 000 + 10/byte`;
- `get`: `500 + 1/byte`;
- `keyset_add`: `5 000`;
- `call`: `10 000 + instantiation (1 per code byte)`.

**Budget:**
- `fuel_limit` bounds the whole call tree.
- The fee charges the *declared* limit in full, with no refund. A refund would need a
  post-execution change output, which would break the pre-built balance, and the full
  charge makes fees independent of execution.

### 9.6 Storage accounting

```
entry_size(k, v) = 32 + len(k) + len(v)
used = Σ_touched keys (new entry_size − old entry_size) + 200·(notes created − notes consumed)
     + 36·(keys added to key sets) + len(code) (deploy, if the code blob is new)
```

- Execution fails if `max(used, 0) > storage_limit`.
- The fee charges the declared `storage_limit`.
- Deleting data earns nothing back in v1. That keeps fees independent of state, at the
  price of no incentive to clean up; storage rent is future work (§17).

**Per-contract caps:**
- key–value state ≤ 4 MiB;
- key sets ≤ 65 536 keys per set, 256 sets.

---

## 10. State and its commitment

### 10.1 State

The contract state is:
- the code blobs;
- the contracts (`id → code_hash`);
- the key–value entries;
- the unconsumed notes;
- the key sets.

It is always the result of applying the connected chain's blocks `1..tip` in order,
like the transaction state (blocks.md §6). Each block keeps an undo record, used on
reorganization:
- previous values of written keys;
- created and consumed notes;
- deployed contracts;
- key-set appends.

### 10.2 State root

The state is committed in a sparse Merkle tree of depth 256:

```
path(contract, type, key) = H32("contract/state-key", contract ‖ u8(type) ‖ key)
  type 0 = key–value entry (key = user key), 1 = note (key = note id),
       2 = key-set member (key = LE32(set) ‖ LE32(index)), 3 = contract (key = empty)
leaf  = H32("contract/state-leaf", u8(type) ‖ encoded value)
node  = 0^32                                     if both children are 0^32
      = H32("contract/state-node", left ‖ right) otherwise
root of the empty state = 0^32
```

- Each update costs 256 hashes.
- Implementations store only non-empty nodes.
- The root allows later light-client proofs of contract state (§17).

### 10.3 Commitment in the block

After activation, the **coinbase has `version = 2`** and one extra prefix field,
`state_root` (32 bytes), after its outputs. It is the root **after** applying all of the
block's transactions.
- The coinbase is covered by `tx_root`, so every block header commits to the contract
  state.
- A wrong root makes the block invalid.
- Any nondeterminism between nodes therefore surfaces immediately, in the block where
  it happens, instead of as a silent state split.

The coinbase does not affect the contract state, so there is no circularity.

---

## 11. Validation rules

These add to transactions.md §8. Cheap checks come first. The `is_stateless()`
classification decides P2P penalties (p2p.md §10):
- only K-rule failures are penalized;
- X-rule failures can be honest races.

### 11.1 Stateless (K)

| # | Rule |
|---|---|
| K1 | Strict decode; `size ≤ MAX_TX_SIZE` (100 000); every count and length within §5 limits; sorted lists strictly increasing. |
| K2 | Kind 2 or 3 only after activation; call: `n + c ≥ 1` and (`n ≥ 1` or `k_o ≥ 1`); deploy: `n ≥ 1`, no notes, claims, auth or members. |
| K3 | Inputs, outputs and pseudo-outputs as T4–T7; private new notes as outputs (T6); all points decode; `auth_keys` non-identity. |
| K4 | New notes' owners ∈ {contract} ∪ access; `type ∈ {0, 1}`; public amount > 0. |
| K5 | `fee ≥ min_call_fee` (§12); fee arithmetic checked. |
| K6 | BP+ over the private commitments verifies (T10 rules). |
| K7 | Auth signatures verify. |
| K8 | Claims: known kind, refs in range, `min ≤ max`; proofs over tx-internal refs verify. |
| K9 | Deploy: the module passes §9.1. |
| K10 | Exactly `n` CLSAGs, `u` auth signatures, `q` claim proofs and `w` member signatures, all canonical. |

### 11.2 Contextual (X), against the state before the transaction

| # | Rule |
|---|---|
| X1 | Inputs: C1–C3 of transactions.md. |
| X2 | One-time keys of outputs and private notes are new across outputs *and* notes (C4, extended). |
| X3 | `contract` and every `access` entry exist. |
| X4 | Every consumed note exists and is unconsumed, and its owner ∈ {contract} ∪ access. |
| X5 | `E ≠ identity`, and the kernel verifies (§6.2). |
| X6 | Claims over consumed-note refs verify. |
| X7 | Membership proofs: the key set exists, the indices are in range, and the signature verifies over the pre-state members. |
| X8 | Execution (§9) succeeds within `fuel_limit` and `storage_limit`, and all approvals and acceptances hold. |

### 11.3 Block-level

| # | Rule |
|---|---|
| KB1 | After activation, the coinbase is version 2 and its `state_root` equals the root after the block. |
| KB2 | `Σ fuel_limit ≤ MAX_BLOCK_FUEL`, and `Σ storage_limit ≤ MAX_BLOCK_STORAGE`. |
| KB3 | Transactions are applied in block order; a later transaction sees the state left by earlier ones. |

---

## 12. Fees and limits (provisional; calibrated in M6)

```
min_call_fee = weight · FEE_PER_WEIGHT                      (transactions.md §8.4, weight includes code)
             + ceil(fuel_limit / 1 000) · FEE_PER_KFUEL
             + storage_limit · FEE_PER_STATE_BYTE
```

| Constant | Provisional | Calibration target |
|---|---|---|
| `MAX_CALL_FUEL` | 20 000 000 | One call ≤ 0.1 s on the reference CPU |
| `MAX_BLOCK_FUEL` | 200 000 000 | Execution of a full block ≤ 1 s (≪ T = 120 s); regtest the same |
| `MAX_CALL_STORAGE` / `MAX_BLOCK_STORAGE` | 65 536 / 262 144 | ≤ 262 KB state growth per block (≈ 69 GB/year worst case at T = 120 s; see §16.5) |
| `FEE_PER_KFUEL` | 20 | A call's CPU costs the same per second as a transfer's verification |
| `FEE_PER_STATE_BYTE` | 200 | Persistent bytes cost 10× transient transaction bytes |

M6 benchmarks every host function and a worst-case Wasm instruction mix, and fixes these
values before activation. The reference CPU is a 4-core x86-64 (the labnet machine
class).

---

## 13. Mempool and block templates (policy, not consensus)

**Admission:**
- The mempool accepts a call or deploy if it is valid (K and X) against the tip.
- Key images and consumed notes conflict first-seen-wins, as for transfers.

**Re-execution:**
- Pooled calls re-execute after every tip change.
- To bound that cost: ≤ 1 000 pooled calls in total, and ≤ 32 per target contract.
- A call that no longer executes is dropped, without penalty to the peer that relayed
  it (X failures are contextual).

**Block templates:**
- They take calls by fee per weight and execute them sequentially.
- A call that fails at its position is skipped and dropped.

**Dependent calls:** two calls touching the same contract can both be valid alone, but
not in sequence. The second one then waits or is dropped.

**Access lists:** they let a future version execute non-conflicting calls in parallel.
v1 executes sequentially.

---

## 14. Wallet integration

### 14.1 Scanning

- Wallets scan the outputs *and the private new notes* of every call, with the call
  `ctx` (§5.4) and the full transactions.md §3.3 procedure, including the Janus anchor
  check.
- A recognized note is stored with its `note_id`, owner contract, policy and opening.
- A note consumed by a later call is marked spent, whether or not this wallet consumed
  it: for example, the creator refunding. Consumption is public by note id, so no key
  image is needed.
- Wallet restore from the seed recovers notes like outputs.

### 14.2 Keys

```
auth key    k = Hs("wallet/contract-auth",   k_s ‖ contract_id ‖ LE32(role) ‖ LE32(i)),  K = k·G
member key  x = Hs("wallet/contract-member", k_s ‖ contract_id ‖ LE32(set)  ‖ LE32(i))
```

Keys are fresh per contract, role and index, so nobody can link them across contracts.
They can be recovered from the seed.

### 14.3 Fingerprint hygiene (wallet policy)

- Round `fuel_limit` and `storage_limit` up to the SDK's standard buckets (powers of
  two).
- Pay the resulting standard fee.
- Produce ≥ 2 outputs when possible.
- Use the gamma decoy selection for inputs.
- Submit through the own node: dry-run execution is available only on the loopback RPC
  (§15.4).

### 14.4 RPC additions (loopback only)

- `/contract/{id}`: code hash, state size.
- `/contract/{id}/state?key=`: one value.
- `/contract/{id}/notes`: unconsumed notes.
- `/contract/{id}/keyset/{set}`: members.
- `POST /contract/simulate`: dry-run a call against the tip; returns fuel and storage
  used.

---

## 15. Privacy model

### 15.1 Hidden

| Property | Mechanism | Against |
|---|---|---|
| Who called | CLSAG inputs (1 of 16), or no inputs at all | any observer (DDH) |
| Who receives contract payouts | Payouts are ordinary stealth outputs | anyone without the view key |
| Private note beneficiaries | Stealth construction and Janus anchor | same |
| Amounts of private notes and outputs | Pedersen commitments and BP+; claims reveal only the proven predicate | everyone |
| Links between a user's contracts | Fresh auth and member keys per contract (§14.2) | everyone |
| Which member acted | Scoped membership (1 of `r`) | everyone (DDH) |

### 15.2 Public

- Which contract was called; the access list; the call input bytes; fuel and storage
  limits; fee; time.
- Contract code and all contract state, including stored keys and used membership tags.
- Which notes were consumed, so a note's creation and consumption are linkable, though
  not to people.
- Public note amounts.
- Predicates proven by claims, and revealed values.
- The number of inputs, outputs, notes, claims and auth keys.

### 15.3 Linkage risks and guidance

| Risk | Guidance |
|---|---|
| Call input contains identifying data | SDK encodes typed arguments; never put addresses or names in input. |
| Reusing an auth key links calls | Wallet keys per role; use membership proofs for repeated anonymous actions. |
| Note creation → consumption timing | Unavoidable for a given note; beneficiaries can wait and batch. |
| Fee and fuel fingerprinting | Standard buckets (§14.3). |
| Small ring sizes in membership proofs | Contracts should require 16, or the full set. |
| Public pools reveal flows | Amounts in and out of a public note are visible; who is not. Use private notes wherever the logic allows. |
| MEV / front-running | Callers are anonymous and Dandelion++ hides origin, but pending calls are public. Contracts exposed to ordering (auctions, pools) should use commit–reveal or batch settlement. |

### 15.4 Node-side leakage

- `/contract/simulate` on a remote node reveals intent, so it is served on loopback
  only.
- Wallets fetch contract state from their own node.

---

## 16. Security analysis

### 16.1 Guarantees (under transactions.md §9 assumptions, pending review)

| Guarantee | Argument |
|---|---|
| No inflation | §6.3 Claim 1 |
| Notes consumed only by openers, and only with owner approval | §6.3 Claim 2; §9.3 approval check |
| Non-malleability | §6.3 Claim 3 |
| No double consumption | Consumed notes are removed; conflicting txs cannot both be valid; `ctx` unique |
| No cross-network replay | `network_id` in `sig_message` |
| No reentrancy | Host traps on reentrant calls (§9.3) |
| Atomicity | Any failure invalidates the whole transaction (§9.2) |
| Deterministic execution | §16.3 |
| Bounded resources | §9.1 module limits, §9.5 fuel, §9.6 storage, §12 block caps |

### 16.2 Attack scenarios (each becomes a test)

| # | Attack | Defense |
|---|---|---|
| S1 | Consume a note without knowing its opening | Kernel (X5) cannot be produced (Claim 2) |
| S2 | Consume a private note you can open but are not authorized for (creator front-running beneficiary) | Owner code must check auth (policy); SDK patterns; escrow example tests it |
| S3 | Deposit value into a contract that does not expect it | Acceptance check (§9.3) |
| S4 | Drain a contract through reentrancy | Reentrant call traps |
| S5 | Change outputs of a pending call (burn or steal) | Every signature covers `sig_message` |
| S6 | Replay a claim or membership proof in another transaction | Proofs bound to `sig_message` / `claims_hash` |
| S7 | Vote twice anonymously | Contract stores the scope tag; same key gives same tag |
| S8 | Frame another member's tag | Non-frameability of the linkable ring signature |
| S9 | Float NaN or engine nondeterminism | Floats rejected at deploy; `deterministic` feature; state root in every block |
| S10 | Infinite loop, memory bomb, deep recursion | Fuel; 2 MiB memory; wasmi stack limits (pinned) |
| S11 | State bloat | Storage fees, per-call, block and contract caps |
| S12 | Mempool CPU exhaustion via calls that become invalid before inclusion | Pool size and per-contract caps (§13); re-execution is fuel-bounded; stateless-invalid calls are penalized at relay. **Residual risk:** calls that are valid alone but conflict cost CPU without paying fees. M6 measures this under labnet load. |
| S13 | Malformed module crashing the node | Own profile pass plus wasmi validation; fuzzing (§20) |
| S14 | Amount overflow | Checked `u64`/`u128` arithmetic; BP+ ranges; the no-wrap bound (§6.1) |
| S15 | Burning bug in notes | Unique `ctx`; `O` uniqueness across outputs and notes (X2) |
| S16 | Janus probe through a note | Anchor check at scan (§14.1) |

### 16.3 Determinism and the engine dependency

- **Why wasmi is safe to depend on:**
  - It is a pure-Rust interpreter with no JIT, so there is no generated machine code.
  - It is maintained by wasmi-labs and used by Substrate/Polkadot contracts.
- **Its internal `unsafe`** (performance paths in the executor) is outside our
  `forbid(unsafe_code)` rule. It must be reviewed before activation (M2 deliverable:
  dependency review in AUDIT.md).
- **Consensus pins everything that affects results:**
  - the version (`=2.0.0`);
  - the feature set;
  - the fuel schedule;
  - the stack limits;
  - the module profile (§9.1).
- **Upgrading wasmi is a consensus change.** It needs an activation height and golden
  tests with fixed fuel counts for a corpus of modules.
- **The state root in every block** turns any residual nondeterminism into an
  immediately detected block rejection, rather than a silent fork.

### 16.4 External review items

- The kernel argument (§6.3), especially Claim 2's extractability argument with BP+.
- The fixed-base linkable ring signature (§7.2).
- Range claims with two aggregated commitments (§8).
- The host API's approval and acceptance logic, and the fuel schedule.
- The prior-art check (§3).

### 16.5 Known limitations

- Contract code and state are public (§1 non-goals).
- Contracts cannot branch on hidden amounts beyond proven predicates.
- Note creation and consumption are linkable to each other.
- There is no storage rent, so worst-case state growth is bounded only by fees and caps.
- A persistent state store is required: the node keeps state in memory today (R4 open
  items).
- Not post-quantum (transactions.md §11.6).

---

## 17. Roadmap: ZK-ready by design

- **Proof-system claims** (kinds 128–255). A later, height-activated upgrade can add a
  verifier, preferably without trusted setup (e.g. a Halo2- or Plonk-style system in
  pure Rust). Claims then carry `(verifier_id, vk_hash, public_inputs, proof)`, and
  contracts consume the verified public inputs as facts. The contract model does not
  change: contracts already decide over verified facts, not secrets. This is the path to
  option B (private execution).
- **Confidential tokens (v1.1).**
  - Assets carry their own value generator `H_t = Hp("asset", contract ‖ token_id)`,
    with blinded asset tags as in *Confidential Assets* (Poelstra et al., 2017).
  - Balance is enforced per asset, with issuance approved by the token's contract.
  - The note format reserves the type byte for this.
- **Private contract state:** encrypted state entries, readable by key holders and
  updatable via proof-system claims.
- **Parallel execution:** schedule non-overlapping access lists concurrently.
- **Light clients:** SMT proofs against the coinbase `state_root`.
- **Storage rent / deposits**, once state growth data exists.

---

## 18. Activation

- `ChainParams` gains `contracts_height: Option<u64>`: `None` means disabled.
- Before that height: kinds 2 and 3 are invalid, and the coinbase is version 1.
- From that height: calls and deploys are valid, and the coinbase is version 2.
- Regtest activates at height 1.
- For the testnet, one of:
  - a **fork height** chosen when the implementation is complete, if the current
    testnet is live by then;
  - or the contracts ship with a **testnet reset** (new network id and genesis), if the
    multi-machine trial leads to a reset anyway.

The choice is made at release time. Mainnet requires the external review (§16.4).

---

## 19. Implementation plan

**Crates:**

| Crate | Content |
|---|---|
| `crypto` (extend) | Schnorr (kernel, auth, claim-eq, claim-val); fixed-base linkable ring signature; BP+ over arbitrary commitments (already general) |
| `contracts` (new, `blacksilk-contracts`) | Formats and codec; module profile check; wasmi engine and host; fuel and storage accounting; state (KV, notes, key sets, code), undo, SMT root |
| `tx`, `chain` (extend) | Kinds 2 and 3; validation K/X/KB; coinbase v2; activation; mempool and template policy |
| `contract-sdk` (new, `no_std`, wasm32) | Safe typed bindings to the host API; argument codec; auth and membership helpers; the fixed record layouts |
| `contracts/examples` | Escrow with arbiter and timeout; vesting / timelock; anonymous voting (scoped membership); confidential multisig treasury (shared view address plus k-of-n auth); sealed-bid auction (range + reveal claims) |
| `wallet`, `rpc`, `node` (extend) | Note scanning; call builder; CLI commands; RPC endpoints (§14.4) |

**Milestones.** Each ends green: fmt, clippy with `-D warnings`, all tests.

| # | Deliverable |
|---|---|
| M1 | Crypto additions with known-answer and adversarial tests |
| M2 | `contracts` core: profile check, engine, host, state + SMT, undo; wasmi dependency review |
| M3 | Chain integration and activation; mempool and templates; reorg tests with state |
| M4 | SDK and the 5 example contracts, built for `wasm32-unknown-unknown`, with scenario tests |
| M5 | Wallet and RPC; end-to-end: deploy → deposit → claim-gated release → payout found by fresh-wallet restore |
| M6 | Benchmarks and limit calibration; fuzzing; labnet with contract traffic; AUDIT.md R7; this spec to v1 |

---

## 20. Test plan (acceptance criteria)

1. **Crypto:**
   - Schnorr and fixed-base linkable ring signatures: sign/verify at every index.
   - Every single-field mutation is rejected.
   - Same key and scope give the same tag; different scopes give unlinkable tags.
   - Identity tags are rejected.
   - Range, equality and reveal claims: correct statements pass; off-by-one bounds,
     wrong refs and wrong values fail.
2. **Formats:**
   - Round-trips.
   - Every K rule has a negative test.
   - Non-minimal varints and trailing bytes are rejected.
3. **Balance:**
   - Inflation attempts are rejected: outputs over inputs, a forged note, a public
     amount mismatch.
   - A kernel with `E = identity` is rejected.
   - Consuming someone else's private note without its opening fails (S1).
4. **Execution:**
   - Each forbidden Wasm feature is rejected at deploy (a float, a start function,
     foreign imports, oversize code, excess memory).
   - Fuel exhaustion, memory growth and deep recursion trap deterministically.
   - Reentrancy traps.
   - Unapproved or unaccepted notes invalidate the transaction.
   - Golden fuel counts for a fixed corpus.
5. **State:**
   - Apply and undo round-trips restore the exact root.
   - Reorgs across calls restore state and return calls to the mempool.
   - The SMT root matches a reference implementation.
   - A wrong `state_root` rejects the block.
6. **Example contracts:** full lifecycle and every abuse path (S2, S3, S7), including
   refund after timeout, double vote and front-running.
7. **Privacy:**
   - Call outputs are byte-shape identical to transfer outputs.
   - Private notes pass the Janus probe tests A1–A10.
   - Fresh-wallet restore finds notes.
   - Fee buckets are applied.
8. **Adversarial / fuzz:**
   - Decoder fuzzing.
   - Module fuzzing (random modules must never panic the node).
   - Random call sequences with supply conservation (Σ outputs + Σ notes = generated).
9. **Network:** labnet runs with contract traffic, with state-root agreement across all
   nodes.

---

## 21. Decisions requested before implementation

1. **Approve the model:**
   - anonymous callers with no `msg.sender`;
   - declared value effects approved by contracts;
   - private and public notes;
   - claims;
   - scoped membership.
2. **Approve the atomic-failure rule** (§9.2): failed calls are invalid and pay no fee.
   The alternative, fees charged on failure, would leak failed attempts on chain and
   complicate the balance.
3. **Approve the v1 scope:** native BLK only; confidential tokens in v1.1.
4. **Activation:** fork height or testnet reset, decided at release (§18).
