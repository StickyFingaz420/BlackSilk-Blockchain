# PX: private records, nullifiers and the transfer kernel

Status: **v0.4, implemented and tested, integrated into consensus (transaction kinds 2 and 3), with contract tooling and record distribution (§13); not production-ready.**
- Architecture: [`zk.md`](zk.md) §4–§6.
- Virtual machine: [`zkvm.md`](zkvm.md).
- Progress and findings: AUDIT.md R8.

This document specifies what the code in `px-core/` (crate `blacksilk-px-core`) and
`px/` (crate `blacksilk-px`) implements: the hash `Hk`, keys, records, nullifiers, the
commitment tree, the kernel and its proofs, contract records and functions in one
unified proof (§7), the consensus state, record delivery, the consensus integration
(§11), privacy guidance (§12), and contract tooling with the distribution of contract
records (§13). §10 lists what is **not**
done and what must be reviewed externally before any production use. The internal
security review is `docs/reviews/zk-security-review.md`.

---

## 1. Design in one paragraph

A private transfer spends two records and creates two, all hidden. It publishes
- two nullifiers, which mark the spent records without identifying them;
- two new commitments;
- a recent tree root (the anchor);
- the public bridge amounts;
- one STARK proof.

The proof shows that a fixed RISC-V program, the **kernel**, ran on a private witness
and accepted it. The kernel is ordinary Rust (`px-core/src/kernel.rs`), compiled once
for the zkVM and once natively. Nodes, wallets and the proven program therefore run
the same code; there is no separate circuit that could disagree with the specification.

## 2. `Hk`, the hash of PX

`Hk` is built on Poseidon2 over BabyBear, width 16, with the standard parameters (S-box
x^7, 8 full and 13 partial rounds, Plonky3's constants). It is the **same permutation**
that secures the proof system's Merkle trees and Fiat–Shamir transcript, and the one the
zkVM's `POSEIDON2` syscall constrains.

**Sponge** (`px-core/src/hash.rs`):
- rate 8 (state words 0..8), capacity 8 (words 8..16);
- the capacity starts as `[domain, length, 0, …]`, so each use and each input length
  is a distinct function (no padding ambiguity);
- 8 input elements are added into the rate per permutation;
- the digest is the rate after the last permutation: 8 elements, ~248 bits.

**Tree nodes** use the one-permutation compression `node(l, r) = P(l ‖ r)[0..8]`. This
is the construction of Plonky3's own Merkle trees (`TruncatedPermutation`). It is
separated from the sponge because every sponge input has a nonzero domain constant in
word 8. A node input has there the first element of a right child: a collision across
the two would need a digest ending in `[domain, len, 0, 0, 0, 0, 0]`, a 2^−186 event.

**Domains:** `SK, NK, AK, OWNER, DIVERSIFIER, RECORD, NULLIFIER, RHO, IO,
NULLIFIER_CONTRACT` = `0x505800 + 1..10`. Applications (such as the example vault's lock
hash) use their own constants outside this range.

**Security:** the sponge `Hk`: 124-bit collision and preimage resistance, if the
permutation behaves ideally. The node compression is **not** collision resistant on its
own (an invertible public permutation with no feed-forward, R2-C6): the commitment
tree's extractability rests on zk.md §9.3's ePrint 2026/089 argument and its adaptation
("argued, not proven"), zk.md §4.5. Never reuse `node()` in a tree with free leaves or
variable depth.
- *Decision DR-4 (outcome):* no extra rounds. `Hk` uses the standard instance because
  the proof system already depends on it; a stronger `Hk` alone would not raise the
  security of the whole system.
- Poseidon2 over 31-bit fields is young and under active cryptanalysis. It is the
  **first item for external review** (§10).

## 3. Keys, records, nullifiers

```text
sk      = the spend secret of a PX account           wallet-side derivation, §3.1
nk      = Hk(NK, sk)            ak = Hk(AK, sk)
d_i     = Hk(DIVERSIFIER, sk ‖ i_lo16 ‖ i_hi16)      address i
owner_i = Hk(OWNER, ak ‖ nk ‖ d_i)
cm      = Hk(RECORD, owner ‖ contract ‖ asset ‖ value as four 16-bit limbs ‖ data ‖ rho ‖ rcm)
nf      = Hk(NULLIFIER, nk ‖ rho ‖ cm)
rho'_j  = Hk(RHO, nf_0 ‖ j)                          output j of a transfer
```

- **Ownership is hash-based.** Spending proves knowledge of `sk`: no discrete
  logarithms, so it survives a quantum adversary.
- **Addresses are unlinkable.** Different `d_i` give unrelated `owner_i`, and delivery
  keys are per address (§6).
- **Nullifiers are unique.**
  - `rho` of every created record derives from the first nullifier of its transaction,
    and nullifiers never repeat on chain. So two records never share `rho`, which
    prevents the Zcash "Faerie Gold" attack.
  - `nf` also covers `cm`.
- **Nullifiers are unlinkable** to commitments without `nk` (PRF assumption on `Hk`).
- **Contract-owned records** (`contract ≠ 0`, `owner = 0`) hold contract state (§7).
  Their nullifier is `Hk(NULLIFIER_CONTRACT, contract ‖ rcm ‖ cm)`.
- `asset = 0` everywhere (BLK only in this version); the kernel fixes it.

### 3.1 Wallet key derivation and the viewing hierarchy (not consensus)

The kernel takes `sk` and `d` as witnesses. It derives `ak` and `nk` from `sk` and never
recomputes `d`. How a wallet derives `sk`, `d_i` and the delivery keys of address `i` is
therefore wallet policy (reviews R11-W2, R11-W3, I2-R1; dossier 37). Seed format v1
(blocks.md §10) fixes exactly one derivation:

```text
root   = Hk(SK, master as sixteen LE 16-bit limbs)    master: blocks.md §10
sk_a   = Hk(SK_ACCOUNT, root ‖ a_lo16 ‖ a_hi16)        hardened PX account a
nk = Hk(NK, sk_a)   ak = Hk(AK, sk_a)   owner_i = Hk(OWNER, ak ‖ nk ‖ d_i)
dk     = Hk(DIV_KEY, sk_a)                ivk   = Hk(IVK, sk_a)
k      = i >> 16                          (range k holds indexes k·2^16 .. (k+1)·2^16)
dk_k   = Hk(DIV_RANGE, dk ‖ k_lo16 ‖ k_hi16)
ivk_k  = Hk(IVK_RANGE, ivk ‖ k_lo16 ‖ k_hi16)
d_i    = Hk(DIVERSIFIER_V2, dk_k ‖ i_lo16 ‖ i_hi16)
delivery keys of i = DeliveryKeys::derive(ivk_k, i)
hk_px  = H32("px/wallet/hedge-key/v1", sk_a as eight LE32 limbs)   hedge key (transactions.md §10)
```

- **Accounts are hardened** (`Account::account`): `sk_a` needs `root`, and `root`
  never enters a witness. A prover given the witness of account `a` learns `sk_a`
  only, not the other accounts. Accounts have unrelated `nk`, so spend visibility does
  not cross accounts. The wallet uses account 0 only; more accounts are a later
  wallet feature (the scanner and the record store hold one account today).
- **Ranges inside an account are not a spend boundary.** `nk` is account-wide: a
  `RangeViewKey` holder who learns the opening of a record of another range of the
  same account (for example from the payer who created it) computes its nullifier and
  sees its spend (dossier 37 F37-3). Every address the wallet hands out today lies in
  range 0, so `range_view(0)` covers the whole account.
- The domains are wallet-side constants in their own block
  (`blacksilk_px::wallet::key_domain`, `0x0050_5A01..06`), apart from the consensus
  domains (`0x0050_5801..0A`). A future consensus domain must not reuse that block.

**Disclosure** (library API; there is no CLI export or watch-only scanner yet):

| Package | Contents | Sees | Cannot |
|---|---|---|---|
| `RangeViewKey` (`Account::range_view(k)`, `Wallet::px_range_view`) | `ak, nk, dk_k, ivk_k` | Records received in range `k` **and their spends** (`nk`); spends of any record of the account whose opening it learns elsewhere | Spend (needs a preimage of `ak`); derive the addresses of other ranges |
| `IncomingViewKey` (`RangeViewKey::incoming(n)`) | `ivk_k` and the owner tags of the first `n` addresses of range `k` | **Every record sent to any address of range `k`** (all 2^16): `ivk_k` derives the delivery keys of the whole range, so it decrypts value, data and `rcm` of each, and fully accepts contract records at any of them. The owner tags only limit which *user* records it accepts as the wallet's | See spends (no `nk`); spend |

The `IncomingViewKey` is range-wide, not address-scoped (dossier 37 F37-2). An
address-scoped incoming package (per-address delivery secrets, without `ivk_k`) is
planned (K4, P1). Until then, give an `IncomingViewKey` only to someone allowed to see
the whole range.

Security requirement (I2-F2): a `RangeViewKey` holder can recompute owner tags. A
program that accepts "these records are mine" from owner tags alone, without proof of
`sk`, would let every such holder act as the owner. Such programs must be rejected at
design review.

**Removed at the v3 reset:** the flat derivation 1 (`d_i = Hk(DIVERSIFIER, sk ‖ i)`,
delivery keys from `sk`), the 24-word seed and wallet files of versions 1 and 2. No
v3-chain wallet used them. `blacksilk_px::wallet::Derivation::V1` stays in the px
library, where its own tests and tools use it; the wallet never derives with it.

**Not done:** per-period range allocation (every address used today lies in range 0);
multiple PX accounts in the wallet; a separate authorization key (R11-W4, consensus).

Tests:
- `px/src/wallet.rs` `derivation_tests`: V2 keeps `sk`, `ak` and `nk`; range views
  derive their range only; a record opens with the incoming view; the native kernel
  accepts a V2 spend and rejects one with the wrong derivation's `d` (no proof is
  generated); accounts are unrelated and hardened; the hedge key is not `sk`.
- `wallet/tests/seed_vectors.rs`: seed words, `master`, `k_s`, `k_v`, `hk_v1`, `root`,
  `sk_0`, `sk_1`, `nk`, `ak`, `hk_px`, owner tags and the vault secret against the
  independent script `tools/vectors/seed_v1.py`.

## 4. The transfer kernel

### 4.1 Statement

A proof of the kernel program shows that a witness exists for which all of the
following hold. For each input `i ∈ {0, 1}`:
1. **Ownership:**
   - **User record** (`contract = 0`): `nk, ak` derive from the witness `sk`, and
     `owner = Hk(OWNER, ak ‖ nk ‖ d)`. The record is rebuilt with this owner, so only
     the holder of `sk` can spend a record paid to one of its addresses.
   - **Contract record:** `owner = 0`, and a called function of that contract approves
     exactly this commitment (§7).
2. `cm_i` = the commitment of that record.
3. Membership:
   - **Real input:** the depth-32 path from `cm_i` at `position_i` reaches `anchor`.
   - **Dummy input:** a user record of value 0. Its path is still hashed.
4. Nullifier:
   - user: `Hk(NULLIFIER, nk ‖ rho_i ‖ cm_i)`;
   - contract: `Hk(NULLIFIER_CONTRACT, contract ‖ rcm_i ‖ cm_i)`;
   - and `nf_0 ≠ nf_1`.

For each output `j ∈ {0, 1}`: `rho'_j = Hk(RHO, nf_0 ‖ j)`, and `cm'_j` is the
commitment of the output record. A contract output (`contract ≠ 0`) must have
`owner = 0` (PX-F5, testnet v3; `ContractOutputOwner`): contract records are spent by
function approval, never by an owner, so one with an owner could never be spent. The
function rules of §7.2 apply.

Balance, over the integers (`u128`):
`Σ value_i + bridge_in = Σ value'_j + bridge_out`.
- There is no field arithmetic in the balance: the guest computes with ordinary
  integer instructions, which the zkVM proves exactly.
- So the classic ZK inflation bug (a sum wrapping modulo p, zk.md §6.4) cannot occur.
- A test tries exactly that wrap and is rejected.

### 4.2 Witness and outputs

Witness words, in reading order (`kernel::Witness::write`), `VERSION = 2`:

```text
VERSION ‖ anchor[8] ‖ bridge_in(lo, hi) ‖ bridge_out(lo, hi) ‖ n_fn
per function: contract[8] ‖ blind[8] ‖ approve[2] ‖ per output slot: present ‖ owner[8] ‖ contract[8] ‖ value(lo, hi) ‖ data[8]
per input:    dummy ‖ contract[8] ‖ sk[8] ‖ d[8] ‖ value(lo, hi) ‖ data[8] ‖ rho[8] ‖ rcm[8] ‖ position ‖ path[32][8]
per output:   owner[8] ‖ contract[8] ‖ value(lo, hi) ‖ data[8] ‖ rcm[8]
```

- Every element read as a field element must be canonical (`< p`), or the kernel
  rejects the witness.
- Flags must be 0 or 1.

The public output is `46 + 16·n_fn` words:

```text
VERSION ‖ anchor[8] ‖ nf_0[8] ‖ nf_1[8] ‖ cm'_0[8] ‖ cm'_1[8] ‖ bridge_in(lo, hi) ‖ bridge_out(lo, hi) ‖ n_fn ‖ per function: contract[8] ‖ io_hash[8]
```

On rejection the guest halts with the error's exit code:

| Exit | Error | Exit | Error |
|---|---|---|---|
| 2 | Version | 10 | ZeroContract |
| 3 | NonCanonical | 11 | Unauthorized |
| 4 | NotBoolean | 12 | ApprovalMismatch |
| 5 | DummyWithValue | 13 | SpecMismatch |
| 6 | NotInTree | 14 | SpecForeignContract |
| 7 | DuplicateNullifier | 15 | SpecConflict |
| 8 | Unbalanced | 16 | DummyContract |
| 9 | TooManyFunctions | 17 | ContractOutputOwner (PX-F5) |
| | | 18 | ApprovalConflict (F-20-1, testnet v3) |

Codes are append-only: a new rule gets the next code, so an exit code means the same
rule in every kernel build (`px/tests/unified.rs::kernel_exit_codes_are_append_only`).

A panic halts with exit code 1. **A proof is valid only for exit code 0**; the verifier
fixes it.

### 4.3 Proof

`prove::verify(public, calls, window, h_tx, proof, registered)` verifies a BVM-1 proof
of the multi-execution statement:
- the kernel program, with exit code 0 and the public words;
- one execution per called function (§7), each writing the function prefix built from
  its registered ABI, the kernel's `(contract, io_hash)` and the transaction's validity
  `window` (§7.2);
- all bound to `h_tx`.

`verify_transfer` is the case without functions.
- `h_tx` is the transaction hash (zk.md §5.2). It enters the proof's public values and
  transcript, so a proof cannot be moved to another transaction.
- **The kernel program is pinned** (`px/kernel.elf`). Its id, the zkVM program hash, is
  `px/kernel.id`, and a test checks that they match.
  - Rebuilding with `zkvm/guests/build.sh` on the same toolchain reproduced the ELF
    byte for byte.
  - The ELF depends on the rustc version, so consensus must pin the id, never "whatever
    the source compiles to".
- The prover first runs the kernel natively and refuses to prove a rejected witness
  (with the precise error). It then checks that the guest's output equals the native
  result.

### 4.4 Fixed shape (trace-shape privacy)

**Every PX proof has a fixed shape.**
- The kernel has a public row budget for each function count
  (`prove::kernel_budget`), and every registered function has its own
  (§11.2).
- The prover pads each table to the height its budget implies, and the verifier
  accepts only exactly that shape (zkvm.md §8).
- So the table heights and the proof size reveal only which programs ran, never
  what they did: not the dummies, the record kinds, the positions, the amounts, or
  a function's execution path or length.
- An execution that needs more rows than its budget cannot be proven. It fails
  loudly; it never leaks. The prover checks each execution against its own budget in
  every table before proving (`TransferError::OverBudget`): the shared ALU and
  Poseidon2 tables are padded to a power of two of the budgets' sum, so without the
  check an over-budget execution would be provable or not depending on the other
  calls' budgets (RTW1C-1).
- The kernel's budgets cover every shape it accepts: `px/tests/kernel_budget.rs`
  enumerates every input kind (user, dummy, two contracts), output kind, function
  contract and approval and specification pattern for 0, 1 and 2 functions and checks
  that each table stays at or below 95% (RTW1C-1: the earlier sample missed the
  shapes with specified contract outputs, which exceeded the one-function `bit`
  budget). The budgets are prover and verifier parameters, in the consensus
  fingerprint (`px.kernel.BUDGET.n_fn_*`), not part of the kernel ELF. Another test
  (`px/tests/proof.rs`) checks that a deposit and a payment have identical **proof**
  shapes (degree bits and every witness-independent length). Their public statements
  still differ: a deposit shows `bridge_in`, a withdrawal `bridge_out` and its payout,
  and the v1 inputs show who funds the transaction (§12).
- **Byte length** (privacy review P-5). Field elements are always 4 bytes (Plonky3
  writes them fixed-width), so values never change the length. What varies is the
  Merkle opening proof: FRI opens its queries with pruned paths, and the number of
  distinct nodes depends on where the queries land. The query positions are public
  (every verifier recomputes them from the proof) and are drawn by Fiat–Shamir over
  hiding commitments, so they are distributed identically for every witness.
  - **Measured:** 6 transfer proofs of different witnesses were 2,029,768–2,046,856
    bytes (a 0.84% spread).
  - Everything outside the opening proof was 129,898 bytes in each.

The constant-work design below remains as defence in depth:

The proof's table heights are public (zkvm.md §8).
- The kernel is written so that successful executions run the same instructions up to a
  few branch-dependent ones: membership is accumulated without early exit, the path
  order is selected with masks, and digests are compared without early exit.
- Both owner forms and both nullifier forms are computed for every input, so the
  record kind (user or contract) does not change the work.
- **Measured (kernel v2):**
  - 24 990–25 211 cycles over real, dummy and bridge witnesses without functions;
  - 29 314–29 356 cycles with one function, for contract and user inputs alike.
- All table heights were identical within each group (tests
  `successful_executions_have_identical_trace_heights` and
  `record_kinds_are_not_revealed_by_trace_heights`).
- **Margin:** fixed budgets (above) made heights independent of the witness, which
  resolved security review R-5. `px/tests/kernel_budget.rs` keeps every accepted
  kernel shape, and `budgets_leave_headroom` every vault entry, at or below 95% of
  each budget.

## 5. Consensus state (`px/src/state.rs`)

| Component | Rule |
|---|---|
| Tree | Append-only frontier: 32 digests plus the size. Commitments are appended in block order, one leaf per output commitment (two per transfer today). Capacity `CAPACITY = 2^32` leaves: a block whose commitments would exceed it is invalid (B8, transactions.md §8.3; testnet v3). The append that fills the tree keeps the full root, which the frontier returns at `size = CAPACITY` (21-D; below capacity every root is unchanged). Once full, the tree takes no more PX outputs until a new-tree epoch is designed. |
| Root window | The roots after each of the last 100 blocks (initially the empty-tree root). A transfer's anchor must be one of them. Anchors never refer to a state inside the current block. |
| Header root | Every block header carries the root after the block as `px_root` (rule B-PXR, transactions.md §8.3; the genesis header the empty tree's root, `EMPTY_PX_ROOT`): the root it adds to the window, so a list of commitments can be checked against one header (testnet v3, reviews/v3-consensus-changes.md#output-root). |
| Nullifier set | A nullifier can appear once, ever: across blocks, within a block, and within a transfer. |
| Pool | `pool' = pool + bridge_in − bridge_out ≥ 0`, applied in order, as `u128`. Even a complete proof-system break cannot withdraw more than was deposited (containment, zk.md §4.7). |

- Blocks apply atomically: one bad transfer leaves the state untouched.
- `apply_block` returns an undo record that restores the previous state exactly. The
  record keeps only what it cannot recompute (21-F): the frontier before the block if
  the block appended (boxed), the root the block's own root pushed out of the window,
  the pool and the inserted nullifiers; under 100 bytes for a block without PX
  transfers, instead of about 4.2 KB for every block. A seeded property test compares
  it with a full clone of the state over random apply, failed-apply and undo sequences
  (`compact_undo_equals_the_full_clone_reference`).
- Proofs are verified before these rules. The state sees only verified statements.

This state is part of the chain state (`blacksilk_tx::state::MemoryChain`, §11.3),
replayed from the stored blocks on start, with the same per-block undo.

## 6. Record delivery (`px/src/delivery.rs`)

Each output carries its record encrypted to an address. The ciphertext is 1,241 bytes:

```text
R (32) ‖ view tag (1) ‖ ML-KEM-768 ciphertext (1088) ‖ ChaCha20-Poly1305(contract ‖ value ‖ data ‖ rcm) (104 + 16)
key = H32("px/delivery-key/v2", r·V ‖ ss_kem ‖ R ‖ ct_kem ‖ V ‖ H(ek) ‖ cm)
      H(ek) = H32("px/delivery-ek", ek)                            AAD = cm, nonce 0 (fresh key)
```

- **User records** (`contract = 0`) go to their owner's address.
- **Contract records** (`contract ≠ 0`, owner 0) go to the party that will act on them
  (§13).
- The plaintext has one length for both kinds, so the ciphertext does not reveal the
  kind.
- **Consensus fixes** the length and one property of `R`: it must be a canonical
  ristretto255 encoding (RFC 9496) of a point other than the identity
  (`check_ciphertext_r` in `tx/src/px.rs`; `PxCiphertextRNonCanonical`,
  `PxCiphertextRIdentity`, both stateless; testnet v3,
  reviews/v3-consensus-changes.md#px-ciphertext-r). Nothing else is checkable: the
  view tag is a hash byte, every 1,088-byte string is a well-formed ML-KEM-768
  ciphertext, and the body is pseudorandom. The rule forces every wallet, dummy outputs
  included, to publish a real group element: a random 32-byte `R` decodes with
  probability about 1/16, so without the rule a wallet filling `R` with random bytes
  would be recognizable. `seal` meets it by construction (`r ≠ 0`); `open` treats an
  `R` that does not as not addressed to the wallet. `R` is not in the proof's
  statement: it is bound through `h_tx` only, so the rule, not the proof, enforces it.

**Address:** the owner tag, a Ristretto view key `V`, and an ML-KEM-768 encapsulation
key (1,184 bytes). All three are derived per address from `sk`; addresses of one
wallet share nothing visible.

**Confidentiality needs both parts broken:** the discrete logarithm in Ristretto255
and ML-KEM-768. The KEM is RustCrypto `ml-kem` 0.3.2 (pure Rust, FIPS 203), pinned
exactly.

**The key combiner (v2) is not X-Wing.** The key hashes both shared secrets, both
ciphertexts (`R`, `ct_kem`), both recipient public keys (`V` and `H(ek)`) and `cm`.
Every part has a fixed length.
- Binding the classical ciphertext and both recipient public keys follows the X-Wing
  (draft-connolly-cfrg-xwing-kem) and generic hybrid KEM combiners: the key is tied to
  one recipient, so a hybrid share cannot be re-targeted to another key pair.
  Including `ct_kem` is redundant given ML-KEM's own ciphertext binding, but harmless.
- It is not X-Wing (other inputs, hash and classical component), so X-Wing's security
  argument does not carry over as is. Its use adds: each key is used once, for one body
  whose tag and associated data bind `cm`, and the recipient accepts a record only if
  it recomputes `cm` (below).
- The v2 combiner replaces v1 (`"px/delivery-key"`, without `V` and `H(ek)`) at the
  v3 testnet reset, which leaves no v1 ciphertext (decisions.md, "RES-FREEZE
  verified"; R2-C9). A sender refuses an address whose view key is the identity
  (`ss_ec` would be the identity for every `r`).

**Key separation** (the wallet's derivation 2 and seed format v1, §3.1):
- **View and spend.** The delivery keys of address `i` derive from the range's
  incoming viewing key `ivk_k`, not directly from `sk`. A `RangeViewKey` or
  `IncomingViewKey` (§3.1) lets another party scan for records without spending them;
  the packages are a library API, and the wallet has no CLI export or watch-only mode
  yet. Delivery keys never reveal `sk` (every step is one-way).
- **Networks.** Seed format v1 puts the network into `master` (blocks.md §10), so one
  seed gives unrelated v1 and PX keys on each network (test
  `a_seed_gives_unrelated_keys_on_each_network`). Earlier text here described the
  removed derivation 1, which had neither property.

**Acceptance** (Janus principle, transactions.md §12): the recipient accepts a record
only if it recomputes the on-chain commitment with the transaction's `rho` and:
- for a user record, its own owner tag;
- for a contract record, owner 0 and the decrypted contract.

A probe with inconsistent contents is ignored, and the record kind cannot be
misrepresented: a user record presented as a contract record, or the reverse, fails
the commitment check (tested).

**Scanning:** one scalar multiplication per output and wallet address, then a view-tag
check that filters about 255 of every 256 outputs.

**Hygiene:**
- spend and view secrets are zeroized on drop;
- `Account` never prints its keys;
- plaintext buffers are zeroized.

## 7. Contract functions and the unified proof

### 7.1 Model

A transaction may call up to `MAX_FN = 2` functions of private contracts (zk.md §7).
- A function is an ordinary BVM-1 program.
- It runs in the **same batch proof** as the kernel (zkvm.md §6.5): the kernel is
  execution 0 and function `k` is execution `k + 1`.
- The byte, ALU and Poseidon2 tables are shared, so a function adds only its own five
  tables to the proof, not a second proof.

A function of contract `C` sees private data only it is given (for example a contract
record's plaintext and a secret). It decides:
- **approvals:** which kernel inputs, records of `C`, may be consumed. Each approval is
  identified by the exact commitment.
- **specifications:** which kernel outputs must have which contents
  `(owner, contract, value, data)`. These are either records of `C` (new contract
  state) or payouts to users. The kernel adds `rho` and the caller's `rcm`.

### 7.2 Binding (`px-core/src/call.rs`)

Both the function and the kernel compute

```text
io_hash = Hk(IO, C ‖ per input i: [a_i, a_i·cm_i] ‖ per output j: [s_j, s_j·(owner ‖ contract ‖ value₁₆[4] ‖ data)] ‖ blind)
```

- The function writes the **function prefix** as its first `PREFIX_WORDS = 21`
  public output words (`call::function_prefix`), followed by exactly its registered
  number of public output words (`out_words`; the vault writes its selector):

  ```text
  abi ‖ io_hash[8] ‖ C[8] ‖ not_before(lo, hi) ‖ not_after(lo, hi)
  ```

- The kernel writes `(C, io_hash)` for each function, computed from the **actual**
  input commitments and outputs.
- The verifier builds the prefix from public values: `abi` from the program's
  registration (F-28-1: `ABI_VERSION = 1` is the only one a deploy may register),
  `(C, io_hash)` from the statement, and the window from the transaction (PX6,
  §11.3). So a proof exists only if the function and the kernel agree on the
  transcript, and a function can rely on the ABI and on the window it reads. The
  call ABI, its versioning and the window's semantics for contract authors are in
  [`contracts.md`](contracts.md) §4.
- The random `blind` makes `io_hash` a hiding commitment: records, amounts and
  recipients stay private.

**Kernel rules (§4.1, exit codes in §4.2):**
- **Contract inputs:**
  - a contract input must be approved by a function of its contract (`Unauthorized`);
  - a function may approve only real records of its own contract
    (`ApprovalMismatch`);
  - a contract input is approved by exactly one function (`ApprovalConflict`,
    testnet v3, F-20-1): one consumption authorizes one transition. A mismatching
    approval is reported first; the conflict is reported before tree membership,
    which is decided after both inputs.
- **Specified outputs:**
  - a specified output must match exactly (`SpecMismatch`), so a caller cannot redirect
    a payout or change an amount;
  - a function may specify only its own contract's records or user payouts
    (`SpecForeignContract`);
  - at most one function specifies an output (`SpecConflict`).
- **Contract outputs:** a contract output must be specified by a function of its
  contract (`Unauthorized`), so nobody can forge contract state; and it must have owner 0
  (`ContractOutputOwner`, PX-F5: a contract record with an owner is unspendable, its value
  burned).
- **Function contracts:** a function's contract is nonzero (`ZeroContract`).
- **Dummies:** a dummy input may not be a contract record (`DummyContract`).

### 7.3 The registry (consensus requirement)

The proof shows that *some* program produced each function's transcript. It must be
the contract's program: otherwise anyone could write a function that approves spending
another contract's records.
- `prove::verify` therefore takes `registered(contract, program_id)` as a **mandatory**
  argument. The tests check that an unregistered program is refused.
- Consensus answers it from the deploy data (§11.2): PX3 checks registration and the
  output-word count, and PX5 verifies with the registered programs, budgets and ABIs
  (`tx/src/validate.rs`).

### 7.4 Example: a private hash-locked vault (`zkvm/guests/vault`)

Specified in [`contracts.md`](contracts.md) §8 (testnet v3, W28-4). A vault record's
data commits to its terms, `Hk(TERMS, C ‖ claim_lock ‖ refund_lock ‖ timeout₁₆[4])`,
with `claim_lock = Hk(LOCK, C ‖ secret)` and `refund_lock = Hk(REFUND, C ‖
refund_secret)`:
- `LOCK` creates a record of the vault contract holding `value` under the terms;
- `CLAIM` takes the vault record and the secret, approves consuming the record, and
  pays its value to a recipient; with a timeout `T`, only in a transaction whose window
  ends before `T`;
- `REFUND` does the same with the refund secret, only in a transaction whose window
  starts at `T` or later.

Everything except the contract id, the selector, the window and `io_hash` stays
private. Tests (`px/tests/unified.rs`):
- LOCK and CLAIM proven and verified; the proof refused for another window or ABI;
- a two-function transaction (CLAIM and LOCK) proven and verified, and refused with
  the calls swapped, an altered output or a missing registration (W28-3);
- a wrong secret gives no proof;
- 12 contract-rule violations, each rejected identically natively and in the guest;
- double approvals refused, crossed approvals valid, with the error precedence
  (`an_input_approved_by_two_functions_is_rejected`, F-20-1);
- the timeout, the refund and the contract-bound locks, in the pinned vault guest
  against the native kernel;
- a function transcript that differs from the kernel's, or a function echoing another
  window, is detected;
- unregistered programs, wrong shapes and altered outputs are refused;
- kernel heights are identical for contract and user inputs.

## 8. Performance (measured on this machine under the earlier BS-ZK-2 set; re-measured for BS-ZK-3 in Wave 4)

| Item | Value |
|---|---|
| Kernel execution (v2) | 25.0–25.2k cycles; 29.3–29.4k with one function (opt-level "z" gave 141k for v1) |
| Transfer proof | **2.04 MB** (6 proofs: 2,029,768–2,046,856 bytes), proving ~42 s, **verifying 188 ms** |
| Kernel + one function (vault CLAIM) | **~2.5 MB**, proving ~51 s (a 40-proof stress run gave 48.4–51.4 s each; before BS-ZK-3 and the v3 vault) |
| Kernel + two functions (CLAIM + LOCK) | Measured by `px/tests/unified.rs::a_two_function_transaction_proves_and_verifies` (W28-3); the figures are recorded in reviews/v3-consensus-changes.md, section `guest-rebuild` |
| PX transaction (encoded) | ~2.05 MB (bridge-in with one v1 input) |
| Record ciphertext | 1,241 bytes per output |

Measured on this machine, idle, one proof at a time.

**Verification cost** was 1.3–1.5 s, 76% of it spent recommitting the public tables
on every verification. They are now periodic columns the verifier evaluates itself
(zkvm.md §6.1): 188 ms.

**Proof size is the main open problem.** A single transfer proof is far too large for
high-throughput per-transaction use on a chain.
- **Causes:**
  - 108 FRI queries, each opening ~2,400 committed elements;
  - the degree-8 challenge extension, needed for the security margin.
- **Parameter options**, measured by `zk/examples/param_study.rs`:
  - dropping the extra unique-decoding target and keeping Johnson ≥ 120 needs 49–71
    queries (−35% to −55%);
  - a higher blow-up trades prover time for fewer queries.

  The owner has kept the conservative parameters (AUDIT.md R8).
- **Consensus consequence:** blocks carry a separate 8 MiB PX budget (§11.5), room
  for three PX transactions per 2-minute block (4 × 2.18 MB exceeds 8 MiB).
- **Architectural fix:** aggregation (recursion). A design study is in
  `docs/reviews/aggregation-study.md`; it is not implemented.

## 9. Security analysis

### 9.1 Assumptions

1. Knowledge soundness and zero knowledge (statistical and conditional, computational
   in practice) of the BVM-1 STARK at BS-ZK-3 (zk.md §9.3, §12).
2. `Hk`: collision resistance, preimage resistance, and PRF security keyed by `nk`. The
   node compression: extractability of the commitment tree as argued in zk.md §9.3
   (argued, not proven; the compression alone is not collision resistant, §2).
3. Delivery: IND-CCA of the hybrid KEM (secure if either ECDH or ML-KEM holds) and of
   ChaCha20-Poly1305.
4. The kernel source implements §4.1. It is short, with one path per check, and is
   tested per check (§9.3).

### 9.2 Attacks considered

| Attack | Why it fails |
|---|---|
| Spend someone else's record | The owner tag is recomputed from the witness `sk`; any other key gives another commitment, which is not in the tree (test `only_the_owner_can_spend`). |
| Double spend | Nullifiers are deterministic per record; the state rejects repeats across blocks, within a block and within a transfer, and the kernel rejects `nf_0 = nf_1`. |
| Faerie Gold (two records with one nullifier) | `rho` derives from a unique nullifier, and `nf` covers `cm`. |
| Inflation by wrap-around | `u128` integer sums, not field sums; the wrap case is tested. |
| Value from a dummy | Dummies must have value 0; a dummy with value is rejected. |
| Burning another user's record with a dummy nullifier | A dummy's nullifier uses `nk = Hk(NK, sk)` of the witness key. Producing a victim's nullifier needs the victim's `nk` or an `Hk` collision. |
| Proof reuse or malleability | `h_tx` is bound; every public field is bound; each is tested. |
| Stale or forged anchor | The anchor must be one of the last 100 block roots. |
| Non-canonical encodings (one value, two encodings) | Every witness element is checked `< p`; the `POSEIDON2` syscall rejects non-canonical words; output bytes are range-checked. |
| Pool drain after a proof-system break | Bounded by the pool (containment). |
| Timing and shape leakage | Constant work; identical table heights, tested. |
| Link addresses of one wallet | Per-address owner tags and delivery keys. |
| Probe a recipient with a malformed record | The recipient accepts only records that match the commitment. |

### 9.3 Tests (`px/tests`, `px-core`)

- **Native and guest agreement.**
  - Every accepted witness gives the same output natively and in the zkVM
    interpreter.
  - **20 rejection cases** (every check, violated alone) fail with the same error
    natively and in the guest: balance ±1, bridge terms, wrap, value, rho, rcm, data,
    position, path, anchor, sk, diversifier, dummy with value, duplicate record,
    non-canonical input and output, non-boolean flag, version.
  - A truncated witness traps.
- **Proofs.**
  - A deposit, then a private payment spending the deposited records, both proven and
    verified.
  - The payment's proof is rejected for each of 8 altered public fields, another
    `h_tx`, and another transfer's statement.
  - Strict encoding round trip.
  - The state accepts the transfer once.
- **State:** exact undo; atomic blocks; double spends (3 forms); pool underflow; `u64`
  extremes; anchor expiry after 100 blocks.
- **Tree:** the frontier equals the full tree for 300 sizes; paths verify; a wrong
  leaf or position fails.
- **Delivery:** only the addressed recipient opens a ciphertext; one bit flipped in any
  region is rejected; the ciphertext is bound to `cm` and `rho`; probes are refused;
  malformed addresses are refused.
- **Hash:** the fast path equals the reference sponge for lengths 0–40; domain and
  length separation.

## 10. Not production-ready: remaining work and risks

1. **Independent review** (the owner has no external team yet; the internal reviews
   are `docs/reviews/`):
   - Poseidon2 parameters and the `Hk` constructions;
   - the kernel statement;
   - the zkVM circuits;
   - the hybrid delivery combiner;
   - the consensus rules of §11.
2. **Proof size and chain capacity:** §8, §11.5.
3. **Contract tooling:** deploys, calls and record distribution are implemented for
   the reference vault (§13). Contracts other than the vault need their own
   host-side helpers (the equivalent of `px::vault`) before the wallet can call them.
   At most two functions per transaction.
4. **Wallet:**
   - The wallet keeps every commitment (32 bytes each) and rebuilds the tree to
     spend. That is adequate for a testnet; a long-lived chain needs incremental
     witnesses.
   - Restoring a wallet finds records only from its restore height.
5. **Aggregation** (§8).

## 11. Consensus integration (transaction kinds 2 and 3)

### 11.1 PX transaction (kind 2, `tx/src/px.rs`)

```text
prefix:   version ‖ kind=2 ‖ v1 inputs[0..64] (key image, ring) ‖ hidden outputs[0..16]
          ‖ payouts[0..16] (clear amount, stealth) ‖ fee ‖ bridge_in ‖ bridge_out
          ‖ not_before ‖ not_after (varints; the validity window, PX6)
          ‖ anchor ‖ nullifiers[2] ‖ commitments[2] ‖ ciphertexts[2] (1241 bytes each)
          ‖ functions[0..2] (contract, program id, io_hash, public output words)
base:     pseudo-outputs[inputs]
prunable: range proof (if hidden outputs) ‖ CLSAGs[inputs] ‖ proof (≤ 4 MiB)
```

- **v1-side balance.** With `v = fee + bridge_in + Σ payouts − bridge_out`:
  `Σ pseudo_outs − Σ hidden = v·H`. Without v1 inputs there are no hidden outputs and
  `v = 0` exactly. Hidden change needs input masks to balance; payouts carry their
  (already public) amounts in clear, like coinbase outputs.
- **PX-side balance** is proven by the kernel (§4.1).
- **Validity window (PX6, testnet v3):** `[not_before, not_after]`, `(0, 0)` for
  unbounded, which every transaction without a reason for a window carries (§11.3,
  contracts.md §4.3). Each called function receives it in its prefix (§7.2).
- **Binding:** `h_tx = H32("px/tx-binding", LE32(network_id) ‖ LE32(branch_id) ‖
  genesis_id ‖ prefix hash ‖ base hash)` is the proof's binding. It covers every field
  (the validity window included) except the range proof, the signatures and the proof,
  plus the network, the epoch's
  branch id (consensus.md §11) and the chain's genesis id (RT-14, transactions.md §4.4). `h_tx` is a public input of the proof (it enters the CPU tables'
  public values and the transcript, never a guest's input), so the domain changes
  every proof but not the kernel or any program id.
- **Signatures.** The v1 inputs' CLSAGs sign a message that also covers the range
  proof and the proof.
- **Output context.** The stealth-output context is
  `H32("input-context/px", nullifiers ‖ key images)`. It is unique because
  nullifiers never repeat.

### 11.2 Private-contract deploy (kind 3)

- **Format:** a v1 transfer (at least one input, 2–16 outputs) plus a salt and 1–16
  programs, each an ELF binary of at most 256 KiB with its row budget, its call ABI
  and its output-word count (`abi`, `out_words` varints after the budget; testnet v3,
  F-28-1, F-28-5). The binaries are on chain: verifiers need them to build the
  statement.
- **Contract id:** 8 field elements from
  `H64("px/contract-id", first key image ‖ salt ‖ H32(payload))`. It is unique
  because key images never repeat. The payload covers every program's ELF, budget,
  ABI and output words, so the contract id fixes its registrations.
- **What it registers:** each program's id, budget, ABI and output-word count under the
  contract. Entries are immutable, and a registration is usable from the next block.
  A deploy may register only `ABI_VERSION` (`PxUnsupportedAbi`) and at most
  `MAX_FN_OUTPUT_WORDS` output words.
- **Signatures** cover the payload.

### 11.3 State and rules (`tx/src/validate.rs`, `tx/src/state.rs`)

| Rule | Meaning |
|---|---|
| Structure | Counts, sorting, identity points, range-proof shape, sizes. PX transactions: each record ciphertext's `R` is a canonical, non-identity ristretto255 point (§6; `PxCiphertextRNonCanonical`, `PxCiphertextRIdentity`; testnet v3, reviews/v3-consensus-changes.md#px-ciphertext-r), and the fee is **exactly** `PX_STANDARD_FEE`. Deploys: fee **exactly** `deploy_fee(n, k, programs) = standard_fee(n, k) + DEPLOY_FEE_PER_BYTE × payload length`, where `standard_fee(n, k) = FEE_PER_WEIGHT × max_weight(n, k)` is the exact fee of a transfer of the shape (transactions.md T8, §8.4; `TxRules::standard_fee`, one function for both) (`DeployFeeNotExact`; v3 candidate, R5-1/R6 TX-4) |
| Balance | §11.1 (PX); the transfer rule for deploys |
| C1–C3 | Rings and key images, as for transfers. One-time keys (hidden outputs and payouts together) are distinct within the transaction (stateless: the sort of each list, and `PxDuplicateOutputKey` between them) but may repeat across transactions and the chain (transactions.md §8.2) |
| PX1 | The anchor is a root of the last 100 blocks, before this block |
| PX2 | Nullifiers are unspent and unrepeated across the chain and the block |
| PX3 | Every called function is a registered program of its contract (registry before this block), and publishes exactly its registered number of output words (`PxOutputWords`, stateless for scoring: a registration is fixed by its contract id; F-28-5) |
| PX4 | The pool stays ≥ 0 through the block, in order |
| PX6 (window) | The block's height is inside the transaction's validity window: `not_before ≤ h` and (`not_after = 0` or `h ≤ not_after`) (`PxWindow`, contextual and never penalized; testnet v3). An inverted window is a stateless structure error (`PxWindowInverted`). Checked for every PX transaction of a block, including those whose proof the node verified before (the verified-proof cache vouches only for the proof). The mempool admits for the next height, revalidates at every new height (`revalidate_after_extension` takes it) and templates select by it |
| B8 (capacity) | The block's PX output commitments, one tree leaf each, fit in the `2^32 − size` leaves left (`BlockError::PxTreeFull`); for a mempool transaction, contextual `TxError::PxTreeFull`. Checked with the byte budgets, before any cryptography. Templates never exceed it |
| PX5 | The proof verifies with the registered programs and budgets. Checked in three steps, in blocks and on every single-transaction path alike (transactions.md §8.3, §8.5): strict decoding with the stateless rules, the statement's table shape once PX3 holds and before any ring is resolved, and the verification last (the most expensive check). A malformed proof therefore costs no CLSAG (dossier 10 F10-2, red team RTW1-2) |
| Deploy | Every budget is provable: `cycles ≤ MAX_CYCLES` (2^21), `keys ≤ 2^22`, and each ALU and Poseidon2 field plus the kernel's `kernel_budget(1)` share ≤ 2^22 (stateless, `PxBudgetTooLarge`; R7-5). Every ABI is `ABI_VERSION` (stateless, `PxUnsupportedAbi`; F-28-1). Programs load, and their program ids are pairwise distinct (stateless, `PxDuplicateProgram`; R5-7). The contract id is new in the chain and the block |
| Block | Coinbase = reward + all fees; block weight ≤ limit, where the v1 part of a PX or deploy transaction with `n > 0` inputs weighs `max_weight(n, k)` (transactions.md B6; R12-2); PX and deploy bytes ≤ 8 MiB |

**Chain state.** The state (`MemoryChain`) keeps the PX state, the registry and a
log of commitments, ciphertexts and nullifiers for wallets, all with exact per-block
undo. Tests check that a reorganization restores the root and pool exactly.

### 11.4 Wallets and RPC

- Wallets scan whole blocks (`/blocks`) and fetch, whole and in order:
  - the commitment list (`/px/commitments`), in pages, only below their restore height
    (once) and to place an imported record (below):
    `GET /px/commitments?from=F&limit=L` returns the `(height, commitment)`
    entries at tree positions `F..F+L`, the `total` count, the current tree `root`,
    the tip `height`, and `next` (the `from` of the following page, or `null` at the
    end). Both parameters are optional: `from` defaults to 0 and `limit` to 1 024; a
    `limit` of 0 or above 4 096 is rejected (HTTP 400); a `from` at or past the end
    gives an empty page. The node copies only the requested page under its chain
    lock, so the cost of a request is proportional to the page, not to the chain;
  - the contract-registration list (`/px/contracts`: height, contract id, program
    ids and budgets), only below their restore height (once), to find the deploys
    there. Registrations themselves are derived from the deploys (§13.4).

  The node never learns which records a wallet owns or which contracts it uses.
- **The wallet's own tree** (dossier 39 W1, finding F39-1; `wallet/src/tree.rs`). The
  wallet builds the commitment tree from the blocks it scans (bound to their headers by
  `tx_root` and to each other by `prev_id`), appending the two commitments of every PX
  transaction in block order, and keeps the consensus root window of §5: the roots
  after each of the last 100 blocks. Every PX transaction of a scanned block must
  anchor at a root of that window, as consensus requires; a block that does not is
  refused and nothing of it is applied. The wallet anchors its own transactions at the
  root it computed, and checks every authentication path against it, so a node cannot
  choose the anchor. (Before, the tree came from the node's list, whose heights the
  node chose: it could place a wallet's anchor at a non-canonical root that marked the
  transaction as its client's.)
  - **Below the restore height** the commitments come from the node's list, once (the
    backfill). It is bound to the chain as soon as a scanned PX transaction anchors at
    a root that includes a commitment of a scanned block: the backfill is then the
    chain's exact list, by the collision resistance of the node hash and the
    uniqueness of commitments. Until then, a transaction whose anchor's tree holds only
    backfilled commitments (a deposit, for example) is refused until the wallet is
    synced 100 blocks past the restore height, where a shortened list gives a root no
    block accepts; an anchor below the restore height is always refused. A restore
    from height 1 has no backfill. A list that does not follow the chain (an omitted,
    altered or relabelled commitment) is caught by the first PX transaction anchored
    after it, or, for commitments of later blocks labelled as older ones, by the first
    scanned commitment; the wallet then rebuilds the tree from a fresh list at the
    next sync.
  - **The backfill's end is checked against its block** (W3-39b). The wallet reads the
    block of the last listed commitment (bound to the header chain, which a restore
    checks from the genesis, blocks.md §10) and refuses the list unless the entries at
    that height are exactly the block's commitments. This closes the residual W3-39
    left: a node that withholds blocks (reports a stale tip) and labels commitments of
    the withheld blocks as older ones made the wallet's tree a real prefix of the
    chain's that ran ahead of it, so its canonical anchor was the root of a later,
    non-canonical height, which marks the transaction (demonstrated on the base by
    `a_stale_tip_cannot_relabel_withheld_commitments_into_the_backfill`). Such a list
    ends with a commitment its claimed block does not hold. What remains is a list that
    ends early (commitments left out after its last block), whose root no block accepts
    once it is 100 blocks old: the rule above.
  - **Witnesses** are incremental and in-tree: for every leaf the wallet may spend,
    the left siblings are taken from the frontier when the leaf is appended and the
    right siblings recorded as the frontier completes them; the tree keeps the
    frontier at every multiple of 16 (where anchors lie) to compute the one partially
    filled sibling. Rewinds within the wallet's reorganization window replay the kept
    blocks from a checkpoint; deeper ones rescan. The wallet file stores the frontier,
    the window, the last 820 blocks' commitments, the checkpoints and the witnesses,
    not the chain's whole list.
  - **An imported record** already on chain is placed from the commitments of the
    recent blocks the tree keeps (replayed from a checkpoint, and required to end at the
    wallet's own frontier); one not on chain yet is placed by the block it confirms in;
    one older than the kept blocks is placed from the backfill list of a rescan (the
    wallet warns). No download is made for it (RTW3-15: the earlier bulk download after
    an import told the node that the wallet holds a record whose position it does not
    know). Tested by `an_imported_record_is_placed_without_a_download`.
  - Tested (`wallet/src/tree.rs`, `wallet/src/wallet/tests_sync.rs`): paths equal the
    reference tree's, the window equals the consensus state's on random chains, a
    rewind equals rebuilding, and a node that relabels, omits, alters or pads its list
    (behind a stale tip too), or serves a block anchored outside the window, is
    refused.
- CLI commands: `px-address`, `px-balance`, `px-deposit`, `px-send`, `px-withdraw`, and
  the contract commands of §13.4.
- **Canonical anchor** (wallet policy, `wallet::px::anchor_height`). Wallets use the
  root at the highest multiple of 16 that is at least `ANCHOR_MIN_DEPTH` = 3 blocks
  below their synced tip (genesis while the chain is shorter).
  - The multiple of 16 keeps the anchor from revealing when a wallet last synced.
  - The depth keeps a reorganization of up to 3 blocks from removing the anchor
    (ZIP 315's trusted depth). Before it, the anchor was the tip itself once in 16
    heights; a 1-block reorganization then made the spend `PxUnknownAnchor`, and
    the rebuilt spend republished the same nullifiers (dossier 21 F21-3). Tested by
    `a_reorganization_of_up_to_three_blocks_keeps_the_anchor_root`.
  - Every wallet must use the same depth, since the anchor is public in each
    transaction.
  - A record becomes spendable once the anchor reaches it, within 18 blocks of its
    confirmation. The anchor lies 3 to 18 blocks deep, so a transaction stays inside
    the 100-root window for at least 81 blocks after it is built.

### 11.5 Capacity, relay and denial of service

| Limit | Value |
|---|---|
| PX transaction | ≤ `MAX_PX_TX_SIZE` = 4 MiB proof cap + 256 KiB |
| Deploy | ≤ 1 MiB |
| Deploy fee | Exactly the standard v1 fee of its transfer shape plus `DEPLOY_FEE_PER_BYTE` = 50 per payload byte (the vault: ~0.007 BLK; 1 MiB: ~0.52 BLK). A function of public data, so no wallet fingerprint |
| Block deploy budget | `MAX_DEPLOY_BLOCK_BYTES` = 1 MiB of deploys per block, inside the 8 MiB PX budget. A block rule (`BlockError::DeployBytesExceeded`, testnet v3 rule set); templates respect it (reviews/v3-upgrade-mechanism.md §7.2, §8) |
| Block PX budget | 8 MiB (3 PX transactions at measured proof sizes); total block ≤ `MAX_BLOCK_BYTES` = 1,000,000 + 8 MiB + 64 KiB = 9,454,144 bytes |
| PX fee | Exactly `PX_STANDARD_FEE = PX_FEE_PER_BYTE × MAX_PX_TX_SIZE` = 8,912,896 atomic units, a consensus rule (§12). It covers the per-byte fee of any PX transaction. Consequence: every PX transaction pays the same, so the mempool's fee-per-byte ordering ranks larger ones (contract calls, ~2.5 MB) below plain transfers (~2 MB) when the PX budget is congested |
| Relay | PX and deploy transactions together: per peer 0.2/s (burst 4); all peers together 2/s (burst 10) |
| Invalid proof | Misbehaviour (the statement is branch-independent once PX1 and PX3 pass). Across a scheduled activation the binding changes, so near an activation an honest peer can relay a proof for the previous epoch; see reviews/v3-upgrade-mechanism.md §2.4. A malformed proof (failing decoding or shape) is caught by relay admission's cheap checks, before the node-wide PX token and any ring or CLSAG (p2p.md §10); a well-formed proof that does not verify costs every check up to the verification |
| Block weight | A PX or deploy transaction with v1 inputs also takes `max_weight(n, k)` of the 600 000 block weight (R12-2): its CLSAGs are metered like a transfer's. The fixed PX fee covers it (`FEE_PER_WEIGHT × max_weight(64, 16)` = 1,148,780 ≤ `PX_STANDARD_FEE`), so the PX fee stays uniform; a deploy's fee already pays exactly that weight at the v1 rate |
| Mempool | PX class capped at 64 MiB with fee-per-byte eviction; proofs verified once on admission; a PX transaction outside its validity window (PX6) is refused for the next height, leaves the pool at the revalidation after its window ends, and is never selected into a template for a height outside it; one whose window ends within 3 blocks of the next height is refused (expiring-soon policy, RTW1C-4; readmitted after a reorganization); templates take PX transactions first, charge every transaction against both the weight and the PX budgets, and keep the pool non-negative in order |

## 12. Privacy guidance for users and wallets

Measured privacy analysis: `docs/reviews/privacy-review.md`.

- **Deposit and withdrawal amounts are public** (containment). Deposit round amounts,
  wait between deposits and withdrawals, and never withdraw the amount you deposited.
  The CLI prints this reminder.
- **Use your own node,** or a node you trust, reached over a private channel (an SSH
  tunnel, a VPN, or Tor through a local forwarder you run). The wallet itself has no
  Tor or SOCKS support, speaks plain HTTP only (it refuses `https://` addresses), and
  ignores proxy environment variables. A node you do not control learns your IP
  address and sync times, your scan start (the wallet's birthday) and, after a
  restore, the restore point (the `/outputs` pages it serves, at the first `sync` that
  catches up; run `sync` before the first spend), the ids of your pending transactions
  (`/tx/status`) and the transactions you submit. The
  decoy distribution of your v1 rings comes from the wallet's own output index, not
  from the node; after a restore, the part below the restore height is the node's
  unverified backfill, which that node controls, and the node used for the restore is
  trusted for the positions of your outputs (transactions.md §11.3.1). It does not
  learn which outputs or records are yours from scanning: the wallet scans whole
  blocks and builds rings and the PX tree from its own index (docs/testnet.md §11).
- **Give each counterparty its own PX address** (`px-address --index`). Addresses of
  one wallet are unlinkable.
  - Every scanned PX address costs a scalar multiplication for every PX output, so the
    wallet hands out at most 1,000 addresses beyond the highest one that has received a
    record (2,000 with `--force`).
  - A wallet restored from the seed scans 20 addresses beyond the highest one found.
    Keep the wallet file backed up if you hand out addresses far ahead.
- **Contract calls reveal the contract, the program and the function's public
  outputs** (for the vault: LOCK, CLAIM or REFUND). The time between a LOCK and its
  CLAIM is visible to anyone watching that contract.
- **The validity window is public** (PX6). Wallets leave it unbounded, `(0, 0)`,
  unless a contract needs one, so ordinary transactions look alike. A vault claim or
  refund with a timeout reveals its window, which the wallet rounds to 16-block
  boundaries (timeouts are multiples of 16): the timeout itself shows only for a claim
  within about 50 blocks before it or a refund within 16 blocks after it
  (contracts.md §8, RTW1C-2).
- **The fee amount is the same for every PX transaction** (consensus), so the amount
  does not distinguish wallets. Where the fee comes from does show: a deposit pays it
  from v1 inputs, a private payment from the PX side (`bridge_out` equal to the fee,
  with no v1 inputs), a withdrawal within its `bridge_out`, and a contract call from
  either. Together with the bridge amounts and the function count this reveals the
  transaction's kind.
- **Never spend the same funds twice after a transaction may have been relayed**
  (privacy-review.md §3c, P-9). The wallet keeps every submitted transaction and
  never rebuilds it. If a submission ends with "the node may or may not have
  received the transaction", just `sync` later. `clear-pending` is only for a
  transaction that certainly never left the wallet. A second spend of a v1 input
  shares the key image with the first, so the two are linkable. The wallet reuses
  the first ring so they do not reveal the real input, but these rings are kept in
  the wallet file only: keep backups of it, because a restore from the seed loses
  them.
- **Rebroadcast** (dossier 38 W4; `wallet/src/wallet/rebroadcast.rs`). A stored
  transaction that is not mined is checked on at `sync` with `/tx/status`
  (blocks.md §9) every 20 blocks, never by posting it again:
  - `pooled` or `confirmed`: nothing is sent.
  - The node lacks it (`unknown`): nothing is sent before `relayed + 2 190` blocks
    (`NETWORK_EXPIRY_BLOCKS`: the pool expiry, 2 160, plus the recently-expired guard,
    30, both taken from `chain`). Other nodes may still pool it until then, and a
    re-send would show them which node it came from (p2p.md §8.1). The wallet warns
    and lists it as `waiting` (`Wallet::pending_transactions`).
  - After that it is sent again **once**, through the node's normal `/tx` path, with a
    warning, and listed as `resent`. It is never sent again automatically; its funds
    stay reserved until it is mined or found invalid.
  - The node's answers are handled one by one: `Expired` (the node dropped it recently
    and does not originate it again yet) sends nothing and is retried at a later
    check, not counted as the one re-send, with a warning; `Invalid` releases the
    inputs; a full pool or another refusal keeps them reserved and retries later.
  - A submission that failed in transport (`uncertain`) is checked, and sent again if
    the node lacks it, at the next `sync`, not 20 blocks later. If it had arrived, the
    node's originated set keeps the repeat from being originated again (p2p.md §8.1).
  - A node without `/tx/status` gets nothing before `relayed + 2 190`.
  - Each independent sending of the same transaction is another sample for a network
    spy (dossier 33 F33-3); the one re-send is not private broadcast over a fresh Tor
    circuit (not implemented).
  - A PX transaction whose validity window (PX6) ends within the expiring-soon margin
    of the next block is not sent (pools refuse it, RTW1C-4); once its window has
    passed it can never be mined, and the wallet drops it, releases its unspent inputs
    and warns.
  - Tested (`wallet/tests/e2e.rs`): `a_pooled_transaction_is_checked_not_posted_again`,
    `a_transaction_the_node_lacks_is_sent_again_once_only_after_the_network_expiry`,
    `a_stored_transaction_the_node_finds_invalid_releases_its_inputs`;
    (`wallet/src/wallet/tests_sync.rs`)
    `a_px_transaction_past_its_window_is_dropped_not_rebroadcast`.
- **Across a consensus upgrade** a stored transaction built for the previous epoch
  (branch id) can never be mined. The wallet does not rebroadcast it: it releases its
  inputs, warns, and `sync` lists it as "needs rebuilding" (a PX transaction must be
  proven again). The payment sent again reuses the stored v1 rings, but it shares the
  key images and nullifiers of the dropped one, so anyone who saw the dropped one can
  link the two. The wallet warns when an upgrade activates within 60 blocks of the
  next block (reviews/v3-upgrade-mechanism.md §10).

## 13. Contract tooling and the distribution of contract records

### 13.1 The problem

A contract record (`contract = C`, owner 0) is spent through a function of `C` that
approves it. Whoever calls that function must know the record's opening: its value,
data, `rho` and `rcm`, and its tree position. Unlike a user record, its opening is not
tied to anyone's key, so the protocol must say who receives it.

### 13.2 On-chain delivery to a designated party

- **Every output carries one ciphertext** (§6). For a contract output, the caller
  addresses it to the party that will act on the record: for a vault, the claimer.
  With no counterparty, it goes to the caller's own address.
- **The creator keeps a copy** of every contract record it creates, whoever the
  addressee is.
- **Recipients find contract records by ordinary scanning.** The same trial decryption
  as for payments is used: no new message, no node query, the same cost.
- **Spends are seen by every holder.** A contract record's nullifier,
  `Hk(NULLIFIER_CONTRACT, contract ‖ rcm ‖ cm)`, depends only on the opening
  (`px_core::record::contract_nullifier`, checked against the kernel's). Every holder
  sees when the record is consumed.

### 13.3 Off-chain sharing (`px/src/share.rs`)

When more parties need a record than the one on-chain addressee, a holder shares it:

```text
share = version (1) ‖ cm (32) ‖ rho (32) ‖ delivery ciphertext to the recipient's PX address
```

- The sealing is the hybrid encryption of §6. Only the addressee can open a share, and
  the share is bound to `cm`.
- The recipient accepts it only if the record recomputes `cm`, and counts it as
  confirmed only once `cm` is in the chain's commitment list. So a share can describe
  only a real, existing record.
- Only contract records can be imported. User records are received on chain and are
  spendable only by their owner.

### 13.4 Wallet (`wallet/src/px.rs`, `wallet/src/wallet.rs`)

**Contract index** (W3-39b, `wallet::px::deployed`). The wallet derives every
registration from the deploy transaction itself, as consensus records it: the contract
id (which binds the deploy's first key image, salt and every program's ELF, budget, ABI
and output words), and per program its id, budget, call ABI and output words.
- From the blocks it scans, and below its restore height from the blocks that the
  chain's registration list (`/px/contracts`, fetched whole, in block order) names:
  each is read once, bound to the header chain (blocks.md §10), and the list must state
  exactly what the block's deploys register, or it is refused. So a wallet created
  after a deploy knows the contract too (the first version indexed deploys only while
  scanning, so a wallet newer than the deploy could not claim; that was found in review
  and fixed), and a node cannot change a registration: before W3-39b the list was
  trusted, so a node could hide a program registered next to the vault (the P-1
  backdoor) or show one that is not there (tested by
  `registrations_come_from_scanned_deploys` and
  `a_lying_registration_below_the_restore_height_is_detected`, which fail on the base).
- A node can still leave a deploy below the restore height out of its list altogether:
  the wallet then does not know that contract and refuses to use it.
- To call a contract, the wallet uses the budget registered on chain and checks that
  its program is registered to that contract. For the vault it checks more (below).
- On a reorganization, registrations above the fork are dropped and derived again.

**Contract records** are kept apart from the wallet's funds: never counted in the
balance, never selected to pay. Their lifecycle:

| Source | Confirmed when | On a reorganization above it |
|---|---|---|
| Received (its ciphertext was addressed to this wallet) | its block is scanned | dropped; rescanning finds it again |
| Created (by this wallet) | its commitment appears in the chain's list | kept, as unconfirmed (the wallet holds the opening) |
| Imported (a share) | its commitment appears in the chain's list | kept, as unconfirmed |

- `clear-pending` keeps every contract-record opening, including unconfirmed records
  this wallet created: the transaction may have been relayed (review F14).
- A contract record is spendable once confirmed at or below the canonical anchor (§11.4).

**Trust boundary: a contract is its whole program set.** A contract record's nullifier,
`Hk(NULLIFIER_CONTRACT, contract ‖ rcm ‖ cm)`, depends only on the record's opening,
and **any** program registered to the contract can approve spending its records.
So a contract is only as trustworthy as the least trustworthy of its programs.
- **The attack (review P-1).** Bob, who is to claim, deploys `C = {vault, backdoor}`
  and asks Alice to lock funds for him under `C`. Every check Alice's wallet made
  (that the vault program is registered to `C`) passes. Bob then spends the record
  through `backdoor`, without the secret.
- **The wallet's rule.** `px-vault-lock` and `px-vault-claim` accept a contract only if
  its registered program set is **exactly** `{vault}` (`wallet/src/px.rs::vault_check`).
  `px-deploy --vault` cannot be combined with `--program`, and the library refuses any
  deploy that registers the vault next to another program.
- **Budget (review P-2).** The vault must be registered with exactly `vault::BUDGET`:
  - a budget that covers LOCK but not CLAIM would lock funds for good (a CLAIM over
    budget cannot be proven);
  - any other budget would also make the contract's proofs stand out.
- **ABI and output words (W3-39b).** The vault must be registered with the current
  call ABI and exactly `vault::OUT_WORDS` output words. Consensus accepts a deploy with
  any output-word count up to `MAX_FN_OUTPUT_WORDS`, and every call must publish exactly
  the registered count (F-28-5), so
  a vault registered with another count can never be called: funds locked under it
  would be lost. The wallet knows both values only since it derives registrations from
  the deploys (tested by `registrations_come_from_scanned_deploys`).
- `px-contracts` prints each program's ABI and output words, and a warning for a
  contract that registers the vault with other programs, another budget, ABI or
  output-word count.
- **For any other contract:** read every program of the contract, not only the one
  you intend to call, before putting funds under it.

**Vault secrets are derived, and kept in the wallet file (review R11-W1; dossier 37
K6).** Without a secret option, `px-vault-lock` derives the secret deterministically:

```text
secret = H32("px/wallet/vault-secret/v1", hk_px ‖ u8 network ‖ contract ‖ rho_vault)
         as eight limbs LE32(secret[4j..4j+4]) mod 2^30        (240 bits, canonical)
rho_vault = Hk(RHO, nf_0 ‖ 0)       the vault record's own rho (§3)
```

`contract` and `rho_vault` enter as eight LE32 limbs each. `nf_0` is the nullifier of
the lock's first input, a real funding record (a lock whose first input would be a
dummy is refused), so `rho_vault` is unique on chain and known before proving. The
secret is unpredictable without `hk_px` and reveals nothing about it. `network` is the
seed's network code (blocks.md §10).
- The wallet stores the secret with the record's opening, and `submit` saves the
  wallet **before** the transaction is sent. A lock whose submission ends "may or may
  not have received" can still be mined; a vault without a timeout has no refund, so
  losing the secret would lock the funds for good.
- **Restore recovers it** for a vault record the wallet holds the opening of (a lock
  delivered to itself): the wallet re-derives the candidate from the record's `rho` and
  keeps it when the record's data equals the terms of a vault without a timeout,
  `Hk(TERMS, C ‖ Hk(LOCK, C ‖ candidate) ‖ 0 ‖ 0)` (contracts.md §8). A lock delivered
  to someone else leaves no opening in a restored wallet, so its secret is not
  recovered that way (the claimer has the record; the locker keeps the wallet file).
- **Refund secret (testnet v3, W28-4, RTW1C-7).** A lock with a timeout
  (`Wallet::px_vault_lock_until`) also derives a refund secret,
  `H32("px/wallet/vault-refund/v1", hk_px ‖ u8 network ‖ contract ‖ rho_vault)` as
  eight 30-bit limbs (`px_vault_refund_secret_for`; a dedicated tag, frozen for v3),
  so it is seed-recoverable too. The function's blind is hedged with `hk_px`
  (`blacksilk_px::wallet::hedged_digest`), and so is the `rcm` of a vault record
  without a timeout.
- **A lock with a timeout is recoverable from the seed (RTW1C-3).** Its record's
  `rcm` is derived, `H32("px/wallet/vault-rcm/v1", hk_px ‖ u8 network ‖ contract ‖
  rho_vault)` as eight 30-bit limbs (`px_vault_rcm_for`), and its change output (to
  address 1) carries the claim lock in its data. The wallet stores the terms (claim
  lock, timeout) in the wallet file before sending, and a wallet restored from the
  seed rebuilds the record and its terms from the chain
  (`Wallet::recover_vault_locks`, contracts.md §8), so the refund
  (`Wallet::px_vault_refund_stored`) needs no argument either way.
- A secret given with `--secret-file`, `--secret-prompt` or `--secret` is used as is
  and is recoverable from the wallet file only.
- `px-vault-secret --record CM [--out FILE]` shows the stored (or re-derived) secret.
  `px-records` marks the records that have one.

**Commands:**

| Command | What it does |
|---|---|
| `px-deploy --vault` or `--program F.elf --budget c,k,a,b,l,s,m,p --out-words N` (repeatable) | Registers a contract, paid with v1 funds, so the deployer is hidden behind ring signatures. Prints the contract id. `--vault` deploys the vault alone. `--out-words` is the exact number of public output words each call of the program publishes (contracts.md §5) |
| `px-contracts` | Lists deployed contracts and their programs (marks the vault; warns about contracts not usable as a vault) |
| `px-records` | Lists the contract records this wallet holds, with status and source, and for a lock of this wallet with a timeout, the timeout and the terms |
| `px-vault-lock --contract C --amount A [--timeout T] [--secret-file F \| --secret-prompt \| --secret S \| --secret-out F] [--deliver-to PXADDR]` | Locks PX funds in a vault record claimable with `S`, delivering the record to the claimer. The fee is paid from PX. Without a secret option it derives one (above) and prints it after sending (or writes it to the `--secret-out` file). With `--timeout T` (`px_vault_lock_until`; a multiple of 16 more than 3 blocks ahead) the record is claimable before `T` and refundable by this wallet from `T` on; the command prints the terms (`terms claim_lock:refund_lock:T`, public hashes and the timeout) that the claimer needs with the secret |
| `px-vault-claim --record CM [--secret-file F \| --secret S] [--to PXADDR] [--terms TERMS]` | Claims a vault record, paying its value privately; asks for the secret unless a file or `--secret` is given. A record locked with a timeout needs its `--terms` (`px_vault_claim_with_terms`); the claim must be mined before the timeout. The fee is paid from one PX record, or else from v1 funds, so a claimer without PX funds can claim |
| `px-vault-refund --record CM [--to PXADDR]` | From the timeout on, takes back the value of a record this wallet locked with a timeout, with the terms stored at lock time or recovered from the chain (`px_vault_refund_stored`) |
| `px-vault-recover` | Syncs, then finds this wallet's vault locks with a timeout after a restore from the seed (`recover_vault_locks`), and lists the timed locks it holds the terms of |
| `px-vault-secret --record CM [--out F]` | Shows the secret of a vault record this wallet locked |

`--secret S` on the command line stays in shell history and is visible to other local
users in the process list. The wallet warns when it is used; prefer `--secret-file` or
the prompt.
| `px-share --record CM --to PXADDR` / `px-import --share HEX` | Off-chain sharing (§13.3) |

**The reference vault** (`px/src/vault.rs`, program pinned in `px/vault.elf` and
`px/vault.id`) is a **demonstration contract, not production-ready**
(contracts.md §8):

| Limitation | Consequence |
|---|---|
| **A lock without a timeout** (`px-vault-lock`) | Stays claimable forever; the value returns to the locker only by claiming with the secret |
| **Whoever made the claim secret can claim** | With a derived or locally given secret the locker can claim too; a swap needs the counterparty to choose the secret and hand over only its lock |
| **Censorship before a timeout** | A miner can delay a claim until the timeout passes and the refund becomes valid; leave a margin |
| **Not an HTLC** (RTW1C-6) | A claim proves the secret without publishing it, so two vaults do not make an atomic swap (contracts.md §8) |
| **Delivery (PX-F4)** | The caller of a claim or refund chooses the new record's `rcm` and writes its ciphertext |

The wallet prints a warning on every `px-vault-lock`, and the command help says the
same.

**Recovery after restoring a wallet from its seed:**

| Contract record | Recovered from the seed? |
|---|---|
| Received (its ciphertext was addressed to this wallet) at or after the restore height | Yes, by scanning |
| Received before the restore height | No: restore from an earlier height, or ask a holder for a share |
| Created by this wallet and addressed to itself (the default) | Yes, as a received record |
| Created by this wallet and addressed to another party | **No,** except a vault lock with a timeout, which is rebuilt from the seed and the chain (RTW1C-3, above): the creator's copy lives only in the wallet file. Keep the file, or have the other party share the record back |
| Imported from a share | No: import the share again |

Contracts themselves (their registrations) are always recovered: the wallet
downloads the whole registration list.

### 13.4.1 Host-side helpers for other contracts

The wallet can call a contract only through a host-side helper like `px::vault`.
Writing one for a new contract requires:
1. **A function program** (a RISC-V ELF built with the zkVM SDK and the guest link
   layout, zkvm/guests/README.md) that:
   - reads its private input, including the transaction's validity window;
   - checks the contract's rules;
   - writes the function prefix (`px_core::call::function_prefix` with
     `ABI_VERSION`, its `io_hash`, its contract and the window) and then exactly its
     registered number of public output words.
   It must approve only records of its own contract and specify outputs through
   `Call` (docs/px.md §7.2). The author checklist is contracts.md §6.
2. **A row budget** that covers the worst case of every valid input, with headroom.
   - Measure it: `trace::usage`, as in `px/tests/unified.rs::budgets_leave_headroom`.
   - An execution over budget cannot be proven: a liveness failure for that input,
     never a leak.
3. **Pinning:** commit the ELF and its program id (as `px/vault.id`) and test that
   they match. A rebuild with another compiler changes the id.
4. **Host helpers** that produce, for each call:
   - the function's input words;
   - the kernel's `FunctionWitness`, with the **same** approvals, output
     specifications and blind as the function computes. If they differ, the proof
     cannot be built (`FunctionMismatch`), because the kernel and the function
     commit to the same `io_hash`.
   - The blind must come from a CSPRNG (security review R-6).
5. **Wallet operations** (as `px_vault_lock` and `px_vault_claim`) that:
   - choose inputs and outputs;
   - address contract outputs to the right party (§13.2);
   - keep the creator's copy;
   - pay the standard fee.
6. **Tests:** the rule violations natively and in the guest, a proof end to end, and
   the budget headroom.

Deploying registers the program, its budget, its ABI and its output words
(`px-deploy --program --budget --out-words`).
Deploying alone does not make a contract callable from the wallet: steps 4 and 5 are
code.

### 13.5 Tests

- `px/tests/delivery.rs`:
  - contract records reach only their addressee;
  - the record kind cannot be misrepresented;
  - shares open only for their addressee, and any change is refused.
- `px/tests/unified.rs`:
  - the vault program id is pinned;
  - the claim's nullifier equals `contract_nullifier`;
  - the vault's timeout, refund and contract-bound locks (§7.4).
- `wallet/src/wallet/contracts.rs` unit tests: the refund secret is seed-recoverable
  and distinct from the claim secret; `px_vault_secret` opens only records without a
  timeout; a vault deploy needs the current ABI and one output word.
- `wallet/src/px.rs` unit tests:
  - rewinds keep created and imported records;
  - `clear-pending` keeps every contract-record opening;
  - contract records are never funds;
  - `vault_operations_need_the_vault_alone_with_the_reference_budget` (P-1, P-2, and
    the ABI and output words, W3-39b);
  - `registrations_are_derived_from_the_deploy` (W3-39b).
- `wallet/src/wallet/tests_sync.rs` (W3-39b): `registrations_come_from_scanned_deploys`,
  `a_lying_registration_below_the_restore_height_is_detected`.
- `wallet/src/wallet.rs` unit tests:
  - `vault_lock_and_claim_refuse_unsafe_contracts_before_proving`: a contract
    `{vault, backdoor}` and a vault with an odd budget are refused by lock and claim,
    before any proof; the plain vault passes the check;
  - `deploys_mixing_the_vault_with_other_programs_are_refused`;
  - `a_stored_vault_secret_survives_a_save_and_load` (R11-W1).
- `wallet/src/wallet/keys.rs` unit tests (K6): `a_restored_wallet_recovers_its_vault_secret`,
  `vault_secrets_are_deterministic_and_bound_to_the_record`,
  `a_derived_vault_secret_needs_a_funded_first_input`.
- `wallet/tests/e2e.rs::an_uncertain_vault_lock_keeps_the_record_opening` also reloads
  the autosaved file after the uncertain submission and recovers the secret from it.
- `wallet/tests/e2e.rs::a_vault_is_deployed_locked_delivered_shared_and_claimed_over_rpc`,
  through a real node:
  1. deploy;
  2. lock delivered to Bob;
  3. Bob receives the record by scanning;
  4. Alice shares it with Carol, who imports it (Bob cannot open Carol's share);
  5. a wrong secret is refused before proving;
  6. Bob claims with the fee paid from v1 funds;
  7. all three wallets see the record consumed;
  8. a second claim is refused;
  9. Bob then locks half of his new PX funds for himself and claims them with the fee
     paid from a PX record: his v1 balance is untouched, and his PX balance ends at
     exactly 1 BLK minus the two fees.
