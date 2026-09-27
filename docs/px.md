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

**Security:** 124-bit collision and preimage resistance, if the permutation behaves
ideally.
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

A panic halts with exit code 1. **A proof is valid only for exit code 0**; the verifier
fixes it.

### 4.3 Proof

`prove::verify(public, calls, h_tx, proof, registered)` verifies a BVM-1 proof of the
multi-execution statement:
- the kernel program, with exit code 0 and the public words;
- one execution per called function (§7);
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
  loudly; it never leaks.
- A test checks that every tested witness uses at most 95% of each budget, and
  another that a deposit and a payment have identical shapes.
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
  resolved security review R-5. `budgets_leave_headroom` keeps every tested witness at
  or below 95% of each budget.

## 5. Consensus state (`px/src/state.rs`)

| Component | Rule |
|---|---|
| Tree | Append-only frontier: 32 digests plus the size. Commitments are appended in block order, one leaf per output commitment (two per transfer today). Capacity `CAPACITY = 2^32` leaves: a block whose commitments would exceed it is invalid (B8, transactions.md §8.3; testnet v3). The append that fills the tree keeps the full root, which the frontier returns at `size = CAPACITY` (21-D; below capacity every root is unchanged). Once full, the tree takes no more PX outputs until a new-tree epoch is designed. |
| Root window | The roots after each of the last 100 blocks (initially the empty-tree root). A transfer's anchor must be one of them. Anchors never refer to a state inside the current block. |
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
key = H32("px/delivery-key", r·V ‖ ss_kem ‖ R ‖ ct_kem ‖ cm)       AAD = cm, nonce 0 (fresh key)
```

- **User records** (`contract = 0`) go to their owner's address.
- **Contract records** (`contract ≠ 0`, owner 0) go to the party that will act on them
  (§13).
- The plaintext has one length for both kinds, so the ciphertext does not reveal the
  kind.

**Address:** the owner tag, a Ristretto view key `V`, and an ML-KEM-768 encapsulation
key (1,184 bytes). All three are derived per address from `sk`; addresses of one
wallet share nothing visible.

**Confidentiality needs both parts broken:** the discrete logarithm in Ristretto255
and ML-KEM-768. The KEM is RustCrypto `ml-kem` 0.3.2 (pure Rust, FIPS 203), pinned
exactly.

**The key combiner is not X-Wing.** The key hashes both shared secrets, both
ciphertexts (`R`, `ct_kem`) and `cm`:
- X-Wing (draft-connolly-cfrg-xwing-kem) also hashes the recipient's classical public
  key; generic hybrid combiners also bind the KEM public key. This combiner hashes
  neither `V` nor `H(ek)`, so X-Wing's security argument does not carry over as is.
- Why it is acceptable here: each key is used once, for one body whose tag and
  associated data bind `cm`, and the recipient accepts a record only if it recomputes
  `cm` (below).
- **Recorded hardening (non-blocking):** add `V` and `H(ek)` to the key hash. It
  changes every ciphertext's key (a wire-format change), so it needs a coordinated
  upgrade, best done at a testnet reset.

**Key separation: limits.** The delivery keys of address `i` derive from the PX spend
secret `sk` and `i` alone:
- **No view/spend separation.** There is no view key from which a watch-only wallet
  could derive every address's delivery keys without `sk`. One address's delivery keys
  do not reveal `sk` (the derivation is one-way), but no wallet mode exports them, and
  they would not see spends (nullifiers need `nk`).
- **No network separation.** The derivation does not include the network: one seed
  gives the same PX keys and owner tags on every network. Only the address encoding
  differs. (The v1 keys are not network-separated either.) Use separate seeds for
  testnet and mainnet.

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

- The function writes `io_hash ‖ C` as its first 16 public output words, followed by
  its own public outputs (the vault writes its selector).
- The kernel writes `(C, io_hash)` for each function, computed from the **actual**
  input commitments and outputs.
- The verifier builds both from one public value. So a proof exists only if the
  function and the kernel agree on the transcript.
- The random `blind` makes `io_hash` a hiding commitment: records, amounts and
  recipients stay private.

**Kernel rules (§4.1, exit codes in §4.2):**
- **Contract inputs:**
  - a contract input must be approved by a function of its contract (`Unauthorized`);
  - a function may approve only real records of its own contract
    (`ApprovalMismatch`).
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
- Consensus answers it from the deploy data (§11.2): PX3 checks registration, and PX5
  verifies with the registered programs and budgets (`tx/src/validate.rs`).

### 7.4 Example: a private hash-locked vault (`zkvm/guests/vault`)

- `LOCK` creates a record of the vault contract holding `value` under
  `lock = Hk(LOCK, secret)`.
- `CLAIM` takes the vault record and the secret, approves consuming the record, and pays
  its value to a recipient.

Everything except the contract id, the selector and `io_hash` stays private. Tests
(`px/tests/unified.rs`):
- LOCK and CLAIM proven and verified;
- a wrong secret gives no proof;
- 12 contract-rule violations, each rejected identically natively and in the guest;
- a function transcript that differs from the kernel's is detected;
- unregistered programs, wrong shapes and altered outputs are refused;
- kernel heights are identical for contract and user inputs.

## 8. Performance (measured, this machine, BS-ZK-2)

| Item | Value |
|---|---|
| Kernel execution (v2) | 25.0–25.2k cycles; 29.3–29.4k with one function (opt-level "z" gave 141k for v1) |
| Transfer proof | **2.04 MB** (6 proofs: 2,029,768–2,046,856 bytes), proving ~42 s, **verifying 188 ms** |
| Kernel + one function (vault CLAIM) | **~2.5 MB**, proving ~51 s (a 40-proof stress run gave 48.4–51.4 s each) |
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

1. Knowledge soundness and zero knowledge of the BVM-1 STARK at BS-ZK-2 (zk.md §9.3;
   AUDIT.md R8).
2. `Hk` and the node compression: collision resistance, preimage resistance, and PRF
   security keyed by `nk`.
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
- **Binding:** `h_tx = H32("px/tx-binding", LE32(network_id) ‖ LE32(branch_id) ‖
  genesis_id ‖ prefix hash ‖ base hash)` is the proof's binding. It covers every field
  except the range proof, the signatures and the proof, plus the network, the epoch's
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
  programs, each an ELF binary of at most 256 KiB with its row budget. The binaries
  are on chain: verifiers need them to build the statement.
- **Contract id:** 8 field elements from
  `H64("px/contract-id", first key image ‖ salt ‖ H32(payload))`. It is unique
  because key images never repeat.
- **What it registers:** each program's id and budget under the contract. Entries
  are immutable, and a registration is usable from the next block.
- **Signatures** cover the payload.

### 11.3 State and rules (`tx/src/validate.rs`, `tx/src/state.rs`)

| Rule | Meaning |
|---|---|
| Structure | Counts, sorting, identity points, range-proof shape, sizes. PX transactions: fee **exactly** `PX_STANDARD_FEE`. Deploys: fee **exactly** `deploy_fee(n, k, programs) = standard_fee(n, k) + DEPLOY_FEE_PER_BYTE × payload length`, where `standard_fee(n, k) = FEE_PER_WEIGHT × max_weight(n, k)` is the exact fee of a transfer of the shape (transactions.md T8, §8.4; `TxRules::standard_fee`, one function for both) (`DeployFeeNotExact`; v3 candidate, R5-1/R6 TX-4) |
| Balance | §11.1 (PX); the transfer rule for deploys |
| C1–C3 | Rings and key images, as for transfers. One-time keys (hidden outputs and payouts together) are distinct within the transaction (stateless: the sort of each list, and `PxDuplicateOutputKey` between them) but may repeat across transactions and the chain (transactions.md §8.2) |
| PX1 | The anchor is a root of the last 100 blocks, before this block |
| PX2 | Nullifiers are unspent and unrepeated across the chain and the block |
| PX3 | Every called function is a registered program of its contract (registry before this block) |
| PX4 | The pool stays ≥ 0 through the block, in order |
| B8 (capacity) | The block's PX output commitments, one tree leaf each, fit in the `2^32 − size` leaves left (`BlockError::PxTreeFull`); for a mempool transaction, contextual `TxError::PxTreeFull`. Checked with the byte budgets, before any cryptography. Templates never exceed it |
| PX5 | The proof verifies with the registered programs and budgets. Checked in three steps, in blocks and on every single-transaction path alike (transactions.md §8.3, §8.5): strict decoding with the stateless rules, the statement's table shape once PX3 holds and before any ring is resolved, and the verification last (the most expensive check). A malformed proof therefore costs no CLSAG (dossier 10 F10-2, red team RTW1-2) |
| Deploy | Every budget is provable: `cycles ≤ MAX_CYCLES` (2^21), `keys ≤ 2^22`, and each ALU and Poseidon2 field plus the kernel's `kernel_budget(1)` share ≤ 2^22 (stateless, `PxBudgetTooLarge`; R7-5). Programs load, and their program ids are pairwise distinct (stateless, `PxDuplicateProgram`; R5-7). The contract id is new in the chain and the block |
| Block | Coinbase = reward + all fees; block weight ≤ limit, where the v1 part of a PX or deploy transaction with `n > 0` inputs weighs `max_weight(n, k)` (transactions.md B6; R12-2); PX and deploy bytes ≤ 8 MiB |

**Chain state.** The state (`MemoryChain`) keeps the PX state, the registry and a
log of commitments, ciphertexts and nullifiers for wallets, all with exact per-block
undo. Tests check that a reorganization restores the root and pool exactly.

### 11.4 Wallets and RPC

- Wallets scan whole blocks (`/blocks`) and fetch, whole and in order:
  - the commitment list (`/px/commitments`), in pages:
    `GET /px/commitments?from=F&limit=L` returns the `(height, commitment)`
    entries at tree positions `F..F+L`, the `total` count, the current tree `root`,
    the tip `height`, and `next` (the `from` of the following page, or `null` at the
    end). Both parameters are optional: `from` defaults to 0 and `limit` to 1 024; a
    `limit` of 0 or above 4 096 is rejected (HTTP 400); a `from` at or past the end
    gives an empty page. The node copies only the requested page under its chain
    lock, so the cost of a request is proportional to the page, not to the chain.
    A wallet requests pages starting from the number of commitments it already
    has;
  - the contract-registration list (`/px/contracts`: height, contract id, program
    ids and budgets).

  The node never learns which records a wallet owns or which contracts it uses.
- CLI commands: `px-address`, `px-balance`, `px-deposit`, `px-send`, `px-withdraw`, and
  the contract commands of §13.4.
- **Canonical anchor.** Wallets use the root at the most recent height that is a
  multiple of 16. So the anchor does not reveal when a wallet last synced; a record
  becomes spendable once that height reaches it.

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
| Mempool | PX class capped at 64 MiB with fee-per-byte eviction; proofs verified once on admission; templates take PX transactions first, charge every transaction against both the weight and the PX budgets, and keep the pool non-negative in order |

## 12. Privacy guidance for users and wallets

Measured privacy analysis: `docs/reviews/privacy-review.md`.

- **Deposit and withdrawal amounts are public** (containment). Deposit round amounts,
  wait between deposits and withdrawals, and never withdraw the amount you deposited.
  The CLI prints this reminder.
- **Use your own node,** or a node you trust, reached over a private channel (an SSH
  tunnel, a VPN, or Tor through a local forwarder you run). The wallet itself has no
  Tor or SOCKS support, speaks plain HTTP only (it refuses `https://` addresses), and
  ignores proxy environment variables. The node sees when you submit a transaction;
  it learns nothing from your scanning.
- **Give each counterparty its own PX address** (`px-address --index`). Addresses of
  one wallet are unlinkable.
  - Every scanned PX address costs a scalar multiplication for every PX output, so the
    wallet hands out at most 1,000 addresses beyond the highest one that has received a
    record (2,000 with `--force`).
  - A wallet restored from the seed scans 20 addresses beyond the highest one found.
    Keep the wallet file backed up if you hand out addresses far ahead.
- **Contract calls reveal the contract, the program and the function's public
  outputs** (for the vault: LOCK or CLAIM). The time between a LOCK and its CLAIM is
  visible to anyone watching that contract.
- **The fee is the same for every PX transaction** (consensus), so it reveals nothing.
- **Never spend the same funds twice after a transaction may have been relayed**
  (privacy-review.md §3c, P-9). The wallet keeps every submitted transaction and
  rebroadcasts it unchanged. If a submission ends with "the node may or may not have
  received the transaction", just `sync` later. `clear-pending` is only for a
  transaction that certainly never left the wallet. A second spend of a v1 input
  shares the key image with the first, so the two are linkable. The wallet reuses
  the first ring so they do not reveal the real input, but these rings are kept in
  the wallet file only: keep backups of it, because a restore from the seed loses
  them.
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

**Contract index.** The wallet downloads the chain's complete registration list
(`/px/contracts`, paged, in block order) up to its scanned height, like every other
wallet.
- A wallet created after a deploy knows the contract too. The first version indexed
  deploys only while scanning, so a wallet newer than the deploy could not claim;
  that was found in review and fixed.
- To call a contract, the wallet uses the budget registered on chain and checks that
  its program is registered to that contract. For the vault it checks more (below).
- The node is trusted for the list's availability, as for blocks. A false entry can
  only make the wallet build a transaction that consensus refuses (PX3, PX5).
- On a reorganization, entries above the fork are dropped and fetched again.

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
- `px-contracts` prints a warning for a contract that registers the vault with other
  programs or another budget.
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
  not have received" can still be mined; the demonstration vault has no refund, so
  losing the secret would lock the funds for good.
- **Restore recovers it** for a vault record the wallet holds the opening of (a lock
  delivered to itself): the wallet re-derives the candidate from the record's `rho` and
  keeps it when `Hk(LOCK, candidate)` matches. A lock delivered to someone else leaves
  no opening in a restored wallet, so its secret is not recovered that way (the
  claimer has the record; the locker keeps the wallet file).
- A secret given with `--secret-file`, `--secret-prompt` or `--secret` is used as is
  and is recoverable from the wallet file only.
- `px-vault-secret --record CM [--out FILE]` shows the stored (or re-derived) secret.
  `px-records` marks the records that have one.

**Commands:**

| Command | What it does |
|---|---|
| `px-deploy --vault` or `--program F.elf --budget c,k,a,b,l,s,m,p` (repeatable) | Registers a contract, paid with v1 funds, so the deployer is hidden behind ring signatures. Prints the contract id. `--vault` deploys the vault alone |
| `px-contracts` | Lists deployed contracts and their programs (marks the vault; warns about contracts not usable as a vault) |
| `px-records` | Lists the contract records this wallet holds, with status and source |
| `px-vault-lock --contract C --amount A [--secret-file F \| --secret-prompt \| --secret S \| --secret-out F] [--deliver-to PXADDR]` | Locks PX funds in a vault record under `Hk(LOCK, S)`, delivering the record to the claimer. The fee is paid from PX. Without a secret option it derives one (above) and prints it after sending (or writes it to the `--secret-out` file) |
| `px-vault-claim --record CM [--secret-file F \| --secret S] [--to PXADDR]` | Claims a vault record, paying its value privately; asks for the secret unless a file or `--secret` is given. The fee is paid from one PX record, or else from v1 funds, so a claimer without PX funds can claim |
| `px-vault-secret --record CM [--out F]` | Shows the secret of a vault record this wallet locked |

`--secret S` on the command line stays in shell history and is visible to other local
users in the process list. The wallet warns when it is used; prefer `--secret-file` or
the prompt.
| `px-share --record CM --to PXADDR` / `px-import --share HEX` | Off-chain sharing (§13.3) |

**The reference vault** (`px/src/vault.rs`, program pinned in `px/vault.elf` and
`px/vault.id`) is a **demonstration contract. It is not production-ready and not
trustless**:

| Limitation | Consequence |
|---|---|
| **No timeout** | A vault stays claimable forever |
| **No refund** | The value never returns to the locker except by claiming with the secret |
| **The locker knows the secret** | The locker can claim too; whoever holds the secret and the record's opening can claim |
| **Not a trustless swap** | A hash-time-locked contract needs a timelock and a refund function; this vault has neither |

The wallet prints this warning on every `px-vault-lock`, and the command help says
the same.

**Recovery after restoring a wallet from its seed:**

| Contract record | Recovered from the seed? |
|---|---|
| Received (its ciphertext was addressed to this wallet) at or after the restore height | Yes, by scanning |
| Received before the restore height | No: restore from an earlier height, or ask a holder for a share |
| Created by this wallet and addressed to itself (the default) | Yes, as a received record |
| Created by this wallet and addressed to another party | **No:** the creator's copy lives only in the wallet file. Keep the file, or have the other party share the record back |
| Imported from a share | No: import the share again |

Contracts themselves (their registrations) are always recovered: the wallet
downloads the whole registration list.

### 13.4.1 Host-side helpers for other contracts

The wallet can call a contract only through a host-side helper like `px::vault`.
Writing one for a new contract requires:
1. **A function program** (a RISC-V ELF built with the zkVM SDK) that:
   - reads its private input;
   - checks the contract's rules;
   - writes `io_hash ‖ contract` (`px_core::call::function_prefix`) and then its
     public outputs.
   It must approve only records of its own contract and specify outputs through
   `Call` (docs/px.md §7.2).
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

Deploying registers the program and its budget (`px-deploy --program --budget`).
Deploying alone does not make a contract callable from the wallet: steps 4 and 5 are
code.

### 13.5 Tests

- `px/tests/delivery.rs`:
  - contract records reach only their addressee;
  - the record kind cannot be misrepresented;
  - shares open only for their addressee, and any change is refused.
- `px/tests/unified.rs`:
  - the vault program id is pinned;
  - the claim's nullifier equals `contract_nullifier`.
- `wallet/src/px.rs` unit tests:
  - rewinds keep created and imported records;
  - `clear-pending` keeps every contract-record opening;
  - contract records are never funds;
  - `vault_operations_need_the_vault_alone_with_the_reference_budget` (P-1, P-2).
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
