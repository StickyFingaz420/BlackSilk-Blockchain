# PX: private records, nullifiers and the transfer kernel

Status: **v0.2, implemented and tested; not consensus; not production-ready.**
- Architecture: [`zk.md`](zk.md) §4–§6.
- Virtual machine: [`zkvm.md`](zkvm.md).
- Progress and findings: AUDIT.md R8.

This document specifies what the code in `px-core/` (crate `blacksilk-px-core`) and
`px/` (crate `blacksilk-px`) implements: the hash `Hk`, keys, records, nullifiers, the
commitment tree, the kernel and its proofs, contract records and functions in one
unified proof (§7), the consensus state, and record delivery. §10 lists what is **not**
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
sk      = Hk(SK, seed as sixteen 16-bit limbs)       from the 32-byte wallet seed
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
commitment of the output record. The function rules of §7.2 apply.

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
| 9 | TooManyFunctions | | |

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

### 4.4 Constant work (trace-shape privacy)

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
- **Margin:** the largest table (CPU, 2^15 rows) is 90% full with one function. A
  future change must keep all witnesses on one side of the power of two (security
  review R-5).

## 5. Consensus state (`px/src/state.rs`)

| Component | Rule |
|---|---|
| Tree | Append-only frontier: 32 digests plus the size. Commitments are appended in block order, two per transfer. |
| Root window | The roots after each of the last 100 blocks (initially the empty-tree root). A transfer's anchor must be one of them. Anchors never refer to a state inside the current block. |
| Nullifier set | A nullifier can appear once, ever: across blocks, within a block, and within a transfer. |
| Pool | `pool' = pool + bridge_in − bridge_out ≥ 0`, applied in order, as `u128`. Even a complete proof-system break cannot withdraw more than was deposited (containment, zk.md §4.7). |

- Blocks apply atomically: one bad transfer leaves the state untouched.
- `apply_block` returns an undo record that restores the previous state exactly.
- Proofs are verified before these rules. The state sees only verified statements.

**Not yet done:**
- the transaction format;
- bridge amounts tied to the v1 side;
- fees;
- persistence;
- block validation wiring.

These belong to the consensus-integration phase (AUDIT.md R8).

## 6. Record delivery (`px/src/delivery.rs`)

Each output carries its record encrypted to the recipient's address. The ciphertext is
1,209 bytes:

```text
R (32) ‖ view tag (1) ‖ ML-KEM-768 ciphertext (1088) ‖ ChaCha20-Poly1305(value ‖ data ‖ rcm) (72 + 16)
key = H32("px/delivery-key", r·V ‖ ss_kem ‖ R ‖ ct_kem ‖ cm)       AAD = cm, nonce 0 (fresh key)
```

**Address:** the owner tag, a Ristretto view key `V`, and an ML-KEM-768 encapsulation
key (1,184 bytes). All three are derived per address from `sk`; addresses of one
wallet share nothing visible.

**Confidentiality needs both parts broken:** the discrete logarithm in Ristretto255
and ML-KEM-768. The KEM is RustCrypto `ml-kem` 0.3.2 (pure Rust, FIPS 203), pinned
exactly.

**Acceptance** (Janus principle, transactions.md §12): the recipient accepts a record
only if it recomputes the on-chain commitment with its own owner tag and the
transaction's `rho`. A probe with inconsistent contents is ignored.

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
  contract (`Unauthorized`), so nobody can forge contract state.
- **Function contracts:** a function's contract is nonzero (`ZeroContract`).
- **Dummies:** a dummy input may not be a contract record (`DummyContract`).

### 7.3 The registry (consensus requirement)

The proof shows that *some* program produced each function's transcript. It must be
the contract's program: otherwise anyone could write a function that approves spending
another contract's records.
- `prove::verify` therefore takes `registered(contract, program_id)` as a **mandatory**
  argument. The tests check that an unregistered program is refused.
- Consensus must answer it from the contract deploy data (zk.md §8.3). That is part of
  the consensus-integration phase.

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
| Kernel execution | 18.7k cycles (opt-level "z" gave 141k; hashing path optimized: 7.5×) |
| Poseidon2 permutations per transfer | ~144 (tree nodes use one permutation each) |
| Transfer proof | **2.05 MB**, proving ~40 s, verifying 1.4 s |
| Record ciphertext | 1,209 bytes per output |

**Proof size is the main open problem.** A single transfer proof is far too large for
per-transaction use on a chain.
- **Causes:**
  - 108 FRI queries, each opening ~2,400 committed elements across 12 tables;
  - the degree-8 challenge extension, needed for the security margin.
- **Parameter options**, measured by `zk/examples/param_study.rs`:
  - dropping the extra unique-decoding target and keeping Johnson ≥ 120 needs 49–71
    queries (−35% to −55%);
  - a higher blow-up trades prover time for fewer queries.

  This is a security-policy decision for the owner.
- **Architectural fix:** aggregate the transfers of a block into one proof (recursion),
  or verify many transfers in one batch proof (ZK-5 already shares tables between
  executions). This is a future milestone and not claimed here.

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

1. **External review (required before any production use):**
   - Poseidon2 parameters and the `Hk` constructions;
   - the kernel statement;
   - the zkVM circuits (AUDIT.md R8);
   - the hybrid delivery combiner.
2. **Proof size:** see §8.
3. **Consensus integration:** transaction format, fees, v1 bridge, persistence, block
   validation.
4. **Contract functions, beyond this version:**
   - the registry in consensus (§7.3);
   - distributing contract-record plaintext to the parties that need it;
   - an SDK padding helper for constant-work functions;
   - more than two functions per transaction.
5. **Wallet:** note scanning over chain data, witness maintenance for the tree
   (incremental paths), and backup of per-address state.
6. **Fuzzing** of the witness decoder and of the delivery `open` function.
