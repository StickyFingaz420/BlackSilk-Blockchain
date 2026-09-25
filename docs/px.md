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
| Tree | Append-only frontier: 32 digests plus the size. Commitments are appended in block order, two per transfer. |
| Root window | The roots after each of the last 100 blocks (initially the empty-tree root). A transfer's anchor must be one of them. Anchors never refer to a state inside the current block. |
| Nullifier set | A nullifier can appear once, ever: across blocks, within a block, and within a transfer. |
| Pool | `pool' = pool + bridge_in − bridge_out ≥ 0`, applied in order, as `u128`. Even a complete proof-system break cannot withdraw more than was deposited (containment, zk.md §4.7). |

- Blocks apply atomically: one bad transfer leaves the state untouched.
- `apply_block` returns an undo record that restores the previous state exactly.
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
  contract (`Unauthorized`), so nobody can forge contract state.
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
  for about four PX transactions per 2-minute block.
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
- **Binding:** `h_tx = H32("px/tx-binding", network ‖ prefix hash ‖ base hash)` is
  the proof's binding. It covers every field except the range proof, the signatures
  and the proof, and the network.
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
| Structure | Counts, sorting, identity points, range-proof shape, sizes. PX transactions: fee **exactly** `PX_STANDARD_FEE`. Deploys: fee ≥ `PX_FEE_PER_BYTE` × encoded size |
| Balance | §11.1 (PX); the transfer rule for deploys |
| C1–C4 | Rings, key images and one-time keys, as for transfers, including payouts |
| PX1 | The anchor is a root of the last 100 blocks, before this block |
| PX2 | Nullifiers are unspent and unrepeated across the chain and the block |
| PX3 | Every called function is a registered program of its contract (registry before this block) |
| PX4 | The pool stays ≥ 0 through the block, in order |
| PX5 | The proof verifies with the registered programs and budgets (last; most expensive) |
| Deploy | The contract id is new in the chain and the block; programs load |
| Block | Coinbase = reward + all fees; v1 weight ≤ limit; PX and deploy bytes ≤ 8 MiB |

**Chain state.** The state (`MemoryChain`) keeps the PX state, the registry and a
log of commitments, ciphertexts and nullifiers for wallets, all with exact per-block
undo. Tests check that a reorganization restores the root and pool exactly.

### 11.4 Wallets and RPC

- Wallets scan whole blocks (`/blocks`) and fetch, whole and in order:
  - the commitment list (`/px/commitments`);
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
| Block PX budget | 8 MiB (about 4 PX transactions); total block ≤ `MAX_BLOCK_BYTES` = 1,000,000 + 8 MiB + 64 KiB = 9,454,144 bytes |
| PX fee | Exactly `PX_STANDARD_FEE = PX_FEE_PER_BYTE × MAX_PX_TX_SIZE` = 8,912,896 atomic units, a consensus rule (§12). It covers the per-byte fee of any PX transaction. Consequence: every PX transaction pays the same, so the mempool's fee-per-byte ordering ranks larger ones (contract calls, ~2.5 MB) below plain transfers (~2 MB) when the PX budget is congested |
| Relay | PX and deploy transactions together: per peer 0.2/s (burst 4); all peers together 2/s (burst 10) |
| Invalid proof | Misbehaviour (the statement is branch-independent once PX1 and PX3 pass) |
| Mempool | PX class capped at 64 MiB with fee-per-byte eviction; proofs verified once on admission; templates keep the pool non-negative in order |

## 12. Privacy guidance for users and wallets

Measured privacy analysis: `docs/reviews/privacy-review.md`.

- **Deposit and withdrawal amounts are public** (containment). Deposit round amounts,
  wait between deposits and withdrawals, and never withdraw the amount you deposited.
  The CLI prints this reminder.
- **Use your own node,** or reach one over Tor. The node sees when you submit a
  transaction; it learns nothing from your scanning.
- **Give each counterparty its own PX address** (`px-address --index`). Addresses of
  one wallet are unlinkable.
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
  its program is registered to that contract.
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

- `clear-pending` also drops unconfirmed records this wallet created in transactions
  that never confirmed.
- A contract record is spendable once confirmed at or below the canonical anchor (§11.4).

**Commands:**

| Command | What it does |
|---|---|
| `px-deploy --vault` or `--program F.elf --budget c,k,a,b,l,s,m,p` (repeatable) | Registers a contract, paid with v1 funds, so the deployer is hidden behind ring signatures. Prints the contract id |
| `px-contracts` | Lists deployed contracts and their programs (marks the vault) |
| `px-records` | Lists the contract records this wallet holds, with status and source |
| `px-vault-lock --contract C --amount A [--secret S] [--deliver-to PXADDR]` | Locks PX funds in a vault record under `Hk(LOCK, S)`, delivering the record to the claimer. The fee is paid from PX. Prints the secret if it was generated |
| `px-vault-claim --record CM --secret S [--to PXADDR]` | Claims a vault record, paying its value privately. The fee is paid from one PX record, or else from v1 funds, so a claimer without PX funds can claim |
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
  - `clear-pending` drops only unconfirmed created records;
  - contract records are never funds.
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
