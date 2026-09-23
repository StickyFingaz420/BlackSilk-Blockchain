# BlackSilk Transaction Specification

Status: **v1, implemented** by `blacksilk-crypto` (`crypto/`) and `blacksilk-tx` (`tx/`).
Not yet externally reviewed (§15). This document is normative: wallets, nodes and miners
must follow exactly these rules. Where this document and the code disagree, that is a bug.

Scope:
- transaction format, serialization and hashing
- key and address derivation
- stealth outputs and view tags
- amount commitments and range proofs (Bulletproofs+)
- ring signatures (CLSAG) and key images
- validation rules (stateless, contextual, block-level)
- the privacy model, security guarantees, assumptions and known limitations

Out of scope, and specified separately:
- header chain: [`consensus.md`](consensus.md)
- emission schedule, block reward, block weight limit, fee constants: block/economics spec, pending
- wallet seed format, address string encoding: wallet spec, pending
- transaction relay (Dandelion++, Tor/I2P): P2P spec, pending

Design basis: the Monero RingCT stack as deployed since 2022 (CLSAG, Bulletproofs+,
view tags), with a small number of deliberate changes. Each change is marked
**[Δ Monero]** and justified; §14 lists them together for review.

All integers are unsigned and little-endian unless stated otherwise.

---

## 1. Cryptographic primitives

### 1.1 Group: Ristretto255 [Δ Monero]

All public keys, key images and commitments are elements of the **Ristretto255** group
(RFC 9496), built on Curve25519. Implementation: `curve25519-dalek` 4.x (pure Rust, no
`unsafe` in our code, audited by Quarkslab in 2019).

- `ℓ = 2^252 + 27742317777372353535851937790883648493`: the prime group order.
- `G`: the Ristretto255 base point.
- Scalars are integers mod `ℓ`, encoded as 32 bytes little-endian.
- Points are encoded as 32-byte compressed Ristretto.

**Why not Ed25519 (as Monero does):** Ed25519 has cofactor 8. Every protocol built on it
must defend against small-order components:
- Monero's 2017 key-image bug: `I + T` for a torsion point `T` was a fresh key image for
  the same output, which allowed an unlimited double spend.
- Monero stores `D/8` in CLSAG and multiplies by 8 in several places.

Ristretto255 is a **prime-order** group with a single canonical encoding per element.
That whole class of bugs cannot occur, and every point we decode is already in the group
the security proofs assume. The cost is incompatibility with Monero's wallets and test
vectors, which we do not need.

**Decoding rules (consensus):**
- A point is valid only if its 32 bytes decode as canonical Ristretto (dalek's
  `CompressedRistretto::decompress` returns `Some`).
- A scalar is valid only if it is canonical, i.e. `< ℓ` (`Scalar::from_canonical_bytes`).
  Non-canonical scalars are rejected, never reduced.

### 1.2 Hash functions and domain separation

All hashing uses **Blake2b** (RFC 7693). Every hash has a domain tag. The tag is
length-prefixed so that no two (tag, data) pairs can produce the same hash input:

```
tag(t)     = u8(len(t)) ‖ t                    t is ASCII, always "BlackSilk/v1/" ‖ name
H32(t, x)  = Blake2b-256(tag(t) ‖ x)           32-byte hash
H64(t, x)  = Blake2b-512(tag(t) ‖ x)           64-byte hash / keystream
Hs(t, x)   = H64(t, x) interpreted as a 512-bit LE integer, reduced mod ℓ
Hp(t, x)   = Ristretto255 element derivation (RFC 9496 §4.3.4) of H64(t, x)
```

- `Hs` reduces 512 bits mod `ℓ`, so its bias is below 2^-259 (negligible). This is
  dalek's `Scalar::from_bytes_mod_order_wide`.
- `Hp` is the standard hash-to-group (dalek's `RistrettoPoint::from_uniform_bytes`). Nobody
  knows the discrete logarithm of its output with respect to any other generator.
- Every input `x` has a fixed length or an explicit length prefix, so concatenations are
  unambiguous.

Tag names used in this document (each is prefixed with `BlackSilk/v1/`):

| Name | Use |
|---|---|
| `generator/H` | value generator `H` |
| `generator/bp+/G`, `generator/bp+/H` | Bulletproofs+ vector generators |
| `subaddress` | subaddress offset |
| `input-context`, `input-context/coinbase` | per-transaction output context |
| `ephemeral` | per-output ephemeral secret `r` |
| `output-key`, `view-tag`, `amount`, `mask`, `anchor` | per-output derivations |
| `key-image` | `Hp` for key images |
| `clsag/agg-P`, `clsag/agg-C`, `clsag/round` | CLSAG |
| `bp+/init`, `bp+/y`, `bp+/z`, `bp+/round`, `bp+/final` | Bulletproofs+ transcript |
| `tx/prefix`, `tx/base`, `tx/prunable`, `tx/bp`, `tx/hash`, `tx/sig-message` | tx hashing |
| `nonce` | hedged signing nonces (wallet side) |

### 1.3 Generators

```
G      = Ristretto255 base point                          (blinding generator)
H      = Hp("generator/H", "")                            (value generator)
Gbp[i] = Hp("generator/bp+/G", LE32(i))   i = 0..1023     (BP+ vector generators)
Hbp[i] = Hp("generator/bp+/H", LE32(i))   i = 0..1023
```

All generators are nothing-up-my-sleeve: their discrete-log relations are unknown to
everyone, including the designers. That independence is what makes the commitments
binding (§9.1).

### 1.4 Pedersen commitments

`Com(a, y) = y·G + a·H` commits to amount `a ∈ [0, 2^64)` with mask `y`.
- It is **perfectly hiding**: `Com(a, y)` is uniformly distributed for uniform `y`,
  whatever `a` is.
- It is **computationally binding** under the discrete-log assumption (§9).

---

## 2. Keys and addresses

### 2.1 Wallet keys

A wallet has two independent secret scalars:
- `k_s`: the spend key. It authorizes spending.
- `k_v`: the view key. It detects incoming outputs and decrypts amounts.

Public spend key: `K_s = k_s·G`. Both keys derive from a 32-byte seed drawn from a
CSPRNG:

```
k_s = Hs("wallet/spend-key", seed)      k_v = Hs("wallet/view-key", seed)
```

There is no default or fixed seed (fixes audit finding K1). The mnemonic encoding of the
seed is defined in the wallet spec.

### 2.2 Addresses and subaddresses [Δ Monero]

Every address is a pair of points `(D, C)`. For account `a` and index `i`:

```
m(a,i) = 0                                                     if (a,i) = (0,0)
       = Hs("subaddress", k_v ‖ LE32(a) ‖ LE32(i))             otherwise
D(a,i) = K_s + m(a,i)·G            spend public key of the (sub)address
C(a,i) = k_v · D(a,i)              view public key of the (sub)address
d(a,i) = k_s + m(a,i)              spend secret for D(a,i)
```

`(0,0)` is the primary address. In Monero, the primary address uses view key `k_v·G` and
subaddresses use `k_v·D`, so the two need different transaction formats: subaddress
recipients force "additional tx public keys", which **publicly flags** a transaction as
paying a subaddress. Here every address, including the primary one, has the form
`(D, k_v·D)`. One output format then serves all recipients, and that fingerprint is gone.

Subaddresses cannot be linked to each other without `k_v` (DDH). Wallets should hand out
a fresh subaddress per counterparty or payment instead of payment IDs. **There are no
payment IDs.**

The wallet keeps a table `D(a,i) → (a,i)` for the subaddresses it has generated (a
lookahead window, as Monero does).

---

## 3. Outputs (stealth addresses)

### 3.1 Input context

Every output derivation is bound to a value that is unique for the transaction that
creates it:

```
transfer:  ctx = H32("input-context", I_0 ‖ I_1 ‖ … ‖ I_{n-1})     key images in tx order (§5.2)
coinbase:  ctx = H32("input-context/coinbase", LE64(height))
```

Key images are unique on chain (§8.2), and so are coinbase heights. So two outputs in
different transactions never share derivation inputs, even if a wallet's RNG fails
completely. This prevents Monero's 2018 "burning bug" (two outputs with the same one-time
key, only one of which is spendable) by construction. §8.2 C4 adds a consensus backstop.

### 3.2 Sending to `(D, C)` [Δ Monero: per-output ephemeral key and Janus anchor]

For each output, the sender:

```
1. anchor ← 16 bytes from the CSPRNG (hedged, §10)
2. r      = Hs("ephemeral", anchor ‖ ctx ‖ D ‖ C)            ephemeral secret
3. R      = r·D                                              ephemeral public key (published)
4. S      = r·C                                              shared secret (= k_v·R)
5. x      = Hs("output-key", S)
6. O      = x·G + D                                          one-time output key (published)
7. view_tag  = H32("view-tag", S)[0]                         1 byte (published)
8. y      = Hs("mask", S)                                    commitment mask
9. Cm     = y·G + a·H                                        amount commitment (published)
10. enc_amount = LE64(a)  XOR H64("amount", S)[0..8]         (published)
11. enc_anchor = anchor   XOR H64("anchor", S)[0..16]        (published)
```

Each output has its own ephemeral key `R`, 32 bytes more than Monero's shared key.
Consequences:
- Transactions look the same whoever the recipients are (primary address, subaddress,
  or a mix).
- Scanning costs one scalar multiplication per output instead of per transaction (§13).

### 3.3 Receiving (scanning)

For each output `(O, R, view_tag, Cm, enc_amount, enc_anchor)` in a transaction with
context `ctx`, the wallet:

```
1. S = k_v·R                                                 one variable-base scalar mult
2. if H32("view-tag", S)[0] ≠ view_tag: not ours; stop      (rejects 255/256 of foreign outputs)
3. x = Hs("output-key", S); D' = O − x·G
4. look up D' in the subaddress table; if absent: not ours; stop
5. anchor = enc_anchor XOR H64("anchor", S)[0..16]
   r = Hs("ephemeral", anchor ‖ ctx ‖ D' ‖ C(D'))
   if r·D' ≠ R: reject the output as a Janus probe (§12); do not show it as received
6. a = LE64⁻¹(enc_amount XOR H64("amount", S)[0..8]);  y = Hs("mask", S)
   if y·G + a·H ≠ Cm: reject (bogus amount)
7. record the output: one-time secret p = x + d(a,i), amount a, mask y
```

Steps 1–6 need only `k_v` (view-only wallets can run them). Step 5 costs one more scalar
multiplication, only for outputs that are actually ours.

### 3.4 Spending and key images

The one-time secret for `O` is `p = x + d(a,i)`, with `p·G = O`. Its **key image** is

```
I = p · Hp("key-image", O)
```

`I` is fully determined by `O`, since `p` is unique in a prime-order group. So each
output has exactly one key image, and a second spend of the same output produces the same
`I`. Only the holder of `k_s` can compute `I`.

---

## 4. Transaction format

### 4.1 Encoding primitives

- `varint`: unsigned LEB128, at most 10 bytes, value ≤ `u64::MAX`. The encoding must
  be **minimal**: no trailing zero groups, so `0x80 0x00` is invalid. Non-minimal or
  overflowing encodings invalidate the transaction.
- `point`: 32 bytes, §1.1. `scalar`: 32 bytes, §1.1.
- There are **no optional fields, no free-form `extra` field, no `unlock_time` and no
  payment IDs** [Δ Monero]. Everything that can vary between wallets is either fixed by
  consensus or absent. In Monero, `extra` and `unlock_time` are the largest sources of
  wallet fingerprinting and can carry arbitrary data.

Decoding is strict: every field is range-checked while decoding, trailing bytes are
invalid, and a transaction has exactly one valid encoding.

### 4.2 Transfer transaction

```
Prefix
  version          varint   = 1
  kind             u8       = 1 (transfer)
  input_count      varint   1 ≤ n ≤ 64
  inputs[n]:
    key_image      point    I
    ring[16]       varint   first: absolute global output index; then 15 deltas, each ≥ 1
  output_count     varint   2 ≤ k ≤ 16
  outputs[k]:
    one_time_key   point    O
    ephemeral      point    R
    view_tag       u8
    commitment     point    Cm
    enc_amount     8 bytes
    enc_anchor     16 bytes
  fee              varint   atomic units, in the clear

Base
  pseudo_outs[n]   point    C'_k, one per input, same order as inputs

Prunable
  bp_plus          BP+ proof over the k output commitments (§7)
  clsag[n]:        one per input, same order as inputs
    c0             scalar
    s[16]          scalar
    D              point
```

Ring size is **exactly 16**. It is fixed by consensus, so every input looks the same.

### 4.3 Coinbase transaction

```
Prefix
  version          varint   = 1
  kind             u8       = 0 (coinbase)
  height           varint   = height of the containing block
  output_count     varint   1 ≤ k ≤ 16
  outputs[k]:
    one_time_key   point    O
    ephemeral      point    R
    view_tag       u8
    amount         varint   in the clear
    enc_anchor     16 bytes
```

Coinbase outputs follow the same rules as transfer outputs: one-time keys and
ephemeral keys must not be the identity, and outputs are strictly sorted by one-time key
(§5.2).

A coinbase output's commitment is not transmitted. It is defined as `Cm = 1·G + a·H`, so
anyone can verify it and coinbase outputs can serve as ring members for any transfer.
Coinbase outputs still pay a one-time stealth key, so the miner stays anonymous.
Committing to `height` makes every coinbase transaction unique.

Miners do not need an `extra` nonce: the header nonce is 64 bits, and the per-output `R`
values already make every template unique.

### 4.4 Hashes

```
prefix_hash   = H32("tx/prefix",   prefix bytes)
base_hash     = H32("tx/base",     base bytes)          (empty for coinbase)
prunable_hash = H32("tx/prunable", prunable bytes)      (empty for coinbase)
tx_hash       = H32("tx/hash", prefix_hash ‖ base_hash ‖ prunable_hash)
bp_hash       = H32("tx/bp", bp_plus bytes)

sig_message   = H32("tx/sig-message",
                    LE32(network_id) ‖ prefix_hash ‖ base_hash ‖ bp_hash)
```

- `tx_hash` is the transaction id. It is the leaf of the block's `tx_root` (consensus.md
  §7). It covers every byte of the transaction. The three-part structure allows pruning
  later.
- Every CLSAG signs `sig_message`, which covers **everything except the CLSAGs
  themselves**: version, inputs (key images and ring references), outputs, fee,
  pseudo-outputs and the range proof. Changing any bit of any of these invalidates every
  signature (fixes audit finding S3).
- `network_id` in the message makes a signature valid on one network only, so no
  cross-network replay is possible.

---

## 5. Ring members and inputs

### 5.1 Global output index

Every output, coinbase and transfer alike, gets the next **global index** in chain order:
- blocks in height order;
- within a block, transactions in block order (coinbase first);
- within a transaction, outputs in their serialized order.

Ring member `j` of input `k` refers to the output with the global index decoded from
`ring[]`, i.e. its pair `(O_j, Cm_j)`.

### 5.2 Ordering rules (consensus)

- **Inputs** are sorted by key image bytes, strictly increasing (no duplicates in a tx).
- **Ring indices** are strictly increasing (deltas ≥ 1), so no duplicate members.
- **Outputs** are sorted by one-time key bytes, strictly increasing [Δ Monero].

`O` is pseudorandom, so the sorted order is a uniformly random permutation. No wallet can
leak "the change is the last output", and output order carries no information.

### 5.3 Age rules (consensus)

A transaction included in a block at height `h` may reference an output created at height
`h_o` only if:
- `h − h_o ≥ 10` for transfer outputs (**spendable age**), and
- `h − h_o ≥ 60` for coinbase outputs (**coinbase maturity**).

The mempool applies the same rule with `h = best height + 1`.

Why: a reorganization shallower than 10 blocks can never invalidate a ring, because every
member is buried deeper than the reorg. Coinbase outputs disappear in any reorg that
replaces their block, so they get a longer maturity.

---

## 6. Balance: pseudo-outputs

For each input `k`, the sender chooses a pseudo-output commitment `C'_k = z_k·G + a_k·H`,
where `a_k` is the true input amount. The masks are chosen so that

```
Σ_k z_k = Σ_j y_j          (y_j are the output masks)
```

With that choice, the balance equation holds:

```
Σ_k C'_k  =  Σ_j Cm_j + fee·H                     (consensus check, §8.1 T9)
```

For the real ring member `π`, `Cm_π − C'_k = (y_π − z_k)·G`: a commitment to zero. The
CLSAG for input `k` proves knowledge of that `G`-discrete-log (§6.1). That proves `C'_k`
commits to the same amount as the real input, without revealing which ring member is
real.

- **Inputs:** input amounts were range-proven when their outputs were created, so they
  are in `[0, 2^64)`.
- **Outputs:** output amounts are range-proven in this transaction (§7).
- **No wrap-around:** with at most 64 inputs and 16 outputs, both sides of the equation
  are below `2^71 ≪ ℓ`, so it cannot hold modulo `ℓ` in a way it doesn't hold over the
  integers.

This is what makes inflation impossible (fixes audit finding S4).

### 6.1 CLSAG

Concise Linkable Spontaneous Anonymous Group signatures: Goodell, Noether, Blue,
*"Concise Linkable Ring Signatures and Forgery Against Adversarial Keys"*, IACR ePrint
2019/654. Monero has used CLSAG since 2020 (v13). It was audited before deployment
(Aumasson & Vennard, 2020). BlackSilk follows Monero's construction, except that
Ristretto removes the cofactor handling.

**Inputs to sign:**
- ring `P[0..16)` and `Cr[0..16)`: the `(O, Cm)` of the members
- pseudo-output `C'`
- message `m = sig_message`
- secret index `π`, with `p·G = P[π]` and `z·G = Cr[π] − C'`

```
Hπ  = Hp("key-image", P[π])
I   = p·Hπ                      key image (stored in the input, not in the signature)
D   = z·Hπ                      auxiliary commitment image (stored in the signature)

ring_bytes = P[0] ‖ … ‖ P[15] ‖ Cr[0] ‖ … ‖ Cr[15]
μP  = Hs("clsag/agg-P", ring_bytes ‖ I ‖ D ‖ C')
μC  = Hs("clsag/agg-C", ring_bytes ‖ I ‖ D ‖ C')
W   = μP·I + μC·D               aggregated key image

α ← hedged nonce (§10)
c[π+1] = Hs("clsag/round", ring_bytes ‖ C' ‖ m ‖ α·G ‖ α·Hπ)
for i = π+1, …, π−1 (mod 16):
    s[i] ← hedged random scalar
    L    = s[i]·G  + c[i]·(μP·P[i] + μC·(Cr[i] − C'))
    R    = s[i]·Hp("key-image", P[i]) + c[i]·W
    c[i+1] = Hs("clsag/round", ring_bytes ‖ C' ‖ m ‖ L ‖ R)
s[π] = α − c[π]·(μP·p + μC·z)
signature = (c0 = c[0], s[0..16), D)
```

**Verification:** decode every point and scalar (§1.1) and reject `I = identity`.
Recompute `μP`, `μC` and `W`, then run the loop for `i = 0..15` starting from `c[0] = c0`.
The signature is valid iff the final `c[16]` equals `c0`.

---

## 7. Range proofs: Bulletproofs+

Chung, Han, Ju, Kim, Seo, *"Bulletproofs+: Shorter Proofs for a Privacy-Enhanced
Distributed Ledger"*, IACR ePrint 2020/735, aggregated range proof (§4 and Fig. 3,
weighted inner-product argument of Fig. 1). Monero has used BP+ since 2022 (v15). It was
audited by Cypher Stack (Feickert, 2022).

**Statement:** for the output commitments `V_0..V_{k−1}` (the `Cm_j`), each commits to an
amount in `[0, 2^64)`.
- Bit length `n = 64`.
- `M = k` rounded up to a power of two (`M ≤ 16`); `N = 64·M ≤ 1024`.
- Padding slots are treated as commitments to 0 with mask 0 (the identity) and are not
  transmitted.
- In the paper's notation, `g` (value) = `H`, `h` (blinding) = `G`, and the vector
  generators are `Gbp[0..N)` and `Hbp[0..N)`.

**Proof encoding** (`2·log2(N) + 6` elements):

```
A, A1, B          point
r1, s1, d1        scalar
L[log2(N)]        point
R[log2(N)]        point
```

The number of `L`/`R` entries is implied by `k`. Any other length is invalid.

**Fiat–Shamir transcript** [normative]. Every challenge hashes the complete statement and
all prior prover messages. This avoids the "weak Fiat–Shamir" (Frozen Heart) class of
forgeries.

```
t0 = H32("bp+/init", LE8(n) ‖ LE8(M) ‖ LE8(k) ‖ V_0 ‖ … ‖ V_{k−1})
y  = Hs("bp+/y", t0 ‖ A)
z  = Hs("bp+/z", t0 ‖ A ‖ y)
t  = z                                   (running transcript, 32 bytes)
round j:  e_j = Hs("bp+/round", t ‖ L[j] ‖ R[j]);  t = e_j
final:    e   = Hs("bp+/final", t ‖ A1 ‖ B)
```

Any challenge equal to 0 invalidates the proof. An honest prover hitting 0 (probability
2^-252) restarts with fresh randomness.

**Verification** is the single multi-scalar-multiplication check from the paper. Nodes
may batch-verify all BP+ proofs of a block, weighting each proof's equation with an
independent random 128-bit scalar from the verifier's CSPRNG.
- A batch that fails rejects the block.
- The mempool verifies each transaction individually.
- Batch weights are local randomness and never affect consensus: a valid batch passes
  under any weights, and an invalid one fails except with probability 2^-128.

---

## 8. Validation rules

The rules are listed in evaluation order: cheap checks first, elliptic-curve work last.

### 8.1 Stateless (transaction alone)

| # | Rule |
|---|---|
| T1 | Strict decode (§4); `size ≤ MAX_TX_SIZE = 100 000` bytes; no trailing bytes. |
| T2 | `version = 1`; `kind ∈ {0, 1}`; a coinbase is only valid as the first tx of a block (B1). |
| T3 | Transfer: `1 ≤ n ≤ 64` inputs, `2 ≤ k ≤ 16` outputs. |
| T4 | Key images decode, are not the identity, and are strictly increasing (§5.2). |
| T5 | Each input has exactly 16 ring indices, strictly increasing, with no `u64` overflow. |
| T6 | Every `O` and `R` decodes and is not the identity. Every `Cm` decodes. `O`s are strictly increasing. |
| T7 | Exactly `n` pseudo-outputs; each decodes. |
| T8 | `fee ≥ min_fee(weight)`; fee arithmetic is checked and never overflows (§8.4). |
| T9 | Balance: `Σ C'_k − Σ Cm_j − fee·H = identity`. |
| T10 | BP+: length matches `k`, all elements decode, all scalars canonical, proof verifies (§7). |
| T11 | Exactly `n` CLSAGs; all scalars canonical, all `D` decode. |

### 8.2 Contextual (against the chain state at the block's parent)

| # | Rule |
|---|---|
| C1 | Every ring index refers to an existing output that satisfies the age rules (§5.3). |
| C2 | No key image is already spent on chain, or earlier in the same block. |
| C3 | Each CLSAG verifies (§6.1) over the resolved ring, its `C'_k`, its `I`, and `sig_message`. |
| C4 | No output's `O` already exists on chain or earlier in the same block (global one-time-key uniqueness) [Δ Monero]. |

C4 costs one index lookup per output. It makes a second, unspendable copy of a one-time
key (the burning bug) impossible even for broken wallets.

### 8.3 Block-level

| # | Rule |
|---|---|
| B1 | The first transaction is a coinbase; no other transaction is. |
| B2 | Coinbase `height` equals the block height. |
| B3 | `Σ coinbase amounts = block_reward(height) + Σ fees`, exactly (u128 arithmetic). Under-claiming is invalid, so the supply is exactly computable [Δ Monero, which allows ≤]. |
| B4 | Key images and one-time keys are unique within the block (covered by C2/C4 applied in order). |
| B5 | `tx_root` equals the Merkle root of the `tx_hash`es in block order (consensus.md §7). |
| B6 | Block weight ≤ block weight limit (economics spec). |
| B7 | Coinbase structure: 1–16 outputs, no identity `O` or `R`, outputs strictly sorted, one-time keys unique (C4). |

### 8.4 Weight and fee

```
bp_clawback = 0                                                  if M ≤ 2
            = (320·M − bp_size) · 4 / 5                          otherwise
weight      = tx_size + bp_clawback
min_fee(w)  = w · FEE_PER_WEIGHT                                  (constant: economics spec)
```

- 320 bytes is half the size of a 2-output proof.
- The clawback charges aggregated proofs for their verification cost, which is linear in
  `M`, rather than for their logarithmic size. This is Monero's formula.
- Fees are plain `u64`. Sums of fees use `u128`.

### 8.5 Mempool policy (not consensus)

- A transaction that conflicts with the mempool on any key image is rejected (first seen
  wins; no replace-by-fee in v1).
- Transactions must pass T1–T11 and C1–C4 against `best height + 1`.
- On reorg, disconnected transactions return to the mempool if still valid.

---

## 9. Cryptographic assumptions

Security relies on the following. Nothing else is assumed.

1. **Discrete logarithm (DL)** in Ristretto255: about 126-bit classical security.
2. **Decisional Diffie–Hellman (DDH)** in Ristretto255: needed for privacy properties.
3. **Random-oracle model** for `Hs`, `Hp` and `H32`/`H64` (Blake2b). This is the model in
   which CLSAG and BP+ are proven.
4. **Independent generators:** no one knows a discrete-log relation between `G`, `H`,
   `Gbp[i]` and `Hbp[i]`. This holds because they are hash-to-group outputs (§1.3).
5. **The wallet's CSPRNG** for anchors, masks and nonces, *hedged* (§10): a failing RNG
   degrades to deterministic derivation from secrets, not to key leakage.

**Not assumed: resistance to quantum computers.** See §11.6.

---

## 10. Randomness and secret handling (implementation requirements)

- **Hedged randomness.** Every secret random value (anchor, pseudo-output masks, CLSAG `α`
  and `s[i]`, BP+ blinding values) comes from a hedged stream:

  ```
  seed    = H64("nonce", LE64(#secrets) ‖ (LE64(len) ‖ secret)… ‖
                         LE64(#context) ‖ (LE64(len) ‖ context)… ‖ 32 CSPRNG bytes)
  value_i = H64("nonce/stream", seed ‖ LE64(i))      (reduced mod ℓ for scalars)
  ```

  The secrets are the spend key (transfers, anchors), `p` and `z` (CLSAG), or the amounts
  and masks (BP+). The context contains the input context or signed message, the ring and
  commitments, and a purpose label.
  - If the OS RNG is good, values are uniformly random.
  - If it is broken, values are still unpredictable to anyone without the secret key, and
    never repeat for different messages.
  - Nonce reuse, which leaks the spend key in Schnorr-type signatures, is therefore
    excluded.
- **No other randomness sources:** no `rand::thread_rng` seeded from time, no fixed seeds
  outside tests, no `SmallRng` in any code path. The crypto crates take the RNG as an
  explicit `CryptoRng + RngCore` parameter. Tests use a seeded ChaCha20 RNG.
- Secret scalars and keys are zeroized on drop (`zeroize`). Secret-dependent operations
  use constant-time dalek arithmetic. Variable-time multi-scalar multiplication is used
  **only on public data** (verification).
- The consensus crates contain no `unsafe` (`#![forbid(unsafe_code)]`), no FFI and no C.

---

## 11. Privacy model

### 11.1 What is hidden

| Property | Mechanism | Holds against |
|---|---|---|
| Which output is spent | CLSAG, 1 of 16 ring members | any observer (DDH) |
| Recipient | one-time keys, per-output `R` | anyone without the recipient's view key (DDH) |
| Links between a recipient's outputs | fresh `O`, `R` per output | same |
| Links between subaddresses | `C = k_v·D` | anyone without `k_v` (DDH) |
| Amounts | Pedersen commitments, encrypted amounts | commitments: everyone, unconditionally; encrypted amounts: anyone without `S` |
| Change output position | consensus-sorted outputs | everyone |

### 11.2 What is public

- The number of inputs and outputs, the fee, the transaction size, and when the
  transaction appears.
- The 16 ring members of each input, and therefore statistics about output ages.
- Key images. A spend is recognizable as "this output was spent" **only** by its owner,
  who can compute `I`; everyone else sees an unlinkable tag.
- Coinbase amounts and the miner's one-time keys. The miner's address is not public.
- The network origin of a transaction, unless the P2P layer hides it (Dandelion++, and
  Tor/I2P; P2P spec).

### 11.3 Known deanonymization techniques and mitigations

| Technique | Status in BlackSilk v1 |
|---|---|
| Zero-mixin chain reaction | Impossible: ring size fixed at 16. |
| Reused rings / overlapping ring analysis | Reduced by the fixed ring size and wallet decoy selection (below). Not eliminated. |
| Decoy selection bias, e.g. "newest member is real" | Wallets **must** use Monero's gamma-distribution decoy selection, over output age measured in blocks × `T`. The 10-block spendable age removes the most identifiable newest outputs. Not enforceable by consensus. |
| Eve–Alice–Eve (an adversary sends to and later receives from the victim) | Inherent to ring signatures: the adversary knows the ring member it created. Mitigated only by larger anonymity sets (§11.7). |
| Wallet fingerprinting via `extra`, `unlock_time`, payment IDs, output order, extra tx keys | Removed by format (§4.1, §5.2, §2.2). |
| Fee fingerprinting | Wallets must pay the *standard fee* `min_fee(max_weight(n_in, n_out))` (`tx::builder::standard_fee`), so equal shapes pay equal fees. Not consensus. |
| Input/output count fingerprinting | Wallets should default to 2 outputs; consolidation transactions remain visible. |
| Timing and IP correlation | P2P layer (Dandelion++, Tor/I2P). Out of scope here. |

### 11.4 Janus attack (subaddress linking) [Δ Monero]

Defeated by the Janus anchor. It has a dedicated section: §12.

### 11.5 View keys and auditability

- The view key `k_v` reveals **incoming** outputs and their amounts. It does not reveal
  spends, because spends need key images, which need `k_s`.
- A view-only wallet cannot compute its balance without key images exported from the
  spend wallet (as in Monero).

### 11.6 Quantum adversaries: not protected

BlackSilk v1 transactions are **not post-quantum secure**, and this must not be advertised
otherwise. An adversary with a large quantum computer can compute discrete logarithms. It
could then:
- forge spends and inflate supply, while commitment binding is broken;
- **retroactively deanonymize**: from `O = p·G` it recovers `p` and checks `I = p·Hp(O)`,
  linking every key image to its real output ("harvest now, deanonymize later");
- recover `r` from `R` for outputs to *known* addresses, and so decrypt their amounts.

What survives: Pedersen commitments are perfectly hiding, so **amounts of outputs to
unknown addresses stay hidden** even then.

The earlier "post-quantum ring signature" code does not provide these properties and is
being removed (audit finding S5). Post-quantum privacy is a separate research track: a
lattice-based linkable ring signature or membership proof that survives external review
before anything ships.

### 11.7 Long-term direction

Ring signatures give **statistical** anonymity (1 of 16) that degrades under heuristic
analysis. The state of the art is full-chain membership proofs (Monero's FCMP++ research,
based on curve trees): every spend's anonymity set is the whole chain, and decoy selection
disappears. The v1 format carries a `version` field, and output data (`O`, `Cm`, key
images) is independent of the proof system, so a future proof system can be introduced at
a height-activated upgrade without migrating outputs.

---

## 12. Janus anchor [Δ Monero]

The Janus anchor is a core v1 privacy mechanism, not an optional module. Every output
(transfer, change and coinbase) carries one, and every conforming wallet verifies it.
Implementation: `crypto/src/janus.rs` (construction and attack tests) and
`crypto/src/stealth.rs` (integration into output creation and scanning).

### 12.1 Threat model

**Adversary.** The adversary:
- knows any number of the victim's public addresses (subaddresses);
- can put arbitrary outputs on chain, with any field values that consensus accepts,
  including outputs it builds against the protocol;
- observes the victim's externally visible reaction to received payments, such as
  shipping goods, acknowledging a payment, refunding or spending.

It knows neither `k_v` nor `k_s`, and cannot solve CDH/DL in Ristretto255.

**Goal.** Decide whether two addresses `A` and `B` belong to the same wallet (*linkage*),
with an advantage beyond what it gets from paying `A` and `B` honestly. An honest payment
to `A` tells it only whether the owner of `A` reacts.

**Out of scope:**
- linkage through network metadata, timing, amounts or off-chain behaviour;
- adversaries holding the view key;
- a victim who tells the adversary which subaddresses are theirs.

### 12.2 The attack against plain CryptoNote scanning

Plain CryptoNote scanning is §3.3 steps 1–4 and 6, without step 5. Knowing `(D_a, C_a)`
and `(D_b, C_b)`, the adversary picks `r` and publishes:

```
R = r·D_a,   S = r·C_a,   O = Hs("output-key", S)·G + D_b
```

The victim computes `k_v·R`. That equals `r·C_a = S` only if `a` and `b` share `k_v`. The
victim then recovers `D_b` from `O` and reports "payment received at `b`". Seeing the
payment accepted at `b` proves that `a` and `b` share a wallet.

Test `janus::tests::classic_janus_is_detected` reproduces the attack against steps 1–4:
the legacy recognizer accepts the probe as `b`.

### 12.3 Construction (normative)

Sender, for recipient `(D, C)`, transaction context `ctx` (§3.1) and a fresh anchor:

```
anchor     ∈ {0,1}^128                            hedged CSPRNG (§10), fresh per output
r          = Hs("ephemeral", anchor ‖ ctx ‖ D ‖ C)
R          = r·D                                   (r = 0 → choose a new anchor)
S          = r·C
enc_anchor = anchor ⊕ H64("anchor", S)[0..16]
```

Recipient, after §3.3 steps 1–4 have recognized subaddress `(D', C')` from `S = k_v·R`:

```
anchor' = enc_anchor ⊕ H64("anchor", S)[0..16]
r'      = Hs("ephemeral", anchor' ‖ ctx ‖ D' ‖ C')
accept only if r'·D' = R          (constant-time comparison of encodings)
```

Only `k_v` and the public subaddress table `(D', C')` are needed, so **view-only wallets
verify anchors exactly like full wallets**. The cost is 16 bytes per output, and one extra
scalar multiplication per output that passes steps 1–4 (only the wallet's own outputs,
plus probes).

### 12.4 Security analysis

**Lemma 1 (simulatability; unconditional).** Suppose the scan of output `o` in context
`ctx` accepts it as subaddress `j = (D_j, C_j)`. Then `o` is byte-for-byte equal to the
honest construction `Construct(D_j, C_j, a, ctx, anchor')` for the decrypted amount `a`
and anchor `anchor'`.

*Proof.* Acceptance requires `R = r'·D_j` with
`r' = Hs("ephemeral", anchor' ‖ ctx ‖ D_j ‖ C_j)`. Then `S = k_v·R = r'·k_v·D_j = r'·C_j`,
which is the shared secret `Construct` computes. Every other field is a deterministic
function of `S` and `D_j`, and each was checked against it:
- step 2 checks the view tag;
- step 4 checks `O = Hs("output-key", S)·G + D_j`;
- step 6 checks `Cm` against the decrypted amount and `Hs("mask", S)`;
- `enc_amount` and `enc_anchor` decrypt, under the same `S`, to the values `Construct`
  encrypts.

So every field matches. ∎

This lemma uses no computational assumption; it follows from the algorithm alone. Test
`janus::tests::accepted_outputs_are_honest_constructions` checks it on random honest and
adversarial outputs.

**Theorem 1 (Janus resistance).** For any output `o`, a conforming wallet (§12.5) accepts
`o` as some subaddress `j` iff two conditions hold:
- `o` is an honest construction for `j`'s public address;
- `j` belongs to the wallet.

The first condition depends only on public data, so the adversary knows it for every
address it considers. What the wallet's reaction reveals is therefore exactly "does the
wallet own `j*`", where `j*` is the address the adversary built `o` for. An honest payment
to `j*` reveals the same thing. A probe gives no advantage over honest payments, so in
particular it cannot link `A` to `B`.

*Proof.*
- (⇒) Lemma 1 gives the first condition, and the table lookup (step 4) gives the second.
- (⇐) Honest constructions for owned addresses pass every step (correctness, tested in
  `stealth::tests::round_trip_primary_and_subaddresses`).
- At most one `j` can match, because `S = k_v·R` and hence the candidate
  `D' = O − Hs(S)·G` are unique.
- Rejected outputs cause no observable reaction (§12.5), so outputs that are not honest
  constructions for an owned address are indistinguishable, from outside, from outputs to
  strangers. ∎

**Assumptions used.**
- Lemma 1 and Theorem 1: none beyond the wallet following §12.5.
- The privacy claims in §12.7: CDH in Ristretto255, and Blake2b modeled as a random oracle.

### 12.5 Wallet requirements (normative)

A wallet must treat an output rejected by the anchor check (or by the amount check of step
6) **exactly like an output that is not its own**:
- never show it as received;
- never spend it;
- never trigger any automated or user-visible action from it that another party could
  observe.

It may record the event in a local, private diagnostic log. `blacksilk_tx::scan` reports
such outputs separately in `ScanReport::rejected` for exactly that purpose, and never in
`owned`.

A wallet that reacts to rejected outputs gives the adversary back the linkage bit, and
voids Theorem 1.

### 12.6 Attack scenarios and tests

| # | Scenario | Expected | Test |
|---|---|---|---|
| A1 | Classic Janus: `r` honest for `a`, `O` for `b` | rejected; legacy scan accepts it | `janus::tests::classic_janus_is_detected` |
| A2 | Anchor honest for `b`, `R` built from `a` | rejected | `…::anchor_for_target_with_ephemeral_from_other_address_is_detected` |
| A3 | Arbitrary `r` and anchor bytes | rejected | `…::arbitrary_ephemeral_is_detected` |
| A4 | Every ordered pair of primary / subaddress / cross-account addresses | rejected | `…::all_address_pairs_are_protected` |
| A5 | Same probe in the "same wallet" and "different wallets" worlds | identical observable outcome (nothing received) | `…::outcome_is_independent_of_address_linkage` |
| A6 | View-only wallet | same detection, honest outputs accepted | `…::view_only_wallet_detects_janus` |
| A7 | Any single bit of `enc_anchor` flipped | rejected (all 128 bits) | `…::tampered_anchor_is_rejected` |
| A8 | Anchor replayed in another context or to another address | fails | `…::recipient_recovers_ephemeral_secret`, `stealth::tests::wrong_context_is_rejected` |
| A9 | Coinbase outputs | anchors present and checked | `…::coinbase_outputs_carry_anchors_too` |
| A10 | Probe inside a fully valid, signed on-chain transaction | consensus accepts; victim receives nothing | `tx/tests/adversarial.rs::janus_probe_on_chain_is_refused_by_the_victim` |

### 12.7 Privacy analysis (metadata leakage)

- **To observers**, `enc_anchor` is `anchor ⊕ PRF(S)`.
  - Without `S` (CDH), it is uniformly random in the random-oracle model, even if the
    anchor itself is constant (broken RNG). Test `enc_anchor_is_uniform_to_observers`
    checks the bit balance over 2048 outputs.
  - Every output carries the field with the same 16-byte length, whether it is a payment,
    change, a self-send, a coinbase, or goes to a primary or sub address. It therefore
    creates no distinguisher (tx-level test
    `output_encoding_does_not_depend_on_recipient_type`).
- **`R = r·D` with pseudorandom `r`** is a uniformly distributed group element whatever
  `D` is. Testing whether an output pays a *known* address requires `r` (or CDH), so a
  guessed anchor costs `2^128` per output.
  - Because `ctx` and `D ‖ C` are hashed into `r`, a guess cannot be reused across
    transactions or recipients (no multi-target speed-up across the chain).
  - Within one transaction the speed-up is at most ×16 (one anchor tried against all 16
    `R`s).
  - This matches the ~`2^126` generic security of the group.
- **The recipient** learns `anchor` and `r` of its own outputs. It already knows `S`, so
  it learns nothing new about the output.
  - Anchors come from the hedged stream (§10), so they are independent across outputs, and
    knowing one reveals nothing about the sender's other outputs.
  - Recovering the sender's spend key from an anchor requires inverting Blake2b.
- **Timing:** the extra check runs locally, and only for outputs that passed the view tag
  and the table lookup. There is no network-observable timing.

### 12.8 Limitations

- Protection depends on wallets implementing §12.3 and §12.5. Consensus cannot check
  anchors, because they are encrypted to the recipient.
- It does not stop linkage through other channels: amounts, timing, IP addresses, or
  asking the victim.
- The construction and the analysis above are BlackSilk's own. They follow the idea of
  the Jamtis "Janus anchor" proposed for Monero, but have **not been peer-reviewed**. They
  are listed for external review (§15).

---

## 13. Security guarantees (under §9)

| Guarantee | Argument |
|---|---|
| **No inflation** | Every output amount is in `[0, 2^64)` (BP+ soundness under DL). Every pseudo-output commits to its real input's amount (CLSAG proves `Cm_π − C'` is a pure `G`-multiple; binding under DL). The balance equation holds over integers (no wrap-around, §6). Coinbase amounts are checked exactly (B3). |
| **No double spend** | CLSAG linkability: two valid signatures by the same key yield the same `I`. `I` is unique per output, since the group has prime order and there are no torsion variants. Consensus rejects repeated `I` (C2). |
| **Unforgeability** | Spending requires `p` for some ring member (CLSAG unforgeability under DL in the ROM). |
| **Non-frameability** | No one can produce a key image that blocks someone else's output (CLSAG non-frameability). |
| **Non-malleability of content** | `sig_message` covers every non-signature byte, and `network_id`. Signature bytes are covered by `tx_hash`, and the block commits to `tx_hash`. Re-randomizing a signature cannot change what the transaction does. |
| **Signer anonymity** | CLSAG anonymity under DDH: among 16 members. See §11.3 for statistical limits. |
| **Recipient privacy** | Outputs and subaddresses are unlinkable without `k_v` (DDH). |
| **Encoding safety** | Canonical points and scalars only, minimal varints, a single valid encoding. |

**Resistance to specific attacks:**

| Attack | Defense |
|---|---|
| Key-image torsion double spend (Monero 2017) | Prime-order group: `I` has exactly one representation (§1.1). |
| Burning bug (Monero 2018) | Input-context binding (§3.1) plus the global `O` uniqueness rule (C4). |
| Ring member duplication or out-of-range reference | Strictly increasing indices (T5), existence and age checks (C1). |
| Referencing unconfirmed or very recent outputs | Spendable age of 10, coinbase maturity 60 (§5.3). |
| Weak Fiat–Shamir in range proofs | The transcript absorbs the statement and all prover messages (§7). |
| Cross-network replay | `network_id` in `sig_message`. |
| Verification DoS | Bounded sizes (T1, T3, ring = 16). Cheap checks run first. A transaction's verification cost is bounded by about 64 CLSAGs and one BP+ with `N ≤ 1024`. Peers relaying invalid transactions are penalized (P2P spec). |
| Arithmetic overflow in fees, indices, amounts | Checked arithmetic in decoding and summation (T5, T8, B3). |
| Tx-hash collision between coinbases | `height` is in the coinbase prefix. |

**Size (estimated):**
Each part in bytes:

| Part | Bytes |
|---|---|
| Prefix: one input | about 72 |
| Prefix: one output | 121 |
| Pseudo-output | 32 per input |
| BP+ with 2 outputs | 640 |
| CLSAG | 576 per input |

- 1 input, 2 outputs: about 1.6 KB. Monero: about 1.5 KB; the difference is the per-output
  `R` and anchor, minus Monero's shared tx key.
- 2 inputs, 2 outputs: about 2.3 KB.

---

## 14. Deliberate differences from Monero (for review)

| # | Change | Reason | Cost |
|---|---|---|---|
| Δ1 | Ristretto255 instead of Ed25519 | Prime order; no torsion/cofactor bug class | Not Monero-compatible; no reuse of Monero test vectors |
| Δ2 | Primary address uses the same form `(D, k_v·D)` as subaddresses | One output format; no "additional tx keys" fingerprint | Not Monero-compatible |
| Δ3 | Per-output ephemeral key `R` | Uniform transactions | +32 B per output; 2× scan cost for 2-output transactions |
| Δ4 | Encrypted 16-byte Janus anchor | Defeats Janus with the view key alone | +16 B per output; novel, needs review |
| Δ5 | Input-context binding; global `O` uniqueness | Burning bug impossible | One index lookup per output |
| Δ6 | No `extra`, `unlock_time` or payment IDs; sorted outputs | Removes the main fingerprinting vectors | Fewer app features (no arbitrary data on chain) |
| Δ7 | Exact coinbase amount (not ≤) | Exact supply accounting | none |
| Δ8 | Limits: ≤ 64 inputs, 2–16 outputs, 100 kB transactions | Bounded verification cost | Large sweeps need several transactions |

---

## 15. Known limitations and open items

- **No external audit yet.** CLSAG and BP+ are implemented from the papers and from
  Monero's audited design, in pure Rust. Because of Δ1 no official test vectors exist. The
  test plan (§16) compensates with adversarial and property testing, but it does not
  replace an external cryptographic review before mainnet.
- **The Janus anchor (Δ4)** is our construction. Its analysis (§12.4) needs external
  review.
- **Decoy selection** (wallet policy, `tx/src/decoy.rs`) uses Monero's gamma parameters,
  which were fitted to Monero's spend-age data. BlackSilk has no spend data of its own yet.
- **Economics constants are provisional in code:** `PROVISIONAL_FEE_PER_WEIGHT = 20` and
  `PROVISIONAL_MAX_BLOCK_WEIGHT = 600 000` in `tx/src/params.rs`.
- **Ring-signature anonymity is statistical** (§11.3, §11.7).
- **Not post-quantum** (§11.6).
- **Economics constants are not fixed yet:** `block_reward`, `FEE_PER_WEIGHT`, and the
  block weight limit (with a dynamic limit later).
- **Genesis coinbase:** the genesis block needs a coinbase in this format, which finalizes
  the provisional genesis headers of consensus.md §1.

## 16. Test plan (acceptance criteria for the implementation)

1. **Primitives**
   - Encode/decode round-trips.
   - Rejection of every non-canonical point, scalar and varint.
   - Domain-separation distinctness across all tags.
   - Fixed known-answer vectors for `Hs`, `Hp` and the generators, so any accidental
     change fails.
2. **Stealth outputs**
   - Sender/receiver round trip for the primary address and for subaddresses.
   - View-tag rejection.
   - Janus probe rejected.
   - Bogus amount rejected.
   - Outputs to other wallets not detected.
3. **CLSAG**
   - Sign/verify at every secret index.
   - Rejection when changing any of: the message, any ring member, `C'`, `I`, `D`, `c0`,
     any `s[i]`.
   - Two signatures by the same key produce equal key images.
   - Different keys produce different key images.
   - A signature with a wrong commitment secret fails.
4. **BP+**
   - Prove/verify for `k = 1..16`, including the amounts 0 and `2^64 − 1`.
   - The honest prover refuses out-of-range values.
   - Every single-element mutation of a proof is rejected.
   - Wrong proof lengths are rejected.
   - Batch verification detects one bad proof among many.
5. **Transactions**
   - Build → serialize → deserialize → validate.
   - One negative test per rule T1–T11, C1–C4 and B1–B7. Each constructs a violating
     transaction and asserts the specific error.
   - Inflation attempt: outputs exceeding inputs with a forged range proof, rejected.
   - Double spend within a transaction, a block and the chain, all rejected.
   - Signature-coverage test: flipping any single prefix, base or BP+ byte invalidates
     the transaction.
6. **Property tests** over random wallets, amounts and ring positions. These are seeded
   randomized loops, not `proptest`: its default features need `getrandom`, which does
   not build on the current audit toolchain (AUDIT.md Phase 1).
7. **Integration** with `blacksilk-consensus`: blocks whose `tx_root` commits to real
   transactions, a reorg deeper than 10 returning transactions to the mempool, and
   coinbase maturity.
