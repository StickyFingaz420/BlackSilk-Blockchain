# BlackSilk Transaction Specification

Status: **v1, implemented** by `blacksilk-crypto` (`crypto/`) and `blacksilk-tx` (`tx/`).
Not externally reviewed; no external review is engaged or planned (owner decision
2026-09-25, reviews/review-status.md; §15). The PX transaction kinds 2 and 3 are
specified in [`px.md`](px.md) §11. This document is normative: wallets, nodes and miners
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
- emission schedule, block reward, block weight limit, fee constants: [`blocks.md`](blocks.md)
- wallet seed words, address strings, wallet file: [`blocks.md`](blocks.md) §10
- transaction relay (Dandelion++, outbound Tor through SOCKS5; I2P is not supported):
  [`p2p.md`](p2p.md)

Design basis: the Monero RingCT stack as deployed since 2022 (CLSAG, Bulletproofs+,
view tags), with a small number of deliberate changes. Each change is marked
**[Δ Monero]** and justified; §14 lists them together for review.

All integers are unsigned and little-endian unless stated otherwise.

---

## 1. Cryptographic primitives

### 1.1 Group: Ristretto255 [Δ Monero]

All public keys, key images and commitments are elements of the **Ristretto255** group
(RFC 9496), built on Curve25519. Implementation: `curve25519-dalek` 4.1.3 (pure Rust;
no `unsafe` in our code, though the crate itself uses some). A 2019 third-party audit
of the dalek libraries is reported elsewhere (reviews/reviewer-candidates.md); the
crate's README does not mention one and we have not verified it, so no audit of this
dependency is claimed (reviews/dependency-review.md §2).

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

Public spend key: `K_s = k_s·G`. Both keys derive from the wallet's 32-byte `master`
secret, which the seed words define (blocks.md §10: `master` hashes 256 bits of CSPRNG
entropy with the seed version and the network):

```
k_s = Hs("wallet/spend-key", master)      k_v = Hs("wallet/view-key", master)
```

There is no default or fixed seed (fixes audit finding K1). The seed format (27 words,
version, network, birthday, check words) is specified in blocks.md §10.

The wallet's hedge key (§10) is derived from the spend key, never from view material:
`hk_v1 = H32("wallet/hedge-key/v1", k_s)` (`WalletKeys::hedge_secret`).

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
key, only one of which is spendable) by construction, at the recipient's wallet:

**Lemma 2 (burning-bug resistance without a ledger rule).** On a valid chain, a wallet
that runs §3.3 step 5 accepts at most one output per one-time key `O`, except with
probability about `q²/2^252` for `q` hash queries (random-oracle model).
- *Sketch.* Two accepted outputs with the same `O` pay the same owned `D`, so they have
  the same `x`; equal `x` with different `S` is an `Hs` collision, so `S`, hence `R`,
  hence `r` are equal. Then `Hs("ephemeral", anchor₁ ‖ ctx₁ ‖ D ‖ C) =
  Hs("ephemeral", anchor₂ ‖ ctx₂ ‖ D ‖ C)`: an `Hs` collision if `ctx₁ ≠ ctx₂`. If
  `ctx₁ = ctx₂`, both outputs are in one transaction (ctx is unique per transaction on
  a chain), which the within-transaction rules exclude (T6, B7, `PxDuplicateOutputKey`).
- *It rests on:* the within-transaction distinctness of one-time keys, which must never
  be dropped; ctx uniqueness (C2, PX2, one coinbase per height); and the wallet running
  step 5. It is an internal argument over BlackSilk's own Janus construction, the same
  shape as Carrot's burning-bug argument; it has not been externally reviewed.

There is **no chain-wide uniqueness rule on `O`** (the former rule C4 was removed for the
v3 genesis, §8.2). A wallet also credits at most one output per key image (§12.5).

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
  payment IDs** [Δ Monero]. No field exists for wallet-chosen data. In Monero, `extra`
  and `unlock_time` are the largest sources of wallet fingerprinting and can carry
  arbitrary data. **Not everything is fixed, though:** the encrypted per-output fields
  (`view_tag`, `enc_amount`, `enc_anchor`, about 25 bytes per output) and the PX record
  ciphertexts (1,241 bytes each, whose leading `R` is not checked to be a valid point)
  are checked for length only. Consensus cannot check that they look random, so a
  non-reference wallet could fill them with structure that fingerprints it, or use
  them as a covert channel. The conformance rule for any wallet: these fields must be
  the outputs of the specified encryption with fresh randomness (§3, px.md §6).

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
                    domain ‖ prefix_hash ‖ base_hash ‖ bp_hash)
domain        = LE32(network_id) ‖ LE32(branch_id) ‖ genesis_id           (40 bytes)
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
- `branch_id` is the branch id of the epoch at the height of the block that includes
  the transaction (consensus.md §11). A signature is valid in one epoch only, so no
  transaction replays across a scheduled upgrade. Wallets sign for the epoch of the
  next block height. The reference wallet records the branch id of each stored
  transaction and never rebroadcasts one into another epoch: it releases its inputs and
  asks the user to send the payment again (reviews/v3-upgrade-mechanism.md §10).
- `genesis_id` is the chain's genesis block id (consensus.md §1, `ChainParams::genesis_id`).
  A signature is valid on one chain only: not on a rehearsal, release-candidate or
  retired chain that shares the network id and branch id (red-team RT-14,
  reviews/v3-consensus-changes.md §3). Without it, replay between such chains was
  blocked only by chain state (ring indices and PX anchors that almost surely differ).
  The reference wallet refuses to load a wallet file recorded for another genesis than
  its build's, and to build with rules of another genesis, so it never signs (and never
  exposes a key image or ring) for a chain the file does not belong to (red team
  RTW1-5). It creates and restores wallets only for a network whose genesis is final
  (`ChainParams::genesis_is_final`; regtest always is), as the node runs only those.
  These are misconfiguration guards: the wallet trusts its node for the chain itself
  (RT-15).

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
2019/654. Monero has used CLSAG since 2020 (v13). It was audited before deployment <!-- doc-lint: allow (Monero's third-party CLSAG audit, not a BlackSilk claim) -->
(Aumasson & Vennard, 2020). BlackSilk follows Monero's construction, except that
Ristretto removes the cofactor handling.

**Inputs to sign:**
- ring `P[0..16)` and `Cr[0..16)`: the `(O, Cm)` of the members
- pseudo-output `C'`
- message `m = sig_message`
- secret index `π`, with `p·G = P[π]` and `z·G = Cr[π] − C'`, and `z ≠ 0` (a signer
  refuses `z = 0`: it gives `D = identity`, which verification rejects, and `C' = Cr[π]`,
  which reveals the real input)

```
Hπ  = Hp("key-image", P[π])
I   = p·Hπ                      key image (stored in the input, not in the signature)
D   = z·Hπ                      auxiliary commitment image (stored in the signature)

ring_bytes = P[0] ‖ … ‖ P[15] ‖ Cr[0] ‖ … ‖ Cr[15]
μP  = Hs("clsag/agg-P", ring_bytes ‖ I ‖ D ‖ C')
μC  = Hs("clsag/agg-C", ring_bytes ‖ I ‖ D ‖ C')
W   = μP·I + μC·D               aggregated key image

α ← hedged nonce (§10; stream bound to the whole transcript, see "CLSAG nonces" there)
c[π+1] = Hs("clsag/round", ring_bytes ‖ C' ‖ m ‖ α·G ‖ α·Hπ)
for i = π+1, …, π−1 (mod 16):
    s[i] ← hedged random scalar
    L    = s[i]·G  + c[i]·(μP·P[i] + μC·(Cr[i] − C'))
    R    = s[i]·Hp("key-image", P[i]) + c[i]·W
    c[i+1] = Hs("clsag/round", ring_bytes ‖ C' ‖ m ‖ L ‖ R)
s[π] = α − c[π]·(μP·p + μC·z)
signature = (c0 = c[0], s[0..16), D)
```

**Verification:** decode every point and scalar (§1.1) and reject `I = identity` and `D = identity`.
Recompute `μP`, `μC` and `W`, then run the loop for `i = 0..15` starting from `c[0] = c0`.
The signature is valid iff the final `c[16]` equals `c0`.

---

## 7. Range proofs: Bulletproofs+

Chung, Han, Ju, Kim, Seo, *"Bulletproofs+: Shorter Proofs for a Privacy-Enhanced
Distributed Ledger"*, IACR ePrint 2020/735, aggregated range proof (§4 and Fig. 3,
weighted inner-product argument of Fig. 1). Monero has used BP+ since 2022 (v15);
Monero's design was reviewed by Cypher Stack (Feickert, 2022), as reported by the
Monero project and not verified by us. That review does not cover this
implementation, which no one outside the project has reviewed.

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
| T1 | Strict decode (§4); `size ≤ MAX_TX_SIZE = 100 000` bytes for coinbase and transfer; no trailing bytes. |
| T2 | `version = 1`; `kind ∈ {0, 1, 2, 3}`; a coinbase is only valid as the first tx of a block (B1). Kinds 2 (PX transaction) and 3 (private-contract deploy) are specified in [`px.md`](px.md) §11, with their own size caps (`MAX_PX_TX_SIZE` = 4 MiB proof cap + 256 KiB; `MAX_DEPLOY_TX_SIZE` = 1 MiB) and rules (PX1–PX6, PX6 being the validity window of testnet v3); they reuse T4–T11 and C1–C3 for their v1 inputs and outputs. The ephemeral key `R` of each PX record ciphertext must decode canonically and not be the identity, as in T6 (px.md §6; `PxCiphertextRNonCanonical`, `PxCiphertextRIdentity`; testnet v3, reviews/v3-consensus-changes.md#px-ciphertext-r). |
| T3 | Transfer: `1 ≤ n ≤ 64` inputs, `2 ≤ k ≤ 16` outputs. |
| T4 | Key images decode, are not the identity, and are strictly increasing (§5.2). |
| T5 | Each input has exactly 16 ring indices, strictly increasing, with no `u64` overflow. |
| T6 | Every `O` and `R` decodes and is not the identity. Every `Cm` decodes. `O`s are strictly increasing, so the one-time keys of a transaction are distinct (the only one-time-key uniqueness rule: keys may repeat across transactions, §8.2). |
| T7 | Exactly `n` pseudo-outputs; each decodes. |
| T8 | `fee = standard_fee(n, k) = min_fee(max_weight(n, k))` **exactly**, for `n` inputs and `k` outputs (§8.4; `FeeNotExact`). Since `max_weight(n, k) ≥ weight`, this implies `fee ≥ min_fee(weight)`. Fee arithmetic is checked and never overflows. Testnet v3 rule set (reviews/v3-consensus-changes.md#exact-v1-fee). |
| T9 | Balance: `Σ C'_k − Σ Cm_j − fee·H = identity`. |
| T10 | BP+: length matches `k`, all elements decode, all scalars canonical, proof verifies (§7). |
| T11 | Exactly `n` CLSAGs; all scalars canonical, all `D` decode and are not the identity (a signature with `z = 0`, so `C' = Cr[π]`, which would reveal the real input; Monero's "bad auxiliary key image" rule). |

### 8.2 Contextual (against the chain state at the block's parent)

| # | Rule |
|---|---|
| C1 | Every ring index refers to an existing output that satisfies the age rules (§5.3). |
| C2 | No key image is already spent on chain, or earlier in the same block. |
| C3 | Each CLSAG verifies (§6.1) over the resolved ring, its `C'_k`, its `I`, and `sig_message`. |
| C4 | *Removed for the v3 genesis* (reviews/v3-consensus-changes.md §1). There is no rule relating an output's `O` to the chain or to other transactions of the block: one-time keys may repeat across transactions. |

**Why there is no C4.** `O` is public as soon as its transaction is relayed, and a sender
chooses its outputs' keys freely. The former C4 ("no output's `O` already exists on chain
or earlier in the same block") therefore let anyone who saw a pending transaction (a
Dandelion stem relay, a miner, any well-connected node) invalidate it for good, for one
fee, by getting a transaction carrying a copy of one of its keys mined first; a first-seen
rule on output keys in the mempool kept the same veto as policy. What C4 was meant to
prevent, the burning bug, is prevented at the recipient without it (§3.1, Lemma 2):
- one-time keys are distinct **within** every transaction (T6 for transfers and deploys,
  B7 for coinbases, the list sorts and `PxDuplicateOutputKey` for PX, px.md §11.3);
- the Janus check refuses a copy placed in another transaction (another `ctx`);
- a wallet credits at most one output per key image (§12.5).

A copy of `O` cannot be spent by its creator (spending needs `p`), cannot block the
owner's output (C2 applies to the key image `I = p·Hp(O)`, one per `O` however many
copies exist), and is a decoy known to its creator like any output it owns. This is
Monero's ledger model (no output-key rule at all) plus Carrot's within-transaction rule
(Carrot §4.3).

### 8.3 Block-level

| # | Rule |
|---|---|
| B1 | The first transaction is a coinbase; no other transaction is. |
| B2 | Coinbase `height` equals the block height. |
| B3 | `Σ coinbase amounts = block_reward(height) + Σ fees`, exactly (u128 arithmetic). Under-claiming is invalid, so the supply is exactly computable [Δ Monero, which allows ≤]. |
| B4 | Key images are unique within the block (C2 applied in order), and so are PX nullifiers (PX2) and contract ids. One-time keys may repeat across the block's transactions (§8.2). |
| B5 | `tx_root` equals the Merkle root of the `tx_hash`es in block order (consensus.md §7). |
| B6 | Block weight ≤ block weight limit (economics spec). A PX or deploy transaction with `n > 0` v1 inputs and `k` hidden outputs weighs `max_weight(n, k)` (§8.4), the weight bound of its v1 part, so its CLSAGs are paid in the same meter as a transfer's; without v1 inputs it weighs 0 (testnet v3, reviews/v3-consensus-changes.md#r12-2). PX and deploy transactions also count, in full, against a separate budget: their encoded bytes sum to at most `MAX_PX_BLOCK_BYTES = 8 MiB` (px.md §11.5), and the deploys' bytes to at most `MAX_DEPLOY_BLOCK_BYTES = 1 MiB` of it (testnet v3). A valid block therefore holds at most ⌊600 000 / 656⌋ = 914 v1 inputs of all kinds. |
| B7 | Coinbase structure: 1–16 outputs, no identity `O` or `R`, outputs strictly sorted (so its one-time keys are distinct; they may repeat keys of other transactions or the chain, §8.2). |
| B8 | PX tree capacity: the block's PX output commitments, one leaf each, fit in the PX commitment tree (`size + leaves ≤ 2^32`, px.md §5; `BlockError::PxTreeFull`). Testnet v3 (reviews/v3-consensus-changes.md#tree-capacity). Validation is a superset of every condition under which applying a block fails, so a valid block always applies. |
| B-OMR | The header commits to the v1 output set: `output_count` = the parent's `output_count` + the block's outputs (coinbase included), and `output_root` = the root of the parent's output range with the block's outputs appended in block order, each with its height and coinbase flag (consensus.md §7.1; `BlockError::OutputCountMismatch`, `OutputRootMismatch`). Testnet v3 (reviews/v3-consensus-changes.md#output-root). |
| B-PXR | The header's `px_root` is the PX commitment tree's root after the block's PX output commitments are appended in block order (px.md §5; `BlockError::PxRootMismatch`), the root the block adds to the root window. Testnet v3 (reviews/v3-consensus-changes.md#output-root). |

**Evaluation order of block validation** (`validate_block_transactions_cached`; policy,
not consensus: every rule is a pure check, so the order decides only which error an
invalid block reports and how much work precedes it, never the verdict):

| Step | Checks | Cost |
|---|---|---|
| 1 | B1, B2, B7 (coinbase) | trivial |
| 2 | Per-transaction structure: T1, T3–T8, T10 shape, T11 (including `D ≠ identity`), PX and deploy structure | cheap |
| 3 | B5, B-OMR, B6, B8, B-PXR, B3 | hashing (one hash per output, up to 33 Poseidon2 permutations per PX commitment), sums |
| 4 | T9 balances (every kind) | one multi-scalar sum per transaction |
| 5 | PX proofs decoded strictly (PX5, first step), unless already verified by this node | a few ms per proof |
| 6 | C2, PX1–PX4, PX6 (the validity window, for every PX transaction, whether or not its proof was verified before), contract ids, in block order; then each decoded PX proof's table shape against its statement (PX5, second step) | lookups |
| 7 | C1: every ring of the block resolved | lookups |
| 8 | T10: one Bulletproofs+ batch over the block | below one CLSAG input per proof |
| 9 | C3: every CLSAG | 2–4 ms per input |
| 10 | PX5: every PX proof not already verified, on the decoded proof | about 0.2 s per proof |

A block of PX transactions whose proofs are malformed (they fail decoding in step 5 or
the table shape in step 6) is therefore rejected with no ring resolved and no CLSAG
verified, whatever its ring signatures (dossier 10 F10-2; `tx/tests/block_pipeline.rs`).
This covers malformed proofs only: a well-formed proof that does not verify (for
instance a valid proof replayed in another transaction, whose binding then differs)
passes steps 5 and 6 and costs every check up to step 10.

### 8.4 Weight and fee

```
bp_clawback = 0                                                  if M ≤ 2
            = (320·M − bp_size) · 4 / 5                          otherwise
weight      = tx_size + bp_clawback
min_fee(w)  = w · FEE_PER_WEIGHT                                  (constant: economics spec)

max_weight(n, k) = weight of a transfer with n inputs and k outputs whose every
                   varint (version, counts, the 16 ring entries per input, fee)
                   takes its 10-byte maximum, with bp_size = 0 and M = 1 when k = 0
standard_fee(n, k) = min_fee(max_weight(n, k))                    (T8: the exact fee)
```

- 320 bytes is half the size of a 2-output proof.
- **Exact fee (T8).** Every transfer pays exactly `standard_fee(n, k)`, a function of
  its public shape alone, as PX and deploy fees already are (px.md §11.3). A fee that
  depends on the wallet (a third-party wallet's own rounding, a "priority" multiple, a
  buggy fee computation) would otherwise single out that wallet and, through the change
  output, its later real inputs (Monero's non-standard-fee clusters; dossier 38 §3.7).
  There is no priority fee; congestion is handled by mempool policy (§8.5). The rule
  is `TxRules::standard_fee` (tx/src/params.rs), so a later epoch could allow fee
  tiers there. `max_weight` is pinned for every shape (`n = 1..64`, `k = 0..16`) in
  `tx/tests/data/max_weight.txt`, generated by the independent
  `tools/vectors/max_weight.py`; for example `max_weight(1, 2) = 1 723`, so a
  1-input, 2-output transfer pays 34 460 atomic units. A property test checks
  `max_weight(n, k) ≥ weight` for every valid shape (`tx/tests/max_weight_vectors.rs`).
- The clawback charges aggregated proofs for their verification cost, which is linear in
  `M`, rather than for their logarithmic size. This is Monero's formula.
- Fees are plain `u64`. Sums of fees use `u128`.

### 8.5 Mempool policy (not consensus)

- A transaction that conflicts with the mempool on any key image is rejected (first seen
  wins; no replace-by-fee in v1).
- Transactions must pass T1–T11 and C1–C3 against `best height + 1`.
- Order: every stateless rule (T1–T11, including the range proof T10, the PX
  structure rules and the strict decoding of the PX proof, PX5's first step) runs
  before any contextual rule (C1–C3, PX1–PX4), except PX6: the validity window, a
  height comparison, runs right before a PX transaction's range proof (RTW1C-5), so a
  transaction outside its window costs no Bulletproofs+ verification (it is then
  refused with `PxWindow` even if its range proof is also invalid; the verdict is
  the same). Once PX1–PX4 pass, the PX proof's table
  shape is checked against its statement (PX5's second step, which needs PX3's
  registered budgets), before any ring is resolved (C1); the proof's verification
  runs last. This is the block path's order (§8.3), applied to every
  single-transaction path: mempool admission, P2P relay, RPC submission and
  re-admission after a reorganization (`validate_px`; red team RTW1-2, before which
  these paths verified the CLSAG before looking at the proof). A transaction that
  breaks a stateless rule therefore always gets a stateless error, which is what peer
  scoring penalizes (p2p.md §10), and costs no chain lookup. A malformed proof gets
  `PxProof` whatever its signatures: one failing decoding costs no chain lookup and no
  range proof, one failing the shape no ring lookup and no CLSAG. A well-formed proof
  that does not verify still costs every check up to the verification. A PX transaction repeating a one-time key between its hidden outputs
  and payouts, or with two equal nullifiers, gets a stateless error
  (`PxDuplicateOutputKey`, `PxNullifierRepeated`), as does one whose record
  ciphertext `R` is non-canonical or the identity (`PxCiphertextRNonCanonical`,
  `PxCiphertextRIdentity`, a validity rule: px.md §6). `PxDuplicateOutputKey` is the only
  rule rejecting such a key repeat (there is no C4); two equal nullifiers would also
  fail PX2 on every chain. The order and these variants decide only which error an
  invalid transaction gets, never whether a transaction or block is valid. The
  classification of every error is documented on `TxError::is_stateless`.
- A PX transaction must be inside its validity window (PX6, px.md §11.3) at
  `best height + 1`: a premature one is refused (`PxWindow`, contextual, never
  penalized), every revalidation after a new block or a reorganization drops one
  whose window no longer contains the next height, and templates select only
  transactions whose window contains their height. Admission (not revalidation)
  also refuses one whose window ends within 3 blocks, `not_after ≠ 0 ∧ not_after <
  best height + 4` (`ExpiringSoon`, policy, RTW1C-4); a transaction a reorganization
  returns is readmitted without that check.
- On reorg, disconnected transactions return to the mempool if still valid.
- A pooled transaction expires 2 160 blocks after the height it was admitted for, and
  the node then refuses it again for 30 blocks (`Expired`); blocks.md §7.

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

- **Hedged randomness.** The secret random values listed in the table below come from a
  hedged stream:

  ```
  seed    = H64("nonce", LE64(#secrets) ‖ (LE64(len) ‖ secret)… ‖
                         LE64(#context) ‖ (LE64(len) ‖ context)… ‖ 32 CSPRNG bytes)
  value_i = H64("nonce/stream", seed ‖ LE64(i))      (reduced mod ℓ for scalars)
  ```

  The context starts with a purpose label and then lists the inputs of the statement
  being signed, proved or built. Variable-length lists are preceded by their count.
  - If the OS RNG is good, values are uniformly random.
  - If it is broken, values are still unpredictable to anyone without the secret, and
    they differ for two statements that differ in anything the context binds. For an
    identical statement they repeat (a deterministic rebuild), which is safe.
  - Nonce reuse, which leaks the spend key in Schnorr-type signatures, is therefore
    excluded wherever the context binds the full statement (all rows marked "full").

  | Values | Secrets | Context (after the label) | Bound |
  |---|---|---|---|
  | CLSAG `α`, `s[i]` | `p`, `z` | see below (`clsag/nonce/v2`) | full |
  | BP+ blinding values | every amount ‖ mask | `"bp+"`, every commitment | full (statement = f(witness)) |
  | Schnorr nonce | `k` | `"schnorr"`, tag, `K`, `m` | full |
  | Transfer anchors, pseudo-output masks | hedge key `hk_v1` (from `k_s`, §2.1) | `transfer/v2`: network id, `H(key images)`, fee, each ring (members in global-index order: `LE64(index) ‖ O ‖ C`), each payment (address ‖ `LE64(amount)`), change address ‖ `LE64(change)`, caller payload (a deploy's salt and programs) | full |
  | Coinbase anchors | miner-supplied secret | `coinbase/v2`: `ctx(height)`, each payout (address ‖ `LE64(amount)`) | full, but see R2-C4 below |
  | PX payout and change anchors, pseudo-output masks | PX hedge secret (required), plus `hk_v1` with v1 inputs | `px/v2`: network id, `ctx` (nullifiers and key images), fee, bridge-in, bridge-out, `LE64(not_before)`, `LE64(not_after)`, both output commitments, each ring, each payout, change address ‖ `LE64(change)` | full |
  | PX delivery `r` and ML-KEM coins `m` | sender's PX hedge secret (required; `seal` refuses an empty or all-zero one) | `px/delivery/hedge/v1`: recipient owner tag, `V`, the whole `ek`, `cm`, contract, `LE64(value)`, data, `rcm`, `rho` (which fixes the output index) | full |
  | PX throwaway delivery key (empty slot) | PX hedge secret | `px/throwaway/v1`: the slot's commitment, `LE64(slot)` | full |
  | PX witness randomness: `rcm` of each user output; every field of each dummy input (`sk`, `d`, `rho`, `rcm`, position, path); owner of each empty slot; unused `sk`, `d` of contract inputs | PX hedge secret (required), plus `hk_v1` with v1 inputs | one stream per value, label `px/witness/rcm/v1`, `px/witness/dummy/v1`, `px/witness/empty-owner/v1` or `px/witness/contract-key/v1`, then `LE64(slot)`; the witness statement: anchor, bridge-in, bridge-out, each input (`"dummy"`, or the spent record's contract ‖ value ‖ data ‖ `rho` ‖ `rcm` ‖ position), each output (`"empty"`, or owner ‖ contract ‖ value ‖ data), each function (contract ‖ blind ‖ approve and spec flags); then the rest of the transaction: network id, fee, the validity window, each ring, each payout, change address, each function run (program id ‖ private input). `build_px` re-derives these before running the kernel (`blacksilk_px::wallet::hedge_witness`) | full, except contract-output `rcm` and function blinds (next row) |
  | Contract-output `rcm` and function blinds of the wallet's vault flows (W28-4) | PX hedge secret `hk_px` | one stream per value, `blacksilk_px::wallet::hedged_digest`, label `px/witness/contract-rcm/v1` or `px/witness/fn-blind/v1`: for a lock, `px/vault/lock`, the contract, `LE64(amount)`, the record data (the terms), each spent input (dummy flag ‖ `rho` ‖ `rcm` ‖ position); for a claim or refund, the selector, the vault record's `rho` ‖ `rcm`, the recipient's owner tag and the window | full |
  | Vault record `rcm` of a lock with a timeout (RTW1C-3) | PX hedge secret `hk_px` | deterministic, no RNG: `H32("px/wallet/vault-rcm/v1", hk_px ‖ u8 network ‖ contract ‖ rho_vault)` as eight 30-bit limbs (`rho_vault` is unique on chain), so a restored wallet rebuilds the record (px.md §13.4) | deterministic (not RNG-dependent) |
  | Membership (bLSAG) nonce | `x` | `"membership"`, `m`, `B`, `P[π]` | **not full** (R2-C5) |

  The hedge secrets are derived hedge keys, not the spend secrets themselves (dossier 37
  K2): `WalletKeys::hedge_secret` is `hk_v1 = H32("wallet/hedge-key/v1", k_s)` and the PX
  hedge secret `blacksilk_px::wallet::Account::hedge_secret` is
  `hk_px = H32("px/wallet/hedge-key/v1", sk as eight LE32 limbs)`. Both come from spend
  material only (a view-key holder cannot predict them) and confine anything the hedge
  absorbs to a key that authorizes nothing. `build_px` refuses an all-zero one (`PxBuildError::NoHedgeSecret`);
  before 2026-09-27 it silently hedged with 32 zero bytes when there were no v1 inputs
  (R2-C3), and delivery used the raw RNG (R2-C2). The old transfer context was only
  `"transfer" ‖ H(key images)` (R2-C1): a rebuild over the same inputs with another amount,
  recipient or fee reused anchors and pseudo-output masks under a broken RNG, which leaked
  amount deltas. Test: `broken_rng_transfers_over_the_same_inputs_share_no_output_secrets`
  (tx/tests/privacy.rs); delivery tests `broken_rng_*` in px/src/delivery.rs. All of this is
  wallet-side: validators check none of these derivations, and no encoding changes.

  **Not hedged (known, accepted or open):**
  - *Coinbase secret (R2-C4, accepted limitation).* The miner draws its hedge secret once
    per process from the OS RNG, the same source as the stream's fresh bytes. If the OS
    RNG fails, both fail, and coinbase outputs become linkable to a known payout address.
  - *Membership nonce (R2-C5).* The context lacks the ring and the tag; with a constant RNG
    two signatures over different rings leak `x`. Unreachable today (contracts are not
    integrated); must be fixed before any integration.
  - *Contract-output `rcm` and function blinds of other callers.* `build_px` keeps the
    `rcm` of a contract output (the caller keeps that record's opening) and the function
    `blind` (it is also in the function's private input), so the caller derives them.
    The wallet's vault flows hedge both (row above; testnet v3, W28-4). Any other caller
    of the library must do the same (`blacksilk_px::wallet::hedged_digest`; contracts.md
    §6 item 11): under a broken RNG an observer could otherwise test guesses of a
    contract record's contents against its `cm`, or of a function's inputs and outputs
    against its `io_hash`. The user-output, dummy-input, empty-slot and
    contract-input values were hedged on 2026-09-27; before that they came from the
    caller's RNG directly (`blacksilk_px::wallet::{output, dummy_input, empty_output}`,
    which still draw placeholders that `build_px` replaces). Tests (no proving):
    `broken_rng_*`, `working_rng_values_are_fresh`, `hedged_rcm_is_uniform_over_the_field`,
    `the_kernel_accepts_a_hedged_witness` in px/src/wallet.rs, and
    `broken_rng_witness_randomness_is_bound_to_the_whole_transaction` in
    tx/src/px_builder.rs.
  - *Other RNG uses* are outside this table: decoy selection (not secret, but predictable
    under a broken RNG), key and seed generation, the wallet file's salt and nonce, and the
    STARK prover's randomness (derived with a witness digest; reviewed separately).
- **CLSAG nonces (§6.1).** `α` is the first value of the stream and the simulated
  responses `s[i]` are the following ones, in ring order from `π+1`. The stream is:

  ```
  secrets = [ p, z ]                                   (32-byte canonical scalars)
  context = [ "clsag/nonce/v2", m, C', I, D, LE64(π),
              P[0] ‖ … ‖ P[15], Cr[0] ‖ … ‖ Cr[15] ]
  ```

  So any change of the signed statement (a ring member `P[i]` or `Cr[i]`, ring order,
  `C'`, `I`, `D`, `m` or `π`) changes every nonce, even with a constant RNG. The label
  separates this stream from every other use of the hedge.

  *Change of 2026-09-27 (internal review round 5, finding F2, low severity, defence in
  depth).* The previous context was `["clsag", m, C', P[π]]`: it did not contain the
  decoys. After a reorg the same transaction (same global indices, so the same `m`) can be
  re-signed over a ring whose decoys resolve to different outputs. With a completely
  broken RNG this reused `α` while `μP`, `μC` and `c[π]` changed. Each such pair gives one
  linear equation `s₁[π] − s₂[π] = (c₂μP₂ − c₁μP₁)·p + (c₂μC₂ − c₁μC₁)·z`, so three
  signatures reveal `p` from public data (the regression test
  `pre_f2_derivation_leaks_the_spend_key_and_fix_prevents_it` performs this recovery on
  the old derivation). The change is wallet-side only: the verifier, the signature
  format, key images and all hash tags used in verification are unchanged, so every
  signature valid before is valid now and vice versa. With a good RNG the output is still
  uniform: adding public context to the hashed input cannot remove the 32 fresh CSPRNG
  bytes' entropy (the hash is modelled as a random oracle on the whole input). `π` is in
  the context but never leaves the hash. The test `nonce_and_signature_test_vector` pins
  the derivation.
- **No other randomness sources:** no `rand::thread_rng` seeded from time, no fixed seeds
  outside tests, no `SmallRng` in any code path. The crypto crates take the RNG as an
  explicit `CryptoRng + RngCore` parameter. Tests use a seeded ChaCha20 RNG.
- Secret scalars and keys are zeroized on drop or after use (`zeroize`), **best effort**:
  `Scalar` is `Copy`, so copies made by arithmetic are not tracked. The builder wipes its
  output masks, mask sums, pseudo-output masks and one-time secrets; the BP+ prover wipes
  its final-round nonces `r_`, `s_`, `δ`, `η` and the folded witness `a0`, `b0`. The
  `Debug` output of `CreatedOutput`, `ReceivedOutput` and `SpendableOutput` redacts the
  mask and output-key offset. Secret-dependent operations
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
  a node running over Tor; p2p.md). I2P is not supported. The wallet itself has no Tor
  or TLS support and talks plaintext HTTP to its node, so it should use its own node.

### 11.3 Known deanonymization techniques and mitigations

| Technique | Status in BlackSilk v1 |
|---|---|
| Zero-mixin chain reaction | Impossible: ring size fixed at 16. |
| Reused rings / overlapping ring analysis | Reduced by the fixed ring size and wallet decoy selection (below). Not eliminated. |
| Decoy selection bias, e.g. "newest member is real" | Wallets **must** use Monero's gamma-distribution decoy selection, over output age measured in blocks × `T`. The 10-block spendable age removes the most identifiable newest outputs. Not enforceable by consensus. |
| Eve–Alice–Eve (an adversary sends to and later receives from the victim) | Inherent to ring signatures: the adversary knows the ring member it created. Mitigated only by larger anonymity sets (§11.7). |
| Wallet fingerprinting via `extra`, `unlock_time`, payment IDs, output order, extra tx keys | Removed by format (§4.1, §5.2, §2.2). |
| Fee fingerprinting | Removed by consensus: every fee is a function of public data. A transfer pays exactly the *standard fee* `min_fee(max_weight(n_in, n_out))` (T8, §8.4), a PX transaction exactly `PX_STANDARD_FEE`, a deploy exactly its shape and payload fee (px.md §11.3). Equal shapes pay equal fees, and no fee carries timing or wallet information. |
| Input/output count fingerprinting | Wallets should default to 2 outputs; consolidation transactions remain visible. |
| Timing and IP correlation | P2P layer (Dandelion++; outbound Tor for the node; no I2P). Out of scope here. |

#### 11.3.1 Wallet decoy selection (`tx/src/decoy.rs`, `wallet/src/wallet/px_flows.rs`, `wallet/src/index.rs`; wallet policy)

**Age draw.** Monero's gamma picker: `x = exp(Gamma(19.28, 1/1.61))` seconds, shifted
by the 10-block spendable age (or uniform in `[0, 15·T)` below it), converted to an
output index with the chain's average output time, then to the block `b` holding that
index.

**Eligibility inside the draw (review R3-1, 2026-09-27).** The picker chooses a uniform
*eligible* output of block `b`. If `b` has none, it takes a uniform eligible output of
the neighbourhood `b ± w`, where `w = clamp(depth / 4, 9, 720)` blocks. If that has
none either, the draw is discarded and made again. Eligible means old enough and, for
coinbase outputs, 60 blocks deep; outputs already in the ring do not count.

An unbounded "nearest eligible block" rule was tried and rejected. On a chain of
coinbase-only blocks (the first days of a testnet) it moved every young draw onto the
first mature blocks. The bounded window keeps that pile-up to draws from 51–59 blocks
deep. Test `no_pile_up_at_the_maturity_boundary` measures the share of decoys 60–69
blocks deep on such a chain: 12.9 % with the window, 6.0 % with discard-and-redraw.
This is a known, bounded bias; the test's bound is 2.5 times. Before this change the draw ignored eligibility and the wallet discarded
immature coinbase picks and drew again at any age. On a young chain, where most
outputs 10–59 blocks deep are immature coinbase outputs, that removed nearly all young
decoys, so a real input spent soon after receipt was usually the newest ring member.

**Measured** (`young_decoys_survive_coinbase_maturity`, fixed seed, 2,000 rings per
variant). The synthetic chain has 2,160 blocks (3 days at 2 min), one coinbase output
per block, a two-output transfer every 18th block, and a real input spent 12 blocks
after it was mined:

| Variant | Decoys younger than 60 blocks | Real input is the newest member |
|---|---|---|
| Target: the same draws with every output eligible | 20.6 % | 62.4 % |
| Before: discard ineligible picks and redraw | 3.4 % | 89.8 % |
| After: eligibility inside the draw | 17.8 % | 51.5 % |

The test requires the young fraction to be within 0.05 of the target, and the
newest-member fraction to be at most 0.05 above it. **Limits:**
- These figures hold **only for this young (3-day) chain.** There the picker drops
  every draw older than the chain, about 60 % of the gamma mass, which inflates the
  young draws about 2.5 times. On a **mature chain** with a steady output rate, a real
  input spent 12 blocks after receipt is the newest ring member in about **84–89 %**
  of rings, so guessing the newest member identifies it that often (decisions "Agent
  38" W9; dossier 38 §2.4). **Measured** (`guess_newest_success_on_a_mature_chain` in
  `tx/tests/decoy_statistics.rs`: one year of 2-minute blocks with four outputs each,
  3,000 rings per row, fixed seed; sampling error about ±1–2 points, two standard
  errors): about 86 % at 12 blocks, 52 % at 20, 13 % at 60 and 3 % at 120. Each
  agrees with the prediction of an independent model of the picker, and the test
  pins the ranges 83–89 %, 48–57 %, 10–16 % and 2–5 %. Over a distribution of spend
  ages, guess-newest succeeds in about 6–7 % of rings (1/16 = 6.25 %) when real
  spends follow the picker's own gamma, and in about 13–15 % when they are four times
  quicker (the age past the 10-block lock a quarter of a model draw). Which of these
  describes BlackSilk users is unknown: the gamma is Monero's, inherited and not
  fitted, and there are no BlackSilk spend data. Even at the target, a young spend is
  the newest member in most rings, because the gamma distribution puts little mass
  10–12 blocks deep. The fix restores
  the distribution; it does not beat it, and only waiting before spending helps (a
  young-spend warning and an opt-in spend delay are decided, not implemented,
  docs/STATUS.md).
- Where eligible young outputs are sparse, the few that exist absorb the young draws.
  The same young transfer outputs then appear in many rings, the real input's sibling
  (the change of the same transaction) included. That is why "after" is below the
  target for newest-member.
- Coinbase-dominated rings (R3-3) are unchanged. Coinbase decoys appear in proportion
  to the coinbase share of the eligible outputs at every age, and never below 60
  blocks (`coinbase_decoys_appear_in_proportion_at_each_age`; decision D7 (a)).
- **Statistical suite** (`tx/tests/decoy_statistics.rs`, fixed seeds, tolerances
  rather than exact rings). Against an independent model of the age draw: the decoy
  depth distribution on a steady chain (chi-square); decoys exactly 10 blocks deep
  occur at the model's rate (about 0.43 % of decoys, within sampling error), and
  coinbase decoys exactly 60 deep too, never younger (the Monero #8872 class); on
  random chains the ring-member rule wallets use (`decoy::RingEligibility`) equals
  the consensus ring check C1 for every output; and the real input's rank among the
  16 is uniform when real ages follow the model. A one-block error in the lock shift
  is too small for these statistics; unit tests in `tx/src/decoy.rs` pin the lock
  shift and the neighbourhood bounds deterministically.
- **Rings rebuilt after a reorganization (X7).** Members orphaned by a reorganization
  are replaced; the wallet keeps every other member (W-5), so an observer who saw
  both transactions (they share the key image) narrows the real input to the
  intersection. Measured (`reorg_ring_intersection_after_rebuilding`, real input 1,000
  blocks deep, 2,000 rings per depth, about ±0.1 members): the intersection keeps
  about 15.9 of 16 members after a 10-block reorganization, 14.9 after 30, 13.2 after
  100 and 9.0 after 720; a ring drawn afresh would share only the real input (about
  1.0). Accepted, to be quantified in the privacy regression suite (tm2-crosscheck
  X7, docs/reviews/phase2-2026-09-27/research/tm2-crosscheck.md).
- The parameters are Monero's, not fitted to BlackSilk spend data (§15).

**Ring members are resolved locally (review I3 §3.9).** The wallet indexes every
output of every block it scans (`wallet/src/index.rs`: key, commitment, height,
coinbase flag) and builds rings from that index. It makes no `/outputs` request per
ring. The previous single request per input contained the real input among the
candidates, so the node could intersect it with the ring on chain. Outputs older than
the wallet's restore height are fetched **once**, as the whole range `0 .. start` in
consecutive pages of 1,024. Those requests depend on the restore height only, not on
what is spent.

**The output distribution comes from the wallet's own index (D1, 2026-10-04; F38-1,
F38-6).** The picker's `cumulative[h]` (outputs in blocks `0..=h`) is derived from the
heights in that index (`OutputIndex::cumulative`), and the same distribution feeds the
ring-member age rule (`decoy::RingEligibility`). No spend path requests `/distribution`
(transfer, deploy, PX deposit, the v1 fee of contract calls; all build v1 rings in
`plans_for`). Before, one request at spend time told the node a spend was being built,
and a node could serve a distribution that was monotone with the right total but skewed
decoy ages old, so the young real input stood out as the newest member. Tested:
`rings_do_not_depend_on_the_nodes_distribution` (a skewed node gets the honest node's
rings, scanned and restored wallets) and `no_spend_path_requests_the_distribution`
(`wallet/src/wallet/tests_sync.rs`, with `a_lying_first_output_cannot_restart_the_scanned_index`
and `a_spend_straight_after_a_restore_backfills_with_a_warning` for what follows); the
e2e ring tests count the requests too. The endpoint stays for tools.

**What is checked, precisely.**
- *Scanned range* (from the restore height on). Keys, commitments, coinbase flags and
  heights come from the blocks the wallet scanned: each block matches its id and its
  `tx_root` and extends the previous one; their headers are checked from the genesis
  while a restored wallet catches up, or always with `set_verify_headers`. The global
  index of each scanned block's first output must continue the index exactly (RT-D1
  F1): a node that misstates it is refused, and can no longer make the wallet discard
  its scanned range and backfill it. The exception is the *first* scanned block, the
  restore point. At the restore its `first_output` is the restoring node's word, checked
  only to be at least its height − 1, and 0 for block 1 (RT-D1b N2). It is then pinned
  with the block id (`RestorePoint`, RT-D1b N1): a rescan that reaches the restore point
  again (a reorganization deeper than the kept window, or one forced by a node lying in
  the single-header reorganization probe) must find the same block at the same position,
  or it is refused, and the backfill below it is kept, since the block id commits to the
  chain below it. Another block there is a real reorganization below the restore point,
  and the backfill is discarded and fetched again (RT-D1b N3), but only under the header
  check: every rewind below the restore point turns on the restore's header check from
  the genesis for the rescan, and without it another block there is refused (RT-D1c M1:
  a node could otherwise relink the real blocks under new ids without new proof of work
  and pass them off as a reorganization). A wallet file written before the pin is pinned
  when loaded, or at its first rewind below the restore point, from its own index: the
  position, with the block id while it is still kept, else by position only, in which
  case any block there must start at that position (RT-D1c M2). A later node whose
  positions contradict the stored ones gets an explicit error: the node used for restore
  may have lied; restore again from a trusted node. A wallet scanned from the genesis
  derives every position and every height itself.
- *Backfill* (below the restore height). Fetched once with `/outputs`, as the whole
  range `0 .. start`, and checked only for shape against consensus facts before it is
  stored: no output at height 0 (the genesis body is empty), every height `1..=synced`
  present with at least one coinbase output (every coinbase has at least one), heights
  non-decreasing and none above the synced block. A backfill that fails is not stored.
- *Old wallet files* (written before the index existed, no block synced since). The
  synced block is fetched again from `/blocks`, checked against the wallet's own block
  id and `tx_root`; its `first_output` must agree with the global indices of the
  wallet's own outputs and is then where the backfill ends.

**When the backfill is made (RT-D1 F2).** By the `sync` that catches up, not by the
spend: a spend requests nothing but `/tx`. The one exception is a spend made straight
after a restore with no `sync` in between (the spend's own scan does not backfill): the
spend then fetches the backfill just before `/tx`, and warns. Run `sync` after `restore`
before spending; the CLI says so.

**Residual (F38-2; 38 W11, P1).** Below the restore height the node chooses the output
keys, commitments and heights. The shape check catches a gap, a stale tail or a block
without a coinbase output, not a consistent fabrication, so that node still chooses the
older part of the distribution and of the decoy pool. The restoring node also chooses
where the restore point's outputs start, so it can shift every global index from there
on consistently; only a later honest node detects it (RT-D1b N2; a header commitment is
under research). Verifying the backfill (38 W11) is P1. Until then, restore from your
own node, or restore from the genesis; the CLI warns at `restore`.

**Forced rescans (RT-D1b N4, RT-D1c M3).** The reorganization probe reads one header per
height without proof of work, so a node can force a rescan back to the restore point at
no cost to itself. The pin makes such a rescan harmless for output positions, a base id
taken from a lying header is dropped when the restore point turns out not to extend it
(so the next sync rebuilds it instead of failing forever), and the rescan is checked
from the genesis. The bandwidth bound is per `sync` call: at most one walk-back and
rescan from the restore point (the blocks from there, the header chain from the genesis)
and one PX backfill (the commitment and contract lists, and the blocks they name); the
output backfill is not fetched again unless the restore point changed. A node can repeat
this at every sync; nothing rate-limits it yet. A node behind the restore point cannot
have the PX backfill take its base id from its own unverified headers: while the header
check is due, the backfill waits for a node past the restore point ("sync again"), and a
base id that a checked header chain from the genesis contradicts is replaced and the PX
backfill rebuilt, instead of failing every sync (RT-D1d R1). Routine syncs (no restore
check, no `set_verify_headers`) still do not check proof of work: a node can relink the
blocks above the restore point, but not move an output position (the index must
continue).

The decoy draws come from an
operating-system-seeded RNG, not the hedged stream (F38-5, not implemented): a cloned
machine or a broken OS RNG repeats decoys.

**Merge avoidance (review R3-13).** When no single output covers a payment, input
selection first takes at most one output per source transaction. Outputs stored
without their transaction, from older wallet files, are grouped by block. Only if that
cannot cover the amount does it fall back to plain largest-first, and it then warns
that the transaction spends outputs of one source together.

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

**The anchor check is also the burning-bug defence.** There is no chain-wide uniqueness
rule on one-time keys (§8.2), so a wallet that skips step 5 of §3.3 can be made to
credit a copy of one of its outputs placed in another transaction. Third-party wallets
without the check are not supported: they are open to the Janus attack anyway.

A wallet must also:
- **credit at most one output per key image.** Outputs with the same `O` share the key
  image `I`, and only one of them can ever be spent. Should two outputs pass the scan with
  the same `I` (unreachable on a valid chain for a wallet running step 5, §3.1 Lemma 2;
  possible with a dishonest node), keep the one with the **largest amount**, then the
  **lowest global index**, and record the event only in a local diagnostic log. Keeping
  the first seen instead would let a small early copy displace a large genuine output.
  Keep **every** such output unchanged, with the credit as a flag, and elect the
  credited one again after every scan and rewind: an output that replaces another in
  place (its height and global index overwritten) is lost when a reorganization
  removes the replacing block, and the genuine output below the fork then stays
  invisible until a restore from the seed (red team RTW1-4). All of them share the key
  image's spent and reserved state. A stored ring reused for that key image drops
  every member carrying the shared one-time key, so the kept part of the ring never
  repeats the credited output's key. Fresh decoy draws for that spend are not yet kept
  from drawing another output with the same key (an open item of the decoy picker).
  Reference: `Wallet::apply_block` and
  `Wallet::elect_credited` (wallet/src/wallet/sync.rs).
- **not filter outputs that share a one-time key out of decoy selection.** The wallet
  cannot tell a copy from the genuine output; excluding both would make the genuine one
  a never-decoy, and its later spend would be identified. Unfiltered, a copy is a decoy
  its creator knows, like any output the creator owns.

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
  the Jamtis "Janus anchor" proposed for Monero, but have **not been peer-reviewed**.
  They would be a first item if an external reviewer were engaged (§15).

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
| Burning bug (Monero 2018) | Input-context binding and the recipient's anchor check (§3.1 Lemma 2, §3.3 step 5), one-time keys distinct within every transaction (T6, B7, `PxDuplicateOutputKey`), and one credited output per key image (§12.5). No ledger rule (§8.2). |
| Front-running veto with a copied `O` | No rule relates `O` to the chain or to other transactions (§8.2), so a mined or pooled copy of a pending transaction's key leaves that transaction valid. |
| Ring member duplication or out-of-range reference | Strictly increasing indices (T5), existence and age checks (C1). |
| Referencing unconfirmed or very recent outputs | Spendable age of 10, coinbase maturity 60 (§5.3). |
| Weak Fiat–Shamir in range proofs | The transcript absorbs the statement and all prover messages (§7). |
| Cross-network and cross-chain replay | `network_id`, `branch_id` and `genesis_id` in `sig_message` and in the PX binding `h_tx` (§4.4). |
| Verification DoS | Bounded sizes (T1, T3, ring = 16). Cheap checks run first. A transaction's verification cost is bounded by about 64 CLSAGs and one BP+ with `N ≤ 1024`. Peers relaying **stateless-invalid** transactions (§8.1) are penalized (p2p.md §10). Signature checks are contextual (they need the ring members from the chain), so relays of transactions with invalid signatures are **not** penalized: an open defect (N-11, docs/reviews/completion-readiness-2026-09-26.md). |
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
| Δ5 | Input-context binding; one-time keys distinct within a transaction (Carrot §4.3), none across transactions (Monero has neither rule) | Burning bug prevented at the recipient by construction | none (no key set is kept) |
| Δ6 | No `extra`, `unlock_time` or payment IDs; sorted outputs | Removes the main fingerprinting vectors | Fewer app features (no arbitrary data on chain) |
| Δ7 | Exact coinbase amount (not ≤) | Exact supply accounting | none |
| Δ8 | Limits: ≤ 64 inputs, 2–16 outputs, 100 kB transactions | Bounded verification cost | Large sweeps need several transactions |

---

## 15. Known limitations and open items

- **No external audit.** CLSAG and BP+ are implemented from the papers and from
  Monero's design (externally reviewed for Monero, as reported by that project; not
  this implementation), in pure Rust. Because of Δ1 no official test vectors exist.
  The test plan (§16) compensates with adversarial and property testing, which is not
  a substitute for a cryptographic review. By the owner's decision of 2026-09-25, no
  external review is engaged or currently required (reviews/review-status.md); this
  layer would be an item if a reviewer were engaged.
- **The Janus anchor (Δ4)** is our construction. Its analysis (§12.4) has been
  reviewed only internally.
- **Decoy selection** (wallet policy, `tx/src/decoy.rs`) uses Monero's gamma parameters,
  which were fitted to Monero's spend-age data. BlackSilk has no spend data of its own yet.
- **Economics constants** are fixed for v1 in [`blocks.md`](blocks.md) §2 and §5:
  `FEE_PER_WEIGHT = 20` and `MAX_BLOCK_WEIGHT = 600 000`. A dynamic block weight is
  future work.
- **Ring-signature anonymity is statistical** (§11.3, §11.7).
- **Not post-quantum** (§11.6).
- **Genesis** has an empty body and no coinbase ([`blocks.md`](blocks.md) §3).

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
   - `z = 0` is refused by the signer, and a signature with `D = identity` is rejected
     (pinned vector `reject.d_identity`, crypto/tests/vectors/clsag.txt).
4. **BP+**
   - Prove/verify for `k = 1..16`, including the amounts 0 and `2^64 − 1`.
   - The honest prover refuses out-of-range values.
   - Every single-element mutation of a proof is rejected.
   - Wrong proof lengths are rejected.
   - Batch verification detects one bad proof among many.
5. **Transactions**
   - Build → serialize → deserialize → validate.
   - One negative test per rule T1–T11, C1–C3 and B1–B7. Each constructs a violating
     transaction and asserts the specific error.
   - Inflation attempt: outputs exceeding inputs with a forged range proof, rejected.
   - Double spend within a transaction, a block and the chain, all rejected.
   - Signature-coverage test: flipping any single prefix, base or BP+ byte invalidates
     the transaction.
6. **Property tests** over random wallets, amounts and ring positions. These are seeded
   randomized loops, not `proptest`. (The original reason, that `getrandom` did not
   build on the GNU toolchain, was resolved in R4 by moving to MSVC, AUDIT.md Phase 1;
   the seeded loops were kept.)
7. **Integration** with `blacksilk-consensus`: blocks whose `tx_root` commits to real
   transactions, a reorg deeper than 10 returning transactions to the mempool, and
   coinbase maturity.
