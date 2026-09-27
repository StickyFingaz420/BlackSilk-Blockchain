# 19 hash-domain-separation: research dossier (phase 2, phase 1)

Specialist agent 19. This is internal engineering research, not an audit. Nothing here
claims that BlackSilk or any of its hashes is secure or proven. "Mathematically
established" below means that an argument was written out, or that a published proof
in an idealized model (ideal permutation or random oracle) applies. It never means that
the concrete permutation is secure.

- **Commit read:** `rebuild/core` @ `9e422d8` (`git rev-parse --short HEAD`).
- **Mode:** read-only on the repository. No builds and no tests were run. Every test
  named below was read, not executed.

---

## 1. Scope and what I read

### 1.1 Code in scope

| Area | Files |
|---|---|
| v1 Blake2b tag scheme | `crypto/src/hash.rs` (all), and the call sites of `h32`/`h64`/`Hasher64`/`Hs`/`Hp` in `crypto/src/{stealth,janus,keys,clsag,schnorr,generators}.rs`, `tx/src/{types,px}.rs`, `px/src/delivery.rs`, `p2p/src/{transport,addrman,addr}.rs`, `node/src/fingerprint.rs`, `px/src/fingerprint.rs` |
| Consensus Blake2b (untagged) | `consensus/src/hash.rs`, `consensus/src/merkle.rs`, `consensus/src/header.rs` (block id), `chain/src/manager.rs:66-72` (PoW cache key), `tools/genesis/src/lib.rs:34,147-170` (genesis nonce) |
| `Hk` and the tree node | `px-core/src/hash.rs` (all), `px-core/src/record.rs`, `px-core/src/call.rs` (`io_hash`), `px-core/src/kernel.rs` (membership loop `:292-311`), `px/src/tree.rs`, `px/src/state.rs`, `px/src/perm.rs` |
| Wallet and application `Hk` domains | `px/src/wallet.rs:30-47` (`key_domain`, `0x0050_5A01..05`), `px/src/vault.rs:45-74` and `zkvm/guests/vault/src` (`LOCK = 0x5641_0001`) |
| Transcript domains | `zk/src/params.rs` (`PARAMS_ID`, `COLLISION_BITS`), `zk/src/config.rs` (challenger, `TruncatedPermutation`, `PaddingFreeSponge`), `zkvm/src/prove.rs:45-80` (`CIRCUIT_ID`, `statement_digest`), `consensus/src/schedule.rs` (`BRANCH_ID_V3`), `tx/src/params.rs` (`SigDomain`) |
| Third party | `p3-baby-bear-0.7.0/src/poseidon2.rs` (round numbers, Grain constants), `p3-symmetric-0.7.0/src/compression.rs` (`TruncatedPermutation`) in the local cargo registry |

### 1.2 Tests read

- `crypto/src/hash.rs`: `tags_are_distinct_and_short`, `domain_separation`,
  `parts_are_concatenated`, `kat_matches_definition`.
- `px-core/src/hash.rs`: `hash_equals_the_reference_sponge_for_every_length`,
  `domain_and_length_separate_outputs`, `non_canonical_input_panics`,
  `domains_are_distinct_and_canonical`. All four use a **toy** permutation.
- `zk/tests/pins.rs::poseidon2_is_the_pinned_permutation`: one Plonky3 vector.
- `zkvm/tests/circuit_id.rs`.
- `px/src/tree.rs::frontier_and_full_tree_agree_and_paths_verify`.
- `px/tests/kernel.rs`: native/guest agreement and the per-check rejections.
- `px/tests/consensus_fingerprint.rs`.
- `tx/tests/upgrade.rs`: the branch id in the signature messages and in `h_tx`.

### 1.3 Documents read

- `docs/reviews/full-review-2026-09-27.md`: §1–§3, and the register rows R2-C6, R2-C7,
  R2-C11, P0-10, P1-11, P2-16 and D9.
- `docs/reviews/autonomous-session-2026-09-27.md` (all).
- `docs/reviews/v3-upgrade-mechanism.md` (all, including **§9, the feed-forward
  measurement**).
- `full-review-2026-09-27/R2-crypto.md`: §2, §8, §13, and the tables.
- `full-review-2026-09-27/SX1-core-crossreview.md` (all).
- `docs/px.md`: §2, §3, §9.1.
- `docs/zk.md`: §9.5–§9.6, §12.
- `docs/transactions.md` §1.2.
- `docs/consensus.md` (the Merkle node).
- The brief, and the roster entries 18–25, 37, 40, 46, 47 and 49.

---

## 2. Current state

### 2.1 v1 Blake2b tag scheme (`crypto/src/hash.rs`)

- **The tag scheme.** A tag is `u8(len) ‖ "BlackSilk/v1/" ‖ name`, prefixed to every
  `H32`, `H64`, `Hs` and `Hp` input. So a tag can never be confused with data.
  - [math] The length byte makes the tag/data split unambiguous.
  - [tested: `domain_separation`, `kat_matches_definition`]
- **Distinct names.** The 68 names in `tags::ALL` are pairwise distinct and short
  [tested: `tags_are_distinct_and_short`].
- **Data parts are not length-prefixed.** Every call site I read passes fixed-width
  items. The one variable-length list is always the final part.
  - [source-read] The call sites are `janus.rs:54`, `keys.rs:113`, `transport.rs:168`,
    `delivery.rs:154`, `px.rs:389,398,572`, `types.rs:278`, `stealth.rs:46-63` and
    `addrman.rs:49`.
  - The addrman group is self-delimiting. Its first byte is a type byte (4, 6 or 10),
    and an onion host is validated to exactly 56 base32 characters (`addr.rs:17,33`).
    [source-read]
- **R2-C13 is not reachable (it was overstated).** R2's theoretical ambiguity in
  `px_context(nullifiers ‖ key images)` cannot happen. Its only caller,
  `tx/src/px.rs:445-447`, passes `self.nullifiers`, which is a `[Digest; 2]`. So the
  nullifier part is always exactly 64 bytes. [source-read]
- **Weakness: names are not enforced by type.** `Hasher64::new(name: &str)` accepts
  any string. Two consensus-adjacent domains bypass `tags::ALL`:
  - `node/src/fingerprint.rs:25` uses `"node/consensus-fingerprint/v1"`;
  - `px/src/fingerprint.rs:148` takes a caller-supplied `domain`.

  Nothing tests that these names differ from the registered ones (§4, F6).

### 2.2 The consensus-layer Blake2b (a separate, untagged scheme)

These hashes do not use the tag scheme. Each is plain Blake2b-256:

| Context | Input |
|---|---|
| Block id | `"BlackSilk/block-id" ‖ LE32(net) ‖ header[100]` (`header.rs:58-64`) |
| Tx Merkle leaf | `0x00 ‖ id` (`merkle.rs:5-11`) |
| Tx Merkle node | `0x01 ‖ l ‖ r` (`merkle.rs:5-11`) |
| PoW cache key | `"BlackSilk/pow-cache/v2" ‖ seed ‖ header` (`manager.rs:66-72`; node-local, not consensus) |
| Genesis nonce | `"BlackSilk/genesis-nonce/v1" ‖ …` (`tools/genesis`) |

- [math] The contexts are separated by their first byte:
  - `0x00` for a leaf and `0x01` for a node;
  - `0x42` ('B') for the three ASCII-prefixed contexts, which are pairwise
    prefix-free;
  - 14–43 for the tag scheme. The tag length byte is 13 + len(name), and the longest
    name is 30 characters.

  So no input of one context can equal an input of another. Within each context the
  input has a fixed length, except the tx Merkle tree. There, leaf and node are
  separated and there is no CVE-2012-2459 duplication [R1 V4; tested:
  `no_duplicate_malleability`].
- This argument is not written down anywhere, and `docs/transactions.md` §1.2 says
  "All hashing uses Blake2b … Every hash has a domain tag". That is not literally
  true of the consensus layer (§4, F6).

### 2.3 `Hk` (`px-core/src/hash.rs`)

**The sponge.**
- It is a Poseidon2-BabyBear-16 sponge: rate 8, capacity 8.
- The capacity starts as `[domain, len, 0⁶]`.
- Absorption is additive, and the output is the rate after the last permutation.
- Every `Hk` input is fixed-length per domain, with the length in the capacity:
  - record 52;
  - owner, nullifier and contract nullifier 24;
  - `nk` and `ak` 8;
  - rho 9;
  - diversifier 10;
  - `io_hash` 92 (`IO_LEN`, `call.rs:47`);
  - `sk` 16.
- Non-canonical elements, and wrong lengths, halt the computation (`invalid_input`).

**Domains.**
- The consensus domains are `0x0050_5801..0A`. They are distinct, nonzero and below
  p [tested with the toy permutation: `domains_are_distinct_and_canonical`], and they
  are pinned in the fingerprint (`px/src/fingerprint.rs:230-245`).
- The wallet domains are `0x0050_5A01..05` (`px/src/wallet.rs:36`).
- The vault's application domain is `0x5641_0001` (`px/src/vault.rs:46`, repeated in
  the vault guest).
- [source-read] All of these are distinct.
- No test covers the three namespaces together.

**Sponge security.**
- [math, ideal permutation] The generic bound is about p^(c/2) = 2^123.6 for both
  collisions and preimages. [R2 §8, SX1]
- [tested, toy permutation only] The fast path agrees with the reference sponge for
  every length from 0 to 40.
- **No known-answer test exists for `Hk` under the real permutation.** It is pinned
  only indirectly:
  - the Plonky3 permutation vector (`zk/tests/pins.rs`);
  - the native/guest agreement tests (`px/tests/kernel.rs`);
  - the pinned kernel ELF id, which pins code, not outputs.

**The tree node.**
- `node(l, r) = P(l ‖ r)[0..8]`: no feed-forward, fixed depth 32, empty leaves
  `ZERO_DIGEST`.
- The code comment was corrected on the candidate (`53d3b49`, now on HEAD,
  `hash.rs:15-35`). It now states correctly that `node()` alone is not collision
  resistant, and it gives the leaf-anchoring argument.
- **The consolidated report's "the comment is still in `px-core/src/hash.rs`" is
  out of date** for the code. It is **not** out of date for the docs (§4, F1).

**Who can add a leaf.** [source-read]
- Leaves are appended only in `px/src/state.rs:135-139`.
- Every leaf there comes from `Public.commitments`: the kernel-proven
  `Record::commit` outputs of verified PX transactions, reached from
  `tx/src/state.rs:219` for PX transactions only.
- Deploys add registry entries, never leaves.

So **every leaf is a proven `Hk(RECORD, 52 elements)` output**. This invariant carries
the tree's binding (§3.1), and nothing in the code states it or guards it.

### 2.4 The STARK's own hashing (`zk/src/config.rs`)

- `Hash = PaddingFreeSponge<Perm,16,8,8>` (an overwrite sponge with zero IV) and
  `Compress = TruncatedPermutation<Perm,2,8,16>`.
  - This is **the same `node()` construction and the same width-16 permutation** as
    the PX tree.
  - The MMCS uses salted leaves (`MERKLE_SALT_ELEMS = 4`).
- The Fiat–Shamir challenger is a duplex sponge on the same permutation. It is seeded
  with `LEN ‖ PARAMS_ID` (bytes as elements) and then the 32-byte statement digest.
- The statement digest is `H64("zkvm/statement", LE64(len) ‖ CIRCUIT_ID ‖ …)`, with
  every table and column length-prefixed [tested: `zkvm/tests/circuit_id.rs`].
- **Consequence.** The soundness of every PX proof already rests on the
  truncated-permutation Merkle construction, which BlackSilk cannot change without
  forking Plonky3's MMCS. This matters for the R2-C6 decision (§3.1).

### 2.5 Branch and network binding

`SigDomain = LE32(network_id) ‖ LE32(branch_id)` is fixed-width and is prepended in all
three signature messages and in `h_tx`. `Schedule::new` enforces that branch ids are
nonzero and pairwise distinct [tested: `tx/tests/upgrade.rs`, including the swapped
(network, branch) case]. It reaches the STARK transcript through the binding public
values (v3-upgrade-mechanism.md §1) [source-read].

### 2.6 The Poseidon2 instance

- The instance is BabyBear with t = 16, α = 7, R_F = 8 and R_P = 13.
  `p3-baby-bear-0.7.0/src/poseidon2.rs:33-47` derives R_P = ⌈1.075 × 11.682⌉ = 13 from
  the paper's Eq. 1. [source-read]
- The round constants come from the Poseidon2 authors' Grain LFSR script
  (`generate_constants.py`, `poseidon2.rs:105-171`).
- The internal diagonal was found by an efficiency search (`poseidon2.rs:3-12`).
- The pinned test vector covers the whole permutation. The fingerprint pins neither
  (t, α, R_F, R_P) nor the constants.

---

## 3. The problems in scope

### 3.1 R2-C6: the tree node without feed-forward (consensus decision)

**What is the problem, and why does it exist?**
- `node()` mirrors Plonky3's `TruncatedPermutation`.
- P is publicly invertible, so `P⁻¹(d‖u₁)` and `P⁻¹(d‖u₂)` are two child pairs with
  the same node. `node` on its own is therefore neither collision resistant nor
  preimage resistant. [math; R2, SX1]
- The Poseidon2 paper's compression mode is `Tr_n(P(x) + x)`. The paper says it
  "crucially relies on a feed-forward operation for one-wayness" (ePrint 2023/323 §3.1).

**New primary evidence.** Coratger, Khovratovich, Mennink and Wagner, *The Billion
Dollar Merkle Tree*, ePrint 2026/089, accepted at ACM CCS 2026. I read the full text.
- It analyses exactly this tree: leaves `H(x)`, nodes `Trunc(P(l, r))`, with no
  feed-forward.
- Theorem 1 proves **strong position-binding** (P an ideal permutation, H collision
  and preimage resistant): about 4q²/|H|.
- Theorem 2 proves **strong extractability** with H a random oracle.
- Theorem 3 proves **strong extractability when H is an overwrite sponge built from
  the same permutation P**, with bound (4q² + 2q)/(|H| − 1).
- With |H| = p⁸ ≈ 2^247.3, this gives about **122.6 bits**. The authors: "the Plonky3
  approach is, in fact, sound".
- Section 6 gives a contrived collision-resistant H built from P that makes the tree
  completely insecure. The leaf hash is therefore load-bearing.
- Appendix C extends the result to MMCS injection at intermediate levels, as sparse
  trees with a fixed topology.

**How the argument maps onto BlackSilk** [math, my adaptation; see F3]:

| Paper's condition | BlackSilk |
|---|---|
| Every leaf is an H-output | Holds by the §2.3 invariant: kernel-proven `Hk(RECORD)` |
| Fixed topology | Holds: depth 32 |
| H is an overwrite sponge with zero IV over the same P | Differs in three ways (below) |

The three differences:
- **(a) Additive absorption.** Per state this is a bijective relabelling of the
  message block, so the extractor recovers `m = input − rate`.
- **(b) A structured IV** `(domain, len, 0⁶)` instead of 0. The extractor's
  termination test becomes "the capacity is a valid IV" over a small set (at most
  about 15 domains × 64 lengths), which adds at most a factor of about |IV set| to one
  q/|H| term.
- **(c) Empty leaves are the constant 0, not H-outputs.** A leaf of 0 is openable only
  by a sponge preimage of 0 (≈ q/|H|).

None of the three changes the bound's order, but **the adapted proof is not written**.

**Classical comparison.**
- Without feed-forward, the best generic forgery against an honest root is a
  meet-in-the-middle claw: top-down inversions against bottom-up paths from
  attacker-made records, about 2^124. [math; R2 and SX1 agree]
- With feed-forward, forging against an honest root becomes a second preimage (about
  2^247). But a *planted* collision (two records with different values, one inserted
  in advance) still costs about 2^124 by the birthday bound.
- **The binding level is the same (about 2^123–2^124) either way.** Feed-forward only
  removes the need to plan ahead.

**Quantum.**
- Claw-finding and the BHT collision bound are both about 2^83 on paper. Bernstein's
  cost analysis puts both no better than parallel classical search. [assumed; R2 §8]
- No difference between the two options.

**Algebraic attack surface.**
- Without feed-forward, a forged path must end at an anchored leaf. So beyond the
  generic attack, the only algebraic target is the sponge CICO problem, and the leaf
  hash depends on that anyway.
- With feed-forward, the tree also depends on the collision resistance of
  **Poseidon2 compression mode**, which is exactly what the 2026 "Skipping Class"
  paper targets. It improves compression-mode preimage attacks and gives the first
  algebraic collision attack that beats the matching preimage attack (ePrint
  2026/306, Table 1).
- So **feed-forward does not strictly dominate**: it removes one structural caveat
  and adds a mode-specific target. [math/assumed: neither mode is broken at full
  rounds]

**Security consequences.**
- There is no exploit today, and the tree is about 122–124 bits binding under the
  ideal-permutation assumption.
- The real risk is **misuse**: reusing `node()` in any tree whose leaves are free.
  For example I2's gap tree, a contract state tree, or a future "commitment from
  outside the kernel". With two adjacent free leaves, forging is instant: take any
  target node and choose `(a, b) = P⁻¹(N ‖ u′)`. That is an inflation bug at zero cost.

**Classification.** Consensus-critical (the tree defines anchors and kernel ids). Not
privacy-critical. Architectural (the misuse trap).

**Prior art.**
- **Plonky3 MMCS** uses `TruncatedPermutation`; SP1, OpenVM, Ziren and others depend
  on it (ePrint 2026/089 §1, App. A).
- **The Poseidon2 paper** recommends feed-forward.
- **Sponge-with-capacity nodes:**
  - Triton VM / Neptune's Tip5 `hash_pair` sets the capacity to a fixed constant;
  - Miden's RPO `merge` is a sponge with domain-separated capacity;
  - both are standalone collision resistant through CICO on the capacity.
- **Zcash Orchard** uses a collision-resistant Sinsemilla node with a level
  personalization.
- **The Daemen–Mennink–Van Assche minimal tree mode** (cited in 2026/089 §1.2) uses
  domain bits for leaf, node and final.

**Alternatives.**

| Option | Consensus | Cost | Standalone CR | Risk |
|---|---|---|---|---|
| A. Keep, write the argument, add a guard, add vectors | none (docs, tests, lint) | S–M | no | Misuse trap (guarded by a lint and documentation) |
| B. Feed-forward `P(l‖r)[0..8] + l` | CONS: kernel id, empty roots | +2,631 cycles measured (§9); `n_fn = 1` goes to 2^16 CPU rows, or a budget of exactly 32,768 at 94.7% use | yes (generic) | Adds a compression-mode target; re-measure the widest proof, ZK-F4 and P-5 |
| C. Feed-forward inside a new `POSEIDON2_COMPRESS` syscall | CONS + AIR (`CIRCUIT_ID`) | about 0 kernel cycles; AIR work | yes | New circuit surface; XL review |
| D. Width-24 node with an 8-element capacity (`P24(l‖r‖IV)`) | CONS + new AIR table | large | yes (CICO) | New permutation instance in consensus; XL |
| E. Move feed-forward (or a different node) into the next hash-agility event | future CONS | 0 now | later | Any Poseidon2 round or width change forces a new tree anyway |

**Tests that prove the chosen option.** See §5 items 2, 4 and 5:
- a real-permutation inverse that demonstrates the `node` collision and the free-leaf
  forgery on a toy tree;
- kernel rejection of every non-anchored leaf;
- golden `Hk`, node, empty-root and frontier vectors.

**Invariants that must never change:**
1. Every tree leaf is a kernel-proven `Hk(RECORD, 52)` output.
2. The depth is fixed at 32 and the topology is fixed.
3. An empty leaf is `ZERO_DIGEST`, and no opening of it is accepted.
4. `node()` is never used where leaves are not anchored sponge outputs.
5. The `Hk` domain constants, IV layout and absorption rule change only through a
   versioned upgrade (never-change list item 13).

#### R2-C6 recommendation under the consensus discipline

**Recommendation: option A for v3. Do not adopt feed-forward. Defer any node change to
the first hash-agility event (option E).** This reverses SX1's and D9's "include if
the budgets hold", for four reasons:
1. **A published proof now covers the construction.** The tree reaches about 122.6
   bits, the same birthday-capped level feed-forward would reach. Feed-forward does
   not raise the security level; it only removes a misuse trap, and a lint plus
   documentation can guard that trap.
2. **The system depends on the construction regardless.** Every PX proof's MMCS
   binding uses the identical construction, so adding feed-forward to the PX tree
   removes no dependence on the "truncated permutation plus anchored leaves"
   argument.
3. **The measured cost falls on the wrong shape.** It pushes `n_fn = 1`, the vault
   call and the only contract shape in the trial, to 2^16 CPU rows, or to a 94.7%
   budget. Either way it forces re-measuring the widest proof, ZK-F4 and P-5, and a
   new kernel id, late in the freeze.
4. **Feed-forward adds a target.** It makes the tree depend on Poseidon2
   compression-mode collision resistance, an actively attacked mode in 2026.

SX1's counter-argument was that "`node` is kernel-id-bound, so a later change costs
another identity". It is weakened by R2-C7. The most plausible reason to change `node`
later is a change to the Poseidon2 instance (rounds or width). That change needs a new
permutation table, a new `PARAMS_ID` and a new tree anyway, so feed-forward can ride it
at no extra identity cost.

The 12 discipline steps:

| Step | Content |
|---|---|
| 1. Problem | §3.1: standalone non-CR `node`; a misuse trap; false documentation (F1) |
| 2. Demonstrated failure | None against the PX tree. A standalone collision and a free-leaf forgery are *demonstrable*, and item 5 builds the demonstration as a test |
| 3. Prior art | Plonky3 MMCS, and ePrint 2026/089 Thms 1–3 and §6; Poseidon2 §3.1; Tip5, RPO and Orchard (above) |
| 4. Alternatives | A–E (above) |
| 5. Affected components | Option A: docs, tests, a lint (`clippy.toml` `disallowed-methods`). No px-core code change, so the kernel ELF is unchanged |
| 6. Activation | Option A: none. Option E: with the verifier-id and tree migration (§3.4) |
| 7. Compatibility | Option A: full |
| 8. Reorg, wallet, mining, P2P | Option A: none. For option B, recorded for completeness: wallets must rebuild trees; the empty root and genesis PX root change; no P2P or mining effect |
| 9. Golden vectors | `Hk` for each domain (lengths 0, 1, 7, 8, 9, 24, 52, 92), `node`, `empty_roots[0..=32]`, frontier roots at 1, 2, 3, 300 and 2^k ± 1, record/nullifier/rho/owner, `io_hash` (item 2) |
| 10. Regression tests | Item 5 (adversarial) and the existing kernel rejection tests |
| 11. Full suite | Required only if code changes. For option A, only the lint and the new tests |
| 12. Adversarial review | A second reviewer re-derives the Thm 3 adaptation (F3). The owner signs off the written argument |

**If the owner nevertheless chooses feed-forward (option B):**
- change `node` in px-core, the kernel budgets (`px/src/prove.rs:54-60`, `n_fn = 1`
  → 32,768 or accept 2^16), `kernel.elf` and `kernel.id`, the zk.md and px.md text,
  and the empty roots;
- re-run the vault id check (the vault does not call `node`, but it links px-core);
- re-measure the widest two-function proof, ZK-F4 and P-5;
- do it **before** the platform-neutral rebuild (SX1 §3 item 2).

### 3.2 Are all domains distinct and length-prefixed?

| Namespace | Distinct | Length handling | Evidence |
|---|---|---|---|
| v1 tags (68) | yes | tag length byte; data fixed-width or a single final variable list | tested + source-read |
| Fingerprint domains (`node/consensus-fingerprint/v1`, the manifest's own) | yes by inspection | as tags | **not in `tags::ALL`; untested** (F6) |
| Consensus Blake2b (block id, Merkle, PoW cache, genesis nonce) | yes, by first byte | fixed lengths; the Merkle tree separates leaf and node | math, undocumented (F6) |
| `Hk` consensus `0x0050_5801..0A` | yes | length in the capacity | tested (toy) + fingerprint |
| `Hk` wallet `0x0050_5A01..05` | yes | length in the capacity | source-read; no cross-namespace test (F5) |
| `Hk` application (vault `0x5641_0001`) | yes | length in the capacity | source-read; no reserved range (F5) |
| `Hk` sponge vs `node` | only for honest siblings | — | **F2**: kernel siblings are witness-chosen |
| STARK: MMCS sponge (zero IV) vs `Hk` (nonzero domain) | yes (capacity word 8) | fixed row widths | math |
| STARK transcript (`PARAMS_ID`, `CIRCUIT_ID`, statement) | yes | length-prefixed | tested |
| Branch and network (`SigDomain`) | yes, distinct branch ids enforced | fixed 8 bytes | tested |

### 3.3 R2-C7: Poseidon2 round margins, with the 2025–2026 cryptanalysis

**What was published** (primary sources, read on 2026-09-27):
- **Skipping Class** (Merz and Rodríguez García, ePrint 2026/306):
  - It exploits the structure of Poseidon2's external matrix (`P_{t/4} ⊗ M4`) for
    round skipping in CICO, in compression mode (with feed-forward) and in sponge
    mode.
  - Up to 2^106 improvement for one recommended 128-bit set, and the first algebraic
    collision attack that beats the matching preimage attack.
  - Their words: "due to the algebraic security margin this does not mean the
    primitive falls short of its claimed security level".
  - They state that the conditions of their attack hold whenever c ≥ t/4 or
    d ≥ t/4. BlackSilk has t = 16 and c = d = 8, so **the structural precondition
    applies**. BabyBear-16 with α = 7 is not among their worked parameter sets.
  - Countermeasures: more external rounds, MDS matrices, or `M4 ⊗ P_{t/4}`.
  - The Poseidon2b designers increased external rounds after the disclosure (§6).
- **GSR, "From Round Skipping to S-Box Skipping"** (Bhati, Tariq and Ashur, ePrint
  2026/1692):
  - Poseidon (v1), KoalaBear, t = 24, α = 3: CICO-1 at 28 of 31 rounds, CICO-2 at 25
    of 31.
  - The authors say it is independent of the constants, the matrix, α and p.
- **Midpoint Reset** (Jo, ePrint 2026/1760): a full-round collision on Poseidon (v1)
  KoalaBear (16, 3, 8, 20) in compression mode, **only where the MDS matrix is chosen
  after the round constants**. That is not a standard instance. The lesson is about
  provenance (F9).
- **Resultant and bounty papers** (ePrint 2026/150, 2026/1905): reduced-round only.
- **Poseidon Cryptanalysis Initiative** (poseidon-initiative.info):
  - 2026 CICO bounties on Poseidon-31 KoalaBear were solved up to R_F = 6, R_P = 10
    (July 2026), and the zero-test up to R_P = 12;
  - the program is paused from 1 Aug 2026.
- **Ethereum Foundation:**
  - V. Buterin, X, Feb 2026: the program "identif[ied] some important security issues
    in Poseidon2 (which we could solve either by adding extra rounds, or by going back
    to Poseidon1…)". This is an official-voice primary post, but it gives no technical
    details.
  - Aug 2026: EF researchers announced moving L1 hashing away from Poseidon toward SHA
    or BLAKE. This comes via a secondary report citing J. Drake's post; I treat it as
    [assumed] in detail.
- **Round-number mismatches in production** (Ziren issue #524, Aug 2026): KoalaBear
  α = 3 was shipped with α = 7's R_P = 13. BlackSilk's α = 7 with R_P = 13 matches the
  `(16, 7) ⇒ (8, 13)` table [source-read], but no BlackSilk test asserts this mapping.

**Assessment.**
- No published attack reaches full-round BabyBear-16 with α = 7, R_F = 8, R_P = 13
  [unknown whether unpublished results exist].
- The trend has turned against Poseidon2 specifically, in the matrix structure that
  BlackSilk's instance shares. The margin is +2 full rounds and +7.5% partial rounds.

**Consequence for BlackSilk.** One permutation secures three things:
- `Hk` (records, nullifiers, ownership);
- the PX tree;
- the STARK (MMCS and Fiat–Shamir).

So a round increase means a new `POSEIDON2` table, a new `CIRCUIT_ID` and `PARAMS_ID`,
new verifier and kernel ids, and a new tree. It is a planned hard fork, never a patch.

**Severity and plan.**
- Medium (strategic), accepted limitation for the trial.
- P1: a written agility plan (§3.4) with explicit monitoring triggers.
- P2: pin the instance in the fingerprint.

### 3.4 Hash-agility plan (proposal; no consensus change now)

1. **Name the instance.** Add a `hash_instance` to the verifier-id tuple
   (zk.md §9.5): (t, α, R_F, R_P, a digest of the round constants and the internal
   diagonal). Pin it in the consensus fingerprint (item 6).
2. **Version `Hk`.** Allocate a new domain block per `Hk` version. For example, v2
   uses `0x0050_59xx`, and the wallet and application ranges are reserved (item 3).
   Never reuse a block.
3. **Migrate with two trees.**
   - At activation height A, epoch k+1 names verifier v′ (new permutation, new `Hk`,
     new tree T′).
   - T is frozen at A. Its last root stays a valid anchor until the sunset S.
   - A *migration kernel* under v′ opens T records with the old `node` and `Hk` and
     outputs into T′. It needs both permutation tables in one circuit, or it runs as a
     separate old-verifier statement bound to a v′ output by a public commitment.
   - Nullifiers must be domain-separated per tree version, so that a record cannot
     be spent once in T and again in T′.
   - The pool turnstile carries value across.
   - Prior art: Zcash Sprout→Sapling→Orchard turnstiles (ZIP 209), and the zk.md
     §9.5 sunset table.
4. **Triggers** (monitor quarterly; the owner decides):
   - any published attack on BabyBear or KoalaBear Poseidon2 reaching R_P ≥ 10 with
     R_F = 8, in CICO, sponge or compression mode;
   - any full-round Poseidon2 result on a standard (Grain) instance;
   - Plonky3 changing its default rounds;
   - an EF or Poseidon-author recommendation to change rounds for 31-bit instances.
5. **Candidate responses, costed later:**
   - +R_P (to 16–21) or +R_F (to 10);
   - `M4 ⊗ P` external matrices (Skipping Class §6), which is a non-standard instance;
   - width 24;
   - Poseidon1;
   - a hash-friendly migration away from arithmetization-oriented hashing (I4).

   Feed-forward, or a capacity node, rides the same event (option E).

---

## 4. New findings

| ID | Severity | Status | Location | Scenario | Confidence |
|---|---|---|---|---|---|
| **F1** | Medium (claim) | Partially implemented | `docs/px.md:57-58` ("124-bit collision and preimage resistance"), `docs/px.md` §9.1 item 2 ("`Hk` and the node compression: collision resistance, preimage resistance"), `docs/zk.md` §12.1 item 2 and §12.3 row "`Hk` weakness" | The code comment was fixed in `53d3b49`, but the normative docs still state that the node is collision and preimage resistant. That is the false claim of R2-C6, now in the spec. A contract or tree designer reading the spec would reuse `node()` with free leaves (§3.1: an instant inflation forgery) | High |
| **F2** | Low | Not implemented (docs) | `px-core/src/hash.rs:37-40`, `docs/px.md:49-51` | The sponge/node separation argument ("needs a digest ending in `[domain, len, 0…]`, 2^−186") assumes honest siblings. In the kernel, siblings are **witness-chosen** (`kernel.rs:295`). For every 8-element domain D, `node(l, (D, 8, 0⁶)) = Hk(D, l)`: for example, `node(sk, (NK, 8, 0⁶)) = nk`. No exploit: tree binding does not use this separation, and no node output is ever read as an `Hk` digest. But the stated property is false in the kernel's threat model | High (math) |
| **F3** | Low | Complete but requires further analysis | `px-core/src/hash.rs:22-31` | The tree's binding now has a published proof (ePrint 2026/089, Thm 3), but for an overwrite sponge with zero IV. `Hk` differs in additive absorption, its (domain, len) IV and the constant-zero empty leaves. The adaptation (§3.1) is argued here, not written as a proof. Section 6 of the paper shows that dependent leaf hashes can break the tree, so the adaptation must be checked, not assumed | Medium |
| **F4** | Low (P0 evidence item) | Not implemented | `px-core/src/hash.rs:197-275` (toy permutation only); none in `px/tests` | There are no real-permutation `Hk`, node, empty-root or frontier known-answer vectors (R2-C11, P0-10). A coordinated px-core change with a rebuilt ELF (for example, overwrite instead of additive absorption) passes every current test except the kernel-id pin, and that pin is updated by design in such a change | High |
| **F5** | Low | Partially implemented | `px/src/wallet.rs:36`, `px/src/vault.rs:46`, `zkvm/guests/vault/src` (`LOCK`), `px-core/src/hash.rs:255-274` | There is no registry or test across the consensus, wallet and application `Hk` namespaces, and no reserved range for applications. A contract can use any domain, including consensus ones. That has no consensus effect (the kernel computes every consensus hash itself), but it breaks the "each use is a distinct function" story for contract authors | High |
| **F6** | Low | Partially implemented | `crypto/src/hash.rs:176` (`name: &str`), `node/src/fingerprint.rs:25`, `px/src/fingerprint.rs:148`, `docs/transactions.md` §1.2 | Tag names are not type-enforced, and two fingerprint domains bypass `tags::ALL`. The consensus Blake2b contexts use a separate, untagged scheme whose separation (first byte) holds but is undocumented. The docs claim that every hash carries a domain tag | High |
| **F7** | Info | — | `crypto/src/stealth.rs:55` | R2-C13's `px_context` ambiguity is unreachable: nullifiers are always `[Digest; 2]` (`tx/src/px.rs:445`). Harden by making the API take `&[[u8; 32]; 2]` (no byte change) | High |
| **F8** | Medium (strategic) | Accepted limitation | `p3-baby-bear-0.7.0/src/poseidon2.rs:33-47` (instance) | 2026 cryptanalysis targets Poseidon2's matrix structure, and the Skipping Class precondition holds for t = 16, c = 8. The EF reports unspecified "important security issues" in Poseidon2. BlackSilk has one permutation in three roles, so any response is a planned hard fork with a new tree (§3.3–§3.4) | Medium |
| **F9** | Info | Accepted limitation | `poseidon2.rs:3-12,105-171` | Provenance: the constants come from the Grain LFSR (good). The internal diagonal comes from an efficiency search after the constants were fixed. Midpoint Reset (2026/1760) shows that an adversarially chosen linear layer can correlate with fixed constants. Plonky3's diagonal is small-integer and efficiency-driven, not engineered, so I see no risk. The provenance should still be documented and fingerprinted | Medium |
| **F10** | Info | — | `zk/src/params.rs:65` | `COLLISION_BITS = 123`, but the only proof of the tree (2026/089 Thm 3) gives about 122.6 bits, and 4q²/|H| gives 122 after flooring. The soundness calculator input overstates by about 0.4 bits. For workstream 25: set 122, or document the rounding (it changes the fingerprint entry `zk.COLLISION_BITS`, not proofs) | Medium |

Checked and **not** a finding: the addrman `group ‖ source_group` concatenation is
self-delimiting (type byte, fixed onion length 56, `addr.rs:17,33,72-94`).

---

## 5. Implementation plan for phase 2

Owner of every item is 19 unless the coordinator reassigns. **No item changes consensus
or the kernel ELF.** Items touching `px-core/src` edit comments only, and must be
followed by `zkvm/guests/reproduce.sh` to show that the ids are unchanged.

| # | Item | Files (ownership) | Consensus | Identity impact | Tests | Docs | Size | Prio |
|---|---|---|---|---|---|---|---|---|
| 1 | Correct the claims (F1, F2) and write the tree-binding argument with the 2026/089 citation, the three-point adaptation (F3) and the invariants of §3.1 | `docs/px.md` §2 and §9.1, `docs/zk.md` §9.6, §12.1 and §12.3; `px-core/src/hash.rs` comment lines 11-40 only | none | none (comments; verify the ELF id is unchanged) | none | as listed | S | **P0** |
| 2 | Real-permutation golden vectors: `Hk` for every consensus domain at lengths 0/1/7/8/9/24/52/92; `node`; `empty_roots[0..=32]` (including the genesis PX root); `Frontier` roots after 1, 2, 3, 300 and 2^k ± 1 leaves; `Record::commit`, `nullifier`, `contract_nullifier`, `output_rho`, `owner`, `io_hash`, `lock_of`. Derived by an **independent** script (a Poseidon2 implementation from the authors' reference constants, not Plonky3), stored as hex | `px/tests/hk_vectors.rs` (new); `tools/vectors/poseidon2_hk.py` (new, test tooling only) | none | none | unit KAT; independent recompute | `docs/px.md` §9.3 (evidence) | S–M | **P0** (freeze with v3, P0-10) |
| 3 | Domain registry: one normative table of the v1 tags, the fingerprint names, the consensus Blake2b contexts with the first-byte argument, the `Hk` consensus/wallet/application ranges (reserve `0x0050_58xx` consensus, `0x0050_59xx` the next `Hk` version, `0x0050_5Axx` wallet, `0x5641_xxxx` "application, never consensus"), `PARAMS_ID`, `CIRCUIT_ID`, the branch ids and `SigDomain`. Plus a cross-namespace test | `docs/hash-domains.md` (new); `px/tests/domains.rs` (new: consensus, `key_domain` and vault domains distinct, canonical, in their ranges) | none | none | unit | `docs/transactions.md` §1.2 (point to the registry; fix "every hash has a tag") | S | P1 |
| 4 | Guard `node()` against reuse: a `clippy.toml` `disallowed-methods` entry for `blacksilk_px_core::hash::node`, with `#[allow]` only at `px-core/src/kernel.rs` (the membership loop) and `px/src/tree.rs`. **No px-core code change** (a rename or a module move could change the ELF) | `clippy.toml` (workspace root; coordinate with 43); `px/src/tree.rs` (attribute only); the kernel allow needs a px-core attribute, so if the coordinator forbids any px-core touch, allow at crate level in px-core's `lib.rs` with a comment. Check ELF identity either way | none | none (verify) | clippy in CI | registry | S | P1 |
| 5 | Adversarial tests: a test-only BabyBear Poseidon2-16 **inverse** (S-box x^(7⁻¹ mod p−1), inverse external and internal layers by Gaussian elimination at test time); (a) build two child pairs with the same `node`; (b) forge a membership path in a toy tree with two free adjacent leaves; (c) show the kernel refuses a forged path whose leaf is not `Commit(record)` (`NotInTree`); (d) show `node(l, (D, 8, 0⁶)) == Hk(D, l)` (documents F2) | `px/tests/tree_binding.rs` (new) | none | none | adversarial, regression | registry, px.md | M | P1 |
| 6 | Pin the Poseidon2 instance in the fingerprint: t, α, R_F, R_P and a Blake2b digest of the round constants and internal diagonal. Add a test that recomputes R_F and R_P from Eq. 1 of ePrint 2023/323 for (p, 16, 7, κ = 128) and asserts (8, 13) (the Ziren #524 lesson) | `px/src/fingerprint.rs`, `px/tests/consensus_fingerprint.rs`, `zk/tests/pins.rs` | none (the fingerprint value changes: do it before the freeze) | fingerprint only | unit | testnet fingerprint docs | S | P1 (before the freeze) |
| 7 | Type the v1 tags: `pub struct Tag(&'static str)` with the constants in `tags`, and `Hasher64::new(Tag)`; register the fingerprint domains in `tags::ALL`. Byte-identical | `crypto/src/hash.rs`; callers `node/src/fingerprint.rs`, `px/src/fingerprint.rs`, `crypto/src/{clsag,schnorr,generators}.rs` | none | none (existing KATs must pass) | the existing `kat_matches_definition` + golden | registry | S–M | P2 |
| 8 | Hygiene: `px_context` takes `&[[u8; 32]; 2]` (F7); a `debug_assert!(len < P)` in `hash()` and `Sponge::new` **only if** the guest profile compiles debug assertions out (otherwise skip: ELF change) | `crypto/src/stealth.rs`, `tx/src/px.rs:445`; `px-core/src/hash.rs` (conditional) | none | none (verify) | existing | — | S | P2 |
| 9 | Hash-agility plan (§3.4) as a design document with triggers and a monitoring checklist | `docs/hash-agility.md` (new), or a section of item 3's registry | none (plan) | none | — | zk.md §9.5 cross-ref | S | P2 |
| 10 | (Owner option B only) Feed-forward node: see §3.1, "if the owner chooses feed-forward" | `px-core/src/hash.rs`, `px/src/prove.rs`, `px/kernel.elf`, `px/kernel.id`, docs | **CONS** | new kernel id and empty roots | items 2 and 5 regenerated; the full suite; re-measure the widest proof, ZK-F4, P-5 | many | M | only if chosen |

**Benchmarks.** None are needed for option A. Option B would need proving time and
proof size for `n_fn = 1` at 2^15 vs 2^16 CPU rows (workstream 45 or 27).

---

## 6. Dependencies and conflicts

| # | Workstream | Relationship |
|---|---|---|
| 20 | px-kernel | Shares `px-core`. Any kernel edit (theirs) must come before item 1's comment edit, or both verify the ELF id. The kernel's membership loop is where the item 4 allow goes |
| 21 | px-nullifiers-commitments | The leaf-anchoring invariant (every leaf proven) and the anchor window are theirs; the binding argument is mine. Nullifier per-tree-version separation in the agility plan (§3.4) needs their review |
| 22, 24 | px-proof-system, plonky3-verifier-security | MMCS uses the same `TruncatedPermutation`; 2026/089 covers it. Plonky3 0.8 changes to `TruncatedPermutation` or the MMCS leaf hash must be re-checked against Thm 3 (for example, a leaf hash that is not an overwrite sponge) |
| 25 | zk-soundness | F10 (`COLLISION_BITS` 123 vs about 122.6) |
| 37 | wallet-keys | `key_domain` range reservation (item 3); the seed-to-`sk` domain `SK` |
| 40 | testnet-genesis | Item 2's empty-root vector is the genesis PX root; item 6 changes the fingerprint (before the freeze) |
| 43 | ci-reproducibility | `clippy.toml` (item 4) and the ELF-id reproduction after the comment edits |
| 46 | architecture | The registry doc placement; the typed `Tag` (item 7) |
| 47 | docs-spec-consistency | F1 and F6 overlap with the discrepancy list. I own the hash-related text; 47 should not edit the same paragraphs |
| 49 | innovation | The post-quantum and agility trigger responses (move away from arithmetization-oriented hashing) |
| 50 | red-team | The adversarial item 5 is a natural red-team regression |

---

## 7. Open questions for the coordinator and owner

1. **R2-C6.** Does the owner accept option A (keep; argument, guard and vectors) for
   v3, reversing D9's conditional "include"? If the owner prefers B, it must land
   before the neutral kernel rebuild, with the `n_fn = 1` budget choice (32,768 at
   94.7%, or accept 2^16).
2. **Item 4.** May a px-core attribute (`#[allow(clippy::disallowed_methods)]`) be added
   if reproduction proves the ELF id unchanged? Or should the lint be allowed at crate
   level?
3. **Item 6.** Should the Poseidon2 instance digest enter the consensus fingerprint now?
   It changes the published fingerprint value and must precede the freeze.
4. **Item 2's independent script.** Is Python acceptable as test tooling, given the
   pure-Rust rule applies to core components? Roster 40 already proposes a Python
   recompute.
5. **Monitoring owner** for the R2-C7 triggers (§3.4.4) after the phase ends.

---

## 8. Sources

- Coratger, Khovratovich, Mennink, Wagner. *The Billion Dollar Merkle Tree.* ePrint
  2026/089 (rev. 2026-07-22), ACM CCS 2026. Thms 1–3, §6 counterexample, App. C MMCS.
  https://eprint.iacr.org/2026/089
- Grassi, Khovratovich, Schofnegger. *Poseidon2: A Faster Version of the Poseidon Hash
  Function.* ePrint 2023/323, §3.1 (compression `Tr_n(P(x) + x)`, feed-forward "for
  one-wayness"), Eq. 1. https://eprint.iacr.org/2023/323
- Merz, Rodríguez García. *Skipping Class: Algebraic Attacks exploiting weak matrices
  and operation modes of Poseidon2(b).* ePrint 2026/306, Table 1 and §6.
  https://eprint.iacr.org/2026/306
- Bhati, Tariq, Ashur. *From Round Skipping to S-Box Skipping.* ePrint 2026/1692.
  https://eprint.iacr.org/2026/1692
- Jo. *Midpoint Reset: A Full-Round Poseidon Collision from an Adaptively Chosen MDS
  Matrix.* ePrint 2026/1760. https://eprint.iacr.org/2026/1760
- Bak, Hostettler. *A Better Bivariate Resultant Attack on Round-Reduced Poseidon.*
  ePrint 2026/1905. https://eprint.iacr.org/2026/1905
- *Claiming bounties on small scale Poseidon and Poseidon2 instances using
  resultant-based algebraic attacks.* ePrint 2026/150.
  https://eprint.iacr.org/2026/150
- Grassi, Koschatko, Rechberger. *Poseidon and Neptune: Gröbner Basis Cryptanalysis
  Exploiting Subspace Trails.* TOSC 2025 / ePrint 2025/954 (via R2).
  https://eprint.iacr.org/2025/954
- Poseidon Cryptanalysis Initiative, bounty status and the pause from 1 Aug 2026.
  https://www.poseidon-initiative.info/
- V. Buterin, X post, Feb 2026 (Poseidon2 "important security issues"; extra rounds or
  Poseidon1). https://x.com/VitalikButerin/status/2027405623189803453
- Secondary pointer only (the EF moving L1 hashing from Poseidon to SHA or BLAKE, Aug
  2026). https://postquantum.com/security-pqc/ethereum-roadmap-drops-poseidon/
- ProjectZKM Ziren issue #524 (a KoalaBear α = 3 round-count mismatch, Aug 2026).
  https://github.com/ProjectZKM/Ziren/issues/524
- Plonky3 0.7.0 source: `p3-baby-bear/src/poseidon2.rs` (R_F = 8, R_P = 13
  derivation, Grain constants), `p3-symmetric/src/compression.rs`
  (`TruncatedPermutation`). Local cargo registry.
- Daemen, Mennink, Van Assche. *Sound hashing modes of arbitrary functions,
  permutations, and block ciphers.* ToSC 2018 (cited in 2026/089 §1.2), as the
  minimal tree mode with domain bits.
- RFC 7693 (BLAKE2) and RFC 9496 (ristretto255): the v1 primitives (via R2).
- Zcash ZIP 209 (shielded pool turnstile), as the migration prior art.
  https://zips.z.cash/zip-0209
