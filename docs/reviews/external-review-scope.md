# Scope of a future independent security review (reference only)

Status: **kept for future reference (2026-09-25). No external reviewer is engaged and
none is currently planned** (docs/reviews/review-status.md). No part of BlackSilk's
own code has been independently reviewed. Everything in `docs/reviews/` and AUDIT.md is internal
analysis and testing. This document tells an external reviewer what to review, what
evidence exists, and which questions matter most. It also separates what has had
outside scrutiny from what rests on internal work only.

## 0. Status labels

| Label | Meaning |
|---|---|
| **Independently reviewed** | Reviewed by a party outside the project |
| **Public scrutiny (upstream)** | A published standard, paper or widely used library, not reviewed *as used here* |
| **Internal only** | Analysed and tested within the project; no outside review |

## 1. Summary

| # | Area | Status | Priority |
|---|---|---|---|
| 1 | Poseidon2 and the `Hk` constructions | Poseidon2 itself: public scrutiny. Our instance and constructions: **internal only** | Critical |
| 2 | Plonky3 as configured (STARK, hiding mode, lookups, transcript) and the three local patches | Plonky3: public code, **no audit verified**. Our configuration and patches: **internal only** | Critical |
| 3 | BVM-1 zkVM circuits (AIR tables, buses, fixed shapes) | **Internal only** | Critical |
| 4 | PX kernel statement (`px-core/src/kernel.rs`) and the function binding | **Internal only** | Critical |
| 5 | PX consensus rules (PX1–PX5, fee, registry, pool, block budget, mempool cache) | **Internal only** | Critical |
| 6 | Record delivery (hybrid ECDH and ML-KEM combiner) and contract-record distribution | ML-KEM, ChaCha20-Poly1305, Ristretto: public scrutiny. The combiner as built: **internal only** | High |
| 7 | Metadata and privacy leakage (all channels, including P-5 proof length) | **Internal only** | High |
| 8 | Wallet PX and contract code (keys, anchors, selection, delivery, recovery), submission handling and ring reuse (W-1 to W-5) | **Internal only** | Medium |
| 9 | K4: the provisional reorganization-depth policy (no limit, no checkpoints, warn at 10) and PX state under deep reorganizations | **Internal only** | High |

## 2. Areas in detail

### 2.1 Poseidon2 and `Hk` (critical)
- **Files:** `px-core/src/hash.rs`, `zk/src/config.rs`, `zk/tests/pins.rs`; docs/px.md §2.
- **Claims to verify:**
  - the width-16 BabyBear instance with Plonky3's default constants gives about 124
    bits of collision and preimage resistance;
  - the sponge's domain and length separation, and its separation from the tree-node
    compression, are sound;
  - no extra rounds are needed (decision DR-4).
- **Internal evidence:**
  - known-answer pin of the permutation;
  - reference-sponge equality tests;
  - the separation argument in px.md §2.
- **Open question for the reviewer:** is the round count adequate against current
  algebraic attacks on 31-bit fields?

### 2.2 Plonky3 and the proof system (critical)
- **Files:** `zk/src/*`, `zk/tests/*`, `third_party/` (three patched files); docs/zk.md
  §9, docs/reviews/zk-security-review.md, docs/reviews/query-policy.md.
- **Claims to verify:**
  1. knowledge soundness at BS-ZK-2: ≥ 123 bits (Johnson) and ≥ 105 (unique decoding)
     over the shape envelope, as computed by our calculator;
  2. **zero knowledge of the hiding mode** (`HidingFriPcs`, `MerkleTreeHidingMmcs`),
     including whether 4 random codewords and 4 salt elements suffice;
  3. the Fiat–Shamir transcript: domain separation (`PARAMS_ID`), and the statement
     digest absorbed before any commitment (ZK-F13);
  4. the LogUp bound (63% of p);
  5. the three lock-scope patches change nothing but lock scope.
- **Internal evidence:**
  - mutation tests (231,120 ALU; 37,616 CPU and memory; 2,500 Poseidon2; 180
    public-copy);
  - 402 proof-byte mutations;
  - upstream's own suites pass with the patches (207 tests).
- **Not verified:** any audit of Plonky3 itself.

### 2.3 BVM-1 circuits (critical)
- **Files:** `zkvm/src/air/*`, `zkvm/src/prove.rs`, `zkvm/tests/*`; docs/zkvm.md.
- **Claims to verify:**
  - the AIR constrains exactly the interpreter's semantics: every instruction, memory
    consistency, the syscalls, public tables as periodic columns with constrained
    copies;
  - budgets fix the shape.
- **Internal evidence:**
  - the mutation tests;
  - 20,000 random programs satisfying every constraint;
  - a differential test of interpreter against constraints;
  - coverage-guided fuzzing of the loader.

### 2.4 Kernel and function binding (critical)
- **Files:** `px-core/src/kernel.rs`, `px-core/src/call.rs`, `px-core/src/record.rs`,
  `px/src/prove.rs`; docs/px.md §3, §4, §7.
- **Claims to verify:**
  - the statement of px.md §4.1: ownership, membership, nullifiers, balance over
    `u128`, dummies;
  - the contract rules of §7.2;
  - the `io_hash` binding between function and kernel;
  - that `rho` and nullifier uniqueness prevent Faerie Gold.
- **Internal evidence:**
  - 20 plain and 12 contract rejection cases, identical natively and in the guest;
  - differential fuzzing (20,000 seeded; coverage-guided `kernel_diff`).

### 2.5 PX consensus (critical)
- **Files:** `tx/src/px.rs`, `tx/src/validate.rs`, `tx/src/state.rs`,
  `chain/src/mempool.rs`, `chain/src/manager.rs`, `p2p/src/net.rs`; docs/px.md §11.
- **Claims to verify:**
  - PX1–PX5;
  - the exact fee;
  - the registry (contract ids unique; entries immutable);
  - the containment pool never goes below zero;
  - exact per-block undo;
  - the block-level proof cache is sound (the transaction id commits to the proof);
  - peer scoring of PX failures;
  - relay limits.
- **Internal evidence:** `tx/tests/px_consensus.rs`, the adversarial transaction tests,
  the p2p tests, and the fuzzing of transaction and block decoding.

### 2.6 Delivery and record distribution (high)
- **Files:** `px/src/delivery.rs`, `px/src/share.rs`, `wallet/src/px.rs`; docs/px.md
  §6, §13.
- **Claims to verify:**
  - the combiner `H32(ss_ec ‖ ss_kem ‖ R ‖ ct_kem ‖ cm)` gives IND-CCA if either
    Ristretto ECDH or ML-KEM-768 holds (X-Wing-style);
  - a nonce of zero is safe because every key is fresh;
  - acceptance by recomputing the commitment stops probes and kind confusion;
  - shares add no weakness.
- **Internal evidence:**
  - the delivery tests (7);
  - coverage-guided `delivery_open` fuzzing.

### 2.7 Metadata and privacy (high)
- **Files:** docs/reviews/privacy-review.md (every channel; P-1 to P-8; §3a on proof
  length).
- **Claims to verify:**
  - fixed shapes and a uniform fee;
  - canonical anchors;
  - wallet scanning reveals nothing to the node;
  - Dandelion++ for PX;
  - **P-5: proof-length variation carries no witness information** (supported by
    measurement and reasoning; the key item for outside confirmation).

### 2.8 Wallet (medium)
- **Files:** `wallet/src/px.rs`, `wallet/src/wallet.rs`.
- **Claims to verify:**
  - key derivation and separation from the v1 keys;
  - blinds from a CSPRNG (R-6);
  - no secret in logs or errors;
  - reorganization handling;
  - encrypted persistence;
  - submission handling: inputs are never spent again with new rings while an
    earlier spend may be public; stored rings are reused (docs/reviews/wallet-review.md
    W-1 to W-5).

### 2.9 Reorganization-depth policy K4 (high)
- **Files:** `chain/src/manager.rs` (`sync_state`), `tx/src/state.rs` (`undo_block`),
  docs/consensus.md §8, docs/reviews/k4-reorg-policy.md.
- **Questions:** k4-reorg-policy.md §6. Is the provisional testnet policy acceptable,
  is PX state undone correctly at any depth, and what should mainnet adopt?

## 3. What has had outside scrutiny (not as used here)

| Component | Scrutiny |
|---|---|
| Poseidon2 permutation design | Published (Grassi, Khovratovich, Schofnegger 2023); ongoing public cryptanalysis |
| ML-KEM-768 | FIPS 203 standard. The RustCrypto `ml-kem` 0.3.2 implementation is unaudited as far as we know |
| ChaCha20-Poly1305, BLAKE2 | Standards; RustCrypto implementations widely used |
| curve25519-dalek | Widely deployed; its audit history is not claimed here |
| Plonky3 | One published audit: Least Authority for Polygon, completed 2024-07-18, updated 2024-11-07. Its scope is described as "a non-hiding STARK protocol" (https://leastauthority.com/blog/audit-of-plonky3/, read 2026-09-25). So **the hiding (zero-knowledge) mode this project relies on, including `HidingFriPcs` and `MerkleTreeHidingMmcs`, has no published audit.** The pinned 0.7.0 is also about two years newer than the audited code. Security advisories: docs/reviews/dependency-review.md §5a |
| Poseidon2 over 31-bit fields | Public cryptanalysis exists (for example ePrint 2023/537, 2026/306); no published result specific to BabyBear width 16 was found (2026-09-25). The Ethereum Foundation's Poseidon Cryptanalysis Initiative targets 31-bit, width-16 instances (KoalaBear) |
| RandomX | Published algorithm; our Rust implementation is internal (AUDIT.md R1) |

## 4. Deliverables requested from the reviewer

1. Findings with severity, reproduction and suggested fixes, per area.
2. An explicit opinion on the critical claims: soundness, zero knowledge, kernel
   statement, consensus rules.
3. An opinion on P-5, and on whether the query policy (docs/reviews/query-policy.md)
   is adequate.
4. A statement of what was *not* covered.

## 5. Proceeding without it

The owner may decide to run the controlled seven-machine testnet before the external
review. If so, that decision and its consequences must be recorded:
- the testnet shows operation, not security;
- no production use and no real value;
- every "internal only" claim above stays unconfirmed.
