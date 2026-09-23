# PX-0 measurements (2026-09-23)

**Setup:**
- Machine: the labnet machine (Windows 10, 8 threads).
- Libraries: Plonky3 0.7.0, with `p3-uni-stark` using the `parallel` feature.
- Every proof below is zero-knowledge:
  - `HidingFriPcs` with 4 random codewords;
  - `MerkleTreeHidingMmcs` with 4 salt elements;
  - standard Poseidon2 constants (BabyBear width 16, Goldilocks width 8) for Merkle
    hashing and Fiat–Shamir.
- Security bits come from `p3-security` 0.7.0:
  - "UD" is the unique-decoding regime (no list-decoding theorem needed);
  - "LD" is the Johnson-bound regime (BCI+20 / BCSS25).
- Instance shape used for the bits: 500 constraints, degree 3, 300 batched columns.

## 1. Provable security (no conjectures)

| Configuration | Best UD bits | Best LD bits | Note |
|---|---|---|---|
| BabyBear, degree-4 extension, any blow-up, ≤ 200 queries | 97 (n = 2^16), 91 (n = 2^22) | 86 | **Never reaches 100 provable bits:** rejected |
| BabyBear, degree-5 extension, blow-up 8, 128 queries, 16-bit grinding | 121 | 108 | |
| BabyBear, degree-5 extension, blow-up 32, 50 queries | 47 | 105 | Johnson regime only |
| Goldilocks, degree-5 extension, blow-up 4, 160 queries, 16-bit grinding | 124 | 124 | Capped by the 124-bit digest collision bound |

In the unique-decoding regime each query adds about 1 bit, so ≥ 100 bits needs about
110–128 queries whatever the blow-up.

## 2. Proof sizes and times

| Circuit | Parameters | Prove | Verify | Proof |
|---|---|---|---|---|
| 128 Poseidon2 permutations (wide AIR) | BabyBear^5, blow-up 8, 128 queries | 0.08–0.11 s | 18–29 ms | 293–324 KB |
| 4 096 Poseidon2 permutations | BabyBear^5, blow-up 8, 128 queries | 1.6 s | 25 ms | 414–502 KB |
| 4 096 Poseidon2 permutations | Goldilocks^5, blow-up 4, 160 queries | 0.9 s | 36 ms | 764 KB |
| Narrow AIR, width 20, 2^12 rows | BabyBear^5, blow-up 8, 128 queries | 0.9 s | 27 ms | 259–272 KB |
| Narrow AIR, width 20, 2^16 rows | same | 11 s | 40 ms | 380–389 KB |
| Narrow AIR, width 60, 2^16 rows | same | 13 s | 41 ms | 405–412 KB |
| Narrow AIR, width 20, 2^20 rows | same | 207–239 s | 39–64 ms | 521–534 KB |
| Narrow AIR, width 20, 2^12 rows | **Johnson regime:** BabyBear^5, blow-up 32, 50 queries | 3.0 s | 11 ms | **130 KB** |
| Narrow AIR, width 20, 2^16 rows | Johnson regime | 43 s | 16 ms | **183 KB** |

**Conclusion:** proof size is dominated by Merkle authentication paths (queries × FRI
layers × log n), not by circuit width.
- At ≥ 100 unique-decoding bits, proofs are 260–550 KB.
- At ≥ 100 Johnson-bound bits, they are 130–230 KB.

## 3. Candidate stacks

| Stack | Result |
|---|---|
| Plonky3 0.7 (uni-/batch-STARK, LogUp, hiding FRI, `p3-security`) | Suitable. The proof logic crates have almost no `unsafe`; the field crates' `unsafe` is mostly in SIMD paths; one Least Authority audit on file (version unspecified). The README warns that the verifier may panic on malformed proofs. |
| Winterfell 0.13 | **Cannot be unpacked on Windows** (the file `aux.rs` is a reserved name): rejected |
| Stwo 2.3 | No hiding / zero-knowledge mode: rejected |
| SP1 | Core STARK proofs are not zero-knowledge; it relies on a trusted-setup SNARK wrap: rejected |
| RISC Zero | C++ kernels (not pure Rust): rejected |
| Halo2 (zcash, 0.3.5) | Pure Rust, 1 `unsafe`, audited and deployed in Zcash Orchard; small proofs; **not post-quantum sound** |

**Findings to carry into the design:**
- Plonky3's hiding needs a CSPRNG seed for each proof; its tests use fixed seeds.
- On x86-64, Goldilocks uses inline assembly in its reduction; BabyBear's scalar path
  does not.
- On aarch64, the field crates' NEON code (which uses inline assembly) is enabled by
  default.
- Our release profile uses `panic = "abort"`, which would turn a verifier panic into a
  node crash.
