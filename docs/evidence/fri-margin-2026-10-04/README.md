# FRI margin before the freeze: queries or grinding (2026-10-04)

Internal study behind decision "BS-ZK-4" and record
docs/reviews/v3-consensus-changes.md#bs-zk-4. Read-only arithmetic; no proof was built
for it. Not an audit.

## Method

Same formulas as `zk/tests/soundness_calc.rs` (`udr()`): unique decoding, per-query
bits −log2(1 − δ) with δ = (1 − ρ⁺)/2, ρ⁺ = (k + 2)/n; total = queries × bits +
grinding; the mixed-height union term subtracts log2(H). Proof-size factors from
docs/reviews/aggregation-study.md §1 (about 92 % of a proof scales linearly with the
query count, so about +0.85 % per query), applied to the golden PX fixture and to the
widest measured proof of record W28-3 (3,629,639 B).

## Facts used

- Per query: 0.829449 bits at the smallest committed height (degree bits 9), 0.830075
  at the largest (23). 108 queries give 89.58 statistical bits at the worst point.
- The floor `MIN_PROVEN_BITS` (100) is checked against total bits, grinding included;
  docs/zk.md §9.3 counts at most 20 bits of grinding.
- Hard ceiling: eq. 17 (`zk/src/params.rs`), 2·(q + 8·2) ≤ 2^MIN_LOG_HEIGHT = 256, so
  q ≤ 112. 116 or 120 queries need `MIN_LOG_HEIGHT` 9 (ceiling 240), which pads every
  table to at least 512 rows (a circuit-envelope change).

## Options (bits at the worst point; the term at H = 32, 23 and 15)

| q | grinding | statistical | total | −log2 32 | −log2 23 | −log2 15 |
|---|---|---|---|---|---|---|
| 108 | 16 | 89.58 | 105.58 | 100.58 | 101.06 | 101.67 |
| **108** | **20** | **89.58** | **109.58** | **104.58** | **105.06** | **105.67** |
| 110 | 16 | 91.24 | 107.24 | 102.24 | 102.72 | 103.33 |
| 112 | 16 | 92.90 | 108.90 | 103.90 | 104.37 | 104.99 |
| 112 | 20 | 92.90 | 112.90 | 107.90 | 108.37 | 108.99 |
| 116 | 16 | 96.22 | 112.22 | 107.22 | 107.69 | 108.31 |
| 120 | 16 | 99.53 | 115.53 | 110.53 | 111.01 | 111.63 |

The calculator now charges H = 33 (log2 33 = 5.04): 108 queries and 20 bits give
104.54 at the worst point.

## Proof size of the query options (estimates)

| q | size factor | golden fixture | widest measured (W28-3) | headroom to 4 MiB | headroom to 3.8 MB |
|---|---|---|---|---|---|
| 108 | 1 | as measured | 3,629,639 B | 15.6 % | 4.7 % |
| 112 | 1.0341 | 2,491,079 B | 3,753,316 B | 11.7 % | 1.2 % |
| 116 | 1.0681 | 2,573,164 B | 3,876,992 B | 8.2 % | −2.0 % |
| 120 | 1.1022 | 2,655,248 B | 4,000,669 B | 4.8 % | −5.0 % |

Headroom is (bound − widest) / widest.

Raising grinding costs no expected proof size (the witness is one field element at any
bit count). It costs the prover about 2^20 instead of 2^16 Poseidon2 permutations per
proof (measured for BS-ZK-4: 1.32 s mean, record item 11).

## Literature checked

- Zhang et al., "Fast RS-IOP Multivariate Polynomial Commitments and Verifiable Secret
  Sharing", USENIX Security 2024: Protocol 1 ("rolling batch FRI") and Theorem 3.1
  (proof in their Appendix C). Fold arity 2; a new lower-degree polynomial is rolled
  in each round with the square of the folding challenge (as Plonky3's β^arity for
  arity 2); unique-decoding regime; error |L0|/|F| + ((1 + ρ)/2)^q + negligible terms.
  The query term has no factor in the number of rolled-in polynomials.
- Differences from Plonky3 0.7.0's construction: arity up to 16, skipped heights,
  DEEP-batched inputs, hiding codewords and the mask `R`, a final polynomial of 64
  coefficients, ρ⁺ instead of ρ, and Fiat–Shamir (Block et al., ePrint 2023/1071). So
  it is a close analogue, not a theorem for this construction; the union term is kept.
- No 2024–2026 ePrint was found that analyses Plonky3's multi-height roll-in.
