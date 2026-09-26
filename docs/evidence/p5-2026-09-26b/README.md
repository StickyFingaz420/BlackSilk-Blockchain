# Evidence: proof-length campaign for privacy review P-5, Option A (2026-09-26)

This re-runs the campaign of `../p5-2026-09-26/` on the final Option A configuration:
- BS-ZK-2 with 4 random codewords;
- terminal blinding;
- minimum height 2^8;
- the round-4 fixes (AUDIT.md R13).

The proof system is the same as in `../p5-2026-09-26/`; this run confirms it on the
build that is being committed.

**Setup:**
- Windows 10, 8 logical CPUs, release build;
- the working tree on top of `b4262e1`, committed with this evidence;
- 13,493 s;
- the local testnet rehearsal ran part of the time, which affects time, not lengths.

**Reproduce:**

```sh
cargo run --release -p blacksilk-px --example proof_length_campaign -- 50 30 proof_lengths.csv
```

| Shape | Class | n | Mean bytes | sd | Min | Max |
|---|---|---|---|---|---|---|
| transfer | deposit | 50 | 2,179,093 | 5,255 | 2,164,978 | 2,190,610 |
| transfer | pay2 | 50 | 2,179,372 | 4,947 | 2,169,010 | 2,190,610 |
| transfer | pay1 | 50 | 2,178,966 | 4,835 | 2,165,170 | 2,189,426 |
| transfer | withdraw | 50 | 2,177,855 | 4,400 | 2,167,698 | 2,186,034 |
| vault | lock | 30 | 2,688,368 | 3,515 | 2,682,608 | 2,696,528 |
| vault | claim | 30 | 2,689,750 | 3,762 | 2,682,928 | 2,698,096 |

**Non-authentication parts:** byte-identical within each shape, as asserted by the
tool. They are **1,811,565 B** (transfer) and **2,359,622 B** (vault), the same as in
`../p5-2026-09-26/`.

**Pairwise permutation tests** (20,000 relabellings; 7 pairs × 2 statistics = 14
tests):
- p(mean) ranges from 0.107 to 0.898;
- p(KS) ranges from 0.172 to 0.965.
- The smallest are pay2 vs withdraw (p(mean) = 0.107) and lock vs claim
  (p(mean) = 0.148).

**Interpretation:**
- No test is significant. The multiple-comparison threshold is 0.05/14 ≈ 0.0036.
- The previous campaign's lowest p (0.071, lock vs claim KS) is 0.282 here. This is
  consistent with that value having been chance.
- With 30–50 proofs per class only large effects would be detected
  (privacy-review.md §3a).
- The variation comes only from pruned Merkle paths.

Files:
- `proof_lengths.csv`: one row per proof, with the shape, class, index, total bytes,
  authentication bytes and other bytes;
- `campaign-output.txt`.
