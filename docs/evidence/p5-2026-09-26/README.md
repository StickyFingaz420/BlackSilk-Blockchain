# Evidence: proof-length campaign for privacy review P-5, blinded layout (2026-09-26)

A re-run of the 2026-09-25 campaign (`../p5-2026-09-25/`) after terminal blinding
and the minimum height of 2^8 (AUDIT.md R12; docs/reviews/terminal-blinding.md).

**Setup:**
- Windows 10, 8 logical CPUs, release build, commit `dfa82bf`.
- The run shared the machine with an internal review and a full test run, which
  affects time, not lengths.
- 14,997 s.

**Reproduce:**

```sh
cargo run --release -p blacksilk-px --example proof_length_campaign -- 50 30 proof_lengths.csv
```

| Shape | Class | n | Mean bytes | sd | Min | Max |
|---|---|---|---|---|---|---|
| transfer | deposit | 50 | 2,178,951 | 4,139 | 2,166,482 | 2,187,122 |
| transfer | pay2 | 50 | 2,178,622 | 4,296 | 2,167,250 | 2,185,778 |
| transfer | pay1 | 50 | 2,178,465 | 4,654 | 2,170,642 | 2,188,786 |
| transfer | withdraw | 50 | 2,179,352 | 4,353 | 2,167,410 | 2,186,898 |
| vault | lock | 30 | 2,687,868 | 3,990 | 2,675,888 | 2,695,600 |
| vault | claim | 30 | 2,688,960 | 3,750 | 2,680,784 | 2,696,176 |

**Non-authentication parts:** byte-identical within each shape (asserted by the
tool): **1,811,565 B** (transfer) and **2,359,622 B** (vault).

**Pairwise permutation tests** (20,000 relabellings), 7 pairs × 2 statistics = 14
tests:
- p(mean) ranges from 0.286 to 0.866;
- p(KS) ranges from 0.071 to 0.864.

The two smallest are:
- lock vs claim, KS: p = 0.071;
- pay1 vs withdraw, KS: p = 0.083.

**Interpretation:**
- No test is significant. The smallest p among 14 tests is expected near 1/15 ≈ 0.067
  by chance alone, and the multiple-comparison threshold is 0.05/14 ≈ 0.0036.
- These p-values are **lower than the previous campaign's** (all ≥ 0.49). That is
  compatible with chance, but not evidence of independence either. With 30–50 proofs
  per class, only large effects would be detected.
- A larger campaign would narrow this (privacy-review.md §3a "What would increase
  confidence").

Files: `proof_lengths.csv` (one row per proof: shape, class, index, total,
authentication bytes, other bytes) and `campaign-output.txt`.
