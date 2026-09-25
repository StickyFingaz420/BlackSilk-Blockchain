# Evidence: proof-length campaign for privacy review P-5 (2026-09-25)

**Machine:** Windows 10, 8 logical CPUs, release build. Plonky3 0.7.0 with the
patches of `third_party/`, before the ZK-F28 fix. That fix changes only lock scope,
and the drawn values are proven identical by `widen_matches_with_random_cols`, so the
proof layout is unaffected.

**Reproduce:**

```sh
cargo run --release -p blacksilk-px --example proof_length_campaign -- 50 30 proof_lengths.csv
```

| File | Content |
|---|---|
| `proof_lengths.csv` | One row per proof: shape, class, index, total bytes, Merkle-authentication bytes, all other bytes. Two `# shape` marker lines at the end |
| `campaign-output.txt` | The tool's summary: per-class statistics, and permutation tests on the mean and on the Kolmogorov–Smirnov statistic |

**Classes:**
- transfer shape: `deposit`, `pay2`, `pay1`, `withdraw`, 50 proofs each;
- vault shape: `lock`, `claim`, 30 proofs each.

The seeds are fixed, so a re-run reproduces the witnesses. Proof bytes differ between
runs, because the hiding randomness is drawn in a scheduling-dependent order.

**Interpretation:** docs/reviews/privacy-review.md §3a.
