# PX deploy budget caps: size and memory model (2026-10-04)

Internal study behind decision "px-deploy-row-caps (V12)" and record
docs/reviews/v3-consensus-changes.md#px-deploy-row-caps. Base: the freeze-gate B2/B3
evidence of commit `914b74f` (docs/evidence/freeze-b2-b3-2026-10-04 on rebuild/core).
No proof was built for this study; it is a model calibrated on measured proofs. Not an
audit.

## Size model

The B2 size model (`px/examples/freeze_b2_b3.rs` of `914b74f`) restated with the exact
expectation over query positions instead of 4,000 draws, calibrated on the measured
non-digest bytes of two measured configurations. Validation against the harness: the
widest vault-program result 4,094,185 B (exact), any programs 4,125,167 B (harness
4,125,175), worst cases 4,199,575 and 4,242,995 B (exact); the base set 3,631,957 B
against the measured P-5 mean 3,631,326 B.

Widest proof against a uniform table-height cap (expected / worst over the query
positions; standard deviation 4–8 KB):

| Cap | Vault programs | Any programs |
|---|---|---|
| 2^16 | 3,669,769 / 3,737,539 | 3,700,750 / 3,780,959 |
| 2^17 | 3,731,864 / 3,805,905 | 3,762,846 / 3,849,325 |
| 2^18 | 3,797,416 / 3,877,727 | 3,828,398 / 3,921,147 |
| 2^19 | 3,866,424 / 3,953,005 | 3,897,406 / 3,996,425 |
| 2^20 | 3,938,888 / 4,031,739 | 3,969,870 / 4,075,159 |
| 2^21 | 4,014,809 / 4,113,929 | 4,045,790 / 4,157,349 |
| 2^22 (R7-5) | 4,094,185 / 4,199,575 | 4,125,167 / 4,242,995 |

Only 2^16 keeps even the worst case below 3.8 MB for any programs; each extra level
adds about 62–76 KB.

## Memory model

Weighted cells of a table = rows × (main width + 8 × quotient chunks + 24); widths and
chunk counts from `px/tests/proof_limits.rs`. Lookup columns are not counted (absorbed
by the fit).

- L: a linear fit on the three measured statements n_fn = 0, 1, 2 (3,622, 4,339 and
  6,446 MB peak): 755 MB + 141.1 MB per million cells, residuals ≤ 18 MB.
- H: L plus a term in the tallest table, fitted to the measured coarse18 point
  (≥ 10,280 MB); equal to L when the tallest table is 2^16.
- M: the marginal of coarse18 over the base statement, 235 MB per million cells
  (pessimistic).

Memory-widest two-function statement (every field at its cap):

| Scheme | Million cells | Memory (L / M) |
|---|---|---|
| R7-5 (before V12) | 6,801.8 | about 961 GB / 1.6 TB |
| uniform 2^16 | 167.1 | 24.3 / 36.2 GB |
| V12 (chosen) | 68.5 | 10.4 / 13.1 GB |
| V10 | 52.5 | 8.2 / 9.3 GB |
| V8 (the vault-pair heights) | 40.3 | 6.45 GB (the measured point) |

## Per-field schemes

| Scheme | Per-function maxima (add, bit, lt, shift, mul, Poseidon2, keys, cycles) | Widest proof |
|---|---|---|
| uniform 2^16 | 20,168; 31,768; 22,493; 31,943; 31,943; 32,692; 65,536; 65,536 | 3.70 / 3.78 MB |
| **V12** | **20,168; 7,192; 22,493; 7,367; 7,367; 948; 16,384; 32,768** | **3.70 / 3.78 MB** |
| V10 | 20,168; 3,096; 22,493; 3,271; 3,271; 436; 8,192; 16,384 | 3.70 / 3.78 MB |
| V8 | 20,168; 1,048; 6,109; 1,223; 1,223; 52; 4,096; 8,192 | 3.67 / 3.74 MB |

The vault fits every scheme. V12's shared-table caps (log2): add 16, lt 16, bit 14,
shift 14, mul 14, Poseidon2 11, with `kernel_budget(MAX_FN)` reserved; a function's own
tables: cycles 2^15, keys 2^14, program and image 2^14.

## Limits of this evidence

- The memory figures are a model: the memory-widest V12 pair has not been proven.
- The size model's worst case is over the query positions in the model, not a proven
  bound; `MAX_PROOF_BYTES` (4 MiB) is the consensus limit either way.
