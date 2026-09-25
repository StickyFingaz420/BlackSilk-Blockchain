# Version A (names BlackSilk). DRAFT, NOT SUBMITTED

**Title:** Deadlock: `spin::Mutex` in `HidingFriPcs` / `MerkleTreeHidingMmcs` held across rayon work

## Summary

With the `parallel` feature, proving with the hiding PCS can hang forever, with worker
threads spinning at 100% CPU and no progress. `HidingFriPcs` (`p3-fri`) and
`MerkleTreeHidingMmcs` (`p3-merkle-tree`) keep their randomness in a `spin::Mutex` and,
at three sites, hold it while rayon work runs. The same pattern in `Radix2DitParallel`'s
twiddle cache was fixed in 0.8.0 (`twiddle_cache.rs`: "A missing table is computed
outside the lock…"). These are the remaining instances.

## Affected components and versions

| Crate | File, function | 0.7.0 | 0.8.0 / `main` (checked 2026-09-25) |
|---|---|---|---|
| `p3-fri` | `hiding_pcs.rs`, `commit` | affected | affected |
| `p3-fri` | `hiding_pcs.rs`, `get_quotient_ldes` | affected | affected |
| `p3-merkle-tree` | `hiding_mmcs.rs`, `commit` | affected | affected |
| `p3-dft` | `radix_2_dit_parallel.rs`, twiddle caches | affected | fixed |

## Mechanism

1. A thread holding the lock enters a rayon operation (`par_iter`, `join`) and, while
   it waits for subtasks, executes other queued tasks.
2. If such a task, from another table, commitment or concurrent proof, needs the same
   lock, it spins forever on a lock held further up the same thread's stack.
3. With two locks, two threads can each hold one and spin on the other.
4. `spin::Mutex` never yields, so the result is full CPU use with no progress.

## The three sites (0.7.0 line numbers)

1. **`HidingFriPcs::commit`** (around line 121):
   ```rust
   let mut random_evaluation = mat.with_random_cols(
       mat_width + 2 * self.num_random_codewords,
       &mut *self.rng.lock(), // the guard lives to the end of the statement
   );
   ```
   `RowMajorMatrix::with_random_cols` copies rows with `par_rows_mut()` before drawing.
2. **`HidingFriPcs::get_quotient_ldes`** (around line 190): `let mut rng = self.rng.lock();`
   lives to the end of the function, across `with_random_cols` (parallel copy) and the
   per-chunk coset DFTs. The batch prover calls this for several tables inside a
   parallel loop.
3. **`MerkleTreeHidingMmcs::commit`** (around line 137): `let mut rng =
   self.rng.lock();` is still held when `self.inner.commit(salted_inputs)` builds the
   tree in parallel.

## Evidence (downstream: BlackSilk, Plonky3 0.7.0, `parallel`, Windows x86_64, 8 threads)

BlackSilk proves a batch STARK with lookups over about 12 tables, with the hiding PCS
and MMCS.
- **Before any fix:** sequential test runs hung in 3 of 3 runs, one of them for 4
  hours at full CPU. The span log placed the stall in a table's quotient step.
- **After fixing sites 2 (partly) and 3:** a full test-suite run with several proofs
  concurrently in one process hung for 2 hours, with 5 threads at 100%. The remaining
  sites were found by auditing every lock.

## Limitations of the diagnosis

- The hang depends on scheduling and could not be reproduced on demand afterwards: two
  full concurrent test runs and 80 concurrent proofs completed on the build without
  the later fixes.
- The diagnosis therefore rests on code analysis: each site holds a spin lock across
  rayon work, which is enough for the deadlock described.
- No stack trace was captured of the hung process.
- The independent upstream fix of the identical `p3-dft` pattern supports the
  analysis.

## Recommended remediation

Draw all random values while holding the lock, in the same order as today, and do
**no** parallel work under the lock.
- In `commit` and `get_quotient_ldes`: draw the random columns with
  `RowMajorMatrix::rand(&mut *rng, h, cols)`, which yields the same values row by
  row, then append them with a parallel copy after the lock is released.
- In `MerkleTreeHidingMmcs::commit`: end the lock's scope before
  `self.inner.commit`.

A patch against 0.7.0 is attached (`hiding-lock-scope.patch`). It applies cleanly to
the v0.7.0 tag; it would be ported to `main` in a pull request.

**Test results with the patch:**
- Plonky3's own suites pass for `p3-fri` (65 tests), `p3-merkle-tree` (99) and
  `p3-dft` (44), with and without parallelism;
- a new unit test, `widen_matches_with_random_cols`, shows the drawn values are
  identical to `with_random_cols` for the same RNG state, so proofs are unchanged for
  a seed;
- downstream, with the final patch: the full downstream test suite passes (396 tests, 0 failures), and 80 proofs running concurrently on 8 threads complete without a hang (909 s).

A regression test in the style of `miss_computes_without_holding_the_lock` could
assert that each site's lock is free during the parallel part.

## Impact

Liveness only: a prover can hang. Soundness and zero knowledge are unaffected, and
the proof bytes for a given RNG state are unchanged by the fix.
