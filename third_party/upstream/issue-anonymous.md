# Version B (does not name the project). DRAFT, NOT SUBMITTED

**Title:** Possible deadlock: `spin::Mutex` in `HidingFriPcs` / `MerkleTreeHidingMmcs` held across rayon work

## Summary

With the `parallel` feature, `HidingFriPcs` (`p3-fri`) and `MerkleTreeHidingMmcs`
(`p3-merkle-tree`) keep their randomness in a `spin::Mutex`. At three sites they hold
that lock while rayon work runs. In a downstream project, proving with the hiding PCS
hung with worker threads spinning at 100% CPU. We believe these sites are the cause.

The same pattern in `Radix2DitParallel`'s twiddle cache was fixed in 0.8.0
(`twiddle_cache.rs`: "A missing table is computed outside the lock…"). These appear
to be the remaining instances.

## Affected components and versions

| Crate | File, function | 0.7.0 | 0.8.0 and `main` (as of 2026-09-25) |
|---|---|---|---|
| `p3-fri` | `hiding_pcs.rs`, `commit` | pattern present; hang observed (see "What was observed") | pattern present (code inspection only; not built or run) |
| `p3-fri` | `hiding_pcs.rs`, `get_quotient_ldes` | pattern present; hang observed | pattern present (code inspection only) |
| `p3-merkle-tree` | `hiding_mmcs.rs`, `commit` | pattern present | pattern present (code inspection only) |
| `p3-dft` | `radix_2_dit_parallel.rs`, twiddle caches | pattern present | fixed upstream |

"Pattern present" means a `spin` lock guard is alive while rayon work runs. It does not
mean a hang was observed at that site: see "What was observed".

## Mechanism (from the code)

1. A thread holding the lock enters a rayon operation (`par_iter`, `join`) and, while
   it waits for subtasks, executes other queued tasks (rayon work stealing).
2. If such a task (from another table, another commitment or a concurrent proof) needs
   the same lock, it spins on a lock held further up the same thread's stack.
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

## Environment

- Plonky3 0.7.0 (crates.io), feature `parallel`;
- `rayon` 1.12.0, `spin` 0.12.3;
- rustc 1.98.1 stable, `x86_64-pc-windows-msvc`, release profile;
- Windows 10, 8 logical CPUs, rayon's default thread pool;
- a batch STARK with lookups over about 12 tables, with `HidingFriPcs` and
  `MerkleTreeHidingMmcs`.

**Not tested:** Linux, macOS, other architectures, other thread counts, 0.8.0, `main`.

## What was observed

These are measurements, not guarantees.
- **Unmodified 0.7.0:** 3 of 3 runs of the downstream test suite, run sequentially,
  hung; one hung for 4 hours at full CPU. Instrumented logging placed the stall in the
  quotient step (`get_quotient_ldes`) of one table.
- **With `get_quotient_ldes` partly fixed and site 3 fixed:** one run of the full
  suite, with several proofs concurrently in one process, hung for 2 hours with 5
  threads at 100% CPU.
- **Site 1 and the `p3-dft` twiddle cache** were then found by auditing every lock,
  not by locating a stall in them.
- **After that hang, the build without the later fixes did not hang again:** 2 full
  concurrent suite runs and 80 concurrent proofs completed. The hang is
  scheduling-dependent and we could not reproduce it on demand.
- No stack trace or debugger dump of a hung process was captured.

## What is inferred, and what is not claimed

- **Inferred from the code:** each listed site holds a spin lock across rayon work.
  Together with work stealing, that is sufficient for the deadlock above. The upstream
  0.8.0 fix of the identical `p3-dft` pattern supports this reading.
- **Not claimed:**
  - that every hang observed was caused by one specific site;
  - that the listed sites are the only ones in Plonky3 (we audited the three crates
    above only);
  - that the patched code cannot deadlock. The runs without a hang (below) are
    consistent with the fix but do not prove it: hangs were rare before the fix too.

## Reproducing

There is no deterministic reproducer.
- **What exposed it here:** many multi-table hiding proofs at the same time in one
  process, with `parallel` enabled, repeated until one stalls. A stall shows as all
  rayon workers at 100% CPU with no progress for minutes.
- **A deterministic test would be better:** in the style of the existing
  `miss_computes_without_holding_the_lock`, a test could assert that each site's lock
  is free during its parallel part (for example with `try_lock` from inside a rayon
  task). We have not written one against upstream.

## Recommended remediation

Draw all random values while holding the lock, in the same order as today, and do
**no** parallel work under the lock.
- In `commit` and `get_quotient_ldes`: draw the random columns with
  `RowMajorMatrix::rand(&mut *rng, h, cols)`, which yields the same values row by
  row. Append them with a parallel copy after the lock is released.
- In `MerkleTreeHidingMmcs::commit`: end the lock's scope before
  `self.inner.commit`.

A patch against 0.7.0 is attached (`hiding-lock-scope-neutral.patch`). It applies
cleanly to the v0.7.0 tag. Its code comments are written as downstream notes; a pull
request would reword them and port the change to `main`. The port has not been done or
tested.

## Test results with the patch

**The attached patch on a clean v0.7.0 checkout** (tag `v0.7.0`, `fb93826`; the
patch touches only `p3-fri` and `p3-merkle-tree`; environment as above):

| Suite | Without `p3-maybe-rayon/parallel` | With it |
|---|---|---|
| `p3-fri` | 65 passed | 65 passed |
| `p3-merkle-tree` | 99 passed (1 doc test ignored, as upstream) | 99 passed |

- The patch adds a unit test, `widen_matches_with_random_cols`. It shows that the
  patched code builds exactly the matrix that `with_random_cols` builds from the same
  RNG state, so the values drawn and their order are unchanged.
- **Not claimed:** that proof bytes are reproducible. In multi-table proofs the order in
  which tables draw randomness depends on scheduling, before and after the patch.
- **Downstream** (the patch **plus** a backport of the 0.8.0 `p3-dft` twiddle-cache
  fix, which is not part of the attached patch): the downstream test suite passes, and
  80 proofs running concurrently on 8 threads completed without a hang (909 s). **No
  hang observed; this is not proof that none can occur.**
- `p3-dft` is not in the patch because 0.8.0 already fixed that site upstream.

## Impact

- **Liveness:** a prover can hang indefinitely.
- **Soundness and zero knowledge:** a hang produces no proof, so it cannot produce an
  invalid one. The patch only moves where the lock is released, and the unit test above
  shows the drawn randomness is unchanged. We did not analyse other effects beyond
  that.

## Classification of every claim in this report

| Claim | Class |
|---|---|
| The three sites hold a `spin` lock guard while rayon work runs (0.7.0) | **Observed** in the source |
| The same pattern is present at the three sites in 0.8.0 and `main` | **Observed** in the source only; not built or run |
| Work stealing plus a spin lock held across rayon work can deadlock | **Inferred** from the code and rayon's documented behaviour |
| The downstream hangs (3 of 3 sequential runs; one concurrent run for 2 hours) | **Observed** |
| The hangs were caused by these sites | **Inferred**: the stall was located in `get_quotient_ldes` by logging; the other sites by code audit. No stack trace |
| The patch prevents the deadlock | **Inferred** from the code. No hang in later runs, but the hang was never reproducible on demand, so this is unverified by experiment |
| The patch does not change the values drawn | **Observed** (the unit test) |
| The suites pass with the patch on v0.7.0 | **Observed** (the table above) |
| Soundness and zero knowledge are unaffected | **Inferred**: a hang yields no proof, and the drawn values are unchanged. Not otherwise analysed |
| Behaviour on platforms other than Windows x86_64 | **Unverified** |
