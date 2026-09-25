# Draft upstream report for Plonky3 (not filed)

**Status:** draft, for the project owner to review and file. Nothing has been sent to
the Plonky3 maintainers.

**Channel.** Plonky3 publishes no security policy (no `SECURITY.md`). Its contribution
guide covers GitHub issues and pull requests. This is a liveness defect: no soundness
or zero-knowledge impact. So a public GitHub issue on `Plonky3/Plonky3`, optionally with
a pull request, is the appropriate channel.

**Status upstream (checked 2026-09-25 against the released 0.8.0 crates and `main`):**

| Site | 0.7.0 | 0.8.0 / `main` |
|---|---|---|
| `p3-dft` `Radix2DitParallel` twiddle caches | lock held across a parallel computation | **fixed** (`twiddle_cache.rs`: tables computed outside the lock) |
| `p3-fri` `HidingFriPcs::commit` | lock guard passed into `with_random_cols` (parallel row copy) | **not fixed** |
| `p3-fri` `HidingFriPcs::get_quotient_ldes` | lock held across the per-chunk DFTs | **not fixed** |
| `p3-merkle-tree` `MerkleTreeHidingMmcs::commit` | lock held across the parallel tree build | **not fixed** |

---

## Issue text

**Title:** Deadlock: `spin::Mutex` in `HidingFriPcs` / `MerkleTreeHidingMmcs` is held across rayon work

**Summary.** With the `parallel` feature, proving with the hiding PCS can hang forever,
with the worker threads spinning at 100% CPU. `HidingFriPcs` and
`MerkleTreeHidingMmcs` keep their randomness in a `spin::Mutex` and hold it while rayon
work runs. The same pattern in `Radix2DitParallel`'s twiddle cache was fixed in 0.8.0
(`twiddle_cache.rs`, "A missing table is computed outside the lock…"). These are
remaining instances of the same problem.

**Mechanism.**
1. A thread holding the lock blocks inside a rayon operation (`par_iter`, `join`)
   while waiting for its subtasks.
2. While waiting, rayon lets it execute other queued tasks.
3. If one of those tasks, from another table, commitment or proof, takes the same
   lock, it spins forever on a lock held further up the same thread's stack.
4. With two locks, two threads can each hold one and spin on the other.

`spin::Mutex` never yields, so the process shows full CPU use with no progress.

**Sites (0.8.0):**

1. `fri/src/hiding_pcs.rs`, `commit`:
   ```rust
   let mut random_evaluation = mat.with_random_cols(
       mat_width + 2 * self.num_random_codewords,
       &mut *self.rng.lock(),   // guard lives until the end of the statement
   );
   ```
   `RowMajorMatrix::with_random_cols` copies rows with `par_rows_mut()` before drawing,
   so the lock is held across rayon work.
2. `fri/src/hiding_pcs.rs`, `get_quotient_ldes`: `let mut rng = self.rng.lock();` is
   held until the end of the function, across the per-chunk coset DFTs. The caller
   invokes this for several tables inside a parallel loop.
3. `merkle-tree/src/hiding_mmcs.rs`, `commit`: `let mut rng = self.rng.lock();` is still
   held when `self.inner.commit(salted_inputs)` builds the tree in parallel.

**Observed.** Downstream (BlackSilk, Plonky3 0.7.0, `parallel`, Windows x86_64, 8
threads), in a batch STARK with lookups and several tables:
- sequential test runs hung in 3 of 3 runs before sites 2 and 3 were fixed; one of
  them spun for 4 hours;
- after those two were fixed, one full test-suite run with several proofs running
  concurrently in one process hung for 2 hours (5 threads at 100%), before sites 1 and
  the DFT cache were fixed.

The hang is scheduling-dependent and was not reproducible on demand afterwards
(two full concurrent test runs and 80 concurrent proofs passed on the unpatched
build), so the diagnosis rests on the code. The upstream DFT
fix describes the same mechanism.

**Proposed fix** (what BlackSilk applies as local patches):
- draw all random values while holding the lock, in the same order as today, and
  release the lock before any parallel work;
- in `commit`, draw the random columns with `RowMajorMatrix::rand(&mut *rng, h, cols)`
  (the same values, row by row), then widen the matrix outside the lock.

Proofs are unchanged for a given RNG state, since the draw order is preserved. We can
open a pull request with these changes and a regression test in the style of
`miss_computes_without_holding_the_lock`.

**Impact.** Liveness only: a prover can hang. Soundness and zero knowledge are
unaffected.

---

## For the owner: disclosure considerations (not part of the issue)

**What filing would reveal:**
- that a project named BlackSilk uses Plonky3 0.7's hiding (zero-knowledge) mode with
  the `parallel` feature, and runs several proofs concurrently;
- that its prover could hang before the local patches.

**What it would not reveal:** no vulnerability of BlackSilk itself.
- The hang is fixed locally.
- It was a liveness defect, with no effect on soundness, zero knowledge or funds.
- The issue text contains no keys, addresses, network details, parameters beyond
  what the public repository states, or user data.

**Risk:**
- **Low.** Anyone reading the (public) BlackSilk code already sees the Plonky3
  dependency and the patches in `third_party/`.
- The only practical exposure is attention: the report ties the name BlackSilk to the
  Plonky3 issue tracker.

**Options:**
1. File as written, naming BlackSilk (most useful to upstream: a real reproduction
   context).
2. File without naming the project: replace "Downstream (BlackSilk, …)" with
   "Downstream (a project using the hiding PCS, …)". The technical content is enough
   for the maintainers.
3. Send only the three code locations and the proposed fix as a pull request, with no
   observation details.

**Recommendation:** option 1 or 2.
- The issue affects every user of the hiding mode with `parallel`.
- Upstream has already accepted the same fix for `p3-dft`.
- Reporting shortens the time BlackSilk carries local patches.

Nothing has been sent.

## Local references

- AUDIT.md ZK-F11 and ZK-F21: evidence and verification.
- `third_party/README.md`: the patches, their scope and when to remove them.
- `zkvm/tests/stress.rs`: the concurrency stress test kept for upgrades.
