# Patched third-party crates

These are copies of published crates with a minimal, reviewed change, used through
`[patch.crates-io]` in the workspace `Cargo.toml`. Each entry records what changed, why,
and when to remove it.

## `p3-batch-stark` 0.7.0 (Plonky3): quotient randomness drawn in scheduling order (PXDET-1)

**Upstream behaviour:** `prove_batch` (`p3-batch-stark/src/prover.rs`) computes every
instance's quotient inside a rayon `into_par_iter` loop, and calls
`HidingFriPcs::get_quotient_ldes` from inside that loop. Under zero knowledge that call
draws the quotient chunks' hiding randomness from the PCS's one shared RNG. Which
instance takes the RNG first, and so which values each instance gets, followed thread
scheduling.

**Effect:** the quotient commitment differed between two runs with the same witness
and seeded RNG, and so did every later Fiat–Shamir challenge and the FRI query
positions. The pruned Merkle paths depend on the query positions, so the proof
**length** varied as well as its bytes.
- Measured before the patch (`zkvm/tests/reproducible.rs`, 8 threads): two in-process
  proofs of one tiny program from one seed were 2,325,370 and 2,327,386 bytes. The
  first difference was at byte 69, the first byte of the quotient commitment (version,
  main cap and permutation cap make up bytes 0–68).
- With `RAYON_NUM_THREADS=1`, the same test passed.

**Change:** the quotient values are still computed in parallel per instance. The
`get_quotient_ldes` calls then run sequentially, in instance order (one block in
`prove_batch`). The LDEs stay parallel inside the DFT.
- Each instance draws the same values, in the same order, that upstream draws for it
  on a single thread. Evidence: the patched prover at the default thread count gives
  the same proof digest as the unpatched prover with `RAYON_NUM_THREADS=1`.
- The verifier is untouched, and the proof format and its distribution are unchanged.
  Soundness and zero knowledge are unaffected.
- No measurable slowdown: 18.0–18.4 s per zkvm test proof before and after, three runs
  each, on the development machine.

**Evidence after the patch (2026-10-04, branch `pxdet`, Windows, MSVC):**
- `zkvm/tests/reproducible.rs` passes (several in-process proofs from one seed are
  identical).
- The same proof's digest was identical across processes at 2, 3 and the default number
  of threads.
- The golden PX fixture generator (`node/tests/px_fixture.rs`) ran twice, once at the
  default thread count and once with 3 threads. Both runs gave sha256 `75357ff4…`
  (2,408,643 bytes), and the verdict check passed both times.
- Not yet tested: identity across operating systems and CPU architectures. Field
  arithmetic is exact, so no difference is expected, but none has been measured.

**Remove when:** upstream makes the quotient randomness order-independent.

## `p3-fri`, `p3-merkle-tree` and `p3-dft` 0.7.0 (Plonky3): spin locks held across parallel work

**Upstream bug (found here, AUDIT.md ZK-F11): the prover can hang forever.**
- `HidingFriPcs::get_quotient_ldes` (`p3-fri/src/hiding_pcs.rs`) takes the PCS
  randomness lock, a `spin::Mutex`, and holds it across the parallel coset DFTs.
- `p3-batch-stark` calls this function for several tables inside a rayon parallel
  loop.
- A rayon thread that holds the lock and waits inside the DFT can steal another
  table's task. That task then spins on the lock held further up the same thread's
  stack: a livelock that burns CPU with no progress.
- `MerkleTreeHidingMmcs::commit` (`p3-merkle-tree/src/hiding_mmcs.rs`) held its lock
  across the parallel tree construction in the same way.

**Evidence:**
- A multi-execution proof (kernel and one function) hung in 3 of 3 sequential test runs
  on this machine.
- The span log showed the stall inside table 4's quotient step, after the quotient
  polynomial, with ~4 cores busy.
- With the patch: see AUDIT.md ZK-F11 for the stress-test result.

**Change:** in both functions, the random values are drawn while the lock is held, and
the lock is released before any parallel work. (This first round changed nothing
else; the later rounds below add more. The complete list of differences from the
published crates is under "Diff against the published crates".)
- Within each call, the values are drawn in the same order as upstream, and are used in
  the same way. Soundness and zero knowledge are unaffected.
- Upstream (and this patch alone), concurrent calls for different tables take the lock
  in a scheduling-dependent order, so proofs were not byte-reproducible from a seed. The
  `p3-batch-stark` patch below (PXDET-1) removes that: the calls are now made in
  instance order.

**Second round (AUDIT.md ZK-F21): two more sites of the same bug.** Found when the
full test suite ran the unified-proof tests concurrently: five threads spun at 100% for
two hours, while each test alone passed in about a minute.
- `HidingFriPcs::commit` passed its lock guard into `p3-matrix`'s `with_random_cols`,
  whose row copy is parallel (`par_rows_mut`). So the lock was held across rayon work.
- `p3-dft`'s `Radix2DitParallel` (the DFT this project uses) computed its twiddle
  tables under the write lock of a `spin::RwLock`. The computation is itself parallel
  (`Powers::collect_n` resolves to `BoundedPowers::collect`, which splits across
  threads from 1,024 elements). The twiddle caches of the other DFTs were checked:
  - `Radix2DFTSmallBatch`, used by the FRI prover, already computes outside the lock;
  - `Radix2Dit` and the monty-31 DFT are not used.
- **Fix:** in `commit`, the random columns are drawn under the lock (same values, same
  order as `with_random_cols`); the matrix is widened after the lock is released. In
  `Radix2DitParallel`, each table is computed first and then inserted under the write
  lock. On a miss, two threads may compute the same deterministic table, and the first
  insert wins.

**Third round (AUDIT.md ZK-F28): the ZK-F11 fix was incomplete.** Inside its locked
block, `get_quotient_ldes` still called `with_random_cols`, whose row copy is
parallel. Now the random columns are drawn sequentially under the lock (the same
values in the same order), and a shared helper `widen` builds the widened matrices
after the lock is released. A unit test (`widen_matches_with_random_cols`) shows the
result is identical to `with_random_cols` for the same RNG state. Every `lock()` in
the three patched crates now does sequential work only.

**Diff against the published crates** (re-checked 2026-09-27 with
`diff -r --strip-trailing-cr` against the registry's 0.7.0 copies; only these three
source files differ, apart from upstream's `Cargo.lock`, `.cargo_vcs_info.json` and
`Cargo.toml.orig`, which were removed):
- `p3-fri/src/hiding_pcs.rs`: `get_quotient_ldes` and `commit`, one block each (the
  `get_quotient_ldes` block also moves upstream's comment on the random values and
  drops the unwidened matrices early, to keep peak memory as upstream); the `widen`
  helper and its unit test; the `p3_maybe_rayon` prelude and `Field` imports.
- `p3-merkle-tree/src/hiding_mmcs.rs`: `commit`, one block.
- `p3-dft/src/radix_2_dit_parallel.rs`: `get_or_compute_twiddles`,
  `get_or_compute_coset_twiddles` and `get_or_compute_inverse_twiddles`, one block
  each.
- `p3-batch-stark/src/prover.rs` (PXDET-1, 2026-10-04, `diff -r --strip-trailing-cr`
  against the registry copy): `prove_batch`, one block. The parallel per-instance loop
  now returns the quotient chunks, and a sequential loop computes their LDEs. The first
  loop's type annotation changed to match.

- `p3-fri/src/hiding_pcs.rs` also has a **test-only** addition (2026-09-26, internal
  review round 3): `randomization_polynomial_spans_the_extension_at_each_table_height`
  checks that the FRI mask `R` has exactly `NUM_RANDOM_CODEWORDS` + the extension
  degree columns and one matrix at each table height, under upstream's test
  configuration (2 codewords, degree-4 extension). It changes no library code.
  `third_party` is outside the workspace, so this test (like upstream's suites) runs
  only in the manual upstream checkout described below, not in our suite or CI.

`cargo`'s registry copies were taken verbatim (`.cargo_vcs_info.json` and
`Cargo.toml.orig` removed).

**Remove when:** upstream Plonky3 releases a fix for each site (for `p3-dft`, 0.8.0
already has one; see below). Then the exact pins move to that version, after
re-running the full test suite and `zkvm/tests/stress.rs`.

**Tested against upstream's own suites (2026-09-25):**
- the three patched files were applied to the v0.7.0 release commit (`fb93826`), whose
  sources equal the crates.io copies;
- `cargo test` passes for `p3-dft` (44 tests), `p3-merkle-tree` (99) and `p3-fri`
  (65, including the equivalence test added with ZK-F28), with and without rayon
  parallelism.

**Upstream status (checked 2026-09-25, released 0.8.0 and `main`):**
- **`p3-dft`: fixed upstream in 0.8.0.** The new `twiddle_cache.rs` computes tables
  outside the lock, with a comment describing the same mechanism and a test
  (`miss_computes_without_holding_the_lock`). That independently confirms the
  diagnosis. This patch can go on the upgrade to 0.8.0.
- **`p3-fri` and `p3-merkle-tree`: not fixed.** 0.8.0 still holds the lock in all
  three places.

**To report upstream:** a ready-to-file issue is drafted in `UPSTREAM-REPORT.md`
(public GitHub issue; Plonky3 has no security policy, and this is a liveness defect).
It has not been filed: the project owner decides.
