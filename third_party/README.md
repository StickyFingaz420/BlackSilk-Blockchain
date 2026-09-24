# Patched third-party crates

These are copies of published crates with a minimal, reviewed change, used through
`[patch.crates-io]` in the workspace `Cargo.toml`. Each entry records what changed, why,
and when to remove it.

## `p3-fri` 0.7.0 and `p3-merkle-tree` 0.7.0 (Plonky3): lock scope in the hiding commitments

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
the lock is released before any parallel work. No other line changes.
- Within each call, the values are drawn in the same order as upstream, and are used in
  the same way. Soundness and zero knowledge are unaffected.
- Upstream and patched alike, concurrent calls for different tables take the lock in a
  scheduling-dependent order. So proofs are **not** byte-reproducible from a seed. That
  is harmless for security (the randomness stays fresh and unpredictable), but no
  document may claim reproducible proof bytes.

**Diff against the published crates:**
- `p3-fri/src/hiding_pcs.rs`: `get_quotient_ldes`, one block.
- `p3-merkle-tree/src/hiding_mmcs.rs`: `commit`, one block.

`cargo`'s registry copies were taken verbatim (`.cargo_vcs_info.json` and
`Cargo.toml.orig` removed).

**Remove when:** upstream Plonky3 releases a fix. Then the exact pins move to that
version, after re-running the full test suite and the stress harness.

**To report upstream:** the maintainers have not been notified from here. The project
owner decides whether and how to report it.
