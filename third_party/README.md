# Patched third-party crates

These are copies of published crates with a minimal, reviewed change, used through
`[patch.crates-io]` in the workspace `Cargo.toml`. Each entry records what changed, why,
and when to remove it.

## CI check: published crate + allow-listed diff (RT-PXDET finding 1, RT-TPGATE, RT-TPGATE2)

`.github/scripts/third-party-gate.sh` (CI job `gates`) checks every crate directory
here (a directory with a `Cargo.toml`) against what it claims to be:
- `PRISTINE.sha256` pins the sha256 of each published `<name>-<version>.crate`. Each
  value is the checksum `Cargo.lock` carried before the crate was patched (git history)
  and was re-checked against the static.crates.io download on 2026-10-04.
- The gate takes that `.crate` from the local cargo cache or static.crates.io, verifies
  the pin, unpacks it and runs `diff -a -ruN --strip-trailing-cr` against the copy
  here. `-a` (text mode) keeps a NUL byte from turning a file into an opaque "Binary
  files differ" line. The documented packaging differences are dropped first, at the
  top level only: `Cargo.toml.orig`, `.cargo_vcs_info.json` and `Cargo.lock` on the
  published side, and cargo's unpack marker `.cargo-ok` (`{"v":1}`) on ours. Any
  other added, removed or changed file shows up in the diff.
- That diff, with CRs stripped and timestamps removed, must equal
  `patches/<crate>.patch` byte for byte (CRs stripped from it too). On a mismatch the
  gate names the crate and the first differing file.
- `patches/<crate>.sha256` lists the sha256, mode and path of every tracked file of
  the crate, hashed from the committed (index) bytes. It pins what the diff
  normalizes: line endings, data files and file modes. The crate's working tree must
  equal the index (nothing modified or untracked).
- Escape lint, a reviewer aid and not a guarantee:
  - no "Binary files" line in a patch, and no added or changed `build.rs`;
  - no added line with an `include*!` macro (spaces allowed), a `path` attribute or
    `path =` key, a `..` path segment, or a `build`, `proc-macro` or `links` key.
  - Code can still reach outside the diff in ways no regular expression sees (a
    `concat!` of path pieces, for example). Review is what catches those.
  - No current patch trips the lint.
- Control bytes: every tracked file under `third_party/` (patches and pins included)
  must be free of NUL and the other control bytes (DEL too) except TAB, LF and CR. With a NUL
  in its first 8,000 bytes, git and GitHub show a file and its patch only as "Bin".
  - The exceptions are the files named in `BINARY-ALLOWLIST`, each with its reason;
    adding one is a reviewed change.
  - An allow-listed file must be unchanged from the published crate, or its bytes
    reach the patch file, which may not contain them.
  - `.gitattributes` sets `third_party/** diff`, so every change shows as text.
- Stale entries fail: a patch, manifest, pin or binary entry without its file.
- Dependency identity, by `tools/tpgate` (Rust, built from this checkout; it uses
  only crates already in `Cargo.lock` and fails closed on anything it cannot parse):
  - It runs `cargo metadata --no-deps --offline` for every tracked `Cargo.lock`'s
    workspace (root, `fuzz/`, `contracts/`, `contracts/fuzz/`, `zkvm/guests/`). That
    gives cargo's own list of members and their declared dependencies, with renames
    and paths. It also parses each `Cargo.lock` as TOML.
  - No member is named like a crate here.
  - Every path dependency is one of: a member (of any workspace), a standalone crate
    in the gate's `STANDALONE` list (today `zkvm/sdk`, which may have no
    dependencies), or `third_party/<its own name>`.
  - No crate here is aliased by a rename.
  - Every source is crates.io.
  - Every sourceless `Cargo.lock` entry is a member or a crate here.
  - No workspace locks a patched version from the registry.
  - The gate sets `RUSTUP_TOOLCHAIN` (default `stable`; CI uses 1.98.1), so
    `zkvm/guests`' pinned toolchain is never installed for this.
- Cargo files: in every tracked `Cargo.toml` and `.cargo/config[.toml]`, no table or
  key starting with `patch`, `replace`, `paths` or `source` (configs also
  `registries`, `registry`), however quoted, spaced or dotted. The only exception is
  a workspace root's exact `[patch.crates-io]`, whose entries must each be
  `<name> = { path = "<to root>third_party/<name>" }`.
- `--selftest` runs tampered fixtures and expects each to fail. It also expects
  clean fixtures to pass, and an allow-listed binary file to pass the byte check.
  The tampered fixtures:
  - edits: an edit, a CRLF conversion, a mode change, an allow-listed NUL file
    edited again;
  - files: added, removed, untracked or unstaged files, a re-added packaging file;
  - allow-list: a wrong pin, a missing or stale patch or manifest, a stale binary
    entry;
  - control bytes in a source file, a patch file or the README;
  - lint: `include_str!` and `include_str !`, a `cfg_attr` path, a `".."`, an added
    `build.rs`, a `build =` key;
  - identity: a git source, another registry, an unknown path crate, a registry copy
    of a patched crate, a member named like a patched crate (written without
    spaces), a renamed path copy, a path dependency outside every workspace;
  - cargo files: the `[patch]`, `[replace]`, `paths` and `[source]` spellings above.
  - `tools/tpgate` has its own unit tests
    (`cargo test -p blacksilk-tpgate`).

The patch files apply with `patch -p1` inside an unpacked published crate. To
change a patched crate: make the change and stage it (`git add`), then run
`bash .github/scripts/third-party-gate.sh --write <crate>`, which rewrites
`patches/<crate>.patch` and `patches/<crate>.sha256`. Review both like any other
code change. Adding a crate here needs, in the same commit:
- its `PRISTINE.sha256` line (from `Cargo.lock` before the switch, or the registry
  index);
- its patch and manifest;
- its `[patch.crates-io]` line in every workspace that locks it.

The lockfile gate (`.github/scripts/lockfile-gate.sh`) separately requires a commit
that moves a crate in any tracked `Cargo.lock` to another source or checksum
to name that crate.

**What this does not prove.** The allow-list certifies itself: a commit can change
a crate here and regenerate its patch and manifest in the same commit, and the gate
passes. The gate makes such a change exact and visible, nothing more. The control is
human review of every `third_party/` diff (a consensus path: `consensus-gate.sh`
requires a `Consensus-Change:` trailer). Required review of these paths
(CODEOWNERS plus branch protection) is a repository setting for the owner.

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
- Upstream and patched alike, concurrent calls for different tables take the lock in a
  scheduling-dependent order. So proofs are **not** byte-reproducible from a seed. That
  is harmless for security (the randomness stays fresh and unpredictable), but no
  document may claim reproducible proof bytes.

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

**Diff against the published crates** (since 2026-10-04 checked on every CI run;
the exact diffs are `patches/p3-fri.patch`, `patches/p3-merkle-tree.patch` and
`patches/p3-dft.patch`; first re-checked 2026-09-27 with
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
