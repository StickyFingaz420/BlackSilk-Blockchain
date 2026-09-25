# Upstream report for Plonky3: two drafts for the owner (NOT SUBMITTED)

**Status:** drafts for the project owner's decision. Nothing has been sent to the
Plonky3 maintainers. The owner decides whether to file, and which version.

## Files

| File | Content |
|---|---|
| `upstream/issue-named.md` | **Version A:** the issue text, naming BlackSilk as the downstream project |
| `upstream/issue-anonymous.md` | **Version B:** the same text without the project's name |
| `upstream/hiding-lock-scope.patch` | The fix as applied here (comments reference BlackSilk's AUDIT.md) |
| `upstream/hiding-lock-scope-neutral.patch` | The same code with project references removed from the comments |

Both patches apply cleanly to Plonky3's v0.7.0 tag (checked with `git apply --check`).
They were not tried against `main`: a pull request would port them, and reword the
comments, which are written as downstream notes.

## What the drafts contain

- **The three affected sites**, all still present in 0.8.0:
  1. `HidingFriPcs::commit`;
  2. `HidingFriPcs::get_quotient_ldes`;
  3. `MerkleTreeHidingMmcs::commit`.

  Each holds a `spin::Mutex` across rayon work.
- **The fourth, `p3-dft` site,** already fixed upstream in 0.8.0, which confirms the
  mechanism.
- **Technical evidence:**
  - the observed hangs;
  - the code analysis;
  - upstream's own tests passing with the patch (208 tests: `p3-fri` 65,
    `p3-merkle-tree` 99, `p3-dft` 44), including a new equivalence test;
  - the downstream results with the final patch.
- **Limitations of the diagnosis:**
  - not reproducible on demand;
  - no stack trace;
  - the analysis rests on the code.
- **Recommended remediation, and the impact:** liveness only; soundness and zero
  knowledge are unaffected.

## Channel

Plonky3 publishes no security policy (no `SECURITY.md`). Its contribution guide
covers GitHub issues and pull requests. The defect has no soundness or
zero-knowledge impact, so a public GitHub issue on `Plonky3/Plonky3`, optionally
followed by a pull request, is the appropriate channel. No embargo is needed.

## For the owner: disclosure considerations (not part of either draft)

**What Version A reveals:**
- that a project named BlackSilk uses Plonky3 0.7's hiding (zero-knowledge) mode with
  `parallel` and runs several proofs concurrently;
- that its prover could hang before the local patches.

**What Version B reveals:** only that *some* downstream project hit the bug. The
platform details (Windows, 8 threads) and the approximate table count remain; they
identify little on their own.

**What neither reveals:** any vulnerability of BlackSilk. The hang is fixed locally,
it was a liveness defect, and no key, address, network detail or user data is in the
text.

**Risk:**
- **Low for both.** BlackSilk's public repository already shows the Plonky3
  dependency and the patches in `third_party/`, so Version A adds attention rather
  than information.
- Version B avoids linking the name to the issue tracker, at the cost of less context
  for the maintainers.

**Recommendation:** Version B if avoiding attention matters; otherwise Version A.
Either one:
- helps every user of the hiding mode;
- matches the fix upstream already accepted for `p3-dft`;
- shortens the time BlackSilk carries local patches.

## Before filing

1. Done: the downstream results with the final patch are in both drafts (the full
   suite, 396 tests; 80 concurrent proofs, no hang).
2. The owner chooses a version and files it; nothing is filed from here.
