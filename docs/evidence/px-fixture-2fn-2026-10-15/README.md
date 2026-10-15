# Two-function PX fixture: generation, determinism, verification and tamper sweep (2026-10-15)

This is internal engineering evidence, not an audit. Everything here was run on one
Windows machine. The cross-machine check (CI) is listed under "Not done".

Step 5(C) of the freeze-gate plan adds the PX fixture that was still missing: a proven
transaction with two vault functions. The golden fixture `node/src/px_fixture.bin` has
no functions, so it has no function tables, no function prefixes and no window
binding (STATUS §5, TM2-2 / F2). The new fixture is pinned by tests only, not by the
consensus manifest (decisions, "Two-function PX fixture: test-pinned, CI regenerates
and compares hashes, never commits").

**Results**

- Two local generations gave byte-identical files: one with `RAYON_NUM_THREADS=1` and
  one with the default 8 threads.
- A regeneration of the golden transfer fixture from today's code reproduced the
  committed files byte for byte.
- Every verify-only test passes on the committed fixture.
- The full tamper sweep ran 53,069 cases. No case verifies, and each one is refused
  with the class its field implies.
- Six scratch mutants each drop or weaken one binding in `px/src/prove.rs`. Every one
  of them makes a test fail.

## Fixture

| Item | Value |
|---|---|
| Files | `node/tests/fixtures/px_fixture_2fn.bin` (3,634,307 bytes), `node/tests/fixtures/px_fixture_2fn.txt` (713 bytes) |
| SHA-256 `.bin` | `d0553badda419bd821cbc4371d4e3c41cc24f012adc7c52b57db2f78c92f6ef1` |
| SHA-256 `.txt` | `6a7ed2fbbc49f421c774099aa3eb3d37ff36d30719273c136d6adfe13023e247` |
| Pinned in | `node/tests/px_fixture_2fn.rs` (`PINNED_BIN_SHA256`, `PINNED_TXT_SHA256`, and the byte-for-byte round-trip test) |
| Generated from | the uncommitted tree later committed as `7206d64` (branch `tests/px-fixture-two-function`, on rebuild/core `1d0f102`); it differed from `1d0f102` only in test files, so the release build ran with `BLACKSILK_ALLOW_DIRTY=1`; no prover, verifier or builder code differs |
| Toolchain | rustc 1.98.1, release, Windows 10, Intel i7-6700 (4 cores, 8 threads), 16 GB |

Shape:

- **Functions.** `n_fn = 2`: function 0 is vault CLAIM, function 1 is vault LOCK. Both
  are the reference vault program under the contract of the golden deploy (its one
  registration; budget `vault::BUDGET`, ABI 1, one output word). The outputs are
  `[CLAIM]` and `[LOCK]`.
- **CLAIM.** It spends a vault record worth 400,000,000 (kernel input 0) and pays it to
  a user record (output 0).
- **LOCK.** It locks 300,000,000, bridged in from v1, into a new vault record
  (output 1).
- **v1 side.** One input: the fingerprint fixture's coinbase output 0 with the fixture
  transfer's first ring. The fee is `PX_STANDARD_FEE`.
- **Validity window.** `[0, 200]` (fixture height + 100). It is bounded, so the
  functions' prefixes carry it.
- **Chain state.** This is synthetic, built in `node/tests/support/px_fixture_2fn.rs`:
  - a PX tree holding exactly the claimed record (the `.txt`'s `record` line); its
    root is the anchor;
  - no spent nullifier;
  - a pool equal to the record's value;
  - the golden deploy's registration.
- **Shared key image.** The v1 input is the same output as the golden PX
  transaction's input, so the two share a key image. Each fixture is validated on its
  own chain view, so this does not matter for the tests, but the two transactions
  cannot both be in one block.

## Generation and determinism (PXDET), local

```text
cargo test --release -p blacksilk-node --test px_fixture_2fn --no-run
# run 1: writes node/tests/fixtures/
RAYON_NUM_THREADS=1  px_fixture_2fn-<hash>.exe --ignored --exact regenerate_the_two_function_px_fixture --nocapture --test-threads=1
# run 2: default thread count, into a temporary directory
PX_FIXTURE_OUT=<tmp> px_fixture_2fn-<hash>.exe --ignored --exact regenerate_the_two_function_px_fixture --nocapture --test-threads=1
cmp <both files>   # identical
```

Before each run the machine was otherwise idle, and available memory was checked
first (`\Memory\Available MBytes`: 10,353 and 10,453). Peak memory is the test
process's `PeakWorkingSet64`, polled every 500 ms (the value is the OS's running
peak).

| Run | Threads | `build_px` (proving included) | `validate_px` | Wall | Peak working set |
|---|---|---|---|---|---|
| 1 | 1 | 409.3 s | 395 ms | 410.2 s | 6,444 MiB |
| 2 | 8 (default) | 103.8 s | 415 ms | 104.5 s | 6,446 MiB |

Both runs printed the hashes above, and `cmp` found no difference.

The golden transfer fixture was also regenerated from the same tree into a temporary
directory: 55.6 s and 3,621 MiB peak. `PX_FIXTURE_OUT` is a test-only addition to its
generator. Its `.bin` and `.txt` are byte-identical to the committed files
(`git show 1d0f102:node/src/px_fixture.bin | sha256sum`, and the same for `.txt`). The
generator-path commits since `ee0e96f` therefore did not change its bytes on this
machine.

## Verify-only tests (`node/tests/px_fixture_2fn.rs`)

All six tests pass. The full test binary takes 2.0 s wall and peaks at 33 MiB.

| Test | What it checks |
|---|---|
| `sha256_matches_known_answers` | The test-local SHA-256 (no new dependency) on FIPS 180-4 vectors, the empty message and a 64-byte message |
| `the_two_function_fixture_is_pinned_and_round_trips_byte_for_byte` | The files' SHA-256 equal the pins; the decoded transaction re-encodes to the `.bin`; the record re-renders the `.txt` |
| `the_two_function_fixture_has_its_shape` | Two functions of the golden registration, outputs `[CLAIM]` and `[LOCK]`, the program id equal to `vault.id`, budget, ABI, out words, the window, fee and bridge amounts, the ring; anchor = root of the one-record tree; nullifier 0 = the record's contract nullifier |
| `the_two_function_transaction_is_valid_in_its_window_only` | `validate_px` returns `Ok` at h (341 ms, PX5 included); without PX5 it returns `Ok` at `not_after` = 200; at 201 it returns `PxWindow`, with and without PX5 |
| `the_proof_binds_both_functions_and_the_window` | `prove::verify`, called with the arguments `check_px_proof_decoded` passes, with one input changed per case (results in the next table) |
| `the_node_refuses_an_unregistered_function_and_an_unknown_anchor` | Another `program_id` for function 1 gives `PxUnregistered { function: 1 }` (with and without PX5); another anchor gives `PxUnknownAnchor` |

Refusals of `prove::verify` on the committed proof. The variant is the `ZkError`
variant from its `Debug` text, which is how the tamper sweep classifies it too.

| Case | Result | Time |
|---|---|---|
| Control | `Ok` | 318.8 / 319.0 / 346.2 ms (three runs) |
| Calls swapped | `Proof(Invalid(..))` | 47.6 ms |
| `outputs[1][0]` = CLAIM | `Proof(Invalid(..))` | not timed |
| ABI + 1 on function 0, and on function 1 | `Proof(Invalid(..))` | not timed |
| Kernel program in place of function 1's | `Unregistered(1)` | no proof check |
| Registry that knows only the first call | `Unregistered(1)` | no proof check |
| Window `(0, 0)` with the same `h_tx` | `Proof(Invalid(..))` | 34.9 ms |
| Window `(0, 201)` with the same `h_tx` | `Proof(Invalid(..))` | 47.9 ms |
| Window `(1, 200)` with the same `h_tx` | `Proof(Invalid(..))` | 35.3 ms |
| `verify_transfer` on the same proof | `Shape` | - |

The `Invalid` refusals are fast because a changed statement moves the transcript. The
first check that depends on the transcript, the query grinding witness, then fails:
the mutant runs below printed `Invalid("Verification(InvalidOpeningArgument(InvalidPowWitness))")`.

For the transfer fixture, another window with the same `h_tx` verifies
(`px_tamper.rs`, `known_non_binding`). Here, with functions, every function prefix
carries the window, so the statement binds it.

## Tamper sweep (`node/tests/px_tamper.rs`)

The sweep uses the same layout map, targets and classes as for the transfer fixture.
The two-function statement side adds:

- every function-slot word: a contract word is expected `Unregistered` (no program is
  registered to that contract); an `io_hash` word is expected `Invalid`;
- the 4 window words;
- each call's first output word;
- each call's ABI.

| Run | Cases | Result | Time | Peak |
|---|---|---|---|---|
| Layout map, two-function proof | 23 instances | The regions re-encode the proof exactly; every field has a value region | - | - |
| Smoke subset (with the suite, also through `check_px_proof`) | 80 | Decode 30, Invalid 46, Shape 3, Unregistered 1; none verifies | 8.2 s | - |
| Full sweep (`full_two_function_px_proof_tamper_sweep`) | 53,069 | Decode 49,786, Invalid 3,243, Shape 24, Unregistered 16; **none verifies**, every case gets its expected class | 437 s (7.3 min) | 95 MiB |
| Full sweep, transfer fixture (rerun, regression check) | 32,210 | Unchanged: Decode 29,584, Invalid 2,612, Shape 14 | 265 s | 61 MiB |
| `known_non_binding_two_function` | - | Window variants give `Invalid` (bound); without the range proof or the signatures, PX5 gives `Ok` (prunable part) and full validation refuses the transaction | - | - |

- 3,283 of the 53,069 cases (6.2 %) reach the verifier call; the rest are decode
  refusals.
- 78 input-opening row widths re-parse into another well-formed proof and are refused
  by verification (the transfer fixture had 37).
- The first full run stopped on an assertion in the sweep itself, not a finding: the
  input-opening row count had been read as a one-byte varint, and a query of the
  two-function proof opens 128 or more matrices, so its count is two bytes. The count
  is now decoded as a LEB128 varint, and the rerun above passed.
- Each case flips one bit, so the sweep has the same limits as the transfer sweep (the
  module docs of `px_tamper.rs`).

## Non-vacuity (scratch mutants)

These ran in a separate scratch worktree at `7206d64` with its own target directory.
Each mutant edits `px/src/prove.rs`, rebuilds the release test binary and runs the
verify-only tests; the file is restored afterwards. None of these changes was
committed.

| Mutant | Change | Result |
|---|---|---|
| M1 ABI not bound | `statement`: `function_prefix(ABI_VERSION, ..)` instead of `call.abi` | **Killed**: "abi + 1 on function 0" verifies. A discriminating mutant: the control still verifies |
| M2 window start dropped | `statement`: prefix window `(0, window.not_after)` | **Killed**: window `(1, 200)` verifies. Discriminating |
| M3 window not in the prefix | `statement`: prefix window `Window::UNBOUNDED` | **Killed**, through the control (`Invalid`) and `validate_px` (`PxProof`). The proof carries the bounded window, so no verifier change can drop it without failing the control |
| M4 outputs not extended | `statement`: the call outputs left out of the expected output | **Killed**, through the control and `validate_px`. As for M3 |
| M5 unregistered call borrows a budget | `verify` and `check_shape_bits`: `None` uses the first call's budget instead of `Unregistered(k)` | **Killed**: the kernel-program case gives `Proof(Invalid(..))` instead of `Unregistered(1)` |
| M6 call position not bound | `statement`: calls sorted by outputs (descending) before pairing | **Killed**: the swapped calls verify. Discriminating |

- **Outputs test.** The "outputs[1][0] changed" test is killed only through the
  control (M4). No verifier change can ignore the outputs and still accept the honest
  proof.
- **Not run.** cargo-mutants over `statement` and `function_prefix` was optional and
  was not run.

## Not done

- **Cross-machine determinism (CI).** `.github/workflows/px-fixture.yml` is committed,
  but it could not be dispatched. GitHub dispatches only workflows that exist on the
  default branch (`rebuild/core`):
  `gh workflow run px-fixture.yml --ref tests/px-fixture-two-function` answered
  `HTTP 404: workflow px-fixture.yml not found on the default branch`. The workflow
  can run once it is on `rebuild/core`, and the branch's fixtures can then be checked
  with `--ref`. Until then, determinism is shown on one machine at two thread counts
  only.
- **Golden fixture status.** The transfer fixture's regeneration is reproduced locally
  (above), not in CI. It stays consensus-pinned, and the manual workflow only compares
  it.
