# Freeze gate B2: prover memory of the V12 memory-widest pair, measured (2026-10-10)

Internal engineering evidence, not an audit. One run on one GitHub Actions runner.

The prover memory of the memory-widest two-function PX statement the V12 deploy caps
accept (record docs/reviews/v3-consensus-changes.md#px-deploy-row-caps, decision
"px-deploy-row-caps (V12)") had only been modelled at 10.4 to 13.1 GB
([budget-cap evidence](../budget-cap-2026-10-04/README.md)). This run proves and
verifies that statement once and records the prover's peak memory.

**Result: peak RSS 10,585 MiB, no swap used, no OOM, prover exit 0; the proof
(3,673,891 bytes) verifies. The measurement lies within the model range.** The
size-widest V12 shape is a different shape and is not measured (see "Limits").

## Run

| Item | Value |
|---|---|
| Run | <https://github.com/StickyFingaz420/BlackSilk-Blockchain/actions/runs/38007856183> (job `measure`) |
| Workflow | `.github/workflows/px-widest.yml` as of `1c2aed7` (manual dispatch) |
| Branch and commit | `gate/b2-v12-shape` at `1c2aed7` (on top of rebuild/core `05b2ef2`; it changes only `px/examples/freeze_b2_b3.rs` and the workflow; not merged into rebuild/core when this was written) |
| Inputs | `config=v12mem`, `count=1`, `swap=on` |
| Runner | `ubuntu-24.04` (image 20261004.327.1), 4 vCPU, MemTotal 15,988 MiB, 3 GiB swap file |
| Date | 2026-10-10 (UTC) |

## Method

The workflow builds the example in release mode and runs it three ways:

```
cargo build --locked --release -p blacksilk-px --example freeze_b2_b3
target/release/examples/freeze_b2_b3 b2 v12mem 0 out --check-only     # shape and admission, no proving
/usr/bin/time -v -o out/time.txt \
  target/release/examples/freeze_b2_b3 b2 v12mem 1 out                # prove and verify, one proof
```

- A guard step refuses a runner below 15,360 MiB (an OOM there would not measure
  `v12mem`) and refuses `count=0` for this shape.
- During proving a sampler logs, every 5 s, the system's used and available memory
  and swap, and the prover's `VmRSS`, `VmHWM` (peak RSS) and `VmSwap` from
  `/proc/<pid>/status`.
- The example proves one statement in one process, then verifies it three times; it
  asserts that verification returns `Ok` and that the proof decodes strictly, so a
  printed result line means a verified proof.
- The report step prints the shape, the `/usr/bin/time -v` output, the CSV row, the
  kernel's OOM messages (`dmesg`) and the memory samples.

The full log is fetched read-only with
`gh run view 38007856183 --repo StickyFingaz420/BlackSilk-Blockchain --log`; the
relevant lines are in [run-38007856183-excerpt.txt](run-38007856183-excerpt.txt).

## The shape (`v12mem`)

The kernel plus two padded vault functions, with every budget and every program table
at its V12 cap:

- **Budgets** (both functions): the V12 per-function maxima, cycles 32,768, keys 16,384,
  add 20,168, bit 7,192, lt 22,493, shift 7,367, mul 7,367, Poseidon2 948. The example
  checks both budgets and both programs against the V12 deploy rules, restated in the
  example (px cannot depend on tx; see "Limits").
- **Programs**: the vault programs padded to 15,292 and 15,291 code words, images of
  15,360 and 15,359 words, so each function's program, image and memory-init tables
  are at 2^14 and its CPU table at 2^15.
- **Shared tables** at their V12 heights: add 2^16, lt 2^16, bit 2^14, shift 2^14,
  mul 2^14, Poseidon2 2^11; byte and kernel CPU 2^16.
- **Function output tables** at the vault's 2^8. The caps allow 2^9, which adds about
  0.04 M weighted cells (under 0.1 % of the total), so the measured shape is the
  memory-widest vault-based pair up to that margin.
- Size: **68.5 M weighted cells** (the vault pair, the earlier measured base: 40.3 M);
  7 distinct heights, FRI schedule [1, 1, 1, 1, 1, 3, 3]. The example's schedule search
  (216 shared-table choices × 27 per function) finds no vault-based V12 pair with more
  FRI rounds among pairs whose budgets are at least the vault's own budget (each
  search range starts at `vault::BUDGET`, about 6 % above the vault's measured use).
  A deployable pair with smaller budgets that still fit the run could reach lower
  table heights and so possibly one more distinct height and FRI round; that case is
  not searched (open). The log line "no vault-based V12 pair has more FRI rounds"
  in the excerpt carries the same limit.

The table heights, widths and cells per table are in the excerpt (the "Shape and
admission" lines).

## Results

| Quantity | Value | Source |
|---|---|---|
| Peak RSS | **10,839,076 KB = 10,585 MiB** | `/usr/bin/time -v`, "Maximum resident set size" |
| Largest sampled `VmHWM` | 10,573 MiB | sampler (5 s period) |
| Swap | **0 MiB**: largest sampled `VmSwap` 0 MiB; `swap_used=0MiB` in every printed sample; time "Swaps: 0", 0 major page faults | sampler, `/usr/bin/time -v` |
| Lowest available memory | 4,466 MiB (of 15,988 MiB) | sampler, printed samples (the last 40 of 56, covering the peak) |
| OOM | none: prover exit 0, `dmesg` OOM check "none" | report step |
| Proof size | **3,673,891 bytes** (non-digest 3,316,109) | example result line, `b2.csv` |
| Proof budget | below the 3.8 MB budget (decision "Agent 22") and the 4 MiB `MAX_PROOF_BYTES` (4,194,304 bytes) | |
| Verification | passed (asserted `Ok`, strict decoding); 344.0 / 345.9 / 344.3 ms | example result line |
| Prove time | 278.6 s | example result line |
| Wall time | 4:39.79 (user 1,087 s, 390 % CPU) | `/usr/bin/time -v` |

## Comparison with the model

The memory model ([budget-cap evidence](../budget-cap-2026-10-04/README.md), "Memory
model") gives for this statement L = 10,413 MB (a linear fit on the measured n_fn = 0,
1, 2 peaks) and M = 13,064 MB (the pessimistic marginal). The measured peak, 10,585 MiB,
lies **within** the L–M range: 1.7 % above L if the model's unit is read as MiB, or
about 11,099 MB (6.6 % above L) if it is read as 10^6 bytes; within the range either
way, and about 2.5 GB (19 %) below M. The linear fit is therefore close for this shape,
and the pessimistic figure was not reached.

The proof size is consistent with the size model's figure for vault programs with
every table at most 2^16 (3,669,769 bytes expected, 3,737,539 bytes worst over the
query positions; same evidence, "Size model"); this is one draw of query positions.

What this supports: on a 16 GB machine of this class, the memory-widest vault-based V12
pair proves without swap and with about 4.4 GiB to spare, so the "16 GB proving class"
statement of px-deploy-row-caps holds for this shape.

## Limits

- **One run, one runner.** A single proof on one GitHub-hosted runner (4 vCPU,
  16 GB). Peak memory depends on the allocator, the thread count and the machine;
  other machines were not measured, and the 278.6 s prove time is this runner's.
- **Memory-widest, not size-widest.** The vault-based shape is the memory-widest V12
  shape, but not the size-widest. The size-widest V12 proof (about 3.70 MB expected,
  3.78 MB worst over the query positions, by model) needs non-vault programs: small
  program, image, cycles and keys tables with output tables at 2^9, which shift the
  FRI schedule. That shape was **not measured**, so B2's proof-size bound below
  3.8 MB remains a model.
- **The caps are restated.** The example restates the V12 caps (px cannot depend on
  tx) instead of calling `tx::px::budget_is_provable` and `program_is_provable`. The
  restatement is not yet pinned against the tx constants by a test across the crates;
  that is an open follow-up.
- **Output tables at 2^8.** The caps allow 2^9 for a function's output table; that adds
  about 0.04 M weighted cells, not measured but within the model's resolution.
- **The 8 GB class is unchanged.** 8 GB devices are still covered only for transfers,
  single calls and the vault pair (6.45 GB measured earlier), not for every
  two-function call.
- **Keys-cap observation.** Function 0 uses 15,618 of its 16,384 keys (its image of
  15,360 words plus 258 keys outside the image). A program whose image is exactly 2^14
  words therefore fits the keys cap only if it touches no key outside its image. That
  is a limit on what such a program can do, not a soundness or memory issue, and the
  deploy rule is unchanged.
- **The model's unit.** The model's figures are labelled MB; the measurement is in MiB.
  The verdict "within the range" holds under either reading (see above).
