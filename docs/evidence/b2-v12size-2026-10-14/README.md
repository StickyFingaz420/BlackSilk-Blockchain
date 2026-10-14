# Freeze gate B2: proof size of the V12 size-widest shape, measured (2026-10-14)

Internal engineering evidence, not an audit. One run on one GitHub Actions runner, two
proofs.

The widest PX proof (bytes) the V12 deploy caps admit (record
docs/reviews/v3-consensus-changes.md#px-deploy-row-caps, decision "px-deploy-row-caps
(V12)") had only been modelled: 3,700,750 bytes expected and 3,780,959 bytes worst over
the query positions ([budget-cap evidence](../budget-cap-2026-10-04/README.md), "any
programs" at 2^16), against the 3.8 MB budget (decision "Agent 22"). The memory-widest
V12 pair was measured earlier ([b2-v12mem](../b2-v12mem-2026-10-10/README.md)); it is
not the size-widest shape. This run proves and verifies the size-widest shape twice.

**Result: two proofs of 3,704,031 and 3,694,591 bytes, both verified; the model expects
3,700,725 bytes (sd 5,092) for this shape, so the measurements lie +0.09 % and -0.17 %
from it, and both are below the 3.8 MB budget (by 95,969 and 105,409 bytes) and below
the 4 MiB `MAX_PROOF_BYTES`. The size model reproduces both proofs byte-exactly.** Peak
RSS 5,410 MiB, no swap, no OOM. The 3,780,959-byte worst case over the query positions
remains a model figure: it is a bound over positions no two draws can test.

## Run

| Item | Value |
|---|---|
| Run | <https://github.com/StickyFingaz420/BlackSilk-Blockchain/actions/runs/38569791238> (job `measure`, id 115871675464) |
| Workflow | `.github/workflows/px-widest.yml` as of `2018636` (manual dispatch) |
| Branch and commit | `gate/b2-size-widest` at `2018636` (on top of rebuild/core `862f4a5`; it changes only `px/examples/freeze_b2_b3.rs` and the workflow; not merged into rebuild/core when this was written) |
| Inputs | `config=v12size`, `count=2`, `swap=on` |
| Runner | `ubuntu-24.04` (image 20261012.334.1), 4 vCPU, MemTotal 15,989 MiB, 3 GiB swap file |
| Date | 2026-10-14 (UTC) |

## Method

As for v12mem: the workflow builds the example in release mode and runs it

```
cargo build --locked --release -p blacksilk-px --example freeze_b2_b3
target/release/examples/freeze_b2_b3 b2 v12size 0 out --check-only    # shape and admission, no proving
/usr/bin/time -v -o out/time.txt \
  target/release/examples/freeze_b2_b3 b2 v12size 2 out               # prove and verify, two proofs
```

- The example proves one statement at a time in one process and verifies each proof
  three times; it asserts that verification returns `Ok` and that the proof decodes
  strictly under the PX limits, so a printed result line means a verified proof. It
  also asserts that the proof's degree bits are the shape's.
- After each proof it prints the size model computed from that proof (same widths):
  the mean, standard deviation and maximum over 20,000 uniform query draws, the worst
  case over any query positions, and every height set the search reaches, ranked by
  expected size; it asserts that none is expected to be larger than the shape's.
- The guard (MemTotal at least 15,360 MiB; count 0 refused for every V12 shape), the
  5 s memory sampler (`VmRSS`, `VmHWM`, `VmSwap` and system memory) and the report are
  those of the v12mem run.

The full log is fetched read-only with
`gh run view 38569791238 --repo StickyFingaz420/BlackSilk-Blockchain --log`; the
relevant lines are in [run-38569791238-excerpt.txt](run-38569791238-excerpt.txt).

## The shape (`v12size`) and why it is the size-widest

**Why.** Every input batch of a PX proof has the depth of its tallest table, the fixed
2^16 byte table, and the opened values depend on the tables' widths only. So, by the
size model (exact on every measured two-function proof, including the two here), a
proof's length is fixed by its FRI folding schedule (`honest_fri_schedule`) and the
pruned digests of its trees, both functions of the **set of distinct table heights**.
The schedule stops at every distinct height. With a table at every height from 2^8
(`MIN_LOG_HEIGHT`) to 2^16 (the PX5 shape bound), it is **[1, 1, 1, 1, 1, 1, 1, 1, 3],
nine rounds**: the longest schedule any PX statement can have. The memory-widest vault
pair (v12mem) has heights {8, 11, 12, 13, 14, 15, 16} and seven rounds,
[1, 1, 1, 1, 1, 3, 3]. Each extra round adds a commit-phase Merkle tree whose digests
outweigh the sibling values the finer folding saves: the non-digest bytes of v12size
(3,306,469) are 9,640 bytes **fewer** than v12mem's (3,316,109), and the proof is larger
through its digests (12,423 and 12,128 digests against about 11,180).

The kernel fixes heights 2^8 (output, blind), 2^12 (program, image), 2^13 (memory
init) and 2^16 (byte, CPU). The missing heights are 2^9, 2^10, 2^11, 2^14 and 2^15. The
vault's own tables cannot go below 2^11, so 2^9 and 2^10 need a smaller program.

**Programs.** Both functions run a synthetic **echo program** (13 instructions, and 14
with one padding NOP for a distinct program id): it reads a word count and that many
private-input words, writes each to its public output and halts with exit code 0. It
is fed the kernel's function prefix, so it is a valid function with no contract logic:
it approves whatever the caller's witness says. The witness is W28-3's pair
(`claim_lock`: a vault record of `C` released to a user, and a contract output of `C2`),
unchanged; only the function programs and inputs differ. Its program, image and output
tables are at 2^8, so the budget alone sets its memory-init (keys) and CPU (cycles)
tables.

**Search.** `v12_size_search` enumerates every echo-based realization under the V12
caps: per function, keys from its use to 2^14 and cycles from its use to 2^15 rows
(56 choices each); each shared table from the height `kernel_budget(MAX_FN)` plus both
uses gives to its V12 cap (1,024 choices). It reaches 32 height sets. It keeps the
longest schedule, then the most distinct heights, then the **fewest weighted cells**
(the bytes do not depend on which tables carry the heights, so the cheapest statement
to prove is chosen), and asserts that the real `Statement::shape` of the realization
has the searched heights.

**Tables** (the excerpt's "Shape and admission" lines):

| Height | Tables |
|---|---|
| 2^16 | byte, kernel CPU |
| 2^15 | add, lt (the kernel's own budget: 25,200 and 20,550 rows) |
| 2^14 | bit (both functions' bit budget 7,192, the V12 per-function maximum) |
| 2^13 | kernel memory init |
| 2^12 | kernel program, kernel image |
| 2^11 | shift, mul (the kernel's own budget) |
| 2^10 | function 1 memory init (keys budget 1,024) |
| 2^9 | function 0 memory init (keys budget 512) |
| 2^8 | kernel output, Poseidon2, blind; both functions' program, image, CPU and output |

- **Budgets**: function 0 cycles 256, keys 512, add 88, bit 7,192, lt 22, shift, mul and
  Poseidon2 0; function 1 the same with keys 1,024. Each function uses 154 cycles,
  45 or 46 keys (its image; none outside it), 88 add and 22 lt.
- **Admission**: both budgets pass `blacksilk_px::deploy_caps::budget_is_provable` and
  both programs `program_is_provable` (asserted at run time), the definition tx
  re-exports and consensus applies. The example checks the cap rules only; the rest of
  a deploy (ELF parsing, ABI, fee) is not exercised for the echo program.
- **Size**: 32.1 M weighted cells; modelled peak memory L 5,285 MB. (The example's M
  figure, 4,523 MB, is the marginal over the vault pair extrapolated below it and does
  not apply to a statement smaller than the vault pair.)
- The search's ranking (from either proof): the full set 3,700,686 bytes expected; the
  next sets, each missing one of 2^9, 2^10 or 2^11, 3,683,458, 3,680,035 and 3,676,595;
  v12mem's set 3,669,718 (2,000 common draws each).

## Results

| Quantity | Proof #0 | Proof #1 | Source |
|---|---|---|---|
| Proof size | **3,704,031 bytes** | **3,694,591 bytes** | example result lines, `b2.csv` |
| Non-digest bytes | 3,306,469 | 3,306,469 (identical) | same |
| Digests (4 input batches / 9 FRI steps) | 4 × 1,344 / 1,236 … 183 (12,423) | 4 × 1,320 / 1,212 … 174 (12,128) | same |
| FRI schedule | [1, 1, 1, 1, 1, 1, 1, 1, 3] | the same | same |
| Degree bits | [17, 13, 13, 14, 17, 16, 15, 16, 12, 12, 9, 9, 9, 9, 10, 9, 9, 9, 9, 11, 9, 9, 9] | the same | same |
| Verification | passed (asserted `Ok`, strict decoding); 364.3 / 364.6 / 364.7 ms | passed; 363.9 / 363.7 / 364.0 ms | same |
| Prove time | 148.0 s | 146.3 s | same |

| Quantity (the whole process, both proofs) | Value | Source |
|---|---|---|
| Peak RSS | **5,540,524 KB = 5,410 MiB** | `/usr/bin/time -v`, "Maximum resident set size" |
| Largest sampled `VmHWM` | 5,410 MiB | sampler (5 s period) |
| Swap | **0 MiB**: largest sampled `VmSwap` 0; `swap_used=0MiB` in every printed sample; "Swaps: 0", 0 major page faults | sampler, `/usr/bin/time -v` |
| Lowest available memory | 9,666 MiB (of 15,989 MiB) | sampler, printed samples (the last 40 of 61, covering both peaks) |
| OOM | none: prover exit 0, `dmesg` OOM check "none" | report step |
| Wall time | 5:03.21 (user 1,158.6 s, 383 % CPU) | `/usr/bin/time -v` |

## Comparison with the model and the budget

| | Bytes | Against the model mean | Against 3.8 MB |
|---|---|---|---|
| Model, budget-cap study (base proof of `914b74f`) | 3,700,750 expected, 3,780,959 worst | | 19,041 below (worst) |
| Model from proof #0 or #1 (this run) | 3,700,725 expected, sd 5,092, max of 20,000 draws 3,721,535, worst 3,780,959 | | 19,041 below (worst) |
| Proof #0 | 3,704,031 | +3,306 (+0.09 %, +0.65 sd) | 95,969 below |
| Proof #1 | 3,694,591 | -6,134 (-0.17 %, -1.2 sd) | 105,409 below |

- **Exactness.** With the budget-cap study's base proof (the `914b74f` vault pair) and
  the measured degree bits, schedule and digest counts, the size model's `synth`
  reproduces both measured lengths byte-exactly (`freeze_b2_b3 model` on the two
  `b2.csv` rows: "size model exact on 2 real two-function proofs"); its expectation from
  that base equals the one computed from the new proofs (3,700,725 bytes) and the
  worst case is the study's figure to the byte. The digest counts agree with uniform
  query positions (12,275.5 mean of the two against 12,321.6 modelled, sd 158.8; two
  proofs say little more).
- **Deviation**: both measurements lie within 0.2 % of the model; nothing to
  investigate.
- **Budget**: both measured proofs are below 3.8 MB with about 96–105 KB to spare. The
  worst case over any query positions, 3,780,959 bytes, is 19,041 bytes (0.5 %) below
  3.8 MB; it is a model bound, not reachable by sampling, and the consensus limit
  `MAX_PROOF_BYTES` (4,194,304 bytes) applies either way.
- **Verifier time**: 0.36 s for the size-widest shape, measured (the earlier B2 study
  estimated 0.35–0.75 s for the former, wider R7-5 shape); v12mem verified in 0.34 s.
- **Memory** (not the B2 size quantity): 5,410 MiB is 2.4 % above the linear fit L
  (5,285) if the model's unit is read as MiB, 7.3 % above if read as 10^6 bytes; v12mem
  was 1.7 % above L. The fit is close for this shape too.

What this supports: under the V12 deploy caps, the widest PX proof the model allows
measures 3.69–3.70 MB on this runner, as the model expects, below the 3.8 MB budget;
the B2 size quantity is **measured on one runner, one run (two proofs)**.

## Limits

- **One run, one runner, two proofs.** Two query draws of one shape. The proof length
  varies with the query positions (sd about 5 KB); the worst case is a model bound.
- **The size-widest claim rests on the size model.** That the full height set is the
  widest is a model result (exact on every measured two-function proof, now including
  these two) plus the search: the full set has the longest possible schedule, and the
  ranking of the 32 reachable sets puts it first. Other realizations of the same set
  (other programs, other tables at the same heights) have the same length by the model;
  none was measured.
- **The echo program is synthetic.** It is admitted by the V12 cap rules; the rest of a
  deploy (ELF form, ABI version, fee) was not exercised for it, and a real contract
  would carry logic. It is the cheapest statement with this height set, not a
  memory-widest one. Any realization of the set has every table at or below its cap,
  so its memory is covered by the memory-widest statement (every table at its cap,
  measured as v12mem up to its output tables at 2^8 instead of 2^9); no larger
  realization of this set was measured.
- **The base proof of the exactness check is from `914b74f`**; it decodes and
  re-encodes under the current code and gives the same non-digest bytes as the new
  proofs.
