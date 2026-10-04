# Evidence: freeze gates B2 (widest PX proof) and B3 (P-5 re-run), 2026-10-04

This is internal engineering work, not an audit. Nothing here shows that BlackSilk is
secure.

**Setup:**
- Tree: rebuild/core `a427adb` (frozen kernel `ef75a535…`, BS-ZK-3, PXDET-1) plus this
  harness (`px/examples/freeze_b2_b3.rs`).
- Machine: Windows 10, i7-6700 (4 cores, 8 threads), 16 GB, release build, MSVC.
- One proving process at a time. Each process started only with at least 9 GB free and
  no cargo, rustc or `t-coord` process running. A runner logged the peak working set and
  stopped its own process above 8 GB (`runner.log`).

**Files:**
- `b2.csv`, `p5.csv`: one row per proof. The columns are the total bytes, the non-digest
  bytes, the pruned-digest count of every input batch and FRI step, the FRI schedule,
  the degree bits, the proving time and three verification times.
- `model.txt`: the output of `freeze_b2_b3 model`.
- `campaign-output.txt`: the output of each proving process.
- `runner.log`: the P-5 steps and the stopped dense18 run. The base and coarse18 runs
  came before this log; their figures are in `b2.csv`.
- `proofs.sha256`: the first proof of each configuration. The proofs (2.4–3.7 MB each)
  are not committed.

**Reproduce** (each proving command alone on the machine):

```sh
cargo build --locked --release -p blacksilk-px --example freeze_b2_b3
X=target/release/examples/freeze_b2_b3
$X check                    # no proving: witnesses, heights, schedules
$X b2 base 2 out            # also coarse18 (peak memory above 10 GB, see below)
$X p5 0 15 out; $X p5 1 15 out; $X p5 2 10 out
$X model out                # no proving
```

`.github/workflows/px-widest.yml` runs a `b2` configuration on a CI runner
(workflow_dispatch only). It has not been run.

---

## B2: the widest PX proof

### What "widest" means

A PX proof's shape is fixed by the registered budgets (`Statement::shape`). The widths
are fixed per table kind (`analysis::trace_widths`), and the quotient chunks do not
depend on the heights (`proof_limits.rs`). Two things grow with the heights:
- the depth of every Merkle tree;
- the FRI folding schedule (`honest_fri_schedule`). It stops at every distinct input
  height, so **many distinct table heights mean many arity-1 rounds**, each with its
  own tree.

Deploys may register budgets up to `MAX_CYCLES` = 2^21 cycles and 2^22 rows per table
(`tx::px::budget_is_provable`). The widest proof is therefore not the W28-3 vault pair.
It is the shape with tables at every height up to 2^22.

### Measured proofs

| Configuration (kernel + CLAIM + LOCK) | Proofs | Bytes | Prove | Verify (3 runs each) | Peak working set |
|---|---|---|---|---|---|
| base (vault budgets; same shape as P-5 n_fn = 2) | 2 + 30 | 3,619,591 – 3,637,159 | 96–97 s | 310–382 ms (median of per-proof medians 324) | 6,446 MB |
| coarse18 (`add` at 2^18) | 2 | 3,710,965; 3,717,269 | 149–150 s | 324–476 ms (first verification of #0: 476) | at least 10,280 MB (sampled during the run) |
| dense18 (9 heights, up to 2^18) | 0 | void | — | — | passed 11.2 GB with 0.4 GB free; stopped by the Lead and the guard |

Peak working sets for the other shapes: n_fn = 0, 3,622 MB; n_fn = 1, 4,339 MB.

### Size model

`synth` takes a real two-function proof. It sets the degree bits, the FRI schedule
(`honest_fri_schedule`) and every pruned-digest count to a target's, then encodes the
result with the real `encode_proof`. The verifier fixes the digest counts: they are the
frontier of the public query positions (`p3-merkle-tree` pruning.rs, `restore_paths`
rejects any other count).

**Validation:**
- **Exact (0 bytes off)** on all 34 real two-function proofs: base, coarse18 (another
  schedule, `[2,1,2,1,4,3]` against `[1,2,1,4,3]`) and the 30 P-5 proofs.
- In every one of the 124 proofs, the four input batches have equal digest counts: one
  depth, one query set.
- The digest counts match those of uniform query positions (frontier simulation,
  20,000 draws). KS p-values: n_fn = 0, 0.053; n_fn = 1, 0.495; n_fn = 2 (P-5), 0.552;
  coarse18, 0.924. The means agree within 0.3%.

**Search:** every reachable set of table heights (the kernel tables, Byte and Blind
fixed), under two assumptions:
- (a) both functions run the reference vault program, at any registrable budgets
  (1,024 reachable sets);
- (b) any two programs (2,048 reachable sets).

The largest set is also the most finely folded one:

| | Heights (log2) | FRI schedule | Expected | sd | Range of 20,000 query draws | Worst case for any query positions |
|---|---|---|---|---|---|---|
| (a) vault programs | 8, 11–22 | 11 × 1, 3, 3 | **4,094,185** | 6,830 | 4,065,015 – 4,116,695 | 4,199,575 |
| (b) any programs | 8–22 | 14 × 1, 3 | **4,125,175** | 7,657 | 4,091,923 – 4,151,859 | 4,242,995 |

Shape (a) is realized with registrable budgets, and `Statement::shape` gives exactly
that set:
- C: add 4,164,804, bit 2,094,892, lt 1,024,126, shift 522,398, mul 260,254,
  poseidon 1,870, keys 131,072, cycles 32,768;
- C2: the vault budget with keys 16,384.

**Against the limits:**
- **3.8 MB (Agent 22):** exceeded with probability 1 in both cases, by about 294 KB (a)
  and 325 KB (b).
- **4 MiB = 4,194,304 (`MAX_PROOF_BYTES`):** below in every one of the 20,000 draws,
  with a margin of at least about 77 KB (a) and 42 KB (b). The worst case over any query
  positions exceeds it (by 5,271 B and 48,691 B). Query positions come from
  Fiat–Shamir, so that case is not reached in practice, but the cap is not a hard
  guarantee for these shapes.

### Verifier time

Not measured for the widest shape, because it cannot be proven here. The verifier hashes
the same opened rows as for any shape. It does more Merkle compressions (model: 25,082
(a) and 26,563 (b), against 10,086 for base) and runs 13–15 FRI rounds instead of 5.
- Compression cost alone (1.3 µs each, microbenchmark): about 345 ms.
- Linear fit through base and coarse18 (slope 24 µs per compression; two
  configurations, with one 476 ms outlier): about 690–720 ms.
- Estimate: **about 0.35–0.75 s** per widest proof. At the 8 MiB PX block budget
  (`MAX_PX_BLOCK_BYTES`), 2 widest proofs fit, so about 1.5 s per block in the worst
  case. Today's shapes: 3 transfers × about 0.2 s, or 2 two-function proofs × 0.32 s.

### Prover memory

This is a finding in itself. Prover memory grows with the rows × columns of the tall
tables:
- coarse18 adds one 2^18-row table to base and costs about 4 GB more;
- dense18 passed 11.2 GB before it was stopped.

Extrapolating from coarse18, one 2^22-row ALU table alone costs about 60 GB, and the
widest shape needs on the order of 100 GB or more. **Such statements cannot be proven on
a wallet device, on this machine, or on a 16 GB CI runner.** A deploy can still register
the budgets: `budget_is_provable` checks the height limits, not memory or proof size.
The CI job can measure base and probably coarse18; it cannot measure the widest shape.

### Verdict B2: FAIL (the widest provable shape exceeds 3.8 MB)

The widest proof the current rules accept at deploy is about 4.09–4.13 MB. Agent 22's
decision for a result above 3.8 MB is a **deploy-time proof-size bound, a consensus
rule**. It is not implemented here.

Recommendations, for a decision record:
- bound the registered budgets (or the reachable height set) of a deploy, so that the
  model's worst case for kernel + `MAX_FN` functions stays at or below a chosen size;
- since memory, not bytes, is the binding constraint, a much lower table-height cap for
  function budgets is the likely form of the bound.

The vault pair itself (3.63 MB) is below 3.8 MB.

---

## B3: P-5 on the frozen kernel (n_fn = 0, 1, 2)

**Definition under PXDET-1.** The prover is deterministic for a fixed witness and seed,
so each proof uses a fresh witness, a fresh prover seed and a fresh `h_tx` (ChaCha20,
seeded per index). The classes are interleaved.

### Exact assertions (primary, ZP-2)

1. **The non-digest bytes are identical within each shape** (asserted on every proof,
   with a panic on mismatch):
   - n_fn = 0: 2,049,372 B (60 proofs);
   - n_fn = 1: 2,683,996 B (30 proofs);
   - n_fn = 2: 3,339,573 B (30 proofs, and the same for the two base B2 proofs, which
     use another contract).
2. The only variable part is the pruned digests. The verifier fixes their count as a
   function of the public query positions (`restore_paths`).
3. In all 124 proofs, the four input batches have identical digest counts, consistent
   with one query set opened in trees of equal depth.

So, given the shape, the length is a function of the query positions alone. The shape
is public (n_fn and the registered budgets).

### Statistics (sanity check only)

| n_fn | Class | n | Mean bytes | sd | Min | Max |
|---|---|---|---|---|---|---|
| 0 | deposit | 15 | 2,401,816 | 6,081 | 2,393,010 | 2,413,554 |
| 0 | pay2 | 15 | 2,402,582 | 4,813 | 2,395,538 | 2,412,146 |
| 0 | pay1 | 15 | 2,403,715 | 4,638 | 2,395,090 | 2,410,482 |
| 0 | withdraw | 15 | 2,400,888 | 4,036 | 2,393,842 | 2,407,698 |
| 1 | lock | 15 | 3,001,652 | 3,427 | 2,997,616 | 3,008,208 |
| 1 | claim | 15 | 3,002,090 | 3,729 | 2,995,472 | 3,007,728 |
| 2 | claim_lock | 10 | 3,632,103 | 5,273 | 3,619,591 | 3,637,159 |
| 2 | lock_lock | 10 | 3,631,047 | 3,113 | 3,624,743 | 3,635,175 |
| 2 | claim_claim | 10 | 3,630,829 | 5,086 | 3,623,463 | 3,636,455 |

**Pairwise permutation tests** (20,000 relabellings; 10 pairs × 2 statistics = 20
tests): the smallest p is 0.074 (KS, pay1 against withdraw), against a Bonferroni
threshold of 0.05 / 20 = 0.0025. None is significant.

**Against the uniform-query model** (digest totals, KS): p = 0.053, 0.495 and 0.552 for
n_fn = 0, 1 and 2.

With 10–15 proofs per class, only large effects could be detected.

### Verdict B3: PASS

- The exact assertions hold for n_fn = 0, 1 and 2.
- No class difference was detected, and the lengths match uniform query positions.
- P-5 stays "supported, not closed" (it rests on the random-oracle model of the query
  positions).

---

## Limits

- The widest size is a model result, not a measured proof. The model is exact on every
  real proof, and its only stochastic input, the digest counts, matches the real
  distribution. It assumes that the structure seen at heights up to 2^18 (equal-depth
  input batches; step trees of depth `height − arity`) holds up to 2^22.
- Verifier time for the widest shape is an estimate.
- The coarse18 memory figure is a sample taken during the run, not the final peak. The
  dense18 figure is where the run was stopped, not its peak.
