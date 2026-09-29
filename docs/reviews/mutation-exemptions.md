# Mutation exemptions

Status: the register of **equivalent mutants** in consensus code: code changes a
mutation tool reports as surviving, because no input can observe them. The freeze gate
of decisions "Agent 42" allows zero unexplained survivors in `consensus` and `px-core`;
an entry here is the written explanation, with its proof or its evidence and the
command that reproduces it. Internal engineering work, not an audit. An exemption
never covers a mutant of a reachable rule: those need a test.

Each entry names: the code, the mutants covered, the argument, the evidence, and the
record that decided it.

## E1: the LWMA weighted-sum floor `n²T/20` (consensus/src/difficulty.rs)

Decision: decisions "RT-FP3" (RTFP3-16). Record:
[v3-consensus-changes.md](v3-consensus-changes.md) `fingerprint-v3`, Follow-up (RT-FP3).

**Code.** In `next_difficulty`, after the weighted sum of the window's solve times:
`weighted = weighted.max(n * n * t / 20).max(1);`. The rule id
`lwma1-n75-step-t/2-warm11-cap6t-floor20` names the floor, and it stays as a documented
defensive floor: the rule id is unchanged.

**Argument (the floor never binds).** Let `n` be the window's solve-time count
(1 ≤ n ≤ 75) and `step = max(1, ⌊T/2⌋)`. The counted clock gives each block
`this = max(ts, prev + step)`, so every counted solve time `this − prev` is at least
`step`, and the 6T cap keeps it at least `min(step, 6T) = step` (as `step ≤ T/2 < 6T`
for T ≥ 2, and `step = 1 ≤ 6` for T = 1). Hence

  weighted = Σ i · solve_i ≥ step · n(n + 1)/2 =: LB(n, T).

For T ≥ 2, `step ≥ (T − 1)/2 ≥ T/4`, so LB ≥ n(n + 1)T/8 > n²T/20 ≥ ⌊n²T/20⌋. For
T = 1, LB = n(n + 1)/2 ≥ n²/20. So `weighted ≥ ⌊n²T/20⌋` on every input, the first
`max` returns `weighted`, and for n ≥ 1 the second `max(1)` returns it too (LB ≥ 1).
The floor is unreachable for every T ≥ 1. `ChainParams::check` requires T ≥ 2; testnet
and mainnet have T = 120, regtest T = 10.

**Mutants covered** (equivalent by this argument): any mutant of the floor term whose
value never exceeds LB(n, T). Checked exhaustively for n = 1..75 with this standard-
library Python (FX-RTFP3, 2026-09-29), for each mutant `f`:

```python
step = lambda t: max(1, t // 2)
lb = lambda n, t: step(t) * n * (n + 1) // 2
binds = lambda f, ts: next(((n, t) for t in ts for n in range(1, 76) if f(n, t) > lb(n, t)), None)
# e.g. binds(lambda n, t: n * n * t // 20, range(1, 100_001)) is None
```

Results:

| Mutant of `n * n * t / 20` | T = 120 (testnet, mainnet) | T = 10 (regtest) | Every T in 2..=100 000 |
|---|---|---|---|
| the rule itself | never binds | never binds | never binds |
| `/ 19`, `/ 21` | never binds | never binds | never binds |
| `n + n * t / 20`, `n / n * t / 20`, `n * n / t / 20` | never binds | never binds | never binds |
| the floor removed (0), or only `.max(1)` | never binds | never binds | never binds |
| `n * n + t / 20` | never binds | never binds | binds (n = 2, T = 2) |
| `% 20` | never binds | **binds** (n = 1) | binds |
| `* 20` | **binds** (n = 1) | **binds** (n = 1) | binds |

**Exempt:** the first four rows, on every valid parameter set; and `n * n + t / 20`
on the built-in networks only (a network with T = 2 would observe it: record it here
before adding one). **Not exempt**, they need killing tests: `% 20` (regtest observes
it) and `* 20`. Under `* 20` an on-target window of 75 blocks at T = 120 has a floor of
20·75²·120 = 13 500 000, about 39 times its weighted sum 120·75·76/2 = 342 000, so any
on-target vector (for example the steady case of `rules.sample.next_difficulty`,
1 000 000) changes.

**Consequence for the fingerprint.** The rule samples (`rules.sample.next_difficulty`)
cannot tell the floor's equivalent mutants apart, by construction: no input can. The
rule id in the manifest names the floor.

**Run evidence (W4-MUT, cargo-mutants 27.1.0).** Run A reported exactly three floor
mutants as missed, all in the exempt first row group: `replace * with + in
next_difficulty` at 91:31 (`n + n * t / 20`), `replace * with / in next_difficulty` at
91:31 (`n / n * t / 20`) and `replace * with / in next_difficulty` at 91:35
(`n * n / t / 20`). The two non-exempt rows are killed: `replace / with %` (`% 20`)
and `replace / with *` (`* 20`) at 91:39 were caught, and so was `replace * with +`
at 91:35 (`n * n + t / 20`). Reproduce with
`cargo mutants -p blacksilk-consensus --profile mutants -F 'difficulty.rs:91:'`
(docs/evidence/mutation-2026-09-29/).

## E2: the stored-ancestor top-up of `overlay_context` (consensus/src/chain.rs)

Decision: W4-MUT (docs/evidence/mutation-2026-09-29/), for the Lead's review.

**Code.** `HeaderChain::overlay_context` collects the timestamps and cumulative work
of a batch header's ancestors, newest first: first from the unstored batch
(`overlay`, at most `need` entries), then, only `if ts.len() < need`, from the stored
chain with `self.recent(anchor, need - ts.len())`. `need` is
`max(difficulty_ancestors, median_time_window)`. The lists are then reversed and
only their last `median_time_window` and `difficulty_ancestors` entries are read.

**Mutants covered** (both missed in run A):
- 527:21 `replace < with <= in HeaderChain::overlay_context`;
- 531:47 `replace - with + in HeaderChain::overlay_context`.

**Argument.**
- `<=`: the branch additionally runs when `ts.len() == need`, and then asks `recent`
  for 0 entries, which returns none (its loop runs while `out.len() < 0`). The index
  `i - overlay.len()` stays in range: the overlay holds exactly one entry per unstored
  header before `i` (`precheck_batch` refuses a stored header after an unstored one,
  and `required_difficulty_after` passes `i = overlay.len()`). Same lists, same context.
- `need + ts.len()`: `recent` then returns more stored ancestors (still stopping at
  genesis). They are all older than the ones the rule reads: the newest `need`
  entries are the same in both versions (or both lists end at genesis with the same
  entries), and both slices read at most the newest `need`
  (`median_time_window ≤ need`, `difficulty_ancestors ≤ need`). Same context; the only
  difference is work.

**Evidence.** Both survive every test, including
`chain::tests::precheck_agrees_with_sequential_validation_and_computes_no_pow` and
`required_difficulty_after_matches_the_stored_branch`, which compare the overlay
path with the stored path on long branches. Reproduce with
`cargo mutants -p blacksilk-consensus --profile mutants -F 'overlay_context'`.

## E3: `clock_step`'s branch at `T/2 = 1` (consensus/src/difficulty.rs)

Decision: W4-MUT, for the Lead's review.

**Code.** `if target / 2 > 1 { target / 2 } else { 1 }`, the counted clock's step
`max(1, ⌊T/2⌋)`.

**Mutant covered:** 35:19 `replace > with >= in clock_step` (missed in run A).

**Argument.** The two versions differ only when `target / 2 == 1` (T = 2 or 3), where
the original takes the `else` branch (1) and the mutant returns `target / 2`, also 1.
Both compute `max(1, ⌊T/2⌋)` for every `u64` input. Checked for every T below 10^6
with `cs = lambda t, ge: t // 2 if (t // 2 >= 1 if ge else t // 2 > 1) else 1` and
`all(cs(t, False) == cs(t, True) for t in range(10**6))`. The existing test
`difficulty::tests::ancestors_and_step` pins T = 0, 1, 2, 3, 10 and 120.

## E4: the nibble join of `parse_display_hex` (consensus/src/genesis.rs)

Decision: W4-MUT, for the Lead's review.

**Code.** `*b = digit(s[2 * i])? << 4 | digit(s[2 * i + 1])?;` with `digit` in `0..=15`.

**Mutant covered:** 121:36 `replace | with ^ in parse_display_hex` (missed in run A).

**Argument.** `x << 4` for `x ≤ 15` has a zero low nibble and `y ≤ 15` has a zero high
nibble, so the operands share no bit and `|`, `^` (and `+`) agree. Checked
exhaustively: `all(((x << 4) | y) == ((x << 4) ^ y) for x in range(16) for y in
range(16))`. The known answer `genesis::tests::known_answer_bitcoin_block_0` pins the
decoding.

## E5: `2 + 2` in two word-count constants (px-core/src/call.rs, kernel.rs)

Decision: W4-MUT, for the Lead's review.

**Code.** `PREFIX_WORDS = 1 + 8 + 8 + 2 + 2` (call.rs) and
`MAX_PUBLIC_WORDS = 1 + 8 + 8 * N_IN + 8 * N_OUT + 2 + 2 + 1 + 16 * MAX_FN` (kernel.rs).

**Mutants covered** (missed in run B): call.rs 54:47 and kernel.rs 66:70,
`replace + with *`, the `+` between the two 2s.

**Argument.** `*` binds tighter than `+`, so each mutant replaces the term `2 + 2` by
`2 * 2 = 4`: the constants keep their values (21 and 78) and the compiled code is
the same. Every other mutant of both lines is caught, or unviable where it makes a
constant negative (run B, `caught.txt` and `unviable.txt`).

## E6: `|` of operands with disjoint bits in the kernel (px-core/src/kernel.rs)

Decision: W4-MUT, for the Lead's review.

**Mutants covered** (missed in run B):
- 192:8 `replace | with ^ in u64_word`: `lo | (hi << 32)` with `lo = src.next() as
  u64 < 2^32` and `hi << 32` a multiple of 2^32;
- 217:27 `replace | with ^ in select`: `(a[i] & m) | (b[i] & !m)`, where the masks
  `m` and `!m` are complementary.

**Argument.** In both, the two operands share no set bit, so `|` and `^` agree on
every input (as for E4). The `&`-to-`|` and `&`-to-`^` mutants of `select`, and the
`<<`/`>>` mutants of `u64_word`, are caught.

## E7: the first two terms of the approval guard (px-core/src/kernel.rs)

Decision: W4-MUT, for the Lead's review.

**Code.** In `transfer`, for input `i` approved by a function of contract `C_f`:
`if dummy || !is_contract || !digest_eq(&call.contract, &contract) {
ApprovalMismatch }`.

**Mutant covered:** 332:26 `replace || with && in transfer`, the first `||`, which
gives `(dummy && !is_contract) || !digest_eq(..)` (missed in run B, and again after
the new tests).

**Argument.** The two conditions differ only when `digest_eq(C_f, contract)` holds
and `dummy || !is_contract` holds but `dummy && !is_contract` does not. `C_f ≠ 0`
(a function with contract 0 was refused with `ZeroContract` when it was read), so
`contract = C_f ≠ 0` and `is_contract` holds; the case then needs `dummy`, but a
dummy input with a contract was refused with `DummyContract` a few lines earlier, for
the same input. So no witness reaches the difference: the first two terms are
implied by the third. The second `||` (332:42) and both `!` deletions are caught
(run B, `caught.txt`).

**Reproduce (E5–E7).** In run B's configuration (docs/evidence/mutation-2026-09-29/),
with the `--re` filters in the evidence's `rerunB.args`.
