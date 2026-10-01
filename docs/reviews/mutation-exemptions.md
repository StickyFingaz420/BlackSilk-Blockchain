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

**What the equivalence depends on (RT-MUT).** The argument holds only because the
`DummyContract` check runs, for the same input, *before* the approval loop, and
because `ZeroContract` is checked when the function is read. A reordering that moves
the approval loop above the dummy checks would make the mutant observable: a dummy
contract input approved by its own function would pass the guard, so the refusal
would come later with another exit code, or not at all if the later dummy check were
also changed. Any such edit changes the kernel guest, and
so the pinned kernel ELF and its id (`px/kernel.id`, the consensus fingerprint): that
pin is the tripwire, and the edit must re-examine this entry.

**Reproduce (E5–E7).** In run B's configuration (docs/evidence/mutation-2026-09-29/),
with the `--re` filters in the evidence's `rerunB.args`.

## E17: the end check of the decode pre-scan's `skip` (zk/src/bounds.rs)

Decision: mutation run D (docs/evidence/mutation-runD-2026-10-01/). E8–E16 are run C's
(branch `w4-mutc`); this register continues at E17.

**Code.** `Reader::skip` in the proof decoder's pre-scan (RT-FUZZ-1):
`if end > self.bytes.len() { return Err(exhausted()); } self.pos = end;`.

**Mutants covered:** 111:16 `replace > with >= in Reader<'_>::skip` and `replace > with
== in Reader<'_>::skip` (missed in run D and again after its new tests).

**Argument.** Both differ from the code only when a skip ends at or past the end of
the body. `pos` never decreases, and every skip of `prescan` is followed, directly or
after more skips, by a `byte` read (a varint or an option tag): after a Merkle root, an
extension vector, a salt, the sibling digests, an input row, the grinding witnesses and
a lookup terminal comes a length, a tag or the next field; the final polynomial's skip
is followed by the query witness's skip and then by the lookup terminals' length.
`skip` is never the walk's last read. Where the code returns `Ok` with `pos == len`,
the next `byte` returns `exhausted()`; where it refuses `end > len`, it returns
`exhausted()`. `>=` returns `exhausted()` at `end == len` itself. `==` lets `pos` pass
the end (later skips pass too, unless one ends exactly at the end and returns
`exhausted()`), and the next `byte` (`bytes.get(pos)`) returns `exhausted()`. In every
case the result is the same `Err(Encoding("proof bytes end early"))`, before `postcard`
runs, so no input observes the mutants. The final `pos != len` check would also refuse
a walk left past the end.

**What the equivalence depends on.** The order of the walk: a change that made a skip
the last read must re-examine this entry. The tests decode
honest proofs whose last field is a varint (`decode_bounds.rs`), so a `>=` at the real
end would refuse them.

**Reproduce.** Run D's `rerunZ` (filters `rerunZ.args`, the zk test set of the
evidence).

## E18: the layout and trace length of the quotient-chunk helper (zk/src/lib.rs)

Decision: mutation run D (docs/evidence/mutation-runD-2026-10-01/).

**Code.** `blacksilk_zk::analysis::quotient_chunks`, a test-support helper (its only
caller is `px/tests/proof_limits.rs`): it recomputes, for each table, the quotient
chunk count that Plonky3 0.7.0's `verify_batch` requires, so that the test can check
the decoder's PX limits (RT-FUZZ-1). It passes Plonky3's
`get_log_num_quotient_chunks` an `AirLayout` and the trace length
`1 << (degree_bits[i] - 1)`.

**Mutants covered:** 634:21 `delete field preprocessed_width from struct AirLayout
expression in analysis::quotient_chunks`; 649:42 `replace - with +` and `replace - with
/ in analysis::quotient_chunks` (the trace length becomes `2^(db + 1)` or `2^db`
instead of `2^(db − 1)`).

**Argument.**
- `preprocessed_width`. The deleted field takes its default, 0. No BVM-1 table has a
  committed preprocessed trace: the public tables (BYTE, PROGRAM, IMAGE, OUTPUT) are
  periodic columns that the verifier evaluates itself (zkvm/src/air/mod.rs,
  `periodic_columns`; `Table` keeps the default `preprocessed_trace`, `None`), so the
  helper's computed width is 0 for every table it is ever given, and Plonky3's
  `validate_against_air` does not check this field. Equivalent on every BVM-1 table.
- The trace length. Plonky3 0.7.0 reads it only to weigh periodic columns
  (`get_max_constraint_degree`: without periodic columns the cached degree multiple
  is used). With them, a constraint's degree is `⌈(d − 1)/(n − 1)⌉` for its
  polynomial degree `d` at trace length `n`; the result changes with `n` only for a
  constraint whose degree is set by a product of periodic columns. For every PX
  statement (n_fn 0, 1 and 2: 13, 18 and 23 tables, the helper's only inputs) the
  mutated helper returns the same counts, and those for n_fn 0 equal the real transfer
  proof's (px/tests/proof.rs). This is an equivalence on the helper's uses, not on
  every AIR: it is a limit of the oracle, as E15 is.

**What the equivalence depends on.** A BVM-1 table with a committed preprocessed
trace, or a constraint whose degree a product of periodic columns sets, must
re-examine this entry; the helper would then need a test AIR of its own.

**Reproduce.** Run D's `after-analysisA` (filters `analysisZ.args`,
`--test-package blacksilk-px -C=--test=proof_limits`).

## E19: where a PX transaction's stateless checks run (p2p/src/net/admission.rs)

Decision: mutation run D (docs/evidence/mutation-runD-2026-10-01/). Policy code, not a
consensus rule; listed because run D's gate covers it.

**Code.** `px_pre_checks` runs a PX transaction's stateless checks (`px_stateless`:
structure, balance and the bounded proof decoding) on a blocking thread, off the chain
actor, and hands the result (`Some(Some(pre))`, the degree bits or the failed rule) to
`cheap_checks`. It returns `Some(None)` for a transaction it does not decode (not PX,
or expiring soon at the published height). `cheap_checks` first refuses an expiring
transaction at the actor's own height, then runs `px_stateless` itself whenever `pre`
is `None` (`pre.get_or_insert_with(|| px_stateless(t))`). A panic or a cancellation of
the blocking task drops the transaction (`None`), with a warning for a panic.

**Mutants covered:**
- 254:5 `replace px_pre_checks -> Option<Option<PxPre>> with Some(None)`;
- 264:9 `delete match arm Transaction::Px(t) in px_pre_checks` (the blocking closure
  returns `None`, so `px_pre_checks` returns `Some(None)`);
- 257:44 `replace + with * in px_pre_checks` (the expiring-soon pre-check at the
  published height instead of the next), and, under release arithmetic, `replace +
  with -` (in a debug build it overflows at height 0, which the tests catch);
- 273:19 `replace match guard e.is_panic() with true` and `with false in
  px_pre_checks`.

**Argument.** The first four change only whether `pre` arrives filled. `px_stateless`
reads only the transaction, so computing it in the chain command gives the same
result; `cheap_checks` computes it there whenever `pre` is `None`, after the same
expiring-soon refusal at the actor's height, which is the check that decides (the
pre-check at the published height only spares a decoding). Every verdict, penalty,
statistic and message is the same: what differs is that the decoding runs on the chain
actor (the RT-FUZZ-1 / RT-PXDOS F1 resource property) and skips the `PX_DECODES`
semaphore. The two guard mutants differ only in the log line: both arms return `None`.
No test observes which thread decodes: the tests check verdicts, scores, statistics and
messages. This is a limit of the oracle (as E15 is), not a claim that the off-actor
decoding is unimportant; a test would need a count of decodings made in chain commands,
which the code does not keep.

**What the equivalence depends on.** `cheap_checks` recomputing `px_stateless` for a
`None` and refusing an expiring transaction before it reads `pre`. A change that made
`cheap_checks` trust `pre` alone must re-examine this entry.

**Reproduce.** Run D's `after-admissionP` and `ovfP` (filters `admissionP.args`; the
admission test list `admission.tests`).

## E19a: the prebuild mark's drop guard (consensus/src/pow.rs)

Decision: mutation run D (docs/evidence/mutation-runD-2026-10-01/). Numbered E19a
because run D was given E17–E19 and run C continues at E20; the Lead may renumber it.

**Code.** `SeedCache::prebuild` marks a hot key (`prebuilding`, with the thread's
number), then starts a detached thread that calls `fetch(seed, Some(id))`. The thread
owns a `Pending` guard whose `Drop` clears its own mark "if `fetch` did not".

**Mutant covered:** 546:17 `replace SeedCache<C>::prebuild::<impl Drop for
Pending<C>>::drop with ()` (missed in run D's census).

**Argument.** Since `9bba1bd` (RT-POW L2) `fetch` clears the thread's mark in the
same critical section in which it stops waiting, on each of its three exits: the
cache is resident, the key left the hot set (it gives up), or the build starts. The
build itself runs after the clear, so a panicking build finds the mark gone (its
`BuildGuard` releases the key and the room). Nothing before those exits can panic in
a prebuild thread: the lock recovers from poisoning, the waits do not panic, and the
debug caller-rule check holds in a fresh thread, which holds no handle. So once the
thread runs, the guard's clear finds no mark of its number and changes nothing. It
matters only when `std::thread::Builder::spawn` fails: then the closure, and the
guard in it, are dropped unrun, and without the guard the key's mark would stay, so
the key would never be prebuilt again (the cache would still be built on first use:
no hash or liveness change). A test cannot make the operating system refuse a
thread, so no test observes the mutant. A limit of the oracle, as E15 is.

**What the equivalence depends on.** `fetch` clearing the mark before any code that
can panic. A change that moved the clear after the build must re-examine this entry
(run A's census caught this guard when it was the only clear on a panicking build).

**Reproduce.** Run D's `runPow` and `rerunPow` (filters `rerunPow.args`, the whole
consensus test suite).

## E19b: the first branch's edge in `seed_height` (consensus/src/pow.rs)

Decision: mutation run D, boundary pass (docs/evidence/mutation-runD-2026-10-01/,
§ Boundary pass: cargo-mutants 27.1.0 never turns `<=` into `<`). Numbered E19b for the
same reason as E19a.

**Code.** `seed_height(height, epoch, lag)`: `if height <= epoch + lag { 0 } else {
(height - lag - 1) & !(epoch - 1) }`, with `epoch` a power of two and `1 ≤ lag <
epoch` (`ChainParams::check`).

**Mutant covered:** 28:15 `<=` → `<` (the boundary pass's script; missed).

**Argument.** The two differ only at `height = epoch + lag`, where the mutant takes
the second branch: `(epoch + lag − lag − 1) & !(epoch − 1) = (epoch − 1) & !(epoch −
1) = 0`, the first branch's value, and `height − lag − 1 = epoch − 1` does not
underflow. So both branches agree at the edge for every valid schedule: the key of
block `E + L` is genesis either way (Monero `rx/0`: `seed_height(2112) = 0`).
`seed_schedule_matches_the_spec_for_every_valid_small_schedule` checks every valid
schedule with `epoch ≤ 16` against the spec formula and passes under the mutant, as
the argument predicts. The `>` mutant of the same comparison (`<=` → `>`) is caught.

**Reproduce.** `boundary.py` of run D (the evidence directory), mutant 2.

## E19c: the prebuild thread numbers under release arithmetic (consensus/src/pow.rs)

Decision: mutation run D, release arithmetic (docs/evidence/mutation-runD-2026-10-01/,
`ovfPow`). Numbered E19c for the same reason as E19a.

**Code.** `SeedCache::prebuild`: `let id = st.prebuild_seq; st.prebuild_seq += 1;`.
The number tags the thread's mark, so that a thread clears only its own mark (RT-POW
L2); it is compared for equality only, never ordered or shown.

**Mutant covered:** 536:29 `replace += with -= in SeedCache<C>::prebuild`, under
release arithmetic only. With overflow checks on (the census profile) the second
prebuild panics on `0 − 1` and the mutant is caught.

**Argument.** With wrapping arithmetic the mutated counter yields 0, 2^64 − 1, 2^64 −
2, …: like the code's 0, 1, 2, …, a value repeats only after 2^64 prebuilds, and only
distinctness is used. No input observes the change in a release build.

**Reproduce.** Run D's `ovfPow` (filters `ovfPow.args`, the whole consensus test
suite, `RUSTFLAGS="-C overflow-checks=off -C debug-assertions=off"`).
