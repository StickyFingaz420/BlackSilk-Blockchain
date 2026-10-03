# Mutation exemptions

Status: the register of **equivalent mutants** in consensus code: code changes a
mutation tool reports as surviving, because no input can observe them. The freeze gate
of decisions "Agent 42" allows zero unexplained survivors in `consensus` and `px-core`,
and run C (decisions "W4-MUT and RT-MUT") extends it to the transaction rules; an entry
here is the written explanation, with its proof or its evidence and the
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

## E8: T1 in `check_shape` (tx/src/validate.rs)

Decision: W4-MUTC (run C, docs/evidence/mutation-runC-2026-09-30/), for the Lead's
review.

**Code.** The last rule of `check_shape`: `if size > MAX_TX_SIZE { TooLarge }`, with
`size = tx.encoded_len()` and `MAX_TX_SIZE` = 100 000.

**Mutants covered** (missed in run C): 445:13 `replace > with == in check_shape` and
`replace > with >= in check_shape`.

**Argument (the rule never fires).** It runs only after T3–T7, T10's shape and T11
passed, so the transfer has 1 ≤ n ≤ 64 inputs, 2 ≤ k ≤ 16 outputs, n pseudo-outputs, n
CLSAGs and a range proof of exactly `rounds(k)` points per list. Every field of such a
transfer has a fixed length except its 4 + 16n varints (version, the two counts, the
fee, and each ring's 16 indices), each at most 10 bytes (a u64 LEB128). `max_weight(n,
k)` counts exactly that encoding with every varint at 10 bytes, plus a non-negative
clawback (docs/transactions.md §8.4), so `size ≤ max_weight(n, k) ≤ max_weight(64, 16)
= 57 439 < 100 000`. `size` never reaches `MAX_TX_SIZE`, so `>`, `==` and `>=` give the
same verdict on every transfer that reaches the line. The `<` mutant is caught (every
valid transfer then fails). T1 stays as a documented defensive bound (docs/
transactions.md T1).

**Evidence and tripwire.** `tx/tests/mutation_regressions.rs`
`t1_is_implied_by_the_transfer_shape_rules` checks the premise: the largest
`max_weight` over every shape is `max_weight(64, 16)` and lies below `MAX_TX_SIZE`, and
a maximal shaped transfer encodes within it. `tx/tests/max_weight_encoder.rs` derives
`max_weight` through the real encoder for all 1 088 shapes. If a constant changes so
that the premise fails, T1 becomes reachable: this entry must then be replaced by a
boundary test. PX transactions and deploys have their own size rules, which are
reachable and tested at their bounds (`a_px_transaction_of_exactly_the_size_cap_is_well_formed`,
`a_deploy_of_exactly_the_size_cap_is_well_formed`).

**Reproduce.** `cargo mutants -p blacksilk-tx --profile mutants -F 'check_shape'` with
run C's test targets (docs/evidence/mutation-runC-2026-09-30/README.md).

## E9: `hex_id`, the log text of a contained verifier panic (tx/src/validate.rs)

Decision: W4-MUTC, for the Lead's review.

**Code.** `hex_id(h)` formats a binding as hex. Its only caller is the `log::warn!` in
`check_px_proof_decoded` that reports a PX proof that made the Plonky3 verifier panic
(contained, zkvm.md §10). The verdict (`TxError::PxProof`) does not depend on it.

**Mutants covered** (missed in run C): 747:5 `replace hex_id -> String with
String::new()` and `with "xyzzy".into()`.

**Argument.** Neither the returned `Result` nor any state depends on the string: it
only goes into a log line. No consensus or policy verdict can observe it. (A test of
it would need a proof that panics the verifier, which the proving tests do not have,
and a log capture; it would test a diagnostic, not a rule.)

## E10: the range-proof arm guard of `check_px_structure` (tx/src/px.rs)

Decision: W4-MUTC, for the Lead's review.

**Code.**

```text
match (&tx.range_proof, k) {
    (None, 0) => {}
    (Some(p), k) if k > 0 => { let rounds = bpp::rounds(k).ok_or(RangeProofShape)?; ... }
    _ => return Err(RangeProofShape),
}
```

**Mutants covered** (missed in run C): 770:25 `replace match guard k > 0 with true in
check_px_structure` and 770:27 `replace > with >= in check_px_structure` (the same
change, since `k >= 0` holds for every `usize`).

**Argument.** The guard differs only for `(Some(p), 0)`. The original sends it to the
last arm, `RangeProofShape`. The mutant enters the second arm, where `bpp::rounds(0)`
is `None` (`rounds` refuses 0 outputs, crypto/src/bulletproofs_plus.rs), so `ok_or`
returns the same `RangeProofShape`, before any other check. Same result on every
input. The case itself is tested (`px_range_proof_shape_is_checked_on_both_point_lists`:
a range proof without hidden outputs is `RangeProofShape`), and so is `rounds(0) =
None` (crypto's own tests and `bpp_proof_len_matches_the_crypto_crate`). The `||` of the
point-list comparison (772:36), the other mutant of the arm, is killed by the same test.

## E11: the same answer by a longer walk (chain/src/manager/fork_choice.rs)

Decision: W4-MUTC (run C), for the Lead's review.

**Mutants covered** (missed in run C):
- 54:25 `replace < with <= in ChainManager::ancestor_at` and `replace < with == in
  ChainManager::ancestor_at`;
- 252:9 `replace ChainManager::fork_height -> usize with 0`.

**Code and argument.**
- `ancestor_at(id, height)` walks back from `id`: `if h.height == height { return
  Some(id) } if h.height < height { return None } id = h.prev_id`. The `==` test comes
  first, so at the second test `h.height != height` and `<=` equals `<`. With `==`
  the second test never holds: the walk continues to genesis, whose parent is no
  known header, so `self.headers.header(&id)?` returns `None`, the original's answer
  (an ancestor below `height` cannot be at `height`). Same result for every input; the
  mutant only walks further.
- `fork_height()` feeds only `missing_bodies`, which lists the header-best chain's
  heights from `fork_height() + 1` whose body is not held. Every block at or below
  the fork is on the connected chain, whose bodies the manager always holds (`bodies`
  keeps every kept body in memory, connected ones included), so starting the scan at
  height 1 lists exactly the same blocks, in the same order, within the same `max`.
  The `→ 1` mutant is caught (it skips height 1 when the fork is at genesis), and so
  are the loop's `-=` mutants (`+=` fails an assertion, `/=` never ends).

Neither changes a verdict, a stored state or a message; only the work of a walk.

## E12: log text and log levels in fork choice (chain/src/manager/fork_choice.rs)

Decision: W4-MUTC (run C), for the Lead's review.

**Mutants covered** (missed in run C):
- 314:22 `replace >= with <` and 320:29 `replace > with ==`, `<`, `>=` in
  `ChainManager::sync_state`: whether a reorganization is logged as a warning (`depth
  >= DEEP_REORG_WARN_DEPTH`) or as information (`depth > 0`);
- 347:56 `replace += with -=`, `*=` in `ChainManager::sync_state`:
  `outcome.uncaptured`, the count of returned transactions beyond the readmission
  budget, read only by `finish_sync`'s log line;
- 442:20 and 450:20 `replace > with ==`, `<`, `>=` in `ChainManager::finish_sync`:
  `if flushed > 0` and `if expired > 0`, each guarding only a `log::info!`;
- the boundary pass's 314:22 `replace >= with >` (the warning threshold itself;
  tools/boundary-mutants.sh, run C evidence § Boundary pass).

**Argument.** Each changes only whether or what a log line says. `deepest_reorg`
(the reported depth) is set before the branch and is not mutated here; `flushed` and
`expired` are computed by the mempool, which acts on them itself. No verdict, state
or message depends on them. (The `-=` of the counter can underflow only past the
readmission budget, `READMIT_MAX_BYTES`, which no test reaches; in a release build it
would wrap, still only in a log line.)

## E13: withdrawn (killed)

The Bulletproofs+ zero-challenge guards (`y == 0 || z == 0` in the prover,
`y == 0 || z == 0 || e == 0 || es.contains(&0)` in the verifier) were first exempted
here as computationally unreachable. Decision RT-MUTC: they were moved into the pure
helper `any_zero` (commit `b3e4e40`, no change of verdict or proof bytes), whose
mutants the unit test `any_zero_finds_a_zero_challenge_in_any_position` kills. The
number stays reserved.

## E14: the length of the `y` powers in Bulletproofs+ (crypto/src/bulletproofs_plus.rs)

Decision: W4-MUTC (run C), for the Lead's review.

**Code.** `let y_pows = powers(&y, n + 2);` in `prove_bits` (260) and `Msm::add` (453),
with `n = 64·m` (`BITS × next_power_of_two(outputs)`), so `n ≥ 64`.

**Mutants covered** (missed in run C): 260:31 `replace + with * in prove_bits` and
453:35 `replace + with * in Msm::add` (`n * 2` powers).

**Argument.** `powers(y, k)` returns `[1, y, y², …, y^(k−1)]`: a longer vector has the
same first `n + 2` entries. Every use indexes at most `n + 1` (`y_pows[n − i]`,
`y_pows[n + 1]`, `y_pows[half]`) or slices `y_pows[1..=n]`, and `2n ≥ n + 2` for every
`n ≥ 2`. The values read are identical; only unused powers are computed. The `-` and
`/` mutants of the same terms are caught.

## E15: zeroization on drop (crypto/src/janus.rs, keys.rs, nonce.rs, stealth.rs)

Decision: W4-MUTC (run C), for the Lead's review.

**Code.** The `Drop` implementations that wipe secret material when a value is
dropped: `Anchor` (janus.rs 48), `ViewKeys` (keys.rs 141), `WalletKeys` (208),
`WalletSeed` (217), `HedgedRng` (nonce.rs 102) and `SharedSecret` (stealth.rs 42),
each a `zeroize()` of its secret fields.

**Mutants covered** (missed in run C): each `replace <impl Drop for T>::drop with ()`,
6 mutants.

**Argument (unobservable, not equivalent).** The mutants do change the program: the
secret bytes stay in freed memory. But no safe Rust code can observe it: after `drop`
the value is gone, `Drop::drop` cannot be called explicitly, and reading the freed
memory needs `unsafe` (`ManuallyDrop::drop`, `ptr::drop_in_place` or a raw pointer),
which BlackSilk crates forbid (`#![forbid(unsafe_code)]`, brief §3). No test in the
repository's rules can kill them. This is a limit of the oracle, recorded as such:
the wiping is memory hygiene against a later memory disclosure (a core dump, swap, a
co-resident attacker), not a verdict. What protects it: code review (every secret
type's `Drop` is listed here) and the `zeroize` crate's own guarantees
(volatile writes plus a compiler fence). An entry here does not claim the wiping
works; it records that this census cannot tell.

## E16: withdrawn (killed)

`Hash for Point` → `()` was first exempted here as performance only. Red team
RT-MUTC killed it with `a_point_hashes_as_its_encoding` (crypto/src/point.rs): a
point hashes as its 32-byte encoding, so the mutant is observable through any
deterministic hasher. The number stays reserved.

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
re-examine this entry; the helper would then need a test AIR of its own. Both
premises are guarded by tests that fail when they stop holding (RT-MUTD):
`zkvm/tests/multi.rs` `no_table_commits_a_preprocessed_trace` (every table of 1 to
`MAX_EXECUTIONS` executions) and `px/tests/proof_limits.rs`
`quotient_chunks_do_not_depend_on_the_trace_length` (every PX table, every degree-bits
value `verify` accepts, 9 to 23).

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

## E20: the prebuild mark's drop guard (consensus/src/pow.rs)

Decision: mutation run D (docs/evidence/mutation-runD-2026-10-01/).

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

## E21: the first branch's edge in `seed_height` (consensus/src/pow.rs)

Decision: mutation run D, boundary pass (docs/evidence/mutation-runD-2026-10-01/,
§ Boundary pass: cargo-mutants 27.1.0 never turns `<=` into `<`). The same mutant and
argument as run C's E27, found independently by both boundary passes; kept as its own
entry because run D's evidence names it.

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

## E22: the prebuild thread numbers under release arithmetic (consensus/src/pow.rs)

Decision: mutation run D, release arithmetic (docs/evidence/mutation-runD-2026-10-01/,
`ovfPow`).

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

## E23: the sign split of the PX v1 balance at `v = 0` (tx/src/px.rs)

Decision: W4-MUTC (run C, boundary pass), for the Lead's review.

**Code.** In `check_px_balance`: `let scalar = if v >= 0 { Scalar::from(v as u128) }
else { -Scalar::from((-v) as u128) };`.

**Mutant covered:** 808:23 `replace >= with >` (boundary pass).

**Argument.** The versions differ only at `v = 0`, where the original computes
`Scalar::from(0) = 0` and the mutant `-Scalar::from(0) = −0 = 0`: the same scalar.
Every `v ≠ 0` takes the same branch in both. The balance rule itself, for both signs
of `v` and at `v = 0`, is tested (`px_v1_balance_holds_exactly_for_either_sign_of_v`).

## E24: compile-time assertions that still hold when made strict (tx/src/params.rs)

Decision: W4-MUTC (run C, boundary pass), for the Lead's review.

**Code.** `const _: () = assert!(..)` items: 49 `MAX_DEPLOY_BLOCK_BYTES <=
MAX_PX_BLOCK_BYTES` (1 MiB, 8 MiB), 50 `DEPLOY_FEE_PER_BYTE >= FEE_PER_WEIGHT` (50,
20), 127 `max_weight(64, 16) · FEE_PER_WEIGHT <= PX_STANDARD_FEE` (1 148 780,
8 912 896).

**Mutants covered:** 49:46 and 127:76 `replace <= with <`, 50:43 `replace >= with >`
(boundary pass).

**Argument.** A `const` assertion emits no code: a build either fails (the
assertion does not hold) or produces the same program. With the current constants
each stricter form still holds, so each mutant compiles to the unmutated program. The
assertions guard constant changes, not inputs; 48:49 (`MAX_DEPLOY_TX_SIZE <=
MAX_DEPLOY_BLOCK_BYTES`, both 1 MiB) fails to compile when made strict (unviable), and
the constants are pinned by `px_size_and_fee_constants_have_their_specified_values`.

## E25: `max_weight`'s clawback at two outputs (tx/src/params.rs)

Decision: W4-MUTC (run C, boundary pass; red team RT-MUTC found it first, its M6),
for the Lead's review.

**Code.** `let m = outputs.next_power_of_two(); if m <= 2 { size } else { size +
(320·m).saturating_sub(bp)·4/5 }`, with `bp = bpp_proof_len(outputs)`.

**Mutant covered:** 103:10 `replace <= with <` (boundary pass).

**Argument.** The versions differ only at `m = 2`, which is `outputs = 2` (`m = 1`
satisfies both conditions). There `bp = 32·(6 + 2·log2(64·2)) = 32·20 = 640 = 320·2`,
so the mutant adds `(640 − 640)·4/5 = 0`: the same weight. Checked for all 1 088 shapes
by tx/tests/max_weight_encoder.rs and the independent table
(tx/tests/data/max_weight.txt), which pass under the mutant.

## E26: the difficulty-overflow bound at exactly 2^64 (consensus/src/params.rs)

Decision: W4-MUTC (boundary pass over run A's scope), for the Lead's review.

**Code.** `ChainParams::check`: `if n.saturating_mul(n + 1).saturating_mul(t as u128)
>= 1 << 64 { DifficultyOverflow }`, after `2 <= t < 2^51` and `n >= 1` are checked
(`n` = `difficulty_window` as `u128`).

**Mutant covered:** 198:62 `replace >= with >` (boundary pass).

**Argument.** The versions differ only if `n(n + 1)·t = 2^64` exactly (a saturated
product is `u128::MAX`, not 2^64). Then `n(n + 1)` divides a power of two, so both `n`
and `n + 1` are powers of two; as they are coprime and consecutive, `n = 1`, and then
`t = 2^63`, which the earlier `t < 2^51` check refuses. No accepted parameter set
reaches the difference. The bound's off-by-one direction that matters (`+` → `-` and
`*` in `N·(N + 1)·T`) is killed by run A's exact edge at N = 1000.

## E27: `seed_height` at the first switch height (consensus/src/pow.rs)

Decision: W4-MUTC (boundary pass over run A's scope), for the Lead's review.

**Code.** `if height <= epoch + lag { 0 } else { (height - lag - 1) & !(epoch - 1) }`,
`epoch` a power of two.

**Mutant covered:** 28:15 `replace <= with <` (boundary pass).

**Argument.** The versions differ only at `height = epoch + lag`, where the mutant
computes `(epoch − 1) & !(epoch − 1) = 0`, the original's 0. Same seed height for
every input. `seed_schedule_matches_the_spec_for_every_valid_small_schedule` pins the
schedule around every switch.

## E28: the `pos < 8` guards of the Poseidon2 sponge (px-core/src/hash.rs)

Decision: W4-MUTC (boundary pass over run B's scope), for the Lead's review.

**Code.** `Sponge::absorb`: `if self.remaining == 0 || !canonical(x) || self.pos >= 8 {
invalid_input() }`; `hash`: `if !canonical(x) || pos >= 8 { invalid_input() }`. In
both, the position is incremented right after and reset to 0 when it reaches 8 (with a
permutation); `Sponge::pos` is private and starts at 0.

**Mutants covered:** 116:61 and 165:37 `replace >= with >` (boundary pass).

**Argument.** The position is always below 8 when the guard runs, so `pos >= 8` and
`pos > 8` are both false there: the guards are defensive (they replace the bounds
check, whose panic would carry a source location, R15-6). The mutants never change a
result, natively or in the guest. The other two terms of each guard are tested
(`sponge_refuses_each_invalid_input_through_the_hook`,
`hash_refuses_a_non_canonical_element_through_the_hook`). A change that lets `pos` reach
8 at the guard changes the kernel guest, hence its pinned id (`px/kernel.id`): that
pin is the tripwire for re-examining this entry.

**Reproduce (E23–E28).** `tools/boundary-mutants.sh run` with the oracles of the run C
evidence (§ Boundary pass); `BM_FILTER` selects one mutant.

## E29: the varint's continuation bit and loop bound (tx/src/codec.rs)

Decision: mutation run E (docs/evidence/mutation-runE-2026-10-01/), for the Lead's
review.

**Code.** `Writer::varint`: `while v >= 0x80 { self.buf.push((v as u8 & 0x7f) |
0x80); v >>= 7; }`. `Reader::varint`: `for i in 0..10 { let b = self.u8()?; … if i
== 9 && (b & 0x80 != 0 || low > 1) { return Err(VarintOverflow) } … if b & 0x80 ==
0 { … return Ok(value) } } unreachable!(…)`.

**Mutants covered:** 52:44 `replace | with ^` (cargo-mutants); the hand mutant
`0..10` → `0..11` in `Reader::varint` (§ Hand mutants of the evidence).

**Argument.** (1) `as` binds tighter than `&`, so the left operand is `(v as u8) &
0x7f`, whose bit 7 is always 0. For such a byte `x`, `x | 0x80 = x ^ 0x80 = x +
0x80`: the same byte for every input. (2) At `i = 9` the loop body either returns
`Ok` (the byte ends the varint) or returns `VarintOverflow` (a continuation bit, or a
value bit past 64): no iteration with `i = 9` falls through, so a bound above 10 is
never reached. The other bound mutants are caught (`0..9` reaches `unreachable!`,
`i == 8` refuses ten-byte values, `low > 0` and `low > 2` change the 64-bit edge).
The encoding is pinned by `varint_round_trip`, the exhaustive two-byte uniqueness
test and every transaction vector.

## E30: `Transfer::weight`'s clawback at two outputs (tx/src/types.rs)

Decision: mutation run E, boundary pass and hand mutants, for the Lead's review.

**Code.** `let m = self.outputs.len().next_power_of_two() as u64; if m <= 2 { return
size; } … size + (320 * m).saturating_sub(bp_size) * 4 / 5`: the clause of
`params::max_weight` (E25), on an actual transfer.

**Mutants covered:** 327:14 `replace <= with <` (boundary pass) and the hand mutant
`m <= 2` → `m <= 1` (§ Hand mutants of the evidence).

**Argument.** As E25: the versions differ only at `m = 2` (`m = 1` satisfies every
form), where the range proof of a transfer with two outputs has `7` rounds and
`bp_size = 32·(6 + 2·7) = 640 = 320·2`, so the clawback adds `0·4/5 = 0`: the same
weight. A transfer has at least `MIN_OUTPUTS` = 2 outputs, so `m = 1` never occurs.

## E31: `statement`'s guard, which both callers check first (px/src/prove.rs)

Decision: mutation run E, for the Lead's review.

**Code.** `fn statement(public, calls, budgets, window, h_tx)` begins `if public.n_fn >
MAX_FN || calls.len() != public.n_fn || budgets.len() != calls.len() { return None;
}`. It is private; its only callers are `verify` and `check_shape_bits`, which both
return `Shape` first when `public.n_fn > MAX_FN || calls.len() != public.n_fn`, and
then build `budgets` with one entry per call (or return `Unregistered`).

**Mutants covered:** 166:29 and 166:59 `replace || with &&` (cargo-mutants).

**Argument.** Whenever `statement` runs, each of the three terms is false (the first
two by the caller's check, the third by construction), so the guard is false in the
original and under either mutant: `statement` never returns `None` from it. The
callers' guards are killed by tests (`verify_judges_the_statement_before_the_proof`
and run D's `the_shape_check_accepts_exactly_the_statements_degree_bits`), including
`n_fn = MAX_FN + 1` with as many calls, which must be `Shape` and not a panic.

## E32: one more main-chain entry before the truncation in `missing_bodies` (chain/src/manager/header_sync.rs)

Decision: mutation run E, for the Lead's review.

**Code.** `missing_bodies(max)`: the header-best chain is scanned from the fork
`while out.len() < max { … out.push((h, id)) … h += 1 }`, the heavier side branches
are walked back and appended (`seen` keeps ids unique), then `out.sort_by_key(|&(h,
_)| h); out.truncate(max)`.

**Mutant covered:** 68:29 `replace < with <=` (cargo-mutants).

**Argument.** The mutant adds at most one more main-chain entry, at a height above
every main-chain entry already listed, and only when `max` of them were listed. After
the stable sort by height those `max` entries all come before it, so the truncation
to `max` drops it: the same list. Its id in `seen` changes nothing either: if a side
branch's walk passes that header, the original appends it from the walk instead,
the same entry, which the truncation drops in the same way; every other entry is
listed as before. The cap itself
(at most `max` entries, lowest heights first) is tested (tests/manager.rs
`headers_without_bodies_do_not_move_the_state`, tests/fork_choice.rs).

## E33: log lines of block submission (chain/src/manager/submission.rs)

Decision: mutation run E, for the Lead's review (as E12 for fork choice).

**Code.** In `submit_inner`, on a store failure that reaches the limit: `if
!self.store_failed { log::error!("block store failed …") } self.store_failed = true;`.
In `drain_ready`: `if self.tip_id() != before { log::debug!("tip … at height …") }`.

**Mutants covered:** 140:24 `delete !`, 211:26 `replace != with ==` (cargo-mutants).

**Argument.** Both conditions guard only a log line. For the first, `submit_inner`
refuses every persisting submission once `store_failed` is set (its first check), so
at the guard `store_failed` is always false: the mutant removes the error line and
nothing else; `store_failed` is set in both versions, and the refusal that follows it
is tested (tests/storage_recovery.rs, the full-disk test). The second only changes
when a debug line is written. No test observes the log; the behaviour is the same.

## E34: the capacity check of the full test tree (px/src/tree.rs)

Decision: mutation run E, boundary pass, for the Lead's review.

**Code.** `Tree::append`: `let pos = self.size(); if pos >= CAPACITY { return
Err(TreeFull) }`. `Tree` keeps every node (`levels[0]` holds every leaf); it is the
reference tree of tests and of the wallet's tree tests, used by no node or wallet
code path (the consensus tree is `Frontier`, whose capacity check, 64:22, is killed
by `the_last_append_keeps_the_full_root`).

**Mutant covered:** 151:16 `replace >= with >` (boundary pass).

**Argument.** The versions differ only for an append at `pos = CAPACITY = 2^32`,
which needs a `Tree` already holding 2^32 leaves: 128 GiB for `levels[0]` alone, and
`Tree` has no test constructor that skips appending (`Frontier::uniform_for_tests`
exists for that reason). No test can reach the edge, and no product path builds a
`Tree`. The consensus rule at that edge, `TreeFull` from the frontier and the block
rule that refuses a block past capacity, is tested (px state and tree tests,
tx/tests/tree_capacity.rs).

## E35: the locator's length cap, unreachable below 2^54 blocks (chain/src/manager/header_sync.rs)

Decision: mutation run E, boundary pass and hand mutants, for the Lead's review.

**Code.** `locator`: `loop { out.push(id at h); if h == 0 || out.len() >= 63 {
break } if out.len() >= 10 { step *= 2 } h = h.saturating_sub(step) }`, then the
genesis id if the last entry is not it: at most 64 ids (`MAX_LOCATOR`).

**Mutants covered:** 19:36 `replace >= with >` (boundary pass); the hand mutants `63`
→ `62` and `63` → `64` (§ Hand mutants of the evidence).

**Argument.** The first 10 entries step by 1, then the step doubles each entry, so
entry `10 + k` lies `9 + (2^(k+1) − 2)` blocks below the tip, and `h` reaches 0 by
entry `10 + k` once `2^(k+1) + 7 ≥ height`. The cap of 63 entries is reached first
only for a best header chain above `2^54 + 7` blocks (`k = 53`), which no chain
reaches (2^54 blocks at the 120 s target is over 6·10^10 years); a cap of 62
binds above `2^53 + 7` blocks, equally out of reach. Below that the loop
always ends at `h == 0` with fewer than 63 entries, and the three mutants change
nothing. The bound that matters to peers, at most 64 ids in a `GetHeaders`, is the
message decoder's (`MAX_LOCATOR`), and the locator's shape is tested
(`locator_and_headers_after`).

## E36: the trim of a request locator over `MAX_LOCATOR`, unreachable (p2p/src/net/headers.rs)

Decision: mutation run E, for the Lead's review.

**Code.** `request_headers_after(peer, Some(id))`: `locator.retain(|h| *h != id);
locator.insert(0, id); if locator.len() > MAX_LOCATOR as usize {
locator.remove(locator.len() - 2); }`, where `locator` is the published summary's,
`ChainManager::locator()`'s (`MAX_LOCATOR` = 64).

**Mutants covered:** 140:30 `replace > with ==` and `replace > with >=`; 142:46
`replace - with +` and `replace - with /` (cargo-mutants).

**Argument.** The trim runs only when the summary's locator holds 64 ids and `id` is
not among them. `locator()` holds at most 63 entries before the genesis, and reaches
that many only for a best header chain above `2^54 + 7` blocks (E35); below that it
holds at most `10 + log2(height) + 1` ids (about 45 at 2^32 blocks), so the edited
locator never exceeds 64 and the branch, in either form, never runs: with `==` or
`>=` at 64 ids it would need a 64-id summary locator, and the two removals only run
inside the branch. The edit itself (`id` first and once, then our chain down to the
genesis) is tested (`a_request_after_a_batch_starts_its_locator_at_the_batch`), which
also kills `>` → `<` (the removal of `id` from a short locator), and the decoder
refuses a `GetHeaders` of more than 64 ids from any peer.

## E37: the skip test of the parallel proof-of-work jobs (wallet/src/headers.rs)

Decision: mutation run E, for the Lead's review.

**Code.** `first_failure(pow, jobs, threads, computed)`: each worker loops `let i =
next.fetch_add(1); if i >= jobs.len() || i > failed.load() { return } … if
!check_hash(..) { failed.fetch_min(i) }`, `failed` starting at `usize::MAX`.

**Mutant covered:** 412:33 `replace > with >=` (cargo-mutants).

**Argument.** The versions differ only when `i == failed` at the test. `failed` is
`usize::MAX` or the index of a job whose hash was computed and failed; that job's
index was taken from `next` by the thread that computed it, after its own test, and
`fetch_add` hands every index out once. A thread tests `i` right after taking it, so
no other job can have failed at `i` yet: `i ≠ failed` at every test, and the skip
condition is the same. The verdict (the first failing job in chain order, every job
before it computed) is tested against the sequential check on 1, 2, 4 and 8 threads
(`parallel_and_sequential_verdicts_agree`).

## E38: equivalent mutants of header verification (p2p/src/net/headers.rs)

Decision: mutation run E, for the Lead's review.

**Mutants covered** (cargo-mutants), each with its argument:

- **576:36 `replace || with &&`** in `precheck`: `let jobs = if first.is_empty() ||
  !worth { None } else { c.pow_jobs(&headers[first]) }`. The mutant computes the
  first chunk's jobs also when the batch is not worth verifying (and asks
  `pow_jobs` for an empty slice, which returns `None`). `verify_headers` returns
  `LowWork` for a batch that is not worth verifying before it reads `jobs`, and
  `pow_jobs` only reads the header tree: the same outcome, no hash, no state change.
- **729:21 `replace += with -=` and `with *=`** in `verify_headers`: the `Ok(n)` arm
  after accepting the unknown-version header alone, marked "Not reached". A header
  whose version no epoch of the schedule uses is never valid (`check_rules` returns
  `UnknownUpgrade` or `InsufficientWork`), so it is never stored, and
  `accept_headers` cannot return `Ok` for it (it skips only stored headers).
- **747:12 `replace > with >=`** (`new > 0` in the live-arrival test `new > 0 &&
  on_main && !full && last.height > ours_before`): the versions differ only for
  `new = 0` with the rest true, a batch that stored nothing whose last header is on
  the best header chain above `ours_before`, the best header height when the batch
  was taken up. Every header of such a batch was stored before, and a stored header
  on the best chain is at most `ours_before` high (the worker takes batches one at a
  time; the summary it reads is published before the actor answers the previous
  batch's last command). The other terms of the test are killed by
  `clock_samples_come_from_live_arrivals_only` and
  `note_clock_samples_refused_headers_and_live_arrivals`.

## E39: a sender's departure inside the pre-check, and a cancelled PoW task (p2p/src/net/headers.rs)

Decision: mutation run E, an oracle limit (as E19), for the Lead's review.

**Mutants covered:** 668:14 `replace > with >=` (`if k > 0 && !sender_live(…)` between
proof-of-work chunks); 489:23 `replace match guard e.is_panic() with true` (the
header worker's `Err(e) if e.is_panic() => fatal(…)`, `Err(_) => return`).

**Argument.** Neither is equivalent; each differs only inside a window no test can
place an event in without a hook in the product:

- 668:14: `verify_headers` reads the sender's liveness before its pre-check command and
  returns `Abandoned` after it if the sender had left by then. With `>=` the check
  also runs before the first chunk, so a sender that leaves while its pre-check
  command runs costs no chunk instead of one. A test cannot make the departure fall
  between the liveness read and the end of that command (holding the chain lock
  delays the command, but not the worker's read before it; tried, and the batch was
  abandoned before either). The bound that matters, at most one chunk of hashes for
  a sender that left, holds in both, and the checks between chunks are killed by
  `a_departed_senders_batch_stops_at_the_next_chunk` (`>` → `==`, `<`).
- 489:23: the `spawn_blocking` task of `verify_headers` ends in a non-panic
  `JoinError` only when the runtime cancels it at shutdown, when the worker itself
  is being dropped. The panic branch is killed by
  `a_panic_in_the_header_pow_jobs_stops_the_node` (a child process that must exit
  with `POISONED_EXIT_CODE`).

## E40: the tip-age limits at their exact second (wallet/src/wallet/sync.rs)

Decision: mutation run E, an oracle limit (as E19), for the Lead's review.

**Code.** `note_tip_age`: `let age = unix_now().saturating_sub(header.timestamp); … if
age > warn { warning }`; `check_fresh_tip`: `Some((height, age)) if age > refuse =>
Err(StaleTip)`, with `tip_age()` reading `unix_now()` again.

**Mutants covered:** 576:16 and 618:40 `replace > with >=` (cargo-mutants).

**Argument.** The versions differ only when the age equals the limit to the second.
Both ages are read from the system clock at the time of the call, and the wallet has
no injectable clock: a test that stamps the tip at `now − limit` sees an age of
`limit` or `limit + 1` depending on when the second turns, so the edge cannot be
checked deterministically. Both limits are pinned by value
(`a_withheld_tip_is_reported_and_blocks_transactions`: 10 and 60 target block times
plus the future time limit), and the warning and the refusal are tested 60 s past
each limit and below it. A clock seam (an injected `now`) would make the edge
testable; it is a product change, not made here.

## E41: the sampling threshold's two edges (wallet/src/headers.rs)

Decision: mutation run E, boundary pass, for the Lead's review.

**Code.** `HeaderCheck::build`: `let threshold = if samples >= expected.max(1) {
u64::MAX } else { ((u64::MAX as u128 * samples as u128) / expected.max(1) as u128) as
u64 };` `precheck`: `let sampled = force_pow || self.rng.next_u64() <= self.threshold;`.

**Mutants covered:** 185:36 `replace >= with >` and 371:56 `replace <= with <`
(boundary pass).

**Argument.** 185:36: the versions differ only at `samples == expected`, where the
mutant computes `u64::MAX · samples / samples = u64::MAX`, the original's value. 371:56:
the versions differ only for a draw equal to the threshold, one value of 2^64 for
each header, drawn from a ChaCha20 stream seeded by the OS RNG: no test can make or
observe it, and a sampled header is a probabilistic check in both versions. The rate
itself is tested (`the_header_check_samples_at_the_requested_rate`), as are full and
forced sampling.

## E42: `prove`'s checks after proving that repeat the checks before it (px/src/prove.rs)

Decision: mutation run E, for the Lead's review.

**Code.** `prove` runs the kernel guest and every function first: the kernel's exit
code must be 0 (`kernel_exec.exit_code != 0` → error), and each function must exit 0
and write the kernel's prefix (`exec.output.len() < PREFIX_WORDS ||
exec.output[..PREFIX_WORDS] != prefix` → `FunctionMismatch`). It then proves the same
programs on the same inputs (`prove_shaped` runs them again) and checks the proven
statement: `st.exit_code != 0 || st.output != public_words(&public)` (293) and, per
function, `part.output.len() < PREFIX_WORDS || part.output[..PREFIX_WORDS] != prefix`
(309).

**Mutants covered:** 293:26 and 309:45 `replace || with &&` (cargo-mutants; the
proving run `provingP1`, release, with the PX-proving unified test).

**Argument.** The BVM-1 interpreter is deterministic: `prove_shaped` re-runs the same
program on the same input to the same exit code and output as the runs before
proving. 309:45: when the first test passed, `part.output` is the same prefix-led
output, so `len < PREFIX_WORDS` is false and the slice equals the prefix: both forms
are false. 293:26: the kernel's exit code is 0 here (checked before), so the original
is `st.output != public_words(&public)` and the mutant is `false`; they differ only if
the pinned kernel guest's output differs from the native kernel's public statement
for an accepted witness, which the kernel's differential tests and fuzzing exclude
(`a_real_transfer_is_accepted_natively_and_by_the_guest`, px/tests/fuzz.rs) and which
`verify` would refuse anyway (the statement is rebuilt from `public`). The other
mutants of both lines (`!=` → `==`, `<` → `==`, `>`, `<=`, the exit codes) are killed
by the proving tests (§ px/src/prove.rs).

## E43: the maintenance loop's timeouts at their exact instant (p2p/src/net/maintenance.rs)

Decision: mutation run E, an oracle limit (as E40), for the Lead's review.

**Code.** `maintenance_loop` reads `let now = Instant::now()` once per tick and compares
it with instants recorded elsewhere: `now >= p.next_inv` (the trickle delay, 119);
`now.duration_since(t) > LIMIT` for a seed's address fetch (128), an unanswered ping
(133), the ping interval (136), a header request (142), block and transaction
requests (157, 171), the outbound round (216) and the save interval (228); and
`now.duration_since(t) <= LIMIT` for keeping late block and transaction requests
(167, 179).

**Mutants covered:** 128:59, 133:49, 136:59, 142:60, 157:62, 171:62, 216:46 and
228:46 `replace > with >=` (cargo-mutants, `rerunM`); 119:51 `replace >= with >`,
167:60 and 179:55 `replace <= with <` (boundary pass, `bndM2`).

**Argument.** Each pair of versions differs only when the elapsed time equals the
limit exactly, to the resolution of the monotonic clock (100 ns on Windows, 1 ns on
Linux), at the one tick that reads that instant; at the next tick (50 ms in the tests,
250 ms by default) both versions take the same action. `Instant` cannot be set and the
loop has no injectable clock, so no test can arrange the equality, and in operation
the difference is one tick, with probability about zero. Each rule is tested on both
sides with margins: `requests_time_out_after_their_timeouts_and_late_ones_are_kept_as_long`
and `late_transaction_requests_are_capped` (block and transaction requests, late
requests, set in the state with ages 10 s below and above each limit),
`a_header_request_times_out_after_the_headers_timeout`,
`an_answering_peer_is_pinged_once_per_interval`,
`a_peer_that_never_answers_a_ping_is_left_after_the_pong_timeout`,
`an_announcement_waits_for_its_trickle_delay`,
`a_silent_seed_has_the_whole_timeout_to_answer`,
`outbound_connections_are_maintained_every_two_seconds` and
`the_first_save_of_the_address_table_comes_5_s_after_the_start`; every other mutant of
these lines is killed (`rerunM`, `bndM2`).

## E44: the upper side of two unnamed delays of the maintenance loop (p2p/src/net/maintenance.rs)

Decision: mutation run E, an oracle limit, for the Lead's review, with a
recommendation (below).

**Code.** `maintenance_loop` starts with `let mut last_save = Instant::now() -
SAVE_INTERVAL + Duration::from_secs(5);` ("Save soon after the first change"): a
changed table is first saved 5 s after the start, then at most every `SAVE_INTERVAL`
(60 s). It runs `maintain_outbound` when `now.duration_since(last_outbound) >
Duration::from_secs(2)` (docs/p2p.md §9: "`maintain_outbound`, every 2 s").

**Mutants covered** (hand mutants, missed in `handM2`, `handM3` and `handM4`): 84 the
first save's `from_secs(5)` → `from_secs(6)`; 216 the outbound round's `from_secs(2)`
→ `from_secs(3)`. (`handM3` reported the second caught: four network tests timed out
while the release test suite ran beside it; alone, in `handM4`, it was missed.)

**Argument.** Both are literals, not named constants, so no test can state them by
value, as the tests now state `KEY_EXCHANGE_TIMEOUT`, `HANDSHAKE_TIMEOUT`,
`HANDSHAKE_DEADLINE`, `IDLE_TIMEOUT`, `PONG_TIMEOUT` and `SAVE_INTERVAL`. Their lower
sides are tested exactly, since a delay never ends early
(`the_first_save_of_the_address_table_comes_5_s_after_the_start`: not before 4.5 s;
`outbound_connections_are_maintained_every_two_seconds`: dials at least 1.8 s apart;
the mutants 4 s and 1 s are caught). The upper sides need a bound on when an event is
observed, which load moves: in this run a 5 s close was observed after more than
7.5 s (`facb993`), and the 3 s round "failed" four tests only under load. The first
save's 5 s is not a specified value (docs/p2p.md §9 promises a save "within a minute
of changing", which 6 s keeps); the round's 2 s is (a round every 3 s is a change of
the documented behavior that no test notices).

**Recommendation.** Name both delays as constants (for example `FIRST_SAVE_DELAY` and
`OUTBOUND_ROUND`) and state them in a test, as the timeouts are; this run changes no
product code, so it is left to the Lead.
