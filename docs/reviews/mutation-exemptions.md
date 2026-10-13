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

## E40: withdrawn (killed)

The tip-age limits at their exact second (wallet/src/wallet/sync.rs 576:16 in
`note_tip_age` and 618:40 in `check_fresh_tip`, `replace > with >=`) were first exempted
here as an oracle limit (no injectable clock). Decision RT-MUTE: the red team's
`the_tip_age_limits_are_strict_at_their_exact_second` (wallet/src/wallet/tests_sync.rs)
reads the clock in whole seconds and repeats a try that crosses a second boundary, so a
tip exactly `warn` or `refuse` old is tested; it kills both mutants (`f2w` in
docs/evidence/mutation-runE-2026-10-01/: 2 of 2 caught). The number stays reserved.

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

## E43: the maintenance loop's comparisons against constant limits, no clock seam (p2p/src/net/maintenance.rs)

Decision: mutation run E, an oracle limit; reworded and narrowed by decision RT-MUTE.

**Code.** `maintenance_loop` reads `let now = Instant::now()` once per tick and compares
it with instants recorded elsewhere, against limits that are constants:
`now >= p.next_inv` (the trickle delay, 119); `now.duration_since(t) > LIMIT` for an
unanswered ping (`PONG_TIMEOUT`, 133), a header request (`HEADERS_TIMEOUT`, 142), block
and transaction requests (`BLOCK_TIMEOUT`, `TX_TIMEOUT`, 157, 171), the outbound round
(`OUTBOUND_ROUND`, 216) and the save interval (`SAVE_INTERVAL`, 228); and
`now.duration_since(t) <= LIMIT` for keeping late block and transaction requests (167,
179).

**Mutants covered:** 133:49, 142:60, 157:62, 171:62, 216:46 and 228:46 `replace > with
>=` (cargo-mutants, `rerunM`); 119:51 `replace >= with >`, 167:60 and 179:55 `replace
<= with <` (boundary pass, `bndM2`). Withdrawn (RT-MUTE): 128:59 and 136:59, the
address-fetch timeout and the ping interval, whose limits are configurable: the red
team's `an_elapsed_time_equal_to_a_zero_limit_does_not_trigger_it` sets both to zero
and the recorded instants in the future, so `duration_since` saturates to exactly the
limit at every tick; it kills both (`f2p`: 2 of 2 caught).

**Argument.** Each pair of versions differs only when the elapsed time equals a
constant limit exactly, to the resolution of the monotonic clock (100 ns on Windows,
1 ns on Linux), at the one tick that reads that instant; at the next tick (50 ms in the
tests, 250 ms by default) both versions take the same action. A test cannot set a
constant limit to zero, `Instant` cannot be set, and the loop has no clock seam (an
injected `now`), so no test can arrange the equality; for 119:51 the instant compared
is `next_inv`, set from an exponential draw. Each rule is tested on both sides with
margins: `requests_time_out_after_their_timeouts_and_late_ones_are_kept_as_long` and
`late_transaction_requests_are_capped` (block and transaction requests, late requests,
set in the state with ages 10 s below and above each limit),
`a_header_request_times_out_after_the_headers_timeout`,
`a_peer_that_never_answers_a_ping_is_left_after_the_pong_timeout`,
`an_announcement_waits_for_its_trickle_delay`,
`outbound_connections_are_maintained_every_two_seconds` and
`the_first_save_of_the_address_table_comes_5_s_after_the_start`; the constants are
pinned by value; every other mutant of these lines is killed (`rerunM`, `bndM2`). A
clock seam would make the edges testable; it is a product change, not made here.

## E44: the upper side of the first save's delay and the outbound round (p2p/src/net/maintenance.rs)

Decision: mutation run E, confirmed by decision RT-MUTE, which also had the two delays
named (`a91c178`, a refactor with no behavior change): `FIRST_SAVE_DELAY` (5 s) and
`OUTBOUND_ROUND` (2 s, docs/p2p.md §9), pinned by value in
`the_first_save_delay_and_the_outbound_round_are_the_specified_ones`.

**Mutants covered:** the hand mutants 5 s → 6 s of the first save and 2 s → 3 s of the
outbound round, as run E made them on the literals (missed in `handM2`, `handM3` and
`handM4`). (`handM3` reported the second caught: four network tests timed out while
the release test suite ran beside it; alone, in `handM4`, it was missed.) Their
successors, the constants ± 1 s, are caught by the pinning test.

**Argument.** The lower sides are tested exactly, since a delay never ends early
(`the_first_save_of_the_address_table_comes_5_s_after_the_start`: not before 4.5 s;
`outbound_connections_are_maintained_every_two_seconds`: dials at least 1.8 s apart).
The upper sides need a bound on when an event is observed, which load moves (a 5 s
close was observed after more than 7.5 s, `facb993`); the value itself is now stated
by the pinning test, so what this entry keeps is only the behavior test's upper side.

## E51: `range_word` slices whose end is mutated (zkvm/src/air/alu_mul.rs, alu_shift.rs)

Decision: W4-MUTAIR (the AIR census, docs/evidence/mutation-air-2026-10-02), for the
Lead's review. E29–E44 are run E's.

**Code.** `range_word(bld, &r[A..A + 4], real)` (alu_mul.rs:109, `A = 4`; :110,
`B = 8`; alu_shift.rs:67, `A = 3`). `util::range_word` reads `w[0..4]` only.

**Mutants covered:** alu_mul.rs 109:29 and 110:29, alu_shift.rs 67:29 `replace + with
*` (the slice end `A + 4` becomes `4·A`: 16, 32 and 12, all within the row).

**Argument.** The slice keeps its start and its first four elements, the only ones
`range_word` reads; no constraint or lookup changes.

## E52: `INS + f::FLAGS` with `f::FLAGS = 0` (zkvm/src/air/cpu.rs)

Decision: W4-MUTAIR, for the Lead's review.

**Mutant covered:** cpu.rs 108:31 `replace + with -` (`r[INS + f::FLAGS + k]` becomes
`r[INS - f::FLAGS + k]`).

**Argument.** `f::FLAGS = 0` (program.rs), so both index the same column. A change
of the layout constant changes the program table's fields and the circuit
fingerprint.

## E53: `KB + 2` with `KB = 2` (zkvm/src/air/memory.rs)

Decision: W4-MUTAIR, for the Lead's review.

**Mutant covered:** memory.rs 105:24 `replace + with *` (`r[KB + 2]` becomes
`r[KB * 2]`).

**Argument.** `KB = 2`, and `2 + 2 = 2 · 2`: the same column.

## E54: withdrawn (killed)

`poseidon::p2_width` (zkvm/src/air/poseidon.rs 252:5, `replace p2_width -> usize with
0` and `with 1`) was first exempted here as dead code. Decision RT-MUTAIR: it is now
tested (`the_poseidon2_sub_air_width_is_its_column_count`, zkvm/tests/air_tamper.rs:
`p2_width() = P2_COLS`), which kills both mutants. The number stays reserved.

## E55: other register bases (zkvm/src/air/util.rs)

Decision: W4-MUTAIR, for the Lead's review.

**Code.** `pub const REG_BASE: u32 = 1 << 26;` Register `r` is memory-argument key
`REG_BASE + r`, memory words are keys `address / 4`.

**Mutants covered:** util.rs 76:29 `replace << with >>` (`REG_BASE = 0`), and the hand
mutant H02 (`REG_BASE = 2^26 + 1`).

**Argument.** The base only relabels the 32 register keys; it matters only if a
register key equals a memory key some trace can use. Memory keys are `< 2^26`
(addresses are range-checked `< 2^28`, cpu.rs:291, poseidon.rs:110-114) and, for every
access a valid trace makes, `≥ 0x400`: loads and stores check `address ≥ NULL_GUARD =
0x1000` (cpu.rs:320-337), `POSEIDON2` buffers start at `CODE_END` or above
(cpu.rs:441-451), and image words lie at or above the code base, which the loader
keeps at or above `NULL_GUARD`. So base 0 (keys 0–31) and base `2^26 + 1` (keys up to
`2^26 + 32 < 2^27`, within `MEM_INIT`'s key range) never meet a memory key. A base
that does alias, `2^26 − 1` (hand mutant H01), is caught by
`the_top_memory_word_and_the_registers_have_distinct_keys`.

## E56: `range_bits`'s `bits ≤ 8` guard (zkvm/src/air/util.rs)

Decision: W4-MUTAIR (boundary pass), for the Lead's review.

**Mutant covered:** util.rs 176:18 `replace <= with <` in `assert!(bits <= 8)`.

**Argument.** Every call passes 3, 4, 6 or 7 bits (`grep range_bits zkvm/src/air`),
so the guard holds strictly; it never runs at 8. A call with 8 bits would be
`range_pair(x, x)`, still sound.

## E57: nine blinding values (zkvm/src/air/util.rs)

Decision: W4-MUTAIR (constant hand mutants), for the Lead's review.

**Mutant covered:** hand mutant H04, `BLIND_VALUES = 9`.

**Argument.** The requirement is at least `EXTENSION_DEGREE = 8` values, so the
blinding offsets reach the whole extension field (util.rs, ZK-F29); nine meets it and
only widens every table by a column. Soundness does not depend on the count. Seven
(H03) is caught by `a_blinding_message_spans_the_extension_field`. A change of the
count changes the circuit fingerprint.

## E58: local and exclusive interactions in the oracle (zkvm/src/air/check.rs)

Decision: W4-MUTAIR (run B), for the Lead's review.

**Code.** `EvalBuilder` and `FingerprintBuilder` implement
`push_local_interaction` and `push_exclusive_interaction`; `check` and
`MutationChecker::caught` sum local interactions; `shapes` counts
`global.len() + local.len()`.

**Mutants covered:** check.rs 98:9, 108:9, 110:75 (×2), 206:43 (×2), 209:42, 350:62
(×2), 353:62 (×2), 356:38, 415:46 `replace + with -`, 528:9, 540:9.

**Argument.** No BVM-1 table emits a local or an exclusive interaction: every bus
use in `zkvm/src/air` is `lookup_key`, `table_entry` or `push_interaction`, and
Plonky3's `Poseidon2Air` emits none (`grep -rn
'local_interaction\|exclusive' zkvm/src` finds only these two builders). With no such
interaction the mutated code runs on empty lists. If a table ever uses one, these
mutants become live and need a test.

## E59: the bus test of `MutationChecker::caught` on a balanced baseline (zkvm/src/air/check.rs)

Decision: W4-MUTAIR (run B), for the Lead's review.

**Mutant covered:** check.rs 370:68 `replace + with -` in `buses[k] + d != 0`.

**Argument.** `MutationChecker::new` asserts the baseline valid, so every stored sum
`buses[k]` is 0, and `0 + d` and `0 − d` are zero together.

## E60: the last-row flag of `MutationChecker` when it is never set (zkvm/src/air/check.rs)

Decision: W4-MUTAIR (run B), narrowed by decision RT-MUTAIR.

**Code.** `eval_row`: `last: Val::from_bool(r == h - 1)`, used only by
`MutationChecker`, whose callers change one cell.

**Mutants covered:** check.rs 261:37 `replace - with +` and `with /` (the flag is never
set: `r == h + 1` and `r == h` hold on no row). The third mutant, 261:32 `replace ==
with !=` (the flag set on every other row), is killed by the red team's zero-delta
probes on rows 0, 1, `h/2` and `h − 1` of every table
(`the_mutation_checker_agrees_with_the_full_checker`).

**Argument.** The only last-row constraint of any table is the CPU's
`real · (1 − sh) = 0` (cpu.rs:167). A single-cell change that breaks it on a valid
trace's last row also breaks a rule the mutants leave intact: setting `real` to 1 on a
padding row looks up an all-zero instruction that the program table never provides;
changing `sh` on a halting row breaks `sh + srd + swr + sp2 = ecall`; changing `real`
on a halting row breaks the padding rows' zero fields. So a checker that never applies
the last-row rule answers every single-cell probe the same way.

## E61: rejection sampling of blinding values (zkvm/src/air/trace.rs)

Decision: W4-MUTAIR (run B), for the Lead's review.

**Code.** `uniform`: `let x = rng.next_u32() & 0x7fff_ffff; if x < Val::ORDER_U32 {
return Val::from_u32(x) }`.

**Mutants covered:** trace.rs 462:32 `replace & with ^`, 463:14 `replace < with <=`.

**Argument.** `^ 0x7fff_ffff` flips the low 31 bits, a bijection of them, and keeps
bit 31, so an accepted `x` is uniform on `[0, p)` as before (only the acceptance
rate changes). `<=` also accepts `x = p`, returned as 0: a statistical distance of
about `2^−31` per value from uniform, below anything a test or an observer can
measure. The mutants that bias the values (`<` to `>`) or never return (`&` to `|`,
`<` to `==`) are caught by `blinding_values_cover_the_field` or hang.

## E62: the default `BlockStore::bind` (chain/src/store.rs)

Decision: W4-MUTF (run F), confirmed by the Lead's review (read, not run).

**Code.** The trait default: `let _ = identity; Ok(())`.

**Mutants covered:** store.rs 192 `replace bind -> io::Result<()> with Ok(())`.

**Argument.** The mutant is the same code: the default already ignores its argument and
returns `Ok(())`. Stores that bind (`FileStore`) override it and are tested.

## E63: `<=` for `<` in `FileStore::load`'s record loop (chain/src/store.rs)

Decision: W4-MUTF (run F), confirmed by the Lead's review (read, not run).

**Code.** `while pos < data.len() { match codec.parse_frame(&data[pos..]) { ... } }`.

**Mutants covered:** store.rs 849 `replace < with <=`.

**Argument.** The only extra pass is at `pos == data.len()`. There `parse_frame(&[])`
returns `Err("short header")`, `next_valid_record(.., len + 1)` finds nothing (no panic),
the file is truncated to its own length and the loop ends: the same records and the
same file. Not strictly identical: every clean load also logs a "truncating damaged
tail, 0 bytes dropped" warning and makes one extra `set_len` and `fsync`. Under an I/O
fault in those calls it returns `Err` where the original returns `Ok`. No test can
tell the two apart without fault injection; the difference is diagnostic only.

## E64: `pos * 1` for `pos + 1` in `FileStore::load`'s damage search (chain/src/store.rs)

Decision: W4-MUTF (run F), confirmed by the Lead's review (read, not run).

**Code.** `if let Some(at) = next_valid_record(codec, &data, pos + 1)`.

**Mutants covered:** store.rs 876 `replace + with *`.

**Argument.** Starting the search at `pos` rather than `pos + 1` adds one candidate:
the frame just found not to parse. `next_valid_record` re-runs `parse_frame` on exactly
that input, which fails again deterministically, and moves on; the only cost is one
redundant parse. The answer is the same for every input.

## E65: the "helper ended" log guard, `<` to `>` (chain/src/manager/pow_cache.rs)

Decision: mutation run G (freeze gate 1.1), batch G9, for the Lead's review. E65–E86
are run G's ([evidence](../evidence/mutation-runG-2026-10-12/README.md)).

**Code.** `HashPool::start`: `let before = workers.len(); workers.retain(|h|
!h.is_finished()); if workers.len() < before { log::error!(…) }`, then the loop that
starts helpers until there are `wanted`.

**Mutant covered:** 289:26 `replace < with >` (cargo-mutants).

**Argument.** `Vec::retain` only removes elements, so after it `workers.len() >
before` is never true: the mutant deletes the log line and nothing else. The
original's branch is unreachable as well while the pool is open: `Queue::serve` runs
every batch under `catch_unwind` (the guard also covers dropping the ticket), its lock
and condition-variable waits recover from poisoning, and it returns only once
`closed` is set, which only `HashPool`'s `Drop` does; `start` takes `&self`, so it
never runs after that. The other two mutants of the condition (`==`, `<=`), which log
a false error at every start, are killed by
`starting_the_pool_logs_no_error_when_no_helper_ended` (chain/tests/pow_pool_log.rs).

**Evidence.** Missed in `runG9s1` (stage 1) and `runG9s2` (stage 2), internal records
of run G.

Record: mutation run G, 2026-10-12.

## E66: `OutputMmr::truncate` to its own length (tx/src/mmr.rs)

Decision: mutation run G, batch G2, for the Lead's review.

**Code.** `pub fn truncate(&mut self, count: u64) { if count < self.count {
self.nodes.truncate(mmr_size(count) as usize); self.count = count; } }`. The fields
`count` and `nodes` are private; only `Default` (`new`), `push` and `truncate` change
them.

**Mutant covered:** 186:18 `replace < with <=` (cargo-mutants).

**Argument.** The invariant `nodes.len() == mmr_size(count)` holds after `default`
(0 and 0), after `push` (asserted there: `debug_assert_eq!`) and after `truncate`
(both set together). The mutant adds only the case `count == self.count`, where it
truncates `nodes` to `mmr_size(self.count) = nodes.len()` (a no-op) and sets `count`
to its own value: the same state. Truncation below the count is tested
(`truncate_then_append_equals_the_original`).

**Evidence.** Missed in `runG2s1m` and `runG2s2` (every non-PX-proving tx target and
the chain set).

Record: mutation run G, 2026-10-12.

## E67: `ProverChallenger` methods Plonky3 never calls (zk/src/config.rs)

Decision: mutation run G, batch G5, for the Lead's review.

**Code.** `ProverChallenger` wraps the verifier's `Challenger` and forwards each trait
method to it: `CanSample::sample_vec` (`self.inner.sample_vec(n)`) and
`GrindingChallenger::check_witness` (`self.inner.check_witness(bits, witness)`). Its
`grind` calls `self.inner.check_witness`, the inner challenger's, not its own.

**Mutants covered:** 150:9 `replace sample_vec -> Vec<T> with vec![]`; 203:9 `replace
check_witness -> bool with true` and `with false` (cargo-mutants).

**Argument.** `ProverChallenger` is only the prover's challenger (`ProverZkConfig`);
the verifier uses `Challenger` itself. In Plonky3 0.7.0 (and the patched `p3-fri`),
`check_witness` is called only by the FRI verifier (`p3-fri` `verifier.rs`), on the
verifier's challenger, and `sample_vec` is called by no prover or verifier code (only
`p3-challenger`'s own tests); BlackSilk's code calls neither on a
`ProverChallenger` (`grep -rn 'sample_vec\|check_witness' zk zkvm px tx`). The
mutated bodies never run. If a Plonky3 upgrade starts calling them, these mutants
become live and need a test.

**Evidence.** Missed in `runG5s1`, `runG5s2a`, `runG5s2b` and `runG5s3` (every zk
target, px `consensus_fingerprint` and `proof_limits`, tx `px_proof_wiring`, zkvm
`alu`).

Record: mutation run G, 2026-10-12.

## E68: candidates at or past the field order in `smallest_pow_witness` (zk/src/config.rs)

Decision: mutation run G, batch G5, for the Lead's review.

**Code.** `while start < order { let mut state = base; state[slot] =
Packed::from_fn(|l| Val::from_u64((start + l as u64).min(order - 1)));
permute_mut(&mut state); for (l, sample) in state[RATE - 1].as_slice().iter()
.enumerate() { let candidate = start + l as u64; if candidate < order && sample & mask
== 0 { return Val::from_u64(candidate) } } start += lanes; }` (`order` = p, `lanes` =
the packing width). The lanes of one packed permutation are independent.

**Mutants covered:** 246:17 `replace < with <=` (the loop bound); 250:86 `replace -
with +` and `replace - with /` (the clamp `order - 1` becomes `order + 1` or
`order`); 254:26 `replace < with <=` (`candidate <= order`) (cargo-mutants).

**Argument.** Each mutant changes only what happens to candidates `≥ order`, which
the original never returns, and never changes a candidate below `order` or the order
of the scan:

- 246:17 adds one pass at `start == order`; all its candidates are `≥ order`, so the
  `candidate < order` test skips them and the function panics as the original does
  (both only after the whole field was scanned without a witness).
- 250:86 changes the value placed in a padding lane (`start + l > order - 1`) from
  `order - 1` to `order` or `order + 1` (`from_u64` reduces); a candidate below the
  order is never clamped by either bound. Padding lanes' samples are never returned
  (`candidate < order` fails), and lanes do not mix, so every other sample is the same.
- 254:26 can additionally return `candidate = order`, which only a padding lane
  holds, with the value `order - 1`; that lane's sample equals the sample of the
  candidate `order - 1`, which is scanned first (the lane before it in the same
  permutation, or the last lane of the previous one, since `start < order`) and
  returned first if it has the zero bits. So `order` is never returned.

This holds for every packing width, including width 1, where there is no padding lane.
The result is also confirmed by the verifier's `check_witness` in `grind`.

**Evidence.** Missed in `runG5s1`, `runG5s2a`, `runG5s2b`, `runG5s3`.

Record: mutation run G, 2026-10-12.

## E69: `start - l` for `start + l` in `smallest_pow_witness`, at packing width 1 (zk/src/config.rs)

Decision: mutation run G, batch G5, for the Lead's review. **Conditional on the build
target: it does not hold on aarch64, which the project builds** (§ Open items (f) of
the run G evidence).

**Code.** As E68: the lane values `start + l as u64` (250:64) and the candidate
`start + l as u64` (253:35). `<BabyBear as Field>::Packing` is chosen by
`p3-monty-31` 0.7.0 (`monty_31.rs`): `PackedMontyField31Neon` (width 4) when
`target_arch = "aarch64"` and `target_feature = "neon"`, the AVX2 or AVX-512 packings
on x86_64 with those features, and the field itself (width 1) otherwise.

**Mutants covered:** 250:64 `replace + with -`, 253:35 `replace + with -`
(cargo-mutants), **on width-1 builds only**.

**Argument.** On x86_64 without AVX2 or AVX-512 (the repository sets no target feature
and no `target-cpu`; this run's x86_64-pc-windows-msvc build), the width is 1, so `l`
is always 0 and `start - 0 = start + 0`: the same function.

The width is not 1 everywhere the project builds. NEON is a default target feature of
aarch64, so an aarch64 build (CI's `ubuntu-24.04-arm` leg) uses width 4, and there the
mutants are live:

- 250:64 puts `start - l` into lane `l` while the candidate stays `start + l`; at
  `start = 0` the subtraction underflows (a panic under overflow checks; in a release
  build it wraps and is clamped to `order - 1`);
- 253:35 keeps the lane values and names the candidate `start - l` (the same
  underflow at `start = 0`; a wrapped candidate fails `candidate < order` and is
  skipped).

Either way the returned witness is no longer the one whose sample was tested. `grind`
then runs the verifier's own `check_witness` on it and asserts the result: the prover
panics, or, if the returned value happens to pass the verifier's check, it is a valid
proof-of-work witness. So no invalid proof results; on aarch64 these are prover
failures, not equivalents. A census on the arm64 runner would kill them (follow-up:
re-check the two mutants there).

**Evidence.** Missed in `runG5s1`, `runG5s2a`, `runG5s2b`, `runG5s3`, on
x86_64-pc-windows-msvc.

Record: mutation run G, 2026-10-12; narrowed to width-1 builds in the run G revision,
2026-10-13.

## E70: `VerifierConfig::setup` as `Default::default()` (zk/src/config.rs)

Decision: mutation run G, batch G5, for the Lead's review.

**Code.** `pub fn setup() -> Self { Self::new() }` and `impl Default for
VerifierConfig { fn default() -> Self { Self::new() } }`.

**Mutant covered:** 450:9 `replace VerifierConfig::setup -> Self with
Default::default()` (cargo-mutants).

**Argument.** Both bodies call `Self::new()`: the same code.

**Evidence.** Missed in `runG5s1`, `runG5s2a`, `runG5s2b`, `runG5s3`.

Record: mutation run G, 2026-10-12.

## E71: the cycle-limit trap at a budget of exactly `MAX_CYCLES` (px/src/prove.rs)

Decision: mutation run G, batch G4, for the Lead's review.

**Code.** For each function: `let limit = budget.cycles.max(1 << FN_RUN_LOG_CYCLES)
.saturating_add(1).min(MAX_CYCLES as usize) as u32;` then a `CycleLimit` trap with
`budget.cycles < limit as usize` is `OverBudget`, any other trap `Execution`.
`FN_RUN_LOG_CYCLES = 15`, `zkvm::MAX_CYCLES = 2^21`.

**Mutant covered:** 302:38 `replace < with <=` (cargo-mutants).

**Argument.** The versions differ only when `budget.cycles == limit`. For `b ≤ 2^15`,
`limit = 2^15 + 1 > b`; for `2^15 < b < 2^21`, `limit = b + 1 > b`; for `b > 2^21`,
`limit = 2^21 < b`. So they differ only at `b = 2^21`, and only in which error a
cycle-limit trap returns (`OverBudget` against `Execution`), on the prover's side. No
registered function has that budget: a deploy is valid only with `b.cycles ≤ 2^15`
(`budget_is_provable`, tx/src/px.rs:873, `PX_FN_LOG_CYCLES = 15`). The other two
mutants of the guard are killed by
`a_function_trap_other_than_the_cycle_limit_is_an_execution_error`.

**Evidence.** Missed in `runG4s1` and `runG4s2a`.

Record: mutation run G, 2026-10-12.

## E72: the record loops' bounds and the damage search's start in the store repair (chain/src/store.rs)

Decision: mutation run G, batch G6, for the Lead's review (as E63 and E64).

**Code.** `valid_prefix`: `while pos < data.len() { match parse_frame(&data[pos..]) {
Ok((_, used)) => pos += used, Err(_) => break } }`. `operator_records`: `while pos <
region.len() { match parse_frame(&region[pos..]) { Ok(..) => … pos += used, Err(_) =>
{ let named_end = (…).then(|| pos + RECORD_HEADER + n).filter(|&end| end ==
region.len() || (end < region.len() && parse_frame(&region[end..]).is_ok()));
match named_end.or_else(|| next_valid_record(codec, region, pos + 1)) { Some(next) =>
pos = next, None => break } } } }`.

**Mutants covered:** 912:15 `replace < with <=` (`valid_prefix`); 939:15 `replace <
with <=`, 969:33 `replace < with <=`, 971:81 `replace + with *` (`operator_records`)
(cargo-mutants).

**Argument.**

- **912:15, 939:15.** `pos` never exceeds the length: `used` is at most the rest of
  the slice; a `named_end` is kept only if it equals or is below the length; and
  `next_valid_record` returns an `at` with `at + 4 ≤ len`. So the mutants add one pass
  at `pos == len` only. There `parse_frame(&[])` is `Err("short header")`; in
  `valid_prefix` that breaks with the same `pos`; in `operator_records` the named end
  needs `len − pos ≥ RECORD_HEADER` (false) and `next_valid_record(.., len + 1)` finds
  nothing, so the loop breaks with the same records.
- **969:33.** The right operand of `end == region.len() || (end < region.len() && …)`
  runs only when `end != region.len()`, where `end < len` and `end <= len` agree.
- **971:81.** `pos * 1 = pos` starts the search one byte earlier, at the frame that
  just failed to parse. `next_valid_record` finds the first magic at or after its
  start; if it is at `pos`, `parse_frame` fails there again (deterministic) and the
  search moves on to `pos + 1`, as the original starts; if it is not, the first magic
  found is the same. The same answer for every input.

**Evidence.** Missed in `runG6s1` and `runG6s2` (every chain target but
`restart_rebuilds_the_px_state_exactly`, and node lib, `halt_exit`, `node_binary`).

Record: mutation run G, 2026-10-12.

## E73: log lines of store replay (chain/src/manager/replay.rs)

Decision: mutation run G, batch G6, for the Lead's review (as E12 and E33).

**Code.** In `open_checked`: `if checkpoints + verdicts > 0 { log::info!(…) }` and
`if !operator.is_empty() { log::warn!(…) }`, then `manager.log_operator_verdicts()`.
In `replay`: `if !invalid_desc.is_empty() { log::info!(…) }` and `if orphans > 0 {
log::warn!(…) }`. In `scan`: `out.checkpoints += 1` and `out.verdicts += 1`.
`log_operator_verdicts(&self)` only logs (one warning per verdict in force, and one
for `operator_fork()`, a `&self` query).

**Mutants covered:** 243:35 `replace > with ==`, `with <`, `with >=`; 243:24 `replace +
with *`; 249:12 `delete !`; 402:12 `delete !`; 412:20 `replace > with ==`, `with <`,
`with >=`; 695:70 `replace += with *=`; 697:56 `replace += with *=`; 595:9 `replace
ChainManager::log_operator_verdicts with ()` (12, cargo-mutants).

**Argument.** Each condition guards only a log line, and `checkpoints` and `verdicts`
are read only by the line at 243 to 246 (`grep -n 'checkpoints\|verdicts'
chain/src/manager/replay.rs`); `invalid_desc` and `orphans` are read by their log
lines only after the replay is complete. 243:24 `*` cannot overflow for any store a
node can hold. 595:9 removes the operator warnings and changes no state. The same
blocks are connected and refused in both versions, and no test observes the log. The
other 243:24 mutant (`-`, an overflow panic when verdicts outnumber checkpoints) is
killed by `a_store_with_verdict_markers_and_no_checkpoint_opens`.

Not covered by the argument: the warning of 595:9 is the operator-facing message of
RTW3-11 (each operator verdict in force, and whether a heavier chain is refused only
because of it). Only a log-capture test can hold it: open, low (run G evidence, § Open
items (c)).

**Evidence.** Missed in `runG6s1` and `runG6s2`.

Record: mutation run G, 2026-10-12.

## E74: `|` of disjoint bits in the store instructions (zkvm/src/exec.rs)

Decision: mutation run G, batch G10, for the Lead's review.

**Code.** `Op::Sb | Op::Sh | Op::Sw`: `(align, mask)` is `(4, 0xffff_ffff)`, `(2,
0xffff)` or `(1, 0xff)`; `check_addr(addr, align, true)?`; `let shift = 8 * (addr %
4);` `let after = (before & !(mask << shift)) | ((rs2 & mask) << shift);`.

**Mutant covered:** 288:57 `replace | with ^` (cargo-mutants).

**Argument.** The left operand has every bit of `mask << shift` cleared; the right
operand has bits only inside `mask << shift` (`rs2 & mask` is within `mask`, and the
same shift moves both, bits shifted out of the word being lost from both). The
operands share no bit, so `|` and `^` agree for every input.

**Evidence.** Missed in `runG10s1`, `runG10s2` (every zkvm target), `runG10s3` (px
`kernel`, `kernel_budget`, `elf_paths`, `fuzz`, `proof_limits`, tx `deploy_rules`), and
`runG10keq` (with the new loader and boundary tests).

Record: mutation run G, 2026-10-12.

## E75: two loader checks that refuse only programs refused anyway (zkvm/src/program.rs)

Decision: mutation run G, batch G10, for the Lead's review.

**Code.** `Program::from_elf`: `if elf.len() < 52 || &elf[..4] != b"\x7fELF" { return
Err(e("not an ELF file")) }` (82); the identification, type, machine and flag checks;
each `PT_LOAD` header read with `u32_at` (which returns `Err("truncated")` past the
end), a `memsz == 0` segment skipped; the executable segment must be 4-aligned with
`memsz == filesz`; then `if writable.iter().any(|&base| base < code_base) { return
Err(…) }` (162) and `Self::new(…)`, whose `validate` refuses overlapping segments,
a code base below `NULL_GUARD = 0x1000` and an empty code segment. Consensus reads
only whether loading fails (`load_programs` maps every error to
`TxError::PxInvalidProgram`).

**Mutants covered:** 162:45 `replace < with <=`; 82:22 `replace < with <=`
(cargo-mutants).

**Argument.** Each mutant refuses one more class of input, and the original refuses
every input of that class too; only the error value differs, which no consensus path
reads.

- **162:45** also refuses a writable segment at `base == code_base`. Such a data
  segment has `mem_size ≥ 1` (zero-size segments are skipped) and the code segment is
  non-empty (else `validate` refuses it), so both ranges start at `code_base` and end
  above it: `validate`'s overlap check refuses the program.
- **82:22** also refuses an input of exactly 52 bytes. No 52-byte input loads: it
  needs an executable `PT_LOAD` header read entirely inside the file, so at an offset
  `h ≤ 24` (its flags are at `h + 24 … h + 28`), and only the first header can be
  there (`h = phoff + 32 i`). Its type word `01 00 00 00` at `h` conflicts with the
  fixed ELF header bytes for `h` = 0 to 5 (the magic, the identification bytes) and 13
  to 19 (`e_type = 2`, `e_machine = 243`). For `h` = 6 and 7 its flags byte is a zero
  byte of `phoff` (`PF_X` clear); for `h = 8` its `vaddr` is bytes 16 to 19, `0x00f30002`,
  not 4-aligned; for `h` = 9 to 12 and 21 to 23 its file offset contains `e_type`,
  `e_machine` or `phoff` bytes, which put it far past the 52 bytes ("segment outside
  the file"); for `h = 20` its `vaddr` is `phoff = 20`, below `NULL_GUARD`; for `h =
  24` its `filesz` contains `e_phentsize = 32` in its third byte (at least 2^21),
  past the file. So every 52-byte input is refused by the original, as by the mutant.

**Evidence.** Missed in `runG10s1`, `runG10s2`, `runG10s3`, and `runG10keq` (with
the new zkvm/tests/elf_loader.rs, among them
`inputs_shorter_than_an_elf_header_are_rejected_without_panicking` and
`writable_segment_below_the_code_is_rejected_and_above_it_is_accepted`).

Record: mutation run G, 2026-10-12.

## E76: `|` of disjoint bit fields in RandomX (randomx/src/superscalar.rs, vm.rs)

Decision: mutation run G, batch G3, for the Lead's review.

**Code and mutants covered** (cargo-mutants, each `replace | with ^`):

- superscalar.rs 267:22 `P01 = P0 | P1`, 268:22 `P05 = P0 | P5`, 269:23 and 269:28
  `P015 = P0 | P1 | P5`, with `P0 = 1`, `P1 = 2`, `P5 = 4`;
- vm.rs 225:14 `small_positive_float_bits`: `exponent | mantissa`;
- vm.rs 236:24 `float_mask`: `(entropy & MASK22) | static_exponent(entropy)`;
- vm.rs 649:69, 650:69 `mask_e`: `(x[k].to_bits() & DYNAMIC_MANTISSA_MASK) |
  e_mask[k]`.

**Argument.** In each, the two operands share no bit, so `|` and `^` agree:

- the ports are distinct single bits;
- `exponent` is masked to 11 bits and shifted by 52, `mantissa` is below 2^52;
- `static_exponent` is `(0x300 | (entropy >> 60) << 4) << 52`, bits 56 to 61, and
  `MASK22` is bits 0 to 21;
- `mask_e`'s argument is always a `load_f` value (its only callers, vm.rs 690 and
  866), an `i32` converted to `f64`. A nonzero `n` with `2^k ≤ |n| < 2^(k+1)` has the
  fraction `(|n| − 2^k) · 2^(52−k)`, so bits 0 to 21 are zero for `k ≤ 30`, and
  `|n| = 2^31` has fraction 0. So `x & DYNAMIC_MANTISSA_MASK` (bits 0 to 55) has bits
  0 to 21 clear, while `e_mask` (a `float_mask`) has bits only in 0 to 21 and 56 to
  61. Disjoint.

**Evidence.** Missed in `runG3s1`, `runG3s2` (with the ignored light-mode tests: the
FPU oracle, the large pinned digest) and `runG3s2b` (consensus `golden`).

Record: mutation run G, 2026-10-12.

## E77: unreachable comparisons in RandomX program generation and compilation (randomx/src/superscalar.rs, vm.rs)

Decision: mutation run G, batch G3, for the Lead's review.

**Mutants covered** (cargo-mutants): superscalar.rs 344:65, 345:67, 346:67, 347:67,
348:67, 349:67, 350:67 `delete -` (the `src_op` of `IROR_C`, `IADD_C7`, `IXOR_C7`,
`IADD_C8`, `IXOR_C8`, `IADD_C9`, `IXOR_C9`: `-1` becomes `1`); superscalar.rs 744:26
`replace < with <=` (`program.len() < SUPERSCALAR_MAX_SIZE` in `generate`'s loop);
vm.rs 501:26 `replace < with <=` (`opcode < Ceil::ISTORE` in `compile`).

**Argument.**

- **344 to 350.** These instructions have one macro-op. `generate` compares
  `macro_op_index == current.info.src_op` only after reading `ops[macro_op_index]`,
  so with `macro_op_index = 0`; `-1` and `1` both differ from 0. The source branch
  never runs in either version.
- **744:26.** The versions differ only if `program.len()` reaches
  `SUPERSCALAR_MAX_SIZE = 3 · 170 + 2 = 512`. Every instruction has at least one
  macro-op that is not eliminated, and each committed uop takes a free (cycle, port)
  slot of the map (`schedule_uop` writes a slot only where it is 0). While the ports
  are not saturated every commit is at a cycle below 170 (a commit at 170 or later sets
  `ports_saturated`), so at most `3 · 170 = 510` instructions are complete before
  saturation, and at most one more (the instruction in progress) after it: at most 511
  instructions. `program.len() < 512` always holds, and the mutated condition is
  equivalent. (Observed maximum: 494 in 8 million programs.)
- **501:26.** `opcode` is a byte (`ins[0] as u16 ≤ 255`) and `Ceil::ISTORE = 256` (the
  frequencies sum to 256, a compile-time assertion in randomx/src/config.rs). Both
  `< 256` and `≤ 256` hold for every opcode; the final `else` (`Op::Nop`) is
  unreachable in both.

**Evidence.** Missed in `runG3s1`, `runG3s2`, `runG3s2b`.

Record: mutation run G, 2026-10-12.

## E78: initial values that are overwritten or never compared with another value (randomx/src/superscalar.rs)

Decision: mutation run G, batch G3, for the Lead's review.

**Mutants covered** (cargo-mutants, each `delete -`, so `-1` becomes `1`): 422:28
`INVALID_GROUP`; 458:18 and 459:18 (`Instruction::null`'s `src`, `dst`); 497:20
(`create`'s `self.dst = -1`); 535:37, 541:37, 547:37, 565:37 (`op_group_par = -1` of
`IROR_C`, the `IADD_C*`, the `IXOR_C*`, `IMUL_RCP`).

**Argument.**

- **422:28.** `INVALID_GROUP` is only the `last_op_group` of a register no
  instruction has written (`RegisterInfo::default`, `last_op_par = -1`); a written
  register gets the writer's group and parameter together. It is read in
  `select_destination` in `reg.last_op_group != ImulR` (3: both `-1` and `1` differ)
  and in `(reg.last_op_group != self.op_group || reg.last_op_par !=
  self.op_group_par)`. Only an `IXOR_R` has `op_group = 1`; its `op_group_par` is
  set by `select_source` to a register index (`group_par_is_source`, `src_op =
  dst_op = 0`, the source chosen first), so `-1 != op_group_par` and the condition
  holds in both versions.
- **458:18, 459:18.** `Instruction::null` has no macro-ops, so the next loop pass
  calls `create`, which sets `src = -1` and `dst = -1`, before anything reads them; a
  null instruction is never emitted.
- **497:20.** Every instruction's `dst_op` is below its macro-op count and not above
  its `result_op`, so `select_destination` sets `dst` before `registers[dst]` (at
  `result_op`) or `to_instr` reads it; a thrown-away instruction is never read.
- **535, 541, 547, 565.** These groups (`IROR_C` 4, `IADD_C7` 5, `IXOR_C7` 6,
  `IMUL_RCP` 13) have `src_op = -1`, so `select_source` never sets their parameter,
  and no other instruction has these groups. `op_group_par` is read only in the
  condition above and stored as the register's `last_op_par` with its group. The
  comparison matters only against a register last written by the same group, which
  stored the same constant: `-1` against `-1`, or `1` against `1`, the same answer.

**Evidence.** Missed in `runG3s1`, `runG3s2`, `runG3s2b`.

Record: mutation run G, 2026-10-12.

## E79: `+ 4` for `% 4` in the float register indices (randomx/src/vm.rs)

Decision: mutation run G, batch G3, for the Lead's review.

**Code.** `compile` stores `dst: dst % 4` and `src: src % 4` in the float operations
(`dst`, `src` are `ins[k] % 8`, so 0 to 7); `execute_program` reads them only through
`fi(i) = i as usize & 3`.

**Mutants covered:** 443:26, 444:26, 448:26, 455:26, 456:26, 460:26, 466:35, 469:26,
470:26, 474:26, 480:35 `replace % with +` (11, cargo-mutants).

**Argument.** `(d + 4) & 3 = d & 3 = (d % 4) & 3` for `d` in 0 to 7 (no overflow of a
`u8`). The fields are read nowhere else (`grep -n 'FaddR\|FsubR\|FmulR\|FscalR\|FsqrtR\|FdivM\|FaddM\|FsubM'
randomx/src`: the definition, `compile` and `execute_program` only).

**Evidence.** Missed in `runG3s1`, `runG3s2`, `runG3s2b`.

Record: mutation run G, 2026-10-12.

## E80: `|=` for `^=` on a zero scratchpad address (randomx/src/vm.rs)

Decision: mutation run G, batch G3, for the Lead's review.

**Code.** `execute`: `self.r = [0; 8]; let mut sp_addr0 = self.mx; let mut sp_addr1 =
self.ma;` then per iteration `let sp_mix = self.r[rr0] ^ self.r[rr1]; sp_addr0 ^=
sp_mix as u32; … sp_addr1 ^= (sp_mix >> 32) as u32; …` and at its end `sp_addr0 = 0;
sp_addr1 = 0;`.

**Mutants covered:** 676:22, 678:22 `replace ^= with |=` (cargo-mutants).

**Argument.** In the first iteration the registers are zero, so `sp_mix = 0` and
`a ^ 0 = a | 0`; in every later iteration the address is 0 (reset at the end of the
previous one) and `0 ^ b = 0 | b`. One operand is always zero.

**Evidence.** Missed in `runG3s1`, `runG3s2`, `runG3s2b`.

Record: mutation run G, 2026-10-12.

## E81: an extra pass past the port map in `schedule_mop` (randomx/src/superscalar.rs)

Decision: mutation run G, batch G3, checked by the lead.

**Code.** `while (cycle as usize) < CYCLE_MAP_SIZE { let cycle1 = schedule_uop(false,
…, cycle); let cycle2 = schedule_uop(false, …, cycle); if cycle1 >= 0 && cycle1 ==
cycle2 { … return cycle1 } cycle += 1 } -1`, with `CYCLE_MAP_SIZE = 174`.

**Mutant covered:** 706:28 `replace < with <=` (cargo-mutants).

**Argument.** The only extra pass is at `cycle = 174`. There both `schedule_uop` calls
(not committing) skip their loop and return `-1`, so the test fails, `cycle` becomes
175 and the function returns `-1`, as the original does, with no state written.

**Evidence.** Missed in `runG3s1`, `runG3s2`, `runG3s2b`.

Record: mutation run G, 2026-10-12.

## E82: the 257th consecutive throwaway (randomx/src/superscalar.rs)

Decision: mutation run G, batch G3, for the Lead's review. **Equivalent under a
probabilistic reachability argument, not unconditionally.**

**Code.** In `generate`, when no source (782) or destination (807) register is found
within `LOOK_FORWARD_CYCLES = 4` cycles: `if throw_away_count < MAX_THROWAWAY_COUNT
{ throw_away_count += 1; macro_op_index = ops.len(); continue } current =
Instruction::null(); break`, with `MAX_THROWAWAY_COUNT = 256`. `throw_away_count` is
reset to 0 whenever a macro-op passes both selections.

**Mutants covered:** 782:41, 807:41 `replace < with <=` (cargo-mutants).

**Argument.** The versions differ only after 256 consecutive throwaways. Each
throwaway follows four failed tries, each of which adds 1 to `cycle`, and `continue`
skips the reset `cycle = top_cycle`; nothing else lowers `cycle` during a streak. So a
streak raises `cycle` by 4 per throwaway, so at most 44 throwaways of a streak happen
below cycle 174, the end of the port map. No macro-op is committed during a streak,
so every register's latency comes from a commit before it, at a cycle below 170 (a
later commit saturates the ports), plus at most 4: at most 173. From cycle 174 on, an
instruction whose first
macro-op uses a port is refused by `schedule_mop` with `-1`, which saturates the
ports and ends the program, not a throwaway. The only instructions that can still be
thrown away are `IMULH_R` and `ISMULH_R`, whose first macro-op (`MOV_RR`) is
eliminated (their source is chosen at the second macro-op, which a full map refuses).
Their destination choice, with every register's latency passed, `can_reuse` set and
chained multiplications allowed (`throw_away_count > 0`), fails only if every register was
last written by the same group with the same `op_group_par`, a fresh 32-bit value from
the generator. So the remaining throwaways, at least 212, each need an event of
probability at most `8 · 2^−32`, treating the Blake2 generator's output as uniform.
The streak's probability is far below anything observable. In 8 million generated
programs the longest streak was 3 (internal record `reach-1M.txt`). This is an
argument about the generator's output, not a proof for every key.

**Evidence.** Missed in `runG3s1`, `runG3s2`, `runG3s2b`.

Record: mutation run G, 2026-10-12.

## E83: the compile-time check of the kernel error list (px/src/fingerprint.rs)

Decision: mutation run G, batch G7, for the Lead's review (as E24).

**Code.** `const _: () = { let mut i = 0; while i < KERNEL_ERRORS.len() { assert!(…);
assert!(…); i += 1; } };`

**Mutants covered:** 550:13 `replace < with ==`, `replace < with >` (cargo-mutants).

**Argument.** The block is evaluated at compile time and produces no run-time code.
With `i = 0` and a non-empty list, `0 == len` and `0 > len` are false, so the mutated
loop never runs and the assertions, which hold in the original, are skipped. The
built program is the same.

**Evidence.** Missed in `runG7s1px` and `runG7s2px` (the cheap px targets and every
node target).

Record: mutation run G, 2026-10-12.

## E84: a difficulty sample input shifted by a constant that the rule never reads (node/src/fingerprint.rs)

**Superseded (2026-10-13, fingerprint-sample-inputs):** the manifest now records each
difficulty sample's timestamps and cumulative difficulties, so the covered mutant
(480:48 at `85a8753`, now 528:48 at `1a74131`) changes the rules fingerprint and is
killed, as is the open 482:12 (now 530:12); E84 covers no mutant. Kill record: `runFPSI`
([run G evidence](../evidence/mutation-runG-2026-10-12/README.md), § Open items (b));
record docs/reviews/v3-consensus-changes.md#fingerprint-sample-inputs. The text below
is kept as written.

Decision: mutation run G, batch G7, for the Lead's review; narrowed in the run G
revision (2026-10-13).

**Code.** `rule_samples`: `ts = 1_000_000 + i · 120` and `cd = (i + 1) · 10^6` for `i`
in 0 to 86; samples `next_difficulty(&ts, &cd, …)`, `next_difficulty(&ts[11..],
&cd[11..], …)` and the genesis-only case `(&ts[..1], &cd[..1], …, 777)`. In
`next_difficulty` (consensus/src/difficulty.rs) the cumulative difficulties enter only
as differences `cumulative[w0 + i] − cumulative[w0 + i − 1]`, and the genesis-only
case returns `initial` before reading them.

**Mutant covered:** 480:48 `replace + with *` (`cd = i · 10^6`) (cargo-mutants).

**Argument.** The mutant shifts every cumulative difficulty by the same `10^6`, and the
rule reads only differences of them: the same samples through the same computation.
A rule change would have to start reading absolute cumulative values to tell the two
inputs apart, and then both inputs move the sample.

**Not covered (moved to open):** 482:12 `replace -= with /=` (`ts[11] = 770` instead of
`1_000_020`). Under today's rule both inputs give the same outputs (the warm-up lifts
the stamp to the counted clock, `1_001_260`, in the full sample; the first solve time
of the window-only sample is capped at `6T = 720` in both). But the original stamp lies
1 240 s below the counted clock and the mutated one about 1 000 490 s below it, so a
rule change that treats a low stamp by how far below it lies, with a tolerance
between those two (for example "count a stamp as given if it lies at most
`MAX_FUTURE_TIME_LIMIT` = 7 200 s low, lift it otherwise"), moves the original sample
and not the mutated one. Under the criterion of the run G evidence (§ Open items (b))
that is a weakening, so 482:12 is open, not exempt. (Tolerances up to 1 240 s, among
them the future time limit of 360 s and `6T`, treat both inputs alike, as do a
changed cap and a changed warm-up length.)

**Evidence.** Missed in `runG7s1node` and `runG7s2node` (every node target).

Record: mutation run G, 2026-10-12; narrowed 2026-10-13.

## E85: transaction-sample variants changed by another amount, with the same verdict (node/src/fingerprint.rs)

**Superseded (2026-10-13, fingerprint-sample-inputs):** every verdict variant now
records the hash of its transaction's encoding (and the signature domain of the
other-branch case), so both covered mutants (1007:58 `plus_g`, now 1216:58; 1253:54
"other salt", now 1545:54) and the open 1023:36 and 1208:52 (now 1259:36 and 1495:52)
change the rules fingerprint and are killed; E85 covers no mutant. Kill record:
`runFPSI` ([run G evidence](../evidence/mutation-runG-2026-10-12/README.md), § Open
items (b)). The text below is kept as written.

Decision: mutation run G, batch G7, for the Lead's review; narrowed in the run G
revision (2026-10-13).

**Mutants covered** (cargo-mutants): 1007:58 `replace + with -` (`plus_g` adds `−G`
instead of `G`); 1253:54 `replace ^= with &=` (the "other salt" variant: `salt[0] & 1`
instead of `salt[0] ^ 1`).

**Argument.** Each variant still changes the same field so that the same rule refuses
it, and no plausible rule change tells the original input from the mutated one:

- `−G` instead of `+G` (`G` is the blinding generator, not the value generator): a
  pseudo-output shifted alone leaves the commitments unbalanced; a pseudo-output and
  an output commitment shifted together keep them balanced and break the output's
  range proof. The balance is an equality of points, and a blinding-only difference
  has no sign a rule could treat differently.
- `salt[0] & 1` changes the salt, as `^ 1` does, since the golden deploy's `salt[0]`
  is above 1 (otherwise the variant would be the valid deploy and its pinned verdict
  would differ). Both give another contract id from the same derivation.

**Not covered (moved to open, § Open items (b) of the run G evidence):**

- 1023:36 `replace ^ with &`: the "other branch id" sample uses `BRANCH_ID_V3 ^ 1`,
  which is `"BSv2"`, the previous version's tag; the mutant uses 1. Today both are
  refused alike, but a rule change that accepted the previous version's branch id
  (a replay-protection relaxation) moves only the original sample.
- 1208:52 `replace += with -=`: the PX "bridge_in + 1" variant becomes `− 1`. Today
  both break the PX balance, but a relaxation of the balance equality to an
  inequality in one direction is caught by `+ 1` only, and in the other by `− 1`
  only: the mutant swaps the direction the sample holds.

**Evidence.** Missed in `runG7s1node` and `runG7s2node`.

Record: mutation run G, 2026-10-12; narrowed 2026-10-13.

## E86: `FixtureChain` answers the samples never use (node/src/fingerprint.rs)

Decision: mutation run G, batch G7, for the Lead's review.

**Code.** `FixtureChain`, the chain view of the fixture samples and of
node/tests/px_fixture.rs, used only for transaction verdicts (`validate_transfer`,
`validate_px`, `validate_px_without_proof`, `validate_deploy`): `px_tree_size` → 0;
`px_root_after` → the empty PX state's root after the leaves; `output_frontier` → an
empty frontier ("no block is validated on this view").

**Mutants covered:** 887:9 `replace px_tree_size -> u64 with 1`; 893:9 `replace
px_root_after -> Option<Digest> with None` and `with Some(Default::default())`; 898:9
`replace output_frontier -> OutputFrontier with Default::default()` (cargo-mutants).

**Argument.**

- `px_root_after` and `output_frontier` are called only by block-level validation
  (tx/src/validate.rs `BlockContext::committing` and the block checks at 1313 and
  1373), which no sample or fixture test runs on this view: never called.
- `px_tree_size` is read by B8 for one transaction (`check_px_capacity`, through
  `px_free_leaves = CAPACITY − size`): `2^32 − 1` instead of `2^32` free leaves; the
  fixture transactions have a few commitments, so the verdict is the same.

**Evidence.** Missed in `runG7s1node` and `runG7s2node`.

Record: mutation run G, 2026-10-12.
