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

## E17–E22: reserved for run D

Run D's entries take these numbers when it merges (Lead decision, 2026-10-01).

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
