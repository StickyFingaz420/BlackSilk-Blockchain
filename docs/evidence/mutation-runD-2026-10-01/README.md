# Mutation run D: decode bounds, admission, header sync, the cache store (Wave 4 freeze gate)

Internal engineering evidence, not an audit. A mutation census shows which code
changes the tests notice; it does not show that the code is correct or secure.

The gate (decisions "Agent 42" and "W4-MUT and RT-MUT"): zero unexplained missed
mutants per completed file or function set. Every survivor is killed by a new test or
explained in [mutation-exemptions.md](../../reviews/mutation-exemptions.md) (E17–E22,
and the later entries of § Follow-up; E8–E16 and E23–E28 are run C's). A boundary
pass adds the mutants cargo-mutants never makes (`>=` → `>`, `<=` → `<`;
§ Boundary pass). Run D covers code merged after runs A–C,
which no run had censused, in this order:

1. `zk/src/bounds.rs` (the decoder's pre-scan, W4-PXDOS) and the bound parts of
   `zk/src/lib.rs` (`decode_proof`, `decode_proof_with`, and the `analysis` helpers
   the PX limits test uses);
2. the wiring: `px/src/prove.rs` `PROOF_LIMITS`, `check_shape`, `check_shape_bits`;
   `tx/src/validate.rs` `check_px_proof`, `decode_px_proof`, `check_px_proof_shape`,
   `check_px_proof_shape_bits`;
3. `p2p/src/net/admission.rs` `admit_tx`, `px_stateless`, `px_pre_checks`,
   `cheap_checks` (the off-actor checks, the semaphore, the expiring-soon branch, the
   node-wide PX token);
4. the W4-SYNC rules: `Peer::wants_tip` and `has_header` (`p2p/src/net/state.rs`),
   the handshake's `GetHeaders` rule and `knows_tip` (`conn.rs`), `end_of`
   (`headers.rs`), `announce_tip` and `announce_loop` (`maintenance.rs`), and
   `chain/src/manager/summary.rs` (`tip_on_best_chain`, the tip listeners);
5. `consensus/src/pow.rs`, changed by `9bba1bd` after run A's census of the bounded
   store.

## Result in brief

| Scope | Mutants | Caught (run) | Missed (run) | Unviable | After the new tests |
|---|---|---|---|---|---|
| zk/src/bounds.rs | 82 | 61 | 20 | 1 | 18 killed; 2 equivalent (E17) |
| zk/src/lib.rs `decode_proof`, `decode_proof_with` | 8 | 4 | 2 | 2 | 2 killed |
| zk/src/lib.rs `analysis::quotient_chunks`, `trace_widths` | 16 | 11 | 5 | 0 | 2 killed; 3 equivalent on the helper's inputs (E18) |
| px/src/prove.rs `PROOF_LIMITS`, `check_shape`, `check_shape_bits` | 19 | 7 | 12 | 0 | 12 killed |
| tx/src/validate.rs (the four PX5 decode and shape functions) | 4 | 0 | 3 | 1 | 3 killed |
| p2p/src/net/admission.rs (four functions) | 26 | 10 | 14 | 2 | 9 killed; 5 unobserved by any test (E19); release arithmetic: 1 more killed, 1 more E19 |
| p2p W4-SYNC rules (state.rs, conn.rs, headers.rs, maintenance.rs) | 35 | 24 | 11 | 0 | 11 killed |
| chain/src/manager/summary.rs (listeners, store, `Debug`) | 4 | 3 | 1 | 0 | 1 killed; 2 hand mutants of `tip_on_best_chain` caught |
| consensus/src/pow.rs | 182 | 130 (+8 timeouts) | 4 | 40 | 3 killed; 1 unobservable (E20); the 8 timeouts fail assertions in isolation; release arithmetic: 1 more killed, 1 equivalent (E22) |
| boundary pass (`>=` → `>`, `<=` → `<`) | 5 | 4 | 1 | 0 | 1 equivalent (E21, the same as run C's E27) |

No run had a timeout but pow.rs (§ consensus/src/pow.rs).

- **No survivor revealed a bug in a consensus rule or a bound.** Every cap of the
  pre-scan held at its boundary: each cargo-mutants mutant of a cap's comparison was
  caught by the existing tests in `runZ`, and so was the boundary pass's `<=` → `<`.
  The survivors were caps written only symbolically in the tests, the inclusive size
  limit, the ten-byte varint rule, error-message indices, and code that only proving
  tests reached.
- **What had no non-proving test before:**
  - PX5's shape step (`check_shape_bits`): 12 of 19 prove.rs mutants survived, the
    whole check among them (`Ok(())`); `check_px_proof` itself (`Ok(())`, as in run
    C, whose test is on the unmerged `w4-mutc`);
  - admission's path past the cheap stage: the node-wide PX token, its drop count, and
    the shape check on off-actor degree bits (only proving tests sent a decodable
    proof to admission);
  - the activation grace window in admission (no p2p test had an activation) and PX6
    at the next block's height;
  - the handshake's header request (height and `knows_tip`), and a peer's header
    knowledge learned after its handshake (`has_header`, the work from `end_of`);
  - the summary's `tip_on_best_chain` and its tip listeners (only through network
    timing).
- **The hollow proof.** Most new tests use a proof with one empty instance per table
  and chosen degree bits (`hollow_proof` in px/tests/proof_limits.rs,
  tx/tests/px_proof_wiring.rs and p2p/tests/network.rs): it passes the pre-scan,
  `postcard` and the canonical-form rules, so its degree bits reach the shape check,
  but it verifies nothing. This needs no proving.
- **Release arithmetic.** Every kill that could rest on an overflow check was re-run
  with overflow checks and debug assertions off (§ Release arithmetic). Two admission
  and two pow.rs mutants survived there; one of each is now killed by a new test
  (an expiring-soon check above genesis; `evicted` with builds in flight), the
  other two are E19 and E22.
- **The boundary pass** (requested by the Lead after RT-MUTC) found no off-by-one at
  an inclusive bound: the decoder's one `<=` cap (`Reader::len`) and three of pow.rs's
  four are caught; the fourth, `seed_height`'s first branch, is equivalent (E21, the same as run C's E27).
- **A flaky test, outside the scope (§ Flaky tests).**
  `relaying_headers_of_a_block_with_an_invalid_body_is_not_penalized` failed 1 time in
  3 alone on the unmutated tree, so it was left out of the oracle.

## Setup

- **Tool:** cargo-mutants 27.1.0, as runs A–C.
- **Toolchain:** rustc 1.98.1 (x86_64-pc-windows-msvc).
- **Code:** branch `w4-mutd` on base `11cb583` (`rebuild/core`). No non-test source
  line was changed.
  - The "before" runs ran on a `git archive` export of `11cb583` (`base/`), except
    `runZ`, which ran on the worktree before any test edit.
  - The "after" runs and re-runs ran on the worktree with the test code of their
    start time. `after-admissionP` had every new admission test but
    `an_expiring_soon_px_transaction_is_judged_at_the_next_blocks_height`, written
    after `ovfP`; `rerunP` (its 5 survivors) and `ovfP2` ran with the final list.
    `runPow` ran before the two pow.rs test edits, `rerunPow`, `ovfPow2` and the
    boundary pass after them.
- **Profile:** `[profile.mutants]` of the root Cargo.toml (overflow checks and debug
  assertions on).
- **Machine:** 4 cores / 8 threads, 16 GB, shared with another agent's red-team runs
  (one of them a PX-proving test). cargo-mutants `--jobs 2` throughout.
- **Environment:** `CARGO_BUILD_JOBS=2`, `CARGO_INCREMENTAL=0`, `CARGO_TARGET_DIR`
  unset for cargo-mutants.

## Oracles

- **zk (`runZ`, `rerunZ`, `ovfZ`):** the zk lib unit tests, `decode_bounds` and
  `rt_pxdos_differential` at its default iterations (3 000 byte mutations, 3 000
  structural edits, stride 13; about 80 s). Baseline by hand: 3 + 6 + 4 passed.
- **The analysis helpers:** `px/tests/proof_limits.rs` (`--test-package
  blacksilk-px`), the helpers' only caller.
- **prove.rs and validate.rs:** px `proof_limits` plus run C's 17 non-proving tx test
  targets and the tx lib tests (`txtests.args`); after: plus `px_proof_wiring`.
- **Admission:** p2p's lib tests and `network`, filtered to the admission tests,
  `--exact --test-threads=4`, about 35 s: `admission-before.tests` (24 network tests,
  the lib's `the_chain_command_carries_no_decoded_proof`, and the first new test's
  name, which the base does not have), `admission-after.tests` (plus the token and
  grace-window tests), `admission.tests` (plus the expiring-soon test; `rerunP`,
  `ovfP2`).
  The PX-proving `px_transactions_travel_the_stem_and_confirm_everywhere` and
  `invalid_px_transactions_get_the_relaying_peer_penalized` are left out.
- **W4-SYNC:** `network`, `liveness` and `withheld_body`, filtered to the sync tests
  (`sync-before.tests`, 25; `sync.tests` adds the two new ones; the hand mutants ran
  with those 25 plus `relaying_headers_of_a_block_with_an_invalid_body_is_not_penalized`,
  which was removed afterwards), `--exact --test-threads=4`, 25–100 s under load.
  Left out:
  `pings_are_answered_while_a_header_batch_is_verified` and
  `relaying_headers_of_a_block_with_an_invalid_body_is_not_penalized`, which failed
  on the unmutated tree under load (§ Flaky tests); header-queue, ban and
  unknown-version tests outside W4-SYNC.
- **summary.rs:** the sync oracle plus chain's `manager` test
  `the_summary_flags_a_tip_off_the_best_header_chain_and_calls_tip_listeners`.
- **pow.rs:** the whole consensus test suite, as run A's `runPow3`.
- **Not used:** the PX-proving tests (px `proof`, `unified`; tx `px_consensus`; p2p's
  two PX tests), the node, wallet and labnet tests, and the p2p tests outside the
  lists above.

Every caught mutant of the p2p runs was checked against its log for the test that
failed (`kills.py`): each former survivor was caught by the test written for it,
and no p2p mutant counts as caught because of an unrelated failure.

## Commands

Run from the repository root (`-d <dir>`: the export or the worktree). `$X` stands
for the content of the named file, one argument per line (`mapfile -t X < file`;
the `--re` filters contain spaces).

```text
# runZ: bounds.rs and lib.rs's decode functions (the 4 `delete field` mutants of
# analysis::quotient_chunks ignore --re in 27.1.0 and ran too; see § Tool notes)
cargo mutants -p blacksilk-zk -f zk/src/bounds.rs -f zk/src/lib.rs --re '^zk/src/bounds\.rs' \
  --re 'decode_proof' --exclude-re 'analysis::' --profile mutants --jobs 2 --baseline skip \
  --timeout 450 --build-timeout 2400 --cap-lints true -o <out> \
  -C=--lib -C=--test=decode_bounds -C=--test=rt_pxdos_differential
# rerunZ: runZ's 22 survivors (rerunZ.args), final tests; same test selection
cargo mutants -p blacksilk-zk -f zk/src/bounds.rs -f zk/src/lib.rs $rerunZ ... (as runZ)
# ovfZ: the 6 kills that could rest on an overflow check (ovfZ.args)
RUSTFLAGS="-C overflow-checks=off -C debug-assertions=off" cargo mutants -p blacksilk-zk \
  -f zk/src/bounds.rs $ovfZ --profile mutants --jobs 2 --baseline skip --timeout 450 \
  --build-timeout 3600 --cap-lints true -o <out> -C=--lib -C=--test=decode_bounds \
  -C=--test=rt_pxdos_differential

# before-/after-analysisA, -proveW, -validateW (item2.sh; after adds -C=--test=px_proof_wiring)
cargo mutants -d <dir> -p blacksilk-zk -f zk/src/lib.rs $analysisZ --test-package blacksilk-px \
  --profile mutants --jobs 2 --baseline skip --build-timeout 2400 --cap-lints true \
  --timeout 300 -o <out> -C=--test=proof_limits
cargo mutants -d <dir> -p blacksilk-px -f px/src/prove.rs $proveW \
  --test-package blacksilk-px,blacksilk-tx ... --timeout 450 -o <out> \
  -C=--test=proof_limits $txtests
cargo mutants -d <dir> -p blacksilk-tx -f tx/src/validate.rs $validateW ... --timeout 450 \
  -o <out> $txtests

# before-/after-admissionP, -syncP, -summaryC (p2p.sh)
cargo mutants -d <dir> -p blacksilk-p2p -f p2p/src/net/admission.rs $admissionP \
  --profile mutants --jobs 2 --baseline skip --build-timeout 2400 --cap-lints true \
  --timeout 300 -o <out> -C=--lib -C=--test=network -- -- --exact --test-threads=4 $admission
cargo mutants -d <dir> -p blacksilk-p2p -f p2p/src/net/state.rs -f p2p/src/net/conn.rs \
  -f p2p/src/net/maintenance.rs -f p2p/src/net/headers.rs $syncP ... --timeout 600 -o <out> \
  -C=--test=network -C=--test=liveness -C=--test=withheld_body -- -- --exact \
  --test-threads=4 $sync
cargo mutants -d <dir> -p blacksilk-chain -f chain/src/manager/summary.rs $summaryC \
  --test-package blacksilk-chain,blacksilk-p2p ... --timeout 600 -o <out> \
  -C=--test=manager -C=--test=network -C=--test=liveness -C=--test=withheld_body -- -- \
  --exact --test-threads=4 $sync the_summary_flags_a_tip_off_the_best_header_chain_and_calls_tip_listeners
# ovfP, ovfP2: release arithmetic for admission (ovfP.args, ovfP2.args), oracle as admission
RUSTFLAGS="-C overflow-checks=off -C debug-assertions=off" cargo mutants -d <worktree> \
  -p blacksilk-p2p -f p2p/src/net/admission.rs $ovfP --profile mutants --jobs 2 \
  --baseline skip --build-timeout 3600 --cap-lints true --timeout 300 -o <out> \
  -C=--lib -C=--test=network -- -- --exact --test-threads=4 $admission

# runPow: pow.rs with the whole consensus suite (baseline run by the tool)
cargo mutants -p blacksilk-consensus -f consensus/src/pow.rs --profile mutants --jobs 2 \
  --timeout-multiplier 5 --minimum-test-timeout 300 --build-timeout 2400 --cap-lints true -o <out>
# rerunPow: runPow's 4 survivors with the new pow.rs tests (baseline run by the tool)
cargo mutants -p blacksilk-consensus -f consensus/src/pow.rs $rerunPow --profile mutants \
  --jobs 2 --timeout-multiplier 5 --minimum-test-timeout 300 --build-timeout 3600 \
  --cap-lints true -o <out>
# timeoutPow: the 8 timeouts in isolation, as run A's timeoutPow3
cargo mutants -p blacksilk-consensus -f consensus/src/pow.rs $timeoutPow --profile mutants \
  --jobs 1 --baseline skip --timeout 120 --build-timeout 3600 --cap-lints true -o <out> \
  -C=--lib -C=--test=golden -C=--test=lwma_warm -- -- --skip chain::tests --skip pow::tests
# ovfPow, ovfPow2: release arithmetic, the whole consensus suite
RUSTFLAGS="-C overflow-checks=off -C debug-assertions=off" cargo mutants \
  -p blacksilk-consensus -f consensus/src/pow.rs $ovfPow --profile mutants --jobs 2 \
  --baseline skip --timeout 600 --build-timeout 3600 --cap-lints true -o <out>
# the boundary pass (§ Boundary pass): in a copy of the worktree, one mutant at a time
python boundary.py <copy> boundary.txt
```

The `--re` filters follow run A's convention (`mkre.py` writes them: each mutant's
name, anchored, every character but a letter, a digit or a space as a one-character
class, `[ ] \ ^ -` escaped). `cargo mutants --list` with each filter file returns
exactly its mutants (checked for `rerunZ.args`: 22 of 22, plus the 4 `delete field`
mutants that ignore filters).

**Hand mutants of `tip_on_best_chain`** (`hm.sh`; cargo-mutants does not mutate a
struct field's value): `ChainSummary::of`'s `tip_on_best_chain:
m.headers().is_on_main(&tip_id)` replaced with `true` (HM1) and `false` (HM2) in a
copy of the worktree, then the chain summary test and the sync oracle:

```text
cargo test --locked --profile mutants -p blacksilk-chain --test manager -- --exact \
  the_summary_flags_a_tip_off_the_best_header_chain_and_calls_tip_listeners
cargo test --locked --profile mutants -p blacksilk-p2p --test network --test liveness \
  --test withheld_body -- --exact --test-threads=4 $sync
```

**Times (UTC, 2026-10-01):**

| Run | Start | End | Mutants |
|---|---|---|---|
| runZ | 02:00 | 02:36 | 94 (90 + the 4 filter-ignoring `delete field` mutants) |
| rerunZ | 02:40 | 02:54 | 26 (22 + 4) |
| ovfZ | 02:54 | 02:58 | 6 |
| before-analysisA, -proveW, -validateW | 02:59 | 03:46 | 16, 19, 4 |
| after-analysisA, -proveW, -validateW | 03:46 | 04:29 | 16, 19, 4 |
| hand mutants HM1, HM2 | 03:53 | 04:11 | 2 |
| before-admissionP, -syncP, -summaryC | 04:29 | 05:14 | 26, 35, 4 |
| after-admissionP, -syncP, -summaryC | 05:16 | 06:06 | 26, 35, 4 |
| ovfP | 06:07 | 06:12 | 4 |
| runPow | 06:12 | 07:03 | 182 |
| ovfP2 | 07:04 | 07:08 | 1 |
| boundary pass | 07:09 | 07:16 | 5 (and the two baselines) |
| rerunPow, timeoutPow, ovfPow | 07:16 | 07:21 | 4, 8, 6 |
| rerunP | 07:21 | 07:27 | 5 |
| ovfPow2 | 07:27 | 07:27 | 1 |

**Outputs:** each subdirectory holds the tool's `caught.txt`, `missed.txt`,
`timeout.txt` and `unviable.txt` for that run; `*.args` and `*.tests` are the filter
and test-name lists.

## Survivors and their resolution

### zk/src/bounds.rs and lib.rs's decode functions (runZ: 22 missed)

| Mutant | Resolution |
|---|---|
| lib.rs 306:20 `bytes.len() > MAX_PROOF_BYTES` → `==`, `>=` | killed: `the_size_limit_is_inclusive` (a proof of exactly 4 MiB within every cap decodes; one byte more is "proof too large") |
| bounds.rs 73:50 ×2, 73:54 `/` (`MAX_FRI_ROUNDS = MAX_LOG_HEIGHT + 1 − LOG_FINAL_POLY_LEN`), 77:52 ×2, 77:56 ×2 (`MAX_MERKLE_DEPTH`), 82:52 `*` → `+` (`MAX_PRUNED_SIBLINGS`) | killed: `the_fri_and_merkle_caps_follow_from_the_tallest_matrix` (the values 17, 26 and 2 808 from the largest degree bits `verify` accepts; every canonical FRI schedule has at most 15 rounds). The tests had used the constants only symbolically, so a smaller cap went unnoticed; 15 and 16 rounds would still have admitted every valid proof |
| bounds.rs 111:16 `end > len` → `==`, `>=` in `Reader::skip` | equivalent: E17 |
| bounds.rs 126:32 the tenth varint byte's `b > 1` → `==`, `<`, `>=` | killed: `varints_are_read_as_postcard_reads_them` (`>=` and `==` refused a valid ten-byte varint ending in 1: degree bits up to `usize::MAX` decode; `<` let a tenth byte of 2 past the walk, to `postcard`) |
| bounds.rs 250:27 ×2, 252:15 ×2, 256:19 ×2, 319:19 `*=` (`cap_index`, the commitment named in the two-roots message) | killed: `a_commitment_with_two_roots_is_named_by_its_index` (diagnostic text only, cheap to pin: the index of every commitment, as `check_canonical_form` numbers them) |

Re-run (`rerunZ`): 20 caught, 6 missed: E17 (2) and the 4 analysis `delete field`
mutants, which this oracle cannot reach (below).

### zk/src/lib.rs analysis helpers (before-analysisA: 5 missed)

| Mutant | Resolution |
|---|---|
| 662:9 `trace_widths` → `vec![0]`, `vec![1]` | killed: `every_px_statement_is_within_the_decoder_limits` pins the transfer's 13 widths (and px/tests/proof.rs compares them with the real proof) |
| 634:21 `delete field preprocessed_width`; 649:42 `- 1` → `+ 1`, `/ 1` (the trace length) | equivalent on the helper's every input: E18 |

### px/src/prove.rs (before-proveW: 12 missed)

All 12 were in `check_shape` and `check_shape_bits`: `check_shape` → `Ok(())`,
`check_shape_bits` → `Ok(())`, 377:20 ×3 and 377:29 and 377:44 (the function count),
392:32, 393:9, 396:33, 396:64 ×2 (the degree-bits comparison). Killed by
`the_shape_check_accepts_exactly_the_statements_degree_bits` (px/tests/proof_limits.rs):
for every function count the statement's degree bits pass, every table one higher
or lower, a table more or fewer, another call count and an unregistered function fail
with their errors, `n_fn = MAX_FN + 1` is `Shape`, and `check_shape` reads only a
decoded hollow proof's degree bits. `PROOF_LIMITS`'s 7 mutants were already caught
(the limit is pinned at 23).

### tx/src/validate.rs (before-validateW: 3 missed, 1 unviable)

`check_px_proof`, `check_px_proof_shape` and `check_px_proof_shape_bits` → `Ok(())`:
killed by tx/tests/px_proof_wiring.rs (`decode_px_proof` decodes a hollow proof; only
its degree bits decide the shape check, from the proof or the bits; the full check
refuses it; PX proofs decode under the 23-table PX limits, not the 33-table
envelope). `decode_px_proof` → `Ok(Default::default())` does not compile.

### p2p/src/net/admission.rs (before-admissionP: 14 missed)

| Mutant | Resolution |
|---|---|
| 208:12 `delete !` (`px_global.take`), 211:32 `+=` → `*=` (drops), 218:28 `+=` → `*=` (taken) | killed: `a_px_transaction_past_the_cheap_stage_takes_a_node_wide_token` (25 shape-valid hollow-proof transactions from 7 peers: one token each until the burst of 10 is spent, the rest dropped unverified and counted) |
| 211:32 and 218:28 `+=` → `-=` | caught in the census by an overflow abort; under release arithmetic killed by the same test (`ovfP`) |
| 321:86 `c.height() + 1` → `-`, `*` (the contextual rules' height) | killed: the same test (the first transaction is valid from the next block on, PX6) |
| 323:13 `delete match arm` (the shape check on the off-actor degree bits) | killed: `a_decodable_proof_of_the_wrong_shape_is_penalized_in_the_cheap_stage` |
| 331:67 `c.height() + 1` → `*` (`is_stateless_at`) | killed: `a_px_proof_failure_is_not_penalized_in_the_activation_grace_window` (second epoch at 150: penalized at height 88, not at 89, whose next block opens the grace window) |
| 254:5 `px_pre_checks` → `Some(None)`; 257:44 `+` → `*`; 264:9 `delete match arm`; 273:19 guard → `true`, `false` | unobserved by any test: E19 (where the stateless checks run; the log line of a contained panic) |

After (`after-admissionP`): 19 caught, 5 missed, exactly the E19 set. 303:52
(`cheap_checks`' expiring-soon height `+ 1` → `- 1`) was caught in the census but
survived release arithmetic (§ Release arithmetic): now killed by
`an_expiring_soon_px_transaction_is_judged_at_the_next_blocks_height` (`ovfP2`).
`px_stateless` → `Default` and `px_pre_checks` → `Some(Some(Default))` do not compile.

### The W4-SYNC rules (before-syncP: 11 missed)

| Mutant | Resolution |
|---|---|
| conn.rs 391:54 `theirs.height > height` → `==`, `>=` (the handshake's request) | killed: `the_handshake_asks_for_headers_for_more_height_or_an_unknown_tip`. With the default tick the maintenance loop asks a taller peer anyway within one tick, which hid `==`; the test slows the tick to a minute |
| conn.rs 568:30, 568:50 `\|\|` → `&&` in `knows_tip` | killed: the same test (our connected tip, off our best header chain after a heavier header-only branch, is known: neither our best header nor in our locator) |
| headers.rs 762:5 `end_of` → `(true, 0)`, `(true, 1)`; state.rs 150:9 `has_header` → `()`, 150:17 `>` → `==`, `<`, `>=`; state.rs 143:55 `\|\|` → `&&` in `wants_tip` | killed: `tips_are_not_echoed_to_the_peer_that_delivered_their_headers` (the peer's Version tip and both of its batches count, the second, heavier, replacing the first, and not an equal-work sibling; under each mutant N echoed its new tips to the peer) |

After (`after-syncP`): 35 caught, each former survivor by the test written for it.

### chain/src/manager/summary.rs (before-summaryC: 1 missed)

`<impl Debug for SummaryCell>::fmt` → `Ok(Default)`: killed by
`the_summary_flags_a_tip_off_the_best_header_chain_and_calls_tip_listeners`
(chain/tests/manager.rs), which also kills the other three without the network tests.
The hand mutants: HM1 (`true`) is caught only by that chain test; HM2 (`false`) by it
and by `rt_sync_a_draining_node_does_not_echo_tips_to_a_peer_ahead` ("11 ancestors of
E's tip were announced to it").

### consensus/src/pow.rs

The bounded store's code changed in `9bba1bd` (RT-POW L1–L3) after run A's `runPow3`:
the census ran again on the whole file with the whole consensus suite, as `runPow3`.
182 mutants: 130 caught, 4 missed, 8 timeouts, 40 unviable.

| Mutant | Resolution |
|---|---|
| 161:28 `+=` → `-=`, `*=` in `held::acquire`; 170:27 `==` → `!=` in `held::release` (the debug-only handle count of the caller rule) | killed: `pow::tests::the_debug_handle_count_counts_each_handle` (two handles count 2, one released leaves 1); only the refusal at a count of 1 was tested |
| 546:17 `Pending`'s `Drop` → `()` (the prebuild mark's guard) | unobservable: E20 (since `9bba1bd`, `fetch` clears the mark on every exit; the guard matters only when the OS refuses a thread) |

- **Timeouts.** The 8 are `check_hash` (12:5 ×2, 12:19, 20:20 ×2, 20:41, 20:50,
  22:11), as in run A: the chain unit tests' nonce searches never end under them. In
  isolation (`timeoutPow`) all 8 fail `check_hash_boundaries_golden` (3 also the
  header-chain golden tests) within 120 s.
- **Re-run** (`rerunPow`): 3 caught, 1 missed (E20).

## Boundary pass

cargo-mutants 27.1.0 turns `>` into `>=` and `<` into `<=`, but never `>=` into `>`
or `<=` into `<`, so an off-by-one at an inclusive bound is never tested (RT-MUTC
found two real survivors this way in run C's scope). `boundary.py` applies exactly
those mutants, one at a time, to a copy of the worktree (`git ls-files` of the final
tree), runs the scope's oracle with `--profile mutants`, and restores the file. The
scope's functions hold five such comparisons; the others in the files (connection
limits, ban scores, tests) are outside it.

| Mutant | Oracle | Result |
|---|---|---|
| zk/src/bounds.rs 139:24 `n <= cap` → `<` (`Reader::len`, every capped vector) | zk lib, `decode_bounds`, `rt_pxdos_differential` | caught: `at_the_caps_nothing_is_refused_by_the_bounds`, `every_cap_refuses_one_more` and 6 more |
| consensus/src/pow.rs 28:15 `height <= epoch + lag` → `<` (`seed_height`) | the consensus suite | missed: equivalent, E21 (= run C's E27) (both branches give 0 at `E + L`) |
| pow.rs 291:27 `side.len() <= side_cap` → `<` (`trim`) | the consensus suite | caught (4 pow tests) |
| pow.rs 417:51 `alive + 1 + reserve <= MAX_CACHES` → `<` | the consensus suite | caught (4 pow tests) |
| pow.rs 418:58 `evicted(alive) <= 1` → `<` | the consensus suite | caught (2 pow tests) |

Baselines on the same copy passed first (zk 3 + 10 + 4, consensus 70 + 17 + 2 + 2 +
1 + 1). Results in `boundary.txt`. No comparison of the decoder's caps is off by one.

## Release arithmetic

The census builds with overflow checks and debug assertions on, so a mutant can be
caught by an overflow panic that a release build would not have. Every caught
mutant's log was searched for `with overflow` and abnormal exits:

- **zk (`ovfZ`): 6 of 6 caught** with both off (bounds.rs 103:18, 278:22, 290:38,
  319:19, 324:26, 341:57), each by a failed assertion.
- **prove.rs, validate.rs, the analysis helpers, the W4-SYNC rules, summary.rs:** no
  log shows an overflow.
- **admission (`ovfP`): 2 of 4 caught.** 211:32 and 218:28 `-=` by the token test.
  257:44 `+ 1` → `- 1` in `px_pre_checks` survives: at height 0 it wraps, refuses
  decoding off the actor for the windowed transactions, and `cheap_checks` decides
  (E19). 303:52 `+ 1` → `- 1` in `cheap_checks` survived: at height 0 the wrapped
  height refuses the same transactions as the code, and the only test ran at
  genesis; the new test at height 10 kills it (`ovfP2`: 1 of 1 caught, by
  `an_expiring_soon_px_transaction_is_judged_at_the_next_blocks_height`).
- **pow.rs (`ovfPow`): 4 of 6 caught** (28:15 `<=` → `>` and 28:24 `+` → `-` in
  `seed_height`, 417:37 and 437:26 in `fetch`), each by an assertion.
  - 267:50 `resident.len() + building.len()` → `-` in `evicted` survived: in a debug
    build it underflows (caught), in release it wraps or overcounts by twice the
    builds in flight, and no test had a build in flight with at least as many kept
    caches. A new assertion in `a_side_build_leaves_room_for_the_missing_hot_keys`
    (two kept, two in flight: no evicted cache) kills it (`ovfPow2`: 1 of 1, "left:
    4").
  - 536:29 `prebuild_seq += 1` → `-=` survived: the numbers stay distinct (E22).

## Flaky tests

`p2p/tests/network.rs` `relaying_headers_of_a_block_with_an_invalid_body_is_not_penalized`
failed on the unmutated tree, alone, 1 time in 3 ("a rule-breaking header gets the
peer banned", line 1865: the peer was not disconnected within 5 s after its broken
header), and in both hand-mutant runs. `pings_are_answered_while_a_header_batch_is_verified`
timed out ("batch verified") 2 times in 5 under the machine's load. Both were left
out of the sync oracle. Not investigated further (outside this run's scope); the
first may be a dropped single-header announcement while the peer's earlier batch is
still being verified, which would make the penalty depend on timing.

## Tool notes

- cargo-mutants 27.1.0 applies `--re` and `--exclude-re` to every mutant but the
  `delete field … from struct … expression` ones, which are always listed for the
  files given with `-f`. They are reported where their oracle reaches them.
- `--test-package` with `-C=--test=…` runs the named targets of every listed package;
  the tool's baseline cannot (run B), so these runs use `--baseline skip` and the
  baselines were run by hand on the same tree: px `proof_limits` 2 passed, tx
  `px_proof_wiring` 2 passed, the admission list 27 passed (33 s), the sync list
  24 + 1 + 1 passed (24–100 s), all with `--profile mutants`.

## Limits

- **Operators.** The census covers cargo-mutants' mutation operators, not every
  possible fault. A caught mutant shows only that some test notices that change.
- **Function scope.** In admission.rs and the p2p sync files only the functions
  listed in the scope were censused (the code W4-PXDOS and W4-SYNC added or
  changed); the rest of those files was not.
- **Oracles.** Non-proving tests only, except the hand-picked network test lists.
  Real proofs reach these paths only in the proving tests (CI's PX-proving step),
  which were not oracles; the hollow proof stands in for them up to the shape
  check, never beyond.
- **E19 is a limit of the oracle**, as E15 is: no test observes on which thread a
  PX transaction's stateless checks run.
- **E18 holds on the helper's inputs** (the PX statements), not for every AIR.
- **Timeouts as kills.** None in this run: pow.rs's 8 timeouts fail assertions in
  isolation.
- **Boundary pass.** Hand-applied to the `>=`/`<=` comparisons inside the scope's
  functions only (5), not to every comparison of the files.

## Commits

On branch `w4-mutd` (base `11cb583`), tests and evidence only:

- `beea8f9` zk tests: kill the survivors of mutation run D in the proof decoder's bounds
- `332966b` px, tx tests: the decode-bounds wiring and the shape check without proving
- `5e68f94` p2p, chain tests: kill the survivors of mutation run D in admission and
  header sync
- `2a46a9a` p2p tests: the expiring-soon refusal above genesis (release arithmetic)
- `8c43dc3` consensus pow tests: kill the survivors of mutation run D in the bounded
  cache store
- `10796be` px tests: the real transfer proof's trace widths (px/tests/proof.rs, PX-proving;
  § Proving test)
- `0338732` tx tests: arrays, not vectors, for the hollow proofs' degree bits (clippy)
- this evidence and E17–E22 in docs/reviews/mutation-exemptions.md

## Proving test

`px/tests/proof.rs` (PX-proving, in CI's PX-proving step) gets one assertion: the
real transfer proof's `trace_local` lengths equal the widths
`analysis::trace_widths` reports and px/tests/proof_limits.rs pins. It was run once
locally (`cargo test --locked --release -p blacksilk-px --test proof --
--test-threads=1`, with at least 7 GB free): 3 passed in 188 s.
