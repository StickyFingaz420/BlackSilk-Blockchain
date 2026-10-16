# Mutation run G8: the supply audit (`tools/supply-audit`)

Internal engineering work, not an audit. A mutation census shows which code changes
the tests notice; it does not show that the code is correct or secure.

The gate (decisions "Agent 42", "W4-MUT and RT-MUT", "RT-MUTD"): zero unexplained
missed mutants per completed file or function set. Every survivor is killed by a new
test or explained in [mutation-exemptions.md](../../reviews/mutation-exemptions.md).
G8 is the batch that run G left out ([run G](../mutation-runG-2026-10-12/README.md),
"Not in run G"), run as planned in
[plans-g8-742-2026-10-15.md](../../reviews/plans-g8-742-2026-10-15.md), Plan 1.

**Result: the criterion is met for `tools/supply-audit/src/*.rs`.** Of 227 mutants,
211 are caught (161 by the tests at the base, 50 by tests added for G8, each with a
kill record), 15 are unviable, and 1 is equivalent and exempt (E90, proof checked by
a second reviewer). All 15 hand mutants (H1-H12, H5b, H10b, H10c) fail a test. No
production line changed: the new tests are test files, appended `#[cfg(test)]`
modules and dev-dependencies on workspace crates.

## Scope

- **Code:** `tools/supply-audit/src/lib.rs` (200 mutants) and `src/main.rs` (27):
  the `Pinned` node view, `scan_chain`, `audit`, `summarize`, the report and the CLI.
- **Base:** `e21eb4a` (`rebuild/core`). `tools/supply-audit/` and its dependencies are
  unchanged from `432b8c2` (the plan's base) to `e21eb4a`; the list at `e21eb4a` is
  byte-identical to the plan's and run G's (`ledgers/G8-list.txt`).
- **Tests added** (branch `tests/g8-supply-audit`, on `e21eb4a`):

| Commit | Tests |
|---|---|
| `beccd2b` | T1, T1c: `tests/pinned.rs` |
| `7d794c7` | T2: `tests/px_scan.rs` |
| `d49e3fb` | T4, T5, T6, T8, T9, H3 test: `tests/regtest.rs` |
| `93cb3e2` | T9u: `src/main.rs` test module; T10: `src/lib.rs` test module `report_tests` |
| `f14a690` | T3: `tests/px_scan.rs`; T7: `tests/px_audit.rs`; dev-dependencies `blacksilk-px`, `blacksilk-px-core`, `blacksilk-zkvm` (path crates) |
| `29284c2` | T11: `tests/regtest.rs` |
| `855c024` | exact messages in T5 and T3 (red team) |

- **Not in G8:** everything outside `tools/supply-audit/src/`. The wallet, chain,
  node and RPC code the tests exercise is covered by its own runs, not by this one.

## Method

- **Tool:** cargo-mutants 27.1.0, `--profile mutants` (the test profile with overflow
  checks and debug assertions), `--cap-lints true`, `--build-timeout 2400`,
  `--timeout 300`; toolchain rustc 1.98.1 (48a229cea 2026-09-01,
  x86_64-pc-windows-msvc), cargo 1.98.1; Windows 10 Pro 10.0.19045, i7-6700 4C/8T,
  16 GB. `CARGO_BUILD_JOBS=2`, `CARGO_INCREMENTAL=0`, `CARGO_TARGET_DIR` unset,
  `TMP` in a per-batch directory; never `--in-place`.
- **Selection:** anchored `--re` per mutant name (`args/`, made by the run G
  `mkargs.py`), each checked with `--list`. The two `delete field` mutants are not
  filtered by `--re` and ride along; they are counted once, in stage 1b.
- **Step 0 (measured, no mutants):** baseline build 478 s; tests: lib 1 s, px_scan
  0 s, regtest 2 s; regtest test executable peak 42 MB, rustc peak 347 MB. No PX
  proving anywhere, and the regtest wallets do not check headers, so no RandomX
  cache is built. Hence `--jobs 2`.
- **Stages:**

| Run | Base | Selection (`args/` sha256) | Oracle | Result |
|---|---|---|---|---|
| `runG8s1a` | `e21eb4a` | SC1 + SC2, 151 (`G8-sec.args` `e46b4621…`) | `--lib --test px_scan` | 54 caught, 87 missed, 10 unviable |
| `runG8s1b` | `e21eb4a` | the rest, 76 (`G8-rest.args` `4eb9039b…`) | same | 41 caught, 30 missed, 5 unviable |
| `runG8s2` | `e21eb4a` | stage-1 missed, 117 (`G8-s2.args` `58471b6d…`) | `--lib --bins --test regtest` | 66 caught, 51 missed |
| `runG8k1` | `e21eb4a` + T1-T10 (uncommitted, before fmt) | the 51 survivors (`G8-k1.args` `8232f631…`) | `--lib --bins --test px_scan --test pinned --test regtest` | 40 caught, 11 missed |
| `runG8k2` | `f14a690` | the 51 survivors (same args) | k1 + `--test px_audit` | 49 caught, 2 missed |
| `runG8k3` | `29284c2` | 618:50 `>=` (`G8-k3.args` `65faadb0…`) | k2 | caught |
| `runG8k4` | `855c024` | 436, 437, 618:44, 618:50 (`G8-k4.args` `eb568092…`) | k2 | 8 of 8 caught |

  Full sha256 of every file here: `SHA256SUMS` (over the committed, LF-normalized
  bytes; a checkout that converts line endings must convert back before checking).
- **Command shape** (`$RE` is the args file):

```text
cargo mutants -p blacksilk-supply-audit -f 'tools/supply-audit/src/*.rs' $RE \
  --profile mutants --cap-lints true --build-timeout 2400 --jobs 2 --timeout 300 -o <out> \
  -C=--lib -C=--bins -C=--test=px_scan -C=--test=pinned -C=--test=regtest -C=--test=px_audit
```

- **Hand mutants** (`patches/`, never committed): each in its own copy of the tree
  with its own target directory, `cargo test -p blacksilk-supply-audit --profile
  mutants --no-fail-fast` over the union oracle; each patch checked to be applied as
  written. H1 to H12 are the plan's (H8 `retain` removed, H9 `submit_tx` forwarded,
  H10 to H12 the `info` and `headers` pinning); H5b, H10b, H10c are variants.
- **Memory guard:** `memguard-G8.ps1` (from run G's `memguardconf.ps1`): every 5 s,
  every process of the batch including `rustc`, cap 4 GB per process, abort below
  1.5 GB free memory or 8 GB free disk, stops by verified PID only. No stop and no
  abort in any run. Each stage started only with at least 4.5 GB free.
- **Environment-failure scan** (`0xC0000142`, `os error 1455`, `0xC0000409`) of
  every mutant log: none.
- **Timeouts:** none in any run.

## Result

| | Mutants | Caught | Unviable | Equivalent (exempt) | Open |
|---|---|---|---|---|---|
| G8 (`lib.rs` 200, `main.rs` 27) | 227 | 211 | 15 | 1 (E90) | 0 |

- Caught by the tests at the base: 161; by the G8 tests: 50 (kill records in
  `ledgers/runG8k2.tsv`, `runG8k3.tsv`, `runG8k4.tsv`; the failing test per mutant in
  `final-G8-table.md`).
- **Unviable (15), all `error[E0277]` (`Default` not satisfied):** the eight `Pinned`
  `Ok(Default::default())` mutants (`rpc::Info`, `Blocks`, `Headers`, `Distribution`,
  `Outputs`, `SubmitResult`, `PxCommitments`, `PxContracts`), `node_params`
  (`ChainParams`), `audit` (`Report`), `parse_args` (`Args`), and four
  `read_password_file` replacements (`Zeroizing::new()` with no argument, three
  `Zeroizing::from_iter`). As a consequence the read-only refusal of
  `Pinned::submit_tx` had no viable cargo-mutants mutant; hand mutant H9 covers it.
- **Equivalent (1):** `lib.rs:618:24` `||` → `&&`, E90.
- Scores as in run G: (caught + timeout) / viable = caught / viable = 211 / 212.
  Scores are not the criterion.

## Survivors and the tests that kill them

| Test | File | Mutants killed |
|---|---|---|
| T1 `pinned_serves_exactly_the_audit_height` | `tests/pinned.rs` | 104:31, 104:17 `==` `>=`, 120:17 ×3, 120:31, 120:40, 126:34 ×2, 126:41 `*`, 126:56 ×2; H8, H9, H10, H10b, H11, H12 |
| T1c `pinned_never_requests_above_the_audit_height` | `tests/pinned.rs` | 107:67 ×2, 125:50 ×2 |
| T2 `the_scan_refuses_a_block_whose_transactions_or_id_do_not_match` | `tests/px_scan.rs` | 401:40 |
| T3 `a_deploy_is_counted_and_its_fee_is_owed_by_the_coinbase` | `tests/px_scan.rs` | 436:38 ×2, 437:30 ×2 |
| T4 `a_syncing_node_is_refused_and_one_without_a_header_height_is_audited` | `tests/regtest.rs` | 557:27 `<` |
| T5 `a_wallet_on_another_block_at_the_audit_height_is_refused` | `tests/regtest.rs` | 618:44, 618:50 `==` `<` |
| T6 `an_audit_at_the_genesis_with_a_wallet_that_never_synced` | `tests/regtest.rs` | (none alone; kept as a case) |
| T7 `px_records_over_two_wallets_account_for_the_pool`, `a_px_record_without_a_bridge_in_raises_the_alarm` | `tests/px_audit.rs` | 637:38 ×2, 655:35 `+`, 656:30 `+`, 669:41 `-`; H2, H4 |
| `equal_amounts_in_distinct_outputs_are_each_counted` | `tests/regtest.rs` | H3 |
| T8 `a_password_file_count_that_does_not_match_the_wallets_is_refused` | `tests/regtest.rs` | main.rs 122:8 |
| T9 `save_keeps_the_kdf_parameters_of_the_wallet_file` | `tests/regtest.rs` | main.rs 103:5 ×2, 103:20 `>`, 103:40 |
| T9u `file_kdf_reads_only_a_wallet_file_header` | `src/main.rs` (test module) | main.rs 103:25, 103:20 `==` `<=` |
| T10 (three tests) | `src/lib.rs` `report_tests` | 325:46 ×3, 325:28 ×2, 366:21, 478:23 `*`, 480:9, 488:31, 490:39 |
| T11 `an_audit_at_the_genesis_after_the_kept_block_ids_moved_past_it` | `tests/regtest.rs` | 618:50 `>=` |

Findings behind them (test gaps; no bug in the shipped code was found):

- **The read-only guarantee was untested:** with `Pinned::submit_tx` forwarding to
  the node (H9), every test passed (a rebroadcast of the pending transaction is a
  duplicate the node ignores).
- **A tampered block was never served to the scan:** a block with an extra
  transaction under its original header (same id, wrong tx_root) was accepted under
  401:40.
- **The PX half on the wallet side had no test** (F40-9): T7 builds a chain without
  proving, with records sealed to the audited wallets (1 050 bridged in, 50 out,
  pool 1 000; a spent record, two records of equal value, a missing wallet, a wallet
  listed twice, a record without a bridge-in). Its spend derives the PX nullifier key
  through the wallet's public APIs; that shapes the test chain only and checks
  itself (a wrong key leaves the record unspent and the exact-zero assertions fail).
- **The negative paths of `audit`:** a syncing node, a wallet on another block at the
  audit height, and a wallet whose kept block ids (720, `wallet/src/wallet.rs:50`) no
  longer reach the genesis.

The release binaries are not affected by the dev-dependencies:
`cargo tree -e features,normal --locked --offline` for `blacksilk-node`,
`blacksilk-miner`, `blacksilk-wallet` and `blacksilk-genesis` is byte-identical
before and after `f14a690`; `Cargo.lock` changes only in the supply-audit package's
dependency list; the lockfile gate passes.

## Resource use

Wall time: step 0 8 min; stages 1a 10 min, 1b 9 min, 2 14 min; k1 8 min, k2 8 min,
k3 3 min, k4 4 min; hand mutants 2 h 09 at the base (one at a time) and 40 min at
`f14a690` (two at a time). Batch memory at most 1.6 GB; lowest free memory 3.08 GB
(other work on the machine), above the 1.5 GB abort line.

## Review

- **Red team** (internal, multi-pass) on the branch: MERGE WITH FIXES; the fixes
  (exact messages in T5 and T3) are `855c024`, re-checked by `runG8k4`.
- **Second review of P1 (E90):** VERIFIED (internal red team, 2026-10-16).

## Limits

- The oracle is the supply-audit package's own tests; G8 says nothing about the
  wallet, chain or node code those tests run.
- T7 serves a hand-built chain from an in-memory node and does not prove PX
  transactions; whether proven transactions behave the same in the audit rests on the
  PX and wallet tests elsewhere.
- Not part of G8, noted: the regtest audit wallets do not check headers
  (`restore_check` and `verify_headers` are off for `Wallet::from_seed`); the audit
  trusts its own node for the header chain.

## Reproduction

- Code: a worktree at `e21eb4a` for stages 1a to 2; at the test commits for k1 to k4
  (k1 ran on the uncommitted T1-T10, before `cargo fmt`; k2 re-ran the same 51
  mutants at `f14a690`).
- Files here: `final-G8-table.md` (every mutant and hand mutant, its status, its
  killing test or compiler reason); `ledgers/` (per-run outcomes, the per-mutant
  ledger, the list, the hand-mutant results); `args/`; `patches/`; `SHA256SUMS`.
  The full cargo-mutants output directories, logs and guard logs are internal
  records in the lead's scratch area (`C:/bszkeval/g8-scratch`).
