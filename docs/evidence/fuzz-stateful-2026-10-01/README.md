# Stateful fuzz harnesses (W4-STATEFUL)

Internal engineering evidence, not an audit. This covers the three stateful
harnesses that decisions "W4-FUZZ and RT-FUZZ" made P1 before the freeze, and a
small extra one for the wallet's header feed. All runs were on one Windows
machine, one fuzzer process at a time, ten minutes per target, and two other
agents' jobs shared the machine.

These runs found no crash, invariant failure, leak, timeout or out-of-memory
report. That shows what these inputs reached in this time. It does not show
that the surfaces are free of bugs.

## What was added
Commit `a4643e5` (branch `w4-stateful`, base `11cb583`).

| Target | Surface | Stable twin (in the owning crate) | Seeds |
|---|---|---|---|
| `peer_protocol` | one connection's handshake negotiation and per-peer protocol (`conn::run_connection`) | `p2p/tests/fuzz_peer_protocol.rs` | 28 |
| `px_admission` | a relayed PX transaction's admission steps and verification | `p2p/tests/fuzz_px_admission.rs` (PX-proving, `#[ignore]`) | 18 |
| `scan_outputs` | wallet-side output scanning (`tx::scan`) | `tx/tests/fuzz_scan.rs` | 19 (+2 from the generator's PX run) |
| (none) | the wallet's header feed (`for_each_header`, `node_id_at`) | `wallet/src/wallet/fuzz_headers.rs` (`cfg(test)`) | 12 |

- **Bodies:** every target's body and invariants are in `fuzz/src/targets/<target>.rs`. The
  libFuzzer target and the stable twin run the same body. The twin's iteration
  count comes from `BLACKSILK_FUZZ_ITERS` (default 2,000).
- **Shared chain fixture:** `peer_protocol` and `px_admission` use
  `fuzz/src/targets/chain_fixture.rs`, a deterministic regtest chain.
- **No libFuzzer target for the wallet header feed.** The wallet crate pulls
  reqwest and hyper, so it stays out of the fuzz workspace, and the paging
  functions are private. Its twin is a `cfg(test)` module next to them.

### The seam (F41-9), and why it changes no behaviour
- **`Network::start_with` (`p2p/src/net.rs`).** Its state construction moved
  unchanged into `new_inner`. `start_with` calls it and then starts its tasks
  as before.
- **`p2p/src/net/fuzzing.rs`.** It exists only with the new p2p feature
  `test-hooks`.
  - Only p2p's own dev-dependencies and the fuzz workspace turn the feature on.
    No node, wallet or tool manifest names it.
  - `Victim` builds the network state with `new_inner`, with a seeded
    generator, no listeners and only the header and block workers. It then
    runs the real `conn::run_connection` on a stream the harness provides.
  - `admission` calls `admission::for_tests` (also feature-gated). That runs
    `admit_tx`'s chain-side steps, then `on_tx`'s verification and scoring,
    with the same functions in the same order.
- **What the harness leaves out:**
  - the peer's relay budgets, the reject caches and the node-wide PX token,
    which are network state;
  - the inbound handshake slot. `run_connection` gets `None`, as an outbound
    connection does.
- **No sans-IO rewrite.** The harness drives the real async code on a paused
  tokio clock instead (tokio's `test-util` feature in the dev and fuzz builds
  only; no new crate).
- **Time.** Pre-Verack timing is exact: the handshake reads only tokio time
  and the published chain snapshot.
  - After registration, a command to the chain actor's thread can let the
    paused clock advance while the runtime waits for it.
  - So after `Verack` the harness checks no timing, only the invariants below.

## Invariants
Each body's header comment gives the full list. In short:

- **`peer_protocol`.**
  - **Model.** A model of the negotiation (docs/p2p.md §4) predicts the
    result from the script alone. The model takes its limits from the
    specification, not from the code under test: 20 s deadline, 5 s and 10 s
    key-exchange timeouts, 8 unknown frames.
  - **Exact prediction.** It predicts registration, or the exact virtual
    instant of the close: at the deciding frame, at the key-exchange timeout,
    or at the deadline.
  - **Before registration.** Nothing is scored or banned, and the address
    and peer tables do not change. A decrypt failure counts only as a
    transport failure.
  - **Reads before `Verack`.** No read before `Verack` asks for more than
    `MAX_HANDSHAKE_FRAME` plus its tag. Nothing is read beyond the bytes the
    model consumes. Over 8 unknown frames close the connection.
  - **The victim's messages.**
    - Its `Version` carries our network and protocol, and either no listen
      address or our public one.
    - On a block-relay-only connection it carries no listen address and no
      transaction relay, and the victim never sends address or transaction
      messages there.
    - Before registration it sends only `Version` and `Verack`.
    - Everything it sends decodes.
  - **Cleanup.** At the end, the peer, its block and transaction requests,
    its Dandelion stems and its handshake nonce are gone.
- **`px_admission`.**
  - **Setup.** The chain has 75 blocks and a deployed vault contract; the
    base is a real PX deposit.
  - **Edits.** `px_tx_struct`'s edits, calls of the registered vault
    function, and `proof_struct`'s edits of the decoded proof.
  - **Stable verdicts.** The stateless and cheap checks give the same
    verdicts twice.
  - **Early refusal.** Whatever the cheap checks refuse (except the expiry
    policy), `check_tx` also refuses. What they score is stateless for
    `check_tx` too.
  - **Scoring.** A verification failure is scored exactly when it is
    stateless, or is a signature failure.
  - **Non-malleability.** A transaction that passes verification is the
    base itself. This holds only over the edits the target makes.
  - **Bounds.** A decoded proof has at most 64 degree bits. The cheap
    checks take at most 2 s plus 2 µs per byte.
  - **Panics.** Any panic fails, including one the decoder or the verifier
    contains with `catch_unwind`. libFuzzer's hook aborts on it, and the
    twin counts panics through its own hook.
- **`scan_outputs`.**
  - **Exact outcomes.** Every output's outcome must equal one derived
    independently with the secret keys: not owned, owned by subaddress `s`,
    refused for the anchor, or refused for the commitment.
  - **How it is derived.** The derivation uses the shared secret `k_v·R`,
    the hashed view tag, offset, mask, amount pad and anchor pad, and a
    search of every subaddress spend key. It does not use the scanner's
    table lookup or `janus::verify`.
  - **Owned outputs.** Their offset, mask and amount must match the
    derivation, and `(x + d)·G = O`.
  - **Indices.** `scan_block` over two copies shifts the global indices
    correctly.
  - **Time.** The scan takes at most 250 ms plus 20 ms per output.
- **Wallet header feed.**
  - **Requests.** Each request asks for 1 to 2,000 headers, from the next
    height not yet delivered, and never past the range.
  - **Delivery.** Delivered headers are consecutive, start at the range's
    start, and are ones the node served. A success covers the whole range.
  - **Honest node.** It needs exactly `ceil(n / 2000)` requests.
  - **No loops.** There is at most one request per header, plus one.
  - **`node_id_at`.** It returns the served header's id, `None` only for an
    empty answer, and an error otherwise.

## Do the oracles catch real bugs? Injected-bug demonstrations
Each bug was a local edit, never committed. The twin ran on its seeds
(`BLACKSILK_FUZZ_ITERS=0`, or 300 for the scan cases) in a release build, and
the source was restored afterwards (`git diff` empty). Every injected bug was
caught:

| Edit (product code) | Caught by |
|---|---|
| D1: `conn.rs` skips 9 unknown frames instead of 8 | `peer_protocol`: "the peer was registered" (`unknown_9`) |
| D2: the victim's handshake deadline 21 s instead of 20 s | `peer_protocol`: "the victim closed at 21s, not at 20s" |
| D3: handshake frames read with `recv()` (`MAX_FRAME`) instead of `recv_limited(MAX_HANDSHAKE_FRAME)` | `peer_protocol`: "an unregistered connection is still open after 0ns (Closed(0ns))": a 4,113-byte frame was accepted and skipped |
| D4: our listen address sent on a block-relay-only connection | `peer_protocol`: "our address on a block-relay-only connection" |
| D5: the address table written on a wrong-network `Version` | `peer_protocol`: "the address table changed before registration" |
| S1: `stealth::scan_output` skips the view-tag check | `scan_outputs`: `Owned(..)` where `NotOwned` was derived |
| S2: the Janus anchor check skipped | `scan_outputs`: `Owned(..)` where `Refused(.., JanusAnchorMismatch)` was derived |
| S3: the commitment check skipped | `scan_outputs`: "the amount does not open the commitment" |

### Tautological model limits (found and fixed during development)
The first version of the model took its limits (the deadline, the timeouts
and the unknown-frame count) from the product's constants, re-exported through
the hooks. With D1 and D2 applied, that version still passed: the model just
followed the changed code. Two changes fixed this:

- the limits are now the specification's numbers, in the target body;
- the close-time check has an upper bound as well as a lower one.

The re-exports were removed.

## Results

### libFuzzer, `-O -a` (optimized, debug assertions and overflow checks), AddressSanitizer
- **Build.** The binaries were built from commit `a4643e5` with a clean tree,
  using `cargo +nightly-x86_64-pc-windows-msvc fuzz build -O -a --fuzz-dir .`
  (rustc 1.100.0-nightly 2026-09-23, cargo-fuzz 0.13.2).
- **Run.** The prebuilt binaries were run directly by [run/run1.sh](run/run1.sh)
  and [run/chain.sh](run/chain.sh) (the 1,500 s `px_admission` run by
  `run1.sh px_admission 1500 final2`), with the flags of `fuzz/run_campaign.sh`.
- **Corpora.** Each run started from the corpus that the target's earlier
  runs had grown, plus the generator's seeds. The full generator run included
  the PX seeds and `px_admission_base/tx`, at 2,404,002 bytes.

| Target | Time (s) | Executions | Exec/s | cov/ft start → end | Corpus files | New units | Last new unit at | Peak RSS (MB) | Artifacts | Findings |
|---|---|---|---|---|---|---|---|---|---|---|
| `peer_protocol` | 602 | 66,200 | 110 | 11132/30634 → 11527/33490 | 1,243 → 1,791 | 603 | execution 65,185 (98 %) | 558 | 0 | 0 |
| `scan_outputs` | 602 | 12,752 | 21 | 2230/8051 → 2371/8479 | 446 → 641 | 225 | execution 12,502 (98 %) | 491 | 0 | 0 |
| `px_admission` (600 s) | 725 | 287 | 0 | 14877/25845 (load only) | 285 → 285 | 0 | none | 625 | 0 | 0 |
| `px_admission` (1,500 s) | 1,514 | 2,012 | 1 | 14888/24924 → 15660/29816 | 285 → 698 | 429 | execution 2,012 (100 %) | 634 | 0 | 0 |

- **Exit status.** Every fuzzer exited 0. No log holds a panic or an `ERROR`
  line.
- **`px_admission` at 600 s only loaded its corpus.** The 285 inputs it had
  grown earlier took the whole 600 s to load: inputs that pass the cheap
  checks are verified, at seconds each under AddressSanitizer. No mutation
  ran.
- **The 1,500 s run.** Its load was quicker, so it ran 1,726 mutations after
  it. Treat its numbers as the campaign's for this target.

Sources: [run/summary.txt](run/summary.txt), from the libFuzzer logs.

### Earlier runs (development)
These ran on uncommitted trees whose oracles are the committed ones. The
committed tree added only the reach counters.

| Target | Time (s) | Executions | cov/ft start → end | Findings |
|---|---|---|---|---|
| `peer_protocol` (run 1, with length control: inputs stayed at 46 bytes) | 605 | 10,134 | 9259/18522 → 11021/23206 | 0 |
| `peer_protocol` (run 2, `-len_control=0`) | 607 | 50,990 | 10839/22797 → 11342/31218 | 0 |
| `scan_outputs` | 603 | 10,898 | 1653/5902 → 1774/7576 | 0 |
| `px_admission` (smoke) | 126 | 83 | 5331/9461 → 14270/21266 | 0 (one slow-unit file: see below) |
| `px_admission` | 605 | 608 | 14287/21325 → 14883/26478 | 0 |

An invalid run was discarded. One `scan_outputs` run (`run1`) used
`cargo fuzz run`, which rebuilds from the working tree. It started while an
injected-bug demonstration (S1) had `crypto/src/stealth.rs` edited, so it ran
the broken scanner.

- **What it showed.** It failed at once with `Owned(..)` where `NotOwned` was
  derived. This shows that the libFuzzer target catches S1 too, but the run is
  not evidence for the committed code.
- **The fix.** Since then the run script calls the prebuilt binary, and
  writes its timestamp into the run's `.meta` file. Nothing is rebuilt during
  a run.

### Stable twins (release builds, plain allocator)

| Twin | Command | Inputs | Result | Reached |
|---|---|---|---|---|
| `peer_protocol` | `BLACKSILK_FUZZ_ITERS=10000 cargo test --locked --release -p blacksilk-p2p --test fuzz_peer_protocol -- --nocapture` | 10,028 | pass, 108.8 s | registered 2,056; closed at a frame 5,271; at the key-exchange timeout 885; at the deadline 1,816; decrypt failures 524 |
| `scan_outputs` | `BLACKSILK_FUZZ_ITERS=20000 cargo test --locked --release -p blacksilk-tx --test fuzz_scan -- --nocapture` | 20,019 | pass, 182.8 s | outputs not owned 94,630; owned 59,390; refused for the anchor 13,779; for the commitment 1,011 |
| wallet header feed | `BLACKSILK_FUZZ_ITERS=20000 cargo test --locked --release -p blacksilk-wallet --lib fuzz_headers -- --nocapture` | 20,012 | pass, 37.7 s | (no counters) |
| `px_admission` (PX-proving, alone, 8.4 GB free) | `BLACKSILK_FUZZ_ITERS=2000 cargo test --locked --release -p blacksilk-p2p --test fuzz_px_admission -- --ignored --test-threads=1 --nocapture` | 2,018 | pass, 674.2 s | not decoded 787; dropped or expiring 9; refused early: scored 476, contextual 109; failed verification 250; passed 387 (each the base itself) |

## Findings
**None.** No product bug was found. These were harness defects found and
fixed during development, and none is a product bug:

- **Tautological limits.** The model took its limits from the code under
  test (above).
- **Wallet twin index.** On a failed node call nothing is recorded, and the
  twin indexed an empty list. Fixed in the twin.
- **px_admission slow units.** The base transaction, unedited, passes the
  cheap checks and is verified. Under AddressSanitizer one such input took
  14 s, and libFuzzer wrote a `slow-unit-` file at its default threshold of
  10 s. `run_campaign.sh` treats any artifact as a failure, so `px_admission`
  runs with `-report_slow_units=60`.

## Coverage and limits, read honestly
- **Robustness only for `px_admission`.**
  - Verifier grinding is NOT disabled in these builds. An edit that changes
    the statement fails Fiat-Shamir's query proof of work before the FRI
    checks.
  - What it shows is robustness, scoring consistency and non-malleability
    over the edits reached, not soundness (F41-8).
  - 387 of the twin's 2,018 inputs passed verification. Each was an edit
    that left the transaction unchanged.
  - The libFuzzer target runs at about 1 execution per second.
- **`px_admission` uses one transaction shape.** The base is a deposit with
  no function call. Calls of the registered vault function are added by the
  edits, so the registry lookup and the shape check run against a real
  registration. No base carries a real function proof.
- **Dandelion is reached only shallowly.** The fuzzed `StemTx` and `Tx`
  bodies are not valid transactions on the victim's chain, so they stop at
  decoding or at the cheap checks. No input sets up a stem route.
  - What is checked: a block-relay-only connection never carries transaction
    messages, and a peer's stem state is cleaned up when it leaves.
  - What is not reached: the stem-or-fluff decision with a valid stem
    transaction.
- **After `Verack` only invariants, no timing**, for the reason given under
  the seam.
- **One connection per input.** No eviction, no handshake caps and no
  multi-peer interaction. The inbound handshake slot is not modelled.
- **Coverage still growing.** Every target was still finding new units at
  the end of its run, the last one after 98 % or more of its executions.
  These are short runs, not saturation, and `px_admission` ran only 1,726
  mutations.
- **Platform caveats (unchanged from W4-FUZZ2):**
  - a Rust panic aborts with `STATUS_STACK_BUFFER_OVERRUN` and leaves no
    crash artifact on Windows;
  - `-s none` does not link.
- **Time bounds are deliberately loose.** The `scan_outputs` and
  `px_admission` time bounds sit far above the measured cost, so a shared
  machine does not trip them. They catch superlinear behaviour, not small
  regressions.

## Reproducing
1. **Seeds.** In `fuzz/`, run `cargo +nightly build --locked --release --bin
   seeds`, then run `seeds.exe` in a scratch directory. Its PX part needs
   7 GB free and about 3 minutes.
2. **Build.** Run `cargo +nightly fuzz build -O -a --fuzz-dir .`.
3. **Run.** Run [run/run1.sh](run/run1.sh) `<target> 600 <tag>` for each
   target (1,500 s for `px_admission`, whose corpus load alone can take
   10 minutes).
   - It needs MSVC's ASan runtime on `PATH`.
   - It sets `BLACKSILK_FUZZ_SEEDS` to the scratch directory, which
     `px_admission` reads its base from.
4. **Twins.** Run the commands in the table above.
