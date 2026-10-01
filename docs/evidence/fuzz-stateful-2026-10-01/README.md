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

## Fix pass after RT-STATEFUL (2026-10-01)
Lead decision: W4-STATEFUL accepted with fixes. Commits:
- `b5114e3`: RT's `8260a9f`, cherry-picked. It adds a spec `MAX_HANDSHAKE_FRAME`
  (4096) to the model, and the scan oracle's coinbase-flag, height and hash
  checks.
- `132cca0`: the oracles below.
- `ccbb076`: the twin's per-field base digests, and an `anchor_unknown` seed.

### Product constants removed from the oracles
- **`peer_protocol`.**
  - The protocol versions (3 and 3) and the known message types (0 to 14)
    come from docs/p2p.md §4, §4.1 and §5. They no longer come from
    `PROTOCOL_VERSION`, `MIN_PROTOCOL_VERSION` or `is_known_type`.
  - `Verack` is its type byte alone (§5: no body).
  - Still from the product: the codec (`Message::decode`/`encode`), which
    decides whether a raw frame is malformed. A second strict decoder would
    be the codec again; the codec has its own target, `p2p_message`.
- **`px_admission`.** An independent table maps each `TxError` to the rule
  it reports, and each rule to its class:
  - T1–T11 are stateless and C1–C3 contextual (transactions.md §8.1,
    §8.2).
  - PX1–PX4 are contextual (§8.5).
  - PX3's output-word count, the PX structure and deploy rules, the
    inverted window and the repeats are stateless (px.md §11.3).
  - PX5 counts as misbehaviour (px.md §11.5).
  - PX6 and B8 are contextual (px.md §11.3).

  The early scoring must equal this class in both directions. A
  verification failure must be scored exactly when it is stateless, or when
  it is a signature over ring members at least 60 blocks deep (p2p.md §10).
  The harness computes that depth from the chain. The product's
  `is_stateless_at` and its own scoring verdict are no longer trusted.
  - **Ambiguity:** `DuplicateContract` has no class in the spec (px.md §11.3
    "Deploy"). It is taken as contextual; a PX transaction never reports it.
  - **Activation grace:** the grace near an activation (p2p.md §10) is left
    out. The harness asserts that the chain has a single rule epoch.
- **`scan_outputs`.** All three input contexts now come from the spec:
  - transfer and coinbase from transactions.md §3.1;
  - PX from px.md §11.1;
  - the hash tags are the spec's strings.

  The product's `t.output_context()` and context functions are no longer
  used.
  - **Ambiguity:** px.md §11.1 does not say how a nullifier (8 field
    elements) enters the hash. The harness uses eight LE32 limbs, the wire
    format's digest encoding.
  - The hash functions (`h32`, `h64`, `hash_to_scalar`) are still the
    product's.

### New coverage
- **PX transactions in `scan_outputs` (SC4).** A PX base transaction is
  added: three hidden outputs and two payouts, paying both wallets under the
  PX context. It is built without a proof, since scanning reads none. It
  appears in both modes, with 7 PX seeds. The 20,000-input twin scanned
  3,048 PX transactions.
- **Scoring after `Verack` (P5).** `peer_protocol` now scores each frame
  sent after `Verack` from a table of docs/p2p.md §10, plus §9 for address
  fetches. After every frame it checks the peer's score, the disconnect at
  100, and the ban (none for proxied or onion peers).
  - Where the spec does not fix the score of a frame, exact accounting
    stops. These cases are listed at the table in the body:
    - a second `Version` or `Verack`;
    - an unrequested `Tx` that does not decode (10 or 20);
    - address and transaction messages on block-relay-only connections;
    - an `Addr` on an address fetch;
    - `GetAddr` from an inbound peer that sent `relay_txs = false`;
    - delays.
  - The 10,036-input twin checked 846 scores at 0, 1,448 above 0 and 532
    bans.

### Injected bugs (local edits, reverted with `git checkout` of the product file)
Each bug ran against its twin on the seeds alone, or with 300 inputs for
the scan cases. Every one was caught:

| Edit | Caught by |
|---|---|
| P4: `MAX_HANDSHAKE_FRAME` 8192 (`p2p/src/message.rs`) | `peer_protocol`: "an unregistered connection is still open after 0ns (Closed(0ns))" |
| P5: an invalid header after `Verack` not scored (`p2p/src/net/headers.rs`, RT's edit) | `peer_protocol`: "not disconnected at score 100 after Frame([7, …])" |
| P6: `MIN_PROTOCOL_VERSION` 2 (`p2p/src/message.rs`) | `peer_protocol`: "an unregistered connection is still open after 0ns" |
| SC2: `coinbase: false` for owned outputs (`tx/src/scan.rs`) | `scan_outputs`: "output 0: coinbase flag" |
| SC3: the owned output's height + 1 (`tx/src/scan.rs`) | `scan_outputs`: "output 0: position" (6 against 5) |
| SC4: PX outputs scanned under `transfer_context(&[])` (`tx/src/scan.rs`) | `scan_outputs`: `Refused(.., JanusAnchorMismatch)` where `Owned(..)` was derived |
| PXC: `PxUnknownAnchor` classified stateless (`tx/src/validate.rs`) | `px_admission`: "the cheap checks scored PxUnknownAnchor as stateless, the specification says Contextual(\"PX1\")" |

- The first PXC run used the seeds alone and passed: no seed reached
  `PxUnknownAnchor`. The anchor seed writes the non-canonical word `P`,
  which fails earlier.
- The 2,000-input runs reached `PxUnknownAnchor` 31 times. With the new
  seed `anchor_unknown` (a canonical anchor that is no recent root), the
  seeds alone catch PXC.

### The px_admission counter difference (475/476, 251/250)
- **The question.** RT's run gave scored 475 and failed verification 251.
  The W4-STATEFUL run gave 476 and 250. Two runs of commit `132cca0` here,
  alone with 7.2 and 7.9 GB free, gave 477/249 and 475/251. Their verdict
  digests differ (`03a8e0c4459de606` and `6391cdc153950db5`), and so do
  their base transaction digests.
- **Per input.** The verdict files differ in two ways:
  - every passing input's transaction id (the base's id differs);
  - two inputs, which flip a raw proof byte (site 23). In one run each one
    hits a field the strict decoder refuses (`PxProof`, scored). In the
    other it hits one it accepts, and then fails the signatures, which
    cover the proof (`InvalidSignature`, contextual).
- **Which fields differ.** Two seeds-only runs print a digest per field of
  the base. Only the proof and the signatures differ. Inputs, outputs,
  statement, ciphertexts, pseudo-outputs and range proof are equal.
- **With one thread.** With `RAYON_NUM_THREADS=1`, two runs print the same
  proof, signature, base and verdict digests (`953a25d778d9945d`,
  `e41208f77ee56398`).
- **Explanation: a different base per process, not a varying verdict.**
  Every verdict is a function of the transaction. The base differs between
  processes because the prover's output depends on the scheduling of its
  parallel tasks.
  - **Likely cause (source-read, not confirmed by a targeted test).** The
    hiding Merkle commitment and the hiding PCS draw salts and random
    codewords from one seeded RNG behind a mutex
    (`third_party/p3-merkle-tree/src/hiding_mmcs.rs`,
    `third_party/p3-fri/src/hiding_pcs.rs`). Parallel commits take draws in
    a varying order.
  - **Impact.** Every such proof verifies. The draws still come from the
    hedged, seeded stream, so zero knowledge is not weakened as far as this
    shows.
  - **What it is.** An observation for the zk owner about reproducibility:
    proofs are not reproducible byte for byte across processes. It is not
    a harness or admission finding.
  - **For the evidence.** Compare twin digests only with
    `RAYON_NUM_THREADS=1`, as the twin's header now says.
  - **Not affected:** the libFuzzer target. It reads a fixed base from the
    seed generator's file.

### Results, fix pass (`-O -a`, AddressSanitizer, built from `ccbb076`, one at a time)

| Target | Time (s) | Executions | Exec/s | cov/ft start → end | Corpus files | New units | Last new unit at | Peak RSS (MB) | Artifacts | Findings |
|---|---|---|---|---|---|---|---|---|---|---|
| `peer_protocol` | 602 | 17,503 | 29 | 11566/33780 → 11653/34266 | 1,799 → 1,978 | 195 | execution 17,458 | 564 | 0 | 0 |
| `scan_outputs` | 603 | 14,467 | 24 | 2501/9040 → 2588/9828 | 647 → 908 | 301 | execution 14,362 | 497 | 0 | 0 |
| `px_admission` | 1,506 | 2,135 | 1 | 15668/29294 → 15899/31706 | 699 → 958 | 275 | execution 2,135 | 626 | 0 | 0 |

- **Exit status.** Every fuzzer exited 0. No log holds a panic or an
  `ERROR` line.
- **`peer_protocol` is slower:** 29 executions per second against 110.
  The scoring checks wait in real time for the header worker and the slow
  lane.
- **Run.** [run/chain2.sh](run/chain2.sh). Logs are summarized in
  [run/summary-fix.txt](run/summary-fix.txt).

### Twins, fix pass (release)

| Twin | Inputs | Result | Reached |
|---|---|---|---|
| `peer_protocol` (`BLACKSILK_FUZZ_ITERS=10000`) | 10,036 | pass, 19.6 s | registered 2,529; closed at a frame 4,994, at the key-exchange timeout 808, at the deadline 1,705 (decrypt failures 459); score checks after `Verack`: at 0 846, above 0 1,448, at the ban 532 |
| `scan_outputs` (`20000`) | 20,026 | pass, 134.4 s | outputs not owned 88,313, owned 53,394, refused for the anchor 14,982, for the commitment 1,203; transactions: coinbase 5,106, transfer 4,562, PX 3,048 |
| `px_admission` (`2000`, alone, run 1 / run 2) | 2,018 each | pass / pass | scored 477 / 475; failed verification 249 / 251; the rest equal (see above) |
| `px_admission` (seeds only, `RAYON_NUM_THREADS=1`, twice) | 19 each | pass / pass | identical digests |

- **Memory.** One seeds-only `px_admission` run started with 6.6 GB free,
  below the 7 GB rule: the second multithreaded base comparison, run before
  the `RAYON_NUM_THREADS` pair. It passed. Every other PX run started with at
  least 7.0 GB free.
